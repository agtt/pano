// Optional containers, for services that only ship as images (Redis, Postgres,
// n8n, Uptime Kuma...). Nothing is installed until the admin asks: then Podman
// (daemonless, so no memory is used while no container runs) comes from the
// distribution's own packages. Every container is a systemd unit (Quadlet), runs
// in its own user namespace (root inside is an unprivileged uid outside), gets a
// memory/pids cap, publishes only on 127.0.0.1 and is reached from outside
// through the edge, like any other site.

import { paths } from "../shared/config.ts";
import { formatEnv, parseEnv, v } from "../shared/validate.ts";
import { assertDomainsFree } from "./apps.ts";
import { applyEdge, ensureUser } from "./edge.ts";
import { apps, audit, containers, sites, type Container } from "./state.ts";
import { ensureDir, exists, randomPassword, readText, remove, run, writeAtomic } from "./sys.ts";

const PODMAN = "/usr/bin/podman";
const PORT_BASE = 5100;
const unitName = (name: string) => `pano-ct-${name}.service`;
const quadlet = (name: string) => `${paths.quadlets}/pano-ct-${name}.container`;
const envFile = (name: string) => `${paths.containerEnv}/${name}.env`;
const dataDir = (name: string) => `${paths.containers}/${name}`;
const siteName = (name: string) => `ct-${name}`;

/** Ready-made settings for common services. Images are fully qualified (no short-name guessing). */
export const TEMPLATES: Record<string, { image: string; port: number; volumes: string[]; env: Record<string, string>; memory_mb: number; note: string }> = {
  redis: { image: "docker.io/library/redis:7-alpine", port: 6379, volumes: ["/data"], env: {}, memory_mb: 256, note: "127.0.0.1:<port> from your apps" },
  postgres: {
    image: "docker.io/library/postgres:17-alpine", port: 5432, volumes: ["/var/lib/postgresql/data"],
    env: { POSTGRES_USER: "app", POSTGRES_PASSWORD: "", POSTGRES_DB: "app" }, memory_mb: 512, note: "postgres://app:<password>@127.0.0.1:<port>/app",
  },
  meilisearch: { image: "docker.io/getmeili/meilisearch:latest", port: 7700, volumes: ["/meili_data"], env: { MEILI_MASTER_KEY: "", MEILI_ENV: "production" }, memory_mb: 512, note: "add a domain to reach it over HTTPS" },
  "uptime-kuma": { image: "docker.io/louislam/uptime-kuma:1", port: 3001, volumes: ["/app/data"], env: {}, memory_mb: 256, note: "add a domain, then create the admin account" },
  n8n: { image: "docker.io/n8nio/n8n:latest", port: 5678, volumes: ["/home/node/.n8n"], env: { N8N_SECURE_COOKIE: "true" }, memory_mb: 768, note: "add a domain; set WEBHOOK_URL=https://<domain>/" },
};

export async function podmanInstalled(): Promise<boolean> {
  return exists(PODMAN);
}

export async function installPodman(actor: string) {
  if (!(await podmanInstalled())) {
    const os = (await readText("/etc/os-release")) ?? "";
    if (/^(ID|ID_LIKE)=.*\b(debian|ubuntu)\b/m.test(os)) await run(["apt-get", "install", "-y", "podman"], { timeoutMs: 1_800_000 });
    else await run(["dnf", "-y", "install", "podman"], { timeoutMs: 1_800_000 });
  }
  // UserNS=auto takes container uids from the "containers" subordinate range, far away from real users.
  await ensureUser("containers", "/nonexistent");
  for (const f of ["/etc/subuid", "/etc/subgid"]) {
    const text = (await readText(f)) ?? "";
    if (!/^containers:/m.test(text)) await writeAtomic(f, `${text}${text && !text.endsWith("\n") ? "\n" : ""}containers:2147483647:2147483648\n`, 0o644);
  }
  audit(actor, "containers.install", {});
}

export type ContainerInput = Omit<Container, "host_port" | "created_at"> & { env: Record<string, string> };

const IMAGE = /^[A-Za-z0-9][A-Za-z0-9._\/:@-]{0,254}$/;
const VOLUME = /^\/[A-Za-z0-9._\/-]{1,200}$/;

export function validateContainer(x: Record<string, unknown>): ContainerInput {
  let image = String(x.image ?? "").trim();
  if (!IMAGE.test(image) || image.includes("..")) throw new Error("image: e.g. docker.io/library/redis:7-alpine");
  // "redis:7" -> docker.io/library/redis:7, "user/app" -> docker.io/user/app: never let a registry be guessed.
  const first = image.split("/")[0]!;
  if (!image.includes("/")) image = `docker.io/library/${image}`;
  else if (!first.includes(".") && !first.includes(":") && first !== "localhost") image = `docker.io/${image}`;
  const volumes = String(x.volumes ?? "").split(/[\s,]+/).filter(Boolean);
  for (const p of volumes) if (!VOLUME.test(p) || p.split("/").includes("..")) throw new Error(`volume path ${p}: absolute path inside the container`);
  const env: Record<string, string> = {};
  for (const [k, val] of Object.entries(typeof x.env === "string" ? parseEnv(x.env) : ((x.env ?? {}) as Record<string, string>))) {
    env[v.envKey(k)] = v.envValue(val);
  }
  const domains = String(x.domains ?? "").trim() ? v.domains(x.domains) : [];
  const port = x.port ? v.int(x.port, 1, 65535, "container port") : 0;
  if (domains.length && !port) throw new Error("a domain needs the container's HTTP port");
  return {
    name: v.appName(x.name),
    image,
    port,
    domains,
    volumes: [...new Set(volumes)].slice(0, 10),
    command: v.command(x.command, "command"),
    memory_mb: v.int(x.memory_mb ?? 512, 64, 65536, "memory limit"),
    env,
  };
}

function nextPort(): number {
  const used = new Set<number>();
  for (const c of containers.list()) used.add(c.host_port);
  for (const a of apps.list()) {
    used.add(a.port_a), used.add(a.port_b);
    for (const p of a.processes) used.add(p.port_a), used.add(p.port_b);
  }
  let p = PORT_BASE;
  while (used.has(p)) p++;
  return p;
}

export function renderQuadlet(c: Container): string {
  const lines = [
    "# Managed by pano.",
    "[Unit]",
    `Description=pano container ${c.name} (${c.image})`,
    "After=network-online.target",
    "Wants=network-online.target",
    "",
    "[Container]",
    `ContainerName=pano-${c.name}`,
    `Image=${c.image}`,
    `EnvironmentFile=${envFile(c.name)}`,
    // Only reachable from this host; the edge or local apps connect to it.
    ...(c.port ? [`PublishPort=127.0.0.1:${c.host_port}:${c.port}`] : []),
    // :U hands the data directory to the container's mapped uid.
    ...c.volumes.map((p, i) => `Volume=${dataDir(c.name)}/v${i}:${p}:U,Z`),
    "UserNS=auto",
    "NoNewPrivileges=true",
    "DropCapability=NET_RAW MKNOD AUDIT_WRITE",
    `PodmanArgs=--memory=${c.memory_mb}m --pids-limit=2048`,
    ...(c.command ? [`Exec=${c.command}`] : []),
    "",
    "[Service]",
    "Restart=always",
    "TimeoutStartSec=900",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ];
  return lines.join("\n");
}

/** Domains go through the edge as a proxy site owned by the container. */
async function syncSite(c: Container) {
  if (c.domains.length) {
    sites.upsert({
      name: siteName(c.name), kind: "proxy", domains: c.domains, root: "", routes: [{ path: "/", upstream: `127.0.0.1:${c.host_port}` }],
      ask_url: "", php_version: "", tls_cert: "", tls_key: "", source: "container", enabled: 1, on_demand_tls: 0,
    });
  } else {
    sites.remove(siteName(c.name));
  }
  await applyEdge();
}

export async function saveContainer(input: ContainerInput, actor: string): Promise<Container> {
  if (!(await podmanInstalled())) throw new Error("install container support first");
  const prev = containers.get(input.name);
  assertDomainsFree(input.domains, { site: siteName(input.name) }, { apps: apps.list(), sites: sites.list() });
  const { env, ...rest } = input;
  // Empty secrets in templates (passwords, master keys) are generated here, once.
  const old = parseEnv((await readText(envFile(input.name))) ?? "");
  for (const [k, val] of Object.entries(env)) if (!val && /PASSWORD|KEY|SECRET|TOKEN/.test(k)) env[k] = old[k] || randomPassword(32);
  const c: Container = { ...rest, host_port: prev?.host_port || nextPort(), created_at: prev?.created_at ?? 0 };
  await ensureDir(paths.containerEnv, 0o700);
  await writeAtomic(envFile(c.name), formatEnv(env), 0o600);
  await ensureDir(paths.containers, 0o755);
  await ensureDir(dataDir(c.name), 0o700);
  for (let i = 0; i < c.volumes.length; i++) await ensureDir(`${dataDir(c.name)}/v${i}`, 0o700);
  await ensureDir(paths.quadlets, 0o755);
  await writeAtomic(quadlet(c.name), renderQuadlet(c), 0o644);
  containers.upsert(c);
  await run(["systemctl", "daemon-reload"]);
  // First start pulls the image, which can take a while.
  await run(["systemctl", "restart", unitName(c.name)], { timeoutMs: 900_000 });
  await syncSite(c);
  audit(actor, prev ? "container.update" : "container.create", { name: c.name, image: c.image, domains: c.domains });
  return c;
}

function mustGet(name: string): Container {
  const c = containers.get(v.appName(name));
  if (!c) throw new Error(`no container named ${name}`);
  return c;
}

export async function containerAction(name: string, action: "start" | "stop" | "restart" | "pull", actor: string) {
  const c = mustGet(name);
  if (action === "pull") {
    // New image of the same tag (security fixes), then a restart onto it.
    await run([PODMAN, "pull", c.image], { timeoutMs: 900_000 });
    await run(["systemctl", "restart", unitName(c.name)], { timeoutMs: 900_000 });
  } else {
    await run(["systemctl", action, unitName(c.name)], { timeoutMs: 300_000 });
  }
  audit(actor, `container.${action}`, { name: c.name });
}

export async function containerStatus(c: Container): Promise<{ active: string; memory: number }> {
  const r = await run(["systemctl", "show", unitName(c.name), "--property=ActiveState,MemoryCurrent"], { check: false });
  const props = Object.fromEntries(r.stdout.trim().split("\n").map((l) => l.split(/=(.*)/s).slice(0, 2)));
  const mem = Number(props.MemoryCurrent);
  return { active: props.ActiveState ?? "unknown", memory: Number.isFinite(mem) ? mem : 0 };
}

export async function containerDetail(name: string) {
  const c = mustGet(name);
  const [status, logs] = await Promise.all([
    containerStatus(c),
    run(["journalctl", "-u", unitName(c.name), "-n", "200", "--no-pager", "-o", "short-iso"], { check: false }).then((r) => r.stdout),
  ]);
  const env = parseEnv((await readText(envFile(c.name))) ?? "");
  return { ...c, status, logs, env, dataDir: dataDir(c.name) };
}

export async function deleteContainer(name: string, removeData: boolean, actor: string) {
  const c = mustGet(name);
  await run(["systemctl", "stop", unitName(c.name)], { check: false, timeoutMs: 120_000 });
  await remove(quadlet(c.name));
  await remove(envFile(c.name));
  await run(["systemctl", "daemon-reload"], { check: false });
  if (removeData) await remove(dataDir(c.name));
  containers.remove(c.name);
  sites.remove(siteName(c.name));
  await applyEdge();
  audit(actor, "container.delete", { name: c.name, removeData });
}

export async function listContainers() {
  return Promise.all(containers.list().map(async (c) => ({ ...c, status: await containerStatus(c) })));
}
