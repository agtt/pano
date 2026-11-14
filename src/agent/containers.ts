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

const SETUP_NOTE = "Until setup is finished its port on 127.0.0.1 is reachable by every other local user (apps, sites) on this server.";

/** Ready-made settings for common services. Images are fully qualified (no short-name guessing). */
export const TEMPLATES: Record<string, { image: string; port: number; volumes: string[]; env: Record<string, string>; memory_mb: number; note: string }> = {
  redis: {
    image: "docker.io/library/redis:7-alpine", port: 6379, volumes: ["/data"], env: { REDIS_PASSWORD: "" }, memory_mb: 256,
    note: "redis://:<REDIS_PASSWORD>@127.0.0.1:<port> from your apps; the password is generated on save (Show values)",
  },
  postgres: {
    image: "docker.io/library/postgres:17-alpine", port: 5432, volumes: ["/var/lib/postgresql/data"],
    env: { POSTGRES_USER: "app", POSTGRES_PASSWORD: "", POSTGRES_DB: "app" }, memory_mb: 512, note: "postgres://app:<password>@127.0.0.1:<port>/app",
  },
  meilisearch: { image: "docker.io/getmeili/meilisearch:latest", port: 7700, volumes: ["/meili_data"], env: { MEILI_MASTER_KEY: "", MEILI_ENV: "production" }, memory_mb: 512, note: "add a domain to reach it over HTTPS" },
  "uptime-kuma": {
    image: "docker.io/louislam/uptime-kuma:1", port: 3001, volumes: ["/app/data"], env: {}, memory_mb: 256,
    note: `add a domain, then create the admin account at once. ${SETUP_NOTE}`,
  },
  n8n: {
    image: "docker.io/n8nio/n8n:latest", port: 5678, volumes: ["/home/node/.n8n"], env: { N8N_SECURE_COOKIE: "true" }, memory_mb: 768,
    note: `add a domain; set WEBHOOK_URL=https://<domain>/. Create the owner account at once. ${SETUP_NOTE}`,
  },
};

const REDIS_IMAGES = new Set(["docker.io/library/redis", "docker.io/redis"]);
const isRedis = (image: string) => REDIS_IMAGES.has(repoOf(image));
// Redis 7 cannot read a password from the environment, and a password in the command line is visible to
// every local user (ps). The entrypoint writes it to a config file inside the container instead (no $ or
// backslash, which systemd would expand). Container root is an unprivileged uid; the file is 0600 and in
// the container's own filesystem.
export const REDIS_COMMAND = `sh -c 'umask 077; printenv REDIS_PASSWORD | sed "s/^/requirepass /" > /tmp/redis.conf; exec redis-server /tmp/redis.conf'`;
const REDIS_PASSWORD = /^[A-Za-z0-9._~+-]{8,128}$/;

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

export type ContainerInput = Omit<Container, "host_port" | "created_at" | "digest"> & { env: Record<string, string> };

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
    read_only: x.read_only === "1" || x.read_only === 1 || x.read_only === true ? 1 : 0,
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

const DIGEST = /^sha256:[a-f0-9]{64}$/;

/** registry/name without tag or digest ("host:5000/x/y:1@sha256:.." -> "host:5000/x/y"). */
export function repoOf(image: string): string {
  const noDigest = image.split("@")[0]!;
  const slash = noDigest.lastIndexOf("/");
  const colon = noDigest.indexOf(":", slash + 1);
  return colon === -1 ? noDigest : noDigest.slice(0, colon);
}

/** What actually runs: the image by digest, so a moved tag (or a hijacked registry account) changes nothing until "update". */
export function runRef(c: Pick<Container, "image" | "digest">): string {
  return DIGEST.test(c.digest) ? `${repoOf(c.image)}@${c.digest}` : c.image;
}

/** Pulls the tag and returns the digest it points to now. skopeo, when installed, is asked first (no pull needed to see it). */
export async function resolveDigest(image: string): Promise<string> {
  const given = image.match(/@(sha256:[a-f0-9]{64})$/)?.[1];
  if (given) return given;
  await run([PODMAN, "pull", "--quiet", image], { timeoutMs: 900_000 });
  for (const cmd of [
    [PODMAN, "image", "inspect", "--format", "{{.Digest}}", image],
    ["skopeo", "inspect", "--format", "{{.Digest}}", `docker://${image}`],
  ]) {
    const r = await run(cmd, { check: false, timeoutMs: 120_000 });
    const d = r.stdout.trim();
    if (r.code === 0 && DIGEST.test(d)) return d;
  }
  // Dry-run and registries that give no digest (local images): run the tag as before.
  return "";
}

export function renderQuadlet(c: Container): string {
  const lines = [
    "# Managed by pano.",
    "[Unit]",
    `Description=pano container ${c.name} (${c.image}${c.digest ? ` ${c.digest.slice(0, 19)}` : ""})`,
    "After=network-online.target",
    "Wants=network-online.target",
    "",
    "[Container]",
    `ContainerName=pano-${c.name}`,
    `Image=${runRef(c)}`,
    `EnvironmentFile=${envFile(c.name)}`,
    // Only reachable from this host; the edge or local apps connect to it.
    ...(c.port ? [`PublishPort=127.0.0.1:${c.host_port}:${c.port}`] : []),
    // :U hands the data directory to the container's mapped uid.
    ...c.volumes.map((p, i) => `Volume=${dataDir(c.name)}/v${i}:${p}:U,Z`),
    "UserNS=auto",
    "NoNewPrivileges=true",
    ...(c.read_only ? ["ReadOnly=true"] : []),
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
  const old = parseEnv((await readText(envFile(input.name))) ?? "");
  // Redis: always password-protected (any local user can reach the published port). A command the admin
  // set themselves is left alone; saving an older, unprotected Redis container turns the password on.
  if (isRedis(rest.image) && !rest.command) {
    rest.command = REDIS_COMMAND;
    env.REDIS_PASSWORD ||= old.REDIS_PASSWORD || "";
  }
  // Empty secrets in templates (passwords, master keys) are generated here, once.
  for (const [k, val] of Object.entries(env)) if (!val && /PASSWORD|KEY|SECRET|TOKEN/.test(k)) env[k] = old[k] || randomPassword(32);
  if (rest.command === REDIS_COMMAND && !REDIS_PASSWORD.test(env.REDIS_PASSWORD ?? "")) throw new Error("REDIS_PASSWORD: 8-128 characters from A-Z a-z 0-9 . _ ~ + -");
  // Pinned once per image: saving other settings does not move a running container to a newer build.
  const digest = prev && prev.image === input.image && prev.digest ? prev.digest : await resolveDigest(input.image);
  const c: Container = { ...rest, digest, host_port: prev?.host_port || nextPort(), created_at: prev?.created_at ?? 0 };
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
    // Re-resolves the tag (security fixes) and moves the container onto that digest, the one place it changes.
    const next = { ...c, digest: await resolveDigest(c.image) };
    await writeAtomic(quadlet(c.name), renderQuadlet(next), 0o644);
    containers.upsert(next);
    await run(["systemctl", "daemon-reload"]);
    await run(["systemctl", "restart", unitName(c.name)], { timeoutMs: 900_000 });
    audit(actor, "container.pull", { name: c.name, from: c.digest, to: next.digest });
    return;
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

/** What the env file holds now (empty for a new container). */
export async function containerEnv(name: string): Promise<Record<string, string>> {
  return parseEnv((await readText(envFile(name))) ?? "");
}

export async function containerDetail(name: string) {
  const c = mustGet(name);
  const [status, logs] = await Promise.all([
    containerStatus(c),
    run(["journalctl", "-u", unitName(c.name), "-n", "200", "--no-pager", "-o", "short-iso"], { check: false }).then((r) => r.stdout),
  ]);
  const env = parseEnv((await readText(envFile(c.name))) ?? "");
  // A Redis container made before passwords were added still answers anyone on this server.
  const notice = isRedis(c.image) && !c.command && !env.REDIS_PASSWORD ? "This Redis has no password: every local user can read and change its data. Save it once to turn a generated password on, then add it to the apps that use it (redis://:<REDIS_PASSWORD>@127.0.0.1:<port>)." : "";
  return { ...c, status, logs, env, dataDir: dataDir(c.name), notice };
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
