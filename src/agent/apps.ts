// Managed apps: git -> sandboxed install/build -> blue/green systemd slots ->
// health check -> edge switch. Each app has its own system user, its own
// directory and hardened units; builds run in a transient systemd sandbox with
// a memory cap so a runaway build cannot take the server down.

import { appendFile, readdir } from "node:fs/promises";
import { createHmac, timingSafeEqual } from "node:crypto";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import { formatEnv, parseEnv, v } from "../shared/validate.ts";
import { applyEdge, ensureUser } from "./edge.ts";
import { runtimeBin, type Runtime } from "./runtimes.ts";
import { apps, audit, deploys, type App } from "./state.ts";
import { ensureDir, exists, randomToken, readText, remove, run, writeAtomic, type RunOptions } from "./sys.ts";

export const appUser = (name: string) => `app-${name}`;
export const appHome = (name: string) => `${paths.apps}/${name}`;
const unitName = (name: string, slot: "a" | "b") => `pano-app-${name}@${slot}.service`;
const unitFile = (name: string) => `${paths.systemd}/pano-app-${name}@.service`;
const deployLog = (id: number) => `${paths.deployLogs}/${id}.log`;

// ---- create / update / delete ----------------------------------------------

export type AppInput = {
  name: string;
  domains: string[];
  runtime: Runtime;
  runtime_version: string;
  repo: string;
  branch: string;
  root_dir: string;
  install_cmd: string;
  build_cmd: string;
  start_cmd: string;
  health_path: string;
  memory_mb: number;
};

export function validateAppInput(x: Record<string, unknown>): AppInput {
  return {
    name: v.appName(x.name),
    domains: x.domains ? v.domains(x.domains) : [],
    runtime: v.runtime(x.runtime ?? "node"),
    runtime_version: v.version(x.runtime_version),
    repo: v.gitUrl(x.repo),
    branch: v.branch(x.branch || "main"),
    root_dir: v.subdir(x.root_dir),
    install_cmd: v.command(x.install_cmd, "install command"),
    build_cmd: v.command(x.build_cmd, "build command"),
    start_cmd: v.command(x.start_cmd, "start command"),
    health_path: v.httpPath(x.health_path),
    memory_mb: v.int(x.memory_mb ?? 1024, 128, 65536, "memory limit"),
  };
}

export function assertDomainsFree(domains: string[], except: { app?: string; site?: string }, all: { apps: App[]; sites: { name: string; domains: string[] }[] }) {
  for (const d of domains) {
    const a = all.apps.find((x) => x.name !== except.app && x.domains.includes(d));
    const s = all.sites.find((x) => x.name !== except.site && x.domains.includes(d));
    if (a || s) throw new Error(`${d} is already used by ${a ? `app ${a.name}` : `site ${s!.name}`}`);
  }
}

export async function createApp(input: AppInput, actor: string): Promise<App> {
  if (apps.get(input.name)) throw new Error(`app ${input.name} already exists`);
  const [port_a, port_b] = apps.nextPorts();
  const user = appUser(input.name);
  const home = appHome(input.name);
  await ensureUser(user, home);
  await ensureDir(home, 0o750, user);
  await ensureDir(`${home}/releases`, 0o750, user);
  await ensureDir(`${home}/cache`, 0o750, user);
  await ensureDir(`${home}/.ssh`, 0o700, user);
  await ensureDir(`${home}/shared`, 0o750);
  await run(["chgrp", user, fsPath(`${home}/shared`)], { check: false });
  if (!(await exists(`${home}/shared/.env`))) await writeAtomic(`${home}/shared/.env`, "", 0o640);
  await run(["chgrp", user, fsPath(`${home}/shared/.env`)], { check: false });
  await writeAtomic(`${home}/slot-a.env`, `PORT=${port_a}\n`, 0o644);
  await writeAtomic(`${home}/slot-b.env`, `PORT=${port_b}\n`, 0o644);
  apps.insert({ ...input, kind: "managed", port_a, port_b, webhook_secret: randomToken(24) });
  const app = apps.get(input.name)!;
  await writeUnit(app);
  audit(actor, "app.create", { name: app.name, repo: app.repo });
  return app;
}

export async function updateApp(name: string, input: AppInput, actor: string) {
  const app = mustGet(name);
  apps.update(name, { ...input, name: undefined } as Partial<App>);
  const next = apps.get(name)!;
  if (app.kind === "managed") await writeUnit(next);
  await applyEdge();
  audit(actor, "app.update", { name });
}

export async function deleteApp(name: string, actor: string, removeFiles: boolean) {
  const app = mustGet(name);
  if (app.kind === "managed") {
    for (const slot of ["a", "b"] as const) await run(["systemctl", "disable", "--now", unitName(name, slot)], { check: false });
    await remove(unitFile(name));
    await run(["systemctl", "daemon-reload"], { check: false });
    if (removeFiles) {
      await remove(appHome(name));
      await run(["userdel", appUser(name)], { check: false });
    }
  }
  apps.remove(name);
  await applyEdge();
  audit(actor, "app.delete", { name, removeFiles });
}

function mustGet(name: string): App {
  const app = apps.get(v.appName(name));
  if (!app) throw new Error(`no app named ${name}`);
  return app;
}

// ---- systemd ---------------------------------------------------------------

export function renderUnit(app: App): string {
  const home = appHome(app.name);
  const workdir = app.root_dir ? `${home}/slot-%i/${app.root_dir}` : `${home}/slot-%i`;
  const high = Math.floor(app.memory_mb * 0.9);
  return `[Unit]
Description=pano app ${app.name} (slot %i)
After=network-online.target mariadb.service
Wants=network-online.target

[Service]
Type=simple
User=${appUser(app.name)}
Group=${appUser(app.name)}
WorkingDirectory=${workdir}
EnvironmentFile=-${home}/shared/.env
EnvironmentFile=${home}/slot-%i.env
Environment=NODE_ENV=production HOSTNAME=127.0.0.1 HOME=${home} NEXT_TELEMETRY_DISABLED=1
Environment=PATH=${runtimeBin(app.runtime, app.runtime_version)}:/usr/local/bin:/usr/bin:/bin
ExecStart=${home}/start.sh
Restart=always
RestartSec=2
TimeoutStopSec=20
KillMode=mixed
MemoryHigh=${high}M
MemoryMax=${app.memory_mb}M
TasksMax=1024
UMask=0027
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${home}
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
`;
}

async function writeUnit(app: App) {
  await writeAtomic(unitFile(app.name), renderUnit(app), 0o644);
  // The start command is written to a root-owned script so no quoting ever
  // reaches the unit file; it still runs as the app user.
  const start = app.start_cmd || "npm run start";
  await writeAtomic(`${appHome(app.name)}/start.sh`, `#!/bin/sh\nset -e\nexec ${start}\n`, 0o755);
  await run(["systemctl", "daemon-reload"]);
}

export async function appAction(name: string, action: "start" | "stop" | "restart", actor: string) {
  const app = mustGet(name);
  if (app.kind === "external") {
    if (!app.external_unit) throw new Error("this app has no service unit to control");
    await run(["systemctl", action, app.external_unit]);
  } else {
    if (!app.active_slot) throw new Error("deploy the app first");
    await run(["systemctl", action, unitName(name, app.active_slot)]);
  }
  audit(actor, `app.${action}`, { name });
}

export async function appStatus(app: App): Promise<{ active: string; memory: number; since: string }> {
  const unit = app.kind === "external" ? app.external_unit : app.active_slot ? unitName(app.name, app.active_slot) : "";
  if (!unit) return { active: app.kind === "external" ? "unknown" : "not deployed", memory: 0, since: "" };
  const r = await run(["systemctl", "show", unit, "--property=ActiveState,MemoryCurrent,ActiveEnterTimestamp"], { check: false });
  const props = Object.fromEntries(r.stdout.trim().split("\n").map((l) => l.split(/=(.*)/s).slice(0, 2)));
  const mem = Number(props.MemoryCurrent);
  return { active: props.ActiveState ?? "unknown", memory: Number.isFinite(mem) ? mem : 0, since: props.ActiveEnterTimestamp ?? "" };
}

export async function appLogs(name: string, lines = 200): Promise<string> {
  const app = mustGet(name);
  const unit = app.kind === "external" ? app.external_unit : app.active_slot ? unitName(name, app.active_slot) : "";
  if (!unit) return "";
  const n = v.int(lines, 10, 5000, "lines");
  const r = await run(["journalctl", "-u", unit, "-n", String(n), "--no-pager", "-o", "short-iso"], { check: false });
  return r.stdout;
}

// ---- env and deploy key ----------------------------------------------------

export async function getEnv(name: string): Promise<Record<string, string>> {
  mustGet(name);
  return parseEnv((await readText(`${appHome(name)}/shared/.env`)) ?? "");
}

export async function setEnv(name: string, vars: Record<string, string>, actor: string) {
  mustGet(name);
  await writeAtomic(`${appHome(name)}/shared/.env`, formatEnv(vars), 0o640);
  await run(["chgrp", appUser(name), fsPath(`${appHome(name)}/shared/.env`)], { check: false });
  audit(actor, "app.env", { name, keys: Object.keys(vars) });
}

/** Read-only deploy key for private repositories (add it to the repo, not to an account). */
export async function deployKey(name: string): Promise<string> {
  mustGet(name);
  const key = `${appHome(name)}/.ssh/id_ed25519`;
  if (!(await exists(key))) {
    await run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", `pano-${name}`, "-f", fsPath(key)], { user: appUser(name) });
  }
  return ((await readText(`${key}.pub`)) ?? "").trim();
}

// ---- deploy ----------------------------------------------------------------

let buildQueue: Promise<unknown> = Promise.resolve();

/** Starts a deploy in the background and returns its id. Builds run one at a time. */
export function startDeploy(name: string, trigger: string, actor: string): number {
  const app = mustGet(name);
  if (app.kind !== "managed") throw new Error("external apps are deployed by their own tooling");
  if (deploys.running(name)) throw new Error("a deploy is already running for this app");
  const id = deploys.start(name, trigger);
  audit(actor, "app.deploy", { name, id, trigger });
  buildQueue = buildQueue.then(() => deploy(app, id)).catch(() => {});
  return id;
}

async function deploy(app: App, id: number) {
  const logFile = fsPath(deployLog(id));
  await ensureDir(paths.deployLogs, 0o700);
  const log = (line: string) => appendFile(logFile, `${line}\n`).catch(() => {});
  const step = (s: string) => log(`\n==> ${s}`);
  const home = appHome(app.name);
  const user = appUser(app.name);
  const release = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const dir = `${home}/releases/${release}`;
  const workdir = app.root_dir ? `${dir}/${app.root_dir}` : dir;
  const slot: "a" | "b" = app.active_slot === "a" ? "b" : "a";
  const port = slot === "a" ? app.port_a : app.port_b;
  const binPath = `${runtimeBin(app.runtime, app.runtime_version)}:/usr/local/bin:/usr/bin:/bin`;

  try {
    if (!(await exists(runtimeBin(app.runtime, app.runtime_version)))) {
      throw new Error(`${app.runtime} ${app.runtime_version} is not installed (Runtimes page)`);
    }
    await step(`clone ${app.repo} (${app.branch})`);
    const sshKey = `${home}/.ssh/id_ed25519`;
    const gitSsh = `ssh -i ${sshKey} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${home}/.ssh/known_hosts`;
    await sandbox(app, ["git", "clone", "--depth", "1", "--branch", app.branch, "--", app.repo, dir], {
      cwd: `${home}/releases`, env: { GIT_SSH_COMMAND: gitSsh, PATH: binPath }, onLine: log,
    });
    const sha = (await run(["git", "-C", fsPath(dir), "rev-parse", "HEAD"], { user, check: false })).stdout.trim();
    await log(`commit ${sha}`);
    await run(["ln", "-sfn", fsPath(`${home}/shared/.env`), fsPath(`${workdir}/.env`)], { user });

    const plan = await detectPlan(app, workdir);
    if (plan.install) {
      await step(plan.install);
      await sandbox(app, ["/bin/sh", "-c", plan.install], { cwd: workdir, env: { PATH: binPath }, onLine: log, envFile: false });
    }
    if (plan.build) {
      await step(plan.build);
      await sandbox(app, ["/bin/sh", "-c", plan.build], { cwd: workdir, env: { PATH: binPath, NODE_ENV: "production" }, onLine: log, envFile: true });
    }
    if (plan.start !== app.start_cmd) {
      apps.update(app.name, { start_cmd: plan.start });
      app = apps.get(app.name)!;
    }
    await writeUnit(app);

    await step(`start slot ${slot} on 127.0.0.1:${port}`);
    await run(["ln", "-sfn", fsPath(dir), fsPath(`${home}/slot-${slot}`)]);
    await run(["systemctl", "restart", unitName(app.name, slot)]);
    await healthCheck(app, slot, port, log);

    await step("switch traffic");
    const previous = app.active_slot;
    apps.update(app.name, { active_slot: slot, current_release: release });
    await run(["systemctl", "enable", unitName(app.name, slot)], { check: false });
    const edge = await applyEdge();
    await log(edge.reloaded ? "edge reloaded" : "edge not running yet (traffic switches at cutover)");
    if (previous) {
      // Let in-flight requests on the old slot finish before stopping it.
      setTimeout(() => {
        run(["systemctl", "disable", "--now", unitName(app.name, previous)], { check: false });
      }, 15_000);
    }
    await pruneReleases(app.name, [release]);
    await log(`\ndeploy ${id} done: ${release} (${sha.slice(0, 7)})`);
    deploys.finish(id, { status: "success", commit_sha: sha, release });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await log(`\nFAILED: ${msg}`);
    await run(["systemctl", "stop", unitName(app.name, slot)], { check: false });
    deploys.finish(id, { status: "failed", error: msg.slice(0, 500) });
  }
}

/** Runs a deploy step as the app user inside a transient, memory-capped systemd sandbox. */
async function sandbox(app: App, cmd: string[], o: RunOptions & { envFile?: boolean }) {
  const home = appHome(app.name);
  const props = [
    `User=${appUser(app.name)}`,
    `Group=${appUser(app.name)}`,
    `WorkingDirectory=${o.cwd ?? home}`,
    `MemoryMax=${Math.max(app.memory_mb, 2048)}M`,
    "RuntimeMaxSec=1800",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    `ReadWritePaths=${home}`,
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "RestrictSUIDSGID=yes",
    "CapabilityBoundingSet=",
    "UMask=0027",
    ...(o.envFile ? [`EnvironmentFile=-${home}/shared/.env`] : []),
  ];
  const env = {
    HOME: home,
    CI: "1",
    NEXT_TELEMETRY_DISABLED: "1",
    npm_config_cache: `${home}/cache/npm`,
    BUN_INSTALL_CACHE_DIR: `${home}/cache/bun`,
    XDG_CACHE_HOME: `${home}/cache`,
    ...o.env,
  };
  const argv = [
    "systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
    `--unit=pano-build-${app.name}-${Date.now()}`,
    ...props.flatMap((p) => ["-p", p]),
    ...Object.entries(env).map(([k, val]) => `--setenv=${k}=${val}`),
    "--", ...cmd,
  ];
  await run(argv, { onLine: o.onLine, timeoutMs: 1_900_000 });
}

type Plan = { install: string; build: string; start: string };

/** Fills in commands the admin left empty, based on the repository's lockfile and scripts. */
export async function detectPlan(app: Pick<App, "install_cmd" | "build_cmd" | "start_cmd" | "runtime">, workdir: string): Promise<Plan> {
  const has = (f: string) => exists(`${workdir}/${f}`);
  const pkg = JSON.parse((await readText(`${workdir}/package.json`)) ?? "{}") as { scripts?: Record<string, string>; dependencies?: Record<string, string> };
  const scripts = pkg.scripts ?? {};
  let pm = app.runtime === "bun" ? "bun" : "npm";
  let install = app.runtime === "bun" ? "bun install --frozen-lockfile" : "npm ci";
  if ((await has("bun.lock")) || (await has("bun.lockb"))) (pm = "bun"), (install = "bun install --frozen-lockfile");
  else if (await has("pnpm-lock.yaml")) (pm = "npx --yes pnpm@10"), (install = "npx --yes pnpm@10 install --frozen-lockfile");
  else if (await has("yarn.lock")) (pm = "npx --yes yarn@1"), (install = "npx --yes yarn@1 install --frozen-lockfile");
  else if (!(await has("package-lock.json")) && app.runtime !== "bun") install = "npm install";
  const script = (s: string) => `${pm} run ${s}`;

  const isNext = !!pkg.dependencies?.next || /\bnext (start|build)\b/.test(Object.values(scripts).join(" "));
  let start = app.start_cmd;
  if (!start) {
    // Apps bind to localhost only; the edge is the single public entry point.
    if (isNext) start = "./node_modules/.bin/next start -H 127.0.0.1 -p $PORT";
    else if (scripts.start) start = script("start");
    else start = app.runtime === "bun" ? "bun run index.ts" : "node server.js";
  }
  return {
    install: app.install_cmd || ((await has("package.json")) ? install : ""),
    build: app.build_cmd || (scripts.build ? script("build") : ""),
    start,
  };
}

async function healthCheck(app: App, slot: "a" | "b", port: number, log: (l: string) => void) {
  const url = `http://127.0.0.1:${port}${app.health_path || "/"}`;
  if (DRY_RUN) return log(`[dry-run] health check ${url}`);
  const deadline = Date.now() + 90_000;
  let last = "";
  while (Date.now() < deadline) {
    const st = await run(["systemctl", "is-active", unitName(app.name, slot)], { check: false });
    if (st.stdout.trim() === "failed") throw new Error("the app exited during startup (see Logs)");
    try {
      const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(5000) });
      if (res.status < 500) {
        await log(`health ok: ${url} -> ${res.status}`);
        return;
      }
      last = `HTTP ${res.status}`;
    } catch (e) {
      last = e instanceof Error ? e.message : String(e);
    }
    await Bun.sleep(1500);
  }
  throw new Error(`health check failed for ${url}: ${last}`);
}

async function pruneReleases(name: string, keepAlso: string[], keep = 5) {
  const dir = `${appHome(name)}/releases`;
  let all: string[] = [];
  try {
    all = (await readdir(fsPath(dir))).sort().reverse();
  } catch {
    return;
  }
  const linked = new Set(keepAlso);
  for (const slot of ["a", "b"]) {
    const r = await run(["readlink", fsPath(`${appHome(name)}/slot-${slot}`)], { check: false });
    const target = r.stdout.trim().split("/").pop();
    if (target) linked.add(target);
  }
  for (const rel of all.slice(keep)) if (!linked.has(rel)) await remove(`${dir}/${rel}`);
}

export async function readDeployLog(id: number, offset = 0): Promise<{ text: string; offset: number }> {
  const file = Bun.file(fsPath(deployLog(id)));
  if (!(await file.exists())) return { text: "", offset };
  const size = file.size;
  if (offset >= size) return { text: "", offset: size };
  return { text: await file.slice(offset, size).text(), offset: size };
}

// ---- GitHub webhook ----------------------------------------------------------

export function verifyWebhook(name: string, body: string, signature: string, ref: string): { deploy: boolean; reason: string } {
  const app = mustGet(name);
  const expected = "sha256=" + createHmac("sha256", app.webhook_secret).update(body).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(signature || "");
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error("bad signature");
  if (ref && ref !== `refs/heads/${app.branch}`) return { deploy: false, reason: `ignored push to ${ref}` };
  return { deploy: true, reason: "ok" };
}
