// Managed apps: git -> sandboxed install/build -> blue/green systemd slots ->
// health check -> edge switch. Each app has its own system user, its own
// directory and hardened units; builds run in a transient systemd sandbox with
// a memory cap so a runaway build cannot take the server down.
//
// An app is one build and one or more processes. A plain app is a single
// unnamed process; a monorepo (e.g. several Next.js apps and a worker) lists
// its processes, each with its own directory, routes, ports and memory cap.

import { appendFile, readdir } from "node:fs/promises";
import { createHmac, timingSafeEqual } from "node:crypto";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import { formatEnv, parseEnv, parseProcesses, v, type ProcessSpec } from "../shared/validate.ts";
import { reportStatus } from "./github.ts";
import { applyEdge, ensureUser } from "./edge.ts";
import { installed, runtimeBin, type Runtime } from "./runtimes.ts";
import { appHosts, apps, audit, deploys, procsOf, type App, type Process } from "./state.ts";
import { ensureDir, exists, randomToken, readText, remove, run, writeAtomic, type RunOptions } from "./sys.ts";

export const appUser = (name: string) => `app-${name}`;
export const appHome = (name: string) => `${paths.apps}/${name}`;
// App names never contain "_", so "<app>_<process>" cannot collide with another app.
const unitBase = (app: string, p: Process) => (p.name ? `pano-app-${app}_${p.name}` : `pano-app-${app}`);
const unitName = (app: string, p: Process, slot: "a" | "b") => `${unitBase(app, p)}@${slot}.service`;
const unitFile = (app: string, p: Process) => `${paths.systemd}/${unitBase(app, p)}@.service`;
/** Per process and slot: <home>/run/<key>-<slot>.env (PORT) and .sh (start script). Root-owned. */
const runFile = (app: string, p: Process, slot: string, ext: "env" | "sh") => `${appHome(app)}/run/${p.name || "main"}-${slot}.${ext}`;
const isWeb = (p: Process) => p.port_a > 0;
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
  processes: ProcessSpec[];
  ask_url: string;
  auto_deploy: number;
};

export function validateAppInput(x: Record<string, unknown>): AppInput {
  const processes = Array.isArray(x.processes) ? parseProcesses(x.processes.join("\n")) : parseProcesses(String(x.processes ?? ""));
  const askUrl = String(x.ask_url ?? "").trim();
  if (askUrl && !/^http:\/\/127\.0\.0\.1:\d{2,5}\/[A-Za-z0-9._~\/-]*$/.test(askUrl)) throw new Error("ask URL must be http://127.0.0.1:PORT/path");
  return {
    name: v.appName(x.name),
    // With processes, routes live on each process and the app-level fields are unused.
    domains: processes.length || !x.domains ? [] : v.domains(x.domains),
    runtime: v.runtime(x.runtime ?? "node"),
    runtime_version: v.version(x.runtime_version),
    repo: v.gitUrl(x.repo),
    branch: v.branch(x.branch || "main"),
    root_dir: v.subdir(x.root_dir),
    install_cmd: v.command(x.install_cmd, "install command"),
    build_cmd: v.command(x.build_cmd, "build command"),
    start_cmd: processes.length ? "" : v.command(x.start_cmd, "start command"),
    health_path: v.httpPath(x.health_path),
    memory_mb: v.int(x.memory_mb ?? 1024, 128, 65536, "memory limit"),
    processes,
    ask_url: askUrl,
    // The form sends a hidden "0" plus the checkbox's "1"; API callers may leave it out (on).
    auto_deploy: x.auto_deploy === undefined ? 1 : [x.auto_deploy].flat().some((d) => d === "1" || d === 1 || d === true) ? 1 : 0,
  };
}

/** Host names the input would serve, for the uniqueness check. */
export function inputHosts(input: AppInput): string[] {
  if (!input.processes.length) return input.domains;
  return [...new Set(input.processes.flatMap((p) => p.routes.map((r) => r.split("/")[0]!)))];
}

export function assertDomainsFree(domains: string[], except: { app?: string; site?: string }, all: { apps: App[]; sites: { name: string; domains: string[] }[] }) {
  for (const d of domains) {
    const a = all.apps.find((x) => x.name !== except.app && appHosts(x).includes(d));
    const s = all.sites.find((x) => x.name !== except.site && x.domains.includes(d));
    if (a || s) throw new Error(`${d} is already used by ${a ? `app ${a.name}` : `site ${s!.name}`}`);
  }
}

/** Keeps the ports of processes that already had them; new web processes get a fresh pair. */
function assignPorts(prev: Process[], next: ProcessSpec[]): Process[] {
  const taken: number[] = [];
  return next.map((p) => {
    if (!p.routes.length) return { ...p, port_a: 0, port_b: 0 };
    const old = prev.find((o) => o.name === p.name && o.port_a);
    if (old) return { ...p, port_a: old.port_a, port_b: old.port_b };
    const [a, b] = apps.nextPorts(taken);
    taken.push(a, b);
    return { ...p, port_a: a, port_b: b };
  });
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
  // Survives deploys (releases do not): SQLite files, uploads. Exposed as DATA_DIR.
  await ensureDir(`${home}/data`, 0o700, user);
  await ensureDir(`${home}/.ssh`, 0o700, user);
  await ensureDir(`${home}/run`, 0o755);
  await ensureDir(`${home}/shared`, 0o750);
  await run(["chgrp", user, fsPath(`${home}/shared`)], { check: false });
  if (!(await exists(`${home}/shared/.env`))) await writeAtomic(`${home}/shared/.env`, "", 0o640);
  await run(["chgrp", user, fsPath(`${home}/shared/.env`)], { check: false });
  const processes = assignPorts([], input.processes);
  apps.insert({ ...input, kind: "managed", port_a, port_b, processes, webhook_secret: randomToken(24) });
  const app = apps.get(input.name)!;
  await writeUnits(app);
  audit(actor, "app.create", { name: app.name, repo: app.repo, processes: processes.map((p) => p.name) });
  return app;
}

export async function updateApp(name: string, input: AppInput, actor: string) {
  const app = mustGet(name);
  const processes = assignPorts(app.processes, input.processes);
  apps.update(name, { ...input, processes, name: undefined } as Partial<App>);
  const next = apps.get(name)!;
  if (app.kind === "managed") await writeUnits(next);
  await applyEdge();
  audit(actor, "app.update", { name });
}

export async function deleteApp(name: string, actor: string, removeFiles: boolean) {
  const app = mustGet(name);
  if (app.kind === "managed") {
    for (const file of await unitFiles(name)) {
      const base = file.replace(/@\.service$/, "");
      for (const slot of ["a", "b"]) await run(["systemctl", "disable", "--now", `${base}@${slot}.service`], { check: false });
      await remove(`${paths.systemd}/${file}`);
    }
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

/** Template unit files of an app on disk: "pano-app-<name>@.service" and "pano-app-<name>_<proc>@.service". */
async function unitFiles(name: string): Promise<string[]> {
  const all = await readdir(fsPath(paths.systemd)).catch(() => [] as string[]);
  return all.filter((f) => f === `pano-app-${name}@.service` || (f.startsWith(`pano-app-${name}_`) && f.endsWith("@.service")));
}

// ---- systemd ---------------------------------------------------------------

/**
 * PATH for builds and processes. Monorepos often mix runtimes (bun as package
 * manager, node to run Next.js), so the newest installed version of the other
 * runtime follows the app's pinned one.
 */
async function toolPath(app: App): Promise<string> {
  const dirs = [runtimeBin(app.runtime, app.runtime_version)];
  const other = (await installed()).find((r) => r.runtime !== app.runtime);
  if (other) dirs.push(runtimeBin(other.runtime, other.version));
  return [...dirs, "/usr/local/bin", "/usr/bin", "/bin"].join(":");
}

export function renderUnit(app: App, p: Process, path: string): string {
  const home = appHome(app.name);
  const sub = [app.root_dir, p.dir].filter(Boolean).join("/");
  const high = Math.floor(p.memory_mb * 0.9);
  const key = p.name || "main";
  return `[Unit]
Description=pano app ${app.name}${p.name ? ` / ${p.name}` : ""} (slot %i)
After=network-online.target mariadb.service
Wants=network-online.target

[Service]
Type=simple
User=${appUser(app.name)}
Group=${appUser(app.name)}
WorkingDirectory=${home}/slot-%i${sub ? `/${sub}` : ""}
EnvironmentFile=-${home}/shared/.env
EnvironmentFile=${home}/run/${key}-%i.env
Environment=NODE_ENV=production HOSTNAME=127.0.0.1 HOME=${home} DATA_DIR=${home}/data NEXT_TELEMETRY_DISABLED=1
Environment=PATH=${path}
ExecStart=${home}/run/${key}-%i.sh
Restart=always
RestartSec=2
TimeoutStopSec=20
KillMode=mixed
MemoryHigh=${high}M
MemoryMax=${p.memory_mb}M
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

/**
 * Writes every process's template unit, removes units of processes that no
 * longer exist and, for a slot being deployed, its env files and start scripts.
 * Start commands go into root-owned scripts so no quoting ever reaches a unit file.
 */
async function writeUnits(app: App, deploy?: { slot: "a" | "b"; starts: Map<string, string> }) {
  const path = await toolPath(app);
  const procs = procsOf(app);
  const home = appHome(app.name);
  await ensureDir(`${home}/run`, 0o755);
  const keep = new Set(procs.map((p) => `${unitBase(app.name, p)}@.service`));
  for (const file of await unitFiles(app.name)) {
    if (keep.has(file)) continue;
    const base = file.replace(/@\.service$/, "");
    for (const slot of ["a", "b"]) await run(["systemctl", "disable", "--now", `${base}@${slot}.service`], { check: false });
    await remove(`${paths.systemd}/${file}`);
  }
  for (const p of procs) {
    await writeAtomic(unitFile(app.name, p), renderUnit(app, p, path), 0o644);
    if (!deploy) continue;
    const port = deploy.slot === "a" ? p.port_a : p.port_b;
    const env = `PANO_PROCESS=${p.name || "main"}\n${port ? `PORT=${port}\n` : ""}`;
    await writeAtomic(runFile(app.name, p, deploy.slot, "env"), env, 0o644);
    const rootBin = [`${home}/slot-${deploy.slot}`, app.root_dir, "node_modules/.bin"].filter(Boolean).join("/");
    const start = deploy.starts.get(p.name) || "npm run start";
    await writeAtomic(
      runFile(app.name, p, deploy.slot, "sh"),
      `#!/bin/sh\nset -e\nPATH="$PWD/node_modules/.bin:${rootBin}:$PATH"\nexec ${start}\n`,
      0o755,
    );
  }
  await run(["systemctl", "daemon-reload"]);
}

const activeUnits = (app: App): string[] =>
  app.kind === "external"
    ? (app.external_unit ? [app.external_unit] : [])
    : app.active_slot
      ? procsOf(app).map((p) => unitName(app.name, p, app.active_slot as "a" | "b"))
      : [];

export async function appAction(name: string, action: "start" | "stop" | "restart", actor: string) {
  const app = mustGet(name);
  const units = activeUnits(app);
  if (!units.length) throw new Error(app.kind === "external" ? "this app has no service unit to control" : "deploy the app first");
  await run(["systemctl", action, ...units]);
  audit(actor, `app.${action}`, { name });
}

type UnitStatus = { active: string; memory: number; since: string };

async function unitStatus(unit: string): Promise<UnitStatus> {
  const r = await run(["systemctl", "show", unit, "--property=ActiveState,MemoryCurrent,ActiveEnterTimestamp"], { check: false });
  const props = Object.fromEntries(r.stdout.trim().split("\n").map((l) => l.split(/=(.*)/s).slice(0, 2)));
  const mem = Number(props.MemoryCurrent);
  return { active: props.ActiveState ?? "unknown", memory: Number.isFinite(mem) ? mem : 0, since: props.ActiveEnterTimestamp ?? "" };
}

export async function appStatus(app: App): Promise<UnitStatus & { procs: (UnitStatus & { name: string })[] }> {
  const units = activeUnits(app);
  if (!units.length) return { active: app.kind === "external" ? "unknown" : "not deployed", memory: 0, since: "", procs: [] };
  const names = app.kind === "external" ? [app.name] : procsOf(app).map((p) => p.name || app.name);
  const procs = await Promise.all(units.map(async (u, i) => ({ name: names[i]!, ...(await unitStatus(u)) })));
  const down = procs.find((p) => p.active !== "active");
  return { active: down?.active ?? "active", memory: procs.reduce((n, p) => n + p.memory, 0), since: procs[0]!.since, procs };
}

export async function appLogs(name: string, lines = 200): Promise<string> {
  const app = mustGet(name);
  const units = activeUnits(app);
  if (!units.length) return "";
  const n = v.int(lines, 10, 5000, "lines");
  const r = await run(["journalctl", ...units.flatMap((u) => ["-u", u]), "-n", String(n), "--no-pager", "-o", "short-iso"], { check: false });
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
  const procs = procsOf(app);
  const binPath = await toolPath(app);
  let commit = "";

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
    commit = sha;
    void reportStatus(app, sha, "pending", `Deploying (deploy ${id})`);
    // Every process directory sees the shared .env (Next.js reads it from its own directory).
    for (const d of new Set(procs.map((p) => (p.dir ? `${workdir}/${p.dir}` : workdir)))) {
      await run(["ln", "-sfn", fsPath(`${home}/shared/.env`), fsPath(`${d}/.env`)], { user, check: false });
    }

    const plan = await detectPlan(app, workdir);
    if (plan.install) {
      await step(plan.install);
      await sandbox(app, ["/bin/sh", "-c", plan.install], { cwd: workdir, env: { PATH: binPath }, onLine: log, envFile: false });
    }
    if (plan.build) {
      await step(plan.build);
      await sandbox(app, ["/bin/sh", "-c", plan.build], { cwd: workdir, env: { PATH: binPath, NODE_ENV: "production" }, onLine: log, envFile: true });
    }
    if (!app.processes.length && plan.start !== app.start_cmd) {
      apps.update(app.name, { start_cmd: plan.start });
      app = apps.get(app.name)!;
    }
    const starts = new Map<string, string>();
    for (const p of procsOf(app)) {
      starts.set(p.name, p.start || (p.name ? await detectStart(app.runtime, p.dir ? `${workdir}/${p.dir}` : workdir, plan.pm) : plan.start));
      if (p.name) await log(`process ${p.name}: ${starts.get(p.name)}`);
    }
    await writeUnits(app, { slot, starts });

    await run(["ln", "-sfn", fsPath(dir), fsPath(`${home}/slot-${slot}`)]);
    for (const p of procs.filter(isWeb)) {
      const port = slot === "a" ? p.port_a : p.port_b;
      await step(`start ${p.name || "app"} (slot ${slot}) on 127.0.0.1:${port}`);
      await run(["systemctl", "restart", unitName(app.name, p, slot)]);
    }
    for (const p of procs.filter(isWeb)) await healthCheck(app, p, slot, log);

    await step("switch traffic");
    const previous = app.active_slot as "a" | "b" | "";
    apps.update(app.name, { active_slot: slot, current_release: release });
    for (const p of procs.filter(isWeb)) await run(["systemctl", "enable", unitName(app.name, p, slot)], { check: false });
    const edge = await applyEdge();
    await log(edge.reloaded ? "edge reloaded" : "edge not running yet (traffic switches at cutover)");
    // Workers must never run twice (queues, cron): stop the old one, then start the new one.
    for (const p of procs.filter((x) => !isWeb(x))) {
      if (previous) await run(["systemctl", "disable", "--now", unitName(app.name, p, previous)], { check: false });
      await run(["systemctl", "enable", "--now", unitName(app.name, p, slot)]);
      await log(`worker ${p.name} started`);
    }
    if (previous) {
      // Let in-flight requests on the old slot finish before stopping it.
      const old = procs.filter(isWeb).map((p) => unitName(app.name, p, previous));
      setTimeout(() => {
        run(["systemctl", "disable", "--now", ...old], { check: false });
      }, 15_000);
    }
    await pruneReleases(app.name, [release]);
    await log(`\ndeploy ${id} done: ${release} (${sha.slice(0, 7)})`);
    deploys.finish(id, { status: "success", commit_sha: sha, release });
    void reportStatus(app, sha, "success", `Live: release ${release}`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await log(`\nFAILED: ${msg}`);
    if (apps.get(app.name)?.active_slot !== slot) {
      await run(["systemctl", "stop", ...procs.map((p) => unitName(app.name, p, slot))], { check: false });
    }
    deploys.finish(id, { status: "failed", error: msg.slice(0, 500) });
    if (commit) void reportStatus(app, commit, "failure", msg);
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

type Plan = { install: string; build: string; start: string; pm: string };

type Pkg = { scripts?: Record<string, string>; dependencies?: Record<string, string> };
const readPkg = async (dir: string) => JSON.parse((await readText(`${dir}/package.json`)) ?? "{}") as Pkg;

/** Fills in commands the admin left empty, based on the repository's lockfile and scripts. */
export async function detectPlan(app: Pick<App, "install_cmd" | "build_cmd" | "start_cmd" | "runtime">, workdir: string): Promise<Plan> {
  const has = (f: string) => exists(`${workdir}/${f}`);
  const scripts = (await readPkg(workdir)).scripts ?? {};
  let pm = app.runtime === "bun" ? "bun" : "npm";
  let install = app.runtime === "bun" ? "bun install --frozen-lockfile" : "npm ci";
  if ((await has("bun.lock")) || (await has("bun.lockb"))) (pm = "bun"), (install = "bun install --frozen-lockfile");
  else if (await has("pnpm-lock.yaml")) (pm = "npx --yes pnpm@10"), (install = "npx --yes pnpm@10 install --frozen-lockfile");
  else if (await has("yarn.lock")) (pm = "npx --yes yarn@1"), (install = "npx --yes yarn@1 install --frozen-lockfile");
  else if (!(await has("package-lock.json")) && app.runtime !== "bun") install = "npm install";
  return {
    install: app.install_cmd || ((await has("package.json")) ? install : ""),
    build: app.build_cmd || (scripts.build ? `${pm} run build` : ""),
    start: app.start_cmd || (await detectStart(app.runtime, workdir, pm)),
    pm,
  };
}

/** Start command for a process directory. Apps bind to localhost only; the edge is the single public entry point. */
export async function detectStart(runtime: Runtime, dir: string, pm: string): Promise<string> {
  const pkg = await readPkg(dir);
  const scripts = pkg.scripts ?? {};
  // `next` resolves through the start script's PATH (process dir, then repo root node_modules/.bin).
  if (pkg.dependencies?.next || /\bnext (start|build)\b/.test(Object.values(scripts).join(" "))) return "next start -H 127.0.0.1 -p $PORT";
  if (scripts.start) return `${pm} run start`;
  return runtime === "bun" ? "bun run index.ts" : "node server.js";
}

async function healthCheck(app: App, p: Process, slot: "a" | "b", log: (l: string) => void) {
  const port = slot === "a" ? p.port_a : p.port_b;
  const url = `http://127.0.0.1:${port}${app.health_path || "/"}`;
  if (DRY_RUN) return log(`[dry-run] health check ${url}`);
  const deadline = Date.now() + 90_000;
  let last = "";
  while (Date.now() < deadline) {
    const st = await run(["systemctl", "is-active", unitName(app.name, p, slot)], { check: false });
    if (st.stdout.trim() === "failed") throw new Error(`${p.name || app.name} exited during startup (see Logs)`);
    try {
      const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(5000) });
      if (res.status < 500) {
        await log(`health ok: ${p.name ? `${p.name} ` : ""}${url} -> ${res.status}`);
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

// ---- push webhooks -------------------------------------------------------------

/**
 * GitHub, Gitea and Forgejo sign the body (X-Hub-Signature-256); GitLab sends the
 * secret itself (X-Gitlab-Token). Either way it is compared in constant time.
 */
export function verifyWebhook(name: string, body: string, signature: string, ref: string, gitlabToken = ""): { deploy: boolean; reason: string } {
  const app = mustGet(name);
  const expected = gitlabToken ? app.webhook_secret : "sha256=" + createHmac("sha256", app.webhook_secret).update(body).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(gitlabToken || signature || "");
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error("bad signature");
  if (ref && ref !== `refs/heads/${app.branch}`) return { deploy: false, reason: `ignored push to ${ref}` };
  return { deploy: true, reason: "ok" };
}
