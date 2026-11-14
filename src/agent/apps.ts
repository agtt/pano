// Managed apps: git -> sandboxed install/build -> blue/green systemd slots ->
// health check -> edge switch. Each app has its own system user, its own
// directory and hardened units; builds run in a transient systemd sandbox with
// a memory cap so a runaway build cannot take the server down.
//
// An app is one build and one or more processes. A plain app is a single
// unnamed process; a monorepo (e.g. several Next.js apps and a worker) lists
// its processes, each with its own directory, routes, ports and memory cap.

import { constants } from "node:fs";
import { appendFile, open, readdir, type FileHandle } from "node:fs/promises";
import { createHmac, timingSafeEqual } from "node:crypto";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import { envSnapshot, groupList, mergeEnv, normalizeGroups } from "../shared/env.ts";
import { normalizeEnvExclude, PREVIEW_MAX_DEFAULT, PREVIEW_TTL_DEFAULT, validatePreviewDomain } from "../shared/preview.ts";
import { formatEnv, parseEnv, parseProcesses, v, type ProcessSpec } from "../shared/validate.ts";
import { notify } from "./alerts.ts";
import { removeAppValkey } from "./appvalkey.ts";
import { groupFile, readGroup } from "./envgroups.ts";
import { reportStatus } from "./github.ts";
import { parsePm2Ref, pm2App, pm2Logs, pm2Reload } from "./pm2.ts";
import { applyEdge, ensureUser } from "./edge.ts";
import { available, installed, install as installRuntime, runtimeBin, type Runtime } from "./runtimes.ts";
import { appHosts, apps, audit, deploys, procsOf, type App, type Process } from "./state.ts";
import { ensureDir, exists, randomToken, readText, remove, removeAs, run, showUnits, writeAtomic, type RunOptions } from "./sys.ts";

export const appUser = (name: string) => `app-${name}`;
export const appHome = (name: string) => `${paths.apps}/${name}`;
// App names never contain "_", so "<app>_<process>" cannot collide with another app.
const unitBase = (app: string, p: Process) => (p.name ? `pano-app-${app}_${p.name}` : `pano-app-${app}`);
export const unitName = (app: string, p: Process, slot: "a" | "b") => `${unitBase(app, p)}@${slot}.service`;
const unitFile = (app: string, p: Process) => `${paths.systemd}/${unitBase(app, p)}@.service`;
/** Per process and slot: <home>/run/<key>-<slot>.env (PORT) and .sh (start script). Root-owned. */
const runFile = (app: string, p: Process, slot: string, ext: "env" | "sh") => `${appHome(app)}/run/${p.name || "main"}-${slot}.${ext}`;
export const isWeb = (p: Process) => p.port_a > 0;
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
  build_isolated: number;
  crons: Cron[];
  preview_domain: string;
  preview_max: number;
  preview_ttl_days: number;
  preview_env_exclude: string;
  env_groups: string;
  http_redirect: number;
};

/** A form's hidden "0" plus a checkbox's "1", or an API caller's value; left out: `missing`. */
/** A form checkbox (hidden "0" + checkbox "1"), a boolean or a number; missing: the default. */
export const flag = (x: unknown, missing: 0 | 1): number => (x === undefined ? missing : [x].flat().some((d) => d === "1" || d === 1 || d === true) ? 1 : 0);

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
    // Arrays (API callers) go through the same checks as the text form.
    crons: parseCrons(Array.isArray(x.crons) ? x.crons.map((c: any) => `${String(c?.schedule ?? "").replace(/[|\r\n]/g, " ")} | ${String(c?.command ?? "")}`).join("\n") : String(x.crons ?? "")),
    auto_deploy: flag(x.auto_deploy, 1),
    // Off unless asked for (slower: no shared caches).
    build_isolated: flag(x.build_isolated, 0),
    preview_domain: validatePreviewDomain(x.preview_domain),
    preview_max: v.int(x.preview_max || PREVIEW_MAX_DEFAULT, 1, 20, "max previews"),
    preview_ttl_days: v.int(x.preview_ttl_days || PREVIEW_TTL_DEFAULT, 1, 90, "preview lifetime (days)"),
    preview_env_exclude: normalizeEnvExclude(x.preview_env_exclude),
    env_groups: normalizeGroups(x.env_groups),
    // On unless turned off: plain HTTP is redirected to HTTPS.
    http_redirect: flag(x.http_redirect, 1),
  };
}

/** Host names the input would serve, for the uniqueness check. */
export function inputHosts(input: AppInput): string[] {
  if (!input.processes.length) return input.domains;
  return [...new Set(input.processes.flatMap((p) => p.routes.map((r) => r.split("/")[0]!)))];
}

export function assertDomainsFree(domains: string[], except: { app?: string; site?: string }, all: { apps: App[]; sites: { name: string; domains: string[] }[]; previews?: { app: string; host: string }[] }) {
  for (const d of domains) {
    const pv = all.previews?.find((x) => x.app !== except.app && x.host === d);
    if (pv) throw new Error(`${d} is already used by a preview of app ${pv.app}`);
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
  await ensureAppHome(input.name);
  const processes = assignPorts([], input.processes);
  apps.insert({ ...input, kind: "managed", port_a, port_b, processes, webhook_secret: randomToken(24) });
  const app = apps.get(input.name)!;
  await writeUnits(app);
  audit(actor, "app.create", { name: app.name, repo: app.repo, processes: processes.map((p) => p.name) });
  return app;
}

/** The app's system user and directories; idempotent (also used by recovery). */
export async function ensureAppHome(name: string) {
  const user = appUser(name);
  const home = appHome(name);
  await ensureUser(user, home);
  // root:<user> 0750: the app can read its home but not rename what is in it (run/, releases/,
  // slot links), so nothing root later writes or deletes there can be swapped for a symlink.
  await ensureDir(home, 0o750);
  await run(["chown", "-h", `root:${user}`, fsPath(home)]);
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
}

export async function updateApp(name: string, input: AppInput, actor: string) {
  const app = mustGet(name);
  const processes = assignPorts(app.processes, input.processes);
  apps.update(name, { ...input, processes, name: undefined } as Partial<App>);
  const next = apps.get(name)!;
  if (app.kind === "managed") {
    await writeUnits(next);
    await writeCrons(next);
  }
  await applyEdge();
  audit(actor, "app.update", { name });
}

export async function deleteApp(name: string, actor: string, removeFiles: boolean) {
  const app = mustGet(name);
  if (app.kind === "managed") {
    await writeCrons({ ...app, crons: [] });
    await teardownUnits(name, removeFiles);
  }
  await removeAppValkey(name);
  apps.remove(name);
  await applyEdge();
  audit(actor, "app.delete", { name, removeFiles });
}

/** Stops and removes the units of a managed app (or preview) and, optionally, its home and system user. */
export async function teardownUnits(name: string, removeFiles: boolean) {
  for (const file of await unitFiles(name)) {
    const base = file.replace(/@\.service$/, "");
    for (const slot of ["a", "b"]) await run(["systemctl", "disable", "--now", `${base}@${slot}.service`], { check: false });
    await remove(`${paths.systemd}/${file}`);
  }
  await run(["systemctl", "daemon-reload"], { check: false });
  if (removeFiles) {
    // What the app could write goes first, as the app's user (see removeAs); root then removes only its
    // own layout (run/, shared/, slot links) and whatever the user could not.
    for (const d of ["releases", "cache", "data", ".ssh"]) await removeAs(`${appHome(name)}/${d}`, appUser(name));
    await remove(appHome(name));
    await run(["userdel", appUser(name)], { check: false });
  }
}

export function mustGet(name: string): App {
  const app = apps.get(v.appName(name));
  if (!app) throw new Error(`no app named ${name}`);
  return app;
}

/** Refuses what would build or start an app's code while it is suspended. */
export function assertNotSuspended(app: Pick<App, "name" | "suspended">, what = "deploy") {
  if (app.suspended) throw new Error(`${app.name} is suspended: resume it before you ${what}`);
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

/**
 * CPU and disk shares for work nobody waits on. Web processes keep the default
 * weight of 100, so under load they get 5x more than builds and cron jobs and
 * 2x more than queue workers; on an idle server everything runs at full speed.
 */
export const LOW = "Nice=10\nCPUWeight=20\nIOWeight=20\n";
const BACKGROUND = "Nice=5\nCPUWeight=50\nIOWeight=50\n";

/** Hardening shared by app processes and their cron jobs. */
const sandboxLines = (home: string) => `UMask=0027
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
# Cloud metadata (user-data can hold root passwords and keys) and other users' processes are out of reach.
IPAddressDeny=169.254.169.254/32
ProtectProc=invisible
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# Calls newer than this systemd (fchmodat2 on 6.6+ kernels) fail softly and libc falls back.
SystemCallErrorNumber=ENOSYS
`;

/** Shared variable groups, read by systemd (as root) before the app's own .env, which wins. */
const groupEnvLines = (app: App) => groupList(app.env_groups ?? "").map((g) => `EnvironmentFile=-${groupFile(g)}\n`).join("");

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
${groupEnvLines(app)}EnvironmentFile=-${home}/shared/.env
EnvironmentFile=${home}/run/${key}-%i.env
Environment=NODE_ENV=production HOSTNAME=127.0.0.1 HOME=${home} XDG_CACHE_HOME=${home}/cache DATA_DIR=${home}/data NEXT_TELEMETRY_DISABLED=1
Environment=PATH=${path}
ExecStart=${home}/run/${key}-%i.sh
Restart=always
RestartSec=2
TimeoutStopSec=20
KillMode=mixed
MemoryHigh=${high}M
MemoryMax=${p.memory_mb}M
TasksMax=1024
${isWeb(p) ? "" : BACKGROUND}${sandboxLines(home)}
[Install]
WantedBy=multi-user.target
`;
}

/**
 * Writes every process's template unit, removes units of processes that no
 * longer exist and, for a slot being deployed, its env files and start scripts.
 * Start commands go into root-owned scripts so no quoting ever reaches a unit file.
 */
export async function writeUnits(app: App, deploy?: { slot: "a" | "b"; starts: Map<string, string> }) {
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
    const start = deploy.starts.get(p.name) || "bun run start";
    await writeAtomic(
      runFile(app.name, p, deploy.slot, "sh"),
      `#!/bin/sh\nset -e\nPATH="$PWD/node_modules/.bin:${rootBin}:$PATH"\nexec ${start}\n`,
      0o755,
    );
  }
  await run(["systemctl", "daemon-reload"]);
}

export const activeUnits = (app: App): string[] =>
  app.kind === "external"
    ? (app.external_unit && !parsePm2Ref(app.external_unit) ? [app.external_unit] : [])
    : app.active_slot
      ? procsOf(app).map((p) => unitName(app.name, p, app.active_slot as "a" | "b"))
      : [];

// ---- instant rollback ------------------------------------------------------------

/**
 * Switches back to the release the other slot still holds: no clone, no build.
 * Same order as a deploy: start, health check, switch traffic, then stop.
 */
export async function rollback(name: string, actor: string) {
  const app = mustGet(name);
  if (app.kind !== "managed" || !app.active_slot) throw new Error("nothing deployed yet");
  assertNotSuspended(app, "roll back");
  if (deploys.running(name)) throw new Error("a deploy is running");
  const home = appHome(name);
  const from = app.active_slot;
  const to: "a" | "b" = from === "a" ? "b" : "a";
  const target = (await run(["readlink", "-f", fsPath(`${home}/slot-${to}`)], { check: false })).stdout.trim();
  const release = target.split("/").pop() ?? "";
  if (!release || release === app.current_release || !(await exists(`${home}/releases/${release}`))) throw new Error("no previous release on disk");
  if (!(await exists(runFile(name, procsOf(app)[0]!, to, "sh")))) throw new Error("the previous release has no start script");
  const procs = procsOf(app);
  const log = (l: string) => console.log(`[rollback ${name}] ${l}`);
  for (const p of procs.filter(isWeb)) await run(["systemctl", "restart", unitName(name, p, to)]);
  for (const p of procs.filter(isWeb)) await healthCheck(app, p, to, log);
  // The older build's env is not known: no redeploy hint until the next deploy.
  apps.update(name, { active_slot: to, current_release: release, env_running: envSnapshot(await effectiveEnv(app)), env_built: "" });
  await run(["ln", "-sfn", fsPath(`${home}/slot-${to}`), fsPath(`${home}/current`)]);
  for (const p of procs.filter(isWeb)) await run(["systemctl", "enable", unitName(name, p, to)], { check: false });
  await applyEdge();
  for (const p of procs.filter((x) => !isWeb(x))) {
    await run(["systemctl", "disable", "--now", unitName(name, p, from)], { check: false });
    await run(["systemctl", "enable", "--now", unitName(name, p, to)]);
  }
  const old = procs.filter(isWeb).map((p) => unitName(name, p, from));
  setTimeout(() => run(["systemctl", "disable", "--now", ...old], { check: false }), 15_000);
  audit(actor, "app.rollback", { name, release });
  return { release };
}

// ---- cron jobs -------------------------------------------------------------------

export type Cron = { schedule: string; command: string };

/** `schedule | command` per line. Schedules are systemd calendar expressions: hourly, daily, *:0/5, Mon *-*-* 03:00 … */
export function parseCrons(text: string): Cron[] {
  const out: Cron[] = [];
  for (const line of text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))) {
    const i = line.indexOf("|");
    if (i < 0) throw new Error(`cron: "schedule | command" expected: ${line.slice(0, 40)}`);
    const schedule = line.slice(0, i).trim();
    const command = v.command(line.slice(i + 1).trim(), "cron command");
    if (!/^[A-Za-z0-9*:\/,.~ -]{1,64}$/.test(schedule)) throw new Error(`cron schedule: ${schedule}`);
    if (!command) throw new Error("cron command is empty");
    out.push({ schedule, command });
  }
  if (out.length > 20) throw new Error("at most 20 cron jobs per app");
  return out;
}

export const formatCrons = (c: Cron[]) => c.map((x) => `${x.schedule} | ${x.command}`).join("\n");

const cronBase = (app: string, i: number) => `pano-cron-${app}-${i}`;
/** The timers of an app's cron jobs. */
export const cronTimers = (app: App) => app.crons.map((_, i) => `${cronBase(app.name, i)}.timer`);

/** One timer + oneshot service per job, in the live release, with the app's user, env and sandbox. Never two runs at once. */
export async function writeCrons(app: App) {
  const home = appHome(app.name);
  const all = await readdir(fsPath(paths.systemd)).catch(() => [] as string[]);
  const keep = new Set(app.crons.flatMap((_, i) => [`${cronBase(app.name, i)}.timer`, `${cronBase(app.name, i)}.service`]));
  for (const f of all.filter((f) => f.startsWith(`pano-cron-${app.name}-`) && !keep.has(f))) {
    if (f.endsWith(".timer")) await run(["systemctl", "disable", "--now", f], { check: false });
    await remove(`${paths.systemd}/${f}`);
  }
  const path = await toolPath(app);
  const dir = `${home}/current${app.root_dir ? `/${app.root_dir}` : ""}`;
  for (const [i, c] of app.crons.entries()) {
    const base = cronBase(app.name, i);
    await writeAtomic(`${home}/run/cron-${i}.sh`, `#!/bin/sh\nset -e\nPATH="$PWD/node_modules/.bin:$PATH"\n${c.command}\n`, 0o755);
    await writeAtomic(
      `${paths.systemd}/${base}.service`,
      `[Unit]
Description=pano cron ${app.name} #${i}: ${c.schedule}

[Service]
Type=oneshot
User=${appUser(app.name)}
Group=${appUser(app.name)}
WorkingDirectory=${dir}
${groupEnvLines(app)}EnvironmentFile=-${home}/shared/.env
Environment=NODE_ENV=production HOME=${home} XDG_CACHE_HOME=${home}/cache DATA_DIR=${home}/data PANO_CRON=${i}
Environment=PATH=${path}
ExecStart=${home}/run/cron-${i}.sh
TimeoutStartSec=1h
MemoryMax=${app.memory_mb}M
TasksMax=256
${LOW}${sandboxLines(home)}`,
      0o644,
    );
    await writeAtomic(`${paths.systemd}/${base}.timer`, `[Unit]\nDescription=pano cron ${app.name} #${i}\n\n[Timer]\nOnCalendar=${c.schedule}\nPersistent=true\nRandomizedDelaySec=5\n\n[Install]\nWantedBy=timers.target\n`, 0o644);
  }
  await run(["systemctl", "daemon-reload"]);
  // Timers start with the first deploy, and again when a suspended app resumes.
  if (!app.active_slot || app.suspended) return;
  for (const i of app.crons.keys()) await run(["systemctl", "enable", "--now", `${cronBase(app.name, i)}.timer`], { check: false });
}

/** Rejects a schedule systemd would not understand, before anything is saved. */
export async function checkSchedules(crons: Cron[]) {
  for (const c of crons) {
    const r = await run(["systemd-analyze", "calendar", c.schedule], { check: false });
    if (r.code !== 0) throw new Error(`cron schedule not understood: ${c.schedule} (examples: hourly, daily, *:0/15, Mon..Fri 09:00)`);
  }
}

export async function cronLogs(app: App, lines = 100): Promise<string> {
  if (!app.crons.length) return "";
  const units = app.crons.flatMap((_, i) => ["-u", `${cronBase(app.name, i)}.service`]);
  return (await run(["journalctl", ...units, "-n", String(lines), "--no-pager", "-o", "short-iso"], { check: false })).stdout;
}

export async function appAction(name: string, action: "start" | "stop" | "restart", actor: string) {
  const app = mustGet(name);
  const pm2 = parsePm2Ref(app.external_unit);
  if (pm2) {
    // A stop here would take the site down with no way back from pano: only the safe reload.
    if (action !== "restart") throw new Error("PM2 runs this app: pano only reloads it (zero downtime); start and stop it with pm2");
    await pm2Reload(pm2);
    audit(actor, "app.reload", { name, pm2: true });
    return;
  }
  // Suspension stopped a managed app's processes; only resume starts them again.
  if (app.kind === "managed" && action !== "stop") assertNotSuspended(app, action);
  const units = activeUnits(app);
  if (!units.length) throw new Error(app.kind === "external" ? "this app has no service unit to control" : "deploy the app first");
  await run(["systemctl", action, ...units]);
  // The processes now run with the current env: nothing left to restart for.
  if (app.kind === "managed" && action !== "stop") apps.update(name, { env_running: envSnapshot(await effectiveEnv(app)) });
  audit(actor, `app.${action}`, { name });
}

type UnitStatus = { active: string; memory: number; since: string };

type AppStatus = UnitStatus & { procs: (UnitStatus & { name: string })[] };

/** Status of many apps from one `systemctl show` for all their units. */
export async function appStatuses(list: App[]): Promise<AppStatus[]> {
  const shown = await showUnits(list.flatMap(activeUnits), ["ActiveState", "MemoryCurrent", "ActiveEnterTimestamp"]);
  const pm2 = await Promise.all(list.map((app) => {
    const ref = parsePm2Ref(app.external_unit);
    return ref ? pm2App(ref) : null;
  }));
  return list.map((app, i) => {
    if (app.suspended) return { active: "suspended", memory: 0, since: "", procs: [] };
    if (parsePm2Ref(app.external_unit)) {
      const p = pm2[i];
      if (!p) return { active: "unknown", memory: 0, since: "", procs: [] };
      const since = p.since ? new Date(p.since).toISOString() : "";
      const active = p.online === p.total && p.total > 0 ? "active" : p.online ? "degraded" : "failed";
      return { active, memory: p.memory, since, procs: [{ name: `${p.name} (pm2 ${p.online}/${p.total})`, active, memory: p.memory, since }] };
    }
    const units = activeUnits(app);
    if (!units.length) return { active: app.kind === "external" ? "unknown" : "not deployed", memory: 0, since: "", procs: [] };
    const names = app.kind === "external" ? [app.name] : procsOf(app).map((p) => p.name || app.name);
    const procs = units.map((u, i) => {
      const p = shown.get(u) ?? {};
      const mem = Number(p.MemoryCurrent);
      return { name: names[i]!, active: p.ActiveState || "unknown", memory: Number.isFinite(mem) ? mem : 0, since: p.ActiveEnterTimestamp ?? "" };
    });
    const down = procs.find((p) => p.active !== "active");
    return { active: down?.active ?? "active", memory: procs.reduce((n, p) => n + p.memory, 0), since: procs[0]!.since, procs };
  });
}

export const appStatus = async (app: App): Promise<AppStatus> => (await appStatuses([app]))[0]!;

export async function appLogs(name: string, lines = 200): Promise<string> {
  const app = mustGet(name);
  const n = v.int(lines, 10, 5000, "lines");
  const pm2 = parsePm2Ref(app.external_unit);
  if (pm2) return pm2Logs(pm2, n);
  const units = activeUnits(app);
  if (!units.length) return "";
  const r = await run(["journalctl", ...units.flatMap((u) => ["-u", u]), "-n", String(n), "--no-pager", "-o", "short-iso"], { check: false });
  return r.stdout;
}

// ---- env and deploy key ----------------------------------------------------

/**
 * production: the app's own variables (read by the app, group-readable).
 * preview: values only previews get (a test Stripe key, a staging database); root-only, the app never reads them.
 */
export type EnvScope = "production" | "preview";
const envFile = (name: string, scope: EnvScope) => `${appHome(name)}/shared/${scope === "preview" ? ".env.preview" : ".env"}`;

export async function getEnv(name: string, scope: EnvScope = "production"): Promise<Record<string, string>> {
  mustGet(name);
  return parseEnv((await readText(envFile(name, scope))) ?? "");
}

export async function setEnv(name: string, vars: Record<string, string>, actor: string, scope: EnvScope = "production") {
  mustGet(name);
  if (scope === "preview") await writeAtomic(envFile(name, scope), formatEnv(vars), 0o600);
  else {
    await writeAtomic(envFile(name, scope), formatEnv(vars), 0o640);
    await run(["chgrp", appUser(name), fsPath(envFile(name, scope))], { check: false });
  }
  audit(actor, "app.env", { name, scope, keys: Object.keys(vars) });
}

/** What the app's processes get: its shared variable groups in order, then its own variables. */
export async function effectiveEnv(app: App): Promise<Record<string, string>> {
  const groups = await Promise.all(groupList(app.env_groups ?? "").map((g) => readGroup(g).catch(() => ({}))));
  return mergeEnv(groups, parseEnv((await readText(envFile(app.name, "production"))) ?? ""));
}

/** Read-only deploy key for private repositories (add it to the repo, not to an account). */
export async function deployKey(name: string): Promise<string> {
  mustGet(name);
  const key = `${appHome(name)}/.ssh/id_ed25519`;
  if (!(await exists(key))) {
    await run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", `pano-${name}`, "-f", fsPath(key)], { user: appUser(name) });
  }
  // Read as the app's user: .ssh is the app's, so the .pub could be a link to a root-only file.
  const pub = await run(["cat", "--", fsPath(`${key}.pub`)], { user: appUser(name), check: false });
  const line = pub.stdout.trim();
  return /^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( [ -~]*)?$/.test(line) ? line : "";
}

// ---- deploy ----------------------------------------------------------------

let buildQueue: Promise<unknown> = Promise.resolve();

/** Starts a deploy in the background and returns its id. Builds run one at a time. */
export function startDeploy(name: string, trigger: string, actor: string): number {
  const app = mustGet(name);
  if (app.kind !== "managed") throw new Error("external apps are deployed by their own tooling");
  assertNotSuspended(app);
  if (deploys.running(name)) throw new Error("a deploy is already running for this app");
  const id = enqueueDeploy(app, appTarget(name), trigger);
  audit(actor, "app.deploy", { name, id, trigger });
  return id;
}

/**
 * Where a deploy keeps its state. A real app lives in the apps table; a preview (previews.ts)
 * is deployed by the same code as a synthetic app and keeps its state in its own row.
 */
export type DeployTarget = {
  /** latest state, null when it was removed while the build ran */
  get(): App | null;
  update(patch: Partial<App>): void;
  /** releases kept on disk */
  keep: number;
  /** no alert for a failed build */
  quiet?: boolean;
  /** runs once the home exists, before the build reads its env file */
  prepare?(): Promise<void>;
  report(app: App, sha: string, state: "pending" | "success" | "failure", description: string): void;
};

const appTarget = (name: string): DeployTarget => ({
  get: () => apps.get(name),
  update: (patch) => apps.update(name, patch),
  keep: 2,
  report: (app, sha, state, description) => void reportStatus(app, sha, state, description),
});

/** Queues a build (one at a time) and returns the deploy id. */
export function enqueueDeploy(app: App, target: DeployTarget, trigger: string): number {
  // A preview carries its parent's suspension (previewApp).
  if (app.suspended) throw new Error("the app is suspended: resume it before you deploy");
  if (deploys.running(app.name)) throw new Error("a deploy is already running for this app");
  const id = deploys.start(app.name, trigger);
  buildQueue = buildQueue.then(() => deploy(app, id, target)).catch(() => {});
  return id;
}

async function deploy(app: App, id: number, target: DeployTarget) {
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
  let binPath = await toolPath(app);
  let commit = "";
  let builtEnv = "";

  try {
    await ensureAppHome(app.name); // brings homes made before the root-owned layout up to date
    await target.prepare?.();
    if (!(await exists(runtimeBin(app.runtime, app.runtime_version)))) {
      throw new Error(`${app.runtime} ${app.runtime_version} is not installed (Runtimes page)`);
    }
    if (app.runtime !== "bun" && !(await installed()).some((r) => r.runtime === "bun")) {
      await step("install bun (package manager)");
      const { bun } = await available();
      if (!bun[0]) throw new Error("cannot reach github.com to fetch bun");
      await installRuntime("bun", bun[0], log);
      binPath = await toolPath(app);
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
    target.report(app, sha, "pending", `Deploying (deploy ${id})`);
    // Every process directory sees the shared .env (Next.js reads it from its own directory).
    for (const d of new Set(procs.map((p) => (p.dir ? `${workdir}/${p.dir}` : workdir)))) {
      await run(["ln", "-sfn", fsPath(`${home}/shared/.env`), fsPath(`${d}/.env`)], { user, check: false });
    }

    const plan = await detectPlan(app, workdir);
    // One Next.js build cache per process, outside the releases: faster rebuilds, no copy per release.
    // An isolated build cannot reach it and starts empty.
    for (const p of app.build_isolated ? [] : procs) {
      const d = p.dir ? `${workdir}/${p.dir}` : workdir;
      if (!(await readText(`${d}/package.json`))?.includes('"next"')) continue;
      // cache/ is the app's: created as the app, never chmod'ed by root through a path it can swap.
      await run(["install", "-d", "-m", "0750", fsPath(`${home}/cache/next-${p.name || "main"}`)], { user });
      await run(["mkdir", "-p", "-m", "0750", fsPath(`${d}/.next`)], { user }); // inside the repo: as the app, never as root
      await run(["ln", "-sfn", fsPath(`${home}/cache/next-${p.name || "main"}`), fsPath(`${d}/.next/cache`)], { user, check: false });
    }
    if (plan.install) {
      await step(plan.install);
      await sandbox(app, ["/bin/sh", "-c", plan.install], { cwd: workdir, env: { PATH: binPath }, onLine: log, envFile: false, release: dir });
    }
    // What this build and the new processes read; compared later to tell what a restart or redeploy would change.
    builtEnv = envSnapshot(await effectiveEnv(app));
    if (plan.build) {
      await step(plan.build);
      await sandbox(app, ["/bin/sh", "-c", plan.build], { cwd: workdir, env: { PATH: binPath, NODE_ENV: "production" }, onLine: log, envFile: true, release: dir });
    }
    // An isolated build's caches go with it; installed packages stay (hard links).
    if (app.build_isolated) await removeAs(isolatedCache(dir), user);
    if (!app.processes.length && plan.start !== app.start_cmd) {
      target.update({ start_cmd: plan.start });
      app = target.get()!;
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
    const now = target.get();
    if (!now) throw new Error("removed while it was building");
    // Suspended while it was building: never switch traffic to it (the failure path stops the new slot).
    if (now.suspended) throw new Error("suspended while it was building");
    target.update({ active_slot: slot, current_release: release, env_running: builtEnv, env_built: builtEnv });
    await run(["ln", "-sfn", fsPath(`${home}/slot-${slot}`), fsPath(`${home}/current`)]);
    await writeCrons(target.get()!);
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
    await pruneReleases(app.name, [release], target.keep);
    await log(`\ndeploy ${id} done: ${release} (${sha.slice(0, 7)})`);
    deploys.finish(id, { status: "success", commit_sha: sha, release });
    target.report(app, sha, "success", `Live: release ${release}`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await log(`\nFAILED: ${msg}`);
    if (target.get()?.active_slot !== slot) {
      await run(["systemctl", "stop", ...procs.map((p) => unitName(app.name, p, slot))], { check: false });
      // A release that never went live is only disk space.
      await removeAs(dir, user).catch(() => {});
    }
    deploys.finish(id, { status: "failed", error: msg.slice(0, 500) });
    if (!target.quiet) void notify(`🔴 deploy of ${app.name} failed: ${msg.slice(0, 300)}`);
    // Fixed text only: the error carries build output (it may print env values), and a commit status
    // is visible to everyone who can see the commit (anyone, on a public repository).
    if (commit) target.report(app, commit, "failure", `Deploy ${id} failed (log in pano)`);
  }
}

/** Caches of an isolated build, inside its release; deleted when the build is done. */
const isolatedCache = (release: string) => `${release}/.pano-build`;

/**
 * Runs a deploy step as the app user inside a transient, memory-capped systemd sandbox.
 * With the app's build_isolated and a release, the step can write only that release and
 * cannot see the rest of the home (deploy key, data, env file, shared caches).
 */
async function sandbox(app: App, cmd: string[], o: RunOptions & { envFile?: boolean; release?: string }) {
  const home = appHome(app.name);
  const isolated = !!app.build_isolated && !!o.release;
  const cache = isolated ? isolatedCache(o.release!) : `${home}/cache`;
  const props = [
    `User=${appUser(app.name)}`,
    `Group=${appUser(app.name)}`,
    `WorkingDirectory=${o.cwd ?? home}`,
    `MemoryMax=${Math.max(app.memory_mb, 2048)}M`,
    "RuntimeMaxSec=1800",
    // Builds yield to the sites that are serving traffic.
    ...LOW.trim().split("\n"),
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    ...(isolated
      ? [`ReadWritePaths=${o.release}`, `InaccessiblePaths=-${home}/.ssh -${home}/data -${home}/shared -${home}/cache -${home}/run`]
      : [`ReadWritePaths=${home}`]),
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "RestrictSUIDSGID=yes",
    "CapabilityBoundingSet=",
    "UMask=0027",
    "ProtectKernelLogs=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "RestrictRealtime=yes",
    "RestrictNamespaces=yes",
    "LockPersonality=yes",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
    // Same as the running app: no cloud metadata, no other processes, ordinary syscalls only.
    "IPAddressDeny=169.254.169.254/32",
    "ProtectProc=invisible",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallErrorNumber=ENOSYS",
    // The install step runs third-party scripts (postinstall); it never sees the
    // app's secrets or data: both directories are empty there (a linked .env just
    // goes missing). Only the build gets the env (frameworks inline it).
    // systemd reads the env files itself, so an isolated build gets them without seeing the directory.
    ...(o.envFile
      ? [...groupEnvLines(app).split("\n").filter(Boolean), `EnvironmentFile=-${home}/shared/.env`]
      : isolated
        ? []
        : [`TemporaryFileSystem=${home}/shared:ro ${home}/data:ro`]),
  ];
  const env = {
    HOME: isolated ? cache : home,
    CI: "1",
    NEXT_TELEMETRY_DISABLED: "1",
    npm_config_cache: `${cache}/npm`,
    BUN_INSTALL_CACHE_DIR: `${cache}/bun`,
    // bun and pnpm hard-link packages from these stores: node_modules of each release costs almost no disk.
    npm_config_store_dir: `${cache}/pnpm`,
    XDG_CACHE_HOME: cache,
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
/**
 * Read as root from a repository: a package.json that is a link (to /etc/shadow, a FIFO) is
 * not followed, and a broken one says only that, never a piece of what it holds.
 */
async function readPkg(dir: string): Promise<Pkg> {
  let fh: FileHandle | undefined;
  try {
    fh = await open(fsPath(`${dir}/package.json`), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = await fh.stat();
    if (!st.isFile() || st.size > 1024 * 1024) return {};
    return JSON.parse(await fh.readFile("utf8")) as Pkg;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code) return {};
    throw new Error(`${dir}/package.json is not valid JSON`);
  } finally {
    await fh?.close();
  }
}

/** Fills in commands the admin left empty, based on the repository's lockfile and scripts. */
export async function detectPlan(app: Pick<App, "install_cmd" | "build_cmd" | "start_cmd" | "runtime">, workdir: string): Promise<Plan> {
  const has = (f: string) => exists(`${workdir}/${f}`);
  const scripts = (await readPkg(workdir)).scripts ?? {};
  // bun is the package manager for every app, also Node.js ones (they still run on node).
  // It reads package-lock.json, yarn.lock and pnpm-lock.yaml and keeps their exact versions,
  // and hard-links packages from its store, so each release costs almost no disk.
  const pm = "bun";
  const install = (await has("bun.lock")) || (await has("bun.lockb")) ? "bun install --frozen-lockfile" : "bun install";
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
  // A plain start script runs directly (no package manager process kept in memory next to the app).
  if (scripts.start) return /\b(npm|npx|yarn|pnpm|bun)\b|&&|\|\|/.test(scripts.start) ? `${pm} run start` : scripts.start;
  return runtime === "bun" ? "bun run index.ts" : "node server.js";
}

/** Every process listening on the port is in the unit's cgroup. */
async function listenerIsUnit(port: number, unit: string): Promise<boolean> {
  const r = await run(["ss", "-Htlnp", `sport = :${port}`], { check: false });
  const pids = [...new Set([...r.stdout.matchAll(/pid=(\d+)/g)].map((m) => m[1]!))];
  if (!pids.length) return false;
  for (const pid of pids) {
    const cgroup = (await readText(`/proc/${pid}/cgroup`)) ?? "";
    if (!cgroup.split("\n").some((l) => l.endsWith(`/${unit}`))) return false;
  }
  return true;
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
        // Another app's user could have bound this idle slot port first; its answer must not put it live.
        if (!(await listenerIsUnit(port, unitName(app.name, p, slot)))) throw new Error(`port ${port} is answered by a process outside ${unitName(app.name, p, slot)}`);
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

/** The live release, the one before it (instant rollback) and anything a slot still points at. */
async function pruneReleases(name: string, keepAlso: string[], keep = 2) {
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
  // releases/ is the app's: deleted as its user.
  for (const rel of all.slice(keep)) if (!linked.has(rel)) await removeAs(`${dir}/${rel}`, appUser(name));
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
