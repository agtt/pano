// Runner (optional): heavy commands sent from a developer's machine (or a
// coding agent on it) run here instead. tools/pano-remote rsyncs the working
// tree into a workspace over SSH, asks for a command and streams its output
// back; build outputs, node_modules and the caches stay on the server, so the
// next run is incremental. SSH logs in as `pano-run` only with keys added on
// the Runner page and only into `pano run-shell` (forced command): rsync is
// held to the workspaces by rrsync, everything else is asked of the agent on a
// socket only that user can open. Each run is a transient systemd unit as
// pano-run: memory cap, time limit, low CPU priority, nothing of pano, the apps
// or other users in sight, of its own home only the workspaces and the cache,
// no service listening on this host reachable (nftables by uid).

import { createHash, randomBytes } from "node:crypto";
import { chmod, chown, readdir, stat, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import { EXIT, OUT, RRSYNC, RUN_USER, WORKSPACE, frame, runCache, runHome, runWorkspaces, runnerSocket } from "../shared/runner.ts";
import { ValidationError, v } from "../shared/validate.ts";
import { SDK, jdkDir } from "./android.ts";
import { LOW } from "./apps.ts";
import { installed as installedRuntimes, runtimeBin } from "./runtimes.ts";
import { audit, settings } from "./state.ts";
import { dirBytes, ensureDir, exists, lookupUser, readText, removeTree, run, writeAtomic } from "./sys.ts";
import { hardening } from "./throwaway.ts";

const KEYS = `${runHome}/.ssh/authorized_keys`;
const NET_UNIT = "pano-runner-net.service";
const NET_RULES = `${paths.etc}/runner.nft`;
const FORCED = `restrict,command="${paths.bin}/pano run-shell"`;
const KEY = /^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(?:256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) ([A-Za-z0-9+/]+={0,2})(?: ([ -~]{0,100}))?$/;

export type RunnerConfig = { memory_mb: number; timeout_min: number; parallel: number };
export type RunnerKey = { type: string; blob: string; comment: string; fingerprint: string; added: number };
export type RunRecord = { ws: string; cmd: string; started: number; seconds: number; code: number };

const DEFAULTS: RunnerConfig = { memory_mb: 8192, timeout_min: 60, parallel: 1 };

export const enabled = () => settings.get("runner.enabled") === "1";

export function runnerConfig(): RunnerConfig {
  try {
    return { ...DEFAULTS, ...JSON.parse(settings.get("runner.config") ?? "{}") };
  } catch {
    return DEFAULTS;
  }
}

function keys(): RunnerKey[] {
  try {
    return JSON.parse(settings.get("runner.keys") ?? "[]");
  } catch {
    return [];
  }
}

function recent(): RunRecord[] {
  try {
    return JSON.parse(settings.get("runner.recent") ?? "[]");
  } catch {
    return [];
  }
}

export function saveConfig(x: Record<string, unknown>, actor: string) {
  const c: RunnerConfig = {
    memory_mb: v.int(x.memory_mb ?? DEFAULTS.memory_mb, 1024, 65536, "memory"),
    timeout_min: v.int(x.timeout_min ?? DEFAULTS.timeout_min, 5, 360, "timeout"),
    parallel: v.int(x.parallel ?? DEFAULTS.parallel, 1, 8, "parallel runs"),
  };
  settings.set("runner.config", JSON.stringify(c));
  audit(actor, "runner.config", c);
  return c;
}

// ---- on / off, keys -----------------------------------------------------------------

export async function enableRunner(actor: string) {
  if (!(await rrsyncPath())) {
    const deb = await exists("/usr/bin/apt-get");
    await run(deb ? ["apt-get", "install", "-y", "rsync"] : ["dnf", "-y", "install", "rsync"], { timeoutMs: 600_000, env: { DEBIAN_FRONTEND: "noninteractive" } });
    if (!(await rrsyncPath())) throw new Error("rrsync not found: the runner needs rsync 3.2.4 or newer");
  }
  // A real shell (sshd runs the forced command through it) and no password at all ("*", not a locked "!").
  if ((await run(["id", "-u", RUN_USER], { check: false })).code !== 0) {
    await run(["useradd", "--system", "--home-dir", runHome, "--no-create-home", "--shell", "/bin/sh", RUN_USER]);
  }
  await run(["usermod", "-p", "*", "-s", "/bin/sh", RUN_USER]);
  // Home and .ssh root-owned (sshd accepts that; the user cannot add keys), the rest the user's.
  await ensureDir(runHome, 0o755);
  await ensureDir(`${runHome}/.ssh`, 0o755);
  await ensureDir(runWorkspaces, 0o700, RUN_USER);
  await ensureDir(runCache, 0o700, RUN_USER);
  await applyRunnerNet();
  await restrictPtrace();
  settings.set("runner.enabled", "1");
  await writeKeys();
  await startRunner();
  audit(actor, "runner.enable");
}

/** Removes every key (no SSH login any more) and stops what runs; workspaces and the cache stay until cleared. */
export async function disableRunner(actor: string) {
  settings.set("runner.enabled", "0");
  await writeKeys();
  for (const unit of units.values()) await stopUnit(unit);
  audit(actor, "runner.disable");
}

/**
 * Runs reach the internet and their own ephemeral ports (Gradle and Kotlin talk to their daemons
 * over loopback), never a service listening on this host: databases, Valkey, the panel, apps, the edge.
 * By uid, in the kernel, so nothing a run does can lift it; DNS stays reachable.
 */
export function renderRunnerNet(uid: number, ephemeralFrom: number): string {
  return [
    "table inet pano_runner",
    "delete table inet pano_runner",
    "table inet pano_runner {",
    "\tchain output {",
    "\t\ttype filter hook output priority 0; policy accept;",
    `\t\tmeta skuid != ${uid} accept`,
    "\t\tfib daddr type local meta l4proto { tcp, udp } th dport 53 accept",
    `\t\tfib daddr type local meta l4proto { tcp, udp } th dport < ${ephemeralFrom} reject`,
    "\t}",
    "}",
    "",
  ].join("\n");
}

async function applyRunnerNet() {
  const user = await lookupUser(RUN_USER);
  if (!user) throw new Error(`no ${RUN_USER} user`);
  const range = (await readText("/proc/sys/net/ipv4/ip_local_port_range")) ?? "";
  const from = Math.max(1024, Number(range.trim().split(/\s+/)[0]) || 32768);
  await writeAtomic(NET_RULES, renderRunnerNet(user.uid, from), 0o600);
  await run(["nft", "-c", "-f", NET_RULES]);
  await writeAtomic(
    `${paths.systemd}/${NET_UNIT}`,
    `[Unit]\nDescription=pano runner: runs cannot reach local services\nAfter=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=nft -f ${NET_RULES}\nExecReload=nft -f ${NET_RULES}\nExecStop=-nft delete table inet pano_runner\n\n[Install]\nWantedBy=multi-user.target\n`,
    0o644,
  );
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", NET_UNIT]);
  await run(["systemctl", "restart", NET_UNIT]);
}

/**
 * A run and the SSH side (rrsync, run-shell) share the pano-run uid. With Yama's ptrace scope 1
 * (Ubuntu's default) a process can only debug or write the memory of its own children, so a run
 * cannot take over the unsandboxed SSH side. Raised from 0 when the runner is turned on.
 */
async function restrictPtrace() {
  const scope = (await readText("/proc/sys/kernel/yama/ptrace_scope"))?.trim();
  if (scope == null) throw new Error("the kernel has no Yama LSM: the runner cannot keep runs from tracing the SSH side");
  if (scope !== "0") return;
  await writeAtomic("/etc/sysctl.d/60-pano-ptrace.conf", "# pano runner: no ptrace of processes that are not your children\nkernel.yama.ptrace_scope = 1\n", 0o644);
  await run(["sysctl", "-w", "kernel.yama.ptrace_scope=1"]);
}

export function parseKey(line: string): Omit<RunnerKey, "added"> {
  const s = line.trim();
  const m = /[\r\n]/.test(s) ? null : KEY.exec(s.replace(/[ \t]+/g, " "));
  if (!m) throw new ValidationError("paste one public key (ssh-ed25519 AAAA… comment)");
  const fingerprint = `SHA256:${createHash("sha256").update(Buffer.from(m[2]!, "base64")).digest("base64").replace(/=+$/, "")}`;
  return { type: m[1]!, blob: m[2]!, comment: m[3] ?? "", fingerprint };
}

export async function addKey(line: string, actor: string) {
  const k = parseKey(line);
  const all = keys().filter((x) => x.fingerprint !== k.fingerprint);
  if (all.length >= 20) throw new ValidationError("up to 20 keys");
  settings.set("runner.keys", JSON.stringify([...all, { ...k, added: Math.floor(Date.now() / 1000) }]));
  await writeKeys();
  audit(actor, "runner.key.add", { fingerprint: k.fingerprint, comment: k.comment });
}

export async function removeKey(fingerprint: string, actor: string) {
  settings.set("runner.keys", JSON.stringify(keys().filter((x) => x.fingerprint !== fingerprint)));
  await writeKeys();
  audit(actor, "runner.key.remove", { fingerprint });
}

/** Every key is held to run-shell (no shell, no forwarding, no pty); none at all while the runner is off. */
export function authorizedKeys(list: RunnerKey[], on: boolean): string {
  return on ? list.map((k) => `${FORCED} ${k.type} ${k.blob}${k.comment ? ` ${k.comment}` : ""}\n`).join("") : "";
}

async function writeKeys() {
  if (!(await exists(`${runHome}/.ssh`))) return;
  await writeAtomic(KEYS, authorizedKeys(keys(), enabled()), 0o644);
}

async function rrsyncPath(): Promise<string | null> {
  for (const p of RRSYNC) if (await exists(p)) return p;
  return null;
}

// ---- runs ----------------------------------------------------------------------------

/** Running units by workspace: one run per workspace at a time. */
const units = new Map<string, string>();
let active = 0;
const waiting: (() => void)[] = [];

/** A slot among `parallel`; false when the caller went away while waiting. */
function acquire(signal: AbortSignal): Promise<boolean> {
  if (active < runnerConfig().parallel) {
    active++;
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    const go = () => {
      signal.removeEventListener("abort", gone);
      resolve(true);
    };
    const gone = () => {
      const i = waiting.indexOf(go);
      if (i >= 0) waiting.splice(i, 1);
      resolve(false);
    };
    waiting.push(go);
    signal.addEventListener("abort", gone, { once: true });
  });
}

function release() {
  const next = waiting.shift();
  if (next) next();
  else active--;
}

async function stopUnit(unit: string) {
  await run(["systemctl", "stop", `${unit}.service`], { check: false, quiet: true });
}

/** PATH and toolchains a run finds: the Android SDK and JDK when installed, the newest Node.js and Bun pano has. */
async function runEnv(jdk: number): Promise<Record<string, string>> {
  const env: Record<string, string> = { HOME: runCache, LANG: "C.UTF-8", TERM: "dumb" };
  const path: string[] = [];
  if (await exists(jdkDir(jdk))) {
    env.JAVA_HOME = jdkDir(jdk);
    path.push(`${jdkDir(jdk)}/bin`);
  }
  if (await exists(SDK)) {
    env.ANDROID_HOME = SDK;
    env.ANDROID_SDK_ROOT = SDK;
    path.push(`${SDK}/platform-tools`);
  }
  const newest = (rt: "node" | "bun", list: { runtime: string; version: string }[]) =>
    list
      .filter((r) => r.runtime === rt)
      .map((r) => r.version)
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
      .at(-1);
  const rts = await installedRuntimes();
  for (const rt of ["node", "bun"] as const) {
    const ver = newest(rt, rts);
    if (ver) path.push(runtimeBin(rt, ver));
  }
  env.PATH = [...path, `${runCache}/.bun/bin`, "/usr/local/bin", "/usr/bin", "/bin"].join(":");
  return env;
}

export function runnerArgv(unit: string, ws: string, cmd: string, c: RunnerConfig, env: Record<string, string>): string[] {
  const dir = `${runWorkspaces}/${ws}`;
  const props = [
    `User=${RUN_USER}`,
    `Group=${RUN_USER}`,
    `WorkingDirectory=${dir}`,
    `MemoryMax=${c.memory_mb}M`,
    "MemorySwapMax=0",
    `RuntimeMaxSec=${c.timeout_min * 60}`,
    "TasksMax=8192",
    ...LOW.trim().split("\n"),
    ...hardening(true),
    // Of the runner's home only the workspaces and the cache; not the keys, not the agent's socket. The mount
    // sources are root-owned paths: a workspace the user swapped for a symlink cannot pull another directory
    // in (the working directory is entered inside the sandbox, where pano's paths do not exist).
    `TemporaryFileSystem=${runHome}:ro`,
    `BindPaths=${runWorkspaces} ${runCache}`,
    `InaccessiblePaths=-${dirname(runnerSocket)}`,
    "UMask=0022",
  ];
  return [
    "systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", `--unit=${unit}`,
    ...props.flatMap((p) => ["-p", p]),
    ...Object.entries(env).map(([k, val]) => `--setenv=${k}=${val}`),
    "--", "/bin/bash", "-c", cmd,
  ];
}

/** Streams a run's output as frames (shared/runner.ts); the last frame is its exit code. */
function runStream(ws: string, cmd: string, jdk: number, signal: AbortSignal): ReadableStream<Uint8Array> {
  let unit = "";
  return new ReadableStream({
    async start(ctl) {
      const send = (kind: number, data: Uint8Array | string) => {
        try {
          ctl.enqueue(frame(kind, data));
        } catch {}
      };
      const say = (s: string) => send(OUT, `pano: ${s}\n`);
      const onAbort = () => unit && stopUnit(unit);
      signal.addEventListener("abort", onAbort, { once: true });
      let code = 1;
      let slot = false;
      const started = Date.now();
      // Gradle can be quiet for minutes; an empty frame now and then keeps the connection from idling out.
      const beat = setInterval(() => send(OUT, new Uint8Array(0)), 5_000);
      try {
        if (units.has(ws)) throw new Error(`a run is already going in ${ws}`);
        unit = `pano-run-${ws.replace(/[^a-z0-9]/g, "-").slice(0, 40)}-${randomBytes(3).toString("hex")}`;
        units.set(ws, unit);
        if (active >= runnerConfig().parallel) say("waiting for a free slot…");
        slot = await acquire(signal);
        if (!slot) return;
        const c = runnerConfig();
        const dir = `${runWorkspaces}/${ws}`;
        const env = await runEnv(jdk);
        const argv = DRY_RUN ? ["/bin/bash", "-c", cmd] : runnerArgv(unit, ws, cmd, c, env);
        const proc = Bun.spawn(argv, { cwd: DRY_RUN ? fsPath(dir) : "/", stdin: "ignore", stdout: "pipe", stderr: "pipe", env: DRY_RUN ? { ...process.env, ...env } : { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8" } });
        const pump = async (s: ReadableStream<Uint8Array>) => {
          for await (const chunk of s) send(OUT, chunk);
        };
        await Promise.all([pump(proc.stdout), pump(proc.stderr)]);
        code = await proc.exited;
        const secs = Math.round((Date.now() - started) / 1000);
        if (code !== 0 && secs >= c.timeout_min * 60) say(`stopped after ${c.timeout_min} min (the Runner page sets the limit)`);
        else if (code === 137) say(`killed: over ${c.memory_mb} MB (the Runner page sets the limit), or stopped`);
      } catch (e) {
        say(e instanceof Error ? e.message : String(e));
      } finally {
        clearInterval(beat);
        signal.removeEventListener("abort", onAbort);
        if (units.get(ws) === unit) units.delete(ws);
        if (slot) release();
        record({ ws, cmd: cmd.slice(0, 200), started: Math.floor(started / 1000), seconds: Math.round((Date.now() - started) / 1000), code });
        send(EXIT, String(code));
        try {
          ctl.close();
        } catch {}
      }
    },
    cancel() {
      if (unit) stopUnit(unit);
    },
  });
}

function record(r: RunRecord) {
  settings.set("runner.recent", JSON.stringify([r, ...recent()].slice(0, 30)));
}

async function stopRun(ws: string) {
  const unit = units.get(ws);
  if (unit) await stopUnit(unit);
}

// ---- workspaces -----------------------------------------------------------------------

export async function workspaces(): Promise<{ name: string; bytes: number; modified: number; running: boolean }[]> {
  const names = await readdir(fsPath(runWorkspaces)).catch(() => [] as string[]);
  return Promise.all(
    names
      .filter((n) => WORKSPACE.test(n))
      .map(async (name) => ({
        name,
        bytes: await dirBytes(`${runWorkspaces}/${name}`),
        modified: Math.floor(((await stat(fsPath(`${runWorkspaces}/${name}`)).catch(() => null))?.mtimeMs ?? 0) / 1000),
        running: units.has(name),
      })),
  );
}

export async function cleanWorkspace(ws: string, actor: string) {
  if (!WORKSPACE.test(ws)) throw new ValidationError("bad workspace name");
  if (units.has(ws)) throw new Error("a run is going in this workspace");
  await removeTree(`${runWorkspaces}/${ws}`, RUN_USER);
  audit(actor, "runner.workspace.clean", { ws });
}

/** The shared download cache (Gradle, npm, bun); the next runs fill it again. */
export async function clearRunnerCache(actor: string) {
  if (units.size) throw new Error("wait until no run is going");
  await removeTree(runCache, RUN_USER);
  if (await lookupUser(RUN_USER)) await ensureDir(runCache, 0o700, RUN_USER);
  audit(actor, "runner.cache.clear");
}

export async function runnerStatus() {
  return {
    enabled: enabled(),
    config: runnerConfig(),
    keys: keys(),
    workspaces: await workspaces(),
    cacheBytes: await dirBytes(runCache),
    recent: recent(),
    running: [...units.keys()],
    host: (await run(["hostname", "-f"], { check: false })).stdout.trim() || "your-server",
    androidToolchain: await exists(SDK),
  };
}

// ---- the socket run-shell talks to ---------------------------------------------------------

let server: ReturnType<typeof Bun.serve> | null = null;

/** Listens when the runner is on (agent start, enable). Only root and pano-run can open the socket. */
export async function startRunner() {
  if (!enabled() || server) return;
  const user = await lookupUser(RUN_USER);
  if (!user && !DRY_RUN) return;
  await ensureDir(dirname(runnerSocket), 0o750);
  if (user && process.getuid?.() === 0) await chown(fsPath(dirname(runnerSocket)), 0, user.gid);
  const socket = fsPath(runnerSocket);
  await unlink(socket).catch(() => {});
  const umask = process.umask(0o077);
  server = Bun.serve({ unix: socket, maxRequestBodySize: 64 * 1024, fetch: handle });
  process.umask(umask);
  await chmod(socket, 0o660);
  if (user && process.getuid?.() === 0) await chown(socket, 0, user.gid);
}

async function handle(req: Request): Promise<Response> {
  const path = new URL(req.url).pathname;
  if (req.method !== "POST") return new Response("no", { status: 405 });
  if (!enabled()) return Response.json({ error: "the runner is off (Runner page)" }, { status: 403 });
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return Response.json({ error: "bad json" }, { status: 400 });
  }
  const ws = String(body.ws ?? "");
  try {
    switch (path) {
      case "/run": {
        if (!WORKSPACE.test(ws)) throw new ValidationError("bad workspace name");
        if (!(await exists(`${runWorkspaces}/${ws}`))) throw new ValidationError(`no workspace ${ws}: sync it first`);
        const cmd = String(body.cmd ?? "");
        if (!cmd.trim() || cmd.length > 8000) throw new ValidationError("command: 1-8000 characters");
        const jdk = Number(body.jdk ?? 17) === 21 ? 21 : 17;
        audit("runner", "runner.run", { ws, cmd: cmd.slice(0, 200) });
        return new Response(runStream(ws, cmd, jdk, req.signal), { headers: { "content-type": "application/octet-stream" } });
      }
      case "/stop":
        await stopRun(ws);
        return Response.json({ ok: true });
      case "/clean":
        await cleanWorkspace(ws, "runner");
        return Response.json({ ok: true });
      case "/ls":
        return Response.json({ workspaces: await workspaces(), running: [...units.keys()] });
      default:
        return Response.json({ error: "unknown" }, { status: 404 });
    }
  } catch (e) {
    return Response.json({ error: e instanceof Error ? e.message : String(e) }, { status: 400 });
  }
}
