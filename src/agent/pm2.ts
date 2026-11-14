// Apps PM2 runs (adopted, not deployed by pano): status, logs and a zero-downtime reload.
// Read through `pm2 jlist` as the owner. jlist also carries every process's environment
// (secrets): only names, pids, ports, memory and log paths are kept, nothing else leaves here.

import { readText, run } from "./sys.ts";

export type Pm2Ref = { user: string; name: string };
export type Pm2App = {
  name: string;
  pids: number[];
  online: number;
  total: number;
  memory: number;
  /** ms since epoch the oldest online instance started */
  since: number;
  restarts: number;
  port: number;
  mode: string;
  out: string;
  err: string;
};

const PM2_BINS = ["/usr/bin/pm2", "/usr/local/bin/pm2"];
const REF = /^pm2:([a-z_][a-z0-9_-]{0,31})\/([A-Za-z0-9._-]{1,64})$/;

export const parsePm2Ref = (unit: string): Pm2Ref | null => {
  const m = unit.match(REF);
  return m ? { user: m[1]!, name: m[2]! } : null;
};
export const pm2Ref = (r: Pm2Ref) => `pm2:${r.user}/${r.name}`;

async function home(user: string): Promise<string | null> {
  const line = (await readText("/etc/passwd"))?.split("\n").find((l) => l.startsWith(`${user}:`));
  return line?.split(":")[5] || null;
}

async function pm2(user: string, args: string[], timeoutMs = 15_000) {
  const h = await home(user);
  if (!h) throw new Error(`unknown user ${user}`);
  let bin = "";
  for (const b of PM2_BINS) if ((await run(["test", "-x", b], { check: false })).code === 0) bin = b;
  if (!bin) throw new Error("pm2 is not installed");
  return run(["env", `HOME=${h}`, `PM2_HOME=${h}/.pm2`, bin, ...args], { user, check: false, timeoutMs });
}

/** `-p 3000`, `--port 3000`, `--port=3000` in the start arguments, else PORT in its env. */
export function portOf(args: unknown, envPort: unknown): number {
  const a = Array.isArray(args) ? args.map(String) : typeof args === "string" ? args.split(/\s+/) : [];
  for (let i = 0; i < a.length; i++) {
    const eq = a[i]!.match(/^--port=(\d+)$/);
    if (eq) return Number(eq[1]);
    if ((a[i] === "-p" || a[i] === "--port") && /^\d+$/.test(a[i + 1] ?? "")) return Number(a[i + 1]);
  }
  return /^\d+$/.test(String(envPort ?? "")) ? Number(envPort) : 0;
}

/** Instances grouped by app name (cluster mode runs several); PM2 modules (logrotate) left out. */
export function parseJlist(json: string): Pm2App[] {
  const by = new Map<string, Pm2App>();
  for (const p of JSON.parse(json) as any[]) {
    const e = p?.pm2_env ?? {};
    if (e.pmx_module || typeof p?.name !== "string") continue;
    const a: Pm2App = by.get(p.name) ?? { name: p.name, pids: [], online: 0, total: 0, memory: 0, since: 0, restarts: 0, port: 0, mode: String(e.exec_mode ?? ""), out: String(e.pm_out_log_path ?? ""), err: String(e.pm_err_log_path ?? "") };
    a.total++;
    if (e.status === "online") {
      a.online++;
      if (p.pid) a.pids.push(Number(p.pid));
      const up = Number(e.pm_uptime);
      if (up && (!a.since || up < a.since)) a.since = up;
    }
    a.memory += Number(p.monit?.memory) || 0;
    a.restarts += Number(e.restart_time) || 0;
    a.port ||= portOf(e.args, e.env?.PORT ?? e.PORT);
    by.set(p.name, a);
  }
  return [...by.values()];
}

const cache = new Map<string, { at: number; list: Promise<Pm2App[]> }>();

/** One `pm2 jlist` per user every few seconds, however many pages ask. */
export function pm2List(user: string): Promise<Pm2App[]> {
  const hit = cache.get(user);
  if (hit && Date.now() - hit.at < 5_000) return hit.list;
  const list = pm2(user, ["jlist"]).then((r) => {
    if (r.code !== 0) throw new Error(r.stderr.trim().split("\n").at(-1) || "pm2 jlist failed");
    // pm2 may print a banner before the JSON on its first run.
    return parseJlist(r.stdout.slice(r.stdout.indexOf("[")));
  });
  cache.set(user, { at: Date.now(), list });
  list.catch(() => cache.delete(user));
  return list;
}

export async function pm2App(ref: Pm2Ref): Promise<Pm2App | null> {
  return (await pm2List(ref.user).catch(() => [])).find((a) => a.name === ref.name) ?? null;
}

/** Reload, never restart or stop: cluster apps swap instances one by one, the site stays up. */
export async function pm2Reload(ref: Pm2Ref) {
  const r = await pm2(ref.user, ["reload", ref.name], 300_000);
  cache.delete(ref.user);
  if (r.code !== 0) throw new Error(r.stderr.trim().split("\n").at(-1) || "pm2 reload failed");
}

/** The log path PM2 reports comes from the tenant's own daemon: only a file under <home>/.pm2/logs/ is read. */
export function pm2LogPath(home: string, file: string): boolean {
  const dir = `${home.replace(/\/+$/, "")}/.pm2/logs/`;
  return file.startsWith(dir) && file.length > dir.length && !file.includes("\0") && !file.split("/").includes("..");
}

export async function pm2Logs(ref: Pm2Ref, lines: number): Promise<string> {
  const a = await pm2App(ref);
  if (!a) return "";
  const h = await home(ref.user);
  if (!h) return "";
  const n = Math.max(1, Math.min(5000, Math.floor(Number(lines)) || 100));
  const out: string[] = [];
  for (const [label, file] of [["stdout", a.out], ["stderr", a.err]] as const) {
    if (!file || !pm2LogPath(h, file)) continue;
    // As the app's own user (what it cannot read, pano does not read for it), and a FIFO or a hung mount
    // cannot stall the page: tail is killed after a few seconds.
    const r = await run(["timeout", "-k", "1", "5", "tail", "-n", String(n), "--", file], { user: ref.user, check: false, timeoutMs: 10_000 });
    if (r.stdout.trim()) out.push(`==> ${label} (${file})\n${r.stdout}`);
  }
  return out.join("\n");
}
