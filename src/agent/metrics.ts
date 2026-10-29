// Metrics history: once a minute the agent reads /proc and /sys/fs/cgroup (small
// files, no subprocess) and stores one narrow row per value. Minute points are
// kept 48 hours; a rollup turns them into 15-minute averages kept 30 days, so the
// table stays a few tens of thousands of rows however long the server runs.

import type { Database } from "bun:sqlite";
import { readFileSync, statSync, statfsSync } from "node:fs";
import { loadavg } from "node:os";
import { fsPath, paths } from "../shared/config.ts";
import { activeUnits } from "./apps.ts";
import { apps, state } from "./state.ts";

export const RANGES = { "1h": 3600, "24h": 86_400, "7d": 7 * 86_400, "30d": 30 * 86_400 } as const;
export type Range = keyof typeof RANGES;
/** Seconds per returned point: keeps every chart at 60 to 360 points. */
const STEPS: Record<Range, number> = { "1h": 60, "24h": 300, "7d": 1800, "30d": 7200 };

const FINE = 60;
const COARSE = 900;
const KEEP_FINE = 48 * 3600;
const KEEP_COARSE = 30 * 86_400;

export type Point = [ts: number, value: number];
export type History = { range: Range; from: number; to: number; step: number; series: Record<string, Point[]> };

// ---- parsing (pure) ----------------------------------------------------------

/** First line of /proc/stat: total and idle jiffies. */
export function parseCpuStat(text: string): { total: number; idle: number } | null {
  const f = text.split("\n", 1)[0]?.trim().split(/\s+/);
  if (!f || f[0] !== "cpu" || f.length < 5) return null;
  const n = f.slice(1, 9).map(Number);
  if (n.some((x) => !Number.isFinite(x))) return null;
  return { total: n.reduce((a, b) => a + b, 0), idle: (n[3] ?? 0) + (n[4] ?? 0) };
}

export function parseMeminfo(text: string) {
  const kb = (k: string) => Number(text.match(new RegExp(`^${k}:\\s+(\\d+)`, "m"))?.[1] ?? 0) * 1024;
  return { total: kb("MemTotal"), available: kb("MemAvailable"), swapTotal: kb("SwapTotal"), swapFree: kb("SwapFree") };
}

const VIRTUAL_IF = /^(lo|veth|docker|br-|virbr|cni|flannel|cali|tun|tap|wg)/;

/** Bytes received and sent on real network interfaces (containers' and tunnels' own links would count traffic twice). */
export function parseNetDev(text: string): { rx: number; tx: number } {
  let rx = 0;
  let tx = 0;
  for (const line of text.split("\n").slice(2)) {
    const [name, rest] = line.split(":");
    if (!rest || VIRTUAL_IF.test(name!.trim())) continue;
    const f = rest.trim().split(/\s+/).map(Number);
    rx += f[0] || 0;
    tx += f[8] || 0;
  }
  return { rx, tx };
}

export const parseCgroupCpu = (text: string): number | null => {
  const m = text.match(/^usage_usec\s+(\d+)/m);
  return m ? Number(m[1]) : null;
};

// ---- one sample ----------------------------------------------------------------

export type Disk = { mount: string; used: number; total: number };
export type Prev = { at: number; cpu?: { total: number; idle: number }; net?: { rx: number; tx: number }; apps: Record<string, number> };
export type Input = {
  /** text of a file, null when it does not exist */
  read: (path: string) => string | null;
  disks: Disk[];
  apps: { name: string; units: string[] }[];
  load1: number;
};

/**
 * Turns the current readings into values. Rates (cpu, network, per-app cpu) need
 * the previous reading, so the first sample after a start has none; a counter that
 * went backwards (reboot, restarted unit) is skipped rather than drawn as a spike.
 */
export function collect(input: Input, prev: Prev | null, nowMs: number): { values: Record<string, number>; next: Prev } {
  const values: Record<string, number> = { load1: input.load1 };
  const next: Prev = { at: nowMs, apps: {} };
  const secs = prev ? (nowMs - prev.at) / 1000 : 0;

  const cpu = parseCpuStat(input.read("/proc/stat") ?? "");
  if (cpu) {
    next.cpu = cpu;
    if (prev?.cpu && cpu.total > prev.cpu.total) {
      values.cpu = Math.min(100, Math.max(0, (1 - (cpu.idle - prev.cpu.idle) / (cpu.total - prev.cpu.total)) * 100));
    }
  }

  const mem = input.read("/proc/meminfo");
  if (mem) {
    const m = parseMeminfo(mem);
    values.mem = m.total - m.available;
    values.memtotal = m.total;
    values.swap = m.swapTotal - m.swapFree;
    values.swaptotal = m.swapTotal;
  }

  const netText = input.read("/proc/net/dev");
  if (netText) {
    const net = parseNetDev(netText);
    next.net = net;
    if (prev?.net && secs > 0 && net.rx >= prev.net.rx && net.tx >= prev.net.tx) {
      values.rx = (net.rx - prev.net.rx) / secs;
      values.tx = (net.tx - prev.net.tx) / secs;
    }
  }

  for (const d of input.disks) {
    values[`disk:${d.mount}`] = d.used;
    values[`disktotal:${d.mount}`] = d.total;
  }

  for (const a of input.apps) {
    let mems = 0;
    let usec = 0;
    let seen = 0;
    for (const unit of a.units) {
      const dir = `/sys/fs/cgroup/system.slice/${unit}`;
      const m = input.read(`${dir}/memory.current`);
      if (m === null) continue;
      seen++;
      mems += Number(m) || 0;
      usec += parseCgroupCpu(input.read(`${dir}/cpu.stat`) ?? "") ?? 0;
    }
    if (!seen) continue;
    values[`app:${a.name}:mem`] = mems;
    next.apps[a.name] = usec;
    const before = prev?.apps[a.name];
    if (before !== undefined && secs > 0 && usec >= before) values[`app:${a.name}:cpu`] = ((usec - before) / (secs * 1e6)) * 100;
  }
  return { values, next };
}

// ---- storage (db is a parameter so tests can use :memory:) -------------------------

export function store(db: Database, ts: number, values: Record<string, number>) {
  const ins = db.query("INSERT OR REPLACE INTO metrics (res, key, ts, value) VALUES (?, ?, ?, ?)");
  db.transaction(() => {
    for (const [k, v] of Object.entries(values)) if (Number.isFinite(v)) ins.run(FINE, k, ts, v);
  })();
}

/** Averages the finished 15-minute buckets that are not rolled up yet, then drops what is past its retention. Safe to repeat. */
export function rollup(db: Database, now: number) {
  const end = Math.floor(now / COARSE) * COARSE;
  const last = (db.query("SELECT MAX(ts) AS t FROM metrics WHERE res = ?").get(COARSE) as { t: number | null }).t;
  db.query(
    `INSERT OR REPLACE INTO metrics (res, key, ts, value)
     SELECT ${COARSE}, key, ts / ${COARSE} * ${COARSE}, AVG(value) FROM metrics
     WHERE res = ${FINE} AND ts >= ? AND ts < ? GROUP BY key, ts / ${COARSE}`,
  ).run(last === null ? 0 : last + COARSE, end);
  db.query("DELETE FROM metrics WHERE res = ? AND ts < ?").run(FINE, now - KEEP_FINE);
  db.query("DELETE FROM metrics WHERE res = ? AND ts < ?").run(COARSE, now - KEEP_COARSE);
}

/** Averages points into buckets of `step` seconds (bucket start as the timestamp). */
export function downsample(points: Point[], step: number): Point[] {
  const out: Point[] = [];
  let bucket = -1;
  let sum = 0;
  let n = 0;
  const flush = () => n && out.push([bucket, sum / n]);
  for (const [ts, v] of [...points].sort((a, b) => a[0] - b[0])) {
    const b = Math.floor(ts / step) * step;
    if (b !== bucket) {
      flush();
      bucket = b;
      sum = 0;
      n = 0;
    }
    sum += v;
    n++;
  }
  flush();
  return out;
}

export function history(db: Database, range: Range, app: string | undefined, now: number): History {
  const from = now - RANGES[range];
  const step = STEPS[range];
  const keys = app ? [`app:${app}:mem`, `app:${app}:cpu`] : null;
  const filter = keys ? ` AND key IN (${keys.map(() => "?").join(",")})` : " AND key NOT LIKE 'app:%'";
  // Past the minute data's reach the series comes from the 15-minute averages, plus the minutes not rolled up yet.
  const cut = RANGES[range] > KEEP_FINE / 2 ? Math.floor(now / COARSE) * COARSE : from;
  const q = (res: number, lo: number, hi: number) =>
    db.query(`SELECT key, ts, value FROM metrics WHERE res = ? AND ts >= ? AND ts < ?${filter}`).all(res, lo, hi, ...(keys ?? [])) as { key: string; ts: number; value: number }[];
  const rows = cut > from ? [...q(COARSE, from, cut), ...q(FINE, cut, now + 1)] : q(FINE, from, now + 1);
  const raw: Record<string, Point[]> = {};
  for (const r of rows) (raw[r.key] ??= []).push([r.ts, r.value]);
  const series: Record<string, Point[]> = {};
  for (const [k, pts] of Object.entries(raw)) series[k] = downsample(pts, step);
  return { range, from, to: now, step, series };
}

// ---- sampler -------------------------------------------------------------------

const read = (path: string): string | null => {
  try {
    return readFileSync(fsPath(path), "utf8");
  } catch {
    return null;
  }
};

/** Root, the data directory and the app directory; mounts that are one filesystem count once. */
function disks(): Disk[] {
  const out: Disk[] = [];
  const seen = new Set<number>();
  for (const mount of ["/", paths.data, paths.apps]) {
    try {
      const real = fsPath(mount);
      const dev = statSync(real).dev;
      if (seen.has(dev)) continue;
      seen.add(dev);
      const s = statfsSync(real);
      out.push({ mount, used: (s.blocks - s.bfree) * s.bsize, total: (s.blocks - s.bfree + s.bavail) * s.bsize });
    } catch {
      // not mounted here (development machine): no point
    }
  }
  return out;
}

let prev: Prev | null = null;
let lastRollup = -1;

export function sampleOnce(nowMs = Date.now()) {
  const db = state();
  const list = apps.list().map((a) => ({ name: a.name, units: activeUnits(a) }));
  const { values, next } = collect({ read, disks: disks(), apps: list, load1: loadavg()[0] ?? 0 }, prev, nowMs);
  prev = next;
  const ts = Math.round(nowMs / 1000 / FINE) * FINE;
  store(db, ts, values);
  const bucket = Math.floor(ts / COARSE);
  if (bucket !== lastRollup) {
    rollup(db, ts);
    lastRollup = bucket;
  }
}

export function startMetrics() {
  const tick = () => {
    try {
      sampleOnce();
    } catch (e) {
      console.error(`[agent] metrics: ${e}`);
    }
  };
  tick();
  setInterval(tick, FINE * 1000);
}

export const metricsHistory = (range: Range, app?: string): History => history(state(), range, app, Math.floor(Date.now() / 1000));
