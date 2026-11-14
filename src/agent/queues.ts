// Background job queues, on demand. Apps keep their own queue library (BullMQ,
// Laravel queues) and run workers as app processes; this reads the queues from
// Valkey/Redis once a minute while it is turned on and says when jobs start
// failing or a queue stops moving. Nothing runs or is installed until it is
// turned on; turning it on installs Valkey only if no Redis is on the server.

import { RedisClient } from "bun";
import { isWeb, unitName } from "./apps.ts";
import { appValkeyUrl, appValkeys } from "./appvalkey.ts";
import * as services from "./services.ts";
import { apps, audit, procsOf, settings } from "./state.ts";
import { run } from "./sys.ts";

export type Queue = {
  kind: "bullmq" | "laravel";
  /** the key prefix, e.g. "bull:emails" or "laravel_database_queues:default" */
  key: string;
  name: string;
  waiting: number;
  active: number;
  delayed: number;
  failed: number | null;
  completed: number | null;
  paused: boolean;
};

export type Worker = { app: string; process: string; unit: string; active: string; memory: number };

const enabled = () => settings.get("queues.enabled") === "1";
const MAX_QUEUES = 200;

async function connect(url: string): Promise<RedisClient> {
  const c = new RedisClient(url, { connectionTimeout: 3000, autoReconnect: false, maxRetries: 0, enableOfflineQueue: false });
  await c.connect();
  return c;
}

/**
 * Queues in the shared server and in every app's own Valkey; an app's queues
 * carry its name in front. The shared server must answer (queues were turned on
 * there); an app's instance that does not is skipped until the next look.
 */
async function readAll(): Promise<Queue[]> {
  const out: Queue[] = [];
  let c: RedisClient | null = null;
  try {
    // Not valkeyUrl(): the password must not go to whatever listens on 6379 while Valkey is down.
    c = await connect(await services.valkeyUrlChecked());
    out.push(...(await readQueues(c)));
  } finally {
    c?.close();
  }
  for (const { app } of appValkeys()) {
    const url = await appValkeyUrl(app);
    if (!url) continue;
    c = null;
    try {
      c = await connect(url);
      out.push(...(await readQueues(c)).map((q) => ({ ...q, key: `${app}/${q.key}`, name: `${app}/${q.name}` })));
    } catch {
      // stopped or restarting
    } finally {
      c?.close();
    }
  }
  return out;
}

/** Every key matching a pattern, without blocking the server (SCAN, never KEYS). */
async function scan(c: RedisClient, pattern: string, limit = 2000): Promise<string[]> {
  const out: string[] = [];
  let cursor = "0";
  do {
    const [next, keys] = (await c.send("SCAN", [cursor, "MATCH", pattern, "COUNT", "1000"])) as [string, string[]];
    out.push(...keys);
    cursor = String(next);
  } while (cursor !== "0" && out.length < limit);
  return out;
}

const n = (x: unknown) => Number(x ?? 0) || 0;

/** Reads BullMQ queues (prefix:name:meta hashes) and Laravel queues (…queues:name lists). */
export async function readQueues(c: RedisClient): Promise<Queue[]> {
  const out: Queue[] = [];
  for (const meta of (await scan(c, "*:meta")).slice(0, MAX_QUEUES)) {
    const key = meta.slice(0, -":meta".length);
    const [type, id, events] = await Promise.all([c.send("TYPE", [meta]), c.send("EXISTS", [`${key}:id`]), c.send("EXISTS", [`${key}:events`])]);
    if (type !== "hash" || !(n(id) || n(events))) continue;
    const [wait, paused, prio, active, delayed, failed, completed, flag] = await Promise.all([
      c.send("LLEN", [`${key}:wait`]),
      c.send("LLEN", [`${key}:paused`]),
      c.send("ZCARD", [`${key}:prioritized`]),
      c.send("LLEN", [`${key}:active`]),
      c.send("ZCARD", [`${key}:delayed`]),
      c.send("ZCARD", [`${key}:failed`]),
      c.send("ZCARD", [`${key}:completed`]),
      c.send("HGET", [meta, "paused"]),
    ]);
    out.push({
      kind: "bullmq",
      key,
      name: key.split(":").at(-1)!,
      waiting: n(wait) + n(paused) + n(prio),
      active: n(active),
      delayed: n(delayed),
      failed: n(failed),
      completed: n(completed),
      paused: flag === "1",
    });
  }
  for (const key of (await scan(c, "*queues:*")).slice(0, MAX_QUEUES)) {
    if (/:(delayed|reserved|notify)$/.test(key) || (await c.send("TYPE", [key])) !== "list") continue;
    const [wait, reserved, delayed] = await Promise.all([c.send("LLEN", [key]), c.send("ZCARD", [`${key}:reserved`]), c.send("ZCARD", [`${key}:delayed`])]);
    // Laravel keeps failed jobs in the database, not in Redis.
    out.push({ kind: "laravel", key, name: key.split(":").at(-1)!, waiting: n(wait), active: n(reserved), delayed: n(delayed), failed: null, completed: null, paused: false });
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}

/** App processes that serve no traffic: queue workers and other long-running background processes. */
export async function workers(): Promise<Worker[]> {
  const out: Worker[] = [];
  for (const a of apps.list()) {
    if (a.kind !== "managed" || !a.active_slot) continue;
    for (const p of procsOf(a).filter((p) => !isWeb(p))) {
      const unit = unitName(a.name, p, a.active_slot);
      const r = await run(["systemctl", "show", unit, "-p", "ActiveState", "-p", "MemoryCurrent"], { check: false });
      const get = (k: string) => r.stdout.match(new RegExp(`^${k}=(.*)$`, "m"))?.[1] ?? "";
      const mem = Number(get("MemoryCurrent"));
      out.push({ app: a.name, process: p.name, unit, active: get("ActiveState") || "unknown", memory: Number.isFinite(mem) && mem < 2 ** 60 ? mem : 0 });
    }
  }
  return out;
}

export async function queueStatus() {
  const store = (await services.status()).find((s) => s.key === "valkey")!;
  const base = { enabled: enabled(), store: { installed: store.installed, managed: store.managed, version: store.version, active: store.active }, workers: await workers() };
  if (!base.enabled) return { ...base, queues: [] as Queue[], error: "" };
  try {
    return { ...base, queues: await readAll(), error: "" };
  } catch (e) {
    return { ...base, queues: [] as Queue[], error: e instanceof Error ? e.message : String(e) };
  }
}

export async function setQueues(on: boolean, actor: string) {
  if (on && !(await services.status()).find((s) => s.key === "valkey")?.installed) await services.install("valkey", actor);
  settings.set("queues.enabled", on ? "1" : "0");
  audit(actor, "queues.set", { on });
}

export async function restartWorker(app: string, process: string, actor: string) {
  const w = (await workers()).find((x) => x.app === app && x.process === process);
  if (!w) throw new Error("no such worker");
  if (apps.get(app)?.suspended) throw new Error(`${app} is suspended: resume it first`);
  await run(["systemctl", "restart", w.unit]);
  audit(actor, "worker.restart", { app, process });
}

// ---- monitor -----------------------------------------------------------------------

type Seen = { failed: number; waiting: number; done: number; stuckSince: number | null; notifiedAt: number; pending: number };
const seen = new Map<string, Seen>();
const STUCK_MS = 10 * 60_000;
const QUIET_MS = 15 * 60_000;

/**
 * One look at the queues, from the alert monitor. New failures are reported at
 * most every 15 minutes per queue (summed); a queue with work waiting, nothing
 * active and nothing finishing for 10 minutes is a problem until it moves again.
 */
export async function checkQueues(
  problem: (key: string, bad: boolean, text: string) => Promise<void>,
  notify: (text: string) => Promise<unknown>,
  now = Date.now(),
) {
  if (!enabled()) return;
  let queues: Queue[];
  try {
    queues = await readAll();
  } catch (e) {
    await problem("queues:store", true, `queue store unreachable: ${e instanceof Error ? e.message : e}`);
    return;
  }
  await judge(queues, problem, notify, now);
  await problem("queues:store", false, "");
}

export async function judge(
  queues: Queue[],
  problem: (key: string, bad: boolean, text: string) => Promise<void>,
  notify: (text: string) => Promise<unknown>,
  now: number,
) {
  for (const q of queues) {
    const prev = seen.get(q.key);
    const done = (q.completed ?? 0) + (q.failed ?? 0);
    const s: Seen = prev ?? { failed: q.failed ?? 0, waiting: q.waiting, done, stuckSince: null, notifiedAt: -Infinity, pending: 0 };
    if (prev && q.failed !== null && q.failed > prev.failed) s.pending += q.failed - prev.failed;
    if (s.pending && now - s.notifiedAt >= QUIET_MS) {
      await notify(`🟠 queue ${q.name}: ${s.pending} job${s.pending > 1 ? "s" : ""} failed (${q.failed} in the failed list)`);
      s.notifiedAt = now;
      s.pending = 0;
    }
    const moving = q.active > 0 || done !== s.done || q.waiting < s.waiting || q.paused;
    s.stuckSince = q.waiting > 0 && !moving ? (s.stuckSince ?? now) : null;
    await problem(`queue:${q.key}`, s.stuckSince !== null && now - s.stuckSince >= STUCK_MS, `queue ${q.name}: ${q.waiting} jobs waiting and no worker taking them`);
    s.failed = q.failed ?? 0;
    s.waiting = q.waiting;
    s.done = done;
    seen.set(q.key, s);
  }
}
