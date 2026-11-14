// Telegram alerts: failed deploys, crons and backups as they happen, plus a
// once-a-minute check of apps, services, disk and memory. Each problem is
// reported once when it starts and once when it clears, never in a loop.

import { hostname } from "node:os";
import { paths } from "../shared/config.ts";
import { failedJobs } from "./jobs.ts";
import { checkQueues } from "./queues.ts";
import { apps, procsOf, settings } from "./state.ts";
import { diskUsage, ensureDir, readText, run, showUnits, writeAtomic } from "./sys.ts";

const TOKEN_FILE = `${paths.secrets}/telegram.token`;

export async function alertSettings() {
  return { chatId: settings.get("alerts.chatId") ?? "", tokenSet: !!((await readText(TOKEN_FILE)) ?? "").trim() };
}

export async function saveAlerts(input: { token?: unknown; chatId?: unknown }) {
  const token = String(input.token ?? "").trim();
  const chatId = String(input.chatId ?? "").trim();
  if (token && !/^\d{5,15}:[A-Za-z0-9_-]{30,64}$/.test(token)) throw new Error("bot token looks like 123456:ABC… (from @BotFather)");
  if (chatId && !/^-?\d{3,20}$/.test(chatId)) throw new Error("chat id is a number");
  if (token) {
    await ensureDir(paths.secrets, 0o700);
    await writeAtomic(TOKEN_FILE, token + "\n", 0o600);
  }
  settings.set("alerts.chatId", chatId);
}

/** Never throws: an alert that cannot be sent must not break what reported it. */
export async function notify(text: string): Promise<boolean> {
  const token = ((await readText(TOKEN_FILE)) ?? "").trim();
  const chatId = settings.get("alerts.chatId") ?? "";
  if (!token || !chatId) return false;
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: `${hostname()} · ${text}`.slice(0, 4000), link_preview_options: { is_disabled: true } }),
      signal: AbortSignal.timeout(10_000),
    });
    return r.ok;
  } catch {
    return false;
  }
}

// ---- periodic checks -------------------------------------------------------------

const open = new Map<string, string>();

async function problem(key: string, bad: boolean, text: string) {
  if (bad && !open.has(key)) {
    open.set(key, text);
    await notify(`🔴 ${text}`);
  } else if (!bad && open.has(key)) {
    await notify(`✅ resolved: ${open.get(key)}`);
    open.delete(key);
  }
}

/** One `systemctl is-active` for every unit (it answers one line per unit, in order). */
async function activeStates(units: string[]): Promise<Map<string, boolean>> {
  if (!units.length) return new Map();
  const lines = (await run(["systemctl", "is-active", ...units], { check: false })).stdout.trim().split("\n");
  return new Map(units.map((u, i) => [u, lines[i] === "active"]));
}

export async function checkOnce() {
  const appUnits = apps
    .list()
    // A suspended app is stopped on purpose.
    .filter((a) => a.kind === "managed" && a.active_slot && !a.suspended)
    .map((a) => ({ name: a.name, units: procsOf(a).map((p) => `pano-app-${a.name}${p.name ? `_${p.name}` : ""}@${a.active_slot}.service`) }));
  const services = Object.entries(await watchedServices());
  const active = await activeStates([...appUnits.flatMap((a) => a.units), ...services.map(([, u]) => u)]);
  for (const a of appUnits) await problem(`app:${a.name}`, !a.units.every((u) => active.get(u)), `app ${a.name} is down`);
  for (const j of await failedJobs()) await problem(j.key, j.failed, j.text);
  await checkQueues(problem, notify);
  for (const [key, unit] of services) await problem(`svc:${key}`, !active.get(unit), `${key} is not running`);
  const disk = await diskUsage("/");
  const used = disk.used + disk.avail ? Math.round((disk.used / (disk.used + disk.avail)) * 100) : 0;
  await problem("disk", used >= 85, `disk ${used}% full`);
  const mem = (await readText("/proc/meminfo")) ?? "";
  const kb = (k: string) => Number(mem.match(new RegExp(`^${k}:\\s+(\\d+)`, "m"))?.[1] ?? 0);
  const free = kb("MemTotal") ? kb("MemAvailable") / kb("MemTotal") : 1;
  await problem("memory", free < 0.05, `memory almost full (${Math.round(free * 100)}% available)`);
}

/** Services worth watching: the ones enabled on this server. */
async function watchedServices(): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const own = { edge: "pano-edge.service", vpn: "pano-vpn.service" };
  const state = await showUnits(Object.values(own), ["UnitFileState"]);
  for (const [key, val] of Object.entries(own)) if (state.get(val)?.UnitFileState === "enabled") out[key] = val;
  for (const key of ["mariadb", "postgres", "valkey"]) {
    const rec = JSON.parse(settings.get(`svc.${key}`) || "null") as { unit: string } | null;
    if (rec) out[key] = rec.unit;
  }
  return out;
}

export function startMonitor() {
  setInterval(() => checkOnce().catch((e) => console.error(`[agent] monitor: ${e}`)), 60_000);
}
