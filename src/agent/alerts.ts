// Telegram alerts: failed deploys, crons and backups as they happen, plus a
// once-a-minute check of apps, services, disk and memory. Each problem is
// reported once when it starts and once when it clears, never in a loop.

import { hostname } from "node:os";
import { paths } from "../shared/config.ts";
import { apps, procsOf, settings } from "./state.ts";
import { ensureDir, readText, run, writeAtomic } from "./sys.ts";

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

const isActive = async (units: string[]) => {
  if (!units.length) return true;
  const r = await run(["systemctl", "is-active", ...units], { check: false });
  return r.stdout.trim().split("\n").every((s) => s === "active");
};

export async function checkOnce() {
  for (const a of apps.list()) {
    if (a.kind !== "managed" || !a.active_slot) continue;
    const units = procsOf(a).map((p) => `pano-app-${a.name}${p.name ? `_${p.name}` : ""}@${a.active_slot}.service`);
    await problem(`app:${a.name}`, !(await isActive(units)), `app ${a.name} is down`);
    for (const i of a.crons.keys()) {
      const r = await run(["systemctl", "show", `pano-cron-${a.name}-${i}.service`, "-p", "Result", "--value"], { check: false });
      const result = r.stdout.trim();
      await problem(`cron:${a.name}:${i}`, !!result && result !== "success", `cron ${a.name} #${i} (${a.crons[i]!.schedule}) failed: ${result}`);
    }
  }
  for (const [key, unit] of Object.entries(await watchedServices())) {
    await problem(`svc:${key}`, !(await isActive([unit])), `${key} is not running`);
  }
  const df = await run(["df", "-P", "/"], { check: false });
  const used = Number(df.stdout.trim().split("\n")[1]?.split(/\s+/)[4]?.replace("%", "") ?? 0);
  await problem("disk", used >= 85, `disk ${used}% full`);
  const mem = (await readText("/proc/meminfo")) ?? "";
  const kb = (k: string) => Number(mem.match(new RegExp(`^${k}:\\s+(\\d+)`, "m"))?.[1] ?? 0);
  const free = kb("MemTotal") ? kb("MemAvailable") / kb("MemTotal") : 1;
  await problem("memory", free < 0.05, `memory almost full (${Math.round(free * 100)}% available)`);
}

/** Services worth watching: the ones enabled on this server. */
async function watchedServices(): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const [key, val] of Object.entries({ edge: "pano-edge.service", vpn: "pano-vpn.service" })) {
    if ((await run(["systemctl", "is-enabled", val], { check: false })).stdout.trim() === "enabled") out[key] = val;
  }
  for (const key of ["mariadb", "postgres", "valkey"]) {
    const rec = JSON.parse(settings.get(`svc.${key}`) || "null") as { unit: string } | null;
    if (rec) out[key] = rec.unit;
  }
  return out;
}

export function startMonitor() {
  setInterval(() => checkOnce().catch((e) => console.error(`[agent] monitor: ${e}`)), 60_000);
}
