// Reboots for kernel and core library updates: on request, or automatically in
// the night window of one chosen weekday (off by default).
//
// Before: a reboot must actually be needed (automatic only), nothing may be
// deploying, backing up or installing packages, /etc/fstab must have no errors
// (a bad entry stops the boot in emergency mode, with no network to fix it
// from), and nothing else may want the edge's ports at boot (tailscale serve on
// 443 starts before the edge and keeps it from listening).
//
// The new kernel is tried once: the running kernel stays the default and the
// new one boots through grub2-reboot, with panic=10 and rd.emergency=reboot so
// a panic or an initramfs that cannot mount root reboots into the old kernel
// instead of hanging. After the boot the new kernel becomes the default (or is
// remembered as bad), every enabled service that ran before is running again
// (restarted once if not), the edge listens on 80/443, and Telegram hears how
// it went.

import { paths } from "../shared/config.ts";
import { notify } from "./alerts.ts";
import { audit, settings, state } from "./state.ts";
import { exists, readText, run, writeAtomic } from "./sys.ts";

const PENDING = `${paths.data}/reboot.json`;
const SAFETY_ARGS = ["panic=10", "rd.emergency=reboot"];
const EDGE_UNIT = "pano-edge.service";

type Pending = {
  at: number;
  actor: string;
  /** running kernel and the one being tried ("" when the kernel does not change) */
  from: string;
  to: string;
  oldId: string;
  newId: string;
  /** kernel arguments added to the new kernel's entry for this boot only */
  added: string[];
  /** enabled services that were running before */
  units: string[];
};

// ---- settings ------------------------------------------------------------------------------------

export const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
export type RebootSettings = { auto: boolean; day: number };

export function rebootSettings(): RebootSettings {
  const day = Number(settings.get("reboot.day") ?? 0);
  return { auto: settings.get("reboot.auto") === "1", day: Number.isInteger(day) && day >= 0 && day <= 6 ? day : 0 };
}

export function setRebootSettings(next: { auto: boolean; day: unknown }, actor: string) {
  const day = Number(next.day);
  if (!Number.isInteger(day) || day < 0 || day > 6) throw new Error("reboot day must be 0 (Sunday) to 6 (Saturday)");
  settings.set("reboot.auto", next.auto ? "1" : "0");
  settings.set("reboot.day", String(day));
  audit(actor, "reboot.settings", { auto: next.auto, day });
}

// ---- is one needed -------------------------------------------------------------------------------

let cache: { at: number; value: boolean } | null = null;

/** Kernel, glibc, systemd and the like were updated since the boot. */
export async function rebootNeeded(): Promise<boolean> {
  const r = await run(["dnf", "needs-restarting", "-r"], { check: false, quiet: true });
  cache = { at: Date.now(), value: r.code === 1 };
  return r.code === 1;
}

// `dnf needs-restarting` starts the whole dnf (Python, package database): seconds on a busy
// server. Only updates change its answer, so the page reuses it for 10 minutes.
export async function rebootNeededCached(): Promise<boolean> {
  if (cache && Date.now() - cache.at < 600_000) return cache.value;
  return rebootNeeded().catch(() => false);
}

// ---- parsing (pure, tested) ----------------------------------------------------------------------

/** A field of `grubby --info` output: id="..." → ... */
export function grubbyField(info: string, key: string): string {
  return info.match(new RegExp(`^${key}="?([^"\\n]*)"?$`, "m"))?.[1]?.trim() ?? "";
}

export const kernelOf = (vmlinuz: string) => vmlinuz.trim().replace(/^.*\/vmlinuz-/, "");

/** `findmnt --verify` ends with "N parse errors, N errors, N warnings": warnings do not stop a boot. */
export function fstabErrors(out: string): number {
  const m = out.match(/(\d+) parse errors?, (\d+) errors?/);
  return m ? Number(m[1]) + Number(m[2]) : out.trim() ? 1 : 0;
}

/** `tailscale serve status --json`: does it claim 80 or 443 on the tailnet address? */
export function tailscaleTakesWebPorts(json: string): boolean {
  try {
    const tcp = (JSON.parse(json) as { TCP?: Record<string, unknown> }).TCP ?? {};
    return Object.keys(tcp).some((p) => p === "80" || p === "443");
  } catch {
    return false;
  }
}

/** First column of `systemctl list-units --plain --no-legend`. */
export const unitNames = (out: string) => out.split("\n").map((l) => l.trim().split(/\s+/)[0] ?? "").filter((u) => u.endsWith(".service"));

// ---- checks --------------------------------------------------------------------------------------

async function uptimeSec(): Promise<number> {
  return Number(((await readText("/proc/uptime")) ?? "0").split(" ")[0]) || 0;
}

function busyWork(): string {
  const q = (table: string) => (state().query(`SELECT count(*) AS n FROM ${table} WHERE status = 'running'`).get() as { n: number }).n;
  const parts = [
    [q("deploys"), "a deploy"],
    [q("backup_runs"), "a backup"],
    [q("android_builds"), "an Android build"],
  ].filter(([n]) => (n as number) > 0);
  return parts.length ? `${parts.map(([, what]) => what).join(", ")} is running` : "";
}

type Plan = { from: string; to: string; oldId: string; newId: string; add: string[] };

/** The kernel change, if any, and what it takes to try it once. */
async function kernelPlan(): Promise<Plan | string> {
  const from = (await run(["uname", "-r"])).stdout.trim();
  const def = await run(["grubby", "--default-kernel"], { check: false });
  if (def.code !== 0) return "grubby is not available, so the new kernel cannot be tried once with a way back";
  const to = kernelOf(def.stdout);
  if (!to || to === from) return { from, to: "", oldId: "", newId: "", add: [] };
  if (settings.get("reboot.badKernel") === to) return `kernel ${to} did not boot last time; it stays off until a newer one is installed`;
  if (!(await exists(`/boot/initramfs-${to}.img`))) return `kernel ${to} has no initramfs (/boot/initramfs-${to}.img)`;
  const [oldInfo, newInfo] = await Promise.all([
    run(["grubby", `--info=/boot/vmlinuz-${from}`], { check: false }),
    run(["grubby", `--info=/boot/vmlinuz-${to}`], { check: false }),
  ]);
  const oldId = grubbyField(oldInfo.stdout, "id");
  const newId = grubbyField(newInfo.stdout, "id");
  if (!oldId || !newId) return `no boot entry for kernel ${oldId ? to : from}, so there is no way back if the new kernel fails`;
  const args = grubbyField(newInfo.stdout, "args").split(/\s+/);
  return { from, to, oldId, newId, add: SAFETY_ARGS.filter((a) => !args.includes(a)) };
}

/** Why the server must not reboot now, or "" when it may. */
async function blocker(): Promise<string> {
  if ((await uptimeSec()) < 1800) return "the server started less than 30 minutes ago";
  const busy = busyWork();
  if (busy) return busy;
  if ((await run(["pgrep", "-x", "dnf|dnf-automatic|dnf-3|rpm|yum"], { check: false })).code === 0) return "packages are being installed";
  const fm = await run(["findmnt", "--verify"], { check: false });
  const errs = fstabErrors(`${fm.stdout}\n${fm.stderr}`);
  if (errs) return `/etc/fstab has ${errs} error(s) (findmnt --verify); the boot would stop in emergency mode`;
  const ts = await run(["tailscale", "serve", "status", "--json"], { check: false });
  if (ts.code === 0 && tailscaleTakesWebPorts(ts.stdout)) {
    return "tailscale serve uses port 80 or 443 and can take it before the edge at boot; move it (tailscale serve --bg --https=8443 <target>; tailscale serve --https=443 off)";
  }
  return "";
}

async function enabledRunning(): Promise<string[]> {
  const running = unitNames((await run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"])).stdout);
  if (!running.length) return [];
  const states = (await run(["systemctl", "is-enabled", ...running], { check: false })).stdout.split("\n");
  return running.filter((_, i) => states[i]?.trim() === "enabled");
}

// ---- reboot --------------------------------------------------------------------------------------

let rebooting = false;

/**
 * Reboot now if it is safe; throws with the reason when it is not.
 * `auto`: the nightly window, which also requires that an update needs it.
 */
export async function safeReboot(actor: string, auto = false): Promise<string> {
  if (rebooting || (await exists(PENDING))) throw new Error("a reboot is already under way");
  if (auto && !(await rebootNeeded())) throw new Error("no update needs a reboot");
  const why = await blocker();
  if (why) throw new Error(why);
  const plan = await kernelPlan();
  if (typeof plan === "string") throw new Error(plan);
  rebooting = true;
  try {
    const units = await enabledRunning();
    if (plan.to) {
      if (plan.add.length) await run(["grubby", `--update-kernel=/boot/vmlinuz-${plan.to}`, `--args=${plan.add.join(" ")}`]);
      await run(["grub2-set-default", plan.oldId]);
      await run(["grub2-reboot", plan.newId]);
      const env = (await run(["grub2-editenv", "list"])).stdout;
      if (!env.includes(`next_entry=${plan.newId}`)) {
        await undoKernel({ newId: plan.newId, to: plan.to, added: plan.add }, true);
        throw new Error("the one-time boot entry did not stick (grub2-editenv)");
      }
    }
    const pending: Pending = { at: Date.now(), actor, from: plan.from, to: plan.to, oldId: plan.oldId, newId: plan.newId, added: plan.add, units };
    await writeAtomic(PENDING, JSON.stringify(pending), 0o600);
    audit(actor, "reboot", { from: plan.from, to: plan.to || plan.from, auto });
    await notify(`🔁 rebooting${auto ? " (automatic window)" : ""}${plan.to ? `: kernel ${plan.from} → ${plan.to}, the old one stays as the way back` : ""}; ${units.length} services to check after the boot`);
    await run(["sync"], { check: false });
    await run(["systemd-run", "--on-active=10", "--unit=pano-reboot", "systemctl", "reboot"]);
    return plan.to ? `Rebooting in 10 seconds into kernel ${plan.to}; the panel is back in about a minute` : "Rebooting in 10 seconds; the panel is back in about a minute";
  } catch (e) {
    rebooting = false;
    throw e;
  }
}

/** Takes the safety arguments off the new kernel; `restoreDefault`: the boot never happened, so the new kernel is the default again. */
async function undoKernel(p: Pick<Pending, "newId" | "to" | "added">, restoreDefault: boolean) {
  if (!p.to) return;
  if (p.added.length) await run(["grubby", `--update-kernel=/boot/vmlinuz-${p.to}`, `--remove-args=${p.added.join(" ")}`], { check: false });
  if (restoreDefault) {
    await run(["grub2-editenv", "-", "unset", "next_entry"], { check: false });
    await run(["grub2-set-default", p.newId], { check: false });
  }
}

let checking = false;

/** After the boot pano asked for: the kernel, the services, the edge. Called at agent start and every few minutes. */
export async function afterReboot() {
  if (checking) return;
  const raw = await readText(PENDING);
  if (!raw) return;
  checking = true;
  try {
    const p = JSON.parse(raw) as Pending;
    const bootedAt = Date.now() - (await uptimeSec()) * 1000;
    if (bootedAt < p.at) {
      // Not rebooted yet: the countdown, or a reboot that never came.
      if (rebooting || Date.now() - p.at < 15 * 60_000) return;
      await undoKernel(p, true);
      await run(["rm", "-f", PENDING]);
      await notify("🟠 the reboot pano started did not happen; the boot settings are back as they were");
      return;
    }
    await run(["systemctl", "is-system-running", "--wait"], { check: false, timeoutMs: 300_000 });

    const lines: string[] = [];
    let bad = false;
    const now = (await run(["uname", "-r"])).stdout.trim();
    if (p.to && now === p.to) {
      await run(["grub2-set-default", p.newId], { check: false });
      await undoKernel(p, false);
      lines.push(`kernel ${now}`);
    } else if (p.to) {
      bad = true;
      settings.set("reboot.badKernel", p.to);
      await undoKernel(p, false);
      lines.push(`kernel ${p.to} did not boot; back on ${now}, which stays the default`);
    } else lines.push(`kernel ${now}`);

    const down = async () => {
      const st = (await run(["systemctl", "is-active", ...p.units], { check: false })).stdout.split("\n");
      return p.units.filter((_, i) => st[i]?.trim() !== "active");
    };
    let missing = p.units.length ? await down() : [];
    if (missing.length) {
      for (const u of missing) {
        await run(["systemctl", "reset-failed", u], { check: false });
        await run(["systemctl", "restart", u], { check: false, timeoutMs: 120_000 });
      }
      await Bun.sleep(5000);
      const still = await down();
      const fixed = missing.filter((u) => !still.includes(u));
      if (fixed.length) lines.push(`started again: ${fixed.join(", ")}`);
      missing = still;
    }
    if (missing.length) {
      bad = true;
      lines.push(`not running: ${missing.join(", ")}`);
    }
    if (p.units.includes(EDGE_UNIT)) {
      const ports = (await run(["ss", "-ltnpH", "( sport = :80 or sport = :443 )"], { check: false })).stdout;
      const others = [...new Set([...ports.matchAll(/users:\(\("([^"]+)"/g)].map((m) => m[1]).filter((n) => n !== "caddy"))];
      if (!/:443\s.*"caddy"/.test(ports)) {
        bad = true;
        lines.push(`the edge is not listening on 443${others.length ? ` (held by ${others.join(", ")})` : ""}`);
      }
    }
    lines.push(`${p.units.length - missing.length}/${p.units.length} services running`);
    await run(["rm", "-f", PENDING]);
    audit("system", "reboot.done", { ok: !bad, lines });
    await notify(`${bad ? "🔴 back after the reboot, with problems" : "✅ back after the reboot"}: ${lines.join("; ")}`);
  } catch (e) {
    console.error(`[agent] after reboot: ${e}`);
  } finally {
    checking = false;
  }
}

export async function rebootStatus() {
  return { ...rebootSettings(), pending: await exists(PENDING), badKernel: settings.get("reboot.badKernel") ?? "" };
}
