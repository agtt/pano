// Every scheduled job on the server in one place: app cron jobs, PHP site cron
// jobs, and (read-only) the crontabs left from the previous panel. Jobs are
// systemd timers: nothing stays running between runs, a job never overlaps
// itself, a missed run (server off) runs at boot, and each run gets a small
// CPU and disk share so it cannot slow the sites down.

import { readdir } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import { v } from "../shared/validate.ts";
import { LOW, checkSchedules, parseCrons } from "./apps.ts";
import { confDir, phpRoot, phpSandbox, siteHome, siteUser } from "./php.ts";
import { apps, audit, sites, type Site } from "./state.ts";
import { readText, remove, run, showUnits, writeAtomic } from "./sys.ts";

export type JobRef = { owner: "app" | "site"; name: string; index: number };
export type Job = JobRef & {
  schedule: string;
  command: string;
  /** timer armed (app deployed / site enabled) */
  armed: boolean;
  running: boolean;
  next: number | null;
  last: number | null;
  /** "success", "exit-code", "timeout", ... of the last run; "" before the first */
  result: string;
  seconds: number | null;
};

const siteBase = (site: string, i: number) => `pano-sitecron-${site}-${i}`;
const baseOf = (j: JobRef) => (j.owner === "app" ? `pano-cron-${j.name}-${j.index}` : siteBase(j.name, j.index));
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ---- PHP site jobs -----------------------------------------------------------------

export function renderSiteCron(site: Site, i: number): { service: string; timer: string; script: string } {
  const c = site.crons[i]!;
  const home = siteHome(site.name);
  const user = siteUser(site.name);
  const conf = confDir(site.name);
  return {
    // Not "exec": a command with && or ; must run whole.
    script: `#!/bin/sh\nset -e\n${c.command}\n`,
    service: `[Unit]
Description=pano cron site ${site.name} #${i}: ${c.schedule}
After=mariadb.service

[Service]
Type=oneshot
User=${user}
Group=${user}
WorkingDirectory=${home}
Environment=HOME=${home} PHPRC=${conf}/php.ini PANO_CRON=${i}
Environment=PATH=${phpRoot(site.php_version)}/usr/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=${conf}/cron-${i}.sh
TimeoutStartSec=1h
MemoryMax=512M
TasksMax=64
${LOW}${phpSandbox(site.name)}`,
    timer: `[Unit]\nDescription=pano cron site ${site.name} #${i}\n\n[Timer]\nOnCalendar=${c.schedule}\nPersistent=true\nRandomizedDelaySec=5\n\n[Install]\nWantedBy=timers.target\n`,
  };
}

/** Brings a site's timers in line with its saved jobs: removed, rewritten, armed only while the site is enabled. */
export async function writeSiteCrons(name: string) {
  const site = sites.get(name);
  const jobs = site?.kind === "php" ? site.crons : [];
  const mine = new RegExp(`^pano-sitecron-${escape(name)}-\\d+\\.(timer|service)$`);
  const keep = new Set(jobs.flatMap((_, i) => [`${siteBase(name, i)}.timer`, `${siteBase(name, i)}.service`]));
  const files = (await readdir(fsPath(paths.systemd)).catch(() => [] as string[])).filter((f) => mine.test(f));
  for (const f of files.filter((f) => !keep.has(f))) {
    if (f.endsWith(".timer")) await run(["systemctl", "disable", "--now", f], { check: false });
    await remove(`${paths.systemd}/${f}`);
  }
  for (const i of jobs.keys()) {
    const r = renderSiteCron(site!, i);
    await writeAtomic(`${confDir(name)}/cron-${i}.sh`, r.script, 0o755);
    await writeAtomic(`${paths.systemd}/${siteBase(name, i)}.service`, r.service, 0o644);
    await writeAtomic(`${paths.systemd}/${siteBase(name, i)}.timer`, r.timer, 0o644);
  }
  await run(["systemctl", "daemon-reload"], { check: false });
  for (const i of jobs.keys()) {
    await run(["systemctl", site!.enabled ? "enable" : "disable", "--now", `${siteBase(name, i)}.timer`], { check: false });
  }
}

export async function setSiteCrons(name: unknown, text: unknown, actor: string) {
  const site = sites.get(v.siteName(name));
  if (!site) throw new Error("not found");
  if (site.kind !== "php") throw new Error("cron jobs run on pano PHP sites; convert the site first");
  const crons = parseCrons(String(text ?? ""));
  await checkSchedules(crons);
  sites.setCrons(site.name, crons);
  await writeSiteCrons(site.name);
  audit(actor, "site.crons", { name: site.name, count: crons.length });
}

// ---- all jobs --------------------------------------------------------------------

const stamp = (s: string) => {
  const n = Number(s.replace(/^@/, ""));
  return s.startsWith("@") && n > 0 ? n : null;
};

const TIMER_PROPS = ["ActiveState", "NextElapseUSecRealtime", "LastTriggerUSec"];
const SERVICE_PROPS = ["ActiveState", "Result", "ExecMainStartTimestamp", "ExecMainExitTimestamp"];

function unitInfo(timer: Record<string, string>, svc: Record<string, string>) {
  const started = stamp(svc.ExecMainStartTimestamp ?? "");
  const exited = stamp(svc.ExecMainExitTimestamp ?? "");
  const last = stamp(timer.LastTriggerUSec ?? "") ?? started;
  return {
    armed: timer.ActiveState === "active",
    running: svc.ActiveState === "activating",
    next: stamp(timer.NextElapseUSecRealtime ?? ""),
    last,
    result: last ? (svc.Result ?? "") : "",
    seconds: started && exited && exited >= started ? exited - started : null,
  };
}

export function jobRefs(): (JobRef & { schedule: string; command: string })[] {
  const out: (JobRef & { schedule: string; command: string })[] = [];
  for (const a of apps.list()) if (a.kind === "managed") a.crons.forEach((c, index) => out.push({ owner: "app", name: a.name, index, ...c }));
  for (const s of sites.list()) if (s.kind === "php") s.crons.forEach((c, index) => out.push({ owner: "site", name: s.name, index, ...c }));
  return out;
}

export async function listJobs(filter?: { owner: JobRef["owner"]; name: string }): Promise<Job[]> {
  const refs = jobRefs().filter((j) => !filter || (j.owner === filter.owner && j.name === filter.name));
  // Two systemctl calls for all jobs (timers, services), not two per job: the monitor asks every minute.
  const [timers, svcs] = await Promise.all([
    showUnits(refs.map((j) => `${baseOf(j)}.timer`), TIMER_PROPS, ["--timestamp=unix"]),
    showUnits(refs.map((j) => `${baseOf(j)}.service`), SERVICE_PROPS, ["--timestamp=unix"]),
  ]);
  return refs.map((j) => ({ ...j, ...unitInfo(timers.get(`${baseOf(j)}.timer`) ?? {}, svcs.get(`${baseOf(j)}.service`) ?? {}) }));
}

export function parseRef(p: Record<string, unknown>): JobRef {
  const owner = p.owner === "app" ? "app" : p.owner === "site" ? "site" : null;
  if (!owner) throw new Error("owner must be app or site");
  const name = owner === "app" ? v.appName(p.name) : v.siteName(p.name);
  const index = v.int(p.index, 0, 99, "index");
  const ref = { owner, name, index } as JobRef;
  if (!jobRefs().some((j) => j.owner === ref.owner && j.name === ref.name && j.index === ref.index)) throw new Error("no such job");
  return ref;
}

/** Starts a run now, in the background; a run already in progress is not doubled. */
export async function runJob(ref: JobRef, actor: string) {
  await run(["systemctl", "start", "--no-block", `${baseOf(ref)}.service`]);
  audit(actor, "job.run", ref);
}

export async function jobLogs(ref: JobRef, lines = 200): Promise<string> {
  return (await run(["journalctl", "-u", `${baseOf(ref)}.service`, "-n", String(lines), "--no-pager", "-o", "short-iso"], { check: false })).stdout;
}

/** Failed last runs, for the alert monitor. */
export async function failedJobs(): Promise<{ key: string; text: string; failed: boolean }[]> {
  return (await listJobs()).map((j) => ({
    key: `cron:${j.owner}:${j.name}:${j.index}`,
    failed: !!j.result && j.result !== "success",
    text: `cron ${j.name} #${j.index} (${j.schedule}) failed: ${j.result}`,
  }));
}

// ---- crontabs from before pano -------------------------------------------------------

/** Values that look like credentials are hidden: the panel shows commands, not passwords. */
export const maskSecrets = (line: string) =>
  line
    .replace(/(\/\/[^:/@\s]+:)[^@\s]+@/g, "$1••••@")
    .replace(/(\s-p|\s--pass(?:word)?=|(?:password|passwd|token|secret|api_?key|key)=|Bearer\s+)([^\s'"&]+)/gi, "$1••••");

export async function legacyCrontabs(): Promise<{ user: string; lines: string[] }[]> {
  const dir = "/var/spool/cron";
  const out: { user: string; lines: string[] }[] = [];
  for (const user of (await readdir(fsPath(dir)).catch(() => [] as string[])).sort()) {
    const lines = ((await readText(`${dir}/${user}`)) ?? "")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#") && !/^[A-Za-z_]+=/.test(l));
    if (lines.length) out.push({ user, lines: lines.slice(0, 100).map(maskSecrets) });
  }
  return out;
}
