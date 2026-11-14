// Suspending a site or an app (like "suspend account" in other panels). The edge keeps its domains
// and certificates but answers every request with a fixed page (503, Retry-After; see edge.ts), and
// what runs the tenant's code stops: a PHP site's pool and cron timers, a managed app's processes,
// cron timers and previews. Resume brings back exactly what ran before. External apps (systemd units
// pano did not make, PM2) only get the page: pano does not know what else those processes serve.

import { pvName } from "../shared/preview.ts";
import { v } from "../shared/validate.ts";
import { activeUnits, cronTimers, mustGet, writeCrons } from "./apps.ts";
import { applyEdge } from "./edge.ts";
import { writeSiteCrons } from "./jobs.ts";
import { setPhpEnabled } from "./php.ts";
import { apps, audit, deploys, previewApp, previews, sites, type App, type Site, type SuspendedUnit } from "./state.ts";
import { run, showUnits } from "./sys.ts";

/** A reason as the admin typed it: one line, printable, at most 200 characters. */
export function suspendReason(x: unknown): string {
  return String(x ?? "")
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 200);
}

// ---- sites -----------------------------------------------------------------------

function mustSite(name: unknown): Site {
  const site = sites.get(v.siteName(name));
  if (!site) throw new Error("not found");
  return site;
}

export async function suspendSite(name: unknown, reasonInput: unknown, actor: string) {
  const site = mustSite(name);
  if (!site.enabled) throw new Error(`${site.name} is already suspended`);
  const reason = suspendReason(reasonInput);
  sites.setSuspended(site.name, reason);
  // The page goes up first, then the pool stops: visitors never see a 502 in between.
  await applyEdge();
  if (site.kind === "php") await setPhpEnabled(site, false);
  await writeSiteCrons(site.name); // timers are armed only while the site is enabled
  audit(actor, "site.suspend", { name: site.name, reason });
}

export async function resumeSite(name: unknown, actor: string) {
  const site = mustSite(name);
  if (site.enabled) throw new Error(`${site.name} is not suspended`);
  sites.setEnabled(site.name, true);
  if (site.kind === "php") await setPhpEnabled(site, true);
  await writeSiteCrons(site.name);
  await applyEdge();
  audit(actor, "site.resume", { name: site.name, reason: site.suspended_reason });
}

// ---- apps ------------------------------------------------------------------------

/** What suspension stops for an app: a managed app's live processes, cron timers and live previews. */
export function suspendTargets(app: App): string[] {
  if (app.kind !== "managed") return [];
  const pv = previews.list(app.name).flatMap((p) => activeUnits(previewApp(app, p)));
  return [...new Set([...activeUnits(app), ...cronTimers(app), ...pv])];
}

const RUNNING = new Set(["active", "activating", "reloading"]);

export async function suspendApp(name: unknown, reasonInput: unknown, actor: string) {
  const app = mustGet(String(name ?? ""));
  if (app.suspended) throw new Error(`${app.name} is already suspended`);
  // A build that finishes would start processes again: wait for it (production and previews).
  if (deploys.running(app.name) || previews.list(app.name).some((p) => deploys.running(pvName(p.id)))) {
    throw new Error("a deploy is running for this app: suspend it when the deploy is done");
  }
  const reason = suspendReason(reasonInput);
  const units = suspendTargets(app);
  const shown = await showUnits(units, ["ActiveState", "UnitFileState"]);
  const kept: SuspendedUnit[] = units.map((unit) => {
    const s = shown.get(unit) ?? {};
    return { unit, active: RUNNING.has(s.ActiveState ?? ""), enabled: /^enabled/.test(s.UnitFileState ?? "") };
  });
  // From here deploys, previews, webhooks and starts are refused, and the edge serves the page.
  apps.update(app.name, { suspended: 1, suspended_reason: reason, suspended_at: Math.floor(Date.now() / 1000), suspended_units: kept });
  await applyEdge();
  // Disabled too, so a reboot does not bring them back while suspended.
  for (const u of units) await run(["systemctl", "disable", "--now", u], { check: false });
  audit(actor, "app.suspend", { name: app.name, reason, stopped: kept.filter((u) => u.active).map((u) => u.unit) });
}

export async function resumeApp(name: unknown, actor: string) {
  const app = mustGet(String(name ?? ""));
  if (!app.suspended) throw new Error(`${app.name} is not suspended`);
  // Unit by unit: one that is gone meanwhile (a preview removed while suspended) must not stop the rest.
  for (const u of app.suspended_units) {
    if (u.enabled) await run(["systemctl", "enable", u.unit], { check: false });
    if (u.active) await run(["systemctl", "start", u.unit], { check: false });
  }
  apps.update(app.name, { suspended: 0, suspended_reason: "", suspended_at: 0, suspended_units: [] });
  const fresh = apps.get(app.name)!;
  // Cron jobs saved while suspended get their timers now (writeCrons arms all of a deployed app's).
  if (fresh.kind === "managed") await writeCrons(fresh);
  await applyEdge();
  audit(actor, "app.resume", { name: app.name, reason: app.suspended_reason });
}

// ---- projects (grouped in the web; the agent gets the members) ----------------------

const names = (x: unknown): string[] => (Array.isArray(x) ? x : x === undefined || x === "" ? [] : [x]).map(String).slice(0, 200);

/** Suspends or resumes every app and site given; members already in that state are skipped. */
export async function setProjectSuspended(p: { apps?: unknown; sites?: unknown; reason?: unknown }, on: boolean, actor: string) {
  const done: string[] = [];
  const failed: string[] = [];
  const each = async (label: string, fn: () => Promise<unknown>) => {
    try {
      await fn();
      done.push(label);
    } catch (e) {
      failed.push(`${label}: ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  // Every name is checked before anything changes.
  const appList = names(p.apps).map((n) => mustGet(n));
  const siteList = names(p.sites).map((n) => mustSite(n));
  if (!appList.length && !siteList.length) throw new Error("nothing to " + (on ? "suspend" : "resume"));
  for (const a of appList.filter((x) => !!x.suspended !== on)) {
    await each(`app ${a.name}`, () => (on ? suspendApp(a.name, p.reason, actor) : resumeApp(a.name, actor)));
  }
  for (const s of siteList.filter((x) => !x.enabled !== on)) {
    await each(`site ${s.name}`, () => (on ? suspendSite(s.name, p.reason, actor) : resumeSite(s.name, actor)));
  }
  return { done, failed };
}
