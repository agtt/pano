// Preview deploys: a branch built on its own and served at <branch-slug>.<preview domain>.
//
// A preview is deployed by the same code as an app (apps.ts deploy) as a synthetic app
// "pv_<id>": its own system user, home, DATA_DIR, ports and systemd units, so it cannot touch the
// app's data. It gets a copy of the app's env minus the variables marked prod-only. The edge
// serves it with on-demand TLS, and the ask endpoint only approves hosts of existing previews.

import { fsPath } from "../shared/config.ts";
import {
  branchFromRef, evictions, expiredIds, expiryFrom, hostMatchesPattern, isBranchDeletion, previewComment, previewEnv, previewHost, previewProcesses, previewSlug, pvName,
} from "../shared/preview.ts";
import { formatEnv, v } from "../shared/validate.ts";
import { appHome, appUser, assertDomainsFree, effectiveEnv, enqueueDeploy, getEnv, mustGet, teardownUnits, type DeployTarget } from "./apps.ts";
import { applyEdge } from "./edge.ts";
import { commentPreview, reportStatus } from "./github.ts";
import { apps, audit, deploys, previewApp, previews, procsOf, sites, type App, type Preview, type Process } from "./state.ts";
import { remove, run, writeAtomic } from "./sys.ts";

const nowSec = () => Math.floor(Date.now() / 1000);

// Creating and removing previews is serialized, so two pushes at once cannot exceed the limit.
let lock: Promise<unknown> = Promise.resolve();
function serial<T>(fn: () => Promise<T>): Promise<T> {
  const r = lock.then(fn);
  lock = r.catch(() => {});
  return r;
}

const busy = (id: number) => !!deploys.running(pvName(id));

/** The copy of the app's env a preview runs with. */
async function writePreviewEnv(parent: App, pv: Preview) {
  const name = pvName(pv.id);
  const env = previewEnv(await effectiveEnv(parent), parent.preview_env_exclude, await getEnv(parent.name, "preview"), {
    PANO_PREVIEW: "1",
    PANO_PREVIEW_BRANCH: pv.branch,
    PANO_PREVIEW_URL: `https://${pv.host}`,
  });
  const file = `${appHome(name)}/shared/.env`;
  await writeAtomic(file, formatEnv(env), 0o640);
  await run(["chgrp", appUser(name), fsPath(file)], { check: false });
}

function target(id: number): DeployTarget {
  const live = () => {
    const pv = previews.get(id);
    const parent = pv && apps.get(pv.app);
    return pv && parent ? { pv, parent } : null;
  };
  return {
    get: () => {
      const x = live();
      return x ? previewApp(x.parent, x.pv) : null;
    },
    update: (patch) => {
      const { active_slot, current_release } = patch;
      previews.update(id, { ...(active_slot !== undefined ? { active_slot } : {}), ...(current_release !== undefined ? { current_release } : {}) });
    },
    keep: 1,
    quiet: true, // a broken branch should not page anyone
    prepare: async () => {
      const x = live();
      if (!x) throw new Error("removed while it was building");
      await writePreviewEnv(x.parent, x.pv);
    },
    report: (app, sha, state, description) => {
      void reportStatus(app, sha, state, description, { context: "pano/preview" });
      const x = live();
      if (x && state !== "pending") void commentPreview(x.parent, x.pv.branch, previewComment(x.pv.branch, x.pv.host, sha, state === "success", x.pv.last_deploy)).catch(() => {});
    },
  };
}

// ---- remove ----------------------------------------------------------------

async function removeNow(id: number, actor: string, why: string): Promise<boolean> {
  const pv = previews.get(id);
  if (!pv) return false;
  previews.remove(id);
  await applyEdge().catch((e) => console.error(`[preview] edge: ${e instanceof Error ? e.message : e}`));
  await teardownUnits(pvName(id), true);
  audit(actor, "preview.remove", { app: pv.app, branch: pv.branch, host: pv.host, why });
  return true;
}

export function removePreview(appName: string, id: number, actor: string) {
  return serial(async () => {
    const pv = previews.get(id);
    if (!pv || pv.app !== appName) throw new Error("no such preview");
    if (busy(id)) throw new Error("this preview is building; try again when it has finished");
    await removeNow(id, actor, "manual");
  });
}

/** Branch deleted: its preview goes. False when there was none (or it is still building and will expire). */
export function removeByBranch(appName: string, branch: string, actor: string) {
  return serial(async () => {
    const pv = previews.find(appName, previewSlug(branch));
    if (!pv || pv.branch !== branch || busy(pv.id)) return false;
    return removeNow(pv.id, actor, "branch deleted");
  });
}

/** All previews of an app (the app is being deleted). */
export function removeAll(appName: string, actor: string) {
  return serial(async () => {
    for (const pv of previews.list(appName)) await removeNow(pv.id, actor, "app deleted");
  });
}

/** Previews past their lifetime, and previews whose app is gone. Safe to call often. */
async function sweepNow() {
  const all = previews.list();
  const orphans = all.filter((p) => !apps.get(p.app)).map((p) => p.id);
  for (const id of new Set([...expiredIds(all, nowSec()), ...orphans])) if (!busy(id)) await removeNow(id, "system", "expired");
}
export const sweepPreviews = () => serial(sweepNow);

/** After the app's settings changed: previews outside the new domain go, then the limit is enforced. */
export function reconcilePreviews(appName: string, actor: string) {
  return serial(async () => {
    const app = apps.get(appName);
    if (!app) return;
    for (const pv of previews.list(appName)) {
      if ((!app.preview_domain || !hostMatchesPattern(app.preview_domain, pv.host)) && !busy(pv.id)) await removeNow(pv.id, actor, "preview domain changed");
    }
    await trim(app, "", actor);
  });
}

async function trim(app: App, branch: string, actor: string) {
  const list = () => previews.list(app.name).map((p) => ({ id: p.id, branch: p.branch, updated_at: p.updated_at, busy: busy(p.id) }));
  for (const id of evictions(list(), branch, app.preview_max)) await removeNow(id, actor, "limit");
  const left = list();
  if (branch && !left.some((p) => p.branch === branch) && left.length + 1 > app.preview_max) {
    throw new Error(`at most ${app.preview_max} previews, and the others are still building`);
  }
}

// ---- start -----------------------------------------------------------------

/** Builds (or rebuilds) the preview of a branch. Returns the deploy id to follow in the log. */
export function startPreview(appName: string, branchInput: string, trigger: string, actor: string): Promise<{ id: number; host: string; deploy: number }> {
  return serial(async () => {
    const app = mustGet(appName);
    if (app.kind !== "managed") throw new Error("external apps have no previews");
    if (!app.preview_domain) throw new Error("previews are off for this app: set a preview domain in its settings");
    const branch = v.branch(branchInput);
    if (branch === app.branch) throw new Error(`${branch} is the production branch: use Deploy`);
    const slug = previewSlug(branch);
    const host = previewHost(app.preview_domain, slug);
    const existing = previews.find(app.name, slug);
    if (existing && existing.branch !== branch) throw new Error(`${host} already belongs to branch ${existing.branch}`);
    if (existing && busy(existing.id)) throw new Error("a build is already running for this preview");

    await sweepNow();
    await trim(app, branch, actor);

    let id = existing?.id ?? 0;
    if (!existing) {
      assertDomainsFree([host], {}, { apps: apps.list(), sites: sites.list(), previews: previews.list() });
      const taken: number[] = [];
      const processes: Process[] = previewProcesses(procsOf(app), host).map((p) => {
        const [port_a, port_b] = apps.nextPorts(taken);
        taken.push(port_a, port_b);
        return { ...p, port_a, port_b };
      });
      if (!processes.length) throw new Error("this app has no web process (with a route) to preview");
      id = previews.insert({ app: app.name, branch, slug, host, processes, expires_at: expiryFrom(nowSec(), app.preview_ttl_days) });
      // A home left over from an earlier state must never carry its data into a new preview.
      await remove(appHome(pvName(id)));
    }
    try {
      const deploy = enqueueDeploy(previewApp(app, previews.get(id)!), target(id), `preview:${branch}`.slice(0, 80));
      previews.update(id, { last_deploy: deploy, expires_at: expiryFrom(nowSec(), app.preview_ttl_days) });
      audit(actor, "preview.deploy", { app: app.name, branch, host, id, deploy, trigger });
      return { id, host, deploy };
    } catch (e) {
      if (!existing) previews.remove(id);
      throw e;
    }
  });
}

// ---- webhooks --------------------------------------------------------------

/**
 * A verified push to a branch that is not the app's own: builds its preview, or removes it when
 * the branch was deleted. Null when previews do not apply, so the caller keeps its normal answer.
 */
export async function onPush(appName: string, ref: string, body: string, source: string): Promise<{ deploy: boolean; reason: string; id?: number; preview?: string } | null> {
  const app = apps.get(appName);
  const branch = branchFromRef(ref);
  if (!app || app.kind !== "managed" || !app.preview_domain || !branch || branch === app.branch) return null;
  try {
    v.branch(branch);
    let payload: unknown = null;
    try {
      payload = JSON.parse(body);
    } catch {}
    if (isBranchDeletion(payload)) {
      return { deploy: false, reason: (await removeByBranch(appName, branch, source)) ? "preview removed" : "no preview to remove" };
    }
    if (app.auto_deploy === 0) return { deploy: false, reason: "auto deploy is off" };
    const r = await startPreview(appName, branch, source, source);
    return { deploy: true, reason: "preview", id: r.deploy, preview: r.host };
  } catch (e) {
    return { deploy: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

/** A pull request opened after its branch's preview went live: the link goes on it now. Signature already verified. */
export async function onPullRequest(appName: string, body: string): Promise<{ reason: string }> {
  let p: { action?: unknown; pull_request?: { head?: { ref?: unknown } } };
  try {
    p = JSON.parse(body);
  } catch {
    return { reason: "bad json" };
  }
  if (!["opened", "reopened", "ready_for_review"].includes(String(p.action))) return { reason: "ignored" };
  const app = apps.get(appName);
  const branch = String(p.pull_request?.head?.ref ?? "");
  const pv = app && branch ? previews.find(appName, previewSlug(branch)) : null;
  if (!app || !pv || pv.branch !== branch || !pv.active_slot) return { reason: "no live preview" };
  const sha = (pv.last_deploy ? deploys.get(pv.last_deploy)?.commit_sha : "") ?? "";
  await commentPreview(app, branch, previewComment(branch, pv.host, sha, true, pv.last_deploy)).catch(() => {});
  return { reason: "commented" };
}

// ---- view ------------------------------------------------------------------

export type PreviewView = {
  id: number;
  branch: string;
  host: string;
  /** building: a build runs; live: served; failed: never went live */
  status: "building" | "live" | "failed";
  error: string;
  commit: string;
  deploy: number;
  updated_at: number;
  expires_at: number;
};

export function previewList(appName: string): PreviewView[] {
  return previews.list(appName).map((pv) => {
    const d = pv.last_deploy ? deploys.get(pv.last_deploy) : null;
    const status = d?.status === "running" ? "building" : pv.active_slot ? "live" : "failed";
    return {
      id: pv.id,
      branch: pv.branch,
      host: pv.host,
      status,
      error: d?.status === "failed" ? d.error : "",
      commit: d?.commit_sha ?? "",
      deploy: pv.last_deploy,
      updated_at: pv.updated_at,
      expires_at: pv.expires_at,
    };
  });
}

/** The deploy log of a preview may be read through its app's page. */
export function previewOwnsDeploy(appName: string, deployId: number): boolean {
  const app = deploys.get(deployId)?.app ?? "";
  const m = /^pv_(\d+)$/.exec(app);
  return !!m && previews.get(Number(m[1]))?.app === appName;
}
