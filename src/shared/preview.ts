// Preview deploys: pure rules (names, hosts, limits, lifetime, env filtering).
// No state, no system calls: the agent (previews.ts) applies them and tests cover them.

import { createHash } from "node:crypto";
import { v, ValidationError, type ProcessSpec } from "./validate.ts";

export const PREVIEW_MAX_DEFAULT = 3;
export const PREVIEW_TTL_DEFAULT = 7;
const DAY = 86400;

/** The synthetic app name of a preview. "_" never occurs in real app names, so it cannot collide with one. */
export const pvName = (id: number) => `pv_${id}`;

/**
 * Host label for a branch. A branch that is already a plain lowercase label keeps its name;
 * anything else (feature/x, Fix_Y) is cleaned and gets a short hash of the real name, so
 * "feature/x" and "feature-x" never share a preview.
 */
export function previewSlug(branch: string): string {
  const clean = branch.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  if (clean === branch && clean.length <= 40) return clean;
  const hash = createHash("sha1").update(branch).digest("hex").slice(0, 6);
  return `${clean.slice(0, 40).replace(/-+$/, "") || "b"}-${hash}`;
}

/** "" (previews off) or a wildcard such as *.preview.example.com that the admin owns. */
export function validatePreviewDomain(s: unknown, ownHosts: string[] = []): string {
  const x = String(s ?? "").trim().toLowerCase();
  if (!x) return "";
  const d = v.domain(x);
  if (!d.startsWith("*.")) throw new ValidationError("preview domain must be a wildcard such as *.preview.example.com");
  if (d.slice(2).split(".").length < 2) throw new ValidationError("preview domain must be a wildcard such as *.preview.example.com");
  const problem = previewDomainProblem(d, ownHosts);
  if (problem) throw new ValidationError(problem);
  return d;
}

/**
 * Why a preview domain is not acceptable next to these hosts (the app's own), or "" when it is.
 * A branch named "mail" or "admin" takes the host <branch>.<zone>: the zone must be a dedicated one
 * (*.preview.example.com), never the app's own domain or a parent of it (*.example.com).
 */
export function previewDomainProblem(pattern: string, ownHosts: string[]): string {
  if (!pattern.startsWith("*.")) return "";
  const zone = pattern.slice(2);
  const hit = ownHosts.map((h) => h.toLowerCase()).find((h) => h === zone || h.endsWith(`.${zone}`));
  return hit ? `the preview domain ${pattern} covers this app's own domain (${hit}): use a dedicated zone of its own, such as *.preview.example.com` : "";
}

export const previewHost = (pattern: string, slug: string) => `${slug}${pattern.slice(1)}`;

/** True when host is exactly one label in front of the pattern's suffix. */
export function hostMatchesPattern(pattern: string, host: string): boolean {
  if (!pattern.startsWith("*.") || !host.endsWith(pattern.slice(1))) return false;
  return /^[a-z0-9-]{1,63}$/.test(host.slice(0, host.length - pattern.length + 1));
}

// ---- env: a preview gets the app's variables minus the ones marked prod-only ----

const EXCLUDE_ITEM = /^(!?[A-Za-z_][A-Za-z0-9_]{0,127}\*?|!\*)$/;

/**
 * "STRIPE_*, DATABASE_URL" -> "STRIPE_*,DATABASE_URL" (a trailing * matches a prefix).
 * "!NAME" (or "!PREFIX*", "!*" for everything) lets a variable through that previews leave out by default.
 */
export function normalizeEnvExclude(s: unknown): string {
  const items = [...new Set(String(s ?? "").split(/[\s,]+/).filter(Boolean))];
  if (items.length > 100) throw new ValidationError("at most 100 prod-only variables");
  for (const i of items) if (!EXCLUDE_ITEM.test(i)) throw new ValidationError(`invalid prod-only variable: ${i.slice(0, 40)}`);
  return items.join(",");
}

/** Names that carry credentials or connection strings: URLs, keys, secrets, tokens, passwords, DATABASE_*. */
export const SECRET_LIKE = /^DATABASE_|(^|_)(URL|URI|KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|DSN|CREDENTIALS?)$/i;

const ruleMatches = (rule: string, k: string) => (rule === "*" ? true : rule.endsWith("*") ? k.startsWith(rule.slice(0, -1)) : k === rule);

/**
 * The app's env as a preview gets it. Branch code runs with it, and anyone who can push a branch
 * can start a build, so by default a preview does not get what looks like a secret (SECRET_LIKE) nor
 * anything from a shared variable group (`groupKeys`); "!NAME" in the list lets one through.
 * A list the admin wrote with prod-only names ("STRIPE_*, DATABASE_URL") is taken as their own
 * decision and applied as it stands, as before this default existed.
 * Then come the preview values (Vercel's "Preview" scope: a test Stripe key, a staging database),
 * which are never excluded, then pano's own.
 */
export function previewEnv(env: Record<string, string>, exclude: string, overrides: Record<string, string> = {}, extra: Record<string, string> = {}, groupKeys: string[] = []): Record<string, string> {
  const items = exclude.split(",").filter(Boolean);
  const allow = items.filter((r) => r.startsWith("!")).map((r) => r.slice(1));
  const deny = items.filter((r) => !r.startsWith("!"));
  const groups = new Set(groupKeys);
  const dropped = (k: string) => {
    if (deny.some((r) => ruleMatches(r, k))) return true;
    if (deny.length) return false;
    return (SECRET_LIKE.test(k) || groups.has(k)) && !allow.some((r) => ruleMatches(r, k));
  };
  return { ...Object.fromEntries(Object.entries(env).filter(([k]) => !dropped(k))), ...overrides, ...extra };
}

// ---- which processes a preview runs ----

/**
 * A preview serves the app's web processes under its own host. A route keeps its path
 * ("example.com/api" -> "<host>/api"); a path already taken by an earlier process is dropped
 * with its process, and workers are not run in previews (they could drain the real queues).
 */
export function previewProcesses(procs: ProcessSpec[], host: string): ProcessSpec[] {
  const taken = new Set<string>();
  const out: ProcessSpec[] = [];
  for (const p of procs) {
    const routes: string[] = [];
    for (const r of p.routes) {
      const i = r.indexOf("/");
      const path = i < 0 ? "" : r.slice(i);
      if (taken.has(path)) continue;
      taken.add(path);
      routes.push(host + path);
    }
    if (routes.length) out.push({ ...p, routes });
  }
  return out;
}

// ---- limits and lifetime ----

export type PreviewLike = { id: number; branch: string; updated_at: number; busy?: boolean };

/**
 * Previews to remove so `branch` fits within max: least recently pushed first, never a preview
 * that is building and never the branch itself (a push to an existing preview adds nothing).
 * With an empty branch nothing is being added (max was lowered: just trim). May return fewer than needed if the rest are all building.
 */
export function evictions(existing: PreviewLike[], branch: string, max: number): number[] {
  const adding = !branch || existing.some((p) => p.branch === branch) ? 0 : 1;
  const need = existing.length + adding - max;
  if (need <= 0) return [];
  return existing
    .filter((p) => p.branch !== branch && !p.busy)
    .sort((a, b) => a.updated_at - b.updated_at || a.id - b.id)
    .slice(0, need)
    .map((p) => p.id);
}

export const expiryFrom = (now: number, ttlDays: number) => now + ttlDays * DAY;

export function expiredIds(previews: { id: number; expires_at: number }[], now: number): number[] {
  return previews.filter((p) => p.expires_at <= now).map((p) => p.id);
}

/** The pull request comment of a preview build (Markdown; the branch is shown as code). */
export function previewComment(branch: string, host: string, sha: string, ok: boolean, deploy: number): string {
  const b = "`" + branch.replace(/`/g, "") + "`";
  const commit = sha ? ` (commit ${sha.slice(0, 7)})` : "";
  return ok
    ? `**Preview ready:** https://${host}\n\nBranch ${b}${commit}, deployed by pano.`
    : `**Preview build failed** for branch ${b}${commit}: see deploy ${deploy} on the app's page in pano.`;
}

// ---- webhooks ----

/** "refs/heads/feature/x" -> "feature/x"; tags and anything else -> "". */
export function branchFromRef(ref: string): string {
  return ref.startsWith("refs/heads/") ? ref.slice("refs/heads/".length) : "";
}

/** A push that deletes the branch: GitHub/Gitea set `deleted`, GitLab (and git) send an all-zero `after`. */
export function isBranchDeletion(payload: unknown): boolean {
  const p = (payload ?? {}) as { deleted?: unknown; after?: unknown };
  return p.deleted === true || (typeof p.after === "string" && /^0{7,}$/.test(p.after));
}
