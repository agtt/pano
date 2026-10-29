// App environment: pure rules (shared variable groups, what a restart or a redeploy would
// change). No state, no system calls: the agent applies them and tests cover them.

import { createHash } from "node:crypto";
import { ValidationError } from "./validate.ts";

// ---- shared variable groups ----

const GROUP_NAME = /^[a-z][a-z0-9-]{0,31}$/;

export function groupName(s: unknown): string {
  const x = String(s ?? "").trim();
  if (!GROUP_NAME.test(x)) throw new ValidationError("group name: lowercase letters, digits and -, starting with a letter (max 32)");
  return x;
}

/** "stripe, sentry" -> "stripe,sentry" (order kept: a later group wins over an earlier one). */
export function normalizeGroups(s: unknown): string {
  const items = [...new Set((Array.isArray(s) ? s.map(String) : String(s ?? "").split(/[\s,]+/)).filter(Boolean))];
  if (items.length > 20) throw new ValidationError("at most 20 shared variable groups per app");
  return items.map(groupName).join(",");
}

export const groupList = (s: string) => s.split(",").filter(Boolean);

/** What the app runs with: its groups in order, then its own variables (which win). */
export function mergeEnv(groups: Record<string, string>[], own: Record<string, string>): Record<string, string> {
  return Object.assign({}, ...groups, own);
}

// ---- pending changes: restart or redeploy ----

/**
 * Variables frameworks copy into the built code (client bundles): changing one needs a new build,
 * a restart keeps the old value. Next.js, Vite/SvelteKit/Astro, Create React App, Nuxt, Expo, Gatsby, Vue CLI, Storybook.
 */
const BUILD_PREFIXES = ["NEXT_PUBLIC_", "VITE_", "PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_", "EXPO_PUBLIC_", "GATSBY_", "VUE_APP_", "STORYBOOK_"];
export const isBuildVar = (k: string) => BUILD_PREFIXES.some((p) => k.startsWith(p));

/** Per-variable fingerprints (kept by the agent only; the UI sees names, never these). */
export function envSnapshot(env: Record<string, string>): string {
  const out: Record<string, string> = {};
  for (const k of Object.keys(env).sort()) out[k] = createHash("sha256").update(`${k}\0${env[k]}`).digest("hex").slice(0, 20);
  return JSON.stringify(out);
}

function changed(env: Record<string, string>, snapshot: string): string[] {
  let then: Record<string, string>;
  try {
    then = JSON.parse(snapshot);
  } catch {
    return [];
  }
  const now = JSON.parse(envSnapshot(env)) as Record<string, string>;
  return [...new Set([...Object.keys(now), ...Object.keys(then)])].filter((k) => now[k] !== then[k]).sort();
}

/**
 * Variables that differ from what the running processes started with (a restart applies them)
 * and build-time variables that differ from the live build (only a redeploy applies them).
 * An empty snapshot (nothing recorded yet) reports nothing.
 */
export function envPending(env: Record<string, string>, running: string, built: string): { restart: string[]; redeploy: string[] } {
  return {
    restart: running ? changed(env, running) : [],
    redeploy: built ? changed(env, built).filter(isBuildVar) : [],
  };
}
