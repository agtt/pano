// The Python half of a deploy (apps.ts calls it only for runtime "python"): detect, install into a
// per-release virtualenv, build (Django collectstatic), start command, the Django migrate release
// step and the copy of static files for the edge. Every step is an argv run through the same
// sandbox as a Node.js build; nothing is passed to a shell except the admin's own commands.

import { lstat } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import {
  PY_DEFAULTS, defaultWorkers, detectPython, djangoArgv, djangoProbeArgv, hasHashes, insideDir, installSteps, parsePyStatic, parseStaticProbe, serverCommand,
  serverInstallStep, serverPackage, staticDir, triOn, uvEnv, type PyPlan, type PyServer, type PyStep, type PyTri,
} from "../shared/python.ts";
import { ensureBuildPackages, readRepo, snapshotStatic } from "./python.ts";
import { exists, remove } from "./sys.ts";
import type { App } from "./state.ts";

/** Runs one argv in the build sandbox; `envFile`: the app's variables are loaded (build, migrate), otherwise it never sees them. */
export type PySandbox = (argv: string[], o: { env: Record<string, string>; envFile: boolean; onLine?: (l: string) => void }) => Promise<void>;

export type PyCtx = {
  app: App;
  /** the release */
  dir: string;
  workdir: string;
  /** PATH of the build: uv and the pinned Python */
  path: string;
  /** uv's cache directory's parent (shared cache, or the release's own for an isolated build) */
  cache: string;
  log: (l: string) => void;
  step: (s: string) => void | Promise<void>;
  sb: PySandbox;
};

export const venvDir = (release: string) => `${release}/.venv`;

const pythonBin = (app: App) => `${paths.runtimes}/python/${app.runtime_version}/bin/python3`;

/** Environment of a step that runs with the venv active. */
const venvEnv = (c: PyCtx, extra: Record<string, string> = {}) => ({
  PATH: `${venvDir(c.dir)}/bin:${c.path}`,
  VIRTUAL_ENV: venvDir(c.dir),
  PYTHONUNBUFFERED: "1",
  ...extra,
});

export type PyBuilt = { plan: PyPlan; maps: { url: string; src: string }[] };

/** Install dependencies and build; returns what detection found and where static files are (not yet copied). */
export async function buildPython(c: PyCtx): Promise<PyBuilt> {
  const { app } = c;
  const repo = await readRepo(c.workdir, app.py_requirements);
  const plan = detectPython(repo, app);
  c.log(`detected: install=${app.install_cmd ? "custom command" : plan.mode}${plan.requirements ? ` (${plan.requirements})` : ""}, django=${plan.django}, app=${plan.app ? `${plan.app.target} (${plan.app.kind})` : "none"}`);
  await ensureBuildPackages(plan.deps, c.log);

  const steps: PyStep[] = installSteps({
    mode: plan.mode,
    requirements: plan.requirements,
    venv: venvDir(c.dir),
    python: pythonBin(app),
    hashes: !!plan.requirements && hasHashes(repo.texts[plan.requirements] ?? ""),
    custom: !!app.install_cmd,
    cache: c.cache,
  });
  if (plan.mode === "none" && !app.install_cmd) c.log("no requirements.txt, pyproject.toml, uv.lock or poetry.lock: no dependencies installed");
  for (const s of steps) {
    await c.step(s.label);
    await c.sb(s.argv, { env: { ...s.env, PATH: c.path }, envFile: false, onLine: c.log });
  }
  if (app.install_cmd) {
    await c.step(app.install_cmd);
    await c.sb(["/bin/sh", "-c", app.install_cmd], { env: venvEnv(c, uvEnv({ venv: venvDir(c.dir), cache: c.cache })), envFile: false, onLine: c.log });
  }

  if (app.build_cmd) {
    await c.step(app.build_cmd);
    await c.sb(["/bin/sh", "-c", app.build_cmd], { env: venvEnv(c), envFile: true, onLine: c.log });
  }
  // Django: collectstatic with the app's env (settings read it). "auto" does not fail the deploy: many
  // projects have no STATIC_ROOT; "on" is the admin's word and does.
  let collected = false;
  if (triOn(app.py_collectstatic as PyTri, plan.django && !app.build_cmd)) {
    if (!plan.django) throw new Error("collectstatic needs a Django project (manage.py)");
    await c.step("collectstatic");
    try {
      await c.sb(djangoArgv(venvDir(c.dir), "collectstatic"), { env: venvEnv(c), envFile: true, onLine: c.log });
      collected = true;
    } catch (e) {
      if (app.py_collectstatic === "on") throw e;
      c.log(`collectstatic failed (${e instanceof Error ? e.message.split("\n")[0] : e}); continuing. Set STATIC_ROOT, or turn it off.`);
    }
  }
  return { plan, maps: await staticMaps(c, plan, collected) };
}

/** Which directories the edge serves: the admin's list, else (Django, after collectstatic) what the settings say. */
async function staticMaps(c: PyCtx, plan: PyPlan, collected: boolean): Promise<{ url: string; src: string }[]> {
  const given = parsePyStatic(c.app.py_static);
  if (given.length) return given.map((g) => ({ url: g.url, src: `${c.workdir}/${g.dir}` }));
  if (!plan.django || !collected) return [];
  const lines: string[] = [];
  try {
    await c.sb(djangoProbeArgv(venvDir(c.dir)), { env: venvEnv(c), envFile: true, onLine: (l) => lines.push(l) });
  } catch {
    return [];
  }
  const probe = parseStaticProbe(lines.join("\n"));
  if (!probe) return [];
  // The directory must be inside this release: settings are the app's, the copy is done as root.
  if (!insideDir(probe.root, c.dir)) {
    c.log(`STATIC_ROOT ${probe.root} is outside the release: its files are not served by the edge`);
    return [];
  }
  return [{ url: probe.url, src: probe.root }];
}

/** The start command: the admin's, or the detected server. Throws with what to set when nothing is known. */
export function startFor(plan: PyPlan, app: App, memoryMb: number, cpus: number): string {
  if (!plan.app) throw new Error('cannot find the WSGI/ASGI application: set "Python app" (module:attribute, e.g. config.wsgi:application) or a start command');
  return serverCommand(plan.app, (app.py_server || PY_DEFAULTS.py_server) as PyServer, app.py_workers || defaultWorkers(memoryMb, cpus));
}

/** gunicorn/uvicorn missing from the dependencies: installed last, and the log says so. */
export async function ensureServers(c: PyCtx, starts: Iterable<string>) {
  for (const pkg of new Set([...starts].map(serverPackage).filter(Boolean))) {
    if (await exists(`${venvDir(c.dir)}/bin/${pkg}`)) continue;
    const s = serverInstallStep(pkg as "gunicorn" | "uvicorn", { venv: venvDir(c.dir), cache: c.cache });
    await c.step(s.label);
    c.log(`${pkg} is not in your dependencies: add it to your requirements to pin its version`);
    await c.sb(s.argv, { env: { ...s.env, PATH: c.path }, envFile: false, onLine: c.log });
  }
}

/**
 * Django `migrate --noinput`, once per release, after the build and before anything of the new
 * release starts or any traffic moves: if it fails the deploy fails and the live release keeps running.
 * It runs against the live database, so migrations must work with the previous release's code too
 * (add before you remove); a rollback does not undo them.
 */
export async function migrate(c: PyCtx, plan: PyPlan) {
  if (!triOn(c.app.py_migrate as PyTri, plan.django)) return;
  if (!plan.django) throw new Error("migrate needs a Django project (manage.py)");
  await c.step("migrate (before the traffic switch)");
  await c.sb(djangoArgv(venvDir(c.dir), "migrate"), { env: venvEnv(c), envFile: true, onLine: c.log });
}

/** Copies the static files into the slot's own directories for the edge; returns the URL prefixes that are now served. */
export async function publishStatic(c: PyCtx, slot: "a" | "b", maps: { url: string; src: string }[]): Promise<string[]> {
  await remove(`${paths.static}/${c.app.name}/${slot}`);
  const urls: string[] = [];
  for (const m of maps) {
    if (!(await lstat(fsPath(m.src)).catch(() => null))?.isDirectory()) {
      c.log(`static files: ${m.src} does not exist, ${m.url} is left to the app`);
      continue;
    }
    const r = await snapshotStatic(m.src, c.dir, staticDir(c.app.name, slot, urls.length));
    c.log(`static files ${m.url}: ${r.files} files (${Math.round(r.bytes / 1024)} KB) served by the edge${r.skipped ? `, ${r.skipped} skipped (links, dot files, too large)` : ""}`);
    urls.push(m.url);
  }
  return urls;
}
