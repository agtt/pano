// Python apps (Django, FastAPI, Flask, any WSGI/ASGI app): everything that can be decided without
// touching the system. Detection of what a repository needs, the argv of every install step, the
// start command, validation of the Python-specific settings. The agent (agent/python.ts, apps.ts)
// only runs what these functions return, so it is all testable without a server.

import { paths } from "./config.ts";
import { v, ValidationError } from "./validate.ts";

function check(ok: boolean, msg: string): asserts ok {
  if (!ok) throw new ValidationError(msg);
}

// ---- settings of a Python app --------------------------------------------------

export const PY_SERVERS = ["auto", "gunicorn", "uvicorn"] as const;
export type PyServer = (typeof PY_SERVERS)[number];
export const PY_TRI = ["auto", "on", "off"] as const;
export type PyTri = (typeof PY_TRI)[number];

export type PyStatic = { url: string; dir: string };

/** The Python-specific columns of an app; the defaults are what other runtimes keep (unused). */
export type PyFields = {
  py_server: PyServer;
  /** module:attribute of the WSGI/ASGI application; empty: detected */
  py_app: string;
  /** requirements file, relative to the root directory; empty: detected */
  py_requirements: string;
  /** Django `collectstatic --noinput` in the build */
  py_collectstatic: PyTri;
  /** Django `migrate --noinput` once per release, before the traffic switch */
  py_migrate: PyTri;
  /** `/static | staticfiles` per line: URL prefix and directory (relative to the root directory) the edge serves */
  py_static: string;
  /** server worker processes; 0: from the memory limit */
  py_workers: number;
};

export const PY_DEFAULTS: PyFields = {
  py_server: "auto",
  py_app: "",
  py_requirements: "",
  py_collectstatic: "auto",
  py_migrate: "auto",
  py_static: "",
  py_workers: 0,
};

const PY_APP = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$/;
const PY_FILE = /^[A-Za-z0-9_.][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_.][A-Za-z0-9._-]*)*$/;
const STATIC_URL = /^\/[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*$/;

const oneOf = <T extends string>(list: readonly T[], x: unknown, def: T, field: string): T => {
  const s = String(x ?? "").trim() || def;
  check((list as readonly string[]).includes(s), `${field} must be ${list.join(", ")}`);
  return s as T;
};

/** `url | dir` per line (# comments allowed), at most 4. */
export function parsePyStatic(text: unknown): PyStatic[] {
  const out: PyStatic[] = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [url = "", dir = "", ...rest] = line.split("|").map((x) => x.trim());
    const u = url.replace(/\/+$/, "");
    check(STATIC_URL.test(u) && !u.split("/").some((p) => p === ".."), `static files: "/static | staticfiles" expected: ${line.slice(0, 60)}`);
    check(!rest.length && !!dir, `static files: "/static | staticfiles" expected: ${line.slice(0, 60)}`);
    check(!out.some((p) => p.url === u), `static files: ${u} is listed twice`);
    out.push({ url: u, dir: v.subdir(dir) });
  }
  check(out.length <= 4, "at most 4 static file directories");
  return out;
}

export const formatPyStatic = (list: PyStatic[]) => list.map((p) => `${p.url} | ${p.dir}`).join("\n");

/** Validates the Python-specific part of the app form / API call. */
export function validatePython(x: Record<string, unknown>): PyFields {
  const app = String(x.py_app ?? "").trim();
  check(!app || PY_APP.test(app), "Python app: module.path:attribute, e.g. config.wsgi:application");
  const req = String(x.py_requirements ?? "").trim().replace(/^\.\//, "");
  check(!req || (PY_FILE.test(req) && !req.split("/").includes("..") && req.length <= 200), "requirements file: a relative path such as requirements/production.txt");
  return {
    py_server: oneOf(PY_SERVERS, x.py_server, "auto", "server"),
    py_app: app,
    py_requirements: req,
    py_collectstatic: oneOf(PY_TRI, x.py_collectstatic, "auto", "collectstatic"),
    py_migrate: oneOf(PY_TRI, x.py_migrate, "auto", "migrate"),
    py_static: formatPyStatic(parsePyStatic(x.py_static)),
    py_workers: v.int(x.py_workers || 0, 0, 32, "workers"),
  };
}

/** Where the collected static files of a Python app's slot are served from: root-owned copies, one directory per mapping and slot, so a deploy never touches what is live. */
export const staticDir = (app: string, slot: string, i: number) => `${paths.static}/${app}/${slot}/${i}`;

/** URL prefixes the edge serves for the live release (state column static_live, a JSON array). */
export function liveStatic(raw: unknown): string[] {
  try {
    const list = JSON.parse(String(raw || "[]"));
    return Array.isArray(list) ? list.filter((u): u is string => typeof u === "string" && STATIC_URL.test(u)) : [];
  } catch {
    return [];
  }
}

// ---- reading a repository ------------------------------------------------------

/**
 * What the agent read of a repository (it does the I/O, safely: no links followed, size limits):
 * `files` are relative paths up to two levels deep, `texts` the contents of the few files detection needs.
 */
export type PyRepo = { files: Set<string>; texts: Record<string, string> };

/** PEP 503 normalized name. */
export const normName = (n: string) => n.toLowerCase().replace(/[-_.]+/g, "-");

/** Package names in a requirements file (options, comments, URLs and includes are skipped). */
export function requirementNames(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s#.*$/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:$|[<>=!~;@,( ])/);
    if (m) out.push(normName(m[1]!));
  }
  return out;
}

/** Names out of pyproject.toml (PEP 621 lists, Poetry tables) and lock files (`name = "x"` per package). */
export function projectNames(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/^name = "([A-Za-z0-9][A-Za-z0-9._-]*)"\s*$/gm)) out.add(normName(m[1]!));
  // "django>=5", "psycopg2-binary[extra]==2.9"
  for (const m of text.matchAll(/"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@][^"]*)?"/g)) out.add(normName(m[1]!));
  // [tool.poetry.dependencies] django = "^5"
  let inDeps = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*\[/.test(line)) inDeps = /^\s*\[tool\.poetry(\.group\.[\w-]+)?\.dependencies\]/.test(line);
    else if (inDeps) {
      const m = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/);
      if (m) out.add(normName(m[1]!));
    }
  }
  return [...out];
}

const REQ_ROOT = ["requirements.txt"];
/** Under requirements/: what a deployment installs, most specific first (they usually include base.txt). */
const REQ_DIR = ["production", "prod", "deploy", "main", "base", "common"];

/** Files the agent loads for detection (requirements/*.txt are added by what the directory holds). */
export const PY_TEXT_FILES = ["pyproject.toml", "uv.lock", "poetry.lock", "requirements.txt", "manage.py", "Pipfile", "setup.py"];
export const PY_APP_FILES = ["main.py", "app.py", "application.py", "server.py", "wsgi.py", "asgi.py", "app/main.py", "app/__init__.py", "src/main.py", "src/app.py"];

export type PyInstallMode = "uv-lock" | "poetry" | "requirements" | "pyproject" | "none";

/** The requirements file a deploy installs: the configured one, requirements.txt, or the best file in requirements/. */
export function pickRequirements(repo: PyRepo, configured: string): string {
  if (configured) return configured;
  const has = (f: string) => repo.files.has(f);
  const root = REQ_ROOT.find(has);
  if (root) return root;
  for (const n of REQ_DIR) if (has(`requirements/${n}.txt`)) return `requirements/${n}.txt`;
  const any = [...repo.files].filter((f) => /^requirements\/[A-Za-z0-9._-]+\.txt$/.test(f)).sort()[0];
  return any ?? "";
}

export function installMode(repo: PyRepo, configured = ""): { mode: PyInstallMode; requirements: string } {
  const has = (f: string) => repo.files.has(f);
  const pyproject = repo.texts["pyproject.toml"] ?? "";
  // An explicit requirements file beats any lock: the admin chose it.
  if (configured) return { mode: "requirements", requirements: configured };
  if (has("uv.lock") && has("pyproject.toml")) return { mode: "uv-lock", requirements: "" };
  if (has("poetry.lock") && has("pyproject.toml")) return { mode: "poetry", requirements: "" };
  const req = pickRequirements(repo, "");
  if (req) return { mode: "requirements", requirements: req };
  if (has("pyproject.toml")) return { mode: /^\s*\[tool\.poetry\]/m.test(pyproject) && !/^\s*\[project\]/m.test(pyproject) ? "poetry" : "pyproject", requirements: "" };
  return { mode: "none", requirements: "" };
}

/** Every package name the repository mentions (all requirement files, pyproject, locks). */
export function dependencyNames(repo: PyRepo): Set<string> {
  const out = new Set<string>();
  for (const [file, text] of Object.entries(repo.texts)) {
    if (file.endsWith(".txt")) for (const n of requirementNames(text)) out.add(n);
    else if (file.endsWith(".toml") || file.endsWith(".lock")) for (const n of projectNames(text)) out.add(n);
  }
  return out;
}

export type PyApp = { kind: "wsgi" | "asgi"; target: string };

const ASGI_FRAMEWORKS = ["fastapi", "starlette", "quart", "litestar", "sanic"];
const ASGI_SERVERS = ["uvicorn", "hypercorn", "daphne", "granian"];

/** Django project: manage.py mentions Django's settings. */
export function isDjango(repo: PyRepo): boolean {
  return repo.files.has("manage.py") && /DJANGO_SETTINGS_MODULE|django/i.test(repo.texts["manage.py"] ?? "");
}

/** `proj.settings` out of manage.py's `os.environ.setdefault("DJANGO_SETTINGS_MODULE", "proj.settings")`. */
export function djangoSettings(repo: PyRepo): string {
  return (repo.texts["manage.py"] ?? "").match(/["']DJANGO_SETTINGS_MODULE["']\s*,\s*["']([A-Za-z_][\w.]*)["']/)?.[1] ?? "";
}

/** The package that holds wsgi.py/asgi.py: the first part of the settings module, or the only top-level directory that has one. */
export function djangoPackage(repo: PyRepo): string {
  const s = djangoSettings(repo).split(".")[0];
  if (s && repo.files.has(`${s}/wsgi.py`)) return s;
  const dirs = [...repo.files].map((f) => f.match(/^([A-Za-z_][A-Za-z0-9_]*)\/wsgi\.py$/)?.[1]).filter((x): x is string => !!x);
  return dirs.length === 1 ? dirs[0]! : s || "";
}

/** `main.py` -> `main`, `app/main.py` -> `app.main`. */
const moduleOf = (file: string) => file.replace(/\.py$/, "").replace(/\/__init__$/, "").replace(/\//g, ".");

/** Finds the application object in the usual entry files: `app = FastAPI()`, `application = get_wsgi_application()`. */
export function detectApp(repo: PyRepo, deps: Set<string>): PyApp | null {
  for (const file of PY_APP_FILES) {
    const text = repo.texts[file];
    if (text === undefined || !repo.files.has(file)) continue;
    const mod = moduleOf(file);
    const m = text.match(/^(\w+)\s*(?::[^=\n]+)?=\s*(?:\w+\.)*(FastAPI|Starlette|Quart|Litestar|Sanic|Flask|Bottle)\s*\(/m);
    if (m) return { kind: ["Flask", "Bottle"].includes(m[2]!) ? "wsgi" : "asgi", target: `${mod}:${m[1]}` };
    if (/^application\s*=/m.test(text)) return { kind: file === "asgi.py" || /asgi/i.test(text) ? "asgi" : "wsgi", target: `${mod}:application` };
    if (file === "wsgi.py" || file === "asgi.py") return { kind: file === "asgi.py" ? "asgi" : "wsgi", target: `${mod}:${/^app\s*=/m.test(text) ? "app" : "application"}` };
    if (/^app\s*=/m.test(text)) return { kind: ASGI_FRAMEWORKS.some((f) => deps.has(f)) ? "asgi" : "wsgi", target: `${mod}:app` };
  }
  return null;
}

export type PyPlan = {
  mode: PyInstallMode;
  requirements: string;
  django: boolean;
  /** null: nothing found, the admin must give the application or a start command */
  app: PyApp | null;
  deps: Set<string>;
};

/** Everything detection decides, from what the agent read. */
export function detectPython(repo: PyRepo, f: Pick<PyFields, "py_requirements" | "py_app" | "py_server">): PyPlan {
  const { mode, requirements } = installMode(repo, f.py_requirements);
  const deps = dependencyNames(repo);
  const django = isDjango(repo);
  let app: PyApp | null = null;
  if (f.py_app) {
    // The server decides the protocol; with "auto", the dependencies do.
    const asgi = f.py_server === "uvicorn" || (f.py_server === "auto" && [...ASGI_FRAMEWORKS, ...ASGI_SERVERS].some((d) => deps.has(d)) && !(django && !deps.has("channels")));
    app = { kind: asgi ? "asgi" : "wsgi", target: f.py_app };
  } else if (django) {
    const pkg = djangoPackage(repo);
    const asgi = f.py_server === "uvicorn" || (f.py_server === "auto" && repo.files.has(`${pkg}/asgi.py`) && (deps.has("channels") || deps.has("daphne")));
    if (pkg) app = { kind: asgi ? "asgi" : "wsgi", target: `${pkg}.${asgi ? "asgi" : "wsgi"}:application` };
  } else {
    app = detectApp(repo, deps);
  }
  return { mode, requirements, django, app, deps };
}

// ---- Django steps ---------------------------------------------------------------

/** "auto" follows Django detection, "on"/"off" are the admin's word. */
export const triOn = (t: PyTri, auto: boolean) => (t === "on" ? true : t === "off" ? false : auto);

// ---- server command --------------------------------------------------------------

/** Workers when the admin set none: what the memory limit holds (about 384 MB each), at most 2 per core + 1 and 8. */
export function defaultWorkers(memoryMb: number, cpus: number): number {
  return Math.max(1, Math.min(2 * Math.max(1, cpus) + 1, 8, Math.floor(memoryMb / 384)));
}

/**
 * The server for a detected app. gunicorn runs WSGI, uvicorn ASGI; the other combination is refused
 * with a clear message instead of a crash loop. $PORT comes from the slot's env file; both bind to
 * 127.0.0.1 only and trust forwarded headers from there only (the edge is the one proxy).
 */
export function serverCommand(app: PyApp, server: PyServer, workers: number): string {
  check(PY_APP.test(app.target), `Python app ${app.target} is not module:attribute`);
  const useUvicorn = server === "uvicorn" || (server === "auto" && app.kind === "asgi");
  if (useUvicorn) {
    check(app.kind === "asgi", `${app.target} is a WSGI app: use gunicorn (or point "Python app" at an ASGI one)`);
    return `uvicorn ${app.target} --host 127.0.0.1 --port $PORT --workers ${workers} --proxy-headers --forwarded-allow-ips 127.0.0.1`;
  }
  check(app.kind === "wsgi", `${app.target} is an ASGI app: use uvicorn`);
  return `gunicorn ${app.target} --bind 127.0.0.1:$PORT --workers ${workers} --timeout 60 --graceful-timeout 20 --access-logfile - --error-logfile - --forwarded-allow-ips 127.0.0.1`;
}

/** Which server binary the start command needs in the venv. */
export const serverPackage = (cmd: string): "gunicorn" | "uvicorn" | "" => (/^gunicorn\b/.test(cmd) ? "gunicorn" : /^uvicorn\b/.test(cmd) ? "uvicorn" : "");

// ---- install steps ----------------------------------------------------------------

export type PyStep = { label: string; argv: string[]; env?: Record<string, string> };

/** Poetry is not part of the repository: run once through uv from PyPI (uv checks the hashes the index gives). */
export const POETRY_SPEC = "poetry>=2,<3";

export type PyInstallInput = {
  mode: PyInstallMode;
  requirements: string;
  /** absolute path of the release's virtualenv */
  venv: string;
  /** absolute path of the pinned interpreter */
  python: string;
  /** a requirements file with --hash= lines is installed with --require-hashes */
  hashes: boolean;
  /** admin's own install command: it only gets the empty virtualenv */
  custom?: boolean;
  /** directory for uv's caches (shared between releases unless the build is isolated) */
  cache: string;
};

/** Environment every uv step gets: never downloads a Python, never reads user config, project env = the release's venv. */
export function uvEnv(i: Pick<PyInstallInput, "venv" | "cache">): Record<string, string> {
  return {
    UV_PYTHON_DOWNLOADS: "never",
    UV_NO_CONFIG: "1",
    UV_NO_PROGRESS: "1",
    UV_CACHE_DIR: `${i.cache}/uv`,
    UV_PROJECT_ENVIRONMENT: i.venv,
    VIRTUAL_ENV: i.venv,
  };
}

/** The argv of each install step; no shell anywhere. The venv is created by uv from the pinned interpreter, never from system Python. */
export function installSteps(i: PyInstallInput): PyStep[] {
  const env = uvEnv(i);
  const venv: PyStep = { label: "create virtualenv", argv: ["uv", "venv", "--python", i.python, "--no-managed-python", i.venv], env };
  const target = `${i.venv}/bin/python`;
  if (i.custom) return [venv];
  switch (i.mode) {
    case "uv-lock":
      return [{ label: "uv sync (uv.lock)", argv: ["uv", "sync", "--locked", "--no-dev", "--no-install-project", "--python", i.python, "--no-managed-python"], env }];
    case "poetry":
      return [
        venv,
        {
          label: "poetry install (poetry.lock)",
          argv: ["uv", "tool", "run", "--python", i.python, "--no-managed-python", "--from", POETRY_SPEC, "poetry", "install", "--no-root", "--only", "main", "--no-interaction"],
          env: { ...env, POETRY_VIRTUALENVS_CREATE: "false", POETRY_NO_INTERACTION: "1", POETRY_CACHE_DIR: `${i.cache}/poetry`, UV_TOOL_DIR: `${i.cache}/uv-tools`, UV_TOOL_BIN_DIR: `${i.cache}/uv-tools/bin` },
        },
      ];
    case "requirements":
      return [venv, { label: `install ${i.requirements}`, argv: ["uv", "pip", "install", "--python", target, ...(i.hashes ? ["--require-hashes"] : []), "-r", i.requirements], env }];
    case "pyproject":
      return [venv, { label: "install pyproject.toml dependencies", argv: ["uv", "pip", "install", "--python", target, "-r", "pyproject.toml"], env }];
    default:
      return [venv];
  }
}

/** The server was not in the dependencies: installed after them (not pinned, the log says so). */
export function serverInstallStep(pkg: "gunicorn" | "uvicorn", i: Pick<PyInstallInput, "venv" | "cache">): PyStep {
  return { label: `install ${pkg} (not in your dependencies)`, argv: ["uv", "pip", "install", "--python", `${i.venv}/bin/python`, pkg], env: uvEnv(i) };
}

/** True when a requirements file pins hashes. */
export const hasHashes = (text: string) => /--hash=sha\d+:/.test(text);

// ---- Django ---------------------------------------------------------------------------

export const djangoArgv = (venv: string, sub: "collectstatic" | "migrate"): string[] => [`${venv}/bin/python`, "manage.py", sub, "--noinput"];

/** Asks Django where its static files are: one line `PANO_STATIC <url> <root>`. */
export const STATIC_PROBE = 'from django.conf import settings as s; print("PANO_STATIC", s.STATIC_URL or "-", s.STATIC_ROOT or "-")';
export const djangoProbeArgv = (venv: string): string[] => [`${venv}/bin/python`, "manage.py", "shell", "-c", STATIC_PROBE];

/** `{url, root}` out of the probe's output; null when Django serves no static files of its own. */
export function parseStaticProbe(output: string): { url: string; root: string } | null {
  const m = output.match(/^PANO_STATIC (\S+) (\S+)$/m);
  if (!m || m[1] === "-" || m[2] === "-") return null;
  const url = m[1]!;
  if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith("//")) return null; // a CDN
  const path = ("/" + url.split(/[?#]/)[0]!).replace(/\/+/g, "/").replace(/\/$/, "");
  return STATIC_URL.test(path) && m[2]!.startsWith("/") ? { url: path, root: m[2]! } : null;
}

/** Whether `path` is inside `root` (both absolute, already resolved); never the root itself. */
export const insideDir = (path: string, root: string) => path.startsWith(root.replace(/\/+$/, "") + "/") && !path.split("/").includes("..");

// ---- native build packages ----------------------------------------------------------------

/**
 * OS packages a source build of a Python package needs. Only packages without a ready wheel for
 * Linux (mysqlclient, psycopg2, python-ldap) are listed; Pillow, lxml, cryptography, numpy and
 * the like come as wheels and need nothing. Python itself needs nothing (its headers are in the
 * runtime). Installed when the first app that needs them deploys, never earlier.
 */
const NATIVE: Record<string, { el: string[]; debian: string[] }> = {
  mysqlclient: { el: ["gcc", "pkgconf-pkg-config", "mariadb-connector-c-devel"], debian: ["gcc", "pkg-config", "libmariadb-dev"] },
  psycopg2: { el: ["gcc", "libpq-devel"], debian: ["gcc", "libpq-dev"] },
  "python-ldap": { el: ["gcc", "openldap-devel", "cyrus-sasl-devel"], debian: ["gcc", "libldap2-dev", "libsasl2-dev"] },
};

export function nativePackages(deps: Iterable<string>, family: "el" | "debian"): string[] {
  const out = new Set<string>();
  for (const d of deps) for (const p of NATIVE[d]?.[family] ?? []) out.add(p);
  return [...out].sort();
}

// ---- unit and script rendering -----------------------------------------------------------------

/** POSIX single-quoted word. */
export const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/**
 * The start script of a Python process: the slot's virtualenv first on PATH, then `exec` the command.
 * `slot` is the slot's directory (home/slot-a); the venv sits at the release root, where the build made it.
 */
export function pythonStartScript(slot: string, start: string): string {
  return `#!/bin/sh\nset -e\nVIRTUAL_ENV=${shq(`${slot}/.venv`)}\nexport VIRTUAL_ENV\nPATH="$VIRTUAL_ENV/bin:$PATH"\nexec ${start}\n`;
}

/** Cron script of a Python app: same PATH as the process, in the live release. */
export function pythonCronScript(current: string, command: string): string {
  return `#!/bin/sh\nset -e\nVIRTUAL_ENV=${shq(`${current}/.venv`)}\nexport VIRTUAL_ENV\nPATH="$VIRTUAL_ENV/bin:$PATH"\n${command}\n`;
}

// ---- python-build-standalone / uv downloads ------------------------------------------------------

export const PBS_FLAVOR = "install_only_stripped";
const triple = (arch: "x64" | "arm64") => (arch === "arm64" ? "aarch64-unknown-linux-gnu" : "x86_64-unknown-linux-gnu");

export const pbsAsset = (version: string, tag: string, arch: "x64" | "arm64") => `cpython-${version}+${tag}-${triple(arch)}-${PBS_FLAVOR}.tar.gz`;
export const uvAsset = (arch: "x64" | "arm64") => `uv-${triple(arch)}.tar.gz`;

const cmp3 = (a: string, b: string) => {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
};

/**
 * Newest CPython matching `wanted` ("3.14" or "3.14.2") among a release's asset names, for this CPU.
 * Pre-releases (3.15.0a1) never match.
 */
export function pickPython(names: string[], wanted: string, arch: "x64" | "arm64"): { version: string; asset: string } | null {
  const re = new RegExp(`^cpython-(\\d+\\.\\d+\\.\\d+)\\+\\d+-${triple(arch)}-${PBS_FLAVOR}\\.tar\\.gz$`);
  const found = names
    .map((asset) => ({ asset, version: asset.match(re)?.[1] ?? "" }))
    .filter((x) => x.version && (x.version === wanted || x.version.startsWith(`${wanted}.`)))
    .sort((a, b) => cmp3(b.version, a.version));
  return found[0] ?? null;
}

/** Every CPython version a release offers for this CPU, newest first (one per minor: the newest patch). */
export function listPython(names: string[], arch: "x64" | "arm64"): string[] {
  const re = new RegExp(`^cpython-(\\d+\\.\\d+\\.\\d+)\\+\\d+-${triple(arch)}-${PBS_FLAVOR}\\.tar\\.gz$`);
  const best = new Map<string, string>();
  for (const n of names) {
    const ver = n.match(re)?.[1];
    if (!ver) continue;
    const minor = ver.split(".").slice(0, 2).join(".");
    if (!best.has(minor) || cmp3(ver, best.get(minor)!) > 0) best.set(minor, ver);
  }
  return [...best.values()].sort((a, b) => cmp3(b, a));
}

/** A release's asset the way GitHub's API lists it. */
export type GhAsset = { name: string; browser_download_url: string };

/** A download URL must stay on github.com/astral-sh: the API answer is data, not trust. */
export const trustedDownload = (url: string) => /^https:\/\/github\.com\/astral-sh\/(python-build-standalone|uv)\/releases\/download\/[A-Za-z0-9._%+-]+\/[A-Za-z0-9._%+-]+$/.test(url);

/** What stays after the last Python runtime is removed: uv and the (then empty) python directory go with it. */
export function afterUninstall(remaining: { runtime: string }[]): { removeUv: boolean } {
  return { removeUv: !remaining.some((r) => r.runtime === "python") };
}
