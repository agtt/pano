import { describe, expect, spyOn, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { renderUnit, teardownUnits, validateAppInput } from "../src/agent/apps.ts";
import { renderCaddyfile } from "../src/agent/edge.ts";
import { migrate } from "../src/agent/pydeploy.ts";
import { readRepo, snapshotStatic, stageInstall, uninstallPython } from "../src/agent/python.ts";
import { installed, installedAll, runtimeBin } from "../src/agent/runtimes.ts";
import { alwaysAsk, changesRuntimeEnv, methods } from "../src/agent/rpc.ts";
import { previewApp, type App } from "../src/agent/state.ts";
import { fsPath, paths } from "../src/shared/config.ts";
import {
  PY_DEFAULTS, POETRY_SPEC, isPreviewName, sharedStoreKeys, STATIC_PROBE, afterUninstall, defaultWorkers, detectPython, djangoArgv, djangoProbeArgv, formatPyStatic, hasHashes, insideDir, installMode,
  installSteps, listPython, liveStatic, nativePackages, parsePyStatic, parseStaticProbe, pbsAsset, pickPython, pickRequirements, projectNames, pythonCronScript, pythonStartScript,
  requirementNames, serverCommand, serverInstallStep, serverPackage, shq, staticDir, triOn, trustedDownload, uvAsset, validatePython, type PyRepo,
} from "../src/shared/python.ts";
import { v } from "../src/shared/validate.ts";

const repo = (files: Record<string, string>): PyRepo => ({ files: new Set(Object.keys(files)), texts: files });

const django = repo({
  "manage.py": `import os\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "khateeb.settings.production")\n`,
  "khateeb/wsgi.py": "application = get_wsgi_application()",
  "khateeb/asgi.py": "application = get_asgi_application()",
  "requirements/base.txt": "Django==6.0\nmysqlclient==2.2.7\ngunicorn==23.0\n",
  "requirements/production.txt": "-r base.txt\nsentry-sdk==2.0\n",
});

describe("validation", () => {
  test("python versions", () => {
    expect(v.pythonVersion("3.14")).toBe("3.14");
    expect(v.pythonVersion("v3.13.5")).toBe("3.13.5");
    for (const bad of ["3", "2.7", "3.14.1.1", "3.x", "3.13; rm", "", "../3.13"]) expect(() => v.pythonVersion(bad)).toThrow();
    expect(v.runtimeVersion("node", "24.1.0")).toBe("24.1.0");
    expect(() => v.runtimeVersion("node", "24")).toThrow();
    expect(v.runtime("python")).toBe("python");
    expect(() => v.runtime("ruby")).toThrow();
  });

  test("python settings", () => {
    expect(validatePython({})).toEqual(PY_DEFAULTS);
    const ok = validatePython({ py_server: "uvicorn", py_app: "config.asgi:application", py_requirements: "./requirements/prod.txt", py_collectstatic: "off", py_migrate: "on", py_workers: "3", py_static: "/static/ | staticfiles\n# c\n/assets | web/dist" });
    expect(ok).toMatchObject({ py_server: "uvicorn", py_requirements: "requirements/prod.txt", py_collectstatic: "off", py_migrate: "on", py_workers: 3 });
    expect(ok.py_static).toBe("/static | staticfiles\n/assets | web/dist");
    for (const bad of [
      { py_app: "x.wsgi:app; rm -rf /" }, { py_app: "wsgi" }, { py_app: "a b:c" }, { py_requirements: "../x.txt" }, { py_requirements: "-r evil.txt" }, { py_requirements: "a b.txt" },
      { py_server: "waitress" }, { py_migrate: "yes" }, { py_workers: 99 }, { py_static: "static | x" }, { py_static: "/ | x" }, { py_static: "/a | ../x" }, { py_static: "/a | x\n/a | y" },
      { py_static: "/a|b|c" }, { py_static: "/1 | a\n/2 | a\n/3 | a\n/4 | a\n/5 | a" },
    ]) expect(() => validatePython(bad)).toThrow();
    expect(formatPyStatic(parsePyStatic("/static/ | staticfiles"))).toBe("/static | staticfiles");
  });

  test("app input: python fields only for python, other runtimes keep the defaults", () => {
    const base = { name: "web", domains: "example.com", repo: "https://github.com/a/b.git" };
    const py = validateAppInput({ ...base, runtime: "python", runtime_version: "3.14", py_server: "gunicorn", py_migrate: "off" });
    expect(py).toMatchObject({ runtime: "python", runtime_version: "3.14", py_server: "gunicorn", py_migrate: "off" });
    const node = validateAppInput({ ...base, runtime: "node", runtime_version: "22.0.0", py_server: "uvicorn", py_migrate: "on" });
    expect(node).toMatchObject(PY_DEFAULTS);
    expect(() => validateAppInput({ ...base, runtime: "node", runtime_version: "22" })).toThrow();
    expect(() => validateAppInput({ ...base, runtime: "python", runtime_version: "3.14", py_app: "a:b c" })).toThrow();
  });
});

describe("detection", () => {
  test("requirement and project names", () => {
    expect(requirementNames("Django==6.0  # web\n-r base.txt\n--hash=x\nmysqlclient>=2\npsycopg2_binary[x]==2.9 ; python_version>'3'\ngit+https://x/y#egg=z\nPillow\n")).toEqual([
      "django", "mysqlclient", "psycopg2-binary", "pillow",
    ]);
    const names = projectNames('[project]\nname = "app"\ndependencies = [\n  "Django>=5,<6",\n  "gunicorn",\n  "psycopg2[x]==2.9",\n]\n[tool.poetry.dependencies]\npython = "^3.13"\nfastapi = "^0.1"\n');
    expect(names).toEqual(expect.arrayContaining(["django", "gunicorn", "psycopg2", "fastapi", "app"]));
  });

  test("install mode: lock files first, then requirements, then pyproject", () => {
    expect(installMode(repo({ "uv.lock": "", "pyproject.toml": "", "requirements.txt": "" })).mode).toBe("uv-lock");
    expect(installMode(repo({ "poetry.lock": "", "pyproject.toml": "[tool.poetry]\n" })).mode).toBe("poetry");
    expect(installMode(repo({ "uv.lock": "" })).mode).toBe("none");
    expect(installMode(repo({ "requirements.txt": "x" }))).toEqual({ mode: "requirements", requirements: "requirements.txt" });
    expect(installMode(repo({ "requirements.txt": "x", "uv.lock": "", "pyproject.toml": "" }), "requirements/prod.txt")).toEqual({ mode: "requirements", requirements: "requirements/prod.txt" });
    expect(installMode(repo({ "pyproject.toml": '[project]\nname="x"\n' })).mode).toBe("pyproject");
    expect(installMode(repo({ "pyproject.toml": '[tool.poetry]\nname="x"\n' })).mode).toBe("poetry");
    expect(installMode(repo({})).mode).toBe("none");
  });

  test("requirements/ directory: the deployment file wins, then base, then any", () => {
    expect(pickRequirements(django, "")).toBe("requirements/production.txt");
    expect(pickRequirements(repo({ "requirements/base.txt": "", "requirements/dev.txt": "" }), "")).toBe("requirements/base.txt");
    expect(pickRequirements(repo({ "requirements/dev.txt": "", "requirements/a.txt": "" }), "")).toBe("requirements/a.txt");
    expect(pickRequirements(django, "requirements/custom.txt")).toBe("requirements/custom.txt");
    expect(pickRequirements(repo({}), "")).toBe("");
  });

  test("Django: wsgi module from manage.py, gunicorn", () => {
    const p = detectPython(django, PY_DEFAULTS);
    expect(p).toMatchObject({ mode: "requirements", requirements: "requirements/production.txt", django: true, app: { kind: "wsgi", target: "khateeb.wsgi:application" } });
    expect(p.deps.has("mysqlclient")).toBe(true);
    expect(p.deps.has("sentry-sdk")).toBe(true);
  });

  test("Django with channels uses asgi; an explicit app and server win", () => {
    const ch = repo({ ...django.texts, "requirements/base.txt": "Django\nchannels\nuvicorn\n" });
    expect(detectPython(ch, PY_DEFAULTS).app).toEqual({ kind: "asgi", target: "khateeb.asgi:application" });
    expect(detectPython(django, { ...PY_DEFAULTS, py_server: "uvicorn" }).app?.kind).toBe("asgi");
    expect(detectPython(django, { ...PY_DEFAULTS, py_app: "config.wsgi:application" }).app).toEqual({ kind: "wsgi", target: "config.wsgi:application" });
    // package without settings in manage.py: the only directory with a wsgi.py
    expect(detectPython(repo({ "manage.py": "# django", "site/wsgi.py": "application = x" }), PY_DEFAULTS).app?.target).toBe("site.wsgi:application");
    expect(detectPython(repo({ "manage.py": "# django" }), PY_DEFAULTS).app).toBeNull();
  });

  test("FastAPI, Flask, plain wsgi", () => {
    expect(detectPython(repo({ "main.py": "from fastapi import FastAPI\napp = FastAPI()\n", "requirements.txt": "fastapi\nuvicorn" }), PY_DEFAULTS).app).toEqual({ kind: "asgi", target: "main:app" });
    expect(detectPython(repo({ "app.py": "app = Flask(__name__)\n" }), PY_DEFAULTS).app).toEqual({ kind: "wsgi", target: "app:app" });
    expect(detectPython(repo({ "app/main.py": "api: FastAPI = FastAPI()\n" }), PY_DEFAULTS).app).toEqual({ kind: "asgi", target: "app.main:api" });
    expect(detectPython(repo({ "wsgi.py": "from app import create\napplication = create()\n" }), PY_DEFAULTS).app).toEqual({ kind: "wsgi", target: "wsgi:application" });
    expect(detectPython(repo({ "server.py": "app = something()\n", "requirements.txt": "starlette" }), PY_DEFAULTS).app).toEqual({ kind: "asgi", target: "server:app" });
    expect(detectPython(repo({ "readme.md": "" }), PY_DEFAULTS).app).toBeNull();
    expect(detectPython(repo({ "requirements.txt": "fastapi" }), { ...PY_DEFAULTS, py_app: "svc.api:app" }).app).toEqual({ kind: "asgi", target: "svc.api:app" });
    expect(detectPython(repo({ "requirements.txt": "flask" }), { ...PY_DEFAULTS, py_app: "svc.api:app" }).app?.kind).toBe("wsgi");
  });
});

describe("server command", () => {
  test("gunicorn and uvicorn bind to 127.0.0.1 and trust only it", () => {
    const g = serverCommand({ kind: "wsgi", target: "a.wsgi:application" }, "auto", 3);
    expect(g).toBe("gunicorn a.wsgi:application --bind 127.0.0.1:$PORT --workers 3 --timeout 60 --graceful-timeout 20 --access-logfile - --error-logfile - --forwarded-allow-ips 127.0.0.1");
    const u = serverCommand({ kind: "asgi", target: "m:app" }, "auto", 2);
    expect(u).toBe("uvicorn m:app --host 127.0.0.1 --port $PORT --workers 2 --proxy-headers --forwarded-allow-ips 127.0.0.1");
    expect(g).not.toContain("0.0.0.0");
    expect(u).not.toContain("0.0.0.0");
    expect(() => serverCommand({ kind: "asgi", target: "m:app" }, "gunicorn", 1)).toThrow(/uvicorn/);
    expect(() => serverCommand({ kind: "wsgi", target: "m:app" }, "uvicorn", 1)).toThrow(/gunicorn/);
    expect(() => serverCommand({ kind: "wsgi", target: "m:app;rm -rf /" }, "auto", 1)).toThrow();
    expect(serverPackage(g)).toBe("gunicorn");
    expect(serverPackage(u)).toBe("uvicorn");
    expect(serverPackage("celery -A x worker")).toBe("");
  });

  test("default workers follow the memory limit", () => {
    expect(defaultWorkers(512, 4)).toBe(1);
    expect(defaultWorkers(1024, 4)).toBe(2);
    expect(defaultWorkers(4096, 1)).toBe(3);
    expect(defaultWorkers(65536, 32)).toBe(8);
    expect(defaultWorkers(64, 0)).toBe(1);
  });

  test("auto / on / off", () => {
    expect([triOn("auto", true), triOn("auto", false), triOn("on", false), triOn("off", true)]).toEqual([true, false, true, false]);
  });
});

describe("install steps (argv only, no shell)", () => {
  const base = { venv: "/srv/pano/apps/x/releases/1/.venv", python: "/opt/pano/runtimes/python/3.14.2/bin/python3", cache: "/srv/pano/apps/x/cache", hashes: false };

  test("every step is an argv of plain strings and never downloads or reads user config", () => {
    for (const mode of ["uv-lock", "poetry", "requirements", "pyproject", "none"] as const) {
      for (const s of installSteps({ ...base, mode, requirements: "requirements/production.txt" })) {
        expect(s.argv.every((a) => typeof a === "string")).toBe(true);
        expect(s.argv[0]).toBe("uv");
        expect(s.argv.join(" ")).not.toMatch(/\bsh\b|-c |&&|\|/);
        expect(s.env).toMatchObject({ UV_PYTHON_DOWNLOADS: "never", UV_NO_CONFIG: "1", UV_CACHE_DIR: "/srv/pano/apps/x/cache/uv", UV_PROJECT_ENVIRONMENT: base.venv });
      }
    }
  });

  test("uv.lock: locked sync with the pinned interpreter", () => {
    const [s, ...rest] = installSteps({ ...base, mode: "uv-lock", requirements: "" });
    expect(rest).toEqual([]);
    expect(s!.argv).toEqual(["uv", "sync", "--locked", "--no-dev", "--no-install-project", "--python", base.python, "--no-managed-python"]);
  });

  test("requirements: venv from the pinned interpreter, then uv pip into it; hashes make it strict", () => {
    const steps = installSteps({ ...base, mode: "requirements", requirements: "requirements/production.txt" });
    expect(steps[0]!.argv).toEqual(["uv", "venv", "--python", base.python, "--no-managed-python", base.venv]);
    expect(steps[1]!.argv).toEqual(["uv", "pip", "install", "--python", `${base.venv}/bin/python`, "-r", "requirements/production.txt"]);
    expect(installSteps({ ...base, hashes: true, mode: "requirements", requirements: "r.txt" })[1]!.argv).toContain("--require-hashes");
    expect(hasHashes("a==1 \\\n    --hash=sha256:abc")).toBe(true);
    expect(hasHashes("a==1")).toBe(false);
  });

  test("poetry runs through uv with the venv active and no venv of its own", () => {
    const steps = installSteps({ ...base, mode: "poetry", requirements: "" });
    expect(steps.map((s) => s.argv[1])).toEqual(["venv", "tool"]);
    expect(steps[1]!.argv).toContain(POETRY_SPEC);
    expect(steps[1]!.argv.slice(-5)).toEqual(["install", "--no-root", "--only", "main", "--no-interaction"]);
    expect(steps[1]!.env).toMatchObject({ POETRY_VIRTUALENVS_CREATE: "false", VIRTUAL_ENV: base.venv });
  });

  test("pyproject, an admin's own install command (empty venv only) and nothing found", () => {
    expect(installSteps({ ...base, mode: "pyproject", requirements: "" })[1]!.argv.slice(-2)).toEqual(["-r", "pyproject.toml"]);
    expect(installSteps({ ...base, mode: "requirements", requirements: "x.txt", custom: true }).map((s) => s.label)).toEqual(["create virtualenv"]);
    expect(installSteps({ ...base, mode: "none", requirements: "" })).toHaveLength(1);
  });

  test("server installed when missing", () => {
    expect(serverInstallStep("gunicorn", base).argv).toEqual(["uv", "pip", "install", "--python", `${base.venv}/bin/python`, "gunicorn"]);
  });
});

describe("Django steps", () => {
  const venv = "/r/.venv";
  test("argv", () => {
    expect(djangoArgv(venv, "collectstatic")).toEqual(["/r/.venv/bin/python", "manage.py", "collectstatic", "--noinput"]);
    expect(djangoArgv(venv, "migrate")).toEqual(["/r/.venv/bin/python", "manage.py", "migrate", "--noinput"]);
    expect(djangoProbeArgv(venv).slice(1)).toEqual(["manage.py", "shell", "-c", STATIC_PROBE]);
  });

  test("static probe: relative and absolute STATIC_URL, CDN and unset", () => {
    expect(parseStaticProbe("warn\nPANO_STATIC /static/ /r/staticfiles\n")).toEqual({ url: "/static", root: "/r/staticfiles" });
    expect(parseStaticProbe("PANO_STATIC static/ /r/sf")).toEqual({ url: "/static", root: "/r/sf" });
    expect(parseStaticProbe("PANO_STATIC https://cdn.example.com/s/ /r/sf")).toBeNull();
    expect(parseStaticProbe("PANO_STATIC //cdn.example.com/s/ /r/sf")).toBeNull();
    expect(parseStaticProbe("PANO_STATIC /static/ -")).toBeNull();
    expect(parseStaticProbe("PANO_STATIC - -")).toBeNull();
    expect(parseStaticProbe("nothing")).toBeNull();
    expect(parseStaticProbe("PANO_STATIC /a b/ /r")).toBeNull();
  });

  test("STATIC_ROOT must be inside the release", () => {
    expect(insideDir("/rel/1/staticfiles", "/rel/1")).toBe(true);
    expect(insideDir("/rel/1", "/rel/1")).toBe(false);
    expect(insideDir("/rel/12/x", "/rel/1")).toBe(false);
    expect(insideDir("/etc", "/rel/1")).toBe(false);
    expect(insideDir("/rel/1/../../etc", "/rel/1")).toBe(false);
  });
});

describe("native build packages", () => {
  test("only what has no wheel, per distribution family", () => {
    expect(nativePackages(["django", "mysqlclient"], "el")).toEqual(["gcc", "mariadb-connector-c-devel", "pkgconf-pkg-config"]);
    expect(nativePackages(["mysqlclient", "psycopg2"], "debian")).toEqual(["gcc", "libmariadb-dev", "libpq-dev", "pkg-config"]);
    expect(nativePackages(["pillow", "psycopg2-binary", "lxml", "cryptography", "django"], "el")).toEqual([]);
    expect(nativePackages(detectPython(django, PY_DEFAULTS).deps, "debian")).toContain("libmariadb-dev");
    expect(nativePackages(["python-ldap"], "el")).toContain("openldap-devel");
  });
});

describe("scripts and units", () => {
  test("start script puts the slot's venv first and execs the command", () => {
    const sh = pythonStartScript("/srv/pano/apps/x/slot-a", "gunicorn a:b --bind 127.0.0.1:$PORT");
    expect(sh).toBe(`#!/bin/sh\nset -e\nVIRTUAL_ENV='/srv/pano/apps/x/slot-a/.venv'\nexport VIRTUAL_ENV\nPATH="$VIRTUAL_ENV/bin:$PATH"\nexec gunicorn a:b --bind 127.0.0.1:$PORT\n`);
    expect(pythonCronScript("/srv/pano/apps/x/current", "python manage.py clearsessions")).toContain("VIRTUAL_ENV='/srv/pano/apps/x/current/.venv'");
    expect(shq("it's")).toBe(`'it'\\''s'`);
  });

  const app = (over: Partial<App>) =>
    ({ name: "hub", kind: "managed", domains: ["hub.example.com"], runtime: "python", runtime_version: "3.14.2", active_slot: "a", port_a: 4100, port_b: 4101, processes: [], memory_mb: 1024, start_cmd: "", env_groups: "", root_dir: "", ...over }) as App;
  const proc = { name: "", dir: "", routes: ["hub.example.com"], memory_mb: 1024, start: "", port_a: 4100, port_b: 4101 };

  test("unit of a Python app: no Node variables, same sandbox and limits as other apps", () => {
    const unit = renderUnit(app({}), proc, "/opt/pano/runtimes/uv/0.9.0:/opt/pano/runtimes/python/3.14.2/bin:/usr/bin");
    expect(unit).toContain("Environment=PYTHONUNBUFFERED=1 HOSTNAME=127.0.0.1 HOME=/srv/pano/apps/hub XDG_CACHE_HOME=/srv/pano/apps/hub/cache DATA_DIR=/srv/pano/apps/hub/data\n");
    expect(unit).not.toContain("NODE_ENV");
    expect(unit).not.toContain("NEXT_TELEMETRY");
    expect(unit).toContain("User=app-hub");
    expect(unit).toContain("MemoryMax=1024M");
    expect(unit).toContain("NoNewPrivileges=true");
    expect(unit).toContain("ProtectSystem=strict");
    expect(unit).toContain("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX");
    expect(unit).toContain("ExecStart=/srv/pano/apps/hub/run/main-%i.sh");
  });

  test("unit of a Node app is exactly what it was", () => {
    const unit = renderUnit(app({ runtime: "node", runtime_version: "24.1.0" }), proc, "/p");
    expect(unit).toContain("Environment=NODE_ENV=production HOSTNAME=127.0.0.1 HOME=/srv/pano/apps/hub XDG_CACHE_HOME=/srv/pano/apps/hub/cache DATA_DIR=/srv/pano/apps/hub/data NEXT_TELEMETRY_DISABLED=1\n");
    expect(unit).not.toContain("PYTHON");
  });
});

describe("edge", () => {
  const settings = { email: "", behindCloudflare: false, hooksDomain: "" };
  const pyApp = (over: Partial<App> = {}) =>
    ({ name: "hub", kind: "managed", domains: ["hub.example.com"], runtime: "python", active_slot: "b", port_a: 4100, port_b: 4101, processes: [], http_redirect: 1, static_live: '["/static"]', ...over }) as App;

  test("collected static files are served by the edge from the slot's copy, the rest goes to the app", () => {
    const out = renderCaddyfile({ apps: [pyApp()], sites: [], settings, certs: new Set() });
    expect(out).toContain("\t@route0 path /static /static/*");
    expect(out).toContain("\t\turi strip_prefix /static\n\t\troot * /srv/pano/static/hub/b/0\n");
    expect(out).toContain("\t\tfile_server");
    expect(out).toContain("\t\treverse_proxy 127.0.0.1:4101");
    expect(staticDir("hub", "b", 0)).toBe("/srv/pano/static/hub/b/0");
  });

  test("apps without static files render exactly as before", () => {
    for (const a of [pyApp({ static_live: "" }), pyApp({ runtime: "node" as App["runtime"], static_live: undefined as unknown as string })]) {
      const out = renderCaddyfile({ apps: [a], sites: [], settings, certs: new Set() });
      expect(out).not.toContain("file_server");
      expect(out).toContain("\treverse_proxy 127.0.0.1:4101");
      expect(out).not.toContain("handle @route0");
    }
  });

  test("a preview never serves the live release's static copy", () => {
    const pv = previewApp(pyApp(), { id: 3, app: "hub", branch: "x", slug: "x", host: "x.pv.example.com", processes: [{ ...proc0(), routes: ["x.pv.example.com"] }], active_slot: "a", current_release: "r", last_deploy: 1, created_at: 0, updated_at: 0, expires_at: 9 });
    expect(pv.static_live).toBe("");
  });

  test("live static urls are read defensively", () => {
    expect(liveStatic('["/static","/assets"]')).toEqual(["/static", "/assets"]);
    expect(liveStatic("")).toEqual([]);
    expect(liveStatic("{not json")).toEqual([]);
    expect(liveStatic('["/ok", "http://evil", 3, "/a b"]')).toEqual(["/ok"]);
  });
});
const proc0 = () => ({ name: "", dir: "", routes: [], memory_mb: 512, start: "", port_a: 4102, port_b: 4103 });

describe("python-build-standalone and uv downloads", () => {
  const names = [
    "cpython-3.14.2+20260101-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
    "cpython-3.14.1+20251201-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
    "cpython-3.14.2+20260101-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz",
    "cpython-3.13.9+20260101-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
    "cpython-3.13.9+20260101-x86_64-unknown-linux-gnu-install_only.tar.gz",
    "cpython-3.15.0a3+20260101-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
    "cpython-3.13.9+20260101-x86_64-unknown-linux-musl-install_only_stripped.tar.gz",
    "SHA256SUMS",
  ];
  test("newest patch of a minor, exact patch, nothing for other CPUs or pre-releases", () => {
    expect(pickPython(names, "3.14", "x64")).toEqual({ version: "3.14.2", asset: names[0]! });
    expect(pickPython(names, "3.14.1", "x64")?.version).toBe("3.14.1");
    expect(pickPython(names, "3.14", "arm64")?.asset).toBe(names[2]!);
    expect(pickPython(names, "3.15", "x64")).toBeNull();
    expect(pickPython(names, "3.12", "x64")).toBeNull();
    expect(pickPython(names, "3.1", "x64")).toBeNull();
    expect(listPython(names, "x64")).toEqual(["3.14.2", "3.13.9"]);
  });
  test("asset names and trusted URLs", () => {
    expect(pbsAsset("3.14.2", "20260101", "x64")).toBe(names[0]!);
    expect(uvAsset("arm64")).toBe("uv-aarch64-unknown-linux-gnu.tar.gz");
    expect(trustedDownload("https://github.com/astral-sh/python-build-standalone/releases/download/20260101/cpython-3.14.2%2B20260101-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz")).toBe(true);
    expect(trustedDownload("https://github.com/astral-sh/uv/releases/download/0.9.0/uv-x86_64-unknown-linux-gnu.tar.gz.sha256")).toBe(true);
    for (const bad of ["http://github.com/astral-sh/uv/releases/download/1/x", "https://evil.example/astral-sh/uv/releases/download/1/x", "https://github.com/evil/uv/releases/download/1/x", "https://github.com/astral-sh/uv/releases/download/1/../x", "https://github.com/astral-sh/uv/archive/x.tar.gz"]) {
      expect(trustedDownload(bad)).toBe(false);
    }
  });
});

describe("optional: nothing of Python exists until it is used", () => {
  const rt = (rel: string) => fsPath(`${paths.runtimes}/${rel}`);

  test("a server without Python: node/bun listing, PATH and runtime dirs are untouched", async () => {
    expect(existsSync(rt("python"))).toBe(false);
    expect(existsSync(rt("uv"))).toBe(false);
    expect(await installedAll()).toEqual(await installed());
    expect((await installedAll()).some((r) => r.runtime === "python")).toBe(false);
    const listed = (await methods["runtimes.list"]!({}, "t")) as { runtime: string; version: string }[];
    expect(listed.map((r) => `${r.runtime}@${r.version}`)).toEqual((await installed()).map((r) => `${r.runtime}@${r.version}`));
    // listing created nothing
    expect(existsSync(rt("python"))).toBe(false);
    expect(existsSync(fsPath(paths.static))).toBe(false);
    expect(runtimeBin("python", "3.14.2")).toBe("/opt/pano/runtimes/python/3.14.2/bin");
    expect(runtimeBin("node", "24.1.0")).toBe("/opt/pano/runtimes/node/24.1.0/bin");
    expect(runtimeBin("bun", "1.3.0")).toBe("/opt/pano/runtimes/bun/1.3.0");
  });

  test("an installed Python shows up only in the full list; node's PATH and scans never see it", async () => {
    mkdirSync(rt("python/3.14.2/bin"), { recursive: true });
    mkdirSync(rt("python/3.13.9/bin"), { recursive: true });
    mkdirSync(rt("uv/0.9.0"), { recursive: true });
    writeFileSync(rt("uv/0.9.0/uv"), "");
    expect((await installed()).some((r) => r.runtime === ("python" as string))).toBe(false);
    expect((await installedAll()).filter((r) => r.runtime === "python").map((r) => r.version)).toEqual(["3.14.2", "3.13.9"]);
    const listed = (await methods["runtimes.list"]!({}, "t")) as { runtime: string; version: string; inUse: boolean }[];
    expect(listed.filter((r) => r.runtime === "python")).toHaveLength(2);
  });

  test("removing the last Python version takes uv and the directory with it", async () => {
    await uninstallPython("3.14.2");
    expect(existsSync(rt("python/3.13.9"))).toBe(true);
    expect(existsSync(rt("uv/0.9.0"))).toBe(true);
    await uninstallPython("3.13.9");
    expect(existsSync(rt("python"))).toBe(false);
    expect(existsSync(rt("uv"))).toBe(false);
    expect(afterUninstall([{ runtime: "node" }]).removeUv).toBe(true);
    expect(afterUninstall([{ runtime: "python" }]).removeUv).toBe(false);
  });

  test("an app in use blocks removing its runtime; deleting the app frees it", async () => {
    await expect(methods["runtimes.uninstall"]!({ runtime: "python", version: "3.14.2" }, "t")).resolves.toBeUndefined();
    const { apps } = await import("../src/agent/state.ts");
    apps.insert({ name: "pyuse", kind: "managed", runtime: "python", runtime_version: "3.14.3", domains: [] } as never);
    await expect(methods["runtimes.uninstall"]!({ runtime: "python", version: "3.14.3" }, "t")).rejects.toThrow(/used by an app/);
    apps.remove("pyuse");
    await expect(methods["runtimes.uninstall"]!({ runtime: "python", version: "3.14.3" }, "t")).resolves.toBeUndefined();
  });

  test("removing an app or preview removes its static copies", async () => {
    mkdirSync(fsPath(`${paths.static}/gone/a/0`), { recursive: true });
    writeFileSync(fsPath(`${paths.static}/gone/a/0/x.css`), "x");
    const quiet = spyOn(console, "log").mockImplementation(() => {});
    await teardownUnits("gone", false);
    quiet.mockRestore();
    expect(existsSync(fsPath(`${paths.static}/gone`))).toBe(false);
  });
});

describe("Python settings decide what runs: changing them asks for a code", () => {
  test("py_* fields are guarded like the commands", async () => {
    const { apps } = await import("../src/agent/state.ts");
    apps.insert({ name: "pyguard", kind: "managed", runtime: "python", runtime_version: "3.14.2", repo: "https://github.com/a/b.git", branch: "main", domains: ["g.example.com"], health_path: "/", memory_mb: 1024 } as never);
    const same = { name: "pyguard", domains: "g.example.com", runtime: "python", runtime_version: "3.14.2", repo: "https://github.com/a/b.git", branch: "main" };
    expect(await alwaysAsk("apps.update", same)).toBe(false);
    for (const change of [{ py_migrate: "off" }, { py_app: "x.wsgi:application" }, { py_server: "uvicorn" }, { py_static: "/static | sf" }, { py_requirements: "r.txt" }, { py_workers: 4 }, { py_collectstatic: "on" }]) {
      expect(await alwaysAsk("apps.update", { ...same, ...change })).toBe(true);
    }
    apps.remove("pyguard");
  });
});


describe("previews never migrate a store they share with production", () => {
  const plan = { mode: "requirements", requirements: "r.txt", django: true, app: null, deps: new Set<string>() } as never;
  const ctx = (name: string, py_migrate: string, shared: string[] = []) => {
    const ran: string[][] = [];
    const envs: Record<string, string>[] = [];
    const logs: string[] = [];
    const c = {
      app: { name, py_migrate } as App, dir: "/r", workdir: "/r", path: "/usr/bin", cache: "/c", log: (l: string) => void logs.push(l), step: () => {},
      sb: async (argv: string[], o: { env: Record<string, string> }) => void (ran.push(argv), envs.push(o.env)), sharedStoreKeys: shared,
    };
    return { c, ran, envs, logs };
  };

  test("names and shared keys", () => {
    expect([isPreviewName("pv_12"), isPreviewName("pv_x"), isPreviewName("web"), isPreviewName("app-pv_1")]).toEqual([true, false, false, false]);
    const prod = { DATABASE_URL: "postgres://u:p@db/x", DB_HOST: "10.0.0.1", SECRET_KEY: "s", REDIS_URL: "redis://r", DEBUG: "0" };
    expect(sharedStoreKeys({ DATABASE_URL: "postgres://u:p@db/x", DB_HOST: "10.0.0.1", SECRET_KEY: "s", REDIS_URL: "redis://other", DEBUG: "0" }, prod)).toEqual(["DATABASE_URL", "DB_HOST"]);
    expect(sharedStoreKeys({ DATABASE_URL: "sqlite:///preview.db" }, prod)).toEqual([]);
    expect(sharedStoreKeys({}, prod)).toEqual([]);
  });

  test("a live app migrates (auto or on); a preview does not unless Always and nothing is shared", async () => {
    const live = ctx("hub", "auto");
    await migrate(live.c as never, plan);
    expect(live.ran).toEqual([["/r/.venv/bin/python", "manage.py", "migrate", "--noinput"]]);
    // the same DATA_DIR the running app gets: its SQLite database, not a fresh one in the release
    expect(live.envs[0]!.DATA_DIR).toBe("/srv/pano/apps/hub/data");

    const auto = ctx("pv_3", "auto");
    await migrate(auto.c as never, plan);
    expect(auto.ran).toEqual([]);
    expect(auto.logs.join()).toContain("migrate skipped");

    const on = ctx("pv_3", "on");
    await migrate(on.c as never, plan);
    expect(on.ran).toHaveLength(1);

    const shared = ctx("pv_3", "on", ["DATABASE_URL"]);
    await migrate(shared.c as never, plan);
    expect(shared.ran).toEqual([]);
    expect(shared.logs.join()).toContain("shares DATABASE_URL with production");

    const off = ctx("hub", "off");
    await migrate(off.c as never, plan);
    expect(off.ran).toEqual([]);
  });
});

describe("static copies end with the Python runtime; UV_* is a Python-only runtime variable", () => {
  const settings = { email: "", behindCloudflare: false, hooksDomain: "" };
  test("an app that is no longer Python serves no static copy", () => {
    const a = { name: "hub", kind: "managed", domains: ["h.example.com"], runtime: "node", active_slot: "a", port_a: 4100, port_b: 4101, processes: [], http_redirect: 1, static_live: '["/static"]' } as unknown as App;
    expect(renderCaddyfile({ apps: [a], sites: [], settings, certs: new Set() })).not.toContain("file_server");
  });

  test("updating to another runtime clears static_live and the copies", async () => {
    const { apps } = await import("../src/agent/state.ts");
    const { updateApp } = await import("../src/agent/apps.ts");
    apps.insert({ name: "pyswitch", kind: "managed", runtime: "python", runtime_version: "3.14.2", repo: "https://github.com/a/b.git", domains: ["s.example.com"], active_slot: "a", static_live: '["/static"]' } as never);
    mkdirSync(fsPath(`${paths.static}/pyswitch/a/0`), { recursive: true });
    const quiet = spyOn(console, "log").mockImplementation(() => {});
    await updateApp("pyswitch", validateAppInput({ name: "pyswitch", domains: "s.example.com", runtime: "node", runtime_version: "24.1.0", repo: "https://github.com/a/b.git" }), "t");
    quiet.mockRestore();
    expect(apps.get("pyswitch")!.static_live).toBe("");
    expect(existsSync(fsPath(`${paths.static}/pyswitch`))).toBe(false);
    apps.remove("pyswitch");
  });

  test("UV_/PIP_/VIRTUAL_ENV ask for a code only for Python apps", async () => {
    const { apps } = await import("../src/agent/state.ts");
    expect(changesRuntimeEnv({ UV_THREADPOOL_SIZE: "8" }, {})).toBe(false);
    expect(changesRuntimeEnv({ UV_INDEX_URL: "https://evil" }, {}, true)).toBe(true);
    expect(changesRuntimeEnv({ PIP_INDEX_URL: "https://evil" }, {}, true)).toBe(true);
    expect(changesRuntimeEnv({ PIP_INDEX_URL: "https://evil" }, {})).toBe(false);
    expect(changesRuntimeEnv({ LD_PRELOAD: "/x" }, {})).toBe(true);
    apps.insert({ name: "uvnode", kind: "managed", runtime: "node", runtime_version: "24.1.0", domains: [] } as never);
    apps.insert({ name: "uvpy", kind: "managed", runtime: "python", runtime_version: "3.14.2", domains: [] } as never);
    expect(await alwaysAsk("apps.env.set", { name: "uvnode", vars: { UV_THREADPOOL_SIZE: "8" } })).toBe(false);
    expect(await alwaysAsk("apps.env.set", { name: "uvpy", vars: { UV_INDEX_URL: "https://evil" } })).toBe(true);
    expect(await alwaysAsk("apps.env.set", { name: "uvpy", vars: { SECRET: "x" } })).toBe(false);
    apps.remove("uvnode");
    apps.remove("uvpy");
  });
});

describe("repository reading and static snapshot (real files)", () => {
  const tmp = mkdtempSync(join(fsPath("/"), "pyrepo-"));
  const logical = (p: string) => p.slice(fsPath("/").length - 1);

  test("reads what detection needs, skips links and junk", async () => {
    const dir = join(tmp, "repo");
    mkdirSync(join(dir, "requirements"), { recursive: true });
    mkdirSync(join(dir, "node_modules/x"), { recursive: true });
    mkdirSync(join(dir, ".venv"), { recursive: true });
    writeFileSync(join(dir, "manage.py"), 'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "p.settings")');
    writeFileSync(join(dir, "requirements/base.txt"), "django");
    writeFileSync(join(dir, "node_modules/x/requirements.txt"), "evil");
    writeFileSync(join(dir, ".venv/pyproject.toml"), "evil");
    writeFileSync(join(tmp, "secret"), "root only");
    symlinkSync(join(tmp, "secret"), join(dir, "pyproject.toml"));
    const r = await readRepo(logical(dir), "", logical(tmp));
    expect([...r.files].sort()).toEqual(["manage.py", "requirements/base.txt"]);
    expect(r.texts["manage.py"]).toContain("DJANGO_SETTINGS_MODULE");
    expect(r.texts["pyproject.toml"]).toBeUndefined();
    expect(Object.values(r.texts).join()).not.toContain("root only");
    expect(detectPython(r, PY_DEFAULTS).django).toBe(true);
  });

  test("snapshot copies regular files only, never follows links, skips dot files", async () => {
    const rel = join(tmp, "release");
    const src = join(rel, "staticfiles");
    mkdirSync(join(src, "css"), { recursive: true });
    writeFileSync(join(src, "css/app.css"), "body{}");
    writeFileSync(join(src, "a.js"), "1");
    writeFileSync(join(src, ".env"), "SECRET=1");
    writeFileSync(join(tmp, "outside.txt"), "outside");
    symlinkSync(join(tmp, "outside.txt"), join(src, "link.txt"));
    symlinkSync(tmp, join(src, "linkdir"));
    const dest = `${paths.static}/snap/a/0`;
    const r = await snapshotStatic(logical(src), logical(rel), dest);
    expect(r.files).toBe(2);
    expect(r.skipped).toBe(3);
    const out = fsPath(dest);
    expect(readdirSync(out).sort()).toEqual(["a.js", "css"]);
    expect(readFileSync(join(out, "css/app.css"), "utf8")).toBe("body{}");
    expect(existsSync(join(out, "outside.txt"))).toBe(false);
  });

  test("a directory swapped for a link while the copy runs is never followed (the file is skipped)", async () => {
    const rel = join(tmp, "release2");
    const src = join(rel, "staticfiles");
    mkdirSync(join(src, "pages"), { recursive: true });
    writeFileSync(join(src, "pages/shadow"), "tenant copy");
    writeFileSync(join(src, "ok.css"), "ok");
    const secretDir = join(tmp, "rootonly");
    mkdirSync(secretDir, { recursive: true });
    writeFileSync(join(secretDir, "shadow"), "root:$6$secret");
    let swapped = false;
    const r = await snapshotStatic(logical(src), logical(rel), `${paths.static}/swap/a/0`, {
      beforeOpen: (path) => {
        // The name list of pages/ was read already; now the directory becomes a link to a root-only one.
        if (!swapped && path.endsWith("pages/shadow")) {
          swapped = true;
          renameSync(join(src, "pages"), join(rel, "pages-moved"));
          symlinkSync(secretDir, join(src, "pages"));
        }
      },
    });
    expect(swapped).toBe(true);
    const out = fsPath(`${paths.static}/swap/a/0`);
    expect(existsSync(join(out, "pages/shadow"))).toBe(false);
    expect(readFileSync(join(out, "ok.css"), "utf8")).toBe("ok");
    expect(r.files).toBe(1);
    expect(r.skipped).toBeGreaterThanOrEqual(1);
    // and nothing anywhere in the copy holds the secret
    const all = (d: string): string[] => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? all(join(d, e.name)) : [join(d, e.name)]));
    for (const f of all(out)) expect(readFileSync(f, "utf8")).not.toContain("$6$secret");
  });

  test("a static directory outside the releases is refused, also in development", async () => {
    const rel = join(tmp, "release3");
    mkdirSync(rel, { recursive: true });
    const outside = join(tmp, "elsewhere");
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(outside, "x.css"), "x");
    symlinkSync(outside, join(rel, "staticfiles"));
    await expect(snapshotStatic(logical(join(rel, "staticfiles")), logical(rel), `${paths.static}/out/a/0`)).rejects.toThrow();
    await expect(snapshotStatic(logical(outside), logical(rel), `${paths.static}/out/a/0`)).rejects.toThrow(/outside the release/);
    expect(existsSync(fsPath(`${paths.static}/out`))).toBe(false);
  });

  test("files not owned by the app are not copied", async () => {
    const rel = join(tmp, "release4");
    const src = join(rel, "sf");
    mkdirSync(src, { recursive: true });
    writeFileSync(join(src, "a.css"), "a");
    const r = await snapshotStatic(logical(src), logical(rel), `${paths.static}/uid/a/0`, { uid: 1 << 30 });
    expect(r.files).toBe(0);
    expect(r.skipped).toBe(1);
  });

  test("configuration files read through a linked directory are ignored", async () => {
    const dir = join(tmp, "repo2");
    const real = join(tmp, "realreqs");
    mkdirSync(dir, { recursive: true });
    mkdirSync(real, { recursive: true });
    writeFileSync(join(real, "prod.txt"), "mysqlclient");
    symlinkSync(real, join(dir, "reqs"));
    const r = await readRepo(logical(dir), "reqs/prod.txt", logical(dir));
    expect(r.texts["reqs/prod.txt"]).toBeUndefined();
  });

  test("a directory swapped for a link to another tree is never walked: no names of it appear, nothing is copied", async () => {
    const rel = join(tmp, "release5");
    const src = join(rel, "staticfiles");
    mkdirSync(join(src, "a/b"), { recursive: true });
    writeFileSync(join(src, "a/b/x.css"), "x");
    const other = join(tmp, "tenants");
    mkdirSync(join(other, "b/other-tenant-dir"), { recursive: true });
    writeFileSync(join(other, "b/secret"), "s");
    let swapped = false;
    const dest = `${paths.static}/dirswap/a/0`;
    const r = await snapshotStatic(logical(src), logical(rel), dest, {
      beforeOpen: (path) => {
        if (!swapped && path.endsWith("staticfiles/a/b")) {
          swapped = true;
          renameSync(join(src, "a"), join(rel, "a-moved"));
          symlinkSync(other, join(src, "a"));
        }
      },
    });
    expect(swapped).toBe(true);
    expect(r.files).toBe(0);
    const out = fsPath(dest);
    expect(existsSync(join(out, "a/b/other-tenant-dir"))).toBe(false);
    expect(existsSync(join(out, "a/b/secret"))).toBe(false);
  });

  test("the walk is capped: too many directories or too slow aborts instead of stalling the queue", async () => {
    const rel = join(tmp, "release6");
    const src = join(rel, "sf");
    for (const d of ["1", "2", "3", "4"]) mkdirSync(join(src, d), { recursive: true });
    await expect(snapshotStatic(logical(src), logical(rel), `${paths.static}/cap/a/0`, { maxDirs: 3 })).rejects.toThrow(/too many directories/);
    await expect(snapshotStatic(logical(src), logical(rel), `${paths.static}/cap/a/0`, { maxMs: -1 })).rejects.toThrow(/too slow/);
    expect((await snapshotStatic(logical(src), logical(rel), `${paths.static}/cap/a/0`)).skipped).toBe(0);
  });

  test("runtime installs: stale staging directories are swept, a final directory without its main file is replaced", async () => {
    const parent = join(tmp, "runtimes/python");
    mkdirSync(parent, { recursive: true });
    mkdirSync(join(parent, ".stage-old"));
    mkdirSync(join(parent, ".stage-new"));
    const old = new Date(Date.now() - 2 * 3_600_000);
    utimesSync(join(parent, ".stage-old"), old, old);
    mkdirSync(join(parent, "3.14.9/bin"), { recursive: true }); // half-extracted: no bin/python3
    writeFileSync(join(parent, "3.14.9/bin/leftover"), "x");
    await stageInstall(logical(join(parent, "3.14.9")), "bin/python3", async (stage) => {
      mkdirSync(fsPath(`${stage}/bin`), { recursive: true });
      writeFileSync(fsPath(`${stage}/bin/python3`), "#!");
    });
    expect(existsSync(join(parent, ".stage-old"))).toBe(false);
    expect(existsSync(join(parent, ".stage-new"))).toBe(true);
    expect(existsSync(join(parent, "3.14.9/bin/python3"))).toBe(true);
    expect(existsSync(join(parent, "3.14.9/bin/leftover"))).toBe(false);
    // a complete one stays as it is
    await stageInstall(logical(join(parent, "3.14.9")), "bin/python3", async (stage) => {
      mkdirSync(fsPath(`${stage}/bin`), { recursive: true });
      writeFileSync(fsPath(`${stage}/bin/python3`), "second");
    });
    expect(readFileSync(join(parent, "3.14.9/bin/python3"), "utf8")).toBe("#!");
    expect(readdirSync(parent).filter((n) => n.startsWith(".stage-")).sort()).toEqual([".stage-new"]);
  });
});
