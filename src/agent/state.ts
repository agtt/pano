// The agent's own state. Lives in /var/lib/pano/state.db (root, 0600); the web
// process never opens it and only sees what the agent returns over RPC.

import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { APP_PORT_BASE, fsPath, paths } from "../shared/config.ts";
import { pvName } from "../shared/preview.ts";
import type { ProcessSpec } from "../shared/validate.ts";

export type App = {
  name: string;
  kind: "managed" | "external";
  domains: string[];
  runtime: "node" | "bun";
  runtime_version: string;
  repo: string;
  branch: string;
  root_dir: string;
  install_cmd: string;
  build_cmd: string;
  start_cmd: string;
  health_path: string;
  port_a: number;
  port_b: number;
  active_slot: "a" | "b" | "";
  memory_mb: number;
  current_release: string;
  webhook_secret: string;
  /** external apps: upstream address and the unit that runs them */
  upstream: string;
  external_unit: string;
  /** Several processes from one build (monorepos). Empty: the app is a single process. */
  processes: Process[];
  /** on-demand TLS for a "*" route: local URL asked whether a host may get a certificate */
  ask_url: string;
  /** 1: a push to the branch deploys (webhook); 0: only manual deploys */
  auto_deploy: number;
  /** 1: install and build see only the new release (no deploy key, data, env file or shared caches); their caches are deleted after */
  build_isolated: number;
  /** scheduled commands run in the live release (systemd timers) */
  crons: { schedule: string; command: string }[];
  /** preview deploys: wildcard such as *.preview.example.com ("" = off), how many at once, days to keep, variables left out */
  preview_domain: string;
  preview_max: number;
  preview_ttl_days: number;
  preview_env_exclude: string;
  /** shared variable groups the app gets, in order ("stripe,sentry"); its own variables win */
  env_groups: string;
  /** env fingerprints (envSnapshot) the processes started with and the live build used; never sent to the UI */
  env_running: string;
  env_built: string;
  /** 1: plain HTTP is redirected to HTTPS (default); 0: also served on plain HTTP (Cloudflare "Flexible" SSL, apps that redirect themselves) */
  http_redirect: number;
  /** 1: the edge answers every request with the suspended page; its processes, cron timers and previews are stopped */
  suspended: number;
  suspended_reason: string;
  suspended_at: number;
  /** what suspend stopped, so resume brings back exactly that */
  suspended_units: SuspendedUnit[];
  created_at: number;
  updated_at: number;
};

/** A unit as it was when its app was suspended. */
export type SuspendedUnit = { unit: string; active: boolean; enabled: boolean };

/** A process of a multi-process app. Workers have no routes and port 0. */
export type Process = ProcessSpec & { port_a: number; port_b: number };

export type Route = { path: string; upstream: string };

export type Site = {
  name: string;
  /**
   * legacy: served by the old OpenLiteSpeed on localhost (PHP, WordPress, rewrite rules)
   * php: pano's own PHP-FPM (per-site user and pool), started only for sites that exist
   */
  kind: "legacy" | "static" | "proxy" | "php";
  /** "*" means catch-all: any host that reaches the server (needs on_demand_tls). */
  domains: string[];
  root: string;
  /** proxy sites: path prefix -> 127.0.0.1:port, most specific first */
  routes: Route[];
  /** on-demand TLS: local URL asked whether a host may get a certificate */
  ask_url: string;
  php_version: string;
  tls_cert: string;
  tls_key: string;
  source: "cyberpanel" | "cpanel" | "container" | "pano";
  /** 0: suspended. The edge keeps the domains (and their certificates) but answers with the suspended page; a PHP site's pool and cron timers are stopped. */
  enabled: number;
  /** why and when it was suspended ("" / 0 while it runs, and for sites disabled before suspension existed) */
  suspended_reason: string;
  suspended_at: number;
  /** 1: plain HTTP is redirected to HTTPS; 0: also served on plain HTTP (legacy imports: the backend decides) */
  http_redirect: number;
  on_demand_tls: number;
  /** php sites: path prefixes answered with 404 (from "deny from all" .htaccess files) */
  deny_paths: string[];
  /** set when a legacy site was converted to php: what to go back to */
  converted_from: { kind: Site["kind"]; root: string; php_version: string } | null;
  /** php sites: scheduled commands run as the site user with the site's PHP (systemd timers) */
  crons: { schedule: string; command: string }[];
  created_at: number;
};

/** A branch built on its own (own user, home, ports and data) and served at <slug>.<preview domain>. */
export type Preview = {
  id: number;
  app: string;
  branch: string;
  slug: string;
  host: string;
  processes: Process[];
  active_slot: "a" | "b" | "";
  current_release: string;
  /** the deploys row of the latest build: status, commit and error come from there */
  last_deploy: number;
  created_at: number;
  updated_at: number;
  expires_at: number;
};

export type Deploy = {
  id: number;
  app: string;
  status: "running" | "success" | "failed";
  trigger: string;
  commit_sha: string;
  release: string;
  error: string;
  started_at: number;
  finished_at: number | null;
};

export type BackupJob = {
  id: number;
  name: string;
  kind: "mysql" | "postgres" | "path" | "app" | "panel";
  target: string;
  schedule: string;
  keep: number;
  enabled: number;
  last_run_at: number | null;
  last_status: string;
};

export type BackupRun = {
  id: number;
  job_id: number;
  object_key: string;
  bytes: number;
  status: "running" | "success" | "failed";
  error: string;
  started_at: number;
  finished_at: number | null;
  /** "a" main store, "b" second store */
  dest: string;
  /** "archive": object_key is a file; "restic": object_key is a snapshot id */
  engine: string;
};

/** Metric samples: res 60 = one point a minute (48 h), res 900 = 15-minute averages (30 days). One narrow row per value. */
export const METRICS_DDL = `
CREATE TABLE IF NOT EXISTS metrics (
  res INTEGER NOT NULL,
  key TEXT NOT NULL,
  ts INTEGER NOT NULL,
  value REAL NOT NULL,
  PRIMARY KEY (res, key, ts)
) WITHOUT ROWID;
`;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS apps (
  name TEXT PRIMARY KEY,
  kind TEXT NOT NULL DEFAULT 'managed',
  domains TEXT NOT NULL DEFAULT '[]',
  runtime TEXT NOT NULL DEFAULT 'node',
  runtime_version TEXT NOT NULL DEFAULT '',
  repo TEXT NOT NULL DEFAULT '',
  branch TEXT NOT NULL DEFAULT 'main',
  root_dir TEXT NOT NULL DEFAULT '',
  install_cmd TEXT NOT NULL DEFAULT '',
  build_cmd TEXT NOT NULL DEFAULT '',
  start_cmd TEXT NOT NULL DEFAULT '',
  health_path TEXT NOT NULL DEFAULT '/',
  port_a INTEGER NOT NULL DEFAULT 0,
  port_b INTEGER NOT NULL DEFAULT 0,
  active_slot TEXT NOT NULL DEFAULT '',
  memory_mb INTEGER NOT NULL DEFAULT 1024,
  current_release TEXT NOT NULL DEFAULT '',
  webhook_secret TEXT NOT NULL DEFAULT '',
  upstream TEXT NOT NULL DEFAULT '',
  external_unit TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
  name TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  domains TEXT NOT NULL DEFAULT '[]',
  root TEXT NOT NULL DEFAULT '',
  routes TEXT NOT NULL DEFAULT '[]',
  ask_url TEXT NOT NULL DEFAULT '',
  php_version TEXT NOT NULL DEFAULT '',
  tls_cert TEXT NOT NULL DEFAULT '',
  tls_key TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'pano',
  enabled INTEGER NOT NULL DEFAULT 1,
  on_demand_tls INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deploys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app TEXT NOT NULL,
  status TEXT NOT NULL,
  trigger TEXT NOT NULL,
  commit_sha TEXT NOT NULL DEFAULT '',
  release TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS deploys_app ON deploys(app, id DESC);
CREATE TABLE IF NOT EXISTS previews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app TEXT NOT NULL,
  branch TEXT NOT NULL,
  slug TEXT NOT NULL,
  host TEXT NOT NULL UNIQUE,
  processes TEXT NOT NULL DEFAULT '[]',
  active_slot TEXT NOT NULL DEFAULT '',
  current_release TEXT NOT NULL DEFAULT '',
  last_deploy INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  UNIQUE (app, slug)
);
CREATE TABLE IF NOT EXISTS backup_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  schedule TEXT NOT NULL DEFAULT 'manual',
  keep INTEGER NOT NULL DEFAULT 7,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at INTEGER,
  last_status TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS backup_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL,
  object_key TEXT NOT NULL DEFAULT '',
  bytes INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS backup_runs_job ON backup_runs(job_id, id DESC);
CREATE TABLE IF NOT EXISTS containers (
  name TEXT PRIMARY KEY,
  image TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 0,
  host_port INTEGER NOT NULL DEFAULT 0,
  domains TEXT NOT NULL DEFAULT '[]',
  volumes TEXT NOT NULL DEFAULT '[]',
  command TEXT NOT NULL DEFAULT '',
  memory_mb INTEGER NOT NULL DEFAULT 512,
  digest TEXT NOT NULL DEFAULT '',
  read_only INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vpn_peers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  public_key TEXT NOT NULL UNIQUE,
  psk TEXT NOT NULL,
  ip TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS android_projects (
  name TEXT PRIMARY KEY,
  repo TEXT NOT NULL,
  branch TEXT NOT NULL,
  root_dir TEXT NOT NULL DEFAULT '',
  gradle_dir TEXT NOT NULL DEFAULT '',
  prepare_cmd TEXT NOT NULL DEFAULT '',
  tasks TEXT NOT NULL,
  sdk_packages TEXT NOT NULL DEFAULT '',
  jdk INTEGER NOT NULL DEFAULT 17,
  memory_mb INTEGER NOT NULL DEFAULT 6144,
  timeout_min INTEGER NOT NULL DEFAULT 60,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS android_builds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL,
  status TEXT NOT NULL,
  trigger TEXT NOT NULL,
  commit_sha TEXT NOT NULL DEFAULT '',
  signed INTEGER NOT NULL DEFAULT 0,
  artifacts TEXT NOT NULL DEFAULT '[]',
  error TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS android_builds_project ON android_builds(project, id DESC);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
${METRICS_DDL}`;

let db: Database | null = null;

export function state(): Database {
  if (db) return db;
  const file = fsPath(paths.stateDb);
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  db = new Database(file, { create: true, strict: true });
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec(SCHEMA);
  migrate(db);
  return db;
}

/** Columns added after the first release; CREATE TABLE IF NOT EXISTS does not add them to old databases. */
const ADDED_COLUMNS: [table: string, column: string, def: string][] = [
  ["apps", "processes", "TEXT NOT NULL DEFAULT '[]'"],
  ["apps", "ask_url", "TEXT NOT NULL DEFAULT ''"],
  ["apps", "auto_deploy", "INTEGER NOT NULL DEFAULT 1"],
  ["apps", "build_isolated", "INTEGER NOT NULL DEFAULT 0"],
  ["apps", "crons", "TEXT NOT NULL DEFAULT '[]'"],
  ["apps", "preview_domain", "TEXT NOT NULL DEFAULT ''"],
  ["apps", "preview_max", "INTEGER NOT NULL DEFAULT 3"],
  ["apps", "preview_ttl_days", "INTEGER NOT NULL DEFAULT 7"],
  ["apps", "preview_env_exclude", "TEXT NOT NULL DEFAULT ''"],
  ["apps", "env_groups", "TEXT NOT NULL DEFAULT ''"],
  ["apps", "env_running", "TEXT NOT NULL DEFAULT ''"],
  ["apps", "env_built", "TEXT NOT NULL DEFAULT ''"],
  ["apps", "http_redirect", "INTEGER NOT NULL DEFAULT 1"],
  ["apps", "suspended", "INTEGER NOT NULL DEFAULT 0"],
  ["apps", "suspended_reason", "TEXT NOT NULL DEFAULT ''"],
  ["apps", "suspended_at", "INTEGER NOT NULL DEFAULT 0"],
  ["apps", "suspended_units", "TEXT NOT NULL DEFAULT '[]'"],
  ["sites", "deny_paths", "TEXT NOT NULL DEFAULT '[]'"],
  ["sites", "converted_from", "TEXT NOT NULL DEFAULT ''"],
  ["sites", "crons", "TEXT NOT NULL DEFAULT '[]'"],
  ["sites", "suspended_reason", "TEXT NOT NULL DEFAULT ''"],
  ["sites", "suspended_at", "INTEGER NOT NULL DEFAULT 0"],
  ["sites", "http_redirect", "INTEGER NOT NULL DEFAULT 1"],
  ["containers", "digest", "TEXT NOT NULL DEFAULT ''"],
  ["containers", "read_only", "INTEGER NOT NULL DEFAULT 0"],
  ["backup_runs", "dest", "TEXT NOT NULL DEFAULT 'a'"],
  ["backup_runs", "engine", "TEXT NOT NULL DEFAULT 'archive'"],
];

/** Data changes that go with a new column: run once, right after the column is added. */
const COLUMN_MIGRATIONS: Record<string, string> = {
  // Imported OpenLiteSpeed sites keep what they did before the edge: OLS (the backend) decides whether
  // plain HTTP redirects, so a site behind Cloudflare "Flexible" SSL does not start looping.
  "sites.http_redirect": "UPDATE sites SET http_redirect = 0 WHERE kind = 'legacy'",
};

// Sites disabled before suspension existed (enabled = 0, e.g. imported as suspended from CyberPanel) need
// no change: enabled = 0 now means suspended, and the edge serves them the suspended page.
export function migrate(d: Database) {
  for (const [table, column, def] of ADDED_COLUMNS) {
    const cols = d.query(`PRAGMA table_info(${table})`).all() as { name: string }[];
    if (cols.some((c) => c.name === column)) continue;
    d.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${def}`);
    const then = COLUMN_MIGRATIONS[`${table}.${column}`];
    if (then) d.exec(then);
  }
}

const now = () => Math.floor(Date.now() / 1000);

function decodeApp(row: any): App {
  return {
    ...row,
    domains: JSON.parse(row.domains),
    processes: JSON.parse(row.processes || "[]"),
    crons: JSON.parse(row.crons || "[]"),
    suspended_units: JSON.parse(row.suspended_units || "[]"),
  };
}
function decodeSite(row: any): Site {
  return {
    ...row,
    domains: JSON.parse(row.domains),
    routes: JSON.parse(row.routes),
    deny_paths: JSON.parse(row.deny_paths || "[]"),
    converted_from: row.converted_from ? JSON.parse(row.converted_from) : null,
    crons: JSON.parse(row.crons || "[]"),
  };
}

/** The processes an app runs. A single-process app is one unnamed process using the app's own fields. */
export function procsOf(app: App): Process[] {
  if (app.processes?.length) return app.processes;
  return [{ name: "", dir: "", routes: app.domains, memory_mb: app.memory_mb, start: app.start_cmd, port_a: app.port_a, port_b: app.port_b }];
}

/** Host names an app answers for (without route paths). */
export function appHosts(app: App): string[] {
  if (app.kind === "external") return app.domains;
  return [...new Set(procsOf(app).flatMap((p) => p.routes.map((r) => r.split("/")[0]!)))];
}

export const apps = {
  list(): App[] {
    return state().query("SELECT * FROM apps ORDER BY name").all().map(decodeApp);
  },
  get(name: string): App | null {
    const row = state().query("SELECT * FROM apps WHERE name = ?").get(name);
    return row ? decodeApp(row) : null;
  },
  insert(a: Partial<App> & { name: string }) {
    const t = now();
    const row: Record<string, unknown> = { ...a, domains: JSON.stringify(a.domains ?? []), processes: JSON.stringify(a.processes ?? []), crons: JSON.stringify(a.crons ?? []), created_at: t, updated_at: t };
    if (a.suspended_units) row.suspended_units = JSON.stringify(a.suspended_units);
    const cols = Object.keys(row);
    state()
      .query(`INSERT INTO apps (${cols.join(",")}) VALUES (${cols.map((c) => "$" + c).join(",")})`)
      .run(row as any);
  },
  update(name: string, patch: Partial<App>) {
    const row: Record<string, unknown> = { ...patch, updated_at: now() };
    if (patch.domains) row.domains = JSON.stringify(patch.domains);
    if (patch.processes) row.processes = JSON.stringify(patch.processes);
    if (patch.crons) row.crons = JSON.stringify(patch.crons);
    if (patch.suspended_units) row.suspended_units = JSON.stringify(patch.suspended_units);
    delete row.name;
    const sets = Object.keys(row).map((c) => `${c} = $${c}`);
    state().query(`UPDATE apps SET ${sets.join(", ")} WHERE name = $name`).run({ ...row, name } as any);
  },
  remove(name: string) {
    state().query("DELETE FROM apps WHERE name = ?").run(name);
  },
  /** Two consecutive free ports for a new app's blue/green slots. */
  nextPorts(taken: number[] = []): [number, number] {
    const used = new Set<number>(taken);
    for (const c of containers.list()) used.add(c.host_port);
    for (const a of apps.list()) {
      used.add(a.port_a), used.add(a.port_b);
      for (const p of a.processes) used.add(p.port_a), used.add(p.port_b);
    }
    for (const pv of previews.list()) for (const p of pv.processes) used.add(p.port_a), used.add(p.port_b);
    let p = APP_PORT_BASE;
    while (used.has(p) || used.has(p + 1)) p += 2;
    return [p, p + 1];
  },
};

/** The preview as the app deploy code sees it: the parent's build settings, the preview's own branch, host, ports and state. */
export function previewApp(parent: App, pv: Preview): App {
  return {
    ...parent,
    name: pvName(pv.id),
    kind: "managed",
    branch: pv.branch,
    domains: [pv.host],
    processes: pv.processes,
    port_a: pv.processes[0]?.port_a ?? 0,
    port_b: pv.processes[0]?.port_b ?? 0,
    active_slot: pv.active_slot,
    current_release: pv.current_release,
    ask_url: "",
    auto_deploy: 0,
    crons: [],
    preview_domain: "",
    // A preview's env is one file with the groups already merged in (prod-only variables left out).
    env_groups: "",
  };
}

const decodePreview = (row: any): Preview => ({ ...row, processes: JSON.parse(row.processes || "[]") });

export const previews = {
  list(app?: string): Preview[] {
    const rows = app === undefined ? state().query("SELECT * FROM previews ORDER BY id").all() : state().query("SELECT * FROM previews WHERE app = ? ORDER BY id").all(app);
    return rows.map(decodePreview);
  },
  get(id: number): Preview | null {
    const row = state().query("SELECT * FROM previews WHERE id = ?").get(id);
    return row ? decodePreview(row) : null;
  },
  find(app: string, slug: string): Preview | null {
    const row = state().query("SELECT * FROM previews WHERE app = ? AND slug = ?").get(app, slug);
    return row ? decodePreview(row) : null;
  },
  insert(p: Pick<Preview, "app" | "branch" | "slug" | "host" | "processes" | "expires_at">): number {
    const t = now();
    const r = state()
      .query("INSERT INTO previews (app, branch, slug, host, processes, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id")
      .get(p.app, p.branch, p.slug, p.host, JSON.stringify(p.processes), t, t, p.expires_at) as { id: number };
    return r.id;
  },
  update(id: number, patch: Partial<Pick<Preview, "active_slot" | "current_release" | "last_deploy" | "expires_at" | "updated_at">>) {
    const row: Record<string, unknown> = { updated_at: now(), ...patch };
    const sets = Object.keys(row).map((c) => `${c} = $${c}`);
    state().query(`UPDATE previews SET ${sets.join(", ")} WHERE id = $id`).run({ ...row, id } as any);
  },
  remove(id: number) {
    state().query("DELETE FROM previews WHERE id = ?").run(id);
  },
};

export const sites = {
  list(): Site[] {
    return state().query("SELECT * FROM sites ORDER BY name").all().map(decodeSite);
  },
  get(name: string): Site | null {
    const row = state().query("SELECT * FROM sites WHERE name = ?").get(name);
    return row ? decodeSite(row) : null;
  },
  upsert(
    input: Omit<Site, "created_at" | "deny_paths" | "converted_from" | "crons" | "suspended_reason" | "suspended_at" | "http_redirect"> &
      Partial<Pick<Site, "deny_paths" | "converted_from" | "crons" | "suspended_reason" | "suspended_at" | "http_redirect">>,
  ) {
    // Cron jobs change only through setCrons.
    const { crons: _crons, ...s } = input;
    const prev = sites.get(s.name);
    const deny = s.deny_paths ?? prev?.deny_paths ?? [];
    const from = s.converted_from !== undefined ? s.converted_from : (prev?.converted_from ?? null);
    // Why it was suspended stays while it is; a site that runs has none.
    const suspended = !s.enabled;
    state()
      .query(
        `INSERT INTO sites (name, kind, domains, root, routes, ask_url, php_version, tls_cert, tls_key, source, enabled, on_demand_tls, deny_paths, converted_from,
           suspended_reason, suspended_at, http_redirect, created_at)
         VALUES ($name, $kind, $domains, $root, $routes, $ask_url, $php_version, $tls_cert, $tls_key, $source, $enabled, $on_demand_tls, $deny_paths, $converted_from,
           $suspended_reason, $suspended_at, $http_redirect, $created_at)
         ON CONFLICT(name) DO UPDATE SET kind=$kind, domains=$domains, root=$root, routes=$routes, ask_url=$ask_url, php_version=$php_version,
           tls_cert=$tls_cert, tls_key=$tls_key, source=$source, enabled=$enabled, on_demand_tls=$on_demand_tls, deny_paths=$deny_paths, converted_from=$converted_from,
           suspended_reason=$suspended_reason, suspended_at=$suspended_at, http_redirect=$http_redirect`,
      )
      .run({
        ...s,
        domains: JSON.stringify(s.domains),
        routes: JSON.stringify(s.routes),
        deny_paths: JSON.stringify(deny),
        converted_from: from ? JSON.stringify(from) : "",
        suspended_reason: suspended ? (s.suspended_reason ?? prev?.suspended_reason ?? "") : "",
        suspended_at: suspended ? (s.suspended_at ?? prev?.suspended_at ?? 0) : 0,
        http_redirect: s.http_redirect ?? prev?.http_redirect ?? 1,
        created_at: now(),
      } as any);
  },
  setCrons(name: string, crons: Site["crons"]) {
    state().query("UPDATE sites SET crons = ? WHERE name = ?").run(JSON.stringify(crons), name);
  },
  /** enabled = false is a suspension (without a reason); see setSuspended. */
  setEnabled(name: string, enabled: boolean) {
    if (enabled) state().query("UPDATE sites SET enabled = 1, suspended_reason = '', suspended_at = 0 WHERE name = ?").run(name);
    else state().query("UPDATE sites SET enabled = 0, suspended_at = CASE WHEN enabled = 1 THEN ? ELSE suspended_at END WHERE name = ?").run(now(), name);
  },
  setSuspended(name: string, reason: string) {
    state().query("UPDATE sites SET enabled = 0, suspended_reason = ?, suspended_at = ? WHERE name = ?").run(reason, now(), name);
  },
  remove(name: string) {
    state().query("DELETE FROM sites WHERE name = ?").run(name);
  },
};

export const deploys = {
  start(app: string, trigger: string): number {
    const r = state()
      .query("INSERT INTO deploys (app, status, trigger, started_at) VALUES (?, 'running', ?, ?) RETURNING id")
      .get(app, trigger, now()) as { id: number };
    return r.id;
  },
  finish(id: number, patch: { status: "success" | "failed"; error?: string; commit_sha?: string; release?: string }) {
    state()
      .query("UPDATE deploys SET status = ?, error = ?, commit_sha = coalesce(?, commit_sha), release = coalesce(?, release), finished_at = ? WHERE id = ?")
      .run(patch.status, patch.error ?? "", patch.commit_sha ?? null, patch.release ?? null, now(), id);
  },
  list(app: string, limit = 20): Deploy[] {
    return state().query("SELECT * FROM deploys WHERE app = ? ORDER BY id DESC LIMIT ?").all(app, limit) as Deploy[];
  },
  get(id: number): Deploy | null {
    return (state().query("SELECT * FROM deploys WHERE id = ?").get(id) as Deploy) ?? null;
  },
  running(app: string): Deploy | null {
    return (state().query("SELECT * FROM deploys WHERE app = ? AND status = 'running'").get(app) as Deploy) ?? null;
  },
  /** Deploys left 'running' by a crash or restart are marked failed at startup. */
  failStale() {
    state().query("UPDATE deploys SET status = 'failed', error = 'agent restarted', finished_at = ? WHERE status = 'running'").run(now());
  },
};

export const backups = {
  jobs(): BackupJob[] {
    return state().query("SELECT * FROM backup_jobs ORDER BY name").all() as BackupJob[];
  },
  job(id: number): BackupJob | null {
    return (state().query("SELECT * FROM backup_jobs WHERE id = ?").get(id) as BackupJob) ?? null;
  },
  addJob(j: Pick<BackupJob, "name" | "kind" | "target" | "schedule" | "keep">): number {
    const r = state()
      .query("INSERT INTO backup_jobs (name, kind, target, schedule, keep) VALUES (?, ?, ?, ?, ?) RETURNING id")
      .get(j.name, j.kind, j.target, j.schedule, j.keep) as { id: number };
    return r.id;
  },
  removeJob(id: number) {
    state().query("DELETE FROM backup_jobs WHERE id = ?").run(id);
    state().query("DELETE FROM backup_runs WHERE job_id = ?").run(id);
  },
  startRun(jobId: number, dest = "a", engine = "archive"): number {
    const r = state()
      .query("INSERT INTO backup_runs (job_id, status, started_at, dest, engine) VALUES (?, 'running', ?, ?, ?) RETURNING id")
      .get(jobId, now(), dest, engine) as { id: number };
    return r.id;
  },
  finishRun(id: number, jobId: number, patch: { status: "success" | "failed"; object_key?: string; bytes?: number; error?: string }) {
    const t = now();
    state()
      .query("UPDATE backup_runs SET status = ?, object_key = ?, bytes = ?, error = ?, finished_at = ? WHERE id = ?")
      .run(patch.status, patch.object_key ?? "", patch.bytes ?? 0, patch.error ?? "", t, id);
    state().query("UPDATE backup_jobs SET last_run_at = ?, last_status = ? WHERE id = ?").run(t, patch.status, jobId);
  },
  runs(jobId: number, limit = 30): BackupRun[] {
    return state().query("SELECT * FROM backup_runs WHERE job_id = ? ORDER BY id DESC LIMIT ?").all(jobId, limit) as BackupRun[];
  },
  run(id: number): BackupRun | null {
    return (state().query("SELECT * FROM backup_runs WHERE id = ?").get(id) as BackupRun) ?? null;
  },
  /** Kept versions of a job in one store and engine, newest first. */
  successfulRuns(jobId: number, dest: string, engine: string): BackupRun[] {
    return state()
      .query("SELECT * FROM backup_runs WHERE job_id = ? AND status = 'success' AND object_key != '' AND dest = ? AND engine = ? ORDER BY id DESC")
      .all(jobId, dest, engine) as BackupRun[];
  },
  markDeleted(id: number) {
    state().query("UPDATE backup_runs SET object_key = '' WHERE id = ?").run(id);
  },
  failStale() {
    state().query("UPDATE backup_runs SET status = 'failed', error = 'agent restarted', finished_at = ? WHERE status = 'running'").run(now());
  },
};

export type Container = {
  name: string;
  image: string;
  /** port inside the container (0: not published) and its localhost port on the host */
  port: number;
  host_port: number;
  domains: string[];
  /** paths inside the container; each is backed by /srv/pano/containers/<name>/<n> */
  volumes: string[];
  command: string;
  memory_mb: number;
  /** sha256:... the tag resolved to when it was saved or last updated; this is what runs ("" on old rows: tag) */
  digest: string;
  /** 1: root filesystem read-only (volumes stay writable) */
  read_only: number;
  created_at: number;
};

export const containers = {
  list(): Container[] {
    return state()
      .query("SELECT * FROM containers ORDER BY name")
      .all()
      .map((r: any) => ({ ...r, domains: JSON.parse(r.domains), volumes: JSON.parse(r.volumes) }));
  },
  get(name: string): Container | null {
    return containers.list().find((c) => c.name === name) ?? null;
  },
  upsert(c: Omit<Container, "created_at">) {
    state()
      .query(
        `INSERT INTO containers (name, image, port, host_port, domains, volumes, command, memory_mb, digest, read_only, created_at)
         VALUES ($name, $image, $port, $host_port, $domains, $volumes, $command, $memory_mb, $digest, $read_only, $created_at)
         ON CONFLICT(name) DO UPDATE SET image=$image, port=$port, host_port=$host_port, domains=$domains, volumes=$volumes, command=$command, memory_mb=$memory_mb, digest=$digest, read_only=$read_only`,
      )
      .run({ ...c, domains: JSON.stringify(c.domains), volumes: JSON.stringify(c.volumes), created_at: now() } as any);
  },
  remove(name: string) {
    state().query("DELETE FROM containers WHERE name = ?").run(name);
  },
};

export type AndroidProject = {
  name: string;
  repo: string;
  branch: string;
  /** where prepare_cmd runs (repo root when empty) */
  root_dir: string;
  /** directory of gradlew under root_dir; empty: root_dir itself, or its android/ (React Native, Expo) */
  gradle_dir: string;
  /** e.g. "bun install" for React Native; runs in the build sandbox like Gradle */
  prepare_cmd: string;
  /** Gradle tasks, space separated */
  tasks: string;
  /** SDK packages this project needs beyond the defaults (the SDK is read-only for builds), e.g. "ndk;27.1.12297006" */
  sdk_packages: string;
  jdk: number;
  memory_mb: number;
  timeout_min: number;
  created_at: number;
};

export type AndroidArtifact = { name: string; size: number; sha256: string };

export type AndroidBuild = {
  id: number;
  project: string;
  status: "running" | "success" | "failed";
  trigger: string;
  commit_sha: string;
  signed: number;
  artifacts: AndroidArtifact[];
  error: string;
  started_at: number;
  finished_at: number | null;
};

export const androidProjects = {
  list(): AndroidProject[] {
    return state().query("SELECT * FROM android_projects ORDER BY name").all() as AndroidProject[];
  },
  get(name: string): AndroidProject | null {
    return (state().query("SELECT * FROM android_projects WHERE name = ?").get(name) as AndroidProject) ?? null;
  },
  upsert(p: Omit<AndroidProject, "created_at">) {
    state()
      .query(
        `INSERT INTO android_projects (name, repo, branch, root_dir, gradle_dir, prepare_cmd, tasks, sdk_packages, jdk, memory_mb, timeout_min, created_at)
         VALUES ($name, $repo, $branch, $root_dir, $gradle_dir, $prepare_cmd, $tasks, $sdk_packages, $jdk, $memory_mb, $timeout_min, $created_at)
         ON CONFLICT(name) DO UPDATE SET repo=$repo, branch=$branch, root_dir=$root_dir, gradle_dir=$gradle_dir, prepare_cmd=$prepare_cmd,
           tasks=$tasks, sdk_packages=$sdk_packages, jdk=$jdk, memory_mb=$memory_mb, timeout_min=$timeout_min`,
      )
      .run({ ...p, created_at: now() } as any);
  },
  remove(name: string) {
    state().query("DELETE FROM android_projects WHERE name = ?").run(name);
  },
};

const decodeBuild = (r: any): AndroidBuild => ({ ...r, artifacts: JSON.parse(r.artifacts || "[]") });

export const androidBuilds = {
  start(project: string, trigger: string, signed: boolean): number {
    const r = state()
      .query("INSERT INTO android_builds (project, status, trigger, signed, started_at) VALUES (?, 'running', ?, ?, ?) RETURNING id")
      .get(project, trigger, signed ? 1 : 0, now()) as { id: number };
    return r.id;
  },
  setCommit(id: number, sha: string) {
    state().query("UPDATE android_builds SET commit_sha = ? WHERE id = ?").run(sha, id);
  },
  finish(id: number, patch: { status: "success" | "failed"; error?: string; artifacts?: AndroidArtifact[] }) {
    state()
      .query("UPDATE android_builds SET status = ?, error = ?, artifacts = ?, finished_at = ? WHERE id = ?")
      .run(patch.status, patch.error ?? "", JSON.stringify(patch.artifacts ?? []), now(), id);
  },
  get(id: number): AndroidBuild | null {
    const r = state().query("SELECT * FROM android_builds WHERE id = ?").get(id);
    return r ? decodeBuild(r) : null;
  },
  list(project: string, limit = 20): AndroidBuild[] {
    return state().query("SELECT * FROM android_builds WHERE project = ? ORDER BY id DESC LIMIT ?").all(project, limit).map(decodeBuild);
  },
  running(): AndroidBuild[] {
    return state().query("SELECT * FROM android_builds WHERE status = 'running'").all().map(decodeBuild);
  },
  dropArtifacts(id: number) {
    state().query("UPDATE android_builds SET artifacts = '[]' WHERE id = ?").run(id);
  },
  /** Ids past the newest `keep` of a project (their logs and artifacts go). */
  older(project: string, keep: number): number[] {
    return (state().query("SELECT id FROM android_builds WHERE project = ? ORDER BY id DESC LIMIT -1 OFFSET ?").all(project, keep) as { id: number }[]).map((r) => r.id);
  },
  remove(ids: number[]) {
    for (const id of ids) state().query("DELETE FROM android_builds WHERE id = ?").run(id);
  },
  /** Builds left 'running' by a crash or restart are marked failed at startup. */
  failStale() {
    state().query("UPDATE android_builds SET status = 'failed', error = 'agent restarted', finished_at = ? WHERE status = 'running'").run(now());
  },
};

export const settings = {
  get(key: string): string | null {
    const r = state().query("SELECT value FROM settings WHERE key = ?").get(key) as { value: string } | null;
    return r?.value ?? null;
  },
  set(key: string, value: string) {
    state().query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(key, value);
  },
};

export function audit(actor: string, action: string, detail: unknown = "") {
  state()
    .query("INSERT INTO audit (at, actor, action, detail) VALUES (?, ?, ?, ?)")
    .run(now(), actor, action, typeof detail === "string" ? detail : JSON.stringify(detail));
}

/** The audit log keeps a year: enough to look back on an incident, without growing forever. */
export function pruneAudit(days = 365) {
  state().query("DELETE FROM audit WHERE at < ?").run(now() - days * 86400);
}

export function auditList(limit = 200) {
  return state().query("SELECT * FROM audit ORDER BY id DESC LIMIT ?").all(limit) as {
    id: number;
    at: number;
    actor: string;
    action: string;
    detail: string;
  }[];
}
