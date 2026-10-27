// The agent's own state. Lives in /var/lib/pano/state.db (root, 0600); the web
// process never opens it and only sees what the agent returns over RPC.

import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { APP_PORT_BASE, fsPath, paths } from "../shared/config.ts";
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
  created_at: number;
  updated_at: number;
};

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
  enabled: number;
  on_demand_tls: number;
  /** php sites: path prefixes answered with 404 (from "deny from all" .htaccess files) */
  deny_paths: string[];
  /** set when a legacy site was converted to php: what to go back to */
  converted_from: { kind: Site["kind"]; root: string; php_version: string } | null;
  created_at: number;
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
  kind: "mysql" | "postgres" | "path" | "app";
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
};

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
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
`;

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
  ["sites", "deny_paths", "TEXT NOT NULL DEFAULT '[]'"],
  ["sites", "converted_from", "TEXT NOT NULL DEFAULT ''"],
];

function migrate(d: Database) {
  for (const [table, column, def] of ADDED_COLUMNS) {
    const cols = d.query(`PRAGMA table_info(${table})`).all() as { name: string }[];
    if (!cols.some((c) => c.name === column)) d.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${def}`);
  }
}

const now = () => Math.floor(Date.now() / 1000);

function decodeApp(row: any): App {
  return { ...row, domains: JSON.parse(row.domains), processes: JSON.parse(row.processes || "[]") };
}
function decodeSite(row: any): Site {
  return {
    ...row,
    domains: JSON.parse(row.domains),
    routes: JSON.parse(row.routes),
    deny_paths: JSON.parse(row.deny_paths || "[]"),
    converted_from: row.converted_from ? JSON.parse(row.converted_from) : null,
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
    const row = { ...a, domains: JSON.stringify(a.domains ?? []), processes: JSON.stringify(a.processes ?? []), created_at: t, updated_at: t };
    const cols = Object.keys(row);
    state()
      .query(`INSERT INTO apps (${cols.join(",")}) VALUES (${cols.map((c) => "$" + c).join(",")})`)
      .run(row as any);
  },
  update(name: string, patch: Partial<App>) {
    const row: Record<string, unknown> = { ...patch, updated_at: now() };
    if (patch.domains) row.domains = JSON.stringify(patch.domains);
    if (patch.processes) row.processes = JSON.stringify(patch.processes);
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
    let p = APP_PORT_BASE;
    while (used.has(p) || used.has(p + 1)) p += 2;
    return [p, p + 1];
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
  upsert(s: Omit<Site, "created_at" | "deny_paths" | "converted_from"> & Partial<Pick<Site, "deny_paths" | "converted_from">>) {
    const prev = sites.get(s.name);
    const deny = s.deny_paths ?? prev?.deny_paths ?? [];
    const from = s.converted_from !== undefined ? s.converted_from : (prev?.converted_from ?? null);
    state()
      .query(
        `INSERT INTO sites (name, kind, domains, root, routes, ask_url, php_version, tls_cert, tls_key, source, enabled, on_demand_tls, deny_paths, converted_from, created_at)
         VALUES ($name, $kind, $domains, $root, $routes, $ask_url, $php_version, $tls_cert, $tls_key, $source, $enabled, $on_demand_tls, $deny_paths, $converted_from, $created_at)
         ON CONFLICT(name) DO UPDATE SET kind=$kind, domains=$domains, root=$root, routes=$routes, ask_url=$ask_url, php_version=$php_version,
           tls_cert=$tls_cert, tls_key=$tls_key, source=$source, enabled=$enabled, on_demand_tls=$on_demand_tls, deny_paths=$deny_paths, converted_from=$converted_from`,
      )
      .run({
        ...s,
        domains: JSON.stringify(s.domains),
        routes: JSON.stringify(s.routes),
        deny_paths: JSON.stringify(deny),
        converted_from: from ? JSON.stringify(from) : "",
        created_at: now(),
      } as any);
  },
  setEnabled(name: string, enabled: boolean) {
    state().query("UPDATE sites SET enabled = ? WHERE name = ?").run(enabled ? 1 : 0, name);
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
  startRun(jobId: number): number {
    const r = state()
      .query("INSERT INTO backup_runs (job_id, status, started_at) VALUES (?, 'running', ?) RETURNING id")
      .get(jobId, now()) as { id: number };
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
  successfulRuns(jobId: number): BackupRun[] {
    return state().query("SELECT * FROM backup_runs WHERE job_id = ? AND status = 'success' ORDER BY id DESC").all(jobId) as BackupRun[];
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
        `INSERT INTO containers (name, image, port, host_port, domains, volumes, command, memory_mb, created_at)
         VALUES ($name, $image, $port, $host_port, $domains, $volumes, $command, $memory_mb, $created_at)
         ON CONFLICT(name) DO UPDATE SET image=$image, port=$port, host_port=$host_port, domains=$domains, volumes=$volumes, command=$command, memory_mb=$memory_mb`,
      )
      .run({ ...c, domains: JSON.stringify(c.domains), volumes: JSON.stringify(c.volumes), created_at: now() } as any);
  },
  remove(name: string) {
    state().query("DELETE FROM containers WHERE name = ?").run(name);
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

export function auditList(limit = 200) {
  return state().query("SELECT * FROM audit ORDER BY id DESC LIMIT ?").all(limit) as {
    id: number;
    at: number;
    actor: string;
    action: string;
    detail: string;
  }[];
}
