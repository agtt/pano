// Database and cache servers, installed only when asked for: MariaDB, PostgreSQL
// and Valkey (the BSD-licensed Redis fork; same protocol, every Redis client
// works). Native packages from the distribution or the vendor's signed repo, not
// containers: nothing in between and the lowest memory use. Each listens on
// localhost only, starts with small memory settings and needs a password.
// A server that was already there (CyberPanel's MariaDB) is used as is: pano
// never rewrites the configuration of something it did not install.

import { createHash } from "node:crypto";
import { paths } from "../shared/config.ts";
import { v } from "../shared/validate.ts";
import { ensureJob } from "./backup.ts";
import { sizes } from "./tune.ts";
import { attachUser as attachMysqlUser, createDatabase } from "./mysql.ts";
import { audit, settings } from "./state.ts";
import { ensureDir, exists, randomPassword, readText, run, writeAtomic } from "./sys.ts";

export type ServiceKey = "mariadb" | "postgres" | "valkey";
type Record_ = { unit: string; version: string; managed: boolean; psql?: string; dataDir?: string };

export const SERVICES: Record<ServiceKey, { label: string; port: number; note: string }> = {
  mariadb: { label: "MariaDB (MySQL)", port: 3306, note: "WordPress, PHP apps, Prisma/Drizzle mysql" },
  postgres: { label: "PostgreSQL", port: 5432, note: "Prisma, Drizzle, Supabase-style apps; latest major from postgresql.org" },
  valkey: { label: "Valkey (Redis)", port: 6379, note: "cache, sessions, BullMQ queues; works with every Redis client" },
};

const VALKEY_PASS = `${paths.secrets}/valkey.pass`;
const PG_NAME = /^[a-z_][a-z0-9_]{0,62}$/;
const RESERVED_PG = new Set(["postgres", "template0", "template1"]);

const rec = (k: ServiceKey): Record_ | null => JSON.parse(settings.get(`svc.${k}`) || "null");
const save = (k: ServiceKey, r: Record_) => settings.set(`svc.${k}`, JSON.stringify(r));
const debian = async () => /^(ID|ID_LIKE)=.*\b(debian|ubuntu)\b/m.test((await readText("/etc/os-release")) ?? "");
const elMajor = async () => (await readText("/etc/os-release"))?.match(/^VERSION_ID="?(\d+)/m)?.[1] ?? "9";
const unitExists = async (unit: string) => (await run(["systemctl", "cat", unit], { check: false, quiet: true })).code === 0;
const LONG = { timeoutMs: 900_000 };

async function dnf(...args: string[]) {
  return run(["dnf", "-y", "--setopt=strict=0", ...args], LONG);
}

/** Enables the newest module stream (EL ships older defaults, e.g. MariaDB 10.5 next to 10.11). */
async function newestStream(name: string) {
  const r = await run(["dnf", "-q", "module", "list", name], { check: false, timeoutMs: 300_000 });
  const streams = [...r.stdout.matchAll(new RegExp(`^${name}\\s+(\\d+(?:\\.\\d+)?)`, "gm"))].map((m) => m[1]!);
  const newest = streams.sort((a, b) => Number(a.split(".")[0]) - Number(b.split(".")[0]) || Number(a.split(".")[1] ?? 0) - Number(b.split(".")[1] ?? 0)).at(-1);
  if (newest) await run(["dnf", "-y", "module", "enable", `${name}:${newest}`], { check: false, timeoutMs: 300_000 });
}

// ---- status --------------------------------------------------------------------

async function unitState(unit: string) {
  const r = await run(["systemctl", "show", unit, "-p", "ActiveState", "-p", "MemoryCurrent", "-p", "UnitFileState"], { check: false });
  const get = (k: string) => r.stdout.match(new RegExp(`^${k}=(.*)$`, "m"))?.[1] ?? "";
  const mem = Number(get("MemoryCurrent"));
  return { active: get("ActiveState") || "unknown", memory: Number.isFinite(mem) && mem < 2 ** 60 ? mem : 0, enabled: get("UnitFileState") === "enabled" };
}

/** MariaDB or Redis that was on the server before pano (CyberPanel) counts as installed but not managed. */
async function detect(k: ServiceKey): Promise<Record_ | null> {
  const r = rec(k);
  if (r) return r;
  if (k === "mariadb" && (await unitExists("mariadb.service"))) {
    const v = await run(["mariadb", "--version"], { check: false });
    return { unit: "mariadb.service", version: v.stdout.match(/(\d+\.\d+\.\d+)-MariaDB/)?.[1] ?? "", managed: false };
  }
  if (k === "valkey") {
    // Installing next to it would fight over port 6379.
    for (const [unit, bin] of [["valkey.service", "valkey-server"], ["redis.service", "redis-server"]] as const) {
      if (!(await unitExists(unit))) continue;
      const v = await run([bin, "--version"], { check: false });
      return { unit, version: v.stdout.match(/v=(\d+\.\d+\.\d+)/)?.[1] ?? "", managed: false };
    }
  }
  return null;
}

export async function status() {
  const out = [];
  for (const k of Object.keys(SERVICES) as ServiceKey[]) {
    const r = await detect(k);
    out.push({ key: k, ...SERVICES[k], installed: !!r, version: r?.version ?? "", managed: r?.managed ?? false, ...(r ? await unitState(r.unit) : { active: "", memory: 0, enabled: false }) });
  }
  return out;
}

// ---- install -------------------------------------------------------------------

export async function install(k: ServiceKey, actor: string, valkeyPassword?: string) {
  if (await detect(k)) throw new Error(`${SERVICES[k].label} is already installed`);
  const r = k === "mariadb" ? await installMariadb() : k === "postgres" ? await installPostgres() : await installValkey(valkeyPassword);
  save(k, r);
  await run(["systemctl", "enable", "--now", r.unit]);
  if (k === "mariadb") await secureMariadb();
  audit(actor, "service.install", { service: k, version: r.version });
  return r;
}

async function installMariadb(): Promise<Record_> {
  const deb = await debian();
  if (deb) await run(["apt-get", "install", "-y", "mariadb-server"], LONG);
  else {
    await newestStream("mariadb");
    await dnf("install", "mariadb-server");
  }
  const conf = deb ? "/etc/mysql/mariadb.conf.d/90-pano.cnf" : "/etc/my.cnf.d/pano.cnf";
  await writeAtomic(
    conf,
    `# Written by pano. Localhost only; memory sized to this server.
[mysqld]
bind-address = 127.0.0.1
local-infile = 0
performance_schema = OFF
innodb_buffer_pool_size = ${sizes().innodbPoolMb}M
innodb_log_file_size = 256M
innodb_flush_method = O_DIRECT
max_connections = ${sizes().mariadbConnections}
thread_cache_size = 32
table_open_cache = 4000
tmp_table_size = 64M
max_heap_table_size = 64M
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
`,
    0o644,
  );
  const v = await run(["mariadb", "--version"], { check: false });
  return { unit: "mariadb.service", version: v.stdout.match(/(\d+\.\d+\.\d+)-MariaDB/)?.[1] ?? "", managed: true };
}

/** root stays on unix_socket auth (only the system root can use it); anonymous accounts go. */
async function secureMariadb() {
  await run(["mariadb", "--batch"], { input: "DELETE FROM mysql.global_priv WHERE User = '';\nFLUSH PRIVILEGES;\n", check: false });
}

async function installPostgres(): Promise<Record_> {
  if (await debian()) {
    await run(["apt-get", "install", "-y", "postgresql"], LONG);
    const version = (await run(["ls", "/usr/lib/postgresql"])).stdout.trim().split("\n").sort((a, b) => Number(a) - Number(b)).at(-1) ?? "";
    // Debian clusters read conf.d/ already and listen on localhost by default.
    await writeAtomic(`/etc/postgresql/${version}/main/conf.d/90-pano.conf`, pgConf(), 0o644);
    await run(["systemctl", "restart", "postgresql"], { check: false });
    return { unit: "postgresql.service", version, managed: true, psql: "/usr/bin/psql" };
  }
  // postgresql.org's repository has the current major for every EL release and architecture; packages are GPG-checked.
  const arch = (await run(["uname", "-m"])).stdout.trim();
  await dnf("install", `https://download.postgresql.org/pub/repos/yum/reporpms/EL-${await elMajor()}-${arch}/pgdg-redhat-repo-latest.noarch.rpm`);
  await run(["dnf", "-qy", "module", "disable", "postgresql"], { check: false, timeoutMs: 300_000 });
  let version = "";
  for (const n of ["18", "17", "16"]) {
    if ((await run(["dnf", "-y", "install", `postgresql${n}-server`], { ...LONG, check: false })).code === 0) {
      version = n;
      break;
    }
  }
  if (!version) throw new Error("no PostgreSQL server package found");
  const dataDir = `/var/lib/pgsql/${version}/data`;
  if (!(await exists(`${dataDir}/PG_VERSION`))) {
    await run([`/usr/pgsql-${version}/bin/postgresql-${version}-setup`, "initdb"], {
      env: { PGSETUP_INITDB_OPTIONS: "--auth-local=peer --auth-host=scram-sha-256 --data-checksums --encoding=UTF8 --locale=C.UTF-8" },
      timeoutMs: 300_000,
    });
  }
  await writeAtomic(`${dataDir}/pano.conf`, pgConf(), 0o600, "postgres");
  const main = (await readText(`${dataDir}/postgresql.conf`)) ?? "";
  if (!main.includes("include_if_exists = 'pano.conf'")) await writeAtomic(`${dataDir}/postgresql.conf`, `${main.trimEnd()}\n\ninclude_if_exists = 'pano.conf'\n`, 0o600, "postgres");
  return { unit: `postgresql-${version}.service`, version, managed: true, psql: `/usr/pgsql-${version}/bin/psql`, dataDir };
}

const pgConf = () => `# Written by pano. Localhost only; memory sized to this server.
listen_addresses = 'localhost'
password_encryption = 'scram-sha-256'
max_connections = 50
shared_buffers = ${sizes().pgSharedMb}MB
effective_cache_size = ${sizes().pgEffectiveCacheMb}MB
work_mem = 8MB
maintenance_work_mem = 128MB
random_page_cost = 1.1
effective_io_concurrency = 200
max_wal_size = 1GB
min_wal_size = 128MB
`;

async function installValkey(password = randomPassword(40)): Promise<Record_> {
  const deb = await debian();
  let unit = "";
  let conf = "";
  let group = "";
  if (deb) {
    if ((await run(["apt-get", "install", "-y", "valkey-server"], { ...LONG, check: false })).code === 0) [unit, conf, group] = ["valkey-server.service", "/etc/valkey/valkey.conf", "valkey"];
    else {
      await run(["apt-get", "install", "-y", "redis-server"], LONG);
      [unit, conf, group] = ["redis-server.service", "/etc/redis/redis.conf", "redis"];
    }
  } else {
    await dnf("install", "epel-release");
    if ((await dnf("install", "valkey").catch(() => null))) [unit, conf, group] = ["valkey.service", "/etc/valkey/valkey.conf", "valkey"];
    else {
      await newestStream("redis");
      await dnf("install", "redis");
      [unit, conf, group] = ["redis.service", (await exists("/etc/redis/redis.conf")) ? "/etc/redis/redis.conf" : "/etc/redis.conf", "redis"];
    }
  }
  await ensureDir(paths.secrets, 0o700);
  await writeAtomic(VALKEY_PASS, password + "\n", 0o600);
  // Last directive wins, so an include at the end of the stock file overrides it.
  const extra = `${conf.replace(/[^/]+$/, "")}pano.conf`;
  await writeAtomic(
    extra,
    `# Written by pano. Localhost only, password required.
bind 127.0.0.1 -::1
protected-mode yes
port 6379
requirepass ${password}
maxmemory ${sizes().valkeyMaxMb}mb
maxmemory-policy noeviction
`,
    0o640,
  );
  await run(["chgrp", group, extra], { check: false });
  const main = (await readText(conf)) ?? "";
  if (!main.includes(`include ${extra}`)) await writeAtomic(conf, `${main.trimEnd()}\n\ninclude ${extra}\n`, 0o640);
  await run(["chgrp", group, conf], { check: false });
  const bin = unit.startsWith("valkey") ? "valkey-server" : "redis-server";
  const v = await run([bin, "--version"], { check: false });
  return { unit, version: v.stdout.match(/v=(\d+\.\d+\.\d+)/)?.[1] ?? "", managed: true };
}

// ---- actions -------------------------------------------------------------------

export async function action(k: ServiceKey, what: "start" | "stop" | "restart", actor: string) {
  const r = await detect(k);
  if (!r) throw new Error("not installed");
  if (what === "stop") await run(["systemctl", "disable", "--now", r.unit]);
  else await run(["systemctl", what === "start" ? "enable" : "restart", ...(what === "start" ? ["--now"] : []), r.unit]);
  audit(actor, `service.${what}`, { service: k });
}

/** Connection details for apps; the Valkey password is revealed only to an authenticated, 2FA-confirmed admin. */
export async function valkeyUrl(): Promise<string> {
  const pw = ((await readText(VALKEY_PASS)) ?? "").trim();
  // "default" is the user requirepass sets; some clients reject an empty user name.
  if (pw) return `redis://default:${pw}@127.0.0.1:6379`;
  const existing = await existingRedisUrl();
  if (!existing) throw new Error("Valkey is not installed");
  return existing;
}

/** A Redis/Valkey that was there before pano: its address and password, read from its own config. */
export async function existingRedisUrl(): Promise<string | null> {
  for (const file of ["/etc/valkey/valkey.conf", "/etc/redis/redis.conf", "/etc/redis.conf"]) {
    const conf = await readText(file);
    if (conf === null) continue;
    const last = (k: string) => [...conf.matchAll(new RegExp(`^\\s*${k}\\s+(\\S+)`, "gm"))].at(-1)?.[1];
    const port = Number(last("port") ?? 6379);
    if (!port) continue; // unix socket only
    const pw = last("requirepass")?.replace(/^"(.*)"$/, "$1");
    return `redis://${pw ? `default:${encodeURIComponent(pw)}@` : ""}127.0.0.1:${port}`;
  }
  return null;
}

// ---- PostgreSQL databases --------------------------------------------------------

async function psql(query: string, db = "postgres"): Promise<string[][]> {
  const r = rec("postgres");
  if (!r?.psql) throw new Error("PostgreSQL is not installed");
  const out = await run([r.psql, "-X", "-q", "-A", "-t", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-d", db], { user: "postgres", cwd: "/", input: query, timeoutMs: 120_000 });
  return out.stdout
    .split("\n")
    .filter(Boolean)
    .map((l) => l.split("\t"));
}

const pgIdent = (s: string) => `"${s.replace(/"/g, '""')}"`;
const pgLit = (s: string) => `'${s.replace(/'/g, "''")}'`;

export async function pgList() {
  const rows = await psql("SELECT datname, pg_database_size(datname), pg_get_userbyid(datdba) FROM pg_database WHERE NOT datistemplate ORDER BY 1;");
  return rows.map(([name, size, owner]) => ({ name: name!, sizeMb: Math.round(Number(size) / 104857.6) / 10, owner: owner!, system: RESERVED_PG.has(name!) }));
}

export async function pgCreate(input: { name?: unknown; user?: unknown; password?: string }, actor: string) {
  const name = String(input.name ?? "").trim();
  const user = String(input.user ?? "").trim() || name;
  if (!PG_NAME.test(name) || !PG_NAME.test(user)) throw new Error("names: lowercase letters, digits and _, starting with a letter");
  if (RESERVED_PG.has(name) || RESERVED_PG.has(user)) throw new Error("reserved name");
  const password = input.password || randomPassword();
  // CREATE DATABASE cannot run in a transaction: psql sends each statement on its own.
  await psql(
    [
      `CREATE ROLE ${pgIdent(user)} LOGIN PASSWORD ${pgLit(password)};`,
      `CREATE DATABASE ${pgIdent(name)} OWNER ${pgIdent(user)} ENCODING 'UTF8';`,
      `REVOKE ALL ON DATABASE ${pgIdent(name)} FROM PUBLIC;`,
    ].join("\n"),
  );
  audit(actor, "pg.create", { name, user });
  ensureJob("postgres", name, actor);
  return { name, user, password, url: `postgres://${user}:${password}@127.0.0.1:5432/${name}` };
}

export async function pgDrop(name: unknown, confirm: unknown, actor: string) {
  const db = String(name ?? "");
  if (!PG_NAME.test(db) || RESERVED_PG.has(db)) throw new Error("cannot drop this database");
  if (confirm !== db) throw new Error("type the database name to confirm");
  const owner = (await psql(`SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = ${pgLit(db)};`))[0]?.[0] ?? "";
  await psql(`DROP DATABASE ${pgIdent(db)} WITH (FORCE);`);
  // The role created with the database goes too, unless it still owns another one.
  if (PG_NAME.test(owner) && !RESERVED_PG.has(owner)) {
    const rest = await psql(`SELECT count(*) FROM pg_database WHERE datdba = (SELECT oid FROM pg_roles WHERE rolname = ${pgLit(owner)});`);
    if (rest[0]?.[0] === "0") await psql(`DROP ROLE IF EXISTS ${pgIdent(owner)};`).catch(() => {});
  }
  audit(actor, "pg.drop", { name: db, owner });
}

export function pgName(s: unknown): string {
  const name = String(s ?? "");
  if (!PG_NAME.test(name)) throw new Error("PostgreSQL database name: lowercase letters, digits and _");
  return name;
}

function pgBin(tool: "psql" | "pg_dump"): string {
  const r = rec("postgres");
  if (!r?.psql) throw new Error("PostgreSQL is not installed");
  return r.psql.replace(/psql$/, tool);
}

/** Plain SQL dump (restores into any version) as the postgres superuser over the local socket. */
export function pgDumpCommand(db: string): string[] {
  return ["/usr/sbin/runuser", "-u", "postgres", "--", pgBin("pg_dump"), "--no-owner", "--no-privileges", "--", pgName(db)];
}

/**
 * Restores into an existing database; stops at the first error. The dump carries no owners, so
 * it loads as the database's owner: the tables belong to the app's role, not to postgres.
 */
export async function pgRestoreCommand(db: string): Promise<string[]> {
  const owner = await pgOwner(pgName(db)).catch(() => null);
  const asOwner = owner && !owner.superuser ? ["-c", `SET ROLE ${pgIdent(owner.name)}`, "-f", "-"] : [];
  return ["/usr/sbin/runuser", "-u", "postgres", "--", pgBin("psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", pgName(db), ...asOwner];
}

async function pgOwner(db: string): Promise<{ name: string; superuser: boolean } | null> {
  const row = (await psql(`SELECT r.rolname, r.rolsuper FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba WHERE d.datname = ${pgLit(db)};`))[0];
  return row ? { name: row[0]!, superuser: row[1] === "t" } : null;
}

/**
 * Full use of an existing database for a role that does not own it. When the owner is an
 * ordinary role with only this database, the role joins it (tables, migrations, everything the
 * owner may do). Otherwise (postgres, or an owner of several databases) it gets every privilege
 * on the public schema and on what the owner creates there later.
 */
export async function pgGrantAccess(db: string, user: string): Promise<"owner" | "member" | "grants"> {
  const owner = await pgOwner(pgName(db));
  if (!owner) throw new Error(`no PostgreSQL database ${db}`);
  const u = pgIdent(pgName(user));
  if (owner.name === user) return "owner";
  await psql(`GRANT CONNECT, TEMPORARY ON DATABASE ${pgIdent(db)} TO ${u};`);
  const owned = Number((await psql(`SELECT count(*) FROM pg_database WHERE datdba = (SELECT oid FROM pg_roles WHERE rolname = ${pgLit(owner.name)});`))[0]?.[0] ?? 0);
  if (!owner.superuser && owned === 1 && PG_NAME.test(owner.name)) {
    await psql(`GRANT ${pgIdent(owner.name)} TO ${u};`);
    return "member";
  }
  const o = pgIdent(owner.name);
  await psql(
    [
      `GRANT USAGE, CREATE ON SCHEMA public TO ${u};`,
      `GRANT ALL ON ALL TABLES IN SCHEMA public TO ${u};`,
      `GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ${u};`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE ${o} IN SCHEMA public GRANT ALL ON TABLES TO ${u};`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE ${o} IN SCHEMA public GRANT ALL ON SEQUENCES TO ${u};`,
    ].join("\n"),
    db,
  );
  return "grants";
}

/**
 * Recovery on a new server: the service as recorded in the restored panel state
 * is installed again; Valkey keeps its old password (apps have it in REDIS_URL).
 */
export async function reinstall(k: ServiceKey, actor: string) {
  if (!rec(k) || (await unitExists(rec(k)!.unit))) return;
  const password = k === "valkey" ? (await readText(VALKEY_PASS))?.trim() : undefined;
  settings.set(`svc.${k}`, "null");
  await install(k, actor, password || undefined);
}

/** Installs a service unless one is already there (recovery: what the restored data needs). */
export async function ensureService(k: ServiceKey, actor: string, valkeyPassword?: string) {
  if (!(await detect(k))) await install(k, actor, valkeyPassword);
}

export const recordedServices = (): ServiceKey[] => (Object.keys(SERVICES) as ServiceKey[]).filter((k) => !!rec(k));

/** An empty database for a dump to load into (recovery); the owner comes from the dump or an app's env. */
export async function pgEnsureDb(name: string) {
  if (!(await psql(`SELECT 1 FROM pg_database WHERE datname = ${pgLit(name)};`)).length) await psql(`CREATE DATABASE ${pgIdent(name)} ENCODING 'UTF8';`);
}

/** A database role/user with the password an app already has in its env (recovery). */
export async function pgEnsure(name: string, user: string, password: string) {
  const exists = (await psql(`SELECT 1 FROM pg_roles WHERE rolname = ${pgLit(user)};`)).length > 0;
  await psql(exists ? `ALTER ROLE ${pgIdent(user)} LOGIN PASSWORD ${pgLit(password)};` : `CREATE ROLE ${pgIdent(user)} LOGIN PASSWORD ${pgLit(password)};`);
  if (!(await psql(`SELECT 1 FROM pg_database WHERE datname = ${pgLit(name)};`)).length) {
    await psql(`CREATE DATABASE ${pgIdent(name)} OWNER ${pgIdent(user)} ENCODING 'UTF8';\nREVOKE ALL ON DATABASE ${pgIdent(name)} FROM PUBLIC;`);
  }
}

// ---- one click: a database for an app, straight into its environment ---------------

export type Engine = "postgres" | "mariadb" | "valkey";

/**
 * Creates a database (and its own user) for an app, installing the server first
 * if needed, and writes the connection URL into the app's environment. The
 * password goes from here into the app's env file only; it is not returned.
 * An existing variable is never overwritten.
 */
export async function databaseForApp(
  app: string,
  engine: Engine,
  env: { get: () => Promise<Record<string, string>>; set: (vars: Record<string, string>) => Promise<void> },
  actor: string,
) {
  const key = engine === "valkey" ? "REDIS_URL" : "DATABASE_URL";
  const current = await env.get();
  if (current[key]) throw new Error(`${key} is already set for ${app}; remove it from the environment first`);
  if (!(await detect(engine))) await install(engine, actor);
  const name = app.replace(/-/g, "_").slice(0, 32);
  let url: string;
  if (engine === "postgres") url = (await pgCreate({ name, user: name }, actor)).url;
  else if (engine === "mariadb") {
    const r = await createDatabase({ name, user: name }, actor);
    url = `mysql://${r.user}:${r.password}@127.0.0.1:3306/${r.name}`;
  } else {
    // One Valkey for the server; each app gets its own logical database number.
    const n = Number(settings.get("svc.valkey.nextDb") ?? 1);
    if (n > 15) throw new Error("all 15 Valkey databases are in use");
    settings.set("svc.valkey.nextDb", String(n + 1));
    url = `${await valkeyUrl()}/${n}`;
  }
  await env.set({ ...current, [key]: url });
  if (engine !== "valkey") ensureJob(engine === "postgres" ? "postgres" : "mysql", name, actor);
  audit(actor, "app.database", { app, engine, key });
  return { key, engine, database: engine === "valkey" ? url.split("/").pop()! : name };
}

/** The app's own user on an existing database: "<app>_<hash of the database>", unique per pair, at most 27 characters. */
export const attachUserName = (app: string, db: string) =>
  `${app.replace(/-/g, "_").slice(0, 20)}_${createHash("sha1").update(db).digest("hex").slice(0, 6)}`;

/**
 * Connects an app to a database that already exists (imported from cPanel/CyberPanel, or used by
 * another app): a user of its own that can reach only that database, a fresh password, the URL
 * written under `key`. Other users of the database keep theirs. An existing variable is never overwritten.
 */
export async function attachDatabaseToApp(
  app: string,
  engine: "postgres" | "mariadb",
  database: unknown,
  keyInput: unknown,
  env: { get: () => Promise<Record<string, string>>; set: (vars: Record<string, string>) => Promise<void> },
  actor: string,
) {
  const key = keyInput ? v.envKey(keyInput) : "DATABASE_URL";
  const current = await env.get();
  if (current[key]) throw new Error(`${key} is already set for ${app}; remove it from the environment first or pick another name`);
  const password = randomPassword();
  let db: string;
  let user: string;
  let url: string;
  let access: string;
  if (engine === "mariadb") {
    db = v.dbName(database);
    user = attachUserName(app, db);
    await attachMysqlUser(db, user, password);
    url = `mysql://${user}:${password}@127.0.0.1:3306/${db}`;
    access = "own user";
  } else {
    db = pgName(database);
    if (RESERVED_PG.has(db)) throw new Error("reserved database");
    user = attachUserName(app, db);
    const exists = (await psql(`SELECT 1 FROM pg_roles WHERE rolname = ${pgLit(user)};`)).length > 0;
    await psql(`${exists ? "ALTER" : "CREATE"} ROLE ${pgIdent(user)} LOGIN PASSWORD ${pgLit(password)};`);
    access = await pgGrantAccess(db, user);
    url = `postgres://${user}:${password}@127.0.0.1:5432/${db}`;
  }
  await env.set({ ...current, [key]: url });
  ensureJob(engine === "postgres" ? "postgres" : "mysql", db, actor);
  audit(actor, "app.database.attach", { app, engine, database: db, user, key, access });
  return { key, engine, database: db, user, access };
}
