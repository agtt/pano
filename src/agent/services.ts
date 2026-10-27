// Database and cache servers, installed only when asked for: MariaDB, PostgreSQL
// and Valkey (the BSD-licensed Redis fork; same protocol, every Redis client
// works). Native packages from the distribution or the vendor's signed repo, not
// containers: nothing in between and the lowest memory use. Each listens on
// localhost only, starts with small memory settings and needs a password.
// A server that was already there (CyberPanel's MariaDB) is used as is: pano
// never rewrites the configuration of something it did not install.

import { paths } from "../shared/config.ts";
import { createDatabase } from "./mysql.ts";
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

/** MariaDB that was on the server before pano (CyberPanel) counts as installed but not managed. */
async function detect(k: ServiceKey): Promise<Record_ | null> {
  const r = rec(k);
  if (r) return r;
  if (k === "mariadb" && (await unitExists("mariadb.service"))) {
    const v = await run(["mariadb", "--version"], { check: false });
    return { unit: "mariadb.service", version: v.stdout.match(/(\d+\.\d+\.\d+)-MariaDB/)?.[1] ?? "", managed: false };
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

export async function install(k: ServiceKey, actor: string) {
  if (await detect(k)) throw new Error(`${SERVICES[k].label} is already installed`);
  const r = k === "mariadb" ? await installMariadb() : k === "postgres" ? await installPostgres() : await installValkey();
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
    `# Written by pano. Localhost only, small footprint.
[mysqld]
bind-address = 127.0.0.1
skip-name-resolve
local-infile = 0
performance_schema = OFF
innodb_buffer_pool_size = 128M
max_connections = 100
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

const pgConf = () => `# Written by pano. Localhost only, small footprint.
listen_addresses = 'localhost'
password_encryption = 'scram-sha-256'
max_connections = 50
shared_buffers = 128MB
work_mem = 4MB
max_wal_size = 256MB
min_wal_size = 64MB
`;

async function installValkey(): Promise<Record_> {
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
  const password = randomPassword(40);
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
maxmemory 256mb
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
  if (!pw) throw new Error("Valkey is not installed by pano");
  // "default" is the user requirepass sets; some clients reject an empty user name.
  return `redis://default:${pw}@127.0.0.1:6379`;
}

// ---- PostgreSQL databases --------------------------------------------------------

async function psql(query: string): Promise<string[][]> {
  const r = rec("postgres");
  if (!r?.psql) throw new Error("PostgreSQL is not installed");
  const out = await run([r.psql, "-X", "-q", "-A", "-t", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], { user: "postgres", cwd: "/", input: query, timeoutMs: 120_000 });
  return out.stdout
    .split("\n")
    .filter(Boolean)
    .map((l) => l.split("\t"));
}

const pgIdent = (s: string) => `"${s}"`;
const pgLit = (s: string) => `'${s.replace(/'/g, "''")}'`;

export async function pgList() {
  const rows = await psql("SELECT datname, pg_database_size(datname), pg_get_userbyid(datdba) FROM pg_database WHERE NOT datistemplate ORDER BY 1;");
  return rows.map(([name, size, owner]) => ({ name: name!, sizeMb: Math.round(Number(size) / 104857.6) / 10, owner: owner!, system: RESERVED_PG.has(name!) }));
}

export async function pgCreate(input: { name?: unknown; user?: unknown }, actor: string) {
  const name = String(input.name ?? "").trim();
  const user = String(input.user ?? "").trim() || name;
  if (!PG_NAME.test(name) || !PG_NAME.test(user)) throw new Error("names: lowercase letters, digits and _, starting with a letter");
  if (RESERVED_PG.has(name) || RESERVED_PG.has(user)) throw new Error("reserved name");
  const password = randomPassword();
  // CREATE DATABASE cannot run in a transaction: psql sends each statement on its own.
  await psql(
    [
      `CREATE ROLE ${pgIdent(user)} LOGIN PASSWORD ${pgLit(password)};`,
      `CREATE DATABASE ${pgIdent(name)} OWNER ${pgIdent(user)} ENCODING 'UTF8';`,
      `REVOKE ALL ON DATABASE ${pgIdent(name)} FROM PUBLIC;`,
    ].join("\n"),
  );
  audit(actor, "pg.create", { name, user });
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

/** Restores into an existing database; stops at the first error. */
export function pgRestoreCommand(db: string): string[] {
  return ["/usr/sbin/runuser", "-u", "postgres", "--", pgBin("psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", pgName(db)];
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
  audit(actor, "app.database", { app, engine, key });
  return { key, engine, database: engine === "valkey" ? url.split("/").pop()! : name };
}
