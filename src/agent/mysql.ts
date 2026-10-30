// MariaDB/MySQL management through the local `mysql` client as root (unix
// socket or /root/.my.cnf). SQL is sent on stdin, identifiers are validated
// against a strict pattern and literals are escaped, so nothing user-supplied is
// ever interpolated unchecked.

import { v } from "../shared/validate.ts";
import { audit, settings } from "./state.ts";
import { exists, randomPassword, run } from "./sys.ts";

const SYSTEM_DBS = new Set(["mysql", "information_schema", "performance_schema", "sys"]);
/** Databases other software depends on: visible, never droppable from the panel. */
const PROTECTED_DBS = new Set([...SYSTEM_DBS, "cyberpanel"]);
/** Accounts the server itself relies on: no password change or grant from the panel. */
const SYSTEM_USERS = new Set(["root", "mysql", "mariadb.sys", "mysql.sys", "mysql.session", "mysql.infoschema", "debian-sys-maint", "cyberpanel", "healthcheck"]);

export const lit = (s: string) => `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
export const ident = (s: string) => `\`${s.replace(/`/g, "``")}\``;
/**
 * A database name in GRANT/REVOKE ... ON <db>.*: "_" and "%" are wildcards there, so a_b would also
 * cover axb (and _____ every five-letter database, mysql included). Escaped, it means only itself.
 * A name that comes escaped already (cPanel's grants) is read as the database it names.
 */
export const grantDb = (s: string) => ident(s.replace(/\\([_%])/g, "$1").replace(/[_%]/g, "\\$&"));

export async function sql(query: string): Promise<string[][]> {
  const r = await run(["mysql", "--batch", "--skip-column-names", "--raw"], { input: query, timeoutMs: 60_000 });
  return r.stdout
    .split("\n")
    .filter(Boolean)
    .map((l) => l.split("\t"));
}

export type DbInfo = { name: string; sizeMb: number; tables: number; users: string[]; system: boolean };

export async function listDatabases(): Promise<DbInfo[]> {
  const [dbs, sizes, grants] = await Promise.all([
    sql("SHOW DATABASES;"),
    sql("SELECT table_schema, ROUND(SUM(data_length + index_length) / 1048576, 1), COUNT(*) FROM information_schema.tables GROUP BY table_schema;"),
    sql("SELECT Db, User, Host FROM mysql.db;"),
  ]);
  const size = new Map(sizes.map(([db, mb, n]) => [db!, { mb: Number(mb), n: Number(n) }]));
  return dbs.map(([name]) => ({
    name: name!,
    sizeMb: size.get(name!)?.mb ?? 0,
    tables: size.get(name!)?.n ?? 0,
    users: grants.filter(([db]) => db === name || db === name!.replace(/_/g, "\\_")).map(([, u, h]) => `${u}@${h}`),
    system: PROTECTED_DBS.has(name!),
  }));
}

/** Names only, without the protected ones (pickers; no size scan over information_schema). */
export async function databaseNames(): Promise<string[]> {
  return (await sql("SHOW DATABASES;")).map(([n]) => n!).filter((n) => !PROTECTED_DBS.has(n));
}

export async function listUsers(): Promise<{ user: string; host: string }[]> {
  const rows = await sql("SELECT User, Host FROM mysql.user WHERE User <> '' ORDER BY User;");
  return rows.map(([user, host]) => ({ user: user!, host: host! }));
}

export async function createDatabase(input: { name: unknown; user?: unknown; password?: unknown }, actor: string) {
  const name = v.dbName(input.name);
  if (SYSTEM_DBS.has(name)) throw new Error("reserved name");
  const user = input.user ? v.dbUser(input.user) : "";
  const password = user ? (input.password ? v.password(input.password) : randomPassword()) : "";
  const stmts = [`CREATE DATABASE ${ident(name)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`];
  if (user) {
    stmts.push(
      `CREATE USER IF NOT EXISTS ${lit(user)}@'localhost' IDENTIFIED BY ${lit(password)};`,
      `GRANT ALL PRIVILEGES ON ${grantDb(name)}.* TO ${lit(user)}@'localhost';`,
      "FLUSH PRIVILEGES;",
    );
  }
  await sql(stmts.join("\n"));
  audit(actor, "db.create", { name, user });
  return { name, user, password };
}

export async function dropDatabase(name: unknown, confirm: unknown, actor: string) {
  const db = v.dbName(name);
  if (PROTECTED_DBS.has(db)) throw new Error(`${db} is protected`);
  if (confirm !== db) throw new Error("type the database name to confirm");
  await sql(`DROP DATABASE ${ident(db)};`);
  audit(actor, "db.drop", { name: db });
}

export async function setPassword(user: unknown, host: unknown, password: unknown, actor: string) {
  const u = v.dbUser(user);
  const h = String(host ?? "localhost");
  if (!/^[A-Za-z0-9.%:_-]{1,255}$/.test(h)) throw new Error("invalid host");
  if (SYSTEM_USERS.has(u)) throw new Error(`change the ${u} password from the shell`);
  const pw = password ? v.password(password) : randomPassword();
  await sql(`ALTER USER ${lit(u)}@${lit(h)} IDENTIFIED BY ${lit(pw)};\nFLUSH PRIVILEGES;`);
  audit(actor, "db.password", { user: u, host: h });
  return { user: u, password: pw };
}

export async function grant(db: unknown, user: unknown, actor: string) {
  const name = v.dbName(db);
  if (PROTECTED_DBS.has(name)) throw new Error(`${name} is protected`);
  const u = v.dbUser(user);
  if (SYSTEM_USERS.has(u)) throw new Error(`${u} is a system account`);
  await sql(`GRANT ALL PRIVILEGES ON ${grantDb(name)}.* TO ${lit(u)}@'localhost';\nFLUSH PRIVILEGES;`);
  audit(actor, "db.grant", { db: name, user: u });
}

/** A user (new, or its password reset) with every privilege on one existing database and nothing else. */
export async function attachUser(db: string, user: string, password: string) {
  const name = v.dbName(db);
  if (PROTECTED_DBS.has(name)) throw new Error(`${name} is protected`);
  const u = v.dbUser(user);
  if (SYSTEM_USERS.has(u)) throw new Error(`${u} is a system account`);
  if (!(await sql(`SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ${lit(name)};`)).length) throw new Error(`no database ${name}`);
  await sql(
    [
      `CREATE USER IF NOT EXISTS ${lit(u)}@'localhost' IDENTIFIED BY ${lit(password)};`,
      `ALTER USER ${lit(u)}@'localhost' IDENTIFIED BY ${lit(password)};`,
      `GRANT ALL PRIVILEGES ON ${grantDb(name)}.* TO ${lit(u)}@'localhost';`,
      "FLUSH PRIVILEGES;",
    ].join("\n"),
  );
}

/** A grant pattern with an unescaped "_" or "%": it also covers databases it does not name. */
export const wildcardGrant = (db: string) => /(^|[^\\])(\\\\)*[_%]/.test(db);

/** `GRANT <privs> ON <db>.* TO ...` lines of SHOW GRANTS: the database and what it grants. */
export function parseDbGrants(lines: string[]): { db: string; privs: string; withGrant: boolean }[] {
  const out: { db: string; privs: string; withGrant: boolean }[] = [];
  for (const line of lines) {
    const m = line.match(/^GRANT (.+?) ON `((?:[^`]|``)+)`\.\* TO .*?( WITH GRANT OPTION)?$/);
    if (m) out.push({ db: m[2]!.replace(/``/g, "`"), privs: m[1]!, withGrant: !!m[3] });
  }
  return out;
}

/**
 * Once: grants written before names were escaped (a_b also covering axb) are
 * narrowed to the database they name, where a database by exactly that name
 * exists. A deliberate pattern (cPanel's user\_%) has no such database and stays.
 */
export async function narrowWildcardGrants() {
  if (settings.get("mysql.grants.narrowed") === "1") return;
  if (!(await exists("/usr/bin/mysql")) && !(await exists("/usr/bin/mariadb"))) return settings.set("mysql.grants.narrowed", "1");
  const dbs = new Set((await sql("SHOW DATABASES;")).map(([n]) => n!));
  const narrowed: string[] = [];
  for (const [db, user, host] of await sql("SELECT Db, User, Host FROM mysql.db;")) {
    if (!db || !user || !host || SYSTEM_USERS.has(user) || !wildcardGrant(db) || !dbs.has(db)) continue;
    const lines = (await sql(`SHOW GRANTS FOR ${lit(user)}@${lit(host)};`)).map(([l]) => l!);
    const g = parseDbGrants(lines).find((x) => x.db === db);
    if (!g) continue;
    await sql(
      [
        `GRANT ${g.privs} ON ${grantDb(db)}.* TO ${lit(user)}@${lit(host)}${g.withGrant ? " WITH GRANT OPTION" : ""};`,
        `REVOKE ALL PRIVILEGES${g.withGrant ? ", GRANT OPTION" : ""} ON ${ident(db)}.* FROM ${lit(user)}@${lit(host)};`,
        "FLUSH PRIVILEGES;",
      ].join("\n"),
    );
    narrowed.push(`${user}@${host} on ${db}`);
  }
  settings.set("mysql.grants.narrowed", "1");
  if (narrowed.length) audit("system", "db.grants.narrowed", { grants: narrowed });
}

/** mysqldump argv for a consistent, non-locking dump of one database. */
export function dumpCommand(db: string): string[] {
  return ["mysqldump", "--single-transaction", "--quick", "--routines", "--triggers", "--events", "--hex-blob", "--", v.dbName(db)];
}

/**
 * --binary-mode: client commands in the dump ("\! cmd", "source file", also inside a /*! *\/ comment
 * a tenant's routine body can carry) are not run; this client runs as root.
 */
export function restoreCommand(db: string): string[] {
  return ["mysql", "--binary-mode", v.dbName(db)];
}

/** Whether the server listens beyond localhost (shown on the Security page). */
export async function bindAddress(): Promise<string> {
  const rows = await sql("SELECT @@bind_address;").catch(() => [] as string[][]);
  return rows[0]?.[0] ?? "";
}
