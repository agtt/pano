// MariaDB (MySQL) remote access over TLS, for apps that run elsewhere (Vercel, Netlify, a laptop
// without the VPN). Off by default. When on:
// - MariaDB also listens on the server's address, TLS 1.2+ with the edge's certificate for a
//   name of its own (db.example.com), so clients verify it like any HTTPS site; renewals are
//   loaded with FLUSH SSL, no restart;
// - only "remote users" can log in from outside: accounts of their own for one database, with
//   a 40-character random password, REQUIRE SSL and a connection cap. The apps' own users are
//   'user'@'localhost' and match no remote address. Turning it on is refused while any other
//   account accepts a non-local host ('x'@'%' from an import), since that one would then face
//   the internet with a password only;
// - optionally only from given networks (Vercel Static IPs, a fixed office address): the
//   accounts' hosts and the firewalls (firewalld, pano's own, the VPN services lock) enforce it.
// Everything sits in one drop-in file (removed when turned off), so it also works with a MariaDB
// that pano did not install (CyberPanel's) without rewriting its configuration.

import { createHash } from "node:crypto";
import { applyEdge } from "./edge.ts";
import { grantDb, lit, sql } from "./mysql.ts";
import { assertRemoteDomainFree, copyCert, listening, localIp, obtainCert, parseAllow, REMOTE_CONN_LIMIT, remoteDomain, syncNetwork } from "./remotedb.ts";
import { REMOTE_PORT, remoteConfig, saveRemoteConfig } from "./remotedb-config.ts";
import { v } from "../shared/validate.ts";
import { audit, settings } from "./state.ts";
import { exists, randomPassword, readText, remove, run, writeAtomic } from "./sys.ts";

export type RemoteUser = { user: string; database: string; created_at: number };

const PORT = REMOTE_PORT.mariadb;
/** Include directories MariaDB reads, in the order the packages use them (Debian/Ubuntu, EL, older Debian layouts). */
const INCLUDE_DIRS = ["/etc/mysql/mariadb.conf.d", "/etc/my.cnf.d", "/etc/mysql/conf.d"];
const DROPIN_NAME = "zz-pano-remote.cnf";
const LOCAL_HOSTS = ["localhost", "127.0.0.1", "::1"];
const WILDCARD_BIND = ["", "*", "0.0.0.0", "::"];

const users = (): RemoteUser[] => JSON.parse(settings.get("mysql.remote.users") || "[]");
const saveUsers = (list: RemoteUser[]) => settings.set("mysql.remote.users", JSON.stringify(list));
const config = () => remoteConfig("mariadb");

// ---- rendering ---------------------------------------------------------------

/** The drop-in: TLS files and versions, and the address list when the server does not already listen everywhere. */
export function renderDropin(o: { bind?: string; cert: string; key: string }): string {
  return [
    "# Written by pano: MariaDB remote access (Services → MariaDB). Removed when it is turned off.",
    "[mysqld]",
    ...(o.bind ? [`bind-address = ${o.bind}`] : []),
    `ssl_cert = ${o.cert}`,
    `ssl_key = ${o.key}`,
    "tls_version = TLSv1.2,TLSv1.3",
    "",
  ].join("\n");
}

/** What the server should listen on: its own setting plus the address, or nothing to add when it already listens everywhere. */
export function bindFor(base: string, ip: string): string | undefined {
  const b = base.trim();
  if (WILDCARD_BIND.includes(b)) return undefined;
  return [...new Set([...b.split(",").map((s) => s.trim()).filter(Boolean), ip])].join(",");
}

/** A MariaDB account host for an allowed network: the address, or IPv4 "network/netmask". IPv6 matches only whole addresses. */
export function hostSpec(network: string): string {
  const [addr, bitsText] = network.split("/");
  const bits = Number(bitsText);
  if (network.includes(":")) {
    if (bits !== 128) throw new Error(`MariaDB matches IPv6 only as single addresses: ${network}`);
    return addr!;
  }
  if (bits === 32) return addr!;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return `${addr}/${[24, 16, 8, 0].map((s) => (mask >>> s) & 255).join(".")}`;
}

export const accountHosts = (allow: string[]) => (allow.length ? allow.map(hostSpec) : ["%"]);

/** DATABASE_URL in the two forms clients read: Prisma (sslaccept) and mysql2/Drizzle (ssl options as JSON). */
export function remoteUrls(u: { user: string; database: string }, password: string, domain: string) {
  const base = `mysql://${u.user}:${password}@${domain}:${PORT}/${u.database}`;
  return { prisma: `${base}?sslaccept=strict`, mysql2: `${base}?ssl=${encodeURIComponent('{"rejectUnauthorized":true}')}` };
}

// ---- applying ----------------------------------------------------------------

async function includeDir(): Promise<string> {
  for (const d of INCLUDE_DIRS) if (await exists(d)) return d;
  throw new Error(`no MariaDB include directory (${INCLUDE_DIRS.join(", ")})`);
}

async function unit(): Promise<string> {
  for (const u of ["mariadb.service", "mysql.service", "mysqld.service"]) {
    if ((await run(["systemctl", "cat", u], { check: false, quiet: true })).code === 0) return u;
  }
  throw new Error("MariaDB is not installed");
}

async function files() {
  const dir = await includeDir();
  return { dropin: `${dir}/${DROPIN_NAME}`, tlsDir: `${dir}/pano-tls` };
}

/** MariaDB 10.11+ listens on a list of addresses; older ones only on one, or everywhere. */
async function checkServer(base: string) {
  const version = (await sql("SELECT VERSION();"))[0]?.[0] ?? "";
  if (!/MariaDB/i.test(version)) throw new Error(`remote access supports MariaDB (this server runs MySQL ${version})`);
  const [maj, min] = version.split(".").map(Number) as [number, number];
  // ACCOUNT LOCK and FLUSH SSL (certificate renewals without a restart) came with 10.4.
  if (maj < 10 || (maj === 10 && min < 4)) throw new Error(`MariaDB ${version.split("-")[0]} is too old for remote access (10.4 or newer)`);
  if (bindFor(base, "x") && (maj < 10 || (maj === 10 && min < 11))) throw new Error(`MariaDB ${version.split("-")[0]} listens on one address only; remote access needs 10.11 or newer`);
}

/** Accounts that would answer from the internet besides pano's remote users. */
async function exposedAccounts(): Promise<string[]> {
  const ours = new Set(users().map((u) => u.user));
  // Host = '' is not local: the server reads it as "any host", so such an account counts as exposed.
  const rows = await sql(`SELECT User, Host FROM mysql.user WHERE Host NOT IN (${LOCAL_HOSTS.map(lit).join(", ")});`);
  return rows.filter(([u]) => !ours.has(u!)).map(([u, h]) => `'${u}'@'${h}'`);
}

async function hostsOf(user: string): Promise<string[]> {
  return (await sql(`SELECT Host FROM mysql.user WHERE User = ${lit(user)};`)).map(([h]) => h!);
}

/**
 * Each remote user gets exactly the accounts the allowed networks call for. New hosts copy the
 * password hash of an existing account (the password itself is not kept anywhere).
 */
async function syncAccounts(allow: string[], open: boolean) {
  const want = accountHosts(allow);
  for (const u of users()) {
    const have = await hostsOf(u.user);
    if (!have.length) continue;
    const from = have[0]!;
    const missing = want.filter((h) => !have.includes(h));
    if (missing.length) {
      const [plugin, hash] = (await sql(`SELECT plugin, authentication_string FROM mysql.user WHERE User = ${lit(u.user)} AND Host = ${lit(from)};`))[0] ?? [];
      if (!plugin || !/^[a-z0-9_]{1,64}$/.test(plugin) || !hash) throw new Error(`cannot copy the password of ${u.user}`);
      for (const h of missing) {
        await sql(
          [
            `CREATE USER ${lit(u.user)}@${lit(h)} IDENTIFIED VIA ${plugin} USING ${lit(hash)} REQUIRE SSL WITH MAX_USER_CONNECTIONS ${REMOTE_CONN_LIMIT};`,
            `GRANT ALL PRIVILEGES ON ${grantDb(u.database)}.* TO ${lit(u.user)}@${lit(h)};`,
          ].join("\n"),
        );
      }
    }
    for (const h of have) if (!want.includes(h)) await sql(`DROP USER IF EXISTS ${lit(u.user)}@${lit(h)};`);
    // Off: the accounts stay (and come back when it is turned on) but cannot log in, even if the server listens everywhere anyway.
    for (const h of want) await sql(`ALTER USER ${lit(u.user)}@${lit(h)} ACCOUNT ${open ? "UNLOCK" : "LOCK"};`);
  }
  await sql("FLUSH PRIVILEGES;");
}

/**
 * Writes the drop-in from the saved state (only with a certificate in place), restarts MariaDB
 * when it changed, else reloads the certificate; then brings the remote accounts in line.
 */
async function apply() {
  const f = await files();
  const c = config();
  const ip = c.on ? await localIp() : "";
  const tls = !!(c.on && ip && (await exists(`${f.tlsDir}/server.crt`)) && (await exists(`${f.tlsDir}/server.key`)));
  const base = settings.get("mysql.remote.baseBind") ?? "127.0.0.1";
  const want = tls ? renderDropin({ bind: bindFor(base, ip), cert: `${f.tlsDir}/server.crt`, key: `${f.tlsDir}/server.key` }) : null;
  const before = await readText(f.dropin);
  if (want !== before) {
    if (want) await writeAtomic(f.dropin, want, 0o644);
    else await remove(f.dropin);
    await restart();
  } else if (tls) await sql("FLUSH SSL;");
  if (tls) {
    const [ssl, cert, bind] = (await sql("SELECT @@have_ssl, @@ssl_cert, @@bind_address;"))[0] ?? [];
    if (ssl !== "YES" || cert !== `${f.tlsDir}/server.crt`) throw new Error(`MariaDB did not take ${f.dropin} (another file read later overrides it?)`);
    if (!WILDCARD_BIND.includes(bind ?? "") && !(bind ?? "").split(",").includes(ip)) throw new Error(`MariaDB listens on ${bind}, not on ${ip}`);
  }
  await syncAccounts(c.allow, tls);
  return { listening: tls, ip };
}

async function restart() {
  const u = await unit();
  await run(["systemctl", "restart", u], { check: false, timeoutMs: 180_000 });
  for (let i = 0; i < 60; i++) {
    if (await sql("SELECT 1;").then(() => true, () => false)) return;
    await Bun.sleep(500);
  }
  const log = (await run(["journalctl", "-u", u, "-n", "5", "--no-pager"], { check: false })).stdout.trim();
  throw new Error(`MariaDB did not come back: ${log.split("\n").at(-1) ?? ""}`);
}

// ---- operations --------------------------------------------------------------

export async function status() {
  const c = config();
  const ip = c.on ? await localIp() : "";
  const available = await unit().then(() => true, () => false);
  return {
    engine: "mariadb" as const,
    available,
    on: c.on,
    domain: c.domain,
    allow: c.allow,
    port: PORT,
    ip,
    listening: c.on && (await listening(PORT, ip)),
    connLimit: REMOTE_CONN_LIMIT,
    users: users(),
  };
}

/**
 * Turns remote access on, or changes its name or networks while on. Needs the edge (it gets the
 * certificate) and a DNS-only record for the name pointing here. Anything failing puts the
 * previous state back.
 */
export async function enable(input: { domain?: unknown; allow?: unknown }, actor: string) {
  await unit();
  const f = await files();
  const domain = remoteDomain(input.domain);
  assertRemoteDomainFree(domain);
  const allow = parseAllow(input.allow);
  accountHosts(allow); // IPv6 networks are refused before anything changes
  const exposed = await exposedAccounts();
  if (exposed.length) {
    throw new Error(`these accounts accept logins from other hosts and would face the internet with a password only: ${exposed.slice(0, 10).join(", ")}. Restrict them to localhost (or drop them) first.`);
  }
  // The server's own address setting, read while pano's file is not there yet.
  if (!(await exists(f.dropin))) settings.set("mysql.remote.baseBind", (await sql("SELECT @@bind_address;"))[0]?.[0] ?? "127.0.0.1");
  await checkServer(settings.get("mysql.remote.baseBind") ?? "127.0.0.1");
  const previous = config();
  saveRemoteConfig("mariadb", { on: true, domain, allow });
  try {
    await obtainCert(domain, f.tlsDir, "mysql");
    const r = await apply();
    if (!r.listening) throw new Error("no IPv4 address to listen on");
    await syncNetwork("mariadb");
  } catch (e) {
    saveRemoteConfig("mariadb", previous);
    if (previous.on) await copyCert(previous.domain, f.tlsDir, "mysql").catch(() => {});
    await apply().catch(() => {});
    await syncNetwork("mariadb").catch(() => {});
    await applyEdge().catch(() => {});
    throw e;
  }
  audit(actor, "mysql.remote.enable", { domain, allow });
  return status();
}

/** Back to how MariaDB was. Remote users stay (locked) and work again when it is turned on. */
export async function disable(actor: string) {
  const f = await files();
  saveRemoteConfig("mariadb", { ...config(), on: false });
  await apply();
  await syncNetwork("mariadb");
  await remove(f.tlsDir);
  await applyEdge().catch(() => {});
  audit(actor, "mysql.remote.disable", {});
}

/** A remote user for one database; the URLs (with the password) are returned once and not stored. */
export async function addUser(input: { database?: unknown }, actor: string) {
  const c = config();
  if (!c.on) throw new Error("turn remote access on first");
  const database = v.dbName(input.database);
  if (["mysql", "information_schema", "performance_schema", "sys", "cyberpanel"].includes(database)) throw new Error(`${database} is protected`);
  if (!(await sql(`SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ${lit(database)};`)).length) throw new Error(`no database ${database}`);
  const tag = createHash("sha1").update(`${database}:${Date.now()}:${randomPassword(8)}`).digest("hex").slice(0, 6);
  const user = v.dbUser(`${database.slice(0, 20)}_r_${tag}`);
  const password = randomPassword(40);
  const stmts = accountHosts(c.allow).flatMap((h) => [
    `CREATE USER ${lit(user)}@${lit(h)} IDENTIFIED BY ${lit(password)} REQUIRE SSL WITH MAX_USER_CONNECTIONS ${REMOTE_CONN_LIMIT};`,
    `GRANT ALL PRIVILEGES ON ${grantDb(database)}.* TO ${lit(user)}@${lit(h)};`,
  ]);
  await sql([...stmts, "FLUSH PRIVILEGES;"].join("\n"));
  saveUsers([...users(), { user, database, created_at: Date.now() }]);
  await apply();
  audit(actor, "mysql.remote.user.add", { user, database });
  return { user, database, ...remoteUrls({ user, database }, password, c.domain) };
}

/** Takes the remote user away: every account of it, and its open sessions. */
export async function removeUser(input: { user?: unknown }, actor: string) {
  const name = String(input.user ?? "");
  const u = users().find((x) => x.user === name);
  if (!u) throw new Error("no such remote user");
  await dropAccounts(u.user);
  saveUsers(users().filter((x) => x.user !== name));
  audit(actor, "mysql.remote.user.remove", { user: u.user, database: u.database });
}

async function dropAccounts(user: string) {
  for (const h of await hostsOf(user)) await sql(`DROP USER IF EXISTS ${lit(user)}@${lit(h)};`);
  // DROP USER leaves sessions that are already open.
  for (const [id] of await sql(`SELECT ID FROM information_schema.PROCESSLIST WHERE USER = ${lit(user)};`)) {
    if (/^\d+$/.test(id ?? "")) await sql(`KILL CONNECTION ${id};`).catch(() => {});
  }
  await sql("FLUSH PRIVILEGES;");
}

/** A dropped database takes its remote users with it. */
export async function forgetDatabase(database: string, actor: string) {
  const gone = users().filter((u) => u.database === database);
  if (!gone.length) return;
  for (const u of gone) await dropAccounts(u.user).catch(() => {});
  saveUsers(users().filter((u) => u.database !== database));
  audit(actor, "mysql.remote.user.remove", { database, users: gone.map((u) => u.user) });
}

/** From the agent's timer: the edge's renewals (FLUSH SSL), a changed address or a restored server (recovery). */
export async function renew() {
  const c = config();
  if (!c.on) return;
  const f = await files().catch(() => null);
  if (!f || !(await unit().then(() => true, () => false))) return;
  const changed = await copyCert(c.domain, f.tlsDir, "mysql");
  if (changed === null) return;
  const ip = await localIp();
  const dropin = (await readText(f.dropin)) ?? "";
  const bindOk = !ip || !bindFor(settings.get("mysql.remote.baseBind") ?? "127.0.0.1", ip) || dropin.includes(`,${ip}`);
  if (!changed && dropin && bindOk) return;
  await apply();
  await syncNetwork("mariadb");
}
