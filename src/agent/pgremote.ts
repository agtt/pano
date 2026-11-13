// PostgreSQL remote access over TLS, for apps that run elsewhere (Vercel, Netlify, a laptop
// without the VPN). Off by default. When on:
// - PostgreSQL also listens on the server's address, TLS 1.2+ only, with the edge's
//   certificate for a name of its own (db.example.com), so clients verify it like any HTTPS
//   site (sslmode=verify-full) and renewals come from the edge;
// - only "remote users" may log in from outside: each is a role of its own for one database,
//   with a long random password (SCRAM), TLS required (hostssl) and a connection cap, listed
//   in a pano-managed block at the top of pg_hba.conf. Every other role (the apps' own) has
//   no line for a non-local address, so PostgreSQL refuses it before asking for a password;
// - optionally only from given networks (Vercel Static IPs, a fixed office address): both
//   pg_hba and the firewalls (firewalld, pano's own, the VPN services lock) enforce the list.
// A server pano did not install is never reconfigured.

import { createHash } from "node:crypto";
import { applyEdge, edgeCert, edgeInstalled } from "./edge.ts";
import { followSettings as followFirewall } from "./firewall.ts";
import { cidr, PG_REMOTE_PORT, pgRemoteConfig, type PgRemote } from "./pgremote-config.ts";
import { pgConf, pgGrantAccess, pgIdent, pgLit, pgName, pgOwner, pgPaths, psql, RESERVED_PG } from "./services.ts";
import { audit, settings } from "./state.ts";
import { ensureDir, exists, randomPassword, readText, remove, run, writeAtomic } from "./sys.ts";
import { followPgRemote as followVpn } from "./vpn.ts";

export type RemoteUser = { user: string; database: string; created_at: number };

/** Connections one remote user may hold: serverless functions open many; local apps keep the rest of max_connections. */
export const REMOTE_CONN_LIMIT = 20;
const BEGIN = "# pano remote access: begin (written by pano, edits are replaced)";
const END = "# pano remote access: end";
const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

const users = (): RemoteUser[] => JSON.parse(settings.get("pg.remote.users") || "[]");
const saveUsers = (list: RemoteUser[]) => settings.set("pg.remote.users", JSON.stringify(list));
const saveConfig = (c: PgRemote) => settings.set("pg.remote", JSON.stringify(c));

// ---- rendering ---------------------------------------------------------------

/** pg_hba lines for the remote users: TLS only, SCRAM, their own database, from the allowed networks (empty: anywhere). */
export function renderHbaBlock(list: Pick<RemoteUser, "user" | "database">[], allow: string[]): string[] {
  if (!list.length) return [];
  const sources = allow.length ? allow : ["0.0.0.0/0", "::/0"];
  // Quoted: a database called "all" or "replication" would otherwise be read as the keyword.
  return [BEGIN, ...list.flatMap((u) => sources.map((s) => `hostssl "${u.database}" "${u.user}" ${s} scram-sha-256`)), END];
}

/** The file with pano's block replaced (or removed when empty). It goes first: pg_hba uses the first line that matches. */
export function mergeHba(current: string, block: string[]): string {
  const lines = current.split("\n");
  const start = lines.indexOf(BEGIN);
  const end = lines.indexOf(END);
  const rest = start >= 0 && end > start ? [...lines.slice(0, start), ...lines.slice(end + 1)] : lines;
  return block.length ? [...block, ...rest].join("\n") : rest.join("\n");
}

/** Parses the allowed networks (spaces, commas or new lines between them); throws on the first that is not one. */
export function parseAllow(input: unknown): string[] {
  const out = new Set<string>();
  for (const part of String(input ?? "").split(/[\s,]+/).filter(Boolean)) {
    const c = cidr(part);
    if (!c) throw new Error(`not an IP address or network: ${part} (e.g. 203.0.113.7 or 203.0.113.0/24)`);
    out.add(c);
  }
  if (out.size > 64) throw new Error("at most 64 networks");
  return [...out];
}

export const remoteUrl = (u: { user: string; database: string }, password: string, domain: string) =>
  `postgres://${u.user}:${password}@${domain}:${PG_REMOTE_PORT}/${u.database}?sslmode=verify-full`;

// ---- applying ----------------------------------------------------------------

/** The address PostgreSQL listens on for remote clients: the one the default route leaves from (behind 1:1 NAT, the private one). */
async function localIp(): Promise<string> {
  const r = await run(["ip", "-4", "route", "get", "1.1.1.1"], { check: false });
  return r.stdout.match(/\bsrc (\S+)/)?.[1] ?? "";
}

function paths() {
  const p = pgPaths();
  if (!p) throw new Error("remote access works with a PostgreSQL that pano installed (Services → PostgreSQL → Install)");
  return p;
}

/** Copies the edge's certificate where only postgres can read it. null: none yet; else whether it changed. */
async function copyCert(domain: string): Promise<boolean | null> {
  const p = paths();
  const c = await edgeCert(domain);
  if (!c) return null;
  const same = (await readText(`${p.tlsDir}/server.crt`)) === c.cert && (await readText(`${p.tlsDir}/server.key`)) === c.key;
  if (same) return false;
  await ensureDir(p.tlsDir, 0o700, "postgres");
  await writeAtomic(`${p.tlsDir}/server.crt`, c.cert, 0o600, "postgres");
  await writeAtomic(`${p.tlsDir}/server.key`, c.key, 0o600, "postgres");
  return true;
}

/**
 * Writes postgresql settings and pg_hba from the saved state. Listening beyond localhost only
 * with a certificate in place (else PostgreSQL would not start). A changed address needs a
 * restart; users, networks and renewed certificates only a reload.
 */
async function apply() {
  const p = paths();
  const c = pgRemoteConfig();
  const ip = c.on ? await localIp() : "";
  const tls = c.on && ip && (await exists(`${p.tlsDir}/server.crt`)) && (await exists(`${p.tlsDir}/server.key`));
  const conf = pgConf(tls ? { listen: [ip], cert: `${p.tlsDir}/server.crt`, key: `${p.tlsDir}/server.key` } : undefined);
  const before = (await readText(p.conf)) ?? "";
  await writeAtomic(p.conf, conf, p.confMode, p.confOwner);

  const hbaFile = (await psql("SHOW hba_file;"))[0]?.[0] ?? "";
  if (!hbaFile.endsWith("pg_hba.conf")) throw new Error("PostgreSQL did not say where pg_hba.conf is");
  const hba = await readText(hbaFile);
  if (hba === null) throw new Error(`cannot read ${hbaFile}`);
  const next = mergeHba(hba, tls ? renderHbaBlock(users(), c.allow) : []);
  if (next !== hba) await writeAtomic(hbaFile, next, p.confOwner ? 0o600 : 0o640, "postgres");

  const listen = (s: string) => s.match(/^listen_addresses = .*$/m)?.[0] ?? "";
  const ssl = (s: string) => s.includes("\nssl = on");
  if (listen(before) !== listen(conf) || ssl(before) !== ssl(conf)) await restartPg(p.unit);
  else await psql("SELECT pg_reload_conf();");
  // pg_reload_conf only signals; a bad pg_hba is reported in pg_hba_file_rules.
  const bad = await psql("SELECT line_number, error FROM pg_hba_file_rules WHERE error IS NOT NULL;").catch(() => [] as string[][]);
  if (bad.length) throw new Error(`pg_hba.conf line ${bad[0]![0]}: ${bad[0]![1]}`);
  return { listening: !!tls, ip };
}

async function restartPg(unit: string) {
  await run(["systemctl", "restart", unit], { check: false, timeoutMs: 120_000 });
  for (let i = 0; i < 60; i++) {
    if (await psql("SELECT 1;").then(() => true, () => false)) return;
    await Bun.sleep(500);
  }
  const log = (await run(["journalctl", "-u", unit, "-n", "5", "--no-pager"], { check: false })).stdout.trim();
  throw new Error(`PostgreSQL did not come back: ${log.split("\n").at(-1) ?? ""}`);
}

const firewalld = async () => (await run(["firewall-cmd", "--state"], { check: false })).stdout.trim() === "running";

/** firewalld (EL): the port for everyone, or one rich rule per allowed network; what was added is remembered and taken back exactly. */
async function syncFirewalld() {
  const c = pgRemoteConfig();
  const want = !c.on
    ? []
    : !c.allow.length
      ? [`--add-port=${PG_REMOTE_PORT}/tcp`]
      : c.allow.map((n) => `--add-rich-rule=rule family="${n.includes(":") ? "ipv6" : "ipv4"}" source address="${n}" port port="${PG_REMOTE_PORT}" protocol="tcp" accept`);
  const had: string[] = JSON.parse(settings.get("pg.remote.firewalld") || "[]");
  if (!(await firewalld())) {
    settings.set("pg.remote.firewalld", "[]");
    return;
  }
  if (JSON.stringify(had) === JSON.stringify(want)) return;
  for (const a of had) if (!want.includes(a)) await run(["firewall-cmd", "--permanent", a.replace(/^--add-/, "--remove-")], { check: false });
  for (const a of want) if (!had.includes(a)) await run(["firewall-cmd", "--permanent", a]);
  await run(["firewall-cmd", "--reload"], { check: false });
  settings.set("pg.remote.firewalld", JSON.stringify(want));
}

/** Every firewall pano knows about follows the saved state. */
async function syncNetwork() {
  await syncFirewalld();
  await followFirewall();
  await followVpn();
}

// ---- operations --------------------------------------------------------------

export async function status() {
  const c = pgRemoteConfig();
  const p = pgPaths();
  const ip = c.on ? await localIp() : "";
  const listening = c.on && !!ip && (await run(["ss", "-Htln", `sport = :${PG_REMOTE_PORT}`], { check: false })).stdout.includes(`${ip}:`);
  return { available: !!p, on: c.on, domain: c.domain, allow: c.allow, port: PG_REMOTE_PORT, ip, listening, connLimit: REMOTE_CONN_LIMIT, users: users() };
}

/**
 * Turns remote access on, or changes its name or networks while on. Needs the edge (it gets the
 * certificate) and a DNS-only record for the name pointing here. Anything failing puts the
 * previous state back.
 */
export async function enable(input: { domain?: unknown; allow?: unknown }, actor: string) {
  paths();
  const domain = String(input.domain ?? "").trim().toLowerCase();
  if (!DOMAIN.test(domain)) throw new Error("domain: a name of its own for the database, e.g. db.example.com");
  const allow = parseAllow(input.allow);
  if (!(await edgeInstalled())) throw new Error("remote access uses the edge's certificate: install the edge first");
  const previous = pgRemoteConfig();
  saveConfig({ on: true, domain, allow });
  try {
    await applyEdge();
    let got = false;
    for (let i = 0; i < 45 && !got; i++) {
      got = (await copyCert(domain)) !== null;
      if (!got) await Bun.sleep(2000);
    }
    if (!got) throw new Error(`no certificate for ${domain} yet: its DNS record must point to this server (DNS only, no proxy) and ports 80/443 must reach the edge`);
    const r = await apply();
    if (!r.listening) throw new Error("no IPv4 address to listen on");
    await syncNetwork();
  } catch (e) {
    saveConfig(previous);
    await apply().catch(() => {});
    await syncNetwork().catch(() => {});
    await applyEdge().catch(() => {});
    throw e;
  }
  audit(actor, "pg.remote.enable", { domain, allow });
  return status();
}

/** Back to localhost only. Remote users stay (without a way in) and work again when it is turned on. */
export async function disable(actor: string) {
  const p = paths();
  const c = pgRemoteConfig();
  saveConfig({ ...c, on: false });
  await apply();
  await syncNetwork();
  await remove(p.tlsDir);
  await applyEdge().catch(() => {});
  audit(actor, "pg.remote.disable", {});
}

/** A remote user for one database; the URL (with the password) is returned once and not stored. */
export async function addUser(input: { database?: unknown }, actor: string) {
  const c = pgRemoteConfig();
  if (!c.on) throw new Error("turn remote access on first");
  const database = pgName(input.database);
  if (RESERVED_PG.has(database)) throw new Error("reserved database");
  if (!(await pgOwner(database))) throw new Error(`no PostgreSQL database ${database}`);
  const tag = createHash("sha1").update(`${database}:${Date.now()}:${randomPassword(8)}`).digest("hex").slice(0, 6);
  const user = `${database.slice(0, 40)}_remote_${tag}`;
  const password = randomPassword(40);
  await psql(`CREATE ROLE ${pgIdent(user)} LOGIN PASSWORD ${pgLit(password)} CONNECTION LIMIT ${REMOTE_CONN_LIMIT};`);
  const access = await pgGrantAccess(database, user);
  saveUsers([...users(), { user, database, created_at: Date.now() }]);
  await apply();
  audit(actor, "pg.remote.user.add", { user, database, access });
  return { user, database, access, url: remoteUrl({ user, database }, password, c.domain) };
}

/** Takes the remote user away: its sessions end, what it created goes to the database's owner. */
export async function removeUser(input: { user?: unknown }, actor: string) {
  const name = String(input.user ?? "");
  const u = users().find((x) => x.user === name);
  if (!u) throw new Error("no such remote user");
  saveUsers(users().filter((x) => x.user !== name));
  await apply();
  await dropRole(u);
  audit(actor, "pg.remote.user.remove", { user: u.user, database: u.database });
}

async function dropRole(u: RemoteUser) {
  const role = pgIdent(pgName(u.user));
  await psql(`ALTER ROLE ${role} NOLOGIN;\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ${pgLit(u.user)};`).catch(() => {});
  const owner = await pgOwner(u.database).catch(() => null);
  if (owner) await psql(`REASSIGN OWNED BY ${role} TO ${pgIdent(owner.name)};\nDROP OWNED BY ${role};`, u.database);
  await psql(`DROP ROLE IF EXISTS ${role};`);
}

/** A dropped database takes its remote users with it. */
export async function forgetDatabase(database: string, actor: string) {
  const gone = users().filter((u) => u.database === database);
  if (!gone.length) return;
  saveUsers(users().filter((u) => u.database !== database));
  await apply();
  for (const u of gone) await dropRole(u).catch(() => {});
  audit(actor, "pg.remote.user.remove", { database, users: gone.map((u) => u.user) });
}

/**
 * From the agent's timer: PostgreSQL reads its certificate at start and on reload, so the edge's
 * renewals are copied over; a changed address or a restored server (recovery) is set up again.
 */
export async function renew() {
  const c = pgRemoteConfig();
  if (!c.on || !pgPaths()) return;
  const changed = await copyCert(c.domain);
  if (changed === null) return;
  const conf = (await readText(pgPaths()!.conf)) ?? "";
  const ip = await localIp();
  if (!changed && ip && conf.includes(`'localhost, ${ip}'`)) return;
  await apply();
  await syncNetwork();
}
