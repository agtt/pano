// Imports cPanel accounts from their full backup (cpmove-<user>.tar.gz from
// /scripts/pkgacct or "Download a Full Account Backup"), copied by the admin
// into /var/lib/pano/imports. Each domain becomes a pano PHP site, databases
// and their users come back with the original password hashes (so existing
// config files keep working), and everything pano does not host is listed.
//
// The archive is unpacked as an unprivileged user, dumps are loaded by a
// MariaDB user that can only reach the one new database, and nothing that
// already exists on this server (site, database, user) is ever overwritten.

import { lstat, readdir, realpath, stat } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import { PHP_VERSIONS, v } from "../shared/validate.ts";
import { assertDomainsFree } from "./apps.ts";
import { applyEdge, ensureUser } from "./edge.ts";
import { scanHtaccess } from "./htaccess.ts";
import { grantDb, ident, listDatabases, listUsers, lit, sql } from "./mysql.ts";
import { createPhpSite, fixPermissions, siteHome, unitName as phpUnit } from "./php.ts";
import { apps, audit, sites } from "./state.ts";
import { ensureDir, exists, randomPassword, readText, remove, run, writeAtomic } from "./sys.ts";

const WORK = `${paths.imports}/work`;
const IMPORT_USER = "pano-import";
const ARCHIVE = /^[A-Za-z0-9._-]+\.(tar\.gz|tgz|tar)$/;
/** PHP for sites whose cPanel version was "inherit" (server default). */
const INHERIT_PHP = "8.4";
// cPanel's service subdomains are not sites.
const SERVICE_HOST = /^(mail|cpanel|webmail|webdisk|whm|cpcalendars|cpcontacts|autodiscover|autoconfig)\./;
const PRIVILEGES = new Set([
  "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "INDEX", "ALTER", "CREATE TEMPORARY TABLES", "LOCK TABLES",
  "EXECUTE", "CREATE VIEW", "SHOW VIEW", "CREATE ROUTINE", "ALTER ROUTINE", "EVENT", "TRIGGER", "REFERENCES", "ALL PRIVILEGES",
]);

export type CpSite = { name: string; domains: string[]; docroot: string; php: string; exists: boolean; warnings: string[] };
export type CpDb = { name: string; bytes: number; exists: boolean };
export type CpUser = { user: string; hashOk: boolean; dbs: Record<string, string[]>; exists: boolean };
export type CpPlan = {
  archive: string;
  account: string;
  mainDomain: string;
  sites: CpSite[];
  databases: CpDb[];
  users: CpUser[];
  notMigrated: string[];
  warnings: string[];
};

export async function listArchives(): Promise<{ file: string; bytes: number }[]> {
  await ensureDir(paths.imports, 0o711);
  const out: { file: string; bytes: number }[] = [];
  for (const f of await readdir(fsPath(paths.imports))) {
    if (!ARCHIVE.test(f)) continue;
    const st = await stat(fsPath(`${paths.imports}/${f}`));
    if (st.isFile()) out.push({ file: f, bytes: st.size });
  }
  return out;
}

/** Unpacks once per archive version, as an unprivileged user, and returns the account directory. */
async function extract(file: string): Promise<string> {
  if (!ARCHIVE.test(file)) throw new Error("invalid archive name");
  const src = `${paths.imports}/${file}`;
  const st = await stat(fsPath(src)).catch(() => null);
  if (!st?.isFile()) throw new Error(`${src} not found`);
  const dir = `${WORK}/${file.replace(/\.(tar\.gz|tgz|tar)$/, "")}-${Math.floor(st.mtimeMs)}`;
  if (!(await exists(`${dir}/.pano-done`))) {
    await ensureUser(IMPORT_USER, WORK);
    await ensureDir(WORK, 0o711);
    await remove(dir); // an interrupted earlier unpack of this same archive
    await ensureDir(dir, 0o700, IMPORT_USER);
    const z = /\.t?gz$/.test(file) ? ["-z"] : [];
    // The agent opens the archive and streams it in, so the import user needs no access to it,
    // and whatever the archive contains can only land inside its own directory.
    await run(["tar", "-x", ...z, "-f", "-", "-C", fsPath(dir), "--no-same-owner", "--no-same-permissions"], {
      user: IMPORT_USER, inputFile: fsPath(src), timeoutMs: 3 * 3600_000,
    });
    const root = await accountRoot(dir);
    if ((await insideArchive(root, `${root}/homedir.tar`)) && !(await exists(`${root}/homedir`))) {
      await run(["mkdir", fsPath(`${root}/homedir`)], { user: IMPORT_USER });
      await run(["tar", "-x", "-f", "-", "-C", fsPath(`${root}/homedir`), "--no-same-owner", "--no-same-permissions"], {
        user: IMPORT_USER, inputFile: fsPath(`${root}/homedir.tar`), timeoutMs: 3 * 3600_000,
      });
    }
    await writeAtomic(`${dir}/.pano-done`, "", 0o600);
  }
  return accountRoot(dir);
}

async function accountRoot(dir: string): Promise<string> {
  if (await exists(`${dir}/userdata/main`)) return dir;
  for (const e of await readdir(fsPath(dir), { withFileTypes: true })) {
    if (e.isDirectory() && (await exists(`${dir}/${e.name}/userdata/main`))) return `${dir}/${e.name}`;
  }
  throw new Error("userdata/main not found: is this a cPanel cpmove / full backup archive?");
}

const yaml = (text: string | null): any => (text ? Bun.YAML.parse(text) : null);

/** True when p is a regular file (or a directory, with dir) really inside base: the archive may hold symlinks to anywhere. */
async function insideArchive(base: string, p: string, dir = false): Promise<boolean> {
  try {
    if ((await lstat(fsPath(base))).isSymbolicLink()) return false;
    const st = await lstat(fsPath(p));
    if (st.isSymbolicLink() || (dir ? !st.isDirectory() : !st.isFile())) return false;
    const [b, real] = await Promise.all([realpath(fsPath(base)), realpath(fsPath(p))]);
    return real === b || real.startsWith(`${b}/`);
  } catch {
    return false;
  }
}

/** Reads a file of the unpacked archive as root, refusing symlinks and anything outside it. */
async function readArchive(root: string, p: string): Promise<string | null> {
  return (await insideArchive(root, p)) ? readText(p) : null;
}

const safeName = (s: unknown): s is string => typeof s === "string" && /^[A-Za-z0-9._-]{1,253}$/.test(s) && !s.includes("..");

function phpFrom(raw: unknown, warnings: string[], domain: string): string {
  const m = String(raw ?? "").match(/php(\d)(\d)$/);
  if (!m) return INHERIT_PHP;
  const ver = `${m[1]}.${m[2]}`;
  if (PHP_VERSIONS.includes(ver)) return ver;
  warnings.push(`${domain}: PHP ${ver} is not available; using 7.4 (end of life) — test the site and upgrade`);
  return "7.4";
}

function hostList(...lists: unknown[]): string[] {
  const out = new Set<string>();
  for (const l of lists) {
    for (const h of Array.isArray(l) ? l : String(l ?? "").split(/\s+/)) {
      const d = String(h).trim().toLowerCase();
      if (!d || SERVICE_HOST.test(d)) continue;
      try {
        out.add(v.domain(d));
      } catch {}
    }
  }
  return [...out];
}

export type GrantInfo = { users: Map<string, { hash: string }>; grants: { user: string; db: string; privs: string[] }[] };

/** Reads mysql.sql from the archive. Only localhost accounts and per-database grants are kept. */
export function parseGrants(text: string): GrantInfo {
  const Q = "[`'\"]";
  const createUser = new RegExp(`^CREATE USER (?:IF NOT EXISTS )?${Q}([^\`'"]+)${Q}@${Q}([^\`'"]+)${Q} IDENTIFIED (?:WITH ${Q}?\\w+${Q}? AS|BY PASSWORD) '([^']*)'`, "i");
  const grant = new RegExp(`^GRANT (.+?) ON (\\*|${Q}[^\`'"]+${Q})\\.\\* TO ${Q}([^\`'"]+)${Q}@${Q}([^\`'"]+)${Q}(?: IDENTIFIED BY PASSWORD '([^']*)')?`, "i");
  const users = new Map<string, { hash: string }>();
  const grants: GrantInfo["grants"] = [];
  for (const raw of text.split(/;\s*(?:\r?\n|$)/)) {
    const stmt = raw.replace(/\s+/g, " ").trim();
    const cu = stmt.match(createUser);
    if (cu) {
      if (cu[2] === "localhost") users.set(cu[1]!, { hash: cu[3]! });
      continue;
    }
    const g = stmt.match(grant);
    if (!g || g[4] !== "localhost") continue;
    const [, privList, target, user, , hash] = g;
    if (hash || !users.has(user!)) users.set(user!, { hash: hash || users.get(user!)?.hash || "" });
    if (target === "*") continue; // global grants (USAGE) only carry the password
    const db = target!.slice(1, -1);
    const privs = privList!.toUpperCase().split(",").map((p) => p.trim()).map((p) => (p === "ALL" ? "ALL PRIVILEGES" : p)).filter((p) => PRIVILEGES.has(p));
    if (privs.length) grants.push({ user: user!, db, privs });
  }
  return { users, grants };
}

/** Grant targets may be patterns ("user\_%"): does a database name fall under one? */
export function grantMatches(pattern: string, db: string): boolean {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "\\" && i + 1 < pattern.length) re += pattern[++i]!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    else if (c === "%") re += ".*";
    else if (c === "_") re += ".";
    else re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`).test(db);
}

export async function scanArchive(file: string): Promise<CpPlan> {
  const root = await extract(file);
  const warnings: string[] = [];
  const notMigrated: string[] = [];
  const main = yaml(await readArchive(root, `${root}/userdata/main`));
  if (!safeName(main?.main_domain)) throw new Error("userdata/main has no valid main_domain");
  const mainUd = yaml(await readArchive(root, `${root}/userdata/${main.main_domain}`)) ?? {};
  const account = String(mainUd.user ?? (await readdir(fsPath(`${root}/cp`)).catch(() => [] as string[]))[0] ?? "");
  const homedir = String(mainUd.homedir ?? `/home/${account}`).replace(/\/+$/, "");

  // ---- sites: main domain (+ parked), addon domains, plain subdomains
  const addon = (main.addon_domains ?? {}) as Record<string, string>;
  const addonSubs = new Set(Object.values(addon));
  const entries: { domain: string; userdata: string; extra: string[] }[] = [
    { domain: main.main_domain, userdata: main.main_domain, extra: (main.parked_domains ?? []).flatMap((p: string) => [p, `www.${p}`]) },
    ...Object.entries(addon).map(([d, sub]) => ({ domain: d, userdata: sub, extra: [d, `www.${d}`] })),
    ...((main.sub_domains ?? []) as string[]).filter((s) => !addonSubs.has(s)).map((s) => ({ domain: s, userdata: s, extra: [] })),
  ];
  const result: CpSite[] = [];
  for (const e of entries) {
    if (!safeName(e.domain) || !safeName(e.userdata)) {
      warnings.push(`${String(e.domain).slice(0, 80)}: invalid domain name, skipped`);
      continue;
    }
    const ud = yaml(await readArchive(root, `${root}/userdata/${e.userdata}`));
    if (!ud?.documentroot) {
      warnings.push(`${e.domain}: no userdata, skipped`);
      continue;
    }
    const docroot = String(ud.documentroot).replace(/\/+$/, "");
    if ((docroot !== homedir && !docroot.startsWith(`${homedir}/`)) || docroot.split("/").includes("..")) {
      warnings.push(`${e.domain}: document root ${docroot} is outside the home directory, skipped`);
      continue;
    }
    const inArchive = `${root}/homedir${docroot.slice(homedir.length)}`;
    if (!(await insideArchive(`${root}/homedir`, inArchive, true))) {
      warnings.push(`${e.domain}: ${docroot} is not in the archive, skipped`);
      continue;
    }
    const internal = addonSubs.has(e.userdata) ? e.userdata : "";
    const domains = hostList([e.domain], ud.serveralias, e.extra).filter((d) => d !== internal && d !== `www.${internal}`);
    const name = v.siteName(e.domain);
    const siteWarnings = (await scanHtaccess(inArchive)).warnings;
    const refs = await run(
      ["grep", "-rlIF", "--include=*.php", "--include=*.ini", "--include=.htaccess", "-e", `${homedir}/`, fsPath(inArchive)],
      { check: false, timeoutMs: 300_000 },
    );
    const n = refs.stdout.split("\n").filter(Boolean).length;
    if (n) siteWarnings.push(`${n} file(s) contain the old path ${homedir}/ — the new document root is ${siteHome(name)}/public`);
    result.push({ name, domains, docroot: inArchive, php: phpFrom(ud.phpversion, warnings, e.domain), exists: !!sites.get(name), warnings: siteWarnings });
  }

  // ---- databases and users
  const existingDbs = new Set((await listDatabases()).map((d) => d.name));
  const existingUsers = new Set((await listUsers()).filter((u) => u.host === "localhost").map((u) => u.user));
  const databases: CpDb[] = [];
  for (const f of (await readdir(fsPath(`${root}/mysql`)).catch(() => [] as string[])).sort()) {
    if (!f.endsWith(".sql")) continue;
    const name = f.slice(0, -4);
    if (!/^[A-Za-z0-9_]{1,64}$/.test(name) || !(await insideArchive(root, `${root}/mysql/${f}`))) {
      warnings.push(`database ${name.slice(0, 80)}: unusual name or not a regular file, skipped`);
      continue;
    }
    databases.push({ name, bytes: (await stat(fsPath(`${root}/mysql/${f}`))).size, exists: existingDbs.has(name) });
  }
  const { users: userMap, grants } = parseGrants((await readArchive(root, `${root}/mysql.sql`)) ?? "");
  const users: CpUser[] = [];
  for (const [user, { hash }] of userMap) {
    if (!/^[A-Za-z0-9_]{1,32}$/.test(user) || user === account) continue; // the cPanel login itself has no use here
    const dbs: Record<string, string[]> = {};
    for (const g of grants.filter((x) => x.user === user)) {
      for (const d of databases.filter((x) => grantMatches(g.db, x.name))) dbs[d.name] = [...new Set([...(dbs[d.name] ?? []), ...g.privs])];
    }
    if (!Object.keys(dbs).length) continue;
    const hashOk = /^\*[0-9A-F]{40}$/.test(hash);
    if (!hashOk) warnings.push(`database user ${user}: password hash cannot be used by MariaDB; a new password will be generated`);
    users.push({ user, hashOk, dbs, exists: existingUsers.has(user) });
  }
  for (const d of databases.filter((x) => x.exists)) warnings.push(`database ${d.name} already exists here and will not be touched`);
  for (const u of users.filter((x) => x.exists)) warnings.push(`database user ${u.user} already exists here; it will not be changed or granted access`);

  // ---- what pano does not migrate
  const mailboxes = await run(["find", fsPath(`${root}/homedir/mail`), "-mindepth", "2", "-maxdepth", "2", "-type", "d", "-not", "-name", ".*"], { check: false });
  const boxes = mailboxes.stdout.split("\n").filter(Boolean).length;
  if (boxes) notMigrated.push(`${boxes} mailbox(es): pano does not host mail; move mail to a mail provider and update MX records`);
  const cron = ((safeName(account) ? await readArchive(root, `${root}/cron/${account}`) : null) ?? "").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !/^[A-Z_]+=/.test(l));
  if (cron.length) notMigrated.push(`${cron.length} cron job(s), recreate them as needed:\n${cron.slice(0, 20).join("\n")}`);
  const zones = (await readdir(fsPath(`${root}/dnszones`)).catch(() => [] as string[])).filter((z) => z.endsWith(".db")).map((z) => z.slice(0, -3));
  if (zones.length) notMigrated.push(`DNS zones (${zones.join(", ")}): point the A/AAAA records to this server when the sites are ready`);
  const ftp = ((await readArchive(root, `${root}/proftpdpasswd`)) ?? "").split("\n").filter(Boolean).length;
  if (ftp) notMigrated.push(`${ftp} FTP account(s): use SFTP instead`);
  notMigrated.push("SSL certificates: issued again automatically by the edge once DNS points here");

  return { archive: file, account, mainDomain: main.main_domain, sites: result, databases, users, notMigrated, warnings };
}

// ---- apply -------------------------------------------------------------------

/** One dump line, made loadable by an unprivileged user on MariaDB. Data rows pass through untouched. */
export function cleanDumpLine(line: string): string | null {
  if (line.startsWith("INSERT INTO")) return line;
  // Replication/GTID settings need SUPER and are meaningless on a fresh database.
  if (/^(\/\*!\d+ )?SET @@(GLOBAL|SESSION)\.(GTID_PURGED|SQL_LOG_BIN)\s*=/i.test(line)) return null;
  return line
    .replace(/DEFINER\s*=\s*(`[^`]*`|'[^']*'|\w+)@(`[^`]*`|'[^']*'|[\w.%-]+)\s*/gi, "")
    .replace(/\butf8mb4_0900_\w+/g, "utf8mb4_unicode_520_ci")
    .replace(/\/\*!80\d{3}\s[^*]*\*\/\s?/g, "");
}

async function mysqlSocket(): Promise<string> {
  const r = await run(["my_print_defaults", "--mysqld"], { check: false });
  return r.stdout.match(/--socket=(\S+)/)?.[1] ?? "/var/lib/mysql/mysql.sock";
}

/** Streams a dump into one database as the given user (whose only rights are on that database). */
async function loadDump(dumpFile: string, db: string, user: string, password: string) {
  await ensureDir(`${paths.data}/tmp`, 0o700);
  const cnf = `${paths.data}/tmp/import-${user}.cnf`;
  // --defaults-file: nothing else (e.g. /root/.my.cnf) can swap in root's credentials.
  await writeAtomic(cnf, `[client]\nuser=${user}\npassword=${password}\nsocket=${await mysqlSocket()}\n`, 0o600);
  try {
    // --binary-mode: a line like "\! cmd" or "source file" in the dump is data, not a client command run as root.
    const proc = Bun.spawn(["mysql", `--defaults-file=${fsPath(cnf)}`, "--batch", "--binary-mode", db], { stdin: "pipe", stdout: "ignore", stderr: "pipe" });
    const errText = new Response(proc.stderr).text();
    let pending = "";
    const push = async (lines: string[]) => {
      const out = lines.map(cleanDumpLine).filter((l): l is string => l !== null);
      if (out.length) proc.stdin.write(Buffer.from(out.join("\n") + "\n", "latin1"));
      await proc.stdin.flush();
    };
    // latin1 keeps every byte as is (dumps may contain binary data); the rewrites only touch ASCII.
    for await (const chunk of Bun.file(fsPath(dumpFile)).stream()) {
      pending += Buffer.from(chunk).toString("latin1");
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      await push(lines);
    }
    if (pending) await push([pending]);
    await proc.stdin.end();
    const code = await proc.exited;
    if (code !== 0) throw new Error(`loading ${db} failed: ${(await errText).trim().split("\n").slice(-2).join(" ")}`);
  } finally {
    await remove(cnf);
  }
}

export type CpApplyReport = { sites: string[]; databases: string[]; users: { user: string; password?: string }[]; warnings: string[] };

export async function applyArchive(file: string, select: { sites: string[]; databases: string[] }, actor: string): Promise<CpApplyReport> {
  const plan = await scanArchive(file); // never trust a plan sent by the browser
  const root = await extract(file);
  const report: CpApplyReport = { sites: [], databases: [], users: [], warnings: [] };

  // Databases first: each is loaded by its real owner (so views/triggers keep a valid definer),
  // created with a temporary password and full rights on that one database only.
  const created = new Map<string, string>(); // user -> temporary password
  const tempUsers: string[] = [];
  for (const db of plan.databases.filter((d) => select.databases.includes(d.name) && !d.exists)) {
    await sql(`CREATE DATABASE ${ident(db.name)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
    const owner = plan.users.find((u) => !u.exists && u.dbs[db.name]);
    let user = owner?.user;
    if (!user) {
      user = `pano_imp_${randomPassword(8).toLowerCase()}`;
      tempUsers.push(user);
      report.warnings.push(`${db.name}: no database user in the archive; views/triggers may need their definer fixed`);
    }
    if (!created.has(user)) {
      const pw = randomPassword();
      await sql(`CREATE USER ${lit(user)}@'localhost' IDENTIFIED BY ${lit(pw)};`);
      created.set(user, pw);
    }
    await sql(`GRANT ALL PRIVILEGES ON ${grantDb(db.name)}.* TO ${lit(user)}@'localhost';`);
    try {
      if (!(await insideArchive(root, `${root}/mysql/${db.name}.sql`))) throw new Error(`${db.name}: dump is not a regular file in the archive`);
      await loadDump(`${root}/mysql/${db.name}.sql`, db.name, user, created.get(user)!);
      report.databases.push(db.name);
    } catch (e) {
      report.warnings.push(e instanceof Error ? e.message : String(e));
    }
    // Back to exactly what cPanel granted.
    await sql(`REVOKE ALL PRIVILEGES ON ${grantDb(db.name)}.* FROM ${lit(user)}@'localhost';`);
  }
  for (const u of tempUsers) await sql(`DROP USER IF EXISTS ${lit(u)}@'localhost';`);

  const imported = new Set(report.databases);
  for (const u of plan.users.filter((x) => !x.exists)) {
    const dbs = Object.entries(u.dbs).filter(([d]) => imported.has(d));
    if (!dbs.length) continue;
    if (!created.has(u.user)) {
      const pw = randomPassword();
      await sql(`CREATE USER ${lit(u.user)}@'localhost' IDENTIFIED BY ${lit(pw)};`);
      created.set(u.user, pw);
    }
    for (const [d, privs] of dbs) await sql(`GRANT ${privs.join(", ")} ON ${grantDb(d)}.* TO ${lit(u.user)}@'localhost';`);
    const hash = u.hashOk ? parseGrants((await readArchive(root, `${root}/mysql.sql`)) ?? "").users.get(u.user)?.hash : "";
    if (hash) {
      await sql(`ALTER USER ${lit(u.user)}@'localhost' IDENTIFIED BY PASSWORD ${lit(hash)};`);
      report.users.push({ user: u.user });
    } else {
      report.users.push({ user: u.user, password: created.get(u.user) });
    }
  }
  if (created.size) await sql("FLUSH PRIVILEGES;");

  // Sites: a PHP site per domain, files copied from the archive, .htaccess deny rules kept.
  const all = { apps: apps.list(), sites: sites.list() };
  for (const s of plan.sites.filter((x) => select.sites.includes(x.name) && !x.exists)) {
    try {
      assertDomainsFree(s.domains, {}, all);
      if (!(await insideArchive(`${root}/homedir`, s.docroot, true))) throw new Error("document root leaves the archive");
      await createPhpSite({ name: s.name, domains: s.domains, version: s.php, source: "cpanel", placeholder: false }, actor);
      const home = siteHome(s.name);
      // No PHP runs while root copies: the archive's own code, already copied and called through the
      // edge, could otherwise swap a directory for a link and have cp write through it.
      await run(["systemctl", "stop", phpUnit(s.name)]);
      await run(["cp", "-a", "--", `${fsPath(s.docroot)}/.`, fsPath(`${home}/public/`)], { timeoutMs: 3_600_000 });
      report.warnings.push(...(await fixPermissions(s.name)).map((w) => `${s.name}: ${w}`));
      await run(["systemctl", "start", phpUnit(s.name)]);
      const ht = await scanHtaccess(`${home}/public`);
      sites.upsert({ ...sites.get(s.name)!, deny_paths: ht.denyPaths });
      report.warnings.push(...s.warnings.map((w) => `${s.name}: ${w}`));
      report.sites.push(s.name);
    } catch (e) {
      report.warnings.push(`${s.name}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  await applyEdge();
  audit(actor, "import.cpanel", { archive: file, sites: report.sites, databases: report.databases, users: report.users.map((u) => u.user) });
  return report;
}
