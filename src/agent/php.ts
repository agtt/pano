// PHP sites without OpenLiteSpeed and without a shared PHP. Each site gets its
// own system user and its own PHP-FPM master running as that user (never root)
// in a hardened systemd unit, with a socket only the edge may open. PHP itself
// (Remi packages on AlmaLinux/Rocky, Sury's on Debian/Ubuntu; one install per
// minor version, see php-os.ts) is installed the first time
// a site needs that version, and pm=ondemand keeps an idle site at one small
// process: nothing PHP runs on the server unless a PHP site exists.

import { readdir, readlink, realpath, rename, unlink } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import { DEFAULT_PHP, PHP_VERSIONS, v } from "../shared/validate.ts";
import { ensureJob } from "./backup.ts";
import { EDGE_USER, applyEdge, ensureUser, phpSocket } from "./edge.ts";
import { scanHtaccess } from "./htaccess.ts";
import {
  ONDREJ_FINGERPRINT, ONDREJ_KEYRING, ONDREJ_KEY_URL, ONDREJ_SOURCES, SURY_KEYRING, SURY_KEYRING_DEB, SURY_LIST,
  assertSupported, cliFor, currentOs, debOptionalPackages, debRequiredPackages, debShimRoot, distroFpmUnit, elPackages, fpmBinFor,
  gpgFingerprints, installedDebPackages, mysqlSocketFor, ondrejSources, phpRootFor, suryList, type PhpOs,
} from "./php-os.ts";
import { audit, sites, type Site } from "./state.ts";
import { ensureDir, exists, remove, run, showUnits, writeAtomic } from "./sys.ts";

const scl = (ver: string) => `php${ver.replace(".", "")}`;
export const phpRoot = (ver: string) => phpRootFor(currentOs(), ver);
const fpmBin = (ver: string) => fpmBinFor(currentOs(), ver);
export const phpCli = (ver: string) => cliFor(currentOs(), ver);
export const siteUser = (name: string) => `site-${name.replace(/[^a-z0-9]/g, "-").slice(0, 27)}`;
export const siteHome = (name: string) => `${paths.sites}/${name}`;
export const unitName = (name: string) => `pano-php-${name}.service`;
export const confDir = (name: string) => `${paths.phpEtc}/${name}`;

// ---- PHP versions ------------------------------------------------------------

export async function installedPhp(): Promise<string[]> {
  const out: string[] = [];
  for (const ver of PHP_VERSIONS) if (await exists(fpmBin(ver))) out.push(ver);
  return out;
}

const APT_ENV = { DEBIAN_FRONTEND: "noninteractive", NEEDRESTART_MODE: "a" };
const APT_OPTS = ["-y", "-o", "Dpkg::Options::=--force-confold"];
const LONG = { timeoutMs: 1_800_000 };

/**
 * Surý's repository with a signed keyring under /usr/share/keyrings (no apt-key).
 * Debian: his keyring package + sources.list entry; Ubuntu: ppa:ondrej/php as a
 * deb822 source whose key is checked against a pinned fingerprint. Idempotent,
 * and left alone when the admin already added the repository themselves.
 */
async function ensureDebRepo(os: PhpOs) {
  const ubuntu = os.id === "ubuntu";
  const have = async (needle: string) =>
    (await run(["grep", "-rqs", needle, "/etc/apt/sources.list", "/etc/apt/sources.list.d"], { check: false })).code === 0;
  if (await have(ubuntu ? "ondrej/php" : "packages.sury.org")) return;
  await run(["apt-get", "update", "-qq"], { env: APT_ENV, check: false, ...LONG });
  await run(["apt-get", "install", ...APT_OPTS, "--no-install-recommends", "ca-certificates", "curl", "gnupg"], { env: APT_ENV, ...LONG });
  const tmp = (await run(["mktemp", "-d"])).stdout.trim();
  try {
    if (ubuntu) {
      const armored = `${tmp}/ondrej.asc`;
      await run(["curl", "-fsSL", "--max-time", "60", "-o", armored, ONDREJ_KEY_URL]);
      const fprs = gpgFingerprints((await run(["gpg", "--show-keys", "--with-colons", armored])).stdout);
      if (!fprs.includes(ONDREJ_FINGERPRINT)) throw new Error(`ppa:ondrej/php signing key has an unexpected fingerprint (${fprs.join(", ") || "none"}); not trusting it`);
      await run(["gpg", "--batch", "--yes", "--dearmor", "-o", fsPath(ONDREJ_KEYRING), armored]);
      await run(["chmod", "0644", fsPath(ONDREJ_KEYRING)]);
      await writeAtomic(ONDREJ_SOURCES, ondrejSources(os.codename), 0o644);
    } else {
      const deb = `${tmp}/keyring.deb`;
      await run(["curl", "-fsSL", "--max-time", "60", "-o", deb, SURY_KEYRING_DEB]);
      await run(["dpkg", "-i", deb], { env: APT_ENV });
      if (!(await exists(SURY_KEYRING))) throw new Error(`${SURY_KEYRING} is missing after installing the Sury keyring package`);
      await writeAtomic(SURY_LIST, suryList(os.codename), 0o644);
    }
  } finally {
    await run(["rm", "-rf", "--", tmp], { check: false });
  }
  await run(["apt-get", "update", "-qq"], { env: APT_ENV, ...LONG });
}

/** Debian: `php` for this minor in a directory cron jobs can put on PATH. */
async function ensureCliShim(ver: string) {
  const bin = `${debShimRoot(ver)}/usr/bin`;
  await ensureDir(bin, 0o755);
  await run(["ln", "-sfn", cliFor(currentOs(), ver), `${fsPath(bin)}/php`]);
}

async function installPhpDeb(ver: string, os: PhpOs) {
  await ensureDebRepo(os);
  // Masked before the package lands, so its postinst never starts the server-wide pool.
  await run(["systemctl", "mask", `${distroFpmUnit(os, ver)}.service`], { check: false });
  await run(["apt-get", "install", ...APT_OPTS, "--no-install-recommends", "acl", ...debRequiredPackages(ver)], { env: APT_ENV, ...LONG });
  // One by one: an extension that does not exist for this version (built in, or not built yet) is skipped.
  for (const pkg of debOptionalPackages(ver)) {
    await run(["apt-get", "install", ...APT_OPTS, "--no-install-recommends", pkg], { env: APT_ENV, check: false, ...LONG });
  }
}

export async function installPhp(ver: string, actor: string) {
  v.phpVersion(ver);
  const os = currentOs();
  if (await exists(fpmBin(ver))) {
    if (os.family === "debian") await ensureCliShim(ver);
    return;
  }
  assertSupported(os);
  if (os.family === "debian") await installPhpDeb(ver, os);
  else {
    // remi-release brings Remi's signing keys; every PHP package after it is GPG-checked by dnf.
    if (!(await exists("/etc/yum.repos.d/remi-safe.repo"))) {
      await run(["dnf", "-y", "install", "epel-release"], { timeoutMs: 900_000, check: false });
      await run(["dnf", "-y", "install", `https://rpms.remirepo.net/enterprise/remi-release-${os.version.split(".")[0]}.rpm`], { timeoutMs: 900_000 });
    }
    // strict=0: an extension that does not exist for this version (built in) is skipped, not fatal.
    await run(["dnf", "-y", "--setopt=strict=0", "install", "acl", ...elPackages(ver)], { timeoutMs: 1_800_000 });
  }
  if (!(await exists(fpmBin(ver)))) throw new Error(`PHP ${ver} did not install: ${fpmBin(ver)} is missing`);
  // The distribution ships a server-wide php-fpm service; pano runs one pool per site instead.
  await run(["systemctl", "disable", "--now", distroFpmUnit(os, ver)], { check: false });
  if (os.family === "debian") {
    await run(["systemctl", "mask", `${distroFpmUnit(os, ver)}.service`], { check: false });
    await ensureCliShim(ver);
  }
  audit(actor, "php.install", { version: ver });
}

/** Installed phpX.Y-* packages on a Debian-family system. */
async function debPackages(ver: string): Promise<string[]> {
  const r = await run(["dpkg-query", "-W", "-f", "${Package} ${db:Status-Abbrev}\\n", `php${ver}-*`], { check: false });
  return installedDebPackages(r.stdout, ver);
}

/** Patch releases of the installed minors (vulns.ts). Pools move to the new binary via reloadUpdatedPhp. */
export async function upgradePhpPackages(minors: string[]): Promise<{ code: number; stderr: string }> {
  if (currentOs().family === "el") {
    return run(["dnf", "-y", "-q", "update", ...minors.map((m) => `${scl(m)}-*`)], { check: false, timeoutMs: 900_000 });
  }
  const pkgs = (await Promise.all(minors.map(debPackages))).flat();
  if (!pkgs.length) return { code: 0, stderr: "" };
  await run(["apt-get", "update", "-qq"], { env: APT_ENV, check: false, timeoutMs: 600_000 });
  return run(["apt-get", "install", ...APT_OPTS, "--only-upgrade", ...pkgs], { env: APT_ENV, check: false, timeoutMs: 900_000 });
}

export async function uninstallPhp(ver: string, actor: string) {
  v.phpVersion(ver);
  const users = sites.list().filter((s) => s.kind === "php" && s.php_version === ver);
  if (users.length) throw new Error(`PHP ${ver} is used by ${users.map((s) => s.name).join(", ")}`);
  const os = currentOs();
  if (os.family === "debian") {
    const pkgs = await debPackages(ver);
    if (pkgs.length) await run(["apt-get", "remove", ...APT_OPTS, ...pkgs], { env: APT_ENV, timeoutMs: 900_000 });
    await run(["systemctl", "unmask", `${distroFpmUnit(os, ver)}.service`], { check: false });
    await remove(debShimRoot(ver));
  } else {
    await run(["dnf", "-y", "remove", `${scl(ver)}-*`], { timeoutMs: 900_000 });
  }
  audit(actor, "php.uninstall", { version: ver });
}

// ---- configuration -------------------------------------------------------------

export function renderPhpIni(name: string): string {
  const home = siteHome(name);
  return `; Managed by pano. Per-site overrides: .user.ini in the site (system settings below cannot be loosened there).
[PHP]
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = ${home}/logs/php-error.log
error_reporting = E_ALL & ~E_DEPRECATED
memory_limit = 256M
max_execution_time = 60
max_input_time = 60
max_input_vars = 3000
post_max_size = 64M
upload_max_filesize = 64M
max_file_uploads = 20
upload_tmp_dir = ${home}/tmp
sys_temp_dir = ${home}/tmp
open_basedir = ${home}/
allow_url_fopen = On
allow_url_include = Off
enable_dl = Off
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,pcntl_fork,dl,show_source,posix_kill,posix_setuid,posix_setgid,posix_setsid,posix_mkfifo
cgi.fix_pathinfo = 0
default_charset = "UTF-8"
date.timezone = UTC
mail.add_x_header = Off
; PCRE and opcache JIT need writable+executable memory, which the unit forbids.
pcre.jit = 0

[Session]
session.save_path = "${home}/sessions"
session.use_strict_mode = 1
session.use_only_cookies = 1
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Lax
session.gc_probability = 1
session.gc_divisor = 100

realpath_cache_size = 4096K
realpath_cache_ttl = 600

[opcache]
opcache.enable = 1
; Shared by the site's workers; pages only count once they are used.
opcache.memory_consumption = 128
opcache.interned_strings_buffer = 16
opcache.max_accelerated_files = 20000
opcache.validate_timestamps = 1
opcache.revalidate_freq = 2
opcache.jit = disable
opcache.jit_buffer_size = 0
opcache.restrict_api = ${home}/

[MySQL]
mysqli.default_socket = ${mysqlSocketFor(currentOs())}
pdo_mysql.default_socket = ${mysqlSocketFor(currentOs())}
`;
}

export function renderFpmConf(name: string): string {
  const home = siteHome(name);
  return `; Managed by pano. The master runs as the site user, so there is no user/group switch.
[global]
error_log = ${home}/logs/fpm.log
log_level = notice
daemonize = no

[site]
listen = ${phpSocket(name)}
listen.mode = 0660
; Only the edge (and the site user) may connect.
listen.acl_users = ${EDGE_USER}
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 60s
pm.max_requests = 1000
request_terminate_timeout = 300s
security.limit_extensions = .php
clear_env = yes
catch_workers_output = yes
decorate_workers_output = no
`;
}

/** Hardening shared by a site's PHP-FPM and its cron jobs. */
export const phpSandbox = (name: string) => `UMask=0027
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${siteHome(name)}
InaccessiblePaths=-${paths.secrets} -${paths.data} -${paths.apps}
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# The cloud's metadata service (instance credentials, user-data) like for apps.
IPAddressDeny=169.254.169.254/32
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
`;

export function renderPhpUnit(name: string, ver: string): string {
  const user = siteUser(name);
  const conf = confDir(name);
  return `[Unit]
Description=pano PHP ${ver} for site ${name}
After=network.target mariadb.service

[Service]
Type=notify
User=${user}
Group=${user}
ExecStart=${fpmBin(ver)} --nodaemonize --fpm-config ${conf}/php-fpm.conf --php-ini ${conf}/php.ini
ExecReload=/bin/kill -USR2 $MAINPID
RuntimeDirectory=pano-php/${name}
RuntimeDirectoryMode=0711
Restart=on-failure
RestartSec=2
MemoryHigh=896M
MemoryMax=1024M
TasksMax=256
${phpSandbox(name)}
[Install]
WantedBy=multi-user.target
`;
}

// ---- sites -------------------------------------------------------------------

function mustGet(name: string): Site {
  const s = sites.get(v.siteName(name));
  if (!s) throw new Error(`no site named ${name}`);
  return s;
}

function assertUserFree(name: string) {
  const other = sites.list().find((s) => s.kind === "php" && s.name !== name && siteUser(s.name) === siteUser(name));
  if (other) throw new Error(`${name} would share the system user ${siteUser(name)} with ${other.name}; pick another name`);
}

/** User, directories, configs and unit for a site; idempotent. */
async function provision(name: string, ver: string) {
  const user = siteUser(name);
  const home = siteHome(name);
  await ensureUser(EDGE_USER, paths.edgeData);
  await ensureUser(user, home);
  await ensureDir(paths.sites, 0o755);
  // root:<user>: PHP can write in public/, tmp/... but cannot swap them for symlinks root would follow.
  await ensureDir(home, 0o750);
  await run(["chown", "-h", `root:${user}`, fsPath(home)]);
  await ensureDir(`${home}/public`, 0o750, user);
  for (const d of ["tmp", "sessions", "logs"]) await ensureDir(`${home}/${d}`, 0o700, user);
  await ensureDir(paths.phpEtc, 0o755);
  await ensureDir(confDir(name), 0o755);
  await writeAtomic(`${confDir(name)}/php.ini`, renderPhpIni(name), 0o644);
  await writeAtomic(`${confDir(name)}/php-fpm.conf`, renderFpmConf(name), 0o644);
  await writeAtomic(`${paths.systemd}/${unitName(name)}`, renderPhpUnit(name, ver), 0o644);
  await edgeAccess(name);
  // SELinux (if enforcing): label site files as web content.
  if ((await run(["getenforce"], { check: false })).stdout.trim() === "Enforcing") {
    await run(["semanage", "fcontext", "-a", "-t", "httpd_sys_rw_content_t", `${paths.sites}(/.*)?`], { check: false });
    await run(["restorecon", "-R", fsPath(home)], { check: false });
  }
  await run(["systemctl", "daemon-reload"]);
}

/** The edge serves static files itself: it may enter the site dir and read public/, including files PHP creates later. */
async function edgeAccess(name: string) {
  const home = fsPath(siteHome(name));
  await run(["setfacl", "-m", `u:${EDGE_USER}:x`, home]);
  await run(["setfacl", "-P", "-R", "-m", `u:${EDGE_USER}:rX`, `${home}/public`]);
  await run(["find", `${home}/public`, "-type", "d", "-exec", "setfacl", "-d", "-m", `u:${EDGE_USER}:rX`, "{}", "+"]);
}

/**
 * Owner, modes and ACLs after files were copied in. Symlinks that lead outside
 * the site are removed (they would expose other files to PHP or the edge).
 */
export async function fixPermissions(name: string): Promise<string[]> {
  const home = siteHome(name);
  const user = siteUser(name);
  const warnings: string[] = [];
  const links = await run(["find", fsPath(home), "-type", "l"], { check: false });
  const base = await realpath(fsPath(home));
  for (const link of links.stdout.split("\n").filter(Boolean)) {
    const target = await realpath(link).catch(() => "");
    if (target === base || target.startsWith(base + "/")) continue;
    await unlink(link);
    warnings.push(`removed symlink ${link.slice(fsPath(home).length)} (pointed outside the site)`);
  }
  await run(["chown", "-R", "--no-dereference", `${user}:${user}`, fsPath(home)]);
  // As the site's user: the site's PHP may run meanwhile and swap a path for a link, and then chmod
  // reaches only what that user owns anyway.
  await run(["find", fsPath(home), "-type", "d", "-exec", "chmod", "0750", "{}", "+"], { user, check: false });
  await run(["find", fsPath(home), "-type", "f", "-exec", "chmod", "0640", "{}", "+"], { user, check: false });
  // find never follows a symlinked start point: no chmod of whatever such a link points at.
  await run(["find", ...["tmp", "sessions", "logs"].map((d) => fsPath(`${home}/${d}`)), "-maxdepth", "0", "-type", "d", "-exec", "chmod", "0700", "{}", "+"], { user, check: false });
  await run(["chown", "-h", `root:${user}`, fsPath(home)]);
  await edgeAccess(name);
  return warnings;
}

export type PhpSiteInput = { name: string; domains: string[]; version: string; source?: Site["source"]; placeholder?: boolean };

export async function createPhpSite(input: PhpSiteInput, actor: string) {
  const name = v.siteName(input.name);
  const ver = v.phpVersion(input.version || DEFAULT_PHP);
  if (sites.get(name)) throw new Error(`site ${name} already exists`);
  assertUserFree(name);
  await installPhp(ver, actor);
  await provision(name, ver);
  const home = siteHome(name);
  if (input.placeholder !== false && !(await readdir(fsPath(`${home}/public`))).length) {
    await writeAtomic(`${home}/public/index.php`, "<?php\nhttp_response_code(200);\necho 'Site is ready. Upload your files to public/.';\n", 0o640, siteUser(name));
  }
  sites.upsert({
    name, kind: "php", domains: input.domains, root: `${home}/public`, routes: [], ask_url: "", php_version: ver,
    tls_cert: "", tls_key: "", source: input.source ?? "pano", enabled: 1, on_demand_tls: 0,
  });
  await run(["systemctl", "enable", "--now", unitName(name)]);
  await applyEdge();
  ensureJob("path", `${home}/public`, actor);
  audit(actor, "php.site.create", { name, version: ver, domains: input.domains });
  return { name, root: `${home}/public`, user: siteUser(name) };
}

/** Recovery on a new server: PHP, the site's user, pool and unit from the restored state (files come from its backup). */
export async function reprovisionSite(site: Site, actor: string) {
  await installPhp(site.php_version, actor);
  await provision(site.name, site.php_version);
}

/** After its files are back: owners and ACLs, then the pool if the site is on. */
export async function startRestoredSite(site: Site) {
  await fixPermissions(site.name);
  if (site.enabled) await run(["systemctl", "enable", "--now", unitName(site.name)], { check: false });
}

export async function setPhpVersion(name: string, version: string, actor: string) {
  const site = mustGet(name);
  if (site.kind !== "php") throw new Error("not a PHP site");
  const ver = v.phpVersion(version);
  await installPhp(ver, actor);
  await provision(site.name, ver);
  sites.upsert({ ...site, php_version: ver });
  if (site.enabled) await run(["systemctl", "restart", unitName(site.name)]);
  audit(actor, "php.site.version", { name: site.name, from: site.php_version, to: ver });
}

/** Disabled PHP sites stop their pool too, so they cost no memory. */
export async function setPhpEnabled(site: Site, enabled: boolean) {
  await run(["systemctl", enabled ? "enable" : "disable", "--now", unitName(site.name)], { check: false });
}

export async function deletePhpSite(site: Site, removeFiles: boolean) {
  await run(["systemctl", "disable", "--now", unitName(site.name)], { check: false });
  await remove(`${paths.systemd}/${unitName(site.name)}`);
  await remove(confDir(site.name));
  await run(["systemctl", "daemon-reload"], { check: false });
  if (removeFiles && !site.converted_from) {
    await remove(siteHome(site.name));
    await run(["userdel", siteUser(site.name)], { check: false });
  }
}

/**
 * Moves a site that OpenLiteSpeed served onto pano's PHP. The files are copied
 * (the original directory is never touched), .htaccess deny rules become edge
 * rules, and the site can be switched back with revertConvert.
 */
export async function convertLegacy(name: string, version: string, actor: string): Promise<{ warnings: string[] }> {
  const site = mustGet(name);
  if (site.kind !== "legacy") throw new Error("only legacy (OpenLiteSpeed) sites can be converted");
  if (!site.root || !(await exists(site.root))) throw new Error(`document root ${site.root || "(none)"} not found`);
  const ver = v.phpVersion(version || site.php_version || DEFAULT_PHP);
  assertUserFree(site.name);
  await installPhp(ver, actor);
  const home = siteHome(site.name);
  // A previous conversion's copy is kept aside, never overwritten.
  if ((await exists(`${home}/public`)) && (await readdir(fsPath(`${home}/public`))).length) {
    await rename(fsPath(`${home}/public`), fsPath(`${home}/public.${Date.now()}`));
  }
  await provision(site.name, ver);
  await run(["cp", "-a", "--", `${fsPath(site.root)}/.`, fsPath(`${home}/public/`)], { timeoutMs: 3_600_000 });
  const warnings = await fixPermissions(site.name);
  const ht = await scanHtaccess(`${home}/public`);
  warnings.push(...ht.warnings);
  sites.upsert({
    ...site,
    kind: "php",
    root: `${home}/public`,
    php_version: ver,
    deny_paths: ht.denyPaths,
    converted_from: { kind: site.kind, root: site.root, php_version: site.php_version },
  });
  if (site.enabled) await run(["systemctl", "enable", "--now", unitName(site.name)]);
  await applyEdge();
  audit(actor, "php.site.convert", { name: site.name, version: ver, deny: ht.denyPaths, warnings: warnings.length });
  return { warnings };
}

/** Back to OpenLiteSpeed. The PHP copy stays on disk; changes made there are not copied back. */
export async function revertConvert(name: string, actor: string) {
  const site = mustGet(name);
  if (site.kind !== "php" || !site.converted_from) throw new Error("this site was not converted from OpenLiteSpeed");
  await run(["systemctl", "disable", "--now", unitName(site.name)], { check: false });
  const from = site.converted_from;
  sites.upsert({ ...site, kind: from.kind, root: from.root, php_version: from.php_version, deny_paths: [], converted_from: null });
  await applyEdge();
  audit(actor, "php.site.revert", { name: site.name });
}

export async function phpLogs(name: string): Promise<string> {
  const site = mustGet(name);
  if (site.kind !== "php") return "";
  const out: string[] = [];
  for (const f of ["fpm.log", "php-error.log"]) {
    // As the site user: logs/ is the site's, a symlink there must not read root's files.
    const r = await run(["tail", "-n", "100", fsPath(`${siteHome(site.name)}/logs/${f}`)], { check: false, user: siteUser(site.name) });
    if (r.stdout.trim()) out.push(`== ${f}\n${r.stdout}`);
  }
  return out.join("\n");
}

/** Reloads pools whose php-fpm binary was replaced by a package update (same minor, new patch release). */
export async function reloadUpdatedPhp() {
  // One systemctl for all pools; the binary is read from /proc without a process per site.
  const units = sites.list().filter((x) => x.kind === "php" && x.enabled).map((s) => unitName(s.name));
  const shown = await showUnits(units, ["MainPID"]);
  for (const unit of units) {
    const pid = shown.get(unit)?.MainPID;
    if (!pid || pid === "0") continue;
    const exe = await readlink(`/proc/${pid}/exe`).catch(() => "");
    if (exe.endsWith("(deleted)")) await run(["systemctl", "reload", unit], { check: false });
  }
}
