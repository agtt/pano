// PHP sites without OpenLiteSpeed and without a shared PHP. Each site gets its
// own system user and its own PHP-FPM master running as that user (never root)
// in a hardened systemd unit, with a socket only the edge may open. PHP itself
// (Remi packages, one directory per minor version) is installed the first time
// a site needs that version, and pm=ondemand keeps an idle site at one small
// process: nothing PHP runs on the server unless a PHP site exists.

import { readdir, realpath, rename, unlink } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import { DEFAULT_PHP, PHP_VERSIONS, v } from "../shared/validate.ts";
import { ensureJob } from "./backup.ts";
import { EDGE_USER, applyEdge, ensureUser, phpSocket } from "./edge.ts";
import { scanHtaccess } from "./htaccess.ts";
import { audit, sites, type Site } from "./state.ts";
import { ensureDir, exists, readText, remove, run, writeAtomic } from "./sys.ts";

const scl = (ver: string) => `php${ver.replace(".", "")}`;
export const phpRoot = (ver: string) => `/opt/remi/${scl(ver)}/root`;
const fpmBin = (ver: string) => `${phpRoot(ver)}/usr/sbin/php-fpm`;
export const phpCli = (ver: string) => `${phpRoot(ver)}/usr/bin/php`;
export const siteUser = (name: string) => `site-${name.replace(/[^a-z0-9]/g, "-").slice(0, 27)}`;
export const siteHome = (name: string) => `${paths.sites}/${name}`;
const unitName = (name: string) => `pano-php-${name}.service`;
export const confDir = (name: string) => `${paths.phpEtc}/${name}`;

const EXTENSIONS = ["fpm", "cli", "common", "mysqlnd", "opcache", "gd", "intl", "mbstring", "xml", "sodium", "bcmath", "pecl-zip"];

// ---- PHP versions ------------------------------------------------------------

export async function installedPhp(): Promise<string[]> {
  const out: string[] = [];
  for (const ver of PHP_VERSIONS) if (await exists(fpmBin(ver))) out.push(ver);
  return out;
}

async function elMajor(): Promise<string> {
  const os = (await readText("/etc/os-release")) ?? "";
  const major = os.match(/^VERSION_ID="?(\d+)/m)?.[1] ?? "";
  if (!/^(ID|ID_LIKE)=.*\b(rhel|centos|fedora|almalinux|rocky)\b/m.test(os) || !["8", "9", "10"].includes(major)) {
    throw new Error("PHP sites currently need AlmaLinux, Rocky or RHEL 8-10 (Remi packages)");
  }
  return major;
}

export async function installPhp(ver: string, actor: string) {
  v.phpVersion(ver);
  if (await exists(fpmBin(ver))) return;
  const major = await elMajor();
  // remi-release brings Remi's signing keys; every PHP package after it is GPG-checked by dnf.
  if (!(await exists("/etc/yum.repos.d/remi-safe.repo"))) {
    await run(["dnf", "-y", "install", "epel-release"], { timeoutMs: 900_000, check: false });
    await run(["dnf", "-y", "install", `https://rpms.remirepo.net/enterprise/remi-release-${major}.rpm`], { timeoutMs: 900_000 });
  }
  // strict=0: an extension that does not exist for this version (built in) is skipped, not fatal.
  const pkgs = EXTENSIONS.map((e) => `${scl(ver)}-php-${e}`);
  await run(["dnf", "-y", "--setopt=strict=0", "install", "acl", ...pkgs], { timeoutMs: 1_800_000 });
  if (!(await exists(fpmBin(ver)))) throw new Error(`PHP ${ver} did not install: ${fpmBin(ver)} is missing`);
  // Remi ships a server-wide php-fpm service; pano runs one pool per site instead.
  await run(["systemctl", "disable", "--now", `${scl(ver)}-php-fpm`], { check: false });
  audit(actor, "php.install", { version: ver });
}

export async function uninstallPhp(ver: string, actor: string) {
  v.phpVersion(ver);
  const users = sites.list().filter((s) => s.kind === "php" && s.php_version === ver);
  if (users.length) throw new Error(`PHP ${ver} is used by ${users.map((s) => s.name).join(", ")}`);
  await run(["dnf", "-y", "remove", `${scl(ver)}-*`], { timeoutMs: 900_000 });
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
mysqli.default_socket = /var/lib/mysql/mysql.sock
pdo_mysql.default_socket = /var/lib/mysql/mysql.sock
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
  await run(["find", fsPath(home), "-type", "d", "-exec", "chmod", "0750", "{}", "+"]);
  await run(["find", fsPath(home), "-type", "f", "-exec", "chmod", "0640", "{}", "+"]);
  // find never follows a symlinked start point: no chmod of whatever such a link points at.
  await run(["find", ...["tmp", "sessions", "logs"].map((d) => fsPath(`${home}/${d}`)), "-maxdepth", "0", "-type", "d", "-exec", "chmod", "0700", "{}", "+"], { check: false });
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
  for (const s of sites.list().filter((x) => x.kind === "php" && x.enabled)) {
    const pid = (await run(["systemctl", "show", "-p", "MainPID", "--value", unitName(s.name)], { check: false })).stdout.trim();
    if (!pid || pid === "0") continue;
    const exe = (await run(["readlink", `/proc/${pid}/exe`], { check: false })).stdout.trim();
    if (exe.endsWith("(deleted)")) await run(["systemctl", "reload", unitName(s.name)], { check: false });
  }
}
