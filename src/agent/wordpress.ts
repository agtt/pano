// WordPress tools for pano PHP sites, through wp-cli. The phar is downloaded
// from the official GitHub release, checked against the sha512 published next
// to it and kept in a root-owned directory. Every wp-cli run is the site's own
// system user running the site's PHP in the site's directory, never root
// following paths the site controls. Passwords never go on a command line
// (visible to other users in `ps`): they travel in a 0600 wp-cli config file in
// the site's tmp/ that exists only for the length of the command.

import { readdir, stat } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import { v } from "../shared/validate.ts";
import { notify } from "./alerts.ts";
import { createDatabase, listDatabases } from "./mysql.ts";
import { DISABLED_FUNCTIONS, confDir, fixPermissions, phpCli, phpSandbox, siteHome, siteUser } from "./php.ts";
import { audit, settings, sites, type Site } from "./state.ts";
import { currentOs, mysqlSocketFor } from "./php-os.ts";
import { ensureDir, exists, randomPassword, randomToken, readText, remove, run, writeAtomic } from "./sys.ts";

export const WP_PHAR = `${paths.bin}/wp-cli.phar`;
const RELEASE_API = "https://api.github.com/repos/wp-cli/wp-cli/releases/latest";
const MAX_PHAR = 30 * 1024 * 1024;
const REFRESH_MS = 45 * 24 * 3600_000;
const SLUG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
/** Where MariaDB listens on this OS (Remi/EL vs Debian/Ubuntu). */
const mysqlSocket = () => mysqlSocketFor(currentOs());

// ---- pure helpers (tested) -----------------------------------------------------

/** The phar and its sha512 file from a GitHub "latest release" document. */
export function pickWpCliAssets(release: any): { phar: string; sha512: string } {
  const assets: { name: string; browser_download_url: string }[] = Array.isArray(release?.assets) ? release.assets : [];
  const phar = assets.find((a) => /^wp-cli-[0-9][0-9.]*\.phar$/.test(a.name));
  const sum = phar && assets.find((a) => a.name === `${phar.name}.sha512`);
  if (!phar || !sum) throw new Error("wp-cli release has no phar with a published sha512");
  for (const a of [phar, sum]) if (!a.browser_download_url.startsWith("https://github.com/wp-cli/wp-cli/releases/download/")) throw new Error("unexpected wp-cli download URL");
  return { phar: phar.browser_download_url, sha512: sum.browser_download_url };
}

/** The hash out of a `.sha512` file ("<hash>" or "<hash>  <file>"). */
export function parseSha512(text: string): string {
  const m = text.trim().match(/^([0-9a-fA-F]{128})(\s|$)/);
  if (!m) throw new Error("unreadable sha512 file");
  return m[1]!.toLowerCase();
}

/** wp-cli prints PHP notices or "Success:" lines around JSON; take the JSON. */
export function parseWpJson<T>(out: string, fallback: T): T {
  const lines = out.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!.trimStart();
    if (!l.startsWith("[") && !l.startsWith("{")) continue;
    try {
      return JSON.parse(lines.slice(i).join("\n")) as T;
    } catch {
      continue;
    }
  }
  return fallback;
}

export type Extension = { name: string; title: string; status: string; version: string; update: string };

/** `plugin list` / `theme list` JSON (--fields=name,title,status,version,update_version). */
export function parseExtensions(out: string): Extension[] {
  const rows = parseWpJson<any[]>(out, []);
  if (!Array.isArray(rows)) return [];
  return rows
    .filter((r) => r && typeof r.name === "string")
    .map((r) => ({
      name: r.name,
      title: String(r.title || r.name),
      status: String(r.status ?? ""),
      version: String(r.version ?? ""),
      update: r.update_version ? String(r.update_version) : "",
    }));
}

export type CoreUpdate = { version: string; type: string };

/** `core check-update --format=json`: a list, or nothing when WordPress is current. */
export function parseCoreUpdates(out: string): CoreUpdate[] {
  const rows = parseWpJson<any[]>(out, []);
  if (!Array.isArray(rows)) return [];
  return rows.filter((r) => r && r.version).map((r) => ({ version: String(r.version), type: String(r.update_type ?? "") }));
}

export type WpAdmin = { id: number; login: string; email: string };

export function parseAdmins(out: string): WpAdmin[] {
  const rows = parseWpJson<any[]>(out, []);
  if (!Array.isArray(rows)) return [];
  return rows
    .filter((r) => r && Number.isInteger(Number(r.ID)) && typeof r.user_login === "string")
    .map((r) => ({ id: Number(r.ID), login: r.user_login, email: String(r.user_email ?? "") }));
}

/** `maintenance-mode status` prints "Maintenance mode is active." / "... is not active." */
export const parseMaintenance = (out: string) => /is active/i.test(out) && !/not active/i.test(out);

/**
 * wp-cli argv: the site's PHP, the phar, then the arguments and the globals. wp-cli runs the site's
 * code (wp-config.php, wp-cli.yml), so it gets the site's own php.ini like its PHP-FPM: open_basedir
 * (no symlink() to pano's keys or another site) and disable_functions. The CLI's conf.d still loads the
 * extensions. Only the phar is added to open_basedir. `launch`: wp-cli may start processes (proc_open);
 * only `core download` needs it (it unpacks with tar), and only on an empty site.
 */
export function wpCommand(ver: string, home: string, args: string[], o: { launch?: boolean } = {}): string[] {
  const name = home.slice(home.lastIndexOf("/") + 1);
  return [
    phpCli(ver),
    "-c", `${confDir(name)}/php.ini`,
    "-d", `open_basedir=${home}/:${WP_PHAR}`,
    ...(o.launch ? ["-d", `disable_functions=${DISABLED_FUNCTIONS.filter((f) => f !== "proc_open").join(",")}`] : []),
    "-d", "memory_limit=512M",
    "-d", "max_execution_time=0",
    "-d", "display_errors=0",
    "-d", `sys_temp_dir=${home}/tmp`,
    "-d", `mysqli.default_socket=${mysqlSocket()}`,
    "-d", `pdo_mysql.default_socket=${mysqlSocket()}`,
    WP_PHAR,
    ...args,
    `--path=${home}/public`,
    "--skip-plugins",
    "--skip-themes",
    "--no-color",
  ];
}

export const wpEnv = (ver: string, home: string): Record<string, string> => ({
  HOME: `${home}/tmp`,
  TMPDIR: `${home}/tmp`,
  WP_CLI_CACHE_DIR: `${home}/tmp/wp-cli-cache`,
  WP_CLI_PHP: phpCli(ver),
  WP_CLI_DISABLE_AUTO_CHECK_UPDATE: "1",
  // Not the defaults under HOME (the site's tmp/): a config there can `require:` PHP files and a packages
  // dir is autoloaded, which would run before any check. wp() points the config at its own file when it has one.
  WP_CLI_CONFIG_PATH: "/dev/null",
  WP_CLI_PACKAGES_DIR: `${paths.bin}/wp-cli-packages`,
});

/** wp-cli config file with per-command defaults: how a password reaches wp-cli without argv. */
export function secretsYaml(cmds: Record<string, Record<string, string>>): string {
  return (
    Object.entries(cmds)
      .map(([cmd, kv]) => `${cmd}:\n${Object.entries(kv).map(([k, val]) => `  ${k}: ${JSON.stringify(val)}`).join("\n")}`)
      .join("\n") + "\n"
  );
}

/** `plugin update` arguments for "all" or a list of slugs. */
export function updateArgs(kind: "plugin" | "theme", which: string[] | "all"): string[] {
  if (which === "all") return [kind, "update", "--all"];
  if (!Array.isArray(which)) throw new Error(`bad ${kind} selection`);
  const slugs = which.map((s) => {
    if (!SLUG.test(s)) throw new Error(`invalid ${kind} name: ${s}`);
    return s;
  });
  if (!slugs.length) throw new Error(`no ${kind} selected`);
  return [kind, "update", ...slugs];
}

export function validateInstall(input: Record<string, unknown>): { title: string; adminUser: string; adminEmail: string } {
  const title = String(input.title ?? "").replace(/[\x00-\x1f\x7f]/g, "").trim();
  if (!title || title.length > 100) throw new Error("site title: 1-100 characters");
  const adminUser = String(input.adminUser ?? "").trim();
  if (!/^[A-Za-z0-9_.-]{3,60}$/.test(adminUser)) throw new Error("admin user: 3-60 letters, digits, dot, dash, underscore");
  const adminEmail = String(input.adminEmail ?? "").trim();
  if (adminEmail.length > 120 || !/^[^\s@,;<>"'\\]+@[^\s@,;<>"'\\]+\.[^\s@,;<>"'\\]+$/.test(adminEmail)) throw new Error("admin email looks invalid");
  return { title, adminUser, adminEmail };
}

/** Database and user names for a site: wp_<site>, numbered if taken. */
export function dbNameFor(site: string, taken: Set<string>): string {
  const base = `wp_${site.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 22)}`;
  let n = base;
  for (let i = 2; taken.has(n); i++) n = `${base.slice(0, 26)}_${i}`;
  return n;
}

// ---- wp-cli binary --------------------------------------------------------------

async function download(url: string): Promise<Uint8Array> {
  const res = await fetch(url, { headers: { "user-agent": "pano" }, redirect: "follow", signal: AbortSignal.timeout(120_000) });
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length > MAX_PHAR) throw new Error("download too large");
  return buf;
}

/** Downloads wp-cli from its latest GitHub release and installs it only if the published sha512 matches. */
export async function installWpCli(actor = "system") {
  const rel = await fetch(RELEASE_API, { headers: { "user-agent": "pano", accept: "application/vnd.github+json" }, signal: AbortSignal.timeout(30_000) });
  if (!rel.ok) throw new Error(`wp-cli release lookup: ${rel.status}`);
  const urls = pickWpCliAssets(await rel.json());
  const [phar, sum] = await Promise.all([download(urls.phar), download(urls.sha512)]);
  const want = parseSha512(new TextDecoder().decode(sum));
  const got = new Bun.CryptoHasher("sha512").update(phar).digest("hex");
  if (got !== want) throw new Error("wp-cli checksum mismatch, not installed");
  if (!new TextDecoder().decode(phar.subarray(0, 2)).startsWith("#!")) throw new Error("wp-cli download is not a phar");
  await ensureDir(paths.bin, 0o755);
  await writeAtomic(WP_PHAR, phar, 0o644);
  audit(actor, "wp.cli.install", { url: urls.phar, sha512: got.slice(0, 16) });
}

/** The phar is there and not stale; a failed refresh keeps the old one. */
export async function ensureWpCli() {
  const st = await stat(fsPath(WP_PHAR)).catch(() => null);
  if (st && Date.now() - st.mtimeMs < REFRESH_MS) return;
  try {
    await installWpCli();
  } catch (e) {
    if (!st) throw e;
    console.error(`[agent] wp-cli refresh: ${e}`);
  }
}

// ---- running it -----------------------------------------------------------------

function phpSite(name: unknown): Site {
  const site = sites.get(v.siteName(name));
  if (!site) throw new Error(`no site named ${name}`);
  if (site.kind !== "php") throw new Error("WordPress tools are for pano PHP sites");
  return site;
}

/** wp-cli loads the site's wp-config.php and plugins, i.e. runs its code: never for a suspended site. */
export function assertSiteRuns(site: Pick<Site, "name" | "enabled">) {
  if (!site.enabled) throw new Error(`${site.name} is suspended: resume it before you run WordPress tools`);
}

/** A PHP site whose code may run now (not suspended). */
function runnableSite(name: unknown): Site {
  const site = phpSite(name);
  assertSiteRuns(site);
  return site;
}

type WpOpts = { secrets?: Record<string, Record<string, string>>; timeoutMs?: number; check?: boolean; launch?: boolean };

/**
 * wp-cli loads the site's own code (wp-config.php, plugins), so it runs in the same sandbox as the
 * site's PHP-FPM: a transient unit as the site user, not a bare runuser outside it.
 */
export function wpSandboxed(name: string, user: string, home: string, env: Record<string, string>, cmd: string[]): string[] {
  const props = phpSandbox(name).split("\n").filter((l) => l && !l.startsWith("#"));
  return [
    "systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
    `--uid=${user}`, `--gid=${user}`, `--working-directory=${home}/public`,
    ...props.flatMap((p) => ["-p", p]),
    ...Object.entries(env).map(([k, val]) => `--setenv=${k}=${val}`),
    "--", ...cmd,
  ];
}

async function wp(site: Site, args: string[], o: WpOpts = {}) {
  assertSiteRuns(site);
  const home = siteHome(site.name);
  const user = siteUser(site.name);
  const env = wpEnv(site.php_version, home);
  let conf = "";
  if (o.secrets) {
    conf = `${home}/tmp/wp-cli-${randomToken(9)}.yml`;
    await writeAtomic(conf, secretsYaml(o.secrets), 0o600, user);
    env.WP_CLI_CONFIG_PATH = conf;
  }
  try {
    return await run(wpSandboxed(site.name, user, home, env, wpCommand(site.php_version, home, args, { launch: o.launch })), { timeoutMs: o.timeoutMs ?? 300_000, check: o.check });
  } finally {
    if (conf) await remove(conf);
  }
}

// ---- state of a site --------------------------------------------------------------

const PLACEHOLDER = "Site is ready";

export type WpDetect = { installed: boolean; version: string; empty: boolean; auto: boolean };

/** Cheap (no PHP): is WordPress there, or is the site empty enough to install it. */
export async function detect(name: unknown): Promise<WpDetect> {
  const site = phpSite(name);
  const pub = `${siteHome(site.name)}/public`;
  const version = (await readText(`${pub}/wp-includes/version.php`))?.match(/\$wp_version\s*=\s*'([^']+)'/)?.[1] ?? "";
  return { installed: !!version, version, empty: !version && (await emptyForInstall(pub)), auto: settings.get(`wp.auto.${site.name}`) === "1" };
}

async function emptyForInstall(pub: string): Promise<boolean> {
  const files = await readdir(fsPath(pub)).catch(() => null);
  if (!files) return false;
  if (!files.length) return true;
  return files.length === 1 && files[0] === "index.php" && ((await readText(`${pub}/index.php`)) ?? "").includes(PLACEHOLDER);
}

export type WpStatus = {
  version: string;
  coreUpdates: CoreUpdate[];
  plugins: Extension[];
  themes: Extension[];
  maintenance: boolean;
  admins: WpAdmin[];
  auto: boolean;
};

export async function status(name: unknown): Promise<WpStatus> {
  const site = runnableSite(name);
  if (!(await detect(site.name)).installed) throw new Error("WordPress is not installed on this site");
  await ensureWpCli();
  const soft = { check: false };
  const [ver, core, plugins, themes, maint, admins] = await Promise.all([
    wp(site, ["core", "version"]),
    wp(site, ["core", "check-update", "--format=json"], soft),
    wp(site, ["plugin", "list", "--fields=name,title,status,version,update_version", "--format=json"], soft),
    wp(site, ["theme", "list", "--fields=name,title,status,version,update_version", "--format=json"], soft),
    wp(site, ["maintenance-mode", "status"], soft),
    wp(site, ["user", "list", "--role=administrator", "--fields=ID,user_login,user_email", "--format=json"], soft),
  ]);
  return {
    version: ver.stdout.trim().split("\n").at(-1) ?? "",
    coreUpdates: parseCoreUpdates(core.stdout),
    plugins: parseExtensions(plugins.stdout),
    themes: parseExtensions(themes.stdout),
    maintenance: parseMaintenance(maint.stdout),
    admins: parseAdmins(admins.stdout),
    auto: settings.get(`wp.auto.${site.name}`) === "1",
  };
}

// ---- actions ----------------------------------------------------------------------

export async function install(input: Record<string, unknown>, actor: string) {
  const site = runnableSite(input.name);
  const { title, adminUser, adminEmail } = validateInstall(input);
  const domain = site.domains.find((d) => d && !d.includes("*"));
  if (!domain) throw new Error("the site needs a real domain (not a catch-all) to install WordPress");
  const d = await detect(site.name);
  if (!d.empty) throw new Error(d.installed ? "WordPress is already installed" : "the site's public/ folder is not empty");
  await ensureWpCli();

  const taken = new Set((await listDatabases()).map((x) => x.name));
  const dbName = dbNameFor(site.name, taken);
  const db = await createDatabase({ name: dbName, user: dbName.slice(0, 32) }, actor);
  const adminPassword = randomPassword(24);
  const url = `https://${domain}`;

  try {
    // The site was checked empty just above, so no site code is there to use the processes wp-cli may start.
    await wp(site, ["core", "download", "--force"], { timeoutMs: 600_000, launch: true });
    await wp(site, ["config", "create", `--dbname=${db.name}`, `--dbuser=${db.user}`, "--dbhost=localhost"], { secrets: { "config create": { dbpass: db.password } } });
    await wp(site, ["core", "install", `--url=${url}`, `--title=${title}`, `--admin_user=${adminUser}`, `--admin_email=${adminEmail}`, "--skip-email"], {
      secrets: { "core install": { admin_password: adminPassword } },
    });
  } catch (e) {
    throw new Error(`${e instanceof Error ? e.message : e} (database ${db.name} was created and kept; install again to get a new one, or drop it under Databases)`);
  }
  await fixPermissions(site.name);
  audit(actor, "wp.install", { site: site.name, db: db.name, admin: adminUser });
  return { url, adminUrl: `${url}/wp-admin/`, adminUser, adminPassword, dbName: db.name };
}

export type UpdateInput = { name: unknown; core?: boolean; plugins?: string[] | "all"; themes?: string[] | "all" };

export async function update(input: UpdateInput, actor: string): Promise<string[]> {
  const site = runnableSite(input.name);
  if (!input.core && !input.plugins && !input.themes) throw new Error("nothing selected to update");
  await ensureWpCli();
  const steps: string[][] = [];
  if (input.core) steps.push(["core", "update"], ["core", "update-db"]);
  if (input.plugins) steps.push(updateArgs("plugin", input.plugins));
  if (input.themes) steps.push(updateArgs("theme", input.themes));
  const log: string[] = [];
  for (const args of steps) {
    const r = await wp(site, args, { timeoutMs: 600_000 });
    log.push(...r.stdout.split("\n").filter((l) => /^(Success|Warning|Error)/.test(l)));
  }
  audit(actor, "wp.update", { site: site.name, core: !!input.core, plugins: input.plugins ?? null, themes: input.themes ?? null });
  return log;
}

export async function setMaintenance(name: unknown, on: boolean, actor: string) {
  const site = runnableSite(name);
  await ensureWpCli();
  await wp(site, ["maintenance-mode", on ? "activate" : "deactivate"]);
  audit(actor, "wp.maintenance", { site: site.name, on });
}

/** A new password for one administrator; their sessions end. Returned once. */
export async function resetPassword(name: unknown, userId: unknown, actor: string) {
  const site = runnableSite(name);
  const id = v.int(userId, 1, 1e9, "user");
  await ensureWpCli();
  const admins = parseAdmins((await wp(site, ["user", "list", "--role=administrator", "--fields=ID,user_login,user_email", "--format=json"])).stdout);
  const admin = admins.find((a) => a.id === id);
  if (!admin) throw new Error("not an administrator of this site");
  const password = randomPassword(24);
  await wp(site, ["user", "update", String(id)], { secrets: { "user update": { user_pass: password } } });
  await wp(site, ["user", "session", "destroy", String(id), "--all"], { check: false });
  audit(actor, "wp.password.reset", { site: site.name, user: admin.login });
  return { login: admin.login, password };
}

export function setAutoUpdate(name: unknown, on: boolean, actor: string) {
  const site = phpSite(name);
  settings.set(`wp.auto.${site.name}`, on ? "1" : "0");
  audit(actor, "wp.auto", { site: site.name, on });
}

/** Opt-in nightly: minor core releases (security fixes) and all plugins, for sites that turned it on. */
export async function nightlyUpdates() {
  const failed: string[] = [];
  for (const site of sites.list()) {
    // A suspended site's code does not run, not even for updates.
    if (site.kind !== "php" || !site.enabled || settings.get(`wp.auto.${site.name}`) !== "1") continue;
    try {
      if (!(await exists(`${siteHome(site.name)}/public/wp-includes/version.php`))) continue;
      await ensureWpCli();
      await wp(site, ["core", "update", "--minor"], { timeoutMs: 600_000 });
      await wp(site, ["core", "update-db"], { timeoutMs: 600_000 });
      await wp(site, ["plugin", "update", "--all"], { timeoutMs: 600_000 });
      audit("system", "wp.auto.update", { site: site.name });
    } catch (e) {
      failed.push(`${site.name}: ${e instanceof Error ? e.message.slice(0, 120) : e}`);
    }
  }
  if (failed.length) await notify(`🔴 WordPress auto-update failed: ${failed.join("; ")}`);
}
