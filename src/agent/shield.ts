// Shield: the Imunify-like layer, without a daemon or a license.
//   1. Malware scanner for sites: built-in signatures for PHP webshells, injected
//      code, obfuscation and SEO spam; changed files every hour, everything weekly;
//      quarantine (reversible), ignore, Telegram alert. Optional ClamAV deep scan.
//   2. IP reputation: Spamhaus DROP (hijacked networks) blocked both ways,
//      abuse.ch Feodo (botnet C2) blocked outbound, refreshed daily, in nftables.
//   3. Login brute force: WordPress wp-login.php / xmlrpc.php POST floods found
//      in the edge's access logs; the address gets 429 at the edge for an hour
//      (works behind Cloudflare too, the edge sees the real visitor address).

import { createHash } from "node:crypto";
import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import { isIP } from "node:net";
import { basename, dirname } from "node:path";
import { DRY_RUN, env, fsPath, paths } from "../shared/config.ts";
import { notify } from "./alerts.ts";
import { applyEdge, edgeInstalled, edgeSettings, heldByEdge, refreshEdgeView } from "./edge.ts";
import { appUser } from "./apps.ts";
import { removeOutsideLinks, siteUser } from "./php.ts";
import { apps, audit, settings, sites, state } from "./state.ts";
import { ensureDir, exists, readAs, readText, remove, run, userName, writeAtomic } from "./sys.ts";

// ---- settings ----------------------------------------------------------------------

export type ShieldSettings = { scan: boolean; autoQuarantine: boolean; reputation: boolean; bruteforce: boolean };
const DEFAULTS: ShieldSettings = { scan: false, autoQuarantine: false, reputation: false, bruteforce: false };
export const shieldSettings = (): ShieldSettings => ({ ...DEFAULTS, ...JSON.parse(settings.get("shield") ?? "{}") });

function tables() {
  state().exec(`
    CREATE TABLE IF NOT EXISTS shield_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      path TEXT NOT NULL,
      rule TEXT NOT NULL,
      severity TEXT NOT NULL,
      snippet TEXT NOT NULL DEFAULT '',
      sha256 TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'open',
      quarantine TEXT NOT NULL DEFAULT '',
      owner TEXT NOT NULL DEFAULT '',
      found_at INTEGER NOT NULL,
      UNIQUE(path, rule)
    );
    CREATE TABLE IF NOT EXISTS shield_bans (ip TEXT PRIMARY KEY, until INTEGER NOT NULL, reason TEXT NOT NULL);
  `);
}

export type Finding = { id: number; path: string; rule: string; severity: "malware" | "suspicious"; snippet: string; sha256: string; status: "open" | "quarantined" | "ignored" | "cleaned"; quarantine: string; owner: string; found_at: number };

// ---- signatures ----------------------------------------------------------------------

type Rule = { id: string; severity: Finding["severity"]; files: RegExp; re: RegExp; note: string };
const PHP = /\.(php\d?|phtml|phar|inc)$/i;
const NOT_PHP = /\.(jpe?g|png|gif|ico|svg|webp|txt|css|bmp|pdf|zip)$/i;

export const RULES: Rule[] = [
  { id: "php.shell.known", severity: "malware", files: PHP, note: "known web shell", re: /FilesMan|c99shell|r57shell|\bWSO [0-9.]+|b374k|IndoXploit|AnonymousFox|ALFA_DATA|alfacgiapi|Uname:\s*<|wso_version|\$default_action\s*=\s*['"]FilesMan/i },
  { id: "php.eval.decode", severity: "malware", files: PHP, note: "eval of decoded data", re: /\b(eval|assert)\s*\(\s*(@\s*)?(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uudecode)\s*\(/i },
  { id: "php.exec.input", severity: "malware", files: PHP, note: "runs code or commands straight from the request", re: /\b(eval|assert|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(\s*(@\s*)?(stripslashes\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/i },
  { id: "php.callable.input", severity: "malware", files: PHP, note: "calls a function named by the request", re: /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i },
  { id: "php.preg.e", severity: "malware", files: PHP, note: "preg_replace /e (code execution)", re: /preg_replace\s*\(\s*(['"])([^\w\s\\]).{0,200}?\2[imsxuADSUX]*e[imsxuADSUX]*\1\s*,/ },
  { id: "php.create_function", severity: "malware", files: PHP, note: "create_function from request data", re: /create_function\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/i },
  { id: "php.upload.shell", severity: "malware", files: PHP, note: "uploads arbitrary files", re: /move_uploaded_file\s*\(\s*\$_FILES\[[^\]]+\]\[['"]tmp_name['"]\]\s*,\s*\$_FILES\[[^\]]+\]\[['"]name['"]\]/i },
  { id: "php.in.media", severity: "malware", files: NOT_PHP, note: "PHP code inside a non-PHP file", re: /<\?php|<\?=\s*\$|\beval\s*\(\s*base64_decode/i },
  { id: "htaccess.spam.redirect", severity: "malware", files: /(^|\/)\.htaccess$/, note: "redirects search engine visitors elsewhere (SEO spam)", re: /RewriteCond\s+%\{HTTP_(REFERER|USER_AGENT)\}[^\n]*(google|bing|yahoo|yandex|baidu)[\s\S]{0,300}RewriteRule[^\n]+https?:\/\//i },
  { id: "htaccess.prepend", severity: "suspicious", files: /(^|\/)(\.htaccess|\.user\.ini|php\.ini)$/, note: "prepends a PHP file to every request", re: /auto_(prepend|append)_file/i },
  { id: "php.obfuscated.blob", severity: "suspicious", files: PHP, note: "very long encoded string", re: /['"][A-Za-z0-9+\/=]{3000,}['"]/ },
  { id: "php.obfuscated.chr", severity: "suspicious", files: PHP, note: "string built from many chr() calls", re: /(chr\s*\(\s*\d+\s*\)\s*\.\s*){12,}/i },
  { id: "php.obfuscated.hex", severity: "suspicious", files: PHP, note: "long hex-escaped string", re: /(\\x[0-9a-f]{2}){40,}/i },
  { id: "php.obfuscated.goto", severity: "suspicious", files: PHP, note: "goto-scrambled code", re: /(goto\s+[A-Za-z0-9_]+;\s*[^;]{0,80};\s*){20,}/ },
  { id: "php.mailer.input", severity: "suspicious", files: PHP, note: "sends mail with request data (spam mailer)", re: /\bmail\s*\(\s*\$_(POST|GET|REQUEST)/i },
  { id: "php.in.uploads", severity: "suspicious", files: PHP, note: "PHP file in an uploads directory", re: /^/ },
  { id: "js.injected", severity: "suspicious", files: /\.js$/i, note: "injected/obfuscated script loader", re: /eval\s*\(\s*String\.fromCharCode\(|document\.write\s*\(\s*unescape\s*\(|\bvar\s+_0x[0-9a-f]{4,6}\s*=\s*\[[\s\S]{0,200}\bdocument\.createElement\(\s*['"]script/i },
];

const MAX_BYTES = 3_000_000;
const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "cache", ".cache"]);

/** Checks one file's content; `rel` is its path (for the uploads rule). */
export function matchRules(rel: string, text: string): { rule: Rule; snippet: string }[] {
  const out: { rule: Rule; snippet: string }[] = [];
  for (const rule of RULES) {
    if (!rule.files.test(rel)) continue;
    if (rule.id === "php.in.uploads") {
      if (/\/wp-content\/uploads\//i.test(rel) || /\/uploads?\//i.test(rel)) out.push({ rule, snippet: "" });
      continue;
    }
    const m = rule.re.exec(text);
    if (m) out.push({ rule, snippet: text.slice(Math.max(0, m.index - 40), m.index + 120).replace(/\s+/g, " ") });
  }
  return out;
}

// ---- scanning ------------------------------------------------------------------------

/** Where untrusted files live: every site root and every app's DATA_DIR (uploads). */
function scanRoots(): string[] {
  const roots = new Set<string>();
  for (const s of sites.list()) if (s.root && (s.kind === "php" || s.kind === "legacy" || s.kind === "static")) roots.add(s.root);
  for (const a of apps.list()) if (a.kind === "managed") roots.add(`${paths.apps}/${a.name}/data`);
  return [...roots];
}

let scanning: Promise<unknown> | null = null;
export const scanState = () => ({ running: !!scanning, last: JSON.parse(settings.get("shield.lastScan") ?? "null") as { at: number; full: boolean; files: number; found: number; ms: number } | null });

/** Full scan, or only files changed since the last one. One at a time; returns at once. */
export function startScan(full: boolean, actor: string) {
  if (scanning) throw new Error("a scan is already running");
  audit(actor, "shield.scan", { full });
  scanning = scan(full)
    .catch((e) => console.error(`[agent] shield scan: ${e}`))
    .finally(() => (scanning = null));
}

async function scan(full: boolean) {
  tables();
  const t0 = Date.now();
  const since = full ? 0 : (scanState().last?.at ?? 0);
  let files = 0;
  const found: Finding[] = [];
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > 25) return;
    let entries;
    try {
      entries = await readdir(fsPath(dir), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = `${dir}/${e.name}`;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) await walk(p, depth + 1);
        continue;
      }
      if (!e.isFile() || !RULES.some((r) => r.files.test(p))) continue;
      const st = await stat(fsPath(p)).catch(() => null);
      if (!st || st.size > MAX_BYTES || st.mtimeMs < since) continue;
      files++;
      const buf = await readFile(fsPath(p)).catch(() => null);
      if (!buf) continue;
      const hits = matchRules(p, buf.toString("latin1"));
      if (!hits.length) continue;
      const sha = createHash("sha256").update(buf).digest("hex");
      for (const h of hits) {
        const prev = state().query("SELECT * FROM shield_findings WHERE path = ? AND rule = ?").get(p, h.rule.id) as Finding | null;
        // An ignored finding stays ignored until the file changes.
        if (prev && (prev.status === "ignored" || prev.status === "quarantined") && prev.sha256 === sha) continue;
        state()
          .query(
            `INSERT INTO shield_findings (path, rule, severity, snippet, sha256, status, found_at) VALUES (?, ?, ?, ?, ?, 'open', ?)
             ON CONFLICT(path, rule) DO UPDATE SET severity = excluded.severity, snippet = excluded.snippet, sha256 = excluded.sha256, status = 'open', found_at = excluded.found_at`,
          )
          .run(p, h.rule.id, h.rule.severity, h.snippet.slice(0, 300), sha, Math.floor(Date.now() / 1000));
        found.push(state().query("SELECT * FROM shield_findings WHERE path = ? AND rule = ?").get(p, h.rule.id) as Finding);
      }
    }
  };
  for (const root of scanRoots()) await walk(root, 0);
  // Files that were flagged and are now clean (fixed by hand) close themselves.
  for (const f of findings().filter((x) => x.status === "open")) {
    const buf = await readFile(fsPath(f.path)).catch(() => null);
    if (!buf || !matchRules(f.path, buf.toString("latin1")).some((h) => h.rule.id === f.rule)) state().query("UPDATE shield_findings SET status = 'cleaned' WHERE id = ?").run(f.id);
  }
  if (shieldSettings().autoQuarantine) for (const f of found.filter((x) => x.severity === "malware")) await quarantine(f.id, "shield").catch(() => {});
  settings.set("shield.lastScan", JSON.stringify({ at: t0, full, files, found: found.length, ms: Date.now() - t0 }));
  if (found.length) {
    const malware = found.filter((f) => f.severity === "malware");
    await notify(`🦠 shield: ${malware.length} malware, ${found.length - malware.length} suspicious\n${found.slice(0, 8).map((f) => `${f.rule} ${f.path}`).join("\n")}`);
  }
}

export function findings(): Finding[] {
  tables();
  return state().query("SELECT * FROM shield_findings ORDER BY status = 'open' DESC, severity = 'malware' DESC, found_at DESC LIMIT 500").all() as Finding[];
}

const finding = (id: number) => {
  const f = findings().find((x) => x.id === id);
  if (!f) throw new Error("no such finding");
  return f;
};

/**
 * The file's path with its directory resolved, refused unless that directory really is inside a
 * scan root: a site user can swap a directory for a symlink to make root move files elsewhere.
 */
async function underRoots(p: string): Promise<{ real: string; root: string }> {
  const dir = await realpath(fsPath(dirname(p))).catch(() => null);
  if (dir) {
    for (const r of scanRoots()) {
      const base = await realpath(fsPath(r)).catch(() => null);
      if (base && (dir === base || dir.startsWith(`${base}/`))) return { real: `${dir}/${basename(p)}`, root: r };
    }
  }
  throw new Error("path is outside the site and app directories");
}

/**
 * Who works on files under a scan root: the tenant who can write there (a PHP site's or an app's user,
 * else whoever owns the root itself; "" = root, for a root that is root's). Taken from the root, never
 * from the file's directory at the time of the move, which the tenant could have swapped by then. Moves
 * into and out of the tree run as this user, so a directory swapped for a link meanwhile only ever leads
 * to what they could change anyway.
 */
async function rootOwner(root: string): Promise<string> {
  const site = sites.list().find((s) => s.root === root && s.kind === "php");
  if (site) return siteUser(site.name);
  const app = apps.list().find((a) => a.kind === "managed" && `${paths.apps}/${a.name}/data` === root);
  if (app) return appUser(app.name);
  const st = await lstat(fsPath(root));
  if (st.uid === 0) return "";
  const user = await userName(st.uid);
  if (!user) throw new Error(`no user with uid ${st.uid} owns ${root}`);
  return user;
}

/** Moves the file out of the site (root-only, original owner and mode remembered); reversible. */
export async function quarantine(id: number, actor: string) {
  const f = finding(id);
  if (f.status === "quarantined") return;
  const { real, root } = await underRoots(f.path);
  const st = await lstat(real);
  if (!st.isFile()) throw new Error("not a regular file");
  const user = await rootOwner(root);
  // Read and deleted as the tree's user (root never moves it by path): a copy into root's
  // quarantine, then the original goes. The copy must be the file the scan flagged.
  const buf = await readAs(real, user);
  const sha = createHash("sha256").update(buf).digest("hex");
  if (f.sha256 && sha !== f.sha256) throw new Error("the file changed since the scan; scan again");
  const dir = `${paths.data}/quarantine`;
  await ensureDir(dir, 0o700);
  const target = `${dir}/${f.id}-${sha.slice(0, 16)}`;
  await writeAtomic(target, buf, 0o600);
  try {
    await run(["rm", "-f", "--", real], { user: user || undefined });
  } catch (e) {
    await remove(target);
    throw e;
  }
  // Every finding of the same file follows it.
  state()
    .query("UPDATE shield_findings SET status = 'quarantined', quarantine = ?, owner = ? WHERE path = ?")
    .run(target, `${st.uid}:${st.gid}:${(st.mode & 0o7777).toString(8)}`, f.path);
  audit(actor, "shield.quarantine", { path: f.path, rule: f.rule });
}

export async function restore(id: number, actor: string) {
  const f = finding(id);
  if (f.status !== "quarantined" || !f.quarantine) throw new Error("not in quarantine");
  const { real, root } = await underRoots(f.path);
  if (await lstat(real).catch(() => null)) throw new Error("a file with that name exists again; remove it first");
  const [uid, gid, mode] = f.owner.split(":");
  // Never give back setuid/setgid/sticky bits, whatever the file had.
  const perm = (/^[0-7]{1,4}$/.test(mode ?? "") ? Number.parseInt(mode!, 8) : 0o644) & 0o777;
  // Written as the tree's user (who then owns the file, as it did before), never by root on a path the
  // site controls: dd's conv=excl creates it with O_EXCL, which neither replaces a file nor follows a link.
  const user = await rootOwner(root);
  const as = { user: user || undefined };
  await run(["dd", `of=${real}`, "conv=excl", "status=none"], { ...as, inputFile: fsPath(f.quarantine) });
  await run(["chmod", perm.toString(8), "--", real], as);
  // A root-owned tree (no tenant can swap it): root gives the file its old owner back.
  if (!user && /^\d+$/.test(uid ?? "") && /^\d+$/.test(gid ?? "")) await run(["chown", "-h", `${uid}:${gid}`, real]);
  await remove(f.quarantine);
  state().query("UPDATE shield_findings SET status = 'ignored', quarantine = '' WHERE path = ?").run(f.path);
  audit(actor, "shield.restore", { path: f.path });
}

export function ignore(id: number, actor: string) {
  const f = finding(id);
  state().query("UPDATE shield_findings SET status = 'ignored' WHERE id = ?").run(f.id);
  audit(actor, "shield.ignore", { path: f.path, rule: f.rule });
}

// ---- ClamAV deep scan (optional) -------------------------------------------------------

export const clamInstalled = () => exists("/usr/bin/clamscan");

export async function deepScan(actor: string) {
  if (scanning) throw new Error("a scan is already running");
  audit(actor, "shield.deepscan", {});
  scanning = (async () => {
    if (!(await clamInstalled())) {
      const os = (await readText("/etc/os-release")) ?? "";
      if (/^(ID|ID_LIKE)=.*\b(debian|ubuntu)\b/m.test(os)) await run(["apt-get", "install", "-y", "clamav"], { timeoutMs: 900_000 });
      else {
        await run(["dnf", "-y", "install", "epel-release"], { timeoutMs: 900_000, check: false });
        await run(["dnf", "-y", "install", "clamav", "clamav-update"], { timeoutMs: 900_000 });
      }
    }
    await run(["freshclam", "--quiet"], { timeoutMs: 900_000, check: false });
    tables();
    // No daemon: signatures load for this scan only (about 1 GB of memory while it runs).
    const r = await run(["nice", "-n", "15", "clamscan", "-r", "-i", "--no-summary", "--max-filesize=20M", "--exclude-dir=node_modules", "--exclude-dir=\\.git", ...scanRoots().map(fsPath)], { timeoutMs: 6 * 3600_000, check: false });
    let n = 0;
    for (const line of r.stdout.split("\n")) {
      const m = line.match(/^(.*): (.+) FOUND$/);
      if (!m) continue;
      n++;
      state()
        .query(`INSERT INTO shield_findings (path, rule, severity, snippet, status, found_at) VALUES (?, ?, 'malware', '', 'open', ?) ON CONFLICT(path, rule) DO UPDATE SET status = 'open', found_at = excluded.found_at`)
        .run(m[1]!, `clamav:${m[2]!}`.slice(0, 120), Math.floor(Date.now() / 1000));
    }
    settings.set("shield.lastDeepScan", JSON.stringify({ at: Date.now(), found: n }));
    if (n) await notify(`🦠 shield (ClamAV): ${n} infected files`);
  })()
    .catch((e) => console.error(`[agent] clamav: ${e}`))
    .finally(() => (scanning = null));
}

// ---- IP reputation ---------------------------------------------------------------------

const PRIVATE = /^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|2[3-5]\d\.)/;
const CIDR4 = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/;
const CIDR6 = /^[0-9a-f:]+(\/\d{1,3})?$/i;

/** Lists of hostile networks, never anything private or reserved. */
export function parseLists(drop4: string, drop6: string, feodo: string) {
  const fromJson = (text: string, re: RegExp) =>
    text
      .split("\n")
      .map((l) => {
        try {
          return String(JSON.parse(l).cidr ?? "");
        } catch {
          return "";
        }
      })
      .filter((c) => re.test(c));
  const v4 = fromJson(drop4, CIDR4).filter((c) => !PRIVATE.test(c));
  const v6 = fromJson(drop6, CIDR6).filter((c) => !/^(fe80|fc|fd|::)/i.test(c));
  const c2 = feodo
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && CIDR4.test(l) && !PRIVATE.test(l));
  return { v4, v6, c2 };
}

export function renderReputation(l: { v4: string[]; v6: string[]; c2: string[] }): string {
  const set = (name: string, type: string, items: string[]) =>
    `\tset ${name} { type ${type}; flags interval; auto-merge;${items.length ? ` elements = { ${items.join(", ")} }` : ""} }`;
  return [
    "table inet pano_shield",
    "delete table inet pano_shield",
    "table inet pano_shield {",
    set("drop4", "ipv4_addr", l.v4),
    set("drop6", "ipv6_addr", l.v6),
    set("c2", "ipv4_addr", l.c2),
    "\tchain input {",
    "\t\ttype filter hook input priority -15; policy accept;",
    '\t\tiifname { "lo", "pano0" } accept',
    "\t\tip saddr @drop4 drop",
    "\t\tip6 saddr @drop6 drop",
    "\t}",
    // Outbound too: a compromised app cannot call home to a known botnet controller.
    "\tchain output {",
    "\t\ttype filter hook output priority -15; policy accept;",
    '\t\toifname "lo" accept',
    "\t\tip daddr @drop4 reject",
    "\t\tip6 daddr @drop6 reject",
    "\t\tip daddr @c2 reject",
    "\t}",
    "}",
    "",
  ].join("\n");
}

const REPUTATION_FILE = `${paths.etc}/shield.nft`;

export async function refreshReputation() {
  const get = async (url: string) => {
    const r = await fetch(url, { signal: AbortSignal.timeout(30_000), headers: { "user-agent": "pano" } });
    if (!r.ok) throw new Error(`${url}: ${r.status}`);
    return r.text();
  };
  const [d4, d6, feodo] = await Promise.all([
    get("https://www.spamhaus.org/drop/drop_v4.json"),
    get("https://www.spamhaus.org/drop/drop_v6.json"),
    get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt").catch(() => ""),
  ]);
  const lists = parseLists(d4, d6, feodo);
  if (lists.v4.length < 100) throw new Error("Spamhaus DROP list looks empty; keeping the previous one");
  await writeAtomic(REPUTATION_FILE, renderReputation(lists), 0o600);
  await run(["nft", "-c", "-f", fsPath(REPUTATION_FILE)]);
  await run(["nft", "-f", fsPath(REPUTATION_FILE)]);
  settings.set("shield.reputation", JSON.stringify({ at: Date.now(), v4: lists.v4.length, v6: lists.v6.length, c2: lists.c2.length }));
}

async function reputationUnit(on: boolean) {
  const unit = "pano-shield.service";
  if (!on) {
    await run(["systemctl", "disable", "--now", unit], { check: false });
    await run(["nft", "delete", "table", "inet", "pano_shield"], { check: false });
    return;
  }
  // Reloads the last good list at boot, before the network comes up.
  await writeAtomic(
    `${paths.systemd}/${unit}`,
    `[Unit]\nDescription=pano shield (IP reputation lists)\nBefore=network-pre.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=-nft -f ${REPUTATION_FILE}\nExecStop=-nft delete table inet pano_shield\n\n[Install]\nWantedBy=multi-user.target\n`,
    0o644,
  );
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", unit]);
  await refreshReputation();
}

// ---- login brute force (from the edge's access logs) ----------------------------------

const LOGIN = /^\/(wp-login\.php|xmlrpc\.php)(\?|$)/;
const WINDOW = 10 * 60_000;
const LIMIT = 20;
const BAN_SECONDS = 3600;
const offsets = new Map<string, number>();
const hits = new Map<string, number[]>();

/** Reads what the edge logged since the last minute; returns addresses that crossed the limit. */
export function countLogins(lines: string[], now = Date.now()): string[] {
  const over: string[] = [];
  for (const line of lines) {
    let e: any;
    try {
      e = JSON.parse(line);
    } catch {
      continue;
    }
    const req = e.request ?? {};
    if (req.method !== "POST" || !LOGIN.test(String(req.uri ?? ""))) continue;
    const ip = String(req.client_ip || req.remote_ip || "");
    // Never this server or a WireGuard device.
    // Only a plain address: it ends up in nft and Caddy rules.
    if (!isIP(ip) || /^(127\.|10\.77\.0\.)/.test(ip) || ip === "::1") continue;
    const list = (hits.get(ip) ?? []).filter((t) => now - t < WINDOW);
    list.push(now);
    hits.set(ip, list);
    if (list.length > LIMIT && !over.includes(ip)) over.push(ip);
  }
  return over;
}

const logFiles = async () =>
  (await readdir(fsPath(paths.accessLogs)).catch(() => [] as string[])).filter((f) => f.endsWith(".log") && !/-\d{4}-\d{2}-\d{2}T/.test(f)); // rolled files are old

/** Remembers where every log ends now, so the next check reads only what comes after. */
async function primeOffsets() {
  for (const f of await logFiles()) offsets.set(f, (await stat(fsPath(`${paths.accessLogs}/${f}`)).catch(() => null))?.size ?? 0);
}

export async function checkLogins() {
  tables();
  const lines: string[] = [];
  for (const f of await logFiles()) {
    const p = fsPath(`${paths.accessLogs}/${f}`);
    const size = (await stat(p).catch(() => null))?.size ?? 0;
    // A log that appeared since the last check (new site, or rolled) is read from its start.
    const from = Math.min(offsets.get(f) ?? 0, size);
    offsets.set(f, size);
    if (size <= from) continue;
    const text = await Bun.file(p).slice(from, Math.min(size, from + 20_000_000)).text();
    lines.push(...text.split("\n"));
  }
  const now = Math.floor(Date.now() / 1000);
  let changed = state().query("DELETE FROM shield_bans WHERE until < ?").run(now).changes > 0;
  for (const ip of countLogins(lines)) {
    state().query("INSERT INTO shield_bans (ip, until, reason) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET until = excluded.until").run(ip, now + BAN_SECONDS, "login brute force");
    changed = true;
    void notify(`🛡️ shield: ${ip} blocked for an hour (WordPress login brute force)`);
  }
  if (changed) await syncBans();
}

export function bans(): { ip: string; until: number; reason: string }[] {
  tables();
  return state().query("SELECT * FROM shield_bans WHERE until >= ? ORDER BY until DESC").all(Math.floor(Date.now() / 1000)) as any[];
}

/**
 * Two layers: the kernel drops banned addresses on 80/443 (they never reach the
 * edge), and the edge answers them 429 by the visitor address it sees, which is
 * what still works behind Cloudflare, where every connection comes from Cloudflare.
 */
async function syncBans() {
  const list = shieldSettings().bruteforce ? bans().map((b) => b.ip) : [];
  settings.set("shield.bans", JSON.stringify(list));
  await applyEdge().catch((e) => console.error(`[agent] shield bans: ${e}`));
  const v4 = list.filter((ip) => isIP(ip) === 4);
  const v6 = list.filter((ip) => isIP(ip) === 6);
  const file = `${paths.etc}/shield-bans.nft`;
  const kernel = list.length && !edgeSettings().behindCloudflare;
  if (!kernel) {
    await run(["nft", "delete", "table", "inet", "pano_bans"], { check: false });
    return;
  }
  await writeAtomic(file, renderBans(v4, v6), 0o600);
  await run(["nft", "-f", fsPath(file)], { check: false });
}

export function renderBans(v4: string[], v6: string[]): string {
  return [
    "table inet pano_bans",
    "delete table inet pano_bans",
    "table inet pano_bans {",
    `\tset web4 { type ipv4_addr;${v4.length ? ` elements = { ${v4.join(", ")} }` : ""} }`,
    `\tset web6 { type ipv6_addr;${v6.length ? ` elements = { ${v6.join(", ")} }` : ""} }`,
    "\tchain input {",
    "\t\ttype filter hook input priority -12; policy accept;",
    "\t\ttcp dport { 80, 443 } ip saddr @web4 drop",
    "\t\tudp dport 443 ip saddr @web4 drop",
    "\t\ttcp dport { 80, 443 } ip6 saddr @web6 drop",
    "\t\tudp dport 443 ip6 saddr @web6 drop",
    "\t}",
    "}",
    "",
  ].join("\n");
}

export async function unban(ip: string, actor: string) {
  tables();
  state().query("DELETE FROM shield_bans WHERE ip = ?").run(ip);
  hits.delete(ip);
  await syncBans();
  audit(actor, "shield.unban", { ip });
}

// ---- switches and schedule ------------------------------------------------------------

export async function setShield(next: ShieldSettings, actor: string) {
  const prev = shieldSettings();
  settings.set("shield", JSON.stringify(next));
  if (next.reputation !== prev.reputation) await reputationUnit(next.reputation);
  if (next.bruteforce !== prev.bruteforce) {
    if (next.bruteforce) await primeOffsets();
    await syncBans();
  }
  if (next.scan && !prev.scan) startScan(true, actor);
  audit(actor, "shield.set", next);
}

export async function shieldStatus() {
  return {
    settings: shieldSettings(),
    scan: scanState(),
    deepScan: JSON.parse(settings.get("shield.lastDeepScan") ?? "null") as { at: number; found: number } | null,
    clamav: await clamInstalled(),
    reputation: JSON.parse(settings.get("shield.reputation") ?? "null") as { at: number; v4: number; v6: number; c2: number } | null,
    bans: bans(),
    findings: findings(),
    roots: scanRoots(),
  };
}

// ---- symlinks out of sites ---------------------------------------------------------------

/**
 * The edge reads PHP and static sites through its no-symlink views (edge.ts EDGE_VIEW, WWW_VIEW); this also
 * brings existing installs onto them. Where the server cannot mount one (Linux before 5.10, or the remount of
 * viewlock.ts failed), its sites are held offline and every agent start and day says so on the alert channel. Only with
 * PANO_EDGE_FOLLOW_LINKS=1 does the edge read the real paths; it would follow a link a site plants to a TLS
 * key or another site's files, so links leading out of a site are removed (as the site's user, see
 * removeOutsideLinks). A stopgap: a link lives until the next sweep.
 */
export async function guardSiteLinks() {
  settings.set("shield.linkGuard", String(Date.now()));
  if (DRY_RUN || !(await edgeInstalled())) return;
  const views = await refreshEdgeView();
  const held = heldByEdge(sites.list(), views, env.edgeFollowLinks).filter((s) => s.enabled && s.domains.length);
  if (held.length) {
    audit("agent", "edge.view.missing", { held: held.map((s) => s.name) });
    await notify(viewMissingAlert(held.map((s) => s.name)));
  }
  if (views.sites || !env.edgeFollowLinks) return;
  const removed: string[] = [];
  for (const s of sites.list().filter((x) => x.kind === "php")) {
    const gone = await removeOutsideLinks(s.name).catch((e) => {
      console.error(`[agent] link sweep ${s.name}: ${e}`);
      return [] as string[];
    });
    removed.push(...gone.map((w) => `${s.name}: ${w}`));
  }
  if (removed.length) await notify(`🔗 shield: ${removed.length} symlinks leading out of sites removed (this kernel cannot keep the edge from following them)\n${removed.slice(0, 8).join("\n")}`);
}

/** The alert when PHP sites are held offline because the edge view cannot be mounted. */
export function viewMissingAlert(names: string[]): string {
  return (
    `⛔ edge: ${names.length} site(s) are offline (503): their files cannot be served without following symlinks ` +
    `(no read-only nosymfollow view, needs Linux 5.10+; or a static root outside /var/www or inside /srv/pano), and the edge could ` +
    `be made to serve TLS keys or other sites' files.\n${names.slice(0, 8).join(", ")}${names.length > 8 ? ", …" : ""}\nFix: see the Security page.`
  );
}

/** Every minute: login brute force. Hourly: changed files. Weekly: full scan. Daily: reputation lists, site links. */
export function startShield() {
  void primeOffsets();
  void guardSiteLinks().catch((e) => console.error(`[agent] site links: ${e}`));
  setInterval(async () => {
    const s = shieldSettings();
    try {
      // Not awaited: a sweep of large sites must not hold up the login check. It stamps its start, so it never overlaps.
      if (Date.now() - Number(settings.get("shield.linkGuard") ?? 0) > 86400_000) void guardSiteLinks().catch((e) => console.error(`[agent] site links: ${e}`));
      if (s.bruteforce) await checkLogins();
      const last = scanState().last?.at ?? 0;
      const lastFull = Number(settings.get("shield.lastFull") ?? 0);
      if (s.scan && !scanning) {
        if (Date.now() - lastFull > 7 * 86400_000) {
          settings.set("shield.lastFull", String(Date.now()));
          startScan(true, "scheduler");
        } else if (Date.now() - last > 3600_000) startScan(false, "scheduler");
      }
      const rep = JSON.parse(settings.get("shield.reputation") ?? "null") as { at: number } | null;
      if (s.reputation && (!rep || Date.now() - rep.at > 86400_000)) await refreshReputation();
    } catch (e) {
      console.error(`[agent] shield: ${e}`);
    }
  }, 60_000);
}
