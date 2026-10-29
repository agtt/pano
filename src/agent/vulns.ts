// Known vulnerabilities in everything third-party on the server, checked daily,
// and closed automatically where that is safe:
//
// - OS packages: pending security advisories from the distribution (dnf
//   updateinfo); automatic security updates (dnf-automatic) install them daily
//   and a reboot that a kernel or glibc fix needs is reported.
// - PHP (Remi): patch releases of each installed minor are installed daily and
//   the sites' pools reload on the new binary by themselves.
// - The edge (Caddy): patch releases, or any 2.x release when the running one
//   has a known vulnerability, are installed at night, checked, and rolled back
//   if the edge does not come up. The realtime server updates itself the same way.
// - Node.js runtimes: newer security releases of the same major (nodejs.org).
// - App and site dependencies (npm lockfiles, composer.lock) and the edge and
//   realtime binaries: OSV.dev, the open vulnerability database behind GitHub,
//   Go, crates.io and Packagist advisories. These live in the app's repository,
//   so they are reported with the fixed version, not changed here.
// - WordPress core: wordpress.org's own list of insecure versions.
// - Exploit data: CISA KEV (attacked in the wild) and FIRST EPSS (likely to be)
//   mark findings urgent; every 6 hours a scan runs and urgent ones that pano
//   can patch (OS, PHP, edge) are patched right away instead of at night.
//
// New high and critical (and urgent) findings go to Telegram once.

import { fsPath, paths } from "../shared/config.ts";
import { notify } from "./alerts.ts";
import { appHome } from "./apps.ts";
import { installCaddy } from "./edge.ts";
import { installedPhp, phpCli, upgradePhpPackages } from "./php.ts";
import * as realtime from "./realtime.ts";
import { installed as installedRuntimes } from "./runtimes.ts";
import { apps, audit, settings, sites, state } from "./state.ts";
import { exists, readText, run, writeAtomic } from "./sys.ts";

export type Severity = "critical" | "high" | "medium" | "low" | "unknown";
export type Finding = {
  /** where it is: "os", "edge", "realtime", "runtime", "php", "app:<name>", "site:<name>" */
  where: string;
  ecosystem: string;
  name: string;
  version: string;
  id: string;
  aliases: string[];
  severity: Severity;
  summary: string;
  fixed: string;
  /** closed by pano itself (automatic updates) or needs a change in the app */
  autofix: boolean;
  /** in CISA's Known Exploited Vulnerabilities catalog: attacked in the wild now */
  exploited?: boolean;
  /** FIRST EPSS: probability (0-1) of exploitation in the next 30 days */
  epss?: number;
};
type Pkg = { where: string; ecosystem: string; name: string; version: string; autofix: boolean };

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const UA = { "user-agent": "pano" };

// ---- severity ---------------------------------------------------------------------------

const roundUp = (x: number) => Math.ceil(x * 10 - 1e-9) / 10;

/** CVSS 3.x base score from its vector string. */
export function cvss3(vector: string): number | null {
  const m = Object.fromEntries(vector.split("/").slice(1).map((p) => p.split(":") as [string, string]));
  const changed = m.S === "C";
  const w = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV!],
    AC: { L: 0.77, H: 0.44 }[m.AC!],
    PR: { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR!],
    UI: { N: 0.85, R: 0.62 }[m.UI!],
  };
  const cia = (k: string) => ({ H: 0.56, L: 0.22, N: 0 })[m[k]!];
  const [c, i, a] = [cia("C"), cia("I"), cia("A")];
  if (Object.values(w).some((x) => x === undefined) || [c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * w.AV! * w.AC! * w.PR! * w.UI!;
  return roundUp(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

const fromScore = (s: number): Severity => (s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : s > 0 ? "low" : "unknown");

export function severityOf(v: any): Severity {
  const named = String(v?.database_specific?.severity ?? "").toLowerCase();
  if (named === "moderate") return "medium";
  if (named in RANK) return named as Severity;
  for (const s of v?.severity ?? []) {
    if (String(s.type).startsWith("CVSS_V3")) {
      const score = cvss3(String(s.score));
      if (score !== null) return fromScore(score);
    }
  }
  return "unknown";
}

/** "Fixed in" versions for this package, from the advisory's ranges. */
export function fixedIn(v: any, name: string): string {
  const out = new Set<string>();
  for (const a of v?.affected ?? []) {
    if (a?.package?.name !== name) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) out.add(String(e.fixed));
  }
  return [...out].join(", ");
}

// ---- inventory ------------------------------------------------------------------------

/** name@version pairs from bun.lock (text) or package-lock.json. */
export function parseNpmLock(file: string, text: string): { name: string; version: string }[] {
  const out = new Map<string, string>();
  if (file.endsWith("bun.lock")) {
    for (const m of text.matchAll(/^\s*"[^"]+": \["(@?[^@"]+)@([^"]+)"/gm)) {
      if (/^(workspace|file|link|github|git)[:+]/.test(m[2]!)) continue;
      out.set(`${m[1]}@${m[2]}`, m[2]!);
    }
  } else {
    const lock = JSON.parse(text) as { packages?: Record<string, { version?: string; link?: boolean }> };
    for (const [path, p] of Object.entries(lock.packages ?? {})) {
      const name = path.split("node_modules/").at(-1);
      if (!path || !name || !p.version || p.link) continue;
      out.set(`${name}@${p.version}`, p.version);
    }
  }
  return [...out.keys()].map((k) => ({ name: k.slice(0, k.lastIndexOf("@")), version: out.get(k)! }));
}

export function parseComposerLock(text: string): { name: string; version: string }[] {
  const lock = JSON.parse(text) as { packages?: { name: string; version: string }[]; "packages-dev"?: { name: string; version: string }[] };
  return [...(lock.packages ?? []), ...(lock["packages-dev"] ?? [])].map((p) => ({ name: p.name, version: p.version.replace(/^v/, "") }));
}

async function appPackages(): Promise<Pkg[]> {
  const out: Pkg[] = [];
  for (const a of apps.list()) {
    if (a.kind !== "managed" || !a.active_slot) continue;
    const base = `${appHome(a.name)}/current`;
    for (const dir of new Set([base, a.root_dir ? `${base}/${a.root_dir}` : base])) {
      for (const f of ["bun.lock", "package-lock.json"]) {
        const text = await readText(`${dir}/${f}`);
        if (!text) continue;
        for (const p of parseNpmLock(f, text)) out.push({ where: `app:${a.name}`, ecosystem: "npm", ...p, autofix: false });
        break;
      }
      const composer = await readText(`${dir}/composer.lock`);
      if (composer) for (const p of parseComposerLock(composer)) out.push({ where: `app:${a.name}`, ecosystem: "Packagist", ...p, autofix: false });
    }
  }
  return out;
}

async function sitePackages(): Promise<{ pkgs: Pkg[]; wordpress: { site: string; version: string }[] }> {
  const pkgs: Pkg[] = [];
  const wordpress: { site: string; version: string }[] = [];
  for (const s of sites.list()) {
    if (!s.root || !["php", "legacy"].includes(s.kind)) continue;
    const parent = s.root.replace(/\/[^/]+$/, "");
    for (const dir of [s.root, parent]) {
      const composer = await readText(`${dir}/composer.lock`);
      if (!composer) continue;
      for (const p of parseComposerLock(composer)) pkgs.push({ where: `site:${s.name}`, ecosystem: "Packagist", ...p, autofix: false });
      break;
    }
    const wp = (await readText(`${s.root}/wp-includes/version.php`))?.match(/\$wp_version\s*=\s*'([^']+)'/)?.[1];
    if (wp) wordpress.push({ site: s.name, version: wp });
  }
  return { pkgs, wordpress };
}

async function binaryPackages(): Promise<Pkg[]> {
  const out: Pkg[] = [];
  const caddy = (await run([paths.caddy, "version"], { check: false })).stdout.match(/v(\d+\.\d+\.\d+)/)?.[1];
  if (caddy) out.push({ where: "edge", ecosystem: "Go", name: "github.com/caddyserver/caddy/v2", version: caddy, autofix: true });
  const rt = realtime.installedVersion();
  if (rt) out.push({ where: "realtime", ecosystem: "crates.io", name: "sockudo", version: rt, autofix: true });
  return out;
}

// ---- OSV ---------------------------------------------------------------------------------

function cacheTable() {
  state().exec("CREATE TABLE IF NOT EXISTS osv_cache (id TEXT PRIMARY KEY, modified TEXT NOT NULL, json TEXT NOT NULL)");
}

async function vulnDetails(id: string, modified: string): Promise<any> {
  cacheTable();
  const hit = state().query("SELECT modified, json FROM osv_cache WHERE id = ?").get(id) as { modified: string; json: string } | null;
  if (hit && hit.modified === modified) return JSON.parse(hit.json);
  const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { headers: UA, signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`OSV ${id}: ${res.status}`);
  const json = await res.json();
  state().query("INSERT OR REPLACE INTO osv_cache (id, modified, json) VALUES (?, ?, ?)").run(id, modified, JSON.stringify(json));
  return json;
}

async function osv(pkgs: Pkg[]): Promise<Finding[]> {
  // The same package in several apps is asked about once.
  const unique = [...new Map(pkgs.map((p) => [`${p.ecosystem}|${p.name}|${p.version}`, p])).values()];
  const hits = new Map<string, { id: string; modified: string }[]>();
  for (let i = 0; i < unique.length; i += 1000) {
    const batch = unique.slice(i, i + 1000);
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { ...UA, "content-type": "application/json" },
      body: JSON.stringify({ queries: batch.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) throw new Error(`OSV query: ${res.status}`);
    const { results } = (await res.json()) as { results: { vulns?: { id: string; modified: string }[] }[] };
    results.forEach((r, j) => {
      const p = batch[j]!;
      if (r.vulns?.length) hits.set(`${p.ecosystem}|${p.name}|${p.version}`, r.vulns);
    });
  }
  const details = new Map<string, any>();
  const ids = [...new Map([...hits.values()].flat().map((v) => [v.id, v])).values()];
  for (let i = 0; i < ids.length; i += 8) {
    await Promise.all(ids.slice(i, i + 8).map(async (v) => details.set(v.id, await vulnDetails(v.id, v.modified).catch(() => null))));
  }
  const out: Finding[] = [];
  for (const p of pkgs) {
    for (const h of hits.get(`${p.ecosystem}|${p.name}|${p.version}`) ?? []) {
      const d = details.get(h.id);
      out.push({
        ...p,
        id: h.id,
        aliases: (d?.aliases ?? []).filter((a: string) => a.startsWith("CVE-")),
        severity: severityOf(d),
        summary: String(d?.summary ?? d?.details ?? "").split("\n")[0]!.slice(0, 200),
        fixed: fixedIn(d, p.name),
      });
    }
  }
  return out;
}

// ---- other sources -------------------------------------------------------------------------

const DNF_SEVERITY: Record<string, Severity> = { Critical: "critical", Important: "high", Moderate: "medium", Low: "low" };

/** Security advisories the distribution has published and this server has not installed yet. */
export function parseUpdateinfo(text: string): Finding[] {
  const out: Finding[] = [];
  for (const line of text.split("\n")) {
    const m = line.trim().match(/^(\S+)\s+(Critical|Important|Moderate|Low)\/Sec\.\s+(\S+)$/);
    if (!m) continue;
    const pkg = m[3]!.replace(/\.(x86_64|aarch64|noarch|i686)$/, "");
    const name = pkg.replace(/-(\d+:)?[^-]+-[^-]+$/, "");
    out.push({
      where: "os",
      ecosystem: "os",
      name,
      version: "",
      id: m[1]!,
      aliases: [],
      severity: DNF_SEVERITY[m[2]!]!,
      summary: `${m[2]} security update`,
      fixed: pkg.slice(name.length + 1),
      autofix: true,
    });
  }
  return out;
}

async function osAdvisories(): Promise<Finding[]> {
  if ((await run(["which", "dnf"], { check: false })).code !== 0) return [];
  const r = await run(["dnf", "-q", "updateinfo", "list", "--security", "--available"], { check: false, timeoutMs: 300_000 });
  // The same list keyed by CVE: the advisories' CVE ids, for the exploit checks below.
  const c = await run(["dnf", "-q", "updateinfo", "list", "--security", "--available", "--with-cve"], { check: false, timeoutMs: 300_000 });
  const cves = new Map<string, string[]>();
  for (const x of parseUpdateinfo(c.stdout)) if (/^CVE-\d{4}-\d+$/.test(x.id)) cves.set(x.name, [...(cves.get(x.name) ?? []), x.id]);
  return parseUpdateinfo(r.stdout).map((f) => ({ ...f, aliases: [...new Set(cves.get(f.name) ?? [])] }));
}

const cmpVer = (a: string, b: string) => {
  const [x, y] = [a.split(".").map(Number), b.split(".").map(Number)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  return 0;
};

/** Installed Node.js versions with a newer security release in the same major line. */
export function nodeSecurity(installed: string[], index: { version: string; security: boolean }[]): Finding[] {
  const out: Finding[] = [];
  for (const ver of installed) {
    const major = ver.split(".")[0];
    const fixes = index
      .map((r) => ({ ...r, version: r.version.replace(/^v/, "") }))
      .filter((r) => r.security && r.version.split(".")[0] === major && cmpVer(r.version, ver) > 0)
      .sort((a, b) => cmpVer(b.version, a.version));
    if (!fixes.length) continue;
    out.push({
      where: "runtime",
      ecosystem: "nodejs",
      name: "node",
      version: ver,
      id: `node-${fixes[0]!.version}`,
      aliases: [],
      severity: "high",
      summary: `Node.js ${fixes.at(-1)!.version}${fixes.length > 1 ? ` and ${fixes.length - 1} later releases` : ""} fixed security issues`,
      fixed: fixes[0]!.version,
      autofix: false,
    });
  }
  return out;
}

async function runtimeFindings(): Promise<Finding[]> {
  const node = (await installedRuntimes()).filter((r) => r.runtime === "node").map((r) => r.version);
  if (!node.length) return [];
  const res = await fetch("https://nodejs.org/dist/index.json", { headers: UA, signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`nodejs.org: ${res.status}`);
  return nodeSecurity(node, (await res.json()) as { version: string; security: boolean }[]);
}

async function phpFindings(): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const minor of await installedPhp()) {
    const current = (await run([phpCli(minor), "-r", "echo PHP_VERSION;"], { check: false })).stdout.trim();
    const res = await fetch(`https://www.php.net/releases/index.php?json&version=${minor}`, { headers: UA, signal: AbortSignal.timeout(20_000) });
    const latest = res.ok ? String(((await res.json()) as { version?: string }).version ?? "") : "";
    if (!current || !latest || cmpVer(latest, current) <= 0) continue;
    out.push({
      where: "php",
      ecosystem: "php",
      name: `php ${minor}`,
      version: current,
      id: `php-${latest}`,
      aliases: [],
      severity: "medium",
      summary: `PHP ${latest} is out; PHP patch releases carry security fixes`,
      fixed: latest,
      autofix: true,
    });
  }
  return out;
}

async function wordpressFindings(list: { site: string; version: string }[]): Promise<Finding[]> {
  if (!list.length) return [];
  const res = await fetch("https://api.wordpress.org/core/stable-check/1.0/", { headers: UA, signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`wordpress.org: ${res.status}`);
  const status = (await res.json()) as Record<string, string>;
  const latest = Object.entries(status).find(([, s]) => s === "latest")?.[0] ?? "";
  return list
    .filter((w) => status[w.version] === "insecure")
    .map((w) => ({
      where: `site:${w.site}`,
      ecosystem: "wordpress",
      name: "wordpress",
      version: w.version,
      id: `wordpress-${w.version}`,
      aliases: [],
      severity: "high" as Severity,
      summary: "wordpress.org lists this WordPress version as insecure",
      fixed: latest,
      autofix: false,
    }));
}

// ---- scan ------------------------------------------------------------------------------------

export type ScanResult = { at: number; findings: Finding[]; errors: string[]; packages: number };

export function lastScan(): ScanResult | null {
  return JSON.parse(settings.get("vulns.last") || "null");
}

let scanning: Promise<ScanResult> | null = null;

export function scan(): Promise<ScanResult> {
  scanning ??= doScan().finally(() => (scanning = null));
  return scanning;
}

async function doScan(): Promise<ScanResult> {
  const errors: string[] = [];
  const safe = async <T,>(what: string, fn: () => Promise<T[]>): Promise<T[]> => {
    try {
      return await fn();
    } catch (e) {
      errors.push(`${what}: ${e instanceof Error ? e.message : e}`);
      return [];
    }
  };
  const site = await sitePackages();
  const pkgs = [...(await appPackages()), ...site.pkgs, ...(await binaryPackages())];
  const findings = [
    ...(await safe("os", osAdvisories)),
    ...(await safe("osv.dev", () => osv(pkgs))),
    ...(await safe("node", runtimeFindings)),
    ...(await safe("php", phpFindings)),
    ...(await safe("wordpress", () => wordpressFindings(site.wordpress))),
  ];
  await safe("exploit data (CISA KEV, EPSS)", async () => (await enrich(findings), []));
  findings.sort((a, b) => +urgent(b) - +urgent(a) || RANK[b.severity] - RANK[a.severity] || a.where.localeCompare(b.where));
  const result = { at: Math.floor(Date.now() / 1000), findings, errors, packages: pkgs.length };
  await report(findings);
  settings.set("vulns.last", JSON.stringify(result));
  return result;
}

// ---- exploit intelligence -----------------------------------------------------------------------
// Severity says how bad a hole is; these say whether anyone is using it. A finding in CISA's
// Known Exploited Vulnerabilities catalog, or with an EPSS score of 10% or more, is urgent:
// what pano can patch itself is patched within hours instead of at night.

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URGENT = 0.1;
const CVE = /^CVE-\d{4}-\d{4,}$/;

export const urgent = (f: Finding) => !!f.exploited || (f.epss ?? 0) >= EPSS_URGENT;
const cvesOf = (f: Finding) => [f.id, ...f.aliases].filter((x) => CVE.test(x));

/** The KEV catalog's CVE ids, fetched at most twice a day. */
async function kevIds(): Promise<Set<string>> {
  const cached = JSON.parse(settings.get("vulns.kev") || "null") as { at: number; ids: string[] } | null;
  if (cached && Date.now() - cached.at < 12 * 3600_000) return new Set(cached.ids);
  const res = await fetch(KEV_URL, { headers: UA, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`CISA KEV: ${res.status}`);
  const ids = ((await res.json()) as { vulnerabilities: { cveID: string }[] }).vulnerabilities.map((v) => v.cveID).filter((x) => CVE.test(x));
  settings.set("vulns.kev", JSON.stringify({ at: Date.now(), ids }));
  return new Set(ids);
}

async function epssScores(cves: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  for (let i = 0; i < cves.length; i += 100) {
    const res = await fetch(`https://api.first.org/data/v1/epss?cve=${cves.slice(i, i + 100).join(",")}`, { headers: UA, signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`EPSS: ${res.status}`);
    for (const d of ((await res.json()) as { data: { cve: string; epss: string }[] }).data) out.set(d.cve, Number(d.epss) || 0);
  }
  return out;
}

export function markExploits(findings: Finding[], kev: Set<string>, epss: Map<string, number>) {
  for (const f of findings) {
    const ids = cvesOf(f);
    f.exploited = ids.some((x) => kev.has(x));
    f.epss = Math.max(0, ...ids.map((x) => epss.get(x) ?? 0));
  }
}

async function enrich(findings: Finding[]) {
  const cves = [...new Set(findings.flatMap(cvesOf))];
  if (!cves.length) return;
  const [kev, epss] = await Promise.all([kevIds(), epssScores(cves)]);
  markExploits(findings, kev, epss);
}

let urgentRun: Promise<void> | null = null;

/** Patches now what pano can patch itself and is being exploited (or likely to be). */
async function patchUrgent(findings: Finding[]) {
  const hot = findings.filter((f) => f.autofix && urgent(f));
  if (!hot.length || urgentRun) return;
  const p = patchSettings();
  const why = (w: string) => hot.filter((f) => f.where === w).map((f) => cvesOf(f)[0] ?? f.id);
  urgentRun = (async () => {
    if (p.os && why("os").length && (await run(["which", "dnf"], { check: false })).code === 0) {
      const r = await run(["dnf", "-y", "-q", "upgrade", "--security"], { check: false, timeoutMs: 1_800_000 });
      await notify(r.code === 0 ? `🚨 exploited OS hole patched now (${why("os").slice(0, 5).join(", ")})` : `🔴 urgent OS update failed: ${r.stderr.trim().split("\n").at(-1)}`);
      audit("auto-update", "patch.urgent", { where: "os", ids: why("os") });
    }
    if (p.php && why("php").length) {
      await patchPhp();
      audit("auto-update", "patch.urgent", { where: "php", ids: why("php") });
    }
    if (p.edge && why("edge").length && (await exists(paths.caddy))) await patchEdge(findings);
    if (await rebootNeeded()) await notify("🔁 the urgent security update needs a reboot (kernel or core library)");
  })()
    .catch(async (e) => void (await notify(`🔴 urgent patching failed: ${e instanceof Error ? e.message : e}`)))
    .finally(() => (urgentRun = null));
  await urgentRun;
}

/** Telegram, once per new high or critical finding. */
async function report(findings: Finding[]) {
  const seen = new Set<string>(JSON.parse(settings.get("vulns.notified") || "[]"));
  const key = (f: Finding) => `${f.where}|${f.name}|${f.version}|${f.id}`;
  const worth = (f: Finding) => RANK[f.severity] >= RANK.high || urgent(f);
  const fresh = findings.filter((f) => worth(f) && !seen.has(key(f)));
  if (fresh.length) {
    const hot = (f: Finding) => (f.exploited ? " 🚨 exploited in the wild" : urgent(f) ? ` 🚨 EPSS ${Math.round((f.epss ?? 0) * 100)}%` : "");
    const lines = fresh.slice(0, 10).map((f) => `• ${f.severity} ${f.where} ${f.name} ${f.version} (${f.aliases[0] ?? f.id})${f.fixed ? ` → ${f.fixed}` : ""}${f.autofix ? " [auto]" : ""}${hot(f)}`);
    await notify(`🛡 ${fresh.length} new vulnerabilit${fresh.length > 1 ? "ies" : "y"}:\n${lines.join("\n")}${fresh.length > 10 ? "\n…" : ""}`);
  }
  // Remember only what is still open, so a finding that comes back is reported again.
  settings.set("vulns.notified", JSON.stringify(findings.filter(worth).map(key)));
}

// ---- automatic fixes ----------------------------------------------------------------------------

export type PatchSettings = { os: boolean; php: boolean; edge: boolean };
export const patchSettings = (): PatchSettings => {
  const on = (k: string) => settings.get(`patch.${k}`) !== "0";
  return { os: on("os"), php: on("php"), edge: on("edge") };
};

const DNF_AUTOMATIC = "/etc/dnf/automatic.conf";

export function renderDnfAutomatic(): string {
  return `# Written by pano: install security updates daily.
[commands]
upgrade_type = security
random_sleep = 900
download_updates = yes
apply_updates = yes
reboot = never

[emitters]
emit_via = stdio

[base]
debuglevel = 1
`;
}

let osQueue: Promise<unknown> = Promise.resolve();
/** One at a time: the first start and a settings change must not run dnf together. */
function applyOsPatching(on: boolean) {
  const next = osQueue.then(() => doApplyOsPatching(on));
  osQueue = next.catch(() => {});
  return next;
}

async function doApplyOsPatching(on: boolean) {
  if ((await run(["which", "dnf"], { check: false })).code !== 0) return;
  if (on) {
    if ((await run(["rpm", "-q", "dnf-automatic"], { check: false })).code !== 0) await run(["dnf", "-y", "install", "dnf-automatic"], { timeoutMs: 600_000 });
    const current = await readText(DNF_AUTOMATIC);
    if (current && !current.startsWith("# Written by pano") && !(await exists(`${DNF_AUTOMATIC}.pano-orig`))) {
      await writeAtomic(`${DNF_AUTOMATIC}.pano-orig`, current, 0o644);
    }
    await writeAtomic(DNF_AUTOMATIC, renderDnfAutomatic(), 0o644);
    await run(["systemctl", "enable", "--now", "dnf-automatic.timer"], { check: false });
  } else {
    await run(["systemctl", "disable", "--now", "dnf-automatic.timer"], { check: false });
  }
}

export async function setPatching(next: PatchSettings, actor: string) {
  for (const k of ["os", "php", "edge"] as const) settings.set(`patch.${k}`, next[k] ? "1" : "0");
  await applyOsPatching(next.os);
  audit(actor, "patch.set", next);
}

/** Patch releases of the installed PHP minors; pools move to the new binary within 10 minutes (reloadUpdatedPhp). */
async function patchPhp() {
  const minors = await installedPhp();
  if (!minors.length) return;
  const r = await upgradePhpPackages(minors);
  if (r.code !== 0) await notify(`🔴 PHP update failed: ${r.stderr.trim().split("\n").at(-1)}`);
}

/**
 * The edge binary: a newer patch release of the running minor, or any newer 2.x
 * when the running one has a known vulnerability. Rolled back if it does not come up.
 */
async function patchEdge(findings: Finding[]) {
  const cur = (await run([paths.caddy, "version"], { check: false })).stdout.match(/v(\d+\.\d+\.\d+)/)?.[1];
  if (!cur) return;
  const res = await fetch("https://api.github.com/repos/caddyserver/caddy/releases?per_page=30", { headers: UA, signal: AbortSignal.timeout(20_000) });
  if (!res.ok) return;
  // A release must have been out a while (3 days, 1 if this one is vulnerable): a hijacked release is
  // usually pulled within hours, and the checksums come from the same place as the binary.
  const soakMs = (findings.some((f) => f.where === "edge") ? 1 : 3) * 86_400_000;
  const stable = ((await res.json()) as { tag_name: string; prerelease: boolean; draft: boolean; published_at?: string }[])
    .filter((r) => !r.prerelease && !r.draft && /^v2\.\d+\.\d+$/.test(r.tag_name) && Date.now() - Date.parse(r.published_at ?? "") >= soakMs)
    .map((r) => r.tag_name.slice(1))
    .sort((a, b) => cmpVer(b, a));
  const vulnerable = findings.some((f) => f.where === "edge");
  const minor = cur.split(".").slice(0, 2).join(".");
  const target = vulnerable ? stable[0] : stable.find((s) => s.startsWith(`${minor}.`));
  if (!target || cmpVer(target, cur) <= 0) return;
  const prev = `${paths.caddy}.prev`;
  await run(["cp", "-p", fsPath(paths.caddy), fsPath(prev)]);
  try {
    await installCaddy(target);
    await run(["systemctl", "restart", "pano-edge"]);
    await Bun.sleep(3000);
    if ((await run(["systemctl", "is-active", "pano-edge"], { check: false })).stdout.trim() !== "active") throw new Error("edge did not start");
    await notify(`🔄 edge updated ${cur} → ${target}${vulnerable ? " (security)" : ""}`);
    audit("auto-update", "edge.update", { from: cur, to: target });
  } catch (e) {
    await run(["install", "-m", "0755", fsPath(prev), fsPath(paths.caddy)]);
    await run(["systemctl", "restart", "pano-edge"], { check: false });
    await notify(`🔴 edge update to ${target} failed, back on ${cur}: ${e instanceof Error ? e.message : e}`);
  } finally {
    await run(["rm", "-f", fsPath(prev)], { check: false });
  }
}

/** Reboot needed after kernel/glibc/systemd updates: reported, never done on its own. */
export async function rebootNeeded(): Promise<boolean> {
  const r = await run(["dnf", "needs-restarting", "-r"], { check: false, quiet: true });
  return r.code === 1;
}

async function nightly() {
  const p = patchSettings();
  if (p.os && !(await run(["systemctl", "is-enabled", "dnf-automatic.timer"], { check: false })).stdout.includes("enabled")) await applyOsPatching(true);
  if (p.php) await patchPhp();
  const result = await scan();
  await patchUrgent(result.findings);
  if (p.edge && (await exists(paths.caddy))) await patchEdge(result.findings);
  if (await rebootNeeded()) await notify("🔁 a security update needs a reboot (kernel or core library); restart the server when traffic is low");
}

/** Patches and a scan now, as at night. */
export function patchNow(actor: string) {
  audit(actor, "patch.now");
  void nightly().catch((e) => notify(`🔴 patching failed: ${e instanceof Error ? e.message : e}`));
}

export async function vulnStatus() {
  return {
    patch: patchSettings(),
    osAutomatic: (await run(["systemctl", "is-enabled", "dnf-automatic.timer"], { check: false })).stdout.trim() === "enabled",
    rebootNeeded: await rebootNeeded().catch(() => false),
    last: lastScan(),
    scanning: !!scanning,
  };
}

/** Every night between 04:00 and 05:00: patches, then a full scan. */
export function startVulns() {
  // OS patching is on by default: switch dnf-automatic on once at first start.
  if (patchSettings().os && !settings.get("patch.osApplied")) {
    applyOsPatching(true)
      .then(() => settings.set("patch.osApplied", "1"))
      .catch((e) => console.error(`[agent] dnf-automatic: ${e}`));
  }
  setInterval(() => {
    const now = new Date();
    const day = now.toISOString().slice(0, 10);
    if (now.getHours() === 4 && settings.get("vulns.nightly") !== day) {
      settings.set("vulns.nightly", day);
      nightly().catch((e) => console.error(`[agent] nightly patch/scan: ${e}`));
      return;
    }
    // Between nights, every 6 hours: a scan, and what is being exploited is patched right away.
    const slot = `${day}-${Math.floor(now.getHours() / 6)}`;
    if (settings.get("vulns.urgentCheck") === slot) return;
    settings.set("vulns.urgentCheck", slot);
    scan()
      .then((r) => patchUrgent(r.findings))
      .catch((e) => console.error(`[agent] urgent check: ${e}`));
  }, 5 * 60_000);
}
