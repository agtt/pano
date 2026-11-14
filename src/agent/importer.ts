// Reads an existing CyberPanel/OpenLiteSpeed server and turns it into pano
// sites and external apps. Scanning is read-only; applying only writes pano's
// own state. Nothing CyberPanel owns is modified until the separate cutover.

import { paths } from "../shared/config.ts";
import { v } from "../shared/validate.ts";
import { readServerConfig, readVhost, type OlsVhost } from "./ols.ts";
import { apps, audit, sites, type App, type Route, type Site } from "./state.ts";
import { pm2List, pm2Ref } from "./pm2.ts";
import { exists, readText, run } from "./sys.ts";

export type ImportSite = Omit<Site, "created_at" | "deny_paths" | "converted_from" | "crons"> & { wordpress: boolean; wpProxyReady: boolean; databases: string[] };
export type ImportApp = Pick<App, "name" | "external_unit" | "upstream"> & { ports: number[]; process: string };
export type ImportPlan = {
  cyberpanel: { installed: boolean; version: string; services: Record<string, string> };
  sites: ImportSite[];
  apps: ImportApp[];
  warnings: string[];
};

const OLS_CONF = `${paths.ols}/conf/httpd_config.conf`;

/** The validator's result, or "" when it rejects the value. */
const attempt = (f: () => string) => {
  try {
    return f();
  } catch {
    return "";
  }
};

function upstreamOf(address: string): string | null {
  const m = address.replace(/^https?:\/\//, "").match(/^(127\.0\.0\.1|localhost|\[::1\]):(\d+)$/);
  return m ? `127.0.0.1:${m[2]}` : null;
}

function classify(vh: OlsVhost): { kind: Site["kind"]; routes: Route[]; php: string } {
  const routes: Route[] = [];
  for (const c of vh.contexts) {
    if (c.type !== "proxy") continue;
    const proc = vh.processors.find((p) => p.name === c.handler);
    const up = proc && upstreamOf(proc.address);
    if (up) routes.push({ path: c.uri.replace(/\/+$/, "") || "/", upstream: up });
  }
  // Pure reverse proxies go straight from the edge to the app. Anything with
  // PHP, static files or custom rewrite rules stays on OpenLiteSpeed (moved to
  // localhost) so it behaves exactly as before.
  if (routes.some((r) => r.path === "/") && !hasCustomRewrites(vh)) return { kind: "proxy", routes, php: "" };
  const ver = vh.processors.find((p) => p.type === "lsapi")?.path.match(/lsphp(\d)(\d+)/);
  return { kind: "legacy", routes, php: ver ? `${ver[1]}.${ver[2]}` : "" };
}

const hasCustomRewrites = (vh: OlsVhost) => /^\s*RewriteRule\b/m.test(vh.rewriteRules);

/** Maps listening ports to the process and systemd unit behind them. */
type PortOwner = { process: string; unit: string; pid: number; user: string };

async function portOwners(): Promise<Map<number, PortOwner>> {
  const out = new Map<number, PortOwner>();
  const passwd = (await readText("/etc/passwd")) ?? "";
  const userOf = (uid: string) => passwd.split("\n").find((l) => l.split(":")[2] === uid)?.split(":")[0] ?? "";
  const r = await run(["ss", "-Htlnp"], { check: false });
  for (const line of r.stdout.split("\n")) {
    const port = Number(line.split(/\s+/)[3]?.split(":").pop());
    const m = line.match(/users:\(\("([^"]+)",pid=(\d+)/);
    if (!port || !m || out.has(port)) continue;
    const cgroup = (await readText(`/proc/${m[2]}/cgroup`)) ?? "";
    const unit = cgroup.match(/\/([^/\n]+\.service)/)?.[1] ?? "";
    const uid = ((await readText(`/proc/${m[2]}/status`)) ?? "").match(/^Uid:\s+(\d+)/m)?.[1] ?? "";
    out.set(port, { process: m[1]!, unit, pid: Number(m[2]), user: userOf(uid) });
  }
  return out;
}

async function cyberpanelDbMap(): Promise<Map<string, string[]>> {
  const map = new Map<string, string[]>();
  const r = await run(
    ["mysql", "--batch", "--skip-column-names", "cyberpanel"],
    { input: "SELECT w.domain, d.dbName FROM databases_databases d JOIN websiteFunctions_websites w ON d.website_id = w.id;", check: false },
  );
  for (const line of r.stdout.split("\n").filter(Boolean)) {
    const [domain, db] = line.split("\t");
    map.set(domain!, [...(map.get(domain!) ?? []), db!]);
  }
  return map;
}

async function suspendedDomains(): Promise<Set<string>> {
  const r = await run(["mysql", "--batch", "--skip-column-names", "cyberpanel"], {
    input: "SELECT domain FROM websiteFunctions_websites WHERE state = 0;",
    check: false,
  });
  return new Set(r.stdout.split("\n").filter(Boolean));
}

export async function scan(): Promise<ImportPlan> {
  const warnings: string[] = [];
  const conf = await readText(OLS_CONF);
  const cpVersion = (await readText(`${paths.cyberpanel}/version.txt`))?.trim() ?? "";
  const services: Record<string, string> = {};
  for (const unit of ["lscpd", "lshttpd", "lsws", "fastapi_ssh_server", "mariadb", "postfix", "dovecot", "pdns", "pure-ftpd"]) {
    const r = await run(["systemctl", "is-active", unit], { check: false });
    const state = r.stdout.trim();
    if (state && state !== "inactive" && state !== "unknown") services[unit] = state;
  }
  const plan: ImportPlan = {
    cyberpanel: { installed: await exists(paths.cyberpanel), version: cpVersion, services },
    sites: [],
    apps: [],
    warnings,
  };
  if (!conf) {
    warnings.push(`${OLS_CONF} not found: nothing to import`);
    return plan;
  }

  const server = readServerConfig(conf);
  const [dbMap, suspended, owners] = await Promise.all([cyberpanelDbMap(), suspendedDomains(), portOwners()]);

  for (const ref of server.vhosts) {
    if (ref.name === "Example") continue;
    const vars = { VH_NAME: ref.name, SERVER_ROOT: paths.ols, VH_ROOT: "" };
    vars.VH_ROOT = ref.vhRoot.replace("$SERVER_ROOT", paths.ols).replace("$VH_NAME", ref.name).replace(/\/$/, "");
    const file = ref.configFile.replace("$SERVER_ROOT", paths.ols).replace("$VH_NAME", ref.name);
    const text = await readText(file);
    if (!text) {
      warnings.push(`${ref.name}: ${file} missing, skipped`);
      continue;
    }
    const vh = readVhost(text, vars);
    const mapped = new Set<string>();
    for (const l of server.listeners) for (const m of l.maps) if (m.vhost === ref.name) m.domains.forEach((d) => mapped.add(d.toLowerCase()));
    if (!mapped.size) [vh.domain, ...vh.aliases].forEach((d) => d && mapped.add(d.toLowerCase()));
    // Everything below lands in pano's state and the edge's config: only well-formed values.
    const domains: string[] = [];
    for (const d of mapped) {
      const clean = d === "*" ? d : attempt(() => v.domain(d));
      if (!clean) warnings.push(`${ref.name}: skipped the domain "${d.slice(0, 80)}" (not a valid host name)`);
      else if (!domains.includes(clean)) domains.push(clean);
    }
    const name = attempt(() => v.siteName(ref.name.replace(/[^a-z0-9.-]/gi, "-").toLowerCase()));
    if (!name || !domains.length) {
      warnings.push(`${ref.name}: skipped (${domains.length ? "unusable name" : "no valid domain"})`);
      continue;
    }
    const { kind, routes, php } = classify(vh);
    const wpConfig = kind === "legacy" ? await readText(`${vh.docRoot}/wp-config.php`) : null;
    // Certificate files: an absolute path or none. syncCerts (edge.ts) copies them only when root owns
    // the files and every directory on the way (sys.ts readRootOwned).
    const pem = (p: string | undefined) => (p && /^\/[^\0\n\r]{1,1024}$/.test(p) ? p : "");
    const site: ImportSite = {
      name,
      kind,
      domains,
      root: vh.docRoot,
      routes,
      ask_url: "",
      php_version: php,
      tls_cert: pem(vh.ssl?.certFile),
      tls_key: pem(vh.ssl?.keyFile),
      source: "cyberpanel",
      enabled: suspended.has(ref.name) ? 0 : 1,
      on_demand_tls: domains.includes("*") ? 1 : 0,
      wordpress: wpConfig !== null,
      wpProxyReady: !!wpConfig && /HTTP_X_FORWARDED_PROTO/.test(wpConfig),
      databases: dbMap.get(ref.name) ?? [],
    };
    plan.sites.push(site);

    if (site.wordpress && !site.wpProxyReady)
      warnings.push(`${site.name}: WordPress behind the edge needs the X-Forwarded-Proto snippet in wp-config.php (see Import page) or it may loop on HTTPS.`);
    if (kind === "legacy" && routes.length)
      warnings.push(`${site.name}: proxies to ${routes.map((r) => r.upstream).join(", ")} but has rewrite rules, so it stays on OpenLiteSpeed. Switch it to "proxy" once the rules are no longer needed.`);
    if (domains.includes("*"))
      warnings.push(`${site.name}: serves any host ("*"). Set an ask URL so only your customers' domains get certificates.`);
    if (domains.some((d) => d.startsWith("*.")) && !site.tls_cert)
      warnings.push(`${site.name}: wildcard domain without a certificate; certificates will be issued per host on demand.`);
    for (const r of routes) {
      const port = Number(r.upstream.split(":")[1]);
      if (!owners.has(port)) warnings.push(`${site.name}: nothing is listening on ${r.upstream} (${r.path})`);
    }
  }

  // Processes behind proxy routes become "external" apps: pano shows their
  // status and logs and can restart them, but does not deploy them.
  const byUnit = new Map<string, ImportApp>();
  for (const s of plan.sites) {
    for (const r of s.routes) {
      const port = Number(r.upstream.split(":")[1]);
      const owner = owners.get(port);
      if (!owner?.unit || /^(lshttpd|lsws|lscpd)\.service$/.test(owner.unit)) continue;
      const name = owner.unit.replace(/\.service$/, "").replace(/[^a-z0-9-]/gi, "-").toLowerCase().slice(0, 24).replace(/-+$/, "");
      const entry = byUnit.get(owner.unit) ?? { name, external_unit: owner.unit, upstream: "", ports: [], process: owner.process };
      if (!entry.ports.includes(port)) entry.ports.push(port);
      entry.upstream = entry.ports.map((p) => `127.0.0.1:${p}`).join(",");
      byUnit.set(owner.unit, entry);
    }
  }
  plan.apps = [...byUnit.values(), ...(await pm2Apps(owners, warnings))];
  return plan;
}

/**
 * Apps PM2 runs (often outside any systemd unit, so the unit scan above misses them): one
 * external app per PM2 app name, for every user that owns a listening port and has a PM2 home.
 * The port comes from the start arguments, or from the socket its process holds (fork mode).
 */
async function pm2Apps(owners: Map<number, PortOwner>, warnings: string[]): Promise<ImportApp[]> {
  const users = [...new Set([...owners.values()].map((o) => o.user).filter(Boolean))];
  const out: ImportApp[] = [];
  for (const user of users) {
    const home = ((await readText("/etc/passwd")) ?? "").split("\n").find((l) => l.startsWith(`${user}:`))?.split(":")[5];
    // Only where a PM2 daemon is running: a bare ~/.pm2 (pm2 tried once) has nothing to list.
    const daemon = home ? (await readText(`${home}/.pm2/pm2.pid`))?.trim() : "";
    if (!daemon || !/^\d+$/.test(daemon) || !(await exists(`/proc/${daemon}`))) continue;
    const list = await pm2List(user).catch((e) => {
      warnings.push(`pm2 (${user}): ${e instanceof Error ? e.message : e}`);
      return [];
    });
    for (const a of list) {
      const ports = a.port ? [a.port] : [...owners].filter(([, o]) => a.pids.includes(o.pid)).map(([p]) => p);
      const name = a.name.replace(/[^a-z0-9-]/gi, "-").toLowerCase().slice(0, 24).replace(/-+$/, "");
      if (!name) continue;
      out.push({ name, external_unit: pm2Ref({ user, name: a.name }), upstream: ports[0] ? `127.0.0.1:${ports[0]}` : "", ports, process: "pm2" });
    }
  }
  return out;
}

/** Re-scans (never trusts a plan sent by the client) and stores the selected items. */
export async function apply(select: { sites: string[]; apps: string[] }, actor: string) {
  const plan = await scan();
  let siteCount = 0;
  let appCount = 0;
  for (const s of plan.sites.filter((x) => select.sites.includes(x.name))) {
    const { wordpress, wpProxyReady, databases, ...site } = s;
    // Already moved to pano's PHP: a re-import must not send it back to OpenLiteSpeed.
    if (sites.get(site.name)?.kind === "php") continue;
    sites.upsert(site);
    siteCount++;
  }
  for (const a of plan.apps.filter((x) => select.apps.includes(x.name))) {
    if (apps.get(a.name)) continue;
    apps.insert({ name: a.name, kind: "external", external_unit: a.external_unit, upstream: a.upstream, domains: [] });
    appCount++;
  }
  audit(actor, "import.apply", { sites: siteCount, apps: appCount });
  return { sites: siteCount, apps: appCount };
}

export const WP_PROXY_SNIPPET = `// Added for pano edge (TLS terminates at Caddy)
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}`;
