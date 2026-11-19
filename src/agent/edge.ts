// The edge: a pano-owned Caddy that terminates TLS on :80/:443 and routes to
// apps (blue/green ports), proxy sites and, for legacy PHP sites, the old
// OpenLiteSpeed server moved to localhost. Caddy runs as its own user with only
// CAP_NET_BIND_SERVICE; the Caddyfile is rendered from state and validated
// before every reload, so a bad change never replaces a working config.

import { lstat, readdir } from "node:fs/promises";
import { DRY_RUN, env, fsPath, paths } from "../shared/config.ts";
import { liveStatic, staticDir } from "../shared/python.ts";
import { remoteDomains } from "./remotedb-config.ts";
import { apps as appStore, previewApp, previews as previewStore, procsOf, settings, sites as siteStore, type App, type Route, type Site } from "./state.ts";
import { cloudflareRanges } from "./cloudflare.ts";
import { ensureDir, exists, readRootOwned, readText, remove, run, showUnits, writeAtomic } from "./sys.ts";
import { mountOptions, viewLocked } from "./viewlock.ts";

export const EDGE_USER = "pano-edge";

/**
 * turnDomain: only set while TURN over TLS is on; dbDomains: the names of database remote access
 * that is on. The edge then holds a certificate for them (see turn.ts, remotedb.ts).
 */
export type EdgeSettings = { email: string; behindCloudflare: boolean; hooksDomain: string; localCerts?: boolean; turnDomain?: string; dbDomains?: string[] };

export function edgeSettings(): EdgeSettings {
  return {
    email: settings.get("edge.email") ?? "",
    behindCloudflare: settings.get("edge.behindCloudflare") === "1",
    hooksDomain: settings.get("edge.hooksDomain") ?? "",
    localCerts: settings.get("edge.localCerts") === "1",
    turnDomain: settings.get("turn.tls") === "1" ? settings.get("turn.domain") ?? "" : "",
    dbDomains: remoteDomains(),
  };
}

/** Caddy's certificate for the domain (its storage layout: certificates/<issuer>/<domain>/<domain>.crt). */
export async function edgeCert(domain: string): Promise<{ cert: string; key: string } | null> {
  const base = `${paths.edgeData}/caddy/certificates`;
  let issuers: string[] = [];
  try {
    issuers = await readdir(fsPath(base));
  } catch {}
  for (const i of issuers) {
    const cert = await readText(`${base}/${i}/${domain}/${domain}.crt`);
    const key = await readText(`${base}/${i}/${domain}/${domain}.key`);
    if (cert?.includes("-----BEGIN CERTIFICATE-----") && key && /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) return { cert, key };
  }
  return null;
}

const certDir = (name: string) => `${paths.certs}/${name}`;

function tlsLine(name: string, hasCert: boolean, onDemand: boolean): string[] {
  if (hasCert) return [`\ttls ${certDir(name)}/cert.pem ${certDir(name)}/key.pem`];
  if (onDemand) return ["\ttls {", "\t\ton_demand", "\t}"];
  return [];
}

function siteAddresses(domains: string[]): string {
  // A "*" catch-all becomes Caddy's "https://" (any host, certificates on demand).
  return domains.map((d) => (d === "*" ? "https://" : d)).join(", ");
}

/**
 * One site block, and with `plainHttp` its twin on port 80 with the same handlers (no redirect to HTTPS:
 * Cloudflare "Flexible" SSL, or a backend that redirects itself). A "*" catch-all keeps its redirect: an
 * "http://" block for any host would sit in front of every other site's redirect. ACME HTTP-01 still
 * works on the twin: Caddy answers /.well-known/acme-challenge/ before any route.
 */
function blocks(hosts: string[], tls: string[], body: string[], log: string, plainHttp: boolean): string[] {
  const out = [`${siteAddresses(hosts)} {`, "\timport pano_common", ...tls, ...body, ...logBlock(log), "}", ""];
  const plain = plainHttp ? hosts.filter((h) => h !== "*") : [];
  if (plain.length) out.push(`${plain.map((h) => `http://${h}`).join(", ")} {`, "\timport pano_common", ...body, ...logBlock(log), "}", "");
  return out;
}

/**
 * What a suspended site or app answers: a fixed page, 503 with Retry-After, nothing from the tenant and
 * no backend contacted. Backticks and no braces: Caddy takes the body as is (no placeholders).
 */
export const SUSPENDED_PAGE =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">' +
  "<title>Site suspended</title></head>" +
  '<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f6f8;color:#1d2433;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif">' +
  '<main style="max-width:32rem;padding:2rem;text-align:center"><h1 style="margin:0 0 .5rem;font-size:1.5rem">This site is suspended</h1>' +
  '<p style="margin:0;color:#5b6475">Please contact the site owner or the hosting provider.</p></main></body></html>';

const SUSPENDED_SNIPPET = [
  "(pano_suspended) {",
  "\thandle {",
  '\t\theader Content-Type "text/html; charset=utf-8"',
  '\t\theader Cache-Control "no-store"',
  "\t\theader Retry-After 3600",
  `\t\trespond \`${SUSPENDED_PAGE}\` 503`,
  "\t}",
  "}",
  "",
];
const SUSPENDED_BODY = ["\timport pano_suspended"];

const WWW_APEX = ["\t@pano_www header_regexp pano_www Host ^www\\.([^:]+)", "\tredir @pano_www https://{re.pano_www.1}{uri} 301"];

function logBlock(name: string): string[] {
  return [
    "\tlog {",
    `\t\toutput file ${paths.accessLogs}/${name}.log {`,
    "\t\t\troll_size 10MiB",
    "\t\t\troll_keep 5",
    "\t\t}",
    "\t}",
  ];
}

export function activePort(a: App): number {
  if (a.kind === "external") return Number(a.upstream.split(":").pop());
  return a.active_slot === "b" ? a.port_b : a.port_a;
}

export const phpSocket = (site: string) => `${paths.phpRun}/${site}/fpm.sock`;

/** Host -> path routes of an app, pointing at the active slot of each web process. */
export function appRoutes(a: App): Map<string, Route[]> {
  const out = new Map<string, Route[]>();
  const add = (host: string, path: string, port: number) => out.set(host, [...(out.get(host) ?? []), { path, upstream: `127.0.0.1:${port}` }]);
  if (a.kind === "external") {
    for (const d of a.domains) add(d, "/", activePort(a));
    return out;
  }
  for (const p of procsOf(a)) {
    if (!p.port_a) continue;
    const port = a.active_slot === "b" ? p.port_b : p.port_a;
    for (const r of p.routes) {
      const i = r.indexOf("/");
      add(i < 0 ? r : r.slice(0, i), i < 0 ? "/" : r.slice(i), port);
    }
  }
  // Collected static files (Python apps): the edge answers these paths itself, on every host of the app.
  const urls = a.active_slot && a.runtime === "python" ? liveStatic(a.static_live) : [];
  if (urls.length) {
    for (const host of [...out.keys()]) {
      urls.forEach((url, i) => out.set(host, [...out.get(host)!, { path: url, upstream: "", static: staticDir(a.name, a.active_slot, i) }]));
    }
  }
  return out;
}

/** Path-prefix handles, most specific first; "/" is the fallback. */
function routeLines(routes: Route[], notFound = false): string[] {
  const sorted = [...routes].sort((x, y) => y.path.length - x.path.length);
  const out: string[] = [];
  // A redirect route answers itself; the target was checked by parseSiteRoutes (no spaces, quotes or braces but {uri}).
  // The "*" matcher is needed: Caddy would read a target starting with "/" as a path matcher.
  const action = (r: Route, prefix = "") =>
    r.static
      ? [`\t\turi strip_prefix ${prefix}`, `\t\troot * ${r.static}`, '\t\theader ?Cache-Control "public, max-age=3600"', "\t\tfile_server"].join("\n")
      : r.redirect ? `\t\tredir * ${r.redirect} ${r.code ?? 301}` : `\t\treverse_proxy ${r.upstream}`;
  sorted.forEach((r, i) => {
    if (r.path === "/") return;
    const prefix = r.path.replace(/\/$/, "");
    out.push(`\t@route${i} path ${prefix} ${prefix}/*`, `\thandle @route${i} {`, action(r, prefix), "\t}");
  });
  const root = sorted.find((r) => r.path === "/");
  if (root) out.push("\thandle {", action(root), "\t}");
  else if (notFound) out.push("\thandle {", "\t\trespond 404", "\t}");
  return out;
}

// Never served from a PHP site: dotfiles (.env, .git, .htaccess), dumps and
// backups, composer manifests, and PHP inside WordPress uploads (also as x.php/y.jpg, which
// php_fastcgi splits into the script x.php and a path info).
const PHP_DENY = String.raw`(?i)(/\.|\.(sql|bak|old|orig|swp|ini|log|sh|env|dist|config)$|/composer\.(json|lock)$|/wp-content/uploads/.*\.(php\d?|phtml|phar)(/|$))`;

/** Dotfiles and dumps/backups are never served from a static root either (.env, .git, a forgotten .sql). */
const STATIC_DENY = String.raw`(?i)(/\.|\.(sql|bak|old|orig|swp)$)`;

/**
 * Where the edge reads site files: a read-only bind of the sites directory mounted nosymfollow
 * (Linux 5.10+; with util-linux before 2.38 by mount(2), see VIEW_LOCK), so a link a site plants (to a TLS key, another site's
 * wp-config.php) is never followed. Without it PHP sites are held offline (HELD_BODY), unless root
 * set PANO_EDGE_FOLLOW_LINKS=1: then the edge reads the real paths and a daily sweep removes links
 * that lead out of a site (shield.ts).
 */
export const EDGE_VIEW = "/srv/pano/edgeview";

/**
 * Static sites live under /var/www, which the edge reads the same way: through its own read-only,
 * nosymfollow view, so a link that whoever writes a static root plants (to a TLS key, to what pano-edge
 * may read) is never followed. Roots elsewhere, or without the view, are held offline like PHP sites.
 */
export const WWW_ROOT = "/var/www";
export const WWW_VIEW = "/srv/pano/wwwview";

/** Which no-symlink views are mounted and locked: the sites directory's and /var/www's. */
export type EdgeViews = { sites: boolean; www: boolean };
export const NO_VIEWS: EdgeViews = { sites: false, www: false };

/** The view's path for a static root under /var/www; null for roots elsewhere (never served from the real path). */
export function wwwViewPath(root: string): string | null {
  const r = root.replace(/\/+/g, "/").replace(/(.)\/$/, "$1");
  return r === WWW_ROOT ? WWW_VIEW : r.startsWith(`${WWW_ROOT}/`) ? WWW_VIEW + r.slice(WWW_ROOT.length) : null;
}

/** pano's own tree: apps, sites, the edge views, Python static files, containers. */
const PANO_SRV = "/srv/pano";

/** A static root the edge must never publish: inside pano's own tree, or a directory above it ("/srv"). */
export function forbiddenStaticRoot(root: string): boolean {
  const r = root.replace(/\/+/g, "/").replace(/(.)\/$/, "$1");
  return r === PANO_SRV || r.startsWith(`${PANO_SRV}/`) || r === "/" || PANO_SRV.startsWith(`${r}/`);
}

/**
 * Sites whose files the edge cannot serve safely, held offline: a static root in pano's own tree, and,
 * unless PANO_EDGE_FOLLOW_LINKS=1, every PHP site without the sites view and every static site whose
 * root is not under /var/www or lacks that view.
 */
export function heldByEdge(list: Site[], views: EdgeViews, followLinks: boolean): Site[] {
  return list.filter(
    (s) =>
      (s.kind === "static" && (forbiddenStaticRoot(s.root) || (!(views.www && wwwViewPath(s.root)) && !followLinks))) ||
      (s.kind === "php" && !(views.sites && viewPath(s.root)) && !followLinks),
  );
}

/** What a site answers when the edge cannot serve its files safely: a fixed 503, nothing read from disk. */
const HELD_BODY = ["\theader Retry-After 3600", '\trespond "Service temporarily unavailable" 503'];

/** systemd's unit name for a mount at a path (as `systemd-escape --path --suffix=mount`). */
export function mountUnitName(path: string): string {
  const p = path.replace(/\/+/g, "/").replace(/^\/|\/$/g, "");
  if (!p) return "-.mount";
  const esc = [...p].map((c, i) => (c === "/" ? "-" : /[A-Za-z0-9:_]/.test(c) || (c === "." && i > 0) ? c : `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`));
  return `${esc.join("")}.mount`;
}

export const EDGE_VIEW_UNIT = mountUnitName(EDGE_VIEW);

/** The view's path for a root under the sites directory; null for roots elsewhere (served as they are). */
export function viewPath(root: string): string | null {
  return root.startsWith(`${paths.sites}/`) ? EDGE_VIEW + root.slice(paths.sites.length) : null;
}

const PHP_TRY_FILES = "{path} {path}/index.php {path}/index.html {path}/index.htm index.php";

function phpLines(site: Site, view: boolean): string[] {
  const served = view ? viewPath(site.root) : null;
  const out = [`\troot * ${served ?? site.root}`, "\t@pano_deny {", `\t\tpath_regexp ${PHP_DENY}`, "\t\tnot path /.well-known/*", "\t}", "\trespond @pano_deny 404"];
  if (site.deny_paths.length) {
    out.push(`\t@pano_deny_dirs path ${site.deny_paths.flatMap((p) => (p === "/" ? ["*"] : [p, `${p}/*`])).join(" ")}`, "\trespond @pano_deny_dirs 404");
  }
  // Static files and php_fastcgi's file matchers (try_files, index.php) use the root above, the view;
  // PHP-FPM gets the real paths (SCRIPT_FILENAME, DOCUMENT_ROOT) through the transport's own root.
  // A directory with only an index.html (sites brought over from OpenLiteSpeed) serves it; Caddy's
  // default goes from {path} straight to index.php and answers "/" with PHP's "No input file specified".
  out.push(`\tphp_fastcgi unix/${phpSocket(site.name)} {`, `\t\ttry_files ${PHP_TRY_FILES}`);
  if (served) out.push(`\t\troot ${site.root}`);
  out.push("\t}");
  out.push(...ASSET_CACHE, "\tfile_server");
  return out;
}

// Static files get a browser cache lifetime unless the site sets its own
// (WordPress and most themes version their URLs with ?ver=).
const ASSET_CACHE = [
  "\t@pano_assets path *.css *.js *.mjs *.woff *.woff2 *.ttf *.otf *.svg *.png *.jpg *.jpeg *.gif *.webp *.avif *.ico *.mp4 *.webm *.pdf",
  '\theader @pano_assets ?Cache-Control "public, max-age=604800"',
];

/** A live preview, as the synthetic app the deploy code built (see previewApp), and the app it belongs to. */
export type EdgePreview = { parent: string; app: App };

/**
 * edgeView: the no-symlink view of the sites directory is mounted (see EDGE_VIEW); without it PHP sites
 * are held offline unless followLinks (PANO_EDGE_FOLLOW_LINKS=1) serves them from the real paths.
 */
export function renderCaddyfile(input: { apps: App[]; sites: Site[]; settings: EdgeSettings; certs: Set<string>; banned?: string[]; previews?: EdgePreview[]; edgeView?: boolean; wwwView?: boolean; followLinks?: boolean }): string {
  const { settings: s } = input;
  const view = !!input.edgeView;
  const www = !!input.wwwView;
  const held = new Set(heldByEdge(input.sites, { sites: view, www }, !!input.followLinks).map((x) => x.name));
  const out: string[] = [
    "# Managed by pano. Every change here is overwritten; edit through the panel.",
    "{",
    `\tadmin unix/${paths.caddyAdmin}`,
    ...(s.email ? [`\temail ${s.email}`] : []),
    // Staging/test servers: certificates from Caddy's own CA instead of Let's Encrypt.
    ...(s.localCerts ? ["\tlocal_certs", "\tskip_install_trust"] : []),
    "\tgrace_period 20s",
    "\tservers {",
    "\t\tprotocols h1 h2 h3",
    ...(s.behindCloudflare
      ? [`\t\ttrusted_proxies static ${cloudflareRanges().join(" ")}`, "\t\tclient_ip_headers CF-Connecting-IP X-Forwarded-For"]
      : []),
    "\t}",
    "\ton_demand_tls {",
    `\t\task http://127.0.0.1:${env.askPort}/ask`,
    "\t}",
    "}",
    "",
    "(pano_common) {",
    "\tencode zstd gzip",
    "\theader {",
    '\t\tStrict-Transport-Security "max-age=31536000"',
    '\t\tX-Content-Type-Options "nosniff"',
    '\t\tReferrer-Policy "strict-origin-when-cross-origin"',
    "\t\t-Server",
    "\t\t-X-Powered-By",
    "\t}",
    // Addresses the shield caught brute-forcing logins (client_ip: the real visitor, also behind Cloudflare).
    // Without Cloudflare the kernel drops them already (shield.ts); this covers visitors behind a proxy.
    ...(input.banned?.length ? [`\t@pano_banned client_ip ${input.banned.join(" ")}`, "\thandle @pano_banned {", '\t\trespond "Too many login attempts" 429', "\t}"] : []),
    "}",
    "",
  ];
  const anySuspended =
    input.apps.some((a) => a.suspended) || input.sites.some((x) => !x.enabled && x.domains.length) || (input.previews ?? []).some((p) => p.app.suspended);
  if (anySuspended) out.push(...SUSPENDED_SNIPPET);

  if (s.hooksDomain) {
    // Only the webhook endpoint is public; the panel itself never is.
    out.push(
      `${s.hooksDomain} {`,
      "\timport pano_common",
      `\thandle /hooks/* {`,
      `\t\treverse_proxy 127.0.0.1:${env.hookPort}`,
      "\t}",
      "\trespond 404",
      "}",
      "",
    );
  }

  // Nothing is served here; the blocks make Caddy obtain and renew the certificates that coturn
  // (turns:) and the databases (remote access over TLS) use. One block per name, even when they share it.
  for (const d of new Set([s.turnDomain, ...(s.dbDomains ?? [])].filter((x): x is string => !!x))) {
    out.push(`${d} {`, "\timport pano_common", "\trespond 404", "}", "");
  }

  for (const a of input.apps) {
    const plainHttp = a.http_redirect === 0;
    const tls = (hosts: string[]) => tlsLine(`app-${a.name}`, input.certs.has(`app-${a.name}`), hosts.some((h) => h.includes("*")));
    if (a.suspended) {
      // Every host of the app, deployed or not, gets the notice (and keeps its certificate).
      const hosts = [...appRoutes(a).keys()];
      if (hosts.length) out.push(...blocks(hosts, tls(hosts), SUSPENDED_BODY, `app-${a.name}`, plainHttp));
      continue;
    }
    if (a.kind === "managed" && !a.active_slot) continue;
    // Hosts with the same routes share one block (example.com, www.example.com).
    const groups = new Map<string, { hosts: string[]; routes: Route[] }>();
    for (const [host, routes] of appRoutes(a)) {
      const key = JSON.stringify([...routes].sort((x, y) => x.path.localeCompare(y.path)));
      const g = groups.get(key) ?? { hosts: [], routes };
      g.hosts.push(host);
      groups.set(key, g);
    }
    for (const { hosts, routes } of groups.values()) {
      const single = routes.length === 1 && routes[0]!.path === "/";
      out.push(...blocks(hosts, tls(hosts), single ? [`\treverse_proxy ${routes[0]!.upstream}`] : routeLines(routes, true), `app-${a.name}`, plainHttp));
    }
  }

  // Previews: one exact host each. Certificates are issued on demand, and the ask endpoint
  // (agent main.ts) approves only hosts of existing previews. A suspended app's previews are suspended too.
  for (const { parent, app: pv } of input.previews ?? []) {
    if (!pv.active_slot) continue;
    for (const [host, routes] of appRoutes(pv)) {
      const single = routes.length === 1 && routes[0]!.path === "/";
      const body = pv.suspended ? SUSPENDED_BODY : single ? [`\treverse_proxy ${routes[0]!.upstream}`] : routeLines(routes, true);
      out.push(...blocks([host], tlsLine("", false, true), body, `preview-${parent}`, false));
    }
  }

  for (const site of input.sites) {
    if (!site.domains.length) continue;
    const onDemand = !!site.on_demand_tls || site.domains.includes("*");
    let body: string[];
    if (!site.enabled) {
      // Suspended: the domains stay on the edge (certificates keep renewing), nothing reaches the site.
      body = SUSPENDED_BODY;
    } else if (site.kind === "legacy") {
      // Imported PHP/static/rewrite-heavy sites stay on OpenLiteSpeed, now on localhost only.
      // Caddy adds X-Forwarded-For/-Proto/-Host and keeps the Host header.
      body = [`\treverse_proxy 127.0.0.1:${env.olsBackendPort}`];
    } else if (held.has(site.name)) {
      // Fail closed: without the no-symlink view the edge would read the real paths (and follow links).
      body = HELD_BODY;
    } else if (site.kind === "static") {
      body = [`\troot * ${(www && wwwViewPath(site.root)) || site.root}`, "\t@pano_deny {", `\t\tpath_regexp ${STATIC_DENY}`, "\t\tnot path /.well-known/*", "\t}", "\trespond @pano_deny 404", ...ASSET_CACHE, "\tfile_server"];
    } else if (site.kind === "php") {
      body = phpLines(site, view);
    } else {
      body = routeLines(site.routes);
    }
    // www.<host> -> https://<host>, same path and query (redir runs before the site's handlers).
    if (site.enabled && site.www_apex && site.kind !== "legacy") body = [...WWW_APEX, ...body];
    const hasCert = input.certs.has(`site-${site.name}`);
    const named = site.domains.filter((d) => d !== "*");
    if (hasCert && named.length < site.domains.length) {
      // A file certificate on a catch-all would be Caddy's choice for every name on the server (its
      // connection policy has no SNI to match), so other sites would get this one. The listed names
      // keep the file; any other host gets its own certificate on demand.
      if (named.length) out.push(...blocks(named, tlsLine(`site-${site.name}`, true, false), body, `site-${site.name}`, site.http_redirect === 0));
      out.push(...blocks(["*"], tlsLine("", false, true), body, `site-${site.name}`, false));
    } else {
      out.push(...blocks(site.domains, tlsLine(`site-${site.name}`, hasCert, onDemand), body, `site-${site.name}`, site.http_redirect === 0));
    }
  }
  return out.join("\n");
}

/**
 * Set when a copied certificate's content changed (renewed by certbot/acme.sh at the same path): the
 * Caddyfile stays the same, but Caddy reads certificate files only on a reload.
 */
let certsRenewed = false;

/** Copies imported certificate files where only the edge user can read them. */
async function syncCerts(): Promise<Set<string>> {
  const have = new Set<string>();
  const want: { id: string; cert: string; key: string }[] = siteStore
    .list()
    // Suspended sites too: the edge still serves their domains (the suspended page).
    .filter((s) => s.tls_cert && s.tls_key)
    .map((s) => ({ id: `site-${s.name}`, cert: s.tls_cert, key: s.tls_key }));
  for (const w of want) {
    // Only files root put there (owner of the file, every directory and link on the way), so a path under a
    // tenant's home can never be pointed at another key; and only PEM goes to the edge.
    const cert = await readRootOwned(w.cert);
    const key = await readRootOwned(w.key);
    if (!cert?.includes("-----BEGIN CERTIFICATE-----") || !key || !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) continue;
    await ensureDir(certDir(w.id), 0o750);
    const old = await readText(`${certDir(w.id)}/cert.pem`);
    if (old !== null && old !== cert) certsRenewed = true;
    await writeAtomic(`${certDir(w.id)}/cert.pem`, cert, 0o640);
    await writeAtomic(`${certDir(w.id)}/key.pem`, key, 0o640);
    await run(["chgrp", "-R", EDGE_USER, fsPath(certDir(w.id))], { check: false });
    have.add(w.id);
  }
  return have;
}

export async function buildCaddyfile(): Promise<string> {
  const certs = await syncCerts();
  const banned = (JSON.parse(settings.get("shield.bans") ?? "[]") as string[]).filter((ip) => /^[0-9a-fA-F:.]{3,45}$/.test(ip));
  const previews = previewStore.list().flatMap((pv) => {
    const parent = appStore.get(pv.app);
    return parent ? [{ parent: parent.name, app: previewApp(parent, pv) }] : [];
  });
  return renderCaddyfile({ apps: appStore.list(), sites: siteStore.list(), settings: edgeSettings(), certs, banned, previews, edgeView: await edgeViewMounted(), wwwView: await viewMountedAt(WWW_VIEW), followLinks: env.edgeFollowLinks });
}

/**
 * The view is mounted, read-only and nosymfollow, as the host sees it. Checked on the mount itself: an old
 * libmount accepts the option and silently drops it (viewlock.ts sets it then). `pid`: the view as that
 * process sees it (the running edge, in its own namespace: a copy made when it started).
 */
export async function edgeViewMounted(pid = "1"): Promise<boolean> {
  return viewMountedAt(EDGE_VIEW, pid);
}

/** Like edgeViewMounted, for any of the views. */
export async function viewMountedAt(view: string, pid = "1"): Promise<boolean> {
  const info = (await readText(`/proc/${pid}/mountinfo`)) ?? (pid === "1" ? await readText("/proc/self/mountinfo") : null) ?? "";
  return viewLocked(mountOptions(info, view));
}

export async function edgeInstalled() {
  return exists(paths.caddy);
}

export async function edgeActive(): Promise<boolean> {
  const r = await run(["systemctl", "is-active", "pano-edge"], { check: false });
  return r.stdout.trim() === "active";
}

/**
 * Renders, validates and (if the edge is running) reloads. The previous file is
 * kept, so a failed validation leaves the live config untouched.
 */
export async function applyEdge(): Promise<{ changed: boolean; reloaded: boolean }> {
  certsRenewed = false;
  const next = await buildCaddyfile();
  const current = await readText(paths.caddyfile);
  if (current === next) {
    if (!certsRenewed || !(await edgeActive())) return { changed: false, reloaded: false };
    await run(["systemctl", "reload", "pano-edge"]);
    return { changed: false, reloaded: true };
  }
  const candidate = `${paths.caddyfile}.next`;
  await writeAtomic(candidate, next, 0o640);
  await run(["chgrp", EDGE_USER, fsPath(candidate)], { check: false });
  if (await edgeInstalled()) {
    await run(["chown", "-R", `${EDGE_USER}:${EDGE_USER}`, fsPath(paths.accessLogs)], { check: false });
    // Validate as the edge user: it opens log files and certificates exactly as the live server would.
    const r = await run([fsPath(paths.caddy), "validate", "--config", fsPath(candidate), "--adapter", "caddyfile"], {
      check: false,
      user: EDGE_USER,
      env: { HOME: paths.edgeData, XDG_DATA_HOME: paths.edgeData, XDG_CONFIG_HOME: paths.edgeData },
    });
    if (r.code !== 0) {
      await remove(candidate);
      throw new Error(`edge config rejected: ${(r.stderr || r.stdout).trim().split("\n").slice(-2).join(" ")}`);
    }
  }
  if (current !== null) await writeAtomic(`${paths.caddyfile}.prev`, current, 0o640);
  await writeAtomic(paths.caddyfile, next, 0o640);
  await run(["chgrp", EDGE_USER, fsPath(paths.caddyfile)], { check: false });
  await remove(candidate);
  if (await edgeActive()) {
    await run(["systemctl", "reload", "pano-edge"]);
    return { changed: true, reloaded: true };
  }
  return { changed: true, reloaded: false };
}

// ---- installing Caddy ------------------------------------------------------

export async function installCaddy(version?: string): Promise<string> {
  const arch = process.arch === "arm64" ? "arm64" : "amd64";
  let ver = version;
  if (!ver) {
    const res = await fetch("https://api.github.com/repos/caddyserver/caddy/releases/latest", { headers: { "user-agent": "pano" } });
    if (!res.ok) throw new Error(`GitHub API: ${res.status}`);
    ver = String(((await res.json()) as { tag_name: string }).tag_name).replace(/^v/, "");
  }
  if (!/^\d+\.\d+\.\d+$/.test(ver)) throw new Error(`unexpected Caddy version ${ver}`);
  const base = `https://github.com/caddyserver/caddy/releases/download/v${ver}`;
  const file = `caddy_${ver}_linux_${arch}.tar.gz`;
  const [tar, sums] = await Promise.all([fetch(`${base}/${file}`), fetch(`${base}/caddy_${ver}_checksums.txt`)]);
  if (!tar.ok || !sums.ok) throw new Error("Caddy download failed");
  const bytes = new Uint8Array(await tar.arrayBuffer());
  const expected = (await sums.text()).split("\n").find((l) => l.trim().endsWith(file))?.split(/\s+/)[0];
  const actual = new Bun.CryptoHasher("sha512").update(bytes).digest("hex");
  if (!expected || expected !== actual) throw new Error("Caddy checksum mismatch, refusing to install");
  const tmp = `${paths.data}/tmp/caddy-${ver}`;
  await ensureDir(tmp, 0o700);
  await Bun.write(fsPath(`${tmp}/${file}`), bytes);
  await run(["tar", "-xzf", fsPath(`${tmp}/${file}`), "-C", fsPath(tmp), "caddy"]);
  await ensureDir(paths.bin, 0o755);
  await run(["install", "-m", "0755", "-o", "root", "-g", "root", fsPath(`${tmp}/caddy`), fsPath(paths.caddy)]);
  await remove(tmp);
  return ver;
}

/**
 * The edge's unit. It never sees the real sites directory or /var/www: it reads them through their views
 * (and requires each view it uses, mount and lock), and without a view the sites there are held offline.
 * Only PANO_EDGE_FOLLOW_LINKS=1 lets it at a real directory whose view is missing.
 */
export function edgeUnit(views: EdgeViews, followLinks = false): string {
  const used = VIEWS.filter((x) => views[x.key]).flatMap((x) => [x.mount, x.lock]);
  const hidden = VIEWS.filter((x) => views[x.key] || !followLinks).map((x) => `-${x.parent}`);
  return `[Unit]
Description=pano edge (Caddy)
After=network-online.target${used.map((u) => ` ${u}`).join("")}
Wants=network-online.target
${used.length ? `Requires=${used.join(" ")}\n` : ""}
[Service]
Type=notify
User=${EDGE_USER}
Group=${EDGE_USER}
ExecStart=${paths.caddy} run --environ --config ${paths.caddyfile} --adapter caddyfile
ExecReload=${paths.caddy} reload --config ${paths.caddyfile} --adapter caddyfile --address unix/${paths.caddyAdmin} --force
Environment=XDG_DATA_HOME=${paths.edgeData} XDG_CONFIG_HOME=${paths.edgeData}
RuntimeDirectory=pano-edge
RuntimeDirectoryMode=0750
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictRealtime=true
ProtectClock=true
ProtectKernelLogs=true
ProtectHostname=true
ReadWritePaths=${paths.edgeData} ${paths.accessLogs}
${hidden.length ? `InaccessiblePaths=${hidden.join(" ")}\n` : ""}LimitNOFILE=1048576
TimeoutStopSec=30s
Restart=on-failure

[Install]
WantedBy=multi-user.target
`;
}

/** A read-only bind of `parent` at `view` on which no symlink is followed (see EDGE_VIEW, WWW_VIEW). */
export function viewMount(parent: string, view: string, what: string): string {
  return `[Unit]
Description=pano: ${what} for the edge (read-only, symlinks not followed)
RequiresMountsFor=${parent}

[Mount]
What=${parent}
Where=${view}
Type=none
Options=bind,ro,nosymfollow
DirectoryMode=0755

[Install]
WantedBy=multi-user.target
`;
}

/**
 * Runs `pano edge-view-lock <view>` after the mount and before the edge, in the host's mount namespace (no
 * sandboxing here on purpose): where mount(8) dropped nosymfollow (util-linux before 2.38) it remounts the
 * view with mount(2), then proves it with a real link (viewlock.ts). Failing, it keeps the edge (which
 * requires it) from starting on a view that follows links, until the agent renders it without the view.
 */
export function viewLock(mount: string, view: string, what: string): string {
  return `[Unit]
Description=pano: no symlinks followed in the edge's view of ${what}
Requires=${mount}
After=${mount}
Before=pano-edge.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${paths.bin}/pano edge-view-lock ${view}

[Install]
WantedBy=multi-user.target
`;
}

export const VIEW_LOCK_UNIT = "pano-edgeview-lock.service";
export const WWW_VIEW_UNIT = mountUnitName(WWW_VIEW);
export const WWW_LOCK_UNIT = "pano-wwwview-lock.service";
export const VIEW_MOUNT = viewMount(paths.sites, EDGE_VIEW, "site files");
export const VIEW_LOCK = viewLock(EDGE_VIEW_UNIT, EDGE_VIEW, "site files");

/** The views the edge reads site files through. */
export const VIEWS = [
  { key: "sites", parent: paths.sites, view: EDGE_VIEW, mount: EDGE_VIEW_UNIT, lock: VIEW_LOCK_UNIT, mountUnit: VIEW_MOUNT, lockUnit: VIEW_LOCK },
  {
    key: "www", parent: WWW_ROOT, view: WWW_VIEW, mount: WWW_VIEW_UNIT, lock: WWW_LOCK_UNIT,
    mountUnit: viewMount(WWW_ROOT, WWW_VIEW, "static sites"), lockUnit: viewLock(WWW_VIEW_UNIT, WWW_VIEW, "static sites"),
  },
] as const satisfies readonly { key: keyof EdgeViews; parent: string; view: string; mount: string; lock: string; mountUnit: string; lockUnit: string }[];

/**
 * Mounts a view and makes sure the kernel really applied nosymfollow (by mount(2) where util-linux before
 * 2.38 drops it, see viewLock). When it still did not (Linux before 5.10, or the remount failed), the
 * mount is left off and the sites it holds are held offline (see EDGE_VIEW, WWW_VIEW).
 */
/**
 * The directory a view shows. pano's own sites directory is kept at 0755; /var/www belongs to the host:
 * created only when missing, never chmodded, and a symlink or non-directory there means no view.
 */
export async function ensureViewParent(parent: string): Promise<boolean> {
  if (parent !== WWW_ROOT) {
    await ensureDir(parent, 0o755);
    return true;
  }
  let st;
  try {
    st = await lstat(fsPath(parent));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    await ensureDir(parent, 0o755);
    return true;
  }
  return st.isDirectory() && !st.isSymbolicLink();
}

async function ensureView(x: (typeof VIEWS)[number]): Promise<boolean> {
  if (!(await ensureViewParent(x.parent))) return false;
  await writeAtomic(`${paths.systemd}/${x.mount}`, x.mountUnit, 0o644);
  await writeAtomic(`${paths.systemd}/${x.lock}`, x.lockUnit, 0o644);
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", "--now", x.mount], { check: false });
  await run(["systemctl", "enable", x.lock], { check: false });
  // A lock that already ran stays active (RemainAfterExit) and would not check again on start; restarting
  // it also restarts the edge (Requires=), so only when the view lacks the flag.
  await run(["systemctl", (await viewMountedAt(x.view)) ? "start" : "restart", x.lock], { check: false });
  return viewMountedAt(x.view);
}

/** Edge user, directories, the views and the unit; idempotent. Which views the edge reads sites through. */
export async function setupEdgeUnit(): Promise<EdgeViews> {
  await ensureUser(EDGE_USER, paths.edgeData);
  await ensureDir(paths.edgeData, 0o700, EDGE_USER);
  await ensureDir(paths.logs, 0o711);
  await ensureDir(paths.accessLogs, 0o750, EDGE_USER);
  await run(["chown", "-R", `${EDGE_USER}:${EDGE_USER}`, fsPath(paths.accessLogs), fsPath(paths.edgeData)], { check: false });
  await ensureDir(paths.certs, 0o750);
  await run(["chgrp", EDGE_USER, fsPath(paths.certs)], { check: false });
  const views = { ...NO_VIEWS };
  for (const x of VIEWS) views[x.key] = await ensureView(x);
  await writeAtomic(`${paths.systemd}/pano-edge.service`, edgeUnit(views, env.edgeFollowLinks), 0o644);
  await run(["systemctl", "daemon-reload"]);
  // Off only once the edge no longer requires them (stopping a required unit stops the edge too).
  for (const x of VIEWS) if (!views[x.key]) await run(["systemctl", "disable", "--now", x.lock, x.mount], { check: false });
  return views;
}

/**
 * Restart first, config second: a running edge's mount namespace is a copy made when it started, and
 * nosymfollow set later (the lock) does not reach it, while a new mount does. Reloading onto view paths
 * before the restart would let that edge read through a view that still follows links. In between, the
 * restarted edge serves the old config, which never names the view without the flag (real paths are hidden
 * from it, held sites stay held).
 */
export async function restartThenApply(needRestart: boolean, restart: () => Promise<unknown>, apply: () => Promise<unknown>) {
  if (needRestart) await restart();
  await apply();
}

/**
 * At agent start and daily (shield.ts): brings existing installs onto the view, and back to the real
 * paths if the view is gone (a kernel that cannot nosymfollow after a reboot: the edge, which requires
 * the mount, would not start). The edge restarts only when its unit changed or its copy of the view lacks
 * the flag (it was set after the edge started).
 */
export async function refreshEdgeView(): Promise<EdgeViews> {
  if (DRY_RUN || !(await edgeInstalled())) return { ...NO_VIEWS };
  const before = await readText(`${paths.systemd}/pano-edge.service`);
  const views = await setupEdgeUnit();
  const pid = (await showUnits(["pano-edge.service"], ["MainPID"])).get("pano-edge.service")?.MainPID ?? "0";
  let stale = false;
  if (/^[1-9]\d*$/.test(pid)) for (const x of VIEWS) if (views[x.key] && !(await viewMountedAt(x.view, pid))) stale = true;
  const enabled = (await run(["systemctl", "is-enabled", "pano-edge"], { check: false })).stdout.trim() === "enabled";
  await restartThenApply(
    enabled && (stale || before !== edgeUnit(views, env.edgeFollowLinks)),
    () => run(["systemctl", "restart", "pano-edge"], { check: false }),
    () => applyEdge().catch((e) => console.error(`[agent] edge view: ${e instanceof Error ? e.message : e}`)),
  );
  return views;
}

export async function ensureUser(user: string, home: string) {
  const r = await run(["id", "-u", user], { check: false });
  if (r.code === 0) return;
  await run(["useradd", "--system", "--home-dir", home, "--no-create-home", "--shell", "/usr/sbin/nologin", user]);
}
