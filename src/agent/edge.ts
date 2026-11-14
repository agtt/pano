// The edge: a pano-owned Caddy that terminates TLS on :80/:443 and routes to
// apps (blue/green ports), proxy sites and, for legacy PHP sites, the old
// OpenLiteSpeed server moved to localhost. Caddy runs as its own user with only
// CAP_NET_BIND_SERVICE; the Caddyfile is rendered from state and validated
// before every reload, so a bad change never replaces a working config.

import { readdir } from "node:fs/promises";
import { DRY_RUN, env, fsPath, paths } from "../shared/config.ts";
import { remoteDomains } from "./remotedb-config.ts";
import { apps as appStore, previewApp, previews as previewStore, procsOf, settings, sites as siteStore, type App, type Route, type Site } from "./state.ts";
import { cloudflareRanges } from "./cloudflare.ts";
import { ensureDir, exists, readRootOwned, readText, remove, run, writeAtomic } from "./sys.ts";

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
  return out;
}

/** Path-prefix handles, most specific first; "/" is the fallback. */
function routeLines(routes: Route[], notFound = false): string[] {
  const sorted = [...routes].sort((x, y) => y.path.length - x.path.length);
  const out: string[] = [];
  sorted.forEach((r, i) => {
    if (r.path === "/") return;
    const prefix = r.path.replace(/\/$/, "");
    out.push(`\t@route${i} path ${prefix} ${prefix}/*`, `\thandle @route${i} {`, `\t\treverse_proxy ${r.upstream}`, "\t}");
  });
  const root = sorted.find((r) => r.path === "/");
  if (root) out.push("\thandle {", `\t\treverse_proxy ${root.upstream}`, "\t}");
  else if (notFound) out.push("\thandle {", "\t\trespond 404", "\t}");
  return out;
}

// Never served from a PHP site: dotfiles (.env, .git, .htaccess), dumps and
// backups, composer manifests, and PHP inside WordPress uploads (also as x.php/y.jpg, which
// php_fastcgi splits into the script x.php and a path info).
const PHP_DENY = String.raw`(?i)(/\.|\.(sql|bak|old|orig|swp|ini|log|sh|env|dist|config)$|/composer\.(json|lock)$|/wp-content/uploads/.*\.(php\d?|phtml|phar)(/|$))`;

/**
 * Where the edge reads site files: a read-only bind of the sites directory mounted nosymfollow
 * (Linux 5.10+), so a link a site plants (to a TLS key, another site's wp-config.php) is never
 * followed. Without it (older kernel) the edge reads the real paths and a daily sweep removes links
 * that lead out of a site (shield.ts).
 */
export const EDGE_VIEW = "/srv/pano/edgeview";

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

function phpLines(site: Site, view: boolean): string[] {
  const served = view ? viewPath(site.root) : null;
  const out = [`\troot * ${served ?? site.root}`, "\t@pano_deny {", `\t\tpath_regexp ${PHP_DENY}`, "\t\tnot path /.well-known/*", "\t}", "\trespond @pano_deny 404"];
  if (site.deny_paths.length) {
    out.push(`\t@pano_deny_dirs path ${site.deny_paths.flatMap((p) => (p === "/" ? ["*"] : [p, `${p}/*`])).join(" ")}`, "\trespond @pano_deny_dirs 404");
  }
  // Static files and php_fastcgi's file matchers (try_files, index.php) use the root above, the view;
  // PHP-FPM gets the real paths (SCRIPT_FILENAME, DOCUMENT_ROOT) through the transport's own root.
  if (served) out.push(`\tphp_fastcgi unix/${phpSocket(site.name)} {`, `\t\troot ${site.root}`, "\t}");
  else out.push(`\tphp_fastcgi unix/${phpSocket(site.name)}`);
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

/** edgeView: the no-symlink view of the sites directory is mounted (see EDGE_VIEW). */
export function renderCaddyfile(input: { apps: App[]; sites: Site[]; settings: EdgeSettings; certs: Set<string>; banned?: string[]; previews?: EdgePreview[]; edgeView?: boolean }): string {
  const { settings: s } = input;
  const view = !!input.edgeView;
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
      out.push(
        `${siteAddresses(hosts)} {`,
        "\timport pano_common",
        ...tlsLine(`app-${a.name}`, input.certs.has(`app-${a.name}`), hosts.some((h) => h.includes("*"))),
        ...(single ? [`\treverse_proxy ${routes[0]!.upstream}`] : routeLines(routes, true)),
        ...logBlock(`app-${a.name}`),
        "}",
        "",
      );
    }
  }

  // Previews: one exact host each. Certificates are issued on demand, and the ask endpoint
  // (agent main.ts) approves only hosts of existing previews.
  for (const { parent, app: pv } of input.previews ?? []) {
    if (!pv.active_slot) continue;
    for (const [host, routes] of appRoutes(pv)) {
      const single = routes.length === 1 && routes[0]!.path === "/";
      out.push(
        `${host} {`,
        "\timport pano_common",
        ...tlsLine("", false, true),
        ...(single ? [`\treverse_proxy ${routes[0]!.upstream}`] : routeLines(routes, true)),
        ...logBlock(`preview-${parent}`),
        "}",
        "",
      );
    }
  }

  for (const site of input.sites) {
    if (!site.enabled || !site.domains.length) continue;
    const onDemand = !!site.on_demand_tls || site.domains.includes("*");
    out.push(`${siteAddresses(site.domains)} {`, "\timport pano_common", ...tlsLine(`site-${site.name}`, input.certs.has(`site-${site.name}`), onDemand));
    if (site.kind === "legacy") {
      // Imported PHP/static/rewrite-heavy sites stay on OpenLiteSpeed, now on localhost only.
      // Caddy adds X-Forwarded-For/-Proto/-Host and keeps the Host header.
      out.push(`\treverse_proxy 127.0.0.1:${env.olsBackendPort}`);
    } else if (site.kind === "static") {
      out.push(`\troot * ${(view && viewPath(site.root)) || site.root}`, ...ASSET_CACHE, "\tfile_server");
    } else if (site.kind === "php") {
      out.push(...phpLines(site, view));
    } else {
      out.push(...routeLines(site.routes));
    }
    out.push(...logBlock(`site-${site.name}`), "}", "");
  }
  return out.join("\n");
}

/** Copies imported certificate files where only the edge user can read them. */
async function syncCerts(): Promise<Set<string>> {
  const have = new Set<string>();
  const want: { id: string; cert: string; key: string }[] = siteStore
    .list()
    .filter((s) => s.enabled && s.tls_cert && s.tls_key)
    .map((s) => ({ id: `site-${s.name}`, cert: s.tls_cert, key: s.tls_key }));
  for (const w of want) {
    // Only files root put there (owner of the file, every directory and link on the way), so a path under a
    // tenant's home can never be pointed at another key; and only PEM goes to the edge.
    const cert = await readRootOwned(w.cert);
    const key = await readRootOwned(w.key);
    if (!cert?.includes("-----BEGIN CERTIFICATE-----") || !key || !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) continue;
    await ensureDir(certDir(w.id), 0o750);
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
  return renderCaddyfile({ apps: appStore.list(), sites: siteStore.list(), settings: edgeSettings(), certs, banned, previews, edgeView: await edgeViewMounted() });
}

/**
 * The view is mounted, read-only and nosymfollow, as the host sees it (the agent's own mount namespace
 * gets it by propagation too). Checked on the mount itself: an old libmount may accept the option and
 * silently drop it. `pid`: the view as that process sees it (the running edge, in its own namespace).
 */
export async function edgeViewMounted(pid = "1"): Promise<boolean> {
  const info = (await readText(`/proc/${pid}/mountinfo`)) ?? (pid === "1" ? await readText("/proc/self/mountinfo") : null) ?? "";
  // Fields: id parent major:minor root mount-point options ...; the last mount on a point is the visible one.
  const opts = info
    .split("\n")
    .map((l) => l.split(" "))
    .filter((f) => f[4] === EDGE_VIEW)
    .at(-1)?.[5]
    ?.split(",") ?? [];
  return opts.includes("ro") && opts.includes("nosymfollow");
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
  const next = await buildCaddyfile();
  const current = await readText(paths.caddyfile);
  if (current === next) return { changed: false, reloaded: false };
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

/** The edge's unit; with the view it needs the mount and cannot see the real sites directory at all. */
export function edgeUnit(view: boolean): string {
  return `[Unit]
Description=pano edge (Caddy)
After=network-online.target${view ? ` ${EDGE_VIEW_UNIT}` : ""}
Wants=network-online.target
${view ? `Requires=${EDGE_VIEW_UNIT}\n` : ""}
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
${view ? `InaccessiblePaths=-${paths.sites}\n` : ""}LimitNOFILE=1048576
TimeoutStopSec=30s
Restart=on-failure

[Install]
WantedBy=multi-user.target
`;
}

/** Read-only bind of the sites directory on which no symlink is followed (see EDGE_VIEW). */
export const VIEW_MOUNT = `[Unit]
Description=pano: site files for the edge (read-only, symlinks not followed)
RequiresMountsFor=${paths.sites}

[Mount]
What=${paths.sites}
Where=${EDGE_VIEW}
Type=none
Options=bind,ro,nosymfollow
DirectoryMode=0755

[Install]
WantedBy=multi-user.target
`;

/**
 * Mounts the view and checks the kernel really applied nosymfollow. When it did not (Linux before
 * 5.10, or a mount that drops the option), the mount is left off and the edge reads the real paths.
 */
async function ensureEdgeView(): Promise<boolean> {
  await ensureDir(paths.sites, 0o755);
  await writeAtomic(`${paths.systemd}/${EDGE_VIEW_UNIT}`, VIEW_MOUNT, 0o644);
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", "--now", EDGE_VIEW_UNIT], { check: false });
  return edgeViewMounted();
}

/** Edge user, directories, the view and the unit; idempotent. True when the edge reads sites through the view. */
export async function setupEdgeUnit(): Promise<boolean> {
  await ensureUser(EDGE_USER, paths.edgeData);
  await ensureDir(paths.edgeData, 0o700, EDGE_USER);
  await ensureDir(paths.logs, 0o711);
  await ensureDir(paths.accessLogs, 0o750, EDGE_USER);
  await run(["chown", "-R", `${EDGE_USER}:${EDGE_USER}`, fsPath(paths.accessLogs), fsPath(paths.edgeData)], { check: false });
  await ensureDir(paths.certs, 0o750);
  await run(["chgrp", EDGE_USER, fsPath(paths.certs)], { check: false });
  const view = await ensureEdgeView();
  await writeAtomic(`${paths.systemd}/pano-edge.service`, edgeUnit(view), 0o644);
  await run(["systemctl", "daemon-reload"]);
  // Off only once the edge no longer requires it (stopping a required unit stops the edge too).
  if (!view) await run(["systemctl", "disable", "--now", EDGE_VIEW_UNIT], { check: false });
  return view;
}

/**
 * At agent start and daily (shield.ts): brings existing installs onto the view, and back to the real
 * paths if the view is gone (a kernel that cannot nosymfollow after a reboot: the edge, which requires
 * the mount, would not start). The edge restarts only when its unit changed.
 */
export async function refreshEdgeView(): Promise<boolean> {
  if (DRY_RUN || !(await edgeInstalled())) return false;
  const before = await readText(`${paths.systemd}/pano-edge.service`);
  const view = await setupEdgeUnit();
  // Paths first, so the restarted edge starts on a config that matches its unit.
  await applyEdge().catch((e) => console.error(`[agent] edge view: ${e instanceof Error ? e.message : e}`));
  if (before !== edgeUnit(view) && (await run(["systemctl", "is-enabled", "pano-edge"], { check: false })).stdout.trim() === "enabled") {
    await run(["systemctl", "restart", "pano-edge"], { check: false });
  }
  return view;
}

export async function ensureUser(user: string, home: string) {
  const r = await run(["id", "-u", user], { check: false });
  if (r.code === 0) return;
  await run(["useradd", "--system", "--home-dir", home, "--no-create-home", "--shell", "/usr/sbin/nologin", user]);
}
