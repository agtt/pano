// The edge: a pano-owned Caddy that terminates TLS on :80/:443 and routes to
// apps (blue/green ports), proxy sites and, for legacy PHP sites, the old
// OpenLiteSpeed server moved to localhost. Caddy runs as its own user with only
// CAP_NET_BIND_SERVICE; the Caddyfile is rendered from state and validated
// before every reload, so a bad change never replaces a working config.

import { env, fsPath, paths } from "../shared/config.ts";
import { apps as appStore, previewApp, previews as previewStore, procsOf, settings, sites as siteStore, type App, type Route, type Site } from "./state.ts";
import { ensureDir, exists, readText, remove, run, writeAtomic } from "./sys.ts";

const CLOUDFLARE_RANGES = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
  "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
  "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
  "2a06:98c0::/29", "2c0f:f248::/32",
];

export const EDGE_USER = "pano-edge";

/** turnDomain: only set while TURN over TLS is on; the edge then holds a certificate for it (see turn.ts). */
export type EdgeSettings = { email: string; behindCloudflare: boolean; hooksDomain: string; localCerts?: boolean; turnDomain?: string };

export function edgeSettings(): EdgeSettings {
  return {
    email: settings.get("edge.email") ?? "",
    behindCloudflare: settings.get("edge.behindCloudflare") === "1",
    hooksDomain: settings.get("edge.hooksDomain") ?? "",
    localCerts: settings.get("edge.localCerts") === "1",
    turnDomain: settings.get("turn.tls") === "1" ? settings.get("turn.domain") ?? "" : "",
  };
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
// backups, composer manifests, and PHP inside WordPress uploads.
const PHP_DENY = String.raw`(?i)(/\.|\.(sql|bak|old|orig|swp|ini|log|sh|env|dist|config)$|/composer\.(json|lock)$|/wp-content/uploads/.*\.(php\d?|phtml|phar)$)`;

function phpLines(site: Site): string[] {
  const out = [`\troot * ${site.root}`, "\t@pano_deny {", `\t\tpath_regexp ${PHP_DENY}`, "\t\tnot path /.well-known/*", "\t}", "\trespond @pano_deny 404"];
  if (site.deny_paths.length) {
    out.push(`\t@pano_deny_dirs path ${site.deny_paths.flatMap((p) => (p === "/" ? ["*"] : [p, `${p}/*`])).join(" ")}`, "\trespond @pano_deny_dirs 404");
  }
  out.push(`\tphp_fastcgi unix/${phpSocket(site.name)}`, ...ASSET_CACHE, "\tfile_server");
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

export function renderCaddyfile(input: { apps: App[]; sites: Site[]; settings: EdgeSettings; certs: Set<string>; banned?: string[]; previews?: EdgePreview[] }): string {
  const { settings: s } = input;
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
      ? [`\t\ttrusted_proxies static ${CLOUDFLARE_RANGES.join(" ")}`, "\t\tclient_ip_headers CF-Connecting-IP X-Forwarded-For"]
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

  if (s.turnDomain) {
    // Nothing is served here; the block makes Caddy obtain and renew the certificate that coturn uses for turns:.
    out.push(`${s.turnDomain} {`, "\timport pano_common", "\trespond 404", "}", "");
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
      out.push(`\troot * ${site.root}`, ...ASSET_CACHE, "\tfile_server");
    } else if (site.kind === "php") {
      out.push(...phpLines(site));
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
    const cert = await readText(w.cert);
    const key = await readText(w.key);
    // Only PEM goes to the edge: a path that now leads to some other file (symlink) is skipped.
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
  return renderCaddyfile({ apps: appStore.list(), sites: siteStore.list(), settings: edgeSettings(), certs, banned, previews });
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

export const EDGE_UNIT = `[Unit]
Description=pano edge (Caddy)
After=network-online.target
Wants=network-online.target

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
LimitNOFILE=1048576
TimeoutStopSec=30s
Restart=on-failure

[Install]
WantedBy=multi-user.target
`;

export async function setupEdgeUnit() {
  await ensureUser(EDGE_USER, paths.edgeData);
  await ensureDir(paths.edgeData, 0o700, EDGE_USER);
  await ensureDir(paths.logs, 0o711);
  await ensureDir(paths.accessLogs, 0o750, EDGE_USER);
  await run(["chown", "-R", `${EDGE_USER}:${EDGE_USER}`, fsPath(paths.accessLogs), fsPath(paths.edgeData)], { check: false });
  await ensureDir(paths.certs, 0o750);
  await run(["chgrp", EDGE_USER, fsPath(paths.certs)], { check: false });
  await writeAtomic(`${paths.systemd}/pano-edge.service`, EDGE_UNIT, 0o644);
  await run(["systemctl", "daemon-reload"]);
}

export async function ensureUser(user: string, home: string) {
  const r = await run(["id", "-u", user], { check: false });
  if (r.code === 0) return;
  await run(["useradd", "--system", "--home-dir", home, "--no-create-home", "--shell", "/usr/sbin/nologin", user]);
}
