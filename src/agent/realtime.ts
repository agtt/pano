// Realtime: a Pusher-compatible WebSocket server, installed only when asked for.
// Sockudo (MIT, one static Rust binary, about 40 MB of memory) speaks the Pusher
// protocol and HTTP API, so pusher-js, Laravel Echo and every Pusher server SDK
// work unchanged once pointed at this server. Before install nothing is on disk;
// after it, one binary. It keeps itself up to date within its major version:
// every download is checked against the release checksum, the server is
// health-checked with a signed API call after the switch, and the previous
// binary comes back if the new one does not answer. Only one version is kept.

import { createHmac } from "node:crypto";
import { readdir } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import { notify } from "./alerts.ts";
import { assertPublicEndpoint } from "./backup.ts";
import { applyEdge } from "./edge.ts";
import { arch, download, expectedSum, sha256 } from "./runtimes.ts";
import { audit, settings, sites, state } from "./state.ts";
import { ensureDir, exists, remove, run, writeAtomic } from "./sys.ts";

const REPO = "sockudo/sockudo";
const DIR = `${paths.opt}/realtime`;
const CONFIG = `${paths.etc}/realtime.toml`;
const UNIT = "pano-realtime.service";
export const PORT = 6001;

export type RealtimeApp = {
  id: string;
  name: string;
  key: string;
  secret: string;
  origins: string[];
  /** Pusher-style webhooks (occupancy, presence), signed with the app secret; "" = none */
  webhook_url: string;
  /** concurrent connections for this app; 0 = no limit of its own */
  max_connections: number;
  created_at: number;
};

// ---- apps (Pusher "apps": id, key, secret) --------------------------------------------

function table() {
  state().exec(`CREATE TABLE IF NOT EXISTS realtime_apps (
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, key TEXT NOT NULL UNIQUE, secret TEXT NOT NULL,
    origins TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL)`);
  const cols = new Set((state().query("PRAGMA table_info(realtime_apps)").all() as { name: string }[]).map((c) => c.name));
  if (!cols.has("webhook_url")) state().exec("ALTER TABLE realtime_apps ADD COLUMN webhook_url TEXT NOT NULL DEFAULT ''");
  if (!cols.has("max_connections")) state().exec("ALTER TABLE realtime_apps ADD COLUMN max_connections INTEGER NOT NULL DEFAULT 0");
}

/** The events Pusher sends to webhooks: channel occupancy and presence members. */
export const WEBHOOK_EVENTS = ["channel_occupied", "channel_vacated", "member_added", "member_removed"];

/** https to a public host, or plain http to an app on this server. */
export async function parseWebhookUrl(s: unknown): Promise<string> {
  const url = String(s ?? "").trim();
  if (!url) return "";
  if (/^http:\/\/127\.0\.0\.1:\d{2,5}\/[A-Za-z0-9._~\/-]*$/.test(url)) return url;
  if (!/^https:\/\/[A-Za-z0-9.-]+(:\d{2,5})?\/[A-Za-z0-9._~\/-]*$/.test(url)) throw new Error("webhook: https://example.com/path or http://127.0.0.1:PORT/path");
  await assertPublicEndpoint(url);
  return url;
}

const parseMaxConnections = (s: unknown) => {
  const n = Number(String(s ?? "").trim() || 0);
  if (!Number.isInteger(n) || n < 0 || n > 1_000_000) throw new Error("max connections: 0 (no limit) to 1000000");
  return n;
};

export function listApps(): RealtimeApp[] {
  table();
  return state()
    .query("SELECT * FROM realtime_apps ORDER BY name")
    .all()
    .map((r: any) => ({ ...r, origins: JSON.parse(r.origins) }));
}

function mustApp(name: unknown): RealtimeApp {
  const a = listApps().find((x) => x.name === name);
  if (!a) throw new Error("no such realtime app");
  return a;
}

export function parseOrigins(text: unknown): string[] {
  const out = String(text ?? "")
    .split(/[\s,]+/)
    .map((s) => s.trim().replace(/\/$/, ""))
    .filter(Boolean);
  for (const o of out) if (!/^https?:\/\/(\*\.)?[a-z0-9.-]+(:\d{1,5})?$/i.test(o)) throw new Error(`origin "${o}": use https://example.com`);
  if (out.length > 20) throw new Error("at most 20 origins");
  return out;
}

const hex = (bytes: number) => Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("hex");

type AppInput = { name?: unknown; origins?: unknown; webhook_url?: unknown; max_connections?: unknown };

export async function addApp(input: AppInput, actor: string): Promise<Omit<RealtimeApp, "secret">> {
  const name = String(input.name ?? "").trim();
  if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(name)) throw new Error("name: lowercase letters, digits and -");
  if (listApps().some((a) => a.name === name)) throw new Error(`${name} already exists`);
  const app: RealtimeApp = {
    // Pusher app ids are numeric; some SDKs insist.
    id: String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0]! % 900000)),
    name,
    key: hex(10),
    secret: hex(20),
    origins: parseOrigins(input.origins),
    webhook_url: await parseWebhookUrl(input.webhook_url),
    max_connections: parseMaxConnections(input.max_connections),
    created_at: Math.floor(Date.now() / 1000),
  };
  table();
  state()
    .query("INSERT INTO realtime_apps (id, name, key, secret, origins, webhook_url, max_connections, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .run(app.id, app.name, app.key, app.secret, JSON.stringify(app.origins), app.webhook_url, app.max_connections, app.created_at);
  if (installedVersion()) await apply();
  audit(actor, "realtime.app.add", { name, id: app.id });
  const { secret: _s, ...pub } = app;
  return pub;
}

/** Origins, webhook and connection limit of an existing app; id, key and secret stay. */
export async function updateApp(input: AppInput, actor: string) {
  const a = mustApp(input.name);
  const origins = parseOrigins(input.origins);
  const webhook = await parseWebhookUrl(input.webhook_url);
  const max = parseMaxConnections(input.max_connections);
  state().query("UPDATE realtime_apps SET origins = ?, webhook_url = ?, max_connections = ? WHERE id = ?").run(JSON.stringify(origins), webhook, max, a.id);
  if (installedVersion()) await apply();
  audit(actor, "realtime.app.update", { name: a.name, webhook: !!webhook, max_connections: max });
}

export async function removeApp(name: unknown, actor: string) {
  const a = mustApp(name);
  state().query("DELETE FROM realtime_apps WHERE id = ?").run(a.id);
  if (installedVersion()) await apply();
  audit(actor, "realtime.app.remove", { name: a.name });
}

export const revealApp = (name: unknown) => mustApp(name);

/** Pusher settings for an app's environment; server side talks to localhost, browsers to the public domain. */
export function envFor(a: RealtimeApp, domain: string): Record<string, string> {
  const pub = domain ? { host: domain, port: "443", scheme: "https" } : { host: "127.0.0.1", port: String(PORT), scheme: "http" };
  return {
    PUSHER_APP_ID: a.id,
    PUSHER_APP_KEY: a.key,
    PUSHER_APP_SECRET: a.secret,
    PUSHER_HOST: "127.0.0.1",
    PUSHER_PORT: String(PORT),
    PUSHER_SCHEME: "http",
    PUSHER_APP_CLUSTER: "mt1",
    // The names the Pusher Node SDK docs (and most Next.js apps) use.
    PUSHER_KEY: a.key,
    PUSHER_SECRET: a.secret,
    PUSHER_CLUSTER: "mt1",
    NEXT_PUBLIC_PUSHER_KEY: a.key,
    NEXT_PUBLIC_PUSHER_HOST: pub.host,
    NEXT_PUBLIC_PUSHER_PORT: pub.port,
    NEXT_PUBLIC_PUSHER_SCHEME: pub.scheme,
  };
}

export async function toAppEnv(
  realtimeApp: unknown,
  env: { get: () => Promise<Record<string, string>>; set: (vars: Record<string, string>) => Promise<void> },
  appName: string,
  actor: string,
) {
  const a = mustApp(realtimeApp);
  const current = await env.get();
  if (current.PUSHER_APP_KEY) throw new Error(`PUSHER_APP_KEY is already set for ${appName}; remove it from the environment first`);
  await env.set({ ...current, ...envFor(a, settings.get("realtime.domain") ?? "") });
  audit(actor, "realtime.app.env", { app: appName, realtime: a.name });
}

// ---- server ---------------------------------------------------------------------

export const installedVersion = () => settings.get("realtime.version") ?? "";
const toml = (s: string) => JSON.stringify(s); // JSON string escapes are valid TOML basic strings

export function renderConfig(apps: RealtimeApp[]): string {
  const lines = [
    "# Written by pano. Listens on localhost only; the edge serves it on the realtime domain.",
    `host = "127.0.0.1"`,
    `port = ${PORT}`,
    `mode = "production"`,
    "debug = false",
    "",
    "[adapter]",
    `driver = "local"`,
    "",
    "[cache]",
    `driver = "memory"`,
    "",
    "[queue]",
    `driver = "memory"`,
    "",
    "[metrics]",
    "enabled = false",
    "",
    // Mobile push (APNs/FCM/Web Push) is not used; one node needs no durable push store.
    "[push]",
    `storage_driver = "memory"`,
    `queue_driver = "memory"`,
    "allow_memory_drivers = true",
    "fcm_enabled = false",
    "apns_enabled = false",
    "webpush_enabled = false",
    "",
    "[app_manager]",
    `driver = "memory"`,
    "",
    "[app_manager.cache]",
    "enabled = false",
  ];
  for (const a of apps) {
    lines.push(
      "",
      "[[app_manager.array.apps]]",
      `id = ${toml(a.id)}`,
      `key = ${toml(a.key)}`,
      `secret = ${toml(a.secret)}`,
      "enabled = true",
      "",
      "[app_manager.array.apps.policy.features]",
      // Browsers may only listen; events are published by the app's server with the secret.
      "enable_client_messages = false",
      "enable_user_authentication = true",
    );
    if (a.origins.length) lines.push("", "[app_manager.array.apps.policy.channels]", `allowed_origins = [${a.origins.map(toml).join(", ")}]`);
    // A limit keeps one busy app from taking every connection of the server; 0 = none.
    if (a.max_connections) lines.push("", "[app_manager.array.apps.policy.limits]", `max_connections = ${a.max_connections}`);
    if (a.webhook_url) {
      // Signed like Pusher's (X-Pusher-Key / X-Pusher-Signature with the app secret); delivered through the memory queue.
      lines.push("", "[[app_manager.array.apps.policy.webhooks]]", `url = ${toml(a.webhook_url)}`, `event_types = [${WEBHOOK_EVENTS.map(toml).join(", ")}]`, "request_timeout_ms = 5000");
    }
  }
  return `${lines.join("\n")}\n`;
}

export function renderUnit(version: string): string {
  return `[Unit]
Description=pano realtime (Sockudo ${version}, Pusher-compatible WebSockets)
After=network-online.target
Wants=network-online.target

[Service]
DynamicUser=yes
# The config holds the app secrets: root-only on disk; a copy only the service
# can read lives in memory (/run) while it runs. (Not LoadCredential: containers
# without credential support start it with no config, on defaults.)
RuntimeDirectory=pano-realtime
RuntimeDirectoryMode=0700
ExecStartPre=+/usr/bin/install -m 0400 -o pano-realtime ${CONFIG} /run/pano-realtime/config.toml
# Even with a broken config file it stays on localhost without metrics.
Environment=HOST=127.0.0.1 PORT=${PORT} METRICS_ENABLED=false
WorkingDirectory=/
ExecStart=${DIR}/current/sockudo --config /run/pano-realtime/config.toml
Restart=always
RestartSec=2
MemoryHigh=192M
MemoryMax=256M
TasksMax=256
LimitNOFILE=65536
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
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
IPAddressDeny=169.254.169.254/32
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
`;
}

/** Pusher HTTP API request signature (auth_signature). */
export function signQuery(method: string, path: string, params: Record<string, string>, secret: string): string {
  const query = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("&");
  const sig = createHmac("sha256", secret).update(`${method}\n${path}\n${query}`).digest("hex");
  return `${query}&auth_signature=${sig}`;
}

/** Up, and serving our apps (proves our config loaded, not defaults). */
async function healthy(timeoutMs = 15_000): Promise<boolean> {
  const app = listApps()[0];
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    try {
      const up = await fetch(`http://127.0.0.1:${PORT}/up`, { signal: AbortSignal.timeout(2000) });
      if (up.ok) {
        if (!app) return true;
        const path = `/apps/${app.id}/channels`;
        const q = signQuery("GET", path, { auth_key: app.key, auth_timestamp: String(Math.floor(Date.now() / 1000)), auth_version: "1.0" }, app.secret);
        const r = await fetch(`http://127.0.0.1:${PORT}${path}?${q}`, { signal: AbortSignal.timeout(2000) });
        if (r.ok) return true;
      }
    } catch {}
    await Bun.sleep(500);
  }
  return false;
}

async function journalTail() {
  return (await run(["journalctl", "-u", UNIT, "-n", "15", "--no-pager", "-o", "cat"], { check: false })).stdout.trim();
}

/** Writes config and unit, restarts, and checks the server answers with our apps. */
async function apply() {
  await writeAtomic(CONFIG, renderConfig(listApps()), 0o600);
  await writeAtomic(`${paths.systemd}/${UNIT}`, renderUnit(installedVersion()), 0o644);
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", UNIT], { check: false });
  await run(["systemctl", "restart", UNIT]);
  if (!(await healthy())) throw new Error(`realtime server did not come up:\n${await journalTail()}`);
}

const semver = (s: string) => s.split(".").map(Number);
export const newer = (a: string, b: string) => {
  const [x, y] = [semver(a), semver(b)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  return false;
};

/** Stable releases, newest first. */
async function releases(): Promise<string[]> {
  const res = await fetch(`https://api.github.com/repos/${REPO}/releases?per_page=30`, { headers: { "user-agent": "pano" } });
  if (!res.ok) throw new Error(`cannot reach GitHub releases (${res.status})`);
  return ((await res.json()) as { tag_name: string; prerelease: boolean; draft: boolean }[])
    .filter((r) => !r.prerelease && !r.draft && /^v\d+\.\d+\.\d+$/.test(r.tag_name))
    .map((r) => r.tag_name.slice(1))
    .sort((a, b) => (newer(a, b) ? -1 : newer(b, a) ? 1 : 0));
}

/** Downloads one release into its own directory; nothing else on disk changes. */
async function fetchVersion(ver: string) {
  const target = `${DIR}/${ver}`;
  if (await exists(`${target}/sockudo`)) return;
  const file = `sockudo-v${ver}-${arch() === "arm64" ? "aarch64" : "x86_64"}-unknown-linux-musl.tgz`;
  const base = `https://github.com/${REPO}/releases/download/v${ver}`;
  const [bytes, sum] = await Promise.all([download(`${base}/${file}`), download(`${base}/${file}.sha256`)]);
  if (sha256(bytes) !== expectedSum(new TextDecoder().decode(sum), file)) throw new Error("checksum mismatch");
  const tmp = `${paths.data}/tmp/${file}`;
  await ensureDir(`${paths.data}/tmp`, 0o700);
  await ensureDir(target, 0o755);
  try {
    await Bun.write(fsPath(tmp), bytes);
    await run(["tar", "-xzf", fsPath(tmp), "-C", fsPath(target), "--no-same-owner", "sockudo"]);
    await run(["chmod", "0755", fsPath(`${target}/sockudo`)]);
  } catch (e) {
    await remove(target);
    throw e;
  } finally {
    await remove(tmp);
  }
}

const point = (ver: string) => run(["ln", "-sfn", ver, fsPath(`${DIR}/current`)]);

/** Recovery on a new server: the recorded version again, with its apps from the restored state. */
export async function reinstall(actor: string) {
  const ver = installedVersion();
  if (!ver) return;
  await fetchVersion(ver);
  await point(ver);
  await apply();
  audit(actor, "realtime.reinstall", { version: ver });
}

/** Removes every downloaded version except the one in use. */
async function prune(keep: string) {
  for (const d of await readdir(fsPath(DIR)).catch(() => [] as string[])) {
    if (d !== "current" && d !== keep) await remove(`${DIR}/${d}`);
  }
}

export async function install(actor: string) {
  if (installedVersion()) throw new Error("realtime is already installed");
  const ver = (await releases())[0];
  if (!ver) throw new Error("no release found");
  await fetchVersion(ver);
  await point(ver);
  settings.set("realtime.version", ver);
  if (settings.get("realtime.autoUpdate") === null) settings.set("realtime.autoUpdate", "1");
  if (!listApps().length) await addApp({ name: "default" }, actor);
  try {
    await apply();
  } catch (e) {
    await uninstall(actor);
    throw e;
  }
  audit(actor, "realtime.install", { version: ver });
  return { version: ver };
}

/** Switches to another version; back to the previous one if the new one does not answer. */
export async function update(ver: string, actor: string) {
  const prev = installedVersion();
  if (!prev) throw new Error("realtime is not installed");
  if (ver === prev) return { version: prev };
  await fetchVersion(ver);
  await point(ver);
  settings.set("realtime.version", ver);
  try {
    await apply();
  } catch (e) {
    await point(prev);
    settings.set("realtime.version", prev);
    await apply().catch(() => {});
    await remove(`${DIR}/${ver}`);
    audit(actor, "realtime.update.failed", { from: prev, to: ver });
    throw new Error(`update to ${ver} failed, back on ${prev}: ${e instanceof Error ? e.message : e}`);
  }
  await prune(ver);
  settings.set("realtime.updatedAt", String(Math.floor(Date.now() / 1000)));
  audit(actor, "realtime.update", { from: prev, to: ver });
  return { version: ver };
}

export async function uninstall(actor: string) {
  if (settings.get("realtime.domain")) await setDomain("", actor);
  await run(["systemctl", "disable", "--now", UNIT], { check: false });
  await remove(`${paths.systemd}/${UNIT}`);
  await run(["systemctl", "daemon-reload"], { check: false });
  await remove(DIR);
  await remove(CONFIG);
  settings.set("realtime.version", "");
  audit(actor, "realtime.uninstall");
}

export function setAutoUpdate(on: boolean, actor: string) {
  settings.set("realtime.autoUpdate", on ? "1" : "0");
  audit(actor, "realtime.autoUpdate", { on });
}

/** Serves the server on a domain through the edge (WebSockets pass through Caddy and Cloudflare). */
export async function setDomain(domain: string, actor: string) {
  const prev = settings.get("realtime.domain") ?? "";
  const ours = (name: string) => sites.get(name)?.routes.some((r) => r.upstream === `127.0.0.1:${PORT}`);
  if (prev && prev !== domain && ours(prev)) sites.remove(prev);
  if (domain) {
    const existing = sites.get(domain);
    if (existing && !ours(domain)) throw new Error(`${domain} is already a site`);
    sites.upsert({
      name: domain,
      kind: "proxy",
      domains: [domain],
      root: "",
      routes: [{ path: "/", upstream: `127.0.0.1:${PORT}` }],
      ask_url: "",
      php_version: "",
      tls_cert: "",
      tls_key: "",
      source: "pano",
      enabled: 1,
      on_demand_tls: 0,
    });
  }
  settings.set("realtime.domain", domain);
  await applyEdge();
  audit(actor, "realtime.domain", { domain });
}

export async function realtimeStatus() {
  const ver = installedVersion();
  const unit = ver
    ? await run(["systemctl", "show", UNIT, "-p", "ActiveState", "-p", "MemoryCurrent"], { check: false })
    : { stdout: "" };
  const get = (k: string) => unit.stdout.match(new RegExp(`^${k}=(.*)$`, "m"))?.[1] ?? "";
  const mem = Number(get("MemoryCurrent"));
  return {
    installed: !!ver,
    version: ver,
    latest: settings.get("realtime.latest") ?? "",
    autoUpdate: settings.get("realtime.autoUpdate") !== "0",
    updatedAt: Number(settings.get("realtime.updatedAt") ?? 0) || null,
    active: get("ActiveState"),
    memory: Number.isFinite(mem) && mem < 2 ** 60 ? mem : 0,
    domain: settings.get("realtime.domain") ?? "",
    port: PORT,
    apps: listApps().map(({ secret: _s, ...a }) => a),
  };
}

/**
 * Daily: remembers the newest release (shown in the panel) and, when auto
 * update is on, moves to the newest one of the same major version. A new major
 * version can change behavior, so that one waits for a click.
 */
export async function checkUpdates() {
  const cur = installedVersion();
  if (!cur) return;
  const all = await releases();
  settings.set("realtime.latest", all[0] ?? "");
  if (settings.get("realtime.autoUpdate") === "0") return;
  const next = all.find((x) => x.split(".")[0] === cur.split(".")[0]);
  if (!next || !newer(next, cur)) return;
  try {
    await update(next, "auto-update");
    await notify(`🔄 realtime server updated ${cur} → ${next}`);
  } catch (e) {
    await notify(`🔴 realtime server update to ${next} failed, still on ${cur}: ${e instanceof Error ? e.message : e}`);
  }
}

export function startRealtime() {
  const tick = () => checkUpdates().catch((e) => console.error(`[agent] realtime update check: ${e}`));
  setTimeout(tick, 10 * 60_000);
  setInterval(tick, 24 * 3600_000);
}
