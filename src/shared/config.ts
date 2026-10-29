// Every path pano touches lives here. In development PANO_ROOT prefixes all of
// them (a sandbox directory) and PANO_DRY_RUN=1 turns system commands into logs.

const ROOT = (process.env.PANO_ROOT ?? "").replace(/\/+$/, "");

import pkg from "../../package.json";

export const VERSION: string = pkg.version;
export const DRY_RUN = process.env.PANO_DRY_RUN === "1";

/** Real filesystem location of a logical absolute path. */
export const fsPath = (abs: string) => ROOT + abs;

export const paths = {
  etc: "/etc/pano",
  secrets: "/etc/pano/secrets",
  certs: "/etc/pano/certs",
  caddyfile: "/etc/pano/Caddyfile",
  data: "/var/lib/pano",
  stateDb: "/var/lib/pano/state.db",
  webDb: "/var/lib/pano/web/web.db",
  deployLogs: "/var/lib/pano/deploys",
  configBackups: "/var/lib/pano/config-backups",
  logs: "/var/log/pano",
  apps: "/srv/pano/apps",
  sites: "/srv/pano/sites",
  containers: "/srv/pano/containers",
  containerEnv: "/etc/pano/containers",
  quadlets: "/etc/containers/systemd",
  vpn: "/etc/pano/vpn",
  phpEtc: "/etc/pano/php",
  phpRun: "/run/pano-php",
  /** Drop cPanel cpmove archives here (scp) to import them. */
  imports: "/var/lib/pano/imports",
  opt: "/opt/pano",
  bin: "/opt/pano/bin",
  caddy: "/opt/pano/bin/caddy",
  runtimes: "/opt/pano/runtimes",
  run: "/run/pano",
  agentSocket: "/run/pano/agent.sock",
  edgeData: "/var/lib/pano/edge",
  accessLogs: "/var/log/pano/access",
  caddyAdmin: "/run/pano-edge/admin.sock",
  systemd: "/etc/systemd/system",
  ols: "/usr/local/lsws",
  cyberpanel: "/usr/local/CyberCP",
} as const;

export const env = {
  /** Where the web UI listens. Keep it on localhost or a Tailscale address. */
  webHost: process.env.PANO_WEB_HOST ?? "127.0.0.1",
  webPort: Number(process.env.PANO_WEB_PORT ?? 7800),
  /** Set by the panel when "panel over WireGuard" is on: the UI also listens on this VPN address. */
  webVpnHost: process.env.PANO_WEB_VPN_HOST ?? "",
  /** Extra names the panel may be reached by (comma separated, e.g. a Tailscale MagicDNS name); other Host headers are refused. */
  webHosts: process.env.PANO_WEB_HOSTS ?? "",
  /** Caddy's on-demand TLS "ask" endpoint, served by the agent on localhost only. */
  askPort: Number(process.env.PANO_ASK_PORT ?? 7801),
  /** Localhost-only listener for GitHub webhooks; the edge exposes just /hooks/* on the hooks domain. */
  hookPort: Number(process.env.PANO_HOOK_PORT ?? 7802),
  /** Port the legacy OpenLiteSpeed server moves to after cutover. */
  olsBackendPort: Number(process.env.PANO_OLS_BACKEND_PORT ?? 8088),
  /** Set when the UI is reached over plain HTTP (dev, Tailscale): drops the Secure cookie flag. */
  insecureCookies: process.env.PANO_INSECURE_COOKIES === "1",
  lang: (process.env.PANO_LANG ?? "tr") as "tr" | "en",
};

/** First port handed to managed apps; each app takes two (blue/green slots). */
export const APP_PORT_BASE = 4100;
