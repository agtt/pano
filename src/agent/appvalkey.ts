// Valkey per app: a small instance of its own for every app that asks for one
// (own port, password, data and memory cap), instead of a database number in
// the shared server, where any app could SELECT another's number and read or
// flush its sessions and queues. Idle, an instance takes a few MB.

import { createHash } from "node:crypto";
import { paths } from "../shared/config.ts";
import { audit, settings } from "./state.ts";
import { ensureDir, exists, randomPassword, readText, remove, run, writeAtomic } from "./sys.ts";

const CONF_DIR = `${paths.etc}/valkey`;
/**
 * Below 1024: only a process with CAP_NET_BIND_SERVICE can listen there, so no
 * app or site user can take an instance's port while it restarts and collect the
 * password its app sends. Skips ports other software is known to use.
 */
const PORT_RANGE: [number, number] = [700, 899];
const PORT_SKIP = new Set([749, 750, 751, 752, 753, 754, 853, 860, 873, 883, 888]);
const MAX_MB = 128;

export const valkeyUnit = (app: string) => `pano-valkey-${app}.service`;
const confFile = (app: string) => `${CONF_DIR}/${app}.conf`;
/** The instance's own user: exists only while it runs, 32 characters at most. */
const runUser = (app: string) => `pano-vk-${createHash("sha256").update(app).digest("hex").slice(0, 12)}`;

/** app -> port */
function ports(): Record<string, number> {
  try {
    return JSON.parse(settings.get("valkey.apps") ?? "{}");
  } catch {
    return {};
  }
}

export const appValkeys = () => Object.entries(ports()).map(([app, port]) => ({ app, port }));

export function renderValkeyConf(o: { port: number; password: string; app: string; maxMb: number }): string {
  return `# Written by pano: Valkey for app ${o.app}. Localhost only, password required.
bind 127.0.0.1 -::1
protected-mode yes
port ${o.port}
requirepass ${o.password}
dir /var/lib/pano-valkey-${o.app}
maxmemory ${o.maxMb}mb
maxmemory-policy noeviction
save 3600 1 300 100 60 10000
appendonly no
daemonize no
enable-debug-command no
enable-module-command no
`;
}

export function renderValkeyUnit(app: string, bin: string, maxMb: number): string {
  const u = runUser(app);
  return `[Unit]
Description=pano: Valkey for app ${app}
After=network.target

[Service]
DynamicUser=yes
User=${u}
StateDirectory=pano-valkey-${app}
RuntimeDirectory=pano-valkey-${app}
RuntimeDirectoryMode=0700
# The config holds the password: root-only on disk, a copy only this instance reads while it runs.
ExecStartPre=+/usr/bin/install -m 0400 -o ${u} ${confFile(app)} /run/pano-valkey-${app}/valkey.conf
ExecStart=${bin} /run/pano-valkey-${app}/valkey.conf
Restart=always
RestartSec=2
MemoryMax=${maxMb * 2}M
TasksMax=64
Nice=5
NoNewPrivileges=true
# Its port is below 1024 (see PORT_RANGE); nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
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
InaccessiblePaths=-${paths.etc} -${paths.data} -/srv/pano
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressDeny=any
IPAddressAllow=localhost
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
`;
}

async function serverBinary(): Promise<string> {
  for (const b of ["/usr/bin/valkey-server", "/usr/bin/redis-server"]) if (await exists(b)) return b;
  throw new Error("Valkey is not installed");
}

async function freePort(taken: number[]): Promise<number> {
  const listening = (await run(["ss", "-Htln"], { check: false })).stdout;
  for (let p = PORT_RANGE[0]; p <= PORT_RANGE[1]; p++) {
    if (!PORT_SKIP.has(p) && !taken.includes(p) && !new RegExp(`:${p}\\s`).test(listening)) return p;
  }
  throw new Error("no free port for another Valkey");
}

/** Starts the app's own instance (Valkey must be installed) and returns the URL for its environment. */
export async function createAppValkey(app: string, actor: string): Promise<string> {
  const all = ports();
  if (all[app]) throw new Error(`${app} already has its own Valkey`);
  const bin = await serverBinary();
  const port = await freePort(Object.values(all));
  const unprivileged = Number((await readText("/proc/sys/net/ipv4/ip_unprivileged_port_start"))?.trim() ?? 1024);
  if (unprivileged <= port) throw new Error(`net.ipv4.ip_unprivileged_port_start is ${unprivileged}: any user could take port ${port}`);
  const password = randomPassword(32);
  await ensureDir(CONF_DIR, 0o700);
  await writeAtomic(confFile(app), renderValkeyConf({ port, password, app, maxMb: MAX_MB }), 0o600);
  await writeAtomic(`${paths.systemd}/${valkeyUnit(app)}`, renderValkeyUnit(app, bin, MAX_MB), 0o644);
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", "--now", valkeyUnit(app)]);
  settings.set("valkey.apps", JSON.stringify({ ...all, [app]: port }));
  audit(actor, "app.valkey", { app, port });
  return `redis://default:${password}@127.0.0.1:${port}/0`;
}

/** The instance's URL (queue monitor); null when the app has none. */
export async function appValkeyUrl(app: string): Promise<string | null> {
  const port = ports()[app];
  if (!port) return null;
  const pw = (await readText(confFile(app)))?.match(/^requirepass (\S+)$/m)?.[1];
  return pw ? `redis://default:${pw}@127.0.0.1:${port}/0` : null;
}

/** With the app: the instance, its config and its data. */
export async function removeAppValkey(app: string) {
  const all = ports();
  if (!all[app]) return;
  await run(["systemctl", "disable", "--now", valkeyUnit(app)], { check: false });
  await remove(`${paths.systemd}/${valkeyUnit(app)}`);
  await remove(confFile(app));
  await remove(`/var/lib/private/pano-valkey-${app}`);
  await remove(`/var/lib/pano-valkey-${app}`);
  await run(["systemctl", "daemon-reload"], { check: false });
  delete all[app];
  settings.set("valkey.apps", JSON.stringify(all));
}
