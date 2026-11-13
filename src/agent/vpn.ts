// Private access: a WireGuard interface owned by pano, with no coordination
// server and no third-party account. Off until enabled. Devices are added by
// their public key (the private key never touches the server) or, for phones,
// with a one-time config/QR that is shown once and not stored. Every peer also
// gets a preshared key. Locks then close SSH and admin ports to everything but
// the tunnel; a lock must be confirmed from inside the tunnel within a few
// minutes or it is undone automatically, so a mistake cannot lock you out.

import { DRY_RUN, env, paths } from "../shared/config.ts";
import { notify } from "./alerts.ts";
import { allSshPorts, nftPorts } from "./firewall.ts";
import { nftAccept, remoteOpen, type RemoteOpen } from "./remotedb-config.ts";
import { audit, settings, state } from "./state.ts";
import { ensureDir, exists, readText, run, writeAtomic } from "./sys.ts";

export const IFACE = "pano0";
const NET = "10.77.0";
export const SERVER_IP = `${NET}.1`;
const UNIT = "pano-vpn.service";
const LOCKS_UNIT = "pano-vpn-locks.service";
const CONF = `${paths.vpn}/${IFACE}.conf`;
const RULES = `${paths.vpn}/rules.nft`;
const KEY = `${paths.secrets}/wg.key`;
/** firewalld zone of the tunnel interface: default-reject, opened port by port (it used to be "trusted": everything). */
export const ZONE = "pano-vpn";
/** Admin services that should never face the internet: MariaDB, Postgres, Redis, OLS admin, CyberPanel, its SSH web shell, memcached. */
export const SERVICE_PORTS = [3306, 5432, 6379, 7080, 8090, 8888, 11211];

/** databases: MariaDB/PostgreSQL/Valkey also answer on the tunnel address (for TablePlus, DBeaver…). */
export type Locks = { panel: boolean; ssh: boolean; services: boolean; databases: boolean };
type Pending = { previous: Locks; deadline: number };
export type Peer = { id: number; name: string; public_key: string; psk: string; ip: string; created_at: number };

const NO_LOCKS: Locks = { panel: false, ssh: false, services: false, databases: false };
const PUBKEY = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

export const locks = (): Locks => ({ ...NO_LOCKS, ...JSON.parse(settings.get("vpn.locks") ?? "{}") });
const pending = (): Pending | null => JSON.parse(settings.get("vpn.pending") || "null");
const peers = (): Peer[] => state().query("SELECT * FROM vpn_peers ORDER BY id").all() as Peer[];

// ---- rendering ---------------------------------------------------------------

export function renderConf(privateKey: string, port: number, list: Pick<Peer, "public_key" | "psk" | "ip">[]): string {
  const out = ["[Interface]", `PrivateKey = ${privateKey}`, `ListenPort = ${port}`, ""];
  for (const p of list) out.push("[Peer]", `PublicKey = ${p.public_key}`, `PresharedKey = ${p.psk}`, `AllowedIPs = ${p.ip}/32`, "");
  return out.join("\n");
}

/** remoteDb: database remote access that is on; those ports stay open (to their allowed networks) through the services lock. */
export function renderRules(l: Locks, sshPort: number | number[], remoteDb: RemoteOpen[] = []): string {
  const drops = [
    ...(l.ssh ? [`\t\ttcp dport ${nftPorts(sshPort)} drop`] : []),
    ...(l.services ? remoteDb.flatMap(nftAccept) : []),
    ...(l.services ? [`\t\ttcp dport { ${SERVICE_PORTS.join(", ")} } drop`] : []),
  ];
  // Own table, created and replaced atomically; a drop here wins over any accept elsewhere.
  return [
    "table inet pano_vpn",
    "delete table inet pano_vpn",
    "table inet pano_vpn {",
    "\tchain input {",
    "\t\ttype filter hook input priority -5; policy accept;",
    '\t\tiifname "lo" accept',
    `\t\tiifname "${IFACE}" accept`,
    // The tunnel addresses exist only inside the tunnel: never accept them from another interface (a spoofing neighbour).
    `\t\tip daddr ${NET}.0/24 drop`,
    // Sessions already open (the SSH you are using right now) keep working.
    "\t\tct state established,related accept",
    ...drops,
    "\t}",
    "}",
    "",
  ].join("\n");
}

export function renderUnit(): string {
  return `[Unit]
Description=pano private access (WireGuard ${IFACE})
After=network-online.target
Wants=network-online.target
Before=pano-web.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-ip link del ${IFACE}
ExecStart=ip link add ${IFACE} type wireguard
ExecStart=wg setconf ${IFACE} ${CONF}
ExecStart=ip address add ${SERVER_IP}/24 dev ${IFACE}
ExecStart=ip link set ${IFACE} up
ExecStart=nft -f ${RULES}
ExecReload=wg syncconf ${IFACE} ${CONF}
ExecReload=nft -f ${RULES}
ExecStop=-nft delete table inet pano_vpn
ExecStop=ip link del ${IFACE}

[Install]
WantedBy=multi-user.target
`;
}

/**
 * The locks on their own, loaded before the network comes up: the WireGuard unit waits for the
 * network, and until it ran a locked SSH or database port would be open after a reboot.
 */
export function renderLocksUnit(): string {
  return `[Unit]
Description=pano private access locks (nftables table pano_vpn)
Wants=network-pre.target
Before=network-pre.target sshd.service ssh.service
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=nft -f ${RULES}
ExecReload=nft -f ${RULES}

[Install]
WantedBy=multi-user.target
`;
}

async function ensureLocksUnit() {
  await writeAtomic(`${paths.systemd}/${LOCKS_UNIT}`, renderLocksUnit(), 0o644);
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", LOCKS_UNIT]);
}

export function clientConfig(p: { privateKey: string; ip: string; psk: string }, server: { publicKey: string; endpoint: string; port: number }): string {
  const host = server.endpoint.includes(":") ? `[${server.endpoint}]` : server.endpoint;
  return [
    "[Interface]",
    `PrivateKey = ${p.privateKey}`,
    `Address = ${p.ip}/32`,
    "",
    "[Peer]",
    `PublicKey = ${server.publicKey}`,
    `PresharedKey = ${p.psk}`,
    `Endpoint = ${host}:${server.port}`,
    // Only the server goes through the tunnel; the rest of the device's traffic is untouched.
    `AllowedIPs = ${SERVER_IP}/32`,
    "PersistentKeepalive = 25",
    "",
  ].join("\n");
}

// ---- system ------------------------------------------------------------------

const wg = async (args: string[], input?: string) => (await run(["wg", ...args], { input })).stdout.trim();

async function serverKey(): Promise<{ privateKey: string; publicKey: string }> {
  let privateKey = (await readText(KEY))?.trim() ?? "";
  if (!privateKey) {
    privateKey = await wg(["genkey"]);
    await ensureDir(paths.secrets, 0o700);
    await writeAtomic(KEY, privateKey + "\n", 0o600);
  }
  return { privateKey, publicKey: await wg(["pubkey"], privateKey) };
}

async function defaultEndpoint(): Promise<string> {
  const r = await run(["ip", "-4", "route", "get", "1.1.1.1"], { check: false });
  return r.stdout.match(/\bsrc (\S+)/)?.[1] ?? "";
}

/** What a VPN device may reach on the server: SSH and the panel always (the lock confirmation comes through the tunnel), admin services and database forwarders as the locks say. */
export function zonePorts(l: Locks, sshPort: number | number[], panelPort: number): string[] {
  const ports = new Set([...[sshPort].flat(), panelPort, ...(l.services ? SERVICE_PORTS : []), ...(l.databases ? DB_PORTS : [])]);
  return [...ports].sort((a, b) => a - b).map((p) => `${p}/tcp`);
}

export type ZoneState = { zones: string[]; inTrusted: boolean; inZone: boolean; ports: string[] };

/** The firewall-cmd --permanent arguments that bring the zone to `want`, and nothing when it already is (no reload then). */
export function zoneCommands(s: ZoneState, want: string[]): string[][] {
  const z = `--zone=${ZONE}`;
  const out: string[][] = [];
  if (!s.zones.includes(ZONE)) out.push([`--new-zone=${ZONE}`]);
  // Migration: pano0 sat in "trusted"; one interface cannot be in two zones.
  if (s.inTrusted) out.push(["--zone=trusted", `--remove-interface=${IFACE}`]);
  if (!s.inZone || s.inTrusted) out.push([z, `--add-interface=${IFACE}`]);
  for (const p of s.ports) if (!want.includes(p)) out.push([z, `--remove-port=${p}`]);
  for (const p of want) if (!s.ports.includes(p)) out.push([z, `--add-port=${p}`]);
  return out;
}

const firewalld = async () => (await run(["firewall-cmd", "--state"], { check: false })).stdout.trim() === "running";
const active = async () => (await run(["systemctl", "is-active", UNIT], { check: false })).stdout.trim() === "active";

/** Writes interface config and lock rules; reloads a running interface without dropping sessions. */
async function sync() {
  const { privateKey } = await serverKey();
  const port = Number(settings.get("vpn.port") ?? 51820);
  await ensureDir(paths.vpn, 0o700);
  await writeAtomic(CONF, renderConf(privateKey, port, peers()), 0o600);
  await writeAtomic(RULES, renderRules(locks(), await allSshPorts(), remoteOpen()), 0o600);
  if (await active()) await run(["systemctl", "reload", UNIT]);
  const on = settings.get("vpn.enabled") === "1";
  await syncDbForward(on && locks().databases);
  if (on) await syncZone();
}

/** Brings the tunnel's firewalld zone in line with the locks; leaves "trusted" if the interface is still there. */
export async function syncZone() {
  if (!(await firewalld())) return;
  const fw = (args: string[]) => run(["firewall-cmd", "--permanent", ...args], { check: false });
  const query = async (args: string[]) => (await fw(args)).stdout.trim() === "yes";
  const zones = (await fw(["--get-zones"])).stdout.trim().split(/\s+/);
  const has = zones.includes(ZONE);
  const cmds = zoneCommands(
    {
      zones,
      inTrusted: await query(["--zone=trusted", `--query-interface=${IFACE}`]),
      inZone: has && (await query([`--zone=${ZONE}`, `--query-interface=${IFACE}`])),
      ports: has ? (await fw([`--zone=${ZONE}`, "--list-ports"])).stdout.trim().split(/\s+/).filter(Boolean) : [],
    },
    zonePorts(locks(), await allSshPorts(), env.webPort),
  );
  if (!cmds.length) return;
  for (const c of cmds) await fw(c);
  await run(["firewall-cmd", "--reload"], { check: false });
}

export const DB_PORTS = [3306, 5432, 6379];

/**
 * Databases stay on 127.0.0.1; a socket-activated forwarder answers on the tunnel
 * address and connects locally, so no database configuration changes and only
 * WireGuard devices can reach it. Logins still need the database's own password.
 */
async function syncDbForward(on: boolean) {
  for (const port of DB_PORTS) {
    const base = `pano-vpn-db-${port}`;
    const listening = (await run(["ss", "-Htln", `sport = :${port}`], { check: false })).stdout.includes("127.0.0.1:");
    if (!on || !listening) {
      await run(["systemctl", "disable", "--now", `${base}.socket`], { check: false });
      continue;
    }
    await writeAtomic(`${paths.systemd}/${base}.socket`, `[Unit]\nDescription=pano: 127.0.0.1:${port} on WireGuard\n\n[Socket]\nListenStream=${SERVER_IP}:${port}\nFreeBind=true\n\n[Install]\nWantedBy=sockets.target\n`, 0o644);
    await writeAtomic(
      `${paths.systemd}/${base}.service`,
      `[Unit]\nDescription=pano: forward WireGuard ${port} to 127.0.0.1\n\n[Service]\nExecStart=/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:${port}\nDynamicUser=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n`,
      0o644,
    );
    await run(["systemctl", "daemon-reload"]);
    await run(["systemctl", "enable", "--now", `${base}.socket`], { check: false });
  }
}

/** pano.env decides where the UI listens; the web process restarts to pick it up. */
async function setPanelOverVpn(on: boolean) {
  const file = `${paths.etc}/pano.env`;
  const text = (await readText(file)) ?? "";
  const lines = text.split("\n").filter((l) => !l.startsWith("PANO_WEB_VPN_HOST="));
  if (on) lines.splice(lines.length && lines.at(-1) === "" ? lines.length - 1 : lines.length, 0, `PANO_WEB_VPN_HOST=${SERVER_IP}`);
  const next = lines.join("\n");
  if (next === text) return;
  await writeAtomic(file, next, 0o600);
  // Delayed: the request that asked for this is still being answered by pano-web.
  setTimeout(() => run(["systemctl", "restart", "pano-web"], { check: false }), 1500);
}

// ---- operations --------------------------------------------------------------

export async function status() {
  const installed = await exists("/usr/bin/wg");
  const enabled = settings.get("vpn.enabled") === "1";
  const stats = new Map<string, { endpoint: string; handshake: number; rx: number; tx: number }>();
  if (enabled && (await active())) {
    const dump = await run(["wg", "show", IFACE, "dump"], { check: false });
    for (const line of dump.stdout.trim().split("\n").slice(1)) {
      const [key, , endpoint, , handshake, rx, tx] = line.split("\t");
      if (key) stats.set(key, { endpoint: endpoint === "(none)" ? "" : endpoint!, handshake: Number(handshake), rx: Number(rx), tx: Number(tx) });
    }
  }
  return {
    installed,
    enabled,
    running: enabled && (await active()),
    address: SERVER_IP,
    port: Number(settings.get("vpn.port") ?? 51820),
    endpoint: settings.get("vpn.endpoint") || (await defaultEndpoint()),
    publicKey: enabled ? (await serverKey()).publicKey : "",
    peers: peers().map(({ psk, ...p }) => ({ ...p, ...(stats.get(p.public_key) ?? { endpoint: "", handshake: 0, rx: 0, tx: 0 }) })),
    locks: locks(),
    pending: pending(),
    sshPort: (await allSshPorts()).join(", "),
  };
}

export async function enable(input: { port?: unknown; endpoint?: unknown }, actor: string) {
  const port = Number(input.port || 51820);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("port must be 1024-65535");
  const endpoint = String(input.endpoint ?? "").trim();
  if (endpoint && !/^[A-Za-z0-9.:-]{2,253}$/.test(endpoint)) throw new Error("endpoint: public IP or host name of this server");
  if (!(await exists("/usr/bin/wg")) || !(await exists("/usr/sbin/nft"))) {
    const os = (await readText("/etc/os-release")) ?? "";
    const pkgs = ["wireguard-tools", "nftables", "qrencode"];
    if (/^(ID|ID_LIKE)=.*\b(debian|ubuntu)\b/m.test(os)) await run(["apt-get", "install", "-y", ...pkgs], { timeoutMs: 900_000 });
    else await run(["dnf", "-y", "--setopt=strict=0", "install", ...pkgs], { timeoutMs: 900_000 });
  }
  settings.set("vpn.port", String(port));
  settings.set("vpn.endpoint", endpoint);
  await sync();
  await writeAtomic(`${paths.systemd}/${UNIT}`, renderUnit(), 0o644);
  await run(["systemctl", "daemon-reload"]);
  if (await firewalld()) {
    await run(["firewall-cmd", "--permanent", `--add-port=${port}/udp`], { check: false });
    await run(["firewall-cmd", "--reload"], { check: false });
    await syncZone();
  }
  await run(["systemctl", "enable", UNIT]);
  await run(["systemctl", "restart", UNIT]);
  await ensureLocksUnit();
  settings.set("vpn.enabled", "1");
  audit(actor, "vpn.enable", { port, endpoint });
}

/** Database remote access changed: the services lock lets its port through (or no longer does) right away. */
export async function followRemoteDb() {
  if (settings.get("vpn.enabled") !== "1" || !(await exists(RULES))) return;
  await writeAtomic(RULES, renderRules(locks(), await allSshPorts(), remoteOpen()), 0o600);
  if (await active()) await run(["systemctl", "reload", UNIT]);
}

export async function disable(actor: string) {
  settings.set("vpn.locks", JSON.stringify(NO_LOCKS));
  settings.set("vpn.pending", "");
  await setPanelOverVpn(false);
  await syncDbForward(false);
  await run(["systemctl", "disable", "--now", UNIT], { check: false });
  await run(["systemctl", "disable", LOCKS_UNIT], { check: false });
  if (await firewalld()) {
    await run(["firewall-cmd", "--permanent", `--remove-port=${settings.get("vpn.port") ?? 51820}/udp`], { check: false });
    await run(["firewall-cmd", "--permanent", `--delete-zone=${ZONE}`], { check: false });
    await run(["firewall-cmd", "--reload"], { check: false });
  }
  settings.set("vpn.enabled", "0");
  audit(actor, "vpn.disable", {});
}

export async function addPeer(input: { name?: unknown; publicKey?: unknown }, actor: string) {
  if (settings.get("vpn.enabled") !== "1") throw new Error("enable private access first");
  const name = String(input.name ?? "").trim();
  if (!/^[A-Za-z0-9 ._-]{1,32}$/.test(name)) throw new Error("device name: 1-32 letters, digits, space . _ -");
  let publicKey = String(input.publicKey ?? "").trim();
  let privateKey = "";
  if (publicKey) {
    if (!PUBKEY.test(publicKey)) throw new Error("not a WireGuard public key");
  } else {
    // Phones: generate the device's keys here, hand them over once, keep only the public key.
    privateKey = await wg(["genkey"]);
    publicKey = await wg(["pubkey"], privateKey);
  }
  const used = new Set(peers().map((p) => p.ip));
  let host = 2;
  while (used.has(`${NET}.${host}`) && host < 255) host++;
  if (host >= 255) throw new Error("no free addresses left");
  const ip = `${NET}.${host}`;
  const psk = await wg(["genpsk"]);
  state()
    .query("INSERT INTO vpn_peers (name, public_key, psk, ip, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(name, publicKey, psk, ip, Math.floor(Date.now() / 1000));
  await sync();
  audit(actor, "vpn.peer.add", { name, ip, generated: !!privateKey });
  const s = await status();
  const config = clientConfig({ privateKey: privateKey || "<this device's private key>", ip, psk }, { publicKey: s.publicKey, endpoint: s.endpoint, port: s.port });
  let qr = "";
  if (privateKey) {
    const r = await run(["qrencode", "-t", "SVG", "-o", "-"], { input: config, check: false });
    if (r.code === 0) qr = `data:image/svg+xml;base64,${Buffer.from(r.stdout).toString("base64")}`;
  }
  return { name, ip, config, qr, generated: !!privateKey };
}

export async function removePeer(id: number, actor: string) {
  const p = peers().find((x) => x.id === id);
  if (!p) throw new Error("no such device");
  state().query("DELETE FROM vpn_peers WHERE id = ?").run(id);
  await sync();
  audit(actor, "vpn.peer.remove", { name: p.name, ip: p.ip });
}

let revertTimer: Timer | undefined;

/**
 * New locks take effect at once but stay pending: unless confirmed from inside
 * the tunnel before the deadline, the previous locks come back.
 */
export async function setLocks(next: Locks, confirmSeconds: number, actor: string) {
  if (settings.get("vpn.enabled") !== "1") throw new Error("enable private access first");
  if ((next.ssh || next.services) && !peers().length) throw new Error("add a device first, or you cannot reach the server afterwards");
  const seconds = Math.min(Math.max(Math.floor(confirmSeconds) || 300, 30), 900);
  const previous = pending()?.previous ?? locks();
  settings.set("vpn.locks", JSON.stringify(next));
  await sync();
  await setPanelOverVpn(next.panel);
  const tighter = (next.ssh && !previous.ssh) || (next.services && !previous.services);
  if (tighter) {
    settings.set("vpn.pending", JSON.stringify({ previous, deadline: Date.now() + seconds * 1000 }));
    scheduleRevert();
  } else {
    settings.set("vpn.pending", "");
  }
  audit(actor, "vpn.locks", { ...next, confirmWithin: tighter ? seconds : 0 });
}

function scheduleRevert() {
  clearTimeout(revertTimer);
  const p = pending();
  if (!p) return;
  revertTimer = setTimeout(() => revertUnconfirmed().catch((e) => console.error(`[agent] vpn revert: ${e}`)), Math.max(p.deadline - Date.now(), 0));
}

async function revertUnconfirmed() {
  const p = pending();
  if (!p) return;
  settings.set("vpn.locks", JSON.stringify(p.previous));
  settings.set("vpn.pending", "");
  await sync();
  await setPanelOverVpn(p.previous.panel);
  audit("system", "vpn.locks.reverted", { reason: "not confirmed over WireGuard in time" });
  void notify("⚠️ private access: new locks were not confirmed over WireGuard and have been undone");
}

/** Confirmation counts only when it arrives through the tunnel: that proves the tunnel works. */
export function confirm(remote: string, actor: string) {
  if (!pending()) return { confirmed: false, reason: "nothing to confirm" };
  const ip = remote.replace(/^::ffff:/, "");
  if (!ip.startsWith(`${NET}.`)) throw new Error(`open the panel over WireGuard (http://${SERVER_IP}:7800) to confirm; this request came from ${ip}`);
  settings.set("vpn.pending", "");
  clearTimeout(revertTimer);
  audit(actor, "vpn.locks.confirmed", { from: ip });
  return { confirmed: true };
}

/** At agent start: an expired, unconfirmed lock is undone; one still in its window is re-armed. */
export async function recoverPending() {
  // Old installs still have pano0 in the trusted zone: moved at the first start after the update.
  if (settings.get("vpn.enabled") === "1") {
    await syncZone().catch((e) => console.error(`[agent] vpn firewall zone: ${e}`));
    // Installs from before the separate locks unit get it (and keep it after every update).
    if (!DRY_RUN) await ensureLocksUnit().catch((e) => console.error(`[agent] vpn locks unit: ${e}`));
  }
  const p = pending();
  if (!p) return;
  if (p.deadline <= Date.now()) await revertUnconfirmed();
  else scheduleRevert();
}
