// TURN for calls and games: coturn, installed only when asked for.
// WebRTC (voice and video calls, peer-to-peer game data) needs a relay when
// both sides sit behind NAT. Apps never hand out a fixed password: they get
// TURN_SECRET and mint short-lived credentials themselves (the TURN REST
// scheme: username "<expiry>:<user>", password base64 HMAC-SHA1 of it), and
// the server only checks the HMAC. The relay refuses private, loopback,
// link-local and CGNAT/Tailscale peers, so it cannot be used to reach services
// on this host or its networks, and quotas cap what one user or all together
// may take. An existing coturn (CyberPanel servers often have one) is adopted
// with its secret, so clients that already use it keep working.

import { createHmac } from "node:crypto";
import { hostname } from "node:os";
import { paths } from "../shared/config.ts";
import { audit, settings } from "./state.ts";
import { ensureDir, exists, readText, remove, run, writeAtomic } from "./sys.ts";

const CONF = "/etc/coturn/turnserver.conf";
const DROPIN = `${paths.systemd}/coturn.service.d/pano.conf`;
const UNIT = "coturn.service";
const MARK = "# Written by pano";
export const PORT = 3478;
export const RELAY = { min: 49160, max: 49200 };

/** Peers the relay must never reach: this host, private networks, CGNAT (Tailscale), multicast. */
export const DENIED_PEERS = [
  "0.0.0.0-0.255.255.255",
  "10.0.0.0-10.255.255.255",
  "100.64.0.0-100.127.255.255",
  "127.0.0.0-127.255.255.255",
  "169.254.0.0-169.254.255.255",
  "172.16.0.0-172.31.255.255",
  "192.0.0.0-192.0.0.255",
  "192.168.0.0-192.168.255.255",
  "198.18.0.0-198.19.255.255",
  "224.0.0.0-255.255.255.255",
  "::-::1",
  "::ffff:0.0.0.0-::ffff:255.255.255.255",
  "64:ff9b::-64:ff9b::ffff:ffff",
  "fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
  "fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
];

export function renderConf(o: { ip: string; realm: string; secret: string }): string {
  // From the recovery bundle or an adopted config: one token, nothing that could add a line.
  if (!/^[A-Za-z0-9+\/=_-]{16,128}$/.test(o.secret)) throw new Error("invalid TURN secret");
  return `${MARK}; changes here are overwritten. The original is in turnserver.conf.pano-orig.
listening-port=${PORT}
listening-ip=${o.ip}
relay-ip=${o.ip}
external-ip=${o.ip}
min-port=${RELAY.min}
max-port=${RELAY.max}
realm=${o.realm}
use-auth-secret
static-auth-secret=${o.secret}
fingerprint
# UDP and TCP to the client; relayed traffic is UDP only (what WebRTC uses).
no-tcp-relay
no-tls
no-dtls
no-cli
no-multicast-peers
no-rfc5780
no-stun-backward-compatibility
response-origin-only-with-rfc5780
no-software-attribute
stale-nonce=600
max-allocate-lifetime=3600
user-quota=12
total-quota=1200
max-bps=3000000
${DENIED_PEERS.map((r) => `denied-peer-ip=${r}`).join("\n")}
syslog
`;
}

/** The unit as shipped, with the process locked down and a smaller CPU share than websites. */
export function renderDropin(): string {
  return `[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
ReadWritePaths=-/var/lib/coturn -/var/log/coturn -/run/coturn -/var/run/coturn
CPUWeight=50
MemoryMax=512M
TasksMax=256
`;
}

/** Short-lived TURN credentials for one user (what an app's server does with TURN_SECRET). */
export function credentials(secret: string, user: string, ttlSeconds = 3600, now = Date.now()) {
  const username = `${Math.floor(now / 1000) + ttlSeconds}:${user}`;
  return { username, credential: createHmac("sha1", secret).update(username).digest("base64") };
}

async function publicIp(): Promise<string> {
  const r = await run(["ip", "-4", "route", "get", "1.1.1.1"], { check: false });
  return r.stdout.match(/\bsrc (\S+)/)?.[1] ?? "";
}

const confSecret = (conf: string | null) => conf?.match(/^\s*static-auth-secret\s*=\s*(\S+)/m)?.[1] ?? "";
const firewalld = async () => (await run(["firewall-cmd", "--state"], { check: false })).stdout.trim() === "running";
const isActive = async () => (await run(["systemctl", "is-active", UNIT], { check: false })).stdout.trim();
const installed = async () => (await run(["rpm", "-q", "coturn"], { check: false })).code === 0;

export async function turnSecret(): Promise<string> {
  const s = confSecret(await readText(CONF));
  if (!s) throw new Error("TURN is not installed");
  return s;
}

/** Where clients connect: the domain when one is set (it must point here), else the address. */
async function host(): Promise<string> {
  return settings.get("turn.domain") || (await publicIp());
}

export function urlsFor(h: string): string[] {
  return [`turn:${h}:${PORT}?transport=udp`, `turn:${h}:${PORT}?transport=tcp`, `stun:${h}:${PORT}`];
}

async function firewall(open: boolean) {
  if (!(await firewalld())) return;
  const op = open ? "--add-port" : "--remove-port";
  for (const p of [`${PORT}/udp`, `${PORT}/tcp`, `${RELAY.min}-${RELAY.max}/udp`]) await run(["firewall-cmd", "--permanent", `${op}=${p}`], { check: false });
  await run(["firewall-cmd", "--reload"], { check: false });
}

async function write(secretValue: string) {
  const ip = await publicIp();
  if (!ip) throw new Error("no public IPv4 address found");
  await writeAtomic(CONF, renderConf({ ip, realm: settings.get("turn.domain") || hostname(), secret: secretValue }), 0o640);
  await run(["chown", "root:coturn", CONF]);
  await ensureDir(`${paths.systemd}/coturn.service.d`, 0o755);
  await writeAtomic(DROPIN, renderDropin(), 0o644);
  await run(["systemctl", "daemon-reload"]);
}

async function restart() {
  await run(["systemctl", "enable", UNIT], { check: false });
  await run(["systemctl", "restart", UNIT]);
  for (let i = 0; i < 20; i++) {
    if ((await isActive()) === "active" && (await run(["ss", "-Hlun", `sport = :${PORT}`], { check: false })).stdout.trim()) return;
    await Bun.sleep(250);
  }
  const log = (await run(["journalctl", "-u", UNIT, "-n", "5", "--no-pager"], { check: false })).stdout.trim();
  throw new Error(`coturn did not start: ${log.split("\n").at(-1) ?? ""}`);
}

export async function install(actor: string) {
  const preexisting = await installed();
  if (!preexisting) {
    await run(["dnf", "-y", "install", "epel-release"], { check: false, timeoutMs: 600_000 });
    await run(["dnf", "-y", "install", "coturn"], { timeoutMs: 600_000 });
  }
  const current = await readText(CONF);
  // An existing setup keeps its secret, so clients already using it keep working,
  // and gets its own config back on uninstall.
  const foreign = preexisting && !!current && !current.startsWith(MARK);
  const adopted = foreign ? confSecret(current) : "";
  if (foreign && !(await exists(`${CONF}.pano-orig`))) await writeAtomic(`${CONF}.pano-orig`, current!, 0o600);
  await write(adopted || confSecret(current) || Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex"));
  await firewall(true);
  await restart();
  settings.set("turn.installed", "1");
  audit(actor, "turn.install", { adopted: !!adopted });
  return { adopted: !!adopted };
}

/** Recovery on a new server: installed again with the secret the apps already have. */
export async function reinstall(secretValue: string, actor: string) {
  await install(actor);
  if (secretValue) {
    await write(secretValue);
    await restart();
  }
}

/** A new secret; every app that has TURN_SECRET gets it and is restarted by the caller. */
export async function rotate(actor: string) {
  const next = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
  await write(next);
  await restart();
  audit(actor, "turn.rotate");
  return next;
}

export async function setDomain(domain: string, actor: string) {
  if (domain && !/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain)) throw new Error("domain: e.g. turn.example.com");
  settings.set("turn.domain", domain.toLowerCase());
  if (await installed()) {
    await write(await turnSecret());
    await restart();
  }
  audit(actor, "turn.domain", { domain });
}

/** An adopted coturn goes back to its original config; one pano installed is removed. */
export async function uninstall(actor: string) {
  await remove(DROPIN);
  await run(["systemctl", "daemon-reload"], { check: false });
  const orig = await readText(`${CONF}.pano-orig`);
  if (orig) {
    await writeAtomic(CONF, orig, 0o640);
    await run(["chown", "root:coturn", CONF]);
    await remove(`${CONF}.pano-orig`);
    await run(["systemctl", "restart", UNIT], { check: false });
  } else {
    await run(["systemctl", "disable", "--now", UNIT], { check: false });
    await firewall(false);
    await run(["dnf", "-y", "remove", "coturn"], { check: false, timeoutMs: 600_000 });
  }
  settings.set("turn.domain", "");
  settings.set("turn.installed", "0");
  audit(actor, "turn.uninstall", { restored: !!orig });
}

export function envFor(urls: string[], secretValue: string): Record<string, string> {
  return { TURN_URLS: urls.join(","), TURN_SECRET: secretValue, NEXT_PUBLIC_TURN_URLS: urls.join(",") };
}

export async function toAppEnv(
  env: { get: () => Promise<Record<string, string>>; set: (vars: Record<string, string>) => Promise<void> },
  appName: string,
  actor: string,
) {
  const current = await env.get();
  await env.set({ ...current, ...envFor(urlsFor(await host()), await turnSecret()) });
  audit(actor, "turn.app.env", { app: appName });
}

export async function turnStatus() {
  const pkg = await installed();
  const conf = pkg ? await readText(CONF) : null;
  const active = pkg ? await isActive() : "";
  const mem = pkg ? Number((await run(["systemctl", "show", UNIT, "-p", "MemoryCurrent", "--value"], { check: false })).stdout.trim()) || 0 : 0;
  const allocations = pkg
    ? (await run(["ss", "-Hun", `sport >= :${RELAY.min} and sport <= :${RELAY.max}`], { check: false })).stdout.trim().split("\n").filter(Boolean).length
    : 0;
  const h = pkg ? await host() : "";
  return {
    installed: pkg,
    managed: !!conf?.startsWith(MARK),
    active,
    memory: mem,
    domain: settings.get("turn.domain") ?? "",
    urls: h ? urlsFor(h) : [],
    allocations,
    port: PORT,
    relay: RELAY,
  };
}
