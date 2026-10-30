// Optional default-deny inbound firewall, off until enabled (many servers already
// sit behind a provider firewall such as Hetzner Cloud Firewall). It lives in its
// own nftables table next to the private-access one (pano_vpn): a drop in either
// table wins, so both stay independent. Enabling is armed with an automatic
// rollback: unless confirmed from the panel within a couple of minutes the table
// is removed again. Only a confirmed firewall is written to disk and started at
// boot, so a mistake is undone by waiting or by a reboot.

import { env, paths } from "../shared/config.ts";
import { type FwPort, formatPorts, parsePorts } from "../shared/validate.ts";
import { notify } from "./alerts.ts";
import { audit, settings } from "./state.ts";
import { PORT as TURN_PORT, RELAY as TURN_RELAY } from "./turn.ts";
import { ensureDir, exists, readText, run, writeAtomic } from "./sys.ts";

const TABLE = "pano_fw";
const UNIT = "pano-firewall.service";
const RULES = `${paths.etc}/firewall.nft`;
const IFACE_VPN = "pano0";
/** Long enough to open a new connection and click confirm, short enough to recover alone. */
const DEFAULT_SECONDS = 120;

export type FwOpts = {
  ssh: number[];
  /** Set only when the panel listens on a public address. */
  panel?: number;
  /** WireGuard UDP port, when private access is on. */
  wg?: number;
  turn: boolean;
  extra: FwPort[];
};

/** Sorted, with overlapping and touching ranges merged (nft rejects overlapping elements in one set). */
function setOf(items: [number, number][]): string {
  const sorted = [...items].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const out: [number, number][] = [];
  for (const [a, b] of sorted) {
    const last = out.at(-1);
    if (last && a <= last[1] + 1) last[1] = Math.max(last[1], b);
    else out.push([a, b]);
  }
  return out.map(([a, b]) => (a === b ? String(a) : `${a}-${b}`)).join(", ");
}

export function renderRules(o: FwOpts): string {
  const tcp: [number, number][] = [80, 443, ...o.ssh, ...(o.panel ? [o.panel] : []), ...(o.turn ? [TURN_PORT] : [])].map((p) => [p, p]);
  // 443/udp is HTTP/3.
  const udp: [number, number][] = [[443, 443]];
  if (o.wg) udp.push([o.wg, o.wg]);
  if (o.turn) udp.push([TURN_PORT, TURN_PORT], [TURN_RELAY.min, TURN_RELAY.max]);
  for (const p of o.extra) (p.proto === "tcp" ? tcp : udp).push([p.from, p.to]);
  return [
    `table inet ${TABLE}`,
    `delete table inet ${TABLE}`,
    `table inet ${TABLE} {`,
    "\tchain input {",
    "\t\ttype filter hook input priority 0; policy drop;",
    "\t\tct state invalid drop",
    // Sessions already open (the SSH you are using right now) keep working.
    "\t\tct state established,related accept",
    // Local and private paths: loopback, the WireGuard and Tailscale interfaces, container bridges.
    '\t\tiifname "lo" accept',
    `\t\tiifname "${IFACE_VPN}" accept`,
    '\t\tiifname "tailscale0" accept',
    '\t\tiifname "podman*" accept',
    '\t\tiifname "cni-podman*" accept',
    // Without these the host loses its address, its neighbours and path MTU discovery.
    "\t\ticmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } limit rate 20/second accept",
    "\t\ticmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } limit rate 20/second accept",
    "\t\tudp sport 67 udp dport 68 accept",
    "\t\tudp sport 547 udp dport 546 accept",
    `\t\ttcp dport { ${setOf(tcp)} } accept`,
    `\t\tudp dport { ${setOf(udp)} } accept`,
    "\t}",
    "}",
    "",
  ].join("\n");
}

export function renderUnit(): string {
  return `[Unit]
Description=pano firewall (nftables table ${TABLE})
Wants=network-pre.target
Before=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=nft -f ${RULES}
ExecReload=nft -f ${RULES}
ExecStop=-nft delete table inet ${TABLE}

[Install]
WantedBy=multi-user.target
`;
}

/** The panel is public unless it listens on loopback or a private/Tailscale address (same test as the security audit). */
export function panelIsPublic(host: string): boolean {
  if (host === "127.0.0.1" || host === "::1" || host === "localhost") return false;
  if (host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("100.")) return false;
  return !/^172\.(1[6-9]|2\d|3[01])\./.test(host);
}

/** sshd's configured ports plus whatever sshd is really listening on (a socket-activated or second instance). */
export function sshPorts(sshdT: string, ss: string): number[] {
  const ports = new Set<number>();
  for (const m of sshdT.matchAll(/^port (\d+)$/gm)) ports.add(Number(m[1]));
  for (const line of ss.split("\n")) {
    if (!line.includes('"sshd')) continue;
    const local = line.trim().split(/\s+/)[3] ?? "";
    const port = Number(local.slice(local.lastIndexOf(":") + 1));
    if (port > 0 && port < 65536) ports.add(port);
  }
  return [...ports].sort((a, b) => a - b);
}

export async function detectSsh(): Promise<number[]> {
  const [t, ss] = await Promise.all([run(["sshd", "-T"], { check: false }), run(["ss", "-Hltnp"], { check: false })]);
  return sshPorts(t.stdout, ss.stdout);
}

/** Every SSH port sshd has (a second Port line or instance too), 22 when none is found. */
export async function allSshPorts(): Promise<number[]> {
  const ports = await detectSsh();
  return ports.length ? ports : [22];
}

/** nft port expression: one port, or a set of them. */
export const nftPorts = (p: number | number[]) => (Array.isArray(p) ? (p.length === 1 ? String(p[0]) : `{ ${p.join(", ")} }`) : String(p));

const extraPorts = (): FwPort[] => parsePorts(settings.get("firewall.ports") ?? "");

async function currentOpts(ssh: number[]): Promise<FwOpts> {
  return {
    ssh,
    panel: panelIsPublic(env.webHost) ? env.webPort : undefined,
    wg: settings.get("vpn.enabled") === "1" ? Number(settings.get("vpn.port") ?? 51820) : undefined,
    turn: settings.get("turn.installed") === "1",
    extra: extraPorts(),
  };
}

const on = () => settings.get("firewall.on") === "1";
const deadline = () => Number(settings.get("firewall.pending") || 0);
const loaded = async () => (await run(["nft", "list", "table", "inet", TABLE], { check: false })).code === 0;

/** Checks the rules, then swaps the table in one transaction; the old table stays if either step fails. */
async function apply(rules: string) {
  await ensureDir(paths.etc, 0o755);
  // Checked under another name first: the file the unit loads at boot is only ever a ruleset nft accepted.
  await writeAtomic(`${RULES}.new`, rules, 0o600);
  await run(["nft", "-c", "-f", `${RULES}.new`]);
  await run(["nft", "-f", `${RULES}.new`]);
  await run(["mv", "-f", `${RULES}.new`, RULES]);
}

async function unload() {
  await run(["nft", "delete", "table", "inet", TABLE], { check: false });
}

// ---- operations --------------------------------------------------------------

export async function status() {
  const ssh = await detectSsh();
  const opts = await currentOpts(ssh.length ? ssh : [22]);
  return {
    installed: await exists("/usr/sbin/nft"),
    on: on(),
    loaded: on() ? await loaded() : false,
    /** Seconds left to confirm, or 0 when nothing is waiting. */
    confirmIn: deadline() ? Math.max(Math.ceil((deadline() - Date.now()) / 1000), 0) : 0,
    ports: formatPorts(opts.extra),
    detected: { ssh: opts.ssh, panel: opts.panel ?? null, wg: opts.wg ?? null, turn: opts.turn },
  };
}

let revertTimer: Timer | undefined;

export async function enable(input: { confirmSeconds?: unknown }, actor: string) {
  if (on() && !deadline()) return;
  if (!(await exists("/usr/sbin/nft"))) {
    const os = (await readText("/etc/os-release")) ?? "";
    if (/^(ID|ID_LIKE)=.*\b(debian|ubuntu)\b/m.test(os)) await run(["apt-get", "install", "-y", "nftables"], { timeoutMs: 900_000 });
    else await run(["dnf", "-y", "install", "nftables"], { timeoutMs: 900_000 });
  }
  const ssh = await detectSsh();
  // A guess at 22 is no guess when sshd answered with nothing: refuse rather than risk cutting SSH off.
  if (!ssh.length) throw new Error("could not detect the SSH port (sshd -T); add it under extra ports first, then retry");
  const seconds = Math.min(Math.max(Math.floor(Number(input.confirmSeconds)) || DEFAULT_SECONDS, 60), 600);
  await apply(renderRules(await currentOpts(ssh)));
  settings.set("firewall.on", "1");
  settings.set("firewall.pending", String(Date.now() + seconds * 1000));
  scheduleRevert();
  audit(actor, "firewall.enable", { ssh, confirmWithin: seconds });
}

function scheduleRevert() {
  clearTimeout(revertTimer);
  if (!deadline()) return;
  revertTimer = setTimeout(() => revertUnconfirmed().catch((e) => console.error(`[agent] firewall revert: ${e}`)), Math.max(deadline() - Date.now(), 0));
}

async function revertUnconfirmed() {
  if (!deadline()) return;
  await unload();
  settings.set("firewall.on", "0");
  settings.set("firewall.pending", "");
  audit("system", "firewall.reverted", { reason: "not confirmed in time" });
  void notify("⚠️ firewall: it was not confirmed in time and has been switched off again");
}

/** Reaching the panel through the new rules is the proof; only now does the firewall survive a reboot. */
export async function confirm(actor: string) {
  if (!deadline()) return { confirmed: false, reason: "nothing to confirm" };
  await writeAtomic(`${paths.systemd}/${UNIT}`, renderUnit(), 0o644);
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", UNIT]);
  clearTimeout(revertTimer);
  settings.set("firewall.pending", "");
  audit(actor, "firewall.confirmed", {});
  return { confirmed: true };
}

export async function disable(actor: string) {
  clearTimeout(revertTimer);
  settings.set("firewall.pending", "");
  settings.set("firewall.on", "0");
  await run(["systemctl", "disable", UNIT], { check: false });
  await unload();
  audit(actor, "firewall.disable", {});
}

/** Replaces the extra ports; a confirmed, running firewall picks them up at once. */
export async function setPorts(text: unknown, actor: string) {
  const list = parsePorts(text);
  settings.set("firewall.ports", formatPorts(list));
  if (on() && !deadline()) await refresh();
  audit(actor, "firewall.ports", { count: list.length });
  return list.length;
}

/** Re-renders a confirmed firewall so it follows VPN, TURN, panel and SSH changes; leaves it as it was if anything fails. */
async function refresh() {
  const ssh = await detectSsh();
  if (!ssh.length) return;
  const rules = renderRules(await currentOpts(ssh));
  if (rules === (await readText(RULES)) && (await loaded())) return;
  await apply(rules);
}

/** At agent start: an expired, unconfirmed firewall is undone; one still in its window is re-armed. */
export async function startFirewall() {
  setInterval(() => {
    if (on() && !deadline()) refresh().catch((e) => console.error(`[agent] firewall refresh: ${e}`));
  }, 5 * 60_000);
  if (!on()) return;
  if (!deadline()) return refresh();
  if (deadline() <= Date.now()) await revertUnconfirmed();
  else scheduleRevert();
}
