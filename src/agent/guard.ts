// Brute-force and flood guard in the kernel (nftables), no daemon, no log
// parsing: an address opening SSH connections too fast is banned for a while;
// one opening HTTP connections at flood rates is dropped. WireGuard devices and
// localhost are never limited. Off until switched on.

import { paths } from "../shared/config.ts";
import { edgeSettings } from "./edge.ts";
import { audit, settings } from "./state.ts";
import { run, writeAtomic } from "./sys.ts";

const UNIT = "pano-guard.service";
const RULES = `${paths.etc}/guard.nft`;

export type Guard = { ssh: boolean; http: boolean };

export const guardSettings = (): Guard => ({ ssh: false, http: false, ...JSON.parse(settings.get("guard") ?? "{}") });

export function renderGuard(g: Guard, sshPort: number, behindCloudflare: boolean): string {
  const http = g.http && !behindCloudflare; // behind Cloudflare every visitor arrives from a few Cloudflare addresses
  const sets = (name: string, timeout: string) => [
    `\tset ${name}4 { type ipv4_addr; flags dynamic, timeout; timeout ${timeout}; }`,
    `\tset ${name}6 { type ipv6_addr; flags dynamic, timeout; timeout ${timeout}; }`,
  ];
  return [
    "table inet pano_guard",
    "delete table inet pano_guard",
    "table inet pano_guard {",
    ...(g.ssh ? [...sets("ssh_rate", "1m"), ...sets("ssh_ban", "15m")] : []),
    ...(http ? sets("http_rate", "1m") : []),
    "\tchain input {",
    "\t\ttype filter hook input priority -10; policy accept;",
    '\t\tiifname { "lo", "pano0" } accept',
    ...(g.ssh
      ? [
          `\t\tip saddr @ssh_ban4 tcp dport ${sshPort} drop`,
          `\t\tip6 saddr @ssh_ban6 tcp dport ${sshPort} drop`,
          // 20 new connections a minute is far beyond a person (and git, scp, rsync loops).
          `\t\ttcp dport ${sshPort} ct state new add @ssh_rate4 { ip saddr limit rate over 20/minute burst 20 packets } add @ssh_ban4 { ip saddr } drop`,
          `\t\ttcp dport ${sshPort} ct state new add @ssh_rate6 { ip6 saddr limit rate over 20/minute burst 20 packets } add @ssh_ban6 { ip6 saddr } drop`,
        ]
      : []),
    ...(http
      ? [
          "\t\ttcp dport { 80, 443 } ct state new add @http_rate4 { ip saddr limit rate over 150/second burst 300 packets } drop",
          "\t\ttcp dport { 80, 443 } ct state new add @http_rate6 { ip6 saddr limit rate over 150/second burst 300 packets } drop",
        ]
      : []),
    "\t}",
    "}",
    "",
  ].join("\n");
}

async function sshPort(): Promise<number> {
  const r = await run(["sshd", "-T"], { check: false });
  return Number(r.stdout.match(/^port (\d+)/m)?.[1] ?? 22);
}

export async function setGuard(g: Guard, actor: string) {
  const text = renderGuard(g, await sshPort(), edgeSettings().behindCloudflare);
  await writeAtomic(RULES, text, 0o600);
  // Checked before it is loaded: a rule nft rejects never half-applies.
  await run(["nft", "-c", "-f", RULES]);
  settings.set("guard", JSON.stringify(g));
  if (g.ssh || g.http) {
    await writeAtomic(
      `${paths.systemd}/${UNIT}`,
      `[Unit]\nDescription=pano guard (SSH brute force, HTTP flood)\nAfter=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=nft -f ${RULES}\nExecReload=nft -f ${RULES}\nExecStop=-nft delete table inet pano_guard\n\n[Install]\nWantedBy=multi-user.target\n`,
      0o644,
    );
    await run(["systemctl", "daemon-reload"]);
    await run(["systemctl", "enable", UNIT]);
    await run(["systemctl", "restart", UNIT]);
  } else {
    await run(["systemctl", "disable", "--now", UNIT], { check: false });
  }
  audit(actor, "guard.set", g);
}

/** Banned addresses right now (for the Security page). */
export async function banned(): Promise<string[]> {
  const r = await run(["nft", "-j", "list", "set", "inet", "pano_guard", "ssh_ban4"], { check: false });
  if (r.code !== 0) return [];
  try {
    const set = (JSON.parse(r.stdout).nftables as any[]).find((x) => x.set)?.set;
    return (set?.elem ?? []).map((e: any) => (typeof e === "string" ? e : (e.elem?.val ?? ""))).filter(Boolean);
  } catch {
    return [];
  }
}
