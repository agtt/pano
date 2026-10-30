// Behind Cloudflare: Cloudflare's address ranges (kept current, the edge trusts
// them for the visitor's address) and, optionally, a lock in the kernel so only
// Cloudflare reaches ports 80 and 443. Without the lock anyone who finds the
// server's address can go around Cloudflare's firewall, rate limits and cache.
// SSH, the panel (VPN/Tailscale) and localhost are untouched.

import { Resolver } from "node:dns/promises";
import { paths } from "../shared/config.ts";
import { appRoutes, applyEdge, edgeSettings } from "./edge.ts";
import { apps, audit, settings, sites } from "./state.ts";
import { run, writeAtomic } from "./sys.ts";

const UNIT = "pano-cloudflare.service";
const RULES = `${paths.etc}/cloudflare.nft`;
const DAY = 24 * 3600_000;

/** Built in; replaced by the lists Cloudflare publishes once they are fetched. */
export const CLOUDFLARE_RANGES = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
  "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
  "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
  "2a06:98c0::/29", "2c0f:f248::/32",
];

// ---- addresses ----------------------------------------------------------------------

function parse4(ip: string): bigint | null {
  const p = ip.split(".");
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
}

function parse6(ip: string): bigint | null {
  if (!/^[0-9a-f:]+$/i.test(ip)) return null;
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const groups = [...head, ...Array<string>(Math.max(fill, 0)).fill("0"), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return groups.reduce((a, g) => (a << 16n) | BigInt(parseInt(g, 16)), 0n);
}

const parseIp = (ip: string) => (ip.includes(":") ? { bits: 128, n: parse6(ip) } : { bits: 32, n: parse4(ip) });

/** "a.b.c.d/n" or "x::/n", null when it is not one. */
export function parseCidr(cidr: string): { bits: number; n: bigint; prefix: number } | null {
  const m = cidr.trim().match(/^([0-9a-fA-F.:]+)\/(\d{1,3})$/);
  if (!m) return null;
  const ip = parseIp(m[1]!);
  const prefix = Number(m[2]);
  return ip.n === null || prefix > ip.bits ? null : { bits: ip.bits, n: ip.n, prefix };
}

export function inRanges(ip: string, ranges: string[]): boolean {
  const a = parseIp(ip);
  if (a.n === null) return false;
  return ranges.some((r) => {
    const c = parseCidr(r);
    if (!c || c.bits !== a.bits) return false;
    const shift = BigInt(c.bits - c.prefix);
    return a.n! >> shift === c.n >> shift;
  });
}

/** One CIDR per line, as Cloudflare publishes them; null when anything else is in there. */
export function parseRangeList(text: string, v6: boolean): string[] | null {
  const out = text.split("\n").map((l) => l.trim()).filter(Boolean);
  return out.length && out.every((l) => parseCidr(l)?.bits === (v6 ? 128 : 32)) ? out : null;
}

/** The current ranges: fetched ones when there are, else the built-in list. */
export function cloudflareRanges(): string[] {
  try {
    const r = JSON.parse(settings.get("cloudflare.ranges") ?? "null") as { v4: string[]; v6: string[] } | null;
    if (r?.v4?.length && r.v6?.length) return [...r.v4, ...r.v6];
  } catch {}
  return CLOUDFLARE_RANGES;
}

/** Fetches Cloudflare's lists (at most once a day, only behind Cloudflare); applies them when they changed. */
export async function refreshRanges(force = false) {
  if (!edgeSettings().behindCloudflare) return;
  if (!force && Date.now() - Number(settings.get("cloudflare.ranges.at") ?? 0) < DAY) return;
  const get = async (url: string) => (await fetch(url, { signal: AbortSignal.timeout(15_000) })).text();
  const [v4, v6] = await Promise.all([get("https://www.cloudflare.com/ips-v4"), get("https://www.cloudflare.com/ips-v6")]);
  const r4 = parseRangeList(v4, false);
  const r6 = parseRangeList(v6, true);
  // A truncated or odd answer must never shrink the lock to a few addresses.
  if (!r4 || !r6 || r4.length < 5 || r6.length < 3) throw new Error("Cloudflare's address lists look wrong; kept the current ones");
  const before = cloudflareRanges().join(" ");
  settings.set("cloudflare.ranges", JSON.stringify({ v4: r4, v6: r6 }));
  settings.set("cloudflare.ranges.at", String(Date.now()));
  if (cloudflareRanges().join(" ") === before) return;
  await applyEdge();
  if (locked()) await loadLock();
}

// ---- the lock -----------------------------------------------------------------------

const locked = () => settings.get("cloudflare.lock") === "1";

export function renderLock(ranges: string[]): string {
  const v4 = ranges.filter((r) => !r.includes(":"));
  const v6 = ranges.filter((r) => r.includes(":"));
  const web = "meta l4proto { tcp, udp } th dport { 80, 443 }";
  return [
    "table inet pano_cf",
    "delete table inet pano_cf",
    "table inet pano_cf {",
    `\tset cf4 { type ipv4_addr; flags interval; elements = { ${v4.join(", ")} } }`,
    `\tset cf6 { type ipv6_addr; flags interval; elements = { ${v6.join(", ")} } }`,
    "\tchain input {",
    "\t\ttype filter hook input priority -5; policy accept;",
    '\t\tiifname { "lo", "pano0", "tailscale0" } accept',
    `\t\t${web} ip saddr @cf4 accept`,
    `\t\t${web} ip6 saddr @cf6 accept`,
    `\t\t${web} drop`,
    "\t}",
    "}",
    "",
  ].join("\n");
}

async function loadLock() {
  await writeAtomic(RULES, renderLock(cloudflareRanges()), 0o600);
  // Checked before it is loaded: a rule nft rejects never half-applies.
  await run(["nft", "-c", "-f", RULES]);
  await writeAtomic(
    `${paths.systemd}/${UNIT}`,
    `[Unit]\nDescription=pano: only Cloudflare reaches ports 80 and 443\nAfter=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=nft -f ${RULES}\nExecReload=nft -f ${RULES}\nExecStop=-nft delete table inet pano_cf\n\n[Install]\nWantedBy=multi-user.target\n`,
    0o644,
  );
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", UNIT]);
  await run(["systemctl", "restart", UNIT]);
}

/** Every name the edge serves (wildcards aside): what has to come through Cloudflare once the lock is on. */
export function servedDomains(): string[] {
  const s = edgeSettings();
  const names = new Set<string>();
  for (const a of apps.list()) for (const host of appRoutes(a).keys()) names.add(host);
  for (const site of sites.list()) for (const d of site.domains) names.add(d);
  if (s.hooksDomain) names.add(s.hooksDomain);
  return [...names].filter((d) => d && !d.startsWith("*.")).sort();
}

export type DnsCheck = { domain: string; addrs: string[]; cloudflare: boolean };

/** Where each served name points: through Cloudflare (proxied, orange cloud) or straight at this server. */
export async function checkDns(domains = servedDomains()): Promise<DnsCheck[]> {
  const r = new Resolver({ timeout: 3000, tries: 2 });
  const ranges = cloudflareRanges();
  return Promise.all(
    domains.map(async (domain) => {
      const [a, aaaa] = await Promise.all([r.resolve4(domain).catch(() => [] as string[]), r.resolve6(domain).catch(() => [] as string[])]);
      const addrs = [...a, ...aaaa];
      return { domain, addrs, cloudflare: addrs.length > 0 && addrs.every((x) => inRanges(x, ranges)) };
    }),
  );
}

/** What would stop working with the lock on. */
export async function lockProblems(): Promise<string[]> {
  const out: string[] = [];
  const s = edgeSettings();
  if (s.turnDomain) out.push(`${s.turnDomain} (TURN) must reach this server directly; its certificate could not be renewed`);
  for (const d of await checkDns()) if (d.addrs.length && !d.cloudflare) out.push(`${d.domain} points at ${d.addrs.join(", ")}, not through Cloudflare (turn its proxy on)`);
  return out;
}

export async function setLock(on: boolean, force: boolean, actor: string) {
  if (on) {
    if (!edgeSettings().behindCloudflare) throw new Error('turn on "Sites are behind Cloudflare" first');
    const problems = await lockProblems();
    if (problems.length && !force) throw new Error(`these would stop working: ${problems.join("; ")}`);
    await refreshRanges(true).catch((e) => console.error(`[agent] cloudflare ranges: ${e}`));
    await loadLock();
    settings.set("cloudflare.lock", "1");
    audit(actor, "cloudflare.lock", { on, force, problems });
  } else {
    await run(["systemctl", "disable", "--now", UNIT], { check: false });
    await run(["nft", "delete", "table", "inet", "pano_cf"], { check: false });
    settings.set("cloudflare.lock", "0");
    audit(actor, "cloudflare.lock", { on });
  }
}

export function cloudflareStatus() {
  const r = cloudflareRanges();
  return { locked: locked(), ranges: r.length, updatedAt: Number(settings.get("cloudflare.ranges.at") ?? 0) };
}
