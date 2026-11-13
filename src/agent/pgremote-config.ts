// PostgreSQL remote access settings, read by the edge (certificate), the firewalls and the
// VPN locks (the port they open). A leaf module so none of them import pgremote.ts.

import { isIP } from "node:net";
import { settings } from "./state.ts";

export const PG_REMOTE_PORT = 5432;

/** on: listening beyond localhost; allow: source networks (empty = any address). */
export type PgRemote = { on: boolean; domain: string; allow: string[] };

export function pgRemoteConfig(): PgRemote {
  const raw = JSON.parse(settings.get("pg.remote") || "null") ?? {};
  return { on: raw.on === true, domain: typeof raw.domain === "string" ? raw.domain : "", allow: Array.isArray(raw.allow) ? raw.allow.filter((c: unknown) => typeof c === "string" && !!cidr(c)) : [] };
}

/** The port and sources the firewalls must let in, or null while remote access is off. */
export function pgRemoteOpen(): { port: number; allow: string[] } | null {
  const c = pgRemoteConfig();
  return c.on ? { port: PG_REMOTE_PORT, allow: c.allow } : null;
}

/** "203.0.113.7" or "203.0.113.0/24" (IPv4 or IPv6) in canonical "addr/prefix" form; null when it is not one. */
export function cidr(input: string): string | null {
  const m = input.trim().match(/^([0-9a-fA-F:.]{2,45})(?:\/(\d{1,3}))?$/);
  if (!m) return null;
  const fam = isIP(m[1]!);
  if (!fam) return null;
  const max = fam === 4 ? 32 : 128;
  const bits = m[2] === undefined ? max : Number(m[2]);
  // A /0 is "anywhere": that is what an empty list means, written out it is only a mistake waiting to happen.
  if (!Number.isInteger(bits) || bits < 1 || bits > max) return null;
  // Host bits cleared (203.0.113.7/24 → 203.0.113.0/24): nft and pg_hba then agree on what is meant.
  return `${fam === 4 ? network4(m[1]!, bits) : network6(m[1]!, bits)}/${bits}`;
}

function network4(addr: string, bits: number): string {
  const n = addr.split(".").reduce((a, o) => (a << 8n) | BigInt(Number(o)), 0n);
  const net = n & (((1n << 32n) - 1n) ^ ((1n << BigInt(32 - bits)) - 1n));
  return [24n, 16n, 8n, 0n].map((s) => String((net >> s) & 255n)).join(".");
}

function network6(addr: string, bits: number): string {
  let s = addr.toLowerCase();
  // An embedded IPv4 tail (::ffff:1.2.3.4) as two hex groups.
  const v4 = s.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number) as [number, number, number, number];
    s = s.slice(0, v4.index) + `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = s.includes("::") ? s.split("::") : [s, undefined];
  const h = head ? head.split(":") : [];
  const t = tail === undefined ? [] : tail ? tail.split(":") : [];
  const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  const n = groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
  const net = n & (((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n));
  const out = Array.from({ length: 8 }, (_, i) => ((net >> BigInt((7 - i) * 16)) & 0xffffn).toString(16));
  // Longest run of zero groups becomes "::".
  let best = [-1, 0];
  for (let i = 0; i < 8; ) {
    if (out[i] !== "0") {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && out[j] === "0") j++;
    if (j - i > best[1]! && j - i > 1) best = [i, j - i];
    i = j;
  }
  if (best[0]! < 0) return out.join(":");
  return `${out.slice(0, best[0]).join(":")}::${out.slice(best[0]! + best[1]!).join(":")}`;
}

/** nft accept rules for the remote port: one per address family, or the port for everyone when the list is empty. */
export function nftAccept(open: { port: number; allow: string[] }): string[] {
  if (!open.allow.length) return [`\t\ttcp dport ${open.port} accept`];
  const v4 = open.allow.filter((c) => !c.includes(":"));
  const v6 = open.allow.filter((c) => c.includes(":"));
  return [
    ...(v4.length ? [`\t\tip saddr { ${v4.join(", ")} } tcp dport ${open.port} accept`] : []),
    ...(v6.length ? [`\t\tip6 saddr { ${v6.join(", ")} } tcp dport ${open.port} accept`] : []),
  ];
}
