// Database remote access settings (PostgreSQL and MariaDB), read by the edge (certificates), the
// firewalls and the VPN locks (the ports they open). A leaf module so none of them import the
// engine modules (pgremote.ts, mysqlremote.ts).

import { isIP } from "node:net";
import { settings } from "./state.ts";

export type RemoteEngine = "postgres" | "mariadb";
export const REMOTE_ENGINES: RemoteEngine[] = ["postgres", "mariadb"];
export const REMOTE_PORT: Record<RemoteEngine, number> = { postgres: 5432, mariadb: 3306 };
const KEY: Record<RemoteEngine, string> = { postgres: "pg.remote", mariadb: "mysql.remote" };

/** on: listening beyond localhost; allow: source networks (empty = any address). */
export type RemoteConfig = { on: boolean; domain: string; allow: string[] };
export type RemoteOpen = { port: number; allow: string[] };

export function remoteConfig(e: RemoteEngine): RemoteConfig {
  const raw = JSON.parse(settings.get(KEY[e]) || "null") ?? {};
  return { on: raw.on === true, domain: typeof raw.domain === "string" ? raw.domain : "", allow: Array.isArray(raw.allow) ? raw.allow.filter((c: unknown) => typeof c === "string" && !!cidr(c)) : [] };
}

export const saveRemoteConfig = (e: RemoteEngine, c: RemoteConfig) => settings.set(KEY[e], JSON.stringify(c));

/** The ports and sources the firewalls must let in: one entry per engine with remote access on. */
export function remoteOpen(): RemoteOpen[] {
  return REMOTE_ENGINES.map((e) => ({ e, c: remoteConfig(e) }))
    .filter((x) => x.c.on)
    .map((x) => ({ port: REMOTE_PORT[x.e], allow: x.c.allow }));
}

/** Names the edge keeps a certificate for (the engines may share one). */
export const remoteDomains = (): string[] => REMOTE_ENGINES.map(remoteConfig).flatMap((c) => (c.on && c.domain ? [c.domain] : []));

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
  // Host bits cleared (203.0.113.7/24 → 203.0.113.0/24): nft, pg_hba and MariaDB then agree on what is meant.
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

/** nft accept rules for one remote port: one per address family, or the port for everyone when the list is empty. */
export function nftAccept(open: RemoteOpen): string[] {
  if (!open.allow.length) return [`\t\ttcp dport ${open.port} accept`];
  const v4 = open.allow.filter((c) => !c.includes(":"));
  const v6 = open.allow.filter((c) => c.includes(":"));
  return [
    ...(v4.length ? [`\t\tip saddr { ${v4.join(", ")} } tcp dport ${open.port} accept`] : []),
    ...(v6.length ? [`\t\tip6 saddr { ${v6.join(", ")} } tcp dport ${open.port} accept`] : []),
  ];
}
