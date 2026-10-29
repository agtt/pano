// DNS-rebinding guard: a page on evil.example can point its name at the panel's address and
// then talk to it with the browser's cookies of that name. Such requests carry Host: evil.example,
// so the panel answers only to the names and addresses it is actually reached by.

import { isIP } from "node:net";

const WILDCARD = new Set(["0.0.0.0", "::", ""]);

export type HostEnv = { webHost: string; webVpnHost: string; webHosts?: string };

/** The Host header value without port and brackets, lowercase. */
export function hostName(h: string): string {
  const s = h.trim().toLowerCase();
  const m = s.match(/^\[([^\]]+)\](?::\d+)?$/) ?? s.match(/^([^:]*)(?::\d+)?$/);
  return m?.[1] ?? "";
}

export function allowedHosts(e: HostEnv): { names: Set<string>; anyIp: boolean } {
  const names = new Set(["localhost", "127.0.0.1", "::1"]);
  for (const n of [e.webHost, e.webVpnHost, ...(e.webHosts ?? "").split(",")]) {
    const x = n.trim().toLowerCase();
    if (x && !WILDCARD.has(x)) names.add(x);
  }
  // Listening on every address: which IPs reach us is unknown, but a bare IP cannot be a rebinding name.
  return { names, anyIp: WILDCARD.has(e.webHost.trim()) };
}

export function hostAllowed(header: string | undefined, e: HostEnv): boolean {
  if (!header) return false;
  const h = hostName(header);
  if (!h) return false;
  const { names, anyIp } = allowedHosts(e);
  return names.has(h) || (anyIp && isIP(h) !== 0);
}
