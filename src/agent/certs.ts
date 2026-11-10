// Expiry of the certificates sites bring from before pano (Let's Encrypt, Cloudflare Origin CA).
// The edge renews its own; these are the ones that can quietly run out.

import { X509Certificate } from "node:crypto";
import { sites } from "./state.ts";
import { readText } from "./sys.ts";

export type CertInfo = { site: string; file: string; notAfter: number; issuer: string } | { site: string; file: string; error: string };

export async function siteCerts(): Promise<CertInfo[]> {
  const out: CertInfo[] = [];
  for (const s of sites.list()) {
    if (!s.tls_cert) continue;
    try {
      const pem = await readText(s.tls_cert);
      if (!pem) throw new Error("file missing");
      const c = new X509Certificate(pem);
      const issuer = c.issuer.match(/(?:^|\n)O=([^\n]+)/)?.[1] ?? c.issuer.match(/CN=([^\n]+)/)?.[1] ?? "";
      out.push({ site: s.name, file: s.tls_cert, notAfter: Math.floor(Date.parse(c.validTo) / 1000), issuer });
    } catch (e) {
      out.push({ site: s.name, file: s.tls_cert, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}
