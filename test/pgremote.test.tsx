import { expect, test } from "bun:test";
import { renderCaddyfile } from "../src/agent/edge.ts";
import { renderRules as fwRules } from "../src/agent/firewall.ts";
import { cidr, nftAccept } from "../src/agent/pgremote-config.ts";
import { mergeHba, parseAllow, remoteUrl, renderHbaBlock } from "../src/agent/pgremote.ts";
import { pgConf } from "../src/agent/services.ts";
import { renderRules as vpnRules } from "../src/agent/vpn.ts";

test("cidr: canonical networks, host bits cleared, no /0", () => {
  expect(cidr("203.0.113.7")).toBe("203.0.113.7/32");
  expect(cidr("203.0.113.7/24")).toBe("203.0.113.0/24");
  expect(cidr("2001:DB8::1/48")).toBe("2001:db8::/48");
  expect(cidr("2001:db8:0:0:1:0:0:1")).toBe("2001:db8::1:0:0:1/128");
  expect(cidr("0.0.0.0/0")).toBeNull();
  expect(cidr("10.0.0.1/33")).toBeNull();
  expect(cidr("example.com")).toBeNull();
  expect(cidr("1.2.3.4; drop")).toBeNull();
});

test("allowed networks: any separator, duplicates merged, bad entry named", () => {
  expect(parseAllow("1.2.3.4, 1.2.3.4\n5.6.7.0/24")).toEqual(["1.2.3.4/32", "5.6.7.0/24"]);
  expect(parseAllow("")).toEqual([]);
  expect(() => parseAllow("1.2.3.4 nope")).toThrow("nope");
});

test("pg_hba block: TLS + SCRAM per user and network, first in the file, replaced and removed cleanly", () => {
  const block = renderHbaBlock([{ user: "shop_remote_ab12cd", database: "shop" }], ["1.2.3.4/32"]);
  expect(block).toContain('hostssl "shop" "shop_remote_ab12cd" 1.2.3.4/32 scram-sha-256');
  expect(block.some((l) => l.startsWith("host "))).toBe(false);
  const any = renderHbaBlock([{ user: "u", database: "all" }], []);
  expect(any).toContain('hostssl "all" "u" 0.0.0.0/0 scram-sha-256');
  expect(any).toContain('hostssl "all" "u" ::/0 scram-sha-256');
  expect(renderHbaBlock([], ["1.2.3.4/32"])).toEqual([]);

  const stock = "local all postgres peer\nhost all all 127.0.0.1/32 scram-sha-256\n";
  const once = mergeHba(stock, block);
  expect(once.startsWith(block[0]!)).toBe(true);
  expect(mergeHba(once, block)).toBe(once);
  expect(mergeHba(once, [])).toBe(stock);
});

test("postgresql.conf: localhost only unless remote, then TLS 1.2+ with the given files", () => {
  expect(pgConf()).toContain("listen_addresses = 'localhost'");
  expect(pgConf()).not.toContain("ssl = on");
  const r = pgConf({ listen: ["203.0.113.7"], cert: "/d/pano-tls/server.crt", key: "/d/pano-tls/server.key" });
  expect(r).toContain("listen_addresses = 'localhost, 203.0.113.7'");
  expect(r).toContain("ssl = on\nssl_cert_file = '/d/pano-tls/server.crt'\nssl_key_file = '/d/pano-tls/server.key'\nssl_min_protocol_version = 'TLSv1.2'");
  expect(r).toContain("password_encryption = 'scram-sha-256'");
});

test("firewalls: the port for everyone or per family from the list; the VPN services lock lets it through", () => {
  expect(nftAccept({ port: 5432, allow: [] })).toEqual(["\t\ttcp dport 5432 accept"]);
  expect(nftAccept({ port: 5432, allow: ["1.2.3.4/32", "2001:db8::/48"] })).toEqual(["\t\tip saddr { 1.2.3.4/32 } tcp dport 5432 accept", "\t\tip6 saddr { 2001:db8::/48 } tcp dport 5432 accept"]);

  const base = { ssh: [22], turn: false, extra: [] };
  expect(fwRules(base)).not.toContain("5432");
  expect(fwRules({ ...base, pgRemote: { port: 5432, allow: ["1.2.3.4/32"] } })).toContain("ip saddr { 1.2.3.4/32 } tcp dport 5432 accept");

  const locks = { panel: false, ssh: false, services: true, databases: false };
  const open = vpnRules(locks, 22, { port: 5432, allow: [] });
  expect(open.indexOf("tcp dport 5432 accept")).toBeLessThan(open.indexOf("3306, 5432"));
  expect(vpnRules(locks, 22)).not.toContain("tcp dport 5432 accept");
  // Without the services lock nothing changes.
  expect(vpnRules({ ...locks, services: false }, 22, { port: 5432, allow: [] })).toBe(vpnRules({ ...locks, services: false }, 22));
});

test("edge: one certificate-only block per name, shared with TURN", () => {
  const caddy = (s: { turnDomain?: string; dbDomain?: string }) =>
    renderCaddyfile({ apps: [], sites: [], settings: { email: "", behindCloudflare: false, hooksDomain: "", ...s }, certs: new Set() });
  expect(caddy({ dbDomain: "db.example.com" })).toContain("db.example.com {");
  expect(caddy({ dbDomain: "x.example.com", turnDomain: "x.example.com" }).match(/x\.example\.com \{/g)?.length).toBe(1);
});

test("URL verifies the certificate", () => {
  expect(remoteUrl({ user: "u", database: "d" }, "pw", "db.example.com")).toBe("postgres://u:pw@db.example.com:5432/d?sslmode=verify-full");
});
