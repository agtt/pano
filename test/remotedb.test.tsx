import { expect, test } from "bun:test";
import { renderCaddyfile } from "../src/agent/edge.ts";
import { renderRules as fwRules } from "../src/agent/firewall.ts";
import { accountHosts, bindFor, hostSpec, remoteUrls, renderDropin } from "../src/agent/mysqlremote.ts";
import { mergeHba, remoteUrl, renderHbaBlock } from "../src/agent/pgremote.ts";
import { lit, SQL_PRELUDE } from "../src/agent/mysql.ts";
import { assertRemoteDomainFree, parseAllow } from "../src/agent/remotedb.ts";
import { sites } from "../src/agent/state.ts";
import { cidr, nftAccept } from "../src/agent/remotedb-config.ts";
import { pgConf, pgLit } from "../src/agent/services.ts";
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
  const both = fwRules({ ...base, remoteDb: [{ port: 5432, allow: ["1.2.3.4/32"] }, { port: 3306, allow: [] }] });
  expect(both).toContain("ip saddr { 1.2.3.4/32 } tcp dport 5432 accept");
  expect(both).toContain("tcp dport 3306 accept");

  const locks = { panel: false, ssh: false, services: true, databases: false };
  const open = vpnRules(locks, 22, [{ port: 3306, allow: [] }]);
  expect(open.indexOf("tcp dport 3306 accept")).toBeLessThan(open.indexOf("{ 3306, 5432"));
  expect(vpnRules(locks, 22)).not.toContain("tcp dport 3306 accept");
  // Without the services lock nothing changes.
  expect(vpnRules({ ...locks, services: false }, 22, [{ port: 5432, allow: [] }])).toBe(vpnRules({ ...locks, services: false }, 22));
});

test("edge: one certificate-only block per name, shared with TURN and between engines", () => {
  const caddy = (s: { turnDomain?: string; dbDomains?: string[] }) =>
    renderCaddyfile({ apps: [], sites: [], settings: { email: "", behindCloudflare: false, hooksDomain: "", ...s }, certs: new Set() });
  expect(caddy({ dbDomains: ["db.example.com"] })).toContain("db.example.com {");
  expect(caddy({ dbDomains: ["x.example.com", "x.example.com"], turnDomain: "x.example.com" }).match(/x\.example\.com \{/g)?.length).toBe(1);
});

test("MariaDB: drop-in, listen list, account hosts", () => {
  const d = renderDropin({ bind: "127.0.0.1,203.0.113.7", cert: "/t/server.crt", key: "/t/server.key" });
  expect(d).toContain("[mysqld]\nbind-address = 127.0.0.1,203.0.113.7\nssl_cert = /t/server.crt\nssl_key = /t/server.key\ntls_version = TLSv1.2,TLSv1.3");
  expect(renderDropin({ cert: "/c", key: "/k" })).not.toContain("bind-address");

  expect(bindFor("127.0.0.1", "203.0.113.7")).toBe("127.0.0.1,203.0.113.7");
  expect(bindFor("127.0.0.1,203.0.113.7", "203.0.113.7")).toBe("127.0.0.1,203.0.113.7");
  // Already everywhere: nothing to add (and no 10.11 list syntax needed).
  for (const w of ["", "*", "0.0.0.0", "::"]) expect(bindFor(w, "203.0.113.7")).toBeUndefined();

  expect(hostSpec("203.0.113.7/32")).toBe("203.0.113.7");
  expect(hostSpec("198.51.100.0/24")).toBe("198.51.100.0/255.255.255.0");
  expect(hostSpec("10.0.0.0/8")).toBe("10.0.0.0/255.0.0.0");
  expect(hostSpec("2001:db8::1/128")).toBe("2001:db8::1");
  expect(() => hostSpec("2001:db8::/48")).toThrow("IPv6");
  expect(accountHosts([])).toEqual(["%"]);
  expect(accountHosts(["203.0.113.7/32", "198.51.100.0/24"])).toEqual(["203.0.113.7", "198.51.100.0/255.255.255.0"]);

  const u = remoteUrls({ user: "shop_r_ab12cd", database: "shop" }, "pw", "db.example.com");
  expect(u.prisma).toBe("mysql://shop_r_ab12cd:pw@db.example.com:3306/shop?sslaccept=strict");
  expect(JSON.parse(new URL(u.mysql2).searchParams.get("ssl")!)).toEqual({ rejectUnauthorized: true });
});

test("SQL literals: the quote never ends the string, every batch starts in a sane sql_mode", () => {
  expect(lit("a'b\\c")).toBe("'a''b\\\\c'");
  expect(lit("x'; DROP USER y; -- ")).toBe("'x''; DROP USER y; -- '");
  expect(SQL_PRELUDE).toBe("SET SESSION sql_mode='';\n");
  expect(pgLit("a'b\\c")).toBe("E'a''b\\\\c'");
});

test("remote database name: refused when an app, site or preview serves it", () => {
  sites.upsert({ name: "ct-db-taken", kind: "proxy", domains: ["taken.db.example.com"], root: "", routes: [], ask_url: "", php_version: "", tls_cert: "", tls_key: "", source: "container", enabled: 1, on_demand_tls: 0 });
  try {
    expect(() => assertRemoteDomainFree("taken.db.example.com")).toThrow("already used");
    expect(() => assertRemoteDomainFree("free.db.example.com")).not.toThrow();
  } finally {
    sites.remove("ct-db-taken");
  }
});

test("URL verifies the certificate", () => {
  expect(remoteUrl({ user: "u", database: "d" }, "pw", "db.example.com")).toBe("postgres://u:pw@db.example.com:5432/d?sslmode=verify-full");
});
