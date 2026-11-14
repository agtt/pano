import { expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { renderValkeyConf, renderValkeyUnit } from "../src/agent/appvalkey.ts";
import { inRanges, parseCidr, parseRangeList, renderLock } from "../src/agent/cloudflare.ts";
import { renderGuard } from "../src/agent/guard.ts";
import { parseDbGrants, wildcardGrant } from "../src/agent/mysql.ts";
import { renderLocksUnit, renderRules } from "../src/agent/vpn.ts";
import { parseSums, signedBy, signedTag } from "../src/release.ts";

test("the signed SHA256SUMS names its release and still parses as checksums", () => {
  const sums = `# pano v1.2.3\n${"a".repeat(64)}  pano-linux-x64\n`;
  expect(signedTag(sums)).toBe("v1.2.3");
  expect(signedTag(`${"a".repeat(64)}  pano-linux-x64\n`)).toBeNull();
  expect(parseSums(sums).get("pano-linux-x64")).toBe("a".repeat(64));
  expect(parseSums(sums).size).toBe(1);
});

test("every SSH port is guarded and locked", () => {
  expect(renderGuard({ ssh: true, http: false }, [22, 2222], false)).toContain("tcp dport { 22, 2222 } ct status assured");
  expect(renderRules({ panel: false, ssh: true, services: false, databases: false }, [22, 2222])).toContain("22, 2222");
});

test("the VPN locks are in place before sshd starts after a reboot", () => {
  const u = renderLocksUnit();
  expect(u).toContain("Before=network-pre.target");
  expect(u).toContain("sshd.service");
  expect(u).toContain("DefaultDependencies=no");
});

test("each app's Valkey: own port and password, localhost only, no debug or module commands", () => {
  const conf = renderValkeyConf({ port: 701, password: "pw", app: "shop", maxMb: 128 });
  expect(conf).toContain("bind 127.0.0.1 -::1");
  expect(conf).toContain("requirepass pw");
  expect(conf).toContain("enable-module-command no");
  const unit = renderValkeyUnit("shop", "/usr/bin/valkey-server", 128);
  expect(unit).toContain("DynamicUser=yes");
  expect(unit).toMatch(/User=pano-vk-[0-9a-f]{12}\n/);
  expect(unit).toContain("IPAddressAllow=localhost");
  expect(unit).toContain("MemoryMax=256M");
  expect(unit).toContain("CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n");
});

test("wildcard grants are told apart from escaped ones and read back from SHOW GRANTS", () => {
  expect(wildcardGrant("my_app")).toBe(true);
  expect(wildcardGrant("my\\_app")).toBe(false);
  expect(wildcardGrant("user\\_%")).toBe(true);
  expect(wildcardGrant("shop")).toBe(false);
  expect(
    parseDbGrants([
      "GRANT USAGE ON *.* TO `u`@`localhost` IDENTIFIED BY PASSWORD '*AB'",
      "GRANT ALL PRIVILEGES ON `my_app`.* TO `u`@`localhost`",
      "GRANT SELECT, INSERT ON `a``b`.* TO `u`@`localhost` WITH GRANT OPTION",
    ]),
  ).toEqual([
    { db: "my_app", privs: "ALL PRIVILEGES", withGrant: false },
    { db: "a`b", privs: "SELECT, INSERT", withGrant: true },
  ]);
});

test("Cloudflare ranges: matching, parsing and the lock", () => {
  expect(parseCidr("104.16.0.0/13")?.prefix).toBe(13);
  expect(parseCidr("2606:4700::/32")?.bits).toBe(128);
  expect(parseCidr("1.2.3.4/33")).toBeNull();
  expect(parseCidr("nope")).toBeNull();
  const ranges = ["104.16.0.0/13", "2606:4700::/32"];
  expect(inRanges("104.21.5.9", ranges)).toBe(true);
  expect(inRanges("104.24.0.1", ranges)).toBe(false);
  expect(inRanges("2606:4700:3031::ac43:a1b2", ranges)).toBe(true);
  expect(inRanges("2a01:4f8::1", ranges)).toBe(false);
  expect(parseRangeList("173.245.48.0/20\n103.21.244.0/22\n", false)).toEqual(["173.245.48.0/20", "103.21.244.0/22"]);
  expect(parseRangeList("<html>", false)).toBeNull();
  expect(parseRangeList("2400:cb00::/32\n", false)).toBeNull();
  const lock = renderLock(ranges);
  expect(lock).toContain("elements = { 104.16.0.0/13 }");
  expect(lock).toContain("elements = { 2606:4700::/32 }");
  expect(lock).toContain('iifname { "lo", "pano0", "tailscale0" } accept');
  expect(lock.indexOf("@cf4 accept")).toBeLessThan(lock.indexOf("th dport { 80, 443 } drop"));
});

test("a release is only taken when SHA256SUMS is signed by the release key", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const sums = new TextEncoder().encode("abc  pano-linux-x64\n");
  const sig = sign(null, sums, privateKey);
  expect(signedBy(sums, sig, pem)).toBe(true);
  expect(signedBy(new TextEncoder().encode("abd  pano-linux-x64\n"), sig, pem)).toBe(false);
  expect(signedBy(sums, sig)).toBe(false); // not the built-in key
  expect(signedBy(sums, new Uint8Array(3), pem)).toBe(false);
});

test("the shared Valkey's password goes only to a listener inside its own unit", async () => {
  const { listenerPids, onlyUnitListens } = await import("../src/agent/services.ts");
  const ss = 'LISTEN 0 511 127.0.0.1:6379 0.0.0.0:* users:(("valkey-server",pid=812,fd=6))\n';
  expect(listenerPids(ss)).toEqual(["812"]);
  const own = { "812": "0::/system.slice/valkey.service\n" };
  expect(onlyUnitListens(["812"], own, "valkey.service")).toBe(true);
  expect(onlyUnitListens(["812"], { "812": "0::/system.slice/pano-app-shop.service\n" }, "valkey.service")).toBe(false);
  expect(onlyUnitListens(["812", "900"], { ...own, "900": "0::/user.slice/user-1001.slice/session-3.scope\n" }, "valkey.service")).toBe(false);
  expect(onlyUnitListens([], {}, "valkey.service")).toBe(false); // nothing listens: Valkey is down
});
