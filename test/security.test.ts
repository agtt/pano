import { expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fsPath } from "../src/shared/config.ts";
import { renderLocalPorts } from "../src/agent/localports.ts";
import { grantDb, ident, restoreCommand } from "../src/agent/mysql.ts";
import { placeSnapshots } from "../src/agent/sqlite.ts";
import { wpSandboxed } from "../src/agent/wordpress.ts";

test("database grants name one database, not a pattern", () => {
  expect(grantDb("my_app")).toBe("`my\\_app`");
  expect(grantDb("_____")).toBe("`\\_\\_\\_\\_\\_`");
  expect(grantDb("user\\_shop")).toBe("`user\\_shop`"); // cPanel's escaped form stays one database
  expect(grantDb("a%")).toBe("`a\\%`");
  expect(ident("a`b")).toBe("`a``b`");
  expect(restoreCommand("shop")).toContain("--binary-mode");
});

test("panel ports only for root, pano's users and people; TURN only to its relay ports", () => {
  const r = renderLocalPorts([0, 990, 991], [7800, 7801, 7802], { uid: 980, min: 49160, max: 49200 });
  expect(r).toContain("meta skuid { 0, 990, 991, 1000-61183 } accept");
  expect(r).toContain("fib daddr type local tcp dport { 7800, 7801, 7802 } reject with tcp reset");
  expect(r).toContain("meta skuid 980 fib daddr type local udp dport != 49160-49200 reject");
  expect(r.indexOf("skuid 980")).toBeLessThan(r.indexOf("} accept"));
});

test("wp-cli runs in the site's sandbox", () => {
  const argv = wpSandboxed("blog", "site-blog", "/srv/pano/sites/blog", { HOME: "/srv/pano/sites/blog/tmp" }, ["php", "wp.phar", "core", "version"]);
  expect(argv.slice(0, 2)).toEqual(["systemd-run", "--quiet"]);
  expect(argv).toContain("--uid=site-blog");
  expect(argv).toContain("NoNewPrivileges=true");
  expect(argv).toContain("IPAddressDeny=169.254.169.254/32");
  expect(argv.slice(-4)).toEqual(["php", "wp.phar", "core", "version"]);
});

test("restored SQLite copies never land through a planted symlink", async () => {
  const data = "/srv/pano/apps/x/data";
  const real = fsPath(data);
  const outside = fsPath("/root/.ssh");
  mkdirSync(join(real, ".pano-sqlite/a"), { recursive: true });
  mkdirSync(join(real, ".pano-sqlite/db"), { recursive: true });
  mkdirSync(outside, { recursive: true });
  const sqlite = Buffer.concat([Buffer.from("SQLite format 3\0"), Buffer.from("payload")]);
  writeFileSync(join(real, ".pano-sqlite/a/authorized_keys"), sqlite);
  writeFileSync(join(real, ".pano-sqlite/db/app.db"), sqlite);
  symlinkSync(outside, join(real, "a"));
  await placeSnapshots(data);
  expect(existsSync(join(outside, "authorized_keys"))).toBe(false);
  expect(readFileSync(join(real, "db/app.db")).equals(sqlite)).toBe(true);
  expect(existsSync(join(real, ".pano-sqlite"))).toBe(false);
});
