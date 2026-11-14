import { expect, test } from "bun:test";
import { parseShow } from "../src/agent/sys.ts";

test("one systemctl show for many units: blocks map back to the units asked", () => {
  const out = "ActiveState=active\nMemoryCurrent=1234\nActiveEnterTimestamp=Wed 2026-10-28 10:00:00 UTC\n\nActiveState=inactive\nMemoryCurrent=[not set]\nActiveEnterTimestamp=\n";
  const m = parseShow(out, ["a@a.service", "b@b.service", "c.service"]);
  expect(m.get("a@a.service")).toEqual({ ActiveState: "active", MemoryCurrent: "1234", ActiveEnterTimestamp: "Wed 2026-10-28 10:00:00 UTC" });
  expect(m.get("b@b.service")?.ActiveState).toBe("inactive");
  expect(m.get("b@b.service")?.ActiveEnterTimestamp).toBe("");
  expect(m.get("c.service")).toEqual({}); // missing block: nothing known
});

test("certificate files: read only as a regular file (never a directory or nothing); ensureDir refuses a symlink", async () => {
  const { mkdirSync, symlinkSync, writeFileSync } = await import("node:fs");
  const { ensureDir, readRootOwned } = await import("../src/agent/sys.ts");
  const root = process.env.PANO_ROOT!;
  mkdirSync(`${root}/etc/ssl-test`, { recursive: true });
  writeFileSync(`${root}/etc/ssl-test/cert.pem`, "-----BEGIN CERTIFICATE-----\n");
  expect(await readRootOwned("/etc/ssl-test/cert.pem")).toContain("BEGIN CERTIFICATE");
  expect(await readRootOwned("/etc/ssl-test")).toBeNull();
  expect(await readRootOwned("/etc/ssl-test/missing.pem")).toBeNull();
  mkdirSync(`${root}/srv/link-test/real`, { recursive: true });
  symlinkSync(`${root}/srv/link-test/real`, `${root}/srv/link-test/link`);
  await expect(ensureDir("/srv/link-test/link", 0o750)).rejects.toThrow("refusing");
});
