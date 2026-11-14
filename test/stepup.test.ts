import { expect, test } from "bun:test";
import { grantValid, issueGrant } from "../src/agent/otp.ts";
import { alwaysAsk, changesRuntimeEnv, needsOtp } from "../src/agent/rpc.ts";
import { registeredDomain, wildcardAllowed } from "../src/agent/main.ts";

test("a grant is good only for the method and params its code was checked for", () => {
  const params = { name: "shop", vars: { A: "1" } };
  const g = issueGrant("alice", "apps.env.set", params);
  expect(grantValid(g, "alice", "apps.env.set", { name: "other", vars: { A: "1" } })).toBe(false);
  expect(grantValid(g, "alice", "apps.env.reveal", params)).toBe(false);
  expect(grantValid(g, "alice", "admins.add", { username: "mallory" })).toBe(false);
  expect(grantValid(g, "mallory", "apps.env.set", params)).toBe(false);
  expect(grantValid(g, "alice", "apps.env.set", { name: "shop", vars: { A: "1" } })).toBe(true);
});

test("always-ask actions: no trusted window, no grant", async () => {
  for (const m of ["admins.add", "backup.key.export", "recovery.kit", "apps.env.reveal", "vpn.peer.add", "runner.key.add", "apps.create", "firewall.disable"])
    expect(await alwaysAsk(m, {})).toBe(true);
  for (const m of ["sites.save", "apps.addDatabase", "sites.fixPermissions", "shield.quarantine"]) expect(await alwaysAsk(m, {})).toBe(false);
  // an app that does not exist: nothing changes (the handler rejects it)
  expect(await alwaysAsk("apps.update", { name: "nope" })).toBe(false);
  for (const m of ["sites.fixPermissions", "shield.quarantine"]) expect(needsOtp(m, {})).toBe(true);
});

test("variables that change what runs always ask; ordinary ones do not", () => {
  const cur = { DATABASE_URL: "x", NODE_OPTIONS: "--max-old-space-size=512" };
  expect(changesRuntimeEnv({ ...cur, STRIPE_KEY: "sk" }, cur)).toBe(false);
  expect(changesRuntimeEnv(cur, cur)).toBe(false); // unchanged runtime variable
  expect(changesRuntimeEnv({ ...cur, NODE_OPTIONS: "--import=data:text/javascript,1" }, cur)).toBe(true);
  for (const k of ["LD_PRELOAD", "PATH", "HTTPS_PROXY", "BUN_CONFIG_REGISTRY", "npm_config_registry", "PYTHONPATH"]) expect(changesRuntimeEnv({ ...cur, [k]: "/tmp/x" }, cur)).toBe(true);
});

test("registered domain errs wide", () => {
  expect(registeredDomain("*.preview.example.com")).toBe("example.com");
  expect(registeredDomain("*.shop.example.co.uk")).toBe("example.co.uk");
  expect(registeredDomain("example.com.tr")).toBe("example.com.tr");
  expect(registeredDomain("user.github.io")).toBe("github.io");
});

test("wildcard certificates: 5 new names an hour per wildcard, 20 a week per registered domain, seen names pass", () => {
  const t0 = Date.parse("2026-01-05T00:00:00Z");
  const h = 3600_000;
  const ok = (w: string, d: string, t: number) => wildcardAllowed(w, d, t);
  for (let i = 0; i < 5; i++) expect(ok("*.a.cap.example", `n${i}.a.cap.example`, t0 + i)).toBe(true);
  expect(ok("*.a.cap.example", "n5.a.cap.example", t0 + 10)).toBe(false);
  expect(ok("*.a.cap.example", "n0.a.cap.example", t0 + 11)).toBe(true); // already has a certificate
  // another wildcard under the same registered domain has its own hourly cap but shares the weekly one
  for (let i = 0; i < 5; i++) expect(ok("*.b.cap.example", `m${i}.b.cap.example`, t0 + 20 + i)).toBe(true);
  for (let hour = 1; hour <= 2; hour++) for (let i = 0; i < 5; i++) expect(ok("*.a.cap.example", `h${hour}-${i}.a.cap.example`, t0 + hour * h + i)).toBe(true);
  expect(ok("*.c.cap.example", "x.c.cap.example", t0 + 5 * h)).toBe(false); // 20 this week
  expect(ok("*.other.example", "x.other.example", t0 + 5 * h)).toBe(true); // another domain is not affected
  expect(ok("*.c.cap.example", "x.c.cap.example", t0 + 8 * 24 * h)).toBe(true); // a week later
});
