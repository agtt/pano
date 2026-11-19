import { afterEach, describe, expect, test } from "bun:test";
import { env } from "../src/shared/config.ts";
import { forbiddenStaticRoot, restartThenApply } from "../src/agent/edge.ts";
import { grantValid, issueGrant } from "../src/agent/otp.ts";
import { FRESH_ONLY, alwaysAsk, changesRuntimeEnv, methods, needsOtp } from "../src/agent/rpc.ts";
import { sites, type Site } from "../src/agent/state.ts";
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

describe("sites.save and db.grant (N1)", () => {
  const base = (over: Partial<Site>): Site =>
    ({
      name: "n1.example", kind: "proxy", domains: ["n1.example"], root: "", routes: [{ path: "/", upstream: "127.0.0.1:3000" }], ask_url: "", php_version: "", tls_cert: "",
      tls_key: "", source: "pano", enabled: 1, on_demand_tls: 0, deny_paths: [], converted_from: null, crons: [], created_at: 0, http_redirect: 1, www_apex: 0, ...over,
    }) as Site;
  const save = { name: "n1.example", kind: "proxy", domains: "n1.example", routes: "/ 127.0.0.1:3000" };
  afterEach(() => {
    for (const n of ["n1.example", "n1-static", "n1-other"]) sites.remove(n);
  });

  test("granting a database user always asks", async () => {
    expect(FRESH_ONLY.has("db.grant")).toBe(true);
    expect(await alwaysAsk("db.grant", { db: "victim", user: "evil" })).toBe(true);
  });

  test("structural site changes always ask; redirect/www/TLS options and removing a domain stay routine", async () => {
    // a new site
    expect(await alwaysAsk("sites.save", save)).toBe(true);
    sites.upsert(base({ domains: ["n1.example", "www.n1.example"] }));
    const same = { ...save, domains: "n1.example, www.n1.example" };
    expect(await alwaysAsk("sites.save", same)).toBe(false);
    expect(await alwaysAsk("sites.save", { ...same, http_redirect: "0", www_apex: "1", on_demand_tls: true })).toBe(false);
    expect(await alwaysAsk("sites.save", { ...save, domains: "n1.example" })).toBe(false);
    expect(needsOtp("sites.save", same)).toBe(true);
    // what the site is, or where its visitors go
    for (const change of [
      { kind: "static", root: "/var/www/n1" },
      { domains: "n1.example, www.n1.example, victim.example" },
      { domains: "n1.example, victim.example", move: true },
      { routes: "/ 127.0.0.1:3001" },
      { routes: "/ 127.0.0.1:3000\n/api 127.0.0.1:3002" },
      { routes: "/ redirect https://elsewhere.example{uri}" },
      { cert_from: "n1-other" },
    ])
      expect(await alwaysAsk("sites.save", { ...same, ...change })).toBe(true);
    // unreadable input fails closed
    expect(await alwaysAsk("sites.save", { ...same, routes: "nonsense" })).toBe(true);
  });

  test("a static site's root: changing it asks, pano's own directories are refused", async () => {
    sites.upsert(base({ name: "n1-static", kind: "static", domains: ["n1-static.example"], root: "/var/www/n1", routes: [] }));
    const st = { name: "n1-static", kind: "static", domains: "n1-static.example", root: "/var/www/n1/" };
    expect(await alwaysAsk("sites.save", st)).toBe(false);
    expect(await alwaysAsk("sites.save", { ...st, root: "/var/www/n2" })).toBe(true);
    for (const root of ["/srv/pano/sites/victim/public", "/srv/pano/apps/web", "/srv/pano/edgeview/victim/public", "/srv/pano/static/web", "/srv/pano/containers/x", "/srv/pano", "/srv"]) {
      expect(forbiddenStaticRoot(root)).toBe(true);
      await expect(methods["sites.save"]!({ ...st, root }, "tester")).rejects.toThrow();
    }
    // Only under /var/www (N3); through a symlink into pano's tree neither.
    await expect(methods["sites.save"]!({ ...st, root: "/srv/www/n1" }, "tester")).rejects.toThrow("under /var/www");
    const { mkdirSync, symlinkSync } = await import("node:fs");
    const { fsPath } = await import("../src/shared/config.ts");
    mkdirSync(fsPath("/srv/pano/sites/victim"), { recursive: true });
    mkdirSync(fsPath("/var/www"), { recursive: true });
    symlinkSync(fsPath("/srv/pano/sites/victim"), fsPath("/var/www/sneaky"));
    await expect(methods["sites.save"]!({ ...st, root: "/var/www/sneaky" }, "tester")).rejects.toThrow("pano's own directories");
    for (const root of ["/var/www/n1", "/srv/www/n1", "/srv/panorama"]) expect(forbiddenStaticRoot(root)).toBe(false);
  });

  test("a proxy route never points at pano's own ports", async () => {
    for (const port of [env.webPort, env.askPort, env.hookPort])
      await expect(methods["sites.save"]!({ ...save, routes: `/ 127.0.0.1:${port}` }, "tester")).rejects.toThrow("pano's own port");
  });
});

test("a new PHP site or a WordPress install always asks (R1)", async () => {
  for (const m of ["sites.createPhp", "wp.install"]) {
    expect(FRESH_ONLY.has(m)).toBe(true);
    expect(await alwaysAsk(m, { name: "r1.example" })).toBe(true);
  }
});

test("on a view switch the edge restarts before the config moves onto the view (R2)", async () => {
  const order: string[] = [];
  const restart = async () => void order.push("restart");
  const apply = async () => void order.push("apply");
  await restartThenApply(true, restart, apply);
  expect(order).toEqual(["restart", "apply"]);
  order.length = 0;
  await restartThenApply(false, restart, apply);
  expect(order).toEqual(["apply"]);
});
