import { expect, test } from "bun:test";
import { groupProjects } from "../src/web/projects.ts";
import { endTrust, issueTrust, trustValid } from "../src/agent/otp.ts";
import { FRESH_ONLY } from "../src/agent/rpc.ts";

const app = (name: string, upstream: string, unit = "", domains: string[] = []) => ({ name, kind: "external", external_unit: unit, upstream, domains });
const site = (name: string, domains: string[], ups: string[], enabled = 1) => ({ name, kind: "legacy", domains, routes: ups.map((u) => ({ path: "/", upstream: u })), enabled });

const apps = [
  app("pos", "127.0.0.1:3000", "pm2:shop/pos"),
  app("online", "127.0.0.1:3001", "pm2:shop/online"),
  app("worker", "", "pm2:shop/worker"),
  app("quiz", "127.0.0.1:3100", "quiz.service"),
  app("quiz-hook", "127.0.0.1:3101", "quiz-hook.service"),
];
const sites = [
  site("shop.example", ["shop.example", "*.shop.example", "*"], ["127.0.0.1:3000"]),
  site("quiz.example.co.uk", ["quiz.example.co.uk"], ["127.0.0.1:3101", "127.0.0.1:3100"]),
  site("quiz.example", ["quiz.example"], ["127.0.0.1:3100"]),
  site("cafe.example.org", ["cafe.example.org"], []),
];

test("apps join the sites that send them traffic, PM2 apps of one user stay together", () => {
  const ps = groupProjects(apps, sites);
  const by = Object.fromEntries(ps.map((p) => [p.name, { apps: p.apps.map((a) => a.name).sort(), sites: p.sites.map((s) => s.name).sort() }]));
  expect(by.shop).toEqual({ apps: ["online", "pos", "worker"], sites: ["shop.example"] });
  expect(by.quiz).toEqual({ apps: ["quiz", "quiz-hook"], sites: ["quiz.example", "quiz.example.co.uk"] });
  expect(by["cafe.example.org"]).toEqual({ apps: [], sites: ["cafe.example.org"] });
  expect(ps).toHaveLength(3);
});

test("manual moves win: next to another project, or on its own", () => {
  const ps = groupProjects(apps, sites, { "app:worker": "", "site:cafe.example.org": "site:quiz.example.co.uk" });
  const names = ps.map((p) => [p.name, p.apps.length + p.sites.length]);
  expect(names).toContainEqual(["worker", 1]);
  expect(ps.find((p) => p.sites.some((s) => s.name === "cafe.example.org"))!.sites).toHaveLength(3);
});

test("trusted window: per admin, ends on request, never covers the always-ask actions", () => {
  const tk = issueTrust("admin");
  expect(trustValid(tk, "admin")).toBe(true);
  expect(trustValid(tk, "other")).toBe(false);
  endTrust(tk);
  expect(trustValid(tk, "admin")).toBe(false);
  for (const m of ["apps.delete", "db.drop", "backup.restore", "edge.cutover", "admins.add"]) expect(FRESH_ONLY.has(m)).toBe(true);
  expect(FRESH_ONLY.has("apps.env.set")).toBe(false);
});
