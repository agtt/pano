import { describe, expect, test } from "bun:test";
import { renderUnit } from "../src/agent/apps.ts";
import { attachUserName } from "../src/agent/services.ts";
import type { App } from "../src/agent/state.ts";
import { envPending, envSnapshot, groupName, isBuildVar, mergeEnv, normalizeGroups } from "../src/shared/env.ts";
import { previewComment } from "../src/shared/preview.ts";
import { AppDetail } from "../src/web/views/apps.tsx";
import { EnvGroupsPage } from "../src/web/views/envgroups.tsx";

describe("shared variable groups", () => {
  test("names are checked and the order is kept", () => {
    expect(normalizeGroups("stripe, sentry stripe")).toBe("stripe,sentry");
    expect(normalizeGroups(["mail"])).toBe("mail");
    expect(normalizeGroups("")).toBe("");
    expect(() => groupName("../etc")).toThrow();
    expect(() => groupName("Stripe")).toThrow();
    expect(() => normalizeGroups("a;rm")).toThrow();
  });

  test("a later group wins over an earlier one, the app's own variables win over all", () => {
    expect(mergeEnv([{ A: "1", B: "1" }, { B: "2", C: "2" }], { C: "own" })).toEqual({ A: "1", B: "2", C: "own" });
  });

  test("units read the groups before the app's own .env", () => {
    const app = { name: "shop", root_dir: "", env_groups: "stripe,mail" } as App;
    const u = renderUnit(app, { name: "", dir: "", routes: ["a.test"], memory_mb: 512, start: "", port_a: 4100, port_b: 4101 }, "/usr/bin");
    const lines = u.split("\n").filter((l) => l.startsWith("EnvironmentFile="));
    expect(lines[0]).toEndWith("/env-groups/stripe.env");
    expect(lines[1]).toEndWith("/env-groups/mail.env");
    expect(lines[2]).toEndWith("/shop/shared/.env");
    expect(renderUnit({ ...app, env_groups: "" }, { name: "", dir: "", routes: [], memory_mb: 512, start: "", port_a: 0, port_b: 0 }, "/usr/bin")).not.toContain("env-groups");
  });
});

describe("restart or redeploy", () => {
  test("names of changed variables only, build-time ones need a redeploy", () => {
    const then = envSnapshot({ API_URL: "a", NEXT_PUBLIC_KEY: "k", GONE: "x" });
    const now = { API_URL: "b", NEXT_PUBLIC_KEY: "k2", NEW: "n" };
    expect(envPending(now, then, then)).toEqual({ restart: ["API_URL", "GONE", "NEW", "NEXT_PUBLIC_KEY"], redeploy: ["NEXT_PUBLIC_KEY"] });
    expect(envPending({ API_URL: "a", NEXT_PUBLIC_KEY: "k", GONE: "x" }, then, then)).toEqual({ restart: [], redeploy: [] });
    // Nothing recorded yet (an app deployed before this existed): no false alarm.
    expect(envPending(now, "", "")).toEqual({ restart: [], redeploy: [] });
  });

  test("fingerprints hold no values", () => {
    const s = envSnapshot({ SECRET: "hunter2" });
    expect(s).not.toContain("hunter2");
    expect(isBuildVar("VITE_X") && isBuildVar("NEXT_PUBLIC_X") && !isBuildVar("DATABASE_URL")).toBe(true);
  });
});

test("an attached database gets a user of the app's own, unique per database", () => {
  const u = attachUserName("my-long-application-name", "cp_wordpress");
  expect(u).toMatch(/^[a-z][a-z0-9_]{1,31}$/);
  expect(u).not.toBe(attachUserName("my-long-application-name", "cp_other"));
});

test("the pull request comment links the preview or says the build failed", () => {
  expect(previewComment("feat/x", "feat-x-1a2b3c.pv.example.com", "0123456789abcdef", true, 7)).toContain("https://feat-x-1a2b3c.pv.example.com");
  const failed = previewComment("a`b", "h", "", false, 7);
  expect(failed).toContain("deploy 7");
  expect(failed).toContain("`ab`");
});

test("env views: pending banner, preview scope, attach, groups", () => {
  const app: any = {
    name: "shop", kind: "managed", domains: ["a.test"], runtime: "node", runtime_version: "24", repo: "x", branch: "main", root_dir: "", install_cmd: "", build_cmd: "",
    start_cmd: "", health_path: "/", memory_mb: 512, port_a: 1, port_b: 2, active_slot: "a", current_release: "r", upstream: "", external_unit: "", ask_url: "",
    processes: [], crons: [], auto_deploy: 1, preview_domain: "*.pv.test", env_groups: "stripe",
    env_pending: { restart: ["API_URL", "NEXT_PUBLIC_KEY"], redeploy: ["NEXT_PUBLIC_KEY"] },
    status: { active: "active", memory: 1, since: "" }, deploys: [], previews: [],
  };
  const props = { csrf: "c", app, env: { A: "••••••••" }, logs: "", runtimes: [], hookUrl: "h", github: { connected: false, repo: "" } };
  const html = String(<AppDetail {...props} previewEnv={{ STRIPE_KEY: "sk_test" }} revealed="preview" databases={[{ engine: "mariadb", name: "cp_wp" }]} />);
  expect(html).toContain("only a redeploy applies them");
  expect(html).toContain("Preview environment");
  expect(html).toContain("STRIPE_KEY=sk_test");
  expect(html).toContain('value="mariadb:cp_wp"');
  expect(html).toContain("shared variables of stripe");
  const restartOnly = String(<AppDetail {...props} app={{ ...app, env_pending: { restart: ["API_URL"], redeploy: [] } }} />);
  expect(restartOnly).toContain("a restart applies them");
  expect(String(<AppDetail {...props} app={{ ...app, env_pending: { restart: [], redeploy: [] } }} />)).not.toContain("flash warn");

  const groups = String(<EnvGroupsPage csrf="c" groups={[{ name: "stripe", keys: ["STRIPE_KEY"], apps: ["shop"] }, { name: "old", keys: [], apps: [] }]} />);
  expect(groups).toContain("STRIPE_KEY");
  expect(groups).toContain("/env-groups/old/delete");
  expect(groups).not.toContain("/env-groups/stripe/delete");
});
