import { describe, expect, test } from "bun:test";
import { validateAppInput } from "../src/agent/apps.ts";
import { renderCaddyfile } from "../src/agent/edge.ts";
import { apps, previewApp, previews, type App } from "../src/agent/state.ts";
import {
  branchFromRef, evictions, expiredIds, expiryFrom, hostMatchesPattern, isBranchDeletion, normalizeEnvExclude, previewEnv, previewHost, previewProcesses,
  previewDomainProblem, previewSlug, validatePreviewDomain,
} from "../src/shared/preview.ts";

describe("preview names", () => {
  test("a plain branch keeps its name, others get a hash so they never collide", () => {
    expect(previewSlug("login")).toBe("login");
    expect(previewSlug("fix-1")).toBe("fix-1");
    const a = previewSlug("feature/login");
    const b = previewSlug("feature-login");
    expect(a).toMatch(/^feature-login-[0-9a-f]{6}$/);
    expect(b).toBe("feature-login");
    expect(a).not.toBe(b);
    expect(previewSlug("Fix_Y")).toMatch(/^fix-y-[0-9a-f]{6}$/);
  });

  test("slugs are valid, short DNS labels", () => {
    for (const b of ["a".repeat(99), "x/" + "y".repeat(90), "..weird..", "_", "UPPER.case"]) {
      const s = previewSlug(b);
      expect(s).toMatch(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/);
      expect(s.length).toBeLessThanOrEqual(47);
    }
  });

  test("domain pattern and host", () => {
    expect(validatePreviewDomain("")).toBe("");
    expect(validatePreviewDomain(" *.Preview.Example.com ")).toBe("*.preview.example.com");
    expect(() => validatePreviewDomain("preview.example.com")).toThrow();
    expect(() => validatePreviewDomain("*.com")).toThrow();
    // A dedicated zone: never the app's own domain or a parent of it.
    expect(() => validatePreviewDomain("*.example.com", ["example.com"])).toThrow("own domain");
    expect(() => validatePreviewDomain("*.example.com", ["app.example.com"])).toThrow("own domain");
    expect(validatePreviewDomain("*.preview.example.com", ["app.example.com", "example.com"])).toBe("*.preview.example.com");
    expect(previewDomainProblem("*.pv.example.net", ["example.com"])).toBe("");
    expect(previewHost("*.preview.example.com", "login")).toBe("login.preview.example.com");
    expect(hostMatchesPattern("*.preview.example.com", "login.preview.example.com")).toBe(true);
    expect(hostMatchesPattern("*.preview.example.com", "a.b.preview.example.com")).toBe(false);
    expect(hostMatchesPattern("*.preview.example.com", "preview.example.com")).toBe(false);
    expect(hostMatchesPattern("*.preview.example.com", "x.other.example.com")).toBe(false);
  });
});

describe("preview limits and lifetime", () => {
  const list = [
    { id: 1, branch: "a", updated_at: 300 },
    { id: 2, branch: "b", updated_at: 100 },
    { id: 3, branch: "c", updated_at: 200 },
  ];
  test("a new branch at the limit removes the oldest", () => {
    expect(evictions(list, "d", 3)).toEqual([2]);
    expect(evictions(list, "d", 2)).toEqual([2, 3]);
  });
  test("a push to an existing preview adds nothing", () => {
    expect(evictions(list, "b", 3)).toEqual([]);
  });
  test("room left: nothing goes", () => {
    expect(evictions(list, "d", 4)).toEqual([]);
  });
  test("building previews and the branch itself are never evicted", () => {
    const l = [{ ...list[0]! }, { ...list[1]!, busy: true }, { ...list[2]! }];
    expect(evictions(l, "d", 3)).toEqual([3]);
    expect(evictions(l, "b", 2)).toEqual([3]); // lowered max: trims, keeps "b"
    expect(evictions([{ id: 9, branch: "x", updated_at: 1, busy: true }], "d", 1)).toEqual([]);
  });
  test("lowered max trims without adding", () => {
    expect(evictions(list, "", 2)).toEqual([2]);
    expect(evictions(list, "", 3)).toEqual([]);
  });
  test("ttl", () => {
    expect(expiryFrom(1000, 7)).toBe(1000 + 7 * 86400);
    const ps = [{ id: 1, expires_at: 500 }, { id: 2, expires_at: 1500 }, { id: 3, expires_at: 1000 }];
    expect(expiredIds(ps, 1000)).toEqual([1, 3]);
    expect(expiredIds(ps, 400)).toEqual([]);
  });
});

describe("preview env and processes", () => {
  test("prod-only variables are left out, exact or by prefix", () => {
    const env = { DATABASE_URL: "x", STRIPE_KEY: "k", STRIPE_WEBHOOK: "w", SECRET: "s", KEEP: "1" };
    const out = previewEnv(env, normalizeEnvExclude("DATABASE_URL, STRIPE_* SECRET"), {}, { PANO_PREVIEW: "1" });
    expect(out).toEqual({ KEEP: "1", PANO_PREVIEW: "1" });
    // No list of the admin's own: secret-looking names and shared-group variables stay out by default, "!NAME" lets one in.
    expect(previewEnv(env, "")).toEqual({ KEEP: "1", STRIPE_WEBHOOK: "w" });
    expect(previewEnv({ KEEP: "1", SHARED_FLAG: "on", API_TOKEN: "t", DB_HOST: "h" }, "", {}, {}, ["SHARED_FLAG"])).toEqual({ KEEP: "1", DB_HOST: "h" });
    expect(previewEnv(env, "!DATABASE_URL,!STRIPE_*")).toEqual({ DATABASE_URL: "x", STRIPE_KEY: "k", STRIPE_WEBHOOK: "w", KEEP: "1" });
    expect(previewEnv(env, "!*")).toEqual(env);
    expect(previewEnv({ KEEP: "1", MY_KEY: "k" }, "OTHER")).toEqual({ KEEP: "1", MY_KEY: "k" }); // an admin's own list is applied as it stands
    // Preview values win and are never excluded; pano's own come last.
    const scoped = previewEnv(env, "STRIPE_*", { STRIPE_KEY: "test", KEEP: "2", PANO_PREVIEW: "x" }, { PANO_PREVIEW: "1" });
    expect(scoped).toEqual({ DATABASE_URL: "x", SECRET: "s", KEEP: "2", STRIPE_KEY: "test", PANO_PREVIEW: "1" });
    expect(normalizeEnvExclude("A, B,A")).toBe("A,B");
    expect(() => normalizeEnvExclude("bad key")).not.toThrow(); // split on spaces
    expect(() => normalizeEnvExclude("1BAD")).toThrow();
    expect(() => normalizeEnvExclude("A;rm")).toThrow();
    expect(normalizeEnvExclude("!DATABASE_URL !*")).toBe("!DATABASE_URL,!*");
    expect(() => normalizeEnvExclude("!")).toThrow();
  });

  test("web processes move to the preview host, workers do not run", () => {
    const procs = [
      { name: "web", dir: "apps/web", routes: ["example.com", "www.example.com"], memory_mb: 512, start: "" },
      { name: "api", dir: "apps/api", routes: ["example.com/api"], memory_mb: 256, start: "" },
      { name: "admin", dir: "apps/admin", routes: ["admin.example.com"], memory_mb: 256, start: "" },
      { name: "worker", dir: ".", routes: [], memory_mb: 128, start: "bun w.ts" },
    ];
    const out = previewProcesses(procs, "x.pv.example.com");
    expect(out.map((p) => [p.name, p.routes])).toEqual([["web", ["x.pv.example.com"]], ["api", ["x.pv.example.com/api"]]]);
  });
});

describe("preview webhooks", () => {
  test("refs and deletion events", () => {
    expect(branchFromRef("refs/heads/feature/x")).toBe("feature/x");
    expect(branchFromRef("refs/tags/v1")).toBe("");
    expect(isBranchDeletion({ deleted: true })).toBe(true);
    expect(isBranchDeletion({ after: "0000000000000000000000000000000000000000" })).toBe(true);
    expect(isBranchDeletion({ after: "abc1234", deleted: false })).toBe(false);
    expect(isBranchDeletion(null)).toBe(false);
  });
});

describe("preview state and edge", () => {
  const base = {
    name: "web", kind: "managed", domains: ["example.com"], runtime: "node", runtime_version: "22.0.0", repo: "https://github.com/a/b.git", branch: "main", root_dir: "",
    install_cmd: "", build_cmd: "", start_cmd: "node server.js", health_path: "/", port_a: 4100, port_b: 4101, active_slot: "a", memory_mb: 512, current_release: "r1",
    webhook_secret: "s", upstream: "", external_unit: "", processes: [], ask_url: "", auto_deploy: 1, build_isolated: 0, crons: [], preview_domain: "*.pv.example.com", preview_max: 3,
    preview_ttl_days: 7, preview_env_exclude: "", env_groups: "", env_running: "", env_built: "", created_at: 0, updated_at: 0,
    http_redirect: 1, suspended: 0, suspended_reason: "", suspended_at: 0, suspended_units: [],
  } as App;

  test("settings validate; defaults apply", () => {
    const input = validateAppInput({ name: "web", domains: "example.com", runtime: "node", runtime_version: "22.0.0", repo: "https://github.com/a/b.git" });
    expect([input.preview_domain, input.preview_max, input.preview_ttl_days, input.preview_env_exclude]).toEqual(["", 3, 7, ""]);
    const on = validateAppInput({ name: "web", domains: "example.com", runtime: "node", runtime_version: "22.0.0", repo: "https://github.com/a/b.git", preview_domain: "*.pv.example.com", preview_max: "5", preview_ttl_days: "2", preview_env_exclude: "A, B*" });
    expect([on.preview_domain, on.preview_max, on.preview_ttl_days, on.preview_env_exclude]).toEqual(["*.pv.example.com", 5, 2, "A,B*"]);
    expect(() => validateAppInput({ name: "web", domains: "example.com", runtime: "node", runtime_version: "22.0.0", repo: "https://github.com/a/b.git", preview_max: 99 })).toThrow();
  });

  test("previews keep their own ports and become a synthetic app", () => {
    apps.insert({ ...base, domains: ["example.com"], processes: [], crons: [] } as any);
    const procs = [{ name: "", dir: "", routes: ["feat.pv.example.com"], memory_mb: 512, start: "node server.js", port_a: 0, port_b: 0 }];
    const [a, b] = apps.nextPorts();
    const id = previews.insert({ app: "web", branch: "feat", slug: "feat", host: "feat.pv.example.com", processes: [{ ...procs[0]!, port_a: a, port_b: b }], expires_at: 10 });
    expect(apps.nextPorts()).not.toContain(a);
    expect(apps.nextPorts()[0]).not.toBe(a);
    expect(previews.find("web", "feat")?.id).toBe(id);
    const pv = previews.get(id)!;
    const synthetic = previewApp(base, pv);
    expect(synthetic.name).toBe(`pv_${id}`);
    expect(synthetic.branch).toBe("feat");
    expect(synthetic.repo).toBe(base.repo);
    expect(synthetic.crons).toEqual([]);
    previews.update(id, { active_slot: "b", current_release: "r9" });
    expect(previews.get(id)!.active_slot).toBe("b");
    previews.remove(id);
    expect(previews.get(id)).toBeNull();
  });

  test("the Caddyfile serves live previews on demand, and only those", () => {
    const pvApp = (slot: "a" | "b" | "") =>
      ({ ...base, name: "pv_1", domains: ["feat.pv.example.com"], active_slot: slot, processes: [{ name: "", dir: "", routes: ["feat.pv.example.com"], memory_mb: 512, start: "", port_a: 4200, port_b: 4201 }] }) as App;
    const settings = { email: "", behindCloudflare: false, hooksDomain: "" };
    const out = renderCaddyfile({ apps: [base], sites: [], settings, certs: new Set(), previews: [{ parent: "web", app: pvApp("b") }] });
    expect(out).toContain("feat.pv.example.com {");
    expect(out).toContain("reverse_proxy 127.0.0.1:4201");
    expect(out).toContain("on_demand");
    expect(out).toContain("preview-web.log");
    const none = renderCaddyfile({ apps: [base], sites: [], settings, certs: new Set(), previews: [{ parent: "web", app: pvApp("") }] });
    expect(none).not.toContain("feat.pv.example.com");
    expect(renderCaddyfile({ apps: [base], sites: [], settings, certs: new Set() })).not.toContain("on_demand\n");
  });
});
