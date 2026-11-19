import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { appAction, startDeploy } from "../src/agent/apps.ts";
import { SUSPENDED_PAGE, renderCaddyfile } from "../src/agent/edge.ts";
import { FRESH_ONLY, methods, needsOtp } from "../src/agent/rpc.ts";
import { apps, deploys, migrate, sites, state, type App, type Site } from "../src/agent/state.ts";
import { runJob } from "../src/agent/jobs.ts";
import { resumeApp, resumeSite, setProjectSuspended, suspendApp, suspendReason, suspendSite } from "../src/agent/suspend.ts";
import * as wordpress from "../src/agent/wordpress.ts";
import { withLang } from "../src/web/i18n.ts";
import { AppForm, AppHead } from "../src/web/views/apps.tsx";
import { SiteForm, SiteHead } from "../src/web/views/pages.tsx";
import { ProjectDetail, ProjectsPage } from "../src/web/views/projects.tsx";

const settings = { email: "", behindCloudflare: false, hooksDomain: "" };
const site = (over: Partial<Site>): Site =>
  ({
    name: "shop", kind: "proxy", domains: ["shop.example"], root: "", routes: [{ path: "/", upstream: "127.0.0.1:3000" }], ask_url: "", php_version: "", tls_cert: "",
    tls_key: "", source: "pano", enabled: 1, on_demand_tls: 0, deny_paths: [], converted_from: null, crons: [], created_at: 0, ...over,
  }) as Site;
const app = (over: Partial<App>): App =>
  ({ name: "web", kind: "managed", domains: ["example.com", "www.example.com"], active_slot: "b", port_a: 4100, port_b: 4101, processes: [], ...over }) as App;
/** The block that starts with `head` (up to its closing brace at column 0). */
const block = (out: string, head: string) => {
  const i = out.indexOf(`${head} {\n`);
  return i < 0 ? "" : out.slice(i, out.indexOf("\n}\n", i) + 2);
};

test("edge: a file certificate never sits on a catch-all (it would answer for every other site)", () => {
  const out = renderCaddyfile({
    apps: [],
    sites: [site({ domains: ["shop.example", "*.shop.example", "*"], tls_cert: "/x/c.pem", tls_key: "/x/k.pem" })],
    settings,
    certs: new Set(["site-shop"]),
  });
  const named = block(out, "shop.example, *.shop.example");
  expect(named).toContain("\ttls /etc/pano/certs/site-shop/cert.pem");
  const any = block(out, "https://");
  expect(any).toContain("on_demand");
  expect(any).not.toContain("cert.pem");
});

describe("edge: suspended sites and apps", () => {
  test("a suspended site keeps its domain and certificate but answers with the fixed page", () => {
    const out = renderCaddyfile({ apps: [], sites: [site({ enabled: 0, tls_cert: "/x/c.pem", tls_key: "/x/k.pem" })], settings, certs: new Set(["site-shop"]) });
    const b = block(out, "shop.example");
    expect(b).toContain("\timport pano_common");
    expect(b).toContain("\ttls /etc/pano/certs/site-shop/cert.pem /etc/pano/certs/site-shop/key.pem");
    expect(b).toContain("\timport pano_suspended");
    expect(b).not.toContain("reverse_proxy");
    expect(b).toContain("site-shop.log");
    // The page: 503, Retry-After, HTML, nothing Caddy would read as a placeholder or the end of the token.
    const snip = block(out, "(pano_suspended)");
    expect(snip).toContain("respond `<!doctype html>");
    expect(snip).toMatch(/` 503\n/);
    expect(snip).toContain("header Retry-After 3600");
    expect(snip).toContain('header Content-Type "text/html; charset=utf-8"');
    expect(SUSPENDED_PAGE).not.toMatch(/[{}`]/);
    expect(SUSPENDED_PAGE).toContain("This site is suspended");
  });

  test("PHP and legacy sites reach no backend while suspended", () => {
    const php = site({ name: "blog", kind: "php", domains: ["blog.example"], root: "/srv/pano/sites/blog/public", routes: [], enabled: 0 });
    const legacy = site({ name: "old", kind: "legacy", domains: ["old.example"], routes: [], enabled: 0 });
    const out = renderCaddyfile({ apps: [], sites: [php, legacy], settings, certs: new Set() });
    expect(out).not.toContain("php_fastcgi");
    expect(out).not.toContain("reverse_proxy 127.0.0.1:8088");
    expect(block(out, "blog.example")).toContain("import pano_suspended");
  });

  test("nothing suspended: no snippet, sites served as before", () => {
    const out = renderCaddyfile({ apps: [app({})], sites: [site({})], settings, certs: new Set() });
    expect(out).not.toContain("pano_suspended");
    expect(block(out, "shop.example")).toContain("reverse_proxy 127.0.0.1:3000");
  });

  test("a suspended app: every host gets the page (deployed or not), never its ports; its previews too", () => {
    const out = renderCaddyfile({ apps: [app({ suspended: 1 })], sites: [], settings, certs: new Set() });
    const b = block(out, "example.com, www.example.com");
    expect(b).toContain("import pano_suspended");
    expect(out).not.toContain("reverse_proxy 127.0.0.1:4101");
    const fresh = renderCaddyfile({ apps: [app({ suspended: 1, active_slot: "" })], sites: [], settings, certs: new Set() });
    expect(fresh).toContain("example.com, www.example.com {");
    const pv = app({ name: "pv_1", domains: ["feat.pv.example.com"], suspended: 1, processes: [{ name: "", dir: "", routes: ["feat.pv.example.com"], memory_mb: 512, start: "", port_a: 4200, port_b: 4201 }] });
    const withPv = renderCaddyfile({ apps: [app({ suspended: 1 })], sites: [], settings, certs: new Set(), previews: [{ parent: "web", app: pv }] });
    expect(block(withPv, "feat.pv.example.com")).toContain("import pano_suspended");
    expect(withPv).not.toContain("127.0.0.1:4201");
  });
});

describe("edge: redirect HTTP to HTTPS", () => {
  test("on (default): only the HTTPS block, Caddy redirects plain HTTP", () => {
    const out = renderCaddyfile({ apps: [app({})], sites: [site({})], settings, certs: new Set() });
    expect(out).not.toMatch(/^http:\/\//m);
  });

  test("off: a plain HTTP twin with the same handlers and no tls; a catch-all keeps its redirect", () => {
    const s = site({ kind: "legacy", domains: ["old.example", "www.old.example", "*"], routes: [], http_redirect: 0, tls_cert: "/c", tls_key: "/k" });
    const out = renderCaddyfile({ apps: [], sites: [s], settings, certs: new Set(["site-shop"]) });
    const https = block(out, "old.example, www.old.example");
    const any = block(out, "https://");
    const plain = block(out, "http://old.example, http://www.old.example");
    expect(https).toContain("\ttls /etc/pano/certs/site-shop/cert.pem");
    expect(https).toContain("reverse_proxy 127.0.0.1:8088");
    expect(any).toContain("on_demand");
    expect(any).toContain("reverse_proxy 127.0.0.1:8088");
    expect(plain).toContain("\timport pano_common");
    expect(plain).toContain("reverse_proxy 127.0.0.1:8088");
    expect(plain).not.toContain("tls");
    expect(plain).toContain("site-shop.log");
    expect(out).not.toContain("http://, ");
    expect(out).not.toMatch(/http:\/\/\s*\{/);
  });

  test("off for an app, and for a suspended one (its page on plain HTTP too)", () => {
    const out = renderCaddyfile({ apps: [app({ http_redirect: 0 })], sites: [], settings, certs: new Set() });
    expect(block(out, "http://example.com, http://www.example.com")).toContain("reverse_proxy 127.0.0.1:4101");
    const off = renderCaddyfile({ apps: [app({ http_redirect: 0, suspended: 1 })], sites: [], settings, certs: new Set() });
    expect(block(off, "http://example.com, http://www.example.com")).toContain("import pano_suspended");
  });
});

describe("state", () => {
  test("migration: existing legacy sites stop redirecting (the backend decides), others keep it", () => {
    sites.upsert(site({ name: "m-legacy", kind: "legacy", domains: ["m-legacy.example"] }));
    sites.upsert(site({ name: "m-proxy", domains: ["m-proxy.example"] }));
    // As a database from before the column: drop it, then migrate again.
    state().exec("ALTER TABLE sites DROP COLUMN http_redirect");
    migrate(state());
    expect(sites.get("m-legacy")!.http_redirect).toBe(0);
    expect(sites.get("m-proxy")!.http_redirect).toBe(1);
    // A later save without the field keeps it.
    sites.upsert(site({ name: "m-legacy", kind: "legacy", domains: ["m-legacy.example"] }));
    expect(sites.get("m-legacy")!.http_redirect).toBe(0);
    sites.remove("m-legacy");
    sites.remove("m-proxy");
  });

  test("reasons are one printable line", () => {
    expect(suspendReason("  unpaid\ninvoice\t#12 ")).toBe("unpaid invoice #12");
    expect(suspendReason(undefined)).toBe("");
    expect(suspendReason("x".repeat(500))).toHaveLength(200);
  });
});

describe("suspend and resume", () => {
  const lines: string[] = [];
  const spy = spyOn(console, "log").mockImplementation((...a: unknown[]) => void lines.push(a.join(" ")));
  afterEach(() => void (lines.length = 0));
  const ran = (cmd: string) => lines.some((l) => l === `[dry-run] ${cmd}`);

  test("guarded like other routine changes: a code, or the trusted window", () => {
    for (const m of ["sites.suspend", "sites.resume", "sites.toggle", "apps.suspend", "apps.resume", "projects.suspend", "projects.resume"]) {
      expect(needsOtp(m, {})).toBe(true);
      expect(FRESH_ONLY.has(m)).toBe(false);
    }
  });

  test("site: reason and date kept while suspended, cleared on resume; saving settings keeps it suspended", async () => {
    sites.upsert(site({ name: "s1.example", domains: ["s1.example"] }));
    await suspendSite("s1.example", "unpaid", "tester");
    let s = sites.get("s1.example")!;
    expect(s.enabled).toBe(0);
    expect(s.suspended_reason).toBe("unpaid");
    expect(s.suspended_at).toBeGreaterThan(0);
    await expect(suspendSite("s1.example", "", "tester")).rejects.toThrow("already suspended");
    await methods["sites.save"]!({ name: "s1.example", kind: "proxy", domains: "s1.example", routes: "/ 127.0.0.1:3000", http_redirect: ["0", "1"] }, "tester");
    s = sites.get("s1.example")!;
    expect(s.enabled).toBe(0);
    expect(s.suspended_reason).toBe("unpaid");
    expect(s.http_redirect).toBe(1);
    await resumeSite("s1.example", "tester");
    s = sites.get("s1.example")!;
    expect([s.enabled, s.suspended_reason, s.suspended_at]).toEqual([1, "", 0]);
    await expect(resumeSite("s1.example", "tester")).rejects.toThrow("not suspended");
    // The older toggle maps onto suspend / resume.
    await methods["sites.toggle"]!({ name: "s1.example", enabled: false }, "tester");
    expect(sites.get("s1.example")!.enabled).toBe(0);
    await methods["sites.toggle"]!({ name: "s1.example", enabled: true }, "tester");
    expect(sites.get("s1.example")!.enabled).toBe(1);
    sites.remove("s1.example");
  });

  test("PHP site: pool and cron timers stop, and start again", async () => {
    sites.upsert(site({ name: "p1.example", kind: "php", domains: ["p1.example"], root: "/srv/pano/sites/p1.example/public", routes: [] }));
    await suspendSite("p1.example", "", "tester");
    expect(ran("systemctl disable --now pano-php-p1.example.service")).toBe(true);
    lines.length = 0;
    await resumeSite("p1.example", "tester");
    expect(ran("systemctl enable --now pano-php-p1.example.service")).toBe(true);
    sites.remove("p1.example");
  });

  test("suspended: cron jobs run by hand and wp-cli are refused (N6)", async () => {
    sites.upsert(site({ name: "n6.example", kind: "php", domains: ["n6.example"], root: "/srv/pano/sites/n6.example/public", routes: [], crons: [{ schedule: "daily", command: "php x.php" }] }));
    apps.insert({ name: "n6-web", kind: "managed", domains: ["n6.example.com"], active_slot: "a", port_a: 4310, port_b: 4311, crons: [{ schedule: "daily", command: "echo hi" }] });
    await suspendSite("n6.example", "", "tester");
    await suspendApp("n6-web", "", "tester");
    lines.length = 0;
    await expect(runJob({ owner: "site", name: "n6.example", index: 0 }, "tester")).rejects.toThrow("suspended");
    await expect(runJob({ owner: "app", name: "n6-web", index: 0 }, "tester")).rejects.toThrow("suspended");
    expect(lines.some((l) => l.includes("systemctl start"))).toBe(false);
    for (const call of [() => wordpress.setMaintenance("n6.example", true, "tester"), () => wordpress.status("n6.example"), () => wordpress.update({ name: "n6.example", core: true }, "tester")])
      await expect(call()).rejects.toThrow("suspended");
    expect(() => wordpress.assertSiteRuns(sites.get("n6.example")!)).toThrow("suspended");
    await resumeSite("n6.example", "tester");
    await resumeApp("n6-web", "tester");
    expect(() => wordpress.assertSiteRuns(sites.get("n6.example")!)).not.toThrow();
    await runJob({ owner: "app", name: "n6-web", index: 0 }, "tester");
    expect(ran("systemctl start --no-block pano-cron-n6-web-0.service")).toBe(true);
    sites.remove("n6.example");
    apps.remove("n6-web");
  });

  test("app: processes and cron timers stop; deploys, starts and rollbacks are refused; resume restores what ran", async () => {
    apps.insert({ name: "susp-web", kind: "managed", domains: ["susp.example.com"], active_slot: "a", port_a: 4300, port_b: 4301, crons: [{ schedule: "daily", command: "echo hi" }] });
    await suspendApp("susp-web", "abuse report", "tester");
    expect(ran("systemctl disable --now pano-app-susp-web@a.service")).toBe(true);
    expect(ran("systemctl disable --now pano-cron-susp-web-0.timer")).toBe(true);
    const a = apps.get("susp-web")!;
    expect([a.suspended, a.suspended_reason]).toEqual([1, "abuse report"]);
    expect(a.suspended_units.map((u) => u.unit)).toEqual(["pano-app-susp-web@a.service", "pano-cron-susp-web-0.timer"]);
    expect(() => startDeploy("susp-web", "manual", "tester")).toThrow("suspended");
    await expect(appAction("susp-web", "start", "tester")).rejects.toThrow("suspended");
    await expect(suspendApp("susp-web", "", "tester")).rejects.toThrow("already suspended");

    // What ran before: the web process (running, enabled) and the timer (enabled, idle between runs).
    apps.update("susp-web", {
      suspended_units: [
        { unit: "pano-app-susp-web@a.service", active: true, enabled: true },
        { unit: "pano-cron-susp-web-0.timer", active: false, enabled: true },
        { unit: "pano-app-pv_9@a.service", active: false, enabled: false },
      ],
    });
    lines.length = 0;
    await resumeApp("susp-web", "tester");
    expect(ran("systemctl enable pano-app-susp-web@a.service")).toBe(true);
    expect(ran("systemctl start pano-app-susp-web@a.service")).toBe(true);
    expect(ran("systemctl enable pano-cron-susp-web-0.timer")).toBe(true);
    expect(ran("systemctl start pano-cron-susp-web-0.timer")).toBe(false);
    expect(lines.some((l) => l.includes("pv_9"))).toBe(false);
    const b = apps.get("susp-web")!;
    expect([b.suspended, b.suspended_reason, b.suspended_units]).toEqual([0, "", []]);
    apps.remove("susp-web");
  });

  test("an app is not suspended while a deploy runs (it would start processes again)", async () => {
    apps.insert({ name: "busy-web", kind: "managed", domains: ["busy.example.com"], active_slot: "a", port_a: 4310, port_b: 4311 });
    const id = deploys.start("busy-web", "manual");
    await expect(suspendApp("busy-web", "", "tester")).rejects.toThrow("deploy is running");
    deploys.finish(id, { status: "failed" });
    apps.remove("busy-web");
  });

  test("project: every member at once, members already so are skipped", async () => {
    apps.insert({ name: "proj-api", kind: "external", domains: [], external_unit: "pm2:shop/api", upstream: "127.0.0.1:3900" });
    sites.upsert(site({ name: "proj.example", domains: ["proj.example"] }));
    sites.upsert(site({ name: "proj2.example", domains: ["proj2.example"], enabled: 0 }));
    const r = await setProjectSuspended({ apps: ["proj-api"], sites: ["proj.example", "proj2.example"], reason: "unpaid" }, true, "tester");
    expect(r.done).toEqual(["app proj-api", "site proj.example"]);
    expect(r.failed).toEqual([]);
    expect(apps.get("proj-api")!.suspended).toBe(1);
    // An external app keeps running: pano only puts the page up.
    expect(lines.some((l) => l.includes("pm2"))).toBe(false);
    expect(sites.get("proj.example")!.suspended_reason).toBe("unpaid");
    await expect(setProjectSuspended({ apps: ["nope-app"] }, true, "tester")).rejects.toThrow();
    const back = await setProjectSuspended({ apps: ["proj-api"], sites: ["proj.example", "proj2.example"] }, false, "tester");
    expect(back.done).toEqual(["app proj-api", "site proj.example", "site proj2.example"]);
    expect(sites.get("proj2.example")!.enabled).toBe(1);
    apps.remove("proj-api");
    sites.remove("proj.example");
    sites.remove("proj2.example");
  });

  test("restore console", () => spy.mockRestore());
});

describe("views", () => {
  const html = (x: unknown) => String(x);
  const row = { name: "s.example", kind: "proxy", domains: ["s.example"], root: "", routes: [], ask_url: "", php_version: "", tls_cert: "", source: "pano", on_demand_tls: 0 };
  const appRow: any = {
    name: "web", kind: "managed", domains: ["example.com"], runtime: "node", runtime_version: "24", active_slot: "a", external_unit: "", upstream: "", processes: [],
    status: { active: "suspended", memory: 0, since: "" }, suspended: 1, suspended_reason: "unpaid", suspended_at: 1_700_000_000,
  };

  test("site and app heads: Suspend with a reason, or Resume with a banner; no Deploy while suspended", () => {
    const on = html(<SiteHead site={{ ...row, enabled: 1 }} csrf="c" />);
    expect(on).toContain('action="/sites/s.example/suspend"');
    expect(on).toContain('name="reason"');
    const off = html(<SiteHead site={{ ...row, enabled: 0, suspended_reason: "abuse <b>", suspended_at: 1_700_000_000 }} csrf="c" />);
    expect(off).toContain('action="/sites/s.example/resume"');
    expect(off).toContain("This site is suspended.");
    expect(off).toContain("abuse &lt;b&gt;");
    expect(off).toContain("2023-11-14 22:13");
    const a = html(<AppHead app={appRow} csrf="c" />);
    expect(a).toContain('action="/apps/web/resume"');
    expect(a).not.toContain('action="/apps/web/deploy"');
    expect(a).toContain("unpaid");
    expect(withLang("tr", () => html(<AppHead app={appRow} csrf="c" />))).toContain("Bu uygulama askıda.");
  });

  test("settings: the HTTPS redirect checkbox, on unless turned off", () => {
    const form = html(<SiteForm site={{ ...row, enabled: 1, http_redirect: 0 }} csrf="c" />);
    expect(form).toContain('name="http_redirect" value="0"');
    expect(form).not.toMatch(/name="http_redirect" value="1" checked/);
    expect(html(<SiteForm csrf="c" />)).toMatch(/name="http_redirect" value="1" checked/);
    expect(html(<AppForm csrf="c" runtimes={[]} action="/apps" submit="Create" />)).toContain("Redirect HTTP to HTTPS");
  });

  test("projects: Suspended pill, partial count and the summary card", () => {
    const sRow = (name: string, enabled: number) => ({ ...row, name, domains: [name], enabled, routes: [] });
    const all = { key: "site:a.example", name: "a.example", apps: [], sites: [sRow("a.example", 0)], domains: ["a.example"] };
    const part = { key: "site:b.example", name: "b.example", apps: [appRow], sites: [sRow("b.example", 1)], domains: ["b.example"] };
    const page = html(<ProjectsPage projects={[all, part] as any} certs={[]} now={1_700_000_000} />);
    expect(page).toContain('class="state-pill suspended"');
    expect(page).toContain("Suspended 1/2");
    expect(page).toContain("Apps: 1, sites: 1");
    const detail = html(<ProjectDetail p={part as any} projects={[part] as any} certs={[]} now={1_700_000_000} csrf="c" />);
    // Partly suspended: Resume for those that are, Suspend for the rest.
    expect(detail).toMatch(/action="\/projects\/[^/"]+\/resume"/);
    expect(detail).toMatch(/action="\/projects\/[^/"]+\/suspend"/);
  });
});
