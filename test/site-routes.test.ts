import { expect, spyOn, test } from "bun:test";
import { renderCaddyfile } from "../src/agent/edge.ts";
import { methods } from "../src/agent/rpc.ts";
import { sites, type Site } from "../src/agent/state.ts";
import { parseSiteRoutes, routeText } from "../src/shared/validate.ts";

spyOn(console, "log").mockImplementation(() => {});

const settings = { email: "", behindCloudflare: false, hooksDomain: "" };
const site = (over: Partial<Site>): Site =>
  ({
    name: "shop", kind: "proxy", domains: ["shop.example"], root: "", routes: [{ path: "/", upstream: "127.0.0.1:3000" }], ask_url: "", php_version: "", tls_cert: "",
    tls_key: "", source: "pano", enabled: 1, on_demand_tls: 0, deny_paths: [], converted_from: null, crons: [], created_at: 0, ...over,
  }) as Site;

test("routes: ports and redirects parse, and print back the same", () => {
  const text = "/partner redirect https://partner.example.com{uri} 301\n/ redirect /partner/login 302\n/api 127.0.0.1:3001";
  const routes = parseSiteRoutes(text);
  expect(routes).toEqual([
    { path: "/partner", upstream: "", redirect: "https://partner.example.com{uri}", code: 301 },
    { path: "/", upstream: "", redirect: "/partner/login", code: 302 },
    { path: "/api", upstream: "127.0.0.1:3001" },
  ]);
  expect(routes.map(routeText).join("\n")).toBe(text);
  expect(parseSiteRoutes("/old redirect https://example.com")[0]!.code).toBe(301);
  for (const bad of ["/x redirect https://e.com/{host}", "/x redirect https://e.com/ 200", '/x redirect https://e.com/"a', "/x redirect javascript:alert(1)", "/x 10.0.0.1:80", "x 127.0.0.1:80"]) {
    expect(() => parseSiteRoutes(bad)).toThrow();
  }
});

test("edge: redirect routes and www to the bare domain", () => {
  const out = renderCaddyfile({
    apps: [],
    sites: [
      site({
        domains: ["shop.example", "www.shop.example"],
        www_apex: 1,
        routes: [{ path: "/partner", upstream: "", redirect: "https://partner.shop.example{uri}", code: 301 }, { path: "/", upstream: "127.0.0.1:3000" }],
      }),
    ],
    settings,
    certs: new Set(),
  });
  expect(out).toContain("\thandle @route0 {\n\t\tredir * https://partner.shop.example{uri} 301\n\t}");
  expect(out).toContain("\thandle {\n\t\treverse_proxy 127.0.0.1:3000\n\t}");
  expect(out).toContain("\tredir @pano_www https://{re.pano_www.1}{uri} 301");
  // Off by default, and never in front of a suspended site's page.
  const off = renderCaddyfile({ apps: [], sites: [site({ www_apex: 1, enabled: 0 }), site({ name: "b", domains: ["b.example"] })], settings, certs: new Set() });
  expect(off).not.toContain("pano_www");
});

test("save: move takes domains from other sites in one step; cert_from reuses a certificate", async () => {
  sites.upsert(site({ name: "old", kind: "legacy", domains: ["a.example", "b.example", "c.example"], tls_cert: "/etc/x/c.pem", tls_key: "/etc/x/k.pem" }));
  await expect(methods["sites.save"]!({ name: "new", kind: "proxy", domains: "a.example b.example", routes: "/ 127.0.0.1:3001" }, "t")).rejects.toThrow("already used by site old");
  await methods["sites.save"]!({ name: "new", kind: "proxy", domains: "a.example b.example", routes: "/ 127.0.0.1:3001", move: true, cert_from: "old", www_apex: ["0", "1"] }, "t");
  expect(sites.get("old")!.domains).toEqual(["c.example"]);
  const n = sites.get("new")!;
  expect([n.domains, n.tls_cert, n.tls_key, n.www_apex]).toEqual([["a.example", "b.example"], "/etc/x/c.pem", "/etc/x/k.pem", 1]);
  await expect(methods["sites.save"]!({ name: "new2", kind: "proxy", domains: "d.example", routes: "/ 127.0.0.1:3001", cert_from: "new2" }, "t")).rejects.toThrow("no imported certificate");
  // A later save without the fields keeps them.
  await methods["sites.save"]!({ name: "new", kind: "proxy", domains: "a.example b.example", routes: "/ 127.0.0.1:3002" }, "t");
  expect([sites.get("new")!.tls_cert, sites.get("new")!.www_apex]).toEqual(["/etc/x/c.pem", 1]);
  sites.remove("new");
  sites.remove("old");
});
