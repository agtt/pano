import { expect, test } from "bun:test";
import { cp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { apply, scan } from "../src/agent/importer.ts";
import { sites } from "../src/agent/state.ts";

test("imports a CyberPanel/OpenLiteSpeed layout into sites", async () => {
  // test/setup.ts points PANO_ROOT at a temp dir and enables dry-run.
  await cp(join(import.meta.dir, "fixtures/lsws"), join(process.env.PANO_ROOT!, "usr/local/lsws"), { recursive: true });

  const plan = await scan();
  const byName = Object.fromEntries(plan.sites.map((s) => [s.name, s]));
  expect(Object.keys(byName).sort()).toEqual(["api.example.net", "blog.example.org", "shop.example"]);

  expect(byName["shop.example"]!.kind).toBe("proxy");
  expect(byName["shop.example"]!.on_demand_tls).toBe(1);
  expect(byName["shop.example"]!.routes).toEqual([
    { path: "/online", upstream: "127.0.0.1:3001" },
    { path: "/", upstream: "127.0.0.1:3000" },
  ]);
  expect(byName["api.example.net"]!.tls_cert).toBe("/opt/api/tls/origin.pem");
  expect(byName["blog.example.org"]!.kind).toBe("legacy");
  // proxy with rewrite rules stays on OpenLiteSpeed to keep its behaviour
  expect(byName["api.example.net"]!.kind).toBe("legacy");
  expect(byName["blog.example.org"]!.php_version).toBe("8.3");
  expect(byName["blog.example.org"]!.root).toBe("/home/blog.example.org/public_html");
  expect(plan.warnings.some((w) => w.includes("ask URL"))).toBe(true);

  await apply({ sites: ["blog.example.org", "shop.example"], apps: [] }, "test");
  expect(sites.list().map((s) => s.name)).toEqual(["blog.example.org", "shop.example"]);
});

test("a malformed domain in the OpenLiteSpeed config never reaches pano's state", async () => {
  const conf = join(process.env.PANO_ROOT!, "usr/local/lsws/conf/httpd_config.conf");
  const text = await readFile(conf, "utf8");
  await writeFile(conf, text.replace("blog.example.org blog.example.org", "blog.example.org blog.example.org, evil.example}{import x"));
  const plan = await scan();
  const blog = plan.sites.find((s) => s.name === "blog.example.org")!;
  expect(blog.domains).toEqual(["blog.example.org"]);
  expect(plan.warnings.some((w) => w.includes("skipped the domain"))).toBe(true);
  await writeFile(conf, text);
});
