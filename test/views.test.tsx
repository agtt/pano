import { expect, test } from "bun:test";
import { AppDetail, AppForm } from "../src/web/views/apps.tsx";
import { ImportPage, PhpSiteNew, RuntimesPage, SiteForm } from "../src/web/views/pages.tsx";

const versions = [
  { version: "8.5", installed: true, inUse: true, eol: "2029-12-31" },
  { version: "7.4", installed: false, inUse: false, eol: "2022-11-28" },
];
const site = {
  name: "a.test", kind: "php", domains: ["a.test"], root: "/srv/pano/sites/a.test/public", routes: [], ask_url: "", php_version: "8.5", tls_cert: "",
  source: "cpanel", enabled: 1, on_demand_tls: 0, deny_paths: ["/x"], converted_from: { kind: "legacy", root: "/home/a", php_version: "8.1" },
};
const app: any = {
  name: "fp", kind: "managed", domains: [], runtime: "node", runtime_version: "24.1.0", repo: "x", branch: "main", root_dir: "", install_cmd: "", build_cmd: "",
  start_cmd: "", health_path: "/", memory_mb: 1024, port_a: 1, port_b: 2, active_slot: "a", current_release: "", upstream: "", external_unit: "", ask_url: "",
  processes: [
    { name: "pos", dir: "apps/pos", routes: ["a.test"], memory_mb: 512, start: "", port_a: 4102, port_b: 4103 },
    { name: "jobs", dir: "", routes: [], memory_mb: 128, start: "bun w.ts", port_a: 0, port_b: 0 },
  ],
  status: { active: "active", memory: 1000, since: "", procs: [{ name: "pos", active: "active", memory: 100 }] },
  deploys: [],
};

test("new views render", () => {
  const html = (x: unknown) => String(x);
  expect(html(<SiteForm site={site} csrf="c" versions={versions} logs="log" />)).toContain("Revert");
  expect(html(<SiteForm site={{ ...site, kind: "legacy", converted_from: null }} csrf="c" versions={versions} />)).toContain("Move to pano PHP");
  expect(html(<PhpSiteNew csrf="c" versions={versions} />)).toContain("end of life");
  expect(html(<RuntimesPage csrf="c" installed={[]} available={null} php={versions} />)).toContain("PHP 8.5");
  expect(html(<AppDetail csrf="c" app={app} env={{}} logs="" runtimes={[]} hookUrl="" />)).toContain("worker");
  expect(html(<AppForm csrf="c" app={app} runtimes={[]} action="/x" submit="Save" />)).toContain("jobs | . | - | 128 | bun w.ts");
  const imp = html(
    <ImportPage
      csrf="c"
      snippet=""
      existing={new Set()}
      archives={[{ file: "cpmove-a.tar.gz", bytes: 10 }]}
      cpPlan={{
        archive: "cpmove-a.tar.gz", account: "a", mainDomain: "a.test",
        sites: [{ name: "a.test", domains: ["a.test"], php: "8.4", exists: false, warnings: ["w"] }],
        databases: [{ name: "a_wp", bytes: 1, exists: false }],
        users: [{ user: "a_wp", hashOk: true, dbs: { a_wp: ["ALL PRIVILEGES"] }, exists: false }],
        notMigrated: ["mail"], warnings: [],
      }}
      cpReport={{ sites: ["a.test"], databases: ["a_wp"], users: [{ user: "u", password: "p" }], warnings: [] }}
    />,
  );
  expect(imp).toContain("cpanel/apply");
  expect(imp).toContain("New passwords are shown only now");
});
