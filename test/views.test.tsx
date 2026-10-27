import { expect, test } from "bun:test";
import { AppDetail, AppForm, GitPage } from "../src/web/views/apps.tsx";
import { ServicesPage } from "../src/web/views/services.tsx";
import { VpnPage } from "../src/web/views/vpn.tsx";
import { ProtectCards } from "../src/web/views/protect.tsx";
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
  expect(html(<AppDetail csrf="c" app={app} env={{}} logs="" runtimes={[]} hookUrl="https://h/hooks/github/fp" github={{ connected: true, repo: "me/fp" }} />)).toContain("worker");
  expect(html(<AppDetail csrf="c" app={app} env={{}} logs="" runtimes={[]} hookUrl="https://h/hooks/github/fp" github={{ connected: true, repo: "me/fp" }} />)).toContain("/hooks/gitlab/fp");
  expect(html(<AppForm csrf="c" runtimes={[]} action="/x" submit="Create" repos={[{ full_name: "me/fp", ssh_url: "git@github.com:me/fp.git", default_branch: "main", private: true }]} />)).toContain("git@github.com:me/fp.git");
  expect(html(<GitPage csrf="c" github={{ connected: false, login: "" }} hooksDomain="" />)).toContain("github_pat_");
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

test("vpn and services views render", () => {
  const html = (x: unknown) => String(x);
  const base = {
    installed: true, enabled: true, running: true, address: "10.77.0.1", port: 51820, endpoint: "203.0.113.1", publicKey: "k",
    peers: [{ id: 1, name: "laptop", ip: "10.77.0.2", public_key: "p", created_at: 0, endpoint: "1.2.3.4:5", handshake: 1, rx: 10, tx: 20 }],
    locks: { panel: true, ssh: true, services: false, databases: true }, pending: { previous: { panel: false, ssh: false, services: false, databases: false }, deadline: Date.now() + 60_000 }, sshPort: 22,
  };
  expect(html(<VpnPage csrf="c" s={{ ...base, enabled: false }} viaVpn={false} />)).toContain("Enable private access");
  const on = html(<VpnPage csrf="c" s={base} viaVpn={true} created={{ name: "phone", ip: "10.77.0.3", config: "[Interface]", qr: "data:image/svg+xml;base64,AA", generated: true }} />);
  expect(on).toContain("Confirm, it works");
  expect(on).toContain("laptop");
  const svc = html(
    <ServicesPage
      csrf="c"
      list={[
        { key: "postgres", label: "PostgreSQL", port: 5432, note: "", installed: true, version: "18", managed: true, active: "active", memory: 1, enabled: true },
        { key: "valkey", label: "Valkey", port: 6379, note: "", installed: false, version: "", managed: false, active: "", memory: 0, enabled: false },
      ]}
      pg={[{ name: "app", sizeMb: 7.5, owner: "app", system: false }]}
      secret={{ title: "x", lines: [["DATABASE_URL", "postgres://a"]] }}
    />,
  );
  expect(svc).toContain("/services/valkey/install");
  expect(svc).toContain("postgres://a");
  expect(svc).toContain("$DATA_DIR");
});

test("security cards render", () => {
  const html = String(<ProtectCards csrf="c" guard={{ ssh: true, http: false, banned: ["198.51.100.7"] }} alerts={{ chatId: "1", tokenSet: true }} behindCloudflare={true} />);
  expect(html).toContain("198.51.100.7");
  expect(html).toContain("saved; empty = keep");
  expect(html).toContain("inactive while behind Cloudflare");
});
