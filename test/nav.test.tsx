import { expect, test } from "bun:test";
import { groupProjects } from "../src/web/projects.ts";
import { Layout, NAV, crumbFor, navAt } from "../src/web/views/layout.tsx";
import { ProjectsPage, appType, mainDomain, type Proj } from "../src/web/views/projects.tsx";

test("a short menu; every page that was in it is still one click away", () => {
  expect(NAV.length).toBeLessThanOrEqual(7);
  const reachable = new Set(NAV.flatMap((it) => [it.href, ...(it.tabs ?? []).map((x) => x.href)]));
  const before = ["/", "/projects", "/databases", "/env-groups", "/services", "/jobs", "/backups", "/containers", "/runtimes", "/edge", "/security", "/shield", "/vpn", "/admins", "/activity", "/import", "/android", "/runner"];
  for (const href of before) expect(reachable.has(href)).toBe(true);
});

test("the menu item lights up for its tabs and the pages under them", () => {
  expect(navAt("/").item?.label).toBe("Overview");
  expect(navAt("/shield").item?.label).toBe("Security");
  expect(navAt("/edge/cutover").tab?.label).toBe("Edge");
  expect(navAt("/apps/shop").item?.label).toBe("Projects");
  expect(navAt("/sites/new-php").item?.label).toBe("Projects");
  expect(navAt("/containers/db1")).toMatchObject({ item: { label: "Server" }, tab: { label: "Containers" } });
  expect(navAt("/android/app").item?.label).toBe("Settings");
  expect(navAt("/security").item?.label).toBe("Security");
  expect(navAt("/services").item?.label).toBe("Server");
  expect(crumbFor("/containers/db1")).toEqual([["/services", "Server"], ["/containers", "Containers"]]);
  expect(crumbFor("/shield")).toEqual([]);

  const html = String(<Layout title="Shield" path="/shield" user="a" csrf="c" />);
  expect(html).toContain('<a href="/security" class="on" aria-current="page">');
  expect(html).toContain('<a href="/shield" class="on" aria-current="page">Shield</a>');
  expect(html).not.toContain('<a href="/projects" class="on"');
  // A page under a tab: breadcrumb back up, no tab row.
  const detail = String(<Layout title="db1" path="/containers/db1" user="a" csrf="c" />);
  expect(detail).toContain('<a href="/services" class="on"');
  expect(detail).toContain('<nav class="crumb"');
  expect(detail).not.toContain('class="tabs"');
});

test("projects list: summary, one row per project, type and last deploy", () => {
  const st = { active: "active", memory: 0, since: "" };
  const apps: any[] = [
    { name: "web", kind: "managed", runtime: "node", runtime_version: "24", build_cmd: "next build", start_cmd: "", domains: ["www.shop.test", "shop.test"], upstream: "", external_unit: "", status: st },
    { name: "crm", kind: "external", domains: [], upstream: "127.0.0.1:3000", external_unit: "pm2:crm/app", status: { ...st, active: "failed" } },
  ];
  const projects = groupProjects(apps, []) as Proj[];
  expect(appType(apps[0]).label).toBe("Next.js");
  expect(appType(apps[1]).label).toBe("PM2");
  expect(mainDomain(projects.find((p) => p.name === "web")!)).toBe("shop.test");

  const now = 1_800_000_000;
  const html = String(<ProjectsPage projects={projects} certs={[]} now={now} deploys={{ web: { status: "failed", started_at: now - 60, finished_at: now } }} />);
  expect(html).toContain("Failed deploys");
  expect(html).toContain('href="https://shop.test"');
  expect(html).toContain("Next.js");
  expect(html).toContain('data-filter-for="projects"');
  expect(html.match(/>Manage</g)?.length).toBe(2);
  expect(html).toContain('href="/apps/new"');

  const empty = String(<ProjectsPage projects={[]} certs={[]} now={now} />);
  expect(empty).toContain('href="/import"');
  expect(empty).not.toContain("<table");
});
