// Projects: the apps and sites that belong together, worked out from how traffic flows.
// Nothing is stored except manual moves; apps and sites keep their own records and pages.
//
// Links, in order:
//   1. a site's route to 127.0.0.1:<port> joins the app listening on that port
//   2. an app's own domains join the site that has the same domain
//   3. PM2 apps of the same system user belong together (one ecosystem, one deploy)
//   4. a manual move ("worker belongs to shop") wins over all of the above

export type ProjApp = {
  name: string;
  kind: string;
  external_unit: string;
  upstream: string;
  domains: string[];
  port_a?: number;
  port_b?: number;
  processes?: { name: string; routes: string[]; port_a: number; port_b: number }[];
};
export type ProjSite = { name: string; kind: string; domains: string[]; routes: { path: string; upstream: string }[]; enabled: number };

export type Project<A extends ProjApp = ProjApp, S extends ProjSite = ProjSite> = {
  /** stable id: the first member's key ("site:shop.example" / "app:worker") */
  key: string;
  name: string;
  apps: A[];
  sites: S[];
  /** every host the project answers */
  domains: string[];
};

/** item key ("app:worker") -> key of the item it was moved next to, or "" for its own project */
export type Moves = Record<string, string>;

export const appKey = (name: string) => `app:${name}`;
export const siteKey = (name: string) => `site:${name}`;

function appPorts(a: ProjApp): number[] {
  const ports = new Set<number>();
  for (const u of a.upstream.split(",")) {
    const p = Number(u.split(":").at(-1));
    if (p) ports.add(p);
  }
  for (const p of [a.port_a, a.port_b, ...(a.processes ?? []).flatMap((x) => [x.port_a, x.port_b])]) if (p) ports.add(p);
  return [...ports];
}

function appHosts(a: ProjApp): string[] {
  const procHosts = (a.processes ?? []).flatMap((p) => p.routes.map((r) => r.split("/")[0]!));
  return [...new Set([...a.domains, ...procHosts].map((d) => d.toLowerCase()).filter(Boolean))];
}

const pm2User = (a: ProjApp) => a.external_unit.match(/^pm2:([^/]+)\//)?.[1] ?? "";

/** A readable name: "shop.example" -> "shop", "quiz.example.co.uk" -> "quiz"; a PM2 user's name when it has one. */
function nameOf(sites: ProjSite[], apps: ProjApp[]): string {
  if (sites.length + apps.length === 1) return sites[0]?.name ?? apps[0]!.name;
  const user = apps.map(pm2User).find(Boolean);
  if (user) return user;
  const site = [...sites].sort((a, b) => a.name.length - b.name.length)[0];
  if (site && sites.length > 1) return site.name.replace(/^www\./, "").split(".")[0]!;
  if (site) return site.name;
  return [...apps].sort((a, b) => a.name.length - b.name.length)[0]?.name ?? "";
}

export function groupProjects<A extends ProjApp, S extends ProjSite>(apps: A[], sites: S[], moves: Moves = {}): Project<A, S>[] {
  const keys = [...sites.map((s) => siteKey(s.name)), ...apps.map((a) => appKey(a.name))];
  const parent = new Map(keys.map((k) => [k, k]));
  const find = (k: string): string => {
    let r = k;
    while (parent.get(r) !== r) r = parent.get(r)!;
    parent.set(k, r);
    return r;
  };
  const join = (a: string, b: string) => {
    if (!parent.has(a) || !parent.has(b) || moves[a] !== undefined || moves[b] !== undefined) return;
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(rb, ra);
  };

  const byPort = new Map<number, string>();
  for (const a of apps) for (const p of appPorts(a)) byPort.set(p, appKey(a.name));
  for (const s of sites) {
    for (const r of s.routes) {
      const app = byPort.get(Number(r.upstream.split(":").at(-1)));
      if (app) join(siteKey(s.name), app);
    }
  }
  const byHost = new Map<string, string>();
  for (const s of sites) for (const d of s.domains) byHost.set(d.toLowerCase(), siteKey(s.name));
  for (const a of apps) for (const h of appHosts(a)) if (byHost.has(h)) join(byHost.get(h)!, appKey(a.name));
  const byUser = new Map<string, string>();
  for (const a of apps) {
    const u = pm2User(a);
    if (!u) continue;
    if (byUser.has(u)) join(byUser.get(u)!, appKey(a.name));
    else byUser.set(u, appKey(a.name));
  }
  // Manual moves last: an item moved next to another joins that one's project; "" stands alone.
  for (const [item, target] of Object.entries(moves)) {
    if (!parent.has(item) || !target || !parent.has(target) || item === target) continue;
    parent.set(item, find(target));
  }

  const groups = new Map<string, { apps: A[]; sites: S[] }>();
  const at = (k: string) => groups.get(find(k)) ?? groups.set(find(k), { apps: [], sites: [] }).get(find(k))!;
  for (const s of sites) at(siteKey(s.name)).sites.push(s);
  for (const a of apps) at(appKey(a.name)).apps.push(a);

  const out: Project<A, S>[] = [];
  for (const g of groups.values()) {
    const key = g.sites[0] ? siteKey(g.sites[0].name) : appKey(g.apps[0]!.name);
    const domains = [...new Set([...g.sites.flatMap((s) => s.domains), ...g.apps.flatMap(appHosts)])];
    out.push({ key, name: nameOf(g.sites, g.apps), apps: g.apps, sites: g.sites, domains });
  }
  // Bigger projects first, then by name.
  return out.sort((a, b) => b.apps.length + b.sites.length - (a.apps.length + a.sites.length) || a.name.localeCompare(b.name));
}

/** The project's URL id: "site:shop.example" -> "site~shop.example" (no colon in paths). */
export const projectSlug = (key: string) => key.replace(":", "~");
export const slugKey = (slug: string) => slug.replace("~", ":");
