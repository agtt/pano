// One place for everything that serves a product: its domains, the apps behind them and the
// sites (PHP, static, proxy). Each app and site keeps its own detail page for deeper work.

import { fmtBytes, fmtDuration, fmtTime, t } from "../i18n.ts";
import { appKey, projectSlug, siteKey, type Project } from "../projects.ts";
import { Ago, appState, parseSince, portOf, runtimeOf, type AppRow, type CertRow, type SiteRow } from "./dashboard.tsx";
import { Icon } from "./icons.tsx";
import { routeLabel, type SiteRoute } from "../../shared/validate.ts";
import { Csrf, SuspendControl } from "./layout.tsx";

export type ProjAppRow = AppRow & {
  port_a?: number;
  port_b?: number;
  processes?: { name: string; routes: string[]; port_a: number; port_b: number }[];
  build_cmd?: string;
  start_cmd?: string;
};
export type ProjSiteRow = SiteRow & { routes: SiteRoute[] };
export type Proj = Project<ProjAppRow, ProjSiteRow>;
/** An app's latest deploy, as the agent keeps it. */
export type LastDeploy = { status: string; started_at: number; finished_at: number | null };

const DAY = 86400;
type State = "up" | "warn" | "down" | "idle" | "suspended";

/** Suspended members of a project (sites: enabled 0). */
export const suspendedCount = (p: Proj) => p.apps.filter((a) => a.suspended).length + p.sites.filter((s) => !s.enabled).length;
const memberCount = (p: Proj) => p.apps.length + p.sites.length;

/** "ok" when every app runs and every enabled site has a valid certificate; else the worst thing in it. "suspended": all of it is. */
export function projectState(p: Proj, certs: Map<string, CertRow>, now: number): State {
  if (memberCount(p) && suspendedCount(p) === memberCount(p)) return "suspended";
  if (p.apps.some((a) => appState(a) === "down")) return "down";
  const certDays = p.sites.filter((s) => s.enabled).map((s) => certs.get(s.name)).filter((c): c is CertRow => !!c?.notAfter).map((c) => Math.floor((c.notAfter! - now) / DAY));
  if (certDays.some((d) => d < 7)) return "down";
  if (p.apps.some((a) => appState(a) === "unknown") || certDays.some((d) => d < 14)) return "warn";
  if (!p.apps.some((a) => !a.suspended) && !p.sites.some((s) => s.enabled)) return "idle";
  return "up";
}

const siteKind = (s: ProjSiteRow) => (s.kind === "legacy" ? (s.source === "cyberpanel" ? "OpenLiteSpeed" : t("legacy")) : s.kind === "php" ? "PHP" : s.kind);

/** What a member is, in one word; `tone` groups them for color (JavaScript apps, PHP, plain web, run elsewhere). */
export type TypeTag = { label: string; tone: "js" | "php" | "web" | "ext" };

export function appType(a: ProjAppRow): TypeTag {
  if (a.kind === "managed") {
    // No framework is stored: the commands tell Next.js apart; auto-detected ones count as their runtime.
    if (/(^|[\s/])next(\s|$)/.test(`${a.build_cmd ?? ""} ${a.start_cmd ?? ""}`)) return { label: "Next.js", tone: "js" };
    if (a.runtime === "python") return { label: "Python", tone: "web" };
    return { label: a.runtime === "bun" ? "Bun" : "Node", tone: "js" };
  }
  return a.external_unit.startsWith("pm2:") ? { label: "PM2", tone: "ext" } : { label: t("External"), tone: "ext" };
}

export function siteType(s: ProjSiteRow, wordpress = false): TypeTag {
  if (s.kind === "php") return { label: wordpress ? "WordPress" : "PHP", tone: "php" };
  if (s.kind === "legacy") return { label: s.source === "cyberpanel" ? "OpenLiteSpeed" : "PHP", tone: "php" };
  if (s.kind === "static") return { label: t("Static"), tone: "web" };
  return { label: "Proxy", tone: "web" };
}

/** The project's kinds, apps first; a proxy in front of the project's own app adds nothing. */
export function projectTypes(p: Proj, wordpress: Set<string> = new Set()): TypeTag[] {
  const all = [...p.apps.map(appType), ...p.sites.filter((s) => !(p.apps.length && s.kind === "proxy")).map((s) => siteType(s, wordpress.has(s.name)))];
  return all.filter((x, i) => all.findIndex((y) => y.label === x.label) === i);
}

/** The domain to show and open: a plain host, the shortest (example.com before www.example.com). */
export function mainDomain(p: Proj): string {
  return [...p.domains].filter((d) => d !== "*" && !d.startsWith("*.")).sort((a, b) => a.length - b.length || a.localeCompare(b))[0] ?? "";
}

/** The project's newest deploy over its own apps. */
function lastDeployOf(p: Proj, deploys: Record<string, LastDeploy>): LastDeploy | null {
  return p.apps.map((a) => deploys[a.name]).filter((d): d is LastDeploy => !!d).sort((a, b) => b.started_at - a.started_at)[0] ?? null;
}

/** Days left on the soonest certificate of the project's enabled sites; `error` when one cannot be read. */
function certOf(p: Proj, certs: Map<string, CertRow>, now: number): { days: number | null; error: boolean } {
  const cs = p.sites.filter((s) => s.enabled).map((s) => certs.get(s.name)).filter((c): c is CertRow => !!c);
  const days = cs.filter((c) => c.notAfter).map((c) => Math.floor((c.notAfter! - now) / DAY));
  return { days: days.length ? Math.min(...days) : null, error: cs.some((c) => c.error) };
}

const STATE_LABEL: Record<State, string> = { up: "Running", warn: "Check", down: "Down", idle: "Idle", suspended: "Suspended" };

export function StatePill({ state }: { state: State }) {
  return (
    <span class={`state-pill ${state}`}>
      <span class={`led ${state}`} aria-hidden="true" />
      {t(STATE_LABEL[state])}
    </span>
  );
}

/** The project's state, and a "Suspended n/m" pill when only some of it is. */
function ProjectStatus({ p, st }: { p: Proj; st: State }) {
  const n = suspendedCount(p);
  return (
    <span class="pills">
      <StatePill state={st} />
      {n && st !== "suspended" ? (
        <span class="state-pill suspended" title={t("Suspended")}>
          <span class="led suspended" aria-hidden="true" />
          {`${t("Suspended")} ${n}/${memberCount(p)}`}
        </span>
      ) : null}
    </span>
  );
}

function TypeTags({ list, max = 2 }: { list: TypeTag[]; max?: number }) {
  if (!list.length) return <span class="muted">—</span>;
  return (
    <span class="type-tags">
      {list.slice(0, max).map((x) => (
        <span class={`type ${x.tone}`}>{x.label}</span>
      ))}
      {list.length > max ? <span class="muted small">+{list.length - max}</span> : null}
    </span>
  );
}

function CertCell({ days, error }: { days: number | null; error: boolean }) {
  if (error) return <span class="crit">{t("unreadable")}</span>;
  if (days === null) return <span class="muted">—</span>;
  if (days < 0) return <span class="crit">{t("expired")}</span>;
  return <span class={days < 7 ? "crit" : days < 14 ? "soon" : ""}>{t("{n} days").replace("{n}", String(days))}</span>;
}

const DEPLOY_LABEL: Record<string, string> = { success: "Deployed", failed: "Failed", running: "Deploying" };

function DeployCell({ d, now }: { d: LastDeploy | null; now: number }) {
  if (!d) return <span class="muted">—</span>;
  const tone = d.status === "success" ? "up" : d.status === "failed" ? "down" : "warn";
  return (
    <span class="deploy-cell" title={fmtTime(d.started_at)}>
      <span class={`led ${tone}`} aria-hidden="true" />
      {t(DEPLOY_LABEL[d.status] ?? d.status)}
      <small class="muted">{t("{t} ago").replace("{t}", fmtDuration(Math.max(0, now - d.started_at)))}</small>
    </span>
  );
}

function AddMenu() {
  return (
    <details class="menu">
      <summary class="btn primary">
        <Icon name="plus" size={16} /> {t("Add")}
      </summary>
      <div class="menu-list">
        <a href="/apps/new">
          <Icon name="git" size={16} />
          <span>
            {t("New app")}
            <small>{t("Deploy from git")}</small>
          </span>
        </a>
        <a href="/sites/new-php">
          <Icon name="sites" size={16} />
          <span>
            {t("PHP site")}
            <small>{t("WordPress or any PHP")}</small>
          </span>
        </a>
        <a href="/sites/new">
          <Icon name="edge" size={16} />
          <span>
            {t("Proxy or static site")}
            <small>{t("Files, or traffic sent to a port")}</small>
          </span>
        </a>
        <a href="/import">
          <Icon name="import" size={16} />
          <span>
            {t("Import")}
            <small>{t("What already runs on this server")}</small>
          </span>
        </a>
        <a href="/git">
          <Icon name="git" size={16} />
          <span>
            Git
            <small>{t("Connect GitHub and other hosts")}</small>
          </span>
        </a>
      </div>
    </details>
  );
}

function Summary({ projects, cm, now, deploys }: { projects: Proj[]; cm: Map<string, CertRow>; now: number; deploys?: Record<string, LastDeploy> }) {
  // Suspended apps are off on purpose: not counted as running or not running.
  const apps = projects.flatMap((p) => p.apps).filter((a) => !a.suspended);
  const sites = projects.flatMap((p) => p.sites);
  const up = apps.filter((a) => appState(a) === "up").length;
  const on = sites.filter((s) => s.enabled).length;
  const offApps = projects.flatMap((p) => p.apps).filter((a) => a.suspended).length;
  const offSites = sites.length - on;
  const domains = new Set(projects.flatMap((p) => p.domains).filter((d) => d !== "*")).size;
  const badApps = apps.filter((a) => appState(a) === "down" || appState(a) === "unknown").length;
  const badCerts = sites.filter((s) => s.enabled).map((s) => cm.get(s.name)).filter((c) => c && (c.error || (c.notAfter && c.notAfter - now < 14 * DAY))).length;
  const attention = projects.filter((p) => ["down", "warn"].includes(projectState(p, cm, now))).length;
  const failed = deploys ? apps.filter((a) => deploys[a.name]?.status === "failed").length : null;
  const cards: { label: string; value: string; sub: string; tone?: string }[] = [
    { label: t("Projects"), value: String(projects.length), sub: t("{n} domains").replace("{n}", String(domains)) },
    { label: t("Apps running"), value: apps.length ? `${up}/${apps.length}` : "0", sub: apps.length === up ? t("all running") : t("{n} not running").replace("{n}", String(apps.length - up)), tone: apps.length > up ? "warn" : "" },
    { label: t("Sites"), value: String(sites.length), sub: sites.length === on ? t("all on") : t("{n} suspended").replace("{n}", String(sites.length - on)) },
    {
      label: t("Need attention"),
      value: String(attention),
      sub: attention ? t("Apps: {a}, certificates: {c}").replace("{a}", String(badApps)).replace("{c}", String(badCerts)) : t("nothing to check"),
      tone: projects.some((p) => projectState(p, cm, now) === "down") ? "down" : attention ? "warn" : "",
    },
  ];
  if (failed !== null) cards.push({ label: t("Failed deploys"), value: String(failed), sub: t("last deploy of each app"), tone: failed ? "down" : "" });
  if (offApps + offSites) {
    cards.push({
      label: t("Suspended"),
      value: String(offApps + offSites),
      sub: t("Apps: {a}, sites: {s}").replace("{a}", String(offApps)).replace("{s}", String(offSites)),
      tone: "suspended",
    });
  }
  return (
    <section class="summary" aria-label={t("Summary")}>
      {cards.map((c) => (
        <div class={`summary-card ${c.tone ?? ""}`}>
          <span class="summary-label">{c.label}</span>
          <strong class="summary-value">{c.value}</strong>
          <small class="muted">{c.sub}</small>
        </div>
      ))}
    </section>
  );
}

/** A member's link with its state light, for projects with more than one. */
function Members({ p }: { p: Proj }) {
  if (p.apps.length + p.sites.length < 2) return null;
  return (
    <div class="members">
      {p.apps.map((a) => (
        <a class="chip" href={`/apps/${a.name}`}>
          <span class={`led ${a.suspended ? "suspended" : appState(a)}`} aria-hidden="true" />
          {a.name}
        </a>
      ))}
      {p.sites.map((s) => (
        <a class="chip" href={`/sites/${s.name}`}>
          <span class={`led ${s.enabled ? "up" : "suspended"}`} aria-hidden="true" />
          {s.name}
        </a>
      ))}
    </div>
  );
}

export function ProjectsPage({ projects, certs, now, deploys, wordpress = [] }: { projects: Proj[]; certs: CertRow[]; now: number; deploys?: Record<string, LastDeploy>; wordpress?: string[] }) {
  const cm = new Map(certs.map((c) => [c.site, c]));
  const wp = new Set(wordpress);
  if (!projects.length) {
    return (
      <section class="card empty-state">
        <Icon name="apps" size={28} />
        <h2>{t("No projects yet")}</h2>
        <p class="muted">{t("Import what already runs on this server, or start a new app or site.")}</p>
        <a class="btn primary" href="/import">
          {t("Import from this server")}
        </a>
        <p class="small">
          <a href="/apps/new">{t("New app")}</a> · <a href="/sites/new-php">{t("PHP site")}</a>
        </p>
      </section>
    );
  }
  return (
    <div class="stack">
      <Summary projects={projects} cm={cm} now={now} deploys={deploys} />
      <section class="card table-card">
        <div class="toolbar">
          <label class="filter">
            <Icon name="search" size={16} />
            <input type="search" data-filter-for="projects" placeholder={t("Filter by name, domain or type")} aria-label={t("Filter projects")} autocomplete="off" />
          </label>
          <AddMenu />
        </div>
        <div class="table-scroll">
          <table class="list" id="projects">
            <thead>
              <tr>
                <th>{t("Project")}</th>
                <th>{t("Type")}</th>
                <th>{t("Status")}</th>
                <th>SSL</th>
                <th>{t("Last deploy")}</th>
                <th class="end">
                  <span class="sr-only">{t("Actions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {projects.map((p) => {
                const st = projectState(p, cm, now);
                const types = projectTypes(p, wp);
                const dom = mainDomain(p);
                const href = `/projects/${projectSlug(p.key)}`;
                const more = p.domains.filter((d) => d !== dom).length;
                const words = [
                  p.name, ...p.domains, ...types.map((x) => x.label), ...p.apps.flatMap((a) => [a.name, a.runtime ?? ""]), ...p.sites.flatMap((s) => [s.name, s.kind]),
                  ...(suspendedCount(p) ? ["suspended", t("Suspended")] : []),
                ];
                return (
                  <tr data-filter={words.join(" ").toLowerCase()}>
                    <td class="proj-cell">
                      <a class="proj-name" href={href}>
                        {p.name}
                      </a>
                      <div class="proj-domain">
                        {dom ? (
                          <a href={`https://${dom}`} target="_blank" rel="noopener noreferrer" title={t("Open {d}").replace("{d}", dom)}>
                            {dom} <Icon name="external" size={12} />
                          </a>
                        ) : p.domains.includes("*") ? (
                          <span class="muted">{t("any domain")}</span>
                        ) : (
                          <span class="muted">{t("no domain")}</span>
                        )}
                        {more > 0 && dom ? <span class="muted small"> +{more}</span> : null}
                      </div>
                      <Members p={p} />
                    </td>
                    <td>
                      <TypeTags list={types} />
                    </td>
                    <td>
                      <ProjectStatus p={p} st={st} />
                    </td>
                    <td class="nowrap">
                      <CertCell {...certOf(p, cm, now)} />
                    </td>
                    <td class="nowrap">
                      <DeployCell d={deploys ? lastDeployOf(p, deploys) : null} now={now} />
                    </td>
                    <td class="end">
                      <a class="btn small" href={href}>
                        {t("Manage")}
                      </a>
                    </td>
                  </tr>
                );
              })}
              <tr class="filter-empty" hidden>
                <td colspan={6} class="muted">
                  {t("No projects match.")}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
      <p class="muted small">{t("Apps and sites are grouped by where traffic goes; move one if it belongs elsewhere.")}</p>
    </div>
  );
}

function MoveForm({ item, current, projects, csrf }: { item: string; current: string; projects: Proj[]; csrf: string }) {
  return (
    <form method="post" action="/projects/move" class="move">
      <Csrf token={csrf} />
      <input type="hidden" name="item" value={item} />
      <select name="target" aria-label={t("Move to project")}>
        <option value="" selected={false}>
          {t("Own project")}
        </option>
        {projects.map((p) => (
          <option value={p.key} selected={p.key === current}>
            {p.name}
          </option>
        ))}
      </select>
      <button class="btn small">{t("Move")}</button>
    </form>
  );
}

function DomainLinks({ list }: { list: string[] }) {
  if (!list.length) return <p class="muted">{t("no domain")}</p>;
  return (
    <ul class="domain-list">
      {list.map((d) => (
        <li>
          {d === "*" || d.startsWith("*.") ? (
            <code>{d === "*" ? t("any domain") : d}</code>
          ) : (
            <a href={`https://${d}`} target="_blank" rel="noopener noreferrer">
              {d} <Icon name="external" size={12} />
            </a>
          )}
        </li>
      ))}
    </ul>
  );
}

// A project's own page. Room for more tabs later (members, who may manage it).
export function ProjectDetail({ p, projects, certs, now, csrf }: { p: Proj; projects: Proj[]; certs: CertRow[]; now: number; csrf: string }) {
  const cm = new Map(certs.map((c) => [c.site, c]));
  const off = suspendedCount(p);
  const base = `/projects/${projectSlug(p.key)}`;
  return (
    <div class="stack">
      <section class="card">
        <div class="card-head">
          <h2>{t("Domains")}</h2>
          <div class="row">
            <ProjectStatus p={p} st={projectState(p, cm, now)} />
            {/* Partly suspended: both, for the rest and for those that are. */}
            {off ? <SuspendControl base={base} suspended csrf={csrf} what="project" /> : null}
            {off < memberCount(p) ? <SuspendControl base={base} suspended={false} csrf={csrf} what="project" /> : null}
          </div>
        </div>
        <DomainLinks list={p.domains} />
      </section>

      {p.apps.length ? (
        <section class="card table-card">
          <div class="card-head">
            <h2>{t("Apps")}</h2>
          </div>
          <div class="table-scroll">
            <table class="list">
              <thead>
                <tr>
                  <th>{t("Name")}</th>
                  <th>{t("Type")}</th>
                  <th class="num">{t("Port")}</th>
                  <th class="num">{t("Memory")}</th>
                  <th class="num">{t("Up for")}</th>
                  <th>{t("Project")}</th>
                  <th class="end">
                    <span class="sr-only">{t("Actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {p.apps.map((a) => {
                  const s = appState(a);
                  return (
                    <tr class={a.suspended ? "off" : s}>
                      <td>
                        <span class={`led ${a.suspended ? "suspended" : s}`} title={a.suspended ? t("suspended") : a.status.active} />
                        <a href={`/apps/${a.name}`}>{a.name}</a>
                      </td>
                      <td>
                        <TypeTags list={[appType(a)]} /> <span class="muted small">{runtimeOf(a)}</span>
                      </td>
                      <td class="num muted">{portOf(a)}</td>
                      <td class="num">{a.status.memory ? fmtBytes(a.status.memory) : "—"}</td>
                      <td class="num">{s === "up" ? <Ago at={parseSince(a.status.since)} now={now} /> : <span class="state">{a.suspended ? t("Suspended") : a.status.active}</span>}</td>
                      <td>
                        <MoveForm item={appKey(a.name)} current={p.key} projects={projects} csrf={csrf} />
                      </td>
                      <td class="end">
                        <a class="btn small" href={`/apps/${a.name}`}>
                          {t("Manage")}
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {p.sites.length ? (
        <section class="card table-card">
          <div class="card-head">
            <h2>{t("Sites")}</h2>
          </div>
          <div class="table-scroll">
            <table class="list">
              <thead>
                <tr>
                  <th>{t("Site")}</th>
                  <th>{t("Type")}</th>
                  <th>{t("Goes to")}</th>
                  <th class="num">{t("Certificate")}</th>
                  <th>{t("Project")}</th>
                  <th class="end">
                    <span class="sr-only">{t("Actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {p.sites.map((s) => {
                  const c = cm.get(s.name);
                  const days = c?.notAfter ? Math.floor((c.notAfter - now) / DAY) : null;
                  return (
                    <tr class={s.enabled ? "" : "off"}>
                      <td>
                        <span class={`led ${s.enabled ? "up" : "suspended"}`} title={s.enabled ? t("enabled") : t("suspended")} />
                        <a href={`/sites/${s.name}`}>{s.name}</a>
                      </td>
                      <td>
                        <span class={`kind ${s.kind}`}>{siteKind(s)}</span>
                      </td>
                      <td class="muted small">{s.routes.length ? s.routes.map(routeLabel).join(", ") : "—"}</td>
                      <td class={`num ${days === null ? "" : days < 7 ? "crit" : days < 14 ? "warn" : ""}`}>
                        {c?.error ? <span class="crit">{t("unreadable")}</span> : days === null ? <span class="muted">{t("edge")}</span> : days < 0 ? t("expired") : t("{n} days").replace("{n}", String(days))}
                      </td>
                      <td>
                        <MoveForm item={siteKey(s.name)} current={p.key} projects={projects} csrf={csrf} />
                      </td>
                      <td class="end">
                        <a class="btn small" href={`/sites/${s.name}`}>
                          {t("Manage")}
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
      <p class="muted small">{t("Apps and sites are grouped by where traffic goes; move one if it belongs elsewhere.")}</p>
    </div>
  );
}
