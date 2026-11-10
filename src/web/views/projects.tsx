// One place for everything that serves a product: its domains, the apps behind them and the
// sites (PHP, static, proxy). Each app and site keeps its own detail page for deeper work.

import { fmtBytes, t } from "../i18n.ts";
import { appKey, projectSlug, siteKey, type Project } from "../projects.ts";
import { Ago, appState, parseSince, portOf, runtimeOf, type AppRow, type CertRow, type SiteRow } from "./dashboard.tsx";
import { Icon } from "./icons.tsx";
import { Csrf } from "./layout.tsx";

export type ProjAppRow = AppRow & { port_a?: number; port_b?: number; processes?: { name: string; routes: string[]; port_a: number; port_b: number }[] };
export type ProjSiteRow = SiteRow & { routes: { path: string; upstream: string }[] };
export type Proj = Project<ProjAppRow, ProjSiteRow>;

const DAY = 86400;

/** "ok" when every app runs and every enabled site has a valid certificate; else the worst thing in it. */
export function projectState(p: Proj, certs: Map<string, CertRow>, now: number): "up" | "warn" | "down" | "idle" {
  if (p.apps.some((a) => appState(a) === "down")) return "down";
  const certDays = p.sites.filter((s) => s.enabled).map((s) => certs.get(s.name)).filter((c): c is CertRow => !!c?.notAfter).map((c) => Math.floor((c.notAfter! - now) / DAY));
  if (certDays.some((d) => d < 7)) return "down";
  if (p.apps.some((a) => appState(a) === "unknown") || certDays.some((d) => d < 14)) return "warn";
  if (!p.apps.length && !p.sites.some((s) => s.enabled)) return "idle";
  return "up";
}

const siteKind = (s: ProjSiteRow) => (s.kind === "legacy" ? (s.source === "cyberpanel" ? "OpenLiteSpeed" : t("legacy")) : s.kind === "php" ? "PHP" : s.kind);

function Domains({ list, max = 4 }: { list: string[]; max?: number }) {
  if (!list.length) return <span class="muted">—</span>;
  const shown = list.slice(0, max);
  return (
    <span class="domains">
      {shown.map((d) => (
        <code>{d === "*" ? t("any domain") : d}</code>
      ))}
      {list.length > max ? <span class="muted small">+{list.length - max}</span> : null}
    </span>
  );
}

function NewButtons() {
  return (
    <div class="row">
      <a class="btn" href="/git">
        <Icon name="git" size={16} /> Git
      </a>
      <a class="btn" href="/sites/new-php">
        <Icon name="sites" size={16} /> {t("PHP site")}
      </a>
      <a class="btn" href="/sites/new">
        <Icon name="edge" size={16} /> {t("Proxy or static site")}
      </a>
      <a class="btn primary" href="/apps/new">
        <Icon name="plus" size={16} /> {t("New app")}
      </a>
    </div>
  );
}

export function ProjectsPage({ projects, certs, now }: { projects: Proj[]; certs: CertRow[]; now: number }) {
  const cm = new Map(certs.map((c) => [c.site, c]));
  return (
    <div class="stack">
      <div class="page-actions">
        <p class="muted">{t("Each project gathers its domains, the apps that serve them and its sites. Open one to manage it.")}</p>
        <NewButtons />
      </div>
      {projects.length ? (
        <div class="projects">
          {projects.map((p) => {
            const st = projectState(p, cm, now);
            const up = p.apps.filter((a) => appState(a) === "up").length;
            const mem = p.apps.reduce((n, a) => n + (a.status.memory || 0), 0);
            return (
              <a class={`project ${st}`} href={`/projects/${projectSlug(p.key)}`}>
                <div class="project-head">
                  <span class={`led ${st}`} aria-hidden="true" />
                  <h2>{p.name}</h2>
                  <span class="muted small project-meta">
                    {p.apps.length ? t("{up}/{all} apps").replace("{up}", String(up)).replace("{all}", String(p.apps.length)) : ""}
                    {p.apps.length && p.sites.length ? ", " : ""}
                    {p.sites.length ? t("{n} sites").replace("{n}", String(p.sites.length)) : ""}
                  </span>
                </div>
                <Domains list={p.domains} />
                {p.apps.length ? (
                  <div class="chips">
                    {p.apps.map((a) => (
                      <span class="chip">
                        <span class={`led ${appState(a)}`} />
                        {a.name}
                      </span>
                    ))}
                  </div>
                ) : null}
                {p.sites.length && !p.apps.length ? (
                  <div class="chips">
                    {p.sites.map((s) => (
                      <span class="chip">
                        <span class={`led ${s.enabled ? "up" : "idle"}`} />
                        {siteKind(s)}
                      </span>
                    ))}
                  </div>
                ) : null}
                {mem ? <small class="muted">{t("Memory")}: {fmtBytes(mem)}</small> : null}
              </a>
            );
          })}
        </div>
      ) : (
        <section class="panel empty">
          <p>{t("No projects yet. Import what already runs on this server, or start a new app or site.")}</p>
          <div class="row">
            <a class="btn primary" href="/import">
              {t("Import from this server")}
            </a>
            <a class="btn" href="/apps/new">
              {t("New app")}
            </a>
          </div>
        </section>
      )}
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

export function ProjectDetail({ p, projects, certs, now, csrf }: { p: Proj; projects: Proj[]; certs: CertRow[]; now: number; csrf: string }) {
  const cm = new Map(certs.map((c) => [c.site, c]));
  return (
    <div class="stack">
      <section class="panel">
        <header class="panel-head">
          <h2 class="with-icon">
            <Icon name="sites" /> {t("Domains")}
          </h2>
        </header>
        <Domains list={p.domains} max={40} />
      </section>

      {p.apps.length ? (
        <section class="panel">
          <header class="panel-head">
            <h2 class="with-icon">
              <Icon name="apps" /> {t("Apps")}
            </h2>
          </header>
          <table class="rack">
            <thead>
              <tr>
                <th>{t("Name")}</th>
                <th>{t("Runs on")}</th>
                <th class="num">{t("Port")}</th>
                <th class="num">{t("Memory")}</th>
                <th class="num">{t("Up for")}</th>
                <th>{t("Project")}</th>
              </tr>
            </thead>
            <tbody>
              {p.apps.map((a) => {
                const s = appState(a);
                return (
                  <tr class={s}>
                    <td>
                      <span class={`led ${s}`} title={a.status.active} />
                      <a href={`/apps/${a.name}`}>{a.name}</a>
                    </td>
                    <td class="muted">{runtimeOf(a)}</td>
                    <td class="num muted">{portOf(a)}</td>
                    <td class="num">{a.status.memory ? fmtBytes(a.status.memory) : "—"}</td>
                    <td class="num">{s === "up" ? <Ago at={parseSince(a.status.since)} now={now} /> : <span class="state">{a.status.active}</span>}</td>
                    <td>
                      <MoveForm item={appKey(a.name)} current={p.key} projects={projects} csrf={csrf} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      ) : null}

      {p.sites.length ? (
        <section class="panel">
          <header class="panel-head">
            <h2 class="with-icon">
              <Icon name="sites" /> {t("Sites")}
            </h2>
          </header>
          <table class="rack">
            <thead>
              <tr>
                <th>{t("Site")}</th>
                <th>{t("Type")}</th>
                <th>{t("Goes to")}</th>
                <th class="num">{t("Certificate")}</th>
                <th>{t("Project")}</th>
              </tr>
            </thead>
            <tbody>
              {p.sites.map((s) => {
                const c = cm.get(s.name);
                const days = c?.notAfter ? Math.floor((c.notAfter - now) / DAY) : null;
                return (
                  <tr class={s.enabled ? "" : "off"}>
                    <td>
                      <span class={`led ${s.enabled ? "up" : "idle"}`} title={s.enabled ? t("enabled") : t("suspended")} />
                      <a href={`/sites/${s.name}`}>{s.name}</a>
                    </td>
                    <td>
                      <span class={`kind ${s.kind}`}>{siteKind(s)}</span>
                    </td>
                    <td class="muted small">{s.routes.length ? s.routes.map((r) => `${r.path} → ${r.upstream}`).join(", ") : "—"}</td>
                    <td class={`num ${days === null ? "" : days < 7 ? "crit" : days < 14 ? "warn" : ""}`}>
                      {c?.error ? <span class="crit">{t("unreadable")}</span> : days === null ? <span class="muted">{t("edge")}</span> : days < 0 ? t("expired") : t("{n} days").replace("{n}", String(days))}
                    </td>
                    <td>
                      <MoveForm item={siteKey(s.name)} current={p.key} projects={projects} csrf={csrf} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      ) : null}
      <p class="muted small">{t("Apps and sites are grouped by where traffic goes; move one if it belongs elsewhere.")}</p>
    </div>
  );
}
