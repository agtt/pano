// The home page answers one question first: is anything wrong? A status line with the things
// that need you, then the live gauges, apps, sites and the rest of the server, then history.

import { fmtBytes, fmtDuration, fmtTime, t } from "../i18n.ts";
import { ServerCharts, type History, type Point } from "./charts.tsx";
import type { ServerInfo } from "./home.tsx";

type AppRow = {
  name: string;
  kind: string;
  external_unit: string;
  upstream: string;
  domains: string[];
  runtime?: string;
  runtime_version?: string;
  status: { active: string; memory: number; since: string };
};
type SiteRow = { name: string; kind: string; domains: string[]; enabled: number; tls_cert: string; source: string };
type CertRow = { site: string; notAfter?: number; issuer?: string; error?: string };
type BackupJob = { id: number; name: string; enabled: number; last_run_at: number | null; last_status: string };
type VulnInfo = { rebootNeeded: boolean; last: { at: number; findings: { severity: string }[] } | null } | null;
type AuditRow = { id: number; at: number; actor: string; action: string };

export type DashData = {
  info: ServerInfo;
  history: History | null;
  apps: AppRow[];
  sites: SiteRow[];
  certs: CertRow[];
  backups: BackupJob[];
  vulns: VulnInfo;
  activity: AuditRow[];
  now: number;
};

type Level = "crit" | "warn" | "info";
type Notice = { level: Level; text: string; href: string };

const DAY = 86400;
const pct = (used: number, total: number) => (total > 0 ? Math.round((used / total) * 100) : 0);
const lastOf = (pts: Point[] | undefined) => pts?.[pts.length - 1]?.[1];

/** systemd ("Tue 2026-11-10 19:12:03 UTC") or ISO start time → seconds since epoch. */
export function parseSince(since: string): number {
  if (!since) return 0;
  const iso = Date.parse(since);
  if (Number.isFinite(iso)) return Math.floor(iso / 1000);
  const m = since.match(/(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?: (UTC|GMT))?/);
  const ms = m ? Date.parse(`${m[1]}T${m[2]}Z`) : NaN;
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0;
}

const appState = (a: AppRow) => (a.status.active === "active" ? "up" : a.status.active === "unknown" ? "unknown" : a.status.active === "not deployed" ? "idle" : "down");
const runtimeOf = (a: AppRow) => (a.kind === "managed" ? `${a.runtime ?? ""} ${a.runtime_version ?? ""}`.trim() : a.external_unit.startsWith("pm2:") ? "PM2" : a.external_unit ? "systemd" : t("external"));
const portOf = (a: AppRow) => a.upstream.split(",")[0]?.split(":").at(-1) ?? "";

/** Everything that wants a decision, worst first. */
export function notices(d: DashData): Notice[] {
  const out: Notice[] = [];
  for (const a of d.apps) {
    const s = appState(a);
    if (s === "down") out.push({ level: "crit", text: t("{app} is not running ({state}).").replace("{app}", a.name).replace("{state}", a.status.active), href: `/apps/${a.name}` });
    else if (s === "unknown") out.push({ level: "warn", text: t("{app}: status unknown.").replace("{app}", a.name), href: `/apps/${a.name}` });
  }
  for (const c of d.certs) {
    if (c.error) {
      out.push({ level: "warn", text: t("{site}: certificate unreadable ({error}).").replace("{site}", c.site).replace("{error}", c.error), href: `/sites/${c.site}` });
      continue;
    }
    const days = Math.floor(((c.notAfter ?? 0) - d.now) / DAY);
    if (days < 0) out.push({ level: "crit", text: t("{site}: certificate expired.").replace("{site}", c.site), href: `/sites/${c.site}` });
    else if (days < 14) out.push({ level: days < 7 ? "crit" : "warn", text: t("{site}: certificate expires in {n} days.").replace("{site}", c.site).replace("{n}", String(days)), href: `/sites/${c.site}` });
  }
  const mem = pct(d.info.memory.total - d.info.memory.available, d.info.memory.total);
  const disk = pct(d.info.disk.used, d.info.disk.size);
  if (disk >= 85) out.push({ level: disk >= 95 ? "crit" : "warn", text: t("Disk is {n}% full.").replace("{n}", String(disk)), href: "/" });
  if (mem >= 90) out.push({ level: "warn", text: t("Memory is {n}% used.").replace("{n}", String(mem)), href: "/" });
  for (const s of d.info.services) if (s.state === "failed") out.push({ level: "crit", text: t("Service {unit} failed.").replace("{unit}", s.unit), href: "/services" });
  const jobs = d.backups.filter((j) => j.enabled);
  if (!jobs.length) out.push({ level: "warn", text: t("No backups are set up."), href: "/backups" });
  for (const j of jobs) {
    if (j.last_status && !/^(ok|success|done|running)$/.test(j.last_status)) out.push({ level: "crit", text: t("Backup {job} failed last time.").replace("{job}", j.name), href: "/backups" });
    else if (j.last_run_at && d.now - j.last_run_at > 2 * DAY) out.push({ level: "warn", text: t("Backup {job} has not run for {n} days.").replace("{job}", j.name).replace("{n}", String(Math.floor((d.now - j.last_run_at) / DAY))), href: "/backups" });
  }
  const serious = d.vulns?.last?.findings.filter((f) => f.severity === "critical" || f.severity === "high").length ?? 0;
  if (serious) out.push({ level: "warn", text: t("{n} serious vulnerabilities found.").replace("{n}", String(serious)), href: "/security" });
  if (d.vulns?.rebootNeeded) out.push({ level: "info", text: t("An update needs a reboot when traffic is low."), href: "/security" });
  if (!d.info.edge.cutover) out.push({ level: "info", text: t("The old web server still serves :80/:443. Move over from Edge when ready."), href: "/edge" });
  const rank: Record<Level, number> = { crit: 0, warn: 1, info: 2 };
  return out.sort((a, b) => rank[a.level] - rank[b.level]);
}

function Gauge(p: { label: string; value: number; display: string; detail: string }) {
  const r = 30;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(100, p.value));
  const level = v >= 90 ? "crit" : v >= 75 ? "warn" : "ok";
  return (
    <figure class={`gauge ${level}`}>
      <svg viewBox="0 0 72 72" role="img" aria-label={`${p.label}: ${p.display}`}>
        <circle class="gauge-track" cx="36" cy="36" r={r} />
        <circle class="gauge-fill" cx="36" cy="36" r={r} stroke-dasharray={`${((v / 100) * c).toFixed(1)} ${c.toFixed(1)}`} transform="rotate(-90 36 36)" />
      </svg>
      <figcaption>
        <strong>{p.display}</strong>
        <span>{p.label}</span>
        <small>{p.detail}</small>
      </figcaption>
    </figure>
  );
}

const rate = (n: number | undefined) => (n === undefined ? "—" : `${fmtBytes(n)}/s`);

function Ago({ at, now }: { at: number; now: number }) {
  if (!at) return <span class="muted">—</span>;
  return <span title={fmtTime(at)}>{fmtDuration(Math.max(0, now - at))}</span>;
}

function Status({ d }: { d: DashData }) {
  const list = notices(d);
  const crit = list.filter((n) => n.level === "crit").length;
  const warn = list.filter((n) => n.level === "warn").length;
  const level = crit ? "crit" : warn ? "warn" : "ok";
  const headline = crit
    ? (crit === 1 ? t("1 problem needs you now") : t("{n} problems need you now").replace("{n}", String(crit)))
    : warn
      ? (warn === 1 ? t("Running, 1 thing to check") : t("Running, {n} things to check").replace("{n}", String(warn)))
      : t("Everything is running");
  const up = d.apps.filter((a) => appState(a) === "up").length;
  return (
    <section class={`status ${level}`}>
      <div class="status-line">
        <span class={`led ${level === "ok" ? "up" : level === "crit" ? "down" : "warn"}`} aria-hidden="true" />
        <h2>{headline}</h2>
        <p class="status-meta">
          <span>{t("{up} of {all} apps up").replace("{up}", String(up)).replace("{all}", String(d.apps.length))}</span>
          <span>{t("{n} sites").replace("{n}", String(d.sites.length))}</span>
          <span>
            {d.info.hostname}, {t("up for {t}").replace("{t}", fmtDuration(d.info.uptime))}
          </span>
        </p>
      </div>
      {list.length ? (
        <ul class="notices">
          {list.map((n) => (
            <li class={n.level}>
              <a href={n.href}>{n.text}</a>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

function Gauges({ d }: { d: DashData }) {
  const s = d.history?.series ?? {};
  const cpu = lastOf(s.cpu);
  const memUsed = d.info.memory.total - d.info.memory.available;
  const load = d.info.load[0] ?? 0;
  return (
    <section class="gauges" aria-label={t("Server health")}>
      <Gauge label="CPU" value={cpu ?? (load / Math.max(1, d.info.cpus)) * 100} display={cpu === undefined ? "—" : `${Math.round(cpu)}%`} detail={t("{n} cores").replace("{n}", String(d.info.cpus))} />
      <Gauge label={t("Memory")} value={pct(memUsed, d.info.memory.total)} display={`${pct(memUsed, d.info.memory.total)}%`} detail={`${fmtBytes(memUsed)} / ${fmtBytes(d.info.memory.total)}`} />
      <Gauge label={t("Disk")} value={pct(d.info.disk.used, d.info.disk.size)} display={`${pct(d.info.disk.used, d.info.disk.size)}%`} detail={`${fmtBytes(d.info.disk.avail)} ${t("free")}`} />
      <Gauge label={t("Load")} value={(load / Math.max(1, d.info.cpus)) * 100} display={load.toFixed(2)} detail={d.info.load.map((l) => l.toFixed(2)).join(" / ")} />
      <div class="netbox">
        <span class="muted">{t("Network")}</span>
        <p>
          <span class="arrow" aria-label={t("in")}>↓</span> <strong>{rate(lastOf(s.rx))}</strong>
        </p>
        <p>
          <span class="arrow" aria-label={t("out")}>↑</span> <strong>{rate(lastOf(s.tx))}</strong>
        </p>
        <small class="muted">{d.info.os}</small>
      </div>
    </section>
  );
}

function Apps({ d }: { d: DashData }) {
  return (
    <section class="panel">
      <header class="panel-head">
        <h2>{t("Apps")}</h2>
        <a class="btn small" href="/apps">
          {t("All apps")}
        </a>
      </header>
      {d.apps.length ? (
        <table class="rack">
          <thead>
            <tr>
              <th>{t("Name")}</th>
              <th>{t("Runs on")}</th>
              <th class="num">{t("Port")}</th>
              <th class="num">{t("Memory")}</th>
              <th class="num">{t("Up for")}</th>
            </tr>
          </thead>
          <tbody>
            {d.apps.map((a) => {
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
                  <td class="num">{s === "up" ? <Ago at={parseSince(a.status.since)} now={d.now} /> : <span class="state">{a.status.active}</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : (
        <div class="empty">
          <p>{t("No apps yet. Import the ones already running on this server, or deploy one from git.")}</p>
          <div class="row">
            <a class="btn primary" href="/import">
              {t("Import from this server")}
            </a>
            <a class="btn" href="/apps/new">
              {t("New app")}
            </a>
          </div>
        </div>
      )}
    </section>
  );
}

function Sites({ d }: { d: DashData }) {
  const certs = new Map(d.certs.map((c) => [c.site, c]));
  return (
    <section class="panel">
      <header class="panel-head">
        <h2>{t("Sites")}</h2>
        <a class="btn small" href="/sites">
          {t("All sites")}
        </a>
      </header>
      {d.sites.length ? (
        <table class="rack">
          <thead>
            <tr>
              <th>{t("Site")}</th>
              <th>{t("Type")}</th>
              <th class="num">{t("Certificate")}</th>
            </tr>
          </thead>
          <tbody>
            {d.sites.map((s) => {
              const c = certs.get(s.name);
              const days = c?.notAfter ? Math.floor((c.notAfter - d.now) / DAY) : null;
              const cls = days === null ? "" : days < 7 ? "crit" : days < 14 ? "warn" : "";
              return (
                <tr class={s.enabled ? "" : "off"}>
                  <td>
                    <span class={`led ${s.enabled ? "up" : "idle"}`} title={s.enabled ? t("enabled") : t("suspended")} />
                    <a href={`/sites/${s.name}`}>{s.name}</a>
                    {s.domains.length > 1 ? <small class="muted extra">+{s.domains.length - 1}</small> : null}
                  </td>
                  <td>
                    <span class={`kind ${s.kind}`}>{s.kind === "legacy" ? (s.source === "cyberpanel" ? "OpenLiteSpeed" : t("legacy")) : s.kind}</span>
                  </td>
                  <td class={`num ${cls}`}>
                    {c?.error ? <span class="crit">{t("unreadable")}</span> : days === null ? <span class="muted">{t("edge")}</span> : t("{n} days").replace("{n}", String(days))}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : (
        <div class="empty">
          <p>{t("No sites yet. Import the ones OpenLiteSpeed serves today; nothing changes for visitors.")}</p>
          <a class="btn primary" href="/import">
            {t("Import from this server")}
          </a>
        </div>
      )}
    </section>
  );
}

function Side({ d }: { d: DashData }) {
  const lastBackup = Math.max(0, ...d.backups.map((j) => j.last_run_at ?? 0));
  return (
    <div class="side-col">
      <section class="panel">
        <header class="panel-head">
          <h2>{t("Services")}</h2>
          <a class="btn small" href="/services">
            {t("Manage")}
          </a>
        </header>
        <ul class="svc">
          {d.info.services.map((s) => (
            <li>
              <span class={`led ${s.state === "active" ? "up" : s.state === "failed" ? "down" : "idle"}`} />
              <span class="svc-name">{s.unit}</span>
              <span class="muted">{s.memory ? fmtBytes(s.memory) : ""}</span>
            </li>
          ))}
        </ul>
      </section>
      <section class="panel">
        <header class="panel-head">
          <h2>{t("Protection")}</h2>
        </header>
        <dl class="facts">
          <dt>{t("Edge")}</dt>
          <dd>{d.info.edge.cutover ? t("Caddy serves the sites") : d.info.edge.active ? t("Caddy ready, not switched") : t("Not installed")}</dd>
          <dt>{t("Backups")}</dt>
          <dd>{d.backups.length ? (lastBackup ? t("last {t} ago").replace("{t}", fmtDuration(Math.max(0, d.now - lastBackup))) : t("never ran")) : t("not set up")}</dd>
          <dt>{t("Vulnerabilities")}</dt>
          <dd>{d.vulns?.last ? t("{n} found, scanned {t} ago").replace("{n}", String(d.vulns.last.findings.length)).replace("{t}", fmtDuration(Math.max(0, d.now - d.vulns.last.at))) : t("not scanned yet")}</dd>
        </dl>
      </section>
      <section class="panel">
        <header class="panel-head">
          <h2>{t("Activity")}</h2>
          <a class="btn small" href="/activity">
            {t("All")}
          </a>
        </header>
        {d.activity.length ? (
          <ol class="feed">
            {d.activity.slice(0, 6).map((e) => (
              <li>
                <span>{e.action}</span>
                <small class="muted">
                  {e.actor}, <Ago at={e.at} now={d.now} />
                </small>
              </li>
            ))}
          </ol>
        ) : (
          <p class="muted">{t("Nothing yet.")}</p>
        )}
      </section>
    </div>
  );
}

export function Dashboard({ d }: { d: DashData }) {
  return (
    <div class="dash">
      <Status d={d} />
      <Gauges d={d} />
      <div class="dash-grid">
        <div class="main-col">
          <Apps d={d} />
          <Sites d={d} />
        </div>
        <Side d={d} />
      </div>
      {d.history ? <ServerCharts h={d.history} base="/" /> : null}
    </div>
  );
}
