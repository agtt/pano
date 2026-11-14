// Databases: one table for MariaDB and PostgreSQL, a status strip for the servers, creation behind a
// button, and everything per database (users, password, backup, delete) on its own page.

import { fmtTime, t } from "../i18n.ts";
import type { JobRow } from "./pages.tsx";
import { Badge, Card, Csrf, DangerForm, Field, TabPanes, alwaysAttr } from "./layout.tsx";
import { RemoteCard, type PgDb, type RemoteView, type ServiceRow } from "./services.tsx";

export type MariaData = { databases: { name: string; sizeMb: number; tables: number; users: string[]; system: boolean }[]; users: { user: string; host: string }[] };
export type Engine = "mariadb" | "postgres";

const Otp = (p: { always?: boolean }) => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" autocomplete="one-time-code" {...alwaysAttr(p.always)} />;

type Row = { engine: Engine; name: string; sizeMb: number; users: string[]; tables?: number; system: boolean };
const ENGINE_LABEL: Record<Engine, string> = { mariadb: "MariaDB", postgres: "PostgreSQL" };

export const rowsOf = (maria: MariaData, pg: PgDb[]): Row[] => [
  ...maria.databases.map((d): Row => ({ engine: "mariadb", name: d.name, sizeMb: d.sizeMb, users: d.users, tables: d.tables, system: d.system })),
  ...pg.map((d): Row => ({ engine: "postgres", name: d.name, sizeMb: d.sizeMb, users: d.owner ? [d.owner] : [], system: d.system })),
];

export const dbHref = (engine: Engine, name: string) => `/databases/${engine}/${encodeURIComponent(name)}`;
const remoteOf = (engine: Engine, my?: RemoteView, pg?: RemoteView) => (engine === "mariadb" ? my : pg);
/** "On" for a database that has a remote user while remote access is switched on for its engine. */
const remoteOn = (r: Row, my?: RemoteView, pg?: RemoteView) => {
  const v = remoteOf(r.engine, my, pg);
  return !!v?.on && v.users.some((u) => u.database === r.name);
};

/** One line per server: version and state, or a way to install it. */
export function ServiceStrip({ list }: { list: ServiceRow[] }) {
  if (!list.length) return null;
  return (
    <section class="svc-strip" aria-label={t("Database servers")}>
      {list.map((s) => (
        <a class="chip" href="/services" title={s.installed ? s.active : t("Install it from Server > Services")}>
          <span class={`led ${s.installed ? (s.active === "active" ? "up" : "down") : "idle"}`} aria-hidden="true" />
          {s.label} {s.installed ? s.version : t("not installed")}
        </a>
      ))}
    </section>
  );
}

export function DatabasesPage(p: {
  csrf: string;
  data: MariaData;
  pg?: PgDb[];
  services?: ServiceRow[];
  myRemote?: RemoteView;
  pgRemote?: RemoteView;
  created?: { name: string; user: string; password: string };
  error?: string;
}) {
  const all = rowsOf(p.data, p.pg ?? []);
  const rows = all.filter((r) => !r.system);
  const hidden = all.length - rows.length;
  const pgInstalled = !!p.services?.find((s) => s.key === "postgres")?.installed || (p.pg?.length ?? 0) > 0;
  const newDb = (
    <details class="more new-db">
      <summary class="btn primary">{t("New database")}</summary>
      <div class="cols">
        <Card title="MariaDB">
          <form method="post" action="/databases/create">
            <Csrf token={p.csrf} />
            <Field label="Name" name="name" required placeholder="app_db" />
            <Field label="User (optional)" name="user" placeholder="app_user" />
            <Field label="Password (empty = generate)" name="password" type="password" autocomplete="new-password" />
            <button class="btn primary">{t("Create")}</button>
          </form>
        </Card>
        {pgInstalled ? (
          <Card title="PostgreSQL">
            <form method="post" action="/services/postgres/create">
              <Csrf token={p.csrf} />
              <Field label="Name" name="name" required placeholder="app_db" />
              <Field label="User (empty = same as name)" name="user" placeholder="app_user" />
              <button class="btn primary">{t("Create")}</button>
            </form>
          </Card>
        ) : null}
      </div>
    </details>
  );
  const table = rows.length ? (
    <section class="card table-card">
      <table>
        <thead>
          <tr>
            <th>{t("Name")}</th>
            <th>{t("Engine")}</th>
            <th class="num">{t("Size")}</th>
            <th>{t("Users")}</th>
            <th>{t("Remote access")}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr>
              <td>
                <a href={dbHref(r.engine, r.name)}>
                  <strong>{r.name}</strong>
                </a>
              </td>
              <td>
                <span class="kind">{ENGINE_LABEL[r.engine]}</span>
              </td>
              <td class="num">{r.sizeMb} MB</td>
              <td class="small" title={r.users.join(", ")}>
                {r.users.length}
              </td>
              <td>{remoteOn(r, p.myRemote, p.pgRemote) ? <span class="badge good">{t("On")}</span> : <span class="badge neutral">{t("Off")}</span>}</td>
              <td>
                <a class="btn small" href={dbHref(r.engine, r.name)}>
                  {t("Manage")}
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {hidden ? <p class="muted small">{t("{n} system databases are hidden.").replace("{n}", String(hidden))}</p> : null}
    </section>
  ) : (
    <section class="card empty-state">
      <h2>{t("No databases yet")}</h2>
      <p class="muted">{t("Create one here, or add one to an app from its Database tab.")}</p>
    </section>
  );
  const remote = (
    <div class="stack">
      <p class="muted small">{t("Only for apps that run somewhere else (Vercel, Netlify and the like). Apps on this server talk to their database locally and need none of this.")}</p>
      {[
        { v: p.myRemote, installed: !!p.services?.find((s) => s.key === "mariadb")?.installed, dbs: p.data.databases.filter((d) => !d.system).map((d) => d.name), label: "MariaDB" },
        { v: p.pgRemote, installed: pgInstalled, dbs: (p.pg ?? []).filter((d) => !d.system).map((d) => d.name), label: "PostgreSQL" },
      ].map((x) =>
        x.installed && x.v?.available ? (
          <Card title={x.label} actions={<span class={`badge ${x.v.on ? "good" : "neutral"}`}>{x.v.on ? t("On") : t("Off")}</span>}>
            <details class="more">
              <summary>{x.v.on ? t("Change remote access") : t("Turn on remote access")}</summary>
              <RemoteCard v={x.v} dbs={x.dbs} csrf={p.csrf} />
            </details>
          </Card>
        ) : null,
      )}
    </div>
  );
  return (
    <div class="stack">
      {p.created?.user ? (
        <div class="flash ok">
          {p.created.name}: <code>{p.created.user}</code> / <code class="secret">{p.created.password}</code> — shown once, store it now.
        </div>
      ) : null}
      {p.error ? <div class="flash err">{p.error}</div> : null}
      {p.services ? <ServiceStrip list={p.services} /> : null}
      {newDb}
      <TabPanes
        panes={[
          { key: "databases", label: t("Databases"), body: table },
          { key: "remote", label: t("Remote access"), body: remote },
        ]}
        label={t("Databases")}
      />
    </div>
  );
}

/** One database: facts, users, password, backup, remote access and delete. */
export function DatabaseDetail(p: {
  csrf: string;
  engine: Engine;
  name: string;
  row: Row;
  mariaUsers: { user: string; host: string }[];
  job?: JobRow;
  remote?: RemoteView;
}) {
  const { row, engine } = p;
  const kind = engine === "mariadb" ? "mysql" : "postgres";
  const remoteUsers = p.remote?.on ? p.remote.users.filter((u) => u.database === p.name) : [];
  const grantable = p.mariaUsers.filter((u) => u.user !== "root" && !u.user.startsWith("mariadb.") && u.user !== "mysql");
  return (
    <div class="stack">
      <section class="summary" aria-label={t("Summary")}>
        <div class="summary-card">
          <span class="summary-label">{t("Engine")}</span>
          <strong class="summary-value">{ENGINE_LABEL[engine]}</strong>
        </div>
        <div class="summary-card">
          <span class="summary-label">{t("Size")}</span>
          <strong class="summary-value">{row.sizeMb} MB</strong>
          {row.tables !== undefined ? <small class="muted">{row.tables} {t("Tables")}</small> : null}
        </div>
        <div class="summary-card">
          <span class="summary-label">{t("Users")}</span>
          <strong class="summary-value">{row.users.length}</strong>
        </div>
        <div class="summary-card">
          <span class="summary-label">{t("Remote access")}</span>
          <strong class="summary-value">{remoteUsers.length ? t("On") : t("Off")}</strong>
        </div>
      </section>
      <div class="cols">
        <Card title={t("Users")}>
          {row.users.length ? (
            <ul class="svc">
              {row.users.map((u) => (
                <li>
                  <code>{u}</code>
                </li>
              ))}
            </ul>
          ) : (
            <p class="muted">{t("No user has access yet.")}</p>
          )}
          {remoteUsers.length ? (
            <p class="muted small">
              {t("Remote users")}: {remoteUsers.map((u) => u.user).join(", ")}
            </p>
          ) : null}
          {engine === "mariadb" && grantable.length ? (
            <details class="more">
              <summary>{t("Reset password")}</summary>
              <form method="post" action="/databases/password">
                <Csrf token={p.csrf} />
                <label class="field">
                  <span>{t("Users")}</span>
                  <select name="userhost">
                    {grantable.map((u) => (
                      <option value={`${u.user}@${u.host}`}>{`${u.user}@${u.host}`}</option>
                    ))}
                  </select>
                </label>
                <Field label="Password (empty = generate)" name="password" type="password" autocomplete="new-password" />
                <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required always />
                <button class="btn">{t("Reset password")}</button>
              </form>
            </details>
          ) : null}
        </Card>
        <Card title={t("Backup")}>
          {p.job ? (
            <>
              <p>
                {p.job.schedule} · {t("Keep")} {p.job.keep} · {p.job.last_status ? <Badge state={p.job.last_status} /> : <span class="muted">{t("Never")}</span>}{" "}
                <span class="muted small">{p.job.last_run_at ? fmtTime(p.job.last_run_at) : ""}</span>
              </p>
              <div class="row">
                <form method="post" action={`/backups/jobs/${p.job.id}/run`}>
                  <Csrf token={p.csrf} />
                  <button class="btn primary">{t("Back up now")}</button>
                </form>
                <a href="/backups#tab-jobs">{t("Runs and restore")}</a>
              </div>
            </>
          ) : (
            <form method="post" action="/backups/jobs" class="stack-sm">
              <Csrf token={p.csrf} />
              <input type="hidden" name="kind" value={kind} />
              <input type="hidden" name="target" value={p.name} />
              <input type="hidden" name="schedule" value="daily 03:30" />
              <input type="hidden" name="keep" value="30" />
              <p class="muted small">{t("Not backed up yet. This adds a daily backup, kept 30 days.")}</p>
              <div class="row">
                <Otp />
                <button class="btn primary">{t("Back up daily")}</button>
              </div>
            </form>
          )}
        </Card>
      </div>
      <details class="more danger-zone">
        <summary>{t("Delete this database")}</summary>
        <DangerForm
          action={engine === "mariadb" ? "/databases/drop" : "/services/postgres/drop"}
          csrf={p.csrf}
          name={p.name}
          label={t("Delete")}
          extra={<input type="hidden" name="name" value={p.name} />}
        />
      </details>
    </div>
  );
}
