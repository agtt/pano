import { fmtBytes, t } from "../i18n.ts";
import { Badge, Card, Csrf, DangerForm, Field } from "./layout.tsx";
import { RealtimeCard, type RealtimeView } from "./realtime.tsx";
import { TurnCard, type TurnView } from "./turn.tsx";

export type ServiceRow = {
  key: "mariadb" | "postgres" | "valkey";
  label: string;
  port: number;
  note: string;
  installed: boolean;
  version: string;
  managed: boolean;
  active: string;
  memory: number;
  enabled: boolean;
};
export type PgDb = { name: string; sizeMb: number; owner: string; system: boolean };
type Secret = { title: string; lines: [string, string][] };

export function ServicesPage(p: { csrf: string; list: ServiceRow[]; pg: PgDb[]; secret?: Secret; realtime?: RealtimeView; turn?: TurnView; appNames?: string[] }) {
  const pg = p.list.find((s) => s.key === "postgres");
  return (
    <div class="stack">
      {p.secret ? (
        <Card title={p.secret.title}>
          <p class="flash ok">Shown once, store it now (for example in the app's environment variables).</p>
          <dl class="kv">
            {p.secret.lines.map(([k, val]) => (
              <>
                <dt>{k}</dt>
                <dd>
                  <code class="secret" data-copy>
                    {val}
                  </code>
                </dd>
              </>
            ))}
          </dl>
        </Card>
      ) : null}
      <Card title={t("Services")}>
        <p class="muted small">
          Installed only when you ask; nothing runs or uses memory before that. Native packages (no containers), listening on 127.0.0.1 only, with small memory
          settings and a password. For one isolated instance per app, use a container template instead.
        </p>
        <table>
          <thead>
            <tr>
              <th>{t("Name")}</th>
              <th>{t("Version")}</th>
              <th>{t("Status")}</th>
              <th class="num">{t("Memory")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {p.list.map((s) => (
              <tr>
                <td>
                  <b>{s.label}</b>
                  <div class="muted small">
                    127.0.0.1:{s.port} · {s.note}
                    {s.installed && !s.managed ? " · already on the server, used as is" : ""}
                  </div>
                </td>
                <td>{s.version || "—"}</td>
                <td>{s.installed ? <Badge state={s.active} /> : <span class="muted">not installed</span>}</td>
                <td class="num">{s.installed ? fmtBytes(s.memory) : "—"}</td>
                <td>
                  {s.installed ? (
                    <form method="post" action={`/services/${s.key}/action`} class="row">
                      <Csrf token={p.csrf} />
                      {s.active === "active" ? (
                        <>
                          <button class="btn small" name="action" value="restart">
                            Restart
                          </button>
                          <button class="btn small" name="action" value="stop">
                            Stop
                          </button>
                        </>
                      ) : (
                        <button class="btn small" name="action" value="start">
                          Start
                        </button>
                      )}
                    </form>
                  ) : (
                    <form method="post" action={`/services/${s.key}/install`}>
                      <Csrf token={p.csrf} />
                      <button class="btn primary small">Install</button>
                    </form>
                  )}
                </td>
              </tr>
            ))}
            <tr>
              <td>
                <b>SQLite</b>
                <div class="muted small">no server: a file inside the app</div>
              </td>
              <td>—</td>
              <td>
                <span class="muted">built in</span>
              </td>
              <td class="num">0</td>
              <td class="small muted">
                Use <code>$DATA_DIR/app.db</code>: kept across deploys and in app backups.
              </td>
            </tr>
          </tbody>
        </table>
      </Card>

      <div class="cols">
        {p.list.find((s) => s.key === "mariadb")?.installed ? (
          <Card title="MariaDB">
            <p>
              Databases and users: <a href="/databases">{t("Databases")}</a>. Connection: <code>mysql://user:password@127.0.0.1:3306/db</code>
            </p>
          </Card>
        ) : null}
        {p.list.find((s) => s.key === "valkey")?.installed ? (
          <Card title="Valkey">
            <form method="post" action="/services/valkey/url" class="row">
              <Csrf token={p.csrf} />
              <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />
              <button class="btn">Show REDIS_URL</button>
            </form>
          </Card>
        ) : null}
      </div>

      {p.realtime ? <RealtimeCard r={p.realtime} csrf={p.csrf} appNames={p.appNames ?? []} /> : null}
      {p.turn ? <TurnCard v={p.turn} csrf={p.csrf} appNames={p.appNames ?? []} /> : null}

      {pg?.installed ? (
        <Card title={`PostgreSQL ${pg.version}`}>
          <table>
            <thead>
              <tr>
                <th>{t("Name")}</th>
                <th>Owner</th>
                <th class="num">{t("Size")}</th>
              </tr>
            </thead>
            <tbody>
              {p.pg.map((d) => (
                <tr class={d.system ? "muted" : ""}>
                  <td>{d.name}</td>
                  <td>{d.owner}</td>
                  <td class="num">{d.sizeMb} MB</td>
                </tr>
              ))}
            </tbody>
          </table>
          <form method="post" action="/services/postgres/create" class="row">
            <Csrf token={p.csrf} />
            <Field label="Name" name="name" required placeholder="app_db" />
            <Field label="User (empty = same as name)" name="user" placeholder="app_user" />
            <button class="btn primary">{t("New database")}</button>
          </form>
          {p.pg.some((d) => !d.system) ? (
            <details>
              <summary class="muted small">{t("Delete")}</summary>
              <DangerForm
                action="/services/postgres/drop"
                csrf={p.csrf}
                name="database name"
                label={t("Delete")}
                extra={
                  <label class="field">
                    <span>{t("Name")}</span>
                    <select name="name">
                      {p.pg
                        .filter((d) => !d.system)
                        .map((d) => (
                          <option value={d.name}>{d.name}</option>
                        ))}
                    </select>
                  </label>
                }
              />
            </details>
          ) : null}
        </Card>
      ) : null}
    </div>
  );
}
