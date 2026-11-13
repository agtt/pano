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
export type PgRemoteView = {
  available: boolean;
  on: boolean;
  domain: string;
  allow: string[];
  port: number;
  ip: string;
  listening: boolean;
  connLimit: number;
  users: { user: string; database: string; created_at: number }[];
};
type Secret = { title: string; lines: [string, string][] };

const Otp = () => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder="2FA" size={6} class="short" required autocomplete="one-time-code" />;

/** Remote access for apps hosted elsewhere (Vercel, Netlify…): TLS, remote-only users, optional source networks. */
export function PgRemoteCard(p: { v: PgRemoteView; dbs: PgDb[]; csrf: string }) {
  const { v } = p;
  const dbs = p.dbs.filter((d) => !d.system);
  return (
    <div class="stack">
      <h3>Remote access (Vercel and other hosts)</h3>
      <p class="muted small">
        For apps that do not run on this server. PostgreSQL then also answers on {v.port} over TLS only, with the edge's certificate for the name below (clients
        verify it: <code>sslmode=verify-full</code>). Only remote users can log in from outside, each limited to one database and {v.connLimit} connections; the
        apps' own users stay local. Leave the networks empty to allow any address (the password and TLS still protect it), or list fixed egress addresses such as
        Vercel Static IPs.
      </p>
      {v.on ? (
        <p class="small">
          <Badge state={v.listening ? "active" : "failed"} /> {v.domain}:{v.port}
          {v.ip ? ` (${v.ip})` : ""} · {v.allow.length ? `only from ${v.allow.join(", ")}` : "from any address"}
        </p>
      ) : null}
      <form method="post" action="/services/postgres/remote" class="row">
        <Csrf token={p.csrf} />
        <Field label="Domain" name="domain" value={v.domain} placeholder="db.example.com" required hint="A DNS-only (grey cloud) record to this server; the edge gets its certificate." />
        <Field label="Allowed networks (optional)" name="allow" value={v.allow.join(" ")} placeholder="203.0.113.7 198.51.100.0/24" />
        <Otp />
        <button class="btn primary small">{v.on ? "Save" : "Turn on"}</button>
      </form>
      {v.on ? (
        <>
          <table>
            <thead>
              <tr>
                <th>Remote user</th>
                <th>{t("Database")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {v.users.map((u) => (
                <tr>
                  <td>
                    <code>{u.user}</code>
                  </td>
                  <td>{u.database}</td>
                  <td>
                    <form method="post" action="/services/postgres/remote/users/remove" class="row">
                      <Csrf token={p.csrf} />
                      <input type="hidden" name="user" value={u.user} />
                      <Otp />
                      <button class="btn small">{t("Remove")}</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {dbs.length ? (
            <form method="post" action="/services/postgres/remote/users" class="row">
              <Csrf token={p.csrf} />
              <label class="field">
                <span>{t("Database")}</span>
                <select name="database">
                  {dbs.map((d) => (
                    <option value={d.name}>{d.name}</option>
                  ))}
                </select>
              </label>
              <Otp />
              <button class="btn small">New remote user (shows DATABASE_URL once)</button>
            </form>
          ) : null}
          <form method="post" action="/services/postgres/remote/off" class="row">
            <Csrf token={p.csrf} />
            <Otp />
            <button class="btn small">Turn off</button>
            <span class="muted small">Back to localhost only; remote users stay and work again when turned on.</span>
          </form>
        </>
      ) : null}
    </div>
  );
}

export function ServicesPage(p: { csrf: string; list: ServiceRow[]; pg: PgDb[]; pgRemote?: PgRemoteView; secret?: Secret; realtime?: RealtimeView; turn?: TurnView; appNames?: string[] }) {
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

      <h2 class="section">Optional extensions</h2>
      <p class="muted small">Nothing of these is on disk or running until installed.</p>
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
          {p.pgRemote?.available ? <PgRemoteCard v={p.pgRemote} dbs={p.pg} csrf={p.csrf} /> : null}
        </Card>
      ) : null}
    </div>
  );
}
