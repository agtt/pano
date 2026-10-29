import { t } from "../i18n.ts";
import { Card, Csrf, Field } from "./layout.tsx";

const Otp = () => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />;

export type WpDetectView = { installed: boolean; version: string; empty: boolean; auto: boolean };
type Ext = { name: string; title: string; status: string; version: string; update: string };
export type WpStatusView = {
  version: string;
  coreUpdates: { version: string; type: string }[];
  plugins: Ext[];
  themes: Ext[];
  maintenance: boolean;
  admins: { id: number; login: string; email: string }[];
  auto: boolean;
};

/** On the site page: install on an empty site, or a link to the tools when WordPress is there. */
export function WordPressCard({ site, d, csrf }: { site: string; d: WpDetectView; csrf: string }) {
  if (d.installed) {
    return (
      <Card title="WordPress" actions={<a class="btn small" href={`/sites/${site}/wordpress`}>Manage</a>}>
        <p class="muted small">
          Version {d.version}. Updates, maintenance mode, admin password reset{d.auto ? " · nightly auto-update is on" : ""}.
        </p>
      </Card>
    );
  }
  if (!d.empty) return null;
  return (
    <Card title="WordPress">
      <p class="muted small">
        Installs WordPress into this empty site: creates a database and user, downloads the latest WordPress with wp-cli, writes wp-config.php with fresh salts and
        creates the admin. The admin password is shown once.
      </p>
      <form method="post" action={`/sites/${site}/wordpress/install`} class="grid-form">
        <Csrf token={csrf} />
        <Field label="Site title" name="title" required />
        <Field label="Admin user" name="adminUser" required placeholder="admin" />
        <Field label="Admin email" name="adminEmail" type="email" required />
        <div class="actions">
          <Otp />
          <button class="btn primary">Install WordPress</button>
        </div>
      </form>
    </Card>
  );
}

const Row = ({ e, kind }: { e: Ext; kind: "plugins" | "themes" }) => (
  <tr>
    <td>{e.update ? <input type="checkbox" name={kind} value={e.name} /> : null}</td>
    <td>
      {e.title} <code class="small">{e.name}</code>
    </td>
    <td>{e.status}</td>
    <td>{e.version}</td>
    <td>{e.update ? <strong>{e.update}</strong> : <span class="muted">–</span>}</td>
  </tr>
);

function ExtTable({ list, kind }: { list: Ext[]; kind: "plugins" | "themes" }) {
  if (!list.length) return <p class="muted small">None.</p>;
  return (
    <table>
      <thead>
        <tr>
          <th />
          <th>{kind === "plugins" ? "Plugin" : "Theme"}</th>
          <th>Status</th>
          <th>Version</th>
          <th>Update</th>
        </tr>
      </thead>
      <tbody>
        {list.map((e) => (
          <Row e={e} kind={kind} />
        ))}
      </tbody>
    </table>
  );
}

export function WordPressPage({ site, st, csrf }: { site: string; st: WpStatusView; csrf: string }) {
  const base = `/sites/${site}/wordpress`;
  const pluginUpdates = st.plugins.filter((p) => p.update).length;
  const themeUpdates = st.themes.filter((p) => p.update).length;
  return (
    <div class="stack">
      <Card title={`WordPress ${st.version}`} actions={<a class="btn small" href={`/sites/${site}`}>←</a>}>
        <form method="post" action={`${base}/update`} class="stack">
          <Csrf token={csrf} />
          <label class="check">
            <input type="checkbox" name="core" value="1" disabled={!st.coreUpdates.length} />{" "}
            {st.coreUpdates.length ? `Core → ${st.coreUpdates.map((u) => `${u.version}${u.type ? ` (${u.type})` : ""}`).join(", ")}` : "Core is up to date"}
          </label>
          <h3>Plugins ({pluginUpdates} with updates)</h3>
          <ExtTable list={st.plugins} kind="plugins" />
          <h3>Themes ({themeUpdates} with updates)</h3>
          <ExtTable list={st.themes} kind="themes" />
          <p class="muted small">Take a backup first (Backups); updates change files and the database.</p>
          <div class="row">
            <button class="btn primary">Update selected</button>
            <button class="btn" name="all" value="1" title="Core, every plugin and every theme">
              Update everything
            </button>
          </div>
        </form>
      </Card>
      <Card title="Maintenance mode">
        <form method="post" action={`${base}/maintenance`} class="row">
          <Csrf token={csrf} />
          <input type="hidden" name="on" value={st.maintenance ? "0" : "1"} />
          <span>{st.maintenance ? "On: visitors see the maintenance page." : "Off."}</span>
          <button class="btn">{st.maintenance ? "Turn off" : "Turn on"}</button>
        </form>
      </Card>
      <Card title="Automatic updates">
        <form method="post" action={`${base}/auto`} class="row">
          <Csrf token={csrf} />
          <label class="check">
            <input type="checkbox" name="on" value="1" checked={st.auto} /> Every night: minor WordPress releases (security fixes) and all plugins
          </label>
          <button class="btn">{t("Save")}</button>
        </form>
      </Card>
      <Card title="Reset an admin password">
        <form method="post" action={`${base}/password`} class="row">
          <Csrf token={csrf} />
          <select name="userId" required>
            {st.admins.map((a) => (
              <option value={String(a.id)}>
                {a.login} ({a.email})
              </option>
            ))}
          </select>
          <Otp />
          <button class="btn">Reset password</button>
        </form>
        <p class="muted small">The new password is shown once and the user's sessions end.</p>
      </Card>
    </div>
  );
}

/** Shown once, in the response of the action that created them. */
export function WpSecretPage({ title, lines, back }: { title: string; lines: [string, string][]; back: string }) {
  return (
    <Card title={title}>
      <div class="flash ok">Shown once, store it now.</div>
      <table>
        <tbody>
          {lines.map(([k, val]) => (
            <tr>
              <td>{k}</td>
              <td>
                <code class="secret">{val}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <a class="btn" href={back}>
        ←
      </a>
    </Card>
  );
}
