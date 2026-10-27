import { fmtBytes, fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf, DangerForm, Field } from "./layout.tsx";

export type RealtimeView = {
  installed: boolean;
  version: string;
  latest: string;
  autoUpdate: boolean;
  updatedAt: number | null;
  active: string;
  memory: number;
  domain: string;
  port: number;
  apps: { id: string; name: string; key: string; origins: string[]; created_at: number }[];
};

const Otp = () => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder="2FA" size={6} class="short" required />;

export function RealtimeCard({ r, csrf, appNames }: { r: RealtimeView; csrf: string; appNames: string[] }) {
  if (!r.installed) {
    return (
      <Card title="Realtime (Pusher-compatible)">
        <p class="muted small">
          WebSockets for live updates (orders, chat, notifications) without Pusher's bill. Sockudo: speaks the Pusher protocol, so <code>pusher-js</code>,
          Laravel Echo and every Pusher server SDK work unchanged. One binary (about 160 MB on disk, 40 MB of memory), nothing on disk until you install it, updates
          itself.
        </p>
        <form method="post" action="/services/realtime/install">
          <Csrf token={csrf} />
          <button class="btn primary">{t("Install")}</button>
        </form>
      </Card>
    );
  }
  const host = r.domain || "127.0.0.1";
  const upgrade = r.latest && r.latest !== r.version && r.latest.split(".")[0] !== r.version.split(".")[0];
  return (
    <Card title={`Realtime · Sockudo ${r.version}`} actions={<Badge state={r.active || "unknown"} />}>
      <p class="muted small">
        127.0.0.1:{r.port} · {fmtBytes(r.memory)} ·{" "}
        {r.autoUpdate ? "updates itself within its major version (checked daily, rolled back if the new one does not answer)" : "automatic updates off"}
        {r.updatedAt ? ` · last update ${fmtTime(r.updatedAt)}` : ""}
      </p>
      <div class="row">
        <form method="post" action="/services/realtime/auto" class="inline">
          <Csrf token={csrf} />
          <input type="hidden" name="on" value={r.autoUpdate ? "0" : "1"} />
          <button class="btn small">{r.autoUpdate ? "Turn off automatic updates" : "Turn on automatic updates"}</button>
        </form>
        <form method="post" action="/services/realtime/check" class="inline">
          <Csrf token={csrf} />
          <button class="btn small">Check for updates</button>
        </form>
        {upgrade ? (
          <form method="post" action="/services/realtime/update" class="inline">
            <Csrf token={csrf} />
            <button class="btn small primary" title="A new major version can change behavior; it is not installed automatically">
              Update to {r.latest}
            </button>
          </form>
        ) : null}
      </div>

      <form method="post" action="/services/realtime/domain" class="row">
        <Csrf token={csrf} />
        <Field label="Public domain" name="domain" value={r.domain} placeholder="ws.example.com" hint="Point it at this server; TLS is automatic. Empty: localhost only." />
        <button class="btn">{t("Save")}</button>
      </form>

      <table>
        <thead>
          <tr>
            <th>{t("Name")}</th>
            <th>App ID</th>
            <th>Key</th>
            <th>Origins</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {r.apps.map((a) => (
            <tr>
              <td>
                <b>{a.name}</b>
              </td>
              <td>
                <code>{a.id}</code>
              </td>
              <td>
                <code data-copy>{a.key}</code>
              </td>
              <td class="small">{a.origins.length ? a.origins.join(" ") : <span class="muted">any</span>}</td>
              <td class="row">
                <form method="post" action={`/services/realtime/apps/${a.name}/reveal`} class="inline">
                  <Csrf token={csrf} />
                  <Otp />
                  <button class="btn small">Secret</button>
                </form>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div class="cols">
        <form method="post" action="/services/realtime/apps" class="grid-form">
          <Csrf token={csrf} />
          <Field label="Name" name="name" required placeholder="fastpos" />
          <Field label="Allowed origins (optional)" name="origins" placeholder="https://app.example.com" hint="Browsers from other sites cannot connect." />
          <div class="actions">
            <button class="btn primary">+ App</button>
          </div>
        </form>
        {appNames.length && r.apps.length ? (
          <form method="post" action="/services/realtime/to-app" class="grid-form">
            <Csrf token={csrf} />
            <label class="field">
              <span>{t("Apps")}</span>
              <select name="app">
                {appNames.map((n) => (
                  <option value={n}>{n}</option>
                ))}
              </select>
            </label>
            <label class="field">
              <span>Realtime app</span>
              <select name="realtime">
                {r.apps.map((a) => (
                  <option value={a.name}>{a.name}</option>
                ))}
              </select>
            </label>
            <div class="actions">
              <button class="btn">Add to app environment</button>
            </div>
            <small class="muted">
              Sets PUSHER_* (server side, over localhost) and NEXT_PUBLIC_PUSHER_* (browsers, over the public domain); restarts the app. NEXT_PUBLIC_ values reach
              the browser after the next deploy.
            </small>
          </form>
        ) : null}
      </div>

      <details>
        <summary class="muted small">Client example</summary>
        <pre class="log small">{`new Pusher(key, {
  wsHost: "${host}", wsPort: ${r.domain ? 443 : r.port}, wssPort: 443,
  forceTLS: ${r.domain ? "true" : "false"}, enabledTransports: ["ws", "wss"],
  cluster: "mt1", disableStats: true,
})
// server: new Pusher({ appId, key, secret, host: "127.0.0.1", port: "${r.port}", useTLS: false })`}</pre>
      </details>

      <details>
        <summary class="muted small">{t("Delete")}</summary>
        {r.apps.length ? (
          <DangerForm
            action="/services/realtime/apps/remove"
            csrf={csrf}
            name="the app's name"
            label="Remove app"
            extra={
              <label class="field">
                <span>{t("Name")}</span>
                <select name="name">
                  {r.apps.map((a) => (
                    <option value={a.name}>{a.name}</option>
                  ))}
                </select>
              </label>
            }
          />
        ) : null}
        <DangerForm action="/services/realtime/uninstall" csrf={csrf} name="realtime" label="Uninstall (apps and keys are kept)" />
      </details>
    </Card>
  );
}
