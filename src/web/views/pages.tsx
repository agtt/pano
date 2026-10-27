import { fmtBytes, fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf, DangerForm, Field } from "./layout.tsx";

const Otp = () => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />;

// ---- sites -----------------------------------------------------------------

export type SiteRow = {
  name: string;
  kind: string;
  domains: string[];
  root: string;
  routes: { path: string; upstream: string }[];
  ask_url: string;
  php_version: string;
  tls_cert: string;
  source: string;
  enabled: number;
  on_demand_tls: number;
};

export function SitesPage({ sites, csrf }: { sites: SiteRow[]; csrf: string }) {
  return (
    <div class="stack">
      <Card title={t("Sites")} actions={<a class="btn primary" href="/sites/new">+ Site</a>}>
        {sites.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Name")}</th>
                <th>{t("Kind")}</th>
                <th>{t("Domains")}</th>
                <th>TLS</th>
                <th>{t("Status")}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sites.map((s) => (
                <tr>
                  <td>
                    <a href={`/sites/${s.name}`}>{s.name}</a> {s.source === "cyberpanel" ? <span class="tag">cyberpanel</span> : null}
                  </td>
                  <td>
                    {s.kind}
                    {s.php_version ? ` ${s.php_version}` : ""}
                  </td>
                  <td class="muted">{s.domains.join(", ")}</td>
                  <td class="muted small">{s.tls_cert ? "imported cert" : s.on_demand_tls ? "on demand" : "automatic"}</td>
                  <td>
                    <Badge state={s.enabled ? "active" : "disabled"} />
                  </td>
                  <td>
                    <form method="post" action={`/sites/${s.name}/toggle`}>
                      <Csrf token={csrf} />
                      <input type="hidden" name="enabled" value={s.enabled ? "0" : "1"} />
                      <button class="btn small">{s.enabled ? t("Disabled") : t("Enabled")}</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p class="muted">{t("No sites yet.")}</p>
        )}
      </Card>
    </div>
  );
}

export function SiteForm({ site, csrf }: { site?: SiteRow; csrf: string }) {
  const s = site;
  return (
    <div class="stack">
      <Card title={s ? s.name : "+ Site"}>
        <form method="post" action="/sites/save" class="grid-form">
          <Csrf token={csrf} />
          {s ? <input type="hidden" name="name" value={s.name} /> : <Field label="Name" name="name" required placeholder="example.com" />}
          <label class="field">
            <span>{t("Kind")}</span>
            <select name="kind">
              {["proxy", "static", "legacy"].map((k) => (
                <option value={k} selected={s?.kind === k}>
                  {k}
                </option>
              ))}
            </select>
          </label>
          <Field label="Domains" name="domains" value={s?.domains.join(", ")} placeholder="example.com, www.example.com ( * = catch-all )" required />
          <Field label="Root directory" name="root" value={s?.root} placeholder="/srv/www/example (static)" />
          <label class="field wide">
            <span>{t("Routes")} (proxy)</span>
            <textarea name="routes" rows={4} class="mono" placeholder={"/ 127.0.0.1:3000\n/api 127.0.0.1:3001"}>
              {(s?.routes ?? []).map((r) => `${r.path} ${r.upstream}`).join("\n")}
            </textarea>
          </label>
          <Field label="Ask URL (catch-all TLS)" name="ask_url" value={s?.ask_url} placeholder="http://127.0.0.1:3000/api/tls-ask" />
          {s?.tls_cert ? (
            <label class="check">
              <input type="checkbox" name="autoTls" value="1" /> {t("Automatic TLS (drop imported certificate)")} <code class="small">{s.tls_cert}</code>
            </label>
          ) : null}
          <div class="actions">
            <button class="btn primary">{t("Save")}</button>
          </div>
        </form>
      </Card>
      {s ? (
        <Card title={t("Delete")} class="danger-zone">
          <DangerForm action={`/sites/${s.name}/delete`} csrf={csrf} name={s.name} label={t("Delete")} />
        </Card>
      ) : null}
    </div>
  );
}

// ---- databases -------------------------------------------------------------

export function DatabasesPage(p: {
  csrf: string;
  data: { databases: { name: string; sizeMb: number; tables: number; users: string[]; system: boolean }[]; users: { user: string; host: string }[] };
  created?: { name: string; user: string; password: string };
}) {
  return (
    <div class="stack">
      {p.created?.user ? (
        <div class="flash ok">
          {p.created.name}: <code>{p.created.user}</code> / <code class="secret">{p.created.password}</code> — shown once, store it now.
        </div>
      ) : null}
      <Card title={t("Databases")}>
        <table>
          <thead>
            <tr>
              <th>{t("Name")}</th>
              <th class="num">{t("Size")}</th>
              <th class="num">{t("Tables")}</th>
              <th>{t("Users")}</th>
            </tr>
          </thead>
          <tbody>
            {p.data.databases.map((d) => (
              <tr class={d.system ? "muted" : ""}>
                <td>{d.name}</td>
                <td class="num">{d.sizeMb} MB</td>
                <td class="num">{d.tables}</td>
                <td class="small">{d.users.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <div class="cols">
        <Card title={t("New database")}>
          <form method="post" action="/databases/create">
            <Csrf token={p.csrf} />
            <Field label="Name" name="name" required placeholder="app_db" />
            <Field label="User (optional)" name="user" placeholder="app_user" />
            <Field label="Password (empty = generate)" name="password" type="password" autocomplete="new-password" />
            <button class="btn primary">{t("Create")}</button>
          </form>
        </Card>
        <Card title={t("Reset password")}>
          <form method="post" action="/databases/password">
            <Csrf token={p.csrf} />
            <label class="field">
              <span>{t("Users")}</span>
              <select name="userhost">
                {p.data.users
                  .filter((u) => u.user !== "root" && !u.user.startsWith("mariadb.") && u.user !== "mysql")
                  .map((u) => (
                    <option value={`${u.user}@${u.host}`}>{`${u.user}@${u.host}`}</option>
                  ))}
              </select>
            </label>
            <Field label="Password (empty = generate)" name="password" type="password" autocomplete="new-password" />
            <button class="btn">{t("Reset password")}</button>
          </form>
        </Card>
        <Card title={`${t("Delete")} · ${t("Databases")}`} class="danger-zone">
          <form method="post" action="/databases/drop" class="danger">
            <Csrf token={p.csrf} />
            <label class="field">
              <span>{t("Name")}</span>
              <select name="name">
                {p.data.databases
                  .filter((d) => !d.system)
                  .map((d) => (
                    <option value={d.name}>{d.name}</option>
                  ))}
              </select>
            </label>
            <Field label="Type the name to confirm" name="confirm" required />
            <label class="field">
              <span>{t("Current authenticator code")}</span>
              <Otp />
            </label>
            <button class="btn danger">{t("Delete")}</button>
          </form>
        </Card>
      </div>
    </div>
  );
}

// ---- backups ---------------------------------------------------------------

export type JobRow = {
  id: number;
  name: string;
  kind: string;
  target: string;
  schedule: string;
  keep: number;
  last_run_at: number | null;
  last_status: string;
  runs: { id: number; status: string; bytes: number; object_key: string; error: string; started_at: number }[];
};

export function BackupsPage(p: {
  csrf: string;
  r2: { accountId: string; bucket: string; prefix: string; accessKeyId: string; hasSecret: boolean; endpoint: string };
  jobs: JobRow[];
  dbs: string[];
  apps: string[];
  key?: string;
}) {
  return (
    <div class="stack">
      {p.key ? (
        <div class="flash ok">
          Backup key (base64): <code class="secret">{p.key}</code> — keep an offline copy. Without it no backup can be restored.
        </div>
      ) : null}
      <Card title="Cloudflare R2">
        <form method="post" action="/backups/r2" class="grid-form">
          <Csrf token={p.csrf} />
          <Field label="Account ID" name="accountId" value={p.r2.accountId} placeholder="32 hex chars" />
          <Field label="Bucket" name="bucket" value={p.r2.bucket} required />
          <Field label="Prefix" name="prefix" value={p.r2.prefix} />
          <Field label="Access key ID" name="accessKeyId" value={p.r2.accessKeyId} required />
          <Field label="Secret access key" name="secretAccessKey" type="password" placeholder={p.r2.hasSecret ? "•••••• (stored; leave empty to keep)" : ""} autocomplete="new-password" />
          <Field label="Endpoint (non-R2 S3, optional)" name="endpoint" value={p.r2.endpoint} placeholder="https://s3.example.com" />
          <div class="actions">
            <button class="btn primary">{t("Save")}</button>
          </div>
        </form>
        <div class="row">
          <form method="post" action="/backups/r2/test">
            <Csrf token={p.csrf} />
            <button class="btn">{t("Test connection")}</button>
          </form>
          <form method="post" action="/backups/key" class="row">
            <Csrf token={p.csrf} />
            <Otp />
            <button class="btn">{t("Export encryption key")}</button>
          </form>
        </div>
        <p class="muted small">Backups are gzip-compressed and AES-256-GCM encrypted on this server before upload; R2 only stores ciphertext.</p>
      </Card>

      <Card title={t("Backups")}>
        {p.jobs.map((j) => (
          <details class="job">
            <summary>
              <strong>{j.name}</strong> <span class="tag">{j.kind}</span> <span class="muted">{j.target}</span> · {j.schedule} · {t("Keep")} {j.keep} ·{" "}
              {j.last_status ? <Badge state={j.last_status} /> : null} <span class="muted small">{fmtTime(j.last_run_at)}</span>
            </summary>
            <div class="row">
              <form method="post" action={`/backups/jobs/${j.id}/run`}>
                <Csrf token={p.csrf} />
                <button class="btn small">{t("Run now")}</button>
              </form>
              <form method="post" action={`/backups/jobs/${j.id}/remove`}>
                <Csrf token={p.csrf} />
                <button class="btn small danger">{t("Delete")}</button>
              </form>
            </div>
            <table class="compact">
              {j.runs.map((r) => (
                <tr>
                  <td>#{r.id}</td>
                  <td>
                    <Badge state={r.status} />
                  </td>
                  <td class="muted">{fmtTime(r.started_at)}</td>
                  <td class="num">{r.bytes ? fmtBytes(r.bytes) : ""}</td>
                  <td class="small muted">{r.error || r.object_key}</td>
                  <td>
                    {r.status === "success" && r.object_key ? (
                      <form method="post" action={`/backups/runs/${r.id}/restore`} class="row">
                        <Csrf token={p.csrf} />
                        {j.kind === "mysql" ? <input name="target" value={j.target} class="short" title="target database" /> : null}
                        <Otp />
                        <button class="btn small">{t("Restore")}</button>
                      </form>
                    ) : null}
                  </td>
                </tr>
              ))}
            </table>
          </details>
        ))}
        <h3>+ Job</h3>
        <form method="post" action="/backups/jobs" class="grid-form">
          <Csrf token={p.csrf} />
          <label class="field">
            <span>{t("Kind")}</span>
            <select name="kind">
              <option value="mysql">mysql</option>
              <option value="app">app</option>
              <option value="path">path</option>
            </select>
          </label>
          <label class="field">
            <span>{t("Target")}</span>
            <input name="target" list="targets" required placeholder="db name, app name or /home/site" />
            <datalist id="targets">
              {[...p.dbs, ...p.apps].map((x) => (
                <option value={x} />
              ))}
            </datalist>
          </label>
          <Field label="Schedule" name="schedule" value="daily 03:30" hint="manual · hourly · daily HH:MM" />
          <Field label="Keep" name="keep" type="number" value={7} />
          <Field label="Name" name="name" placeholder="(auto)" />
          <div class="actions">
            <button class="btn primary">{t("Create")}</button>
          </div>
        </form>
      </Card>
    </div>
  );
}

// ---- runtimes --------------------------------------------------------------

export function RuntimesPage(p: { csrf: string; installed: { runtime: string; version: string; inUse: boolean }[]; available: { node: { version: string; lts: string | false }[]; bun: string[] } | null }) {
  const have = new Set(p.installed.map((r) => `${r.runtime}@${r.version}`));
  const InstallBtn = ({ rt, ver, label }: { rt: string; ver: string; label?: string }) =>
    have.has(`${rt}@${ver}`) ? (
      <span class="badge good">{t("Installed")}</span>
    ) : (
      <form method="post" action="/runtimes/install">
        <Csrf token={p.csrf} />
        <input type="hidden" name="runtime" value={rt} />
        <input type="hidden" name="version" value={ver} />
        <button class="btn small">
          {t("Install")} {label ?? ver}
        </button>
      </form>
    );
  return (
    <div class="stack">
      <Card title={t("Installed")}>
        <table class="compact">
          {p.installed.map((r) => (
            <tr>
              <td>{r.runtime}</td>
              <td>{r.version}</td>
              <td>{r.inUse ? <span class="tag">{t("In use")}</span> : null}</td>
              <td>
                {r.inUse ? null : (
                  <form method="post" action="/runtimes/uninstall">
                    <Csrf token={p.csrf} />
                    <input type="hidden" name="runtime" value={r.runtime} />
                    <input type="hidden" name="version" value={r.version} />
                    <button class="btn small danger">{t("Delete")}</button>
                  </form>
                )}
              </td>
            </tr>
          ))}
        </table>
      </Card>
      <Card title={t("Available")}>
        {p.available ? (
          <div class="cols">
            <div>
              <h3>Node.js</h3>
              <table class="compact">
                {p.available.node.map((n) => (
                  <tr>
                    <td>{n.version}</td>
                    <td class="muted">{n.lts ? `LTS ${n.lts}` : "current"}</td>
                    <td>
                      <InstallBtn rt="node" ver={n.version} />
                    </td>
                  </tr>
                ))}
              </table>
            </div>
            <div>
              <h3>Bun</h3>
              <table class="compact">
                {p.available.bun.map((b) => (
                  <tr>
                    <td>{b}</td>
                    <td>
                      <InstallBtn rt="bun" ver={b} />
                    </td>
                  </tr>
                ))}
              </table>
            </div>
          </div>
        ) : (
          <p class="muted">Could not reach nodejs.org / GitHub.</p>
        )}
      </Card>
    </div>
  );
}

// ---- edge ------------------------------------------------------------------

export function EdgePage(p: { csrf: string; status: { installed: boolean; active: boolean; cutover: boolean; settings: { email: string; behindCloudflare: boolean; hooksDomain: string; localCerts?: boolean } }; preview: string; report?: { ok: boolean; steps: string[]; probes: { domain: string; status: string }[] } }) {
  const s = p.status;
  return (
    <div class="stack">
      {p.report ? (
        <Card title={p.report.ok ? "Cutover done" : "Cutover rolled back"}>
          <ul>
            {p.report.steps.map((x) => (
              <li>{x}</li>
            ))}
          </ul>
          <table class="compact">
            {p.report.probes.map((x) => (
              <tr>
                <td>{x.domain}</td>
                <td>
                  <Badge state={/^[23]/.test(x.status) ? "ok" : x.status} />
                </td>
              </tr>
            ))}
          </table>
        </Card>
      ) : null}
      <Card title={t("Edge")}>
        <dl class="kv">
          <dt>Caddy</dt>
          <dd>{s.installed ? <Badge state={s.active ? "active" : "inactive"} /> : "not installed"}</dd>
          <dt>{t("Cutover")}</dt>
          <dd>{s.cutover ? "done — the edge owns :80/:443" : "not yet — OpenLiteSpeed/CyberPanel still serve traffic"}</dd>
        </dl>
        <div class="row">
          {!s.installed ? (
            <form method="post" action="/edge/install">
              <Csrf token={p.csrf} />
              <button class="btn primary">{t("Install Caddy")}</button>
            </form>
          ) : null}
          {s.installed && !s.cutover ? (
            <form method="post" action="/edge/cutover" class="row">
              <Csrf token={p.csrf} />
              <Otp />
              <button class="btn danger">{t("Cutover")}</button>
            </form>
          ) : null}
          {s.cutover ? (
            <form method="post" action="/edge/rollback" class="row">
              <Csrf token={p.csrf} />
              <Otp />
              <button class="btn danger">{t("Rollback")}</button>
            </form>
          ) : null}
        </div>
        <p class="muted small">
          Cutover moves OpenLiteSpeed to 127.0.0.1 (PHP sites keep working behind the edge) and starts Caddy on :80/:443. If Caddy fails to start, the old
          config is restored automatically. Test it in a VM first.
        </p>
      </Card>
      <Card title={t("Settings")}>
        <form method="post" action="/edge/settings" class="grid-form">
          <Csrf token={p.csrf} />
          <Field label="ACME email" name="email" value={s.settings.email} type="email" />
          <Field label="Webhook domain" name="hooksDomain" value={s.settings.hooksDomain} placeholder="hooks.example.com" hint="Only /hooks/* is exposed there, for GitHub push deploys." />
          <label class="check">
            <input type="checkbox" name="behindCloudflare" value="1" checked={s.settings.behindCloudflare} /> Sites are behind Cloudflare proxy (trust CF-Connecting-IP)
          </label>
          <label class="check">
            <input type="checkbox" name="localCerts" value="1" checked={s.settings.localCerts} /> Staging: use Caddy's internal CA instead of Let's Encrypt
          </label>
          <div class="actions">
            <button class="btn">{t("Save")}</button>
          </div>
        </form>
      </Card>
      <Card title={`${t("Preview")} · Caddyfile`}>
        <pre class="log">{p.preview}</pre>
      </Card>
    </div>
  );
}

// ---- security --------------------------------------------------------------

export function SecurityPage({ findings }: { findings: { id: string; level: string; title: string; detail: string; fix?: string }[] }) {
  return (
    <Card title={t("Security")}>
      <p class="muted">{t("Everything here is read-only. Each fix is a command you run yourself.")}</p>
      <div class="findings">
        {findings.map((f) => (
          <div class={`finding ${f.level}`}>
            <div>
              <Badge state={f.level === "ok" ? "ok" : f.level === "fail" ? "fail" : "warn"} /> <strong>{f.title}</strong>
            </div>
            {f.detail ? <p class="muted">{f.detail}</p> : null}
            {f.fix ? (
              <pre class="fix" data-copy>
                {f.fix}
              </pre>
            ) : null}
          </div>
        ))}
      </div>
    </Card>
  );
}

// ---- import ----------------------------------------------------------------

export type ImportPlanView = {
  cyberpanel: { installed: boolean; version: string; services: Record<string, string> };
  sites: (SiteRow & { wordpress: boolean; wpProxyReady: boolean; databases: string[] })[];
  apps: { name: string; external_unit: string; upstream: string; process: string }[];
  warnings: string[];
};

export function ImportPage(p: { csrf: string; plan?: ImportPlanView; snippet: string; existing: Set<string> }) {
  const plan = p.plan;
  return (
    <div class="stack">
      <Card title={`${t("Import")} · CyberPanel`}>
        <p class="muted">
          Reads OpenLiteSpeed and CyberPanel configuration and running services. Scanning changes nothing; importing only writes pano's own state. CyberPanel keeps
          serving traffic until the cutover on the Edge page.
        </p>
        <form method="get" action="/import">
          <input type="hidden" name="scan" value="1" />
          <button class="btn primary">{t("Scan server")}</button>
        </form>
      </Card>
      {plan ? (
        <form method="post" action="/import/apply" class="stack">
          <Csrf token={p.csrf} />
          <Card title="CyberPanel">
            <p>
              {plan.cyberpanel.installed ? `installed ${plan.cyberpanel.version}` : "not found"} ·{" "}
              {Object.entries(plan.cyberpanel.services)
                .map(([k, val]) => `${k}: ${val}`)
                .join(", ")}
            </p>
          </Card>
          {plan.warnings.length ? (
            <Card title={t("Warnings")}>
              <ul class="warnings">
                {plan.warnings.map((w) => (
                  <li>{w}</li>
                ))}
              </ul>
              <details>
                <summary>wp-config.php snippet</summary>
                <pre class="fix" data-copy>
                  {p.snippet}
                </pre>
              </details>
            </Card>
          ) : null}
          <Card title={t("Sites")}>
            <table>
              <thead>
                <tr>
                  <th></th>
                  <th>{t("Name")}</th>
                  <th>{t("Kind")}</th>
                  <th>{t("Domains")}</th>
                  <th>TLS</th>
                  <th>{t("Databases")}</th>
                </tr>
              </thead>
              <tbody>
                {plan.sites.map((s) => (
                  <tr>
                    <td>
                      <input type="checkbox" name="sites" value={s.name} checked={!p.existing.has(`site:${s.name}`)} />
                    </td>
                    <td>
                      {s.name} {s.enabled ? null : <span class="tag">suspended</span>} {s.wordpress ? <span class="tag">WordPress</span> : null}
                    </td>
                    <td>
                      {s.kind} {s.php_version}
                      {s.routes.length ? <div class="small muted">{s.routes.map((r) => `${r.path} → ${r.upstream}`).join(" · ")}</div> : null}
                    </td>
                    <td class="small">{s.domains.join(", ")}</td>
                    <td class="small muted">{s.tls_cert || "—"}</td>
                    <td class="small">{s.databases.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <Card title={`${t("Apps")} (external)`}>
            <table class="compact">
              {plan.apps.map((a) => (
                <tr>
                  <td>
                    <input type="checkbox" name="apps" value={a.name} checked={!p.existing.has(`app:${a.name}`)} />
                  </td>
                  <td>{a.name}</td>
                  <td>
                    <code>{a.external_unit}</code>
                  </td>
                  <td class="muted">
                    {a.process} · {a.upstream}
                  </td>
                </tr>
              ))}
            </table>
          </Card>
          <div>
            <button class="btn primary">{t("Import selected")}</button>
          </div>
        </form>
      ) : null}
    </div>
  );
}

// ---- activity --------------------------------------------------------------

export function ActivityPage({ rows }: { rows: { at: number; actor: string; action: string; detail: string }[] }) {
  return (
    <Card title={t("Activity")}>
      <table class="compact">
        <thead>
          <tr>
            <th>{t("Time")}</th>
            <th>{t("Actor")}</th>
            <th>{t("Action")}</th>
            <th>{t("Detail")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr>
              <td class="muted">{fmtTime(r.at)}</td>
              <td>{r.actor}</td>
              <td>{r.action}</td>
              <td class="small muted">{r.detail.slice(0, 300)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
