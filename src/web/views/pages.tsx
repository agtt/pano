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
  deny_paths?: string[];
  converted_from?: { kind: string; root: string; php_version: string } | null;
  crons?: { schedule: string; command: string }[];
};

export type PhpVersion = { version: string; installed: boolean; inUse: boolean; eol: string };

const today = () => new Date().toISOString().slice(0, 10);

function PhpSelect({ versions, current, name = "version" }: { versions: PhpVersion[]; current?: string; name?: string }) {
  return (
    <select name={name}>
      {versions.map((x) => (
        <option value={x.version} selected={x.version === current}>
          PHP {x.version}
          {x.installed ? "" : " (installs on first use)"}
          {x.eol < today() ? " — end of life" : ""}
        </option>
      ))}
    </select>
  );
}

export function SitesPage({ sites, csrf }: { sites: SiteRow[]; csrf: string }) {
  return (
    <div class="stack">
      <Card
        title={t("Sites")}
        actions={
          <div class="row">
            <a class="btn primary" href="/sites/new-php">+ PHP</a>
            <a class="btn" href="/sites/new">+ Site</a>
          </div>
        }
      >
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
                    <a href={`/sites/${s.name}`}>{s.name}</a> {s.source !== "pano" ? <span class="tag">{s.source}</span> : null}
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

export function PhpSiteNew({ csrf, versions }: { csrf: string; versions: PhpVersion[] }) {
  return (
    <Card title="+ PHP site">
      <p class="muted">
        Own system user, own PHP-FPM pool (started on demand, never as root), files in <code>/srv/pano/sites/&lt;name&gt;/public</code>. PHP is installed the
        first time a version is used. Hidden files, dumps, backups and PHP inside uploads are never served.
      </p>
      <form method="post" action="/sites/php" class="grid-form">
        <Csrf token={csrf} />
        <Field label="Name" name="name" required placeholder="example.com" />
        <Field label="Domains" name="domains" required placeholder="example.com, www.example.com" />
        <label class="field">
          <span>PHP</span>
          <PhpSelect versions={versions} current={versions[0]?.version} name="php_version" />
        </label>
        <div class="actions">
          <button class="btn primary">{t("Create")}</button>
        </div>
      </form>
    </Card>
  );
}

function PhpPanel({ s, csrf, versions, logs }: { s: SiteRow; csrf: string; versions: PhpVersion[]; logs: string }) {
  return (
    <>
      <Card title={`PHP ${s.php_version}`}>
        <form method="post" action={`/sites/${s.name}/php-version`} class="row">
          <Csrf token={csrf} />
          <PhpSelect versions={versions} current={s.php_version} />
          <button class="btn">{t("Save")}</button>
        </form>
        <p class="muted small">
          Files: <code>{s.root}</code> · user <code>site-{s.name.replace(/[^a-z0-9]/g, "-").slice(0, 27)}</code>. Upload over SFTP as root, then fix permissions.
        </p>
        <form method="post" action={`/sites/${s.name}/permissions`}>
          <Csrf token={csrf} />
          <button class="btn small">Fix permissions</button>
        </form>
        {s.deny_paths?.length ? (
          <p class="small">
            Blocked (from .htaccess): <code>{s.deny_paths.join("  ")}</code>
          </p>
        ) : null}
      </Card>
      <Card title="Cron" actions={<a class="btn small" href="/jobs">{t("Jobs")}</a>}>
        <form method="post" action={`/sites/${s.name}/crons`}>
          <Csrf token={csrf} />
          <textarea name="crons" rows={3} class="mono" spellcheck={false} placeholder={"*:0/5 | php public/wp-cron.php\nminutely | php artisan schedule:run"}>
            {(s.crons ?? []).map((c) => `${c.schedule} | ${c.command}`).join("\n")}
          </textarea>
          <p class="muted small">
            One job per line, <code>schedule | command</code>. Runs in <code>{s.root.replace(/\/public$/, "")}</code> as the site user with PHP {s.php_version} and
            the site's php.ini. Schedules: <code>minutely</code>, <code>*:0/5</code> (every 5 minutes), <code>hourly</code>, <code>daily</code>,{" "}
            <code>Mon..Fri 09:00</code>.
          </p>
          <div class="row">
            <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />
            <button class="btn">{t("Save")}</button>
          </div>
        </form>
      </Card>
      <Card title={t("Logs")} actions={<a class="btn" href={`/sites/${s.name}`}>↻</a>}>
        <pre class="log">{logs || "—"}</pre>
      </Card>
      {s.converted_from ? (
        <Card title="Back to OpenLiteSpeed">
          <p class="muted small">
            Serves <code>{s.converted_from.root}</code> through OpenLiteSpeed again. Changes made since the move (uploads, posts written to files) stay in the
            pano copy and are not copied back.
          </p>
          <form method="post" action={`/sites/${s.name}/revert`} class="row">
            <Csrf token={csrf} />
            <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />
            <button class="btn danger">Revert</button>
          </form>
        </Card>
      ) : null}
    </>
  );
}

function ConvertPanel({ s, csrf, versions }: { s: SiteRow; csrf: string; versions: PhpVersion[] }) {
  const current = versions.find((x) => x.version === s.php_version && x.eol >= today()) ? s.php_version : versions[0]?.version;
  return (
    <Card title="Move to pano PHP">
      <p class="muted small">
        Copies <code>{s.root || "(no root)"}</code> into a new PHP site with its own user and pool; the original files and OpenLiteSpeed are not changed and you
        can switch back. <code>.htaccess</code> is not read by the edge: directories closed with "deny from all" stay closed, other rules are listed after the move.
      </p>
      <form method="post" action={`/sites/${s.name}/convert`} class="row">
        <Csrf token={csrf} />
        <PhpSelect versions={versions} current={current} />
        <button class="btn primary">Move</button>
      </form>
    </Card>
  );
}

export function NoticePage({ title, items, back }: { title: string; items: string[]; back: string }) {
  return (
    <Card title={title}>
      {items.length ? (
        <ul class="warnings">
          {items.map((w) => (
            <li>{w}</li>
          ))}
        </ul>
      ) : (
        <p>OK</p>
      )}
      <a class="btn" href={back}>
        ←
      </a>
    </Card>
  );
}

export function SiteForm({ site, csrf, versions = [], logs = "" }: { site?: SiteRow; csrf: string; versions?: PhpVersion[]; logs?: string }) {
  const s = site;
  return (
    <div class="stack">
      <Card title={s ? s.name : "+ Site"}>
        <form method="post" action="/sites/save" class="grid-form">
          <Csrf token={csrf} />
          {s ? <input type="hidden" name="name" value={s.name} /> : <Field label="Name" name="name" required placeholder="example.com" />}
          {s?.kind === "php" ? (
            <input type="hidden" name="kind" value="php" />
          ) : (
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
          )}
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
      {s?.kind === "php" ? <PhpPanel s={s} csrf={csrf} versions={versions} logs={logs} /> : null}
      {s?.kind === "legacy" && versions.length ? <ConvertPanel s={s} csrf={csrf} versions={versions} /> : null}
      {s ? (
        <Card title={t("Delete")} class="danger-zone">
          <DangerForm
            action={`/sites/${s.name}/delete`}
            csrf={csrf}
            name={s.name}
            label={t("Delete")}
            extra={
              s.kind === "php" && !s.converted_from ? (
                <label class="check">
                  <input type="checkbox" name="removeFiles" value="1" /> also remove files and the system user
                </label>
              ) : null
            }
          />
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
            <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required />
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
  runs: { id: number; status: string; bytes: number; object_key: string; error: string; started_at: number; dest: string; engine: string }[];
};

type Dest = { accountId: string; bucket: string; prefix: string; accessKeyId: string; hasSecret: boolean; endpoint: string };
export type BackupSettings = { dests: { a: Dest; b: Dest }; engine: "archive" | "restic"; restic: string };

export function BackupsPage(p: {
  csrf: string;
  s: BackupSettings;
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
      <Card title={t("Backup engine")}>
        <form method="post" action="/backups/engine" class="row">
          <Csrf token={p.csrf} />
          <label class="check">
            <input type="radio" name="engine" value="archive" checked={p.s.engine === "archive"} /> Full archives: every run is a complete encrypted copy;
            nothing to install
          </label>
          <label class="check">
            <input type="radio" name="engine" value="restic" checked={p.s.engine === "restic"} /> Incremental (restic{p.s.restic ? ` ${p.s.restic}` : ", installs"}):
            only changes are uploaded, deduplicated and compressed, so many versions cost little more than one
          </label>
          <Otp />
          <button class="btn">{t("Save")}</button>
        </form>
        <p class="muted small">
          Earlier backups stay restorable after a switch. Both are encrypted on this server before upload with the one backup key below; the store only sees
          ciphertext. Every job goes to each destination that is set up.
        </p>
        <form method="post" action="/backups/key" class="row">
          <Csrf token={p.csrf} />
          <Otp />
          <button class="btn">{t("Export encryption key")}</button>
        </form>
      </Card>

      <div class="cols">
        {(["a", "b"] as const).map((d) => {
          const x = p.s.dests[d];
          return (
            <Card title={d === "a" ? "Main destination" : "Second destination (optional)"}>
              <form method="post" action="/backups/dest" class="grid-form">
                <Csrf token={p.csrf} />
                <input type="hidden" name="dest" value={d} />
                <Field label="Account ID" name="accountId" value={x.accountId} placeholder="R2 only: 32 hex chars" />
                <Field label="Bucket" name="bucket" value={x.bucket} required />
                <Field label="Prefix" name="prefix" value={x.prefix} />
                <Field label="Access key ID" name="accessKeyId" value={x.accessKeyId} required />
                <Field label="Secret access key" name="secretAccessKey" type="password" placeholder={x.hasSecret ? "•••••• (stored; leave empty to keep)" : ""} autocomplete="new-password" />
                <Field
                  label="Endpoint (other than R2)"
                  name="endpoint"
                  value={x.endpoint}
                  placeholder="https://s3.eu-central-003.backblazeb2.com"
                  hint="B2: the bucket's S3 endpoint · Hetzner: https://fsn1.your-objectstorage.com · empty for R2"
                />
                <label class="field">
                  <span>{t("Authenticator code")}</span>
                  <Otp />
                </label>
                <div class="actions">
                  <button class="btn primary">{t("Save")}</button>
                </div>
              </form>
              {x.bucket ? (
                <div class="row">
                  <form method="post" action="/backups/dest/test">
                    <Csrf token={p.csrf} />
                    <input type="hidden" name="dest" value={d} />
                    <button class="btn">{t("Test connection")}</button>
                  </form>
                  {d === "b" ? (
                    <form method="post" action="/backups/dest/clear" class="row">
                      <Csrf token={p.csrf} />
                      <input type="hidden" name="dest" value="b" />
                      <Otp />
                      <button class="btn">Stop using it</button>
                    </form>
                  ) : null}
                </div>
              ) : d === "b" ? (
                <p class="muted small">Another provider than the main one (for example R2 + Backblaze B2): one account or region going away cannot take the backups with it.</p>
              ) : null}
            </Card>
          );
        })}
      </div>

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
                  <td class="small muted">
                    {r.dest === "b" ? "2nd" : "main"} · {r.engine === "restic" ? "incremental" : "full"}
                  </td>
                  <td class="num" title={r.engine === "restic" ? "new data uploaded" : "size"}>
                    {r.bytes ? fmtBytes(r.bytes) : ""}
                  </td>
                  <td class="small muted">{r.error || r.object_key}</td>
                  <td>
                    {r.status === "success" && r.object_key ? (
                      <form method="post" action={`/backups/runs/${r.id}/restore`} class="row">
                        <Csrf token={p.csrf} />
                        {j.kind === "mysql" || j.kind === "postgres" ? <input name="target" value={j.target} class="short" title="target database" /> : null}
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
              <option value="postgres">postgres</option>
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
          <Field label="Schedule" name="schedule" value="daily 03:30" hint="manual · hourly · daily HH:MM · weekly Sun HH:MM" />
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

export function RuntimesPage(p: {
  csrf: string;
  installed: { runtime: string; version: string; inUse: boolean }[];
  available: { node: { version: string; lts: string | false }[]; bun: string[] } | null;
  php: PhpVersion[];
}) {
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
      <Card title="PHP">
        <p class="muted small">
          Installed only when needed (Remi packages, signed). Each PHP site runs its own pool; nothing PHP runs without a PHP site. Patch releases arrive with OS
          updates and pools are reloaded automatically.
        </p>
        <table class="compact">
          {p.php.map((x) => (
            <tr>
              <td>PHP {x.version}</td>
              <td class="muted small">{x.eol < today() ? <span class="tag">end of life {x.eol}</span> : `security fixes until ${x.eol}`}</td>
              <td>{x.inUse ? <span class="tag">{t("In use")}</span> : null}</td>
              <td>
                {x.installed ? (
                  x.inUse ? (
                    <span class="badge good">{t("Installed")}</span>
                  ) : (
                    <form method="post" action="/runtimes/php/uninstall">
                      <Csrf token={p.csrf} />
                      <input type="hidden" name="version" value={x.version} />
                      <button class="btn small danger">{t("Delete")}</button>
                    </form>
                  )
                ) : (
                  <form method="post" action="/runtimes/php/install">
                    <Csrf token={p.csrf} />
                    <input type="hidden" name="version" value={x.version} />
                    <button class="btn small">{t("Install")}</button>
                  </form>
                )}
              </td>
            </tr>
          ))}
        </table>
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

export type CpPlanView = {
  archive: string;
  account: string;
  mainDomain: string;
  sites: { name: string; domains: string[]; php: string; exists: boolean; warnings: string[] }[];
  databases: { name: string; bytes: number; exists: boolean }[];
  users: { user: string; hashOk: boolean; dbs: Record<string, string[]>; exists: boolean }[];
  notMigrated: string[];
  warnings: string[];
};
export type CpReportView = { sites: string[]; databases: string[]; users: { user: string; password?: string }[]; warnings: string[] };

function CpanelImport(p: { csrf: string; archives: { file: string; bytes: number }[]; plan?: CpPlanView; report?: CpReportView }) {
  const plan = p.plan;
  return (
    <>
      <Card title={`${t("Import")} · cPanel`}>
        <p class="muted">
          Copy a full account backup (<code>cpmove-USER.tar.gz</code>, from <code>/scripts/pkgacct USER</code> or cPanel → Backup → Full Backup) to{" "}
          <code>/var/lib/pano/imports/</code> on this server. Each domain becomes a PHP site; databases and their users keep their passwords. Nothing that
          already exists here is overwritten.
        </p>
        {p.archives.length ? (
          <table class="compact">
            {p.archives.map((a) => (
              <tr>
                <td>
                  <code>{a.file}</code>
                </td>
                <td class="muted">{fmtBytes(a.bytes)}</td>
                <td>
                  <form method="get" action="/import">
                    <input type="hidden" name="cpanel" value={a.file} />
                    <button class="btn small">{t("Scan")}</button>
                  </form>
                </td>
              </tr>
            ))}
          </table>
        ) : (
          <p class="muted small">No archives found.</p>
        )}
      </Card>
      {p.report ? (
        <Card title="cPanel import done">
          <p>
            Sites: {p.report.sites.join(", ") || "—"} · Databases: {p.report.databases.join(", ") || "—"}
          </p>
          {p.report.users.length ? (
            <table class="compact">
              {p.report.users.map((u) => (
                <tr>
                  <td>
                    <code>{u.user}</code>
                  </td>
                  <td>{u.password ? <code data-copy>{u.password}</code> : <span class="muted">original password kept</span>}</td>
                </tr>
              ))}
            </table>
          ) : null}
          {p.report.users.some((u) => u.password) ? <p class="small">New passwords are shown only now: put them in the site's config.</p> : null}
          {p.report.warnings.length ? (
            <ul class="warnings">
              {p.report.warnings.map((w) => (
                <li>{w}</li>
              ))}
            </ul>
          ) : null}
        </Card>
      ) : null}
      {plan ? (
        <form method="post" action="/import/cpanel/apply" class="stack">
          <Csrf token={p.csrf} />
          <input type="hidden" name="file" value={plan.archive} />
          <Card title={`cPanel: ${plan.account} (${plan.mainDomain})`}>
            {plan.warnings.length ? (
              <ul class="warnings">
                {plan.warnings.map((w) => (
                  <li>{w}</li>
                ))}
              </ul>
            ) : null}
            <h3>{t("Sites")}</h3>
            <table>
              {plan.sites.map((s) => (
                <tr>
                  <td>
                    <input type="checkbox" name="sites" value={s.name} checked={!s.exists} disabled={s.exists} />
                  </td>
                  <td>
                    {s.name} {s.exists ? <span class="tag">exists</span> : null}
                    {s.warnings.length ? (
                      <ul class="warnings small">
                        {s.warnings.map((w) => (
                          <li>{w}</li>
                        ))}
                      </ul>
                    ) : null}
                  </td>
                  <td>PHP {s.php}</td>
                  <td class="small">{s.domains.join(", ")}</td>
                </tr>
              ))}
            </table>
            <h3>{t("Databases")}</h3>
            <table class="compact">
              {plan.databases.map((d) => (
                <tr>
                  <td>
                    <input type="checkbox" name="databases" value={d.name} checked={!d.exists} disabled={d.exists} />
                  </td>
                  <td>
                    {d.name} {d.exists ? <span class="tag">exists</span> : null}
                  </td>
                  <td class="muted">{fmtBytes(d.bytes)}</td>
                  <td class="small">
                    {plan.users
                      .filter((u) => u.dbs[d.name])
                      .map((u) => `${u.user}${u.hashOk ? "" : " (new password)"}${u.exists ? " (exists, skipped)" : ""}`)
                      .join(", ")}
                  </td>
                </tr>
              ))}
            </table>
            <h3>Not migrated</h3>
            <ul class="warnings">
              {plan.notMigrated.map((n) => (
                <li>
                  <pre class="small">{n}</pre>
                </li>
              ))}
            </ul>
          </Card>
          <div>
            <button class="btn primary">{t("Import selected")}</button>
          </div>
        </form>
      ) : null}
    </>
  );
}

export function ImportPage(p: {
  csrf: string;
  plan?: ImportPlanView;
  snippet: string;
  existing: Set<string>;
  archives: { file: string; bytes: number }[];
  cpPlan?: CpPlanView;
  cpReport?: CpReportView;
}) {
  const plan = p.plan;
  return (
    <div class="stack">
      <CpanelImport csrf={p.csrf} archives={p.archives} plan={p.cpPlan} report={p.cpReport} />
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
