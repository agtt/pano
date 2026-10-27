import { fmtBytes, fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf, DangerForm, Field } from "./layout.tsx";

export type AppRow = {
  name: string;
  kind: "managed" | "external";
  domains: string[];
  runtime: string;
  runtime_version: string;
  repo: string;
  branch: string;
  root_dir: string;
  install_cmd: string;
  build_cmd: string;
  start_cmd: string;
  health_path: string;
  memory_mb: number;
  port_a: number;
  port_b: number;
  active_slot: string;
  current_release: string;
  upstream: string;
  external_unit: string;
  status: { active: string; memory: number; since: string };
  deploys?: { id: number; status: string; trigger: string; commit_sha: string; release: string; error: string; started_at: number; finished_at: number | null }[];
};

export function AppsPage({ apps }: { apps: AppRow[] }) {
  return (
    <Card title={t("Apps")} actions={<a class="btn primary" href="/apps/new">{t("New app")}</a>}>
      {apps.length ? (
        <table>
          <thead>
            <tr>
              <th>{t("Name")}</th>
              <th>{t("Domains")}</th>
              <th>{t("Runtime")}</th>
              <th>{t("Status")}</th>
              <th class="num">{t("Memory")}</th>
            </tr>
          </thead>
          <tbody>
            {apps.map((a) => (
              <tr>
                <td>
                  <a href={`/apps/${a.name}`}>{a.name}</a>
                  {a.kind === "external" ? <span class="tag">external</span> : null}
                </td>
                <td class="muted">{a.domains.join(", ") || (a.kind === "external" ? a.upstream : "—")}</td>
                <td>{a.kind === "managed" ? `${a.runtime} ${a.runtime_version}` : a.external_unit}</td>
                <td>
                  <Badge state={a.status.active} />
                </td>
                <td class="num">{a.status.memory ? fmtBytes(a.status.memory) : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p class="muted">{t("No apps yet.")}</p>
      )}
    </Card>
  );
}

export function AppForm(p: { csrf: string; app?: Partial<AppRow>; runtimes: { runtime: string; version: string }[]; action: string; submit: string }) {
  const a = p.app ?? {};
  const opts = p.runtimes.map((r) => `${r.runtime}@${r.version}`);
  const current = a.runtime ? `${a.runtime}@${a.runtime_version}` : opts[0];
  return (
    <form method="post" action={p.action} class="grid-form">
      <Csrf token={p.csrf} />
      {a.name ? <input type="hidden" name="name" value={a.name} /> : <Field label="Name" name="name" required placeholder="my-app" hint="3-24: a-z 0-9 -" />}
      <Field label="Domains" name="domains" value={(a.domains ?? []).join(", ")} placeholder="example.com, www.example.com" />
      <label class="field">
        <span>{t("Runtime")}</span>
        <select name="runtime_ref" required>
          {opts.length ? null : <option value="">— install a runtime first —</option>}
          {opts.map((o) => (
            <option value={o} selected={o === current}>
              {o.replace("@", " ")}
            </option>
          ))}
        </select>
      </label>
      <Field label="Repository" name="repo" value={a.repo} required placeholder="https://github.com/me/app.git or git@github.com:me/app.git" />
      <Field label="Branch" name="branch" value={a.branch ?? "main"} required />
      <Field label="Root directory" name="root_dir" value={a.root_dir} placeholder="apps/web (monorepo)" />
      <Field label="Install command" name="install_cmd" value={a.install_cmd} hint={t("Leave empty to detect automatically")} />
      <Field label="Build command" name="build_cmd" value={a.build_cmd} hint={t("Leave empty to detect automatically")} />
      <Field label="Start command" name="start_cmd" value={a.start_cmd} hint={t("Leave empty to detect automatically") + " · $PORT"} />
      <Field label="Health check path" name="health_path" value={a.health_path ?? "/"} />
      <Field label="Memory limit (MB)" name="memory_mb" type="number" value={a.memory_mb ?? 1024} />
      <div class="actions">
        <button class="btn primary">{t(p.submit)}</button>
      </div>
    </form>
  );
}

export function AppDetail(p: { csrf: string; app: AppRow; env: Record<string, string>; logs: string; runtimes: { runtime: string; version: string }[]; deployId?: number; hookUrl: string }) {
  const a = p.app;
  const managed = a.kind === "managed";
  return (
    <div class="stack">
      <Card
        title={a.name}
        actions={
          <div class="row">
            {managed ? (
              <form method="post" action={`/apps/${a.name}/deploy`}>
                <Csrf token={p.csrf} />
                <button class="btn primary">{t("Deploy")}</button>
              </form>
            ) : null}
            {(["restart", "stop", "start"] as const).map((act) => (
              <form method="post" action={`/apps/${a.name}/action`}>
                <Csrf token={p.csrf} />
                <input type="hidden" name="action" value={act} />
                <button class="btn">{t(act[0]!.toUpperCase() + act.slice(1))}</button>
              </form>
            ))}
          </div>
        }
      >
        <dl class="kv">
          <dt>{t("Status")}</dt>
          <dd>
            <Badge state={a.status.active} /> <span class="muted">{a.status.since}</span>
          </dd>
          <dt>{t("Memory")}</dt>
          <dd>
            {fmtBytes(a.status.memory)} {managed ? <span class="muted">/ {a.memory_mb} MB</span> : null}
          </dd>
          <dt>{t("Domains")}</dt>
          <dd>{a.domains.join(", ") || "—"}</dd>
          {managed ? (
            <>
              <dt>{t("Runtime")}</dt>
              <dd>
                {a.runtime} {a.runtime_version}
              </dd>
              <dt>{t("Repository")}</dt>
              <dd>
                <code>{a.repo}</code> @ {a.branch}
              </dd>
              <dt>Slot</dt>
              <dd>
                {a.active_slot ? `${a.active_slot} → 127.0.0.1:${a.active_slot === "a" ? a.port_a : a.port_b}` : "—"} · release {a.current_release || "—"}
              </dd>
            </>
          ) : (
            <>
              <dt>Unit</dt>
              <dd>
                <code>{a.external_unit}</code>
              </dd>
              <dt>Upstream</dt>
              <dd>{a.upstream}</dd>
            </>
          )}
        </dl>
      </Card>

      {p.deployId ? (
        <Card title={`Deploy #${p.deployId}`}>
          <pre class="log" data-deploy-log={`/apps/${a.name}/deploys/${p.deployId}/log`}></pre>
        </Card>
      ) : null}

      {managed && a.deploys?.length ? (
        <Card title={t("Deploy history")}>
          <table class="compact">
            {a.deploys.map((d) => (
              <tr>
                <td>
                  <a href={`/apps/${a.name}?deploy=${d.id}`}>#{d.id}</a>
                </td>
                <td>
                  <Badge state={d.status} />
                </td>
                <td class="muted">{d.trigger}</td>
                <td>
                  <code>{d.commit_sha.slice(0, 7)}</code>
                </td>
                <td class="muted">{fmtTime(d.started_at)}</td>
                <td class="muted small">{d.error}</td>
              </tr>
            ))}
          </table>
        </Card>
      ) : null}

      <Card title={t("Logs")} actions={<a class="btn" href={`/apps/${a.name}`}>↻</a>}>
        <pre class="log">{p.logs || "—"}</pre>
      </Card>

      {managed ? (
        <>
          <Card title={t("Environment variables")}>
            <form method="post" action={`/apps/${a.name}/env`}>
              <Csrf token={p.csrf} />
              <textarea name="env" rows={8} spellcheck={false} class="mono" placeholder="DATABASE_URL=mysql://...">
                {Object.entries(p.env)
                  .map(([k, val]) => `${k}=${val}`)
                  .join("\n")}
              </textarea>
              <p class="muted small">KEY=value, one per line. Applied on the next deploy or restart.</p>
              <button class="btn">{t("Save")}</button>
            </form>
          </Card>

          <Card title={`${t("Deploy key")} · ${t("Webhook")}`}>
            <form method="post" action={`/apps/${a.name}/deploy-key`} class="row">
              <Csrf token={p.csrf} />
              <button class="btn">Show deploy key</button>
              <span class="muted small">Add it as a read-only deploy key on the repository (private repos, git@ URL).</span>
            </form>
            <p>
              GitHub webhook: <code>{p.hookUrl}</code> · content type <code>application/json</code> · event <code>push</code>
            </p>
            <form method="post" action={`/apps/${a.name}/webhook-secret`} class="row">
              <Csrf token={p.csrf} />
              <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />
              <button class="btn">Show webhook secret</button>
            </form>
          </Card>

          <Card title={t("Settings")}>
            <AppForm csrf={p.csrf} app={a} runtimes={p.runtimes} action={`/apps/${a.name}/settings`} submit="Save" />
          </Card>
        </>
      ) : null}

      <Card title={t("Delete")} class="danger-zone">
        <DangerForm
          action={`/apps/${a.name}/delete`}
          csrf={p.csrf}
          name={a.name}
          label={t("Delete")}
          extra={
            managed ? (
              <label class="check">
                <input type="checkbox" name="removeFiles" value="1" /> also remove files and the system user
              </label>
            ) : null
          }
        />
      </Card>
    </div>
  );
}
