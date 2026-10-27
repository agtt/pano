import { formatProcesses, type ProcessSpec } from "../../shared/validate.ts";
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
  processes: (ProcessSpec & { port_a: number; port_b: number })[];
  ask_url: string;
  auto_deploy: number;
  status: { active: string; memory: number; since: string; procs?: { name: string; active: string; memory: number }[] };
  deploys?: { id: number; status: string; trigger: string; commit_sha: string; release: string; error: string; started_at: number; finished_at: number | null }[];
};

export function AppsPage({ apps }: { apps: AppRow[] }) {
  return (
    <Card
      title={t("Apps")}
      actions={
        <span class="row">
          <a class="btn" href="/git">Git</a>
          <a class="btn primary" href="/apps/new">{t("New app")}</a>
        </span>
      }
    >
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
                <td class="muted">
                  {a.processes?.length
                    ? [...new Set(a.processes.flatMap((p) => p.routes.map((r) => r.split("/")[0])))].join(", ")
                    : a.domains.join(", ") || (a.kind === "external" ? a.upstream : "—")}
                </td>
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

const PROCESS_EXAMPLE = `pos    | apps/pos    | example.com, www.example.com | 1024 |
admin  | apps/admin  | admin.example.com            | 768  |
online | apps/online | *.example.com, *             | 1024 |
worker | .           | -                            | 256  | bun packages/api/cron/worker.ts`;

export type RepoOption = { full_name: string; ssh_url: string; default_branch: string; private: boolean };

export function AppForm(p: { csrf: string; app?: Partial<AppRow>; runtimes: { runtime: string; version: string }[]; action: string; submit: string; repos?: RepoOption[] }) {
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
      <label class="field">
        <span>{t("Repository")}</span>
        <input name="repo" value={a.repo} required list="repo-list" placeholder="https://github.com/me/app.git or git@github.com:me/app.git" />
        {p.repos?.length ? (
          <datalist id="repo-list">
            {p.repos.map((r) => (
              <option value={r.ssh_url}>{`${r.full_name}${r.private ? " (private)" : ""} · ${r.default_branch}`}</option>
            ))}
          </datalist>
        ) : null}
      </label>
      <Field label="Branch" name="branch" value={a.branch ?? "main"} required />
      <Field label="Root directory" name="root_dir" value={a.root_dir} placeholder="apps/web (monorepo)" />
      <Field label="Install command" name="install_cmd" value={a.install_cmd} hint={t("Leave empty to detect automatically")} />
      <Field label="Build command" name="build_cmd" value={a.build_cmd} hint={t("Leave empty to detect automatically")} />
      <Field label="Start command" name="start_cmd" value={a.start_cmd} hint={t("Leave empty to detect automatically") + " · $PORT"} />
      <Field label="Health check path" name="health_path" value={a.health_path ?? "/"} />
      <Field label="Memory limit (MB)" name="memory_mb" type="number" value={a.memory_mb ?? 1024} />
      <label class="field wide">
        <span>{t("Processes")} (monorepo)</span>
        <textarea name="processes" rows={5} class="mono" spellcheck={false} placeholder={PROCESS_EXAMPLE}>
          {formatProcesses(a.processes ?? [])}
        </textarea>
        <small class="muted">
          name | dir | routes | memory MB | start command — one build, several processes. Routes: host, host/path, *.host or * (any host); "-" for a worker
          (no port, never runs twice). Empty start: detected. With processes, Domains and Start command above are not used.
        </small>
      </label>
      <Field label="Ask URL (catch-all TLS)" name="ask_url" value={a.ask_url} placeholder="http://127.0.0.1:4100/api/tls-ask" hint="for a * route" />
      <label class="check">
        <input type="hidden" name="auto_deploy" value="0" />
        <input type="checkbox" name="auto_deploy" value="1" checked={a.auto_deploy !== 0} /> {t("Deploy automatically on every push to the branch")}
      </label>
      {a.name ? (
        <Field
          label="Authenticator code"
          name="otp"
          autocomplete="one-time-code"
          hint="Only when changing the repository, branch, directory or commands: they decide what runs with the app's secrets."
        />
      ) : null}
      <div class="actions">
        <button class="btn primary">{t(p.submit)}</button>
      </div>
    </form>
  );
}

export function AppDetail(p: {
  csrf: string;
  app: AppRow;
  env: Record<string, string>;
  logs: string;
  runtimes: { runtime: string; version: string }[];
  deployId?: number;
  hookUrl: string;
  github: { connected: boolean; repo: string };
  revealed?: boolean;
}) {
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
          {a.processes?.length ? null : (
            <>
              <dt>{t("Domains")}</dt>
              <dd>{a.domains.join(", ") || "—"}</dd>
            </>
          )}
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
                {a.active_slot && !a.processes?.length ? `${a.active_slot} → 127.0.0.1:${a.active_slot === "a" ? a.port_a : a.port_b}` : a.active_slot || "—"} ·
                release {a.current_release || "—"}
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
        {a.processes?.length ? (
          <table class="compact">
            <thead>
              <tr>
                <th>{t("Process")}</th>
                <th>{t("Routes")}</th>
                <th>Port</th>
                <th>{t("Status")}</th>
                <th class="num">{t("Memory")}</th>
              </tr>
            </thead>
            {a.processes.map((proc) => {
              const st = a.status.procs?.find((x) => x.name === proc.name);
              const port = proc.port_a ? (a.active_slot === "b" ? proc.port_b : proc.port_a) : 0;
              return (
                <tr>
                  <td>
                    {proc.name} <span class="muted small">{proc.dir || "."}</span>
                  </td>
                  <td class="small">{proc.routes.join(", ") || <span class="tag">worker</span>}</td>
                  <td class="muted">{port || "—"}</td>
                  <td>
                    <Badge state={st?.active ?? "not deployed"} />
                  </td>
                  <td class="num">
                    {st ? fmtBytes(st.memory) : ""} <span class="muted small">/ {proc.memory_mb} MB</span>
                  </td>
                </tr>
              );
            })}
          </table>
        ) : null}
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
              <textarea name="env" rows={8} spellcheck={false} class="mono" placeholder="DATABASE_URL=postgres://...">
                {Object.entries(p.env)
                  .map(([k, val]) => `${k}=${val}`)
                  .join("\n")}
              </textarea>
              <p class="muted small">
                KEY=value, one per line. {p.revealed ? "Values are shown because you asked; they are not cached." : "Values stay hidden (••••••••); a masked line is kept as it is."} Saving
                needs a code. Applied on the next deploy or restart.
              </p>
              <div class="row">
                <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />
                <button class="btn">{t("Save")}</button>
                {p.revealed ? null : (
                  <button class="btn" formaction={`/apps/${a.name}/env/reveal`}>
                    Show values
                  </button>
                )}
              </div>
            </form>
            <form method="post" action={`/apps/${a.name}/database`} class="row">
              <Csrf token={p.csrf} />
              <select name="engine">
                <option value="postgres">PostgreSQL → DATABASE_URL</option>
                <option value="mariadb">MariaDB / MySQL → DATABASE_URL</option>
                <option value="valkey">Valkey / Redis → REDIS_URL</option>
              </select>
              <button class="btn primary">+ Database</button>
              <span class="muted small">Creates the database and its own user (server installed on first use), writes the URL here and restarts the app.</span>
            </form>
          </Card>

          <Card title={`Git · ${t("Webhook")}`}>
            {p.github.connected && p.github.repo ? (
              <form method="post" action={`/apps/${a.name}/github-link`} class="row">
                <Csrf token={p.csrf} />
                <button class="btn primary">Link {p.github.repo}</button>
                <span class="muted small">Adds a read-only deploy key and the push webhook on GitHub; deploys then show as a check on each commit.</span>
              </form>
            ) : p.github.repo ? (
              <p class="muted small">
                <a href="/git">Connect GitHub</a> to link this repository in one click, or set it up by hand below.
              </p>
            ) : null}
            <p class="muted small">{a.auto_deploy !== 0 ? `Every push to ${a.branch} deploys.` : "Automatic deploys are off: pushes are ignored."}</p>
            <form method="post" action={`/apps/${a.name}/deploy-key`} class="row">
              <Csrf token={p.csrf} />
              <button class="btn">Show deploy key</button>
              <span class="muted small">Read-only deploy key for private repos (git@ URL): GitHub, GitLab, Gitea, Forgejo, Bitbucket.</span>
            </form>
            <p class="small">
              GitHub / Gitea / Forgejo webhook: <code>{p.hookUrl}</code> · <code>application/json</code> · event <code>push</code>
              <br />
              GitLab webhook: <code>{p.hookUrl.replace("/hooks/github/", "/hooks/gitlab/")}</code> · secret token = webhook secret · push events
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

export function GitPage(p: { csrf: string; github: { connected: boolean; login: string }; hooksDomain: string }) {
  return (
    <div class="stack">
      <Card title="GitHub">
        {p.github.connected ? (
          <>
            <p>
              Connected as <b>{p.github.login}</b>. New apps can pick a repository from the list, and "Link" on an app adds its deploy key and webhook. Each deploy
              reports back to the commit as the <code>pano/deploy</code> check.
            </p>
            <form method="post" action="/git/github/disconnect" class="row">
              <Csrf token={p.csrf} />
              <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />
              <button class="btn danger">Disconnect</button>
            </form>
          </>
        ) : (
          <form method="post" action="/git/github/connect">
            <Csrf token={p.csrf} />
            <p class="muted small">
              Create a fine-grained token on GitHub (Settings → Developer settings → Fine-grained tokens), limited to the repositories you deploy, with
              repository permissions: Contents read, Metadata read, Administration read and write (deploy keys), Webhooks read and write, Commit statuses read
              and write. It is stored root-only on this server and never shown again.
            </p>
            <Field label="Token" name="token" type="password" autocomplete="off" required placeholder="github_pat_…" />
            <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required />
            <button class="btn primary">Connect GitHub</button>
          </form>
        )}
      </Card>
      <Card title="GitLab · Gitea · Forgejo · Bitbucket">
        <p class="muted small">
          No token needed: add the app's deploy key (read-only) to the repository and the webhook shown on the app page. GitLab sends the webhook secret as its
          secret token; Gitea and Forgejo sign like GitHub.
        </p>
      </Card>
      {p.hooksDomain ? null : (
        <p class="flash err">
          Automatic deploys need a webhook domain so the Git host can reach this server: <a href="/edge">Edge page</a>.
        </p>
      )}
    </div>
  );
}
