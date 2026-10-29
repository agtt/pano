import { fmtBytes, t } from "../i18n.ts";
import { Badge, Card, Csrf, DangerForm, Field } from "./layout.tsx";

const Otp = () => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />;

export type ContainerRow = {
  name: string;
  image: string;
  port: number;
  host_port: number;
  domains: string[];
  volumes: string[];
  command: string;
  memory_mb: number;
  digest?: string;
  read_only?: number;
  status: { active: string; memory: number };
};
export type Template = { image: string; port: number; volumes: string[]; env: Record<string, string>; memory_mb: number; note: string };
type Draft = Partial<Omit<ContainerRow, "status">> & { env?: Record<string, string> };

export function ContainersPage(p: { csrf: string; installed: boolean; list: ContainerRow[]; templates: Record<string, Template> }) {
  if (!p.installed) {
    return (
      <Card title={t("Containers")}>
        <p>
          Optional. For services that only come as images (Redis, PostgreSQL, Meilisearch, n8n, Uptime Kuma…). Installs Podman from the distribution's
          packages: no background daemon, so nothing runs or uses memory until you add a container.
        </p>
        <p class="muted small">
          Each container is a systemd unit in its own user namespace (root inside is an unprivileged user outside), with a memory cap, published on 127.0.0.1
          only and reachable from outside through the edge with HTTPS when you give it a domain.
        </p>
        <form method="post" action="/containers/install">
          <Csrf token={p.csrf} />
          <Otp />
          <button class="btn primary">Enable containers</button>
        </form>
      </Card>
    );
  }
  return (
    <div class="stack">
      <Card title={t("Containers")} actions={<a class="btn primary" href="/containers/new">+ Container</a>}>
        {p.list.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Name")}</th>
                <th>Image</th>
                <th>Port</th>
                <th>{t("Domains")}</th>
                <th>{t("Status")}</th>
                <th class="num">{t("Memory")}</th>
              </tr>
            </thead>
            <tbody>
              {p.list.map((c) => (
                <tr>
                  <td>
                    <a href={`/containers/${c.name}`}>{c.name}</a>
                  </td>
                  <td class="small">
                    <code>{c.image}</code>
                  </td>
                  <td class="muted">{c.port ? `127.0.0.1:${c.host_port}` : "—"}</td>
                  <td class="muted small">{c.domains.join(", ") || "—"}</td>
                  <td>
                    <Badge state={c.status.active} />
                  </td>
                  <td class="num">{fmtBytes(c.status.memory)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p class="muted">No containers yet.</p>
        )}
      </Card>
      <Card title="Templates">
        <div class="row">
          {Object.entries(p.templates).map(([k, tpl]) => (
            <a class="btn" href={`/containers/new?template=${k}`} title={tpl.image}>
              {k}
            </a>
          ))}
        </div>
      </Card>
    </div>
  );
}

export function ContainerForm(p: { csrf: string; c?: Draft; note?: string; edit?: boolean }) {
  const c = p.c ?? {};
  return (
    <form method="post" action="/containers/save" class="grid-form">
      <Csrf token={p.csrf} />
      {p.edit ? <input type="hidden" name="name" value={c.name} /> : <Field label="Name" name="name" value={c.name} required placeholder="redis" hint="3-24: a-z 0-9 -" />}
      <Field label="Image" name="image" value={c.image} required placeholder="docker.io/library/redis:7-alpine" />
      <Field label="Container port" name="port" type="number" value={c.port || ""} placeholder="6379" hint="published on 127.0.0.1 only" />
      <Field label="Domains" name="domains" value={(c.domains ?? []).join(", ")} placeholder="optional: status.example.com (HTTPS via the edge)" />
      <Field label="Volumes" name="volumes" value={(c.volumes ?? []).join(", ")} placeholder="/data" hint="paths inside the container that keep data" />
      <Field label="Memory limit (MB)" name="memory_mb" type="number" value={c.memory_mb ?? 512} />
      <label class="check">
        <input type="checkbox" name="read_only" value="1" checked={!!c.read_only} /> Read-only root filesystem <span class="muted small">(volumes stay writable; some images need to write elsewhere)</span>
      </label>
      <Field label="Command" name="command" value={c.command} placeholder="optional, overrides the image's command" />
      <label class="field wide">
        <span>{t("Environment variables")}</span>
        <textarea name="env" rows={5} class="mono" spellcheck={false} placeholder="KEY=value">
          {Object.entries(c.env ?? {})
            .map(([k, val]) => `${k}=${val}`)
            .join("\n")}
        </textarea>
        <small class="muted">Empty PASSWORD / KEY / SECRET / TOKEN values are generated. {p.note ?? ""}</small>
      </label>
      <div class="actions">
        <Otp />
        <button class="btn primary">{t("Save")}</button>
      </div>
    </form>
  );
}

export function ContainerDetail(p: { csrf: string; c: ContainerRow & { logs: string; env: Record<string, string>; dataDir: string } }) {
  const c = p.c;
  return (
    <div class="stack">
      <Card
        title={c.name}
        actions={
          <div class="row">
            {(["restart", "stop", "start", "pull"] as const).map((act) => (
              <form method="post" action={`/containers/${c.name}/action`}>
                <Csrf token={p.csrf} />
                <input type="hidden" name="action" value={act} />
                <button class="btn">{act === "pull" ? "Update image" : t(act[0]!.toUpperCase() + act.slice(1))}</button>
              </form>
            ))}
          </div>
        }
      >
        <dl class="kv">
          <dt>{t("Status")}</dt>
          <dd>
            <Badge state={c.status.active} />
          </dd>
          <dt>{t("Memory")}</dt>
          <dd>
            {fmtBytes(c.status.memory)} <span class="muted">/ {c.memory_mb} MB</span>
          </dd>
          <dt>Image</dt>
          <dd>
            <code>{c.image}</code>
          </dd>
          <dt>Digest</dt>
          <dd>
            {c.digest ? <code class="small">{c.digest}</code> : <span class="muted">not pinned yet: runs the tag. "Update image" pins it.</span>}
            {c.digest ? <span class="muted small"> (runs this build; "Update image" re-resolves the tag)</span> : null}
          </dd>
          <dt>Port</dt>
          <dd>{c.port ? `127.0.0.1:${c.host_port} → ${c.port}` : "—"}</dd>
          <dt>{t("Domains")}</dt>
          <dd>{c.domains.join(", ") || "—"}</dd>
          <dt>Data</dt>
          <dd>
            <code>{c.dataDir}</code> <span class="muted small">(add it as a path backup job)</span>
          </dd>
        </dl>
      </Card>
      <Card title={t("Logs")} actions={<a class="btn" href={`/containers/${c.name}`}>↻</a>}>
        <pre class="log">{c.logs || "—"}</pre>
      </Card>
      <Card title={t("Settings")}>
        <ContainerForm csrf={p.csrf} c={c} edit />
      </Card>
      <Card title={t("Delete")} class="danger-zone">
        <DangerForm
          action={`/containers/${c.name}/delete`}
          csrf={p.csrf}
          name={c.name}
          label={t("Delete")}
          extra={
            <label class="check">
              <input type="checkbox" name="removeData" value="1" /> also remove its data ({c.dataDir})
            </label>
          }
        />
      </Card>
    </div>
  );
}
