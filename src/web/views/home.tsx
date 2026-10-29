import { fmtBytes, fmtDuration, t } from "../i18n.ts";
import { ServerCharts, type History } from "./charts.tsx";
import { Badge, Card } from "./layout.tsx";

const TILES: { href: string; label: string; icon: string; desc: string }[] = [
  { href: "/apps", label: "Apps", icon: "▶", desc: "Next.js · Node.js · Bun" },
  { href: "/apps/new", label: "New app", icon: "+", desc: "git → build → live" },
  { href: "/sites", label: "Sites", icon: "◎", desc: "proxy · static · legacy PHP" },
  { href: "/databases", label: "Databases", icon: "⛁", desc: "MariaDB / MySQL" },
  { href: "/backups", label: "Backups", icon: "⇪", desc: "Cloudflare R2, encrypted" },
  { href: "/runtimes", label: "Runtimes", icon: "⬢", desc: "Node.js · Bun versions" },
  { href: "/edge", label: "Edge", icon: "⚿", desc: "Caddy · HTTPS · HTTP/3" },
  { href: "/security", label: "Security", icon: "⛨", desc: "Audit and fixes" },
  { href: "/import", label: "Import", icon: "⇲", desc: "From CyberPanel" },
  { href: "/activity", label: "Activity", icon: "≡", desc: "Who did what" },
];

export type ServerInfo = {
  hostname: string;
  os: string;
  cpus: number;
  load: number[];
  uptime: number;
  memory: { total: number; available: number };
  disk: { size: number; used: number; avail: number };
  services: { unit: string; state: string; memory: number }[];
  edge: { active: boolean; cutover: boolean };
};

// Native <meter>: no inline styles, so the strict CSP stays intact.
function Meter({ used, total }: { used: number; total: number }) {
  return <meter class="meter" min={0} max={total || 1} value={used} high={(total || 1) * 0.85} optimum={0} />;
}

export function HomePage({ info, history }: { info: ServerInfo; history?: History | null }) {
  const memUsed = info.memory.total - info.memory.available;
  return (
    <div class="home">
      <div>
        <p class="lead">{t("Apps, databases, backups and security on one lightweight panel.")}</p>
        <div class="tiles">
          {TILES.map((x) => (
            <a class="tile" href={x.href}>
              <span class="icon">{x.icon}</span>
              <strong>{t(x.label)}</strong>
              <small class="muted">{x.desc}</small>
            </a>
          ))}
        </div>
        {history ? <ServerCharts h={history} base="/" /> : null}
      </div>
      <aside>
        <Card title={t("Server")}>
          <dl class="kv">
            <dt>Host</dt>
            <dd>{info.hostname}</dd>
            <dt>OS</dt>
            <dd>{info.os}</dd>
            <dt>CPU</dt>
            <dd>{info.cpus}</dd>
            <dt>{t("Load")}</dt>
            <dd>{info.load.map((l) => l.toFixed(2)).join(" · ")}</dd>
            <dt>{t("Uptime")}</dt>
            <dd>{fmtDuration(info.uptime)}</dd>
          </dl>
          <p class="meter-label">
            {t("Memory")} <span class="muted">{fmtBytes(memUsed)} / {fmtBytes(info.memory.total)}</span>
          </p>
          <Meter used={memUsed} total={info.memory.total} />
          <p class="meter-label">
            {t("Disk")} <span class="muted">{fmtBytes(info.disk.used)} / {fmtBytes(info.disk.size)}</span>
          </p>
          <Meter used={info.disk.used} total={info.disk.size} />
        </Card>
        <Card title={t("Services")}>
          <table class="compact">
            {info.services.map((s) => (
              <tr>
                <td>{s.unit}</td>
                <td>
                  <Badge state={s.state} />
                </td>
                <td class="num muted">{s.memory ? fmtBytes(s.memory) : ""}</td>
              </tr>
            ))}
          </table>
          <p class="muted small">
            Edge: {info.edge.active ? "active" : "inactive"} · cutover: {info.edge.cutover ? "done" : "not yet"}
          </p>
        </Card>
      </aside>
    </div>
  );
}

export function LoginPage({ error }: { error?: string }) {
  return (
    <div class="login">
      <form method="post" action="/login" class="card">
        <h1>
          <span class="logo">▦</span> pano
        </h1>
        {error ? <div class="flash err">{error}</div> : null}
        <label class="field">
          <span>{t("Username")}</span>
          <input name="username" autocomplete="username" required autofocus />
        </label>
        <label class="field">
          <span>{t("Password")}</span>
          <input name="password" type="password" autocomplete="current-password" required />
        </label>
        <label class="field">
          <span>{t("Authenticator code")}</span>
          <input name="otp" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required />
        </label>
        <button class="btn primary">{t("Sign in")}</button>
      </form>
    </div>
  );
}
