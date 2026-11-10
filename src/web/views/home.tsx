import { fmtBytes, fmtDuration, t } from "../i18n.ts";
import { ServerCharts, type History } from "./charts.tsx";
import { Badge, Card, LangSwitch } from "./layout.tsx";

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

function Stat(p: { label: string; value: string; sub?: string; used?: number; total?: number }) {
  return (
    <div class="stat">
      <span class="muted small">{p.label}</span>
      <strong>{p.value}</strong>
      {p.total !== undefined ? <Meter used={p.used ?? 0} total={p.total} /> : null}
      {p.sub ? <span class="muted small">{p.sub}</span> : null}
    </div>
  );
}

export function HomePage({ info, history }: { info: ServerInfo; history?: History | null }) {
  const memUsed = info.memory.total - info.memory.available;
  const pct = (used: number, total: number) => `${total ? Math.round((used / total) * 100) : 0}%`;
  const edge = info.edge.cutover ? t("Serving :80/:443.") : info.edge.active ? t("Installed, waiting for cutover.") : t("Not installed.");
  return (
    <div class="stack">
      <section class="stats">
        <Stat label={t("Load")} value={(info.load[0] ?? 0).toFixed(2)} sub={`${info.cpus} ${t("CPUs")} · ${t("load average")}`} />
        <Stat label={t("Memory")} value={pct(memUsed, info.memory.total)} used={memUsed} total={info.memory.total} sub={`${fmtBytes(memUsed)} / ${fmtBytes(info.memory.total)}`} />
        <Stat label={t("Disk")} value={pct(info.disk.used, info.disk.size)} used={info.disk.used} total={info.disk.size} sub={`${fmtBytes(info.disk.avail)} ${t("free")}`} />
        <Stat label={t("Uptime")} value={fmtDuration(info.uptime)} sub={`${info.hostname} · ${info.os}`} />
      </section>
      <div class="home">
        <div class="stack">{history ? <Card title={t("Server health")}><ServerCharts h={history} base="/" /></Card> : null}</div>
        <aside class="stack">
          <Card title={t("Edge (Caddy)")} actions={<a class="btn small" href="/edge">{t("Edge")}</a>}>
            <p class="muted">{edge}</p>
            {info.edge.cutover ? null : <p class="muted small">{t("Not taken over yet: the old web server still serves :80/:443.")}</p>}
          </Card>
          <Card title={t("Services")} actions={<a class="btn small" href="/services">{t("Services")}</a>}>
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
          </Card>
        </aside>
      </div>
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
        <p class="login-lang">
          <LangSwitch path="/login" />
        </p>
      </form>
    </div>
  );
}
