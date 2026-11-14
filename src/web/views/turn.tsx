import { fmtBytes, t } from "../i18n.ts";
import { Badge, Card, Csrf, DangerForm, Field, alwaysAttr } from "./layout.tsx";

export type TurnView = {
  installed: boolean;
  managed: boolean;
  active: string;
  memory: number;
  domain: string;
  urls: string[];
  tls?: boolean;
  tlsPort?: number;
  allocations: number;
  port: number;
  relay: { min: number; max: number };
};

const Otp = (p: { always?: boolean }) => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder="2FA" size={6} class="short" required {...alwaysAttr(p.always)} />;

export function TurnCard({ v, csrf, appNames }: { v: TurnView; csrf: string; appNames: string[] }) {
  if (!v.installed || !v.managed) {
    return (
      <Card title="TURN (calls and games)" actions={v.installed ? <Badge state={v.active || "unknown"} /> : null}>
        <p class="muted small">
          A relay for WebRTC: voice and video calls and peer-to-peer game data that cannot connect directly behind NAT. coturn, about 10 MB of memory. Apps get
          a secret and hand each user credentials that expire in an hour; the relay never reaches this server or private networks.
          {v.installed ? " A coturn is already running here: installing takes it over and keeps its secret, so clients that use it keep working." : ""}
        </p>
        <form method="post" action="/services/turn/install">
          <Csrf token={csrf} />
          <Otp />
          <button class="btn primary">{v.installed ? "Take over" : t("Install")}</button>
        </form>
      </Card>
    );
  }
  return (
    <Card title="TURN (calls and games)" actions={<Badge state={v.active || "unknown"} />}>
      <p class="muted small">
        UDP and TCP {v.port}, relay ports {v.relay.min}–{v.relay.max}/udp · {fmtBytes(v.memory)} · {v.allocations} relayed sessions now · updated with the OS
        security updates
      </p>
      <pre class="log small">{v.urls.join("\n")}</pre>
      <form method="post" action="/services/turn/domain" class="row">
        <Csrf token={csrf} />
        <Field label="Domain (optional)" name="domain" value={v.domain} placeholder="turn.example.com" hint="A DNS-only (grey cloud) record to this server." />
        <Otp />
        <button class="btn">{t("Save")}</button>
      </form>
      {v.domain ? (
        <form method="post" action="/services/turn/tls" class="row">
          <Csrf token={csrf} />
          <input type="hidden" name="on" value={v.tls ? "0" : "1"} />
          <Otp />
          <button class="btn small">{v.tls ? "Turn off TLS" : `Turn on TLS (turns: ${v.tlsPort ?? 5349})`}</button>
          <small class="muted">
            {v.tls
              ? "Clients can also reach the relay over an encrypted TCP connection (turns:)."
              : "Optional. Uses the edge's certificate for the domain above (its DNS record must point here, edge installed)."}
          </small>
        </form>
      ) : null}
      <div class="cols">
        {appNames.length ? (
          <form method="post" action="/services/turn/to-app" class="grid-form">
            <Csrf token={csrf} />
            <label class="field">
              <span>{t("Apps")}</span>
              <select name="app">
                {appNames.map((n) => (
                  <option value={n}>{n}</option>
                ))}
              </select>
            </label>
            <div class="actions">
              <Otp />
              <button class="btn">Add to app environment</button>
            </div>
            <small class="muted">Sets TURN_URLS and TURN_SECRET (server only) and NEXT_PUBLIC_TURN_URLS; restarts the app.</small>
          </form>
        ) : null}
        <div class="row">
          <form method="post" action="/services/turn/reveal" class="inline">
            <Csrf token={csrf} />
            <Otp always />
            <button class="btn small">Secret</button>
          </form>
          <form method="post" action="/services/turn/rotate" class="inline">
            <Csrf token={csrf} />
            <Otp />
            <button class="btn small" title="Apps with TURN_SECRET get the new one and restart">
              New secret
            </button>
          </form>
        </div>
      </div>
      <details>
        <summary class="muted small">Server example (credentials for one user)</summary>
        <pre class="log small">{`import { createHmac } from "node:crypto";
const username = \`\${Math.floor(Date.now() / 1000) + 3600}:\${userId}\`;
const credential = createHmac("sha1", process.env.TURN_SECRET!).update(username).digest("base64");
// to the browser: { iceServers: [{ urls: process.env.TURN_URLS!.split(","), username, credential }] }`}</pre>
      </details>
      <details>
        <summary class="muted small">{t("Delete")}</summary>
        <DangerForm action="/services/turn/uninstall" csrf={csrf} name="turn" label="Uninstall (a coturn that was here before gets its own config back)" />
      </details>
    </Card>
  );
}
