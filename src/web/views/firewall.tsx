import { t } from "../i18n.ts";
import { Badge, Card, Csrf, alwaysAttr } from "./layout.tsx";

export type FirewallView = {
  installed: boolean;
  on: boolean;
  loaded: boolean;
  confirmIn: number;
  ports: string;
  detected: { ssh: number[]; panel: number | null; wg: number | null; turn: boolean };
};

const Otp = (p: { always?: boolean }) => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" {...alwaysAttr(p.always)} />;

/** Shown on the Security page. Optional: off by default. */
export function FirewallCard({ v, csrf }: { v: FirewallView; csrf: string }) {
  const d = v.detected;
  const pending = v.on && v.confirmIn > 0;
  return (
    <Card title="Firewall" actions={<Badge state={pending ? "pending" : v.on ? "active" : "off"} />}>
      <p class="muted small">
        Optional. If your provider already has a firewall (Hetzner Cloud Firewall, AWS security groups) you do not need this one; it adds a second layer
        on the server itself. When on, everything inbound is dropped except: replies to what the server started, SSH (port {d.ssh.join(", ") || "22"}),
        web 80/443 and HTTP/3 (443/udp), ping and the IPv6 basics{d.panel ? `, the panel (${d.panel})` : ""}
        {d.wg ? `, WireGuard (${d.wg}/udp)` : ""}
        {d.turn ? ", TURN" : ""} and the extra ports below. Ports opened some other way (a database, firewalld) stay closed until listed here.
      </p>
      {pending ? (
        <div class="stack">
          <p class="small">
            <strong>Confirm within {Math.ceil(v.confirmIn / 60)} min</strong> or the firewall switches itself off again. Open the panel in a new tab and
            start a new SSH connection first; only confirm when both work.
          </p>
          <form method="post" action="/security/firewall/confirm" class="row">
            <Csrf token={csrf} />
            <Otp />
            <button class="btn primary">Confirm, keep the firewall on</button>
          </form>
        </div>
      ) : null}
      <form method="post" action="/security/firewall/ports">
        <Csrf token={csrf} />
        <label>
          Extra open ports (one per line: <code>8080</code>, <code>51820/udp</code>, <code>3000-3010/tcp</code>; max 50)
          <textarea name="ports" rows={4} class="mono" spellcheck={false} placeholder={"8080/tcp\n51820/udp"}>
            {v.ports}
          </textarea>
        </label>
        <div class="row">
          <Otp always />
          <button class="btn">{t("Save")}</button>
        </div>
      </form>
      <form method="post" action={v.on ? "/security/firewall/disable" : "/security/firewall/enable"} class="row">
        <Csrf token={csrf} />
        <Otp always={v.on} />
        <button class={v.on ? "btn danger" : "btn primary"}>
          {v.on ? "Turn off" : "Turn on (rolls back unless confirmed)"}
        </button>
      </form>
      {v.on && !v.loaded ? <p class="small">The rules are not loaded right now; they are re-applied within 5 minutes.</p> : null}
    </Card>
  );
}
