import { fmtBytes, fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf, Field } from "./layout.tsx";

type Locks = { panel: boolean; ssh: boolean; services: boolean };
export type VpnStatus = {
  installed: boolean;
  enabled: boolean;
  running: boolean;
  address: string;
  port: number;
  endpoint: string;
  publicKey: string;
  peers: { id: number; name: string; ip: string; public_key: string; created_at: number; endpoint: string; handshake: number; rx: number; tx: number }[];
  locks: Locks;
  pending: { previous: Locks; deadline: number } | null;
  sshPort: number;
};
export type NewPeer = { name: string; ip: string; config: string; qr: string; generated: boolean };

export function VpnPage(p: { csrf: string; s: VpnStatus; viaVpn: boolean; created?: NewPeer }) {
  const s = p.s;
  if (!s.enabled) {
    return (
      <Card title={t("Private access")}>
        <p>
          Your own WireGuard network, like Tailscale but with nothing in between: no coordination server, no account, no third party. Your laptop and phone
          connect straight to this server; the panel, SSH and databases can then be closed to the rest of the internet.
        </p>
        <p class="muted small">
          Installs wireguard-tools from the distribution. One UDP port opens; WireGuard does not answer anything without a known key, so the port looks closed to
          scanners. Every device gets its own key plus a preshared key (post-quantum safety margin).
        </p>
        <form method="post" action="/vpn/enable">
          <Csrf token={p.csrf} />
          <div class="cols">
            <Field label="UDP port" name="port" value={s.port} />
            <Field label="Public address (empty = detect)" name="endpoint" value={s.endpoint} placeholder="203.0.113.10 or vpn.example.com" />
          </div>
          <button class="btn primary">Enable private access</button>
        </form>
      </Card>
    );
  }
  const left = s.pending ? Math.max(0, Math.round((s.pending.deadline - Date.now()) / 1000)) : 0;
  return (
    <div class="stack">
      {p.created ? <NewPeerCard peer={p.created} /> : null}
      {s.pending ? (
        <div class="flash err">
          New locks are on trial: they are undone automatically in {left}s unless confirmed from a WireGuard device.{" "}
          {p.viaVpn ? (
            <form method="post" action="/vpn/confirm" class="inline">
              <Csrf token={p.csrf} />
              <button class="btn primary">Confirm, it works</button>
            </form>
          ) : (
            <span>
              Open <code>http://{s.address}:7800</code> over WireGuard to confirm.
            </span>
          )}
        </div>
      ) : null}
      <Card title={t("Private access")} actions={<Badge state={s.running ? "active" : "inactive"} />}>
        <dl class="kv">
          <dt>Server</dt>
          <dd>
            <code>{s.address}</code> · UDP <code>{s.endpoint}:{s.port}</code>
          </dd>
          <dt>Public key</dt>
          <dd>
            <code class="small">{s.publicKey}</code>
          </dd>
          <dt>This request</dt>
          <dd>{p.viaVpn ? "over WireGuard" : "not over WireGuard"}</dd>
        </dl>
      </Card>
      <Card title={t("Devices")}>
        {s.peers.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Name")}</th>
                <th>IP</th>
                <th>Last handshake</th>
                <th class="num">In / out</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {s.peers.map((x) => (
                <tr>
                  <td>{x.name}</td>
                  <td>
                    <code>{x.ip}</code>
                  </td>
                  <td class="muted small">{x.handshake ? `${fmtTime(x.handshake)} ${x.endpoint}` : "never"}</td>
                  <td class="num small">
                    {fmtBytes(x.rx)} / {fmtBytes(x.tx)}
                  </td>
                  <td>
                    <form method="post" action="/vpn/peer/remove">
                      <Csrf token={p.csrf} />
                      <input type="hidden" name="id" value={String(x.id)} />
                      <input name="otp" inputmode="numeric" autocomplete="one-time-code" placeholder="2FA" size={6} required />
                      <button class="btn danger small">Revoke</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p class="muted">No devices yet.</p>
        )}
        <form method="post" action="/vpn/peer/add">
          <Csrf token={p.csrf} />
          <div class="cols">
            <Field label="Device name" name="name" required placeholder="laptop" />
            <Field
              label="Device public key (empty = generate, for phones)"
              name="publicKey"
              placeholder="wg genkey | tee key | wg pubkey"
              hint="Best: create the key on the device and paste only its public key; the private key then never exists anywhere else."
            />
          </div>
          <button class="btn primary">+ Device</button>
        </form>
      </Card>
      <Card title="Locks">
        <p class="muted small">
          Locks close ports for everything except WireGuard devices. Open sessions (your current SSH) stay up. A new lock must be confirmed from a WireGuard
          device within the time below, otherwise it is undone by itself, so a mistake cannot lock you out.
        </p>
        <form method="post" action="/vpn/locks">
          <Csrf token={p.csrf} />
          <label class="check">
            <input type="checkbox" name="panel" value="1" checked={s.locks.panel} /> Panel also on <code>http://{s.address}:7800</code> (localhost / SSH tunnel keeps
            working)
          </label>
          <label class="check">
            <input type="checkbox" name="ssh" value="1" checked={s.locks.ssh} /> SSH (port {s.sshPort}) only over WireGuard
          </label>
          <label class="check">
            <input type="checkbox" name="services" value="1" checked={s.locks.services} /> Databases and admin ports (3306, 5432, 6379, 7080, 8090, 8888, 11211)
            only over WireGuard
          </label>
          <div class="cols">
            <Field label="Confirm within (seconds)" name="confirmSeconds" value={300} />
            <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required />
          </div>
          <button class="btn primary">Apply</button>
        </form>
      </Card>
      <Card title="Turn off">
        <form method="post" action="/vpn/disable" class="danger">
          <Csrf token={p.csrf} />
          <p class="muted small">Removes all locks and stops the interface. Devices and keys are kept for when you turn it on again.</p>
          <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required />
          <button class="btn danger">Disable private access</button>
        </form>
      </Card>
    </div>
  );
}

function NewPeerCard({ peer }: { peer: NewPeer }) {
  return (
    <Card title={`${peer.name} · ${peer.ip}`}>
      {peer.generated ? (
        <p class="flash ok">Shown once and not stored on the server. Scan it with the WireGuard app or save the text as {peer.name}.conf now.</p>
      ) : (
        <p class="muted small">Put the device's own private key in place of the placeholder.</p>
      )}
      {peer.qr ? <img class="qr" src={peer.qr} alt="WireGuard QR code" width={260} height={260} /> : null}
      <pre class="secret">{peer.config}</pre>
    </Card>
  );
}
