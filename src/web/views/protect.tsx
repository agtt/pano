import { t } from "../i18n.ts";
import { Card, Csrf, Field } from "./layout.tsx";

export type GuardView = { ssh: boolean; http: boolean; banned: string[] };
export type AlertsView = { chatId: string; tokenSet: boolean };

/** Shown under the read-only audit on the Security page. */
export function ProtectCards(p: { csrf: string; guard: GuardView; alerts: AlertsView; behindCloudflare: boolean }) {
  return (
    <div class="cols">
      <Card title="Guard">
        <form method="post" action="/security/guard">
          <Csrf token={p.csrf} />
          <p class="muted small">In the kernel (nftables): no daemon, no log parsing. WireGuard devices and localhost are never limited.</p>
          <label class="check">
            <input type="checkbox" name="ssh" value="1" checked={p.guard.ssh} /> SSH brute force: more than 20 new connections a minute bans the address for 15
            minutes
          </label>
          <label class="check">
            <input type="checkbox" name="http" value="1" checked={p.guard.http} /> HTTP flood: more than 150 new connections a second from one address are
            dropped{p.behindCloudflare ? " (inactive while behind Cloudflare: visitors arrive from Cloudflare's addresses)" : ""}
          </label>
          {p.guard.banned.length ? <p class="small">Banned now: {p.guard.banned.join(", ")}</p> : null}
          <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required always />
          <button class="btn primary">{t("Save")}</button>
        </form>
      </Card>
      <Card title="Telegram">
        <form method="post" action="/security/alerts">
          <Csrf token={p.csrf} />
          <p class="muted small">
            Failed deploys, crons and backups right away; app or service down, disk over 85%, memory almost full within a minute; and when it clears. Create a
            bot with @BotFather, send it /start, and put your chat id here. Every code used to add an admin, a runner key, a VPN device, a database login or a backup destination, or to export the backup key, is reported here too.
          </p>
          <Field label={p.alerts.tokenSet ? "Bot token (saved; empty = keep)" : "Bot token"} name="token" type="password" autocomplete="off" placeholder="123456:ABC…" />
          <Field label="Chat id" name="chatId" value={p.alerts.chatId} placeholder="123456789" />
          <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required always />
          <div class="row">
            <button class="btn primary">{t("Save")}</button>
            <button class="btn" formaction="/security/alerts/test" formnovalidate>
              Send a test
            </button>
          </div>
        </form>
      </Card>
    </div>
  );
}
