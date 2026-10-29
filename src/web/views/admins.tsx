import { fmtTime, t } from "../i18n.ts";
import { Card, Csrf, Field } from "./layout.tsx";

export type AdminRow = { username: string; created_at: number; last_login: number; twofa: boolean };
/** Shown once, right after an admin is added or reset; nothing here is kept. */
export type AdminSecret = { username: string; password?: string; secret?: string; uri?: string; qr?: string; reason: string };

function NewSecretCard({ s }: { s: AdminSecret }) {
  return (
    <Card title={`${s.username} · ${s.reason}`}>
      <p class="flash ok">{t("Shown once and not stored. Pass it to the admin now; their old sessions were signed out.")}</p>
      {s.password ? (
        <>
          <p class="muted small">{t("One-time password")}</p>
          <pre class="secret">{s.password}</pre>
        </>
      ) : null}
      {s.secret ? (
        <>
          <p class="muted small">{t("Authenticator app")}</p>
          {s.qr ? <img class="qr" src={s.qr} alt="Authenticator QR code" width={200} height={200} /> : null}
          <pre class="secret">{s.secret}</pre>
          <p class="muted small">
            <code class="secret">{s.uri}</code>
          </p>
        </>
      ) : null}
    </Card>
  );
}

export function AdminsPage(p: { csrf: string; me: string; admins: AdminRow[]; created?: AdminSecret }) {
  return (
    <div class="stack">
      {p.created ? <NewSecretCard s={p.created} /> : null}
      <Card title={t("Admins")}>
        <p class="muted small">
          {t("All admins are equal: there are no roles. Every admin can do everything here, including adding and removing other admins.")}{" "}
          {t("Every change below needs your own authenticator code. You cannot remove yourself or the last admin. Removing or resetting an admin signs them out.")}
        </p>
        <table>
          <thead>
            <tr>
              <th>{t("User")}</th>
              <th>{t("Created")}</th>
              <th>{t("Last login")}</th>
              <th>2FA</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {p.admins.map((a) => (
              <tr>
                <td>
                  {a.username} {a.username === p.me ? <span class="muted small">({t("you")})</span> : null}
                </td>
                <td class="muted small">{fmtTime(a.created_at)}</td>
                <td class="muted small">{fmtTime(a.last_login)}</td>
                <td>{a.twofa ? t("set") : t("missing")}</td>
                <td>
                  <form method="post" action={`/admins/${encodeURIComponent(a.username)}`}>
                    <Csrf token={p.csrf} />
                    <input name="otp" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="2FA" size={6} required />
                    <button class="btn small" name="do" value="password">
                      {t("Reset password")}
                    </button>{" "}
                    <button class="btn small" name="do" value="2fa">
                      {t("Reset 2FA")}
                    </button>{" "}
                    {a.username === p.me ? null : (
                      <button class="btn danger small" name="do" value="remove">
                        {t("Remove")}
                      </button>
                    )}
                  </form>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Card title={t("Add admin")}>
        <form method="post" action="/admins">
          <Csrf token={p.csrf} />
          <div class="cols">
            <Field label="Username" name="username" required placeholder="alice" hint="3-32 lowercase letters, digits, _ . -" />
            <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required />
          </div>
          <p class="muted small">{t("A password and an authenticator secret are generated and shown once.")}</p>
          <button class="btn primary">+ {t("Admin")}</button>
        </form>
      </Card>
    </div>
  );
}
