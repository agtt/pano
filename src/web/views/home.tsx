import { t } from "../i18n.ts";
import { LangSwitch } from "./layout.tsx";

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
