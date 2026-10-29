import { t } from "../i18n.ts";
import { Card, Csrf } from "./layout.tsx";

export type EnvGroupRow = { name: string; keys: string[]; apps: string[] };

const envText = (vars: Record<string, string>) =>
  Object.entries(vars)
    .map(([k, val]) => `${k}=${val}`)
    .join("\n");

/** Shared variables: groups kept once and given to several apps (Settings → Shared variables). */
export function EnvGroupsPage(p: { csrf: string; groups: EnvGroupRow[]; edit?: { name: string; vars: Record<string, string>; revealed: boolean } }) {
  return (
    <div class="stack">
      <Card title={t("Shared variables")}>
        <p class="muted small">
          A group of variables (a payment key, an error tracker, mail settings) kept once and given to the apps that list it in their settings. Stored
          root-only; an app's own value wins. A change reaches each app at its next restart (the app page says so).
        </p>
        {p.groups.length ? (
          <table class="compact">
            <thead>
              <tr>
                <th>{t("Name")}</th>
                <th>Variables</th>
                <th>Apps</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {p.groups.map((g) => (
                <tr>
                  <td>
                    <a href={`/env-groups?edit=${g.name}`}>{g.name}</a>
                  </td>
                  <td class="small mono">{g.keys.join(", ") || "—"}</td>
                  <td class="small">{g.apps.length ? g.apps.map((a) => <a href={`/apps/${a}`}>{a} </a>) : <span class="muted">none</span>}</td>
                  <td>
                    {g.apps.length ? null : (
                      <form method="post" action={`/env-groups/${g.name}/delete`} class="row">
                        <Csrf token={p.csrf} />
                        <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />
                        <button class="btn danger">{t("Delete")}</button>
                      </form>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p class="muted small">No groups yet.</p>
        )}
      </Card>

      <Card title={p.edit ? `Group ${p.edit.name}` : "New group"}>
        <form method="post" action="/env-groups">
          <Csrf token={p.csrf} />
          {p.edit ? (
            <input type="hidden" name="name" value={p.edit.name} />
          ) : (
            <label class="field">
              <span>{t("Name")}</span>
              <input name="name" required pattern="[a-z][a-z0-9\-]{0,31}" placeholder="stripe" />
            </label>
          )}
          <textarea name="env" rows={6} spellcheck={false} class="mono" placeholder="STRIPE_SECRET_KEY=sk_live_...">
            {envText(p.edit?.vars ?? {})}
          </textarea>
          <p class="muted small">
            KEY=value, one per line. {p.edit?.revealed ? "Values are shown because you asked; they are not cached." : "Values stay hidden (••••••••); a masked line is kept as it is."}
          </p>
          <div class="row">
            <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" />
            <button class="btn primary">{t("Save")}</button>
            {p.edit && !p.edit.revealed ? (
              <button class="btn" formaction={`/env-groups/${p.edit.name}/reveal`}>
                Show values
              </button>
            ) : null}
          </div>
        </form>
      </Card>
    </div>
  );
}
