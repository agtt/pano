import type { Child } from "hono/jsx";
import { t } from "../i18n.ts";

export const NAV: [string, string][] = [
  ["/", "Home"],
  ["/apps", "Apps"],
  ["/sites", "Sites"],
  ["/databases", "Databases"],
  ["/backups", "Backups"],
  ["/runtimes", "Runtimes"],
  ["/edge", "Edge"],
  ["/security", "Security"],
  ["/import", "Import"],
  ["/activity", "Activity"],
];

export type PageProps = { title: string; path: string; csrf?: string; user?: string; flash?: { ok?: string; err?: string }; children?: Child };

export function Layout(p: PageProps) {
  return (
    <html lang="tr">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{`${p.title} · pano`}</title>
        <link rel="stylesheet" href="/static/app.css" />
        <script src="/static/app.js" defer></script>
      </head>
      <body>
        {p.user ? (
          <header class="top">
            <a class="brand" href="/">
              <span class="logo">▦</span> pano
            </a>
            <nav>
              {NAV.map(([href, label]) => (
                <a href={href} class={href === "/" ? (p.path === "/" ? "on" : "") : p.path.startsWith(href) ? "on" : ""}>
                  {t(label)}
                </a>
              ))}
            </nav>
            <form method="post" action="/logout" class="logout">
              <input type="hidden" name="_csrf" value={p.csrf} />
              <span class="muted">{p.user}</span>
              <button class="link">{t("Sign out")}</button>
            </form>
          </header>
        ) : null}
        <main>
          {p.flash?.ok ? <div class="flash ok">{p.flash.ok}</div> : null}
          {p.flash?.err ? <div class="flash err">{p.flash.err}</div> : null}
          {p.children}
        </main>
      </body>
    </html>
  );
}

export const Csrf = ({ token }: { token: string }) => <input type="hidden" name="_csrf" value={token} />;

export function Card(p: { title?: string; actions?: Child; children?: Child; class?: string }) {
  return (
    <section class={`card ${p.class ?? ""}`}>
      {p.title || p.actions ? (
        <div class="card-head">
          {p.title ? <h2>{p.title}</h2> : <span />}
          {p.actions}
        </div>
      ) : null}
      {p.children}
    </section>
  );
}

export function Field(p: { label: string; name: string; value?: string | number; type?: string; placeholder?: string; hint?: string; required?: boolean; autocomplete?: string }) {
  return (
    <label class="field">
      <span>{t(p.label)}</span>
      <input
        name={p.name}
        type={p.type ?? "text"}
        value={p.value === undefined ? "" : String(p.value)}
        placeholder={p.placeholder}
        required={p.required}
        autocomplete={p.autocomplete ?? "off"}
        spellcheck={false}
      />
      {p.hint ? <small class="muted">{p.hint}</small> : null}
    </label>
  );
}

export function Badge({ state }: { state: string }) {
  const cls = /^(active|success|ok|running)$/.test(state) ? "good" : /^(failed|fail|error)$/.test(state) ? "bad" : "neutral";
  return <span class={`badge ${cls}`}>{state}</span>;
}

/** Destructive actions ask for the name and a fresh authenticator code. */
export function DangerForm(p: { action: string; csrf: string; name: string; label: string; extra?: Child }) {
  return (
    <form method="post" action={p.action} class="danger">
      <Csrf token={p.csrf} />
      <label class="field">
        <span>
          {t("Type the name to confirm")}: <code>{p.name}</code>
        </span>
        <input name="confirm" autocomplete="off" required />
      </label>
      <label class="field">
        <span>{t("Current authenticator code")}</span>
        <input name="otp" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required />
      </label>
      {p.extra}
      <button class="btn danger">{p.label}</button>
    </form>
  );
}
