import type { Child } from "hono/jsx";
import { assets } from "../assets.ts";
import { LANGS, lang, t } from "../i18n.ts";

/** The sidebar, grouped by what you came to do. Every page keeps its own URL. */
export const NAV_GROUPS: { title: string; items: [href: string, label: string][] }[] = [
  { title: "", items: [["/", "Overview"]] },
  {
    title: "Hosting",
    items: [
      ["/apps", "Apps"],
      ["/sites", "Sites"],
      ["/databases", "Databases"],
      ["/env-groups", "Shared variables"],
    ],
  },
  {
    title: "Operations",
    items: [
      ["/services", "Services"],
      ["/jobs", "Jobs"],
      ["/backups", "Backups"],
      ["/containers", "Containers"],
      ["/runtimes", "Runtimes"],
    ],
  },
  {
    title: "Protection",
    items: [
      ["/edge", "Edge"],
      ["/security", "Security"],
      ["/shield", "Shield"],
      ["/vpn", "Private access"],
      ["/admins", "Admins"],
      ["/activity", "Activity"],
    ],
  },
  {
    title: "Tools",
    items: [
      ["/import", "Import"],
      ["/android", "Android"],
      ["/runner", "Runner"],
    ],
  },
];
export const NAV: [string, string][] = NAV_GROUPS.flatMap((g) => g.items);

export type PageProps = { title: string; path: string; csrf?: string; user?: string; flash?: { ok?: string; err?: string }; children?: Child };

const isOn = (href: string, path: string) => (href === "/" ? path === "/" : path === href || path.startsWith(`${href}/`));

/** EN · TR links; the current one is plain text. */
export function LangSwitch({ path }: { path: string }) {
  const now = lang();
  return (
    <span class="lang" aria-label={t("Language")}>
      {LANGS.map((l, i) => (
        <>
          {l.code === now ? (
            <strong title={l.label}>{l.code.toUpperCase()}</strong>
          ) : (
            <a href={`/lang/${l.code}?next=${encodeURIComponent(path)}`} title={l.label} lang={l.code}>
              {l.code.toUpperCase()}
            </a>
          )}
        </>
      ))}
    </span>
  );
}

export function Layout(p: PageProps) {
  return (
    <html lang={lang()}>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{`${p.title} · pano`}</title>
        <link rel="stylesheet" href={assets.css.url} />
        <script src={assets.js.url} defer></script>
      </head>
      <body class={p.user ? "with-side" : ""}>
        {p.user ? (
          <aside class="side">
            <div class="side-top">
              <a class="brand" href="/">
                <span class="logo">▦</span> pano
              </a>
              {/* No JavaScript needed: the checkbox opens the menu on small screens. */}
              <input type="checkbox" id="nav-toggle" class="nav-toggle" />
              <label for="nav-toggle" class="nav-button">{t("Menu")}</label>
            </div>
            <nav>
              {NAV_GROUPS.map((g) => (
                <div class="nav-group">
                  {g.title ? <div class="nav-title">{t(g.title)}</div> : null}
                  {g.items.map(([href, label]) => (
                    <a href={href} class={isOn(href, p.path) ? "on" : ""} aria-current={isOn(href, p.path) ? "page" : undefined}>
                      {t(label)}
                    </a>
                  ))}
                </div>
              ))}
              <form method="post" action="/logout" class="side-foot">
                <input type="hidden" name="_csrf" value={p.csrf} />
                <span class="who">{p.user}</span>
                <LangSwitch path={p.path} />
                <button class="link">{t("Sign out")}</button>
              </form>
            </nav>
          </aside>
        ) : null}
        <main>
          {p.user ? <h1 class="page-title">{p.title}</h1> : null}
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
