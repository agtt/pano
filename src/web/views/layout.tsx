import type { Child } from "hono/jsx";
import { assets } from "../assets.ts";
import { LANGS, lang, t } from "../i18n.ts";

import { Icon, type IconName } from "./icons.tsx";

type NavItem = [href: string, label: string, icon: IconName];

/** The sidebar, grouped by what you came to do. Every page keeps its own URL. */
export const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  { title: "", items: [["/", "Overview", "overview"]] },
  {
    title: "Hosting",
    items: [
      ["/apps", "Apps", "apps"],
      ["/sites", "Sites", "sites"],
      ["/databases", "Databases", "databases"],
      ["/env-groups", "Shared variables", "variables"],
    ],
  },
  {
    title: "Operations",
    items: [
      ["/services", "Services", "services"],
      ["/jobs", "Jobs", "jobs"],
      ["/backups", "Backups", "backups"],
      ["/containers", "Containers", "containers"],
      ["/runtimes", "Runtimes", "runtimes"],
    ],
  },
  {
    title: "Protection",
    items: [
      ["/edge", "Edge", "edge"],
      ["/security", "Security", "security"],
      ["/shield", "Shield", "shield"],
      ["/vpn", "Private access", "vpn"],
      ["/admins", "Admins", "admins"],
      ["/activity", "Activity", "activity"],
    ],
  },
  {
    title: "Tools",
    items: [
      ["/import", "Import", "import"],
      ["/android", "Android", "android"],
      ["/runner", "Runner", "runner"],
    ],
  },
];
export const NAV: [string, string][] = NAV_GROUPS.flatMap((g) => g.items.map(([href, label]) => [href, label] as [string, string]));

export type PageProps = { title: string; path: string; csrf?: string; user?: string; flash?: { ok?: string; err?: string }; children?: Child };

const isOn = (href: string, path: string) => (href === "/" ? path === "/" : path === href || path.startsWith(`${href}/`));

/** EN / TR links; the current one is plain text. */
export function LangSwitch({ path }: { path: string }) {
  const now = lang();
  return (
    <span class="lang" aria-label={t("Language")}>
      {LANGS.map((l) =>
        l.code === now ? (
          <strong title={l.label}>{l.code.toUpperCase()}</strong>
        ) : (
          <a href={`/lang/${l.code}?next=${encodeURIComponent(path)}`} title={l.label} lang={l.code}>
            {l.code.toUpperCase()}
          </a>
        ),
      )}
    </span>
  );
}

/** Where the page sits in the menu: its group, for the breadcrumb. */
function sectionOf(path: string): { group: string; item?: NavItem } {
  for (const g of NAV_GROUPS) for (const it of g.items) if (isOn(it[0], path)) return { group: g.title, item: it };
  return { group: "" };
}

function Sidebar(p: PageProps) {
  return (
    <aside class="side" id="side">
      <a class="brand" href="/">
        <span class="logo" aria-hidden="true">
          <Icon name="overview" size={16} />
        </span>
        pano
      </a>
      <label class="side-search">
        <Icon name="search" size={16} />
        <input type="search" id="nav-search" placeholder={t("Search menu")} aria-label={t("Search menu")} autocomplete="off" />
        <kbd>⌘K</kbd>
      </label>
      <nav aria-label={t("Menu")}>
        {NAV_GROUPS.map((g) => (
          <div class="nav-group">
            {g.title ? <div class="nav-title">{t(g.title)}</div> : null}
            {g.items.map(([href, label, icon]) => (
              <a href={href} class={isOn(href, p.path) ? "on" : ""} aria-current={isOn(href, p.path) ? "page" : undefined} data-nav={`${t(label)} ${label}`.toLowerCase()}>
                <Icon name={icon} />
                <span>{t(label)}</span>
              </a>
            ))}
          </div>
        ))}
        <p class="nav-empty" hidden>
          {t("No matching menu items")}
        </p>
      </nav>
      <div class="side-foot">
        <LangSwitch path={p.path} />
        <span class="muted small">pano</span>
      </div>
    </aside>
  );
}

function Topbar(p: PageProps) {
  const { group, item } = sectionOf(p.path);
  const initial = (p.user ?? "?").slice(0, 1).toUpperCase();
  return (
    <header class="topbar">
      {/* No JavaScript needed: the checkbox opens the menu on small screens. */}
      <input type="checkbox" id="nav-toggle" class="nav-toggle" />
      <label for="nav-toggle" class="nav-button" aria-label={t("Menu")}>
        <Icon name="menu" />
      </label>
      <div class="top-title">
        <nav class="crumb" aria-label={t("You are here")}>
          <a href="/">pano</a>
          {group ? <span>{t(group)}</span> : null}
          {item && item[0] !== "/" && p.path !== item[0] ? <a href={item[0]}>{t(item[1])}</a> : null}
        </nav>
        <h1 class="page-title">{p.title}</h1>
      </div>
      <form method="post" action="/logout" class="who">
        <input type="hidden" name="_csrf" value={p.csrf} />
        <span class="avatar" aria-hidden="true">
          {initial}
        </span>
        <span class="who-name">{p.user}</span>
        <button class="icon-btn" title={t("Sign out")} aria-label={t("Sign out")}>
          <Icon name="logout" />
        </button>
      </form>
    </header>
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
      {p.user ? (
        <body class="with-side">
          <Sidebar {...p} />
          <div class="frame">
            <Topbar {...p} />
            <main id="main">
              {p.flash?.ok ? <div class="flash ok">{p.flash.ok}</div> : null}
              {p.flash?.err ? <div class="flash err">{p.flash.err}</div> : null}
              {p.children}
            </main>
          </div>
        </body>
      ) : (
        <body>
          <main>{p.children}</main>
        </body>
      )}
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
