import type { Child } from "hono/jsx";
import { assets } from "../assets.ts";
import { LANGS, lang, t } from "../i18n.ts";

import { Icon, type IconName } from "./icons.tsx";

/** `find`: more words the search box matches (what is on the page besides its name). */
export type NavTab = { href: string; label: string; find?: string };
export type NavItem = { href: string; label: string; icon: IconName; tabs?: NavTab[]; also?: RegExp; find?: string };

/**
 * The sidebar: a few places, each with its pages as tabs. Every page keeps its own URL;
 * the item lights up for any of its tabs and for the pages under them.
 */
export const NAV: NavItem[] = [
  { href: "/", label: "Overview", icon: "overview" },
  { href: "/projects", label: "Projects", icon: "apps", also: /^\/(apps|sites|git)(\/|$)/, find: "apps sites domains wordpress php" },
  { href: "/databases", label: "Databases", icon: "databases", find: "mariadb mysql postgres" },
  { href: "/backups", label: "Backups", icon: "backups", find: "restore s3 restic" },
  {
    href: "/security",
    label: "Security",
    icon: "security",
    tabs: [
      { href: "/security", label: "Protection", find: "firewall vulnerabilities updates tuning checks alerts" },
      { href: "/edge", label: "Edge", find: "ssl tls caddy certificates cloudflare cutover" },
      { href: "/shield", label: "Shield", find: "malware scan quarantine" },
      { href: "/vpn", label: "Private access", find: "vpn wireguard devices" },
    ],
  },
  {
    href: "/services",
    label: "Server",
    icon: "services",
    tabs: [
      { href: "/services", label: "Services", find: "mariadb postgres valkey redis realtime turn" },
      { href: "/jobs", label: "Jobs", find: "cron queues workers" },
      { href: "/containers", label: "Containers", find: "docker podman" },
      { href: "/runtimes", label: "Runtimes", find: "node bun php versions" },
    ],
  },
  {
    href: "/admins",
    label: "Settings",
    icon: "settings",
    tabs: [
      { href: "/admins", label: "Admins", find: "users 2fa password" },
      { href: "/activity", label: "Activity", find: "audit log" },
      { href: "/env-groups", label: "Shared variables", find: "env environment" },
      { href: "/import", label: "Import", find: "cyberpanel cpanel migrate" },
      { href: "/runner", label: "Runner", find: "ssh build remote" },
      { href: "/android", label: "Android", find: "apk aab builds" },
    ],
  },
];

/** Shortcuts the search box also finds, besides every page above. */
const ACTIONS: { href: string; label: string; under: string }[] = [
  { href: "/apps/new", label: "New app", under: "Projects" },
  { href: "/sites/new-php", label: "PHP site", under: "Projects" },
  { href: "/sites/new", label: "Proxy or static site", under: "Projects" },
  { href: "/git", label: "Git", under: "Projects" },
];

export type PageProps = {
  title: string;
  path: string;
  csrf?: string;
  user?: string;
  flash?: { ok?: string; err?: string };
  trustUntil?: number;
  /** replaces the default page header (title, breadcrumb, section tabs); `false`: the page draws its own */
  head?: Child | false;
  children?: Child;
};

const under = (href: string, path: string) => path === href || path.startsWith(`${href}/`);

/** Where a path sits in the menu: the sidebar item, and the tab when the item has tabs. */
export function navAt(path: string): { item?: NavItem; tab?: NavTab } {
  for (const item of NAV) {
    if (item.href === "/") {
      if (path === "/") return { item };
      continue;
    }
    const tab = item.tabs?.find((x) => under(x.href, path));
    if (tab || under(item.href, path) || item.also?.test(path)) return { item, tab };
  }
  return {};
}

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

function Sidebar(p: PageProps) {
  const on = navAt(p.path).item;
  return (
    <aside class="side" id="side">
      <a class="brand" href="/">
        <span class="logo" aria-hidden="true">
          <Icon name="overview" size={16} />
        </span>
        pano
      </a>
      <nav aria-label={t("Menu")}>
        {NAV.map((it) => (
          <a href={it.href} class={it === on ? "on" : ""} aria-current={it === on ? "page" : undefined}>
            <Icon name={it.icon} />
            <span>{t(it.label)}</span>
          </a>
        ))}
      </nav>
      <div class="side-foot">
        <LangSwitch path={p.path} />
        <span class="muted small">pano</span>
      </div>
    </aside>
  );
}

/** Finds any page or shortcut; the list is in the page, app.js filters it (Cmd/Ctrl+K). */
function Search() {
  const entries: { href: string; label: string; under: string; icon: IconName; find?: string }[] = [
    ...NAV.flatMap((it) =>
      it.tabs ? it.tabs.map((x) => ({ href: x.href, label: x.label, under: it.label, icon: it.icon, find: x.find })) : [{ href: it.href, label: it.label, under: "", icon: it.icon, find: it.find }],
    ),
    ...ACTIONS.map((a) => ({ ...a, icon: "plus" as IconName })),
  ];
  return (
    <div class="search">
      <label class="search-box">
        <Icon name="search" size={16} />
        <input type="search" id="nav-search" placeholder={t("Search pages")} aria-label={t("Search pages")} autocomplete="off" aria-controls="search-results" />
        <kbd>⌘K</kbd>
      </label>
      <ul class="search-results" id="search-results" hidden>
        {entries.map((e) => (
          <li>
            <a href={e.href} data-nav={[t(e.label), e.label, e.under && t(e.under), e.under, e.find].filter(Boolean).join(" ").toLowerCase()}>
              <Icon name={e.icon} size={16} />
              <span>{t(e.label)}</span>
              {e.under ? <small>{t(e.under)}</small> : null}
            </a>
          </li>
        ))}
        <li class="search-empty" hidden>
          {t("No matching pages")}
        </li>
      </ul>
    </div>
  );
}

function Topbar(p: PageProps) {
  const initial = (p.user ?? "?").slice(0, 1).toUpperCase();
  return (
    <header class="topbar">
      {/* No JavaScript needed: the checkbox opens the menu on small screens. */}
      <input type="checkbox" id="nav-toggle" class="nav-toggle" />
      <label for="nav-toggle" class="nav-button" aria-label={t("Menu")}>
        <Icon name="menu" />
      </label>
      <Search />
      {p.trustUntil && p.trustUntil > Date.now() ? (
        <form method="post" action="/trust/end" class="trust" title={t("Routine actions skip the code until then. Revealing secrets, changing what runs, opening the network, deleting, restoring and admin changes still ask.")}>
          <input type="hidden" name="_csrf" value={p.csrf} />
          <Icon name="security" size={16} />
          <span>{t("2FA verified, {n} min left").replace("{n}", String(Math.max(1, Math.ceil((p.trustUntil - Date.now()) / 60_000))))}</span>
          <button class="link-btn">{t("Lock")}</button>
        </form>
      ) : null}
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

/** Links back up: the sidebar item, then its tab. */
export function Crumb({ links }: { links: [href: string, label: string][] }) {
  if (!links.length) return null;
  return (
    <nav class="crumb" aria-label={t("You are here")}>
      {links.map(([href, label]) => (
        <a href={href}>{label}</a>
      ))}
    </nav>
  );
}

/** The parent pages of a path, for pages below a menu item or a tab (an app, a container). */
export function crumbFor(path: string): [string, string][] {
  const { item, tab } = navAt(path);
  if (!item || item.href === "/" || path === item.href || (tab && path === tab.href)) return [];
  const out: [string, string][] = [[item.href, t(item.label)]];
  if (tab && tab.href !== item.href) out.push([tab.href, t(tab.label)]);
  return out;
}

/** A page's title row: breadcrumb, title, a line under it and the main actions on the right. */
export function PageHead(p: { title: Child; crumb?: [string, string][]; sub?: Child; actions?: Child }) {
  return (
    <header class="page-head">
      <div class="page-head-text">
        {p.crumb ? <Crumb links={p.crumb} /> : null}
        <h1 class="page-title">{p.title}</h1>
        {p.sub ? <div class="page-sub">{p.sub}</div> : null}
      </div>
      {p.actions ? <div class="page-actions-row">{p.actions}</div> : null}
    </header>
  );
}

/** A row of links that look like tabs. `current` is the href shown as selected. */
export function Tabs({ items, current, label }: { items: { href: string; label: string }[]; current?: string; label?: string }) {
  return (
    <nav class="tabs" aria-label={label}>
      {items.map((x) => (
        <a href={x.href} class={x.href === current ? "on" : ""} aria-current={x.href === current ? "page" : undefined}>
          {x.label}
        </a>
      ))}
    </nav>
  );
}

/**
 * Tabs inside one page, without JavaScript: every pane is in the page and CSS shows the one
 * named in the URL (#tab-env), else `open` (default: the first). app.js keeps the tab across form posts.
 * At most 8 panes (the CSS pairs anchors, links and panes by position).
 */
export function TabPanes({ panes, open, label }: { panes: { key: string; label: string; body: Child }[]; open?: string; label?: string }) {
  const list = panes.slice(0, 8);
  const first = list.some((x) => x.key === open) ? open : list[0]?.key;
  return (
    <div class="tabbed">
      {list.map((x) => (
        <i id={`tab-${x.key}`} class="tab-anchor" />
      ))}
      <Tabs items={list.map((x) => ({ href: `#tab-${x.key}`, label: x.label }))} current={`#tab-${first}`} label={label} />
      {list.map((x) => (
        <section class={`pane${x.key === first ? " default" : ""}`} data-tab={x.key}>
          {x.body}
        </section>
      ))}
    </div>
  );
}

/** The default header: section title and its tabs on a tab's own page, else the page title under its breadcrumb. */
function DefaultHead(p: PageProps) {
  const { item } = navAt(p.path);
  const onTab = item?.tabs?.some((x) => x.href === p.path);
  if (item && onTab) {
    return (
      <>
        <PageHead title={t(item.label)} />
        <Tabs items={item.tabs!.map((x) => ({ href: x.href, label: t(x.label) }))} current={p.path} label={t(item.label)} />
      </>
    );
  }
  return <PageHead title={p.title} crumb={crumbFor(p.path)} />;
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
        <body class={`with-side${p.trustUntil && p.trustUntil > Date.now() ? " trusted" : ""}`}>
          <Sidebar {...p} />
          <div class="frame">
            <Topbar {...p} />
            <main id="main">
              {p.head === false ? null : p.head === undefined ? <DefaultHead {...p} /> : p.head}
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

/** `always`: a code field the trusted window keeps visible (the agent asks for a code there every time). */
export const alwaysAttr = (on?: boolean) => (on ? { "data-always": "" } : {});

export function Field(p: { label: string; name: string; value?: string | number; type?: string; placeholder?: string; hint?: string; required?: boolean; autocomplete?: string; always?: boolean }) {
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
        {...alwaysAttr(p.always)}
      />
      {p.hint ? <small class="muted">{p.hint}</small> : null}
    </label>
  );
}

export function Badge({ state }: { state: string }) {
  const cls = /^(active|success|ok|running)$/.test(state) ? "good" : /^(failed|fail|error)$/.test(state) ? "bad" : "neutral";
  return <span class={`badge ${cls}`}>{state}</span>;
}

type SuspendWhat = "app" | "site" | "project";

const SUSPEND_EFFECT: Record<SuspendWhat, string> = {
  app: "Visitors get a plain “This site is suspended” page (HTTP 503). The app's processes, cron jobs and previews stop; deploys and webhooks are refused until you resume.",
  site: "Visitors get a plain “This site is suspended” page (HTTP 503). A PHP site's pool and cron jobs stop until you resume.",
  project: "Every app and site of this project shows a plain “This site is suspended” page (HTTP 503); their processes and cron jobs stop until you resume.",
};

/** Suspend (with an optional reason) or Resume, each behind a small confirm panel. `base`: /apps/x, /sites/x, /projects/x. */
export function SuspendControl(p: { base: string; suspended: boolean; csrf: string; what: SuspendWhat }) {
  const otp = (
    <label class="field">
      <span>{t("Authenticator code")}</span>
      <input name="otp" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required />
    </label>
  );
  if (p.suspended) {
    return (
      <details class="menu">
        <summary class="btn primary">{t("Resume")}</summary>
        <form method="post" action={`${p.base}/resume`} class="menu-list menu-form">
          <Csrf token={p.csrf} />
          <p class="small muted">{t("Starts again what ran before the suspension and serves the domains as before.")}</p>
          {otp}
          <button class="btn primary">{t("Resume now")}</button>
        </form>
      </details>
    );
  }
  return (
    <details class="menu">
      <summary class="btn">{t("Suspend")}</summary>
      <form method="post" action={`${p.base}/suspend`} class="menu-list menu-form">
        <Csrf token={p.csrf} />
        <p class="small muted">{t(SUSPEND_EFFECT[p.what])}</p>
        <label class="field">
          <span>{t("Reason (optional)")}</span>
          <input name="reason" maxlength={200} autocomplete="off" placeholder={t("Unpaid invoice, abuse report…")} />
        </label>
        {otp}
        <button class="btn danger">{t("Suspend now")}</button>
      </form>
    </details>
  );
}

/** Under a suspended app's or site's header: since when and why. */
export function SuspendedBanner(p: { what: "app" | "site"; reason?: string; at?: number; external?: boolean }) {
  const when = p.at ? new Date(p.at * 1000).toISOString().replace("T", " ").slice(0, 16) : "";
  return (
    <div class="flash warn suspended-banner" role="status">
      <span>
        <strong>{t(p.what === "app" ? "This app is suspended." : "This site is suspended.")}</strong>{" "}
        {t("Visitors see the suspended page.")}
        {when ? ` ${t("Since {t}.").replace("{t}", when)}` : ""}
        {p.reason ? (
          <>
            {" "}
            {t("Reason")}: <em>{p.reason}</em>
          </>
        ) : null}
        {p.external ? ` ${t("pano does not run this app, so its processes were left running.")}` : ""}
      </span>
    </div>
  );
}

/** Settings checkbox: redirect plain HTTP to HTTPS (on by default). The hidden 0 is sent when it is off. */
export function HttpRedirectCheck({ on }: { on: boolean }) {
  return (
    <label class="check">
      <input type="hidden" name="http_redirect" value="0" />
      <input type="checkbox" name="http_redirect" value="1" checked={on} /> {t("Redirect HTTP to HTTPS")}
      <small class="muted"> {t("Turn off only if Cloudflare SSL is “Flexible” or the app redirects itself.")}</small>
    </label>
  );
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
        <input name="otp" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required data-always />
      </label>
      {p.extra}
      <button class="btn danger">{p.label}</button>
    </form>
  );
}
