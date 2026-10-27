// pano-web: unprivileged UI process. It authenticates the admin and turns form
// posts into agent RPC calls; it cannot touch the system on its own.

import { Hono, type Context } from "hono";
import { getConnInfo } from "hono/bun";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Child } from "hono/jsx";
import { env } from "../shared/config.ts";
import { call, stepUp } from "./agent.ts";
import { csrfOk, login, logout, pruneSessions, session, type Session } from "./auth.ts";
import { t } from "./i18n.ts";
import css from "./static/app.css" with { type: "text" };
import js from "./static/app.js" with { type: "text" };
import { AppDetail, AppForm, AppsPage, GitPage, type AppRow, type RepoOption } from "./views/apps.tsx";
import { ContainerDetail, ContainerForm, ContainersPage } from "./views/containers.tsx";
import { HomePage, LoginPage } from "./views/home.tsx";
import { VpnPage, type VpnStatus } from "./views/vpn.tsx";
import { ProtectCards, type AlertsView, type GuardView } from "./views/protect.tsx";
import { ServicesPage, type PgDb, type ServiceRow } from "./views/services.tsx";
import { Card, Layout } from "./views/layout.tsx";
import {
  ActivityPage,
  BackupsPage,
  DatabasesPage,
  EdgePage,
  ImportPage,
  NoticePage,
  PhpSiteNew,
  RuntimesPage,
  SecurityPage,
  SiteForm,
  SitesPage,
  type CpPlanView,
  type CpReportView,
} from "./views/pages.tsx";

type Env = { Variables: { s: Session } };

/**
 * On the WireGuard address the panel is plain HTTP inside an encrypted tunnel, where
 * browsers refuse Secure cookies; everywhere else (localhost via SSH tunnel) they are Secure.
 */
const plainHttp = (c: Context) => env.insecureCookies || (!!env.webVpnHost && new URL(c.req.url).hostname === env.webVpnHost);
const cookieName = (c: Context) => (plainHttp(c) ? "pano_session" : "__Host-pano_session");
const WP_SNIPPET = `// Added for pano edge (TLS terminates at Caddy)
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}`;

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cache-Control": "no-store",
};

export function createWebApp() {
  const app = new Hono<Env>();

  app.use("*", (c, next) => stepUp.run({}, next));
  app.use("*", async (c, next) => {
    await next();
    for (const [k, val] of Object.entries(SECURITY_HEADERS)) c.res.headers.set(k, val);
    if (!plainHttp(c)) c.res.headers.set("Strict-Transport-Security", "max-age=31536000");
  });

  app.get("/static/app.css", (c) => c.body(css, 200, { "content-type": "text/css; charset=utf-8", "cache-control": "max-age=3600" }));
  app.get("/static/app.js", (c) => c.body(js, 200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "max-age=3600" }));

  app.get("/login", (c) => c.html(<Layout title={t("Sign in")} path="/login"><LoginPage /></Layout>));

  app.post("/login", async (c) => {
    if (!sameOrigin(c)) return c.text("bad origin", 403);
    const f = await c.req.parseBody();
    const ip = getConnInfo(c).remote.address ?? "?";
    const r = await login(String(f.username ?? ""), String(f.password ?? ""), String(f.otp ?? ""), ip);
    if ("error" in r) return c.html(<Layout title={t("Sign in")} path="/login"><LoginPage error={r.error} /></Layout>, 401);
    setCookie(c, cookieName(c), r.sid, { httpOnly: true, secure: !plainHttp(c), sameSite: "Strict", path: "/" });
    return c.redirect("/");
  });

  // Everything below needs a session; every POST also needs the CSRF token and a same-origin request.
  app.use("*", async (c, next) => {
    const s = session(getCookie(c, cookieName(c)));
    if (!s) return c.req.method === "GET" ? c.redirect("/login") : c.text("unauthorized", 401);
    if (c.req.method === "POST") {
      if (!sameOrigin(c)) return c.text("bad origin", 403);
      const f = await c.req.parseBody({ all: true });
      if (!csrfOk(s, f._csrf)) return c.text("bad csrf token", 403);
    }
    c.set("s", s);
    await next();
  });

  app.post("/logout", (c) => {
    logout(getCookie(c, cookieName(c)));
    deleteCookie(c, cookieName(c), { path: "/", secure: !plainHttp(c) });
    return c.redirect("/login");
  });

  const page = (c: Context<Env>, title: string, body: Child, status = 200) => {
    const s = c.get("s");
    const flash = { ok: c.req.query("ok"), err: c.req.query("err") };
    return c.html(
      <Layout title={title} path={new URL(c.req.url).pathname} csrf={s.csrf} user={s.user.username} flash={flash}>
        {body}
      </Layout>,
      status as 200,
    );
  };
  const actor = (c: Context<Env>) => c.get("s").user.username;
  const form = async (c: Context<Env>) => (await c.req.parseBody({ all: true })) as Record<string, string | string[]>;
  const back = (c: Context<Env>, to: string, ok?: string) => c.redirect(ok ? `${to}${to.includes("?") ? "&" : "?"}ok=${encodeURIComponent(ok)}` : to);
  const err = (to: string, e: unknown) => `${to}${to.includes("?") ? "&" : "?"}err=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`;
  const needOtp = (c: Context<Env>, otp: unknown) => {
    // Checked by the agent with the next call, not here: this process holds no TOTP secrets.
    if (!/^\d{6}$/.test(String(otp ?? ""))) throw new Error("Authenticator code required.");
    stepUp.getStore()!.otp = String(otp);
  };
  /** Runs an action and redirects back with a message either way. */
  const act = (to: string, fn: (c: Context<Env>, f: Record<string, any>) => Promise<string | void>) => async (c: Context<Env>) => {
    const f = await form(c);
    try {
      const msg = await fn(c, f);
      return back(c, typeof msg === "string" && msg.startsWith("/") ? msg : to, typeof msg === "string" && !msg.startsWith("/") ? msg : "OK");
    } catch (e) {
      return c.redirect(err(to, e));
    }
  };

  // ---- home
  app.get("/", async (c) => page(c, t("Home"), <HomePage info={await call("system.info")} />));

  // ---- apps
  const runtimeList = () => call<{ runtime: string; version: string }[]>("runtimes.list");
  const appParams = (f: Record<string, any>) => {
    const [runtime, runtime_version] = String(f.runtime_ref ?? "").split("@");
    return { ...f, runtime, runtime_version };
  };

  app.get("/apps", async (c) => page(c, t("Apps"), <AppsPage apps={await call("apps.list")} />));
  app.get("/apps/new", async (c) => {
    const [runtimes, repos] = await Promise.all([runtimeList(), call<RepoOption[]>("github.repos").catch(() => [])]);
    return page(c, t("New app"), <Card title={t("New app")}><AppForm csrf={c.get("s").csrf} runtimes={runtimes} repos={repos} action="/apps" submit="Create" /></Card>);
  });

  // ---- git connections
  app.get("/git", async (c) => {
    const [github, edge] = await Promise.all([call("github.status"), call("edge.status")]);
    return page(c, "Git", <GitPage csrf={c.get("s").csrf} github={github} hooksDomain={edge.settings.hooksDomain} />);
  });
  app.post("/git/github/connect", act("/git", async (c, f) => {
    needOtp(c, f.otp);
    const r = await call("github.connect", { token: f.token }, actor(c));
    return `GitHub: ${r.login}`;
  }));
  app.post("/git/github/disconnect", act("/git", async (c, f) => {
    needOtp(c, f.otp);
    await call("github.disconnect", {}, actor(c));
  }));
  app.post("/apps/:name/github-link", async (c) => {
    const name = c.req.param("name");
    await form(c);
    try {
      const r = await call("github.link", { name }, actor(c));
      return back(c, `/apps/${name}`, `Linked ${r.repo}: pushes now deploy`);
    } catch (e) {
      return c.redirect(err(`/apps/${name}`, e));
    }
  });
  app.post("/apps", act("/apps/new", async (c, f) => {
    const a = await call("apps.create", appParams(f), actor(c));
    return `/apps/${a.name}`;
  }));
  app.get("/apps/:name", (c) => appPage(c, c.req.param("name")));
  async function appPage(c: Context<Env>, name: string, revealed?: Record<string, string>) {
    const deploy = Number(c.req.query("deploy")) || undefined;
    try {
      const [a, envVars, logs, runtimes] = await Promise.all([
        call<AppRow>("apps.get", { name }),
        revealed ?? call("apps.env.get", { name }).catch(() => ({})),
        call<string>("apps.logs", { name, lines: 200 }).catch(() => ""),
        runtimeList(),
      ]);
      const [edge, gh, crons] = await Promise.all([call("edge.status"), call("github.status"), call("apps.crons", { name }).catch(() => undefined)]);
      const hooks = edge.settings.hooksDomain;
      const hookUrl = hooks ? `https://${hooks}/hooks/github/${name}` : "(set a webhook domain on the Edge page)";
      const m = a.repo.match(/github\.com[:/]([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?\/?$/);
      const github = { connected: gh.connected, repo: m?.[1] ?? "" };
      return page(c, a.name, <AppDetail csrf={c.get("s").csrf} app={a} env={envVars} logs={logs} runtimes={runtimes} deployId={deploy} hookUrl={hookUrl} github={github} revealed={!!revealed} crons={crons} />);
    } catch (e) {
      return c.redirect(err("/apps", e));
    }
  }
  app.get("/apps/:name/deploys/:id/log", async (c) =>
    c.json(await call("apps.deployLog", { id: Number(c.req.param("id")), offset: Number(c.req.query("offset") ?? 0) })),
  );
  app.post("/apps/:name/deploy", async (c) => {
    const name = c.req.param("name");
    try {
      const { id } = await call("apps.deploy", { name }, actor(c));
      return c.redirect(`/apps/${name}?deploy=${id}`);
    } catch (e) {
      return c.redirect(err(`/apps/${name}`, e));
    }
  });
  app.post("/apps/:name/action", act("/apps", async (c, f) => {
    const name = c.req.param("name")!;
    await call("apps.action", { name, action: f.action }, actor(c));
    return `/apps/${name}`;
  }));
  app.post("/apps/:name/env", act("/apps", async (c, f) => {
    const name = c.req.param("name")!;
    const vars: Record<string, string> = {};
    for (const line of String(f.env ?? "").split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/);
      if (m) vars[m[1]!] = m[2]!.trim().replace(/^(['"])(.*)\1$/, "$2");
      else if (line.trim() && !line.trim().startsWith("#")) throw new Error(`cannot parse line: ${line.slice(0, 40)}`);
    }
    needOtp(c, f.otp);
    await call("apps.env.set", { name, vars }, actor(c));
    return `/apps/${name}`;
  }));
  app.post("/apps/:name/rollback", act("/apps", async (c) => {
    const name = c.req.param("name")!;
    const r = await call("apps.rollback", { name }, actor(c));
    return `/apps/${name}?ok=${encodeURIComponent(`Rolled back to ${r.release}`)}`;
  }));
  app.post("/apps/:name/database", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      const r = await call("apps.addDatabase", { name, engine: f.engine }, actor(c));
      return back(c, `/apps/${name}`, `${r.key} added (${r.engine} ${r.database})`);
    } catch (e) {
      return c.redirect(err(`/apps/${name}`, e));
    }
  });
  app.post("/apps/:name/env/reveal", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      // Rendered into this response only; the redirect-free page keeps values out of URLs and history.
      return appPage(c, name, await call("apps.env.reveal", { name }, actor(c)));
    } catch (e) {
      return c.redirect(err(`/apps/${name}`, e));
    }
  });
  app.post("/apps/:name/settings", act("/apps", async (c, f) => {
    const name = c.req.param("name")!;
    if (f.otp) needOtp(c, f.otp);
    await call("apps.update", { ...appParams(f), name }, actor(c));
    return `/apps/${name}`;
  }));
  app.post("/apps/:name/delete", act("/apps", async (c, f) => {
    needOtp(c, f.otp);
    await call("apps.delete", { name: c.req.param("name"), confirm: f.confirm, removeFiles: f.removeFiles === "1" }, actor(c));
    return "/apps";
  }));
  app.post("/apps/:name/deploy-key", async (c) => {
    const name = c.req.param("name");
    try {
      const key = await call<string>("apps.deployKey", { name }, actor(c));
      return page(c, name, <Card title={t("Deploy key")}><pre class="fix" data-copy>{key}</pre><a class="btn" href={`/apps/${name}`}>←</a></Card>);
    } catch (e) {
      return c.redirect(err(`/apps/${name}`, e));
    }
  });
  app.post("/apps/:name/webhook-secret", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      const secret = await call<string>("apps.webhookSecret", { name }, actor(c));
      return page(c, name, <Card title="Webhook secret"><pre class="fix" data-copy>{secret}</pre><a class="btn" href={`/apps/${name}`}>←</a></Card>);
    } catch (e) {
      return c.redirect(err(`/apps/${name}`, e));
    }
  });

  // ---- sites
  app.get("/sites", async (c) => page(c, t("Sites"), <SitesPage sites={await call("sites.list")} csrf={c.get("s").csrf} />));
  app.get("/sites/new", (c) => page(c, t("Sites"), <SiteForm csrf={c.get("s").csrf} />));
  app.get("/sites/new-php", async (c) => page(c, t("Sites"), <PhpSiteNew csrf={c.get("s").csrf} versions={await call("php.versions")} />));
  app.get("/sites/:name", async (c) => {
    const site = (await call<any[]>("sites.list")).find((s) => s.name === c.req.param("name"));
    if (!site) return c.redirect("/sites");
    const php = site.kind === "php" || site.kind === "legacy";
    const [versions, logs] = await Promise.all([
      php ? call("php.versions") : [],
      site.kind === "php" ? call<string>("sites.logs", { name: site.name }).catch(() => "") : "",
    ]);
    return page(c, site.name, <SiteForm site={site} csrf={c.get("s").csrf} versions={versions} logs={logs} />);
  });
  app.post("/sites/php", act("/sites/new-php", async (c, f) => {
    const r = await call("sites.createPhp", { name: f.name, domains: f.domains, php_version: f.php_version }, actor(c));
    return `/sites/${r.name}`;
  }));
  app.post("/sites/:name/php-version", act("/sites", async (c, f) => {
    const name = c.req.param("name")!;
    await call("sites.phpVersion", { name, version: f.version }, actor(c));
    return `/sites/${name}`;
  }));
  app.post("/sites/:name/permissions", async (c) => {
    const name = c.req.param("name");
    try {
      const warnings = await call<string[]>("sites.fixPermissions", { name }, actor(c));
      return page(c, name, <NoticePage title="Permissions fixed" items={warnings} back={`/sites/${name}`} />);
    } catch (e) {
      return c.redirect(err(`/sites/${name}`, e));
    }
  });
  app.post("/sites/:name/convert", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      const r = await call<{ warnings: string[] }>("sites.convertPhp", { name, version: f.version }, actor(c));
      return page(c, name, <NoticePage title={`${name} now runs on pano PHP`} items={r.warnings} back={`/sites/${name}`} />);
    } catch (e) {
      return c.redirect(err(`/sites/${name}`, e));
    }
  });
  app.post("/sites/:name/revert", act("/sites", async (c, f) => {
    const name = c.req.param("name")!;
    needOtp(c, f.otp);
    await call("sites.revertPhp", { name }, actor(c));
    return `/sites/${name}`;
  }));
  app.post("/sites/save", act("/sites", async (c, f) => {
    await call("sites.save", { ...f, autoTls: f.autoTls === "1" }, actor(c));
    return "/sites";
  }));
  app.post("/sites/:name/toggle", act("/sites", async (c, f) => {
    await call("sites.toggle", { name: c.req.param("name"), enabled: f.enabled === "1" }, actor(c));
  }));
  app.post("/sites/:name/delete", act("/sites", async (c, f) => {
    needOtp(c, f.otp);
    await call("sites.delete", { name: c.req.param("name"), confirm: f.confirm, removeFiles: f.removeFiles === "1" }, actor(c));
    return "/sites";
  }));

  // ---- databases
  app.get("/databases", async (c) => {
    try {
      return page(c, t("Databases"), <DatabasesPage csrf={c.get("s").csrf} data={await call("db.list")} />);
    } catch (e) {
      return page(c, t("Databases"), <Card title={t("Databases")}><p class="flash err">{String((e as Error).message)}</p></Card>);
    }
  });
  app.post("/databases/create", async (c) => {
    const f = await form(c);
    try {
      const created = await call("db.create", { name: f.name, user: f.user || undefined, password: f.password || undefined }, actor(c));
      return page(c, t("Databases"), <DatabasesPage csrf={c.get("s").csrf} data={await call("db.list")} created={created} />);
    } catch (e) {
      return c.redirect(err("/databases", e));
    }
  });
  app.post("/databases/password", async (c) => {
    const f = await form(c);
    try {
      const [user, host] = String(f.userhost ?? "").split("@");
      needOtp(c, f.otp);
      const r = await call("db.password", { user, host, password: f.password || undefined }, actor(c));
      return page(c, t("Databases"), <DatabasesPage csrf={c.get("s").csrf} data={await call("db.list")} created={{ name: "password", user: r.user, password: r.password }} />);
    } catch (e) {
      return c.redirect(err("/databases", e));
    }
  });
  app.post("/databases/drop", act("/databases", async (c, f) => {
    needOtp(c, f.otp);
    await call("db.drop", { name: f.name, confirm: f.confirm }, actor(c));
  }));

  // ---- database and cache servers
  const servicesPage = async (c: Context<Env>, secret?: { title: string; lines: [string, string][] }) => {
    const list = await call<ServiceRow[]>("services.status");
    const pg = list.find((s) => s.key === "postgres")?.installed ? await call<PgDb[]>("pg.list").catch(() => []) : [];
    return page(c, t("Services"), <ServicesPage csrf={c.get("s").csrf} list={list} pg={pg} secret={secret} />);
  };
  app.get("/services", (c) => servicesPage(c));
  app.post("/services/:key/install", act("/services", async (c) => {
    const r = await call("services.install", { service: c.req.param("key") }, actor(c));
    return `${c.req.param("key")} ${r.version} installed`;
  }));
  app.post("/services/:key/action", act("/services", async (c, f) => {
    await call("services.action", { service: c.req.param("key"), action: f.action }, actor(c));
  }));
  // Secrets are rendered in the POST response only, never put in a redirect URL.
  app.post("/services/valkey/url", async (c) => {
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      return servicesPage(c, { title: "Valkey", lines: [["REDIS_URL", await call<string>("services.valkeyUrl", {}, actor(c))]] });
    } catch (e) {
      return c.redirect(err("/services", e));
    }
  });
  app.post("/services/postgres/create", async (c) => {
    const f = await form(c);
    try {
      const r = await call("pg.create", { name: f.name, user: f.user }, actor(c));
      return servicesPage(c, { title: `PostgreSQL · ${r.name}`, lines: [["User", r.user], ["Password", r.password], ["DATABASE_URL", r.url]] });
    } catch (e) {
      return c.redirect(err("/services", e));
    }
  });
  app.post("/services/postgres/drop", act("/services", async (c, f) => {
    needOtp(c, f.otp);
    await call("pg.drop", { name: f.name, confirm: f.confirm }, actor(c));
  }));

  // ---- backups
  const backupsPage = async (c: Context<Env>, key?: string) => {
    const [r2, jobs, dbs, apps] = await Promise.all([
      call("backup.r2.get"),
      call("backup.jobs"),
      call("db.list").then((d: any) => d.databases.filter((x: any) => !x.system).map((x: any) => x.name)).catch(() => []),
      call("apps.list").then((a: any[]) => a.filter((x) => x.kind === "managed").map((x) => x.name)),
    ]);
    return page(c, t("Backups"), <BackupsPage csrf={c.get("s").csrf} r2={r2} jobs={jobs} dbs={dbs} apps={apps} key={key} />);
  };
  app.get("/backups", (c) => backupsPage(c));
  app.post("/backups/r2", act("/backups", async (c, f) => {
    await call("backup.r2.set", f, actor(c));
  }));
  app.post("/backups/r2/test", act("/backups", async () => call<string>("backup.r2.test")));
  app.post("/backups/key", async (c) => {
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      return backupsPage(c, await call<string>("backup.key.export", {}, actor(c)));
    } catch (e) {
      return c.redirect(err("/backups", e));
    }
  });
  app.post("/backups/jobs", act("/backups", async (c, f) => {
    await call("backup.job.add", f, actor(c));
  }));
  app.post("/backups/jobs/:id/run", act("/backups", async (c) => {
    await call("backup.job.run", { id: Number(c.req.param("id")) }, actor(c));
    return "Started";
  }));
  app.post("/backups/jobs/:id/remove", act("/backups", async (c) => {
    await call("backup.job.remove", { id: Number(c.req.param("id")) }, actor(c));
  }));
  app.post("/backups/runs/:id/restore", act("/backups", async (c, f) => {
    needOtp(c, f.otp);
    return call<string>("backup.restore", { runId: Number(c.req.param("id")), target: f.target }, actor(c));
  }));

  // ---- runtimes
  app.get("/runtimes", async (c) => {
    const [installed, available, php] = await Promise.all([call("runtimes.list"), call("runtimes.available").catch(() => null), call("php.versions")]);
    return page(c, t("Runtimes"), <RuntimesPage csrf={c.get("s").csrf} installed={installed} available={available} php={php} />);
  });
  app.post("/runtimes/php/install", act("/runtimes", async (c, f) => {
    await call("php.install", { version: f.version }, actor(c));
    return `PHP ${f.version} installed`;
  }));
  app.post("/runtimes/php/uninstall", act("/runtimes", async (c, f) => {
    await call("php.uninstall", { version: f.version }, actor(c));
  }));
  app.post("/runtimes/install", act("/runtimes", async (c, f) => {
    await call("runtimes.install", { runtime: f.runtime, version: f.version }, actor(c));
    return `${f.runtime} ${f.version} installed`;
  }));
  app.post("/runtimes/uninstall", act("/runtimes", async (c, f) => {
    await call("runtimes.uninstall", { runtime: f.runtime, version: f.version }, actor(c));
  }));

  // ---- containers (optional)
  app.get("/containers", async (c) => {
    const st = await call("containers.status");
    const list = st.installed ? await call("containers.list") : [];
    return page(c, t("Containers"), <ContainersPage csrf={c.get("s").csrf} installed={st.installed} list={list} templates={st.templates} />);
  });
  app.post("/containers/install", act("/containers", async (c) => {
    await call("containers.install", {}, actor(c));
    return "Containers enabled";
  }));
  app.get("/containers/new", async (c) => {
    const st = await call("containers.status");
    const key = c.req.query("template") ?? "";
    const tpl = st.templates[key];
    const draft = tpl ? { name: key, image: tpl.image, port: tpl.port, volumes: tpl.volumes, env: tpl.env, memory_mb: tpl.memory_mb } : undefined;
    return page(c, t("Containers"), <Card title="+ Container"><ContainerForm csrf={c.get("s").csrf} c={draft} note={tpl?.note} /></Card>);
  });
  app.post("/containers/save", act("/containers/new", async (c, f) => {
    const saved = await call("containers.save", f, actor(c));
    return `/containers/${saved.name}`;
  }));
  app.get("/containers/:name", async (c) => {
    try {
      return page(c, c.req.param("name"), <ContainerDetail csrf={c.get("s").csrf} c={await call("containers.get", { name: c.req.param("name") })} />);
    } catch (e) {
      return c.redirect(err("/containers", e));
    }
  });
  app.post("/containers/:name/action", act("/containers", async (c, f) => {
    const name = c.req.param("name")!;
    await call("containers.action", { name, action: f.action }, actor(c));
    return `/containers/${name}`;
  }));
  app.post("/containers/:name/delete", act("/containers", async (c, f) => {
    needOtp(c, f.otp);
    await call("containers.delete", { name: c.req.param("name"), confirm: f.confirm, removeData: f.removeData === "1" }, actor(c));
    return "/containers";
  }));

  // ---- private access (WireGuard)
  const remoteIp = (c: Context<Env>) => (getConnInfo(c).remote.address ?? "").replace(/^::ffff:/, "");
  const viaVpn = (c: Context<Env>) => /^10\.77\.0\.\d+$/.test(remoteIp(c));
  app.get("/vpn", async (c) => page(c, t("Private access"), <VpnPage csrf={c.get("s").csrf} s={await call<VpnStatus>("vpn.status")} viaVpn={viaVpn(c)} />));
  app.post("/vpn/enable", act("/vpn", async (c, f) => {
    await call("vpn.enable", { port: f.port, endpoint: f.endpoint }, actor(c));
    return "Private access enabled";
  }));
  app.post("/vpn/disable", act("/vpn", async (c, f) => {
    needOtp(c, f.otp);
    await call("vpn.disable", {}, actor(c));
  }));
  app.post("/vpn/peer/add", async (c) => {
    const f = await form(c);
    try {
      // The config (and for phones the private key) is rendered once in this response, never put in a URL.
      needOtp(c, f.otp);
      const created = await call("vpn.peer.add", { name: f.name, publicKey: f.publicKey }, actor(c));
      return page(c, t("Private access"), <VpnPage csrf={c.get("s").csrf} s={await call<VpnStatus>("vpn.status")} viaVpn={viaVpn(c)} created={created} />);
    } catch (e) {
      return c.redirect(err("/vpn", e));
    }
  });
  app.post("/vpn/peer/remove", act("/vpn", async (c, f) => {
    needOtp(c, f.otp);
    await call("vpn.peer.remove", { id: Number(f.id) }, actor(c));
  }));
  app.post("/vpn/locks", act("/vpn", async (c, f) => {
    needOtp(c, f.otp);
    await call("vpn.locks", { panel: f.panel === "1", ssh: f.ssh === "1", services: f.services === "1", databases: f.databases === "1", confirmSeconds: Number(f.confirmSeconds) }, actor(c));
    return "Locks applied";
  }));
  app.post("/vpn/confirm", act("/vpn", async (c) => {
    await call("vpn.confirm", { remote: remoteIp(c) }, actor(c));
    return "Locks confirmed";
  }));

  // ---- edge
  const edgePage =async (c: Context<Env>, report?: any) => {
    const [status, preview] = await Promise.all([call("edge.status"), call<string>("edge.preview").catch((e) => String(e.message))]);
    return page(c, t("Edge"), <EdgePage csrf={c.get("s").csrf} status={status} preview={preview} report={report} />);
  };
  app.get("/edge", (c) => edgePage(c));
  app.post("/edge/install", act("/edge", async (c) => `Caddy ${await call<string>("edge.install", {}, actor(c))} installed`));
  app.post("/edge/settings", act("/edge", async (c, f) => {
    await call("edge.settings", { email: f.email, behindCloudflare: f.behindCloudflare === "1", hooksDomain: f.hooksDomain, localCerts: f.localCerts === "1" }, actor(c));
  }));
  app.post("/edge/cutover", async (c) => {
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      return edgePage(c, await call("edge.cutover", {}, actor(c)));
    } catch (e) {
      return c.redirect(err("/edge", e));
    }
  });
  app.post("/edge/rollback", async (c) => {
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      const steps = await call<string[]>("edge.rollback", {}, actor(c));
      return edgePage(c, { ok: false, steps, probes: [] });
    } catch (e) {
      return c.redirect(err("/edge", e));
    }
  });

  // ---- security, import, activity
  app.get("/security", async (c) => {
    const [findings, guard, alerts, edge] = await Promise.all([call("system.audit"), call<GuardView>("guard.get"), call<AlertsView>("alerts.get"), call("edge.status")]);
    return page(
      c,
      t("Security"),
      <div class="stack">
        <ProtectCards csrf={c.get("s").csrf} guard={guard} alerts={alerts} behindCloudflare={edge.settings.behindCloudflare} />
        <SecurityPage findings={findings} />
      </div>,
    );
  });
  app.post("/security/guard", act("/security", async (c, f) => {
    needOtp(c, f.otp);
    await call("guard.set", { ssh: f.ssh === "1", http: f.http === "1" }, actor(c));
    return "Guard saved";
  }));
  app.post("/security/alerts", act("/security", async (c, f) => {
    needOtp(c, f.otp);
    await call("alerts.save", { token: f.token, chatId: f.chatId }, actor(c));
    return "Telegram saved";
  }));
  app.post("/security/alerts/test", act("/security", async () => call<string>("alerts.test")));
  const importPage = async (c: Context<Env>, cpReport?: CpReportView) => {
    const cpFile = c.req.query("cpanel");
    const [plan, cpPlan, archives, apps, sites] = await Promise.all([
      c.req.query("scan") ? call("import.scan") : undefined,
      cpFile ? call<CpPlanView>("import.cpanel.scan", { file: cpFile }) : undefined,
      call("import.cpanel.list").catch(() => []),
      call<any[]>("apps.list"),
      call<any[]>("sites.list"),
    ]);
    const existing = new Set([...apps.map((a) => `app:${a.name}`), ...sites.map((s) => `site:${s.name}`)]);
    return page(
      c,
      t("Import"),
      <ImportPage csrf={c.get("s").csrf} plan={plan} snippet={WP_SNIPPET} existing={existing} archives={archives} cpPlan={cpPlan} cpReport={cpReport} />,
    );
  };
  app.get("/import", async (c) => {
    try {
      return await importPage(c);
    } catch (e) {
      return c.redirect(err("/import", e));
    }
  });
  app.post("/import/cpanel/apply", async (c) => {
    const f = await form(c);
    const list = (x: unknown) => (Array.isArray(x) ? x : x ? [x] : []).map(String);
    try {
      const report = await call<CpReportView>("import.cpanel.apply", { file: f.file, sites: list(f.sites), databases: list(f.databases) }, actor(c));
      return importPage(c, report);
    } catch (e) {
      return c.redirect(err("/import", e));
    }
  });
  app.post("/import/apply", act("/import", async (c, f) => {
    const list = (x: unknown) => (Array.isArray(x) ? x : x ? [x] : []).map(String);
    const r = await call("import.apply", { sites: list(f.sites), apps: list(f.apps) }, actor(c));
    return `Imported ${r.sites} sites and ${r.apps} apps`;
  }));
  app.get("/activity", async (c) => page(c, t("Activity"), <ActivityPage rows={await call("audit.list")} />));

  app.onError((e, c) => {
    console.error("[web]", e);
    return c.text(`Error: ${e.message}`, 500);
  });

  setInterval(pruneSessions, 10 * 60_000);
  return app;
}

function sameOrigin(c: Context): boolean {
  // Browsers send Sec-Fetch-Site (scripts cannot forge it); trust it when present.
  const site = c.req.header("sec-fetch-site");
  if (site) return site === "same-origin";
  const origin = c.req.header("origin");
  if (!origin) return false;
  try {
    return new URL(origin).host === c.req.header("host");
  } catch {
    return false;
  }
}

/** Public-facing webhook receiver, bound to localhost; the edge forwards /hooks/* to it. */
export function createHookApp() {
  const app = new Hono();
  app.post("/hooks/github/:name", async (c) => {
    const body = await c.req.text();
    if (body.length > 1_000_000) return c.text("too large", 413);
    const event = c.req.header("x-github-event");
    if (event === "ping") return c.text("pong");
    if (event !== "push") return c.text("ignored", 202);
    let ref = "";
    try {
      ref = String(JSON.parse(body).ref ?? "");
    } catch {
      return c.text("bad json", 400);
    }
    try {
      const r = await call("apps.webhook", { name: c.req.param("name"), body, signature: c.req.header("x-hub-signature-256") ?? "", ref }, "github");
      return c.json(r, 202);
    } catch {
      return c.text("rejected", 403);
    }
  });
  app.post("/hooks/gitlab/:name", async (c) => {
    const body = await c.req.text();
    if (body.length > 1_000_000) return c.text("too large", 413);
    if (c.req.header("x-gitlab-event") !== "Push Hook") return c.text("ignored", 202);
    let ref = "";
    try {
      ref = String(JSON.parse(body).ref ?? "");
    } catch {
      return c.text("bad json", 400);
    }
    try {
      const r = await call("apps.webhook", { name: c.req.param("name"), body, gitlabToken: c.req.header("x-gitlab-token") ?? "-", ref }, "gitlab");
      return c.json(r, 202);
    } catch {
      return c.text("rejected", 403);
    }
  });
  app.all("*", (c) => c.text("not found", 404));
  return app;
}
