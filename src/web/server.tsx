// pano-web: unprivileged UI process. It authenticates the admin and turns form
// posts into agent RPC calls; it cannot touch the system on its own.

import { Hono, type Context } from "hono";
import { getConnInfo } from "hono/bun";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Child } from "hono/jsx";
import { ARTIFACT_NAME, artifactFile } from "../shared/android.ts";
import { env, fsPath } from "../shared/config.ts";
import { call, stepUp } from "./agent.ts";
import { addUser, csrfOk, generatePassword, killSessions, listUsers, login, logout, prepareHash, pruneSessions, removeUser, session, setPassword, userExists, type Session } from "./auth.ts";
import { checkUsername } from "../shared/admins.ts";
import { AdminsPage, type AdminSecret } from "./views/admins.tsx";
import { t } from "./i18n.ts";
import { parseRange } from "./views/charts.tsx";
import { assets } from "./assets.ts";
import { AndroidDetail, AndroidPage, type AndroidBuildRow, type AndroidDetailView, type AndroidStatusView } from "./views/android.tsx";
import { AppDetail, AppForm, AppsPage, GitPage, type AppRow, type RepoOption } from "./views/apps.tsx";
import { ContainerDetail, ContainerForm, ContainersPage } from "./views/containers.tsx";
import { HomePage, LoginPage } from "./views/home.tsx";
import { VpnPage, type VpnStatus } from "./views/vpn.tsx";
import { ProtectCards, type AlertsView, type GuardView } from "./views/protect.tsx";
import { ShieldPage, type ShieldView } from "./views/shield.tsx";
import { JobsPage, type JobsView, type QueuesView } from "./views/jobs.tsx";
import { ServicesPage, type PgDb, type ServiceRow } from "./views/services.tsx";
import type { RealtimeView } from "./views/realtime.tsx";
import type { TurnView } from "./views/turn.tsx";
import { VulnsCard, type VulnView } from "./views/vulns.tsx";
import { TuneCard, type TuneView } from "./views/tune.tsx";
import { FirewallCard, type FirewallView } from "./views/firewall.tsx";
import { Card, Layout } from "./views/layout.tsx";
import { EnvGroupsPage, type EnvGroupRow } from "./views/envgroups.tsx";
import { WordPressCard, WordPressPage, WpSecretPage, type WpDetectView, type WpStatusView } from "./views/wordpress.tsx";
import {
  ActivityPage,
  BackupsPage,
  type BackupSettings,
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

import { hostAllowed } from "./hosts.ts";

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

  // Before anything else, login page included. The hook app is separate and has its own public Host.
  app.use("*", async (c, next) => (hostAllowed(c.req.header("host"), env) ? next() : c.text("bad host", 421)));
  app.use("*", (c, next) => stepUp.run({}, next));
  app.use("*", async (c, next) => {
    await next();
    // Static files keep their own Cache-Control (pages are no-store). HTML is deliberately not
    // compressed: pages carry the CSRF token next to reflected text (BREACH).
    for (const [k, val] of Object.entries(SECURITY_HEADERS)) if (k !== "Cache-Control" || !c.res.headers.has(k)) c.res.headers.set(k, val);
    if (!plainHttp(c)) c.res.headers.set("Strict-Transport-Security", "max-age=31536000");
  });

  for (const a of Object.values(assets)) {
    app.get(a.url.split("?")[0]!, (c) => c.body(a.body, 200, { "content-type": a.type, "cache-control": "public, max-age=31536000, immutable" }));
  }

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
  const err = (to: string, e: unknown) => `${to}${to.includes("?") ? "&" : "?"}err=${encodeURIComponent((e instanceof Error ? e.message : String(e)).slice(0, 300))}`;
  const needOtp = (c: Context<Env>, otp: unknown) => {
    // Checked by the agent with the next call, not here: this process holds no TOTP secrets.
    if (!/^\d{6}$/.test(String(otp ?? ""))) throw new Error("Authenticator code required.");
    stepUp.getStore()!.otp = String(otp);
  };
  /** Runs an action and redirects back with a message either way. */
  const act = (to: string, fn: (c: Context<Env>, f: Record<string, any>) => Promise<string | void>) => async (c: Context<Env>) => {
    const f = await form(c);
    // A code typed into any form goes along; the agent decides which calls need it.
    if (/^\d{6}$/.test(String(f.otp ?? ""))) stepUp.getStore()!.otp = String(f.otp);
    try {
      const msg = await fn(c, f);
      return back(c, typeof msg === "string" && msg.startsWith("/") ? msg : to, typeof msg === "string" && !msg.startsWith("/") ? msg : "OK");
    } catch (e) {
      return c.redirect(err(to, e));
    }
  };

  // ---- home
  app.get("/", async (c) => {
    const [info, history] = await Promise.all([call("system.info"), call("metrics.history", { range: parseRange(c.req.query("range")) }).catch(() => null)]);
    return page(c, t("Home"), <HomePage info={info} history={history} />);
  });

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
  // ---- Android builds in throwaway sandboxes (optional)
  app.get("/android", async (c) =>
    page(c, t("Android builds"), <AndroidPage v={await call<AndroidStatusView>("android.status")} csrf={c.get("s").csrf} toolchainLog={c.req.query("toolchain") === "1"} />),
  );
  app.post("/android-toolchain", act("/android", async (c) => {
    await call("android.toolchain.install", {}, actor(c));
    return "/android?toolchain=1";
  }));
  app.post("/android-toolchain/remove", act("/android", async (c) => {
    await call("android.toolchain.remove", {}, actor(c));
    return "Android toolchain removed";
  }));
  app.get("/android-toolchain/log", async (c) => c.json(await call("android.toolchain.log", { offset: Number(c.req.query("offset") ?? 0) })));
  app.post("/android/projects", act("/android", async (c, f) => {
    needOtp(c, f.otp);
    const p = await call("android.project.save", f, actor(c));
    return `/android/${p.name}`;
  }));
  app.get("/android/:name", async (c) => {
    try {
      const d = await call<AndroidDetailView>("android.project.get", { name: c.req.param("name") });
      return page(c, `Android · ${d.project.name}`, <AndroidDetail d={d} csrf={c.get("s").csrf} buildId={Number(c.req.query("build")) || undefined} />);
    } catch (e) {
      return c.redirect(err("/android", e));
    }
  });
  app.post("/android/:name/build", async (c) => {
    const name = c.req.param("name");
    try {
      const { id } = await call("android.build", { name }, actor(c));
      return c.redirect(`/android/${name}?build=${id}`);
    } catch (e) {
      return c.redirect(err(`/android/${name}`, e));
    }
  });
  app.get("/android/:name/builds/:id/log", async (c) =>
    c.json(await call("android.build.log", { name: c.req.param("name"), id: Number(c.req.param("id")), offset: Number(c.req.query("offset") ?? 0) })),
  );
  // Files are served from disk (root:pano, read-only here), only those the agent lists for the build.
  app.get("/android/:name/builds/:id/:file", async (c) => {
    const id = Number(c.req.param("id"));
    const file = c.req.param("file");
    if (!ARTIFACT_NAME.test(file)) return c.text("not found", 404);
    const b = await call<AndroidBuildRow>("android.build.get", { name: c.req.param("name"), id }).catch(() => null);
    if (!b?.artifacts.some((a) => a.name === file)) return c.text("not found", 404);
    const f = Bun.file(fsPath(artifactFile(id, file)));
    if (!(await f.exists())) return c.text("not found", 404);
    return new Response(f, {
      headers: { "content-type": "application/octet-stream", "content-disposition": `attachment; filename="${file}"`, "x-content-type-options": "nosniff" },
    });
  });
  app.post("/android/:name/signing", act("/android", async (c, f) => {
    const name = c.req.param("name")!;
    needOtp(c, f.otp);
    if (!(f.keystore instanceof File)) throw new Error("choose the keystore file");
    if (f.keystore.size > 64 * 1024) throw new Error("keystore: up to 64 KB");
    const keystore = Buffer.from(await f.keystore.arrayBuffer()).toString("base64");
    await call("android.signing.set", { name, keystore, alias: f.alias, storePassword: f.storePassword, keyPassword: f.keyPassword }, actor(c));
    return `/android/${name}`;
  }));
  app.post("/android/:name/signing/clear", act("/android", async (c, f) => {
    const name = c.req.param("name")!;
    needOtp(c, f.otp);
    await call("android.signing.clear", { name }, actor(c));
    return `/android/${name}`;
  }));
  app.post("/android/:name/delete", act("/android", async (c, f) => {
    const name = c.req.param("name")!;
    if (f.confirm !== name) throw new Error("type the name to confirm");
    needOtp(c, f.otp);
    await call("android.project.remove", { name }, actor(c));
  }));

  app.post("/apps", act("/apps/new", async (c, f) => {
    const a = await call("apps.create", appParams(f), actor(c));
    return `/apps/${a.name}`;
  }));
  app.get("/apps/:name", (c) => appPage(c, c.req.param("name")));
  async function appPage(c: Context<Env>, name: string, revealed?: { scope: "production" | "preview"; vars: Record<string, string> }) {
    const deploy = Number(c.req.query("deploy")) || undefined;
    const envOf = (scope: "production" | "preview") =>
      revealed?.scope === scope ? Promise.resolve(revealed.vars) : call<Record<string, string>>("apps.env.get", { name, scope }).catch(() => ({}));
    try {
      // One round of calls, all at once; database names only (no size scans) for the connect picker.
      const [a, envVars, previewEnv, logs, runtimes, edge, gh, crons, history, mariadb, pg] = await Promise.all([
        call<AppRow>("apps.get", { name }),
        envOf("production"),
        envOf("preview"),
        call<string>("apps.logs", { name, lines: 200 }).catch(() => ""),
        runtimeList(),
        call("edge.status"),
        call("github.status"),
        call("apps.crons", { name }).catch(() => undefined),
        call("metrics.history", { range: parseRange(c.req.query("range")), app: name }).catch(() => null),
        call<string[]>("db.names").catch(() => []),
        call<string[]>("pg.names").catch(() => []),
      ]);
      const databases = [...mariadb.map((n) => ({ engine: "mariadb" as const, name: n })), ...pg.map((n) => ({ engine: "postgres" as const, name: n }))];
      const hooks = edge.settings.hooksDomain;
      const hookUrl = hooks ? `https://${hooks}/hooks/github/${name}` : "(set a webhook domain on the Edge page)";
      const m = a.repo.match(/github\.com[:/]([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?\/?$/);
      const github = { connected: gh.connected, repo: m?.[1] ?? "" };
      return page(c, a.name, <AppDetail csrf={c.get("s").csrf} app={a} env={envVars} logs={logs} runtimes={runtimes} deployId={deploy} hookUrl={hookUrl} github={github} revealed={revealed?.scope} previewEnv={previewEnv} databases={databases} crons={crons} history={history} />);
    } catch (e) {
      return c.redirect(err("/apps", e));
    }
  }
  app.get("/apps/:name/deploys/:id/log", async (c) =>
    c.json(await call("apps.deployLog", { name: c.req.param("name"), id: Number(c.req.param("id")), offset: Number(c.req.query("offset") ?? 0) })),
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
  app.post("/apps/:name/previews", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      const r = await call("previews.start", { name, branch: f.branch }, actor(c));
      return c.redirect(`/apps/${name}?deploy=${r.deploy}`);
    } catch (e) {
      return c.redirect(err(`/apps/${name}`, e));
    }
  });
  app.post("/apps/:name/previews/:id/delete", act("/apps", async (c) => {
    const name = c.req.param("name")!;
    await call("previews.remove", { name, id: Number(c.req.param("id")) }, actor(c));
    return `/apps/${name}`;
  }));
  app.post("/apps/:name/action", act("/apps", async (c, f) => {
    const name = c.req.param("name")!;
    await call("apps.action", { name, action: f.action }, actor(c));
    return `/apps/${name}`;
  }));
  /** The KEY=value editor's text; # comments and blank lines are skipped. */
  const parseEnvText = (text: unknown) => {
    const vars: Record<string, string> = {};
    for (const line of String(text ?? "").split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/);
      if (m) vars[m[1]!] = m[2]!.trim().replace(/^(['"])(.*)\1$/, "$2");
      else if (line.trim() && !line.trim().startsWith("#")) throw new Error(`cannot parse line: ${line.slice(0, 40)}`);
    }
    return vars;
  };
  const envScope = (f: Record<string, any>) => (f.scope === "preview" ? "preview" : "production");
  app.post("/apps/:name/env", act("/apps", async (c, f) => {
    const name = c.req.param("name")!;
    const vars = parseEnvText(f.env);
    needOtp(c, f.otp);
    await call("apps.env.set", { name, vars, scope: envScope(f) }, actor(c));
    return `/apps/${name}`;
  }));
  app.post("/apps/:name/database/attach", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      const [engine, database] = String(f.database ?? "").split(/:(.*)/s);
      needOtp(c, f.otp);
      const r = await call("apps.attachDatabase", { name, engine, database, key: f.key }, actor(c));
      return back(c, `/apps/${name}`, `${r.key} connected to ${r.database} (own user ${r.user})`);
    } catch (e) {
      return c.redirect(err(`/apps/${name}`, e));
    }
  });
  app.post("/apps/:name/rollback", act("/apps", async (c) => {
    const name = c.req.param("name")!;
    const r = await call("apps.rollback", { name }, actor(c));
    return `/apps/${name}?ok=${encodeURIComponent(`Rolled back to ${r.release}`)}`;
  }));
  app.post("/apps/:name/database", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      needOtp(c, f.otp);
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
      const scope = envScope(f);
      return appPage(c, name, { scope, vars: await call("apps.env.reveal", { name, scope }, actor(c)) });
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
    const wp = site.kind === "php" ? await call<WpDetectView>("wp.detect", { name: site.name }).catch(() => null) : null;
    const extra = wp ? <WordPressCard site={site.name} d={wp} csrf={c.get("s").csrf} /> : null;
    return page(c, site.name, <SiteForm site={site} csrf={c.get("s").csrf} versions={versions} logs={logs} extra={extra} />);
  });
  // ---- WordPress tools (wp-cli through the agent)
  const wpList = (x: unknown) => (Array.isArray(x) ? x : x ? [x] : []).map(String);
  app.get("/sites/:name/wordpress", async (c) => {
    const name = c.req.param("name");
    try {
      return page(c, name, <WordPressPage site={name} st={await call<WpStatusView>("wp.status", { name })} csrf={c.get("s").csrf} />);
    } catch (e) {
      return c.redirect(err(`/sites/${name}`, e));
    }
  });
  app.post("/sites/:name/wordpress/install", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      const r = await call<{ adminUrl: string; adminUser: string; adminPassword: string }>("wp.install", { name, title: f.title, adminUser: f.adminUser, adminEmail: f.adminEmail }, actor(c));
      return page(c, name, <WpSecretPage title="WordPress installed" back={`/sites/${name}`} lines={[["Admin URL", r.adminUrl], ["User", r.adminUser], ["Password", r.adminPassword]]} />);
    } catch (e) {
      return c.redirect(err(`/sites/${name}`, e));
    }
  });
  app.post("/sites/:name/wordpress/password", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      const r = await call<{ login: string; password: string }>("wp.resetPassword", { name, userId: f.userId }, actor(c));
      return page(c, name, <WpSecretPage title="Admin password reset" back={`/sites/${name}/wordpress`} lines={[["User", r.login], ["Password", r.password]]} />);
    } catch (e) {
      return c.redirect(err(`/sites/${name}/wordpress`, e));
    }
  });
  app.post("/sites/:name/wordpress/update", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    const to = `/sites/${name}/wordpress`;
    try {
      const all = f.all === "1";
      const plugins = all ? "all" : wpList(f.plugins);
      const themes = all ? "all" : wpList(f.themes);
      const items = await call<string[]>(
        "wp.update",
        { name, core: all || f.core === "1", plugins: plugins === "all" || plugins.length ? plugins : undefined, themes: themes === "all" || themes.length ? themes : undefined },
        actor(c),
      );
      return page(c, name, <NoticePage title="WordPress updated" items={items} back={to} />);
    } catch (e) {
      return c.redirect(err(to, e));
    }
  });
  const wpToggle = (method: string, msg: (on: boolean) => string) => async (c: Context<Env>) => {
    const name = c.req.param("name");
    const to = `/sites/${name}/wordpress`;
    const on = (await form(c)).on === "1";
    try {
      await call(method, { name, on }, actor(c));
      return back(c, to, msg(on));
    } catch (e) {
      return c.redirect(err(to, e));
    }
  };
  app.post("/sites/:name/wordpress/maintenance", wpToggle("wp.maintenance", (on) => (on ? "Maintenance mode on" : "Maintenance mode off")));
  app.post("/sites/:name/wordpress/auto", wpToggle("wp.autoUpdate", (on) => (on ? "Nightly auto-update on" : "Nightly auto-update off")));
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

  // ---- shared variables
  async function envGroupsPage(c: Context<Env>, edit?: { name: string; vars: Record<string, string>; revealed: boolean }) {
    const groups = await call<EnvGroupRow[]>("envGroups.list");
    const name = c.req.query("edit");
    if (!edit && name && groups.some((g) => g.name === name)) edit = { name, vars: await call("envGroups.get", { name }), revealed: false };
    return page(c, t("Shared variables"), <EnvGroupsPage csrf={c.get("s").csrf} groups={groups} edit={edit} />);
  }
  app.get("/env-groups", (c) => envGroupsPage(c));
  app.post("/env-groups", act("/env-groups", async (c, f) => {
    needOtp(c, f.otp);
    const r = await call("envGroups.save", { name: f.name, vars: parseEnvText(f.env) }, actor(c));
    return r.apps.length ? `Saved; restart ${r.apps.join(", ")} to apply` : "Saved";
  }));
  app.post("/env-groups/:name/reveal", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      return envGroupsPage(c, { name, vars: await call("envGroups.reveal", { name }, actor(c)), revealed: true });
    } catch (e) {
      return c.redirect(err("/env-groups", e));
    }
  });
  app.post("/env-groups/:name/delete", act("/env-groups", async (c, f) => {
    needOtp(c, f.otp);
    await call("envGroups.remove", { name: c.req.param("name") }, actor(c));
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
    const [list, realtime, turn, apps, pg] = await Promise.all([
      call<ServiceRow[]>("services.status"),
      call<RealtimeView>("realtime.status"),
      call<TurnView>("turn.status"),
      call<{ name: string; kind: string }[]>("apps.names"),
      call<PgDb[]>("pg.list").catch(() => [] as PgDb[]), // fails fast when PostgreSQL is not installed
    ]);
    const appNames = apps.filter((a) => a.kind === "managed").map((a) => a.name);
    return page(c, t("Services"), <ServicesPage csrf={c.get("s").csrf} list={list} pg={pg} secret={secret} realtime={realtime} turn={turn} appNames={appNames} />);
  };
  // ---- realtime
  app.post("/services/realtime/install", act("/services", async (c) => `Realtime ${(await call("realtime.install", {}, actor(c))).version} installed`));
  app.post("/services/realtime/update", act("/services", async (c) => `Realtime updated to ${(await call("realtime.update", {}, actor(c))).version}`));
  app.post("/services/realtime/check", act("/services", async (c) => {
    await call("realtime.check", {}, actor(c));
    return "Checked";
  }));
  app.post("/services/realtime/auto", act("/services", async (c, f) => {
    await call("realtime.autoUpdate", { on: f.on === "1" }, actor(c));
  }));
  app.post("/services/realtime/domain", act("/services", async (c, f) => {
    await call("realtime.domain", { domain: f.domain }, actor(c));
    return f.domain ? `Realtime on wss://${f.domain}` : "Realtime on localhost only";
  }));
  app.post("/services/realtime/apps", act("/services", async (c, f) => {
    const r = await call("realtime.app.add", { name: f.name, origins: f.origins, webhook_url: f.webhook_url, max_connections: f.max_connections }, actor(c));
    return `${r.name} added (key ${r.key})`;
  }));
  app.post("/services/realtime/apps/:name/update", act("/services", async (c, f) => {
    await call("realtime.app.update", { name: c.req.param("name"), origins: f.origins, webhook_url: f.webhook_url, max_connections: f.max_connections }, actor(c));
    return `${c.req.param("name")} saved`;
  }));
  app.post("/services/realtime/to-app", act("/services", async (c, f) => {
    needOtp(c, f.otp);
    await call("apps.addRealtime", { name: f.app, realtime: f.realtime }, actor(c));
    return `Pusher settings added to ${f.app}`;
  }));
  app.post("/services/realtime/apps/remove", act("/services", async (c, f) => {
    needOtp(c, f.otp);
    await call("realtime.app.remove", { name: f.name, confirm: f.confirm }, actor(c));
  }));
  app.post("/services/realtime/uninstall", act("/services", async (c, f) => {
    needOtp(c, f.otp);
    await call("realtime.uninstall", { confirm: f.confirm }, actor(c));
    return "Realtime removed";
  }));
  app.post("/services/realtime/apps/:name/reveal", async (c) => {
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      const a = await call<{ id: string; key: string; secret: string; name: string }>("realtime.app.reveal", { name: c.req.param("name") }, actor(c));
      return servicesPage(c, { title: `Realtime · ${a.name}`, lines: [["PUSHER_APP_ID", a.id], ["PUSHER_APP_KEY", a.key], ["PUSHER_APP_SECRET", a.secret]] });
    } catch (e) {
      return c.redirect(err("/services", e));
    }
  });
  // ---- TURN
  app.post("/services/turn/install", act("/services", async (c) => ((await call("turn.install", {}, actor(c))).adopted ? "TURN taken over (secret kept)" : "TURN installed")));
  app.post("/services/turn/domain", act("/services", async (c, f) => {
    await call("turn.domain", { domain: f.domain }, actor(c));
  }));
  app.post("/services/turn/tls", act("/services", async (c, f) => {
    needOtp(c, f.otp);
    await call("turn.tls", { on: f.on === "1" }, actor(c));
    return f.on === "1" ? "TURN over TLS is on" : "TURN over TLS is off";
  }));
  app.post("/services/turn/to-app", act("/services", async (c, f) => {
    needOtp(c, f.otp);
    await call("apps.addTurn", { name: f.app }, actor(c));
    return `TURN settings added to ${f.app}`;
  }));
  app.post("/services/turn/rotate", act("/services", async (c, f) => {
    needOtp(c, f.otp);
    await call("turn.rotate", {}, actor(c));
    return "New TURN secret; apps that use it were restarted";
  }));
  app.post("/services/turn/uninstall", act("/services", async (c, f) => {
    needOtp(c, f.otp);
    await call("turn.uninstall", { confirm: f.confirm }, actor(c));
    return "TURN removed";
  }));
  app.post("/services/turn/reveal", async (c) => {
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      return servicesPage(c, { title: "TURN", lines: [["TURN_SECRET", await call<string>("turn.reveal", {}, actor(c))]] });
    } catch (e) {
      return c.redirect(err("/services", e));
    }
  });
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
    const [s, jobs, dbs, apps] = await Promise.all([
      call<BackupSettings>("backup.settings"),
      call("backup.jobs"),
      call<string[]>("db.names").catch(() => []),
      call<{ name: string; kind: string }[]>("apps.names").then((a) => a.filter((x) => x.kind === "managed").map((x) => x.name)),
    ]);
    return page(c, t("Backups"), <BackupsPage csrf={c.get("s").csrf} s={s} jobs={jobs} dbs={dbs} apps={apps} key={key} />);
  };
  app.get("/backups", (c) => backupsPage(c));
  app.post("/backups/dest", act("/backups", async (c, f) => {
    needOtp(c, f.otp);
    await call("backup.dest.set", f, actor(c));
    return "Destination saved";
  }));
  app.post("/backups/dest/test", act("/backups", async (_c, f) => call<string>("backup.dest.test", { dest: f.dest })));
  app.post("/backups/dest/clear", act("/backups", async (c, f) => {
    needOtp(c, f.otp);
    await call("backup.dest.clear", { dest: f.dest }, actor(c));
    return "Second destination removed";
  }));
  app.post("/backups/engine", act("/backups", async (c, f) => {
    needOtp(c, f.otp);
    await call("backup.engine", { engine: f.engine }, actor(c));
    return f.engine === "restic" ? "Incremental backups on" : "Full archives on";
  }));
  app.post("/backups/key", async (c) => {
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      return backupsPage(c, await call<string>("recovery.kit", {}, actor(c)));
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

  // ---- admins: the web owns passwords, the agent owns 2FA secrets and the guard rules; every change needs the acting admin's code
  const adminsPage = async (c: Context<Env>, created?: AdminSecret) => {
    const withTwofa = new Set(await call<string[]>("admins.list"));
    const admins = listUsers().map((u) => ({ ...u, twofa: withTwofa.has(u.username) }));
    return page(c, t("Admins"), <AdminsPage csrf={c.get("s").csrf} me={actor(c)} admins={admins} created={created} />);
  };
  app.get("/admins", async (c) => adminsPage(c));
  app.post("/admins", async (c) => {
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      const username = String(f.username ?? "").trim();
      checkUsername(username);
      if (userExists(username)) throw new Error("that admin already exists");
      const password = generatePassword();
      const hash = await prepareHash(password);
      // The agent checks the code and makes the 2FA secret; only then does the account exist here.
      const e = await call<{ secret: string; uri: string; qr: string }>("admins.add", { username }, actor(c));
      addUser(username, hash);
      return adminsPage(c, { username, password, secret: e.secret, uri: e.uri, qr: e.qr, reason: t("new admin") });
    } catch (e) {
      return c.redirect(err("/admins", e));
    }
  });
  app.post("/admins/:name", async (c) => {
    const f = await form(c);
    const name = c.req.param("name")!;
    try {
      needOtp(c, f.otp);
      if (f.do === "remove") {
        await call("admins.remove", { username: name }, actor(c)); // refuses yourself and the last admin
        removeUser(name);
        return back(c, "/admins", `Removed ${name}`);
      }
      if (f.do === "password") {
        const password = generatePassword();
        const hash = await prepareHash(password);
        await call("admins.reset", { username: name, twofa: false }, actor(c));
        setPassword(name, hash);
        return adminsPage(c, { username: name, password, reason: t("password reset") });
      }
      if (f.do === "2fa") {
        const e = await call<{ secret: string; uri: string; qr: string }>("admins.reset", { username: name, twofa: true }, actor(c));
        killSessions(name);
        return adminsPage(c, { username: name, secret: e.secret, uri: e.uri, qr: e.qr, reason: t("2FA reset") });
      }
      throw new Error("unknown action");
    } catch (e) {
      return c.redirect(err("/admins", e));
    }
  });

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
    const [findings, guard, alerts, edge, vulns, tuning, firewall] = await Promise.all([
      call("system.audit"),
      call<GuardView>("guard.get"),
      call<AlertsView>("alerts.get"),
      call("edge.status"),
      call<VulnView>("vulns.status"),
      call<TuneView>("tune.status"),
      call<FirewallView>("firewall.status"),
    ]);
    return page(
      c,
      t("Security"),
      <div class="stack">
        <VulnsCard csrf={c.get("s").csrf} v={vulns} />
        <TuneCard csrf={c.get("s").csrf} v={tuning} />
        <FirewallCard csrf={c.get("s").csrf} v={firewall} />
        <ProtectCards csrf={c.get("s").csrf} guard={guard} alerts={alerts} behindCloudflare={edge.settings.behindCloudflare} />
        <SecurityPage findings={findings} />
      </div>,
    );
  });
  app.post("/security/tune", act("/security", async (c, f) => {
    await call("tune.set", { on: f.on === "1" }, actor(c));
  }));
  app.post("/security/firewall/enable", act("/security", async (c, f) => {
    needOtp(c, f.otp);
    await call("firewall.enable", {}, actor(c));
    return "Firewall on; confirm it below within 2 minutes or it switches itself off";
  }));
  app.post("/security/firewall/confirm", act("/security", async (c) => {
    await call("firewall.confirm", {}, actor(c));
    return "Firewall confirmed";
  }));
  app.post("/security/firewall/disable", act("/security", async (c, f) => {
    needOtp(c, f.otp);
    await call("firewall.disable", {}, actor(c));
    return "Firewall off";
  }));
  app.post("/security/firewall/ports", act("/security", async (c, f) => {
    needOtp(c, f.otp);
    await call("firewall.ports", { ports: f.ports }, actor(c));
    return "Ports saved";
  }));
  app.post("/security/vulns/scan", act("/security", async (c) => {
    await call("vulns.scan", {}, actor(c));
    return "Checking; reload in a minute";
  }));
  app.post("/security/vulns/now", act("/security", async (c) => {
    await call("vulns.patchNow", {}, actor(c));
    return "Patching and checking; reload in a few minutes";
  }));
  app.post("/security/vulns/patch", act("/security", async (c, f) => {
    needOtp(c, f.otp);
    await call("vulns.patch", { os: f.os === "1", php: f.php === "1", edge: f.edge === "1" }, actor(c));
    return "Automatic updates saved";
  }));
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
  // ---- scheduled jobs and queues
  app.get("/jobs", async (c) => {
    const ref = c.req.query("log");
    const [jobs, queues] = await Promise.all([call<JobsView>("jobs.list"), call<QueuesView>("queues.status")]);
    let log: { ref: string; text: string } | undefined;
    if (ref) {
      const [owner, name, index] = ref.split(":");
      log = { ref, text: await call<string>("jobs.logs", { owner, name, index: Number(index) }).catch((e) => String(e instanceof Error ? e.message : e)) };
    }
    return page(c, t("Jobs"), <JobsPage csrf={c.get("s").csrf} jobs={jobs} queues={queues} log={log} />);
  });
  app.post("/jobs/run", act("/jobs", async (c, f) => {
    await call("jobs.run", { owner: f.owner, name: f.name, index: Number(f.index) }, actor(c));
    return "Started";
  }));
  app.post("/jobs/queues", act("/jobs", async (c, f) => {
    await call("queues.set", { on: f.on === "1" }, actor(c));
    return f.on === "1" ? "Queue monitor on" : "Queue monitor off";
  }));
  app.post("/jobs/workers/restart", act("/jobs", async (c, f) => {
    await call("queues.restartWorker", { app: f.app, process: f.process }, actor(c));
    return `${f.app} / ${f.process} restarted`;
  }));
  app.post("/sites/:name/crons", async (c) => {
    const name = c.req.param("name");
    const f = await form(c);
    try {
      needOtp(c, f.otp);
      await call("sites.crons", { name, crons: f.crons }, actor(c));
      return back(c, `/sites/${name}`, "Cron saved");
    } catch (e) {
      return c.redirect(err(`/sites/${name}`, e));
    }
  });

  // ---- shield
  app.get("/shield", async (c) => page(c, t("Shield"), <ShieldPage csrf={c.get("s").csrf} s={await call<ShieldView>("shield.status")} />));
  app.post("/shield/settings", act("/shield", async (c, f) => {
    needOtp(c, f.otp);
    const on = (k: string) => f[k] === "1";
    await call("shield.set", { scan: on("scan"), autoQuarantine: on("autoQuarantine"), reputation: on("reputation"), bruteforce: on("bruteforce") }, actor(c));
    return "Shield saved";
  }));
  app.post("/shield/scan", act("/shield", async (c, f) => {
    await call("shield.scan", { full: f.full === "1" }, actor(c));
    return "Scan started";
  }));
  app.post("/shield/deep", act("/shield", async (c) => {
    await call("shield.deepScan", {}, actor(c));
    return "ClamAV scan started (first run installs it)";
  }));
  app.post("/shield/finding", act("/shield", async (c, f) => {
    if (!["quarantine", "restore", "ignore"].includes(f.action)) throw new Error("bad action");
    if (f.action !== "quarantine") needOtp(c, f.otp);
    await call(`shield.${f.action}`, { id: Number(f.id) }, actor(c));
  }));
  app.post("/shield/unban", act("/shield", async (c, f) => {
    needOtp(c, f.otp);
    await call("shield.unban", { ip: f.ip }, actor(c));
  }));
  app.post("/security/alerts/test", act("/security", async () => call<string>("alerts.test")));
  const importPage = async (c: Context<Env>, cpReport?: CpReportView) => {
    const cpFile = c.req.query("cpanel");
    const [plan, cpPlan, archives, apps, sites] = await Promise.all([
      c.req.query("scan") ? call("import.scan") : undefined,
      cpFile ? call<CpPlanView>("import.cpanel.scan", { file: cpFile }) : undefined,
      call("import.cpanel.list").catch(() => []),
      call<any[]>("apps.names"),
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
      needOtp(c, f.otp);
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
    return c.text("Internal error (details in the pano-web journal)", 500);
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
    if (event === "pull_request") {
      try {
        return c.json(await call("apps.prWebhook", { name: c.req.param("name"), body, signature: c.req.header("x-hub-signature-256") ?? "" }, "github"), 202);
      } catch {
        return c.text("rejected", 403);
      }
    }
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
