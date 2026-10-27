// The complete list of things the web UI can ask the root agent to do. Each
// handler validates its own input; there is no generic "run command" method.

import { v } from "../shared/validate.ts";
import * as appsOps from "./apps.ts";
import * as backup from "./backup.ts";
import * as cutover from "./cutover.ts";
import { applyEdge, buildCaddyfile, edgeActive, edgeInstalled, edgeSettings, installCaddy, setupEdgeUnit } from "./edge.ts";
import * as importer from "./importer.ts";
import * as mysql from "./mysql.ts";
import * as runtimes from "./runtimes.ts";
import { apps, audit, auditList, backups, deploys, settings, sites, type Site } from "./state.ts";
import * as system from "./system.ts";

type P = Record<string, any>;
type Handler = (p: P, actor: string) => unknown | Promise<unknown>;

const allDomains = () => ({ apps: apps.list(), sites: sites.list() });

export const methods: Record<string, Handler> = {
  // ---- overview
  "system.info": () => system.info(),
  "system.audit": () => system.audit(),
  "audit.list": () => auditList(300),

  // ---- apps
  "apps.list": async () => Promise.all(apps.list().map(async (a) => ({ ...hideSecret(a), status: await appsOps.appStatus(a) }))),
  "apps.get": async (p) => {
    const a = apps.get(v.appName(p.name));
    if (!a) throw new Error("not found");
    return { ...hideSecret(a), status: await appsOps.appStatus(a), deploys: deploys.list(a.name) };
  },
  "apps.create": async (p, actor) => {
    const input = appsOps.validateAppInput(p);
    appsOps.assertDomainsFree(input.domains, {}, allDomains());
    return hideSecret(await appsOps.createApp(input, actor));
  },
  "apps.update": async (p, actor) => {
    const input = appsOps.validateAppInput(p);
    appsOps.assertDomainsFree(input.domains, { app: input.name }, allDomains());
    await appsOps.updateApp(input.name, input, actor);
  },
  "apps.delete": (p, actor) => {
    if (p.confirm !== p.name) throw new Error("type the app name to confirm");
    return appsOps.deleteApp(p.name, actor, !!p.removeFiles);
  },
  "apps.deploy": (p, actor) => ({ id: appsOps.startDeploy(p.name, "manual", actor) }),
  "apps.action": (p, actor) => {
    if (!["start", "stop", "restart"].includes(p.action)) throw new Error("bad action");
    return appsOps.appAction(p.name, p.action, actor);
  },
  "apps.logs": (p) => appsOps.appLogs(p.name, p.lines ?? 300),
  "apps.deployLog": (p) => appsOps.readDeployLog(v.int(p.id, 1, 1e9, "id"), v.int(p.offset ?? 0, 0, 1e12, "offset")),
  "apps.env.get": (p) => appsOps.getEnv(p.name),
  "apps.env.set": (p, actor) => {
    const vars: Record<string, string> = {};
    for (const [k, val] of Object.entries((p.vars ?? {}) as Record<string, unknown>)) vars[v.envKey(k)] = v.envValue(val);
    return appsOps.setEnv(p.name, vars, actor);
  },
  "apps.deployKey": (p) => appsOps.deployKey(p.name),
  "apps.webhookSecret": (p) => {
    const a = apps.get(v.appName(p.name));
    if (!a) throw new Error("not found");
    return a.webhook_secret;
  },
  "apps.webhook": (p) => {
    const r = appsOps.verifyWebhook(p.name, String(p.body ?? ""), String(p.signature ?? ""), String(p.ref ?? ""));
    if (!r.deploy) return r;
    return { ...r, id: appsOps.startDeploy(p.name, "webhook", "github") };
  },

  // ---- runtimes
  "runtimes.list": async () => {
    const used = new Set(apps.list().map((a) => `${a.runtime}@${a.runtime_version}`));
    return (await runtimes.installed()).map((r) => ({ ...r, inUse: used.has(`${r.runtime}@${r.version}`) }));
  },
  "runtimes.available": () => runtimes.available(),
  "runtimes.install": async (p, actor) => {
    await runtimes.install(v.runtime(p.runtime), p.version);
    audit(actor, "runtime.install", { runtime: p.runtime, version: p.version });
  },
  "runtimes.uninstall": async (p, actor) => {
    const inUse = apps.list().some((a) => a.runtime === p.runtime && a.runtime_version === p.version);
    await runtimes.uninstall(v.runtime(p.runtime), p.version, inUse);
    audit(actor, "runtime.uninstall", { runtime: p.runtime, version: p.version });
  },

  // ---- sites (routing entries that are not managed apps)
  "sites.list": () => sites.list(),
  "sites.save": async (p, actor) => {
    const name = String(p.name ?? "").toLowerCase();
    if (!/^[a-z0-9][a-z0-9.-]{0,62}$/.test(name)) throw new Error("invalid site name");
    const kind = p.kind as Site["kind"];
    if (!["legacy", "static", "proxy"].includes(kind)) throw new Error("invalid kind");
    const domains = (Array.isArray(p.domains) ? p.domains : String(p.domains ?? "").split(/[\s,]+/)).filter(Boolean);
    const clean = domains.map((d: string) => (d === "*" ? "*" : v.domain(d)));
    if (!clean.length) throw new Error("at least one domain");
    appsOps.assertDomainsFree(clean, { site: name }, allDomains());
    const routes = kind === "proxy"
      ? String(p.routes ?? "").split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
          const [path, up] = l.split(/\s+/);
          if (!path?.startsWith("/") || !/^127\.0\.0\.1:\d{2,5}$/.test(up ?? "")) throw new Error(`route "${l}": use "/path 127.0.0.1:PORT"`);
          return { path: v.httpPath(path), upstream: up! };
        })
      : [];
    const askUrl = String(p.ask_url ?? "").trim();
    if (askUrl && !/^http:\/\/127\.0\.0\.1:\d{2,5}\/[A-Za-z0-9._~\/-]*$/.test(askUrl)) throw new Error("ask URL must be http://127.0.0.1:PORT/path");
    const prev = sites.get(name);
    sites.upsert({
      name,
      kind,
      domains: clean,
      // The edge runs with ProtectHome, so static roots live outside /home.
      root: kind === "static" ? v.pathUnder(p.root, ["/srv", "/var/www"]) : (prev?.root ?? ""),
      routes,
      ask_url: askUrl,
      php_version: prev?.php_version ?? "",
      tls_cert: p.autoTls ? "" : (prev?.tls_cert ?? ""),
      tls_key: p.autoTls ? "" : (prev?.tls_key ?? ""),
      source: prev?.source ?? "pano",
      enabled: p.enabled === false ? 0 : 1,
      on_demand_tls: p.on_demand_tls || clean.includes("*") ? 1 : 0,
    });
    await applyEdge();
    audit(actor, "site.save", { name });
  },
  "sites.toggle": async (p, actor) => {
    sites.setEnabled(String(p.name), !!p.enabled);
    await applyEdge();
    audit(actor, "site.toggle", { name: p.name, enabled: !!p.enabled });
  },
  "sites.delete": async (p, actor) => {
    if (p.confirm !== p.name) throw new Error("type the site name to confirm");
    sites.remove(String(p.name));
    await applyEdge();
    audit(actor, "site.delete", { name: p.name });
  },

  // ---- edge
  "edge.status": async () => ({
    installed: await edgeInstalled(),
    active: await edgeActive(),
    cutover: settings.get("edge.cutover") === "1",
    settings: edgeSettings(),
  }),
  "edge.preview": () => buildCaddyfile(),
  "edge.install": async (_p, actor) => {
    const ver = await installCaddy();
    await setupEdgeUnit();
    audit(actor, "edge.install", { version: ver });
    return ver;
  },
  "edge.settings": async (p, actor) => {
    const email = String(p.email ?? "").trim();
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("invalid email");
    const hooksDomain = p.hooksDomain ? v.domain(p.hooksDomain) : "";
    settings.set("edge.email", email);
    settings.set("edge.behindCloudflare", p.behindCloudflare ? "1" : "0");
    settings.set("edge.hooksDomain", hooksDomain);
    settings.set("edge.localCerts", p.localCerts ? "1" : "0");
    await applyEdge();
    audit(actor, "edge.settings", { email, behindCloudflare: !!p.behindCloudflare, hooksDomain, localCerts: !!p.localCerts });
  },
  "edge.apply": () => applyEdge(),
  "edge.cutover": (_p, actor) => cutover.cutover(actor),
  "edge.rollback": (_p, actor) => cutover.rollback(actor),

  // ---- databases
  "db.list": async () => ({ databases: await mysql.listDatabases(), users: await mysql.listUsers() }),
  "db.create": (p, actor) => mysql.createDatabase({ name: p.name, user: p.user, password: p.password }, actor),
  "db.drop": (p, actor) => mysql.dropDatabase(p.name, p.confirm, actor),
  "db.password": (p, actor) => mysql.setPassword(p.user, p.host, p.password, actor),
  "db.grant": (p, actor) => mysql.grant(p.db, p.user, actor),

  // ---- backups
  "backup.r2.get": () => backup.getR2(),
  "backup.r2.set": (p, actor) => backup.setR2(p, actor),
  "backup.r2.test": () => backup.testR2(),
  "backup.key.export": (_p, actor) => backup.exportKey(actor),
  "backup.jobs": () => backups.jobs().map((j) => ({ ...j, runs: backups.runs(j.id, 10) })),
  "backup.job.add": (p, actor) => {
    const job = backup.validateJob(p);
    const id = backups.addJob(job);
    audit(actor, "backup.job.add", job);
    return id;
  },
  "backup.job.remove": (p, actor) => {
    backups.removeJob(v.int(p.id, 1, 1e9, "id"));
    audit(actor, "backup.job.remove", { id: p.id });
  },
  "backup.job.run": (p, actor) => backup.runJob(v.int(p.id, 1, 1e9, "id"), actor),
  "backup.restore": (p, actor) => backup.restore(v.int(p.runId, 1, 1e9, "run"), p.target, actor),

  // ---- import from CyberPanel
  "import.scan": () => importer.scan(),
  "import.apply": (p, actor) => importer.apply({ sites: (p.sites ?? []).map(String), apps: (p.apps ?? []).map(String) }, actor),
};

function hideSecret<T extends { webhook_secret?: string }>(a: T): T {
  return { ...a, webhook_secret: a.webhook_secret ? "set" : "" };
}
