// The complete list of things the web UI can ask the root agent to do. Each
// handler validates its own input; there is no generic "run command" method.

import { DEFAULT_PHP, PHP_EOL, PHP_VERSIONS, formatProcesses, v } from "../shared/validate.ts";
import { addAdmin, adminNames, checkOtp, endTrust, removeAdmin, resetAdmin } from "./otp.ts";
import * as alerts from "./alerts.ts";
import * as android from "./android.ts";
import * as appsOps from "./apps.ts";
import * as envGroups from "./envgroups.ts";
import { envPending } from "../shared/env.ts";
import * as previewsOps from "./previews.ts";
import * as runner from "./runner.ts";
import * as backup from "./backup.ts";
import * as containers from "./containers.ts";
import * as cpanel from "./cpanel.ts";
import * as github from "./github.ts";
import * as guard from "./guard.ts";
import * as php from "./php.ts";
import * as cutover from "./cutover.ts";
import { applyEdge, buildCaddyfile, edgeActive, edgeInstalled, edgeSettings, installCaddy, setupEdgeUnit } from "./edge.ts";
import { siteCerts } from "./certs.ts";
import * as importer from "./importer.ts";
import * as jobs from "./jobs.ts";
import { RANGES, metricsHistory, type Range } from "./metrics.ts";
import * as queues from "./queues.ts";
import * as realtime from "./realtime.ts";
import * as firewall from "./firewall.ts";
import * as turn from "./turn.ts";
import * as recovery from "./recovery.ts";
import * as tune from "./tune.ts";
import * as vulns from "./vulns.ts";
import * as wordpress from "./wordpress.ts";
import * as mysql from "./mysql.ts";
import * as runtimes from "./runtimes.ts";
import * as services from "./services.ts";
import * as pgRemote from "./pgremote.ts";
import * as mysqlRemote from "./mysqlremote.ts";
import { remoteDomains } from "./remotedb-config.ts";
import * as cloudflare from "./cloudflare.ts";
import * as shield from "./shield.ts";
import { androidBuilds, apps, audit, auditList, backups, deploys, previews, settings, sites, type Site } from "./state.ts";
import * as system from "./system.ts";
import * as vpn from "./vpn.ts";

type P = Record<string, any>;

/**
 * Operations that need a fresh authenticator code, checked by the agent itself:
 * anything that reveals a secret, destroys data, opens network access or changes
 * which code an app runs.
 */
const SENSITIVE = new Set([
  "apps.delete", "apps.webhookSecret", "apps.env.reveal", "apps.env.set", "containers.delete", "sites.delete", "sites.revertPhp",
  "db.drop", "db.password", "pg.drop", "services.valkeyUrl", "backup.key.export", "backup.restore",
  "edge.cutover", "edge.rollback", "github.connect", "github.disconnect",
  "vpn.disable", "vpn.locks", "vpn.peer.add", "vpn.peer.remove", "guard.set", "alerts.save", "shield.set", "shield.restore", "shield.ignore", "shield.unban",
  "sites.crons", "backup.dest.set", "backup.dest.clear", "backup.engine", "vulns.patch", "realtime.uninstall", "realtime.app.add", "realtime.app.update", "realtime.app.remove", "realtime.app.reveal", "turn.uninstall", "turn.rotate", "turn.reveal", "recovery.kit", "recovery.rebuild",
  "apps.addDatabase", "apps.addRealtime", "apps.addTurn",
  // These reach root or the network: a container spec can mount the host, a site can take over a domain.
  // A new app picks its code, domains and shared variables at once (the same fields apps.update guards).
  "apps.create", "sites.createPhp", "containers.install", "containers.save", "containers.env.reveal", "sites.save", "backup.job.add", "vpn.enable", "edge.install", "edge.settings",
  "realtime.install", "turn.install", "turn.tls", "import.apply", "import.cpanel.apply", "db.grant",
  // Who can sign in (listing is read-only and holds no secrets, so it needs no code).
  "admins.add", "admins.remove", "admins.reset",
  "firewall.enable", "firewall.disable", "firewall.ports", "cloudflare.lock",
  // A public domain (with a certificate) for realtime/TURN, like sites.save; dropping backups, like adding them.
  "realtime.domain", "turn.domain", "backup.job.remove", "backup.prune",
  // Confirming keeps a lock that would otherwise roll itself back: the web process alone must not.
  "vpn.confirm", "firewall.confirm",
  "wp.install", "wp.resetPassword",
  "apps.attachDatabase", "envGroups.reveal", "envGroups.save", "envGroups.remove",
  // A project decides which code is built and signed with its key.
  "android.project.save", "android.project.remove", "android.signing.set", "android.signing.clear",
  // A runner key runs any command here (sandboxed).
  "runner.enable", "runner.key.add",
  // PostgreSQL facing the internet, and a password for it shown once.
  "pg.remote.enable", "pg.remote.disable", "pg.remote.user.add", "pg.remote.user.remove",
  "mysql.remote.enable", "mysql.remote.disable", "mysql.remote.user.add", "mysql.remote.user.remove",
  // Root moves or chowns files in a tenant's tree.
  "sites.fixPermissions", "shield.quarantine",
]);
/**
 * Guarded actions that need a code sent with that very call, even while the session is trusted
 * and never through a grant: the ones that reveal a secret, change which code runs, open the
 * network or a lock, leave lasting access (a key, a peer, a token, a backup destination, an admin),
 * silence the alerts, or destroy or overwrite data. A compromised web process gets none of them
 * from a sign-in or from a code the admin typed for something else.
 */
export const FRESH_ONLY = new Set([
  // destroy or overwrite data, move all traffic
  "apps.delete", "sites.delete", "db.drop", "pg.drop", "containers.delete", "realtime.uninstall", "turn.uninstall", "android.project.remove",
  "backup.restore", "recovery.rebuild", "edge.cutover", "edge.rollback",
  // who can sign in
  "admins.add", "admins.remove", "admins.reset",
  // secrets: shown, or set to a value the caller knows
  "apps.env.reveal", "envGroups.reveal", "containers.env.reveal", "apps.webhookSecret", "realtime.app.reveal", "turn.reveal", "services.valkeyUrl",
  "backup.key.export", "recovery.kit", "wp.resetPassword", "db.password",
  // which code runs (as an app, a site, a container or with the Android signing key)
  "apps.create", "sites.crons", "containers.save", "android.project.save", "shield.restore",
  // the network and the locks
  "vpn.peer.add", "vpn.locks", "vpn.disable", "firewall.disable", "firewall.ports", "cloudflare.lock", "guard.set",
  "pg.remote.enable", "pg.remote.user.add", "mysql.remote.enable", "mysql.remote.user.add",
  // lasting access from outside, and the channel that would report it
  "runner.enable", "runner.key.add", "github.connect", "backup.dest.set", "import.cpanel.apply", "alerts.save",
]);
export const ENV_MASK = "••••••••";

/** App fields that decide what runs as the app (and so can read its secrets): changing one always asks. */
// preview_env_exclude decides which secrets branch code receives; env_groups hands shared secrets to the app's code.
// build_isolated: turning it off lets install scripts reach the deploy key and data again.
const RUN_FIELDS = ["repo", "branch", "root_dir", "runtime", "runtime_version", "install_cmd", "build_cmd", "start_cmd", "processes", "crons", "preview_env_exclude", "env_groups", "build_isolated"] as const;
/** Where the app is served: guarded, but routine (the trusted window covers it). */
const CODE_FIELDS = [...RUN_FIELDS, "domains", "ask_url", "preview_domain"] as const;

/** Guarded fields an apps.update call changes; none for an unknown app or invalid input (the handler rejects it the same way). */
function changedAppFields(p: P): string[] {
  const cur = apps.get(String(p.name ?? ""));
  if (!cur) return [];
  let next: appsOps.AppInput;
  try {
    next = appsOps.validateAppInput(p);
  } catch {
    return [];
  }
  const norm = (a: Pick<appsOps.AppInput, (typeof CODE_FIELDS)[number]>, k: (typeof CODE_FIELDS)[number]) => JSON.stringify(k === "processes" ? formatProcesses(a.processes) : a[k]);
  return CODE_FIELDS.filter((k) => norm(next, k) !== norm(cur, k));
}

export function needsOtp(method: string, p: P): boolean {
  if (SENSITIVE.has(method)) return true;
  if (method === "apps.update") return changedAppFields(p).length > 0;
  return false;
}

/**
 * Variables that change what a runtime loads or runs, or where its traffic and trust go
 * (NODE_OPTIONS=--import=data:..., LD_PRELOAD, a proxy, a CA file): setting one is planting code.
 */
const RUNTIME_ENV =
  /^(NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|NODE_REPL_EXTERNAL_MODULE|BUN_.*|DENO_.*|LD_.*|DYLD_.*|PATH|PYTHON.*|PERL5?LIB|PERL5OPT|RUBYOPT|RUBYLIB|GEM_HOME|GEM_PATH|BUNDLE_.*|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|CLASSPATH|PHPRC|PHP_INI_SCAN_DIR|BASH_ENV|ENV|SHELLOPTS|PS4|GIT_.*|NPM_CONFIG_.*|YARN_.*|COREPACK_.*|GCONV_PATH|HOSTALIASES|LOCALDOMAIN|RES_OPTIONS|SSL_CERT_FILE|SSL_CERT_DIR|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|HTTPS?_PROXY|ALL_PROXY|NO_PROXY)$/i;

/** True when the new variables add or change a runtime variable. */
export const changesRuntimeEnv = (next: Record<string, string>, cur: Record<string, string>) =>
  Object.keys(next).some((k) => RUNTIME_ENV.test(k) && next[k] !== cur[k]);

/**
 * Whether this call needs a code sent with it (no trusted window, no grant). Fails closed: if the
 * check itself fails, it asks.
 */
export async function alwaysAsk(method: string, p: P): Promise<boolean> {
  if (FRESH_ONLY.has(method)) return true;
  try {
    if (method === "apps.update") return changedAppFields(p).some((k) => (RUN_FIELDS as readonly string[]).includes(k));
    if (method === "apps.env.set") {
      const cur = await appsOps.getEnv(p.name, envScope(p.scope));
      return changesRuntimeEnv(unmask(p.vars, cur), cur);
    }
    if (method === "envGroups.save") {
      const cur = await envGroups.readGroup(p.name).catch(() => ({}) as Record<string, string>);
      return changesRuntimeEnv(unmask(p.vars, cur), cur);
    }
    // The connection URL goes into the variable the caller names.
    if (method === "apps.attachDatabase") return RUNTIME_ENV.test(String(p.key ?? ""));
  } catch {
    return true;
  }
  return false;
}
type Handler = (p: P, actor: string) => unknown | Promise<unknown>;

const serviceKey = (s: unknown): services.ServiceKey => {
  if (typeof s !== "string" || !(s in services.SERVICES)) throw new Error("unknown service");
  return s as services.ServiceKey;
};

// Remote database names count as taken: a later app or site on one would break the edge config.
const allDomains = () => ({ apps: apps.list(), sites: [...sites.list(), { name: "remote database access", domains: remoteDomains() }], previews: previews.list() });

export const methods: Record<string, Handler> = {
  // ---- login: the web checks the password, the agent checks the code
  "auth.otp": (p) => checkOtp(String(p.username ?? ""), p.code),
  "auth.trust.end": (p) => endTrust(p.trust),

  // ---- admins (all equal, no roles); the web keeps the password hashes
  "admins.list": () => adminNames(),
  "admins.add": (p, actor) => addAdmin(actor, String(p.username ?? "")),
  "admins.remove": (p, actor) => removeAdmin(actor, String(p.username ?? "")),
  "admins.reset": (p, actor) => resetAdmin(actor, String(p.username ?? ""), !!p.twofa),

  // ---- overview
  "system.info": () => system.info(),
  "system.audit": () => system.audit(),
  "audit.list": () => auditList(300),
  "metrics.history": (p) => {
    const range = String(p.range ?? "24h");
    if (!Object.hasOwn(RANGES, range)) throw new Error("range is 1h, 24h, 7d or 30d");
    return metricsHistory(range as Range, p.app ? v.appName(p.app) : undefined);
  },

  // ---- apps
  "apps.list": async () => {
    const list = apps.list();
    const status = await appsOps.appStatuses(list);
    return list.map((a, i) => ({ ...hideSecret(a), status: status[i]! }));
  },
  /** Names only (pickers): no unit status. */
  "apps.names": () => apps.list().map((a) => ({ name: a.name, kind: a.kind })),
  "apps.get": async (p) => {
    const a = apps.get(v.appName(p.name));
    if (!a) throw new Error("not found");
    // Names of variables a restart or a redeploy would apply; never values or fingerprints.
    const env_pending = a.kind === "managed" && a.active_slot ? envPending(await appsOps.effectiveEnv(a), a.env_running, a.env_built) : { restart: [], redeploy: [] };
    return { ...hideSecret(a), status: await appsOps.appStatus(a), deploys: deploys.list(a.name), previews: previewsOps.previewList(a.name), env_pending };
  },
  "apps.create": async (p, actor) => {
    const input = appsOps.validateAppInput(p);
    await appsOps.checkSchedules(input.crons);
    await envGroups.assertGroupsExist(input.env_groups);
    appsOps.assertDomainsFree(appsOps.inputHosts(input), {}, allDomains());
    const created = await appsOps.createApp(input, actor);
    // env, DATA_DIR (SQLite, uploads) and the live release, daily
    backup.ensureJob("app", created.name, actor);
    return hideSecret(created);
  },
  "apps.update": async (p, actor) => {
    const input = appsOps.validateAppInput(p);
    await appsOps.checkSchedules(input.crons);
    await envGroups.assertGroupsExist(input.env_groups);
    appsOps.assertDomainsFree(appsOps.inputHosts(input), { app: input.name }, allDomains());
    await appsOps.updateApp(input.name, input, actor);
    await previewsOps.reconcilePreviews(input.name, actor);
  },
  "apps.delete": async (p, actor) => {
    if (p.confirm !== p.name) throw new Error("type the app name to confirm");
    await previewsOps.removeAll(p.name, actor);
    return appsOps.deleteApp(p.name, actor, !!p.removeFiles);
  },
  "apps.deploy": (p, actor) => ({ id: appsOps.startDeploy(p.name, "manual", actor) }),
  "apps.rollback": (p, actor) => appsOps.rollback(v.appName(p.name), actor),
  "apps.crons": async (p) => {
    const app = apps.get(v.appName(p.name));
    if (!app) throw new Error("no such app");
    return { jobs: await jobs.listJobs({ owner: "app", name: app.name }), logs: await appsOps.cronLogs(app) };
  },
  "apps.action": (p, actor) => {
    if (!["start", "stop", "restart"].includes(p.action)) throw new Error("bad action");
    return appsOps.appAction(p.name, p.action, actor);
  },
  "apps.logs": (p) => appsOps.appLogs(p.name, p.lines ?? 300),
  "apps.deployLog": (p) => {
    const id = v.int(p.id, 1, 1e9, "id");
    if (p.name !== undefined && deploys.get(id)?.app !== p.name && !previewsOps.previewOwnsDeploy(p.name, id)) throw new Error("no such deploy for this app");
    return appsOps.readDeployLog(id, v.int(p.offset ?? 0, 0, 1e12, "offset"));
  },
  // Values never leave the agent without a code; the editor shows masks and keeps masked values unchanged.
  "apps.env.get": async (p) => masked(await appsOps.getEnv(p.name, envScope(p.scope))),
  "apps.env.reveal": (p) => appsOps.getEnv(p.name, envScope(p.scope)),
  "apps.env.set": async (p, actor) => {
    const scope = envScope(p.scope);
    return appsOps.setEnv(p.name, unmask(p.vars, await appsOps.getEnv(p.name, scope)), actor, scope);
  },
  "apps.attachDatabase": async (p, actor) => {
    const app = apps.get(v.appName(p.name));
    if (!app) throw new Error("no such app");
    if (!["postgres", "mariadb"].includes(p.engine)) throw new Error("engine: postgres or mariadb");
    const env = { get: () => appsOps.getEnv(app.name), set: (vars: Record<string, string>) => appsOps.setEnv(app.name, vars, actor) };
    const r = await services.attachDatabaseToApp(app.name, p.engine, p.database, p.key, env, actor);
    if (app.active_slot) await appsOps.appAction(app.name, "restart", actor).catch(() => {});
    return r;
  },

  // ---- shared variables (groups given to several apps)
  "envGroups.list": () => envGroups.listGroups(),
  "envGroups.get": async (p) => masked(await envGroups.readGroup(p.name)),
  "envGroups.reveal": (p) => envGroups.readGroup(p.name),
  "envGroups.save": async (p, actor) => {
    const current = await envGroups.readGroup(p.name).catch(() => ({}));
    return envGroups.saveGroup(p.name, unmask(p.vars, current), actor);
  },
  "envGroups.remove": (p, actor) => envGroups.removeGroup(p.name, actor),
  "apps.addDatabase": async (p, actor) => {
    const app = apps.get(v.appName(p.name));
    if (!app) throw new Error("no such app");
    if (!["postgres", "mariadb", "valkey"].includes(p.engine)) throw new Error("engine: postgres, mariadb or valkey");
    const env = { get: () => appsOps.getEnv(app.name), set: (vars: Record<string, string>) => appsOps.setEnv(app.name, vars, actor) };
    const r = await services.databaseForApp(app.name, p.engine, env, actor);
    // Running apps pick it up now (DATABASE_URL is read at runtime, also by Next.js).
    if (app.active_slot) await appsOps.appAction(app.name, "restart", actor).catch(() => {});
    return r;
  },
  "apps.addRealtime": async (p, actor) => {
    const app = apps.get(v.appName(p.name));
    if (!app) throw new Error("no such app");
    const env = { get: () => appsOps.getEnv(app.name), set: (vars: Record<string, string>) => appsOps.setEnv(app.name, vars, actor) };
    await realtime.toAppEnv(p.realtime, env, app.name, actor);
    if (app.active_slot) await appsOps.appAction(app.name, "restart", actor).catch(() => {});
  },
  "apps.deployKey": (p) => appsOps.deployKey(p.name),
  "apps.webhookSecret": (p) => {
    const a = apps.get(v.appName(p.name));
    if (!a) throw new Error("not found");
    return a.webhook_secret;
  },
  "apps.webhook": async (p) => {
    const source = p.gitlabToken ? "gitlab" : "github";
    const r = appsOps.verifyWebhook(p.name, String(p.body ?? ""), String(p.signature ?? ""), String(p.ref ?? ""), String(p.gitlabToken ?? ""));
    // A push to another branch builds (or, on branch deletion, removes) its preview when the app has a preview domain.
    if (!r.deploy) return (await previewsOps.onPush(String(p.name), String(p.ref ?? ""), String(p.body ?? ""), source)) ?? r;
    if (apps.get(p.name)?.auto_deploy === 0) return { deploy: false, reason: "auto deploy is off" };
    return { ...r, id: appsOps.startDeploy(p.name, "push", source) };
  },
  "apps.prWebhook": async (p) => {
    appsOps.verifyWebhook(p.name, String(p.body ?? ""), String(p.signature ?? ""), ""); // throws on a bad signature
    return previewsOps.onPullRequest(String(p.name), String(p.body ?? ""));
  },

  // ---- previews (branch deploys under a wildcard domain)
  "previews.start": (p, actor) => previewsOps.startPreview(v.appName(p.name), String(p.branch ?? ""), "manual", actor),
  "previews.remove": (p, actor) => previewsOps.removePreview(v.appName(p.name), v.int(p.id, 1, 1e9, "id"), actor),

  // ---- GitHub connection (optional)
  "github.status": () => github.status(),
  "github.connect": (p, actor) => github.connect({ token: p.token }, actor),
  "github.disconnect": (_p, actor) => github.disconnect(actor),
  "github.repos": () => github.repos(),
  "github.link": async (p, actor) => {
    const app = apps.get(v.appName(p.name));
    if (!app) throw new Error("no such app");
    const linked = await github.link(app, await appsOps.deployKey(app.name), actor);
    if (app.repo !== linked.sshUrl) apps.update(app.name, { repo: linked.sshUrl });
    return linked;
  },

  // ---- Android builds in throwaway sandboxes (optional, nothing installed until asked)
  "android.status": () => android.androidStatus(),
  "android.toolchain.install": (_p, actor) => android.installToolchain(actor),
  "android.toolchain.remove": (_p, actor) => android.removeToolchain(actor),
  "android.toolchain.log": (p) => android.readLog("toolchain", v.int(p.offset ?? 0, 0, 1e12, "offset")),
  "android.project.get": (p) => android.projectDetail(v.appName(p.name)),
  "android.project.save": (p, actor) => android.saveProject(p, actor),
  "android.project.remove": (p, actor) => android.removeProject(v.appName(p.name), actor),
  "android.signing.set": (p, actor) => android.setSigning(v.appName(p.name), p, actor),
  "android.signing.clear": (p, actor) => android.clearSigning(v.appName(p.name), actor),
  "android.cache.clear": (p, actor) => android.clearCache(v.appName(p.name), actor),
  "runner.status": () => runner.runnerStatus(),
  "runner.enable": (_p, actor) => runner.enableRunner(actor),
  "runner.disable": (_p, actor) => runner.disableRunner(actor),
  "runner.config": (p, actor) => runner.saveConfig(p, actor),
  "runner.key.add": (p, actor) => runner.addKey(String(p.key ?? ""), actor),
  "runner.key.remove": (p, actor) => runner.removeKey(String(p.fingerprint ?? ""), actor),
  "runner.workspace.clean": (p, actor) => runner.cleanWorkspace(String(p.ws ?? ""), actor),
  "runner.cache.clear": (_p, actor) => runner.clearRunnerCache(actor),
  "android.build": async (p, actor) => ({ id: await android.startBuild(v.appName(p.name), String(p.trigger ?? "manual") === "cli" ? "cli" : "manual", actor) }),
  "android.build.get": (p) => {
    const b = androidBuilds.get(v.int(p.id, 1, 1e9, "id"));
    if (!b || b.project !== p.name) throw new Error("no such build for this project");
    return b;
  },
  "android.build.log": (p) => {
    const id = v.int(p.id, 1, 1e9, "id");
    if (androidBuilds.get(id)?.project !== p.name) throw new Error("no such build for this project");
    return android.readLog(id, v.int(p.offset ?? 0, 0, 1e12, "offset"));
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
    // Compared as the directory it removes: "v20.1.0" is 20.1.0.
    const runtime = v.runtime(p.runtime);
    const version = v.version(p.version);
    const inUse = apps.list().some((a) => a.runtime === runtime && a.runtime_version?.replace(/^v/, "") === version);
    await runtimes.uninstall(runtime, version, inUse);
    audit(actor, "runtime.uninstall", { runtime, version });
  },

  // ---- containers (optional: Podman is installed only when asked for)
  "containers.status": async () => ({ installed: await containers.podmanInstalled(), templates: containers.TEMPLATES }),
  "containers.install": (_p, actor) => containers.installPodman(actor),
  "containers.list": () => containers.listContainers(),
  // Values (database passwords, master keys) only with a code, like an app's variables; a masked value saved back keeps what is stored.
  "containers.get": async (p) => {
    const d = await containers.containerDetail(String(p.name ?? ""));
    return { ...d, env: masked(d.env) };
  },
  "containers.env.reveal": async (p) => (await containers.containerDetail(String(p.name ?? ""))).env,
  "containers.save": async (p, actor) => {
    const input = containers.validateContainer(p);
    return containers.saveContainer({ ...input, env: unmask(input.env, await containers.containerEnv(input.name)) }, actor);
  },
  "containers.action": (p, actor) => {
    if (!["start", "stop", "restart", "pull"].includes(p.action)) throw new Error("bad action");
    return containers.containerAction(String(p.name ?? ""), p.action, actor);
  },
  "containers.delete": (p, actor) => {
    if (p.confirm !== p.name) throw new Error("type the container name to confirm");
    return containers.deleteContainer(String(p.name), !!p.removeData, actor);
  },

  // ---- database and cache servers (installed on demand)
  "services.status": () => services.status(),
  "services.install": (p, actor) => services.install(serviceKey(p.service), actor),
  "services.action": (p, actor) => {
    if (!["start", "stop", "restart"].includes(p.action)) throw new Error("bad action");
    return services.action(serviceKey(p.service), p.action, actor);
  },
  "services.valkeyUrl": () => services.valkeyUrl(),
  "pg.list": () => services.pgList(),
  "pg.names": () => services.pgNames(),
  "db.names": () => mysql.databaseNames(),
  "pg.create": (p, actor) => services.pgCreate({ name: p.name, user: p.user }, actor),
  "pg.drop": async (p, actor) => {
    await services.pgDrop(p.name, p.confirm, actor);
    await pgRemote.forgetDatabase(String(p.name), actor);
  },
  "pg.remote.status": () => pgRemote.status(),
  "pg.remote.enable": (p, actor) => pgRemote.enable({ domain: p.domain, allow: p.allow }, actor),
  "pg.remote.disable": (_p, actor) => pgRemote.disable(actor),
  "pg.remote.user.add": (p, actor) => pgRemote.addUser({ database: p.database }, actor),
  "pg.remote.user.remove": (p, actor) => pgRemote.removeUser({ user: p.user }, actor),

  // ---- shield (malware scan, IP reputation, login brute force)
  // ---- vulnerabilities and automatic patching
  "vulns.status": () => vulns.vulnStatus(),
  "vulns.scan": () => {
    void vulns.scan().catch(() => {});
  },
  "vulns.patch": (p, actor) => vulns.setPatching({ os: !!p.os, php: !!p.php, edge: !!p.edge }, actor),
  "vulns.patchNow": (_p, actor) => vulns.patchNow(actor),

  // ---- realtime (Pusher-compatible)
  "realtime.status": () => realtime.realtimeStatus(),
  "realtime.install": (_p, actor) => realtime.install(actor),
  "realtime.update": async (p, actor) => {
    const s = await realtime.realtimeStatus();
    if (!s.latest || !realtime.newer(s.latest, s.version)) throw new Error("already on the newest version");
    return realtime.update(s.latest, actor);
  },
  "realtime.check": () => realtime.checkUpdates(),
  "realtime.autoUpdate": (p, actor) => realtime.setAutoUpdate(!!p.on, actor),
  "realtime.uninstall": (p, actor) => {
    if (p.confirm !== "realtime") throw new Error("type realtime to confirm");
    return realtime.uninstall(actor);
  },
  "realtime.domain": (p, actor) => {
    const domain = String(p.domain ?? "").trim().toLowerCase();
    if (domain) {
      const all = parseDomains(domain);
      const d = all.length === 1 ? all[0] : undefined;
      if (!d || d.includes("*")) throw new Error("one domain, for example ws.example.com");
      appsOps.assertDomainsFree([d], { site: d }, allDomains());
    }
    return realtime.setDomain(domain ? parseDomains(domain)[0]! : "", actor);
  },
  "realtime.app.add": (p, actor) => realtime.addApp({ name: p.name, origins: p.origins, webhook_url: p.webhook_url, max_connections: p.max_connections }, actor),
  "realtime.app.update": (p, actor) => realtime.updateApp({ name: p.name, origins: p.origins, webhook_url: p.webhook_url, max_connections: p.max_connections }, actor),
  "realtime.app.remove": (p, actor) => {
    if (p.confirm !== p.name) throw new Error("type the app name to confirm");
    return realtime.removeApp(p.name, actor);
  },
  "realtime.app.reveal": (p) => realtime.revealApp(p.name),

  // ---- TURN (WebRTC relay for calls and games)
  "turn.status": () => turn.turnStatus(),
  "turn.install": (_p, actor) => turn.install(actor),
  "turn.domain": (p, actor) => turn.setDomain(String(p.domain ?? "").trim(), actor),
  "turn.tls": (p, actor) => turn.setTls(p.on === true || p.on === "1", actor),
  "turn.uninstall": (p, actor) => {
    if (p.confirm !== "turn") throw new Error("type turn to confirm");
    return turn.uninstall(actor);
  },
  "turn.reveal": () => turn.turnSecret(),
  /** New secret; apps that use TURN get it and restart, so nothing that leaked keeps working. */
  "turn.rotate": async (_p, actor) => {
    const secret = await turn.rotate(actor);
    for (const a of apps.list()) {
      const env = await appsOps.getEnv(a.name).catch(() => ({}) as Record<string, string>);
      if (!env.TURN_SECRET) continue;
      await appsOps.setEnv(a.name, { ...env, TURN_SECRET: secret }, actor);
      if (a.active_slot) await appsOps.appAction(a.name, "restart", actor).catch(() => {});
    }
  },
  "apps.addTurn": async (p, actor) => {
    const app = apps.get(v.appName(p.name));
    if (!app) throw new Error("no such app");
    const env = { get: () => appsOps.getEnv(app.name), set: (vars: Record<string, string>) => appsOps.setEnv(app.name, vars, actor) };
    await turn.toAppEnv(env, app.name, actor);
    if (app.active_slot) await appsOps.appAction(app.name, "restart", actor).catch(() => {});
  },

  // ---- scheduled jobs and queues
  "jobs.list": async () => ({ jobs: await jobs.listJobs(), crontabs: await jobs.legacyCrontabs() }),
  "jobs.run": (p, actor) => jobs.runJob(jobs.parseRef(p), actor),
  "jobs.logs": (p) => jobs.jobLogs(jobs.parseRef(p)),
  "queues.status": () => queues.queueStatus(),
  "queues.set": (p, actor) => queues.setQueues(!!p.on, actor),
  "queues.restartWorker": (p, actor) => queues.restartWorker(v.appName(p.app), String(p.process ?? ""), actor),

  "shield.status": () => shield.shieldStatus(),
  "shield.set": (p, actor) =>
    shield.setShield({ scan: !!p.scan, autoQuarantine: !!p.autoQuarantine, reputation: !!p.reputation, bruteforce: !!p.bruteforce }, actor),
  "shield.scan": (p, actor) => shield.startScan(!!p.full, actor),
  "shield.deepScan": (_p, actor) => shield.deepScan(actor),
  "shield.refresh": () => shield.refreshReputation(),
  "shield.quarantine": (p, actor) => shield.quarantine(v.int(p.id, 1, 1e9, "id"), actor),
  "shield.restore": (p, actor) => shield.restore(v.int(p.id, 1, 1e9, "id"), actor),
  "shield.ignore": (p, actor) => shield.ignore(v.int(p.id, 1, 1e9, "id"), actor),
  "shield.unban": (p, actor) => {
    if (typeof p.ip !== "string" || !/^[0-9a-fA-F:.]{3,45}$/.test(p.ip)) throw new Error("bad address");
    return shield.unban(p.ip, actor);
  },

  // ---- alerts (Telegram)
  "alerts.get": () => alerts.alertSettings(),
  "alerts.save": (p, actor) => {
    audit(actor, "alerts.save", { chatId: p.chatId, token: p.token ? "changed" : "kept" });
    return alerts.saveAlerts({ token: p.token, chatId: p.chatId });
  },
  "alerts.test": async () => {
    if (!(await alerts.notify("✅ test from pano"))) throw new Error("not sent: check the bot token and chat id (send /start to the bot first)");
    return "sent";
  },

  // ---- private access (WireGuard, off until enabled)
  "vpn.status": () => vpn.status(),
  "vpn.enable": (p, actor) => vpn.enable({ port: p.port, endpoint: p.endpoint }, actor),
  "vpn.disable": (_p, actor) => vpn.disable(actor),
  "vpn.peer.add": (p, actor) => vpn.addPeer({ name: p.name, publicKey: p.publicKey }, actor),
  "vpn.peer.remove": (p, actor) => vpn.removePeer(v.int(p.id, 1, 1e9, "id"), actor),
  "vpn.locks": (p, actor) => vpn.setLocks({ panel: !!p.panel, ssh: !!p.ssh, services: !!p.services, databases: !!p.databases }, Number(p.confirmSeconds ?? 300), actor),
  // ---- inbound firewall (optional, default-deny; an unconfirmed enable rolls itself back)
  "firewall.status": () => firewall.status(),
  "firewall.enable": (p, actor) => firewall.enable({ confirmSeconds: p.confirmSeconds }, actor),
  "firewall.confirm": (_p, actor) => firewall.confirm(actor),
  "firewall.disable": (_p, actor) => firewall.disable(actor),
  "firewall.ports": (p, actor) => firewall.setPorts(p.ports, actor),
  "guard.get": async () => ({ ...guard.guardSettings(), banned: await guard.banned() }),
  "guard.set": (p, actor) => guard.setGuard({ ssh: !!p.ssh, http: !!p.http }, actor),
  // `remote` is the address the web process saw the request come from.
  "vpn.confirm": (p, actor) => vpn.confirm(String(p.remote ?? ""), actor),

  // ---- PHP (installed per version, only when a site needs it)
  "php.versions": async () => {
    const used = new Set(sites.list().filter((s) => s.kind === "php").map((s) => s.php_version));
    const have = new Set(await php.installedPhp());
    return PHP_VERSIONS.map((ver) => ({ version: ver, installed: have.has(ver), inUse: used.has(ver), eol: PHP_EOL[ver] }));
  },
  "php.install": (p, actor) => php.installPhp(v.phpVersion(p.version), actor),
  "php.uninstall": (p, actor) => php.uninstallPhp(v.phpVersion(p.version), actor),

  // ---- sites (routing entries that are not managed apps)
  // Manual project moves (grouping is worked out in the UI); "" puts an item in a project of its own.
  "projects.moves": () => JSON.parse(settings.get("projects.moves") ?? "{}") as Record<string, string>,
  "projects.move": (p, actor) => {
    const key = /^(app|site):[A-Za-z0-9._*-]{1,253}$/;
    const item = String(p.item ?? "");
    const target = String(p.target ?? "");
    if (!key.test(item) || (target && !key.test(target))) throw new Error("bad project item");
    const moves = JSON.parse(settings.get("projects.moves") ?? "{}") as Record<string, string>;
    moves[item] = target;
    settings.set("projects.moves", JSON.stringify(moves));
    audit(actor, "projects.move", { item, target });
    return moves;
  },
  "sites.list": () => sites.list(),
  "sites.certs": () => siteCerts(),
  "sites.createPhp": async (p, actor) => {
    const domains = parseDomains(p.domains);
    appsOps.assertDomainsFree(domains, { site: v.siteName(p.name) }, allDomains());
    return php.createPhpSite({ name: p.name, domains, version: p.php_version || DEFAULT_PHP }, actor);
  },
  "sites.phpVersion": async (p, actor) => {
    await php.setPhpVersion(p.name, p.version, actor);
    await jobs.writeSiteCrons(v.siteName(p.name));
  },
  "sites.convertPhp": (p, actor) => php.convertLegacy(p.name, p.version, actor),
  "sites.revertPhp": async (p, actor) => {
    await php.revertConvert(p.name, actor);
    await jobs.writeSiteCrons(v.siteName(p.name));
  },
  "sites.crons": (p, actor) => jobs.setSiteCrons(p.name, p.crons, actor),
  "sites.fixPermissions": async (p, actor) => {
    const warnings = await php.fixPermissions(v.siteName(p.name));
    audit(actor, "php.site.permissions", { name: p.name });
    return warnings;
  },
  "sites.logs": (p) => php.phpLogs(p.name),
  // ---- WordPress (wp-cli, as the site user)
  "wp.detect": (p) => wordpress.detect(p.name),
  "wp.status": (p) => wordpress.status(p.name),
  "wp.install": (p, actor) => wordpress.install(p, actor),
  "wp.update": (p, actor) => wordpress.update({ name: p.name, core: !!p.core, plugins: p.plugins, themes: p.themes }, actor),
  "wp.maintenance": (p, actor) => wordpress.setMaintenance(p.name, !!p.on, actor),
  "wp.resetPassword": (p, actor) => wordpress.resetPassword(p.name, p.userId, actor),
  "wp.autoUpdate": (p, actor) => wordpress.setAutoUpdate(p.name, !!p.on, actor),
  "sites.save": async (p, actor) => {
    const name = v.siteName(p.name);
    const kind = p.kind as Site["kind"];
    if (!["legacy", "static", "proxy", "php"].includes(kind)) throw new Error("invalid kind");
    const clean = parseDomains(p.domains);
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
    // PHP sites need a user, pool and unit: they come from sites.createPhp / convertPhp, then only change here.
    if ((kind === "php") !== (prev?.kind === "php")) throw new Error("use the PHP site form to create or convert PHP sites");
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
    const site = sites.get(v.siteName(p.name));
    if (!site) throw new Error("not found");
    sites.setEnabled(site.name, !!p.enabled);
    if (site.kind === "php") await php.setPhpEnabled(site, !!p.enabled);
    await jobs.writeSiteCrons(site.name);
    await applyEdge();
    audit(actor, "site.toggle", { name: site.name, enabled: !!p.enabled });
  },
  "sites.delete": async (p, actor) => {
    if (p.confirm !== p.name) throw new Error("type the site name to confirm");
    const site = sites.get(v.siteName(p.name));
    if (!site) throw new Error("not found");
    if (site.kind === "php") await php.deletePhpSite(site, !!p.removeFiles);
    sites.remove(site.name);
    await jobs.writeSiteCrons(site.name);
    await applyEdge();
    audit(actor, "site.delete", { name: site.name, removeFiles: !!p.removeFiles });
  },

  // ---- edge
  "edge.status": async () => ({
    installed: await edgeInstalled(),
    active: await edgeActive(),
    cutover: settings.get("edge.cutover") === "1",
    settings: edgeSettings(),
    cloudflare: cloudflare.cloudflareStatus(),
  }),
  "edge.preview": () => buildCaddyfile(),
  "cloudflare.check": async () => ({ dns: await cloudflare.checkDns(), problems: await cloudflare.lockProblems() }),
  "cloudflare.lock": (p, actor) => cloudflare.setLock(!!p.on, !!p.force, actor),
  "cloudflare.refresh": () => cloudflare.refreshRanges(true),
  "edge.install": async (_p, actor) => {
    const ver = await installCaddy();
    await setupEdgeUnit();
    audit(actor, "edge.install", { version: ver });
    return ver;
  },
  "edge.settings": async (p, actor) => {
    const email = String(p.email ?? "").trim();
    // Goes into the Caddyfile as is: no braces, quotes or anything Caddy would parse.
    if (email && !/^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$/.test(email)) throw new Error("invalid email");
    const hooksDomain = p.hooksDomain ? v.domain(p.hooksDomain) : "";
    if (!p.behindCloudflare && cloudflare.cloudflareStatus().locked) throw new Error("ports 80 and 443 are locked to Cloudflare: unlock them first");
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
  "db.create": async (p, actor) => {
    const r = await mysql.createDatabase({ name: p.name, user: p.user, password: p.password }, actor);
    backup.ensureJob("mysql", r.name, actor);
    return r;
  },
  "db.drop": async (p, actor) => {
    await mysql.dropDatabase(p.name, p.confirm, actor);
    await mysqlRemote.forgetDatabase(String(p.name), actor);
  },
  "mysql.remote.status": () => mysqlRemote.status(),
  "mysql.remote.enable": (p, actor) => mysqlRemote.enable({ domain: p.domain, allow: p.allow }, actor),
  "mysql.remote.disable": (_p, actor) => mysqlRemote.disable(actor),
  "mysql.remote.user.add": (p, actor) => mysqlRemote.addUser({ database: p.database }, actor),
  "mysql.remote.user.remove": (p, actor) => mysqlRemote.removeUser({ user: p.user }, actor),
  "db.password": (p, actor) => mysql.setPassword(p.user, p.host, p.password, actor),
  "db.grant": (p, actor) => mysql.grant(p.db, p.user, actor),

  // ---- backups
  "backup.settings": async () => ({
    dests: { a: await backup.getDest("a"), b: await backup.getDest("b") },
    engine: backup.engine(),
    restic: await backup.resticVersion(),
    kit: await recovery.kitState(),
  }),
  "recovery.kit": (_p, actor) => recovery.recoveryKit(actor),
  "recovery.rebuild": (_p, actor) => recovery.startRebuild(actor),
  "recovery.status": () => recovery.recoveryStatus(),
  "tune.status": () => tune.tuningStatus(),
  "tune.set": (p, actor) => tune.setKernelTuning(!!p.on, actor),
  "backup.dest.set": (p, actor) => backup.setDest(backup.parseDest(p.dest), p, actor),
  "backup.dest.clear": (p, actor) => backup.clearDest(backup.parseDest(p.dest), actor),
  "backup.dest.test": (p) => backup.testDest(backup.parseDest(p.dest)),
  "backup.engine": (p, actor) => backup.setEngine(p.engine, actor),
  "backup.prune": (_p, actor) => backup.pruneRepos(actor),
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

  // ---- import from cPanel backups (cpmove archives in /var/lib/pano/imports)
  "import.cpanel.list": () => cpanel.listArchives(),
  "import.cpanel.scan": (p) => cpanel.scanArchive(String(p.file ?? "")),
  "import.cpanel.apply": (p, actor) =>
    cpanel.applyArchive(String(p.file ?? ""), { sites: (p.sites ?? []).map(String), databases: (p.databases ?? []).map(String) }, actor),
};

function parseDomains(x: unknown): string[] {
  const list = (Array.isArray(x) ? x : String(x ?? "").split(/[\s,]+/)).filter(Boolean).map(String);
  if (!list.length) throw new Error("at least one domain");
  return [...new Set(list.map((d) => (d === "*" ? "*" : v.domain(d))))];
}

function hideSecret<T extends { webhook_secret?: string; env_running?: string; env_built?: string }>(a: T): T {
  return { ...a, webhook_secret: a.webhook_secret ? "set" : "", env_running: undefined, env_built: undefined };
}

function envScope(s: unknown): appsOps.EnvScope {
  if (s === undefined || s === "" || s === "production") return "production";
  if (s === "preview") return "preview";
  throw new Error("scope: production or preview");
}
const masked = (env: Record<string, string>) => Object.fromEntries(Object.keys(env).map((k) => [k, ENV_MASK]));

/** Editor input to variables: a masked value keeps what is stored. */
function unmask(input: unknown, current: Record<string, string>): Record<string, string> {
  const vars: Record<string, string> = {};
  for (const [k, val] of Object.entries((input ?? {}) as Record<string, unknown>)) {
    const key = v.envKey(k);
    if (val === ENV_MASK) {
      if (!(key in current)) throw new Error(`${key}: enter a value`);
      vars[key] = current[key]!;
    } else vars[key] = v.envValue(val);
  }
  return vars;
}
