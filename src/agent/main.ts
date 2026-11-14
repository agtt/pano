// pano-agent: the only privileged process. Listens on a unix socket that only
// root and the `pano` group (the web process) can open, plus a localhost-only
// port that answers Caddy's on-demand TLS questions.

import { timingSafeEqual } from "node:crypto";
import { chmod, chown, unlink } from "node:fs/promises";
import { DRY_RUN, env, fsPath, paths } from "../shared/config.ts";
import { ValidationError } from "../shared/validate.ts";
import { notify, startMonitor } from "./alerts.ts";
import { cleanupAndroid } from "./android.ts";
import { startMetrics } from "./metrics.ts";
import { startRealtime } from "./realtime.ts";
import { startVulns } from "./vulns.ts";
import { applyTuning } from "./tune.ts";
import { ensureDefaultJobs } from "./recovery.ts";
import { startShield } from "./shield.ts";
import { startScheduler } from "./backup.ts";
import { cliToken, checkOtp, grantValid, issueGrant, issueTrust, migrateFromWeb, trustValid } from "./otp.ts";
import { alwaysAsk, methods, needsOtp } from "./rpc.ts";
import { startRunner } from "./runner.ts";
import { applyLocalPorts } from "./localports.ts";
import { reloadUpdatedPhp } from "./php.ts";
import { sweepPreviews } from "./previews.ts";
import { type App, appHosts, apps, backups, deploys, previews, procsOf, pruneAudit, settings, sites, state } from "./state.ts";
import { ensureDir, lookupUser } from "./sys.ts";
import { refreshRanges } from "./cloudflare.ts";
import { startFirewall } from "./firewall.ts";
import { narrowWildcardGrants } from "./mysql.ts";
import { renewTlsCert } from "./turn.ts";
import { renew as renewPgRemote } from "./pgremote.ts";
import { renew as renewMysqlRemote } from "./mysqlremote.ts";
import { recoverPending } from "./vpn.ts";

const sameSecret = (given: string | null, secret: string) =>
  !!given && given.length === secret.length && timingSafeEqual(Buffer.from(given), Buffer.from(secret));

/** Code-guarded actions that leave lasting access: each use of a code for one is sent to the alert channel. */
const REPORTED = new Set([
  "admins.add", "admins.reset", "runner.enable", "runner.key.add", "vpn.peer.add", "pg.remote.user.add", "mysql.remote.user.add",
  "github.connect", "backup.dest.set", "backup.dest.connect", "backup.key.export", "recovery.kit", "alerts.save",
]);

/**
 * Names under a wildcard host that already got a certificate pass. New ones: at most 5 an hour per
 * wildcard and 20 a week per registered domain (counted across restarts), so random names sent at the
 * server cannot use up Let's Encrypt's 50 a week for the domain: the domain's own hosts and previews
 * keep at least 30.
 */
const WILDCARD_NEW_PER_HOUR = 5;
const WILDCARD_NEW_PER_WEEK = 20;
const WEEK_MS = 7 * 86400_000;
let wildcardSeen: Set<string> | null = null;

/** Registered domain, erring wide: "a.b.example.co.uk" -> "example.co.uk", "x.example.com" -> "example.com". */
export function registeredDomain(host: string): string {
  const labels = host.replace(/^\*\./, "").split(".");
  // Second-level suffixes like co.uk, com.au, com.tr: one more label. A private suffix (user.github.io) counts as
  // its parent, which only makes the cap stricter.
  const n = labels.length >= 3 && labels.at(-1)!.length === 2 && /^(co|com|net|org|gov|edu|ac|ltd|plc|me|gen|web|nom|biz|info|or|ne|go|in|nic|k12|mil|av|bel|bbs|tv)$/.test(labels.at(-2)!) ? 3 : 2;
  return labels.slice(-n).join(".");
}

export function wildcardAllowed(wildcard: string, domain: string, now = Date.now()): boolean {
  wildcardSeen ??= new Set<string>(JSON.parse(settings.get("edge.wildcard.seen") ?? "[]"));
  if (wildcardSeen.has(domain)) return true;
  // Registered domain -> [wildcard, time] of each new name in the last week.
  let issued: Record<string, [string, number][]> = {};
  try {
    issued = JSON.parse(settings.get("edge.wildcard.issued") ?? "{}");
  } catch {}
  const reg = registeredDomain(wildcard);
  const week = (issued[reg] ?? []).filter(([, t]) => now - t < WEEK_MS);
  if (week.length >= WILDCARD_NEW_PER_WEEK) return false;
  if (week.filter(([w, t]) => w === wildcard && now - t < 3600_000).length >= WILDCARD_NEW_PER_HOUR) return false;
  issued[reg] = [...week, [wildcard, now]];
  for (const k of Object.keys(issued)) if (!issued[k]!.some(([, t]) => now - t < WEEK_MS)) delete issued[k];
  settings.set("edge.wildcard.issued", JSON.stringify(issued));
  wildcardSeen.add(domain);
  settings.set("edge.wildcard.seen", JSON.stringify([...wildcardSeen].slice(-5000)));
  return true;
}

export async function startAgent() {
  if (!DRY_RUN && process.getuid?.() !== 0) throw new Error("pano agent must run as root");
  state();
  deploys.failStale();
  backups.failStale();
  await ensureDir(paths.run, 0o750);
  const group = await lookupUser("pano");
  // Only root and the web process (group pano) may reach the socket.
  if (group && process.getuid?.() === 0) await chown(fsPath(paths.run), 0, group.gid);

  await migrateFromWeb().catch((e) => console.error(`[agent] otp migration: ${e}`));
  const cli = await cliToken();

  const socket = fsPath(paths.agentSocket);
  await unlink(socket).catch(() => {});
  const umask = process.umask(0o077); // the socket starts root-only until chmod/chown below
  Bun.serve({
    maxRequestBodySize: 4 * 1024 * 1024,
    unix: socket,
    async fetch(req) {
      const url = new URL(req.url);
      const method = url.pathname.replace(/^\/rpc\//, "");
      const handler = Object.hasOwn(methods, method) ? methods[method] : undefined;
      if (req.method !== "POST" || !handler) return Response.json({ ok: false, error: "unknown method" }, { status: 404 });
      let body: { params?: Record<string, unknown>; actor?: string; otp?: string; grant?: string; trust?: string };
      try {
        body = (await req.json()) as typeof body;
      } catch {
        return Response.json({ ok: false, error: "bad json" }, { status: 400 });
      }
      const actor = String(body.actor ?? "unknown").slice(0, 64);
      const params = body.params ?? {};
      // Step-up: a code checked here (not in the web process), or a grant from one checked moments ago.
      // Only for methods that need it: a code sent anywhere else is ignored, so calls cannot
      // be used to burn the admin's attempts (lockout) or to mint grants.
      let grant: string | undefined;
      let trust: string | undefined;
      if (needsOtp(method, params) && !sameSecret(req.headers.get("x-pano-cli"), cli)) {
        // Always-ask actions take only a code sent with this call: the trusted window and grants never cover them.
        const always = await alwaysAsk(method, params);
        const passed = !always && (trustValid(body.trust, actor) || grantValid(body.grant, actor, method, params));
        if (!passed) {
          if (!body.otp) return Response.json({ ok: false, error: always ? "This action always needs a new authenticator code." : "Authenticator code required for this action." }, { status: 403 });
          if (!checkOtp(actor, body.otp)) return Response.json({ ok: false, error: "Authenticator code wrong or already used (wait for a new code)." }, { status: 403 });
          if (!always) grant = issueGrant(actor, method, params);
          trust = issueTrust(actor);
          // The code came through the web process, which could have sent it with another method than the
          // admin's form: actions that leave lasting access are reported on the alert channel (before
          // alerts.save can change it).
          if (REPORTED.has(method)) await notify(`🔐 ${actor} used a 2FA code for ${method}${typeof params.username === "string" ? ` (${params.username.slice(0, 64)})` : ""}`);
        }
      }
      try {
        const result = await handler(params, actor);
        // Signing in with a code trusts the new session the same way.
        if (method === "auth.otp" && result === true) trust = issueTrust(String(params.username ?? ""));
        return Response.json({ ok: true, result: result ?? null, grant, trust });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        if (!(e instanceof ValidationError)) console.error(`[agent] ${method}: ${msg}`);
        return Response.json({ ok: false, error: msg }, { status: e instanceof ValidationError ? 400 : 500 });
      }
    },
  });
  process.umask(umask);
  await chmod(socket, 0o660);
  if (group && process.getuid?.() === 0) await chown(socket, 0, group.gid);

  // Caddy asks before issuing an on-demand certificate. Allow only hosts we
  // serve; for catch-all sites, the site's own ask URL decides.
  Bun.serve({
    hostname: "127.0.0.1",
    port: env.askPort,
    async fetch(req) {
      const domain = new URL(req.url).searchParams.get("domain")?.toLowerCase() ?? "";
      if (!/^[a-z0-9.-]{1,253}$/.test(domain)) return new Response("bad", { status: 400 });
      // An ask URL may only reach the owner's own upstream ports, never another local service.
      const appPorts = (a: App) => (a.kind === "external" ? [a.upstream.split(":").at(-1)!] : procsOf(a).flatMap((p) => [String(p.port_a), String(p.port_b)]));
      const owners = [
        ...apps.list().map((a) => ({ hosts: appHosts(a), ask: a.ask_url, ports: appPorts(a) })),
        // Suspended sites too: the edge keeps serving their domains (the suspended page) over HTTPS.
        ...sites.list().map((s) => ({ hosts: s.domains, ask: s.ask_url, ports: s.routes.map((r) => r.upstream.split(":").at(-1)!) })),
        // Preview hosts: certificates only for previews that exist (no ask URL, never a catch-all).
        ...previews.list().map((pv) => ({ hosts: [pv.host], ask: "", ports: [] as string[] })),
      ];
      const all = owners.flatMap((o) => o.hosts);
      if (all.includes(domain)) return new Response("ok");
      const matchesWildcard = (d: string) => {
        if (!d.startsWith("*.") || !domain.endsWith(d.slice(1))) return false;
        const label = domain.slice(0, domain.length - d.length + 1);
        return /^[a-z0-9-]+$/.test(label);
      };
      const wildcard = all.find(matchesWildcard);
      if (wildcard) return wildcardAllowed(wildcard, domain) ? new Response("ok") : new Response("too many new names", { status: 429 });
      for (const o of owners.filter((x) => x.hosts.includes("*") && x.ask && x.ports.includes(new URL(x.ask).port))) {
        const r = await fetch(`${o.ask}?domain=${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(3000), redirect: "manual" }).catch(() => null);
        if (r?.ok) return new Response("ok");
      }
      return new Response("no", { status: 403 });
    },
  });

  ensureDefaultJobs();
  startScheduler();
  startMonitor();
  startMetrics();
  startShield();
  startRealtime();
  startVulns();
  // Previews past their lifetime go (hourly; every new preview sweeps as well).
  setInterval(() => sweepPreviews().catch((e) => console.error(`[agent] previews: ${e}`)), 60 * 60_000);
  applyTuning().catch((e) => console.error(`[agent] tuning: ${e}`));
  // Android builds cut off by a restart fail; their sandboxes are removed.
  cleanupAndroid().catch((e) => console.error(`[agent] android: ${e}`));
  startRunner().catch((e) => console.error(`[agent] runner: ${e}`));
  if (!DRY_RUN) applyLocalPorts().catch((e) => console.error(`[agent] local ports: ${e}`));
  if (!DRY_RUN) narrowWildcardGrants().catch((e) => console.error(`[agent] mysql grants: ${e}`));
  // Cloudflare's ranges, at most daily (the edge trusts them; the lock lets only them in).
  const cfRanges = () => refreshRanges().catch((e) => console.error(`[agent] cloudflare ranges: ${e}`));
  if (!DRY_RUN) {
    cfRanges();
    setInterval(cfRanges, 6 * 3600_000);
  }
  // A lock change still waiting for confirmation survives agent restarts and reboots.
  await recoverPending().catch((e) => console.error(`[agent] vpn: ${e}`));
  await startFirewall().catch((e) => console.error(`[agent] firewall: ${e}`));
  // OS updates bring PHP patch releases (same minor); restart pools onto the new binary.
  setInterval(() => reloadUpdatedPhp().catch((e) => console.error(`[agent] php reload: ${e}`)), 10 * 60_000);
  // coturn reads its certificate at start: pick up the edge's renewals (only does anything when TURN over TLS is on).
  setInterval(() => renewTlsCert().catch((e) => console.error(`[agent] turn cert: ${e}`)), 6 * 3600_000);
  // The same for database remote access; also sets it up again after a recovery or an address change.
  setInterval(() => renewPgRemote().catch((e) => console.error(`[agent] pg remote: ${e}`)), 6 * 3600_000);
  setInterval(() => renewMysqlRemote().catch((e) => console.error(`[agent] mysql remote: ${e}`)), 6 * 3600_000);
  pruneAudit();
  setInterval(() => pruneAudit(), 24 * 3600_000);
  console.log(`[agent] ready on ${paths.agentSocket}${DRY_RUN ? " (dry-run)" : ""}`);
}
