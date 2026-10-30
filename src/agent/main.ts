// pano-agent: the only privileged process. Listens on a unix socket that only
// root and the `pano` group (the web process) can open, plus a localhost-only
// port that answers Caddy's on-demand TLS questions.

import { timingSafeEqual } from "node:crypto";
import { chmod, chown, unlink } from "node:fs/promises";
import { DRY_RUN, env, fsPath, paths } from "../shared/config.ts";
import { ValidationError } from "../shared/validate.ts";
import { startMonitor } from "./alerts.ts";
import { cleanupAndroid } from "./android.ts";
import { startMetrics } from "./metrics.ts";
import { startRealtime } from "./realtime.ts";
import { startVulns } from "./vulns.ts";
import { applyTuning } from "./tune.ts";
import { ensureDefaultJobs } from "./recovery.ts";
import { startShield } from "./shield.ts";
import { startScheduler } from "./backup.ts";
import { cliToken, checkOtp, grantValid, issueGrant, migrateFromWeb } from "./otp.ts";
import { methods, needsOtp } from "./rpc.ts";
import { reloadUpdatedPhp } from "./php.ts";
import { sweepPreviews } from "./previews.ts";
import { type App, appHosts, apps, backups, deploys, previews, procsOf, pruneAudit, sites, state } from "./state.ts";
import { ensureDir, lookupUser } from "./sys.ts";
import { startFirewall } from "./firewall.ts";
import { renewTlsCert } from "./turn.ts";
import { recoverPending } from "./vpn.ts";

const sameSecret = (given: string | null, secret: string) =>
  !!given && given.length === secret.length && timingSafeEqual(Buffer.from(given), Buffer.from(secret));

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
      let body: { params?: Record<string, unknown>; actor?: string; otp?: string; grant?: string };
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
      if (needsOtp(method, params) && !sameSecret(req.headers.get("x-pano-cli"), cli) && !grantValid(body.grant, actor)) {
        if (!body.otp) return Response.json({ ok: false, error: "Authenticator code required for this action." }, { status: 403 });
        if (!checkOtp(actor, body.otp)) return Response.json({ ok: false, error: "Authenticator code wrong or already used (wait for a new code)." }, { status: 403 });
        grant = issueGrant(actor);
      }
      try {
        const result = await handler(params, actor);
        return Response.json({ ok: true, result: result ?? null, grant });
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
        ...sites.list().filter((s) => s.enabled).map((s) => ({ hosts: s.domains, ask: s.ask_url, ports: s.routes.map((r) => r.upstream.split(":").at(-1)!) })),
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
      if (all.some(matchesWildcard)) return new Response("ok");
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
  // A lock change still waiting for confirmation survives agent restarts and reboots.
  await recoverPending().catch((e) => console.error(`[agent] vpn: ${e}`));
  await startFirewall().catch((e) => console.error(`[agent] firewall: ${e}`));
  // OS updates bring PHP patch releases (same minor); restart pools onto the new binary.
  setInterval(() => reloadUpdatedPhp().catch((e) => console.error(`[agent] php reload: ${e}`)), 10 * 60_000);
  // coturn reads its certificate at start: pick up the edge's renewals (only does anything when TURN over TLS is on).
  setInterval(() => renewTlsCert().catch((e) => console.error(`[agent] turn cert: ${e}`)), 6 * 3600_000);
  pruneAudit();
  setInterval(() => pruneAudit(), 24 * 3600_000);
  console.log(`[agent] ready on ${paths.agentSocket}${DRY_RUN ? " (dry-run)" : ""}`);
}
