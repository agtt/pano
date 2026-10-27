// pano-agent: the only privileged process. Listens on a unix socket that only
// root and the `pano` group (the web process) can open, plus a localhost-only
// port that answers Caddy's on-demand TLS questions.

import { chmod, chown, unlink } from "node:fs/promises";
import { DRY_RUN, env, fsPath, paths } from "../shared/config.ts";
import { ValidationError } from "../shared/validate.ts";
import { startScheduler } from "./backup.ts";
import { methods } from "./rpc.ts";
import { apps, backups, deploys, sites, state } from "./state.ts";
import { ensureDir, lookupUser } from "./sys.ts";

export async function startAgent() {
  if (!DRY_RUN && process.getuid?.() !== 0) throw new Error("pano agent must run as root");
  state();
  deploys.failStale();
  backups.failStale();
  await ensureDir(paths.run, 0o750);
  const group = await lookupUser("pano");
  // Only root and the web process (group pano) may reach the socket.
  if (group && process.getuid?.() === 0) await chown(fsPath(paths.run), 0, group.gid);

  const socket = fsPath(paths.agentSocket);
  await unlink(socket).catch(() => {});
  Bun.serve({
    unix: socket,
    async fetch(req) {
      const url = new URL(req.url);
      const method = url.pathname.replace(/^\/rpc\//, "");
      const handler = methods[method];
      if (req.method !== "POST" || !handler) return Response.json({ ok: false, error: "unknown method" }, { status: 404 });
      let body: { params?: Record<string, unknown>; actor?: string };
      try {
        body = (await req.json()) as typeof body;
      } catch {
        return Response.json({ ok: false, error: "bad json" }, { status: 400 });
      }
      const actor = String(body.actor ?? "unknown").slice(0, 64);
      try {
        const result = await handler(body.params ?? {}, actor);
        return Response.json({ ok: true, result: result ?? null });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        if (!(e instanceof ValidationError)) console.error(`[agent] ${method}: ${msg}`);
        return Response.json({ ok: false, error: msg }, { status: e instanceof ValidationError ? 400 : 500 });
      }
    },
  });
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
      const all = [...apps.list().map((a) => a.domains), ...sites.list().filter((s) => s.enabled).map((s) => s.domains)].flat();
      if (all.includes(domain)) return new Response("ok");
      const matchesWildcard = (d: string) => {
        if (!d.startsWith("*.") || !domain.endsWith(d.slice(1))) return false;
        const label = domain.slice(0, domain.length - d.length + 1);
        return /^[a-z0-9-]+$/.test(label);
      };
      if (all.some(matchesWildcard)) return new Response("ok");
      for (const s of sites.list().filter((x) => x.enabled && x.domains.includes("*") && x.ask_url)) {
        const r = await fetch(`${s.ask_url}?domain=${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(3000) }).catch(() => null);
        if (r?.ok) return new Response("ok");
      }
      return new Response("no", { status: 403 });
    },
  });

  startScheduler();
  console.log(`[agent] ready on ${paths.agentSocket}${DRY_RUN ? " (dry-run)" : ""}`);
}
