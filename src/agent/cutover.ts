// Cutover: the edge takes :80/:443 and OpenLiteSpeed moves to localhost as a
// backend for legacy PHP sites. Every step is reversible and a failed check
// rolls back automatically to the exact previous OLS config.

import { chown, stat } from "node:fs/promises";
import { DRY_RUN, env, fsPath, paths } from "../shared/config.ts";
import { applyEdge, edgeActive, edgeInstalled, setupEdgeUnit } from "./edge.ts";
import { blocks, lines, parseOls, readServerConfig, serializeOls, setValue } from "./ols.ts";
import { audit, settings, sites } from "./state.ts";
import { ensureDir, exists, readText, run, writeAtomic } from "./sys.ts";

const OLS_CONF = `${paths.ols}/conf/httpd_config.conf`;

/** Rewrites every OLS listener to a unique localhost port; HTTP lands on olsBackendPort. */
export function moveListenersToLocalhost(text: string, httpPort: number): string {
  const root = parseOls(text);
  let next = httpPort + 1;
  for (const l of blocks(root, "listener")) {
    const addr = lines(l, "address")[0];
    if (!addr) continue;
    const secure = lines(l, "secure")[0]?.value === "1";
    setValue(addr, secure ? `127.0.0.1:${next++}` : `127.0.0.1:${httpPort}`);
  }
  return serializeOls(root);
}

/** Replaces the OLS server config keeping the file's original owner and mode. */
async function writeOlsConf(text: string) {
  const st = await stat(fsPath(OLS_CONF));
  await writeAtomic(OLS_CONF, text, st.mode & 0o777);
  if (!DRY_RUN && process.getuid?.() === 0) await chown(fsPath(OLS_CONF), st.uid, st.gid);
}

/** Full stop/start: a graceful restart keeps the old listening sockets, so :80/:443 would stay taken. */
async function olsRestart() {
  // CyberPanel runs OLS as lshttpd.service; plain installs may not use systemd.
  const managed = (await run(["systemctl", "is-active", "lshttpd"], { check: false })).stdout.trim() === "active";
  const ctl = fsPath(`${paths.ols}/bin/lswsctrl`);
  if (managed) await run(["systemctl", "stop", "lshttpd"], { timeoutMs: 60_000, check: false });
  // quiet: the daemon inherits stdout, so capturing it would never see EOF
  await run([ctl, "stop"], { timeoutMs: 60_000, check: false, quiet: true });
  for (let i = 0; i < 20 && !(await portFree(80)); i++) await Bun.sleep(500);
  if (managed) await run(["systemctl", "start", "lshttpd"], { timeoutMs: 60_000 });
  else await run([ctl, "start"], { timeoutMs: 60_000, quiet: true });
}

const allListenersLocal = (text: string) =>
  readServerConfig(text).listeners.every((l) => l.address.startsWith("127.0.0.1:") || l.address.startsWith("[::1]:"));

async function portFree(port: number): Promise<boolean> {
  const r = await run(["ss", "-Htln", `sport = :${port}`], { check: false });
  return r.stdout.trim() === "";
}

async function probe(domain: string): Promise<string> {
  const r = await run(
    ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", "--resolve", `${domain}:443:127.0.0.1`, `https://${domain}/`],
    { check: false },
  );
  return r.stdout.trim() || `error ${r.code}`;
}

export type CutoverReport = { ok: boolean; steps: string[]; probes: { domain: string; status: string }[] };

export async function cutover(actor: string): Promise<CutoverReport> {
  const steps: string[] = [];
  const say = (s: string) => steps.push(s);
  if (settings.get("edge.cutover") === "1") throw new Error("cutover already done");
  if (!(await edgeInstalled())) throw new Error("install the edge (Caddy) first");
  const original = await readText(OLS_CONF);
  const hasOls = original !== null;
  // A half-finished earlier attempt leaves OLS on localhost; never back that up as the "original".
  if (hasOls && allListenersLocal(original)) throw new Error("OpenLiteSpeed already listens on localhost only; run Rollback first");
  if (hasOls && !(await portFree(env.olsBackendPort))) throw new Error(`port ${env.olsBackendPort} is in use; set PANO_OLS_BACKEND_PORT`);

  await setupEdgeUnit();
  await applyEdge();
  say("edge config rendered and validated");

  let backup = "";
  if (hasOls) {
    await ensureDir(paths.configBackups, 0o700);
    backup = `${paths.configBackups}/httpd_config.${Date.now()}.conf`;
    await writeAtomic(backup, original, 0o600);
    settings.set("edge.olsBackup", backup);
    say(`saved ${OLS_CONF} -> ${backup}`);
  }

  try {
    if (hasOls) {
      await writeOlsConf(moveListenersToLocalhost(original, env.olsBackendPort));
      await olsRestart();
      await Bun.sleep(3000);
      say(`OpenLiteSpeed moved to 127.0.0.1:${env.olsBackendPort}`);
    }
    await run(["systemctl", "enable", "--now", "pano-edge"]);
    await Bun.sleep(4000);
    if (!(await edgeActive())) throw new Error("pano-edge did not start (journalctl -u pano-edge)");
    say("edge running on :80 and :443");
  } catch (e) {
    say(`failed: ${e instanceof Error ? e.message : String(e)}; rolling back`);
    await rollback(actor, steps);
    audit(actor, "edge.cutover.failed", steps.join("\n"));
    return { ok: false, steps, probes: [] };
  }

  settings.set("edge.cutover", "1");
  const probes: CutoverReport["probes"] = [];
  const domains = sites
    .list()
    .filter((s) => s.enabled)
    .flatMap((s) => s.domains)
    .filter((d) => !d.includes("*"))
    .slice(0, 30);
  for (const d of domains) probes.push({ domain: d, status: await probe(d) });
  audit(actor, "edge.cutover", { steps, probes });
  return { ok: true, steps, probes };
}

export async function rollback(actor: string, steps: string[] = []): Promise<string[]> {
  await run(["systemctl", "disable", "--now", "pano-edge"], { check: false });
  steps.push("edge stopped");
  const backup = settings.get("edge.olsBackup");
  if (backup && (await exists(backup))) {
    await writeOlsConf((await readText(backup))!);
    await olsRestart();
    steps.push(`OpenLiteSpeed config restored from ${backup}`);
  }
  settings.set("edge.cutover", "0");
  audit(actor, "edge.rollback", steps.join("\n"));
  return steps;
}
