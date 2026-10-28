// Disaster recovery: bringing this server back on a new one.
//
// What it needs: the nightly backup of the panel itself (job "panel": state,
// configuration, secrets, certificates; see backup.ts) and the recovery kit, the
// one thing kept off the server (a password manager): the backup key and the
// store credentials. On a fresh server: `pano install`, then `pano recover
// <kit>`. The newest panel backup comes back (what was there is moved aside,
// never deleted), the agent starts on it, and rebuild() puts everything else
// back from the stores: services, database users with the passwords the apps
// already have, the databases, every app's env, data and deploy key followed by
// a deploy from git, the PHP sites with their files, the extensions, the edge.

import { S3Client } from "bun";
import { fsPath, paths } from "../shared/config.ts";
import { v } from "../shared/validate.ts";
import { notify } from "./alerts.ts";
import { appHome, appUser, ensureAppHome, getEnv, startDeploy, writeUnits } from "./apps.ts";
import {
  backupHost,
  backupKey,
  client,
  creds,
  destIds,
  ensureJob,
  ensureRestic,
  regionFor,
  restic,
  resticEnv,
  type DestId,
} from "./backup.ts";
import { decryptStream } from "./crypto-stream.ts";
import { EDGE_USER, applyEdge, edgeInstalled, installCaddy, setupEdgeUnit } from "./edge.ts";
import { ident, lit, restoreCommand, sql } from "./mysql.ts";
import { reprovisionSite, startRestoredSite } from "./php.ts";
import * as realtime from "./realtime.ts";
import { install as installRuntime, runtimeBin } from "./runtimes.ts";
import { ensureService, pgEnsure, pgEnsureDb, pgName, pgRestoreCommand, recordedServices, reinstall, type ServiceKey } from "./services.ts";
import { apps, audit, backups, settings, sites, type BackupJob } from "./state.ts";
import { ensureDir, exists, readText, remove, run, writeAtomic } from "./sys.ts";
import * as turn from "./turn.ts";


// ---- the kit ------------------------------------------------------------------------

export const KIT_PREFIX = "pano-recovery-1:";
export type KitDest = { endpoint: string; bucket: string; prefix: string; accessKeyId: string; secret: string };
export type Kit = { key: string; host: string; dests: KitDest[] };

/** Everything needed to recover, as one line for a password manager. Shown only with 2FA. */
export async function recoveryKit(actor: string): Promise<string> {
  const dests: KitDest[] = [];
  for (const d of destIds()) {
    const c = await creds(d);
    dests.push({ endpoint: c.url, bucket: c.bucket, prefix: c.prefix, accessKeyId: c.accessKeyId, secret: c.secret });
  }
  if (!dests.length) throw new Error("set up a backup destination first");
  const kit: Kit = { key: (await backupKey()).toString("base64"), host: backupHost(), dests };
  settings.set("recovery.exportedAt", String(Math.floor(Date.now() / 1000)));
  settings.set("recovery.exportedDests", kitFingerprint(dests));
  audit(actor, "recovery.kit");
  return KIT_PREFIX + Buffer.from(JSON.stringify(kit)).toString("base64url");
}

/** Changes when a store or its key changes, so an outdated kit can be pointed out. */
const kitFingerprint = (dests: Pick<KitDest, "endpoint" | "bucket" | "prefix" | "accessKeyId">[]) =>
  dests.map((d) => [d.endpoint, d.bucket, d.prefix, d.accessKeyId].join("|")).join(";");

/** Whether the kit saved off the server still matches the stores (for the security audit). */
export async function kitState(): Promise<"none" | "outdated" | "ok"> {
  if (!settings.get("recovery.exportedAt")) return "none";
  const now: Pick<KitDest, "endpoint" | "bucket" | "prefix" | "accessKeyId">[] = [];
  for (const d of destIds()) {
    const c = await creds(d).catch(() => null);
    if (c) now.push({ endpoint: c.url, bucket: c.bucket, prefix: c.prefix, accessKeyId: c.accessKeyId });
  }
  return kitFingerprint(now) === settings.get("recovery.exportedDests") ? "ok" : "outdated";
}

export function parseKit(text: string): Kit {
  const t = text.trim();
  if (!t.startsWith(KIT_PREFIX)) throw new Error(`not a recovery kit (it starts with ${KIT_PREFIX})`);
  const kit = JSON.parse(Buffer.from(t.slice(KIT_PREFIX.length), "base64url").toString()) as Kit;
  if (Buffer.from(kit.key ?? "", "base64").length !== 32 || !kit.host || !kit.dests?.length) throw new Error("recovery kit is damaged");
  for (const d of kit.dests) if (!d.endpoint || !d.bucket || !d.accessKeyId || !d.secret) throw new Error("recovery kit is damaged");
  return kit;
}

const kitClient = (d: KitDest) =>
  new S3Client({ accessKeyId: d.accessKeyId, secretAccessKey: d.secret, bucket: d.bucket, endpoint: d.endpoint, region: regionFor(d.endpoint) });

async function listKeys(s3: S3Client, prefix: string): Promise<string[]> {
  const out: string[] = [];
  let startAfter: string | undefined;
  for (;;) {
    const r = await s3.list({ prefix, maxKeys: 1000, ...(startAfter ? { startAfter } : {}) });
    const keys = (r.contents ?? []).map((c) => c.key);
    out.push(...keys);
    if (!r.isTruncated || !keys.length) return out;
    startAfter = keys.at(-1);
  }
}

const STAMP = /\/(\d{8}-\d{6})\.[a-z]+\.gz\.enc$/;

/** The newest panel backup in the kit's stores. */
export async function findPanelBackup(kit: Kit, host = kit.host): Promise<{ dest: KitDest; key: string } | null> {
  let best: { dest: KitDest; key: string; stamp: string } | null = null;
  for (const dest of kit.dests) {
    const keys = await listKeys(kitClient(dest), `${dest.prefix}/${host}/panel/`).catch(() => []);
    for (const key of keys) {
      const stamp = key.match(STAMP)?.[1];
      if (stamp && (!best || stamp > best.stamp)) best = { dest, key, stamp };
    }
  }
  return best && { dest: best.dest, key: best.key };
}

const say = (s: string) => console.log(s);

/**
 * CLI, as root, on the new server after `pano install`: puts the newest panel
 * backup in place and starts the panel on it. Files that were there are kept in
 * /var/lib/pano/before-recover-<time>.
 */
export async function restorePanel(kit: Kit, host?: string) {
  const found = await findPanelBackup(kit, host);
  if (!found) throw new Error(`no panel backup of ${host ?? kit.host} in the stores of this kit`);
  say(`panel backup: ${found.key}`);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*/, "").replace("T", "-");
  const stage = `${paths.data}/recover-${stamp}`;
  const keep = `${paths.data}/before-recover-${stamp}`;
  await ensureDir(stage, 0o700);
  await ensureDir(keep, 0o700);
  const plain = kitClient(found.dest)
    .file(found.key)
    .stream()
    .pipeThrough(decryptStream(Buffer.from(kit.key, "base64")))
    .pipeThrough(new DecompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>);
  const tar = Bun.spawn(["tar", "-xf", "-", "-C", fsPath(stage)], { stdin: plain, stdout: "ignore", stderr: "pipe" });
  if ((await tar.exited) !== 0) throw new Error(`unpacking failed: ${(await new Response(tar.stderr).text()).trim()}`);

  await run(["systemctl", "stop", "pano-web", "pano-agent"], { check: false });
  await run(["cp", "-a", fsPath(paths.etc), fsPath(`${keep}/etc-pano`)], { check: false });
  await run(["cp", "-a", `${fsPath(stage)}${paths.etc}/.`, fsPath(paths.etc)]);
  await localPanelAddress();
  if (await exists(`${stage}${paths.edgeData}`)) await run(["cp", "-a", `${fsPath(stage)}${paths.edgeData}/.`, fsPath(paths.edgeData)]);
  for (const f of ["", "-wal", "-shm"]) {
    if (await exists(paths.stateDb + f)) await run(["mv", fsPath(paths.stateDb + f), fsPath(`${keep}/state.db${f}`)]);
    if (await exists(paths.webDb + f)) await run(["mv", fsPath(paths.webDb + f), fsPath(`${keep}/web.db${f}`)]);
  }
  await run(["install", "-m", "0640", "-o", "root", "-g", "root", fsPath(`${stage}/state.db`), fsPath(paths.stateDb)]);
  if (await exists(`${stage}/web.db`)) await run(["install", "-m", "0600", "-o", "pano", "-g", "pano", fsPath(`${stage}/web.db`), fsPath(paths.webDb)]);
  // The kit is the authority for the key the backups were made with.
  await writeAtomic(`${paths.secrets}/backup.key`, `${kit.key}\n`, 0o600);
  await remove(stage);
  await run(["systemctl", "start", "pano-agent", "pano-web"]);
  say(`panel restored; what was here before is in ${keep}`);
}

/** The old server's panel address is not on this one: the panel listens on localhost until it is set again. */
async function localPanelAddress() {
  const file = `${paths.etc}/pano.env`;
  const conf = (await readText(file)) ?? "";
  const host = conf.match(/^PANO_WEB_HOST=(\S+)/m)?.[1];
  if (!host || ["127.0.0.1", "0.0.0.0", "::1", "localhost"].includes(host)) return;
  const addrs = (await run(["ip", "-o", "addr"], { check: false })).stdout;
  if (addrs.includes(` ${host}/`)) return;
  await writeAtomic(file, conf.replace(/^PANO_WEB_HOST=.*$/m, "PANO_WEB_HOST=127.0.0.1"), 0o600);
  say(`the panel listened on ${host} on the old server; here it listens on 127.0.0.1 (PANO_WEB_HOST in ${file})`);
}

// ---- rebuild (agent) --------------------------------------------------------------

type Status = { running: boolean; startedAt: number; finishedAt: number; failed: number; lines: string[] };
let status: Status = { running: false, startedAt: 0, finishedAt: 0, failed: 0, lines: [] };
const LOG = `${paths.data}/recover.log`;

export const recoveryStatus = (): Status => status;

function log(line: string) {
  status.lines.push(line);
  void Bun.write(fsPath(LOG), status.lines.join("\n") + "\n").catch(() => {});
}

async function step(name: string, fn: () => Promise<unknown>) {
  log(`… ${name}`);
  try {
    await fn();
    log(`ok ${name}`);
  } catch (e) {
    status.failed++;
    log(`FAILED ${name}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

export function startRebuild(actor: string) {
  if (status.running) throw new Error("recovery is already running");
  status = { running: true, startedAt: Math.floor(Date.now() / 1000), finishedAt: 0, failed: 0, lines: [] };
  void rebuild(actor)
    .catch((e) => {
      status.failed++;
      log(`FAILED: ${e instanceof Error ? e.message : String(e)}`);
    })
    .finally(() => {
      status.running = false;
      status.finishedAt = Math.floor(Date.now() / 1000);
      void notify(status.failed ? `🟠 recovery finished with ${status.failed} failed steps` : "🟢 recovery finished; apps are deploying");
    });
  audit(actor, "recovery.rebuild");
}

/** Newest backup of a job, read from the stores themselves (the restored state can be older than them). */
async function latestBackup(job: BackupJob): Promise<{ d: DestId; key: string; engine: "archive" | "restic"; at: string } | null> {
  let best: { d: DestId; key: string; engine: "archive" | "restic"; at: string } | null = null;
  const usesRestic = backups.runs(job.id, 200).some((r) => r.engine === "restic");
  for (const d of destIds()) {
    const { s3, prefix } = await client(d);
    for (const key of await listKeys(s3, `${prefix}/${backupHost()}/${job.name}/`).catch(() => [])) {
      const m = key.match(STAMP)?.[1];
      // 20261027-031500 → 2026-10-27T03:15:00 (sortable like restic's times)
      const at = m ? `${m.slice(0, 4)}-${m.slice(4, 6)}-${m.slice(6, 8)}T${m.slice(9, 11)}:${m.slice(11, 13)}:${m.slice(13, 15)}` : "";
      if (at && (!best || at > best.at)) best = { d, key, engine: "archive", at };
    }
    if (!usesRestic) continue;
    await ensureRestic();
    const r = await restic(await resticEnv(d), ["snapshots", "--json", "--latest", "1", "--tag", `job-${job.id}`, "--host", backupHost()]);
    const snap = r.code === 0 ? (JSON.parse(r.stdout || "[]") as { id: string; time: string }[]).at(-1) : undefined;
    const at = snap?.time.slice(0, 19) ?? "";
    if (snap && (!best || at > best.at)) best = { d, key: snap.id, engine: "restic", at };
  }
  return best;
}

/** Unpacks a file backup (app or path job) into an empty directory. */
async function unpack(job: BackupJob, b: { d: DestId; key: string; engine: "archive" | "restic" }, dir: string) {
  if (b.engine === "restic") {
    const r = await restic(await resticEnv(b.d), ["restore", b.key, "--target", fsPath(dir)]);
    if (r.code !== 0) throw new Error(`restic restore: ${r.stderr.trim().split("\n").at(-1)}`);
    return;
  }
  const { s3 } = await client(b.d);
  const plain = s3
    .file(b.key)
    .stream()
    .pipeThrough(decryptStream(await backupKey()))
    .pipeThrough(new DecompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>);
  const tar = Bun.spawn(["tar", "-xf", "-", "--no-same-owner", "-C", fsPath(dir)], { stdin: plain, stdout: "ignore", stderr: "pipe" });
  if ((await tar.exited) !== 0) throw new Error(`tar: ${(await new Response(tar.stderr).text()).trim().split("\n").at(-1)}`);
  void job;
}

/** A database dump straight into the database. */
async function loadDump(job: BackupJob, b: { d: DestId; key: string; engine: "archive" | "restic" }, cmd: string[]) {
  const source =
    b.engine === "restic"
      ? Bun.spawn(["restic", "dump", b.key, `/${job.target}.sql`], { env: await resticEnv(b.d), stdout: "pipe", stderr: "pipe" }).stdout
      : (await client(b.d)).s3
          .file(b.key)
          .stream()
          .pipeThrough(decryptStream(await backupKey()))
          .pipeThrough(new DecompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>);
  const load = Bun.spawn(cmd, { stdin: source, stdout: "ignore", stderr: "pipe" });
  if ((await load.exited) !== 0) throw new Error(`load failed: ${(await new Response(load.stderr).text()).trim().split("\n").slice(-2).join(" ")}`);
}

async function restoreJob(job: BackupJob) {
  const b = await latestBackup(job);
  if (!b) return log(`  no backup of ${job.name} in the stores`);
  log(`  ${job.name}: ${b.engine} from ${b.at} (destination ${b.d})`);
  if (job.kind === "mysql") {
    await sql(`CREATE DATABASE IF NOT EXISTS ${ident(v.dbName(job.target))} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
    return loadDump(job, b, restoreCommand(job.target));
  }
  if (job.kind === "postgres") {
    await pgEnsureDb(pgName(job.target));
    return loadDump(job, b, pgRestoreCommand(job.target));
  }
  const tmp = `${paths.data}/tmp/recover-${job.id}-${Date.now()}`;
  await ensureDir(tmp, 0o700);
  try {
    await unpack(job, b, tmp);
    // restic keeps absolute paths; archives are relative to what was backed up.
    if (job.kind === "app") {
      const home = appHome(job.target);
      const base = b.engine === "restic" ? `${tmp}${fsPath(home)}` : tmp;
      for (const d of ["shared", "data", ".ssh"]) {
        if (await exists(`${base}/${d}`)) await run(["cp", "-a", "--no-preserve=ownership", fsPath(`${base}/${d}`) + "/.", fsPath(`${home}/${d}`)]);
      }
      const user = appUser(job.target);
      await run(["chown", "-R", `${user}:${user}`, fsPath(`${home}/data`), fsPath(`${home}/.ssh`)]);
      await run(["chown", "-R", `root:${user}`, fsPath(`${home}/shared`)]);
      await run(["chmod", "0640", fsPath(`${home}/shared/.env`)], { check: false });
      await run(["chmod", "-R", "go-rwx", fsPath(`${home}/.ssh`)], { check: false });
    } else {
      const base = b.engine === "restic" ? `${tmp}${fsPath(job.target)}` : tmp;
      await ensureDir(job.target, 0o750);
      await run(["cp", "-a", fsPath(base) + "/.", fsPath(job.target)]);
    }
  } finally {
    await remove(tmp);
  }
}

/** The database user an app connects as, with the password already in its env. */
export async function ensureDbUser(url: string) {
  const u = new URL(url);
  if (!["127.0.0.1", "localhost"].includes(u.hostname)) return;
  const user = decodeURIComponent(u.username);
  const pass = decodeURIComponent(u.password);
  const db = u.pathname.slice(1);
  if (!user || !pass || !db) return;
  if (u.protocol === "mysql:" || u.protocol === "mariadb:") {
    const [name, who] = [v.dbName(db), v.dbUser(user)];
    await sql(
      [
        `CREATE DATABASE IF NOT EXISTS ${ident(name)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`,
        `CREATE USER IF NOT EXISTS ${lit(who)}@'localhost' IDENTIFIED BY ${lit(pass)};`,
        `ALTER USER ${lit(who)}@'localhost' IDENTIFIED BY ${lit(pass)};`,
        `GRANT ALL PRIVILEGES ON ${ident(name)}.* TO ${lit(who)}@'localhost';`,
        "FLUSH PRIVILEGES;",
      ].join("\n"),
    );
  } else if (u.protocol === "postgres:" || u.protocol === "postgresql:") {
    await pgEnsure(pgName(db), pgName(user), pass);
  }
}

const redact = (url: string) => url.replace(/\/\/([^:/@]+):[^@]*@/, "//$1:•••@");

async function rebuild(actor: string) {
  log(`recovery of ${backupHost()} started`);
  await step("edge (Caddy)", async () => {
    if (!(await edgeInstalled())) await installCaddy();
    await setupEdgeUnit();
    // Restored files carry the old server's group ids; the edge has to read its config and certificates.
    await run(["chgrp", "-R", EDGE_USER, fsPath(paths.caddyfile), fsPath(paths.certs)], { check: false });
  });
  for (const k of recordedServices()) await step(`service ${k}`, () => reinstall(k, actor));

  const managed = apps.list().filter((a) => a.kind === "managed");
  const runtimes = new Map(managed.map((a) => [`${a.runtime}@${a.runtime_version}`, a] as const));
  for (const a of runtimes.values()) {
    if (!(await exists(runtimeBin(a.runtime, a.runtime_version)))) await step(`${a.runtime} ${a.runtime_version}`, () => installRuntime(a.runtime, a.runtime_version));
  }

  const jobs = backups.jobs();
  const urls: string[] = [];
  for (const app of managed) {
    await step(`app ${app.name}: env, data, deploy key`, async () => {
      await ensureAppHome(app.name);
      const job = jobs.find((j) => j.kind === "app" && j.target === app.name);
      if (job) await restoreJob(job);
      else log(`  ${app.name} has no backup job: only its settings come back`);
      const env = await getEnv(app.name);
      for (const k of ["DATABASE_URL", "REDIS_URL"]) if (env[k]) urls.push(env[k]);
    });
  }
  // A server where MariaDB was there before pano has no record of it: what the data needs decides.
  const needed = new Map<ServiceKey, string | undefined>();
  for (const job of jobs) if (job.kind === "mysql" || job.kind === "postgres") needed.set(job.kind === "mysql" ? "mariadb" : "postgres", undefined);
  for (const url of urls) {
    const u = new URL(url);
    if (!["127.0.0.1", "localhost"].includes(u.hostname)) continue;
    if (/^redis/.test(u.protocol)) needed.set("valkey", decodeURIComponent(u.password) || undefined);
    else needed.set(/^postgres/.test(u.protocol) ? "postgres" : "mariadb", undefined);
  }
  for (const [k, password] of needed) await step(`service ${k} for the restored data`, () => ensureService(k, actor, password));
  for (const url of urls) if (!url.startsWith("redis")) await step(`database user ${redact(url)}`, () => ensureDbUser(url));
  for (const job of jobs.filter((j) => j.kind === "mysql" || j.kind === "postgres")) await step(`database ${job.target}`, () => restoreJob(job));

  const phpSites = sites.list().filter((s) => s.kind === "php");
  for (const site of phpSites) await step(`site ${site.name}: PHP ${site.php_version}`, () => reprovisionSite(site, actor));
  for (const job of jobs.filter((j) => j.kind === "path")) await step(`files ${job.target}`, () => restoreJob(job));
  for (const site of phpSites) await step(`site ${site.name}: start`, () => startRestoredSite(site));

  if (settings.get("realtime.version")) await step("realtime", () => realtime.reinstall(actor));
  if (settings.get("turn.installed") === "1") {
    await step("TURN", async () => {
      const envs = await Promise.all(managed.map((a) => getEnv(a.name).catch(() => ({}) as Record<string, string>)));
      await turn.reinstall(envs.find((e) => e.TURN_SECRET)?.TURN_SECRET ?? "", actor);
    });
  }

  for (const app of managed) {
    await step(`app ${app.name}: deploy from ${app.branch}`, async () => {
      await writeUnits(app);
      startDeploy(app.name, "recovery", actor);
    });
  }
  await step("edge configuration", async () => {
    await applyEdge();
    // The old server served 80/443 through the edge; a new one has nothing else there.
    if (settings.get("edge.cutover") === "1") await run(["systemctl", "enable", "--now", "pano-edge"]);
  });
  if (sites.list().some((s) => s.kind === "legacy")) log("Sites that were still on OpenLiteSpeed are not moved; bring them over as PHP sites.");
  if (settings.get("vpn.enabled") === "1") log("Private access (WireGuard) was on: turn it on again on its page; locks are not applied automatically.");
  log(status.failed ? `done with ${status.failed} failed steps (see above)` : "done; app deploys are running (Apps page)");
}

/** Jobs every server has: the panel itself, and the files of each PHP site. */
export function ensureDefaultJobs() {
  ensureJob("panel", "panel", "system");
  for (const s of sites.list()) if (s.kind === "php") ensureJob("path", s.root, "system");
}
