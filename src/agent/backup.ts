// Encrypted backups to Cloudflare R2 or any S3-compatible store (Backblaze B2,
// Hetzner Object Storage, Wasabi, AWS S3, MinIO), to one or two of them at once.
//
// Two engines, one key:
// - full archives (default, nothing to install): source (mysqldump | tar) ->
//   gzip -> AES-256-GCM -> multipart upload, all streamed: nothing is staged on
//   disk and memory stays around one chunk. Every run is a complete copy.
// - incremental (restic, installed from the distribution when chosen): only
//   changed data is uploaded, deduplicated and compressed across all runs and
//   jobs, so keeping many versions costs little more than one. The repository
//   password is derived from the same backup key, so that key alone restores
//   everything.
// Both run at low CPU and disk priority.

import { S3Client } from "bun";
import { createHmac, randomBytes } from "node:crypto";
import { realpath } from "node:fs/promises";
import { hostname } from "node:os";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import { v } from "../shared/validate.ts";
import { notify } from "./alerts.ts";
import { appHome } from "./apps.ts";
import { pgDumpCommand, pgName, pgRestoreCommand } from "./services.ts";
import { decryptStream, encryptStream } from "./crypto-stream.ts";
import { dumpCommand, restoreCommand } from "./mysql.ts";
import { apps, audit, backups, settings, type BackupJob, type BackupRun } from "./state.ts";
import { ensureDir, exists, readText, remove, run, writeAtomic } from "./sys.ts";

const KEY_FILE = `${paths.secrets}/backup.key`;
const PATH_ROOTS = ["/home", "/srv", "/var/www", "/opt", "/etc/pano"];
const RESTIC_CACHE = `${paths.data}/restic-cache`;
const LOW = ["nice", "-n", "10", "ionice", "-c2", "-n7"];
const ENV = { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", HOME: "/root" };

// ---- destinations ------------------------------------------------------------------

/** "a" is the main store, "b" an optional second one (another provider), filled by every run. */
export type DestId = "a" | "b";
export const DESTS: DestId[] = ["a", "b"];
const pfx = (d: DestId) => (d === "a" ? "r2" : "r2b");
const secretFile = (d: DestId) => `${paths.secrets}/${pfx(d)}.secret`;

export type R2Settings = { accountId: string; bucket: string; prefix: string; accessKeyId: string; hasSecret: boolean; endpoint: string };

export async function getDest(d: DestId): Promise<R2Settings> {
  const p = pfx(d);
  return {
    accountId: settings.get(`${p}.accountId`) ?? "",
    bucket: settings.get(`${p}.bucket`) ?? "",
    prefix: settings.get(`${p}.prefix`) ?? "pano",
    accessKeyId: settings.get(`${p}.accessKeyId`) ?? "",
    endpoint: settings.get(`${p}.endpoint`) ?? "",
    hasSecret: await exists(secretFile(d)),
  };
}

export const getR2 = () => getDest("a");

/** Destinations with a bucket set, in order. */
export const destIds = (): DestId[] => DESTS.filter((d) => !!settings.get(`${pfx(d)}.bucket`));

export function parseDest(x: unknown): DestId {
  if (x === undefined || x === "" || x === "a") return "a";
  if (x === "b") return "b";
  throw new Error("destination must be a or b");
}

export async function setDest(d: DestId, input: Record<string, unknown>, actor: string) {
  const accountId = String(input.accountId ?? "").trim();
  if (accountId && !/^[a-f0-9]{32}$/.test(accountId)) throw new Error("account id is the 32-character hex id from the R2 dashboard");
  const endpoint = String(input.endpoint ?? "").trim();
  // Plain http only to this machine (a local MinIO).
  if (endpoint && !/^(https:\/\/[A-Za-z0-9.-]+|http:\/\/127\.0\.0\.1)(:\d+)?\/?$/.test(endpoint)) throw new Error("endpoint must be an https URL");
  if (!accountId && !endpoint) throw new Error("R2 account id or an S3 endpoint is required");
  const accessKeyId = String(input.accessKeyId ?? "").trim();
  if (!/^[A-Za-z0-9]{16,128}$/.test(accessKeyId)) throw new Error("invalid access key id");
  const prefix = String(input.prefix ?? "pano").trim().replace(/^\/+|\/+$/g, "");
  if (!/^[A-Za-z0-9._\/-]{0,100}$/.test(prefix)) throw new Error("invalid prefix");
  const secret = String(input.secretAccessKey ?? "").trim();
  if (secret && !/^[A-Za-z0-9+\/=]{16,128}$/.test(secret)) throw new Error("invalid secret access key");
  if (!secret && !(await exists(secretFile(d)))) throw new Error("secret access key is required");
  const p = pfx(d);
  settings.set(`${p}.accountId`, accountId);
  settings.set(`${p}.endpoint`, endpoint);
  settings.set(`${p}.bucket`, v.bucket(input.bucket));
  settings.set(`${p}.prefix`, prefix);
  settings.set(`${p}.accessKeyId`, accessKeyId);
  // The secret is write-only: stored root-only, never sent back to the UI.
  if (secret) {
    await ensureDir(paths.secrets, 0o700);
    await writeAtomic(secretFile(d), secret, 0o600);
  }
  audit(actor, "backup.dest", { dest: d, bucket: input.bucket, accessKeyId });
}

/** Forgets the second destination (what is stored there stays there). */
export async function clearDest(d: DestId, actor: string) {
  if (d === "a") throw new Error("the main destination can only be changed, not removed");
  for (const k of ["accountId", "endpoint", "bucket", "prefix", "accessKeyId"]) settings.set(`${pfx(d)}.${k}`, "");
  await remove(secretFile(d));
  audit(actor, "backup.dest.clear", { dest: d });
}

async function creds(d: DestId) {
  const cfg = await getDest(d);
  const secret = (await readText(secretFile(d)))?.trim();
  if (!cfg.bucket || !cfg.accessKeyId || !secret || (!cfg.accountId && !cfg.endpoint)) throw new Error(`destination ${d} is not configured`);
  return { ...cfg, secret, url: (cfg.endpoint || `https://${cfg.accountId}.r2.cloudflarestorage.com`).replace(/\/$/, "") };
}

async function client(d: DestId): Promise<{ s3: S3Client; prefix: string }> {
  const c = await creds(d);
  const s3 = new S3Client({ accessKeyId: c.accessKeyId, secretAccessKey: c.secret, bucket: c.bucket, endpoint: c.url, region: regionFor(c.endpoint) });
  return { s3, prefix: c.prefix };
}

/** Requests are signed for a region; outside R2 it has to match the one in the endpoint. */
export function regionFor(endpoint: string): string {
  const host = endpoint.replace(/^https?:\/\//, "").replace(/[:/].*$/, "");
  if (!host || host.endsWith(".r2.cloudflarestorage.com")) return "auto";
  const m =
    host.match(/^s3\.([a-z0-9-]+)\.backblazeb2\.com$/) ?? // Backblaze B2
    host.match(/^([a-z0-9-]+)\.your-objectstorage\.com$/) ?? // Hetzner
    host.match(/^s3\.([a-z0-9-]+)\.wasabisys\.com$/) ??
    host.match(/^s3[.-]([a-z0-9-]+)\.amazonaws\.com$/);
  return m?.[1] ?? "us-east-1";
}

export async function testDest(d: DestId): Promise<string> {
  const { s3, prefix } = await client(d);
  const key = `${prefix}/.pano-test-${Date.now()}`;
  await s3.write(key, "ok");
  await s3.delete(key);
  return `destination ${d}: connection works (write + delete)`;
}

/** 32-byte key, created on first use. Losing it makes every backup unreadable. */
async function backupKey(): Promise<Buffer> {
  const existing = await readText(KEY_FILE);
  if (existing) return Buffer.from(existing.trim(), "base64");
  const key = randomBytes(32);
  await ensureDir(paths.secrets, 0o700);
  await writeAtomic(KEY_FILE, key.toString("base64") + "\n", 0o600);
  return key;
}

export async function exportKey(actor: string): Promise<string> {
  audit(actor, "backup.key.export");
  return (await backupKey()).toString("base64");
}

// ---- engine ----------------------------------------------------------------------------

export type Engine = "archive" | "restic";
export const engine = (): Engine => (settings.get("backup.engine") === "restic" ? "restic" : "archive");

export async function resticVersion(): Promise<string> {
  const r = await run(["restic", "version"], { check: false, quiet: false });
  return r.code === 0 ? (r.stdout.match(/restic (\d+\.\d+\.\d+)/)?.[1] ?? "") : "";
}

async function ensureRestic() {
  if (await resticVersion()) return;
  const deb = /^(ID|ID_LIKE)=.*\b(debian|ubuntu)\b/m.test((await readText("/etc/os-release")) ?? "");
  if (deb) await run(["apt-get", "install", "-y", "restic"], { timeoutMs: 600_000 });
  else {
    await run(["dnf", "-y", "install", "epel-release"], { check: false, timeoutMs: 600_000 });
    await run(["dnf", "-y", "install", "restic"], { timeoutMs: 600_000 });
  }
  const ver = await resticVersion();
  if (!ver) throw new Error("restic did not install");
  // Compression needs repository format 2 (restic 0.14+).
  const [maj, min] = ver.split(".").map(Number);
  if (maj === 0 && min! < 14) throw new Error(`restic ${ver} is too old (0.14 or newer needed)`);
}

export async function setEngine(e: unknown, actor: string) {
  if (e !== "archive" && e !== "restic") throw new Error("engine: archive or restic");
  if (e === "restic") await ensureRestic();
  settings.set("backup.engine", e);
  audit(actor, "backup.engine", { engine: e });
}

// ---- jobs ------------------------------------------------------------------

export function validateJob(x: Record<string, unknown>) {
  const kind = x.kind;
  if (kind !== "mysql" && kind !== "postgres" && kind !== "path" && kind !== "app") throw new Error("kind must be mysql, postgres, path or app");
  const target =
    kind === "mysql" ? v.dbName(x.target) : kind === "postgres" ? pgName(x.target) : kind === "app" ? v.appName(x.target) : v.pathUnder(x.target, PATH_ROOTS);
  const schedule = String(x.schedule ?? "manual");
  if (!/^(manual|hourly|daily [0-2]\d:[0-5]\d|weekly (Sun|Mon|Tue|Wed|Thu|Fri|Sat) [0-2]\d:[0-5]\d)$/.test(schedule)) {
    throw new Error("schedule: manual, hourly, 'daily HH:MM' or 'weekly Sun HH:MM'");
  }
  const name = String(x.name ?? "").trim() || `${kind}-${String(target).replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(name)) throw new Error("job name: letters, digits, . _ -");
  return { name, kind, target, schedule, keep: v.int(x.keep ?? 7, 1, 365, "keep") } as const;
}

const EXCLUDES = ["node_modules", ".git", ".next/cache"];

function dumpOf(job: BackupJob): string[] | null {
  if (job.kind === "mysql") return dumpCommand(job.target);
  if (job.kind === "postgres") return pgDumpCommand(job.target);
  return null;
}

function archiveCommand(job: BackupJob): { cmd: string[]; ext: string } {
  const dump = dumpOf(job);
  if (dump) return { cmd: dump, ext: "sql" };
  const excludes = [...EXCLUDES.map((e) => `--exclude=${e}`), "--exclude=./cache"];
  if (job.kind === "app") {
    if (!apps.get(job.target)) throw new Error(`app ${job.target} no longer exists`);
    const home = fsPath(appHome(job.target));
    // slot-a/slot-b are symlinks to releases; --dereference stores their contents.
    return { cmd: ["tar", "-cf", "-", "--dereference", "--ignore-failed-read", ...excludes, "-C", home, "shared", "data", "slot-a", "slot-b"], ext: "tar" };
  }
  return { cmd: ["tar", "-cf", "-", "--exclude=node_modules", "--exclude=.git", "-C", fsPath(job.target), "."], ext: "tar" };
}

/** Directories restic reads for a file job: an app's env, data and live release. */
async function resticPaths(job: BackupJob): Promise<string[]> {
  if (job.kind === "path") return [fsPath(job.target)];
  if (!apps.get(job.target)) throw new Error(`app ${job.target} no longer exists`);
  const home = fsPath(appHome(job.target));
  const out = [`${home}/shared`, `${home}/data`];
  const live = await realpath(`${home}/current`).catch(() => "");
  if (live) out.push(live);
  const have = await Promise.all(out.map((p) => exists(p)));
  return out.filter((_, i) => have[i]);
}

let queue: Promise<unknown> = Promise.resolve();
const enqueue = (fn: () => Promise<unknown>) => {
  queue = queue.then(fn).catch(() => {});
};

/** One run per destination, one after another. Returns the first run's id. */
export function runJob(jobId: number, actor: string): number {
  const job = backups.job(jobId);
  if (!job) throw new Error("no such backup job");
  const dests = destIds();
  if (!dests.length) throw new Error("no backup destination is configured");
  const eng = engine();
  const ids = dests.map((d) => {
    const runId = backups.startRun(jobId, d, eng);
    enqueue(() => (eng === "restic" ? executeRestic(job, runId, d) : executeArchive(job, runId, d)));
    return runId;
  });
  audit(actor, "backup.run", { job: job.name, runs: ids, engine: eng });
  return ids[0]!;
}

async function failed(job: BackupJob, runId: number, d: DestId, e: unknown) {
  const msg = (e instanceof Error ? e.message : String(e)).slice(0, 500);
  backups.finishRun(runId, job.id, { status: "failed", error: msg });
  void notify(`🔴 backup ${job.name} (destination ${d}) failed: ${msg}`);
}

async function executeArchive(job: BackupJob, runId: number, d: DestId) {
  try {
    const { s3, prefix } = await client(d);
    const key = await backupKey();
    const { cmd, ext } = archiveCommand(job);
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*/, "").replace("T", "-");
    const objectKey = `${prefix}/${hostname()}/${job.name}/${stamp}.${ext}.gz.enc`;
    if (DRY_RUN) {
      console.log(`[dry-run] backup ${cmd.join(" ")} -> ${d}://${objectKey}`);
      backups.finishRun(runId, job.id, { status: "success", object_key: objectKey, bytes: 0 });
      return;
    }
    const proc = Bun.spawn([...LOW, ...cmd], { stdout: "pipe", stderr: "pipe", env: ENV });
    const stream = proc.stdout.pipeThrough(new CompressionStream("gzip")).pipeThrough(encryptStream(key));
    const writer = s3.file(objectKey).writer({ partSize: 8 * 1024 * 1024, retry: 3, type: "application/octet-stream" });
    let bytes = 0;
    for await (const chunk of stream) {
      bytes += chunk.length;
      await writer.write(chunk);
    }
    const code = await proc.exited;
    const stderr = await new Response(proc.stderr).text();
    // tar exits 1 for "file changed as we read it", which is fine for live sites.
    if (code !== 0 && !((job.kind === "path" || job.kind === "app") && code === 1)) {
      await Promise.resolve(writer.end()).catch(() => {});
      await s3.delete(objectKey).catch(() => {});
      throw new Error(`${cmd[0]} exited ${code}: ${stderr.trim().split("\n").slice(-2).join(" ")}`);
    }
    await writer.end();
    backups.finishRun(runId, job.id, { status: "success", object_key: objectKey, bytes });
    for (const old of backups.successfulRuns(job.id, d, "archive").slice(job.keep)) {
      await s3.delete(old.object_key).catch(() => {});
      backups.markDeleted(old.id);
    }
  } catch (e) {
    await failed(job, runId, d, e);
  }
}

// ---- restic ---------------------------------------------------------------------------

async function resticEnv(d: DestId): Promise<Record<string, string>> {
  const c = await creds(d);
  const key = await backupKey();
  const path = [c.prefix, "restic", hostname()].filter(Boolean).join("/");
  return {
    ...ENV,
    RESTIC_REPOSITORY: `s3:${c.url}/${c.bucket}/${path}`,
    RESTIC_PASSWORD: resticPassword(key),
    AWS_ACCESS_KEY_ID: c.accessKeyId,
    AWS_SECRET_ACCESS_KEY: c.secret,
    AWS_DEFAULT_REGION: regionFor(c.endpoint),
    RESTIC_CACHE_DIR: fsPath(RESTIC_CACHE),
    GOMAXPROCS: "2",
  };
}

/** The restic repository password, derived from the backup key (so the key is all that must be kept). */
export const resticPassword = (key: Buffer) => createHmac("sha256", key).update("pano restic repository").digest("hex");

async function restic(env: Record<string, string>, args: string[], stdin?: ReadableStream<Uint8Array>) {
  const proc = Bun.spawn([...LOW, "restic", ...args], { env, stdin: stdin ?? "ignore", stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  return { code, stdout, stderr };
}

const resticError = (what: string, r: { code: number; stderr: string }) =>
  new Error(`restic ${what} exited ${r.code}: ${r.stderr.trim().split("\n").slice(-2).join(" ")}`);

async function ensureRepo(env: Record<string, string>) {
  if ((await restic(env, ["cat", "config"])).code === 0) return;
  const r = await restic(env, ["init"]);
  if (r.code !== 0) throw resticError("init", r);
}

/** The summary line of `restic backup --json`. */
export function parseSummary(stdout: string): { snapshot: string; added: number } | null {
  for (const line of stdout.trim().split("\n").reverse()) {
    try {
      const m = JSON.parse(line);
      if (m.message_type === "summary" && m.snapshot_id) return { snapshot: m.snapshot_id, added: m.data_added_packed ?? m.data_added ?? 0 };
    } catch {}
  }
  return null;
}

const tagArgs = (job: BackupJob) => ["--tag", `job-${job.id}`, "--host", hostname()];

async function executeRestic(job: BackupJob, runId: number, d: DestId) {
  try {
    await ensureRestic();
    const env = await resticEnv(d);
    await ensureDir(RESTIC_CACHE, 0o700);
    await ensureRepo(env);
    const dump = dumpOf(job);
    let r: { code: number; stdout: string; stderr: string };
    let dumpFailed = "";
    if (dump) {
      const src = Bun.spawn([...LOW, ...dump], { stdout: "pipe", stderr: "pipe", env: ENV });
      r = await restic(env, ["backup", "--json", "--stdin", "--stdin-filename", `${job.target}.sql`, ...tagArgs(job)], src.stdout);
      const code = await src.exited;
      if (code !== 0) dumpFailed = `${dump[0]} exited ${code}: ${(await new Response(src.stderr).text()).trim().split("\n").slice(-2).join(" ")}`;
    } else {
      const dirs = await resticPaths(job);
      if (!dirs.length) throw new Error("nothing to back up");
      r = await restic(env, ["backup", "--json", "--one-file-system", "--exclude-caches", ...EXCLUDES.flatMap((e) => ["--exclude", e]), ...tagArgs(job), ...dirs]);
    }
    // 3: some files could not be read (live sites); the snapshot exists.
    const sum = parseSummary(r.stdout);
    if ((r.code !== 0 && r.code !== 3) || !sum) throw resticError("backup", r);
    if (dumpFailed) {
      await restic(env, ["forget", sum.snapshot]);
      throw new Error(dumpFailed);
    }
    backups.finishRun(runId, job.id, { status: "success", object_key: sum.snapshot, bytes: sum.added });
    // Older snapshots leave the list now; their data is freed by the weekly prune.
    const f = await restic(env, ["forget", "--keep-last", String(job.keep), ...tagArgs(job)]);
    if (f.code === 0) for (const old of backups.successfulRuns(job.id, d, "restic").slice(job.keep)) backups.markDeleted(old.id);
  } catch (e) {
    await failed(job, runId, d, e);
  }
}

/** Frees space of forgotten snapshots. Weekly, through the same queue as backups. */
export function pruneRepos(actor: string) {
  for (const d of destIds()) {
    enqueue(async () => {
      const env = await resticEnv(d);
      if ((await restic(env, ["cat", "config"])).code !== 0) return;
      const r = await restic(env, ["prune", "--max-unused", "10%"]);
      if (r.code !== 0) void notify(`🔴 backup prune of destination ${d} failed: ${r.stderr.trim().split("\n").at(-1)}`);
      audit(actor, "backup.prune", { dest: d, code: r.code });
    });
  }
}

// ---- restore ----------------------------------------------------------------------------

/** Restores a database backup into a database, or a file backup into a fresh directory. */
export async function restore(runId: number, target: unknown, actor: string): Promise<string> {
  const r = backups.run(runId);
  if (!r || r.status !== "success" || !r.object_key) throw new Error("backup not available");
  const job = backups.job(r.job_id);
  if (!job) throw new Error("job missing");
  const d = parseDest(r.dest);
  let cmd: string[] | null = null;
  let where: string;
  if (job.kind === "mysql") {
    const db = v.dbName(target || job.target);
    cmd = restoreCommand(db);
    where = `database ${db}`;
  } else if (job.kind === "postgres") {
    const db = pgName(target || job.target);
    cmd = pgRestoreCommand(db);
    where = `PostgreSQL database ${db}`;
  } else {
    where = `${paths.data}/restore/${job.name}-${runId}-${Date.now()}`;
    await ensureDir(where, 0o700);
  }
  if (DRY_RUN) return `[dry-run] would restore into ${where}`;

  if (r.engine === "restic") await restoreRestic(r, job, d, cmd, where);
  else await restoreArchive(r, d, cmd ?? ["tar", "-xf", "-", "--no-same-owner", "-C", fsPath(where)]);
  audit(actor, "backup.restore", { runId, where });
  return `restored into ${where}`;
}

async function restoreArchive(r: BackupRun, d: DestId, cmd: string[]) {
  const { s3 } = await client(d);
  const key = await backupKey();
  const plain = s3
    .file(r.object_key)
    .stream()
    .pipeThrough(decryptStream(key))
    .pipeThrough(new DecompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>);
  const proc = Bun.spawn(cmd, { stdin: plain, stdout: "ignore", stderr: "pipe", env: ENV });
  const code = await proc.exited;
  if (code !== 0) throw new Error(`restore failed: ${(await new Response(proc.stderr).text()).trim().split("\n").slice(-2).join(" ")}`);
}

async function restoreRestic(r: BackupRun, job: BackupJob, d: DestId, cmd: string[] | null, where: string) {
  await ensureRestic();
  const env = await resticEnv(d);
  if (!cmd) {
    const res = await restic(env, ["restore", r.object_key, "--target", fsPath(where)]);
    if (res.code !== 0) throw resticError("restore", res);
    return;
  }
  const dump = Bun.spawn(["restic", "dump", r.object_key, `/${job.target}.sql`], { env, stdout: "pipe", stderr: "pipe" });
  const load = Bun.spawn(cmd, { stdin: dump.stdout, stdout: "ignore", stderr: "pipe", env: ENV });
  const [dc, lc] = await Promise.all([dump.exited, load.exited]);
  if (dc !== 0) throw new Error(`restic dump failed: ${(await new Response(dump.stderr).text()).trim().split("\n").at(-1)}`);
  if (lc !== 0) throw new Error(`restore failed: ${(await new Response(load.stderr).text()).trim().split("\n").slice(-2).join(" ")}`);
}

// ---- scheduler -------------------------------------------------------------

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

export function due(job: BackupJob, now: Date): boolean {
  if (!job.enabled || job.schedule === "manual") return false;
  const last = job.last_run_at ? job.last_run_at * 1000 : 0;
  if (job.schedule === "hourly") return now.getTime() - last >= 3600_000 - 30_000;
  const parts = job.schedule.split(" ");
  const [hh, mm] = parts.at(-1)!.split(":").map(Number);
  // The latest planned time that is not in the future.
  const slot = new Date(now);
  slot.setHours(hh!, mm!, 0, 0);
  if (parts[0] === "weekly") slot.setDate(slot.getDate() - ((now.getDay() - DAYS.indexOf(parts[1]!) + 7) % 7));
  if (slot > now) slot.setDate(slot.getDate() - (parts[0] === "weekly" ? 7 : 1));
  return last < slot.getTime();
}

/**
 * Daily encrypted backup for something pano just created (a database, an app).
 * Added even before a destination is set up; scheduled runs start once it is.
 */
export function ensureJob(kind: "mysql" | "postgres" | "app", target: string, actor: string) {
  if (backups.jobs().some((j) => j.kind === kind && j.target === target)) return;
  const job = validateJob({ kind, target, schedule: "daily 03:30", keep: 14 });
  backups.addJob(job);
  audit(actor, "backup.job.add", { ...job, automatic: true });
}

export function startScheduler() {
  setInterval(() => {
    const now = new Date();
    if (!destIds().length) return;
    for (const job of backups.jobs()) {
      if (!due(job, now) || backups.runs(job.id, 1)[0]?.status === "running") continue;
      try {
        runJob(job.id, "scheduler");
      } catch {}
    }
    // Sunday 05:00: free the space of snapshots that left the retention window.
    const week = `${now.getFullYear()}-${Math.floor(now.getTime() / 604_800_000)}`;
    if (now.getDay() === 0 && now.getHours() >= 5 && settings.get("backup.prunedWeek") !== week && engine() === "restic") {
      settings.set("backup.prunedWeek", week);
      pruneRepos("scheduler");
    }
  }, 60_000);
}
