// Encrypted backups to Cloudflare R2 or any S3-compatible store (Backblaze B2,
// Hetzner Object Storage, Wasabi, AWS S3, MinIO).
// source (mysqldump | tar) -> gzip -> AES-256-GCM -> multipart upload, all
// streamed: nothing is staged on disk and memory stays around one chunk.

import { S3Client } from "bun";
import { randomBytes } from "node:crypto";
import { hostname } from "node:os";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import { v } from "../shared/validate.ts";
import { notify } from "./alerts.ts";
import { appHome } from "./apps.ts";
import { pgDumpCommand, pgName, pgRestoreCommand } from "./services.ts";
import { decryptStream, encryptStream } from "./crypto-stream.ts";
import { dumpCommand, restoreCommand } from "./mysql.ts";
import { apps, audit, backups, settings, type BackupJob } from "./state.ts";
import { ensureDir, exists, readText, writeAtomic } from "./sys.ts";

const KEY_FILE = `${paths.secrets}/backup.key`;
const R2_SECRET_FILE = `${paths.secrets}/r2.secret`;
const PATH_ROOTS = ["/home", "/srv", "/var/www", "/opt", "/etc/pano"];

export type R2Settings = { accountId: string; bucket: string; prefix: string; accessKeyId: string; hasSecret: boolean; endpoint: string };

export async function getR2(): Promise<R2Settings> {
  return {
    accountId: settings.get("r2.accountId") ?? "",
    bucket: settings.get("r2.bucket") ?? "",
    prefix: settings.get("r2.prefix") ?? "pano",
    accessKeyId: settings.get("r2.accessKeyId") ?? "",
    endpoint: settings.get("r2.endpoint") ?? "",
    hasSecret: await exists(R2_SECRET_FILE),
  };
}

export async function setR2(input: Record<string, unknown>, actor: string) {
  const accountId = String(input.accountId ?? "").trim();
  if (accountId && !/^[a-f0-9]{32}$/.test(accountId)) throw new Error("account id is the 32-character hex id from the R2 dashboard");
  const endpoint = String(input.endpoint ?? "").trim();
  if (endpoint && !/^https:\/\/[A-Za-z0-9.-]+(:\d+)?\/?$/.test(endpoint)) throw new Error("endpoint must be an https URL");
  const accessKeyId = String(input.accessKeyId ?? "").trim();
  if (!/^[A-Za-z0-9]{16,128}$/.test(accessKeyId)) throw new Error("invalid access key id");
  const prefix = String(input.prefix ?? "pano").trim().replace(/^\/+|\/+$/g, "");
  if (!/^[A-Za-z0-9._\/-]{0,100}$/.test(prefix)) throw new Error("invalid prefix");
  settings.set("r2.accountId", accountId);
  settings.set("r2.endpoint", endpoint);
  settings.set("r2.bucket", v.bucket(input.bucket));
  settings.set("r2.prefix", prefix);
  settings.set("r2.accessKeyId", accessKeyId);
  // The secret is write-only: stored root-only, never sent back to the UI.
  const secret = String(input.secretAccessKey ?? "").trim();
  if (secret) {
    if (!/^[A-Za-z0-9+\/=]{16,128}$/.test(secret)) throw new Error("invalid secret access key");
    await ensureDir(paths.secrets, 0o700);
    await writeAtomic(R2_SECRET_FILE, secret, 0o600);
  }
  audit(actor, "backup.r2", { bucket: input.bucket, accessKeyId });
}

async function client(): Promise<{ s3: S3Client; prefix: string }> {
  const cfg = await getR2();
  const secret = (await readText(R2_SECRET_FILE))?.trim();
  if (!cfg.bucket || !cfg.accessKeyId || !secret || (!cfg.accountId && !cfg.endpoint)) throw new Error("R2 is not configured");
  const s3 = new S3Client({
    accessKeyId: cfg.accessKeyId,
    secretAccessKey: secret,
    bucket: cfg.bucket,
    endpoint: cfg.endpoint || `https://${cfg.accountId}.r2.cloudflarestorage.com`,
    region: regionFor(cfg.endpoint),
  });
  return { s3, prefix: cfg.prefix };
}

/** Requests are signed for a region; outside R2 it has to match the one in the endpoint. */
export function regionFor(endpoint: string): string {
  const host = endpoint.replace(/^https:\/\//, "").replace(/[:/].*$/, "");
  if (!host || host.endsWith(".r2.cloudflarestorage.com")) return "auto";
  const m =
    host.match(/^s3\.([a-z0-9-]+)\.backblazeb2\.com$/) ?? // Backblaze B2
    host.match(/^([a-z0-9-]+)\.your-objectstorage\.com$/) ?? // Hetzner
    host.match(/^s3\.([a-z0-9-]+)\.wasabisys\.com$/) ??
    host.match(/^s3[.-]([a-z0-9-]+)\.amazonaws\.com$/);
  return m?.[1] ?? "us-east-1";
}

export async function testR2(): Promise<string> {
  const { s3, prefix } = await client();
  const key = `${prefix}/.pano-test-${Date.now()}`;
  await s3.write(key, "ok");
  await s3.delete(key);
  return "R2 connection works (write + delete)";
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

function sourceCommand(job: BackupJob): { cmd: string[]; ext: string } {
  if (job.kind === "mysql") return { cmd: dumpCommand(job.target), ext: "sql" };
  if (job.kind === "postgres") return { cmd: pgDumpCommand(job.target), ext: "sql" };
  const excludes = ["--exclude=node_modules", "--exclude=.next/cache", "--exclude=./cache", "--exclude=.git"];
  if (job.kind === "app") {
    if (!apps.get(job.target)) throw new Error(`app ${job.target} no longer exists`);
    const home = fsPath(appHome(job.target));
    // slot-a/slot-b are symlinks to releases; --dereference stores their contents.
    return { cmd: ["tar", "-cf", "-", "--dereference", "--ignore-failed-read", ...excludes, "-C", home, "shared", "data", "slot-a", "slot-b"], ext: "tar" };
  }
  return { cmd: ["tar", "-cf", "-", "--exclude=node_modules", "--exclude=.git", "-C", fsPath(job.target), "."], ext: "tar" };
}

let queue: Promise<unknown> = Promise.resolve();

export function runJob(jobId: number, actor: string): number {
  const job = backups.job(jobId);
  if (!job) throw new Error("no such backup job");
  const runId = backups.startRun(jobId);
  audit(actor, "backup.run", { job: job.name, runId });
  queue = queue.then(() => execute(job, runId)).catch(() => {});
  return runId;
}

async function execute(job: BackupJob, runId: number) {
  try {
    const { s3, prefix } = await client();
    const key = await backupKey();
    const { cmd, ext } = sourceCommand(job);
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*/, "").replace("T", "-");
    const objectKey = `${prefix}/${hostname()}/${job.name}/${stamp}.${ext}.gz.enc`;
    if (DRY_RUN) {
      console.log(`[dry-run] backup ${cmd.join(" ")} -> r2://${objectKey}`);
      backups.finishRun(runId, job.id, { status: "success", object_key: objectKey, bytes: 0 });
      return;
    }
    const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe", env: { PATH: "/usr/bin:/bin", HOME: "/root" } });
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
    await prune(job, s3);
  } catch (e) {
    const msg = (e instanceof Error ? e.message : String(e)).slice(0, 500);
    backups.finishRun(runId, job.id, { status: "failed", error: msg });
    void notify(`🔴 backup ${job.name} failed: ${msg}`);
  }
}

async function prune(job: BackupJob, s3: S3Client) {
  const ok = backups.successfulRuns(job.id).filter((r) => r.object_key);
  for (const old of ok.slice(job.keep)) {
    await s3.delete(old.object_key).catch(() => {});
    backups.markDeleted(old.id);
  }
}

/** Restores a mysql backup into a database, or a file backup into a fresh directory. */
export async function restore(runId: number, target: unknown, actor: string): Promise<string> {
  const r = backups.run(runId);
  if (!r || r.status !== "success" || !r.object_key) throw new Error("backup not available");
  const job = backups.job(r.job_id);
  if (!job) throw new Error("job missing");
  const { s3 } = await client();
  const key = await backupKey();
  const plain = s3
    .file(r.object_key)
    .stream()
    .pipeThrough(decryptStream(key))
    .pipeThrough(new DecompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>);
  let cmd: string[];
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
    const dir = `${paths.data}/restore/${job.name}-${runId}-${Date.now()}`;
    await ensureDir(dir, 0o700);
    cmd = ["tar", "-xf", "-", "--no-same-owner", "-C", fsPath(dir)];
    where = dir;
  }
  if (DRY_RUN) return `[dry-run] would restore into ${where}`;
  const proc = Bun.spawn(cmd, { stdin: plain, stdout: "ignore", stderr: "pipe", env: { PATH: "/usr/bin:/bin", HOME: "/root" } });
  const code = await proc.exited;
  if (code !== 0) throw new Error(`restore failed: ${(await new Response(proc.stderr).text()).trim().split("\n").slice(-2).join(" ")}`);
  audit(actor, "backup.restore", { runId, where });
  return `restored into ${where}`;
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
 * Added even before R2 is set up; scheduled runs start once it is.
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
    if (!settings.get("r2.bucket")) return;
    for (const job of backups.jobs()) {
      if (!due(job, now) || backups.runs(job.id, 1)[0]?.status === "running") continue;
      try {
        runJob(job.id, "scheduler");
      } catch {}
    }
  }, 60_000);
}
