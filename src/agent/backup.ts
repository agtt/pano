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
import { Database } from "bun:sqlite";
import { createHmac, randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { realpath } from "node:fs/promises";
import { isIP, isIPv4 } from "node:net";
import { hostname } from "node:os";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import { PROVIDERS, deriveEndpoint, explainFailure, inferProvider, isProvider, jurisdictionOf, storedEndpoint, type ProviderId, type S3Failure } from "../shared/backup-providers.ts";
import { v } from "../shared/validate.ts";
import { notify } from "./alerts.ts";
import { appHome } from "./apps.ts";
import { b2Authorize, b2CreateBucket, createBucket, checkBucket, StoreError, suggestBucketName, type B2Auth, type Io } from "./s3admin.ts";
import { pgDumpCommand, pgName, pgNames, pgRestoreCommand } from "./services.ts";
import { decryptToFile, encryptStream, objectOf, type BackupContext } from "./crypto-stream.ts";
import { dumpCommand, listDatabases, restoreCommand } from "./mysql.ts";
import { dropSnapshots, liveFiles, placeSnapshots, snapshotApp } from "./sqlite.ts";
import { apps, audit, backups, settings, sites, state, type BackupJob, type BackupRun } from "./state.ts";
import { ensureDir, exists, readText, remove, run, writeAtomic } from "./sys.ts";

const KEY_FILE = `${paths.secrets}/backup.key`;

/** The name backups are stored under; kept in the panel state, so a recovered server continues the same history. */
export function backupHost(): string {
  const h = settings.get("backup.host");
  if (h) return h;
  settings.set("backup.host", hostname());
  return hostname();
}
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

export type R2Settings = {
  accountId: string;
  bucket: string;
  prefix: string;
  accessKeyId: string;
  hasSecret: boolean;
  endpoint: string;
  protect: boolean;
  /** Stored, or inferred from the endpoint for destinations saved before providers existed. */
  provider: ProviderId;
  /** "eu" for an R2 bucket in the EU jurisdiction. */
  jurisdiction: "" | "eu";
};

/**
 * A protected store is never deleted from: old versions leave by the store's own
 * lifecycle rules or Object Lock, so its key can be one without delete permission
 * and someone who takes over this server cannot erase the backups. Runs to it
 * are always full archives (restic needs to delete its lock files).
 */
export const isProtected = (d: DestId) => settings.get(`${pfx(d)}.protect`) === "1";

export async function getDest(d: DestId): Promise<R2Settings> {
  const p = pfx(d);
  const endpoint = settings.get(`${p}.endpoint`) ?? "";
  const stored = settings.get(`${p}.provider`);
  return {
    accountId: settings.get(`${p}.accountId`) ?? "",
    bucket: settings.get(`${p}.bucket`) ?? "",
    prefix: settings.get(`${p}.prefix`) ?? "pano",
    accessKeyId: settings.get(`${p}.accessKeyId`) ?? "",
    endpoint,
    hasSecret: await exists(secretFile(d)),
    protect: isProtected(d),
    provider: isProvider(stored) ? stored : inferProvider(endpoint),
    jurisdiction: jurisdictionOf(endpoint),
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
  if (endpoint.startsWith("https://")) await assertPublicEndpoint(endpoint);
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
  settings.set(`${p}.protect`, input.protect === true || input.protect === "1" ? "1" : "0");
  settings.set(`${p}.provider`, isProvider(input.provider) ? input.provider : inferProvider(endpoint));
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
  for (const k of ["accountId", "endpoint", "bucket", "prefix", "accessKeyId", "protect", "provider"]) settings.set(`${pfx(d)}.${k}`, "");
  await remove(secretFile(d));
  audit(actor, "backup.dest.clear", { dest: d });
}

/** Loopback, private, link-local (cloud metadata), CGNAT, multicast and reserved addresses. */
export function internalIp(ip: string): boolean {
  const v4 = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  if (isIPv4(v4)) {
    const [a, b] = v4.split(".").map(Number) as [number, number];
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const x = ip.toLowerCase();
  return x === "::" || x === "::1" || /^f[cd]/.test(x) || /^fe[89ab]/.test(x) || x.startsWith("ff");
}

/**
 * No https to internal addresses (cloud metadata, the LAN): the agent signs requests as root.
 * The host is taken from the parsed URL (hex/short IPv4 forms and trailing dots normalised)
 * and every address it resolves to is checked.
 */
export async function assertPublicEndpoint(endpoint: string) {
  let host: string;
  try {
    host = new URL(endpoint).hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "");
  } catch {
    throw new Error("endpoint must be an https URL");
  }
  const addrs = isIP(host) ? [host] : (await lookup(host, { all: true }).catch(() => [])).map((a) => a.address);
  if (!addrs.length) throw new Error(`endpoint ${host} does not resolve`);
  if (addrs.some(internalIp)) throw new Error("endpoint must be a public host (not a local or private address)");
}

export async function creds(d: DestId) {
  const cfg = await getDest(d);
  const secret = (await readText(secretFile(d)))?.trim();
  if (!cfg.bucket || !cfg.accessKeyId || !secret || (!cfg.accountId && !cfg.endpoint)) throw new Error(`destination ${d} is not configured`);
  // Again at every use: the name may resolve elsewhere than when it was saved.
  if (cfg.endpoint.startsWith("https://")) await assertPublicEndpoint(cfg.endpoint);
  return { ...cfg, secret, url: (cfg.endpoint || `https://${cfg.accountId}.r2.cloudflarestorage.com`).replace(/\/$/, "") };
}

export async function client(d: DestId): Promise<{ s3: S3Client; prefix: string }> {
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
  const deleted = await s3.delete(key).then(() => true, () => false);
  if (!isProtected(d)) return `destination ${d}: connection works (write + delete)`;
  return deleted
    ? `destination ${d}: writes work, but this key can also delete. Protect the bucket with Object Lock/versioning, or use a key without delete permission.`
    : `destination ${d}: writes work and this key cannot delete: backups here cannot be erased from this server.`;
}

// ---- connect: from a key to a tested destination ---------------------------------------

export type ConnectStep = { name: string; ok: boolean; hint: string };
export type ConnectResult = {
  /** Every step passed and the destination was saved. */
  ok: boolean;
  provider: ProviderId;
  bucket: string;
  endpoint: string;
  region: string;
  prefix: string;
  /** pano made the bucket just now. */
  created: boolean;
  protect: boolean;
  /** Set when pano put a lifecycle rule on a bucket it created in a protected store. */
  lifecycle: { retentionDays: number } | null;
  /** Things to tell the person, in plain words. */
  notes: string[];
  steps: ConnectStep[];
};
export type ProbeConfig = { endpoint: string; region: string; bucket: string; prefix: string; accessKeyId: string; secret: string };
export type ConnectIo = Io & { probe?: (cfg: ProbeConfig, protect: boolean, provider: ProviderId) => Promise<ConnectStep[]> };

/** The SSRF guard for everything connect calls: https only to public addresses. */
const publicGuard = async (url: string) => {
  if (url.startsWith("https://")) await assertPublicEndpoint(url);
};

const failureOf = (e: unknown): S3Failure =>
  e instanceof StoreError
    ? e.failure
    : { code: (e as any)?.code, status: (e as any)?.status ?? (e as any)?.statusCode, message: e instanceof Error ? e.message : String(e) };

/** A message that is already meant for the person. */
class Hint extends Error {}

const withTimeout = <T>(p: Promise<T>, ms = 30_000): Promise<T> =>
  Promise.race([p, new Promise<never>((_, rej) => setTimeout(() => rej(new Error("timed out")), ms))]);

/** Write, read back and compare, list, delete: what a real backup run needs, with a small test file. */
export async function probeStore(cfg: ProbeConfig, protect: boolean, provider: ProviderId): Promise<ConnectStep[]> {
  const s3 = new S3Client({ accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secret, bucket: cfg.bucket, endpoint: cfg.endpoint, region: cfg.region });
  const key = [cfg.prefix, `.pano-test-${Date.now()}`].filter(Boolean).join("/");
  const payload = `pano ${randomBytes(8).toString("hex")}`;
  const steps: ConnectStep[] = [];
  const step = async (name: string, fn: () => Promise<string | void>, soft = false) => {
    try {
      steps.push({ name, ok: true, hint: (await withTimeout(fn())) ?? "" });
      return true;
    } catch (e) {
      steps.push({ name, ok: soft, hint: e instanceof Hint ? e.message : explainFailure(failureOf(e), { provider, bucket: cfg.bucket, what: name }) });
      return soft;
    }
  };
  if (!(await step("write", async () => void (await s3.write(key, payload))))) return steps;
  if (
    !(await step("read", async () => {
      if ((await s3.file(key).text()) !== payload) throw new Hint("The file read back is not what was written: this store returns changed data. Try another provider.");
    }))
  ) return steps;
  await step("list", async () => {
    const r = await s3.list({ prefix: key, maxKeys: 5 });
    if (!(r.contents ?? []).some((o) => o.key === key)) return "Listing works but did not show the test file yet. Backups still work; incremental (restic) mode needs listing.";
  });
  if (protect) {
    // Denied is the intended answer here.
    const deleted = await withTimeout(s3.delete(key)).then(() => true, () => false);
    steps.push({
      name: "delete",
      ok: true,
      hint: deleted
        ? "This key can also delete, so someone who takes over this server could erase these backups. For real protection use a key without delete permission, or turn on Object Lock/versioning at the provider."
        : "Delete is denied for this key, as intended: backups here cannot be erased from this server.",
    });
  } else {
    await step("delete", async () => void (await s3.delete(key)));
    const last = steps.at(-1)!;
    if (!last.ok) last.hint += " pano needs to delete old versions; or mark this store as protected (pano then never deletes there).";
  }
  return steps;
}

const KEY_ERRORS = /InvalidAccessKeyId|SignatureDoesNotMatch|RequestTimeTooSkewed|AuthorizationHeaderMalformed|PermanentRedirect|bad_auth_token/;
const B2_CAPS: Record<string, string> = { listFiles: "list files", readFiles: "read files", writeFiles: "write files", deleteFiles: "delete files" };

/**
 * Turns the keys a person has into a working destination: finds the endpoint, finds or creates
 * the bucket, runs a real write/read/list/delete test, and only then stores it (the secret
 * root-only, like setDest). Failures come back as steps with a plain hint, not as exceptions;
 * only malformed input throws. Nothing is saved unless every step passes.
 */
export async function connectDest(d: DestId, input: Record<string, unknown>, actor: string, io: ConnectIo = {}): Promise<ConnectResult> {
  if (!isProvider(input.provider)) throw new Error(`provider must be one of: ${Object.keys(PROVIDERS).join(", ")}`);
  const provider = input.provider;
  const spec = PROVIDERS[provider];
  const f = (input.fields && typeof input.fields === "object" ? input.fields : {}) as Record<string, unknown>;
  const protect = input.protect === true || input.protect === "1";
  const p = pfx(d);
  const label = (name: string) => spec.fields.find((x) => x.name === name)?.label ?? name;

  const accessKeyId = String(f.accessKeyId ?? "").replace(/\s+/g, "");
  if (!/^[A-Za-z0-9]{16,128}$/.test(accessKeyId)) throw new Error(`${label("accessKeyId")} looks wrong: letters and digits only, copied without spaces`);
  let secret = String(f.secretAccessKey ?? "").replace(/\s+/g, "");
  // Reconnecting with the same key needs no secret again.
  if (!secret && settings.get(`${p}.accessKeyId`) === accessKeyId) secret = ((await readText(secretFile(d))) ?? "").trim();
  if (!/^[A-Za-z0-9+\/=]{16,128}$/.test(secret)) throw new Error(`${label("secretAccessKey")} is missing or has characters it should not have`);
  let prefix = String(f.prefix ?? "").trim().replace(/^\/+|\/+$/g, "") || "pano";
  let bucket = String(f.bucket ?? "").trim();
  if (bucket) v.bucket(bucket);
  const retentionDays = Number(f.retentionDays || 60);
  if (!Number.isInteger(retentionDays) || retentionDays < 7 || retentionDays > 3650) throw new Error("keep backups for 7 to 3650 days");

  const io2: Io = { fetch: io.fetch, guard: io.guard ?? publicGuard };
  const r: ConnectResult = { ok: false, provider, bucket: "", endpoint: "", region: "", prefix, created: false, protect, lifecycle: null, notes: [], steps: [] };
  const fail = (name: string, hint: string) => {
    r.steps.push({ name, ok: false, hint });
    r.bucket = bucket;
    r.prefix = prefix;
    return r;
  };
  const explain = (fl: S3Failure, what: string) => explainFailure(fl, { provider, bucket, what });

  // 1. where the store is
  let endpoint: string;
  let b2: B2Auth | null = null;
  if (provider === "b2") {
    try {
      b2 = await b2Authorize(accessKeyId, secret, io2);
    } catch (e) {
      return fail("keys", explain(failureOf(e), "keys"));
    }
    const missing = Object.keys(B2_CAPS).filter((c) => (protect && c === "deleteFiles" ? false : b2!.capabilities.length > 0 && !b2!.capabilities.includes(c)));
    if (missing.length) {
      return fail("keys", `This key is not allowed to ${missing.map((c) => B2_CAPS[c]).join(", ")}. In Backblaze make the key Read and Write${protect ? "" : " (or mark this store protected if it must not be able to delete)"}.`);
    }
    r.steps.push({ name: "keys", ok: true, hint: "" });
    endpoint = b2.s3ApiUrl;
  } else {
    endpoint = deriveEndpoint(provider, f)!;
    try {
      await io2.guard!(endpoint);
    } catch (e) {
      return fail("endpoint", explain(failureOf(e), "endpoint"));
    }
  }
  const region = regionFor(endpoint);
  r.endpoint = endpoint;
  r.region = region;
  if (provider !== "b2") r.steps.push({ name: "endpoint", ok: true, hint: "" });

  // 2. the bucket: the key's own, the one named, the one already used here, or a new private one
  const bc = () => ({ endpoint, bucket, region, accessKeyId, secretAccessKey: secret });
  const existing = settings.get(`${p}.bucket`) && settings.get(`${p}.accessKeyId`) === accessKeyId && (settings.get(`${p}.endpoint`) || "") === storedEndpoint(provider, endpoint) ? settings.get(`${p}.bucket`)! : "";
  let auto = false;
  let known = false;
  if (b2?.buckets.length) {
    // A key limited to buckets works only there.
    const names = b2.buckets.flatMap((x) => (x.name ? [x.name] : []));
    if (bucket && !names.includes(bucket)) return fail("bucket", `This key only works for ${names.length > 1 ? "buckets" : "bucket"} ${names.join(", ")}. Use ${names.length > 1 ? "one of them" : "that bucket"}, or create a key for all buckets.`);
    bucket = bucket || names[0] || "";
    if (!bucket) return fail("bucket", "This key is limited to a bucket Backblaze could not name (it may have been deleted). Create a new key.");
    r.steps.push({ name: "bucket", ok: true, hint: `Using ${bucket}: the key is limited to it.` });
    known = true;
  } else if (!bucket) {
    bucket = existing || suggestBucketName(backupHost());
    auto = !existing;
  }
  if (b2?.namePrefix) {
    const np = b2.namePrefix.replace(/\/+$/, "");
    if (!prefix.startsWith(np)) {
      prefix = np;
      r.notes.push(`The key is limited to files starting with "${b2.namePrefix}", so backups go under "${np}".`);
    }
  }
  if (!/^[A-Za-z0-9._\/-]{0,100}$/.test(prefix)) throw new Error("invalid prefix");

  if (!known) {
    let state: "yes" | "no" | "unknown" = "no";
    let failure: S3Failure | undefined;
    if (!auto) {
      try {
        const h = await checkBucket(bc(), io2);
        state = h.exists;
        failure = h.failure;
      } catch (e) {
        return fail("bucket", explain(failureOf(e), "bucket"));
      }
    }
    if (state === "unknown" && failure && (KEY_ERRORS.test(`${failure.code} ${failure.message}`) || failure.status === 301 || failure.status === 401)) return fail("bucket", explain(failure, "bucket"));
    if (state === "yes" || state === "unknown") {
      // Unknown (403): a key limited to objects may not ask about the bucket; the test below tells.
      r.steps.push({ name: "bucket", ok: true, hint: "" });
    } else {
      for (let attempt = 0; ; attempt++) {
        try {
          if (b2) {
            const days = protect ? retentionDays : null;
            try {
              await b2CreateBucket(b2, bucket, { retentionDays: days }, io2);
            } catch (e) {
              const fl = failureOf(e);
              throw fl.code === "duplicate_bucket_name" ? new StoreError({ ...fl, code: "BucketAlreadyExists" }) : e;
            }
            if (days) r.lifecycle = { retentionDays: days };
          } else {
            await createBucket(bc(), io2, provider === "s3" || provider === "wasabi" ? region : undefined);
          }
          r.created = true;
          r.steps.push({ name: "bucket", ok: true, hint: `Created the private bucket ${bucket}.` });
          break;
        } catch (e) {
          const fl = failureOf(e);
          if (auto && attempt < 2 && /BucketAlreadyExists/.test(fl.code ?? "")) {
            bucket = suggestBucketName(backupHost());
            continue;
          }
          const plain = !(e instanceof StoreError) || /BucketAlreadyExists|InvalidBucketName/.test(fl.code ?? "") || KEY_ERRORS.test(`${fl.code} ${fl.message}`) || fl.status === 401;
          return fail(
            "bucket",
            plain
              ? explain(fl, "bucket")
              : auto
                ? `No bucket was given and this key cannot create one. Create a bucket in the ${spec.name} dashboard and type its name here, or use a key with admin rights.`
                : `Bucket "${bucket}" does not exist and this key cannot create it. Create bucket "${bucket}" in the ${spec.name} dashboard, or use a key with admin rights.`,
          );
        }
      }
    }
  }
  r.bucket = bucket;
  r.prefix = prefix;

  if (protect) {
    r.notes.push(
      r.lifecycle
        ? `pano will never delete anything in this store. Backblaze removes backups older than ${r.lifecycle.retentionDays} days by a lifecycle rule on the new bucket.`
        : "pano will never delete anything in this store. Old backups stay until you add a lifecycle rule (or Object Lock) at the provider; until then it keeps growing.",
    );
  }

  // 3. the test
  r.steps.push(...(await (io.probe ?? probeStore)({ endpoint, region, bucket, prefix, accessKeyId, secret }, protect, provider)));
  r.ok = r.steps.every((s) => s.ok);
  if (!r.ok) return r;

  // 4. keep it
  settings.set(`${p}.accountId`, provider === "r2" ? String(f.accountId).trim().toLowerCase() : "");
  settings.set(`${p}.endpoint`, storedEndpoint(provider, endpoint));
  settings.set(`${p}.bucket`, bucket);
  settings.set(`${p}.prefix`, prefix);
  settings.set(`${p}.accessKeyId`, accessKeyId);
  settings.set(`${p}.protect`, protect ? "1" : "0");
  settings.set(`${p}.provider`, provider);
  await ensureDir(paths.secrets, 0o700);
  await writeAtomic(secretFile(d), secret, 0o600);
  audit(actor, "backup.dest.connect", { dest: d, provider, bucket, endpoint, accessKeyId, created: r.created, protect });
  return r;
}

// ---- overview ----------------------------------------------------------------------------

/** What an overview banner needs: are backups set up, protected, running, and is the key kept somewhere else. */
export function health() {
  const dests = destIds();
  const jobs = backups.jobs();
  let lastSuccessAt: number | null = null;
  let lastFailure: { job: string; at: number; error: string } | null = null;
  const neverRan: string[] = [];
  for (const j of jobs) {
    const runs = backups.runs(j.id, 20);
    if (!runs.length) {
      neverRan.push(j.name);
      continue;
    }
    for (const d of dests) {
      const done = runs.filter((x) => x.dest === d && x.status !== "running");
      const ok = done.find((x) => x.status === "success");
      if (ok && (ok.finished_at ?? ok.started_at) > (lastSuccessAt ?? 0)) lastSuccessAt = ok.finished_at ?? ok.started_at;
      // Only a failure that is still the latest word for this job and destination.
      const latest = done[0];
      const at = latest?.finished_at ?? latest?.started_at ?? 0;
      if (latest?.status === "failed" && at > (lastFailure?.at ?? 0)) lastFailure = { job: j.name, at, error: latest.error };
    }
  }
  const exportedAt = Number(settings.get("backup.keyExportedAt") || settings.get("recovery.exportedAt") || 0) || null;
  return {
    configured: dests.length,
    protected: dests.some(isProtected),
    allProtected: dests.length > 0 && dests.every(isProtected),
    jobs: jobs.length,
    lastSuccessAt,
    lastFailure,
    neverRan,
    keyExported: exportedAt !== null,
    keyExportedAt: exportedAt,
  };
}

/** 32-byte key, created on first use. Losing it makes every backup unreadable. */
export async function backupKey(): Promise<Buffer> {
  const existing = await readText(KEY_FILE);
  if (existing) {
    const key = Buffer.from(existing.trim(), "base64");
    if (key.length !== 32) throw new Error(`${KEY_FILE} is not a 32-byte base64 key`);
    return key;
  }
  const key = randomBytes(32);
  await ensureDir(paths.secrets, 0o700);
  await writeAtomic(KEY_FILE, key.toString("base64") + "\n", 0o600);
  return key;
}

export async function exportKey(actor: string): Promise<string> {
  audit(actor, "backup.key.export");
  settings.set("backup.keyExportedAt", String(Math.floor(Date.now() / 1000)));
  return (await backupKey()).toString("base64");
}

// ---- engine ----------------------------------------------------------------------------

export type Engine = "archive" | "restic";
export const engine = (): Engine => (settings.get("backup.engine") === "restic" ? "restic" : "archive");

export async function resticVersion(): Promise<string> {
  const r = await run(["restic", "version"], { check: false, quiet: false });
  return r.code === 0 ? (r.stdout.match(/restic (\d+\.\d+\.\d+)/)?.[1] ?? "") : "";
}

export async function ensureRestic() {
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
  if (kind !== "mysql" && kind !== "postgres" && kind !== "path" && kind !== "app" && kind !== "panel") throw new Error("kind must be mysql, postgres, path, app or panel");
  const target =
    kind === "panel"
      ? "panel"
      : kind === "mysql"
        ? v.dbName(x.target)
        : kind === "postgres"
          ? pgName(x.target)
          : kind === "app"
            ? v.appName(x.target)
            : v.pathUnder(x.target, PATH_ROOTS);
  const schedule = String(x.schedule ?? "manual");
  if (!/^(manual|hourly|daily [0-2]\d:[0-5]\d|weekly (Sun|Mon|Tue|Wed|Thu|Fri|Sat) [0-2]\d:[0-5]\d)$/.test(schedule)) {
    throw new Error("schedule: manual, hourly, 'daily HH:MM' or 'weekly Sun HH:MM'");
  }
  const name = kind === "panel" ? "panel" : String(x.name ?? "").trim() || `${kind}-${String(target).replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(name)) throw new Error("job name: letters, digits, . _ -");
  return { name, kind, target, schedule, keep: v.int(x.keep ?? 7, 1, 365, "keep") } as const;
}

const EXCLUDES = ["node_modules", ".git", ".next/cache"];

function dumpOf(job: BackupJob): string[] | null {
  if (job.kind === "mysql") return dumpCommand(job.target);
  if (job.kind === "postgres") return pgDumpCommand(job.target);
  return null;
}

/** `sqlite`: databases in DATA_DIR with a consistent copy in data/.pano-sqlite; their live files stay out. */
function archiveCommand(job: BackupJob, sqlite: string[] = []): { cmd: string[]; ext: string } {
  const dump = dumpOf(job);
  if (dump) return { cmd: dump, ext: "sql" };
  const excludes = [...EXCLUDES.map((e) => `--exclude=${e}`), "--exclude=./cache"];
  // Exact member names from here on (a database called "a*.db" must not exclude others).
  if (sqlite.length) excludes.push("--anchored", "--no-wildcards", ...sqlite.flatMap((rel) => liveFiles(rel).map((f) => `--exclude=data/${f}`)));
  if (job.kind === "app") {
    if (!apps.get(job.target)) throw new Error(`app ${job.target} no longer exists`);
    const home = fsPath(appHome(job.target));
    // slot-a/slot-b are symlinks to releases and stay symlinks (as with restic): following links
    // as root over app-writable dirs would let the app read any file (backup.key) back from a restore.
    // Releases are rebuilt from git on recovery.
    // .ssh: the deploy key, so a recovered server can pull without adding a new key.
    return { cmd: ["tar", "-cf", "-", "--ignore-failed-read", ...excludes, "-C", home, "shared", "data", ".ssh", "slot-a", "slot-b"], ext: "tar" };
  }
  return { cmd: ["tar", "-cf", "-", "--exclude=node_modules", "--exclude=.git", "-C", fsPath(job.target), "."], ext: "tar" };
}

/**
 * The panel itself: consistent copies of its two databases (apps, sites, jobs,
 * settings; admins), its configuration and secrets, and the edge's certificates.
 * Small; with the recovery kit it rebuilds the server elsewhere (recovery.ts).
 */
async function panelArchive() {
  const tmp = `${paths.data}/tmp/panel-${Date.now()}`;
  await ensureDir(tmp, 0o700);
  const files = ["state.db"];
  state().exec(`VACUUM INTO '${fsPath(tmp)}/state.db'`);
  if (await exists(paths.webDb)) {
    const web = new Database(fsPath(paths.webDb), { readonly: true });
    web.exec(`VACUUM INTO '${fsPath(tmp)}/web.db'`);
    web.close();
    files.push("web.db");
  }
  const cmd = ["tar", "-cf", "-", "--ignore-failed-read", "-C", fsPath("/"), paths.etc.slice(1), paths.edgeData.slice(1), "-C", fsPath(tmp), ...files];
  return { cmd, ext: "tar", cleanup: () => remove(tmp) };
}

/** Directories restic reads for a file job: an app's env, data and live release. */
async function resticPaths(job: BackupJob): Promise<string[]> {
  if (job.kind === "path") return [fsPath(job.target)];
  if (!apps.get(job.target)) throw new Error(`app ${job.target} no longer exists`);
  const home = fsPath(appHome(job.target));
  const out = [`${home}/shared`, `${home}/data`, `${home}/.ssh`];
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
  const ids = dests.map((d) => {
    // The panel's own state is one small archive, restorable without restic.
    const eng = job.kind === "panel" || isProtected(d) ? "archive" : engine();
    const runId = backups.startRun(jobId, d, eng);
    enqueue(() => (eng === "restic" ? executeRestic(job, runId, d) : executeArchive(job, runId, d)));
    return runId;
  });
  audit(actor, "backup.run", { job: job.name, runs: ids });
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
    const { cmd, ext, cleanup } =
      job.kind === "panel"
        ? await panelArchive()
        : job.kind === "app"
          ? { ...archiveCommand(job, await snapshotApp(job.target)), cleanup: () => dropSnapshots(job.target) }
          : { ...archiveCommand(job), cleanup: async () => {} };
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*/, "").replace("T", "-");
    const objectKey = `${prefix}/${backupHost()}/${job.name}/${stamp}.${ext}.gz.enc`;
    if (DRY_RUN) {
      await cleanup();
      console.log(`[dry-run] backup ${cmd.join(" ")} -> ${d}://${objectKey}`);
      backups.finishRun(runId, job.id, { status: "success", object_key: objectKey, bytes: 0 });
      return;
    }
    const proc = Bun.spawn([...LOW, ...cmd], { stdout: "pipe", stderr: "pipe", env: ENV });
    const stream = proc.stdout.pipeThrough(new CompressionStream("gzip")).pipeThrough(encryptStream(key, { kind: job.kind, job: job.name, object: objectOf(objectKey) }));
    const writer = s3.file(objectKey).writer({ partSize: 8 * 1024 * 1024, retry: 3, type: "application/octet-stream" });
    let bytes = 0;
    for await (const chunk of stream) {
      bytes += chunk.length;
      await writer.write(chunk);
    }
    const code = await proc.exited;
    const stderr = await new Response(proc.stderr).text();
    await cleanup();
    // tar exits 1 for "file changed as we read it", which is fine for live sites.
    if (code !== 0 && !((job.kind === "path" || job.kind === "app" || job.kind === "panel") && code === 1)) {
      await Promise.resolve(writer.end()).catch(() => {});
      await s3.delete(objectKey).catch(() => {});
      throw new Error(`${cmd[0]} exited ${code}: ${stderr.trim().split("\n").slice(-2).join(" ")}`);
    }
    await writer.end();
    backups.finishRun(runId, job.id, { status: "success", object_key: objectKey, bytes });
    if (isProtected(d)) return;
    for (const old of backups.successfulRuns(job.id, d, "archive").slice(job.keep)) {
      await s3.delete(old.object_key).catch(() => {});
      backups.markDeleted(old.id);
    }
  } catch (e) {
    await failed(job, runId, d, e);
  }
}

// ---- restic ---------------------------------------------------------------------------

export async function resticEnv(d: DestId): Promise<Record<string, string>> {
  const c = await creds(d);
  const key = await backupKey();
  const path = [c.prefix, "restic", backupHost()].filter(Boolean).join("/");
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

export async function restic(env: Record<string, string>, args: string[], stdin?: ReadableStream<Uint8Array>) {
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

const tagArgs = (job: BackupJob) => ["--tag", `job-${job.id}`, "--host", backupHost()];

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
      // Databases in DATA_DIR go in as their consistent copy; a name restic would read as a pattern keeps its live files too.
      const sqlite = job.kind === "app" ? await snapshotApp(job.target) : [];
      const data = fsPath(`${appHome(job.target)}/data`);
      const live = sqlite.filter((rel) => !/[*?[\\]/.test(rel)).flatMap((rel) => liveFiles(rel).flatMap((f) => ["--exclude", `${data}/${f}`]));
      try {
        r = await restic(env, ["backup", "--json", "--one-file-system", "--exclude-caches", ...EXCLUDES.flatMap((e) => ["--exclude", e]), ...live, ...tagArgs(job), ...dirs]);
      } finally {
        if (job.kind === "app") await dropSnapshots(job.target);
      }
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
  for (const d of destIds().filter((x) => !isProtected(x))) {
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
    cmd = await pgRestoreCommand(db);
    where = `PostgreSQL database ${db}`;
  } else {
    where = `${paths.data}/restore/${job.name}-${runId}-${Date.now()}`;
    await ensureDir(where, 0o700);
  }
  if (DRY_RUN) return `[dry-run] would restore into ${where}`;

  if (r.engine === "restic") await restoreRestic(r, job, d, cmd, where);
  else await restoreArchive(r, job, d, cmd ?? ["tar", "-xf", "-", "--no-same-owner", "--no-same-permissions", "--no-overwrite-dir", "-C", fsPath(where)]);
  // The consistent copies of the app's SQLite databases take their place.
  if (job.kind === "app") await placeSnapshots(r.engine === "restic" ? `${where}${fsPath(appHome(job.target))}/data` : `${where}/data`);
  audit(actor, "backup.restore", { runId, where });
  return `restored into ${where}`;
}

async function restoreArchive(r: BackupRun, job: BackupJob, d: DestId, cmd: string[]) {
  const { s3 } = await client(d);
  const res = await feedVerified(s3.file(r.object_key).stream(), await backupKey(), { kind: job.kind, job: job.name, object: objectOf(r.object_key) }, cmd, ENV);
  if (res.code !== 0) throw new Error(`restore failed: ${res.stderr.split("\n").slice(-2).join(" ")}`);
}

/** Runs cmd with the decrypted backup on stdin, from a temporary copy that was fully verified first. */
export async function feedVerified(src: ReadableStream<Uint8Array>, key: Buffer, expect: BackupContext, cmd: string[], env?: Record<string, string>) {
  await ensureDir(`${paths.data}/tmp`, 0o700);
  const tmp = `${paths.data}/tmp/restore-${randomBytes(8).toString("hex")}`;
  try {
    await decryptToFile(src, key, expect, fsPath(tmp));
    const proc = Bun.spawn(cmd, { stdin: Bun.file(fsPath(tmp)), stdout: "ignore", stderr: "pipe", env });
    const [code, stderr] = await Promise.all([proc.exited, new Response(proc.stderr).text()]);
    return { code, stderr: stderr.trim() };
  } finally {
    await remove(tmp);
  }
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
export function ensureJob(kind: "mysql" | "postgres" | "app" | "path" | "panel", target: string, actor: string, opts: { keep?: number } = {}) {
  if (backups.jobs().some((j) => j.kind === kind && j.target === target)) return null;
  // The panel's own state goes last, after the nightly data backups it lists.
  const job = validateJob({ kind, target, schedule: kind === "panel" ? "daily 04:30" : "daily 03:30", keep: opts.keep ?? (kind === "panel" ? 30 : 14) });
  backups.addJob(job);
  audit(actor, "backup.job.add", { ...job, automatic: true });
  return job;
}

export type DefaultSources = { apps: string[]; sites: string[]; mysql: string[]; postgres: string[] };

/** What exists on this server and should be backed up: managed apps, PHP sites (their root), MariaDB and PostgreSQL databases. */
export async function defaultSources(): Promise<DefaultSources> {
  return {
    apps: apps.list().filter((a) => a.kind === "managed").map((a) => a.name),
    sites: sites.list().filter((s) => s.kind === "php" && s.root).map((s) => s.root),
    mysql: (await listDatabases().catch(() => [])).filter((x) => !x.system).map((x) => x.name),
    postgres: await pgNames().catch(() => []),
  };
}

/**
 * A daily job (keeping 30) for everything that has none yet, plus the panel's own state.
 * Safe to run again: whatever already has a job is left as it is.
 */
export async function ensureDefaultJobs(actor: string, src?: DefaultSources) {
  const s = src ?? (await defaultSources());
  const added: { kind: BackupJob["kind"]; target: string; name: string }[] = [];
  const skipped: { kind: BackupJob["kind"]; target: string; reason: string }[] = [];
  let existing = 0;
  const want: [BackupJob["kind"], string][] = [
    ["panel", "panel"],
    ...s.apps.map((t): [BackupJob["kind"], string] => ["app", t]),
    ...s.sites.map((t): [BackupJob["kind"], string] => ["path", t]),
    ...s.mysql.map((t): [BackupJob["kind"], string] => ["mysql", t]),
    ...s.postgres.map((t): [BackupJob["kind"], string] => ["postgres", t]),
  ];
  for (const [kind, target] of want) {
    try {
      const job = ensureJob(kind, target, actor, { keep: 30 });
      if (job) added.push({ kind, target, name: job.name });
      else existing++;
    } catch (e) {
      skipped.push({ kind, target, reason: e instanceof Error ? e.message : String(e) });
    }
  }
  return { added, existing, skipped, keep: 30 };
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
