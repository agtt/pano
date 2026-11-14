// The few bucket-level calls Bun's S3Client does not have: a SigV4 signer, a bucket check and
// CreateBucket for S3-compatible stores, and Backblaze B2's own API (which tells the S3
// address and can create a bucket). Every request goes through a `guard` first (the SSRF
// check of backup.ts, passed in so this file stays free of imports from it).

import { createHash, createHmac, randomBytes } from "node:crypto";
import type { S3Failure } from "../shared/backup-providers.ts";

const sha256 = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex");
const hmac = (key: string | Buffer, data: string) => createHmac("sha256", key).update(data).digest();
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());

export type SignInput = {
  method: string;
  url: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  body?: string | Uint8Array;
  /** Extra headers to send and sign (besides host and the x-amz ones added here). */
  headers?: Record<string, string>;
  date?: Date;
  service?: string;
};

/**
 * AWS Signature V4 for a request with the payload hash in the headers (what S3 wants).
 * Returns the headers to send: the given ones, x-amz-date, x-amz-content-sha256 and authorization
 * (host is signed from the URL and set by fetch itself).
 */
export function signV4(i: SignInput): Record<string, string> {
  const u = new URL(i.url);
  const service = i.service ?? "s3";
  const payload = sha256(i.body ?? "");
  const amzDate = (i.date ?? new Date()).toISOString().replace(/[-:]/g, "").replace(/\.\d+/, "");
  const day = amzDate.slice(0, 8);
  const send: Record<string, string> = {};
  for (const [k, val] of Object.entries(i.headers ?? {})) send[k.toLowerCase()] = val;
  send["x-amz-content-sha256"] = payload;
  send["x-amz-date"] = amzDate;
  const signed: Record<string, string> = { ...send, host: u.host };
  const names = Object.keys(signed).sort();
  const canonicalHeaders = names.map((n) => `${n}:${signed[n]!.trim().replace(/\s+/g, " ")}\n`).join("");
  const query = [...u.searchParams.entries()]
    .map(([k, val]) => [enc(k), enc(val)] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
    .map(([k, val]) => `${k}=${val}`)
    .join("&");
  const canonical = [i.method.toUpperCase(), u.pathname || "/", query, canonicalHeaders, names.join(";"), payload].join("\n");
  const scope = `${day}/${i.region}/${service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac(`AWS4${i.secretAccessKey}`, day), i.region), service), "aws4_request");
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  send.authorization = `AWS4-HMAC-SHA256 Credential=${i.accessKeyId}/${scope},SignedHeaders=${names.join(";")},Signature=${signature}`;
  return send;
}

/** An answer that was not a success, with what the provider said. */
export class StoreError extends Error {
  constructor(public failure: S3Failure) {
    super(failure.message || failure.code || `HTTP ${failure.status ?? "error"}`);
  }
}

export type Io = {
  fetch?: typeof fetch;
  /** Throws when the URL must not be called (private address, not https). */
  guard?: (url: string) => Promise<void>;
};

async function call(io: Io, url: string, init: RequestInit): Promise<Response> {
  await io.guard?.(url);
  // No redirects: a redirect could point at an internal address the guard never saw.
  return (io.fetch ?? fetch)(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(20_000) });
}

const xml = (body: string, tag: string) => body.match(new RegExp(`<${tag}>([^<]*)</${tag}>`))?.[1];

export type BucketCall = {
  endpoint: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
};

async function bucketRequest(method: "GET" | "PUT", b: BucketCall, io: Io, o: { body?: string; query?: string } = {}): Promise<{ status: number; code?: string; message?: string; region?: string }> {
  const url = `${b.endpoint.replace(/\/$/, "")}/${b.bucket}${o.query ?? ""}`;
  const headers = signV4({ method, url, region: b.region, accessKeyId: b.accessKeyId, secretAccessKey: b.secretAccessKey, body: o.body });
  const res = await call(io, url, { method, headers, body: o.body });
  const text = await res.text().catch(() => "");
  return { status: res.status, code: xml(text, "Code"), message: xml(text, "Message"), region: res.headers.get("x-amz-bucket-region") ?? undefined };
}

/**
 * Whether the bucket is there, by asking for one key of its list (unlike HeadBucket, a refusal
 * then names its reason: wrong key, wrong region). "unknown" when the answer does not say
 * (403 AccessDenied: a key limited to objects may not list but still read and write).
 */
export async function checkBucket(b: BucketCall, io: Io = {}): Promise<{ exists: "yes" | "no" | "unknown"; failure?: S3Failure }> {
  const r = await bucketRequest("GET", b, io, { query: "?list-type=2&max-keys=1" });
  if (r.status >= 200 && r.status < 300) return { exists: "yes" };
  if (r.status === 404) return { exists: "no" };
  return { exists: "unknown", failure: { status: r.status, code: r.status === 301 ? "PermanentRedirect" : r.code, message: r.region ? `bucket is in region ${r.region}` : r.message } };
}

/** CreateBucket; throws StoreError when refused. An already owned bucket counts as created. */
export async function createBucket(b: BucketCall, io: Io = {}, locationConstraint?: string): Promise<void> {
  const body = locationConstraint && locationConstraint !== "us-east-1" ? `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>${locationConstraint}</LocationConstraint></CreateBucketConfiguration>` : undefined;
  const r = await bucketRequest("PUT", b, io, { body });
  if (r.status >= 200 && r.status < 300) return;
  if (r.code === "BucketAlreadyOwnedByYou") return;
  throw new StoreError({ status: r.status, code: r.code, message: r.message });
}

/** pano-<host>-<random>: private, unique enough for names that all customers of a provider share. */
export function suggestBucketName(host: string): string {
  const h = host.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 30).replace(/-+$/, "");
  return `pano-${h || "server"}-${randomBytes(3).toString("hex")}`;
}

// ---- Backblaze B2 native API -----------------------------------------------------------

/** The only host the key is ever sent to. */
export const B2_AUTH_URL = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account";
const B2_HOST = /^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)*\.backblazeb2\.com\/?$/;

export type B2Auth = {
  accountId: string;
  token: string;
  /** For further native calls. */
  apiUrl: string;
  /** S3 endpoint of the account's region. */
  s3ApiUrl: string;
  /** The buckets the key is limited to (empty: all). */
  buckets: { id: string; name: string | null }[];
  namePrefix: string | null;
  capabilities: string[];
};

/** Reads b2_authorize_account (v4: storageApi.allowed; v3: bucketId/bucketName/namePrefix/capabilities directly in storageApi). */
export function parseB2Auth(j: any): B2Auth {
  const api = j?.apiInfo?.storageApi;
  if (!j?.accountId || !j?.authorizationToken || !api) throw new StoreError({ message: "Backblaze answered in an unexpected form" });
  const apiUrl = String(api.apiUrl ?? "");
  const s3ApiUrl = String(api.s3ApiUrl ?? "");
  if (!B2_HOST.test(apiUrl) || !B2_HOST.test(s3ApiUrl)) throw new StoreError({ message: "Backblaze answered with an address outside backblazeb2.com" });
  const allowed = api.allowed ?? api;
  let buckets: B2Auth["buckets"] = [];
  if (Array.isArray(allowed.buckets)) buckets = allowed.buckets.map((x: any) => ({ id: String(x.id), name: x.name ? String(x.name) : null }));
  else if (allowed.bucketId) buckets = [{ id: String(allowed.bucketId), name: allowed.bucketName ? String(allowed.bucketName) : null }];
  return {
    accountId: String(j.accountId),
    token: String(j.authorizationToken),
    apiUrl: apiUrl.replace(/\/$/, ""),
    s3ApiUrl: s3ApiUrl.replace(/\/$/, ""),
    buckets,
    namePrefix: allowed.namePrefix ? String(allowed.namePrefix) : null,
    capabilities: Array.isArray(allowed.capabilities) ? allowed.capabilities.map(String) : [],
  };
}

async function b2Json(res: Response, what: string): Promise<any> {
  const j: any = await res.json().catch(() => ({}));
  if (res.ok) return j;
  // After signing in, B2 answers 401 "unauthorized" for a capability the key lacks: that is a permission, not a wrong key.
  const denied = what !== "authorize" && res.status === 401 && /unauthorized|not entitled|capabilit/i.test(`${j.code} ${j.message}`);
  throw new StoreError({ status: denied ? 403 : res.status, code: denied ? "AccessDenied" : j.code, message: j.message });
}

export async function b2Authorize(keyId: string, applicationKey: string, io: Io = {}): Promise<B2Auth> {
  const res = await call(io, B2_AUTH_URL, { headers: { authorization: `Basic ${Buffer.from(`${keyId}:${applicationKey}`).toString("base64")}` } });
  return parseB2Auth(await b2Json(res, "authorize"));
}

/**
 * A private bucket with default server-side encryption. With `retentionDays` (a protected store,
 * where pano never deletes) a lifecycle rule hides files that old and removes them a day later.
 */
export async function b2CreateBucket(auth: B2Auth, name: string, opts: { retentionDays?: number | null } = {}, io: Io = {}): Promise<string> {
  const body: Record<string, unknown> = {
    accountId: auth.accountId,
    bucketName: name,
    bucketType: "allPrivate",
    defaultServerSideEncryption: { mode: "SSE-B2", algorithm: "AES256" },
  };
  if (opts.retentionDays) body.lifecycleRules = [{ fileNamePrefix: "", daysFromUploadingToHiding: opts.retentionDays, daysFromHidingToDeleting: 1 }];
  const res = await call(io, `${auth.apiUrl}/b2api/v4/b2_create_bucket`, { method: "POST", headers: { authorization: auth.token, "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await b2Json(res, "create");
  return String(j.bucketName ?? name);
}
