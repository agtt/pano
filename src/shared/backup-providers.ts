// What pano knows about each storage provider: which fields a person has, where the key
// comes from, how the endpoint follows from the choices, and what an error means in plain words.
// Pure data and functions (no I/O), so the connect flow, the web UI and the tests share one source.

export type ProviderId = "r2" | "b2" | "hetzner" | "wasabi" | "s3" | "other";
export const PROVIDER_IDS: ProviderId[] = ["r2", "b2", "hetzner", "wasabi", "s3", "other"];

export type FieldSpec = {
  /** Key in `fields` of backup.dest.connect. */
  name: string;
  label: string;
  placeholder: string;
  kind: "text" | "password" | "select";
  required: boolean;
  /** Collapsed under "more options" in the UI. */
  advanced?: boolean;
  help?: string;
  options?: { value: string; label: string }[];
  default?: string;
};

export type ProviderSpec = {
  id: ProviderId;
  name: string;
  /** One line under the provider's name in the picker. */
  tagline: string;
  fields: FieldSpec[];
  /** One line: where the key comes from. */
  keyHelp: string;
  /** The provider's page for creating the key (may need a sign-in). */
  keyUrl: string;
  /** The provider's own documentation on creating it. */
  docsUrl: string;
  /** What the key needs, in words: shown next to keyHelp. */
  permission: string;
  /** pano can create the bucket when it does not exist (needs a key with bucket-creation rights). */
  createsBucket: boolean;
};

const accessKeyId = (label: string, placeholder: string): FieldSpec => ({ name: "accessKeyId", label, placeholder, kind: "text", required: true });
const secretAccessKey = (label: string, placeholder: string): FieldSpec => ({ name: "secretAccessKey", label, placeholder, kind: "password", required: true, help: "Shown only once by the provider. pano stores it readable by root only and never shows it again." });
const bucket = (required: boolean, help: string): FieldSpec => ({ name: "bucket", label: "Bucket", placeholder: required ? "my-backups" : "(pano creates one for you)", kind: "text", required, help });
const prefix: FieldSpec = { name: "prefix", label: "Folder in the bucket", placeholder: "pano", kind: "text", required: false, advanced: true, default: "pano", help: "Backups go under this folder; leave as is unless the bucket is shared with something else." };
const BUCKET_HELP = "Leave empty and pano creates a private bucket for you (the key then needs rights to create buckets). Or type the name of one you already made.";

export const WASABI_REGIONS = [
  ["us-east-1", "US East 1 (N. Virginia)"], ["us-east-2", "US East 2 (N. Virginia)"], ["us-central-1", "US Central 1 (Texas)"],
  ["us-west-1", "US West 1 (Oregon)"], ["us-west-2", "US West 2 (San Jose)"], ["ca-central-1", "CA Central 1 (Toronto)"],
  ["eu-central-1", "EU Central 1 (Amsterdam)"], ["eu-central-2", "EU Central 2 (Frankfurt)"], ["eu-west-1", "EU West 1 (London)"],
  ["eu-west-2", "EU West 2 (Paris)"], ["eu-west-3", "EU West 3 (London)"], ["eu-south-1", "EU South 1 (Milan)"],
  ["ap-northeast-1", "AP Northeast 1 (Tokyo)"], ["ap-northeast-2", "AP Northeast 2 (Osaka)"],
  ["ap-southeast-1", "AP Southeast 1 (Singapore)"], ["ap-southeast-2", "AP Southeast 2 (Sydney)"],
] as const;

export const AWS_REGIONS = [
  ["us-east-1", "US East (N. Virginia)"], ["us-east-2", "US East (Ohio)"], ["us-west-1", "US West (N. California)"], ["us-west-2", "US West (Oregon)"],
  ["ca-central-1", "Canada (Central)"], ["eu-west-1", "Europe (Ireland)"], ["eu-west-2", "Europe (London)"], ["eu-west-3", "Europe (Paris)"],
  ["eu-central-1", "Europe (Frankfurt)"], ["eu-north-1", "Europe (Stockholm)"], ["eu-south-1", "Europe (Milan)"],
  ["ap-south-1", "Asia Pacific (Mumbai)"], ["ap-northeast-1", "Asia Pacific (Tokyo)"], ["ap-northeast-2", "Asia Pacific (Seoul)"],
  ["ap-southeast-1", "Asia Pacific (Singapore)"], ["ap-southeast-2", "Asia Pacific (Sydney)"], ["sa-east-1", "South America (Sao Paulo)"],
] as const;

export const HETZNER_LOCATIONS = [["fsn1", "Falkenstein (Germany)"], ["nbg1", "Nuremberg (Germany)"], ["hel1", "Helsinki (Finland)"]] as const;

const opts = (l: readonly (readonly [string, string])[]) => l.map(([value, label]) => ({ value, label }));

export const PROVIDERS: Record<ProviderId, ProviderSpec> = {
  r2: {
    id: "r2",
    name: "Cloudflare R2",
    tagline: "No fees for downloading your backups; 10 GB free",
    fields: [
      { name: "accountId", label: "Account ID", placeholder: "32 characters, letters a-f and digits", kind: "text", required: true, help: "Cloudflare dashboard > R2 object storage > Overview: Account ID is on the right." },
      accessKeyId("Access Key ID", "from the token you create"),
      secretAccessKey("Secret Access Key", "shown once next to the Access Key ID"),
      bucket(false, BUCKET_HELP),
      { name: "jurisdiction", label: "Data location", placeholder: "", kind: "select", required: false, advanced: true, default: "", options: [{ value: "", label: "Automatic (default)" }, { value: "eu", label: "European Union only" }], help: "Choose the EU if the data must stay in Europe. A bucket made for the EU is reachable only through the EU option." },
      prefix,
    ],
    keyHelp: "In Cloudflare open R2 object storage > Manage API Tokens > Create API token, pick \"Admin Read & Write\" (lets pano create the bucket) or \"Object Read & Write\" for a bucket you made, then copy the Access Key ID and Secret Access Key.",
    keyUrl: "https://dash.cloudflare.com/?to=/:account/r2/overview",
    docsUrl: "https://developers.cloudflare.com/r2/api/tokens/",
    permission: "Admin Read & Write (pano creates the bucket) or Object Read & Write on one bucket",
    createsBucket: true,
  },
  b2: {
    id: "b2",
    name: "Backblaze B2",
    tagline: "Cheap storage with a generous free tier",
    fields: [
      accessKeyId("keyID", "starts with 00"),
      secretAccessKey("applicationKey", "starts with K00"),
      bucket(false, "Leave empty: a key limited to one bucket uses that bucket, an all-buckets key gets a new private bucket made by pano."),
      { name: "retentionDays", label: "Keep backups for (days)", placeholder: "60", kind: "text", required: false, advanced: true, default: "60", help: "Only for a protected store that pano creates: Backblaze itself removes backups older than this, because pano never deletes there (7 to 3650)." },
      prefix,
    ],
    keyHelp: "In Backblaze open Application Keys > Add a New Application Key: keep \"All\" buckets (pano creates a private one) or pick one bucket, Read and Write, then copy the keyID and applicationKey; the applicationKey is shown only once.",
    keyUrl: "https://secure.backblaze.com/app_keys.htm",
    docsUrl: "https://www.backblaze.com/docs/cloud-storage-create-and-manage-app-keys",
    permission: "Read and Write on all buckets (pano creates one) or on one bucket you made",
    createsBucket: true,
  },
  hetzner: {
    id: "hetzner",
    name: "Hetzner Object Storage",
    tagline: "European data centres, fixed low price",
    fields: [
      { name: "location", label: "Location", placeholder: "", kind: "select", required: true, default: "fsn1", options: opts(HETZNER_LOCATIONS), help: "Where your buckets live; the same location you picked when creating the bucket." },
      accessKeyId("Access key", "from the S3 credentials you generate"),
      secretAccessKey("Secret key", "shown once next to the access key"),
      bucket(false, BUCKET_HELP),
      prefix,
    ],
    keyHelp: "In the Hetzner Console open your project > Security > S3 Credentials > Generate credentials, then copy the access key and the secret key (the secret is shown only once).",
    keyUrl: "https://console.hetzner.com/",
    docsUrl: "https://docs.hetzner.com/storage/object-storage/getting-started/generating-s3-keys",
    permission: "Credentials of the project that holds the bucket",
    createsBucket: true,
  },
  wasabi: {
    id: "wasabi",
    name: "Wasabi",
    tagline: "Flat price per TB, no download fees",
    fields: [
      { name: "region", label: "Region", placeholder: "", kind: "select", required: true, default: "eu-central-1", options: opts(WASABI_REGIONS), help: "Must match the region of the bucket." },
      accessKeyId("Access key", "from Access Keys > Create Access Key"),
      secretAccessKey("Secret key", "shown once after Create"),
      bucket(false, BUCKET_HELP),
      prefix,
    ],
    keyHelp: "In the Wasabi console open Access Keys > Create Access Key (root user or a sub-user), click Show next to the secret and copy both keys; they cannot be shown again.",
    keyUrl: "https://console.wasabisys.com/access_keys",
    docsUrl: "https://docs.wasabi.com/docs/creating-a-new-access-key",
    permission: "A user that may create buckets, or read/write on the bucket you made",
    createsBucket: true,
  },
  s3: {
    id: "s3",
    name: "Amazon S3",
    tagline: "AWS S3 (also fine for other S3 services with a region list)",
    fields: [
      { name: "region", label: "Region", placeholder: "", kind: "select", required: true, default: "eu-central-1", options: opts(AWS_REGIONS), help: "Must match the region of the bucket." },
      accessKeyId("Access key ID", "starts with AKIA"),
      secretAccessKey("Secret access key", "shown once when the key is created"),
      bucket(false, BUCKET_HELP),
      prefix,
    ],
    keyHelp: "In AWS IAM create a user, open Security credentials > Create access key and copy both values. Give the user S3 rights (AmazonS3FullAccess, or read/write on one bucket you made).",
    keyUrl: "https://console.aws.amazon.com/iam/home#/security_credentials",
    docsUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys-admin-managed.html",
    permission: "S3 read/write; creating the bucket also needs s3:CreateBucket",
    createsBucket: true,
  },
  other: {
    id: "other",
    name: "Other S3-compatible",
    tagline: "MinIO, Ceph, DigitalOcean Spaces, Scaleway and the like",
    fields: [
      { name: "endpoint", label: "Endpoint", placeholder: "https://s3.example.com", kind: "text", required: true, help: "The S3 address from the provider's documentation (https only; plain http only for a MinIO on this server)." },
      accessKeyId("Access key", "from your provider"),
      secretAccessKey("Secret key", "from your provider"),
      bucket(false, BUCKET_HELP),
      prefix,
    ],
    keyHelp: "Create an access key and secret in your provider's console and copy the S3 endpoint address from its documentation.",
    keyUrl: "",
    docsUrl: "",
    permission: "Read/write on the bucket",
    createsBucket: true,
  },
};

export const isProvider = (x: unknown): x is ProviderId => typeof x === "string" && (PROVIDER_IDS as string[]).includes(x);

/** Which provider an existing destination is, from its endpoint (no endpoint: R2 with the account id). */
export function inferProvider(endpoint: string): ProviderId {
  const e = endpoint.trim();
  if (!e) return "r2";
  const host = e.replace(/^https?:\/\//, "").replace(/[:/].*$/, "").toLowerCase();
  if (host.endsWith(".r2.cloudflarestorage.com")) return "r2";
  if (host.endsWith(".backblazeb2.com")) return "b2";
  if (host.endsWith(".your-objectstorage.com")) return "hetzner";
  if (host.endsWith(".wasabisys.com")) return "wasabi";
  if (host === "s3.amazonaws.com" || host.endsWith(".amazonaws.com")) return "s3";
  return "other";
}

/** "eu" when an R2 endpoint is the EU one. */
export const jurisdictionOf = (endpoint: string): "" | "eu" => (/^https:\/\/[a-f0-9]{32}\.eu\.r2\.cloudflarestorage\.com\/?$/.test(endpoint.trim()) ? "eu" : "");

const oneOf = (value: string, list: readonly (readonly [string, string])[], what: string) => {
  if (!list.some(([v]) => v === value)) throw new Error(`${what} must be one of: ${list.map(([v]) => v).join(", ")}`);
  return value;
};

/**
 * The endpoint that follows from the provider and what the person chose, or null when it has to be
 * asked from the provider first (Backblaze B2 tells it after signing in with the key).
 * Every value that ends up in the host name is checked against a fixed list.
 */
export function deriveEndpoint(provider: ProviderId, f: Record<string, unknown>): string | null {
  const s = (k: string) => String(f[k] ?? "").trim();
  switch (provider) {
    case "r2": {
      const id = s("accountId").toLowerCase();
      if (!/^[a-f0-9]{32}$/.test(id)) throw new Error("account id is the 32-character id from the Cloudflare dashboard (R2 > Overview)");
      const j = s("jurisdiction");
      if (j && j !== "eu") throw new Error("data location must be automatic or eu");
      return `https://${id}${j === "eu" ? ".eu" : ""}.r2.cloudflarestorage.com`;
    }
    case "hetzner":
      return `https://${oneOf(s("location") || "fsn1", HETZNER_LOCATIONS, "location")}.your-objectstorage.com`;
    case "wasabi":
      return `https://s3.${oneOf(s("region") || "eu-central-1", WASABI_REGIONS, "region")}.wasabisys.com`;
    case "s3":
      return `https://s3.${oneOf(s("region") || "eu-central-1", AWS_REGIONS, "region")}.amazonaws.com`;
    case "b2":
      return null;
    case "other": {
      const e = s("endpoint").replace(/\/+$/, "");
      // Plain http only to this machine (a local MinIO).
      if (!/^(https:\/\/[A-Za-z0-9.-]+|http:\/\/127\.0\.0\.1)(:\d+)?$/.test(e)) throw new Error("endpoint must be an https URL (like https://s3.example.com)");
      return e;
    }
  }
}

/** What is stored as "endpoint": nothing for R2 in its default location (the account id says it all, as before). */
export const storedEndpoint = (provider: ProviderId, derived: string) => (provider === "r2" && !jurisdictionOf(derived) ? "" : derived);

// ---- plain-words errors ------------------------------------------------------------------

export type S3Failure = { status?: number; code?: string; message?: string };

/**
 * Turns what an S3 or B2 call answered into something a person can act on.
 * `what` is the step that failed ("write", "read", "list", "delete", "bucket", "keys", ...).
 */
export function explainFailure(f: S3Failure, ctx: { provider: ProviderId; bucket?: string; what?: string }): string {
  const text = `${f.code ?? ""} ${f.message ?? ""}`;
  const name = PROVIDERS[ctx.provider].name;
  const b = ctx.bucket ? `"${ctx.bucket}"` : "the bucket";
  if (/NoSuchBucket|bucket.*(not found|does not exist)|not_found/i.test(text) || (f.status === 404 && ctx.what === "bucket")) {
    return `Bucket ${b} does not exist in ${name}. Check the name and ${ctx.provider === "wasabi" || ctx.provider === "s3" ? "region" : ctx.provider === "hetzner" ? "location" : "account"}, or create it in the ${name} dashboard.`;
  }
  if (/InvalidAccessKeyId|SignatureDoesNotMatch|bad_auth_token|Access Key Id.*not.*exist|NotSignedUp|expired_auth_token/i.test(text) || f.status === 401) {
    return "The key or the secret was not accepted: it is mistyped, from another account/region, or it was deleted. Copy them again without spaces (the secret is shown only once; make a new key if you lost it).";
  }
  if (/RequestTimeTooSkewed|RequestExpired|skew|clock/i.test(text)) {
    return "This server's clock is off by more than a few minutes, so the provider refuses the request. Fix the server time (timedatectl set-ntp true) and try again.";
  }
  if (/AccessDenied|Forbidden|not allowed|unauthorized_for_bucket|AllAccessDisabled|unauthorized|capabilit/i.test(text) || f.status === 403) {
    const need = ctx.what === "delete" ? "delete files" : ctx.what === "read" ? "read files" : ctx.what === "list" ? "list files" : ctx.what === "bucket" ? "create buckets" : "read and write files";
    return `The key is valid but not allowed to ${need} in ${b}. Make the key's access Read and Write for this bucket (or all buckets) and try again.`;
  }
  if (/PermanentRedirect|AuthorizationHeaderMalformed|IllegalLocationConstraint/i.test(text) || f.status === 301) {
    return `${b} is in another region than the one chosen. Pick the region the bucket was created in.`;
  }
  if (/BucketAlreadyExists/i.test(text)) return `The name ${b} is already taken by someone else (bucket names are shared by all ${name} customers). Choose another name.`;
  if (/InvalidBucketName/i.test(text)) return `${b} is not a valid bucket name: 3 to 63 lowercase letters, digits and hyphens.`;
  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo|DNS|does not resolve|Unable to connect|ConnectionRefused|ECONNREFUSED|ECONNRESET|ETIMEDOUT|timed? ?out|fetch failed|network/i.test(text)) {
    return ctx.provider === "r2"
      ? "Cannot reach Cloudflare R2: check the Account ID (a wrong one gives an address that does not exist) and that this server has internet access."
      : `Cannot reach ${name}: check the ${ctx.provider === "other" ? "endpoint address" : ctx.provider === "hetzner" ? "location" : ctx.provider === "b2" ? "internet access of this server" : "region"} and that this server has internet access.`;
  }
  if (/SlowDown|TooManyRequests|429|503/i.test(text)) return `${name} is asking to slow down. Wait a minute and try again.`;
  return `${name} answered: ${(f.message || f.code || `HTTP ${f.status ?? "error"}`).toString().slice(0, 200)}`;
}
