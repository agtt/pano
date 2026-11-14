import { afterEach, describe, expect, test } from "bun:test";
import { connectDest, ensureDefaultJobs, getDest, health, type ConnectStep } from "../src/agent/backup.ts";
import { B2_AUTH_URL, b2Authorize, parseB2Auth, signV4, suggestBucketName } from "../src/agent/s3admin.ts";
import { PROVIDERS, PROVIDER_IDS, deriveEndpoint, explainFailure, inferProvider, storedEndpoint } from "../src/shared/backup-providers.ts";
import { backups, settings } from "../src/agent/state.ts";

const noGuard = async () => {};
const okSteps: ConnectStep[] = ["write", "read", "list", "delete"].map((name) => ({ name, ok: true, hint: "" }));
const KEY = "AKIAIOSFODNN7EXAMPLE";
const SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

const resetDest = () => {
  for (const k of ["accountId", "endpoint", "bucket", "prefix", "accessKeyId", "protect", "provider"]) settings.set(`r2.${k}`, "");
};
afterEach(resetDest);

describe("providers", () => {
  test("provider is inferred from the endpoint of an existing destination", () => {
    expect(inferProvider("")).toBe("r2");
    expect(inferProvider("https://abc.r2.cloudflarestorage.com")).toBe("r2");
    expect(inferProvider("https://abc.eu.r2.cloudflarestorage.com/")).toBe("r2");
    expect(inferProvider("https://s3.us-west-004.backblazeb2.com")).toBe("b2");
    expect(inferProvider("https://fsn1.your-objectstorage.com")).toBe("hetzner");
    expect(inferProvider("https://s3.eu-central-1.wasabisys.com")).toBe("wasabi");
    expect(inferProvider("https://s3.eu-west-1.amazonaws.com")).toBe("s3");
    expect(inferProvider("https://s3.amazonaws.com")).toBe("s3");
    expect(inferProvider("https://minio.example.com:9000")).toBe("other");
  });

  test("getDest reports a stored provider, or infers one for older installs", async () => {
    settings.set("r2.endpoint", "https://s3.us-west-004.backblazeb2.com");
    expect((await getDest("a")).provider).toBe("b2");
    settings.set("r2.provider", "other");
    expect((await getDest("a")).provider).toBe("other");
    settings.set("r2.provider", "");
    settings.set("r2.endpoint", "");
    expect((await getDest("a")).provider).toBe("r2");
  });

  test("endpoints follow from the choices; hosts only from fixed lists", () => {
    const id = "a".repeat(32);
    expect(deriveEndpoint("r2", { accountId: id })).toBe(`https://${id}.r2.cloudflarestorage.com`);
    expect(deriveEndpoint("r2", { accountId: id, jurisdiction: "eu" })).toBe(`https://${id}.eu.r2.cloudflarestorage.com`);
    expect(() => deriveEndpoint("r2", { accountId: "nope" })).toThrow("32-character");
    expect(deriveEndpoint("hetzner", { location: "hel1" })).toBe("https://hel1.your-objectstorage.com");
    expect(() => deriveEndpoint("hetzner", { location: "evil.com/x#" })).toThrow("location");
    expect(deriveEndpoint("wasabi", { region: "eu-central-2" })).toBe("https://s3.eu-central-2.wasabisys.com");
    expect(deriveEndpoint("s3", { region: "eu-west-1" })).toBe("https://s3.eu-west-1.amazonaws.com");
    expect(() => deriveEndpoint("s3", { region: "x.evil.com" })).toThrow("region");
    expect(deriveEndpoint("b2", {})).toBeNull();
    expect(deriveEndpoint("other", { endpoint: "https://s3.example.com/" })).toBe("https://s3.example.com");
    expect(() => deriveEndpoint("other", { endpoint: "http://10.0.0.1" })).toThrow("https");
    // R2 in its default location stays stored as before (account id, no endpoint).
    expect(storedEndpoint("r2", deriveEndpoint("r2", { accountId: id })!)).toBe("");
    expect(storedEndpoint("r2", deriveEndpoint("r2", { accountId: id, jurisdiction: "eu" })!)).toContain(".eu.");
  });

  test("every provider has the key fields, a key help text and https urls", () => {
    for (const id of PROVIDER_IDS) {
      const p = PROVIDERS[id];
      expect(p.fields.map((f) => f.name)).toEqual(expect.arrayContaining(["accessKeyId", "secretAccessKey", "bucket"]));
      expect(p.keyHelp.length).toBeGreaterThan(20);
      if (id !== "other") expect(p.keyUrl.startsWith("https://") && p.docsUrl.startsWith("https://")).toBe(true);
    }
  });

  test("errors come back as plain hints", () => {
    const h = (code: string, status?: number, what = "write") => explainFailure({ code, status, message: code }, { provider: "r2", bucket: "b", what });
    expect(h("AccessDenied", 403)).toContain("not allowed to read and write");
    expect(h("AccessDenied", 403, "delete")).toContain("delete files");
    expect(h("NoSuchBucket", 404)).toContain("does not exist");
    expect(h("InvalidAccessKeyId", 403)).toContain("mistyped");
    expect(h("SignatureDoesNotMatch", 403)).toContain("mistyped");
    expect(h("RequestTimeTooSkewed", 403)).toContain("clock");
    expect(explainFailure({ message: "getaddrinfo ENOTFOUND x.r2.cloudflarestorage.com" }, { provider: "r2" })).toContain("Account ID");
  });
});

describe("sigv4", () => {
  const sign = (url: string, headers: Record<string, string>) =>
    signV4({ method: "GET", url, region: "us-east-1", accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", date: new Date("2013-05-24T00:00:00Z"), headers });

  test("matches the AWS documentation example (GET object with Range)", () => {
    const h = sign("https://examplebucket.s3.amazonaws.com/test.txt", { Range: "bytes=0-9" });
    expect(h.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
    );
    expect(h["x-amz-date"]).toBe("20130524T000000Z");
    expect(h["x-amz-content-sha256"]).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  test("matches the AWS documentation example (GET bucket lifecycle, query string)", () => {
    const h = sign("https://examplebucket.s3.amazonaws.com/?lifecycle", {});
    expect(h.authorization).toContain("Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543");
  });

  test("bucket names are lowercase, bounded and random", () => {
    const a = suggestBucketName("My Server.example.com");
    expect(a).toMatch(/^pano-my-server-example-com-[0-9a-f]{6}$/);
    expect(a).not.toBe(suggestBucketName("My Server.example.com"));
    expect(suggestBucketName("")).toMatch(/^pano-server-/);
  });
});

const authV4 = (allowed: Record<string, unknown>) => ({
  accountId: "acc123",
  authorizationToken: "tok",
  apiInfo: { storageApi: { apiUrl: "https://api005.backblazeb2.com", s3ApiUrl: "https://s3.us-west-004.backblazeb2.com", allowed } },
});
const ALL = { buckets: null, capabilities: ["listFiles", "readFiles", "writeFiles", "deleteFiles", "writeBuckets"], namePrefix: null };

describe("backblaze", () => {
  test("authorize response: unrestricted, restricted to a bucket, and the older flat shape", () => {
    const a = parseB2Auth(authV4(ALL));
    expect(a).toMatchObject({ accountId: "acc123", token: "tok", apiUrl: "https://api005.backblazeb2.com", s3ApiUrl: "https://s3.us-west-004.backblazeb2.com", buckets: [], namePrefix: null });
    const r = parseB2Auth(authV4({ buckets: [{ id: "b1", name: "mine" }], capabilities: ["readFiles"], namePrefix: "pano/" }));
    expect(r.buckets).toEqual([{ id: "b1", name: "mine" }]);
    expect(r.namePrefix).toBe("pano/");
    const v3 = parseB2Auth({ accountId: "x", authorizationToken: "t", apiInfo: { storageApi: { apiUrl: "https://api001.backblazeb2.com", s3ApiUrl: "https://s3.us-west-001.backblazeb2.com", bucketId: "b9", bucketName: "old", namePrefix: null, capabilities: ["listFiles"] } } });
    expect(v3.buckets).toEqual([{ id: "b9", name: "old" }]);
    expect(v3.capabilities).toEqual(["listFiles"]);
  });

  test("an address outside backblazeb2.com is refused", () => {
    const bad = authV4(ALL);
    bad.apiInfo.storageApi.s3ApiUrl = "https://169.254.169.254";
    expect(() => parseB2Auth(bad)).toThrow("outside backblazeb2.com");
    expect(() => parseB2Auth({})).toThrow("unexpected");
  });

  test("b2Authorize calls the fixed host with basic auth and reports a wrong key", async () => {
    let seen: { url: string; auth: string } | null = null;
    const ok = (async (url: string, init: any) => {
      seen = { url, auth: init.headers.authorization };
      return Response.json(authV4(ALL));
    }) as unknown as typeof fetch;
    await b2Authorize("key1", "secret1", { fetch: ok, guard: noGuard });
    expect(seen!.url).toBe(B2_AUTH_URL);
    expect(new URL(B2_AUTH_URL).host).toBe("api.backblazeb2.com");
    expect(seen!.auth).toBe(`Basic ${Buffer.from("key1:secret1").toString("base64")}`);
    const denied = (async () => Response.json({ status: 401, code: "unauthorized", message: "Invalid credentials" }, { status: 401 })) as unknown as typeof fetch;
    await expect(b2Authorize("k", "s", { fetch: denied, guard: noGuard })).rejects.toThrow("Invalid credentials");
  });

  test("an unrestricted key and no bucket: pano makes a private bucket, with a lifecycle rule when protected", async () => {
    const calls: { url: string; body?: any }[] = [];
    const fetcher = (async (url: string, init: any) => {
      calls.push({ url, body: init.body ? JSON.parse(init.body) : undefined });
      if (url === B2_AUTH_URL) return Response.json(authV4(ALL));
      if (url.endsWith("/b2_create_bucket")) return Response.json({ bucketName: JSON.parse(init.body).bucketName });
      return new Response("", { status: 500 });
    }) as unknown as typeof fetch;
    const probed: any[] = [];
    const r = await connectDest(
      "a",
      { provider: "b2", fields: { accessKeyId: "0051234567890abcdef12345", secretAccessKey: "K005abcdefghijklmnopqrstuvwxyz1" }, protect: true },
      "tester",
      { fetch: fetcher, guard: noGuard, probe: async (cfg) => (probed.push(cfg), okSteps) },
    );
    expect(r.ok).toBe(true);
    expect(r.created).toBe(true);
    expect(r.bucket).toMatch(/^pano-.+-[0-9a-f]{6}$/);
    expect(r.endpoint).toBe("https://s3.us-west-004.backblazeb2.com");
    expect(r.region).toBe("us-west-004");
    expect(r.lifecycle).toEqual({ retentionDays: 60 });
    expect(r.notes.join(" ")).toContain("never delete");
    const create = calls.find((c) => c.url.endsWith("/b2_create_bucket"))!;
    expect(create.url).toBe("https://api005.backblazeb2.com/b2api/v4/b2_create_bucket");
    expect(create.body).toMatchObject({ accountId: "acc123", bucketType: "allPrivate", defaultServerSideEncryption: { mode: "SSE-B2", algorithm: "AES256" } });
    expect(create.body.lifecycleRules[0]).toMatchObject({ daysFromUploadingToHiding: 60, daysFromHidingToDeleting: 1 });
    expect(probed[0].endpoint).toBe(r.endpoint);
    const d = await getDest("a");
    expect(d).toMatchObject({ provider: "b2", bucket: r.bucket, endpoint: r.endpoint, protect: true, accessKeyId: "0051234567890abcdef12345" });
  });

  test("a key limited to one bucket uses it; a missing capability is explained", async () => {
    const restricted = { buckets: [{ id: "b1", name: "only-this" }], capabilities: ["listFiles", "readFiles", "writeFiles", "deleteFiles"], namePrefix: null };
    const f = (allowed: Record<string, unknown>) => (async () => Response.json(authV4(allowed))) as unknown as typeof fetch;
    const fields = { accessKeyId: "0051234567890abcdef12345", secretAccessKey: "K005abcdefghijklmnopqrstuvwxyz1" };
    const r = await connectDest("a", { provider: "b2", fields }, "t", { fetch: f(restricted), guard: noGuard, probe: async () => okSteps });
    expect(r).toMatchObject({ ok: true, bucket: "only-this", created: false });
    const wrong = await connectDest("a", { provider: "b2", fields: { ...fields, bucket: "other-one" } }, "t", { fetch: f(restricted), guard: noGuard, probe: async () => okSteps });
    expect(wrong.ok).toBe(false);
    expect(wrong.steps.at(-1)!.hint).toContain("only-this");
    const readOnly = await connectDest("a", { provider: "b2", fields }, "t", { fetch: f({ ...restricted, capabilities: ["listFiles", "readFiles"] }), guard: noGuard, probe: async () => okSteps });
    expect(readOnly.ok).toBe(false);
    expect(readOnly.steps.at(-1)).toMatchObject({ name: "keys", ok: false });
    expect(readOnly.steps.at(-1)!.hint).toContain("write files");
  });
});

describe("connect to S3-compatible stores", () => {
  const fields = { location: "fsn1", accessKeyId: KEY, secretAccessKey: SECRET, bucket: "my-backups" };
  const xmlError = (code: string, status: number) => new Response(`<Error><Code>${code}</Code><Message>${code}</Message></Error>`, { status });

  test("a missing bucket that cannot be created gives the plain instruction and saves nothing", async () => {
    const fetcher = (async (_url: string, init: any) => (init.method === "GET" ? xmlError("NoSuchBucket", 404) : xmlError("AccessDenied", 403))) as unknown as typeof fetch;
    const r = await connectDest("a", { provider: "hetzner", fields }, "t", { fetch: fetcher, guard: noGuard, probe: async () => okSteps });
    expect(r.ok).toBe(false);
    expect(r.steps.at(-1)).toMatchObject({ name: "bucket", ok: false });
    expect(r.steps.at(-1)!.hint).toContain('Create bucket "my-backups" in the Hetzner Object Storage dashboard');
    expect((await getDest("a")).bucket).toBe("");
  });

  test("a missing bucket is created with a signed request, then the destination is saved", async () => {
    const seen: { method: string; url: string; auth: string }[] = [];
    const fetcher = (async (url: string, init: any) => {
      seen.push({ method: init.method, url, auth: init.headers.authorization });
      return init.method === "GET" ? xmlError("NoSuchBucket", 404) : new Response("", { status: 200 });
    }) as unknown as typeof fetch;
    const r = await connectDest("a", { provider: "hetzner", fields }, "t", { fetch: fetcher, guard: noGuard, probe: async () => okSteps });
    expect(r).toMatchObject({ ok: true, created: true, bucket: "my-backups", endpoint: "https://fsn1.your-objectstorage.com", region: "fsn1" });
    expect(seen.map((s) => s.method)).toEqual(["GET", "PUT"]);
    expect(seen[1]!.url).toBe("https://fsn1.your-objectstorage.com/my-backups");
    expect(seen[1]!.auth).toContain(`Credential=${KEY}/`);
    expect(seen[1]!.auth).toContain("/fsn1/s3/aws4_request");
    expect(await getDest("a")).toMatchObject({ provider: "hetzner", bucket: "my-backups", endpoint: "https://fsn1.your-objectstorage.com", hasSecret: true });
  });

  test("R2 stays stored by account id; a failing test step stops the save", async () => {
    const id = "b".repeat(32);
    const fetcher = (async () => new Response(null, { status: 200 })) as unknown as typeof fetch;
    const failing: ConnectStep[] = [{ name: "write", ok: false, hint: "denied" }];
    const bad = await connectDest("a", { provider: "r2", fields: { accountId: id, accessKeyId: KEY, secretAccessKey: SECRET, bucket: "mine" } }, "t", { fetch: fetcher, guard: noGuard, probe: async () => failing });
    expect(bad.ok).toBe(false);
    expect((await getDest("a")).bucket).toBe("");
    const good = await connectDest("a", { provider: "r2", fields: { accountId: id, accessKeyId: KEY, secretAccessKey: SECRET, bucket: "mine" } }, "t", { fetch: fetcher, guard: noGuard, probe: async () => okSteps });
    expect(good.ok).toBe(true);
    expect(await getDest("a")).toMatchObject({ provider: "r2", accountId: id, endpoint: "", bucket: "mine" });
  });

  test("a wrong key is told apart from a missing bucket", async () => {
    const fetcher = (async () => xmlError("InvalidAccessKeyId", 403)) as unknown as typeof fetch;
    const r = await connectDest("a", { provider: "wasabi", fields: { region: "eu-central-1", accessKeyId: KEY, secretAccessKey: SECRET, bucket: "mine" } }, "t", { fetch: fetcher, guard: noGuard, probe: async () => okSteps });
    expect(r.ok).toBe(false);
    expect(r.steps.at(-1)!.hint).toContain("mistyped");
  });

  test("an endpoint the guard refuses is reported, not called", async () => {
    let called = false;
    const fetcher = (async () => ((called = true), new Response(null))) as unknown as typeof fetch;
    const guard = async () => {
      throw new Error("endpoint must be a public host (not a local or private address)");
    };
    const r = await connectDest("a", { provider: "hetzner", fields }, "t", { fetch: fetcher, guard, probe: async () => okSteps });
    expect(r.ok).toBe(false);
    expect(r.steps.at(-1)!.name).toBe("endpoint");
    expect(called).toBe(false);
  });
});

describe("overview and defaults", () => {
  test("health has the banner shape and reflects failures and jobs that never ran", () => {
    const base = health();
    expect(Object.keys(base).sort()).toEqual(["allProtected", "configured", "jobs", "keyExported", "keyExportedAt", "lastFailure", "lastSuccessAt", "neverRan", "protected"]);
    settings.set("r2.bucket", "health-bucket");
    settings.set("r2.protect", "1");
    const idle = backups.addJob({ name: "health-idle", kind: "path", target: "/srv/health-idle", schedule: "manual", keep: 1 });
    const bad = backups.addJob({ name: "health-bad", kind: "path", target: "/srv/health-bad", schedule: "manual", keep: 1 });
    const run = backups.startRun(bad, "a", "archive");
    backups.finishRun(run, bad, { status: "failed", error: "boom" });
    const good = backups.addJob({ name: "health-good", kind: "path", target: "/srv/health-good", schedule: "manual", keep: 1 });
    backups.finishRun(backups.startRun(good, "a", "archive"), good, { status: "success", object_key: "k", bytes: 1 });
    const h = health();
    expect(h.configured).toBe(1);
    expect(h.protected).toBe(true);
    expect(h.neverRan).toContain("health-idle");
    expect(h.neverRan).not.toContain("health-good");
    expect(h.lastFailure).toMatchObject({ job: "health-bad", error: "boom" });
    expect(typeof h.lastSuccessAt).toBe("number");
    expect(h.keyExported).toBe(base.keyExported);
    for (const id of [idle, bad, good]) backups.removeJob(id);
  });

  test("defaults add a daily job for everything without one, and only once", async () => {
    const src = { apps: ["dflt-app"], sites: ["/home/dflt.example/public"], mysql: ["dflt_db"], postgres: ["dflt_pg"] };
    const first = await ensureDefaultJobs("tester", src);
    const names = first.added.map((a) => `${a.kind}:${a.target}`);
    expect(names).toEqual(expect.arrayContaining(["app:dflt-app", "path:/home/dflt.example/public", "mysql:dflt_db", "postgres:dflt_pg"]));
    expect(first.keep).toBe(30);
    const job = backups.jobs().find((j) => j.target === "dflt_db")!;
    expect(job).toMatchObject({ schedule: "daily 03:30", keep: 30 });
    const second = await ensureDefaultJobs("tester", src);
    expect(second.added).toEqual([]);
    expect(second.existing).toBe(first.added.length + first.existing);
    expect(backups.jobs().filter((j) => j.target === "dflt_db")).toHaveLength(1);
    // A path outside the allowed roots is skipped with a reason, not fatal.
    const odd = await ensureDefaultJobs("tester", { apps: [], sites: ["/mnt/odd/public"], mysql: [], postgres: [] });
    expect(odd.skipped[0]!.target).toBe("/mnt/odd/public");
  });
});
