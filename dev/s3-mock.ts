// A tiny S3 stand-in for backup tests in the VM (path-style, no auth checks):
// objects, multipart uploads (Bun's S3 client), ListObjects v1/v2, ranges and
// aws-chunked streaming uploads (restic's client over plain http).
//   bun dev/s3-mock.ts /var/tmp/s3mock 9000
import { mkdir, readdir, rm, stat } from "node:fs/promises";
import { dirname, join, relative } from "node:path";

const root = process.argv[2] ?? "/var/tmp/s3mock";
const port = Number(process.argv[3] ?? 9000);
const uploads = new Map<string, Map<number, Uint8Array>>();

const xml = (body: string, status = 200) => new Response(`<?xml version="1.0" encoding="UTF-8"?>\n${body}`, { status, headers: { "content-type": "application/xml" } });
const notFound = (code = "NoSuchKey") => xml(`<Error><Code>${code}</Code><Message>not found</Message></Error>`, 404);
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** Decodes "size;chunk-signature=...\r\n data \r\n" frames. */
function unchunk(buf: Uint8Array): Uint8Array {
  const out: Uint8Array[] = [];
  let i = 0;
  const dec = new TextDecoder();
  while (i < buf.length) {
    let j = i;
    while (j < buf.length - 1 && !(buf[j] === 13 && buf[j + 1] === 10)) j++;
    const size = parseInt(dec.decode(buf.subarray(i, j)).split(";")[0]!, 16);
    if (!size) break;
    out.push(buf.subarray(j + 2, j + 2 + size));
    i = j + 2 + size + 2;
  }
  return Buffer.concat(out);
}

async function body(req: Request): Promise<Uint8Array> {
  const raw = new Uint8Array(await req.arrayBuffer());
  const sha = req.headers.get("x-amz-content-sha256") ?? "";
  return sha.startsWith("STREAMING-") || (req.headers.get("content-encoding") ?? "").includes("aws-chunked") ? unchunk(raw) : raw;
}

async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(p)));
    else out.push(p);
  }
  return out;
}

async function list(bucket: string, q: URLSearchParams) {
  const prefix = q.get("prefix") ?? "";
  const delimiter = q.get("delimiter") ?? "";
  const after = q.get("start-after") ?? q.get("continuation-token") ?? q.get("marker") ?? "";
  const base = join(root, bucket);
  const keys = (await walk(base)).map((p) => relative(base, p)).filter((k) => k.startsWith(prefix) && k > after).sort();
  const files: string[] = [];
  const prefixes = new Set<string>();
  for (const k of keys) {
    const rest = k.slice(prefix.length);
    const cut = delimiter ? rest.indexOf(delimiter) : -1;
    if (cut >= 0) prefixes.add(prefix + rest.slice(0, cut + 1));
    else files.push(k);
  }
  const contents = await Promise.all(
    files.map(async (k) => {
      const s = await stat(join(base, k));
      return `<Contents><Key>${esc(k)}</Key><LastModified>${s.mtime.toISOString()}</LastModified><ETag>"${s.size}"</ETag><Size>${s.size}</Size><StorageClass>STANDARD</StorageClass></Contents>`;
    }),
  );
  return xml(
    `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>${bucket}</Name><Prefix>${esc(prefix)}</Prefix><KeyCount>${files.length + prefixes.size}</KeyCount><MaxKeys>100000</MaxKeys><IsTruncated>false</IsTruncated>${contents.join("")}${[...prefixes].map((p) => `<CommonPrefixes><Prefix>${esc(p)}</Prefix></CommonPrefixes>`).join("")}</ListBucketResult>`,
  );
}

Bun.serve({
  port,
  hostname: "127.0.0.1",
  maxRequestBodySize: 1024 * 1024 * 1024,
  async fetch(req) {
    const url = new URL(req.url);
    const q = url.searchParams;
    const [bucket, ...rest] = decodeURIComponent(url.pathname).slice(1).split("/");
    const key = rest.join("/");
    if (!bucket) return xml("<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>");
    await mkdir(join(root, bucket), { recursive: true });
    const file = join(root, bucket, key);
    if (!key) {
      if (q.has("location")) return xml("<LocationConstraint>us-east-1</LocationConstraint>");
      if (req.method === "HEAD" || req.method === "PUT") return new Response(null, { status: 200 });
      return list(bucket, q);
    }
    if (req.method === "POST" && q.has("uploads")) {
      const id = crypto.randomUUID();
      uploads.set(id, new Map());
      return xml(`<InitiateMultipartUploadResult><Bucket>${bucket}</Bucket><Key>${esc(key)}</Key><UploadId>${id}</UploadId></InitiateMultipartUploadResult>`);
    }
    if (req.method === "PUT" && q.has("uploadId")) {
      uploads.get(q.get("uploadId")!)?.set(Number(q.get("partNumber")), await body(req));
      return new Response(null, { status: 200, headers: { etag: `"p${q.get("partNumber")}"` } });
    }
    if (req.method === "POST" && q.has("uploadId")) {
      const parts = uploads.get(q.get("uploadId")!);
      if (!parts) return notFound("NoSuchUpload");
      await mkdir(dirname(file), { recursive: true });
      await Bun.write(file, Buffer.concat([...parts.entries()].sort((a, b) => a[0] - b[0]).map((e) => e[1])));
      uploads.delete(q.get("uploadId")!);
      return xml(`<CompleteMultipartUploadResult><Bucket>${bucket}</Bucket><Key>${esc(key)}</Key><ETag>"done"</ETag></CompleteMultipartUploadResult>`);
    }
    if (req.method === "DELETE" && q.has("uploadId")) {
      uploads.delete(q.get("uploadId")!);
      return new Response(null, { status: 204 });
    }
    if (req.method === "PUT") {
      await mkdir(dirname(file), { recursive: true });
      await Bun.write(file, await body(req));
      return new Response(null, { status: 200, headers: { etag: '"put"' } });
    }
    if (req.method === "DELETE") {
      await rm(file, { force: true });
      return new Response(null, { status: 204 });
    }
    const s = await stat(file).catch(() => null);
    if (!s?.isFile()) return req.method === "HEAD" ? new Response(null, { status: 404 }) : notFound();
    const headers = { "content-length": String(s.size), etag: `"${s.size}"`, "last-modified": s.mtime.toUTCString(), "accept-ranges": "bytes" };
    if (req.method === "HEAD") return new Response(null, { status: 200, headers });
    const range = req.headers.get("range")?.match(/bytes=(\d+)-(\d*)/);
    if (range) {
      const from = Number(range[1]);
      const to = range[2] ? Math.min(Number(range[2]), s.size - 1) : s.size - 1;
      return new Response(Bun.file(file).slice(from, to + 1), {
        status: 206,
        headers: { ...headers, "content-length": String(to - from + 1), "content-range": `bytes ${from}-${to}/${s.size}` },
      });
    }
    return new Response(Bun.file(file), { headers });
  },
});
console.log(`s3 mock on 127.0.0.1:${port}, data in ${root}`);
