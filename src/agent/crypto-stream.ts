// Streaming AES-256-GCM for backups. Backups are encrypted on the server before
// they leave it, so the bucket (R2) only ever stores ciphertext.
//
// Format v2: "PANOBK2\n" | u32 BE header length | header JSON | 8-byte random nonce prefix | chunks
// Format v1: "PANOBK1\n" | 8-byte random nonce prefix | chunks (read-only, no context)
// chunk:  u32 BE ciphertext length | ciphertext+16-byte tag
// nonce = prefix || u32 BE counter; AAD = u32 BE counter || final flag byte [|| sha256(header) in v2].
// The final flag makes truncation (dropping trailing chunks) detectable. The v2 header
// (kind, job, object, created) is in the clear but authenticated by every chunk, so
// whoever can write to the store cannot hand a restore another job's or run's object:
// the caller says which one it expects and a mismatch fails before any data is released.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { createWriteStream } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

const MAGIC1 = Buffer.from("PANOBK1\n");
const MAGIC2 = Buffer.from("PANOBK2\n");
const CHUNK = 4 * 1024 * 1024;
const MAX_HEADER = 4096;

/** What a backup is: job kind and name, and its place in the store (host/job/file, without the bucket prefix). */
export type BackupContext = { kind: string; job: string; object: string };
export type BackupHeader = BackupContext & { created: string };

/** The context of an object key written as `<prefix>/<host>/<job>/<file>`; the prefix may move, the rest may not. */
export function objectOf(key: string) {
  return key.split("/").slice(-3).join("/");
}

function aad(counter: number, final: boolean, header: Buffer | null) {
  const b = Buffer.alloc(5);
  b.writeUInt32BE(counter, 0);
  b[4] = final ? 1 : 0;
  return header ? Buffer.concat([b, createHash("sha256").update(header).digest()]) : b;
}

function nonce(prefix: Buffer, counter: number) {
  const n = Buffer.alloc(12);
  prefix.copy(n, 0);
  n.writeUInt32BE(counter, 8);
  return n;
}

function seal(key: Buffer, prefix: Buffer, header: Buffer, counter: number, final: boolean, plain: Uint8Array): Uint8Array {
  const c = createCipheriv("aes-256-gcm", key, nonce(prefix, counter));
  c.setAAD(aad(counter, final, header));
  const body = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  const out = Buffer.alloc(4 + body.length);
  out.writeUInt32BE(body.length, 0);
  body.copy(out, 4);
  return out;
}

export function encryptStream(key: Buffer, ctx: BackupContext): TransformStream<Uint8Array, Uint8Array> {
  if (key.length !== 32) throw new Error("backup key must be 32 bytes");
  const prefix = randomBytes(8);
  const header = Buffer.from(JSON.stringify({ kind: ctx.kind, job: ctx.job, object: ctx.object, created: new Date().toISOString() } satisfies BackupHeader));
  const len = Buffer.alloc(4);
  len.writeUInt32BE(header.length, 0);
  let counter = 0;
  let buf = Buffer.alloc(0);
  return new TransformStream({
    start(ctrl) {
      ctrl.enqueue(Buffer.concat([MAGIC2, len, header, prefix]));
    },
    transform(chunk, ctrl) {
      buf = Buffer.concat([buf, chunk]);
      // Keep at least one byte back so the last chunk is always sealed as final.
      while (buf.length > CHUNK) {
        ctrl.enqueue(seal(key, prefix, header, counter++, false, buf.subarray(0, CHUNK)));
        buf = buf.subarray(CHUNK);
      }
    },
    flush(ctrl) {
      ctrl.enqueue(seal(key, prefix, header, counter++, true, buf));
    },
  });
}

/** v2 backups must be the one the caller expects; v1 ones carry no context and are still read. */
export function decryptStream(key: Buffer, expect: BackupContext, onHeader?: (h: BackupHeader | null) => void): TransformStream<Uint8Array, Uint8Array> {
  let buf = Buffer.alloc(0);
  let prefix: Buffer | null = null;
  let header: Buffer | null = null;
  let version = 0;
  let counter = 0;
  let sawFinal = false;
  return new TransformStream({
    transform(chunk, ctrl) {
      buf = Buffer.concat([buf, chunk]);
      if (!version) {
        if (buf.length < 8) return;
        const magic = buf.subarray(0, 8);
        if (magic.equals(MAGIC1)) version = 1;
        else if (magic.equals(MAGIC2)) version = 2;
        else throw new Error("not a pano backup");
        buf = buf.subarray(8);
      }
      if (version === 2 && !header) {
        if (buf.length < 4) return;
        const n = buf.readUInt32BE(0);
        if (n > MAX_HEADER) throw new Error("corrupt backup (header too large)");
        if (buf.length < 4 + n) return;
        header = Buffer.from(buf.subarray(4, 4 + n));
        buf = buf.subarray(4 + n);
      }
      if (!prefix) {
        if (buf.length < 8) return;
        prefix = Buffer.from(buf.subarray(0, 8));
        buf = buf.subarray(8);
        if (header) {
          let h: BackupHeader;
          try {
            h = JSON.parse(header.toString("utf8"));
          } catch {
            throw new Error("corrupt backup (header)");
          }
          // Early, readable error; the header is proven genuine by the chunk tags (AAD), and
          // decryptToFile releases nothing before the whole file verified.
          if (h.kind !== expect.kind || h.job !== expect.job || h.object !== expect.object) {
            throw new Error(`backup does not belong here (it is ${h.kind}/${h.object}, expected ${expect.kind}/${expect.object})`);
          }
          onHeader?.(h);
        } else onHeader?.(null);
      }
      while (buf.length >= 4) {
        const len = buf.readUInt32BE(0);
        if (len > CHUNK + 16) throw new Error("corrupt backup (chunk too large)");
        if (buf.length < 4 + len) break;
        if (sawFinal) throw new Error("corrupt backup (data after final chunk)");
        const body = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);
        const tag = body.subarray(body.length - 16);
        const ct = body.subarray(0, body.length - 16);
        // Try as non-final first; the final chunk authenticates only with flag=1.
        let plain: Buffer | null = null;
        for (const final of [false, true]) {
          try {
            const d = createDecipheriv("aes-256-gcm", key, nonce(prefix, counter));
            d.setAAD(aad(counter, final, header));
            d.setAuthTag(tag);
            plain = Buffer.concat([d.update(ct), d.final()]);
            sawFinal = final;
            break;
          } catch {}
        }
        if (!plain) throw new Error("backup authentication failed (wrong key or tampered data)");
        counter++;
        if (plain.length) ctrl.enqueue(plain);
      }
    },
    flush() {
      if (!sawFinal || buf.length) throw new Error("backup is truncated");
    },
  });
}

/**
 * Decrypts and gunzips a backup into a new 0600 file. A truncated or tampered backup
 * is only detected at its end, so nothing may read the plain data before this resolves:
 * a database loaded straight from the stream would keep the part before the cut.
 */
export async function decryptToFile(src: ReadableStream<Uint8Array>, key: Buffer, expect: BackupContext, file: string) {
  const plain = src
    .pipeThrough(decryptStream(key, expect))
    .pipeThrough(new DecompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>);
  await pipeline(Readable.fromWeb(plain as any), createWriteStream(file, { mode: 0o600, flags: "wx" }));
}
