// Streaming AES-256-GCM for backups. Backups are encrypted on the server before
// they leave it, so the bucket (R2) only ever stores ciphertext.
//
// Format: "PANOBK1\n" | 8-byte random nonce prefix | chunks
// chunk:  u32 BE ciphertext length | ciphertext+16-byte tag
// nonce = prefix || u32 BE counter; AAD = u32 BE counter || final flag byte.
// The final flag makes truncation (dropping trailing chunks) detectable.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const MAGIC = new TextEncoder().encode("PANOBK1\n");
const CHUNK = 4 * 1024 * 1024;

function aad(counter: number, final: boolean) {
  const b = Buffer.alloc(5);
  b.writeUInt32BE(counter, 0);
  b[4] = final ? 1 : 0;
  return b;
}

function nonce(prefix: Buffer, counter: number) {
  const n = Buffer.alloc(12);
  prefix.copy(n, 0);
  n.writeUInt32BE(counter, 8);
  return n;
}

function seal(key: Buffer, prefix: Buffer, counter: number, final: boolean, plain: Uint8Array): Uint8Array {
  const c = createCipheriv("aes-256-gcm", key, nonce(prefix, counter));
  c.setAAD(aad(counter, final));
  const body = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  const out = Buffer.alloc(4 + body.length);
  out.writeUInt32BE(body.length, 0);
  body.copy(out, 4);
  return out;
}

export function encryptStream(key: Buffer): TransformStream<Uint8Array, Uint8Array> {
  if (key.length !== 32) throw new Error("backup key must be 32 bytes");
  const prefix = randomBytes(8);
  let counter = 0;
  let buf = Buffer.alloc(0);
  return new TransformStream({
    start(ctrl) {
      ctrl.enqueue(Buffer.concat([MAGIC, prefix]));
    },
    transform(chunk, ctrl) {
      buf = Buffer.concat([buf, chunk]);
      // Keep at least one byte back so the last chunk is always sealed as final.
      while (buf.length > CHUNK) {
        ctrl.enqueue(seal(key, prefix, counter++, false, buf.subarray(0, CHUNK)));
        buf = buf.subarray(CHUNK);
      }
    },
    flush(ctrl) {
      ctrl.enqueue(seal(key, prefix, counter++, true, buf));
    },
  });
}

export function decryptStream(key: Buffer): TransformStream<Uint8Array, Uint8Array> {
  let buf = Buffer.alloc(0);
  let prefix: Buffer | null = null;
  let counter = 0;
  let sawFinal = false;
  return new TransformStream({
    transform(chunk, ctrl) {
      buf = Buffer.concat([buf, chunk]);
      if (!prefix) {
        if (buf.length < 16) return;
        if (!buf.subarray(0, 8).equals(Buffer.from(MAGIC))) throw new Error("not a pano backup");
        prefix = Buffer.from(buf.subarray(8, 16));
        buf = buf.subarray(16);
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
            d.setAAD(aad(counter, final));
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
