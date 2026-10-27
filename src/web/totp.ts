// RFC 6238 TOTP (SHA-1, 30 s, 6 digits): works with every authenticator app.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function newSecret(): string {
  const bytes = randomBytes(20);
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

function decode(secret: string): Buffer {
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error("bad base32");
    bits += i.toString(2).padStart(5, "0");
  }
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

export function code(secret: string, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", decode(secret)).update(msg).digest();
  const off = h[h.length - 1]! & 0xf;
  const n = (h.readUInt32BE(off) & 0x7fffffff) % 1_000_000;
  return n.toString().padStart(6, "0");
}

/**
 * Returns the matched time step (to block replays) or null. Accepts one step
 * of clock drift either way.
 */
export function verify(secret: string, input: string, lastUsed: number, now = Date.now()): number | null {
  const token = input.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(token)) return null;
  const step = Math.floor(now / 30_000);
  for (const s of [step - 1, step, step + 1]) {
    if (s <= lastUsed) continue;
    const a = Buffer.from(code(secret, s));
    if (timingSafeEqual(a, Buffer.from(token))) return s;
  }
  return null;
}

export function otpauthUri(secret: string, user: string, issuer = "pano"): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
