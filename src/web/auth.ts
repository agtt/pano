// Users, sessions and login throttling for the web UI. Passwords are argon2id,
// every login needs a TOTP code, session ids are stored hashed, and sessions
// expire after 30 idle minutes or 12 hours. The TOTP secret is not here: the
// agent holds it and checks codes, so this process cannot make its own.

import { Database } from "bun:sqlite";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { fsPath, paths } from "../shared/config.ts";
import { call } from "./agent.ts";
import { newSecret } from "./totp.ts";

const IDLE = 30 * 60;
const ABSOLUTE = 12 * 3600;
const MAX_FAILS = 5;
const LOCK_SECONDS = 15 * 60;

let db: Database | null = null;

export function webDb(): Database {
  if (db) return db;
  const file = fsPath(paths.webDb);
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  db = new Database(file, { create: true, strict: true });
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      totp_secret TEXT NOT NULL,
      totp_last INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      csrf TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      seen_at INTEGER NOT NULL,
      ip TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS login_failures (
      key TEXT PRIMARY KEY,
      count INTEGER NOT NULL,
      until INTEGER NOT NULL
    );
  `);
  return db;
}

const now = () => Math.floor(Date.now() / 1000);
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export type User = { id: number; username: string; password_hash: string; totp_secret: string; totp_last: number };
export type Session = { user: User; csrf: string };

export async function createUser(username: string, password: string): Promise<{ secret: string }> {
  if (!/^[a-z][a-z0-9_.-]{2,31}$/.test(username)) throw new Error("username: 3-32 lowercase chars");
  if (password.length < 12) throw new Error("password must be at least 12 characters");
  const hash = await Bun.password.hash(password, { algorithm: "argon2id", memoryCost: 65536, timeCost: 3 });
  // Returned to `pano admin` (root), which hands it to the agent's store; never kept here.
  const secret = newSecret();
  webDb()
    .query("INSERT INTO users (username, password_hash, totp_secret, created_at) VALUES (?, ?, '', ?) ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, totp_secret = '', totp_last = 0")
    .run(username, hash, now());
  // A reset invalidates every existing session of that user.
  const u = webDb().query("SELECT id FROM users WHERE username = ?").get(username) as { id: number };
  webDb().query("DELETE FROM sessions WHERE user_id = ?").run(u.id);
  return { secret };
}

export function userCount(): number {
  return (webDb().query("SELECT COUNT(*) AS n FROM users").get() as { n: number }).n;
}

function locked(key: string): boolean {
  const r = webDb().query("SELECT count, until FROM login_failures WHERE key = ?").get(key) as { count: number; until: number } | null;
  // A user name alone (anyone can type it) locks only after many more failures than one address.
  return !!r && r.count >= (key.startsWith("user:") ? MAX_FAILS * 10 : MAX_FAILS) && r.until > now();
}

function fail(key: string) {
  webDb()
    .query(
      `INSERT INTO login_failures (key, count, until) VALUES (?, 1, ?)
       ON CONFLICT(key) DO UPDATE SET count = CASE WHEN until < ? THEN 1 ELSE count + 1 END, until = ?`,
    )
    .run(key, now() + LOCK_SECONDS, now(), now() + LOCK_SECONDS);
}

// Verifying against a dummy hash keeps response time the same for unknown users.
let dummyHash: string | null = null;

export async function login(username: string, password: string, otp: string, ip: string): Promise<{ sid: string } | { error: string }> {
  const keys = [`ip:${ip}`, `user:${username.toLowerCase()}`];
  if (keys.some(locked)) return { error: "Too many attempts. Try again in 15 minutes." };
  const user = webDb().query("SELECT * FROM users WHERE username = ?").get(username.toLowerCase()) as User | null;
  dummyHash ??= await Bun.password.hash(randomBytes(16).toString("hex"), { algorithm: "argon2id", memoryCost: 65536, timeCost: 3 });
  const passOk = await Bun.password.verify(password, user?.password_hash ?? dummyHash);
  const codeOk = user && passOk ? await call<boolean>("auth.otp", { username: user.username, code: otp }).catch(() => false) : false;
  if (!user || !passOk || !codeOk) {
    keys.forEach(fail);
    return { error: "Invalid username, password or code." };
  }
  keys.forEach((k) => webDb().query("DELETE FROM login_failures WHERE key = ?").run(k));
  const sid = randomBytes(32).toString("base64url");
  webDb()
    .query("INSERT INTO sessions (id_hash, user_id, csrf, created_at, seen_at, ip) VALUES (?, ?, ?, ?, ?, ?)")
    .run(sha(sid), user.id, randomBytes(24).toString("base64url"), now(), now(), ip);
  return { sid };
}

export function session(sid: string | undefined): Session | null {
  if (!sid) return null;
  const row = webDb().query("SELECT * FROM sessions WHERE id_hash = ?").get(sha(sid)) as
    | { id_hash: string; user_id: number; csrf: string; created_at: number; seen_at: number }
    | null;
  if (!row) return null;
  const t = now();
  if (t - row.seen_at > IDLE || t - row.created_at > ABSOLUTE) {
    webDb().query("DELETE FROM sessions WHERE id_hash = ?").run(row.id_hash);
    return null;
  }
  if (t - row.seen_at > 30) webDb().query("UPDATE sessions SET seen_at = ? WHERE id_hash = ?").run(t, row.id_hash);
  const user = webDb().query("SELECT * FROM users WHERE id = ?").get(row.user_id) as User | null;
  return user ? { user, csrf: row.csrf } : null;
}

export function logout(sid: string | undefined) {
  if (sid) webDb().query("DELETE FROM sessions WHERE id_hash = ?").run(sha(sid));
}

export function csrfOk(s: Session, token: unknown): boolean {
  const a = Buffer.from(s.csrf);
  const b = Buffer.from(String(token ?? ""));
  return a.length === b.length && timingSafeEqual(a, b);
}

export function pruneSessions() {
  const t = now();
  webDb().query("DELETE FROM sessions WHERE seen_at < ? OR created_at < ?").run(t - IDLE, t - ABSOLUTE);
  webDb().query("DELETE FROM login_failures WHERE until < ?").run(t);
}
