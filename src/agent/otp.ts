// Authenticator (TOTP) secrets live with the agent, root-only, never in the web
// process. The web UI can ask "is this code right?" but cannot produce codes, so
// even a fully compromised pano-web cannot read secrets, drop databases, add a
// VPN device or change what an app runs on its own: those operations need a code
// sent with that very call, which the agent checks itself (no trusted window, no
// grant). The code still travels through the web, so a compromised web can spend
// a code the admin types on one always-ask action of its choosing.

import { Database } from "bun:sqlite";
import { createHash, randomBytes } from "node:crypto";
import { fsPath, paths } from "../shared/config.ts";
import { checkRemove, checkUsername } from "../shared/admins.ts";
import { newSecret, otpauthUri, verify } from "../web/totp.ts";
import { audit, settings, state } from "./state.ts";
import { ensureDir, exists, readText, run, writeAtomic } from "./sys.ts";

const MAX_FAILS = 5;
const LOCK_SECONDS = 15 * 60;
const GRANT_SECONDS = 60;
/** Retries of the same call; a grant is not a session. */
const GRANT_USES = 10;
const CLI_TOKEN = `${paths.secrets}/cli.token`;

type Admin = { username: string; totp_secret: string; totp_last: number; fails: number; locked_until: number };

function table() {
  state().exec(`CREATE TABLE IF NOT EXISTS admins (
    username TEXT PRIMARY KEY,
    totp_secret TEXT NOT NULL,
    totp_last INTEGER NOT NULL DEFAULT 0,
    fails INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0
  )`);
}

const now = () => Math.floor(Date.now() / 1000);

/** Called by `pano admin` (root). Resets the code counter and any lockout. */
export function setAdminSecret(username: string, secret: string) {
  table();
  state()
    .query("INSERT INTO admins (username, totp_secret) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET totp_secret = excluded.totp_secret, totp_last = 0, fails = 0, locked_until = 0")
    .run(username, secret);
}

/** One use per code; five wrong codes lock the user for 15 minutes (the web cannot brute-force through the agent). */
export function checkOtp(username: string, code: unknown): boolean {
  table();
  const a = state().query("SELECT * FROM admins WHERE username = ?").get(username) as Admin | null;
  if (!a || a.locked_until > now()) return false;
  const step = verify(a.totp_secret, String(code ?? ""), a.totp_last);
  if (step === null) {
    const fails = a.fails + 1;
    state().query("UPDATE admins SET fails = ?, locked_until = ? WHERE username = ?").run(fails >= MAX_FAILS ? 0 : fails, fails >= MAX_FAILS ? now() + LOCK_SECONDS : 0, username);
    return false;
  }
  state().query("UPDATE admins SET totp_last = ?, fails = 0 WHERE username = ?").run(step, username);
  return true;
}

// A verified code yields a short grant so the same form can repeat its call (a retry). It is bound
// to the admin, the method and the exact params the code was checked for, and main.ts never
// accepts one for an always-ask method: a code typed for one action cannot be spent on another.
const grants = new Map<string, { actor: string; scope: string; until: number; uses: number }>();

/** What a grant covers: one method with exactly these params. */
const grantScope = (method: string, params: unknown) => createHash("sha256").update(`${method}\n${JSON.stringify(params ?? {})}`).digest("base64url");

export function issueGrant(actor: string, method = "", params: unknown = {}): string {
  const g = randomBytes(24).toString("base64url");
  grants.set(g, { actor, scope: grantScope(method, params), until: Date.now() + GRANT_SECONDS * 1000, uses: GRANT_USES });
  for (const [k, v] of grants) if (v.until < Date.now()) grants.delete(k);
  return g;
}

/**
 * After a verified code (sign-in or any guarded action), the session is trusted for a while:
 * routine guarded actions go through without a new code. Revealing secrets, changing what runs,
 * opening the network, deleting, restoring and managing admins still ask every time
 * (FRESH_ONLY / alwaysAsk in rpc.ts).
 */
export const TRUST_SECONDS = 15 * 60;
const trusts = new Map<string, { actor: string; until: number }>();

export function issueTrust(actor: string): string {
  const tk = randomBytes(24).toString("base64url");
  trusts.set(tk, { actor, until: Date.now() + TRUST_SECONDS * 1000 });
  for (const [k, v] of trusts) if (v.until < Date.now()) trusts.delete(k);
  return tk;
}

export const trustValid = (tk: unknown, actor: string) => {
  const v = typeof tk === "string" ? trusts.get(tk) : undefined;
  return !!v && v.actor === actor && v.until > Date.now();
};

export const endTrust = (tk: unknown) => {
  if (typeof tk === "string") trusts.delete(tk);
};

/** Spends one use of the grant; only for the method and params it was issued for. */
export const grantValid = (grant: unknown, actor: string, method = "", params: unknown = {}) => {
  const g = typeof grant === "string" ? grants.get(grant) : undefined;
  if (!g || g.actor !== actor || g.until <= Date.now() || g.uses <= 0 || g.scope !== grantScope(method, params)) return false;
  g.uses--;
  return true;
};

// ---- managing admins from the panel. The web keeps the password hashes; the
// secrets stay here and leave only once, in the reply to add / reset 2FA.

/** Everyone who can sign in (has a 2FA secret here). Names only. */
export function adminNames(): string[] {
  table();
  return (state().query("SELECT username FROM admins ORDER BY username").all() as { username: string }[]).map((r) => r.username);
}

export type NewAdmin = { username: string; secret: string; uri: string; qr: string };

/** The secret, its otpauth link and (if qrencode is installed) a QR image, to be shown once. */
async function enrollment(username: string, secret: string): Promise<NewAdmin> {
  const uri = otpauthUri(secret, username);
  let qr = "";
  try {
    const r = await run(["qrencode", "-t", "SVG", "-o", "-"], { input: uri, check: false });
    if (r.code === 0 && r.stdout) qr = `data:image/svg+xml;base64,${Buffer.from(r.stdout).toString("base64")}`;
  } catch {}
  return { username, secret, uri, qr };
}

export async function addAdmin(actor: string, username: string): Promise<NewAdmin> {
  checkUsername(username);
  if (adminNames().includes(username)) throw new Error("that admin already exists");
  const secret = newSecret();
  setAdminSecret(username, secret);
  audit(actor, "admins.add", { username });
  return enrollment(username, secret);
}

export function removeAdmin(actor: string, username: string) {
  checkRemove(actor, username, adminNames());
  state().query("DELETE FROM admins WHERE username = ?").run(username);
  for (const [k, g] of grants) if (g.actor === username) grants.delete(k);
  for (const [k, v] of trusts) if (v.actor === username) trusts.delete(k);
  audit(actor, "admins.remove", { username });
}

/** New secret (old codes stop working), or with `twofa` false only the audit of a password reset the web carries out. */
export async function resetAdmin(actor: string, username: string, twofa: boolean): Promise<NewAdmin | null> {
  if (!adminNames().includes(username)) throw new Error("no such admin");
  audit(actor, "admins.reset", { username, what: twofa ? "2fa" : "password" });
  if (!twofa) return null;
  const secret = newSecret();
  setAdminSecret(username, secret);
  return enrollment(username, secret);
}

/** Root's `pano rpc` proves itself with a root-only token instead of a code. */
export async function cliToken(): Promise<string> {
  let t = ((await readText(CLI_TOKEN)) ?? "").trim();
  if (!t) {
    t = randomBytes(32).toString("base64url");
    await ensureDir(paths.secrets, 0o700);
    await writeAtomic(CLI_TOKEN, t + "\n", 0o600);
  }
  return t;
}

/**
 * Older installs kept the secrets in the web database; move them here and blank them there. Once,
 * on an install that has no admin here yet: the web database belongs to the web process, so reading
 * secrets from it later would let a compromised web plant a secret it knows (or a new admin) and
 * pass every 2FA check after the next agent restart.
 */
export async function migrateFromWeb() {
  table();
  if (settings.get("otp.migrated") === "1") return;
  const has = state().query("SELECT 1 FROM admins LIMIT 1").get();
  settings.set("otp.migrated", "1");
  if (has || !(await exists(paths.webDb))) return;
  const web = new Database(fsPath(paths.webDb));
  try {
    const rows = web.query("SELECT username, totp_secret FROM users WHERE totp_secret <> ''").all() as { username: string; totp_secret: string }[];
    for (const r of rows) {
      state().query("INSERT INTO admins (username, totp_secret) VALUES (?, ?) ON CONFLICT(username) DO NOTHING").run(r.username, r.totp_secret);
      web.query("UPDATE users SET totp_secret = '' WHERE username = ?").run(r.username);
    }
  } finally {
    web.close();
  }
}
