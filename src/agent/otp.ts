// Authenticator (TOTP) secrets live with the agent, root-only, never in the web
// process. The web UI can ask "is this code right?" but cannot produce codes, so
// even a fully compromised pano-web cannot read secrets, drop databases, add a
// VPN device or change what an app runs: those operations need a fresh code,
// which the agent checks itself.

import { Database } from "bun:sqlite";
import { randomBytes } from "node:crypto";
import { fsPath, paths } from "../shared/config.ts";
import { verify } from "../web/totp.ts";
import { state } from "./state.ts";
import { ensureDir, exists, readText, writeAtomic } from "./sys.ts";

const MAX_FAILS = 5;
const LOCK_SECONDS = 15 * 60;
const GRANT_SECONDS = 120;
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

// A verified code yields a short grant so one form post can make several calls.
const grants = new Map<string, { actor: string; until: number }>();

export function issueGrant(actor: string): string {
  const g = randomBytes(24).toString("base64url");
  grants.set(g, { actor, until: Date.now() + GRANT_SECONDS * 1000 });
  for (const [k, v] of grants) if (v.until < Date.now()) grants.delete(k);
  return g;
}

export const grantValid = (grant: unknown, actor: string) => {
  const g = typeof grant === "string" ? grants.get(grant) : undefined;
  return !!g && g.actor === actor && g.until > Date.now();
};

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

/** Older installs kept the secrets in the web database; move them here and blank them there. */
export async function migrateFromWeb() {
  if (!(await exists(paths.webDb))) return;
  const web = new Database(fsPath(paths.webDb));
  try {
    const rows = web.query("SELECT username, totp_secret FROM users WHERE totp_secret <> ''").all() as { username: string; totp_secret: string }[];
    for (const r of rows) {
      table();
      state().query("INSERT INTO admins (username, totp_secret) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET totp_secret = excluded.totp_secret").run(r.username, r.totp_secret);
      web.query("UPDATE users SET totp_secret = '' WHERE username = ?").run(r.username);
    }
  } finally {
    web.close();
  }
}
