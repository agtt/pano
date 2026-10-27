// Prints the current TOTP code of a dev user (default: admin).
import { Database } from "bun:sqlite";
import { join } from "node:path";
import { code } from "../src/web/totp.ts";

const user = process.argv[2] ?? "admin";
const db = new Database(join(import.meta.dir, "root/var/lib/pano/web/web.db"), { readonly: true });
const row = db.query("SELECT totp_secret FROM users WHERE username = ?").get(user) as { totp_secret: string } | null;
if (!row) throw new Error(`no user ${user}`);
const step = Math.floor(Date.now() / 30_000);
console.log(`now ${code(row.totp_secret, step)}  next ${code(row.totp_secret, step + 1)}`);
