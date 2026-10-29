// SQLite in an app's DATA_DIR. Copied file by file while the app writes, a database can come
// out torn (the main file and its -wal from different moments). Before an app backup each
// database gets a consistent copy (VACUUM INTO, made as the app's own user, waiting for writers),
// and the backup holds that copy instead of the live files. Restoring puts the copies in place.

import { Database } from "bun:sqlite";
import { mkdirSync, rmSync } from "node:fs";
import { open, readdir, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fsPath, paths } from "../shared/config.ts";
import { appHome, appUser } from "./apps.ts";
import { remove, run } from "./sys.ts";

/** Inside DATA_DIR, only while a backup runs (and in a restored copy until it is put in place). */
export const SNAP_DIR = ".pano-sqlite";
const MAGIC = Buffer.from("SQLite format 3\0");
const SKIP = new Set([SNAP_DIR, "node_modules", ".git"]);

/** A database and the files SQLite keeps next to it while it is open. */
export const liveFiles = (rel: string) => [rel, `${rel}-wal`, `${rel}-shm`, `${rel}-journal`];

/** SQLite databases under a directory (recognised by their header), as relative paths; symlinks are not followed. */
export async function findSqlite(dir: string, depth = 4): Promise<string[]> {
  const out: string[] = [];
  const walk = async (rel: string, left: number) => {
    const entries = await readdir(join(fsPath(dir), rel), { withFileTypes: true }).catch(() => []);
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory() && left > 0 && !SKIP.has(e.name)) await walk(r, left - 1);
      else if (e.isFile() && !/-(wal|shm|journal)$/.test(e.name) && (await isSqlite(join(fsPath(dir), r)))) out.push(r);
    }
  };
  await walk("", depth);
  return out.sort();
}

async function isSqlite(file: string): Promise<boolean> {
  const f = await open(file, "r").catch(() => null);
  if (!f) return false;
  try {
    const buf = Buffer.alloc(MAGIC.length);
    const { bytesRead } = await f.read(buf, 0, buf.length, 0);
    return bytesRead === MAGIC.length && buf.equals(MAGIC);
  } finally {
    await f.close();
  }
}

/**
 * Consistent copies of an app's databases in DATA_DIR/.pano-sqlite, made by `pano sqlite-snapshot`
 * as the app's user (root never opens the app's files with SQLite, which could leave root-owned
 * -wal/-shm files behind). Returns the databases that were copied; any other stays a plain file in the backup.
 */
export async function snapshotApp(app: string): Promise<string[]> {
  const data = `${appHome(app)}/data`;
  await remove(`${data}/${SNAP_DIR}`);
  const done: string[] = [];
  for (const rel of await findSqlite(data)) {
    const r = await run([`${paths.bin}/pano`, "sqlite-snapshot", fsPath(`${data}/${rel}`), fsPath(`${data}/${SNAP_DIR}/${rel}`)], {
      user: appUser(app),
      cwd: "/",
      check: false,
      timeoutMs: 600_000,
    });
    if (r.code === 0) done.push(rel);
    else console.error(`[backup] ${app}: no consistent copy of ${rel}: ${r.stderr.trim().split("\n").at(-1)}`);
  }
  return done;
}

export const dropSnapshots = (app: string) => remove(`${appHome(app)}/data/${SNAP_DIR}`);

/** `pano sqlite-snapshot <db> <copy>`: run as the app's user. Waits up to 30 s for a writer. */
export function vacuumInto(src: string, dst: string) {
  mkdirSync(dirname(dst), { recursive: true, mode: 0o700 });
  rmSync(dst, { force: true });
  const db = new Database(src, { readonly: true });
  try {
    db.exec("PRAGMA busy_timeout = 30000");
    db.exec(`VACUUM INTO '${dst.replace(/'/g, "''")}'`);
  } finally {
    db.close();
  }
}

/** A restored DATA_DIR: each copy replaces its database (whose -wal/-shm would belong to the old file). */
export async function placeSnapshots(dataDir: string) {
  const snaps = join(fsPath(dataDir), SNAP_DIR);
  for (const rel of await findSqlite(`${dataDir}/${SNAP_DIR}`, 8)) {
    const target = join(fsPath(dataDir), rel);
    for (const f of liveFiles(rel).slice(1)) rmSync(join(fsPath(dataDir), f), { force: true });
    mkdirSync(dirname(target), { recursive: true });
    await rename(join(snaps, rel), target);
  }
  rmSync(snaps, { recursive: true, force: true });
}
