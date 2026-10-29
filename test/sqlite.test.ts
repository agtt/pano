import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { fsPath } from "../src/shared/config.ts";
import { findSqlite, liveFiles, placeSnapshots, SNAP_DIR, vacuumInto } from "../src/agent/sqlite.ts";

test("SQLite in DATA_DIR: found by header, copied consistently, put back on restore", async () => {
  const data = "/srv/sqlite-test/data";
  const root = fsPath(data);
  mkdirSync(`${root}/sub`, { recursive: true });
  // A WAL database with a write still in the -wal file (not checkpointed).
  const db = new Database(`${root}/app.db`);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; CREATE TABLE t (x); INSERT INTO t VALUES (1), (2);");
  new Database(`${root}/sub/cache.sqlite`).exec("CREATE TABLE c (y)");
  writeFileSync(`${root}/notes.db`, "not a database");
  mkdirSync(`${root}/node_modules`, { recursive: true });
  new Database(`${root}/node_modules/dep.db`).exec("CREATE TABLE d (z)");

  expect(await findSqlite(data)).toEqual(["app.db", "sub/cache.sqlite"]);
  expect(existsSync(`${root}/app.db-wal`)).toBe(true);

  vacuumInto(`${root}/app.db`, `${root}/${SNAP_DIR}/app.db`);
  vacuumInto(`${root}/sub/cache.sqlite`, `${root}/${SNAP_DIR}/sub/cache.sqlite`);
  db.exec("INSERT INTO t VALUES (3)"); // written after the copy: not in it
  db.close();
  // The copy is one self-contained file: no -wal needed.
  const copy = new Database(`${root}/${SNAP_DIR}/app.db`, { readonly: true });
  expect(copy.query("SELECT count(*) AS n FROM t").get()).toEqual({ n: 2 });
  copy.close();
  expect(await findSqlite(data)).toEqual(["app.db", "sub/cache.sqlite"]); // the snapshot dir is not scanned

  // Restore: the copies replace the databases, stale -wal/-shm go.
  writeFileSync(`${root}/app.db-wal`, "stale");
  await placeSnapshots(data);
  expect(existsSync(`${root}/${SNAP_DIR}`)).toBe(false);
  expect(existsSync(`${root}/app.db-wal`)).toBe(false);
  const restored = new Database(`${root}/app.db`, { readonly: true });
  expect(restored.query("SELECT count(*) AS n FROM t").get()).toEqual({ n: 2 });
  restored.close();
  expect(liveFiles("a.db")).toEqual(["a.db", "a.db-wal", "a.db-shm", "a.db-journal"]);
});
