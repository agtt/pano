#!/bin/bash
# SQLite in an app's DATA_DIR is backed up consistently while the app keeps writing (after
# dev/vm.sh and dev/vm-e2e.sh; uses the S3 stand-in like dev/vm-e2e-backup.sh). Both engines:
# the backup holds a VACUUM INTO copy instead of the live database + -wal, and a restore puts it in place.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() { R /opt/pano/bin/pano rpc "$1" "${2:-"{}"}"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
cd "$(dirname "$0")/.."
APP=hello-bun
DATA=/srv/pano/apps/$APP/data
BUN=$(R sh -c 'ls /opt/pano/runtimes/bun/*/bun | head -1')
sq() { R "$BUN" -e "const { Database } = require('bun:sqlite'); const db = new Database('$1', { readonly: true }); console.log(db.query(\"$2\").values().flat().join(' '))"; }

step "S3 stand-in"
R install -m 0644 "$PWD/dev/s3-mock.ts" /var/tmp/s3-mock.ts
R systemctl stop pano-s3mock 2>/dev/null || true
R rm -rf /var/tmp/s3mock
R systemd-run --unit=pano-s3mock --collect "$BUN" /var/tmp/s3-mock.ts /var/tmp/s3mock 9000
sleep 1
rpc backup.dest.set '{"dest":"a","endpoint":"http://127.0.0.1:9000","bucket":"store-a","prefix":"pano","accessKeyId":"MOCKKEYMOCKKEY0a","secretAccessKey":"mocksecretmocksecreta"}' >/dev/null
rpc backup.dest.clear '{"dest":"b"}' >/dev/null 2>&1 || true

step "a WAL database the app writes to all the time (never checkpointed)"
R systemctl stop pano-e2e-writer 2>/dev/null || true
R rm -rf "$DATA/shop" "$DATA/.pano-sqlite"
R runuser -u "app-$APP" -- mkdir -p "$DATA/shop"
R tee /var/tmp/writer.ts >/dev/null <<EOF
import { Database } from "bun:sqlite";
const db = new Database("$DATA/shop/app.db");
db.exec("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, body TEXT)");
const ins = db.prepare("INSERT INTO orders (body) VALUES (?)");
for (;;) { db.transaction(() => { for (let i = 0; i < 200; i++) ins.run("x".repeat(500)); })(); await Bun.sleep(5); }
EOF
R chmod 0644 /var/tmp/writer.ts
R systemd-run --unit=pano-e2e-writer --collect -p User="app-$APP" "$BUN" /var/tmp/writer.ts
sleep 3
R ls -la "$DATA/shop"
JOB=$(rpc backup.jobs | jq ".[] | select(.kind == \"app\" and .target == \"$APP\") | .id")
echo "app backup job: $JOB"

for engine in archive restic; do
  step "$engine backup while writing, then restore"
  rpc backup.engine "{\"engine\":\"$engine\"}" >/dev/null
  BEFORE=$(rpc backup.jobs | jq "[.[] | select(.id == $JOB) | .runs[].id] | max // 0")
  rpc backup.job.run "{\"id\":$JOB}" >/dev/null
  for _ in $(seq 180); do
    RUN=$(rpc backup.jobs | jq ".[] | select(.id == $JOB) | .runs[] | select(.id > $BEFORE and .status != \"running\") | .id" | head -1)
    [ -n "$RUN" ] && break
    sleep 1
  done
  rpc backup.jobs | jq -r ".[] | select(.id == $JOB) | .runs[] | select(.id == $RUN) | \"run #\(.id) \(.engine) \(.status) \(.error)\""
  printf 'snapshot dir left in DATA_DIR: '; R test -e "$DATA/.pano-sqlite" && echo yes || echo no
  OUT=$(rpc backup.restore "{\"runId\":$RUN}")
  DIR=${OUT#restored into }
  [ "$engine" = restic ] && DIR="$DIR/srv/pano/apps/$APP"
  R ls -a "$DIR/data/shop"
  printf 'integrity: '; sq "$DIR/data/shop/app.db" "PRAGMA integrity_check"
  printf 'orders: '; sq "$DIR/data/shop/app.db" "SELECT count(*) FROM orders"
  R rm -rf "${OUT#restored into }"
done

step "cleanup"
R systemctl stop pano-e2e-writer
R rm -rf "$DATA/shop"
rpc backup.engine '{"engine":"archive"}' >/dev/null
echo done
