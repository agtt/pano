#!/bin/bash
# Backups in the test VM (after dev/vm.sh) against a local S3 stand-in
# (dev/s3-mock.ts): two destinations at once, full archives, then incremental
# (restic) with small uploads after the first run, retention, restores from the
# second destination, and the weekly prune.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
cd "$(dirname "$0")/.."
DATA=/srv/pano-bk-test

wait_runs() { # job id, number of runs that must have finished
  for _ in $(seq 120); do
    local n
    n=$(rpc backup.jobs | jq "[.[] | select(.id == $1) | .runs[] | select(.status != \"running\")] | length")
    [ "$n" -ge "$2" ] && return 0
    sleep 1
  done
  echo "timeout waiting for runs"; return 1
}
runs() { rpc backup.jobs | jq -r ".[] | select(.id == $1) | .runs[] | \"#\(.id) \(.dest) \(.engine) \(.status) \(.bytes) \(.object_key | split(\"/\") | last) \(.error)\""; }

step "S3 stand-in with two buckets"
BUN=$(R sh -c 'ls /opt/pano/runtimes/bun/*/bun | head -1')
R install -m 0644 "$PWD/dev/s3-mock.ts" /var/tmp/s3-mock.ts
R systemctl stop pano-s3mock 2>/dev/null || true
R rm -rf /var/tmp/s3mock
R systemd-run --unit=pano-s3mock --collect "$BUN" /var/tmp/s3-mock.ts /var/tmp/s3mock 9000
sleep 1
for d in a b; do
  rpc backup.dest.set "{\"dest\":\"$d\",\"endpoint\":\"http://127.0.0.1:9000\",\"bucket\":\"store-$d\",\"prefix\":\"pano\",\"accessKeyId\":\"MOCKKEYMOCKKEY0$d\",\"secretAccessKey\":\"mocksecretmocksecret$d\"}"
  rpc backup.dest.test "{\"dest\":\"$d\"}"
done

step "a directory to back up"
R rm -rf $DATA && R mkdir -p $DATA/uploads
R sh -c "head -c 20000000 /dev/urandom > $DATA/uploads/big.bin; echo v1 > $DATA/note.txt"
for j in $(rpc backup.jobs | jq '.[] | select(.target == "/srv/pano-bk-test") | .id'); do rpc backup.job.remove "{\"id\":$j}"; done
rpc backup.job.add '{"kind":"path","target":"/srv/pano-bk-test","schedule":"manual","keep":3,"name":"bk-test"}' >/dev/null
JOB=$(rpc backup.jobs | jq '.[] | select(.name == "bk-test") | .id')

step "full archives to both destinations"
rpc backup.engine '{"engine":"archive"}'
rpc backup.job.run "{\"id\":$JOB}" >/dev/null
wait_runs "$JOB" 2
runs "$JOB"
R sh -c 'find /var/tmp/s3mock -name "*.enc" | sed "s#/var/tmp/s3mock/##"'

step "incremental (restic): first run uploads everything, the next ones only changes"
rpc backup.engine '{"engine":"restic"}'
R restic version
for i in 1 2 3 4; do
  R sh -c "echo v$i.$RANDOM > $DATA/note.txt"
  rpc backup.job.run "{\"id\":$JOB}" >/dev/null
  wait_runs "$JOB" $((2 + 2 * i))
done
runs "$JOB"
printf 'stored per destination: '; R du -sh /var/tmp/s3mock/store-a /var/tmp/s3mock/store-b | tr '\n' ' '; echo

step "restore the newest restic run from the second destination"
RUN=$(rpc backup.jobs | jq ".[] | select(.id == $JOB) | [.runs[] | select(.dest == \"b\" and .engine == \"restic\" and .status == \"success\")][0].id")
OUT=$(rpc backup.restore "{\"runId\":$RUN}" )
echo "$OUT"
DIR=${OUT#restored into }
R sh -c "cat $DIR$DATA/note.txt; cat $DATA/note.txt; cmp $DIR$DATA/uploads/big.bin $DATA/uploads/big.bin && echo big.bin identical"

step "restore the full archive from the second destination"
RUN=$(rpc backup.jobs | jq ".[] | select(.id == $JOB) | [.runs[] | select(.dest == \"b\" and .engine == \"archive\" and .status == \"success\")][0].id")
OUT=$(rpc backup.restore "{\"runId\":$RUN}" )
DIR=${OUT#restored into }
R sh -c "cmp $DIR/uploads/big.bin $DATA/uploads/big.bin && echo archive big.bin identical"

step "a MariaDB database, incremental"
DB=$(R mariadb -N -e "select schema_name from information_schema.schemata where schema_name not in ('mysql','information_schema','performance_schema','sys') limit 1")
echo "database: $DB"
rpc backup.job.add "{\"kind\":\"mysql\",\"target\":\"$DB\",\"schedule\":\"manual\",\"keep\":5,\"name\":\"bk-db\"}" >/dev/null
DBJOB=$(rpc backup.jobs | jq '.[] | select(.name == "bk-db") | .id')
rpc backup.job.run "{\"id\":$DBJOB}" >/dev/null
wait_runs "$DBJOB" 2
runs "$DBJOB"
RUN=$(rpc backup.jobs | jq ".[] | select(.id == $DBJOB) | .runs[0].id")
rpc backup.restore "{\"runId\":$RUN,\"target\":\"$DB\"}"

step "weekly prune frees forgotten snapshots"
BEFORE=$(R du -s /var/tmp/s3mock/store-a | cut -f1)
rpc backup.prune
sleep 15
printf 'store-a KB: %s -> %s\n' "$BEFORE" "$(R du -s /var/tmp/s3mock/store-a | cut -f1)"
R journalctl -u pano-agent --since "-5min" --no-pager -p warning | tail -5

step "clean up"
rpc backup.job.remove "{\"id\":$JOB}"
rpc backup.job.remove "{\"id\":$DBJOB}"
rpc backup.engine '{"engine":"archive"}'
rpc backup.dest.clear '{"dest":"b"}'
R rm -rf $DATA /var/lib/pano/restore
R systemctl stop pano-s3mock
