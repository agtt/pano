#!/bin/bash
# Disaster recovery between two VMs (after dev/vm.sh and dev/vm-e2e.sh): the
# test VM backs up to two S3 stand-in stores (the second one protected), then a
# brand-new AlmaLinux VM gets only `pano install` and the recovery kit and must
# come back with the same apps, databases, PHP sites and panel login.
#   NEW=pano-dr dev/vm-e2e-recovery.sh
set -euo pipefail
VM=${VM:-pano-test}
NEW=${NEW:-pano-dr}
R() { orb -m "$VM" -u root "$@"; }
N() { orb -m "$NEW" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
nrpc() {
  local params=${2:-}
  N /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
cd "$(dirname "$0")/.."
# The stores live on the Mac (shared into both VMs); each VM runs the stand-in on its own 127.0.0.1:9000.
MOCK=$PWD/dist/s3mock

wait_jobs() { # every run started so far has finished
  for _ in $(seq 600); do
    [ "$(rpc backup.jobs | jq '[.[] | .runs[] | select(.status == "running")] | length')" = 0 ] && return 0
    sleep 1
  done
  echo "timeout waiting for backups"; return 1
}
# what has to be the same on both servers
markers() { # rpc function, machine runner
  local call=$1 on=$2
  printf 'apps: '; $call apps.list | jq -c '[.[] | select(.kind == "managed") | {(.name): .status.active}] | add'
  printf 'bun.test: '; $on curl -sk --resolve bun.test:443:127.0.0.1 https://bun.test/ -w ' %{http_code}' | head -c 80 || true; echo
  printf 'next.test: '; $on curl -sk --resolve next.test:443:127.0.0.1 https://next.test/ -o /dev/null -w '%{http_code}\n' || true
  printf 'php.test: '; $on curl -sk --resolve php.test:443:127.0.0.1 https://php.test/ -w ' %{http_code}' | head -c 80 || true; echo
  printf 'mysql hello_multi tables: '; $on mariadb -N -e "select count(*) from information_schema.tables where table_schema = 'hello_multi'"
  printf 'admins: '; $on sh -c "python3 -c \"import sqlite3; print([r[0] for r in sqlite3.connect('/var/lib/pano/web/web.db').execute('select username from users')])\""
}

step "two stores: a, and b protected (never deleted from)"
BUN=$(R sh -c 'ls /opt/pano/runtimes/bun/*/bun | head -1')
R systemctl stop pano-s3mock 2>/dev/null || true
rm -rf "$MOCK" && mkdir -p "$MOCK"
R cp "$BUN" "$PWD/dist/bun-vm"
R systemd-run --unit=pano-s3mock --collect "$BUN" "$PWD/dev/s3-mock.ts" "$MOCK" 9000
sleep 1
for d in a b; do
  protect=false; [ $d = b ] && protect=true
  rpc backup.dest.set "{\"dest\":\"$d\",\"endpoint\":\"http://127.0.0.1:9000\",\"bucket\":\"store-$d\",\"prefix\":\"pano\",\"accessKeyId\":\"MOCKKEYMOCKKEY0$d\",\"secretAccessKey\":\"mocksecretmocksecret$d\",\"protect\":$protect}"
  rpc backup.dest.test "{\"dest\":\"$d\"}"
done
rpc backup.engine '{"engine":"restic"}'

step "protected store keeps every version (keep 1, three runs)"
R rm -rf /srv/pano-keep && R mkdir -p /srv/pano-keep && R sh -c 'echo x > /srv/pano-keep/f'
for j in $(rpc backup.jobs | jq '.[] | select(.name == "keep-test") | .id'); do rpc backup.job.remove "{\"id\":$j}"; done
rpc backup.job.add '{"kind":"path","target":"/srv/pano-keep","schedule":"manual","keep":1,"name":"keep-test"}' >/dev/null
KJ=$(rpc backup.jobs | jq '.[] | select(.name == "keep-test") | .id')
rpc backup.engine '{"engine":"archive"}'
for i in 1 2 3; do
  rpc backup.job.run "{\"id\":$KJ}" >/dev/null
  wait_jobs
  sleep 1
done
for d in a b; do printf 'store-%s keep-test objects: ' $d; R sh -c "find $MOCK/store-$d -path '*keep-test*' -name '*.enc' | wc -l"; done
rpc backup.jobs | jq -r ".[] | select(.id == $KJ) | .runs[] | \"\(.dest) \(.engine) \(.status)\"" | sort | uniq -c
rpc backup.engine '{"engine":"restic"}'

step "back up everything"
for j in $(rpc backup.jobs | jq '.[] | select(.name != "keep-test") | .id'); do rpc backup.job.run "{\"id\":$j}" >/dev/null; done
wait_jobs
rpc backup.jobs | jq -r '.[] | select(.name != "keep-test") | "\(.name): " + ([.runs[0:2][] | "\(.dest)/\(.engine)/\(.status)\(if .error then " " + .error else "" end)"] | join(", "))'
printf 'security audit: '; rpc system.audit | jq -c '.[] | select(.id == "recovery-kit") | {level, title}'
KIT=$(rpc recovery.kit)
echo "kit: ${KIT:0:24}… (${#KIT} chars)"
printf 'security audit after export: '; rpc system.audit | jq -c '.[] | select(.id == "recovery-kit") | {level, title}'
echo "-- old server"
markers rpc R

step "a brand-new server: $NEW"
orb list | grep -q "^$NEW " || orb create --memory 3G --cpus 4 alma:9 "$NEW"
N dnf -y -q install git tar xz unzip curl procps-ng iproute libatomic python3 openssh-clients >/dev/null
# The test apps deploy from local bare repos; on a real server they come from GitHub.
R tar -C /srv/pano -cf "$PWD/dist/git.tar" git
N mkdir -p /srv/pano
N tar -C /srv/pano -xf "$PWD/dist/git.tar"
rm -f dist/git.tar
ARCH=$(N uname -m)
BIN=dist/pano; [ "$ARCH" = aarch64 ] && BIN=dist/pano-arm64
N install -m 0755 "$PWD/$BIN" /tmp/pano
N /tmp/pano install >/dev/null
N systemctl stop pano-s3mock 2>/dev/null || true
N systemd-run --unit=pano-s3mock --collect "$PWD/dist/bun-vm" "$PWD/dev/s3-mock.ts" "$MOCK" 9000
sleep 1

step "pano recover (kit on stdin)"
time (printf '%s\n' "$KIT" | N /opt/pano/bin/pano recover) || echo "pano recover exited with $?"

step "wait for the app deploys"
for _ in $(seq 300); do
  [ "$(nrpc apps.list | jq '[.[] | select(.kind == "managed" and .status.active != "active")] | length')" = 0 ] && break
  sleep 2
done
echo "-- new server"
markers nrpc N
printf 'restored state on the new server: '; nrpc backup.jobs | jq -c '[.[].name]'
