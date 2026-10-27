#!/bin/bash
# Realtime in the test VM (after dev/vm.sh): install from the GitHub release
# (checksum checked), an app, a signed API call, the locked-down unit, uninstall.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "install"
rpc realtime.uninstall '{"confirm":"realtime"}' >/dev/null 2>&1 || true
rpc realtime.install
rpc realtime.app.add '{"name":"shop","origins":"https://shop.example.com"}'
rpc realtime.status | grep -E '"(version|active|memory)"'
R sh -c 'grep -E "NoNewPrivs|Seccomp:" /proc/$(systemctl show -p MainPID --value pano-realtime)/status'
R du -sh /opt/pano/realtime

step "health and a signed API call"
R curl -sf http://127.0.0.1:6001/up && echo " /up ok"
rpc realtime.check

step "uninstall"
rpc realtime.uninstall '{"confirm":"realtime"}'
R test ! -e /opt/pano/realtime && echo "removed: ok"
