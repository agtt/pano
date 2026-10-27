#!/bin/bash
# TURN in the test VM (after dev/vm.sh): install, the locked-down unit, a STUN
# binding, an allocation with a short-lived credential, a relay to this host
# refused, the secret rotated, uninstall.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "install"
rpc turn.uninstall '{"confirm":"turn"}' >/dev/null 2>&1 || true
rpc turn.install
rpc turn.status
R systemctl show coturn -p CPUWeight -p MemoryMax
R sh -c 'grep -E "NoNewPrivs|Seccomp:" /proc/$(systemctl show -p MainPID --value coturn)/status'
R dnf -y -q install coturn-utils >/dev/null
IP=$(R sh -c "ip -4 route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p'")

step "STUN binding"
R turnutils_stunclient "$IP" | grep -i "UDP reflexive addr"

step "allocation with a short-lived credential; relaying to this host is refused"
SECRET=$(rpc turn.reveal | tr -d '"')
OUT=$(R turnutils_uclient -W "$SECRET" -u alice -n 1 -m 1 -e "$IP" -r 22 -y "$IP" 2>&1 || true)
echo "$OUT" | grep -E "allocate sent|success|403|Forbidden" | head -5
echo "$OUT" | grep -qE "403|Forbidden" && echo "peer refused: ok"
BAD=$(R turnutils_uclient -W wrong-secret -u alice -n 1 -m 1 -y "$IP" 2>&1 || true)
echo "$BAD" | grep -qiE "401|Unauthorized|error" && echo "wrong secret refused: ok"

step "rotate"
rpc turn.rotate
NEW=$(rpc turn.reveal | tr -d '"')
[ "$NEW" != "$SECRET" ] && echo "secret changed: ok"
R systemctl is-active coturn

step "uninstall"
rpc turn.uninstall '{"confirm":"turn"}'
R rpm -q coturn || echo "removed: ok"
