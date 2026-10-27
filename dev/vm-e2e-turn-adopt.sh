#!/bin/bash
# Taking over an existing coturn (as on CyberPanel servers): its secret is kept
# and uninstall gives it its own config back.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
R dnf -y -q install coturn >/dev/null
R sh -c 'printf "listening-port=3478\nuse-auth-secret\nstatic-auth-secret=oldsecret123\nrealm=old\n" > /etc/coturn/turnserver.conf && systemctl restart coturn'
rpc turn.install
[ "$(rpc turn.reveal | tr -d '"')" = oldsecret123 ] && echo "secret kept: ok"
rpc turn.uninstall '{"confirm":"turn"}'
R grep -q "realm=old" /etc/coturn/turnserver.conf && echo "original config back: ok"
R systemctl is-active coturn
R dnf -y -q remove coturn >/dev/null
