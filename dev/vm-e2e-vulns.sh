#!/bin/bash
# Vulnerability check and automatic patching in the test VM (after dev/vm.sh):
# a Node app with an old Next.js lockfile, a scan against OSV.dev, distro
# advisories, nodejs.org and php.net, then dnf-automatic switched on.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "automatic patching on (OS, PHP, edge)"
rpc vulns.patch '{"os":true,"php":true,"edge":true}'
R systemctl is-enabled dnf-automatic.timer
R grep -E '^(upgrade_type|apply_updates|reboot) ' /etc/dnf/automatic.conf

step "scan"
rpc vulns.scan >/dev/null
for _ in $(seq 1 60); do
  if rpc vulns.status | grep -q '"scanning":false'; then break; fi
  sleep 3
done
rpc vulns.status | python3 -c '
import json, sys
v = json.load(sys.stdin)
last = v["last"]
print("packages", last["packages"], "findings", len(last["findings"]), "errors", last["errors"], "reboot", v["rebootNeeded"])
for f in last["findings"][:15]:
    print(f["severity"], f["where"], f["name"], f["version"], "->", f["fixed"], f["id"], f["aliases"][:1])
'
