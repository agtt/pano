#!/bin/bash
# Optional containers in the test VM (after dev/vm.sh, edge cut over): enable
# Podman, run nginx behind the edge on a domain and Redis from its template,
# check isolation (localhost-only port, user namespace), then remove both.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "reset"
for c in web1 cache; do rpc containers.delete "{\"name\":\"$c\",\"confirm\":\"$c\",\"removeData\":true}" >/dev/null 2>&1 || true; done

step "enable containers (installs Podman on first use)"
rpc containers.status | jq -c '{installed}'
time rpc containers.install
R podman --version

step "nginx on a domain, through the edge"
rpc containers.save '{"name":"web1","image":"nginx:alpine","port":80,"domains":"ct.test","memory_mb":128}' | jq -c '{name, image, host_port}'
printf 'https://ct.test     %s\n' "$(R curl -sk --max-time 10 --resolve ct.test:443:127.0.0.1 https://ct.test/ | grep -o '<title>[^<]*' | head -1)"
R ss -Htln 'sport = :5100'

step "redis from the template (password generated)"
rpc containers.save '{"name":"cache","image":"docker.io/library/redis:7-alpine","port":6379,"volumes":"/data","memory_mb":128}' | jq -c '{name, host_port}'
sleep 3
printf 'redis ping          %s\n' "$(R podman exec pano-cache redis-cli ping)"
printf 'uid outside (root inside): %s\n' "$(R podman top pano-cache huser user | tail -1)"
R ls -ln /srv/pano/containers/cache/

step "memory"
R systemctl show pano-ct-web1 pano-ct-cache --property=Id,MemoryCurrent | paste - - - | awk '{printf "%-28s %s\n", $1, $2}'

step "delete"
for c in web1 cache; do rpc containers.delete "{\"name\":\"$c\",\"confirm\":\"$c\",\"removeData\":true}"; done
rpc containers.list | jq -c 'length'
printf 'ct.test after delete %s\n' "$(R curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --resolve ct.test:443:127.0.0.1 https://ct.test/ || true)"
