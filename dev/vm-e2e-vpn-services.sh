#!/bin/bash
# Private access, database/cache servers and GitLab webhooks in the test VM
# (after dev/vm.sh). A network namespace plays the remote laptop: it reaches the
# server over a veth "internet" link and over WireGuard, so locks can be checked
# from both sides, including the automatic undo of an unconfirmed lock.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
NS() { R ip netns exec wgc "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
code() { NS curl -s -o /dev/null -w '%{http_code}' --max-time 4 "$1" || true; }

step "reset"
rpc vpn.disable >/dev/null 2>&1 || true
R ip netns del wgc 2>/dev/null || true
R ip link del vpn-h 2>/dev/null || true
R systemctl stop pano-e2e-8888 2>/dev/null || true

step "enable private access"
time rpc vpn.enable '{"port":51820,"endpoint":"192.168.77.1"}'
rpc vpn.status | jq -c '{installed, enabled, running, address, port}'
R wg show pano0 | head -3

step "a laptop in a network namespace"
R ip netns add wgc
R ip link add vpn-h type veth peer name vpn-c
R ip link set vpn-c netns wgc
R ip addr add 192.168.77.1/24 dev vpn-h
# NetworkManager would otherwise try DHCP on the new link and drop its address after a while.
R nmcli device set vpn-h managed no 2>/dev/null || true
R ip link set vpn-h up
NS ip addr add 192.168.77.2/24 dev vpn-c
NS ip link set vpn-c up
NS ip link set lo up
R sh -c 'umask 077; wg genkey > /root/wgc.key'
PUB=$(R sh -c 'wg pubkey < /root/wgc.key')
ADD=$(rpc vpn.peer.add "{\"name\":\"laptop\",\"publicKey\":\"$PUB\"}")
echo "$ADD" | jq -c '{name, ip, generated, qr: (.qr | length)}'
PSK=$(echo "$ADD" | jq -r .config | awk '/PresharedKey/ {print $3}')
SPUB=$(rpc vpn.status | jq -r .publicKey)
R sh -c "echo $PSK > /root/wgc.psk"
NS ip link add wg0 type wireguard
NS wg set wg0 private-key /root/wgc.key peer "$SPUB" preshared-key /root/wgc.psk endpoint 192.168.77.1:51820 allowed-ips 10.77.0.1/32 persistent-keepalive 25
CIP=$(echo "$ADD" | jq -r .ip) # the address the server gave this peer
NS ip addr add "$CIP/32" dev wg0
NS ip link set wg0 up
NS ip route add 10.77.0.1/32 dev wg0
NS ping -c 2 -W 2 10.77.0.1 | tail -2
rpc vpn.status | jq -c '.peers[] | {name, ip, handshake: (.handshake > 0)}'

step "phone: keys generated on the server, shown once"
rpc vpn.peer.add '{"name":"phone"}' | jq -c '{ip, generated, hasPrivateKey: (.config | test("PrivateKey = [A-Za-z0-9+/]{43}=")), qr: (.qr | startswith("data:image/svg+xml"))}'

step "a service on 8888 (an admin port), reachable before locking"
R systemd-run --quiet --unit=pano-e2e-8888 --working-directory=/tmp python3 -m http.server 8888 --bind 0.0.0.0
sleep 1
printf 'internet  8888: %s\n' "$(code http://192.168.77.1:8888/)"
printf 'wireguard 8888: %s\n' "$(code http://10.77.0.1:8888/)"

step "lock admin ports + panel over WireGuard, not confirmed: undone after 30s"
rpc vpn.locks '{"panel":true,"ssh":false,"services":true,"confirmSeconds":30}'
sleep 4
printf 'internet  8888: %s (locked: 000)\n' "$(code http://192.168.77.1:8888/)"
printf 'wireguard 8888: %s\n' "$(code http://10.77.0.1:8888/)"
printf 'panel over wg : %s\n' "$(code http://10.77.0.1:7800/login)"
rpc vpn.confirm '{"remote":"192.168.77.2"}' 2>&1 | tail -1 || true
echo "waiting for the automatic undo…"
sleep 32
printf 'internet  8888: %s (reverted: 200)\n' "$(code http://192.168.77.1:8888/)"
rpc vpn.status | jq -c '{locks, pending}'

step "lock again and confirm from inside the tunnel: stays"
rpc vpn.locks '{"panel":true,"ssh":false,"services":true,"confirmSeconds":30}'
rpc vpn.confirm "{\"remote\":\"$CIP\"}"
sleep 33
printf 'internet  8888: %s (still locked: 000)\n' "$(code http://192.168.77.1:8888/)"
printf 'wireguard 8888: %s\n' "$(code http://10.77.0.1:8888/)"
R nft list table inet pano_vpn | grep -c drop

step "revoke the laptop"
ID=$(rpc vpn.status | jq --arg ip "$CIP" '.peers[] | select(.ip == $ip) | .id')
rpc vpn.peer.remove "{\"id\":$ID}"
printf 'wireguard after revoke: %s\n' "$(code http://10.77.0.1:8888/)"

step "disable: locks gone, interface down"
rpc vpn.disable
printf 'internet  8888: %s\n' "$(code http://192.168.77.1:8888/)"
R ip link show pano0 2>&1 | head -1 || true
R systemctl stop pano-e2e-8888
R ip netns del wgc
R ip link del vpn-h 2>/dev/null || true

step "services: status (MariaDB was already there)"
rpc services.status | jq -c '.[] | {key, installed, managed, version, active}'

step "PostgreSQL on demand"
time rpc services.install '{"service":"postgres"}' | jq -c . || echo '(already installed)'
DB=$(rpc pg.create '{"name":"shop"}')
echo "$DB" | jq -c '{name, user}'
URL=$(echo "$DB" | jq -r .url)
R sh -c "cd / && runuser -u nobody -- \$(ls /usr/pgsql-*/bin/psql | tail -1) '$URL' -Atc 'select current_user, current_database(), version()'" | cut -c1-80
R ss -Htln 'sport = :5432'
rpc pg.list | jq -c '[.[] | {name, owner}]'
rpc pg.drop '{"name":"shop","confirm":"shop"}'

step "Valkey on demand"
time rpc services.install '{"service":"valkey"}' | jq -c . || echo '(already installed)'
RURL=$(rpc services.valkeyUrl | tr -d '"')
CLI=$(R sh -c 'command -v valkey-cli || command -v redis-cli')
printf 'with password   : %s\n' "$(R "$CLI" -u "$RURL" --no-auth-warning ping)"
printf 'without password: %s\n' "$(R "$CLI" -h 127.0.0.1 ping 2>&1 | head -1)"
R ss -Htln 'sport = :6379'
rpc services.status | jq -c '.[] | {key, version, active, memoryMB: (.memory / 1048576 | floor)}'

step "GitLab webhook: wrong token rejected, other events ignored"
printf 'wrong token : %s\n' "$(R curl -s -o /dev/null -w '%{http_code}' -X POST -H 'X-Gitlab-Event: Push Hook' -H 'X-Gitlab-Token: nope' -d '{"ref":"refs/heads/main"}' http://127.0.0.1:7802/hooks/gitlab/demo)"
printf 'tag event   : %s\n' "$(R curl -s -o /dev/null -w '%{http_code}' -X POST -H 'X-Gitlab-Event: Tag Push Hook' -d '{}' http://127.0.0.1:7802/hooks/gitlab/demo)"
