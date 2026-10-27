#!/bin/bash
# Day-two features in the test VM (after dev/vm.sh + dev/vm-e2e.sh + dev/vm-e2e-secrets.sh):
# bun as the package manager, cron jobs, instant rollback, MariaDB into an app env
# (TCP login + automatic backup job), databases over WireGuard, SSH guard, alerts.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
NS() { R ip netns exec wgc "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
get() { R curl -sk --max-time 5 --resolve "$1:443:127.0.0.1" "https://$1/" || true; }

step "bun installs every app (hello-next has a package-lock.json)"
ID=$(rpc apps.get '{"name":"hello-next"}' | jq '.deploys[0].id')
rpc apps.deployLog "{\"id\":$ID,\"offset\":0}" | jq -r .text | grep -E '^==> (bun|npm)' | head -3

step "cron every 10 s in hello-bun"
rpc apps.get '{"name":"hello-bun"}' | jq '{name, domains: (.domains | join(",")), runtime, runtime_version, repo, branch, root_dir, install_cmd, build_cmd, start_cmd, health_path, memory_mb, ask_url, auto_deploy, crons: "*:*:0/10 | sh -c \"date >> $DATA_DIR/cron.txt\""}' > /tmp/pano-app.json
rpc apps.update "$(cat /tmp/pano-app.json)"
sleep 22
printf 'cron runs so far: %s\n' "$(R sh -c 'wc -l < /srv/pano/apps/hello-bun/data/cron.txt')"
rpc apps.crons '{"name":"hello-bun"}' | jq -c '.jobs[] | {schedule, result}'
printf 'bad schedule: %s\n' "$(rpc apps.update "$(jq '.crons = "every tuesday-ish | date"' /tmp/pano-app.json)" 2>&1 | tail -1)"
rpc apps.update "$(jq '.crons = ""' /tmp/pano-app.json)"
R sh -c 'ls /etc/systemd/system | grep -c pano-cron-hello-bun || true'

step "instant rollback of hello-next"
printf 'before: %s\n' "$(get next.test | grep -o 'hello next v[0-9]' | head -1)"
time rpc apps.rollback '{"name":"hello-next"}'
printf 'after : %s\n' "$(get next.test | grep -o 'hello next v[0-9]' | head -1)"
rpc apps.rollback '{"name":"hello-next"}' >/dev/null
printf 'and back: %s\n' "$(get next.test | grep -o 'hello next v[0-9]' | head -1)"

step "MariaDB for hello-multi: URL in env, TCP login, daily backup job"
rpc apps.addDatabase '{"name":"hello-multi","engine":"mariadb"}' 2>&1 | tail -1 || true
rpc apps.addDatabase '{"name":"hello-next","engine":"postgres"}' 2>&1 | tail -1 || true
MURL=$(rpc apps.env.reveal '{"name":"hello-multi"}' | jq -r .DATABASE_URL)
MUSER=$(echo "$MURL" | sed -E 's#mysql://([^:]+):.*#\1#')
MPASS=$(echo "$MURL" | sed -E 's#mysql://[^:]+:([^@]+)@.*#\1#')
R mysql -h 127.0.0.1 -u "$MUSER" -p"$MPASS" -e 'select current_user() as tcp_login' hello_multi
rpc backup.jobs | jq -c '[.[] | {name, kind, target, schedule}]'

step "databases over WireGuard"
R ip netns del wgc 2>/dev/null || true
R ip link del vpn-h 2>/dev/null || true
rpc vpn.enable '{"port":51820,"endpoint":"192.168.77.1"}' >/dev/null
R ip netns add wgc
R ip link add vpn-h type veth peer name vpn-c
R ip link set vpn-c netns wgc
R nmcli device set vpn-h managed no 2>/dev/null || true
R ip addr add 192.168.77.1/24 dev vpn-h
R ip link set vpn-h up
NS ip addr add 192.168.77.2/24 dev vpn-c
NS ip link set vpn-c up
R sh -c 'umask 077; wg genkey > /root/wgc.key'
PUB=$(R sh -c 'wg pubkey < /root/wgc.key')
ADD=$(rpc vpn.peer.add "{\"name\":\"ops-laptop\",\"publicKey\":\"$PUB\"}")
PSK=$(echo "$ADD" | jq -r .config | awk '/PresharedKey/ {print $3}')
CIP=$(echo "$ADD" | jq -r .ip)
R sh -c "umask 077; echo $PSK > /root/wgc.psk"
NS ip link add wg0 type wireguard
NS wg set wg0 private-key /root/wgc.key peer "$(rpc vpn.status | jq -r .publicKey)" preshared-key /root/wgc.psk endpoint 192.168.77.1:51820 allowed-ips 10.77.0.1/32
NS ip addr add "$CIP/32" dev wg0
NS ip link set wg0 up
NS ip route add 10.77.0.1/32 dev wg0
rpc vpn.locks '{"panel":false,"ssh":false,"services":false,"databases":true,"confirmSeconds":60}'
PURL=$(rpc apps.env.reveal '{"name":"hello-next"}' | jq -r .DATABASE_URL | sed 's/127.0.0.1/10.77.0.1/')
printf 'postgres over wg : %s\n' "$(NS sh -c "\$(ls /usr/pgsql-*/bin/psql | tail -1) '$PURL' -Atc 'select current_user'" 2>&1)"
# The VM's MariaDB (CyberPanel-like) listens on 0.0.0.0, so no forwarder: it answers itself and refuses the 'localhost' user.
printf 'mariadb over wg  : %s\n' "$(NS mysql -h 10.77.0.1 -u "$MUSER" -p"$MPASS" -N -e 'select 1' hello_multi 2>&1)"
printf 'postgres via veth: %s\n' "$(NS timeout 3 bash -c 'echo > /dev/tcp/192.168.77.1/5432' 2>&1 && echo open || echo closed)"
printf 'wg addr via veth : %s\n' "$(NS timeout 3 bash -c 'ip route add 10.77.0.0/24 via 192.168.77.1 dev vpn-c 2>/dev/null; ip route del 10.77.0.1/32 dev wg0; echo > /dev/tcp/10.77.0.1/5432' 2>&1 && echo open || echo dropped)"
NS ip route del 10.77.0.0/24 via 192.168.77.1 dev vpn-c 2>/dev/null || true
NS ip route add 10.77.0.1/32 dev wg0

step "SSH guard: 25 quick connections from the 'internet' get the address banned"
rpc guard.set '{"ssh":true,"http":true}'
for _ in $(seq 25); do NS timeout 1 bash -c 'echo > /dev/tcp/192.168.77.1/22' 2>/dev/null || true; done
rpc guard.get | jq -c .
printf 'over wireguard still fine: %s\n' "$(NS timeout 2 bash -c 'echo > /dev/tcp/10.77.0.1/22' 2>&1 && echo open || echo 'refused (no sshd), not dropped')"
rpc guard.set '{"ssh":false,"http":false}'

step "alerts"
printf 'test without token: %s\n' "$(rpc alerts.test 2>&1 | tail -1)"

step "clean up"
rpc vpn.disable >/dev/null
R ip netns del wgc
R ip link del vpn-h 2>/dev/null || true
