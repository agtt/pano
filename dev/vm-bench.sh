#!/bin/bash
# Panel page times in the test VM (after dev/vm.sh): signs in as a throwaway admin and loads
# every page a few times; prints the median in ms and the HTML size. Also times hot RPCs directly.
set -euo pipefail
VM=${VM:-pano-test}
cd "$(dirname "$0")/.."
R() { orb -m "$VM" -u root "$@"; }
IP=$(orb -m "$VM" hostname -I | awk '{print $1}')
URL="http://$IP:7800"
JAR=$(mktemp)
PW=bench-password-123
N=${N:-5}

SECRET=$(R /opt/pano/bin/pano admin bench "$PW" | awk '/secret:/ {print $2}')
otp() { bun -e "import { code } from './src/web/totp.ts'; console.log(code('$SECRET', Math.floor(Date.now() / 30000)))"; }
curl -s -c "$JAR" -o /dev/null "$URL/login"
curl -s -b "$JAR" -c "$JAR" -o /dev/null -H "Origin: $URL" --data-urlencode username=bench --data-urlencode "password=$PW" --data-urlencode "otp=$(otp)" "$URL/login"

median() { sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
printf '%-28s %8s %8s\n' page ms bytes
for p in / /apps /apps/hello-bun /apps/hello-next /env-groups /sites /databases /services /jobs /backups /runtimes /containers /edge /vpn /security /admins /shield /import /activity; do
  times=$(for _ in $(seq "$N"); do curl -s -b "$JAR" -o /dev/null -w '%{time_total}\n' "$URL$p"; done | awk '{printf "%d\n", $1 * 1000}')
  size=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}/%{size_download}' "$URL$p")
  printf '%-28s %8s %8s\n' "$p" "$(echo "$times" | median)" "$size"
done
R /opt/pano/bin/pano rpc admins.remove '{"username":"bench"}' >/dev/null 2>&1 || true
rm -f "$JAR"
