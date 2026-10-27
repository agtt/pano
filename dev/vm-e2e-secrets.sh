#!/bin/bash
# Secrets in the test VM (after dev/vm.sh and dev/vm-e2e.sh, which leave hello-bun
# running): one-click database into an app's env, masked env values, codes checked
# by the agent, and what a compromised pano-web process can and cannot do.
set -euo pipefail
VM=${VM:-pano-test}
cd "$(dirname "$0")/.."
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
IP=$(orb -m "$VM" hostname -I | awk '{print $1}')
URL="http://$IP:7800"
JAR=$(mktemp)
PW=e2e-secret-password
APP=hello-bun

step "a fresh admin; the TOTP secret goes to the agent, not the web database"
SECRET=$(R /opt/pano/bin/pano admin e2e "$PW" | awk '/secret:/ {print $2}')
otp() { bun -e "import { code } from './src/web/totp.ts'; console.log(code('$SECRET', Math.floor(Date.now() / 30000) + $1))"; }
R python3 -c "import sqlite3; print('web.db secrets left:', sqlite3.connect('/var/lib/pano/web/web.db').execute(\"select count(*) from users where totp_secret <> ''\").fetchone()[0])"

step "log in (password checked by the web, code by the agent)"
curl -s -c "$JAR" -o /dev/null "$URL/login"
curl -s -b "$JAR" -c "$JAR" -o /dev/null -w 'login %{http_code} -> %{redirect_url}\n' -H "Origin: $URL" \
  --data-urlencode username=e2e --data-urlencode "password=$PW" --data-urlencode "otp=$(otp 0)" "$URL/login"
CSRF=$(curl -s -b "$JAR" "$URL/apps/$APP" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//')
post() { curl -s -b "$JAR" -o /dev/null -w '%{http_code} %{redirect_url}\n' -H "Origin: $URL" --data-urlencode "_csrf=$CSRF" "$@"; }

step "+ Database: PostgreSQL for $APP, URL written into its env, app restarted"
rpc apps.env.get "{\"name\":\"$APP\"}" | jq -c 'keys'
post --data-urlencode engine=postgres "$URL/apps/$APP/database" | sed 's/%20/ /g'
rpc apps.env.get "{\"name\":\"$APP\"}" | jq -c .
sleep 3
PID=$(R systemctl show -p MainPID --value "pano-app-$APP@$(rpc apps.get "{\"name\":\"$APP\"}" | jq -r .active_slot)")
printf 'process env has DATABASE_URL: %s\n' "$(R sh -c "tr '\\0' '\\n' < /proc/$PID/environ | grep -c '^DATABASE_URL=postgres://hello_bun:'")"
DBURL=$(rpc apps.env.reveal "{\"name\":\"$APP\"}" | jq -r .DATABASE_URL)
R sh -c "cd / && runuser -u nobody -- \$(ls /usr/pgsql-*/bin/psql | tail -1) '$DBURL' -Atc 'select current_user'"
AGAIN=$(rpc apps.addDatabase "{\"name\":\"$APP\",\"engine\":\"postgres\"}" 2>&1 || true)
printf 'second click: %s\n' "$AGAIN"

step "masked env: reveal needs a code"
printf 'reveal, no code   : '; post "$URL/apps/$APP/env/reveal" | sed 's/%20/ /g; s/.*err=//'
printf 'reveal, wrong code: '; post --data-urlencode otp=123456 "$URL/apps/$APP/env/reveal" | sed 's/%20/ /g; s/.*err=//'
printf 'reveal, code      : '
curl -s -b "$JAR" -H "Origin: $URL" --data-urlencode "_csrf=$CSRF" --data-urlencode "otp=$(otp 1)" "$URL/apps/$APP/env/reveal" | grep -c 'DATABASE_URL=postgres://' || true
printf 'save masked lines keeps values: '
R /opt/pano/bin/pano rpc apps.env.set "{\"name\":\"$APP\",\"vars\":{\"DATABASE_URL\":\"••••••••\",\"EXTRA\":\"1\"}}" >/dev/null
rpc apps.env.reveal "{\"name\":\"$APP\"}" | jq -r '.DATABASE_URL | startswith("postgres://")'

step "a compromised pano-web: straight to the agent socket as the pano user"
A() { R runuser -u pano -- curl -s --unix-socket /run/pano/agent.sock -H 'content-type: application/json' -d "$2" "http://agent/rpc/$1"; echo; }
printf 'env.get    : '; A apps.env.get "{\"params\":{\"name\":\"$APP\"},\"actor\":\"e2e\"}"
printf 'env.reveal : '; A apps.env.reveal "{\"params\":{\"name\":\"$APP\"},\"actor\":\"e2e\"}"
printf 'fake cli   : '; R runuser -u pano -- curl -s --unix-socket /run/pano/agent.sock -H 'x-pano-cli: guess' -d '{"params":{},"actor":"cli"}' http://agent/rpc/backup.key.export; echo
printf 'repo swap  : '; A apps.update "{\"params\":{\"name\":\"$APP\",\"repo\":\"https://github.com/evil/x.git\",\"runtime\":\"bun\",\"runtime_version\":\"1.2.0\"},\"actor\":\"e2e\"}"
printf 'cli token readable by pano: '; R runuser -u pano -- cat /etc/pano/secrets/cli.token 2>&1 | head -1 || true
printf 'brute force: '
for _ in 1 2 3 4 5 6; do A auth.otp '{"params":{"username":"e2e","code":"000000"},"actor":"e2e"}' | tr -d '\n'; printf ' '; done
echo
printf 'after lockout, right code: '; A auth.otp "{\"params\":{\"username\":\"e2e\",\"code\":\"$(otp 0)\"},\"actor\":\"e2e\"}"

step "app sandbox additions and disk"
R systemctl show "pano-app-$APP@a" -p IPAddressDeny -p ProtectProc
for a in $(rpc apps.list | jq -r '.[] | select(.kind == "managed") | .name'); do printf '%-12s releases: %s\n' "$a" "$(R ls "/srv/pano/apps/$a/releases" | wc -l)"; done
R du -sh /srv/pano/apps/*/cache 2>/dev/null | head
R cat /etc/systemd/journald.conf.d/pano.conf
rm -f "$JAR"
