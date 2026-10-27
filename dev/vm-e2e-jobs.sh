#!/bin/bash
# Scheduled jobs and queues in the test VM (after dev/vm.sh; Valkey installed by
# dev/vm-e2e-vpn-services.sh): a PHP site cron job, run now, timers off with the
# site, the old crontab read-only with passwords hidden, the queue monitor with
# BullMQ and Laravel queues, and the low CPU share of builds/crons/workers.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
SITE=jobs.test
HOME_=/srv/pano/sites/$SITE

step "a PHP site with a cron job every 10 s"
rpc sites.delete "{\"name\":\"$SITE\",\"confirm\":\"$SITE\",\"removeFiles\":true}" >/dev/null 2>&1 || true
rpc sites.createPhp "{\"name\":\"$SITE\",\"domains\":\"$SITE\",\"php_version\":\"8.4\"}" >/dev/null
rpc sites.crons "{\"name\":\"$SITE\",\"crons\":\"*:*:0/10 | php -r 'echo PHP_VERSION, \\\" \\\", get_current_user(), \\\" \\\", getenv(\\\"PANO_CRON\\\"), PHP_EOL;' >> public/cron.txt\"}"
sleep 22
R sh -c "tail -2 $HOME_/public/cron.txt"
rpc jobs.list | jq -c '.jobs[] | select(.name == "jobs.test") | {schedule, armed, result, seconds}'
R systemctl show pano-sitecron-jobs.test-0.service -p CPUWeight -p Nice -p IOWeight -p User | tr '\n' ' '; echo

step "bad schedule is refused before anything is saved"
rpc sites.crons "{\"name\":\"$SITE\",\"crons\":\"whenever | php -v\"}" 2>&1 | tail -1 || true

step "run now"
BEFORE=$(R sh -c "wc -l < $HOME_/public/cron.txt")
rpc jobs.run '{"owner":"site","name":"jobs.test","index":0}'
sleep 2
printf 'lines %s -> %s\n' "$BEFORE" "$(R sh -c "wc -l < $HOME_/public/cron.txt")"
rpc jobs.logs '{"owner":"site","name":"jobs.test","index":0}' | tail -2

step "site disabled: timer disarmed; enabled: armed again"
rpc sites.toggle "{\"name\":\"$SITE\",\"enabled\":false}"
R systemctl is-active pano-sitecron-jobs.test-0.timer || true
rpc sites.toggle "{\"name\":\"$SITE\",\"enabled\":true}"
R systemctl is-active pano-sitecron-jobs.test-0.timer

step "old crontab: listed read-only, password hidden"
R sh -c 'echo "0 3 * * * mysqldump -uroot -pS3cretPw shop > /root/shop.sql" > /var/spool/cron/pano-e2e'
rpc jobs.list | jq -c '.crontabs[] | select(.user == "pano-e2e")'
R rm -f /var/spool/cron/pano-e2e

step "queue monitor: off until asked, then BullMQ and Laravel queues"
rpc queues.status | jq -c '{enabled, store}'
rpc queues.set '{"on":true}'
PW=$(R cat /etc/pano/secrets/valkey.pass)
V() { R valkey-cli --no-auth-warning -a "$PW" "$@" >/dev/null; }
V HSET bull:mail:meta opts.maxLenEvents 10000
V SET bull:mail:id 5
V RPUSH bull:mail:wait 4 5
V ZADD bull:mail:failed 1 1 2 2
V ZADD bull:mail:completed 3 3
V RPUSH laravel_database_queues:default '{"job":"x"}'
rpc queues.status | jq -c '.queues[] | {kind, name, waiting, failed, completed}'
rpc queues.status | jq -c '.workers[]'

step "workers and builds get a smaller CPU share than web processes (after a redeploy)"
ID=$(rpc apps.deploy '{"name":"hello-multi"}' | jq .id)
for _ in $(seq 60); do
  STATUS=$(rpc apps.get '{"name":"hello-multi"}' | jq -r ".deploys[] | select(.id == $ID) | .status")
  [ "$STATUS" = running ] || break
  sleep 2
done
echo "deploy $ID: $STATUS"
for u in $(R sh -c 'systemctl list-units --plain --no-legend "pano-app-hello-multi*" | awk "{print \$1}"'); do
  printf '%-40s CPUWeight=%s\n' "$u" "$(R systemctl show "$u" -p CPUWeight --value)"
done

step "clean up"
V DEL bull:mail:meta bull:mail:id bull:mail:wait bull:mail:failed bull:mail:completed laravel_database_queues:default
rpc queues.set '{"on":false}'
rpc sites.delete "{\"name\":\"$SITE\",\"confirm\":\"$SITE\",\"removeFiles\":true}"
R sh -c 'ls /etc/systemd/system | grep -c pano-sitecron || true'
