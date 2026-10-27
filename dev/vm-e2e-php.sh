#!/bin/bash
# Second scenario in the test VM (after dev/vm.sh and dev/vm-e2e.sh, edge cut over):
# a multi-process app (monorepo: two web processes + a worker), a native PHP site,
# moving the OpenLiteSpeed site legacy.test onto pano PHP and back, and importing a
# synthetic cPanel account (site + database + user with its original password).
set -euo pipefail
VM=${VM:-pano-test}
BUN=${BUN:-1.4.4}
PHP=${PHP:-8.5}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
get() { R curl -sk --max-time 10 --resolve "$1:443:127.0.0.1" "https://$1$2"; }
code() { R curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$1:443:127.0.0.1" "https://$1$2"; }

wait_deploy() {
  local app=$1 status=""
  for _ in $(seq 1 240); do
    status=$(rpc apps.get "{\"name\":\"$app\"}" | jq -r '.deploys[0].status')
    [ "$status" != "running" ] && break
    sleep 3
  done
  local id; id=$(rpc apps.get "{\"name\":\"$app\"}" | jq -r '.deploys[0].id')
  echo "$app deploy #$id: $status"
  if [ "$status" != "success" ]; then rpc apps.deployLog "{\"id\":$id}" | jq -r .text | tail -40; exit 1; fi
}

step "reset previous run"
rpc apps.delete '{"name":"hello-multi","confirm":"hello-multi","removeFiles":true}' >/dev/null 2>&1 || true
rpc sites.revertPhp '{"name":"legacy.test"}' >/dev/null 2>&1 || true
for s in php.test shop.test; do rpc sites.delete "{\"name\":\"$s\",\"confirm\":\"$s\",\"removeFiles\":true}" >/dev/null 2>&1 || true; done
R mysql -e "DROP DATABASE IF EXISTS shopuser_wp; DROP USER IF EXISTS 'shopuser_wp'@'localhost';"
R rm -rf /var/lib/pano/imports/work /srv/pano/sites/legacy.test
# OpenLiteSpeed (backend for legacy sites since the cutover) is not a systemd service in this VM.
R bash -c 'pgrep -x litespeed >/dev/null || /usr/local/lsws/bin/lswsctrl start >/dev/null 2>&1'

step "multi-process app (monorepo: web + api + worker)"
R bash -c '
set -e
rm -rf /tmp/src/hello-multi && mkdir -p /tmp/src/hello-multi/apps/web /tmp/src/hello-multi/apps/api && cd /tmp/src/hello-multi
echo "{ \"name\": \"hello-multi\", \"private\": true }" > package.json
echo "Bun.serve({ hostname: \"127.0.0.1\", port: Number(process.env.PORT), fetch: () => new Response(\"web \" + process.env.PANO_PROCESS) });" > apps/web/index.ts
echo "Bun.serve({ hostname: \"127.0.0.1\", port: Number(process.env.PORT), fetch: (r) => new Response(\"api \" + new URL(r.url).pathname) });" > apps/api/index.ts
echo "setInterval(() => console.log(\"tick\", process.env.PANO_PROCESS), 5000); console.log(\"worker up\");" > worker.ts
rm -rf /srv/pano/git/hello-multi.git && git init -q --bare -b main /srv/pano/git/hello-multi.git
git init -q -b main && git add -A && git -c user.email=t@t -c user.name=t commit -qm v1 && git push -q /srv/pano/git/hello-multi.git main
chmod -R a+rX /srv/pano/git
'
PROCS='web | apps/web | multi.test | 256 | bun run index.ts\napi | apps/api | multi.test/api | 256 | bun run index.ts\nworker | . | - | 128 | bun worker.ts'
rpc apps.create "{\"name\":\"hello-multi\",\"runtime\":\"bun\",\"runtime_version\":\"$BUN\",\"repo\":\"file:///srv/pano/git/hello-multi.git\",\"branch\":\"main\",\"processes\":\"$PROCS\"}" | jq -c '{name, processes: [.processes[] | {name, port_a, port_b}]}'
rpc apps.deploy '{"name":"hello-multi"}' && wait_deploy hello-multi
printf 'multi.test/        %s\n' "$(get multi.test /)"
printf 'multi.test/api/x   %s\n' "$(get multi.test /api/x)"
rpc apps.get '{"name":"hello-multi"}' | jq -r '.status.procs[] | "\(.name)\t\(.active)\t\(.memory/1048576|floor)MB"'
step "redeploy: worker moves to the new slot, never two at once"
rpc apps.deploy '{"name":"hello-multi"}' && wait_deploy hello-multi
R systemctl is-active pano-app-hello-multi_worker@a pano-app-hello-multi_worker@b || true

step "native PHP site (installs PHP $PHP on first use)"
time rpc sites.createPhp "{\"name\":\"php.test\",\"domains\":\"php.test\",\"php_version\":\"$PHP\"}" | jq -c .
R bash -c 'cd /srv/pano/sites/php.test/public && rm -f index.php &&
  echo "<?php echo \"php ok \" . PHP_VERSION . \" user=\" . get_current_user() . \" shell=\" . (function_exists(\"shell_exec\") ? \"on\" : \"off\");" > index.php &&
  echo "<?php echo @file_get_contents(\"/etc/pano/pano.env\") === false ? \"blocked\" : \"LEAK\";" > read.php &&
  echo "SECRET=1" > .env && echo "dump" > backup.sql && mkdir -p wp-content/uploads && echo "<?php echo 1;" > wp-content/uploads/x.php &&
  echo "static ok" > hello.txt'
R /opt/pano/bin/pano rpc sites.fixPermissions '{"name":"php.test"}' >/dev/null
printf 'index.php          %s\n' "$(get php.test /)"
printf 'open_basedir       %s\n' "$(get php.test /read.php)"
printf 'static file        %s\n' "$(get php.test /hello.txt)"
for p in /.env /backup.sql /wp-content/uploads/x.php; do printf '%-18s %s\n' "$p" "$(code php.test $p)"; done
R systemctl show pano-php-php.test --property=ActiveState,MemoryCurrent | paste - -
R ls -l /run/pano-php/php.test/

step "move OpenLiteSpeed site legacy.test to pano PHP, then back"
ROOT=$(rpc sites.list | jq -r '.[] | select(.name=="legacy.test") | .root')
R bash -c "mkdir -p $ROOT/private && echo 'top secret' > $ROOT/private/secret.txt && printf 'Require all denied\n' > $ROOT/private/.htaccess"
printf 'before (OLS)       %s / private %s\n' "$(get legacy.test / | head -c 40)" "$(code legacy.test /private/secret.txt)"
rpc sites.convertPhp "{\"name\":\"legacy.test\",\"version\":\"$PHP\"}" | jq -c .
rpc sites.list | jq -c '.[] | select(.name=="legacy.test") | {kind, root, deny_paths, php_version}'
printf 'after (pano PHP)   %s / private %s\n' "$(get legacy.test / | head -c 40)" "$(code legacy.test /private/secret.txt)"
rpc sites.revertPhp '{"name":"legacy.test"}'
printf 'reverted (OLS)     %s\n' "$(get legacy.test / | head -c 40)"

step "cPanel import (synthetic cpmove archive)"
R bash -s <<'EOF'
set -e
HASH=$(mysql -N -e "SELECT PASSWORD('OrigPass123!')")
W=/tmp/cpbuild && rm -rf $W && mkdir -p $W/cpmove-shopuser && cd $W/cpmove-shopuser
mkdir -p userdata mysql cron dnszones cp homedir/public_html/private homedir/mail/shop.test/info
echo "shopuser" > cp/shopuser
cat > userdata/main <<Y
---
main_domain: shop.test
addon_domains: {}
parked_domains: []
sub_domains: []
Y
cat > userdata/shop.test <<Y
---
documentroot: /home/shopuser/public_html
homedir: /home/shopuser
phpversion: ea-php84
serveralias: www.shop.test mail.shop.test
servername: shop.test
user: shopuser
Y
cat > homedir/public_html/index.php <<'P'
<?php
$db = new mysqli('localhost', 'shopuser_wp', 'OrigPass123!', 'shopuser_wp');
echo "cpanel ok: " . $db->query('SELECT msg FROM v_greet')->fetch_row()[0];
P
echo "secret" > homedir/public_html/private/data.txt
printf 'Order deny,allow\nDeny from all\n' > homedir/public_html/private/.htaccess
ln -s /etc/passwd homedir/public_html/passwd
cat > mysql/shopuser_wp.sql <<'S'
CREATE TABLE `greet` (`msg` varchar(50)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
INSERT INTO `greet` VALUES ('hello from cpanel');
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`shopuser_wp`@`localhost` SQL SECURITY DEFINER */
/*!50001 VIEW `v_greet` AS select `greet`.`msg` AS `msg` from `greet` */;
S
cat > mysql.sql <<S
GRANT USAGE ON *.* TO 'shopuser'@'localhost' IDENTIFIED BY PASSWORD '*0000000000000000000000000000000000000000';
GRANT USAGE ON *.* TO 'shopuser_wp'@'localhost' IDENTIFIED BY PASSWORD '$HASH';
GRANT ALL PRIVILEGES ON \`shopuser\\_wp\`.* TO 'shopuser_wp'@'localhost';
S
echo "*/5 * * * * php /home/shopuser/public_html/cron.php" > cron/shopuser
echo "; zone" > dnszones/shop.test.db
mkdir -p /var/lib/pano/imports && cd $W && tar czf /var/lib/pano/imports/cpmove-shopuser.tar.gz cpmove-shopuser
EOF
rpc import.cpanel.list | jq -c .
rpc import.cpanel.scan '{"file":"cpmove-shopuser.tar.gz"}' | jq -c '{account, sites: [.sites[] | {name, domains, php}], databases, users, notMigrated: (.notMigrated | length), warnings}'
rpc import.cpanel.apply '{"file":"cpmove-shopuser.tar.gz","sites":["shop.test"],"databases":["shopuser_wp"]}' | jq -c .
printf 'shop.test          %s\n' "$(get shop.test /)"
printf 'private (htaccess) %s\n' "$(code shop.test /private/data.txt)"
printf 'escaping symlink   %s\n' "$(get shop.test /passwd | grep -q 'root:' && echo LEAK || echo 'not served')"
R mysql -N -e "SHOW GRANTS FOR 'shopuser_wp'@'localhost'"

step "memory"
R systemctl show 'pano-php-*' 'pano-app-hello-multi*' pano-agent pano-edge --property=Id,MemoryCurrent --state=active | paste - - - | awk '{printf "%-40s %s\n", $1, $2}'

step "security audit"
rpc system.audit | jq -r '.[] | "\(.level)\t\(.title)\t\(.detail)"'
