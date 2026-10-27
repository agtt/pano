#!/bin/bash
# Performance defaults in the test VM (after dev/vm.sh): kernel settings,
# journal limits, PHP opcache, and browser caching of a PHP site's static files.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
SITE=tune.test

step "kernel and journal"
R sysctl net.core.somaxconn net.ipv4.tcp_congestion_control net.core.rmem_max vm.swappiness || true
R cat /etc/systemd/journald.conf.d/pano.conf | grep SystemMaxUse

step "PHP site: opcache and asset caching"
rpc sites.delete "{\"name\":\"$SITE\",\"confirm\":\"$SITE\",\"removeFiles\":true}" >/dev/null 2>&1 || true
rpc sites.createPhp "{\"name\":\"$SITE\",\"domains\":\"$SITE\",\"php_version\":\"8.4\"}" >/dev/null
R sh -c "echo 'body{}' > /srv/pano/sites/$SITE/public/app.css && echo '<?php echo ini_get(\"opcache.memory_consumption\"), \" \", ini_get(\"realpath_cache_size\");' > /srv/pano/sites/$SITE/public/i.php && chown -R \$(stat -c %U /srv/pano/sites/$SITE/public) /srv/pano/sites/$SITE/public"
sleep 2
R curl -sk --resolve "$SITE:443:127.0.0.1" "https://$SITE/i.php"; echo
R curl -sk -o /dev/null -D - --resolve "$SITE:443:127.0.0.1" "https://$SITE/app.css" | grep -i cache-control
R curl -sk -o /dev/null -D - --resolve "$SITE:443:127.0.0.1" "https://$SITE/i.php" | grep -ci cache-control || echo "no cache header on PHP: ok"
rpc sites.delete "{\"name\":\"$SITE\",\"confirm\":\"$SITE\",\"removeFiles\":true}" >/dev/null
