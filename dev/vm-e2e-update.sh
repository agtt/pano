#!/bin/bash
# `pano update` in the test VM (after dev/vm.sh): a good update, refused
# binaries, a release that does not start (rolls back by itself) and a manual
# rollback. Apps keep serving throughout.
set -euo pipefail
VM=${VM:-pano-test}
R() { orb -m "$VM" -u root "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
cd "$(dirname "$0")/.."
ARCH=$(R uname -m)
BIN=dist/pano; [ "$ARCH" = aarch64 ] && BIN=dist/pano-arm64
R install -m 0755 "$PWD/$BIN" /var/tmp/pano-next
SHA=$(shasum -a 256 "$BIN" | awk '{print $1}')
serving() { R curl -sk --resolve bun.test:443:127.0.0.1 https://bun.test/ -o /dev/null -w 'bun.test %{http_code}\n'; }

step "refused: wrong checksum, a file that does not run"
R /opt/pano/bin/pano update /var/tmp/pano-next 0000 || true
R sh -c 'echo "not a binary" > /var/tmp/pano-bad; chmod 755 /var/tmp/pano-bad'
R sh -c '/opt/pano/bin/pano update /var/tmp/pano-bad $(sha256sum /var/tmp/pano-bad | cut -d" " -f1)' || true

step "a good update"
R /opt/pano/bin/pano update /var/tmp/pano-next "$SHA"
R ls -la /opt/pano/bin/
serving

step "a release that runs 'version' but does not start"
R sh -c 'printf "#!/bin/sh\n[ \"\$1\" = version ] && echo 9.9.9 && exit 0\nexit 1\n" > /var/tmp/pano-broken; chmod 755 /var/tmp/pano-broken'
R /opt/pano/bin/pano rpc backup.jobs >/dev/null
START=$(date +%s)
R sh -c '/opt/pano/bin/pano update /var/tmp/pano-broken $(sha256sum /var/tmp/pano-broken | cut -d" " -f1)' || true
echo "back after $(($(date +%s) - START))s"
R /opt/pano/bin/pano version
R systemctl is-active pano-agent pano-web
R sh -c 'ls /var/lib/pano/ | grep -c failed- || true'
serving

step "manual rollback"
R /opt/pano/bin/pano update-rollback
R systemctl is-active pano-agent pano-web
R /opt/pano/bin/pano version
serving
