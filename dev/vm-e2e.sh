#!/bin/bash
# End-to-end scenario in the test VM (after dev/vm.sh): import the CyberPanel-like
# setup, install runtimes, deploy a Next.js and a Bun app from local bare repos,
# redeploy (blue/green), cut over to the edge, probe through it, roll back.
set -euo pipefail
VM=${VM:-pano-test}
NODE=${NODE:-24.22.1}
BUN=${BUN:-1.4.4}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

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
for a in hello-next hello-bun; do rpc apps.delete "{\"name\":\"$a\",\"confirm\":\"$a\",\"removeFiles\":true}" >/dev/null 2>&1 || true; done
rpc edge.rollback >/dev/null 2>&1 || true
R chmod 0755 /opt/pano/runtimes /opt/pano/runtimes/node /opt/pano/runtimes/bun 2>/dev/null || true

step "sample repos (bare, under /srv/pano/git)"
R bash -c '
set -e
mkdir -p /srv/pano/git /tmp/src/hello-next/app /tmp/src/hello-bun
cd /tmp/src/hello-next
cat > package.json <<EOF
{ "name": "hello-next", "private": true,
  "scripts": { "build": "next build", "start": "next start" },
  "dependencies": { "next": "latest", "react": "latest", "react-dom": "latest" } }
EOF
cat > app/layout.js <<EOF
export default function Layout({ children }) { return <html><body>{children}</body></html>; }
EOF
echo "export default function Page() { return <h1>hello next v1</h1>; }" > app/page.js
cd /tmp/src/hello-bun
cat > package.json <<EOF
{ "name": "hello-bun", "private": true, "scripts": { "start": "bun run index.ts" } }
EOF
echo "Bun.serve({ hostname: \"127.0.0.1\", port: Number(process.env.PORT), fetch: () => new Response(\"hello bun \" + Bun.version) });" > index.ts
for r in hello-next hello-bun; do
  rm -rf /srv/pano/git/$r.git && git init -q --bare -b main /srv/pano/git/$r.git
  cd /tmp/src/$r && rm -rf .git && git init -q -b main && git add -A && git -c user.email=t@t -c user.name=t commit -qm v1
  git push -q /srv/pano/git/$r.git main
done
chmod -R a+rX /srv/pano/git
'

step "security audit (before)"
rpc system.audit | jq -r '.[] | "\(.level)\t\(.title)\t\(.detail)"'

step "import from OpenLiteSpeed"
rpc import.scan | jq -c '{sites: [.sites[] | {name, kind, domains, routes}], apps: [.apps[] | {name, external_unit, upstream}], warnings}'
rpc import.apply '{"sites":["legacy.test","proxy.test"],"apps":["demo-legacy"]}'

step "runtimes"
rpc runtimes.install "{\"runtime\":\"node\",\"version\":\"$NODE\"}" >/dev/null
rpc runtimes.install "{\"runtime\":\"bun\",\"version\":\"$BUN\"}" >/dev/null
rpc runtimes.list | jq -c .

step "create + deploy apps"
rpc apps.create "{\"name\":\"hello-next\",\"domains\":\"next.test\",\"runtime\":\"node\",\"runtime_version\":\"$NODE\",\"repo\":\"file:///srv/pano/git/hello-next.git\",\"branch\":\"main\",\"memory_mb\":768}" | jq -c '{name, port_a, port_b}'
rpc apps.create "{\"name\":\"hello-bun\",\"domains\":\"bun.test\",\"runtime\":\"bun\",\"runtime_version\":\"$BUN\",\"repo\":\"file:///srv/pano/git/hello-bun.git\",\"branch\":\"main\",\"memory_mb\":256}" | jq -c '{name, port_a, port_b}'
rpc apps.deploy '{"name":"hello-bun"}' && wait_deploy hello-bun
rpc apps.deploy '{"name":"hello-next"}' && wait_deploy hello-next
rpc apps.list | jq -r '.[] | "\(.name)\t\(.kind)\tslot=\(.active_slot)\t\(.status.active)\t\(.status.memory/1048576|floor)MB"'

step "edge: install, settings, cutover"
rpc edge.install
rpc edge.settings '{"email":"","localCerts":true}'
rpc edge.cutover | jq -c .
for h in next.test bun.test legacy.test proxy.test; do
  printf '%-12s %s\n' "$h" "$(R curl -sk --resolve $h:443:127.0.0.1 https://$h/ | head -c 80 | tr '\n' ' ')"
done
printf 'http->https %s\n' "$(R curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --resolve next.test:80:127.0.0.1 http://next.test/)"

step "zero-downtime redeploy (v2) while probing every 200 ms"
R bash -c 'cd /tmp/src/hello-next && echo "export default function Page() { return <h1>hello next v2</h1>; }" > app/page.js && git -c user.email=t@t -c user.name=t commit -qam v2 && git push -q /srv/pano/git/hello-next.git main'
R bash -c 'rm -f /tmp/probe.log; (for i in $(seq 1 1500); do curl -sk -o /dev/null -w "%{http_code}\n" --max-time 2 --resolve next.test:443:127.0.0.1 https://next.test/ >> /tmp/probe.log; sleep 0.2; done) & echo $! > /tmp/probe.pid'
rpc apps.deploy '{"name":"hello-next"}' && wait_deploy hello-next
sleep 20
R bash -c 'kill $(cat /tmp/probe.pid) 2>/dev/null; sort /tmp/probe.log | uniq -c'
printf 'now serving: %s\n' "$(R curl -sk --resolve next.test:443:127.0.0.1 https://next.test/ | grep -o 'hello next v[0-9]' | head -1)"
rpc apps.list | jq -r '.[] | "\(.name)\tslot=\(.active_slot)\t\(.status.active)"'

step "memory"
R systemctl show pano-agent pano-web pano-edge lshttpd --property=Id,MemoryCurrent | paste - - - | awk '{printf "%-24s %s\n", $1, $2}'

step "rollback + cutover again"
rpc edge.rollback | jq -c .
printf 'legacy via OLS on :80 again: %s\n' "$(R curl -s -H 'Host: legacy.test' http://127.0.0.1/)"
rpc edge.cutover | jq -c '.ok'

step "security audit (after)"
rpc system.audit | jq -r '.[] | "\(.level)\t\(.title)\t\(.detail)"'
