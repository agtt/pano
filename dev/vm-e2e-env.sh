#!/bin/bash
# App environment in the test VM (after dev/vm.sh and dev/vm-e2e.sh, which leave hello-bun
# running; MariaDB and PostgreSQL installed): shared variable groups, restart/redeploy hints,
# preview-only values and connecting existing databases. Re-runnable: cleans its leftovers first.
set -euo pipefail
VM=${VM:-pano-test}
cd "$(dirname "$0")/.."
R() { orb -m "$VM" -u root "$@"; }
rpc() { R /opt/pano/bin/pano rpc "$1" "${2:-"{}"}"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
APP=hello-bun
PSQL='$(ls /usr/pgsql-*/bin/psql | tail -1)'
pg() { R sh -c "cd / && runuser -u postgres -- $PSQL -qAt -d ${2:-postgres} -c \"$1\""; }
penv() { # variables of the live process
  local pid
  pid=$(R systemctl show -p MainPID --value "pano-app-$APP@$(rpc apps.get "{\"name\":\"$APP\"}" | jq -r .active_slot)")
  R sh -c "tr '\\0' '\\n' < /proc/$pid/environ"
}
settings() { rpc apps.get "{\"name\":\"$APP\"}" | jq -c --arg g "$1" '{name, runtime, runtime_version, repo, branch, root_dir, install_cmd, build_cmd, start_cmd, health_path, memory_mb, ask_url, auto_deploy, crons, domains, preview_domain, preview_max, preview_ttl_days, preview_env_exclude, env_groups: $g}'; }
wait_deploy() {
  local id=$1 s
  for _ in $(seq 1 120); do
    s=$(rpc apps.get "{\"name\":\"$APP\"}" | jq -r --argjson id "$id" '.deploys[] | select(.id == $id) | .status')
    [ "$s" != "running" ] && { echo "deploy $id: $s"; return; }
    sleep 3
  done
  echo "deploy $id: timeout"
}

step "clean leftovers"
rpc apps.update "$(settings "")" >/dev/null
rpc apps.env.set "{\"name\":\"$APP\",\"vars\":{}}" >/dev/null
rpc apps.env.set "{\"name\":\"$APP\",\"vars\":{},\"scope\":\"preview\"}" >/dev/null
rpc envGroups.remove '{"name":"e2e-shared"}' >/dev/null 2>&1 || true
R mysql -e "DROP DATABASE IF EXISTS e2e_attach; DROP DATABASE IF EXISTS e2e_other;" || true
for u in $(R mysql -Nse "SELECT User FROM mysql.user WHERE User LIKE 'hello_bun\\_%'"); do R mysql -e "DROP USER '$u'@'localhost'"; done
pg "DROP DATABASE IF EXISTS e2e_pgown WITH (FORCE)" || true
for r in $(pg "SELECT rolname FROM pg_roles WHERE rolname LIKE 'hello_bun\\_%' OR rolname = 'e2e_pgown'"); do pg "DROP ROLE IF EXISTS $r"; done
echo ok

step "a deploy records what the build and the processes started with"
wait_deploy "$(rpc apps.deploy "{\"name\":\"$APP\"}" | jq -r .id)"
rpc apps.get "{\"name\":\"$APP\"}" | jq -c '{env_pending, leaks: ((.env_running // "") + (.env_built // ""))}'

step "restart and redeploy hints"
rpc apps.env.set "{\"name\":\"$APP\",\"vars\":{\"API_URL\":\"x\",\"NEXT_PUBLIC_E2E\":\"1\",\"OVERRIDE\":\"own\"}}" >/dev/null
rpc apps.get "{\"name\":\"$APP\"}" | jq -c .env_pending
rpc apps.action "{\"name\":\"$APP\",\"action\":\"restart\"}" >/dev/null
printf 'after restart: '; rpc apps.get "{\"name\":\"$APP\"}" | jq -c .env_pending

step "shared variables: group file root-only, read before the app's own .env"
rpc envGroups.save '{"name":"e2e-shared","vars":{"SHARED_X":"from-group","OVERRIDE":"group"}}' | jq -c .
R stat -c '%U:%G %a %n' /etc/pano/env-groups/e2e-shared.env
printf 'unknown group refused: '; rpc apps.update "$(settings "nope")" 2>&1 | tail -1 || true
rpc apps.update "$(settings "e2e-shared")" >/dev/null
R grep EnvironmentFile "/etc/systemd/system/pano-app-$APP@.service"
printf 'pending after linking: '; rpc apps.get "{\"name\":\"$APP\"}" | jq -c .env_pending.restart
rpc apps.action "{\"name\":\"$APP\",\"action\":\"restart\"}" >/dev/null
sleep 2
printf 'process: '; penv | grep -E '^(SHARED_X|OVERRIDE)=' | sort | tr '\n' ' '; echo
printf 'list: '; rpc envGroups.list | jq -c '.[] | select(.name == "e2e-shared")'
printf 'remove while used: '; rpc envGroups.remove '{"name":"e2e-shared"}' 2>&1 | tail -1 || true
rpc envGroups.save '{"name":"e2e-shared","vars":{"SHARED_X":"changed","OVERRIDE":"••••••••"}}' >/dev/null
printf 'group changed -> pending: '; rpc apps.get "{\"name\":\"$APP\"}" | jq -c .env_pending
printf 'masked value kept: '; rpc envGroups.reveal '{"name":"e2e-shared"}' | jq -c .

step "preview-only values: root-only file, never in the live process"
rpc apps.env.set "{\"name\":\"$APP\",\"vars\":{\"STRIPE_KEY\":\"sk_test_e2e\"},\"scope\":\"preview\"}" >/dev/null
rpc apps.env.get "{\"name\":\"$APP\",\"scope\":\"preview\"}" | jq -c .
R stat -c '%U:%G %a %n' "/srv/pano/apps/$APP/shared/.env.preview"
printf 'app user can read it: '; R runuser -u "app-$APP" -- cat "/srv/pano/apps/$APP/shared/.env.preview" >/dev/null 2>&1 && echo yes || echo no
printf 'production env untouched: '; rpc apps.env.get "{\"name\":\"$APP\"}" | jq -c 'keys'

step "connect an existing MariaDB database: own user, that database only"
R mysql -e "CREATE DATABASE e2e_attach; CREATE DATABASE e2e_other; CREATE TABLE e2e_attach.t (id int); INSERT INTO e2e_attach.t VALUES (42);"
rpc apps.attachDatabase "{\"name\":\"$APP\",\"engine\":\"mariadb\",\"database\":\"e2e_attach\",\"key\":\"LEGACY_DB_URL\"}" | jq -c .
URL=$(rpc apps.env.reveal "{\"name\":\"$APP\"}" | jq -r .LEGACY_DB_URL)
U=$(echo "$URL" | sed -E 's#mysql://([^:]+):.*#\1#'); P=$(echo "$URL" | sed -E 's#mysql://[^:]+:([^@]+)@.*#\1#')
printf 'reads its table: '; R mysql -h127.0.0.1 -u"$U" -p"$P" -Nse "SELECT id FROM e2e_attach.t"
printf 'other database: '; R mysql -h127.0.0.1 -u"$U" -p"$P" -Nse "SELECT 1 FROM e2e_other.dual" 2>&1 | tail -1 || true
printf 'same key again: '; rpc apps.attachDatabase "{\"name\":\"$APP\",\"engine\":\"mariadb\",\"database\":\"e2e_attach\",\"key\":\"LEGACY_DB_URL\"}" 2>&1 | tail -1 || true
printf 'protected: '; rpc apps.attachDatabase "{\"name\":\"$APP\",\"engine\":\"mariadb\",\"database\":\"mysql\",\"key\":\"X_URL\"}" 2>&1 | tail -1 || true
printf 'backup job: '; rpc backup.jobs 2>/dev/null | jq -c '[.[] | select(.target == "e2e_attach") | .kind]' || echo "(no backup.jobs method)"

step "connect an existing PostgreSQL database owned by another role: joins the owner (migrations work)"
pg "CREATE ROLE e2e_pgown LOGIN PASSWORD 'x'"
pg "CREATE DATABASE e2e_pgown OWNER e2e_pgown"
pg "SET ROLE e2e_pgown; CREATE TABLE items (id int); INSERT INTO items VALUES (7);" e2e_pgown
rpc apps.attachDatabase "{\"name\":\"$APP\",\"engine\":\"postgres\",\"database\":\"e2e_pgown\"}" | jq -c .
PURL=$(rpc apps.env.reveal "{\"name\":\"$APP\"}" | jq -r .DATABASE_URL)
R sh -c "cd / && runuser -u nobody -- $PSQL '$PURL' -qAt -c 'SELECT id FROM items' -c 'ALTER TABLE items ADD COLUMN name text' -c 'SELECT count(*) FROM information_schema.columns WHERE table_name = '\''items'\'''"
printf 'restarted with both URLs: '; sleep 2; penv | grep -cE '^(DATABASE_URL|LEGACY_DB_URL)=' || true

step "cleanup"
rpc apps.update "$(settings "")" >/dev/null
rpc apps.env.set "{\"name\":\"$APP\",\"vars\":{}}" >/dev/null
rpc apps.env.set "{\"name\":\"$APP\",\"vars\":{},\"scope\":\"preview\"}" >/dev/null
rpc envGroups.remove '{"name":"e2e-shared"}' >/dev/null && echo "group removed"
rpc apps.action "{\"name\":\"$APP\",\"action\":\"restart\"}" >/dev/null && echo restarted
