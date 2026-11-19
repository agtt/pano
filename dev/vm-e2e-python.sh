#!/bin/bash
# Python apps in the test VM (after dev/vm.sh and dev/vm-e2e.sh, which leaves the edge in
# charge of :80/:443): nothing of Python before the first app, a Django app (requirements/,
# mysqlclient-free so it builds anywhere, collectstatic, migrate before the switch, static files
# from the edge, a failing migration that switches nothing, rollback, cron) and a FastAPI app
# (uv.lock-less pyproject, uvicorn), then the runtime goes away with the last app.
set -euo pipefail
VM=${VM:-pano-test}
PY=${PY:-3.13}
R() { orb -m "$VM" -u root "$@"; }
rpc() {
  local params=${2:-}
  R /opt/pano/bin/pano rpc "$1" "${params:-"{}"}"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

wait_deploy() {
  local app=$1 expect=${2:-success} status=""
  for _ in $(seq 1 300); do
    status=$(rpc apps.get "{\"name\":\"$app\"}" | jq -r '.deploys[0].status')
    [ "$status" != "running" ] && break
    sleep 3
  done
  local id; id=$(rpc apps.get "{\"name\":\"$app\"}" | jq -r '.deploys[0].id')
  echo "$app deploy #$id: $status (expected $expect)"
  rpc apps.deployLog "{\"id\":$id}" | jq -r .text | tail -25
  [ "$status" = "$expect" ] || exit 1
}

push() { # push <repo> : commit the working tree in /tmp/src/<repo>
  R bash -c "cd /tmp/src/$1 && rm -rf .git && git init -q -b main && git add -A && git -c user.email=t@t -c user.name=t commit -qm \"\${2:-v1}\" && git push -q -f /srv/pano/git/$1.git main"
}

step "reset previous run"
for a in hello-django hello-fastapi; do rpc apps.delete "{\"name\":\"$a\",\"confirm\":\"$a\",\"removeFiles\":true}" >/dev/null 2>&1 || true; done
for v in $(rpc runtimes.list | jq -r '.[] | select(.runtime == "python") | .version'); do rpc runtimes.uninstall "{\"runtime\":\"python\",\"version\":\"$v\"}" >/dev/null || true; done

step "footprint: no Python, no uv, no static copies, no python units before the first Python app"
R bash -c 'test ! -e /opt/pano/runtimes/python && test ! -e /opt/pano/runtimes/uv && test ! -e /srv/pano/static && echo "clean"'
rpc runtimes.list | jq -c '[.[] | .runtime] | unique'

step "sample repos"
R bash -c 'mkdir -p /srv/pano/git /tmp/src/hello-django/hub /tmp/src/hello-django/requirements /tmp/src/hello-django/core/migrations /tmp/src/hello-fastapi'
R bash -c 'cd /tmp/src/hello-django && printf "Django>=5.2,<6.1\ngunicorn\n" > requirements/base.txt && printf -- "-r base.txt\n" > requirements/production.txt'
R bash -c 'cd /tmp/src/hello-django && cat > manage.py <<PY
#!/usr/bin/env python
import os, sys
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hub.settings")
from django.core.management import execute_from_command_line
execute_from_command_line(sys.argv)
PY
touch hub/__init__.py core/__init__.py core/migrations/__init__.py
cat > hub/settings.py <<PY
import os
from pathlib import Path
BASE = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ.get("SECRET_KEY", "e2e-only")
DEBUG = False
ALLOWED_HOSTS = ["*"]
INSTALLED_APPS = ["django.contrib.staticfiles", "django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions", "django.contrib.messages", "core"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware", "django.contrib.auth.middleware.AuthenticationMiddleware", "django.contrib.messages.middleware.MessageMiddleware"]
ROOT_URLCONF = "hub.urls"
TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates", "APP_DIRS": True, "OPTIONS": {"context_processors": ["django.template.context_processors.request", "django.contrib.auth.context_processors.auth", "django.contrib.messages.context_processors.messages"]}}]
WSGI_APPLICATION = "hub.wsgi.application"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.path.join(os.environ.get("DATA_DIR", str(BASE)), "db.sqlite3")}}
STATIC_URL = "/static/"
STATIC_ROOT = BASE / "staticfiles"
USE_TZ = True
PY
cat > hub/urls.py <<PY
from django.http import JsonResponse
from django.urls import path
from core.models import Visit
def index(request):
    return JsonResponse({"hello": "django v1", "visits": Visit.objects.count()})
urlpatterns = [path("", index)]
PY
cat > hub/wsgi.py <<PY
import os
from django.core.wsgi import get_wsgi_application
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hub.settings")
application = get_wsgi_application()
PY
cat > core/models.py <<PY
from django.db import models
class Visit(models.Model):
    at = models.DateTimeField(auto_now_add=True)
PY
cat > core/migrations/0001_initial.py <<PY
from django.db import migrations, models
class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [migrations.CreateModel(name="Visit", fields=[("id", models.AutoField(primary_key=True, serialize=False)), ("at", models.DateTimeField(auto_now_add=True))])]
PY'
R bash -c 'cd /tmp/src/hello-fastapi && printf "[project]\nname = \"api\"\nversion = \"0.1\"\nrequires-python = \">=3.11\"\ndependencies = [\"fastapi\", \"uvicorn\"]\n" > pyproject.toml && printf "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get(\"/\")\ndef index():\n    return {\"hello\": \"fastapi\"}\n" > main.py'
for r in hello-django hello-fastapi; do
  R bash -c "rm -rf /srv/pano/git/$r.git && git init -q --bare -b main /srv/pano/git/$r.git"
  push $r
done
R chmod -R a+rX /srv/pano/git

step "create + first deploy (installs Python $PY and uv on demand, migrates, collects static files)"
rpc apps.create "{\"name\":\"hello-django\",\"domains\":\"django.test\",\"runtime\":\"python\",\"runtime_version\":\"$PY\",\"repo\":\"file:///srv/pano/git/hello-django.git\",\"branch\":\"main\",\"memory_mb\":768}" | jq -c '{name, runtime_version, py_migrate, py_collectstatic}'
rpc apps.deploy '{"name":"hello-django"}' && wait_deploy hello-django
rpc runtimes.list | jq -c '[.[] | select(.runtime == "python")]'
R ls /opt/pano/runtimes/python /opt/pano/runtimes/uv
R ls /srv/pano/apps/hello-django/data

step "through the edge: the app answers, static files come from Caddy"
for h in django.test; do
  printf 'GET /            %s\n' "$(R curl -sk --resolve $h:443:127.0.0.1 https://$h/)"
  printf 'GET /static/admin/css/base.css %s\n' "$(R curl -sk -o /dev/null -D - --resolve $h:443:127.0.0.1 https://$h/static/admin/css/base.css | grep -iE '^(HTTP|server|content-type|cache-control)' | tr -d '\r' | tr '\n' ' ')"
done
R ls /srv/pano/static/hello-django/a/0 | head -3
R sh -c 'stat -c "%U:%G %a" /srv/pano/static/hello-django/a/0/admin/css/base.css'

step "the process: venv python, unprivileged, sandboxed, bound to 127.0.0.1 only"
R sh -c 'cat /srv/pano/apps/hello-django/run/main-a.sh'
R sh -c 'ss -Htlnp | grep -E ":41(0|1)[0-9] " || true'
R systemctl show pano-app-hello-django@a -p User -p MemoryMax -p NoNewPrivileges | tr '\n' ' '; echo

step "a failing migration: the deploy fails, nothing switches, the live release keeps answering"
R bash -c 'cd /tmp/src/hello-django && cat > core/migrations/0002_boom.py <<PY
from django.db import migrations
def boom(apps, schema_editor):
    raise RuntimeError("migration failed on purpose")
class Migration(migrations.Migration):
    dependencies = [("core", "0001_initial")]
    operations = [migrations.RunPython(boom)]
PY'
push hello-django v2
SLOT=$(rpc apps.get '{"name":"hello-django"}' | jq -r .active_slot)
rpc apps.deploy '{"name":"hello-django"}' && wait_deploy hello-django failed
printf 'slot before %s, after %s\n' "$SLOT" "$(rpc apps.get '{"name":"hello-django"}' | jq -r .active_slot)"
R curl -sk --resolve django.test:443:127.0.0.1 https://django.test/

step "fixed: next release switches; rollback returns to the previous one"
R bash -c 'cd /tmp/src/hello-django && rm core/migrations/0002_boom.py && sed -i "s/django v1/django v2/" hub/urls.py'
push hello-django v3
rpc apps.deploy '{"name":"hello-django"}' && wait_deploy hello-django
R curl -sk --resolve django.test:443:127.0.0.1 https://django.test/; echo
rpc apps.rollback '{"name":"hello-django"}' | jq -c .
sleep 3
R curl -sk --resolve django.test:443:127.0.0.1 https://django.test/; echo

step "cron job runs with the venv python"
rpc apps.get '{"name":"hello-django"}' > /tmp/pano-hd.json
rpc apps.update "{\"name\":\"hello-django\",\"domains\":\"django.test\",\"runtime\":\"python\",\"runtime_version\":\"$(jq -r .runtime_version /tmp/pano-hd.json)\",\"repo\":\"file:///srv/pano/git/hello-django.git\",\"branch\":\"main\",\"memory_mb\":768,\"crons\":[{\"schedule\":\"*:*:0/10\",\"command\":\"python manage.py check >> \$DATA_DIR/cron.txt 2>&1\"}]}" >/dev/null
sleep 25
R sh -c 'tail -2 /srv/pano/apps/hello-django/data/cron.txt'

step "FastAPI (pyproject.toml, uvicorn installed because it is a dependency; no gunicorn)"
rpc apps.create "{\"name\":\"hello-fastapi\",\"domains\":\"fastapi.test\",\"runtime\":\"python\",\"runtime_version\":\"$PY\",\"repo\":\"file:///srv/pano/git/hello-fastapi.git\",\"branch\":\"main\",\"memory_mb\":512}" | jq -c '{name, runtime_version}'
rpc apps.deploy '{"name":"hello-fastapi"}' && wait_deploy hello-fastapi
R curl -sk --resolve fastapi.test:443:127.0.0.1 https://fastapi.test/; echo

step "a Node.js app on the same server is untouched by any of this"
rpc apps.list | jq -r '.[] | "\(.name)\t\(.runtime)\t\(.status.active)"'

step "removing the Python apps frees the runtime; deleting it leaves no Python behind"
for a in hello-django hello-fastapi; do rpc apps.delete "{\"name\":\"$a\",\"confirm\":\"$a\",\"removeFiles\":true}" >/dev/null; done
for v in $(rpc runtimes.list | jq -r '.[] | select(.runtime == "python") | .version'); do rpc runtimes.uninstall "{\"runtime\":\"python\",\"version\":\"$v\"}"; done
R bash -c 'test ! -e /opt/pano/runtimes/python && test ! -e /opt/pano/runtimes/uv && test -z "$(ls /srv/pano/static 2>/dev/null)" && echo "no Python left (build packages such as gcc stay)"'
R sh -c 'systemctl list-units --plain --no-legend "pano-app-hello-django*" "pano-app-hello-fastapi*" | wc -l'
