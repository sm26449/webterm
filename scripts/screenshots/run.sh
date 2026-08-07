#!/usr/bin/env bash
# Generates the screenshots for README/docs with FICTIONAL DATA (not the real hosts).
# It starts an ephemeral WebTerm (empty DB), seeds a demo fleet plus real agents in the
# container (so they show up online with metrics), a session with harmless output and a
# demo file, then runs Playwright (in its own container, on the same network) to
# capture the key screens in dark + light.
#
#   scripts/screenshots/run.sh [out_dir]
#
# Prereq: docker plus the images ghcr.io/sm26449/webterm:<tag> and
# mcr.microsoft.com/playwright:v1.61.1-noble locally. No node dependency on the host.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/docs/screenshots}"
IMAGE="${WEBTERM_IMAGE:-ghcr.io/sm26449/webterm:v2.0.0}"
PW_IMAGE="mcr.microsoft.com/playwright:v1.61.1-noble"
NET=wt-shots-net
APP=wt-shots-app
TOKEN=shots-setup-token
EMAIL="demo@webterm.local"
PASSWORD="parola-demo-123456"

say() { printf '\033[1;36m%s\033[0m\n' "$*"; }
pyrun() { docker exec -i "$APP" python3 - "$@"; }   # run python from stdin inside the container

cleanup() {
  docker rm -f "$APP" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
mkdir -p "$OUT"

say "── starting an ephemeral WebTerm ($IMAGE) ──"
docker network create "$NET" >/dev/null
docker run -d --name "$APP" --network "$NET" --hostname prod-web-01 \
  -e WEBTERM_SETUP_TOKEN="$TOKEN" \
  -e WEBTERM_PUBLIC_URL="http://$APP:8000" \
  -e WEBTERM_AGENT_INSECURE=1 \
  "$IMAGE" >/dev/null

# wait for health (python urllib, not curl — the runtime image has no curl)
for i in $(seq 1 30); do
  if pyrun <<'PY' 2>/dev/null
import urllib.request
urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=2)
PY
  then break; fi
  sleep 1
done

say "── account + demo fleet (seed.py in the container) ──"
docker cp "$ROOT/scripts/screenshots/seed.py" "$APP:/tmp/seed.py"
AGENTS=$(docker exec "$APP" python3 /tmp/seed.py "$EMAIL" "$PASSWORD" "$TOKEN")

say "── starting the real agents (hosts online) ──"
idx=0
while read -r _tag name tok; do
  [ "${_tag:-}" = "AGENT" ] || continue
  idx=$((idx+1))
  home="/tmp/agent$idx"
  cfg="{\"url\":\"ws://127.0.0.1:8000/agent/ws\",\"token\":\"$tok\",\"insecure\":true}"
  docker exec "$APP" sh -c "mkdir -p $home/.webterm && printf '%s' '$cfg' > $home/.webterm/agent.json"
  docker exec -d -e "HOME=$home" -e "WEBTERM_INSTANCE_ID=demo-$name" "$APP" \
    python3 /srv/webterm/agent/ptyd.py run
  say "   agent: $name"
done <<< "$AGENTS"

say "── demo files for the editor/browser (on agent 1) ──"
docker exec "$APP" sh -c 'mkdir -p /tmp/agent1/project'
docker exec "$APP" sh -c 'cat > /tmp/agent1/project/deploy.sh <<"EOS"
#!/usr/bin/env bash
# deploy.sh — run the migrations and restart the service (demo)
set -euo pipefail

APP_DIR=/opt/app
RELEASE="$(date +%Y%m%d-%H%M%S)"

echo "→ pulling code ($RELEASE)"
git -C "$APP_DIR" pull --ff-only

echo "→ database migrations"
"$APP_DIR/manage.py" migrate --noinput

echo "→ restarting the service"
systemctl restart app.service
echo "✓ deploy $RELEASE done"
EOS'
docker exec "$APP" sh -c 'cat > /tmp/agent1/project/app.py <<"EOS"
"""Minimal API (demo) — a typical web service you would administer from WebTerm."""
from fastapi import FastAPI

app = FastAPI(title="demo-api")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/users/{uid}")
def user(uid: int) -> dict:
    return {"id": uid, "role": "admin"}
EOS'
docker exec "$APP" sh -c 'cat > /tmp/agent1/project/config.yaml <<"EOS"
service: demo-api
listen: 0.0.0.0:8080
workers: 4
database:
  host: db-eu-1.intern
  pool: 20
cache:
  host: cache-02.intern
  ttl: 300
EOS'
docker exec "$APP" sh -c 'printf "fastapi==0.139.0\nuvicorn==0.34.0\npydantic==2.9.2\n" > /tmp/agent1/project/requirements.txt'
docker exec "$APP" sh -c 'printf "# demo-api\n\nAn example service administered through WebTerm.\n\n- \`deploy.sh\` — release\n- \`app.py\` — the code\n" > /tmp/agent1/project/README.md'
docker exec "$APP" sh -c 'printf "DATABASE_URL=postgres://app@db-eu-1.intern/app\nREDIS_URL=redis://cache-02.intern:6379/0\n" > /tmp/agent1/project/.env.example'

say "── waiting for the hosts to come online ──"
for i in $(seq 1 40); do
  n=$(pyrun 2>/dev/null <<'PY'
import urllib.request, json
d=json.load(urllib.request.urlopen("http://127.0.0.1:8000/api/hosts", timeout=3))
print(sum(1 for h in d if h.get("online")))
PY
) || true
  n=${n:-0}
  [ "$n" -ge 4 ] 2>/dev/null && { say "   $n host-uri online"; break; }
  sleep 1
done
sleep 6   # a few heartbeats → metrics/sparkline

say "── Playwright: capturing the screens (dark + light) ──"
# The `playwright` npm package is NOT in the mcr image (only the browsers, in /ms-playwright);
# we mount it from frontend/node_modules (1.61.1, matching the image's browsers). On a fresh
# clone that directory does not exist until you run `npm ci` in frontend/ — set PW_MODULES to
# point somewhere else if you keep it elsewhere.
PW_MODULES="${PW_MODULES:-$ROOT/frontend/node_modules}"
[ -d "$PW_MODULES/playwright" ] || {
  echo "playwright not found in $PW_MODULES — run 'npm ci' in frontend/, or set PW_MODULES" >&2
  exit 1
}
docker run --rm --network "$NET" \
  -v "$ROOT/scripts/screenshots:/work:ro" \
  -v "$PW_MODULES:/node_modules:ro" \
  -v "$OUT:/out" \
  -e BASE="http://$APP:8000" -e EMAIL="$EMAIL" -e PASSWORD="$PASSWORD" \
  "$PW_IMAGE" node /work/shots.mjs

say "✓ screenshots in $OUT"
ls -la "$OUT"
