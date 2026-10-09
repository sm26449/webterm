#!/usr/bin/env bash
# Generates the screenshots for README/docs with FICTIONAL DATA (not the real hosts).
# It starts an ephemeral WebTerm (empty DB), seeds a demo fleet plus real agents in the
# container (so they show up online with metrics), demo files, then runs Playwright (in
# its own container, on the same network) to capture the key screens in dark + light,
# plus a phone capture, and finally shrinks the PNGs with pngquant.
#
#   scripts/screenshots/run.sh [out_dir]          # default out_dir: docs/screenshots
#
# Env knobs:
#   WEBTERM_IMAGE=…   image to capture (default: ghcr.io/sm26449/webterm:v<GATEWAY_VERSION>)
#   PW_MODULES=…      a node_modules dir holding the `playwright` package (default: frontend/node_modules)
#   ONLY=a,b          capture only these steps (dashboard,terminal,host,files,security,fleet,phone;
#                     opt-in, never in the default run: copy — the folder-copy UI, for review)
#   KEEP=1            leave the demo container running afterwards (iterate on shots.mjs)
#   REUSE=1           reuse a container left by KEEP=1 instead of seeding a new one
#   OPTIMIZE=0        skip the pngquant pass
#
# Prereq: docker plus the WebTerm image and mcr.microsoft.com/playwright:v1.63.0-noble
# locally. No node dependency on the host beyond `npm ci` in frontend/ (for the package).
# Nothing is left behind unless KEEP=1 (container + network wt-shots-*).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/docs/screenshots}"
VERSION="$(sed -n 's/^GATEWAY_VERSION = "\(.*\)"/\1/p' "$ROOT/gateway/app/config.py")"
IMAGE="${WEBTERM_IMAGE:-ghcr.io/sm26449/webterm:v$VERSION}"
PW_IMAGE="mcr.microsoft.com/playwright:v1.63.0-noble"
NET=wt-shots-net
APP=wt-shots-app
TOKEN=shots-setup-token
EMAIL="demo@example.com"
PASSWORD="parola-demo-123456"

say() { printf '\033[1;36m%s\033[0m\n' "$*"; }
pyrun() { docker exec -i "$APP" python3 - "$@"; }   # run python from stdin inside the container

cleanup() {
  docker rm -f "$APP" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
if [ "${KEEP:-0}" = 1 ]; then
  trap 'say "KEEP=1: $APP left running — re-run with REUSE=1, remove with: docker rm -f $APP; docker network rm $NET"' EXIT
else
  trap cleanup EXIT
fi
mkdir -p "$OUT"

reuse=0
if [ "${REUSE:-0}" = 1 ] && [ "$(docker inspect -f '{{.State.Running}}' "$APP" 2>/dev/null)" = true ]; then
  reuse=1
  say "── reusing the running $APP ──"
fi

if [ "$reuse" = 0 ]; then
cleanup
say "── starting an ephemeral WebTerm ($IMAGE) ──"
docker network create "$NET" >/dev/null
docker run -d --name "$APP" --network "$NET" --hostname web-01 \
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

say "── host polish: tmux (persistent sessions) + an @reboot entry (\"starts at boot\") ──"
# Without tmux the host page shows a "sessions do not survive" banner; without a boot entry
# every host carries a "won't come back after a reboot" warning. Both are true of this
# throwaway container, and both would distract from what the screenshots are about.
docker exec "$APP" sh -c 'apt-get update -qq >/dev/null 2>&1 &&
  apt-get install -y -qq --no-install-recommends tmux >/dev/null 2>&1' \
  || say "   (tmux not installed — sessions will show as not persistent)"
# drop the package lists again, or every host gets the same "N OS updates pending" badge
docker exec "$APP" sh -c 'rm -rf /var/lib/apt/lists/*'
docker exec "$APP" sh -c 'cat > /usr/local/bin/crontab <<"EOS"
#!/bin/sh
# screenshot shim: report the installer'"'"'s two cron lines, accept (and drop) writes
[ "$1" = "-l" ] && printf "%s\n" "@reboot python3 ~/.webterm/ptyd.py start # webterm" \
  "* * * * * python3 ~/.webterm/ptyd.py start # webterm-watchdog"
exit 0
EOS
chmod +x /usr/local/bin/crontab'

say "── starting the real agents (hosts online) ──"
idx=0
while read -r _tag name tok; do
  [ "${_tag:-}" = "AGENT" ] || continue
  idx=$((idx+1))
  home="/home/$name"; [ "$idx" = 1 ] && home=/root   # web-01 = root's real home
  cfg="{\"url\":\"ws://127.0.0.1:8000/agent/ws\",\"token\":\"$tok\",\"insecure\":true}"
  docker exec "$APP" sh -c "mkdir -p $home/.webterm && printf '%s' '$cfg' > $home/.webterm/agent.json"
  # shell integration pre-installed (the Commands panel works from the first prompt) and a
  # prompt carrying the demo host's name — every agent shares this one container
  docker exec "$APP" sh -c "cp /srv/webterm/agent/shell-integration.sh $home/.webterm/ &&
    printf '%s\n' \"PS1='\\\\[\\\\e[1;32m\\\\]\\\\u@$name\\\\[\\\\e[0m\\\\]:\\\\[\\\\e[1;34m\\\\]\\\\w\\\\[\\\\e[0m\\\\]# '\" \
      'alias ls=\"ls --color=auto\"' \
      '[ -f ~/.webterm/shell-integration.sh ] && . ~/.webterm/shell-integration.sh' > $home/.bashrc &&
    echo '. ~/.bashrc' > $home/.bash_profile"   # the agent starts a login shell
  # what the "Deployed release" saved command reads; cache-01 has none (a failed row)
  case "$name" in
    web-01|web-02) rel="demo-api 2.14.1  deployed 2026-10-06 18:42" ;;
    db-01)         rel="postgres 16.4    schema rev 0087" ;;
    *)             rel="" ;;
  esac
  [ -n "$rel" ] && docker exec "$APP" sh -c "echo '$rel' > $home/RELEASE"
  # …and each agent reports its demo name as the hostname (instead of the container's), so
  # the sidebar reads root@web-02, not root@web-01 five times. Screenshot-only shim.
  # TMUX_TMPDIR per agent: they all run as root in one container and would otherwise share
  # (and reconcile away) each other's tmux server.
  docker exec "$APP" mkdir -p "$home/.tmux"
  docker exec -d -e "HOME=$home" -e "TMUX_TMPDIR=$home/.tmux" -e "WEBTERM_INSTANCE_ID=demo-$name" "$APP" python3 -c \
    "import runpy, socket, sys; name = sys.argv[1]; socket.gethostname = lambda: name; \
sys.argv = ['/srv/webterm/agent/ptyd.py', 'run']; \
runpy.run_path('/srv/webterm/agent/ptyd.py', run_name='__main__')" "$name"
  say "   agent: $name"
done <<< "$AGENTS"

say "── demo files for the editor/browser (on agent 1 = web-01) ──"
docker exec "$APP" sh -c 'mkdir -p /root/project/logs /root/project/static'
docker exec "$APP" sh -c 'cat > /root/project/deploy.sh <<"EOS"
#!/usr/bin/env bash
# deploy.sh — pull, migrate, restart the service (demo)
set -euo pipefail

APP_DIR=/opt/app
RELEASE="2.14.1"
DRY="${1:-}"

step() { printf "\033[1;36m→\033[0m %s\n" "$*"; }
run() {
  if [ "$DRY" = --dry-run ]; then printf "  \033[2m\$ %s\033[0m\n" "$*"
  else "$@"; fi
}

step "pulling code ($RELEASE)"
run git -C "$APP_DIR" pull --ff-only

step "database migrations"
run "$APP_DIR/manage.py" migrate --noinput

step "restarting the service"
run systemctl restart app.service

printf "\033[1;32m✓\033[0m deploy %s %s\n" "$RELEASE" "${DRY:+(dry run)}"
EOS
chmod +x /root/project/deploy.sh'
docker exec "$APP" sh -c 'cat > /root/project/app.py <<"EOS"
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
docker exec "$APP" sh -c 'cat > /root/project/config.yaml <<"EOS"
service: demo-api
listen: 0.0.0.0:8080
workers: 4
database:
  host: 10.0.2.11      # db-01
  pool: 20
cache:
  host: 10.0.3.21      # cache-01
  ttl: 300
EOS'
docker exec "$APP" sh -c 'printf "fastapi==0.139.0\nuvicorn==0.34.0\npydantic==2.9.2\n" > /root/project/requirements.txt'
docker exec "$APP" sh -c 'printf "# demo-api\n\nAn example service administered through WebTerm.\n\n- \`deploy.sh\` — release\n- \`app.py\` — the code\n" > /root/project/README.md'
docker exec "$APP" sh -c 'printf "DATABASE_URL=postgres://app@10.0.2.11/app\nREDIS_URL=redis://10.0.3.21:6379/0\n" > /root/project/.env.example'
docker exec "$APP" sh -c 'for d in 03 04 05 06; do for i in 1 2 3 4 5 6; do
  printf "10.0.1.%s - - [%s/Oct/2026:0%s:12:0%s] \"GET /health HTTP/1.1\" 200 15 \"-\" \"kube-probe/1.31\"\n" \
    $((20+i)) "$d" "$i" "$i"; done > /root/project/logs/access-2026-10-$d.log; done'
docker exec "$APP" sh -c 'head -c 180000 /dev/urandom > /root/project/static/bundle.js.gz; head -c 42000 /dev/urandom > /root/project/static/logo.png'
# a symbolic link inside a folder: copying the folder (ONLY=copy) lists it as "not copied"
docker exec "$APP" ln -sf bundle.js.gz /root/project/static/latest.js.gz

say "── waiting for the hosts to come online ──"
# one login, then poll /api/hosts (logging in on every poll would trip the login rate limit)
pyrun "$EMAIL" "$PASSWORD" <<'PY' || true
import http.cookiejar, json, sys, time, urllib.request
B = "http://127.0.0.1:8000"
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
req = urllib.request.Request(B + "/api/login", method="POST", headers={
    "Content-Type": "application/json", "Origin": B},
    data=json.dumps({"email": sys.argv[1], "password": sys.argv[2]}).encode())
op.open(req, timeout=10).read()
n = 0
for _ in range(60):
    n = sum(1 for h in json.load(op.open(B + "/api/hosts", timeout=5)) if h.get("online"))
    if n >= 4:
        break
    time.sleep(1)
print(f"   {n} hosts online")
op.open(urllib.request.Request(B + "/api/logout", method="POST", headers={"Origin": B}), timeout=10)
PY
sleep 8   # a few heartbeats → metrics/sparkline
fi

say "── Playwright: capturing the screens (dark + light, + phone) ──"
# The `playwright` npm package is NOT in the mcr image (only the browsers, in /ms-playwright);
# we mount it from frontend/node_modules (1.63.0, matching the image's browsers). On a fresh
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
  -e BASE="http://$APP:8000" -e EMAIL="$EMAIL" -e PASSWORD="$PASSWORD" -e ONLY="${ONLY:-}" \
  "$PW_IMAGE" node /work/shots.mjs

if [ "${OPTIMIZE:-1}" = 1 ]; then
  say "── shrinking the PNGs (pngquant, in the Playwright image) ──"
  # Lossy palette quantisation: UI captures have few colours, so 3–4× smaller at no visible
  # cost. --skip-if-larger keeps the original when quantisation would not help.
  docker run --rm -v "$OUT:/out" "$PW_IMAGE" sh -c '
    set -e
    apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends pngquant >/dev/null
    cd /out && for f in *.png; do
      pngquant --quality=70-92 --speed 1 --strip --skip-if-larger --force --output "$f" -- "$f" || true
    done
    chown '"$(id -u):$(id -g)"' /out/*.png'
fi

say "✓ screenshots in $OUT"
ls -la "$OUT"
