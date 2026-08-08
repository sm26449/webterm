#!/usr/bin/env bash
# WebTerm — completely remove the GATEWAY from this machine.
#
#     ./remove.sh                 → show what would be deleted and ask for confirmation
#     ./remove.sh --keep-backups  → keep /var/backups/webterm
#     ./remove.sh --force         → continue even if agents are still enrolled
#
# THE ORDER MATTERS, which is why the script stops if you still have agents:
# an agent is uninstalled from its host THROUGH the gateway (the command travels the live link).
# Delete the gateway first and every machine in the fleet keeps an agent that retries forever,
# with its token, with systemd/cron supervision in place and a tmux server running. Cleanup
# then becomes manual, on each host separately.
#
# What the script does NOT remove (and tells you at the end): DNS records, the Cloudflare token,
# the GitHub/ghcr account, and the agents on hosts that were offline at uninstall time.
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$PWD"
KEEP_BACKUPS=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --keep-backups) KEEP_BACKUPS=1 ;;
    --force)        FORCE=1 ;;
    -h|--help)      sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# Teardown touches /etc/systemd and /var/backups: without root, `rm -f` returns EPERM and `set -e`
# kills the script AFTER the data volumes are already gone. Preflight, not half-measures.
[ "$(id -u)" = 0 ] || die "run with sudo — removal touches /etc/systemd and /var/backups"
command -v docker >/dev/null || die "docker is missing"
docker compose version >/dev/null 2>&1 && COMPOSE="docker compose" || COMPOSE="docker-compose"
FILE=docker-compose.prod.yml
[ -f "$FILE" ] || die "cannot find $FILE in $ROOT — are you running from the install directory?"

# `docker compose` honours COMPOSE_PROJECT_NAME from .env at CREATION time, so the volume filter
# must use the same name. Without that, on an install with a custom project name VOLS came out
# empty and the volumes holding the database and the vault key SURVIVED a removal reported as done.
[ -f .env ] && PROJ_ENV=$(grep -m1 '^COMPOSE_PROJECT_NAME=' .env 2>/dev/null | cut -d= -f2-) || PROJ_ENV=""

# The compose project name (default: the directory name). Every resource is filtered BY it: on a
# machine with two deployments, a `name=webterm` filter also matched the other instance's volumes
# — meaning `remove.sh` could delete someone else's data.
# extern, 2026-08-06.
PROJECT="${COMPOSE_PROJECT_NAME:-${PROJ_ENV:-$(basename "$ROOT" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')}}"
APP_CID=$($COMPOSE -f "$FILE" ps -q app 2>/dev/null | head -1)


# ── 1. are there still agents in the fleet? ──────────────────────────────────
say "Checking the fleet"
HOSTS=""
if [ -n "$APP_CID" ]; then
  HOSTS=$(docker exec "$APP_CID" python3 -c '
import sqlite3, sys, time
sys.path.insert(0, "/srv/webterm")
from app import config
try:
    d = sqlite3.connect("file:%s?mode=ro" % config.DB_PATH, uri=True)
    rows = list(d.execute("SELECT name, last_heartbeat FROM hosts"
                          " WHERE connection_type=? ORDER BY name", ("agent",)))
    print("QUERY_OK")          # sentinel: the query SUCCEEDED (even if the list is empty)
    for name, hb in rows:
        live = hb and (time.time() - hb) < 90
        print("%s\t%s" % (name, "ONLINE" if live else "offline"))
except Exception as e:
    print("QUERY_FAIL", e)
    raise SystemExit(1)
' 2>/dev/null || true)
else
  # We cannot check the fleet. This is exactly where to be strict: agents may still be enrolled,
  # and deleting the gateway would orphan one on every machine. "I do not know" is not
  # the same as "there are none".
  warn "the container is not running — I CANNOT read the host list from the database"
  if [ "$FORCE" != 1 ]; then
    echo "  Start the stack so I can check ($COMPOSE -f $FILE up -d), uninstall the agents"
    echo "  from the UI, then come back. Or, if you know what you are doing: ./remove.sh --force"
    die "stopping: I cannot confirm the fleet is clean"
  fi
  warn "--force: continuing without being able to check the fleet"
fi

# "could not query" is NOT "there are no agents": without the sentinel, any failure of `docker exec`
# (a failed import, a changed schema, a corrupt DB) turned the guard into a silent OK.
if [ -n "$APP_CID" ] && ! printf '%s' "$HOSTS" | grep -q '^QUERY_OK'; then
  warn "the container is running, but I could NOT read the host list from the database"
  if [ "$FORCE" != 1 ]; then
    die "stopping: I cannot confirm the fleet is clean (use --force if you know what you are doing)"
  fi
  warn "--force: continuing without being able to check the fleet"
fi
HOSTS=$(printf '%s\n' "$HOSTS" | grep -v '^QUERY_OK' || true)
if [ -n "$HOSTS" ]; then
  N=$(printf '%s\n' "$HOSTS" | grep -c . || true)
  ONLINE=$(printf '%s\n' "$HOSTS" | grep -c ONLINE || true)
  warn "$N host(s) with an enrolled agent ($ONLINE online):"
  printf '%s\n' "$HOSTS" | sed 's/^/      /'
  echo ""
  echo "  Uninstall them FIRST, while the gateway is alive:"
  echo "    UI → the host menu (⋯) → \"Uninstall the agent from the server\""
  echo ""
  echo "  For hosts that are NOT online (the agent cannot receive the command), run"
  echo "  on each of them, as the user the agent is installed under:"
  cat <<'MANUAL'
      systemctl --user disable --now webterm-agent.service 2>/dev/null || true
      rm -f ~/.config/systemd/user/webterm-agent.service
      # `if`, nu `||`: dacă `crontab -l` eşuează (fără crontab, cron.deny, spool ilizibil),
      # varianta veche scria înapoi un crontab GOL sau rula `crontab -r` — adică ştergea TOT
      # crontab-ul utilizatorului, nu doar liniile WebTerm.
      if CUR=$(crontab -l 2>/dev/null); then
        printf '%s\n' "$CUR" | grep -v 'webterm/ptyd.py' | grep -v 'webterm-watchdog' | crontab - || true
      fi
      pkill -f 'webterm/ptyd.py' || true
      tmux -L webterm kill-server 2>/dev/null || true
      rm -rf ~/.webterm
MANUAL
  echo ""
  if [ "$FORCE" != 1 ]; then
    die "stopping. Clean the fleet, then run again (or --force to continue anyway)."
  fi
  warn "--force: continuing, even though orphan agents will remain on the hosts above"
fi

# ── 2. what is about to disappear ────────────────────────────────────────────
say "What will be removed from this machine"
# the label compose applies — precise, unlike `--filter name=webterm`
VOLS=$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null || true)
echo "  containers:  $($COMPOSE -f "$FILE" ps --services 2>/dev/null | tr '\n' ' ')"
echo "  volumes:     ${VOLS:-<none>}   ← THE DATA (DB, vault key, transcripts)"
echo "  systemd:     webterm-backup.{service,timer}, webterm-cert-check.{service,timer}"
echo "  files:       $ROOT/{.env,docker-compose.prod.yml,*.sh,scripts/}"
if [ "$KEEP_BACKUPS" = 1 ]; then
  echo "  backups:     KEPT (/var/backups/webterm)"
else
  echo "  backups:     /var/backups/webterm  ← AND THE ARCHIVES"
fi

say "Do you want a final backup first?"
if [ -x scripts/backup.sh ] && [ -t 0 ]; then
  printf '  Take a backup now? [Y/n] '; read -r a
  case "$a" in [nN]*) warn "skipping the backup" ;; *) scripts/backup.sh || warn "the backup failed" ;; esac
fi

printf '\n\033[31mTYPE "DELETE EVERYTHING" to confirm (anything else cancels): \033[0m'
# `read` on a closed stdin (a non-interactive run) returns 1, and with `set -e` the script would
# die HERE, silently: you would see only an empty error code and not know whether anything was
# deleted. We treat EOF as an explicit refusal — total deletion never happens by inertia.
read -r confirm || confirm=""
[ "$confirm" = "DELETE EVERYTHING" ] || die "cancelled — nothing was deleted"

# ── 3. teardown, in order ────────────────────────────────────────────────────
say "Stopping the stack"
$COMPOSE -f "$FILE" down --remove-orphans || warn "compose down reported errors"

say "Removing the data volumes"
for v in $VOLS; do
  docker volume rm "$v" >/dev/null && echo "  removed: $v" || warn "could not remove volume $v"
done

say "Removing the systemd units"
for u in webterm-backup webterm-cert-check; do
  systemctl disable --now "$u.timer" >/dev/null 2>&1 || true
  systemctl disable --now "$u.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$u.timer" "/etc/systemd/system/$u.service"
done
# `--keep-backups` păstra arhivele şi ştergea parola care le descifrează — adică exact
# arhivele orfane despre care avertizează linia de mai sus. Arhivele fără parolă sunt zgomot
# criptografic: ocupă spaţiu şi nu se pot restaura niciodată.
if [ "$KEEP_BACKUPS" = 1 ]; then
  echo "  kept /etc/default/webterm-backup (it holds the passphrase for the archives you kept)"
else
  rm -f /etc/default/webterm-backup
fi
rm -f /etc/default/webterm-cert-check
systemctl daemon-reload 2>/dev/null || true
echo "  timers + units removed"

say "Removing the images"
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E "^ghcr\.io/[^/]+/webterm:" \
  | xargs -r docker rmi -f >/dev/null 2>&1 || true
echo "  webterm images removed"

if [ "$KEEP_BACKUPS" != 1 ]; then
  say "Removing the archives"
  rm -rf /var/backups/webterm
  echo "  /var/backups/webterm removed"
fi

say "Removing the installation files"
# .env holds the Cloudflare token and the setup token → we delete it rather than leave it behind
cd /
rm -rf "$ROOT"
echo "  $ROOT removed"

printf '\n\033[32m✓ WebTerm has been removed from this machine.\033[0m\n'
cat <<'REST'

What is left, and could not be removed from here:
  · the DNS record for the domain (and the wildcard one for forwards)
  · the Cloudflare token and any ghcr PAT — revoke them in those accounts
  · if you kept the backups: /var/backups/webterm (they hold the vault key — encrypted)
  · the agents on hosts that were offline at uninstall time
  · the firewall rules install.sh added, if it ran: `ufw` allows 80/tcp and 443/tcp, and
    it may have ENABLED ufw on a machine where it was off. Nothing here touches them,
    because we cannot tell which rules were yours. To undo ours:
        sudo ufw delete allow 80/tcp && sudo ufw delete allow 443/tcp
    and, only if ufw was off before WebTerm:  sudo ufw disable
  · Docker itself, its images and its networks beyond the ones listed above
REST
