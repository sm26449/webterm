#!/usr/bin/env bash
# WebTerm — roll production back to the image from before the last deploy.
# The panic button for when an update breaks the UI or the gateway and there is
# nothing you can do from the web interface: SSH into the server and run
#   cd /opt/webterm && ./rollback.sh
# It needs neither network nor CI: the previous image is already on the machine.
# Rollback is reversible — running ./rollback.sh again brings you forward (swap).
#
# What `.prev-image` holds is whatever `WEBTERM_IMAGE` was before the last deploy — since
# `upgrade.sh` pins by DIGEST (`ghcr.io/…/webterm@sha256:…`), that is a digest: the exact
# bytes that were running, not a tag that the registry may have re-pointed since. The
# human-readable tag travels alongside in `.prev-image-tag` (UI label only).
set -euo pipefail
cd "$(dirname "$0")"

FILE=docker-compose.prod.yml
COMPOSE="docker compose"
docker compose version >/dev/null 2>&1 || COMPOSE="docker-compose"

# set_env KEY VALUE — rewrites `.env` in-process (bash builtins only). The previous
# `sed -i "s|^K=.*|K=$V|"` put the value in sed's argv and interpreted `&`, `|` and `\`
# inside it; a rewrite loop has neither problem. Same helper as deploy.sh/install.sh.
set_env() {
  local k="$1" v="$2" tmp found=0 line
  tmp=$(mktemp .env.XXXXXX)
  if [ -f .env ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in
        "$k="*) [ "$found" = 1 ] && continue; printf '%s=%s\n' "$k" "$v"; found=1 ;;
        *) printf '%s\n' "$line" ;;
      esac
    done < .env > "$tmp"
  fi
  [ "$found" = 1 ] || printf '%s=%s\n' "$k" "$v" >> "$tmp"
  chmod 600 "$tmp" && mv "$tmp" .env
}

PREV_FILE=.prev-image
if [ ! -f "$PREV_FILE" ] || [ ! -s "$PREV_FILE" ]; then
  echo "✗ No $PREV_FILE — no previous deploy recorded to go back to."
  echo "  Manual alternative: point WEBTERM_IMAGE in .env at a known-good tag or digest"
  echo "  (docker images --digests | grep webterm), then: $COMPOSE -f $FILE up -d app"
  exit 1
fi
PREV=$(head -1 "$PREV_FILE")
PREV_TAG=$([ -f .prev-image-tag ] && head -1 .prev-image-tag || true)
CUR=$(grep '^WEBTERM_IMAGE=' .env | head -1 | cut -d= -f2- || true)
CUR_TAG=$(grep '^WEBTERM_IMAGE_TAG=' .env | head -1 | cut -d= -f2- || true)

if [ "$PREV" = "$CUR" ]; then
  echo "✗ The previous image ($PREV) is the same as the current one — nothing to do."
  exit 1
fi

echo "→ Rollback: ${CUR:-<unset>} → $PREV${PREV_TAG:+ ($PREV_TAG)}"
set_env WEBTERM_IMAGE "$PREV"
set_env WEBTERM_IMAGE_TAG "$PREV_TAG"
# swap: what is running now becomes the target of the next rollback (roll-forward)
[ -n "$CUR" ] && printf '%s\n' "$CUR" > "$PREV_FILE"
if [ -n "$CUR_TAG" ]; then printf '%s\n' "$CUR_TAG" > .prev-image-tag; else rm -f .prev-image-tag; fi

# `.env` e sursa de adevăr AICI, iar mediul o bate. `deploy.sh` exportă `WEBTERM_IMAGE` cu
# imaginea NOUĂ şi apoi face `exec ./rollback.sh` — deci variabila exportată supravieţuia, iar
# compose o prefera fişierului pe care tocmai îl rescrisesem. Rezultat: `up -d app` re-rezolva
# la imaginea STRICATĂ, containerul nu era recreat („Running", nu „Recreated"), iar rollback-ul
# automat pe care documentaţia îl listează ca strat de apărare nu făcea nimic. Verificat:
# `WEBTERM_IMAGE=x docker compose config` întoarce `x`, nu valoarea din `.env`.
unset WEBTERM_IMAGE WEBTERM_IMAGE_TAG
$COMPOSE -f "$FILE" up -d app

# wait for the healthcheck verdict, so you do not walk away from the keyboard guessing
APP_ID=$($COMPOSE -f "$FILE" ps -q app)
st=starting
for _ in $(seq 1 45); do
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$APP_ID" 2>/dev/null || echo missing)
  [ "$st" = healthy ] && break
  sleep 2
done
# Ce RULEAZĂ, nu ce am cerut. Mesajul de succes raporta `$PREV` fără să verifice nimic, deci
# anunţa „✓ Rollback done — the app is running v2.0.0" pe un container rămas pe imaginea veche.
RUNNING=$(docker inspect -f '{{.Config.Image}}' "$APP_ID" 2>/dev/null || echo "?")
if [ "$RUNNING" != "$PREV" ]; then
  echo "✗ Rollback did NOT take effect: the container is running $RUNNING, not $PREV."
  echo "  .env now says $PREV. Check for a WEBTERM_IMAGE exported in your shell, then:"
  echo "    env -u WEBTERM_IMAGE $COMPOSE -f $FILE up -d app"
  exit 1
fi
if [ "$st" = healthy ]; then
  echo "✓ Rollback done — the app is running $PREV${PREV_TAG:+ ($PREV_TAG)} (healthy)."
else
  echo "✗ The app did not report healthy within 90s (status: $st). Logs:"
  docker logs --tail 30 "$APP_ID" || true
  exit 1
fi
