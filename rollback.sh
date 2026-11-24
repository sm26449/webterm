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

# ── 3.8: graniţa migrării la criptarea la repaus (H1, recenzia PR4) ──────────────────────────
# Un volum migrat (keys.wtk, migrating.wtm, master.key, nume rezervate `.wt*`, seturi de restore
# 3.8) nu poate fi pornit de o imagine mai veche de 3.8: ea nu vede `data/secret`, îşi poate crea
# unul nou lângă keys.wtk, iar 3.8 refuză apoi volumul amestecat. Deci orice pornire a unei imagini
# < 3.8 (deploy, rollback automat sau manual, upgrade.sh spre o versiune veche) verifică întâi
# volumul. Imaginea ≥ 3.8 nu cere nimic. Orice îndoială (volum necunoscut, Docker care eşuează,
# imagine fără versiune pe un volum migrat) = refuz, cu instrucţiunile de recuperare.
image_era() {   # image_era IMAGE → 38 | pre38 | unknown
  local v rc=0
  v=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$1" 2>/dev/null) \
    || { echo unknown; return 0; }
  v=${v#v}
  if [[ "$v" =~ ^([0-9]+)\.([0-9]+)\. ]]; then
    if [ "${BASH_REMATCH[1]}" -gt 3 ] || { [ "${BASH_REMATCH[1]}" = 3 ] && [ "${BASH_REMATCH[2]}" -ge 8 ]; }; then
      echo 38
    else
      echo pre38
    fi
    return 0
  fi
  # fără etichetă (imagine construită local): codul de chei 3.8 e în imagine sau nu
  docker run --rm --network none --entrypoint sh "$1" -c 'test -f /srv/webterm/gateway/app/keys.py' \
    >/dev/null 2>&1 || rc=$?
  case "$rc" in 0) echo 38 ;; 1) echo pre38 ;; *) echo unknown ;; esac
}
data_volume_name() {   # data_volume_name COMPOSE_FILE → the effective name of the data volume, or ""
  local cid m
  if [ -n "${WEBTERM_VOLUME:-}" ]; then echo "$WEBTERM_VOLUME"; return 0; fi
  cid=$(docker compose -f "$1" ps -a -q app 2>/dev/null | head -n1) || cid=""
  if [ -n "$cid" ]; then
    m=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$cid" 2>/dev/null) || m=""
    if [ -n "$m" ]; then echo "$m"; return 0; fi
  fi
  docker compose -f "$1" config 2>/dev/null | awk '
    /^volumes:/ { inv = 1; next }
    /^[^ ]/ { inv = 0 }
    inv && /^  webterm-data:/ { inw = 1; next }
    inv && /^  [^ ]/ { inw = 0 }
    inw && /^    name:/ { sub(/^    name: */, ""); gsub(/"/, ""); print; exit }' || true
}
volume_38_markers() {   # volume_38_markers VOLUME IMAGE → names on stdout; 0 listed, 2 confirmed absent, 1 error
  local all ls
  all=$(docker volume ls -q) || return 1
  printf '%s\n' "$all" | grep -qxF "$1" || return 2
  ls=$(docker run --rm --network none -v "$1:/data:ro" --entrypoint ls "$2" -A1 /data) || return 1
  printf '%s\n' "$ls" | grep -E '^(keys\.wtk.*|migrating\.wtm.*|master\.key.*|erasures\.wtj|\.restore|restore-pending\..+|.*\.wt[a-z0-9]*)$' || true
}
guard_pre38() {   # guard_pre38 IMAGE COMPOSE_FILE → 0 may start; 1 refused (message printed)
  local era vol marks rc=0
  era=$(image_era "$1")
  [ "$era" = 38 ] && return 0
  vol=$(data_volume_name "$2")
  if [ -z "$vol" ]; then
    echo "✗ Refusing to start $1: it is not a 3.8 image (${era}) and the data volume of this installation" >&2
    echo "  cannot be determined, so it cannot be checked for the 3.8 encryption-at-rest migration." >&2
    echo "  Name it explicitly (docker volume ls) and run again:  WEBTERM_VOLUME=<name> $0 …" >&2
    return 1
  fi
  marks=$(volume_38_markers "$vol" "$1") || rc=$?
  [ "$rc" = 2 ] && return 0
  if [ "$rc" != 0 ]; then
    echo "✗ Refusing to start $1 (${era}): the data volume '$vol' could not be inspected for the 3.8" >&2
    echo "  encryption-at-rest migration (Docker error). Nothing was changed." >&2
    return 1
  fi
  [ -n "$marks" ] || return 0
  echo "✗ Refusing to start $1: the data volume '$vol' was migrated to 3.8 encryption at rest" >&2
  echo "  ($(printf '%s' "$marks" | tr '\n' ' '| sed 's/ $//')), and this image is $([ "$era" = pre38 ] && echo "older than 3.8" || echo "of an unknown version")." >&2
  echo "  A pre-3.8 gateway cannot read that volume: it would create a new vault key next to the" >&2
  echo "  protected one, and 3.8 then refuses the mixed volume. Nothing was changed." >&2
  echo "  Either stay on 3.8 (fix forward: ./deploy.sh <a 3.8.x version>), or go back to 3.7 the only" >&2
  echo "  safe way: restore the backup taken BEFORE the migration into a new volume" >&2
  echo "  (docs/INSTALL.md → Encryption at rest, \"Going back to 3.7\")." >&2
  return 1
}

# H1: înainte ca .env sau .prev-image să fie atinse — un refuz nu schimbă nimic
guard_pre38 "$PREV" "$FILE" || exit 1

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
