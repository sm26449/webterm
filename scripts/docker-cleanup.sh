#!/usr/bin/env bash
# WebTerm — daily reclaim of old, unused Docker images and build cache on the gateway host (3.6.8).
#
#   sudo ./scripts/docker-cleanup.sh              clean up (webterm-docker-cleanup.timer runs it daily)
#   sudo ./scripts/docker-cleanup.sh --dry-run    only list what it would remove
#
# Tune: RETENTION (other images, default 336h = 14 days), BUILD_RETENTION (build cache, default
# 72h), WEBTERM_KEEP_IMAGES (WebTerm versions kept for rollback, default 7 — the same rule as
# upgrade.sh), LOG (default /var/log/webterm-docker-cleanup.log).
#
# Why it is in the repo: it used to be a hand-made /usr/local/bin script + /etc/cron.d entry on the
# prod host, not versioned and invisible to the app. Its `image prune -a --filter until=336h`
# also removed WebTerm images older than 14 days — i.e. the rollback targets upgrade.sh keeps on
# purpose. Now (security review 3.6.8, L2 — the 3.6.8 draft still ran a blanket `prune -a`, which
# also took the digest-pinned python tool image backup.sh needs, the previous Authentik image a
# rollback needs, and locally built WebTerm images):
#   * a PRESERVE set is built first: the tool image (by digest), every image this install's compose
#     files name (Authentik included), every image of any separate Authentik compose project (found
#     by its com.docker.compose.project label) plus the newest older Authentik version on disk (the
#     rollback target), the image of every container (running or stopped), and the running /
#     .env / .prev-image WebTerm images;
#   * dangling images not in it, and other unused images older than RETENTION not in it, are removed
#     ONE BY ONE with `docker image rm` (no -f: an image a container uses is refused) — never a
#     blanket `prune -a`; never a WebTerm image (label org.opencontainers.image.title=webterm, or a
#     repository named *webterm*) — step 3 owns those;
#   * WebTerm images: the newest WEBTERM_KEEP_IMAGES versions are kept, plus the one running and the
#     .prev-image rollback target — exactly upgrade.sh's rule; `docker image rm` refuses in-use ones;
#   * build cache older than BUILD_RETENTION: pruned;
#   * NEVER volumes (the database, the vault key, backups), NEVER containers, NEVER `system prune`.
# At the end it writes the `docker-cleanup` status for Settings → System health.
set -u
umask 022

usage() { sed -n '2,9p' "$SELF" | sed 's/^# \{0,1\}//'; }
note() { printf 'docker-cleanup: %s\n' "$*" >&2; }
die() { printf 'docker-cleanup: %s\n' "$*" >&2; exit "${RC:-1}"; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
SELF="$SCRIPT_DIR/$(basename "$0")"
ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
cd /

TEST_MODE=0
if [ "${WEBTERM_DOCKER_CLEANUP_TEST:-}" = 1 ]; then
  if [ "${EUID:-0}" = 0 ]; then
    note "WEBTERM_DOCKER_CLEANUP_TEST is ignored when running as root"
  else
    TEST_MODE=1
  fi
fi
DOCKER=docker
LOG=/var/log/webterm-docker-cleanup.log
if [ "$TEST_MODE" = 1 ]; then
  DOCKER="${DOCKER_TEST_BIN:-$DOCKER}"
  LOG="${LOG_TEST:-$LOG}"
fi
RETENTION="${RETENTION:-336h}"
BUILD_RETENTION="${BUILD_RETENTION:-72h}"
KEEP="${WEBTERM_KEEP_IMAGES:-7}"
DRY=0

case "${1:-}" in
  "") ;;
  --dry-run) DRY=1 ;;
  -h|--help) usage; exit 0 ;;
  *) RC=2 die "unknown argument: $1 (see --help)" ;;
esac
# the windows reach docker as filter values: plain durations only
printf '%s' "$RETENTION" | grep -Eq '^[0-9]{1,6}h$' || RC=2 die "RETENTION must look like 336h"
printf '%s' "$BUILD_RETENTION" | grep -Eq '^[0-9]{1,6}h$' || RC=2 die "BUILD_RETENTION must look like 72h"
case "$KEEP" in ''|*[!0-9]*) RC=2 die "WEBTERM_KEEP_IMAGES must be a number" ;; esac
[ "$KEEP" -ge 1 ] || RC=2 die "WEBTERM_KEEP_IMAGES must be at least 1"

if [ "${EUID:-0}" != 0 ] && [ "$TEST_MODE" != 1 ]; then
  RC=1 die "must run as root"
fi

# root trusts its own directory (it reads .env and .prev-image there): same rule as cert-renew.sh
safe_path() {
  local owner mode
  owner=$(stat -Lc '%u' -- "$1" 2>/dev/null) || return 1
  mode=$(stat -Lc '%a' -- "$1" 2>/dev/null) || return 1
  [ "$owner" = 0 ] && [ $(( 0$mode & 022 )) -eq 0 ]
}
INSTALL=0
[ -f "$ROOT/docker-compose.prod.yml" ] && [ -f "$ROOT/.env" ] && INSTALL=1
if [ "$TEST_MODE" != 1 ] && [ "$INSTALL" = 1 ]; then
  for p in "$ROOT" "$SCRIPT_DIR" "$SELF" "$ROOT/.env"; do
    safe_path "$p" || RC=2 die "refusing: $p must be owned by root and not writable by group/others"
  done
  d=$(dirname "$ROOT")
  while :; do
    mode=$(stat -Lc '%a' -- "$d" 2>/dev/null) || RC=2 die "refusing: cannot stat $d"
    if [ $(( 0$mode & 01000 )) -eq 0 ]; then
      safe_path "$d" || RC=2 die "refusing: parent $d must be owned by root and not writable by group/others"
    fi
    [ "$d" = / ] && break
    d=$(dirname "$d")
  done
fi

dk() { timeout 300 "$DOCKER" "$@"; }
ts() { date -Is; }
log() { printf '%s  %s\n' "$(ts)" "$*" >> "$LOG" 2>/dev/null || true; printf '%s\n' "$*"; }
free_pct() { df -P / 2>/dev/null | awk 'NR==2 { gsub("%","",$5); printf "%.1f", 100 - $5 }'; }

REMOVED=0
OTHER_REMOVED=0
FAILED=""
REFUSED=""
# shellcheck disable=SC2317,SC2329  # invoked through the EXIT trap below (2317: shellcheck ≤0.9, 2329: ≥0.10)
record_status() {
  local rc=$? st=ok msg pct
  if [ "$DRY" = 1 ]; then return; fi
  # df can fail (or print nothing): never write `"disk_free_pct":,` — invalid JSON is refused and
  # the run would look as if it never reported (security review 3.6.8, L5)
  pct=$(free_pct); [ -n "$pct" ] || pct=0
  if [ -n "$REFUSED" ]; then
    # audit 2026-10-17 OP-04: the daemon did not answer (or its answers do not add up) — say so,
    # never "ok, removed 0"
    st=error; msg="$REFUSED; nothing removed; disk / ${pct}% free"
  else
    msg="removed $REMOVED WebTerm image(s) and $OTHER_REMOVED other(s); disk / ${pct}% free"
    if [ -n "$FAILED" ]; then st=warn; msg="$FAILED failed; $msg"; fi
    [ "$rc" = 0 ] || { st=error; msg="exit code $rc; $msg"; }
  fi
  if [ -x "$SCRIPT_DIR/host-health.sh" ]; then
    "$SCRIPT_DIR/host-health.sh" --record docker-cleanup "$st" "$msg" \
      "{\"disk_free_pct\":$pct,\"images_removed\":$((REMOVED + OTHER_REMOVED))}" >/dev/null 2>&1 || true
  fi
}
trap record_status EXIT
# Every `dk` call below tolerates its own failure (|| true): one image docker cannot inspect must
# not stop the run. But a daemon that does not answer at all (stopped, socket blocked, `timeout`
# hit, docker not on PATH) left every list empty and the run reported `ok` with "removed 0" while
# the disk filled up (audit 2026-10-17, OP-04 — the disk-full incident of 2026-10-09). So the
# calls whose empty answer would mean "nothing to preserve" / "nothing on disk" are checked, and a
# daemon that does not answer ends the run with status `error` (exit 1: the unit fails too).
refuse_run() {
  REFUSED="$1"; FAILED="$FAILED docker"
  log "$1: nothing removed"
  exit 1
}
docker_down() { refuse_run "docker not reachable ($1)"; }

log "── start (retention=$RETENTION, build cache=$BUILD_RETENTION, keep $KEEP WebTerm versions$([ "$DRY" = 1 ] && echo ', DRY RUN')) — disk / $(free_pct)% free"

# ── the preserve set: image IDs that are never removed here (L2) ──────────────────────────────
# the digest-pinned python image backup.sh / restore.sh / host-health.sh run (tests keep it in step)
TOOL_IMAGE="python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
VER_RE='^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,3}$'
NL='
'
PRESERVE="$NL"
keep_id() { case "$1" in sha256:*) PRESERVE="$PRESERVE$1$NL" ;; esac; }
keep_ref() {
  [ -n "$1" ] || return 0
  keep_id "$(dk image inspect --format '{{.Id}}' "$1" 2>/dev/null | head -n1 || true)"
}
kept() { case "$PRESERVE" in *"$NL$1$NL"*) return 0 ;; esac; return 1; }
envval() { sed -n "s/^$1=//p" "$ROOT/.env" 2>/dev/null | tail -n1 | tr -d '"'"'"' ' || true; }

keep_ref "$TOOL_IMAGE"
[ "$INSTALL" = 1 ] && keep_ref "$(envval WEBTERM_TOOL_IMAGE)"
# the image of every container, running or stopped (`image rm` refuses those anyway)
# (`docker ps` failing = no preserve set at all: an empty one with images listed must never proceed)
cids=$(dk ps -aq --no-trunc 2>/dev/null) || docker_down "docker ps failed"
for c in $cids; do
  keep_id "$(dk inspect --format '{{.Image}}' "$c" 2>/dev/null || true)"
done
# every image this install's compose files name (the pinned Authentik, Postgres, Redis, Traefik…)
for f in "$ROOT/docker-compose.prod.yml" "$ROOT/docker-compose.yml" \
         "$ROOT/deploy/authentik/docker-compose.prod.yml" "$ROOT/deploy/authentik/docker-compose.yml"; do
  [ -f "$f" ] || continue
  for ref in $(sed -n -E "s/^[[:space:]]*image:[[:space:]]*[\"']?([^\"' #]+).*/\\1/p" "$f" | grep -v '[$]' || true); do
    keep_ref "$ref"
  done
done
# Authentik in any compose project (e.g. a separate stack in /opt/authentik): every image of that
# project, plus the newest LOCAL Authentik version older than the oldest one in use — the image
# a rollback (scripts/authentik-upgrade.sh restore) starts again
AK_FMT='{{.Image}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.service"}}|{{.Label "com.docker.compose.project.working_dir"}}'
ak_ps=$(dk ps -a --format "$AK_FMT" 2>/dev/null | grep -E '^([^|]*/)?goauthentik/server[:@]' || true)
for p in $(printf '%s\n' "$ak_ps" | cut -d'|' -f2 | sort -u); do
  printf '%s' "$p" | grep -Eq '^[a-z0-9][a-z0-9_-]{0,63}$' || continue
  for ref in $(dk ps -a --filter "label=com.docker.compose.project=$p" --format '{{.Image}}' 2>/dev/null \
                 | cut -d'|' -f1 | sort -u || true); do
    keep_ref "$ref"
  done
done
ALL=$(dk images --no-trunc --format '{{.ID}}|{{.Repository}}|{{.Tag}}|{{.CreatedAt}}' 2>/dev/null) || docker_down "docker images failed"
dk info >/dev/null 2>&1 || docker_down "docker info failed"
ak_inuse=$(printf '%s\n' "$ak_ps" | cut -d'|' -f1 | sed -n 's/.*goauthentik\/server:\([^@]*\).*/\1/p' \
             | grep -E "$VER_RE" | sort -V | head -n1 || true)
ak_local=$(printf '%s\n' "$ALL" | awk -F'|' '$2 ~ /(^|\/)goauthentik\/server$/ { print $3 "|" $1 }' \
             | grep -E '^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,3}[|]' | sort -t'|' -k1,1V || true)
if [ -n "$ak_inuse" ]; then
  ak_prev=$(printf '%s\n' "$ak_local" | awk -F'|' -v cur="$ak_inuse" '$1 != cur { print }' \
              | while IFS='|' read -r v id; do
                  [ "$(printf '%s\n%s\n' "$v" "$ak_inuse" | sort -V | head -n1)" = "$v" ] && echo "$id"
                done | tail -n1)
else
  ak_prev=$(printf '%s\n' "$ak_local" | tail -n2 | cut -d'|' -f2)    # nothing in use: keep the newest two
fi
for id in $ak_prev; do keep_id "$id"; done
# WebTerm: the running image, the one .env pins and the .prev-image rollback target
app=""; running_id=""; prev_id=""; cur_id=""
if [ "$INSTALL" = 1 ]; then
  app=$(dk ps -q --filter "label=com.docker.compose.service=app" \
          --filter "label=com.docker.compose.project.working_dir=$ROOT" 2>/dev/null | head -n1 || true)
  running_id=$([ -n "$app" ] && dk inspect --format '{{.Image}}' "$app" 2>/dev/null || true)
  prev=$([ -f "$ROOT/.prev-image" ] && head -n1 "$ROOT/.prev-image" || true)
  prev_id=$([ -n "$prev" ] && dk image inspect --format '{{.Id}}' "$prev" 2>/dev/null || true)
  cur=$(envval WEBTERM_IMAGE)
  cur_id=$([ -n "$cur" ] && dk image inspect --format '{{.Id}}' "$cur" 2>/dev/null || true)
  keep_id "$running_id"; keep_id "$prev_id"; keep_id "$cur_id"
fi
n_preserved=$(printf '%s' "$PRESERVE" | grep -c . || true)
log "preserved: $n_preserved image(s)"
# images on disk but nothing to preserve: not a state a WebTerm install can be in (its own app
# container, the tool image and the compose-pinned images are always there) — a daemon whose
# answers do not add up (`ps`/`inspect` empty while `images` lists), so refuse rather than remove
# with an empty preserve set. Its own wording: the daemon DID answer, "not reachable" would
# mislead whoever reads System health. Outside an install (INSTALL=0: no containers, the tool
# image never pulled) an empty set is legitimate and the run goes on.
if [ "$INSTALL" = 1 ] && [ "${n_preserved:-0}" = 0 ] && printf '%s' "$ALL" | grep -q .; then
  refuse_run "refusing: preserve set empty while images are listed (stack not running or tool image not pulled yet?)"
fi

# 1+2) dangling images, and other unused images older than RETENTION — one by one, never one in
# the preserve set, never a WebTerm image (step 3 below applies upgrade.sh's keep-N rule to those)
cutoff=$(( $(date +%s) - ${RETENTION%h} * 3600 ))
while IFS='|' read -r id repo tag created; do
  case "$id" in sha256:*) ;; *) continue ;; esac
  kept "$id" && continue
  case "$repo" in *webterm*) continue ;; esac
  if [ "$repo" = "<none>" ] && [ "$tag" = "<none>" ]; then
    what=dangling; ref="$id"
  else
    c=$(date -d "$(printf '%s' "$created" | awk '{print $1" "$2" "$3}')" +%s 2>/dev/null) || continue
    [ "$c" -lt "$cutoff" ] || continue
    what="older than $RETENTION"; ref="$repo:$tag"; [ "$tag" = "<none>" ] && ref="$id"
  fi
  title=$(dk image inspect --format '{{index .Config.Labels "org.opencontainers.image.title"}}' "$id" 2>/dev/null || true)
  [ "$title" = webterm ] && continue
  if [ "$DRY" = 1 ]; then
    log "would remove $ref ($what)"
    continue
  fi
  if dk image rm "$ref" >> "$LOG" 2>&1; then
    log "removed $ref ($what)"
    OTHER_REMOVED=$((OTHER_REMOVED + 1))
  fi
done <<EOF
$ALL
EOF

# 3) WebTerm images: keep the newest KEEP versions + the running one + the rollback target
if [ "$INSTALL" = 1 ]; then
  user=$(envval GHCR_USER)
  printf '%s' "$user" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$' || user=sm26449
  repo="ghcr.io/$(printf '%s' "$user" | tr '[:upper:]' '[:lower:]')/webterm"
  tags=$(dk images "$repo" --format '{{.Tag}}' 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)
  keep_tags=$(printf '%s\n' "$tags" | grep . | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -n "$KEEP" || true)
  for tag in $tags; do
    printf '%s\n' "$keep_tags" | grep -qx "$tag" && continue
    ref="$repo:$tag"
    id=$(dk image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)
    [ -n "$id" ] || continue
    [ "$id" = "$running_id" ] && continue
    [ "$id" = "$prev_id" ] && continue
    [ "$id" = "$cur_id" ] && continue
    if [ "$DRY" = 1 ]; then
      log "would remove $ref"
      continue
    fi
    drefs=$(dk image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" 2>/dev/null || true)
    # shellcheck disable=SC2086  # drefs is a whitespace-separated list of references
    if dk image rm "$ref" $drefs >> "$LOG" 2>&1; then
      log "removed $ref"
      REMOVED=$((REMOVED + 1))
    fi
  done
else
  log "not in a WebTerm install directory: WebTerm images left as they are"
fi

# 4) build cache older than its (shorter) window
if [ "$DRY" = 1 ]; then
  log "would prune build cache older than $BUILD_RETENTION"
else
  dk builder prune -f --filter "until=$BUILD_RETENTION" >> "$LOG" 2>&1 || FAILED="$FAILED builder-prune"
fi

log "── done — disk / $(free_pct)% free"

# keep the log bounded
if [ -f "$LOG" ] && [ ! -L "$LOG" ]; then
  tail -n 1000 "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG" 2>/dev/null || true
fi
exit 0
