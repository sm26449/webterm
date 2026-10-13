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
# purpose. Now:
#   * dangling layers: always pruned;
#   * other unused images older than RETENTION: pruned, but never one labelled as a WebTerm image
#     (org.opencontainers.image.title=webterm);
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
FAILED=""
# shellcheck disable=SC2329  # invoked through the EXIT trap below
record_status() {
  local rc=$? st=ok msg
  if [ "$DRY" = 1 ]; then return; fi
  msg="removed $REMOVED WebTerm image(s); disk / $(free_pct)% free"
  if [ -n "$FAILED" ]; then st=warn; msg="$FAILED failed; $msg"; fi
  [ "$rc" = 0 ] || { st=error; msg="exit code $rc; $msg"; }
  if [ -x "$SCRIPT_DIR/host-health.sh" ]; then
    "$SCRIPT_DIR/host-health.sh" --record docker-cleanup "$st" "$msg" \
      "{\"disk_free_pct\":$(free_pct || echo 0),\"images_removed\":$REMOVED}" >/dev/null 2>&1 || true
  fi
}
trap record_status EXIT

log "── start (retention=$RETENTION, build cache=$BUILD_RETENTION, keep $KEEP WebTerm versions$([ "$DRY" = 1 ] && echo ', DRY RUN')) — disk / $(free_pct)% free"

# 1) dangling layers left behind by rebuilds
if [ "$DRY" = 1 ]; then
  log "would prune dangling images: $(dk images -q -f dangling=true 2>/dev/null | wc -l | tr -d ' ')"
else
  dk image prune -f >> "$LOG" 2>&1 || FAILED="$FAILED dangling-prune"
fi

# 2) other unused images older than the window — never a WebTerm image (label set by the CI build)
if [ "$DRY" = 1 ]; then
  log "would prune unused non-WebTerm images older than $RETENTION"
else
  dk image prune -a -f --filter "until=$RETENTION" \
    --filter 'label!=org.opencontainers.image.title=webterm' >> "$LOG" 2>&1 || FAILED="$FAILED image-prune"
fi

# 3) WebTerm images: keep the newest KEEP versions + the running one + the rollback target
if [ "$INSTALL" = 1 ]; then
  user=$(sed -n 's/^GHCR_USER=//p' "$ROOT/.env" | tail -n1 | tr -d '"'"'"' ')
  printf '%s' "$user" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$' || user=sm26449
  repo="ghcr.io/$(printf '%s' "$user" | tr '[:upper:]' '[:lower:]')/webterm"
  app=$(dk ps -q --filter "label=com.docker.compose.service=app" \
          --filter "label=com.docker.compose.project.working_dir=$ROOT" 2>/dev/null | head -n1 || true)
  running_id=$([ -n "$app" ] && dk inspect --format '{{.Image}}' "$app" 2>/dev/null || true)
  prev=$([ -f "$ROOT/.prev-image" ] && head -n1 "$ROOT/.prev-image" || true)
  prev_id=$([ -n "$prev" ] && dk image inspect --format '{{.Id}}' "$prev" 2>/dev/null || true)
  cur=$(sed -n 's/^WEBTERM_IMAGE=//p' "$ROOT/.env" | tail -n1 | tr -d '"'"'"' ')
  cur_id=$([ -n "$cur" ] && dk image inspect --format '{{.Id}}' "$cur" 2>/dev/null || true)
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
