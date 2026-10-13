#!/usr/bin/env bash
# One Authentik upgrade step at a time, with a verified backup first and health checks after.
# Runbook: docs/AUTHENTIK-UPGRADE.md. Works on the standalone stack (/opt/authentik, services
# server/worker/postgresql) and on the bundled `authentik` profile of docker-compose.prod.yml
# (services authentik-server/authentik-worker/authentik-postgresql).
#
#   scripts/authentik-upgrade.sh [options] status
#   scripts/authentik-upgrade.sh [options] backup
#   scripts/authentik-upgrade.sh [options] upgrade <tag>       e.g. 2026.8.3
#   scripts/authentik-upgrade.sh [options] restore <backup-dir>
#   scripts/authentik-upgrade.sh [--unlisted-minor] check-hop <from> <to>   only say if a hop is allowed
#
# Options:
#   --dir DIR          directory holding the compose file and its .env   (default /opt/authentik)
#   --file NAME        compose file inside DIR (default: docker-compose.yml, compose.yml or
#                      docker-compose.prod.yml, the first that exists)
#   --project NAME     compose project name (default: compose's own, i.e. the directory name)
#   --backup-dir DIR   where backups go (default /var/backups/authentik-upgrade)
#   --min-free-gb N    refuse to start below N GB free on the Docker root (default 5)
#   --timeout SEC      how long to wait for healthy containers after `up` (default 900)
#   --unlisted-minor   allow a minor this script does not know yet (read its release notes first)
#   --yes              do not ask for confirmation (for rehearsals; never the default)
#
# What `upgrade` does, in order, printing each step before doing it:
#   1. pre-checks: stack healthy, current tag (running container == compose file), the hop is
#      allowed (patch inside the same minor, or exactly the NEXT minor — Authentik refuses skips
#      and has no downgrade), free disk, Postgres major;
#   2. backup (see `backup`) and verifies it — no backup, no upgrade;
#   3. pulls the target image while the old version still serves (no downtime yet);
#   4. edits the image tag of server+worker in the compose file (old file kept in the backup);
#   5. `up -d --no-deps` server+worker → downtime starts; waits for both healthy, zero unapplied
#      migrations, /-/health/ready/ and every OIDC discovery document → downtime ends;
#   6. prints the measured downtime and the exact rollback command.
# It never touches Postgres/Redis containers, volumes or images, and never removes anything.
set -euo pipefail

KNOWN_MINORS="2024.10 2024.12 2025.2 2025.4 2025.6 2025.8 2025.10 2025.12 2026.2 2026.5 2026.8"
IMAGE_REPO="ghcr.io/goauthentik/server"

DIR=/opt/authentik
FILE=""
PROJECT=""
BACKUP_ROOT=/var/backups/authentik-upgrade
MIN_FREE_GB=5
TIMEOUT=900
UNLISTED=0
YES=0

die() { echo "✗ $*" >&2; exit 1; }
say() { printf '\n── %s\n' "$*"; }
ok() { echo "  ✓ $*"; }

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR=${2:?}; shift 2 ;;
    --file) FILE=${2:?}; shift 2 ;;
    --project) PROJECT=${2:?}; shift 2 ;;
    --backup-dir) BACKUP_ROOT=${2:?}; shift 2 ;;
    --min-free-gb) MIN_FREE_GB=${2:?}; shift 2 ;;
    --timeout) TIMEOUT=${2:?}; shift 2 ;;
    --unlisted-minor) UNLISTED=1; shift ;;
    --yes) YES=1; shift ;;
    -h|--help) usage 0 ;;
    --) shift; break ;;
    -*) die "unknown option $1" ;;
    *) break ;;
  esac
done
CMD=${1:-}; shift || true
[ -n "$CMD" ] || usage 1

minor() { echo "$1" | cut -d. -f1,2; }
patch() { echo "$1" | cut -d. -f3; }
idx() { local i=0 m; for m in $KNOWN_MINORS; do [ "$m" = "$1" ] && { echo "$i"; return; }; i=$((i + 1)); done; echo -1; }
VER_RE='^20[0-9]{2}\.[0-9]{1,2}\.[0-9]+$'

# Is cur → target ONE allowed step? Prints why not and returns 1. Pure: no Docker, no files.
check_hop() {
  local cur=$1 target=$2 cm tm ci ti cy cn ty tn last
  [[ "$cur" =~ $VER_RE ]] || { echo "current version must look like 2026.8.3 (got '$cur')"; return 1; }
  [[ "$target" =~ $VER_RE ]] || { echo "target must look like 2026.8.3 (got '$target')"; return 1; }
  [ "$cur" != "$target" ] || { echo "already on $target"; return 1; }
  cm=$(minor "$cur"); tm=$(minor "$target"); ci=$(idx "$cm"); ti=$(idx "$tm")
  last=$(( $(echo "$KNOWN_MINORS" | wc -w) - 1 ))
  if [ "$cm" = "$tm" ]; then
    [ "$(patch "$target")" -gt "$(patch "$cur")" ] || { echo "$target is older than $cur — Authentik has no downgrade; use 'restore'"; return 1; }
    echo "patch upgrade inside $cm"
  elif [ "$ci" -ge 0 ] && [ "$ti" -ge 0 ]; then
    [ "$ti" -gt "$ci" ] || { echo "$target is older than $cur — Authentik has no downgrade; use 'restore'"; return 1; }
    [ "$ti" -eq $((ci + 1)) ] || { echo "skipping minors is not supported: from $cm the next step is $(echo "$KNOWN_MINORS" | tr ' ' '\n' | sed -n "$((ci + 2))p").x"; return 1; }
    echo "minor upgrade $cm → $tm (the next one in sequence) — read its release notes first"
  elif [ "$ti" -lt 0 ] && [ "$ci" -eq "$last" ] && [ "$UNLISTED" = 1 ]; then
    # security review 3.6.8 (L3): an unlisted minor must be NEWER — (year, minor) compared as
    # numbers. Before, `--unlisted-minor` from the last known minor accepted any unknown one,
    # 2025.9.0 included: a downgrade, which Authentik cannot do (one-way migrations).
    cy=${cm%%.*}; cn=${cm#*.}; ty=${tm%%.*}; tn=${tm#*.}
    if [ "$((10#$ty))" -lt "$((10#$cy))" ] || { [ "$((10#$ty))" -eq "$((10#$cy))" ] && [ "$((10#$tn))" -le "$((10#$cn))" ]; }; then
      echo "$target is older than $cur — Authentik has no downgrade; use 'restore'"; return 1
    fi
    echo "minor $tm is newer than this script knows; --unlisted-minor given"
  else
    echo "cannot verify that $cm → $tm is a single step (known: $KNOWN_MINORS). If $tm is the release right after $cm, re-run with --unlisted-minor"
    return 1
  fi
}

if [ "$CMD" = check-hop ]; then
  [ $# -eq 2 ] || die "usage: check-hop <from> <to>"
  if out=$(check_hop "$1" "$2"); then ok "$out"; exit 0; else die "$out"; fi
fi

[ -d "$DIR" ] || die "no such directory: $DIR"
DIR=$(cd "$DIR" && pwd)
if [ -z "$FILE" ]; then
  for f in docker-compose.yml compose.yml docker-compose.prod.yml; do
    [ -f "$DIR/$f" ] && { FILE=$f; break; }
  done
fi
[ -n "$FILE" ] && [ -f "$DIR/$FILE" ] || die "no compose file in $DIR (use --file)"
CF="$DIR/$FILE"

# As root, everything this script trusts must be root's: the script itself, the compose dir and
# file (root runs `docker compose` on it), the .env next to it, and every parent up to `/` (whoever
# can write a parent can swap the tree). Sticky parents (/tmp) are the one exception. Same rule as
# cert-renew.sh / host-health.sh.
safe_path() {   # 0 when owned by root and not group/world-writable
  local owner mode
  owner=$(stat -Lc '%u' -- "$1" 2>/dev/null) || return 1
  mode=$(stat -Lc '%a' -- "$1" 2>/dev/null) || return 1
  [ "$owner" = 0 ] && [ $(( 0$mode & 022 )) -eq 0 ]
}
safe_chain() {  # the path and every non-sticky parent
  local d=$1 mode
  safe_path "$d" || die "refusing: $d must be owned by root and not writable by group/others"
  while [ "$d" != / ]; do
    d=$(dirname "$d")
    mode=$(stat -Lc '%a' -- "$d" 2>/dev/null) || die "refusing: cannot stat $d"
    [ $(( 0$mode & 01000 )) -ne 0 ] && continue
    safe_path "$d" || die "refusing: parent $d must be owned by root and not writable by group/others"
  done
}
if [ "${EUID:-$(id -u)}" = 0 ]; then
  SELF=$(readlink -f -- "$0")
  safe_chain "$SELF"
  safe_chain "$DIR"
  safe_path "$CF" || die "refusing: $CF must be owned by root and not writable by group/others"
  if [ -e "$DIR/.env" ]; then
    safe_path "$DIR/.env" || die "refusing: $DIR/.env must be owned by root and not writable by group/others"
  fi
fi

dc() {
  if [ -n "$PROJECT" ]; then
    docker compose --project-directory "$DIR" -f "$CF" -p "$PROJECT" "$@"
  else
    docker compose --project-directory "$DIR" -f "$CF" "$@"
  fi
}

# --- service names (standalone stack vs. bundled profile) ---------------------------------
SERVICES=$(dc config --services 2>/dev/null; COMPOSE_PROFILES=authentik dc config --services 2>/dev/null) || true
pick() { for s in "$@"; do grep -qx "$s" <<<"$SERVICES" && { echo "$s"; return; }; done; }
SRV=$(pick server authentik-server)
WRK=$(pick worker authentik-worker)
PG=$(pick postgresql authentik-postgresql)
[ -n "$SRV" ] && [ -n "$WRK" ] && [ -n "$PG" ] || die "could not find server/worker/postgresql services in $CF"

cid() { dc ps -q "$1" 2>/dev/null | head -1; }
health() { local c; c=$(cid "$1"); [ -n "$c" ] || { echo missing; return; }
  docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$c"; }
running_tag() { local c; c=$(cid "$SRV"); [ -n "$c" ] || return 0
  docker inspect -f '{{.Config.Image}}' "$c" | sed -n "s|^${IMAGE_REPO}:||p"; }
file_tags() { grep -E "^[[:space:]]*image:[[:space:]]*\"?${IMAGE_REPO}:" "$CF" \
  | sed -E "s|.*${IMAGE_REPO}:([^\" ]+).*|\1|" | sort -u; }
pg_major() { dc exec -T "$PG" psql -U authentik -d authentik -Atc 'show server_version' 2>/dev/null \
  | cut -d. -f1 | tr -d '\r'; }
# Python inside the server image (no curl/wget there): readiness + every discovery document.
probe() {
  dc exec -T "$SRV" python - <<'EOF'
import json, sys, urllib.request
base = "http://localhost:9000"
try:
    assert urllib.request.urlopen(base + "/-/health/ready/", timeout=5).status == 200
except Exception as e:
    print("not ready: %s" % e); sys.exit(1)
EOF
}
discovery() {
  # every OAuth2 application's discovery document must answer 200 with an issuer
  dc exec -T "$SRV" ak shell -c '
import json, urllib.request
from authentik.core.models import Application
bad = 0
for a in Application.objects.filter(provider__oauth2provider__isnull=False):
    u = "http://localhost:9000/application/o/%s/.well-known/openid-configuration" % a.slug
    try:
        d = json.load(urllib.request.urlopen(u, timeout=10)); print("DISCOVERY ok %s %s" % (a.slug, d["issuer"]))
    except Exception as e:
        bad += 1; print("DISCOVERY FAIL %s %s" % (a.slug, e))
print("DISCOVERY_BAD=%d" % bad)
' 2>/dev/null | grep -E '^DISCOVERY'
}
unapplied() { dc exec -T "$WRK" ak showmigrations --plan 2>/dev/null | grep -c '^\[ \]' || true; }
version_in_app() { dc exec -T "$SRV" python -c 'import authentik; print(authentik.VERSION)' 2>/dev/null | tr -d '\r'; }

confirm() {
  [ "$YES" = 1 ] && return 0
  [ -t 0 ] || die "refusing to continue without a terminal (use --yes only on a rehearsal)"
  local a; read -r -p "  Type 'yes' to continue: " a; [ "$a" = yes ] || die "aborted"
}

free_gb() { df -P --block-size=1G "$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /)" | awk 'NR==2{print $4}'; }

status() {
  say "Authentik stack: $CF${PROJECT:+ (project $PROJECT)}"
  echo "  services:       $SRV / $WRK / $PG"
  echo "  running tag:    $(running_tag || true)"
  echo "  compose tag(s): $(file_tags | tr '\n' ' ')"
  echo "  version (app):  $(version_in_app || echo '?')"
  echo "  health:         server=$(health "$SRV") worker=$(health "$WRK") postgresql=$(health "$PG")"
  echo "  postgres major: $(pg_major || echo '?')"
  echo "  free disk:      $(free_gb) GB (Docker root)"
}

# --- backup: pg_dump -Fc + compose + .env + blueprints + /media, verified ------------------
do_backup() {
  local tag ts out n users
  tag=$(running_tag); ts=$(date +%Y%m%d-%H%M%S)
  out="$BACKUP_ROOT/authentik-${tag:-unknown}-$ts"
  say "Backup → $out"
  [ "$(health "$PG")" = healthy ] || die "postgresql is not healthy — refusing to back up"
  umask 077; mkdir -p "$out"
  dc exec -T "$PG" pg_dump -U authentik -d authentik -Fc > "$out/authentik.dump"
  [ -s "$out/authentik.dump" ] || die "pg_dump produced an empty file"
  # verify: the archive's table of contents is readable and holds the core tables' data
  # (captured first: `pg_restore -l | grep -q` would SIGPIPE pg_restore and trip pipefail)
  local toc; toc=$(dc exec -T "$PG" pg_restore -l < "$out/authentik.dump") \
    || die "backup verification failed: pg_restore cannot read the dump"
  n=$(grep -c 'TABLE DATA' <<<"$toc" || true)
  grep -q 'TABLE DATA public authentik_core_user ' <<<"$toc" \
    || die "backup verification failed: no authentik_core_user data in the dump"
  users=$(dc exec -T "$PG" psql -U authentik -d authentik -Atc 'select count(*) from authentik_core_user' | tr -d '\r')
  cp -p "$CF" "$out/$FILE"
  [ -f "$DIR/.env" ] && cp -p "$DIR/.env" "$out/env"
  [ -d "$DIR/blueprints" ] && tar -C "$DIR" -czf "$out/blueprints.tgz" blueprints
  [ -d "$DIR/secrets" ] && tar -C "$DIR" -czf "$out/secrets.tgz" secrets
  # /media (uploaded icons, backgrounds) and /certs only if the server actually has them mounted
  local m
  for m in /media /certs /templates; do
    if docker inspect -f '{{range .Mounts}}{{println .Destination}}{{end}}' "$(cid "$SRV")" | grep -qx "$m"; then
      dc exec -T "$SRV" tar -C "$m" -czf - . > "$out/$(basename "$m").tgz"
    fi
  done
  {
    echo "date=$ts"; echo "tag=$tag"; echo "compose=$CF"; echo "project=${PROJECT:-<compose default>}"
    echo "pg_major=$(pg_major)"; echo "users=$users"; echo "dump_table_data_entries=$n"
  } > "$out/meta"
  (cd "$out" && sha256sum -- * > SHA256SUMS)
  ok "dump $(du -h "$out/authentik.dump" | cut -f1), $n table-data entries, $users users; files: $(cd "$out" && echo *)"
  BACKUP_OUT=$out
}

wait_healthy() {
  local t0=$1 s w rc
  while :; do
    s=$(health "$SRV"); w=$(health "$WRK")
    [ "$s" = healthy ] && [ "$w" = healthy ] && probe >/dev/null 2>&1 && return 0
    # a crash loop (e.g. InconsistentMigrationHistory) never heals by waiting: fail fast
    rc=$(docker inspect -f '{{.RestartCount}}' "$(cid "$SRV")" 2>/dev/null || echo 0)
    [ "${rc:-0}" -ge 3 ] && { echo "  server restarted $rc times (crash loop)"; return 1; }
    [ $(( $(date +%s) - t0 )) -gt "$TIMEOUT" ] && { echo "  server=$s worker=$w"; return 1; }
    sleep 3
  done
}

do_upgrade() {
  local target=${1:-} cur ft hop
  [[ "$target" =~ $VER_RE ]] || die "target must look like 2026.8.3 (got '$target')"
  status
  say "Pre-checks"
  cur=$(running_tag); ft=$(file_tags)
  [ -n "$cur" ] || die "server container is not running — start the stack on its CURRENT tag first"
  [ "$(printf '%s\n' "$ft" | wc -l)" = 1 ] && [ "$ft" = "$cur" ] \
    || die "compose file tag(s) [$ft] differ from the running tag [$cur] — reconcile first"
  [ "$(health "$SRV")" = healthy ] && [ "$(health "$WRK")" = healthy ] && [ "$(health "$PG")" = healthy ] \
    || die "stack is not fully healthy — do not upgrade a sick IdP"
  hop=$(check_hop "$cur" "$target") || die "$hop"
  ok "$hop"
  local pgm; pgm=$(pg_major); ok "postgres major $pgm"
  [ "${pgm:-0}" -ge 14 ] || die "Postgres $pgm is too old for current Authentik — upgrade Postgres first (runbook §PG)"
  local fg; fg=$(free_gb); [ "$fg" -ge "$MIN_FREE_GB" ] || die "only ${fg} GB free (< $MIN_FREE_GB)"; ok "$fg GB free"

  say "Plan"
  echo "  1. backup to $BACKUP_ROOT (pg_dump -Fc, verified) + compose/.env/blueprints"
  echo "  2. docker pull $IMAGE_REPO:$target   (no downtime)"
  echo "  3. $FILE: $IMAGE_REPO:$cur → $IMAGE_REPO:$target (server + worker)"
  echo "  4. docker compose up -d --no-deps $SRV $WRK   ← downtime starts"
  echo "  5. wait: healthy, 0 unapplied migrations, discovery documents  ← downtime ends"
  confirm

  do_backup
  say "Pull $IMAGE_REPO:$target"
  docker pull -q "$IMAGE_REPO:$target" >/dev/null || die "pull failed — nothing changed"
  ok "pulled"

  say "Switch tag in $FILE"
  sed -i -E "s#(${IMAGE_REPO}:)${cur//./\\.}([\" ]|\$)#\1${target}\2#" "$CF"
  [ "$(file_tags)" = "$target" ] || { cp -p "$BACKUP_OUT/$FILE" "$CF"; die "tag edit failed — compose file restored"; }
  ok "$(file_tags)"

  say "Recreate $SRV + $WRK (migrations run on start)"
  local t0 t1; t0=$(date +%s)
  dc up -d --no-deps "$SRV" "$WRK"
  if ! wait_healthy "$t0"; then
    echo "  last server errors:"; dc logs --tail 200 "$SRV" 2>&1 | grep -E 'Error|Exception' | tail -5 | sed 's/^/    /'
    die "not healthy (see above). Rollback: $0 --dir $DIR${PROJECT:+ --project $PROJECT} --backup-dir $BACKUP_ROOT restore $BACKUP_OUT"
  fi
  t1=$(date +%s)
  ok "healthy after $((t1 - t0))s (this is the downtime)"

  say "Post-checks"
  local v u d
  v=$(version_in_app); [ "$v" = "$target" ] || die "app reports version '$v', expected $target"
  ok "version $v"
  u=$(unapplied); [ "$u" = 0 ] || die "$u unapplied migrations"
  ok "0 unapplied migrations"
  d=$(discovery || true); printf '%s\n' "$d" | sed 's/^/  /'
  grep -q '^DISCOVERY_BAD=0$' <<<"$d" || die "an OIDC discovery document is not served"
  echo
  echo "Done: $cur → $target, downtime $((t1 - t0))s. Backup: $BACKUP_OUT"
  echo "Rollback (restores the DB as it was before this step + the old tag):"
  echo "  $0 --dir $DIR${PROJECT:+ --project $PROJECT} --backup-dir $BACKUP_ROOT restore $BACKUP_OUT"
}

# --- restore: the ONLY way back once migrations have run --------------------------------------
do_restore() {
  local b=${1:-} oldtag
  [ -n "$b" ] && [ -s "$b/authentik.dump" ] && [ -f "$b/meta" ] || die "not a backup directory: '$b'"
  (cd "$b" && sha256sum -c --quiet SHA256SUMS) || die "backup checksums do not match"
  oldtag=$(sed -n 's/^tag=//p' "$b/meta")
  [ -f "$b/$FILE" ] || die "backup has no $FILE"
  say "Restore $b"
  echo "  This DROPS the current authentik database and replaces it with the dump, then runs"
  echo "  $SRV/$WRK on $oldtag again. Anything changed in Authentik since the backup is lost."
  confirm
  local t0; t0=$(date +%s)
  dc stop "$SRV" "$WRK"
  dc exec -T "$PG" psql -U authentik -d postgres -v ON_ERROR_STOP=1 \
    -c 'DROP DATABASE IF EXISTS authentik WITH (FORCE)' -c 'CREATE DATABASE authentik OWNER authentik'
  dc exec -T "$PG" pg_restore -U authentik -d authentik --exit-on-error --no-owner --role=authentik < "$b/authentik.dump"
  ok "database restored"
  cp -p "$b/$FILE" "$CF"; ok "$FILE restored (tag $oldtag)"
  dc up -d --no-deps "$SRV" "$WRK"
  wait_healthy "$t0" || die "not healthy after restore — check: docker compose logs $SRV"
  ok "healthy on $(version_in_app) after $(( $(date +%s) - t0 ))s"
  discovery | sed 's/^/  /'
}

mkroot() { mkdir -p "$BACKUP_ROOT" && chmod 700 "$BACKUP_ROOT"; }

case "$CMD" in
  status) status ;;
  backup) mkroot; do_backup; echo "backup: $BACKUP_OUT" ;;
  upgrade) mkroot
           exec 9>"$BACKUP_ROOT/.lock"; flock -n 9 || die "another upgrade is running"
           do_upgrade "${1:-}" ;;
  restore) mkroot; exec 9>"$BACKUP_ROOT/.lock"; flock -n 9 || die "another upgrade is running"
           do_restore "${1:-}" ;;
  *) usage 1 ;;
esac
