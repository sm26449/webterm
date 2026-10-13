#!/usr/bin/env bash
# WebTerm — host-side health checks for Settings → System health (3.6.8).
#
#   sudo ./scripts/host-health.sh                  run the host checks, write their status files
#   sudo ./scripts/host-health.sh --install        install/refresh the host-health + docker-cleanup timers
#   sudo ./scripts/host-health.sh --record ID STATUS MESSAGE [DATA_JSON]
#                                                  write one status file (backup.sh, cert-check.sh,
#                                                  docker-cleanup.sh and restore.sh --verify call this)
#
# IDs: backup cert-check host-health cloudflare-token authentik-image docker-cleanup restore-verify
# STATUS: ok | warn | error | skipped
#
# Why: the host timers (backup, certificate check) reported only to journald, so a backup that
# failed every night, or a Cloudflare token that expired, stayed invisible until the day it
# mattered. The gateway cannot look at the host — and must not be able to: it gets no new
# privilege. Instead this script, run as root by a systemd timer, writes a small JSON status per
# check into the app's data volume (`host-status/<id>.json`). The gateway reads those files as
# UNTRUSTED input (schema, size, no symlinks), shows them in Settings → System health and alerts
# when one is in error or stale. The files carry a status and a short message — never a command,
# never a secret.
#
# What the checks look at (all read-only):
#   * which WebTerm timers are installed and enabled;
#   * the Cloudflare DNS token (DNS-01 certificates): `/user/tokens/verify`, status + expiry. The
#     token is read from secrets/cf_dns_api_token and handed to curl on stdin — it never appears on
#     a command line, in the output or in a status file;
#   * the Authentik image that runs vs the one the compose file pins (an upgrade must step through
#     versions, never jump straight to the pin — see docs/AUTHENTIK-UPGRADE.md).
set -eu
umask 022

usage() { sed -n '2,10p' "$SELF" | sed 's/^# \{0,1\}//'; }
note() { printf 'host-health: %s\n' "$*" >&2; }
die() { printf 'host-health: %s\n' "$*" >&2; exit "${RC:-1}"; }
say() { printf '%s\n' "$*"; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
SELF="$SCRIPT_DIR/$(basename "$0")"
ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
# Run from `/`: a python started in the caller's directory would put it first on sys.path (a
# planted json.py would run as root). Python is also started isolated (`-I`).
cd /

# Test mode: the overrides below exist only so the test suite can point the script at a fake tree,
# a fake docker/systemctl and a local fake Cloudflare API. They are honoured ONLY with
# WEBTERM_HOST_HEALTH_TEST=1 and NEVER as root (EUID is bash's own variable).
TEST_MODE=0
if [ "${WEBTERM_HOST_HEALTH_TEST:-}" = 1 ]; then
  if [ "${EUID:-0}" = 0 ]; then
    note "WEBTERM_HOST_HEALTH_TEST is ignored when running as root"
  else
    TEST_MODE=1
  fi
fi
DOCKER=docker
SYSTEMCTL=systemctl
SYSTEMD_DIR=/etc/systemd/system
CRON_DIR=/etc/cron.d
CF_API=https://api.cloudflare.com/client/v4
STATUS_BASE=""
TOOL_IMAGE="python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
if [ "$TEST_MODE" = 1 ]; then
  DOCKER="${DOCKER_TEST_BIN:-$DOCKER}"
  SYSTEMCTL="${WEBTERM_SYSTEMCTL:-$SYSTEMCTL}"
  SYSTEMD_DIR="${WEBTERM_SYSTEMD_DIR:-$SYSTEMD_DIR}"
  CRON_DIR="${WEBTERM_CRON_DIR:-$CRON_DIR}"
  CF_API="${WEBTERM_CF_API:-$CF_API}"
  STATUS_BASE="${WEBTERM_STATUS_BASE:-}"
fi
TIMERS="webterm-backup.timer webterm-cert-check.timer webterm-host-health.timer webterm-docker-cleanup.timer"

MODE=run
REC_ID="" REC_STATUS="" REC_MSG="" REC_DATA=""
case "${1:-}" in
  "") ;;
  --record)
    [ $# -ge 4 ] && [ $# -le 5 ] || RC=2 die "usage: --record ID STATUS MESSAGE [DATA_JSON]"
    MODE=record; REC_ID="$2"; REC_STATUS="$3"; REC_MSG="$4"; REC_DATA="${5:-}" ;;
  --install) [ $# -eq 1 ] || RC=2 die "--install takes no arguments"; MODE=install ;;
  -h|--help) usage; exit 0 ;;
  *) RC=2 die "unknown argument: $1 (see --help)" ;;
esac

if [ "${EUID:-0}" != 0 ] && [ "$TEST_MODE" != 1 ]; then
  if [ "$MODE" = record ]; then
    note "not root — status '$REC_ID' not recorded"
    exit 0                       # never break the caller (backup.sh run by hand, say)
  fi
  RC=1 die "must run as root (it reads the data volume and the systemd units)"
fi

# ── are we in a WebTerm install dir? ─────────────────────────────────────────
if ! { [ -f "$ROOT/docker-compose.prod.yml" ] && [ -f "$ROOT/.env" ]; }; then
  if [ "$MODE" = record ]; then
    note "$ROOT is not a WebTerm install directory — status '$REC_ID' not recorded"
    exit 0
  fi
  RC=2 die "$ROOT is not a WebTerm install directory (no docker-compose.prod.yml + .env)"
fi

# The same root-owned-path rule as cert-renew.sh: this runs as root and trusts its own directory,
# so each piece must be root's and not writable by group/others, and so must every parent (else a
# non-root user could put a tree of their own in its place). Sticky dirs (/tmp) are the exception.
safe_path() {   # safe_path PATH → 0 when owned by root and not group/world-writable
  local owner mode
  owner=$(stat -Lc '%u' -- "$1" 2>/dev/null) || return 1
  mode=$(stat -Lc '%a' -- "$1" 2>/dev/null) || return 1
  [ "$owner" = 0 ] && [ $(( 0$mode & 022 )) -eq 0 ]
}
if [ "$TEST_MODE" != 1 ]; then
  for p in "$ROOT" "$SCRIPT_DIR" "$SELF" "$ROOT/docker-compose.prod.yml" "$ROOT/deploy" \
           "$ROOT/secrets"; do
    [ -e "$p" ] || continue
    safe_path "$p" || RC=2 die "refusing: $p must be owned by root and not writable by group/others"
  done
  envf="$ROOT/.env"
  safe_path "$envf" || RC=2 die "refusing: $envf must be owned by root and not writable by group/others"
  if [ $(( 0$(stat -Lc '%a' -- "$envf") & 077 )) -ne 0 ] && [ "$(stat -Lc '%g' -- "$envf")" != 0 ]; then
    RC=2 die "refusing: $envf is readable by a non-root group (use 0600, or 0640 with group root)"
  fi
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

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

dk() { timeout 20 "$DOCKER" "$@"; }

# ── python helper (host python3, else the pinned tool image with no network) ──
# One program, three sub-commands: `write` (the status-file writer), `cf` (parse the Cloudflare
# answer), `ver` (validate a version tag). Values travel in argv, the program on stdin.
VOL=""
run_py() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -I - "$@"
  else
    dk run --rm -i --network none --entrypoint python3 -w / -v "$WORK:$WORK" \
      ${VOL:+-v "$VOL:/data"} "$TOOL_IMAGE" -I - "$@"
  fi
}

py_tool() {
  run_py "$@" <<'PYEOF'
import json, math, os, re, sys, time

IDS = ("backup", "cert-check", "host-health", "cloudflare-token", "authentik-image",
       "docker-cleanup", "restore-verify")
STATUSES = ("ok", "warn", "error", "skipped")
KEY = re.compile(r"^[a-z_]{1,32}$")
SUBKEY = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


def refuse(msg):
    print("host-health: refused: " + msg, file=sys.stderr)
    sys.exit(2)


def scalar(v, nested=False):
    if isinstance(v, bool) or (isinstance(v, int) and abs(v) < 2 ** 53):
        return True
    if isinstance(v, float) and not nested:
        return math.isfinite(v)
    return isinstance(v, str) and len(v) <= 128


def clean_data(raw):
    if not raw:
        return {}
    if len(raw.encode("utf-8")) > 1024:
        refuse("DATA_JSON is larger than 1024 bytes")
    try:
        obj = json.loads(raw, parse_constant=lambda c: refuse("non-finite number in DATA_JSON"))
    except ValueError:
        refuse("DATA_JSON is not valid JSON")
    if not isinstance(obj, dict) or len(obj) > 16:
        refuse("DATA_JSON must be an object with at most 16 keys")
    nested_seen = False
    for k, v in obj.items():
        if not KEY.match(k):
            refuse("bad DATA_JSON key")
        if isinstance(v, dict):
            if nested_seen or len(v) > 16:
                refuse("DATA_JSON allows one nested object of at most 16 entries")
            nested_seen = True
            for sk, sv in v.items():
                if not SUBKEY.match(sk) or not scalar(sv, nested=True):
                    refuse("bad nested DATA_JSON entry")
        elif not scalar(v):
            refuse("bad DATA_JSON value for %s" % k)
    return obj


def write(base, sid, status, message, data):
    if sid not in IDS:
        refuse("unknown status id")
    if status not in STATUSES:
        refuse("unknown status")
    msg = "".join(ch for ch in message if ch.isprintable())[:200]
    doc = {"v": 1, "id": sid, "status": status, "ts": int(time.time()), "message": msg,
           "data": clean_data(data)}
    blob = (json.dumps(doc, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    flags_dir = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        dfd = os.open(base, flags_dir)
    except OSError as e:
        refuse("cannot open the data volume (%s)" % e.strerror)
    try:
        try:
            os.mkdir("host-status", 0o755, dir_fd=dfd)
        except FileExistsError:
            pass
        try:
            hfd = os.open("host-status", flags_dir, dir_fd=dfd)
        except OSError:
            refuse("host-status is not a plain directory (symlink?) — nothing written")
        try:
            os.fchmod(hfd, 0o755)
            tmp = ".%s.%d.%s.tmp" % (sid, os.getpid(), os.urandom(4).hex())
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o644, dir_fd=hfd)
            try:
                os.write(fd, blob)
                os.fchmod(fd, 0o644)
                os.fsync(fd)
            finally:
                os.close(fd)
            # rename replaces whatever sits at <id>.json — a planted symlink included — without
            # following it
            os.rename(tmp, sid + ".json", src_dir_fd=hfd, dst_dir_fd=hfd)
        finally:
            os.close(hfd)
    finally:
        os.close(dfd)


def cf(path, code):
    """Cloudflare /user/tokens/verify answer → 'status|token_status|expires_on|message'."""
    if code in ("401", "403"):
        print("error|invalid||Cloudflare rejected the token (HTTP %s): revoked or wrong" % code)
        return
    try:
        with open(path, "rb") as f:
            doc = json.loads(f.read(65536).decode("utf-8", "replace"))
    except (OSError, ValueError):
        doc = None
    if code != "200" or not isinstance(doc, dict):
        print("warn|unknown||Cloudflare API unreachable or unexpected answer (HTTP %s)"
              % (code if re.match(r"^[0-9]{3}$", code) else "?"))
        return
    res = doc.get("result") if isinstance(doc.get("result"), dict) else {}
    st = str(res.get("status") or "")
    exp = str(res.get("expires_on") or "")
    if not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z?$", exp):
        exp = ""
    if not doc.get("success") or st not in ("active", "expired", "disabled"):
        print("error|invalid||Cloudflare does not accept the token")
        return
    if st != "active":
        print("error|%s|%s|the Cloudflare token is %s" % (st, exp, st))
        return
    if exp:
        import datetime
        t = datetime.datetime.strptime(exp[:19], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=datetime.timezone.utc).timestamp()
        days = (t - time.time()) / 86400
        if days <= 0:
            print("error|expired|%s|the Cloudflare token expired on %s" % (exp, exp[:10]))
            return
        if days <= 30:
            print("warn|active|%s|the Cloudflare token expires in %d days (%s)" % (exp, days, exp[:10]))
            return
        print("ok|active|%s|the Cloudflare token is active (expires %s)" % (exp, exp[:10]))
        return
    print("ok|active||the Cloudflare token is active (no expiry)")


cmd = sys.argv[1]
if cmd == "write":
    write(*sys.argv[2:7])
elif cmd == "cf":
    cf(sys.argv[2], sys.argv[3])
else:
    refuse("unknown helper command")
PYEOF
}

# ── where the status files go: the volume mounted at /data in the running app ──
BASE=""
find_base() {
  if [ -n "$STATUS_BASE" ]; then
    BASE="$STATUS_BASE"; return 0
  fi
  local cid project
  cid=$(dk ps -q --filter "label=com.docker.compose.service=app" \
          --filter "label=com.docker.compose.project.working_dir=$ROOT" 2>/dev/null | head -n1 || true)
  if [ -z "$cid" ]; then
    project=$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$ROOT/.env" | tail -n1 | tr -d '"'"'"'')
    [ -n "$project" ] || project=$(basename "$ROOT" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
    cid=$(dk ps -q --filter "label=com.docker.compose.service=app" \
            --filter "label=com.docker.compose.project=$project" 2>/dev/null | head -n1 || true)
  fi
  if [ -n "$cid" ]; then
    VOL=$(dk inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' \
            "$cid" 2>/dev/null || true)
  fi
  if [ -z "$VOL" ]; then
    project=$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$ROOT/.env" | tail -n1 | tr -d '"'"'"'')
    [ -n "$project" ] || project=$(basename "$ROOT" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
    VOL="${project}_webterm-data"
  fi
  printf '%s' "$VOL" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' || { VOL=""; return 1; }
  if command -v python3 >/dev/null 2>&1; then
    BASE=$(dk volume inspect -f '{{.Mountpoint}}' "$VOL" 2>/dev/null || true)
    [ -n "$BASE" ] && [ -d "$BASE" ] || return 1
  else
    dk volume inspect "$VOL" >/dev/null 2>&1 || return 1
    BASE=/data
  fi
}

record() {   # record ID STATUS MESSAGE [DATA_JSON]
  if [ -z "$BASE" ]; then
    find_base || { note "the WebTerm data volume was not found — status '$1' not recorded"; return 1; }
  fi
  py_tool write "$BASE" "$1" "$2" "$3" "${4:-}"
}

if [ "$MODE" = record ]; then
  record "$REC_ID" "$REC_STATUS" "$REC_MSG" "$REC_DATA"
  exit $?
fi

# ── --install: the host-health + docker-cleanup timers ──────────────────────
if [ "$MODE" = install ]; then
  if [ "$TEST_MODE" != 1 ] && { [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; }; then
    say "  no systemd on this host — timers not installed (run scripts/host-health.sh and"
    say "  scripts/docker-cleanup.sh from cron yourself)"
    exit 0
  fi
  changed=""
  for unit in webterm-host-health webterm-docker-cleanup; do
    svc="$SYSTEMD_DIR/$unit.service"
    if [ -f "$svc" ] && ! grep -q "^WorkingDirectory=$ROOT\$" "$svc"; then
      other=$(grep -m1 '^WorkingDirectory=' "$svc" | cut -d= -f2- || true)
      note "skipping $unit: it already belongs to ${other:-another install} (unit names are fixed)"
      continue
    fi
    for ext in service timer; do
      src="$ROOT/deploy/$unit.$ext"
      [ -f "$src" ] || { note "missing $src — skipped"; continue; }
      want="$WORK/$unit.$ext"
      if [ "$ext" = service ]; then sed -e "s|/opt/webterm|$ROOT|g" "$src" > "$want"; else cp "$src" "$want"; fi
      dst="$SYSTEMD_DIR/$unit.$ext"
      if [ -f "$dst" ] && cmp -s "$want" "$dst"; then continue; fi
      [ -f "$dst" ] && cp -p "$dst" "$dst.bak"
      install -m 0644 "$want" "$dst"
      say "  installed: $dst"
      changed="$changed $unit.$ext"
    done
  done
  if [ -n "$changed" ]; then
    "$SYSTEMCTL" daemon-reload || note "systemctl daemon-reload failed — run it by hand"
  fi
  for unit in webterm-host-health webterm-docker-cleanup; do
    [ -f "$SYSTEMD_DIR/$unit.timer" ] || continue
    grep -q "^WorkingDirectory=$ROOT\$" "$SYSTEMD_DIR/$unit.service" 2>/dev/null || continue
    if [ "$("$SYSTEMCTL" is-enabled "$unit.timer" 2>/dev/null || true)" != enabled ] \
       || [ -n "$changed" ]; then
      "$SYSTEMCTL" enable --now "$unit.timer" >/dev/null 2>&1 || note "could not enable $unit.timer"
    fi
  done
  # the hand-made cron job this timer replaces (a daily `docker image prune -a` that ignored the
  # rollback images): renamed, not deleted — cron ignores file names with a dot
  legacy="$CRON_DIR/webterm-docker-cleanup"
  if [ -f "$legacy" ] && [ ! -L "$legacy" ] && grep -q '/usr/local/bin/webterm-docker-cleanup' "$legacy"; then
    mv -f "$legacy" "$legacy.disabled-by-webterm"
    say "  the old cron job $legacy is now $legacy.disabled-by-webterm (replaced by webterm-docker-cleanup.timer)"
  fi
  [ -n "$changed" ] || say "  host-health / docker-cleanup timers already up to date"
  exit 0
fi

# ── the checks ───────────────────────────────────────────────────────────────
rc=0
find_base || die "the WebTerm data volume was not found (is the app of $ROOT deployed?)"

# 1. the timers
have_systemd=0
if [ "$TEST_MODE" = 1 ]; then
  [ -d "$SYSTEMD_DIR" ] && have_systemd=1
elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  have_systemd=1
fi
legacy=false
if [ -f "$CRON_DIR/webterm-docker-cleanup" ] && grep -q '/usr/local/bin/webterm-docker-cleanup' "$CRON_DIR/webterm-docker-cleanup" 2>/dev/null; then
  legacy=true
fi
# 3.6.9 — the kit report: for each timer that reports through a status file, does ITS script
# support reporting (`--record <id>`, 3.6.8+), when were the script / timer last installed or
# updated, and when does the timer fire next. Without it the gateway could not tell "your scripts
# predate 3.6.8" from "current scripts, the timer simply has not fired since the update" — and
# warned about the latter right after every upgrade.
mtime() { stat -c %Y "$1" 2>/dev/null || echo 0; }
next_run() {   # epoch seconds of the timer's next elapse, 0 when unknown
  [ "$have_systemd" = 1 ] || { echo 0; return; }
  v=$(timeout 10 "$SYSTEMCTL" show -P NextElapseUSecRealtime --timestamp=unix "$1" 2>/dev/null || true)
  v=${v#@}
  case "$v" in ''|*[!0-9]*)
    v=$(timeout 10 "$SYSTEMCTL" show -P NextElapseUSecRealtime "$1" 2>/dev/null || true)
    # `date -d ""` is today's midnight, not an error: only parse a real timestamp
    case "$v" in ''|n/a|0) v=0 ;; *) v=$(date -d "$v" +%s 2>/dev/null || echo 0) ;; esac ;;
  esac
  case "$v" in ''|*[!0-9]*) echo 0 ;; *) echo "$v" ;; esac
}
kit_json=""
for pair in backup:backup cert_check:cert-check cleanup:docker-cleanup; do
  key=${pair%%:*} sid=${pair#*:}
  script="$ROOT/scripts/$sid.sh" timer="webterm-$sid.timer"
  reports=false
  [ -f "$script" ] && grep -q -- "--record $sid" "$script" 2>/dev/null && reports=true
  since=$(mtime "$script"); t_since=$(mtime "$SYSTEMD_DIR/$timer")
  [ "$t_since" -gt "$since" ] 2>/dev/null && since=$t_since
  kit_json="$kit_json,\"kit_$key\":$reports,\"since_$key\":$since,\"next_$key\":$(next_run "$timer")"
done
if [ "$have_systemd" = 1 ]; then
  timers_json="" bad=""
  for t in $TIMERS; do
    if [ ! -f "$SYSTEMD_DIR/$t" ]; then st=missing
    elif [ "$(timeout 10 "$SYSTEMCTL" is-enabled "$t" 2>/dev/null || true)" = enabled ]; then st=enabled
    else st=disabled
    fi
    [ "$st" = enabled ] || bad="$bad ${t%.timer}"
    timers_json="$timers_json${timers_json:+,}\"$t\":\"$st\""
  done
  data="{\"timers\":{$timers_json},\"legacy_cron\":$legacy,\"script_version\":2$kit_json}"
  if [ -n "$bad" ]; then
    record host-health warn "timers not active:$bad" "$data" || rc=1
  else
    record host-health ok "host checks ran; all WebTerm timers active" "$data" || rc=1
  fi
else
  record host-health ok "host checks ran (no systemd: timers not checked)" \
    "{\"timers\":{},\"legacy_cron\":$legacy,\"script_version\":2$kit_json}" || rc=1
fi

# 2. the Cloudflare DNS token (DNS-01 certificates)
tok=""
if [ -f "$ROOT/secrets/cf_dns_api_token" ] && [ ! -L "$ROOT/secrets/cf_dns_api_token" ]; then
  tok=$(tr -d ' \t\r\n' < "$ROOT/secrets/cf_dns_api_token")
fi
if [ -z "$tok" ]; then
  tok=$(sed -n 's/^CF_DNS_API_TOKEN=//p' "$ROOT/.env" | tail -n1 | tr -d ' \t\r\n"'"'"'')
fi
if [ -z "$tok" ]; then
  record cloudflare-token skipped "no Cloudflare token (HTTP-01 install)" \
    '{"token_status":"unknown","expires_on":""}' || rc=1
elif ! printf '%s' "$tok" | grep -Eq '^[A-Za-z0-9_-]{20,256}$'; then
  record cloudflare-token error "the Cloudflare token file has an unexpected format" \
    '{"token_status":"invalid","expires_on":""}' || rc=1
else
  # the header travels on stdin as a curl config line (printf is a builtin: never on a command line)
  code=$(printf 'header = "Authorization: Bearer %s"\n' "$tok" \
         | timeout 20 curl -K - -sS -m 15 -o "$WORK/cf.json" -w '%{http_code}' \
             "$CF_API/user/tokens/verify" 2>/dev/null || true)
  tok=""
  [ -f "$WORK/cf.json" ] || : > "$WORK/cf.json"
  line=$(py_tool cf "$WORK/cf.json" "${code:-000}" || echo "warn|unknown||could not read the Cloudflare answer")
  IFS='|' read -r s ts exp msg <<EOF
$line
EOF
  record cloudflare-token "$s" "$msg" "{\"token_status\":\"$ts\",\"expires_on\":\"$exp\"}" || rc=1
fi

# 3. the Authentik image: running vs pinned
vercmp() {   # vercmp A B → -1 | 0 | 1 (YYYY.M.P, numerically; both already validated)
  local a b i x y
  IFS=. read -r -a a <<< "$1"
  IFS=. read -r -a b <<< "$2"
  for i in 0 1 2; do
    x=$((10#${a[$i]})); y=$((10#${b[$i]}))
    if [ "$x" -lt "$y" ]; then echo -1; return; fi
    if [ "$x" -gt "$y" ]; then echo 1; return; fi
  done
  echo 0
}
VER_RE='^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,3}$'
# Two real layouts, told apart by the compose PROJECT label (never by container name):
#   * `profile`  — the `authentik` profile of THIS install's compose (project = ours / working_dir = $ROOT);
#   * `kit`      — deploy/authentik/ of this install (working_dir = $ROOT/deploy/authentik);
#   * `separate` — any other compose project (e.g. prod: project `authentik` in /opt/authentik).
# The running version is always compared with the version the WebTerm repo pins (this install's
# docker-compose.prod.yml; deploy/authentik's for the kit). Read-only: only `docker ps` labels.
our_project=$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$ROOT/.env" 2>/dev/null | tail -n1 | tr -d '"'"'"'' || true)
[ -n "$our_project" ] || our_project=$(basename "$ROOT" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
AK_FMT='{{.Image}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.service"}}|{{.Label "com.docker.compose.project.working_dir"}}'
ak_all=$(dk ps --format "$AK_FMT" 2>/dev/null | grep -E '^([^|]*/)?goauthentik/server:' || true)
# the server service first (the worker runs the same image); else any Authentik container
ak=$(printf '%s\n' "$ak_all" | awk -F'|' '$3 ~ /server$/' | head -n1)
[ -n "$ak" ] || ak=$(printf '%s\n' "$ak_all" | head -n1)
if [ -z "$ak" ]; then
  record authentik-image skipped "no Authentik container runs on this host" '{}' || rc=1
else
  IFS='|' read -r img akproj _aksvc wd <<< "$ak"
  running=${img##*goauthentik/server:}; running=${running%%@*}
  compose="$ROOT/docker-compose.prod.yml"
  if [ "$wd" = "$ROOT/deploy/authentik" ] && [ -f "$ROOT/deploy/authentik/docker-compose.prod.yml" ]; then
    layout=kit; compose="$ROOT/deploy/authentik/docker-compose.prod.yml"
  elif [ "$akproj" = "$our_project" ] || [ "$wd" = "$ROOT" ]; then
    layout=profile
  else
    layout=separate
  fi
  printf '%s' "$akproj" | grep -Eq '^[a-z0-9][a-z0-9_-]{0,63}$' || akproj=""
  pinned=$(grep -m1 -oE 'ghcr\.io/goauthentik/server:[0-9.]+' "$compose" 2>/dev/null | sed 's/.*://' || true)
  if ! printf '%s' "$running" | grep -Eq "$VER_RE" || ! printf '%s' "$pinned" | grep -Eq "$VER_RE"; then
    record authentik-image skipped "Authentik version not recognised (running or pinned)" '{}' || rc=1
  else
    cmpv=$(vercmp "$running" "$pinned")
    data="{\"running\":\"$running\",\"pinned\":\"$pinned\",\"layout\":\"$layout\",\"project\":\"$akproj\"}"
    case "$cmpv" in
      -1) record authentik-image warn "Authentik (${akproj:-?}, $layout) runs $running, WebTerm pins $pinned — upgrade step by step through minors, never skip" "$data" || rc=1 ;;
      1)  record authentik-image ok "Authentik runs $running, newer than the pinned $pinned" "$data" || rc=1 ;;
      *)  record authentik-image ok "Authentik runs the pinned $pinned" "$data" || rc=1 ;;
    esac
  fi
fi

[ "$rc" = 0 ] && say "host-health: status written to the data volume ($VOL${VOL:+ }host-status/)"
exit "$rc"
