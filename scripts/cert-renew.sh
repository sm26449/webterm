#!/usr/bin/env bash
# WebTerm — look after Traefik's ACME certificate stores (3.6.7).
#
#   sudo ./scripts/cert-renew.sh                       back up the stores + list what they hold
#   sudo ./scripts/cert-renew.sh --report              list only (read-only; upgrade.sh runs this)
#   sudo ./scripts/cert-renew.sh --domain NAME         force a fresh certificate for NAME
#   sudo ./scripts/cert-renew.sh --prune-unrouted      show entries no router asks for (dry run)
#   sudo ./scripts/cert-renew.sh --prune-unrouted --yes   …and remove them
#   sudo ./scripts/cert-renew.sh --restore DIR         put a backup back (DIR from acme-backups/)
#
# Options: --store RESOLVER (with --domain: only that store) · --yes (no question) ·
#          --timeout SECS (how long --domain waits for the new certificate, default 180)
#
# Why (incident 2026-10-12): the wildcard `*.wt.safegrid.net` expired. It sat in the `le` store
# (acme.json, HTTP-01), and HTTP-01 cannot renew a wildcard: Traefik logged "could not determine
# solvers" every day for weeks. The routers asked for it through `ledns` (DNS-01, acme-dns.json),
# but Traefik never requested it there, because a certificate for that name already existed in
# the `le` store. The fix was: back up acme.json, delete that ONE entry, restart Traefik — ledns
# issued a new wildcard within a minute. This script is that fix, made repeatable and careful:
#   * it backs up every store first (timestamped, 0600, the last 5 kept, an identical copy of
#     the latest one is not made twice so routine runs never rotate the useful backup away);
#   * it prints domains, stores and expiry dates — NEVER keys or certificates;
#   * --domain removes only the entries naming that domain, and refuses when nothing matches or
#     when a store holds more than one match (ambiguous); then it restarts ONLY the Traefik
#     container (stop → edit → start, so Traefik cannot write the old entry back from memory)
#     and waits until a valid, non-default certificate is served for the name;
#   * nothing changes without --yes or a "y" at the prompt.
#
# The WebTerm app NEVER runs this: it has no access to the ACME volume or to Docker. Settings →
# Infrastructure → Certificates only shows (or, for an Owner, types into a terminal) the command.
#
# Needs: bash, docker, openssl, timeout; python3 on the host or, failing that, a pinned
# python:3.12-alpine image (the same one backup.sh uses) with no network.
set -eu
umask 077

usage() { sed -n '2,13p' "$SELF" | sed 's/^# \{0,1\}//'; }
die() { printf 'cert-renew: %s\n' "$*" >&2; exit "${RC:-1}"; }
say() { printf '%s\n' "$*"; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
SELF="$SCRIPT_DIR/$(basename "$0")"
ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
# Run from `/`, never from the caller's directory. Under `sudo` the cwd is kept, and a python
# started there would put that directory first on sys.path: a `json.py` planted in the agent
# user's home would then run as ROOT the moment an Owner presses Enter (security review F1).
# Python is also started isolated (`-I`), below. ORIG_PWD only resolves a relative --restore.
ORIG_PWD=$PWD
cd /

# Test mode. The variables below exist so the test suite can point the script at fake stores, a
# fake docker and a local TLS server. They are honoured ONLY with WEBTERM_CERT_RENEW_TEST=1, and
# NEVER when we run as root through sudo — the path the UI types. Otherwise whoever can shape the
# environment of the sudo call could swap `docker` or the store directory for something of theirs.
TEST_MODE=0
if [ "${WEBTERM_CERT_RENEW_TEST:-}" = 1 ]; then
  if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then
    printf 'cert-renew: WEBTERM_CERT_RENEW_TEST is ignored under sudo\n' >&2
  else
    TEST_MODE=1
  fi
fi
DOCKER=docker
PROBE=127.0.0.1:443
TOOL_IMAGE="python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
ENV_ACME_DIR="" ENV_CID=""
if [ "$TEST_MODE" = 1 ]; then
  DOCKER="${DOCKER_TEST_BIN:-docker}"
  PROBE="${WEBTERM_CERT_PROBE:-$PROBE}"
  TOOL_IMAGE="${WEBTERM_TOOL_IMAGE:-$TOOL_IMAGE}"
  ENV_ACME_DIR="${WEBTERM_ACME_DIR:-}"
  ENV_CID="${WEBTERM_TRAEFIK_CONTAINER:-}"
fi
POLL_EVERY="${WEBTERM_RENEW_POLL:-5}"
KEEP=5

MODE=list DOMAIN="" STORE="" YES=0 TIMEOUT=180 RESTORE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --report) MODE=report; shift ;;
    --domain) [ $# -ge 2 ] || RC=2 die "--domain needs a name"; MODE=domain; DOMAIN="$2"; shift 2 ;;
    --store) [ $# -ge 2 ] || RC=2 die "--store needs a resolver name"; STORE="$2"; shift 2 ;;
    --prune-unrouted) MODE=prune; shift ;;
    --restore) [ $# -ge 2 ] || RC=2 die "--restore needs a backup directory"; MODE=restore; RESTORE="$2"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    --timeout) [ $# -ge 2 ] || RC=2 die "--timeout needs seconds"; TIMEOUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) RC=2 die "unknown argument: $1 (see --help)" ;;
  esac
done

case "$TIMEOUT" in ''|*[!0-9]*) RC=2 die "--timeout must be a number of seconds" ;; esac
case "$POLL_EVERY" in ''|*[!0-9]*|0) POLL_EVERY=5 ;; esac
if [ -n "$STORE" ]; then
  printf '%s' "$STORE" | grep -Eq '^[A-Za-z0-9_-]{1,64}$' || RC=2 die "invalid --store name"
fi
if [ "$MODE" = domain ]; then
  # the same rule as the gateway (certmon.RENEW_NAME_RE): lowercase LDH labels, optional `*.`
  DOMAIN=$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')
  if ! printf '%s' "$DOMAIN" | grep -Eq '^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' \
     || [ "${#DOMAIN}" -gt 255 ] || [ "$(printf '%s' "$DOMAIN" | wc -l)" -ne 0 ]; then
    RC=2 die "invalid domain name: $DOMAIN"
  fi
fi

# ── are we in a WebTerm install dir? ─────────────────────────────────────────
if ! { [ -f "$ROOT/docker-compose.prod.yml" ] && [ -f "$ROOT/.env" ] \
        && grep -q 'certificatesresolvers' "$ROOT/docker-compose.prod.yml"; }; then
  RC=2 die "$ROOT is not a WebTerm install directory (no docker-compose.prod.yml with Traefik resolvers + .env)"
fi

# The script runs as root and trusts its own directory (the install dir, its scripts, the backups
# it may restore from). Each must be root-owned and not writable by group or others; otherwise a
# non-root user could swap the script between the Owner reading the command and pressing Enter, or
# plant a "backup" for --restore. Skipped only in test mode (a CI runner is not root).
safe_path() {   # safe_path PATH → 0 when owned by root and not group/world-writable
  local owner mode
  owner=$(stat -Lc '%u' -- "$1" 2>/dev/null) || return 1
  mode=$(stat -Lc '%a' -- "$1" 2>/dev/null) || return 1
  [ "$owner" = 0 ] && [ $(( 0$mode & 022 )) -eq 0 ]
}
if [ "$TEST_MODE" != 1 ]; then
  for p in "$ROOT" "$SCRIPT_DIR" "$SELF" "$ROOT/acme-backups"; do
    [ -e "$p" ] || continue
    safe_path "$p" || RC=2 die "refusing: $p must be owned by root and not writable by group/others"
  done
fi

WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# ── where Traefik and its stores are ─────────────────────────────────────────
CID="$ENV_CID"
if [ -z "$CID" ]; then
  CID=$("$DOCKER" ps -q --filter "label=com.docker.compose.service=traefik" \
          --filter "label=com.docker.compose.project.working_dir=$ROOT" 2>/dev/null | head -n1 || true)
fi
if [ -z "$CID" ]; then
  # /opt/webterm reached through a symlink has another working_dir label: fall back on the compose
  # project name (COMPOSE_PROJECT_NAME in .env, else the directory name, as compose derives it)
  PROJECT=$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$ROOT/.env" | tail -n1 | tr -d '"'"'"'')
  [ -n "$PROJECT" ] || PROJECT=$(basename "$ROOT" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
  CID=$("$DOCKER" ps -q --filter "label=com.docker.compose.service=traefik" \
          --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null | head -n1 || true)
fi
ACME_DIR="$ENV_ACME_DIR"
if [ -z "$ACME_DIR" ] && [ -n "$CID" ]; then
  ACME_DIR=$("$DOCKER" inspect -f '{{range .Mounts}}{{if eq .Destination "/letsencrypt"}}{{.Source}}{{end}}{{end}}' \
             "$CID" 2>/dev/null || true)
fi
if [ -z "$ACME_DIR" ] || [ ! -d "$ACME_DIR" ]; then
  die "cannot find the ACME store (is the Traefik container of $ROOT running? are you root?)"
fi

# the resolvers as Traefik really runs them (its args), else as the compose file declares them
if [ -n "$CID" ] && "$DOCKER" inspect -f '{{range .Args}}{{println .}}{{end}}' "$CID" > "$WORK/args" 2>/dev/null \
   && grep -q 'certificatesresolvers' "$WORK/args"; then
  :
else
  sed -n 's/^[[:space:]]*-[[:space:]]*\(--certificatesresolvers\.[^[:space:]]*\).*$/\1/p' \
    "$ROOT/docker-compose.prod.yml" > "$WORK/args"
fi

# which domains the routers ask for, per resolver (labels of the running containers); "unknown"
# when Docker cannot tell us — then nothing is ever called unrouted, let alone pruned
: > "$WORK/labels"
LABELS_OK=0
if ids=$("$DOCKER" ps -q 2>/dev/null) && [ -n "$ids" ]; then
  # shellcheck disable=SC2086  # word-splitting the id list is intended
  if "$DOCKER" inspect -f '{{json .Config.Labels}}' $ids > "$WORK/labels" 2>/dev/null; then
    LABELS_OK=1
  fi
fi

# ── the JSON work happens in python (host python3, else a pinned image without network) ──
run_py() {   # run_py RW|RO <args…>   (program on stdin)
  local rw="$1"; shift
  if command -v python3 >/dev/null 2>&1; then
    ACME_DIR="$ACME_DIR" WORK="$WORK" LABELS_OK="$LABELS_OK" python3 -I - "$@"
  else
    local mode=ro; [ "$rw" = RW ] && mode=rw
    "$DOCKER" run --rm -i --network none --entrypoint python3 \
      -e ACME_DIR="$ACME_DIR" -e WORK="$WORK" -e LABELS_OK="$LABELS_OK" \
      -w / -v "$ACME_DIR:$ACME_DIR:$mode" -v "$WORK:$WORK" "$TOOL_IMAGE" -I - "$@"
  fi
}

acme_tool() {   # acme_tool RW|RO <command> [args…]
  run_py "$@" <<'PYEOF'
import calendar, json, os, re, ssl, subprocess, sys, tempfile, time

cmd = sys.argv[1]
argv = sys.argv[2:]
ACME = os.environ["ACME_DIR"]
WORK = os.environ["WORK"]
LABELS_OK = os.environ.get("LABELS_OK") == "1"
NOW = time.time()
WARN_DAYS = 14


def resolvers():
    """name -> {"file": path in ACME_DIR, "challenge": "HTTP-01"|"DNS-01"|"TLS-ALPN-01"|"?"}"""
    out = {}
    for line in open(os.path.join(WORK, "args"), encoding="utf-8", errors="replace"):
        m = re.match(r"^--certificatesresolvers\.([A-Za-z0-9_-]+)\.acme\.([a-z]+)(?:=(\S*))?", line.strip())
        if not m:
            continue
        r = out.setdefault(m.group(1), {"file": None, "challenge": "?"})
        key, val = m.group(2), (m.group(3) or "")
        if key == "storage":
            base = os.path.basename(val)
            if val.startswith("/letsencrypt/") and re.match(r"^[A-Za-z0-9._-]+\.json$", base):
                r["file"] = os.path.join(ACME, base)
        elif key == "httpchallenge" and val.lower() in ("", "true"):
            r["challenge"] = "HTTP-01"
        elif key == "dnschallenge" and val.lower() in ("", "true"):
            r["challenge"] = "DNS-01"
        elif key == "tlschallenge" and val.lower() in ("", "true"):
            r["challenge"] = "TLS-ALPN-01"
    return out


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except ValueError as e:
        sys.exit("cert-renew: %s is not valid JSON (%s) — not touching it" % (path, e))


def expiry(b64):
    """notAfter (epoch) of the FIRST certificate of the chain, or None. Keys are never read."""
    import base64
    try:
        pem = base64.b64decode(b64 or "").decode("ascii", "replace")
    except Exception:
        return None
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if not m:
        return None
    fd, p = tempfile.mkstemp(dir=WORK, suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(m.group(0) + "\n")
        na = None
        try:
            na = ssl._ssl._test_decode_cert(p).get("notAfter")      # stdlib, no openssl CLI needed
        except Exception:
            try:
                out = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", p],
                                     capture_output=True, text=True, timeout=10).stdout
                na = out.strip().split("=", 1)[1] if "=" in out else None
            except Exception:
                na = None
        if not na:
            return None
        return calendar.timegm(time.strptime(na.replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
    finally:
        os.unlink(p)


def entries():
    """[(resolver, info, file, index, cert-dict)] for every certificate in every known store."""
    out = []
    for name, info in sorted(resolvers().items()):
        if not info["file"]:
            continue
        data = load(info["file"])
        block = data.get(name) if isinstance(data.get(name), dict) else {}
        for i, c in enumerate(block.get("Certificates") or []):
            if isinstance(c, dict):
                out.append((name, info, info["file"], i, c))
    return out


def names_of(c):
    d = c.get("domain") or {}
    main = str(d.get("main") or "").lower()
    sans = [str(s).lower() for s in (d.get("sans") or []) if s]
    return main, sans


def requested():
    """resolver -> set of names its routers ask for (tls.domains, else the Host() rule)."""
    if not LABELS_OK:
        return None
    routers = {}
    for line in open(os.path.join(WORK, "labels"), encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line == "null":
            continue
        try:
            labels = json.loads(line)
        except ValueError:
            continue
        if not isinstance(labels, dict) or str(labels.get("traefik.enable", "")).lower() != "true":
            continue
        for k, v in labels.items():
            m = re.match(r"^traefik\.http\.routers\.([^.]+)\.(.+)$", k)
            if not m:
                continue
            r = routers.setdefault(m.group(1), {"resolver": "", "domains": set(), "hosts": set()})
            key = m.group(2)
            if key == "tls.certresolver":
                r["resolver"] = v
            elif re.match(r"^tls\.domains\[\d+\]\.(main|sans)$", key):
                r["domains"] |= {x.strip().lower() for x in str(v).split(",") if x.strip()}
            elif key == "rule":
                r["hosts"] |= {h.lower() for h in re.findall(r"Host\(\s*[`\"]([^`\"]+)[`\"]\s*\)", str(v))}
    out = {}
    for r in routers.values():
        if r["resolver"]:
            out.setdefault(r["resolver"], set()).update(r["domains"] or r["hosts"])
    # no router with a resolver at all = the stack is down or the labels are not ours: "unknown",
    # never "everything is unrouted"
    return out or None


def fmt_exp(na):
    if na is None:
        return "expiry unknown"
    days = (na - NOW) / 86400.0
    when = time.strftime("%Y-%m-%d", time.gmtime(na))
    if days < 0:
        return "EXPIRED %s (%d days ago)" % (when, int(-days) + 1)
    return "expires %s (%d days left)" % (when, int(days))


def report():
    res = resolvers()
    req = requested()
    warns = []
    if not res:
        print("No ACME resolvers found in Traefik's configuration.")
        return
    by_store = {}
    for e in entries():
        by_store.setdefault(e[0], []).append(e)
    for name, info in sorted(res.items()):
        f = info["file"] or "(no storage under /letsencrypt)"
        es = by_store.get(name, [])
        print("Store %s (%s) %s: %d certificate(s)" % (name, info["challenge"], os.path.basename(f), len(es)))
        for (_r, _i, _f, _idx, c) in es:
            main, sans = names_of(c)
            na = expiry(c.get("certificate"))
            flags = []
            allnames = [main] + [s for s in sans if s != main]
            if any(n.startswith("*.") for n in allnames) and info["challenge"] == "HTTP-01":
                flags.append("WILDCARD-IN-HTTP01")
                warns.append("store %s holds the wildcard %s, but it uses HTTP-01, which can NEVER renew a "
                             "wildcard (only DNS-01 can) — remove it: --domain %s"
                             % (name, ", ".join(n for n in allnames if n.startswith("*.")), main or allnames[0]))
            if na is not None and (na - NOW) / 86400.0 < WARN_DAYS:
                flags.append("EXPIRING" if na > NOW else "EXPIRED")
                warns.append("%s in store %s: %s" % (main, name, fmt_exp(na)))
            if req is not None and not (set(allnames) & req.get(name, set())):
                flags.append("UNROUTED")
                warns.append("store %s has an entry for %s that no router asks for (stale; it can shadow the "
                             "right certificate) — see --prune-unrouted" % (name, main))
            print("  %-40s %s%s" % (", ".join(allnames)[:200], fmt_exp(na),
                                    ("   [" + "] [".join(flags) + "]") if flags else ""))
    if req is None:
        print("(router labels unavailable: unrouted entries are not checked)")
    for w in warns:
        print("WARN: " + w)
    if not warns:
        print("OK: no certificate expires within %d days, no wildcard in an HTTP-01 store%s."
              % (WARN_DAYS, "" if req is None else ", no unrouted entries"))


def write_atomic(path, data):
    st = os.stat(path)
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".cert-renew-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)                         # Traefik refuses an acme.json that is not 0600
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def remove(selected, apply):
    """selected: [(resolver, file, index)] → print + (apply) drop exactly those entries."""
    by_file = {}
    for r, f, i in selected:
        by_file.setdefault(f, []).append((r, i))
    for f, items in by_file.items():
        data = load(f)
        for r, i in sorted(items, key=lambda x: -x[1]):
            certs = data[r]["Certificates"]
            main, sans = names_of(certs[i])
            print("%s %s: store %s, entry %s" % ("REMOVED" if apply else "WOULD REMOVE", main,
                                                  r, ", ".join([main] + sans)))
            if apply:
                del certs[i]
        if apply:
            write_atomic(f, data)


if cmd == "report":
    report()
elif cmd == "domain":
    name, store, apply = argv[0], argv[1], argv[2] == "1"
    matches = [(r, f, i) for (r, info, f, i, c) in entries()
               if (not store or r == store) and name in [names_of(c)[0]] + names_of(c)[1]]
    if not matches:
        print("cert-renew: no ACME entry names %s%s — nothing to remove" % (name, " in store " + store if store else ""),
              file=sys.stderr)
        sys.exit(3)
    per_store = {}
    for r, f, i in matches:
        per_store[r] = per_store.get(r, 0) + 1
    many = {r: n for r, n in per_store.items() if n > 1}
    if many:
        print("cert-renew: %s matches more than one entry in store(s) %s — refusing (ambiguous); "
              "use --prune-unrouted or edit by hand from a backup" % (name, ", ".join(sorted(many))),
              file=sys.stderr)
        sys.exit(4)
    remove(matches, apply)
elif cmd == "prune":
    apply = argv[0] == "1"
    req = requested()
    if req is None or not req:
        print("cert-renew: cannot read which domains the routers ask for (docker labels) — refusing to prune",
              file=sys.stderr)
        sys.exit(5)
    sel = []
    for (r, info, f, i, c) in entries():
        main, sans = names_of(c)
        if not (set([main] + sans) & req.get(r, set())):
            sel.append((r, f, i))
    if not sel:
        print("Nothing to prune: every entry is asked for by a router.")
        sys.exit(0)
    remove(sel, apply)
else:
    sys.exit("cert-renew: internal: unknown command %r" % cmd)
PYEOF
}

# ── backups ──────────────────────────────────────────────────────────────────
BACKUP_ROOT="$ROOT/acme-backups"
LAST_BACKUP=""
backup() {
  mkdir -p "$BACKUP_ROOT"; chmod 700 "$BACKUP_ROOT"
  local latest stamp dst f same=1 n=0
  latest=$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'acme-*' 2>/dev/null | sort | tail -n1)
  for f in "$ACME_DIR"/*.json; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    if [ -z "$latest" ] || ! cmp -s "$f" "$latest/$(basename "$f")"; then same=0; fi
  done
  [ "$n" -gt 0 ] || { say "No ACME store files in $ACME_DIR yet — nothing to back up."; return 0; }
  if [ "$same" = 1 ] && [ -n "$latest" ] \
     && [ "$(find "$latest" -maxdepth 1 -name '*.json' | wc -l)" -eq "$n" ]; then
    LAST_BACKUP="$latest"
    say "Backup: unchanged since $latest"
    return 0
  fi
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  dst="$BACKUP_ROOT/acme-$stamp"
  local i=1
  while [ -e "$dst" ]; do               # same second: -02, -03… (still sorts oldest → newest)
    i=$((i + 1)); dst=$(printf '%s/acme-%s-%02d' "$BACKUP_ROOT" "$stamp" "$i")
  done
  mkdir -m 700 "$dst"
  for f in "$ACME_DIR"/*.json; do
    [ -f "$f" ] || continue
    cp -p "$f" "$dst/"
    chmod 600 "$dst/$(basename "$f")"
  done
  LAST_BACKUP="$dst"
  say "Backup: $dst"
  # retention: the newest $KEEP, only our own `acme-*` directories
  find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'acme-*' | sort | head -n "-$KEEP" \
    | while IFS= read -r old; do
        case "$old" in "$BACKUP_ROOT"/acme-*) rm -rf -- "$old" ;; esac
      done
}

confirm() {   # confirm "question" → 0 = go
  [ "$YES" = 1 ] && return 0
  if [ -t 0 ]; then
    printf '%s [y/N] ' "$1"
    local a=""; IFS= read -r a || true
    case "$a" in y|Y|yes|YES) return 0 ;; esac
    say "Cancelled — nothing changed."
    exit 1
  fi
  RC=1 die "not a terminal: re-run with --yes to apply"
}

# Traefik must be stopped while its store is edited (it keeps the store in memory and would write
# the removed entry back on its next save); if anything fails in between, start it again.
TRAEFIK_STOPPED=0
start_traefik() {
  if [ "$TRAEFIK_STOPPED" = 1 ]; then
    "$DOCKER" start "$CID" >/dev/null && TRAEFIK_STOPPED=0 && say "Traefik started."
  fi
}
stop_traefik() {
  [ -n "$CID" ] || die "the Traefik container of $ROOT is not running — start the stack first"
  trap 'start_traefik; cleanup' EXIT
  say "Stopping Traefik ($CID)…"
  "$DOCKER" stop -t 10 "$CID" >/dev/null
  TRAEFIK_STOPPED=1
}

# what Traefik serves for a name: 0 = a valid (not expiring within the hour), non-default
# certificate that covers it. A wildcard is probed through `cert-check.<parent>`.
probe() {
  local name="$1" sni pem
  sni="$name"; case "$name" in '*.'*) sni="cert-check.${name#\*.}" ;; esac
  pem=$(timeout 10 openssl s_client -connect "$PROBE" -servername "$sni" </dev/null 2>/dev/null \
        | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' || true)
  [ -n "$pem" ] || { PROBE_WHY="no certificate (Traefik not answering yet)"; return 1; }
  if printf '%s\n' "$pem" | openssl x509 -noout -subject -issuer 2>/dev/null | grep -q 'TRAEFIK DEFAULT CERT'; then
    PROBE_WHY="Traefik's default certificate (no ACME certificate yet)"; return 1
  fi
  printf '%s\n' "$pem" | openssl x509 -noout -checkend 3600 >/dev/null 2>&1 \
    || { PROBE_WHY="expired"; return 1; }
  printf '%s\n' "$pem" | openssl x509 -noout -checkhost "$sni" 2>/dev/null | grep -q 'does match' \
    || { PROBE_WHY="does not cover $sni"; return 1; }
  PROBE_END=$(printf '%s\n' "$pem" | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  return 0
}

case "$MODE" in
  report)
    acme_tool RO report ;;
  list)
    backup
    acme_tool RO report ;;
  domain)
    backup
    say ""
    set +e; acme_tool RO domain "$DOMAIN" "$STORE" 0; rc=$?; set -e
    [ "$rc" = 0 ] || exit "$rc"
    confirm "Remove these entries and restart Traefik so it requests a new certificate for $DOMAIN?"
    stop_traefik
    set +e; acme_tool RW domain "$DOMAIN" "$STORE" 1; rc=$?; set -e
    start_traefik
    [ "$rc" = 0 ] || die "editing the store failed (rc $rc); the backup is $LAST_BACKUP"
    say "Waiting up to ${TIMEOUT}s for a new certificate for $DOMAIN on $PROBE…"
    deadline=$(( $(date +%s) + TIMEOUT ))
    PROBE_WHY="" PROBE_END=""
    while :; do
      if probe "$DOMAIN"; then
        say "OK: a valid certificate is served for $DOMAIN (expires $PROBE_END)."
        exit 0
      fi
      [ "$(date +%s)" -lt "$deadline" ] || break
      sleep "$POLL_EVERY"
    done
    say "NOT YET: after ${TIMEOUT}s Traefik serves: $PROBE_WHY."
    say "  Look at: docker logs --since 10m $CID 2>&1 | grep -i acme"
    say "  (DNS-01 needs the Cloudflare token with Zone:DNS:Edit rights — and not expired.)"
    say "  To undo: $SELF --restore $LAST_BACKUP"
    exit 1 ;;
  prune)
    if [ "$YES" = 1 ]; then
      backup
      set +e; acme_tool RO prune 0 > "$WORK/plan"; rc=$?; set -e
      cat "$WORK/plan"
      [ "$rc" = 0 ] || exit "$rc"
      grep -q '^WOULD REMOVE' "$WORK/plan" || exit 0
      stop_traefik
      set +e; acme_tool RW prune 1; rc=$?; set -e
      start_traefik
      [ "$rc" = 0 ] || die "editing the store failed (rc $rc); the backup is $LAST_BACKUP"
      say "Done. Traefik re-requests what its routers need."
    else
      set +e; acme_tool RO prune 0; rc=$?; set -e
      [ "$rc" = 0 ] || exit "$rc"
      say "(dry run — nothing changed; add --yes to remove these)"
    fi ;;
  restore)
    case "$RESTORE" in /*) ;; *) RESTORE="$ORIG_PWD/$RESTORE" ;; esac
    src=$(cd "$RESTORE" 2>/dev/null && pwd -P) || RC=2 die "no such backup: $RESTORE"
    case "$src" in "$(cd "$ROOT" && pwd -P)/acme-backups/acme-"*) ;; *) RC=2 die "--restore takes a directory from $BACKUP_ROOT" ;; esac
    ls "$src"/*.json >/dev/null 2>&1 || RC=2 die "$src holds no store files"
    backup
    confirm "Put the store files from $src back and restart Traefik?"
    stop_traefik
    for f in "$src"/*.json; do
      cp -- "$f" "$ACME_DIR/.restore.tmp"
      chmod 600 "$ACME_DIR/.restore.tmp"
      mv -f -- "$ACME_DIR/.restore.tmp" "$ACME_DIR/$(basename "$f")"
      say "restored $(basename "$f")"
    done
    start_traefik ;;
esac
