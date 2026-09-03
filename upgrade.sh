#!/usr/bin/env bash
# WebTerm — a complete upgrade, in one command.
#
#     ./upgrade.sh              → the latest published version
#     ./upgrade.sh v2.0.15       → a specific version (also to go back down)
#     ./upgrade.sh --no-backup  → sare peste backupul de dinainte (nu recomand)
#     ./upgrade.sh -y           → no questions (cron, remote runs)
#     ./upgrade.sh --allow-latest → accept :latest when the version cannot be determined
#
# Why this exists when deploy.sh already does: `deploy.sh` updates the IMAGE. But half the
# system runs on the HOST, not in the container — backup.sh, restore.sh, the compose file, the
# systemd units. `/opt/webterm` is not a git checkout, so those stayed frozen at whatever the
# installer put there. On one machine that meant a backup.sh from weeks earlier: hardening that
# had shipped long ago was not active, and the nightly archives were written UNENCRYPTED, 644,
# with the vault key inside. An "upgrade" that does not touch the host files is an illusion.
#
# The order is chosen, not accidental:
#   1. resolve the version → know what you are installing before touching anything
#   2. preflight           → fail early and without side effects (auth, disk, files)
#   3. pull                → the artefact is local before anything changes
#   4. backup              → the safety net comes BEFORE the change, not after
#   5. sync the host       → from the image you already verified
#   6. deploy.sh           → pin + health check + rollback automat (le are deja)
#   7. final check         → say what is running now, do not assume
set -euo pipefail

# `.env` se CITEŞTE, nu se execută. Era sursat cu `. ./.env` — adică bash îl rula, ca root.
# Două consecinţe, amândouă reproduse de un audit extern: (1) o valoare cu spaţii, perfect
# validă pentru compose (`WEBTERM_ALERT_TO=a@x.com, b@x.com`), omoară instalarea cu
# „command not found" DUPĂ ce s-au copiat fişierele; (2) `WEBTERM_NOTE=x && touch /tmp/pwned`
# chiar creează fişierul. Cazul nu e teoretic: `.env.prod.example` conţinea el însuşi o valoare
# cu `&&`, pe care documentaţia te invita s-o decomentezi. Parserul de mai jos ia KEY=VALUE
# literal, fără expansiune, fără substituţie de comenzi.
load_env() {
  [ -f "$1" ] || return 0
  while IFS= read -r _line || [ -n "$_line" ]; do
    _line=${_line#"${_line%%[![:space:]]*}"}          # taie spaţiile din faţă
    case "$_line" in "export "*) _line=${_line#export } ;; esac
    case "$_line" in ''|'#'*) continue ;; esac
    case "$_line" in *=*) ;; *) continue ;; esac
    _key=${_line%%=*}
    _key=${_key%"${_key##*[![:space:]]}"}             # şi spaţiile dinaintea lui `=`
    case "$_key" in
      ''|*[!A-Za-z0-9_]*)
        # Nu tăcem. Sursarea accepta linii pe care parserul le sare, iar o variabilă pierdută
        # tăcut din `/etc/default/webterm-backup` înseamnă parola de backup dispărută — deci
        # backup picat, iar de la reparaţia cu `-y` asta opreşte upgrade-ul şi dă vina pe altceva.
        echo "note: ignoring unparsable line in $1: $(printf '%.40s' "$_line")" >&2
        continue ;;
    esac
    _val=${_line#*=}
    case "$_val" in
      \"*\") _val=${_val#\"}; _val=${_val%\"} ;;
      \'*\') _val=${_val#\'}; _val=${_val%\'} ;;
    esac
    export "$_key=$_val"
  done < "$1"
}


cd "$(dirname "$0")"
ROOT="$PWD"

TARGET=""
DO_BACKUP=1
ASSUME_YES=0
ALLOW_LATEST=0
for arg in "$@"; do
  case "$arg" in
    --no-backup) DO_BACKUP=0 ;;
    --allow-latest) ALLOW_LATEST=1 ;;
    -y|--yes)    ASSUME_YES=1 ;;
    -h|--help)   sed -n '2,10p' "$0"; exit 0 ;;
    v[0-9]*.[0-9]*.[0-9]*) TARGET="$arg" ;;
    *) echo "Unknown argument: $arg (expected vX.Y.Z, --no-backup, -y)" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ask() {                                    # ask "question" → 0 = yes
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || return 1                     # non-interactive without -y: the safe answer is NO
  printf '  %s [y/N] ' "$1"; read -r a; case "$a" in [yYdD]*) return 0 ;; *) return 1 ;; esac
}

[ -f .env ] || die "no .env in $ROOT — run ./deploy.sh first"
load_env ./.env
GHCR_USER="${GHCR_USER:-sm26449}"
REPO="${WEBTERM_UPDATE_REPO:-$GHCR_USER/webterm}"
IMAGE_BASE="ghcr.io/$GHCR_USER/webterm"

# ── 1. which version to install ──────────────────────────────────────────────
say "Target version"
if [ -z "$TARGET" ]; then
  # The latest semver tag on GitHub. Public repo → works with nothing; private repo → with the
  # token from .env. If we cannot find out, we do NOT guess: `latest` is a moving pointer and
  # we would no longer know what to roll back to, so we ask for confirmation.
  # no array: on bash < 4.4, "${A[@]}" on an empty array trips `set -u`
  AUTH_HDR="Accept: application/vnd.github+json"
  TOKEN_HDR="X-Ignorat: 1"
  [ -n "${GHCR_TOKEN:-}" ] && TOKEN_HDR="Authorization: Bearer $GHCR_TOKEN"
  TAGS=$(curl -fsS -H "$TOKEN_HDR" -H "$AUTH_HDR" \
         "https://api.github.com/repos/$REPO/tags?per_page=100" 2>/dev/null || true)
  TARGET=$(printf '%s' "$TAGS" | grep -o '"name": *"v[0-9][0-9.]*"' \
           | sed 's/.*"v/v/; s/"$//' \
           | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -1 || true)
  if [ -n "$TARGET" ]; then
    echo "  latest published: $TARGET"
  else
    warn "could not determine the latest version (private repo without GHCR_TOKEN in .env, or no network)"
    # `-y` means "do not ask me routine questions", NOT "silently accept degraded mode".
    # `:latest` is a moving pointer: pinned in .env, you no longer know what you are going back
    # to, and `.prev-image` becomes useless. The first production run fell into exactly this trap.
    if [ "$ALLOW_LATEST" != 1 ]; then
      echo "  You have three ways out:" >&2
      echo "    · give the version explicitly:  ./upgrade.sh vX.Y.Z" >&2
      echo "    · put GHCR_TOKEN=<PAT> in $ROOT/.env (deploy.sh reads it too)" >&2
      echo "    · accept a moving tag: ./upgrade.sh --allow-latest" >&2
      die "refusing to pin :latest unless you ask for it explicitly"
    fi
    warn "--allow-latest: pinning a MOVING tag; rolling back to a specific version becomes manual"
    TARGET="latest"
  fi
fi
IMAGE="$IMAGE_BASE:$TARGET"
CURRENT="${WEBTERM_IMAGE:-<nesetat>}"
echo "  now:   $CURRENT"
echo "  target: $IMAGE"
[ "$CURRENT" = "$IMAGE" ] && warn "already the installed version — continuing (useful for re-syncing the host files)"

# ── 2. preflight: fail early, without side effects ───────────────────────────
say "Preflight checks"
command -v docker >/dev/null || die "docker is missing"
docker compose version >/dev/null 2>&1 && COMPOSE="docker compose" || COMPOSE="docker-compose"
$COMPOSE version >/dev/null 2>&1 || die "docker compose is missing"
[ -f docker-compose.prod.yml ] || die "docker-compose.prod.yml missing in $ROOT"
[ -x ./deploy.sh ] || die "deploy.sh missing in $ROOT"

FILE=docker-compose.prod.yml
FREE_MB=$(df -Pm . | awk 'NR==2{print $4}')
[ "$FREE_MB" -lt 2048 ] && warn "only ${FREE_MB}MB free — the image plus the backup need room"
echo "  free space: ${FREE_MB}MB"

# Log in to ghcr BEFORE the pull, with the token from .env if present. The classic trap:
# `docker login` run as your user, `upgrade.sh` run with sudo → different HOME, different
# ~/.docker/config.json, so "unauthorized" on a machine where a manual `docker pull` works.
if [ -n "${GHCR_TOKEN:-}" ]; then
  echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin >/dev/null \
    && echo "  logged in to ghcr.io (token from .env)" \
    || die "ghcr login failed — token expired or wrong"
else
  echo "  no GHCR_TOKEN in .env; relying on the existing docker login of user $(id -un)"
fi

# ── 3. pull: the artefact is local before anything changes ───────────────────
say "Pulling $IMAGE"
if ! docker pull -q "$IMAGE" >/dev/null; then
  echo "" >&2
  echo "  If it says \"unauthorized/denied\": the image is private." >&2
  echo "    echo <PAT_cu_read:packages> | docker login ghcr.io -u $GHCR_USER --password-stdin" >&2
  echo "  or put GHCR_TOKEN=<PAT> in $ROOT/.env (deploy.sh reads it too)." >&2
  die "pull failed"
fi
NEW_VER=$(docker run --rm --entrypoint sh "$IMAGE" -c \
          "grep -m1 '^GATEWAY_VERSION' /srv/webterm/gateway/app/config.py | cut -d'\"' -f2" 2>/dev/null || echo "?")
NEW_AGENT=$(docker run --rm --entrypoint sh "$IMAGE" -c \
          "grep -m1 '^AGENT_VERSION' /srv/webterm/agent/ptyd.py | tr -dc 0-9" 2>/dev/null || echo "?")
echo "  image pulled: gateway v$NEW_VER, agent v$NEW_AGENT"

# The agent signature inside the image. Without it the gateway REFUSES to push updates
# (we do not send unsigned code to hosts), and the fleet would stay stuck on the old version
# with nobody saying anything. It is a property of the artefact, so we check it before
# putting it into production — not after.
SIGCHK=$(docker run --rm --entrypoint python3 "$IMAGE" -c "
import base64, pathlib, re
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    src = pathlib.Path('/srv/webterm/agent/ptyd.py').read_bytes()
    m = re.search(rb'UPDATE_PUBKEY = bytes.fromhex\\(\\s*.([0-9a-f]+).', src, re.S)
    pub = bytes.fromhex(m.group(1).decode())
    sig = base64.b64decode(pathlib.Path('/srv/webterm/agent/ptyd.py.sig').read_text().strip())
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, src)
    print('OK')
except FileNotFoundError:
    print('LIPSA')
except Exception:
    print('INVALIDA')
" 2>/dev/null || echo "NEVERIFICAT")
case "$SIGCHK" in
  OK) echo "  agent signature: valid (the official channel works)" ;;
  LIPSA)  warn "the image has no agent/ptyd.py.sig — without a deployment key, agents cannot update" ;;
  INVALIDA) warn "the agent signature in the image does NOT verify — agents will REFUSE the update" ;;
  *) warn "could not verify the agent signature (old image?)" ;;
esac

# ── 4. backup BEFORE the change ──────────────────────────────────────────────
if [ "$DO_BACKUP" = 1 ]; then
  say "Backup before upgrading"
  if [ -x scripts/backup.sh ]; then
    # The backup passphrase lives in /etc/default/webterm-backup — the same file the systemd
    # timer loads (EnvironmentFile). Without it backup.sh refuses itself ("I do not write
    # unencrypted archives non-interactively"), so the upgrade's safety step did not work
    # precisely on the machines that were configured correctly. One source of truth.
    if [ -r /etc/default/webterm-backup ]; then
      load_env /etc/default/webterm-backup
      echo "  (backup passphrase loaded from /etc/default/webterm-backup)"
    fi
    if scripts/backup.sh; then
      echo "  backup done"
    else
      warn "the backup failed"
      # `-y` înseamnă „nu mă întreba", nu „treci peste o plasă de siguranţă lipsă". `ask`
      # întorcea 0 sub `-y`, deci un upgrade neasistat continua fără snapshot exact când
      # backupul e stricat — adică atunci când ai cea mai mare nevoie de el. Cine chiar vrea
      # asta o spune explicit, cu --no-backup.
      if [ "$ASSUME_YES" = 1 ]; then
        die "the backup failed and -y was given — refusing to upgrade without a snapshot.
Fix the backup, or say so explicitly with --no-backup."
      fi
      ask "Continue the upgrade WITHOUT a backup?" || die "cancelled — fix the backup first"
    fi
  else
    warn "scripts/backup.sh missing — continuing without a backup"
  fi
else
  warn "backup skipped (--no-backup)"
fi

# ── 5. sync the files that run on the HOST ───────────────────────────────────
# From the image already pulled and authenticated, not from the internet. We keep a .bak for
# every file we change, so you can see exactly what moved.
say "Syncing host files from the image"
KIT=$(mktemp -d)
trap 'rm -rf "$KIT"' EXIT
if docker run --rm --entrypoint sh "$IMAGE" -c 'cd /srv/webterm/deploy-kit && tar cf - .' 2>/dev/null \
   | tar xf - -C "$KIT" 2>/dev/null && [ -f "$KIT/docker-compose.prod.yml" ]; then
  CHANGED=0
  for f in docker-compose.prod.yml deploy.sh rollback.sh remove.sh \
           scripts/backup.sh scripts/restore.sh scripts/cert-check.sh; do
    [ -f "$KIT/$f" ] || continue
    if [ -f "$f" ] && cmp -s "$KIT/$f" "$f"; then continue; fi
    mkdir -p "$(dirname "$f")"
    [ -f "$f" ] && cp -p "$f" "$f.bak"
    cp "$KIT/$f" "$f"
    case "$f" in *.sh) chmod +x "$f" ;; esac
    echo "  actualizat: $f$([ -f "$f.bak" ] && echo ' (vechiul → .bak)')"
    CHANGED=$((CHANGED + 1))
  done
  # upgrade.sh replaces itself LAST: the shell reads the script as it runs, and rewriting it
  # now would execute half of the new version.
  if [ -f "$KIT/upgrade.sh" ] && ! cmp -s "$KIT/upgrade.sh" upgrade.sh; then
    cp "$KIT/upgrade.sh" upgrade.sh.new
    SELF_UPDATE=1
  fi
  [ "$CHANGED" = 0 ] && echo "  host files were already up to date"
else
  warn "the image has no deploy kit (version < 2.0.0) — host files left as they are"
fi

# ── 6. deploy propriu-zis: pin + health check + rollback automat ─────────────
say "Applying $TARGET"
./deploy.sh "$TARGET"

# ── 7. final check: what is running NOW ──────────────────────────────────────
say "Verify"
# the container comes from compose, not from a fixed name: on a machine with two deployments,
# `webterm-app-1` could belong to a DIFFERENT instance
APP_CID=$($COMPOSE -f "$FILE" ps -q app 2>/dev/null | head -1)
RUNNING=$(docker inspect "${APP_CID:-nimic}" --format '{{.Config.Image}}' 2>/dev/null || echo "?")
STATE=$(docker inspect "${APP_CID:-nimic}" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null || echo "?")
echo "  image: ${RUNNING:-?}"
echo "  state: $STATE"
[ "$STATE" = healthy ] || warn "the container is NOT healthy — see 'docker logs ${APP_CID:-<container>}' and ./rollback.sh"

if [ -f /etc/default/webterm-backup ] && grep -q '^WEBTERM_BACKUP_PASSPHRASE=.' /etc/default/webterm-backup; then
  echo "  backup: encrypted (passphrase in /etc/default/webterm-backup)"
else
  warn "the automatic backup has NO passphrase → archives would hold the vault key in cleartext."
  warn "  put WEBTERM_BACKUP_PASSPHRASE=... in /etc/default/webterm-backup (chmod 600)."
fi

# ── what is left for you to do: said out loud, not left to guesswork ────────
# An upgrade that ends with "✓" but leaves the fleet stuck is worse than one that fails:
# you walk away reassured. So we ask the RUNNING container what state it is in and list only
# the things that genuinely need a human.
TODO=0
STATE=$(docker exec "${APP_CID:-nimic}" python3 -c '
import sqlite3, sys
sys.path.insert(0, "/srv/webterm")
from app import config, signing
print("KEY", int(signing.key_exists()), int(signing.is_encrypted()))
try:
    d = sqlite3.connect("file:%s?mode=ro" % config.DB_PATH, uri=True)
    r = d.execute("SELECT COUNT(*) FROM hosts WHERE connection_type=?"
                  " AND agent_version IS NOT NULL AND agent_version < ?",
                  ("agent", int(sys.argv[1]))).fetchone()
    print("BEHIND", r[0])
    for name, why in d.execute("SELECT name, update_blocked FROM hosts"
                               " WHERE update_blocked IS NOT NULL AND update_blocked != \x27\x27"):
        print("BLOCKED", name, "|", why)
except Exception:
    print("BEHIND ?")
' "${NEW_AGENT:-0}" 2>/dev/null || true)

KEY_LINE=$(printf '%s' "$STATE" | awk '/^KEY/{print $2" "$3}')
BEHIND=$(printf '%s' "$STATE" | awk '/^BEHIND/{print $2}')

say "What is left to do"
case "$KEY_LINE" in
  "1 1")
    warn "the fleet signing key is ENCRYPTED → after a restart it is LOCKED."
    echo "    Agents will NOT update until you unlock it: Settings → Security → unlock."
    TODO=$((TODO + 1)) ;;
  "1 0") echo "  signing key: loaded automatically (no passphrase) — agents can update" ;;
  "0 0") echo "  no deployment key: using the official channel signed by the maintainer" ;;
  *)     warn "could not read the signing key state" ;;
esac

# hosts that CANNOT update (reason persisted by the gateway) — worse than merely "behind":
# waiting fixes nothing there, it needs an action
printf '%s\n' "$STATE" | awk -F'\\|' '/^BLOCKED/{print $0}' | while IFS= read -r line; do
  [ -n "$line" ] || continue
  warn "$(printf '%s' "$line" | sed 's/^BLOCKED /update BLOCKED on /')"
done
if printf '%s' "$STATE" | grep -q '^BLOCKED'; then
  echo "    An agent is refusing the signed update: most often because it was enrolled BEFORE"
  echo "    the signing key was generated. Fix: reinstall the agent on that host."
  TODO=$((TODO + 1))
fi
if [ -n "${BEHIND:-}" ] && [ "$BEHIND" != "?" ] && [ "$BEHIND" != "0" ]; then
  echo "  $BEHIND host(s) still on an agent older than v$NEW_AGENT."
  echo "    They update on reconnect. If a host has open sessions the restart is DEFERRED —"
  echo "    force it with the ↑ v$NEW_AGENT button on its card."
  TODO=$((TODO + 1))
elif [ "${BEHIND:-}" = "0" ]; then
  echo "  all agents are up to date (v$NEW_AGENT)"
fi

if [ "$TODO" = 0 ]; then
  echo "  nothing — the system is fully up to date"
fi

if [ "${SELF_UPDATE:-0}" = 1 ]; then
  # `.bak` şi pentru el însuşi: linia de mai sus promite „we keep a .bak for every file we
  # change", iar singurul fişier exceptat era chiar cel care face schimbarea — adică exact cel
  # de care ai nevoie ca să te întorci dacă noul upgrade.sh e stricat.
  cp upgrade.sh upgrade.sh.bak 2>/dev/null || true
  mv upgrade.sh.new upgrade.sh && chmod +x upgrade.sh
  echo "  upgrade.sh updated itself (vechiul → upgrade.sh.bak; activ de la următoarea rulare)"
fi

# Bannerul raporta ŢINTA, nu realitatea. `deploy.sh` face `exec ./rollback.sh` când imaginea
# nouă nu devine healthy, iar un rollback reuşit iese cu 0 — deci upgrade.sh continua şi anunţa
# verde „Upgrade complet: v2.1.0" pe o instalare care tocmai revenise la v2.0.0. Comparăm cu
# imaginea care rulează chiar acum, citită mai sus la pasul de verificare.
if [ "$RUNNING" = "$IMAGE" ]; then
  printf '\n\033[32m✓ Upgrade complet: %s (gateway v%s, agent v%s)\033[0m\n' "$TARGET" "$NEW_VER" "$NEW_AGENT"
else
  printf '\n\033[1;33m! Upgrade NEAPLICAT: rulează %s, nu %s\033[0m\n' "${RUNNING:-?}" "$IMAGE"
  echo "  Imaginea nouă nu a devenit healthy, iar deploy.sh a făcut rollback automat."
  echo "  Vezi 'docker logs ${APP_CID:-<container>}' pentru motiv."
  exit 1
fi
