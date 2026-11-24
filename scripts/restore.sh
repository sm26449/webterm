#!/usr/bin/env bash
# Restore a WebTerm backup into the data volume — through the gateway's own restore code.
#
#   ./restore.sh [--legacy-import] <archive.wtbk | archive.tar.gz | archive.tar.gz.enc>
#   ./restore.sh --verify [--legacy-import] <archive>
#
# What it does (3.8, docs/INSTALL.md → Encryption at rest):
#   1. makes ONE private copy of the archive (decrypted first for a .enc) and takes its SHA-256;
#      every later step reads that copy and checks the digest again;
#   2. checks it with the APP image (python3 -m app.hostops verify): the same strict extractor,
#      keyring and database checks as Settings → Backup, with the master key this installation
#      is configured with (its key directory bound read-only; the key is never copied into an
#      environment file). A refused archive costs no downtime;
#   3. asks, stops the app, refuses if any other container still uses the volume (or if Docker
#      cannot tell), and STAGES the archive with the gateway's staging code under the data
#      directory's own lock (python3 -m app.hostops stage-restore): a lock held by anything else
#      is refused before anything changes;
#   4. starts the app, whose boot applies the staged set under its lock with the resumable
#      journal (and keeps a safety copy of the previous state). `.lock` and an in-volume
#      `master.key` are never moved.
# The app is restarted after a refusal (nothing changed) or a committed stage; never after a
# stage that ended in an unknown state.
#
#   --legacy-import             a pre-3.8 archive (with data/secret) restored onto a PROTECTED
#                               volume (keys.wtk): its vault key becomes this installation's
#                               legacy key, wrapped under the master key (never written raw)
#   WEBTERM_VOLUME              Docker volume name   (default webterm_webterm-data)
#   WEBTERM_UID                 uid:gid the app runs as (default 10001:10001)
#   WEBTERM_APP_CONTAINER       the app container (default: the one that mounts the volume at /data)
#   WEBTERM_TOOL_IMAGE          image with python3 for the 3.7 archive scan (default python:3.12-alpine)
#   WEBTERM_BACKUP_PASSPHRASE   required for an encrypted archive (.wtbk, or .enc from a 3.7 backup.sh)
#   WEBTERM_RESTORE_MAX_BYTES   decompressed-size cap, anti compression-bomb (default 2 GiB)
#   WEBTERM_RESTORE_MAX_MEMBERS max number of entries in a 3.7 archive       (default 20000)
#
#   --verify (3.6.8): a restore TEST that changes nothing — the same checks as steps 1–2; the
#   result is recorded for Settings → System health ("restore verified").
set -euo pipefail

VERIFY=0 LEGACY_IMPORT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --verify) VERIFY=1; shift ;;
    --legacy-import) LEGACY_IMPORT=1; shift ;;
    --) shift; break ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
ARCHIVE="${1:?usage: ./restore.sh [--verify] [--legacy-import] <archive.wtbk|.tar.gz|.enc>}"
SRC_NAME="$ARCHIVE"
[ -f "$ARCHIVE" ] || { echo "not found: $ARCHIVE"; exit 1; }
VOLUME="${WEBTERM_VOLUME:-webterm_webterm-data}"
OWNER="${WEBTERM_UID:-10001:10001}"
# Plafon anti bombă de compresie (acelaşi spirit ca `_gunzip_bounded` din gateway/app/backup.py).
RESTORE_MAX_BYTES="${WEBTERM_RESTORE_MAX_BYTES:-2147483648}"
RESTORE_MAX_MEMBERS="${WEBTERM_RESTORE_MAX_MEMBERS:-20000}"
# Imaginea-unealtă (doar scanarea unei arhive 3.7): pinuită pe digest, ca în backup.sh.
# `WEBTERM_IMAGE` înseamnă imaginea GATEWAY-ULUI peste tot altundeva; aici e ignorată.
IMAGE="${WEBTERM_TOOL_IMAGE:-python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df}"
if [ -z "${WEBTERM_TOOL_IMAGE:-}" ] && [ -n "${WEBTERM_IMAGE:-}" ]; then
  echo "note: WEBTERM_IMAGE is the gateway image and is IGNORED here;" \
       "use WEBTERM_TOOL_IMAGE to change the python image ($IMAGE)." >&2
fi

# Un singur trap: temporarele şi — dacă l-am oprit noi ŞI ştim că volumul e într-o stare bună —
# repornirea app-ului. RESTART_OK=0 cât timp staging-ul rulează: o ieşire în mijlocul lui (Ctrl-C,
# crash) nu porneşte un gateway peste o stare pe care n-o cunoaştem (H2).
PRIV="" APP_CID="" APP_STOPPED=0 RESTART_OK=1
# shellcheck disable=SC2329  # invoked through the EXIT trap
cleanup() {
  if [ "$APP_STOPPED" = 1 ]; then
    if [ "$RESTART_OK" = 1 ]; then
      echo "restarting the app…" >&2
      docker start "$APP_CID" >/dev/null 2>&1 \
        || echo "!! could not restart the app — run: docker start $APP_CID" >&2
    else
      echo "!! the app was NOT restarted: the staging step did not finish cleanly. Read the output" >&2
      echo "   above; the gateway applies only a completely staged set, so starting it is safe once" >&2
      echo "   you have read it:  docker start $APP_CID" >&2
    fi
  fi
  [ -z "${PRIV:-}" ] || rm -rf "$PRIV"
}
trap cleanup EXIT

# ── 1. copia privată, fixată (M5) ────────────────────────────────────────────
# Tot ce urmează citeşte ACEASTĂ copie (0600 într-un director 0700), iar digestul ei se verifică
# din nou în containerul care o pune în staging: arhiva verificată e arhiva aplicată.
umask 077
PRIV=$(mktemp -d)
chmod 700 "$PRIV"
PINNED="$PRIV/archive"
case "$ARCHIVE" in
  *.enc)
    : "${WEBTERM_BACKUP_PASSPHRASE:?encrypted archive — set WEBTERM_BACKUP_PASSPHRASE}"
    command -v openssl >/dev/null 2>&1 || { echo "openssl is missing (required for .enc)"; exit 1; }
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
      -in "$ARCHIVE" -out "$PINNED" -pass env:WEBTERM_BACKUP_PASSPHRASE \
      || { echo "decryption failed (wrong passphrase?)"; exit 1; }
    ;;
  *) cp -- "$ARCHIVE" "$PINNED" ;;
esac
chmod 600 "$PINNED"
SHA=$(sha256sum "$PINNED" | cut -d' ' -f1)
if [ "$(head -c 5 "$PINNED")" = WTBK1 ]; then
  AKIND=wtbk
  : "${WEBTERM_BACKUP_PASSPHRASE:?encrypted archive (.wtbk) — set WEBTERM_BACKUP_PASSPHRASE}"
elif [ "$(od -An -tx1 -N2 "$PINNED" | tr -d ' \n')" = 1f8b ]; then
  AKIND=legacy
else
  echo "REFUSING: '$SRC_NAME' is not a WebTerm backup (neither .wtbk nor a 3.7 tar.gz) — nothing was changed." >&2
  exit 1
fi

# ── scanarea structurală a unei arhive 3.7 (tar.gz), cu imaginea-unealtă, fără reţea ─────────
# Plafoane (bombă de compresie, număr de membri), DB integru, `secret` prezent, niciun material
# de chei 3.8. Decizia finală (extractorul strict, cheile) rămâne a gateway-ului, la pasul 2.
PY_SCAN=$(cat <<'PY'
import gzip, io, os, sqlite3, sys, tarfile, tempfile
IN = os.environ.get("WT_IN", "/in")
maxb, maxm = int(os.environ["MAXB"]), int(os.environ["MAXM"])
KEY_MATERIAL = ("master.key", "master.key.tmp", "keys.wtk", "keys.wtk.tmp", "migrating.wtm",
                "migrating.wtm.tmp", "erasures.wtj")


def top(name):
    return os.path.normpath(name).lstrip("/").split("/", 1)[0]


flat, read = io.BytesIO(), 0
try:
    with gzip.open(os.path.join(IN, "archive"), "rb") as g:
        while True:
            chunk = g.read(1 << 20)
            if not chunk:
                break
            read += len(chunk)
            if read > maxb:
                sys.exit("refusing: archive unpacks beyond %d bytes (possible compression bomb)" % maxb)
            flat.write(chunk)
except (OSError, EOFError) as e:
    sys.exit("corrupt archive, or not a WebTerm backup: %s" % e)
flat.seek(0)
try:
    t = tarfile.open(fileobj=flat, mode="r:")
except tarfile.TarError as e:
    sys.exit("corrupt archive, or not a WebTerm backup: %s" % e)
with t:
    members = t.getmembers()
    if len(members) > maxm:
        sys.exit("refusing: archive has %d entries (> %d)" % (len(members), maxm))
    names = [m.name for m in members]
    if len(set(names)) != len(names):
        # un nume de două ori = scanarea şi extragerea pot vedea membri diferiţi
        sys.exit("refusing: the archive lists the same name twice")
    byname = {m.name: m for m in members}
    tops = {top(m.name) for m in members}
    if "webterm.db" not in byname or not byname["webterm.db"].isfile():
        sys.exit("archive without webterm.db")
    bad = sorted(tops.intersection(KEY_MATERIAL))
    if bad:
        sys.exit("refusing: the archive contains %s — a 3.7 archive never holds 3.8 key files (a "
                 "protected volume's backup is a .wtbk)" % ", ".join(bad))
    if "secret" not in byname:
        sys.exit("archive without the vault key (secret) — refusing; it would restore "
                 "undecryptable credentials")
    td = tempfile.mkdtemp()
    t.extract(byname["webterm.db"], td, filter="data")
integ = sqlite3.connect(os.path.join(td, "webterm.db")).execute("PRAGMA integrity_check").fetchone()[0]
if integ != "ok":
    sys.exit("integrity FAILED: " + integ[:120])
print("scan: ok")
PY
)

scan_legacy() {   # → SCAN_OUT; 1 if refused
  local rc=0
  SCAN_OUT=$(docker run --rm -i --network none --entrypoint python3 \
       -v "$PRIV":/in:ro -e MAXB="$RESTORE_MAX_BYTES" -e MAXM="$RESTORE_MAX_MEMBERS" \
       "$IMAGE" -I - 2>&1 <<<"$PY_SCAN") || rc=$?
  [ "$rc" = 0 ] && printf '%s\n' "$SCAN_OUT" | grep -q '^scan: ok$'
}

# ── containerul app-ului şi felul în care rulăm codul lui ───────────────────────
# Containerul e cel care montează VOLUMUL la /data (nu un nume ghicit). Un `docker` care eşuează
# nu înseamnă „niciunul": e refuz.
find_app() {   # → APP_CID ("" = none); 1 when Docker cannot tell
  local ids id m svc
  APP_CID="${WEBTERM_APP_CONTAINER:-}"
  if [ -n "$APP_CID" ]; then
    m=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$APP_CID") || return 1
    [ "$m" = "$VOLUME" ] || { APP_ERR="container $APP_CID mounts '${m:-nothing}' at /data, not '$VOLUME'"; return 1; }
    return 0
  fi
  ids=$(docker ps -a -q --filter "volume=$VOLUME") || { APP_ERR="docker ps failed"; return 1; }
  for id in $ids; do
    m=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$id") \
      || { APP_ERR="docker inspect failed"; return 1; }
    [ "$m" = "$VOLUME" ] || continue
    svc=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$id") \
      || { APP_ERR="docker inspect failed"; return 1; }
    [ "$svc" = app ] || continue
    APP_CID=$id
    return 0
  done
  return 0
}

# Un container nou pe imaginea app-ului (ID-ul exact pe care rulează), ca userul serviciului,
# fără reţea. Cheia: DOAR căile ei (WEBTERM_MASTER_KEY_FILE / WEBTERM_KEY_IN_VOLUME, nume şi căi,
# nu valori secrete) şi montarea read-only a directorului care o conţine (secrets/master-key/).
# Cheia brută într-o variabilă de mediu nu se copiază niciodată (M5): refuz, cu explicaţie.
APP_IMG="" KEY_ARGS=()
app_run_args() {   # → APP_IMG, KEY_ARGS; 1 + APP_ERR when the key setup cannot be reproduced
  local envs kf kv want mounts typ name src dst found=""
  APP_IMG=$(docker inspect --format '{{.Image}}' "$APP_CID") || { APP_ERR="cannot inspect $APP_CID"; return 1; }
  envs=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$APP_CID") \
    || { APP_ERR="cannot inspect $APP_CID"; return 1; }
  if printf '%s\n' "$envs" | grep -q '^WEBTERM_MASTER_KEY=.'; then
    APP_ERR="the master key is given as a value (WEBTERM_MASTER_KEY); host scripts never copy it — use a key file (WEBTERM_MASTER_KEY_FILE)"
    return 1
  fi
  kf=$(printf '%s\n' "$envs" | sed -n 's/^WEBTERM_MASTER_KEY_FILE=//p' | head -n1)
  kv=$(printf '%s\n' "$envs" | sed -n 's/^WEBTERM_KEY_IN_VOLUME=//p' | head -n1)
  KEY_ARGS=(-e "WEBTERM_MASTER_KEY_FILE=$kf" -e "WEBTERM_KEY_IN_VOLUME=$kv")
  want="${kf:-/run/secrets/webterm_master_key}"
  if [ -z "$kf" ] && [ "$kv" = 1 ]; then want=""; fi
  [ -n "$want" ] || return 0
  mounts=$(docker inspect --format '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}|{{.Destination}}{{println}}{{end}}' "$APP_CID") \
    || { APP_ERR="cannot inspect $APP_CID"; return 1; }
  while IFS='|' read -r typ name src dst; do
    if [ -z "$dst" ] || [ "$dst" = /data ]; then continue; fi
    case "$want" in "$dst"|"$dst"/*) ;; *) continue ;; esac
    [ "$typ" = volume ] && src="$name"
    KEY_ARGS+=(-v "$src:$dst:ro")
    found=1
  done <<<"$mounts"
  if [ -z "$found" ] && [ -n "$kf" ]; then
    APP_ERR="the key file $kf is not on a mount of the app container"
    return 1
  fi
  return 0
}

# hostops live|ro|rw ARGS…  — `python3 -m app.hostops` cu stdin/stdout trecute mai departe.
# live: în containerul app-ului pornit (`docker exec`, ca userul serviciului, cu mediul lui);
# ro/rw: un container nou cu volumul montat read-only / read-write (app_run_args înainte).
hostops() {
  local mode="$1"; shift
  if [ "$mode" = live ]; then
    docker exec -i -u "$OWNER" -e WEBTERM_BACKUP_PASSPHRASE "$APP_CID" python3 -m app.hostops "$@"
    return
  fi
  local ro=""; [ "$mode" = ro ] && ro=":ro"
  docker run --rm -i --network none --user "$OWNER" --entrypoint python3 \
    -v "$VOLUME:/data$ro" "${KEY_ARGS[@]}" -e WEBTERM_BACKUP_PASSPHRASE "$APP_IMG" -m app.hostops "$@"
}

app_running() {
  [ "$(docker inspect --format '{{.State.Running}}' "$APP_CID" 2>/dev/null || echo false)" = true ]
}

# ── --verify: a restore test that changes nothing ────────────────────────────
RV_SELF_DIR=$(cd "$(dirname "$0")" && pwd -P)
RV_NAME=$(basename "$SRC_NAME")
rv_record() {   # rv_record ok|error MESSAGE
  [ "$VERIFY" = 1 ] || return 0
  if [ -x "$RV_SELF_DIR/host-health.sh" ]; then
    "$RV_SELF_DIR/host-health.sh" --record restore-verify "$1" "$2" \
      "$(printf '{"archive":"%s"}' "$(printf '%s' "$RV_NAME" | tr -cd 'A-Za-z0-9._-' | cut -c1-128)")" \
      >/dev/null 2>&1 || true
  fi
}
refuse() {   # refuse MESSAGE…  — nothing was changed
  printf '%s\n' "$@" >&2
  rv_record error "restore test FAILED for $RV_NAME: $(printf '%s' "$1" | cut -c1-120)"
  exit 1
}
LI=(); [ "$LEGACY_IMPORT" = 1 ] && LI=(--legacy-import)

if [ "$AKIND" = legacy ]; then
  docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null 2>&1 \
    || refuse "REFUSING: cannot get the helper image '$IMAGE' (no registry access?)." \
              "         It scans 3.7 archives. Pre-pull it (docker pull $IMAGE) or set WEBTERM_TOOL_IMAGE."
  if ! scan_legacy; then
    refuse "$(printf '%s' "$SCAN_OUT" | tail -n1)" \
           "REFUSING: '$SRC_NAME' is not a restorable WebTerm backup — nothing was changed."
  fi
fi

# Volumul TREBUIE să existe: Docker ar crea tăcut unul gol, iar restore-ul ar „reuşi" într-un
# volum pe care nu-l foloseşte nimic. Doar „confirmat absent" sau eroare: ambele = refuz.
docker volume inspect "$VOLUME" >/dev/null 2>&1 || refuse \
  "REFUSING: volume '$VOLUME' does not exist (or Docker cannot inspect it)." \
  "          The name comes from the install directory: for /opt/webterm2 it is webterm2_webterm-data." \
  "          List them with 'docker volume ls', then:  WEBTERM_VOLUME=<name> $0 $SRC_NAME"

APP_ERR=""
find_app || refuse "REFUSING: cannot identify the app container of '$VOLUME' ($APP_ERR) — nothing was changed."
[ -n "$APP_CID" ] || refuse \
  "REFUSING: no app container uses volume '$VOLUME': the archive is checked and staged with the app's" \
  "          own code. Start the installation once (docker compose up -d), then run this again."

# ── 2. verificarea cu codul gateway-ului ─────────────────────────────────────
if app_running; then VMODE=live; else
  app_run_args || refuse "REFUSING: $APP_ERR — nothing was changed."
  VMODE=ro
fi
rc=0
VOUT=$(hostops "$VMODE" verify --sha256 "$SHA" "${LI[@]}" <"$PINNED" 2>&1) || rc=$?
if [ "$rc" != 0 ]; then
  if printf '%s' "$VOUT" | grep -q 'No module named'; then
    VOUT="the app image cannot run app.hostops: it is older than 3.8 — restore with the restore.sh of its own version"
  fi
  refuse "$(printf '%s' "$VOUT" | grep -v '^\(sha256\|volume-key\): ' | tail -n3)" \
         "REFUSING: '$SRC_NAME' was not confirmed restorable on this installation — nothing was changed."
fi
VOLUME_KIND=$(printf '%s\n' "$VOUT" | sed -n 's/^volume: //p')
printf '%s\n' "$VOUT" | grep -v '^\(sha256\|volume-key\|volume\|archive\): ' || true

if [ "$VERIFY" = 1 ]; then
  echo "restore test OK: '$RV_NAME' passes the gateway's restore checks on this installation" \
       "(${VOLUME_KIND:-?} volume)"
  rv_record ok "restore test passed for $RV_NAME"
  exit 0
fi

# ── 3. confirmare, oprire, staging sub lock-ul volumului ──────────────────────
echo "!! This REPLACES all data in volume '$VOLUME' with '$SRC_NAME' (applied when the app starts)."
read -r -p "Continue? [y/N] " ok; [ "$ok" = y ] || { echo "aborted"; exit 1; }

if app_running; then
  docker stop "$APP_CID" >/dev/null || { echo "REFUSING: could not stop the app ($APP_CID) — nothing was changed." >&2; exit 1; }
  APP_STOPPED=1
fi
# SIGURANŢĂ DURĂ: niciun alt container pe volum. Un `docker ps` care eşuează nu dovedeşte nimic.
USERS=$(docker ps -q --filter "volume=$VOLUME") \
  || { echo "REFUSING: cannot list the containers using '$VOLUME' — nothing was changed." >&2; exit 1; }
if [ -n "$USERS" ]; then
  echo "REFUSING: a container is still using volume '$VOLUME' ($(printf '%s' "$USERS" | tr '\n' ' '))" \
       "— nothing was changed. Stop it first." >&2
  exit 1
fi
app_run_args || { echo "REFUSING: $APP_ERR — nothing was changed." >&2; exit 1; }

RESTART_OK=0
rc=0
SOUT=$(hostops rw stage-restore --sha256 "$SHA" "${LI[@]}" <"$PINNED" 2>&1) || rc=$?
case "$rc" in
  0) RESTART_OK=1 ;;
  3) RESTART_OK=1
     printf '%s\n' "$SOUT" >&2
     echo "REFUSING: nothing was staged; the data is as it was." >&2
     exit 1 ;;
  *) printf '%s\n' "$SOUT" >&2
     echo "!! the staging step ended unexpectedly (exit $rc)." >&2
     exit 1 ;;
esac
printf '%s\n' "$SOUT" | grep -v '^sha256: ' || true

# ── 4. pornire: boot-ul aplică setul, sub lock-ul lui ────────────────────────
docker start "$APP_CID" >/dev/null
APP_STOPPED=0
st=starting
for _ in $(seq 1 60); do
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$APP_CID" 2>/dev/null || echo missing)
  [ "$st" = healthy ] && break
  sleep 2
done
if [ "$st" != healthy ]; then
  echo "✗ the app did not report healthy within 120s (status: $st). Its log:" >&2
  docker logs --tail 30 "$APP_CID" 2>&1 | tail -n 30 >&2 || true
  echo "  The staged restore is applied by the app's boot; it stays staged until a boot applies it." >&2
  exit 1
fi
echo "restored from $SRC_NAME (applied by the app at boot)"
echo "  the app kept a safety copy of the previous state in the volume (backups/, see its log)"
