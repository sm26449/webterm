#!/usr/bin/env bash
# Restore a WebTerm backup produced by backup.sh into the data volume.
# Stops the app, wipes + extracts the archive (preserving the numeric owner the
# container expects), verifies DB integrity, then starts the app again.
#
#   ./restore.sh <archive.tar.gz|.enc>
#   WEBTERM_VOLUME              Docker volume name   (default webterm_webterm-data)
#   WEBTERM_UID                 owner uid:gid inside (default 10001:10001)
#   WEBTERM_IMAGE               image with python3   (default python:3.12-alpine)
#   COMPOSE_FILE                compose file to (re)start the app (default docker-compose.yml)
#   WEBTERM_BACKUP_PASSPHRASE   required if the archive is encrypted (.enc from backup.sh)
set -euo pipefail

ARCHIVE="${1:?usage: ./restore.sh <archive.tar.gz|.enc>}"
[ -f "$ARCHIVE" ] || { echo "not found: $ARCHIVE"; exit 1; }
VOLUME="${WEBTERM_VOLUME:-webterm_webterm-data}"
OWNER="${WEBTERM_UID:-10001:10001}"
IMAGE="${WEBTERM_IMAGE:-python:3.12-alpine}"

# Arhivă criptată (.enc): decriptează într-un temp plaintext (openssl + parolă) înainte de restore.
DECTMP=""
case "$ARCHIVE" in
  *.enc)
    : "${WEBTERM_BACKUP_PASSPHRASE:?encrypted archive — set WEBTERM_BACKUP_PASSPHRASE}"
    command -v openssl >/dev/null 2>&1 || { echo "openssl is missing (required for .enc)"; exit 1; }
    DECTMP="$(mktemp --suffix=.tar.gz)"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
      -in "$ARCHIVE" -out "$DECTMP" -pass env:WEBTERM_BACKUP_PASSPHRASE \
      || { rm -f "$DECTMP"; echo "decryption failed (wrong passphrase?)"; exit 1; }
    trap 'rm -f "$DECTMP"' EXIT
    ARCHIVE="$DECTMP"
    ;;
esac
# auto-detectează compose-ul: prod are docker-compose.prod.yml, nu docker-compose.yml.
# Default-ul greșit făcea `stop app` să eșueze tăcut → wipe cu SQLite VIU (corupere).
FILE="${COMPOSE_FILE:-}"
if [ -z "$FILE" ]; then
  for f in docker-compose.prod.yml docker-compose.yml; do
    [ -f "$f" ] && FILE="$f" && break
  done
fi
[ -n "$FILE" ] || { echo "no compose file found (set COMPOSE_FILE)"; exit 1; }
COMPOSE="docker compose"; docker compose version >/dev/null 2>&1 || COMPOSE="docker-compose"

ADIR="$(cd "$(dirname "$ARCHIVE")" && pwd)"; ABASE="$(basename "$ARCHIVE")"

echo "!! This OVERWRITES all data in volume '$VOLUME' with '$ARCHIVE'."
read -r -p "Continue? [y/N] " ok; [ "$ok" = y ] || { echo "aborted"; exit 1; }

$COMPOSE -f "$FILE" stop app 2>/dev/null || true
# SIGURANȚĂ DURĂ: nu șterge volumul dacă VREUN container încă îl folosește — un SQLite
# viu scriind peste extract = corupere. Abortăm zgomotos (înlocuiește vechiul `|| true`).
if docker ps -q --filter volume="$VOLUME" | grep -q .; then
  echo "!! a container is still using volume '$VOLUME' — refusing to wipe it (that would corrupt live data)." >&2
  echo "   Stop it first:  $COMPOSE -f $FILE down" >&2
  exit 1
fi

# Extrage în STAGING → validează → abia apoi swap. Vechiul flux făcea `rm -rf ./*` ÎNAINTE
# de validare: o arhivă coruptă/parțială distrugea datele fără cale de întoarcere. Acum
# datele curente se ating DOAR după ce noul DB trece integrity_check, iar starea veche se
# mută în /data/.restore-prev ca plasă de siguranță. Tot în Python (fără capcane de globbing).
docker run --rm -i -v "$VOLUME":/data -v "$ADIR":/in:ro -e ABASE="$ABASE" -e OWNER="$OWNER" \
  "$IMAGE" python3 - <<'PY'
import os, sys, shutil, sqlite3, tarfile
staging, prev = "/data/.restore-staging", "/data/.restore-prev"
shutil.rmtree(staging, ignore_errors=True); os.makedirs(staging)
with tarfile.open("/in/" + os.environ["ABASE"], "r:gz") as t:
    t.extractall(staging, filter="data")          # anti path-traversal/symlink (Py 3.12)
db = os.path.join(staging, "webterm.db")
if not os.path.exists(db):
    shutil.rmtree(staging, ignore_errors=True); sys.exit("arhivă fără webterm.db")
integ = sqlite3.connect(db).execute("PRAGMA integrity_check").fetchone()[0]
if integ != "ok":
    shutil.rmtree(staging, ignore_errors=True); sys.exit("integrity FAILED: " + integ)
# valid → mută datele curente în plasa de siguranță, apoi noul conținut în loc
shutil.rmtree(prev, ignore_errors=True); os.makedirs(prev)
for name in os.listdir("/data"):
    if name in (".restore-staging", ".restore-prev"):
        continue
    shutil.move(os.path.join("/data", name), os.path.join(prev, name))
for name in os.listdir(staging):
    shutil.move(os.path.join(staging, name), os.path.join("/data", name))
shutil.rmtree(staging, ignore_errors=True)
uid, gid = (int(x) for x in os.environ["OWNER"].split(":"))
os.chown("/data", uid, gid)
for root, dirs, files in os.walk("/data"):
    for n in dirs + files:
        try: os.chown(os.path.join(root, n), uid, gid)
        except OSError: pass
print("restore OK (integrity ok); starea veche în /data/.restore-prev")
PY

$COMPOSE -f "$FILE" up -d app
echo "restored from ${1}"
echo "  (safety net: the old state is in volume '$VOLUME' at /data/.restore-prev —"
echo "   delete it once you have confirmed everything is fine)"
