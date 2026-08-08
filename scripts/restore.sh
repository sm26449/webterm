#!/usr/bin/env bash
# Restore a WebTerm backup produced by backup.sh into the data volume.
# Stops the app, wipes + extracts the archive (preserving the numeric owner the
# container expects), verifies DB integrity, then starts the app again.
#
#   ./restore.sh <archive.tar.gz|.enc>
#   WEBTERM_VOLUME              Docker volume name   (default webterm_webterm-data)
#   WEBTERM_UID                 owner uid:gid inside (default 10001:10001)
#   WEBTERM_TOOL_IMAGE          image with python3   (default python:3.12-alpine)
#   COMPOSE_FILE                compose file to (re)start the app (default docker-compose.yml)
#   WEBTERM_BACKUP_PASSPHRASE   required if the archive is encrypted (.enc from backup.sh)
set -euo pipefail

ARCHIVE="${1:?usage: ./restore.sh <archive.tar.gz|.enc>}"
SRC_NAME="$ARCHIVE"      # numele TASTAT de om; `$ARCHIVE` devine un mktemp după decriptare
[ -f "$ARCHIVE" ] || { echo "not found: $ARCHIVE"; exit 1; }
VOLUME="${WEBTERM_VOLUME:-webterm_webterm-data}"
OWNER="${WEBTERM_UID:-10001:10001}"
# Vezi nota din `backup.sh`: `WEBTERM_IMAGE` înseamnă imaginea GATEWAY-ULUI peste tot
# altundeva, iar aici însemna „o imagine cu python3". Backupul a păţit-o deja o dată şi s-a
# reparat local; restaurarea nu avea nici măcar acea plasă, şi pierde mai mult: entrypoint-ul
# imaginii aplicaţiei coboară la userul `webterm`, extragerea reuşeşte, iar `os.chown` cade cu
# PermissionError — DUPĂ ce datele vechi au fost deja mutate în `.restore-prev`. Adică exact
# fereastra în care serviciul rămâne jos şi omul crede că şi-a pierdut datele.
IMAGE="${WEBTERM_TOOL_IMAGE:-python:3.12-alpine}"
if [ -z "${WEBTERM_TOOL_IMAGE:-}" ] && [ -n "${WEBTERM_IMAGE:-}" ]; then
  echo "note: WEBTERM_IMAGE is the gateway image and is IGNORED here;" \
       "use WEBTERM_TOOL_IMAGE to change the python image ($IMAGE)." >&2
fi

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
    trap 'rm -f "$DECTMP"' EXIT      # înlocuit mai jos de trap-ul care reporneşte şi app-ul
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

# Numele pe care îl confirmi trebuie să fie cel pe care l-ai TASTAT. După decriptare
# `$ARCHIVE` e un mktemp aleatoriu, deci promptul cerea confirmarea pentru
# „/tmp/tmp.iSVaLjc0Dn.tar.gz" — un nume care nu-i spune omului nimic.
# Volumul TREBUIE să existe. `backup.sh` are garda asta de mult (refuză să scrie o arhivă
# goală); restaurarea n-o avea, deşi acolo costul e mai mare: Docker creează tăcut volumul
# lipsă, restaurarea reuşeşte în el, iese cu 0 şi tipăreşte „restore OK" — în timp ce aplicaţia
# vie rămâne pe volumul ei, cu datele ei. Omul citeşte „restore OK" după un dezastru şi crede
# că a recuperat. Un nume greşit e cazul obişnuit, nu exotic: numele vine din directorul de
# instalare, iar procedura din RUNBOOK e copiată literal de pe o maşină pe alta.
# Imaginea-unealtă trebuie să fie DISPONIBILĂ. `docker run` o trage la fiecare rulare, iar dacă
# registry-ul e inaccesibil (host air-gapped, DNS căzut, Docker Hub jos, rate-limit) ieşea
# eroarea crudă a Docker-ului şi exit 125 — fără nicio menţiune a produsului, fără sugestie, şi
# în cazul timer-ului nocturn fără ca cineva să afle. Un backup care nu se face tăcut e mai rău
# decât unul care nu există: crezi că-l ai.
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null 2>&1 || {
  echo "REFUSING: cannot get the helper image '$IMAGE' (no registry access?)." >&2
  echo "         It is only used to run python3 against the data volume. Either pre-pull it" >&2
  echo "         once while you have network:   docker pull $IMAGE" >&2
  echo "         or point WEBTERM_TOOL_IMAGE at an image you already have that has python3." >&2
  exit 1
}

docker volume inspect "$VOLUME" >/dev/null 2>&1 || {
  echo "REFUSING: volume '$VOLUME' does not exist — restoring into it would create an empty" >&2
  echo "          volume that nothing uses, while your app keeps running on another one." >&2
  echo "          The name comes from the install directory: for /opt/webterm2 it is" >&2
  echo "          webterm2_webterm-data. List them with 'docker volume ls', then:" >&2
  echo "            WEBTERM_VOLUME=<name> $0 $SRC_NAME" >&2
  exit 1
}

echo "!! This OVERWRITES all data in volume '$VOLUME' with '$SRC_NAME'."
read -r -p "Continue? [y/N] " ok; [ "$ok" = y ] || { echo "aborted"; exit 1; }

# Din clipa asta aplicaţia e oprită. Orice ieşire — reuşită, eşec de validare, Ctrl-C —
# trebuie să o repornească: un restore care eşuează nu are voie să lase serviciul jos.
APP_STOPPED=0
restart_app() {
  [ "$APP_STOPPED" = 1 ] || return 0
  echo "restarting the app…" >&2
  $COMPOSE -f "$FILE" up -d app >/dev/null 2>&1 \
    || echo "!! could not restart the app — run: $COMPOSE -f $FILE up -d app" >&2
}
trap 'restart_app; rm -f "${DECTMP:-}"' EXIT
$COMPOSE -f "$FILE" stop app 2>/dev/null || true
APP_STOPPED=1
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
docker run --rm -i --entrypoint python3 \
  -v "$VOLUME":/data -v "$ADIR":/in:ro -e ABASE="$ABASE" -e OWNER="$OWNER" \
  "$IMAGE" - <<'PY'
import os, sys, shutil, sqlite3, tarfile
staging, prev = "/data/.restore-staging", "/data/.restore-prev"
shutil.rmtree(staging, ignore_errors=True); os.makedirs(staging)
with tarfile.open("/in/" + os.environ["ABASE"], "r:gz") as t:
    t.extractall(staging, filter="data")          # anti path-traversal/symlink (Py 3.12)
db = os.path.join(staging, "webterm.db")
if not os.path.exists(db):
    shutil.rmtree(staging, ignore_errors=True); sys.exit("archive without webterm.db")
# `secret` e cheia care decriptează TOATE credenţialele. O arhivă fără ea restaurează o
# bază de date pe care nimeni n-o mai poate folosi — şi pentru că `integrity_check` pe un
# SQLite gol întoarce `ok`, restul verificărilor o declarau bună.
if not os.path.exists(os.path.join(staging, "secret")):
    shutil.rmtree(staging, ignore_errors=True)
    sys.exit("archive without the vault key (secret) — refusing; it would restore "
             "undecryptable credentials")
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
print("restore OK (integrity ok); previous state kept in /data/.restore-prev")
PY

# Flagul se stinge DUPĂ pornirea reuşită, nu înainte: aici era resetat mai devreme, deci
# dacă `up -d app` eşua (imagine lipsă, `docker login` expirat — cazul realist al unui
# restore de dezastru pe o maşină nouă), `set -e` ieşea, trap-ul rula, iar `restart_app`
# se întorcea imediat pentru că APP_STOPPED era deja 0. Aplicaţia rămânea jos, în tăcere —
# exact comportamentul pe care trap-ul trebuia să-l elimine.
$COMPOSE -f "$FILE" up -d app
APP_STOPPED=0
echo "restored from $SRC_NAME"
# Plasa de siguranţă nu se curăţă singură, deci fiecare restore reuşit dublează ocuparea
# volumului până la următorul. Spunem CÂT ocupă şi cum se şterge — altfel mesajul cere o
# curăţenie fără să zică de ce contează, pe un volum care nu e cotat.
PREV_SZ=$(docker run --rm -v "$VOLUME":/data "$IMAGE" \
  sh -c 'du -sh /data/.restore-prev 2>/dev/null | cut -f1' 2>/dev/null || true)
echo "  safety net: the previous state is kept in volume '$VOLUME' at /data/.restore-prev${PREV_SZ:+ ($PREV_SZ)}"
echo "  it is NOT cleaned up automatically — once you have confirmed the restore, free it with:"
echo "    docker run --rm -v $VOLUME:/data $IMAGE rm -rf /data/.restore-prev"
