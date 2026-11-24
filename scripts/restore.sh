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
#   WEBTERM_RESTORE_MAX_BYTES   decompressed-size cap, anti compression-bomb (default 2 GiB)
#   WEBTERM_RESTORE_MAX_MEMBERS max number of entries in the archive       (default 20000)
#
#   WEBTERM_APP_CONTAINER       app container whose key settings and mounts check a protected
#                               archive (default: `docker compose ps -a -q app`)
#
#   Protected archives (3.8, encryption at rest: `keys.wtk` instead of `secret`) restore only
#   when the master key this installation is configured with opens the archive's keys.wtk:
#   checked with the app image, read-only and before the app is stopped. The data directory's
#   `.lock` is never moved or removed.
#
#   ./restore.sh --verify <archive>   (3.6.8) a restore TEST: decrypt + unpack (bounded) + SQLite
#                                     integrity check in a throw-away container with no network;
#                                     the app and the data volume are NOT touched. The result is
#                                     recorded for Settings → System health ("restore verified").
set -euo pipefail

VERIFY=0
if [ "${1:-}" = "--verify" ]; then VERIFY=1; shift; fi
ARCHIVE="${1:?usage: ./restore.sh [--verify] <archive.tar.gz|.enc>}"
SRC_NAME="$ARCHIVE"      # numele TASTAT de om; `$ARCHIVE` devine un mktemp după decriptare
[ -f "$ARCHIVE" ] || { echo "not found: $ARCHIVE"; exit 1; }
VOLUME="${WEBTERM_VOLUME:-webterm_webterm-data}"
OWNER="${WEBTERM_UID:-10001:10001}"
# Plafon anti bombă de compresie (acelaşi spirit ca `_gunzip_bounded` din gateway/app/backup.py):
# un tar.gz mic poate declara/expanda la zeci de GB şi umple volumul de date la extragere. Un
# snapshot WebTerm real e mic (DB + cheie), deci plafonăm DECOMPRIMATUL la 2 GiB şi numărul de
# membri — refuzăm înainte de a atinge discul. Configurabil pentru instalări mari.
RESTORE_MAX_BYTES="${WEBTERM_RESTORE_MAX_BYTES:-2147483648}"      # 2 GiB decomprimat
RESTORE_MAX_MEMBERS="${WEBTERM_RESTORE_MAX_MEMBERS:-20000}"       # nr. maxim de intrări în arhivă
# Vezi nota din `backup.sh`: `WEBTERM_IMAGE` înseamnă imaginea GATEWAY-ULUI peste tot
# altundeva, iar aici însemna „o imagine cu python3". Backupul a păţit-o deja o dată şi s-a
# reparat local; restaurarea nu avea nici măcar acea plasă, şi pierde mai mult: entrypoint-ul
# imaginii aplicaţiei coboară la userul `webterm`, extragerea reuşeşte, iar `os.chown` cade cu
# PermissionError — DUPĂ ce datele vechi au fost deja mutate în `.restore-prev`. Adică exact
# fereastra în care serviciul rămâne jos şi omul crede că şi-a pierdut datele.
# Pinuit pe DIGEST, ca în backup.sh: restore rulează această imagine ca root peste volumul de
# date, ŞTERGÂND şi rescriind DB-ul + cheia seifului — adică exact „containerul cel mai puternic".
# Un tag flotant (`python:3.12-alpine`) însemna că cine poate muta tag-ul alege ce cod rescrie
# seiful. Acelaşi digest ca backup.sh.
IMAGE="${WEBTERM_TOOL_IMAGE:-python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df}"
if [ -z "${WEBTERM_TOOL_IMAGE:-}" ] && [ -n "${WEBTERM_IMAGE:-}" ]; then
  echo "note: WEBTERM_IMAGE is the gateway image and is IGNORED here;" \
       "use WEBTERM_TOOL_IMAGE to change the python image ($IMAGE)." >&2
fi

# Curăţenie unică pentru orice ieşire: temporarele (arhiva decriptată, manifestul extras, env-ul
# cheii) şi — dacă l-am oprit noi — repornirea app-ului. Un singur trap, ca un al doilea să nu-l
# înlocuiască tăcut pe primul.
DECTMP="" KOUT="" ENVF="" APP_STOPPED=0 FILE="" COMPOSE="docker compose"
restart_app() {
  [ "$APP_STOPPED" = 1 ] || return 0
  echo "restarting the app…" >&2
  $COMPOSE -f "$FILE" up -d app >/dev/null 2>&1 \
    || echo "!! could not restart the app — run: $COMPOSE -f $FILE up -d app" >&2
}
# shellcheck disable=SC2329  # invoked through the EXIT trap
cleanup() {
  restart_app
  rm -f "${DECTMP:-}" "${ENVF:-}"
  [ -z "${KOUT:-}" ] || rm -rf "$KOUT"
}
trap cleanup EXIT

# Arhivă criptată (.enc): decriptează într-un temp plaintext (openssl + parolă) înainte de restore.
case "$ARCHIVE" in
  *.enc)
    : "${WEBTERM_BACKUP_PASSPHRASE:?encrypted archive — set WEBTERM_BACKUP_PASSPHRASE}"
    command -v openssl >/dev/null 2>&1 || { echo "openssl is missing (required for .enc)"; exit 1; }
    DECTMP="$(mktemp --suffix=.tar.gz)"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
      -in "$ARCHIVE" -out "$DECTMP" -pass env:WEBTERM_BACKUP_PASSPHRASE \
      || { echo "decryption failed (wrong passphrase?)"; exit 1; }
    ARCHIVE="$DECTMP"
    ;;
esac
ADIR="$(cd "$(dirname "$ARCHIVE")" && pwd)"; ABASE="$(basename "$ARCHIVE")"

# auto-detectează compose-ul: prod are docker-compose.prod.yml, nu docker-compose.yml.
# Default-ul greșit făcea `stop app` să eșueze tăcut → wipe cu SQLite VIU (corupere).
# (--verify îl foloseşte doar ca să găsească app-ul pentru verificarea cheii; restore-ul îl cere.)
FILE="${COMPOSE_FILE:-}"
if [ -z "$FILE" ]; then
  for f in docker-compose.prod.yml docker-compose.yml; do
    [ -f "$f" ] && FILE="$f" && break
  done
fi
docker compose version >/dev/null 2>&1 || COMPOSE="docker-compose"

# Imaginea-unealtă trebuie să fie DISPONIBILĂ. `docker run` o trage la fiecare rulare, iar dacă
# registry-ul e inaccesibil (host air-gapped, DNS căzut, Docker Hub jos, rate-limit) ieşea
# eroarea crudă a Docker-ului şi exit 125 — fără nicio menţiune a produsului, fără sugestie.
TOOL_OK=1
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null 2>&1 || TOOL_OK=0

# ── citirea arhivei: aceeaşi pentru --verify, pentru verificarea dinainte de oprire şi pentru
# aplicare (MODE=scan|apply). Un singur cod decide ce e o arhivă validă, ca verificarea şi
# restaurarea să nu poată ajunge la verdicte diferite.
# 3.8 (INV-14, docs/design/INVARIANTS.md): o arhivă a unui volum PROTEJAT are keys.wtk în locul lui
# `secret` şi niciodată cheia master; una cu ambele e refuzată (în afară de o migrare surprinsă la
# mijloc, cu migrating.wtm); `.lock` nu se restaurează şi nu se mută niciodată.
PY_RESTORE=$(cat <<'PY'
import gzip, hashlib, io, os, shutil, sqlite3, stat, sys, tarfile, tempfile
mode = os.environ["MODE"]                          # scan | apply
# WT_*: doar pentru testul hermetic (tests/host_backup_script_test.py); în container rămân căile fixe
D = os.environ.get("WT_DATA", "/data")
IN = os.environ.get("WT_IN", "/in")
KO = os.environ.get("WT_KOUT", "/kout")
maxb, maxm = int(os.environ["MAXB"]), int(os.environ["MAXM"])
staging, prev = os.path.join(D, ".restore-staging"), os.path.join(D, ".restore-prev")
LOCK = ".lock"
# cheia master şi temporarele protocolului de chei nu au ce căuta într-o arhivă
KEY_MATERIAL = ("master.key", "master.key.tmp", "keys.wtk.tmp", "migrating.wtm.tmp")


def fail(msg):
    if mode == "apply":
        shutil.rmtree(staging, ignore_errors=True)
    sys.exit(msg)


def top(name):
    return os.path.normpath(name).lstrip("/").split("/", 1)[0]


if mode == "apply":
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
# Decomprimare MĂRGINITĂ (acelaşi spirit ca _gunzip_bounded din gateway/app/backup.py): citim
# gzip-ul în bucăţi şi abandonăm dacă depăşeşte plafonul, ca o bombă de compresie să nu
# materializeze zeci de GB nici în RAM, nici pe disc. `GzipFile.read(n)` decomprimă cel mult n.
flat, read = io.BytesIO(), 0
try:
    with gzip.open(os.path.join(IN, os.environ["ABASE"]), "rb") as g:
        while True:
            chunk = g.read(1 << 20)
            if not chunk:
                break
            read += len(chunk)
            if read > maxb:
                fail("refusing: archive unpacks beyond %d bytes (possible compression bomb)" % maxb)
            flat.write(chunk)
except (OSError, EOFError) as e:
    fail("corrupt archive, or not a WebTerm backup: %s" % e)
flat.seek(0)
try:
    t = tarfile.open(fileobj=flat, mode="r:")
except tarfile.TarError as e:
    fail("corrupt archive, or not a WebTerm backup: %s" % e)
# tar-ul e acum plat ŞI mărginit; plafonăm şi numărul de membri (anti epuizare de inode-uri /
# many-tiny-files) înainte de extragere.
with t:
    members = t.getmembers()
    if len(members) > maxm:
        fail("refusing: archive has %d entries (> %d)" % (len(members), maxm))
    byname = {m.name: m for m in members}
    tops = {top(m.name) for m in members}
    if "webterm.db" not in byname or not byname["webterm.db"].isfile():
        fail("archive without webterm.db")
    bad = sorted(tops.intersection(KEY_MATERIAL))
    if bad:
        fail("refusing: the archive contains %s (key material, or an unfinished key operation); "
             "a backup never holds it" % ", ".join(bad))
    if "keys.wtk" in tops:
        kind = "protected"
        km = byname.get("keys.wtk")
        if km is None or not km.isfile() or km.size > (1 << 20):
            fail("refusing: keys.wtk in the archive is not a plain file")
        # secret + keys.wtk fără marker nu e o stare a migrării (protocolul scrie migrating.wtm
        # înaintea manifestului şi îl şterge după secret): o copie amestecată, refuzată
        if "secret" in tops and "migrating.wtm" not in tops:
            fail("refusing: the archive holds both secret and keys.wtk without migrating.wtm — "
                 "an inconsistent copy of a volume")
        keys_blob = t.extractfile(km).read()
        sha = hashlib.sha256(keys_blob).hexdigest()
    else:
        kind = "legacy"
        stray = sorted(tops.intersection(("migrating.wtm", "erasures.wtj")))
        if stray:
            fail("refusing: the archive contains %s without keys.wtk — an inconsistent copy of a "
                 "volume" % ", ".join(stray))
        # `secret` e cheia care decriptează TOATE credenţialele unui volum 3.7. O arhivă fără ea
        # restaurează o bază de date pe care nimeni n-o mai poate folosi — şi pentru că
        # `integrity_check` pe un SQLite gol întoarce `ok`, restul verificărilor o declarau bună.
        if "secret" not in byname:
            fail("archive without the vault key (secret) — refusing; it would restore "
                 "undecryptable credentials")
        sha = ""
    keep = [m for m in members if top(m.name) != LOCK]
    if mode == "scan":
        td = tempfile.mkdtemp()
        t.extract(byname["webterm.db"], td, filter="data")
        db = os.path.join(td, "webterm.db")
        if kind == "protected":
            kp = os.path.join(KO, "keys.wtk")
            with open(kp, "wb") as f:
                f.write(keys_blob)
            os.chmod(kp, 0o644)         # nu e secret: învelit sub cheia master
    else:
        # arhiva verificată înainte de oprire trebuie să fie ACEEAŞI cu cea aplicată
        if os.environ.get("EXPECT_KIND") != kind or os.environ.get("KEYS_SHA", "") != sha:
            fail("refusing: the archive changed since it was checked")
        t.extractall(staging, members=keep, filter="data")   # anti path-traversal/symlink (Py 3.12)
        db = os.path.join(staging, "webterm.db")
integ = sqlite3.connect(db).execute("PRAGMA integrity_check").fetchone()[0]
if integ != "ok":
    fail("integrity FAILED: " + integ[:120])
if mode == "scan":
    print("kind: %s" % kind)
    print("keys-sha256: %s" % (sha or "-"))
    sys.exit(0)
keep_vkey = kind == "protected" and os.environ.get("KEEP_VOLUME_KEY") == "1"
if keep_vkey:
    try:
        ok_vkey = stat.S_ISREG(os.lstat(os.path.join(D, "master.key")).st_mode)
    except FileNotFoundError:
        ok_vkey = False
    if not ok_vkey:
        fail("refusing: /data/master.key (WEBTERM_KEY_IN_VOLUME=1) disappeared since it was checked")
# valid → mută datele curente în plasa de siguranță, apoi noul conținut în loc
shutil.rmtree(prev, ignore_errors=True)
os.makedirs(prev)
for name in os.listdir(D):
    # `.lock` rămâne pe loc: e lock-ul de proces al volumului (INV-14), nu face parte din date
    if name in (".restore-staging", ".restore-prev", LOCK):
        continue
    shutil.move(os.path.join(D, name), os.path.join(prev, name))
for name in os.listdir(staging):
    shutil.move(os.path.join(staging, name), os.path.join(D, name))
shutil.rmtree(staging, ignore_errors=True)
if keep_vkey:
    # volum „reduced": cheia master stă în volum şi NU e în arhivă; cea a acestui volum a deschis
    # keys.wtk-ul arhivei (verificat înainte de oprire), deci rămâne cu datele restaurate
    shutil.copy2(os.path.join(prev, "master.key"), os.path.join(D, "master.key"))
uid, gid = (int(x) for x in os.environ["OWNER"].split(":"))
os.chown(D, uid, gid)
for root, dirs, files in os.walk(D):
    for n in dirs + files:
        try:
            os.chown(os.path.join(root, n), uid, gid)
        except OSError:
            pass
print("restore OK (integrity ok); previous state kept in /data/.restore-prev")
PY
)

# ── verificarea cheii master pentru o arhivă PROTEJATĂ, cu imaginea app-ului ──────────────────
# Imaginea-unealtă nu are codul de chei; imaginea app-ului îl are, iar `--volumes-from` îi dă exact
# montările app-ului (volumul de date şi secrets/master-key), read-only, şi variabilele lui de cheie.
# Rulează ca userul serviciului (fişierul-cheie e 0400 al lui) şi fără reţea. Decizia vine dintr-o
# deschidere AUTENTIFICATĂ a keys.wtk-ului din arhivă cu cheia configurată (nu doar compararea
# id-urilor, care e informativă): cheia greşită → refuz înainte ca app-ul să fie oprit.
# Ieşire: 0 deschide, 1 nu deschide / nicio cheie configurată, 2 nu se poate verifica aici.
KC_OUT="" VOLUME_KEY=0
key_check() {
  local cid="${WEBTERM_APP_CONTAINER:-}" img rc
  if [ -z "$cid" ] && [ -n "$FILE" ]; then
    cid=$($COMPOSE -f "$FILE" ps -a -q app 2>/dev/null | head -n1) || cid=""
  fi
  if [ -z "$cid" ]; then
    KC_OUT="no app container found (run it from the install directory, or set WEBTERM_APP_CONTAINER)"
    return 2
  fi
  img=$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null) || {
    KC_OUT="cannot inspect the app container $cid"; return 2; }
  ENVF=$(mktemp); chmod 600 "$ENVF"
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null \
    | grep -E '^(WEBTERM_MASTER_KEY_FILE|WEBTERM_MASTER_KEY|WEBTERM_KEY_IN_VOLUME)=' >"$ENVF" || true
  rc=0
  KC_OUT=$(docker run --rm -i --network none --user "$OWNER" --entrypoint python3 \
    --volumes-from "$cid:ro" -v "$KOUT":/kin:ro --env-file "$ENVF" "$img" - 2>&1 <<'PY'
import os, sys, types
D = os.environ.get("WT_DATA", "/data")
K = os.environ.get("WT_KIN", "/kin")
try:
    from app import keyring as kr
    from app import keys
except Exception as e:
    print("the app image cannot check master keys (%s): is it 3.8 or newer?" % type(e).__name__)
    raise SystemExit(2)
with open(os.path.join(K, "keys.wtk"), "rb") as f:
    blob = f.read()
try:
    want = kr._parse_manifest_unauthenticated(blob).mk_id.hex()   # informativ, nu decide
except Exception as e:
    sys.exit("the archive's keys.wtk is not a valid key manifest (%s)" % getattr(e, "reason", type(e).__name__))
dfd = os.open(D, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
inv = types.SimpleNamespace(kind="protected", in_volume=os.path.lexists(os.path.join(D, keys.VOLUME_KEY)))
try:
    # aceeaşi rezolvare a sursei ca la boot (fişier fixat, fără symlink, nu în volum, mod 0400)
    res = keys.resolve_master_key(os.environ, types.SimpleNamespace(dir_fd=dfd), inv)
except keys.BootRefused as e:
    sys.exit("no usable master key is configured for this installation (%s: %s); the archive "
             "needs the key with id %s (docs/INSTALL.md, Encryption at rest)" % (e.reason, e.subject, want))
if res is None or res.mk is None:
    sys.exit("no master key is configured for this installation; the archive needs the key with id %s" % want)
have = kr.key_id(res.mk).hex()
try:
    keys._open_blob(blob, res.mk, kr.PROFILE_V1)                   # autentificat: decide
except keys.BootRefused as e:
    sys.exit("the master key configured for this installation does not open the archive's keys.wtk "
             "(%s): the archive needs the key with id %s, the configured key (%s) has id %s"
             % (e.reason, want, res.source, have))
print("the configured master key (%s, id %s) opens the archive's keys.wtk" % (res.source, have))
print("volume-key: %d" % (res.source == "volume"))
PY
  ) || rc=$?
  rm -f "$ENVF"; ENVF=""
  if [ "$rc" = 0 ] && printf '%s\n' "$KC_OUT" | grep -q '^volume-key: 1$'; then VOLUME_KEY=1; fi
  KC_OUT=$(printf '%s\n' "$KC_OUT" | grep -v '^volume-key: ' || true)
  return "$rc"
}

scan_archive() {   # → SCAN_OUT, SCAN_KIND, SCAN_SHA; 1 if the archive is refused
  local rc=0
  KOUT=$(mktemp -d); chmod 755 "$KOUT"
  SCAN_OUT=$(docker run --rm -i --network none --entrypoint python3 \
       -v "$ADIR":/in:ro -v "$KOUT":/kout -e MODE=scan -e ABASE="$ABASE" \
       -e MAXB="$RESTORE_MAX_BYTES" -e MAXM="$RESTORE_MAX_MEMBERS" \
       "$IMAGE" -I - 2>&1 <<<"$PY_RESTORE") || rc=$?
  SCAN_KIND=$(printf '%s\n' "$SCAN_OUT" | sed -n 's/^kind: //p')
  SCAN_SHA=$(printf '%s\n' "$SCAN_OUT" | sed -n 's/^keys-sha256: //p')
  [ "$SCAN_SHA" = - ] && SCAN_SHA=""
  [ "$rc" = 0 ] && [ -n "$SCAN_KIND" ]
}

# ── --verify: a restore test that touches nothing ────────────────────────────
if [ "$VERIFY" = 1 ]; then
  RV_SELF_DIR=$(cd "$(dirname "$0")" && pwd -P)
  RV_NAME=$(basename "$SRC_NAME")
  rv_record() {   # rv_record ok|error MESSAGE
    if [ -x "$RV_SELF_DIR/host-health.sh" ]; then
      "$RV_SELF_DIR/host-health.sh" --record restore-verify "$1" "$2" \
        "$(printf '{"archive":"%s"}' "$(printf '%s' "$RV_NAME" | tr -cd 'A-Za-z0-9._-' | cut -c1-128)")" \
        >/dev/null 2>&1 || true
    fi
  }
  if [ "$TOOL_OK" = 0 ]; then
    echo "REFUSING: cannot get the helper image '$IMAGE' (no registry access?)." >&2
    rv_record error "restore test not run: the helper image is not available"
    exit 1
  fi
  if ! scan_archive; then
    echo "$SCAN_OUT" >&2
    rv_record error "restore test FAILED for $RV_NAME: $(printf '%s' "$SCAN_OUT" | tail -n1 | cut -c1-120)"
    exit 1
  fi
  if [ "$SCAN_KIND" = legacy ]; then
    echo "restore test OK: the archive unpacks, has the vault key, and its database passes integrity_check"
    rv_record ok "restore test passed for $RV_NAME"
    exit 0
  fi
  rc=0; key_check || rc=$?
  if [ "$rc" = 0 ]; then
    echo "restore test OK: the archive unpacks, its database passes integrity_check, and $KC_OUT"
    rv_record ok "restore test passed for $RV_NAME"
    exit 0
  elif [ "$rc" = 2 ]; then
    echo "restore test OK: the archive unpacks and its database passes integrity_check;" \
         "the master key was NOT checked ($KC_OUT)"
    rv_record ok "restore test passed for $RV_NAME (master key not checked)"
    exit 0
  fi
  echo "restore test FAILED: $KC_OUT" >&2
  rv_record error "restore test FAILED for $RV_NAME: $(printf '%s' "$KC_OUT" | tail -n1 | cut -c1-120)"
  exit 1
fi

[ -n "$FILE" ] || { echo "no compose file found (set COMPOSE_FILE)"; exit 1; }

# Numele pe care îl confirmi trebuie să fie cel pe care l-ai TASTAT. După decriptare
# `$ARCHIVE` e un mktemp aleatoriu, deci promptul cerea confirmarea pentru
# „/tmp/tmp.iSVaLjc0Dn.tar.gz" — un nume care nu-i spune omului nimic.
# Volumul TREBUIE să existe. `backup.sh` are garda asta de mult (refuză să scrie o arhivă
# goală); restaurarea n-o avea, deşi acolo costul e mai mare: Docker creează tăcut volumul
# lipsă, restaurarea reuşeşte în el, iese cu 0 şi tipăreşte „restore OK" — în timp ce aplicaţia
# vie rămâne pe volumul ei, cu datele ei. Omul citeşte „restore OK" după un dezastru şi crede
# că a recuperat. Un nume greşit e cazul obişnuit, nu exotic: numele vine din directorul de
# instalare, iar procedura din RUNBOOK e copiată literal de pe o maşină pe alta.
if [ "$TOOL_OK" = 0 ]; then
  echo "REFUSING: cannot get the helper image '$IMAGE' (no registry access?)." >&2
  echo "         It is only used to run python3 against the data volume. Either pre-pull it" >&2
  echo "         once while you have network:   docker pull $IMAGE" >&2
  echo "         or point WEBTERM_TOOL_IMAGE at an image you already have that has python3." >&2
  exit 1
fi

docker volume inspect "$VOLUME" >/dev/null 2>&1 || {
  echo "REFUSING: volume '$VOLUME' does not exist — restoring into it would create an empty" >&2
  echo "          volume that nothing uses, while your app keeps running on another one." >&2
  echo "          The name comes from the install directory: for /opt/webterm2 it is" >&2
  echo "          webterm2_webterm-data. List them with 'docker volume ls', then:" >&2
  echo "            WEBTERM_VOLUME=<name> $0 $SRC_NAME" >&2
  exit 1
}

# Totul se verifică ÎNAINTE de oprirea app-ului: o arhivă refuzată nu costă niciun minut de
# serviciu căzut. Pentru o arhivă protejată, cheia master configurată trebuie s-o deschidă.
if ! scan_archive; then
  echo "$SCAN_OUT" >&2
  echo "REFUSING: '$SRC_NAME' is not a restorable WebTerm backup — nothing was changed." >&2
  exit 1
fi
if [ "$SCAN_KIND" = protected ]; then
  rc=0; key_check || rc=$?
  if [ "$rc" != 0 ]; then
    echo "$KC_OUT" >&2
    echo "REFUSING: this archive comes from a protected volume (keys.wtk) and the master key of" >&2
    echo "          this installation was not confirmed to open it — nothing was changed. Put the" >&2
    echo "          matching key file in secrets/master-key/ (WEBTERM_MASTER_KEY_FILE in .env)" >&2
    echo "          and run it again (docs/INSTALL.md, Encryption at rest)." >&2
    exit 1
  fi
  echo "$KC_OUT"
else
  echo "note: a pre-3.8 archive (with data/secret). With a master key configured, the next start"
  echo "      migrates it again (docs/INSTALL.md, Encryption at rest)."
fi

echo "!! This OVERWRITES all data in volume '$VOLUME' with '$SRC_NAME'."
read -r -p "Continue? [y/N] " ok; [ "$ok" = y ] || { echo "aborted"; exit 1; }

# Din clipa asta aplicaţia e oprită. Orice ieşire — reuşită, eşec de validare, Ctrl-C —
# trebuie să o repornească: un restore care eşuează nu are voie să lase serviciul jos.
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
# mută în /data/.restore-prev ca plasă de siguranță (în afară de `.lock`). Tot în Python.
docker run --rm -i --entrypoint python3 \
  -v "$VOLUME":/data -v "$ADIR":/in:ro -e MODE=apply -e ABASE="$ABASE" -e OWNER="$OWNER" \
  -e MAXB="$RESTORE_MAX_BYTES" -e MAXM="$RESTORE_MAX_MEMBERS" \
  -e EXPECT_KIND="$SCAN_KIND" -e KEYS_SHA="$SCAN_SHA" -e KEEP_VOLUME_KEY="$VOLUME_KEY" \
  "$IMAGE" -I - <<<"$PY_RESTORE"

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
