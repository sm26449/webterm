#!/usr/bin/env bash
# Crash-consistent backup of WebTerm data (SQLite + transcripts + key files).
# The SQLite copy is taken with the online backup API (checkpoints the WAL into
# a single self-contained file) so it is restorable even while the app is live —
# tarring the raw webterm.db + -wal + -shm at different instants was torn.
#
# Key files (3.8, encryption at rest): a pre-3.8 ("legacy") volume is archived with its vault key
# `data/secret`, as before. A PROTECTED volume (`data/keys.wtk`) is archived with keys.wtk, which
# is useless without the master key, and NEVER with the master key itself: the key file
# (secrets/master-key/master.key in the install directory, or /data/master.key with
# WEBTERM_KEY_IN_VOLUME=1) is not in the archive. Keep a copy of it apart (recovery kit,
# docs/INSTALL.md): restore.sh refuses a protected archive unless the configured key opens it.
#
#   WEBTERM_VOLUME              Docker volume name  (default webterm_webterm-data)
#   WEBTERM_BACKUP_DIR          where archives go   (default /var/backups/webterm)
#   WEBTERM_BACKUP_KEEP         how many to keep    (default 14)
#   WEBTERM_TOOL_IMAGE          image with python3  (default python:3.12-alpine)
#   WEBTERM_BACKUP_PASSPHRASE   if set, encrypt the archive (openssl AES-256) — RECOMMENDED:
#                               a legacy archive contains the vault key (data/secret), which
#                               decrypts every stored SSH credential; a protected one still
#                               holds the database (metadata) and the fleet signing key. An
#                               unencrypted copy that leaves the host (rsync/cloud) exposes them.
#   Off-host copy (encrypted archive only; each destination is independent, use any/all):
#     WEBTERM_BACKUP_RSYNC=user@host:/path/   rsync-over-SSH (key auth); + _RSYNC_KEEP_DAYS=N
#     WEBTERM_BACKUP_FTPS=ftp://host/path/    FTP over TLS (curl --ssl-reqd); + _FTPS_USER/_FTPS_PASSWORD
#     WEBTERM_BACKUP_REMOTE=remote:path       any rclone backend (S3, B2, GDrive…); + _REMOTE_KEEP_DAYS=N
set -euo pipefail

# 3.6.8: the outcome also lands in Settings → System health (a status file in the data volume,
# written by host-health.sh --record). A nightly backup that failed only in journald was invisible
# until the day it was needed. Best effort: never changes this script's exit code; no secrets in it.
BK_SELF_DIR=$(cd "$(dirname "$0")" && pwd -P)
BK_REASON="" BK_ARCHIVE="" BK_ENCRYPTED=false BK_OFFHOST=none BK_TMP=""
# shellcheck disable=SC2329  # invoked through the EXIT trap
_bk_status() {
  local rc=$? st=ok msg
  [ -z "${BK_TMP:-}" ] || rm -f "$BK_TMP"      # o arhivă neverificată nu rămâne niciodată
  [ -x "$BK_SELF_DIR/host-health.sh" ] || return 0
  if [ "$rc" != 0 ]; then
    st=error; msg="${BK_REASON:-the backup failed (exit code $rc)}"
  else
    msg="archive ${BK_ARCHIVE:-?}"
    [ "$BK_ENCRYPTED" = true ] || msg="$msg (NOT encrypted)"
    msg="$msg, off-host $BK_OFFHOST"
    [ "$BK_OFFHOST" = failed ] && st=warn
  fi
  "$BK_SELF_DIR/host-health.sh" --record backup "$st" "$msg" \
    "{\"archive\":\"${BK_ARCHIVE}\",\"encrypted\":$BK_ENCRYPTED,\"offhost\":\"$BK_OFFHOST\"}" \
    >/dev/null 2>&1 || true
}
trap _bk_status EXIT

VOLUME="${WEBTERM_VOLUME:-webterm_webterm-data}"
OUT="${WEBTERM_BACKUP_DIR:-/var/backups/webterm}"
KEEP="${WEBTERM_BACKUP_KEEP:-14}"
# `WEBTERM_IMAGE` numea şi imaginea asta, dar în restul proiectului (.env, compose,
# deploy.sh, upgrade.sh) el înseamnă IMAGINEA GATEWAY-ULUI. Iar `upgrade.sh` sursează
# `.env` înainte să cheme backupul — deci containerul de backup primea imaginea aplicaţiei
# în loc de `python:3.12-alpine`, fără ca nimeni s-o fi cerut. Un nume de variabilă cu două
# înţelesuri în acelaşi proiect e un bug care aşteaptă contextul potrivit; îi dăm un nume
# propriu. Vezi acelaşi tipar în `restore.sh`, unde greşeala costa mai scump.
# Pinuit pe digest: imaginea asta rulează ca root peste volumul de date, cu cheia seifului
# montată — adică e cel mai puternic container din tot sistemul, şi era singurul care
# accepta orice împingea cineva pe tag-ul `python:3.12-alpine`.
IMAGE="${WEBTERM_TOOL_IMAGE:-python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df}"
if [ -z "${WEBTERM_TOOL_IMAGE:-}" ] && [ -n "${WEBTERM_IMAGE:-}" ]; then
  echo "note: WEBTERM_IMAGE is the gateway image and is IGNORED here;" \
       "use WEBTERM_TOOL_IMAGE to change the python image ($IMAGE)." >&2
fi
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUT"
chmod 700 "$OUT" 2>/dev/null || true      # arhivele conțin cheia seifului: dir privat

# One container: online-consistent DB copy + selective tar. /data is rw because
# SQLite may touch -shm to coordinate the WAL read; webterm.db itself is only read.
# `--entrypoint python3`: imaginea aplicaţiei are un entrypoint care face `exec gosu webterm`,
# adică COBOARĂ privilegiile. Rulat aşa, containerul de backup nu poate scrie în $OUT (root, 700)
# şi backupul cade cu PermissionError. Rămâne aici şi după redenumirea variabilei de mai sus:
# cine chiar vrea să folosească imaginea aplicaţiei ca unealtă trebuie să obţină acelaşi
# rezultat, nu o eroare de permisiuni la 03:30 dimineaţa.
# Volumul TREBUIE să existe deja. Docker creează tăcut un volum inexistent, iar de acolo
# totul „reuşeşte": `sqlite3.connect` face un webterm.db gol, `integrity_check` pe el
# întoarce `ok`, arhiva iese cu exit 0 — şi restaurarea ei raportează succes în timp ce
# şterge tot, inclusiv cheia care decriptează credenţialele. Un nume greşit de volum (typo,
# sau o instalare făcută cu `--dir`) e de ajuns. Procedura de verificare din RUNBOOK (timer
# activ, exit 0, arhive care cresc) nu poate distinge cazul ăsta.
# Imaginea-unealtă trebuie să fie DISPONIBILĂ. `docker run` o trage la fiecare rulare, iar dacă
# registry-ul e inaccesibil (host air-gapped, DNS căzut, Docker Hub jos, rate-limit) ieşea
# eroarea crudă a Docker-ului şi exit 125 — fără nicio menţiune a produsului, fără sugestie, şi
# în cazul timer-ului nocturn fără ca cineva să afle. Un backup care nu se face tăcut e mai rău
# decât unul care nu există: crezi că-l ai.
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null 2>&1 || {
  BK_REASON="the helper image is not available (no registry access?)"
  echo "REFUSING: cannot get the helper image '$IMAGE' (no registry access?)." >&2
  echo "         It is only used to run python3 against the data volume. Either pre-pull it" >&2
  echo "         once while you have network:   docker pull $IMAGE" >&2
  echo "         or point WEBTERM_TOOL_IMAGE at an image you already have that has python3." >&2
  exit 1
}

docker volume inspect "$VOLUME" >/dev/null 2>&1 || {
  BK_REASON="the data volume $VOLUME does not exist"
  echo "REFUSING: volume '$VOLUME' does not exist — refusing to write an empty backup." >&2
  echo "         Check WEBTERM_VOLUME (see /etc/default/webterm-backup); 'docker volume ls' lists them." >&2
  exit 1
}

BK_REASON="the snapshot of the data volume failed"
BK_RUN=$(docker run --rm -i --entrypoint python3 \
  -v "$VOLUME":/data -v "$OUT":/out -e STAMP="$STAMP" "$IMAGE" - <<'PY'
import sqlite3, stat, sys, tarfile, os
stamp = os.environ["STAMP"]
# WT_DATA/WT_OUT: doar pentru testul hermetic (tests/host_backup_script_test.py); în container
# rămân /data şi /out — nimeni altcineva nu dă -e aici
D, O = os.environ.get("WT_DATA", "/data"), os.environ.get("WT_OUT", "/out")


def regular(name):
    try:
        st = os.lstat(os.path.join(D, name))
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(st.st_mode):
        sys.exit("REFUSING: /data/%s is not a regular file" % name)
    return True


def present(name):
    return os.path.lexists(os.path.join(D, name))


# ...şi conţinutul trebuie să fie al unei instalări reale: fără DB nu există nimic de salvat.
if not regular("webterm.db"):
    sys.exit("REFUSING: /data/webterm.db missing — this volume is not a WebTerm data volume")
# 3.8 (INV-14, docs/design/INVARIANTS.md): un volum PROTEJAT are keys.wtk (cheile învelite sub
# cheia master, inutil fără ea) şi NU mai are `secret`. Arhiva lui ia keys.wtk şi niciodată
# cheia master (master.key, în volum doar la WEBTERM_KEY_IN_VOLUME=1) — cheia stă separat de date,
# altfel protecţia n-ar exista pentru cine are arhiva. Stările intermediare ale protocolului de chei
# (migrare în curs, temporare) nu se arhivează: gateway-ul le termină la pornire.
if regular("keys.wtk"):
    for n in ("migrating.wtm", "migrating.wtm.tmp", "keys.wtk.tmp", "master.key.tmp"):
        if present(n):
            sys.exit("REFUSING: /data/%s — a key operation is unfinished; start the gateway once "
                     "(it completes it), then back up again" % n)
    if present("secret"):
        sys.exit("REFUSING: /data/secret next to keys.wtk — the volume mixes old and new key files "
                 "(docs/INSTALL.md, Encryption at rest: `ambiguous`)")
    # H3 (recenzia PR4): arhiva unui volum protejat NU se face aici cu tar. O scrie gateway-ul
    # (python3 -m app.hostops backup, în imaginea app-ului): inventar prin fd-uri, filtre
    # inode/nlink, perechea de semnare verificată, WTS1 portabil sub WTBK1. Aici doar clasificăm.
    print("kind: %s" % ("reduced" if present("master.key") else "protected"))
    sys.exit(0)
else:
    # fără keys.wtk: 3.7, exact ca înainte. Dar urme ale formatului nou fără manifest = volum
    # inconsistent (acelaşi refuz ca backup.volume_kind în gateway), nu „legacy".
    for n in ("migrating.wtm", "migrating.wtm.tmp", "keys.wtk.tmp", "master.key", "master.key.tmp",
              "erasures.wtj"):
        if present(n):
            sys.exit("REFUSING: /data/%s without keys.wtk — an inconsistent volume; start the "
                     "gateway once and read its log" % n)
    # Fără `secret`, arhiva nu poate decripta nimic la restaurare — e o pierdere totală care
    # arată ca un backup.
    if not regular("secret"):
        sys.exit("REFUSING: /data/secret missing — this volume is not a WebTerm data volume")
    kind = "legacy"
    names = ("secret", "agent-signing.key", "agent-signing.pub", "transcripts")
tmp = "/tmp/webterm-%s.db" % stamp
src = sqlite3.connect(os.path.join(D, "webterm.db"))
dst = sqlite3.connect(tmp)
with dst:
    src.backup(dst)                 # online backup API — consistent snapshot
dst.close(); src.close()
out = os.path.join(O, "webterm-%s.tar.gz" % stamp)
with tarfile.open(out, "w:gz") as t:
    t.add(tmp, arcname="webterm.db")            # the consistent copy
    # `agent-signing.key/.pub`: fără ele, un restore reface datele dar flota devine
    # NE-actualizabilă — agenţii au pubkey-ul vechi încorporat şi refuză (corect) update-uri
    # semnate cu o cheie nouă. Backupul din UI le includea deja (backup.py); timer-ul systemd,
    # nu. Adică exact copia pe care te bazezi la dezastru era cea incompletă.
    for name in names:
        p = os.path.join(D, name)
        if os.path.exists(p):
            t.add(p, arcname=name)
os.unlink(tmp)
print("backup:", out)
print("kind:", kind)
PY
)
printf '%s\n' "$BK_RUN" | grep -v '^kind: ' || true
VOLKIND=$(printf '%s\n' "$BK_RUN" | sed -n 's/^kind: //p')

# ── volum protejat (3.8): arhiva o scrie gateway-ul, nu tar-ul din shell (H3) ─────────────────
# `python3 -m app.hostops backup` în imaginea app-ului: inventarul prin fd-uri şi filtrele
# inode/nlink ale backup.py (un hardlink spre cheie nu intră), perechea de semnare verificată,
# WTS1 portabil sub WTBK1 cu parola de mai jos. Cu app-ul pornit rulează ÎN el (`docker exec`,
# sub `.maint.lock` partajat); oprit, într-un container nou care ia `.lock`. Arhiva se scrie într-un
# temporar, se verifică cu codul restore-ului şi abia apoi se publică (rename atomic).
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
# Aceeaşi construcţie ca în restore.sh: imaginea exactă a app-ului, ca userul serviciului, fără
# reţea; din cheie doar CĂILE (WEBTERM_MASTER_KEY_FILE / WEBTERM_KEY_IN_VOLUME) şi montarea
# read-only a directorului ei. O cheie dată ca valoare (WEBTERM_MASTER_KEY) nu se copiază.
APP_IMG="" KEY_ARGS=()
app_run_args() {
  local envs kf kv want mounts typ name src dst found=""
  APP_IMG=$(docker inspect --format '{{.Image}}' "$APP_CID") || { APP_ERR="cannot inspect $APP_CID"; return 1; }
  envs=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$APP_CID") \
    || { APP_ERR="cannot inspect $APP_CID"; return 1; }
  if printf '%s\n' "$envs" | grep -q '^WEBTERM_MASTER_KEY=.'; then
    APP_ERR="the master key is given as a value (WEBTERM_MASTER_KEY) and the app is stopped: start the app (the backup then runs inside it), or use a key file"
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
hostops() {   # hostops live|ro|rw ARGS…
  local mode="$1"; shift
  if [ "$mode" = live ]; then
    docker exec -i -u "$OWNER" -e WEBTERM_BACKUP_PASSPHRASE "$APP_CID" python3 -m app.hostops "$@"
    return
  fi
  local ro=""; [ "$mode" = ro ] && ro=":ro"
  docker run --rm -i --network none --user "$OWNER" --entrypoint python3 \
    -v "$VOLUME:/data$ro" "${KEY_ARGS[@]}" -e WEBTERM_BACKUP_PASSPHRASE "$APP_IMG" -m app.hostops "$@"
}
bk_refuse() {   # bk_refuse REASON MESSAGE…
  BK_REASON="$1"; shift
  printf '%s\n' "$@" >&2
  exit 1
}

case "$VOLKIND" in
  legacy)
    HOLDS="the vault key (data/secret)"
    ARCHIVE="$OUT/webterm-$STAMP.tar.gz"
    ;;
  protected|reduced)
    HOLDS="the database and the fleet signing key"
    OWNER="${WEBTERM_UID:-10001:10001}"
    # §12.10: o arhivă care pleacă de pe maşină cere DOUĂ secrete (parola + cheia master)
    [ -n "${WEBTERM_BACKUP_PASSPHRASE:-}" ] || bk_refuse "refused: no WEBTERM_BACKUP_PASSPHRASE for a protected volume" \
      "REFUSING: the data volume is protected (keys.wtk): its backup is always encrypted with" \
      "          WEBTERM_BACKUP_PASSPHRASE (and needs the master key to restore). Set it in" \
      "          /etc/default/webterm-backup and run this again."
    APP_ERR=""
    find_app || bk_refuse "cannot identify the app container" "REFUSING: cannot identify the app container of '$VOLUME' ($APP_ERR)."
    [ -n "$APP_CID" ] || bk_refuse "no app container uses the data volume" \
      "REFUSING: no app container uses volume '$VOLUME': a protected volume is archived by the app's own code."
    STATE=$(docker inspect --format '{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$APP_CID") \
      || bk_refuse "cannot inspect the app container" "REFUSING: cannot inspect the app container $APP_CID."
    case "$STATE" in
      "true|healthy"|"true|") MODE=live; VMODE=live; LIVE=(--live) ;;
      true*) bk_refuse "the app is not healthy" \
               "REFUSING: the app is running but not healthy (${STATE#*|}): back up once it is healthy." ;;
      *) app_run_args || bk_refuse "the key setup cannot be reproduced" "REFUSING: $APP_ERR."
         MODE=rw; VMODE=ro; LIVE=() ;;
    esac
    ARCHIVE="$OUT/webterm-$STAMP.wtbk"
    BK_TMP="$OUT/.webterm-$STAMP.wtbk.tmp"
    rm -f "$BK_TMP"
    rc=0
    HO_OUT=$( { (umask 077; hostops "$MODE" backup "${LIVE[@]}" >"$BK_TMP"); } 2>&1 ) || rc=$?
    if [ "$rc" != 0 ]; then
      bk_refuse "the protected backup was refused" "$(printf '%s' "$HO_OUT" | tail -n3)" \
        "REFUSING: the gateway did not write the archive (exit $rc) — nothing was published."
    fi
    SHA_REP=$(printf '%s\n' "$HO_OUT" | sed -n 's/^sha256: //p')
    SHA_GOT=$(sha256sum "$BK_TMP" | cut -d' ' -f1)
    if [ -z "$SHA_REP" ] || [ "$SHA_REP" != "$SHA_GOT" ]; then
      bk_refuse "the archive was truncated in transit" \
        "REFUSING: the archive on disk is not the one the gateway wrote (truncated?) — nothing was published."
    fi
    VOLKIND=$(printf '%s\n' "$HO_OUT" | sed -n 's/^kind: //p')
    rc=0
    V_OUT=$(hostops "$VMODE" verify --sha256 "$SHA_GOT" <"$BK_TMP" 2>&1) || rc=$?
    [ "$rc" = 0 ] || bk_refuse "the new archive failed its restore check" "$(printf '%s' "$V_OUT" | tail -n3)" \
      "REFUSING: the new archive did not pass the restore check — nothing was published."
    chmod 600 "$BK_TMP"
    mv -f "$BK_TMP" "$ARCHIVE"
    BK_TMP=""
    BK_ENCRYPTED=true
    # Cheia master NU e în arhivă, cu bună ştiinţă: fără ea arhiva nu se poate restaura.
    echo "ENCRYPTED backup: $ARCHIVE (verified)"
    echo "note: the data volume is protected (keys.wtk): the master key is NOT in this archive."
    if [ "$VOLKIND" = reduced ]; then
      echo "      The key is inside the volume (WEBTERM_KEY_IN_VOLUME=1, /data/master.key): keep a copy"
      echo "      of it apart — the archive cannot be restored anywhere without it."
    else
      echo "      Restoring it needs the same key file (secrets/master-key/master.key in the install"
      echo "      directory): keep a copy off this machine (recovery kit, docs/INSTALL.md)."
    fi
    ;;
  *) BK_REASON="the snapshot did not report the volume kind"; echo "REFUSING: unknown volume kind" >&2; exit 1 ;;
esac

BK_REASON=""
BK_ARCHIVE=$(basename "$ARCHIVE")
chmod 600 "$ARCHIVE" 2>/dev/null || true

# Criptare (recomandat): arhiva conține cheia seifului. Cu o parolă → openssl AES-256;
# fără openssl sau fără parolă → avertizăm zgomotos (arhiva rămâne în clar, doar 0600).
if [ "$VOLKIND" != legacy ]; then
  :   # deja criptată (WTBK1, scrisă de gateway)
elif [ -n "${WEBTERM_BACKUP_PASSPHRASE:-}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    # AES-256-CBC + PBKDF2 (200k). NU e AEAD, şi asta e o limitare a uneltei, nu o scăpare:
    # `openssl enc` refuză din construcţie cifrurile autentificate („AEAD ciphers not
    # supported by the enc utility" — verificat pe OpenSSL 3.0.13). Un audit extern a propus
    # `-aes-256-gcm`; comanda aia eşuează pur şi simplu. Consecinţa reală: o arhivă alterată
    # pe disc se decriptează în gunoi, iar eşecul apare la `integrity_check`-ul SQLite din
    # restore.sh (înainte de a atinge datele vii), nu la graniţa criptografică. Backup-ul din
    # UI/cloud foloseşte formatul WTBK1 (scrypt → AES-GCM), acolo unde avem Python.
    openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
      -in "$ARCHIVE" -out "$ARCHIVE.enc" -pass env:WEBTERM_BACKUP_PASSPHRASE
    rm -f "$ARCHIVE"
    chmod 600 "$ARCHIVE.enc" 2>/dev/null || true
    ARCHIVE="$ARCHIVE.enc"
    BK_ARCHIVE=$(basename "$ARCHIVE") BK_ENCRYPTED=true
    echo "ENCRYPTED backup: $ARCHIVE"
  else
    echo "WARNING: openssl is missing — the archive stays UNENCRYPTED (it holds $HOLDS)."
  fi
elif [ -t 1 ] || [ "${WEBTERM_BACKUP_ALLOW_PLAINTEXT:-0}" = "1" ]; then
  # rulare INTERACTIVĂ (sau refuz explicit): avertizăm zgomotos şi mergem mai departe
  echo "WARNING: WEBTERM_BACKUP_PASSPHRASE is not set — the archive holds $HOLDS in CLEARTEXT."
  echo "         Set a passphrase (AES encryption), or keep $OUT strictly private and encrypted off-host."
else
  # rulare NEINTERACTIVĂ (timer systemd, cron): un avertisment pe care nu-l citeşte nimeni
  # nu e o măsură. Arhiva conţine `data/secret` — cheia care decriptează TOATE credenţialele
  # SSH — iar /var/backups ajunge des în rsync-uri şi în snapshot-uri. Refuzăm.
  # Semnalat de auditul extern, 2026-08-06.
  rm -f "$ARCHIVE"
  BK_REASON="refused: no WEBTERM_BACKUP_PASSPHRASE for an automated backup"
  echo "REFUSING: an automated backup without WEBTERM_BACKUP_PASSPHRASE." >&2
  echo "       The archive would hold $HOLDS in cleartext; it has been deleted." >&2
  echo "       Put the passphrase in /etc/default/webterm-backup, or, if you really want cleartext," >&2
  echo "       set WEBTERM_BACKUP_ALLOW_PLAINTEXT=1 (not recommended)." >&2
  exit 1
fi

# Copie off-host (Google Drive, Dropbox, S3, B2, OneDrive... — orice remote rclone).
# Un backup care stă doar pe mașina pe care o salvezi nu te apără de pierderea mașinii.
# NU urcăm niciodată o arhivă necriptată: ar însemna să dai cheia seifului (deci toate
# credențialele SSH) unui terț. Configurare: `rclone config` → un remote, apoi
#   WEBTERM_BACKUP_REMOTE=gdrive:webterm-backups
#   WEBTERM_BACKUP_REMOTE_KEEP_DAYS=30   (opțional: șterge copiile mai vechi de-atât)
if [ -n "${WEBTERM_BACKUP_REMOTE:-}" ]; then
  if [ "$BK_ENCRYPTED" != true ]; then
    BK_REASON="refused the off-host copy of an UNENCRYPTED archive"
    echo "REFUSING the off-host upload: the archive is UNENCRYPTED (it holds $HOLDS)." >&2
    echo "                  Set WEBTERM_BACKUP_PASSPHRASE and run it again." >&2
    exit 1
  elif ! command -v rclone >/dev/null 2>&1; then
    echo "WARNING: WEBTERM_BACKUP_REMOTE is set but rclone is missing — the archive stays local only."
    BK_OFFHOST=failed
  else
    BK_REASON="the off-host upload (rclone) failed"
    rclone copy "$ARCHIVE" "$WEBTERM_BACKUP_REMOTE" --no-traverse
    BK_REASON=""
    [ "$BK_OFFHOST" = failed ] || BK_OFFHOST=ok
    echo "backup uploaded: $WEBTERM_BACKUP_REMOTE/$(basename "$ARCHIVE")"
    if [ -n "${WEBTERM_BACKUP_REMOTE_KEEP_DAYS:-}" ]; then
      rclone delete "$WEBTERM_BACKUP_REMOTE" --min-age "${WEBTERM_BACKUP_REMOTE_KEEP_DAYS}d" \
        --include "webterm-*.tar.gz.enc" --include "webterm-*.wtbk"
    fi
  fi
fi

# Copie off-host prin rsync-over-SSH — universală, criptată în tranzit, auth pe cheie, fără rclone
# şi fără `rclone config`. „Toată lumea are rsync + ssh." NU urcăm niciodată necriptat.
#   WEBTERM_BACKUP_RSYNC=user@host:/cale/backups/   (pune-ţi cheia SSH în ~/.ssh; auth pe cheie)
#   WEBTERM_BACKUP_RSYNC_KEEP_DAYS=30               (opţional: şterge pe remote mai vechi de-atât)
if [ -n "${WEBTERM_BACKUP_RSYNC:-}" ]; then
  if [ "$BK_ENCRYPTED" != true ]; then
    BK_REASON="refused the off-host copy of an UNENCRYPTED archive"
    echo "REFUSING the rsync off-host copy: the archive is UNENCRYPTED (it holds $HOLDS)." >&2
    echo "                  Set WEBTERM_BACKUP_PASSPHRASE and run it again." >&2
    exit 1
  elif ! command -v rsync >/dev/null 2>&1; then
    echo "WARNING: WEBTERM_BACKUP_RSYNC is set but rsync is missing — the archive stays local only."
    BK_OFFHOST=failed
  else
    # BatchMode: fără prompt de parolă (doar cheie); accept-new: TOFU, dar respinge o cheie SCHIMBATĂ.
    BK_REASON="the off-host copy (rsync) failed"
    rsync -a -e "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new" "$ARCHIVE" "$WEBTERM_BACKUP_RSYNC"
    BK_REASON=""
    [ "$BK_OFFHOST" = failed ] || BK_OFFHOST=ok
    echo "backup rsync'd: ${WEBTERM_BACKUP_RSYNC%/}/$(basename "$ARCHIVE")"
    if [ -n "${WEBTERM_BACKUP_RSYNC_KEEP_DAYS:-}" ]; then
      _rh=${WEBTERM_BACKUP_RSYNC%%:*}; _rp=${WEBTERM_BACKUP_RSYNC#*:}
      ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$_rh" \
        "find '$_rp' \\( -name 'webterm-*.tar.gz.enc' -o -name 'webterm-*.wtbk' \\) -mtime +${WEBTERM_BACKUP_RSYNC_KEEP_DAYS} -delete" 2>/dev/null || true
    fi
  fi
fi

# Copie off-host prin FTPS (FTP peste TLS) — pentru NAS/hosting fără SSH. `--ssl-reqd` IMPUNE TLS:
# refuză conexiunea dacă serverul nu oferă TLS, ca parola FTP să nu plece niciodată în clar (FTP
# simplu ar scurge-o, iar cine o are îţi poate şterge/înlocui depozitul de backup).
#   WEBTERM_BACKUP_FTPS=ftp://nas.local/backups/    WEBTERM_BACKUP_FTPS_USER=u  WEBTERM_BACKUP_FTPS_PASSWORD=p
if [ -n "${WEBTERM_BACKUP_FTPS:-}" ]; then
  if [ "$BK_ENCRYPTED" != true ]; then
    BK_REASON="refused the off-host copy of an UNENCRYPTED archive"
    echo "REFUSING the FTPS off-host copy: the archive is UNENCRYPTED (it holds $HOLDS)." >&2
    exit 1
  elif ! command -v curl >/dev/null 2>&1; then
    echo "WARNING: WEBTERM_BACKUP_FTPS is set but curl is missing — the archive stays local only."
    BK_OFFHOST=failed
  else
    _furl="${WEBTERM_BACKUP_FTPS%/}/$(basename "$ARCHIVE")"
    if curl -fsS --ssl-reqd --ftp-create-dirs -T "$ARCHIVE" "$_furl" \
         ${WEBTERM_BACKUP_FTPS_USER:+--user "$WEBTERM_BACKUP_FTPS_USER:${WEBTERM_BACKUP_FTPS_PASSWORD:-}"}; then
      echo "backup uploaded (FTPS): $_furl"
      [ "$BK_OFFHOST" = failed ] || BK_OFFHOST=ok
    else
      echo "WARNING: FTPS upload failed (server without TLS, or wrong credentials/path)." >&2
      BK_OFFHOST=failed
    fi
  fi
fi

# Rotaţie: şterge tot ce trece de cele mai noi $KEEP arhive (.tar.gz şi .tar.gz.enc).
# `|| true` NU e cosmetic: cu `set -o pipefail`, dacă unul dintre globuri nu se potriveşte
# cu nimic (tipic: toate arhivele sunt deja criptate, deci `webterm-*.tar.gz` rămâne
# neexpandat), `ls` iese cu 2 şi ar rupe scriptul DUPĂ ce arhiva a fost deja făcută —
# backup raportat ca eşuat şi, mai rău, rotaţia nu s-ar mai executa niciodată.
{ ls -1t "$OUT"/webterm-*.wtbk "$OUT"/webterm-*.tar.gz.enc "$OUT"/webterm-*.tar.gz 2>/dev/null || true; } \
  | tail -n +"$((KEEP + 1))" | xargs -r rm -f

echo "backup: $ARCHIVE (keeping newest $KEEP)"
