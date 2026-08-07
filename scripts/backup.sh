#!/usr/bin/env bash
# Crash-consistent backup of WebTerm data (SQLite + transcripts + vault key).
# The SQLite copy is taken with the online backup API (checkpoints the WAL into
# a single self-contained file) so it is restorable even while the app is live —
# tarring the raw webterm.db + -wal + -shm at different instants was torn.
#
#   WEBTERM_VOLUME              Docker volume name  (default webterm_webterm-data)
#   WEBTERM_BACKUP_DIR          where archives go   (default /var/backups/webterm)
#   WEBTERM_BACKUP_KEEP         how many to keep    (default 14)
#   WEBTERM_IMAGE               image with python3  (default python:3.12-alpine)
#   WEBTERM_BACKUP_PASSPHRASE   if set, encrypt the archive (openssl AES-256) — RECOMMENDED:
#                               the archive contains the vault key (data/secret), which
#                               decrypts every stored SSH credential. An unencrypted copy
#                               that leaves the host (rsync/cloud sync) exposes them all.
set -euo pipefail

VOLUME="${WEBTERM_VOLUME:-webterm_webterm-data}"
OUT="${WEBTERM_BACKUP_DIR:-/var/backups/webterm}"
KEEP="${WEBTERM_BACKUP_KEEP:-14}"
IMAGE="${WEBTERM_IMAGE:-python:3.12-alpine}"
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUT"
chmod 700 "$OUT" 2>/dev/null || true      # arhivele conțin cheia seifului: dir privat

# One container: online-consistent DB copy + selective tar. /data is rw because
# SQLite may touch -shm to coordinate the WAL read; webterm.db itself is only read.
# `--entrypoint python3`: imaginea aplicaţiei are un entrypoint care face `exec gosu webterm`,
# adică COBOARĂ privilegiile. Rulat aşa, containerul de backup nu poate scrie în $OUT (root, 700)
# şi backupul cade cu PermissionError. Se vedea doar când $WEBTERM_IMAGE era setat în mediu —
# deci nu din timer-ul systemd, ci din upgrade.sh, care sursează .env. Ocolim entrypoint-ul.
# Volumul TREBUIE să existe deja. Docker creează tăcut un volum inexistent, iar de acolo
# totul „reuşeşte": `sqlite3.connect` face un webterm.db gol, `integrity_check` pe el
# întoarce `ok`, arhiva iese cu exit 0 — şi restaurarea ei raportează succes în timp ce
# şterge tot, inclusiv cheia care decriptează credenţialele. Un nume greşit de volum (typo,
# sau o instalare făcută cu `--dir`) e de ajuns. Procedura de verificare din RUNBOOK (timer
# activ, exit 0, arhive care cresc) nu poate distinge cazul ăsta.
docker volume inspect "$VOLUME" >/dev/null 2>&1 || {
  echo "REFUSING: volume '$VOLUME' does not exist — refusing to write an empty backup." >&2
  echo "         Check WEBTERM_VOLUME (see /etc/default/webterm-backup); 'docker volume ls' lists them." >&2
  exit 1
}

docker run --rm -i --entrypoint python3 \
  -v "$VOLUME":/data -v "$OUT":/out -e STAMP="$STAMP" "$IMAGE" - <<'PY'
import sqlite3, sys, tarfile, os
stamp = os.environ["STAMP"]
# ...şi conţinutul trebuie să fie al unei instalări reale. Fără `secret`, arhiva nu poate
# decripta nimic la restaurare — e o pierdere totală care arată ca un backup.
for required in ("webterm.db", "secret"):
    if not os.path.exists(os.path.join("/data", required)):
        sys.exit("REFUSING: /data/%s missing — this volume is not a WebTerm data volume" % required)
tmp = "/tmp/webterm.db"
src = sqlite3.connect("/data/webterm.db")
dst = sqlite3.connect(tmp)
with dst:
    src.backup(dst)                 # online backup API — consistent snapshot
dst.close(); src.close()
out = "/out/webterm-%s.tar.gz" % stamp
with tarfile.open(out, "w:gz") as t:
    t.add(tmp, arcname="webterm.db")            # the consistent copy
    # `agent-signing.key/.pub`: fără ele, un restore reface datele dar flota devine
    # NE-actualizabilă — agenţii au pubkey-ul vechi încorporat şi refuză (corect) update-uri
    # semnate cu o cheie nouă. Backupul din UI le includea deja (backup.py); timer-ul systemd,
    # nu. Adică exact copia pe care te bazezi la dezastru era cea incompletă.
    for name in ("secret", "agent-signing.key", "agent-signing.pub", "transcripts"):
        p = os.path.join("/data", name)
        if os.path.exists(p):
            t.add(p, arcname=name)
print("backup:", out)
PY

ARCHIVE="$OUT/webterm-$STAMP.tar.gz"
chmod 600 "$ARCHIVE" 2>/dev/null || true

# Criptare (recomandat): arhiva conține cheia seifului. Cu o parolă → openssl AES-256;
# fără openssl sau fără parolă → avertizăm zgomotos (arhiva rămâne în clar, doar 0600).
if [ -n "${WEBTERM_BACKUP_PASSPHRASE:-}" ]; then
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
    echo "ENCRYPTED backup: $ARCHIVE"
  else
    echo "WARNING: openssl is missing — the archive stays UNENCRYPTED (it holds the vault key)."
  fi
elif [ -t 1 ] || [ "${WEBTERM_BACKUP_ALLOW_PLAINTEXT:-0}" = "1" ]; then
  # rulare INTERACTIVĂ (sau refuz explicit): avertizăm zgomotos şi mergem mai departe
  echo "WARNING: WEBTERM_BACKUP_PASSPHRASE is not set — the archive holds the vault key in CLEARTEXT."
  echo "         Set a passphrase (AES encryption), or keep $OUT strictly private and encrypted off-host."
else
  # rulare NEINTERACTIVĂ (timer systemd, cron): un avertisment pe care nu-l citeşte nimeni
  # nu e o măsură. Arhiva conţine `data/secret` — cheia care decriptează TOATE credenţialele
  # SSH — iar /var/backups ajunge des în rsync-uri şi în snapshot-uri. Refuzăm.
  # Semnalat de auditul extern, 2026-08-06.
  rm -f "$ARCHIVE"
  echo "REFUSING: an automated backup without WEBTERM_BACKUP_PASSPHRASE." >&2
  echo "       The archive would hold the vault key in cleartext; it has been deleted." >&2
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
  if [ "${ARCHIVE##*.}" != "enc" ]; then
    echo "REFUSING the off-host upload: the archive is UNENCRYPTED (it holds the vault key)." >&2
    echo "                  Set WEBTERM_BACKUP_PASSPHRASE and run it again." >&2
    exit 1
  elif ! command -v rclone >/dev/null 2>&1; then
    echo "WARNING: WEBTERM_BACKUP_REMOTE is set but rclone is missing — the archive stays local only."
  else
    rclone copy "$ARCHIVE" "$WEBTERM_BACKUP_REMOTE" --no-traverse
    echo "backup uploaded: $WEBTERM_BACKUP_REMOTE/$(basename "$ARCHIVE")"
    if [ -n "${WEBTERM_BACKUP_REMOTE_KEEP_DAYS:-}" ]; then
      rclone delete "$WEBTERM_BACKUP_REMOTE" --min-age "${WEBTERM_BACKUP_REMOTE_KEEP_DAYS}d" \
        --include "webterm-*.tar.gz.enc"
    fi
  fi
fi

# Rotaţie: şterge tot ce trece de cele mai noi $KEEP arhive (.tar.gz şi .tar.gz.enc).
# `|| true` NU e cosmetic: cu `set -o pipefail`, dacă unul dintre globuri nu se potriveşte
# cu nimic (tipic: toate arhivele sunt deja criptate, deci `webterm-*.tar.gz` rămâne
# neexpandat), `ls` iese cu 2 şi ar rupe scriptul DUPĂ ce arhiva a fost deja făcută —
# backup raportat ca eşuat şi, mai rău, rotaţia nu s-ar mai executa niciodată.
{ ls -1t "$OUT"/webterm-*.tar.gz.enc "$OUT"/webterm-*.tar.gz 2>/dev/null || true; } \
  | tail -n +"$((KEEP + 1))" | xargs -r rm -f

echo "backup: $ARCHIVE (keeping newest $KEEP)"
