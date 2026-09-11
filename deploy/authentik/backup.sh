#!/usr/bin/env bash
# Backup zilnic al Authentik: dump-ul Postgres (useri, passkeys, config OIDC, cheia de semnare)
# + .env (AUTHENTIK_SECRET_KEY — necesar la restore ca să decripteze câmpurile din DB). Criptat
# cu AUTHENTIK_BACKUP_PASSPHRASE (openssl AES-256), păstrează cele mai noi $KEEP. Rulat de
# authentik-backup.timer. Restore: openssl -d → tar xzf → docker compose exec -T postgresql
# psql -U authentik -d authentik < authentik.sql (pe un stack cu ACELAŞI .env/secret key).
#
#   AUTHENTIK_BACKUP_DIR         where archives go   (default /var/backups/authentik)
#   AUTHENTIK_BACKUP_KEEP        how many to keep    (default 14)
#   AUTHENTIK_BACKUP_PASSPHRASE  encrypt the archive (openssl AES-256) — OBLIGATORIU pentru un
#                                backup automat: arhiva conţine cheia de semnare + secretele.
#   Off-host copy (arhivă criptată; fiecare destinaţie e independentă, foloseşte oricare/toate):
#     AUTHENTIK_BACKUP_RSYNC=user@host:/path/   rsync-over-SSH (key auth); + _RSYNC_KEEP_DAYS=N
#     AUTHENTIK_BACKUP_FTPS=ftp://host/path/    FTP over TLS (curl --ssl-reqd); + _FTPS_USER/_FTPS_PASSWORD
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${AUTHENTIK_BACKUP_DIR:-/var/backups/authentik}"
KEEP="${AUTHENTIK_BACKUP_KEEP:-14}"
COMPOSE="docker compose -f $DIR/docker-compose.yml"
# instalările de producţie folosesc compose-ul de prod; dacă doar el există, îl luăm pe-ăla
[ -f "$DIR/docker-compose.yml" ] || COMPOSE="docker compose -f $DIR/docker-compose.prod.yml"

mkdir -p "$OUT"; chmod 700 "$OUT"
TS=$(date +%Y%m%d-%H%M%S)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# 1. dump Postgres din interiorul containerului (nu depinde de un psql pe host)
$COMPOSE exec -T postgresql pg_dump -U authentik -d authentik > "$TMP/authentik.sql"
[ -s "$TMP/authentik.sql" ] || { echo "REFUSING: pg_dump gol — e stack-ul pornit?" >&2; exit 1; }

# 2. include .env (secretele fără de care restore-ul nu poate decripta câmpurile Authentik)
cp "$DIR/.env" "$TMP/env" 2>/dev/null || true

# 3. arhivă
ARCHIVE="$OUT/authentik-$TS.tar.gz"
tar -czf "$ARCHIVE" -C "$TMP" authentik.sql env
chmod 600 "$ARCHIVE"

# 4. criptare (obligatorie pentru un backup automat: arhiva conţine cheia de semnare + secretele)
if [ -n "${AUTHENTIK_BACKUP_PASSPHRASE:-}" ]; then
  command -v openssl >/dev/null 2>&1 || { echo "REFUSING: openssl lipseşte, iar arhiva ar rămâne în clar." >&2; rm -f "$ARCHIVE"; exit 1; }
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
    -in "$ARCHIVE" -out "$ARCHIVE.enc" -pass env:AUTHENTIK_BACKUP_PASSPHRASE
  rm -f "$ARCHIVE"; ARCHIVE="$ARCHIVE.enc"; chmod 600 "$ARCHIVE"
  echo "ENCRYPTED backup: $ARCHIVE"
else
  echo "REFUSING: AUTHENTIK_BACKUP_PASSPHRASE nesetat — arhiva conţine cheia de semnare şi secretele." >&2
  echo "         Setează parola în /etc/default/authentik-backup şi rulează din nou." >&2
  rm -f "$ARCHIVE"; exit 1
fi

# 5. copie off-host prin rsync-over-SSH (universal, criptat, auth pe cheie, fără rclone). Doar .enc.
if [ -n "${AUTHENTIK_BACKUP_RSYNC:-}" ]; then
  if ! command -v rsync >/dev/null 2>&1; then
    echo "WARNING: AUTHENTIK_BACKUP_RSYNC setat dar rsync lipseşte — arhiva rămâne doar local."
  else
    rsync -a -e "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new" "$ARCHIVE" "$AUTHENTIK_BACKUP_RSYNC"
    echo "backup rsync'd: ${AUTHENTIK_BACKUP_RSYNC%/}/$(basename "$ARCHIVE")"
    if [ -n "${AUTHENTIK_BACKUP_RSYNC_KEEP_DAYS:-}" ]; then
      _rh=${AUTHENTIK_BACKUP_RSYNC%%:*}; _rp=${AUTHENTIK_BACKUP_RSYNC#*:}
      ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$_rh" \
        "find '$_rp' -name 'authentik-*.tar.gz.enc' -mtime +${AUTHENTIK_BACKUP_RSYNC_KEEP_DAYS} -delete" 2>/dev/null || true
    fi
  fi
fi

# 6. copie off-host prin FTPS (curl --ssl-reqd IMPUNE TLS; FTP simplu ar scurge parola în clar)
if [ -n "${AUTHENTIK_BACKUP_FTPS:-}" ]; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "WARNING: AUTHENTIK_BACKUP_FTPS setat dar curl lipseşte — arhiva rămâne doar local."
  else
    _furl="${AUTHENTIK_BACKUP_FTPS%/}/$(basename "$ARCHIVE")"
    if curl -fsS --ssl-reqd --ftp-create-dirs -T "$ARCHIVE" "$_furl" \
         ${AUTHENTIK_BACKUP_FTPS_USER:+--user "$AUTHENTIK_BACKUP_FTPS_USER:${AUTHENTIK_BACKUP_FTPS_PASSWORD:-}"}; then
      echo "backup uploaded (FTPS): $_furl"
    else
      echo "WARNING: FTPS upload eşuat (server fără TLS, sau credenţiale/cale greşite)." >&2
    fi
  fi
fi

# 7. rotaţie: şterge tot ce trece de cele mai noi $KEEP (.tar.gz şi .tar.gz.enc)
{ ls -1t "$OUT"/authentik-*.tar.gz.enc "$OUT"/authentik-*.tar.gz 2>/dev/null || true; } \
  | tail -n +"$((KEEP + 1))" | xargs -r rm -f
echo "backup done (keeping newest $KEEP in $OUT)"
