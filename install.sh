#!/usr/bin/env bash
# WebTerm — production installer for a clean Ubuntu/Debian server.
# Takes a freshly installed machine to a working stack: Docker, the runtime files
# in /opt/webterm, .env (domain + Let's Encrypt + Cloudflare token), a firewall,
# Traefik plus the app from ghcr, a daily backup (systemd timer) and a health check.
#
# Interactive (from a cloned repo):
#   sudo ./install.sh
#
# Non-interactive (cloud-init, curl | bash) — PREFER files for secrets:
# command-line arguments are visible in /proc/<pid>/cmdline and in shell history.
#   curl -fsSL https://raw.githubusercontent.com/sm26449/webterm/main/install.sh \
#     | sudo bash -s -- --domain term.example.com --email you@example.com \
#         --cf-token-file /run/secrets/cf --ghcr-token-file /run/secrets/ghcr
#   (--cf-token/--ghcr-token still work, but leave the secret visible to other processes)
#
# Idempotent: run again and it keeps .env and your data, updating everything else.
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


say()  { printf '\033[1;36m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m%s\033[0m\n' "$*"; }
err()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

# ── argumente ─────────────────────────────────────────────────────────────
INSTALL_DIR=/opt/webterm
REPO_URL=https://github.com/sm26449/webterm.git
BRANCH=main
DOMAIN="" EMAIL="" CF_TOKEN="" GHCR_USER=sm26449 GHCR_TOKEN="" IMAGE=""
DO_PORTCHECK=1
DO_CERTCHECK=1
DO_UFW=1 DO_BACKUP=1 NONINTERACTIVE=0

usage() {
  sed -n '2,15p' "$0" 2>/dev/null || true
  cat <<'EOF'
Options:
  --domain <fqdn>       the public domain (DNS record → this server)
  --email <email>       Let's Encrypt email (expiry notices)
  --cf-token <token>    Cloudflare Zone:DNS:Edit token (DNS-01 certificate)
  --cf-token-file <f>   read the Cloudflare token from a file (preferred over --cf-token)
  --ghcr-user <user>    ghcr.io user (default: sm26449)
  --ghcr-token <token>  ghcr read:packages token (private image)
  --ghcr-token-file <f> read the ghcr token from a file (preferred over --ghcr-token)
  --image <ref>         the image (default: ghcr.io/sm26449/webterm:v2.0.9)
  --dir <path>          installation directory (default: /opt/webterm)
  --repo <url>          repository to take the files from (standalone mode)
  --branch <name>       branch to clone (default: main)
  --no-ufw              do not touch the firewall
  --no-backup           do not install the daily backup timer
  --skip-port-check     do not refuse when 80/443 are taken (you front WebTerm yourself)
  --no-cert-check       do not install the daily certificate-expiry timer
  --non-interactive     ask nothing (fails if a value is missing)
  -h | --help           this message
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --cf-token) CF_TOKEN="$2"; shift 2 ;;
    --cf-token-file) CF_TOKEN="$(cat "$2")"; shift 2 ;;
    --ghcr-user) GHCR_USER="$2"; shift 2 ;;
    --ghcr-token) GHCR_TOKEN="$2"; shift 2 ;;
    --ghcr-token-file) GHCR_TOKEN="$(cat "$2")"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --dir) INSTALL_DIR="$2"; shift 2 ;;
    --repo) REPO_URL="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --no-ufw) DO_UFW=0; shift ;;
    --no-backup) DO_BACKUP=0; shift ;;
    --skip-port-check) DO_PORTCHECK=0; shift ;;
    --no-cert-check) DO_CERTCHECK=0; shift ;;
    --non-interactive) NONINTERACTIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# ── prerechizite ──────────────────────────────────────────────────────────
[ "$(id -u)" = 0 ] || { err "Run this with sudo/root."; exit 1; }
command -v apt-get >/dev/null || { err "The installer requires Ubuntu/Debian (apt)."; exit 1; }

ask() { # ask <var> <prompt> [secret]
  local var="$1" prompt="$2" secret="${3:-}" val
  [ -n "${!var}" ] && return 0
  if [ "$NONINTERACTIVE" = 1 ]; then err "Missing --${var,,} (non-interactive mode)."; exit 1; fi
  if [ -n "$secret" ]; then read -rsp "$prompt: " val < /dev/tty; echo; else read -rp "$prompt: " val < /dev/tty; fi
  [ -n "$val" ] || { err "Empty value."; exit 1; }
  printf -v "$var" '%s' "$val"
}

say "── WebTerm · install on a clean server ──"

# ── 1) Docker (repo oficial) ─────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  say "[1/7] Instalez Docker (repo-ul oficial)…"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg git >/dev/null
  install -m 0755 -d /etc/apt/keyrings
  . /etc/os-release
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
else
  say "[1/7] Docker is already installed."
  apt-get install -y -qq git curl >/dev/null 2>&1 || true
fi
docker compose version >/dev/null 2>&1 || { err "The docker compose plugin is missing."; exit 1; }
# start now and at boot (on systems without systemd — a container — we only check)
if [ -d /run/systemd/system ]; then systemctl enable --now docker >/dev/null 2>&1 || true; fi
docker info >/dev/null 2>&1 || { err "The Docker daemon is not running."; exit 1; }

# Porturile 80/443, verificate AICI — înainte să scriem `.env`, să copiem fişiere în
# $INSTALL_DIR, să atingem ufw sau să instalăm timere systemd. Altfel un port ocupat (nginx,
# un panou, alt reverse proxy — cazul obişnuit pe un server care nu e gol) lasă în urmă o
# instalare pe jumătate şi un mesaj de la Docker care nu spune ce e de făcut.
# `install.sh` e calea de PRODUCŢIE, deci aici starea parţială costă cel mai mult.
# Dacă stiva noastră rulează deja (reinstalare peste ea), ea ţine porturile — nu e o problemă.
# Necunoscut ≠ liber. Fără ambele unelte, verificarea nu poate spune nimic, iar sub
# `set -euo pipefail` chiar putea omorî scriptul tăcut. `setup.sh` a primit avertismentul
# grațios; aici lipsea, deşi asta e calea de PRODUCŢIE.
if [ "$DO_PORTCHECK" = 1 ] && ! command -v ss >/dev/null 2>&1 \
   && ! command -v netstat >/dev/null 2>&1; then
  warn "Neither 'ss' nor 'netstat' is available — I cannot check whether 80/443 are free."
  warn "If Traefik fails to start with 'port is already allocated', that is why."
  DO_PORTCHECK=0
fi
if [ "$DO_PORTCHECK" = 1 ] && [ -z "$(docker ps -q --filter label=com.docker.compose.project=webterm 2>/dev/null)" ]; then
  BUSY=""
  for p in 80 443; do
    if command -v ss >/dev/null 2>&1; then
      h=$(ss -ltnHp "sport = :$p" 2>/dev/null | sed -n 's/.*users:((\"\([^"]*\)\".*/\1/p' | head -1)
    else
      h=$(netstat -ltnp 2>/dev/null | awk -v pat=":$p\$" '$4 ~ pat {print $7; exit}')
    fi
    [ -n "${h:-}" ] && BUSY="${BUSY}  · port ${p} is held by: ${h}"$'\n'
  done
  if [ -n "$BUSY" ]; then
    err "Ports 80/443 are already in use — Traefik could not start and the install would stop halfway:"
    printf '%s' "$BUSY" >&2
    err "Traefik needs :80 for the ACME HTTP-01 challenge and :443 for TLS, so these two are
not configurable here. Free them, or — if you already run a proxy in front and will forward
to WebTerm yourself — re-run with --skip-port-check.
Nothing was changed yet."
    exit 1
  fi
fi

# ── 2) runtime files ──────────────────────────────────────────────────────
# From the local checkout if the installer runs inside one, otherwise clone.
SRC="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /nonexistent)"
mkdir -p "$INSTALL_DIR"
if [ -f "$SRC/docker-compose.prod.yml" ]; then
  say "[2/7] Copying files from the local checkout ($SRC)…"
  FILES_SRC="$SRC"
else
  say "[2/7] Fetching files from $REPO_URL ($BRANCH)…"
  TMP_CLONE=$(mktemp -d)
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TMP_CLONE" >/dev/null
  FILES_SRC="$TMP_CLONE"
fi
if [ "$FILES_SRC" != "$INSTALL_DIR" ]; then
  install -m 0644 "$FILES_SRC/docker-compose.prod.yml" "$INSTALL_DIR/"
  install -m 0644 "$FILES_SRC/.env.prod.example" "$INSTALL_DIR/"
  install -m 0755 "$FILES_SRC/deploy.sh" "$FILES_SRC/rollback.sh" \
    "$FILES_SRC/upgrade.sh" "$FILES_SRC/remove.sh" "$INSTALL_DIR/"
  install -d "$INSTALL_DIR/scripts" "$INSTALL_DIR/deploy"
  install -m 0755 "$FILES_SRC/scripts/backup.sh" "$FILES_SRC/scripts/restore.sh" \
    "$FILES_SRC/scripts/cert-check.sh" "$INSTALL_DIR/scripts/"
  install -m 0644 "$FILES_SRC/deploy/webterm-backup.service" "$FILES_SRC/deploy/webterm-backup.timer" \
    "$FILES_SRC/deploy/webterm-cert-check.service" "$FILES_SRC/deploy/webterm-cert-check.timer" \
    "$INSTALL_DIR/deploy/"
fi
[ -n "${TMP_CLONE:-}" ] && rm -rf "$TMP_CLONE"
cd "$INSTALL_DIR"

# ── 3) .env ───────────────────────────────────────────────────────────────
say "[3/7] Configurare (.env)…"
if [ -f .env ]; then
  say "  .env exists — keeping your values; filling in only what is missing."
  load_env ./.env
  DOMAIN="${DOMAIN:-${WEBTERM_DOMAIN:-}}"
  EMAIL="${EMAIL:-${LETSENCRYPT_EMAIL:-}}"
  CF_TOKEN="${CF_TOKEN:-${CF_DNS_API_TOKEN:-}}"
  IMAGE="${IMAGE:-${WEBTERM_IMAGE:-}}"
fi
ask DOMAIN  "Public domain (e.g. term.example.com)"
ask EMAIL   "Email Let's Encrypt"
# Tokenul Cloudflare NU mai e obligatoriu. Fără el mergem pe HTTP-01, care nu cere
# niciun provider DNS — doar ca domeniul să rezolve spre server şi portul 80 să fie
# accesibil. Cu el, DNS-01: merge în spatele proxy-ului CF sau prin NAT fără port 80,
# şi e singurul care poate emite un WILDCARD pentru subdomeniile de forward.
if [ -z "${CF_TOKEN:-}" ] && [ "$NONINTERACTIVE" != 1 ]; then
  say ""
  say "  Certificat TLS: fără token Cloudflare folosim HTTP-01 (Let's Encrypt), care cere doar"
  say "  ca $DOMAIN să rezolve spre acest server şi portul 80 să fie accesibil din internet."
  say "  Cu token Cloudflare (DNS-01) merge şi în spatele proxy-ului CF sau prin NAT, şi"
  say "  emite un wildcard pentru subdomeniile de port forwarding."
  printf '  Cloudflare Zone:DNS:Edit token (Enter = fără, folosesc HTTP-01): '
  read -rs CF_TOKEN < /dev/tty; echo
fi

# Let's Encrypt refuses the account if the address is invalid (a typo'd TLD, .ent),
# and without an account no certificate is issued. Catch it now, not at runtime.
case "$EMAIL" in
  *@*.*) : ;;
  *) err "Invalid email: '$EMAIL' (expected something like name@domain.tld)."; exit 1 ;;
esac
case "$DOMAIN" in
  *.*) : ;;
  *) err "Invalid domain: '$DOMAIN' (expected an FQDN, e.g. term.example.com)."; exit 1 ;;
esac
IMAGE="${IMAGE:-ghcr.io/sm26449/webterm:v2.0.9}"
SETUP_TOKEN="${WEBTERM_SETUP_TOKEN:-}"
if [ -z "$SETUP_TOKEN" ]; then
  SETUP_TOKEN=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | cut -c1-32)
fi
# .env is UPDATED, not rewritten. The old version (a heredoc with six fixed keys) silently
# erased everything the administrator had added since: GHCR_TOKEN, the alert config, and
# variabilele de securitate (WEBTERM_TRUSTED_PROXY_HOPS, _IDLE_LOCK_SECS, _SESSION_TTL_DAYS,
# above all the hardening settings. Re-running the installer — which you do to FIX something —
# quietly reset it all to defaults.
umask 077
[ -f .env ] || printf '# generated by install.sh %s — see .env.prod.example for details\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > .env

set_env() {          # set_env KEY VALUE — replaces in place, or appends
  _k="$1"; _v="$2"
  if grep -q "^${_k}=" .env 2>/dev/null; then
    # values may contain / and & → use | as delimiter and escape & (sed would interpret them)
    _e=$(printf '%s' "$_v" | sed 's/[|&\\]/\\&/g')
    sed -i "s|^${_k}=.*|${_k}=${_e}|" .env
  else
    printf '%s=%s\n' "$_k" "$_v" >> .env
  fi
}

set_env WEBTERM_DOMAIN "$DOMAIN"
set_env LETSENCRYPT_EMAIL "$EMAIL"
set_env CF_DNS_API_TOKEN "$CF_TOKEN"
# Ce resolver folosesc routerele, şi dacă cerem wildcard. Wildcard-ul se cere DOAR pe
# DNS-01: HTTP-01 nu-l poate emite şi cererea ar eşua în buclă.
FWD_DOM="${FORWARD_DOMAIN:-$DOMAIN}"
if [ -n "$CF_TOKEN" ]; then
  # DNS-01: cerem explicit wildcard, ca un singur certificat să acopere şi forward-urile
  set_env WEBTERM_CERT_RESOLVER "ledns"
  set_env WEBTERM_CERT_LABEL_MAIN "traefik.http.routers.webterm.tls.domains[0].main=$DOMAIN"
  set_env WEBTERM_CERT_LABEL_SANS "traefik.http.routers.webterm.tls.domains[0].sans=*.$DOMAIN"
  set_env WEBTERM_CERT_LABEL_FWD_MAIN "traefik.http.routers.webterm-fwd.tls.domains[0].main=$FWD_DOM"
  set_env WEBTERM_CERT_LABEL_FWD_SANS "traefik.http.routers.webterm-fwd.tls.domains[0].sans=*.$FWD_DOM"
else
  # HTTP-01: NICIO listă de domenii. Traefik deduce numele din regula Host(...) pentru app,
  # iar forward-urile (HostRegexp) nu pot obţine certificat pe calea asta — e documentat.
  set_env WEBTERM_CERT_RESOLVER "le"
  set_env WEBTERM_CERT_LABEL_MAIN ""
  set_env WEBTERM_CERT_LABEL_SANS ""
  set_env WEBTERM_CERT_LABEL_FWD_MAIN ""
  set_env WEBTERM_CERT_LABEL_FWD_SANS ""
fi
set_env WEBTERM_IMAGE "$IMAGE"
set_env GHCR_USER "$GHCR_USER"
# The setup token is kept if it already exists: regenerating it on every run would
# invalidate the instructions you wrote down and confuse you at the first login.
grep -q '^WEBTERM_SETUP_TOKEN=.' .env 2>/dev/null || set_env WEBTERM_SETUP_TOKEN "$SETUP_TOKEN"
chmod 600 .env
umask 022

# verificare token Cloudflare (doar avertisment — poate lipsi accesul la net)
CF_OK=$(curl -fsS -m 10 -H "Authorization: Bearer $CF_TOKEN" \
  https://api.cloudflare.com/client/v4/user/tokens/verify 2>/dev/null \
  | grep -o '"status":"active"' || true)
if [ -n "$CF_OK" ]; then
  say "  Token Cloudflare: activ ✓"
  # An interrupted earlier run can leave an orphan _acme-challenge TXT record in the zone.
  # lego then gets "81058: An identical record already exists" and never issues the
  # certificate. We clean the leftovers — the record is ephemeral, not serving traffic.
  # The zone is NOT "the last two labels": on compound suffixes (term.company.co.uk,
  # host.com.tr) that yields `co.uk`, the API finds nothing, no cleanup happens, and the
  # warning below blames the token scope — sending you down a false trail.
  # We shorten the domain label by label and take the first zone the token can actually see.
  # We query the FULL name first, then shorten. Stripping a label before the first query
  # missed domains hosted on the zone apex (`--domain example.com` with zone `example.com`):
  # it neither cleaned the orphan TXT records NOR reported them, and claimed the token
  # could not see any zone, sending the operator hunting for scopes.
  ZONE=""; ZID=""; CAND="$DOMAIN"
  while :; do
    TRY=$(curl -fsS -m 10 -H "Authorization: Bearer $CF_TOKEN" \
      "https://api.cloudflare.com/client/v4/zones?name=$CAND" 2>/dev/null \
      | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
    if [ -n "$TRY" ]; then ZONE="$CAND"; ZID="$TRY"; break; fi
    [ "${CAND#*.}" != "$CAND" ] || break
    CAND="${CAND#*.}"
  done
  [ -n "$ZONE" ] || ZONE="$DOMAIN"
  if [ -n "$ZID" ]; then
    for RID in $(curl -fsS -m 10 -H "Authorization: Bearer $CF_TOKEN" \
      "https://api.cloudflare.com/client/v4/zones/$ZID/dns_records?type=TXT&name=_acme-challenge.$DOMAIN" 2>/dev/null \
      | grep -o '"id":"[^"]*"' | cut -d'"' -f4); do
      curl -fsS -m 10 -X DELETE -H "Authorization: Bearer $CF_TOKEN" \
        "https://api.cloudflare.com/client/v4/zones/$ZID/dns_records/$RID" >/dev/null 2>&1 \
        && say "  Cleaned up an orphan _acme-challenge TXT record."
    done
  else
    warn "  The token cannot see any zone containing '$DOMAIN' — DNS-01 will fail."
    warn "  Check the scope (Zone:DNS:Edit) AND that the zone belongs to this token's account."
  fi
else
  warn "  Could not confirm the Cloudflare token (continuing — Traefik will use it when issuing)."
fi

# ── 4) ghcr login (private image) ────────────────────────────────────────
if [ -n "$GHCR_TOKEN" ]; then
  say "[4/7] Logging in to ghcr.io…"
  printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin >/dev/null
elif docker pull "$IMAGE" >/dev/null 2>&1; then
  say "[4/7] The image can be pulled without logging in."
else
  warn "[4/7] No --ghcr-token and the pull failed — if the image is private, run 'docker login ghcr.io' and start again."
fi

# ── 5) firewall ───────────────────────────────────────────────────────────
if [ "$DO_UFW" = 1 ] && command -v ufw >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  say "[5/7] Firewall (ufw): permit OpenSSH, 80, 443…"
  ufw allow OpenSSH >/dev/null   # BEFORE enable — so we do not cut off our own SSH
  ufw allow 80/tcp  >/dev/null
  ufw allow 443/tcp >/dev/null
  ufw status | grep -q "Status: active" || ufw --force enable >/dev/null
else
  say "[5/7] Skipping the firewall (no ufw, no systemd, or --no-ufw)."
fi

# ── 6) stack-ul ───────────────────────────────────────────────────────────
say "[6/7] Starting the stack (Traefik + app)…"
docker compose -f docker-compose.prod.yml pull || warn "  pull failed — using local images if present."
docker compose -f docker-compose.prod.yml up -d --remove-orphans

# O A DOUA instalare pe aceeaşi maşină nu are voie să deturneze unităţile primei. Numele lor
# sunt FIXE (`webterm-backup`, `webterm-cert-check`) indiferent de `--dir`, iar
# `/etc/default/webterm-backup` conţine numele volumului ŞI parola de criptare a arhivelor:
# o instalare de test ar fi redirectat backupul nocturn al producţiei spre volumul ei şi ar fi
# suprascris parola, lăsând arhivele vechi indescifrabile. Semnalat de un audit extern.
# Nu redenumim unităţile (ar rupe upgrade-ul instalărilor existente) — refuzăm coliziunea.
unit_belongs_elsewhere() {   # $1 = nume unitate → 0 dacă există şi arată spre alt director
  u="/etc/systemd/system/$1.service"
  [ -f "$u" ] || return 1
  grep -q "WorkingDirectory=$INSTALL_DIR\$" "$u" && return 1
  OTHER=$(grep -m1 '^WorkingDirectory=' "$u" | cut -d= -f2-)
  return 0
}

# backup zilnic (systemd timer), cu numele corect de volum pentru acest director
PROJECT=$(basename "$INSTALL_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
if [ "$DO_BACKUP" = 1 ] && [ -d /run/systemd/system ] \
   && unit_belongs_elsewhere webterm-backup; then
  warn "  Skipping the backup timer: webterm-backup.service already belongs to ${OTHER:-another install}."
  warn "  Unit names are fixed, so installing it here would redirect THAT install's nightly backup"
  warn "  and overwrite /etc/default/webterm-backup, whose passphrase decrypts its archives."
elif [ "$DO_BACKUP" = 1 ] && [ -d /run/systemd/system ]; then
  say "  Installing the daily backup (03:30, keeps 14 archives)…"
  sed -e "s|/opt/webterm|$INSTALL_DIR|g" deploy/webterm-backup.service \
    > /etc/systemd/system/webterm-backup.service
  cp deploy/webterm-backup.timer /etc/systemd/system/
  # The encryption passphrase, generated now. `backup.sh` REFUSES to write unencrypted
  # archives non-interactively (they contain the vault key), so without it the timer would fail
  # every night, silently, while the operator believed they had a daily backup.
  # The file is KEPT if it already exists: otherwise older archives become undecipherable.
  if [ -f /etc/default/webterm-backup ] \
     && grep -q '^WEBTERM_BACKUP_PASSPHRASE=.' /etc/default/webterm-backup; then
    BK_PASS=$(grep '^WEBTERM_BACKUP_PASSPHRASE=' /etc/default/webterm-backup | cut -d= -f2-)
    say "  Kept the existing backup passphrase."
  else
    BK_PASS=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-40)
  fi
  umask 077
  {
    echo "WEBTERM_VOLUME=${PROJECT}_webterm-data"
    echo "# Archive encryption passphrase (AES-256). KEEP A COPY OFF THIS SERVER:"
    echo "# without it, the archives in /var/backups/webterm cannot be recovered."
    echo "WEBTERM_BACKUP_PASSPHRASE=$BK_PASS"
  } > /etc/default/webterm-backup
  chmod 600 /etc/default/webterm-backup
  umask 022
  systemctl daemon-reload
  systemctl enable --now webterm-backup.timer >/dev/null
  printf '\n  \033[1mBACKUP PASSPHRASE (write it down now, somewhere off this server):\033[0m\n'
  printf '      %s\n' "$BK_PASS"
  printf '  Without it, the encrypted archives in /var/backups/webterm cannot be restored.\n\n'
else
  warn "  Skipping the backup timer (no systemd, or --no-backup)."
fi

# Traefik renews the certificate, but that can fail silently (revoked CF token, an orphan
# TXT record). A daily check turns that into a visible failure (systemctl --failed, the
# journal) and, if you set WEBTERM_ALERT_URL, into a notification.
if [ "$DO_CERTCHECK" = 1 ] && [ -d /run/systemd/system ] \
   && unit_belongs_elsewhere webterm-cert-check; then
  warn "  Skipping the certificate check: webterm-cert-check.service already belongs to ${OTHER:-another install}."
elif [ "$DO_CERTCHECK" = 1 ] && [ -d /run/systemd/system ]; then
  say "  Installing the daily certificate check (07:15, alerts under 15 days)…"
  sed -e "s|/opt/webterm|$INSTALL_DIR|g" deploy/webterm-cert-check.service \
    > /etc/systemd/system/webterm-cert-check.service
  cp deploy/webterm-cert-check.timer /etc/systemd/system/
  if [ ! -f /etc/default/webterm-cert-check ]; then
    printf 'WEBTERM_DOMAIN=%s\nWEBTERM_CERT_MIN_DAYS=15\n# Optional webhook (Slack/Discord): notified when expiry is close\n#WEBTERM_ALERT_URL=\n' \
      "$DOMAIN" > /etc/default/webterm-cert-check
  else
    sed -i "s|^WEBTERM_DOMAIN=.*|WEBTERM_DOMAIN=$DOMAIN|" /etc/default/webterm-cert-check
  fi
  systemctl daemon-reload
  systemctl enable --now webterm-cert-check.timer >/dev/null
fi

# ── 7) health check ───────────────────────────────────────────────────────
say "[7/7] Waiting for the app…"
APP_OK=""
for _ in $(seq 1 30); do
  ST=$(docker compose -f docker-compose.prod.yml ps --format '{{.Status}}' app 2>/dev/null || true)
  case "$ST" in *healthy*) APP_OK=1; break ;; esac
  sleep 2
done
if [ -n "$APP_OK" ]; then say "  The app is healthy ✓"
else warn "  The app did not report healthy within 60s — check: docker compose -f docker-compose.prod.yml logs app"; fi

# The certificate (DNS-01) is issued at startup. We check the two things that can
# fail independently: (a) the certificate is from Let's Encrypt, not Traefik's default;
# (b) the route to the app exists — otherwise Traefik answers with its own 404.
say "  Checking the certificate and the route (up to 90s)…"
TLS_OK="" ROUTE_OK=""
for _ in $(seq 1 30); do
  ISSUER=$(echo | openssl s_client -connect "127.0.0.1:443" -servername "$DOMAIN" 2>/dev/null \
    | openssl x509 -noout -issuer 2>/dev/null || true)
  case "$ISSUER" in *"Let's Encrypt"*) TLS_OK=1 ;; esac
  CODE=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" \
    "https://$DOMAIN/" 2>/dev/null || true)
  [ "$CODE" = "200" ] && ROUTE_OK=1
  [ -n "$TLS_OK" ] && [ -n "$ROUTE_OK" ] && break
  sleep 3
done

if [ -n "$ROUTE_OK" ]; then say "  Route to the app: 200 ✓"
else
  warn "  Traefik is not serving the app (response: ${CODE:-none}; 404 = no router for $DOMAIN)."
  warn "  See: docker compose -f docker-compose.prod.yml logs traefik | grep -i error"
fi
if [ -n "$TLS_OK" ]; then say "  Let's Encrypt certificate ✓"
else
  warn "  Still Traefik's default certificate (Let's Encrypt has not issued one)."
  warn "  Usual causes: a Cloudflare token without Zone:DNS:Edit on $DOMAIN's zone, or an invalid LE email."
  warn "  See: docker compose -f docker-compose.prod.yml logs traefik | grep -i acme"
fi

# Cloudflare proxying with SSL set to 'Flexible' = a redirect loop (ERR_TOO_MANY_REDIRECTS):
# CF arrives on :80, Traefik redirects to https, CF comes back on :80… forever.
PUBIP=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1; exit}' || true)
# api.ipify.org e singura terță parte pe care o atinge installerul, şi doar ca să compare
# IP-ul public cu cel din DNS. O apelăm NUMAI dacă domeniul chiar rezolvă — altfel nu avem
# cu ce compara şi i-am divulga IP-ul serverului degeaba.
MYIP=""
if [ -n "$PUBIP" ]; then
  MYIP=$(curl -fsS -m 5 https://api.ipify.org 2>/dev/null || true)
fi
if [ -n "$PUBIP" ] && [ -n "$MYIP" ] && [ "$PUBIP" != "$MYIP" ]; then
  warn "  $DOMAIN points at $PUBIP, not at this server ($MYIP) — probably the Cloudflare proxy."
  warn "  If it is the CF proxy: set SSL/TLS to 'Full (strict)'. On 'Flexible' you get ERR_TOO_MANY_REDIRECTS."
fi

echo
say "── Done ──"
echo "  URL:               https://$DOMAIN"
echo "  Setup token:       $SETUP_TOKEN"
echo "                     (required when creating the first account; stored in $INSTALL_DIR/.env)"
echo "  Directory:         $INSTALL_DIR   (.env config, chmod 600)"
echo "  Data:              Docker volume ${PROJECT}_webterm-data (SQLite + transcripts + key)"
echo "  To upgrade:        cd $INSTALL_DIR && sudo ./upgrade.sh"
echo "  Backup manual:     WEBTERM_VOLUME=${PROJECT}_webterm-data $INSTALL_DIR/scripts/backup.sh"
echo "  Restore:           $INSTALL_DIR/scripts/restore.sh <archive>"
echo
echo "  Next steps: open https://$DOMAIN, create the account with the setup token,"
echo "  then add your first host from the UI (+ host → Agent) — you get the agent install"
echo "  command to run on the target machine."
