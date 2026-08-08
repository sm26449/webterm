#!/usr/bin/env bash
# WebTerm — full gateway installer.
# Run:  ./setup.sh   (interactive)   or   ./setup.sh <domain-or-ip>
set -euo pipefail

cd "$(dirname "$0")"
say()  { printf '\033[1;36m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m%s\033[0m\n' "$*"; }
err()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

say "── WebTerm · install ──"

# 1) Prerequisites
command -v docker >/dev/null 2>&1 || { err "Docker is missing. Install it: https://docs.docker.com/engine/install/"; exit 1; }
if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
else err "Docker Compose is missing."; exit 1; fi
docker info >/dev/null 2>&1 || { err "Docker is not running, or you lack permission (try sudo, or add yourself to the docker group)."; exit 1; }

# Porturile, ÎNAINTE de a atinge ceva. Fără verificarea asta `up -d` porneşte aplicaţia, apoi
# Traefik nu poate lega :80, iar `set -e` opreşte scriptul — rezultatul e o instalare pe
# jumătate: un container sus, altul nu, şi un mesaj de la Docker („Bind for 0.0.0.0:80 failed")
# care nu spune ce e de făcut. Cazul e cel obişnuit, nu exotic: orice server care are deja un
# nginx, un panou de administrare sau un reverse proxy. Mai bine refuzăm din prima, spunând cine
# ţine portul, decât să lăsăm în urmă o stare ambiguă.
# Excepţie: dacă stiva NOASTRĂ e deja pornită, ea ţine portul — `up -d` e idempotent, mergem înainte.
# Fără `ss` ŞI fără `netstat` nu putem şti nimic — iar varianta veche întorcea gol, adică
# „port liber", şi lăsa exact instalarea pe jumătate pe care verificarea există s-o prevină.
# Necunoscut ≠ liber: o spunem şi mergem mai departe, ca omul să ştie ce n-am verificat.
if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
  warn "Neither 'ss' nor 'netstat' is available, so I cannot check whether the ports are free."
  warn "If the stack fails to start with 'port is already allocated', that is why."
fi
port_holder() {      # $1 = port → numele procesului care ascultă, sau gol
  if command -v ss >/dev/null 2>&1; then
    ss -ltnHp "sport = :$1" 2>/dev/null | sed -n 's/.*users:((\"\([^"]*\)\".*/\1/p' | head -1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltnp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p {print $7; exit}'
  fi
}
# Porturile pe care le leagă STIVA, nu 80/443 fix. README-ul documentează un
# `docker-compose.override.yml` cu `ports: !override` pe 8080/8443, exact pentru cazul „am deja
# ceva pe 80" — iar prima versiune a verificării ăsteia refuza fix rețeta pe care o recomandă
# documentația, fără portiță. Îl întrebăm pe compose ce va publica de fapt: el a citit deja
# override-ul, deci e singura sursă de adevăr care nu se poate contrazice cu ea însăși.
# `set -e` + `pipefail`: dacă `compose config` eşuează (un override scris de mână cu o
# indentare greşită — fişierul cu cea mai mare rată de typo din tot traseul), atribuirea de
# mai jos ar omorî scriptul, iar `2>/dev/null` ar înghiţi motivul: banner, exit 1, zero
# explicaţii. Prindem eroarea şi o ARĂTĂM, iar fallback-ul de mai jos redevine accesibil.
published_ports() {
  local out rc
  out=$($COMPOSE config 2>&1); rc=$?
  if [ $rc -ne 0 ]; then
    err "docker compose cannot read the configuration here:"
    printf '%s\n' "$out" | head -5 >&2
    err "Fix it (most often a typo in docker-compose.override.yml) and run again."
    exit 1
  fi
  printf '%s\n' "$out" | sed -n 's/^ *published: *"\{0,1\}\([0-9]\{1,\}\)"\{0,1\} *$/\1/p' | sort -u
}
if [ -z "$($COMPOSE ps -q 2>/dev/null)" ]; then
  BUSY=""
  PORTS="$(published_ports)"
  [ -n "$PORTS" ] || PORTS="80 443"       # compose prea vechi pentru `config` → cazul implicit
  for p in $PORTS; do
    h=$(port_holder "$p" || true)
    [ -n "$h" ] && BUSY="${BUSY}  · port ${p} is held by: ${h}"$'\n'
  done
  if [ -n "$BUSY" ]; then
    err "The ports this stack would publish are already in use:"
    printf '%s' "$BUSY" >&2
    err "Free them, or publish on different ports with a docker-compose.override.yml
(see the \"Ports 80 and 443 must be free\" section of README.md) and re-run.
Nothing was changed — no container was created."
    exit 1
  fi
fi

# 2) Configuration (.env)
HOST_ARG="${1:-}"
if [ -f .env ]; then
  say "Found an existing .env — using it. Delete it if you want to reconfigure."
else
  if [ -z "$HOST_ARG" ]; then
    printf 'Domain (e.g. term.example.com) or IP (e.g. 192.168.1.10, add :8443 if 443 is taken): '
    read -r HOST_ARG
  fi
  [ -n "$HOST_ARG" ] || { err "A domain or IP is required."; exit 1; }

  # A host may carry a port (`example.com:8443`) when 80/443 are taken and compose is
  # overridden. The two variables need it differently: WEBTERM_PUBLIC_URL must keep it
  # (the agent install command shown in the UI is built from that URL, and without the
  # port it is unreachable), while WEBTERM_DOMAIN goes into the Caddy site address and
  # must not. Splitting them here is what makes `setup.sh host:8443` work at all;
  # otherwise the port also broke the IP test below and landed in the Caddyfile.
  HOST_ONLY=${HOST_ARG%%:*}
  PORT_PART=""
  case "$HOST_ARG" in *:*) PORT_PART=":${HOST_ARG##*:}" ;; esac

  INSECURE=""
  if printf '%s' "$HOST_ONLY" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    INSECURE=1
    warn "Reached by IP → self-signed certificate (WEBTERM_AGENT_INSECURE=1)."
    warn "For production use a domain: it gives you valid TLS and passkeys (WebAuthn needs a domain, not an IP)."
  fi

  cat > .env <<EOF
WEBTERM_PUBLIC_URL=https://$HOST_ONLY$PORT_PART
WEBTERM_DOMAIN=$HOST_ONLY
WEBTERM_AGENT_INSECURE=$INSECURE
WEBTERM_SETUP_TOKEN=
EOF
  say "Wrote .env for https://$HOST_ONLY$PORT_PART"
fi

# 3) Build and start
say "Building and starting the containers…"
$COMPOSE up -d --build

# 4) Wait for the gateway
say "Waiting for the gateway…"
for _ in $(seq 1 60); do
  if docker exec "$($COMPOSE ps -q app)" python -c \
      "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/state')" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# 5) Setup token (if no account exists yet)
say ""
say "── Done ──"
URL=$(grep -E '^WEBTERM_PUBLIC_URL=' .env | cut -d= -f2-)
# This used to grep the human-readable sentence and strip spaces — but `tr -d ' '` does not remove
# Docker's container prefix, so the token printed as `app-1|xCXv…`. You copied it, got a 403, tried
# a few more times, and after the fifth you had locked yourself out of your own install for 15
# minutes (per-IP lockout), two minutes after cloning. We grep the STABLE marker
# `WEBTERM_SETUP_TOKEN=…`, which is in the log for exactly this purpose, and take only the value:
# it works with or without a log prefix.
TOKEN=$($COMPOSE logs app 2>/dev/null | grep -oE 'WEBTERM_SETUP_TOKEN=[A-Za-z0-9_-]+' | tail -1 | cut -d= -f2- || true)
if [ -n "$TOKEN" ]; then
  say "Open:  $URL"
  say "Setup token (for the first account):"
  printf '\n      \033[1;32m%s\033[0m\n\n' "$TOKEN"
  # `make` e opţional (README-l listează ca atare) şi lipseşte pe orice Debian/Ubuntu minimal,
  # deci nu poate fi SINGURA cale de recuperare a tokenului oferită la final.
  if command -v make >/dev/null 2>&1; then
    say "You can get it again any time with:  make token"
  else
    say "You can get it again any time with:"
    say "  $COMPOSE logs app | grep -oE 'WEBTERM_SETUP_TOKEN=[A-Za-z0-9_-]+' | tail -1 | cut -d= -f2-"
  fi
else
  # A missing token in the logs does NOT prove an account exists: logs rotate and containers get
  # recreated. This used to claim "an account seems to exist already — just log in", which sent
  # people looking for a password that was never set.
  say "Open:  $URL"
  say "No token found in the logs (rotated? container recreated?). Get it with:"
  say "  $COMPOSE logs app | grep -oE 'WEBTERM_SETUP_TOKEN=[A-Za-z0-9_-]+' | tail -1 | cut -d= -f2-"
fi
command -v make >/dev/null 2>&1 && say "Useful commands:  make help" || true
