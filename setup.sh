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
  say "You can get it again any time with:  make token"
else
  # A missing token in the logs does NOT prove an account exists: logs rotate and containers get
  # recreated. This used to claim "an account seems to exist already — just log in", which sent
  # people looking for a password that was never set.
  say "Open:  $URL"
  say "No token found in the logs (rotated? container recreated?). Get it with:  make token"
fi
say "Useful commands:  make help"
