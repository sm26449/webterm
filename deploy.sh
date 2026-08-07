#!/usr/bin/env bash
# WebTerm — production deploy from a pre-built ghcr image, with Traefik/SSL.
# One command:  ./deploy.sh [vX.Y.Z]
#   - creates .env from the example on first run
#   - generates the setup token if missing
#   - logs in to ghcr.io (private image) and pulls the latest image
#   - starts or updates the stack (Traefik issues the Let's Encrypt certificate)
# With an argument (./deploy.sh v2.0.1): pins the image in .env, remembers the
# previous image in .prev-image and, if the new container does not become healthy
# within 120s, ROLLS BACK to it automatically (./rollback.sh also works on its own).
# Without an argument: the image from .env, or :latest — same guard and rollback.
set -euo pipefail
cd "$(dirname "$0")"

FILE=docker-compose.prod.yml
COMPOSE="docker compose"
docker compose version >/dev/null 2>&1 || COMPOSE="docker-compose"
command -v docker >/dev/null || { echo "Docker is not installed."; exit 1; }

# --- .env ---
if [ ! -f .env ]; then
  cp .env.prod.example .env
  echo "→ Created .env from the example."
  echo "  Fill in WEBTERM_DOMAIN and LETSENCRYPT_EMAIL, then run ./deploy.sh again"
  exit 1
fi
set -a; . ./.env; set +a
: "${WEBTERM_DOMAIN:?set WEBTERM_DOMAIN in .env}"
: "${LETSENCRYPT_EMAIL:?set LETSENCRYPT_EMAIL in .env}"
# CF_DNS_API_TOKEN e OPŢIONAL: fără el, Traefik ia certificatul prin HTTP-01, care nu are
# nevoie de niciun provider DNS. Cerinţa lui obligatorie bloca orice instalare fără cont
# Cloudflare, deşi Let's Encrypt nu cere aşa ceva.
# Etichetele de certificat: `install.sh` le scrie, `deploy.sh` nu le scria deloc — deşi
# `.env.prod.example` afirmă că le scriu amândouă. Cine urma calea „cp .env.prod.example .env
# + ./deploy.sh" rămânea pe HTTP-01 chiar dacă adăuga ulterior un token Cloudflare.
set_cert_env() {
  grep -q "^$1=" .env 2>/dev/null && sed -i "s|^$1=.*|$1=$2|" .env || printf '%s=%s\n' "$1" "$2" >> .env
}
FWD_DOM="${FORWARD_DOMAIN:-$WEBTERM_DOMAIN}"
if [ -n "${CF_DNS_API_TOKEN:-}" ]; then
  set_cert_env WEBTERM_CERT_RESOLVER "ledns"
  set_cert_env WEBTERM_CERT_LABEL_MAIN "traefik.http.routers.webterm.tls.domains[0].main=$WEBTERM_DOMAIN"
  set_cert_env WEBTERM_CERT_LABEL_SANS "traefik.http.routers.webterm.tls.domains[0].sans=*.$WEBTERM_DOMAIN"
  set_cert_env WEBTERM_CERT_LABEL_FWD_MAIN "traefik.http.routers.webterm-fwd.tls.domains[0].main=$FWD_DOM"
  set_cert_env WEBTERM_CERT_LABEL_FWD_SANS "traefik.http.routers.webterm-fwd.tls.domains[0].sans=*.$FWD_DOM"
else
  set_cert_env WEBTERM_CERT_RESOLVER "le"
  set_cert_env WEBTERM_CERT_LABEL_MAIN ""
  set_cert_env WEBTERM_CERT_LABEL_SANS ""
  set_cert_env WEBTERM_CERT_LABEL_FWD_MAIN ""
  set_cert_env WEBTERM_CERT_LABEL_FWD_SANS ""
  echo "  no CF_DNS_API_TOKEN — using HTTP-01 (needs $WEBTERM_DOMAIN to resolve here and port 80 reachable)"
  echo "  note: port-forward subdomains need a wildcard certificate, which only DNS-01 can issue —"
  echo "        forwards will not get TLS on this path. Add a Cloudflare token if you use them."
  set -a; . ./.env; set +a
fi

# --- setup token (generated once, persisted in .env) ---
if [ -z "${WEBTERM_SETUP_TOKEN:-}" ]; then
  TOKEN=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | cut -c1-32)
  if grep -q '^WEBTERM_SETUP_TOKEN=' .env; then
    sed -i "s|^WEBTERM_SETUP_TOKEN=.*|WEBTERM_SETUP_TOKEN=$TOKEN|" .env
  else
    printf '\nWEBTERM_SETUP_TOKEN=%s\n' "$TOKEN" >> .env
  fi
  export WEBTERM_SETUP_TOKEN="$TOKEN"
  echo "→ Setup token generated and written to .env."
fi

# --- ghcr.io login (private image) ---
GHCR_TOKEN="${GHCR_TOKEN:-}"
if [ -z "$GHCR_TOKEN" ] && [ -n "${GHCR_TOKEN_FILE:-}" ] && [ -f "$GHCR_TOKEN_FILE" ]; then
  GHCR_TOKEN=$(tr -d ' \n\r' < "$GHCR_TOKEN_FILE")
fi
if [ -n "$GHCR_TOKEN" ]; then
  echo "$GHCR_TOKEN" | docker login ghcr.io -u "${GHCR_USER:-sm26449}" --password-stdin >/dev/null
  echo "→ Autentificat la ghcr.io."
else
  echo "→ No ghcr token; assuming you already ran 'docker login ghcr.io'."
fi

# --- target version, and recording the current image for rollback ---
# (a broken deploy once left the UI dead with no way back; since then every
# deploy writes down its return point before changing anything)
CUR_IMAGE="${WEBTERM_IMAGE:-}"
if [ -n "${1:-}" ]; then
  # validate the tag before sed writes it into .env: an argument containing |, &,
  # a newline or other metacharacters would corrupt the substitution or inject lines
  case "$1" in
    v[0-9]*.[0-9]*.[0-9]* | latest | sha-[0-9a-f]*) ;;
    *) echo "Invalid tag: $1 (expected vX.Y.Z, latest or sha-...)"; exit 1 ;;
  esac
  NEW_IMAGE="ghcr.io/${GHCR_USER:-sm26449}/webterm:$1"
  if grep -q '^WEBTERM_IMAGE=' .env; then
    sed -i "s|^WEBTERM_IMAGE=.*|WEBTERM_IMAGE=$NEW_IMAGE|" .env
  else
    printf '\nWEBTERM_IMAGE=%s\n' "$NEW_IMAGE" >> .env
  fi
  export WEBTERM_IMAGE="$NEW_IMAGE"
  echo "→ Targeted deploy: $NEW_IMAGE (previous: ${CUR_IMAGE:-<unset>})"
fi
if [ -n "$CUR_IMAGE" ] && [ "$CUR_IMAGE" != "${WEBTERM_IMAGE:-}" ]; then
  printf '%s\n' "$CUR_IMAGE" > .prev-image
fi

# --- pull + up (replaces an older Caddy stack if present, keeps the data) ---
$COMPOSE -f "$FILE" pull
$COMPOSE -f "$FILE" up -d --remove-orphans

# --- health guard and automatic rollback ---
# Prinde imaginile care nu pornesc (crash loop, config stricat). Un frontend
# that only breaks in the browser is NOT visible here — the CI smoke test covers
# that (the image is never published) along with failsafe.js in the page.
APP_ID=$($COMPOSE -f "$FILE" ps -q app)
st=starting
for i in $(seq 1 60); do
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$APP_ID" 2>/dev/null || echo missing)
  [ "$st" = healthy ] && break
  sleep 2
done
if [ "$st" != healthy ]; then
  echo "✗ The app did not become healthy within 120s (status: $st). Logs:"
  docker logs --tail 30 "$APP_ID" 2>/dev/null || true
  if [ -x ./rollback.sh ] && [ -s .prev-image ]; then
    echo "→ Rollback automat la $(cat .prev-image)…"
    exec ./rollback.sh
  fi
  echo "  (no .prev-image — roll back by hand: point WEBTERM_IMAGE in .env at a good tag and rerun)"
  exit 1
fi

echo
echo "✓ WebTerm is running at  https://$WEBTERM_DOMAIN"
echo "  The first login needs the setup token: ${WEBTERM_SETUP_TOKEN:-<see .env>}"
echo "  The Let's Encrypt certificate is issued automatically on first access (may take ~30s)."
