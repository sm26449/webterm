#!/usr/bin/env bash
# Provisionează aplicaţia OIDC WebTerm în Authentik-ul pornit de docker-compose.prod.yml.
# Rulează din deploy/authentik/, după `docker compose -f docker-compose.prod.yml up -d`.
#
#   ./provision.sh
#
# Citeşte .env (AUTHENTIK_DOMAIN, WEBTERM_DOMAIN, WEBTERM_OIDC_PROVIDER_NAME, şi opţional
# AUTHENTIK_BOOTSTRAP_TOKEN). Dacă nu are un token de API valid, generează unul prin `ak shell`
# în container. La final tipăreşte blocul WEBTERM_OIDC_* pentru .env-ul WebTerm.
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.prod.yml"

# --- încarcă .env fără `source` (fără execuţie de cod din fişier) ---
[ -f .env ] || { echo "lipseşte .env (cp .env.prod.example .env şi completează)" >&2; exit 1; }
while IFS='=' read -r k v; do
  case "$k" in ''|\#*) continue;; esac
  k="${k%%[[:space:]]}"; v="${v%$'\r'}"
  export "$k=$v"
done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' .env)

: "${AUTHENTIK_DOMAIN:?setează AUTHENTIK_DOMAIN în .env}"
: "${WEBTERM_DOMAIN:?setează WEBTERM_DOMAIN în .env}"

# --- asigură un token de API valid ---
TOKEN="${AUTHENTIK_API_TOKEN:-${AUTHENTIK_BOOTSTRAP_TOKEN:-}}"
token_ok() {
  [ -n "$TOKEN" ] || return 1
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
    "https://$AUTHENTIK_DOMAIN/api/v3/core/users/me/" || echo 000)
  [ "$code" = "200" ]
}
if ! token_ok; then
  echo "generez un token de API pentru akadmin (ak shell)…" >&2
  TOKEN=$($COMPOSE exec -T worker ak shell -c "
from authentik.core.models import Token, User, TokenIntents
u=User.objects.get(username='akadmin')
Token.objects.filter(identifier='webterm-provision').delete()
t=Token.objects.create(user=u, identifier='webterm-provision', intent=TokenIntents.INTENT_API, expiring=False, description='WebTerm OIDC provisioning')
print('TOKEN='+t.key)
" 2>/dev/null | sed -n 's/^TOKEN=//p' | tr -d '\r')
  [ -n "$TOKEN" ] || { echo "nu am putut genera tokenul (e stack-ul pornit?)" >&2; exit 1; }
fi

export AUTHENTIK_API_TOKEN="$TOKEN"
exec python3 provision.py
