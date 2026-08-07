#!/usr/bin/env bash
# Verifică certificatul TLS servit de Traefik și alertează înainte să expire.
# Reînnoirea e automată (Traefik, DNS-01, cu ~30 de zile înainte), dar poate eșua
# în tăcere: token Cloudflare revocat, TXT _acme-challenge orfan, zonă mutată.
# Fără o verificare, afli abia când browserul refuză site-ul.
#
#   WEBTERM_DOMAIN       domeniul (obligatoriu; de obicei din .env)
#   WEBTERM_CERT_MIN_DAYS  pragul de alertă în zile (default 15)
#   WEBTERM_ALERT_URL    webhook opțional (POST cu textul alertei; Slack-compatibil)
#
# Iese cu 1 dacă certul e pe cale să expire / lipsește → `systemctl --failed` îl
# arată, iar `systemd` scrie eșecul în jurnal.
set -euo pipefail

DOMAIN="${WEBTERM_DOMAIN:-}"
MIN_DAYS="${WEBTERM_CERT_MIN_DAYS:-15}"
[ -n "$DOMAIN" ] || { echo "WEBTERM_DOMAIN is not set." >&2; exit 2; }

alert() {
  local msg="WebTerm/$DOMAIN: $1"
  echo "$msg" >&2
  command -v logger >/dev/null && logger -t webterm-cert -p daemon.err "$msg" || true
  if [ -n "${WEBTERM_ALERT_URL:-}" ]; then
    curl -fsS -m 10 -X POST -H 'Content-Type: application/json' \
      --data "{\"text\":\"$msg\"}" "$WEBTERM_ALERT_URL" >/dev/null 2>&1 || true
  fi
  exit 1
}

# Interogăm chiar socketul lui Traefik (127.0.0.1), cu SNI-ul domeniului: așa vedem
# ce servește el acum, nu ce a memorat un cache/CDN din fața lui.
CERT=$(echo | openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" 2>/dev/null \
  | openssl x509 -noout -issuer -enddate 2>/dev/null || true)
[ -n "$CERT" ] || alert "nu pot citi certificatul de pe :443 (Traefik e pornit?)"

case "$CERT" in
  *"Let's Encrypt"*) : ;;
  *) alert "se servește certificatul default al lui Traefik — Let's Encrypt nu a emis. Vezi: docker compose -f docker-compose.prod.yml logs traefik | grep -i acme" ;;
esac

END=$(echo "$CERT" | sed -n 's/^notAfter=//p')
LEFT=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))
[ "$LEFT" -ge "$MIN_DAYS" ] || alert "the certificate expires in $LEFT days ($END) — automatic renewal did not succeed."

echo "OK: Let's Encrypt certificate valid for another $LEFT days (expires $END)."
