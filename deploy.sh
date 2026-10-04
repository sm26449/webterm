#!/usr/bin/env bash
# WebTerm — production deploy from a pre-built ghcr image, with Traefik/SSL.
# One command:  ./deploy.sh [vX.Y.Z | ghcr.io/…/webterm@sha256:… | sha256:…] [--tag vX.Y.Z]
#   - creates .env from the example on first run
#   - creates secrets/ (setup token, OIDC secret, SMTP password, CF token, Authentik keys)
#     and MOVES any such value still sitting in .env into its file
#   - generates the setup token if missing
#   - logs in to ghcr.io (private image) and pulls the latest image
#   - starts or updates the stack (Traefik issues the Let's Encrypt certificate)
# With an argument (./deploy.sh v2.0.18, or a digest from upgrade.sh): pins the image in .env,
# remembers the previous image in .prev-image and, if the new container does not become
# healthy within 120s, ROLLS BACK to it automatically (./rollback.sh also works on its own).
# Without an argument: the image from .env, or :latest — same guard and rollback.
# `--tag vX.Y.Z` is the human label stored next to a digest pin (WEBTERM_IMAGE_TAG, shown in
# the UI); upgrade.sh passes it. It never changes WHICH image is deployed.
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

cd "$(dirname "$0")"

# --with-authentik: porneşte şi Authentik (SSO) în acelaşi stack (profilul compose `authentik`),
# generând secretele unic la acest deploy. Un tag de versiune (vX.Y.Z) rămâne argument poziţional.
WITH_AUTHENTIK=""
VERSION=""
TAG_HINT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --with-authentik) WITH_AUTHENTIK=1; shift ;;
    --tag) TAG_HINT="${2:-}"; shift 2 ;;
    --tag=*) TAG_HINT="${1#--tag=}"; shift ;;
    --*) echo "unknown flag: $1" >&2; exit 1 ;;
    *) VERSION="$1"; shift ;;
  esac
done

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
load_env ./.env
: "${WEBTERM_DOMAIN:?set WEBTERM_DOMAIN in .env}"
: "${LETSENCRYPT_EMAIL:?set LETSENCRYPT_EMAIL in .env}"

# set_env KEY VALUE — rewrites `.env` in-process, with bash builtins only.
# Two bugs in one fix (auditul de deploy, L1 + L2). The old
# `grep -q && sed -i "s|^K=.*|K=$V|" || printf >>` (a) let sed interpret `&`, `|` and `\`
# inside the value — the OIDC client secret from provision.py goes through here, and a `&`
# in it was silently replaced by the matched text: SSO dead, no message; (b) put the secret
# in sed's argv, i.e. in /proc/<pid>/cmdline, readable by every user on the host for the
# duration of the call. A read/print loop has neither problem: nothing is interpreted and no
# process other than this shell ever sees the value. mktemp in the same directory → atomic mv.
set_env() {
  local k="$1" v="$2" tmp found=0 line
  tmp=$(mktemp .env.XXXXXX)
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$k="*) [ "$found" = 1 ] && continue; printf '%s=%s\n' "$k" "$v"; found=1 ;;
      *) printf '%s\n' "$line" ;;
    esac
  done < .env > "$tmp"
  [ "$found" = 1 ] || printf '%s=%s\n' "$k" "$v" >> "$tmp"
  chmod 600 "$tmp" && mv "$tmp" .env
}

# curl with a bearer token WITHOUT the token in argv. `-H "Authorization: Bearer $T"` shows
# the token in `ps`/`/proc/<pid>/cmdline` to every local user for the whole call — here in a
# loop of up to six minutes while Authentik boots. `-K -` reads options from stdin instead.
curl_bearer() {   # curl_bearer TOKEN [curl args…]
  local t="$1"; shift
  printf 'header = "Authorization: Bearer %s"\n' "$t" | curl -K - "$@"
}

# --- secrets/: files instead of environment (auditul de deploy, M1) ---------------------------
# Traefik reads container metadata through docker-socket-proxy (`CONTAINERS=1`, the minimum
# its docker provider works with). That metadata includes every container's `Config.Env`, so
# a compromised Traefik — the one process exposed to the internet — could read the setup token,
# the OIDC client secret, the SMTP password and the Authentik keys without touching a volume.
# The compose file now mounts them from `secrets/<name>` (bind, read-only, /run/secrets); only
# the path appears in the environment. Rules:
#   · every file must EXIST, even empty: Docker refuses to start a container whose bind source
#     is missing, and compose has no "optional" secret. Empty = unset (config.py, lego).
#   · dir 0700 root, files 0644: compose ignores uid/mode for file secrets (verified on Compose
#     v5), the mount keeps host ownership, and the gateway runs as uid 10001, Postgres as 70,
#     Authentik as 1000. The directory, not the file, is what keeps other host users out.
#   · a value still in .env is MOVED here and the .env line blanked (`${X:-}` fallback stays
#     for hand-written files, but a value there would land in Config.Env again).
SECRETS_DIR="$PWD/secrets"
secret_file() { printf '%s/%s' "$SECRETS_DIR" "$1"; }
secret_read() { tr -d '\r\n' < "$(secret_file "$1")" 2>/dev/null || true; }
secret_write() {   # secret_write NAME VALUE — printf is a builtin: the value never hits argv
  umask 022
  printf '%s\n' "$2" > "$(secret_file "$1")"
  chmod 644 "$(secret_file "$1")"
}
# migrate_secret ENV_VAR NAME — .env value → secrets/NAME, then blank the .env line and the
# exported variable (compose prefers the shell environment over .env, and load_env exported it).
migrate_secret() {
  local var="$1" name="$2" cur
  eval "cur=\${$var:-}"
  [ -n "$cur" ] || return 0
  if [ -n "$(secret_read "$name")" ] && [ "$(secret_read "$name")" != "$cur" ]; then
    echo "→ $var is set in both .env and secrets/$name — keeping the .env value (it was the one in use); the file is the source of truth from now on"
  fi
  secret_write "$name" "$cur"
  set_env "$var" ""
  export "$var="
  echo "→ moved $var from .env to secrets/$name (.env line blanked)"
}
mkdir -p "$SECRETS_DIR" && chmod 700 "$SECRETS_DIR"
for _n in webterm_setup_token webterm_oidc_client_secret webterm_smtp_password cf_dns_api_token \
          authentik_secret_key pg_pass authentik_bootstrap_password authentik_bootstrap_token; do
  [ -f "$(secret_file "$_n")" ] || secret_write "$_n" ""
  chmod 644 "$(secret_file "$_n")"
done
migrate_secret WEBTERM_SETUP_TOKEN        webterm_setup_token
migrate_secret WEBTERM_OIDC_CLIENT_SECRET webterm_oidc_client_secret
migrate_secret WEBTERM_SMTP_PASSWORD      webterm_smtp_password
migrate_secret CF_DNS_API_TOKEN           cf_dns_api_token
migrate_secret AUTHENTIK_SECRET_KEY       authentik_secret_key
migrate_secret PG_PASS                    pg_pass
migrate_secret AUTHENTIK_BOOTSTRAP_PASSWORD authentik_bootstrap_password
migrate_secret AUTHENTIK_BOOTSTRAP_TOKEN  authentik_bootstrap_token

# CF_DNS_API_TOKEN e OPŢIONAL: fără el, Traefik ia certificatul prin HTTP-01, care nu are
# nevoie de niciun provider DNS. Cerinţa lui obligatorie bloca orice instalare fără cont
# Cloudflare, deşi Let's Encrypt nu cere aşa ceva.
# Etichetele de certificat: `install.sh` le scrie, `deploy.sh` nu le scria deloc — deşi
# `.env.prod.example` afirmă că le scriu amândouă. Cine urma calea „cp .env.prod.example .env
# + ./deploy.sh" rămânea pe HTTP-01 chiar dacă adăuga ulterior un token Cloudflare.
FWD_DOM="${FORWARD_DOMAIN:-$WEBTERM_DOMAIN}"
if [ -n "$(secret_read cf_dns_api_token)" ]; then
  set_env WEBTERM_CERT_RESOLVER "ledns"
  set_env WEBTERM_CERT_LABEL_MAIN "traefik.http.routers.webterm.tls.domains[0].main=$WEBTERM_DOMAIN"
  set_env WEBTERM_CERT_LABEL_SANS "traefik.http.routers.webterm.tls.domains[0].sans=*.$WEBTERM_DOMAIN"
  set_env WEBTERM_CERT_LABEL_FWD_MAIN "traefik.http.routers.webterm-fwd.tls.domains[0].main=$FWD_DOM"
  set_env WEBTERM_CERT_LABEL_FWD_SANS "traefik.http.routers.webterm-fwd.tls.domains[0].sans=*.$FWD_DOM"
else
  set_env WEBTERM_CERT_RESOLVER "le"
  set_env WEBTERM_CERT_LABEL_MAIN ""
  set_env WEBTERM_CERT_LABEL_SANS ""
  set_env WEBTERM_CERT_LABEL_FWD_MAIN ""
  set_env WEBTERM_CERT_LABEL_FWD_SANS ""
  echo "  no Cloudflare token (secrets/cf_dns_api_token) — using HTTP-01 (needs $WEBTERM_DOMAIN to resolve here and port 80 reachable)"
  echo "  note: port-forward subdomains need a wildcard certificate, which only DNS-01 can issue —"
  echo "        forwards will not get TLS on this path. Add a Cloudflare token if you use them."
fi
load_env ./.env

# --- setup token (generated once, persisted in secrets/webterm_setup_token) ---
if [ -z "$(secret_read webterm_setup_token)" ]; then
  secret_write webterm_setup_token "$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | cut -c1-32)"
  echo "→ Setup token generated and written to secrets/webterm_setup_token."
fi

# --- optional bundled Authentik (SSO) ---
# --with-authentik (sau COMPOSE_PROFILES=authentik deja în .env) porneşte Authentik în acelaşi
# stack. Generăm secretele lipsă unic la ACEST deploy — niciodată copiate între instalări.
gen_secret() { head -c 48 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | cut -c1-50; }
if [ -n "$WITH_AUTHENTIK" ] || printf '%s' "${COMPOSE_PROFILES:-}" | grep -qw authentik; then
  set_env COMPOSE_PROFILES "authentik"
  export COMPOSE_PROFILES="authentik"
  : "${AUTHENTIK_DOMAIN:?set AUTHENTIK_DOMAIN in .env — the subdomain Authentik answers on (needs its own DNS record)}"
  for _n in authentik_secret_key pg_pass authentik_bootstrap_password authentik_bootstrap_token; do
    if [ -z "$(secret_read "$_n")" ]; then
      secret_write "$_n" "$(gen_secret)"
      echo "→ generated secrets/$_n (unique to this deploy)"
    fi
  done
  echo "→ Authentik profile active — it will start with the stack at https://$AUTHENTIK_DOMAIN"
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
BASE="ghcr.io/${GHCR_USER:-sm26449}/webterm"
CUR_IMAGE="${WEBTERM_IMAGE:-}"
CUR_TAG="${WEBTERM_IMAGE_TAG:-}"
if [ -n "$VERSION" ]; then
  # Validated with anchored regexes BEFORE anything is written: a newline or shell metacharacter
  # in the argument must not be able to inject a line into .env. Accepted:
  #   vX.Y.Z | latest | sha-<hex>          → a TAG on the default repo (mutable in the registry)
  #   sha256:<64 hex>                      → a DIGEST on the default repo (immutable)
  #   ghcr.io/<owner>/webterm@sha256:<hex> → full digest reference (what upgrade.sh passes:
  #                                          the tag was resolved ONCE and this is the exact
  #                                          image whose deploy-kit was just synced to the host)
  #   ghcr.io/<owner>/webterm:vX.Y.Z       → full tag reference
  # Digests used to be REFUSED here ("Invalid tag"), which forced every deploy onto a mutable
  # tag — and tags have been re-pointed in this project's history (auditul de deploy, H1).
  HEX64='[0-9a-f]{64}'
  TAGRE='(v[0-9]+\.[0-9]+\.[0-9]+|latest|sha-[0-9a-f]+)'
  NEW_TAG=""
  if   [[ "$VERSION" =~ ^${TAGRE}$ ]]; then NEW_IMAGE="$BASE:$VERSION"; NEW_TAG="$NEW_IMAGE"
  elif [[ "$VERSION" =~ ^sha256:${HEX64}$ ]]; then NEW_IMAGE="$BASE@$VERSION"
  elif [[ "$VERSION" =~ ^ghcr\.io/[A-Za-z0-9._-]+/webterm@sha256:${HEX64}$ ]]; then NEW_IMAGE="$VERSION"
  elif [[ "$VERSION" =~ ^ghcr\.io/[A-Za-z0-9._-]+/webterm:${TAGRE}$ ]]; then NEW_IMAGE="$VERSION"; NEW_TAG="$VERSION"
  else
    echo "Invalid image reference: $VERSION (expected vX.Y.Z, latest, sha-…, sha256:<digest> or ghcr.io/<owner>/webterm@sha256:<digest>)"; exit 1
  fi
  if [ -n "$TAG_HINT" ]; then
    [[ "$TAG_HINT" =~ ^${TAGRE}$ ]] || { echo "Invalid --tag: $TAG_HINT (expected vX.Y.Z)"; exit 1; }
    # the label only makes sense next to a digest; a tag deploy already IS its own label
    case "$NEW_IMAGE" in *@sha256:*) NEW_TAG="${NEW_IMAGE%%@*}:$TAG_HINT" ;; esac
  fi
  set_env WEBTERM_IMAGE "$NEW_IMAGE"
  set_env WEBTERM_IMAGE_TAG "$NEW_TAG"
  export WEBTERM_IMAGE="$NEW_IMAGE" WEBTERM_IMAGE_TAG="$NEW_TAG"
  echo "→ Targeted deploy: $NEW_IMAGE${NEW_TAG:+ ($NEW_TAG)} (previous: ${CUR_IMAGE:-<unset>})"
fi
if [ -n "$CUR_IMAGE" ] && [ "$CUR_IMAGE" != "${WEBTERM_IMAGE:-}" ]; then
  printf '%s\n' "$CUR_IMAGE" > .prev-image
  if [ -n "$CUR_TAG" ]; then printf '%s\n' "$CUR_TAG" > .prev-image-tag; else rm -f .prev-image-tag; fi
fi

# --- pull + up (replaces an older Caddy stack if present, keeps the data) ---
# `pull` eşuat nu e fatal dacă imaginea E DEJA aici: o imagine construită local
# (`wtd4-broken:local`), o instalare air-gapped sau un registry momentan inaccesibil opreau
# deploy-ul înainte de orice, inclusiv rollback-ul manual pe o imagine bună deja trasă.
if ! $COMPOSE -f "$FILE" pull; then
  if docker image inspect "${WEBTERM_IMAGE:-}" >/dev/null 2>&1; then
    echo "→ pull failed, but ${WEBTERM_IMAGE} is already present locally — continuing."
  else
    echo "✗ pull failed and ${WEBTERM_IMAGE:-the image} is not available locally." >&2
    exit 1
  fi
fi
$COMPOSE -f "$FILE" up -d --remove-orphans

# --- health guard and automatic rollback ---
# Prinde imaginile care nu pornesc (crash loop, config stricat). Un frontend
# that only breaks in the browser is NOT visible here — the CI smoke test covers
# that (the image is never published) along with failsafe.js in the page.
APP_ID=$($COMPOSE -f "$FILE" ps -q app)
st=starting
for _ in $(seq 1 60); do
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$APP_ID" 2>/dev/null || echo missing)
  [ "$st" = healthy ] && break
  sleep 2
done
if [ "$st" != healthy ]; then
  echo "✗ The app did not become healthy within 120s (status: $st). Logs:"
  docker logs --tail 30 "$APP_ID" 2>/dev/null || true
  if [ -x ./rollback.sh ] && [ -s .prev-image ]; then
    echo "→ Rollback automat la $(cat .prev-image)…"
    # `exec` moşteneşte mediul, iar noi tocmai am exportat imaginea NOUĂ — care ar fi bătut
    # `.env`-ul rescris de rollback. Îl scoatem explicit, ca rollback-ul să citească fişierul.
    unset WEBTERM_IMAGE WEBTERM_IMAGE_TAG
    exec ./rollback.sh
  fi
  echo "  (no .prev-image — roll back by hand: point WEBTERM_IMAGE in .env at a good tag and rerun)"
  exit 1
fi

# --- auto-provision the OIDC app in the bundled Authentik (idempotent, best-effort) ---
# Rulează doar cu profilul `authentik` activ şi cât timp SSO nu e încă legat. Nu lasă niciodată
# un stack stricat: dacă Authentik nu e gata la timp, WebTerm rămâne pornit şi tipărim comanda.
if { [ -n "$WITH_AUTHENTIK" ] || printf '%s' "${COMPOSE_PROFILES:-}" | grep -qw authentik; } \
   && [ -z "${WEBTERM_OIDC_ISSUER:-}" ]; then
  PROV="deploy/authentik/provision.py"
  AK_TOKEN=$(secret_read authentik_bootstrap_token)
  echo "→ Waiting for Authentik at https://$AUTHENTIK_DOMAIN (first boot runs migrations, ~1-2 min)…"
  ak_ready=""
  for _ in $(seq 1 90); do
    code=$(curl_bearer "$AK_TOKEN" -s -o /dev/null -w '%{http_code}' --max-time 5 \
      "https://$AUTHENTIK_DOMAIN/api/v3/core/users/me/" 2>/dev/null || echo 000)
    [ "$code" = 200 ] && { ak_ready=1; break; }
    sleep 4
  done
  if [ -n "$ak_ready" ] && [ -f "$PROV" ] && command -v python3 >/dev/null; then
    echo "→ Provisioning the WebTerm OIDC application in Authentik…"
    if OUT=$(AUTHENTIK_DOMAIN="$AUTHENTIK_DOMAIN" WEBTERM_DOMAIN="$WEBTERM_DOMAIN" \
             WEBTERM_OIDC_PROVIDER_NAME="${WEBTERM_OIDC_PROVIDER_NAME:-Authentik}" \
             AUTHENTIK_API_TOKEN="$AK_TOKEN" python3 "$PROV" 2>&1); then
      # the client secret goes to its file, the public settings to .env
      while IFS='=' read -r _k _v; do
        case "$_k" in
          WEBTERM_OIDC_CLIENT_SECRET) secret_write webterm_oidc_client_secret "$_v" ;;
          WEBTERM_OIDC_ISSUER|WEBTERM_OIDC_CLIENT_ID|WEBTERM_OIDC_PROVIDER_NAME) set_env "$_k" "$_v" ;;
        esac
      done < <(printf '%s\n' "$OUT" | grep -E '^WEBTERM_OIDC_(ISSUER|CLIENT_ID|CLIENT_SECRET|PROVIDER_NAME)=')
      echo "→ SSO linked; reloading the app to pick up the OIDC settings…"
      load_env ./.env
      $COMPOSE -f "$FILE" up -d app
      echo "  Add users to the 'wt-access' group in Authentik to grant them access to this instance."
    else
      echo "✗ provisioning failed; WebTerm is up, SSO is off. Details:" >&2
      printf '  %s\n' "$OUT" | tail -5 >&2
    fi
  else
    echo "  Authentik not reachable yet (or python3/provision.py missing). WebTerm is up; provision later:"
    echo "    cd $(pwd) && AUTHENTIK_DOMAIN=$AUTHENTIK_DOMAIN WEBTERM_DOMAIN=$WEBTERM_DOMAIN \\"
    echo "      AUTHENTIK_API_TOKEN=\"\$(cat secrets/authentik_bootstrap_token)\" python3 $PROV"
    echo "    then: WEBTERM_OIDC_CLIENT_SECRET → secrets/webterm_oidc_client_secret, the other"
    echo "    WEBTERM_OIDC_* lines → .env, and run: $COMPOSE -f $FILE up -d app"
  fi
fi

echo
echo "✓ WebTerm is running at  https://$WEBTERM_DOMAIN"
echo "  image: ${WEBTERM_IMAGE:-<from compose default>}${WEBTERM_IMAGE_TAG:+ ($WEBTERM_IMAGE_TAG)}"
# Tokenul de setup se tipăreşte DOAR cât timp mai foloseşte la ceva. Odată creat contul,
# `/api/setup` întoarce 409 şi tokenul e inert — dar afişat la fiecare upgrade arăta a
# credenţial viu, invitând pe cineva să-l trateze ca atare (şi să-l copieze pe unde nu
# trebuie). Întrebăm aplicaţia care tocmai a pornit dacă instalarea mai are nevoie de el.
if curl -fsS --max-time 5 "https://$WEBTERM_DOMAIN/api/state" 2>/dev/null | grep -q '"setup_required":[[:space:]]*true'; then
  echo "  The first login needs the setup token: $(secret_read webterm_setup_token) (secrets/webterm_setup_token)"
fi
echo "  The Let's Encrypt certificate is issued automatically on first access (may take ~30s)."
