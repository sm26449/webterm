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

# R-H1 (recheck PR4): un singur ciclu de viaţă pe instalare — deploy, rollback, upgrade, backup şi
# restore iau acelaşi lacăt (flock pe .deploy.lock din directorul instalării) pe toată rularea; o a
# doua rulare simultană e refuzată, nu pusă la coadă. Copiii îl moştenesc (upgrade.sh → backup.sh /
# deploy.sh, deploy.sh → exec rollback.sh): un fd 9 deja deschis pe ACELAŞI fişier e lacătul
# părintelui (aceeaşi descriere de fişier, deci flock reuşeşte); altfel se deschide şi se ia acum.
lifecycle_lock() {   # lifecycle_lock INSTALL_DIR → returns holding the lock; exits 1 when it is taken
  local f="$1/.deploy.lock" have want
  command -v flock >/dev/null 2>&1 || {
    echo "✗ flock (util-linux) is missing — refusing to run without the lifecycle lock." >&2; exit 1; }
  if [ -e "/proc/$$/fd/9" ] && [ -f "$f" ]; then
    have=$(stat -L -c '%d:%i' "/proc/$$/fd/9" 2>/dev/null || true)
    want=$(stat -c '%d:%i' "$f" 2>/dev/null || true)
    if [ -n "$have" ] && [ "$have" = "$want" ] && flock -n 9; then return 0; fi
  fi
  ( umask 077; : >>"$f" ) 2>/dev/null || {
    echo "✗ cannot create the lifecycle lock $f — refusing." >&2; exit 1; }
  exec 9>>"$f"
  flock -n 9 || {
    echo "✗ another deploy / rollback / upgrade / backup / restore of this installation is running" >&2
    echo "  (it holds $f) — refusing. Wait for it to finish, then run this again." >&2
    exit 1; }
}
lifecycle_lock "$PWD"

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

# 3.8 (M4, recenzia PR4): are acest proiect deja un volum de date? Numele EFECTIV vine din
# `docker compose config` (o suprascriere `name:` a volumului sau a proiectului contează), iar
# „none" înseamnă ABSENŢĂ CONFIRMATĂ: lista volumelor a reuşit şi numele nu e în ea. O eroare
# Docker, un nume nerezolvat sau un container app existent = „unknown"/„exists": nicio cheie.
compose_volume_name() {   # compose_volume_name COMPOSE_FILE → name, or "" when compose cannot tell
  docker compose -f "$1" config 2>/dev/null | awk '
    /^volumes:/ { inv = 1; next }
    /^[^ ]/ { inv = 0 }
    inv && /^  webterm-data:/ { inw = 1; next }
    inv && /^  [^ ]/ { inw = 0 }
    inw && /^    name:/ { sub(/^    name: */, ""); gsub(/"/, ""); print; exit }' || true
}
data_volume_state() {   # data_volume_state COMPOSE_FILE → none | exists | unknown
  local vol all cids
  vol=$(compose_volume_name "$1")
  [ -n "$vol" ] || { echo unknown; return 0; }
  all=$(docker volume ls -q 2>/dev/null) || { echo unknown; return 0; }
  if printf '%s\n' "$all" | grep -qxF "$vol"; then echo exists; return 0; fi
  # un container app al proiectului (chiar oprit) = instalare existentă, oricum ar arăta volumul
  cids=$(docker compose -f "$1" ps -a -q app 2>/dev/null) || { echo unknown; return 0; }
  [ -z "$cids" ] || { echo exists; return 0; }
  echo none
}

# --- master key (3.8, encryption at rest; docs/INSTALL.md → Encryption at rest) ---------------
# ONLY for a brand-new installation: no data volume yet, no key file, nothing configured. An
# existing installation (upgrade.sh runs this script too) always has its volume, so it never gets
# a key here: it stays legacy until the operator opts in. Dir 0700 + file 0400, owned by 10001
# (the app's user; the key reader refuses a file readable by group/others).
MK_DIR="$SECRETS_DIR/master-key"
# M4: „nou" = volumul confirmat absent (numele efectiv din compose config, `docker volume ls` reuşit)
# şi niciun container app al proiectului; orice eroare Docker lasă instalarea fără cheie nouă.
if [ ! -f "$MK_DIR/master.key" ] && [ -z "${WEBTERM_MASTER_KEY_FILE:-}" ] && [ -z "${WEBTERM_KEY_IN_VOLUME:-}" ] \
   && [ -z "${WEBTERM_MASTER_KEY:-}" ] && [ "$(data_volume_state docker-compose.prod.yml)" = none ]; then
  install -d -m 0700 -o 10001 -g 10001 "$MK_DIR"
  head -c 32 /dev/urandom | base64 | install -m 0400 -o 10001 -g 10001 /dev/stdin "$MK_DIR/master.key"
  set_env WEBTERM_MASTER_KEY_FILE /run/webterm-key/master.key
  export WEBTERM_MASTER_KEY_FILE=/run/webterm-key/master.key
  echo "→ master key created: secrets/master-key/master.key — copy it OFF this machine (without it,"
  echo "  this installation's backups cannot be restored)."
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
# ── 3.8: graniţa migrării la criptarea la repaus (H1, recenzia PR4; R-H1, recheck) ──────────
# Un volum migrat (keys.wtk, migrating.wtm, master.key, nume rezervate `.wt*`, seturi de restore
# 3.8) nu poate fi pornit de o imagine mai veche de 3.8: ea nu vede `data/secret`, îşi poate crea
# unul nou lângă keys.wtk, iar 3.8 refuză apoi volumul amestecat. Deci orice pornire a unei imagini
# < 3.8 (deploy, rollback automat sau manual, upgrade.sh spre o versiune veche) verifică întâi
# volumul. Imaginea ≥ 3.8 nu cere nimic. Orice îndoială = refuz, cu instrucţiunile de recuperare.
# R-H1: volumul verificat e cel pe care compose îl va MONTA — planul din `docker compose config
# --format json` (serviciul app, ţinta /data: volum cu numele efectiv sau bind), nu containerul
# vechi şi nu un WEBTERM_VOLUME care nu schimbă compose. Un override divergent, un container vechi
# pe altă montare, o montare necunoscută sau un config neparsabil = refuz. Apelantul re-verifică
# planul chiar înainte de `up` (guard_recheck), sub lacătul de lifecycle.
# RC-H1 (al doilea recheck): planul modelează DOAR un volum numit montat întreg sau un bind simplu.
# `volume.subpath` (compose montează un SUBDIRECTOR, noi am lista rădăcina), opţiunile de montare
# nemodelate (propagare/selinux nedefault, consistency, read_only) şi un volum cu driver_opts care
# îi schimbă dispozitivul (device / o=bind: dacă volumul nu există încă, compose l-ar crea peste un
# director pe care nu l-am listat) = refuz explicit. Totul rulează pe ID-ul imaginii verificate,
# iar re-verificarea cere ca imaginea din ACELAŞI plan (services.app.image) să aibă acelaşi ID
# (un pull care re-indică tag-ul între verificare şi `up` = refuz). Un bind se listează pe gazdă,
# deci doar cu un daemon local (socket unix); un context Docker remote ar lista alt filesystem.
image_era() {   # image_era IMAGE → 38 | pre38 | unknown
  local v
  v=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$1" 2>/dev/null) \
    || { echo unknown; return 0; }
  v=${v#v}
  if [[ "$v" =~ ^([0-9]+)\.([0-9]+)\. ]]; then
    if [ "${BASH_REMATCH[1]}" -gt 3 ] || { [ "${BASH_REMATCH[1]}" = 3 ] && [ "${BASH_REMATCH[2]}" -ge 8 ]; }; then
      echo 38
    else
      echo pre38
    fi
    return 0
  fi
  # R-H1: fără etichetă de versiune (imagine construită local) nu ghicim după fişiere din imagine:
  # doar operatorul o poate declara 3.8, explicit, pentru rularea respectivă
  if [ "${WEBTERM_IMAGE_ERA:-}" = 3.8 ]; then echo 38; else echo unknown; fi
}
# Programul care citeşte planul compose (stdin: `docker compose config --format json`); rulează în
# imaginea ţintă, fără reţea. Ieşire: „image<TAB>services.app.image" pe prima linie, apoi
# „volume<TAB>nume", „bind<TAB>cale" sau „unknown<TAB>motiv".
COMPOSE_PLAN_PY='# wt-compose-plan (R-H1, RC-H1)
import json, sys
def out(*f):
    print("\t".join(f))
    sys.exit(0)
def bad(s):
    return not isinstance(s, str) or not s or any(ch in s for ch in "\t\n\r")
try:
    c = json.load(sys.stdin)
    app = c["services"]["app"]
    assert isinstance(app, dict)
except (ValueError, KeyError, TypeError, AssertionError):
    print("image\t")
    out("unknown", "no service app in the compose config")
img = app.get("image")
print("image\t" + ("" if bad(img) else img))
if app.get("volumes_from"):
    out("unknown", "service app uses volumes_from")
def tgt(t):
    t = str(t or "")
    return t.rstrip("/") or t
vols = [m for m in (app.get("volumes") or []) if isinstance(m, dict)]
if len(vols) != len(app.get("volumes") or []):
    out("unknown", "a volume of service app is not in the long form")
at = [m for m in vols if tgt(m.get("target")) == "/data"]
under = [m for m in vols if tgt(m.get("target")).startswith("/data/")]
tmpfs = app.get("tmpfs") or []
tmpfs = [tmpfs] if isinstance(tmpfs, str) else tmpfs
tmp = [t for t in tmpfs if tgt(str(t).split(":")[0]) in ("/data",) or str(t).startswith("/data/")]
if len(at) != 1 or under or tmp:
    out("unknown", "service app does not have exactly one plain mount at /data")
m = at[0]
def keys(d, allowed, what):
    if d is None:
        return {}
    if not isinstance(d, dict):
        out("unknown", "the %s of the /data mount cannot be read" % what)
    extra = sorted(str(k) for k in d if k not in allowed)
    if extra:
        out("unknown", "the /data mount uses %s options that are not checked (%s)" % (what, ", ".join(extra)))
    return d
keys(m, ("type", "source", "target", "volume", "bind", "read_only"), "mount")
if m.get("read_only"):
    out("unknown", "the /data mount is read-only")
typ, src = m.get("type"), m.get("source") or ""
if typ == "volume":
    if m.get("bind"):
        out("unknown", "the /data volume mount carries bind options")
    vo = keys(m.get("volume"), ("nocopy", "subpath"), "volume")
    if "subpath" in vo:
        out("unknown", "the /data mount uses volume.subpath (a subdirectory of the volume is not checked)")
    v = (c.get("volumes") or {}).get(src)
    name = v.get("name") if isinstance(v, dict) else None
    if bad(src) or bad(name):
        out("unknown", "the /data volume has no resolvable name")
    keys(v, ("name", "external", "labels", "driver", "driver_opts"), "volume definition")
    do = v.get("driver_opts") or {}
    if not isinstance(do, dict):
        out("unknown", "the driver_opts of the /data volume cannot be read")
    if "device" in do or {"bind", "rbind"} & {s.strip() for s in str(do.get("o") or "").split(",")}:
        out("unknown", "the /data volume has driver_opts that change its device (device / o=bind)")
    out("volume", name)
if typ == "bind" and not bad(src) and src.startswith("/"):
    if m.get("volume"):
        out("unknown", "the /data bind mount carries volume options")
    bo = keys(m.get("bind"), ("create_host_path", "propagation", "selinux"), "bind")
    if bo.get("propagation") not in (None, "", "rprivate") or bo.get("selinux"):
        out("unknown", "the /data bind mount uses a non-default propagation or selinux option")
    out("bind", src)
out("unknown", "the /data mount is of type %s" % typ)
'
DATA_PLAN="" PLAN_ERR="" DATA_IMG="" GUARD_PLAN="" GUARD_ID="" GUARD_ERA=""
data_plan() {   # data_plan COMPOSE_FILE IMAGE → 0 + DATA_PLAN ("volume<TAB>name" | "bind<TAB>/path"); 1 + PLAN_ERR
  # DATA_IMG = services.app.image din ACELAŞI plan („" dacă nu se poate citi)
  local cfg out verdict
  DATA_PLAN="" PLAN_ERR="" DATA_IMG=""
  cfg=$(docker compose -f "$1" config --format json 2>/dev/null) \
    || { PLAN_ERR="docker compose config --format json failed"; return 1; }
  out=$(printf '%s' "$cfg" | docker run --rm -i --network none --entrypoint python3 "$2" -I -c "$COMPOSE_PLAN_PY" 2>/dev/null) \
    || { PLAN_ERR="the compose config could not be read"; return 1; }
  case "$out" in
    image$'\t'*$'\n'*) DATA_IMG=${out%%$'\n'*}; DATA_IMG=${DATA_IMG#image$'\t'}; verdict=${out#*$'\n'} ;;
    *) PLAN_ERR="the compose config could not be read"; return 1 ;;
  esac
  case "$verdict" in
    *$'\n'*) ;;
    volume$'\t'?*|bind$'\t'/*) DATA_PLAN="$verdict"; return 0 ;;
    unknown$'\t'*) PLAN_ERR="${verdict#unknown$'\t'}"; return 1 ;;
  esac
  PLAN_ERR="the compose config could not be read"
  return 1
}
docker_is_local() {   # 0 = daemonul e atins printr-un socket unix local (contextul curent, DOCKER_HOST inclus)
  local h
  h=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null) || return 1
  case "$h" in unix:///*) return 0 ;; esac
  return 1
}
volume_38_markers() {   # volume_38_markers TYPE SOURCE IMAGE → names on stdout; 0 listed, 2 confirmed absent, 1 error
  local all ls
  if [ "$1" = bind ]; then
    # un bind e un director al gazdei: îl listăm direct (lipsă = nimic de protejat; compose îl creează gol)
    [ -e "$2" ] || [ -L "$2" ] || return 2
    { [ -d "$2" ] && [ ! -L "$2" ]; } || return 1
    ls=$(ls -A1 -- "$2") || return 1
  else
    all=$(docker volume ls -q) || return 1
    printf '%s\n' "$all" | grep -qxF "$2" || return 2
    ls=$(docker run --rm --network none -v "$2:/data:ro" --entrypoint ls "$3" -A1 /data) || return 1
  fi
  printf '%s\n' "$ls" | grep -E '^(keys\.wtk.*|migrating\.wtm.*|master\.key.*|erasures\.wtj|\.restore|restore-pending\..+|.*\.wt[a-z0-9]*)$' || true
}
guard_pre38() {   # guard_pre38 IMAGE COMPOSE_FILE → 0 may start (GUARD_PLAN, GUARD_ID, GUARD_ERA); 1 refused
  local era marks rc=0 typ src cids cid m id
  GUARD_PLAN="" GUARD_ID="" GUARD_ERA=""
  # RC-H1: eticheta, cititorul planului şi listarea volumului rulează pe ID-ul imaginii, nu pe un
  # tag pe care un pull îl poate re-indica între paşi; o imagine absentă nu e trasă pe tăcute aici
  id=$(docker image inspect --format '{{.Id}}' "$1" 2>/dev/null) || id=""
  if [ -z "$id" ] || [[ "$id" == *[[:space:]]* ]]; then
    echo "✗ Refusing to start $1: the image is not present locally, so it cannot be checked for the 3.8" >&2
    echo "  encryption-at-rest migration. Pull it first (docker pull $1), then run this again." >&2
    return 1
  fi
  era=$(image_era "$id")
  GUARD_ERA=$era
  if [ "$era" = 38 ]; then GUARD_ID=$id; return 0; fi
  if ! data_plan "$2" "$id"; then
    echo "✗ Refusing to start $1: it is not a 3.8 image (${era}) and the /data mount compose would start" >&2
    echo "  cannot be determined or is not supported ($PLAN_ERR), so it cannot be checked for the 3.8" >&2
    echo "  encryption-at-rest migration." >&2
    echo "  Nothing was changed. Only a whole named volume or a plain bind mount at /data is" >&2
    echo "  checked (no volume.subpath, no driver_opts device, default mount options). An image built" >&2
    echo "  locally without a version label can be declared 3.8 explicitly for one run:" >&2
    echo "  WEBTERM_IMAGE_ERA=3.8 $0 …" >&2
    return 1
  fi
  typ=${DATA_PLAN%%$'\t'*} src=${DATA_PLAN#*$'\t'}
  if [ -n "${WEBTERM_VOLUME:-}" ] && { [ "$typ" != volume ] || [ "$WEBTERM_VOLUME" != "$src" ]; }; then
    echo "✗ Refusing to start $1 (${era}): WEBTERM_VOLUME=$WEBTERM_VOLUME, but compose would mount $typ '$src'" >&2
    echo "  at /data. WEBTERM_VOLUME does not change what compose mounts: unset it, or change the compose" >&2
    echo "  file. Nothing was changed." >&2
    return 1
  fi
  if [ "$typ" = bind ] && ! docker_is_local; then
    echo "✗ Refusing to start $1 (${era}): /data is a bind mount ('$src') and Docker is reached through a" >&2
    echo "  remote context or DOCKER_HOST, so this host's directory may not be the one the daemon mounts." >&2
    echo "  Run this on the Docker host itself (local unix socket). Nothing was changed." >&2
    return 1
  fi
  cids=$(docker compose -f "$2" ps -a -q app 2>/dev/null) || {
    echo "✗ Refusing to start $1 (${era}): docker compose ps failed — the existing app container cannot be" >&2
    echo "  compared with the compose plan. Nothing was changed." >&2
    return 1; }
  for cid in $cids; do
    m=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{"\t"}}{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}' "$cid" 2>/dev/null) || m="?"
    if [ "$m" != "$DATA_PLAN" ]; then
      echo "✗ Refusing to start $1 (${era}): the existing app container $cid mounts '${m:-nothing}' at /data," >&2
      echo "  but compose would now mount $typ '$src'. A remapped data mount is not checked on a downgrade:" >&2
      echo "  check both, then remove the old container (docker compose -f $2 rm -sf app) or restore the mapping." >&2
      return 1
    fi
  done
  marks=$(volume_38_markers "$typ" "$src" "$id") || rc=$?
  if [ "$rc" = 2 ]; then GUARD_PLAN="$DATA_PLAN" GUARD_ID=$id; return 0; fi
  if [ "$rc" != 0 ]; then
    echo "✗ Refusing to start $1 (${era}): the data $typ '$src' could not be inspected for the 3.8" >&2
    echo "  encryption-at-rest migration (Docker error). Nothing was changed." >&2
    return 1
  fi
  if [ -z "$marks" ]; then GUARD_PLAN="$DATA_PLAN" GUARD_ID=$id; return 0; fi
  echo "✗ Refusing to start $1: the data $typ '$src' was migrated to 3.8 encryption at rest" >&2
  echo "  ($(printf '%s' "$marks" | tr '\n' ' '| sed 's/ $//')), and this image is $([ "$era" = pre38 ] && echo "older than 3.8" || echo "of an unknown version")." >&2
  echo "  A pre-3.8 gateway cannot read that volume: it would create a new vault key next to the" >&2
  echo "  protected one, and 3.8 then refuses the mixed volume. Nothing was changed." >&2
  echo "  Either stay on 3.8 (fix forward: ./deploy.sh <a 3.8.x version>), or go back to 3.7 the only" >&2
  echo "  safe way: restore the backup taken BEFORE the migration into a new volume" >&2
  echo "  (docs/INSTALL.md → Encryption at rest, \"Going back to 3.7\")." >&2
  return 1
}
guard_recheck() {   # guard_recheck IMAGE COMPOSE_FILE PLAN IMAGE_ID → 0 the same plan and image still hold; 1 refused
  # R-H1: chiar înainte de `up`: aceeaşi verificare, iar planul trebuie să fie EXACT cel verificat
  local want="$3" want_id="$4" run_id=""
  guard_pre38 "$1" "$2" || return 1
  if [ -z "$want_id" ] || [ "$GUARD_ID" != "$want_id" ]; then
    echo "✗ Refusing to start $1: the image changed since it was checked ('${want_id:-?}' → '$GUARD_ID')," >&2
    echo "  e.g. a pull re-pointed the tag. Nothing was started; run this again." >&2
    return 1
  fi
  if [ "$GUARD_PLAN" != "$want" ]; then
    echo "✗ Refusing to start $1: the /data mount compose would start changed since it was checked" >&2
    echo "  ('${want:-3.8 image}' → '${GUARD_PLAN:-3.8 image}'). Nothing was started; run this again." >&2
    return 1
  fi
  # RC-H1: imaginea pe care o porneşte compose (services.app.image din acelaşi plan JSON) trebuie să
  # fie chiar cea verificată, ca ID; pentru o imagine 3.8 planul se citeşte acum doar pentru asta
  [ "$GUARD_ERA" = 38 ] && { data_plan "$2" "$GUARD_ID" || true; }
  [ -n "$DATA_IMG" ] && run_id=$(docker image inspect --format '{{.Id}}' "$DATA_IMG" 2>/dev/null) || run_id=""
  if [ -z "$run_id" ] || [ "$run_id" != "$GUARD_ID" ]; then
    echo "✗ Refusing to start $1: compose would start image '${DATA_IMG:-?}', which is not the image that was" >&2
    echo "  checked ($1). Point WEBTERM_IMAGE / the compose file at the same image. Nothing was started." >&2
    return 1
  fi
  return 0
}
# imaginea pe care compose o va porni: WEBTERM_IMAGE, altfel default-ul din compose
TARGET_IMG="${WEBTERM_IMAGE:-}"
if [ -z "$TARGET_IMG" ]; then
  TARGET_IMG=$($COMPOSE -f "$FILE" config --images 2>/dev/null | grep -m1 -E '/webterm[:@]' || true)
fi
if [ -n "$TARGET_IMG" ]; then
  # R-H1: verificarea e chiar înaintea lui `up`, sub lacătul de lifecycle; nimic nu rulează între ele
  # RC-H1: şi imaginea din planul compose (services.app.image) e exact cea verificată, ca ID
  guard_pre38 "$TARGET_IMG" "$FILE" || exit 1
  guard_recheck "$TARGET_IMG" "$FILE" "$GUARD_PLAN" "$GUARD_ID" || exit 1
else
  echo "✗ cannot tell which image would start (WEBTERM_IMAGE is empty and compose lists none) — refusing." >&2
  exit 1
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
# FL-12 (audit 2026-10-17): run by an upgrade.sh older than 3.6.9? That script syncs THIS file from
# the new kit and executes it while its own replacement still waits as upgrade.sh.new (moved into
# place only at its very end) — the one moment new code runs inside that old run. The new upgrade.sh
# mv's .new away before its re-exec, so a ≥3.6.9 run never has it here.
if [ -f upgrade.sh.new ] && ! grep -q WEBTERM_UPGRADE_REEXEC upgrade.sh 2>/dev/null; then
  echo "  ! this upgrade was run by an upgrade.sh older than 3.6.9 — the host kit (host-health, cert-renew," >&2
  echo "  ! docker-cleanup, authentik-upgrade + timers) is NOT synced yet: run ./upgrade.sh once more after" >&2
  echo "  ! it finishes (docs/INSTALL.md, \"Upgrading from a version before 3.6.9\")" >&2
fi
# Tokenul de setup se tipăreşte DOAR cât timp mai foloseşte la ceva. Odată creat contul,
# `/api/setup` întoarce 409 şi tokenul e inert — dar afişat la fiecare upgrade arăta a
# credenţial viu, invitând pe cineva să-l trateze ca atare (şi să-l copieze pe unde nu
# trebuie). Întrebăm aplicaţia care tocmai a pornit dacă instalarea mai are nevoie de el.
if curl -fsS --max-time 5 "https://$WEBTERM_DOMAIN/api/state" 2>/dev/null | grep -q '"setup_required":[[:space:]]*true'; then
  echo "  The first login needs the setup token: $(secret_read webterm_setup_token) (secrets/webterm_setup_token)"
fi
echo "  The Let's Encrypt certificate is issued automatically on first access (may take ~30s)."
