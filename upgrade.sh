#!/usr/bin/env bash
# WebTerm — a complete upgrade, in one command.
#
#     ./upgrade.sh              → the latest published version
#     ./upgrade.sh v2.0.18       → a specific version (also to go back down)
#     ./upgrade.sh --no-backup  → sare peste backupul de dinainte (nu recomand)
#     ./upgrade.sh -y           → no questions (cron, remote runs)
#     ./upgrade.sh --allow-latest → accept :latest when the version cannot be determined
#     ./upgrade.sh --allow-unpinned → deploy the tag itself if its digest cannot be resolved
#
# Why this exists when deploy.sh already does: `deploy.sh` updates the IMAGE. But half the
# system runs on the HOST, not in the container — backup.sh, restore.sh, the compose file, the
# systemd units. `/opt/webterm` is not a git checkout, so those stayed frozen at whatever the
# installer put there. On one machine that meant a backup.sh from weeks earlier: hardening that
# had shipped long ago was not active, and the nightly archives were written UNENCRYPTED, 644,
# with the vault key inside. An "upgrade" that does not touch the host files is an illusion.
#
# The order is chosen, not accidental:
#   1. resolve the version → know what you are installing before touching anything
#   2. preflight           → fail early and without side effects (auth, disk, files)
#   3. pull                → the artefact is local before anything changes
#   3b. pin + verify       → tag → DIGEST (immutable), optional cosign check; from here on
#                            every step uses the digest, never the tag again
#   4. backup              → the safety net comes BEFORE the change, not after
#   5. sync the host       → from the image you already verified
#   6. deploy.sh           → pin + health check + rollback automat (le are deja)
#   7. final check         → say what is running now, do not assume
#
# Why a digest (auditul de deploy, H1): the host-side kit (deploy.sh, backup.sh, rollback.sh,
# upgrade.sh itself) is copied OUT of the image and runs as root. A tag like `v3.0.1` is a
# moving pointer in the registry — this project has re-pointed tags before — so "the image I
# pulled" and "the image I will run / roll back to" could be different bytes. The digest is
# the content hash of the manifest: `.env` and `.prev-image` record THAT, and a rollback brings
# back exactly what ran. cosign (if installed and configured) additionally answers WHO built it.
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
ROOT="$PWD"

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
# RC4-L1: planurile vechi se curăţă doar dacă lacătul e luat acum (fd 9 neprimit de la un părinte)
WT_RUN_START=$(date +%s); WT_SWEEP=1; [ -e "/proc/$$/fd/9" ] && WT_SWEEP=0
lifecycle_lock "$ROOT"

TARGET=""
DO_BACKUP=1
ASSUME_YES=0
ALLOW_LATEST=0
ALLOW_UNPINNED=0
for arg in "$@"; do
  case "$arg" in
    --no-backup) DO_BACKUP=0 ;;
    --allow-latest) ALLOW_LATEST=1 ;;
    --allow-unpinned) ALLOW_UNPINNED=1 ;;
    -y|--yes)    ASSUME_YES=1 ;;
    -h|--help)   sed -n '2,11p' "$0"; exit 0 ;;
    v[0-9]*.[0-9]*.[0-9]*) TARGET="$arg" ;;
    *) echo "Unknown argument: $arg (expected vX.Y.Z, --no-backup, -y)" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ask() {                                    # ask "question" → 0 = yes
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || return 1                     # non-interactive without -y: the safe answer is NO
  printf '  %s [y/N] ' "$1"; read -r a; case "$a" in [yYdD]*) return 0 ;; *) return 1 ;; esac
}
# curl with a bearer token WITHOUT the token in argv: `-H "Authorization: Bearer $T"` is
# visible in `ps`/`/proc/<pid>/cmdline` to every local user for the duration of the call.
# `-K -` reads the option from stdin, which nobody else can see.
curl_bearer() {   # curl_bearer TOKEN [curl args…]
  local t="$1"; shift
  printf 'header = "Authorization: Bearer %s"\n' "$t" | curl -K - "$@"
}

[ -f .env ] || die "no .env in $ROOT — run ./deploy.sh first"
load_env ./.env
GHCR_USER="${GHCR_USER:-sm26449}"
REPO="${WEBTERM_UPDATE_REPO:-$GHCR_USER/webterm}"
IMAGE_BASE="ghcr.io/$GHCR_USER/webterm"

# ── 1. which version to install ──────────────────────────────────────────────
say "Target version"
if [ -z "$TARGET" ]; then
  # The latest semver tag on GitHub. Public repo → works with nothing; private repo → with the
  # token from .env. If we cannot find out, we do NOT guess: `latest` is a moving pointer and
  # we would no longer know what to roll back to, so we ask for confirmation.
  AUTH_HDR="Accept: application/vnd.github+json"
  TAGS_URL="https://api.github.com/repos/$REPO/tags?per_page=100"
  if [ -n "${GHCR_TOKEN:-}" ]; then
    TAGS=$(curl_bearer "$GHCR_TOKEN" -fsS -H "$AUTH_HDR" "$TAGS_URL" 2>/dev/null || true)
  else
    TAGS=$(curl -fsS -H "$AUTH_HDR" "$TAGS_URL" 2>/dev/null || true)
  fi
  TARGET=$(printf '%s' "$TAGS" | grep -o '"name": *"v[0-9][0-9.]*"' \
           | sed 's/.*"v/v/; s/"$//' \
           | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -1 || true)
  if [ -n "$TARGET" ]; then
    echo "  latest published: $TARGET"
  else
    warn "could not determine the latest version (private repo without GHCR_TOKEN in .env, or no network)"
    # `-y` means "do not ask me routine questions", NOT "silently accept degraded mode".
    # `:latest` is a moving pointer: pinned in .env, you no longer know what you are going back
    # to, and `.prev-image` becomes useless. The first production run fell into exactly this trap.
    if [ "$ALLOW_LATEST" != 1 ]; then
      echo "  You have three ways out:" >&2
      echo "    · give the version explicitly:  ./upgrade.sh vX.Y.Z" >&2
      echo "    · put GHCR_TOKEN=<PAT> in $ROOT/.env (deploy.sh reads it too)" >&2
      echo "    · accept a moving tag: ./upgrade.sh --allow-latest" >&2
      die "refusing to pin :latest unless you ask for it explicitly"
    fi
    warn "--allow-latest: pinning a MOVING tag; rolling back to a specific version becomes manual"
    TARGET="latest"
  fi
fi
IMAGE="$IMAGE_BASE:$TARGET"
CURRENT="${WEBTERM_IMAGE:-<nesetat>}"
echo "  now:   $CURRENT${WEBTERM_IMAGE_TAG:+ ($WEBTERM_IMAGE_TAG)}"
echo "  target: $IMAGE (digest resolved after pull)"

# ── 2. preflight: fail early, without side effects ───────────────────────────
say "Preflight checks"
command -v docker >/dev/null || die "docker is missing"
docker compose version >/dev/null 2>&1 && COMPOSE="docker compose" || COMPOSE="docker-compose"
$COMPOSE version >/dev/null 2>&1 || die "docker compose is missing"
[ -f docker-compose.prod.yml ] || die "docker-compose.prod.yml missing in $ROOT"
[ -x ./deploy.sh ] || die "deploy.sh missing in $ROOT"

FILE=docker-compose.prod.yml
FREE_MB=$(df -Pm . | awk 'NR==2{print $4}')
[ "$FREE_MB" -lt 2048 ] && warn "only ${FREE_MB}MB free — the image plus the backup need room"
echo "  free space: ${FREE_MB}MB"

# Log in to ghcr BEFORE the pull, with the token from .env if present. The classic trap:
# `docker login` run as your user, `upgrade.sh` run with sudo → different HOME, different
# ~/.docker/config.json, so "unauthorized" on a machine where a manual `docker pull` works.
if [ -n "${GHCR_TOKEN:-}" ]; then
  echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin >/dev/null \
    && echo "  logged in to ghcr.io (token from .env)" \
    || die "ghcr login failed — token expired or wrong"
else
  echo "  no GHCR_TOKEN in .env; relying on the existing docker login of user $(id -un)"
fi

# ── 3. pull: the artefact is local before anything changes ───────────────────
say "Pulling $IMAGE"
if ! docker pull -q "$IMAGE" >/dev/null; then
  echo "" >&2
  echo "  If it says \"unauthorized/denied\": the image is private." >&2
  echo "    echo <PAT_cu_read:packages> | docker login ghcr.io -u $GHCR_USER --password-stdin" >&2
  echo "  or put GHCR_TOKEN=<PAT> in $ROOT/.env (deploy.sh reads it too)." >&2
  die "pull failed"
fi

# ── 3b. pin the tag to its digest, then (optionally) verify who signed it ────
# `RepoDigests` after a registry pull is the digest of the manifest index the registry served
# for the tag — the same value `docker buildx imagetools inspect` prints (checked on v3.0.0).
# Resolved ONCE, here; everything below (version read, kit extraction, deploy.sh, the final
# "what is running" comparison, `.env`, `.prev-image`) uses the digest reference.
say "Pinning $TARGET to its digest"
DIGEST=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$IMAGE" 2>/dev/null \
         | awk -v b="$IMAGE_BASE@" 'index($0, b) == 1 { print substr($0, length(b) + 1); exit }' || true)
case "$DIGEST" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) DIGEST="" ;;
esac
if [ -n "$DIGEST" ]; then
  PINNED="$IMAGE_BASE@$DIGEST"
  echo "  $TARGET = $DIGEST"
else
  # A registry pull always records a digest; an empty one means something unusual (a daemon
  # that strips RepoDigests, a mirror answering oddly). Deploying the tag would silently bring
  # back the mutable-pointer problem, so it needs to be asked for by name.
  [ "$ALLOW_UNPINNED" = 1 ] || die "could not resolve $IMAGE to a digest — refusing to deploy a mutable tag.
  Inspect: docker image inspect --format '{{.RepoDigests}}' $IMAGE
  Or, if you accept it: ./upgrade.sh $TARGET --allow-unpinned"
  warn "--allow-unpinned: deploying the TAG $IMAGE; .env/.prev-image will hold a moving pointer"
  PINNED="$IMAGE"
fi
# cosign (keyless, Sigstore): the CI signs the digest it pushed with the identity of the
# workflow that built it. Opt-in: `cosign` on PATH + WEBTERM_COSIGN_IDENTITY in .env (a regexp
# over the certificate identity, e.g. ^https://github.com/<owner>/webterm/.github/workflows/
# docker-publish.yml@refs/tags/v). Without both we say so, in one line, every time — a check
# that silently does not run is worse than none, because you believe it ran.
if command -v cosign >/dev/null 2>&1 && [ -n "${WEBTERM_COSIGN_IDENTITY:-}" ]; then
  COSIGN_ISSUER="${WEBTERM_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
  if cosign verify --certificate-identity-regexp "$WEBTERM_COSIGN_IDENTITY" \
       --certificate-oidc-issuer "$COSIGN_ISSUER" "$PINNED" >/dev/null 2>&1; then
    echo "  cosign: signature verified (identity ~ $WEBTERM_COSIGN_IDENTITY, issuer $COSIGN_ISSUER)"
  else
    die "cosign: NO valid signature for $PINNED (identity ~ $WEBTERM_COSIGN_IDENTITY, issuer $COSIGN_ISSUER). Not deploying."
  fi
else
  if command -v cosign >/dev/null 2>&1; then REASON="WEBTERM_COSIGN_IDENTITY not set in .env"; else REASON="cosign is not installed"; fi
  warn "signature verification SKIPPED ($REASON) — the digest pin keeps these exact bytes, but says nothing about who built them"
fi
# 3.6.9: after a re-exec into the release's own upgrade.sh, the image must be EXACTLY the one the
# previous script resolved and checked (a tag re-pointed in between is refused, not followed).
if [ "${WEBTERM_UPGRADE_REEXEC:-0}" = 1 ] && [ -n "${WEBTERM_UPGRADE_PINNED:-}" ] \
   && [ "$WEBTERM_UPGRADE_PINNED" != "$PINNED" ]; then
  die "the image changed between the two upgrade.sh runs ($WEBTERM_UPGRADE_PINNED → $PINNED) — not deploying; run ./upgrade.sh again"
fi
IMAGE="$PINNED"
if [ "$CURRENT" = "$IMAGE" ]; then
  warn "already the installed digest — continuing (useful for re-syncing the host files)"
fi

NEW_VER=$(docker run --rm --entrypoint sh "$IMAGE" -c \
          "grep -m1 '^GATEWAY_VERSION' /srv/webterm/gateway/app/config.py | cut -d'\"' -f2" 2>/dev/null || echo "?")
NEW_AGENT=$(docker run --rm --entrypoint sh "$IMAGE" -c \
          "grep -m1 '^AGENT_VERSION' /srv/webterm/agent/ptyd.py | tr -dc 0-9" 2>/dev/null || echo "?")
echo "  image pulled: gateway v$NEW_VER, agent v$NEW_AGENT"

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
# RC2-H1 (al treilea recheck): `up` nu mai re-rezolvă nimic — porneşte EXACT ID-ul verificat
# (up_checked: WEBTERM_IMAGE=<sha256:ID> doar pentru apel, `--pull never --no-build`); un serviciu
# app cu `build:` sau cu pull_policy în afară de missing/never = refuz, pentru orice imagine. `.env`
# păstrează referinţa umană (tag/digest), deci .prev-image şi rollback-ul rămân pe referinţe.
# RC2-H2: gateway-ul îşi ia datele din WEBTERM_DATA_DIR (config.py), nu neapărat din /data. Pentru
# o imagine < 3.8 valoarea EFECTIVĂ (environment-ul serviciului din plan, cu .env/env_file deja
# rezolvate de compose, altfel ENV-ul imaginii verificate) trebuie să fie exact /data; altfel refuz.
# RC3-H1 (al patrulea recheck): WEBTERM_IMAGE=<ID> injectat abia la `up` re-randa compose cu alt
# mediu decât cel verificat (o sursă bind interpolată şi din WEBTERM_IMAGE schimba planul fără nicio
# cursă). Acum planul se randează O SINGURĂ DATĂ (render_checked: `config --format json`, toate
# profilele, cu WEBTERM_IMAGE=<ID>) într-un fişier privat .wt-plan.* (0600, în directorul instalării),
# services.app.image = ID-ul verificat, iar garda (guard_recheck) şi `up` (`-p <proiect> -f <plan>`)
# folosesc EXACT acel fişier. Randarea se face de două ori (referinţa umană şi ID-ul): orice diferenţă
# în afară de services.app.image şi WEBTERM_IMAGE_REF/TAG = refuz, pentru orice imagine. Re-up-ul după
# SSO re-randează (.env are acum setările OIDC) şi acceptă faţă de planul pornit DOAR cele trei chei
# WEBTERM_OIDC_* pe care le scrie provizionarea.
# RC3-M1: un bind la /data s-ar lista pe filesystem-ul clientului, care nu e neapărat cel montat de
# daemon (proxy, alt namespace). Pentru o ţintă < 3.8 / necunoscută se acceptă DOAR un volum numit
# montat întreg; un bind = refuz (o instalare pe bind revine la 3.7 doar prin restaurarea backup-ului
# de dinainte de migrare). Ţintele 3.8 nu sunt afectate.
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
# imaginea ţintă, fără reţea. Ieşire: „image<TAB>services.app.image" pe prima linie,
# „run<TAB>ok" sau „run<TAB>motiv" (build / pull_policy) pe a doua, apoi
# „volume<TAB>nume", „bind<TAB>cale" sau „unknown<TAB>motiv".
COMPOSE_PLAN_PY='# wt-compose-plan (R-H1, RC-H1, RC2-H1, RC2-H2)
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
    print("run\tno service app in the compose config")
    out("unknown", "no service app in the compose config")
img = app.get("image")
print("image\t" + ("" if bad(img) else img))
pp = app.get("pull_policy")
if "build" in app:
    print("run\tservice app has a build section (the checked image could be rebuilt)")
elif pp not in (None, "missing", "never"):
    print("run\tservice app has pull_policy %s (only missing or never keep the checked image)" % str(pp)[:40])
else:
    print("run\tok")
env = app.get("environment")
if env is not None and not isinstance(env, dict):
    out("unknown", "the environment of service app cannot be read")
if "env_file" in app:
    out("unknown", "service app has an env_file compose did not resolve")
dd = (env or {}).get("WEBTERM_DATA_DIR")
if dd is not None and dd != "/data":
    out("unknown", "custom WEBTERM_DATA_DIR is not supported by the downgrade guard (service app sets it)")
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
DATA_PLAN="" PLAN_ERR="" DATA_IMG="" DATA_RUN="" GUARD_PLAN="" GUARD_ID="" GUARD_ERA=""
data_plan() {   # data_plan COMPOSE_FILE IMAGE → 0 + DATA_PLAN ("volume<TAB>name" | "bind<TAB>/path"); 1 + PLAN_ERR
  # DATA_IMG = services.app.image din ACELAŞI plan („" dacă nu se poate citi); DATA_RUN = „ok" sau
  # motivul pentru care `up` ar putea re-construi / re-trage imaginea app („" dacă nu se poate citi)
  local cfg out verdict
  DATA_PLAN="" PLAN_ERR="" DATA_IMG="" DATA_RUN=""
  cfg=$(docker compose -f "$1" config --format json 2>/dev/null) \
    || { PLAN_ERR="docker compose config --format json failed"; return 1; }
  out=$(printf '%s' "$cfg" | docker run --rm -i --network none --entrypoint python3 "$2" -I -c "$COMPOSE_PLAN_PY" 2>/dev/null) \
    || { PLAN_ERR="the compose config could not be read"; return 1; }
  case "$out" in
    image$'\t'*$'\n'run$'\t'*$'\n'*)
      DATA_IMG=${out%%$'\n'*}; DATA_IMG=${DATA_IMG#image$'\t'}; out=${out#*$'\n'}
      DATA_RUN=${out%%$'\n'*}; DATA_RUN=${DATA_RUN#run$'\t'}; verdict=${out#*$'\n'} ;;
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
volume_38_markers() {   # volume_38_markers VOLUME IMAGE → names on stdout; 0 listed, 2 confirmed absent, 1 error
  # RC3-M1: doar volume numite, listate prin daemonul care va porni serviciul (bind-ul e refuzat înainte)
  local all ls
  all=$(docker volume ls -q) || return 1
  printf '%s\n' "$all" | grep -qxF "$1" || return 2
  ls=$(docker run --rm --network none -v "$1:/data:ro" --entrypoint ls "$2" -A1 /data) || return 1
  printf '%s\n' "$ls" | grep -E '^(keys\.wtk.*|migrating\.wtm.*|master\.key.*|erasures\.wtj|\.restore|restore-pending\..+|.*\.wt[a-z0-9]*)$' || true
}
guard_pre38() {   # guard_pre38 IMAGE COMPOSE_FILE → 0 may start (GUARD_PLAN, GUARD_ID, GUARD_ERA); 1 refused
  local era marks rc=0 typ src cids cid m id ienv dd
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
  # RC2-H2: ce cale de date vede gateway-ul imaginii verificate când compose nu o schimbă (ENV-ul
  # imaginii); orice altceva decât exact /data (lipsă, goală, alt director) = refuz
  ienv=$(docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$id" 2>/dev/null) || ienv="?"
  dd=$(printf '%s\n' "$ienv" | sed -n 's/^WEBTERM_DATA_DIR=//p' | tail -n1)
  if [ "$ienv" = "?" ] || [ "$dd" != /data ]; then
    echo "✗ Refusing to start $1 (${era}): custom WEBTERM_DATA_DIR is not supported by the downgrade guard" >&2
    echo "  (the image sets '${dd:-nothing}', only /data is checked). Nothing was changed." >&2
    return 1
  fi
  if ! data_plan "$2" "$id"; then
    echo "✗ Refusing to start $1: it is not a 3.8 image (${era}) and the /data mount compose would start" >&2
    echo "  cannot be determined or is not supported ($PLAN_ERR), so it cannot be checked for the 3.8" >&2
    echo "  encryption-at-rest migration." >&2
    echo "  Nothing was changed. Only a whole named volume at /data is checked (no bind mount, no" >&2
    echo "  volume.subpath, no driver_opts device, default mount options, WEBTERM_DATA_DIR unset or" >&2
    echo "  /data). An image built" >&2
    echo "  locally without a version label can be declared 3.8 explicitly for one run:" >&2
    echo "  WEBTERM_IMAGE_ERA=3.8 $0 …" >&2
    return 1
  fi
  typ=${DATA_PLAN%%$'\t'*} src=${DATA_PLAN#*$'\t'}
  # RC3-M1: un bind nu se poate verifica prin daemon fără a-l lista pe gazdă → doar volume numite
  if [ "$typ" != volume ]; then
    echo "✗ Refusing to start $1 (${era}): /data is a bind mount ('$src'). Before an image older than 3.8" >&2
    echo "  (or of an unknown version) starts, only a whole named volume is checked: a host directory" >&2
    echo "  listed here need not be what the Docker daemon mounts. Nothing was changed." >&2
    echo "  A bind-mount installation goes back to 3.7 only by restoring the backup taken BEFORE the" >&2
    echo "  migration (docs/INSTALL.md → Encryption at rest, \"Going back to 3.7\")." >&2
    return 1
  fi
  if [ -n "${WEBTERM_VOLUME:-}" ] && [ "$WEBTERM_VOLUME" != "$src" ]; then
    echo "✗ Refusing to start $1 (${era}): WEBTERM_VOLUME=$WEBTERM_VOLUME, but compose would mount $typ '$src'" >&2
    echo "  at /data. WEBTERM_VOLUME does not change what compose mounts: unset it, or change the compose" >&2
    echo "  file. Nothing was changed." >&2
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
  marks=$(volume_38_markers "$src" "$id") || rc=$?
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
# Programul care randează planul final (RC3-H1); rulează în imaginea verificată (ca ID), fără reţea.
# stdin: referinţa umană, ID-ul, apoi un tablou JSON [config cu referinţa, config cu ID-ul, planul de
# bază sau null]. Ieşire: „name<TAB>proiect" + planul JSON pe o linie, sau „refuse<TAB>motiv".
COMPOSE_RENDER_PY='# wt-compose-render (RC3-H1)
import json, re, sys
def refuse(msg):
    print("refuse\t" + msg)
    sys.exit(0)
try:
    ref, iid, rest = sys.stdin.read().split("\n", 2)
    by_ref, by_id, base = json.loads(rest)
    for c in (by_ref, by_id):
        assert isinstance(c, dict) and isinstance(c["services"]["app"], dict)
    assert base is None or isinstance(base, dict)
except (ValueError, KeyError, TypeError, AssertionError):
    refuse("the compose config could not be read")
if by_ref["services"]["app"].get("image") != ref or by_id["services"]["app"].get("image") != iid:
    refuse("services.app.image does not follow WEBTERM_IMAGE (it must be exactly the WEBTERM_IMAGE variable, so the checked image is the one started)")
name = by_id.get("name")
if not isinstance(name, str) or not re.match(r"^[a-z0-9][a-z0-9_-]*$", name):
    refuse("the compose project has no usable name")
def without(c, image, env_keys):
    c = json.loads(json.dumps(c))
    app = c["services"]["app"]
    if image:
        app.pop("image", None)
    env = app.get("environment")
    if isinstance(env, dict):
        for k in env_keys:
            env.pop(k, None)
    return c
def diff(a, b, path, out):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                out.append(path + "." + str(k))
            else:
                diff(a[k], b[k], path + "." + str(k), out)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i in range(len(a)):
            diff(a[i], b[i], "%s[%d]" % (path, i), out)
    elif type(a) is not type(b) or a != b:
        out.append(path or ".")
    return out
d = diff(without(by_ref, True, ("WEBTERM_IMAGE_REF", "WEBTERM_IMAGE_TAG")),
         without(by_id, True, ("WEBTERM_IMAGE_REF", "WEBTERM_IMAGE_TAG")), "", [])
if d:
    refuse(("changing WEBTERM_IMAGE also changes %s (only services.app.image may follow it)" % ", ".join(d[:3]))[:300])
by_id["services"]["app"]["image"] = iid
if base is not None:
    sso = ("WEBTERM_OIDC_ISSUER", "WEBTERM_OIDC_CLIENT_ID", "WEBTERM_OIDC_PROVIDER_NAME")
    d = diff(without(base, False, sso), without(by_id, False, sso), "", [])
    if d:
        refuse(("the configuration changed since it was started, beyond the SSO settings (%s)" % ", ".join(d[:3]))[:300])
print("name\t" + name)
print(json.dumps(by_id, sort_keys=True))
'
PLAN_FILE="" PLAN_NAME="" PLAN_FILES=""
plan_cleanup() {   # şterge planurile randate de această rulare (conţin mediul rezolvat al serviciilor)
  local f
  for f in $PLAN_FILES; do rm -f -- "$f"; done
  PLAN_FILES=""
}
plan_sweep() {   # plan_sweep DIR → şterge planurile rămase de la o rulare întreruptă (RC4-L1)
  # Un SIGKILL / o cădere a maşinii nu rulează trap-ul, iar planul conţine mediul rezolvat al serviciilor.
  # Doar când lacătul a fost luat ACUM (WT_SWEEP=1, nu moştenit de la un părinte care ar putea avea un
  # plan viu): fişiere obişnuite (nu symlink-uri), ale noastre, din DIR, mai vechi decât începutul rulării.
  local n
  [ "${WT_SWEEP:-0}" = 1 ] && [ -n "${WT_RUN_START:-}" ] || return 0
  n=$(find "$1" -maxdepth 1 -name '.wt-plan.*' -type f -user "$(id -u)" ! -newermt "@$WT_RUN_START" \
        -print -delete 2>/dev/null | wc -l) || n=0
  [ "${n:-0}" -eq 0 ] || echo "→ removed $n stale compose plan file(s) left by an interrupted run."
  return 0
}
render_checked() {   # render_checked COMPOSE_FILE IMAGE_REF IMAGE_ID LABEL [BASE_PLAN] → 0 + PLAN_FILE, PLAN_NAME; 1 refused
  # RC3-H1: planul se randează o singură dată, cu mediul din `up` (WEBTERM_IMAGE=<ID>, eticheta), şi se
  # scrie într-un fişier privat; garda şi `up` folosesc exact acel fişier. Toate profilele (`*`): un
  # serviciu dintr-un profil inactiv rămâne cunoscut, altfel `--remove-orphans` i-ar şterge containerele.
  local f="$1" ref="$2" id="$3" label="$4" base=null by_ref by_id out name tmp
  PLAN_FILE="" PLAN_NAME=""
  if ! [[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]] || [ -z "$ref" ] || [[ "$ref$label" == *[[:cntrl:]]* ]]; then
    echo "✗ Refusing to start ${ref:-?}: the checked image '${id:-?}' or its reference cannot be used. Nothing was started." >&2
    return 1
  fi
  if [ -n "${5:-}" ]; then
    base=$(cat -- "$5") || { echo "✗ Refusing to start $ref: the started plan $5 cannot be read. Nothing was started." >&2; return 1; }
  fi
  by_ref=$(WEBTERM_IMAGE="$ref" WEBTERM_IMAGE_TAG="$label" docker compose --profile '*' -f "$f" config --format json 2>/dev/null) \
    && by_id=$(WEBTERM_IMAGE="$id" WEBTERM_IMAGE_TAG="$label" docker compose --profile '*' -f "$f" config --format json 2>/dev/null) \
    && out=$(printf '%s\n%s\n[%s,%s,%s]' "$ref" "$id" "$by_ref" "$by_id" "$base" \
             | docker run --rm -i --network none --entrypoint python3 "$id" -I -c "$COMPOSE_RENDER_PY" 2>/dev/null) \
    || out=""
  case "$out" in
    refuse$'\t'*)
      echo "✗ Refusing to start $ref: ${out#refuse$'\t'}. Nothing was started." >&2
      return 1 ;;
    name$'\t'*$'\n'\{*) name=${out%%$'\n'*}; name=${name#name$'\t'}; out=${out#*$'\n'} ;;
    *) echo "✗ Refusing to start $ref: the compose plan could not be rendered (docker compose config --format json). Nothing was started." >&2
       return 1 ;;
  esac
  tmp=$(umask 077; mktemp .wt-plan.XXXXXX) || { echo "✗ Refusing to start $ref: cannot create the plan file. Nothing was started." >&2; return 1; }
  PLAN_FILES="$PLAN_FILES $tmp"
  printf '%s\n' "$out" > "$tmp" || { echo "✗ Refusing to start $ref: cannot write the plan file. Nothing was started." >&2; return 1; }
  PLAN_FILE=$tmp PLAN_NAME=$name
}
up_checked() {   # up_checked IMAGE_ID LABEL PLAN_FILE [up args / services…] → `up` pe EXACT planul randat
  # RC2-H1: fără pull şi fără build: un tag mutabil re-indicat între verificare şi `up` nu schimbă ce
  # porneşte. RC3-H1: compose citeşte planul randat şi verificat (services.app.image = ID-ul), cu
  # proiectul lui; nimic nu se mai interpolează din mediu (WEBTERM_IMAGE=<ID> rămâne doar ca plasă).
  local id="$1" label="$2" f="$3"
  shift 3
  if ! [[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "✗ Refusing to start: the checked image '${id:-?}' is not a sha256 image ID. Nothing was started." >&2
    return 1
  fi
  if [ -z "$f" ] || [ "$f" != "$PLAN_FILE" ] || [ -z "$PLAN_NAME" ] || [ ! -f "$f" ] || [ -L "$f" ]; then
    echo "✗ Refusing to start: '${f:-?}' is not the plan that was rendered and checked. Nothing was started." >&2
    return 1
  fi
  WEBTERM_IMAGE="$id" WEBTERM_IMAGE_TAG="$label" docker compose -p "$PLAN_NAME" -f "$f" up -d --pull never --no-build "$@"
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
  # RC2-H1: `up` porneşte ID-ul verificat cu `--pull never --no-build`; un serviciu app care cere
  # build sau alt pull_policy contrazice asta, deci refuz (şi pentru o imagine 3.8)
  if [ "$DATA_RUN" != ok ]; then
    echo "✗ Refusing to start $1: ${DATA_RUN:-the compose config could not be read}. Remove it from the" >&2
    echo "  app service; only the checked image is started (no pull, no build). Nothing was started." >&2
    return 1
  fi
  return 0
}
# ── sfârşitul gărzii 3.8 (bloc identic în deploy.sh, rollback.sh, upgrade.sh) ──
plan_sweep "$ROOT"
# H1: o ţintă mai veche de 3.8 pe un volum migrat se refuză ÎNAINTE de backup, de trusa de pe
# host (deploy.sh-ul ţintei n-ar mai avea garda) şi de deploy
guard_pre38 "$IMAGE" "$FILE" || die "refusing to install a pre-3.8 image on this migrated volume"
CHECKED_PLAN="$GUARD_PLAN" CHECKED_ID="$GUARD_ID"
# RC2-H1: deploy.sh-ul unei ţinte < 3.8 (din trusa ei) nu are up_checked şi porneşte referinţa aşa cum
# e; doar un digest (imuabil) garantează că porneşte imaginea verificată, deci fără --allow-unpinned
if [ "$GUARD_ERA" != 38 ] && [[ "$IMAGE" != *@sha256:* ]]; then
  die "refusing to install $IMAGE unpinned: a target older than 3.8 (or of an unknown version) starts through its own deploy.sh, so only a digest reference guarantees the checked image starts — resolve the digest (drop --allow-unpinned)"
fi

# The agent signature inside the image. Without it the gateway REFUSES to push updates
# (we do not send unsigned code to hosts), and the fleet would stay stuck on the old version
# with nobody saying anything. It is a property of the artefact, so we check it before
# putting it into production — not after.
SIGCHK=$(docker run --rm --entrypoint python3 "$IMAGE" -c "
import base64, pathlib, re
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    src = pathlib.Path('/srv/webterm/agent/ptyd.py').read_bytes()
    m = re.search(rb'UPDATE_PUBKEY = bytes.fromhex\\(\\s*.([0-9a-f]+).', src, re.S)
    pub = bytes.fromhex(m.group(1).decode())
    sig = base64.b64decode(pathlib.Path('/srv/webterm/agent/ptyd.py.sig').read_text().strip())
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, src)
    print('OK')
except FileNotFoundError:
    print('LIPSA')
except Exception:
    print('INVALIDA')
" 2>/dev/null || echo "NEVERIFICAT")
case "$SIGCHK" in
  OK) echo "  agent signature: valid (the official channel works)" ;;
  LIPSA)  warn "the image has no agent/ptyd.py.sig — without a deployment key, agents cannot update" ;;
  INVALIDA) warn "the agent signature in the image does NOT verify — agents will REFUSE the update" ;;
  *) warn "could not verify the agent signature (old image?)" ;;
esac

# ── 4. backup BEFORE the change ──────────────────────────────────────────────
BACKUP_DONE=0
if [ "$DO_BACKUP" = 1 ] && [ "${WEBTERM_UPGRADE_REEXEC:-0}" = 1 ] && [ "${WEBTERM_UPGRADE_BACKUP_DONE:-0}" = 1 ]; then
  say "Backup before upgrading"
  echo "  already done by the previous upgrade.sh in this run — not repeated"
  BACKUP_DONE=1
elif [ "$DO_BACKUP" = 1 ]; then
  say "Backup before upgrading"
  if [ -x scripts/backup.sh ]; then
    # The backup passphrase lives in /etc/default/webterm-backup — the same file the systemd
    # timer loads (EnvironmentFile). Without it backup.sh refuses itself ("I do not write
    # unencrypted archives non-interactively"), so the upgrade's safety step did not work
    # precisely on the machines that were configured correctly. One source of truth.
    if [ -r /etc/default/webterm-backup ]; then
      load_env /etc/default/webterm-backup
      echo "  (backup passphrase loaded from /etc/default/webterm-backup)"
    fi
    if scripts/backup.sh; then
      echo "  backup done"
      BACKUP_DONE=1
    else
      warn "the backup failed"
      # `-y` înseamnă „nu mă întreba", nu „treci peste o plasă de siguranţă lipsă". `ask`
      # întorcea 0 sub `-y`, deci un upgrade neasistat continua fără snapshot exact când
      # backupul e stricat — adică atunci când ai cea mai mare nevoie de el. Cine chiar vrea
      # asta o spune explicit, cu --no-backup.
      if [ "$ASSUME_YES" = 1 ]; then
        die "the backup failed and -y was given — refusing to upgrade without a snapshot.
Fix the backup, or say so explicitly with --no-backup."
      fi
      ask "Continue the upgrade WITHOUT a backup?" || die "cancelled — fix the backup first"
    fi
  else
    warn "scripts/backup.sh missing — continuing without a backup"
  fi
else
  warn "backup skipped (--no-backup)"
fi

# ── 5. sync the files that run on the HOST ───────────────────────────────────
# From the image already pulled and authenticated, not from the internet. We keep a .bak for
# every file we change, so you can see exactly what moved.
say "Syncing host files from the image"
KIT=$(mktemp -d)
trap 'rm -rf "$KIT"' EXIT
if docker run --rm --entrypoint sh "$IMAGE" -c 'cd /srv/webterm/deploy-kit && tar cf - .' 2>/dev/null \
   | tar xf - -C "$KIT" 2>/dev/null && [ -f "$KIT/docker-compose.prod.yml" ]; then
  # 3.6.9: the release's OWN upgrade.sh does the rest. It used to replace this file only at the
  # very end ("active from the next run"), so 3.6.8 was installed by the 3.6.7 script — which
  # synced only the scripts IT knew: host-health.sh, docker-cleanup.sh and authentik-upgrade.sh
  # never reached prod, no timers, no health list, "command not found". Now: same source as every
  # other kit file (the digest-pinned image, signature-checked above when configured), a syntax
  # check, a .bak, then `exec` with the same arguments (+ the resolved tag) and a guard that makes
  # a second switch impossible. Steps already done (pull, digest, backup) are not repeated: the
  # backup is skipped as done, and the digest must match the one resolved here.
  if [ -f "$KIT/upgrade.sh" ] && ! cmp -s "$KIT/upgrade.sh" upgrade.sh; then
    if [ "${WEBTERM_UPGRADE_REEXEC:-0}" = 1 ]; then
      warn "the release's upgrade.sh still differs after switching to it once — not switching again (continuing)"
    elif ! bash -n "$KIT/upgrade.sh" 2>/dev/null; then
      warn "the release's upgrade.sh does not parse — continuing with this one"
    else
      cp -p upgrade.sh upgrade.sh.bak
      cp "$KIT/upgrade.sh" upgrade.sh.new && chmod +x upgrade.sh.new && mv upgrade.sh.new upgrade.sh
      echo "  upgrade.sh: the release ships a newer one — switching to it now (old → upgrade.sh.bak)"
      rm -rf "$KIT"
      trap - EXIT
      REEXEC_TAG=""
      case "$TARGET" in v[0-9]*.[0-9]*.[0-9]*) REEXEC_TAG="$TARGET" ;; esac
      export WEBTERM_UPGRADE_REEXEC=1 WEBTERM_UPGRADE_PINNED="$IMAGE" WEBTERM_UPGRADE_BACKUP_DONE="$BACKUP_DONE"
      exec bash ./upgrade.sh "$@" ${REEXEC_TAG:+"$REEXEC_TAG"}
    fi
  fi
  # FL-12 (audit 2026-10-17): the run BEFORE this one may have been made by an upgrade.sh older
  # than 3.6.9 — the one a 3.5.x install still has. That script synced only the files IT knew
  # (backup/restore/cert-check) and put THIS file in place at its very end ("active from the next
  # run"), so nothing from 3.6.8+ reached the host: no host-health.sh, cert-renew.sh,
  # docker-cleanup.sh, authentik-upgrade.sh, no timers — and System health showed the host checks
  # without data, under a green "✓". Nothing can be done from inside THAT run (the old file keeps
  # executing after it replaces itself); this run is the one that completes it. Its trace: an
  # upgrade.sh.bak without the re-exec guard, and the kit script missing while the release ships it.
  # We say why the "installed:" lines below are there, instead of listing them as routine.
  OLD_STYLE_PREV=0
  if [ "${WEBTERM_UPGRADE_REEXEC:-0}" != 1 ] && [ -f upgrade.sh.bak ] \
     && ! grep -q 'WEBTERM_UPGRADE_REEXEC' upgrade.sh.bak \
     && [ -f "$KIT/scripts/host-health.sh" ] && [ ! -f scripts/host-health.sh ]; then
    OLD_STYLE_PREV=1
    warn "the previous upgrade was made by an upgrade.sh older than 3.6.9 (kept as upgrade.sh.bak)."
    warn "  That script synced only backup/restore/cert-check and installed this file at its very end,"
    warn "  so the host kit (host-health.sh, cert-renew.sh, docker-cleanup.sh, authentik-upgrade.sh"
    warn "  and their timers) was NOT installed by that run. This run installs it — let it finish."
  fi
  CHANGED=0
  KIT_DONE=""
  for f in docker-compose.prod.yml deploy.sh rollback.sh remove.sh \
           scripts/backup.sh scripts/restore.sh scripts/cert-check.sh scripts/cert-renew.sh \
           scripts/host-health.sh scripts/docker-cleanup.sh scripts/authentik-upgrade.sh \
           deploy/authentik/docker-compose.prod.yml deploy/authentik/docker-compose.yml \
           deploy/authentik/.env.prod.example deploy/authentik/.env.example \
           deploy/authentik/provision.py deploy/authentik/provision.sh \
           deploy/authentik/blueprints/webterm.yaml \
           deploy/webterm-backup.service deploy/webterm-backup.timer \
           deploy/webterm-cert-check.service deploy/webterm-cert-check.timer \
           deploy/webterm-host-health.service deploy/webterm-host-health.timer \
           deploy/webterm-docker-cleanup.service deploy/webterm-docker-cleanup.timer; do
    [ -f "$KIT/$f" ] || continue
    if [ -f "$f" ] && cmp -s "$KIT/$f" "$f"; then continue; fi
    mkdir -p "$(dirname "$f")"
    WHAT="updated"
    if [ -f "$f" ]; then cp -p "$f" "$f.bak"; else WHAT="installed"; fi
    cp "$KIT/$f" "$f"
    case "$f" in *.sh) chmod +x "$f" ;; esac
    echo "  $WHAT: $f$([ "$WHAT" = updated ] && echo ' (old → .bak)')"
    KIT_DONE="$KIT_DONE
    $WHAT: $f"
    CHANGED=$((CHANGED + 1))
  done
  [ "$CHANGED" = 0 ] && echo "  host files were already up to date"
else
  warn "the image has no deploy kit (version < 2.0.0) — host files left as they are"
  KIT_NONE=1         # FL-12: nothing to compare the host kit against — checked again at the end
fi

# ── 5b. unităţile systemd (backup + cert-check) ──────────────────────────────
# `install.sh` le copiază în /etc/systemd/system o singură dată şi nimic nu le mai atingea: pe
# prod am găsit timere din iulie cu `Persistent=true  # comentariu` pe aceeaşi linie — systemd
# NU acceptă asta („Failed to parse boolean value, ignoring"), deci Persistent cădea tăcut pe
# false şi backupul ratat la un server oprit nu se mai recupera. Repo-ul era reparat de luni de
# zile; fix-ul n-a ajuns pe host pentru că nu exista mecanism. Sincronizăm din `deploy/` (adus
# mai sus din imagine, când kitul le conţine) DOAR unităţile deja instalate şi al căror
# .service arată spre ACEST director: nu instalăm nimic nou (--no-backup / --no-cert-check
# rămân respectate) şi nu atingem unităţile altei instalări de pe aceeaşi maşină.
# `.service` se randează ca în install.sh (/opt/webterm → $ROOT); `.timer` e copiat ca atare.
SYSTEMD_DIR="${WEBTERM_SYSTEMD_DIR:-/etc/systemd/system}"
UNITS_CHANGED=""
UNITS_SEEN=0
for unit in webterm-backup webterm-cert-check; do
  svc="$SYSTEMD_DIR/$unit.service"
  [ -f "$svc" ] || continue
  grep -q "^WorkingDirectory=$ROOT\$" "$svc" || continue       # altă instalare → nu e a noastră
  UNITS_SEEN=$((UNITS_SEEN + 1))
  for ext in service timer; do
    src="deploy/$unit.$ext"; dst="$SYSTEMD_DIR/$unit.$ext"
    [ -f "$src" ] && [ -f "$dst" ] || continue
    want="$KIT/.unit-$unit.$ext"
    if [ "$ext" = service ]; then sed -e "s|/opt/webterm|$ROOT|g" "$src" > "$want"; else cp "$src" "$want"; fi
    cmp -s "$want" "$dst" && continue
    if [ ! -w "$SYSTEMD_DIR" ]; then
      warn "$dst differs from $src but $SYSTEMD_DIR is not writable — run with sudo to sync it"
      continue
    fi
    cp -p "$dst" "$dst.bak"
    cp "$want" "$dst"
    echo "  actualizat: $dst (vechiul → .bak)"
    UNITS_CHANGED="$UNITS_CHANGED $unit.$ext"
  done
done
if [ -n "$UNITS_CHANGED" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    # daemon-reload ca systemd să citească fişierele noi; `enable --now` e idempotent şi
    # reporneşte timerul cu noul OnCalendar/Persistent (un timer deja activ nu reciteşte singur).
    systemctl daemon-reload || warn "systemctl daemon-reload failed — run it by hand"
    for u in $UNITS_CHANGED; do
      case "$u" in
        *.timer) systemctl enable --now "$u" >/dev/null 2>&1 || warn "could not re-enable $u" ;;
      esac
    done
    echo "  systemd units reloaded:$UNITS_CHANGED"
  else
    warn "units updated but systemctl is missing — reload them by hand"
  fi
elif [ "$UNITS_SEEN" != 0 ]; then
  echo "  systemd units already up to date"
fi

# ── 6. deploy propriu-zis: pin + health check + rollback automat ─────────────
# The DIGEST reference goes to deploy.sh (it lands in .env as WEBTERM_IMAGE and, on the next
# upgrade, in .prev-image); the tag rides along only as the UI label (WEBTERM_IMAGE_TAG).
say "Applying $TARGET ($IMAGE)"
# R-H1: trusa sincronizată mai sus poate aduce alt docker-compose.prod.yml (iar deploy.sh-ul unei
# ţinte < 3.8 nu are garda): planul /data se re-verifică pe fişierul care va porni, sub lacăt
# RC-H1: planul se citeşte cu imaginea pe care deploy.sh o va exporta (WEBTERM_IMAGE bate .env la
# compose), ca services.app.image să fie legată de ID-ul verificat; într-un subshell, fără efecte
# RC3-H1: şi planul randat cu ID-ul trebuie să difere de cel cu referinţa DOAR prin services.app.image
# (un Compose în care WEBTERM_IMAGE mută şi altceva = refuz); planul temporar se şterge în subshell
# RC4-L1: subshell-ul nu moşteneşte trap-urile; planul lui se şterge şi la Ctrl-C / TERM
( trap plan_cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
  export WEBTERM_IMAGE="$IMAGE"
  render_checked "$FILE" "$IMAGE" "$CHECKED_ID" "$TARGET" \
    && guard_recheck "$IMAGE" "$PLAN_FILE" "$CHECKED_PLAN" "$CHECKED_ID"
  rc=$?; plan_cleanup; exit "$rc" ) \
  || die "the data mount or the image changed since it was checked (e.g. with the host kit) — nothing deployed (run ./upgrade.sh <a 3.8.x version> to restore the 3.8 kit)"
# RC4-M1: ID-ul imaginii care rula ÎNAINTE de deploy — singurul reper prin care „a revenit la
# vechea imagine" (rollback real) se poate deosebi de „rulează altceva" după deploy
BEFORE_CID=$($COMPOSE -f "$FILE" ps -q app 2>/dev/null | head -1 || true)
BEFORE_ID=""
if [ -n "$BEFORE_CID" ]; then
  BEFORE_ID=$(docker inspect "$BEFORE_CID" --format '{{.Image}}' 2>/dev/null || true)
fi
./deploy.sh "$IMAGE" --tag "$TARGET"

# ── 7. final check: what is running NOW ──────────────────────────────────────
say "Verify"
# the container comes from compose, not from a fixed name: on a machine with two deployments,
# `webterm-app-1` could belong to a DIFFERENT instance
APP_CID=$($COMPOSE -f "$FILE" ps -q app 2>/dev/null | head -1)
# RC4-M1: ce rulează se citeşte ca ID efectiv (.Image), nu ca .Config.Image: containerul pornit din
# planul verificat are în Config.Image ID-ul local sha256, nu referinţa repo@sha256 din manifest, deci
# comparaţia pe şir declara „rollback" un upgrade reuşit (cu volumul poate deja migrat)
RUNNING_ID=$(docker inspect "${APP_CID:-nimic}" --format '{{.Image}}' 2>/dev/null || echo "?")
HEALTH_STATE=$(docker inspect "${APP_CID:-nimic}" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null || echo "?")
echo "  image: $IMAGE"
echo "  running image id: ${RUNNING_ID:-?} (checked: $CHECKED_ID)"
echo "  state: $HEALTH_STATE"
[ "$HEALTH_STATE" = healthy ] || warn "the container is NOT healthy — see 'docker logs ${APP_CID:-<container>}' and ./rollback.sh"

# ── 7b. prune old images: keep the last N versions for rollback, drop the rest ────────────────
# Fiecare upgrade lăsa imaginea veche pe disc (~300MB fiecare) → zeci de GB în timp. Păstrăm
# ultimele KEEP versiuni (semver desc) ca să poţi face rollback manual la oricare, PLUS — mereu,
# chiar dacă ies din top KEEP — imaginea care RULEAZĂ acum şi ţinta din .prev-image (ce foloseşte
# rollback.sh). Ştergem doar restul. `docker image rm` refuză o imagine folosită de un container,
# deci e sigur; ignorăm acele refuzuri.
KEEP="${WEBTERM_KEEP_IMAGES:-7}"
REPO_IMG="$IMAGE_BASE"
say "Pruning old images (keeping the last $KEEP)"
{
  # Comparăm pe ID de imagine, nu pe şir: containerul rulează acum pe `repo@sha256:…`, iar
  # `.prev-image` ţine tot un digest, deci o comparaţie cu `repo:vX.Y.Z` nu s-ar potrivi
  # niciodată şi am fi şters chiar tag-ul imaginii care rulează / ţinta de rollback.
  running_id=$(docker inspect "${APP_CID:-nimic}" --format '{{.Image}}' 2>/dev/null || true)
  prev=$([ -f .prev-image ] && head -1 .prev-image || true)
  prev_id=$([ -n "$prev" ] && docker image inspect --format '{{.Id}}' "$prev" 2>/dev/null || true)
  pinned_id=$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || true)
  # tag-urile vX.Y.Z, sortate semantic descrescător; primele KEEP se păstrează
  keep_tags=$(docker images "$REPO_IMG" --format '{{.Tag}}' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -n "$KEEP")
  removed=0
  for tag in $(docker images "$REPO_IMG" --format '{{.Tag}}' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$'); do
    ref="$REPO_IMG:$tag"
    printf '%s\n' "$keep_tags" | grep -qx "$tag" && continue     # în top KEEP
    id=$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)
    [ -n "$id" ] && [ "$id" = "$running_id" ] && continue        # rulează acum
    [ -n "$id" ] && [ "$id" = "$prev_id" ] && continue           # ţinta de rollback
    [ -n "$id" ] && [ "$id" = "$pinned_id" ] && continue         # ce tocmai am instalat
    # şi referinţele pe digest ale aceleiaşi imagini, altfel `rm` doar de-tag-uieşte şi
    # straturile rămân pe disc sub `repo@sha256:…`
    drefs=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" 2>/dev/null || true)
    # shellcheck disable=SC2086  # drefs e o listă de referinţe separate prin spaţiu/newline
    if docker image rm "$ref" $drefs >/dev/null 2>&1; then
      echo "  removed $tag"; removed=$((removed + 1))
    fi
  done
  # `if`, nu `[ ... ] && echo`: pe calea „s-a şters ceva", un `[ x = 0 ]` fals lăsa blocul cu
  # exit 1 → declanşa fals `|| warn "skipped"` DEŞI curăţenia reuşise. `if` iese mereu 0.
  if [ "$removed" = 0 ]; then echo "  nothing to prune (≤ $KEEP versions on disk)"; fi
} || warn "image prune skipped (non-fatal)"

# ── 7c. host health (3.6.8): the hourly root check + the daily Docker cleanup ─────────────────
# host-health.sh owns its units (install.sh calls the same --install): it renders them for THIS
# directory, leaves another install's units alone and retires the old hand-made cron job. Then one
# run now, so Settings → System health (and the list below) starts from fresh host data.
say "Host health"
HH_T=$(date +%s)
if [ -x scripts/host-health.sh ]; then
  scripts/host-health.sh --install || warn "host-health --install failed (non-fatal) — run: sudo $ROOT/scripts/host-health.sh --install"
  scripts/host-health.sh || warn "the host-health run reported a problem (non-fatal) — see Settings → System health"
else
  warn "scripts/host-health.sh missing — host checks not installed"
fi

if [ -f /etc/default/webterm-backup ] && grep -q '^WEBTERM_BACKUP_PASSPHRASE=.' /etc/default/webterm-backup; then
  echo "  backup: encrypted (passphrase in /etc/default/webterm-backup)"
else
  warn "the automatic backup has NO passphrase → archives would hold the vault key in cleartext."
  warn "  put WEBTERM_BACKUP_PASSPHRASE=... in /etc/default/webterm-backup (chmod 600)."
fi

# ── what is left for you to do: said out loud, not left to guesswork ────────
# An upgrade that ends with "✓" but leaves the fleet stuck is worse than one that fails:
# you walk away reassured. So we ask the RUNNING container what state it is in and list only
# the things that genuinely need a human.
TODO=0
STATE=$(docker exec "${APP_CID:-nimic}" python3 -c '
import sqlite3, sys
sys.path.insert(0, "/srv/webterm")
from app import config, signing
print("KEY", int(signing.key_exists()), int(signing.is_encrypted()))
try:
    d = sqlite3.connect("file:%s?mode=ro" % config.DB_PATH, uri=True)
    r = d.execute("SELECT COUNT(*) FROM hosts WHERE connection_type=?"
                  " AND agent_version IS NOT NULL AND agent_version < ?",
                  ("agent", int(sys.argv[1]))).fetchone()
    print("BEHIND", r[0])
    for name, why in d.execute("SELECT name, update_blocked FROM hosts"
                               " WHERE update_blocked IS NOT NULL AND update_blocked != \x27\x27"):
        print("BLOCKED", name, "|", why)
except Exception:
    print("BEHIND ?")
' "${NEW_AGENT:-0}" 2>/dev/null || true)

KEY_LINE=$(printf '%s' "$STATE" | awk '/^KEY/{print $2" "$3}')
BEHIND=$(printf '%s' "$STATE" | awk '/^BEHIND/{print $2}')

say "What is left to do"
case "$KEY_LINE" in
  "1 1")
    warn "the agent signing key is ENCRYPTED → after a restart it is LOCKED."
    echo "    Agents will NOT update until you unlock it: Settings → Infrastructure & tokens → Agent signing key."
    TODO=$((TODO + 1)) ;;
  "1 0") echo "  signing key: loaded automatically (no passphrase) — agents can update" ;;
  "0 0") echo "  no deployment key: using the official channel signed by the maintainer" ;;
  *)     warn "could not read the signing key state" ;;
esac

# hosts that CANNOT update (reason persisted by the gateway) — worse than merely "behind":
# waiting fixes nothing there, it needs an action
printf '%s\n' "$STATE" | awk -F'\\|' '/^BLOCKED/{print $0}' | while IFS= read -r line; do
  [ -n "$line" ] || continue
  warn "$(printf '%s' "$line" | sed 's/^BLOCKED /update BLOCKED on /')"
done
if printf '%s' "$STATE" | grep -q '^BLOCKED'; then
  echo "    An agent is refusing the signed update: most often because it was enrolled BEFORE"
  echo "    the signing key was generated. Fix: reinstall the agent on that host."
  TODO=$((TODO + 1))
fi
if [ -n "${BEHIND:-}" ] && [ "$BEHIND" != "?" ] && [ "$BEHIND" != "0" ]; then
  echo "  $BEHIND host(s) still on an agent older than v$NEW_AGENT."
  echo "    They update on reconnect. If a host has open sessions the restart is DEFERRED —"
  echo "    force it with the ↑ v$NEW_AGENT button on its card."
  TODO=$((TODO + 1))
elif [ "${BEHIND:-}" = "0" ]; then
  echo "  all agents are up to date (v$NEW_AGENT)"
fi

# TLS certificates (3.6.7). Incident 2026-10-12: a wildcard sat in the HTTP-01 store, which can
# never renew it, and Traefik logged the failure daily for weeks while every upgrade said "✓".
# READ-ONLY here (`--report` writes nothing, not even a backup): we only say it out loud. Fixing
# is a deliberate `cert-renew.sh --domain …` / `--prune-unrouted --yes` by a human.
if [ -x scripts/cert-renew.sh ]; then
  CERT_REPORT=$(timeout 60 scripts/cert-renew.sh --report 2>&1) || true
  if printf '%s\n' "$CERT_REPORT" | grep -q '^WARN: '; then
    printf '%s\n' "$CERT_REPORT" | sed -n 's/^WARN: //p' | while IFS= read -r w; do
      warn "certificate: $w"
    done
    echo "    Details: $ROOT/scripts/cert-renew.sh --report  ·  fix: --domain <name> or --prune-unrouted"
    echo "    (docs/INSTALL.md, \"TLS certificates\"). Nothing was changed."
    TODO=$((TODO + 1))
  elif printf '%s\n' "$CERT_REPORT" | grep -q '^OK: '; then
    echo "  certificates: $(printf '%s\n' "$CERT_REPORT" | sed -n 's/^OK: //p' | head -n1)"
  else
    warn "certificate report unavailable: $(printf '%s\n' "$CERT_REPORT" | tail -n1)"
  fi
fi

# FL-12: the host kit, verified on disk — not assumed from the sync above. A run made by an
# upgrade.sh older than 3.6.9 ends with "✓" and without it; a run whose image had no (complete)
# deploy kit too. Whatever path led here: when a 3.6.8+ host script is not on this host, say so
# in a way that cannot be missed, and say what to do. Two readings: against `$KIT` (this run's
# extracted kit) when there is one, and — when there was none to compare against (extraction
# failed) — the bare fact that host-health.sh (shipped since 3.6.8) is absent. A kit that was read
# and simply does not ship it (a deliberate downgrade below 3.6.8) is not a finding. Both readings
# count as a to-do, so the run never ends with "fully up to date" while the host checks do not exist.
KIT_MISSING=""
for f in scripts/host-health.sh scripts/cert-renew.sh scripts/docker-cleanup.sh scripts/authentik-upgrade.sh; do
  [ -f "$KIT/$f" ] && [ ! -f "$f" ] && KIT_MISSING="$KIT_MISSING $f"
done
if [ -n "$KIT_MISSING" ]; then
  warn "HOST KIT NOT INSTALLED — the host-side scripts this release ships are missing on this host:"
  warn "  $KIT_MISSING"
  warn "  Without them there is no host health (disk, Docker, certificates) and no timers, while"
  warn "  Settings → System health shows the host checks without data. The sync step above did not"
  warn "  install them — see its warning (usually the image's deploy kit was incomplete or unreadable)."
  warn "  Once that is fixed, run once more:  cd $ROOT && sudo ./upgrade.sh"
  warn "  then check:     systemctl list-timers 'webterm-*'   (docs/INSTALL.md, \"Upgrading from a version before 3.6.9\")"
  TODO=$((TODO + 1))
elif [ "${KIT_NONE:-0}" = 1 ] && [ ! -x scripts/host-health.sh ]; then
  warn "HOST KIT NOT INSTALLED — scripts/host-health.sh is missing and this run had no deploy kit to"
  warn "  sync it from (see the warning under \"Syncing host files\"): no host health, no timers, while"
  warn "  Settings → System health shows the host checks without data."
  warn "  Once that is fixed, run once more:  cd $ROOT && sudo ./upgrade.sh"
  warn "  then check:     systemctl list-timers 'webterm-*'   (docs/INSTALL.md, \"Upgrading from a version before 3.6.9\")"
  TODO=$((TODO + 1))
elif [ "${OLD_STYLE_PREV:-0}" = 1 ]; then
  echo "  host kit: installed in this run (the previous upgrade, made by an upgrade.sh older than 3.6.9, had left it out)"
  echo "    check: systemctl list-timers 'webterm-*'  — webterm-host-health and webterm-docker-cleanup should be listed"
fi

# System health (3.6.8): the SAME list as Settings → System health, read from the running gateway
# (one source of truth). It waits up to 45 s for a check pass newer than the host-health run above.
say "System health"
if HEALTH=$(docker exec "${APP_CID:-nimic}" python3 -m app.admin health --wait 45 \
              --newer-than "${HH_T:-0}" 2>/dev/null); then
  printf '%s\n' "$HEALTH" | sed 's/^/  /'
  HN=$(printf '%s\n' "$HEALTH" | grep -cE '^\[(CRITICAL|WARNING)\]' || true)
  TODO=$((TODO + ${HN:-0}))
else
  warn "health report unavailable (docker exec ${APP_CID:-<container>} python3 -m app.admin health)"
fi

if [ "$TODO" = 0 ]; then
  echo "  nothing — the system is fully up to date"
fi

# 3.6.9: which kit files this run installed or updated (the banner used to say nothing about it)
if [ "${WEBTERM_UPGRADE_REEXEC:-0}" = 1 ]; then
  echo "  upgrade.sh: this run switched to the release's own upgrade.sh (old → upgrade.sh.bak)"
fi
if [ -n "${KIT_DONE:-}" ]; then
  echo "  host kit files changed in this run:$KIT_DONE"
else
  echo "  host kit files: none changed in this run"
fi

# Bannerul raporta ŢINTA, nu realitatea. `deploy.sh` face `exec ./rollback.sh` când imaginea
# nouă nu devine healthy, iar un rollback reuşit iese cu 0 — deci upgrade.sh continua şi anunţa
# verde „Upgrade complet: v2.1.0" pe o instalare care tocmai revenise la v2.0.0. Comparăm cu
# imaginea care rulează chiar acum, citită mai sus la pasul de verificare.
# RC4-M1: trei stări distincte, fiecare din ce s-a citit, nu dedusă: ID-ul verificat + healthy = aplicat;
# ID-ul verificat dar nu healthy = aplicat, NU sănătos (fără „rollback" — nu a avut loc); ID-ul de dinainte
# = rollback real; orice alt ID = stare necunoscută. Doar primul caz iese cu 0.
if [ -n "$CHECKED_ID" ] && [ "$RUNNING_ID" = "$CHECKED_ID" ] && [ "$HEALTH_STATE" = healthy ]; then
  printf '\n\033[32m✓ Upgrade complete: %s (gateway v%s, agent v%s)\033[0m\n' "$TARGET" "$NEW_VER" "$NEW_AGENT"
  echo "  pinned: $IMAGE"
  echo "  running: $RUNNING_ID (the checked image), healthy"
elif [ -n "$CHECKED_ID" ] && [ "$RUNNING_ID" = "$CHECKED_ID" ]; then
  printf '\n\033[1;33m! Upgrade APPLIED but the container is NOT healthy (%s)\033[0m\n' "$HEALTH_STATE"
  echo "  The checked image $TARGET is running ($RUNNING_ID); no rollback took place."
  echo "  See 'docker logs ${APP_CID:-<container>}' and Settings → System health."
  exit 1
elif [ -n "$BEFORE_ID" ] && [ "$RUNNING_ID" = "$BEFORE_ID" ]; then
  printf '\n\033[1;33m! Upgrade ROLLED BACK: the previous image is running again (%s), not %s\033[0m\n' "$RUNNING_ID" "$TARGET"
  echo "  The new image did not become healthy and deploy.sh rolled back (state now: $HEALTH_STATE)."
  echo "  See 'docker logs ${APP_CID:-<container>}' for the reason."
  exit 1
else
  printf '\n\033[1;31m✗ Upgrade state UNKNOWN: running image id %s is neither the checked one (%s) nor the previous one (%s)\033[0m\n' \
    "${RUNNING_ID:-?}" "${CHECKED_ID:-?}" "${BEFORE_ID:-none}"
  echo "  State: $HEALTH_STATE. Check 'docker ps' / 'docker logs ${APP_CID:-<container>}' before doing anything else."
  exit 1
fi
