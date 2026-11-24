#!/usr/bin/env bash
# WebTerm — roll production back to the image from before the last deploy.
# The panic button for when an update breaks the UI or the gateway and there is
# nothing you can do from the web interface: SSH into the server and run
#   cd /opt/webterm && ./rollback.sh
# It needs neither network nor CI: the previous image is already on the machine.
# Rollback is reversible — running ./rollback.sh again brings you forward (swap).
#
# What `.prev-image` holds is whatever `WEBTERM_IMAGE` was before the last deploy — since
# `upgrade.sh` pins by DIGEST (`ghcr.io/…/webterm@sha256:…`), that is a digest: the exact
# bytes that were running, not a tag that the registry may have re-pointed since. The
# human-readable tag travels alongside in `.prev-image-tag` (UI label only).
set -euo pipefail
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

FILE=docker-compose.prod.yml
COMPOSE="docker compose"
docker compose version >/dev/null 2>&1 || COMPOSE="docker-compose"

# set_env KEY VALUE — rewrites `.env` in-process (bash builtins only). The previous
# `sed -i "s|^K=.*|K=$V|"` put the value in sed's argv and interpreted `&`, `|` and `\`
# inside it; a rewrite loop has neither problem. Same helper as deploy.sh/install.sh.
set_env() {
  local k="$1" v="$2" tmp found=0 line
  tmp=$(mktemp .env.XXXXXX)
  if [ -f .env ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in
        "$k="*) [ "$found" = 1 ] && continue; printf '%s=%s\n' "$k" "$v"; found=1 ;;
        *) printf '%s\n' "$line" ;;
      esac
    done < .env > "$tmp"
  fi
  [ "$found" = 1 ] || printf '%s=%s\n' "$k" "$v" >> "$tmp"
  chmod 600 "$tmp" && mv "$tmp" .env
}

PREV_FILE=.prev-image
if [ ! -f "$PREV_FILE" ] || [ ! -s "$PREV_FILE" ]; then
  echo "✗ No $PREV_FILE — no previous deploy recorded to go back to."
  echo "  Manual alternative: point WEBTERM_IMAGE in .env at a known-good tag or digest"
  echo "  (docker images --digests | grep webterm), then: $COMPOSE -f $FILE up -d app"
  exit 1
fi
PREV=$(head -1 "$PREV_FILE")
PREV_TAG=$([ -f .prev-image-tag ] && head -1 .prev-image-tag || true)
CUR=$(grep '^WEBTERM_IMAGE=' .env | head -1 | cut -d= -f2- || true)
CUR_TAG=$(grep '^WEBTERM_IMAGE_TAG=' .env | head -1 | cut -d= -f2- || true)

if [ "$PREV" = "$CUR" ]; then
  echo "✗ The previous image ($PREV) is the same as the current one — nothing to do."
  exit 1
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

# H1: înainte ca .env sau .prev-image să fie atinse — un refuz nu schimbă nimic
guard_pre38 "$PREV" "$FILE" || exit 1

echo "→ Rollback: ${CUR:-<unset>} → $PREV${PREV_TAG:+ ($PREV_TAG)}"
set_env WEBTERM_IMAGE "$PREV"
set_env WEBTERM_IMAGE_TAG "$PREV_TAG"
# swap: what is running now becomes the target of the next rollback (roll-forward)
[ -n "$CUR" ] && printf '%s\n' "$CUR" > "$PREV_FILE"
if [ -n "$CUR_TAG" ]; then printf '%s\n' "$CUR_TAG" > .prev-image-tag; else rm -f .prev-image-tag; fi

# `.env` e sursa de adevăr AICI, iar mediul o bate. `deploy.sh` exportă `WEBTERM_IMAGE` cu
# imaginea NOUĂ şi apoi face `exec ./rollback.sh` — deci variabila exportată supravieţuia, iar
# compose o prefera fişierului pe care tocmai îl rescrisesem. Rezultat: `up -d app` re-rezolva
# la imaginea STRICATĂ, containerul nu era recreat („Running", nu „Recreated"), iar rollback-ul
# automat pe care documentaţia îl listează ca strat de apărare nu făcea nimic. Verificat:
# `WEBTERM_IMAGE=x docker compose config` întoarce `x`, nu valoarea din `.env`.
unset WEBTERM_IMAGE WEBTERM_IMAGE_TAG
# R-H1: planul /data verificat mai sus trebuie să fie exact cel pe care îl porneşte `up` (cu .env-ul
# rescris şi mediul curăţat); altfel .env şi .prev-image revin la ce erau şi nu porneşte nimic
CHECKED_PLAN="$GUARD_PLAN" CHECKED_ID="$GUARD_ID"
if ! guard_recheck "$PREV" "$FILE" "$CHECKED_PLAN" "$CHECKED_ID"; then
  set_env WEBTERM_IMAGE "$CUR"
  set_env WEBTERM_IMAGE_TAG "$CUR_TAG"
  printf '%s\n' "$PREV" > "$PREV_FILE"
  if [ -n "$PREV_TAG" ]; then printf '%s\n' "$PREV_TAG" > .prev-image-tag; else rm -f .prev-image-tag; fi
  exit 1
fi
$COMPOSE -f "$FILE" up -d app

# wait for the healthcheck verdict, so you do not walk away from the keyboard guessing
APP_ID=$($COMPOSE -f "$FILE" ps -q app)
st=starting
for _ in $(seq 1 45); do
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$APP_ID" 2>/dev/null || echo missing)
  [ "$st" = healthy ] && break
  sleep 2
done
# Ce RULEAZĂ, nu ce am cerut. Mesajul de succes raporta `$PREV` fără să verifice nimic, deci
# anunţa „✓ Rollback done — the app is running v2.0.0" pe un container rămas pe imaginea veche.
RUNNING=$(docker inspect -f '{{.Config.Image}}' "$APP_ID" 2>/dev/null || echo "?")
if [ "$RUNNING" != "$PREV" ]; then
  echo "✗ Rollback did NOT take effect: the container is running $RUNNING, not $PREV."
  echo "  .env now says $PREV. Check for a WEBTERM_IMAGE exported in your shell, then:"
  echo "    env -u WEBTERM_IMAGE $COMPOSE -f $FILE up -d app"
  exit 1
fi
if [ "$st" = healthy ]; then
  echo "✓ Rollback done — the app is running $PREV${PREV_TAG:+ ($PREV_TAG)} (healthy)."
else
  echo "✗ The app did not report healthy within 90s (status: $st). Logs:"
  docker logs --tail 30 "$APP_ID" || true
  exit 1
fi
