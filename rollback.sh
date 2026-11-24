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
# RC4-L1: planurile vechi se curăţă doar dacă lacătul e luat acum (fd 9 neprimit de la un părinte)
WT_RUN_START=$(date +%s); WT_SWEEP=1; [ -e "/proc/$$/fd/9" ] && WT_SWEEP=0
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
plan_sweep "$PWD"

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
# RC3-H1: planul final se randează o dată (cu ID-ul verificat), iar re-verificarea şi `up` folosesc
# exact acel fişier; o randare refuzată readuce .env şi .prev-image, ca orice refuz de aici
CHECKED_PLAN="$GUARD_PLAN" CHECKED_ID="$GUARD_ID"
# RC4-L1: şi la Ctrl-C / TERM (exit din trap rulează trap-ul EXIT)
trap plan_cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
if ! render_checked "$FILE" "$PREV" "$CHECKED_ID" "${PREV_TAG:-$PREV}" \
   || ! guard_recheck "$PREV" "$PLAN_FILE" "$CHECKED_PLAN" "$CHECKED_ID"; then
  set_env WEBTERM_IMAGE "$CUR"
  set_env WEBTERM_IMAGE_TAG "$CUR_TAG"
  printf '%s\n' "$PREV" > "$PREV_FILE"
  if [ -n "$PREV_TAG" ]; then printf '%s\n' "$PREV_TAG" > .prev-image-tag; else rm -f .prev-image-tag; fi
  exit 1
fi
# RC2-H1: porneşte exact ID-ul verificat (fără pull/build): un tag mutabil în .prev-image, re-indicat
# între verificare şi `up`, nu mai schimbă ce porneşte; .env rămâne pe referinţa umană ($PREV)
up_checked "$CHECKED_ID" "${PREV_TAG:-$PREV}" "$PLAN_FILE" app || exit 1

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
# RC2-H1: containerul porneşte pe ID-ul verificat, deci se compară ID-ul imaginii, nu referinţa
RUNNING=$(docker inspect -f '{{.Image}}' "$APP_ID" 2>/dev/null || echo "?")
if [ "$RUNNING" != "$CHECKED_ID" ]; then
  echo "✗ Rollback did NOT take effect: the container is running image $RUNNING, not $PREV ($CHECKED_ID)."
  echo "  .env now says $PREV. Check for a WEBTERM_IMAGE exported in your shell, then run ./rollback.sh"
  echo "  again or ./deploy.sh with the version you want."
  exit 1
fi
if [ "$st" = healthy ]; then
  echo "✓ Rollback done — the app is running $PREV${PREV_TAG:+ ($PREV_TAG)} (healthy)."
else
  echo "✗ The app did not report healthy within 90s (status: $st). Logs:"
  docker logs --tail 30 "$APP_ID" || true
  exit 1
fi
