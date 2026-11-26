"""`deploy.sh`, `rollback.sh` şi filtrul de imagini din `remove.sh` — rulate pe bune, cu `docker` simulat.

M4 din auditul de deploy (2026-10-04): niciun test nu EXECUTA scripturile de deploy — `upgrade_script_test`
le înlocuia cu shim-uri, deci `deploy.sh` (care refuza referinţele pe digest, scria secretele prin `sed`
cu valoarea în argv şi fără escapare) şi `rollback.sh` nu fuseseră rulate niciodată de CI. Aici rulează
într-un director-sandbox, cu `docker`/`curl`/`systemctl` înlocuite de stub-uri care ÎNREGISTREAZĂ fiecare
apel (argv complet, NUL-separat) şi răspund ca un daemon pe care compose l-a pinuit pe digest.

`remove.sh` NU e rulat dincolo de confirmare: coada lui şterge `/etc/systemd/system/webterm-*`,
`/etc/default/webterm-backup` şi `/var/backups/webterm` pe căi FIXE, iar testele rulează şi ca root pe
maşini care chiar au o instalare. Pasul de imagini (singurul care s-a schimbat, L3) e extras din script
şi rulat izolat cu acelaşi stub `docker`; gărzile de dinaintea confirmării sunt în `upgrade_script_test`.
"""
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


OLD = "ghcr.io/x/webterm@sha256:" + "0" * 64          # ce rula înainte (pinuit pe digest)
NEW = "ghcr.io/x/webterm@sha256:" + "1" * 64          # ce instalăm acum
SETUP_IN_ENV = "tok-din-env-SECRET-7f3a"                # secretele care trebuie să PLECE din .env
CF_IN_ENV = "cf&tok|en\\slash-SECRET"                   # cu caractere pe care sed le interpreta

DOCKER_SHIM = r'''#!/bin/sh
echo "docker $*" >> "$CALLS"
for a in "$@"; do printf '%s\0' "$a" >> "$ARGV_LOG"; done
case "$1 $2" in "compose version") exit 0 ;; esac
# RC3-H1: `-f <fişier>`; un plan randat (.wt-plan.*) e citit de compose aşa cum e (nimic de interpolat)
pf=""; _p=""; for a in "$@"; do [ "$_p" = "-f" ] && pf="$a"; _p="$a"; done
PIMG=""
case "$pf" in .wt-plan.*) [ -f "$pf" ] && PIMG=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["services"]["app"]["image"])' "$pf") ;; esac
# ID-urile de imagine au forma reală (sha256:<64 hex>), derivate determinist din referinţă
# (CALLS.ids ţine perechile ID → referinţă, ca eticheta de versiune să se citească şi pe ID)
sid() { _h="sha256:$(printf '%s' "$1" | sha256sum | cut -c1-64)"; echo "$_h $1" >> "$CALLS.ids"; echo "$_h"; }
# imaginea pe care compose ar porni-o: variabila din mediu bate .env (exact ca la compose real),
# altfel linia din .env din directorul curent
img="${WEBTERM_IMAGE:-$(grep -m1 '^WEBTERM_IMAGE=' .env 2>/dev/null | cut -d= -f2-)}"
case "$*" in
  # garda 3.8 (H1) şi detecţia instalării noi (M4)
  "volume ls"*) [ -n "${VOL_LS_FAIL:-}" ] && exit 1; [ -n "${VOLUMES-x}" ] && printf '%s\n' "${VOLUMES-proj_webterm-data}"; exit 0 ;;
  # R-H1: planul compose (JSON) şi programul care îl citeşte (rulat aici cu python-ul gazdei)
  *"config --format json"*) [ -n "${CFG_FAIL:-}" ] && exit 1
    case "$pf" in .wt-plan.*) cat "$pf"; exit 0 ;; esac
    echo "render WEBTERM_IMAGE=$img" >> "$CALLS"
    # @IMG@ = interpolarea lui ${WEBTERM_IMAGE} pe care o face compose (services.app.image)
    if [ -n "${JSON_AFTER_SWAP:-}" ] && grep -qxF "WEBTERM_IMAGE=${SWAP_REF:-}" .env 2>/dev/null; then
      printf '%s' "$JSON_AFTER_SWAP" | sed "s|@IMG@|$img|g"; exit 0; fi
    # RC3-H1: @OIDC@ = ${WEBTERM_OIDC_ISSUER}; JSON_AFTER_SSO = alt plan odată ce SSO e legat
    oidc="${WEBTERM_OIDC_ISSUER:-}"
    if [ -n "$oidc" ] && [ -n "${JSON_AFTER_SSO:-}" ]; then
      printf '%s' "$JSON_AFTER_SSO" | sed "s|@IMG@|$img|g; s|@OIDC@|$oidc|g"; exit 0; fi
    printf '%s' "${COMPOSE_JSON:-$DEFAULT_JSON}" | sed "s|@IMG@|$img|g; s|@OIDC@|$oidc|g"; exit 0 ;;
  *wt-compose-render*) eval "prog=\${$#}"; [ -n "${RENDER_RUN_FAIL:-}" ] && exit 125; exec python3 -I -c "$prog" ;;
  *wt-compose-plan*) eval "prog=\${$#}"; [ -n "${PLAN_RUN_FAIL:-}" ] && exit 125; exec python3 -I -c "$prog" ;;
  *"compose -f"*" config"*) printf '%b' "${COMPOSE_CFG:-}"; exit 0 ;;
  *"ps -a -q app"*) [ -n "${PS_FAIL:-}" ] && exit 1; [ -n "${APP_PS-x}" ] && printf '%s\n' "${APP_PS-cid-app-1}"; exit 0 ;;
  *image.version*)
    _r="${*##* }"; _m=$(grep -m1 "^$_r " "$CALLS.ids" 2>/dev/null | cut -d' ' -f2-)
    case "$* ${_m}" in *1111111111*) echo "${NEW_LABEL-${IMG_LABEL:-}}" ;; *) echo "${IMG_LABEL:-}" ;; esac; exit 0 ;;
  *'"/data"'*) printf '%b\n' "${DATA_MOUNT:-volume\tproj_webterm-data}"; exit 0 ;;
  *"--entrypoint ls"*) [ -n "${LS_FAIL:-}" ] && exit 125; printf '%b' "${VOL_LS:-}"; exit 0 ;;
  *"ps -q app"*) echo "cid-app-1"; exit 0 ;;
  # RC2-H1: ce imagine porneşte `up` (WEBTERM_IMAGE din mediul apelului) = ce raportează containerul
  *"compose "*" up "*) echo "up-image=${WEBTERM_IMAGE:-} up-label=${WEBTERM_IMAGE_TAG:-} up-plan=${PIMG:-none}" >> "$CALLS"
    # RC4-M2: STARTED_AFTER_SSO = ID-ul pe care îl raportează containerul după re-up-ul SSO (OIDC în .env)
    if [ -n "${STARTED_AFTER_SSO:-}" ] && grep -q '^WEBTERM_OIDC_ISSUER=.' .env 2>/dev/null; then
      printf '%s\n' "$STARTED_AFTER_SSO" > "$CALLS.started"
    else printf '%s\n' "${PIMG:-$img}" > "$CALLS.started"; fi; exit ${UP_FAILS:-0} ;;
  # RC2-H2: ENV-ul imaginii verificate
  *Config.Env*) printf '%b\n' "${IMG_ENV-PATH=/usr/bin\nWEBTERM_DATA_DIR=/data}"; exit 0 ;;
  *"compose -f"*"pull"*) exit ${PULL_FAILS:-0} ;;
  *"compose -f"*) exit 0 ;;
esac
case "$1" in
  login|logs|rmi) exit 0 ;;
  context) echo "${CTX_HOST-unix:///var/run/docker.sock}"; exit 0 ;;
  ps) [ "$2" = "-aq" ] && printf 'c-foreign\n'; exit 0 ;;
  inspect)
    case "$*" in
      *Config.Image*) echo "$img" ;;
      *"{{.Image}}"*)
        case "$*" in *cid-app-1*) if [ -s "$CALLS.started" ]; then cat "$CALLS.started"; else sid foreign-uses; fi ;;
                     *) sid foreign-uses ;; esac ;;
      *) if [ -n "${HEALTH_AFTER_SSO:-}" ] && grep -q '^WEBTERM_OIDC_ISSUER=.' .env 2>/dev/null; then
           echo "$HEALTH_AFTER_SSO"; else echo "${HEALTH:-healthy}"; fi ;;
    esac; exit 0 ;;
  image)
    case "$*" in
      *RepoDigests*) exit 0 ;;
      *"{{.Id}}"*)
        # ID-uri de imagine: fiecare referinţă (ultimul argument) îşi are al ei; cea din
        # IN_USE_REF e „folosită" de un container străin (acelaşi ID ca `{{.Image}}` de mai sus)
        ref="${*##* }"
        [ -n "${ID_MISSING:-}" ] && [ "$ref" = "$ID_MISSING" ] && exit 1
        # un ID (sha256:<64 hex>) se rezolvă la el însuşi, ca la daemonul real (planul randat îl conţine)
        case "$ref" in sha256:*) [ ${#ref} = 71 ] && { echo "$ref"; exit 0; } ;; esac
        # RC-H1: ID_FLIP = referinţa al cărei ID se schimbă după prima rezolvare (un pull între verificare şi `up`)
        if [ -n "${ID_FLIP:-}" ] && [ "$ref" = "$ID_FLIP" ]; then
          if [ -e "$CALLS.idflip" ]; then sid "$ref-repointed"; else : > "$CALLS.idflip"; sid "$ref"; fi
          exit 0; fi
        if [ -n "${IN_USE_REF:-}" ] && [ "$ref" = "$IN_USE_REF" ]; then sid foreign-uses; else sid "$ref"; fi
        exit 0 ;;
      *) exit ${IMAGE_MISSING:-0} ;;
    esac ;;
  images)
    case "$*" in
      *--digests*) printf '%s\n' "ghcr.io/x/webterm@sha256:$(printf 'd%.0s' $(seq 1 64))"; exit 0 ;;
      *) printf '%s\n' "ghcr.io/x/webterm:v1" "ghcr.io/x/webterm:v2"; exit 0 ;;
    esac ;;
esac
exit 0
'''

CURL_SHIM = r'''#!/bin/sh
echo "curl $*" >> "$CALLS"
for a in "$@"; do printf '%s\0' "$a" >> "$ARGV_LOG"; done
[ -t 0 ] || cat >> "$CURL_STDIN"
case "$*" in *api/state*) echo '{"setup_required": true}' ;; *users/me*) echo "${AK_CODE:-000}" ;; *) echo 000 ;; esac
exit 0
'''


def sandbox(tmp, env_txt=None):
    d = pathlib.Path(tmp)
    (d / "bin").mkdir(exist_ok=True)
    for name in ("deploy.sh", "rollback.sh"):
        shutil.copy(ROOT / name, d / name)
        os.chmod(d / name, 0o755)
    shutil.copy(ROOT / ".env.prod.example", d / ".env.prod.example")
    (d / "docker-compose.prod.yml").write_text("services: {app: {}}\n")
    if env_txt is None:
        env_txt = ("WEBTERM_DOMAIN=term.test\nLETSENCRYPT_EMAIL=a@b.test\nGHCR_USER=x\n"
                   f"WEBTERM_IMAGE={OLD}\nWEBTERM_IMAGE_TAG=ghcr.io/x/webterm:v1.0.0\n"
                   f"WEBTERM_SETUP_TOKEN={SETUP_IN_ENV}\nCF_DNS_API_TOKEN={CF_IN_ENV}\n"
                   "WEBTERM_OIDC_ISSUER=\n")
    (d / ".env").write_text(env_txt)
    os.chmod(d / ".env", 0o600)
    # `sleep` stubuit: bucla de sănătate din deploy.sh aşteaptă până la 120 s, cea din rollback.sh
    # 90 s — pe calea „unhealthy" testul ar dura 3½ minute. Logica (numărul de încercări, ordinea)
    # e aceeaşi; doar aşteptarea dispare.
    for name, body in (("docker", DOCKER_SHIM), ("curl", CURL_SHIM),
                       ("systemctl", '#!/bin/sh\necho "systemctl $*" >> "$CALLS"\nexit 0\n'),
                       ("sleep", '#!/bin/sh\nexit 0\n')):
        p = d / "bin" / name
        p.write_text(body)
        os.chmod(p, 0o755)
    return d


def cfg_json(volname="proj_webterm-data", mount=None, vols=None):
    """`docker compose config --format json` cum îl scrie compose v2 (doar ce citeşte planul)."""
    m = mount or {"type": "volume", "source": "webterm-data", "target": "/data", "volume": {}}
    return json.dumps({"name": "proj", "services": {"app": {"image": "@IMG@", "volumes": [m]}},
                       "volumes": vols if vols is not None else {"webterm-data": {"name": volname}}})


DEFAULT_JSON = cfg_json()


def run(d, script, args=(), stdin=None, **extra):
    calls = d / "calls.log"
    calls.write_text("")
    pathlib.Path(str(calls) + ".started").unlink(missing_ok=True)
    (d / "argv.log").write_bytes(b"")
    (d / "curl-stdin.log").write_text("")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("WEBTERM_", "CF_", "AUTHENTIK_", "PG_"))}
    env.update(PATH=f"{d/'bin'}:{os.environ['PATH']}", CALLS=str(calls), ARGV_LOG=str(d / "argv.log"),
               DEFAULT_JSON=DEFAULT_JSON,
               CURL_STDIN=str(d / "curl-stdin.log"), **extra)
    r = subprocess.run(["bash", str(d / script), *args], cwd=str(d), env=env, capture_output=True,
                       text=True, timeout=120, input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL)
    return r, calls.read_text()


def sid(ref):
    """ID-ul pe care stub-ul `docker` îl dă referinţei (sha256 al textului)."""
    import hashlib
    return "sha256:" + hashlib.sha256(ref.encode()).hexdigest()


def env_of(d):
    out = {}
    for line in (d / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v
    return out


def argv_text(d):
    return (d / "argv.log").read_bytes().decode("utf-8", "replace")


def secret(d, name):
    return (d / "secrets" / name).read_text().rstrip("\n")


def mode(p):
    return stat.S_IMODE(p.stat().st_mode)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        # ── 1. deploy pe DIGEST (ce trimite upgrade.sh) + migrarea secretelor ──────────────
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        r, calls = run(d, "deploy.sh", [NEW, "--tag", "v9.9.9"])
        out = r.stdout + r.stderr
        check("deploy pe referinţă @sha256 rulează până la capăt (nu mai e 'Invalid tag')", r.returncode == 0, out[-600:])
        e = env_of(d)
        check(".env pinuieşte DIGESTUL", e.get("WEBTERM_IMAGE") == NEW, e.get("WEBTERM_IMAGE"))
        check("eticheta lizibilă stă separat (WEBTERM_IMAGE_TAG), cu repo-ul din referinţă",
              e.get("WEBTERM_IMAGE_TAG") == "ghcr.io/x/webterm:v9.9.9", e.get("WEBTERM_IMAGE_TAG"))
        check(".prev-image = digestul de DINAINTE (ţinta de rollback), nu un tag",
              (d / ".prev-image").read_text().strip() == OLD)
        check(".prev-image-tag păstrează eticheta veche",
              (d / ".prev-image-tag").read_text().strip() == "ghcr.io/x/webterm:v1.0.0")
        check("pull + up prin compose, apoi verdictul de sănătate",
              "docker compose -f docker-compose.prod.yml pull" in calls
              and "docker compose -p proj -f .wt-plan." in calls and "up -d --pull never --no-build --remove-orphans" in calls
              and calls.index("pull") < calls.index("up -d") < calls.index("docker inspect -f", calls.index("up -d")), calls)
        check("ce RULEAZĂ e raportat la final", NEW in out, out[-400:])
        # secretele: din .env → fişiere, .env golit
        check("secrets/ e creat 0700", (d / "secrets").is_dir() and mode(d / "secrets") == 0o700,
              oct(mode(d / "secrets")) if (d / "secrets").exists() else "lipsă")
        check("toate cele 8 fişiere există (compose refuză un bind lipsă), 0644 ca să le citească uid 10001/70/1000",
              all((d / "secrets" / n).is_file() and mode(d / "secrets" / n) == 0o644 for n in
                  ("webterm_setup_token", "webterm_oidc_client_secret", "webterm_smtp_password", "cf_dns_api_token",
                   "authentik_secret_key", "pg_pass", "authentik_bootstrap_password", "authentik_bootstrap_token")),
              str(sorted(p.name for p in (d / "secrets").iterdir())))
        check("tokenul de setup a fost MUTAT din .env în fişier",
              secret(d, "webterm_setup_token") == SETUP_IN_ENV and e.get("WEBTERM_SETUP_TOKEN") == "",
              (secret(d, "webterm_setup_token"), e.get("WEBTERM_SETUP_TOKEN")))
        check("tokenul Cloudflare cu `&|\\` a ajuns VERBATIM în fişier (fără sed, fără escapare)",
              secret(d, "cf_dns_api_token") == CF_IN_ENV and e.get("CF_DNS_API_TOKEN") == "",
              (secret(d, "cf_dns_api_token"), e.get("CF_DNS_API_TOKEN")))
        check("mutarea e anunţată", "moved WEBTERM_SETUP_TOKEN" in out and "moved CF_DNS_API_TOKEN" in out, out[:800])
        check("cu token CF (din fişier) resolverul e DNS-01 + wildcard",
              e.get("WEBTERM_CERT_RESOLVER") == "ledns" and "sans=*.term.test" in e.get("WEBTERM_CERT_LABEL_SANS", ""),
              (e.get("WEBTERM_CERT_RESOLVER"), e.get("WEBTERM_CERT_LABEL_SANS")))
        check("tokenul de setup e tipărit din fişier cât timp setup-ul mai e necesar",
              SETUP_IN_ENV in out and "secrets/webterm_setup_token" in out, out[-500:])
        # L2: niciun secret în argv-ul vreunui proces (docker, curl, systemctl)
        argv = argv_text(d)
        check("niciun secret în argv-ul vreunui proces pornit de deploy.sh",
              SETUP_IN_ENV not in argv and CF_IN_ENV not in argv and "SECRET" not in argv, argv[-300:])
        check(".env rămâne 0600 după rescriere", mode(d / ".env") == 0o600, oct(mode(d / ".env")))
        # a doua rulare: idempotentă, fără „moved", fără alt token
        r2, _ = run(d, "deploy.sh")
        check("a doua rulare: nimic de mutat, tokenul rămâne acelaşi",
              r2.returncode == 0 and "moved" not in (r2.stdout + r2.stderr)
              and secret(d, "webterm_setup_token") == SETUP_IN_ENV, (r2.stdout + r2.stderr)[-300:])
        check("fără argument nu se schimbă pinul şi nu se rescrie .prev-image",
              env_of(d).get("WEBTERM_IMAGE") == NEW and (d / ".prev-image").read_text().strip() == OLD)

        # ── 2. formele acceptate / refuzate ale referinţei ────────────────────────────────
        d2 = sandbox(tempfile.mkdtemp(dir=tmp))
        r, _ = run(d2, "deploy.sh", ["sha256:" + "2" * 64])
        check("`sha256:<hex>` scurt → repo-ul implicit (GHCR_USER) @ digest",
              r.returncode == 0 and env_of(d2).get("WEBTERM_IMAGE") == "ghcr.io/x/webterm@sha256:" + "2" * 64,
              env_of(d2).get("WEBTERM_IMAGE"))
        d3 = sandbox(tempfile.mkdtemp(dir=tmp))
        r, _ = run(d3, "deploy.sh", ["v1.2.3"])
        check("un tag merge în continuare şi e propria lui etichetă",
              r.returncode == 0 and env_of(d3).get("WEBTERM_IMAGE") == "ghcr.io/x/webterm:v1.2.3"
              and env_of(d3).get("WEBTERM_IMAGE_TAG") == "ghcr.io/x/webterm:v1.2.3", env_of(d3))
        for bad in ("v1.0.0;rm -rf /", "sha256:abc", "ghcr.io/x/webterm@sha256:" + "z" * 64,
                    "ghcr.io/x/webterm@sha256:" + "3" * 63, "latest\nWEBTERM_IMAGE=evil", "../x"):
            db = sandbox(tempfile.mkdtemp(dir=tmp))
            r, callsb = run(db, "deploy.sh", [bad])
            check(f"referinţă invalidă {bad[:24]!r} → refuz, fără compose up, .env neatins",
                  r.returncode != 0 and "up -d" not in callsb and env_of(db).get("WEBTERM_IMAGE") == OLD,
                  (r.stdout + r.stderr)[-200:])
        db = sandbox(tempfile.mkdtemp(dir=tmp))
        r, _ = run(db, "deploy.sh", [NEW, "--tag", "v1;x"])
        check("--tag invalid → refuz", r.returncode != 0 and env_of(db).get("WEBTERM_IMAGE") == OLD)

        # ── 3. containerul nu devine healthy → rollback automat la digestul anterior ──────
        d4 = sandbox(tempfile.mkdtemp(dir=tmp))
        r, calls4 = run(d4, "deploy.sh", [NEW, "--tag", "v9.9.9"], HEALTH="unhealthy")
        out4 = r.stdout + r.stderr
        e4 = env_of(d4)
        check("unhealthy → deploy.sh face exec rollback.sh", "Rollback automat" in out4 and "Rollback:" in out4, out4[-700:])
        check("rollback-ul readuce DIGESTUL anterior în .env (nu un tag)", e4.get("WEBTERM_IMAGE") == OLD, e4.get("WEBTERM_IMAGE"))
        check("eticheta e readusă odată cu el", e4.get("WEBTERM_IMAGE_TAG") == "ghcr.io/x/webterm:v1.0.0", e4.get("WEBTERM_IMAGE_TAG"))
        check("digestul picat devine ţinta următorului rollback (swap)",
              (d4 / ".prev-image").read_text().strip() == NEW and (d4 / ".prev-image-tag").read_text().strip() == "ghcr.io/x/webterm:v9.9.9")
        check("rollback.sh porneşte app-ul FĂRĂ WEBTERM_IMAGE exportat (altfel compose re-rezolva la imaginea stricată)",
              calls4.count("--no-build app") == 1 and f"up-image={sid(OLD)} " in calls4, calls4)
        # stub-ul răspunde unhealthy şi rollback-ului → trebuie să o spună, nu să anunţe verde
        check("rollback-ul raportează că nici imaginea veche n-a devenit healthy (nu minte)",
              r.returncode != 0 and "did not report healthy" in out4, out4[-300:])

        # ── 4. rollback.sh singur: swap digest ↔ digest ──────────────────────────────────
        d5 = sandbox(tempfile.mkdtemp(dir=tmp))
        (d5 / ".prev-image").write_text(NEW + "\n")
        (d5 / ".prev-image-tag").write_text("ghcr.io/x/webterm:v9.9.9\n")
        r, calls5 = run(d5, "rollback.sh")
        e5 = env_of(d5)
        check("rollback.sh: .env ← .prev-image (digest), .prev-image ← fostul curent",
              r.returncode == 0 and e5.get("WEBTERM_IMAGE") == NEW and (d5 / ".prev-image").read_text().strip() == OLD,
              (r.stdout + r.stderr)[-300:])
        check("rollback.sh: etichetele se schimbă între ele",
              e5.get("WEBTERM_IMAGE_TAG") == "ghcr.io/x/webterm:v9.9.9"
              and (d5 / ".prev-image-tag").read_text().strip() == "ghcr.io/x/webterm:v1.0.0")
        check("rollback.sh: secretele din .env nu sunt atinse (nu e treaba lui)",
              e5.get("WEBTERM_SETUP_TOKEN") == SETUP_IN_ENV)
        check("rollback.sh raportează healthy pe ce RULEAZĂ", "✓ Rollback done" in r.stdout and NEW in r.stdout, r.stdout[-300:])
        (d5 / ".prev-image").write_text(NEW + "\n")
        r, _ = run(d5, "rollback.sh")
        check("rollback.sh: acelaşi digest în .env şi .prev-image → nimic de făcut, exit 1",
              r.returncode != 0 and "same as the current one" in r.stdout, r.stdout[-200:])
        (d5 / ".prev-image").unlink()
        r, calls_np = run(d5, "rollback.sh")
        check("rollback.sh fără .prev-image: alternativa manuală e ./deploy.sh <ref> (garda 3.8), nu compose up",
              r.returncode != 0 and "./deploy.sh <vX.Y.Z" in r.stdout and "up -d app" not in r.stdout
              and "up -d" not in calls_np, r.stdout[-400:])

        # ── 5. set_env (L1): valoarea cu `&`, `|`, `\` ajunge verbatim, fără proces extern ──
        # Extragem funcţia din fiecare script şi o rulăm pe un .env de jucărie: e EXACT codul
        # de producţie, nu o copie în test.
        for script in ("deploy.sh", "rollback.sh", "install.sh"):
            src = (ROOT / script).read_text()
            start = src.index("\nset_env() {")
            fn = src[start:src.index("\n}\n", start) + 3]
            check(f"{script}: set_env nu mai foloseşte sed (valoarea nu intră în argv-ul altui proces)",
                  "sed" not in fn, fn)
            de = pathlib.Path(tempfile.mkdtemp(dir=tmp))
            (de / ".env").write_text("A=1\nWEBTERM_OIDC_CLIENT_SECRET=old\nB=2\n")
            val = "s3c&r|e\\t/x$y`z"
            rr = subprocess.run(["bash", "-c", fn + '\nset_env WEBTERM_OIDC_CLIENT_SECRET "$1"\nset_env C "$2"', "_", val, "c&c"],
                                cwd=str(de), capture_output=True, text=True, timeout=30)
            got = env_of(de)
            check(f"{script}: set_env păstrează `&|\\$` verbatim, înlocuieşte în loc şi adaugă la final",
                  rr.returncode == 0 and got.get("WEBTERM_OIDC_CLIENT_SECRET") == val and got.get("C") == "c&c"
                  and list(got) == ["A", "WEBTERM_OIDC_CLIENT_SECRET", "B", "C"], (rr.stderr, got))
            check(f"{script}: .env rescris e 0600", mode(de / ".env") == 0o600, oct(mode(de / ".env")))

        # ── 6. remove.sh: şterge doar imaginile ACESTEI instalări (L3) ──────────────────
        src = (ROOT / "remove.sh").read_text()
        a = src.index('say "Removing the images"')
        b = src.index('echo "  images of ')
        block = src[a:src.index("\n", b)]
        dr = sandbox(tempfile.mkdtemp(dir=tmp))
        (dr / ".prev-image").write_text("ghcr.io/x/webterm:v2\n")
        prog = 'say() { :; }\nwarn() { :; }\n' + block + '\n'
        (dr / "images-step.sh").write_text(prog)
        r, callsr = run(dr, "images-step.sh", IN_USE_REF="ghcr.io/x/webterm:v2")
        check("pasul de imagini rulează curat", r.returncode == 0, r.stderr[-300:])
        check("şterge tag-urile repo-ului nostru care nu mai sunt folosite", "docker rmi ghcr.io/x/webterm:v1" in callsr, callsr)
        check("NU şterge o imagine folosită de un container al altei instalări (chiar dacă e .prev-image al nostru)",
              "docker rmi ghcr.io/x/webterm:v2" not in callsr and "kept ghcr.io/x/webterm:v2" in r.stdout, callsr + r.stdout)
        check("şterge şi referinţa pe digest a propriei imagini din .env", f"docker rmi {OLD}" in callsr, callsr)
        check("filtrul e pe REPO-ul din WEBTERM_IMAGE, nu pe orice ghcr.io/*/webterm",
              "docker images ghcr.io/x/webterm" in callsr and "ghcr.io/[^/]" not in block, callsr)
        code_lines = [l for l in block.splitlines() if not l.strip().startswith("#")]
        check("fără `rmi -f`: o imagine încă referită de un container nu e smulsă",
              "rmi -f" not in callsr and not any("rmi -f" in l for l in code_lines))

        # ── 7. FL-12 (audit 2026-10-17): deploy.sh rulat de un upgrade.sh mai vechi de 3.6.9 avertizează ──
        # Scriptul vechi sincronizează deploy.sh din kitul nou şi îl rulează cât timp propriul înlocuitor
        # mai aşteaptă ca upgrade.sh.new — singurul moment în care cod nou rulează în acea rundă veche.
        src = (ROOT / "deploy.sh").read_text()
        a = src.index("# FL-12 (audit 2026-10-17)")
        b = src.index("\nfi\n", a) + len("\nfi\n")
        block = src[a:b]
        check("deploy.sh: garda FL-12 e un bloc `if … fi` de sine stătător", block.rstrip().endswith("fi") and "upgrade.sh.new" in block)
        for label, new_present, reexec, expect in (
                ("upgrade.sh.new prezent + upgrade.sh FĂRĂ re-exec (rundă veche) → avertisment", True, False, True),
                ("fără upgrade.sh.new → tăcere", False, False, False),
                ("upgrade.sh.new prezent, dar upgrade.sh e deja ≥3.6.9 (WEBTERM_UPGRADE_REEXEC) → tăcere", True, True, False)):
            dg = pathlib.Path(tempfile.mkdtemp(dir=tmp))
            (dg / "guard.sh").write_text(block)
            (dg / "upgrade.sh").write_text("#!/bin/bash\n" + ("WEBTERM_UPGRADE_REEXEC=1\n" if reexec else "") + "echo old\n")
            if new_present:
                (dg / "upgrade.sh.new").write_text("#!/bin/bash\necho new\n")
            rg = subprocess.run(["bash", str(dg / "guard.sh")], cwd=str(dg), capture_output=True, text=True, timeout=30)
            warned = "run ./upgrade.sh once more" in rg.stderr and "older than 3.6.9" in rg.stderr
            check(f"deploy.sh FL-12: {label}", rg.returncode == 0 and warned == expect, (rg.returncode, rg.stderr[-300:]))
        check("deploy.sh FL-12: avertismentul merge pe stderr şi numeşte secţiunea din INSTALL.md",
              ">&2" in block and "Upgrading from a version before 3.6.9" in block
              and "Upgrading from a version before 3.6.9" in (ROOT / "docs" / "INSTALL.md").read_text())

        pre38_checks(tmp)
        master_key_checks(tmp)
        install_checks(tmp)
        rh1_checks(tmp)

    print(f"\n{ok}/{total} passed")
    return ok == total


MIGRATED = "webterm.db\\nkeys.wtk\\n.lock\\n.maint.lock\\n"
LEGACY = "webterm.db\\nsecret\\n.lock\\n.maint.lock\\n"


def pre38_checks(tmp):
    """H1 (recenzia PR4): nicio imagine < 3.8 nu porneşte pe un volum migrat — nici rollback-ul
    manual, nici cel automat din deploy.sh, nici un deploy ţintit spre o versiune veche."""
    print("── 8. 3.8 migration boundary (rollback / deploy to a pre-3.8 image)")

    def rb(**extra):
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        (d / ".prev-image").write_text(NEW + "\n")
        before = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        r, calls = run(d, "rollback.sh", **extra)
        after = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        return r, calls, before == after

    r, calls, same = rb(IMG_LABEL="v3.7.1", VOL_LS=MIGRATED)
    out = r.stdout + r.stderr
    check("rollback.sh spre v3.7.1 pe un volum cu keys.wtk → refuz", r.returncode != 0 and "migrated to 3.8" in out, out[-500:])
    check("….env şi .prev-image neatinse, niciun `up`", same and "up -d" not in calls, calls)
    check("…spune ce e de făcut (rămâi pe 3.8 sau restaurează backup-ul de dinainte de migrare)",
          "stay on 3.8" in out and "BEFORE the migration" in out, out[-500:])
    check("…volumul e listat read-only, fără reţea, cu imaginea ţintă",
          f"--network none -v proj_webterm-data:/data:ro --entrypoint ls {sid(NEW)}" in calls, calls)
    r, calls, same = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY)
    check("rollback.sh spre v3.7.1 pe un volum 3.7 (secret, lacăte) → merge", r.returncode == 0 and not same,
          (r.stdout + r.stderr)[-300:])
    r, calls, same = rb(IMG_LABEL="v3.8.2", VOL_LS=MIGRATED)
    check("rollback.sh între versiuni 3.8 pe un volum migrat → merge, volumul nici nu e listat",
          r.returncode == 0 and "--entrypoint ls" not in calls, (r.stdout + r.stderr)[-300:])
    r, calls, same = rb(IMG_LABEL="", VOL_LS=MIGRATED)
    check("R-H1: imagine fără etichetă (chiar cu codul 3.8 în ea) = versiune necunoscută → refuz pe volum migrat",
          r.returncode != 0 and same and "unknown version" in (r.stdout + r.stderr) and "keys.py" not in calls,
          (r.stdout + r.stderr)[-300:])
    r, calls, same = rb(IMG_LABEL="", VOL_LS=MIGRATED, WEBTERM_IMAGE_ERA="3.8")
    check("R-H1: imagine fără etichetă declarată explicit 3.8 (WEBTERM_IMAGE_ERA=3.8) → merge",
          r.returncode == 0 and not same and "--entrypoint ls" not in calls, (r.stdout + r.stderr)[-300:])
    r, calls, same = rb(IMG_LABEL="v3.7.1", VOL_LS=MIGRATED, WEBTERM_IMAGE_ERA="3.8")
    check("R-H1: WEBTERM_IMAGE_ERA nu bate o etichetă 3.7", r.returncode != 0 and same, (r.stdout + r.stderr)[-300:])
    r, calls, same = rb(IMG_LABEL="", VOL_LS=LEGACY)
    check("R-H1: imagine fără etichetă pe volum 3.7 → merge (nimic de protejat)", r.returncode == 0,
          (r.stdout + r.stderr)[-300:])
    r, calls, same = rb(IMG_LABEL="v3.7.1", VOL_LS_FAIL="1")
    check("`docker volume ls` eşuat → refuz (nu „volum curat”)", r.returncode != 0 and same, (r.stdout + r.stderr)[-300:])
    r, calls, same = rb(IMG_LABEL="v3.7.1", LS_FAIL="1")
    check("listarea volumului eşuează → refuz", r.returncode != 0 and same, (r.stdout + r.stderr)[-300:])
    r, calls, same = rb(IMG_LABEL="v3.7.1", VOLUMES="alt_volum", VOL_LS=MIGRATED)
    check("volumul de date confirmat absent → nimic de protejat, merge", r.returncode == 0, (r.stdout + r.stderr)[-300:])
    for marker in ("migrating.wtm", "master.key", "erasures.wtj", "restore-pending.0123", ".restore"):
        r, calls, same = rb(IMG_LABEL="v3.7.1", VOL_LS="webterm.db\\nsecret\\n%s\\n" % marker)
        check(f"marker 3.8 `{marker}` → refuz", r.returncode != 0 and same and marker in (r.stdout + r.stderr),
              (r.stdout + r.stderr)[-300:])

    # deploy.sh: rollback-ul AUTOMAT după o imagine nouă nesănătoasă
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW, "--tag", "v9.9.9"], HEALTH="unhealthy", IMG_LABEL="v3.7.1",
                   NEW_LABEL="v3.8.0", VOL_LS=MIGRATED)
    out = r.stdout + r.stderr
    check("deploy.sh: imaginea 3.8 nesănătoasă pe volum migrat → rollback-ul automat spre 3.7 e REFUZAT",
          r.returncode != 0 and "Rollback automat" in out and "migrated to 3.8" in out
          and env_of(d).get("WEBTERM_IMAGE") == NEW and calls.count("--no-build app") == 0, out[-700:])
    # deploy.sh ţintit direct spre o imagine < 3.8
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    (d / ".prev-image").write_text("ghcr.io/x/webterm:v0.9.0\n")
    # pinul (WEBTERM_IMAGE / _TAG) şi ţinta de rollback; mutarea secretelor din .env în secrets/
    # (normalizare idempotentă, nu o schimbare de ţintă) rulează înaintea gărzii, ca la orice deploy
    def pin(dd):
        e = env_of(dd)
        return (e.get("WEBTERM_IMAGE"), e.get("WEBTERM_IMAGE_TAG"), (dd / ".prev-image").read_text(),
                (dd / ".prev-image-tag").exists())
    before = pin(d)
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.7.1", NEW_LABEL="v3.7.1", VOL_LS=MIGRATED)
    check("deploy.sh spre o imagine < 3.8 pe volum migrat → refuz înainte de `up`",
          r.returncode != 0 and "up -d" not in calls and "migrated to 3.8" in (r.stdout + r.stderr),
          (r.stdout + r.stderr)[-400:])
    after = pin(d)
    check("…refuzul nu schimbă .env (pinul) şi nici .prev-image / .prev-image-tag (ţinta de rollback)",
          before == after, (before, after))
    # acelaşi deploy, garda trece (ţintă 3.8): abia atunci se scriu pinul şi ţinta de rollback
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.7.1", NEW_LABEL="v3.8.0", VOL_LS=MIGRATED)
    check("…cu garda trecută (ţintă 3.8) se scriu .env şi .prev-image",
          r.returncode == 0 and env_of(d).get("WEBTERM_IMAGE") == NEW
          and (d / ".prev-image").read_text().strip() != "ghcr.io/x/webterm:v0.9.0", (r.stdout + r.stderr)[-400:])


def rh1_checks(tmp):
    """R-H1 (recheck PR4): garda verifică montarea /data pe care o porneşte COMPOSE (planul din
    `config --format json`), refuză un override divergent, un container vechi pe altă montare, o
    montare necunoscută; lifecycle-ul e serializat (.deploy.lock)."""
    print("── 10. R-H1: the effective /data mount, lifecycle lock")

    def rb(**extra):
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        (d / ".prev-image").write_text(NEW + "\n")
        before = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        r, calls = run(d, "rollback.sh", **extra)
        after = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        return r, calls, before == after, r.stdout + r.stderr

    two = {"webterm-data": {"name": "proj_webterm-data"}, "data-b": {"name": "proj_data-b"}}
    remap = cfg_json(mount={"type": "volume", "source": "data-b", "target": "/data"}, vols=two)
    # remap în compose; containerul vechi încă pe A (legacy) → refuz, nu „A e curat”
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=remap, VOLUMES="proj_webterm-data\nproj_data-b")
    check("remap A→B, containerul vechi pe A → refuz (nu se verifică A în locul lui B)",
          r.returncode != 0 and same and "remapped" in out and "up -d" not in calls, out[-400:])
    # remap, fără container vechi: se listează B (cel efectiv), care e migrat → refuz
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=MIGRATED, COMPOSE_JSON=remap, APP_PS="",
                             VOLUMES="proj_webterm-data\nproj_data-b")
    check("remap fără container vechi → volumul EFECTIV (proj_data-b) e cel listat → migrat → refuz",
          r.returncode != 0 and same and "-v proj_data-b:/data:ro" in calls
          and "-v proj_webterm-data:/data:ro" not in calls and "migrated to 3.8" in out, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=remap, APP_PS="",
                             VOLUMES="proj_webterm-data\nproj_data-b")
    check("remap fără container vechi, B legacy → merge", r.returncode == 0 and "-v proj_data-b:/data:ro" in calls, out[-400:])
    # WEBTERM_VOLUME divergent de compose
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, WEBTERM_VOLUME="proj_alt")
    check("WEBTERM_VOLUME ≠ volumul din compose → refuz", r.returncode != 0 and same and "WEBTERM_VOLUME" in out, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, WEBTERM_VOLUME="proj_webterm-data")
    check("WEBTERM_VOLUME = volumul din compose → merge", r.returncode == 0, out[-400:])
    # RC3-M1: bind mount la /data pentru o ţintă < 3.8 → refuz, oricum ar arăta directorul (nu se
    # mai listează pe gazdă); doar volume numite
    bd = pathlib.Path(tempfile.mkdtemp(dir=tmp)) / "data"
    bind = cfg_json(mount={"type": "bind", "source": str(bd), "target": "/data"})
    bm = "bind\\t%s" % bd
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=bind, DATA_MOUNT=bm)
    check("RC3-M1: bind mount absent, ţintă 3.7 → refuz (doar volume numite)",
          r.returncode != 0 and same and "bind mount" in out and "up -d" not in calls, out[-400:])
    bd.mkdir()
    (bd / "webterm.db").write_text("x")
    (bd / "secret").write_text("x")
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=bind, DATA_MOUNT=bm)
    check("RC3-M1: bind mount 3.7, ţintă 3.7 → refuz, spune cum se revine (backup de dinainte de migrare)",
          r.returncode != 0 and same and "BEFORE the" in out and "Going back to 3.7" in out
          and "--entrypoint ls" not in calls and "up -d" not in calls, out[-400:])
    for lbl in ("", "v3.6.0"):
        r, calls, same, out = rb(IMG_LABEL=lbl, COMPOSE_JSON=bind, DATA_MOUNT=bm)
        check(f"RC3-M1: bind mount, ţintă {lbl or 'necunoscută'} → refuz", r.returncode != 0 and same and "bind mount" in out, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.8.1", COMPOSE_JSON=bind, DATA_MOUNT=bm)
    check("RC3-M1: bind mount, ţintă 3.8 → merge (neafectată)", r.returncode == 0, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=bind)
    check("bind în compose, containerul vechi pe un volum → refuz", r.returncode != 0 and same, out[-400:])
    # layout necunoscut / config neparsabil / Docker care eşuează
    for label, extra in (
            ("config neparsabil", dict(COMPOSE_JSON="not json")),
            ("`config --format json` eşuat (compose v1)", dict(CFG_FAIL="1")),
            ("imaginea nu poate rula cititorul planului", dict(PLAN_RUN_FAIL="1")),
            ("volum anonim la /data", dict(COMPOSE_JSON=cfg_json(mount={"type": "volume", "source": "", "target": "/data"}))),
            ("tmpfs la /data", dict(COMPOSE_JSON=cfg_json(mount={"type": "tmpfs", "target": "/data"}))),
            ("niciun mount la /data", dict(COMPOSE_JSON=cfg_json(mount={"type": "volume", "source": "webterm-data", "target": "/srv"}))),
            ("volumul nu are nume rezolvat", dict(COMPOSE_JSON=cfg_json(vols={"webterm-data": {}}))),
            ("`docker compose ps` eşuat", dict(PS_FAIL="1"))):
        r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, **extra)
        check(f"{label} → refuz, nimic schimbat", r.returncode != 0 and same and "up -d" not in calls, out[-300:])
    sub = json.loads(DEFAULT_JSON)
    sub["services"]["app"]["volumes"].append({"type": "volume", "source": "webterm-data", "target": "/data/transcripts"})
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=json.dumps(sub))
    check("un al doilea mount sub /data → layout necunoscut → refuz", r.returncode != 0 and same, out[-300:])
    # planul se schimbă între verificare şi `up` (după rescrierea .env) → refuz, .env revine
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, JSON_AFTER_SWAP=remap, SWAP_REF=NEW,
                             VOLUMES="proj_webterm-data\nproj_data-b")
    check("planul /data se schimbă înainte de `up` → refuz, .env şi .prev-image revin, niciun `up`",
          r.returncode != 0 and same and "up -d" not in calls, out[-400:])

    # lifecycle: o a doua rulare cât prima ţine lacătul
    import fcntl
    for script in ("rollback.sh", "deploy.sh"):
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        (d / ".prev-image").write_text(NEW + "\n")
        before = (d / ".env").read_text()
        fd = os.open(str(d / ".deploy.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            r, calls = run(d, script, [NEW] if script == "deploy.sh" else [], IMG_LABEL="v3.8.0")
        finally:
            os.close(fd)
        out = r.stdout + r.stderr
        check(f"{script} cât alt deploy/rollback ţine .deploy.lock → refuz, nimic atins",
              r.returncode != 0 and "another deploy" in out and (d / ".env").read_text() == before
              and "up -d" not in calls and "pull" not in calls, out[-300:])
    # moştenit: deploy.sh → exec rollback.sh (acelaşi lacăt), fără refuz
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW, "--tag", "v9.9.9"], HEALTH="unhealthy", IMG_LABEL="v3.8.0")
    out = r.stdout + r.stderr
    check("deploy.sh → exec rollback.sh moşteneşte lacătul (rollback-ul rulează)",
          "Rollback:" in out and "another deploy" not in out and calls.count("--no-build app") == 1, out[-400:])
    for script in ("deploy.sh", "rollback.sh", "upgrade.sh", "scripts/backup.sh", "scripts/restore.sh"):
        src = (ROOT / script).read_text()
        check(f"{script}: ia lacătul de lifecycle", "\nlifecycle_lock " in src and "flock -n 9" in src)
    blocks = []
    for script in ("deploy.sh", "rollback.sh", "upgrade.sh"):
        src = (ROOT / script).read_text()
        a = src.index("# ── 3.8: graniţa migrării")
        blocks.append(src[a:src.index("# ── sfârşitul gărzii 3.8", a)])
    check("garda (cu render_checked, up_checked, guard_recheck) e identică în deploy.sh, rollback.sh, upgrade.sh",
          len(set(blocks)) == 1 and all("\nguard_recheck() {" in b and "\nrender_checked() {" in b for b in blocks))
    rch1_checks(tmp)
    rc2_checks(tmp)
    rc3_checks(tmp)


def rch1_checks(tmp):
    """RC-H1 (al doilea recheck PR4): montări nemodelate refuzate explicit (subpath, driver_opts care
    schimbă dispozitivul, opţiuni de mount), bind doar cu daemon local, imaginea legată ca ID de
    services.app.image şi re-verificată chiar înainte de `up`."""
    print("── 11. RC-H1: unmodelled mounts, remote daemon, image bound by ID")

    def rb(**extra):
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        (d / ".prev-image").write_text(NEW + "\n")
        before = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        r, calls = run(d, "rollback.sh", **extra)
        after = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        return r, calls, before == after, r.stdout + r.stderr

    def vol(volume=None, vdef=None, **mopts):
        m = {"type": "volume", "source": "webterm-data", "target": "/data", "volume": volume or {}}
        m.update(mopts)
        return cfg_json(mount=m, vols={"webterm-data": dict({"name": "proj_webterm-data"}, **(vdef or {}))})

    for label, js, why in (
            ("volume.subpath", vol({"subpath": "data"}), "volume.subpath"),
            ("volume.subpath + nocopy", vol({"subpath": "data", "nocopy": True}), "volume.subpath"),
            ("driver_opts device (bind la un director)", vol(vdef={"driver_opts": {"type": "none", "device": "/srv/q", "o": "bind"}}), "driver_opts"),
            ("driver_opts o=bind fără device", vol(vdef={"driver_opts": {"o": "rbind"}}), "driver_opts"),
            ("driver_opts nfs (device)", vol(vdef={"driver_opts": {"type": "nfs", "o": "addr=10.0.0.1", "device": ":/x"}}), "driver_opts"),
            ("consistency pe /data", vol(consistency="cached"), "consistency"),
            ("read_only pe /data", vol(read_only=True), "read-only"),
            ("opţiune de volum necunoscută", vol({"labels": {"a": "b"}}), "not checked"),
            ("cheie necunoscută în definiţia volumului", vol(vdef={"driver_opts": {}, "x-weird": 1}), "not checked")):
        r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=js)
        check(f"RC-H1: {label} → refuz explicit, nimic schimbat, volumul nici nu e listat",
              r.returncode != 0 and same and why in out and "up -d" not in calls and "--entrypoint ls" not in calls,
              out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=vol({"nocopy": True}))
    check("RC-H1: volume.nocopy e modelat (aceeaşi rădăcină) → merge", r.returncode == 0, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=MIGRATED, COMPOSE_JSON=vol({"nocopy": True}))
    check("RC-H1: volume.nocopy pe volum migrat → refuzul obişnuit", r.returncode != 0 and same and "migrated to 3.8" in out, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=vol(vdef={"driver_opts": {"type": "tmpfs"}}, ))
    check("RC-H1: driver_opts fără device / bind → modelat, merge", r.returncode == 0, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.8.1", VOL_LS=MIGRATED, COMPOSE_JSON=vol({"subpath": "data"}))
    check("RC-H1: imagine 3.8 cu subpath → merge (garda priveşte doar imaginile < 3.8)", r.returncode == 0, out[-400:])

    # bind + context Docker remote (RC3-M1: orice bind e refuzat pentru < 3.8, local sau remote)
    bd = pathlib.Path(tempfile.mkdtemp(dir=tmp)) / "data"
    bd.mkdir()
    (bd / "webterm.db").write_text("x")
    (bd / "secret").write_text("x")
    bind = cfg_json(mount={"type": "bind", "source": str(bd), "target": "/data", "bind": {"create_host_path": True}})
    bm = "bind\\t%s" % bd
    for ctx in ("tcp://10.0.0.5:2376", "unix:///var/run/docker.sock"):
        r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=bind, DATA_MOUNT=bm, CTX_HOST=ctx)
        check(f"RC3-M1: bind cu daemon {ctx} → refuz, nimic schimbat",
              r.returncode != 0 and same and "bind mount" in out and "up -d" not in calls, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, CTX_HOST="tcp://10.0.0.5:2376")
    check("RC-H1: volum numit cu daemon remote → merge (listat prin daemon, nu pe gazdă)", r.returncode == 0, out[-400:])
    for label, b in (("propagation rshared", {"propagation": "rshared"}), ("selinux z", {"selinux": "z"})):
        js = cfg_json(mount={"type": "bind", "source": str(bd), "target": "/data", "bind": b})
        r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=js, DATA_MOUNT=bm)
        check(f"RC-H1: bind cu {label} → refuz", r.returncode != 0 and same and "non-default" in out, out[-400:])

    # imaginea: ID-ul se schimbă între verificare şi `up` (pull care re-indică tag-ul)
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, ID_FLIP=NEW)
    check("RC-H1: ID-ul imaginii se schimbă între verificare şi `up` → refuz, .env/.prev-image revin, niciun `up`",
          r.returncode != 0 and same and "image changed since it was checked" in out and "up -d" not in calls, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.8.0", VOL_LS=MIGRATED, ID_FLIP=NEW)
    check("RC-H1: …şi pentru o imagine 3.8 (re-indicată spre altceva)", r.returncode != 0 and same and "up -d" not in calls, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, ID_MISSING=NEW)
    check("RC-H1: imaginea ţintă absentă local → refuz (nu e trasă pe tăcute de `docker run`)",
          r.returncode != 0 and same and "not present locally" in out and "docker run" not in calls, out[-400:])
    # compose ar porni ALTĂ imagine decât cea verificată (image fixat în compose)
    other = json.loads(DEFAULT_JSON)
    other["services"]["app"]["image"] = "ghcr.io/x/webterm:v3.7.1"
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.7.1", NEW_LABEL="v3.8.0", VOL_LS=MIGRATED,
                   COMPOSE_JSON=json.dumps(other))
    out = r.stdout + r.stderr
    check("RC-H1: deploy.sh verifică NEW (3.8), dar compose ar porni altă imagine → refuz înainte de `up`",
          r.returncode != 0 and "does not follow WEBTERM_IMAGE" in out and "up -d" not in calls, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, JSON_AFTER_SWAP=json.dumps(other), SWAP_REF=NEW)
    check("RC-H1: rollback.sh: services.app.image ≠ imaginea verificată la re-verificare → refuz, .env revine",
          r.returncode != 0 and same and "up -d" not in calls, out[-400:])
    noimg = json.loads(DEFAULT_JSON)
    del noimg["services"]["app"]["image"]
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.8.0", NEW_LABEL="v3.8.0", COMPOSE_JSON=json.dumps(noimg))
    check("RC-H1: planul fără services.app.image → refuz", r.returncode != 0 and "up -d" not in calls,
          (r.stdout + r.stderr)[-400:])
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.8.0", NEW_LABEL="v3.8.0")
    check("RC-H1: deploy.sh 3.8 normal → merge, imaginea pornită e legată de plan",
          r.returncode == 0 and "up -d" in calls and "wt-compose-plan" in calls, (r.stdout + r.stderr)[-400:])


def rc2_checks(tmp):
    """RC2-H1/H2 (al treilea recheck PR4): `up` porneşte EXACT ID-ul verificat (`--pull never
    --no-build`, WEBTERM_IMAGE=<ID> doar pentru apel, .env pe referinţa umană); build / pull_policy
    refuzate; WEBTERM_DATA_DIR efectiv ≠ /data refuzat pentru o ţintă < 3.8."""
    print("── 12. RC2: start by the checked ID, no pull/build, effective WEBTERM_DATA_DIR")
    TAG371 = "ghcr.io/x/webterm:v3.7.1"

    def rb(prev=NEW, **extra):
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        (d / ".prev-image").write_text(prev + "\n")
        before = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        r, calls = run(d, "rollback.sh", **extra)
        after = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        return d, r, calls, before == after, r.stdout + r.stderr

    def app_cfg(**app):
        js = json.loads(DEFAULT_JSON)
        for k, v in app.items():
            if v is None:
                js["services"]["app"].pop(k, None)
            else:
                js["services"]["app"][k] = v
        return json.dumps(js)

    # deploy.sh: `up` cu ID-ul verificat, fără pull/build; .env rămâne pe referinţă
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW, "--tag", "v9.9.9"], IMG_LABEL="v3.8.0")
    check("RC2-H1: deploy.sh: `up -d --pull never --no-build` cu WEBTERM_IMAGE=<ID-ul verificat>",
          r.returncode == 0 and "up -d --pull never --no-build --remove-orphans" in calls
          and f"up-image={sid(NEW)} up-label=ghcr.io/x/webterm:v9.9.9" in calls, calls[-600:])
    check("RC2-H1: deploy.sh: .env păstrează referinţa umană (digestul), nu ID-ul",
          env_of(d).get("WEBTERM_IMAGE") == NEW and env_of(d).get("WEBTERM_IMAGE_TAG") == "ghcr.io/x/webterm:v9.9.9",
          env_of(d))
    ups = [ln for ln in calls.splitlines() if " up " in ln and ln.startswith("docker compose")]
    check("RC2-H1: deploy.sh: niciun `up` fără `--pull never --no-build`",
          ups and all("--pull never --no-build" in ln for ln in ups), ups)

    # rollback.sh spre un TAG mutabil (v3.7.1): porneşte ID-ul verificat al tag-ului
    d, r, calls, same, out = rb(prev=TAG371, IMG_LABEL="v3.7.1", VOL_LS=LEGACY)
    check("RC2-H1: rollback.sh spre un tag mutabil → `up … --pull never --no-build app` pe ID-ul verificat",
          r.returncode == 0 and "up -d --pull never --no-build app" in calls
          and f"up-image={sid(TAG371)} up-label={TAG371}" in calls, (out + calls)[-700:])
    check("RC2-H1: rollback.sh: .env = tag-ul (referinţa umană), .prev-image = fostul curent",
          env_of(d).get("WEBTERM_IMAGE") == TAG371 and (d / ".prev-image").read_text().strip() == OLD, env_of(d))
    check("RC2-H1: rollback.sh: „✓ Rollback done” doar când containerul rulează ID-ul verificat",
          "✓ Rollback done" in out, out[-300:])
    # tag re-indicat între verificare şi `up` (ID_FLIP) → refuz în re-verificare, nimic pornit
    d, r, calls, same, out = rb(prev=TAG371, IMG_LABEL="v3.7.1", VOL_LS=LEGACY, ID_FLIP=TAG371)
    check("RC2-H1: tag-ul re-indicat după prima verificare → refuz, nimic pornit, .env revine",
          r.returncode != 0 and same and "up -d" not in calls, out[-300:])
    # containerul porneşte altceva decât ID-ul verificat → rollback-ul NU raportează succes
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    (d / ".prev-image").write_text(TAG371 + "\n")
    (d / "bin" / "docker").write_text(DOCKER_SHIM.replace(
        'printf \'%s\\n\' "${PIMG:-$img}" > "$CALLS.started"',
        'printf \'%s\\n\' "sha256:$(printf %064d 7)" > "$CALLS.started"'))
    r, calls = run(d, "rollback.sh", IMG_LABEL="v3.7.1", VOL_LS=LEGACY)
    out = r.stdout + r.stderr
    check("RC2-H1: containerul rulează alt ID decât cel verificat → „did NOT take effect”, exit ≠ 0",
          r.returncode != 0 and "did NOT take effect" in out and "✓ Rollback done" not in out, out[-400:])

    # build / pull_policy pe serviciul app → refuz (şi pentru o imagine 3.8)
    for label, app, lbl, vl in (
            ("build:", dict(build={"context": "."}), "v3.7.1", LEGACY),
            ("build: (imagine 3.8)", dict(build={"context": "."}), "v3.8.0", MIGRATED),
            ("pull_policy always", dict(pull_policy="always"), "v3.7.1", LEGACY),
            ("pull_policy build", dict(pull_policy="build"), "v3.7.1", LEGACY),
            ("pull_policy daily (imagine 3.8)", dict(pull_policy="daily"), "v3.8.0", MIGRATED)):
        d, r, calls, same, out = rb(IMG_LABEL=lbl, VOL_LS=vl, COMPOSE_JSON=app_cfg(**app))
        check(f"RC2-H1: app cu {label} → refuz, nimic pornit, .env/.prev-image neatinse",
              r.returncode != 0 and same and "up -d" not in calls
              and ("build" in out or "pull_policy" in out), out[-400:])
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.8.0", COMPOSE_JSON=app_cfg(build="."))
    check("RC2-H1: deploy.sh cu build: pe app → refuz înainte de `up`",
          r.returncode != 0 and "up -d" not in calls and "build section" in (r.stdout + r.stderr),
          (r.stdout + r.stderr)[-300:])
    for pp in ("missing", "never"):
        d, r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=app_cfg(pull_policy=pp))
        check(f"RC2-H1: pull_policy {pp} → merge", r.returncode == 0 and "--no-build app" in calls, out[-300:])

    # up_checked: un ID care nu e sha256:<64 hex> nu ajunge la compose
    src = (ROOT / "deploy.sh").read_text()
    fn = src[src.index("up_checked() {"):]
    fn = fn[:fn.index("\n}\n") + 3]
    for bad_id in ("", "ghcr.io/x/webterm:v3.7.1", "sha256:abc", "sha256:" + "A" * 64):
        rr = subprocess.run(["bash", "-c", fn + '\ndocker() { echo CALLED; }\nup_checked "$1" L f app', "x", bad_id],
                            capture_output=True, text=True)
        check(f"RC2-H1: up_checked refuză ID-ul {bad_id[:20]!r} fără să cheme compose",
              rr.returncode != 0 and "CALLED" not in rr.stdout, rr.stdout + rr.stderr)
    for script in ("deploy.sh", "rollback.sh"):
        body = (ROOT / script).read_text()
        live = [ln for ln in body.splitlines()
                if " up " in ln and "COMPOSE" in ln and not ln.lstrip().startswith(("#", "echo"))]
        check(f"RC2-H1: {script}: niciun `$COMPOSE … up` direct (doar up_checked)", not live, live)

    # RC2-H2: WEBTERM_DATA_DIR efectiv
    for label, env, vl in (
            ("/data/x", {"WEBTERM_DATA_DIR": "/data/x"}, LEGACY),
            ("/data/x pe un volum migrat", {"WEBTERM_DATA_DIR": "/data/x"}, MIGRATED),
            ("gol", {"WEBTERM_DATA_DIR": ""}, LEGACY),
            ("/data/ (cu slash)", {"WEBTERM_DATA_DIR": "/data/"}, LEGACY),
            ("/srv/other", {"WEBTERM_DATA_DIR": "/srv/other"}, LEGACY)):
        d, r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=vl, COMPOSE_JSON=app_cfg(environment=env))
        check(f"RC2-H2: compose setează WEBTERM_DATA_DIR={label} → refuz pentru < 3.8, nimic schimbat",
              r.returncode != 0 and same and "custom WEBTERM_DATA_DIR" in out and "up -d" not in calls, out[-400:])
    # două montări: /data neprotejat + al doilea dataset indicat de WEBTERM_DATA_DIR
    two = json.loads(DEFAULT_JSON)
    two["services"]["app"]["volumes"].append({"type": "volume", "source": "data-b", "target": "/data2", "volume": {}})
    two["volumes"]["data-b"] = {"name": "proj_data-b"}
    two["services"]["app"]["environment"] = {"WEBTERM_DATA_DIR": "/data2"}
    d, r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=json.dumps(two))
    check("RC2-H2: două montări, WEBTERM_DATA_DIR spre a doua → refuz (nu se verifică doar /data)",
          r.returncode != 0 and same and "custom WEBTERM_DATA_DIR" in out and "up -d" not in calls, out[-400:])
    d, r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY,
                                COMPOSE_JSON=app_cfg(environment={"WEBTERM_DATA_DIR": "/data", "X": None}))
    check("RC2-H2: WEBTERM_DATA_DIR=/data explicit → merge", r.returncode == 0, out[-300:])
    d, r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY,
                                COMPOSE_JSON=app_cfg(environment={"WEBTERM_DATA_DIR": None}))
    check("RC2-H2: WEBTERM_DATA_DIR declarat fără valoare (nesetat) → ENV-ul imaginii (/data) → merge",
          r.returncode == 0, out[-300:])
    d, r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=app_cfg(env_file=["x.env"]))
    check("RC2-H2: env_file nerezolvat în plan → refuz", r.returncode != 0 and same and "env_file" in out, out[-300:])
    d, r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=app_cfg(environment=["A=1"]))
    check("RC2-H2: environment ilizibil (listă) → refuz", r.returncode != 0 and same, out[-300:])
    for label, ienv in (("/srv/webterm", "PATH=/usr/bin\\nWEBTERM_DATA_DIR=/srv/webterm"),
                        ("lipsă (v1.x: cwd/data)", "PATH=/usr/bin"),
                        ("gol", "WEBTERM_DATA_DIR=")):
        d, r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, IMG_ENV=ienv)
        check(f"RC2-H2: ENV-ul imaginii < 3.8 are WEBTERM_DATA_DIR {label} → refuz, volumul nici nu e listat",
              r.returncode != 0 and same and "custom WEBTERM_DATA_DIR" in out
              and "--entrypoint ls" not in calls and "up -d" not in calls, out[-400:])
    d, r, calls, same, out = rb(IMG_LABEL="v3.8.0", VOL_LS=MIGRATED, IMG_ENV="PATH=/usr/bin\\nWEBTERM_DATA_DIR=/srv/x",
                                COMPOSE_JSON=app_cfg(environment={"WEBTERM_DATA_DIR": "/data/x"}))
    check("RC2-H2: imagine 3.8 cu WEBTERM_DATA_DIR propriu → merge (garda priveşte doar < 3.8)",
          r.returncode == 0, out[-300:])


def rc3_checks(tmp):
    """RC3-H1 (al patrulea recheck PR4): planul final se randează O DATĂ cu ID-ul verificat într-un
    fişier privat, garda şi `up` folosesc exact acel fişier; un Compose în care WEBTERM_IMAGE schimbă şi
    altceva decât services.app.image e refuzat; deploy.sh compară ID-ul pornit; re-up-ul SSO acceptă
    doar cheile OIDC. RC3-M1 (bind refuzat pentru < 3.8) e în secţiunile 10/11."""
    print("── 13. RC3: one rendered plan, image-only interpolation, started ID, SSO re-up")

    def rb(prev=NEW, **extra):
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        (d / ".prev-image").write_text(prev + "\n")
        before = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        r, calls = run(d, "rollback.sh", **extra)
        after = ((d / ".env").read_text(), (d / ".prev-image").read_text())
        return d, r, calls, before == after, r.stdout + r.stderr

    def plans(d):
        return sorted(p.name for p in d.iterdir() if p.name.startswith(".wt-plan."))

    # planul randat: `up -p proj -f .wt-plan.*`, imaginea din plan = ID-ul, re-verificarea pe acelaşi fişier
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    shim = (d / "bin" / "docker").read_text()
    (d / "bin" / "docker").write_text(shim.replace(
        'case "$1 $2" in "compose version") exit 0 ;; esac',
        'case "$1 $2" in "compose version") exit 0 ;; esac\n'
        'for a in "$@"; do case "$a" in .wt-plan.*) [ -f "$a" ] && stat -c "plan-mode=%a $a" "$a" >> "$CALLS" ;; esac; done'))
    r, calls = run(d, "deploy.sh", [NEW, "--tag", "v9.9.9"], IMG_LABEL="v3.8.0")
    ups = [ln for ln in calls.splitlines() if ln.startswith("docker compose") and " up " in ln]
    pf = ups[0].split(" -f ")[1].split()[0] if ups else "?"
    check("RC3-H1: deploy.sh porneşte planul randat (`-p proj -f .wt-plan.*`), cu imaginea = ID-ul verificat",
          r.returncode == 0 and len(ups) == 1 and ups[0].startswith("docker compose -p proj -f .wt-plan.")
          and f"up-plan={sid(NEW)}" in calls, (r.stdout + r.stderr + calls)[-700:])
    check("RC3-H1: planul e 0600 şi e EXACT fişierul re-verificat (config --format json pe el)",
          f"plan-mode=600 {pf}" in calls and f"-f {pf} config --format json" in calls, calls[-900:])
    check("RC3-H1: randarea rulează de două ori: cu referinţa umană şi cu ID-ul, toate profilele",
          f"render WEBTERM_IMAGE={NEW}" in calls and f"render WEBTERM_IMAGE={sid(NEW)}" in calls
          and "compose --profile * -f docker-compose.prod.yml config --format json" in calls, calls[-900:])
    check("RC3-H1: planul (mediul rezolvat) nu rămâne pe disc după rulare", plans(d) == [], plans(d))
    d, r, calls, same, out = rb(prev="ghcr.io/x/webterm:v3.7.1", IMG_LABEL="v3.7.1", VOL_LS=LEGACY)
    check("RC3-H1: rollback.sh porneşte planul randat, cu ID-ul tag-ului, şi îl şterge apoi",
          r.returncode == 0 and "docker compose -p proj -f .wt-plan." in calls
          and f"up-plan={sid('ghcr.io/x/webterm:v3.7.1')}" in calls and plans(d) == [], (out + calls)[-600:])

    # WEBTERM_IMAGE interpolat şi în altceva decât services.app.image → refuz, pentru orice imagine
    def with_img_elsewhere(where):
        js = json.loads(DEFAULT_JSON)
        if where == "bind":
            js["services"]["app"]["volumes"].append({"type": "bind", "source": "/srv/@IMG@", "target": "/extra"})
        elif where == "label":
            js["services"]["app"]["labels"] = {"x": "@IMG@"}
        elif where == "other":
            js["services"]["sidecar"] = {"image": "@IMG@"}
        elif where == "volname":
            js["volumes"]["webterm-data"]["name"] = "proj_@IMG@"
        return json.dumps(js)
    for where in ("bind", "label", "other", "volname"):
        for lbl, vl in (("v3.7.1", LEGACY), ("v3.8.0", MIGRATED)):
            d, r, calls, same, out = rb(IMG_LABEL=lbl, VOL_LS=vl, COMPOSE_JSON=with_img_elsewhere(where), APP_PS="")
            check(f"RC3-H1: WEBTERM_IMAGE schimbă şi {where} (ţintă {lbl}) → refuz, .env/.prev-image neatinse, niciun `up`",
                  r.returncode != 0 and same and "up -d" not in calls
                  and "changing WEBTERM_IMAGE also changes" in out and plans(d) == [], out[-400:])
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.8.0", COMPOSE_JSON=with_img_elsewhere("bind"))
    out = r.stdout + r.stderr
    check("RC3-H1: deploy.sh: o sursă bind interpolată din WEBTERM_IMAGE → refuz înainte de `up`, cu calea",
          r.returncode != 0 and "up -d" not in calls and "changing WEBTERM_IMAGE also changes" in out
          and "volumes[1].source" in out, out[-400:])
    lit = json.loads(DEFAULT_JSON)
    lit["services"]["app"]["image"] = NEW
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.8.0", COMPOSE_JSON=json.dumps(lit))
    check("RC3-H1: services.app.image literal (chiar egal cu ţinta) nu urmează WEBTERM_IMAGE → refuz",
          r.returncode != 0 and "up -d" not in calls and "does not follow WEBTERM_IMAGE" in (r.stdout + r.stderr),
          (r.stdout + r.stderr)[-300:])
    ref_env = json.loads(DEFAULT_JSON)
    ref_env["services"]["app"]["environment"] = {"WEBTERM_IMAGE_REF": "@IMG@", "WEBTERM_DATA_DIR": "/data"}
    d, r, calls, same, out = rb(IMG_LABEL="v3.7.1", VOL_LS=LEGACY, COMPOSE_JSON=json.dumps(ref_env))
    check("RC3-H1: WEBTERM_IMAGE_REF care urmează WEBTERM_IMAGE e singura excepţie în environment → merge",
          r.returncode == 0, out[-300:])
    for label, extra in (("randarea eşuează (compose)", dict(CFG_FAIL="1")),
                         ("imaginea nu poate rula programul de randare", dict(RENDER_RUN_FAIL="1"))):
        d, r, calls, same, out = rb(IMG_LABEL="v3.8.0", VOL_LS=MIGRATED, **extra)
        check(f"RC3-H1: {label} → refuz, nimic pornit", r.returncode != 0 and same and "up -d" not in calls, out[-300:])
    noname = json.loads(DEFAULT_JSON)
    noname["name"] = "Bad Name"
    d, r, calls, same, out = rb(IMG_LABEL="v3.8.0", VOL_LS=MIGRATED, COMPOSE_JSON=json.dumps(noname))
    check("RC3-H1: proiect fără nume utilizabil → refuz", r.returncode != 0 and same and "project" in out, out[-300:])

    # deploy.sh compară ID-ul containerului pornit cu cel verificat
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    (d / "bin" / "docker").write_text(DOCKER_SHIM.replace(
        'printf \'%s\\n\' "${PIMG:-$img}" > "$CALLS.started"',
        'printf \'%s\\n\' "sha256:$(printf %064d 7)" > "$CALLS.started"'))
    (d / ".prev-image").write_text(OLD + "\n")
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.8.0")
    out = r.stdout + r.stderr
    check("RC3-H1: deploy.sh: containerul rulează alt ID decât cel verificat → exit ≠ 0, fără „running” şi fără rollback automat",
          r.returncode != 0 and "not the checked" in out and "WebTerm is running" not in out
          and "Rollback" not in out, out[-400:])

    # re-up după SSO: planul re-randat poate diferi DOAR prin cheile OIDC
    def sso(after=None, **kw):
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        with open(d / ".env", "a") as f:
            f.write("AUTHENTIK_DOMAIN=ak.test\n")
        (d / "deploy" / "authentik").mkdir(parents=True)
        (d / "deploy" / "authentik" / "provision.py").write_text(
            "print('WEBTERM_OIDC_ISSUER=https://ak.test/app/o/wt/')\n"
            "print('WEBTERM_OIDC_CLIENT_ID=cid')\nprint('WEBTERM_OIDC_CLIENT_SECRET=csec')\n")
        js = json.loads(DEFAULT_JSON)
        js["services"]["app"]["environment"] = {"WEBTERM_OIDC_ISSUER": "@OIDC@"}
        extra = {"JSON_AFTER_SSO": after(js)} if after else {}
        r, calls = run(d, "deploy.sh", [NEW, "--with-authentik"], IMG_LABEL="v3.8.0",
                       COMPOSE_JSON=json.dumps(js), **{"AK_CODE": "200", **extra, **kw})
        ups = [ln for ln in calls.splitlines() if ln.startswith("docker compose") and " up " in ln]
        return d, r, calls, ups, r.stdout + r.stderr

    d, r, calls, ups, out = sso()
    check("RC3-H1: re-up SSO: doar WEBTERM_OIDC_ISSUER s-a schimbat → re-randat, re-verificat, `up app` pe noul plan",
          r.returncode == 0 and len(ups) == 2 and ups[1].endswith("--pull never --no-build app")
          and ups[0].split(" -f ")[1].split()[0] != ups[1].split(" -f ")[1].split()[0]
          and "SSO linked" in out and "NOT reloaded" not in out and plans(d) == [], (out + "\n".join(ups))[-700:])

    # RC4-M2: SSO se anunţă activ doar după ce re-up-ul rulează ID-ul verificat şi e healthy
    d, r, calls, ups, out = sso(HEALTH_AFTER_SSO="unhealthy")
    check("RC4-M2: re-up SSO → app unhealthy → exit ≠ 0, fără rollback automat, fără „WebTerm is running”",
          r.returncode != 0 and len(ups) == 2 and "reloaded app did not become healthy (status: unhealthy)" in out
          and "Rollback" not in out and "WebTerm is running" not in out and "rollback.sh" not in calls, out[-600:])
    d, r, calls, ups, out = sso(STARTED_AFTER_SSO="sha256:" + "7" * 64)
    check("RC4-M2: re-up SSO → containerul rulează alt ID → exit ≠ 0, „not the checked”, fără „WebTerm is running”",
          r.returncode != 0 and len(ups) == 2 and "not the checked" in out and "WebTerm is running" not in out,
          out[-600:])
    d, r, calls, ups, out = sso(AK_CODE="000")
    check("RC4-M2: Authentik indisponibil → instrucţiunea e ./deploy.sh, niciodată `compose … up` direct",
          r.returncode == 0 and "and run: cd " in out and "./deploy.sh" in out.split("and run: cd ")[1].splitlines()[0]
          and " up -d" not in out and len(ups) == 1, out[-600:])

    def extra_vol(js):
        js = json.loads(json.dumps(js))
        js["services"]["app"]["volumes"].append({"type": "bind", "source": "/srv/x", "target": "/extra"})
        return json.dumps(js)

    def extra_env(js):
        js = json.loads(json.dumps(js))
        js["services"]["app"]["environment"]["WEBTERM_DATA_DIR"] = "/srv/x"
        return json.dumps(js)
    for label, after in (("un mount nou", extra_vol), ("altă cheie de mediu (WEBTERM_DATA_DIR)", extra_env)):
        d, r, calls, ups, out = sso(after)
        check(f"RC3-H1: re-up SSO cu {label} → refuzat, app-ul nu e re-pornit, mesaj clar",
              len(ups) == 1 and "NOT reloaded" in out and "beyond the SSO settings" in out and plans(d) == [],
              (out + "\n".join(ups))[-700:])


CFG = "name: proj\\nservices:\\n  app:\\n    image: x\\nvolumes:\\n  webterm-data:\\n    name: custom_data\\n"


def master_key_checks(tmp):
    """M4 (recenzia PR4): cheia master se creează DOAR pe o instalare nouă confirmată — numele
    efectiv al volumului din `compose config`, absenţa confirmată de `docker volume ls`, niciun
    container app; orice eroare Docker = nicio cheie."""
    print("── 9. master key only on a confirmed fresh install")

    def dep(**extra):
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        extra.setdefault("IMG_LABEL", "v3.8.0")      # garda R-H1 nu e subiectul aici
        r, calls = run(d, "deploy.sh", **extra)
        return r, (d / "secrets" / "master-key" / "master.key").exists(), env_of(d), calls

    for label, extra in (("`docker volume ls` eşuat", dict(VOL_LS_FAIL="1", APP_PS="")),
                         ("compose nu poate spune numele volumului", dict(COMPOSE_CFG="", VOLUMES="", APP_PS="")),
                         ("volumul cu numele EFECTIV (suprascris) există",
                          dict(COMPOSE_CFG=CFG, VOLUMES="custom_data", APP_PS="")),
                         ("un container app al proiectului există", dict(COMPOSE_CFG=CFG, VOLUMES="", APP_PS="c1"))):
        r, made, e, _ = dep(**extra)
        check(f"deploy.sh: {label} → nicio cheie creată, nimic activat",
              r.returncode == 0 and not made and not e.get("WEBTERM_MASTER_KEY_FILE"), (r.stdout + r.stderr)[-300:])
    r, made, e, _ = dep(COMPOSE_CFG=CFG, VOLUMES="proj_webterm-data", APP_PS="")
    check("deploy.sh: alt volum cu numele CONVENŢIONAL există, cel efectiv nu → instalare nouă",
          (made and e.get("WEBTERM_MASTER_KEY_FILE") == "/run/webterm-key/master.key") if os.geteuid() == 0
          else r.returncode != 0, (r.stdout + r.stderr)[-300:])
    # install.sh / setup.sh: aceeaşi regulă, citită din sursă (rularea lor atinge sistemul)
    for script in ("install.sh", "deploy.sh"):
        src = (ROOT / script).read_text()
        fn = src[src.index("data_volume_state() {"):]
        fn = fn[:fn.index("\n}\n")]
        check(f"{script}: „none” cere `docker volume ls` reuşit + nume efectiv din compose config",
              "docker volume ls -q" in fn and "compose_volume_name" in fn and "echo unknown" in fn
              and "docker volume inspect" not in fn, fn)
    src = (ROOT / "setup.sh").read_text()
    check("setup.sh: modul „reduced” doar la cerere explicită (--key-in-volume), niciodată ca plasă",
          "--key-in-volume" in src and 'if [ "$KEY_IN_VOLUME" = 1 ]' in src
          and src.count('echo "WEBTERM_KEY_IN_VOLUME=1" >> .env') == 1)



# ── RC5-H1 / RC4-L1: install.sh porneşte doar prin deploy.sh; planuri vechi curăţate ────────────
INSTALL_KIT = ("docker-compose.prod.yml", ".env.prod.example", "deploy.sh", "rollback.sh", "upgrade.sh",
               "remove.sh", "scripts/backup.sh", "scripts/restore.sh", "scripts/cert-check.sh",
               "scripts/cert-renew.sh", "scripts/host-health.sh", "scripts/docker-cleanup.sh",
               "scripts/authentik-upgrade.sh")
FAKE_PROVISION = ("print('WEBTERM_OIDC_ISSUER=https://auth.term.test/application/o/webterm/')\n"
                  "print('WEBTERM_OIDC_CLIENT_ID=cid')\nprint('WEBTERM_OIDC_CLIENT_SECRET=csecret')\n")


def install_sandbox(tmp):
    """Sursa trusei (install.sh + fişierele pe care le copiază, provision.py înlocuit cu un stub) şi
    shim-urile; installerul rulează pe un --dir din sandbox, cu `docker` & co. stub-uite."""
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    src = d / "src"
    shutil.copytree(ROOT / "deploy", src / "deploy")
    for rel in ("install.sh",) + INSTALL_KIT:
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, src / rel)
    (src / "deploy" / "authentik" / "provision.py").write_text(FAKE_PROVISION)
    # installerul cere root, apt şi chown 10001; în sandbox (şi pe runner-ul CI, ne-root) le stub-uim
    for name, body in (("apt-get", "#!/bin/sh\nexit 0\n"),
                       ("openssl", "#!/bin/sh\nexit 1\n"),
                       ("getent", "#!/bin/sh\nexit 2\n"),
                       ("id", '#!/bin/sh\n[ "$1" = -u ] && [ $# = 1 ] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n'),
                       ("install", '#!/bin/bash\na=()\nwhile [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; '
                                   '*) a+=("$1"); shift ;; esac; done\nexec /usr/bin/install "${a[@]}"\n')):
        p = d / "bin" / name
        p.write_text(body)
        os.chmod(p, 0o755)
    return d, d / "inst"


INSTALL_ARGS = ("--domain", "term.test", "--email", "a@b.test", "--non-interactive", "--no-ufw",
                "--no-backup", "--no-cert-check", "--no-host-health", "--skip-port-check")


def run_install(d, inst, args=(), **extra):
    r, calls = run(d, "src/install.sh", ("--dir", str(inst)) + INSTALL_ARGS + tuple(args), **extra)
    ups = [ln for ln in calls.splitlines() if ln.startswith("docker ") and " up " in f"{ln} "]
    return r, calls, ups, r.stdout + r.stderr


def install_checks(tmp):
    print("── 15. RC5-H1: install.sh starts the stack only through ./deploy.sh; RC4-L1 stale plans")
    checked = "docker compose -p proj -f .wt-plan."
    # volumul existent = cel din planul /data (proj_webterm-data, implicit listat de `docker volume ls`)
    CFG_PROJ = CFG.replace("custom_data", "proj_webterm-data")
    fresh = dict(COMPOSE_CFG=CFG, VOLUMES="", APP_PS="", IMG_LABEL="v3.8.0")

    # instalare nouă: o singură pornire, a planului verificat (nu `compose -f … up`)
    d, inst = install_sandbox(tmp)
    r, calls, ups, out = run_install(d, inst, **fresh)
    check("install.sh, instalare nouă: porneşte prin deploy.sh (planul verificat, ID, fără pull/build)",
          r.returncode == 0 and len(ups) == 1 and ups[0].startswith(checked)
          and "up -d --pull never --no-build --remove-orphans" in ups[0], (out[-600:], ups))
    check("…cheia master creată, niciun plan rămas în director",
          (inst / "secrets" / "master-key" / "master.key").exists()
          and not any(p.name.startswith(".wt-plan.") for p in inst.iterdir()), out[-300:])

    # --with-authentik: re-up-ul SSO e tot planul re-verificat al lui deploy.sh
    d, inst = install_sandbox(tmp)
    r, calls, ups, out = run_install(d, inst, ("--with-authentik", "--authentik-domain", "auth.term.test"),
                                     AK_CODE="200", **fresh)
    e = env_of(inst)
    check("install.sh --with-authentik: pornire + re-up SSO, ambele prin planul verificat al lui deploy.sh",
          r.returncode == 0 and len(ups) == 2 and all(u.startswith(checked) for u in ups)
          and ups[1].rstrip().endswith("--no-build app")
          and e.get("WEBTERM_OIDC_ISSUER") == "https://auth.term.test/application/o/webterm/",
          (out[-700:], ups))

    # instalare existentă, volum migrat, .env pe o imagine < 3.8: garda lui deploy.sh refuză, nimic pornit
    d, inst = install_sandbox(tmp)
    inst.mkdir()
    (inst / ".env").write_text("WEBTERM_DOMAIN=term.test\nLETSENCRYPT_EMAIL=a@b.test\nGHCR_USER=x\n"
                               f"WEBTERM_IMAGE={OLD}\nWEBTERM_IMAGE_TAG=ghcr.io/x/webterm:v3.7.1\n")
    r, calls, ups, out = run_install(d, inst, COMPOSE_CFG=CFG_PROJ, APP_PS="cid-app-1",
                                     IMG_LABEL="v3.7.1", VOL_LS=MIGRATED)
    check("install.sh peste un volum migrat, imagine < 3.8 în .env → deploy.sh refuză, nimic pornit, exit ≠ 0",
          r.returncode != 0 and ups == [] and "migrated to 3.8" in out and "never 'docker compose up'" in out,
          (out[-700:], ups))
    check("…imaginea din .env rămâne cea a instalării (installerul nu o rescrie)",
          env_of(inst).get("WEBTERM_IMAGE") == OLD, env_of(inst).get("WEBTERM_IMAGE"))

    # instalare existentă pe 3.8: delegată, imaginea neschimbată
    d, inst = install_sandbox(tmp)
    inst.mkdir()
    (inst / ".env").write_text("WEBTERM_DOMAIN=term.test\nLETSENCRYPT_EMAIL=a@b.test\nGHCR_USER=x\n"
                               f"WEBTERM_IMAGE={NEW}\n")
    r, calls, ups, out = run_install(d, inst, COMPOSE_CFG=CFG_PROJ, APP_PS="cid-app-1",
                                     IMG_LABEL="v3.8.0", VOL_LS=MIGRATED)
    check("install.sh peste o instalare 3.8 existentă → delegă la deploy.sh (o pornire, planul verificat)",
          r.returncode == 0 and len(ups) == 1 and ups[0].startswith(checked) and "Existing installation" in out
          and env_of(inst).get("WEBTERM_IMAGE") == NEW
          and not (inst / "secrets" / "master-key" / "master.key").exists(), (out[-600:], ups))

    # --image diferit pe o instalare existentă → refuz înainte de trusă şi de .env
    d, inst = install_sandbox(tmp)
    inst.mkdir()
    env0 = f"WEBTERM_DOMAIN=term.test\nLETSENCRYPT_EMAIL=a@b.test\nWEBTERM_IMAGE={NEW}\n"
    (inst / ".env").write_text(env0)
    r, calls, ups, out = run_install(d, inst, ("--image", "ghcr.io/x/webterm:v3.7.1"),
                                     COMPOSE_CFG=CFG_PROJ, IMG_LABEL="v3.7.1")
    check("install.sh --image <altă imagine> pe o instalare existentă → refuz, trimite la upgrade.sh/deploy.sh",
          r.returncode != 0 and "does not change the image" in out and "upgrade.sh" in out
          and ups == [] and (inst / ".env").read_text() == env0 and not (inst / "deploy.sh").exists(),
          (out[-500:], ups))

    # sursa: nicio pornire compose directă în installer (în afara mesajelor)
    bad = [ln for ln in (ROOT / "install.sh").read_text().splitlines()
           if re.search(r"compose\b.*\bup\b", ln) and not re.match(r"\s*(#|err |warn |say |echo )", ln)]
    check("install.sh: niciun `docker compose … up` direct în cod", bad == [], bad)

    # RC4-L1: planurile rămase de la o rulare întreruptă se şterg la începutul rulării care ia lacătul
    def stale(d):
        p = d / ".wt-plan.STALE1"
        p.write_text('{"x": "secret"}\n')
        os.utime(p, (time.time() - 3600, time.time() - 3600))
        tgt = d / "keep-me"
        tgt.write_text("x\n")
        (d / ".wt-plan.LINK").symlink_to(tgt)
        return p, tgt
    for script in ("deploy.sh", "rollback.sh"):
        d = sandbox(tempfile.mkdtemp(dir=tmp))
        (d / ".prev-image").write_text(NEW + "\n")
        p, tgt = stale(d)
        r, _ = run(d, script, IMG_LABEL="v3.8.0")
        out = r.stdout + r.stderr
        check(f"RC4-L1: {script} şterge planul vechi la început; symlink-ul (şi ţinta lui) rămân",
              not p.exists() and (d / ".wt-plan.LINK").is_symlink() and tgt.exists()
              and "stale compose plan" in out, out[-400:])
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    p, _ = stale(d)
    (d / "wrap.sh").write_text('exec 9>>"$PWD/.deploy.lock"\nexec bash ./deploy.sh\n')
    r, _ = run(d, "wrap.sh", IMG_LABEL="v3.8.0")
    check("RC4-L1: cu lacătul moştenit de la un părinte, nimic nu se şterge (planul lui poate fi viu)",
          r.returncode == 0 and p.exists() and "stale compose plan" not in (r.stdout + r.stderr),
          (r.stdout + r.stderr)[-300:])
    for script in ("deploy.sh", "rollback.sh", "upgrade.sh"):
        src = (ROOT / script).read_text()
        check(f"RC4-L1: {script}: planul se şterge şi la INT/TERM, iar curăţarea rulează după lacăt",
              "trap plan_cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM" in src
              and src.index("\nlifecycle_lock ") < src.index("\nplan_sweep "), script)


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
