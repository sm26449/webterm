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
import shutil
import stat
import subprocess
import sys
import tempfile

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
# imaginea pe care compose ar porni-o: variabila din mediu bate .env (exact ca la compose real),
# altfel linia din .env din directorul curent
img="${WEBTERM_IMAGE:-$(grep -m1 '^WEBTERM_IMAGE=' .env 2>/dev/null | cut -d= -f2-)}"
case "$*" in
  # garda 3.8 (H1) şi detecţia instalării noi (M4)
  "volume ls"*) [ -n "${VOL_LS_FAIL:-}" ] && exit 1; [ -n "${VOLUMES-x}" ] && printf '%s\n' "${VOLUMES-proj_webterm-data}"; exit 0 ;;
  # R-H1: planul compose (JSON) şi programul care îl citeşte (rulat aici cu python-ul gazdei)
  *"config --format json"*) [ -n "${CFG_FAIL:-}" ] && exit 1
    # @IMG@ = interpolarea lui ${WEBTERM_IMAGE} pe care o face compose (services.app.image)
    if [ -n "${JSON_AFTER_SWAP:-}" ] && grep -qxF "WEBTERM_IMAGE=${SWAP_REF:-}" .env 2>/dev/null; then
      printf '%s' "$JSON_AFTER_SWAP" | sed "s|@IMG@|$img|g"; exit 0; fi
    printf '%s' "${COMPOSE_JSON:-$DEFAULT_JSON}" | sed "s|@IMG@|$img|g"; exit 0 ;;
  *wt-compose-plan*) eval "prog=\${$#}"; [ -n "${PLAN_RUN_FAIL:-}" ] && exit 125; exec python3 -I -c "$prog" ;;
  *"compose -f"*" config"*) printf '%b' "${COMPOSE_CFG:-}"; exit 0 ;;
  *"ps -a -q app"*) [ -n "${PS_FAIL:-}" ] && exit 1; [ -n "${APP_PS-x}" ] && printf '%s\n' "${APP_PS-cid-app-1}"; exit 0 ;;
  *image.version*)
    case "$*" in *1111111111*) echo "${NEW_LABEL-${IMG_LABEL:-}}" ;; *) echo "${IMG_LABEL:-}" ;; esac; exit 0 ;;
  *'"/data"'*) printf '%b\n' "${DATA_MOUNT:-volume\tproj_webterm-data}"; exit 0 ;;
  *"--entrypoint ls"*) [ -n "${LS_FAIL:-}" ] && exit 125; printf '%b' "${VOL_LS:-}"; exit 0 ;;
  *"ps -q app"*) echo "cid-app-1"; exit 0 ;;
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
      *"{{.Image}}"*) echo "id-foreign-uses" ;;
      *) echo "${HEALTH:-healthy}" ;;
    esac; exit 0 ;;
  image)
    case "$*" in
      *RepoDigests*) exit 0 ;;
      *"{{.Id}}"*)
        # ID-uri de imagine: fiecare referinţă (ultimul argument) îşi are al ei; cea din
        # IN_USE_REF e „folosită" de un container străin (acelaşi ID ca `{{.Image}}` de mai sus)
        ref="${*##* }"
        [ -n "${ID_MISSING:-}" ] && [ "$ref" = "$ID_MISSING" ] && exit 1
        # RC-H1: ID_FLIP = referinţa al cărei ID se schimbă după prima rezolvare (un pull între verificare şi `up`)
        if [ -n "${ID_FLIP:-}" ] && [ "$ref" = "$ID_FLIP" ]; then
          if [ -e "$CALLS.idflip" ]; then echo "id-$ref-repointed"; else : > "$CALLS.idflip"; echo "id-$ref"; fi
          exit 0; fi
        if [ -n "${IN_USE_REF:-}" ] && [ "$ref" = "$IN_USE_REF" ]; then echo "id-foreign-uses"; else echo "id-$ref"; fi
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
case "$*" in *api/state*) echo '{"setup_required": true}' ;; *) echo 000 ;; esac
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
    (d / "argv.log").write_bytes(b"")
    (d / "curl-stdin.log").write_text("")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("WEBTERM_", "CF_", "AUTHENTIK_", "PG_"))}
    env.update(PATH=f"{d/'bin'}:{os.environ['PATH']}", CALLS=str(calls), ARGV_LOG=str(d / "argv.log"),
               DEFAULT_JSON=DEFAULT_JSON,
               CURL_STDIN=str(d / "curl-stdin.log"), **extra)
    r = subprocess.run(["bash", str(d / script), *args], cwd=str(d), env=env, capture_output=True,
                       text=True, timeout=120, input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL)
    return r, calls.read_text()


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
              and "docker compose -f docker-compose.prod.yml up -d --remove-orphans" in calls
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
              calls4.count("up -d app") == 1, calls4)
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
          f"--network none -v proj_webterm-data:/data:ro --entrypoint ls id-{NEW}" in calls, calls)
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
          and env_of(d).get("WEBTERM_IMAGE") == NEW and calls.count("up -d app") == 0, out[-700:])
    # deploy.sh ţintit direct spre o imagine < 3.8
    d = sandbox(tempfile.mkdtemp(dir=tmp))
    r, calls = run(d, "deploy.sh", [NEW], IMG_LABEL="v3.7.1", NEW_LABEL="v3.7.1", VOL_LS=MIGRATED)
    check("deploy.sh spre o imagine < 3.8 pe volum migrat → refuz înainte de `up`",
          r.returncode != 0 and "up -d" not in calls and "migrated to 3.8" in (r.stdout + r.stderr),
          (r.stdout + r.stderr)[-400:])


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
    # bind mount: directorul gazdei e listat direct
    bd = pathlib.Path(tempfile.mkdtemp(dir=tmp)) / "data"
    bind = cfg_json(mount={"type": "bind", "source": str(bd), "target": "/data"})
    bm = "bind\\t%s" % bd
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=bind, DATA_MOUNT=bm)
    check("bind mount absent → nimic de protejat, merge", r.returncode == 0, out[-400:])
    bd.mkdir()
    (bd / "webterm.db").write_text("x")
    (bd / "keys.wtk").write_text("x")
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=bind, DATA_MOUNT=bm)
    check("bind mount cu keys.wtk → refuz (listat pe gazdă, nu prin volume ls)",
          r.returncode != 0 and same and "keys.wtk" in out and "volume ls" not in calls, out[-400:])
    (bd / "keys.wtk").unlink()
    (bd / "secret").write_text("x")
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=bind, DATA_MOUNT=bm)
    check("bind mount 3.7 → merge", r.returncode == 0, out[-400:])
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
          "Rollback:" in out and "another deploy" not in out and calls.count("up -d app") == 1, out[-400:])
    for script in ("deploy.sh", "rollback.sh", "upgrade.sh", "scripts/backup.sh", "scripts/restore.sh"):
        src = (ROOT / script).read_text()
        check(f"{script}: ia lacătul de lifecycle", "\nlifecycle_lock " in src and "flock -n 9" in src)
    blocks = []
    for script in ("deploy.sh", "rollback.sh", "upgrade.sh"):
        src = (ROOT / script).read_text()
        a = src.index("# ── 3.8: graniţa migrării")
        blocks.append(src[a:src.index("\nguard_recheck() {", a)])
    check("garda e identică în deploy.sh, rollback.sh, upgrade.sh", len(set(blocks)) == 1)
    rch1_checks(tmp)


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

    # bind + context Docker remote
    bd = pathlib.Path(tempfile.mkdtemp(dir=tmp)) / "data"
    bd.mkdir()
    (bd / "webterm.db").write_text("x")
    (bd / "secret").write_text("x")
    bind = cfg_json(mount={"type": "bind", "source": str(bd), "target": "/data", "bind": {"create_host_path": True}})
    bm = "bind\\t%s" % bd
    for ctx in ("tcp://10.0.0.5:2376", "ssh://admin@far", "npipe:////./pipe/docker_engine", ""):
        r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=bind, DATA_MOUNT=bm, CTX_HOST=ctx)
        check(f"RC-H1: bind cu daemon remote ({ctx or 'context ilizibil'}) → refuz, nimic schimbat",
              r.returncode != 0 and same and "remote" in out and "up -d" not in calls, out[-400:])
    r, calls, same, out = rb(IMG_LABEL="v3.7.1", COMPOSE_JSON=bind, DATA_MOUNT=bm)
    check("RC-H1: bind cu socket unix local → merge", r.returncode == 0, out[-400:])
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
          r.returncode != 0 and "not the image that was" in out and "up -d" not in calls, out[-400:])
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



if __name__ == "__main__":
    sys.exit(0 if main() else 1)
