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
  *"ps -q app"*) echo "cid-app-1"; exit 0 ;;
  *"compose -f"*"pull"*) exit ${PULL_FAILS:-0} ;;
  *"compose -f"*) exit 0 ;;
esac
case "$1" in
  login|logs|rmi) exit 0 ;;
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


def run(d, script, args=(), stdin=None, **extra):
    calls = d / "calls.log"
    calls.write_text("")
    (d / "argv.log").write_bytes(b"")
    (d / "curl-stdin.log").write_text("")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("WEBTERM_", "CF_", "AUTHENTIK_", "PG_"))}
    env.update(PATH=f"{d/'bin'}:{os.environ['PATH']}", CALLS=str(calls), ARGV_LOG=str(d / "argv.log"),
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
              and calls.index("pull") < calls.index("up -d") < calls.index("docker inspect"), calls)
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

    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
