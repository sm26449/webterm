"""`upgrade.sh` şi `remove.sh` — rulate pe bune, cu `docker` simulat.

Scriptul ăsta rulează ca root pe producţie şi atinge, în ordine: reţeaua, backupul, fişierele
de pe host şi containerul. Un `bash -n` nu spune nimic despre asta. Aşa că îl rulăm într-un
director-sandbox, cu shim-uri care ÎNREGISTREAZĂ fiecare apel, şi verificăm secvenţa.

Prima versiune a scriptului avea `` `docker login` `` într-un string cu ghilimele duble — deci
ar fi EXECUTAT un docker login interactiv, blocând upgrade-ul pe o maşină fără token. Testul de
mai jos („fără GHCR_TOKEN nu se face login") prinde exact clasa asta.
"""
import os
import pathlib
import shutil
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


DOCKER_SHIM = r'''#!/bin/sh
echo "docker $*" >> "$CALLS"
# salvăm ARGV-ul complet (NUL-separat): programul python trimis prin `-c` trebuie
# inspectat, nu doar numărat — ghilimelele din el sunt o suprafaţă de eroare reală
[ -n "${ARGV_LOG:-}" ] && for a in "$@"; do printf '%s\0' "$a" >> "$ARGV_LOG"; done
case "$1 $2" in
  "compose version") exit 0 ;;
esac
# `docker compose -f ... ps -q app` → id de container (scripturile nu mai folosesc nume fixe)
case "$*" in
  *"ps -q app"*) [ -n "${NO_APP:-}" ] || echo "cid-app-1"; exit 0 ;;
esac
case "$1" in
  login) exit 0 ;;
  pull)  exit ${PULL_FAILS:-0} ;;
  ps)    case "$*" in *Names*) echo "webterm-app-1" ;; *) echo "ghcr.io/x/webterm:$WANT_TAG" ;; esac; exit 0 ;;
  inspect) echo healthy; exit 0 ;;
  run)
    # ultimul argument e comanda `sh -c "..."`; distingem după conţinut
    case "$*" in
      *GATEWAY_VERSION*)  echo "9.9.9" ;;
      *AGENT_VERSION*)    echo "99" ;;
      *deploy-kit*)       cd "$KITSRC" && tar cf - . ;;
      *UPDATE_PUBKEY*)    echo "${SIGSTATE:-OK}" ;;
      *) : ;;
    esac
    exit 0 ;;
  exec)
    # remove.sh cere lista de hosturi; upgrade.sh cere starea cheii + agenţii rămaşi
    # sentinelul de sănătate: „interogarea a reuşit" ≠ „nu sunt agenţi"
    if [ -n "${HOSTS_OUT+x}" ]; then
      [ -n "${QUERY_BROKEN:-}" ] || echo "QUERY_OK"
      printf '%b\n' "$HOSTS_OUT"; exit 0
    fi
    echo "KEY ${KEY_EXISTS:-0} ${KEY_ENC:-0}"
    echo "BEHIND ${BEHIND:-0}"
    exit 0 ;;
  volume) [ "$2" = ls ] && echo "webterm_webterm-data"; exit 0 ;;
  images) exit 0 ;;
esac
exit 0
'''

CURL_SHIM = r'''#!/bin/sh
echo "curl $*" >> "$CALLS"
[ -n "${TAGS_FAIL:-}" ] && exit 1
# ordinea din API e deliberat amestecată: scriptul trebuie să aleagă cel mai MARE tag
cat <<'JSON'
[{"name": "v1.0.9"}, {"name": "v1.0.30"}, {"name": "nu-e-tag"}, {"name": "v1.0.10"}]
JSON
'''


def sandbox(tmp, with_token=False):
    """Un /opt/webterm de jucărie + shim-uri pe PATH."""
    d = pathlib.Path(tmp)
    (d / "scripts").mkdir(parents=True, exist_ok=True)
    (d / "bin").mkdir(exist_ok=True)
    (d / "kit" / "scripts").mkdir(parents=True, exist_ok=True)

    shutil.copy(ROOT / "upgrade.sh", d / "upgrade.sh")
    os.chmod(d / "upgrade.sh", 0o755)
    env_txt = "WEBTERM_DOMAIN=x\nWEBTERM_IMAGE=ghcr.io/x/webterm:v1.0.1\nGHCR_USER=x\n"
    if with_token:
        env_txt += "GHCR_TOKEN=secret\n"
    (d / ".env").write_text(env_txt)
    (d / "docker-compose.prod.yml").write_text("services: {}\n")
    for name in ("deploy.sh", "rollback.sh"):
        p = d / name
        p.write_text('#!/bin/sh\necho "%s $*" >> "$CALLS"\n' % name)
        os.chmod(p, 0o755)
    bk = d / "scripts" / "backup.sh"
    bk.write_text('#!/bin/sh\necho "backup.sh" >> "$CALLS"\nexit ${BACKUP_FAILS:-0}\n')
    os.chmod(bk, 0o755)

    # trusa de deploy pe care „imaginea" o livrează: un compose DIFERIT (trebuie copiat)
    # şi un upgrade.sh diferit (trebuie pus deoparte ca .new, nu peste cel care rulează)
    (d / "kit" / "docker-compose.prod.yml").write_text("services: {app: {}}   # nou\n")
    (d / "kit" / "scripts" / "backup.sh").write_text("#!/bin/sh\n# backup nou\n")
    (d / "kit" / "upgrade.sh").write_text("#!/usr/bin/env bash\n# upgrade nou\n")

    # `id` stubuit: `remove.sh` cere root (atinge /etc/systemd şi /var/backups), iar runner-ul
    # de CI nu e root — deci testele gărzii de FLOTĂ picau acolo şi treceau local, unde rulăm
    # ca root. Mediul decidea rezultatul, ceea ce e exact ce un test nu trebuie să lase.
    # `FAKE_UID` alege ce răspunde: 0 pentru testele care verifică altceva, non-zero pentru
    # testul care verifică garda de root însăşi.
    ID_SHIM = '#!/bin/sh\n[ "$1" = "-u" ] && { echo "${FAKE_UID:-0}"; exit 0; }\nexec /usr/bin/id "$@"\n'
    for name, body in (("docker", DOCKER_SHIM), ("curl", CURL_SHIM), ("id", ID_SHIM)):
        p = d / "bin" / name
        p.write_text(body)
        os.chmod(p, 0o755)
    return d


def run(d, args=(), **extra):
    calls = d / "calls.log"
    calls.write_text("")
    env = dict(os.environ, PATH=f"{d/'bin'}:{os.environ['PATH']}", CALLS=str(calls),
               ARGV_LOG=str(d / "argv.log"), KITSRC=str(d / "kit"),
               WANT_TAG="v1.0.30", **extra)
    (d / "argv.log").write_bytes(b"")
    r = subprocess.run(["bash", str(d / "upgrade.sh"), *args], cwd=str(d), env=env,
                       capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    return r, calls.read_text()



def python_programs(d):
    """Programele python pe care scriptul le trimite containerului (argumentul de după `-c`).

    Verificarea lor e necesară, nu paranoia: programul e împachetat într-un string cu
    GHILIMELE SIMPLE în shell, deci orice ghilimea simplă dinăuntru îl închide. Aşa s-a
    rupt interogarea din `upgrade.sh`: SQL-ul a devenit `connection_type=agent` (coloană
    inexistentă), excepţia a fost înghiţită, iar raportul a spus „nimic de făcut" fără să
    fi verificat nimic. Acelaşi tipar în `remove.sh` ar face garda de flotă să creadă că
    nu mai există agenţi — şi ar şterge tot.
    """
    raw = (d / "argv.log").read_bytes().split(b"\0")
    args = [a.decode("utf-8", "replace") for a in raw if a]
    progs = [args[i + 1] for i, a in enumerate(args) if a == "-c" and i + 1 < len(args)]
    return [p for p in progs if "import " in p]          # nu şi comenzile `sh -c`


def main():
    with tempfile.TemporaryDirectory() as tmp:
        d = sandbox(tmp)
        r, calls = run(d, ["-y"])
        out = r.stdout + r.stderr
        check("rulează până la capăt", r.returncode == 0, out[-400:])
        check("alege cel mai MARE tag, nu primul din API", "v1.0.30" in out, out[:300])
        check("deploy.sh e chemat cu versiunea rezolvată",
              "deploy.sh v1.0.30" in calls, calls)
        check("backupul se face ÎNAINTE de deploy",
              calls.index("backup.sh") < calls.index("deploy.sh"), calls)
        check("pull-ul se face înainte de backup (artefactul e local întâi)",
              calls.index("docker pull") < calls.index("backup.sh"), calls)
        check("fără GHCR_TOKEN NU se face docker login (backtick executat din greşeală)",
              "docker login" not in calls, calls)
        check("fişierele de host se sincronizează din imagine",
              "# nou" in (d / "docker-compose.prod.yml").read_text(), "compose nesincronizat")
        check("versiunea veche a fişierului rămâne ca .bak",
              (d / "docker-compose.prod.yml.bak").exists())
        check("backup.sh e sincronizat şi el",
              "# backup nou" in (d / "scripts" / "backup.sh").read_text())
        check("upgrade.sh se înlocuieşte pe sine DOAR la final (nu în timpul rulării)",
              "# upgrade nou" in (d / "upgrade.sh").read_text()
              and not (d / "upgrade.sh.new").exists())
        check("raportează versiunile din imaginea nouă", "9.9.9" in out and "99" in out, out[:200])
        check("verifică semnătura agentului din imagine ÎNAINTE de deploy",
              "agent signature: valid" in out
              and out.index("agent signature") < out.index("Applying"), out[:400])
        check("spune că nu mai e nimic de făcut când chiar nu e",
              "nothing — the system is fully up to date" in out, out[-500:])

        # ── programul python trimis containerului nu trebuie să fie rupt de ghilimele ──
        progs = python_programs(d)
        check("scriptul chiar trimite un program python containerului", len(progs) >= 1, str(len(progs)))
        for prog in progs:
            try:
                compile(prog, "<trimis>", "exec")
                syntax_ok = True
            except SyntaxError as e:
                syntax_ok = False
                detail = str(e)
            check("programul python trimis compilează", syntax_ok, locals().get("detail", ""))
            if "connection_type" in prog:
                check("SQL-ul nu e rupt de ghilimele (ar deveni connection_type=agent)",
                      "connection_type=agent" not in prog, prog[:200])
                check("interogarea foloseşte parametru legat, nu literal cu apostrofuri",
                      "connection_type=?" in prog, prog[:200])

        # ── semnătură invalidă în imagine → avertisment, nu tăcere ──
        ds = sandbox(tempfile.mkdtemp(dir=tmp))
        rs, _ = run(ds, ["-y"], SIGSTATE="INVALIDA")
        check("semnătură invalidă → avertisment explicit",
              "does NOT verify" in (rs.stdout + rs.stderr), (rs.stdout + rs.stderr)[:300])

        # ── cheie de semnare criptată → după repornire e blocată; trebuie SPUS ──
        dk = sandbox(tempfile.mkdtemp(dir=tmp))
        rk, _ = run(dk, ["-y"], KEY_EXISTS="1", KEY_ENC="1", BEHIND="2")
        outk = rk.stdout + rk.stderr
        check("cheie criptată → spune că agenţii NU se actualizează până la deblocare",
              "LOCKED" in outk and "Settings → Security" in outk, outk[-600:])
        check("raportează câţi agenţi au rămas în urmă", "2 host(s)" in outk, outk[-600:])
        check("explică restartul amânat cât sunt sesiuni deschise", "DEFERRED" in outk, outk[-400:])

        # ── cheie fără parolă → se încarcă singură, nimic de făcut ──
        dn = sandbox(tempfile.mkdtemp(dir=tmp))
        rn, _ = run(dn, ["-y"], KEY_EXISTS="1", KEY_ENC="0")
        check("cheie fără parolă → nu cere nicio acţiune",
              "loaded automatically" in (rn.stdout + rn.stderr), (rn.stdout + rn.stderr)[-400:])

        # ── nu putem afla versiunea → NU pin-uim :latest din inerţie ──────────
        # `-y` înseamnă „nu mă întreba de rutină", nu „acceptă tăcut modul degradat".
        # Prima rulare pe producţie a pin-uit :latest exact aşa, iar `.prev-image`
        # devenise inutil: nu mai ştiai la ce versiune te întorci.
        dl = sandbox(tempfile.mkdtemp(dir=tmp))
        rl, callsl = run(dl, ["-y"], TAGS_FAIL="1")
        outl = rl.stdout + rl.stderr
        check("versiune nedeterminabilă + -y → REFUZ, nu :latest tăcut",
              rl.returncode != 0 and "refusing to pin :latest" in outl, outl[-400:])
        check("refuzul nu atinge nimic", "deploy.sh" not in callsl and "pull" not in callsl, callsl)
        check("refuzul dă cele trei ieşiri", "--allow-latest" in outl and "GHCR_TOKEN" in outl, outl[-500:])
        dl2 = sandbox(tempfile.mkdtemp(dir=tmp))
        rl2, callsl2 = run(dl2, ["-y", "--allow-latest"], TAGS_FAIL="1")
        check("--allow-latest acceptă explicit tag-ul mişcător",
              "deploy.sh latest" in callsl2, callsl2)
        check("--allow-latest avertizează despre rollback-ul manual",
              "MOVING" in (rl2.stdout + rl2.stderr), (rl2.stdout + rl2.stderr)[-300:])

        # ── backupul primeşte parola din /etc/default/webterm-backup ──────────
        check("upgrade.sh încarcă parola de backup din fişierul systemd",
              "/etc/default/webterm-backup" in (ROOT / "upgrade.sh").read_text(),
              "altfel backup.sh se autorefuză pe maşinile configurate corect")

        # ── token în .env → login explicit, ca să meargă şi sub sudo ──
        d2 = sandbox(tempfile.mkdtemp(dir=tmp), with_token=True)
        r2, calls2 = run(d2, ["-y"])
        check("cu GHCR_TOKEN în .env se face login (capcana sudo → alt HOME)",
              "docker login ghcr.io" in calls2, calls2)

        # ── versiune explicită ──
        d3 = sandbox(tempfile.mkdtemp(dir=tmp))
        r3, calls3 = run(d3, ["v1.0.7", "-y"])
        check("versiunea dată explicit e respectată", "deploy.sh v1.0.7" in calls3, calls3)
        check("cu versiune explicită nu mai întrebăm GitHub", "curl" not in calls3, calls3)

        # ── --no-backup ──
        d4 = sandbox(tempfile.mkdtemp(dir=tmp))
        r4, calls4 = run(d4, ["--no-backup", "-y"])
        check("--no-backup sare peste backup", "backup.sh" not in calls4, calls4)
        check("--no-backup tot face deploy", "deploy.sh" in calls4, calls4)

        # ── backup eşuat, neinteractiv, fără -y → OPREŞTE ──
        d5 = sandbox(tempfile.mkdtemp(dir=tmp))
        r5, calls5 = run(d5, [], BACKUP_FAILS="1")
        check("backup eşuat + neinteractiv → NU face deploy",
              r5.returncode != 0 and "deploy.sh" not in calls5, calls5)

        # ── pull eşuat → se opreşte înainte să atingă ceva ──
        d6 = sandbox(tempfile.mkdtemp(dir=tmp))
        r6, calls6 = run(d6, ["-y"], PULL_FAILS="1")
        check("pull eşuat → nici backup, nici deploy, nici fişiere atinse",
              r6.returncode != 0 and "backup.sh" not in calls6 and "deploy.sh" not in calls6, calls6)
        check("pull eşuat → explică autentificarea la ghcr",
              "docker login" in (r6.stdout + r6.stderr), (r6.stdout + r6.stderr)[-300:])

        # ── argument aiurea → refuz, nu interpretare creativă ──
        d7 = sandbox(tempfile.mkdtemp(dir=tmp))
        r7, calls7 = run(d7, ["--stergetot"])
        check("argument necunoscut → iese cu 2, fără efecte",
              r7.returncode == 2 and calls7.strip() == "", calls7)

        # ── fără .env → nu ghicim nimic ──
        d8 = sandbox(tempfile.mkdtemp(dir=tmp))
        (d8 / ".env").unlink()
        r8, _ = run(d8, ["-y"])
        check("fără .env → refuz explicit", r8.returncode != 0 and "env" in (r8.stdout + r8.stderr))

        # ── remove.sh: refuză cât mai există agenţi ──────────────────────────
        # Ordinea e tot ce contează aici: agentul se dezinstalează PRIN gateway. Ştergi
        # întâi gateway-ul → pe fiecare maşină rămâne un agent care reconectează la
        # nesfârşit, cu supraveghere systemd/cron pusă. Deci scriptul trebuie să se
        # OPREASCĂ, nu doar să avertizeze.
        dr = sandbox(tempfile.mkdtemp(dir=tmp))
        shutil.copy(ROOT / "remove.sh", dr / "remove.sh")
        os.chmod(dr / "remove.sh", 0o755)

        def run_remove(d, args=(), **extra):
            calls = d / "calls.log"
            calls.write_text("")
            env = dict(os.environ, PATH=f"{d/'bin'}:{os.environ['PATH']}", CALLS=str(calls),
                       ARGV_LOG=str(d / "argv.log"), KITSRC=str(d / "kit"),
                       WANT_TAG="v1", **extra)
            (d / "argv.log").write_bytes(b"")
            r = subprocess.run(["bash", str(d / "remove.sh"), *args], cwd=str(d), env=env,
                               capture_output=True, text=True, timeout=120,
                               stdin=subprocess.DEVNULL)
            return r, calls.read_text()

        rr, callsr = run_remove(dr, [], HOSTS_OUT="prod\tONLINE\nbackup\toffline")
        outr = rr.stdout + rr.stderr
        check("remove.sh se OPREŞTE cât mai există agenţi înrolaţi",
              rr.returncode != 0 and "stopping" in outr, outr[-400:])
        check("remove.sh listează hosturile afectate", "prod" in outr and "backup" in outr, outr[:600])
        check("remove.sh dă paşii manuali pentru hosturile offline",
              "rm -rf ~/.webterm" in outr and "kill-server" in outr, outr[:900])
        check("remove.sh NU a şters nimic când s-a oprit",
              "down" not in callsr and "volume rm" not in callsr, callsr)

        # garda de root, verificată explicit: fără ea, scriptul ar ajunge să atingă
        # /etc/systemd şi /var/backups fără drepturi şi ar muri LA JUMĂTATE, după ce a şters
        # deja volumele. Până acum n-o testa nimeni — CI-ul doar se împiedica de ea.
        rrr, callsrr = run_remove(dr, [], HOSTS_OUT="", FAKE_UID="1000")
        outrr = rrr.stdout + rrr.stderr
        check("remove.sh fără root → refuză din start",
              rrr.returncode != 0 and "sudo" in outrr, outrr[-300:])
        check("refuzul pe lipsă de root nu şterge nimic",
              "down" not in callsrr and "volume rm" not in callsrr, callsrr)

        # interogare EŞUATĂ (fără sentinel) → refuz, nu „flota e curată"
        rrq, callsrq = run_remove(dr, [], HOSTS_OUT="", QUERY_BROKEN="1")
        outq = rrq.stdout + rrq.stderr
        check("interogare eşuată → refuz (nu presupune flotă curată)",
              rrq.returncode != 0 and "cannot confirm" in outq, outq[-300:])
        check("refuzul pe interogare eşuată nu şterge nimic",
              "down" not in callsrq and "volume rm" not in callsrq, callsrq)

        rr2, callsr2 = run_remove(dr, [], HOSTS_OUT="")
        out2 = rr2.stdout + rr2.stderr
        check("fără agenţi, cere confirmare scrisă (stdin gol → anulează)",
              rr2.returncode != 0 and "cancelled" in out2, out2[-300:])
        check("anulat = nimic şters", "down" not in callsr2, callsr2)

        # „nu pot verifica flota" ≠ „flota e curată": containerul oprit e chiar cazul în care
        # agenţii pot fi vii pe hosturi, iar ştergerea gateway-ului i-ar lăsa orfani
        dn2 = sandbox(tempfile.mkdtemp(dir=tmp))
        shutil.copy(ROOT / "remove.sh", dn2 / "remove.sh")
        os.chmod(dn2 / "remove.sh", 0o755)
        rn3, callsn3 = run_remove(dn2, [], NO_APP="1")
        outn3 = rn3.stdout + rn3.stderr
        check("container oprit → refuz (nu pot confirma că flota e curată)",
              rn3.returncode != 0 and "cannot confirm" in outn3, outn3[-400:])
        check("refuzul nu şterge nimic", "down" not in callsn3 and "volume rm" not in callsn3, callsn3)

    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
