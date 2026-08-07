"""Fiecare variabilă citită de `config.py` chiar ajunge în container.

Defectul ăsta a apărut de DOUĂ ori. Prima dată în producţie: 22 din 28 de variabile nu erau
pasate, deci alertele pe email şi `WEBTERM_TRUSTED_PROXY_CIDRS` — o reparaţie de securitate din
aceeaşi zi — erau moarte, fără niciun semn. S-a reparat manual, prin inspecţie pe instanţa vie,
şi **doar în `docker-compose.prod.yml`**. A doua oară în `docker-compose.yml`, calea pe care
README-ul o recomandă prima: 26 din 30 de variabile aruncate, printre ele două documentate în
tabelul de configurare.

Reparaţia manuală nu ţine: a treia variabilă adăugată reintroduce defectul. Testul ăsta e
gardul. Nu verifică valorile — verifică doar că un buton documentat are un fir în spate.

Deliberat exclusă e doar categoria „setat de Dockerfile, nu de operator": acelea ajung în
container prin `ENV`, deci nu trebuie repetate în compose.
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def _read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def main():
    cfg = _read("gateway/app/config.py")
    read_vars = set(re.findall(r'["\'](WEBTERM_[A-Z_]+)["\']', cfg))
    check("config.py chiar citeşte variabile (testul nu e gol)", len(read_vars) > 10,
          str(len(read_vars)))

    # `ENV` acceptă blocuri multi-linie cu `\`, deci ancorarea pe începutul liniei rata
    # exact variabilele din continuare (`WEBTERM_AGENT_FILE`) şi le raporta drept lipsă.
    dockerfile = _read("Dockerfile")
    from_env = set(re.findall(r"^(?:ENV\s+|\s+)(WEBTERM_[A-Z_]+)=", dockerfile, re.M))

    # Un `ENV` din Dockerfile pe care nimeni nu-l citeşte e un buton mort, cu comentariu
    # liniştitor: `WEBTERM_FORWARDED_ALLOW_IPS` a stat aşa, sfătuind operatorul să-l strângă
    # „ca un vecin să nu falsifice IP-ul clientului", după ce încetase să mai fie pasat lui
    # uvicorn. Cine urma sfatul nu obţinea nimic.
    dead = sorted(from_env - read_vars)
    check("niciun ENV din Dockerfile nu e citit de nimeni", not dead, ", ".join(dead))

    # Excepţii DECLARATE, cu motiv — o listă albă explicită e diferenţa dintre „ştim de ele"
    # şi „ne-au scăpat". Orice adăugare aici trebuie să vină cu o frază.
    ALLOWED = {
        # în producţie nu vrem un buton care dezactivează verificarea TLS către agent:
        # absent → default `False`, exact ce trebuie.
        "docker-compose.prod.yml": {"WEBTERM_AGENT_INSECURE"},
    }

    for compose in ("docker-compose.yml", "docker-compose.prod.yml"):
        txt = _read(compose)
        passed = set(re.findall(r"^\s+(WEBTERM_[A-Z_]+):", txt, re.M))
        missing = sorted(read_vars - passed - from_env - ALLOWED.get(compose, set()))
        check("%s pasează tot ce citeşte config.py" % compose, not missing,
              "lipsesc: " + ", ".join(missing))

    # `WEBTERM_IMAGE` înseamnă IMAGINEA GATEWAY-ULUI: aşa e scrisă în `.env`, aşa o rescriu
    # `deploy.sh` şi `rollback.sh`, aşa o citeşte compose. `backup.sh` şi `restore.sh` o
    # foloseau însă cu al doilea înţeles — „o imagine care are python3" — iar `upgrade.sh`
    # sursează `.env` înainte să cheme backupul. Deci containerul de unealtă primea imaginea
    # aplicaţiei fără ca cineva s-o fi cerut: entrypoint-ul ei coboară la userul `webterm`,
    # iar scriptul cade cu PermissionError. Backupul şi-a reparat simptomul pe loc; restaurarea
    # avea acelaşi defect nereparat, şi acolo eşecul vine DUPĂ mutarea datelor vechi.
    # Un nume, un înţeles — verificat, nu ţinut minte.
    for script in ("scripts/backup.sh", "scripts/restore.sh"):
        txt = _read(script)
        check("%s nu mai citeşte WEBTERM_IMAGE ca imagine de unealtă" % script,
              # ancorat pe ATRIBUIRE: scripturile îl citesc în continuare, dar numai ca să
              # spună „e ignorat aici". Un `${WEBTERM_IMAGE:-}` gol în avertisment nu e defectul.
              not re.search(r'^IMAGE=.*\$\{WEBTERM_IMAGE\b', txt, re.M),
              "foloseşte WEBTERM_TOOL_IMAGE; WEBTERM_IMAGE e imaginea gateway-ului")
        # …iar dacă cineva chiar ţinteşte imaginea aplicaţiei, trebuie să meargă, nu să pice
        # la 03:30 dimineaţa cu o eroare de permisiuni.
        check("%s ocoleşte entrypoint-ul care coboară privilegiile" % script,
              "--entrypoint python3" in txt, "adaugă --entrypoint python3 la docker run")

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
