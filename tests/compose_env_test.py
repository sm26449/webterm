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

    # ── secretele: fişiere montate, nu valori în mediu (auditul de deploy, M1) ───────────
    # Traefik citeşte `Config.Env` al oricărui container prin dockerproxy (CONTAINERS=1 e
    # minimul providerului). Deci în compose-ul de producţie fiecare secret al aplicaţiei are
    # un `_FILE` care arată spre /run/secrets/<nume>, serviciul declară secretul, iar blocul
    # `secrets:` îl leagă de ./secrets/<nume>. Verificăm FIRUL întreg, nu doar o parte.
    prod = _read("docker-compose.prod.yml")
    SECRETS = {
        "WEBTERM_SETUP_TOKEN": "webterm_setup_token",
        "WEBTERM_OIDC_CLIENT_SECRET": "webterm_oidc_client_secret",
        "WEBTERM_SMTP_PASSWORD": "webterm_smtp_password",
    }
    top = re.search(r"^secrets:\n((?:  .*\n?)+)", prod, re.M)
    check("docker-compose.prod.yml are blocul `secrets:` de nivel superior", bool(top))
    top_txt = top.group(1) if top else ""
    for var, name in SECRETS.items():
        check(f"{var}_FILE arată spre /run/secrets/{name}",
              re.search(rf"^\s+{var}_FILE:\s*/run/secrets/{name}\s*$", prod, re.M) is not None)
        check(f"secretul {name} e legat de ./secrets/{name}",
              re.search(rf"^  {name}:\n    file: \./secrets/{name}\s*$", top_txt, re.M) is not None,
              top_txt[:200])
        check(f"serviciul app declară secretul {name}",
              re.search(rf"^      - {name}\s*$", prod, re.M) is not None)
        # fallback-ul din mediu rămâne (instalări cu .env scris de mână), dar GOL implicit
        check(f"{var} rămâne pasat ca ${{{var}:-}} (fallback, gol = nesetat)",
              re.search(rf"^\s+{var}:\s*\$\{{{var}:-\}}\s*$", prod, re.M) is not None)
    # Traefik: lego citeşte CF_DNS_API_TOKEN_FILE când CF_DNS_API_TOKEN e gol
    check("Traefik primeşte CF_DNS_API_TOKEN_FILE şi secretul cf_dns_api_token",
          re.search(r"^\s+CF_DNS_API_TOKEN_FILE:\s*/run/secrets/cf_dns_api_token\s*$", prod, re.M) is not None
          and re.search(r"^  cf_dns_api_token:\n    file: \./secrets/cf_dns_api_token", top_txt, re.M) is not None)
    check("CF_DNS_API_TOKEN nu mai e obligatoriu în mediu (${CF_DNS_API_TOKEN:-})",
          re.search(r"^\s+CF_DNS_API_TOKEN:\s*\$\{CF_DNS_API_TOKEN:-\}\s*$", prod, re.M) is not None)
    # Postgres: _FILE şi POSTGRES_PASSWORD sunt EXCLUSIVE în entrypoint-ul oficial → doar fişier
    check("Postgres primeşte DOAR POSTGRES_PASSWORD_FILE (entrypoint-ul refuză ambele)",
          "POSTGRES_PASSWORD_FILE: /run/secrets/pg_pass" in prod
          and re.search(r"^\s+POSTGRES_PASSWORD:", prod, re.M) is None)
    # Authentik: `file://` e sintaxa lui pentru orice variabilă; fallback pe valoarea din .env
    for var, name in (("AUTHENTIK_SECRET_KEY", "authentik_secret_key"), ("PG_PASS", "pg_pass"),
                      ("AUTHENTIK_BOOTSTRAP_PASSWORD", "authentik_bootstrap_password"),
                      ("AUTHENTIK_BOOTSTRAP_TOKEN", "authentik_bootstrap_token")):
        check(f"Authentik citeşte {name} ca file:// cu fallback pe ${{{var}}}",
              f"${{{var}:-file:///run/secrets/{name}}}" in prod, name)
    # nicio VALOARE de secret nu mai e pasată singură (fără _FILE lângă) în compose-ul de prod
    bare = [v for v in SECRETS if re.search(rf"^\s+{v}:\s*\$\{{{v}\}}\s*$", prod, re.M)]
    check("niciun secret pasat ca ${VAR} obligatoriu (ar forţa valoarea în .env)", not bare, str(bare))

    # ── întărirea tuturor serviciilor (auditul de deploy, M2) ─────────────────────────────
    # Doar `app` era întărit; Traefik (procesul expus pe internet), dockerproxy, Caddy,
    # Postgres, Redis şi Authentik rulau cu toate capabilităţile şi fără plafon de memorie.
    def service_block(txt, name):
        m = re.search(rf"^  {re.escape(name)}:\n((?:    .*\n|\n)+)", txt, re.M)
        return m.group(1) if m else ""
    for compose, services in (("docker-compose.prod.yml", ["dockerproxy", "traefik", "app", "authentik-postgresql",
                                                           "authentik-redis", "authentik-server", "authentik-worker"]),
                              ("docker-compose.yml", ["app", "caddy"])):
        txt = _read(compose)
        for svc in services:
            blk = service_block(txt, svc)
            check(f"{compose}:{svc} există", bool(blk))
            check(f"{compose}:{svc} cap_drop ALL + no-new-privileges + mem_limit + pids_limit + logging",
                  "cap_drop" in blk and "ALL" in blk and "no-new-privileges:true" in blk
                  and "mem_limit:" in blk and "pids_limit:" in blk and "logging: *default-logging" in blk,
                  blk[:300])
    prodtxt = _read("docker-compose.prod.yml")
    for svc in ("dockerproxy", "traefik", "authentik-redis"):
        check(f"{svc} rulează cu rădăcina read-only", "read_only: true" in service_block(prodtxt, svc))
    check("caddy rulează cu rădăcina read-only", "read_only: true" in service_block(_read("docker-compose.yml"), "caddy"))
    # imagini terţe pe tag de MINOR (nu `latest`, nu doar major): contractul de upgrade
    for img in ("postgres:16.15-alpine", "redis:7.4.11-alpine", "goauthentik/server:2026.8.3"):
        check(f"imaginea {img} e pinuită pe versiune de minor", img in prodtxt)
    check("nicio imagine pe :latest în compose-urile de producţie/dev",
          ":latest" not in prodtxt and ":latest" not in _read("docker-compose.yml"))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
