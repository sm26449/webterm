"""Configurarea din mediu: valoarea GOALĂ nu trebuie să doboare gateway-ul.

Incidentul, pe scurt. `docker-compose.prod.yml` pasează variabilele cu `${VAR:-}`, ca să nu
trebuiască să le declari pe toate în `.env`. Efectul e că variabila ajunge în container
**prezentă şi goală**, nu absentă — iar `os.environ.get(name, default)` întoarce default DOAR
când lipseşte. Deci `int(os.environ.get("WEBTERM_TRANSCRIPT_MAX_BYTES", "67108864"))` primea
`""` şi ridica ValueError **la import**, adică înainte ca uvicorn să apuce să pornească aplicaţia.

A ieşit la iveală la deploy-ul 1.0.153: passthrough-urile adăugate în compose cu o zi înainte
(fără ele, alertele erau moarte în producţie) au activat exact citirile astea. Containerul a
intrat în buclă de restart, failsafe-ul a făcut rollback — dar producţia a fost jos câteva minute.

Ce verificăm aici e regula, nu variabila care s-a întâmplat să crape prima: orice număr citit
din mediu suportă gol → default, şi invalid → default (un typo în `.env` nu doboară serviciul).
"""
import importlib
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


# toate numericele citite din mediu, cu (variabilă, atribut, default aşteptat)
NUMERIC = [
    ("WEBTERM_ARCHIVE_DAYS", "ARCHIVE_RETENTION_DAYS", 120),
    ("WEBTERM_AUDIT_DAYS", "AUDIT_RETENTION_DAYS", 120),
    ("WEBTERM_IDLE_LOCK_SECS", "IDLE_LOCK_SECS", 300),
    ("WEBTERM_TRANSCRIPT_MAX_BYTES", "TRANSCRIPT_MAX_BYTES", 64 * 1024 * 1024),
    ("WEBTERM_TRANSCRIPT_KEEP_BYTES", "TRANSCRIPT_KEEP_BYTES", 16 * 1024 * 1024),
    ("WEBTERM_TRUSTED_PROXY_HOPS", "TRUSTED_PROXY_HOPS", 1),
    ("WEBTERM_CLIENT_BUFFER", "CLIENT_BUFFER_LIMIT", 1024 * 1024),
    ("WEBTERM_IP_MAX_FAILS", "IP_MAX_FAILS", 5),
    ("WEBTERM_SMTP_PORT", "SMTP_PORT", 587),
    ("WEBTERM_SESSION_TTL_DAYS", "WEB_SESSION_TTL", 30 * 24 * 3600),
    ("WEBTERM_SESSION_IDLE_HOURS", "WEB_SESSION_IDLE", 12 * 3600),
]


def load(env):
    """Reîncarcă `config` cu mediul dat (citirile se fac la import).

    Scoatem şi pachetul `app`, nu doar `app.config`: `from app import config` ia atributul deja
    aşezat pe pachet, deci ştergerea submodulului singură nu forţează re-importul — testul ar
    citi valorile primei încărcări şi ar trece/pica din motive care n-au legătură cu ce verifică."""
    for m in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[m]
    for k in [k for k in os.environ if k.startswith("WEBTERM_")]:
        del os.environ[k]
    os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
    os.environ.update(env)
    return importlib.import_module("app.config")


def main():
    # ── 1. TOATE goale: exact ce livrează compose fără `.env` complet ─────────
    cfg = load({v: "" for v, _, _ in NUMERIC})
    for var, attr, default in NUMERIC:
        check(f"{var} gol → default", getattr(cfg, attr) == default,
              f"{attr}={getattr(cfg, attr)!r}, aşteptat {default}")

    # ── 2. valori invalide: un typo în `.env` nu doboară serviciul ────────────
    cfg = load({v: "nu-i număr" for v, _, _ in NUMERIC})
    for var, attr, default in NUMERIC:
        check(f"{var} invalid → default", getattr(cfg, attr) == default,
              f"{attr}={getattr(cfg, attr)!r}")

    # ── 3. valorile CHIAR se aplică (altfel „tolerant" ar însemna „ignorat") ──
    cfg = load({"WEBTERM_IDLE_LOCK_SECS": "77", "WEBTERM_SMTP_PORT": "2525",
                "WEBTERM_TRANSCRIPT_MAX_BYTES": "123456",
                "WEBTERM_SESSION_TTL_DAYS": "2"})
    check("valoare setată se aplică (IDLE_LOCK_SECS)", cfg.IDLE_LOCK_SECS == 77, cfg.IDLE_LOCK_SECS)
    check("valoare setată se aplică (SMTP_PORT)", cfg.SMTP_PORT == 2525, cfg.SMTP_PORT)
    check("valoare setată se aplică (TRANSCRIPT_MAX_BYTES)",
          cfg.TRANSCRIPT_MAX_BYTES == 123456, cfg.TRANSCRIPT_MAX_BYTES)
    check("valoare fracţionară se aplică (SESSION_TTL_DAYS)",
          cfg.WEB_SESSION_TTL == 2 * 24 * 3600, cfg.WEB_SESSION_TTL)

    # ── 4. minimele rămân minime chiar şi cu 0 explicit ───────────────────────
    cfg = load({"WEBTERM_IP_MAX_FAILS": "0", "WEBTERM_TRUSTED_PROXY_HOPS": "0"})
    check("IP_MAX_FAILS nu coboară sub 1", cfg.IP_MAX_FAILS == 1, cfg.IP_MAX_FAILS)
    check("TRUSTED_PROXY_HOPS nu coboară sub 1", cfg.TRUSTED_PROXY_HOPS == 1, cfg.TRUSTED_PROXY_HOPS)

    # ── 5. şirurile goale nu strică semantica (precedenţa lui `or`) ───────────
    # O reparaţie grăbită a scris `os.environ.get(X) or "".split(",")`, unde `.split()` se leagă
    # de default, nu de rezultat: cu variabila SETATĂ, lista devenea caracterele şirului.
    cfg = load({"WEBTERM_TRUSTED_PROXY_CIDRS": "10.0.0.0/8, 192.168.0.0/16"})
    check("CIDR-urile se despart pe virgulă, nu pe caractere",
          cfg.TRUSTED_PROXY_CIDRS == ["10.0.0.0/8", "192.168.0.0/16"], cfg.TRUSTED_PROXY_CIDRS)
    cfg = load({"WEBTERM_TRUSTED_PROXY_CIDRS": ""})
    check("CIDR gol → listă goală", cfg.TRUSTED_PROXY_CIDRS == [], cfg.TRUSTED_PROXY_CIDRS)
    cfg = load({"WEBTERM_PUBLIC_URL": "https://x.test/"})
    check("PUBLIC_URL setat rămâne fără slash final",
          cfg.PUBLIC_URL == "https://x.test", cfg.PUBLIC_URL)
    cfg = load({"WEBTERM_TRUST_CF_IP": ""})
    check("TRUST_CF_IP gol → False (nu şir gol adevărat)",
          cfg.TRUST_CF_CONNECTING_IP is False, cfg.TRUST_CF_CONNECTING_IP)
    cfg = load({"WEBTERM_AGENT_INSECURE": ""})
    check("AGENT_INSECURE gol → False", cfg.AGENT_INSECURE is False, cfg.AGENT_INSECURE)

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
