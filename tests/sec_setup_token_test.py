"""Tokenul de setup NU trebuie să ajungă în logul aplicaţiei.

DE CE acest test: până la 3.2.0 `init_setup_token` scria tokenul ÎNTREG în log (marker-ul
`WEBTERM_SETUP_TOKEN=<value>`). Înainte de primul setup, oricine putea citi `docker compose
logs app` — colectoare de loguri, operatori fără drepturi de admin — obţinea tokenul şi crea
contul de admin. Fixăm aici invariantul: tokenul GENERAT nu apare în log (doar un prefix + cum
se recuperează), stă într-un fişier numai-owner (0600), tokenul PROVIDED din mediu nu se
loghează deloc, iar fişierul dispare după ce setup-ul s-a închis.
"""
import asyncio
import logging
import os
import stat
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
# Fără WEBTERM_SETUP_TOKEN în mediu: config.SETUP_TOKEN pornește None, ca să putem exercita
# întâi cazul PROVIDED (monkeypatch) și apoi cel GENERAT.
os.environ.pop("WEBTERM_SETUP_TOKEN", None)
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, security  # noqa: E402
from app.main import app  # noqa: E402

# csrf_guard cere Origin pe metodele care schimbă ceva — imităm un browser.
_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}

ok = 0
total = 0
PW = "parolabuna1"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class _Capture(logging.Handler):
    """Prinde tot ce scrie logger-ul `webterm`, formatat ca în producţie (cu %-args expandate)."""
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(self.format(record))

    def text(self):
        return "\n".join(self.lines)

    def clear(self):
        self.lines = []


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()

    cap = _Capture()
    cap.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger("webterm").addHandler(cap)

    tok_file = api._SETUP_TOKEN_FILE

    # ── Cazul PROVIDED (token din mediu): nimic secret în log, niciun fişier ─────────────────
    config.SETUP_TOKEN = "env-provided-secret-ABC123"
    api._setup_token = None
    api._clear_setup_token_file()
    cap.clear()
    await api.init_setup_token()
    logged = cap.text()
    check("provided: tokenul din mediu NU apare în log",
          "env-provided-secret-ABC123" not in logged, logged)
    check("provided: setup-ul e deschis (tokenul e în memorie)",
          api._setup_token == "env-provided-secret-ABC123")
    check("provided: nu se scrie fişier (operatorul deja are tokenul)",
          not os.path.exists(tok_file))

    # ── Cazul GENERATED: tokenul întreg NU e în log, dar e în fişierul 0600 ──────────────────
    config.SETUP_TOKEN = None
    api._setup_token = None
    api._clear_setup_token_file()
    cap.clear()
    await api.init_setup_token()
    gen = api._setup_token
    logged = cap.text()
    check("generated: s-a generat un token", bool(gen) and len(gen) > 10)
    check("generated: tokenul ÎNTREG NU apare în log", gen not in logged, logged)
    check("generated: logul conţine un prefix scurt (verificare la ochi)", gen[:6] in logged)
    check("generated: marker-ul vechi nu mai poartă o valoare reală",
          "WEBTERM_SETUP_TOKEN=%s" % gen not in logged, logged)
    check("generated: fişierul 0600 există", os.path.exists(tok_file))
    check("generated: conţinutul fişierului e tokenul întreg",
          open(tok_file).read() == gen)
    mode = stat.S_IMODE(os.stat(tok_file).st_mode)
    check("generated: fişierul e numai-owner (0600)", mode == 0o600, oct(mode))

    # ── După setup reuşit (cont creat), fişierul dispare ─────────────────────────────────────
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        r = await c.post("/api/setup",
                         json={"email": "a@b.co", "password": PW, "setup_token": gen})
        check("setup cu tokenul generat reuşeşte", r.status_code == 200, str(r.status_code))
        check("după setup, fişierul 0600 e şters (secretul nu zăboveşte)",
              not os.path.exists(tok_file))

    print(f"\n{ok}/{total} passed")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
