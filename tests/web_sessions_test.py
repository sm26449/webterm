"""Dispozitive conectate: listare + revocare per-dispozitiv (Settings → Securitate).

Golul închis: până acum, dacă bănuiai un cookie furat, aveai doar două opţiuni, amândouă
prea mari — schimbi parola (omoară TOATE sesiunile, inclusiv a ta) sau intri prin SSH pe
server. Lipsea calea de mijloc.

Testul verifică efectul, nu forma: după revocare, cookie-ul ACELUI dispozitiv nu mai
autentifică nimic. Un test care s-ar uita doar la rândul din tabelă ar trece şi dacă
sesiunea ar rămâne valabilă din altă cauză.
"""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402

from app import api, config, db, security  # noqa: E402
from app.main import app  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


PW = "parola-de-test-1234"


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)

    async def client():
        return httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN)

    # ── trei „dispozitive": fiecare cu propriul jar de cookie-uri ────────────
    a = await client()
    r = await a.post("/api/setup", json={"email": "u@example.com", "password": PW,
                                         "setup_token": "test-setup"})
    check("cont creat", r.status_code == 200, r.text[:80])
    uid = (await db.fetchone("SELECT id FROM users WHERE email=?", "u@example.com"))["id"]

    b = await client()
    r = await b.post("/api/login", json={"email": "u@example.com", "password": PW},
                     headers={**_ORIGIN, "user-agent": "Mozilla/5.0 (iPhone) Safari/605"})
    check("al doilea dispozitiv autentificat", r.status_code == 200, r.text[:80])
    c = await client()
    r = await c.post("/api/login", json={"email": "u@example.com", "password": PW},
                     headers={**_ORIGIN, "user-agent": "Mozilla/5.0 (X11; Linux) Firefox/128"})
    check("al treilea dispozitiv autentificat", r.status_code == 200, r.text[:80])

    # ── listarea ────────────────────────────────────────────────────────────
    lst = (await a.get("/api/account/sessions")).json()
    check("toate trei apar în listă", len(lst) == 3, len(lst))
    check("exact unul e marcat drept cel curent", sum(1 for x in lst if x["current"]) == 1,
          [x["current"] for x in lst])
    labels = [x["label"] for x in lst]
    check("user-agent-ul devine etichetă lizibilă",
          any("iOS" in x for x in labels) and any("Firefox" in x for x in labels), labels)
    check("nu expunem amprenta credenţialei",
          all("token" not in k and "hash" not in k for x in lst for k in x), lst[0].keys())

    # ── revocarea unui dispozitiv ───────────────────────────────────────────
    victim = next(x for x in lst if not x["current"] and "iOS" in x["label"])
    r = await a.delete("/api/account/sessions/%d" % victim["id"])
    check("revocare acceptată", r.status_code == 200, r.text[:80])

    # EFECTUL, nu rândul: cookie-ul acelui dispozitiv nu mai autentifică
    r = await b.get("/api/hosts")
    check("dispozitivul revocat nu mai are acces (401)", r.status_code == 401, r.status_code)
    r = await c.get("/api/hosts")
    check("celelalte dispozitive rămân conectate", r.status_code == 200, r.status_code)
    r = await a.get("/api/hosts")
    check("sesiunea curentă rămâne conectată", r.status_code == 200, r.status_code)

    # nu poţi revoca sesiunea altcuiva
    await db.execute("INSERT INTO users(email,password_hash,created) VALUES(?,?,?)",
                     "alt@example.com", security.hash_password(PW), time.time())
    other = (await db.fetchone("SELECT id FROM users WHERE email=?", "alt@example.com"))["id"]
    tok = await security.create_web_session(other, "curl/8")
    rid = (await db.fetchone("SELECT rowid AS rid FROM web_sessions WHERE token_hash=?",
                             security.sha256_hex(tok)))["rid"]
    r = await a.delete("/api/account/sessions/%d" % rid)
    check("sesiunea altui cont nu poate fi revocată (404)", r.status_code == 404, r.status_code)
    still = await db.fetchone("SELECT 1 FROM web_sessions WHERE rowid=?", rid)
    check("…şi chiar nu a fost ştearsă", still is not None)

    # ── „deconectează de peste tot, în afară de aici" ────────────────────────
    d = await client()
    await d.post("/api/login", json={"email": "u@example.com", "password": PW})
    security.open_stepup_window(uid, 1)
    check("fereastră de step-up deschisă înainte", security.stepup_window_ok(uid, 1) is True)

    r = await a.post("/api/account/sessions/revoke-others")
    check("revocare în masă acceptată", r.status_code == 200, r.text[:80])
    check("a raportat câte a scos", r.json().get("revoked", 0) >= 2, r.json())
    check("sesiunea curentă a supravieţuit",
          (await a.get("/api/hosts")).status_code == 200)
    check("celelalte au murit", (await c.get("/api/hosts")).status_code == 401)
    check("inclusiv cea creată între timp", (await d.get("/api/hosts")).status_code == 401)
    # Ferestrele de step-up sunt per (cont, host), nu per dispozitiv: dacă n-am închide-o,
    # „sudo-ul" dispozitivului scos ar supravieţui pe al nostru.
    check("ferestrele de step-up s-au închis", security.stepup_window_ok(uid, 1) is False)
    # contul celălalt nu e atins
    check("sesiunea altui cont e neatinsă",
          await db.fetchone("SELECT 1 FROM web_sessions WHERE rowid=?", rid) is not None)

    for cl in (a, b, c, d):
        await cl.aclose()
    await db.close()
    print(f"\n{ok}/{total} PASS", flush=True)
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
