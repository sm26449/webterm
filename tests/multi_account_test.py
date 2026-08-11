"""Conturi multiple, TOATE cu drepturi depline (fără RBAC).

Cerut de două audituri externe (2026-08-06): la 2-3 oameni, contul partajat face
imposibilă întrebarea „cine a făcut asta". Ce se schimbă e ATRIBUIREA, nu autorizarea —
deci testele de aici verifică exact asta: identităţi separate, credenţiale separate,
revocare reală la ştergere; şi NICIO diferenţă de drepturi între conturi.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, security  # noqa: E402

# Middleware-ul `csrf_guard` cere `Origin` pe metodele care schimbă ceva şi refuză
# lipsa lui (ca `_origin_ok` pentru WebSocket). Testele imită un BROWSER, deci trimit
# antetul; fără el ar testa o cale pe care niciun browser n-o produce.
_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0
PW1, PW2 = "parolabuna1", "parolabuna2"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as a:
        r = await a.post("/api/setup", json={"email": "unu@x.co", "password": PW1,
                                             "setup_token": "test-setup"})
        check("primul cont creat prin setup", r.status_code == 200)

        r = await a.post("/api/users", json={"email": "doi@x.co", "password": PW2})
        check("cont nou FĂRĂ re-auth → 401 (un cont e încă o cheie la regat)", r.status_code == 401)
        r = await a.post("/api/users", json={"email": "nu-e-email", "password": PW2,
                                             "current_password": PW1})
        check("email invalid respins", r.status_code == 400)
        r = await a.post("/api/users", json={"email": "doi@x.co", "password": "scurt",
                                             "current_password": PW1})
        check("parolă prea scurtă respinsă", r.status_code == 400)
        r = await a.post("/api/users", json={"email": "doi@x.co", "password": PW2,
                                             "current_password": PW1})
        check("cont creat cu re-auth", r.status_code == 200 and len(r.json()) == 2)
        r = await a.post("/api/users", json={"email": "DOI@x.co", "password": PW2,
                                             "current_password": PW1})
        check("email duplicat (case-insensitive) respins", r.status_code == 409)
        me = [u for u in (await a.get("/api/users")).json() if u["is_self"]]
        check("lista marchează contul curent", len(me) == 1 and me[0]["email"] == "unu@x.co")

    # ── contul nou e admin deplin: aceleaşi drepturi, fără roluri ──
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as b:
        r = await b.post("/api/login", json={"email": "doi@x.co", "password": PW2})
        check("contul nou se poate autentifica", r.status_code == 200 and r.json().get("ok"))
        r = await b.post("/api/hosts", json={"name": "al-doilea-cont"})
        check("contul nou poate crea hosturi (drepturi depline, fără RBAC)", r.status_code == 200)
        hid = r.json()["id"]
        r = await b.get("/api/audit?limit=20")
        entries = r.json()["entries"]
        check("auditul distinge ACUM cine a făcut acţiunea",
              any(e["actor"] == "doi@x.co" for e in entries)
              and any(e["actor"] == "unu@x.co" for e in entries),
              str([(e["actor"], e["path"]) for e in entries[:4]]))
        r = await b.post(f"/api/users/{me[0]['id']}/delete", json={"current_password": PW2})
        check("un cont poate şterge alt cont (sunt egale)", r.status_code == 200)
        r = await b.delete(f"/api/hosts/{hid}")
        check("curăţare host", r.status_code in (200, 404))

    # ── ştergerea e o REVOCARE: sesiunile contului şters nu mai merg ──
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as a2:
        r = await a2.post("/api/login", json={"email": "unu@x.co", "password": PW1})
        check("contul şters nu se mai poate autentifica", r.status_code == 401)

    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as b2:
        await b2.post("/api/login", json={"email": "doi@x.co", "password": PW2})
        users = (await b2.get("/api/users")).json()
        check("a rămas un singur cont", len(users) == 1)
        r = await b2.post(f"/api/users/{users[0]['id']}/delete",
                          json={"current_password": PW2})
        check("nu-ţi poţi şterge propriul cont (te-ai bloca la jumătatea operaţiei)",
              r.status_code == 400)
        # al doilea cont, ca să testăm gardul „ultimul cont"
        await b2.post("/api/users", json={"email": "trei@x.co", "password": PW1,
                                          "current_password": PW2})
        users = (await b2.get("/api/users")).json()
        other = [u for u in users if not u["is_self"]][0]
        await b2.post(f"/api/users/{other['id']}/delete", json={"current_password": PW2})
        check("după ştergere rămâne exact contul curent",
              len((await b2.get("/api/users")).json()) == 1)

        # setup-ul rămâne închis: conturile se adaugă doar DIN interior, autentificat
        async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as anon:
            r = await anon.post("/api/setup", json={"email": "hacker@x.co", "password": PW1,
                                                    "setup_token": "test-setup"})
            check("setup-ul rămâne blocat după primul cont", r.status_code == 409)
            r = await anon.get("/api/users")
            check("lista de conturi cere autentificare", r.status_code == 401)

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
