"""Endpoint-urile cheii de semnare a flotei (Faza 4) — in-process ASGI.

status / generate (+ 409 la a doua) / lock / unlock / backup (descărcare criptată) și
reflectarea în /api/state (signing_missing). Auth obligatoriu. Fără agent/UI real.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://localhost:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, backup, config, db, security  # noqa: E402

# Middleware-ul `csrf_guard` cere `Origin` pe metodele care schimbă ceva şi refuză
# lipsa lui (ca `_origin_ok` pentru WebSocket). Testele imită un BROWSER, deci trimit
# antetul; fără el ar testa o cale pe care niciun browser n-o produce.
_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0


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
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost", headers=_ORIGIN) as c:
        # auth obligatoriu (înainte de setup)
        r = await c.get("/api/signing/status")
        check("status fără auth → respins", r.status_code in (401, 403))

        r = await c.post("/api/setup", json={"email": "a@b.co", "password": "parolabuna1",
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200)

        r = await c.get("/api/signing/status")
        check("status inițial: fără cheie", r.status_code == 200 and r.json()["exists"] is False)

        r = await c.get("/api/state")
        check("/api/state: signing_missing True fără cheie", r.json().get("signing_missing") is True)

        # generare fără parolă → deblocată imediat
        # cheia flotei nu se schimbă cu un cookie: generate/import/backup cer parola
        # CONTULUI (vezi reauth_secrets_test pentru invariantul complet)
        r = await c.post("/api/signing/generate", json={"current_password": "parolabuna1"})
        js = r.json()
        check("generate → exists+unlocked, pubkey de 64 hex",
              r.status_code == 200 and js["exists"] and js["unlocked"]
              and js["encrypted"] is False and len(js["pubkey"]) == 64)

        # cheia flotei nu se schimbă cu un cookie: generate/import/backup cer parola
        # CONTULUI (vezi reauth_secrets_test pentru invariantul complet)
        r = await c.post("/api/signing/generate", json={"current_password": "parolabuna1"})
        check("a doua generare → 409", r.status_code == 409)

        r = await c.post("/api/signing/import", json={"pem": "orice",
                                                      "current_password": "parolabuna1"})
        check("import când există deja cheie → 409", r.status_code == 409)

        r = await c.get("/api/state")
        check("/api/state: signing_missing False după generare", r.json().get("signing_missing") is False)

        # lock / unlock (cheie fără parolă → unlock merge cu parolă de cheie goală)
        # Ambele cer acum parola CONTULUI: blocarea opreşte auto-update-ul pe toată flota
        # dintr-un singur POST, iar deblocarea era un oracol nelimitat de ghicire a parolei
        # cheii — restul operaţiilor pe cheie o cereau deja.
        r = await c.post("/api/signing/lock", json={})
        check("lock FĂRĂ parola contului → 401", r.status_code == 401, str(r.status_code))
        r = await c.post("/api/signing/unlock", json={})
        check("unlock FĂRĂ parola contului → 401", r.status_code == 401, str(r.status_code))
        r = await c.post("/api/signing/lock", json={"current_password": "parolabuna1"})
        check("lock → unlocked False", r.json()["unlocked"] is False)
        r = await c.post("/api/signing/unlock", json={"current_password": "parolabuna1"})
        check("unlock (fără parolă de cheie) → unlocked True",
              r.status_code == 200 and r.json()["unlocked"] is True)

        # backup: parolă prea scurtă respinsă, apoi descărcare criptată decriptabilă
        r = await c.post("/api/signing/backup", json={"passphrase": "scurt",
                                                      "current_password": "parolabuna1"})
        check("backup cu parolă scurtă → 400", r.status_code == 400)
        r = await c.post("/api/signing/backup", json={"passphrase": "parola-backup",
                                                      "current_password": "parolabuna1"})
        check("backup → octet-stream", r.status_code == 200 and len(r.content) > 0)
        try:
            dec = backup.decrypt(r.content, "parola-backup")
            check("backup-ul cheii e decriptabil cu parola", b"PRIVATE KEY" in dec)
        except Exception as e:  # noqa: BLE001
            check("backup-ul cheii e decriptabil cu parola", False, str(e))

    await db.close()
    print(f"\n{ok}/{total} passed")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
