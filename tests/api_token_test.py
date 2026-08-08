"""Token-uri de automatizare: listă albă strictă, scope-uri, expirare, revocare.

Cerute de auditul extern (job de mentenanţă / CI / monitorizare fără browser deschis), dar
cu prudenţă declarată: un token ocoleşte prin definiţie passkey-ul şi step-up-ul. De-aia
testele de aici insistă pe ce NU poate face — restul API-ului rămâne pe cookie, iar
hosturile cu 2FA rămân accesibile doar unui om într-un browser.
"""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, security  # noqa: E402
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"


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
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
        hid = (await c.post("/api/hosts", json={"name": "normal"})).json()["id"]
        hid2fa = (await c.post("/api/hosts", json={"name": "critic", "require_2fa": True})).json()["id"]

        r = await c.post("/api/tokens", json={"name": "cron", "scopes": ["read"]})
        check("creare fără re-auth → 401", r.status_code == 401)
        r = await c.post("/api/tokens", json={"name": "", "scopes": ["read"],
                                              "current_password": PW})
        check("token fără nume respins (ca să ştii ce revoci)", r.status_code == 400)
        r = await c.post("/api/tokens", json={"name": "x", "scopes": ["admin"],
                                              "current_password": PW})
        check("scope inventat respins", r.status_code == 400)

        r = await c.post("/api/tokens", json={"name": "monitorizare", "scopes": ["read"],
                                              "days": 30, "current_password": PW})
        read_tok = r.json()["token"]
        check("token creat, valoarea în clar întoarsă o singură dată",
              read_tok.startswith(security.TOKEN_PREFIX))
        rows = await db.fetchall("SELECT token_hash FROM api_tokens")
        check("în DB stă doar hash-ul", all(read_tok not in r["token_hash"] for r in rows))
        r = await c.post("/api/tokens", json={"name": "mentenanta", "scopes": ["read", "run"],
                                              "days": 9999, "current_password": PW})
        run_tok = r.json()["token"]
        exp = (await db.fetchone("SELECT expires FROM api_tokens WHERE name='mentenanta'"))["expires"]
        check("expirarea e obligatorie şi plafonată",
              exp - time.time() <= api.TOKEN_MAX_DAYS * 86400 + 5)

    # ── ce POATE şi ce NU POATE un token ──
    H = {"Authorization": "Bearer " + read_tok}
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=H) as t:
        check("read: /api/status", (await t.get("/api/status")).status_code == 200)
        check("read: /api/hosts", (await t.get("/api/hosts")).status_code == 200)
        check("read: /api/sessions", (await t.get("/api/sessions")).status_code == 200)
        # `/api/audit` a fost mutat pe `require_user`: coloana `detail` conţine textul complet
        # al comenzilor rulate pe flotă şi interogările de căutare, adică exact conţinutul pe
        # care toate celelalte citiri îl ţin în afara tokenurilor. Un token ajunge în loguri de
        # CI şi în `.env`; nu are ce căuta în istoricul operaţional.
        check("NU poate citi /api/audit (conţine textul comenzilor)",
              (await t.get("/api/audit")).status_code == 401)
        r = await t.post(f"/api/hosts/{hid}/run", json={"command": "uptime"})
        check("fără scope `run` → 403", r.status_code == 403)
        # tot ce nu e pe lista albă rămâne pe cookie, deci 401 pentru token
        for path, method in (("/api/users", "GET"), ("/api/tokens", "GET"),
                             ("/api/audit", "GET"),
                             ("/api/backup/status", "GET"), ("/api/settings/smtp", "GET"),
                             ("/api/signing/status", "GET")):
            r = await t.request(method, path)
            check(f"NU poate {method} {path}", r.status_code == 401, str(r.status_code))
        r = await t.post("/api/tokens", json={"name": "altul", "scopes": ["run"],
                                              "current_password": PW})
        check("un token nu-şi poate crea alt token", r.status_code == 401)
        r = await t.post("/api/hosts", json={"name": "de-la-token"})
        check("un token nu poate crea hosturi", r.status_code == 401)

    H2 = {"Authorization": "Bearer " + run_tok}
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=H2) as t2:
        r = await t2.post(f"/api/hosts/{hid}/run", json={"command": "uptime"})
        check("cu scope `run` trece de autorizare (cade la host offline)",
              r.status_code != 401 and r.status_code != 403, str(r.status_code))
        r = await t2.post(f"/api/hosts/{hid2fa}/run", json={"command": "uptime"})
        check("host cu 2FA → REFUZAT prin token (step-up cere om + passkey)",
              r.status_code == 403 and "2FA" in r.text, r.text[:60])

    # Auditul se citeşte cu SESIUNE, nu cu tokenul — dar tot trebuie să arate tokenul ca actor
    # al acţiunilor lui. Verificarea rulase prin token; de când `/api/audit` cere `require_user`
    # nu mai poate, iar `r.json()["entries"]` pe un 401 ridica un KeyError care lăsa firul
    # aiosqlite viu şi făcea testul să atârne în loc să pice cu traceback.
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ca:
        await ca.post("/api/login", json={"email": "a@b.co", "password": PW})
        actors = {e["actor"] for e in (await ca.get("/api/audit?limit=20")).json()["entries"]}
        check("auditul arată tokenul ca actor, nu „anonim”",
              any(a.startswith("token:") for a in actors), str(actors))

    # ── expirare şi revocare ──
    await db.execute("UPDATE api_tokens SET expires=? WHERE name='monitorizare'",
                     time.time() - 1)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=H) as t3:
        check("token expirat → 401", (await t3.get("/api/status")).status_code == 401)

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c2:
        await c2.post("/api/login", json={"email": "a@b.co", "password": PW})
        toks = (await c2.get("/api/tokens")).json()
        check("lista arată tokenurile fără valoarea lor",
              toks and all("token" not in x for x in toks))
        tid = [x for x in toks if x["name"] == "mentenanta"][0]["id"]
        await c2.post(f"/api/tokens/{tid}/revoke")
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=H2) as t4:
        check("token revocat → 401 imediat", (await t4.get("/api/status")).status_code == 401)

    # ── un Bearer inventat nu deschide nimic ──
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 headers={"Authorization": "Bearer wt_inventat"}) as t5:
        check("token inexistent → 401", (await t5.get("/api/status")).status_code == 401)

    # ── ştergerea contului îi ia şi tokenurile ──
    # Un token nu are nevoie de cont ca să funcţioneze: e o credenţială de sine stătătoare.
    # Ştergerea contului emitent curăţa sesiuni, passkey-uri şi coduri de recuperare, dar
    # lăsa tokenul viu până la expirare (până la un an) — deci arăta ca o revocare completă
    # fără să fie una. Semnalat de un audit extern.
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c3:
        await c3.post("/api/login", json={"email": "a@b.co", "password": PW})
        await c3.post("/api/users", json={"email": "pleaca@b.co", "password": PW,
                                          "current_password": PW})
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c4:
        await c4.post("/api/login", json={"email": "pleaca@b.co", "password": PW})
        gone_tok = (await c4.post("/api/tokens", json={
            "name": "al-contului-care-pleaca", "scopes": ["read"],
            "current_password": PW})).json()["token"]
    HG = {"Authorization": "Bearer " + gone_tok}
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=HG) as t6:
        check("tokenul contului merge cât timp contul există",
              (await t6.get("/api/status")).status_code == 200)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c5:
        await c5.post("/api/login", json={"email": "a@b.co", "password": PW})
        uid = [u for u in (await c5.get("/api/users")).json()
               if u["email"] == "pleaca@b.co"][0]["id"]
        r = await c5.post(f"/api/users/{uid}/delete", json={"current_password": PW})
        check("contul a fost şters", r.status_code == 200, r.text[:120])
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=HG) as t7:
        check("tokenul lui moare odată cu contul → 401",
              (await t7.get("/api/status")).status_code == 401)

    # ── şi supravieţuieşte unei SCHIMBĂRI DE EMAIL ──
    # Revocarea era cheiată pe `created_by` (emailul), iar schimbarea emailului nu-l migra:
    # creezi token → schimbi emailul → contul e şters → `DELETE ... WHERE created_by=<email nou>`
    # nu prindea nimic, iar tokenul trăia până la 365 de zile. Cauza era cheia mutabilă, nu
    # ştergerea. Acum decizia se ia pe `created_by_id`.
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c6:
        await c6.post("/api/login", json={"email": "a@b.co", "password": PW})
        await c6.post("/api/users", json={"email": "vechi@b.co", "password": PW,
                                          "current_password": PW})
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c7:
        await c7.post("/api/login", json={"email": "vechi@b.co", "password": PW})
        moved_tok = (await c7.post("/api/tokens", json={
            "name": "supravietuitor", "scopes": ["read"], "current_password": PW})).json()["token"]
        r = await c7.post("/api/account", json={"email": "nou@b.co", "current_password": PW})
        check("emailul contului s-a schimbat", r.status_code == 200, r.text[:120])
    HM = {"Authorization": "Bearer " + moved_tok}
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=HM) as t8:
        check("tokenul merge după schimbarea emailului",
              (await t8.get("/api/status")).status_code == 200)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c8:
        await c8.post("/api/login", json={"email": "a@b.co", "password": PW})
        uid2 = [u for u in (await c8.get("/api/users")).json()
                if u["email"] == "nou@b.co"][0]["id"]
        await c8.post(f"/api/users/{uid2}/delete", json={"current_password": PW})
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=HM) as t9:
        check("tokenul moare şi dacă emailul s-a schimbat între timp → 401",
              (await t9.get("/api/status")).status_code == 401)

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
