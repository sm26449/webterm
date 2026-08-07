"""Jurnalul de audit: fiecare cerere care schimbă ceva ajunge în audit_log, cu actor/IP/status,
fără să scurgă corpuri de cerere. Rulează in-process prin ASGI (fără agent, fără rețea)."""
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
from app import api, audit, config, db, security  # noqa: E402
from app.main import app  # noqa: E402

ok = 0
total = 0


def check(name, cond):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


async def entries(**kw):
    return await audit.recent(**kw)


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    PASSWORD = "parolabuna1"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": PASSWORD,
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200)

        # ── acoperire automată: middleware-ul prinde orice mutație, fără apel manual ──
        r = await c.post("/api/hosts", json={"name": "auditat"})
        hid = r.json()["id"]
        rows = await entries()
        hostrow = [e for e in rows if e["path"] == "/api/hosts" and e["method"] == "POST"]
        check("POST înregistrat automat", len(hostrow) == 1)
        check("actor = contul autentificat", hostrow[0]["actor"] == "a@b.co")
        check("status păstrat", hostrow[0]["status"] == 200)
        check("IP-ul clientului prezent", bool(hostrow[0]["ip"]))

        before_get = len(await entries())
        await c.get("/api/hosts")
        check("GET-urile NU se înregistrează (jurnal de acțiuni, nu de trafic)",
              len(await entries()) == before_get)

        # ── context semantic acolo unde calea nu e de-ajuns ──
        await c.post(f"/api/hosts/{hid}/run", json={"command": "rm -rf /tmp/x"})
        run = [e for e in await entries() if e["path"].endswith("/run")]
        check("run înregistrat chiar dacă a eșuat (host offline)", len(run) == 1)
        check("comanda ajunge în detaliu", "rm -rf /tmp/x" in run[0]["detail"])
        check("statusul de eșec e păstrat", run[0]["status"] >= 400)

        # ── login eșuat: fără cookie, dar cu emailul încercat ──
        r = await c.post("/api/login", json={"email": "a@b.co", "password": "gresita"})
        fail = [e for e in await entries() if e["path"] == "/api/login"]
        check("login eșuat înregistrat", len(fail) == 1 and fail[0]["status"] == 401)
        check("emailul încercat e vizibil deși n-are sesiune", fail[0]["actor"] == "a@b.co")

        # ── nicio scurgere de corp: parolele nu ajung niciodată în jurnal ──
        allrows = await entries(limit=1000)
        blob = " ".join(str(v) for e in allrows for v in e.values())
        check("parola nu apare nicăieri în jurnal", PASSWORD not in blob)
        check("parola greșită nu apare nici ea", "gresita" not in blob)

        # ── filtrare + paginare ──
        check("filtru pe text (q)", all("/run" in e["path"] for e in await entries(q="/run")))
        check("filtru doar eșecuri", all(e["status"] >= 400 for e in await entries(failed_only=True)))
        newest = (await entries(limit=1))[0]
        older = await entries(before=newest["ts"], limit=1)
        check("paginare în trecut (before)", older and older[0]["ts"] < newest["ts"])

        # ── zgomot exclus: istoricul de comenzi are deja tabelul lui ──
        n = len(await entries(limit=1000))
        await c.post("/api/history", json={"host_id": hid, "host_name": "auditat",
                                           "command": "ls", "exit_code": 0})
        check("/api/history nu umple jurnalul", len(await entries(limit=1000)) == n)

        # ...dar ŞTERGEREA lui e altceva. `_SKIP` compara doar prefixul căii, indiferent de
        # metodă, deci golirea întregului istoric căutabil de comenzi — exact ce ar face cineva
        # care vrea să-şi acopere urmele — nu lăsa nicio urmă.
        n = len(await entries(limit=1000))
        await c.delete("/api/history")
        after = await entries(limit=1000)
        check("DELETE /api/history ESTE auditat", len(after) == n + 1)
        check("intrarea de ştergere e recognoscibilă",
              any(e["method"] == "DELETE" and e["path"] == "/api/history" for e in after))

        # ── citirile care SCOT date: middleware-ul urmărea doar mutaţiile ─────
        # Scenariul pentru care există jurnalul e „mi-a fost furat cookie-ul, ce a scos?".
        # Descărcarea unui transcript nu schimbă nimic, deci nu apărea nicăieri.
        n = len(await entries(limit=1000))
        await c.get("/api/sessions/%s/transcript?format=txt" % ("0" * 32))
        after = await entries(limit=1000)
        check("GET transcript ESTE auditat (exfiltrare)", len(after) > n)
        # ...iar simpla listare rămâne în afara jurnalului: se cere la fiecare refresh
        n = len(await entries(limit=1000))
        await c.get("/api/hosts")
        check("GET /api/hosts (listare) NU umple jurnalul",
              len(await entries(limit=1000)) == n)

        # ── un client anonim nu poate umfla jurnalul ─────────────────────────
        # Orice 401/404 pe /api/* scria un rând, iar retenţia e doar temporală: cine bate
        # API-ul umple discul mult înainte ca vechimea să conteze.
        anon = httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30)
        n = len(await entries(limit=1000))
        for _ in range(5):
            await anon.post("/api/hosts", json={"name": "x"})
            await anon.delete("/api/forwards/999")
        await anon.aclose()
        check("cereri anonime respinse NU umplu jurnalul",
              len(await entries(limit=1000)) == n)

        # ── endpointul de citire cere autentificare ──
        r = await c.get("/api/audit?limit=5")
        check("GET /api/audit autentificat → 200", r.status_code == 200 and r.json()["entries"])
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as anon:
        r = await anon.get("/api/audit")
        check("GET /api/audit fără sesiune → 401", r.status_code == 401)

    # ── retenție ──
    await db.execute("UPDATE audit_log SET ts=? WHERE id=(SELECT MIN(id) FROM audit_log)",
                     time.time() - (config.AUDIT_RETENTION_DAYS + 1) * 86400)
    n_before = (await db.fetchone("SELECT COUNT(*) c FROM audit_log"))["c"]
    await audit.prune()
    n_after = (await db.fetchone("SELECT COUNT(*) c FROM audit_log"))["c"]
    check("retenția șterge intrările prea vechi", n_after == n_before - 1)

    print(f"\n{ok}/{total} passed")
    return ok == total


async def run():
    # Fără `finally`, orice excepţie din test lăsa conexiunea aiosqlite deschisă, iar firul ei
    # (non-daemon) ţinea procesul viu: testul ATÂRNA în loc să raporteze eroarea. Am pierdut
    # minute bune pe asta crezând că e o blocare de reţea, când era doar un TypeError.
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
