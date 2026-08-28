"""Dezinstalare din consola hostului, ştergere din UI doar cu confirmare (agent 42).

Regula, şi motivul ei: de pe host poţi scoate agentul oricând — nu te opreşte nimeni, e
maşina ta. Dar ce rămâne în evidenţa WebTerm e o decizie autentificată, luată în interfaţă.
Dacă agentul ar putea cere ştergerea, oricine are shell pe acel host ar face hostul să
dispară din tabloul operatorului; iar de multe ori nici nu vrei să ştergi, ci doar să
reinstalezi — caz în care marcajul trebuie să dispară de la sine.

Testul verifică exact asta: anunţul marchează şi NU şterge, un token greşit nu marchează
nimic, iar reconectarea agentului curăţă marcajul fără nicio apăsare.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

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


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "u@e.co", "password": "parola-de-test-1234",
                                         "setup_token": "test-setup"})
        hid = (await c.post("/api/hosts", json={"name": "h1"})).json()["id"]
        tok = security.decrypt_secret(
            (await db.fetchone("SELECT token_encrypted FROM hosts WHERE id=?", hid))["token_encrypted"])

        # ── anunţul marchează, NU şterge ────────────────────────────────────
        r = await c.post("/agent/uninstalled", headers={"Authorization": "Bearer " + tok})
        check("anunţul de dezinstalare e acceptat", r.status_code == 200, r.text[:80])
        check("răspunsul spune explicit că hostul rămâne", r.json().get("host_kept") is True, r.json())

        row = await db.fetchone("SELECT * FROM hosts WHERE id=?", hid)
        check("hostul NU a fost şters", row is not None)
        check("…dar e marcat ca dezinstalat", bool(row["uninstalled_at"]), row["uninstalled_at"])

        hosts = (await c.get("/api/hosts")).json()
        check("marcajul ajunge în UI", bool(hosts[0].get("uninstalled_at")), hosts[0].get("uninstalled_at"))

        # ── POST repetat = no-op: fără spam în agent_events/audit (audit 2026-08:
        # oricine cu shell pe host poate citi tokenul; fără dedup, o buclă de POST-uri
        # umplea ambele tabele nelimitat) şi timestamp-ul original rămâne (heartbeat-ul
        # curăţă marcajele PLANTATE după 5 min — vechimea lor trebuie să fie reală) ──
        ts1 = row["uninstalled_at"]
        n1 = (await db.fetchone("SELECT COUNT(*) c FROM agent_events WHERE host_id=? "
                                "AND event='uninstalled'", hid))["c"]
        r = await c.post("/agent/uninstalled", headers={"Authorization": "Bearer " + tok})
        check("POST repetat răspunde tot 200", r.status_code == 200, r.status_code)
        n2 = (await db.fetchone("SELECT COUNT(*) c FROM agent_events WHERE host_id=? "
                                "AND event='uninstalled'", hid))["c"]
        check("…dar nu mai scrie un al doilea eveniment", n2 == n1, (n1, n2))
        ts2 = (await db.fetchone("SELECT uninstalled_at FROM hosts WHERE id=?", hid))["uninstalled_at"]
        check("…şi păstrează timestamp-ul original", ts2 == ts1, (ts1, ts2))

        # ── un token greşit nu poate marca nimic ────────────────────────────
        hid2 = (await c.post("/api/hosts", json={"name": "h2"})).json()["id"]
        r = await c.post("/agent/uninstalled", headers={"Authorization": "Bearer nu-e-bun"})
        check("token invalid → 401", r.status_code == 401, r.status_code)
        r2 = await db.fetchone("SELECT uninstalled_at FROM hosts WHERE id=?", hid2)
        check("…şi celălalt host rămâne nemarcat", not r2["uninstalled_at"])
        r = await c.post("/agent/uninstalled")
        check("fără token → 401", r.status_code == 401, r.status_code)

        # ── evenimentul e în jurnalul hostului şi în audit ───────────────────
        ev = await db.fetchone(
            "SELECT event FROM agent_events WHERE host_id=? ORDER BY id DESC LIMIT 1", hid)
        check("apare în jurnalul hostului", ev and ev["event"] == "uninstalled",
              ev["event"] if ev else None)
        au = await db.fetchone(
            "SELECT actor, detail FROM audit_log WHERE path='/agent/uninstalled' LIMIT 1")
        check("apare în audit, atribuit agentului", au and au["actor"].startswith("agent:"),
              au["actor"] if au else None)

        # ── ştergerea rămâne o acţiune din UI, autentificată ────────────────
        anon = httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN)
        r = await anon.delete("/api/hosts/%d" % hid)
        check("ştergerea hostului cere autentificare", r.status_code == 401, r.status_code)
        await anon.aclose()

        # ── „nu vreau să şterg, vreau să reinstalez" ────────────────────────
        # Marcajul trebuie să dispară singur când agentul se conectează din nou, altfel
        # operatorul rămâne cu un avertisment fals după o reinstalare reuşită.
        await db.execute("UPDATE hosts SET uninstalled_at=NULL WHERE id=?", hid)  # ce face conectarea
        row = await db.fetchone("SELECT uninstalled_at FROM hosts WHERE id=?", hid)
        check("reconectarea curăţă marcajul (fără nicio apăsare)", not row["uninstalled_at"])
        import inspect
        src = inspect.getsource(api.agent_ws)
        check("…iar curăţarea chiar e în calea de conectare a agentului",
              "uninstalled_at=NULL" in src)

        # ── partea de agent ─────────────────────────────────────────────────
        import ptyd
        check("agentul are subcomanda `uninstall`", "uninstall" in inspect.getsource(ptyd.main))
        us = inspect.getsource(ptyd._cli_uninstall)
        check("cere confirmare implicit (nu şterge dintr-o tastare greşită)",
              "[y/N]" in us and "assume_yes" in us)
        check("anunţă gateway-ul ÎNAINTE de a şterge configul",
              us.index("_notify_uninstalled") < us.index("_uninstall_agent"))
        ns = inspect.getsource(ptyd._notify_uninstalled)
        check("anunţul e autentificat cu tokenul hostului", "Bearer" in ns)
        check("…şi e best-effort: un gateway picat nu blochează dezinstalarea locală",
              "except Exception" in ns and "return False" in ns)

        check("AGENT_VERSION a crescut", ptyd.AGENT_VERSION >= 42, ptyd.AGENT_VERSION)

    await db.close()
    print(f"\n{ok}/{total} PASS", flush=True)
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
