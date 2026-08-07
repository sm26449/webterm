"""Editarea unui host (PATCH /api/hosts/{id}) — parţială, completă şi reversibilă.

De ce există fişierul: PATCH-ul lua un `HostIn` întreg şi scria doar name/note/folder.
Două defecte, ambele tăcute:

  1. câmpurile de conexiune (hostname, user, port, credenţiale) erau ACCEPTATE şi ignorate —
     clientul primea `ok: true` fără să se fi schimbat nimic, deci nu avea cum să afle;
  2. un PATCH parţial ŞTERGEA nota şi folderul, fiindcă lipsa lor din corp înseamnă `""`
     în `HostIn`. Simpla redenumire a unui host îi golea nota.

Iar în UI nu exista deloc „Editează": puteai doar muta hostul în alt grup sau să-l ştergi.
Un IP schimbat însemna ştergere + recreare, adică pierderea istoricului.

Cazul care a cerut asta: agentul nu mai răspunde şi vrei să intri pe SSH ca să-l repari.
Comutarea agent→SSH trebuie să fie posibilă ORICÂND — dar credenţialele SSH sunt şterse la
instalarea agentului dacă politica era `ephemeral`, deci le cerem explicit, nu eşuăm abia la
prima conectare.
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
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})

        async def get(hid):
            hosts = (await c.get("/api/hosts")).json()
            return next(h for h in hosts if h["id"] == hid)

        # ── host agent, cu notă şi folder ────────────────────────────────────
        r = await c.post("/api/hosts", json={"name": "srv", "note": "nota-mea",
                                             "folder": "productie"})
        hid = r.json()["id"]

        # ── 1. PATCH parţial: nu şterge ce nu i-ai dat ───────────────────────
        r = await c.patch(f"/api/hosts/{hid}", json={"name": "srv-redenumit"})
        check("PATCH parţial → 200", r.status_code == 200, r.text)
        h = await get(hid)
        check("numele s-a schimbat", h["name"] == "srv-redenumit", h["name"])
        check("nota NU s-a şters (defectul vechi)", h["note"] == "nota-mea", repr(h["note"]))
        check("folderul NU s-a şters (defectul vechi)", h["folder"] == "productie",
              repr(h["folder"]))

        # PATCH gol: nimic de făcut, dar nici eroare — clientul află că n-a schimbat nimic
        r = await c.patch(f"/api/hosts/{hid}", json={})
        check("PATCH fără câmpuri → changed=False", r.json().get("changed") is False, r.text)

        # ── 2. câmpurile de conexiune chiar se aplică ────────────────────────
        # Înainte erau acceptate şi ignorate: `ok: true` peste zero modificări.
        r = await c.patch(f"/api/hosts/{hid}", json={
            "connection_type": "ssh", "hostname": "10.0.0.9", "ssh_username": "admin",
            "ssh_port": 2222, "auth_method": "password", "credential": "secret",
            "credential_policy": "stored"})
        check("agent → SSH cu credenţial → 200", r.status_code == 200, r.text)
        h = await get(hid)
        check("tipul conexiunii s-a schimbat", h["connection_type"] == "ssh",
              h["connection_type"])
        check("hostname-ul chiar s-a scris", h["hostname"] == "10.0.0.9", str(h["hostname"]))
        check("userul chiar s-a scris", h["ssh_username"] == "admin", str(h["ssh_username"]))
        check("portul chiar s-a scris", h["ssh_port"] == 2222, str(h["ssh_port"]))
        check("credenţialul e stocat", h["has_credentials"] is True, str(h))

        # ── 3. credenţialul nu se pierde la o editare care nu-l menţionează ──
        # Altfel redenumirea unui host SSH îl deconecta definitiv.
        await c.patch(f"/api/hosts/{hid}", json={"name": "srv-ssh"})
        check("credenţialul supravieţuieşte unei redenumiri",
              (await get(hid))["has_credentials"] is True)

        # ── 4. pinul de host-key aparţine MAŞINII, nu hostului din WebTerm ───
        await db.execute("UPDATE hosts SET known_hosts=? WHERE id=?", "ssh-rsa PIN-VECHI", hid)
        r = await c.patch(f"/api/hosts/{hid}", json={"hostname": "10.0.0.10"})
        check("mutarea pe altă maşină raportează resetarea pinului",
              r.json().get("host_key_reset") is True, r.text)
        row = await db.fetchone("SELECT known_hosts FROM hosts WHERE id=?", hid)
        check("pinul vechi chiar e şters (altfel noua maşină pare MITM)",
              row["known_hosts"] is None, repr(row["known_hosts"]))
        r = await c.patch(f"/api/hosts/{hid}", json={"note": "doar nota"})
        check("o editare fără mutare NU resetează pinul",
              r.json().get("host_key_reset") is False, r.text)

        # ── 5. validări: nu lăsăm hostul într-o stare neconectabilă ──────────
        r = await c.patch(f"/api/hosts/{hid}", json={"connection_type": "quantum"})
        check("tip de conexiune necunoscut → 400", r.status_code == 400, str(r.status_code))
        r2 = await c.post("/api/hosts", json={"name": "gol"})
        hid2 = r2.json()["id"]
        r = await c.patch(f"/api/hosts/{hid2}", json={"connection_type": "ssh"})
        check("SSH fără hostname → 400", r.status_code == 400, str(r.status_code))
        r = await c.patch(f"/api/hosts/{hid2}", json={"connection_type": "ssh",
                                                     "hostname": "1.2.3.4"})
        check("SSH fără user → 400", r.status_code == 400, str(r.status_code))

        # ── 6. întoarcerea la SSH după ce agentul a preluat ──────────────────
        # Provisioning-ul şterge credenţialul dacă politica era `ephemeral`. Fără el nu ne
        # putem conecta, deci refuzăm ACUM, cu un mesaj care spune ce lipseşte — nu la prima
        # conectare, când omul crede că a stricat altceva.
        r = await c.patch(f"/api/hosts/{hid2}", json={
            "connection_type": "ssh", "hostname": "1.2.3.4", "ssh_username": "root"})
        check("SSH fără credenţial stocat → 400", r.status_code == 400, str(r.status_code))
        check("mesajul spune CE lipseşte", "credential" in r.text.lower(), r.text)
        r = await c.patch(f"/api/hosts/{hid2}", json={
            "connection_type": "ssh", "hostname": "1.2.3.4", "ssh_username": "root",
            "credential": "parola", "credential_policy": "stored"})
        check("acelaşi PATCH cu credenţial → 200", r.status_code == 200, r.text)
        # …şi înapoi pe agent: hostul rămâne acelaşi, cu tot istoricul lui
        r = await c.patch(f"/api/hosts/{hid2}", json={"connection_type": "agent"})
        check("SSH → agent (dus-întors) → 200", r.status_code == 200, r.text)
        check("hostul e din nou pe agent", (await get(hid2))["connection_type"] == "agent")

        # politica `ask` nu cere credenţial stocat: se cere la fiecare conectare
        r = await c.post("/api/hosts", json={"name": "ask-host"})
        hid3 = r.json()["id"]
        r = await c.patch(f"/api/hosts/{hid3}", json={
            "connection_type": "ssh", "hostname": "1.2.3.4", "ssh_username": "root",
            "credential_policy": "ask"})
        check("politica `ask` nu cere credenţial stocat", r.status_code == 200, r.text)

        # ── 7. host inexistent ───────────────────────────────────────────────
        r = await c.patch("/api/hosts/99999", json={"name": "x"})
        check("host inexistent → 404", r.status_code == 404, str(r.status_code))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
