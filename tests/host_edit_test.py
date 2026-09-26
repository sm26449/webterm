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

# Middleware-ul `csrf_guard` cere `Origin` pe metodele care schimbă ceva şi refuză
# lipsa lui (ca `_origin_ok` pentru WebSocket). Testele imită un BROWSER, deci trimit
# antetul; fără el ar testa o cale pe care niciun browser n-o produce.
_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
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
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30, headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})

        async def get(hid):
            hosts = (await c.get("/api/hosts")).json()
            return next(h for h in hosts if h["id"] == hid)

        # ── host agent, cu notă şi folder ────────────────────────────────────
        r = await c.post("/api/hosts", json={"name": "srv", "note": "nota-mea",
                                             "folder": "productie", "tags": "Prod, Debian PROD"})
        hid = r.json()["id"]
        h = await get(hid)
        # etichetele se normalizează (lowercase, fără duplicate/spaţii) şi se întorc ca listă
        check("tag-urile normalizate + listă", h["tags"] == ["prod", "debian"], repr(h["tags"]))

        # ── 1. PATCH parţial: nu şterge ce nu i-ai dat ───────────────────────
        r = await c.patch(f"/api/hosts/{hid}", json={"name": "srv-redenumit"})
        check("PATCH parţial → 200", r.status_code == 200, r.text)
        h = await get(hid)
        check("numele s-a schimbat", h["name"] == "srv-redenumit", h["name"])
        check("nota NU s-a şters (defectul vechi)", h["note"] == "nota-mea", repr(h["note"]))
        check("folderul NU s-a şters (defectul vechi)", h["folder"] == "productie",
              repr(h["folder"]))

        # PATCH pe tags: se schimbă independent, rămân normalizate
        r = await c.patch(f"/api/hosts/{hid}", json={"tags": "web,web,STAGING"})
        check("PATCH tags → 200", r.status_code == 200, r.text)
        h = await get(hid)
        check("tag-urile s-au înlocuit + normalizat", h["tags"] == ["web", "staging"], repr(h["tags"]))
        check("nota NU s-a şters la PATCH de tags", h["note"] == "nota-mea", repr(h["note"]))

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

        # ── 8. editarea care deconectează agentul DETAŞEAZĂ hub-urile ────────
        # Bug raportat: editezi un host agent, agentul e deconectat şi reconectat, dar
        # terminalul deschis nu mai poate scrie. Cauza: `sources.pop` de dinaintea
        # disconnect-ului face `was_current` False în `_shutdown`, deci `on_detached` nu
        # rulează şi hub-ul rămâne `attached=True` → `ensure_attached` de la reconectare e
        # no-op, iar noua conexiune de agent nu re-primeşte niciodată `attach`. Handler-ul
        # cheamă acum `detach_host_hubs` explicit; verificăm exact asta.
        from app import core  # noqa: E402
        class _StubHub:
            def __init__(self, host_id):
                self.host_id = host_id
                self.attached = True
            def on_detached(self):
                self.attached = False
        stub = _StubHub(hid)
        core.hubs["a" * 32] = stub
        try:
            # cazul UI: AddHostModal trimite MEREU connection_type, chiar la o redenumire pură.
            # Cu el NESCHIMBAT nu trebuie să se întâmple NIMIC la conexiune — altfel fiecare
            # redenumire deconecta agentul degeaba şi lăsa terminalul fără input.
            cur_type = (await get(hid))["connection_type"]
            r = await c.patch(f"/api/hosts/{hid}",
                              json={"name": "srv-r2", "connection_type": cur_type})
            check("redenumire cu connection_type NESCHIMBAT → fără deconectare",
                  r.json().get("disconnected") is False, r.text)
            check("…şi hub-urile rămân ataşate (fără bounce inutil)", stub.attached is True)
            # o SCHIMBARE reală de conexiune tot detaşează, ca noua sursă să re-ataşeze
            await c.patch(f"/api/hosts/{hid}", json={"hostname": "10.0.0.77"})
            check("schimbare reală de conexiune DETAŞEAZĂ hub-urile (re-attach la reconectare)",
                  stub.attached is False)
        finally:
            core.hubs.pop("a" * 32, None)

        # ── 9. host inexistent ───────────────────────────────────────────────
        r = await c.patch("/api/hosts/99999", json={"name": "x"})
        check("host inexistent → 404", r.status_code == 404, str(r.status_code))

        # ── 10. Wake-on-LAN: construcţia magic packet-ului + căile de eroare ──
        # send_magic_packet e din AGENT (stdlib), dar îl testăm aici ca unit hermetic.
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("ptyd_wol",
                os.path.join(os.path.dirname(__file__), "..", "agent", "ptyd.py"))
        # ptyd.py rulează cod la import? nu — doar definiţii + `if __name__`. Îl încărcăm.
        try:
            _ptyd = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_ptyd)
            import socket as _sock, threading as _thr, time as _tm
            got = {}
            def _listen():
                r = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                r.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
                r.bind(("127.0.0.1", 19999)); r.settimeout(3)
                try: got["d"], _ = r.recvfrom(200)
                except _sock.timeout: pass
                r.close()
            th = _thr.Thread(target=_listen); th.start(); _tm.sleep(0.2)
            norm = _ptyd.send_magic_packet("aa-bb-cc-dd-ee-ff", "127.0.0.1", 19999)
            th.join()
            pkt = got.get("d", b"")
            check("magic packet: 102 octeţi, 6×0xFF + MAC×16",
                  len(pkt) == 102 and pkt[:6] == b"\xff" * 6 and pkt[6:] == bytes.fromhex("aabbccddeeff") * 16,
                  pkt.hex()[:40])
            check("MAC normalizat (separatori indiferenţi)", norm == "AA:BB:CC:DD:EE:FF", norm)
            bad = False
            try: _ptyd.send_magic_packet("nu-e-mac")
            except ValueError: bad = True
            check("MAC invalid → ValueError", bad)
        except Exception as e:                       # noqa: BLE001
            check("send_magic_packet importabil din agent", False, str(e))

        # căile de eroare ale endpoint-ului wake (fără agent real → nu poate trezi)
        wh = (await c.post("/api/hosts", json={"name": "wake-host"})).json()["id"]
        r = await c.post(f"/api/hosts/{wh}/wake")
        check("wake fără diagnostic (niciun MAC) → 400 wake.noMac",
              r.status_code == 400 and r.headers.get("X-WebTerm-Error") == "wake.noMac", r.text)
        ssh = (await c.post("/api/hosts", json={"name": "ssh-host", "connection_type": "ssh",
               "hostname": "1.2.3.4", "ssh_username": "u"})).json()["id"]
        r = await c.post(f"/api/hosts/{ssh}/wake")
        check("wake pe host non-agent → 400 wake.notAgent",
              r.status_code == 400 and r.headers.get("X-WebTerm-Error") == "wake.notAgent", r.text)

        # ── 10b. wake: interfeţele VIRTUALE nu candidează (audit 2026-09) ──
        # Pe un host cu Docker, diagnosticele listează `docker0`/`br-…` înaintea lui `eth0`
        # (sortare /sys/class/net); fără filtru, MAC-ul bridge-ului devenea ţinta „preferată"
        # şi subnetul 172.17/16 găsea drept peer orice alt host cu Docker → fals succes.
        import json as _json
        _diag = lambda ifaces: _json.dumps({"network": {"interfaces": ifaces}})  # noqa: E731
        await db.execute("UPDATE hosts SET diagnostics=? WHERE id=?", _diag([
            {"name": "docker0", "mac": "02:42:ac:11:00:01", "ipv4": ["172.17.0.1/16"]},
        ]), wh)
        r = await c.post(f"/api/hosts/{wh}/wake")
        check("wake cu DOAR interfeţe virtuale → 400 wake.noMac (bridge-ul nu candidează)",
              r.status_code == 400 and r.headers.get("X-WebTerm-Error") == "wake.noMac", r.text)
        await db.execute("UPDATE hosts SET diagnostics=? WHERE id=?", _diag([
            {"name": "docker0", "mac": "02:42:ac:11:00:01", "ipv4": ["172.17.0.1/16"]},
            {"name": "eth0", "mac": "aa:bb:cc:dd:ee:ff", "ipv4": ["192.168.77.10/24"]},
        ]), wh)
        r = await c.post(f"/api/hosts/{wh}/wake")
        check("wake cu docker0 + eth0 → trece de noMac (eth0 rămâne candidat), pică la noPeer",
              r.status_code == 400 and r.headers.get("X-WebTerm-Error") == "wake.noPeer", r.text)
        await db.execute("UPDATE hosts SET diagnostics=? WHERE id=?", _diag([
            {"name": "eth0", "mac": "aa:bb:cc:dd:ee:ff", "ipv4": ["10.0.0.5/32"]},
        ]), wh)
        r = await c.post(f"/api/hosts/{wh}/wake")
        check("wake cu /32 (fără broadcast real) → 400 wake.noMac, nu unicast inutil raportat ca succes",
              r.status_code == 400 and r.headers.get("X-WebTerm-Error") == "wake.noMac", r.text)

        # ── 10c. alertele offline pe un host 2FA: OPRIREA cere step-up, REPORNIREA nu ──
        # Sweep-ul refuză ca marcajul neautentificat de uninstall să cumpere tăcere; un cookie
        # furat nu are voie s-o cumpere nici pe calea asta (audit 2026-09).
        uid = (await db.fetchone("SELECT id FROM users WHERE email='a@b.co'"))["id"]
        g2 = (await c.post("/api/hosts", json={"name": "muted-2fa"})).json()["id"]
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", g2)
        security._stepup_windows.clear()
        r = await c.patch(f"/api/hosts/{g2}", json={"alerts_muted": True})
        check("mute alerte pe host 2FA fără step-up → 403", r.status_code == 403, r.text)
        security.open_stepup_window(uid, g2)
        r = await c.patch(f"/api/hosts/{g2}", json={"alerts_muted": True})
        check("mute alerte pe host 2FA cu fereastră de step-up → ok", r.status_code == 200, r.text)
        security._stepup_windows.clear()
        r = await c.patch(f"/api/hosts/{g2}", json={"alerts_muted": False})
        check("UNmute nu cere step-up (întăreşte monitorizarea)", r.status_code == 200, r.text)
        row = await db.fetchone("SELECT alerts_muted, offline_notified FROM hosts WHERE id=?", g2)
        check("unmute → alerts_muted=0 şi dedup-ul re-armat (offline_notified=0)",
              row["alerts_muted"] == 0 and row["offline_notified"] == 0, str(dict(row)))

        # ── 10d. agent v50 hermetic: fs_stat + guard-ul offset la fs_write ──
        # handle_ctrl foloseşte doar `self.send_ctrl` pe aceste ramuri → self fals cu colector.
        class _CtrlSink:
            def __init__(self): self.r = []
            def send_ctrl(self, m): self.r.append(m)
        import base64 as _b64
        snk = _CtrlSink()
        with tempfile.TemporaryDirectory() as td:
            fp = os.path.join(td, "f.bin")
            with open(fp, "wb") as f:
                f.write(b"hello")
            _ptyd.Agent.handle_ctrl(snk, {"op": "fs_stat", "path": fp, "id": 1})
            st = snk.r[-1]
            check("fs_stat: fişier real → exists + size corect",
                  st.get("ok") and st.get("exists") and st.get("size") == 5, str(st))
            _ptyd.Agent.handle_ctrl(snk, {"op": "fs_stat", "path": fp + ".nu", "id": 2})
            st = snk.r[-1]
            check("fs_stat: fişier lipsă → ok cu exists=False (resume de la 0, nu eroare)",
                  st.get("ok") and st.get("exists") is False and st.get("size") == 0, str(st))
            _ptyd.Agent.handle_ctrl(snk, {"op": "fs_stat", "path": td, "id": 3})
            st = snk.r[-1]
            check("fs_stat: director → dir=True", st.get("ok") and st.get("dir") is True, str(st))
            _ptyd.Agent.handle_ctrl(snk, {"op": "fs_write", "path": fp, "id": 4,
                                          "data_b64": _b64.b64encode(b"XY").decode(), "offset": 3})
            st = snk.r[-1]
            check("fs_write: offset ≠ mărimea curentă → offset_conflict (fără append orb)",
                  not st.get("ok") and st.get("code") == "offset_conflict", str(st))
            with open(fp, "rb") as f:
                check("…şi fişierul a rămas neatins", f.read() == b"hello")
            _ptyd.Agent.handle_ctrl(snk, {"op": "fs_write", "path": fp, "id": 5,
                                          "data_b64": _b64.b64encode(b"XY").decode(), "offset": 5})
            st = snk.r[-1]
            with open(fp, "rb") as f:
                data = f.read()
            check("fs_write: offset = mărimea curentă → append reuşit",
                  st.get("ok") and data == b"helloXY", "%s %r" % (st, data))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
