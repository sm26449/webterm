"""Ştergerea unui host curăţă TOT ce îl referenţiază, iar validările de jump nu lasă hosturi
„bricked".

De ce există fişierul (audit 2026-10-04, G-12 / G-30..G-33 / recent-commits #1, #2, #5):

  * `hosts.id` e INTEGER PRIMARY KEY fără AUTOINCREMENT → id-ul celui mai nou host şters se
    REUTILIZEAZĂ la următorul INSERT (cazul normal al ţintelor „conectează o dată"). Cum
    `PRAGMA foreign_keys` e oprit, `delete_host` lăsa `sessions`, `port_forwards`, `ssh_keys`,
    `agent_events` pe loc → hostul nou moştenea forward-urile (servite prin agentul LUI către
    porturi de pe altă maşină), istoricul de sesiuni şi cheia de deploy („are deja o cheie").
    Niciun test nu acoperea DELETE /api/hosts.
  * copiii jump: un agent cu ţinte ssh-jump/telnet-jump SALVATE sub el nu se şterge (409, cod
    stabil); cei efemeri pleacă odată cu el (altfel rămân invizibili în sidebar — randaţi doar
    sub părinte).
  * reaper-ul efemer ştergea sesiunile fără să arhiveze transcripturile → fişiere orfane pe disc,
    pentru totdeauna (nicio măturare nu caută fişiere fără rând în DB).
  * PATCH: self-via (A via A) şi ciclul (A via B via A) → 400; tip necunoscut la POST → 400 (era
    coerce tăcut la agent); telnet creat prin API primea portul 22; `online` pentru telnet-jump
    era permanent False (nu are sursă proprie) → sesiunile lui vii dispăreau din tot UI-ul.
"""
import asyncio
import os
import sys
import tempfile
import time
import uuid

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402

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


class FakeAgent(core.AgentConnection):
    """Doar cât îi trebuie lui `_host_json` / `_host_online`: o sursă de tip AgentConnection
    înregistrată sub id-ul agentului (nu deschide niciun ws)."""

    def __init__(self, host_id):
        self.host_id = host_id
        self.metrics = None
        self.agent_version = None
        self.link = {}
        self.forwards = {}

    async def disconnect(self):
        pass


async def _count(table, col, hid):
    row = await db.fetchone(f"SELECT COUNT(*) AS c FROM {table} WHERE {col}=?", hid)
    return row["c"]


async def _seed_session(hid, state="closed"):
    """Sesiune închisă + transcripturile ei pe disc (ce lasă în urmă o sesiune reală)."""
    sid = uuid.uuid4().hex
    await db.execute(
        "INSERT INTO sessions(id, host_id, title, state, created, closed_at)"
        " VALUES(?,?,?,?,?,?)", sid, hid, "t", state, time.time() - 10, time.time())
    out, cast = core.transcript_paths(sid)
    out.write_bytes(b"hello\r\n")
    cast.write_text('{"version":2}\n')
    return sid


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30, headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})

        async def hosts_by_id():
            return {h["id"]: h for h in (await c.get("/api/hosts")).json()}

        # ── 1. delete purges sessions / forwards / ssh_keys / agent_events / connections ──
        r = await c.post("/api/hosts", json={"name": "victim"})
        vid = r.json()["id"]
        r = await c.post("/api/hosts", json={"name": "target-agent"})
        tid = r.json()["id"]                 # ţinta unei muchii de deploy-key dinspre victim
        sid = await _seed_session(vid)
        await db.execute(
            "INSERT INTO port_forwards(host_id, label, slug, target_host, target_port, scheme,"
            " enabled, created) VALUES(?,?,?,?,?,?,?,?)",
            vid, "web", "web-victim", "127.0.0.1", 8080, "http", 1, time.time())
        kid = await db.execute(
            "INSERT INTO ssh_keys(host_id, public_key, fingerprint, created) VALUES(?,?,?,?)",
            vid, "ssh-ed25519 AAAA test", "SHA256:x", time.time())
        await db.execute(
            "INSERT INTO ssh_key_deployments(key_id, target_host_id, line, deployed_at)"
            " VALUES(?,?,?,?)", kid, tid, "ssh-ed25519 AAAA test", time.time())
        await db.execute(
            "INSERT INTO agent_events(host_id, ts, event) VALUES(?,?,?)", vid, time.time(), "connect")
        await db.execute(
            "INSERT INTO connections(host_id, label, engine, created) VALUES(?,?,?,?)",
            vid, "db", "postgres", time.time())
        await db.execute(
            "INSERT INTO command_history(host_id, host_name, command, created) VALUES(?,?,?,?)",
            vid, "victim", "ls", time.time())
        epoch_before = security.forward_epoch() if hasattr(security, "forward_epoch") else None

        r = await c.delete(f"/api/hosts/{vid}")
        check("DELETE /api/hosts/{id} → 200", r.status_code == 200, r.text)
        check("rândul hosts a dispărut", await _count("hosts", "id", vid) == 0)
        check("sessions purjate", await _count("sessions", "host_id", vid) == 0)
        out, cast = core.transcript_paths(sid)
        check("transcripturile NU rămân orfane în transcripts/",
              not out.exists() and not cast.exists())
        check("transcripturile sunt ARHIVATE (recuperabile, cu retenţie), nu şterse",
              (config.ARCHIVE_DIR / out.name).exists() and (config.ARCHIVE_DIR / cast.name).exists())
        check("port_forwards purjate", await _count("port_forwards", "host_id", vid) == 0)
        # cheile NU se şterg, se detaşează (M-6: evidenţa supravieţuieşte hostului): rândul rămâne,
        # dar pe id NEGAT, ca următorul host cu acelaşi id să nu-l moştenească
        check("ssh_keys: nimic pe id-ul pozitiv (nu se moşteneşte)", await _count("ssh_keys", "host_id", vid) == 0)
        check("ssh_keys: evidenţa cheii rămâne, detaşată (id negat)", await _count("ssh_keys", "host_id", -vid) == 1)
        check("ssh_key_deployments ale cheii rămân (cheia e încă pe ţinte)",
              await _count("ssh_key_deployments", "key_id", kid) == 1)
        check("agent_events purjate", await _count("agent_events", "host_id", vid) == 0)
        check("connections purjate", await _count("connections", "host_id", vid) == 0)
        hist = await db.fetchone("SELECT host_id, host_name FROM command_history WHERE host_name='victim'")
        check("istoricul de comenzi rămâne (jurnal global), dar fără legătura pe id",
              hist is not None and hist["host_id"] is None, str(dict(hist)) if hist else "lipsă")
        if epoch_before is not None:
            check("epoca biletelor de forward a fost bumpată (slug-ul se poate recicla)",
                  security.forward_epoch() != epoch_before)

        # ── 2. muchiile de deploy-key care aveau hostul şters ca ŢINTĂ rămân ca ORFANI (cheia
        #       e încă în authorized_keys pe maşina aia), dar detaşate de id-ul reutilizabil ──
        r = await c.post("/api/hosts", json={"name": "src-agent"})
        sid2 = r.json()["id"]
        kid2 = await db.execute(
            "INSERT INTO ssh_keys(host_id, public_key, fingerprint, created) VALUES(?,?,?,?)",
            sid2, "ssh-ed25519 BBBB test", "SHA256:y", time.time())
        await db.execute(
            "INSERT INTO ssh_key_deployments(key_id, target_host_id, line, deployed_at)"
            " VALUES(?,?,?,?)", kid2, tid, "ssh-ed25519 BBBB test", time.time())
        r = await c.delete(f"/api/hosts/{tid}")
        check("ştergerea ţintei → 200", r.status_code == 200, r.text)
        check("muchia către ţinta ştearsă nu mai e pe id-ul pozitiv",
              await _count("ssh_key_deployments", "target_host_id", tid) == 0)
        # 2 orfani: muchia lui kid2 (de acum) + cea a cheii lui `victim` din pasul 1 (şi ea ţintea tid)
        check("muchiile către ţinta ştearsă rămân ca orfani (id negat)",
              await _count("ssh_key_deployments", "target_host_id", -tid) == 2)
        r = await c.get(f"/api/hosts/{sid2}/deploy-key")
        dl = r.json()["deployments"]
        check("listarea sursei arată orfanul fără nume (M-6)",
              len(dl) == 1 and dl[0]["target_name"] in ("", None), r.text)
        check("cheia SURSEI supravieţuieşte", await _count("ssh_keys", "id", kid2) == 1)

        # ── 3. următorul host cu ACELAŞI id nu moşteneşte nimic ──
        # ştergem cel mai nou host (id maxim) → SQLite fără AUTOINCREMENT dă acelaşi id la INSERT
        r = await c.post("/api/hosts", json={"name": "newest"})
        nid = r.json()["id"]
        await _seed_session(nid)
        await db.execute(
            "INSERT INTO port_forwards(host_id, label, slug, target_host, target_port, scheme,"
            " enabled, created) VALUES(?,?,?,?,?,?,?,?)",
            nid, "web", "web-newest", "127.0.0.1", 8081, "http", 1, time.time())
        await db.execute(
            "INSERT INTO ssh_keys(host_id, public_key, fingerprint, created) VALUES(?,?,?,?)",
            nid, "ssh-ed25519 CCCC test", "SHA256:z", time.time())
        core.pending_updates[nid] = True
        r = await c.delete(f"/api/hosts/{nid}")
        check("ştergerea celui mai nou host → 200", r.status_code == 200, r.text)
        r = await c.post("/api/hosts", json={"name": "reborn"})
        rid = r.json()["id"]
        check("id-ul se REUTILIZEAZĂ (premisa defectului G-12)", rid == nid, f"{rid} vs {nid}")
        r = await c.get(f"/api/hosts/{rid}/sessions")
        check("hostul renăscut nu are istoric de sesiuni", r.status_code == 200 and r.json() == [], r.text)
        r = await c.get(f"/api/hosts/{rid}/forwards")
        check("hostul renăscut nu are forward-uri", r.status_code == 200 and r.json() == [], r.text)
        r = await c.get(f"/api/hosts/{rid}/deploy-key")
        # răspunsul e {"key": {...} | None, ...}: verificăm `key`, nu un câmp inexistent la rădăcină
        check("hostul renăscut nu are cheie de deploy",
              r.status_code == 200 and (r.json() or {}).get("key") is None, r.text)
        h = (await hosts_by_id())[rid]
        check("starea din RAM (update_pending) nu e moştenită", h["update_pending"] is False, str(h["update_pending"]))

        # ── 4. copii jump: persistenţi → 409 cu cod stabil; efemeri → purjaţi recursiv ──
        r = await c.post("/api/hosts", json={"name": "bastion"})
        bid = r.json()["id"]
        r = await c.post("/api/hosts", json={"name": "sw1", "connection_type": "telnet-jump",
                                             "hostname": "10.0.0.9", "via_host_id": bid})
        check("telnet-jump creat sub bastion", r.status_code == 200, r.text)
        child = r.json()["id"]
        r = await c.delete(f"/api/hosts/{bid}")
        check("ştergerea agentului cu copil jump SALVAT → 409", r.status_code == 409, r.text)
        check("409 poartă codul stabil host.hasJumpChildren",
              r.headers.get("X-WebTerm-Error") == "host.hasJumpChildren", r.headers.get("X-WebTerm-Error"))
        check("bastionul şi copilul sunt încă acolo",
              await _count("hosts", "id", bid) == 1 and await _count("hosts", "id", child) == 1)
        r = await c.post(f"/api/hosts/{bid}/uninstall?force=1")
        check("uninstall cu copil jump salvat → tot 409 (înainte să-i cerem agentului ceva)",
              r.status_code == 409 and r.headers.get("X-WebTerm-Error") == "host.hasJumpChildren", r.text)
        # retipizarea agentului-părinte lasă copiii fără agent → acelaşi refuz
        r = await c.patch(f"/api/hosts/{bid}", json={"connection_type": "ssh", "hostname": "1.2.3.4",
                                                     "ssh_username": "u", "credential": "p"})
        check("PATCH agent→ssh cu copii jump → 409", r.status_code == 409, r.text)
        # copilul efemer pleacă odată cu părintele (cu sesiunile + transcripturile lui arhivate)
        r = await c.post("/api/hosts", json={"name": "once", "connection_type": "telnet-jump",
                                             "hostname": "10.0.0.10", "via_host_id": bid, "ephemeral": True})
        eph = r.json()["id"]
        esid = await _seed_session(eph)
        await c.delete(f"/api/hosts/{child}")
        r = await c.delete(f"/api/hosts/{bid}")
        check("fără copii persistenţi → ştergerea trece", r.status_code == 200, r.text)
        check("copilul EFEMER a fost purjat recursiv", await _count("hosts", "id", eph) == 0)
        check("sesiunile copilului efemer purjate", await _count("sessions", "host_id", eph) == 0)
        eo, _ = core.transcript_paths(esid)
        check("transcripturile copilului efemer arhivate", (config.ARCHIVE_DIR / eo.name).exists())

        # ── 5. validări jump: self-via şi ciclu → 400 ──
        r = await c.post("/api/hosts", json={"name": "ag-a"})
        a = r.json()["id"]
        r = await c.patch(f"/api/hosts/{a}", json={"connection_type": "ssh-jump", "hostname": "h",
                                                   "ssh_username": "u", "via_host_id": a})
        check("PATCH via == propriul id → 400", r.status_code == 400, r.text)
        check("codul stabil sshjump.viaLoop", r.headers.get("X-WebTerm-Error") == "sshjump.viaLoop")
        hrow = await db.fetchone("SELECT connection_type, via_host_id FROM hosts WHERE id=?", a)
        check("hostul NU a fost retipizat (rămâne agent, fără via)",
              hrow["connection_type"] == "agent" and hrow["via_host_id"] is None, str(dict(hrow)))
        # ciclu A via B via A: B e un agent cu `via_host_id` agăţat (stare moştenită din DB-uri
        # vechi, unde retipizarea nu golea coloana) → PATCH A via B ar închide bucla
        r = await c.post("/api/hosts", json={"name": "ag-b"})
        b = r.json()["id"]
        await db.execute("UPDATE hosts SET via_host_id=? WHERE id=?", a, b)
        r = await c.patch(f"/api/hosts/{a}", json={"connection_type": "ssh-jump", "hostname": "h",
                                                   "ssh_username": "u", "via_host_id": b})
        check("PATCH care ar închide un ciclu A→B→A → 400", r.status_code == 400, r.text)
        check("ciclul poartă acelaşi cod sshjump.viaLoop", r.headers.get("X-WebTerm-Error") == "sshjump.viaLoop")
        await db.execute("UPDATE hosts SET via_host_id=NULL WHERE id=?", b)

        # ── 6. ieşirea din familia jump goleşte via_host_id ──
        r = await c.post("/api/hosts", json={"name": "jump-x", "connection_type": "ssh-jump",
                                             "hostname": "h", "ssh_username": "u", "via_host_id": a,
                                             "credential": "p"})
        jx = r.json()["id"]
        r = await c.patch(f"/api/hosts/{jx}", json={"connection_type": "ssh"})
        check("PATCH ssh-jump → ssh → 200", r.status_code == 200, r.text)
        h = (await hosts_by_id())[jx]
        check("via_host_id golit la ieşirea din familia jump", h["via_host_id"] is None, str(h["via_host_id"]))

        # ── 7. tip necunoscut la POST → 400 (nu agent tăcut) ──
        r = await c.post("/api/hosts", json={"name": "typo", "connection_type": "SSH",
                                             "hostname": "h", "ssh_username": "u", "credential": "p"})
        check("POST cu tip necunoscut → 400", r.status_code == 400, r.text)
        check("codul stabil host.badType", r.headers.get("X-WebTerm-Error") == "host.badType")
        check("nu s-a creat niciun host", not any(h["name"] == "typo" for h in (await hosts_by_id()).values()))

        # ── 8. telnet prin API fără port → 23 (ssh rămâne 22; portul explicit se respectă) ──
        r = await c.post("/api/hosts", json={"name": "tn", "connection_type": "telnet", "hostname": "h"})
        check("telnet fără port → 23", r.status_code == 200 and r.json()["ssh_port"] == 23, r.text)
        r = await c.post("/api/hosts", json={"name": "tj", "connection_type": "telnet-jump",
                                             "hostname": "h", "via_host_id": a})
        tj = r.json()["id"]
        check("telnet-jump fără port → 23", r.json()["ssh_port"] == 23, r.text)
        r = await c.post("/api/hosts", json={"name": "ss", "connection_type": "ssh", "hostname": "h",
                                             "ssh_username": "u", "credential": "p"})
        check("ssh fără port → 22", r.json()["ssh_port"] == 22, r.text)
        r = await c.post("/api/hosts", json={"name": "tn2", "connection_type": "telnet", "hostname": "h",
                                             "ssh_port": 2323})
        check("portul explicit (contractul UI) se respectă", r.json()["ssh_port"] == 2323, r.text)

        # ── 9. online pentru telnet-jump urmează agentul părinte ──
        hs = await hosts_by_id()
        check("telnet-jump fără agent conectat → online False", hs[tj]["online"] is False)
        core.sources[a] = FakeAgent(a)
        try:
            hs = await hosts_by_id()
            check("agentul părinte conectat → telnet-jump online True", hs[tj]["online"] is True, str(hs[tj]))
            check("...fără metrice proprii (nu are sursă)", hs[tj]["metrics"] is None)
            check("agentul însuşi online", hs[a]["online"] is True)
            st = (await c.get("/api/status")).json()
            check("numărătoarea din /api/status foloseşte aceeaşi regulă",
                  st["hosts"]["online"] == sum(1 for h in hs.values() if h["online"]), str(st["hosts"]))
            r = await c.get(f"/api/hosts/{tj}/events")
            check("panoul de evenimente/diagnostic al hostului telnet-jump zice online",
                  r.status_code == 200 and r.json()["online"] is True, r.text[:200])
        finally:
            core.sources.pop(a, None)
        hs = await hosts_by_id()
        check("agentul plecat → telnet-jump redevine offline", hs[tj]["online"] is False)

        # ── 10. reaper-ul efemer arhivează transcripturile (nu lasă fişiere orfane) ──
        r = await c.post("/api/hosts", json={"name": "once2", "connection_type": "telnet-jump",
                                             "hostname": "10.0.0.11", "via_host_id": a, "ephemeral": True})
        e2 = r.json()["id"]
        await db.execute("UPDATE hosts SET created=? WHERE id=?", time.time() - 3600, e2)
        rsid = await _seed_session(e2)
        await core.sweep_ephemeral_hosts()
        check("reaper: hostul efemer fără sesiuni vii e şters", await _count("hosts", "id", e2) == 0)
        ro, rc = core.transcript_paths(rsid)
        check("reaper: transcripturile mutate în arhivă, nimic orfan",
              not ro.exists() and (config.ARCHIVE_DIR / ro.name).exists()
              and (config.ARCHIVE_DIR / rc.name).exists())

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
