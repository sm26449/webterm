"""Linkuri de share pe un host 2FA: invitatul vede terminalul DOAR cât e ataşat un operator
VERIFICAT, iar un link live nu publică o sesiune încheiată (raport de securitate 2026-11, lot 1).

Trei găuri, toate prin `/ws/shared/{token}`:
  1. Prezenţa se citea din `is_owner`: un client-owner BLOCAT (alt cont fără step-up) sau un
     watcher read-only ţinea uşa deschisă unui invitat nou după plecarea operatorului real.
  2. Plecarea operatorului nu atingea invitaţii deja ataşaţi: rămâneau până la idle-lock.
  3. Pe o sesiune încheiată nu există hub, deci poarta era sărită şi invitatul primea coada
     transcriptului — o înregistrare publicată prin `share.live`, fără `recording.view`.

Rulăm handler-ele WS REALE (`browser_ws`, `shared_ws`) cu un WebSocket fals, ca în
sec_stepup_cap_test. Clientul-owner „blocat al altui cont" e construit direct (BrowserClient):
ce testăm e decizia de prezenţă, nu fluxul de autorizare al celui de-al doilea cont.
"""
import asyncio
import json
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
os.environ["WEBTERM_IDLE_LOCK_SECS"] = "300"
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


class _Client:
    host = "127.0.0.1"


class FakeWS:
    def __init__(self, cookie_token=None):
        self.headers = {"origin": os.environ["WEBTERM_PUBLIC_URL"], "user-agent": "test"}
        self.cookies = {security.COOKIE_NAME: cookie_token} if cookie_token else {}
        self.query_params = {}
        self.client = _Client()
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.texts = []
        self.binary = []
        self.closed = None
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000):
        self.closed = code
        await self.inbox.put({"type": "websocket.disconnect"})

    async def send_text(self, t):
        self.texts.append(t)

    async def send_bytes(self, b):
        self.binary.append(b)

    async def receive(self):
        return await self.inbox.get()

    def msgs(self, typ):
        out = []
        for t in self.texts:
            try:
                m = json.loads(t)
            except ValueError:
                continue
            if m.get("type") == typ:
                out.append(m)
        return out


async def settle(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        await asyncio.sleep(0.02)
    return cond()


TASKS = []


def start(coro):
    t = asyncio.create_task(coro)
    TASKS.append(t)
    return t


async def leave(ws, task):
    await ws.inbox.put({"type": "websocket.disconnect"})
    try:
        await asyncio.wait_for(task, 5)
    except Exception:                                  # noqa: BLE001
        task.cancel()


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200, r.text[:120])
        uid = (await db.fetchone("SELECT id FROM users WHERE email=?", "a@b.co"))["id"]
        hid = (await c.post("/api/hosts", json={"name": "critic", "require_2fa": True})).json()["id"]
        plain = (await c.post("/api/hosts", json={"name": "plain"})).json()["id"]
        tok = await security.create_web_session(uid)

        async def new_session(host_id, sid, state="live"):
            await db.execute(
                "INSERT INTO sessions(id,host_id,title,state,created,rows,cols) VALUES(?,?,?,?,?,?,?)",
                sid, host_id, "root", state, time.time(), 24, 80)

        async def share(sid, writable=1):
            t = security.new_token()
            await db.execute("UPDATE sessions SET share_token=?, share_expires=?, share_writable=?,"
                             " share_by=? WHERE id=?",
                             security.sha256_hex(t), time.time() + 3600, writable, "a@b.co", sid)
            return t

        def guests(hub):
            return [x for x in hub.clients if not x.is_owner]

        src_inputs = []

        class _Src:
            epoch = "ep"

            async def send_data(self, s, data):
                src_inputs.append(data)

        # ── 1. operatorul pleacă, rămâne doar un client-owner BLOCAT al altui cont ──────────
        sid = "a" * 32
        await new_session(hid, sid)
        core.session_sources[sid] = _Src()
        security._stepup_windows.clear()
        security.open_stepup_window(uid, hid)
        op = FakeWS(tok)
        t_op = start(api.browser_ws(op, sid))
        await settle(lambda: sid in core.hubs and core.hubs[sid].clients)
        hub = core.hubs[sid]
        check("precondiţie: operatorul e ataşat deblocat", not hub.locked
              and all(not x.locked for x in hub.clients) and hub.has_operator())

        stranger = core.BrowserClient(FakeWS(None), hub)
        stranger.id, stranger.is_owner, stranger.user_id = "o_x", True, 999
        stranger.writable = True
        stranger.lock()                                # alt cont, fără step-up: blocat individual
        hub.clients.add(stranger)
        check("un client-owner blocat NU contează drept operator",
              not core.SessionHub.has_operator(type("H", (), {"locked": False,
                                                               "clients": {stranger}})()))

        await leave(op, t_op)
        check("după plecarea operatorului hub-ul NU e blocat (idle-lock încă departe)",
              hub.locked is False)
        stok = await share(sid)
        g1 = FakeWS(None)
        t_g1 = start(api.shared_ws(g1, stok))
        await settle(lambda: len(guests(hub)) == 1)
        gc1 = guests(hub)
        check("invitat nou cu doar un owner blocat ataşat → BLOCAT",
              len(gc1) == 1 and gc1[0].locked and bool(g1.msgs("locked")), g1.texts[-3:])
        check("…şi n-a primit niciun octet din scrollback", g1.binary == [], len(g1.binary))
        await hub.handle_input(gc1[0], b"id\n")
        check("…iar input-ul lui (link writable) e refuzat", src_inputs == [], str(src_inputs))

        # ── 2. un watcher read-only deblocat nu ţine nici el uşa deschisă ───────────────────
        stranger.writable = False
        stranger.unlock()
        check("un watcher read-only deblocat NU contează drept operator", not hub.has_operator())
        hub.clients.discard(stranger)
        await leave(g1, t_g1)

        # ── 3. invitat ataşat cât operatorul e prezent, apoi operatorul pleacă → blocat ACUM ──
        security.open_stepup_window(uid, hid)
        op2 = FakeWS(tok)
        t_op2 = start(api.browser_ws(op2, sid))
        await settle(lambda: any(x.is_owner for x in hub.clients))
        g2 = FakeWS(None)
        t_g2 = start(api.shared_ws(g2, stok))
        await settle(lambda: len(guests(hub)) == 1)
        gc2 = guests(hub)
        check("invitat cu operator verificat prezent → deblocat", len(gc2) == 1 and not gc2[0].locked)
        await leave(op2, t_op2)
        check("operatorul pleacă → invitatul e blocat pe loc (nu la idle-lock)",
              gc2[0].locked and any(m.get("reason") == "owner" for m in g2.msgs("locked")),
              g2.texts[-3:])
        check("…fără să blocheze hub-ul (procesele, ceilalţi: neatinşi)", hub.locked is False)
        await hub.handle_input(gc2[0], b"rm -rf /tmp/x\n")
        check("…şi tastele lui nu mai ajung la PTY", src_inputs == [], str(src_inputs))

        # ── 4. operatorul revine (fereastră deschisă) → invitatul se deblochează ─────────────
        security.open_stepup_window(uid, hid)
        op3 = FakeWS(tok)
        t_op3 = start(api.browser_ws(op3, sid))
        await settle(lambda: not gc2[0].locked)
        check("operatorul revine → invitatul primeşte `unlocked`",
              not gc2[0].locked and bool(g2.msgs("unlocked")), g2.texts[-3:])

        # ── 5. operatorul devine read-only (rol retras) → invitatul e blocat ─────────────────
        oc3 = next(x for x in hub.clients if x.is_owner)
        oc3.writable = False
        await hub.sync_guests()
        check("operator retrogradat la read-only → invitatul blocat", gc2[0].locked)
        oc3.writable = True
        await hub.sync_guests()
        await leave(op3, t_op3)
        await leave(g2, t_g2)

        # ── 5b. ferestrele de ATAŞARE (review lot 1, F1 + F2). Output-ul care curge cât invitatul
        #    se ataşează (audit, roster, drum la agent) nu-i ajunge dacă nu e operator; iar un owner
        #    FĂRĂ step-up, în timpul propriei ataşări, nu contează drept operator verificat.
        orig_record = api.audit.record
        seen = {}

        async def leaky_record(ts, who, *a, **kw):
            if who.startswith("guest:"):
                for x in list(hub.clients):
                    x.push(b"LEAK-LIVE")              # output live în fereastra de ataşare
            else:
                seen["has_operator"] = hub.has_operator()
            return await orig_record(ts, who, *a, **kw)
        api.audit.record = leaky_record
        try:
            g5 = FakeWS(None)                         # niciun operator ataşat
            t_g5 = start(api.shared_ws(g5, stok))
            await settle(lambda: bool(g5.msgs("locked")))
            await asyncio.sleep(0.2)
            check("F1: output pus în coadă cât invitatul (fără operator) se ataşează → nu-i ajunge",
                  not any(b"LEAK-LIVE" in b for b in g5.binary), g5.binary)
            await leave(g5, t_g5)

            security._stepup_windows.clear()          # owner fără fereastră de step-up
            ow = FakeWS(tok)
            t_ow = start(api.browser_ws(ow, sid))
            await settle(lambda: "has_operator" in seen)
            check("F2: owner fără step-up, în timpul ataşării, NU e operator verificat",
                  seen.get("has_operator") is False, seen)
            await settle(lambda: bool(ow.msgs("locked")))
            check("…şi n-a primit output live în fereastra ataşării",
                  not any(b"LEAK-LIVE" in b for b in ow.binary), ow.binary)
            await leave(ow, t_ow)
        finally:
            api.audit.record = orig_record
        if hub.locked:                                # F2 a blocat hub-ul (corect): deblocăm pt. restul
            await hub.unlock(time.time())

        # ── 5c. închiderea sesiunii anulează linkul live (nu mai e listat ca activ) ───────────
        sid5 = "e" * 32
        await new_session(hid, sid5)
        row5 = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid5)
        h5 = core.get_or_create_hub(row5)
        await share(sid5)
        await h5.on_exit(0, None)
        r5 = await db.fetchone("SELECT share_token, share_expires, state FROM sessions WHERE id=?", sid5)
        check("sesiunea se încheie → linkul live e anulat în DB",
              r5["state"] == "closed" and r5["share_token"] is None and r5["share_expires"] is None,
              dict(r5))

        # ── 6. host FĂRĂ 2FA: nimic nu se schimbă — invitatul rămâne după plecarea owner-ului ──
        sid2 = "b" * 32
        await new_session(plain, sid2)
        p = FakeWS(tok)
        t_p = start(api.browser_ws(p, sid2))
        await settle(lambda: sid2 in core.hubs and core.hubs[sid2].clients)
        h2 = core.hubs[sid2]
        ptok = await share(sid2)
        g3 = FakeWS(None)
        t_g3 = start(api.shared_ws(g3, ptok))
        await settle(lambda: len(guests(h2)) == 1)
        await leave(p, t_p)
        check("host fără 2FA: invitatul rămâne deblocat după plecarea owner-ului",
              len(guests(h2)) == 1 and not guests(h2)[0].locked)
        await leave(g3, t_g3)

        # ── 7. sesiune ÎNCHEIATĂ: linkul live nu mai livrează nimic ───────────────────────────
        sid3 = "c" * 32
        await new_session(plain, sid3, state="closed")
        out_path, _ = core.transcript_paths(sid3)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(b"secret-din-transcript\r\n")
        ctok = await share(sid3, writable=0)
        g4 = FakeWS(None)
        await api.shared_ws(g4, ctok)
        check("ws/shared pe sesiune închisă → refuzat (4404), fără accept", g4.closed == 4404
              and not g4.accepted, (g4.closed, g4.accepted))
        check("…şi niciun octet din transcript", g4.binary == [] and not any(
            "secret-din-transcript" in t for t in g4.texts), g4.texts)
        r = await c.get("/api/shared/" + ctok)
        check("GET /api/shared pe sesiune închisă → 404 link.invalid (nici titlul)",
              r.status_code == 404 and r.json().get("code") == "link.invalid", r.text[:120])
        r = await c.post(f"/api/sessions/{sid3}/share", json={})
        check("crearea unui link live pe sesiune închisă → 409 session.notLive",
              r.status_code == 409 and r.json().get("code") == "session.notLive", r.text[:160])
        await db.execute("UPDATE sessions SET state='lost' WHERE id=?", sid3)
        r = await c.post(f"/api/sessions/{sid3}/share", json={})
        check("…şi pe una pierdută (lost) → 409", r.status_code == 409, r.text[:120])

        # ── 8. control: sesiune LIVE fără 2FA → linkul se creează, ca înainte ────────────────
        r = await c.post(f"/api/sessions/{sid2}/share", json={})
        check("link live pe sesiune live (host fără 2FA) → 200", r.status_code == 200
              and "/#/shared/" in r.json().get("url", ""), r.text[:160])

    for t in TASKS:
        if not t.done():
            t.cancel()
    for h in list(core.hubs.values()):
        try:
            h.teardown()
        except Exception:                                  # noqa: BLE001
            pass
    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    res = asyncio.run(run())
    sys.stdout.flush()
    os._exit(0 if res else 1)
