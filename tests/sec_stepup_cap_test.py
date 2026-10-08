"""Plafonul ABSOLUT de step-up pe terminalele unui host 2FA (3.5.14).

Gaura: `browser_ws` consulta fereastra de step-up DOAR la ataşare, iar revalidarea periodică
verifica doar sesiunea web. Idle-lock-ul măsoară inactivitatea — deci un terminal ţinut în uz
(sau ţinut viu de un script care tastează) rămânea deblocat la nesfârşit, mult peste plafonul de
60 min (`STEPUP_WINDOW_MAX`) pe care îl are orice altă acţiune pe acel host. Iar un invitat cu
drept de scriere, prin link de share, rămânea utilizabil cât owner-ul ţinea hub-ul viu.

Politica (decizie a userului): pe un host `require_2fa`, un terminal în uz se BLOCHEAZĂ când au
trecut 60 min de la factorul care l-a autorizat, dacă nu e deschisă o fereastră de step-up mai
nouă. Procesele rulează mai departe (blocarea = mecanismul existent de idle-lock: output/input
reţinute), deblocarea cere factor proaspăt. Blocarea e la nivel de HUB, deci prinde şi invitaţii.

Testăm prin handler-ele WS REALE (`browser_ws`, `shared_ws`) cu un WebSocket fals, plus
`core.sweep_stepup_caps` (rulat de main la 15 s). Şi: POST /api/history pe un host 2FA (fix 3)
trece doar cu fereastră deschisă SAU cu un terminal deblocat ataşat de acelaşi cont.
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
from app import totp as totp_mod  # noqa: E402

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
    """Suficient din starlette.WebSocket cât să rulăm browser_ws/shared_ws in-process."""

    def __init__(self, cookie_token=None, origin=os.environ["WEBTERM_PUBLIC_URL"]):
        self.headers = {"origin": origin, "user-agent": "test"} if origin else {"user-agent": "test"}
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

    def push(self, obj):
        self.inbox.put_nowait({"type": "websocket.receive", "text": json.dumps(obj)})

    def json_msgs(self, typ):
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


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    # main._idle_lock_sweep nu rulează în ASGITransport (fără lifespan) → îl chemăm explicit

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200, r.text[:120])
        me = await db.fetchone("SELECT * FROM users WHERE email=?", "a@b.co")
        uid = me["id"]
        hid = (await c.post("/api/hosts", json={"name": "critic", "require_2fa": True})).json()["id"]
        plain = (await c.post("/api/hosts", json={"name": "plain"})).json()["id"]
        tok = await security.create_web_session(uid)

        async def new_session(host_id, sid):
            await db.execute(
                "INSERT INTO sessions(id,host_id,title,state,created,rows,cols) VALUES(?,?,?,?,?,?,?)",
                sid, host_id, "root", "live", time.time(), 24, 80)

        sid = "c" * 32
        await new_session(hid, sid)

        # ── 1. ataşare cu fereastră deschisă → deblocat, autorizat de opened_at-ul ferestrei ──
        security._stepup_windows.clear()
        opened = time.time() - 120                         # factorul a fost dat acum 2 min
        security._stepup_windows[(uid, hid)] = (opened, time.time() + 300)
        check("accessor: stepup_window_opened_at = opened_at pe fereastră deschisă",
              security.stepup_window_opened_at(uid, hid) == opened)
        check("accessor: None fără fereastră", security.stepup_window_opened_at(uid, 999) is None)
        owner = FakeWS(tok)
        t_owner = asyncio.create_task(api.browser_ws(owner, sid))
        hub = None
        await settle(lambda: sid in core.hubs and core.hubs[sid].clients)
        hub = core.hubs.get(sid)
        check("owner ataşat", hub is not None and len(hub.clients) == 1)
        oc = next(iter(hub.clients))
        check("ataşare cu fereastră deschisă → deblocat", not hub.locked and not oc.locked)
        check("hub.stepup_cap activ pe host 2FA", hub.stepup_cap is True)
        check("authorized_at = opened_at al ferestrei (NU momentul ataşării)",
              hub.authorized_at == opened, str(hub.authorized_at))
        check("clientul owner poartă user_id-ul", oc.user_id == uid)

        # ── 2. invitat prin share (writable), owner prezent → deblocat ──
        share_tok = security.new_token()
        await db.execute("UPDATE sessions SET share_token=?, share_expires=?, share_writable=1,"
                         " share_by=? WHERE id=?",
                         security.sha256_hex(share_tok), time.time() + 3600, "a@b.co", sid)
        guest = FakeWS(None)
        t_guest = asyncio.create_task(api.shared_ws(guest, share_tok))
        await settle(lambda: len(hub.clients) == 2)
        gc = [x for x in hub.clients if not x.is_owner]
        check("invitat ataşat şi deblocat (owner prezent)", len(gc) == 1 and not gc[0].locked)

        # ── 3. terminal în uz, plafonul NU e atins → sweep-ul nu blochează ──
        hub.last_interaction = time.time()
        await core.sweep_stepup_caps()
        check("sub plafon: sweep nu blochează", hub.locked is False)

        # ── 4. POST /api/history: fereastră închisă, dar terminal deblocat al ACESTUI cont → trece ──
        security._stepup_windows.clear()
        r = await c.post("/api/history", json={"host_id": hid, "command": "make deploy"})
        check("history pe host 2FA: fără fereastră, dar cu terminal deblocat ataşat → 200",
              r.status_code == 200, r.text[:120])

        # ── 5. 60 min de la factor, terminal ACTIV, nicio fereastră nouă → BLOCAT (toţi clienţii) ──
        hub.authorized_at = time.time() - security.STEPUP_WINDOW_MAX - 1
        hub.last_interaction = time.time()                 # tastat chiar acum: idle-lock n-ar prinde
        await core.sweep_idle_locks()
        check("control: idle-lock-ul NU blochează un terminal activ", hub.locked is False)
        await core.sweep_stepup_caps()
        check("plafon depăşit pe terminal activ → hub blocat", hub.locked is True)
        check("motivul blocării = stepup_max", hub.lock_reason == "stepup_max")
        check("owner-ul primeşte {type: locked, reason: stepup_max}",
              any(m.get("reason") == "stepup_max" for m in owner.json_msgs("locked")), owner.texts[-3:])
        check("invitatul e blocat şi el (blocarea e pe hub)",
              all(x.locked for x in hub.clients) and bool(guest.json_msgs("locked")), guest.texts[-3:])
        src_inputs = []

        class _Src:
            epoch = "ep"

            async def send_data(self, s, data):
                src_inputs.append(data)
        core.session_sources[sid] = _Src()
        await hub.handle_input(gc[0], b"rm -rf /tmp/x\n")
        check("input-ul invitatului cu drept de scriere e REFUZAT după plafon", src_inputs == [],
              str(src_inputs))

        # ── 6. history pe host 2FA: terminal blocat + fără fereastră → 403 opac ──
        r = await c.post("/api/history", json={"host_id": hid, "command": "forged"})
        check("history pe host 2FA: terminal blocat, fără fereastră → 403 opac",
              r.status_code == 403 and r.json().get("code") == "history.denied"
              and "critic" not in r.text, r.text[:160])
        n = await db.fetchone("SELECT COUNT(*) AS c FROM command_history WHERE command='forged'")
        check("…şi rândul NU a fost scris", n["c"] == 0)
        r = await c.post("/api/history", json={"host_id": plain, "command": "ls"})
        check("history pe host FĂRĂ 2FA → 200 (neatins)", r.status_code == 200, r.text[:120])

        # ── 7. deblocare pe WS: cont doar cu parolă → refuz cu cod stepup.needsFactor ──
        owner.push({"type": "unlock", "password": PW})
        await settle(lambda: bool(owner.json_msgs("unlock_failed")))
        fails = owner.json_msgs("unlock_failed")
        check("unlock cu parola singură (fără passkey/TOTP) → unlock_failed code=stepup.needsFactor",
              fails and fails[-1].get("code") == "stepup.needsFactor", str(fails))
        check("…hub-ul rămâne blocat", hub.locked is True)

        # ── 8. deblocare cu factor proaspăt (TOTP) → deblocat, plafonul reporneşte ACUM ──
        secret = totp_mod.new_secret()
        await db.execute("UPDATE users SET totp_enabled=1, totp_secret_encrypted=? WHERE id=?",
                         security.encrypt_secret(secret), uid)
        t0 = time.time()
        owner.push({"type": "unlock", "totp": totp_mod.generate(secret)})
        await settle(lambda: not hub.locked)
        check("unlock cu TOTP proaspăt → deblocat (owner + invitat)",
              hub.locked is False and not any(x.locked for x in hub.clients))
        check("authorized_at reporneşte la momentul factorului de deblocare",
              hub.authorized_at is not None and hub.authorized_at >= t0 - 1, str(hub.authorized_at))
        await core.sweep_stepup_caps()
        check("după deblocare, sweep-ul nu re-blochează", hub.locked is False)

        # ── 9. o fereastră NOUĂ a owner-ului ataşat avansează autorizarea ──
        hub.authorized_at = time.time() - security.STEPUP_WINDOW_MAX - 1
        security._stepup_windows.clear()
        security.open_stepup_window(uid, hid)
        new_open = security.stepup_window_opened_at(uid, hid)
        await core.sweep_stepup_caps()
        check("fereastră nouă a owner-ului ataşat → nu se blochează, authorized_at avansat",
              hub.locked is False and hub.authorized_at == new_open, str(hub.authorized_at))

        # ── 10. fereastra unui ALT cont, neataşat, NU re-autorizează terminalul ──
        await db.execute("INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
                         "x@b.co", security.hash_password("altaparola1"), time.time())
        other = (await db.fetchone("SELECT id FROM users WHERE email='x@b.co'"))["id"]
        hub.authorized_at = time.time() - security.STEPUP_WINDOW_MAX - 1
        security._stepup_windows.clear()
        security.open_stepup_window(other, hid)
        await core.sweep_stepup_caps()
        check("fereastra altui cont (neataşat) nu prelungeşte → blocat", hub.locked is True)

        # ── 11. reataşare cu hub blocat → mesajul locked poartă motivul ──
        security.open_stepup_window(uid, hid)
        owner2 = FakeWS(tok)
        t_owner2 = asyncio.create_task(api.browser_ws(owner2, sid))
        await settle(lambda: bool(owner2.json_msgs("locked")))
        lk = owner2.json_msgs("locked")
        check("reataşare pe hub blocat → locked cu reason=stepup_max (fără scrollback)",
              lk and lk[-1].get("reason") == "stepup_max" and not owner2.binary, str(lk))

        # ── 12. host FĂRĂ 2FA: plafonul nu se aplică niciodată ──
        sid2 = "d" * 32
        await new_session(plain, sid2)
        p = FakeWS(tok)
        t_p = asyncio.create_task(api.browser_ws(p, sid2))
        await settle(lambda: sid2 in core.hubs and core.hubs[sid2].clients)
        h2 = core.hubs[sid2]
        h2.authorized_at = time.time() - 10 * security.STEPUP_WINDOW_MAX
        await core.sweep_stepup_caps()
        check("host fără 2FA: stepup_cap inactiv, nu se blochează",
              h2.stepup_cap is False and h2.locked is False)

        # ── 13. ataşare fără fereastră → blocată cu reason=stepup ──
        sid3 = "e" * 32
        await new_session(hid, sid3)
        security._stepup_windows.clear()
        w3 = FakeWS(tok)
        t3 = asyncio.create_task(api.browser_ws(w3, sid3))
        await settle(lambda: bool(w3.json_msgs("locked")))
        check("ataşare fără fereastră → locked reason=stepup",
              any(m.get("reason") == "stepup" for m in w3.json_msgs("locked")), w3.texts[-3:])

        for ws_, t_ in ((owner, t_owner), (guest, t_guest), (owner2, t_owner2), (p, t_p), (w3, t3)):
            await ws_.inbox.put({"type": "websocket.disconnect"})
            try:
                await asyncio.wait_for(t_, 5)
            except Exception:                              # noqa: BLE001
                t_.cancel()

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
