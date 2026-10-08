"""fix 1 — o sesiune ÎNCHISĂ pe un host 2FA nu-şi mai scurge transcriptul (read_tail) pe WS fără
step-up. Înainte, pasul de step-up stătea sub `if hub:` (doar sesiuni live), iar pentru o sesiune
închisă `hub` e None → `start_locked` rămânea False → scrollback-ul unui host 2FA pleca fără al
doilea factor. Acum: fără fereastră → pornim BLOCAT, niciun octet; cu fereastră (sau după `unlock`
cu factor proaspăt) → transcriptul se trimite. Hermetic: conducem handler-ul cu un WebSocket fals."""
import asyncio
import json
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402
from app import totp as totp_mod  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0
SECRET = b"SECRET-SCROLLBACK-2FA"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeWS:
    """Doar atributele atinse de browser_ws pe calea unei sesiuni ÎNCHISE (fără hub)."""
    def __init__(self, cookie, incoming):
        self.headers = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
        self.cookies = {security.COOKIE_NAME: cookie}
        self.client = type("C", (), {"host": "127.0.0.1"})()
        self.sent_text = []
        self.sent_bytes = []
        self.closed = None
        self._incoming = list(incoming)

    async def accept(self):
        pass

    async def send_text(self, t):
        self.sent_text.append(t)

    async def send_bytes(self, b):
        self.sent_bytes.append(b)

    async def receive(self):
        if self._incoming:
            return self._incoming.pop(0)
        return {"type": "websocket.disconnect"}

    async def close(self, code=None):
        self.closed = code


def _types(ws):
    out = []
    for t in ws.sent_text:
        try:
            out.append(json.loads(t).get("type"))
        except ValueError:
            pass
    return out


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": "parolabuna1",
                                         "setup_token": "test-setup"})
        hid = (await c.post("/api/hosts", json={"name": "critic", "require_2fa": True})).json()["id"]
        hidn = (await c.post("/api/hosts", json={"name": "normal"})).json()["id"]
    uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]
    token = await security.create_web_session(uid, "test-agent", False)

    sid = "b" * 32
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,rows,cols) VALUES(?,?,?,?,?,?,?)",
        sid, hid, "t", "closed", time.time(), 24, 80)
    out_path, _ = core.transcript_paths(sid)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(SECRET)

    # ── 1. fără fereastră: sesiune închisă pe host 2FA → BLOCAT, zero scrollback ──
    security.clear_stepup_for(uid)
    ws = FakeWS(token, [])
    await api.browser_ws(ws, sid)
    sent = b"".join(ws.sent_bytes)
    check("fără fereastră: niciun octet de scrollback trimis", SECRET not in sent and sent == b"")
    check("fără fereastră: clientul primeşte semnalul `locked`", "locked" in _types(ws))

    # ── 2. cu fereastră deschisă: scrollback-ul se trimite ──
    security.open_stepup_window(uid, hid)
    ws = FakeWS(token, [])
    await api.browser_ws(ws, sid)
    check("cu fereastră: transcriptul e trimis", SECRET in b"".join(ws.sent_bytes))

    # ── 3. unlock pe sesiune închisă fără factor valabil → eşuează, tot niciun octet ──
    security.clear_stepup_for(uid)
    bad = {"type": "websocket.receive",
           "text": json.dumps({"type": "unlock", "password": "gresit"})}
    ws = FakeWS(token, [bad])
    await api.browser_ws(ws, sid)
    check("unlock cu parolă greşită → unlock_failed, fără scrollback",
          "unlock_failed" in _types(ws) and SECRET not in b"".join(ws.sent_bytes))

    # ── 4a. 3.5.14: parola CORECTĂ singură (cont fără passkey/TOTP) NU mai deblochează ──
    security.clear_stepup_for(uid)
    pw_only = {"type": "websocket.receive",
               "text": json.dumps({"type": "unlock", "password": "parolabuna1"})}
    ws = FakeWS(token, [pw_only])
    await api.browser_ws(ws, sid)
    fails = [json.loads(t) for t in ws.sent_text if '"unlock_failed"' in t]
    check("unlock cu parola singură → unlock_failed code=stepup.needsFactor, fără scrollback",
          fails and fails[-1].get("code") == "stepup.needsFactor"
          and SECRET not in b"".join(ws.sent_bytes), str(fails))

    # ── 4b. unlock cu un factor real proaspăt (TOTP) → redă transcriptul ──
    secret = totp_mod.new_secret()
    await db.execute("UPDATE users SET totp_enabled=1, totp_secret_encrypted=? WHERE id=?",
                     security.encrypt_secret(secret), uid)
    security.clear_stepup_for(uid)
    good = {"type": "websocket.receive",
            "text": json.dumps({"type": "unlock", "totp": totp_mod.generate(secret)})}
    ws = FakeWS(token, [good])
    await api.browser_ws(ws, sid)
    check("unlock cu factor proaspăt (TOTP) → `unlocked` + scrollback redat",
          "unlocked" in _types(ws) and SECRET in b"".join(ws.sent_bytes))
    await db.execute("UPDATE users SET totp_enabled=0, totp_secret_encrypted=NULL WHERE id=?", uid)

    # ── 5. host FĂRĂ 2FA: scrollback-ul se trimite ca înainte (fără regresie) ──
    sidn = "c" * 32
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,rows,cols) VALUES(?,?,?,?,?,?,?)",
        sidn, hidn, "t", "closed", time.time(), 24, 80)
    outn, _ = core.transcript_paths(sidn)
    outn.write_bytes(SECRET)
    security.clear_stepup_for(uid)
    ws = FakeWS(token, [])
    await api.browser_ws(ws, sidn)
    check("host fără 2FA: scrollback trimis normal (fără regresie)",
          SECRET in b"".join(ws.sent_bytes))

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
