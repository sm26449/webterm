"""WebSocket-ul de terminal şi proxy-ul de forward respectă rolurile — la ataşare ŞI după (3.6).

  * ataşare: rw (session.open + sesiunea ta) / ro (session.watch, sau sesiunea altcuiva) /
    replay (sesiune închisă, recording.view) / refuz 4404 identic cu o sesiune inexistentă;
  * read-only: octeţii de input NU ajung la PTY (filtrat în handler ŞI în hub), resize ignorat;
  * o retrogradare (open → watch) taie scrierea PE LOC (epoch bump trezeşte revalidarea), iar
    pierderea accesului închide socketul (4403) — fără să aştepte tick-ul de 60 s;
  * forward: biletul (12 h) e re-verificat la fiecare cerere — scope-ul scos = tunel închis,
    iar handshake-ul nu emite bilete fără `forward.use`.

Hermetic: handler-ul real (`api.browser_ws`) condus de un WebSocket fals, cu o sursă falsă care
înregistrează ce ar ajunge la PTY.
"""
import asyncio
import json

import rbac_util as U
from app import api, core, db, security

check = U.Checker()


class FakeWS:
    def __init__(self, cookie):
        self.headers = {"origin": U.ORIGIN["origin"], "user-agent": "rbac-test"}
        self.cookies = {security.COOKIE_NAME: cookie}
        self.client = type("C", (), {"host": "127.0.0.1"})()
        self.query_params = {}
        self.sent_text, self.sent_bytes = [], []
        self.closed = None
        self.accepted = False
        self.q = asyncio.Queue()

    async def accept(self):
        self.accepted = True

    async def send_text(self, t):
        self.sent_text.append(t)

    async def send_bytes(self, b):
        self.sent_bytes.append(b)

    async def receive(self):
        return await self.q.get()

    async def close(self, code=None):
        if self.closed is None:
            self.closed = code
        await self.q.put({"type": "websocket.disconnect"})

    def types(self):
        out = []
        for t in self.sent_text:
            try:
                out.append(json.loads(t).get("type"))
            except ValueError:
                pass
        return out

    def init(self):
        for t in self.sent_text:
            j = json.loads(t)
            if j.get("type") == "init":
                return j
        return {}


class FakeSource:
    epoch = None

    def __init__(self):
        self.data = []

    async def send_data(self, sid, data):
        self.data.append(data)

    async def resize(self, sid, rows, cols):
        pass


def cookie_of(c):
    return c.cookies.get(security.COOKIE_NAME)


async def attach(c, sid):
    ws = FakeWS(cookie_of(c))
    task = asyncio.create_task(api.browser_ws(ws, sid))
    for _ in range(50):
        await asyncio.sleep(0.02)
        if ws.closed is not None or ws.init():
            break
    return ws, task


async def finish(ws, task):
    await ws.q.put({"type": "websocket.disconnect"})
    try:
        await asyncio.wait_for(task, 5)
    except Exception:                                  # noqa: BLE001
        pass


async def main():
    await U.boot()
    owner = await U.owner_client()
    a = await U.add_host(owner, "alpha", folder="prod")
    op_id = await U.add_user("op@x.co", bindings=[("operator", "folder", "prod")])
    await U.add_user("other@x.co", bindings=[("operator", "folder", "lab")])
    await U.add_user("vw@x.co", bindings=[("viewer", "host", a)])
    op, other, vw = await U.login("op@x.co"), await U.login("other@x.co"), await U.login("vw@x.co")
    api.WS_REVALIDATE_SECS = 30          # revalidarea vine din epoch bump, nu din tick

    s_own = await U.add_session(a, state="live", created_by=op_id)
    s_foreign = await U.add_session(a, state="live", created_by=1)
    s_closed = await U.add_session(a, state="closed", created_by=1)
    src = FakeSource()
    for sid in (s_own, s_foreign):
        row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
        hub = core.get_or_create_hub(row)
        hub.attached = True
        hub._source = lambda s=src: s

    # ── ataşare ──────────────────────────────────────────────────────────────────────────
    ws, t = await attach(op, s_own)
    check("Operator pe sesiunea LUI: rw (readonly=false)", ws.accepted and ws.init().get("readonly") is False,
          str(ws.sent_text[:2]))
    await ws.q.put({"type": "websocket.receive", "bytes": b"ls\r"})
    await asyncio.sleep(0.05)
    check("…input-ul ajunge la PTY", src.data == [b"ls\r"], str(src.data))

    # retrogradare: open → watch, în timp ce socketul e DESCHIS
    await U.unbind_all(op_id)
    await U.bind(op_id, "viewer", "folder", "prod")
    await asyncio.sleep(0.2)
    check("retrogradat la Viewer: clientul primeşte `readonly` PE LOC (fără tick de 60 s)",
          "readonly" in ws.types(), str(ws.types()))
    src.data.clear()
    await ws.q.put({"type": "websocket.receive", "bytes": b"rm -rf /\r"})
    await asyncio.sleep(0.05)
    check("…şi tastele lui NU mai ajung la PTY", src.data == [], str(src.data))
    await ws.q.put({"type": "websocket.receive",
                    "text": json.dumps({"type": "resize", "rows": 10, "cols": 10, "active": True})})
    await asyncio.sleep(0.05)
    hub = core.hubs[s_own]
    check("…nici resize (read-only nu schimbă grila celorlalţi)", (hub.rows, hub.cols) != (10, 10))
    # pierderea accesului: socketul se închide
    await U.unbind_all(op_id)
    await asyncio.sleep(0.2)
    check("acces scos: socketul DESCHIS se închide (4403)", ws.closed == 4403, str(ws.closed))
    await finish(ws, t)

    # reataşare după scoaterea legăturii
    ws, t = await attach(op, s_own)
    check("reataşare fără legătură: refuz 4404 ÎNAINTE de accept (identic cu inexistent)",
          ws.closed == 4404 and not ws.accepted and not ws.sent_bytes, str(ws.closed))
    await finish(ws, t)
    ws, t = await attach(op, "f" * 32)
    check("…acelaşi cod ca o sesiune inexistentă", ws.closed == 4404)
    await finish(ws, t)

    # Operator pe sesiunea ALTCUIVA: urmăreşte, nu tastează (Q5)
    await U.bind(op_id, "operator", "folder", "prod")
    ws, t = await attach(op, s_foreign)
    check("Operator pe sesiunea altcuiva: read-only", ws.init().get("readonly") is True)
    src.data.clear()
    await ws.q.put({"type": "websocket.receive", "bytes": b"whoami\r"})
    await asyncio.sleep(0.05)
    check("…input aruncat", src.data == [])
    client = next(c for c in core.hubs[s_foreign].clients if c.ws is ws)
    check("…clientul din hub e marcat non-writable (roster corect)", client.writable is False)
    await core.hubs[s_foreign].handle_input(client, b"x")
    check("…şi hub-ul însuşi refuză input de la un client read-only (apărare în adâncime)",
          src.data == [])
    await finish(ws, t)
    await U.bind(op_id, "admin", "folder", "prod")          # session.manage pe prod
    ws, t = await attach(op, s_foreign)
    check("cu session.manage: poate tasta şi în sesiunea altcuiva", ws.init().get("readonly") is False)
    await finish(ws, t)
    await U.unbind_all(op_id)
    await U.bind(op_id, "operator", "folder", "prod")

    # Viewer: live → ro; închisă → replay
    ws, t = await attach(vw, s_own)
    check("Viewer pe o sesiune vie: read-only", ws.accepted and ws.init().get("readonly") is True)
    await finish(ws, t)
    ws, t = await attach(vw, s_closed)
    check("Viewer pe o sesiune ÎNCHISĂ: replay (acceptat, read-only)",
          ws.accepted and ws.init().get("readonly") is True)
    await finish(ws, t)
    ws, t = await attach(other, s_own)
    check("Operator pe ALT folder: 4404, nimic trimis", ws.closed == 4404 and not ws.accepted
          and not ws.sent_text)
    await finish(ws, t)

    # ── forward: re-verificare per cerere ────────────────────────────────────────────────
    fid = await U.add_forward(a, "svc", enabled=1)
    del fid
    ticket = security.make_forward_token("svc", op_id)
    check("bilet + forward.use pe host → acces", await api._forward_authz_ok("svc", ticket))
    host = "svc." + api.forward_domain()
    async with U.client(cookies={api.FWD_COOKIE: ticket}) as fc:
        r = await fc.get("http://%s/" % host, headers={"host": host, "origin": "http://" + host})
        check("cerere pe subdomeniu cu bilet valid: trece de autorizare (host offline → 409)",
              r.status_code == 409, "%s %s" % (r.status_code, r.text[:80]))
        await U.unbind_all(op_id)
        check("legătura scoasă: ACELAŞI bilet nu mai trece", not await api._forward_authz_ok("svc", ticket))
        r = await fc.get("http://%s/" % host, headers={"host": host, "origin": "http://" + host})
        check("…cererea e trimisă la handshake (302), nu proxy-ată", r.status_code == 302
              and "/__wtfwd/auth" in r.headers.get("location", ""), str(r.status_code))
    r = await op.get("/__wtfwd/auth", params={"slug": "svc"}, follow_redirects=False)
    check("handshake fără acces la host: 404 (ca un forward inexistent)", r.status_code == 404
          and U.code(r) == "forward.missing", "%s %s" % (r.status_code, r.text[:80]))
    await U.bind(op_id, "viewer", "host", a)
    r = await op.get("/__wtfwd/auth", params={"slug": "svc"}, follow_redirects=False)
    check("handshake cu forward.use (Viewer): bilet emis (302 spre subdomeniu)",
          r.status_code == 302 and "/__wtfwd/set" in r.headers.get("location", ""))
    ticket_other = security.make_forward_token("svc", 99999)
    check("bilet al unui cont inexistent: refuz", not await api._forward_authz_ok("svc", ticket_other))

    for c in (owner, op, other, vw):
        await c.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
