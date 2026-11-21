"""Igiena sesiunilor inactive (3.7.1, idlesess.py; INV-13).

  * inactivă = fără input, fără output, fără client — fiecare dintre ele reporneşte ceasul;
  * o singură notificare per perioadă, proprietarului (fără proprietar → session.manage; terminal root
    fără proprietar → nimeni, deci nimic);
  * închiderea automată oprită → nu închide niciodată; pornită → doar după grație, doar dacă notificarea
    a fost trimisă cu închiderea pornită, doar fără nicio folosire după ea;
  * Keep open, client ataşat, host offline, hub neataşat, eroare la kill → nu închide;
  * rutele: keep-open (al tău / session.manage), setările (settings.manage), validarea zilelor;
  * migraţiile rulează de două ori fără eroare.
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rbac_util as U  # noqa: E402  (pune mediul şi DB-ul temporar înainte de `app`)
from app import core, db, idlesess  # noqa: E402

check = U.Checker()
DAY = 86400.0


class FakeSource:
    """Sursa unui host: kill-ul închide sesiunea ca agentul (on_exit), sau eşuează la cerere."""
    backend = "tmux"
    epoch = "e1"

    def __init__(self):
        self.killed = []
        self.fail = False

    async def kill(self, sid):
        if self.fail:
            raise core.AgentGone("host offline")
        self.killed.append(sid)
        hub = core.hubs.get(sid)
        if hub is not None:
            await hub.on_exit(0, None)

    async def reap(self, sid):
        pass

    async def send_data(self, sid, data):
        pass


class FakeClient:
    """Un client de browser minimal (hash-uibil, ca în `hub.clients`)."""
    def __init__(self, owner=True):
        self.writable, self.locked, self.is_owner = True, False, owner
        self.last_interaction, self.user_id, self.id, self.label = 0.0, 1, "c1", "x"

    def push(self, data):
        pass


def fake_client(owner=True):
    return FakeClient(owner)


async def new_session(hid, by, days_old=10.0, origin="web"):
    """O sesiune vie cu hub ataşat, folosită ultima oară acum `days_old` zile."""
    sid = await U.add_session(hid, created_by=by)
    await db.execute("UPDATE sessions SET origin=? WHERE id=?", origin, sid)
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    hub = core.get_or_create_hub(row)
    hub.attached = True
    hub.attached_mono = time.monotonic() - 3600     # ataşat la sursă de o oră, replay terminat
    await backdate(sid, days_old)
    return sid, hub


async def sweep_at(now):
    """Un sweep la momentul `now` pe AMBELE ceasuri: timpul simulat trece şi pe cel monoton."""
    return await idlesess.sweep(now=now, mono=time.monotonic() + (now - time.time()))


async def backdate(sid, days):
    t = time.time() - days * DAY
    hub = core.hubs[sid]
    hub.created = t
    hub.last_output_at = hub.last_input_at = hub.last_presence_at = None
    hub._persisted_active = 0.0
    await db.execute("UPDATE sessions SET created=?, last_active=NULL WHERE id=?", t, sid)
    out = core.transcript_paths(sid)[0]
    out.touch()
    os.utime(out, (t, t))


async def srow(sid):
    return await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)


async def alerts_for(uid, kind):
    await asyncio.sleep(0.05)            # _fire înregistrează pe un task
    return await db.fetchall("SELECT * FROM alerts WHERE user_id=? AND kind=?", uid, kind)


async def settle():
    for _ in range(5):
        await asyncio.sleep(0.02)        # bgtasks (anularea notificării, persistarea)


async def main():
    await U.boot()
    try:
        await body()
    finally:
        await db.close()


async def body():
    owner = await U.owner_client()
    owner_id = (await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL))["id"]
    hid = await U.add_host(owner, "box", folder="prod")
    alice = await U.add_user("alice@x.co", bindings=[("operator", "all", "")])
    bob = await U.add_user("bob@x.co", bindings=[("operator", "all", "")])
    adm = await U.add_user("adm@x.co", bindings=[("admin", "all", "")])
    ca, cb, cadm = await U.login("alice@x.co"), await U.login("bob@x.co"), await U.login("adm@x.co")
    src = FakeSource()
    core.sources[hid] = src

    # ── migraţii idempotente + coloane ──
    await db.close()
    await db.connect()
    cols = {r["name"] for r in await db.fetchall("PRAGMA table_info(sessions)")}
    check("migraţiile rulează de două ori; coloanele există",
          {"last_active", "idle_notified_at", "idle_close_after", "keep_open"} <= cols, str(cols))

    # ── setări: implicite, permisiuni, validare ──
    r = await owner.get("/api/settings/idle-sessions")
    j = r.json()
    check("implicit: notificare pornită 7 zile, închidere OPRITĂ, grație 2",
          r.status_code == 200 and j["notify"] is True and j["notify_days"] == 7
          and j["autoclose"] is False and j["grace_days"] == 2, r.text)
    check("setările: Operator → 403", (await cb.get("/api/settings/idle-sessions")).status_code == 403)
    r = await cb.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7,
                                                          "autoclose": True, "grace_days": 2, "current_password": U.OWNER_PW})
    check("setările: Operator nu poate porni închiderea", r.status_code == 403)
    r = await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 0,
                                                             "autoclose": False, "grace_days": 2})
    check("zile în afara limitelor → 400 settings.idleDaysRange",
          r.status_code == 400 and U.code(r) == "settings.idleDaysRange", r.text)
    r = await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7,
                                                             "autoclose": False, "grace_days": 31})
    check("grație > 30 → 400", r.status_code == 400)
    r = await cadm.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7,
                                                            "autoclose": False, "grace_days": 2})
    check("setările: Admin poate salva", r.status_code == 200, r.text)
    check("politica stocată corupt → implicit (închidere oprită)",
          idlesess.sanitize({"autoclose": "yes", "notify_days": "x"})["autoclose"] is False
          and idlesess.sanitize({"notify_days": 999})["notify_days"] == 90)

    # ── detecţie: notificare o dată, doar proprietarului ──
    s1, h1 = await new_session(hid, alice, days_old=6)
    st = await idlesess.sweep()
    check("6 zile < 7 → nicio notificare", st["notified"] == 0 and not (await srow(s1))["idle_notified_at"], str(st))
    await backdate(s1, 8)
    st = await idlesess.sweep()
    check("8 zile → notificat", st["notified"] == 1 and (await srow(s1))["idle_notified_at"], str(st))
    check("închidere oprită → fără termen de închidere", (await srow(s1))["idle_close_after"] is None)
    check("alerta session_idle ajunge la proprietar", len(await alerts_for(alice, "session_idle")) == 1)
    check("…şi nu la alt Operator", len(await alerts_for(bob, "session_idle")) == 0)
    check("…nici la Owner (sesiunea are proprietar)", len(await alerts_for(owner_id, "session_idle")) == 0)
    st = await idlesess.sweep()
    check("a doua trecere: nu notifică din nou", st["notified"] == 0, str(st))
    check("o singură alertă", len(await alerts_for(alice, "session_idle")) == 1)
    st = await sweep_at(time.time() + 60 * DAY)
    check("închidere OPRITĂ → nu închide niciodată", st["closed"] == 0 and not src.killed
          and (await srow(s1))["state"] == "live", str(st))
    lst = (await ca.get("/api/sessions")).json()
    me = next((x for x in lst if x["id"] == s1), {})
    check("lista de sesiuni arată notificarea (fără dată de închidere)",
          me.get("idle_notice") and me["idle_notice"]["close_at"] is None and me["keep_open"] is False, str(me))

    # ── fiecare activitate anulează notificarea şi reporneşte ceasul ──
    await h1.handle_input(fake_client(), b"x")
    await settle()
    check("input → notificarea anulată imediat", (await srow(s1))["idle_notified_at"] is None)
    check("input → nu mai e inactivă", (await idlesess.sweep())["notified"] == 0)
    await backdate(s1, 8)
    await idlesess.sweep()
    check("din nou inactivă → notificată", (await srow(s1))["idle_notified_at"] is not None)
    await h1._process_output(b"build line\r\n")
    await settle()
    check("output → notificarea anulată", (await srow(s1))["idle_notified_at"] is None)
    check("output → nu mai e inactivă", (await idlesess.sweep())["notified"] == 0)
    await backdate(s1, 8)
    await idlesess.sweep()
    c = fake_client()
    h1.clients.add(c)
    h1.note_presence()
    await settle()
    check("ataşare → notificarea anulată", (await srow(s1))["idle_notified_at"] is None)
    await backdate(s1, 8)
    check("client ataşat → nu e inactivă, oricât de vechi", (await idlesess.sweep())["notified"] == 0)
    h1.clients.discard(c)
    h1.note_presence()
    await settle()
    check("plecarea se persistă (last_active)", ((await srow(s1))["last_active"] or 0) > time.time() - 60)
    check("după plecare ceasul porneşte de la zero", (await idlesess.sweep())["notified"] == 0)

    # ── închidere automată pornită ──
    await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7,
                                                         "autoclose": True, "grace_days": 2, "current_password": U.OWNER_PW})
    s2, h2 = await new_session(hid, alice, days_old=10)
    now = time.time()
    await sweep_at(now)
    r2 = await srow(s2)
    check("notificare cu închiderea pornită → termen fixat la +2 zile",
          r2["idle_notified_at"] and abs(r2["idle_close_after"] - (now + 2 * DAY)) < 5, dict(r2))
    st = await sweep_at(now + 1 * DAY)
    check("înainte de grație → nu închide", st["closed"] == 0 and s2 not in src.killed, str(st))
    st = await sweep_at(now + 2 * DAY + 60)
    r2 = await srow(s2)
    check("după grație, nefolosită → închisă pe calea Stop", st["closed"] == 1 and s2 in src.killed
          and r2["state"] == "closed" and r2["close_reason"] == "idle", "%s %s" % (st, dict(r2)))
    check("hub-ul curăţat", s2 not in core.hubs)
    aud = await db.fetchone("SELECT * FROM audit_log WHERE actor='system:idle-sessions'")
    check("închiderea e în audit", aud is not None)
    check("alerta session_idle_closed la proprietar", len(await alerts_for(alice, "session_idle_closed")) == 1)

    # activitate după notificare → nu închide
    s3, h3 = await new_session(hid, alice, days_old=10)
    now = time.time()
    await sweep_at(now)
    await h3._process_output(b"tick\r\n")
    await settle()
    st = await sweep_at(now + 3 * DAY)
    check("output după notificare → nu închide", s3 not in src.killed and (await srow(s3))["state"] == "live", str(st))

    # activitate pe care hub-ul n-a semnalat-o (idle_pending pierdut) → sweep-ul o vede şi anulează
    s3b, h3b = await new_session(hid, alice, days_old=10)
    now = time.time()
    await sweep_at(now)
    h3b.idle_pending = False
    h3b.last_input_at = now + 60
    st = await sweep_at(now + 3 * DAY)
    check("activitate după notificare văzută de sweep → anulată, nu închisă",
          s3b not in src.killed and (await srow(s3b))["idle_notified_at"] is None, str(st))

    # client ataşat la momentul închiderii → nu închide
    s4, h4 = await new_session(hid, alice, days_old=10)
    now = time.time()
    await sweep_at(now)
    h4.clients.add(fake_client())          # fără note_presence: plasa sweep-ului
    await sweep_at(now + 3 * DAY)
    check("client ataşat → nu închide", s4 not in src.killed and (await srow(s4))["state"] == "live")
    h4.clients.clear()

    # Keep open: rutele + efectul
    s5, h5 = await new_session(hid, alice, days_old=10)
    now = time.time()
    await sweep_at(now)
    r = await cb.post(f"/api/sessions/{s5}/keep-open", json={"keep": True})
    check("keep-open: alt Operator → 403", r.status_code == 403, r.text)
    r = await ca.post(f"/api/sessions/{s5}/keep-open", json={"keep": True})
    check("keep-open: proprietarul → 200", r.status_code == 200, r.text)
    r5 = await srow(s5)
    check("keep-open anulează notificarea în curs", r5["keep_open"] == 1 and r5["idle_notified_at"] is None)
    st = await sweep_at(now + 30 * DAY)
    check("Keep open → nu notifică, nu închide", s5 not in src.killed and (await srow(s5))["idle_notified_at"] is None)
    r = await cadm.post(f"/api/sessions/{s5}/keep-open", json={"keep": False})
    check("keep-open: session.manage (Admin) → 200", r.status_code == 200, r.text)
    check("keep-open oprit", (await srow(s5))["keep_open"] == 0)
    r = await ca.post("/api/sessions/%s/keep-open" % s2, json={"keep": True})
    check("keep-open pe o sesiune închisă → 409", r.status_code == 409 and U.code(r) == "session.keepNotLive", r.text)
    r = await ca.post("/api/sessions/%s/keep-open" % ("0" * 32), json={"keep": True})
    check("keep-open pe o sesiune inexistentă → 404", r.status_code == 404, r.text)

    # host offline / hub neataşat / kill eşuat → nu închide
    s6, h6 = await new_session(hid, alice, days_old=10)
    now = time.time()
    await sweep_at(now)
    core.sources.pop(hid)
    st = await sweep_at(now + 3 * DAY)
    check("host offline → nu închide", st["closed"] == 0 and (await srow(s6))["state"] == "live", str(st))
    core.sources[hid] = src
    h6.attached = False
    st = await sweep_at(now + 3 * DAY)
    check("hub neataşat (output nevăzut) → nu închide", s6 not in src.killed, str(st))
    h6.attached = True
    src.fail = True
    st = await sweep_at(now + 3 * DAY)
    check("kill eşuat → rămâne vie, motivul de ieşire resetat",
          s6 not in src.killed and (await srow(s6))["state"] == "live" and h6.exit_reason == "exited", str(st))
    src.fail = False
    s7 = await U.add_session(hid, created_by=alice)
    await db.execute("UPDATE sessions SET created=? WHERE id=?", time.time() - 30 * DAY, s7)
    st = await sweep_at(time.time() + 30 * DAY)
    check("sesiune fără hub (fluxul nu trece prin gateway) → nimic", not (await srow(s7))["idle_notified_at"])

    # notificare trimisă cu închiderea OPRITĂ → pornirea ulterioară trimite întâi o notificare nouă
    await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7,
                                                         "autoclose": False, "grace_days": 2})
    s8, h8 = await new_session(hid, alice, days_old=10)
    now = time.time()
    await sweep_at(now)
    await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7,
                                                         "autoclose": True, "grace_days": 2, "current_password": U.OWNER_PW})
    st = await sweep_at(now + 5 * DAY)
    r8 = await srow(s8)
    check("închidere pornită după notificare → notificare nouă, nu închidere",
          st["closed"] == 0 and r8["idle_close_after"] and s8 not in src.killed, "%s %s" % (st, dict(r8)))
    check("a doua notificare anunţă închiderea", len(await alerts_for(alice, "session_idle")) >= 2)
    st = await sweep_at(now + 7 * DAY + 60)
    check("…apoi închide după grație", s8 in src.killed, str(st))

    # destinatari: fără proprietar → session.manage; terminal root fără proprietar → nimeni
    s9, h9 = await new_session(hid, None, days_old=10)
    row9 = await srow(s9)
    rec = await idlesess.recipients(row9)
    check("fără proprietar → cei cu session.manage (Owner + Admin), nu Operatorii",
          set(rec) == {owner_id, adm}, str(rec))
    s10, h10 = await new_session(hid, None, days_old=10, origin="cert-renew")
    check("terminal root fără proprietar → nimeni", await idlesess.recipients(await srow(s10)) == [])
    now = time.time()
    await sweep_at(now)
    st = await sweep_at(now + 30 * DAY)
    check("…deci nicio notificare şi nicio închidere",
          not (await srow(s10))["idle_notified_at"] and s10 not in src.killed)
    await db.execute("UPDATE users SET disabled=1 WHERE id=?", alice)
    s11, _ = await new_session(hid, alice, days_old=10)
    check("proprietar dezactivat → cei cu session.manage",
          set(await idlesess.recipients(await srow(s11))) == {owner_id, adm})
    await db.execute("UPDATE users SET disabled=0 WHERE id=?", alice)

    # notificarea oprită → nimic nou, nimic închis
    await owner.post("/api/settings/idle-sessions", json={"notify": False, "notify_days": 7,
                                                         "autoclose": True, "grace_days": 2, "current_password": U.OWNER_PW})
    s12, _ = await new_session(hid, alice, days_old=30)
    st = await sweep_at(time.time() + 30 * DAY)
    check("notificarea oprită → nicio notificare, nicio închidere",
          st["notified"] == 0 and st["closed"] == 0 and s12 not in src.killed, str(st))

    # ── review 3.7.1 ──
    await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7,
                                                         "autoclose": True, "grace_days": 2, "current_password": U.OWNER_PW})
    # 1) cursa ataşării: un browser care se ataşează exact cât _close îşi citeşte rândul → nu se închide
    s13, h13 = await new_session(hid, alice, days_old=20)
    t0 = time.time()
    await sweep_at(t0)
    check("cursă: notificarea a plecat", (await srow(s13))["idle_notified_at"] is not None)
    real_fetchone = db.fetchone
    joined = []

    async def attach_during_read(sql, *args):
        r = await real_fetchone(sql, *args)
        if sql.startswith("SELECT * FROM sessions WHERE id=?") and args and args[0] == s13 and not joined:
            h13.clients.add(fake_client())       # ataşare „în timpul" citirii
            joined.append(1)
        return r
    db.fetchone = attach_during_read
    try:
        await sweep_at(t0 + 3 * DAY)
    finally:
        db.fetchone = real_fetchone
    check("cursă: un client ataşat în timpul ultimei citiri → sesiunea NU se închide",
          joined and s13 not in src.killed and (await srow(s13))["state"] == "live")
    h13.clients.clear()

    # 2) închiderea oprită apoi repornită: termenul vechi nu mai închide; pleacă o notificare nouă
    s14, h14 = await new_session(hid, alice, days_old=20)
    t1 = time.time()
    await sweep_at(t1)
    await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7,
                                                         "autoclose": False, "grace_days": 2})
    await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7,
                                                         "autoclose": True, "grace_days": 2, "current_password": U.OWNER_PW})
    check("repornită: termenul vechi a fost şters", (await srow(s14))["idle_close_after"] is None)
    await sweep_at(t1 + 30 * DAY)
    r14 = await srow(s14)
    check("…prima trecere trimite o notificare nouă cu termen, NU închide",
          s14 not in src.killed and r14["idle_close_after"] is not None and r14["state"] == "live")

    # 3) fără proprietar: o singură alertă (un singur email/webhook) pentru toţi destinatarii
    from app import alert_history as _ah
    fired = []
    real_req = _ah.record_required

    async def count_req(*a, **k):
        fired.append(k.get("user_id"))
        return await real_req(*a, **k)
    _ah.record_required = count_req
    try:
        s15, _ = await new_session(hid, None, days_old=20)
        await sweep_at(time.time())
    finally:
        _ah.record_required = real_req
    check("fără proprietar → un singur apel de alertă, cu toţi destinatarii",
          len(fired) == 1 and isinstance(fired[0], list) and len(fired[0]) >= 2, str(fired))

    await audit_fixes(hid, src, owner, alice)

    for c in (owner, ca, cb, cadm):
        await c.aclose()


class IdleWS:
    """WebSocket fals pentru `browser_ws` / `shared_ws` (ca în share_presence_test)."""
    class _C:
        host = "127.0.0.1"

    def __init__(self, cookie_token=None):
        from app import security
        self.headers = {"origin": os.environ["WEBTERM_PUBLIC_URL"], "user-agent": "test"}
        self.cookies = {security.COOKIE_NAME: cookie_token} if cookie_token else {}
        self.query_params = {}
        self.client = self._C()
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.closed = None
        self.reason = ""
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000, reason=""):
        self.closed, self.reason = code, reason
        await self.inbox.put({"type": "websocket.disconnect"})

    async def send_text(self, t):
        pass

    async def send_bytes(self, b):
        pass

    async def receive(self):
        return await self.inbox.get()


async def close_all_live():
    await db.execute("UPDATE sessions SET state='closed' WHERE state='live'")
    idlesess._backoff.clear()


async def audit_rows(sid, status):
    return await db.fetchall("SELECT * FROM audit_log WHERE actor='system:idle-sessions' AND path=? AND status=?",
                             "/api/sessions/%s/kill" % sid, status)


async def audit_fixes(hid, src, owner, alice):
    """Auditul Codex 3.7.1 (constatările 1–3, 5, 6, 8): fiecare caz reprodus întâi, apoi reparat."""
    from app import alert_history, api, security
    pol_on = {"notify": True, "notify_days": 7, "autoclose": True, "grace_days": 2,
              "current_password": U.OWNER_PW}
    await close_all_live()

    # ── 1) notificarea neînregistrată nu programează nimic ──
    sA, hA = await new_session(hid, alice, days_old=20)
    real_req = alert_history.record_required

    async def broken(*a, **k):
        raise OSError(28, "no space left on device")
    alert_history.record_required = broken
    t0 = time.time()
    try:
        st = await sweep_at(t0)
    finally:
        alert_history.record_required = real_req
    rA = await srow(sA)
    check("C1: alerta nu s-a putut scrie → nicio notificare, niciun termen",
          st["notified"] == 0 and rA["idle_notified_at"] is None and rA["idle_close_after"] is None, dict(rA))
    idlesess._backoff.clear()
    await sweep_at(t0 + 3 * DAY)
    rA = await srow(sA)
    check("C1: …după grație nu închide; abia acum pleacă notificarea (cu termen nou)",
          sA not in src.killed and rA["idle_close_after"] and rA["idle_close_after"] > t0 + 4 * DAY, dict(rA))
    # preferinţa „fără alerte în aplicaţie" nu ascunde notificarea care programează o închidere
    await db.execute("INSERT OR REPLACE INTO alert_prefs(user_id, kind, email, inapp) VALUES(?,?,0,0)",
                     alice, "session_idle")
    sA2, _ = await new_session(hid, alice, days_old=20)
    await sweep_at(time.time())
    got = await db.fetchall("SELECT * FROM alerts WHERE user_id=? AND msg_key='session_idle_close'"
                            " AND msg_params LIKE ?", alice, '%' + sA2 + '%')
    check("C1: notificarea cu închidere se păstrează în aplicaţie chiar cu preferinţa oprită",
          len(got) == 1 and (await srow(sA2))["idle_close_after"] is not None)
    await db.execute("DELETE FROM alert_prefs WHERE user_id=?", alice)
    # dovada lipsă la închidere (istoricul de alerte golit) → nu închide; termenul cade, notificare nouă
    sA3, _ = await new_session(hid, alice, days_old=20)
    t0b = time.time()
    await sweep_at(t0b)
    await db.execute("DELETE FROM alerts WHERE user_id=? AND msg_params LIKE ?", alice, '%' + sA3 + '%')
    await sweep_at(t0b + 3 * DAY)
    check("C1: fără rândul de notificare pentru un destinatar curent → nu închide, termenul şters",
          sA3 not in src.killed and (await srow(sA3))["idle_close_after"] is None)
    await close_all_live()

    # ── 2) politica oprită în timpul unui sweep câştigă ──
    sB, hB = await new_session(hid, alice, days_old=20)
    t1 = time.time()
    await sweep_at(t1)
    check("C2: precondiţie — termen fixat", (await srow(sB))["idle_close_after"] is not None)
    real_rec = idlesess.recipients
    for flag, label in (("autoclose", "închiderea"), ("notify", "notificarea")):
        async def turn_off(row, flag=flag):
            if row["id"] == sB:
                pol = {"notify": True, "notify_days": 7, "autoclose": True, "grace_days": 2}
                pol[flag] = False
                await idlesess.save_policy(pol)
            return await real_rec(row)
        idlesess.recipients = turn_off
        try:
            await sweep_at(t1 + 3 * DAY)
        finally:
            idlesess.recipients = real_rec
        check("C2: %s oprită cât sweep-ul căuta destinatarii → nu închide" % label,
              sB not in src.killed and (await srow(sB))["state"] == "live")
        r = await owner.post("/api/settings/idle-sessions", json=pol_on)
        check("C2: repornită (cu parola)", r.status_code == 200 and r.json()["autoclose"] is True, r.text)
    # memoria înaintea DB-ului: cât se scrie setarea, politica din memorie e deja oprită
    real_set = db.set_setting
    seen_mem = []

    async def spy_set(key, value):
        if key == idlesess.SETTING_KEY:
            seen_mem.append(idlesess.current_policy()["autoclose"])
        return await real_set(key, value)
    db.set_setting = spy_set
    try:
        await idlesess.save_policy({"notify": True, "notify_days": 7, "autoclose": False, "grace_days": 2})
    finally:
        db.set_setting = real_set
    check("C2: oprirea e în memorie ÎNAINTE de scrierea în DB", seen_mem == [False], str(seen_mem))
    gen_before = idlesess.current_policy()["gen"]
    r = await owner.post("/api/settings/idle-sessions", json={k: v for k, v in pol_on.items()
                                                              if k != "current_password"})
    check("C7: pornirea închiderii fără re-autentificare → 401, politica neschimbată",
          r.status_code == 401 and idlesess.current_policy()["autoclose"] is False, r.text)
    r = await owner.post("/api/settings/idle-sessions", json=dict(pol_on, current_password="gresita123"))
    check("C7: parolă greşită → 401", r.status_code == 401, r.text)
    r = await owner.post("/api/settings/idle-sessions", json=pol_on)
    check("C7: cu parola → pornită", r.status_code == 200 and idlesess.current_policy()["autoclose"] is True)
    check("C2: comutarea măreşte generaţia", idlesess.current_policy()["gen"] > gen_before)
    r = await owner.post("/api/settings/idle-sessions", json=dict(pol_on, grace_days=3, current_password=""))
    check("C7: o modificare care nu porneşte închiderea nu cere parola", r.status_code == 200, r.text)
    await owner.post("/api/settings/idle-sessions", json=pol_on)
    # un termen dintr-o generaţie mai veche nu închide
    sB2, _ = await new_session(hid, alice, days_old=20)
    t1b = time.time()
    await sweep_at(t1b)
    await db.execute("UPDATE sessions SET idle_close_gen=idle_close_gen-1 WHERE id=?", sB2)
    await sweep_at(t1b + 3 * DAY)
    r2 = await srow(sB2)
    check("C2: termen din generaţia veche → nu închide, pleacă o notificare nouă",
          sB2 not in src.killed and r2["idle_close_gen"] == idlesess.current_policy()["gen"]
          and r2["idle_notified_at"] > t1b + DAY, dict(r2))
    await close_all_live()

    # ── 3) ataşarea cât kill-ul e în zbor e refuzată; replay / ataşare recentă → nu închide ──
    sC, hC = await new_session(hid, alice, days_old=20)
    t2 = time.time()
    await sweep_at(t2)
    gate, started = asyncio.Event(), asyncio.Event()

    class SlowSource(FakeSource):
        async def kill(self, sid):
            started.set()
            await gate.wait()
            await FakeSource.kill(self, sid)
    slow = SlowSource()
    core.sources[hid] = slow
    try:
        task = asyncio.create_task(sweep_at(t2 + 3 * DAY))
        await asyncio.wait_for(started.wait(), 10)
        check("C3: kill în zbor → idle_closing setat", hC.idle_closing is True)
        ws = IdleWS(await security.create_web_session(alice))
        await asyncio.wait_for(api.browser_ws(ws, sC), 10)
        check("C3: browser_ws cât se închide → 4410, niciun client în hub",
              ws.closed == 4410 and not hC.clients and "inactivity" in ws.reason, (ws.closed, ws.reason))
        tok = security.new_token()
        await db.execute("UPDATE sessions SET share_token=?, share_expires=? WHERE id=?",
                         security.sha256_hex(tok), time.time() + 3600, sC)
        g = IdleWS(None)
        await asyncio.wait_for(api.shared_ws(g, tok), 10)
        check("C3: shared_ws cât se închide → 4410", g.closed == 4410 and not hC.clients, g.closed)
        gate.set()
        st = await asyncio.wait_for(task, 10)
    finally:
        gate.set()
        core.sources[hid] = src
    check("C3: …apoi închisă şi confirmată", st["closed"] == 1 and (await srow(sC))["state"] == "closed", str(st))

    sD, hD = await new_session(hid, alice, days_old=20)
    t3 = time.time()
    await sweep_at(t3)
    hD._replay_expected = True
    hD._replay_end.clear()
    await sweep_at(t3 + 3 * DAY)
    check("C3: replay-ul după reconectare încă în curs → nu închide", sD not in src.killed)
    hD._replay_end.set()
    hD.attached_mono = time.monotonic() + 3 * DAY - 60     # re-ataşat acum un minut (timp simulat)
    await sweep_at(t3 + 3 * DAY)
    check("C3: hub re-ataşat de mai puţin de 10 minute → nu închide", sD not in src.killed)
    hD.attached_mono = time.monotonic() - 3600
    await sweep_at(t3 + 3 * DAY)
    check("C3: replay terminat + ataşat de o oră → închide", sD in src.killed)
    await close_all_live()

    # ── 5) ceasul monoton: saltul ceasului de perete şi restartul nu scurtează grația ──
    sE, hE = await new_session(hid, alice, days_old=20)
    t4 = time.time()
    await sweep_at(t4)
    await idlesess.sweep(now=t4 + 3 * DAY, mono=time.monotonic())
    check("C5: ceasul de perete sare 3 zile înainte, cel monoton nu → nu închide", sE not in src.killed)
    core.hubs.pop(sE, None)                                # „restart": un hub nou, fără observaţia veche
    hE2 = core.get_or_create_hub(await srow(sE))
    hE2.attached, hE2.attached_mono = True, time.monotonic() - 3600
    await sweep_at(t4 + 3 * DAY)
    check("C5: după restart grația reîncepe → nu închide la termenul vechi", sE not in src.killed)
    await sweep_at(t4 + 5 * DAY + 60)
    check("C5: …închide după o grație întreagă văzută de procesul nou", sE in src.killed)
    await close_all_live()

    # ── 6) răspunsul agentului contează; succesul vine doar după on_exit ──
    class RefusingSource(FakeSource):
        calls = 0

        async def kill_checked(self, sid):
            RefusingSource.calls += 1
            return {"ok": False, "code": "no_session"}
    closed_before = len(await alerts_for(alice, "session_idle_closed"))
    sF, hF = await new_session(hid, alice, days_old=20)
    t5 = time.time()
    await sweep_at(t5)
    core.sources[hid] = RefusingSource()
    try:
        st = await sweep_at(t5 + 3 * DAY)
        check("C6: agentul răspunde no_session → nu e închisă, fără alerta „închisă”",
              st["closed"] == 0 and (await srow(sF))["state"] == "live"
              and len(await alerts_for(alice, "session_idle_closed")) == closed_before, str(st))
        check("C6: …audit „not confirmed” (504), niciun 200",
              len(await audit_rows(sF, 504)) == 1 and not await audit_rows(sF, 200))
        check("C6: …idle_closing şters, motivul de ieşire resetat",
              hF.idle_closing is False and hF.exit_reason == "exited")
        await sweep_at(t5 + 3 * DAY)
        check("C6: …şi nicio reîncercare imediată (backoff)", RefusingSource.calls == 1, RefusingSource.calls)
    finally:
        core.sources[hid] = src

    class SilentSource(FakeSource):
        async def kill_checked(self, sid):
            return {"ok": True}                       # agentul zice ok, dar exit-ul nu mai vine
    sG, hG = await new_session(hid, alice, days_old=20)
    t6 = time.time()
    await sweep_at(t6)
    real_wait = idlesess.CLOSE_CONFIRM
    idlesess.CLOSE_CONFIRM = 0.3
    core.sources[hid] = SilentSource()
    try:
        st = await sweep_at(t6 + 3 * DAY)
        check("C6: ok fără exit → „pending”, nu „closed”", st["closed"] == 0 and st["pending"] == 1, str(st))
        await asyncio.sleep(1.2)
        check("C6: …după fereastra de confirmare: audit 504, fără 200, ataşarea permisă din nou",
              len(await audit_rows(sG, 504)) == 1 and not await audit_rows(sG, 200)
              and hG.idle_closing is False)
    finally:
        idlesess.CLOSE_CONFIRM = real_wait
        core.sources[hid] = src
    await close_all_live()

    # ── 8) cursorul rotativ ajunge la sesiunile de după primul lot ──
    real_rows = idlesess.MAX_ROWS
    idlesess.MAX_ROWS = 2
    try:
        many = [(await new_session(hid, alice, days_old=20))[0] for _ in range(5)]
        for _ in range(6):
            await sweep_at(time.time())
        notified = [s for s in many if (await srow(s))["idle_notified_at"]]
        check("C8: cu plafonul de 2 rânduri, toate cele 5 sesiuni sunt notificate în câteva treceri",
              len(notified) == 5, "%d/5" % len(notified))
    finally:
        idlesess.MAX_ROWS = real_rows
    # persist_activity: watermark-ul avansează doar după o scriere reuşită
    hX = core.hubs[many[0]]
    hX.last_input_at = time.time()
    real_exec = db.execute

    async def failing(sql, *a):
        if sql.startswith("UPDATE sessions SET last_active"):
            raise OSError(5, "I/O error")
        return await real_exec(sql, *a)
    db.execute = failing
    try:
        try:
            await hX.persist_activity()
        except OSError:
            pass
    finally:
        db.execute = real_exec
    check("C8: scriere eşuată → watermark-ul nu avansează", hX._persisted_active < hX.last_input_at)
    await hX.persist_activity()
    check("C8: …reîncercarea reuşeşte", hX._persisted_active >= hX.last_input_at)
    await close_all_live()


if __name__ == "__main__":
    asyncio.run(main())
    raise SystemExit(0 if check.summary() else 1)
