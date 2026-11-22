"""Igiena sesiunilor inactive (3.7.1, idlesess.py; INV-13) — DOAR notificare.

  * inactivă = fără input, fără output, fără client — fiecare dintre ele reporneşte ceasul;
  * o singură notificare per perioadă, proprietarului (fără proprietar → session.manage; terminal root
    fără proprietar → nimeni, deci nimic); o nouă perioadă de inactivitate aduce o notificare nouă;
  * nimic nu se închide automat: `autoclose: true` → 400, un `autoclose: true` stocat se citeşte oprit,
    sweep-ul nu trimite niciodată un kill, iar notificarea nu poartă nicio dată de închidere;
  * Keep open, rutele (keep-open: al tău / session.manage; setările: settings.manage), validarea zilelor;
  * tokenurile nu primesc metadatele de inactivitate; `shared` doar ca boolean;
  * notificarea neînregistrată nu marchează sesiunea (reîncercare după backoff); bugetul şi cursorul;
  * migraţiile rulează de două ori fără eroare.
"""
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rbac_util as U  # noqa: E402  (pune mediul şi DB-ul temporar înainte de `app`)
from app import alert_history, core, db, idlesess  # noqa: E402

check = U.Checker()
DAY = 86400.0


class FakeSource(core.AgentConnection):
    """Sursa unui host: un agent care ar ACCEPTA orice închidere (kill, kill_checked, kill_if_quiet) — dacă
    gateway-ul i-ar cere vreuna, testul ar vedea-o în `killed`. Fără `super().__init__`: nu există websocket."""
    backend = "tmux"
    epoch = "e1"

    def __init__(self):
        self.killed = []
        self.agent_version = 99

    async def request(self, op, timeout=20.0, **fields):
        if op.startswith("kill"):
            self.killed.append((op, fields.get("sid")))
            return {"ok": True}
        raise core.AgentGone("fake source: no websocket")

    async def kill(self, sid):
        self.killed.append(("kill", sid))
        hub = core.hubs.get(sid)
        if hub is not None:
            await hub.on_exit(0, None)

    async def kill_checked(self, sid):
        await self.kill(sid)
        return {"ok": True}

    async def kill_if_quiet(self, sid, quiet_secs, still_ok=None):
        await self.kill(sid)
        return {"ok": True}

    def can_kill_if_quiet(self):
        return True

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


async def new_session(hid, by, days_old=10.0, origin="web"):
    """O sesiune vie cu hub ataşat, folosită ultima oară acum `days_old` zile."""
    sid = await U.add_session(hid, created_by=by)
    await db.execute("UPDATE sessions SET origin=? WHERE id=?", origin, sid)
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    hub = core.get_or_create_hub(row)
    hub.attached = True
    await backdate(sid, days_old)
    return sid, hub


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


async def alerts_for(uid, kind="session_idle", sid=None):
    await asyncio.sleep(0.05)
    rows = await db.fetchall("SELECT * FROM alerts WHERE user_id=? AND kind=?", uid, kind)
    return [r for r in rows if sid is None or sid in (r["msg_params"] or "")]


async def settle():
    for _ in range(5):
        await asyncio.sleep(0.02)        # bgtasks (anularea notificării, persistarea)


async def close_all_live():
    await db.execute("UPDATE sessions SET state='closed' WHERE state='live'")
    for sid in list(core.hubs):
        core.hubs.pop(sid, None)
    idlesess._backoff.clear()


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
          {"last_active", "idle_notified_at", "keep_open"} <= cols, str(cols))

    # ── 3.7.1 nu are închidere automată ──
    check("AUTOCLOSE_AVAILABLE = False", idlesess.AUTOCLOSE_AVAILABLE is False)
    check("gateway-ul nu mai ştie să trimită kill_if_quiet",
          not hasattr(core.AgentConnection, "kill_if_quiet") and not hasattr(core, "KILL_IF_QUIET_MIN_AGENT"))

    # ── setări: implicite, permisiuni, validare ──
    r = await owner.get("/api/settings/idle-sessions")
    j = r.json()
    check("implicit: notificare pornită 7 zile, închidere oprită şi indisponibilă",
          r.status_code == 200 and j["notify"] is True and j["notify_days"] == 7
          and j["autoclose"] is False and j["autoclose_available"] is False and "grace_days" not in j, r.text)
    check("setările: Operator → 403", (await cb.get("/api/settings/idle-sessions")).status_code == 403)
    r = await cb.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7})
    check("setările: Operator nu poate salva → 403", r.status_code == 403)
    r = await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 0})
    check("zile în afara limitelor → 400 settings.idleDaysRange",
          r.status_code == 400 and U.code(r) == "settings.idleDaysRange", r.text)
    r = await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 91})
    check("zile > 90 → 400", r.status_code == 400 and U.code(r) == "settings.idleDaysRange", r.text)
    for who, c in (("Owner", owner), ("Admin", cadm)):
        r = await c.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7, "autoclose": True,
                                                             "grace_days": 2, "current_password": U.OWNER_PW})
        check("autoclose: true (%s) → 400 settings.autocloseUnavailable, politica neschimbată" % who,
              r.status_code == 400 and U.code(r) == "settings.autocloseUnavailable"
              and idlesess.current_policy()["autoclose"] is False, r.text)
    r = await cadm.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7})
    check("setările: Admin poate salva", r.status_code == 200 and r.json()["autoclose"] is False, r.text)
    r = await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7, "autoclose": False,
                                                             "grace_days": 99})
    check("un `grace_days` vechi trimis de un client rc e ignorat (nu mai există)", r.status_code == 200, r.text)
    check("politica stocată corupt → implicit",
          idlesess.sanitize({"autoclose": "yes", "notify_days": "x"})["autoclose"] is False
          and idlesess.sanitize({"notify_days": 999})["notify_days"] == 90)
    check("sanitize: un `autoclose: true` explicit se citeşte OPRIT",
          idlesess.sanitize({"autoclose": True})["autoclose"] is False)
    # un DB de la un rc 3.7.1 cu închiderea pornită
    await db.set_setting(idlesess.SETTING_KEY, json.dumps({"notify": True, "notify_days": 7, "autoclose": True,
                                                           "grace_days": 2, "gen": 5}))
    pol = await idlesess.load_policy(fresh=True)
    check("`autoclose: true` stocat (rc) → citit oprit", pol["autoclose"] is False, str(pol))
    j = (await owner.get("/api/settings/idle-sessions")).json()
    check("…şi ruta raportează oprit", j["autoclose"] is False and j["autoclose_available"] is False, str(j))

    # ── detecţie: notificare o dată, doar proprietarului; nicio închidere, nicio dată ──
    s1, h1 = await new_session(hid, alice, days_old=6)
    st = await idlesess.sweep()
    check("6 zile < 7 → nicio notificare", st["notified"] == 0 and not (await srow(s1))["idle_notified_at"], str(st))
    await backdate(s1, 8)
    st = await idlesess.sweep()
    check("8 zile → notificat", st["notified"] == 1 and (await srow(s1))["idle_notified_at"], str(st))
    got = await alerts_for(alice, sid=s1)
    check("alerta session_idle (rândul) e înregistrată la proprietar", len(got) == 1)
    if got:
        params = json.loads(got[0]["msg_params"] or "{}")
        check("notificarea nu poartă nicio dată/grație de închidere",
              got[0]["msg_key"] == "session_idle" and "grace" not in params and "close" not in json.dumps(params)
              and "closed automatically" not in (got[0]["details"] or ""), dict(got[0]))
    check("…şi nu la alt Operator", len(await alerts_for(bob)) == 0)
    check("…nici la Owner (sesiunea are proprietar)", len(await alerts_for(owner_id)) == 0)
    st = await idlesess.sweep()
    check("a doua trecere: nu notifică din nou", st["notified"] == 0, str(st))
    st = await idlesess.sweep(now=time.time() + 60 * DAY)
    check("60 de zile mai târziu, cu `autoclose: true` stocat: NICIUN kill, nicio notificare repetată",
          not src.killed and (await srow(s1))["state"] == "live" and st["notified"] == 0
          and len(await alerts_for(alice, sid=s1)) == 1, "%s %s" % (st, src.killed))
    lst = (await ca.get("/api/sessions")).json()
    me = next((x for x in lst if x["id"] == s1), {})
    check("lista de sesiuni arată notificarea, fără dată de închidere",
          me.get("idle_notice") and set(me["idle_notice"]) == {"at", "days"} and me["keep_open"] is False, str(me))

    # ── fiecare activitate anulează notificarea; o perioadă nouă aduce o notificare nouă ──
    await h1.handle_input(FakeClient(), b"x")
    await settle()
    check("input → notificarea anulată imediat", (await srow(s1))["idle_notified_at"] is None)
    check("input → nu mai e inactivă", (await idlesess.sweep())["notified"] == 0)
    await backdate(s1, 8)
    await idlesess.sweep()
    check("din nou inactivă → notificată din nou", (await srow(s1))["idle_notified_at"] is not None
          and len(await alerts_for(alice, sid=s1)) == 2)
    await h1._process_output(b"build line\r\n")
    await settle()
    check("output → notificarea anulată", (await srow(s1))["idle_notified_at"] is None)
    check("output → nu mai e inactivă", (await idlesess.sweep())["notified"] == 0)
    await backdate(s1, 8)
    await idlesess.sweep()
    c = FakeClient()
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
    # activitate pe care hub-ul n-a semnalat-o (idle_pending pierdut) → sweep-ul o vede şi anulează
    s3, h3 = await new_session(hid, alice, days_old=10)
    await idlesess.sweep()
    h3.idle_pending = False
    h3.last_input_at = time.time() + 60
    st = await idlesess.sweep(now=time.time() + 120)
    check("activitate după notificare văzută de sweep → anulată",
          (await srow(s3))["idle_notified_at"] is None and st["cleared"] >= 1, str(st))

    # ── Keep open: rutele + efectul ──
    s5, _ = await new_session(hid, alice, days_old=10)
    await idlesess.sweep()
    r = await cb.post(f"/api/sessions/{s5}/keep-open", json={"keep": True})
    check("keep-open: alt Operator → 403", r.status_code == 403, r.text)
    r = await ca.post(f"/api/sessions/{s5}/keep-open", json={"keep": True})
    check("keep-open: proprietarul → 200", r.status_code == 200, r.text)
    r5 = await srow(s5)
    check("keep-open anulează notificarea în curs", r5["keep_open"] == 1 and r5["idle_notified_at"] is None)
    await idlesess.sweep(now=time.time() + 30 * DAY)
    check("Keep open → nu notifică", (await srow(s5))["idle_notified_at"] is None)
    r = await cadm.post(f"/api/sessions/{s5}/keep-open", json={"keep": False})
    check("keep-open: session.manage (Admin) → 200", r.status_code == 200, r.text)
    check("keep-open oprit", (await srow(s5))["keep_open"] == 0)
    await db.execute("UPDATE sessions SET state='closed' WHERE id=?", s3)
    r = await ca.post("/api/sessions/%s/keep-open" % s3, json={"keep": True})
    check("keep-open pe o sesiune închisă → 409", r.status_code == 409 and U.code(r) == "session.keepNotLive", r.text)
    r = await ca.post("/api/sessions/%s/keep-open" % ("0" * 32), json={"keep": True})
    check("keep-open pe o sesiune inexistentă → 404", r.status_code == 404, r.text)

    # ── fail-closed: host offline / hub neataşat / fără hub → nimic ──
    await close_all_live()
    s6, h6 = await new_session(hid, alice, days_old=10)
    core.sources.pop(hid)
    await idlesess.sweep()
    check("host offline → nicio notificare", (await srow(s6))["idle_notified_at"] is None)
    core.sources[hid] = src
    h6.attached = False
    await idlesess.sweep()
    check("hub neataşat (output nevăzut) → nicio notificare", (await srow(s6))["idle_notified_at"] is None)
    h6.attached = True
    s7 = await U.add_session(hid, created_by=alice)
    await db.execute("UPDATE sessions SET created=? WHERE id=?", time.time() - 30 * DAY, s7)
    await idlesess.sweep(now=time.time() + 30 * DAY)
    check("sesiune fără hub (fluxul nu trece prin gateway) → nimic", not (await srow(s7))["idle_notified_at"])

    # ── notificarea neînregistrată nu marchează sesiunea; se reîncearcă după backoff ──
    await close_all_live()
    sA, _ = await new_session(hid, alice, days_old=20)
    real_req = alert_history.record_required

    async def broken(*a, **k):
        raise OSError(28, "no space left on device")
    alert_history.record_required = broken
    try:
        st = await idlesess.sweep()
    finally:
        alert_history.record_required = real_req
    check("alerta nu s-a putut scrie → sesiunea NU rămâne marcată notificată, backoff",
          st["notified"] == 0 and (await srow(sA))["idle_notified_at"] is None and idlesess._backed_off(sA), str(st))
    st = await idlesess.sweep()
    check("…în backoff nu se reîncearcă", st["notified"] == 0)
    idlesess._backoff.clear()
    st = await idlesess.sweep()
    check("…după backoff, notificarea pleacă şi rândul e înregistrat",
          st["notified"] == 1 and len(await alerts_for(alice, sid=sA)) == 1, str(st))
    # preferinţa „fără alerte în aplicaţie": sesiunea e marcată (fără buclă), niciun rând
    await db.execute("INSERT OR REPLACE INTO alert_prefs(user_id, kind, email, inapp) VALUES(?,?,0,0)",
                     alice, "session_idle")
    sA2, _ = await new_session(hid, alice, days_old=20)
    st = await idlesess.sweep()
    check("preferinţa în aplicaţie oprită → respectată (niciun rând), sesiunea marcată (fără reîncercări)",
          (await srow(sA2))["idle_notified_at"] is not None and len(await alerts_for(alice, sid=sA2)) == 0, str(st))
    await db.execute("DELETE FROM alert_prefs WHERE user_id=?", alice)

    # ── destinatari: fără proprietar → session.manage; terminal root fără proprietar → nimeni ──
    await close_all_live()
    s9, _ = await new_session(hid, None, days_old=10)
    rec = await idlesess.recipients(await srow(s9))
    check("fără proprietar → cei cu session.manage (Owner + Admin), nu Operatorii",
          set(rec) == {owner_id, adm}, str(rec))
    s10, _ = await new_session(hid, None, days_old=10, origin="cert-renew")
    check("terminal root fără proprietar → nimeni", await idlesess.recipients(await srow(s10)) == [])
    fired = []

    async def count_req(*a, **k):
        fired.append(k.get("user_id"))
        return await real_req(*a, **k)
    alert_history.record_required = count_req
    try:
        await idlesess.sweep()
    finally:
        alert_history.record_required = real_req
    check("fără proprietar → un singur apel de alertă, cu toţi destinatarii",
          len(fired) == 1 and isinstance(fired[0], list) and set(fired[0]) == {owner_id, adm}, str(fired))
    check("terminal root fără proprietar → nicio notificare", not (await srow(s10))["idle_notified_at"])
    await db.execute("UPDATE users SET disabled=1 WHERE id=?", alice)
    s11, _ = await new_session(hid, alice, days_old=10)
    check("proprietar dezactivat → cei cu session.manage",
          set(await idlesess.recipients(await srow(s11))) == {owner_id, adm})
    await db.execute("UPDATE users SET disabled=0 WHERE id=?", alice)

    # ── notificarea oprită → nimic ──
    await close_all_live()
    await owner.post("/api/settings/idle-sessions", json={"notify": False, "notify_days": 7})
    s12, _ = await new_session(hid, alice, days_old=30)
    st = await idlesess.sweep(now=time.time() + 30 * DAY)
    check("notificarea oprită → nicio notificare", st["notified"] == 0 and not (await srow(s12))["idle_notified_at"])
    await owner.post("/api/settings/idle-sessions", json={"notify": True, "notify_days": 7})

    # ── tokenuri: fără metadate de inactivitate; `shared` doar boolean ──
    await idlesess.sweep()
    await db.execute("UPDATE sessions SET keep_open=1, share_token='h', share_expires=? WHERE id=?",
                     time.time() + 600, s12)
    r = await owner.post("/api/tokens", json={"name": "auto", "scopes": ["read"], "days": 1, "role": "viewer",
                                              "scope_kind": "all", "scope_value": "", "current_password": U.OWNER_PW})
    tok = r.json().get("token") if r.status_code == 200 else None
    check("token creat", bool(tok), r.text[:160])
    if tok:
        tc = U.client(headers={"authorization": "Bearer " + tok})
        rows = (await tc.get("/api/sessions")).json()
        me = next((x for x in rows if x["id"] == s12), {})
        check("token: idle_notice null, keep_open false, last_output null, shared false",
              me and me["idle_notice"] is None and me["keep_open"] is False and me["last_output"] is None
              and me["shared"] is False, str(me))
        r = await tc.get("/api/hosts/%d/sessions" % hid)
        if r.status_code == 200:
            me = next((x for x in r.json() if x["id"] == s12), {})
            check("token, lista per host: la fel", me and me["idle_notice"] is None and me["keep_open"] is False, str(me))
        else:
            check("token, lista per host: refuzată (deci nimic expus)", r.status_code in (401, 403), r.text[:120])
        await tc.aclose()
    me = next((x for x in (await ca.get("/api/sessions")).json() if x["id"] == s12), {})
    check("browser: `shared` adevărat ca boolean, fără token", me.get("shared") is True and "share_token" not in me
          and "h" not in me.values(), str(me))
    check("browser: keep_open vizibil", me.get("keep_open") is True, str(me))
    await db.execute("UPDATE sessions SET keep_open=0, share_token=NULL, share_expires=NULL WHERE id=?", s12)

    # ── buget: cel mult MAX_ACTIONS notificări pe sweep; cursorul rotativ ──
    await close_all_live()
    real_act, real_rows = idlesess.MAX_ACTIONS, idlesess.MAX_ROWS
    idlesess.MAX_ACTIONS = 2
    try:
        many = [(await new_session(hid, alice, days_old=20))[0] for _ in range(5)]
        st = await idlesess.sweep()
        check("buget: cel mult MAX_ACTIONS notificări într-o trecere", st["notified"] == 2, str(st))
        for _ in range(3):
            await idlesess.sweep()
        check("…restul în trecerile următoare",
              all([(await srow(s))["idle_notified_at"] for s in many]))
    finally:
        idlesess.MAX_ACTIONS = real_act
    await close_all_live()
    idlesess.MAX_ROWS = 2
    try:
        many = [(await new_session(hid, alice, days_old=20))[0] for _ in range(5)]
        for _ in range(6):
            await idlesess.sweep()
        notified = [s for s in many if (await srow(s))["idle_notified_at"]]
        check("cursor: cu plafonul de 2 rânduri, toate cele 5 sesiuni sunt notificate în câteva treceri",
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
    check("persist: scriere eşuată → watermark-ul nu avansează", hX._persisted_active < hX.last_input_at)
    await hX.persist_activity()
    check("persist: …reîncercarea reuşeşte", hX._persisted_active >= hX.last_input_at)

    check("nicio cerere de închidere n-a ajuns vreodată la sursă", not src.killed, str(src.killed))
    audit = await db.fetchall("SELECT * FROM audit_log WHERE actor='system:idle-sessions'")
    check("nicio închidere de inactivitate în audit", not audit)

    for c in (owner, ca, cb, cadm):
        await c.aclose()


if __name__ == "__main__":
    asyncio.run(main())
    raise SystemExit(0 if check.summary() else 1)
