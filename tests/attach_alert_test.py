"""Anunţ de ataşare (2.0.2): când cineva se ataşează la o sesiune vie, ceilalţi clienţi
conectaţi primesc un eveniment `attached`, iar dispozitivele de pe adrese care nu sunt locuri
stabilite ale contului sunt marcate `known=False` (ridică notificarea la avertisment + email).

Invariantul care contează, şi motivul pentru care testul îl verifică explicit: identitatea de
dispozitiv decide DOAR volumul alertei, niciodată dacă se sare peste o verificare. Nu există
cale prin care `known=True` să scutească pe cineva de step-up — dacă apare vreodată una, testul
`known nu atinge lock/step-up` de mai jos pică.
"""
import asyncio
import json
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import core, db, email_alerts, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send_text(self, t):
        self.sent.append(t)


class DeadWS(FakeWS):
    async def send_text(self, t):
        raise RuntimeError("socket mort")


def mk(hub, cid, *, ip="", agent="", known=True, owner=True, label="self"):
    c = core.BrowserClient(FakeWS(), hub)
    c.id, c.label, c.is_owner = cid, label, owner
    c.remote_addr, c.user_agent, c.known = ip, agent, known
    c.attached_at = time.time()
    hub.clients.add(c)
    return c


async def main():
    await db.connect()
    sid = "b" * 32
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,rows,cols) VALUES(?,?,?,?,?,?,?)",
        sid, 1, "t", "live", time.time(), 24, 80)
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    hub = core.get_or_create_hub(row)

    # ---- roster: poartă acum de UNDE e ataşat fiecare ----
    a = mk(hub, "o_aaa", ip="1.2.3.4", agent="Mozilla/5.0 (iPhone) Safari/605", known=True)
    r = hub.roster()
    check("roster: un rând per client", len(r) == 1, r)
    e = r[0]
    check("roster: duce IP-ul", e.get("ip") == "1.2.3.4", e)
    check("roster: duce user-agent-ul", "iPhone" in (e.get("agent") or ""), e)
    check("roster: duce marcajul known", e.get("known") is True, e)
    check("roster: duce momentul ataşării", isinstance(e.get("since"), int) and e["since"] > 0, e)
    # …dar user-agent-ul e tăiat: e text controlat de client, iar roster-ul se difuzează
    # la fiecare ataşare/plecare — fără plafon, un UA de 8 KB devine amplificare.
    long_ua = mk(hub, "o_len", agent="X" * 4000)
    check("roster: user-agent plafonat la 120",
          len(next(x for x in hub.roster() if x["id"] == "o_len")["agent"]) == 120)
    hub.clients.discard(long_ua)

    # ---- announce_attach: ceilalţi află, cel care intră NU se anunţă singur ----
    b = mk(hub, "o_bbb", ip="9.9.9.9", agent="Mozilla/5.0 (X11; Linux) Firefox/128", known=False)
    await hub.announce_attach(b)
    msgs = [json.loads(t) for t in a.ws.sent if '"attached"' in t]
    check("announce: cel deja ataşat primeşte evenimentul", len(msgs) == 1, a.ws.sent)
    check("announce: cel care tocmai a intrat NU se anunţă sieşi",
          not any('"attached"' in t for t in b.ws.sent), b.ws.sent)
    if msgs:
        cl = msgs[0]["client"]
        check("announce: identifică cine s-a ataşat", cl["id"] == "o_bbb", cl)
        check("announce: duce IP + agent", cl["ip"] == "9.9.9.9" and "Firefox" in cl["agent"], cl)
        check("announce: marchează dispozitivul necunoscut", cl["known"] is False, cl)

    # ---- un client mort nu opreşte anunţul către ceilalţi ----
    dead = core.BrowserClient(DeadWS(), hub)
    dead.id = "o_dead"
    hub.clients.add(dead)
    before = len([t for t in a.ws.sent if '"attached"' in t])
    c = mk(hub, "o_ccc", ip="5.5.5.5")
    await hub.announce_attach(c)
    check("announce: un socket mort nu blochează restul anunţului",
          len([t for t in a.ws.sent if '"attached"' in t]) == before + 1)
    hub.clients.discard(dead)

    # ---- known nu atinge NIMIC din lock/step-up ----
    # Un „dispozitiv cunoscut" trebuie să fie blocat de idle-lock exact ca oricare altul;
    # altfel semnalul slab (istoric de IP) ar deveni ocolire de autentificare.
    hub.lock_idle = 300
    await hub.lock()
    check("known nu atinge lock/step-up: clientul cunoscut e blocat la fel",
          a.locked is True and a.known is True)
    await hub.unlock()

    # ---- ip_is_known: citeşte, nu înregistrează ----
    await db.execute(
        "INSERT INTO users(email,password_hash,created) VALUES(?,?,?)",
        "u@example.com", "x", time.time())
    user = await db.fetchone("SELECT * FROM users WHERE email=?", "u@example.com")
    check("ip_is_known: IP nemaivăzut → False",
          await security.ip_is_known(user["id"], "203.0.113.7") is False)
    # „Cunoscut" nu înseamnă „văzut o dată", ci „loc cu istoric": mai multe login-uri, peste
    # mai mult de o zi. Un singur login nu-şi poate declara singur adresa drept obişnuită.
    await security.note_new_login(user, "203.0.113.7", "curl/8")
    check("ip_is_known: după UN login de acolo → încă necunoscut",
          await security.ip_is_known(user["id"], "203.0.113.7") is False)
    for _ in range(3):
        await security.note_new_login(user, "203.0.113.7", "curl/8")
    await db.execute("UPDATE seen_logins SET created=? WHERE user_id=? AND ip_hash=?",
                     time.time() - security.ESTABLISHED_AGE - 60, user["id"],
                     security.sha256_hex("203.0.113.7"))
    check("ip_is_known: cu istoric şi vechime → cunoscut",
          await security.ip_is_known(user["id"], "203.0.113.7") is True)
    check("ip_is_known: alt IP rămâne necunoscut",
          await security.ip_is_known(user["id"], "203.0.113.8") is False)
    # simpla interogare nu trebuie să înveţe IP-ul (altfel primul atacator care se ataşează
    # şi-ar marca singur adresa drept „cunoscută" şi a doua oară n-ar mai suna nimic)
    check("ip_is_known: interogarea NU înregistrează adresa",
          await security.ip_is_known(user["id"], "203.0.113.8") is False)

    # ---- emailul e throttled per adresă ----
    sent = []
    orig = email_alerts._fire
    email_alerts._fire = lambda subj, body: sent.append((subj, body))
    try:
        email_alerts.notify_session_attach("deploy", "203.0.113.9", "Firefox/128", "u@example.com")
        email_alerts.notify_session_attach("deploy", "203.0.113.9", "Firefox/128", "u@example.com")
        check("email: un singur mesaj pentru rafală de pe aceeaşi adresă", len(sent) == 1, sent)
        email_alerts.notify_session_attach("deploy", "198.51.100.4", "Safari/605", "u@example.com")
        check("email: adresă nouă → mesaj nou", len(sent) == 2, sent)
        if sent:
            body = sent[0][1]
            check("email: spune de unde şi cu ce", "203.0.113.9" in body and "Firefox/128" in body, body)
            check("email: numeşte sesiunea", "deploy" in body, body)
    finally:
        email_alerts._fire = orig

    for h in list(core.hubs.values()):
        try:
            h.teardown()
        except Exception:
            pass
    print(f"\n{ok}/{total} PASS", flush=True)
    os._exit(0 if ok == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
