"""Istoricul de alerte în aplicaţie + preferinţe per eveniment (3.5.11).

Ce verificăm:
  * înregistrare: evenimentele de CONT ajung doar la contul lor, cele de FLOTĂ la fiecare cont;
  * preferinţe: „în aplicaţie" oprit nu mai înregistrează — dar tipurile de securitate se
    înregistrează ORICUM; „email" oprit opreşte canalul extern (email/webhook), iar la un eveniment
    de flotă emailul pleacă dacă măcar un cont îl vrea;
  * retenţia: ultimele 500 per cont, maxim 30 de zile (tăiate la inserare);
  * igienă: tokenuri / parole / credenţiale din URL nu ajung în `details`;
  * API: doar cookie (401 fără, 401 cu token Bearer), izolare între conturi la listare, marcare
    şi ştergere, paginare newest-first, filtru necitite, prefs validate;
  * ştergerea unui cont îi şterge istoricul şi preferinţele.
"""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import alert_history, api, config, db, email_alerts, security  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0
PW1, PW2 = "parolabuna1", "parolabuna2"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


async def _rows(uid, kind=None):
    if kind:
        return await db.fetchall("SELECT * FROM alerts WHERE user_id=? AND kind=? ORDER BY id", uid, kind)
    return await db.fetchall("SELECT * FROM alerts WHERE user_id=? ORDER BY id", uid)


async def _settle():
    # _fire rulează în task-uri de fundal; câteva ture de event loop le lasă să termine
    for _ in range(20):
        await asyncio.sleep(0.01)


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    # canalul extern: numărăm trimiterile în loc să vorbim cu un SMTP/webhook real
    sent = []
    email_alerts._send_blocking = lambda cfg, subject, body: sent.append(subject)
    for k, v in (("smtp_host", "smtp.example.com"), ("smtp_to", "ops@example.com"),
                 ("smtp_from", "wt@example.com")):
        await api._set_setting(k, v)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as a, \
            httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as b, \
            httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as anon:
        await a.post("/api/setup", json={"email": "unu@x.co", "password": PW1, "setup_token": "test-setup"})
        r = await a.post("/api/users", json={"email": "doi@x.co", "password": PW2, "current_password": PW1})
        check("al doilea cont creat", r.status_code == 200, r.text[:120])
        u1 = (await db.fetchone("SELECT id FROM users WHERE email='unu@x.co'"))["id"]
        u2 = (await db.fetchone("SELECT id FROM users WHERE email='doi@x.co'"))["id"]
        await _settle()

        # ── evenimente reale, prin fluxurile existente ─────────────────────────────────────
        adm1, adm2 = await _rows(u1, "admin_change"), await _rows(u2, "admin_change")
        check("cont nou = eveniment de flotă → câte o copie pentru FIECARE cont",
              len(adm1) == 1 and len(adm2) == 1 and "new WebTerm account" in adm1[0]["title"],
              f"{[dict(x) for x in adm1]} {[dict(x) for x in adm2]}")
        r = await b.post("/api/login", json={"email": "doi@x.co", "password": PW2})
        check("login cont 2", r.status_code == 200, r.text[:120])
        await _settle()
        check("login nou = eveniment de CONT → doar la contul 2",
              len(await _rows(u2, "new_login")) == 1 and len(await _rows(u1, "new_login")) == 0)

        # ── fan-out + host_id + severitate, direct prin notify_* ───────────────────────────
        hid = (await a.post("/api/hosts", json={"name": "srv-a"})).json()["id"]
        email_alerts.notify_host_offline(hid, "srv-a", 300)
        await _settle()
        off = await _rows(u2, "host_offline")
        check("host offline → la ambele conturi, cu host_id şi severity=warning",
              len(off) == 1 and off[0]["host_id"] == hid and off[0]["severity"] == "warning"
              and len(await _rows(u1, "host_offline")) == 1, str([dict(x) for x in off]))

        # ── preferinţe: în aplicaţie oprit (non-securitate) ────────────────────────────────
        await alert_history.set_prefs(u1, {"host_offline": {"email": True, "inapp": False}})
        email_alerts.notify_host_online(hid, "srv-a")
        await _settle()
        check("in-app oprit pe host_offline → contul 1 NU primeşte rândul, contul 2 da",
              len(await _rows(u1, "host_offline")) == 1 and len(await _rows(u2, "host_offline")) == 2)

        # ── securitate: in-app nu se poate opri ───────────────────────────────────────────
        await alert_history.set_prefs(u2, {"account_change": {"email": True, "inapp": False}})
        prefs = {p["kind"]: p for p in await alert_history.get_prefs(u2)}
        check("prefs: tipul de securitate rămâne inapp=True chiar dacă s-a cerut False",
              prefs["account_change"]["inapp"] is True and prefs["account_change"]["security"] is True)
        email_alerts.notify_security_change("2FA (TOTP) disabled", "1.2.3.4", "doi@x.co",
                                            severity="critical", user_id=u2)
        await _settle()
        acc = await _rows(u2, "account_change")
        check("schimbare de cont → înregistrată la contul 2 (critical), nu şi la contul 1",
              len(acc) == 1 and acc[0]["severity"] == "critical"
              and len(await _rows(u1, "account_change")) == 0, str([dict(x) for x in acc]))

        # ── email gating ──────────────────────────────────────────────────────────────────
        sent.clear()
        await alert_history.set_prefs(u2, {"account_change": {"email": False, "inapp": True}})
        email_alerts.notify_security_change("passkey deleted", "1.2.3.4", "doi@x.co", user_id=u2)
        await _settle()
        check("email oprit pe un eveniment de cont → nu pleacă, dar rămâne în aplicaţie",
              sent == [] and len(await _rows(u2, "account_change")) == 2, str(sent))

        sent.clear()
        await alert_history.set_prefs(u1, {"gateway_disk": {"email": False, "inapp": True}})
        email_alerts._last_sent.clear()
        email_alerts.notify_disk_low(1, 100, 1.0)
        await _settle()
        check("flotă: un cont a oprit emailul, celălalt nu → emailul pleacă",
              len(sent) == 1 and "disk" in sent[0], str(sent))
        sent.clear()
        await alert_history.set_prefs(u2, {"gateway_disk": {"email": False, "inapp": True}})
        email_alerts._last_sent.clear()
        email_alerts.notify_disk_low(1, 100, 1.0)
        await _settle()
        check("flotă: TOATE conturile au oprit emailul → nu pleacă, dar e în istoric",
              sent == [] and len(await _rows(u1, "gateway_disk")) == 2, str(sent))

        # ── retenţie ──────────────────────────────────────────────────────────────────────
        now = time.time()
        await db.execute("INSERT INTO alerts(user_id, ts, kind, severity, title) VALUES(?,?,?,?,?)",
                         u1, now - 31 * 86400, "resource", "info", "foarte veche")
        for i in range(505):
            await db.execute("INSERT INTO alerts(user_id, ts, kind, severity, title) VALUES(?,?,?,?,?)",
                             u1, now, "resource", "info", "umplutură %d" % i)
        await alert_history.record("resource", "warning", "ultima", "", user_email=None)
        n1 = (await db.fetchone("SELECT COUNT(*) AS c FROM alerts WHERE user_id=?", u1))["c"]
        old = await db.fetchone("SELECT 1 FROM alerts WHERE title='foarte veche'")
        newest = await db.fetchone("SELECT title FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 1", u1)
        check("retenţie: cel mult 500 per cont, cea mai nouă păstrată",
              n1 == alert_history.KEEP_PER_USER and newest["title"] == "ultima", f"{n1} {dict(newest)}")
        check("retenţie: >30 zile şters", old is None)
        n2 = (await db.fetchone("SELECT COUNT(*) AS c FROM alerts WHERE user_id=?", u2))["c"]
        check("retenţia unui cont nu atinge rândurile altuia", 0 < n2 < 20, str(n2))

        # ── igienă ────────────────────────────────────────────────────────────────────────
        s = alert_history.scrub("upload to sftp://bob:hunter2@h/x failed; token=abc123 "
                                "Authorization: Bearer abcdefghijklmnop wt_ABCDEFGHIJKLMNOP "
                                "password: s3cret ?sig=zzz&x=1")
        check("scrub: credenţiale din URL, token=, Bearer, wt_, password:, ?sig= — toate ascunse",
              all(x not in s for x in ("hunter2", "abc123", "abcdefghijklmnop", "ABCDEFGHIJKLMNOP",
                                         "s3cret", "zzz")) and "sftp://bob:***@h" in s, s)
        email_alerts._last_sent.clear()
        email_alerts.notify_backup_failed("sftp", 2, 0, "auth failed for sftp://u:topsecret@b/ (token=deadbeef)")
        await _settle()
        bf = await _rows(u1, "backup_failed")
        check("alerta de backup eşuat ajunge în istoric fără secretele din mesajul de eroare",
              bf and "topsecret" not in bf[-1]["details"] and "deadbeef" not in bf[-1]["details"]
              and bf[-1]["severity"] == "critical", str([dict(x) for x in bf]))

        # ── API: autentificare ────────────────────────────────────────────────────────────
        for method, path in (("GET", "/api/alerts"), ("GET", "/api/alerts/unread"),
                             ("POST", "/api/alerts/read"), ("DELETE", "/api/alerts"),
                             ("GET", "/api/alerts/prefs"), ("POST", "/api/alerts/prefs")):
            r = await anon.request(method, path, json={"all": True} if method == "POST" else None)
            check(f"{method} {path} fără cookie → 401", r.status_code == 401, str(r.status_code))
        r = await a.post("/api/tokens", json={"name": "cron", "scopes": ["read"], "days": 30,
                                              "current_password": PW1})
        raw = r.json().get("token") if r.status_code == 200 else None
        check("token de automatizare creat (pentru testul de mai jos)", bool(raw), r.text[:120])
        if raw:
            r = await anon.get("/api/alerts", headers={"Authorization": "Bearer " + raw})
            check("token Bearer NU deschide istoricul (doar cookie)", r.status_code == 401, str(r.status_code))

        # ── API: listare, paginare, izolare ───────────────────────────────────────────────
        r = await b.get("/api/alerts?limit=2")
        j = r.json()
        ids = [x["id"] for x in j["alerts"]]
        check("listă: newest-first, limit respectat, next_before prezent",
              r.status_code == 200 and len(ids) == 2 and ids[0] > ids[1] and j["next_before"] == ids[1],
              str(j)[:200])
        r2 = (await b.get(f"/api/alerts?limit=2&before={j['next_before']}")).json()
        check("pagina a doua continuă sub cursor", all(x["id"] < ids[1] for x in r2["alerts"]), str(r2)[:200])
        mine = {x["id"] for x in (await b.get("/api/alerts?limit=200")).json()["alerts"]}
        theirs = {x["id"] for x in await db.fetchall("SELECT id FROM alerts WHERE user_id=?", u1)}
        check("contul 2 nu vede niciun rând al contului 1", mine and not (mine & theirs))
        check("câmpurile unui rând", set((await b.get("/api/alerts?limit=1")).json()["alerts"][0])
              == {"id", "ts", "kind", "severity", "title", "details", "host_id", "read"})

        unread_before = (await a.get("/api/alerts/unread")).json()["unread"]
        foreign = sorted(theirs)[-1]
        r = await b.post("/api/alerts/read", json={"ids": [foreign]})
        check("marcarea unui id STRĂIN nu-l atinge",
              r.status_code == 200 and (await a.get("/api/alerts/unread")).json()["unread"] == unread_before)
        one = sorted(mine)[-1]
        u2_before = (await b.get("/api/alerts/unread")).json()["unread"]
        r = await b.post("/api/alerts/read", json={"ids": [one]})
        check("marchează unul citit → necitite scade cu 1", r.json()["unread"] == u2_before - 1, r.text)
        r = await b.get("/api/alerts?unread=true&limit=200")
        check("filtrul unread exclude rândul citit", all(x["id"] != one for x in r.json()["alerts"]))
        r = await b.post("/api/alerts/read", json={})
        check("POST read fără ids/all → 400 cu cod", r.status_code == 400
              and r.headers.get("x-webterm-error") == "alerts.nothingToMark", r.text)
        r = await b.post("/api/alerts/read", json={"all": True})
        check("marchează toate → 0 necitite", r.json()["unread"] == 0, r.text)
        check("…doar la contul 2", (await a.get("/api/alerts/unread")).json()["unread"] == unread_before)

        r = await b.request("DELETE", "/api/alerts")
        check("clear → şterge doar ale mele",
              r.status_code == 200 and r.json()["cleared"] == len(mine)
              and (await b.get("/api/alerts")).json()["alerts"] == []
              and len(await _rows(u1)) == len(theirs), r.text)

        # ── API: prefs ────────────────────────────────────────────────────────────────────
        r = await a.get("/api/alerts/prefs")
        kinds = [p["kind"] for p in r.json()["prefs"]]
        check("prefs: toate tipurile vizibile, fără cel intern `system`",
              "new_login" in kinds and "host_offline" in kinds and "system" not in kinds, str(kinds))
        r = await a.post("/api/alerts/prefs", json={"prefs": {"nope": {"email": False}}})
        check("tip necunoscut → 400 alerts.unknownKind",
              r.status_code == 400 and r.headers.get("x-webterm-error") == "alerts.unknownKind", r.text)
        r = await a.post("/api/alerts/prefs", json={"prefs": {"system": {"email": False}}})
        check("tipul intern `system` nu se poate seta", r.status_code == 400, r.text)
        r = await a.post("/api/alerts/prefs", json={"prefs": {"resource": {"email": False, "inapp": False},
                                                              "new_login": {"email": False, "inapp": False}}})
        p = {x["kind"]: x for x in r.json()["prefs"]}
        check("POST prefs: non-securitate se opreşte complet, securitate doar emailul",
              p["resource"]["email"] is False and p["resource"]["inapp"] is False
              and p["new_login"]["email"] is False and p["new_login"]["inapp"] is True, str(p)[:300])
        p2 = {x["kind"]: x for x in (await b.get("/api/alerts/prefs")).json()["prefs"]}
        check("prefs sunt per cont (contul 2 nu le moşteneşte)", p2["resource"]["email"] is True)
        await a.post("/api/alerts/prefs", json={"prefs": {"resource": {"email": True, "inapp": True}}})
        row = await db.fetchone("SELECT 1 FROM alert_prefs WHERE user_id=? AND kind='resource'", u1)
        check("revenirea la implicit şterge rândul (tabela ţine doar abaterile)", row is None)

        # ── ştergerea contului ────────────────────────────────────────────────────────────
        await alert_history.record("resource", "info", "pentru doi", "")
        r = await a.post(f"/api/users/{u2}/delete", json={"current_password": PW1})
        check("cont 2 şters", r.status_code == 200, r.text[:120])
        left = await db.fetchone("SELECT COUNT(*) AS c FROM alerts WHERE user_id=?", u2)
        lp = await db.fetchone("SELECT COUNT(*) AS c FROM alert_prefs WHERE user_id=?", u2)
        check("…istoricul şi preferinţele lui au plecat odată cu el", left["c"] == 0 and lp["c"] == 0)

    # ── contractul cu UI-ul: fiecare tip vizibil are etichetă în ambele cataloage ─────────
    lang_dir = os.path.join(os.path.dirname(__file__), "..", "frontend", "src", "lang")
    for lang in ("en", "ro"):
        src = open(os.path.join(lang_dir, lang + ".ts"), encoding="utf-8").read()
        missing = [k for k, m in alert_history.KINDS.items()
                   if not m.get("hidden") and ("'alerts.kind.%s':" % k) not in src]
        groups = {m["group"] for m in alert_history.KINDS.values()}
        missing += [g for g in groups if ("'alerts.group.%s':" % g) not in src]
        check(f"{lang}.ts: etichete pentru toate tipurile şi grupurile", not missing, str(missing))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
