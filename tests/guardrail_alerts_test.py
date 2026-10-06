"""Guardrail aplicat server-side pe `/run` + alertele noi (host căzut/revenit, webhook).

Ambele vin din auditul extern din 2026-08-06:
- guardrail-ul era verificat DOAR în browser, la Enter; cine ocolea UI-ul ocolea regula.
  Pe tastarea directă în PTY aşa rămâne (nu inspectăm fluxul de taste) — dar `/run` e un
  punct de strangulare şi acolo se poate aplica;
- lipsea alerta pentru evenimentul cel mai banal dintr-o flotă: „agentul a tăcut".
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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, email_alerts, security  # noqa: E402

# Middleware-ul `csrf_guard` cere `Origin` pe metodele care schimbă ceva şi refuză
# lipsa lui (ca `_origin_ok` pentru WebSocket). Testele imită un BROWSER, deci trimit
# antetul; fără el ar testa o cale pe care niciun browser n-o produce.
_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    # ── guardrail: potrivirea de reguli, server-side ──
    await db.execute("INSERT INTO app_settings(key, value) VALUES('command_guard', ?)",
                     json.dumps({"enabled": True, "rules": [
                         {"pattern": r"rm\s+-rf\s+/", "action": "block"},
                         {"pattern": r"^reboot\b", "action": "confirm"}]}))
    check("regula `block` se potriveşte",
          (await api._match_guard_rule("rm -rf /var"))["action"] == "block")
    check("regula `confirm` se potriveşte",
          (await api._match_guard_rule("reboot now"))["action"] == "confirm")
    check("comandă inofensivă → nicio regulă", await api._match_guard_rule("ls -la") is None)
    # 3.5.1: un `confirm` larg DEASUPRA unui `block` nu mai face blocarea ocolibilă cu confirmed:true
    await db.execute("UPDATE app_settings SET value=? WHERE key='command_guard'",
                     json.dumps({"enabled": True, "rules": [
                         {"pattern": r"^rm\b", "action": "confirm"},
                         {"pattern": r"rm\s+-rf\s+/", "action": "block"}]}))
    check("`block` câştigă chiar dacă un `confirm` e mai sus în listă",
          (await api._match_guard_rule("rm -rf /"))["action"] == "block")
    check("…iar `confirm` se aplică în rest", (await api._match_guard_rule("rm x"))["action"] == "confirm")
    await db.execute("UPDATE app_settings SET value=? WHERE key='command_guard'",
                     json.dumps({"enabled": False, "rules": [
                         {"pattern": r"rm\s+-rf\s+/", "action": "block"}]}))
    check("guardrail dezactivat → nu blochează nimic",
          await api._match_guard_rule("rm -rf /") is None)
    await db.execute("UPDATE app_settings SET value=? WHERE key='command_guard'",
                     json.dumps({"enabled": True, "rules": [
                         {"pattern": "[nevalid(", "action": "block"},
                         {"pattern": r"mkfs", "action": "block"}]}))
    check("regex invalid e sărit, nu opreşte evaluarea",
          (await api._match_guard_rule("mkfs.ext4 /dev/sda"))["action"] == "block")

    # ── F-09: bugetul de timp per regulă chiar limitează ──
    # Cazul auditului (2026-10-04): `^(a+)+$` pe "a"*28+"!" (backtracking catastrofal).
    # Măsurat în .venv (Python 3.12.3), aceeaşi maşină:
    #   ÎNAINTE — `wait_for(to_thread(re.search…), 0.25)`: revenea după 12,92 s (firul nu poate
    #             fi întrerupt; `wait_for` îl aşteaptă), cu un thread din pool-ul implicit ocupat;
    #   DUPĂ    — worker separat omorât la buget: 0,31 s cap-coadă (0,25 buget + ~30 ms pornirea
    #             worker-ului nou pentru regula următoare + rândul de audit); la salvare 0,29 s.
    await db.execute("UPDATE app_settings SET value=? WHERE key='command_guard'",
                     json.dumps({"enabled": True, "rules": [
                         {"pattern": r"^(a+)+$", "action": "block"},
                         {"pattern": r"a+!$", "action": "confirm"}]}))
    t0 = time.monotonic()
    hit = await api._match_guard_rule("a" * 28 + "!")
    dt = time.monotonic() - t0
    check("regulă patologică: revine în buget (%.2fs < 1.5s), nu după ~13 s" % dt, dt < 1.5)
    check("…regula patologică e SĂRITĂ, iar următoarea se potriveşte (worker refăcut)",
          hit is not None and hit["action"] == "confirm", str(hit))
    row = await db.fetchone("SELECT count(*) n FROM audit_log WHERE actor='system:guardrail'")
    check("…şi lasă urmă în jurnalul de audit, cu regula numită", row["n"] >= 1)
    check("worker-ul nu rămâne viu între cereri", security._re_worker is None)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": "parolabuna1",
                                         "setup_token": "test-setup"})
        r = await c.post("/api/hosts", json={"name": "h"})
        hid = r.json()["id"]
        await db.execute("UPDATE app_settings SET value=? WHERE key='command_guard'",
                         json.dumps({"enabled": True, "rules": [
                             {"pattern": r"rm\s+-rf\s+/", "action": "block"},
                             {"pattern": r"^reboot\b", "action": "confirm"}]}))
        r = await c.post(f"/api/hosts/{hid}/run", json={"command": "rm -rf /"})
        check("/run: comanda blocată → 403 (nu mai depinde de browser)", r.status_code == 403)
        r = await c.post(f"/api/hosts/{hid}/run", json={"command": "reboot", "confirmed": False})
        check("/run: comanda de confirmat, fără confirmare → 409", r.status_code == 409)
        # atenţie: „host offline" întoarce TOT 409, deci distingem după mesaj, nu după cod
        r = await c.post(f"/api/hosts/{hid}/run", json={"command": "reboot", "confirmed": True})
        check("/run: cu confirmare explicită trece de guardrail (cade abia la host offline)",
              "guardrail" not in r.text, r.text[:80])
        r = await c.post(f"/api/hosts/{hid}/run", json={"command": "uptime"})
        check("/run: comandă inofensivă neatinsă de guardrail",
              "guardrail" not in r.text, r.text[:80])

        # F-09, bariera de la SALVARE: regula patologică e refuzată cu 400 (fuzz cu acelaşi buget);
        # regulile implicite şi una polinomială (`.*.*=`) trec — bugetul nu respinge regex-uri reale.
        t0 = time.monotonic()
        r = await c.post("/api/settings/command-guard", json={"enabled": True, "rules": [
            {"pattern": r"^(a+)+$", "action": "block"}]})
        check("save: regulă cu backtracking catastrofal → 400 (%.2fs)" % (time.monotonic() - t0),
              r.status_code == 400 and "too slow" in r.text, f"{r.status_code} {r.text[:80]}")
        r = await c.post("/api/settings/command-guard", json={
            "enabled": True, "rules": api.COMMAND_GUARD_DEFAULT["rules"]
            + [{"pattern": r".*.*=.*", "action": "confirm"}]})
        check("save: regulile implicite + una polinomială trec (200)", r.status_code == 200, r.text[:80])
        r = await c.post("/api/settings/command-guard", json={"enabled": True, "rules": [
            {"pattern": "[nevalid(", "action": "block"}]})
        check("save: regex invalid → tot 400", r.status_code == 400)

    # ── alerte: host căzut / revenit, o singură dată per tranziţie ──
    sent = []
    orig_fire = email_alerts._fire
    email_alerts._fire = lambda subject, body: sent.append(subject)
    # dedup-ul trăieşte acum în DB (hosts.offline_notified), nu în RAM: îl resetăm între cazuri
    await db.execute("UPDATE hosts SET offline_notified=0, alerts_muted=0 WHERE id=?", hid)
    try:
        await db.execute("UPDATE hosts SET last_heartbeat=? WHERE id=?",
                         time.time() - config.HEARTBEAT_STALE - 10, hid)
        await core.sweep_hosts_offline()
        await core.sweep_hosts_offline()          # a doua tură: nu re-alertează (offline_notified persistat)
        check("host tăcut → o singură alertă", sum("offline" in s for s in sent) == 1, str(sent))
        await db.execute("UPDATE hosts SET last_heartbeat=? WHERE id=?", time.time(), hid)
        await core.sweep_hosts_offline()
        await core.sweep_hosts_offline()
        check("host revenit → o singură alertă de revenire",
              sum("back online" in s for s in sent) == 1, str(sent))

        # ── toggle per-host: alertele oprite (alerts_muted) tac complet ──
        sent.clear()
        await db.execute("UPDATE hosts SET last_heartbeat=?, alerts_muted=1, offline_notified=0 WHERE id=?",
                         time.time() - config.HEARTBEAT_STALE - 10, hid)
        await core.sweep_hosts_offline()
        await core.sweep_hosts_offline()
        check("host offline cu alertele oprite → nicio alertă", sent == [], str(sent))
        await db.execute("UPDATE hosts SET alerts_muted=0, offline_notified=0 WHERE id=?", hid)

        sent.clear()
        await db.execute("UPDATE hosts SET last_heartbeat=0 WHERE id=?", hid)
        await core.sweep_hosts_offline()
        check("host care n-a raportat NICIODATĂ nu declanşează alertă (nu e o cădere)",
              sent == [], str(sent))

        # ── audit de securitate 2026-08: un marcaj de uninstall NU suprimă alerta ──
        # (un atacator cu shell l-ar posta şi apoi ar omorî agentul ca să tacă detecţia).
        # Alerta se declanşează ORICUM; doar textul se adaptează.
        sent.clear()
        await db.execute("UPDATE hosts SET offline_notified=0, alerts_muted=0 WHERE id=?", hid)
        gone = time.time() - config.HEARTBEAT_STALE - 10
        await db.execute("UPDATE hosts SET last_heartbeat=?, uninstalled_at=? WHERE id=?",
                         gone, gone, hid)
        await core.sweep_hosts_offline()
        check("host tăcut cu marcaj de uninstall: TOT alertează (fără tăcere cumpărabilă)",
              sum("offline" in s for s in sent) == 1, str(sent))
        check("…iar textul e cel adaptat pentru uninstall, nu incidentul obişnuit",
              any("uninstall report" in s for s in sent), str(sent))
        await db.execute("UPDATE hosts SET uninstalled_at=NULL WHERE id=?", hid)
    finally:
        email_alerts._fire = orig_fire

    # ── webhook: independent de SMTP, payload compatibil Slack/Discord ──
    cfg = await email_alerts.load_config()
    check("webhook citit din config (gol implicit)", "webhook" in cfg)
    posted = {}
    orig_post = email_alerts._post_webhook
    email_alerts._post_webhook = lambda url, s, b: posted.update(url=url, subject=s, body=b)
    try:
        await db.execute("INSERT INTO app_settings(key, value) VALUES('alert_webhook', ?)",
                         "https://hooks.example.com/x")
        cfg = await email_alerts.load_config()
        check("webhook din DB are prioritate", cfg["webhook"] == "https://hooks.example.com/x")
        email_alerts._fire("Test", "corp")
        await asyncio.sleep(0.05)
        check("alerta pleacă pe webhook chiar fără SMTP configurat",
              posted.get("subject") == "Test", str(posted))
    finally:
        email_alerts._post_webhook = orig_post

    # ── starea livrării (UX §7): ultimul email trimis / eşuat e PERSISTAT, nu doar logat ──
    for k, v in (("smtp_host", "smtp.example.com"), ("smtp_to", "ops@example.com"),
                 ("smtp_from", "wt@example.com")):
        await db.execute("INSERT INTO app_settings(key, value) VALUES(?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, v)
    orig_send = email_alerts._send_blocking

    def _refused(cfg, subject, body):
        raise ConnectionRefusedError("connection refused")
    email_alerts._send_blocking = _refused
    try:
        email_alerts._fire("Alertă care pică", "corp")
        await asyncio.sleep(0.1)
        st = await email_alerts.alert_status()
        f = st["alert_email_last_failed"]
        check("email eşuat → alert_email_last_sent gol, last_failed cu subiect + eroare",
              st["alert_email_last_sent"] is None and f and f["subject"] == "Alertă care pică"
              and "refused" in f["error"], str(st))
        email_alerts._send_blocking = lambda cfg, subject, body: None
        email_alerts._fire("Alertă care merge", "corp")
        await asyncio.sleep(0.1)
        st = await email_alerts.alert_status()
        s_ = st["alert_email_last_sent"]
        check("email trimis → alert_email_last_sent cu subiect + ts, eşecul vechi rămâne istoric",
              s_ and s_["subject"] == "Alertă care merge" and s_["ts"] > f["ts"]
              and st["alert_email_last_failed"]["ts"] == f["ts"], str(st))
    finally:
        email_alerts._send_blocking = orig_send

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
