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

    # ── alerte: host căzut / revenit, o singură dată per tranziţie ──
    sent = []
    orig_fire = email_alerts._fire
    email_alerts._fire = lambda subject, body: sent.append(subject)
    email_alerts._offline_since.clear()
    try:
        await db.execute("UPDATE hosts SET last_heartbeat=? WHERE id=?",
                         time.time() - config.HEARTBEAT_STALE - 10, hid)
        await core.sweep_hosts_offline()
        await core.sweep_hosts_offline()          # a doua tură: nu re-alertează
        check("host tăcut → o singură alertă", sum("offline" in s for s in sent) == 1, str(sent))
        await db.execute("UPDATE hosts SET last_heartbeat=? WHERE id=?", time.time(), hid)
        await core.sweep_hosts_offline()
        await core.sweep_hosts_offline()
        check("host revenit → o singură alertă de revenire",
              sum("back online" in s for s in sent) == 1, str(sent))
        sent.clear()
        await db.execute("UPDATE hosts SET last_heartbeat=0 WHERE id=?", hid)
        await core.sweep_hosts_offline()
        check("host care n-a raportat NICIODATĂ nu declanşează alertă (nu e o cădere)",
              sent == [], str(sent))
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

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
