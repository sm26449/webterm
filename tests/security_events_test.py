"""Evenimentele de securitate RARE + CRITICE ajung pe canalul de alertă (email + webhook via
`_fire`): cont nou (un admin egal în plus), token de automatizare nou, şi deblocarea (step-up) a
unui host marcat `require_2fa`. Restul (login device nou, schimbări de credenţiale, host offline…)
erau deja acoperite; astea trei erau golul. Rulează in-process prin ASGI, fără reţea."""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, email_alerts, security  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

PW = "parola-cont-123456"
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    # capturăm notificările (fără email/webhook real)
    changes, unlocks = [], []
    email_alerts.notify_security_change = lambda what, ip, email: changes.append(what)
    email_alerts.notify_host_unlocked = lambda host, ip, email: unlocks.append(host)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "admin@x.co", "password": PW,
                                             "setup_token": "test-setup"})
        check("setup cont", r.status_code == 200)

        # 1. cont nou (acelaşi device ⇒ second_gate trece cu parola) → notify_security_change
        r = await c.post("/api/users", json={"email": "doi@x.co", "password": PW,
                                             "current_password": PW})
        check("cont nou creat", r.status_code == 200, r.text[:120])
        check("cont nou → alertă de securitate",
              any("account" in w for w in changes), str(changes))

        # 2. token de automatizare → notify_security_change
        n_before = len(changes)
        r = await c.post("/api/tokens", json={"name": "ci", "scopes": ["read"], "days": 30,
                                              "current_password": PW})
        check("token creat", r.status_code == 200, r.text[:120])
        check("token nou → alertă de securitate",
              any("token" in w for w in changes[n_before:]), str(changes[n_before:]))

        # 3. host cu require_2fa → step-up cu parola deschide fereastra → notify_host_unlocked
        r = await c.post("/api/hosts", json={"name": "prod-secret", "connection_type": "agent",
                                             "require_2fa": True})
        check("host 2FA creat", r.status_code == 200, r.text[:120])
        hid = r.json()["id"]
        r = await c.post("/api/hosts/%d/stepup" % hid, json={"stepup_password": PW})
        check("step-up cu parola reuşeşte", r.status_code == 200, r.text[:120])
        check("host 2FA deblocat → alertă (host protejat accesat)",
              "prod-secret" in unlocks, str(unlocks))

        # 4. re-apel idempotent cât fereastra e deschisă NU mai alertează (fără zgomot)
        n_unlocks = len(unlocks)
        await c.post("/api/hosts/%d/stepup" % hid, json={"stepup_password": PW})
        check("re-step-up în fereastră NU re-alertează", len(unlocks) == n_unlocks)

    await db.close()
    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
