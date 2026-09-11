"""Onboarding la scară de flotă: un token de înrolare DE GRUP. Un one-liner rulat pe N maşini;
fiecare `/install/group/<token>` AUTO-CREEAZĂ un host nou cu PROPRIUL token permanent (revocabil
individual — modelul per-host nu se erodează). Tokenul de grup doar autorizează crearea: opt-in,
expiră, revocabil, plafon de utilizări (atomic, TOCTOU-safe), auto-enroll auditat + alertat.
Rulează in-process prin ASGI, fără reţea."""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, audit, config, db, email_alerts, security  # noqa: E402

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

    enrolled = []
    email_alerts.notify_host_enrolled = lambda group, ip: enrolled.append(group)
    email_alerts.notify_security_change = lambda what, ip, email: None

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "admin@x.co", "password": PW,
                                             "setup_token": "test-setup"})
        check("setup cont", r.status_code == 200)

        # creare token de grup (acelaşi device ⇒ second_gate trece cu parola), plafon 2, folder + 2FA
        r = await c.post("/api/enroll-groups", json={"name": "prod-rollout", "days": 7,
                         "max_uses": 2, "folder": "prod", "require_2fa": True,
                         "current_password": PW})
        check("token de grup creat", r.status_code == 200, r.text[:150])
        raw = r.json()["token"]
        check("valoarea tokenului se întoarce o dată", bool(raw) and "token" in r.json())
        check("one-liner de grup întors", "/install/group/" in r.json()["install_command"])

        # două instalări → două hosturi auto-create, fiecare cu token PROPRIU (scripturi diferite)
        r1 = await c.get("/install/group/%s.sh" % raw)
        r2 = await c.get("/install/group/%s.sh" % raw)
        check("prima instalare de grup → 200", r1.status_code == 200)
        check("a doua instalare de grup → 200", r2.status_code == 200)
        check("scripturile conţin un token de agent", "TOKEN=" in r1.text and "TOKEN=" in r2.text)
        check("fiecare maşină primeşte un token DIFERIT (revocabil individual)", r1.text != r2.text)

        # plafonul de utilizări e respectat ATOMIC: a treia instalare e refuzată
        r3 = await c.get("/install/group/%s.sh" % raw)
        check("a treia instalare peste plafon → 404", r3.status_code == 404, str(r3.status_code))

        # hosturile auto-create: placeholder de nume, în folderul grupului, cu 2FA moştenit
        hosts = (await c.get("/api/hosts")).json()
        auto = [h for h in hosts if h["name"] == "(enrolling…)"]
        check("două hosturi auto-create", len(auto) == 2, str([h["name"] for h in hosts]))
        check("hosturile moştenesc folderul grupului", all(h["folder"] == "prod" for h in auto))
        check("hosturile moştenesc require_2fa", all(h["require_2fa"] for h in auto))

        # fiecare auto-enroll e alertat + auditat
        check("auto-enroll → alertă", len(enrolled) == 2, str(enrolled))
        arows = [e for e in await audit.recent(limit=200) if e["path"] == "/install/group"]
        check("auto-enroll auditat (actor = group:<nume>)",
              len(arows) == 2 and all(e["actor"] == "group:prod-rollout" for e in arows))

        # revocarea opreşte înrolări noi (chiar sub plafon nou n-ar conta — e revocat)
        gid = r.json()["groups"][0]["id"]
        # (mai întâi golim plafonul creând un grup nou nelimitat ca să testăm strict revocarea)
        r = await c.post("/api/enroll-groups", json={"name": "temp", "days": 7, "max_uses": 0,
                         "current_password": PW})
        raw2 = r.json()["token"]
        gid2 = [g for g in r.json()["groups"] if g["name"] == "temp"][0]["id"]
        check("grup nelimitat: instalare merge înainte de revocare",
              (await c.get("/install/group/%s.sh" % raw2)).status_code == 200)
        await c.post("/api/enroll-groups/%d/revoke" % gid2)
        check("după revocare → 404", (await c.get("/install/group/%s.sh" % raw2)).status_code == 404)
        groups = (await c.get("/api/enroll-groups")).json()
        check("grupul revocat apare ca revoked (fără secret)",
              any(g["id"] == gid2 and g["revoked"] and "token" not in g for g in groups))
        _ = gid

        # token de grup invalid → 404 (fără scurgere)
        check("token de grup inexistent → 404",
              (await c.get("/install/group/inexistent.sh")).status_code == 404)

    await db.close()
    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
