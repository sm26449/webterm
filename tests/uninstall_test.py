"""Dezinstalarea agentului de pe host — endpointul gateway (Faza gateway) — in-process ASGI.

Testează logica endpointului: agent offline → 409 (fără force) / 200 (cu force); agent online
(fake) → cere `uninstall` agentului + scoate din WebTerm. Curățenia REALĂ de pe host (systemd/
cron/tmux/fișiere) e integrare (agent real) — aici doar contractul gateway.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://localhost:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402
from app.main import app  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeAgent(core.AgentConnection):
    def __init__(self, host_id):
        self.host_id = host_id
        self.uninstalled = False

    async def request(self, op, **kw):
        if op == "uninstall":
            self.uninstalled = True
            return {"ok": True, "warnings": []}
        return {"ok": False}

    async def disconnect(self):
        pass


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": "parolabuna1",
                                         "setup_token": "test-setup"})

        # host de agent OFFLINE (fără sursă)
        r = await c.post("/api/hosts", json={"name": "off", "connection_type": "agent"})
        hid = r.json()["id"]
        core.sources.pop(hid, None)
        r = await c.post(f"/api/hosts/{hid}/uninstall")
        check("agent offline, fără force → 409", r.status_code == 409)
        r = await c.post(f"/api/hosts/{hid}/uninstall?force=1")
        check("agent offline, force=1 → 200 (scos din WebTerm)", r.status_code == 200)
        gone = await db.fetchone("SELECT id FROM hosts WHERE id=?", hid)
        check("host scos din DB după force", gone is None)

        # host de agent ONLINE (fake) → uninstall cere agentului + scoate
        r = await c.post("/api/hosts", json={"name": "on", "connection_type": "agent"})
        hid2 = r.json()["id"]
        fake = FakeAgent(hid2)
        core.sources[hid2] = fake
        r = await c.post(f"/api/hosts/{hid2}/uninstall")
        js = r.json()
        check("agent online → 200 uninstalled True", r.status_code == 200 and js.get("uninstalled") is True)
        check("agentului i s-a cerut uninstall", fake.uninstalled is True)
        check("host scos din DB", await db.fetchone("SELECT id FROM hosts WHERE id=?", hid2) is None)
        check("sursa scoasă din core.sources", core.sources.get(hid2) is None)

        # host cu sesiune activă → refuzat
        r = await c.post("/api/hosts", json={"name": "busy", "connection_type": "agent"})
        hid3 = r.json()["id"]
        await db.execute(
            "INSERT INTO sessions(id, host_id, title, state, created, rows, cols)"
            " VALUES(?,?,?,?,?,?,?)", "aa" * 16, hid3, "s", "live", 0.0, 24, 80)
        r = await c.post(f"/api/hosts/{hid3}/uninstall?force=1")
        check("host cu sesiune activă → 409", r.status_code == 409)

    await db.close()
    print(f"\n{ok}/{total} passed")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
