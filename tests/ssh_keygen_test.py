"""Helpers pentru chei SSH pe hosturile directe: generează o pereche Ed25519 (stochează privata
criptat, întoarce publica o dată) şi derivă publica din privata stocată. Scuteşte userul de
ssh-keygen. Rulează in-process prin ASGI."""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, security  # noqa: E402

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

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW, "setup_token": "test-setup"})

        # host SSH (cu parolă iniţial) + un host agent (pt. cazul negativ)
        r = await c.post("/api/hosts", json={"name": "ssh-box", "connection_type": "ssh",
                         "hostname": "10.0.0.5", "ssh_username": "root", "auth_method": "password",
                         "credential": "parola-ssh"})
        sid = r.json()["id"]
        r = await c.post("/api/hosts", json={"name": "agent-box", "connection_type": "agent"})
        aid = r.json()["id"]

        # generare cheie: întoarce o cheie publică ed25519 + amprentă
        r = await c.post("/api/hosts/%d/ssh-key/generate" % sid, json={})
        check("generate → 200", r.status_code == 200, r.text[:150])
        pub = r.json().get("public_key", "")
        check("cheie publică ed25519 întoarsă", pub.startswith("ssh-ed25519 AAAA"), pub[:40])
        check("amprentă SHA256 întoarsă", r.json().get("fingerprint", "").startswith("SHA256:"))

        # derivarea publicului din privata stocată dă ACEEAŞI cheie
        r2 = await c.post("/api/hosts/%d/ssh-key/public" % sid, json={})
        check("public → 200", r2.status_code == 200, r2.text[:150])
        check("publicul derivat == publicul generat", r2.json().get("public_key") == pub)

        # generare pe un host AGENT → refuz (nu are sens)
        r = await c.post("/api/hosts/%d/ssh-key/generate" % aid, json={})
        check("generate pe host agent → 400", r.status_code == 400, str(r.status_code))

        # host SSH cu PAROLĂ (nu cheie): /public refuză (nu e cheie privată)
        r = await c.post("/api/hosts", json={"name": "ssh-pw", "connection_type": "ssh",
                         "hostname": "10.0.0.6", "ssh_username": "root", "auth_method": "password",
                         "credential": "doar-parola"})
        pwid = r.json()["id"]
        r = await c.post("/api/hosts/%d/ssh-key/public" % pwid, json={})
        check("public pe host cu parolă → 400", r.status_code == 400, str(r.status_code))

    await db.close()
    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
