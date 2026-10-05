"""fix 9 (plafon pe corpul de login) + fix 10 (default conservator trusted-proxy) — hermetice."""
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

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


async def main():
    # ── fix 10 (unit): _peer_is_trusted — default fail-closed vs CIDR explicit ──
    saved = config.TRUSTED_PROXY_CIDRS
    try:
        config.TRUSTED_PROXY_CIDRS = []
        check("default (fără CIDR): peer privat NU e crezut", not security._peer_is_trusted("10.0.0.5"))
        check("default (fără CIDR): loopback NU e crezut", not security._peer_is_trusted("127.0.0.1"))
        config.TRUSTED_PROXY_CIDRS = ["172.18.0.0/16", "10.0.0.0/8"]
        check("CIDR configurat: peer din interval → crezut", security._peer_is_trusted("172.18.0.9"))
        check("CIDR configurat: alt peer privat din afara intervalului → NU", not security._peer_is_trusted("192.168.1.1"))
        check("CIDR configurat: peer public → NU", not security._peer_is_trusted("8.8.8.8"))
        config.TRUSTED_PROXY_CIDRS = ["nu-e-un-cidr"]
        check("CIDR invalid → fail-closed (nu crede pe nimeni)", not security._peer_is_trusted("172.18.0.9"))
    finally:
        config.TRUSTED_PROXY_CIDRS = saved

    # ── fix 9: plafon pe corpul de login ÎNAINTE de parse / argon2 ──
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": "parolabuna1",
                                         "setup_token": "test-setup"})
        big = b'{"email":"a@b.co","password":"' + b"x" * (5 * 1024 * 1024) + b'"}'
        r = await c.post("/api/login", content=big,
                         headers={**_ORIGIN, "content-type": "application/json"})
        check("corp de login de 5 MB → 413 (plafonat înainte de parse)",
              r.status_code == 413, str(r.status_code))
        # calea normală rămâne funcţională
        r = await c.post("/api/login", json={"email": "a@b.co", "password": "parolabuna1"})
        check("login normal cu parola corectă → 200", r.status_code == 200, r.text[:120])
        r = await c.post("/api/login", json={"email": "a@b.co", "password": "gresit"})
        check("login cu parola greşită → 401 (nu 413/422)", r.status_code == 401, str(r.status_code))
        r = await c.post("/api/login", content=b"nu-e-json{",
                         headers={**_ORIGIN, "content-type": "application/json"})
        check("corp invalid (nu JSON) → 400 (nu 500)", r.status_code == 400, str(r.status_code))
    await db.close()

    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
