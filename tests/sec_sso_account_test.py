"""fix 7 — un cont SSO îşi poate schimba emailul: parola locală e un hash aleator, deci
`current_password` NU poate trece niciodată. Acceptăm în loc re-auth-ul real al contului SSO:
un grant passkey account-scope (host_id=0) SAU o fereastră OIDC proaspătă account-scope (host_id=0).
Un cont local NEschimbat continuă să ceară parola. Hermetic, in-process prin ASGI."""
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
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "owner@b.co", "password": "parolabuna1",
                                         "setup_token": "test-setup"})

    # cont SSO: parola locală = hash pe un secret aleator (ca în oidc_api.callback)
    locked = await security.hash_password_async(security.new_token())
    await db.execute("INSERT INTO users(email, password_hash, created, sso_subject) VALUES(?,?,?,?)",
                     "sso@b.co", locked, time.time(), "idp-subject-123")
    sso = await db.fetchone("SELECT id FROM users WHERE email='sso@b.co'")
    sso_uid = sso["id"]
    token = await security.create_web_session(sso_uid, "test-agent", False)
    HSSO = {**_ORIGIN, "cookie": "%s=%s" % (security.COOKIE_NAME, token)}

    saved_oidc = config.OIDC_ENABLED
    config.OIDC_ENABLED = True   # ramura SSO din update_account cere OIDC activ
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            # fără re-auth (doar „parola", imposibilă pt. SSO) → 403 account.ssoReauth
            security.clear_stepup_for(sso_uid)
            r = await c.post("/api/account", json={"current_password": "orice", "email": "nou@b.co"},
                             headers=HSSO)
            check("SSO: parola singură e refuzată (403 account.ssoReauth)",
                  r.status_code == 403 and r.json().get("code") == "account.ssoReauth", r.text[:160])

            # fereastră OIDC proaspătă account-scope (host_id=0, deschisă de callback intent=stepup) → OK
            security.open_stepup_window(sso_uid, 0)
            r = await c.post("/api/account", json={"current_password": "", "email": "nou@b.co"},
                             headers=HSSO)
            check("SSO: fereastră re-auth OIDC account-scope → schimbarea reuşeşte",
                  r.status_code == 200 and r.json().get("email") == "nou@b.co", r.text[:160])

            # grant passkey account-scope (host_id=0, din /webauthn/stepup/verify cu host_id=0) → OK
            security.clear_stepup_for(sso_uid)
            grant = security.issue_stepup_grant(sso_uid, 0)
            r = await c.post("/api/account",
                             json={"current_password": "", "email": "nou2@b.co", "stepup_grant": grant},
                             headers=HSSO)
            check("SSO: grant passkey account-scope → schimbarea reuşeşte",
                  r.status_code == 200 and r.json().get("email") == "nou2@b.co", r.text[:160])
            check("grant-ul account-scope e single-use",
                  not security.consume_stepup_grant(grant, sso_uid, 0))

        # un cont LOCAL (ne-SSO) continuă să ceară parola, neschimbat
        async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
            r = await c.post("/api/login", json={"email": "owner@b.co", "password": "parolabuna1"})
            check("owner local logat", r.status_code == 200, r.text[:120])
            r = await c.post("/api/account", json={"current_password": "gresit", "email": "o2@b.co"})
            check("cont local: parola greşită → 401 (comportament neschimbat)",
                  r.status_code == 401, str(r.status_code))
            r = await c.post("/api/account", json={"current_password": "parolabuna1", "email": "o2@b.co"})
            check("cont local: parola corectă → 200", r.status_code == 200, r.text[:160])
    finally:
        config.OIDC_ENABLED = saved_oidc

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
