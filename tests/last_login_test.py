"""Ultima autentificare a fiecărui cont (3.6.10, Settings → Users & roles → Accounts).

Ce se verifică, pe căile REALE de login (nu doar pe funcţia care ştampilează):
  * parolă locală → `password`; parolă + TOTP → `password_2fa`; passkey → `passkey`;
    SSO (callback-ul OIDC real, cu IdP fals ca în rbac_oidc_test) → `sso`; setup → `password`;
  * un login EŞUAT (parolă greşită) nu ştampilează nimic;
  * o sesiune creată fără metodă (intern / teste) nu se dă drept autentificare;
  * GET /api/users: `last_login` + `last_login_method` + `last_login_tracked_since` doar cu
    `users.manage`; un cont fără el (îşi vede doar propriul rând) nu le primeşte deloc;
  * migrarea: coloanele există, `last_login_since` e scris o singură dată (re-boot nu-l mută).
"""
import asyncio
import os
import time

os.environ["WEBTERM_OIDC_ISSUER"] = "http://127.0.0.1:9"
os.environ["WEBTERM_OIDC_CLIENT_ID"] = "wt-client"
os.environ["WEBTERM_OIDC_CLIENT_SECRET"] = "wt-secret"
os.environ.pop("WEBTERM_OIDC_ALLOWED_GROUPS", None)

import rbac_util as U  # noqa: E402
from app import db, oidc, oidc_api, security, webauthn_api  # noqa: E402

check = U.Checker()
PW = "parolabuna1"


async def stamp(email):
    r = await db.fetchone("SELECT last_login, last_login_method FROM users WHERE email=?", email)
    return (r["last_login"], r["last_login_method"]) if r else (None, None)


async def password_login(email, pw, totp=""):
    c = U.client()
    body = {"email": email, "password": pw}
    if totp:
        body["totp_code"] = totp
    r = await c.post("/api/login", json=body)
    await c.aclose()
    return r


def idp(sub, email):
    def complete(state, code):
        return {"sub": sub, "email": email, "email_verified": True, "groups": set(),
                "groups_present": False, "groups_readable": True, "intent": "login",
                "host_id": None}
    oidc.complete = complete


class _Verified:
    new_sign_count = 3


async def main():
    await U.boot()
    t0 = time.time()
    owner = await U.owner_client()
    s = await stamp(U.OWNER_EMAIL)
    check("setup: primul cont e ştampilat (password)", s[1] == "password" and s[0] >= t0 - 1, str(s))
    since = (await db.fetchone("SELECT value FROM app_settings WHERE key='last_login_since'"))
    check("migrarea: last_login_since scris la boot", since is not None and since["value"].isdigit(),
          str(since and since["value"]))

    # ── parolă locală ────────────────────────────────────────────────────────────────────
    await U.add_user("ana@x.co", PW, bindings=[("viewer", "all", "")])
    check("cont nou: nicio ştampilă", await stamp("ana@x.co") == (None, None))
    r = await password_login("ana@x.co", "gresita-total")
    check("login eşuat → 401", r.status_code == 401, r.text[:120])
    check("…şi nu ştampilează nimic", await stamp("ana@x.co") == (None, None))
    r = await password_login("ana@x.co", PW)
    s = await stamp("ana@x.co")
    check("login cu parola → password", r.status_code == 200 and s[1] == "password", "%s %s" % (r.text[:80], s))

    # ── parolă + al doilea factor ───────────────────────────────────────────────────────
    await U.add_user("dan@x.co", PW)
    await db.execute("UPDATE users SET totp_enabled=1 WHERE email='dan@x.co'")
    orig = security.verify_second_factor

    async def ok_factor(user, code):
        return code == "123456"
    security.verify_second_factor = ok_factor
    try:
        r = await password_login("dan@x.co", PW)
        check("parolă fără cod (2FA activ) → cere codul, nicio ştampilă",
              r.json().get("totp_required") is True and await stamp("dan@x.co") == (None, None),
              r.text[:120])
        r = await password_login("dan@x.co", PW, totp="123456")
        s = await stamp("dan@x.co")
        check("parolă + cod → password_2fa", r.status_code == 200 and s[1] == "password_2fa",
              "%s %s" % (r.text[:80], s))
    finally:
        security.verify_second_factor = orig

    # ── passkey ──────────────────────────────────────────────────────────────────────────
    import base64
    uid = await U.add_user("pk@x.co", PW)
    await db.execute("INSERT INTO webauthn_credentials(user_id, credential_id, public_key,"
                     " sign_count, name, created) VALUES(?,?,?,0,'k',?)", uid, b"cred-pk", b"pk",
                     time.time())
    orig_v, orig_c = webauthn_api.verify_authentication_response, webauthn_api._consume
    webauthn_api.verify_authentication_response = lambda **kw: _Verified()
    webauthn_api._consume = lambda cred: b"challenge"
    try:
        raw = base64.urlsafe_b64encode(b"cred-pk").rstrip(b"=").decode()
        c = U.client()
        r = await c.post("/api/webauthn/login/verify", json={"credential": {"rawId": raw, "id": raw}})
        await c.aclose()
        s = await stamp("pk@x.co")
        check("login cu passkey → passkey", r.status_code == 200 and s[1] == "passkey",
              "%s %s" % (r.text[:120], s))
    finally:
        webauthn_api.verify_authentication_response, webauthn_api._consume = orig_v, orig_c

    # ── SSO (callback OIDC real) ────────────────────────────────────────────────────────
    idp("sub-ll-1", "sso@x.co")
    c = U.client()
    r = await c.get("/api/oidc/callback", params={"code": "c", "state": "s"},
                    cookies={oidc_api.STATE_COOKIE: "s"}, follow_redirects=False)
    await c.aclose()
    s = await stamp("sso@x.co")
    check("login SSO (cont provizionat) → sso", r.status_code == 303 and s[1] == "sso",
          "%s %s %s" % (r.status_code, r.headers.get("location"), s))
    before = s[0]
    await asyncio.sleep(0.01)
    c = U.client()
    await c.get("/api/oidc/callback", params={"code": "c", "state": "s"},
                cookies={oidc_api.STATE_COOKIE: "s"}, follow_redirects=False)
    await c.aclose()
    check("al doilea login SSO mută ştampila înainte", (await stamp("sso@x.co"))[0] > before)

    # ── o sesiune fără metodă nu e o autentificare ──────────────────────────────────────
    await U.add_user("quiet@x.co", PW)
    qc = await U.login("quiet@x.co")       # create_web_session fără `method`
    check("sesiune internă (fără metodă): nicio ştampilă", await stamp("quiet@x.co") == (None, None))
    await qc.aclose()

    # ── cine vede ───────────────────────────────────────────────────────────────────────
    r = await owner.get("/api/users")
    rows = {u["email"]: u for u in r.json()}
    check("users.manage: last_login + metoda în listă",
          rows["ana@x.co"].get("last_login_method") == "password"
          and isinstance(rows["ana@x.co"].get("last_login"), float)
          and rows["pk@x.co"].get("last_login_method") == "passkey"
          and rows["sso@x.co"].get("last_login_method") == "sso", str(rows["ana@x.co"])[:200])
    check("…„niciodată\" = null, cu data de la care se înregistrează",
          rows["quiet@x.co"].get("last_login") is None
          and rows["quiet@x.co"].get("last_login_tracked_since") is not None)
    ana = await U.login("ana@x.co")
    r = await ana.get("/api/users")
    me = r.json()
    check("fără users.manage: doar propriul rând, FĂRĂ câmpurile de ultimă autentificare",
          r.status_code == 200 and len(me) == 1
          and not any(k.startswith("last_login") for k in me[0]), str(me)[:200])
    await ana.aclose()

    # ── re-boot: last_login_since nu se mută ────────────────────────────────────────────
    v1 = (await db.fetchone("SELECT value FROM app_settings WHERE key='last_login_since'"))["value"]
    await db.execute("UPDATE app_settings SET value='1000' WHERE key='last_login_since'")
    await db.close()
    await db.connect()
    v2 = (await db.fetchone("SELECT value FROM app_settings WHERE key='last_login_since'"))["value"]
    check("re-boot: last_login_since păstrat (scris o singură dată)", v2 == "1000", "%s → %s" % (v1, v2))

    await owner.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
