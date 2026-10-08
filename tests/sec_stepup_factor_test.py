"""Patch de securitate 3.5.13 — step-up, mutaţii, Origin, deploy-key, argon2.

  · fix 2 — parola SINGURĂ nu mai deschide un host `require_2fa` (decizie de politică): un cont
            fără passkey şi fără TOTP primeşte 403 `stepup.needsFactor`, orice parolă ar trimite
            (inclusiv cea corectă — fără oracol). TOTP/passkey/SSO neschimbate. Re-auth-ul cu
            parola pe o ţintă FĂRĂ 2FA (gate-ul de factor proaspăt al deploy-key) rămâne.
            Activarea require_2fa nu e blocată, dar întoarce un `warning`; /api/state expune
            `stepup_method`.
  · fix 3 — PATCH /api/sessions/{sid} cere step-up pe hostul sesiunii; DELETE /api/history cere
            re-auth (parola contului, ca „Revocă tot") şi e auditat.
  · fix 4 — Origin-ul WS se compară pe schemă+host+port (porturi implicite normalizate).
  · fix 5 — deploy-key single: şi SURSA `require_2fa` cere fereastra ei de step-up.
  · fix 7 — un hash argon2 corupt e „parolă greşită" (False), nu un 500.
(Plafonul de 60 min pe terminale + POST /api/history: vezi sec_stepup_cap_test.)
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
from app import api, config, db, security  # noqa: E402
from app import totp as totp_mod  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class _H:
    def __init__(self, origin):
        self.headers = {"origin": origin} if origin is not None else {}


def _code(r):
    try:
        return r.json().get("code")
    except ValueError:
        return None


async def _raises_code(coro):
    try:
        await coro
        return None
    except Exception as e:                                 # noqa: BLE001
        return getattr(e, "code", type(e).__name__)


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    # ── fix 7: argon2 — hash corupt = False, nu excepţie ─────────────────────
    good = security.hash_password("x-parola")
    check("argon2: hash valid + parola corectă → True", security.verify_password("x-parola", good))
    check("argon2: parolă greşită → False", security.verify_password("alta", good) is False)
    for bad in ("garbage", "", "$argon2id$v=19$m=65536,t=3,p=4$xx$yy", "$argon2id$v=19$"):
        try:
            res = security.verify_password("x", bad)
        except Exception as e:                             # noqa: BLE001
            res = "raised %s" % type(e).__name__
        check("argon2: hash corupt %r → False (nu excepţie)" % bad[:24], res is False, str(res))

    # ── fix 4: Origin WS = schemă + host + port ──────────────────────────────
    old_url = config.PUBLIC_URL
    try:
        config.PUBLIC_URL = "https://wt.example.com"
        cases = [("https://wt.example.com", True), ("https://wt.example.com:443", True),
                 ("https://WT.example.com", True),
                 ("http://wt.example.com", False), ("http://wt.example.com:443", False),
                 ("https://wt.example.com:8443", False), ("https://evil.example", False),
                 ("null", False), ("", False), (None, False), ("https://wt.example.com:99999", False)]
        for origin, want in cases:
            check("Origin %r vs PUBLIC_URL https → %s" % (origin, want),
                  api._origin_ok(_H(origin)) is want)
        config.PUBLIC_URL = "http://localhost:8000"
        check("Origin http://localhost:8000 vs PUBLIC_URL identic → True",
              api._origin_ok(_H("http://localhost:8000")) is True)
        check("Origin https://localhost:8000 (altă schemă, acelaşi netloc) → False",
              api._origin_ok(_H("https://localhost:8000")) is False)
        check("Origin http://localhost (port implicit 80 ≠ 8000) → False",
              api._origin_ok(_H("http://localhost")) is False)
    finally:
        config.PUBLIC_URL = old_url

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200, r.text[:120])
        uid = (await db.fetchone("SELECT id FROM users WHERE email='a@b.co'"))["id"]
        me = lambda: db.fetchone("SELECT * FROM users WHERE id=?", uid)   # noqa: E731
        gated = (await c.post("/api/hosts", json={"name": "critic", "require_2fa": True})).json()["id"]
        plain = (await c.post("/api/hosts", json={"name": "plain"})).json()["id"]
        security._stepup_windows.clear()

        # ── fix 2: /api/state expune metoda de step-up ───────────────────────
        st = (await c.get("/api/state")).json()
        check("/api/state: stepup_method=none pentru un cont doar cu parolă",
              st.get("stepup_method") == "none", str(st.get("stepup_method")))

        # ── fix 2: parola singură refuzată pe host 2FA (corectă SAU greşită) ──
        r = await c.post(f"/api/hosts/{gated}/stepup", json={"stepup_password": PW})
        check("/stepup cu parola CORECTĂ, fără passkey/TOTP → 403 stepup.needsFactor",
              r.status_code == 403 and _code(r) == "stepup.needsFactor", r.text[:160])
        check("…mesajul spune ce e de făcut (passkey sau TOTP)",
              "passkey" in r.text and "TOTP" in r.text, r.text[:200])
        check("…fereastra NU s-a deschis", not security.stepup_window_is_open(uid, gated))
        r = await c.post(f"/api/hosts/{gated}/stepup", json={"stepup_password": "gresita"})
        check("/stepup cu parola GREŞITĂ → acelaşi 403 (fără oracol de parolă)",
              r.status_code == 403 and _code(r) == "stepup.needsFactor", r.text[:160])
        r = await c.get(f"/api/hosts/{gated}/sessions?stepup_password={PW}")
        check("o acţiune de host cu parola în query → tot needsFactor",
              r.status_code == 403 and _code(r) == "stepup.needsFactor", r.text[:160])
        check("_require_fresh_factor pe ţintă 2FA (unlock/deploy) → needsFactor",
              await _raises_code(api._require_fresh_factor(gated, await me(), "", PW))
              == "stepup.needsFactor")
        # re-auth tip `sudo` pe o ţintă FĂRĂ 2FA rămâne pe parolă (deploy-key spre un host simplu)
        security._stepup_windows.clear()
        check("_require_fresh_factor pe ţintă FĂRĂ 2FA: parola corectă trece",
              await _raises_code(api._require_fresh_factor(plain, await me(), "", PW)) is None)
        security._stepup_windows.clear()
        check("_require_fresh_factor pe ţintă FĂRĂ 2FA: fără parolă → stepup.password",
              await _raises_code(api._require_fresh_factor(plain, await me(), "", "")) == "stepup.password")
        r = await c.post(f"/api/hosts/{plain}/stepup", json={"stepup_password": PW})
        check("/stepup pe host FĂRĂ 2FA cu parola → 200 (neschimbat)", r.status_code == 200, r.text[:160])

        # ── fix 2: avertisment la activarea require_2fa fără factor ──────────
        other = (await c.post("/api/hosts", json={"name": "devine-critic"})).json()["id"]
        r = await c.post(f"/api/hosts/{other}/require-2fa", json={"enabled": True})
        check("require-2fa ON fără factor → 200 (nu blocăm) + warning=stepup.needsFactor",
              r.status_code == 200 and r.json().get("warning") == "stepup.needsFactor", r.text[:160])
        row = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", other)
        check("…flag-ul chiar s-a activat", row["require_2fa"] == 1)

        # ── fix 2: SSO păstrează calea de re-auth la IdP ─────────────────────
        await db.execute("UPDATE users SET sso_subject='sub-1' WHERE id=?", uid)
        old_oidc = config.OIDC_ENABLED
        config.OIDC_ENABLED = True
        try:
            check("SSO: step-up → host.needs2faSso (nu needsFactor)",
                  await _raises_code(api._require_host_stepup(gated, await me(), "", PW))
                  == "host.needs2faSso")
            check("SSO: stepup_method=sso", await api._stepup_method(await me()) == "sso")
        finally:
            config.OIDC_ENABLED = old_oidc
            await db.execute("UPDATE users SET sso_subject=NULL WHERE id=?", uid)

        # ── fix 2: TOTP neschimbat — deschide fereastra ──────────────────────
        secret = totp_mod.new_secret()
        await db.execute("UPDATE users SET totp_enabled=1, totp_secret_encrypted=? WHERE id=?",
                         security.encrypt_secret(secret), uid)
        st = (await c.get("/api/state")).json()
        check("/api/state: stepup_method=totp după înrolare", st.get("stepup_method") == "totp")
        r = await c.post(f"/api/hosts/{gated}/stepup", json={"stepup_password": PW})
        check("TOTP activ: parola singură → stepup.totp (neschimbat)",
              r.status_code == 403 and _code(r) == "stepup.totp", r.text[:160])
        r = await c.post(f"/api/hosts/{gated}/stepup", json={"stepup_totp": totp_mod.generate(secret)})
        check("TOTP activ: codul deschide fereastra", r.status_code == 200, r.text[:160])
        other2 = (await c.post("/api/hosts", json={"name": "devine-critic-2"})).json()["id"]
        r = await c.post(f"/api/hosts/{other2}/require-2fa", json={"enabled": True})
        check("require-2fa ON cu TOTP → fără warning", r.status_code == 200 and "warning" not in r.json(),
              r.text[:160])

        # ── fix 3: PATCH /api/sessions/{sid} pe host 2FA cere step-up ────────
        sid = "f" * 32
        await db.execute(
            "INSERT INTO sessions(id,host_id,title,state,created,rows,cols) VALUES(?,?,?,?,?,?,?)",
            sid, gated, "orig", "closed", time.time(), 24, 80)
        security._stepup_windows.clear()
        r = await c.patch(f"/api/sessions/{sid}", json={"title": "pwned"})
        check("PATCH sesiune pe host 2FA fără fereastră → 403 stepup.*",
              r.status_code == 403 and (_code(r) or "").startswith("stepup."), r.text[:160])
        t = (await db.fetchone("SELECT title FROM sessions WHERE id=?", sid))["title"]
        check("…titlul NU s-a schimbat", t == "orig", t)
        security.open_stepup_window(uid, gated)
        r = await c.patch(f"/api/sessions/{sid}", json={"title": "redenumit"})
        check("PATCH cu fereastră deschisă → 200", r.status_code == 200, r.text[:160])
        sid_p = "9" * 32
        await db.execute(
            "INSERT INTO sessions(id,host_id,title,state,created,rows,cols) VALUES(?,?,?,?,?,?,?)",
            sid_p, plain, "x", "closed", time.time(), 24, 80)
        security._stepup_windows.clear()
        r = await c.patch(f"/api/sessions/{sid_p}", json={"note": "n"})
        check("PATCH sesiune pe host FĂRĂ 2FA → 200 (neschimbat)", r.status_code == 200, r.text[:160])

        # ── fix 3: DELETE /api/history cere re-auth + audit ──────────────────
        for i in range(3):
            await c.post("/api/history", json={"host_id": plain, "command": "cmd%d" % i})
        r = await c.request("DELETE", "/api/history")
        check("DELETE /api/history fără parolă → 401 auth.wrongPassword",
              r.status_code == 401 and _code(r) == "auth.wrongPassword", r.text[:160])
        r = await c.request("DELETE", "/api/history", json={"current_password": "gresita"})
        check("DELETE /api/history cu parola greşită → 401", r.status_code == 401, r.text[:160])
        n = (await db.fetchone("SELECT COUNT(*) AS c FROM command_history"))["c"]
        check("…istoricul e intact", n == 3, str(n))
        r = await c.request("DELETE", "/api/history", json={"current_password": PW})
        check("DELETE /api/history cu parola contului → 200 + deleted=3",
              r.status_code == 200 and r.json().get("deleted") == 3, r.text[:160])
        n = (await db.fetchone("SELECT COUNT(*) AS c FROM command_history"))["c"]
        check("…istoricul e gol", n == 0, str(n))
        a = None
        for _ in range(100):
            a = await db.fetchone("SELECT * FROM audit_log WHERE method='DELETE' AND path='/api/history'"
                                  " AND status=200")
            if a:
                break
            await asyncio.sleep(0.02)
        check("ştergerea e în audit_log, cu contul şi numărul de rânduri",
              a is not None and a["actor"] == "a@b.co" and "3" in (a["detail"] or ""),
              dict(a) if a else None)

        # ── fix 5: deploy-key single — sursa 2FA cere fereastra ei ───────────
        await db.execute("UPDATE hosts SET connection_type='agent' WHERE id IN (?,?)", gated, plain)
        await db.execute("INSERT INTO ssh_keys(host_id, public_key, fingerprint, created)"
                         " VALUES(?,?,?,?)", gated,
                         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq7dQ0oF2b8fQ2l3bUo8xk3c9o6m5J2k1P0o9i8u7y6 t",
                         "SHA256:test", time.time())
        security._stepup_windows.clear()
        grant = security.issue_stepup_grant(uid, plain)
        r = await c.post(f"/api/hosts/{plain}/deploy-key/deploy",
                         json={"key_host_id": gated, "stepup_grant": grant})
        check("deploy single cu sursa 2FA fără fereastră → 403 sshkey.sourceNeeds2fa",
              r.status_code == 403 and _code(r) == "sshkey.sourceNeeds2fa", r.text[:160])
        check("…grant-ul single-use al ţintei NU a fost consumat degeaba",
              grant in security._stepup_grants)
        security.open_stepup_window(uid, gated)
        r = await c.post(f"/api/hosts/{plain}/deploy-key/deploy",
                         json={"key_host_id": gated, "stepup_grant": grant})
        check("…cu fereastra sursei deschisă trece de ambele porţi (eşuează abia la agent offline)",
              _code(r) not in ("sshkey.sourceNeeds2fa",) and not (_code(r) or "").startswith("stepup."),
              "%s %s" % (r.status_code, r.text[:160]))

        # ── fix 7 prin HTTP: un cont cu hash corupt primeşte 401, nu 500 ─────
        await db.execute("INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
                         "corupt@b.co", "nu-e-un-hash-argon2", time.time())
        async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                     headers=_ORIGIN) as c2:
            r = await c2.post("/api/login", json={"email": "corupt@b.co", "password": "orice"})
            check("login pe un cont cu hash corupt → 401 (nu 500)", r.status_code == 401,
                  "%s %s" % (r.status_code, r.text[:120]))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    res = asyncio.run(run())
    sys.stdout.flush()
    os._exit(0 if res else 1)
