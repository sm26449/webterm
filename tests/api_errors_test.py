"""Erorile de API poartă un COD stabil (audit UX §8): `ApiError` pune codul în antetul
`X-WebTerm-Error` ŞI în corp, iar `vars` (datele din mesaj — retry, limită, amprente) merg în
`X-WebTerm-Error-Vars` + corp, nu în `detail` (care rămâne şirul englezesc pentru curl/scripturi).

Verificăm in-process (ASGI, fără reţea):
  * 404-urile goale de dinainte („Not Found") au acum cod — host.missing, session.missing;
  * 401 neautentificat → auth.required; lockout-ul → auth.rateLimited + Retry-After + vars.retry;
  * clasificatoarele de pass-through (`str(e)`) → coduri după tipul/textul excepţiei, iar
    textul brut rămâne DOAR în `detail`;
  * `/api/state` expune idle_lock_seconds / idle_lock_at / hostkey_changed.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
os.environ["WEBTERM_IP_MAX_FAILS"] = "3"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402
from app.errors import ApiError  # noqa: E402
from app.main import app  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
PW = "parola-cont-123456"
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


def unit_checks():
    # ApiError: cod + vars în antete; detail neschimbat
    e = ApiError(429, "auth.rateLimited", "too many attempts; retry in 7s",
                 headers={"Retry-After": "7"}, vars={"retry": 7, "skip": object()})
    check("ApiError: X-WebTerm-Error = codul", e.headers.get("X-WebTerm-Error") == "auth.rateLimited")
    check("ApiError: X-WebTerm-Error-Vars = JSON compact doar cu scalare",
          e.headers.get("X-WebTerm-Error-Vars") == '{"retry":7}', str(e.headers))
    check("ApiError: antetele proprii se păstrează (Retry-After)", e.headers.get("Retry-After") == "7")
    check("ApiError: detail rămâne şirul englezesc", e.detail == "too many attempts; retry in 7s")

    # clasificatorul de erori de fişiere: text de strerror de la agent → cod; mesajul în detail
    cases = [
        (core.FileError("/etc/shadow: Permission denied"), 400, "files.permissionDenied"),
        (core.FileError("/nope: No such file or directory"), 400, "files.notFound"),
        (core.FileError("/var/x: No space left on device"), 400, "files.noSpace"),
        (core.FileError("/etc: Is a directory"), 400, "files.isDirectory"),
        (core.FileError("integrity check failed: CRC mismatch (got 1, expected 2)"), 400, "files.crcMismatch"),
        (core.FileError("refusing to archive the filesystem root"), 400, "files.rootRefused"),
        (core.FileError("eroare"), 400, "files.failed"),           # agentul n-a trimis msg
        (core.FileConflict("the file changed on the host"), 409, "files.conflict"),
        (TimeoutError(), 504, "files.timeout"),
    ]
    for exc, status, code in cases:
        r = api._file_api_error(exc, 504 if isinstance(exc, TimeoutError) else 400)
        check("_file_api_error(%r) → %d %s" % (str(exc)[:30], status, code),
              r.status_code == status and r.code == code, "%s %s" % (r.status_code, r.code))
    r = api._file_api_error(core.FileError("/etc/shadow: Permission denied"))
    check("_file_api_error păstrează calea în detail (nu se pierde informaţia)",
          "/etc/shadow" in r.detail)

    # RuntimeError-urile din core → coduri, nu instrucţiuni de meniu în UI
    rt = [
        ("the fleet signing key is LOCKED — unlock it from Settings → Infrastructure & tokens", "signing.locked"),
        ("agent/ptyd.py.sig missing — run scripts/sign-agent.py", "signing.sigMissing"),
        ("the agent refused the update (downgrade)", "update.refused"),
        ("agent refused: limit", "agent.refused"),
        ("serial open failed", "session.createFailed"),
    ]
    for msg, code in rt:
        r = api._runtime_api_error(RuntimeError(msg), "session.createFailed")
        check("_runtime_api_error(%r) → %s" % (msg[:28], code), r.code == code and r.status_code == 502, r.code)

    bk = [("wrong passphrase, or the file is corrupt", "backup.badPassphrase"),
          ("backup too large when unpacked (possible compression bomb) — refused", "backup.tooLarge"),
          ("backup without the vault key — a restore would leave the credentials unreadable", "backup.noVaultKey"),
          ("nu pare un backup WebTerm", "backup.badFile")]
    for msg, code in bk:
        check("_backup_value_error(%r) → %s" % (msg[:24], code), api._backup_value_error(ValueError(msg)).code == code)
    check("_signing_value_error: not ed25519", api._signing_value_error(ValueError("the key is not ed25519")).code == "signing.notEd25519")
    check("_signing_value_error: exists → 409", api._signing_value_error(ValueError("a signing key already exists")).status_code == 409)


async def main():
    unit_checks()
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        r = await c.get("/api/hosts")
        check("neautentificat → 401 cu cod auth.required",
              r.status_code == 401 and r.headers.get("x-webterm-error") == "auth.required", r.text[:100])
        check("corpul JSON poartă `code` (pentru curl/scripturi, nu doar antetul)",
              r.json().get("code") == "auth.required", r.text[:100])

        r = await c.post("/api/setup", json={"email": "admin@x.co", "password": PW, "setup_token": "test-setup"})
        check("setup cont", r.status_code == 200, r.text[:120])

        r = await c.get("/api/state")
        st = r.json()
        check("/api/state: idle_lock_seconds = pragul configurat",
              st.get("idle_lock_seconds") == int(config.IDLE_LOCK_SECS), str(st.get("idle_lock_seconds")))
        check("/api/state: idle_lock_at prezent (null — cronometrul e per sesiune de terminal)",
              "idle_lock_at" in st and st["idle_lock_at"] is None)
        check("/api/state: hostkey_changed = listă (goală)", st.get("hostkey_changed") == [])

        r = await c.get("/api/hosts/999999/hostkey")
        check("host inexistent → 404 host.missing (nu „Not Found” gol)",
              r.status_code == 404 and r.headers.get("x-webterm-error") == "host.missing", r.text[:100])
        r = await c.get("/api/sessions/%s/preview" % ("a" * 32))
        check("sesiune inexistentă → 404 session.missing",
              r.status_code == 404 and r.headers.get("x-webterm-error") == "session.missing", r.text[:100])
        r = await c.post("/api/users/999999/delete", json={"current_password": PW})
        check("cont inexistent → user.missing", r.headers.get("x-webterm-error") == "user.missing", r.text[:100])
        r = await c.post("/api/users", json={"email": "admin@x.co", "password": PW, "current_password": PW})
        check("email duplicat → 409 account.emailTaken",
              r.status_code == 409 and r.headers.get("x-webterm-error") == "account.emailTaken", r.text[:100])
        r = await c.post("/api/users", json={"email": "scurt@x.co", "password": "abc", "current_password": PW})
        check("parolă scurtă → account.passwordTooShort + vars.min",
              r.headers.get("x-webterm-error") == "account.passwordTooShort"
              and r.json().get("vars", {}).get("min") == 8, r.text[:120])
        r = await c.post("/api/setup", json={"email": "x@x.co", "password": PW, "setup_token": "test-setup"})
        check("setup repetat → setup.alreadyConfigured", r.headers.get("x-webterm-error") == "setup.alreadyConfigured")

    # lockout: un client NOU (fără cookie) greşeşte parola până la plafon → 429 cu cod + vars
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c2:
        last = None
        for _ in range(config.IP_MAX_FAILS + 1):
            last = await c2.post("/api/login", json={"email": "admin@x.co", "password": "gresit-gresit"})
            if last.status_code == 429:
                break
        check("lockout → 429 auth.rateLimited", last is not None and last.status_code == 429
              and last.headers.get("x-webterm-error") == "auth.rateLimited", "%s %s" % (last.status_code, last.text[:80]))
        if last is not None and last.status_code == 429:
            body = last.json()
            check("429: Retry-After + vars.retry (acelaşi număr)",
                  last.headers.get("retry-after") and body.get("vars", {}).get("retry") == int(last.headers["retry-after"]),
                  "%s %s" % (last.headers.get("retry-after"), body))
            check("429: detail rămâne englezesc cu secundele („retry in Ns”)", "retry in" in body.get("detail", ""))

    await db.close()
    print(f"\n{ok}/{total} teste trecute")
    sys.stdout.flush()
    os._exit(0 if ok == total else 1)


asyncio.run(main())
