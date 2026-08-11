"""Pre-production security checks: auth coverage, CSWSH, rate limiting,
user-enumeration, security headers, agent/setup gating."""

import asyncio
import os
import subprocess
import sys
import tempfile
import time

import httpx

# Middleware-ul `csrf_guard` cere `Origin` pe metodele care schimbă ceva şi refuză
# lipsa lui (ca `_origin_ok` pentru WebSocket). Testele imită un BROWSER, deci trimit
# antetul; fără el ar testa o cale pe care niciun browser n-o produce.
# ATENŢIE: testul ăsta porneşte un uvicorn PROPRIU pe alt port şi îi dă
# `WEBTERM_PUBLIC_URL=BASE`. Originea trimisă trebuie să fie a ACELUI server, nu a suitei
# — altfel `csrf_guard` respinge corect, iar testul pică din motive care n-au legătură cu
# ce verifică. `_ORIGIN` se defineşte mai jos, după BASE.
import websockets

# rădăcina repo-ului, derivată din locația testului (tests/ e sub root) — nu hardcodată
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8796
BASE = f"http://127.0.0.1:{PORT}"
_ORIGIN = {"origin": BASE}
WS = BASE.replace("http", "ws")
P = []


def ok(name, cond, detail=""):
    P.append((name, cond))
    print(("  PASS " if cond else "  FAIL ") + name + ("" if cond else f"  {detail}"))


async def main():
    tmp = tempfile.mkdtemp(prefix="sec-")
    env = dict(os.environ, WEBTERM_SETUP_TOKEN="test-setup", WEBTERM_DATA_DIR=os.path.join(tmp, "data"),
               WEBTERM_PUBLIC_URL=BASE, PYTHONPATH=f"{ROOT}/gateway")
    # interpretorul curent (nu o cale .venv hardcodată) → rulează din orice clonă
    gw = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT),
         "--host", "127.0.0.1", "--log-level", "warning"],
        env=env, cwd=f"{ROOT}/gateway")
    try:
        async with httpx.AsyncClient(base_url=BASE, headers=_ORIGIN) as h:
            for _ in range(60):
                try:
                    if (await h.get("/api/state")).status_code == 200:
                        break
                except httpx.TransportError:
                    await asyncio.sleep(0.2)

            # ── security headers present ──
            r = await h.get("/api/state")
            hh = r.headers
            ok("CSP header present", "content-security-policy" in hh)
            ok("X-Frame-Options DENY", hh.get("x-frame-options") == "DENY")
            ok("X-Content-Type-Options nosniff", hh.get("x-content-type-options") == "nosniff")
            ok("Referrer-Policy set", hh.get("referrer-policy") == "no-referrer")

            # ── protected endpoints reject without auth ──
            # Rutele fs sunt cele mai periculoase din API (citire/scriere arbitrară
            # pe host, ex. /fs/download?path=/etc/shadow), iar singura barieră e
            # auth-ul — deci le verificăm explicit pe TOATE cele 8.
            for method, path in [("GET", "/api/hosts"), ("GET", "/api/sessions"),
                                 ("POST", "/api/account"), ("GET", "/api/search?q=xx"),
                                 ("POST", "/api/hosts/1/sessions"),
                                 ("GET", "/api/webauthn/credentials"),
                                 ("GET", "/api/hosts/1/fs?path=~"),
                                 ("GET", "/api/hosts/1/fs/cwd?sid=x"),
                                 ("GET", "/api/hosts/1/fs/download?path=/etc/passwd"),
                                 ("GET", "/api/hosts/1/fs/preview?path=~/.bashrc"),
                                 ("POST", "/api/hosts/1/fs/upload?path=~/x"),
                                 ("POST", "/api/hosts/1/fs/mkdir"),
                                 ("POST", "/api/hosts/1/fs/rename"),
                                 ("POST", "/api/hosts/1/fs/delete")]:
                rr = await h.request(method, path, json={} if method == "POST" else None)
                ok(f"{method} {path} needs auth", rr.status_code in (401, 403), str(rr.status_code))

            # ── path traversal blocked (raw ASGI, bypasses client normalization) ──
            import urllib.request
            try:
                req = urllib.request.Request(BASE + "/..%2f..%2f..%2fdata/secret")
                body = urllib.request.urlopen(req, timeout=5).read()
                leaked = b"secret" in body or len(body) == 32
            except Exception:
                leaked = False
            # also try a raw dotted path via httpx (server-side join)
            r = await h.get("/../../data/webterm.db")
            served_index = b"<!doctype html" in r.content.lower() or b"<div id=\"root\"" in r.content
            ok("path traversal blocked (no file leak)", not leaked and (r.status_code != 200 or served_index))

            # ── setup requires the setup token ──
            r = await h.post("/api/setup", json={"email": "a@b.com", "password": "buna-parola-1"})
            ok("setup without token rejected", r.status_code == 403, str(r.status_code))
            r = await h.post("/api/setup", json={"email": "a@b.com", "password": "buna-parola-1", "setup_token": "WRONG"})
            ok("setup with wrong token rejected", r.status_code == 403, str(r.status_code))

            # ── setup then gated ──
            r = await h.post("/api/setup", json={"email": "a@b.com", "password": "buna-parola-1", "setup_token": "test-setup"})
            ok("setup creates first user (with token)", r.status_code == 200)
            cookie = r.cookies["wt_session"]
            r = await h.post("/api/setup", json={"email": "x@y.com", "password": "another-one-2", "setup_token": "test-setup"})
            ok("setup blocked once configured", r.status_code == 409)

            # ── user enumeration: same status+message for unknown email vs bad pw ──
            r1 = await h.post("/api/login", json={"email": "nope@nope.com", "password": "whatever-xx"})
            r2 = await h.post("/api/login", json={"email": "a@b.com", "password": "wrong-pass-xx"})
            ok("unknown email and wrong password look identical",
               r1.status_code == r2.status_code == 401 and r1.json() == r2.json(),
               f"{r1.status_code}:{r1.text} vs {r2.status_code}:{r2.text}")

            # ── brute-force lockout ──
            got_429 = False
            for i in range(12):
                rr = await h.post("/api/login", json={"email": "a@b.com", "password": f"bad{i}"})
                if rr.status_code == 429:
                    got_429 = True
                    break
            ok("brute-force lockout kicks in (429)", got_429)

            # ── CSWSH: browser WS ──
            hdr_auth = {"Cookie": "wt_session=" + cookie}
            # no Origin → rejected
            try:
                async with websockets.connect(f"{WS}/ws/sessions/" + "0" * 32,
                                              additional_headers=hdr_auth):
                    ok("WS without Origin rejected", False, "connected")
            except Exception:
                ok("WS without Origin rejected", True)
            # hostile Origin → rejected
            try:
                async with websockets.connect(f"{WS}/ws/sessions/" + "0" * 32,
                                              additional_headers=dict(hdr_auth, Origin="https://evil.example.com")):
                    ok("WS with hostile Origin rejected (CSWSH)", False, "connected")
            except Exception:
                ok("WS with hostile Origin rejected (CSWSH)", True)
            # correct Origin but no auth cookie → 4401 (not accepted)
            try:
                async with websockets.connect(f"{WS}/ws/sessions/" + "0" * 32,
                                              additional_headers={"Origin": BASE}):
                    ok("WS with good Origin but no auth rejected", False, "connected")
            except Exception:
                ok("WS with good Origin but no auth rejected", True)

            # ── agent WS without a valid token rejected ──
            try:
                async with websockets.connect(f"{WS}/agent/ws"):
                    ok("agent WS without token rejected", False, "connected")
            except Exception:
                ok("agent WS without token rejected", True)

            # ── install endpoint: bogus enroll token → 404 ──
            r = await h.get("/install/deadbeefdeadbeef.sh")
            ok("bogus enroll token 404", r.status_code == 404)

            # ── share: bogus token rejected (meta + ws) ──
            r = await h.get("/api/shared/nu-exista-token")
            ok("bogus share token → 404 (meta)", r.status_code == 404)
            try:
                async with websockets.connect(f"{WS}/ws/shared/nu-exista",
                                              additional_headers={"Origin": BASE}):
                    ok("bogus share token → ws rejected", False, "connected")
            except Exception:
                ok("bogus share token → ws rejected", True)
            # creating a share requires auth
            r = await h.post("/api/sessions/" + "0" * 32 + "/share")
            ok("creating a share needs auth", r.status_code in (401, 403, 404))

            # ── M1: schimbările de credențiale cer RE-AUTH cu parola (nu doar cookie) ──
            # `h` e deja autentificat din setup-ul de mai sus (a@b.com). Aceste endpoint-uri
            # au require_user (îl avem) DAR şi parola — un cookie furat nu trebuie să înroleze
            # un factor 2FA / să șteargă passkey-uri. Fără parolă → 401.
            r = await h.get("/api/state")
            authed = r.status_code == 200 and bool(r.json().get("authenticated"))
            ok("sesiune autentificată (din setup)", authed)
            r = await h.post("/api/totp/setup", json={})
            ok("TOTP setup autentificat, fără parolă → 401", r.status_code == 401)
            r = await h.post("/api/totp/activate", json={"code": "000000"})
            ok("TOTP activate autentificat, fără parolă → 401", r.status_code == 401)
            r = await h.request("DELETE", "/api/webauthn/credentials/1", json={})
            ok("passkey delete autentificat, fără parolă → 401", r.status_code == 401)
    finally:
        gw.terminate()

    failed = [n for n, c in P if not c]
    print(f"\n{len(P) - len(failed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
