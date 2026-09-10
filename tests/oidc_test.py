"""SSO / OIDC — hermetic, cu un IdP MOCK (server local: discovery + JWKS + token endpoint,
semnează id_token real RS256). Exersează exact codul din `oidc.py` şi endpoint-ul de callback,
fără Authentik. Acoperă: schimbul de cod, validarea id_token (semnătură/iss/aud/exp/nonce,
respingerea algoritmilor greşiţi), state single-use + TTL, provizionarea contului, refuzul pe
grup, şi emiterea sesiunii WebTerm.
"""
import asyncio
import base64
import json
import os
import sys
import threading
import time
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
# SSO activ, cu un grup cerut
os.environ["WEBTERM_OIDC_ISSUER"] = "http://127.0.0.1:0"      # rescris după ce pornim serverul
os.environ["WEBTERM_OIDC_CLIENT_ID"] = "wt-client"
os.environ["WEBTERM_OIDC_CLIENT_SECRET"] = "wt-secret"
os.environ["WEBTERM_OIDC_ALLOWED_GROUPS"] = "wt-access"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


# --- cheie RSA de test + JWKS ---
_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_priv_pem = _key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
_pub_nums = _key.public_key().public_numbers()


def _b64u(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


_KID = "test-key-1"
_JWKS = {"keys": [{"kty": "RSA", "use": "sig", "kid": _KID, "alg": "RS256",
                   "n": _b64u(_pub_nums.n), "e": _b64u(_pub_nums.e)}]}

# stare mock: codul curent + payload-ul id_token pe care-l va emite token endpoint-ul
_MOCK = {"issuer": None, "next_claims": None, "last_code": None}


def _make_id_token(claims: dict) -> str:
    return jwt.encode(claims, _priv_pem, algorithm="RS256", headers={"kid": _KID})


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        iss = _MOCK["issuer"]
        if self.path == "/.well-known/openid-configuration":
            self._json({"issuer": iss, "authorization_endpoint": iss + "/authorize",
                        "token_endpoint": iss + "/token", "jwks_uri": iss + "/jwks"})
        elif self.path == "/jwks":
            self._json(_JWKS)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/token":
            claims = _MOCK["next_claims"]
            self._json({"access_token": "at", "token_type": "Bearer",
                        "id_token": _make_id_token(claims)})
        else:
            self._json({"error": "not found"}, 404)


def start_mock():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % port


def base_claims(iss, **over):
    c = {"iss": iss, "aud": "wt-client", "sub": "authentik-sub-alice",
         "email": "alice@example.com", "groups": ["wt-access"],
         "exp": int(time.time()) + 300, "iat": int(time.time())}
    c.update(over)
    return c


async def main():
    srv, issuer = start_mock()
    _MOCK["issuer"] = issuer
    # reconfigurăm config + oidc pe issuer-ul real
    from app import config, db, oidc, oidc_api, security  # noqa: E402
    config.OIDC_ISSUER = issuer
    oidc._disco = None
    oidc._jwks_client = None
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()

    try:
        # ---- 1. begin(): URL de authorize cu state/nonce/PKCE ----
        url = oidc.begin(intent="login")
        check("begin() ţinteşte authorization_endpoint", url.startswith(issuer + "/authorize"), url[:60])
        check("begin() include PKCE S256", "code_challenge_method=S256" in url)
        state = dict(x.split("=", 1) for x in url.split("?", 1)[1].split("&"))["state"]
        nonce = oidc._TXN[state]["nonce"]

        # ---- 2. complete() cu token valid ----
        _MOCK["next_claims"] = base_claims(issuer, nonce=nonce)
        info = oidc.complete(state, "code-123")
        check("complete() întoarce sub/email/groups", info["sub"] == "authentik-sub-alice"
              and info["email"] == "alice@example.com" and "wt-access" in info["groups"], str(info))
        check("state e single-use (a doua oară → eroare)",
              _raises(lambda: oidc.complete(state, "code-123")))

        # ---- 3. nonce greşit → respins ----
        u2 = oidc.begin()
        s2 = dict(x.split("=", 1) for x in u2.split("?", 1)[1].split("&"))["state"]
        _MOCK["next_claims"] = base_claims(issuer, nonce="WRONG")
        check("nonce nepotrivit → OidcError", _raises(lambda: oidc.complete(s2, "c")))

        # ---- 4. audience greşit → respins ----
        u3 = oidc.begin(); s3 = _state(u3)
        _MOCK["next_claims"] = base_claims(issuer, nonce=oidc._TXN[s3]["nonce"], aud="ALT-CLIENT")
        check("aud greşit → OidcError", _raises(lambda: oidc.complete(s3, "c")))

        # ---- 5. expirat → respins ----
        u4 = oidc.begin(); s4 = _state(u4)
        _MOCK["next_claims"] = base_claims(issuer, nonce=oidc._TXN[s4]["nonce"],
                                           exp=int(time.time()) - 60, iat=int(time.time()) - 120)
        check("id_token expirat → OidcError", _raises(lambda: oidc.complete(s4, "c")))

        # ---- 6. grup lipsă → respins (defence-in-depth) ----
        u5 = oidc.begin(); s5 = _state(u5)
        _MOCK["next_claims"] = base_claims(issuer, nonce=oidc._TXN[s5]["nonce"], groups=["other"])
        check("grup neautorizat → OidcError", _raises(lambda: oidc.complete(s5, "c")))

        # ---- 7. token semnat cu ALTĂ cheie → respins (semnătură invalidă) ----
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        u6 = oidc.begin(); s6 = _state(u6)
        bad = jwt.encode(base_claims(issuer, nonce=oidc._TXN[s6]["nonce"]), other_pem,
                         algorithm="RS256", headers={"kid": _KID})
        _orig = oidc._http_json
        oidc._http_json = lambda url, data=None, headers=None: (
            {"id_token": bad} if url.endswith("/token") else _orig(url, data, headers))
        check("semnătură cu cheie străină → OidcError", _raises(lambda: oidc.complete(s6, "c")))
        oidc._http_json = _orig

        # ---- 8. provizionare cont prin callback (end-to-end pe endpoint) ----
        import httpx
        from app.main import app
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            u7 = oidc.begin(); s7 = _state(u7)
            _MOCK["next_claims"] = base_claims(issuer, nonce=oidc._TXN[s7]["nonce"])
            # H2: callback FĂRĂ cookie-ul de state (login-CSRF) → refuz, fără sesiune
            r0 = await c.get("/api/oidc/callback", params={"code": "c", "state": s7},
                             follow_redirects=False)
            check("callback fără cookie de state → refuz (state_mismatch)",
                  r0.status_code == 303 and "state_mismatch" in r0.headers.get("location", ""),
                  r0.headers.get("location"))
            # calea corectă: cookie-ul legat de browser corespunde state-ului
            r = await c.get("/api/oidc/callback", params={"code": "c", "state": s7},
                            cookies={oidc_api.STATE_COOKIE: s7}, follow_redirects=False)
            check("callback login → 303 redirect", r.status_code == 303, str(r.status_code))
            check("callback setează cookie de sesiune", any("session" in v for v in
                  r.headers.get_list("set-cookie")), str(r.headers.get_list("set-cookie")))
            row = await db.fetchone("SELECT * FROM users WHERE sso_subject=?", "authentik-sub-alice")
            check("cont provizionat cu sso_subject", row is not None and row["email"] == "alice@example.com")
            check("parola locală e blocată (SSO-only): login local eşuează",
                  not await security.verify_password_async("alice-test-pass-1234", row["password_hash"]))

            # ---- 8b. adopţie după email: refuzată fără email_verified, permisă cu el ----
            await db.execute("INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
                             "bob@example.com", await security.hash_password_async("x"), time.time())
            u8 = oidc.begin(); s8 = _state(u8)
            _MOCK["next_claims"] = base_claims(issuer, nonce=oidc._TXN[s8]["nonce"],
                                               sub="sub-bob-idp", email="bob@example.com")  # fără email_verified
            r = await c.get("/api/oidc/callback", params={"code": "c", "state": s8},
                            cookies={oidc_api.STATE_COOKIE: s8}, follow_redirects=False)
            check("adopţie fără email_verified → refuz (email_unverified)",
                  r.status_code == 303 and "email_unverified" in r.headers.get("location", ""),
                  r.headers.get("location"))
            bob = await db.fetchone("SELECT * FROM users WHERE email=?", "bob@example.com")
            check("contul existent NU a fost legat la refuz", bob["sso_subject"] is None)

            u9 = oidc.begin(); s9 = _state(u9)
            _MOCK["next_claims"] = base_claims(issuer, nonce=oidc._TXN[s9]["nonce"],
                                               sub="sub-bob-idp", email="bob@example.com", email_verified=True)
            r = await c.get("/api/oidc/callback", params={"code": "c", "state": s9},
                            cookies={oidc_api.STATE_COOKIE: s9}, follow_redirects=False)
            check("adopţie cu email_verified=True → 303 + cont legat",
                  r.status_code == 303 and "sso_error" not in r.headers.get("location", ""))
            bob = await db.fetchone("SELECT * FROM users WHERE email=?", "bob@example.com")
            check("cont existent legat la sub IdP după adopţie verificată", bob["sso_subject"] == "sub-bob-idp")

            # ---- 8c. cookie-ul de state pus de /login e chiar ACCEPTAT la callback ----
            # (faţă de 8/8b care injectau cookie-ul manual; asta prinde un Set-Cookie stricat —
            #  ex. Max-Age float — pe care jar-ul îl aruncă tăcut, lăsând callback-ul fără state.)
            from urllib.parse import urlparse, parse_qs
            rlog = await c.get("/api/oidc/login", follow_redirects=False)
            check("/login pune cookie-ul de state (parsabil de jar)", oidc_api.STATE_COOKIE in c.cookies,
                  str(dict(c.cookies)))
            sL = parse_qs(urlparse(rlog.headers["location"]).query)["state"][0]
            _MOCK["next_claims"] = base_claims(issuer, nonce=oidc._TXN[sL]["nonce"],
                                               sub="sub-login-flow", email="cflow@example.com")
            r = await c.get("/api/oidc/callback", params={"code": "c", "state": sL},
                            follow_redirects=False)  # jar-ul trimite cookie-ul pus de /login
            check("callback cu cookie din /login → 303, fără state_mismatch",
                  r.status_code == 303 and "state_mismatch" not in r.headers.get("location", ""),
                  r.headers.get("location"))

            # status endpoint
            st = (await c.get("/api/oidc/status")).json()
            check("/api/oidc/status: enabled", st["enabled"] is True)

        # ---- 9. status când SSO e dezactivat ----
        config.OIDC_ENABLED = False
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            st = (await c.get("/api/oidc/status")).json()
            check("SSO dezactivat → status.enabled False", st["enabled"] is False)
        config.OIDC_ENABLED = True
    finally:
        srv.shutdown()
        await db.close()

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


def _state(url):
    return dict(x.split("=", 1) for x in url.split("?", 1)[1].split("&"))["state"]


def _raises(fn):
    try:
        fn()
        return False
    except Exception:
        return True


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
