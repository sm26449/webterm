"""Reparaţiile din auditul extern de pe 2026-08-11 (F-01…F-09).

Fiecare test aici există fiindcă un auditor a găsit lipsa apărării, nu fiindcă părea o idee
bună. Ordinea urmează severitatea raportată.

Nota cea mai importantă e despre ce NU e adevărat: auditul a escaladat CSRF-ul la „Critical"
susţinând că FastAPI parsează un body fără `Content-Type` ca JSON, deci că o cerere fără
preflight ar ajunge la `/api/hosts/{id}/run` — execuţie de comenzi. Testul
`fara_content_type_nu_e_parsat_ca_json` de mai jos verifică asta pe versiunile pe care le
LIVRĂM şi arată contrariul (422, nu 200). Dacă vreodată devine adevărat — un bump de FastAPI
schimbă comportamentul — testul pică şi aflăm ÎNAINTE ca cineva să publice imaginea.
"""
import asyncio
import os
import socket
import sys
import tempfile
import threading
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "https://term.example.com")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


# ── F-01: comportamentul REAL al lui FastAPI la body fără Content-Type ───────
def fastapi_body_parsing():
    """Rulat pe un uvicorn adevărat, prin socket, ca să nu depindem de TestClient."""
    from fastapi import FastAPI
    from pydantic import BaseModel
    import uvicorn

    app = FastAPI()

    class RunIn(BaseModel):
        command: str

    @app.post("/run")
    async def run(body: RunIn):          # noqa: ANN001
        return {"got": body.command}

    port = 8793
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical")
    srv = uvicorn.Server(cfg)
    threading.Thread(target=srv.run, daemon=True).start()
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)

    body = b'{"command":"id"}'

    def post(ct):
        h = "POST /run HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % len(body)
        if ct is not None:
            h += "Content-Type: %s\r\n" % ct
        h += "Connection: close\r\n\r\n"
        s = socket.create_connection(("127.0.0.1", port), 3)
        s.sendall(h.encode() + body)
        data = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
        s.close()
        return data.split(b"\r\n")[0].decode()

    # Tipurile „CORS-simple" (fără preflight) NU trebuie parsate ca JSON. Dacă vreunul
    # ajunge 200, orice endpoint cu body devine ţintă CSRF şi F-01 chiar e Critical.
    for ct in (None, "text/plain", "text/plain;charset=UTF-8",
               "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"):
        st = post(ct)
        check("body cu %-38s → nu e parsat ca JSON" % (ct or "(fără Content-Type)"),
              " 200 " not in st, st)
    check("body cu application/json → parsat (declanşează preflight, deci nu e CSRF-abil)",
          " 200 " in post("application/json"))
    srv.should_exit = True
    time.sleep(0.3)


async def main():
    from app import config, db, security
    from app.main import app as real_app

    fastapi_body_parsing()

    # ── F-01: middleware-ul de origine ──────────────────────────────────────
    names = [m.cls.__name__ if hasattr(m, "cls") else str(m) for m in real_app.user_middleware]
    fns = []
    for m in real_app.user_middleware:
        f = getattr(m, "kwargs", {}).get("dispatch") or (m.options.get("dispatch") if hasattr(m, "options") else None)
        if f is not None:
            fns.append(getattr(f, "__name__", ""))
    check("există un middleware csrf_guard", "csrf_guard" in fns, fns or names)

    from app.main import csrf_guard

    # Originea „proprie" se ia din config, nu se scrie de mână: suita exportă
    # `WEBTERM_PUBLIC_URL`, deci o constantă hardcodată ar testa alt domeniu decât cel
    # pe care middleware-ul îl compară — a şi păcălit-o o dată.
    from urllib.parse import urlparse as _up
    OURS = _up(config.PUBLIC_URL).netloc
    SELF_ORIGIN = config.PUBLIC_URL.rstrip("/")
    FWD_ORIGIN = "https://cam1." + OURS.split(":")[0]

    class Req:
        def __init__(self, method, path, origin=None, host=OURS.split(":")[0], auth=None,
                     cookie=True):
            self.method = method
            self.headers = {}
            if origin:
                self.headers["origin"] = origin
            self.headers["host"] = host
            if auth:
                self.headers["authorization"] = auth
            # Poarta se aplică doar cererilor cu credenţială ambientală (cookie de sesiune).
            self.cookies = {security.COOKIE_NAME: "x"} if cookie else {}
            self.url = type("U", (), {"path": path})()

    async def passthru(_):
        return "OK"

    async def call(req):
        r = await csrf_guard(req, passthru)
        return r if r == "OK" else getattr(r, "status_code", "?")

    check("POST /api/ fără Origin → refuzat",
          await call(Req("POST", "/api/hosts/1/uninstall")) == 403)
    check("POST /api/ cu Origin străin → refuzat",
          await call(Req("POST", "/api/hosts/1/uninstall", "https://evil.example")) == 403)
    # ESENŢA: un subdomeniu de forward e same-site, deci cookie-ul pleacă — dar Origin diferă.
    check("POST /api/ de pe un SUBDOMENIU de forward → refuzat",
          await call(Req("POST", "/api/hosts/1/uninstall", FWD_ORIGIN)) == 403)
    check("POST /api/ cu Origin propriu → trece",
          await call(Req("POST", "/api/hosts/1/uninstall", SELF_ORIGIN)) == "OK")
    check("GET nu e atins (metodă sigură)",
          await call(Req("GET", "/api/hosts")) == "OK")
    check("Bearer (automatizare) nu e cerut Origin",
          await call(Req("POST", "/api/hosts/1/run", auth="Bearer wt_x")) == "OK")
    check("cererile către subdomeniul forwardat trec (nu sunt API-ul nostru)",
          await call(Req("POST", "/login", host="cam1." + OURS.split(":")[0])) == "OK")
    # Fără cookie nu există autoritate ambientală de furat, deci nu e CSRF — şi asta e ce
    # ţine în viaţă provisioning-ul scriptat (`curl` către /api/setup, E2E-ul cu fetch din
    # Node). Poarta prea largă a rupt exact calea de instalare, prinsă în CI.
    # Accesul pe un nume ALTERNATIV (IP în loc de domeniu) trebuie să meargă: browserul
    # trimite Origin-ul URL-ului încărcat, care e egal cu Host-ul cererii. Fără asta, un
    # admin care intră pe IP primea 403 la fiecare scriere — prins de fwd-test în CI.
    alt = Req("POST", "/api/hosts/1/uninstall", "http://127.0.0.1:8000")
    alt.headers["host"] = "127.0.0.1:8000"
    check("acces pe un nume alternativ (Origin == Host) → trece", await call(alt) == "OK")
    hostile = Req("POST", "/api/hosts/1/uninstall", "https://evil.example")
    hostile.headers["host"] = "127.0.0.1:8000"
    check("…dar Origin străin pe acelaşi Host → tot refuzat", await call(hostile) == 403)

    check("fără cookie de sesiune → nu cerem Origin (bootstrap/curl)",
          await call(Req("POST", "/api/setup", cookie=False)) == "OK")
    check("…dar CU cookie şi fără Origin → tot refuzat",
          await call(Req("POST", "/api/setup")) == 403)

    # ── F-03: plafonul dur e CHIAR mai larg ─────────────────────────────────
    check("plafonul dur > plafonul moale",
          security._HARD_MAX_FAILS > config.IP_MAX_FAILS,
          (security._HARD_MAX_FAILS, config.IP_MAX_FAILS))
    key = "reauth-hard:424242"
    for _ in range(config.IP_MAX_FAILS + 2):
        security.record_login_failure(key)
    check("după cât blochează plafonul MOALE, cel dur încă permite",
          security.login_allowed(key)[0] is True)

    # ── F-02: backstop-ul global încetineşte, nu refuză ─────────────────────
    security._global_fails.clear()
    now = time.time()
    security._global_fails.extend([now] * (security._GLOBAL_MAX_FAILS + 5))
    allowed, retry = security.login_allowed("203.0.113.200")
    check("backstop global: nu mai REFUZĂ", allowed is True, (allowed, retry))
    check("backstop global: semnalează frâna (retry=-1)", retry == -1, retry)
    security.record_login_success("203.0.113.201")
    check("un IP cu login reuşit recent trece nestingherit",
          security.login_allowed("203.0.113.201") == (True, 0))
    t0 = time.time()
    await security.apply_global_tarpit(-1)
    check("frâna chiar întârzie", time.time() - t0 >= security._GLOBAL_TARPIT * 0.9)
    security._global_fails.clear()

    # cheile interne nu mai hrănesc backstop-ul global
    security._global_fails.clear()
    for _ in range(10):
        security.record_login_failure("reauth:99")
    check("eşecurile pe cheie internă NU umplu backstop-ul global",
          len(security._global_fails) == 0, len(security._global_fails))

    # ── F-04: executor dedicat pentru argon2 ────────────────────────────────
    check("hashing-ul are pool propriu, nu cel implicit",
          security._pw_pool._max_workers == 2, security._pw_pool._max_workers)
    h = await security.hash_password_async("parola-de-test-1234")
    check("verify_password_async merge", await security.verify_password_async("parola-de-test-1234", h))
    check("verify_password_async respinge parola greşită",
          await security.verify_password_async("altceva", h) is False)

    # ── F-06: biletul de forward nu depăşeşte fereastra de step-up ──────────
    check("FORWARD_TOKEN_TTL rămâne cel lung pentru hosturi fără 2FA",
          security.FORWARD_TOKEN_TTL == 12 * 3600)
    check("plafonul pentru hosturi cu 2FA e fereastra absolută de step-up",
          security.STEPUP_WINDOW_MAX <= security.FORWARD_TOKEN_TTL)
    security.init_crypto(config.load_secret())
    short = security.make_forward_token("slug1", 7, ttl=security.STEPUP_WINDOW_MAX)
    check("biletul scurt e valid acum", security.verify_forward_token(short, "slug1"))
    exp = int(short.split(".")[0])
    check("biletul scurt expiră în ≤ o oră, nu în 12",
          exp - time.time() <= security.STEPUP_WINDOW_MAX + 5)

    await db.close() if db.connected() else None
    print(f"\n{ok}/{total} PASS", flush=True)
    os._exit(0 if ok == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
