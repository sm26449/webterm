"""Limita per IP pe link-urile de share LIVE (3.5.15).

`/api/shared/{token}` şi `/ws/shared/{token}` erau singurele endpoint-uri publice cu token fără
nicio limită per IP (replay-ul o avea din 3.5.12). Acum folosesc acelaşi limitator
(`replay.PublicLimiter`), cu găleată PROPRIE (`replay.SHARE_LIMIT`). Verificăm:
  * plafonul total per IP → 429 + Retry-After (meta) / close 4429 (WS);
  * blocarea pe eşecuri e valabilă şi pentru tokenul VALID (altfel blocajul ar fi un oracol);
  * WS-ul blocat se închide ÎNAINTE de lookup şi de accept (nu află nimic, nici despre un token bun);
  * găleţile sunt separate: un IP blocat pe share-uri nu e blocat pe replay (şi invers), iar alt
    IP nu e afectat;
  * calea fericită rămâne neschimbată (meta 200, WS acceptat).
"""
import asyncio
import os
import sys
import tempfile
import time
from types import SimpleNamespace

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, replay, security  # noqa: E402
from app.main import app  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class _Accepted(Exception):
    """Oprim handler-ul WS la accept(): ce urmează (hub, replay) nu ţine de limită."""


class FakeWS:
    def __init__(self, ip, origin="http://localhost:8000"):
        self.headers = {"origin": origin}
        self.client = SimpleNamespace(host=ip)
        self.query_params = {}
        self.closed = None
        self.accepted = False

    async def close(self, code=1000):
        self.closed = code

    async def accept(self):
        self.accepted = True
        raise _Accepted()


async def ws_try(token, ip):
    ws = FakeWS(ip)
    try:
        await api.shared_ws(ws, token)
    except _Accepted:
        pass
    return ws


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    # o sesiune închisă cu un share valid (token în clar aici, hash în DB — ca în producţie)
    hid = 1          # sesiune închisă: hostul nu e atins (fără hub, fără agent)
    good = security.new_token()
    sid = "a" * 32
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,rows,cols,share_token,share_expires)"
        " VALUES(?,?,?,?,?,?,?,?,?)", sid, hid, "demo", "closed", time.time(), 24, 80,
        security.sha256_hex(good), time.time() + 3600)

    def client(ip):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 1234)),
                                 base_url="http://t")

    lim = replay.SHARE_LIMIT
    async with client("198.51.100.1") as c, client("198.51.100.2") as other:
        # ── calea fericită ──
        replay.reset_limits()
        r = await c.get(f"/api/shared/{good}")
        check("meta cu token valid → 200", r.status_code == 200 and r.json()["title"] == "demo", r.text[:200])
        ws = await ws_try(good, "198.51.100.1")
        check("WS cu token valid → acceptat", ws.accepted and ws.closed is None, str(ws.closed))
        ws = await ws_try("nu-exista-token-0123", "198.51.100.1")
        check("WS cu token greşit → 4404 (neschimbat)", ws.closed == 4404 and not ws.accepted, str(ws.closed))

        # ── blocare pe eşecuri: şi tokenul VALID primeşte 429 (fără oracol) ──
        replay.reset_limits()
        for _ in range(lim.miss_max):
            await c.get(f"/api/shared/{security.new_token()}")
        r = await c.get(f"/api/shared/{good}")
        check("după MISS_MAX tokenuri greşite, şi tokenul VALID → 429 + Retry-After",
              r.status_code == 429 and r.headers.get("retry-after")
              and r.headers.get("x-webterm-error") == "share.rateLimited", f"{r.status_code} {dict(r.headers)}")
        ws = await ws_try(good, "198.51.100.1")
        check("…iar WS-ul aceluiaşi IP se închide 4429 ÎNAINTE de accept (nici tokenul valid nu trece)",
              ws.closed == 4429 and not ws.accepted, str(ws.closed))
        r = await other.get(f"/api/shared/{good}")
        check("alt IP nu e afectat", r.status_code == 200, str(r.status_code))
        check("găleată separată: IP-ul blocat pe share-uri nu e blocat pe replay",
              replay.REPLAY_LIMIT.gate("198.51.100.1") == 0)

        # ── eşecurile pe WS se numără la fel ──
        replay.reset_limits()
        for _ in range(lim.miss_max):
            await ws_try(security.new_token(), "198.51.100.3")
        ws = await ws_try(good, "198.51.100.3")
        check("MISS_MAX tokenuri greşite pe WS → blocat (4429) şi pentru tokenul valid",
              ws.closed == 4429 and not ws.accepted, str(ws.closed))
        async with client("198.51.100.3") as c3:
            r = await c3.get(f"/api/shared/{good}")
            check("…şi meta-ul aceluiaşi IP → 429 (aceeaşi găleată: o pagină = meta + WS)",
                  r.status_code == 429, str(r.status_code))

        # ── plafonul total ──
        replay.reset_limits()
        codes = [(await c.get(f"/api/shared/{good}")).status_code for _ in range(lim.rate_max + 1)]
        check("plafonul total per IP: după RATE_MAX cereri → 429",
              codes[:-1] == [200] * lim.rate_max and codes[-1] == 429, codes[-3:])

        # ── replay blocat nu blochează share-ul ──
        replay.reset_limits()
        for _ in range(replay.MISS_MAX):
            replay.record_miss("198.51.100.1")
        check("replay blocat pentru IP…", replay.gate("198.51.100.1") > 0)
        r = await c.get(f"/api/shared/{good}")
        check("…dar share-ul aceluiaşi IP merge (găleţi separate)", r.status_code == 200, str(r.status_code))

        # ── tokenuri absurde nu ating DB-ul, dar se numără ca eşec ──
        replay.reset_limits()
        r = await c.get("/api/shared/" + "x" * 300)
        check("token supradimensionat → 404 link.invalid", r.status_code == 404
              and r.headers.get("x-webterm-error") == "link.invalid", str(r.status_code))
        check("…şi contează la eşecuri", len(lim._miss.get("198.51.100.1", [])) == 1, str(lim._miss))

    # ── contractul cu UI-ul ──
    lang_dir = os.path.join(os.path.dirname(__file__), "..", "frontend", "src", "lang")
    for lang in ("en", "ro"):
        src = open(os.path.join(lang_dir, lang + ".ts"), encoding="utf-8").read()
        check(f"{lang}.ts: mesajele 429 / 4429 ale share-ului există",
              "'err.share.rateLimited':" in src and "'share.errRateLimitedWs':" in src)
    sv = open(os.path.join(os.path.dirname(__file__), "..", "frontend", "src", "components",
                           "SharedView.tsx"), encoding="utf-8").read()
    check("SharedView tratează 4429 (nu-l confundă cu „deconectat”)", "4429" in sv)

    replay.reset_limits()
    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
