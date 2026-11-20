"""Poarta handshake-ului de agent, în memorie (agentgate.py, 3.6.38).

Cerinţa: un robot cu token lipsă sau greşit nu ne face să citim/scriem în SQLite la fiecare cerere;
un token bun trece mereu. Fără reţea, fără Traefik: apelăm `api.agent_ws` cu un WebSocket fals şi
numărăm citirile din DB.
  * token lipsă → refuz 4401, ZERO citiri;
  * token greşit → o citire, strike; după STRIKES strike-uri adresa e blocată;
  * adresă blocată + token necunoscut → refuz 4429, ZERO citiri, numărat (edgeguard „blocked");
  * adresă blocată + token CUNOSCUT → trece (NAT împărţit cu un atacator);
  * host nou, încă necunoscut în memorie → trece prin citirea din DB cât adresa nu e blocată;
  * IPv6 pe /64, IPv4-mapat, sursă nedeterminată = o singură cheie;
  * recidivă: blocarea se dublează până la BLOCK_MAX; memoria e plafonată.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import agentgate, api, db, edgeguard, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


class _C:
    def __init__(self, host):
        self.host = host


class WS:
    def __init__(self, ip, token=None, path=b"/agent/ws"):
        self.client = _C(ip)
        self.headers = {"authorization": "Bearer " + token} if token else {}
        self.scope = {"raw_path": path}
        self.closed = None
        self.accepted = False

    async def close(self, code=1000, reason=""):
        self.closed = code

    async def accept(self):
        self.accepted = True
        raise RuntimeError("stop after accept")      # nu vrem să rulăm conexiunea în test


reads = []
_real_fetchone = db.fetchone


async def spy(sql, *a):
    reads.append(sql)
    return await _real_fetchone(sql, *a)


async def handshake(ip, token=None, path=b"/agent/ws"):
    w = WS(ip, token, path)
    reads.clear()
    db.fetchone = spy
    try:
        await api.agent_ws(w)
    except RuntimeError:
        pass
    finally:
        db.fetchone = _real_fetchone
    return w, [r for r in reads if "FROM hosts WHERE token_hash" in r]


async def main():
    await db.connect()
    good = "good-token-" + "x" * 20
    await db.execute("INSERT INTO hosts(name, token_hash, token_encrypted, created) VALUES('h1', ?, '', 0)", security.sha256_hex(good))
    agentgate.reset_for_tests()

    print("== missing token")
    w, r = await handshake("203.0.113.10")
    check("no token → 4401", w.closed == 4401, w.closed)
    check("no token → no token lookup", r == [], r)

    print("== wrong token: strikes, then a block")
    bad_ip = "203.0.113.20"
    lookups = 0
    for i in range(agentgate.STRIKES):
        w, r = await handshake(bad_ip, "wrong-%d" % i)
        lookups += len(r)
    check("each wrong token before the block costs one lookup", lookups == agentgate.STRIKES, lookups)
    check("after STRIKES wrong tokens the address is blocked", agentgate.blocked(bad_ip))
    before = edgeguard._pending.get(("gateway", "blocked"), 0)
    for i in range(50):
        w, r = await handshake(bad_ip, "flood-%d" % i)
        if r or w.closed != 4429:
            break
    check("50 more from the blocked address: 4429, zero lookups", w.closed == 4429 and r == [], (w.closed, r))
    check("counted for the admin view (edgeguard 'blocked')",
          edgeguard._pending.get(("gateway", "blocked"), 0) - before == 50)
    check("blocked count visible", agentgate.blocked_count() == 1, agentgate.blocked_count())
    w, r = await handshake(bad_ip)
    check("missing token from a blocked address: still no lookup", r == [] and w.closed == 4401)

    print("== a valid token passes, even from a blocked address (shared NAT)")
    await agentgate.refresh_known(force=True)
    w, r = await handshake(bad_ip, good)
    check("known token from a blocked address reaches accept()", w.accepted, w.closed)

    print("== a host created a moment ago (not yet in memory)")
    new = "new-host-token-" + "y" * 20
    await db.execute("INSERT INTO hosts(name, token_hash, token_encrypted, created) VALUES('h2', ?, '', 0)", security.sha256_hex(new))
    check("not in the in-memory set yet", not agentgate.is_known(security.sha256_hex(new)))
    w, r = await handshake("198.51.100.7", new)
    check("an unblocked address gets the DB lookup and connects", w.accepted and len(r) == 1, (w.closed, r))
    check("…and the token is remembered", agentgate.is_known(security.sha256_hex(new)))

    print("== address keys")
    check("IPv6 is keyed on its /64", agentgate.ip_key("2001:db8:1:2::5") == agentgate.ip_key("2001:db8:1:2:ffff::9"))
    check("another /64 is another key", agentgate.ip_key("2001:db8:1:3::5") != agentgate.ip_key("2001:db8:1:2::5"))
    check("IPv4-mapped IPv6 = the IPv4", agentgate.ip_key("::ffff:203.0.113.5") == "203.0.113.5")
    check("an undeterminable source shares ONE key", agentgate.ip_key("?") == agentgate.ip_key("") == "unknown")
    v6 = "2001:db8:aa:bb::1"
    for i in range(agentgate.STRIKES):
        agentgate.strike("2001:db8:aa:bb::%x" % (i + 10))
    check("rotating addresses inside one /64 does not escape the block", agentgate.blocked(v6))

    print("== repeat offenders, memory cap")
    agentgate.reset_for_tests()
    t = 1_000_000.0
    durations = []
    for rnd in range(9):
        for i in range(agentgate.STRIKES):
            agentgate.strike("192.0.2.9", now=t)
        st = agentgate._state[agentgate.ip_key("192.0.2.9")]
        durations.append(st[2] - t)
        t = st[2] + 1
    check("the block doubles on each repeat", durations[:3] == [600.0, 1200.0, 2400.0], durations[:3])
    check("…and stops at BLOCK_MAX", max(durations) == agentgate.BLOCK_MAX, durations)
    agentgate.reset_for_tests()
    for i in range(agentgate.MAX_KEYS + 500):
        agentgate.strike("10.%d.%d.%d" % (i >> 16 & 255, i >> 8 & 255, i & 255), now=2_000_000.0 + i)
    check("tracked addresses stay bounded", len(agentgate._state) <= agentgate.MAX_KEYS + 1, len(agentgate._state))

    print("== concurrency: 40 simultaneous wrong tokens from one address")
    agentgate.reset_for_tests()
    reads.clear()
    async def slow_fetch(sql, *a):
        reads.append(sql)
        await asyncio.sleep(0.01)                  # o citire lentă: toate cererile ajung „în zbor"
        return await _real_fetchone(sql, *a)
    db.fetchone = slow_fetch
    ws_list = [WS("203.0.113.88", "conc-%d" % i) for i in range(40)]
    try:
        await asyncio.gather(*(api.agent_ws(w) for w in ws_list), return_exceptions=True)
    finally:
        db.fetchone = _real_fetchone
    n = len([r for r in reads if "FROM hosts WHERE token_hash" in r])
    check("at most STRIKES lookups even when all 40 arrive together", n <= agentgate.STRIKES, n)
    check("the rest were refused in memory (4429)", sum(1 for w in ws_list if w.closed == 4429) >= 40 - agentgate.STRIKES)
    print("== a valid token does not leave a strike behind")
    agentgate.reset_for_tests()
    for _ in range(agentgate.STRIKES + 3):
        w, r = await handshake("203.0.113.99", new)          # tokenul nou, încă necunoscut în memorie
        agentgate._known.discard(security.sha256_hex(new))     # forţăm calea „necunoscut → DB" de fiecare dată
    check("repeated valid-but-unknown tokens never block the address", not agentgate.blocked("203.0.113.99"))

    print("== review fixes")
    agentgate.reset_for_tests()
    calls = []
    real_fetchall = db.fetchall
    async def slow_all(sql, *a):
        calls.append(sql); await asyncio.sleep(0.01); return await real_fetchall(sql, *a)
    db.fetchall = slow_all
    try:
        await asyncio.gather(*(agentgate.refresh_known() for _ in range(200)))
    finally:
        db.fetchall = real_fetchall
    check("200 concurrent refreshes = ONE SELECT", len(calls) == 1, len(calls))
    import time as _t
    agentgate.reset_for_tests()
    t0 = _t.perf_counter()
    for i in range(agentgate.MAX_KEYS + 2000):
        agentgate.strike("10.%d.%d.%d" % (i >> 16 & 255, i >> 8 & 255, i & 255), now=3_000_000.0)
    dt = _t.perf_counter() - t0
    check("eviction at the cap stays cheap (52k new addresses < 2 s)", dt < 2.0, dt)
    check("…and bounded", len(agentgate._state) <= agentgate.MAX_KEYS, len(agentgate._state))
    agentgate.reset_for_tests()
    for i in range(agentgate.STRIKES - 1):
        agentgate.strike("203.0.113.50", now=4_000_000.0)
    trig = agentgate.strike("203.0.113.50", now=4_000_000.0)
    agentgate.forgive("203.0.113.50", trig)
    check("forgiving the strike that blocked: unblocked, but the other strikes stay",
          trig and not agentgate.blocked("203.0.113.50", now=4_000_001.0)
          and agentgate._state[agentgate.ip_key("203.0.113.50")][0] == agentgate.STRIKES - 1)
    check("…so the very next wrong token blocks again", agentgate.strike("203.0.113.50", now=4_000_002.0))
    agentgate.reset_for_tests()
    tt = 5_000_000.0
    for rnd in range(3):
        for i in range(agentgate.STRIKES):
            agentgate.strike("198.51.100.60", now=tt)
        tt = agentgate._state[agentgate.ip_key("198.51.100.60")][2] + 1
    tt += agentgate.BLOCK_MAX + 10                 # o zi întreagă fără nimic
    for i in range(agentgate.STRIKES):
        agentgate.strike("198.51.100.60", now=tt)
    st = agentgate._state[agentgate.ip_key("198.51.100.60")]
    check("the repeat level is forgotten after a quiet day (block back to BLOCK_BASE)",
          st[2] - tt == agentgate.BLOCK_BASE, st[2] - tt)
    from app import core
    core._handshake_last.clear()
    core._handshake_last[(7, "handshake_bad_token")] = _t.time()
    for i in range(core.HANDSHAKE_KEYS_MAX + 50):
        core.handshake_log_allowed("ip:198.18.%d.%d" % (i // 256, i % 256))
    check("the per-host event throttle survives a many-address flood", (7, "handshake_bad_token") in core._handshake_last)

    print("== bad path counts as a strike")
    agentgate.reset_for_tests()
    for _ in range(agentgate.STRIKES):
        w, r = await handshake("203.0.113.77", good, path=b"/agent%2Fws")
    check("encoded path refused 4400 with no lookup", w.closed == 4400 and r == [], (w.closed, r))
    check("…and enough of them block the address", agentgate.blocked("203.0.113.77"))

    await db.close()


asyncio.run(main())
print("\n%d/%d passed" % (ok, total))
sys.exit(0 if ok == total else 1)
