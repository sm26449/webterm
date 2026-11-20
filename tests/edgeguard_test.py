"""Protecţia handshake-ului de agent: ce vede administratorul (edgeguard.py, 3.6.38).

Limitele le aplică Traefik; gateway-ul citeşte contoarele lui (Prometheus) şi ţine EPISOADE.
Verificăm, fără reţea şi fără Traefik real:
  * parsarea: doar routerul nostru, 429 = per IP, 529 = global, însumare peste metodă/protocol;
  * diferenţele: linie de bază la prima citire, contor cumulativ, repornirea lui Traefik
    (alt process_start_time_seconds sau valoare care scade) nu pierde şi nu dublează;
  * episoadele: unul pe regulă, actualizat (nu un rând pe cerere), închis după QUIET, redeschis;
  * sursele separate: proxy (autentificare necunoscută) vs gateway (refuz de autentificare);
  * telemetria indisponibilă: starea o spune, refuzurile gateway-ului se numără mai departe,
    la revenire diferenţa acoperă pauza;
  * agent_ws: un token greşit numără în memorie, fără scriere SQLite per cerere;
  * retenţie şi plafon de rânduri; plafonul cheilor per IP din core.
"""
import asyncio
import json
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
os.environ["WEBTERM_AGENT_RL_METRICS_URL"] = "http://traefik:8082/metrics"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import api, audit, core, db, edgeguard, syshealth  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


R = "webterm-agent@docker"


def metrics(c429=0, c529=0, start=1700000000.0, extra=""):
    return ("# HELP traefik_router_requests_total x\n"
            "process_start_time_seconds %s\n" % start +
            'traefik_router_requests_total{code="0",method="GET",protocol="websocket",router="%s",service="webterm@docker"} 50\n' % R +
            'traefik_router_requests_total{code="429",method="GET",protocol="websocket",router="%s",service="webterm@docker"} %s\n' % (R, c429) +
            'traefik_router_requests_total{code="429",method="GET",protocol="http",router="%s",service="webterm@docker"} 1\n' % R +
            'traefik_router_requests_total{code="529",method="GET",protocol="websocket",router="%s",service="webterm@docker"} %s\n' % (R, c529) +
            'traefik_router_requests_total{code="429",method="POST",protocol="http",router="webterm@docker",service="webterm@docker"} 999\n' +
            extra)


async def rows():
    return [dict(r) for r in await db.fetchall("SELECT * FROM edge_episodes ORDER BY id")]


async def audits():
    return [r["detail"] for r in await db.fetchall("SELECT detail FROM audit_log WHERE actor='system:edgeguard' ORDER BY id")]


async def main():
    await db.connect()

    print("== parse")
    m = edgeguard.parse_metrics(metrics(7, 3), R)
    check("429 for our router, summed over protocols (7 + 1)", m["429"] == 8, m)
    check("529 = the global rule", m["529"] == 3, m)
    check("another router's 429 is ignored", m["429"] != 1007, m)
    check("process start time read", m["_start"] == 1700000000.0, m)
    check("router seen", m["_router_seen"] is True)
    check("absent router → not seen, zero", edgeguard.parse_metrics(metrics(), "other@docker")["_router_seen"] is False)
    fwd = 'traefik_router_requests_total{code="429",method="GET",protocol="websocket",router="webterm-agent-fwd@docker",service="webterm@docker"} 4\n'
    m2 = edgeguard.parse_metrics(metrics(7, 3, extra=fwd), ("webterm-agent@docker", "webterm-agent-fwd@docker"))
    check("both agent routers counted (the forward-host one too)", m2["429"] == 12, m2)
    deny = 'traefik_router_requests_total{code="403",method="GET",protocol="websocket",router="webterm-agent-deny@file",service="webterm@docker"} 9\n'
    m3 = edgeguard.parse_metrics(metrics(extra=deny), ("webterm-agent@docker", "webterm-agent-deny@file"))
    check("everything through the deny router counts as 'deny', whatever its code", m3["418"] == 9 and m3["429"] == 1, m3)

    print("== deltas")
    d = edgeguard.deltas({}, {"429": 10, "529": 5, "_start": 1})
    check("first reading is a baseline (0, not the whole history)", d == {"429": 0, "529": 0, "418": 0}, d)
    d = edgeguard.deltas({"429": 10, "529": 5, "_start": 1}, {"429": 14, "529": 5, "_start": 1})
    check("cumulative counter → difference", d == {"429": 4, "529": 0, "418": 0}, d)
    d = edgeguard.deltas({"429": 10, "529": 5, "_start": 1}, {"429": 3, "529": 2, "_start": 2})
    check("Traefik restarted (new start time) → the new value is all new", d == {"429": 3, "529": 2, "418": 0}, d)
    d = edgeguard.deltas({"429": 10, "529": 5}, {"429": 3, "529": 9})
    check("value went down without a start time → treated as a restart", d == {"429": 3, "529": 4, "418": 0}, d)

    print("== episodes from the proxy")
    feed = {"text": metrics(0, 0)}
    fetch = lambda url: feed["text"]                                   # noqa: E731
    t0 = 1_800_000_000.0
    await edgeguard.tick(now=t0, fetch=fetch)                          # baseline
    check("baseline writes no episode", await rows() == [])
    feed["text"] = metrics(40, 0)
    await edgeguard.tick(now=t0 + 30, fetch=fetch)
    r = await rows()
    check("refusals open one per-IP episode", len(r) == 1 and r[0]["source"] == "proxy" and r[0]["rule"] == "ip"
          and r[0]["count"] == 40 and r[0]["ended"] is None, r)
    feed["text"] = metrics(100, 12)
    await edgeguard.tick(now=t0 + 60, fetch=fetch)
    r = await rows()
    check("the same episode is UPDATED (one row per rule, not per request)",
          len([x for x in r if x["rule"] == "ip"]) == 1 and [x for x in r if x["rule"] == "ip"][0]["count"] == 100, r)
    check("the global rule gets its own episode", any(x["rule"] == "global" and x["count"] == 12 for x in r), r)
    ep = (await edgeguard.episodes())[0]
    check("API view: auth result unknown for a proxy refusal", ep["auth"] == "unknown", ep)
    res = await syshealth.c_agent_handshakes()
    check("System health: warning while a proxy episode is open (global first)",
          res.severity == "warning" and res.key == "edge_proxy_global", res)
    # linişte
    await edgeguard.tick(now=t0 + 60 + edgeguard.QUIET + 1, fetch=fetch)
    r = await rows()
    check("no refusals for QUIET → episodes closed at their last sighting",
          all(x["ended"] == t0 + 60 for x in r), r)
    check("health back to ok", (await syshealth.c_agent_handshakes()).key == "edge_ok")
    a = await audits()
    check("start and end of each episode in the audit log (4 rows)", len(a) == 4 and "episode started" in a[0], a)
    check("audit text carries no IP, token or path query", all("Bearer" not in x and "?" not in x for x in a), a)
    feed["text"] = metrics(105, 12)
    await edgeguard.tick(now=t0 + 2000, fetch=fetch)
    r = await rows()
    check("a new burst after the pause → a NEW episode", len(r) == 3 and r[-1]["count"] == 5 and r[-1]["ended"] is None, r)

    print("== gateway refusals (auth result known)")
    for _ in range(25):
        edgeguard.note_gateway_refusal("bad_token")
    edgeguard.note_gateway_refusal("not-a-rule")
    await edgeguard.tick(now=t0 + 2030, fetch=fetch)
    g = [x for x in await rows() if x["source"] == "gateway"]
    check("25 bad tokens = ONE row, count 25", len(g) == 1 and g[0]["rule"] == "bad_token" and g[0]["count"] == 25, g)
    check("unknown rule ignored (fixed cardinality)", all(x["rule"] in ("ip", "global", "bad_token", "instance_conflict") for x in await rows()))
    gv = [e for e in await edgeguard.episodes() if e["source"] == "gateway"][0]
    check("API view: gateway refusal = authentication refused", gv["auth"] == "refused", gv)

    print("== telemetry unavailable")
    def boom(url):
        raise ConnectionRefusedError("traefik down")
    edgeguard.note_gateway_refusal("instance_conflict")
    await edgeguard.tick(now=t0 + 2060, fetch=boom)
    st = edgeguard.status(t0 + 2060)
    check("status says unavailable, with the time it started", st["available"] is False and st["error_since"] == t0 + 2060
          and st["error"] == "ConnectionRefusedError", st)
    check("gateway refusals still counted while the proxy is unreachable",
          any(x["rule"] == "instance_conflict" for x in await rows()))
    await edgeguard.tick(now=t0 + 2300, fetch=boom)
    check("error_since keeps the FIRST failure", edgeguard.status()["error_since"] == t0 + 2060)
    # (episoadele gateway sunt încă deschise → health le arată pe ele întâi; le închidem şi verificăm telemetria)
    await edgeguard.tick(now=t0 + 2700, fetch=boom)
    import types
    real_time = syshealth.time
    syshealth.time = types.SimpleNamespace(time=lambda: t0 + 2700)     # ceasul testului, nu cel real
    try:
        res = await syshealth.c_agent_handshakes()
    finally:
        syshealth.time = real_time
    check("health: info about the missing telemetry once nothing else is open",
          res.key == "edge_telemetry_down", res)
    feed["text"] = metrics(160, 12)                                     # 55 noi în timpul pauzei
    await edgeguard.tick(now=t0 + 2730, fetch=fetch)
    st = edgeguard.status(t0 + 2730)
    check("telemetry back → available, error cleared", st["available"] and not st["error"], st)
    last = (await rows())[-1]
    check("refusals made during the outage are counted on return (cumulative counter)",
          last["rule"] == "ip" and last["count"] == 55, last)

    print("== gateway restart keeps the baseline")
    edgeguard._open.clear()
    edgeguard._loaded = False
    feed["text"] = metrics(170, 12)
    await edgeguard.tick(now=t0 + 2760, fetch=fetch)
    last = [x for x in await rows() if x["rule"] == "ip"][-1]
    check("after a gateway restart the open episode is reloaded and continued (10 more), not duplicated",
          last["count"] == 65 and last["ended"] is None, last)

    print("== agent_ws: a bad token costs no write")
    class _C:
        host = "203.0.113.9"
    class WS:
        scope = {}
        headers = {"authorization": "Bearer wrong"}
        client = _C()
        closed = None
        async def close(self, code=1000, reason=""):
            self.closed = code
        async def accept(self):
            raise AssertionError("must not accept")
    before = edgeguard._pending.get(("gateway", "bad_token"), 0)
    w = WS()
    await api.agent_ws(w)
    check("refused with 4401", w.closed == 4401)
    check("counted in memory", edgeguard._pending.get(("gateway", "bad_token"), 0) == before + 1)

    print("== agent_ws: an encoded path is refused before any lookup")
    w2 = WS(); w2.scope = {"raw_path": b"/agent%2Fws"}
    before = edgeguard._pending.get(("gateway", "bad_path"), 0)
    real_fetch = db.fetchone
    calls = []
    async def spy(*a, **k):
        calls.append(a[0]); return await real_fetch(*a, **k)
    db.fetchone = spy
    try:
        await api.agent_ws(w2)
    finally:
        db.fetchone = real_fetch
    check("/agent%2Fws closed with 4400", w2.closed == 4400, w2.closed)
    check("no DB read for it", calls == [], calls)
    check("counted as bad_path", edgeguard._pending.get(("gateway", "bad_path"), 0) == before + 1)
    w3 = WS(); w3.scope = {"raw_path": b"/agent/ws"}
    await api.agent_ws(w3)
    check("the literal path still reaches the token check (4401)", w3.closed == 4401, w3.closed)

    print("== web refusals: sign-ins, API tokens, browser WebSockets")
    edgeguard._pending.clear(); edgeguard._pending_src.clear()
    for _ in range(7):
        edgeguard.note_web_refusal("login_failed", "203.0.113.30")
    edgeguard.note_web_refusal("login_failed", "2001:db8:9:9::1")
    edgeguard.note_web_refusal("ws_refused", "198.51.100.4", "/ws/shared/SECRET-share-token-abc?x=1")
    edgeguard.note_web_refusal("ws_refused", "198.51.100.4", "/api/live/ws")
    edgeguard.note_web_refusal("nonsense", "198.51.100.4")
    await edgeguard.tick(now=t0 + 5000, fetch=fetch)
    w = {e["rule"]: e for e in await edgeguard.episodes() if e["source"] == "web" and e["active"]}
    check("failed sign-ins → one episode with its sources", w.get("login_failed", {}).get("count") == 8 and
          dict(w["login_failed"]["sources"]) == {"203.0.113.30": 7, "2001:db8:9:9::/64": 1}, w.get("login_failed"))
    ws_src = dict(w.get("ws_refused", {}).get("sources", []))
    check("refused WebSockets keyed by address + first two path segments", ws_src == {"198.51.100.4 /ws/shared": 1, "198.51.100.4 /api/live": 1}, ws_src)
    check("a share token in the path never reaches the episode", "SECRET" not in json.dumps(await edgeguard.episodes()))
    check("unknown web rule ignored", "nonsense" not in w)
    edgeguard._pending.clear(); edgeguard._pending_src.clear()
    for i in range(edgeguard.MAX_PENDING_SOURCES + 40):
        edgeguard.note_web_refusal("api_token_bad", "10.1.%d.%d" % (i // 256, i % 256))
    await edgeguard.tick(now=t0 + 5030, fetch=fetch)
    a = [e for e in await edgeguard.episodes() if e["rule"] == "api_token_bad"][0]
    check("sources bounded: TOP_SOURCES named + 'other'", len(a["sources"]) <= edgeguard.TOP_SOURCES + 1 and
          dict(a["sources"]).get("other", 0) >= 40 and a["count"] == edgeguard.MAX_PENDING_SOURCES + 40, a["sources"][-2:])

    print("== the API-token hook in security")
    from app import security as _sec
    class _R:
        headers = {"authorization": "Bearer wt_not-a-real-token"}
        client = type("C", (), {"host": "192.0.2.77"})()
    before = edgeguard._pending.get(("web", "api_token_bad"), 0)
    check("an invalid API token is refused", await _sec.api_token_principal(_R()) is None)
    check("…and counted, with no other effect", edgeguard._pending.get(("web", "api_token_bad"), 0) == before + 1)

    print("== the WebSocket refusal middleware")
    from app import main as _main
    async def refuse(scope, receive, send):
        await send({"type": "websocket.close", "code": 1008})
    async def accept(scope, receive, send):
        await send({"type": "websocket.accept"}); await send({"type": "websocket.close", "code": 1000})
    async def noop_send(m):
        pass
    async def rcv():
        return {"type": "websocket.connect"}
    def scope(path):
        return {"type": "websocket", "path": path, "headers": [], "client": ("203.0.113.40", 5555), "query_string": b""}
    before = edgeguard._pending.get(("web", "ws_refused"), 0)
    await _main.WsRefusalMiddleware(refuse)(scope("/ws/sessions/abc"), rcv, noop_send)
    check("closed before accept → counted", edgeguard._pending.get(("web", "ws_refused"), 0) == before + 1)
    await _main.WsRefusalMiddleware(accept)(scope("/ws/sessions/abc"), rcv, noop_send)
    check("accepted then closed → not counted", edgeguard._pending.get(("web", "ws_refused"), 0) == before + 1)
    await _main.WsRefusalMiddleware(refuse)(scope("/agent/ws"), rcv, noop_send)
    check("/agent/ws left to its own counters", edgeguard._pending.get(("web", "ws_refused"), 0) == before + 1)

    print("== retention and caps")
    await db.execute("UPDATE edge_episodes SET ended=?, last_seen=? WHERE id=1", 1.0, 1.0)
    await edgeguard.prune(now=t0 + 3000)
    check("ended episodes older than RETAIN_DAYS are deleted", all(x["id"] != 1 for x in await rows()))
    for i in range(edgeguard.MAX_ROWS + 20):
        await db.execute("INSERT INTO edge_episodes(source, rule, started, last_seen, ended, count) VALUES('proxy','ip',?,?,?,1)",
                         t0 + 3000 + i, t0 + 3000 + i, t0 + 3000 + i)
    await edgeguard.prune(now=t0 + 3500)
    n = (await db.fetchone("SELECT COUNT(*) AS c FROM edge_episodes WHERE ended IS NOT NULL"))["c"]
    check("at most MAX_ROWS ended episodes kept", n <= edgeguard.MAX_ROWS, n)
    check("open episodes are never pruned",
          (await db.fetchone("SELECT COUNT(*) AS c FROM edge_episodes WHERE ended IS NULL"))["c"] >= 1)
    core._handshake_last.clear()
    for i in range(core.HANDSHAKE_KEYS_MAX + 50):
        core.handshake_log_allowed("ip:198.51.%d.%d" % (i // 256, i % 256))
    check("per-IP log keys stay bounded under a many-address flood",
          len(core._handshake_last) <= core.HANDSHAKE_KEYS_MAX + 1, len(core._handshake_last))

    print("== disabled (no Traefik)")
    edgeguard.config.AGENT_RL_METRICS_URL = ""
    await edgeguard.tick(now=t0 + 4000, fetch=boom)
    st = edgeguard.status()
    check("no metrics URL → not configured, not an error", st["configured"] is False and st["available"] is False)

    await db.close()


asyncio.run(main())
print("\n%d/%d passed" % (ok, total))
sys.exit(0 if ok == total else 1)
