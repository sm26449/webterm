"""Flota de agenţi în System health (GET /api/health/agents, 3.7.0).

  * doar hosturile agent (nu SSH/telnet) şi doar cele pe care apelantul le vede (host.view);
  * ruta: "mtls" când conexiunea vie a venit cu certificat, "token" altfel, null când e offline;
  * reconnects_24h = evenimentele `connect` din ultimele 24 h (cele mai vechi nu contează);
  * nimic secret în răspuns: fără token, hash, serial de certificat;
  * jurnalul de connect poartă ruta („v60 · mTLS" / „v60 · token").
"""
import asyncio
import json
import os
import sys
import tempfile
import time
import types

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import api, authz, config, core, db, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


def req(grants):
    return types.SimpleNamespace(state=types.SimpleNamespace(grants=grants))


def live(via_mtls, since):
    # o AgentConnection reală (isinstance contează), fără ws: ruta citeşte doar câmpurile
    c = object.__new__(core.AgentConnection)
    c.via_mtls = via_mtls
    c.connected_at = since
    return c


TOKEN = "tok-secret-" + "z" * 30
SERIAL = "ABCDEF0123456789SERIAL"


async def main():
    await db.connect()
    try:
        await body()
    finally:
        await db.close()        # altfel firul aiosqlite ţine procesul viu după o excepţie


async def body():
    security.init_crypto(config.load_secret())
    ids = {}
    for name, folder in (("alpha", "prod"), ("beta", "prod"), ("gamma", "lab")):
        await db.execute("INSERT INTO hosts(name, folder, token_hash, token_encrypted, created, agent_version,"
                         " agent_ip, last_heartbeat) VALUES(?,?,?,?,0,60,'198.51.100.7',?)",
                         name, folder, security.sha256_hex(TOKEN + name), security.encrypt_secret(TOKEN + name), time.time())
        ids[name] = (await db.fetchone("SELECT id FROM hosts WHERE name=?", name))["id"]
    await db.execute("UPDATE hosts SET mtls_serial=?, mtls_required=1, mtls_not_after=? WHERE id=?",
                     SERIAL, time.time() + 30 * 86400, ids["alpha"])
    await db.execute("INSERT INTO hosts(name, hostname, connection_type, token_hash, token_encrypted, created)"
                     " VALUES('sshbox','10.0.0.9','ssh','x','',0)")
    sshid = (await db.fetchone("SELECT id FROM hosts WHERE name='sshbox'"))["id"]

    now = time.time()
    core.sources[ids["alpha"]] = live(True, now - 120)
    core.sources[ids["beta"]] = live(False, now - 60)
    core.sources[sshid] = object()        # o sursă SSH vie: nu e agent, nu apare
    for ts in (now - 10, now - 3600, now - 90000):        # ultima e în afara ferestrei de 24 h
        await db.execute("INSERT INTO agent_events(host_id, ts, event, reason, detail) VALUES(?,?,?,?,?)",
                         ids["alpha"], ts, "connect", "", "v60 · mTLS")
    await db.execute("INSERT INTO agent_events(host_id, ts, event, reason, detail) VALUES(?,?,?,?,?)",
                     ids["alpha"], now - 5, "disconnect", "closed", "")

    owner = authz.Grants(1, [], frozenset({"security.view"}), frozenset({"host.view"}))
    out = await api.health_agents(req(owner), user=None)
    by = {a["name"]: a for a in out["agents"]}

    print("== who is listed")
    check("only agent hosts (the SSH host is left out)", set(by) == {"alpha", "beta", "gamma"}, sorted(by))
    b = authz.Binding(1, "viewer", "Viewer", frozenset({"host.view"}), "folder", "lab", "local", None)
    scoped = authz.Grants.from_bindings(2, [b])
    s = await api.health_agents(req(scoped), user=None)
    check("a scoped account sees only its hosts", [a["name"] for a in s["agents"]] == ["gamma"],
          [a["name"] for a in s["agents"]])
    check("…and the summary counts only those",
          s["summary"]["online"] == 0 and s["summary"]["offline"] == 1 and s["summary"]["versions"] == {"60": 1},
          s["summary"])
    none = await api.health_agents(req(None), user=None)
    check("no grants → nothing (fail closed)", none["agents"] == [], none["agents"])

    print("== route and state")
    check("route mtls when the live connection came with a certificate", by["alpha"]["route"] == "mtls")
    check("route token when online without it", by["beta"]["route"] == "token")
    check("route null and offline when not connected",
          by["gamma"]["route"] is None and by["gamma"]["online"] is False and by["gamma"]["connected_since"] is None)
    check("connected_since from the live connection", abs(by["alpha"]["connected_since"] - (now - 120)) < 1)
    check("mTLS fields", by["alpha"]["mtls_required"] is True and by["alpha"]["mtls_issued"] is True
          and by["beta"]["mtls_issued"] is False and by["alpha"]["mtls_not_after"] > now)
    check("reconnects_24h counts connects in the last 24 h only",
          by["alpha"]["reconnects_24h"] == 2 and by["beta"]["reconnects_24h"] == 0, by["alpha"]["reconnects_24h"])
    sm = out["summary"]
    check("summary", sm["online"] == 2 and sm["offline"] == 1 and sm["mtls"] == 1 and sm["token"] == 1
          and sm["versions"] == {"60": 3}, sm)

    print("== no secrets")
    blob = json.dumps(out)
    check("no token, hash or serial in the payload",
          TOKEN not in blob and security.sha256_hex(TOKEN + "alpha") not in blob and SERIAL not in blob
          and "token_hash" not in blob and "mtls_serial" not in blob)

    print("== the connect journal carries the route")
    src = open(os.path.join(os.path.dirname(__file__), "..", "gateway", "app", "core.py")).read()
    check("connect detail = version · route",
          '"mTLS" if self.via_mtls else "token"' in src and '"v%s · %s" % (v, route)' in src)

    for k in (ids["alpha"], ids["beta"], sshid):
        core.sources.pop(k, None)


asyncio.run(main())
print("\n%d/%d teste trecute" % (ok, total))
sys.exit(0 if ok == total else 1)
