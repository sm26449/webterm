"""Handshake-urile de agent REFUZATE lasă urme (audit UX §1.2): un `close()` înainte de
`accept()` arată identic la agent pentru token invalid şi pentru conflict de instanţă, iar
gateway-ul nu scria nimic — omul vedea „Waiting for the agent connection…" la nesfârşit.

Acum:
  * token necunoscut → WARNING cu IP-ul + eveniment `handshake_refused/handshake_bad_token`
    pe hosturile care nu s-au conectat NICIODATĂ (acolo aşteaptă omul), cu IP-ul în detail;
  * instanţă diferită de cea pinată → `handshake_instance_conflict` (pe lângă evenimentul
    `instance_refused` existent);
  * plafon: un rând pe minut per motiv per host (agentul reîncearcă în buclă);
  * evenimentele apar în `GET /api/hosts/{id}/events`.

Apelăm handlerul `agent_ws` cu un WebSocket fals (fără reţea, fără agent real).
"""
import asyncio
import logging
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import api, config, core, db, email_alerts, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


class _Client:
    def __init__(self, host):
        self.host = host


class FakeWS:
    def __init__(self, headers, ip="10.0.0.5"):
        self.headers = headers
        self.client = _Client(ip)
        self.closed = None
        self.accepted = False

    async def close(self, code=1000, reason=""):
        self.closed = code

    async def accept(self):
        self.accepted = True


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


async def _insert_host(name, ctype="agent", agent_version=None, instance_id=None):
    tok = security.new_token()
    await db.execute(
        "INSERT INTO hosts(name, token_hash, token_encrypted, created, connection_type, agent_version, instance_id)"
        " VALUES(?,?,?,?,?,?,?)",
        name, security.sha256_hex(tok), security.encrypt_secret(tok), time.time(), ctype, agent_version, instance_id)
    return (await db.fetchone("SELECT id FROM hosts WHERE name=?", name))["id"], tok


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    cap = _Capture()
    logging.getLogger().addHandler(cap)
    logging.getLogger().setLevel(logging.INFO)
    email_alerts.notify_agent_relocation = lambda *a, **k: None

    pending, _ = await _insert_host("pending")                      # niciodată conectat
    online, _ = await _insert_host("online", agent_version=50)      # a mai fost online
    sshhost, _ = await _insert_host("sshbox", ctype="ssh")          # nu e host de agent

    # ── token necunoscut ──
    ws = FakeWS({"authorization": "Bearer nu-exista-asa-ceva"})
    await api.agent_ws(ws)
    check("token necunoscut → close 4401, fără accept", ws.closed == 4401 and not ws.accepted)
    check("… WARNING cu IP-ul sursă", any("unknown token" in ln and "10.0.0.5" in ln for ln in cap.lines),
          str(cap.lines[-3:]))
    ev = await db.fetchall("SELECT host_id, event, reason, detail FROM agent_events ORDER BY id")
    pend_ev = [e for e in ev if e["host_id"] == pending]
    check("… eveniment handshake_refused/handshake_bad_token pe hostul NECONECTAT încă",
          len(pend_ev) == 1 and pend_ev[0]["event"] == "handshake_refused"
          and pend_ev[0]["reason"] == "handshake_bad_token", str([dict(e) for e in ev]))
    check("… detail conţine IP-ul", pend_ev and "10.0.0.5" in pend_ev[0]["detail"])
    check("… NU pe hostul care a mai fost online, nici pe hostul SSH",
          not any(e["host_id"] in (online, sshhost) for e in ev))

    # plafon: a doua încercare în acelaşi minut nu mai scrie
    ws2 = FakeWS({"authorization": "Bearer alt-token-gresit"})
    await api.agent_ws(ws2)
    n = (await db.fetchone("SELECT COUNT(*) c FROM agent_events WHERE host_id=? AND reason='handshake_bad_token'", pending))["c"]
    check("plafon: a doua refuzare în acelaşi minut NU adaugă rând", n == 1, str(n))
    # după expirarea ferestrei se scrie din nou
    core._handshake_last.clear()
    await api.agent_ws(FakeWS({"authorization": "Bearer inca-unul"}, ip="10.0.0.6"))
    n = (await db.fetchone("SELECT COUNT(*) c FROM agent_events WHERE host_id=? AND reason='handshake_bad_token'", pending))["c"]
    check("după fereastră: se scrie din nou (cu noul IP)", n == 2, str(n))

    # ── conflict de instanţă (token valid, maşină diferită de cea pinată) ──
    pinned, tok = await _insert_host("pinned", agent_version=50, instance_id="abcdef1234567890")
    ws3 = FakeWS({"authorization": "Bearer " + tok, "x-webterm-instance": "ffffffff00000000"}, ip="10.0.0.7")
    await api.agent_ws(ws3)
    check("instanţă diferită → close 4409", ws3.closed == 4409 and not ws3.accepted, str(ws3.closed))
    ev = await db.fetchall("SELECT event, reason, detail FROM agent_events WHERE host_id=? ORDER BY id", pinned)
    check("… evenimentul istoric instance_refused rămâne",
          any(e["reason"] == "instance_refused" for e in ev), str([dict(e) for e in ev]))
    hc = [e for e in ev if e["reason"] == "handshake_instance_conflict"]
    check("… + handshake_refused/handshake_instance_conflict cu IP şi instanţele",
          len(hc) == 1 and "10.0.0.7" in hc[0]["detail"] and "ffffffff" in hc[0]["detail"], str([dict(e) for e in ev]))
    check("… WARNING-ul de conflict conţine IP-ul", any("refusing agent from 10.0.0.7" in ln for ln in cap.lines))
    # al doilea conflict în acelaşi minut: instance_refused se scrie (istoric), conflictul plafonat nu
    await api.agent_ws(FakeWS({"authorization": "Bearer " + tok, "x-webterm-instance": "ffffffff00000000"}, ip="10.0.0.7"))
    n = (await db.fetchone("SELECT COUNT(*) c FROM agent_events WHERE host_id=? AND reason='handshake_instance_conflict'", pinned))["c"]
    check("plafon şi pe conflictul de instanţă", n == 1, str(n))

    # ── vizibile în GET /api/hosts/{id}/events ──
    out = await api.host_events(pending, user={"id": 1})
    reasons = [e["reason"] for e in out.get("events", [])] if isinstance(out, dict) else []
    if not reasons and isinstance(out, dict):
        # forma răspunsului poate diferi; căutăm orice listă cu dict-uri cu `reason`
        for v in out.values():
            if isinstance(v, list) and v and isinstance(v[0], dict) and "reason" in v[0]:
                reasons = [e["reason"] for e in v]
    check("GET /api/hosts/{id}/events listează handshake_bad_token", "handshake_bad_token" in reasons, str(out)[:200])

    await db.close()
    print(f"\n{ok}/{total} teste trecute")
    sys.stdout.flush()
    os._exit(0 if ok == total else 1)


asyncio.run(main())
