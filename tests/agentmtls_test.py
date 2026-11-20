"""mTLS pentru agenţi, partea din gateway (edgemtls.py + api.agent_ws, 3.7.0).

  * configuraţia Traefik: opţiunile TLS cu CA-ul nostru, routerul pe numele de agenţi, antetul-secret;
    oprită (document gol) cu WEBTERM_AGENT_MTLS=off / în spatele unui CDN / fără nume valid;
  * agent_ws: certificatul din antet contează DOAR cu secretul routerului; alt host / serial vechi →
    4403; clichetul după prima conexiune mTLS (token singur → 4403), dar NU cât mTLS e oprit;
  * emiterea după hello: doar agent ≥ 60, o singură dată, reînnoire cu serial „next" promovat la
    prima conexiune cu el; cheia pleacă spre agent şi nu rămâne în DB.
"""
import asyncio
import json
import os
import sys
import tempfile
import time
import urllib.parse

EDGE = tempfile.mkdtemp()
os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "https://wt.example.org"
os.environ["WEBTERM_AGENT_LISTS_DIR"] = EDGE
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import agentca, agentgate, api, config, core, db, edgemtls, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


def hdr(pem):
    body = "".join(pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").split())
    return urllib.parse.quote(body, safe="")


class _C:
    host = "203.0.113.5"


class WS:
    def __init__(self, token, headers=None):
        self.headers = dict({"authorization": "Bearer " + token}, **(headers or {}))
        self.client = _C()
        self.scope = {"raw_path": b"/agent/ws"}
        self.closed = None
        self.accepted = False

    async def close(self, code=1000, reason=""):
        self.closed = code

    async def accept(self):
        self.accepted = True


class FakeConn:
    def __init__(self, host_id, version=60, reported=None):
        self.host_id, self.agent_version, self.via_mtls = host_id, version, False
        self.mtls_reported = reported
        self._stop_reason, self.sent = None, []

    async def run(self):
        return None

    async def send_ctrl(self, obj):
        self.sent.append(obj)


async def fake_register(ws, host_id, pinned=False):
    return FakeConn(host_id)


async def row(hid):
    return dict(await db.fetchone("SELECT * FROM hosts WHERE id=?", hid))


async def main():
    await db.connect()
    security.init_crypto(config.load_secret())
    core.register_agent = fake_register
    tok1, tok2 = "tok-one-" + "a" * 30, "tok-two-" + "b" * 30
    for name, tok in (("h1", tok1), ("h2", tok2)):
        await db.execute("INSERT INTO hosts(name, token_hash, token_encrypted, created) VALUES(?,?,'',0)",
                         name, security.sha256_hex(tok))
    h1 = (await db.fetchone("SELECT id FROM hosts WHERE name='h1'"))["id"]
    h2 = (await db.fetchone("SELECT id FROM hosts WHERE name='h2'"))["id"]

    print("== Traefik configuration")
    await edgemtls.startup()
    secret = await edgemtls.load_secret()
    check("router secret generated and kept", len(secret) >= 32 and await db.get_setting(edgemtls.K_SECRET, "") == secret)
    check("written", edgemtls.write(force=True) and edgemtls.enabled())
    doc = json.load(open(os.path.join(EDGE, edgemtls.FILE_NAME)))
    r = doc["http"]["routers"]["webterm-agent-mtls"]
    check("router on the agents name and the exact path", r["rule"] == "Host(`agents.wt.example.org`) && Path(`/agent/ws`)", r["rule"])
    check("TLS options require a client certificate signed by OUR CA",
          doc["tls"]["options"]["webterm-agents"]["clientAuth"] == {"caFiles": ["/edge/agent-ca.pem"],
                                                                      "clientAuthType": "RequireAndVerifyClientCert"})
    check("the CA file next to it is the public certificate only",
          "BEGIN CERTIFICATE" in open(os.path.join(EDGE, edgemtls.CA_FILE)).read()
          and "PRIVATE" not in open(os.path.join(EDGE, edgemtls.CA_FILE)).read())
    mw = doc["http"]["middlewares"]
    check("the certificate is passed on, and the secret header set by Traefik",
          mw["webterm-agent-mtls-cert"] == {"passTLSClientCert": {"pem": True}}
          and mw["webterm-agent-mtls-secret"]["headers"]["customRequestHeaders"]["X-Webterm-Mtls-Router"] == secret)
    config.AGENT_MTLS = "off"
    edgemtls.write(force=True)
    check("WEBTERM_AGENT_MTLS=off → empty document", json.load(open(os.path.join(EDGE, edgemtls.FILE_NAME))) == {}
          and not edgemtls.enabled() and edgemtls.status["reason"] == "off")
    config.AGENT_MTLS = "on"
    config.TRUST_CF_CONNECTING_IP = True
    edgemtls.write(force=True)
    check("behind a CDN → off, with the reason", not edgemtls.enabled() and edgemtls.status["reason"] == "proxy")
    config.TRUST_CF_CONNECTING_IP = False
    edgemtls.write(force=True)

    print("== provisioning after hello")
    c59 = FakeConn(h1, version=59)
    await edgemtls.provision_hook(c59)
    check("agent 59 gets nothing", c59.sent == [] and not (await row(h1))["mtls_serial"])
    c60 = FakeConn(h1)
    await edgemtls.provision_hook(c60)
    sent = c60.sent[0] if c60.sent else {}
    check("agent 60 gets cert + key + serial + the agents URL", sent.get("op") == "mtls_provision" and "PRIVATE KEY" in sent.get("key", "")
          and sent.get("url") == "wss://agents.wt.example.org/agent/ws" and sent.get("serial"))
    rw = await row(h1)
    check("serial recorded, key NOT stored", rw["mtls_serial"] and "PRIVATE" not in json.dumps(rw, default=str))
    again = FakeConn(h1)
    await edgemtls.provision_hook(again)
    check("a second hello right after does not re-issue", again.sent == [])
    cert1 = sent["cert"]

    print("== agent_ws")
    sh = {edgemtls.SECRET_HEADER: secret}
    w = WS(tok1, {edgemtls.CERT_HEADER: hdr(cert1)})
    await api.agent_ws(w)
    check("cert header WITHOUT the router secret is ignored (token route; not ratcheted yet → accepted)",
          w.accepted and not (await row(h1))["mtls_required"])
    w = WS(tok2, dict(sh, **{edgemtls.CERT_HEADER: hdr(cert1)}))
    await api.agent_ws(w)
    check("h1's certificate with h2's token → 4403", w.closed == 4403 and not w.accepted)
    w = WS(tok1, dict(sh, **{edgemtls.CERT_HEADER: "garbage"}))
    await api.agent_ws(w)
    check("through the mTLS router with an unverifiable certificate → 4403", w.closed == 4403)
    w = WS(tok1, dict(sh, **{edgemtls.CERT_HEADER: hdr(cert1)}))
    await api.agent_ws(w)
    rw = await row(h1)
    check("valid mTLS connection accepted and the host ratcheted", w.accepted and rw["mtls_required"] == 1 and rw["mtls_last"])
    w = WS(tok1)
    await api.agent_ws(w)
    check("ratcheted host, token only → 4403", w.closed == 4403 and not w.accepted)
    config.AGENT_MTLS = "off"
    edgemtls.write(force=True)
    w = WS(tok1)
    await api.agent_ws(w)
    check("…but with mTLS turned off, the token route works again (rollback, no lockout)", w.accepted)
    config.AGENT_MTLS = "on"
    edgemtls.write(force=True)

    print("== reported serial decides re-sending (review 3.7.0)")
    cur = (await row(h1))["mtls_serial"]
    await db.execute("UPDATE hosts SET mtls_not_after=? WHERE id=?", time.time() + 300 * 86400, h1)
    old_issued = time.time() + 300 * 86400 - agentca.CERT_DAYS * 86400 - 2 * edgemtls.RETRY_UNUSED
    has = FakeConn(h1, reported=cur)
    await edgemtls.provision_hook(has)
    check("an agent that HAS its certificate but is on the token route gets no new one", has.sent == [])
    await db.execute("UPDATE hosts SET mtls_not_after=? WHERE id=?", old_issued + agentca.CERT_DAYS * 86400, h1)
    lost = FakeConn(h1, reported=None)
    await edgemtls.provision_hook(lost)
    check("an agent that never got it (lost message) gets it again after RETRY_UNUSED", len(lost.sent) == 1)
    cur = (await row(h1))["mtls_serial"]
    cert1 = lost.sent[0]["cert"]                    # de aici încolo, certificatul curent e cel retrimis

    print("== renewal and revocation")
    await db.execute("UPDATE hosts SET mtls_not_after=? WHERE id=?", time.time() + 30 * 86400, h1)
    cr = FakeConn(h1, reported=cur)
    cr.via_mtls = True
    await edgemtls.provision_hook(cr)
    rw = await row(h1)
    check("near expiry: a new certificate is sent, stored as 'next', the old one still current",
          cr.sent and rw["mtls_serial_next"] and rw["mtls_serial_next"] != rw["mtls_serial"])
    cert2 = cr.sent[0]["cert"]
    w = WS(tok1, dict(sh, **{edgemtls.CERT_HEADER: hdr(cert1)}))
    await api.agent_ws(w)
    check("the old certificate still works until the new one is used", w.accepted)
    w = WS(tok1, dict(sh, **{edgemtls.CERT_HEADER: hdr(cert2)}))
    await api.agent_ws(w)
    rw = await row(h1)
    check("first connection with the new one promotes it", w.accepted and rw["mtls_serial"] == agentca.verify_client_cert(hdr(cert2))["serial"]
          and rw["mtls_serial_next"] is None)
    w = WS(tok1, dict(sh, **{edgemtls.CERT_HEADER: hdr(cert1)}))
    await api.agent_ws(w)
    check("from then on the old certificate is revoked → 4403", w.closed == 4403)
    rw = await row(h1)
    check("promotion also stores the NEW expiry (no renewal loop)", rw["mtls_not_after"] > time.time() + 360 * 86400, rw["mtls_not_after"])
    after = FakeConn(h1, reported=rw["mtls_serial"])
    after.via_mtls = True
    await edgemtls.provision_hook(after)
    check("the next hello after promotion sends nothing", after.sent == [])
    print("== a renewal that never arrives is re-sent")
    await db.execute("UPDATE hosts SET mtls_not_after=? WHERE id=?", time.time() + 20 * 86400, h1)
    r1 = FakeConn(h1, reported=rw["mtls_serial"]); r1.via_mtls = True
    await edgemtls.provision_hook(r1)
    nxt = (await row(h1))["mtls_serial_next"]
    r2 = FakeConn(h1, reported=rw["mtls_serial"]); r2.via_mtls = True
    await edgemtls.provision_hook(r2)
    check("not re-sent within RETRY_UNUSED", r2.sent == [] and nxt)
    await db.execute("UPDATE hosts SET mtls_next_at=? WHERE id=?", time.time() - 2 * edgemtls.RETRY_UNUSED, h1)
    r3 = FakeConn(h1, reported=rw["mtls_serial"]); r3.via_mtls = True
    await edgemtls.provision_hook(r3)
    check("…re-sent after it, with a fresh 'next' serial", len(r3.sent) == 1 and (await row(h1))["mtls_serial_next"] != nxt)
    r4 = FakeConn(h1, reported=(await row(h1))["mtls_serial_next"]); r4.via_mtls = True
    await db.execute("UPDATE hosts SET mtls_next_at=? WHERE id=?", time.time() - 2 * edgemtls.RETRY_UNUSED, h1)
    await edgemtls.provision_hook(r4)
    check("an agent that reports the pending one is left alone (it uses it on reconnect)", r4.sent == [])
    print("== failures keep the ratchet (fail closed), only 'off' lifts it")
    await db.execute("UPDATE hosts SET mtls_required=1 WHERE id=?", h1)
    edgemtls.status.update(enabled=False, reason="ca-error")
    w = WS(tok1)
    await api.agent_ws(w)
    check("CA error: token-only for a required host still refused", w.closed == 4403)
    from app import syshealth
    res = await syshealth.c_agents_mtls()
    check("…and System health says it is critical", res.severity == "critical" and res.key == "mtls_broken", res)
    edgemtls.write(force=True)

    print("== re-enrolment resets mTLS")
    from app import hostmodel
    await db.execute("UPDATE hosts SET instance_id=NULL, " + hostmodel.MTLS_RESET + " WHERE id=?", h1)
    rw = await row(h1)
    check("ratchet cleared and serials revoked", not rw["mtls_required"] and rw["mtls_serial"] is None and rw["mtls_serial_next"] is None)
    w = WS(tok1, dict(sh, **{edgemtls.CERT_HEADER: hdr(cert2)}))
    await api.agent_ws(w)
    check("the old machine's certificate no longer works", w.closed == 4403)
    w = WS(tok1)
    await api.agent_ws(w)
    check("the new installation can connect with its token first", w.accepted)
    src = open(os.path.join(os.path.dirname(__file__), "..", "gateway", "app", "api.py")).read() + \
        open(os.path.join(os.path.dirname(__file__), "..", "gateway", "app", "hosts_api.py")).read()
    check("both re-enrolment paths use MTLS_RESET", src.count("hostmodel.MTLS_RESET") >= 2)

    print("== an agent that stays connected still renews")
    await db.execute("UPDATE hosts SET mtls_required=1, mtls_serial='abc123', mtls_not_after=?, mtls_serial_next=NULL, mtls_next_at=NULL WHERE id=?",
                     time.time() + 20 * 86400, h1)
    long_lived = FakeConn(h1, reported=(await row(h1))["mtls_serial"])
    long_lived.via_mtls = True
    core.sources[h1] = long_lived
    try:
        await edgemtls.renew_sweep()
    finally:
        core.sources.pop(h1, None)
    check("the periodic sweep sends the renewal without waiting for a hello", len(long_lived.sent) == 1
          and (await row(h1))["mtls_serial_next"], repr((edgemtls.status, dict(await row(h1)))))

    print("== rollback works even when the CA cannot be loaded")
    real_ensure = agentca.ensure_ca
    async def broken():
        raise ValueError("vault key changed")
    agentca.ensure_ca = broken
    try:
        await edgemtls._refresh(force=True)
        check("CA error with mTLS on → ca-error, ratchet kept", edgemtls.status["reason"] == "ca-error" and edgemtls.enforce_ratchet())
        config.AGENT_MTLS = "off"
        await edgemtls._refresh(force=True)
        check("…with WEBTERM_AGENT_MTLS=off → off, ratchet lifted, even though the CA still fails",
              edgemtls.status["reason"] == "off" and not edgemtls.enforce_ratchet())
        await db.execute("UPDATE hosts SET mtls_required=1 WHERE id=?", h1)
        w = WS(tok1)
        await api.agent_ws(w)
        check("…and a required host connects with its token", w.accepted)
    finally:
        agentca.ensure_ca = real_ensure
        config.AGENT_MTLS = "on"
        await edgemtls._refresh(force=True)

    print("== the forward middleware leaves the agents name alone")
    from app import main as _main, forward_api as _fwd
    hit = []
    async def fake_forward_ws(scope, receive, send):
        hit.append("forward")
    async def app_inner(scope, receive, send):
        hit.append("app")
    real = _fwd.handle_forward_ws
    _fwd.handle_forward_ws = fake_forward_ws
    try:
        for host in ("agents.wt.example.org", "grafana.wt.example.org"):
            sc = {"type": "websocket", "path": "/agent/ws", "headers": [(b"host", host.encode())]}
            await _main.ForwardWSMiddleware(app_inner)(sc, None, None)
    finally:
        _fwd.handle_forward_ws = real
    check("agents.<domain> goes to the app, a real forward name to the forward proxy", hit == ["app", "forward"], hit)

    await db.close()


asyncio.run(main())
print("\n%d/%d passed" % (ok, total))
sys.exit(0 if ok == total else 1)
