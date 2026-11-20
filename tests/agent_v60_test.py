"""Agent 60: certificatul de client pentru mTLS (docs/design/AGENT-MTLS.md).

Fără Docker, fără reţea în afara 127.0.0.1:
  * `mtls_provision` scrie cert + cheie (0600) şi `mtls_url` în agent.json, atomic; refuză (fără să scrie
    nimic) un certificat / o cheie / un URL invalid, o pereche care nu se potriveşte şi un nume de agenţi
    din afara domeniului instalării;
  * WSClient prezintă certificatul în handshake: un server TLS local care CERE certificat de client
    semnat de CA-ul de test îl acceptă; fără certificat, handshake-ul cade;
  * alternarea: după un eşec pe ruta mTLS, încercarea următoare merge pe ruta cu token, apoi iar mTLS.
"""
import json
import time
import os
import socket
import ssl
import sys
import tempfile
import threading

os.environ["HOME"] = tempfile.mkdtemp(prefix="v60-home-")
os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp(prefix="v60-data-")
os.environ["WEBTERM_PUBLIC_URL"] = "https://wt.example.org"
os.environ["TMUX_TMPDIR"] = tempfile.mkdtemp(prefix="v60-tmux-")
os.environ.pop("TMUX", None)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
import ptyd  # noqa: E402

import asyncio  # noqa: E402
import datetime  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from app import agentca, config, db, security  # noqa: E402

os.makedirs(ptyd.WEBTERM_DIR, exist_ok=True)
ok_n = 0
total = 0


def check(name, cond, detail=""):
    global ok_n, total
    total += 1
    ok_n += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % (detail,)))


check("AGENT_VERSION is at least 60 (mTLS); 61 = the fd-reuse fix", ptyd.AGENT_VERSION >= 61, ptyd.AGENT_VERSION)

# certificate reale, din CA-ul gateway-ului (agentca), ca în producţie
async def _issue():
    await db.connect()
    security.init_crypto(config.load_secret())
    await agentca.ensure_ca()
    c = agentca.issue(5)
    other = agentca.issue(6)
    pem = agentca.ca_pem()
    await db.close()
    return c, other, pem
cert, other, ca_pem = asyncio.run(_issue())

cfg = {"url": "wss://wt.example.org/agent/ws", "token": "t"}
with open(ptyd.CONFIG_PATH, "w") as f:
    json.dump(cfg, f)


def msg(**kw):
    m = {"cert": cert["cert"], "key": cert["key"], "url": "wss://agents.wt.example.org/agent/ws", "serial": cert["serial"]}
    m.update(kw)
    return m


print("== mtls_provision: refusals write nothing")
for name, m in (("not a certificate", msg(cert="hello")),
                ("not a key", msg(key="nope")),
                ("http url", msg(url="http://agents.wt.example.org/agent/ws")),
                ("other path", msg(url="wss://agents.wt.example.org/x")),
                ("another domain", msg(url="wss://agents.evil.example/agent/ws")),
                ("lookalike suffix", msg(url="wss://agents.wt.example.org.evil.example/agent/ws")),
                ("a sibling, not a subdomain (public-suffix trick)", msg(url="wss://agents.example.org/agent/ws")),
                ("an explicit port", msg(url="wss://agents.wt.example.org:8443/agent/ws")),
                ("no serial", msg(serial=None)),
                ("key of another certificate", msg(key=other["key"]))):
    e = ptyd._mtls_install(m, cfg)
    check("%s → refused" % name, e != "" and not os.path.exists(ptyd.MTLS_PEM_PATH)
          and not [f for f in os.listdir(ptyd.WEBTERM_DIR) if f.endswith(".tmp")]
          and "mtls_url" not in json.load(open(ptyd.CONFIG_PATH)), e)

print("== mtls_provision: success")
e = ptyd._mtls_install(msg(), cfg)
check("valid pair installed", e == "", e)
check("key + certificate in ONE file, 0600 (one atomic swap)", oct(os.stat(ptyd.MTLS_PEM_PATH).st_mode & 0o777) == "0o600"
      and "PRIVATE KEY" in open(ptyd.MTLS_PEM_PATH).read() and "BEGIN CERTIFICATE" in open(ptyd.MTLS_PEM_PATH).read())
data = json.load(open(ptyd.CONFIG_PATH))
check("agent.json keeps url + token and gains mtls_url + mtls_serial",
      data["url"] == cfg["url"] and data["token"] == "t" and data["mtls_url"] == "wss://agents.wt.example.org/agent/ws"
      and data["mtls_serial"] == cert["serial"])
check("no temporary file left", not [f for f in os.listdir(ptyd.WEBTERM_DIR) if f.endswith(".tmp")])

print("== the handshake presents the certificate")
d = tempfile.mkdtemp()
skey = ec.generate_private_key(ec.SECP256R1())
now = datetime.datetime.now(datetime.timezone.utc)
scert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).public_key(skey.public_key())
         .serial_number(1).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False).sign(skey, hashes.SHA256()))
open(os.path.join(d, "s.crt"), "wb").write(scert.public_bytes(serialization.Encoding.PEM))
open(os.path.join(d, "s.key"), "wb").write(skey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                              serialization.NoEncryption()))
open(os.path.join(d, "ca.pem"), "w").write(ca_pem)
sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
sctx.load_cert_chain(os.path.join(d, "s.crt"), os.path.join(d, "s.key"))
sctx.verify_mode = ssl.CERT_REQUIRED                                   # ca RequireAndVerifyClientCert
sctx.load_verify_locations(os.path.join(d, "ca.pem"))
lsock = socket.socket()
lsock.bind(("127.0.0.1", 0))
lsock.listen(4)
port = lsock.getsockname()[1]
seen = []


def serve(n):
    for _ in range(n):
        c, _ = lsock.accept()
        try:
            t = sctx.wrap_socket(c, server_side=True)
            seen.append(t.getpeercert() is not None)
            t.recv(2048)
            t.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            t.close()
        except (ssl.SSLError, OSError) as e:
            seen.append("refused:" + type(e).__name__)
            c.close()


th = threading.Thread(target=serve, args=(2,), daemon=True)
th.start()
url = "wss://localhost:%d/agent/ws" % port
w = ptyd.WSClient(url, "t", insecure=True, client_cert=(ptyd.MTLS_PEM_PATH, None))
try:
    w.connect(timeout=5)
except Exception:                       # noqa: BLE001 — serverul de test răspunde 403, nu 101
    pass
w2 = ptyd.WSClient(url, "t", insecure=True)
try:
    w2.connect(timeout=5)
except Exception:                       # noqa: BLE001
    pass
th.join(5)
check("with the certificate the TLS handshake completes (server saw a client cert)", seen[:1] == [True], seen)
check("without it the server refuses the handshake", len(seen) > 1 and str(seen[1]).startswith("refused"), seen)

print("== alternating routes")


class _A:
    pass


a = _A()
a.config = json.load(open(ptyd.CONFIG_PATH))
a._try_token_next = False
a._attempt_mtls = False
a._mtls_use_prev = a._attempt_prev = False
a._connect_worker = lambda ws: None
urls = []


class _WS:
    def __init__(self, url, token, insecure=False, cert_pin=None, client_cert=None):
        urls.append((url, bool(client_cert)))


real_ws, real_thread = ptyd.WSClient, ptyd.threading.Thread
ptyd.WSClient = _WS
ptyd.threading.Thread = lambda *x, **k: type("T", (), {"start": lambda self: None})()
try:
    ptyd.Agent._start_connect(a)
    a._try_token_next = bool(a._attempt_mtls)          # ce face _on_connect_failed
    ptyd.Agent._start_connect(a)
    a._try_token_next = bool(a._attempt_mtls)
    ptyd.Agent._start_connect(a)
finally:
    ptyd.WSClient, ptyd.threading.Thread = real_ws, real_thread
check("first try: mTLS route with the certificate", urls[0] == ("wss://agents.wt.example.org/agent/ws", True), urls)
check("after a failure: the token route, no certificate", urls[1] == ("wss://wt.example.org/agent/ws", False), urls)
check("then mTLS again", urls[2][1] is True, urls)
pem_backup = open(ptyd.MTLS_PEM_PATH).read()
os.unlink(ptyd.MTLS_PEM_PATH)
a._try_token_next = False
urls.clear()
ptyd.WSClient = _WS
ptyd.threading.Thread = lambda *x, **k: type("T", (), {"start": lambda self: None})()
try:
    ptyd.Agent._start_connect(a)
finally:
    ptyd.WSClient, ptyd.threading.Thread = real_ws, real_thread
check("missing key file → token route (never a half-configured mTLS attempt)", urls[0][1] is False, urls)

print("== back to mTLS after a fallback")
b = _A()
b.config = {"url": "wss://wt.example.org/agent/ws", "token": "t", "mtls_url": "wss://agents.wt.example.org/agent/ws"}
open(ptyd.MTLS_PEM_PATH, "w").write(pem_backup)                      # fişierul înapoi
b._mtls_retry_delay = ptyd.MTLS_RETRY
b.connected, b._connected_via_mtls, b._try_token_next = True, False, True
b._mtls_use_prev = b._attempt_prev = False
b._disconnect_requested, b._mtls_retry_at = False, 0.0
b._last_hb_ack, b.next_heartbeat = 1e18, 1e18
b._wd_interval, b._last_wd = 0, 0
b._touch_alive = b._rotate_log = lambda *a: None
try:
    ptyd.Agent._tick(b, 1000.0)
except AttributeError:
    pass                                    # restul _tick-ului cere atribute pe care testul nu le are
check("on the token route with a certificate: the tick asks for a reconnect through mTLS",
      b._disconnect_requested is True and b._try_token_next is False and b._mtls_retry_at == 1000.0 + ptyd.MTLS_RETRY)
b._disconnect_requested = False
try:
    ptyd.Agent._tick(b, 1001.0)
except AttributeError:
    pass
check("…but not again before MTLS_RETRY", b._disconnect_requested is False)
b._attempt_mtls, b._mtls_retry_delay = True, ptyd.MTLS_RETRY
b._connecting, b.backoff, b.next_connect = False, 1.0, 0.0
ptyd.Agent._on_connect_failed(b, "mtls failed")
check("a failed mTLS retry doubles the delay before the next one", b._mtls_retry_delay == 2 * ptyd.MTLS_RETRY)
for _ in range(10):
    b._attempt_mtls = True
    ptyd.Agent._on_connect_failed(b, "mtls failed")
check("…up to once a day", b._mtls_retry_delay == ptyd.MTLS_RETRY_MAX)

print("== closing from another thread: wake the reader, let IT close the descriptor (prod: nfs)")
import socket as _s
import ssl as _ssl
import threading as _th
a_end, b_end = _s.socketpair()
wc = ptyd.WSClient("wss://wt.example.org/agent/ws", "t")
wc.sock, wc.reader_owned = a_end, True
woke = []


def _reader_like():
    try:
        woke.append(a_end.recv(10))
    finally:
        wc.release()


rt = _th.Thread(target=_reader_like, daemon=True)
rt.start()
time.sleep(0.2)
fd_before = a_end.fileno()
wc.close()
rt.join(2)
check("close() from another thread wakes the blocked reader at once (shutdown)", not rt.is_alive() and woke == [b""], woke)
check("…and only the reader closed the descriptor (no number to reuse while it could still read)",
      fd_before >= 0 and a_end.fileno() == -1)
b_end.close()
c_end, d_end = _s.socketpair()
wc2 = ptyd.WSClient("wss://wt.example.org/agent/ws", "t")
wc2.sock = c_end
wc2.close()
check("without a reader, close() closes the descriptor itself", c_end.fileno() == -1)
d_end.close()
e_end, f_end = _s.socketpair()
tls = _ssl.create_default_context().wrap_socket(e_end, server_hostname="x", do_handshake_on_connect=False)
wc3 = ptyd.WSClient("wss://wt.example.org/agent/ws", "t")
wc3.sock, wc3.reader_owned = tls, True
wc3.close()
check("the shutdown is the raw socket's: the TLS layer stays until the reader closes",
      getattr(tls, "_sslobj", None) is not None and tls.fileno() >= 0)
wc3.release()
f_end.close()

print("== renewal keeps the previous certificate until the new one works (Codex audit)")
first_pem = open(ptyd.MTLS_PEM_PATH).read()
cfg = json.load(open(ptyd.CONFIG_PATH))
ptyd._mtls_drop_prev(cfg)                    # = o conectare reuşită cu primul certificat: confirmat
check("a successful connection marks the certificate as confirmed",
      json.load(open(ptyd.CONFIG_PATH)).get("mtls_confirmed") == cert["serial"])
e = ptyd._mtls_install(msg(cert=other["cert"], key=other["key"], serial=other["serial"]), cfg)
data = json.load(open(ptyd.CONFIG_PATH))
check("renewal installed; the previous pair kept as agent-mtls.prev.pem (0600) with its URL",
      e == "" and open(ptyd.MTLS_PREV_PATH).read() == first_pem
      and oct(os.stat(ptyd.MTLS_PREV_PATH).st_mode & 0o777) == "0o600"
      and data["mtls_prev_url"] == "wss://agents.wt.example.org/agent/ws" and data["mtls_serial"] == other["serial"], e)
c = _A()
c.config = data
c._try_token_next = c._attempt_mtls = c._mtls_use_prev = c._attempt_prev = False
c._mtls_retry_delay, c._connecting, c.backoff, c.next_connect = ptyd.MTLS_RETRY, False, 1.0, 0.0
c._connect_worker = lambda ws: None
seq = []


class _WS2:
    def __init__(self, url, token, insecure=False, cert_pin=None, client_cert=None):
        seq.append(os.path.basename(client_cert[0]) if client_cert else "token")


ptyd.WSClient = _WS2
ptyd.threading.Thread = lambda *x, **k: type("T", (), {"start": lambda self: None})()
try:
    for _ in range(4):
        ptyd.Agent._start_connect(c)
        ptyd.Agent._on_connect_failed(c, "failed")
finally:
    ptyd.WSClient, ptyd.threading.Thread = real_ws, real_thread
check("routes after failures: new certificate → previous one → token → new again",
      seq == ["agent-mtls.pem", "agent-mtls.prev.pem", "token", "agent-mtls.pem"], seq)
third = agentca.issue(5)                     # CA-ul rămâne încărcat în memorie
e = ptyd._mtls_install(msg(cert=third["cert"], key=third["key"], serial=third["serial"]), c.config)
check("another renewal before the new one was ever confirmed: the backup stays the CONFIRMED one",
      e == "" and open(ptyd.MTLS_PREV_PATH).read() == first_pem
      and json.load(open(ptyd.CONFIG_PATH))["mtls_serial"] == third["serial"], e)
ptyd._mtls_drop_prev(c.config)
check("once the new one connects, the previous one is gone (file + mtls_prev_url)",
      not os.path.exists(ptyd.MTLS_PREV_PATH) and "mtls_prev_url" not in json.load(open(ptyd.CONFIG_PATH))
      and "mtls_prev_url" not in c.config
      and not [f for f in os.listdir(ptyd.WEBTERM_DIR) if f.endswith(".tmp")])

print("\n%d/%d passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
