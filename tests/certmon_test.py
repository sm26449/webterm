"""TLS certificate monitoring + "Renew from the UI" (3.6.7, certmon.py + the /api/certs routes).

Incident 2026-10-12: a wildcard expired after weeks of a renewal error only Traefik's log knew.
What we check, all hermetic (local TLS servers on 127.0.0.1, a temp DB, no agent):
  * the checker reads the leaf actually served — expired, 2 days, 10 days, 30 days, Traefik's
    default certificate, a certificate for another name — WITHOUT validating the chain;
  * Traefik first, the public name only when Traefik is unreachable; a server that never
    finishes the handshake costs at most the timeout;
  * which names are checked (main / forward only on DNS-01 / Authentik only on the same stack);
  * alert dedup: one alert per threshold per certificate (14 d, 3 d, critical), persisted across
    a restart, an "OK again" after the fix, Traefik's ever-changing default cert alerted once,
    an unreachable check never alerted; every alert audited;
  * the command builder: only strict hostnames (optional `*.`), quoted, nothing a shell would
    expand; a bad name or install dir → no command at all;
  * the typed-not-run session command: nothing runs on EOF / an empty line; Enter runs exactly
    the validated argv (checked through a real pty with readline);
  * the routes: who sees the status (settings.manage), "Check now" rate limit, Owner-only
    renew-host and renew terminal (Admin refused), the picked host, the name allow-list, the fresh
    second factor BEFORE anything is created, tokens refused.
"""
import asyncio
import datetime
import json
import os
import pty
import select
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rbac_util as U  # noqa: E402  (sets the env before `app` is imported)
from app import certmon, config, core, db  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def make_cert(names, days, cn=None, issuer_cn=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn or (names[0] if names else "x"))])
    iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or "Test CA R1"),
                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")]) if issuer_cn != "self" else subj
    nb = now - datetime.timedelta(days=90 if days < 0 else 1)
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(iss).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb)
         .not_valid_after(now + datetime.timedelta(days=days)))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    cert = b.sign(key, hashes.SHA256())
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


class TLSServer:
    def __init__(self, names, days, cn=None, issuer_cn=None, handshake=True):
        d = tempfile.mkdtemp()
        pem, kpem = make_cert(names, days, cn, issuer_cn)
        crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        open(crt, "wb").write(pem)
        open(key, "wb").write(kpem)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(crt, key)
        self.handshake = handshake
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.held = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            if not self.handshake:
                self.held.append(c)              # accept, then say nothing (a hung peer)
                continue
            try:
                c.settimeout(3)
                self.ctx.wrap_socket(c, server_side=True).close()
            except Exception:
                c.close()

    def close(self):
        self.stop = True
        for c in self.held:
            c.close()
        self.sock.close()


def test_reading():
    print("── reading the served certificate (no chain validation)")
    cases = [
        ("expired", ["wt.example.com"], -3, None, None, "expired"),
        ("2 days", ["wt.example.com"], 2, None, None, "expiring_soon"),
        ("10 days", ["wt.example.com"], 10, None, None, "expiring"),
        ("30 days", ["wt.example.com", "*.wt.example.com"], 30, None, None, "ok"),
        ("Traefik default", [], 365, "TRAEFIK DEFAULT CERT", "self", "default"),
        ("another name", ["other.example.org"], 60, None, None, "mismatch"),
    ]
    for label, names, days, cn, iss, want in cases:
        srv = TLSServer(names, days, cn, iss)
        try:
            der = certmon.fetch_leaf("127.0.0.1", srv.port, "wt.example.com")
            info = certmon.parse_leaf(der)
            ev = certmon.evaluate("wt.example.com", info)
        finally:
            srv.close()
        check("%s → %s" % (label, want), ev["state"] == want, "%s %s" % (ev, info.get("subject_cn")))
        if label == "expired":
            check("…days_left is negative, level critical", ev["days_left"] < 0 and ev["level"] == certmon.L_CRIT, ev)
        if label == "30 days":
            check("…issuer, SANs, fingerprint read", info["issuer"] == "Test CA R1, Test Org"
                  and "*.wt.example.com" in info["sans"] and len(info["fingerprint"]) == 64, info)
            check("…a wildcard is noticed", ev["wildcard"] is True)
    check("a wildcard covers one label only", certmon.covers("a.wt.example.com", ["*.wt.example.com"])
          and not certmon.covers("a.b.wt.example.com", ["*.wt.example.com"])
          and not certmon.covers("wt.example.com", ["*.wt.example.com"]))
    check("thresholds: 14 and 3 days", certmon.WARN_DAYS == 14 and certmon.CRIT_DAYS == 3)


def test_probe():
    print("── Traefik first, the public name only as a fallback; bounded")
    srv = TLSServer(["localhost"], 40)
    old_target = config.CERT_CHECK_TARGET
    try:
        config.CERT_CHECK_TARGET = "127.0.0.1:%d" % srv.port
        r = certmon.probe({"name": "localhost", "role": "main", "public_port": 1})
        check("Traefik reachable → read there (via=traefik)", r.get("via") == "traefik", r)
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()                                     # a port nobody listens on → refused
        config.CERT_CHECK_TARGET = "127.0.0.1:%d" % dead_port
        r = certmon.probe({"name": "localhost", "role": "main", "public_port": srv.port})
        check("Traefik unreachable → the public name for the MAIN domain (via=public)", r.get("via") == "public", r)
        for role in ("forward", "authentik"):
            r = certmon.probe({"name": "localhost", "role": role, "public_port": srv.port})
            check("…but never for the %s name (no direct dial of an editable domain: SSRF)" % role,
                  "error" in r and "public:" not in r["error"] and r.get("via") is None, r)
        r = certmon.probe({"name": "localhost", "role": "main", "public_port": dead_port})
        check("both unreachable → an error, not an exception", "error" in r and "traefik:" in r["error"], r)
    finally:
        config.CERT_CHECK_TARGET = old_target
        srv.close()
    hung = TLSServer(["x.example.com"], 30, handshake=False)
    try:
        t0 = time.time()
        try:
            certmon.fetch_leaf("127.0.0.1", hung.port, "x.example.com", timeout=1.0)
            res = "no error"
        except (OSError, ssl.SSLError) as e:
            res = type(e).__name__
        took = time.time() - t0
        check("a peer that never answers the handshake costs ≤ the timeout", took < 3 and res != "no error",
              "%s %.1fs" % (res, took))
    finally:
        hung.close()
    # a peer that TRICKLES bytes (one every 0.3 s) used to reset a per-operation timeout forever
    trickle = socket.socket()
    trickle.bind(("127.0.0.1", 0))
    trickle.listen(4)
    tport = trickle.getsockname()[1]
    stop = threading.Event()

    def _trickle():
        trickle.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = trickle.accept()
            except OSError:
                continue
            def drip(c=c):
                try:
                    c.recv(4096)
                    for _ in range(100):
                        if stop.is_set():
                            break
                        c.send(b"\x16")       # a TLS record header byte, never a full record
                        time.sleep(0.3)
                except OSError:
                    pass
                finally:
                    c.close()
            threading.Thread(target=drip, daemon=True).start()
    threading.Thread(target=_trickle, daemon=True).start()
    try:
        t0 = time.time()
        try:
            certmon.fetch_leaf("127.0.0.1", tport, "x.example.com", timeout=1.5)
            res = "no error"
        except (OSError, ssl.SSLError) as e:
            res = type(e).__name__
        took = time.time() - t0
        check("a peer that trickles bytes is cut at ONE total deadline (≤ timeout + slack)",
              took < 2.5 and res != "no error", "%s %.1fs" % (res, took))
    finally:
        stop.set()
        trickle.close()
    check("probes run in a dedicated pool of at most 4 threads", certmon._pool._max_workers == 4)


def test_targets():
    print("── which names are checked")
    saved = (config.PUBLIC_URL, config.CERT_RESOLVER, config.CERT_CHECK_FORWARD, config.AUTHENTIK_DOMAIN,
             config.COMPOSE_PROFILES, config.CERT_CHECK)
    try:
        config.PUBLIC_URL, config.CERT_RESOLVER, config.CERT_CHECK_FORWARD = "https://wt.example.com", "ledns", ""
        config.AUTHENTIK_DOMAIN, config.COMPOSE_PROFILES, config.CERT_CHECK = "auth.example.com", ["authentik"], True
        t = certmon.targets("wt.example.com")
        check("DNS-01 + Authentik profile: main, forward probe, authentik",
              [(x["name"], x["role"]) for x in t] == [("wt.example.com", "main"),
                                                      ("cert-check.wt.example.com", "forward"),
                                                      ("auth.example.com", "authentik")], t)
        check("the forward's renewal name is the wildcard", t[1]["renew_domain"] == "*.wt.example.com", t)
        config.CERT_RESOLVER = "le"
        check("HTTP-01: no forward name (no forward certificate exists by design)",
              [x["role"] for x in certmon.targets("wt.example.com")] == ["main", "authentik"])
        config.CERT_CHECK_FORWARD = "1"
        check("WEBTERM_CERT_CHECK_FORWARD=1 forces it", "forward" in [x["role"] for x in certmon.targets("wt.example.com")])
        config.CERT_CHECK_FORWARD = ""
        config.COMPOSE_PROFILES = []
        check("Authentik only when its profile runs on this stack",
              [x["role"] for x in certmon.targets("wt.example.com")] == ["main"])
        config.PUBLIC_URL = "https://10.0.0.5"
        check("an IP address has no certificate name to check", certmon.targets("") == [])
        config.PUBLIC_URL = "http://wt.example.com"
        check("http:// → nothing to check", certmon.targets("wt.example.com") == [])
        config.PUBLIC_URL, config.CERT_CHECK = "https://wt.example.com", False
        check("WEBTERM_CERT_CHECK=0 → nothing to check", certmon.targets("wt.example.com") == [])
        config.CERT_CHECK, config.CERT_RESOLVER = True, "ledns"
        check("a bogus forward domain is skipped, not probed", [x["role"] for x in certmon.targets("bad domain;x")] == ["main"])
    finally:
        (config.PUBLIC_URL, config.CERT_RESOLVER, config.CERT_CHECK_FORWARD, config.AUTHENTIK_DOMAIN,
         config.COMPOSE_PROFILES, config.CERT_CHECK) = saved


def test_command_builder():
    print("── the renewal command: validated names only")
    good = {
        "wt.example.com": "sudo -k /opt/webterm/scripts/cert-renew.sh --domain wt.example.com",
        "*.wt.example.com": "sudo -k /opt/webterm/scripts/cert-renew.sh --domain '*.wt.example.com'",
        "auth.x-y.example.co": "sudo -k /opt/webterm/scripts/cert-renew.sh --domain auth.x-y.example.co",
    }
    for d, want in good.items():
        got = certmon.renew_command(d, "/opt/webterm")
        check("%s → %s" % (d, want), got == want, got)
        check("…round-trips to exactly five argv tokens", shlex.split(got) == ["sudo", "-k", "/opt/webterm/scripts/cert-renew.sh",
                                                                              "--domain", d])
    bad = ["wt.example.com;id", "$(id).example.com", "`id`.example.com", "wt.example.com && rm -rf /",
           "wt.example.com\nid", "-rf.example.com", "--yes", "localhost", "*.*.example.com", "*example.com",
           "wt.example.com.", "WT.EXAMPLE.COM", "wt..example.com", "wt.example.com ", "a" * 64 + ".com",
           "ẃt.example.com", "wt.exa'mple.com", "wt.example.com|sh", "", None, 42]
    for d in bad:
        try:
            certmon.renew_command(d, "/opt/webterm")
            res = "built"
        except ValueError:
            res = "refused"
        check("refuses %r" % (d,), res == "refused")
    for d in ("/opt/web term", "/opt/webterm/../../etc", "opt/webterm", "/opt/$(id)", "/opt/webterm;id", "/",
              "/opt/./webterm", "/opt/webterm\n"):
        try:
            certmon.renew_command("wt.example.com", d)
            res = "built"
        except ValueError:
            res = "refused"
        check("refuses install dir %r" % d, res == "refused")


def test_typed_cmd():
    print("── typed, not run")
    d = tempfile.mkdtemp()
    try:
        marker = os.path.join(d, "ran")
        fake = os.path.join(d, "sudo")
        open(fake, "w").write('#!/bin/sh\nprintf "%%s\\n" "$@" > %s\n' % shlex.quote(marker))
        os.chmod(fake, 0o755)
        cmd = certmon.typed_session_cmd(certmon.renew_command("*.wt.example.com", "/opt/webterm"))
        env = dict(os.environ, PATH=d + ":" + os.environ.get("PATH", ""), HOME=d)
        for label, stdin in (("EOF", b""), ("an empty line (no tty: nothing pre-filled)", b"\n")):
            subprocess.run(["sh", "-c", cmd], input=stdin, env=env, capture_output=True, timeout=10)
            check("%s → nothing runs" % label, not os.path.exists(marker))
        # the real path: a terminal, readline pre-filled with the command, the person presses Enter
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe("sh", ["sh", "-c", cmd], env)
        out = b""
        deadline = time.time() + 10
        sent = False
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
            if not sent and b"cert-renew.sh --domain" in out:
                os.write(fd, b"\r")                   # Enter
                sent = True
            if sent and os.path.exists(marker):
                os.write(fd, b"\r")                   # "press Enter to close"
                break
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        text = out.decode("utf-8", "replace")
        check("the terminal shows the command, typed", "/opt/webterm/scripts/cert-renew.sh --domain" in text
              and "TYPED, NOT RUN" in text, text[-400:])
        args = open(marker).read().split("\n") if os.path.exists(marker) else []
        check("Enter runs exactly the validated argv (the wildcard reaches sudo unexpanded)",
              args[:4] == ["-k", "/opt/webterm/scripts/cert-renew.sh", "--domain", "*.wt.example.com"], args)
    finally:
        shutil.rmtree(d, ignore_errors=True)


async def _settle():
    for _ in range(30):
        await asyncio.sleep(0.01)


async def _alerts(uid):
    return await db.fetchall("SELECT severity, msg_key FROM alerts WHERE user_id=? AND kind='tls_cert' ORDER BY id", uid)


async def test_dedup(owner_uid):
    print("── alerts: one per threshold per certificate")
    T = [{"name": "wt.example.com", "role": "main", "renew_domain": "wt.example.com", "public_port": 443}]
    state = {"info": None}

    def fake_probe(t):
        return dict(state["info"])

    def info(days, fp="A" * 64, cn="R11", subj="wt.example.com", err=None):
        if err:
            return {"error": err}
        return {"not_after": time.time() + days * 86400, "not_before": 0, "subject_cn": subj,
                "issuer": cn, "issuer_cn": cn, "sans": [subj] if subj != certmon.TRAEFIK_DEFAULT_CN else [],
                "fingerprint": fp, "self_signed": False, "via": "traefik"}

    orig_targets, orig_probe = certmon.targets, certmon.probe
    certmon.targets = lambda fwd="": T
    certmon.probe = fake_probe
    stuck = asyncio.get_running_loop().create_future()          # an earlier probe still running
    certmon._inflight.add(stuck)
    calls_before = []
    certmon.probe = lambda t: calls_before.append(t) or {"error": "x"}
    await certmon.check_all("")
    check("a check is skipped while earlier probes are still running", calls_before == [])
    stuck.cancel()
    certmon._inflight.clear()
    certmon.probe = fake_probe
    try:
        seq = [
            ("30 days: nothing", info(30), []),
            ("10 days: the 14-day warning", info(10), [("warning", "cert_expiring")]),
            ("10 days again (next day): no repeat", info(10), []),
            ("9 days: same threshold, no repeat", info(9), []),
            ("2 days: the 3-day warning", info(2), [("warning", "cert_expiring_soon")]),
            ("2 days again: no repeat", info(2), []),
            ("expired: critical", info(-1), [("critical", "cert_expired")]),
            ("expired again: no repeat", info(-1), []),
        ]
        for label, inf, want in seq:
            n0 = len(await _alerts(owner_uid))
            state["info"] = inf
            await certmon.check_all("")
            await _settle()
            rows = await _alerts(owner_uid)
            got = [(r["severity"], r["msg_key"]) for r in rows[n0:]]
            check(label, got == want, got)
        certmon.reset_for_tests()                         # a gateway restart: memory gone, DB stays
        n0 = len(await _alerts(owner_uid))
        await certmon.check_all("")
        await _settle()
        check("after a restart: still no repeat (dedup is persisted)", len(await _alerts(owner_uid)) == n0)
        state["info"] = info(0, err="traefik: timed out")
        await certmon.check_all("")
        await _settle()
        st = certmon.status()["items"][0]
        check("an unreachable check: no alert, last error kept with the last known certificate",
              len(await _alerts(owner_uid)) == n0 and st["state"] == "error" and "timed out" in st["error"]
              and st.get("issuer") == "R11", st)
        state["info"] = info(89, fp="B" * 64)
        await certmon.check_all("")
        await _settle()
        rows = await _alerts(owner_uid)
        check("renewed (new certificate, 89 days): one OK-again alert", [(r["severity"], r["msg_key"]) for r in rows[n0:]]
              == [("ok", "cert_ok")], rows[n0:])
        n0 = len(rows)
        await certmon.check_all("")
        await _settle()
        check("…and silence afterwards", len(await _alerts(owner_uid)) == n0)
        for i in range(3):                                # Traefik mints a new default cert per start
            state["info"] = info(365, fp=("%d" % i) * 64, cn=certmon.TRAEFIK_DEFAULT_CN, subj=certmon.TRAEFIK_DEFAULT_CN)
            await certmon.check_all("")
            await _settle()
        rows = await _alerts(owner_uid)
        check("Traefik's default certificate (new bytes each restart) → ONE critical alert",
              [(r["severity"], r["msg_key"]) for r in rows[n0:]] == [("critical", "cert_default")], rows[n0:])
        aud = await db.fetchall("SELECT detail FROM audit_log WHERE actor='system:certmon' ORDER BY id")
        check("every alert is in the audit log (actor system:certmon)", len(aud) == 5
              and "expired" in aud[2]["detail"], [a["detail"] for a in aud])
        store = json.loads((await db.fetchone("SELECT value FROM app_settings WHERE key=?", certmon.K_ALERTS))["value"])
        check("the dedup state names the default cert by condition, not bytes",
              store["wt.example.com"]["fp"] == "traefik-default", store)
    finally:
        certmon.targets, certmon.probe = orig_targets, orig_probe
        certmon.reset_for_tests()


async def test_routes():
    print("── routes: who may see, check, renew")
    owner = await U.owner_client()
    owner_uid = (await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL))["id"]
    hid = await U.add_host(owner, "gw")
    ssh_hid = await U.add_host(owner, "sshbox", connection_type="ssh", hostname="10.0.0.9", ssh_username="u",
                               auth_method="password", credential_policy="ask")
    await U.add_user("admin@x.co", bindings=[("admin", "all", "")])
    await U.add_user("op@x.co", bindings=[("operator", "all", "")])
    await U.add_user("view@x.co", bindings=[("viewer", "all", "")])
    admin, op, view = await U.login("admin@x.co"), await U.login("op@x.co"), await U.login("view@x.co")
    anon = U.client()

    r = await anon.get("/api/certs")
    check("anonymous → 401", r.status_code == 401, r.status_code)
    r = await owner.get("/api/certs")
    check("Owner sees the status; can_renew", r.status_code == 200 and r.json()["can_renew"] is True, r.text[:200])
    r = await admin.get("/api/certs")
    check("Admin (settings.manage) sees it; can_renew false", r.status_code == 200 and r.json()["can_renew"] is False
          and r.json()["renew_host"] is None, r.text[:200])
    for who, c in (("Operator", op), ("Viewer", view)):
        r = await c.get("/api/certs")
        check("%s → 403" % who, r.status_code == 403 and U.code(r) == "authz.denied", r.status_code)
    r = await U.client(headers={"authorization": "Bearer wt_nope"}).get("/api/certs")
    check("a Bearer token → refused", r.status_code in (401, 403), r.status_code)

    certmon.reset_for_tests()
    r1 = await owner.post("/api/certs/check")
    r2 = await owner.post("/api/certs/check")
    check("Check now: first runs", r1.status_code == 200, r1.text[:200])
    check("…a second within 30 s → 429 certs.rateLimited with Retry-After", r2.status_code == 429
          and U.code(r2) == "certs.rateLimited" and int(r2.headers.get("retry-after", "0")) > 0, r2.status_code)
    r = await op.post("/api/certs/check")
    check("Operator cannot trigger a check", r.status_code == 403)

    r = await admin.put("/api/certs/renew-host", json={"host_id": hid})
    check("Admin cannot pick the renewal host (certs.renew is Owner-only)", r.status_code == 403
          and U.code(r) == "authz.denied", r.text[:200])
    r = await owner.put("/api/certs/renew-host", json={"host_id": ssh_hid})
    check("an SSH host is refused (agent hosts only)", r.status_code == 400 and U.code(r) == "certs.renewAgentOnly", r.text[:200])
    r = await owner.put("/api/certs/renew-host", json={"host_id": 99999})
    check("a missing host → 404", r.status_code == 404)

    url = "/api/hosts/%d/cert-renew" % hid
    T = [{"name": "wt.example.com", "role": "main", "renew_domain": "wt.example.com", "public_port": 443},
         {"name": "cert-check.wt.example.com", "role": "forward", "renew_domain": "*.wt.example.com", "public_port": 443}]
    orig_targets, orig_create = certmon.targets, core.create_session
    certmon.targets = lambda fwd="": T
    created = []

    async def fake_create(host_id, title, rows=24, cols=80, tz=None, cmd=None, pw=None,
                          created_by_id=None, origin=None):
        created.append({"host_id": host_id, "title": title, "cmd": cmd, "by": created_by_id, "origin": origin})
        sid = "s-cert-%d" % len(created)
        await db.execute("INSERT INTO sessions(id, host_id, title, state, created, created_by_id, origin)"
                         " VALUES(?,?,?,?,?,?,?)", sid, host_id, title, "live", time.time(),
                         created_by_id, origin or "web")
        return {"id": sid, "host_id": host_id, "title": title}

    core.create_session = fake_create
    try:
        r = await owner.post(url, json={"domain": "wt.example.com", "stepup_password": U.OWNER_PW})
        check("before a host is picked → 409 certs.noRenewHost", r.status_code == 409 and U.code(r) == "certs.noRenewHost",
              r.text[:200])
        r = await owner.put("/api/certs/renew-host", json={"host_id": hid})
        check("Owner picks the gateway host", r.status_code == 200 and r.json()["renew_host"]["id"] == hid, r.text[:200])
        cmds = {i["name"]: i["renew_command"] for i in (await owner.get("/api/certs")).json()["items"]}
        check("status carries server-built commands (none until a check ran)", cmds == {} or all(cmds.values()), cmds)

        r = await admin.post(url, json={"domain": "wt.example.com", "stepup_password": "parolabuna1"})
        check("Admin (has session.open everywhere) cannot open the renew terminal", r.status_code == 403
              and U.code(r) == "authz.denied", r.text[:200])
        r = await op.post(url, json={"domain": "wt.example.com"})
        check("Operator → 403", r.status_code == 403)
        r = await owner.post("/api/hosts/%d/cert-renew" % ssh_hid, json={"domain": "wt.example.com"})
        check("another host than the picked one → 409 certs.wrongRenewHost", r.status_code == 409
              and U.code(r) == "certs.wrongRenewHost", r.text[:200])
        for d in ("evil.example.com", "wt.example.com;id", "*.wt.example.com && id", "$(id)"):
            r = await owner.post(url, json={"domain": d, "stepup_password": U.OWNER_PW})
            check("name %r not monitored → 400 certs.badDomain" % d, r.status_code == 400
                  and U.code(r) == "certs.badDomain", r.text[:200])
        r = await owner.post(url, json={"domain": "wt.example.com"})
        check("no fresh second factor → 403 stepup.*, nothing created", r.status_code == 403
              and U.code(r).startswith("stepup.") and not created, "%s %s" % (r.status_code, U.code(r)))
        r = await owner.post(url, json={"domain": "wt.example.com", "stepup_password": "wrong-password"})
        check("a wrong password → refused, nothing created", r.status_code in (401, 403) and not created, r.status_code)
        r = await owner.post(url, json={"domain": "*.wt.example.com", "stepup_password": U.OWNER_PW})
        check("Owner + picked host + monitored name + fresh factor → the session", r.status_code == 200
              and r.json()["id"] == "s-cert-1", r.text[:200])
        check("…returns the exact command", r.json().get("command")
              == "sudo -k /opt/webterm/scripts/cert-renew.sh --domain '*.wt.example.com'", r.json())
        cmd = created[0]["cmd"] if created else ""
        check("…the session command TYPES it (read -e -i), passed as an argument",
              "read -r -e -i" in cmd and shlex.quote("sudo -k /opt/webterm/scripts/cert-renew.sh --domain '*.wt.example.com'") in cmd,
              cmd[-300:])
        check("…on the picked host only", created and created[0]["host_id"] == hid)
        aud = await db.fetchone("SELECT detail FROM audit_log WHERE path=? ORDER BY id DESC LIMIT 1", url)
        check("…audited (command typed, not run)", aud and "typed, not run" in aud["detail"], aud and aud["detail"])
        # ── review F2: the fresh-factor window opened by /stepup on a host WITHOUT require_2fa ──
        from app import security, totp as totp_mod
        security._stepup_windows.clear()
        n = len(created)
        r = await owner.post("/api/hosts/%d/stepup" % hid, json={})
        check("follow-up 4: a /stepup that opens nothing says so: {ok, opened: false, window: 0}",
              r.status_code == 200 and r.json() == {"ok": True, "opened": False, "window": 0}, r.text[:200])
        r = await owner.post("/api/hosts/%d/stepup" % hid, json={"stepup_password": U.OWNER_PW})
        check("password-only account: /stepup with the password still opens the window", r.status_code == 200
              and r.json().get("opened") is True and r.json().get("window", 0) > 290, r.text[:200])
        r = await owner.post(url, json={"domain": "wt.example.com"})
        check("…and the fresh-factor gate accepts it (unchanged behaviour)", r.status_code == 200
              and len(created) == n + 1, r.text[:200])
        secret = totp_mod.new_secret()
        await db.execute("UPDATE users SET totp_enabled=1, totp_secret_encrypted=?, totp_last_counter=0 WHERE id=?",
                         security.encrypt_secret(secret), owner_uid)
        security._stepup_windows.clear()
        n = len(created)
        r = await owner.post("/api/hosts/%d/stepup" % hid, json={"stepup_password": U.OWNER_PW})
        check("TOTP account, host without 2FA: password-only /stepup → 403 stepup.totp",
              r.status_code == 403 and U.code(r) == "stepup.totp", "%s %s" % (r.status_code, r.text[:200]))
        r = await owner.post(url, json={"domain": "wt.example.com"})
        check("…and the fresh-factor gate stays closed (nothing created)", r.status_code == 403
              and U.code(r) == "stepup.totp" and len(created) == n, r.text[:200])
        r = await owner.post("/api/hosts/%d/stepup" % hid, json={"stepup_totp": totp_mod.generate(secret)})
        check("…a TOTP code on /stepup opens it (it used to be silently ignored there)", r.status_code == 200,
              r.text[:200])
        r = await owner.post(url, json={"domain": "wt.example.com"})
        check("…then the renew terminal opens", r.status_code == 200 and len(created) == n + 1, r.text[:200])
        await db.execute("UPDATE users SET totp_enabled=0, totp_secret_encrypted=NULL WHERE id=?", owner_uid)

        # ── review F4: nobody but the opener types into a renew terminal; it cannot be shared ──
        await db.execute("INSERT INTO sessions(id, host_id, title, state, created, created_by_id, origin)"
                         " VALUES(?,?,?,?,?,?,?)", "s-renew-x", hid, "TLS renew", "live", time.time(),
                         owner_uid, "cert-renew")
        await db.execute("INSERT INTO sessions(id, host_id, title, state, created, created_by_id, origin)"
                         " VALUES(?,?,?,?,?,?,?)", "s-plain-x", hid, "plain", "live", time.time(),
                         owner_uid, "web")
        from app import api as api_mod
        admin_uid = (await db.fetchone("SELECT id FROM users WHERE email='admin@x.co'"))["id"]
        rr = await db.fetchone("SELECT * FROM sessions WHERE id='s-renew-x'")
        rp = await db.fetchone("SELECT * FROM sessions WHERE id='s-plain-x'")
        check("Admin (session.manage) may type into the Owner's ordinary session (unchanged)",
              await api_mod._ws_access(admin_uid, rp) == "rw")
        check("…but only WATCH the Owner's certificate-renewal terminal", await api_mod._ws_access(admin_uid, rr) == "ro")
        check("…the Owner still types into it", await api_mod._ws_access(owner_uid, rr) == "rw")
        r = await owner.post("/api/sessions/s-renew-x/share", json={"writable": False})
        check("a renewal terminal cannot be shared (403 certs.renewSessionPrivate)", r.status_code == 403
              and U.code(r) == "certs.renewSessionPrivate", r.text[:200])
        st = await db.fetchone("SELECT origin, created_by_id FROM sessions WHERE id=?", "s-cert-1")
        check("sessions opened by the renew route are stamped origin=cert-renew, owned by the Owner",
              st is not None and st["origin"] == "cert-renew" and st["created_by_id"] == owner_uid, st and dict(st))

        tok = U.client(headers={"authorization": "Bearer wt_nope"})
        r = await tok.post(url, json={"domain": "wt.example.com"})
        check("a Bearer token cannot open it", r.status_code in (401, 403), r.status_code)
    finally:
        certmon.targets, core.create_session = orig_targets, orig_create

    # ── follow-up 3: creator + origin are in the row from its very first SELECT (real core) ──
    from app import api as api_mod, security as sec
    admin_uid = (await db.fetchone("SELECT id FROM users WHERE email='admin@x.co'"))["id"]
    seen = {}

    class FirstLook:
        epoch = 0

        async def create(self, sid, rows, cols, term, tz, cmd, pw):
            # called right after the INSERT, before anything else touches the row
            row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
            seen.update(state=row["state"], by=row["created_by_id"], origin=row["origin"],
                        admin=await api_mod._ws_access(admin_uid, row),
                        owner=await api_mod._ws_access(owner_uid, row))
            return {"ok": False, "code": "test-stop"}

    certmon.targets = lambda fwd="": T
    core.sources[hid] = FirstLook()
    try:
        sec._stepup_windows.clear()
        r = await owner.put("/api/certs/renew-host", json={"host_id": hid})
        r = await owner.post(url, json={"domain": "wt.example.com", "stepup_password": U.OWNER_PW})
        check("real core.create_session: at the first SELECT the row is 'creating', owned by the Owner,"
              " origin=cert-renew", seen.get("state") == "creating" and seen.get("by") == owner_uid
              and seen.get("origin") == "cert-renew", "%s %s" % (seen, r.text[:200]))
        check("…read-write only for its opener from that moment (Admin: ro, Owner: rw)",
              seen.get("admin") == "ro" and seen.get("owner") == "rw", seen)
    finally:
        core.sources.pop(hid, None)
        certmon.targets = orig_targets
    r = await owner.put("/api/certs/renew-host", json={"host_id": 0})
    check("the pick can be cleared", r.status_code == 200 and r.json()["renew_host"] is None)
    return owner_uid


async def amain():
    await U.boot()
    owner_uid = await test_routes()
    await test_dedup(owner_uid)
    await db.close()


def main():
    test_reading()
    test_probe()
    test_targets()
    test_command_builder()
    test_typed_cmd()
    asyncio.run(amain())
    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
