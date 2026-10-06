"""„Test connection" din Add host (POST /api/hosts/test) + cheia generată la creare (3.5.4).

Hermetic: server SSH REAL in-process (asyncssh), ascultători TCP locali, un FakeAgent care face
forward real pentru jump, API in-process (ASGI). Acoperă:
  * etapele: port închis → tcp; ascultător non-SSH → banner; SSH real → host key întors, parolă
    greşită → auth, parolă bună → ok; fără credenţial → auth „sărit";
  * nimic lăsat deschis (nicio sursă, nicio conexiune la server după test, niciun host creat);
  * metadatele cloud blocate (text, IPv4-mapat, după rezolvare), portul validat, plafonul per user,
    tokenurile de automatizare refuzate, step-up pe hostul 2FA editat;
  * credenţialul nu ajunge nici în audit, nici în loguri;
  * pin_hostkey acceptat DOAR dacă e cheia văzută de test (aceeaşi ţintă, cache neexpirat);
    pinul existent nu poate fi schimbat prin PATCH pe aceeaşi ţintă; hostul editat cu pin diferit
    → refuz ÎNAINTE de auth;
  * ciclul cheii în aşteptare: generare → test → legare la creare; expirare; alt user nu o leagă;
  * jump: agent offline → cod; prin agent (FakeAgent) → ok; telnet: prompt / tăcere.
"""
import asyncio
import json
import logging
import os
import socket
import sys
import tempfile
import time
import uuid

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import asyncssh  # noqa: E402
import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402
from app.main import app  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
PW = "parola-cont-123456"
SSH_USER = "tester"
GOOD = "parola-e2e-good-123456"       # parola bună a ţintei — NU trebuie să apară în audit/loguri
BAD = "parola-e2e-bad-654321"
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


AUTH_KEYS = set()            # cheile publice acceptate de server (tip + blob)
STATS = {"active": 0, "pw_tries": 0}


class _Server(asyncssh.SSHServer):
    def connection_made(self, conn):
        STATS["active"] += 1

    def connection_lost(self, exc):
        STATS["active"] -= 1

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        STATS["pw_tries"] += 1
        return username == SSH_USER and password == GOOD

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return " ".join(key.export_public_key().decode().split()[:2]) in AUTH_KEYS


class FakeAgent(core.AgentConnection):
    """AgentConnection minimal (ca în ssh_jump_test): `open_forward` deschide un socket REAL către
    ţinta din test şi pompează octeţii pe un ForwardStream — rolul agentului real."""

    def __init__(self, host_id, target):
        self.host_id = host_id
        self.forwards = {}
        self._target = target
        self._wr = {}

    async def open_forward(self, host, port):
        try:
            reader, writer = await asyncio.open_connection(*self._target)
        except OSError as e:
            raise core.ForwardError("connect failed: %s" % e)
        stream = uuid.uuid4().hex
        fs = core.ForwardStream(self, stream)
        self.forwards[stream] = fs
        self._wr[stream] = writer

        async def feed():
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        fs._eof()
                        break
                    fs._feed(data)
            except Exception:       # noqa: BLE001
                fs._eof()
        asyncio.create_task(feed())
        return fs

    async def send_fwd(self, stream_id, data):
        w = self._wr.get(stream_id)
        if w:
            w.write(data)
            await w.drain()

    async def request(self, op, timeout=20.0, **fields):
        if op == "fwd_close":
            w = self._wr.pop(fields.get("stream"), None)
            if w:
                w.close()
            return {"ok": True}
        return {"ok": False}


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        try:
            self.lines.append(record.getMessage())
        except Exception:           # noqa: BLE001
            self.lines.append(str(record.msg))


def _stage(r, sid):
    return next((s for s in r.get("stages", []) if s["id"] == sid), None)


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    cap = _Capture()
    logging.getLogger().addHandler(cap)           # logul gateway-ului (webterm, INFO+)
    sshlog = logging.getLogger("asyncssh")        # asyncssh la DEBUG, captat fără zgomot pe consolă
    sshlog.addHandler(cap)
    sshlog.setLevel(logging.DEBUG)
    sshlog.propagate = False
    core.PROBE_BANNER_WAIT = 0.6         # testele de tăcere nu aşteaptă 5 s
    core.PROBE_TELNET_WAIT = 0.6

    hostkey = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(_Server, "127.0.0.1", 0, server_host_keys=[hostkey])
    sport = server.sockets[0].getsockname()[1]
    server_fp = hostkey.get_fingerprint()
    server_pub = hostkey.export_public_key().decode().strip()

    async def http_junk(reader, writer):
        writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    async def silent(reader, writer):
        await asyncio.sleep(3)
        writer.close()

    async def telnet_login(reader, writer):
        writer.write(b"\r\nRouter\r\nlogin: ")
        await writer.drain()
        await asyncio.sleep(2)
        writer.close()
    junk = await asyncio.start_server(http_junk, "127.0.0.1", 0)
    quiet = await asyncio.start_server(silent, "127.0.0.1", 0)
    tln = await asyncio.start_server(telnet_login, "127.0.0.1", 0)
    junk_port = junk.sockets[0].getsockname()[1]
    quiet_port = quiet.sockets[0].getsockname()[1]
    tln_port = tln.sockets[0].getsockname()[1]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW, "setup_token": "test-setup"})
        uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]

        def ssh_body(**kw):
            b = {"connection_type": "ssh", "hostname": "127.0.0.1", "ssh_port": sport,
                 "ssh_username": SSH_USER, "auth_method": "password", "credential": GOOD}
            b.update(kw)
            return b

        async def test(**kw):
            api._hosttest_hits.clear()          # plafonul se testează separat
            return await c.post("/api/hosts/test", json=ssh_body(**kw))

        n_hosts = (await db.fetchone("SELECT COUNT(*) n FROM hosts"))["n"]

        # ── tcp: port închis ──
        r = await test(ssh_port=_closed_port())
        j = r.json()
        check("port închis → 200, ok=false", r.status_code == 200 and j.get("ok") is False, r.text[:200])
        st = _stage(j, "tcp")
        check("port închis → etapa tcp picată cu hosttest.refused",
              st and not st["ok"] and st.get("code") == "hosttest.refused", str(j)[:200])
        check("fără proză englezească: etapele au doar coduri", all("message" not in s for s in j["stages"]))

        # ── banner: ascultător care nu e SSH ──
        r = await test(ssh_port=junk_port)
        j = r.json()
        check("non-SSH → tcp ok", (_stage(j, "tcp") or {}).get("ok") is True, str(j)[:200])
        st = _stage(j, "banner")
        check("non-SSH → banner picat cu hosttest.notSsh",
              st and not st["ok"] and st.get("code") == "hosttest.notSsh", str(j)[:200])
        r = await test(ssh_port=quiet_port)
        st = _stage(r.json(), "banner")
        check("ascultător tăcut → banner picat cu ssh.noBanner (acelaşi cod ca la conectare)",
              st and st.get("code") == "ssh.noBanner", r.text[:200])

        # ── SSH real: parolă greşită ──
        STATS["pw_tries"] = 0
        r = await test(credential=BAD)
        j = r.json()
        check("parolă greşită → ok=false", j.get("ok") is False, r.text[:200])
        check("parolă greşită → tcp/banner/hostkey ok",
              all((_stage(j, s) or {}).get("ok") for s in ("tcp", "banner", "hostkey")), str(j)[:300])
        st = _stage(j, "auth")
        check("parolă greşită → auth picat cu ssh.authFailed", st and st.get("code") == "ssh.authFailed",
              str(st))
        check("banner: versiunea serverului ca detaliu", "SSH-2.0" in ((_stage(j, "banner") or {}).get("detail") or ""))
        check("host key întors: tip + amprentă SHA256 a serverului",
              j.get("hostkey", {}).get("fingerprint_sha256") == server_fp
              and j["hostkey"].get("type") == "ssh-ed25519", str(j.get("hostkey")))

        # ── SSH real: parolă bună ──
        r = await test()
        j = r.json()
        check("parolă bună → ok=true, 4 etape ok",
              j.get("ok") is True and [s["id"] for s in j["stages"]] == ["tcp", "banner", "hostkey", "auth"]
              and all(s["ok"] for s in j["stages"]), str(j)[:300])
        check("fiecare etapă are durata (ms)", all(isinstance(s.get("ms"), int) for s in j["stages"]))
        good_key = j.get("hostkey", {}).get("key", "")
        check("cheia de pinat întoarsă = cheia serverului", good_key.split()[:2] == server_pub.split()[:2])
        await asyncio.sleep(0.3)
        check("nimic lăsat deschis: serverul nu mai are conexiuni", STATS["active"] == 0, str(STATS))
        check("nicio sursă înregistrată în core.sources", not any(isinstance(s, core.SshSource)
                                                                  for s in core.sources.values()))
        check("testul nu salvează nimic (niciun host nou)",
              (await db.fetchone("SELECT COUNT(*) n FROM hosts"))["n"] == n_hosts)

        # ── fără credenţial: până la host key, auth sărit ──
        STATS["pw_tries"] = 0
        r = await test(credential="")
        j = r.json()
        st = _stage(j, "auth")
        check("fără credenţial → auth sărit (skipped, hosttest.authSkipped), ok=true",
              j.get("ok") is True and st and st.get("skipped") and st.get("code") == "hosttest.authSkipped",
              str(j)[:300])
        check("fără credenţial → nicio parolă încercată", STATS["pw_tries"] == 0, str(STATS))

        # ── validare de intrare ──
        r = await test(ssh_port=0)
        check("port 0 → 400 hosttest.badPort", r.status_code == 400
              and r.headers.get("x-webterm-error") == "hosttest.badPort", r.text[:150])
        r = await test(ssh_port=70000)
        check("port 70000 → 400 hosttest.badPort", r.status_code == 400)
        r = await test(connection_type="agent")
        check("tip agent → 400 hosttest.badType", r.headers.get("x-webterm-error") == "hosttest.badType")

        # ── metadatele cloud: blocate pe text, IPv4-mapat şi după rezolvare ──
        for h in ("169.254.169.254", "metadata.google.internal", "[fd00:ec2::254]", "::ffff:169.254.169.254"):
            r = await test(hostname=h, ssh_port=80)
            check("metadate %s → 400 hosttest.blocked" % h, r.status_code == 400
                  and r.headers.get("x-webterm-error") == "hosttest.blocked", r.text[:150])
        orig_resolve = core.resolve_target

        async def evil_resolve(hostname, port):
            if hostname == "innocent.example":
                return [(socket.AF_INET, ("169.254.169.254", port))]
            return await orig_resolve(hostname, port)
        core.resolve_target = evil_resolve
        r = await test(hostname="innocent.example", ssh_port=80)
        check("nume care REZOLVĂ la metadate → 400 hosttest.blocked", r.status_code == 400
              and r.headers.get("x-webterm-error") == "hosttest.blocked", r.text[:150])
        core.resolve_target = orig_resolve
        r = await test(hostname="no-such-host.invalid")
        st = _stage(r.json(), "tcp")
        check("nume nerezolvabil → tcp picat cu hosttest.dns", st and st.get("code") == "hosttest.dns", r.text[:200])

        # ── plafonul per user ──
        api._hosttest_hits.clear()
        closed = _closed_port()
        codes = []
        for _ in range(api.HOSTTEST_RATE + 1):
            r = await c.post("/api/hosts/test", json=ssh_body(ssh_port=closed))
            codes.append(r.status_code)
        check("primele %d teste trec, al %d-lea → 429" % (api.HOSTTEST_RATE, api.HOSTTEST_RATE + 1),
              codes[:-1] == [200] * api.HOSTTEST_RATE and codes[-1] == 429, str(codes))
        check("429 cu cod hosttest.rateLimited + Retry-After",
              r.headers.get("x-webterm-error") == "hosttest.rateLimited" and r.headers.get("retry-after"))
        api._hosttest_hits.clear()

        # ── tokenurile de automatizare: refuzate (doar cookie) ──
        r = await c.post("/api/tokens", json={"name": "auto", "scopes": ["read", "run"], "days": 1,
                                              "current_password": PW})
        tok = r.json().get("token", "")
        async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                     headers=dict(_ORIGIN, authorization="Bearer " + tok)) as tc:
            r = await tc.post("/api/hosts/test", json=ssh_body())
            check("token de automatizare → 401", r.status_code == 401, str(r.status_code))
            r = await tc.post("/api/hosts/ssh-key/pending", json={})
            check("token de automatizare nu generează chei → 401", r.status_code == 401, str(r.status_code))

        # ── credenţialul NU apare în audit sau în loguri ──
        rows = await db.fetchall("SELECT detail FROM audit_log WHERE path='/api/hosts/test'")
        details = " ".join(r["detail"] or "" for r in rows)
        check("auditul are urma testului (host:port → rezultat)",
              "connection test (ssh) to 127.0.0.1:%d → ok" % sport in details, details[:300])
        check("auditul are şi eşecul cu etapa + codul", "failed at auth (ssh.authFailed)" in details)
        check("parola NU e în audit", GOOD not in details and BAD not in details)
        logs = "\n".join(cap.lines)
        check("parola NU e în loguri (gateway + asyncssh)", GOOD not in logs and BAD not in logs)

        # ── pin_hostkey: doar cheia văzută de test, pe aceeaşi ţintă ──
        r = await test()
        good_key = r.json()["hostkey"]["key"]
        other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
        base = {"name": "pin-ok", "connection_type": "ssh", "hostname": "127.0.0.1", "ssh_port": sport,
                "ssh_username": SSH_USER, "auth_method": "password", "credential": GOOD}
        r = await c.post("/api/hosts", json=dict(base, name="pin-forged", pin_hostkey=other))
        check("pin_hostkey inventat → 400 hosttest.pinMismatch", r.status_code == 400
              and r.headers.get("x-webterm-error") == "hosttest.pinMismatch", r.text[:150])
        r = await c.post("/api/hosts", json=dict(base, name="pin-wrongport", ssh_port=sport + 1,
                                                  pin_hostkey=good_key))
        check("pin_hostkey pentru ALTĂ ţintă (alt port) → 400", r.status_code == 400, r.text[:150])
        r = await c.post("/api/hosts", json=dict(base, pin_hostkey=good_key))
        check("pin_hostkey = cheia testului → 200", r.status_code == 200, r.text[:150])
        pid_host = r.json().get("id")
        row = await db.fetchone("SELECT known_hosts FROM hosts WHERE id=?", pid_host)
        check("hostul salvat e pinat de la început cu cheia serverului",
              row and (row["known_hosts"] or "").split()[:2] == server_pub.split()[:2], str(row and row["known_hosts"]))
        r = await c.post("/api/hosts", json=dict(base, name="pin-fp", pin_hostkey=server_fp))
        check("pin_hostkey ca amprentă SHA256 → acceptat", r.status_code == 200, r.text[:150])
        # cache expirat
        for k in list(api._tested_hostkeys):
            kl, fp, _ts = api._tested_hostkeys[k]
            api._tested_hostkeys[k] = (kl, fp, time.monotonic() - api.HOSTKEY_TEST_TTL - 5)
        r = await c.post("/api/hosts", json=dict(base, name="pin-stale", pin_hostkey=good_key))
        check("cache-ul testului expirat → pin refuzat", r.status_code == 400, r.text[:150])
        # alt user nu foloseşte testul altuia: cheia cache-ului conţine user_id
        await test()
        check("cache-ul e per user (cheia include user_id)",
              all(k[0] == uid for k in api._tested_hostkeys))

        # editare: hostul pinat cu altă cheie → testul refuză ÎNAINTE de auth
        await db.execute("UPDATE hosts SET known_hosts=? WHERE id=?", other, pid_host)
        STATS["pw_tries"] = 0
        api._tested_hostkeys.clear()
        r = await test(host_id=pid_host)
        j = r.json()
        st = _stage(j, "hostkey")
        check("host editat, pin diferit → hostkey picat cu hosttest.hostKeyMismatch",
              st and st.get("code") == "hosttest.hostKeyMismatch"
              and st.get("vars", {}).get("new_fp") == server_fp, str(j)[:300])
        check("pin diferit → parola NU a fost trimisă ţintei", STATS["pw_tries"] == 0 and _stage(j, "auth") is None,
              str(STATS))
        check("pin diferit → cheia nu intră în cache-ul de pin (deci nici în răspuns ca `key`)",
              not api._tested_hostkeys and "key" not in j.get("hostkey", {}), str(api._tested_hostkeys))
        # un test FĂRĂ host_id vede cheia nouă — dar PATCH-ul nu poate repina pe aceeaşi ţintă
        await test()
        r = await c.patch("/api/hosts/%d" % pid_host, json={"pin_hostkey": good_key})
        check("PATCH cu pin diferit de cel stocat, aceeaşi ţintă → 409 hosttest.pinConflict",
              r.status_code == 409 and r.headers.get("x-webterm-error") == "hosttest.pinConflict", r.text[:150])
        check("pinul stocat a rămas neatins",
              (await db.fetchone("SELECT known_hosts FROM hosts WHERE id=?", pid_host))["known_hosts"] == other)
        # host fără pin: PATCH cu pinul testat îl pinează
        await db.execute("UPDATE hosts SET known_hosts=NULL WHERE id=?", pid_host)
        await test(host_id=pid_host, credential="")      # credenţialul stocat (parola bună)
        r = await c.patch("/api/hosts/%d" % pid_host, json={"pin_hostkey": good_key})
        check("PATCH cu pinul testat pe un host nepinat → pinat", r.status_code == 200
              and (await db.fetchone("SELECT known_hosts FROM hosts WHERE id=?", pid_host))["known_hosts"],
              r.text[:150])
        r = await test(host_id=pid_host, credential="")
        check("edit: testul foloseşte credenţialul STOCAT când nu se tastează altul",
              r.json().get("ok") is True and (_stage(r.json(), "auth") or {}).get("ok") is True, r.text[:300])

        # ── step-up: hostul editat cere 2FA → testul cere step-up ca la conectare ──
        r = await c.post("/api/hosts", json=dict(base, name="h2fa", require_2fa=True))
        h2fa = r.json()["id"]
        r = await test(host_id=h2fa, credential="")
        check("host_id pe un host 2FA, fără step-up → 403", r.status_code == 403, str(r.status_code))

        # ── cheia în aşteptare: generare → test → legare la creare ──
        r = await c.post("/api/hosts/ssh-key/pending", json={})
        j = r.json()
        check("generare → 200 cu pending_key_id + publica ed25519",
              r.status_code == 200 and j.get("pending_key_id") and j.get("public_key", "").startswith("ssh-ed25519 "),
              r.text[:200])
        pend, pub = j["pending_key_id"], j["public_key"]
        prow = await db.fetchone("SELECT * FROM pending_ssh_keys WHERE id=?", pend)
        check("privata e în seif (criptată), nu în clar",
              prow and "PRIVATE KEY" not in prow["credential_encrypted"]
              and "PRIVATE KEY" in json.loads(security.decrypt_secret(prow["credential_encrypted"]))["key"])
        check("generarea NU întoarce privata", "PRIVATE" not in r.text)
        r = await test(credential="", auth_method="key", pending_key_id=pend)
        st = _stage(r.json(), "auth")
        check("test cu cheia în aşteptare ÎNAINTE de authorized_keys → auth picat",
              st and st.get("code") == "ssh.authFailed", r.text[:300])
        AUTH_KEYS.add(" ".join(pub.split()[:2]))
        r = await test(credential="", auth_method="key", pending_key_id=pend)
        check("test cu cheia în aşteptare după authorized_keys → ok", r.json().get("ok") is True, r.text[:300])
        r = await c.post("/api/hosts", json=dict(base, name="keyed", auth_method="password", credential="",
                                                  pending_key_id=pend))
        check("create cu pending_key_id → 200", r.status_code == 200, r.text[:200])
        kid = r.json()["id"]
        hrow = await db.fetchone("SELECT * FROM hosts WHERE id=?", kid)
        cred = api._decode_credential(hrow["credential_encrypted"])
        derived = asyncssh.import_private_key(cred["key"]).export_public_key().decode().split()[:2]
        check("hostul are cheia legată: auth key, politica stored, aceeaşi publică",
              hrow["auth_method"] == "key" and hrow["credential_policy"] == "stored"
              and derived == pub.split()[:2], str(dict(hrow))[:200])
        check("rândul în aşteptare a fost consumat",
              await db.fetchone("SELECT 1 FROM pending_ssh_keys WHERE id=?", pend) is None)
        r = await c.post("/api/hosts", json=dict(base, name="keyed-again", pending_key_id=pend))
        check("aceeaşi cheie a doua oară → 400 sshkey.pendingMissing",
              r.headers.get("x-webterm-error") == "sshkey.pendingMissing", r.text[:150])
        try:
            src = await core.dial_ssh(hrow, cred)
            check("conectarea REALĂ cu cheia legată merge", isinstance(src, core.SshSource))
            core.sources.pop(kid, None)
            await src.disconnect()
        except Exception as e:      # noqa: BLE001
            check("conectarea REALĂ cu cheia legată merge", False, repr(e))
        # PATCH cu o cheie nouă în aşteptare
        p2 = (await c.post("/api/hosts/ssh-key/pending", json={})).json()["pending_key_id"]
        r = await c.patch("/api/hosts/%d" % pid_host, json={"pending_key_id": p2})
        prow = await db.fetchone("SELECT auth_method, credential_policy FROM hosts WHERE id=?", pid_host)
        check("PATCH cu pending_key_id → hostul trece pe cheie stocată",
              r.status_code == 200 and prow["auth_method"] == "key" and prow["credential_policy"] == "stored",
              r.text[:150])
        # expirare
        p3 = (await c.post("/api/hosts/ssh-key/pending", json={})).json()["pending_key_id"]
        await db.execute("UPDATE pending_ssh_keys SET created=? WHERE id=?", time.time() - core.PENDING_KEY_TTL - 5, p3)
        r = await test(credential="", auth_method="key", pending_key_id=p3)
        check("cheie expirată → testul o refuză (400 sshkey.pendingMissing)",
              r.headers.get("x-webterm-error") == "sshkey.pendingMissing", r.text[:150])
        r = await c.post("/api/hosts", json=dict(base, name="keyed-stale", pending_key_id=p3))
        check("cheie expirată → create o refuză", r.status_code == 400, r.text[:150])
        await core.purge_pending_ssh_keys()
        check("purge şterge cheia expirată", await db.fetchone("SELECT 1 FROM pending_ssh_keys WHERE id=?", p3) is None)
        # alt user: rând al altcuiva (user_id diferit) — nu se leagă şi nu se testează
        foreign = (await c.post("/api/hosts/ssh-key/pending", json={})).json()["pending_key_id"]
        await db.execute("UPDATE pending_ssh_keys SET user_id=? WHERE id=?", uid + 100, foreign)
        r = await c.post("/api/hosts", json=dict(base, name="keyed-foreign", pending_key_id=foreign))
        check("cheia altui user → 400 (nu se leagă)", r.headers.get("x-webterm-error") == "sshkey.pendingMissing",
              r.text[:150])
        check("cheia altui user rămâne a lui (neconsumată)",
              await db.fetchone("SELECT 1 FROM pending_ssh_keys WHERE id=?", foreign) is not None)
        r = await test(credential="", auth_method="key", pending_key_id=foreign)
        check("cheia altui user nu poate fi nici testată", r.status_code == 400)
        r = await c.post("/api/hosts", json={"name": "tel", "connection_type": "telnet", "hostname": "10.0.0.1",
                                             "pending_key_id": "x"})
        check("pending_key_id pe telnet → 400 sshkey.notSsh", r.headers.get("x-webterm-error") == "sshkey.notSsh")

        # ── /ssh-key/generate (edit) scrie acum blob JSON: conectarea nu mai crapă ──
        r = await c.post("/api/hosts/%d/ssh-key/generate" % kid, json={})
        hrow = await db.fetchone("SELECT * FROM hosts WHERE id=?", kid)
        check("generate (edit) → credenţial citibil de _resolve_credential",
              r.status_code == 200 and "key" in api._resolve_credential(hrow))
        await db.execute("UPDATE hosts SET credential_encrypted=? WHERE id=?",
                         security.encrypt_secret(asyncssh.generate_private_key("ssh-ed25519")
                                                 .export_private_key().decode()), kid)
        hrow = await db.fetchone("SELECT * FROM hosts WHERE id=?", kid)
        check("rând vechi cu PEM gol (dinainte de 3.5.4) → tot citibil", "key" in api._resolve_credential(hrow))
        r = await c.post("/api/hosts/%d/ssh-key/public" % kid, json={})
        check("show public key merge pe rândul vechi", r.status_code == 200, r.text[:150])

        # ── jump: agentul via offline / nu e agent / online prin tunel ──
        r = await c.post("/api/hosts", json={"name": "agent-a", "connection_type": "agent"})
        aid = r.json()["id"]
        r = await test(connection_type="ssh-jump", via_host_id=aid, hostname="10.9.9.9")
        check("jump cu agentul via OFFLINE → 409 hosttest.viaOffline", r.status_code == 409
              and r.headers.get("x-webterm-error") == "hosttest.viaOffline", r.text[:150])
        r = await test(connection_type="ssh-jump", via_host_id=pid_host)
        check("jump cu via care NU e agent → 400 sshjump.needsAgent",
              r.headers.get("x-webterm-error") == "sshjump.needsAgent", r.text[:150])
        core.sources[aid] = FakeAgent(aid, ("127.0.0.1", sport))
        r = await test(connection_type="ssh-jump", via_host_id=aid, hostname="10.9.9.9")
        j = r.json()
        check("jump prin agent (tunel real) → ok, 4 etape", j.get("ok") is True and len(j["stages"]) == 4, str(j)[:300])
        check("jump: nicio sursă înregistrată, niciun forward rămas",
              not any(isinstance(s, core.SshSource) for s in core.sources.values())
              and not core.sources[aid].forwards, str(core.sources[aid].forwards))
        jkey = j.get("hostkey", {}).get("key", "")
        r = await c.post("/api/hosts", json=dict(base, name="jump-pinned", connection_type="ssh-jump",
                                                  hostname="10.9.9.9", via_host_id=aid, pin_hostkey=jkey))
        check("jump: pin_hostkey de la test acceptat la creare", r.status_code == 200, r.text[:150])
        core.sources[aid] = FakeAgent(aid, ("127.0.0.1", _closed_port()))
        r = await test(connection_type="ssh-jump", via_host_id=aid, hostname="10.9.9.9")
        st = _stage(r.json(), "tcp")
        check("jump: agentul nu ajunge la ţintă → tcp picat cu sshjump.unreachable",
              st and st.get("code") == "sshjump.unreachable", r.text[:200])

        # ── telnet: prompt / tăcere, direct şi prin agent ──
        r = await test(connection_type="telnet", ssh_port=tln_port, credential="")
        j = r.json()
        st = _stage(j, "banner")
        check("telnet: tcp ok + prompt de login detectat", j.get("ok") is True and st and st["ok"]
              and st.get("detail") == "prompt", str(j)[:200])
        r = await test(connection_type="telnet", ssh_port=quiet_port, credential="")
        j = r.json()
        st = _stage(j, "banner")
        check("telnet tăcut → avertisment (warn, hosttest.telnetSilent), ok=true",
              j.get("ok") is True and st and st.get("warn") and st.get("code") == "hosttest.telnetSilent", str(j)[:200])
        r = await test(connection_type="telnet", ssh_port=_closed_port(), credential="")
        st = _stage(r.json(), "tcp")
        check("telnet port închis → tcp picat", st and st.get("code") == "hosttest.refused", r.text[:200])
        core.sources[aid] = FakeAgent(aid, ("127.0.0.1", tln_port))
        r = await test(connection_type="telnet-jump", via_host_id=aid, hostname="10.9.9.8", ssh_port=23,
                       credential="")
        j = r.json()
        check("telnet-jump prin agent → prompt", j.get("ok") is True
              and (_stage(j, "banner") or {}).get("detail") == "prompt", str(j)[:200])
        check("telnet-jump: forward-ul închis după test", not core.sources[aid].forwards)
        core.sources.pop(aid, None)

        logs = "\n".join(cap.lines)
        check("la final: parolele tot nu apar în loguri", GOOD not in logs and BAD not in logs)

    logging.getLogger().removeHandler(cap)
    server.close()
    for s in (junk, quiet, tln):
        s.close()
    await db.close()
    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
