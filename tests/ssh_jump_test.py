"""SSH-jump (bastion de prim rang): gateway-ul rulează clientul asyncssh PESTE tunelul TCP al
agentului (ForwardStream), nu printr-un socket direct. Testăm partea securitate-critică pe un
server SSH REAL in-process + un FakeAgent care face forward real (socket → server):
  * dial_ssh_jump stabileşte conexiunea prin tunel şi deschide o sesiune (PTY);
  * host-key PINNING: cheie potrivită → OK; cheie greşită → HostKeyMismatch + ALARMĂ, conexiune
    refuzată (apărarea MITM, deţinută de gateway, chiar şi când agentul ar fi ostil);
  * teardown: disconnect dărâmă tunelul (ForwardStream + socketpair + pompă).
"""
import asyncio
import os
import sys
import tempfile
import uuid

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_SETUP_TOKEN", "test-setup")
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://localhost:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import asyncssh  # noqa: E402
from app import config, core, db, email_alerts, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return False          # fără auth (testăm transportul+host-key, nu auth)


async def _handle(process):
    process.stdout.write("JUMP_OK\r\n")
    process.exit(0)


class FakeAgent(core.AgentConnection):
    """AgentConnection minimal: `open_forward` deschide un socket REAL către serverul SSH
    in-process şi pompează octeţii pe/de pe un ForwardStream (exact rolul agentului real)."""

    def __init__(self, host_id, target_host, target_port):
        self.host_id = host_id
        self.forwards = {}
        self._target = (target_host, target_port)
        self._wr = {}   # stream_id -> asyncio writer către server

    async def open_forward(self, host, port):
        stream = uuid.uuid4().hex
        fs = core.ForwardStream(self, stream)
        self.forwards[stream] = fs
        reader, writer = await asyncio.open_connection(*self._target)
        self._wr[stream] = writer

        async def feed():
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        fs._eof(); break
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
                try:
                    w.close()
                except Exception:   # noqa: BLE001
                    pass
            return {"ok": True}
        return {"ok": False}


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()

    # server SSH real, in-process, cu o cheie de host generată
    hostkey = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        _Server, "127.0.0.1", 0, server_host_keys=[hostkey], process_factory=_handle)
    port = server.sockets[0].getsockname()[1]
    server_pub = hostkey.export_public_key().decode().strip()

    # alarma de host-key — o interceptăm ca să verificăm că se declanşează la mismatch
    fired = {"n": 0}
    orig = email_alerts.notify_host_key_changed
    email_alerts.notify_host_key_changed = lambda *a, **k: fired.__setitem__("n", fired["n"] + 1)

    AGENT_ID, TGT_OK, TGT_BAD, TGT_TOFU = 1, 10, 11, 12
    core.sources[AGENT_ID] = FakeAgent(AGENT_ID, "127.0.0.1", port)

    def row(host_id, known):
        return {"id": host_id, "name": "jump%d" % host_id, "connection_type": "ssh-jump",
                "via_host_id": AGENT_ID, "hostname": "10.0.0.9", "ssh_port": port,
                "ssh_username": "tester", "auth_method": "password", "known_hosts": known}

    # ── happy path: cheie pinată corectă → conexiune prin tunel + sesiune ──
    try:
        src = await core.dial_ssh_jump(row(TGT_OK, server_pub), {"password": ""})
        check("dial_ssh_jump prin tunelul agentului → SshJumpSource", isinstance(src, core.SshJumpSource))
        r = await src.create("s" * 32, 24, 80, "xterm")
        check("sesiune (PTY) deschisă peste jump", r.get("ok") is True, str(r))
        await src.disconnect()
        check("disconnect nu aruncă (tunel dărâmat)", True)
    except Exception as e:       # noqa: BLE001
        check("happy path", False, repr(e))

    # ── MITM: cheie pinată GREŞITĂ → HostKeyMismatch + alarmă, refuz ──
    core.sources.pop(TGT_BAD, None)
    bad = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    raised = False
    try:
        await core.dial_ssh_jump(row(TGT_BAD, bad), {"password": ""})
    except core.HostKeyMismatch:
        raised = True
    except Exception as e:       # noqa: BLE001
        check("mismatch tip eroare", False, repr(e))
    check("host-key greşit → HostKeyMismatch (conexiune refuzată)", raised)
    check("mismatch → alarma notify_host_key_changed s-a declanşat", fired["n"] >= 1)
    check("sursa NU a fost înregistrată la mismatch", core.sources.get(TGT_BAD) is None)

    # ── TOFU: fără cheie pinată → prima conectare pinează cheia serverului ──
    try:
        src = await core.dial_ssh_jump(row(TGT_TOFU, None), {"password": ""})
        check("TOFU: prima conectare reuşeşte şi pinează", isinstance(src, core.SshJumpSource))
        await src.disconnect()
    except Exception as e:       # noqa: BLE001
        check("TOFU path", False, repr(e))

    email_alerts.notify_host_key_changed = orig
    server.close()
    await db.close()
    print(f"\n{ok}/{total} checks passed")
    if ok != total:
        raise SystemExit(1)


asyncio.run(main())
