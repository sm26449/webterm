"""Telnet-jump (bastion telnet salvat): o ţintă telnet din LAN-ul unui agent, salvată ca host
cuibărit (connection_type='telnet-jump', via_host_id=agent). Gateway-ul deschide un ForwardStream
prin agent şi vorbeşte telnet peste el (ForwardTelnetSource — acelaşi cod ca bastionul telnet din
forward-uri), cu sesiunea aparţinând host-ului telnet-jump. Testăm pe un server TCP REAL in-process
+ un FakeAgent care face forward real:
  * _telnet_agent_for rezolvă agentul prin via_host_id (telnet-jump) ŞI direct (host=agent);
  * create_telnet_jump_session deschide sesiunea prin tunel, o marchează 'live', iar banner-ul
    device-ului ajunge la hub;
  * agentul offline → AgentGone (conexiune refuzată, nimic „live" fantomă).
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

from app import config, core, db, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeAgent(core.AgentConnection):
    """AgentConnection minimal: `open_forward` deschide un socket REAL către serverul TCP
    in-process şi pompează octeţii pe/de pe un ForwardStream (exact rolul agentului real)."""

    def __init__(self, host_id, target_host, target_port):
        self.host_id = host_id
        self.forwards = {}
        self._target = (target_host, target_port)
        self._wr = {}

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
            w.write(data); await w.drain()

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

    # device telnet trivial: scrie un banner la connect (fără negociere IAC — shim-ul o tolerează)
    async def _dev(reader, writer):
        writer.write(b"login: ")
        await writer.drain()
        try:
            await reader.read(65536)      # consumă ce vine, ţine socketul deschis
        except Exception:                 # noqa: BLE001
            pass
    server = await asyncio.start_server(_dev, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    # capturăm output-ul livrat la hub (banner-ul device-ului) fără un client WS real
    seen = bytearray()
    orig_on_output = core.SessionHub.on_output

    async def _rec(self, data):
        seen.extend(data)
        return await orig_on_output(self, data)
    core.SessionHub.on_output = _rec

    AGENT_ID, TGT_ID = 1, 20
    core.sources[AGENT_ID] = FakeAgent(AGENT_ID, "127.0.0.1", port)

    # host-uri reale în DB: agentul + ţinta telnet-jump cuibărită sub el (pt. _telnet_agent_for)
    import time as _t
    await db.execute("INSERT INTO hosts(id, name, token_hash, token_encrypted, created, connection_type)"
                     " VALUES(?,?,?,?,?,?)", AGENT_ID, "agent1", "tok-agent", "enc-agent", _t.time(), "agent")
    await db.execute(
        "INSERT INTO hosts(id, name, token_hash, token_encrypted, created, connection_type,"
        " via_host_id, hostname, ssh_port) VALUES(?,?,?,?,?,?,?,?,?)",
        TGT_ID, "switch-lan", "tok-tgt", "enc-tgt", _t.time(), "telnet-jump", AGENT_ID, "10.0.0.9", port)
    trow = await db.fetchone("SELECT * FROM hosts WHERE id=?", TGT_ID)

    # ── _telnet_agent_for: telnet-jump → rezolvă agentul prin via_host_id; agent → direct ──
    a1 = await core._telnet_agent_for(TGT_ID)
    check("_telnet_agent_for(telnet-jump) → agentul via_host_id", a1 is core.sources[AGENT_ID])
    a2 = await core._telnet_agent_for(AGENT_ID)
    check("_telnet_agent_for(agent) → agentul direct", a2 is core.sources[AGENT_ID])

    # ── happy path: sesiune telnet-jump prin tunel, 'live', banner ajuns la hub ──
    try:
        res = await core.create_telnet_jump_session(trow, "sw", 24, 80)
        sid = res["id"]
        check("create_telnet_jump_session întoarce un id", bool(sid))
        srow = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
        check("sesiunea e 'live'", srow["state"] == "live", srow["state"])
        check("kind='telnet' (bastion)", srow["kind"] == "telnet")
        check("host_id = host-ul telnet-jump (nu agentul)", srow["host_id"] == TGT_ID)
        check("target_host/port salvate pt. reconnect", srow["target_host"] == "10.0.0.9" and srow["target_port"] == port)
        await asyncio.sleep(0.3)          # lasă pump-ul să livreze banner-ul
        check("banner-ul device-ului a ajuns la hub", b"login:" in bytes(seen), bytes(seen)[:40])
        src = core.session_sources.get(sid)
        check("sursa e un ForwardTelnetSource", isinstance(src, core.ForwardTelnetSource))
        if src:
            await src.close(sid)
    except Exception as e:       # noqa: BLE001
        check("happy path", False, repr(e))

    # ── agent offline → AgentGone (nimic 'live' fantomă) ──
    core.sources.pop(AGENT_ID, None)
    raised = False
    try:
        await core.create_telnet_jump_session(trow, "sw2", 24, 80)
    except core.AgentGone:
        raised = True
    except Exception as e:       # noqa: BLE001
        check("offline tip eroare", False, repr(e))
    check("agent offline → AgentGone (refuz)", raised)

    core.SessionHub.on_output = orig_on_output
    # teardown curat: închide orice sursă rămasă şi lasă finalizatorii pump-ului (on_exit →
    # checkpoint) să ruleze CÂT timp DB-ul e încă deschis, altfel apare un „Task exception"
    # inofensiv (checkpoint pe DB închis). Nu e un bug de produs — doar ordine de oprire în test.
    for s in list(core.session_sources.values()):
        try:
            await s.close()
        except Exception:       # noqa: BLE001
            pass
    await asyncio.sleep(0.2)
    server.close()
    await db.close()
    print(f"\n{ok}/{total} checks passed")
    if ok != total:
        raise SystemExit(1)


asyncio.run(main())
