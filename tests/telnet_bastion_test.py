"""Transport telnet-via-agent (Faza 2): ForwardTelnetSource peste un tunel fals de
agent, contra unui server telnet raw in-process. Verifică negocierea IAC prin shim,
round-trip de I/O, strip-ul IAC din transcript, NAWS, EOF/teardown, plafonul separat.

Nu are nevoie de docker/agent real: `FakeAgent.open_forward` întoarce un stream peste
un socket real către serverul telnet din proces — exact interfața ForwardStream
(read/write/close) pe care o consumă ForwardTelnetSource. (Calea cu agent REAL prin
FRAME_FWD e acoperită de scripts/fwd-test.sh în CI.)"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import core, db  # noqa: E402
from app.telnet import (IAC, DO, WILL, SB, SE,  # noqa: E402
                        OPT_ECHO as ECHO, OPT_SGA as SGA,
                        OPT_TTYPE as TTYPE, OPT_NAWS as NAWS)
from app import telnet as T  # noqa: E402

PORT = 2401
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


# ---------------------------------------------------------------- server telnet raw
srv_state = {"naws": None, "ttype": None, "got": bytearray()}


async def telnet_server(reader, writer):
    # negociere tipică de server + prompt
    writer.write(bytes((IAC, WILL, ECHO, IAC, WILL, SGA, IAC, DO, NAWS, IAC, DO, TTYPE)))
    await writer.drain()
    parse = T.TelnetShim()          # ca să scoatem IAC din ce trimite clientul
    sent_ttype_send = False
    sent_pw = False                 # am cerut deja parola pe această conexiune?
    in_pw = False                   # în fereastra de parolă → echo OPRIT (ca telnetd real)
    # bannerul include OSC 133 (marcaj de prompt) + OSC 52 (clipboard) — un device ostil
    # le poate falsifica; filtrul F5 trebuie să le scoată, păstrând textul vizibil.
    writer.write(b"\x1b]133;A\x07login: \x1b]52;c;ZXZpbA==\x07")
    await writer.drain()
    while True:
        raw = await reader.read(4096)
        if not raw:
            break
        # capturează subnegocierile clientului (dovada că negocierea a mers)
        i = raw.find(bytes((IAC, SB, NAWS)))
        if i >= 0:
            srv_state["naws"] = raw[i + 3:i + 7]
        j = raw.find(bytes((IAC, SB, TTYPE, 0)))
        if j >= 0:
            end = raw.find(bytes((IAC, SE)), j)
            srv_state["ttype"] = raw[j + 4:end]
        # după ce clientul acceptă TTYPE (WILL TTYPE), cere-i tipul
        if not sent_ttype_send and bytes((IAC, WILL, TTYPE)) in raw:
            sent_ttype_send = True
            writer.write(bytes((IAC, SB, TTYPE, 1, IAC, SE)))   # 1 = SEND
            await writer.drain()
        clean = parse.receive(raw)
        if clean:
            srv_state["got"] += clean
            if not in_pw:
                writer.write(clean)         # echo (ca un shell); OPRIT pe parolă
                await writer.drain()
            has_nl = b"\n" in clean or b"\r" in clean
            if has_nl and not sent_pw:       # primul rând (user) → cerem parola, echo off
                sent_pw = True
                in_pw = True
                writer.write(b"\r\nPassword: ")
                await writer.drain()
            elif has_nl and in_pw:           # parola trimisă → repornim echo + prompt shell
                in_pw = False
                writer.write(b"\r\nswitch> ")
                await writer.drain()


class FakeForwardStream:
    """Interfața ForwardStream (read/write/close) peste un socket asyncio real."""
    def __init__(self, reader, writer):
        self._r = reader
        self._w = writer
        self.tunnel_lost = False      # ca ForwardStream real (cădere de agent vs. țintă)

    async def read(self):
        data = await self._r.read(4096)
        return data if data else None

    async def write(self, data):
        self._w.write(data)
        await self._w.drain()

    async def close(self):
        try:
            self._w.close()
        except Exception:
            pass


class FakeAgent(core.AgentConnection):
    """AgentConnection minimal: doar open_forward (către serverul telnet local)."""
    def __init__(self, host_id):
        self.host_id = host_id
        self.epoch = "fake-epoch"

    async def open_forward(self, host, port):
        reader, writer = await asyncio.open_connection(host, port)
        return FakeForwardStream(reader, writer)


class FakeHub:
    def __init__(self):
        self.out = bytearray()
        self.exited = None

    async def on_output(self, data):
        self.out += data

    async def on_exit(self, status, sig):
        self.exited = (status, sig)


async def main():
    await db.connect()
    server = await asyncio.start_server(telnet_server, "127.0.0.1", PORT)

    # ---- test 1: sursă directă (fără db) — negociere, echo, strip IAC, NAWS ----
    sid = "a" * 32
    hub = FakeHub()
    core.hubs[sid] = hub
    src = core.ForwardTelnetSource(sid, 1, FakeAgent(1), "127.0.0.1", PORT, 24, 80)
    resp = await src.create(sid, 24, 80, "xterm-256color")
    check("create ok (forward deschis)", resp.get("ok") is True, str(resp))
    await asyncio.sleep(0.3)          # schimb de negociere + prompt

    check("promptul serverului ajunge la hub", b"login:" in bytes(hub.out), bytes(hub.out))
    check("IAC scos din output (fără 0xFF în transcript)", 0xff not in hub.out)
    # F5: OSC 133 / OSC 52 din banner-ul device-ului NU trebuie să ajungă la browser
    check("OSC 133 filtrat din output device", b"\x1b]133" not in bytes(hub.out), bytes(hub.out))
    check("OSC 52 filtrat din output device", b"]52;" not in bytes(hub.out), bytes(hub.out))
    check("clientul a negociat NAWS (80x24)", srv_state["naws"] == bytes((0, 80, 0, 24)),
          srv_state["naws"].hex() if srv_state["naws"] else "None")
    check("clientul a trimis TTYPE xterm-256color", srv_state["ttype"] == b"xterm-256color",
          srv_state["ttype"])

    # round-trip de input (server face echo)
    hub.out.clear()
    await src.send_data(sid, b"root\r")
    await asyncio.sleep(0.2)
    check("input ajunge la server + echo înapoi", b"root" in bytes(hub.out), bytes(hub.out))
    check("serverul a primit input curat", b"root" in bytes(srv_state["got"]))

    # resize → NAWS nou
    srv_state["naws"] = None
    await src.resize(sid, 40, 120)
    await asyncio.sleep(0.15)
    check("resize trimite NAWS nou (120x40)", srv_state["naws"] == bytes((0, 120, 0, 40)),
          srv_state["naws"].hex() if srv_state["naws"] else "None")

    # EOF: închidem sursa → pump se termină → hub.on_exit
    await src.close(sid)
    await asyncio.sleep(0.15)
    check("close → session_sources curățat", sid not in core.session_sources)

    # ---- test 2: create_telnet_session (wiring db + hub real) ----
    core.sources[1] = FakeAgent(1)
    fwd = {"host_id": 1, "target_host": "127.0.0.1", "target_port": PORT, "scheme": "telnet"}
    res = await core.create_telnet_session(fwd, "Switch core", 24, 80)
    tsid = res["id"]
    check("create_telnet_session → sesiune live", bool(tsid))
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", tsid)
    check("sesiunea are kind=telnet în db", row["kind"] == "telnet", row["kind"])
    check("sursă per-sesiune înregistrată", tsid in core.session_sources)
    await asyncio.sleep(0.25)
    # read_tail citește doar octeții flush-uiți pe disc (fereastră de checkpoint ~2s);
    # forțăm checkpoint-ul ca să verificăm determinist ce s-a scris în transcript
    await core.hubs[tsid]._checkpoint(force=True)
    tail = await asyncio.to_thread(core.read_tail, tsid)
    check("transcriptul conține promptul, fără IAC", b"login:" in tail and 0xff not in tail,
          repr(bytes(tail[:60])))
    check("transcriptul fără OSC 133/52 (F5)", b"\x1b]133" not in tail and b"]52;" not in tail,
          repr(bytes(tail[:80])))

    # ---- test 2b: F3 — redactarea parolei în transcript ----
    # Login-ul telnet e in-band: parola tastată la „Password:" NU trebuie să ajungă în
    # .cast (evenimente „i"). Pump-ul intră în redactare la promptul de parolă; hub-ul
    # sare peste scrierea input-ului; Enter-ul închide fereastra. Input-ul de dinainte
    # (user) și de după (comandă) se înregistrează normal.
    class _Client:
        def __init__(self):
            self.last_interaction = 0.0
    cli = _Client()
    hub2 = core.hubs[tsid]
    src2 = core.session_sources[tsid]
    await hub2.handle_input(cli, b"admin\r")   # username — NU secret, se înregistrează
    await asyncio.sleep(0.3)                    # serverul răspunde „Password:" (echo off)
    check("redact_input activ după promptul de parolă", src2.redact_input is True)
    await hub2.handle_input(cli, b"s3cr3tPW\r")  # PAROLA — nu trebuie să apară nicăieri
    await asyncio.sleep(0.25)
    check("redact_input dezactivat după Enter (submit)", src2.redact_input is False)
    await hub2.handle_input(cli, b"show version\r")   # comandă normală — se înregistrează
    await asyncio.sleep(0.2)
    hub2.cast_f.flush()
    cast_path = core.config.TRANSCRIPT_DIR / (tsid + ".cast")
    cast = cast_path.read_bytes()
    check("parola NU apare în .cast", b"s3cr3tPW" not in cast, repr(cast[-200:]))
    check("username-ul (input pre-parolă) apare în .cast", b"admin" in cast)
    check("comanda de după parolă apare în .cast", b"show version" in cast)

    # ---- test 2c: reconectare după căderea agentului (lost → live) ----
    src2 = core.session_sources[tsid]
    src2._fs.tunnel_lost = True          # simulăm cădere de AGENT (nu de țintă)
    src2._fs._w.close()                  # → pump vede EOF → mark_lost
    await asyncio.sleep(0.35)
    lrow = await db.fetchone("SELECT state FROM sessions WHERE id=?", tsid)
    check("cădere de tunel → sesiune 'lost' (nu 'exited')", lrow["state"] == "lost", lrow["state"])
    check("sursa 'lost' curățată din registru", tsid not in core.session_sources)
    # reconectăm: telnet nou spre aceeași țintă, același sid/tab
    rr = await core.reconnect_telnet_session(tsid)
    check("reconnect → același sid", rr["id"] == tsid)
    await asyncio.sleep(0.25)
    rrow = await db.fetchone("SELECT state FROM sessions WHERE id=?", tsid)
    check("reconnect → sesiune 'live' din nou", rrow["state"] == "live", rrow["state"])
    check("sursă nouă înregistrată după reconnect", tsid in core.session_sources)
    await core.hubs[tsid]._checkpoint(force=True)
    tail2 = await asyncio.to_thread(core.read_tail, tsid)
    check("transcript are marcaj de reconectare", b"reconectat la" in tail2, repr(bytes(tail2[-120:])))

    # reconnect pe sesiune inexistentă / non-telnet → KeyError
    missing = False
    try:
        await core.reconnect_telnet_session("f" * 32)
    except KeyError:
        missing = True
    check("reconnect pe sid inexistent → KeyError", missing)

    # ---- test 3: plafon separat ----
    core.MAX_TELNET_SESSIONS = 2      # coborâm pentru test
    # avem deja 1 activă (tsid); mai deschidem 1 → ok, a 3-a → limită
    r2 = await core.create_telnet_session(fwd, "s2", 24, 80)
    hit_limit = False
    try:
        await core.create_telnet_session(fwd, "s3", 24, 80)
    except core.SessionLimitReached:
        hit_limit = True
    check("plafon telnet separat aplicat", hit_limit)

    # ---- test 4: host offline → AgentGone ----
    core.sources.pop(1, None)
    offline = False
    try:
        await core.create_telnet_session(fwd, "s4", 24, 80)
    except core.AgentGone:
        offline = True
    check("host offline → AgentGone", offline)

    # cleanup mărginit (task-uri pump / thread aiosqlite reziduale nu trebuie să
    # atârne procesul de test după ce assert-urile au trecut)
    async def _cleanup():
        for s in list(core.session_sources.values()):
            await s.close(None)
        await asyncio.sleep(0.2)     # lasă pump-urile anulate să-și termine on_exit (db încă deschis)
        server.close()
    try:
        await asyncio.wait_for(_cleanup(), 5)
    except Exception:
        pass
    # db rămâne deschis: os._exit oprește procesul (și thread-ul aiosqlite) fără să
    # concureze cu checkpoint-urile de teardown
    print(f"\n{ok}/{total} PASS", flush=True)
    os._exit(0 if ok == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
