"""Reconciliere de liveness a sesiunilor (gateway): starea 'live' din DB trebuie să
corespundă realității backendului. Acoperă:
  - reconcile_telnet_on_start: telnet 'live' → 'lost' la pornirea gateway-ului
  - sweep_stale_sessions: telnet fără sursă → lost; shell pe host offline → lost;
    sesiuni servite (host online / cu sursă) → neatinse
  - reconcile(): restaurare 'lost' → 'live' când agentul re-adoptă sesiunea
Fără proces gateway/agent real."""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import core, db  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


async def state(sid):
    r = await db.fetchone("SELECT state FROM sessions WHERE id=?", sid)
    return r["state"] if r else None


async def mk_host(hid, last_hb, conn_type="agent"):
    await db.execute(
        "INSERT INTO hosts(id,name,token_hash,token_encrypted,last_heartbeat,created,connection_type)"
        " VALUES(?,?,?,?,?,?,?)",
        hid, "h%d" % hid, "tok%d" % hid, "enc%d" % hid, last_hb, 0.0, conn_type)


async def mk_session(sid, hid, kind="shell", stt="live"):
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,kind) VALUES(?,?,?,?,?,?)",
        sid, hid, "t", stt, 0.0, kind)


class FakeAgent(core.AgentConnection):
    """AgentConnection minimal — doar identitatea; fără ws real. attach/resize sunt
    mock-uite (altfel ensure_attached ar aștepta un răspuns pe ws-ul inexistent)."""
    def __init__(self, host_id):
        self.host_id = host_id
        self.epoch = "ep-%d" % host_id
        self.backend = "tmux"
        self.agent_version = 18
        self.host_name = "h%d" % host_id
        self.metrics = None
        self._tasks = set()
        self._reconcile_latest = None
        self._reconcile_saw_hello = False
        self._reconcile_running = False

    async def attach(self, sid, from_offset):
        return {"ok": True, "replay_start": from_offset or 0}

    async def resize(self, sid, rows, cols):
        pass


async def main():
    await db.connect()
    now = time.time()

    # ---- test 1: reconcile_telnet_on_start ----
    await mk_host(1, now)                                   # host de AGENT
    await mk_session("a" * 32, 1, kind="telnet", stt="live")
    await mk_session("b" * 32, 1, kind="telnet", stt="creating")
    await mk_session("c" * 32, 1, kind="shell", stt="live")
    # hosturi DIRECTE (sursă doar în memoria gateway-ului → nu supraviețuiesc restartului):
    # sesiunile lor au kind='shell', deci DOAR connection_type le prinde la startup
    await mk_host(6, None, conn_type="ssh")
    await mk_host(7, None, conn_type="telnet")
    await mk_session("07" * 16, 6, kind="shell", stt="live")     # SSH direct → lost
    await mk_session("08" * 16, 7, kind="shell", stt="creating")  # telnet direct → lost
    await core.reconcile_telnet_on_start()
    check("telnet 'live' → 'lost' la startup", await state("a" * 32) == "lost", await state("a" * 32))
    check("telnet 'creating' → 'lost' la startup", await state("b" * 32) == "lost", await state("b" * 32))
    check("shell pe host AGENT neatins la startup", await state("c" * 32) == "live", await state("c" * 32))
    check("shell pe SSH DIRECT → 'lost' la startup", await state("07" * 16) == "lost", await state("07" * 16))
    check("shell pe TELNET DIRECT → 'lost' la startup", await state("08" * 16) == "lost", await state("08" * 16))

    # ---- test 2: sweep_stale_sessions ----
    # host 2 online (AgentConnection viu, heartbeat proaspăt), host 3 offline (heartbeat vechi)
    await mk_host(2, now)
    await mk_host(3, now - 10 * core.config.HEARTBEAT_STALE)   # mut demult → offline
    core.sources[2] = FakeAgent(2)
    core.sources.pop(3, None)
    await mk_session("d" * 32, 2, kind="shell", stt="live")    # host online → rămâne
    await mk_session("e" * 32, 3, kind="shell", stt="live")    # host offline → lost
    await mk_session("f" * 32, 2, kind="telnet", stt="live")   # telnet cu sursă → rămâne
    await mk_session("01" * 16, 2, kind="telnet", stt="live")   # telnet fără sursă → lost
    core.session_sources["f" * 32] = object()                  # sursă vie (dummy non-None)
    core.session_sources.pop("01" * 16, None)
    await core.sweep_stale_sessions()
    check("shell pe host ONLINE rămâne 'live'", await state("d" * 32) == "live", await state("d" * 32))
    check("shell pe host OFFLINE → 'lost'", await state("e" * 32) == "lost", await state("e" * 32))
    check("telnet CU sursă rămâne 'live'", await state("f" * 32) == "live", await state("f" * 32))
    check("telnet FĂRĂ sursă → 'lost'", await state("01" * 16) == "lost", await state("01" * 16))

    # host online dar heartbeat vechi în DB: sursa vie primează (agent tocmai reconectat)
    await db.execute("UPDATE hosts SET last_heartbeat=? WHERE id=?", now - 999, 2)
    await mk_session("02" * 16, 2, kind="shell", stt="live")
    await core.sweep_stale_sessions()
    check("host cu AgentConnection viu NU e reapat (chiar cu hb vechi)",
          await state("02" * 16) == "live", await state("02" * 16))

    # ---- test 2b: REGRESIA — sesiuni DIRECTE SSH/telnet vii NU se reapează ----
    # host SSH direct: sursa e SshSource (NU AgentConnection) și n-are niciodată heartbeat.
    class FakeSshSource:                       # sursă vie, non-agent
        epoch = "ssh-ep"
    await mk_host(4, None, conn_type="ssh")    # last_heartbeat NULL, ca la SSH direct
    core.sources[4] = FakeSshSource()
    await mk_session("05" * 16, 4, kind="shell", stt="live")
    await core.sweep_stale_sessions()
    check("sesiune DIRECT-SSH vie (sursă non-agent) NU e reapată",
          await state("05" * 16) == "live", await state("05" * 16))
    # host SSH direct FĂRĂ sursă (gateway repornit) + fără heartbeat → NU se reapează
    # (se re-dial-uiește la reconectarea browserului; nu heartbeat-based)
    await mk_host(5, None, conn_type="ssh")
    core.sources.pop(5, None)
    await mk_session("06" * 16, 5, kind="shell", stt="live")
    await core.sweep_stale_sessions()
    check("sesiune SSH direct fără sursă NU e reapată pe heartbeat (se re-dial-uiește)",
          await state("06" * 16) == "live", await state("06" * 16))

    # ---- test 3: reconcile() restaurează 'lost' → 'live' la re-adopție ----
    await mk_session("03" * 16, 2, kind="shell", stt="lost")    # pierdută, dar tmux a supraviețuit
    await mk_session("04" * 16, 2, kind="shell", stt="live")    # vie, dar agentul n-o mai raportează
    msg = {"epoch": "ep-2", "backend": "tmux", "agent_version": 18,
           "sessions": [{"sid": "03" * 16, "alive": True, "rows": 24, "cols": 80, "created": 0}]}
    await asyncio.wait_for(core.reconcile(core.sources[2], msg), 5)
    check("sesiune 'lost' re-adoptată (raportată vie) → 'live'",
          await state("03" * 16) == "live", await state("03" * 16))
    check("sesiune 'live' neraportată de agent → 'lost'",
          await state("04" * 16) == "lost", await state("04" * 16))

    # ---- test 4: schedule_reconcile serializează + coalescează ----
    # reconcile() e declanșat la fiecare hello/heartbeat; două concurente ar face
    # read-modify-write pe aceleași rânduri. Verificăm: cel mult una rulează, mesajele
    # stivuite se coalescează în ULTIMUL, iar un 'hello' nu se pierde în coalescing.
    calls = []
    real_reconcile = core.reconcile

    async def fake_reconcile(conn, m):
        calls.append(m)
        await asyncio.sleep(0.03)      # lasă alte mesaje să se stivuiască în timpul rulării

    core.reconcile = fake_reconcile
    try:
        agent = core.sources[2]
        agent._reconcile_latest = None
        agent._reconcile_saw_hello = False
        agent._reconcile_running = False
        for i in range(5):
            agent.schedule_reconcile({"event": "heartbeat", "n": i})
        await asyncio.sleep(0.2)
        check("coalescing: 5 mesaje → cel mult 2 rulări reale", len(calls) <= 2, "runs=%d" % len(calls))
        check("coalescing: se procesează ULTIMA stare (n=4)", calls and calls[-1]["n"] == 4,
              "last=%r" % (calls[-1] if calls else None))

        calls.clear()
        agent.schedule_reconcile({"event": "hello", "n": 10})
        agent.schedule_reconcile({"event": "heartbeat", "n": 11})
        await asyncio.sleep(0.2)
        check("coalescing: 'hello' nu se pierde când e urmat de heartbeat",
              any(m.get("event") == "hello" for m in calls), "calls=%r" % calls)
    finally:
        core.reconcile = real_reconcile

    # ---- test 5: dial_ssh serializat per-host (anti TOCTOU / conexiuni duble) ----
    # două cereri concurente către un host SSH fără sursă trebuie să deschidă O SINGURĂ
    # conexiune (a doua re-verifică sub lock și primește sursa creată de prima).
    connect_calls = []

    class _FakeKey:
        def export_public_key(self):
            return b"ssh-ed25519 AAAAtest"

    class _FakeConn:
        def get_server_host_key(self):
            return _FakeKey()

    async def _fake_connect(**kw):
        connect_calls.append(1)
        await asyncio.sleep(0.05)          # ține lock-ul → a doua cerere așteaptă
        return _FakeConn()

    class _FakeSsh:
        def __init__(self, host_id, conn):
            self.host_id = host_id
            self.epoch = "ssh-ep"

    orig_connect = core.asyncssh.connect
    orig_ssh = core.SshSource
    core.asyncssh.connect = _fake_connect
    core.SshSource = _FakeSsh
    try:
        await mk_host(9, None, conn_type="ssh")
        core.sources.pop(9, None)
        core._dial_locks.pop(9, None)
        hrow = {"id": 9, "hostname": "h", "ssh_port": 22, "known_hosts": None,
                "ssh_username": "u", "auth_method": "password"}
        res = await asyncio.gather(core.dial_ssh(hrow, {"password": "x"}),
                                   core.dial_ssh(hrow, {"password": "x"}))
        check("dial_ssh: 2 cereri concurente → O SINGURĂ conectare", len(connect_calls) == 1,
              "conectări=%d" % len(connect_calls))
        check("dial_ssh: ambele primesc aceeași sursă", res[0] is res[1])
    finally:
        core.asyncssh.connect = orig_connect
        core.SshSource = orig_ssh

    async def _cleanup():
        for h in list(core.hubs.values()):
            try:
                h.teardown()
            except Exception:
                pass
        await asyncio.sleep(0.1)
    try:
        await asyncio.wait_for(_cleanup(), 3)
    except Exception:
        pass
    print(f"\n{ok}/{total} PASS", flush=True)
    os._exit(0 if ok == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
