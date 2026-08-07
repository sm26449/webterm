"""Valul 3 — reziliența agentului (ptyd.py), verificări stdlib-only, fără gateway/pty real.

Acoperă: sd_notify systemd (WATCHDOG=1 pe $NOTIFY_SOCKET + no-op fără socket), parsarea
WATCHDOG_USEC → interval de ping, TCP keepalive aplicat pe socket, și plafoanele de backlog
(pending_input aruncat, wbuf de forward → tunel închis) care apără de OOM la producător rapid."""
import os
import socket
import hashlib
import sys
import tempfile
import time

# home izolat (nu scriem în ~/.webterm real) — hard set, nu setdefault: pe CI HOME e
# deja setat, iar setdefault l-ar păstra pe cel real
os.environ["HOME"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

import ptyd  # noqa: E402

# Pe o mașină cu tmux instalat (ex. runner-ul CI), Agent.__init__ scrie ~/.webterm/tmux.conf.
# _instance_id() creează WEBTERM_DIR la import DOAR când lipsește /etc/machine-id — pe runner
# machine-id există, deci dir-ul nu se creează → open() ar pica. Îl creăm noi, explicit.
os.makedirs(ptyd.WEBTERM_DIR, exist_ok=True)

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def test_sd_notify():
    # socket real AF_UNIX DGRAM ca „systemd"
    d = tempfile.mkdtemp()
    path = os.path.join(d, "notify.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(path)
    srv.settimeout(2)
    old = os.environ.get("NOTIFY_SOCKET")
    os.environ["NOTIFY_SOCKET"] = path
    try:
        ptyd._sd_notify("WATCHDOG=1")
        got = srv.recv(64)
        check("sd_notify trimite WATCHDOG=1", got == b"WATCHDOG=1", repr(got))
        ptyd._sd_notify("READY=1")
        check("sd_notify trimite READY=1", srv.recv(64) == b"READY=1")
    finally:
        if old is None:
            os.environ.pop("NOTIFY_SOCKET", None)
        else:
            os.environ["NOTIFY_SOCKET"] = old
        srv.close()

    # fără NOTIFY_SOCKET → no-op silențios (nu aruncă)
    os.environ.pop("NOTIFY_SOCKET", None)
    try:
        ptyd._sd_notify("WATCHDOG=1")
        check("sd_notify fără socket = no-op", True)
    except Exception as e:  # noqa: BLE001
        check("sd_notify fără socket = no-op", False, str(e))


def test_watchdog_interval():
    old = os.environ.get("WATCHDOG_USEC")
    os.environ.pop("NOTIFY_SOCKET", None)
    # WatchdogSec=45 → systemd exportă WATCHDOG_USEC=45000000 → interval de ping ~22.5s
    os.environ["WATCHDOG_USEC"] = "45000000"
    try:
        a = ptyd.Agent({"url": "ws://x/y", "token": "t"})
        check("WATCHDOG_USEC → interval la jumătate", abs(a._wd_interval - 22.5) < 0.01,
              "interval=%r" % a._wd_interval)
    finally:
        if old is None:
            os.environ.pop("WATCHDOG_USEC", None)
        else:
            os.environ["WATCHDOG_USEC"] = old
    # fără WATCHDOG_USEC → 0 (fără watchdog systemd)
    os.environ.pop("WATCHDOG_USEC", None)
    a2 = ptyd.Agent({"url": "ws://x/y", "token": "t"})
    check("fără WATCHDOG_USEC → interval 0", a2._wd_interval == 0.0)


def test_keepalive():
    a, b = socket.socketpair()
    try:
        ptyd._set_keepalive(a)
        on = a.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
        check("_set_keepalive activează SO_KEEPALIVE", on == 1, "SO_KEEPALIVE=%r" % on)
    finally:
        a.close()
        b.close()


class _FakeSession:
    def __init__(self, master):
        self.sid = "s" * 32
        self.alive = True
        self.master = master
        self.pending_input = b""


def test_pending_input_cap():
    os.environ.pop("WATCHDOG_USEC", None)
    a = ptyd.Agent({"url": "ws://x/y", "token": "t"})
    master, slave = os.openpty()
    os.set_blocking(master, False)
    s = _FakeSession(master)
    a.sessions[s.sid] = s
    a.sel.register(master, __import__("selectors").EVENT_READ, ("pty", s.sid))
    # umplem slave-ul ca pty-ul să NU mai accepte scriere (backlog forțat), apoi
    # simulăm un backlog deja aproape de plafon și trimitem peste
    s.pending_input = b"x" * (ptyd.PENDING_INPUT_MAX - 10)
    before = len(s.pending_input)
    a.write_input(s.sid, b"y" * 1000)   # ar depăși plafonul → aruncat
    check("input peste plafon e aruncat (nu crește)", len(s.pending_input) <= before + 0,
          "len=%d before=%d" % (len(s.pending_input), before))
    check("backlog rămâne mărginit", len(s.pending_input) <= ptyd.PENDING_INPUT_MAX)
    os.close(master)
    os.close(slave)


def test_fwd_wbuf_cap():
    os.environ.pop("WATCHDOG_USEC", None)
    a = ptyd.Agent({"url": "ws://x/y", "token": "t"})
    s1, s2 = socket.socketpair()
    s1.setblocking(False)
    stream = "f" * 32
    fwd = ptyd.Forward(stream, s1)
    fwd.connecting = False
    a.forwards[stream] = fwd
    a.sel.register(s1, __import__("selectors").EVENT_READ, ("fwd", stream))
    # umplem wbuf lângă plafon + trimitem peste → teardown (tunel scos)
    fwd.wbuf = b"z" * (ptyd.FWD_WBUF_MAX - 10)
    a.fwd_write(stream, b"z" * 1000)
    check("forward peste plafon → tunel închis", stream not in a.forwards)
    try:
        s2.close()
    except OSError:
        pass


def test_outbox_overflow_signals():
    # #7: la overflow de outbox, send_frame NU trebuie să facă _disconnect() direct (ar putea
    # rula pe un thread worker → mută selector-ul → crash); doar semnalizează loop-ul.
    os.environ.pop("WATCHDOG_USEC", None)
    a = ptyd.Agent({"url": "ws://x/y", "token": "t"})
    a.connected = True
    a._disconnect_requested = False
    a.send_frame(b"x" * (ptyd.OUTBOX_LIMIT + 1))
    check("overflow → _disconnect_requested setat", a._disconnect_requested is True)
    check("overflow NU deconectează în send_frame (o face loop-ul)", a.connected is True)


def test_cert_pin():
    # layer anti-DNS-hijack: verificarea amprentei certificatului gateway-ului
    der = b"fake-gateway-cert-DER-bytes"
    pin = hashlib.sha256(der).hexdigest()
    ws = ptyd.WSClient("wss://x/y", "tok", cert_pin=pin.upper())
    check("cert_pin normalizat lowercase", ws.cert_pin == pin)
    ws._check_cert_pin(der)                          # pin corect → nu aruncă
    check("pin corect acceptat + peer_pin expus", ws.peer_pin == pin)
    ws_bad = ptyd.WSClient("wss://x/y", "tok", cert_pin="deadbeef")
    try:
        ws_bad._check_cert_pin(der)
        check("pin greșit → respins (WSError)", False)
    except ptyd.WSError:
        check("pin greșit → respins (WSError)", True)
    ws_none = ptyd.WSClient("wss://x/y", "tok")      # fără pin → no-op (dar observă peer_pin)
    ws_none._check_cert_pin(der)
    check("fără pin → no-op (TOFU observă peer_pin)", ws_none.cert_pin is None and ws_none.peer_pin == pin)


def test_content_version_anchored():
    # #20: parse ancorat — nu prinde AGENT_VERSION_OLD/_MIN etc.
    check("_content_version ia AGENT_VERSION exact, nu _OLD",
          ptyd._content_version(b"AGENT_VERSION_OLD = 3\nAGENT_VERSION = 22\n") == 22)
    check("_content_version simplu", ptyd._content_version(b"AGENT_VERSION = 22") == 22)
    check("_content_version lipsă → None", ptyd._content_version(b"x = 1\ny = 2\n") is None)


def test_handshake_deadline():
    # #8: un gateway care ACCEPTĂ dar nu trimite răspunsul de handshake (drip-feed extrem)
    # nu trebuie să blocheze la nesfârșit — connect() are un deadline TOTAL.
    import threading
    import time as _t
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    def serve():
        try:
            c, _ = srv.accept()
            _t.sleep(5)          # ține conexiunea deschisă fără să trimită nimic
            c.close()
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()

    ws = ptyd.WSClient("ws://127.0.0.1:%d/agent/ws" % port, "tok")
    t0 = _t.monotonic()
    try:
        ws.connect(timeout=1)
        check("handshake fără răspuns → timeout", False, "n-a expirat")
    except ptyd.WSError as e:
        dt = _t.monotonic() - t0
        check("handshake fără răspuns → WSError timeout", "timeout" in str(e).lower(), str(e))
        check("handshake respectă deadline-ul (~1s, nu blochează)", dt < 3.0, "dt=%.1fs" % dt)
    srv.close()


def test_async_connect_statemachine():
    # #8: conectarea e non-blocantă (pe thread worker); loop-ul procesează rezultatul din inbox
    os.environ.pop("WATCHDOG_USEC", None)
    a = ptyd.Agent({"url": "ws://x/y", "token": "t"})
    a._connecting = True
    b0 = a.backoff
    a._on_connect_failed("boom")
    check("connect eșuat → _connecting False", a._connecting is False)
    check("connect eșuat → backoff avansează", a.backoff > b0 or a.backoff == ptyd.BACKOFF_MAX)
    check("connect eșuat → next_connect în viitor", a.next_connect > time.time())

    # rezultat 'connected' învechit (la oprire) → nu se cablează, ws-ul e închis
    a.stop_requested = True

    class _FakeWS:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True
    fw = _FakeWS()
    a._on_connected(fw)
    check("__connected__ la stop → ignorat + ws închis", a.connected is False and fw.closed)

    # _drain_inbox dispecerizează markerii de conectare
    a.stop_requested = False
    a._connecting = True
    a.inbox.put(("__connect_failed__", "x"))
    a._drain_inbox()
    check("_drain_inbox tratează __connect_failed__", a._connecting is False)

    # ── orice excepţie din thread-ul de conectare trebuie raportată loop-ului ──────────────
    # Se prindeau doar (WSError, OSError, ssl.SSLError). Orice altceva scăpa din thread fără să
    # pună nimic în inbox → `_connecting` rămânea True pe veci, iar gardul din buclă e chiar
    # `_connecting`: agentul nu mai încerca NICIODATĂ să se reconecteze, cu watchdog-urile verzi
    # (`_tick` atinge în continuare fişierul de viaţă). Pe Python 3.6, `ssl.CertificateError` e
    # subclasă de ValueError — deci o schimbare de certificat era de ajuns ca să se întâmple.
    for exc in (ValueError("cert schimbat"), RuntimeError("bug"), KeyError("k")):
        a._connecting = True
        while not a.inbox.empty():
            a.inbox.get()

        class _Boom:
            def connect(self_inner):
                raise exc
        a._connect_worker(_Boom())
        kind, payload = a.inbox.get_nowait()
        check("excepţie %s → raportată loop-ului" % type(exc).__name__,
              kind == "__connect_failed__", "%s %r" % (kind, payload))
        check("mesajul spune ce fel de eroare a fost (%s)" % type(exc).__name__,
              type(exc).__name__ in str(payload), str(payload))
        a.inbox.put((kind, payload))    # îl consumasem ca să-l inspectez — îl dau înapoi buclei
        a._drain_inbox()
        check("agentul poate reîncerca după %s" % type(exc).__name__, a._connecting is False)

    # plasa din buclă: dacă thread-ul nu raportează NICIODATĂ (a murit înainte de `finally`),
    # `_connecting` nu are voie să blocheze agentul definitiv
    a._connecting = True
    a._connect_started = time.time() - ptyd.CONNECT_STUCK_SECS - 1
    now = time.time()
    stuck = a._connecting and now - a._connect_started > ptyd.CONNECT_STUCK_SECS
    check("conectare blocată peste prag → detectată de buclă", stuck)
    a._connecting = True
    a._connect_started = time.time()
    check("conectare recentă NU e considerată blocată",
          not (time.time() - a._connect_started > ptyd.CONNECT_STUCK_SECS))


def test_run_cap():
    # Cap pe rulările `run` concurente: peste MAX_RUNS → err run_limit (fără a porni procese),
    # iar slotul se eliberează după rulare (release garantat prin _run_command_guarded).
    a = ptyd.Agent({"url": "ws://x/y", "token": "t"})
    replies = []
    a.send_ctrl = lambda m: replies.append(m)
    for _ in range(ptyd.MAX_RUNS):
        assert a._run_sem.acquire(blocking=False)          # ocupăm toate sloturile
    a.handle_ctrl({"op": "run", "id": "r1", "cmd": "echo hi"})
    last = replies[-1] if replies else {}
    check("run peste cap → err run_limit (fără proces pornit)",
          last.get("code") == "run_limit" and last.get("ok") is False)
    a._run_sem.release()                                   # eliberăm un slot
    a.handle_ctrl({"op": "run", "id": "r2", "cmd": "true"})
    time.sleep(0.6)                                        # worker async trimite reply-ul
    r2 = [m for m in replies if m.get("id") == "r2"]
    check("run sub cap → acceptat (reply de la worker, nu run_limit)",
          bool(r2) and r2[-1].get("code") != "run_limit")
    check("slotul se eliberează după rulare (finally din _run_command_guarded)",
          a._run_sem.acquire(blocking=False))


def test_link_health():
    # Faza 3: hb_ack actualizează liveness + calculează RTT; get_log întoarce tail-ul logului.
    a = ptyd.Agent({"url": "ws://x/y", "token": "t"})
    a._last_hb_ack = 0.0
    a._hb_sent_at[3] = time.time() - 0.02
    a.handle_ctrl({"type": "hb_ack", "seq": 3})
    check("hb_ack actualizează _last_hb_ack (liveness link)", a._last_hb_ack > 0)
    check("hb_ack calculează RTT din dus-întors", a._last_rtt is not None and a._last_rtt >= 0)
    check("hb_ack curăţă seq-ul ack-uit din _hb_sent_at", 3 not in a._hb_sent_at)

    # în producţie agentul face dup2(stderr → LOG_PATH); în test scriem direct în fişier
    with open(ptyd.LOG_PATH, "a") as _f:
        _f.write("MARCAJ_TEST_LOG\n")
    replies = []
    a.send_ctrl = lambda m: replies.append(m)
    a.handle_ctrl({"op": "get_log", "id": "L1"})
    last = replies[-1] if replies else {}
    check("get_log întoarce tail-ul logului (conţine marcajul)",
          bool(last.get("ok")) and "MARCAJ_TEST_LOG" in last.get("log", ""))


class _FakeSel:
    """Selector de test: reţine ce s-a înregistrat, fără epoll real."""
    def __init__(self):
        self.registered = set()

    def register(self, fd, events, data):
        self.registered.add(fd)

    def unregister(self, fd):
        self.registered.discard(fd)

    def modify(self, fd, events, data):
        pass


def _fake_session(agent, sid="a" * 32):
    """Sesiune tmux fără pty real: master = capătul unui pipe (se poate close-ui),
    pid = un pid care nu e copilul nostru (waitpid dă ECHILD → tratat)."""
    s = object.__new__(ptyd.Session)
    s.sid, s.backend, s.alive, s.kill_requested = sid, "tmux", True, False
    s.respawns, s.last_respawn, s.client_started, s.retry_at = 0, 0.0, time.time(), 0.0
    s.pending_input, s.ring, s.ring_bytes, s.stream_offset = b"", [], 0, 0
    s.exited_at = s.exit_status = s.exit_signal = None
    s.rows, s.cols, s.attached = 24, 80, False
    r, w = os.pipe()
    os.close(w)
    s.master, s.pid = r, 999_999
    agent.sessions[sid] = s

    def spawn():                      # „reataşare reuşită": client nou, fd nou
        nr, nw = os.pipe()
        os.close(nw)
        s.master, s.pid = nr, 999_999
        s.client_started, s.retry_at = time.time(), 0.0
        spawn.calls += 1
    spawn.calls = 0
    s.spawn_client = spawn
    return s


def test_reattach_backoff():
    """Regresie pentru incidentul din 2026-08-05: agentul ≤31 renunţa după 3 reataşări
    eşuate în 2s şi OMORA sesiunea tmux — o ceartă tranzitorie de clienţi ştergea tot ce
    avea utilizatorul deschis. Acum: încercări rărite, sesiunea tmux rămâne intactă."""
    a = ptyd.Agent({"url": "ws://x/y", "token": "t"})
    a.sel = _FakeSel()
    a.connected = False
    killed = []
    state = {"v": "alive"}
    ptyd_state, ptyd_wedged = ptyd.tmux_session_state, ptyd.tmux_server_wedged
    ptyd.tmux_session_state = lambda sid: state["v"]
    ptyd.tmux_server_wedged = lambda: False
    a._reap_tmux_session = lambda sid: killed.append(sid)
    try:
        s = _fake_session(a)
        for i in range(ptyd.TMUX_REATTACH_FAST):
            s.client_started = time.time()        # clientul moare imediat după spawn
            a._session_exited(s)
        check("primele încercări reataşează imediat",
              s.spawn_client.calls == ptyd.TMUX_REATTACH_FAST and s.alive)

        s.client_started = time.time()
        a._session_exited(s)                  # a (FAST+1)-a moarte rapidă
        check("după încercările rapide NU mai spawnăm imediat",
              s.spawn_client.calls == ptyd.TMUX_REATTACH_FAST)
        check("sesiunea rămâne vie (procesele utilizatorului trăiesc în tmux)", s.alive)
        check("sesiunea tmux NU e omorâtă (regresia incidentului)", killed == [])
        check("s-a programat o reîncercare", s.retry_at > time.time())
        check("pid-ul e uitat cât nu avem client (anti-refolosire de pid)", s.pid is None)

        # cât suntem fără client: resize şi input nu trebuie să arunce, input-ul aşteaptă
        s.set_winsize(40, 100)
        a.write_input(s.sid, b"echo salut\n")
        check("resize fără client nu aruncă, reţine mărimea", (s.rows, s.cols) == (40, 100))
        check("input-ul tastat între clienţi rămâne în coadă", s.pending_input.endswith(b"salut\n"))

        a._retry_reattach(time.time())            # încă nu e momentul
        check("nu reîncercăm înainte de termen", s.spawn_client.calls == ptyd.TMUX_REATTACH_FAST)
        a._retry_reattach(s.retry_at + 0.01)
        check("la termen ne reataşăm", s.spawn_client.calls == ptyd.TMUX_REATTACH_FAST + 1)
        check("input-ul în aşteptare se scurge după reataşare", s.pending_input == b"")

        # backoff crescător, plafonat
        delays = []
        for _ in range(6):
            s.client_started = time.time()
            a._session_exited(s)
            delays.append(round(s.retry_at - time.time()))
            a._retry_reattach(s.retry_at + 0.01)
        check("backoff-ul creşte şi se plafonează",
              delays == sorted(delays) and delays[-1] == int(ptyd.TMUX_REATTACH_BACKOFF[-1]),
              str(delays))

        # un client care a trăit destul = reataşare reuşită → numărătoarea repornește
        s.client_started = time.time() - ptyd.TMUX_CLIENT_HEALTHY - 1
        a._session_exited(s)
        check("un client sănătos resetează numărătoarea (spawn imediat)", s.retry_at == 0.0)

        # „nu ştiu" (tmux nu răspunde: timeout, socket refuzat, server înţepenit) NU e „a murit"
        state["v"] = "unknown"
        calls_before_unknown = s.spawn_client.calls
        s.client_started = time.time()
        a._session_exited(s)
        check("tmux fără răspuns → sesiunea NU e declarată moartă", s.alive)
        check("tmux fără răspuns → se programează o reîncercare", s.retry_at > time.time())
        a._retry_reattach(s.retry_at + 0.01)
        check("reîncercarea pe „unknown\" nu declară moartea sesiunii", s.alive)
        check("pe „unknown\" nu spawnăm orbeşte o sesiune nouă",
              s.spawn_client.calls == calls_before_unknown)

        # abia un răspuns CLAR de la tmux („can't find session" / „no server") o îngroapă
        state["v"] = "gone"
        a._retry_reattach(s.retry_at + 0.01)
        check("sesiune tmux dispărută cu răspuns clar → declarată moartă", not s.alive)
        check("nici acum nu omorâm nimic în tmux", killed == [])
    finally:
        ptyd.tmux_session_state, ptyd.tmux_server_wedged = ptyd_state, ptyd_wedged


def main():
    test_reattach_backoff()
    test_run_cap()
    test_link_health()
    test_sd_notify()
    test_watchdog_interval()
    test_keepalive()
    test_pending_input_cap()
    test_fwd_wbuf_cap()
    test_outbox_overflow_signals()
    test_cert_pin()
    test_content_version_anchored()
    test_handshake_deadline()
    test_async_connect_statemachine()
    print(f"\n{ok}/{total} teste trecute")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
