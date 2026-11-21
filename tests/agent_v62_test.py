"""Agent 62: închiderea CONDIŢIONATĂ `kill_if_quiet` (INV-13, auditul Codex 3.7.1, reziduul #3).

De ce: închiderea automată a unei sesiuni inactive se decide pe gateway, dar între ultima lui verificare
şi momentul în care agentul execută kill-ul pot apărea output, input sau un om ataşat direct la tmux pe
host — lucruri pe care gateway-ul nu le vede. Gateway-ul spune cât timp n-a văzut nimic (`quiet_secs`);
agentul închide DOAR dacă nici el nu are dovezi de activitate în fereastra aceea.

Acoperă:
  · session_activity_reason cu tmux MOCKUIT: output / input recent, input în coadă, marcaje tmux
    (session_activity = input, window_activity = output), alt client tmux ataşat, orice eşec al
    interogării tmux = refuz (fail-closed), backend pty fără tmux;
  · op-ul prin handle_ctrl: sid necunoscut → no_session, quiet_secs invalid → bad_request, activ → active
    fără kill, liniştit → kill exact ca `kill`;
  · tmux REAL pe un socket IZOLAT (-L propriu + TMUX_TMPDIR temporar; doar kill-session, niciodată
    kill-server) — sărit dacă tmux lipseşte.
"""
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

os.environ["HOME"] = tempfile.mkdtemp(prefix="v62-home-")
os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp(prefix="v62-data-")
# tmux-ul de test NU are voie să atingă serverul de producţie: socket propriu, în alt director
os.environ["TMUX_TMPDIR"] = tempfile.mkdtemp(prefix="v62-tmux-")
os.environ.pop("TMUX", None)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import ptyd  # noqa: E402

# independent de terminalul apelantului: cu TERM=dumb `tmux attach` refuză (Codex a văzut 46/47)
os.environ["TERM"] = "xterm-256color"

os.makedirs(ptyd.WEBTERM_DIR, exist_ok=True)
ok_n = 0
total = 0


def check(name, cond, detail=""):
    global ok_n, total
    total += 1
    ok_n += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % (detail,)))


check("AGENT_VERSION >= 62 (kill_if_quiet)", ptyd.AGENT_VERSION >= 62, ptyd.AGENT_VERSION)

HOUR = 3600.0


class FakeSession:
    def __init__(self, backend="tmux", quiet_for=10 * HOUR):
        self.sid = uuid.uuid4().hex
        self.backend = backend
        self.alive = True
        self.pid = None
        self.master = None
        self.kill_requested = False
        self.created = time.time()
        self.created_steady = ptyd._steady()
        self.pending_input = b""
        self.last_out_mono = time.monotonic() - quiet_for
        self.last_in_mono = time.monotonic() - quiet_for


class R:
    def __init__(self, rc=0, out=b"", err=b""):
        self.returncode, self.stdout, self.stderr = rc, out, err


GONE = R(1, b"", b"can't find session: wt-x\n")


class FakeTmux:
    """înlocuitor pentru tmux_cmd: răspunde după subcomandă, înregistrează apelurile (şi timeout-urile).
    `display` = răspunsurile la cele două sonde (prag 0, prag real), în ordine."""
    def __init__(self, windows=None, clients=None, display=None, ifshell=None, has=None, delay=0.0):
        old = int(time.time() - 10 * HOUR)
        self.windows = R(0, ("%d %d\n" % (old, old)).encode()) if windows is None else windows
        self.clients = R(0, b"") if clients is None else clients
        self.display = list(display) if display is not None else [R(0, b"0\n"), R(0, b"1\n")]
        self.ifshell = R(0) if ifshell is None else ifshell
        self.has = GONE if has is None else has
        self.delay = delay
        self.calls = []
        self.timeouts = []

    def __call__(self, *args, **kw):
        self.calls.append(args)
        self.timeouts.append(kw.get("timeout"))
        if self.delay:
            time.sleep(self.delay)
        if args[0] == "display-message":
            r = self.display.pop(0) if self.display else R(1)
        else:
            r = {"list-windows": self.windows, "list-clients": self.clients, "if-shell": self.ifshell,
                 "has-session": self.has}.get(args[0], R(0))
        if isinstance(r, Exception):
            raise r
        return r


def reason(s, quiet, fake):
    saved = ptyd.tmux_cmd
    ptyd.tmux_cmd = fake
    try:
        return ptyd.session_activity_reason(s, quiet)
    finally:
        ptyd.tmux_cmd = saved


# ═════════════════════════ 1. dovezile, cu tmux mockuit ═════════════════════════
Q = 2 * HOUR
f = FakeTmux()
check("liniştită (agent + tmux vechi, niciun client) → \"\"", reason(FakeSession(), Q, f) == "", f.calls)
check("…interogările ţintesc EXACT sesiunea (`=nume`), pe list-windows şi list-clients",
      [c[0] for c in f.calls] == ["list-windows", "list-clients"]
      and all(c[c.index("-t") + 1].startswith("=" + ptyd.TMUX_SESSION_PREFIX) for c in f.calls), f.calls)
s = FakeSession()
s.last_out_mono = time.monotonic() - 60
check("output citit acum un minut → output", reason(s, Q, FakeTmux()) == "output")
s = FakeSession()
s.last_in_mono = time.monotonic() - 60
check("input primit acum un minut → input", reason(s, Q, FakeTmux()) == "input")
s = FakeSession()
s.pending_input = b"x"
check("input în coadă (pty plin) → refuz", reason(s, Q, FakeTmux()) == "input pending")
s = FakeSession()
s.last_out_mono = time.monotonic() - Q - 2
check("Recheck 2 #3: marja LĂRGEŞTE fereastra (activitate la Q+2 s → încă refuz)", reason(s, Q, FakeTmux()) == "output")
s = FakeSession()
s.last_out_mono = time.monotonic() - Q - 10
check("…dincolo de Q + marjă → ok", reason(s, Q, FakeTmux()) == "")
s = FakeSession()
s.created = time.time() - 1000                 # ceasul de perete a sărit înainte faţă de cel continuu
check("Recheck 2 #3: salt de ceas de la crearea sesiunii → refuz (epoch tmux nesigur)",
      reason(s, Q, FakeTmux()) == "clock jump")
s = FakeSession()
del s.created_steady
check("…reper continuu lipsă → refuz", reason(s, Q, FakeTmux()) == "clock jump")
check("Recheck 2 #3: marcaj tmux din viitor (ceas sărit înapoi) → refuz",
      reason(FakeSession(), Q, FakeTmux(windows=R(0, b"%d %d\n" % (time.time() + 600, time.time() - 36000))))
      == "clock skew")
# Recheck 2, High 1: output aflat pe fd-ul PTY, necitit de loop (marcajul n-a apucat să se mute)
m, sl = os.openpty()
try:
    p = FakeSession(backend="pty")
    p.master = m
    check("PTY: niciun octet în aşteptare → ok", reason(p, Q, FakeTmux()) == "")
    os.write(sl, b"fresh output\n")
    time.sleep(0.05)
    check("Recheck 2 High 1: PTY cu output NECITIT pe master → unread output", reason(p, Q, FakeTmux()) == "unread output")
    t = FakeSession()
    t.master = m
    check("…şi pe clientul tmux al nostru (acelaşi fd-check)", reason(t, Q, FakeTmux()) == "unread output")
    os.read(m, 4096)
    check("…după citire → ok", reason(p, Q, FakeTmux()) == "")
finally:
    os.close(sl)
    os.close(m)
p = FakeSession(backend="pty")
p.master = m                                    # fd închis: nu putem verifica → refuz
check("PTY: fd invalid → refuz", reason(p, Q, FakeTmux()) in ("unread output", "pty check failed"))
saved_poll = ptyd.select.poll


class _BadPoll:
    def register(self, *a):
        raise OSError("poll")


ptyd.select.poll = _BadPoll
try:
    p = FakeSession(backend="pty")
    p.master = 0
    check("PTY: verificarea fd-ului eşuează → refuz", reason(p, Q, FakeTmux()) == "pty check failed")
finally:
    ptyd.select.poll = saved_poll
now = int(time.time())
check("tmux: output în fereastră (window_activity recent) → tmux activity",
      reason(FakeSession(), Q, FakeTmux(windows=R(0, b"%d %d\n" % (now - 10 * 3600, now - 30)))) == "tmux activity")
check("tmux: input direct pe host (session_activity recent) → tmux activity",
      reason(FakeSession(), Q, FakeTmux(windows=R(0, b"%d %d\n" % (now - 30, now - 36000)))) == "tmux activity")
check("tmux: a doua fereastră activă → tmux activity",
      reason(FakeSession(), Q, FakeTmux(windows=R(0, b"%d %d\n%d %d\n" % (now - 36000, now - 36000,
                                                                          now - 36000, now - 5)))) == "tmux activity")
s = FakeSession()
s.pid = 4242
check("tmux: doar clientul NOSTRU ataşat → ok", reason(s, Q, FakeTmux(clients=R(0, b"4242\n"))) == "")
check("tmux: alt client ataşat (un om pe host) → refuz",
      reason(s, Q, FakeTmux(clients=R(0, b"4242\n999\n"))) == "another tmux client attached")
check("tmux: un client când noi n-avem niciunul → refuz",
      reason(FakeSession(), Q, FakeTmux(clients=R(0, b"999\n"))) == "another tmux client attached")
for name, fk in (("list-windows rc≠0", FakeTmux(windows=R(1, b""))),
                 ("list-windows gol", FakeTmux(windows=R(0, b""))),
                 ("list-windows ilizibil", FakeTmux(windows=R(0, b"abc def\n"))),
                 ("list-windows timeout", FakeTmux(windows=subprocess.TimeoutExpired("tmux", 3))),
                 ("tmux lipsă (OSError)", FakeTmux(windows=OSError("no tmux"))),
                 ("list-clients rc≠0", FakeTmux(clients=R(1, b""))),
                 ("list-clients ilizibil", FakeTmux(clients=R(0, b"pid?\n"))),
                 ("list-clients timeout", FakeTmux(clients=subprocess.TimeoutExpired("tmux", 3)))):
    check("fail-closed: %s → refuz" % name, reason(FakeSession(), Q, fk) == "tmux query failed")
p = FakeSession(backend="pty")
f = FakeTmux(windows=R(1, b""))
check("backend pty: doar dovezile agentului, tmux neîntrebat", reason(p, Q, f) == "" and f.calls == [])
d = FakeSession()
d.alive = False
f = FakeTmux(windows=R(1, b""))
check("sesiune deja încheiată: tmux neîntrebat", reason(d, Q, f) == "" and f.calls == [])


# ═════════════════════════ 2. op-ul prin handle_ctrl ═════════════════════════
def op(msg, session=None, fake=None, ver=(3, 4)):
    ag = object.__new__(ptyd.Agent)
    ag.replies = []
    ag.send_ctrl = ag.replies.append
    ag._hb_sent_at = {}
    ag.sessions = {session.sid: session} if session else {}
    fake = fake or FakeTmux()
    saved = ptyd.tmux_cmd, ptyd._TMUX_VER
    ptyd.tmux_cmd, ptyd._TMUX_VER = fake, ver
    try:
        ptyd.Agent.handle_ctrl(ag, dict(msg, id=9))
    finally:
        ptyd.tmux_cmd, ptyd._TMUX_VER = saved
    return (ag.replies[0] if ag.replies else {}), fake.calls


def killed(calls):
    return any(c[0] in ("kill-session", "if-shell") for c in calls)


def child():
    """un proces real în locul clientului tmux al nostru: vedem dacă a primit SIGHUP"""
    return subprocess.Popen(["sleep", "30"])


s = FakeSession()
cp = child()
s.pid = cp.pid
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s, FakeTmux(clients=R(0, b"%d\n" % cp.pid)))
name = ptyd.TMUX_SESSION_PREFIX + s.sid
ifs = [list(c) for c in calls if c[0] == "if-shell"]
time.sleep(0.1)
check("op: liniştită → ok: if-shell ATOMIC (condiţie + kill-session pe sesiunea exactă), apoi has-session",
      r.get("ok") is True and s.kill_requested and len(ifs) == 1
      and ifs[0][:4] == ["if-shell", "-F", "-t", "=" + name + ":"] and ifs[0][5] == "kill-session -t =" + name
      and [c[0] for c in calls][-2:] == ["if-shell", "has-session"]
      and not any(c[0] == "kill-session" for c in calls), (r, calls))
check("…condiţia: input, toate ferestrele, numărul de clienţi, clienţii străini (L:, tmux ≥ 3.4)",
      all(k in ifs[0][4] for k in ("#{session_activity}", "#{W:", "#{session_attached},1}", "#{L:",
                                   "#{client_pid},%d}" % cp.pid)), ifs[0][4] if ifs else None)
check("…clientul nostru semnalizat (SIGHUP) DOAR după confirmarea dispariţiei", cp.poll() == -signal.SIGHUP, cp.poll())
f = FakeTmux()
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s, f)
check("op: fiecare comandă tmux are timeout ≤ 3 s (în bugetul total)",
      all(t is not None and 0 < t <= ptyd.QUIET_TMUX_TIMEOUT for t in f.timeouts), f.timeouts)
# Recheck 2, Medium 4 + High 1: kill-ul atomic nu se face → refuz, clientul neatins, kill_requested nepus
for label, fk, code in (
        ("condiţie falsă la kill (sesiunea trăieşte)", FakeTmux(has=R(0)), "active"),
        ("if-shell eşuează, sesiunea trăieşte", FakeTmux(ifshell=R(1, b"", b"boom"), has=R(0)), "kill_failed"),
        ("has-session expiră", FakeTmux(has=subprocess.TimeoutExpired("tmux", 3)), "kill_failed"),
        ("has-session: eroare neclară", FakeTmux(has=R(1, b"", b"lost server")), "kill_failed"),
        ("if-shell expiră", FakeTmux(ifshell=subprocess.TimeoutExpired("tmux", 3)), "kill_failed")):
    s = FakeSession()
    cp = child()
    s.pid = cp.pid
    fk.clients = R(0, b"%d\n" % cp.pid)
    r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s, fk)
    time.sleep(0.05)
    check("Recheck 2 #4: %s → %s, fără SIGHUP, kill_requested nepus" % (label, code),
          r.get("ok") is False and r.get("code") == code and cp.poll() is None and not s.kill_requested, (r, calls))
    cp.kill()
    cp.wait()
# tmux care nu poate garanta atomicitatea → refuz (niciodată închidere pe acel host)
for label, fk, ver in (("tmux 3.1", FakeTmux(), (3, 1)),
                       ("versiune tmux necunoscută", FakeTmux(), None),
                       ("sonda dă gol (modificator necunoscut)", FakeTmux(display=[R(0, b"\n"), R(0, b"1\n")]), (3, 4)),
                       ("sonda pe prag 0 dă 1", FakeTmux(display=[R(0, b"1\n"), R(0, b"1\n")]), (3, 4)),
                       ("sonda dă text literal", FakeTmux(display=[R(0, b"0\n"), R(0, b"#{&&:1,1}\n")]), (3, 4))):
    s = FakeSession()
    r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s, fk, ver=ver)
    check("Recheck 2: %s → active, nimic omorât" % label,
          r.get("code") == "active" and not killed(calls) and not s.kill_requested, (r, calls))
s = FakeSession()
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s, FakeTmux(), ver=(3, 2))
ifs = [c for c in calls if c[0] == "if-shell"]
check("tmux 3.2–3.3: fără bucla L:, doar numărul de clienţi ataşaţi",
      r.get("ok") is True and ifs and "#{L:" not in ifs[0][4] and "#{session_attached},0}" in ifs[0][4], calls)
s = FakeSession()
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s,
              FakeTmux(display=[R(0, b"0\n"), R(0, b"0\n")]))
check("sonda pe pragul real dă 0 (activitate) → active, fără if-shell", r.get("code") == "active" and not killed(calls), calls)
# Recheck 2, Medium 5: buget TOTAL
saved_b = ptyd.QUIET_BUDGET
try:
    ptyd.QUIET_BUDGET = 0.0
    s = FakeSession()
    r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s)
    check("Recheck 2 #5: fără buget → refuz, nimic omorât", r.get("code") == "active" and not killed(calls), (r, calls))
    ptyd.QUIET_BUDGET = 0.5
    s = FakeSession()
    t0 = time.monotonic()
    r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s, FakeTmux(delay=0.2))
    el = time.monotonic() - t0
    check("Recheck 2 #5: comenzi lente epuizează bugetul → refuz, op-ul se opreşte la buget",
          r.get("ok") is False and not killed(calls) and not s.kill_requested and el < 1.0, (r, calls, el))
finally:
    ptyd.QUIET_BUDGET = saved_b
s = FakeSession()
s.last_out_mono = time.monotonic() - 1
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s)
check("op: output recent → active, NIMIC omorât", r.get("ok") is False and r.get("code") == "active"
      and not killed(calls) and not s.kill_requested, (r, calls))
s = FakeSession()
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s, FakeTmux(windows=R(1, b"")))
check("op: interogarea tmux eşuează → active, nimic omorât", r.get("code") == "active" and not killed(calls), r)
s = FakeSession()
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s, FakeTmux(clients=R(0, b"77\n")))
check("op: alt client tmux ataşat → active, nimic omorât", r.get("code") == "active" and not killed(calls), r)
r, calls = op({"op": "kill_if_quiet", "sid": uuid.uuid4().hex, "quiet_secs": Q}, FakeSession())
check("op: sid necunoscut → no_session", r.get("code") == "no_session" and not killed(calls), r)
r, calls = op({"op": "kill_if_quiet", "sid": ["x"], "quiet_secs": Q}, FakeSession())
check("op: sid de alt tip → no_session, nu crash", r.get("code") == "no_session", r)
for bad in (None, "3600", -1, True, float("nan"), float("inf"), 1e12):
    s = FakeSession()
    r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": bad}, s)
    check("op: quiet_secs=%r → bad_request, nimic omorât" % (bad,),
          r.get("code") == "bad_request" and not killed(calls) and not s.kill_requested, r)
s = FakeSession()
r, calls = op({"op": "kill", "sid": s.sid}, s)
check("op `kill` neschimbat: omoară fără nicio verificare", r.get("ok") is True and killed(calls)
      and not any(c[0] in ("list-windows", "list-clients") for c in calls), calls)
for q in (0, 5, 59, 59.9):
    s = FakeSession()
    r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": q}, s)
    check("Recheck 2 #3: quiet_secs=%r (fereastră degenerată) → bad_request, nimic omorât" % q,
          r.get("code") == "bad_request" and not killed(calls) and not s.kill_requested, r)
s = FakeSession()
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": 60}, s)
check("op: quiet_secs=60 (minimul) acceptat", r.get("ok") is True, r)
m, sl = os.openpty()
try:
    p = FakeSession(backend="pty")
    p.master = m
    cp = child()
    p.pid = cp.pid
    os.write(sl, b"late output\n")
    time.sleep(0.05)
    r, calls = op({"op": "kill_if_quiet", "sid": p.sid, "quiet_secs": Q}, p)
    time.sleep(0.05)
    check("op: PTY direct cu output necitit → active, procesul neatins",
          r.get("code") == "active" and cp.poll() is None and not p.kill_requested, r)
    os.read(m, 4096)
    r, calls = op({"op": "kill_if_quiet", "sid": p.sid, "quiet_secs": Q}, p)
    time.sleep(0.1)
    check("op: PTY direct liniştit → ok, SIGHUP, tmux neîntrebat",
          r.get("ok") is True and cp.poll() == -signal.SIGHUP and p.kill_requested and calls == [], (r, calls))
finally:
    os.close(sl)
    os.close(m)

# urmărirea pe Session: append_output / write_input mută marcajele monotone
real = object.__new__(ptyd.Session)
real.ring, real.ring_bytes, real.stream_offset = [], 0, 0
real.last_out_mono = 0.0
ptyd.Session.append_output(real, b"hello")
check("Session.append_output marchează last_out_mono", time.monotonic() - real.last_out_mono < 5)
src = open(os.path.join(os.path.dirname(__file__), "..", "agent", "ptyd.py"), encoding="utf-8").read()
wi = src[src.index("    def write_input(self, sid, data):"):]
wi = wi[:wi.index("\n    def ", 10)]
check("write_input marchează last_in_mono ÎNAINTE de orice aruncare (plafon / copy-mode)",
      wi.index("s.last_in_mono = time.monotonic()") < wi.index("PENDING_INPUT_MAX"))


# ═════════════════════════ 3. tmux REAL, pe un socket izolat ═════════════════════════
def at(sess, offset, **kw):
    """session_activity_reason „peste `offset` secunde": ambele ceasuri înaintează (fără salt)"""
    return ptyd.session_activity_reason(sess, 600, now_wall=time.time() + offset,
                                        now_steady=ptyd._steady() + offset, **kw)


def atomic(sess, offset, wrap=None):
    """tmux_kill_if_quiet „peste `offset` secunde"; `wrap` poate falsifica DOAR anumite răspunsuri (ca
    if-shell-ul real să fie cel care decide)"""
    saved = ptyd.tmux_cmd
    if wrap:
        ptyd.tmux_cmd = wrap(saved)
    try:
        return ptyd.tmux_kill_if_quiet(sess, 600, time.monotonic() + ptyd.QUIET_BUDGET, now_wall=time.time() + offset)
    finally:
        ptyd.tmux_cmd = saved


def lie(real, display_ok=True, no_clients=False):
    """trece totul la tmux-ul real, dar: sondele spun „0"/„1" (ca şi cum pre-check-ul ar fi văzut linişte),
    iar list-clients poate pretinde că nu e nimeni ataşat → doar if-shell-ul ATOMIC mai poate refuza"""
    n = {"display": 0}

    def f(*args, **kw):
        if args[0] == "display-message" and display_ok:
            n["display"] += 1
            return R(0, b"0\n" if n["display"] == 1 else b"1\n")
        if args[0] == "list-clients" and no_clients:
            return R(0, b"")
        return real(*args, **kw)
    return f


def alive(name):
    return ptyd.tmux_cmd("has-session", "-t", "=" + name).returncode == 0


TMUX = shutil.which("tmux")
if not TMUX:
    print("  SKIP tmux real: binarul lipseşte (CI hermetic)")
elif ptyd._TMUX_VER is None or ptyd._TMUX_VER < ptyd.TMUX_ATOMIC_MIN:
    print("  SKIP tmux real: tmux %r < %r" % (ptyd._TMUX_VER, ptyd.TMUX_ATOMIC_MIN))
else:
    sock = "wt62test-%d" % os.getpid()
    saved = (ptyd.TMUX_SOCKET, ptyd.TMUX_CONF)
    ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = sock, os.devnull
    sess = FakeSession()
    name = ptyd.TMUX_SESSION_PREFIX + sess.sid
    keep = FakeSession()                       # a doua sesiune: serverul nu iese când o omorâm pe prima
    keep_name = ptyd.TMUX_SESSION_PREFIX + keep.sid
    sock_path = os.path.join(os.environ["TMUX_TMPDIR"], "tmux-%d" % os.getuid(), sock)
    started = False
    client = None
    try:
        try:
            started = ptyd.tmux_cmd("new-session", "-d", "-s", name, "-x", "100", "-y", "20", "sh",
                                    timeout=20).returncode == 0
            started = started and ptyd.tmux_cmd("new-session", "-d", "-s", keep_name, "sh",
                                                timeout=20).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            started = False
        if not started:
            raise RuntimeError("skip")
        check("tmux real: serverul de test e pe socketul IZOLAT", os.path.exists(sock_path), sock_path)
        check("tmux real: liniştită (marcaje vechi, niciun client) → \"\"", at(sess, HOUR) == "")
        check("tmux real: salt de ceas (doar peretele înaintează) → refuz",
              ptyd.session_activity_reason(sess, 600, now_wall=time.time() + HOUR) == "clock jump")
        # output într-o fereastră din FUNDAL, fără client ataşat
        ptyd.tmux_cmd("new-window", "-d", "-t", "=" + name + ":", "sh")
        ptyd.tmux_cmd("send-keys", "-t", "=" + name + ":1", "echo v62-bg-output", "Enter")
        time.sleep(1.2)
        check("tmux real: output în fereastra din fundal → tmux activity (pre-check)", at(sess, 60) == "tmux activity")
        check("tmux real: …dar nu peste fereastra de linişte", at(sess, 700) == "")
        code, why = atomic(sess, 60)
        check("tmux real ATOMIC: output în fundal → active (sonda), sesiunea vie", code == "active" and alive(name),
              (code, why))
        code, why = atomic(sess, 60, wrap=lambda real: lie(real))
        check("tmux real ATOMIC: sondele mint „linişte”, if-shell-ul vede output-ul din fundal → active, vie",
              code == "active" and why == "activity at kill time" and alive(name), (code, why))
        # un om ataşat direct pe host: un client tmux în propriul pty
        pid, fd = pty.fork()
        if pid == 0:
            os.execv(TMUX, [TMUX, "-L", sock, "-f", os.devnull, "attach-session", "-t", "=" + name])
        client = (pid, fd)
        end = time.time() + 5
        while time.time() < end and not ptyd.tmux_cmd("list-clients", "-t", "=" + name).stdout.strip():
            try:
                os.read(fd, 65536) if select.select([fd], [], [], 0.05)[0] else None
            except OSError:
                break
        check("tmux real: alt client ataşat → refuz",
              at(sess, 7200) == "another tmux client attached")
        code, why = atomic(sess, 7200, wrap=lambda real: lie(real, no_clients=True))
        check("tmux real ATOMIC: client străin pe care pre-check-ul nu l-a văzut → if-shell refuză, vie",
              code == "active" and why == "activity at kill time" and alive(name), (code, why))
        if ptyd._TMUX_VER >= ptyd.TMUX_CLIENT_LOOP_MIN:
            # numărul de clienţi se potriveşte (1), dar clientul NU e al nostru: doar bucla L: îl prinde
            sess.pid = 999999
            def same_count(real):
                liar = lie(real)
                return lambda *a, **kw: R(0, b"999999\n") if a[0] == "list-clients" else liar(*a, **kw)
            code, why = atomic(sess, 7200, wrap=same_count)
            check("tmux real ATOMIC: client străin cu acelaşi NUMĂR de clienţi → bucla L: refuză, vie",
                  code == "active" and why == "activity at kill time" and alive(name), (code, why))
        sess.pid = pid                       # acelaşi client, dar al NOSTRU
        check("tmux real: clientul nostru nu contează ca „alt om”", at(sess, 7200) == "")
        sess.pid = None
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        os.close(fd)
        client = None
        end = time.time() + 5
        while time.time() < end and ptyd.tmux_cmd("list-clients", "-t", "=" + name).stdout.strip():
            time.sleep(0.05)
        ghost = FakeSession()
        check("tmux real: sesiune tmux inexistentă → refuz (interogare eşuată)", at(ghost, 0) == "tmux query failed")
        code, why = atomic(ghost, HOUR)
        check("tmux real ATOMIC: sesiune inexistentă → refuz", code == "active", (code, why))
        # liniştită: verificarea şi kill-ul în aceeaşi comandă → sesiunea dispare, cealaltă rămâne
        code, why = atomic(sess, HOUR)
        check("tmux real ATOMIC: liniştită → \"\" şi sesiunea a DISPĂRUT (doar ea)",
              code == "" and not alive(name) and alive(keep_name), (code, why))
    except RuntimeError:
        print("  SKIP tmux real: serverul de test n-a pornit la timp")
    finally:
        if client is not None:
            try:
                os.kill(client[0], signal.SIGTERM)
                os.waitpid(client[0], 0)
            except OSError:
                pass
            os.close(client[1])
        # NICIODATĂ kill-server: doar sesiunile noastre (ultima închisă opreşte serverul de test)
        for n in (name, keep_name):
            try:
                ptyd.tmux_cmd("kill-session", "-t", "=" + n)
            except (OSError, subprocess.TimeoutExpired):
                pass
        ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = saved

shutil.rmtree(os.environ["TMUX_TMPDIR"], ignore_errors=True)
print("\n%d/%d checks passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
