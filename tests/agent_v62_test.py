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
        self.pending_input = b""
        self.last_out_mono = time.monotonic() - quiet_for
        self.last_in_mono = time.monotonic() - quiet_for


class R:
    def __init__(self, rc=0, out=b""):
        self.returncode, self.stdout, self.stderr = rc, out, b""


class FakeTmux:
    """înlocuitor pentru tmux_cmd: răspunde după subcomandă, înregistrează apelurile"""
    def __init__(self, windows=None, clients=None):
        old = int(time.time() - 10 * HOUR)
        self.windows = R(0, ("%d %d\n" % (old, old)).encode()) if windows is None else windows
        self.clients = R(0, b"") if clients is None else clients
        self.calls = []

    def __call__(self, *args, **kw):
        self.calls.append(args)
        r = {"list-windows": self.windows, "list-clients": self.clients}.get(args[0], R(0))
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
s.last_out_mono = time.monotonic() - Q + 2
check("activitate în marja de 5 s de la capătul ferestrei → tot ok (marja e în favoarea refuzului doar înăuntru)",
      reason(s, Q, FakeTmux()) == "")
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
def op(msg, session=None, fake=None):
    ag = object.__new__(ptyd.Agent)
    ag.replies = []
    ag.send_ctrl = ag.replies.append
    ag._hb_sent_at = {}
    ag.sessions = {session.sid: session} if session else {}
    fake = fake or FakeTmux()
    saved = ptyd.tmux_cmd
    ptyd.tmux_cmd = fake
    try:
        ptyd.Agent.handle_ctrl(ag, dict(msg, id=9))
    finally:
        ptyd.tmux_cmd = saved
    return (ag.replies[0] if ag.replies else {}), fake.calls


def killed(calls):
    return any(c[0] == "kill-session" for c in calls)


s = FakeSession()
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": Q}, s)
check("op: liniştită → ok + kill-session pe sesiunea exactă",
      r.get("ok") is True and killed(calls) and s.kill_requested
      and ["kill-session", "-t", "=" + ptyd.TMUX_SESSION_PREFIX + s.sid] in [list(c) for c in calls], (r, calls))
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
s = FakeSession()
s.last_in_mono = time.monotonic()
r, calls = op({"op": "kill_if_quiet", "sid": s.sid, "quiet_secs": 0}, s)
check("op: quiet_secs=0 = fără fereastră → se comportă ca kill", r.get("ok") is True and killed(calls), r)

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
TMUX = shutil.which("tmux")
if not TMUX:
    print("  SKIP tmux real: binarul lipseşte (CI hermetic)")
else:
    sock = "wt62test-%d" % os.getpid()
    saved = (ptyd.TMUX_SOCKET, ptyd.TMUX_CONF)
    ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = sock, os.devnull
    sess = FakeSession()
    name = ptyd.TMUX_SESSION_PREFIX + sess.sid
    sock_path = os.path.join(os.environ["TMUX_TMPDIR"], "tmux-%d" % os.getuid(), sock)
    started = False
    client = None
    try:
        try:
            started = ptyd.tmux_cmd("new-session", "-d", "-s", name, "-x", "100", "-y", "20", "sh",
                                    timeout=20).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            started = False
        if not started:
            raise RuntimeError("skip")
        check("tmux real: serverul de test e pe socketul IZOLAT", os.path.exists(sock_path), sock_path)
        # „acum + 1 oră" pe ceasul de perete: marcajele de la crearea sesiunii sunt vechi
        later = time.time() + HOUR
        check("tmux real: liniştită (marcaje vechi, niciun client) → \"\"",
              ptyd.session_activity_reason(sess, 600, now_wall=later) == "")
        ptyd.tmux_cmd("send-keys", "-t", name + ":", "echo v62-output", "Enter")
        time.sleep(1.2)
        check("tmux real: output fără client ataşat (window_activity) → tmux activity",
              ptyd.session_activity_reason(sess, 600, now_wall=time.time() + 60) == "tmux activity")
        check("tmux real: …dar nu peste fereastra de linişte", ptyd.session_activity_reason(
            sess, 600, now_wall=time.time() + 700) == "")
        # un om ataşat direct pe host: un client tmux în propriul pty
        pid, fd = pty.fork()
        if pid == 0:
            os.execv(TMUX, [TMUX, "-L", sock, "-f", os.devnull, "attach-session", "-t", "=" + name])
        client = (pid, fd)
        end = time.time() + 5
        while time.time() < end and not ptyd.tmux_cmd("list-clients", "-t", "=" + name).stdout.strip():
            time.sleep(0.05)
        check("tmux real: alt client ataşat → refuz",
              ptyd.session_activity_reason(sess, 600, now_wall=time.time() + 7200) == "another tmux client attached")
        sess.pid = pid                       # acelaşi client, dar al NOSTRU
        check("tmux real: clientul nostru nu contează ca „alt om”",
              ptyd.session_activity_reason(sess, 600, now_wall=time.time() + 7200) == "")
        sess.pid = None
        ghost = FakeSession()
        check("tmux real: sesiune tmux inexistentă → refuz (interogare eşuată)",
              ptyd.session_activity_reason(ghost, 600) == "tmux query failed")
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
        if started:
            ptyd.tmux_cmd("kill-session", "-t", "=" + name)    # NICIODATĂ kill-server: doar sesiunea noastră
        ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = saved

shutil.rmtree(os.environ["TMUX_TMPDIR"], ignore_errors=True)
print("\n%d/%d checks passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
