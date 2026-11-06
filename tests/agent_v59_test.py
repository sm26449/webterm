"""Agent v59 — tastatura te scoate din istoricul tmux (copy-mode) + op-ul `scroll_exit`.

De ce: cu `mouse on`, rotiţa bagă pane-ul în copy-mode-ul tmux, iar copy-mode ia tastatura —
săgeţile îi mută cursorul, literele şi Enter sunt aruncate, ieşi doar cu q / Esc / Ctrl+C sau
derulând până jos. Raportat 2026-11-06: „dacă dăm scroll, nu mai putem reveni la prompt cu săgeata,
tastând sau cu Enter". Mai rău, Space („pagină în jos") iese singur când ajunge jos, deci o comandă
tastată orbeşte ajungea la prompt TRUNCHIATĂ. v59: input de TASTATURĂ cu pane-ul în copy-mode →
agentul iese din copy-mode întâi, apoi livrează tastele — mai puţin pe cele care ar TRIMITE linia
(Enter, Ctrl+O): acelea doar te întorc la prompt, ca să nu rulezi o linie la care nu te uitai.

Acoperă:
  · clasificarea unui chunk de input (copy_mode_action): rapoarte de terminal vs. taste, PageUp /
    PageDown rămân ale istoricului, Esc / Ctrl+C şi tastele de trimitere doar ies;
  · armarea (copy_mode_arms): doar rotiţă / drag, nu un click şi nu mişcarea fără buton;
  · poarta _copy_mode_gate cu tmux MOCKUIT: când întreabă tmux (o dată, nu la fiecare tastă, şi
    cu plafon de ritm), ce livrează, când rămâne armată (rapoarte încă pe drum);
  · tmux_copy_mode_exit cu tmux mockuit: ţinta, `-X cancel`, tmux < 2.4 neatins, erori;
  · op-ul `scroll_exit` prin handle_ctrl;
  · tmux REAL pe un socket IZOLAT (-L propriu + TMUX_TMPDIR temporar; doar kill-session, niciodată
    kill-server) — sărit dacă tmux lipseşte;
  · quoting-ul din tmux.conf: linia `word-separators` (cu apostrofă) era respinsă de tmux < 3.0;
  · gateway: poarta de versiune (agent < 59 nu primeşte op-ul), porţile hub-ului (read-only,
    blocat, ritm) şi eşecurile care devin „nu era în istoric".
"""
import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

os.environ["HOME"] = tempfile.mkdtemp(prefix="v59-home-")
os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp(prefix="v59-data-")
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
# tmux-ul de test NU are voie să atingă serverul de producţie: socket propriu, în alt director
os.environ["TMUX_TMPDIR"] = tempfile.mkdtemp(prefix="v59-tmux-")
os.environ.pop("TMUX", None)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
import ptyd  # noqa: E402

os.makedirs(ptyd.WEBTERM_DIR, exist_ok=True)
ok_n = 0
total = 0


def check(name, cond, detail=""):
    global ok_n, total
    total += 1
    ok_n += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % (detail,)))


check("AGENT_VERSION >= 59", ptyd.AGENT_VERSION >= 59, ptyd.AGENT_VERSION)

WHEEL_UP = b"\x1b[<64;40;10M"
WHEEL_DOWN = b"\x1b[<65;40;10M"
CLICK = b"\x1b[<0;5;5M\x1b[<0;5;5m"
DRAG = b"\x1b[<32;6;5M"

# ═════════════════════════ 1. clasificarea input-ului ═════════════════════════
act = ptyd.copy_mode_action
for name, data in (
        ("rotiţă (mouse SGR)", WHEEL_UP), ("click + release", CLICK), ("mouse X10", b"\x1b[M !!"),
        ("focus in", b"\x1b[I"), ("focus out + in", b"\x1b[O\x1b[I"), ("CPR", b"\x1b[12;40R"),
        ("DA1", b"\x1b[?1;2c"), ("DA2", b"\x1b[>0;276;0c"), ("DECRPM", b"\x1b[?2026;2$y"),
        ("raport de fereastră", b"\x1b[8;24;80t"), ("OSC cu BEL", b"\x1b]11;rgb:0000/0000/0000\x07"),
        ("OSC cu ST", b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\"), ("DCS (XTVERSION)", b"\x1bP>|xterm.js(5.5.0)\x1b\\"),
        ("DSR (stare)", b"\x1b[0n"), ("DECXCPR", b"\x1b[?12;40R"), ("DECXCPR cu pagină", b"\x1b[?12;40;1R"),
        ("mai multe rapoarte lipite", WHEEL_UP * 3 + b"\x1b[I"), ("gol", b"")):
    check("raport: %s → nu e tastatură" % name, act(data) == "report", (data, act(data)))
for name, data in (
        ("literă", b"a"), ("text", b"ls -la"), ("Tab", b"\t"),
        ("Space", b" "), ("q", b"q"), ("săgeată sus", b"\x1b[A"), ("săgeată (mod aplicaţie)", b"\x1bOA"),
        ("Home", b"\x1b[H"), ("Alt+b", b"\x1bb"), ("Ctrl+U", b"\x15"), ("Ctrl+R", b"\x12"),
        ("UTF-8 (ș)", "ș".encode()), ("paste bracketed pe un rând", b"\x1b[200~rm -rf x\x1b[201~"),
        ("raport URMAT de tastă", WHEEL_UP + b"x"), ("tastă urmată de raport", b"x" + WHEEL_UP),
        ("Esc + literă (nu Esc singur)", b"\x1bx"), ("PageUp cu tastă după", b"\x1b[5~a"),
        ("Shift+PageUp", b"\x1b[5;2~")):
    check("tastatură: %s → ieşim şi livrăm" % name, act(data) == "exit", (data, act(data)))
check("PageUp rămâne al istoricului", act(b"\x1b[5~") == "page")
check("PageDown rămâne al istoricului", act(b"\x1b[6~") == "page")
check("PageUp ţinut apăsat (mai multe într-un chunk)", act(b"\x1b[5~\x1b[5~\x1b[6~") == "page")
check("Esc singur doar iese", act(b"\x1b") == "quit")
check("Ctrl+C singur doar iese", act(b"\x03") == "quit")
check("Ctrl+C dublu într-un chunk NU e „doar ieşi” (al doilea e pentru program)", act(b"\x03\x03") == "exit")
# tastele care TRIMIT linia doar te întorc la prompt: nu rulezi o linie la care nu te uitai
for name, data in (
        ("Enter (CR)", b"\r"), ("LF (Ctrl+J)", b"\n"), ("Ctrl+O", b"\x0f"), ("text + Enter (IME, snippet)", b"ls\r"),
        ("două linii", b"a\nb\n"), ("paste bracketed cu Enter în el", b"\x1b[200~rm -rf x\r\x1b[201~"),
        ("Esc urmat de Enter", b"\x1b\r"), ("raport + Enter", WHEEL_UP + b"\r")):
    check("trimitere: %s → ieşim, NU livrăm" % name, act(data) == "quit", (data, act(data)))

arms = ptyd.copy_mode_arms
check("armare: rotiţă sus", arms(WHEEL_UP))
check("armare: rotiţă jos (bitul 64; inofensiv)", arms(WHEEL_DOWN))
check("armare: rotiţă cu Shift / Ctrl", arms(b"\x1b[<68;1;1M") and arms(b"\x1b[<80;1;1M"))
check("armare: drag cu butonul 1", arms(DRAG))
check("armare: mouse X10 (butonul nu se decodează)", arms(b"\x1b[M !!"))
check("un click simplu NU armează (TUI-uri cu mouse)", not arms(CLICK))
check("butonul din mijloc / dreapta NU armează", not arms(b"\x1b[<1;1;1M") and not arms(b"\x1b[<2;1;1M"))
check("mişcarea FĂRĂ buton (any-motion, cod 35) NU armează — vine la fiecare pixel", not arms(b"\x1b[<35;10;10M"))
check("drag cu butonul din mijloc / dreapta armează", arms(b"\x1b[<33;1;1M") and arms(b"\x1b[<34;1;1M"))
check("tastele nu armează", not arms(b"ls\r") and not arms(b"\x1b[A") and not arms(b"\x1b[I"))
check("raportul armează şi lipit de taste", arms(b"x" + WHEEL_UP + b"y"))
check("cod de buton absurd (cifre multe) nu aruncă", arms(b"\x1b[<99999999999;1;1M") is False)


# ═════════════════════════ 2. poarta, cu tmux mockuit ═════════════════════════
class FakeSession:
    def __init__(self, armed=False):
        self.sid = uuid.uuid4().hex
        self.backend = "tmux"
        self.alive = True
        self.master = 7
        self.pending_input = b""
        self.copy_armed = armed
        self.copy_armed_at = 0.0
        self.copy_checked_at = 0.0


class Exit:
    """înlocuitor pentru tmux_copy_mode_exit: numără apelurile, întoarce ce i se spune"""
    def __init__(self, *results):
        self.results, self.calls = list(results), []

    def __call__(self, sid):
        self.calls.append(sid)
        return self.results.pop(0) if self.results else False


def gate(s, data, *results, **kw):
    if not kw.get("keep_rate"):
        s.copy_checked_at = 0.0          # fiecare apel = o tastă „mult după" precedenta
    ag = object.__new__(ptyd.Agent)
    fake = Exit(*results)
    real = ptyd.tmux_copy_mode_exit
    ptyd.tmux_copy_mode_exit = fake
    try:
        return ptyd.Agent._copy_mode_gate(ag, s, data), fake.calls
    finally:
        ptyd.tmux_copy_mode_exit = real


s = FakeSession()
out, calls = gate(s, b"ls\r")
check("nearmată: tastele trec fără nicio întrebare către tmux", out == b"ls\r" and calls == [], (out, calls))
out, calls = gate(s, WHEEL_UP)
check("rotiţa armează sesiunea, raportul pleacă neatins, tmux nu e întrebat",
      out == WHEEL_UP and calls == [] and s.copy_armed, (out, calls, s.copy_armed))
out, calls = gate(s, b"\x1b[I")
check("armată + raport de focus: neatins, rămâne armată (schimbi tabul, nu ieşi din istoric)",
      out == b"\x1b[I" and calls == [] and s.copy_armed)
out, calls = gate(s, b"\x1b[5~")
check("armată + PageUp: livrat copy-mode-ului, rămâne armată, tmux nu e întrebat",
      out == b"\x1b[5~" and calls == [] and s.copy_armed)
s.copy_armed_at = time.time() - 5
out, calls = gate(s, b"e", True)
check("armată + tastă, pane în copy-mode: ieşim (o întrebare) şi livrăm tasta",
      out == b"e" and calls == [s.sid] and not s.copy_armed, (out, calls, s.copy_armed))
out, calls = gate(s, b"cho hi\r")
check("…iar restul liniei nu mai întreabă tmux (dezarmată)", out == b"cho hi\r" and calls == [])

s = FakeSession(armed=True)
out, calls = gate(s, b"\x1b", True)
check("Esc cu pane-ul în copy-mode: iese şi NU ajunge la program", out == b"" and calls == [s.sid] and not s.copy_armed)
s = FakeSession(armed=True)
out, calls = gate(s, b"\x03", True)
check("Ctrl+C cu pane-ul în copy-mode: iese şi NU omoară jobul", out == b"" and not s.copy_armed)
s = FakeSession(armed=True)
out, calls = gate(s, b"\x1b", False)
check("Esc când pane-ul NU e în copy-mode: ajunge la program, ca până acum", out == b"\x1b" and not s.copy_armed)
s = FakeSession(armed=True)
out, calls = gate(s, b"\x03", False)
check("Ctrl+C când pane-ul NU e în copy-mode: ajunge la program", out == b"\x03")
s = FakeSession(armed=True)
out, calls = gate(s, b"x", None)
check("tmux n-a răspuns (None): tasta pleacă oricum, dezarmăm (fără subprocess la fiecare tastă)",
      out == b"x" and not s.copy_armed)
s = FakeSession(armed=True)
out, calls = gate(s, b"\r", True)
check("Enter cu pane-ul în copy-mode: ieşim şi NU îl livrăm (linia de la prompt nu rulează nevăzută)",
      out == b"" and calls == [s.sid] and not s.copy_armed, (out, calls))
s = FakeSession(armed=True)
out, calls = gate(s, b"\r", False)
check("Enter când pane-ul NU e în copy-mode: livrat, ca întotdeauna", out == b"\r" and not s.copy_armed)
s = FakeSession(armed=True)
out, calls = gate(s, b"\r", None)
check("Enter când tmux n-a răspuns: livrat (nu înghiţim taste pe o presupunere)", out == b"\r")
s = FakeSession(armed=True)
out, calls = gate(s, b"\x0f", True)
check("Ctrl+O cu pane-ul în copy-mode: NU se livrează", out == b"")
s = FakeSession(armed=True)
out, calls = gate(s, b"rm -rf /srv/x\r", True)
check("text + Enter într-un chunk, cu pane-ul în copy-mode: nimic livrat (nici textul, nici Enter-ul)", out == b"")
s = FakeSession(armed=True)
out, calls = gate(s, b"\x1b[200~echo hi\x1b[201~", True)
check("paste pe un rând cu pane-ul în copy-mode: ieşim şi livrăm textul întreg", out == b"\x1b[200~echo hi\x1b[201~")
s = FakeSession()
out, calls = gate(s, b"\r")
check("nearmată: Enter trece fără nicio întrebare (drumul obişnuit e neatins)", out == b"\r" and calls == [])

s = FakeSession()
gate(s, WHEEL_UP)
out, calls = gate(s, b"x", False)
check("„nu e în copy-mode” imediat după rotiţă = poate „încă nu”: rămâne armată",
      out == b"x" and calls == [s.sid] and s.copy_armed)
s.copy_armed_at = time.time() - ptyd.COPY_MODE_SETTLE - 0.1
out, calls = gate(s, b"y", False)
check("…după fereastra de aşezare, acelaşi răspuns dezarmează", out == b"y" and not s.copy_armed)
s = FakeSession()
gate(s, WHEEL_UP)
out, calls = gate(s, b"x", True)
check("ieşit din copy-mode imediat după rotiţă: rămâne armată (rapoartele de pe drum o pot băga la loc)",
      out == b"x" and s.copy_armed)
out, calls = gate(s, b"y", True)
check("…şi tasta următoare iese din nou", out == b"y" and calls == [s.sid])
s = FakeSession()
gate(s, WHEEL_UP)
out, calls = gate(s, b"x", None)
check("tmux n-a răspuns imediat după rotiţă: dezarmează oricum (nu repetăm un subprocess care eşuează)",
      out == b"x" and not s.copy_armed)

# plafonul de ritm: cât rămâne armată, cel mult o întrebare la COPY_MODE_MIN_INTERVAL
s = FakeSession()
gate(s, WHEEL_UP)
out, calls = gate(s, b"a", False)
out2, calls2 = gate(s, b"b", True, keep_rate=True)
check("a doua tastă în interiorul plafonului: trece FĂRĂ întrebare şi rămâne armată",
      out2 == b"b" and calls2 == [] and s.copy_armed, (out2, calls2, s.copy_armed))
out3, calls3 = gate(s, WHEEL_UP + b"\r", True, keep_rate=True)
check("…inclusiv un chunk raport+Enter trimis în rafală (fără subprocess per frame)",
      out3 == WHEEL_UP + b"\r" and calls3 == [])
s.copy_checked_at = time.time() - ptyd.COPY_MODE_MIN_INTERVAL - 0.01
out4, calls4 = gate(s, b"c", True, keep_rate=True)
check("…după plafon, tasta următoare întreabă din nou", out4 == b"c" and calls4 == [s.sid])
s = FakeSession(armed=True)
s.pending_input = b"\x1b[<64;1;1M"
out, calls = gate(s, b"x", False)
check("raportul e încă în coada de input (nescris): rămâne armată", s.copy_armed)
s = FakeSession(armed=True)
s.master = None
out, calls = gate(s, b"x", False)
check("fără client tmux ataşat (input în aşteptare): rămâne armată", s.copy_armed)
s = FakeSession()
out, calls = gate(s, WHEEL_UP + b"x", False)
check("raport + tastă în acelaşi chunk: întreabă, livrează tot, rămâne armată (rotiţa e încă nescrisă)",
      out == WHEEL_UP + b"x" and calls == [s.sid] and s.copy_armed)
bare = object.__new__(FakeSession)
bare.sid, bare.pending_input, bare.master = "x" * 32, b"", 7
ag0 = object.__new__(ptyd.Agent)
check("sesiune construită fără __init__ (fără atributele porţii): nearmată, tastele trec, fără excepţie",
      ptyd.Agent._copy_mode_gate(ag0, bare, b"ls\r") == b"ls\r")
real_spawn = ptyd.Session.spawn_client
ptyd.Session.spawn_client = lambda self: None          # fără fork: doar starea din __init__
try:
    fresh = ptyd.Session(uuid.uuid4().hex, 24, 80, "xterm-256color", backend="tmux")
finally:
    ptyd.Session.spawn_client = real_spawn
check("o sesiune nouă porneşte armată (re-adoptată după restart putea fi lăsată în istoric)",
      fresh.copy_armed is True and fresh.copy_armed_at == 0.0 and fresh.copy_checked_at == 0.0)


# write_input: poarta e doar pentru tmux, iar o tastă înghiţită nu ajunge în coadă
def agent_with(s):
    ag = object.__new__(ptyd.Agent)
    ag.sessions = {s.sid: s}
    ag.flushed = []
    ag._flush_input = lambda sess: ag.flushed.append(bytes(sess.pending_input))
    return ag


real_exit = ptyd.tmux_copy_mode_exit
try:
    fake = Exit(True)
    ptyd.tmux_copy_mode_exit = fake
    s = FakeSession(armed=True)
    ag = agent_with(s)
    ptyd.Agent.write_input(ag, s.sid, b"\x1b")
    check("write_input: Esc care doar a închis istoricul nu intră în coada PTY-ului",
          s.pending_input == b"" and ag.flushed == [] and fake.calls == [s.sid], (s.pending_input, ag.flushed))
    ptyd.Agent.write_input(ag, s.sid, b"ls")
    check("write_input: tastele următoare ajung în coadă", s.pending_input == b"ls" and ag.flushed == [b"ls"])
    fake = Exit(True)
    ptyd.tmux_copy_mode_exit = fake
    s = FakeSession(armed=True)
    s.backend = "pty"
    ag = agent_with(s)
    ptyd.Agent.write_input(ag, s.sid, b"\x1b")
    check("write_input pe backend pty: fără poartă (nu există copy-mode), Esc pleacă",
          s.pending_input == b"\x1b" and fake.calls == [])
finally:
    ptyd.tmux_copy_mode_exit = real_exit


# ═════════════════════════ 3. tmux_copy_mode_exit, cu tmux mockuit ═════════════════════════
class R:
    def __init__(self, rc=0, out=b""):
        self.returncode, self.stdout, self.stderr = rc, out, b""


class FakeTmux:
    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, *args, **kw):
        self.calls.append((args, kw))
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def exit_with(fake, has_x=True):
    saved = (ptyd.tmux_cmd, ptyd._TMUX_HAS_COPY_X)
    ptyd.tmux_cmd, ptyd._TMUX_HAS_COPY_X = fake, has_x
    try:
        return ptyd.tmux_copy_mode_exit("abc123")
    finally:
        ptyd.tmux_cmd, ptyd._TMUX_HAS_COPY_X = saved


f = FakeTmux(R(0, b"0\n"))
check("pane_in_mode=0 → False, fără a doua comandă", exit_with(f) is False and len(f.calls) == 1, f.calls)
check("întrebarea ţinteşte sesiunea ca `wt-<sid>:` (pane-ul activ), cu timeout scurt",
      f.calls[0][0] == ("display-message", "-p", "-t", "wt-abc123:", "#{pane_in_mode}")
      and f.calls[0][1].get("timeout") == ptyd.COPY_MODE_TIMEOUT, f.calls)
f = FakeTmux(R(0, b"1\n"), R(0))
check("pane_in_mode=1 → `send-keys -X cancel` pe aceeaşi ţintă → True",
      exit_with(f) is True and f.calls[1][0] == ("send-keys", "-t", "wt-abc123:", "-X", "cancel"), f.calls)
f = FakeTmux(R(0, b"1\n"), R(0))
check("tmux < 2.4 (fără `-X cancel`): None şi tmux NEATINS — niciun `q` trimis pe ghicite",
      exit_with(f, has_x=False) is None and f.calls == [], f.calls)
f = FakeTmux(R(0, b"2\n"), R(0))
check("moduri imbricate (pane_in_mode=2) → tot ieşim", exit_with(f) is True)
f = FakeTmux(R(1, b""))
check("display-message eşuat (fără server / sesiune) → None, fără cancel", exit_with(f) is None and len(f.calls) == 1)
f = FakeTmux(R(0, b""))
check("ieşire goală → False (nu trimitem cancel orbeşte)", exit_with(f) is False and len(f.calls) == 1)
f = FakeTmux(R(0, b"1\n"), R(1))
check("cancel refuzat (alt mod decât copy-mode, sau a ieşit singur între timp) → None", exit_with(f) is None)
check("…şi la ieşire nu se trimite NICIODATĂ o tastă literală, doar `-X cancel`",
      all(c[0][0] != "send-keys" or "-X" in c[0] for c in f.calls), f.calls)
f = FakeTmux(subprocess.TimeoutExpired("tmux", 2))
check("tmux înţepenit (timeout) → None, nu excepţie", exit_with(f) is None)
f = FakeTmux(R(0, b"1\n"), OSError("gone"))
check("OSError la cancel → None, nu excepţie", exit_with(f) is None)


# ═════════════════════════ 4. op-ul scroll_exit prin handle_ctrl ═════════════════════════
def op(msg, session=None, result=True):
    ag = object.__new__(ptyd.Agent)
    ag.replies = []
    ag.send_ctrl = ag.replies.append
    ag._hb_sent_at = {}
    ag.sessions = {session.sid: session} if session else {}
    fake = Exit(result)
    real = ptyd.tmux_copy_mode_exit
    ptyd.tmux_copy_mode_exit = fake
    try:
        ptyd.Agent.handle_ctrl(ag, dict(msg, id=7))
    finally:
        ptyd.tmux_copy_mode_exit = real
    return (ag.replies[0] if ag.replies else {}), fake.calls


s = FakeSession()
r, calls = op({"op": "scroll_exit", "sid": s.sid}, s, True)
check("op scroll_exit: pane în istoric → ok, was=True", r == {"ok": True, "id": 7, "was": True} and calls == [s.sid], r)
r, calls = op({"op": "scroll_exit", "sid": s.sid}, s, False)
check("op scroll_exit: nu era în istoric → ok, was=False", r.get("ok") is True and r.get("was") is False, r)
r, calls = op({"op": "scroll_exit", "sid": s.sid}, s, None)
check("op scroll_exit: tmux n-a răspuns → ok, was=False (UI-ul cade pe dialog)", r.get("ok") is True and r.get("was") is False, r)
r, calls = op({"op": "scroll_exit", "sid": "nu-exista"}, s)
check("op scroll_exit: sesiune necunoscută → no_session", r.get("code") == "no_session" and calls == [], r)
r, calls = op({"op": "scroll_exit", "sid": ["x"]}, s)
check("op scroll_exit: sid de alt tip → no_session, nu crash", r.get("code") == "no_session", r)
r, calls = op({"op": "scroll_exit"}, s)
check("op scroll_exit: fără sid → no_session", r.get("code") == "no_session", r)
p = FakeSession()
p.backend = "pty"
r, calls = op({"op": "scroll_exit", "sid": p.sid}, p)
check("op scroll_exit pe backend pty: was=False, tmux neatins", r.get("was") is False and calls == [], (r, calls))
d = FakeSession()
d.alive = False
r, calls = op({"op": "scroll_exit", "sid": d.sid}, d)
check("op scroll_exit pe sesiune încheiată: was=False, tmux neatins", r.get("was") is False and calls == [], (r, calls))


# ═════════════════════════ 5. tmux REAL, pe un socket izolat ═════════════════════════
TMUX = shutil.which("tmux")
if not TMUX:
    print("  SKIP tmux real: binarul lipseşte (CI hermetic)")
else:
    sock = "wt59test-%d" % os.getpid()
    saved = (ptyd.TMUX_SOCKET, ptyd.TMUX_CONF)
    ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = sock, os.devnull
    sid = uuid.uuid4().hex
    name = ptyd.TMUX_SESSION_PREFIX + sid
    sock_path = os.path.join(os.environ["TMUX_TMPDIR"], "tmux-%d" % os.getuid(), sock)

    def in_mode():
        return ptyd.tmux_cmd("display-message", "-p", "-t", name + ":", "#{pane_in_mode}").stdout.strip()

    def wait_for(fn, secs=5.0):
        end = time.time() + secs
        while time.time() < end:
            if fn():
                return True
            time.sleep(0.05)
        return False

    started = False
    try:
        try:
            started = ptyd.tmux_cmd("new-session", "-d", "-s", name, "-x", "100", "-y", "20", "sh",
                                    timeout=20).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            started = False
        if not started or not ptyd._TMUX_HAS_COPY_X:
            raise RuntimeError("skip")
        check("tmux real: serverul de test e pe socketul IZOLAT (nu pe cel de producţie)",
              os.path.exists(sock_path), sock_path)
        wait_for(lambda: in_mode() == b"0")
        check("tmux real: la prompt → False, pane-ul neatins", ptyd.tmux_copy_mode_exit(sid) is False and in_mode() == b"0")
        ptyd.tmux_cmd("send-keys", "-t", name + ":", "for i in $(seq 1 80); do echo L$i; done", "Enter")
        time.sleep(0.4)
        ptyd.tmux_cmd("copy-mode", "-e", "-t", name + ":")
        check("tmux real: pane-ul e în copy-mode (ce face rotiţa)", wait_for(lambda: in_mode() == b"1"), in_mode())
        check("tmux real: din istoric → True şi pane-ul e iar la prompt",
              ptyd.tmux_copy_mode_exit(sid) is True and wait_for(lambda: in_mode() == b"0"), in_mode())
        check("tmux real: a doua oară → False (idempotent)", ptyd.tmux_copy_mode_exit(sid) is False)
        check("tmux real: sesiune inexistentă → niciodată True", ptyd.tmux_copy_mode_exit(uuid.uuid4().hex) is not True)
    except RuntimeError:
        print("  SKIP tmux real: serverul de test n-a pornit la timp sau tmux < 2.4")
    finally:
        if started:
            ptyd.tmux_cmd("kill-session", "-t", name)    # NICIODATĂ kill-server: doar sesiunea noastră
        ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = saved


# ═════════════════════════ 5b. quoting-ul din tmux.conf (word-separators pe tmux < 3.0) ═════════════════════════
q = ptyd._tmux_q
check("quoting: fără apostrofă → între apostrofe, literal (neschimbat faţă de v58)",
      q("/bin/bash") == "'/bin/bash'" and q(",*:Ms=\\E]52;%p1%s;%p2%s\\007") == "',*:Ms=\\E]52;%p1%s;%p2%s\\007'")
check("quoting: cu apostrofă → între ghilimele (nu `'\\''`, respins de tmux < 3.0)",
      q(" ()[]{},\"'`") == '" ()[]{},\\"\'`"', q(" ()[]{},\"'`"))
check("quoting: între ghilimele `\\`, `\"` şi `$` sunt escapate", q("a'\\b\"c$d") == '"a\'\\\\b\\"c\\$d"', q("a'\\b\"c$d"))
check("quoting: un sfârşit de rând nu poate începe o linie nouă de config", "\n" not in q("a\nset -g x y") and "\n" not in q("a'\r\nb"))
conf_lines = ptyd.TMUX_CONF_CONTENT.splitlines()
ws = [ln for ln in conf_lines if ln.startswith("set -g word-separators ")]
check("conf: linia word-separators e în forma acceptată de orice tmux",
      ws == ['set -g word-separators " ()[]{},\\"\'`"'], ws)
check("conf: nicio linie nu mai foloseşte idiomul `'\\''`", "'\\''" not in ptyd.TMUX_CONF_CONTENT)
check("conf: celelalte opţiuni au rămas între apostrofe (byte-identice cu v58)",
      "set -g history-limit '50000'" in conf_lines and "set -g escape-time '0'" in conf_lines
      and any(ln.startswith("set -g default-shell '") for ln in conf_lines), conf_lines)
if TMUX:
    sock = "wt59conf-%d" % os.getpid()
    conf_path = os.path.join(os.environ["HOME"], "wt59.conf")
    with open(conf_path, "w") as fh:
        fh.write(ptyd.TMUX_CONF_CONTENT)
    saved = (ptyd.TMUX_SOCKET, ptyd.TMUX_CONF)
    ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = sock, os.devnull
    started = False
    try:
        try:
            started = ptyd.tmux_cmd("new-session", "-d", "-s", "wt59conf", "sh", timeout=20).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            started = False
        if started:
            r = ptyd.tmux_cmd("source-file", conf_path)
            said = (r.stdout + r.stderr).decode("utf-8", "replace")
            check("tmux real: TOT tmux.conf-ul agentului se încarcă fără nicio eroare", r.returncode == 0 and not said.strip(), said[:300])
            got = ptyd.tmux_cmd("show-options", "-gv", "word-separators").stdout.decode("utf-8", "replace").rstrip("\n")
            check("tmux real: word-separators are exact valoarea cerută", got == " ()[]{},\"'`", got)
        else:
            print("  SKIP tmux real (conf): serverul de test n-a pornit la timp")
    finally:
        if started:
            ptyd.tmux_cmd("kill-session", "-t", "wt59conf")    # doar sesiunea noastră, pe socketul izolat
        ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = saved


# ═════════════════════════ 6. gateway: versiune, porţi, eşecuri ═════════════════════════
from app import core  # noqa: E402


class HConn(core.AgentConnection):
    def __init__(self, version, reply, backend="tmux"):
        self.host_id, self.agent_version, self.backend = 1, version, backend
        self.reply, self.sent = reply, []

    async def request(self, op, timeout=20.0, **fields):
        self.sent.append(dict(fields, op=op))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


class Client:
    def __init__(self, writable=True, locked=False, owner=True):
        self.writable, self.locked, self.is_owner, self.last_interaction = writable, locked, owner, 0.0


def hub_with(source):
    h = object.__new__(core.SessionHub)
    h.sid = uuid.uuid4().hex
    h.closed = False
    h.locked = False
    h.last_interaction = 0.0
    h._last_scroll_exit = 0.0
    h._source = lambda: source
    return h


async def gw():
    sid = uuid.uuid4().hex
    check("gateway: pragul op-ului e agentul 59", core.SCROLL_EXIT_MIN_AGENT == 59)
    c = HConn(59, {"ok": True, "was": True})
    check("gateway + agent 59: cere scroll_exit, was=True", await c.scroll_exit(sid) is True
          and c.sent == [{"sid": sid, "op": "scroll_exit"}], c.sent)
    c = HConn(59, {"ok": True, "was": False})
    check("gateway + agent 59: was=False → False", await c.scroll_exit(sid) is False)
    c = HConn(58, {"ok": True, "was": True})
    check("gateway + agent 58: op-ul NU se trimite (ar răspunde bad_op) → False",
          await c.scroll_exit(sid) is False and c.sent == [], c.sent)
    c = HConn(None, {"ok": True, "was": True})
    check("gateway + versiune necunoscută: nu se trimite", await c.scroll_exit(sid) is False and c.sent == [])
    c = HConn(59, {"ok": True, "was": True}, backend="pty")
    check("gateway + agent pe backend pty: nu se trimite", await c.scroll_exit(sid) is False and c.sent == [])
    c = HConn(59, {"ok": False, "code": "no_session", "was": True})
    check("gateway: răspuns ok=False → False, orice ar scrie în `was`", await c.scroll_exit(sid) is False)
    c = HConn(59, {"ok": True, "was": "yes"})
    check("gateway: `was` care nu e exact True → False", await c.scroll_exit(sid) is False)
    check("gateway: o sursă fără tmux (ssh / telnet) răspunde False",
          await core.SessionSource().scroll_exit(sid) is False)

    c = HConn(59, {"ok": True, "was": True})
    h = hub_with(c)
    cl = Client()
    check("hub: client care poate scrie → cere agentului, True", await h.scroll_exit(cl) is True and len(c.sent) == 1)
    check("hub: gestul contează ca activitate a operatorului (idle-lock)", cl.last_interaction > 0 and h.last_interaction > 0)
    check("hub: a doua cerere imediat după → refuzată de ritm (False), agentul neatins",
          await h.scroll_exit(cl) is False and len(c.sent) == 1, c.sent)
    h._last_scroll_exit = 0.0
    check("hub: client READ-ONLY → False, agentul neatins",
          await h.scroll_exit(Client(writable=False)) is False and len(c.sent) == 1)
    check("hub: client blocat (invitat fără owner) → False", await h.scroll_exit(Client(locked=True)) is False and len(c.sent) == 1)
    h.locked = True
    check("hub BLOCAT (idle-lock 2FA) → False, agentul neatins", await h.scroll_exit(Client()) is False and len(c.sent) == 1)
    h.locked = False
    h.closed = True
    check("hub închis → False", await h.scroll_exit(Client()) is False and len(c.sent) == 1)
    h.closed = False
    g = Client(owner=False)
    h.last_interaction = 0.0
    await h.scroll_exit(g)
    check("hub: un invitat writable NU ţine treaz idle-lock-ul owner-ului", g.last_interaction > 0 and h.last_interaction == 0.0)
    h = hub_with(HConn(59, core.AgentGone()))
    check("hub: agent plecat → False, nu excepţie", await h.scroll_exit(Client()) is False)
    h = hub_with(HConn(59, asyncio.TimeoutError()))
    check("hub: timeout la agent → False, nu excepţie", await h.scroll_exit(Client()) is False)
    h = hub_with(None)
    check("hub fără sursă (host offline) → False", await h.scroll_exit(Client()) is False)


asyncio.run(gw())
shutil.rmtree(os.environ["TMUX_TMPDIR"], ignore_errors=True)
print("\n%d/%d checks passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
