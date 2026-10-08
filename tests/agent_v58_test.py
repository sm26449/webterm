"""Agent v58 — `fs_chmod` (modul la copierea host → host) + istoricul tmux pe pane-uri multiple.

De ce:
  1. Copierea pe server a folderelor (gateway/app/fscopy.py) scrie fişierele prin maşinăria de
     upload, deci pe destinaţie aterizau 0644: un `deploy.sh` ne-executabil, o cheie 0600 citibilă
     de alţii. v58 adaugă op-ul `fs_chmod` (biţii 0o777, fără symlink-uri, pe fd) şi `mode` în
     `fs_stat`.
  2. „tmux multi-pane history": până la v57 op-ul `history` refuza orice fereastră cu >1 pane
     (`multi_pane`) → un split în tmux lăsa browserul aproape fără scrollback. v58: pane zoom-at =
     un singur pane vizibil → captura lui; pane-uri vizibile → captura pane-ului ACTIV, doar dacă
     gateway-ul o cere (`pane: "active"`) şi o marchează; captura ţinteşte pane-ul sondat după id.

Acoperă:
  · _fs_chmod pe un FS real (tmpdir): mascare 0o7777 → 0o777 (setuid/setgid/sticky NU ajung pe
    disc), director, symlink refuzat (ţinta neatinsă), FIFO refuzat, inexistent, calea O_RDONLY
    (fără O_PATH), inode schimbat între lstat şi open;
  · op-ul `fs_chmod` prin handle_ctrl: validarea (tipuri, interval, NUL), reply-ul;
  · `fs_stat` raportează `mode`;
  · tmux_history cu tmux MOCKUIT: probe în 4 câmpuri, multi_pane fără `pane`, pane activ cu
    `pane`, zoom fără `pane`, ţinta = id-ul pane-ului, pane_id invalid → capture_failed;
  · op-ul `history`: `pane` invalid → bad_request;
  · tmux REAL pe un socket IZOLAT (-L propriu + TMUX_TMPDIR temporar; doar kill-session, niciodată
    kill-server) — sărit dacă tmux lipseşte;
  · gateway: `pane="active"` trimis, îmbinarea „history of the active pane (N panes)", zoom →
    îmbinarea obişnuită, agent 57 (`multi_pane`) → fallback tăcut.
"""
import asyncio
import base64
import errno
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zlib

os.environ["HOME"] = tempfile.mkdtemp(prefix="v58-home-")
os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp(prefix="v58-data-")
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
# tmux-ul de test NU are voie să atingă serverul de producţie: socket propriu, în alt director
os.environ["TMUX_TMPDIR"] = tempfile.mkdtemp(prefix="v58-tmux-")
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


check("AGENT_VERSION == 58", ptyd.AGENT_VERSION == 58, ptyd.AGENT_VERSION)


def mode_of(p):
    return stat.S_IMODE(os.lstat(p).st_mode)


# ═════════════════════════ 1. _fs_chmod pe un FS real ═════════════════════════
T = tempfile.mkdtemp(prefix="v58-fs-")
f1 = os.path.join(T, "deploy.sh")
open(f1, "w").write("#!/bin/sh\n")
os.chmod(f1, 0o644)
got = ptyd._fs_chmod(f1, 0o755)
check("chmod 0755 pe un fişier → aplicat şi raportat", mode_of(f1) == 0o755 and got == 0o755, oct(mode_of(f1)))
got = ptyd._fs_chmod(f1, 0o4755)
check("setuid cerut (04755) → TĂIAT: pe disc 0755, fără S_ISUID", mode_of(f1) == 0o755
      and not os.lstat(f1).st_mode & stat.S_ISUID and got == 0o755, oct(os.lstat(f1).st_mode))
ptyd._fs_chmod(f1, 0o7777)
check("07777 → 0777 (setuid/setgid/sticky niciodată)", mode_of(f1) == 0o777, oct(mode_of(f1)))
ptyd._fs_chmod(f1, 0o600)
check("0600 (cheie privată) aplicat", mode_of(f1) == 0o600)
ptyd._fs_chmod(f1, 0o000)
check("0000 aplicat (O_PATH nu cere drept de citire)", mode_of(f1) == 0o000)
ptyd._fs_chmod(f1, 0o644)
d1 = os.path.join(T, "dir")
os.mkdir(d1, 0o755)
ptyd._fs_chmod(d1, 0o700)
check("director: 0700 aplicat", mode_of(d1) == 0o700)
os.chmod(d1, 0o755)

target = os.path.join(T, "target")
open(target, "w").write("x")
os.chmod(target, 0o600)
ln = os.path.join(T, "ln")
os.symlink(target, ln)
try:
    ptyd._fs_chmod(ln, 0o777)
    check("symlink → refuzat (ELOOP)", False, "no error")
except OSError as e:
    check("symlink → refuzat (ELOOP)", e.errno == errno.ELOOP, e)
check("…iar ŢINTA link-ului e neatinsă (0600)", mode_of(target) == 0o600, oct(mode_of(target)))
ln_dir = os.path.join(T, "ln_dir")
os.symlink(d1, ln_dir)
try:
    ptyd._fs_chmod(ln_dir, 0o777)
    check("symlink spre director → refuzat", False)
except OSError:
    check("symlink spre director → refuzat", mode_of(d1) == 0o755)
fifo = os.path.join(T, "fifo")
os.mkfifo(fifo, 0o644)
try:
    ptyd._fs_chmod(fifo, 0o600)
    check("FIFO → refuzat (EINVAL), fără blocare", False)
except OSError as e:
    check("FIFO → refuzat (EINVAL), fără blocare", e.errno == errno.EINVAL and mode_of(fifo) == 0o644, e)
try:
    ptyd._fs_chmod(os.path.join(T, "nope"), 0o644)
    check("inexistent → FileNotFoundError", False)
except FileNotFoundError:
    check("inexistent → FileNotFoundError", True)

# calea fără O_PATH (non-Linux / fără /proc): O_RDONLY|O_NOFOLLOW + fchmod
saved_opath = getattr(os, "O_PATH", None)
if saved_opath is not None:
    del os.O_PATH
try:
    ptyd._fs_chmod(f1, 0o750)
    check("fără O_PATH: fchmod pe fd O_RDONLY", mode_of(f1) == 0o750, oct(mode_of(f1)))
    try:
        ptyd._fs_chmod(ln, 0o777)
        check("fără O_PATH: symlink tot refuzat", False)
    except OSError:
        check("fără O_PATH: symlink tot refuzat", mode_of(target) == 0o600)
finally:
    if saved_opath is not None:
        os.O_PATH = saved_opath

# înlocuire între lstat şi open: lstat vede un inode, open altul → refuzat, nimic schimbat
other = os.path.join(T, "other")
open(other, "w").write("o")
os.chmod(other, 0o644)
real_lstat = os.lstat
fake_ino = real_lstat(other)


def swapped_lstat(p, *a, **kw):
    return fake_ino if p == f1 else real_lstat(p, *a, **kw)


os.chmod(f1, 0o644)
ptyd.os.lstat = swapped_lstat
try:
    try:
        ptyd._fs_chmod(f1, 0o700)
        check("inode schimbat între lstat şi open → refuzat", False)
    except OSError as e:
        check("inode schimbat între lstat şi open → refuzat", "changed" in str(e) and mode_of(f1) == 0o644, e)
finally:
    ptyd.os.lstat = real_lstat


# ═════════════════════════ 2. op-urile fs_chmod / fs_stat prin handle_ctrl ═════════════════════════
def bare_agent():
    ag = object.__new__(ptyd.Agent)
    ag.replies = []
    ag.send_ctrl = ag.replies.append
    ag._hb_sent_at = {}
    ag.sessions = {}
    return ag


def op(msg):
    ag = bare_agent()
    ptyd.Agent.handle_ctrl(ag, dict(msg, id=7))
    return ag.replies[0] if ag.replies else {}


r = op({"op": "fs_chmod", "path": f1, "mode": 0o755})
check("op fs_chmod: ok + path + mode aplicat", r.get("ok") is True and r.get("mode") == 0o755
      and r.get("path") == f1 and mode_of(f1) == 0o755, r)
r = op({"op": "fs_chmod", "path": f1, "mode": 0o2775})
check("op fs_chmod: setgid cerut → 0775 pe disc", r.get("ok") is True and mode_of(f1) == 0o775, (r, oct(mode_of(f1))))
for bad in (True, "0755", -1, 0o10000, 1.5, None):
    r = op({"op": "fs_chmod", "path": f1, "mode": bad})
    check("op fs_chmod: mode=%r → bad_request" % (bad,), r.get("code") == "bad_request", r)
for bad in (None, "", 7, "a\x00b"):
    r = op({"op": "fs_chmod", "path": bad, "mode": 0o644})
    check("op fs_chmod: path=%r → bad_request" % (bad,), r.get("code") == "bad_request", r)
r = op({"op": "fs_chmod", "path": ln, "mode": 0o777})
check("op fs_chmod: symlink → fs_error, ţinta neatinsă", r.get("ok") is False and r.get("code") == "fs_error"
      and mode_of(target) == 0o600, r)
r = op({"op": "fs_chmod", "path": os.path.join(T, "nope"), "mode": 0o644})
check("op fs_chmod: inexistent → fs_error", r.get("code") == "fs_error", r)
os.chmod(f1, 0o751)
r = op({"op": "fs_stat", "path": f1})
check("op fs_stat: raportează mode (0o777)", r.get("ok") is True and r.get("mode") == 0o751, r)
r = op({"op": "fs_stat", "path": ln})
check("op fs_stat pe symlink: link=True, mode-ul LINK-ului (lstat)", r.get("link") is True
      and r.get("mode") == 0o777, r)

# ═════════════════════════ 3. tmux_history cu tmux mockuit (pane-uri multiple) ═════════════════════════
HSID = "a" * 32
check("probe: 4 câmpuri → (hsize, panes, pane_id, zoomed)",
      ptyd.parse_history_probe(b"500 3 %12 1\n") == (500, 3, "%12", True))
for bad in (b"500 1", b"500 1 12 0", b"500 1 %1x 0", b"500 1 %1 2", b"500 1 %1 0 x", b"a 1 %1 0", b""):
    check("probe ciudat %r → None" % bad, ptyd.parse_history_probe(bad) is None)
check("probe-ul cere history_size, window_panes, pane_id, window_zoomed_flag",
      all(x in ptyd.HISTORY_PROBE_FMT for x in ("#{history_size}", "#{window_panes}", "#{pane_id}",
                                                  "#{window_zoomed_flag}")))
check("argv: cu pane → ţinta e id-ul pane-ului (nu `sesiune:`)",
      ptyd.history_capture_argv(HSID, 10, "%4")[5] == "%4"
      and ptyd.history_capture_argv(HSID, 10)[5] == ptyd.TMUX_SESSION_PREFIX + HSID + ":")


class FakeTmux:
    def __init__(self, probe, data=b"L1\nL2\n"):
        self.calls, self.probe, self.data = [], probe, data

    def __call__(self, *args, **kw):
        self.calls.append(list(args))
        if args[0] == "display-message":
            return subprocess.CompletedProcess(args, 0, self.probe, b"")
        return subprocess.CompletedProcess(args, 0, self.data, b"")


def with_tmux(fake, fn):
    saved = ptyd.tmux_cmd
    ptyd.tmux_cmd = fake
    try:
        return fn()
    finally:
        ptyd.tmux_cmd = saved


ft = FakeTmux(b"500 2 %7 0")
res = with_tmux(ft, lambda: ptyd.tmux_history(HSID, 3000))
check("2 pane-uri, fără `pane` (gateway vechi) → multi_pane, ca în v57, fără captură",
      res.get("error") == "multi_pane" and len(ft.calls) == 1, (res, ft.calls))
ft = FakeTmux(b"500 2 %7 0")
res = with_tmux(ft, lambda: ptyd.tmux_history(HSID, 3000, True))
check("2 pane-uri + `pane=active` → captura pane-ului activ, ţinta %7, -S plafonat la 500",
      res.get("z") and ft.calls[1] == ptyd.history_capture_argv(HSID, 500, "%7"), (res, ft.calls))
check("…răspunsul spune câte pane-uri şi că nu e zoom",
      res.get("panes") == 2 and res.get("zoomed") is False
      and zlib.decompress(base64.b64decode(res["z"])) == b"L1\nL2\n", res)
ft = FakeTmux(b"800 3 %2 1")
res = with_tmux(ft, lambda: ptyd.tmux_history(HSID, 100))
check("pane zoom-at, fără `pane` → captura (un singur pane vizibil)",
      res.get("z") is not None and res.get("zoomed") is True and res.get("panes") == 3
      and ft.calls[1] == ptyd.history_capture_argv(HSID, 100, "%2"), (res, ft.calls))
ft = FakeTmux(b"800 1 %0 0")
res = with_tmux(ft, lambda: ptyd.tmux_history(HSID, 100))
check("un singur pane: neschimbat (panes=1), ţinta = pane-ul sondat",
      res.get("panes") == 1 and ft.calls[1][5] == "%0", (res, ft.calls))
res = with_tmux(FakeTmux(b"800 1 ;rm 0"), lambda: ptyd.tmux_history(HSID, 100))
check("pane_id invalid în probe → capture_failed (nu ajunge ca ţintă tmux)",
      res.get("error") == "capture_failed", res)

ag = bare_agent()
ag.sessions = {HSID: type("S", (), {"backend": "tmux"})()}
ptyd.Agent.handle_ctrl(ag, {"op": "history", "id": 9, "sid": HSID, "lines": 10, "pane": "all"})
check("op history: pane=\"all\" → bad_request", ag.replies and ag.replies[0].get("code") == "bad_request", ag.replies)
ag = bare_agent()
ag.sessions = {HSID: type("S", (), {"backend": "tmux"})()}
ft = FakeTmux(b"40 2 %3 0")
saved_cmd = ptyd.tmux_cmd
ptyd.tmux_cmd = ft
try:
    ptyd.Agent.handle_ctrl(ag, {"op": "history", "id": 10, "sid": HSID, "lines": 10, "pane": "active"})
    end = time.time() + 5
    while not ag.replies and time.time() < end:
        time.sleep(0.01)
finally:
    ptyd.tmux_cmd = saved_cmd
r = ag.replies[0] if ag.replies else {}
check("op history: pane=\"active\" ajunge la worker → ok, panes=2", r.get("ok") is True and r.get("id") == 10
      and r.get("panes") == 2, r)

# ═════════════════════════ 4. tmux REAL, socket izolat ═════════════════════════
TMUX = shutil.which("tmux")
if not TMUX:
    print("  SKIP tmux real: binarul lipseşte (CI hermetic)")
else:
    sock = "wt58test-%d" % os.getpid()
    saved = (ptyd.TMUX_SOCKET, ptyd.TMUX_CONF)
    ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = sock, os.devnull
    sid = uuid.uuid4().hex
    name = ptyd.TMUX_SESSION_PREFIX + sid
    sock_path = os.path.join(os.environ["TMUX_TMPDIR"], "tmux-%d" % os.getuid(), sock)

    def wait_for(fn, secs=5.0):
        end = time.time() + secs
        while time.time() < end:
            if fn():
                return True
            time.sleep(0.05)
        return False

    def pane_text(target):
        return ptyd.tmux_cmd("capture-pane", "-p", "-t", target, "-S", "-", "-E", "-").stdout

    try:
        ptyd.tmux_cmd("new-session", "-d", "-s", name, "-x", "100", "-y", "20", "sh")
        check("tmux real: serverul de test e pe socketul IZOLAT (nu pe cel de producţie)",
              os.path.exists(sock_path), sock_path)
        ptyd.tmux_cmd("send-keys", "-t", name + ":", "for i in $(seq 1 120); do echo LEFT$i; done", "Enter")
        wait_for(lambda: b"LEFT120" in pane_text(name + ":"))
        res = ptyd.tmux_history(sid, 1000)
        raw = zlib.decompress(base64.b64decode(res.get("z", ""))) if res.get("z") else b""
        check("tmux real, 1 pane: istoricul conţine rândurile derulate", b"LEFT10\n" in raw and res.get("panes") == 1,
              res if not raw else raw[:80])
        ptyd.tmux_cmd("split-window", "-h", "-t", name + ":", "sh")
        ptyd.tmux_cmd("send-keys", "-t", name + ":", "for i in $(seq 1 90); do echo RIGHT$i; done", "Enter")
        wait_for(lambda: b"RIGHT90" in pane_text(name + ":"))
        res = ptyd.tmux_history(sid, 1000)
        check("tmux real, 2 pane-uri fără `pane` → multi_pane (comportamentul v57)",
              res.get("error") == "multi_pane", res)
        res = ptyd.tmux_history(sid, 1000, True)
        raw = zlib.decompress(base64.b64decode(res.get("z", ""))) if res.get("z") else b""
        check("tmux real, 2 pane-uri + pane=active → istoricul pane-ului ACTIV (dreapta), nu al celuilalt",
              b"RIGHT5\n" in raw and b"LEFT" not in raw and res.get("panes") == 2, raw[:120])
        ptyd.tmux_cmd("select-pane", "-t", name + ":.0")
        res = ptyd.tmux_history(sid, 1000, True)
        raw = zlib.decompress(base64.b64decode(res.get("z", ""))) if res.get("z") else b""
        check("tmux real: după select-pane, istoricul pane-ului stâng", b"LEFT5\n" in raw and b"RIGHT" not in raw,
              raw[:120])
        ptyd.tmux_cmd("resize-pane", "-Z", "-t", name + ":.0")
        res = ptyd.tmux_history(sid, 1000)
        check("tmux real: pane zoom-at, fără `pane` → captura (zoomed=True)",
              res.get("zoomed") is True and res.get("z") and res.get("panes") == 2, res)
    finally:
        ptyd.tmux_cmd("kill-session", "-t", name)    # NICIODATĂ kill-server: doar sesiunea noastră
        ptyd.TMUX_SOCKET, ptyd.TMUX_CONF = saved


# ═════════════════════════ 5. gateway: pane="active", îmbinarea, fallback ═════════════════════════
from app import core  # noqa: E402


class HConn(core.AgentConnection):
    def __init__(self, version, reply):
        self.host_id, self.agent_version, self.backend = 1, version, "tmux"
        self.reply, self.sent = reply, []

    async def request(self, op, timeout=20.0, **fields):
        self.sent.append(dict(fields, op=op))
        return self.reply


def reply(data, **kw):
    return dict({"ok": True, "z": base64.b64encode(zlib.compress(data)).decode(), "n": len(data),
                 "lines": data.count(b"\n"), "truncated": False}, **kw)


async def gw():
    sid = uuid.uuid4().hex
    c = HConn(58, reply(b"one\ntwo\n", panes=2, zoomed=False))
    raw = await core.fetch_tmux_history(c, sid, 500)
    check("gateway: cere history cu pane=\"active\"", c.sent == [{"sid": sid, "lines": 500, "pane": "active",
                                                                  "op": "history"}], c.sent)
    check("gateway: captura e bytes (apelanţii neschimbaţi) cu panes=2", raw == b"one\ntwo\n" and raw.panes == 2,
          (raw, getattr(raw, "panes", None)))
    blk = core.build_history_block(raw, 100, 10)
    check("gateway: îmbinarea spune „history of the active pane (2 panes)”",
          core.HISTORY_SEAM_PANE % 2 in blk and core.HISTORY_SEAM not in blk, blk[-200:])
    raw = await core.fetch_tmux_history(HConn(58, reply(b"z\n", panes=3, zoomed=True)), sid, 500)
    check("gateway: pane zoom-at → îmbinarea obişnuită", raw.panes == 1
          and core.HISTORY_SEAM in core.build_history_block(raw, 100, 10))
    raw = await core.fetch_tmux_history(HConn(58, reply(b"z\n")), sid, 500)
    check("gateway: fără `panes` (un pane) → îmbinarea obişnuită", raw.panes == 1
          and core.HISTORY_SEAM in core.build_history_block(raw, 100, 10))
    raw = await core.fetch_tmux_history(HConn(58, reply(b"z\n", panes=10 ** 6)), sid, 500)
    check("gateway: panes absurd (agent stricat) → ignorat", raw.panes == 1)
    raw = await core.fetch_tmux_history(HConn(57, {"ok": False, "code": "multi_pane"}), sid, 500)
    check("gateway + agent 57 cu pane-uri multiple → None (transcriptul, ca înainte)", raw is None)
    check("gateway: îmbinarea pe pane-uri e tot text + SGR (sanitizabilă)",
          b"\x1b[2J" not in core.HISTORY_SEAM_PANE and b"\n" not in core.HISTORY_SEAM_PANE)


asyncio.run(gw())
shutil.rmtree(T, ignore_errors=True)
shutil.rmtree(os.environ["TMUX_TMPDIR"], ignore_errors=True)
print("\n%d/%d checks passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
