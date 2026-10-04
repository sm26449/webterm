"""Agent v54 — remedierile auditului din 2026-10-04 (docs/audit-2026-10-04/agent-security.md).

Hermetic: fără gateway, fără pty real, fără socketul tmux de producţie. HOME e sandboxat ÎNAINTE
de import, iar op-urile se apelează direct pe un `Agent` construit cu `object.__new__` (fără
`__init__`, care ar scrie tmux.conf), cu `send_ctrl` înlocuit de o captură.

Acoperă: anti-rollback fail-closed (H parser), fs_read/fs_crc32 pe FD cu FIFO refuzat şi CRC pe
worker cu coadă mărginită, allowlist-ul serial, resolver-ul unic de shell (nologin), filtrul de
UID la _kill_tmux_procs, fwd_open fără DNS pe loop (+ IPv6 literal, timeout, anulare), self-heal-ul
KillMode=process şi plafonul de o colectare de diagnostic în zbor cu `force` rărit."""
import base64
import inspect
import os
import queue
import socket
import stat
import sys
import tempfile
import threading
import time
import zlib

os.environ["HOME"] = tempfile.mkdtemp(prefix="v54-home-")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import ptyd  # noqa: E402

os.makedirs(ptyd.WEBTERM_DIR, exist_ok=True)
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


class _Sel:
    def __init__(self):
        self.registered = {}

    def register(self, fd, events, data):
        self.registered[fd] = data

    def unregister(self, fd):
        self.registered.pop(fd, None)

    def modify(self, fd, events, data):
        pass


def fake_agent():
    """Agent fără __init__: doar starea de care au nevoie op-urile testate."""
    ag = object.__new__(ptyd.Agent)
    ag.replies = []
    ag.send_ctrl = ag.replies.append
    ag.sessions, ag.forwards, ag.serials = {}, {}, {}
    ag.sel = _Sel()
    ag.inbox = queue.Queue()
    ag._wake = lambda: None
    ag.connected = True
    ag.epoch = "deadbeef"
    ag._crc_q, ag._crc_lock, ag._crc_workers = queue.Queue(), threading.Lock(), 0
    ag._fwd_resolving = {}
    ag._diag_inflight, ag._diag_last, ag._last_diag_force = threading.Lock(), None, 0.0
    return ag


def wait_for(pred, t=5.0):
    dl = time.time() + t
    while time.time() < dl:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def by_id(ag, rid):
    return next((r for r in ag.replies if r.get("id") == rid), None)


tmp = tempfile.mkdtemp(prefix="v54-")

# ───────────────────────── versiune ─────────────────────────
check("AGENT_VERSION == 54", ptyd.AGENT_VERSION == 54, ptyd.AGENT_VERSION)

# ───────────────────────── 7. parserul anti-rollback ─────────────────────────
cv = ptyd._content_version
for src, want in [
    (b"AGENT_VERSION = 53\n", 53),
    (b"AGENT_VERSION = 53  # bumped\n", 53),
    (b"AGENT_VERSION=54\n", 54),
    (b"AGENT_VERSION = 55\r\n", 55),                          # CRLF
    (b"AGENT_VERSION_OLD = 1\nAGENT_VERSION = 7\n", 7),        # ancorat la nume exact
    (b"# AGENT_VERSION = 9\nAGENT_VERSION = 8\n", 8),          # comentariul nu e linia
    (b"AGENT_VERSION: int = 53\n", None),
    (b'AGENT_VERSION = int("53")\n', None),
    (b"x = 1\n", None),
    (b"\n" * 300 + b"AGENT_VERSION = 5\n", None),               # dincolo de primele 200 de linii
]:
    got = cv(src)
    check("_content_version(%r) == %r" % (src[:40], want), got == want, got)
with open(ptyd.__file__, "rb") as f:
    check("parserul citeşte versiunea din ptyd.py-ul real == AGENT_VERSION",
          cv(f.read()) == ptyd.AGENT_VERSION)
check("regex-ul e cel documentat pentru gateway",
      ptyd._VERSION_LINE.pattern == rb"^AGENT_VERSION\s*=\s*(\d+)\s*(?:#.*)?$", ptyd._VERSION_LINE.pattern)

# op-ul `update`: fail-closed pe versiune neparsabilă, downgrade refuzat (semnătura mock-uită OK;
# ne oprim ÎNAINTE de probe/instalare — ramurile de refuz nu ating discul)
_orig_verify = ptyd.ed25519_verify
ptyd.ed25519_verify = lambda *a: True
try:
    ag = fake_agent()
    ptyd.Agent.handle_ctrl(ag, {"op": "update", "id": "u1",
                                "content_b64": base64.b64encode(b"print(1)\n").decode(), "sig_b64": ""})
    r = by_id(ag, "u1")
    check("update fără AGENT_VERSION citibil → update_badversion (fail-closed)",
          r and r["ok"] is False and r["code"] == "update_badversion", r)
    ptyd.Agent.handle_ctrl(ag, {"op": "update", "id": "u2",
                                "content_b64": base64.b64encode(b"AGENT_VERSION = 1  # old\n").decode(),
                                "sig_b64": ""})
    r = by_id(ag, "u2")
    check("update cu versiune mai mică (cu comentariu pe linie) → update_downgrade",
          r and r["code"] == "update_downgrade", r)
finally:
    ptyd.ed25519_verify = _orig_verify

# ───────────────────────── 6. fs_read pe FD ─────────────────────────
reg = os.path.join(tmp, "reg.bin")
data = os.urandom(300 * 1024)
with open(reg, "wb") as f:
    f.write(data)
fifo = os.path.join(tmp, "fifo")
os.mkfifo(fifo)

ag = fake_agent()
ptyd.Agent.handle_ctrl(ag, {"op": "fs_read", "id": "f1", "path": reg, "offset": 0})
r = by_id(ag, "f1")
check("fs_read fişier obişnuit: primul chunk corect, eof=False",
      r and r["ok"] and base64.b64decode(r["data_b64"]) == data[:ptyd.FS_CHUNK]
      and r["eof"] is False and r["size"] == len(data), r and {k: r[k] for k in r if k != "data_b64"})
ptyd.Agent.handle_ctrl(ag, {"op": "fs_read", "id": "f2", "path": reg, "offset": ptyd.FS_CHUNK})
r = by_id(ag, "f2")
check("fs_read ultimul chunk: eof=True",
      r and r["ok"] and base64.b64decode(r["data_b64"]) == data[ptyd.FS_CHUNK:] and r["eof"] is True)
t0 = time.time()
ptyd.Agent.handle_ctrl(ag, {"op": "fs_read", "id": "f3", "path": fifo, "offset": 0})
dt = time.time() - t0
r = by_id(ag, "f3")
check("fs_read pe FIFO fără scriitor: refuzat IMEDIAT (nu blochează loop-ul)",
      r and r["ok"] is False and r["code"] == "fs_error" and "regular" in r["msg"] and dt < 1.0,
      "%r dt=%.2fs" % (r, dt))
ptyd.Agent.handle_ctrl(ag, {"op": "fs_read", "id": "f4", "path": "/dev/null", "offset": 0})
r = by_id(ag, "f4")
check("fs_read pe dispozitiv-caracter: refuzat", r and r["ok"] is False and "regular" in r["msg"], r)
ptyd.Agent.handle_ctrl(ag, {"op": "fs_read", "id": "f5", "path": tmp, "offset": 0})
r = by_id(ag, "f5")
check("fs_read pe director: refuzat", r and r["ok"] is False, r)
link = os.path.join(tmp, "link-to-reg")
os.symlink(reg, link)
ptyd.Agent.handle_ctrl(ag, {"op": "fs_read", "id": "f6", "path": link, "offset": 0})
r = by_id(ag, "f6")
check("fs_read prin symlink către fişier obişnuit: încă merge (semantica păstrată)",
      r and r["ok"] and r["size"] == len(data), r and r.get("code"))
link2 = os.path.join(tmp, "link-to-fifo")
os.symlink(fifo, link2)
ptyd.Agent.handle_ctrl(ag, {"op": "fs_read", "id": "f7", "path": link2, "offset": 0})
r = by_id(ag, "f7")
check("fs_read prin symlink către FIFO: refuzat", r and r["ok"] is False, r)
fd, st = ptyd._open_regular(reg)
import fcntl  # noqa: E402
check("_open_regular scoate O_NONBLOCK după verificare",
      not (fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK) and stat.S_ISREG(st.st_mode))
os.close(fd)

# ───────────────────────── 2. fs_crc32 pe worker ─────────────────────────
check("_fs_crc32 == zlib.crc32", ptyd._fs_crc32(reg) == (zlib.crc32(data) & 0xffffffff))
raised = None
try:
    ptyd._fs_crc32(fifo)
except OSError as e:
    raised = e
check("_fs_crc32 pe FIFO: OSError, nu blocaj", raised is not None, raised)

ag = fake_agent()
ptyd.Agent.handle_ctrl(ag, {"op": "fs_crc32", "id": "c1", "path": reg})
check("fs_crc32: handler-ul NU răspunde sincron (lucrul e pe worker)", by_id(ag, "c1") is None)
check("fs_crc32: reply de pe worker cu CRC-ul corect",
      wait_for(lambda: by_id(ag, "c1") is not None) and by_id(ag, "c1").get("crc32") == (zlib.crc32(data) & 0xffffffff),
      by_id(ag, "c1"))
ptyd.Agent.handle_ctrl(ag, {"op": "fs_crc32", "id": "c2", "path": fifo})
check("fs_crc32 pe FIFO: fs_error de pe worker",
      wait_for(lambda: by_id(ag, "c2") is not None) and by_id(ag, "c2")["code"] == "fs_error", by_id(ag, "c2"))
ptyd.Agent.handle_ctrl(ag, {"op": "fs_crc32", "id": "c3", "path": os.path.join(tmp, "nu-exista")})
check("fs_crc32 pe fişier lipsă: fs_error (ENOENT)",
      wait_for(lambda: by_id(ag, "c3") is not None) and by_id(ag, "c3")["code"] == "fs_error", by_id(ag, "c3"))
check("worker-ii de CRC se retrag când coada e goală",
      wait_for(lambda: ag._crc_workers == 0), ag._crc_workers)
# coada e mărginită: fără worker-i (CRC_WORKERS=0) cererile se adună, peste CRC_QUEUE_MAX → busy
_w, _q = ptyd.CRC_WORKERS, ptyd.CRC_QUEUE_MAX
ptyd.CRC_WORKERS, ptyd.CRC_QUEUE_MAX = 0, 2
try:
    ag = fake_agent()
    for i in range(3):
        ptyd.Agent.handle_ctrl(ag, {"op": "fs_crc32", "id": "q%d" % i, "path": reg})
    check("coada CRC mărginită: a 3-a cerere peste CRC_QUEUE_MAX=2 → busy",
          by_id(ag, "q0") is None and by_id(ag, "q1") is None
          and by_id(ag, "q2") and by_id(ag, "q2")["code"] == "busy", ag.replies)
    ptyd.CRC_WORKERS = 2
    ptyd.CRC_QUEUE_MAX = 64
    ptyd.Agent.handle_ctrl(ag, {"op": "fs_crc32", "id": "q3", "path": reg})
    check("un worker nou dren­ează TOATĂ coada (nicio cerere orfană)",
          wait_for(lambda: all(by_id(ag, "q%d" % i) for i in (0, 1, 3)))
          and all(by_id(ag, "q%d" % i)["ok"] for i in (0, 1, 3)), ag.replies)
    check("cel mult CRC_WORKERS thread-uri au fost pornite", ag._crc_workers <= 2 and wait_for(lambda: ag._crc_workers == 0))
finally:
    ptyd.CRC_WORKERS, ptyd.CRC_QUEUE_MAX = _w, _q

# ───────────────────────── 9. allowlist serial ─────────────────────────
sda = ptyd.serial_device_allowed
for dev in ("/dev/ttyUSB0", "/dev/ttyACM3", "/dev/ttyS0", "/dev/ttyAMA0", "/dev/ttyXRUSB1", "/dev/ttyUSB12"):
    check("serial acceptă %s" % dev, sda(dev, link_targets=set()) == dev, sda(dev, link_targets=set()))
for dev in ("/dev/pts/0", "/dev/tty1", "/dev/tty", "/dev/console", "/dev/null", "/dev/ttyUSB",
            "/dev/ttyUSB0x", "/etc/passwd", "/dev/../etc/passwd", "/dev/ttyUSB0/../tty1",
            "/dev/ttyUSB0\x00x", "", "dev/ttyUSB0", None, 5, "/dev/serial/by-id/", "/dev/serial/by-id/a/../../tty1"):
    check("serial refuză %r" % (dev,), sda(dev, link_targets=set()) is None, sda(dev, link_targets=set()))
check("serial: ţinta unui link by-id cu driver exotic e acceptată (UI-ul o listează)",
      sda("/dev/ttyMXUSB0", link_targets={"/dev/ttyMXUSB0"}) == "/dev/ttyMXUSB0")
check("serial: acelaşi nume exotic FĂRĂ link by-id → refuzat",
      sda("/dev/ttyMXUSB0", link_targets=set()) is None)
check("serial: link_targets nu poate strecura un pts", sda("/dev/pts/3", link_targets={"/dev/pts/3"}) is None)
_orig_realpath = ptyd.os.path.realpath
try:
    ptyd.os.path.realpath = lambda p: {"/dev/serial/by-id/usb-FTDI-if00-port0": "/dev/ttyUSB0",
                                       "/dev/serial/by-path/pci-0000:00:14.0-usb-0:1:1.0": "/dev/ttyACM0",
                                       "/dev/serial/by-id/evil": "/dev/tty1",
                                       "/dev/ttyUSB7": "/dev/pts/2"}.get(p, _orig_realpath(p))
    check("by-id → /dev/ttyUSB0: acceptat (calea normalizată, nu ţinta)",
          sda("/dev/serial/by-id/usb-FTDI-if00-port0") == "/dev/serial/by-id/usb-FTDI-if00-port0")
    check("by-path → /dev/ttyACM0: acceptat",
          sda("/dev/serial/by-path/pci-0000:00:14.0-usb-0:1:1.0") is not None)
    check("by-id care duce la /dev/tty1: refuzat", sda("/dev/serial/by-id/evil") is None)
    check("nume permis care e de fapt link spre /dev/pts: refuzat", sda("/dev/ttyUSB7", link_targets=set()) is None)
finally:
    ptyd.os.path.realpath = _orig_realpath
# op-ul serial_open respinge înainte de open
ag = fake_agent()
ptyd.Agent.handle_ctrl(ag, {"op": "serial_open", "id": "s1", "stream": "x" * 32, "device": "/dev/tty1"})
r = by_id(ag, "s1")
check("serial_open /dev/tty1 → bad_device", r and r["code"] == "bad_device", r)
check("serial_ports() rămâne consistent cu allowlist-ul",
      all(sda(p["device"]) for p in ptyd.serial_ports()))

# ───────────────────────── 8. resolver unic de shell ─────────────────────────
class _Pw:
    def __init__(self, sh):
        self.pw_shell = sh


_orig_getpwuid = ptyd.pwd.getpwuid
_orig_shell = os.environ.get("SHELL")
try:
    ptyd.pwd.getpwuid = lambda _uid: _Pw("/usr/sbin/nologin")
    os.environ["SHELL"] = "/usr/sbin/nologin"
    got = ptyd._login_shell()
    check("nologin în passwd ŞI în $SHELL → fallback /bin/bash sau /bin/sh", got in ("/bin/bash", "/bin/sh"), got)
    fs = fake_agent()
    ptyd.Agent._run_command(fs, "r1", "echo shell-ok", 10)
    r = fs.replies[-1]
    check("`run` pe cont de serviciu (nologin) merge prin resolver (nu `nologin -lc`)",
          r["ok"] and r["exit_code"] == 0 and "shell-ok" in r["stdout"], r)
finally:
    ptyd.pwd.getpwuid = _orig_getpwuid
    if _orig_shell is None:
        os.environ.pop("SHELL", None)
    else:
        os.environ["SHELL"] = _orig_shell
check("spawn_client foloseşte _login_shell (cmd + fallback pty), rezolvat înainte de fork",
      "shell = _login_shell()" in inspect.getsource(ptyd.Session.spawn_client)
      and inspect.getsource(ptyd.Session.spawn_client).index("_login_shell()")
      < inspect.getsource(ptyd.Session.spawn_client).index("pty.fork()"))
check("_run_command foloseşte _login_shell", "shell = _login_shell()" in inspect.getsource(ptyd.Agent._run_command))
check("tmux default-shell vine din acelaşi resolver", ("default-shell", ptyd._login_shell()) in ptyd._TMUX_BASE_OPTIONS)

# ───────────────────────── 4. _kill_tmux_procs: filtru UID ─────────────────────────
proc = os.path.join(tmp, "proc")


def mkproc(pid, argv, uid=None):
    d = os.path.join(proc, str(pid))
    os.makedirs(d)
    with open(os.path.join(d, "cmdline"), "wb") as f:
        f.write(b"\0".join(argv) + b"\0")
    if uid is not None:
        with open(os.path.join(d, "status"), "wb") as f:
            f.write(b"Name:\ttmux: server\nUid:\t%d\t%d\t%d\t%d\nGid:\t1\t1\t1\t1\n" % (uid, uid, uid, uid))


TM = [b"/usr/bin/tmux", b"-L", b"webterm", b"-f", b"/x/tmux.conf", b"new-session", b"-A", b"-D", b"-s", b"wt-abc"]
mkproc(100, TM, uid=1000)                                   # al nostru (uid 1000)
mkproc(200, TM, uid=0)                                      # serverul lui ROOT, acelaşi -L webterm
mkproc(300, [b"/usr/bin/tmux", b"-L", b"altul", b"attach"], uid=1000)   # alt socket
mkproc(400, TM)                                             # fără status → fallback st_uid (al nostru real)
mkproc(500, [b"/usr/bin/python3", b"-L", b"webterm"], uid=1000)         # non-tmux
os.makedirs(os.path.join(proc, "self"))                     # intrare ne-numerică, ignorată
# pid 400 n-are status → cade pe st_uid-ul directorului fals = UID-ul care rulează testul
_me400 = [400] if os.getuid() == 1000 else []
got = ptyd.tmux_procs_to_kill("webterm", 1000, proc_root=proc)
check("uid 1000 → doar PID-ul propriu (nu serverul root, nu alt socket, nu non-tmux)", got == [100] + _me400, got)
got = ptyd.tmux_procs_to_kill("webterm", 0, proc_root=proc)
check("uid 0 (agent root) → doar serverul lui root, NU al userului webterm",
      got == [200] + ([400] if os.getuid() == 0 else []), got)
got = ptyd.tmux_procs_to_kill("webterm", 1000, proc_root=proc, skip_pid=100)
check("skip_pid (noi înşine) e sărit", got == [], got)
got = ptyd.tmux_procs_to_kill("webterm", os.getuid(), proc_root=proc)
check("fără /proc/<pid>/status → fallback pe st_uid-ul directorului", 400 in got, got)
check("/proc ilizibil → listă goală, nu excepţie", ptyd.tmux_procs_to_kill("webterm", 1, proc_root=os.path.join(tmp, "nope")) == [])
seen = {}
_orig_tpk = ptyd.tmux_procs_to_kill
ptyd.tmux_procs_to_kill = lambda sock, uid, proc_root="/proc", skip_pid=None: seen.update(sock=sock, uid=uid, skip=skip_pid) or []
try:
    n = ptyd.Agent._kill_tmux_procs(fake_agent())
    check("_kill_tmux_procs trece prin filtru cu os.getuid() + os.getpid()",
          n == 0 and seen == {"sock": "webterm", "uid": os.getuid(), "skip": os.getpid()}, seen)
finally:
    ptyd.tmux_procs_to_kill = _orig_tpk

# ───────────────────────── 5. fwd_open fără DNS pe loop ─────────────────────────
lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lst.bind(("127.0.0.1", 0))
lst.listen(5)
PORT = lst.getsockname()[1]
_orig_gai = ptyd.socket.getaddrinfo
gai_calls = []


def fake_gai(host, port, family=0, type=0, proto=0, flags=0):
    gai_calls.append((host, flags, threading.current_thread().name))
    if flags & socket.AI_NUMERICHOST:
        return _orig_gai(host, port, family, type, proto, flags)      # literal: fără reţea
    if host == "slow.example":
        time.sleep(0.6)                                               # resolver lent
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    if host == "v6only.example":
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0))]
    if host == "dual.example":
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    raise socket.gaierror(-2, "Name or service not known")


ptyd.socket.getaddrinfo = fake_gai
try:
    ag = fake_agent()
    # literal IPv4 → connect imediat, pe loop, fără DNS
    ptyd.Agent.handle_ctrl(ag, {"op": "fwd_open", "id": "w1", "stream": "a" * 32, "host": "127.0.0.1", "port": PORT})
    r = by_id(ag, "w1")
    check("fwd_open literal IPv4: ok sincron + forward înregistrat",
          r and r["ok"] and "a" * 32 in ag.forwards and ag.forwards["a" * 32].sock.family == socket.AF_INET, r)
    check("literalul nu a trecut prin DNS (doar AI_NUMERICHOST)",
          all(f & socket.AI_NUMERICHOST for h, f, t in gai_calls), gai_calls)
    # hostname → handler-ul se întoarce imediat, fără reply; DNS pe alt thread
    gai_calls.clear()
    t0 = time.time()
    ptyd.Agent.handle_ctrl(ag, {"op": "fwd_open", "id": "w2", "stream": "b" * 32, "host": "slow.example", "port": PORT})
    dt = time.time() - t0
    check("fwd_open hostname: handler-ul NU blochează (%.2fs) şi nu răspunde încă" % dt,
          dt < 0.3 and by_id(ag, "w2") is None and "b" * 32 in ag._fwd_resolving)
    check("slotul rezervat contează la limită", "b" * 32 not in ag.forwards)
    item = ag.inbox.get(timeout=3)
    check("rezultatul DNS vine prin inbox, de pe un thread worker",
          item[0] == "__fwd_resolved__" and item[1] == "b" * 32
          and any(h == "slow.example" and t != threading.main_thread().name for h, f, t in gai_calls), (item, gai_calls))
    ptyd.Agent._on_fwd_resolved(ag, item[1], item[2], item[3])
    r = by_id(ag, "w2")
    check("după rezolvare: ok + forward deschis, slotul de rezolvare eliberat",
          r and r["ok"] and "b" * 32 in ag.forwards and "b" * 32 not in ag._fwd_resolving, r)
    # hostname inexistent → err resolve
    ptyd.Agent.handle_ctrl(ag, {"op": "fwd_open", "id": "w3", "stream": "c" * 32, "host": "nope.example", "port": PORT})
    item = ag.inbox.get(timeout=3)
    ptyd.Agent._on_fwd_resolved(ag, item[1], item[2], item[3])
    r = by_id(ag, "w3")
    check("hostname nerezolvabil → err resolve (nu internal, nu blocaj)",
          r and r["ok"] is False and r["code"] == "resolve", r)
    # dual-stack: preferăm IPv4
    check("_pick_addr preferă IPv4 când există", ptyd._pick_addr(fake_gai("dual.example", PORT))[0] == socket.AF_INET)
    check("_pick_addr acceptă IPv6-only", ptyd._pick_addr(fake_gai("v6only.example", PORT))[0] == socket.AF_INET6)
    check("_literal_addr: IPv6 literal → AF_INET6 (nu mai e AF_INET fix)",
          ptyd._literal_addr("::1", 80) is not None and ptyd._literal_addr("::1", 80)[0] == socket.AF_INET6)
    check("_literal_addr: hostname → None (fără DNS)", ptyd._literal_addr("gw.example", 80) is None)
    # fwd_close în timpul rezolvării → rezultatul târziu e ignorat
    ptyd.Agent.handle_ctrl(ag, {"op": "fwd_open", "id": "w4", "stream": "d" * 32, "host": "slow.example", "port": PORT})
    ptyd.Agent.handle_ctrl(ag, {"op": "fwd_close", "id": "w4c", "stream": "d" * 32})
    check("fwd_close anulează rezolvarea în curs", "d" * 32 not in ag._fwd_resolving)
    item = ag.inbox.get(timeout=3)
    n_before = len(ag.replies)
    ptyd.Agent._on_fwd_resolved(ag, item[1], item[2], item[3])
    check("rezultatul DNS târziu e ignorat (fără reply, fără forward)",
          len(ag.replies) == n_before and "d" * 32 not in ag.forwards)
    # expirare în _tick
    ag2 = fake_agent()
    ag2.connected = False
    ag2._last_alive = ag2._last_logcheck = ag2._last_wd = 0.0
    ag2._wd_interval = 0.0
    ag2._pending_reap = set()
    ag2.reaped = {}
    ag2.backend = "pty"
    _ap, _lp = ptyd.ALIVE_PATH, ptyd.LOG_PATH
    ptyd.ALIVE_PATH, ptyd.LOG_PATH = os.path.join(tmp, "alive"), os.path.join(tmp, "ptyd.log")
    try:
        ag2._fwd_resolving["e" * 32] = ("w5", time.time() - 1)
        ptyd.Agent._tick(ag2, time.time())
        r = by_id(ag2, "w5")
        check("rezolvare expirată în _tick → err resolve + slot eliberat",
              r and r["code"] == "resolve" and "e" * 32 not in ag2._fwd_resolving, r)
    finally:
        ptyd.ALIVE_PATH, ptyd.LOG_PATH = _ap, _lp
    # limită: rezolvările în curs ocupă sloturi
    ag3 = fake_agent()
    _mf = ptyd.MAX_FORWARDS
    ptyd.MAX_FORWARDS = 1
    try:
        ag3._fwd_resolving["f" * 32] = ("x", time.time() + 10)
        ptyd.Agent.handle_ctrl(ag3, {"op": "fwd_open", "id": "w6", "stream": "g" * 32, "host": "127.0.0.1", "port": PORT})
        check("MAX_FORWARDS numără şi rezolvările în curs", by_id(ag3, "w6")["code"] == "limit", by_id(ag3, "w6"))
    finally:
        ptyd.MAX_FORWARDS = _mf
    ptyd.Agent.handle_ctrl(ag3, {"op": "fwd_open", "id": "w7", "stream": "h" * 32, "host": "127.0.0.1", "port": 0})
    check("port invalid → bad_request", by_id(ag3, "w7")["code"] == "bad_request", by_id(ag3, "w7"))
    for a in (ag, ag3):
        for f in list(a.forwards.values()):
            f.sock.close()
finally:
    ptyd.socket.getaddrinfo = _orig_gai
    lst.close()

# ───────────────────────── 3. KillMode=process self-heal ─────────────────────────
unit = os.path.join(tmp, "webterm-agent.service")
me = os.path.join(tmp, "home", ".webterm", "ptyd.py")
UNIT = ("[Unit]\nDescription=WebTerm agent (ptyd)\nAfter=network-online.target\n\n[Service]\nType=simple\n"
        "ExecStart=/usr/bin/python3 %s run\nRestart=always\nRestartSec=3\nWatchdogSec=45\n\n"
        "[Install]\nWantedBy=default.target\n")
with open(unit, "w") as f:
    f.write(UNIT % me)
os.chmod(unit, 0o600)
check("unit al instalatorului fără KillMode → patched", ptyd.patch_unit_killmode(unit, me) == "patched")
txt = open(unit).read()
svc = txt.split("[Service]", 1)[1].split("[Install]", 1)[0]
check("KillMode=process a intrat în secţiunea [Service]", "\nKillMode=process\n" in svc, txt)
check("restul unit-ului e neatins", all(l in txt for l in ("ExecStart=/usr/bin/python3 %s run" % me, "WatchdogSec=45", "WantedBy=default.target")))
check("modul fişierului e păstrat (0600)", stat.S_IMODE(os.stat(unit).st_mode) == 0o600)
check("a doua trecere e idempotentă → ok", ptyd.patch_unit_killmode(unit, me) == "ok" and open(unit).read() == txt)
with open(unit, "w") as f:
    f.write(UNIT.replace("Restart=always", "Restart=always\nKillMode=mixed") % me)
check("KillMode setat explicit de operator (mixed) NU se suprascrie",
      ptyd.patch_unit_killmode(unit, me) == "ok" and "KillMode=mixed" in open(unit).read() and "KillMode=process" not in open(unit).read())
other = UNIT % "/opt/other/ptyd.py"
with open(unit, "w") as f:
    f.write(other)
check("unit al ALTUI agent (ExecStart străin) → None, neatins",
      ptyd.patch_unit_killmode(unit, me) is None and open(unit).read() == other)
check("unit lipsă → None", ptyd.patch_unit_killmode(os.path.join(tmp, "nope.service"), me) is None)
with open(unit, "w") as f:
    f.write(UNIT % me)
_env_keys = ("INVOCATION_ID", "NOTIFY_SOCKET")
_saved = {k: os.environ.pop(k, None) for k in _env_keys}
_orig_cands, _orig_self, _orig_run = ptyd._systemd_unit_candidates, ptyd.SELF_PATH, ptyd.subprocess.run
calls = []
try:
    ptyd._systemd_unit_candidates = lambda: [(unit, True)]
    ptyd.SELF_PATH = me
    ptyd.subprocess.run = lambda argv, **k: calls.append(argv) or None
    check("fără INVOCATION_ID/NOTIFY_SOCKET (cron/manual) → nu atinge nimic",
          ptyd.ensure_systemd_killmode() is None and "KillMode" not in open(unit).read() and calls == [])
    os.environ["INVOCATION_ID"] = "abc"
    check("sub systemd: patched + `systemctl --user daemon-reload` (best-effort)",
          ptyd.ensure_systemd_killmode() == "patched" and calls == [["systemctl", "--user", "daemon-reload"]], calls)
    calls.clear()
    check("a doua pornire: ok, fără daemon-reload", ptyd.ensure_systemd_killmode() == "ok" and calls == [])
    ptyd._systemd_unit_candidates = lambda: [(unit, False)]
    with open(unit, "w") as f:
        f.write(UNIT % me)
    ptyd.ensure_systemd_killmode()
    check("unit de sistem (/etc) → daemon-reload FĂRĂ --user", calls == [["systemctl", "daemon-reload"]], calls)

    def _boom(argv, **k):
        raise OSError("no systemctl")
    ptyd.subprocess.run = _boom
    with open(unit, "w") as f:
        f.write(UNIT % me)
    check("systemctl absent → unit-ul tot e reparat, fără excepţie",
          ptyd.ensure_systemd_killmode() == "patched" and "KillMode=process" in open(unit).read())
    check("self-heal e chemat la pornire şi înainte de re-exec",
          "ensure_systemd_killmode()" in inspect.getsource(ptyd.Agent.run)
          and "ensure_systemd_killmode()" in inspect.getsource(ptyd.Agent._reexec))
finally:
    ptyd._systemd_unit_candidates, ptyd.SELF_PATH, ptyd.subprocess.run = _orig_cands, _orig_self, _orig_run
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

# ───────────────────────── 10. diagnostics: una în zbor + force rărit ─────────────────────────
diag_calls = []
_orig_collect = ptyd.collect_diagnostics
ptyd.collect_diagnostics = lambda force_updates=False: diag_calls.append(force_updates) or {"collected_at": 1}
try:
    ag = fake_agent()
    ag._diag_inflight.acquire()                         # „una e deja în curs"
    ptyd.Agent.handle_ctrl(ag, {"op": "diagnostics", "id": "d1"})
    check("colectare în curs + niciun snapshot → busy", by_id(ag, "d1") and by_id(ag, "d1")["code"] == "busy", by_id(ag, "d1"))
    ag._diag_last = {"collected_at": 0}
    ptyd.Agent.handle_ctrl(ag, {"op": "diagnostics", "id": "d2"})
    r = by_id(ag, "d2")
    check("colectare în curs + snapshot vechi → ultimul snapshot, marcat stale",
          r and r["ok"] and r.get("stale") is True and r["diag"] == {"collected_at": 0}, r)
    n = len(ag.replies)
    ptyd.Agent._start_diag(ag)                          # push periodic în timp ce una rulează
    check("push-ul periodic sare când una e în curs (fără al doilea thread)", len(ag.replies) == n and diag_calls == [])
    ag._diag_inflight.release()
    ptyd.Agent._start_diag(ag, "d3")
    check("on-demand: colectat pe worker, force=True prima dată",
          wait_for(lambda: by_id(ag, "d3") is not None) and diag_calls == [True], (diag_calls, by_id(ag, "d3")))
    ptyd.Agent._start_diag(ag, "d4")
    check("al doilea Refresh imediat: rulează, dar FĂRĂ force (rărit la DIAG_FORCE_MIN_INTERVAL)",
          wait_for(lambda: by_id(ag, "d4") is not None) and diag_calls == [True, False], diag_calls)
    ag._last_diag_force = 0.0
    ptyd.Agent._start_diag(ag, "d5")
    check("după interval: force din nou", wait_for(lambda: by_id(ag, "d5") is not None) and diag_calls[-1] is True)
    ptyd.Agent._start_diag(ag)
    check("push-ul periodic nu forţează niciodată",
          wait_for(lambda: any(r.get("event") == "diagnostics" for r in ag.replies)) and diag_calls[-1] is False)
    check("lock-ul e eliberat după fiecare colectare", wait_for(lambda: ag._diag_inflight.acquire(False)))
    ag._diag_inflight.release()
finally:
    ptyd.collect_diagnostics = _orig_collect

# ───────────────────────── 12. cod mort ─────────────────────────
for sym in ("_persist_cert_pin", "tmux_has_session", "_sys_read"):
    check("%s şters" % sym, not hasattr(ptyd, sym) and not hasattr(ptyd.Agent, sym))
check("Serial fără opened_at, Session fără last_respawn",
      "opened_at" not in ptyd.Serial.__slots__ and "last_respawn" not in inspect.getsource(ptyd.Session.__init__))
check("compat flotă: citirea legacy `cert_pin` rămâne",
      'cfg.get("cert_pin")' in inspect.getsource(ptyd.Agent._start_connect))

print("\n%d/%d PASS" % (ok, total))
sys.exit(0 if ok == total else 1)
