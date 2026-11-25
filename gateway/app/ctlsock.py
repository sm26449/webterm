"""Local control socket for `hostops backup --live` (ENCRYPTION-AT-REST.md §12.11.3 "Control socket
protocol", PR6c).

While encrypted recordings are active, a host-side backup of the RUNNING gateway never reads the
live volume itself: it asks this socket, and the gateway runs the same `backup_snapshot()` as every
in-app backup (barrier, pins, verify pass, emit pass), spools the portable WTS1 to a private file,
verifies it in full, and only then offers it for reading. No socket answer while the app runs →
the host backup is refused (hostops), never a direct read.

* **Creation** (boot, after `txhub.boot`, before routes serve): `DATA_DIR/.ctl` opened with
  O_NOFOLLOW and checked on its fd (directory, owned by the gateway uid, 0700); a leftover
  `backup.sock` is unlinked only if it is a socket of ours; `spool/` emptied. Anything else → no
  socket and a System health alarm (`health()`).
* **Peer**: SO_PEERCRED uid 0 or the gateway uid, checked before any byte is read; otherwise the
  connection is closed and audited.
* **Framing**: 4-byte big-endian length + payload; requests are JSON ≤ 4 KiB with `v` = 1, `op`,
  `id` and only the op's keys. Anything else → one `error` frame, then close.
* **Ops**: `snapshot.start {profile: "portable", recordings: "all"|"none"}`, `snapshot.read {snap,
  offset, length ≤ 1 MiB}` (a header frame + one data frame, from the spool only), `snapshot.release
  {snap}`. No secret crosses the socket except the archive bytes (a WTS1 whose portable envelope
  needs the MK; the passphrase layer is added by hostops).
* **Limits**: 2 connections, one snapshot in flight per process (txstore's slot, shared with the
  in-app and scheduled backups); first request ≤ 10 s, then ≤ 60 s between requests; each frame
  written within 30 s; `snapshot.start` answers within 15 min; a ready spool lives ≤ 15 min and
  ≤ 60 s without a read; free space ≥ estimate + 10 %; at most 2 ready spools, and the ready
  spools plus the new estimate ≤ half the filesystem. The in-flight slot is taken synchronously
  before the first await and released only when the worker has really finished.
* **Disconnect**: the worker owns a submitted snapshot (cancel flag, unlinks its spool on exit); the
  connection's ready spools are unlinked with it. Nothing is kept for a later connection.
"""
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import secrets
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass, field

from . import audit, backup, config

log = logging.getLogger("webterm.ctlsock")

CTL_DIR = ".ctl"
SOCK_NAME = "backup.sock"
SPOOL_DIR = "spool"
MAX_CONN = 2
FRAME_MAX = 4096
READ_MAX = 1 << 20
FIRST_REQ_SECS = 10.0
IDLE_SECS = 60.0
WRITE_SECS = 30.0
START_SECS = 900.0
SPOOL_LIFE_SECS = 900.0
SPOOL_IDLE_SECS = 60.0
SPACE_SLACK = 1.10
MAX_SPOOLS = 2                    # spool-uri gata ţinute deodată (toate conexiunile)
SPOOL_SHARE = 0.5                 # spool-urile gata + cel nou ≤ jumătate din sistemul de fişiere
VERSION = 1
OPS = {
    "snapshot.start": frozenset({"profile", "recordings"}),
    "snapshot.read": frozenset({"snap", "offset", "length"}),
    "snapshot.release": frozenset({"snap"}),
}
_BASE_KEYS = frozenset({"v", "op", "id"})
_SNAP_RE_LEN = 32
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_PEERCRED = struct.Struct("3i")


class _Proto(Exception):
    """A request outside the protocol: one error frame, then close."""


@dataclass
class _Spool:
    name: str
    fd: int
    size: int
    sha256: str
    conn: object
    created: float = field(default_factory=time.monotonic)
    last_read: float = field(default_factory=time.monotonic)


@dataclass
class _State:
    server: object = None
    ctl_fd: int = None
    spool_fd: int = None
    conns: set = field(default_factory=set)
    spools: dict = field(default_factory=dict)
    inflight: object = None           # threading.Event al snapshot-ului în lucru
    janitor: object = None
    error: str = ""
    uid: int = None
    # teste: injectează un worker (fileobj, include, cancel) → None
    worker: object = None
    clock: object = time.monotonic


_s = _State()


def health():
    """(severity, key, params) for System health, or None when nothing is wrong / inactive."""
    if _s.error:
        return ("warning", "ctl_socket_unavailable", {"error": _s.error})
    return None


def active() -> bool:
    return _s.server is not None


def _fail(msg):
    _s.error = msg[:200]
    log.error("backup control socket not available: %s — host live backups are refused", msg)


# ── creation ────────────────────────────────────────────────────────────────


def _check_dir_fd(fd, what):
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise OSError("%s is not a private directory of the gateway (owner/mode)" % what)


def _open_private_dir(parent_fd, name, what):
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as e:
        raise OSError("%s cannot be opened as a plain directory (%s)" % (what, e.strerror)) from None
    try:
        _check_dir_fd(fd, what)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _prepare(data_dir):
    """→ (ctl fd, spool fd), with a leftover socket removed and the spool emptied."""
    data_fd = os.open(str(data_dir), _DIR_FLAGS)
    try:
        ctl = _open_private_dir(data_fd, CTL_DIR, CTL_DIR)
    finally:
        os.close(data_fd)
    try:
        try:
            st = os.stat(SOCK_NAME, dir_fd=ctl, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None:
            if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid():
                raise OSError("%s/%s exists and is not our socket" % (CTL_DIR, SOCK_NAME))
            os.unlink(SOCK_NAME, dir_fd=ctl)
        spool = _open_private_dir(ctl, SPOOL_DIR, CTL_DIR + "/" + SPOOL_DIR)
        try:
            for n in os.listdir(spool):
                sst = os.stat(n, dir_fd=spool, follow_symlinks=False)
                if not stat.S_ISREG(sst.st_mode):
                    raise OSError("the backup spool holds a non-regular entry")
                os.unlink(n, dir_fd=spool)
        except BaseException:
            os.close(spool)
            raise
    except BaseException:
        os.close(ctl)
        raise
    return ctl, spool


def _bind(ctl):
    """The socket bound THROUGH the directory fd (/proc/self/fd/N/…), never a path walk."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind("/proc/self/fd/%d/%s" % (ctl, SOCK_NAME))
        os.chmod(SOCK_NAME, 0o600, dir_fd=ctl)
        st = os.stat(SOCK_NAME, dir_fd=ctl, follow_symlinks=False)
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid():
            raise OSError("the bound socket is not ours")
        sock.listen(MAX_CONN)
        sock.setblocking(False)
    except BaseException:
        sock.close()
        raise
    return sock


async def start(data_dir=None) -> bool:
    """Boot (encrypted recordings active only). False = no socket (alarm set): host live backups
    are refused until the next boot fixes it."""
    await stop()
    _s.error = ""
    _s.uid = os.geteuid()
    try:
        ctl, spool = _prepare(config.DATA_DIR if data_dir is None else data_dir)
    except OSError as e:
        _fail(str(e))
        return False
    try:
        sock = _bind(ctl)
        _s.server = await asyncio.start_unix_server(_handle, sock=sock)
    except OSError as e:
        os.close(spool)
        os.close(ctl)
        _fail("cannot bind %s/%s: %s" % (CTL_DIR, SOCK_NAME, e.strerror or e))
        return False
    _s.ctl_fd, _s.spool_fd = ctl, spool
    _s.janitor = asyncio.get_running_loop().create_task(_janitor())
    return True


async def stop() -> None:
    if _s.janitor is not None:
        _s.janitor.cancel()
        _s.janitor = None
    if _s.server is not None:
        _s.server.close()
        with contextlib.suppress(Exception):
            await _s.server.wait_closed()
        _s.server = None
    if _s.inflight is not None:
        _s.inflight.set()
    for sp in list(_s.spools.values()):
        _drop(sp)
    if _s.ctl_fd is not None:
        with contextlib.suppress(OSError):
            os.unlink(SOCK_NAME, dir_fd=_s.ctl_fd)
        os.close(_s.ctl_fd)
        _s.ctl_fd = None
    if _s.spool_fd is not None:
        os.close(_s.spool_fd)
        _s.spool_fd = None


# ── spools ──────────────────────────────────────────────────────────────────


def _unlink_spool(name):
    if _s.spool_fd is not None:
        with contextlib.suppress(FileNotFoundError, OSError):
            os.unlink(name, dir_fd=_s.spool_fd)


def _drop(sp):
    _s.spools.pop(sp.name, None)
    with contextlib.suppress(OSError):
        os.close(sp.fd)
    _unlink_spool(sp.name)


def expire_spools():
    """A ready spool lives ≤ 15 min, and ≤ 60 s without a read. → how many were removed."""
    now = _s.clock()
    n = 0
    for sp in list(_s.spools.values()):
        if now - sp.created > SPOOL_LIFE_SECS or now - sp.last_read > SPOOL_IDLE_SECS:
            log.warning("backup spool %s expired unread — removed", sp.name[:8])
            _drop(sp)
            n += 1
    return n


async def _janitor():
    while True:
        await asyncio.sleep(5)
        expire_spools()


def _estimate():
    """Bytes the spool may need: the DB and every file under transcripts/ (and arhiva/)."""
    n = 0
    for p in (config.DB_PATH, config.DATA_DIR / "webterm.db-wal"):
        with contextlib.suppress(OSError):
            n += os.stat(str(p)).st_size
    for d in (config.TRANSCRIPT_DIR, config.ARCHIVE_DIR):
        with contextlib.suppress(OSError):
            with os.scandir(str(d)) as it:
                for e in it:
                    with contextlib.suppress(OSError):
                        if e.is_file(follow_symlinks=False):
                            n += e.stat(follow_symlinks=False).st_size
    return n


def _worker(fd, name, include, cancel, spool_fd):
    """Runs in a thread and OWNS the spool from submit: writes the WTS1, fsyncs, verifies it in
    full, and on any failure or cancel unlinks it before returning. → (size, sha256 hex)."""
    ok = False
    try:
        with os.fdopen(os.dup(fd), "w+b") as f:
            if _s.worker is not None:
                _s.worker(f, include, cancel)
            else:
                backup.spool_live_snapshot(f, include, cancel)
            if cancel.is_set():
                raise backup.SnapshotBusy("cancelled")
            size, sha = backup.verify_spool(f)
        if cancel.is_set():
            raise backup.SnapshotBusy("cancelled")
        ok = True
        return size, sha
    finally:
        if not ok:
            with contextlib.suppress(OSError):
                os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=spool_fd)


# ── protocol ────────────────────────────────────────────────────────────────


def _frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


async def _send(writer, obj=None, raw=None):
    data = _frame(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode() if raw is None else raw)
    writer.write(data)
    await asyncio.wait_for(writer.drain(), WRITE_SECS)


async def _read_request(reader, timeout):
    try:
        head = await asyncio.wait_for(reader.readexactly(4), timeout)
    except asyncio.IncompleteReadError as e:
        if not e.partial:
            return None                         # EOF curat între cereri
        raise _Proto("truncated frame") from None
    (n,) = struct.unpack(">I", head)
    if n == 0 or n > FRAME_MAX:
        raise _Proto("frame size")
    try:
        body = await asyncio.wait_for(reader.readexactly(n), timeout)
    except asyncio.IncompleteReadError:
        raise _Proto("truncated frame") from None
    try:
        req = json.loads(body.decode("utf-8"), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except (ValueError, UnicodeDecodeError):
        raise _Proto("invalid json") from None
    if type(req) is not dict or req.get("v") != VERSION or req.get("op") not in OPS:
        raise _Proto("version or op")
    if set(req) - _BASE_KEYS - OPS[req["op"]] or not OPS[req["op"]] <= set(req) or "id" not in req:
        raise _Proto("keys")
    if type(req["id"]) not in (int, str) or (type(req["id"]) is str and len(req["id"]) > 64):
        raise _Proto("id")
    return req


async def _audit(peer, op, status, det=""):
    with contextlib.suppress(Exception):
        await audit.record(time.time(), "ctl:uid=%d" % peer[1], "local", "CTL", "/ctl/%s" % op, status,
                           ("pid=%d %s" % (peer[0], det)).strip())


def peer_ok(uid) -> bool:
    """SO_PEERCRED uid, as this namespace sees it: root or the gateway's own uid (fail closed)."""
    return uid in (0, _s.uid)


async def _handle(reader, writer):
    sock = writer.get_extra_info("socket")
    try:
        pid, uid, _gid = _PEERCRED.unpack(sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size))
    except OSError:
        writer.close()
        return
    peer = (pid, uid)
    if len(_s.conns) >= MAX_CONN:
        await _audit(peer, "connect", 429, "too many connections")
        writer.close()
        return
    if not peer_ok(uid):
        # o identitate străină nu ajunge să trimită niciun octet (verificat înainte de citire)
        await _audit(peer, "connect", 403, "peer uid refused")
        writer.close()
        return
    conn = object()
    _s.conns.add(conn)
    try:
        first = True
        while True:
            try:
                req = await _read_request(reader, FIRST_REQ_SECS if first else IDLE_SECS)
            except _Proto as e:
                await _audit(peer, "protocol", 400, str(e))
                with contextlib.suppress(Exception):
                    await _send(writer, {"ok": False, "error": "protocol"})
                return
            if req is None:
                return
            first = False
            op = req["op"]
            if op == "snapshot.start":
                if not await _op_start(req, reader, writer, conn, peer):
                    return
            elif op == "snapshot.read":
                if not await _op_read(req, writer, conn, peer):
                    return
            else:
                sp = _s.spools.get(req["snap"]) if type(req["snap"]) is str else None
                if sp is None or sp.conn is not conn:
                    await _send(writer, {"ok": False, "id": req["id"], "error": "unknown-snapshot"})
                    return
                _drop(sp)
                await _audit(peer, op, 200, sp.name[:8])
                await _send(writer, {"ok": True, "id": req["id"]})
    except (asyncio.TimeoutError, ConnectionError, OSError) as e:
        await _audit(peer, "disconnect", 408, type(e).__name__)
    finally:
        _s.conns.discard(conn)
        for sp in [x for x in _s.spools.values() if x.conn is conn]:
            _drop(sp)
        with contextlib.suppress(Exception):
            writer.close()


async def _op_start(req, reader, writer, conn, peer):
    rid = req["id"]
    if req["profile"] != "portable" or req["recordings"] not in ("all", "none"):
        await _send(writer, {"ok": False, "id": rid, "error": "protocol"})
        return False
    if (_s.inflight is not None or any(sp.conn is conn for sp in _s.spools.values())
            or len(_s.spools) >= MAX_SPOOLS):
        await _audit(peer, "snapshot.start", 409, "busy")
        await _send(writer, {"ok": False, "id": rid, "code": "backup.busy"})
        return True
    # M3: slotul se ia SINCRON, înainte de primul await (estimarea de spaţiu): două conexiuni nu
    # pot trece amândouă de verificarea de mai sus. Se eliberează pe orice cale, şi doar după ce
    # worker-ul s-a terminat efectiv (callback pe viitorul lui), nu când pleacă peer-ul.
    cancel = threading.Event()
    _s.inflight = cancel
    fut = None
    try:
        try:
            vfs = os.fstatvfs(_s.spool_fd)
            need = await asyncio.to_thread(_estimate)
            held = sum(sp.size for sp in _s.spools.values())
            total = vfs.f_blocks * vfs.f_frsize
            # spaţiu liber ≥ estimare + 10 %, iar spool-urile gata + acesta ≤ SPOOL_SHARE din disc
            # (discul e comun cu restul sistemului)
            if (vfs.f_bavail * vfs.f_frsize < need * SPACE_SLACK
                    or held + need * SPACE_SLACK > total * SPOOL_SHARE):
                await _audit(peer, "snapshot.start", 507, "no space")
                await _send(writer, {"ok": False, "id": rid, "code": "backup.noSpace"})
                return True
        except OSError:
            await _audit(peer, "snapshot.start", 507, "space unknown")
            await _send(writer, {"ok": False, "id": rid, "code": "backup.noSpace"})
            return True
        if cancel.is_set():                     # stop() între timp
            return False
        name = secrets.token_hex(16)
        fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                     dir_fd=_s.spool_fd)
        loop = asyncio.get_running_loop()
        # de aici worker-ul e proprietarul spool-ului (îl şterge el la eşec / anulare)
        fut = loop.run_in_executor(None, _worker, fd, name, req["recordings"] == "all", cancel, _s.spool_fd)
        fut.add_done_callback(_clear_inflight(cancel, unless_ready=True))
    finally:
        if fut is None:
            _clear_inflight(cancel)(None)
    watch = asyncio.ensure_future(reader.read(1))
    try:
        done, _p = await asyncio.wait({fut, watch}, timeout=START_SECS, return_when=asyncio.FIRST_COMPLETED)
    except BaseException:
        # task-ul conexiunii anulat (oprire): worker-ul e oprit, slotul îl eliberează callback-ul lui
        cancel.set()
        fut.add_done_callback(_orphaned(fd, name))
        if fut.done():                          # callback-ul „unless_ready" a trecut deja
            _clear_inflight(cancel)(None)
        raise
    finally:
        if not watch.done():
            watch.cancel()
            # anularea se livrează asincron: aşteptăm s-o ia, altfel StreamReader are încă un cititor
            await asyncio.wait([watch])
    if watch in done and fut in done and watch.result():
        done = {watch}                          # octeţi neaşteptaţi în timpul snapshot-ului = încălcare
    if fut not in done:
        # deconectare (sau octeţi neaşteptaţi) în timpul snapshot-ului, ori bugetul de 15 min depăşit
        cancel.set()
        fut.add_done_callback(_orphaned(fd, name))
        if fut.done():                          # gata, dar peer-ul a încălcat protocolul: slotul liber
            _clear_inflight(cancel)(None)
        why = "timeout" if not done else "peer gone"
        await _audit(peer, "snapshot.start", 408, why)
        if not done:
            with contextlib.suppress(Exception):
                await _send(writer, {"ok": False, "id": rid, "code": "backup.busy"})
        return False
    try:
        size, sha = fut.result()
    except backup.SnapshotBusy:
        await _audit(peer, "snapshot.start", 409, "busy")
        await _send(writer, {"ok": False, "id": rid, "code": "backup.busy"})
        return True
    except Exception as e:                      # noqa: BLE001 — un eşec e un răspuns, nu o cădere
        log.warning("live backup snapshot failed: %s", type(e).__name__)
        await _audit(peer, "snapshot.start", 500, type(e).__name__)
        await _send(writer, {"ok": False, "id": rid, "code": "backup.failed"})
        return True
    sp = _Spool(name, fd, size, sha, conn, created=_s.clock(), last_read=_s.clock())
    _s.spools[name] = sp
    # slotul trece la spool-ul gata în acelaşi pas sincron (bugetul de spool-uri îl vede imediat)
    _clear_inflight(cancel)(None)
    await _audit(peer, "snapshot.start", 200, "size=%d" % size)
    await _send(writer, {"ok": True, "id": rid, "snap": name, "size": size, "sha256": sha})
    return True


def _orphaned(fd, name):
    """The worker finished after its connection was gone: a spool nobody will read is removed."""
    def done(f):
        if not f.cancelled() and f.exception() is None:
            with contextlib.suppress(OSError):
                os.close(fd)
            _unlink_spool(name)
    return done


def _clear_inflight(cancel, unless_ready=False):
    """`unless_ready`: a worker that produced a spool for a connection still waiting for it leaves
    the slot to that connection, which releases it only once the spool is registered (no window
    in which neither the slot nor the spool counts)."""
    def done(f):
        if (unless_ready and f is not None and not f.cancelled() and f.exception() is None
                and not cancel.is_set()):
            return
        if _s.inflight is cancel:
            _s.inflight = None
    return done


async def _op_read(req, writer, conn, peer):
    rid = req["id"]
    sp = _s.spools.get(req["snap"]) if type(req["snap"]) is str else None
    off, n = req["offset"], req["length"]
    if (sp is None or sp.conn is not conn or type(off) is not int or type(n) is not int
            or off < 0 or n < 0 or n > READ_MAX or off > sp.size):
        await _send(writer, {"ok": False, "id": rid, "error": "bad-read"})
        return False
    n = min(n, sp.size - off)
    data = await asyncio.to_thread(os.pread, sp.fd, n, off)
    if len(data) != n:
        _drop(sp)
        await _send(writer, {"ok": False, "id": rid, "code": "backup.failed"})
        return False
    sp.last_read = _s.clock()
    await _send(writer, {"ok": True, "id": rid, "offset": off, "length": n})
    await _send(writer, raw=data)
    return True


# ── client (hostops backup --live) ──────────────────────────────────────────


class ClientError(Exception):
    """The socket did not answer, refused, or the snapshot failed (`code` when it said why)."""

    def __init__(self, msg, code=""):
        super().__init__(msg)
        self.code = code


def socket_path(data_dir=None):
    return os.path.join(str(config.DATA_DIR if data_dir is None else data_dir), CTL_DIR, SOCK_NAME)


class Client:
    """Blocking client: one connection, one snapshot, written into `out` (a private temp file)."""

    def __init__(self, path, *, connect_timeout=10.0, start_timeout=START_SECS + 60, io_timeout=WRITE_SECS + 30):
        self.path = path
        self.start_timeout = start_timeout
        self.io_timeout = io_timeout
        st = os.stat(path, follow_symlinks=False)
        if not stat.S_ISSOCK(st.st_mode):
            raise ClientError("the backup control socket is not a socket")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(connect_timeout)
        try:
            self.sock.connect(path)
        except OSError as e:
            self.sock.close()
            raise ClientError("the gateway did not answer on its backup control socket (%s)" % (e.strerror or e)) from None
        self._id = 0

    def close(self):
        with contextlib.suppress(OSError):
            self.sock.close()

    def _exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            b = self.sock.recv(min(n - len(buf), 1 << 20))
            if not b:
                raise ClientError("the gateway closed the backup control socket")
            buf += b
        return bytes(buf)

    def _recv(self, limit=FRAME_MAX):
        (n,) = struct.unpack(">I", self._exact(4))
        if n > limit:
            raise ClientError("oversized frame from the gateway")
        return self._exact(n)

    def call(self, op, timeout=None, **kw):
        self._id += 1
        req = dict(kw, v=VERSION, op=op, id=self._id)
        self.sock.settimeout(self.io_timeout)
        self.sock.sendall(_frame(json.dumps(req).encode()))
        self.sock.settimeout(timeout or self.io_timeout)
        try:
            doc = json.loads(self._recv())
        except socket.timeout:
            raise ClientError("the gateway did not answer %s in time" % op) from None
        if type(doc) is not dict:
            raise ClientError("bad answer from the gateway")
        return doc

    def snapshot(self, out, *, recordings=True):
        """→ (size, sha256 hex) after the bytes were written to `out` and both were checked."""
        doc = self.call("snapshot.start", timeout=self.start_timeout, profile="portable",
                        recordings="all" if recordings else "none")
        if not doc.get("ok"):
            raise ClientError("the gateway refused the live backup (%s)" % (doc.get("code") or doc.get("error")),
                              doc.get("code", ""))
        snap, size, sha = doc.get("snap"), doc.get("size"), doc.get("sha256")
        if type(snap) is not str or type(size) is not int or type(sha) is not str or size < 0:
            raise ClientError("bad snapshot.start answer")
        h = hashlib.sha256()
        off = 0
        while off < size:
            hd = self.call("snapshot.read", snap=snap, offset=off, length=min(READ_MAX, size - off))
            if not hd.get("ok") or hd.get("offset") != off:
                raise ClientError("snapshot.read refused (%s)" % (hd.get("code") or hd.get("error")))
            data = self._recv(READ_MAX)
            if len(data) != hd.get("length") or not data:
                raise ClientError("short snapshot.read")
            out.write(data)
            h.update(data)
            off += len(data)
        if h.hexdigest() != sha:
            raise ClientError("the archive read from the gateway does not match its SHA-256")
        self.call("snapshot.release", snap=snap)
        return size, sha
