"""Encrypted recordings: publication (Recorder) and readers (ENCRYPTION-AT-REST.md §12.11).

PR5a: implemented and tested in isolation, **not wired** into core.py. A `Store` refuses to exist
unless `WEBTERM_TX_RECORDINGS=1`, `WEBTERM_TEST_GATE=1` (both checked before anything is opened)
*and* the volume is a test-fixture volume: an existing DB (opened `mode=rw`, never created) and a
transcripts dir, both in one private harness dir under the system temp dir, whose
`tx_state.test_volume` marker binds both identities (written only by `create_test_volume`, which
refuses a DB with `users` / `hosts` rows). This guards against accidents, not against an operator
who can write the DB. Enabling on a real volume needs PR6
(migration, erasure journal, quarantine).

Layout (§12.11.0): `transcripts/<sid>.<k>.<gen>.wtx` (k = out | cast, gen = 32 lowercase hex) and
the cache `transcripts/<sid>.<k>.<gen>.idx`, created through a directory fd, never renamed or
rewritten. Tables (db.SCHEMA): `session_keys`, `tx_descriptors`, `tx_files`, `tx_migration`,
`tx_state`.

Publication (§12.11.1): one `Recorder` per sid, one worker task with a FIFO job queue; a job holds
the sid's lease from capture to commit (lease → barrier, always in that order). Records are
appended and fsynced off the loop, then one isolated `BEGIN IMMEDIATE` transaction on txstore's
own connection updates both descriptors, the ledger and `sessions.agent_epoch/agent_offset` after
a CAS on the descriptor versions, the writer token and the agent position, and a monotonic check
that the new generation lists only extend the committed ones (or, for cap / merge, replace exactly
the pinned prefix P). An uncertain COMMIT is resolved from the DB on a fresh connection.

Readers (§12.11.2): `Store.open(sid, kind, access=…)` → `Snapshot` (fds, descriptor version and
revocation counters fixed together at one synchronous check, the linearisation point). Every byte
returned is reached through an authentic index or a verified parse; bytes past the committed prefix
are never read. Streams re-check before every chunk (counters, fences, `not_after`).

Nothing else in the gateway opens a generation, decodes a descriptor or unwraps an RK.
"""
import asyncio
import collections
import contextlib
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import sqlite3
import stat
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import NamedTuple

from . import config
from . import keyring
from . import keys
from . import txdesc
from . import txformat

# ── activation (§12.11 "PR5/PR6 boundary") ───────────────────────────────────

ENV_FLAG = "WEBTERM_TX_RECORDINGS"
ENV_TEST_GATE = "WEBTERM_TEST_GATE"


def enabled(env=None):
    """True only for exactly `WEBTERM_TX_RECORDINGS=1` (absent, empty, anything else = off)."""
    env = os.environ if env is None else env
    return env.get(ENV_FLAG, "") == "1"


def test_gate(env=None):
    """True only for exactly `WEBTERM_TEST_GATE=1` ("0", "false", " 1" … = off)."""
    env = os.environ if env is None else env
    return env.get(ENV_TEST_GATE, "") == "1"


def _volume_binding(db_path, transcripts_dir=None):
    """(db realpath, transcripts realpath, marker) of a test volume. Both roots live in ONE private
    harness dir (a mode-0700 dir of ours under the system temp dir): the DB file directly in it,
    the transcripts dir below it (default `<that dir>/transcripts`). The marker binds both
    identities (dev, ino, path), so a copied or restored DB, or a transcripts dir elsewhere (another
    volume), does not carry a valid marker. This is a guard against accidents, not access control
    against an operator who can write the DB."""
    real = os.path.realpath(str(db_path))
    root = os.path.realpath(tempfile.gettempdir())
    parent = os.path.dirname(real)
    if parent == root or os.path.commonpath([real, root]) != root:
        raise TxStoreError("disabled", "a test volume lives in a harness temp dir only")
    try:
        st = os.stat(real)
        pst = os.stat(parent)
    except OSError:
        raise TxStoreError("disabled", "test volume DB missing") from None
    if not stat.S_ISREG(st.st_mode):
        raise TxStoreError("disabled", "test volume DB is not a regular file")
    # Directorul fixture-ului e privat (al nostru, 0700): un DB într-un temp partajat nu e un volum de test.
    if pst.st_uid != os.geteuid() or pst.st_mode & 0o077:
        raise TxStoreError("disabled", "test volume dir is not a private harness dir")
    treal = os.path.realpath(str(transcripts_dir) if transcripts_dir is not None
                             else os.path.join(parent, "transcripts"))
    if treal == parent or os.path.commonpath([treal, parent]) != parent:
        raise TxStoreError("disabled", "transcripts dir outside the test volume's dir")
    try:
        tst = os.stat(treal)
    except OSError:
        raise TxStoreError("disabled", "test volume transcripts dir missing") from None
    if not stat.S_ISDIR(tst.st_mode):
        raise TxStoreError("disabled", "test volume transcripts dir is not a directory")
    return real, treal, (f"2:{st.st_dev}:{st.st_ino}:{real}:"
                         f"{tst.st_dev}:{tst.st_ino}:{treal}")


def _connect_rw(path):
    # mode=rw: niciodată nu creează fişierul (un DB lipsă nu devine un volum gol).
    return sqlite3.connect(pathlib.Path(path).as_uri() + "?mode=rw", uri=True, isolation_level=None,
                           check_same_thread=False, timeout=5)


def create_test_volume(db_path, transcripts_dir=None, env=None):
    """The test-fixture helper: marks a volume `tx_state.test_volume` with its identity binding (DB
    file + transcripts dir). Nothing else sets it. Refused outside a test gate, for roots outside
    one private harness dir, for a DB that has any `users` or `hosts` row (a real installation),
    and on any read error that is not a proven absent table."""
    if not test_gate(env):
        raise TxStoreError("disabled", "test volumes exist only under WEBTERM_TEST_GATE=1")
    real, _treal, marker = _volume_binding(db_path, transcripts_dir)
    con = _connect_rw(real)
    try:
        for table in ("users", "hosts"):
            try:
                # Absenţa se dovedeşte din sqlite_master; orice altă eroare de citire = refuz.
                present = con.execute("SELECT 1 FROM sqlite_master WHERE name=?",
                                      (table,)).fetchone() is not None
                has = present and con.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None
            except sqlite3.Error as e:
                raise TxStoreError("disabled", f"cannot prove {table} empty: {e}") from None
            if has:
                raise TxStoreError("disabled", f"{table} has rows: not a fresh test volume")
        if _volume_binding(db_path, transcripts_dir)[2] != marker:
            raise TxStoreError("disabled", "test volume changed while marking")
        con.execute("INSERT OR REPLACE INTO tx_state(key, value) VALUES('test_volume', ?)", (marker,))
    finally:
        con.close()


# ── constants ────────────────────────────────────────────────────────────────

KINDS = {"out": txformat.KIND_OUT, "cast": txformat.KIND_CAST}
KIND_NAMES = ("out", "cast")
# Identic cu core.GAP_MARKER (testul o verifică): txstore stă sub core şi nu-l poate importa.
GAP_MARKER = b"\r\n\x1b[7m[webterm: some output was lost here]\x1b[0m\r\n"
CAP_HEADER_MAX = 64 * 1024
CAP_CHUNK = 1024 * 1024
CAP_RETRY_SECS = 60.0
PENDING_CAP = 8 * 1024 * 1024          # per sid, pending + in-flight
REC_BUFFER_TOTAL = 64 * 1024 * 1024    # per proces
OP_GEN_CAP = 256                       # plafonul operaţional (codecul acceptă 4096)
READ_WORKERS = 4
READ_WAIT_SECS = 5.0
MAX_SNAPSHOTS = 64
MAX_GEN_FDS = 4096
SNAPSHOT_IDLE_SECS = 60.0
INDEX_STRIDE = 1024 * 1024
PARSE_WITH_INDEX = 1024 * 1024
STREAM_CHUNK = 64 * 1024
SEARCH_READ_CAP = 4 * 1024 * 1024
SEARCH_TOTAL_CAP = 128 * 1024 * 1024
SEARCH_MAX_RESULTS = 20
VERIFY_PASS_BYTES = 256 * 1024 * 1024
RK_CACHE_MAX = 256
LEDGER_KEEP_SECS = 90 * 86400
IDX_MAX_FILE = txformat.IDX_FIXED + txformat.DEFAULT_MAX_INDEX_ENTRIES * txformat.IDX_ENTRY_LEN \
    + txformat.MAC_LEN
SHUTDOWN_SECS = 5.0
OWNER_RECOVERY_ROUTE = "owner-recovery"
# Cel mai rău caz fizic per octet în clar: un DATA de 1 octet = antet + tag + 1.
PHYS_PER_PLAIN = txformat.REC_HDR_LEN + txformat.TAG_LEN + 1
REPRESENTATIONS = ("raw", "redacted")

_NAME_RE = re.compile(r"^([0-9a-f]{32})\.(out|cast)\.([0-9a-f]{32})\.(wtx|idx)$")
_TMP_IDX_RE = re.compile(r"^([0-9a-f]{32})\.(out|cast)\.([0-9a-f]{32})\.t[0-9a-f]{16}\.idx$")
_SID_RE = re.compile(r"^[0-9a-f]{32}$")
_CREATE = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_RDONLY = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_CAST_TS_RE = re.compile(rb"\[\s*(-?[0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?)\s*,")


# ── errors ───────────────────────────────────────────────────────────────────


class TxStoreError(Exception):
    """`reason` is the short code; `code` = "transcript.<reason>" for the routes (PR5b)."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason

    @property
    def code(self):
        return "transcript." + self.reason


class Refused(TxStoreError):
    """A publication's CAS or monotonic check failed: nothing was published."""


class RecorderLost(TxStoreError):
    """The sid's worker is gone; the job's outcome is decided by re-adoption from the DB."""


class Revoked(TxStoreError):
    """A sid counter moved or the sid was erased: the stream is aborted, never resumed."""


class NeedsReauth(TxStoreError):
    """A global counter moved, a fence is pending or `not_after` passed: re-run authorization."""


class Uncertain(Exception):
    """An exception at or after COMMIT: the outcome is read back from the DB."""


class _KillWorker(Exception):
    """Fault injection only: an exception outside a job's own handling (worker death)."""


def _sid_bytes(sid):
    if not isinstance(sid, str) or not _SID_RE.match(sid):
        raise TxStoreError("notFound", "bad sid")
    return bytes.fromhex(sid)


def gen_name(sid, kind, gen_hex, ext="wtx"):
    name = f"{sid}.{kind}.{gen_hex}.{ext}"
    # Numele trebuie să fie în spaţiul rezervat (aceeaşi definiţie ca restore şi inventarul).
    if not keys.is_reserved_name(name, "transcripts"):
        raise TxStoreError("bad-name", name)
    return name


def _list_digest(desc):
    h = hashlib.sha256()
    for g in desc.generations:
        h.update(g.gen_id + bytes([g.state]) + g.data_count.to_bytes(8, "little")
                 + g.plain_len.to_bytes(8, "little") + g.phys_len.to_bytes(8, "little") + g.hdr_mac)
    return h.digest()


def keyring_epoch_value(kwk, installation_id, epoch):
    """`tx_state.keyring_epoch` value (§12.11.0, M1): "epoch:mac-hex"."""
    mac = hmac.new(keyring.desc_key(kwk), b"wt/v1/kepoch" + installation_id + epoch.to_bytes(8, "little"),
                   hashlib.sha256).hexdigest()
    return f"{epoch}:{mac}"


def check_keyring_epoch(kwk, installation_id, file_epoch, value):
    """'ok' | 'rolled-back' (DB older than keys.wtk, or a bad MAC → quarantine) | 'newer' (restore)."""
    try:
        e, mac = value.split(":", 1)
        e = int(e)
    except (AttributeError, ValueError):
        return "rolled-back"
    if not hmac.compare_digest(keyring_epoch_value(kwk, installation_id, e), f"{e}:{mac}"):
        return "rolled-back"
    if e < file_epoch:
        return "rolled-back"
    return "newer" if e > file_epoch else "ok"


# ── 3.7 cap rule, on logical streams ─────────────────────────────────────────


def cap_streams(read_out, read_cast, out_end, cast_end, keep, fallback_ts, out_sink, cast_sink,
                abort=None):
    """Exactly 3.7's `_cap_build` content (core.py), over random-access readers of the logical
    `.out`/`.cast` streams (`read_x(offset, n) -> bytes`): `.out` = GAP_MARKER + the last `keep`
    bytes; `.cast` = header line (≤ CAP_HEADER_MAX) + gap event + whole lines of the last `keep`
    bytes, the gap timestamped with the first kept event. A reader of None = that kind is absent
    (a one-kind recording is capped on its own stream)."""
    def copy(read, sink, start, end):
        pos = start
        while pos < end:
            if abort is not None and abort.is_set():
                raise TxStoreError("aborted")
            buf = read(pos, min(CAP_CHUNK, end - pos))
            if not buf:
                raise TxStoreError("corrupt", "stream shorter than its descriptor")
            sink(buf)
            pos += len(buf)

    if read_out is not None:
        out_sink(GAP_MARKER)
        copy(read_out, out_sink, max(0, out_end - keep), out_end)
    if read_cast is None:
        return
    head = read_cast(0, min(CAP_HEADER_MAX, cast_end))
    nl = head.find(b"\n")
    if nl < 0:
        raise TxStoreError("corrupt", "asciicast header line missing or too long")
    header = head[:nl + 1]
    pos = max(len(header), cast_end - keep)
    if pos > len(header) and read_cast(pos - 1, 1) != b"\n":
        while pos < cast_end:
            buf = read_cast(pos, min(CAP_CHUNK, cast_end - pos))
            if not buf:
                break
            i = buf.find(b"\n")
            if i >= 0:
                pos += i + 1
                break
            pos += len(buf)
        pos = min(pos, cast_end)
    gap_ts = fallback_ts
    m = _CAST_TS_RE.match(read_cast(pos, min(64, cast_end - pos)) if pos < cast_end else b"")
    if m:
        try:
            gap_ts = json.loads(m.group(1))
        except ValueError:
            pass
    cast_sink(header)
    cast_sink((json.dumps([gap_ts, "o", GAP_MARKER.decode("utf-8", "replace")]) + "\n").encode())
    copy(read_cast, cast_sink, pos, cast_end)


def gap_event(ts):
    return (json.dumps([ts, "o", GAP_MARKER.decode("utf-8", "replace")]) + "\n").encode()


# ── small helpers ────────────────────────────────────────────────────────────


class _File:
    """The Writer's file object: one `os.write` per call (a short count = ambiguous write)."""

    def __init__(self, fd, store):
        self.fd = fd
        self._store = store

    def write(self, b):
        self._store._fault("write")
        return os.write(self.fd, b)


class _PRead:
    """File-like over an fd with its own position (pread): snapshots share nothing. `limit` is the
    physical end the parse may reach (the generation's committed `phys_len`): a record claiming a
    length past it gets a short read (corrupt) without any byte past the limit being read.
    `budget` (optional) is charged for every physical byte BEFORE the pread."""

    def __init__(self, fd, pos, limit=None, budget=None, hook=None):
        self.fd = fd
        self.pos = pos
        self.limit = limit
        self.budget = budget
        self.hook = hook

    def read(self, n):
        if self.limit is not None:
            n = max(0, min(n, self.limit - self.pos))
        if n == 0:
            return b""
        if self.budget is not None:
            self.budget.spend_phys(n)
        if self.hook is not None:
            self.hook()
        b = os.pread(self.fd, n, self.pos)
        self.pos += len(b)
        return b


class Budget:
    """Bytes a request may parse: `total` plaintext across every generation, `pre_first` before the
    first returned byte (None = the default for the path: 1 MiB with an index, max+keep without),
    and `phys` physical bytes read (default: the worst case of `total`, 1-byte records), charged
    before each read."""

    def __init__(self, total, pre_first=None, phys=None):
        self.total = total
        self.pre_first = pre_first
        self.phys = total * PHYS_PER_PLAIN + txformat.PREFIX_LEN if phys is None else phys
        self.used = 0
        self.phys_used = 0

    def spend(self, n):
        self.used += n
        if self.used > self.total:
            raise TxStoreError("limitExceeded", "request budget")

    def spend_phys(self, n):
        if self.phys_used + n > self.phys:
            raise TxStoreError("limitExceeded", "physical read budget")
        self.phys_used += n


@dataclass(frozen=True)
class Access:
    """Issued only by `Store.access` from the route's own authorization step; counters captured
    *before* the decision. `issuer` ties it to the Store (an Access built by hand is refused);
    `owner_recovery` is honoured only with `route == OWNER_RECOVERY_ROUTE`."""
    sid: str
    principal: str
    route: str
    sid_epoch: int
    access_epoch: int
    not_after: float = None
    owner_recovery: bool = False
    issuer: object = field(default=None, compare=False, repr=False)


def _same_grant(a, b):
    """A re-authorization may refresh counters and the deadline, never the grant's subject."""
    return (a.sid, a.principal, a.route, a.owner_recovery) == (b.sid, b.principal, b.route,
                                                               b.owner_recovery)


@dataclass
class _Gen:
    kind: str
    gen_id: bytes
    name: str
    fd: int
    writer: object
    dev: int
    ino: int
    published: bool = False
    broken: bool = False
    index: list = field(default_factory=list)
    next_index_at: int = 0


@dataclass
class RecoveryReport:
    removed_rows: list = field(default_factory=list)
    collisions: list = field(default_factory=list)
    unlinked: list = field(default_factory=list)
    recovered: list = field(default_factory=list)
    damaged: list = field(default_factory=list)
    orphans: list = field(default_factory=list)
    alarms: list = field(default_factory=list)

    def changed(self):
        return bool(self.removed_rows or self.collisions or self.unlinked or self.recovered
                    or self.damaged)


# ── Store ────────────────────────────────────────────────────────────────────


class Store:
    """Process-wide state: connections, barrier, leases, ledger, counters, readers' budgets."""

    def __init__(self, *, transcripts_dir, kwk, installation_id, db_path=None, env=None,
                 max_bytes=None, keep_bytes=None, gen_limits=None, op_gen_cap=OP_GEN_CAP,
                 pending_cap=PENDING_CAP, total_cap=REC_BUFFER_TOTAL, clock=time.time):
        env = os.environ if env is None else env
        # Starea minimă pentru close() înainte de orice deschidere (un refuz nu lasă resurse).
        self._w = self._r = None
        self.dir_fd = None
        self._snapshots = set()
        self._io_lock = threading.Lock()
        self._io_busy = 0
        self._closing = False
        self._released = False
        if not enabled(env):
            raise TxStoreError("disabled", f"{ENV_FLAG} is not 1")
        # PR5: activ doar pe un volum de test, şi doar sub o poartă de test (§12.11 PR5/PR6).
        # Poarta se verifică înaintea oricărei deschideri; DB-ul se deschide mode=rw (nu-l creează).
        if not test_gate(env):
            raise TxStoreError("disabled", "test volume outside a test gate")
        self._db_path, tdir, marker = _volume_binding(db_path or config.DB_PATH, transcripts_dir)
        try:
            self._r = self._connect()
            row = self._r.execute("SELECT value FROM tx_state WHERE key='test_volume'").fetchone()
            if row is None or not hmac.compare_digest(str(row[0]), marker):
                raise TxStoreError("disabled", "encrypted recordings need PR6 on a real volume")
            self._w = self._connect()
            self.dir_fd = os.open(tdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            # Identitatea EFECTIV deschisă (fd-ul directorului, DB-ul re-stat-at după conectare) e
            # cea din marker: o cale schimbată între verificare şi deschidere nu trece.
            dst = os.fstat(self.dir_fd)
            if (not marker.endswith(f":{dst.st_dev}:{dst.st_ino}:{tdir}")
                    or _volume_binding(self._db_path, tdir)[2] != marker):
                raise TxStoreError("disabled", "test volume identity changed while opening")
        except BaseException:
            self.close()
            raise
        self._rlock = threading.Lock()
        self._fd_lock = threading.Lock()
        self._issuer = object()
        self._slots = 0
        self._starting = set()
        self._shutting = False
        self.kwk = kwk
        self.inst = installation_id
        self.max_bytes = config.TRANSCRIPT_MAX_BYTES if max_bytes is None else max_bytes
        self.keep_bytes = config.TRANSCRIPT_KEEP_BYTES if keep_bytes is None else keep_bytes
        self.gen_limits = gen_limits or (txformat.MAX_DATA_RECORDS, txformat.MAX_PLAIN_BYTES)
        self.op_gen_cap = op_gen_cap
        self.pending_cap = pending_cap
        self.total_cap = total_cap
        self.clock = clock
        self.barrier = asyncio.Lock()
        self._leases = {}
        self.tokens = {}
        self.recorders = {}
        self.buffered_total = 0
        self.sid_epoch = collections.Counter()
        self.access_epoch = 0
        self._fences = {}                 # scope (sid | None) → [asyncio.Event]
        self.tombstoned = set()
        self._rk_cache = collections.OrderedDict()
        self._pins = collections.Counter()
        self._deferred = {}               # gen hex → (name, dev, ino)
        self._gen_fds = 0
        self._sem = None
        self._caches = []
        self.live_index = {}              # (sid, kind, gen hex) → [IndexEntry]
        self.alarms = []
        self.fault = None
        self.gen_id_source = os.urandom
        self._supervised = set()
        self.abandoned = []                      # shutdown: sid-uri cu worker abandonat (nu e curat)
        self.on_readopt = None
        self.readopt_enabled = True              # teste: un „crash" de proces nu se readoptă pe loc

    # ── plumbing ──

    def _connect(self):
        con = _connect_rw(self._db_path)
        con.execute("PRAGMA busy_timeout=5000")
        return con

    def close(self):
        """Logical close: every snapshot closed (their fds go when their last reader returns), no
        new I/O admitted; the connections and the directory fd are released when the last
        in-flight thread call has returned (never under a worker that still uses them)."""
        for s in list(self._snapshots):
            s.close()
        with self._io_lock:
            self._closing = True
            now = self._io_busy == 0
        if now:
            self._release()

    def _release(self):
        with self._io_lock:
            if self._released:
                return
            self._released = True
        for con in (self._w, self._r):
            if con is not None:
                with contextlib.suppress(Exception):
                    con.close()
        if self.dir_fd is not None:
            os.close(self.dir_fd)
            self.dir_fd = None

    def _io_done(self):
        with self._io_lock:
            self._io_busy -= 1
            last = self._closing and self._io_busy == 0
        if last:
            self._release()

    def _fault(self, point):
        if self.fault is not None:
            self.fault(point)

    def alarm(self, code, detail):
        # Cârligul pentru System health + audit (PR5b îl leagă); aici doar se reţine.
        self.alarms.append((code, detail))

    def lease(self, sid):
        lk = self._leases.get(sid)
        if lk is None:
            lk = self._leases[sid] = asyncio.Lock()
        return lk

    async def io(self, fn, *args, **kw):
        """Blocking I/O off the loop. A cancel does not abandon the thread: we wait until the
        call has really returned before propagating it, so fds and leases are never released
        while a thread is still inside write/fsync (§12.11.1 Supervision). A second (third…)
        cancel while waiting does not cut that wait short."""
        loop = asyncio.get_running_loop()

        def run():
            try:
                return fn(*args, **kw)
            finally:
                self._io_done()
        with self._io_lock:
            if self._closing:
                raise TxStoreError("closed", "store closed")
            self._io_busy += 1
        try:
            fut = loop.run_in_executor(None, run)
        except BaseException:
            self._io_done()
            raise
        try:
            return await asyncio.shield(fut)
        except asyncio.CancelledError:
            while not fut.done():
                try:
                    await asyncio.wait([fut])
                except asyncio.CancelledError:
                    continue
            raise

    def _run_txn(self, fn):
        cur = self._w.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            res = fn(cur)
        except BaseException:
            cur.execute("ROLLBACK")
            raise
        try:
            self._fault("pre-commit")
            cur.execute("COMMIT")
        except Exception as e:
            with contextlib.suppress(Exception):
                cur.execute("ROLLBACK")
            raise Uncertain(repr(e)) from e
        except BaseException:
            # Moartea procesului (teste: Crash) nu e un rezultat incert de rezolvat pe loc.
            with contextlib.suppress(Exception):
                cur.execute("ROLLBACK")
            raise
        try:
            self._fault("post-commit")
        except Exception as e:
            raise Uncertain(repr(e)) from e
        return res

    async def txn(self, fn):
        """One isolated transaction on txstore's own connection, under the barrier; the only
        await inside is the hop to the DB thread."""
        async with self.barrier:
            return await self.io(self._run_txn, fn)

    def _run_read(self, fn, con=None, lock=None):
        lock = lock or self._rlock
        with lock:
            con = con or self._r
            con.execute("BEGIN")
            try:
                return fn(con)
            finally:
                con.execute("COMMIT")

    async def read(self, fn):
        return await self.io(self._run_read, fn)

    def _fresh_read_sync(self, fn):
        con = self._connect()
        try:
            return self._run_read(fn, con=con, lock=threading.Lock())
        finally:
            con.close()

    async def fresh_read(self, fn):
        return await self.io(self._fresh_read_sync, fn)

    # ── keys ──

    def rk_for(self, sid, envelope):
        h = keyring.envelope_hash(envelope)
        hit = self._rk_cache.get(sid)
        if hit is not None and hit[0] == h:
            self._rk_cache.move_to_end(sid)
            return hit[1]
        try:
            rk = keyring.unwrap_under_kwk(self.kwk, envelope, keyring.KT_RK)
        except keyring.KeyringError as e:
            self.alarm("transcript.keyError", f"{sid}: {e.reason}")
            raise TxStoreError("keyError", e.reason) from None
        self._rk_cache[sid] = (h, rk)
        while len(self._rk_cache) > RK_CACHE_MAX:
            self._rk_cache.popitem(last=False)
        return rk

    def drop_key(self, sid):
        self._rk_cache.pop(sid, None)

    async def ensure_rk(self, sid):
        """Caller holds the sid's lease. Returns (envelope, rk); draws and commits the RK when the
        session has none (lease → barrier, before any generation is reserved)."""
        row = await self.read(lambda c: c.execute("SELECT envelope FROM session_keys WHERE sid=?",
                                                  (sid,)).fetchone())
        if row is None:
            rk = secrets.token_bytes(32)
            env = keyring.wrap_under_kwk(self.kwk, keyring.KT_RK, rk)

            def ins(cur):
                cur.execute("INSERT INTO session_keys(sid, envelope, created, origin) "
                            "VALUES(?,?,?,'session')", (sid, env, self.clock()))
            await self.txn(ins)
            self._fault("rk-committed")
            return env, self.rk_for(sid, env)
        return bytes(row[0]), self.rk_for(sid, bytes(row[0]))

    def decode(self, row, sid, kind, envelope):
        """(Descriptor) from a tx_descriptors row (blob, version); version column must match."""
        try:
            d = txdesc.decode_descriptor(bytes(row[0]), self.kwk, installation_id=self.inst,
                                         sid=_sid_bytes(sid), kind=KINDS[kind], rk_envelope=envelope)
        except txdesc.DescriptorError as e:
            # Legătura cu plicul RK ruptă = defect de cheie (hub refuzat), nu descriptor stricat.
            if e.reason in ("rk-mismatch", "bad-rk-envelope"):
                raise TxStoreError("keyError", f"{sid}.{kind}: {e.reason}") from None
            raise TxStoreError("damaged", f"{sid}.{kind}: {e.reason}") from None
        if d.version != row[1]:
            raise TxStoreError("damaged", f"{sid}.{kind}: version column {row[1]} != {d.version}")
        return d

    def encode(self, d):
        return txdesc.encode_descriptor(d, self.kwk)

    # ── directory / ledger ──

    def _lstat(self, name):
        try:
            return os.stat(name, dir_fd=self.dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def _unlink_if_ours_sync(self, name, dev, ino):
        """Unlink only the inode the ledger recorded at our O_EXCL create."""
        st = self._lstat(name)
        if st is None:
            return "absent"
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (dev, ino):
            return "mismatch"
        os.unlink(name, dir_fd=self.dir_fd)
        os.fsync(self.dir_fd)
        return "unlinked"

    def _drop_idx_sync(self, sid, kind, hexid):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(gen_name(sid, kind, hexid, "idx"), dir_fd=self.dir_fd)

    async def retire(self, sid, kind, hexid):
        """Unlink a generation whose ledger row is `retired` (deferred while pinned); row → gone.
        Never a generation an authentic descriptor lists (the caller published without it)."""
        if self._pins[hexid]:
            self._deferred[hexid] = (sid, kind)
            return "deferred"
        self._fault("retire")
        row = await self.read(lambda c: c.execute(
            "SELECT state, dev, ino FROM tx_files WHERE gen_id=?", (hexid,)).fetchone())
        if row is None or row[0] != "retired":
            return "not-retired"
        if self._pins[hexid]:
            # Un pin luat cât am citit registrul: amânat, niciodată şters sub un cititor.
            self._deferred[hexid] = (sid, kind)
            return "deferred"
        res = await self.io(self._unlink_if_ours_sync, gen_name(sid, kind, hexid), row[1], row[2])
        await self.io(self._drop_idx_sync, sid, kind, hexid)
        if res == "mismatch":
            self.alarm("transcript.orphan", f"{sid}.{kind}.{hexid}: inode differs, left in place")
            return res
        await self.txn(lambda c: c.execute("UPDATE tx_files SET state='gone' WHERE gen_id=? "
                                           "AND state='retired'", (hexid,)))
        return res

    @contextlib.contextmanager
    def pinned(self, hexids):
        hexids = list(hexids)
        for h in hexids:
            self._pins[h] += 1
        try:
            yield
        finally:
            for h in hexids:
                self._pins[h] -= 1
                if self._pins[h] <= 0:
                    del self._pins[h]
                    later = self._deferred.pop(h, None)
                    if later is not None:
                        asyncio.get_running_loop().create_task(self.retire(later[0], later[1], h))

    async def reserve_and_create(self, sid, kind):
        """Reservation → O_EXCL create → ledger `created` with the inode. Caller holds the lease.
        Returns (gen_id, fd, dev, ino, name)."""
        for _ in range(16):
            gid = self.gen_id_source(16)
            hexid = gid.hex()
            name = gen_name(sid, kind, hexid)
            try:
                await self.txn(lambda c: c.execute(
                    "INSERT INTO tx_files(gen_id, sid, kind, state, created) "
                    "VALUES(?,?,?,'reserved',?)", (hexid, sid, kind, self.clock())))
            except sqlite3.IntegrityError:
                continue                          # gen_id deja rezervat: alt id
            self._fault("reserved")
            try:
                fd = await self.io(os.open, name, _CREATE, 0o600, dir_fd=self.dir_fd)
            except FileExistsError:
                # Fişierul existent NU e al nostru: nu-l ştergem niciodată, doar îl raportăm.
                await self.txn(lambda c: c.execute(
                    "UPDATE tx_files SET state='collision' WHERE gen_id=?", (hexid,)))
                self.alarm("transcript.orphan", f"{name}: exists before our O_EXCL create")
                continue
            try:
                st = os.fstat(fd)
                self._fault("created-unrecorded")
                await self.txn(lambda c: c.execute(
                    "UPDATE tx_files SET state='created', dev=?, ino=? WHERE gen_id=? "
                    "AND state='reserved'", (st.st_dev, st.st_ino, hexid)))
            except Exception:
                # Eşec în proces (nu moartea lui): fişierul e al nostru (fd-ul O_EXCL, inode-ul lui),
                # deci se şterge acum; rândul `reserved` rămâne pentru recuperare dacă DB-ul nu merge.
                with contextlib.suppress(Exception):
                    st2 = os.fstat(fd)
                    await self.io(self._unlink_if_ours_sync, name, st2.st_dev, st2.st_ino)
                    await self.txn(lambda c: c.execute(
                        "DELETE FROM tx_files WHERE gen_id=? AND state='reserved'", (hexid,)))
                os.close(fd)
                raise
            except BaseException:
                os.close(fd)
                raise
            return gid, fd, st.st_dev, st.st_ino, name
        raise TxStoreError("collision", "could not reserve a fresh generation id")

    # ── recovery (§12.11.1 table) ──

    async def recover(self, sid=None):
        """Crash recovery for every sid (boot) or one (writer start, re-adoption). Idempotent."""
        rep = RecoveryReport()

        def load(c):
            q = " WHERE sid=?" if sid else ""
            a = (sid,) if sid else ()
            return (c.execute("SELECT gen_id, sid, kind, state, dev, ino FROM tx_files" + q, a).fetchall(),
                    c.execute("SELECT sid, kind, blob, version, status FROM tx_descriptors" + q, a).fetchall(),
                    dict(c.execute("SELECT sid, envelope FROM session_keys" + q, a).fetchall()))
        ledger, drows, envs = await self.read(load)
        names = await self.io(os.listdir, self.dir_fd)
        listed = {}                               # gen hex → (sid, kind, Generation)
        descs = {}
        undecodable = set()
        for s, k, blob, version, status in drows:
            env = envs.get(s)
            try:
                if env is None:
                    raise TxStoreError("keyError", "no RK")
                d = self.decode((blob, version), s, k, bytes(env))
            except TxStoreError as e:
                # Lista lui de generaţii nu se poate autentifica: nimic din registrul acestui sid
                # nu se şterge în pasul ăsta (fail closed), doar alarmă.
                undecodable.add(s)
                if e.reason == "keyError":
                    rep.alarms.append(("keyError", f"{s}.{k}"))
                    self.alarm("transcript.keyError", f"{s}.{k}: {e}")
                    continue
                if status == "damaged":
                    continue
                rep.damaged.append((s, k, e.reason))
                await self.txn(lambda c, s=s, k=k: c.execute(
                    "UPDATE tx_descriptors SET status='damaged' WHERE sid=? AND kind=?", (s, k)))
                self.alarm("transcript.damaged", f"{s}.{k}: {e}")
                continue
            descs[(s, k)] = (d, bytes(blob), status)
            for g in d.generations:
                listed[g.gen_id.hex()] = (s, k, g)
        known = set()
        for hexid, s, k, state, dev, ino in ledger:
            known.add(hexid)
            if s in undecodable:
                continue
            name = gen_name(s, k, hexid)
            st = self._lstat(name)
            if hexid in listed and state != "published":
                rep.alarms.append(("ledger-listed", hexid))
                self.alarm("transcript.integrity", f"{name}: ledger {state} but listed")
                continue
            if state == "reserved":
                if st is None:
                    await self.txn(lambda c, h=hexid: c.execute(
                        "DELETE FROM tx_files WHERE gen_id=? AND state='reserved'", (h,)))
                    rep.removed_rows.append(hexid)
                else:
                    await self.txn(lambda c, h=hexid: c.execute(
                        "UPDATE tx_files SET state='collision' WHERE gen_id=?", (h,)))
                    rep.collisions.append(hexid)
                    rep.orphans.append(name)
            elif state in ("created", "retired"):
                res = await self.io(self._unlink_if_ours_sync, name, dev, ino) \
                    if dev is not None else ("absent" if st is None else "mismatch")
                await self.io(self._drop_idx_sync, s, k, hexid)
                if res == "mismatch":
                    await self.txn(lambda c, h=hexid: c.execute(
                        "UPDATE tx_files SET state='collision' WHERE gen_id=?", (h,)))
                    rep.collisions.append(hexid)
                    rep.orphans.append(name)
                else:
                    await self.txn(lambda c, h=hexid: c.execute(
                        "UPDATE tx_files SET state='gone' WHERE gen_id=?", (h,)))
                    if res == "unlinked":
                        rep.unlinked.append(name)
            elif state == "published" and hexid not in listed:
                rep.alarms.append(("published-unlisted", hexid))
                self.alarm("transcript.integrity", f"{name}: published but not listed")
        # Descriptori: fişiere lipsă/scurte → damaged; un `live` → `recovered` la contoarele lui.
        for (s, k), (d, blob, status) in descs.items():
            if status == "damaged":
                continue
            bad = None
            for g in d.generations:
                st = self._lstat(gen_name(s, k, g.gen_id.hex()))
                if st is None or not stat.S_ISREG(st.st_mode) or st.st_size < g.phys_len:
                    bad = g.gen_id.hex()
                    break
            if bad:
                rep.damaged.append((s, k, "missing-or-short " + bad))
                await self.txn(lambda c, s=s, k=k: c.execute(
                    "UPDATE tx_descriptors SET status='damaged' WHERE sid=? AND kind=?", (s, k)))
                self.alarm("transcript.damaged", f"{s}.{k}: generation {bad} missing or short")
                continue
            gens = list(d.generations)
            if gens and gens[-1].state == txdesc.STATE_LIVE:
                last = gens[-1]
                gens[-1] = txdesc.Generation(last.gen_id, txdesc.STATE_RECOVERED, last.data_count,
                                             last.plain_len, last.phys_len, last.hdr_mac)
                nd = txdesc.Descriptor(d.installation_id, d.sid, d.kind, d.version + 1, d.rk_hash,
                                       tuple(gens), d.flags)
                nb = self.encode(nd)

                def pub(c, s=s, k=k, old=blob, nb=nb, v=nd.version):
                    r = c.execute("SELECT blob FROM tx_descriptors WHERE sid=? AND kind=?",
                                  (s, k)).fetchone()
                    if r is None or bytes(r[0]) != old:
                        raise Refused("cas", "descriptor changed during recovery")
                    c.execute("UPDATE tx_descriptors SET blob=?, version=? WHERE sid=? AND kind=?",
                              (nb, v, s, k))
                await self.txn(pub)
                rep.recovered.append((s, k, last.gen_id.hex()))
        # Fişiere fără rând în registru (sau index-uri temporare): orfani / cache-uri.
        for n in names:
            m = _NAME_RE.match(n)
            if m and (sid is None or m.group(1) == sid):
                if m.group(4) == "wtx" and m.group(3) not in known:
                    rep.orphans.append(n)
                elif m.group(4) == "idx" and m.group(3) not in listed:
                    if m.group(3) in known:
                        await self.io(self._drop_idx_sync, m.group(1), m.group(2), m.group(3))
                    else:
                        rep.orphans.append(n)
                continue
            t = _TMP_IDX_RE.match(n)
            if t and (sid is None or t.group(1) == sid) and t.group(3) in known:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(n, dir_fd=self.dir_fd)
            elif keys.is_reserved_name(n, "transcripts") and (sid is None or n.startswith(sid)):
                rep.orphans.append(n)
        for o in rep.orphans:
            self.alarm("transcript.orphan", o)
        return rep

    async def compact_ledger(self, now=None):
        cutoff = (self.clock() if now is None else now) - LEDGER_KEEP_SECS

        def fn(c):
            return c.execute("DELETE FROM tx_files WHERE state IN ('gone','collision') AND created < ?",
                             (cutoff,)).rowcount
        return await self.txn(fn)

    # ── recorders and supervision ──

    async def start_recorder(self, sid, *, track_agent=True):
        """One writer per sid: the start is reserved synchronously (before any await), so two
        concurrent starts cannot both pass the check and the second never runs recovery over the
        first's fresh generations."""
        if self._shutting:
            raise TxStoreError("disabled", "store shutting down")
        old = self.recorders.get(sid)
        if sid in self._starting or (old is not None and old.state == "running"):
            raise TxStoreError("busy", "recorder already running")
        self._starting.add(sid)
        try:
            rec = Recorder(self, sid, track_agent=track_agent)
            await rec._start()
            self.recorders[sid] = rec
            t = asyncio.get_running_loop().create_task(self._supervise(rec))
            self._supervised.add(t)
            t.add_done_callback(self._supervised.discard)
            return rec
        finally:
            self._starting.discard(sid)

    async def _supervise(self, rec):
        await asyncio.wait([rec._task])
        if not rec._task.cancelled():
            rec._task.exception()                 # recuperată: decizia o ia starea, nu excepţia
        if rec.state != "lost":
            return
        # Worker pierdut: fd-urile se închid abia după ce I/O-ul blocant s-a întors (io() aşteaptă
        # thread-ul), apoi sid-ul e readoptat DOAR din DB (§12.11.1 Supervision).
        rec._close_fds()
        if self.tokens.get(rec.sid) == rec.token:
            del self.tokens[rec.sid]
        self.alarm("transcript.recorderLost", rec.sid)
        if self.recorders.get(rec.sid) is rec:
            del self.recorders[rec.sid]
        if not self.readopt_enabled or self._shutting:
            return
        try:
            new = await self.start_recorder(rec.sid, track_agent=rec.track_agent)
        except Exception as e:
            self.alarm("transcript.readoptFailed", f"{rec.sid}: {e}")
            return
        if self.on_readopt is not None:
            self.on_readopt(rec.sid, new)

    async def shutdown(self):
        """Close every recorder (bounded), then stop the remaining workers and WAIT for them (their
        blocking calls included) before their fds are closed. A worker still stuck after the
        bound is abandoned with its fds left open (never reused under it) and an alarm. Returns the
        sids whose worker was abandoned (empty = a clean finalisation); a non-empty result also
        stays in `abandoned`, and the integration must not reuse this Store."""
        self._shutting = True
        for rec in list(self.recorders.values()):
            if rec.state != "running":
                continue
            try:
                await asyncio.wait_for(rec.close(), SHUTDOWN_SECS)
            except (Exception, asyncio.TimeoutError) as e:  # noqa: BLE001
                self.alarm("transcript.shutdown", f"{rec.sid}: close failed: {e!r}")
        for t in list(self._supervised):
            t.cancel()
        tasks = {rec: rec._task for rec in self.recorders.values()
                 if rec._task is not None and not rec._task.done()}
        for t in tasks.values():
            t.cancel()
        if tasks:
            await asyncio.wait(list(tasks.values()), timeout=SHUTDOWN_SECS)
        for rec, t in tasks.items():
            if t.done():
                rec._close_fds()
            else:
                self.abandoned.append(rec.sid)
                self.alarm("transcript.shutdown", f"{rec.sid}: worker still blocked; fds abandoned")
        return list(self.abandoned)

    # ── revocation counters and fences (§12.11.2) ──

    def _bump(self, sid):
        if sid is None:
            self.access_epoch += 1
        else:
            self.sid_epoch[sid] += 1
        for c in self._caches:
            c.drop(sid)

    def bump(self, sid=None):
        """Synchronous, on the loop: a revocation of `sid` (or a global access change)."""
        self._bump(sid)

    @contextlib.asynccontextmanager
    async def revoking(self, sid=None):
        """Bump + fence BEFORE the access-reducing commit, bump again and clear after it."""
        ev = asyncio.Event()
        self._fences.setdefault(sid, []).append(ev)
        self._bump(sid)
        try:
            yield
        finally:
            self._bump(sid)
            self._fences[sid].remove(ev)
            if not self._fences[sid]:
                del self._fences[sid]
            ev.set()

    async def wait_fences(self, sid):
        for scope in (sid, None):
            for ev in list(self._fences.get(scope, ())):
                await ev.wait()

    def tombstone(self, sid):
        """In-memory erasure marker (the journal is PR6); bumps the sid in the same tick."""
        self.tombstoned.add(sid)
        self._bump(sid)
        self.drop_key(sid)

    def access(self, sid, principal, route, *, not_after=None, owner_recovery=False):
        """Capture the counters BEFORE the route's authorization decision. Owner recovery is a
        property of the recovery route itself (§12.11.4), never a flag another route can set."""
        if owner_recovery and route != OWNER_RECOVERY_ROUTE:
            raise TxStoreError("bad-access", "owner recovery only from the recovery route")
        return Access(sid, principal, route, self.sid_epoch[sid], self.access_epoch, not_after,
                      owner_recovery, self._issuer)

    def check(self, access):
        """The synchronous check (linearisation point at open; check points (a)–(c))."""
        if not isinstance(access, Access) or access.issuer is not self._issuer:
            raise TxStoreError("bad-access", "access not issued by this store")
        if access.owner_recovery and access.route != OWNER_RECOVERY_ROUTE:
            raise TxStoreError("bad-access", "owner recovery only from the recovery route")
        sid = access.sid
        if sid in self.tombstoned or self.sid_epoch[sid] != access.sid_epoch or sid in self._fences:
            raise Revoked("revoked", sid)
        if None in self._fences or self.access_epoch != access.access_epoch:
            raise NeedsReauth("reauth", "access changed")
        if access.not_after is not None and self.clock() >= access.not_after:
            raise NeedsReauth("expired", "access expired")

    # ── readers ──

    def _reserve(self, nfds, *, force=False):
        """Atomic admission: one snapshot slot and `nfds` generation fds are reserved BEFORE any fd
        is opened (released when the snapshot's fds are really closed). `force` (compaction, an
        internal job) counts without refusing."""
        with self._fd_lock:
            if not force and (self._slots >= MAX_SNAPSHOTS or self._gen_fds + nfds > MAX_GEN_FDS):
                raise TxStoreError("busy", "snapshot budget")
            self._slots += 1
            self._gen_fds += nfds

    def _unreserve(self, nfds):
        with self._fd_lock:
            self._slots -= 1
            self._gen_fds -= nfds

    async def _make_snapshot(self, cls, *args, nfds, force=False):
        """Reserve, construct and REGISTER on the loop (so `close()` sees a snapshot still being
        built), open the fds on a thread inside the fd guard, then re-check synchronously before
        returning: a Store closed (or the snapshot closed) meanwhile gets nothing. Any failure or
        cancel closes it (io() returns only after the thread did, so nothing built is abandoned)."""
        if self._closing:
            raise TxStoreError("closed", "store closed")
        self._reserve(nfds, force=force)
        snap = cls(self, *args, reserved=nfds)
        self._snapshots.add(snap)
        try:
            await self.io(snap._open_guarded)
            if self._closing or snap.closed:
                raise TxStoreError("closed", "store closed while opening")
        except BaseException:
            snap.close()
            raise
        return snap

    @contextlib.asynccontextmanager
    async def worker_slot(self):
        if self._sem is None:
            self._sem = asyncio.Semaphore(READ_WORKERS)
        try:
            await asyncio.wait_for(self._sem.acquire(), READ_WAIT_SECS)
        except asyncio.TimeoutError:
            raise TxStoreError("busy", "decrypt workers") from None
        try:
            yield
        finally:
            self._sem.release()

    async def open(self, sid, kind, *, access, reauthorize=None):
        """Snapshot of the committed (sid, kind); see the module docstring. A failed check at the
        linearisation point closes every fd and retries once from `reauthorize()` (the route's
        own authorization, which returns a fresh Access); a second failure is refused."""
        first = access
        for attempt in (0, 1):
            if access.sid != sid:
                raise TxStoreError("bad-access", "access built for another sid")
            if not _same_grant(first, access):
                raise Revoked("bad-access", "re-authorization changed the grant")
            snap = await self._open_once(sid, kind, access)
            try:
                self.check(access)               # linearisation point: după ce fd-urile sunt deschise
                return snap
            except (Revoked, NeedsReauth):
                snap.close()
                if attempt == 1 or reauthorize is None:
                    raise Revoked("revoked", "access changed while opening") from None
                await self.wait_fences(sid)
                access = await reauthorize()
            except BaseException:
                snap.close()
                raise
        raise Revoked("revoked")                  # pragma: no cover

    async def _open_once(self, sid, kind, access):
        if kind not in KINDS:
            raise TxStoreError("notFound", "kind")
        _sid_bytes(sid)
        if not isinstance(access, Access) or access.issuer is not self._issuer:
            raise TxStoreError("bad-access", "access not issued by this store")
        if sid in self.tombstoned:
            raise TxStoreError("notFound", "erased")

        def load(c):
            return (c.execute("SELECT blob, version, status, list_epoch FROM tx_descriptors "
                              "WHERE sid=? AND kind=?", (sid, kind)).fetchone(),
                    c.execute("SELECT envelope FROM session_keys WHERE sid=?", (sid,)).fetchone(),
                    c.execute("SELECT dir, name, dev, ino, size, mtime_ns, state FROM tx_migration "
                              "WHERE sid=? AND kind=?", (sid, kind)).fetchone(),
                    c.execute("SELECT value FROM tx_state WHERE key='recordings_format'").fetchone())
        drow, krow, mrow, fmt = await self.read(load)
        if drow is None:
            return await self._open_plain(sid, kind, access, krow, mrow, fmt)
        status = drow[2]
        if status in ("damaged", "absent"):
            raise TxStoreError("damaged", f"{sid}.{kind}: {status}")
        # `quarantined` nu-şi codifică motivul (continuitate / epoch keyring / restore): refuzat
        # pentru oricine. Owner recovery deschide DOAR `recovery` (carantina de continuitate pe
        # care ruta de recuperare a ridicat-o explicit, §12.11.4).
        if status == "quarantined" or (status == "recovery" and not access.owner_recovery):
            raise TxStoreError("quarantined", f"{sid}.{kind}")
        if status not in ("ok", "recovery"):
            raise TxStoreError("damaged", f"{sid}.{kind}: unknown status")
        if krow is None:
            self.alarm("transcript.keyError", f"{sid}: descriptor without RK")
            raise TxStoreError("keyError", "no RK")
        env = bytes(krow[0])
        d = self.decode(drow, sid, kind, env)
        rk = self.rk_for(sid, env)
        return await self._make_snapshot(Snapshot, sid, kind, d, rk, drow[3], access,
                                         nfds=len(d.generations))

    async def _open_plain(self, sid, kind, access, krow, mrow, fmt):
        """3.7 plaintext only while inventoried `pending` and identical; otherwise a downgrade."""
        legacy = sid + "." + kind
        exists = self._lstat(legacy) is not None
        if mrow is None:
            if exists:
                self.alarm("transcript.downgrade", f"{sid}.{kind}: plaintext outside the inventory")
                raise TxStoreError("downgrade", "plaintext not in the migration inventory")
            raise TxStoreError("notFound", f"{sid}.{kind}")
        dirn, name, dev, ino, size, mtime_ns, state = mrow
        if state != "pending" or krow is not None or (fmt is not None and fmt[0] == "wtx1"):
            self.alarm("transcript.downgrade", f"{sid}.{kind}: plaintext for a converted recording")
            raise TxStoreError("downgrade", "recording is not plaintext any more")
        # Numele inventarului trebuie să fie exact al acestui (sid, kind): un rând care arată spre
        # alt fişier (alt sid, alt kind) nu devine o cale de citire.
        if dirn not in ("transcripts", "arhiva") or name != legacy:
            self.alarm("transcript.downgrade", f"{sid}.{kind}: inventory row names another file")
            raise TxStoreError("downgrade", "bad inventory row")
        return await self._make_snapshot(PlainSnapshot, sid, kind, dirn, name,
                                         (dev, ino, size, mtime_ns), access, nfds=1)

    def _plain_still_pending(self, sid, kind, ident):
        """Re-read, after the fd is fixed, that the recording is still plaintext-pending for
        exactly this inode (a conversion committed meanwhile wins: downgrade refused)."""
        def load(c):
            return (c.execute("SELECT 1 FROM tx_descriptors WHERE sid=? AND kind=?", (sid, kind)).fetchone(),
                    c.execute("SELECT 1 FROM session_keys WHERE sid=?", (sid,)).fetchone(),
                    c.execute("SELECT dev, ino, size, mtime_ns, state FROM tx_migration "
                              "WHERE sid=? AND kind=?", (sid, kind)).fetchone(),
                    c.execute("SELECT value FROM tx_state WHERE key='recordings_format'").fetchone())
        drow, krow, mrow, fmt = self._run_read(load)
        return (drow is None and krow is None and (fmt is None or fmt[0] != "wtx1")
                and mrow is not None and mrow[4] == "pending" and tuple(mrow[:4]) == tuple(ident))

    async def tail(self, sid, kind, limit, *, access, end=None, reauthorize=None):
        """(bytes, end, list_epoch) of the last `limit` committed bytes, or up to `end`."""
        snap = await self.open(sid, kind, access=access, reauthorize=reauthorize)
        try:
            e = snap.length if end is None else max(0, min(end, snap.length))
            data = await snap.read(max(0, e - limit), e,
                                   budget=Budget(PARSE_WITH_INDEX + limit + self.max_bytes
                                                 + self.keep_bytes))
            return data, e, snap.list_epoch
        finally:
            snap.close()

    async def search_tail(self, sid, *, access, budget):
        """`search_transcripts`' read: ≤ SEARCH_READ_CAP per session, SEARCH_TOTAL_CAP counted on
        decrypted bytes per query. None = past the budget (metadata only, as today)."""
        if budget["used"] >= SEARCH_TOTAL_CAP or budget["results"] >= SEARCH_MAX_RESULTS:
            return None
        want = min(SEARCH_READ_CAP, SEARCH_TOTAL_CAP - budget["used"])
        data, _e, _g = await self.tail(sid, "out", want, access=access)
        budget["used"] += len(data)
        return data

    def sweep_idle(self):
        now = time.monotonic()
        for s in list(self._snapshots):
            if now - s.last_used > SNAPSHOT_IDLE_SECS:
                s.close()

    # ── descriptor data, no file I/O ──

    async def exists(self, sid, kind):
        row = await self.read(lambda c: c.execute(
            "SELECT status FROM tx_descriptors WHERE sid=? AND kind=?", (sid, kind)).fetchone())
        return row is not None and row[0] == "ok" and sid not in self.tombstoned

    async def last_output_at(self, sid):
        row = await self.read(lambda c: c.execute(
            "SELECT committed_at FROM tx_descriptors WHERE sid=? AND kind='out'", (sid,)).fetchone())
        return row[0] if row else None

    async def stats(self):
        """Σ phys_len over the authentic descriptors (replaces the stat-walk)."""
        def load(c):
            return (c.execute("SELECT sid, kind, blob, version FROM tx_descriptors").fetchall(),
                    dict(c.execute("SELECT sid, envelope FROM session_keys").fetchall()))
        rows, envs = await self.read(load)
        total = n = 0
        for s, k, blob, v in rows:
            if s not in envs:
                continue
            try:
                d = self.decode((blob, v), s, k, bytes(envs[s]))
            except TxStoreError:
                continue
            n += 1
            total += sum(g.phys_len for g in d.generations)
        return {"recordings": n, "bytes": total}

    # ── full integrity check ──

    async def verify(self, sid, *, budget=VERIFY_PASS_BYTES, cursor=None):
        """Full integrity report of a session (never on a request path). Returns a dict with
        `ok`, `problems`, `info` and, when the pass budget ran out, `cursor` to resume from (it is
        discarded when a descriptor version changed)."""
        return await self.io(self._verify_sync, sid, budget, cursor)

    def _verify_sync(self, sid, budget, cursor):
        def load(c):
            return (c.execute("SELECT kind, blob, version FROM tx_descriptors WHERE sid=?",
                              (sid,)).fetchall(),
                    c.execute("SELECT envelope FROM session_keys WHERE sid=?", (sid,)).fetchone())
        rows, krow = self._run_read(load)
        rep = {"ok": True, "problems": [], "info": [], "cursor": None}
        if krow is None:
            if rows:
                rep["ok"] = False
                rep["problems"].append("descriptor without RK")
            return rep
        env = bytes(krow[0])
        rk = self.rk_for(sid, env)
        descs = {}
        for k, blob, v in rows:
            try:
                descs[k] = self.decode((blob, v), sid, k, env)
            except TxStoreError as e:
                rep["ok"] = False
                rep["problems"].append(f"{k}: {e}")
        if len(descs) == 1:
            rep["info"].append("one kind only")
        versions = {k: d.version for k, d in descs.items()}
        if cursor is not None and cursor.get("versions") != versions:
            cursor = None                         # descriptorul s-a schimbat: o luăm de la capăt
        start = (cursor or {}).get("at", (0, 0))
        spent = 0
        rep["limitExceeded"] = []
        for ki, k in enumerate(KIND_NAMES):
            d = descs.get(k)
            if d is None:
                continue
            for gi, g in enumerate(d.generations):
                if (ki, gi) < tuple(start):
                    continue
                # Bugetul e tare şi pe octeţi fizici: o generaţie mai mare decât o trecere întreagă
                # NU se verifică pe calea asta (raportată limitExceeded, raportul nu e complet);
                # una care nu mai încape în trecerea curentă → cursor.
                if g.phys_len > budget:
                    rep["limitExceeded"].append(f"{k}.{g.gen_id.hex()}")
                    continue
                if spent + g.phys_len > budget:
                    rep["cursor"] = {"versions": versions, "at": (ki, gi)}
                    return _verify_done(rep)
                spent += g.phys_len
                prob, info = self._verify_gen(sid, k, g, rk)
                if prob:
                    rep["ok"] = False
                    rep["problems"].append(f"{k}.{g.gen_id.hex()}: {prob}")
                if info:
                    rep["info"].append(f"{k}.{g.gen_id.hex()}: {info}")
        return _verify_done(rep)

    def _verify_gen(self, sid, kind, g, rk):
        try:
            fd = os.open(gen_name(sid, kind, g.gen_id.hex()), _RDONLY, dir_fd=self.dir_fd)
        except OSError as e:
            return f"missing ({e.strerror})", None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                return "not a regular single-link file", None
            if st.st_size < g.phys_len:
                return "shorter than phys_len", None
            # Parsarea nu citeşte niciun octet peste prefixul comis (phys_len).
            fp = _PRead(fd, 0, limit=g.phys_len)
            try:
                txformat.verify_header(fp.read(txformat.PREFIX_LEN), txformat.generation_keys(
                    rk, KINDS[kind], g.gen_id), kind=KINDS[kind], sid=_sid_bytes(sid), gen_id=g.gen_id)
                if not hmac.compare_digest(os.pread(fd, 32, 64), g.hdr_mac):
                    return "hdr-mac-mismatch", None
                cur = txformat.RecordCursor(fp, rk, kind=KINDS[kind], gen_id=g.gen_id,
                                            hdr_mac=g.hdr_mac, data_count=g.data_count)
                while cur.next() is not None:
                    pass
                if cur.logical_offset != g.plain_len:
                    return "plain-len-mismatch", None
                if g.state == txdesc.STATE_SEALED:
                    info = cur.seal()
                    if info.phys_len != g.phys_len:
                        return "phys-len-mismatch", None
                    if os.pread(fd, 1, g.phys_len):
                        return "trailing-bytes", None
                    return None, None
                if st.st_size > g.phys_len:
                    return None, "trailing bytes past the committed prefix (ignored)"
                if g.state == txdesc.STATE_RECOVERED:
                    return None, "ended by interruption"
                return None, None
            except txformat.TxFormatError as e:
                return e.reason, None
        finally:
            os.close(fd)


def _verify_done(rep):
    if rep["limitExceeded"]:
        # Neverificat ≠ verificat: raportul nu poate spune „ok" (fail closed).
        rep["ok"] = False
        rep["problems"].append("limitExceeded: " + ", ".join(rep["limitExceeded"]))
    return rep


# ── Snapshot ─────────────────────────────────────────────────────────────────


class _FdOwner:
    """fd lifetime shared by both snapshot kinds: a worker uses the fds only inside `_using()`
    (a refcount under a lock); `close()` is logical (cancel + no new user) and the fds are
    physically closed by whoever leaves last, so an fd number is never released while a thread
    may still pread it (and so never reused under it)."""

    def _init_owner(self, store, reserved):
        self.store = store
        self._reserved = reserved
        self._lk = threading.Lock()
        self._users = 0
        self._released = False
        self.closed = False
        self.cancel = threading.Event()
        self.last_used = time.monotonic()

    def _enter(self):
        with self._lk:
            if self.closed:
                raise TxStoreError("closed", "snapshot closed")
            self._users += 1

    def _leave(self):
        with self._lk:
            self._users -= 1
            last = self.closed and self._users == 0 and not self._released
            if last:
                self._released = True
        if last:
            self._release_fds()

    @contextlib.contextmanager
    def _using(self):
        self._enter()
        try:
            yield
        finally:
            self._leave()

    def _open_guarded(self):
        # Deschiderea fd-urilor e ea însăşi un „utilizator": un close() concurent (Store.close,
        # sweep) nu eliberează lista cât timp thread-ul încă adaugă fd-uri; ultimul care iese le închide.
        with self._using():
            self._open_fds()

    def close(self):
        with self._lk:
            if self.closed:
                return
            self.closed = True
            self.cancel.set()
            now = self._users == 0 and not self._released
            if now:
                self._released = True
        self.store._snapshots.discard(self)
        if now:
            self._release_fds()

    def _release_fds(self):
        try:
            for fd in self._fds():
                with contextlib.suppress(OSError):
                    os.close(fd)
        finally:
            self.store._unreserve(self._reserved)

    def _hook(self):
        self.store._fault("pread")


class Snapshot(_FdOwner):
    """Fds, descriptor and counters of one (sid, kind) fixed at open. Unlinked inodes stay
    readable through the fds, so a concurrent cap / merge / purge cannot change what it reads."""

    def __init__(self, store, sid, kind, desc, rk, list_epoch, access, *, reserved=0):
        self._init_owner(store, reserved)
        self.sid = sid
        self.kind = kind
        self.desc = desc
        self.rk = rk
        self.list_epoch = list_epoch
        self.access = access
        self.gens = []                            # (Generation, fd, logical start)
        self.length = 0

    @property
    def version(self):
        return self.desc.version

    def _fds(self):
        return [fd for _g, fd, _s in self.gens]

    def _open_fds(self):
        """On a thread, before the snapshot is shared: open and check every generation."""
        store, sid, kind, rk = self.store, self.sid, self.kind, self.rk
        store._fault("open-fds")
        for g in self.desc.generations:
            try:
                fd = os.open(gen_name(sid, kind, g.gen_id.hex()), _RDONLY, dir_fd=store.dir_fd)
            except OSError:
                raise TxStoreError("damaged", f"generation {g.gen_id.hex()} missing") from None
            self.gens.append((g, fd, self.length))
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size < g.phys_len:
                raise TxStoreError("damaged", f"generation {g.gen_id.hex()} not usable")
            keys_ = txformat.generation_keys(rk, KINDS[kind], g.gen_id)
            try:
                h = txformat.verify_header(os.pread(fd, txformat.PREFIX_LEN, 0), keys_,
                                           kind=KINDS[kind], sid=_sid_bytes(sid), gen_id=g.gen_id)
            except txformat.CorruptError as e:
                raise TxStoreError("corrupt", e.reason) from None
            if not hmac.compare_digest(h.hdr_mac, g.hdr_mac):
                raise TxStoreError("corrupt", "hdr-mac-mismatch")
            self.length += g.plain_len

    def etag(self):
        h = hashlib.sha256(_sid_bytes(self.sid) + self.kind.encode() + self.version.to_bytes(8, "little")
                           + _list_digest(self.desc) + self.length.to_bytes(8, "little"))
        return '"' + h.hexdigest() + '"'

    # sincron, pe un thread: cursorul verificat pentru o generaţie, de la cea mai apropiată intrare
    def _index_entries(self, g):
        live = self.store.live_index.get((self.sid, self.kind, g.gen_id.hex()))
        if live is not None and g.state == txdesc.STATE_LIVE:
            # Indexul în memorie al hub-ului: construit din recordurile scrise de el însuşi.
            return [e for e in live if e.seq < g.data_count]
        try:
            fd = os.open(gen_name(self.sid, self.kind, g.gen_id.hex(), "idx"), _RDONLY,
                         dir_fd=self.store.dir_fd)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > IDX_MAX_FILE:
                return None
            blob = os.pread(fd, st.st_size, 0)
        finally:
            os.close(fd)
        try:
            ents = txformat.verify_index(blob, self.rk, kind=KINDS[self.kind], gen_id=g.gen_id,
                                         data_count=g.data_count)
        except txformat.TxFormatError:
            return None                           # alt gen / alt watermark / fals: se reconstruieşte
        if any(e.logical_offset >= g.plain_len or e.file_offset >= g.phys_len for e in ents):
            return None
        return ents

    def _cursor(self, g, fd, lo, budget):
        ents = self._index_entries(g)
        start = None
        if ents:
            for e in ents:
                if e.logical_offset <= lo:
                    start = e
                else:
                    break
        pre = budget.pre_first
        if start is not None:
            pre = PARSE_WITH_INDEX if pre is None else pre
            seq, log, foff = start.seq, start.logical_offset, start.file_offset
        else:
            pre = self.store.max_bytes + self.store.keep_bytes if pre is None else pre
            seq, log, foff = 0, 0, txformat.PREFIX_LEN
        # Plafon fizic la I/O: niciun pread peste phys_len, fiecare octet fizic plătit din buget.
        fp = _PRead(fd, foff, limit=g.phys_len, budget=budget, hook=self._hook)
        cur = txformat.RecordCursor(fp, self.rk, kind=KINDS[self.kind],
                                    gen_id=g.gen_id, hdr_mac=g.hdr_mac, data_count=g.data_count,
                                    seq=seq, logical_offset=log, file_offset=foff)
        return cur, pre, start is None

    def _maybe_write_index(self, g, entries):
        if g.state == txdesc.STATE_LIVE or not entries:
            return
        hexid = g.gen_id.hex()
        # Un snapshot poate citi o generaţie deja retrasă (fd vechi): niciun index pentru ea.
        row = self.store._run_read(lambda c: c.execute(
            "SELECT state FROM tx_files WHERE gen_id=?", (hexid,)).fetchone())
        if row is None or row[0] != "published":
            return
        name = gen_name(self.sid, self.kind, g.gen_id.hex(), "idx")
        tmp = f"{self.sid}.{self.kind}.{g.gen_id.hex()}.t{secrets.token_hex(8)}.idx"
        blob = txformat.encode_index(self.rk, kind=KINDS[self.kind], gen_id=g.gen_id,
                                     data_count=g.data_count, entries=entries)
        try:
            fd = os.open(tmp, _CREATE, 0o600, dir_fd=self.store.dir_fd)
        except OSError:
            return
        try:
            os.write(fd, blob)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.rename(tmp, name, src_dir_fd=self.store.dir_fd, dst_dir_fd=self.store.dir_fd)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=self.store.dir_fd)

    def _chunks(self, start, end, budget, chunk):
        """Sync generator of verified plaintext pieces of [start, end) (each ≤ chunk)."""
        end = min(end, self.length)
        if start < 0 or start > end:
            return
        for g, fd, gs in self.gens:
            ge = gs + g.plain_len
            if ge <= start or gs >= end or g.plain_len == 0:
                continue
            lo, hi = max(start, gs) - gs, min(end, ge) - gs
            try:
                cur, pre, from_zero = self._cursor(g, fd, lo, budget)
                rebuilt = [] if from_zero else None
                next_entry = 0
                parsed_before = 0
                while True:
                    if self.cancel.is_set():
                        raise TxStoreError("aborted")
                    if rebuilt is not None and cur.logical_offset >= next_entry:
                        rebuilt.append(txformat.IndexEntry(cur.seq, cur.logical_offset, cur.file_offset))
                        next_entry = cur.logical_offset + INDEX_STRIDE
                    rec = cur.next()
                    if rec is None:
                        break
                    rs, re_ = rec.logical_offset, rec.logical_offset + len(rec.data)
                    budget.spend(len(rec.data))
                    if re_ <= lo:
                        parsed_before += len(rec.data)
                        if parsed_before > pre:
                            raise TxStoreError("limitExceeded", "parse before the first byte")
                        continue
                    piece = rec.data[max(lo, rs) - rs:min(hi, re_) - rs]
                    for i in range(0, len(piece), chunk):
                        yield piece[i:i + chunk]
                    if re_ >= hi:
                        break
                if cur.logical_offset == g.plain_len and rebuilt is not None:
                    self._maybe_write_index(g, rebuilt)
            except txformat.CorruptError as e:
                self.store.alarm("transcript.corrupt", f"{self.sid}.{self.kind}.{g.gen_id.hex()}: {e}")
                raise TxStoreError("corrupt", e.reason) from None

    def _read_sync(self, start, end, budget):
        """Internal (compaction, `read`): no access check here; the fds only inside the guard."""
        with self._using():
            return b"".join(self._chunks(start, end, budget, STREAM_CHUNK))

    def _next_guarded(self, gen, done):
        with self._using():
            return next(gen, done)

    async def _checkpoint(self, reauthorize):
        try:
            self.store.check(self.access)
        except NeedsReauth:
            if reauthorize is None:
                raise Revoked("revoked", "access changed; no re-authorization") from None
            for _ in (0, 1):
                await self.store.wait_fences(self.sid)
                new = await reauthorize()        # NotAuthorized etc. → propagă, fluxul se opreşte
                if not _same_grant(self.access, new):
                    raise Revoked("bad-access", "re-authorization changed the grant")
                try:
                    self.store.check(new)
                    self.access = new
                    return
                except NeedsReauth:
                    continue
            raise Revoked("revoked", "re-authorization did not settle") from None

    async def read(self, start, end, *, budget=None, reauthorize=None):
        """Single-shot read of [start, end): checked before decrypt and again before return."""
        if self.closed:
            raise TxStoreError("closed")
        budget = budget or Budget(max(0, end - start) + PARSE_WITH_INDEX + self.store.max_bytes
                                  + self.store.keep_bytes)
        await self._checkpoint(reauthorize)
        async with self.store.worker_slot():
            data = await self.store.io(self._read_sync, start, end, budget)
        self.last_used = time.monotonic()
        await self._checkpoint(reauthorize)       # (c) înainte de predarea către transport
        return data

    async def iter(self, start, end, *, chunk=STREAM_CHUNK, budget=None, reauthorize=None):
        """Stream of [start, end): the check runs before EACH emitted chunk (≤ 64 KiB)."""
        if self.closed:
            raise TxStoreError("closed")
        chunk = min(chunk, STREAM_CHUNK)
        budget = budget or Budget(max(0, end - start) + PARSE_WITH_INDEX + self.store.max_bytes
                                  + self.store.keep_bytes)
        gen = self._chunks(start, end, budget, chunk)
        done = object()
        try:
            while True:
                await self._checkpoint(reauthorize)
                async with self.store.worker_slot():
                    piece = await self.store.io(self._next_guarded, gen, done)
                if piece is done:
                    return
                self.last_used = time.monotonic()
                await self._checkpoint(reauthorize)
                yield piece
        finally:
            gen.close()


class PlainSnapshot(_FdOwner):
    """3.7 plaintext (inventoried `pending`, identity-checked), same API, one fd. Plaintext has no
    authentication, so the fd's identity (regular, one link, dev, ino, size, mtime) is checked
    against the inventory row before EVERY read, inside the guard."""

    def __init__(self, store, sid, kind, dirn, name, ident, access, *, reserved=0):
        self._init_owner(store, reserved)
        self.sid = sid
        self.kind = kind
        self.dirn = dirn
        self.name = name
        self.ident = tuple(ident)
        self.fd = None
        self.length = ident[2]
        self.access = access
        self.list_epoch = 0

    def _fds(self):
        return [] if self.fd is None else [self.fd]

    def _open_fds(self):
        store = self.store
        store._fault("open-fds")
        try:
            if self.dirn == "arhiva":
                sub = os.open("arhiva", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=store.dir_fd)
                try:
                    self.fd = os.open(self.name, _RDONLY, dir_fd=sub)
                finally:
                    os.close(sub)
            else:
                self.fd = os.open(self.name, _RDONLY, dir_fd=store.dir_fd)
        except OSError:
            raise TxStoreError("notFound", "plaintext missing") from None
        self._check_identity()
        # Starea conversiei revalidată DUPĂ fixarea fd-ului: o conversie comisă între timp câştigă.
        if not store._plain_still_pending(self.sid, self.kind, self.ident):
            store.alarm("transcript.downgrade", f"{self.sid}.{self.kind}: converted while opening")
            raise TxStoreError("downgrade", "recording is not plaintext any more")

    def _check_identity(self):
        st = os.fstat(self.fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != self.ident):
            self.store.alarm("transcript.downgrade", f"{self.sid}.{self.kind}: plaintext changed since inventory")
            raise TxStoreError("downgrade", "plaintext differs from its inventory row")

    def _chunks(self, start, end, budget, chunk):
        pos, end = max(0, start), min(end, self.length)
        while pos < end:
            if self.cancel.is_set():
                raise TxStoreError("aborted")
            n = min(chunk, end - pos)
            budget.spend_phys(n)
            self._hook()
            self._check_identity()
            b = os.pread(self.fd, n, pos)
            if not b:
                return
            budget.spend(len(b))
            yield b
            pos += len(b)

    _read_sync = Snapshot._read_sync
    _next_guarded = Snapshot._next_guarded
    _checkpoint = Snapshot._checkpoint
    read = Snapshot.read
    iter = Snapshot.iter


# ── response helpers (download, redacted replay) ─────────────────────────────


def parse_range(header, length):
    """(status, start, end) for one `Range` on plaintext offsets: 200 full when absent, invalid
    or multi-range; 206 for one range clamped to the length; 416 when start ≥ length."""
    if not header or not header.startswith("bytes=") or "," in header:
        return 200, 0, length
    spec = header[6:].strip()
    a, sep, b = spec.partition("-")
    if not sep:
        return 200, 0, length
    try:
        if a == "":
            n = int(b)
            if n <= 0:
                return 200, 0, length
            return (206, max(0, length - n), length) if length else (416, 0, 0)
        s = int(a)
        e = int(b) + 1 if b else length
    except ValueError:
        return 200, 0, length
    if s < 0 or (b and e <= s):
        return 200, 0, length
    if s >= length:
        return 416, 0, 0
    return 206, s, min(e, length)


async def iter_lines(chunks, max_line=CAP_HEADER_MAX):
    """Whole lines from a decrypted logical stream (record boundaries invisible); a line longer
    than `max_line` is refused, the last unterminated line is yielded at the end."""
    buf = bytearray()
    async for c in chunks:
        buf += c
        while True:
            i = buf.find(b"\n")
            if i < 0:
                break
            # Lungimea se verifică ÎNAINTE de yield: o linie prea lungă dar completă nu trece.
            if i + 1 > max_line:
                raise TxStoreError("limitExceeded", "line longer than the redaction buffer")
            yield bytes(buf[:i + 1])
            del buf[:i + 1]
        if len(buf) > max_line:
            raise TxStoreError("limitExceeded", "line longer than the redaction buffer")
    if buf:
        yield bytes(buf)


class ResponseCache:
    """Small LRU of computed responses keyed by (sid, kind, version, list digest, policy version,
    representation, route, revocation_epoch[sid], access_epoch); dropped on any bump, checked
    before serve and put, and only for an Access of the same sid and route as the key (raw and
    redacted responses never share an entry)."""

    def __init__(self, store, size=1):
        self.store = store
        self.size = size
        self._d = collections.OrderedDict()
        store._caches.append(self)

    def key(self, snap, policy_version, *, representation):
        if representation not in REPRESENTATIONS:
            raise TxStoreError("bad-argument", "representation")
        return (snap.sid, snap.kind, snap.version, _list_digest(snap.desc), policy_version,
                representation, snap.access.route, self.store.sid_epoch[snap.sid],
                self.store.access_epoch)

    def _current(self, key):
        return key[7] == self.store.sid_epoch[key[0]] and key[8] == self.store.access_epoch

    def _bound(self, key, access):
        self.store.check(access)
        if access.sid != key[0] or access.route != key[6]:
            raise TxStoreError("bad-access", "cache key of another sid or route")

    def get(self, key, access):
        self._bound(key, access)                  # (a) înainte de a servi din cache
        v = self._d.get(key)
        if v is None or not self._current(key):
            self._d.pop(key, None)
            return None
        self._d.move_to_end(key)
        return v

    def put(self, key, value, access):
        self._bound(key, access)                  # (a) înainte de a pune în cache
        if not self._current(key):
            return False
        self._d[key] = value
        while len(self._d) > self.size:
            self._d.popitem(last=False)
        return True

    def drop(self, sid):
        for k in [k for k in self._d if sid is None or k[0] == sid]:
            del self._d[k]


# ── Recorder ─────────────────────────────────────────────────────────────────


class Gap(NamedTuple):
    """One published GAP_MARKER: where it sits in each kind and what it stands for."""
    out_pos: int                                  # logical .out position of the marker
    cast_pos: int                                 # logical .cast position of its gap event
    size: int                                     # upstream (agent) bytes lost
    out: object                                   # recorder .out bytes lost (None: unknown, hub gap)
    cast: object                                  # recorder .cast bytes lost (None: unknown)
    epoch: object                                 # agent epoch the lost bytes belong to
    reason: str                                   # skip:<why> | epoch-cut | close
    start: object = None                          # upstream offset (in `epoch`) where the loss starts
    gap_id: str = ""                              # deterministic; the tx_gaps row / audit key (RC-M1)
    marker: tuple = (0, 0)                        # synthetic (.out, .cast) marker bytes, never loss


def gap_id_for(sid, epoch, start, reason, out_pos):
    """Deterministic gap id (RC-M1): the same loss re-emitted after a failed attempt keeps its id;
    two distinct markers never share one (the .out position differs)."""
    h = hashlib.sha256(f"wtgap1|{sid}|{epoch}|{start}|{reason}|{out_pos}".encode())
    return h.hexdigest()[:32]


_SKIP_REASON = re.compile(r"[a-z][a-z0-9-]{0,31}")


def _marker_bytes(gaps):
    return (sum(g.marker[0] for g in gaps), sum(g.marker[1] for g in gaps))


@dataclass
class _Plan:
    op: str                                       # extend | cap | merge
    start: dict                                   # kind → (version, blob | None)
    new: dict                                     # kind → (Descriptor, blob)
    listed: list                                  # gen hexes newly published
    retired: list = field(default_factory=list)   # (kind, gen hex) retired by cap/merge
    agent: tuple = None                           # (epoch, offset) to publish
    agent_prev: tuple = None                      # committed (epoch, offset) at capture
    epoch_change: bool = False
    out_grew: bool = False
    list_epoch: int = None                        # cap/merge: the one seen at build time
    prefix: dict = None                           # cap/merge: kind → tuple(P generations)
    ident: dict = field(default_factory=dict)     # listed gen hex → (kind, dev, ino) of the ledger row
    gaps: list = field(default_factory=list)      # extend: markers this publication lists (tx_gaps rows)


class Recorder:
    """One per recorded sid: a worker task with a FIFO job queue (§12.11.1).

    Ingress contract (the hub, PR5b; §12.11.10 "Admission"): ONE call per agent chunk,
    `feed(out, cast, at=(epoch, offset), agent_bytes=n)` (`at` mandatory, n > 0), admits both
    representations of that chunk together or neither, and returns whether they were admitted.
    `at` must be `received` (the end of everything offered in the current epoch); anything else is
    a hub ordering error, raised as `TxStoreError("position")` with nothing admitted and nothing
    counted (retryable: the hub resends from its ring at `received`). Events that exist only in
    `.cast` (header, resizes) go through `feed_cast_only(cast, at=received)`, in call order with
    the chunks, and never move the agent offset. `False` is terminal for those bytes: `ingress()`
    says why — "overflow" (counted once, keyed by position; call `resume()` and replay from C what
    the ring still has, then `skip_to` past what it no longer has), "closing" (counted in
    `rejected`) or the recorder state (counted in `refused`). The loss accounting (`loss`) counts
    real upstream bytes and real recorder bytes per kind, never synthetic marker bytes.

    A verified upstream skip (`skip_to(epoch, replay_start, reason)`: the agent replays from after
    the cursor) becomes ONE GAP_MARKER published in the same transaction as the new cursor, with
    a durable `tx_gaps` row. `change_epoch(e)` to the current epoch is a no-op (a redundant attach:
    no cut, no reset). An epoch change is a cut at the call: bytes admitted BEFORE `change_epoch(e)`
    belong to the old epoch and are held outside the overflow path (an overflow of `e` never drops
    them); the switch commits only after they are published, or after ONE durable GAP_MARKER for
    exactly the old-epoch bytes that could not be (then alarmed). Bytes admitted AFTER the call
    count from offset 0 of `e` and are published only after the switch committed. A failed switch
    re-adopts the sid from the DB."""

    def __init__(self, store, sid, *, track_agent=True):
        self.store = store
        self.sid = sid
        self.sidb = _sid_bytes(sid)
        self.track_agent = track_agent
        self.token = os.urandom(16)
        self.state = "new"
        self.env = self.rk = None
        self.committed = {k: None for k in KIND_NAMES}
        self.list_epoch = 0
        self.agent_committed = (None, 0)
        self.agent_epoch = None
        self.agent_offset = 0
        self.out_pos = 0
        self.cur = {k: None for k in KIND_NAMES}
        self.done = {k: [] for k in KIND_NAMES}   # sigilate în job, încă nepublicate
        self.to_recover = {k: set() for k in KIND_NAMES}
        self.pending = {k: bytearray() for k in KIND_NAMES}
        self.inflight = 0
        self.overflow = False
        # În overflow: capătul (în epoch-ul curent) a tot ce s-a oferit şi s-a numărat pierdut; un
        # fragment re-oferit sub el nu se mai numără (RC-M2: pierderea se cheie după poziţie).
        self._lost_hw = 0
        self.rejected = 0                         # oferite după close()
        self.refused = 0                          # oferite unui recorder care nu mai rulează
        self.degraded = False
        self.closing = False
        self.cast_pos = 0
        # Pierderea epoch-ului curent de la ultimul resume (octeţi upstream + per kind); păstrată
        # până la commit-ul care publică markerul ei (R-H2).
        self._loss = self._new_loss(None)
        self._close_gap = None                    # markerul datorat la close, păstrat între încercări
        self.gap_pending = []                     # Gap-uri ale markerelor încă în `pending`
        self._gaps_unpub = []                     # scrise în writer, încă nepublicate
        self.gaps = []
        # Poziţia agentului căreia îi corespund octeţii din writere (ultima captură scrisă); se
        # publică DOAR împreună cu ei (H1: prefixele şi offsetul se mişcă împreună).
        self._written_agent = (None, 0)
        # Poziţia acoperită de octeţii publicaţi (= agent_committed când track_agent).
        self._covered = (None, 0)
        # Unde începe `pending` în fluxul agentului (capătul ultimei capturi).
        self._pend_from = (None, 0)
        # Tăietura de epoch în aşteptare: {"old": (epoch, offset), "bufs": {kind: bytearray},
        # "gaps": [Gap], "new": e, "loss": pierderea vechiului epoch, "owed": markerul datorat}
        self._switch = None
        self.cap_not_before = 0.0
        self.capping = False
        self._queue = asyncio.Queue()
        self._task = None

    # ── start / adoption ──

    async def _start(self):
        st = self.store
        async with st.lease(self.sid):
            await st.recover(self.sid)
            self.env, self.rk = await st.ensure_rk(self.sid)
            await self._reload()
            st.tokens[self.sid] = self.token
            try:
                for k in KIND_NAMES:
                    self.cur[k] = await self._open_gen(k)
            except Exception:
                # Pornire parţială (ex. ENOSPC la a doua generaţie): niciun fd rămas deschis,
                # nicio generaţie creată neretrasă, tokenul nu rămâne al unui writer mort.
                for k in KIND_NAMES:
                    g, self.cur[k] = self.cur[k], None
                    if g is not None:
                        self._drop_gen_fd(g)
                        with contextlib.suppress(Exception):
                            await self._retire_unpublished(g)
                if st.tokens.get(self.sid) == self.token:
                    del st.tokens[self.sid]
                raise
        self.state = "running"
        self._task = asyncio.get_running_loop().create_task(self._worker())

    async def _reload(self):
        """Committed state from the DB only (never memory): descriptors + agent position."""
        sid = self.sid

        def load(c):
            return (c.execute("SELECT kind, blob, version, list_epoch, status FROM tx_descriptors "
                              "WHERE sid=?", (sid,)).fetchall(),
                    c.execute("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?",
                              (sid,)).fetchone())
        rows, ag = await self.store.fresh_read(load)
        for k, blob, v, le, status in rows:
            if status != "ok":
                raise TxStoreError("damaged" if status == "damaged" else "quarantined", f"{sid}.{k}")
            # Un plic care nu se despachetează sau un hash RK diferit → hub-ul NU porneşte.
            try:
                self.committed[k] = self.store.decode((blob, v), sid, k, self.env)
            except TxStoreError as e:
                self.store.alarm("transcript.keyError", f"{sid}.{k}: {e}")
                raise TxStoreError("keyError", str(e)) from None
            self.list_epoch = max(self.list_epoch, le)
        if self.track_agent:
            if ag is None:
                raise TxStoreError("notFound", "no session row for the agent position")
            self.agent_committed = (ag[0], ag[1] or 0)
        self.agent_epoch, self.agent_offset = self.agent_committed
        self._written_agent = self._covered = self._pend_from = self.agent_committed
        self._loss = self._new_loss(self.agent_epoch)
        self.out_pos = self.committed_len("out")
        self.cast_pos = self.committed_len("cast")

    def committed_len(self, kind):
        d = self.committed[kind]
        return sum(g.plain_len for g in d.generations) if d else 0

    async def _open_gen(self, kind):
        st = self.store
        gid, fd, dev, ino, name = await st.reserve_and_create(self.sid, kind)
        g = _Gen(kind, gid, name, fd, None, dev, ino)
        try:
            g.writer = await st.io(txformat.Writer, _File(fd, st), self.rk, kind=KINDS[kind],
                                   sid=self.sidb, gen_id=gid, created_ms=int(st.clock() * 1000),
                                   max_records=st.gen_limits[0], max_plain=st.gen_limits[1])
            st._fault("header")
        except Exception:
            # Generaţia e a noastră (O_EXCL + inode în registru): retrasă acum, nu lăsată la boot.
            self._drop_gen_fd(g)
            with contextlib.suppress(Exception):
                await self._retire_unpublished(g)
            raise
        except BaseException:
            self._drop_gen_fd(g)                  # moartea procesului: registrul decide la boot
            raise
        st.live_index[(self.sid, kind, gid.hex())] = g.index
        return g

    async def _reopen(self, kind):
        try:
            self.cur[kind] = await self._open_gen(kind)
        except (TxStoreError, OSError, sqlite3.Error, txformat.TxFormatError, Uncertain) as e:
            # Un recorder „running" fără generaţie curentă nu există: readoptare explicită.
            raise _NeedReadopt(f"cannot open a generation: {e}") from None

    def _drop_gen_fd(self, g):
        if g.fd is not None:
            with contextlib.suppress(OSError):
                os.close(g.fd)
            g.fd = None
        self.store.live_index.pop((self.sid, g.kind, g.gen_id.hex()), None)

    def _close_fds(self):
        for k in KIND_NAMES:
            for g in [self.cur[k]] + self.done[k]:
                if g is not None and g.fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(g.fd)
                    g.fd = None
            self.cur[k] = None
            self.done[k] = []
        self._drop_buffers(include_switch=True)

    # ── loop side (synchronous, no file I/O) ──

    @staticmethod
    def _new_loss(epoch):
        return {"epoch": epoch, "agent": 0, "out": 0, "cast": 0}

    def _lose(self, agent, out, cast, loss=None):
        L = self._loss if loss is None else loss
        L["agent"] += agent
        L["out"] += out
        L["cast"] += cast

    @property
    def dropped(self):
        """Upstream bytes of the current epoch offered and not recorded since the last resume."""
        return self._loss["agent"]

    @property
    def loss(self):
        return dict(self._loss)

    def _drop_buffers(self, include_switch=False):
        """Clears `pending` (and, only when the recorder stops, an epoch cut's held segment).
        Returns the (.out, .cast) lengths cleared from `pending`."""
        bufs = [self.pending]
        if include_switch and self._switch is not None:
            bufs.append(self._switch["bufs"])
            self._switch["gaps"] = []
        # Octeţii markerelor din `pending` sunt sintetici: nu intră în pierdere (RC-M1).
        mk = _marker_bytes(self.gap_pending)
        lost = (len(self.pending["out"]) - mk[0], len(self.pending["cast"]) - mk[1])
        self.store.buffered_total -= sum(len(x) for b in bufs for x in b.values())
        for b in bufs:
            for x in b.values():
                x.clear()
        self.gap_pending = []
        return lost

    def _buffered(self):
        # Segmentul reţinut al vechiului epoch NU intră în contabilitatea overflow-ului (R-H1): e
        # deja admis şi nu poate fi reluat după comutare; doar `pending` + lotul în zbor contează.
        return sum(len(x) for x in self.pending.values()) + self.inflight

    def _held_end(self):
        # Capătul octeţilor DEŢINUŢI (capturaţi sau în `pending`). În overflow `pending` e gol şi
        # agent_offset include octeţi aruncaţi (nu se derulează), deci capătul e începutul lui.
        return self._pend_from if self.overflow else (self.agent_epoch, self.agent_offset)

    def _unpublished(self, kind):
        """Plaintext bytes the writers hold beyond the committed descriptor for `kind`."""
        d = self.committed[kind]
        have = {e.gen_id: e.plain_len for e in d.generations} if d else {}
        return sum(g.writer.plain_len - have.get(g.gen_id, 0) for g in self._writers(kind))

    def _recount_pos(self):
        sw = self._switch["bufs"] if self._switch is not None else None
        for k in KIND_NAMES:
            n = self.committed_len(k) + self._unpublished(k) + len(self.pending[k]) + (len(sw[k]) if sw else 0)
            if k == "out":
                self.out_pos = n
            else:
                self.cast_pos = n

    def ingress(self):
        if self.state != "running":
            return self.state
        if self.closing:
            return "closing"
        return "overflow" if self.overflow else "open"

    @property
    def received(self):
        """(epoch, offset) where the next chunk must start: the end of everything offered in the
        current epoch, admitted or counted lost. Not the committed position (`agent_committed`)."""
        return (self.agent_epoch, self._lost_hw if self.overflow else self.agent_offset)

    @staticmethod
    def _check_at(at):
        if (not isinstance(at, tuple) or len(at) != 2 or not (at[0] is None or isinstance(at[0], str))
                or type(at[1]) is not int or at[1] < 0):
            raise TxStoreError("badInput", "at must be (epoch, offset)")

    def feed(self, out, cast, *, at, agent_bytes=None):
        """Admission of ONE agent chunk: its `.out` bytes and its `.cast` event together, or
        neither (see the class docstring). `at` = (epoch, offset) where the chunk starts upstream
        (mandatory); `agent_bytes` = its upstream length (default `len(out)`, must be > 0; an
        explicitly empty `cast` is a format that omits the event — the offset still moves with
        `.out`). Returns whether it was admitted."""
        if not all(isinstance(x, (bytes, bytearray, memoryview)) for x in (out, cast)):
            raise TxStoreError("badInput", "feed takes bytes")
        self._check_at(at)
        ab = len(out) if agent_bytes is None else agent_bytes
        if type(ab) is not int or ab <= 0:
            # Un agent_bytes > 0 cu ambele reprezentări goale ar muta poziţia fără DATA: refuzat.
            raise TxStoreError("badInput", "agent_bytes must be a positive int (cast-only: feed_cast_only)")
        if not len(out) and not len(cast):
            raise TxStoreError("badInput", "a chunk with upstream bytes has no representation")
        return self._admit(out, cast, at, ab)

    def feed_cast_only(self, cast, *, at):
        """A `.cast`-only event (header, resize) at upstream position `at`: no agent bytes, the
        offset does not move, kept in call order relative to `feed`."""
        if not isinstance(cast, (bytes, bytearray, memoryview)) or not len(cast):
            raise TxStoreError("badInput", "feed_cast_only takes non-empty bytes")
        self._check_at(at)
        return self._admit(b"", cast, at, 0)

    def _admit(self, out, cast, at, ab):
        n = len(out) + len(cast)
        if self.state != "running":
            self.refused += n
            return False
        if self.closing:
            self.rejected += n
            return False
        if at[0] != self.agent_epoch:
            # Alt epoch fără change_epoch: eroare de ordine a hub-ului, nimic admis, nimic numărat.
            raise TxStoreError("position", f"chunk at {at}, recorder in epoch {self.agent_epoch!r}")
        if self.overflow:
            # RC-M2: validat ÎNAINTE de numărare; un fragment re-oferit (sub capătul numărat) nu se
            # mai numără; o suprapunere parţială sau o lipsă e o eroare de ordine.
            hw = self._lost_hw
            if ab == 0:
                if at[1] != hw:
                    raise TxStoreError("position", f"cast event at {at}, recorder received {hw}")
                self._lose(0, 0, len(cast))       # eveniment .cast: nu e în ring, fiecare apel e al lui
                return False
            if at[1] + ab <= hw:
                return False                      # deja numărat
            if at[1] != hw:
                raise TxStoreError("position", f"chunk at {at}, recorder received {hw}")
            self._lose(ab, len(out), len(cast))
            self._lost_hw += ab
            return False
        if at[1] != self.agent_offset:
            # Un fragment care nu începe la poziţia recorderului (lipsă / dublură) nu se admite
            # nicio parte din el: hub-ul are o eroare de ordine.
            raise TxStoreError("position", f"chunk at {at}, recorder at {(self.agent_epoch, self.agent_offset)}")
        if self._buffered() + n > self.store.pending_cap or self.store.buffered_total + n > self.store.total_cap:
            self._enter_overflow()
            self._lose(ab, len(out), len(cast))
            self._lost_hw += ab
            return False
        self.pending["out"] += out
        self.pending["cast"] += cast
        self.store.buffered_total += n
        self.agent_offset += ab
        self.out_pos += len(out)
        self.cast_pos += len(cast)
        return True

    def _enter_overflow(self):
        # Doar `pending` se aruncă: niciodată lotul în zbor, nici segmentul reţinut al unei tăieturi
        # de epoch; agent_offset NU se derulează (§12.11.1 Backpressure), pierderea se numără exact.
        if not self.overflow:
            e0, o0 = self._pend_from
            held = self.agent_offset - o0 if e0 == self.agent_epoch else self.agent_offset
            out_n, cast_n = self._drop_buffers()
            self._lose(max(0, held), out_n, cast_n)
            self.overflow = True
            self._lost_hw = self.agent_offset
        if not self.degraded:
            self.degraded = True
            self.store.alarm("transcript.degraded", f"{self.sid}: recording buffer overflow")

    async def resume(self):
        """After an overflow or a write fault: queued behind the in-flight job, publishes (or
        abandons) what the writers hold, re-reads the committed descriptors and position C from the
        DB (both must be what this recorder last committed, else re-adoption), drops `pending`
        (superseded by the replay) and resumes there. Returns C = (agent_epoch, agent_offset,
        out_pos, dropped upstream bytes). Refused while an epoch change is pending."""
        if self._switch is not None:
            raise TxStoreError("busy", "epoch change in progress: resume after it")
        return await self._submit("resync")

    def skip_to(self, at_epoch, replay_start, reason, cast_ts=0.0):
        """A verified upstream skip (RC-H2): the agent answered an attach from the cursor with
        `replay_start` (same epoch). Equal to the cursor → no-op; after it → ONE GAP_MARKER for
        [cursor, replay_start) and the new cursor, captured in the same tick so they are published
        in the SAME transaction (with its `tx_gaps` row); before it → refused ("position"): the
        hub trims the overlap from the replay and feeds from the cursor. Returns a future that
        resolves once that publication committed (a no-op resolves at once)."""
        if not (at_epoch is None or isinstance(at_epoch, str)) or type(replay_start) is not int or replay_start < 0:
            raise TxStoreError("badInput", "skip_to(epoch, replay_start)")
        if not isinstance(reason, str) or not _SKIP_REASON.fullmatch(reason):
            raise TxStoreError("badInput", "skip reason")
        if self.state != "running":
            raise RecorderLost("lost", f"recorder {self.state}")
        if self.overflow or self.closing or self._switch is not None:
            raise TxStoreError("busy", "resume first")
        if at_epoch != self.agent_epoch:
            raise TxStoreError("position", f"skip in epoch {at_epoch!r}, recorder in {self.agent_epoch!r}")
        cur = self.agent_offset
        if replay_start == cur:
            return self._done(None)
        if replay_start < cur:
            raise TxStoreError("position", f"replay starts at {replay_start}, before the cursor {cur}: "
                                           "trim the overlap and feed from the cursor")
        self._add_gap(replay_start - cur, cast_ts, reason="skip:" + reason, epoch=self.agent_epoch, start=cur)
        # Markerul şi noul cursor intră în aceeaşi captură (acelaşi tick) → aceeaşi tranzacţie.
        self.agent_offset = replay_start
        return self._submit("checkpoint")

    @staticmethod
    def _done(value):
        fut = asyncio.get_running_loop().create_future()
        fut.set_result(value)
        return fut

    def _add_gap(self, size, cast_ts, *, reason, epoch, start, out=None, cast=None, into_switch=False):
        """Marker bytes into `pending` (or into an epoch cut's held segment, BEFORE every byte of
        the new epoch); the positions of everything after it shift accordingly."""
        ev = gap_event(cast_ts)
        if into_switch:
            sw = self._switch
            bufs, lst = sw["bufs"], sw["gaps"]
            pos = [self.committed_len(k) + self._unpublished(k) + len(bufs[k]) for k in KIND_NAMES]
        else:
            bufs, lst = self.pending, self.gap_pending
            pos = [self.out_pos, self.cast_pos]
        g = Gap(pos[0], pos[1], size, out, cast, epoch, reason, start,
                gap_id_for(self.sid, epoch, start, reason, pos[0]), (len(GAP_MARKER), len(ev)))
        bufs["out"] += GAP_MARKER
        bufs["cast"] += ev
        self.store.buffered_total += len(GAP_MARKER) + len(ev)
        self.out_pos += len(GAP_MARKER)
        self.cast_pos += len(ev)
        lst.append(g)
        return g

    # ── jobs ──

    def _submit(self, op, *args):
        if self.state != "running":
            raise RecorderLost("lost", f"recorder {self.state}")
        fut = asyncio.get_running_loop().create_future()
        # Rezultatul e citit şi când apelantul a renunţat (wait_for, shutdown): fără avertismente.
        fut.add_done_callback(lambda f: f.cancelled() or f.exception())
        self._queue.put_nowait((op, args, fut))
        # Anularea apelantului nu anulează un job început.
        return asyncio.shield(fut)

    def checkpoint(self):
        return self._submit("checkpoint")

    def close(self, cast_ts=0.0):
        """Close: ingress stops NOW (later bytes are refused, counted in `rejected`); the finalize
        job drains everything accepted before, seals and publishes. An overflow still open then is
        recorded as one GAP_MARKER at the end (`cast_ts` for its `.cast` event), its size in
        `gaps` and the result's `lost`, and alarmed."""
        fut = self._submit("finalize", cast_ts)
        self.closing = True
        return fut

    def change_epoch(self, new_epoch):
        """The cut is taken HERE, synchronously (see the class docstring). The current epoch is a
        no-op (no cut, no offset reset): a redundant attach, RC-H1."""
        if not isinstance(new_epoch, str) or not new_epoch:
            raise TxStoreError("badInput", "epoch")
        if self.state != "running":
            raise RecorderLost("lost", f"recorder {self.state}")
        if self.closing:
            raise TxStoreError("busy", "recorder closing")
        if new_epoch == self.agent_epoch:
            # RC-H1: o reataşare în acelaşi epoch NU e o tăietură; offsetul 0 ar re-înregistra octeţi
            # deja comişi ca fiind contigui. Hub-ul continuă de la `received` (taie suprapunerea).
            return self._done(self.agent_committed)
        if self._switch is not None:
            raise TxStoreError("busy", "epoch change in progress")
        fut = self._submit("epoch", new_epoch)
        # Segmentul vechi (cu markerele lui şi pierderea vechiului epoch) se mută în tăietură: din
        # acest moment niciun overflow al noului epoch nu-l mai atinge (R-H1).
        self._switch = {"old": self._held_end(), "bufs": self.pending, "gaps": self.gap_pending,
                        "new": new_epoch, "loss": self._loss, "owed": None}
        self.pending = {k: bytearray() for k in KIND_NAMES}
        self.gap_pending = []
        self._loss = self._new_loss(new_epoch)
        self.agent_epoch, self.agent_offset = new_epoch, 0
        self._pend_from = (new_epoch, 0)
        return fut

    async def cap_now(self, truncate=True):
        """Cap (3.7 content) or merge (truncate=False) of everything committed before now."""
        if self.capping:
            raise TxStoreError("busy", "cap in progress")
        self.capping = True
        try:
            prefix, le = await self._submit("roll_all")
            if not any(prefix.values()):
                return False
            built = await self._build_compacted(prefix, truncate)
            try:
                ok = await self._submit("cap_publish", prefix, built, le, truncate)
            except BaseException:
                await self._discard_built(built)
                raise
            if not ok:
                await self._discard_built(built)
            return ok
        except (TxStoreError, OSError, txformat.TxFormatError):
            self.cap_not_before = self.store.clock() + CAP_RETRY_SECS
            raise
        finally:
            self.capping = False

    async def _worker(self):
        fut = None
        try:
            while True:
                op, args, fut = await self._queue.get()
                if op == "_stop":
                    fut.set_result(None)
                    fut = None
                    break
                try:
                    async with self.store.lease(self.sid):
                        res = await getattr(self, "_job_" + op)(*args)
                except (TxStoreError, txformat.TxFormatError, OSError, Uncertain, sqlite3.Error) as e:
                    if isinstance(e, _NeedReadopt) or self.state == "lost":
                        raise
                    if not fut.done():
                        fut.set_exception(e)
                    fut = None
                    if self.state in ("closed", "replaced"):
                        break
                    continue
                if not fut.done():
                    fut.set_result(res)
                fut = None
                if self.state in ("closed", "replaced"):
                    break
        except BaseException:
            if self.state == "running":
                self.state = "lost"
            raise
        finally:
            # Supervizorul: orice viitor primeşte un rezultat (rezultatul lui sau RecorderLost).
            if fut is not None and not fut.done():
                fut.set_exception(RecorderLost("lost", self.sid))
            while not self._queue.empty():
                _op, _a, f = self._queue.get_nowait()
                if not f.done():
                    f.set_exception(RecorderLost("lost", self.sid))
            if self.state in ("closed", "replaced"):
                self._close_fds()

    def _check_token(self):
        if self.store.tokens.get(self.sid) != self.token:
            self.state = "replaced"
            raise Refused("stale-writer", "a newer writer owns this sid")

    async def _job_resync(self):
        self._check_token()
        await self._flush_dirty()
        sid = self.sid

        def load(c):
            return (c.execute("SELECT kind, blob, version FROM tx_descriptors WHERE sid=?", (sid,)).fetchall(),
                    c.execute("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", (sid,)).fetchone())
        try:
            rows, ag = await self.store.fresh_read(load)
        except (sqlite3.Error, OSError) as e:
            raise _NeedReadopt(f"resync cannot read the committed state: {e}") from None
        # Descriptorii şi cursorul se adoptă ÎMPREUNĂ (R-M2): dacă DB-ul nu mai e exact ce a comis
        # acest recorder (ceva s-a mutat independent), nu se adoptă doar cursorul → readoptare.
        db_desc = {k: (v, bytes(b)) for k, b, v in rows}
        for k in KIND_NAMES:
            d = self.committed[k]
            mine = (d.version, self.store.encode(d)) if d else None
            if db_desc.get(k) != mine:
                raise _NeedReadopt(f"{k}: descriptor moved under the writer")
        if self.track_agent:
            if ag is None or (ag[0], ag[1] or 0) != tuple(self.agent_committed):
                raise _NeedReadopt("agent position moved under the writer")
        self._drop_buffers()                      # reluarea de la C le înlocuieşte (doar `pending`)
        self._written_agent = self._covered
        if self._switch is not None:
            # Tăietura rămâne intactă (segmentul vechi se publică de jobul ei); reluarea e în noul epoch.
            self.agent_epoch, self.agent_offset = self._switch["new"], 0
        else:
            self.agent_epoch, self.agent_offset = self._covered
        self._pend_from = (self.agent_epoch, self.agent_offset)
        self._recount_pos()
        lost, self._loss = self._loss, self._new_loss(self.agent_epoch)
        self.overflow = False
        return (self.agent_epoch, self.agent_offset, self.out_pos, lost["agent"])

    def _capture(self):
        """The batch, its agent position and its markers, taken in ONE tick. With an epoch cut
        pending, only the old epoch's held segment is captured (the new epoch's bytes wait for
        the switch)."""
        sw = self._switch
        if sw is not None:
            src, agent_end, gaps = sw["bufs"], sw["old"], sw["gaps"]
            sw["bufs"], sw["gaps"] = {k: bytearray() for k in KIND_NAMES}, []
        else:
            src, agent_end, gaps = self.pending, self._held_end(), self.gap_pending
            self.pending, self.gap_pending = {k: bytearray() for k in KIND_NAMES}, []
            self._pend_from = agent_end
        return {k: bytes(src[k]) for k in KIND_NAMES}, agent_end, gaps

    async def _job_checkpoint(self):
        """Capture → append → fsync → publish. The publication unit is everything the writers hold
        beyond the committed prefix (both kinds, a batch whose publication failed earlier
        included), with the agent position of the last appended capture: both prefixes and the
        offset move together or not at all, and nothing is ever appended twice."""
        self._check_token()
        held = self._switch is not None
        batch, agent_end, gaps = self._capture()
        size = sum(len(b) for b in batch.values())
        # Segmentul reţinut al unei tăieturi nu intră în contabilitatea overflow-ului (R-H1).
        counted = 0 if held else size
        pre = {k: self._unpublished(k) for k in KIND_NAMES}
        self.inflight += counted
        try:
            self.store._fault("captured")
            try:
                touched = await self._append(batch)
                await self._fsync(touched)
            except (OSError, txformat.TxFormatError) as e:
                # Markerele capturii sunt (parţial) în writere: abandonate cu ele, numărate ca
                # sintetice (nu pierdere), re-emise doar dacă sunt datorate (RC-M1).
                self._gaps_unpub += gaps
                await self._writer_failed(e, {k: pre[k] + len(batch[k]) for k in KIND_NAMES})
                raise TxStoreError("writeFailed", str(e)) from None
            self._written_agent = agent_end
            self._gaps_unpub += gaps
        finally:
            self.inflight -= counted
            self.store.buffered_total -= size
        if not self._dirty():
            return self._snapshot_state()
        had_gaps = bool(self._gaps_unpub)
        await self._publish(self._plan(self._written_agent))
        if had_gaps:
            self.degraded = False
        elif not self.overflow and self.degraded and not self.dropped:
            self.degraded = False
        await self._maybe_roll()
        self._maybe_trigger_cap()
        return self._snapshot_state()

    def _snapshot_state(self):
        return {"out_len": self.committed_len("out"), "cast_len": self.committed_len("cast"),
                "agent": self.agent_committed, "list_epoch": self.list_epoch}

    @staticmethod
    def _entry(g):
        w = g.writer
        return txdesc.Generation(g.gen_id, txdesc.STATE_SEALED if w.sealed else txdesc.STATE_LIVE,
                                 w.data_count, w.plain_len, w.phys_len, w.hdr_mac)

    def _writers(self, k):
        return [g for g in self.done[k] + [self.cur[k]]
                if g is not None and not g.broken and g.writer is not None and g.writer.data_count]

    def _dirty(self):
        """True when the writers hold anything the committed descriptors do not list (either
        kind), a generation must become `recovered`, or the written agent position is not the
        committed one."""
        if any(self.to_recover.values()):
            return True
        for k in KIND_NAMES:
            d = self.committed[k]
            have = {e.gen_id: e for e in d.generations} if d else {}
            for g in self._writers(k):
                if have.get(g.gen_id) != self._entry(g):
                    return True
        return self.track_agent and tuple(self._written_agent) != tuple(self.agent_committed)

    async def _flush_dirty(self):
        """Publish what the writers hold with the agent position those bytes belong to, or — if
        that publication fails — abandon those generations (published live → recovered at its
        committed counts, unpublished → retired): the offset never covers bytes that are not
        published, and nothing written is published later under another position."""
        if not self._dirty():
            return
        try:
            await self._publish(self._plan(self._written_agent))
        except _NeedReadopt:
            raise
        except Refused as e:
            if self.state == "replaced":
                raise
            await self._abandon_writers(f"publication refused: {e}")
        except (TxStoreError, sqlite3.Error, OSError) as e:
            await self._abandon_writers(f"publication failed: {e}")

    async def _append(self, batch):
        touched = {k: [] for k in KIND_NAMES}
        for k in KIND_NAMES:
            data = batch[k]
            pos = 0
            while pos < len(data):
                g = self.cur[k]
                pos = await self.store.io(self._append_run, g, data, pos)
                if g not in touched[k]:
                    touched[k].append(g)
                if pos < len(data):
                    # Limita tare ar fi depăşită: SEAL + generaţie nouă ÎN ACELAŞI job.
                    await self.store.io(g.writer.seal)
                    self.done[k].append(g)
                    self.cur[k] = None
                    await self._reopen(k)
        return touched

    def _append_run(self, g, data, pos):
        w = g.writer
        while pos < len(data):
            piece = data[pos:pos + txformat.MAX_DATA_LEN]
            room = w.max_plain - w.plain_len
            if w.data_count >= w.max_records or room <= 0:
                return pos
            piece = piece[:room]
            if w.plain_len >= g.next_index_at:
                g.index.append(txformat.IndexEntry(w.data_count, w.plain_len, w.phys_len))
                g.next_index_at = w.plain_len + INDEX_STRIDE
            w.append(piece)
            self.store._fault("append")
            pos += len(piece)
        return pos

    async def _fsync(self, touched):
        gens = [g for k in KIND_NAMES for g in touched[k]]

        def run():
            for g in gens:
                self.store._fault("fsync")
                os.fsync(g.fd)
            if any(not g.published for g in gens):
                self.store._fault("dir-fsync")
                os.fsync(self.store.dir_fd)
        await self.store.io(run)

    async def _abandon_writers(self, why, lost=None):
        """Abandon every generation of the writers: a published one becomes `recovered` at its
        committed counts in the next publication, an unpublished one is retired; new ones are
        opened, and the written position falls back to the committed one. What they held is
        counted as lost (upstream bytes from the published position to the end of the captures;
        with an epoch cut pending those are the old epoch's, which `_job_epoch` accounts)."""
        self.store.alarm("transcript.writeFailed", f"{self.sid}: {why}")
        if lost is None:
            lost = {k: self._unpublished(k) for k in KIND_NAMES}
        # Octeţii markerelor nepublicate sunt sintetici: nu sunt terminal pierdut (RC-M1).
        mk = _marker_bytes(self._gaps_unpub)
        lo, lc = max(0, lost["out"] - mk[0]), max(0, lost["cast"] - mk[1])
        if self._switch is None:
            e0, o0 = self._pend_from
            ce, co = self._covered
            self._lose(max(0, o0 - co) if e0 == ce else o0, lo, lc)
        else:
            self._lose(0, lo, lc, loss=self._switch["loss"])
        for k in KIND_NAMES:
            for g in self.done[k] + [self.cur[k]]:
                if g is None:
                    continue
                g.broken = True
                if g.published:
                    self.to_recover[k].add(g.gen_id)
                self._drop_gen_fd(g)
                if not g.published:
                    with contextlib.suppress(TxStoreError, OSError, sqlite3.Error, Uncertain):
                        await self._retire_unpublished(g)
            self.done[k] = []
            self.cur[k] = None
        self._written_agent = self._covered
        self._gaps_unpub = []
        if self._switch is None:
            # `pending` continuă după octeţii abandonaţi: nu mai e contiguu cu prefixul publicat →
            # aruncat (numărat), reluare de la C. Cu o tăietură, `pending` e al noului epoch (offset 0).
            self._enter_overflow()
        for k in KIND_NAMES:
            await self._reopen(k)
        self._recount_pos()

    async def _writer_failed(self, err, lost=None):
        """fsync error / ambiguous write: abandon the generations, discard pending, and ask for a
        resume from the committed position. With an epoch cut pending, the abandoned bytes are the
        old epoch's (marked by `_job_epoch`); the new epoch's `pending` starts at its offset 0 and
        stays valid, so it is not discarded."""
        await self._abandon_writers(err, lost)

    async def _retire_unpublished(self, g):
        st = self.store
        hexid = g.gen_id.hex()
        await st.txn(lambda c: c.execute("UPDATE tx_files SET state='retired' WHERE gen_id=? "
                                         "AND state='created'", (hexid,)))
        await st.retire(self.sid, g.kind, hexid)

    def _plan(self, agent_end, *, epoch_change=False):
        new, start, listed, ident = {}, {}, [], {}
        for k in KIND_NAMES:
            old = self.committed[k]
            gens = list(old.generations) if old else []
            for i, e in enumerate(gens):
                if e.gen_id in self.to_recover[k] and e.state == txdesc.STATE_LIVE:
                    gens[i] = txdesc.Generation(e.gen_id, txdesc.STATE_RECOVERED, e.data_count,
                                                e.plain_len, e.phys_len, e.hdr_mac)
            for g in self._writers(k):
                ent = self._entry(g)
                idx = next((i for i, e in enumerate(gens) if e.gen_id == g.gen_id), None)
                if idx is None:
                    gens.append(ent)
                    listed.append(g.gen_id.hex())
                    ident[g.gen_id.hex()] = (k, g.dev, g.ino)
                else:
                    gens[idx] = ent
            if old is None and not gens:
                continue
            start[k] = (old.version, self.store.encode(old)) if old else (0, None)
            d = txdesc.Descriptor(self.store.inst, self.sidb, KINDS[k], (old.version if old else 0) + 1,
                                  keyring.envelope_hash(self.env), tuple(gens), old.flags if old else 0)
            new[k] = (d, self.store.encode(d))
        out_grew = "out" in new and sum(g.plain_len for g in new["out"][0].generations) > self.committed_len("out")
        return _Plan("extend", start, new, listed, agent=agent_end, agent_prev=self.agent_committed,
                     epoch_change=epoch_change, out_grew=out_grew, ident=ident, gaps=list(self._gaps_unpub))

    def _txn_body(self, plan):
        st = self.store
        sid = self.sid
        token = self.token
        env = self.env

        def fn(c):
            if st.tokens.get(sid) != token:
                raise Refused("stale-writer", "writer replaced")
            olds = {}
            for k, (v0, b0) in plan.start.items():
                r = c.execute("SELECT blob, version, list_epoch FROM tx_descriptors WHERE sid=? AND kind=?",
                              (sid, k)).fetchone()
                if (r[1] if r else 0) != v0 or (bytes(r[0]) if r else None) != b0:
                    raise Refused("cas", f"{k}: descriptor version moved")
                if plan.op in ("cap", "merge") and r[2] != plan.list_epoch:
                    raise Refused("cas", "list_epoch moved")
                olds[k] = st.decode((r[0], r[1]), sid, k, env) if r else None
            for k, (d, _b) in plan.new.items():
                if plan.op == "extend":
                    _check_extends(olds.get(k), d)
                else:
                    _check_compaction(olds[k], d, plan.prefix[k])
            if self.track_agent and plan.agent is not None:
                r = c.execute("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", (sid,)).fetchone()
                if r is None:
                    raise Refused("no-session", sid)
                if (r[0], r[1] or 0) != tuple(plan.agent_prev):
                    raise Refused("cas", "agent position moved")
                if plan.epoch_change:
                    # RC-H1: resetarea la 0 e permisă DOAR când epoch-ul chiar se schimbă.
                    if plan.agent[0] == r[0] or plan.agent[1] != 0:
                        raise Refused("agent-regress", f"epoch change {(r[0], r[1])} → {plan.agent}")
                elif plan.agent[0] != r[0] or plan.agent[1] < (r[1] or 0):
                    raise Refused("agent-regress", f"{plan.agent} < {(r[0], r[1])}")
            now = st.clock()
            for g in plan.gaps:
                # RC-M1: rândul durabil al markerului, în ACEEAŞI tranzacţie cu octeţii lui; un id deja
                # publicat ar fi un al doilea marker pentru aceeaşi pierdere → refuzat (readoptare).
                r = c.execute("SELECT published_at FROM tx_gaps WHERE sid=? AND gap_id=?",
                              (sid, g.gap_id)).fetchone()
                if r is not None and r[0] is not None:
                    raise Refused("gap-dup", g.gap_id)
                c.execute("INSERT OR REPLACE INTO tx_gaps(sid, gap_id, epoch, upstream_start, upstream_size, "
                          "reason, out_pos, cast_pos, published_at) VALUES(?,?,?,?,?,?,?,?,?)",
                          (sid, g.gap_id, g.epoch, g.start, g.size, g.reason, g.out_pos, g.cast_pos, now))
            for k, (d, b) in plan.new.items():
                le_bump = 1 if plan.op == "cap" else 0
                if plan.start[k][0] == 0:
                    c.execute("INSERT INTO tx_descriptors(sid, kind, blob, version, list_epoch, "
                              "committed_at, status) VALUES(?,?,?,?,?,?,'ok')",
                              (sid, k, b, d.version, self.list_epoch, now))
                else:
                    c.execute("UPDATE tx_descriptors SET blob=?, version=?, list_epoch=list_epoch+?, "
                              "committed_at=CASE WHEN ? THEN ? ELSE committed_at END "
                              "WHERE sid=? AND kind=?",
                              (b, d.version, le_bump, int(plan.out_grew and k == "out"), now, sid, k))
                st._fault("txn-between")
            for h in plan.listed:
                # Identitatea rândului (sid, kind, inode), nu doar starea lui (R-M2).
                k, dev, ino = plan.ident[h]
                n = c.execute("UPDATE tx_files SET state='published' WHERE gen_id=? AND sid=? "
                              "AND kind=? AND dev=? AND ino=? AND state='created'",
                              (h, sid, k, dev, ino)).rowcount
                if n != 1:
                    raise Refused("ledger", f"{h} not created by us")
            for k, h in plan.retired:
                c.execute("UPDATE tx_files SET state='retired' WHERE gen_id=? AND sid=? AND kind=? "
                          "AND state='published'", (h, sid, k))
            if self.track_agent and plan.agent is not None:
                c.execute("UPDATE sessions SET agent_epoch=?, agent_offset=? WHERE id=?",
                          (plan.agent[0], plan.agent[1], sid))
        return fn

    async def _publish(self, plan):
        fn = self._txn_body(plan)
        try:
            await self.store.txn(fn)
        except Uncertain:
            outcome = await self._resolve(plan)
            if outcome == "not-committed":
                # Doar aceeaşi captură, deja scrisă şi fsync-ată; niciodată un lot re-adăugat.
                try:
                    await self.store.txn(fn)
                except Uncertain:
                    outcome = await self._resolve(plan)
                    if outcome != "committed":
                        raise _NeedReadopt("commit outcome unknown") from None
            elif outcome != "committed":
                raise _NeedReadopt("commit outcome unknown") from None
        except Refused as e:
            if e.args and "stale-writer" in str(e):
                self.state = "replaced"
            else:
                self.store.alarm("transcript.publishRefused", f"{self.sid}: {e}")
            raise
        self._apply(plan)

    async def _resolve(self, plan):
        """Uncertain COMMIT: everything the transaction writes is re-read in ONE read transaction
        on a fresh connection — the descriptors (blob, version, list_epoch), the agent position and
        the ledger rows with their identity (sid, kind, inode). Committed only if all of it is the
        plan's result; not committed only if all of it is still the start; anything else (something
        moved independently), or a re-read that itself fails, is unknown → re-adoption."""
        sid = self.sid
        listed = list(plan.listed)
        retired = [h for _k, h in plan.retired]
        rkind = {h: k for k, h in plan.retired}
        track = self.track_agent and plan.agent is not None
        compact = plan.op in ("cap", "merge")
        if plan.epoch_change and track and plan.agent_prev[0] == plan.agent[0]:
            return "unknown"                      # RC-H1: o „comutare" în acelaşi epoch nu se ia drept comisă

        def load(c):
            descs = {k: c.execute("SELECT blob, version, list_epoch FROM tx_descriptors WHERE sid=? AND kind=?",
                                  (sid, k)).fetchone() for k in plan.start}
            ag = c.execute("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?",
                           (sid,)).fetchone() if track else None
            led = {}
            for h in listed + retired:
                r = c.execute("SELECT state, sid, kind, dev, ino FROM tx_files WHERE gen_id=?", (h,)).fetchone()
                led[h] = tuple(r) if r else None
            gaps = {g.gap_id: c.execute("SELECT published_at, epoch, upstream_start, upstream_size, reason "
                                        "FROM tx_gaps WHERE sid=? AND gap_id=?", (sid, g.gap_id)).fetchone()
                    for g in plan.gaps}
            return descs, ag, led, gaps
        try:
            descs, ag, led, gaps = await self.store.fresh_read(load)
        except (sqlite3.Error, OSError, TxStoreError):
            return "unknown"                      # rezultatul nu se poate stabili: readoptare
        agent_now = (ag[0], ag[1] or 0) if ag is not None else None

        def at(r, version, blob):
            return (r[1] if r else 0) == version and (bytes(r[0]) if r else None) == blob

        def le_is(r, want):
            return not compact or (r is not None and r[2] == want)

        def ours(h, states):
            r = led[h]
            if r is None or r[0] not in states or r[1] != sid:
                return False
            if h in plan.ident:
                return (r[2], r[3], r[4]) == tuple(plan.ident[h])
            return r[2] == rkind.get(h)
        def gap_is(g):
            r = gaps[g.gap_id]
            return r is not None and r[0] is not None and tuple(r[1:]) == (g.epoch, g.start, g.size, g.reason)
        le_after = (plan.list_epoch or 0) + (1 if plan.op == "cap" else 0)
        if (all(at(descs[k], plan.new[k][0].version, plan.new[k][1]) and le_is(descs[k], le_after)
                for k in plan.new)
                and (not track or agent_now == tuple(plan.agent))
                and all(ours(h, ("published",)) for h in listed)
                and all(ours(h, ("retired", "gone")) for h in retired)
                and all(gap_is(g) for g in plan.gaps)):
            return "committed"
        if (all(at(descs[k], *plan.start[k]) and le_is(descs[k], plan.list_epoch) for k in plan.start)
                and (not track or agent_now == tuple(plan.agent_prev))
                and all(ours(h, ("created",)) for h in listed)
                and all(ours(h, ("published",)) for h in retired)
                and all(gaps[g.gap_id] is None or gaps[g.gap_id][0] is None for g in plan.gaps)):
            return "not-committed"
        return "unknown"

    def _apply(self, plan):
        for k, (d, _b) in plan.new.items():
            self.committed[k] = d
            listed = {g.gen_id for g in d.generations}
            for g in self.done[k]:
                if g.gen_id in listed:
                    g.published = True
                    self._drop_gen_fd(g)
            self.done[k] = [g for g in self.done[k] if g.fd is not None]
            c = self.cur[k]
            if c is not None and c.gen_id in listed:
                c.published = True
            self.to_recover[k] = set()
        if plan.op == "cap":
            self.list_epoch += 1
        if plan.agent is not None:
            self._covered = tuple(plan.agent)
            if self.track_agent:
                self.agent_committed = tuple(plan.agent)
        if plan.op == "extend" and plan.gaps:
            # O publicare „extend" listează TOT ce ţin writerele: markerele ei sunt acum comise
            # (cu rândurile lor tx_gaps, în aceeaşi tranzacţie).
            ids = {id(g) for g in plan.gaps}
            self.gaps += plan.gaps
            self._gaps_unpub = [g for g in self._gaps_unpub if id(g) not in ids]
            for g in plan.gaps:
                if g.reason.startswith("skip:"):
                    self.store.alarm("transcript.gap", f"{self.sid}: gap {g.gap_id}: {g.size} bytes of epoch "
                                                       f"{g.epoch} skipped upstream at {g.start} ({g.reason})")

    async def _maybe_roll(self, force=False, reopen=True):
        """SEAL the current generations that are full (or all, `force`), open the next ones
        BEFORE publishing (a failed publication leaves the sealed ones dirty and a usable current
        one), publish with the written position. A seal / fsync fault is a write fault."""
        rolling = [k for k in KIND_NAMES if self.cur[k] is not None and self.cur[k].writer.data_count
                   and (force or self.cur[k].writer.should_roll())]
        if not rolling:
            return False
        try:
            for k in rolling:
                self.store._fault("seal")
                await self.store.io(self.cur[k].writer.seal)
            await self._fsync({k: [self.cur[k]] if k in rolling else [] for k in KIND_NAMES})
        except (OSError, txformat.TxFormatError) as e:
            await self._writer_failed(e)
            raise TxStoreError("writeFailed", str(e)) from None
        for k in rolling:
            self.done[k].append(self.cur[k])
            self.cur[k] = None
        if reopen:
            for k in rolling:
                await self._reopen(k)
        await self._publish(self._plan(self._written_agent))
        return True

    def _maybe_trigger_cap(self):
        if self.capping or self.store.clock() < self.cap_not_before:
            return
        over = any(self.committed_len(k) >= self.store.max_bytes for k in KIND_NAMES)
        many = any(self.committed[k] is not None and len(self.committed[k].generations) > self.store.op_gen_cap
                   for k in KIND_NAMES)
        if over or many:
            async def run():
                with contextlib.suppress(Exception):
                    await self.cap_now(truncate=over)
            asyncio.get_running_loop().create_task(run())

    async def _job_roll_all(self):
        self._check_token()
        await self._job_checkpoint()
        await self._maybe_roll(force=True)
        prefix = {k: (self.committed[k].generations if self.committed[k] else ()) for k in KIND_NAMES}
        return prefix, self.list_epoch

    async def _build_compacted(self, prefix, truncate):
        """Off the lease: T per kind from a snapshot of P (pinned), written, sealed, fsynced and
        read back with verify_full. Returns {kind: _Gen (sealed, unpublished)}."""
        st = self.store
        pins = [g.gen_id.hex() for k in KIND_NAMES for g in prefix[k]]
        built = {}
        with st.pinned(pins):
            snaps = {}
            try:
                for k in KIND_NAMES:
                    if prefix[k]:
                        d = txdesc.Descriptor(st.inst, self.sidb, KINDS[k], 0, b"\0" * 32, prefix[k])
                        snaps[k] = await st._make_snapshot(Snapshot, self.sid, k, d, self.rk,
                                                           self.list_epoch, None,
                                                           nfds=len(prefix[k]), force=True)
                for k in KIND_NAMES:
                    if k in snaps:
                        async with st.lease(self.sid):
                            built[k] = await self._open_gen_full(k)
                await st.io(self._fill_compacted, snaps, built, truncate)
                await st.io(self._finish_compacted, built)
            except BaseException:
                await self._discard_built(built)
                raise
            finally:
                for s in snaps.values():
                    s.close()
        return built

    async def _open_gen_full(self, kind):
        # T foloseşte limitele §12.1 complete (concatenarea unui merge poate depăşi limitele de test).
        st = self.store
        gid, fd, dev, ino, name = await st.reserve_and_create(self.sid, kind)
        g = _Gen(kind, gid, name, fd, None, dev, ino)
        try:
            g.writer = await st.io(txformat.Writer, _File(fd, st), self.rk, kind=KINDS[kind],
                                   sid=self.sidb, gen_id=gid, created_ms=int(st.clock() * 1000))
        except Exception:
            self._drop_gen_fd(g)
            with contextlib.suppress(Exception):
                await self._retire_unpublished(g)
            raise
        return g

    def _fill_compacted(self, snaps, built, truncate):
        big = Budget(1 << 62, pre_first=1 << 62)

        def reader(k):
            if k not in snaps:
                return None
            return lambda off, n: snaps[k]._read_sync(off, off + n, big)

        def sink(k):
            return lambda b: built[k].writer.write(b) if b else None
        if truncate:
            # O pereche istorică cu un singur kind se plafonează pe kind-ul ei (regula 3.7 per flux).
            cap_streams(reader("out"), reader("cast"), snaps["out"].length if "out" in snaps else 0,
                        snaps["cast"].length if "cast" in snaps else 0, self.store.keep_bytes,
                        self.store.clock(), sink("out") if "out" in built else None,
                        sink("cast") if "cast" in built else None)
        else:
            for k, s in snaps.items():
                with s._using():
                    for piece in s._chunks(0, s.length, big, CAP_CHUNK):
                        built[k].writer.write(piece)

    def _finish_compacted(self, built):
        for k, g in built.items():
            g.writer.seal()
            os.fsync(g.fd)
        os.fsync(self.store.dir_fd)
        for k, g in built.items():
            # Citire înapoi pe un fd nou, read-only, prin acelaşi nume (verify_full al întregii generaţii).
            w = g.writer
            fd = os.open(g.name, _RDONLY, dir_fd=self.store.dir_fd)
            try:
                if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (g.dev, g.ino):
                    raise TxStoreError("corrupt", "compacted generation replaced under us")
                txformat.verify_full(_PRead(fd, 0, limit=w.phys_len), self.rk, kind=KINDS[k],
                                     sid=self.sidb, gen_id=g.gen_id, data_count=w.data_count,
                                     plain_len=w.plain_len, phys_len=w.phys_len, hdr_mac=w.hdr_mac)
            finally:
                os.close(fd)

    async def _discard_built(self, built):
        for g in built.values():
            if g.fd is not None:
                with contextlib.suppress(OSError):
                    os.close(g.fd)
                g.fd = None
            if not g.published:
                with contextlib.suppress(Exception):
                    await self._retire_unpublished(g)

    async def _job_cap_publish(self, prefix, built, list_epoch, truncate):
        """Typed cap/merge: the committed list must still start with exactly P (and list_epoch is
        the one seen at build time); P ‖ L → T ‖ L, T published, P retired, then unlinked."""
        self._check_token()
        await self._job_checkpoint()
        new, start, listed, retired, ident = {}, {}, [], [], {}
        for k in KIND_NAMES:
            if k not in built:
                continue
            old = self.committed[k]
            P = tuple(prefix[k])
            if old is None or tuple(old.generations[:len(P)]) != P or list_epoch != self.list_epoch:
                return False                      # rezultat învechit: T se retrage
            L = old.generations[len(P):]
            w = built[k].writer
            T = txdesc.Generation(built[k].gen_id, txdesc.STATE_SEALED, w.data_count, w.plain_len,
                                  w.phys_len, w.hdr_mac)
            d = txdesc.Descriptor(old.installation_id, old.sid, old.kind, old.version + 1, old.rk_hash,
                                  (T,) + tuple(L), old.flags)
            start[k] = (old.version, self.store.encode(old))
            new[k] = (d, self.store.encode(d))
            listed.append(built[k].gen_id.hex())
            ident[built[k].gen_id.hex()] = (k, built[k].dev, built[k].ino)
            retired += [(k, g.gen_id.hex()) for g in P]
        plan = _Plan("cap" if truncate else "merge", start, new, listed, retired, list_epoch=list_epoch,
                     prefix={k: tuple(prefix[k]) for k in built}, ident=ident)
        try:
            await self._publish(plan)
        except Refused:
            return False
        for g in built.values():
            g.published = True
            with contextlib.suppress(OSError):
                os.close(g.fd)
            g.fd = None
        for k, h in retired:
            await self.store.retire(self.sid, k, h)
        return True

    async def _checkpoint_or_flush(self):
        """One checkpoint; if it fails short of a re-adoption, publish what the writers hold or
        abandon them (`_flush_dirty`). Afterwards the writers hold nothing unpublished."""
        try:
            await self._job_checkpoint()
        except _NeedReadopt:
            raise
        except Refused as e:
            if self.state == "replaced":
                raise
            raise _NeedReadopt(f"publication refused: {e}") from None
        except (TxStoreError, OSError, sqlite3.Error, txformat.TxFormatError):
            await self._flush_dirty()

    async def _emit_owned(self, owed, *, into_switch, cast_ts, reason, epoch):
        """A marker the recorder owes (epoch cut, close): emitted once, its Gap kept in `owed`
        across attempts, re-emitted only when the writers holding it were abandoned. Returns the
        published Gap, or None when it could not be published."""
        for _attempt in (0, 1):
            g = owed.get("gap")
            if g is not None and any(x is g for x in self.gaps):
                return g
            if g is None or not any(x is g for x in self._gaps_unpub):
                owed["gap"] = g = self._add_gap(owed["agent"], cast_ts, reason=reason, epoch=epoch,
                                                start=owed["start"], out=owed["out"], cast=owed["cast"],
                                                into_switch=into_switch)
            await self._checkpoint_or_flush()
            if any(x is g for x in self.gaps):
                return g
        return None

    async def _unrecorded(self, owed, epoch):
        """RC-M1: a marker that could not be published. Its loss is alarmed with the gap id and
        kept durably (best effort: a `tx_gaps` row with published_at NULL), and the alarm says
        that re-adoption does NOT repair it: the bytes are gone, only the marker is missing."""
        g = owed.get("gap")
        gid = g.gap_id if g is not None else "-"
        self.store.alarm("transcript.gapUnrecorded",
                         f"{self.sid}: gap {gid}: {owed['agent']} bytes of epoch {epoch} lost, marker not "
                         "published; re-adoption does not repair this loss")
        if g is None:
            return
        sid = self.sid

        def fn(c):
            c.execute("INSERT OR IGNORE INTO tx_gaps(sid, gap_id, epoch, upstream_start, upstream_size, reason, "
                      "out_pos, cast_pos, published_at) VALUES(?,?,?,?,?,?,NULL,NULL,NULL)",
                      (sid, g.gap_id, g.epoch, g.start, owed["agent"], g.reason))
        with contextlib.suppress(Exception):
            await self.store.txn(fn)

    async def _job_epoch(self, new_epoch):
        """The switch for the cut taken in `change_epoch`. The old epoch's held segment is
        published under its position; whatever of the old epoch is not covered by published bytes
        after that (an overflow before the cut, a failed write or publication of the segment)
        becomes ONE GAP_MARKER for exactly those upstream bytes, published BEFORE the switch, then
        alarmed. Then SEAL, then (new_epoch, 0) through the same CAS'd transaction (with
        uncertain-COMMIT resolution) even when no descriptor exists yet. Only then do the new
        epoch's bytes become capturable. A failure re-adopts from the DB; a marker that could not
        be published is alarmed with its exact size first."""
        self._check_token()
        sw = self._switch
        if sw is None or sw["new"] != new_epoch or sw["old"][0] == new_epoch:
            raise _NeedReadopt("epoch job without its cut")
        try:
            await self._checkpoint_or_flush()
            oe, oo = sw["old"]
            ce, co = self._covered
            uncovered = max(0, oo - co) if ce == oe else oo
            owed = sw["owed"]
            if owed is None and (uncovered or any(sw["loss"][k] for k in ("agent", "out", "cast"))):
                owed = sw["owed"] = {"agent": sw["loss"]["agent"] + uncovered, "out": sw["loss"]["out"],
                                     "cast": sw["loss"]["cast"], "gap": None,
                                     "start": co if ce == oe else 0}
            if owed is not None:
                g = await self._emit_owned(owed, into_switch=True, cast_ts=0.0, reason="epoch-cut", epoch=oe)
                if g is None:
                    await self._unrecorded(owed, oe)
                    raise _NeedReadopt("epoch cut: gap marker not published")
                self.store.alarm("transcript.gap", f"{self.sid}: gap {g.gap_id}: {owed['agent']} bytes of epoch "
                                                   f"{oe} lost at the cut")
            await self._maybe_roll(force=True)
            plan = self._plan((new_epoch, 0), epoch_change=True)
            if plan.new or self.track_agent:
                await self._publish(plan)
        except _NeedReadopt:
            raise
        except Refused as e:
            if self.state == "replaced":
                raise
            raise _NeedReadopt(f"epoch change refused: {e}") from None
        except (TxStoreError, OSError, sqlite3.Error, txformat.TxFormatError) as e:
            # Tăietura nu rămâne pe jumătate: octeţii noului epoch aşteaptă un comutator comis.
            raise _NeedReadopt(f"epoch change failed: {e}") from None
        self._switch = None
        self._written_agent = self._covered
        self._recount_pos()
        return self.agent_committed

    async def _job_finalize(self, cast_ts=0.0):
        """Close: drain (final checkpoint of everything accepted before close; a failed one is
        published or abandoned), then ONE GAP_MARKER for everything not recorded (an overflow
        still open, abandoned bytes), SEAL both kinds, publish; retire never-published
        generations. The owed marker and its accounting are kept across attempts: a failure
        leaves the recorder retryable (close() again) with the same total."""
        if self.store.tokens.get(self.sid) != self.token:
            self.state = "replaced"
            return None
        self.closing = True
        await self._checkpoint_or_flush()
        L = self._loss
        if self._close_gap is None and (self.overflow or any(L[k] for k in ("agent", "out", "cast"))):
            ce, co = self._covered
            self._close_gap = {"agent": 0, "out": 0, "cast": 0, "gap": None, "epoch": self.agent_epoch,
                               "start": co if ce == self.agent_epoch else 0, "alarmed": False}
        if self._close_gap is not None:
            cg = self._close_gap
            if cg["gap"] is None or not any(x is cg["gap"] for x in self.gaps):
                # Pierderea nouă (o încercare anterioară eşuată) se adaugă la aceeaşi, nu se înlocuieşte.
                for k in ("agent", "out", "cast"):
                    cg[k] += L[k]
                self._loss = self._new_loss(self.agent_epoch)
                # Offsetul agentului NU avansează peste ce s-a înregistrat.
                self.overflow = False
                self.agent_epoch, self.agent_offset = self._pend_from = self._covered
                self._recount_pos()
                g = await self._emit_owned(cg, into_switch=False, cast_ts=cast_ts, reason="close",
                                           epoch=cg["epoch"])
                if g is None:
                    raise TxStoreError("writeFailed", "close: gap marker not published")
            if not cg["alarmed"]:
                cg["alarmed"] = True
                self.store.alarm("transcript.gap", f"{self.sid}: gap {cg['gap'].gap_id}: {cg['agent']} bytes "
                                                   "lost before close")
        await self._maybe_roll(force=True, reopen=False)
        for k in KIND_NAMES:
            g = self.cur[k]
            if g is not None and not g.published:
                self._drop_gen_fd(g)
                await self._retire_unpublished(g)
            self.cur[k] = None
        self.state = "closed"
        if self.store.tokens.get(self.sid) == self.token:
            del self.store.tokens[self.sid]
        res = self._snapshot_state()
        res["lost"] = self._close_gap["agent"] if self._close_gap is not None else None
        res["rejected"] = self.rejected
        return res


class _NeedReadopt(TxStoreError):
    def __init__(self, detail):
        super().__init__("readopt", detail)


def _check_extends(old, new):
    """checkpoint / seal / roll: same gen_ids in the same order, every count ≥, a committed
    sealed/recovered never changes, at most one new live at the end (txdesc checks the latter)."""
    og = old.generations if old else ()
    ng = new.generations
    if len(ng) < len(og):
        raise Refused("regress", "fewer generations")
    for a, b in zip(og, ng):
        if a.gen_id != b.gen_id or a.hdr_mac != b.hdr_mac:
            raise Refused("regress", "generation list reordered")
        if a.state in (txdesc.STATE_SEALED, txdesc.STATE_RECOVERED) and a != b:
            raise Refused("regress", "a closed generation changed")
        if (b.data_count < a.data_count or b.plain_len < a.plain_len or b.phys_len < a.phys_len):
            raise Refused("regress", "a committed prefix would shrink")
        if a.state == txdesc.STATE_LIVE and b.state == txdesc.STATE_RECOVERED and a != txdesc.Generation(
                b.gen_id, a.state, b.data_count, b.plain_len, b.phys_len, b.hdr_mac):
            raise Refused("regress", "recovered must keep the committed counts")
    if new.flags != (old.flags if old else new.flags):
        raise Refused("regress", "flags changed")


def _check_compaction(old, new, prefix):
    if old is None or tuple(old.generations[:len(prefix)]) != tuple(prefix):
        raise Refused("cas", "committed list no longer starts with P")
    if tuple(new.generations[1:]) != tuple(old.generations[len(prefix):]):
        raise Refused("cas", "tail L not preserved")
