"""Encrypted recordings: publication (Recorder) and readers (ENCRYPTION-AT-REST.md §12.11).

PR5a: implemented and tested in isolation, **not wired** into core.py. A `Store` refuses to exist
unless `WEBTERM_TX_RECORDINGS=1` *and* the volume is a test-fixture volume
(`tx_state.test_volume = 1`, written only by `create_test_volume`, which itself needs
`WEBTERM_TEST_GATE`). Enabling on a real volume needs PR6 (migration, erasure journal, quarantine).

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
import re
import secrets
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass, field

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
    env = os.environ if env is None else env
    return bool(env.get(ENV_TEST_GATE, ""))


def create_test_volume(db_path, env=None):
    """The test-fixture helper: marks a volume `tx_state.test_volume = 1`. Nothing else sets it;
    refused outside a test gate."""
    if not test_gate(env):
        raise TxStoreError("disabled", "test volumes exist only under WEBTERM_TEST_GATE")
    con = sqlite3.connect(str(db_path), isolation_level=None, timeout=5)
    try:
        con.execute("INSERT OR REPLACE INTO tx_state(key, value) VALUES('test_volume', '1')")
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
    bytes, the gap timestamped with the first kept event."""
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

    out_sink(GAP_MARKER)
    copy(read_out, out_sink, max(0, out_end - keep), out_end)
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
    """File-like over an fd with its own position (pread): snapshots share nothing."""

    def __init__(self, fd, pos):
        self.fd = fd
        self.pos = pos

    def read(self, n):
        b = os.pread(self.fd, n, self.pos)
        self.pos += len(b)
        return b


class Budget:
    """Bytes a request may parse: `total` across every generation, `pre_first` before the first
    returned byte (None = the default for the path: 1 MiB with an index, max+keep without)."""

    def __init__(self, total, pre_first=None):
        self.total = total
        self.pre_first = pre_first
        self.used = 0

    def spend(self, n):
        self.used += n
        if self.used > self.total:
            raise TxStoreError("limitExceeded", "request budget")


@dataclass(frozen=True)
class Access:
    """Built by the route's own authorization step; counters captured *before* the decision."""
    sid: str
    principal: str
    route: str
    sid_epoch: int
    access_epoch: int
    not_after: float = None
    owner_recovery: bool = False


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
        if not enabled(env):
            raise TxStoreError("disabled", f"{ENV_FLAG} is not 1")
        self._db_path = str(db_path or config.DB_PATH)
        self._w = self._connect()
        self._r = self._connect()
        self._rlock = threading.Lock()
        # PR5: activ doar pe un volum de test, şi doar sub o poartă de test (§12.11 PR5/PR6).
        row = self._r.execute("SELECT value FROM tx_state WHERE key='test_volume'").fetchone()
        if row is None or row[0] != "1":
            self.close()
            raise TxStoreError("disabled", "encrypted recordings need PR6 on a real volume")
        if not test_gate(env):
            self.close()
            raise TxStoreError("disabled", "test volume outside a test gate")
        self.dir_fd = os.open(str(transcripts_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                              | os.O_CLOEXEC)
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
        self._snapshots = set()
        self._gen_fds = 0
        self._sem = None
        self._caches = []
        self.live_index = {}              # (sid, kind, gen hex) → [IndexEntry]
        self.alarms = []
        self.fault = None
        self.gen_id_source = os.urandom
        self._supervised = set()
        self.on_readopt = None
        self.readopt_enabled = True              # teste: un „crash" de proces nu se readoptă pe loc

    # ── plumbing ──

    def _connect(self):
        con = sqlite3.connect(self._db_path, isolation_level=None, check_same_thread=False, timeout=5)
        con.execute("PRAGMA busy_timeout=5000")
        return con

    def close(self):
        for s in list(getattr(self, "_snapshots", ())):
            s.close()
        for con in (getattr(self, "_w", None), getattr(self, "_r", None)):
            if con is not None:
                con.close()
        if getattr(self, "dir_fd", None) is not None:
            os.close(self.dir_fd)
            self.dir_fd = None

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
        while a thread is still inside write/fsync (§12.11.1 Supervision)."""
        loop = asyncio.get_running_loop()
        fut = loop.run_in_executor(None, lambda: fn(*args, **kw))
        try:
            return await asyncio.shield(fut)
        except asyncio.CancelledError:
            with contextlib.suppress(BaseException):
                await asyncio.wait([fut])
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
        old = self.recorders.get(sid)
        if old is not None and old.state == "running":
            raise TxStoreError("busy", "recorder already running")
        rec = Recorder(self, sid, track_agent=track_agent)
        await rec._start()
        self.recorders[sid] = rec
        t = asyncio.get_running_loop().create_task(self._supervise(rec))
        self._supervised.add(t)
        t.add_done_callback(self._supervised.discard)
        return rec

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
        if not self.readopt_enabled:
            return
        try:
            new = await self.start_recorder(rec.sid, track_agent=rec.track_agent)
        except Exception as e:
            self.alarm("transcript.readoptFailed", f"{rec.sid}: {e}")
            return
        if self.on_readopt is not None:
            self.on_readopt(rec.sid, new)

    async def shutdown(self):
        for rec in list(self.recorders.values()):
            with contextlib.suppress(Exception):
                await asyncio.wait_for(rec.close(), SHUTDOWN_SECS)
        for t in list(self._supervised):
            t.cancel()

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
        """Capture the counters BEFORE the route's authorization decision."""
        return Access(sid, principal, route, self.sid_epoch[sid], self.access_epoch, not_after,
                      owner_recovery)

    def check(self, access):
        """The synchronous check (linearisation point at open; check points (a)–(c))."""
        sid = access.sid
        if sid in self.tombstoned or self.sid_epoch[sid] != access.sid_epoch or sid in self._fences:
            raise Revoked("revoked", sid)
        if None in self._fences or self.access_epoch != access.access_epoch:
            raise NeedsReauth("reauth", "access changed")
        if access.not_after is not None and self.clock() >= access.not_after:
            raise NeedsReauth("expired", "access expired")

    # ── readers ──

    def _admit(self, nfds):
        if len(self._snapshots) >= MAX_SNAPSHOTS or self._gen_fds + nfds > MAX_GEN_FDS:
            raise TxStoreError("busy", "snapshot budget")

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
        for attempt in (0, 1):
            if access.sid != sid:
                raise TxStoreError("bad-access", "access built for another sid")
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
        raise Revoked("revoked")                  # pragma: no cover

    async def _open_once(self, sid, kind, access):
        if kind not in KINDS:
            raise TxStoreError("notFound", "kind")
        _sid_bytes(sid)
        if sid in self.tombstoned:
            raise TxStoreError("notFound", "erased")
        self._admit(0)

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
        if status in ("quarantined", "recovery") and not access.owner_recovery:
            raise TxStoreError("quarantined", f"{sid}.{kind}")
        if krow is None:
            self.alarm("transcript.keyError", f"{sid}: descriptor without RK")
            raise TxStoreError("keyError", "no RK")
        env = bytes(krow[0])
        d = self.decode(drow, sid, kind, env)
        rk = self.rk_for(sid, env)
        self._admit(len(d.generations))
        return await self.io(Snapshot._build, self, sid, kind, d, rk, drow[3], access)

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
        if dirn not in ("transcripts", "arhiva") or "/" in name or name in ("", ".", ".."):
            raise TxStoreError("downgrade", "bad inventory row")
        path_fd = self.dir_fd if dirn == "transcripts" else None
        try:
            if path_fd is None:
                sub = os.open("arhiva", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=self.dir_fd)
                try:
                    fd = os.open(name, _RDONLY, dir_fd=sub)
                finally:
                    os.close(sub)
            else:
                fd = os.open(name, _RDONLY, dir_fd=path_fd)
        except OSError:
            raise TxStoreError("notFound", "plaintext missing") from None
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
                != (dev, ino, size, mtime_ns)):
            os.close(fd)
            self.alarm("transcript.downgrade", f"{sid}.{kind}: plaintext changed since inventory")
            raise TxStoreError("downgrade", "plaintext differs from its inventory row")
        snap = PlainSnapshot(self, sid, kind, fd, size, access)
        self._snapshots.add(snap)
        self._gen_fds += 1
        return snap

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
        for ki, k in enumerate(KIND_NAMES):
            d = descs.get(k)
            if d is None:
                continue
            for gi, g in enumerate(d.generations):
                if (ki, gi) < tuple(start):
                    continue
                if spent and spent + g.plain_len > budget:
                    rep["cursor"] = {"versions": versions, "at": (ki, gi)}
                    return rep
                spent += g.plain_len
                prob, info = self._verify_gen(sid, k, g, rk)
                if prob:
                    rep["ok"] = False
                    rep["problems"].append(f"{k}.{g.gen_id.hex()}: {prob}")
                if info:
                    rep["info"].append(f"{k}.{g.gen_id.hex()}: {info}")
        return rep

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
            fp = _PRead(fd, 0)
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
                    if fp.read(1):
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


# ── Snapshot ─────────────────────────────────────────────────────────────────


class Snapshot:
    """Fds, descriptor and counters of one (sid, kind) fixed at open. Unlinked inodes stay
    readable through the fds, so a concurrent cap / merge / purge cannot change what it reads."""

    def __init__(self, store, sid, kind, desc, rk, list_epoch, access):
        self.store = store
        self.sid = sid
        self.kind = kind
        self.desc = desc
        self.rk = rk
        self.list_epoch = list_epoch
        self.access = access
        self.gens = []                            # (Generation, fd, logical start)
        self.length = 0
        self.closed = False
        self.last_used = time.monotonic()
        self.cancel = threading.Event()

    @property
    def version(self):
        return self.desc.version

    @classmethod
    def _build(cls, store, sid, kind, desc, rk, list_epoch, access):
        snap = cls(store, sid, kind, desc, rk, list_epoch, access)
        try:
            for g in desc.generations:
                try:
                    fd = os.open(gen_name(sid, kind, g.gen_id.hex()), _RDONLY, dir_fd=store.dir_fd)
                except OSError:
                    raise TxStoreError("damaged", f"generation {g.gen_id.hex()} missing") from None
                snap.gens.append((g, fd, snap.length))
                store._gen_fds += 1
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
                snap.length += g.plain_len
        except BaseException:
            snap.close()
            raise
        store._snapshots.add(snap)
        return snap

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.cancel.set()
        for _g, fd, _s in self.gens:
            os.close(fd)
            self.store._gen_fds -= 1
        self.store._snapshots.discard(self)

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
        cur = txformat.RecordCursor(_PRead(fd, foff), self.rk, kind=KINDS[self.kind],
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

    def read_sync(self, start, end, budget):
        return b"".join(self._chunks(start, end, budget, STREAM_CHUNK))

    async def _checkpoint(self, reauthorize):
        try:
            self.store.check(self.access)
        except NeedsReauth:
            if reauthorize is None:
                raise Revoked("revoked", "access changed; no re-authorization") from None
            for _ in (0, 1):
                await self.store.wait_fences(self.sid)
                new = await reauthorize()        # NotAuthorized etc. → propagă, fluxul se opreşte
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
            data = await self.store.io(self.read_sync, start, end, budget)
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
                    piece = await self.store.io(next, gen, done)
                if piece is done:
                    return
                self.last_used = time.monotonic()
                await self._checkpoint(reauthorize)
                yield piece
        finally:
            gen.close()


class PlainSnapshot:
    """3.7 plaintext (inventoried `pending`, identity-checked), same API, one fd."""

    def __init__(self, store, sid, kind, fd, size, access):
        self.store = store
        self.sid = sid
        self.kind = kind
        self.fd = fd
        self.length = size
        self.access = access
        self.list_epoch = 0
        self.closed = False
        self.last_used = time.monotonic()
        self.cancel = threading.Event()

    def close(self):
        if not self.closed:
            self.closed = True
            os.close(self.fd)
            self.store._gen_fds -= 1
            self.store._snapshots.discard(self)

    def _chunks(self, start, end, budget, chunk):
        pos, end = max(0, start), min(end, self.length)
        while pos < end:
            b = os.pread(self.fd, min(chunk, end - pos), pos)
            if not b:
                return
            budget.spend(len(b))
            yield b
            pos += len(b)

    read_sync = Snapshot.read_sync
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
            yield bytes(buf[:i + 1])
            del buf[:i + 1]
        if len(buf) > max_line:
            raise TxStoreError("limitExceeded", "line longer than the redaction buffer")
    if buf:
        yield bytes(buf)


class ResponseCache:
    """Small LRU of computed responses keyed by (sid, kind, version, list digest, policy version,
    revocation_epoch[sid], access_epoch); dropped on any bump, checked before serve and put."""

    def __init__(self, store, size=1):
        self.store = store
        self.size = size
        self._d = collections.OrderedDict()
        store._caches.append(self)

    def key(self, snap, policy_version):
        return (snap.sid, snap.kind, snap.version, _list_digest(snap.desc), policy_version,
                self.store.sid_epoch[snap.sid], self.store.access_epoch)

    def _current(self, key):
        return key[5] == self.store.sid_epoch[key[0]] and key[6] == self.store.access_epoch

    def get(self, key, access):
        self.store.check(access)                  # (a) înainte de a servi din cache
        v = self._d.get(key)
        if v is None or not self._current(key):
            self._d.pop(key, None)
            return None
        self._d.move_to_end(key)
        return v

    def put(self, key, value, access):
        self.store.check(access)                  # (a) înainte de a pune în cache
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


class Recorder:
    """One per recorded sid: a worker task with a FIFO job queue (§12.11.1)."""

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
        self.dropped = 0
        self.degraded = False
        self.gap_pending = None
        self.gaps = []
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
            for k in KIND_NAMES:
                self.cur[k] = await self._open_gen(k)
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
        self.out_pos = self.committed_len("out")

    def committed_len(self, kind):
        d = self.committed[kind]
        return sum(g.plain_len for g in d.generations) if d else 0

    async def _open_gen(self, kind):
        st = self.store
        gid, fd, dev, ino, name = await st.reserve_and_create(self.sid, kind)
        try:
            w = await st.io(txformat.Writer, _File(fd, st), self.rk, kind=KINDS[kind], sid=self.sidb,
                            gen_id=gid, created_ms=int(st.clock() * 1000),
                            max_records=st.gen_limits[0], max_plain=st.gen_limits[1])
        except BaseException:
            os.close(fd)
            raise
        st._fault("header")
        g = _Gen(kind, gid, name, fd, w, dev, ino)
        st.live_index[(self.sid, kind, gid.hex())] = g.index
        return g

    def _close_fds(self):
        for k in KIND_NAMES:
            for g in [self.cur[k]] + self.done[k]:
                if g is not None and g.fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(g.fd)
                    g.fd = None
            self.cur[k] = None
            self.done[k] = []
        self.store.buffered_total -= sum(len(b) for b in self.pending.values())
        for b in self.pending.values():
            b.clear()

    # ── loop side (synchronous, no file I/O) ──

    def _buffered(self):
        return sum(len(b) for b in self.pending.values()) + self.inflight

    def _feed(self, kind, data):
        if self.state != "running":
            self.dropped += len(data)
            return False
        if self.overflow:
            if kind == "out":
                self.dropped += len(data)
            return False
        n = len(data)
        if self._buffered() + n > self.store.pending_cap or self.store.buffered_total + n > self.store.total_cap:
            self._enter_overflow(n if kind == "out" else 0)
            return False
        self.pending[kind] += data
        self.store.buffered_total += n
        return True

    def feed_out(self, data, agent_bytes=None):
        """`.out` bytes from `_process_output`; advances the agent offset in memory."""
        if self._feed("out", data):
            self.agent_offset += len(data) if agent_bytes is None else agent_bytes
            self.out_pos += len(data)

    def feed_cast(self, data):
        self._feed("cast", data)

    def _enter_overflow(self, incoming):
        # Doar bufferul în aşteptare se aruncă, niciodată lotul în zbor; agent_offset NU se derulează
        # cât timp un job e în zbor (§12.11.1 Backpressure).
        lost = len(self.pending["out"])
        self.store.buffered_total -= sum(len(b) for b in self.pending.values())
        for b in self.pending.values():
            b.clear()
        self.overflow = True
        self.dropped += lost + incoming
        if not self.degraded:
            self.degraded = True
            self.store.alarm("transcript.degraded", f"{self.sid}: recording buffer overflow")

    async def resume(self):
        """After an overflow or a write fault: queued behind the in-flight job, re-reads the
        committed position C from the DB and resumes there. Returns C = (agent_epoch,
        agent_offset, out_pos, dropped). The hub re-attaches at C's agent offset; what the ring
        no longer has becomes ONE `gap(size)` at C."""
        return await self._submit("resync")

    def gap(self, size, cast_ts=0.0):
        """One GAP_MARKER at the current committed position, carrying the lost length (recorded
        in `gaps`, audited by the caller); the same position as a `.cast` gap event."""
        if self.overflow or self.state != "running":
            raise TxStoreError("busy", "resume first")
        pos = self.out_pos
        self.pending["out"] += GAP_MARKER
        self.pending["cast"] += gap_event(cast_ts)
        self.store.buffered_total += len(GAP_MARKER) + len(gap_event(cast_ts))
        self.out_pos += len(GAP_MARKER)
        self.gap_pending = (pos, size)

    # ── jobs ──

    def _submit(self, op, *args):
        if self.state != "running":
            raise RecorderLost("lost", f"recorder {self.state}")
        fut = asyncio.get_running_loop().create_future()
        self._queue.put_nowait((op, args, fut))
        # Anularea apelantului nu anulează un job început.
        return asyncio.shield(fut)

    def checkpoint(self):
        return self._submit("checkpoint")

    def close(self):
        return self._submit("finalize")

    def change_epoch(self, new_epoch):
        return self._submit("epoch", new_epoch)

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
        sid = self.sid

        def load(c):
            return (c.execute("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?",
                              (sid,)).fetchone(),)
        (ag,) = await self.store.fresh_read(load)
        if self.track_agent and ag is not None:
            self.agent_committed = (ag[0], ag[1] or 0)
        self.agent_epoch, self.agent_offset = self.agent_committed
        self.out_pos = self.committed_len("out")
        dropped, self.dropped = self.dropped, 0
        self.overflow = False
        return (self.agent_epoch, self.agent_offset, self.out_pos, dropped)

    async def _job_checkpoint(self):
        self._check_token()
        if self.overflow:
            return None
        # Captura: schimbăm bufferele şi luăm poziţia agentului ÎN ACELAŞI tick.
        batch = {k: bytes(self.pending[k]) for k in KIND_NAMES}
        for k in KIND_NAMES:
            self.pending[k] = bytearray()
        size = sum(len(b) for b in batch.values())
        self.inflight += size
        agent_end = (self.agent_epoch, self.agent_offset)
        gap = self.gap_pending
        self.gap_pending = None
        try:
            self.store._fault("captured")
            try:
                touched = await self._append(batch)
                await self._fsync(touched)
            except (OSError, txformat.TxFormatError) as e:
                await self._writer_failed(e)
                raise TxStoreError("writeFailed", str(e)) from None
            if not any(touched.values()) and not any(self.to_recover.values()):
                return self._snapshot_state()
            plan = self._plan(touched, agent_end)
            await self._publish(plan)
        finally:
            self.inflight -= size
            self.store.buffered_total -= size
        if gap is not None:
            self.gaps.append(gap)
            self.degraded = False
        elif not self.overflow and self.degraded and not self.dropped:
            self.degraded = False
        await self._maybe_roll()
        self._maybe_trigger_cap()
        return self._snapshot_state()

    def _snapshot_state(self):
        return {"out_len": self.committed_len("out"), "cast_len": self.committed_len("cast"),
                "agent": self.agent_committed, "list_epoch": self.list_epoch}

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
                    self.cur[k] = await self._open_gen(k)
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

    async def _writer_failed(self, err):
        """fsync error / ambiguous write: abandon the generations of this batch (a published one
        becomes `recovered` at its committed counts in the next publication), open new ones,
        discard pending, and ask for a resume from the committed position."""
        self.store.alarm("transcript.writeFailed", f"{self.sid}: {err}")
        for k in KIND_NAMES:
            for g in self.done[k] + [self.cur[k]]:
                if g is None:
                    continue
                g.broken = True
                if g.published:
                    self.to_recover[k].add(g.gen_id)
                with contextlib.suppress(OSError):
                    os.close(g.fd)
                g.fd = None
                self.store.live_index.pop((self.sid, k, g.gen_id.hex()), None)
                if not g.published:
                    await self._retire_unpublished(g)
            self.done[k] = []
            self.cur[k] = None
        self._enter_overflow(0)
        for k in KIND_NAMES:
            self.cur[k] = await self._open_gen(k)

    async def _retire_unpublished(self, g):
        st = self.store
        hexid = g.gen_id.hex()
        await st.txn(lambda c: c.execute("UPDATE tx_files SET state='retired' WHERE gen_id=? "
                                         "AND state='created'", (hexid,)))
        await st.retire(self.sid, g.kind, hexid)

    def _plan(self, touched, agent_end, *, epoch_change=False):
        new, start, listed = {}, {}, []
        for k in KIND_NAMES:
            old = self.committed[k]
            gens = list(old.generations) if old else []
            for i, e in enumerate(gens):
                if e.gen_id in self.to_recover[k] and e.state == txdesc.STATE_LIVE:
                    gens[i] = txdesc.Generation(e.gen_id, txdesc.STATE_RECOVERED, e.data_count,
                                                e.plain_len, e.phys_len, e.hdr_mac)
            for g in self.done[k] + touched[k]:
                w = g.writer
                if w.data_count == 0 or g.broken:
                    continue
                state = txdesc.STATE_SEALED if w.sealed else txdesc.STATE_LIVE
                ent = txdesc.Generation(g.gen_id, state, w.data_count, w.plain_len, w.phys_len,
                                        w.hdr_mac)
                idx = next((i for i, e in enumerate(gens) if e.gen_id == g.gen_id), None)
                if idx is None:
                    gens.append(ent)
                    listed.append(g.gen_id.hex())
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
                     epoch_change=epoch_change, out_grew=out_grew)

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
                if (r[0], r[1] or 0) != plan.agent_prev:
                    raise Refused("cas", "agent position moved")
                if not plan.epoch_change and (plan.agent[0] != r[0] or plan.agent[1] < (r[1] or 0)):
                    raise Refused("agent-regress", f"{plan.agent} < {(r[0], r[1])}")
            now = st.clock()
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
                n = c.execute("UPDATE tx_files SET state='published' WHERE gen_id=? AND sid=? "
                              "AND state='created'", (h, sid)).rowcount
                if n != 1:
                    raise Refused("ledger", f"{h} not created by us")
            for _k, h in plan.retired:
                c.execute("UPDATE tx_files SET state='retired' WHERE gen_id=? AND state='published'", (h,))
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
        sid = self.sid

        def load(c):
            return {k: c.execute("SELECT blob, version FROM tx_descriptors WHERE sid=? AND kind=?",
                                 (sid, k)).fetchone() for k in plan.new}
        rows = await self.store.fresh_read(load)
        if all(r is not None and r[1] == plan.new[k][0].version and bytes(r[0]) == plan.new[k][1]
               for k, r in rows.items()):
            return "committed"
        if all((r[1] if r else 0) == plan.start[k][0] for k, r in rows.items()):
            return "not-committed"
        return "unknown"

    def _apply(self, plan):
        for k, (d, _b) in plan.new.items():
            self.committed[k] = d
            listed = {g.gen_id for g in d.generations}
            for g in self.done[k]:
                if g.gen_id in listed:
                    g.published = True
                    with contextlib.suppress(OSError):
                        os.close(g.fd)
                    g.fd = None
                    self.store.live_index.pop((self.sid, k, g.gen_id.hex()), None)
            self.done[k] = [g for g in self.done[k] if g.fd is not None]
            c = self.cur[k]
            if c is not None and c.gen_id in listed:
                c.published = True
            self.to_recover[k] = set()
        if plan.op == "cap":
            self.list_epoch += 1
        if self.track_agent and plan.agent is not None:
            self.agent_committed = plan.agent

    async def _maybe_roll(self, force=False):
        rolling = [k for k in KIND_NAMES if self.cur[k] is not None and self.cur[k].writer.data_count
                   and (force or self.cur[k].writer.should_roll())]
        if not rolling:
            return False
        for k in rolling:
            await self.store.io(self.cur[k].writer.seal)
        await self._fsync({k: [self.cur[k]] if k in rolling else [] for k in KIND_NAMES})
        for k in rolling:
            self.done[k].append(self.cur[k])
            self.cur[k] = None
        plan = self._plan({k: [] for k in KIND_NAMES}, self.agent_committed)
        await self._publish(plan)
        for k in rolling:
            self.cur[k] = await self._open_gen(k)
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
                        snaps[k] = await st.io(Snapshot._build, st, self.sid, k, d, self.rk,
                                               self.list_epoch, None)
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
        w = await st.io(txformat.Writer, _File(fd, st), self.rk, kind=KINDS[kind], sid=self.sidb,
                        gen_id=gid, created_ms=int(st.clock() * 1000))
        return _Gen(kind, gid, name, fd, w, dev, ino)

    def _fill_compacted(self, snaps, built, truncate):
        big = Budget(1 << 62, pre_first=1 << 62)

        def reader(k):
            return lambda off, n: snaps[k].read_sync(off, off + n, big)

        def sink(k):
            return lambda b: built[k].writer.write(b) if b else None
        if truncate:
            if "out" not in snaps or "cast" not in snaps:
                raise TxStoreError("capOneKind", "cap needs both kinds")
            cap_streams(reader("out"), reader("cast"), snaps["out"].length, snaps["cast"].length,
                        self.store.keep_bytes, self.store.clock(), sink("out"), sink("cast"))
        else:
            for k, s in snaps.items():
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
                txformat.verify_full(_PRead(fd, 0), self.rk, kind=KINDS[k], sid=self.sidb,
                                     gen_id=g.gen_id, data_count=w.data_count, plain_len=w.plain_len,
                                     phys_len=w.phys_len, hdr_mac=w.hdr_mac)
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
        new, start, listed, retired = {}, {}, [], []
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
            retired += [(k, g.gen_id.hex()) for g in P]
        plan = _Plan("cap" if truncate else "merge", start, new, listed, retired, list_epoch=list_epoch,
                     prefix={k: tuple(prefix[k]) for k in built})
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

    async def _job_epoch(self, new_epoch):
        """Writer change for an agent epoch change: flush, seal, publish the new epoch at offset 0
        with fresh generations (nothing is replayed from the old ring)."""
        self._check_token()
        await self._job_checkpoint()
        await self._maybe_roll(force=True)
        plan = self._plan({k: [] for k in KIND_NAMES}, (new_epoch, 0), epoch_change=True)
        if plan.new:
            await self._publish(plan)
        elif self.track_agent:
            sid = self.sid
            await self.store.txn(lambda c: c.execute(
                "UPDATE sessions SET agent_epoch=?, agent_offset=0 WHERE id=?", (new_epoch, sid)))
            self.agent_committed = (new_epoch, 0)
        self.agent_epoch, self.agent_offset = new_epoch, 0
        return self.agent_committed

    async def _job_finalize(self):
        """Close: final checkpoint, SEAL both kinds, publish; retire never-published generations."""
        if self.store.tokens.get(self.sid) != self.token:
            self.state = "replaced"
            return None
        await self._job_checkpoint()
        await self._maybe_roll(force=True)
        for k in KIND_NAMES:
            g = self.cur[k]
            if g is not None and not g.published:
                with contextlib.suppress(OSError):
                    os.close(g.fd)
                g.fd = None
                self.store.live_index.pop((self.sid, k, g.gen_id.hex()), None)
                await self._retire_unpublished(g)
            self.cur[k] = None
        self.state = "closed"
        if self.store.tokens.get(self.sid) == self.token:
            del self.store.tokens[self.sid]
        return self._snapshot_state()


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
