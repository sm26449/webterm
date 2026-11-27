"""Encrypted recordings: publication (Recorder) and readers (ENCRYPTION-AT-REST.md §12.11).

PR5a: implemented and tested in isolation, **not wired** into core.py. A `Store` refuses to exist
unless `WEBTERM_TX_RECORDINGS=1`, `WEBTERM_TEST_GATE=1` (both checked before anything is opened)
*and* the volume is a test-fixture volume: an existing DB (opened `mode=rw`, never created) and a
transcripts dir, both in one private harness dir under the system temp dir, whose
`tx_state.test_volume` marker binds both identities (written only by `create_test_volume`, which
refuses a DB with `users` / `hosts` rows). This guards against accidents, not against an operator
who can write the DB. A real volume (PR6b) opens only with `real_volume=True`, which only
`txhub.boot` passes, with a protected keyring; the boot then requires the migration, the erasure
journal and the quarantine to report ready. The plaintext-migration primitives (`convert_plain`,
the identity-checked unlink) live here too; their orchestration is `migration.py`.

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
import concurrent.futures
import contextlib
import ctypes
import errno
import hashlib
import hmac
import json
import os
import pathlib
import platform
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


def _has_test_marker(db_path):
    """True when the DB carries `tx_state.test_volume` (read-only probe; an unreadable DB refuses)."""
    real = os.path.realpath(str(db_path))
    try:
        con = sqlite3.connect(pathlib.Path(real).as_uri() + "?mode=ro", uri=True, timeout=5)
    except sqlite3.Error as e:
        raise TxStoreError("disabled", f"cannot read the DB: {type(e).__name__}") from None
    try:
        return con.execute("SELECT 1 FROM tx_state WHERE key='test_volume'").fetchone() is not None
    except sqlite3.Error as e:
        raise TxStoreError("disabled", f"cannot read tx_state: {type(e).__name__}") from None
    finally:
        con.close()


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


# ── inventory of encrypted-recording artefacts (boot, backup, restore: ONE definition) ──

# Tabelele care, nevide, înseamnă „înregistrări criptate pe volum" (PR6a: + migrare + carantină).
TX_TABLES = ("session_keys", "tx_descriptors", "tx_files", "tx_gaps", "tx_migration", "tx_quarantine",
             "tx_erase_intents")
# Chei tx_state care există doar după jurnalul de ştergeri / un restore urmărit (§12.11.4) sau după
# inventarul migrării (§12.11.5, PR6b): un volum cu ele nu mai e servit de calea 3.7.
TX_STATE_KEYS = ("erasure_head", "attested_heads", "continuity", "recordings_format", "migration_inventory")
# La rădăcina DATA_DIR: jurnalul WTJ1, temp-ul lui şi cozile tăiate la boot.
TX_TOP_PREFIX = "erasures.wtj"


def recording_files_present(data_dir=None) -> str:
    """'' when no file of the encrypted-recording namespace is under `transcripts/`; otherwise the
    first one (`keys.find_reserved`: `transcripts/` and one level of subdirectories such as
    `arhiva/`, symlinks never followed below the root, a supported `transcripts` symlink followed
    once; an unreadable directory = found)."""
    root = str(config.DATA_DIR if data_dir is None else data_dir)
    try:
        dfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        return ""
    except OSError as e:
        return "DATA_DIR (unreadable: %s)" % e.strerror
    try:
        if keys.is_link(dfd, keys.RESERVED_DIR):
            return keys.find_reserved_through_link(dfd) or ""
        # doar subarborele transcripts/: nivelul de sus (keys.wtk & co.) nu e o înregistrare
        try:
            top = os.listdir(dfd)
        except OSError:
            return "DATA_DIR (unreadable)"
        return keys.find_reserved(dfd, exempt=frozenset(top)) or ""
    finally:
        os.close(dfd)


def inventory(data_dir=None, db_path=None) -> list:
    """Every encrypted-recording artefact of a dataset (the live volume, a backup's DB copy or a
    restore staging): non-empty tx tables (keys, descriptors, ledger, gaps, migration rows,
    quarantine), the erasure-journal state keys, the journal files at the top of the data dir and
    the generation files under `transcripts/`. [] = none. A table that cannot be read, or a
    directory that cannot be listed, is reported as found (never read as absent)."""
    root = str(config.DATA_DIR if data_dir is None else data_dir)
    dbp = str(db_path) if db_path is not None else os.path.join(root, "webterm.db")
    found = []
    if os.path.exists(dbp):
        try:
            con = sqlite3.connect(pathlib.Path(os.path.abspath(dbp)).as_uri() + "?mode=ro", uri=True)
        except sqlite3.Error as e:
            return ["webterm.db (unreadable: %s)" % type(e).__name__]
        try:
            names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for t in TX_TABLES:
                if t in names and con.execute("SELECT 1 FROM %s LIMIT 1" % t).fetchone():
                    found.append(t)
            if "tx_state" in names:
                marks = ",".join("?" * len(TX_STATE_KEYS))
                found += ["tx_state." + r[0] for r in con.execute(
                    "SELECT key FROM tx_state WHERE key IN (%s) ORDER BY key" % marks, TX_STATE_KEYS)]
        except sqlite3.Error as e:
            found.append("webterm.db (unreadable: %s)" % type(e).__name__)
        finally:
            con.close()
    try:
        top = sorted(n for n in os.listdir(root) if n.startswith(TX_TOP_PREFIX))
    except FileNotFoundError:
        top = []
    except OSError:
        top = ["DATA_DIR (unreadable)"]
    found += top
    f = recording_files_present(root)
    if f:
        found.append("transcripts: " + f)
    return found


# ── plaintext migration helpers (§12.11.5) ──────────────────────────────────

DEL_PREFIX = ".wt-del-"                 # numele privat al unei ştergeri verificate (pasul 6)
MIG_FREE_SLACK = 64 * 1024 * 1024       # spaţiu liber cerut: 2 × mărimea + 64 MiB
RENAME_NOREPLACE = 1


def _load_renameat2():
    """renameat2(2) through libc, or the raw syscall when libc has no wrapper; None = unavailable
    (then nothing is ever deleted by the migration: fail closed)."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None
    fn = getattr(libc, "renameat2", None)
    if fn is not None:
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        return fn
    nr = {"x86_64": 316, "aarch64": 276}.get(platform.machine())
    sc = getattr(libc, "syscall", None)
    if nr is None or sc is None:
        return None
    sc.restype = ctypes.c_long

    def raw(a, b, c, d, e):
        return sc(ctypes.c_long(nr), ctypes.c_int(a), ctypes.c_char_p(b), ctypes.c_int(c),
                  ctypes.c_char_p(d), ctypes.c_uint(e))
    return raw


_renameat2 = _load_renameat2()


def renameat2_noreplace(dfd, old, new):
    """Atomic rename inside one directory fd that never replaces an existing `new`."""
    if _renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 unavailable")
    if _renameat2(dfd, os.fsencode(old), dfd, os.fsencode(new), RENAME_NOREPLACE) != 0:
        e = ctypes.get_errno()
        if e == errno.ENOENT:
            raise FileNotFoundError(e, os.strerror(e), old)
        raise OSError(e, os.strerror(e), old)


def _same_plain(st, ident, what):
    """The plaintext's fd still is the inventoried file: regular, one link, same identity."""
    if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
            or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != tuple(ident)):
        raise TxStoreError("changed", f"{what}: differs from its inventory row")


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
# Cel mai rău caz fizic per octet în clar: un DATA de 1 octet = antet + tag + 1 (v1), sau
# antet + tag + ulen + 1 + 64 (v2, §12.11.14). Bugetul fizic acoperă ambele versiuni.
PHYS_PER_PLAIN = max(txformat.REC_HDR_LEN + txformat.TAG_LEN + 1, txformat.ZREC_MAX_EXTRA + 1)
# §12.11.14: versiunea scrisă de generaţiile noi (writer, cap, conversie, recompactare). Implicit
# comprimat; WEBTERM_TX_COMPRESS=0 scrie din nou v1 (şi opreşte recompactarea), cititorii citesc ambele.
COMPRESS_ENV = "WEBTERM_TX_COMPRESS"


def write_version(env=None):
    env = os.environ if env is None else env
    return txformat.VERSION if env.get(COMPRESS_ENV, "").strip() == "0" else txformat.VERSION_Z
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
        self.detail = detail

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
                 pending_cap=PENDING_CAP, total_cap=REC_BUFFER_TOTAL, clock=time.time,
                 real_volume=False):
        env = os.environ if env is None else env
        # Starea minimă pentru close() înainte de orice deschidere (un refuz nu lasă resurse).
        self._w = self._r = None
        self.dir_fd = None
        self._snapshots = set()
        self._io_lock = threading.Lock()
        self._io_busy = 0
        self._closing = False
        self._released = False
        self.real_volume = False
        if not enabled(env):
            raise TxStoreError("disabled", f"{ENV_FLAG} is not 1")
        try:
            # PR6b: un volum REAL (fără marker de test) se deschide doar când apelantul o cere
            # explicit (txhub.boot, cu un keyring protejat); migrarea, jurnalul de ştergeri şi
            # carantina trebuie apoi să raporteze ready, altfel boot-ul închide Store-ul şi refuză.
            if real_volume and not _has_test_marker(db_path or config.DB_PATH):
                self._open_real(db_path or config.DB_PATH, transcripts_dir)
            else:
                self._open_test(db_path or config.DB_PATH, transcripts_dir, env)
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
        self.write_ver = write_version(env)
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
        self._plain_pins = collections.Counter()   # (dir, name) → backups copying that plaintext
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
        # PR6b: `await before_writer(sid)` înaintea oricărui writer (migrarea unei sesiuni vii la
        # pornirea writer-ului, §12.11.5); o excepţie TxStoreError refuză pornirea.
        self.before_writer = None
        self.readopt_enabled = True              # teste: un „crash" de proces nu se readoptă pe loc

    def _open_test(self, db_path, transcripts_dir, env):
        # PR5: volum de test, doar sub o poartă de test (§12.11 PR5/PR6). Poarta se verifică
        # înaintea oricărei deschideri; DB-ul se deschide mode=rw (nu-l creează).
        if not test_gate(env):
            raise TxStoreError("disabled", "test volume outside a test gate")
        self._db_path, tdir, marker = _volume_binding(db_path, transcripts_dir)
        self._r = self._connect()
        row = self._r.execute("SELECT value FROM tx_state WHERE key='test_volume'").fetchone()
        if row is None or not hmac.compare_digest(str(row[0]), marker):
            raise TxStoreError("disabled", "not a test volume (a real volume opens only from txhub.boot)")
        self._w = self._connect()
        self.dir_fd = os.open(tdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        # Identitatea EFECTIV deschisă (fd-ul directorului, DB-ul re-stat-at după conectare) e
        # cea din marker: o cale schimbată între verificare şi deschidere nu trece.
        dst = os.fstat(self.dir_fd)
        if (not marker.endswith(f":{dst.st_dev}:{dst.st_ino}:{tdir}")
                or _volume_binding(self._db_path, tdir)[2] != marker):
            raise TxStoreError("disabled", "test volume identity changed while opening")

    def _open_real(self, db_path, transcripts_dir):
        # Căile se rezolvă O DATĂ (un `transcripts` symlink suportat, §12.10), apoi directorul se
        # deschide cu O_NOFOLLOW: tot ce urmează trece prin fd-ul lui, nu prin cale.
        self._db_path = os.path.realpath(str(db_path))
        tdir = os.path.realpath(str(transcripts_dir))
        self._r = self._connect()
        self._w = self._connect()
        # markerul re-citit pe conexiunea deschisă: un marker apărut între verificare şi deschidere
        # nu transformă un volum de test într-unul real
        if self._r.execute("SELECT 1 FROM tx_state WHERE key='test_volume'").fetchone() is not None:
            raise TxStoreError("disabled", "test volume marker appeared while opening")
        try:
            self.dir_fd = os.open(tdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as e:
            raise TxStoreError("disabled", f"cannot open the transcripts dir: {e.strerror}") from None
        self.real_volume = True

    # ── plumbing ──

    def _connect(self):
        con = _connect_rw(self._db_path)
        con.execute("PRAGMA busy_timeout=5000")
        # R2-H1: intenţia de ştergere trebuie să fie durabilă la COMMIT (şi la o cădere de OS), nu doar
        # la moartea procesului: FULL explicit, oricare ar fi implicitul compilării SQLite
        con.execute("PRAGMA synchronous=FULL")
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
            if not fut.cancelled():
                fut.exception()          # rezultatul firului e consumat (anularea are prioritate)
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
        self.pin_gens(hexids)
        try:
            yield
        finally:
            self.unpin_gens(hexids)

    def pin_gens(self, hexids):
        """Loop only. A pinned generation is never unlinked (`retire` defers it)."""
        for h in hexids:
            self._pins[h] += 1

    def unpin_gens(self, hexids):
        """Loop only. The last unpin runs the retire that was deferred meanwhile."""
        for h in hexids:
            self._pins[h] -= 1
            if self._pins[h] <= 0:
                del self._pins[h]
                later = self._deferred.pop(h, None)
                if later is not None:
                    asyncio.get_running_loop().create_task(self.retire(later[0], later[1], h))

    # PR6c (§12.11.3): textul clar al unui rând `tx_migration` copiat de un backup e fixat pe nume
    # (dir, name): unlink-ul verificat al migrării se amână cât timp e fixat (rândul rămâne
    # `converted`, janitorul reîncearcă), deci arhiva şi DB-ul ei copiat rămân coerente.
    def pin_plain(self, keys_):
        for k in keys_:
            self._plain_pins[k] += 1

    def unpin_plain(self, keys_):
        for k in keys_:
            self._plain_pins[k] -= 1
            if self._plain_pins[k] <= 0:
                del self._plain_pins[k]

    def plain_pinned(self, dirn, name):
        return self._plain_pins[(dirn, name)] > 0

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
            # `absent` = restaurat fără generaţii („nu e în acest backup", §12.11.3): fişierele lipsesc
            # prin definiţie, nu e o defecţiune de marcat `damaged`
            if status in ("damaged", "absent"):
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
                                             last.plain_len, last.phys_len, last.hdr_mac, last.ver)
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

    async def purge(self, sid, cutoff):
        """Retention purge of one archived recording (§12.11.4 "purge"): descriptors, RK, gaps and
        quarantine rows deleted, generations → retired then unlinked (deferred while pinned). NO
        tombstone (owner Q1: a purge is not an erasure). Re-checked inside the transaction: every
        kind archived before `cutoff`, no writer, nothing in Owner recovery, no plaintext the
        migration still owns. Returns True when purged."""
        rec = self.recorders.get(sid)
        if sid in self._starting or (rec is not None and rec.state == "running") or sid in self.tombstoned:
            return False
        async with self.lease(sid):
            def fn(c):
                rows = c.execute("SELECT archived_at, status FROM tx_descriptors WHERE sid=?", (sid,)).fetchall()
                if not rows or any(a is None or a >= cutoff for a, _s in rows):
                    return None
                if any(s == "recovery" for _a, s in rows):
                    return None
                if c.execute("SELECT 1 FROM tx_migration WHERE sid=? AND state IN "
                             "('pending','orphan','failed','converted')", (sid,)).fetchone():
                    return None
                gens = c.execute("SELECT gen_id, kind FROM tx_files WHERE sid=? AND state='published'",
                                 (sid,)).fetchall()
                c.execute("UPDATE tx_files SET state='retired' WHERE sid=? AND state='published'", (sid,))
                c.execute("DELETE FROM session_keys WHERE sid=?", (sid,))
                c.execute("DELETE FROM tx_descriptors WHERE sid=?", (sid,))
                c.execute("DELETE FROM tx_gaps WHERE sid=?", (sid,))
                c.execute("DELETE FROM tx_quarantine WHERE sid=?", (sid,))
                return [(g[0], g[1]) for g in gens]
            gens = await self.txn(fn)
            if gens is None:
                return False
            self._bump(sid)
            self.drop_key(sid)
            for hexid, kind in gens:
                await self.retire(sid, kind, hexid)
        return True

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
            if self.before_writer is not None:
                await self.before_writer(sid)
            # H2 / R-H2: un writer nu redeschide istoricul unei înregistrări din cohorta unei
            # carantine (orice kind în tx_quarantine: `continuity` după un restore fără dovadă,
            # `journal:*` după un boot cu jurnal invalid): refuzat până la dovadă / recuperarea
            # explicită, auditată, a Owner-ului. Verificat DUPĂ conversia de la pornire (care
            # păstrează carantina pe descriptorul nou).
            if await self.read(lambda c: c.execute(
                    "SELECT 1 FROM tx_quarantine WHERE sid=? LIMIT 1", (sid,)).fetchone()) is not None:
                raise TxStoreError("quarantined", f"{sid}: recording in quarantine")
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

    def fenced(self, sid=None) -> bool:
        """A fence is pending on `sid` (None = a global one): a decision taken now may be stale."""
        return sid in self._fences

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
                    c.execute("SELECT value FROM tx_state WHERE key='recordings_format'").fetchone(),
                    c.execute("SELECT 1 FROM tx_quarantine WHERE sid=? AND kind=?", (sid, kind)).fetchone())
        drow, krow, mrow, fmt, qrow = await self.read(load)
        if drow is None:
            if qrow is not None:
                # H2: text clar din cohorta unui restore fără dovadă: refuzat pentru oricine
                raise TxStoreError("quarantined", f"{sid}.{kind}: plaintext in quarantine")
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
        if self._run_read(lambda c: c.execute("SELECT 1 FROM tx_quarantine WHERE sid=? AND kind=?",
                                              (sid, kind)).fetchone()) is not None:
            return False
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

    # ── plaintext migration primitives (§12.11.5, PR6b; order, inventory, janitor: migration.py) ──
    #
    # Aici, şi numai aici, se scriu generaţiile unei înregistrări migrate (modulul docstring:
    # „nimic altceva nu deschide o generaţie"). Apelantul ţine lease-ul sid-ului.

    def plain_dir_fd(self, dirn):
        """(fd, own) of `transcripts/` (the Store's fd, not to be closed) or `transcripts/arhiva/`
        (opened here with O_NOFOLLOW through the Store's fd; the caller closes it)."""
        if dirn == "transcripts":
            return self.dir_fd, False
        if dirn == "arhiva":
            return os.open("arhiva", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=self.dir_fd), True
        raise TxStoreError("bad-row", f"unknown plaintext dir {dirn!r}")

    def _pin_plain_sync(self, dirn, name, ident):
        """Step 1: the plaintext opened through its dir fd (O_NOFOLLOW) and checked on the fd:
        regular, one link, (dev, ino, size, mtime_ns) = the inventory row's."""
        dfd, own = self.plain_dir_fd(dirn)
        try:
            try:
                fd = os.open(name, _RDONLY, dir_fd=dfd)
            except FileNotFoundError:
                raise TxStoreError("absent", f"{dirn}/{name}") from None
            except OSError as e:
                raise TxStoreError("changed", f"{dirn}/{name}: {e.strerror}") from None
        finally:
            if own:
                os.close(dfd)
        try:
            _same_plain(os.fstat(fd), ident, f"{dirn}/{name}")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _encrypt_plain_sync(self, fd, writer, size):
        """Step 3: the whole plaintext (no truncation) from the pinned fd into the writer,
        hashed on the way. Returns the SHA-256 hex."""
        h = hashlib.sha256()
        pos = 0
        while pos < size:
            b = os.pread(fd, min(CAP_CHUNK, size - pos), pos)
            if not b:
                raise TxStoreError("changed", "plaintext shorter than its inventory size")
            h.update(b)
            writer.write(b)
            pos += len(b)
        return h.hexdigest()

    def _seal_sync(self, built):
        for g in built.values():
            g.writer.seal()
            os.fsync(g.fd)
        os.fsync(self.dir_fd)

    def _hash_snapshot_sync(self, snap, limit=None):
        big = Budget(1 << 62, pre_first=1 << 62)
        h = hashlib.sha256()
        n = 0
        end = snap.length if limit is None else min(limit, snap.length)
        with snap._using():
            for piece in snap._chunks(0, end, big, CAP_CHUNK):
                h.update(piece)
                n += len(piece)
        return h.hexdigest(), n

    def _verify_gen_file_sync(self, sid, kind, g, rk):
        """verify_full of the sealed generation on a NEW read-only fd, same inode as created."""
        w = g.writer
        fd = os.open(g.name, _RDONLY, dir_fd=self.dir_fd)
        try:
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) != (g.dev, g.ino):
                raise TxStoreError("corrupt", "migrated generation replaced under us")
            txformat.verify_full(_PRead(fd, 0, limit=w.phys_len), rk, kind=KINDS[kind],
                                 sid=_sid_bytes(sid), gen_id=g.gen_id, data_count=w.data_count,
                                 plain_len=w.plain_len, phys_len=w.phys_len, hdr_mac=w.hdr_mac,
                                 ver=w.ver)
        finally:
            os.close(fd)

    async def decrypted_digest(self, sid, kind, desc, rk):
        """(SHA-256 hex, length) of what a reader serves for `desc` (the reader path itself)."""
        snap = await self._make_snapshot(Snapshot, sid, kind, desc, rk, 0, None,
                                         nfds=len(desc.generations), force=True)
        try:
            return await self.io(self._hash_snapshot_sync, snap)
        finally:
            snap.close()

    async def converted_prefix_digest(self, sid, kind, size):
        """(SHA-256 hex, length) of the first `size` bytes a reader serves from the committed
        (sid, kind). The descriptor must be authentic, `ok` and flagged `converted` (a crash rule
        re-checks a conversion against it before the plaintext is unlinked)."""
        def load(c):
            return (c.execute("SELECT blob, version, status FROM tx_descriptors WHERE sid=? AND kind=?",
                              (sid, kind)).fetchone(),
                    c.execute("SELECT envelope FROM session_keys WHERE sid=?", (sid,)).fetchone(),
                    c.execute("SELECT reason FROM tx_quarantine WHERE sid=? AND kind=?", (sid, kind)).fetchone())
        drow, krow, qrow = await self.read(load)
        if drow is None or krow is None:
            raise TxStoreError("notFound", f"{sid}.{kind}: no published conversion")
        # H2 / R-H2: o conversie păstrată în carantina cohortei (continuitate sau jurnal) se
        # re-verifică totuşi (doar hash, nimic servit), ca textul clar să poată fi şters; orice
        # altă stare (fără rând de carantină): amânat
        if drow[2] != "ok" and not (drow[2] in ("quarantined", "recovery") and qrow is not None
                                    and (qrow[0] == "continuity" or qrow[0].startswith("journal:"))):
            raise TxStoreError("quarantined", f"{sid}.{kind}: {drow[2]}")
        env = bytes(krow[0])
        d = self.decode((drow[0], drow[1]), sid, kind, env)
        if not d.flags & txdesc.FLAG_CONVERTED:
            raise TxStoreError("integrity", f"{sid}.{kind}: descriptor not flagged converted")
        rk = self.rk_for(sid, env)
        snap = await self._make_snapshot(Snapshot, sid, kind, d, rk, 0, None,
                                         nfds=len(d.generations), force=True)
        try:
            return await self.io(self._hash_snapshot_sync, snap, size)
        finally:
            snap.close()

    async def convert_plain(self, sid, rows, *, origin, live=False):
        """Steps 1–5 of §12.11.5 for one sid (`rows` = {kind: (dir, name, (dev, ino, size,
        mtime_ns))}, both kinds of the pair when both exist). Caller holds the lease. Returns
        ({kind: sha256 hex}, {kind: pinned fd}) — the caller owns the fds (step 6, then close).

        The RK is drawn here but committed only with the descriptors (step 5), so until that
        commit the plaintext stays the readable form (`_open_plain` refuses plaintext once an RK
        exists); a crash before it leaves only `created` generations, which `recover()` unlinks.
        Raises TxStoreError: `absent` / `changed` (→ failed), `disk` (postponed), anything else
        (retried); nothing is published then and every generation created here is retired."""
        sidb = _sid_bytes(sid)
        if origin not in ("migrated", "orphan"):
            raise TxStoreError("bad-argument", "origin")
        fds, built, sha = {}, {}, {}
        ok = False
        try:
            for k, (dirn, name, ident) in rows.items():
                if k not in KINDS:
                    raise TxStoreError("bad-row", k)
                try:
                    fds[k] = await self.io(self._pin_plain_sync, dirn, name, ident)
                except TxStoreError as e:
                    e.kind = k
                    raise
            need = sum(2 * ident[2] for _d, _n, ident in rows.values()) + MIG_FREE_SLACK
            vfs = await self.io(os.fstatvfs, self.dir_fd)
            if vfs.f_bavail * vfs.f_frsize < need:
                raise TxStoreError("disk", f"needs {need} bytes free")
            rk = secrets.token_bytes(32)
            env = keyring.wrap_under_kwk(self.kwk, keyring.KT_RK, rk)
            for k in rows:
                gid, fd, dev, ino, name = await self.reserve_and_create(sid, k)
                built[k] = g = _Gen(k, gid, name, fd, None, dev, ino)
                g.writer = await self.io(txformat.Writer, _File(fd, self), rk, kind=KINDS[k], sid=sidb,
                                         gen_id=gid, created_ms=int(self.clock() * 1000),
                                         ver=self.write_ver)
                sha[k] = await self.io(self._encrypt_plain_sync, fds[k], g.writer, rows[k][2][2])
            self._fault("mig-written")
            await self.io(self._seal_sync, built)
            self._fault("mig-sealed")
            gens = {}
            for k, g in built.items():
                w = g.writer
                gens[k] = txdesc.Generation(g.gen_id, txdesc.STATE_SEALED, w.data_count, w.plain_len,
                                            w.phys_len, w.hdr_mac, w.ver)
                await self.io(self._verify_gen_file_sync, sid, k, g, rk)
                d = txdesc.Descriptor(self.inst, sidb, KINDS[k], 0, b"\0" * 32, (gens[k],))
                got, n = await self.decrypted_digest(sid, k, d, rk)
                if got != sha[k] or n != rows[k][2][2]:
                    raise TxStoreError("readback", f"{sid}.{k}: decrypted copy differs")
                # Fişierul fixat e încă exact rândul inventarului (altfel: schimbat în timpul migrării).
                try:
                    await self.io(lambda fd=fds[k], k=k: _same_plain(os.fstat(fd), rows[k][2], f"{sid}.{k}"))
                except TxStoreError as e:
                    e.kind = k
                    raise
            self._fault("mig-verified")
            try:
                await self.txn(self._convert_txn(sid, rows, built, gens, env, sha, origin, live))
            except Uncertain:
                # rezultatul se citeşte înapoi: convertit cu hash-ul nostru = publicat
                done = await self.fresh_read(lambda c: [c.execute(
                    "SELECT state, sha256 FROM tx_migration WHERE sid=? AND kind=?", (sid, k)).fetchone()
                    for k in rows])
                if not all(r is not None and r[0] == "converted" and r[1] == sha[k]
                           for r, k in zip(done, rows)):
                    raise TxStoreError("uncertain", "conversion commit not confirmed") from None
            for g in built.values():
                g.published = True
            self.drop_key(sid)
            self._fault("mig-committed")
            ok = True
            return sha, fds
        except Exception:
            # eşec în proces: generaţiile nepublicate sunt ale noastre (O_EXCL + inode) → retrase acum
            for k, g in built.items():
                if not g.published:
                    hexid = g.gen_id.hex()
                    with contextlib.suppress(Exception):
                        await self.txn(lambda c, h=hexid: c.execute(
                            "UPDATE tx_files SET state='retired' WHERE gen_id=? AND state='created'", (h,)))
                        await self.retire(sid, k, hexid)
            raise
        finally:
            # moartea procesului (BaseException): doar fd-urile; registrul decide la boot
            for g in built.values():
                if g.fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(g.fd)
                    g.fd = None
            if not ok:
                for fd in fds.values():
                    with contextlib.suppress(OSError):
                        os.close(fd)

    def _convert_txn(self, sid, rows, built, gens, env, sha, origin, live):
        sidb = _sid_bytes(sid)

        def fn(c):
            if (c.execute("SELECT 1 FROM session_keys WHERE sid=?", (sid,)).fetchone()
                    or c.execute("SELECT 1 FROM tx_descriptors WHERE sid=?", (sid,)).fetchone()):
                raise Refused("integrity", "the session already has an encrypted recording")
            for k, (dirn, name, ident) in rows.items():
                r = c.execute("SELECT state, dir, name, dev, ino, size, mtime_ns FROM tx_migration "
                              "WHERE sid=? AND kind=?", (sid, k)).fetchone()
                if (r is None or r[0] not in ("pending", "orphan") or (r[1], r[2]) != (dirn, name)
                        or tuple(r[3:]) != tuple(ident)):
                    raise Refused("cas", f"{sid}.{k}: inventory row moved")
            c.execute("INSERT INTO session_keys(sid, envelope, created, origin) VALUES(?,?,?,?)",
                      (sid, env, self.clock(), origin))
            for k, g in built.items():
                dirn, _name, ident = rows[k]
                d = txdesc.Descriptor(self.inst, sidb, KINDS[k], 1, keyring.envelope_hash(env),
                                      (gens[k],), txdesc.FLAG_CONVERTED)
                # §12.11.6: committed_at = mtime-ul textului clar (niciodată „acum"); arhiva îşi
                # păstrează ceasul de retenţie în archived_at.
                mtime = ident[3] / 1e9
                # H2: un (sid, kind) din cohorta unui restore fără dovadă rămâne în carantină şi
                # după conversie: descriptorul nou NU e servibil până la dovadă / recuperarea Owner
                held = c.execute("SELECT 1 FROM tx_quarantine WHERE sid=? AND kind=?", (sid, k)).fetchone()
                c.execute("INSERT INTO tx_descriptors(sid, kind, blob, version, list_epoch, committed_at, "
                          "archived_at, status) VALUES(?,?,?,?,?,?,?,?)",
                          (sid, k, self.encode(d), 1, 1 if live else 0, mtime,
                           mtime if dirn == "arhiva" else None, "quarantined" if held else "ok"))
                n = c.execute("UPDATE tx_files SET state='published' WHERE gen_id=? AND sid=? AND kind=? "
                              "AND dev=? AND ino=? AND state='created'",
                              (g.gen_id.hex(), sid, k, g.dev, g.ino)).rowcount
                if n != 1:
                    raise Refused("ledger", f"{g.gen_id.hex()} not created by us")
                c.execute("UPDATE tx_migration SET state='converted', sha256=?, error=NULL "
                          "WHERE sid=? AND kind=?", (sha[k], sid, k))
                self._fault("mig-txn-between")
        return fn

    # ── recompaction of version-1 generations (§12.11.14, orchestration: migration.py) ──

    async def recompact_candidates(self, *, with_cost=False):
        """[(sid, v1 bytes)] of closed recordings that still hold a version-1 generation: every
        descriptor of the sid authentic, `ok`, out of quarantine, without a live generation, and
        the sid not erased. Cheap enough for every janitor pass (one HMAC per descriptor).
        `with_cost`: [(sid, v1 bytes, work)], work = recompact_work() of every kind it rewrites."""
        def load(c):
            return (c.execute("SELECT sid, kind, blob, version, status FROM tx_descriptors").fetchall(),
                    dict(c.execute("SELECT sid, envelope FROM session_keys").fetchall()),
                    {r[0] for r in c.execute("SELECT sid FROM tx_quarantine").fetchall()},
                    {r[0] for r in c.execute("SELECT sid FROM tx_erase_intents").fetchall()})
        rows, envs, held, intents = await self.read(load)
        per, work, bad = {}, {}, set()
        for s, k, blob, v, status in rows:
            if s in bad:
                continue
            if status != "ok" or s in held or s in intents or s in self.tombstoned or s not in envs:
                bad.add(s)
                continue
            try:
                d = self.decode((blob, v), s, k, bytes(envs[s]))
            except TxStoreError:
                bad.add(s)
                continue
            if any(g.state == txdesc.STATE_LIVE for g in d.generations):
                bad.add(s)
                continue
            per[s] = per.get(s, 0) + sum(g.phys_len for g in d.generations if g.ver == txformat.VERSION)
            if any(g.ver == txformat.VERSION for g in d.generations):
                work[s] = work.get(s, 0) + recompact_work(d.generations)
        out = sorted(((s, n) for s, n in per.items() if s not in bad and n), key=lambda x: (-x[1], x[0]))
        return [(s, n, work[s]) for s, n in out] if with_cost else out

    def _verify_source_sync(self, sid, kind, snap):
        """Full check of every source generation of `snap` on its own (pinned) fds: a sealed one
        whole (header, records, counts, SEAL, nothing after it), a recovered one exactly its
        committed prefix. Raises RecompactSourceCorrupt; an OSError stays a fault (retried)."""
        def check():
            if snap.cancel.is_set():
                raise TxStoreError("closed", "snapshot closed")
        with snap._using():
            for g, fd, _start in snap.gens:
                try:
                    verify_generation_fd(fd, sid, kind, g, snap.rk, check=check)
                except GenCorrupt as e:
                    raise RecompactSourceCorrupt(
                        "sourceCorrupt", f"{sid}.{kind}.{g.gen_id.hex()}: {e.detail or e.reason}") from None

    def _copy_snapshot_sync(self, snap, writer):
        """The reader's plaintext of `snap` (verified parse) into `writer`, hashed on the way.
        Nothing is written to disk but the writer's records. → (SHA-256 hex, length)."""
        big = Budget(1 << 62, pre_first=1 << 62)
        h = hashlib.sha256()
        n = 0
        with snap._using():
            for piece in snap._chunks(0, snap.length, big, CAP_CHUNK):
                h.update(piece)
                writer.write(piece)
                n += len(piece)
        return h.hexdigest(), n

    async def recompact(self, sid):
        """§12.11.14: rewrites a closed recording that still holds version-1 generations into one
        compressed (version-2) generation per kind. Caller holds the sid's lease. Steps: pin the
        old generations; a reader snapshot per kind, and every source generation fully verified on
        its fds (RecompactSourceCorrupt before anything is written: the source stays as it is);
        per kind, the snapshot → Writer v2 (plaintext only in memory),
        hashed; SEAL + fsync file and directory; verify_full on a new fd of the same inode; the
        new descriptor read back through the reader must hash to the same bytes and length; then
        ONE transaction (barrier) with a CAS on every descriptor (blob and version), the RK
        envelope, the status, the quarantine and the erasure state (INV-14: an erased sid is
        refused), publishing T and retiring the old generations; last, the old files are retired
        (deferred while a backup or reader pins them). A crash before the commit leaves `created`
        rows (`recover()` unlinks them), after it `retired` rows (unlinked the same way).
        Returns {kind: (old phys, new phys)}; {} when the sid is not (or no longer) eligible."""
        if self.write_ver != txformat.VERSION_Z or sid in self.tombstoned:
            return {}
        sidb = _sid_bytes(sid)

        def load(c):
            return (c.execute("SELECT kind, blob, version, status FROM tx_descriptors WHERE sid=? "
                              "ORDER BY kind", (sid,)).fetchall(),
                    c.execute("SELECT envelope FROM session_keys WHERE sid=?", (sid,)).fetchone(),
                    c.execute("SELECT 1 FROM tx_quarantine WHERE sid=?", (sid,)).fetchone(),
                    c.execute("SELECT 1 FROM tx_erase_intents WHERE sid=?", (sid,)).fetchone())
        drows, krow, held, intent = await self.read(load)
        if krow is None or not drows or held or intent:
            return {}
        env = bytes(krow[0])
        descs = {}
        for k, blob, v, status in drows:
            if status != "ok" or k not in KINDS:
                return {}
            descs[k] = (self.decode((blob, v), sid, k, env), bytes(blob))
        if any(g.state == txdesc.STATE_LIVE for d, _b in descs.values() for g in d.generations):
            return {}                             # o sesiune vie: doar coordonatorul ei publică
        todo = {k: db for k, db in descs.items()
                if any(g.ver == txformat.VERSION for g in db[0].generations)}
        if not todo:
            return {}
        for k, (d, _b) in todo.items():
            if sum(g.plain_len for g in d.generations) > txformat.MAX_PLAIN_BYTES * 9 // 10:
                raise TxStoreError("tooLarge", f"{sid}.{k}: above one generation's limit")
        need = sum(g.phys_len for d, _b in todo.values() for g in d.generations) + MIG_FREE_SLACK
        vfs = await self.io(os.fstatvfs, self.dir_fd)
        if vfs.f_bavail * vfs.f_frsize < need:
            raise TxStoreError("disk", f"needs {need} bytes free")
        rk = self.rk_for(sid, env)
        pins = [g.gen_id.hex() for d, _b in todo.values() for g in d.generations]
        built, sha, new, snaps = {}, {}, {}, {}
        with self.pinned(pins):
            try:
                # Codex M1: sursa e verificată ÎNTREG (SEAL, EOF fizic exact, numărători; prefixul comis
                # al unei generaţii recuperate) pe fd-urile fixate din care se şi copiază, ÎNAINTE de
                # orice fişier nou. Citirea pe interval autentifică doar octeţii ceruţi: fără asta, o
                # generaţie cu SEAL stricat / octeţi după SEAL ar fi înlocuită de o copie v2 validă şi
                # dovada coruperii ar dispărea. O sursă care pică NU se atinge (stare, carantină).
                for k, (d, _b) in todo.items():
                    try:
                        snaps[k] = await self._make_snapshot(Snapshot, sid, k, d, rk, 0, None,
                                                             nfds=len(d.generations), force=True)
                    except TxStoreError as e:
                        if e.reason in ("corrupt", "damaged"):
                            raise RecompactSourceCorrupt("sourceCorrupt", f"{sid}.{k}: {e}") from None
                        raise
                for k, snap in snaps.items():
                    await self.io(self._verify_source_sync, sid, k, snap)
                self._fault("rc-source-verified")
                for k, (d, _b) in todo.items():
                    snap = snaps[k]
                    try:
                        gid, fd, dev, ino, name = await self.reserve_and_create(sid, k)
                        built[k] = g = _Gen(k, gid, name, fd, None, dev, ino)
                        g.writer = await self.io(txformat.Writer, _File(fd, self), rk, kind=KINDS[k],
                                                 sid=sidb, gen_id=gid, created_ms=int(self.clock() * 1000),
                                                 ver=txformat.VERSION_Z)
                        sha[k] = await self.io(self._copy_snapshot_sync, snap, g.writer)
                    finally:
                        snap.close()
                    if sha[k][1] != sum(x.plain_len for x in d.generations):
                        raise TxStoreError("readback", f"{sid}.{k}: source length differs")
                self._fault("rc-written")
                await self.io(self._seal_sync, built)
                self._fault("rc-sealed")
                for k, g in built.items():
                    w = g.writer
                    t = txdesc.Generation(g.gen_id, txdesc.STATE_SEALED, w.data_count, w.plain_len,
                                          w.phys_len, w.hdr_mac, w.ver)
                    await self.io(self._verify_gen_file_sync, sid, k, g, rk)
                    probe = txdesc.Descriptor(self.inst, sidb, KINDS[k], 0, b"\0" * 32, (t,))
                    if await self.decrypted_digest(sid, k, probe, rk) != sha[k]:
                        raise TxStoreError("readback", f"{sid}.{k}: recompacted copy differs")
                    old = todo[k][0]
                    nd = txdesc.Descriptor(old.installation_id, old.sid, old.kind, old.version + 1,
                                           old.rk_hash, (t,), old.flags)
                    new[k] = (nd, self.encode(nd))
                self._fault("rc-verified")
                fn = self._recompact_txn(sid, env, todo, new, built)
                try:
                    await self.txn(fn)
                except Uncertain:
                    got = await self.fresh_read(lambda c: [c.execute(
                        "SELECT blob FROM tx_descriptors WHERE sid=? AND kind=?", (sid, k)).fetchone()
                        for k in new])
                    if not all(r is not None and bytes(r[0]) == new[k][1] for r, k in zip(got, new)):
                        raise TxStoreError("uncertain", "recompaction commit not confirmed") from None
                for g in built.values():
                    g.published = True
                self._fault("rc-committed")
            except Exception:
                for k, g in built.items():
                    if not g.published:
                        hexid = g.gen_id.hex()
                        with contextlib.suppress(Exception):
                            await self.txn(lambda c, h=hexid: c.execute(
                                "UPDATE tx_files SET state='retired' WHERE gen_id=? AND state='created'", (h,)))
                            await self.retire(sid, k, hexid)
                raise
            finally:
                for snap in snaps.values():
                    snap.close()
                for g in built.values():
                    if g.fd is not None:
                        with contextlib.suppress(OSError):
                            os.close(g.fd)
                        g.fd = None
        # Cititorii deschişi înainte păstrează fd-urile vechi; backup-ul în curs le-a fixat (amânat).
        for k, (d, _b) in todo.items():
            for g in d.generations:
                await self.retire(sid, k, g.gen_id.hex())
        return {k: (sum(g.phys_len for g in todo[k][0].generations), new[k][0].generations[0].phys_len)
                for k in todo}

    def _recompact_txn(self, sid, env, todo, new, built):
        def fn(c):
            # INV-14 (docs/design/INVARIANTS.md): o înregistrare ştearsă nu revine niciodată. Tombstone-ul
            # din memorie şi intenţia durabilă se reverifică AICI, sub barieră, în tranzacţia publicării.
            if sid in self.tombstoned:
                raise Refused("erased", f"{sid}: erased during recompaction")
            if c.execute("SELECT 1 FROM tx_erase_intents WHERE sid=?", (sid,)).fetchone():
                raise Refused("erased", f"{sid}: erase intent pending")
            r = c.execute("SELECT envelope FROM session_keys WHERE sid=?", (sid,)).fetchone()
            if r is None or bytes(r[0]) != env:
                raise Refused("cas", f"{sid}: RK changed")
            if c.execute("SELECT 1 FROM tx_quarantine WHERE sid=?", (sid,)).fetchone():
                raise Refused("cas", f"{sid}: quarantined")
            for k, (d, blob) in todo.items():
                r = c.execute("SELECT blob, version, status FROM tx_descriptors WHERE sid=? AND kind=?",
                              (sid, k)).fetchone()
                if r is None or bytes(r[0]) != blob or r[1] != d.version or r[2] != "ok":
                    raise Refused("cas", f"{sid}.{k}: descriptor moved")
            for k, (nd, nb) in new.items():
                c.execute("UPDATE tx_descriptors SET blob=?, version=? WHERE sid=? AND kind=? AND version=?",
                          (nb, nd.version, sid, k, todo[k][0].version))
                g = built[k]
                n = c.execute("UPDATE tx_files SET state='published' WHERE gen_id=? AND sid=? AND kind=? "
                              "AND dev=? AND ino=? AND state='created'",
                              (g.gen_id.hex(), sid, k, g.dev, g.ino)).rowcount
                if n != 1:
                    raise Refused("ledger", f"{g.gen_id.hex()} not created by us")
                for old in todo[k][0].generations:
                    c.execute("UPDATE tx_files SET state='retired' WHERE gen_id=? AND sid=? AND kind=? "
                              "AND state='published'", (old.gen_id.hex(), sid, k))
                self._fault("rc-txn-between")
        return fn

    # step 6: identity-checked unlink (renameat2 NOREPLACE → fstatat → unlinkat → dir fsync)

    def rename_private_sync(self, dirn, name):
        """Moves `name` to a fresh private `.wt-del-<random>` name (RENAME_NOREPLACE) in the same
        directory. Returns the private name; FileNotFoundError when `name` is absent."""
        dfd, own = self.plain_dir_fd(dirn)
        try:
            priv = DEL_PREFIX + secrets.token_hex(12)
            renameat2_noreplace(dfd, name, priv)
            return priv
        finally:
            if own:
                os.close(dfd)

    def unlink_private_sync(self, dirn, name, priv, ident, pin_st=None):
        """The file now at `priv` is unlinked only when it is regular, has one link and its
        (dev, ino, size, mtime_ns) equal the row's (and the pinned fd's, when given); then the
        directory is fsynced. Otherwise it is renamed back (NOREPLACE). Returns 'unlinked',
        'mismatch' (back in place) or 'stuck' (left under `priv`)."""
        dfd, own = self.plain_dir_fd(dirn)
        try:
            st = os.stat(priv, dir_fd=dfd, follow_symlinks=False)
            same = (stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                    and (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) == tuple(ident)
                    and (pin_st is None or (pin_st.st_dev, pin_st.st_ino) == (st.st_dev, st.st_ino)))
            if not same:
                try:
                    renameat2_noreplace(dfd, priv, name)
                    return "mismatch"
                except OSError:
                    return "stuck"
            os.unlink(priv, dir_fd=dfd)
            os.fsync(dfd)
            return "unlinked"
        finally:
            if own:
                os.close(dfd)

    def unlink_held_sync(self, dirn, priv, ident):
        """Crash rule: a leftover private name holding exactly the row's identity is unlinked."""
        dfd, own = self.plain_dir_fd(dirn)
        try:
            try:
                st = os.stat(priv, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                return "absent"
            if not (stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                    and (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) == tuple(ident)):
                return "other"
            os.unlink(priv, dir_fd=dfd)
            os.fsync(dfd)
            return "unlinked"
        finally:
            if own:
                os.close(dfd)

    def list_private_sync(self, dirn):
        """Leftover `.wt-del-*` names in `dirn` ([] when the directory does not exist)."""
        try:
            dfd, own = self.plain_dir_fd(dirn)
        except FileNotFoundError:
            return []
        try:
            return sorted(n for n in os.listdir(dfd) if n.startswith(DEL_PREFIX))
        finally:
            if own:
                os.close(dfd)

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
                    rk, KINDS[kind], g.gen_id), kind=KINDS[kind], sid=_sid_bytes(sid), gen_id=g.gen_id,
                    ver=g.ver)
                if not hmac.compare_digest(os.pread(fd, 32, 64), g.hdr_mac):
                    return "hdr-mac-mismatch", None
                cur = txformat.RecordCursor(fp, rk, kind=KINDS[kind], gen_id=g.gen_id,
                                            hdr_mac=g.hdr_mac, data_count=g.data_count, ver=g.ver,
                                            plain_len=g.plain_len)
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
            except OSError as e:
                # Codex WTX2 re-review L: doar un nume lipsă / nefolosibil e „damaged”; o eroare de
                # resurse sau I/O (EMFILE, ENFILE, EIO, ENOMEM…) e trecătoare → "io", reîncercată cu
                # backoff, nu pusă în coşul de integritate (fără reîncercare până la restart).
                if e.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.EISDIR, errno.ENXIO):
                    raise TxStoreError("damaged", f"generation {g.gen_id.hex()} missing") from None
                raise TxStoreError("io", f"generation {g.gen_id.hex()}: {errno.errorcode.get(e.errno, e.errno)}") from None
            self.gens.append((g, fd, self.length))
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size < g.phys_len:
                raise TxStoreError("damaged", f"generation {g.gen_id.hex()} not usable")
            keys_ = txformat.generation_keys(rk, KINDS[kind], g.gen_id)
            try:
                h = txformat.verify_header(os.pread(fd, txformat.PREFIX_LEN, 0), keys_,
                                           kind=KINDS[kind], sid=_sid_bytes(sid), gen_id=g.gen_id,
                                           ver=g.ver)
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
                                         data_count=g.data_count, ver=g.ver)
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
                                    seq=seq, logical_offset=log, file_offset=foff, ver=g.ver,
                                    plain_len=g.plain_len)
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
                                     data_count=g.data_count, entries=entries, ver=g.ver)
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
                    rec = cur.next()
                    if rec is None:
                        break
                    # §12.11.14: o intrare doar la un record de la care se poate începe (v2: ZSTART).
                    if rebuilt is not None and rec.reset and rec.logical_offset >= next_entry:
                        rebuilt.append(txformat.IndexEntry(rec.seq, rec.logical_offset, rec.file_offset))
                        next_entry = rec.logical_offset + INDEX_STRIDE
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
    gap_id: str = ""                              # durable identity of the operation; tx_gaps / audit key
    marker: tuple = (0, 0)                        # synthetic (.out, .cast) marker bytes, never loss
    op_nonce: str = ""                            # random per operation (skip / cut / close), stored with the row


def new_op_nonce():
    return os.urandom(16).hex()


def gap_id_for(sid, epoch, start, size, op_nonce):
    """Durable gap identity (R2-M1): one operation over one upstream interval. Independent of the
    display reason and of the logical projection (.out / .cast positions, which a cap moves): a
    retry of the SAME operation keeps its id; two operations, or two intervals, never share one.
    Canonical serialization (JSON list, fixed separators), so no field can bleed into another."""
    canon = json.dumps(["wtgap2", sid, epoch, start, size, op_nonce], separators=(",", ":"),
                       ensure_ascii=True)
    return hashlib.sha256(canon.encode()).hexdigest()[:32]


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
    the cursor) is a dedicated job: ONE GAP_MARKER published in the same transaction as the new
    cursor, with a durable `tx_gaps` row; ingress at `replay_start` answers `busy` until then, and
    the future resolves only when exactly that row and cursor are committed (R2-H1).
    `change_epoch(e)` to the current epoch is a no-op (a redundant attach: no cut, no reset); to
    the target of a switch still pending it returns that switch's future; to another target while
    a switch or a skip is pending it answers `busy` (R2-M2). With `track_agent=False` there is no
    durable agent offset: a restarted recorder starts at (None, 0). An epoch change is a cut at the call: bytes admitted BEFORE `change_epoch(e)`
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
        self._unoffered_taken = False             # `close(unoffered=)` contabilizat o singură dată
        # R-M2: împărţirea backlog-ului hub-ului (`close(held=)`) — calculată O DATĂ, în worker, după
        # joburile dinaintea închiderii: (octeţi ai epoch-ului curent → marker, octeţi neatribuibili)
        self._held_split = None
        self._unoffered_total = 0
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
        # Skip-ul verificat în aşteptare (R2-H1): {"epoch", "start", "end", "reason", "cast_ts", "nonce",
        # "gap_id"}. Cât există, ingress-ul de la `end` încolo e ţinut (busy) până la commit-ul lui.
        self._skip = None
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
                                   max_records=st.gen_limits[0], max_plain=st.gen_limits[1],
                                   ver=st.write_ver)
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
        current epoch, admitted or counted lost. Not the committed position (`agent_committed`).
        While a skip is pending it is the skip's `replay_start` (feeding there answers `busy` until
        the skip's future resolves; on a failed skip read it again)."""
        if self._skip is not None:
            return (self._skip["epoch"], self._skip["end"])
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
        sk = self._skip
        if sk is not None:
            # R2-H1: cât skip-ul nu e comis, nimic de la replay_start încolo nu intră (nici în pending,
            # nici în overflow): retryable, nimic admis, nimic numărat. Sub replay_start = interval
            # declarat pierdut de agent → eroare de ordine.
            if at[1] >= sk["end"]:
                raise TxStoreError("busy", f"skip to {sk['end']} pending: feed again after it committed")
            raise TxStoreError("position", f"chunk at {at} inside the skipped interval [{sk['start']}, {sk['end']})")
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
        if self._skip is not None:
            raise TxStoreError("busy", "skip in progress: resume after it")
        return await self._submit("resync")

    def skip_to(self, at_epoch, replay_start, reason, cast_ts=0.0):
        """A verified upstream skip (RC-H2, R2-H1): the agent answered an attach from the cursor
        with `replay_start` (same epoch). Equal to the cursor → no-op; before it → refused
        ("position"): the hub trims the overlap and feeds from the cursor; after it → a dedicated
        job carrying the operation's identity (op nonce, gap id) and interval [cursor,
        replay_start): ONE GAP_MARKER, its `tx_gaps` row and the new cursor in ONE transaction.
        Until that commit, ingress at `replay_start` answers `busy` (nothing admitted, nothing
        counted), so no overflow can drop the marker. The future resolves ONLY when the commit
        holds exactly that row and that cursor; otherwise it fails explicitly — `skip-refused`
        (the cursor moved first: resume, re-attach, skip again; nothing counted for the interval)
        or `skipNotPublished` (write / publication failed: the bytes before the skip count as
        lost, the interval does not — the next skip covers it) — or with re-adoption.
        A second skip while one is pending answers `busy`."""
        if not (at_epoch is None or isinstance(at_epoch, str)) or type(replay_start) is not int or replay_start < 0:
            raise TxStoreError("badInput", "skip_to(epoch, replay_start)")
        if not isinstance(reason, str) or not _SKIP_REASON.fullmatch(reason):
            raise TxStoreError("badInput", "skip reason")
        if self.state != "running":
            raise RecorderLost("lost", f"recorder {self.state}")
        if self.overflow or self.closing or self._switch is not None or self._skip is not None:
            raise TxStoreError("busy", "resume first" if self.overflow else "another cut or skip in progress")
        if at_epoch != self.agent_epoch:
            raise TxStoreError("position", f"skip in epoch {at_epoch!r}, recorder in {self.agent_epoch!r}")
        cur = self.agent_offset
        if replay_start == cur:
            return self._done(None)
        if replay_start < cur:
            raise TxStoreError("position", f"replay starts at {replay_start}, before the cursor {cur}: "
                                           "trim the overlap and feed from the cursor")
        nonce = new_op_nonce()
        sk = {"epoch": at_epoch, "start": cur, "end": replay_start, "reason": "skip:" + reason,
              "cast_ts": cast_ts, "nonce": nonce,
              "gap_id": gap_id_for(self.sid, at_epoch, cur, replay_start - cur, nonce)}
        fut = self._submit("skip", sk)
        self._skip = sk
        return fut

    @staticmethod
    def _done(value):
        fut = asyncio.get_running_loop().create_future()
        fut.set_result(value)
        return fut

    def _add_gap(self, size, cast_ts, *, reason, epoch, start, nonce, out=None, cast=None, into_switch=False):
        """Marker bytes into `pending` (or into an epoch cut's held segment, BEFORE every byte of
        the new epoch); the positions of everything after it shift accordingly. `nonce` is the
        operation's (R2-M1): a re-emission by the same operation keeps the same gap id."""
        ev = gap_event(cast_ts)
        if into_switch:
            sw = self._switch
            bufs, lst = sw["bufs"], sw["gaps"]
            pos = [self.committed_len(k) + self._unpublished(k) + len(bufs[k]) for k in KIND_NAMES]
        else:
            bufs, lst = self.pending, self.gap_pending
            pos = [self.out_pos, self.cast_pos]
        g = Gap(pos[0], pos[1], size, out, cast, epoch, reason, start,
                gap_id_for(self.sid, epoch, start, size, nonce), (len(GAP_MARKER), len(ev)), nonce)
        bufs["out"] += GAP_MARKER
        bufs["cast"] += ev
        self.store.buffered_total += len(GAP_MARKER) + len(ev)
        self.out_pos += len(GAP_MARKER)
        self.cast_pos += len(ev)
        lst.append(g)
        return g

    # ── jobs ──

    def _submit_raw(self, op, *args):
        """The job's own future (never handed to a caller directly: see `_submit`)."""
        if self.state != "running":
            raise RecorderLost("lost", f"recorder {self.state}")
        fut = asyncio.get_running_loop().create_future()
        # Rezultatul e citit şi când apelantul a renunţat (wait_for, shutdown): fără avertismente.
        fut.add_done_callback(lambda f: f.cancelled() or f.exception())
        self._queue.put_nowait((op, args, fut))
        return fut

    def _submit(self, op, *args):
        # Anularea apelantului nu anulează un job început: fiecare apelant primeşte PROPRIUL scut.
        return asyncio.shield(self._submit_raw(op, *args))

    def checkpoint(self):
        return self._submit("checkpoint")

    def close(self, cast_ts=0.0, unoffered=0, held=None):
        """Close: ingress stops NOW (later bytes are refused, counted in `rejected`); the finalize
        job drains everything accepted before, seals and publishes. An overflow still open then is
        recorded as one GAP_MARKER at the end (`cast_ts` for its `.cast` event), its size in
        `gaps` and the result's `lost`, and alarmed. `unoffered` = upstream bytes of the current
        epoch the hub held past `received` and never offered (its backlog at close, PR5b M2): they
        join the same close marker, counted once per recorder even when close() is retried.
        `held` (recheck R-M2) = the hub's backlog as `(epoch, offset, n)` extents, classified by
        the WORKER against `received` once every job queued before the close has run (a late skip
        or epoch switch is not counted twice nor charged to another epoch): bytes of the current
        epoch past `received` (holes included) join the close marker, the rest come back as the
        result's `unrecorded` for the caller to alarm. The result always carries `unoffered` and
        `unrecorded`; a recorder replaced before the job runs raises `RecorderLost` (no result =
        no confirmation: the caller keeps its accounting)."""
        if not isinstance(unoffered, int) or unoffered < 0:
            raise TxStoreError("badInput", "unoffered")
        if held is not None:
            try:
                held = tuple((e, int(o), int(n)) for e, o, n in held)
            except (TypeError, ValueError):
                raise TxStoreError("badInput", "held") from None
            if any(o < 0 or n < 0 for _e, o, n in held):
                raise TxStoreError("badInput", "held")
        fut = self._submit("finalize", cast_ts, unoffered, held)
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
        if self._switch is not None:
            # R2-M2: o comutare spre ACELAŞI epoch deja în curs → viitorul ei (nu un no-op cu poziţia
            # veche: tăietura nu e încă comisă); spre alt epoch → busy (adaptorul serializează).
            if new_epoch == self._switch["new"]:
                # Recheck b0ce65f: un scut NOU pentru fiecare apelant în jurul aceluiaşi job — anularea
                # unui apelant nu poate anula viitorul celuilalt.
                return asyncio.shield(self._switch["fut"])
            raise TxStoreError("busy", "epoch change in progress")
        if self._skip is not None:
            raise TxStoreError("busy", "skip in progress")
        if new_epoch == self.agent_epoch:
            # RC-H1: o reataşare în acelaşi epoch NU e o tăietură; offsetul 0 ar re-înregistra octeţi
            # deja comişi ca fiind contigui. Hub-ul continuă de la `received` (taie suprapunerea).
            return self._done(self.agent_committed)
        inner = self._submit_raw("epoch", new_epoch)
        fut = asyncio.shield(inner)
        # Segmentul vechi (cu markerele lui şi pierderea vechiului epoch) se mută în tăietură: din
        # acest moment niciun overflow al noului epoch nu-l mai atinge (R-H1).
        self._switch = {"old": self._held_end(), "bufs": self.pending, "gaps": self.gap_pending,
                        "new": new_epoch, "loss": self._loss, "owed": None, "fut": inner}
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

    async def _job_checkpoint(self, skip=None):
        """Capture → append → fsync → publish. The publication unit is everything the writers hold
        beyond the committed prefix (both kinds, a batch whose publication failed earlier
        included), with the agent position of the last appended capture: both prefixes and the
        offset move together or not at all, and nothing is ever appended twice. With `skip` (the
        skip job), the captured bytes end at the skip's start and their marker, so they are
        written under the skip's `replay_start`; `_pend_from` stays at the start until the skip
        commits (a failure never counts the skipped interval as recorder loss)."""
        self._check_token()
        held = self._switch is not None
        batch, agent_end, gaps = self._capture()
        if skip is not None:
            agent_end = (skip["epoch"], skip["end"])
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
        try:
            await self._publish(self._plan(self._written_agent))
        except Refused as e:
            # R2-M1: un refuz de marker (gap-dup / gap-conflict) nu se repară prin reîncercare: un
            # recorder „running" cu lotul murdar n-ar mai progresa → readoptare deterministă.
            if self.state != "replaced" and e.reason in ("gap-dup", "gap-conflict"):
                raise _NeedReadopt(f"gap refused: {e}") from None
            raise
        if had_gaps:
            self.degraded = False
        elif not self.overflow and self.degraded and not self.dropped:
            self.degraded = False
        await self._maybe_roll()
        self._maybe_trigger_cap()
        return self._snapshot_state()

    async def _job_skip(self, sk):
        """The verified skip (R2-H1): its marker goes into the capture of THIS job (nothing between
        `skip_to` and here could drop it: ingress at `replay_start` is held), the publication
        carries the marker, its row and (epoch, replay_start). Success is decided from the
        committed state, never from the job returning: exactly this gap id published and the
        cursor at `replay_start`."""
        self._check_token()
        try:
            if self._skip is not sk:
                raise _NeedReadopt("skip job without its skip")
            want = (sk["epoch"], sk["end"])
            if (self.overflow or self._switch is not None or self.agent_epoch != sk["epoch"]
                    or tuple(self._held_end()) != (sk["epoch"], sk["start"])):
                # Cursorul s-a mutat înainte de captură (un job anterior a eşuat la scriere → overflow):
                # skip-ul nu mai porneşte de la C. Intervalul nu se numără; hub-ul reia, re-ataşează, sare.
                raise Refused("skip-refused", f"cursor moved before the skip was captured "
                                              f"({self._held_end()} ≠ {(sk['epoch'], sk['start'])}): resume, re-attach, skip again")
            self._add_gap(sk["end"] - sk["start"], sk["cast_ts"], reason=sk["reason"], epoch=sk["epoch"],
                          start=sk["start"], nonce=sk["nonce"])
            err = None
            try:
                await self._job_checkpoint(skip=sk)
            except _NeedReadopt:
                raise
            except Refused as e:
                if self.state == "replaced":
                    raise
                raise _NeedReadopt(f"skip publication refused: {e}") from None
            except (TxStoreError, OSError, sqlite3.Error, txformat.TxFormatError) as e:
                err = e
                # Ce ţin writerele (markerul inclus) se publică acum sau se abandonează; nimic nu rămâne
                # pe jumătate pentru o publicare ulterioară sub altă poziţie.
                await self._flush_dirty()
            g = next((x for x in self.gaps if x.gap_id == sk["gap_id"]), None)
            if g is not None and tuple(self._covered) == want:
                self.agent_offset = sk["end"]
                self._pend_from = want
                return self._snapshot_state()
            if g is not None:
                raise _NeedReadopt("skip marker published without its cursor")
            # Nepublicat: markerul a fost abandonat cu writerele (sintetic, nu pierdere); octeţii
            # dinaintea skip-ului sunt număraţi pierduţi de abandon; intervalul NU (îl acoperă skip-ul
            # următor, după resume).
            if not self.overflow:
                self._enter_overflow()
            raise TxStoreError("skipNotPublished", f"skip {sk['gap_id']} not published: {err}")
        finally:
            if self._skip is sk:
                self._skip = None

    def _snapshot_state(self):
        return {"out_len": self.committed_len("out"), "cast_len": self.committed_len("cast"),
                "agent": self.agent_committed, "list_epoch": self.list_epoch}

    @staticmethod
    def _entry(g):
        w = g.writer
        return txdesc.Generation(g.gen_id, txdesc.STATE_SEALED if w.sealed else txdesc.STATE_LIVE,
                                 w.data_count, w.plain_len, w.phys_len, w.hdr_mac, w.ver)

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
            reset = False
            if w.plain_len >= g.next_index_at:
                g.index.append(txformat.IndexEntry(w.data_count, w.plain_len, w.phys_len))
                g.next_index_at = w.plain_len + INDEX_STRIDE
                reset = True                  # v2: intrarea de index numeşte un început de bloc
            w.append(piece, reset=reset)
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
                                                e.plain_len, e.phys_len, e.hdr_mac, e.ver)
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
                # RC-M1 / R2-M1: rândul durabil al markerului, în ACEEAŞI tranzacţie cu octeţii lui. Un id
                # deja publicat = a doua publicare a aceleiaşi operaţii → refuz (gap-dup, readoptare). Un
                # rând nepublicat (gapUnrecorded) se completează DOAR dacă e aceeaşi operaţie (nonce,
                # epoch, interval); altfel e un conflict, nu un retry → refuz (gap-conflict).
                r = c.execute("SELECT published_at, epoch, upstream_start, upstream_size, op_nonce FROM tx_gaps "
                              "WHERE sid=? AND gap_id=?", (sid, g.gap_id)).fetchone()
                if r is None:
                    c.execute("INSERT INTO tx_gaps(sid, gap_id, epoch, upstream_start, upstream_size, reason, "
                              "op_nonce, out_pos, cast_pos, published_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                              (sid, g.gap_id, g.epoch, g.start, g.size, g.reason, g.op_nonce,
                               g.out_pos, g.cast_pos, now))
                    continue
                if r[0] is not None:
                    raise Refused("gap-dup", g.gap_id)
                if tuple(r[1:]) != (g.epoch, g.start, g.size, g.op_nonce):
                    raise Refused("gap-conflict", g.gap_id)
                n = c.execute("UPDATE tx_gaps SET reason=?, out_pos=?, cast_pos=?, published_at=? WHERE sid=? "
                              "AND gap_id=? AND op_nonce=? AND published_at IS NULL",
                              (g.reason, g.out_pos, g.cast_pos, now, sid, g.gap_id, g.op_nonce)).rowcount
                if n != 1:
                    raise Refused("gap-conflict", g.gap_id)
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
            gaps = {g.gap_id: c.execute("SELECT published_at, epoch, upstream_start, upstream_size, reason, "
                                        "op_nonce, out_pos, cast_pos FROM tx_gaps WHERE sid=? AND gap_id=?",
                                        (sid, g.gap_id)).fetchone()
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
            # R2-M1: şi poziţiile markerului, nu doar intervalul: un rând al altei publicări nu e al nostru.
            r = gaps[g.gap_id]
            return r is not None and r[0] is not None and tuple(r[1:]) == (
                g.epoch, g.start, g.size, g.reason, g.op_nonce, g.out_pos, g.cast_pos)

        def gap_unpublished(g):
            r = gaps[g.gap_id]
            return r is None or (r[0] is None and tuple(r[1:4]) + (r[5],) == (g.epoch, g.start, g.size, g.op_nonce))
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
                and all(gap_unpublished(g) for g in plan.gaps)):
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
                                   sid=self.sidb, gen_id=gid, created_ms=int(st.clock() * 1000),
                                   ver=st.write_ver)
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
                                     plain_len=w.plain_len, phys_len=w.phys_len, hdr_mac=w.hdr_mac,
                                     ver=w.ver)
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
                                  w.phys_len, w.hdr_mac, w.ver)
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
                # Aceeaşi operaţie (acelaşi nonce) între încercări: acelaşi id cât timp intervalul e acelaşi.
                nonce = owed.setdefault("nonce", new_op_nonce())
                owed["gap"] = g = self._add_gap(owed["agent"], cast_ts, reason=reason, epoch=epoch,
                                                start=owed["start"], nonce=nonce, out=owed["out"],
                                                cast=owed["cast"], into_switch=into_switch)
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
                      "op_nonce, out_pos, cast_pos, published_at) VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL)",
                      (sid, g.gap_id, g.epoch, g.start, g.size, g.reason, g.op_nonce))
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

    async def _job_finalize(self, cast_ts=0.0, unoffered=0, held=None):
        """Close: drain (final checkpoint of everything accepted before close; a failed one is
        published or abandoned), then ONE GAP_MARKER for everything not recorded (an overflow
        still open, abandoned bytes), SEAL both kinds, publish; retire never-published
        generations. The owed marker and its accounting are kept across attempts: a failure
        leaves the recorder retryable (close() again) with the same total."""
        if self.store.tokens.get(self.sid) != self.token:
            self.state = "replaced"
            # R-M2: înlocuit ≠ închis. Fără rezultat, apelantul nu primeşte o confirmare falsă şi
            # păstrează (sau alarmează) octeţii pe care îi ţine; înainte întorcea None, citit ca succes.
            raise RecorderLost("replaced", f"{self.sid}: a newer writer owns this sid; not finalized")
        self.closing = True
        if held is not None and self._held_split is None:
            # R-M2: împărţirea se face AICI, după joburile dinaintea close-ului (un skip / o comutare
            # comise târziu au mutat deja `received`), nu faţă de cursorul de la apel
            re_, ro = self.received
            end, other = ro, 0
            for e, o, n in held:
                if e == re_:
                    end = max(end, o + n)         # sub `received`: deja acoperit (înregistrat / marker)
                else:
                    other += n                    # alt epoch: nu poate deveni markerul acestuia
            self._held_split = (end - ro, other)
        held_same, held_other = self._held_split or (0, 0)
        await self._checkpoint_or_flush()
        L = self._loss
        if (unoffered or held_same) and not self._unoffered_taken:
            # octeţii pe care hub-ul nu i-a mai putut oferi: pierdere terminală, în ACELAŞI marker
            self._unoffered_taken = True
            self._unoffered_total = unoffered + held_same
            self._lose(unoffered + held_same, 0, 0)
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
        res["unoffered"] = self._unoffered_total
        res["unrecorded"] = held_other
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
        if a.gen_id != b.gen_id or a.hdr_mac != b.hdr_mac or a.ver != b.ver:
            raise Refused("regress", "generation list reordered")
        if a.state in (txdesc.STATE_SEALED, txdesc.STATE_RECOVERED) and a != b:
            raise Refused("regress", "a closed generation changed")
        if (b.data_count < a.data_count or b.plain_len < a.plain_len or b.phys_len < a.phys_len):
            raise Refused("regress", "a committed prefix would shrink")
        if a.state == txdesc.STATE_LIVE and b.state == txdesc.STATE_RECOVERED and a != txdesc.Generation(
                b.gen_id, a.state, b.data_count, b.plain_len, b.phys_len, b.hdr_mac, b.ver):
            raise Refused("regress", "recovered must keep the committed counts")
    if new.flags != (old.flags if old else new.flags):
        raise Refused("regress", "flags changed")


def _check_compaction(old, new, prefix):
    if old is None or tuple(old.generations[:len(prefix)]) != tuple(prefix):
        raise Refused("cas", "committed list no longer starts with P")
    if tuple(new.generations[1:]) != tuple(old.generations[len(prefix):]):
        raise Refused("cas", "tail L not preserved")


# ── backup snapshot (§12.11.3, PR6c) ─────────────────────────────────────────
#
# `backup_snapshot()` e SINGURA cale prin care un backup citeşte înregistrări. Pasul 1 (VACUUM INTO,
# lista din copie, pin-urile) rulează sub bariera Store-ului viu, pe loop-ul lui, chemat dintr-un
# thread de backup; fără Store viu (restore la boot, `hostops backup` cu app-ul oprit) exclusivitatea
# o dă lacătul de boot al procesului (§12.2), deci acelaşi pas rulează direct. Paşii 2–4 sunt ai
# thread-ului de backup (proprietarul pin-urilor de la „submit": doar `release()` le eliberează).

BACKUP_VACUUM_SECS = 120.0       # bugetul VACUUM INTO (sub barieră)
BACKUP_HOLD_SECS = 600.0         # pin-urile unui snapshot: cel mult 10 min în total
BACKUP_START_WAIT = 900.0        # aşteptarea barierei + pasul 1, din thread-ul de backup
_BACKUP_SLOT = threading.Lock()  # UN snapshot în zbor per proces (in-app, programat, socket)
_backup_source = None            # (Store, loop) cât timp gateway-ul serveşte înregistrări criptate


class BackupBusy(TxStoreError):
    """Another snapshot is in flight, the barrier or a budget ran out, or the snapshot was
    cancelled: nothing was published (`backup.busy`)."""


class BackupChanged(TxStoreError):
    """The emit pass read bytes that differ from the verify pass (media changed under a pin): the
    container is abandoned and rebuilt once without that pair (§12.11.3 step 3)."""

    def __init__(self, sid, detail=""):
        super().__init__("changed", detail or sid)
        self.sid = sid


def recompact_work(generations):
    """Codex M2: estimated I/O of recompacting one kind made of `generations` (ALL of them: a kind
    holding one v1 generation is copied whole, v2 included). The source's physical bytes are read
    twice (full verification, then the copy); the new generation is written once and read back
    twice (verify_full, reader hash), each at most ~ its decoded size (incompressible worst case),
    so the decoded bytes count three times. An upper bound, charged before the attempt."""
    return sum(2 * g.phys_len + 3 * g.plain_len for g in generations)


class GenCorrupt(TxStoreError):
    """A generation failed its authentication / structure check (corruption, never an I/O fault)."""


class RecompactSourceCorrupt(TxStoreError):
    """§12.11.14 (Codex M1): a source generation of a recompaction failed its full integrity
    check. Nothing was written or changed: the recording keeps its status, quarantine state and
    files for investigation; the janitor raises an alarm and System health names the session."""


def set_backup_source(store, loop):
    """txhub.install: the live Store whose barrier and pins every in-process backup uses."""
    global _backup_source
    _backup_source = (store, loop)


def clear_backup_source(store=None):
    global _backup_source
    if store is None or (_backup_source is not None and _backup_source[0] is store):
        _backup_source = None


def backup_source():
    return _backup_source


class _HashPRead(_PRead):
    """_PRead that hashes every byte the parse consumes and checks a cancel hook per read."""

    def __init__(self, fd, limit, check=None):
        super().__init__(fd, 0, limit=limit)
        self.h = hashlib.sha256()
        self.check = check

    def read(self, n):
        if self.check is not None:
            self.check()
        b = super().read(n)
        self.h.update(b)
        return b


def verify_generation_fd(fd, sid, kind, g, rk, *, exact_size=False, check=None):
    """Full check of one committed generation on `fd`, reading exactly its `phys_len` bytes:
    header and hdr_mac, every record, counts, the SEAL of a sealed one (nothing after it).
    Returns the SHA-256 of those bytes. `exact_size` (restore staging): the file must be exactly
    `phys_len` long. Raises GenCorrupt (the recording) — an OSError stays an OSError (a fault)."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise GenCorrupt("corrupt", "not a regular file")
    if st.st_size < g.phys_len or (exact_size and st.st_size != g.phys_len):
        raise GenCorrupt("corrupt", "size %d, committed %d" % (st.st_size, g.phys_len))
    kb = KINDS[kind]
    fp = _HashPRead(fd, g.phys_len, check)
    try:
        hdr = txformat.verify_header(fp.read(txformat.PREFIX_LEN), txformat.generation_keys(
            rk, kb, g.gen_id), kind=kb, sid=_sid_bytes(sid), gen_id=g.gen_id, ver=g.ver)
        if not hmac.compare_digest(hdr.hdr_mac, g.hdr_mac):
            raise GenCorrupt("corrupt", "hdr-mac-mismatch")
        cur = txformat.RecordCursor(fp, rk, kind=kb, gen_id=g.gen_id, hdr_mac=g.hdr_mac,
                                    data_count=g.data_count, ver=g.ver, plain_len=g.plain_len)
        while cur.next() is not None:
            pass
        if cur.logical_offset != g.plain_len:
            raise GenCorrupt("corrupt", "plain-len-mismatch")
        if g.state == txdesc.STATE_SEALED:
            info = cur.seal()
            if info.phys_len != g.phys_len:
                raise GenCorrupt("corrupt", "phys-len-mismatch")
            if os.pread(fd, 1, g.phys_len):
                raise GenCorrupt("corrupt", "trailing-bytes")
    except txformat.TxFormatError as e:
        raise GenCorrupt("corrupt", e.reason) from None
    if fp.pos != g.phys_len:
        raise GenCorrupt("corrupt", "phys-len-mismatch")
    return fp.h.digest()


@dataclass
class BkGen:
    kind: str
    g: object                      # txdesc.Generation
    ledger: tuple = None           # (dev, ino) din registrul copiei, când există
    sha: bytes = None              # din trecerea de verificare


@dataclass
class BkPair:
    """Every generation of both kinds of one sid (verified and emitted as a unit, owner Q3)."""
    sid: str
    kinds: list                    # kind-urile cu descriptor
    rk: bytes = None
    gens: list = field(default_factory=list)
    reason: str = ""               # deja exclusă din pasul 1 (descriptor / cheie / stare)


@dataclass
class BkLegacy:
    """A 3.7 plaintext still owned by the migration (`tx_migration` pending / orphan / failed)."""
    sid: str
    kind: str
    dirn: str
    name: str
    ident: tuple
    reason: str = ""


class BackupSnapshot:
    """Step 1's result: the VACUUM copy, the recordings listed by it, the pins. Owned by the
    backup thread from `backup_snapshot()`'s return; `release()` (idempotent) drops the pins and
    the slot. Generation fds are opened per pair while their gen_id is pinned (a pinned name is
    never unlinked and generation files are never renamed or rewritten), so the open fds stay
    bounded whatever the number of recordings."""

    def __init__(self, *, db_copy, tdir, kwk, inst, store=None, loop=None, recordings=True,
                 hold_secs=BACKUP_HOLD_SECS, cancel=None):
        self.db_copy = db_copy
        self.tdir = tdir
        self.kwk = kwk
        self.inst = inst
        self.store = store
        self.loop = loop
        self.recordings = recordings
        self.pairs = []
        self.legacy = []
        self.listing = []              # (sid, kind, state, reason) pentru `not-requested` / `one-kind`
        self.pinned = []
        self.plain_pinned = []
        self.started = time.monotonic()
        self.hold_secs = hold_secs
        self.cancel = cancel           # threading.Event (socket: deconectare)
        self.alarms = []
        self._released = False
        self._slot = False
        self._own_tdir = None          # fd-ul directorului deschis de noi (fără Store viu)
        self._holds_pins = False       # pin-urile chiar luate pe Store (niciodată „eliberate" altfel)

    # -- budgets / cancel --
    def check(self):
        if self.cancel is not None and self.cancel.is_set():
            raise BackupBusy("busy", "the backup was cancelled")
        if time.monotonic() - self.started > self.hold_secs:
            raise BackupBusy("busy", "the snapshot held its pins over the %d s budget" % self.hold_secs)

    def alarm(self, code, detail):
        self.alarms.append((code, detail))
        src = self.store
        if src is not None and self.loop is not None:
            with contextlib.suppress(RuntimeError):
                self.loop.call_soon_threadsafe(src.alarm, code, detail)

    # -- files --
    def _open_gen(self, sid, bg):
        fd = os.open(gen_name(sid, bg.kind, bg.g.gen_id.hex()), _RDONLY, dir_fd=self.tdir)
        try:
            st = os.fstat(fd)
            if bg.ledger is not None and (st.st_dev, st.st_ino) != tuple(bg.ledger):
                raise GenCorrupt("corrupt", "not the inode the ledger recorded")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def verify_pair(self, p):
        """Verify pass (nothing emitted). '' = every generation authentic, else the reason the
        pair is excluded. I/O errors propagate (they fail the backup, step 4)."""
        if p.reason:
            return p.reason
        for bg in p.gens:
            self.check()
            try:
                fd = self._open_gen(p.sid, bg)
            except FileNotFoundError:
                return "missing-generation"
            except GenCorrupt as e:
                return "generation:" + e.detail[:40]
            try:
                bg.sha = verify_generation_fd(fd, p.sid, bg.kind, bg.g, p.rk, check=self.check)
            except GenCorrupt as e:
                return ("generation:" + e.detail)[:64]
            finally:
                os.close(fd)
        return ""

    def gen_chunks(self, p, bg):
        """Emit pass: exactly `phys_len` bytes, re-hashed while copying; a difference with the
        verify pass → BackupChanged (the container cannot be withdrawn: rebuilt without it)."""
        fd = self._open_gen(p.sid, bg)
        try:
            h = hashlib.sha256()
            pos, end = 0, bg.g.phys_len
            while pos < end:
                self.check()
                b = os.pread(fd, min(CAP_CHUNK, end - pos), pos)
                if not b:
                    raise BackupChanged(p.sid, "generation shrank while copied")
                h.update(b)
                pos += len(b)
                if pos == end and not hmac.compare_digest(h.digest(), bg.sha):
                    raise BackupChanged(p.sid, "generation changed between verify and copy")
                yield b
        finally:
            os.close(fd)

    def legacy_open(self, lg):
        """The plaintext through its dir fd (O_NOFOLLOW), identity = the copied row's. None when it
        is absent or changed (then listed `excluded`)."""
        try:
            dfd = self.tdir if lg.dirn == "transcripts" else os.open(
                "arhiva", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.tdir)
        except FileNotFoundError:
            return None
        try:
            try:
                fd = os.open(lg.name, _RDONLY | os.O_NONBLOCK, dir_fd=dfd)
            except (FileNotFoundError, OSError):
                return None
        finally:
            if dfd != self.tdir:
                os.close(dfd)
        try:
            _same_plain(os.fstat(fd), lg.ident, lg.name)
        except TxStoreError:
            os.close(fd)
            return None
        return fd

    def legacy_chunks(self, fd, size):
        pos = 0
        while pos < size:
            self.check()
            b = os.pread(fd, min(CAP_CHUNK, size - pos), pos)
            if not b:
                raise OSError("plaintext shrank while copied")
            pos += len(b)
            yield b

    # -- release --
    def release(self):
        if self._released:
            return
        self._released = True
        gens, plain = self.pinned, self.plain_pinned
        self.pinned, self.plain_pinned = [], []
        st, loop = self.store, self.loop
        if self._holds_pins and st is not None and loop is not None and (gens or plain):
            self._holds_pins = False
            def unpin():
                st.unpin_gens(gens)
                st.unpin_plain(plain)
            try:
                loop.call_soon_threadsafe(unpin)
            except RuntimeError:
                pass                               # loop-ul s-a închis: Store-ul nu mai există
        if self._own_tdir is not None:
            fd, self._own_tdir = self._own_tdir, None
            os.close(fd)
        if self._slot:
            self._slot = False
            _BACKUP_SLOT.release()


def _vacuum_into(db_path, dest, budget):
    """VACUUM INTO with a hard time budget (sqlite3 interrupt beyond it → BackupBusy)."""
    con = sqlite3.connect(str(db_path))
    deadline = time.monotonic() + budget
    con.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10000)
    try:
        con.execute("VACUUM INTO ?", (dest,))
    except sqlite3.OperationalError as e:
        if time.monotonic() > deadline or "interrupt" in str(e).lower():
            with contextlib.suppress(OSError):
                os.unlink(dest)
            raise BackupBusy("busy", "VACUUM INTO over its %d s budget" % budget) from None
        raise
    finally:
        con.close()


def _list_from_copy(snap):
    """Step 1, on the VACUUM copy only: pairs (descriptors decoded with the copy's RK envelopes),
    the ledger inodes, the plaintext the migration still owns, the `one-kind` entries."""
    con = sqlite3.connect("file:%s?mode=ro" % snap.db_copy, uri=True)
    try:
        try:
            drows = con.execute("SELECT sid, kind, blob, version, status FROM tx_descriptors "
                                "ORDER BY sid, kind").fetchall()
            envs = dict(con.execute("SELECT sid, envelope FROM session_keys").fetchall())
            ledger = {r[0]: (r[1], r[2]) for r in con.execute(
                "SELECT gen_id, dev, ino FROM tx_files WHERE state='published' AND dev IS NOT NULL").fetchall()}
            mig = con.execute("SELECT sid, kind, dir, name, dev, ino, size, mtime_ns FROM tx_migration "
                              "WHERE state IN ('pending','orphan','failed') ORDER BY sid, kind").fetchall()
        except sqlite3.OperationalError:
            drows, envs, ledger, mig = [], {}, {}, []
    finally:
        con.close()
    by_sid = collections.OrderedDict()
    for sid, kind, blob, version, status in drows:
        by_sid.setdefault(sid, []).append((kind, blob, version, status))
    described = set()
    for sid, rows in by_sid.items():
        kinds = [r[0] for r in rows]
        described.update((sid, k) for k in kinds)
        for other in KIND_NAMES:
            if other not in kinds:
                snap.listing.append((sid, other, "one-kind", ""))
        if not snap.recordings:
            snap.listing.extend((sid, k, "not-requested", "") for k in kinds)
            continue
        p = BkPair(sid, kinds)
        snap.pairs.append(p)
        bad = [s for _k, _b, _v, s in rows if s in ("damaged", "absent")]
        if bad:
            p.reason = bad[0]
            continue
        env = envs.get(sid)
        if env is None or not _SID_RE.match(sid) or any(k not in KINDS for k in kinds):
            p.reason = "no-key" if env is None else "bad-row"
            continue
        try:
            p.rk = keyring.unwrap_under_kwk(snap.kwk, bytes(env), keyring.KT_RK)
        except keyring.KeyringError:
            p.reason = "key"
            continue
        for kind, blob, version, _status in rows:
            try:
                d = txdesc.decode_descriptor(bytes(blob), snap.kwk, installation_id=snap.inst,
                                             sid=_sid_bytes(sid), kind=KINDS[kind], rk_envelope=bytes(env))
            except txdesc.DescriptorError as e:
                p.reason = ("descriptor:" + e.reason)[:64]
                break
            if d.version != version:
                p.reason = "descriptor:version"
                break
            for g in d.generations:
                p.gens.append(BkGen(kind, g, ledger.get(g.gen_id.hex())))
    if snap.recordings:
        for sid, kind, dirn, name, dev, ino, size, mtime_ns in mig:
            # un rând cu cheie de cale (nume în afara allowlist-ului) sau lângă un descriptor nu e o
            # înregistrare `legacy` listabilă: nu intră în arhivă (rămâne în DB-ul copiat, cu starea lui)
            if (not _SID_RE.match(sid) or kind not in KINDS or dirn not in ("transcripts", "arhiva")
                    or name != "%s.%s" % (sid, kind) or (sid, kind) in described
                    or None in (dev, ino, size, mtime_ns)):
                continue
            snap.legacy.append(BkLegacy(sid, kind, dirn, name, (dev, ino, size, mtime_ns)))
    snap.pinned = sorted({bg.g.gen_id.hex() for p in snap.pairs for bg in p.gens})
    snap.plain_pinned = sorted({(lg.dirn, lg.name) for lg in snap.legacy})


def _step1_sync(snap, db_path, budget):
    _vacuum_into(db_path, snap.db_copy, budget)
    _list_from_copy(snap)


async def _step1_on_loop(snap, db_path, budget):
    st = snap.store
    async with st.barrier:
        # sub barieră: nicio publicare / retragere nu se intercalează între copia DB-ului şi pin-uri
        await st.io(_step1_sync, snap, db_path, budget)
        st.pin_gens(snap.pinned)
        st.pin_plain(snap.plain_pinned)
        # sincron cu pin-urile: o anulare înainte de linia asta nu are ce elibera
        snap._holds_pins = True
    return snap


def backup_snapshot(db_copy, *, kwk, inst, recordings=True, db_path=None, transcripts_dir=None,
                    vacuum_secs=BACKUP_VACUUM_SECS, hold_secs=BACKUP_HOLD_SECS, cancel=None,
                    start_wait=BACKUP_START_WAIT):
    """Step 1 of §12.11.3 from a backup THREAD (never the loop). Returns a BackupSnapshot that the
    caller owns and must `release()`. The slot (one snapshot per process) is taken here; busy →
    BackupBusy. With a live Store the copy and the pins are taken under its barrier on its loop;
    without one the caller's process exclusivity (boot lock) stands in for the barrier."""
    if not _BACKUP_SLOT.acquire(blocking=False):
        raise BackupBusy("busy", "another backup snapshot is in progress")
    db_path = str(db_path or config.DB_PATH)
    tdir = None
    snap = None
    try:
        src = _backup_source
        tpath = str(transcripts_dir or config.TRANSCRIPT_DIR)
        if src is not None:
            st, loop = src
            try:
                running = asyncio.get_running_loop()
            except RuntimeError:
                running = None
            if running is loop:
                raise RuntimeError("backup_snapshot() called on the loop thread (it would deadlock)")
            snap = BackupSnapshot(db_copy=db_copy, tdir=st.dir_fd, kwk=kwk, inst=inst, store=st, loop=loop,
                                  recordings=recordings, hold_secs=hold_secs, cancel=cancel)
            fut = asyncio.run_coroutine_threadsafe(_step1_on_loop(snap, db_path, vacuum_secs), loop)
            try:
                fut.result(timeout=start_wait)
            except BaseException:
                # anulat înainte de „submit": coroutina eliberează (n-a apucat să fixeze) sau a
                # terminat între timp — atunci pin-urile sunt ale noastre şi le eliberăm aici
                if not fut.cancel() and fut.done() and fut.exception() is None:
                    snap.release()
                    snap = None
                raise
        else:
            try:
                tdir = os.open(tpath, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except FileNotFoundError:
                tdir = None
            snap = BackupSnapshot(db_copy=db_copy, tdir=tdir, kwk=kwk, inst=inst, recordings=recordings,
                                  hold_secs=hold_secs, cancel=cancel)
            _step1_sync(snap, db_path, vacuum_secs)
            if tdir is None and (snap.pairs or snap.legacy):
                # descriptori fără director de transcripturi: fiecare pereche lipseşte (exclusă)
                for p in snap.pairs:
                    p.reason = p.reason or "missing-generation"
                snap.legacy = []
            snap._own_tdir = tdir
            tdir = None
    except BaseException as e:
        if tdir is not None:
            os.close(tdir)
        if snap is not None and not snap._released:
            snap._slot = True
            snap.release()
        else:
            _BACKUP_SLOT.release()
        if isinstance(e, (asyncio.TimeoutError, concurrent.futures.TimeoutError)):
            raise BackupBusy("busy", "the recording store did not admit the backup in time") from None
        raise
    snap._slot = True
    return snap


# ── restore staging / apply helpers (§12.11.3 "Restore of recordings") ──────


def staged_pairs(db_path, kwk, inst, decode=None):
    """Every staged descriptor: {sid: (rk, [(kind, Generation)], {kind: status})}. Those for which
    `decode(sid, kind)` is true (the restore: `included`) are decoded with the STAGED keyring and
    RK envelope; one that does not authenticate raises GenCorrupt. The others are only listed (a
    recording the backup excluded may be excluded precisely because its descriptor is damaged)."""
    con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        try:
            drows = con.execute("SELECT sid, kind, blob, version, status FROM tx_descriptors").fetchall()
            envs = dict(con.execute("SELECT sid, envelope FROM session_keys").fetchall())
        except sqlite3.OperationalError:
            return {}
    finally:
        con.close()
    out = {}
    for sid, kind, blob, version, status in drows:
        if not _SID_RE.match(str(sid)) or kind not in KINDS:
            raise GenCorrupt("corrupt", "staged descriptor key")
        ent = out.setdefault(sid, [None, [], {}])
        ent[2][kind] = status
        if decode is not None and not decode(sid, kind):
            continue
        env = envs.get(sid)
        if env is None:
            raise GenCorrupt("corrupt", "%s: descriptor without RK" % sid[:8])
        try:
            if ent[0] is None:
                ent[0] = keyring.unwrap_under_kwk(kwk, bytes(env), keyring.KT_RK)
            d = txdesc.decode_descriptor(bytes(blob), kwk, installation_id=inst, sid=_sid_bytes(sid),
                                         kind=KINDS[kind], rk_envelope=bytes(env))
        except (keyring.KeyringError, txdesc.DescriptorError) as e:
            raise GenCorrupt("corrupt", "%s.%s: %s" % (sid[:8], kind, getattr(e, "reason", "?"))) from None
        if d.version != version:
            raise GenCorrupt("corrupt", "%s.%s: version column" % (sid[:8], kind))
        ent[1].extend((kind, g) for g in d.generations)
    return {k: tuple(v) for k, v in out.items()}


def rebind_restored_sync(db_path, transcripts_dir):
    """Restore apply, after the DB and the transcripts are in place (under the boot lock): the
    restored ledger and the migration rows name the inodes of the REPLACED volume; they are bound
    to the files the apply has just copied (verified at stage), so `retire` and the migration's
    identity-checked unlink act on them. Idempotent. Rows whose file is absent are left as they
    are (an `absent` recording; a migration row that then fails as missing)."""
    try:
        tdir = os.open(str(transcripts_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return 0
    con = sqlite3.connect(str(db_path), isolation_level=None)
    n = 0
    try:
        con.execute("BEGIN IMMEDIATE")
        try:
            rows = con.execute("SELECT gen_id, sid, kind FROM tx_files WHERE state='published'").fetchall()
            mig = con.execute("SELECT sid, kind, dir, name FROM tx_migration WHERE state IN "
                              "('pending','orphan','failed')").fetchall()
        except sqlite3.OperationalError:
            rows, mig = [], []
        for hexid, sid, kind in rows:
            try:
                st = os.stat(gen_name(sid, kind, hexid), dir_fd=tdir, follow_symlinks=False)
            except (FileNotFoundError, TxStoreError, KeyError, ValueError):
                continue
            if stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                con.execute("UPDATE tx_files SET dev=?, ino=? WHERE gen_id=?", (st.st_dev, st.st_ino, hexid))
                n += 1
        for sid, kind, dirn, name in mig:
            if dirn not in ("transcripts", "arhiva") or "/" in str(name):
                continue
            try:
                st = os.stat((name if dirn == "transcripts" else "arhiva/" + name), dir_fd=tdir,
                             follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                con.execute("UPDATE tx_migration SET dev=?, ino=?, size=?, mtime_ns=?, sha256=NULL "
                            "WHERE sid=? AND kind=?", (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                                                       sid, kind))
                n += 1
        con.execute("COMMIT")
    except BaseException:
        with contextlib.suppress(Exception):
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()
        os.close(tdir)
    return n
