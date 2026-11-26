"""Erasure journal `WTJ1`, off-host attestation, the continuity quarantine and Owner recovery
(ENCRYPTION-AT-REST.md §12.5, §12.11.4, §12.11.8 Q1/Q2/Q4; PR6a).

Inert unless encrypted recordings are active (`txhub.boot` opened a `txstore.Store`, which in this
build happens only on a test-fixture volume under a test gate). With `WEBTERM_TX_RECORDINGS` off
nothing here runs: backup and restore keep their PR5 / 3.7 code (`backup.py` asks `txstore.enabled()`
before calling anything of this module).

Pieces:

* **Codec** (`header`, `encode_entry`, `parse`): the WTJ1 bytes of §12.11.4. Header `"WTJ1"` | ver 1 |
  3 reserved zero bytes | installation id 16 B, then 97-byte entries `n u64 | time u64 ms | sid 16 B |
  kinds u8 | rk_hash 32 B | mac 32 B`, little-endian, mac = HMAC-SHA-256(K_erase, "wt/v1/wtj-entry" ‖
  installation id ‖ previous mac ‖ entry without mac), K_erase = HKDF(KWK, "wt/v1/erase"). `parse`
  returns the authentic prefix and says where (and why) it stops.
* **Journal file** (`Journal`): `DATA_DIR/erasures.wtj`, created `O_EXCL` (file + directory fsync),
  appended `O_APPEND` + fsync after checking that its length is the one we last saw; tail repair
  (copy the authentic prefix to a temp `O_EXCL` file, fsync, rename, directory fsync, cut bytes
  kept as `erasures.wtj.tail-<ms>`).
* **Erasure** (`erase`): the four steps of §12.11.4 under the sid's lease and the Store barrier.
* **Boot** (`boot`): verify the journal against the DB's committed head before any reader; re-apply
  missing entries; quarantine every recording on a missing / rolled-back / forked / broken journal.
* **Attestation** (`attest_once`, janitor `start`): one immutable object per head and destination,
  read back and authenticated; `tx_state.attested_heads`.
* **Freshness and restore** (`decide_restore`, `reconcile_apply`): the newest authentic head wins,
  a stale head never overrides, divergent authentic journals are a conflict, and without proof the
  restored recordings are quarantined (`mark_unproven`).
* **Owner recovery** (`list_quarantined`, `recover`, `recover_journal`, `release`, `requarantine`):
  recordings quarantined for missing continuity proof, or (strictly, never released) for a damaged
  journal while System health shows its diagnosis; one at a time. `retire_destination`: the
  audited Owner override dropping a gone destination from the marker's mandatory set.
* **Readiness** (`journal_ready`, `quarantine_ready`) for the boot's PR6 gate, and `health()` for
  System health.
"""
import asyncio
import collections
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import struct
import time
from dataclasses import dataclass, field

from . import config, keyring, migration, txstore

log = logging.getLogger("webterm.erasure")

# ── format ───────────────────────────────────────────────────────────────────

MAGIC = b"WTJ1"
VERSION = 1
HDR_LEN = 24
ENTRY_LEN = 97
MAC_LEN = 32
ZERO_MAC = b"\x00" * MAC_LEN
MAC_DOMAIN = b"wt/v1/wtj-entry"
_BODY = struct.Struct("<QQ16sB32s")              # 65 B; + mac 32 B = 97 B
KINDS_OUT, KINDS_CAST, KINDS_BOTH = 1, 2, 3
CAP = 1 << 20                                    # §12.11.4: ≈ 100 MiB, apoi refuz
WARN_AT = CAP * 9 // 10
MAX_FILE = HDR_LEN + CAP * ENTRY_LEN
JOURNAL_NAME = "erasures.wtj"
TMP_NAME = "erasures.wtj.tmp"
TAIL_PREFIX = "erasures.wtj.tail-"
APPEND_BUDGET = 5.0                              # singurul fsync permis sub barieră (≤ 97 B)
ATTEST_INTERVAL = 30.0
ATTEST_BACKOFF_MAX = 1800.0
PROVE_INTERVAL = 600.0
FETCH_MAX_OBJECTS = 4                            # câte obiecte (cele mai noi) se încearcă per destinaţie
PROVE_MAX_OBJECTS = 64                           # try_prove: toate obiectele de după restore, cel mult atâtea
REVERIFY_INTERVAL = 3600.0                       # un read-back vechi nu dovedeşte că obiectul mai există azi
KNOWN_MAX = 64                                   # destinaţii ţinute în pragurile unui restore

_OBJ_RE = re.compile(r"^([0-9a-f]{32})\.erasures\.([0-9a-f]{16})(?:\.([0-9a-f]{8,32}))?\.wtj$")
_PLAIN_NAME = re.compile(r"^([0-9a-f]{32})\.(out|cast)$")
_RD = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class JournalError(Exception):
    """A journal that is not what the committed state says (reason = short code)."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class ErasureError(Exception):
    """A refused erasure / recovery action; `code` is the route's error code."""

    def __init__(self, code, detail, status=409):
        super().__init__(detail)
        self.code = code
        self.status = status


class ErasureConflict(ValueError):
    """Two authentic erasure journals that diverge: the restore is refused (`backup.erasureConflict`)."""


class ErasureUnsupported(ValueError):
    """An archive carrying an erasure journal on a build that cannot honour it (`backup.erasureUnsupported`)."""


class DestExists(Exception):
    """An immutable object with this name already exists at the destination."""


@dataclass(frozen=True)
class Entry:
    n: int
    time_ms: int
    sid: bytes
    kinds: int
    rk_hash: bytes
    mac: bytes

    @property
    def sid_hex(self):
        return self.sid.hex()


@dataclass(frozen=True)
class Head:
    n: int
    time_ms: int
    mac: bytes

    def to_json(self):
        return {"n": self.n, "time": self.time_ms, "mac": self.mac.hex()}

    @staticmethod
    def from_json(doc):
        if (type(doc) is not dict or type(doc.get("n")) is not int or doc["n"] < 0
                or type(doc.get("time", 0)) is not int or type(doc.get("mac")) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", doc["mac"])):
            raise JournalError("bad-head", "erasure_head")
        return Head(doc["n"], doc.get("time", 0), bytes.fromhex(doc["mac"]))


EMPTY_HEAD = Head(0, 0, ZERO_MAC)


def reaches(p, t):
    """True when the authentic prefix `p` (Parsed or None) holds the committed head `t` (same n,
    same MAC). An empty threshold is reached by anything, a missing journal by nothing else."""
    if t.n == 0:
        return True
    return p is not None and p.n >= t.n and hmac.compare_digest(p.entries[t.n - 1].mac, t.mac)


def known_from_json(doc):
    """{destination id: n} kept by a restore (staging summary, flag, continuity marker)."""
    if type(doc) is not dict or len(doc) > KNOWN_MAX:
        raise JournalError("bad-known")
    for k, v in doc.items():
        if type(k) is not str or not 0 < len(k) <= 512 or type(v) is not int or v < 0:
            raise JournalError("bad-known")
    return dict(doc)


def merge_known(*sources):
    """Per destination the highest head any source knows it holds (H1/M1: praguri îmbinate)."""
    out = {}
    for src in sources:
        for d, n in (src or {}).items():
            if type(d) is str and type(n) is int and n >= 0:
                out[d] = max(out.get(d, 0), n)
    if len(out) > KNOWN_MAX:
        # fail closed: păstrăm pragurile cele mai mari (obligaţiile n > J* rămân)
        out = dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0]))[:KNOWN_MAX])
    return out


def known_overflow(*sources):
    """R-M2: more destinations than KNOWN_MAX across the sources. `merge_known` keeps the highest
    heads, but a dropped obligation must not let a proof through: the caller refuses the proof."""
    ids = set()
    for src in sources:
        ids |= {d for d in (src or {}) if type(d) is str}
    return len(ids) > KNOWN_MAX


def required_from_json(doc):
    """The destinations a restore without proof made mandatory (R-M2), as a sorted list."""
    if type(doc) is not list or len(doc) > KNOWN_MAX:
        raise JournalError("bad-required")
    for d in doc:
        if type(d) is not str or not 0 < len(d) <= 512:
            raise JournalError("bad-required")
    return sorted(set(doc))


def merge_threshold(*heads):
    """R-H1: the highest committed head of every source (live DB head, the continuity marker of
    the live DB and of the backup's DB, the stage's). Two different MACs at the same n are two
    histories, never a numeric choice → ErasureConflict."""
    seen = {}
    out = EMPTY_HEAD
    for h in heads:
        if h is None or h.n == 0:
            continue
        prev = seen.setdefault(h.n, h.mac)
        if not hmac.compare_digest(prev, h.mac):
            raise ErasureConflict("two erasure heads n=%d with different MACs — refused" % h.n)
        if h.n > out.n:
            out = h
    return out


@dataclass(frozen=True)
class Terms:
    """What a continuity marker obliges a later proof to reach (R-H1/R-M2): the committed
    threshold, the known per-destination heads, the destinations mandatory at the restore, whether
    the known heads overflowed KNOWN_MAX (then nothing proves), and n of the restore."""
    threshold: Head = EMPTY_HEAD
    known: dict = field(default_factory=dict)
    required: tuple = ()
    overflow: bool = False
    n: int = 0


def terms_of(cont):
    """`Terms` of a continuity marker dict; JournalError when it cannot be read."""
    if type(cont) is not dict:
        raise JournalError("bad-state", "continuity")
    t = Head.from_json(cont["threshold"]) if "threshold" in cont else EMPTY_HEAD
    known = known_from_json(cont.get("known", {}))
    req = tuple(required_from_json(cont.get("required", [])))
    ovf = cont.get("overflow", False)
    r_n = cont.get("n", 0)
    if type(ovf) is not bool or type(r_n) is not int or r_n < 0:
        raise JournalError("bad-state", "continuity")
    return Terms(t, known, req, ovf, r_n)


def marker_terms_in(db_path):
    """`Terms` of the unproven continuity marker kept in the database at `db_path` (a live DB or a
    backup's staged copy), None when there is none. A marker that cannot be read → JournalError
    (the caller refuses / proves nothing): R-H1, the threshold of an earlier restore survives every
    later restore, backup and re-import because each of them reads it here."""
    con = sqlite3.connect(pathlib_uri(db_path), uri=True)
    try:
        try:
            row = con.execute("SELECT value FROM tx_state WHERE key='continuity'").fetchone()
        except sqlite3.OperationalError:
            return None
    finally:
        con.close()
    if row is None:
        return None
    try:
        cont = json.loads(row[0])
    except ValueError:
        raise JournalError("bad-state", "continuity") from None
    if type(cont) is not dict:
        raise JournalError("bad-state", "continuity")
    if cont.get("state") != "unproven":
        return None
    return terms_of(cont)


@dataclass(frozen=True)
class Live:
    """What the LIVE volume's database says about the dataset being restored (H1): `state` =
    same (same installation, erasure state readable) | foreign (another installation: nothing
    of it applies) | none (no database) | bad (unreadable: no threshold known → no proof).
    R-H1: `head` is the merged threshold (the committed head AND the continuity marker's threshold
    of an earlier restore without proof), `required` / `overflow` come from that marker."""
    state: str
    head: Head = EMPTY_HEAD
    attested: dict = field(default_factory=dict)
    required: frozenset = frozenset()
    overflow: bool = False


def live_state(db_path, live_inst, inst):
    """`Live` of the database at `db_path` for installation `inst`, when the live keyring is
    `live_inst`. Read BEFORE the live journal: an erasure appends the journal before it commits
    the head, so a journal read afterwards is never behind the head read here. Two different
    MACs at the same n (head vs marker) → ErasureConflict."""
    if live_inst is None or not hmac.compare_digest(bytes(live_inst), bytes(inst)):
        return Live("foreign")
    if not os.path.exists(str(db_path)):
        return Live("none")
    try:
        head, att, _ids = staged_state(db_path)
        terms = marker_terms_in(db_path) or Terms()
    except (JournalError, sqlite3.Error, OSError):
        return Live("bad")
    known = {d: v["n"] for d, v in att.items()
             if type(d) is str and isinstance(v, dict) and type(v.get("n")) is int and v["n"] >= 0}
    return Live("same", merge_threshold(head, terms.threshold), merge_known(known, terms.known),
                frozenset(terms.required), terms.overflow or known_overflow(known, terms.known))


@dataclass
class Parsed:
    inst: bytes
    entries: list
    valid_len: int                 # octeţi până la ultima intrare autentică inclusiv
    total_len: int
    bad: str = ""                  # '' | gap | bad-kinds | bad-mac | partial

    @property
    def head(self):
        if not self.entries:
            return EMPTY_HEAD
        e = self.entries[-1]
        return Head(e.n, e.time_ms, e.mac)

    @property
    def n(self):
        return len(self.entries)


def header(inst):
    if not isinstance(inst, (bytes, bytearray)) or len(inst) != 16:
        raise JournalError("bad-installation")
    return MAGIC + bytes([VERSION]) + b"\x00\x00\x00" + bytes(inst)


def entry_mac(k_erase, inst, prev_mac, body):
    return hmac.new(k_erase, MAC_DOMAIN + bytes(inst) + prev_mac + body, hashlib.sha256).digest()


def encode_entry(k_erase, inst, prev_mac, n, time_ms, sid, kinds, rk_hash):
    if kinds not in (KINDS_OUT, KINDS_CAST, KINDS_BOTH):
        raise JournalError("bad-kinds")
    if len(sid) != 16 or len(rk_hash) != 32 or len(prev_mac) != MAC_LEN or n < 1:
        raise JournalError("bad-entry")
    body = _BODY.pack(n, time_ms, bytes(sid), kinds, bytes(rk_hash))
    return body + entry_mac(k_erase, inst, prev_mac, body)


def parse(data, k_erase, inst=None):
    """The authentic prefix of a journal. A bad header (or another installation's journal when
    `inst` is given) raises JournalError; a bad entry stops the prefix (`bad` says why)."""
    data = bytes(data)
    if len(data) < HDR_LEN:
        raise JournalError("short-header")
    if data[:4] != MAGIC or data[4] != VERSION or data[5:8] != b"\x00\x00\x00":
        raise JournalError("bad-header")
    hinst = data[8:24]
    if inst is not None and not hmac.compare_digest(hinst, bytes(inst)):
        raise JournalError("foreign")
    if len(data) > MAX_FILE + ENTRY_LEN:
        raise JournalError("too-large")
    entries = []
    prev = ZERO_MAC
    off = HDR_LEN
    bad = ""
    while off + ENTRY_LEN <= len(data):
        chunk = data[off:off + ENTRY_LEN]
        body, mac = chunk[:-MAC_LEN], chunk[-MAC_LEN:]
        n, t, sid, kinds, rk_hash = _BODY.unpack(body)
        if n != len(entries) + 1:
            bad = "gap"
            break
        if kinds not in (KINDS_OUT, KINDS_CAST, KINDS_BOTH):
            bad = "bad-kinds"
            break
        if not hmac.compare_digest(mac, entry_mac(k_erase, hinst, prev, body)):
            bad = "bad-mac"
            break
        entries.append(Entry(n, t, sid, kinds, rk_hash, mac))
        prev = mac
        off += ENTRY_LEN
    if not bad and off < len(data):
        bad = "partial"
    return Parsed(hinst, entries, off, len(data), bad)


def prefix_len(n):
    return HDR_LEN + n * ENTRY_LEN


def kinds_bits(kinds):
    b = (KINDS_OUT if "out" in kinds else 0) | (KINDS_CAST if "cast" in kinds else 0)
    return b or KINDS_BOTH          # fără descriptor (doar RK): ambele, conservator


# ── journal file ─────────────────────────────────────────────────────────────


def _fsync_dir(dfd):
    os.fsync(dfd)


class Journal:
    """`<data_dir>/erasures.wtj`, through a directory fd (no symlink followed)."""

    def __init__(self, data_dir, k_erase, inst):
        self.dir = str(data_dir)
        self.k = k_erase
        self.inst = bytes(inst)

    def _dfd(self):
        return os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def read_bytes(self):
        """The file's bytes, or None when it does not exist. Not a regular single-link file, or
        over the cap → JournalError (never read as absent)."""
        dfd = self._dfd()
        try:
            try:
                fd = os.open(JOURNAL_NAME, _RD, dir_fd=dfd)
            except FileNotFoundError:
                return None
            except OSError as e:
                raise JournalError("unreadable", e.strerror or "") from None
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise JournalError("not-regular")
                if st.st_size > MAX_FILE + ENTRY_LEN:
                    raise JournalError("too-large")
                out = bytearray()
                while True:
                    b = os.read(fd, 1 << 20)
                    if not b:
                        break
                    out += b
                    if len(out) > MAX_FILE + ENTRY_LEN:
                        raise JournalError("too-large")
                return bytes(out)
            finally:
                os.close(fd)
        finally:
            os.close(dfd)

    def create(self):
        """Header-only journal: O_EXCL, fsync, directory fsync."""
        dfd = self._dfd()
        try:
            fd = os.open(JOURNAL_NAME, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=dfd)
            try:
                _write_all(fd, header(self.inst))
                os.fsync(fd)
            finally:
                os.close(fd)
            _fsync_dir(dfd)
        finally:
            os.close(dfd)

    def append(self, entry, expect_len, fault=None):
        """One entry, appended O_APPEND + fsync, only if the file still has `expect_len` bytes."""
        dfd = self._dfd()
        try:
            fd = os.open(JOURNAL_NAME, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        finally:
            os.close(dfd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size != expect_len:
                raise JournalError("length-changed", f"{st.st_size} != {expect_len}")
            _write_all(fd, entry)
            if fault is not None:
                fault("journal-written")
            os.fsync(fd)
        finally:
            os.close(fd)

    def replace(self, data):
        """The whole journal replaced atomically (tail repair, restore apply): tmp O_EXCL → fsync →
        rename → directory fsync."""
        dfd = self._dfd()
        try:
            try:
                os.unlink(TMP_NAME, dir_fd=dfd)
            except FileNotFoundError:
                pass
            fd = os.open(TMP_NAME, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=dfd)
            try:
                _write_all(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(TMP_NAME, JOURNAL_NAME, src_dir_fd=dfd, dst_dir_fd=dfd)
            _fsync_dir(dfd)
        finally:
            os.close(dfd)

    def repair_tail(self, data, keep_len, now_ms):
        """Bytes after the last authentic entry (beyond the committed head): the prefix becomes the
        journal, the cut bytes are kept for diagnosis."""
        dfd = self._dfd()
        try:
            name = f"{TAIL_PREFIX}{now_ms}"
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=dfd)
            try:
                _write_all(fd, data[keep_len:])
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(dfd)
        self.replace(data[:keep_len])
        return name


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


# ── process state ────────────────────────────────────────────────────────────


@dataclass
class _State:
    journal: Journal = None
    parsed: Parsed = None          # starea curentă a jurnalului (prefixul autentic)
    head_db: Head = EMPTY_HEAD     # capul comis în DB (tx_state.erasure_head)
    diag: str = ""                 # '' | missing | rollback | fork | prefix | foreign | …
    uncertain: str = ""            # o adăugare al cărei rezultat nu se ştie: refuz până la boot
    attested: dict = field(default_factory=dict)      # dest id → {n, time, name}
    dests: dict = field(default_factory=dict)         # dest id → {state, since, error, next}
    rolled_back: set = field(default_factory=set)
    dest_ids: list = None          # ultimele destinaţii configurate văzute (None = încă necunoscut)
    conflict: str = ""
    continuity: dict = None        # {state: unproven, since, n} | None
    booted: bool = False
    quarantine_pass: bool = False
    task: object = None
    store: object = None
    wake: object = None


_s = _State()
_dest_provider = None


def reset():
    """Tests / shutdown: forget the process state (the files and rows stay)."""
    global _s
    t = _s.task
    if t is not None:
        t.cancel()
    _s = _State()


def active():
    return _s.booted and _s.store is not None


def journal_ready() -> bool:
    """§12.11 PR5/PR6 gate: the journal was verified against the committed head at this boot (a
    broken journal is 'ready' once every recording is quarantined: the volume is in a safe state)."""
    return _s.booted and (_s.parsed is not None or bool(_s.diag))


def quarantine_ready() -> bool:
    return _s.booted and _s.quarantine_pass


def continuity():
    """The restore-without-proof marker ({state, since, n}) or None."""
    c = _s.continuity
    return dict(c) if c and c.get("state") == "unproven" else None


def set_destinations(fn) -> None:
    """`fn()` (async) → the configured off-host destinations (objects with `id`, `refuses_overwrite`,
    `put_new`, `list`, `get`). Registered by txhub at boot; None = no destination."""
    global _dest_provider
    _dest_provider = fn


async def destinations():
    if _dest_provider is None:
        return []
    try:
        return list(await _dest_provider())
    except Exception as e:                       # noqa: BLE001 — o destinaţie neconfigurabilă = nicio dovadă
        log.warning("erasure: destinations unavailable: %s", type(e).__name__)
        return []


def k_erase_of(kwk):
    return keyring.erase_key(kwk)


# ── DB helpers (all through the Store) ───────────────────────────────────────


def _get_json(c, key):
    row = c.execute("SELECT value FROM tx_state WHERE key=?", (key,)).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row[0])
    except ValueError:
        raise JournalError("bad-state", key) from None


def _set_json(c, key, value):
    c.execute("INSERT INTO tx_state(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET "
              "value=excluded.value", (key, json.dumps(value, sort_keys=True, separators=(",", ":"))))


def _destroy_sync(c, sid, head=None):
    """Erasure step 2 for one sid, inside the caller's transaction: live share and replay links
    revoked, RK destroyed, descriptors and gaps gone, generations → retired, head advanced
    (monotonic). Returns the generations to retire."""
    c.execute("UPDATE sessions SET share_token=NULL, share_expires=NULL, share_writable=0 WHERE id=?", (sid,))
    c.execute("DELETE FROM replay_opens WHERE link_id IN (SELECT id FROM replay_links WHERE sid=?)", (sid,))
    c.execute("DELETE FROM replay_links WHERE sid=?", (sid,))
    gens = c.execute("SELECT gen_id, kind FROM tx_files WHERE sid=? AND state='published'", (sid,)).fetchall()
    c.execute("UPDATE tx_files SET state='retired' WHERE sid=? AND state='published'", (sid,))
    c.execute("DELETE FROM session_keys WHERE sid=?", (sid,))
    c.execute("DELETE FROM tx_descriptors WHERE sid=?", (sid,))
    c.execute("DELETE FROM tx_gaps WHERE sid=?", (sid,))
    c.execute("DELETE FROM tx_quarantine WHERE sid=?", (sid,))
    if head is not None:
        cur = _get_json(c, "erasure_head")
        if cur is None or Head.from_json(cur).n < head.n:
            _set_json(c, "erasure_head", head.to_json())
    return [(g[0], g[1]) for g in gens]


async def _read_state(st):
    def load(c):
        return (_get_json(c, "erasure_head"), _get_json(c, "attested_heads"), _get_json(c, "continuity"))
    return await st.read(load)


# ── boot (§12.11.4 "Every boot") ─────────────────────────────────────────────


@dataclass
class BootReport:
    diag: str = ""
    reapplied: list = field(default_factory=list)
    destroyed: list = field(default_factory=list)
    tail: str = ""
    quarantined: int = 0
    created: bool = False


async def boot(st, data_dir=None, clock=time.time):
    """After keyring, restore apply and schema, before `Store.recover()` and before any reader."""
    reset()
    s = _s
    s.store = st
    k = k_erase_of(st.kwk)
    j = s.journal = Journal(config.DATA_DIR if data_dir is None else data_dir, k, st.inst)
    rep = BootReport()
    try:
        head_doc, att, cont = await _read_state(st)
        head = Head.from_json(head_doc) if head_doc is not None else EMPTY_HEAD
    except JournalError as e:
        head, att, cont = None, None, None
        rep.diag = "db-" + e.reason
    s.head_db = head or EMPTY_HEAD
    s.attested = att if isinstance(att, dict) else {}
    s.continuity = cont if isinstance(cont, dict) else None
    parsed = None
    data = None
    if not rep.diag:
        try:
            data = await st.io(j.read_bytes)
        except (JournalError, OSError) as e:
            rep.diag = getattr(e, "reason", "unreadable")
    if not rep.diag:
        if data is None or (len(data) < HDR_LEN and head.n == 0 and header(st.inst).startswith(data)):
            if head.n > 0:
                rep.diag = "missing"
            else:
                # nimic comis: un jurnal absent (sau o creare întreruptă înainte de antet) se (re)face
                if data is not None:
                    await st.io(j.replace, header(st.inst))
                else:
                    await st.io(j.create)
                rep.created = True
                parsed = parse(header(st.inst), k, st.inst)
        else:
            try:
                parsed = parse(data, k, st.inst)
            except JournalError as e:
                rep.diag = e.reason
    if parsed is not None and not rep.diag:
        m = parsed.n
        if m < head.n:
            rep.diag = "prefix" if parsed.bad else "rollback"
        elif head.n > 0 and not hmac.compare_digest(parsed.entries[head.n - 1].mac, head.mac):
            rep.diag = "fork"
        elif parsed.bad:
            # octeţi după ultima intrare autentică, toţi DUPĂ capul comis: crash în pasul 1
            rep.tail = await st.io(j.repair_tail, data, parsed.valid_len, int(clock() * 1000))
            st.alarm("transcript.erasureTail", f"journal tail cut after n={m} ({parsed.bad}), kept as {rep.tail}")
            parsed = parse(data[:parsed.valid_len], k, st.inst)
    now = clock()
    if rep.diag:
        s.diag = rep.diag
        # fail closed: tot ce se poate autentifica rămâne şters; restul înregistrărilor în carantină
        if parsed is not None:
            st.tombstoned.update(e.sid_hex for e in parsed.entries)
        # R-H2: aceeaşi cohortă ca la restore (descriptori, rânduri de migrare care încă deţin text
        # clar, fişiere cu nume 3.7), cu motivul `journal:*` (păstrat la conversie, niciodată
        # recuperabil de Owner): textul clar pending nu trece de cititor
        plain = await st.io(_plain_cohort_fd, st.dir_fd)
        rep.quarantined = await st.txn(lambda c: _quarantine_cohort_sync(c, "journal:" + rep.diag, now, plain))
        st.bump(None)
        st.alarm("transcript.erasureJournal", f"erasure journal {rep.diag}: every recording quarantined")
        s.parsed = None
    else:
        s.parsed = parsed
        sids = {e.sid_hex for e in parsed.entries}
        st.tombstoned.update(sids)
        for sid in sids:
            st.drop_key(sid)
        # jurnal înaintea DB-ului (crash după pasul 1): paşii 2–3 pentru intrările lipsă
        for e in parsed.entries[head.n:]:
            await st.txn(lambda c, e=e: _destroy_sync(c, e.sid_hex, Head(e.n, e.time_ms, e.mac)))
            rep.reapplied.append(e.n)
        s.head_db = parsed.head
        # orice sid şters care încă are o cheie sau un descriptor (un restore) → distrus la fel
        left = await st.read(lambda c: sorted(
            {r[0] for r in c.execute("SELECT sid FROM session_keys").fetchall()}
            | {r[0] for r in c.execute("SELECT sid FROM tx_descriptors").fetchall()}) )
        for sid in left:
            if sid in sids:
                await st.txn(lambda c, sid=sid: _destroy_sync(c, sid))
                rep.destroyed.append(sid)
    # carantina de continuitate (restore fără dovadă): ce a marcat restore-ul rămâne în carantină
    if s.continuity and s.continuity.get("state") == "unproven":
        st.alarm("transcript.erasureUnproven", "erasures after %s cannot be proven" % s.continuity.get("since"))
    s.quarantine_pass = True
    s.booted = True
    return rep


# ── erase (§12.11.4 "Order of erase(sid)") ───────────────────────────────────


async def _journal_and_destroy(st, sid, kinds, env, clock):
    """Erasure steps 1–2 for `sid` (caller holds its lease AND the barrier): one journal entry
    (fsync within APPEND_BUDGET), the in-memory tombstone, then `_destroy_sync` in one transaction.
    → (n, generations to retire). Shared by `erase` and the Owner's discard of a failed migration."""
    s = _s
    if s.parsed.n >= CAP:
        raise ErasureError("transcript.erasureJournalFull",
                           "the erasure journal is full; erasure is refused until compaction", 507)
    prev = s.parsed.head
    n = prev.n + 1
    t_ms = int(clock() * 1000)
    rk_hash = keyring.envelope_hash(bytes(env[0])) if env is not None else b"\x00" * 32
    entry = encode_entry(s.journal.k, st.inst, prev.mac, n, t_ms, bytes.fromhex(sid),
                         kinds_bits(kinds), rk_hash)
    fut = asyncio.ensure_future(st.io(s.journal.append, entry, prefix_len(prev.n), st._fault))
    try:
        await asyncio.wait_for(asyncio.shield(fut), APPEND_BUDGET)
    except asyncio.TimeoutError:
        # rezultatul se decide din fişier la boot; până atunci sid-ul nu mai e servit
        s.uncertain = "append-timeout"
        st.tombstone(sid)
        st.alarm("transcript.erasureUncertain", f"{sid}: journal fsync over budget")
        raise ErasureError("transcript.erasureUncertain",
                           "the erasure journal did not answer in time; restart the gateway", 503)
    except BaseException as e:
        s.uncertain = "append-failed"
        st.tombstone(sid)
        st.alarm("transcript.erasureUncertain", f"{sid}: journal append failed: {type(e).__name__}")
        if isinstance(e, Exception):
            raise ErasureError("transcript.erasureUncertain",
                               "the erasure journal could not be written; restart the gateway",
                               503) from None
        raise
    # durabil: în ACEEAŞI secţiune sincronă, înainte de a elibera bariera
    e = Entry(n, t_ms, bytes.fromhex(sid), kinds_bits(kinds), rk_hash, entry[-MAC_LEN:])
    s.parsed = Parsed(s.parsed.inst, s.parsed.entries + [e], prefix_len(n), prefix_len(n))
    st.tombstone(sid)
    st._fault("erase-appended")
    try:
        gens = await st.io(st._run_txn, lambda c: _destroy_sync(c, sid, Head(n, t_ms, e.mac)))
    except txstore.Uncertain:
        gens = None
    except Exception as x:
        # tombstone-ul e durabil, pasul 2 nu: boot-ul îl re-aplică; până atunci, refuz
        s.uncertain = "commit-failed"
        st.alarm("transcript.erasureUncertain", f"{sid}: step 2 failed: {type(x).__name__}")
        raise ErasureError("transcript.erasureUncertain",
                           "the erasure was journalled but not completed; restart the gateway",
                           503) from None
    confirmed = gens is not None
    if not confirmed:
        # Observaţie PR6: COMMIT incert = durabil în jurnal, distrugerea în DB neconfirmată; boot-ul
        # o re-aplică. Ruta spune asta explicit (nu „distrus").
        gens = []
        s.uncertain = "commit-uncertain"
    elif s.head_db.n < n:
        s.head_db = Head(n, t_ms, e.mac)
    st._fault("erase-committed")
    return n, gens, confirmed


async def erase(st, sid, *, clock=time.time):
    """Steps 1–3; step 4 (attestation) is the janitor's. Returns {erased, n, attested}."""
    _ready_or_raise(st, sid)
    # PR6b (§12.11.5): o înregistrare încă în clar se migrează întâi (textul clar dispare prin
    # unlink-ul verificat), apoi ştergerea normală distruge RK-ul. Ce nu se poate migra rămâne
    # refuzat mai jos (transcript.erasePlaintext): niciodată „şters" cu textul clar pe disc.
    await migration.before_erase(st, sid)
    async with st.lease(sid):
        async with st.barrier:
            if sid in st.tombstoned:
                raise ErasureError("transcript.missing", "no recording for this session", 404)

            def load(c):
                return (c.execute("SELECT envelope FROM session_keys WHERE sid=?", (sid,)).fetchone(),
                        [r[0] for r in c.execute("SELECT kind FROM tx_descriptors WHERE sid=?",
                                                 (sid,)).fetchall()],
                        c.execute("SELECT 1 FROM tx_migration WHERE sid=? AND state IN "
                                  "('pending','orphan','failed','converted')", (sid,)).fetchone())
            env, kinds, plain = await st.read(load)
            if plain is not None:
                # textul clar e încă pe disc (nemigrat, eşuat, sau convertit dar neşters): refuz
                raise ErasureError("transcript.erasePlaintext",
                                   "this recording is not migrated yet; it cannot be erased", 409)
            if env is None and not kinds:
                raise ErasureError("transcript.missing", "no recording for this session", 404)
            n, gens, confirmed = await _journal_and_destroy(st, sid, kinds, env, clock)
        for hexid, kind in gens:
            await st.retire(sid, kind, hexid)
    _kick()
    return {"erased": True, "n": n, "state": "destroyed" if confirmed else "journalled",
            "attested": await attested_everywhere(n)}


def _ready_or_raise(st, sid):
    s = _s
    if not s.booted or s.store is not st:
        raise ErasureError("transcript.erasureUnavailable", "the erasure journal is not ready", 503)
    if s.diag or s.parsed is None:
        raise ErasureError("transcript.erasureJournalBroken",
                           "the erasure journal is damaged (%s); erasure is refused" % (s.diag or "?"), 503)
    if s.uncertain:
        raise ErasureError("transcript.erasureUncertain",
                           "an earlier erasure did not finish; restart the gateway first", 503)
    if _behind():
        # R-M1: o intrare nouă ar fi a doua intrare n+1 lângă una comisă pe care n-o vedem: un fork
        # pe care nicio dovadă nu-l mai poate rezolva. Refuz până la dovada continuităţii.
        raise ErasureError("transcript.erasureBehind",
                           "erasures committed before the last restore are not on this volume yet; "
                           "erasure is refused until they are proven", 409)
    txstore._sid_bytes(sid)
    rec = st.recorders.get(sid)
    if sid in st._starting or (rec is not None and rec.state not in ("closed", "lost", "replaced")):
        raise ErasureError("session.live", "the session is live; close it first", 409)


async def discard_failed(st, sid, *, clock=time.time):
    """Owner discard of a failed plaintext migration (PR6c, owner decision): the failed rows are
    re-inventoried from the files now under their names (→ `pending`, so the boot's crash rule
    drops them if we die after the journal entry), ONE journal entry tombstones the sid (any kind
    it already has encrypted goes with it: a discard is an erasure), then the plaintext goes
    through the migration's identity-checked unlink (row → `unlinked`, error `erased`). The session
    must be closed: a tombstoned sid cannot record again. Returns {discarded, n, attested, kinds}."""
    _ready_or_raise(st, sid)
    async with st.lease(sid):
        rows = await migration.failed_rows(st, sid)
        if not rows:
            raise ErasureError("transcript.notFailed", "no failed migration for this session", 409)
        if sid in st.tombstoned:
            raise ErasureError("transcript.missing", "no recording for this session", 404)
        await migration.rebind_failed(st, sid, rows, state="pending")
        async with st.barrier:
            def load(c):
                return (c.execute("SELECT envelope FROM session_keys WHERE sid=?", (sid,)).fetchone(),
                        [r[0] for r in c.execute("SELECT kind FROM tx_descriptors WHERE sid=?",
                                                 (sid,)).fetchall()])
            env, kinds = await st.read(load)
            kinds = sorted(set(kinds) | {r["kind"] for r in rows})
            n, gens, confirmed = await _journal_and_destroy(st, sid, kinds, env, clock)
        for hexid, kind in gens:
            await st.retire(sid, kind, hexid)
        left = {}
        for r in await migration._rows(st, sid):
            if r["state"] in migration.WORK_STATES:
                left[r["kind"]] = await migration._drop_erased(st, r)
        # Observaţie PR6: rezultatul FIZIC al textului clar, per kind, distinct de tombstone:
        # unlinked (ştergere verificată) | absent (nu mai era nici sub nume, nici sub un nume privat)
        # | kept (amânat: pin de backup / fără renameat2) | failed (identitate schimbată: rămâne pe disc)
        plain = {r["kind"]: migration.physical_outcome(r) for r in await migration._rows(st, sid)
                 if r["kind"] in left}
    _kick()
    return {"discarded": True, "n": n, "state": "destroyed" if confirmed else "journalled",
            "attested": await attested_everywhere(n), "kinds": left, "plaintext": plain}


async def attested_everywhere(n):
    """True when every configured destination holds a head ≥ n (no destination → False)."""
    ds = await destinations()
    return bool(ds) and all(_s.attested.get(d.id, {}).get("n", 0) >= n
                            and (_s.dests.get(d.id) or {}).get("state") != "missing" for d in ds)


def _kick():
    if _s.wake is not None:
        _s.wake.set()


# ── attestation (§12.11.4 step 4) ────────────────────────────────────────────


def object_name(inst, n, nonce=None):
    base = "%s.erasures.%016x" % (bytes(inst).hex(), n)
    return base + ("." + nonce if nonce else "") + ".wtj"


def parse_object_name(name):
    m = _OBJ_RE.match(name or "")
    if not m:
        return None
    return bytes.fromhex(m.group(1)), int(m.group(2), 16)


async def _commit_attested(st, dest_id, head, name, *, again=False):
    def fn(c):
        cur = _get_json(c, "attested_heads") or {}
        if not isinstance(cur, dict):
            cur = {}
        old = cur.get(dest_id, {}).get("n", -1)
        # `again`: acelaşi cap, încărcat din nou după ce obiectul a dispărut (numele se schimbă)
        if old < head.n or (again and old == head.n):
            cur[dest_id] = {"n": head.n, "time": head.time_ms, "name": name}
            _set_json(c, "attested_heads", cur)
        return cur
    return await st.txn(fn)


async def attest_once(st=None, dests=None, clock=time.time):
    """Upload the journal (up to the committed head) to every destination that does not hold it,
    read it back and authenticate it. Returns {dest id: state}."""
    s = _s
    st = st or s.store
    if st is None or s.parsed is None or s.diag:
        return {}
    dests = await destinations() if dests is None else dests
    s.dest_ids = [d.id for d in dests]
    head = s.parsed.head
    if head.n > s.head_db.n:
        head = s.head_db
    out = {}
    data = None
    for d in dests:
        rec = s.attested.get(d.id)
        again = False
        if head.n == 0 or (rec and rec.get("n", 0) >= head.n):
            info = s.dests.get(d.id) or {}
            # M1: un read-back reuşit cândva nu dovedeşte că obiectul mai există azi: din oră în
            # oră lista destinaţiei trebuie să-l mai conţină, altfel se încarcă din nou
            if head.n and rec and rec.get("name") and info.get("verified", 0) + REVERIFY_INTERVAL <= clock():
                try:
                    present = rec["name"] in set(await d.list())
                except Exception as e:           # noqa: BLE001 — inaccesibilă: nu ştim, nu stricăm starea
                    log.warning("erasure: cannot re-check %s: %s", d.id, type(e).__name__)
                    present = None
                if present is True:
                    s.dests[d.id] = dict(info, state="ok", verified=clock())
                elif present is False:
                    log.warning("erasure n=%d: the attested object vanished from %s", rec.get("n", 0), d.id)
                    s.dests[d.id] = {"state": "missing", "since": clock(), "error": "object-missing",
                                     "next": 0, "tries": 0, "verified": 0}
            if (s.dests.get(d.id) or {}).get("state") != "missing":
                out[d.id] = "ok"
                continue
            again = rec is not None and rec.get("n", 0) == head.n
        info = s.dests.get(d.id) or {}
        if info.get("next", 0) > clock():
            out[d.id] = info.get("state", "failing")
            continue
        try:
            if data is None:
                raw = await st.io(s.journal.read_bytes)
                if raw is None or len(raw) < prefix_len(head.n):
                    raise JournalError("missing")
                data = raw[:prefix_len(head.n)]
                p = parse(data, s.journal.k, st.inst)
                if p.n != head.n or not hmac.compare_digest(p.head.mac, head.mac) or p.bad:
                    raise JournalError("mismatch")
            name = object_name(st.inst, head.n, None if d.refuses_overwrite else secrets.token_hex(4))
            try:
                await d.put_new(name, data)
            except DestExists:
                pass                              # imuabil: citirea înapoi decide
            back = await d.get(name)
            if not hmac.compare_digest(bytes(back), data):
                raise JournalError("readback-mismatch")
            p = parse(back, s.journal.k, st.inst)
            if p.n != head.n or p.bad or not hmac.compare_digest(p.head.mac, head.mac):
                raise JournalError("readback-unauthentic")
            s.attested = await _commit_attested(st, d.id, head, name, again=again)
            s.dests[d.id] = {"state": "ok", "since": None, "error": "", "next": 0, "tries": 0,
                             "verified": clock()}
            out[d.id] = "ok"
        except Exception as e:                   # noqa: BLE001 — o destinaţie căzută nu opreşte celelalte
            prevs = s.dests.get(d.id) or {}
            tries = prevs.get("tries", 0) + 1
            since = prevs.get("since") or clock()
            delay = min(ATTEST_BACKOFF_MAX, ATTEST_INTERVAL * (2 ** min(tries, 6)))
            err = getattr(e, "reason", "") or type(e).__name__
            keep = "missing" if prevs.get("state") == "missing" else "failing"
            s.dests[d.id] = {"state": keep, "since": since, "error": err, "next": clock() + delay,
                             "tries": tries, "n": head.n, "verified": 0}
            out[d.id] = keep
            log.warning("erasure n=%d not attested on %s: %s", head.n, d.id, err)
    return out


async def fetch_head(d, k_erase, inst, check_from=None):
    """The newest authentic journal a destination holds for `inst`: (Parsed, bytes) or None when it
    holds none; raises on an unreachable destination. Objects are tried newest first.

    `check_from` (try_prove, H3/M1): EVERY object named above that n is read (at most
    PROVE_MAX_OBJECTS, else JournalError) and all the authentic ones must lie on one chain
    (ErasureConflict otherwise): after a restore our own uploads can be newer than the
    attestation of the dataset we were restored from, and a fork with it must not hide."""
    names = []
    for n in await d.list():
        p = parse_object_name(n)
        if p is not None and p[0] == bytes(inst):
            names.append((p[1], n))
    names.sort(reverse=True)
    if check_from is None:
        for _n, name in names[:FETCH_MAX_OBJECTS]:
            try:
                raw = bytes(await d.get(name))
                p = parse(raw, k_erase, inst)
            except JournalError:
                continue
            if p.bad or p.n != _n:
                continue                              # neautentic sau nume minţit: nu e dovadă
            return p, raw[:p.valid_len]
        return None
    above = [x for x in names if x[0] > check_from]
    if len(above) > PROVE_MAX_OBJECTS:
        raise JournalError("too-many", "too many journal objects to check")
    pick = above + [x for x in names if x[0] <= check_from][:FETCH_MAX_OBJECTS]
    got = []
    for _n, name in pick:
        try:
            raw = bytes(await d.get(name))
            p = parse(raw, k_erase, inst)
        except JournalError:
            continue
        if p.bad or p.n != _n:
            continue
        got.append((name, p, raw[:p.valid_len]))
    if not got:
        return None
    best = _on_one_chain([(name, p) for name, p, _raw in got])
    return next((p, raw) for name, p, raw in got if name == best[0])


@dataclass
class DestResult:
    id: str
    ok: bool                       # a răspuns (nimic sau un jurnal autentic)
    parsed: Parsed = None          # None = niciun jurnal autentic: o destinaţie GOALĂ nu e dovadă (M1)
    data: bytes = None
    error: str = ""


async def fetch_all(dests, k_erase, inst, check_from=None):
    out = []
    for d in dests:
        try:
            got = await fetch_head(d, k_erase, inst, check_from)
            out.append(DestResult(d.id, True, got[0] if got else None, got[1] if got else None))
        except ErasureConflict:
            out.append(DestResult(d.id, False, error="conflict"))
        except Exception as e:                   # noqa: BLE001 — inaccesibilă = fără dovadă
            out.append(DestResult(d.id, False, error=getattr(e, "reason", "") or type(e).__name__))
    return out


def sync_fetcher(loop, dests, timeout=120.0):
    """For the restore staging thread: `fetch(k_erase, inst)` runs `fetch_all` on the gateway's
    loop and waits (bounded). Returns (results, destination ids)."""
    ids = [d.id for d in dests]

    def fetch(k_erase, inst):
        fut = asyncio.run_coroutine_threadsafe(fetch_all(dests, k_erase, inst), loop)
        try:
            return fut.result(timeout), ids
        except Exception:                        # noqa: BLE001 — timeout = fără dovadă
            fut.cancel()
            return [DestResult(i, False, error="timeout") for i in ids], ids
    return fetch


# ── freshness (§12.11.4 "Freshness", "Continuity at restore") ────────────────


def _on_one_chain(cands):
    """cands: [(label, Parsed)] all authentic. The longest, if every other is its prefix; two that
    differ at the same n → ErasureConflict."""
    best = None
    for _label, p in cands:
        if best is None or p.n > best[1].n:
            best = (_label, p)
    for label, p in cands:
        if p.n and not hmac.compare_digest(p.entries[p.n - 1].mac, best[1].entries[p.n - 1].mac):
            raise ErasureConflict("two erasure journals diverge (%s vs %s) — refused" % (label, best[0]))
    return best


@dataclass
class Decision:
    state: str                      # not-tracked | proven | unproven
    proof: str                      # volume | destinations | none
    journal: bytes = None           # J* (None = nothing to publish)
    head: Head = EMPTY_HEAD
    rolled_back: list = field(default_factory=list)
    unreachable: list = field(default_factory=list)
    threshold: Head = EMPTY_HEAD    # capul comis al volumului viu (aceeaşi instalare): J* trebuie să-l atingă
    known: dict = field(default_factory=dict)       # destinaţie → cap cunoscut (toate sursele + ce s-a văzut)
    short: bool = False             # sursele NU ating pragul cunoscut (H1): fără dovadă
    required: list = field(default_factory=list)    # R-M2: destinaţiile obligatorii, păstrate în marker
    overflow: bool = False          # R-M2: prea multe capete cunoscute: nicio dovadă

    def summary(self, since):
        return {"state": self.state, "proof": self.proof, "since": int(since or 0), "n": self.head.n,
                "threshold": self.threshold.to_json(), "known": dict(self.known),
                "required": list(self.required), "overflow": bool(self.overflow)}


def decide_restore(*, k_erase, inst, j_b=None, tracked=False, j_v=None, dest_results=(),
                   required_dests=(), known_attested=None, live=None, mode="stage", staged=None):
    """The restore's erasure decision. `j_b` = the backup's journal bytes (already checked against
    its manifest), `j_v` = the live volume journal bytes (None = absent), `dest_results` =
    `DestResult`s, `required_dests` = every destination id that must answer for a proof (configured
    in the staged DB, on this host, or named by any attested head), `known_attested` = {dest id: n}
    merged from every source, `live` = `Live` of the live database (read BEFORE `j_v`).
    Raises ErasureConflict on divergent authentic journals.

    H1: the live committed head (number + MAC) is the threshold: J_v proves only when it holds
    it (a shorter journal, a damaged committed entry or a fork never does; bytes after the head
    are a crash tail, as at boot), and when no source reaches it there is no proof at all.
    M1: a destination proves only with an authentic head (an empty listing never does) that
    reaches max(its known head, the threshold) — at stage at least n = 1; when proving later
    (`mode="prove"`) only a threshold known at the restore counts (our own uploads made after the
    restore prove nothing).
    R-H1: `staged` = the `Terms` of the backup's own continuity marker (a dataset backed up while
    in quarantine): its threshold, known heads and mandatory destinations are merged in, so a
    re-import never lowers what an earlier restore must still reach. R-M2: the mandatory set is
    kept (`required`), and an overflow of known heads proves nothing."""
    live = live if live is not None else Live("none")
    staged = staged if staged is not None else Terms()
    same = live.state == "same"
    known = merge_known(known_attested, live.attested if same else None, staged.known)
    overflow = (staged.overflow or (same and live.overflow)
                or known_overflow(known_attested, live.attested if same else None, staged.known))
    t = merge_threshold(live.head if same else None, staged.threshold)
    required_all = set(required_dests) | set(staged.required) | (set(live.required) if same else set())
    cands = []
    pb = None
    if j_b is not None:
        pb = parse(j_b, k_erase, inst)
        if pb.bad:
            raise ErasureConflict("the backup's erasure journal is not authentic — refused")
        cands.append(("backup", pb))
    pv = None
    if j_v is not None:
        try:
            pv = parse(j_v, k_erase, inst)
            # prefixul autentic e un candidat (mai multe tombstone-uri = niciodată mai puţină ştergere);
            # dovadă e doar dacă atinge pragul (mai jos)
            cands.append(("volume", pv))
        except JournalError:
            pv = None                              # alt jurnal (alt installation id) / stricat: nu e J_v
    rolled, unreachable, observed, by_id = [], [], {}, {}
    for r in dest_results:
        by_id[r.id] = r
        if not r.ok:
            unreachable.append(r.id)
            continue
        n = r.parsed.n if r.parsed is not None else 0
        if n < known.get(r.id, 0):
            rolled.append(r.id)                    # mai vechi decât ce ştie o sursă: nu e dovadă
            continue
        if r.parsed is not None:
            observed[r.id] = n
            cands.append(("destination " + r.id, r.parsed))
    best = _on_one_chain(cands) if cands else None
    star = best[1] if best else None
    star_bytes = None
    if star is not None and star.n:
        src = {"backup": j_b, "volume": j_v}.get(best[0])
        if src is None:
            src = next(r.data for r in dest_results if "destination " + r.id == best[0])
        star_bytes = bytes(src[:prefix_len(star.n)])
    head = star.head if star is not None else EMPTY_HEAD
    # obligatorii: destinaţiile configurate (DB-ul staged + acest host) şi orice destinaţie care,
    # după ce ştie o sursă, ţine un cap MAI NOU decât J* (acolo pot fi ştergeri pe care nu le avem)
    req = required_all | {d for d, n in known.items() if n > head.n}
    overflow = overflow or known_overflow(known, observed)
    met = live.state != "bad" and reaches(star, t) and not overflow
    floor = 1 if mode == "stage" else 0

    def dest_ok(d):
        r = by_id.get(d)
        if r is None or not r.ok or r.parsed is None or d in rolled:
            return False
        need = max(known.get(d, 0), t.n, floor)
        return need >= 1 and r.parsed.n >= need and reaches(r.parsed, t)
    if not met:
        proof = "none"
    elif live.state == "same" and pv is not None and reaches(pv, t):
        proof = "volume"
    elif req and all(dest_ok(d) for d in req):
        proof = "destinations"
    else:
        proof = "none"
    tracked_any = tracked or head.n > 0 or bool(known) or pv is not None or t.n > 0
    state = "not-tracked" if not tracked_any else ("proven" if proof != "none" else "unproven")
    return Decision(state, proof, star_bytes if tracked_any else None, head, rolled, unreachable,
                    t, merge_known(known, observed), not met, sorted(required_all), overflow)


def journal_reaches(raw, k_erase, inst, t):
    """`reaches` for journal bytes (None / unparsable = nothing)."""
    if raw is None:
        return t.n == 0
    try:
        return reaches(parse(raw, k_erase, inst), t)
    except JournalError:
        return t.n == 0


def reconcile_apply(*, k_erase, inst, staged_journal=None, live_journal=None, stage_summary=None,
                    threshold=EMPTY_HEAD, live_ok=False):
    """The same reconciliation again under the boot lock, immediately before apply: the staged J*
    and the live journal must lie on one chain; the longer one is published. Returns (journal bytes
    to publish or None, proven, head).

    Proof at apply (H1/M1) is the VOLUME only, re-checked now: `live_ok` = the live database is of
    the same installation and readable, `threshold` = the highest committed head known (the stage's
    and the live database's now); J_v must hold it and so must the journal published. A proof by
    destinations at stage is not re-verifiable here: it never lifts the quarantine (the janitor's
    `try_prove` re-fetches them)."""
    cands = []
    if staged_journal is not None:
        ps = parse(staged_journal, k_erase, inst)
        if ps.bad:
            raise ErasureConflict("the staged erasure journal is not authentic — refused")
        cands.append(("staged", ps, staged_journal))
    pv = None
    if live_journal is not None:
        try:
            pv = parse(live_journal, k_erase, inst)
            cands.append(("volume", pv, live_journal))
        except JournalError:
            pv = None
    best = _on_one_chain([(lbl, p) for lbl, p, _raw in cands]) if cands else None
    out = None
    head = EMPTY_HEAD
    if best is not None:
        head = best[1].head
        raw = next(r for lbl, _p, r in cands if lbl == best[0])
        out = bytes(raw[:prefix_len(best[1].n)])
        if pv is not None and best[0] == "volume" and best[1].n == pv.n and not pv.bad:
            out = None                             # jurnalul de pe volum e deja cel mai lung
    final = best[1] if best is not None else None
    proven = live_ok and pv is not None and reaches(pv, threshold) and reaches(final, threshold)
    if (stage_summary or {}).get("state") == "not-tracked" and head.n == 0 and threshold.n == 0:
        proven = True                              # nimic urmărit nicăieri: nimic de dovedit
    return out, proven, head


def _plain_names(names, out):
    for n in names:
        m = _PLAIN_NAME.match(n)
        if m:
            out.add((m.group(1), m.group(2)))


def _plain_cohort(transcripts_dir):
    """(sid, kind) of every 3.7-named plaintext file under `transcripts/` and `arhiva/` (names only,
    no link followed; a directory that cannot be listed adds nothing — the rows still count)."""
    out = set()
    if transcripts_dir is None:
        return out
    for d in (str(transcripts_dir), os.path.join(str(transcripts_dir), "arhiva")):
        try:
            _plain_names(os.listdir(d), out)
        except OSError:
            continue
    return out


def _plain_cohort_fd(dfd):
    """`_plain_cohort` through the Store's directory fd (boot: the path is not re-resolved)."""
    out = set()
    if dfd is None:
        return out
    try:
        _plain_names(os.listdir(dfd), out)
    except OSError:
        pass
    try:
        afd = os.open("arhiva", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    except OSError:
        return out
    try:
        _plain_names(os.listdir(afd), out)
    except OSError:
        pass
    finally:
        os.close(afd)
    return out


def _quarantine_cohort_sync(c, reason, now, plain=()):
    """The WHOLE cohort (H2 / R-H2) quarantined with `reason`, inside the caller's transaction:
    every readable descriptor (→ `quarantined`) and every (sid, kind) still in plaintext — a
    migration row that owns a file, or a 3.7-named file (`plain`) with or without a row — gets its
    `tx_quarantine` row, so the pending-plaintext reader, the migration (a converted descriptor is
    born `quarantined`) and the writer start refuse it. A `journal:*` reason is never replaced by
    `continuity` (that one is Owner-recoverable, a broken journal never is). Returns the count."""
    _ensure_quarantine_table(c)
    rows = c.execute("SELECT sid, kind FROM tx_descriptors WHERE status IN ('ok','recovery')").fetchall()
    keys_ = {(sid, kind) for sid, kind in rows}
    try:
        keys_ |= {(r[0], r[1]) for r in c.execute(
            "SELECT sid, kind FROM tx_migration WHERE state IN ('pending','orphan','failed','converted') "
            "AND kind IN ('out','cast')").fetchall()}
    except sqlite3.OperationalError:
        pass                                   # DB mai vechi decât tabela: doar fişierele
    keys_ |= set(plain)
    for sid, kind in sorted(keys_):
        c.execute("INSERT INTO tx_quarantine(sid, kind, reason, since) VALUES(?,?,?,?) "
                  "ON CONFLICT(sid, kind) DO UPDATE SET reason=CASE WHEN tx_quarantine.reason "
                  "LIKE 'journal:%' THEN tx_quarantine.reason ELSE excluded.reason END",
                  (sid, kind, reason, now))
    c.execute("UPDATE tx_descriptors SET status='quarantined' WHERE status IN ('ok','recovery')")
    return len(keys_)


def mark_unproven_sync(db_path, since, n, now=None, *, threshold=None, known=None, transcripts_dir=None,
                       required=None, overflow=False):
    """Restore without proof (apply, after the DB copy): the WHOLE cohort quarantined with reason
    `continuity` (H2): every readable descriptor (→ `quarantined`), and every (sid, kind) still in
    plaintext — a migration row that owns a file, or a 3.7-named file under `transcripts_dir` with
    or without a row — gets its `tx_quarantine` row, so the pending-plaintext reader, the migration
    (the converted descriptor stays quarantined) and the writer start refuse it until the janitor
    proves continuity or an Owner recovers it. Then the marker the janitor needs (`threshold`,
    `known`, `required`, `overflow` kept: what a later proof must reach, R-H1/R-M2). Idempotent."""
    now = time.time() if now is None else now
    cohort = _plain_cohort(transcripts_dir)
    con = sqlite3.connect(str(db_path), isolation_level=None)
    try:
        con.execute("BEGIN IMMEDIATE")
        try:
            _quarantine_cohort_sync(con, "continuity", now, cohort)
            mark = {"state": "unproven", "since": int(since or 0), "n": int(n)}
            if threshold is not None:
                mark["threshold"] = threshold.to_json()
            if known is not None:
                mark["known"] = known_from_json(known)
            if required:
                mark["required"] = required_from_json(list(required))
            if overflow:
                mark["overflow"] = True
            _set_json(con, "continuity", mark)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
    finally:
        con.close()


def clear_unproven_sync(db_path):
    con = sqlite3.connect(str(db_path), isolation_level=None)
    try:
        con.execute("DELETE FROM tx_state WHERE key='continuity'")
    finally:
        con.close()


def _ensure_quarantine_table(con):
    # DB-ul unui backup mai vechi decât tabela: aceeaşi definiţie ca db.SCHEMA (aditiv)
    con.execute("CREATE TABLE IF NOT EXISTS tx_quarantine (sid TEXT NOT NULL, kind TEXT NOT NULL, "
                "reason TEXT NOT NULL, since REAL NOT NULL, PRIMARY KEY (sid, kind))")


# ── backup member (§12.11.3 manifest v2) ─────────────────────────────────────


def staged_state(db_path):
    """(erasure_head Head|None, attested_heads dict, configured destination ids) of a DB copy
    (a backup's VACUUM copy or a staged restore). Missing tables = nothing tracked."""
    con = sqlite3.connect(pathlib_uri(db_path), uri=True)
    try:
        try:
            rows = dict(con.execute("SELECT key, value FROM tx_state WHERE key IN "
                                    "('erasure_head','attested_heads')").fetchall())
        except sqlite3.OperationalError:
            rows = {}
        try:
            cfg = dict(con.execute("SELECT key, value FROM app_settings WHERE key LIKE 'cloud_%'").fetchall())
        except sqlite3.OperationalError:
            cfg = {}
    finally:
        con.close()
    try:
        head = Head.from_json(json.loads(rows["erasure_head"])) if "erasure_head" in rows else None
        att = json.loads(rows["attested_heads"]) if "attested_heads" in rows else {}
    except ValueError:
        raise JournalError("bad-state", "staged tx_state") from None
    if not isinstance(att, dict):
        raise JournalError("bad-state", "attested_heads")
    did = dest_id_from_settings(cfg)
    return head, att, [did] if did else []


def pathlib_uri(p):
    return "file:%s?mode=ro" % os.path.abspath(str(p))


def dest_id_from_settings(cfg):
    """A stable id for the configured off-host destination (no secret in it): provider + target."""
    prov = (cfg.get("cloud_provider") or "").strip()
    if not prov:
        return ""
    if prov in ("sftp", "ftps"):
        port = int(cfg.get("cloud_port") or 0) or (21 if prov == "ftps" else 22)
        return "%s:%s@%s:%d/%s" % (prov, (cfg.get("cloud_user") or "").strip(),
                                   (cfg.get("cloud_host") or "").strip().lower(), port,
                                   (cfg.get("cloud_path") or "").strip().strip("/"))
    return "%s:%s" % (prov, (cfg.get("cloud_folder") or "").strip())


def backup_member(db_copy, data_dir, kwk, inst):
    """The journal member of a backup: the volume journal cut at the DB copy's committed head, with
    its manifest entry. None = this dataset never had a journal (no file, no head)."""
    head, att, _ids = staged_state(db_copy)
    data = Journal(data_dir, k_erase_of(kwk), inst).read_bytes()
    if data is None and head is None:
        return None
    if data is None:
        raise JournalError("missing", "the erasure journal is missing — backup refused")
    head = head or EMPTY_HEAD
    p = parse(data, k_erase_of(kwk), inst)
    if p.n < head.n or (head.n and not hmac.compare_digest(p.entries[head.n - 1].mac, head.mac)):
        raise JournalError("mismatch", "the erasure journal does not match the database — backup refused")
    member = data[:prefix_len(head.n)]
    attested = sorted(({"destination": k, "n": int(v.get("n", 0)), "time": int(v.get("time", 0))}
                       for k, v in att.items() if isinstance(v, dict)), key=lambda x: x["destination"])
    return {"bytes": member, "head": head, "attested": attested}


def check_member(member, man, k_erase, inst, db_head):
    """Restore: the journal member must match the manifest (length, SHA-256, head) and the staged
    DB's erasure_head, and authenticate under the staged keyring."""
    if member is None:
        raise ErasureConflict("the backup says its erasures are tracked but has no journal — refused")
    if len(member) != man["length"] or hashlib.sha256(member).hexdigest() != man["sha256"]:
        raise ErasureConflict("the backup's erasure journal does not match its manifest — refused")
    p = parse(member, k_erase, inst)
    head = Head.from_json(man["head"])
    if p.bad or p.n != head.n or not hmac.compare_digest(p.head.mac, head.mac):
        raise ErasureConflict("the backup's erasure journal is not authentic — refused")
    dbh = db_head or EMPTY_HEAD
    if dbh.n != head.n or not hmac.compare_digest(dbh.mac, head.mac):
        raise ErasureConflict("the backup's erasure journal does not match its database — refused")
    return p


# ── proof later: the janitor lifts the continuity quarantine ─────────────────


def _marker_terms(cont):
    """`Terms` of a continuity marker, or None when it cannot be read (fail closed: no proof)."""
    try:
        return terms_of(cont)
    except (JournalError, TypeError, KeyError):
        return None


def _behind():
    """R-M1: True while the local journal does not reach what the continuity marker says was
    committed somewhere (its threshold, or a destination head known to be higher). A new local
    entry then would be a second entry n+1 next to one we cannot see (a fork that no proof can
    resolve later). An unreadable marker counts as behind (fail closed)."""
    s = _s
    if not s.continuity or s.continuity.get("state") != "unproven":
        return False
    terms = _marker_terms(s.continuity)
    if terms is None or s.parsed is None:
        return True
    top = max([terms.threshold.n] + list(terms.known.values()))
    return not reaches(s.parsed, terms.threshold) or s.parsed.n < top


async def try_prove(st=None):
    """With every required destination answering an authentic, non-rolled-back head on our chain
    that reaches what was known at the restore (the marker's threshold and per-destination heads):
    apply the tombstones the volume does not have and lift the continuity quarantine.

    H3: the decision is taken again UNDER the barrier against the journal as it is now (CAS on the
    file and on `s.parsed`): an erasure appended while we fetched is on the volume journal, and a
    destination chain that does not extend it is a fork → nothing adopted, quarantine kept. The
    adoption (journal replace + in-memory tombstones) and ONE transaction (destroy every new sid,
    advance the DB head monotonically, lift) run in the same critical section as erase's append."""
    s = _s
    st = st or s.store
    if st is None or s.diag or s.uncertain or s.parsed is None or not s.continuity:
        return False
    cont = s.continuity
    terms = _marker_terms(cont)
    if terms is None or terms.overflow:
        return False                               # R-M2: obligaţii pierdute = nicio dovadă
    t, known, r_n = terms.threshold, terms.known, terms.n
    dests = await destinations()
    if not dests:
        return False
    k = s.journal.k
    results = await fetch_all(dests, k, st.inst, check_from=r_n)
    forks = [r.id for r in results if r.error == "conflict"]
    if forks:
        s.conflict = "erasure journals at %s diverge" % forks[0][:120]
        st.alarm("transcript.erasureConflict", s.conflict)
        return False
    try:
        dec = decide_restore(k_erase=k, inst=st.inst, j_b=None, tracked=True, j_v=None,
                             # R-M2: destinaţiile obligatorii la restore rămân obligatorii chiar
                             # dacă au dispărut din configurare (nu le putem citi → nicio dovadă)
                             dest_results=results,
                             required_dests=set(d.id for d in dests) | set(terms.required),
                             known_attested=known, live=Live("same", t, {}), mode="prove")
    except ErasureConflict as e:
        s.conflict = str(e)
        st.alarm("transcript.erasureConflict", str(e))
        return False
    s.rolled_back = set(dec.rolled_back)
    if dec.proof != "destinations":
        return False
    star = parse(dec.journal, k, st.inst) if dec.journal else None
    gens = []
    async with st.barrier:
        if s.diag or s.uncertain or s.parsed is None or s.continuity is not cont:
            return False
        cur = s.parsed
        # CAS: fişierul e exact jurnalul pe care îl ştim (nicio adăugare / înlocuire nevăzută)
        raw = await st.io(s.journal.read_bytes)
        if raw is None or len(raw) != prefix_len(cur.n):
            return False
        now_p = parse(raw, k, st.inst)
        if now_p.n != cur.n or now_p.bad or not hmac.compare_digest(now_p.head.mac, cur.head.mac):
            return False
        cands = [("volume", cur)] + ([("destinations", star)] if star is not None else [])
        try:
            _on_one_chain(cands)
        except ErasureConflict as e:
            # o ştergere locală (după restore sau concurentă) şi o ramură a destinaţiei: oprim
            s.conflict = str(e)
            st.alarm("transcript.erasureConflict", str(e))
            return False
        final = star if star is not None and star.n > cur.n else cur
        if not reaches(final, t):
            return False
        new = list(star.entries[cur.n:]) if final is star else []
        if new:
            await st.io(s.journal.replace, dec.journal)
            s.parsed = star
            for e in new:
                st.tombstone(e.sid_hex)
                st.drop_key(e.sid_hex)

        def fn(c):
            out = []
            for e in new:
                out += [(e.sid_hex, kind, hexid) for hexid, kind in
                        _destroy_sync(c, e.sid_hex, Head(e.n, e.time_ms, e.mac))]
            rows = c.execute("SELECT sid, kind FROM tx_quarantine WHERE reason='continuity'").fetchall()
            for sid, kind in rows:
                c.execute("UPDATE tx_descriptors SET status='ok' WHERE sid=? AND kind=? AND "
                          "status IN ('quarantined','recovery')", (sid, kind))
            c.execute("DELETE FROM tx_quarantine WHERE reason='continuity'")
            c.execute("DELETE FROM tx_state WHERE key='continuity'")
            return out
        try:
            gens = await st.io(st._run_txn, fn)
        except txstore.Uncertain:
            # jurnalul e deja adoptat (durabil); boot-ul re-aplică paşii 2–3 şi carantina rămâne
            # până la un nou try_prove
            s.uncertain = "commit-uncertain"
            return False
        if new and s.head_db.n < star.head.n:
            s.head_db = star.head
        s.continuity = None
    for sid, kind, hexid in gens:
        await st.retire(sid, kind, hexid)
    st.bump(None)
    return True


# ── Owner recovery (§12.11.4 "Owner recovery mode", Q4) ──────────────────────


def journal_diag():
    """The diagnosis of the erasure journal at this boot ('' = healthy or not booted): the word
    System health shows for `erasure_journal_broken` (`crypto.erasure`)."""
    return _s.diag if _s.booted else ""


def _continuity_only(reason):
    return reason == "continuity"


def _any_quarantine(reason):
    return reason == "continuity" or (reason or "").startswith("journal:")


async def quarantine_reasons(st, sid):
    """The `tx_quarantine` reasons of one recording (every kind), as a set."""
    rows = await st.read(lambda c: c.execute("SELECT reason FROM tx_quarantine WHERE sid=?",
                                             (sid,)).fetchall())
    return {r[0] for r in rows}


async def list_quarantined(st):
    def load(c):
        return c.execute(
            "SELECT d.sid, d.kind, d.status, q.reason, q.since, "
            "EXISTS (SELECT 1 FROM session_keys k WHERE k.sid=d.sid) FROM tx_descriptors d "
            "LEFT JOIN tx_quarantine q ON q.sid=d.sid AND q.kind=d.kind "
            "WHERE d.status IN ('quarantined','recovery') "
            # H2: cohorta restore-ului fără descriptor (text clar încă nemigrat): listată, dar
            # recuperabilă abia după migrare (descriptorul convertit rămâne în carantină)
            "UNION ALL SELECT q.sid, q.kind, 'plaintext', q.reason, q.since, 0 FROM tx_quarantine q "
            "WHERE NOT EXISTS (SELECT 1 FROM tx_descriptors d WHERE d.sid=q.sid AND d.kind=q.kind) "
            "ORDER BY 1, 2").fetchall()
    rows = await st.read(load)
    diag = journal_diag()
    jr = "journal:" + diag if diag else None
    by = collections.OrderedDict()
    for sid, kind, status, reason, since, has_key in rows:
        e = by.setdefault(sid, {"sid": sid, "kinds": [], "status": status, "reason": reason or "unknown",
                                "since": since, "recoverable": True, "_reasons": set(), "_key": bool(has_key)})
        e["kinds"].append(kind)
        e["_reasons"].add(reason)
        if status != e["status"]:
            e["status"] = "mixed"
        if reason != "continuity":
            e["reason"] = reason or "unknown"
    out = list(by.values())
    for e in out:
        reasons, has_key = e.pop("_reasons"), e.pop("_key")
        # recuperare de continuitate (data backup-ului) sau, decizia Owner-ului 2026-11-26, de
        # jurnal: doar cu diagnosticul curent afişat în System health şi cu RK-ul încă prezent
        mode = ("continuity" if reasons == {"continuity"}
                else "journal" if jr is not None and reasons == {jr} and has_key else None)
        e["recovery"] = mode
        e["recoverable"] = mode is not None and e["status"] == "quarantined" and e["sid"] not in st.tombstoned
        if mode == "journal":
            e["confirm_word"] = diag
    return {"items": out, "continuity": _s.continuity, "journal_diag": diag or None}


async def _set_status(st, sid, frm, to, *, allowed=_continuity_only, need_key=False):
    txstore._sid_bytes(sid)
    if sid in st.tombstoned:
        raise ErasureError("transcript.missing", "no recording for this session", 404)
    async with st.lease(sid):
        async with st.revoking(sid):
            def fn(c):
                rows = c.execute("SELECT d.kind, d.status, q.reason FROM tx_descriptors d LEFT JOIN "
                                 "tx_quarantine q ON q.sid=d.sid AND q.kind=d.kind WHERE d.sid=?",
                                 (sid,)).fetchall()
                if not rows:
                    raise ErasureError("transcript.missing", "no recording for this session", 404)
                for _k, status, reason in rows:
                    if status != frm:
                        raise ErasureError("transcript.recoveryState",
                                           "this recording is not %s" % frm, 409)
                    # INV-14 (§12.11.4): doar carantina permisă de apelant se poate deschide
                    # (continuitate; de jurnal doar prin recover_journal); un tombstone, o
                    # înregistrare stricată sau o carantină de epoch niciodată
                    if allowed is not None and not allowed(reason):
                        raise ErasureError("transcript.notRecoverable",
                                           "only recordings quarantined for missing erasure proof "
                                           "can be recovered", 409)
                # un RK distrus (ştergere comisă în DB, chiar dacă jurnalul care o dovedea s-a
                # pierdut) = nimic de recuperat: fără cheie nu există înregistrare
                if need_key and c.execute("SELECT 1 FROM session_keys WHERE sid=?", (sid,)).fetchone() is None:
                    raise ErasureError("transcript.recoveryNoKey",
                                       "this recording's key was destroyed; it cannot be recovered", 409)
                c.execute("UPDATE tx_descriptors SET status=? WHERE sid=? AND status=?", (to, sid, frm))
                if to == "ok":
                    # doar kind-urile eliberate: un kind încă în clar (cohorta H2) rămâne în carantină
                    for kind, _st, _r in rows:
                        c.execute("DELETE FROM tx_quarantine WHERE sid=? AND kind=?", (sid, kind))
                return [r[0] for r in rows]
            return await st.txn(fn)


async def recover(st, sid):
    """quarantined (continuity) → recovery: readable by Owners only, through the recovery route."""
    return await _set_status(st, sid, "quarantined", "recovery")


async def recover_journal(st, sid, diag):
    """Owner decision 2026-11-26: quarantined (`journal:<diag>`) → recovery, one recording, only
    while this boot's journal diagnosis is exactly `diag` (the one System health shows). A sid the
    authentic part of the journal tombstones, or whose RK is gone (an erasure committed in the
    database), is never recovered: there is nothing left to decrypt."""
    if not diag or journal_diag() != diag or not health_has("erasure_journal_broken"):
        raise ErasureError("transcript.journalNotDiagnosed",
                           "System health does not show this erasure journal diagnosis", 409)
    want = "journal:" + diag
    return await _set_status(st, sid, "quarantined", "recovery",
                             allowed=lambda r: r == want, need_key=True)


async def release(st, sid):
    """recovery → ok (one recording, an explicit Owner action). Refused while the local journal is
    behind the restore's threshold (R-H1, "quarantine instead of refuse"): a committed erasure we
    cannot see yet may name this recording, so it may not become normally readable; the audited
    Owner recovery read (`recover`) stays the exceptional access. A recording recovered from a
    `journal:*` quarantine is never released: the erasures it may be named in are unknowable."""
    if _behind():
        raise ErasureError("transcript.releaseBehind",
                           "erasures committed before the last restore are not on this volume yet; "
                           "the recording stays in recovery until they are proven", 409)

    def allowed(reason):
        if (reason or "").startswith("journal:"):
            raise ErasureError("transcript.releaseJournal",
                               "a recording recovered from a damaged erasure journal stays in recovery", 409)
        return reason == "continuity"
    return await _set_status(st, sid, "recovery", "ok", allowed=allowed)


async def requarantine(st, sid):
    # reduce accesul: orice carantină recuperată (continuitate sau jurnal) poate reveni
    return await _set_status(st, sid, "recovery", "quarantined", allowed=_any_quarantine)


# ── Owner override: a mandatory destination that is gone (decision 2026-11-26) ──


async def _configured_ids_strict():
    """The configured destination ids; a provider error refuses (never "none configured")."""
    if _dest_provider is None:
        return set()
    try:
        return {d.id for d in await _dest_provider()}
    except Exception as e:                       # noqa: BLE001
        log.warning("erasure: destinations unavailable: %s", type(e).__name__)
        raise ErasureError("transcript.erasureUnavailable",
                           "the configured destinations cannot be read", 503) from None


async def retire_destination(st, dest_id):
    """Remove `dest_id` from the continuity marker's `required` set (R-M2), an audited Owner
    override for a destination that no longer exists. The quarantine stays; its known head stays
    too (a proof must still reach the highest head that destination was known to hold, so retiring
    it never forgets an erasure it was known to have). Refused for a destination that is still
    configured: `try_prove` requires every configured destination anyway, so retiring it would
    change nothing; remove it from the backup settings first."""
    s = _s
    cont = s.continuity
    terms = _marker_terms(cont) if cont and cont.get("state") == "unproven" else None
    if terms is None or dest_id not in terms.required:
        raise ErasureError("transcript.destinationUnknown",
                           "no unproven restore requires this destination", 404)
    if dest_id in await _configured_ids_strict():
        raise ErasureError("transcript.destinationConfigured",
                           "this destination is still configured; remove it from the backup settings first", 409)
    async with st.barrier:
        if s.continuity is not cont:
            raise ErasureError("transcript.recoveryState", "the continuity state changed; try again", 409)
        new = dict(cont)
        left = sorted(set(terms.required) - {dest_id})
        if left:
            new["required"] = left
        else:
            new.pop("required", None)
        # aceeaşi secţiune critică cu try_prove (CAS pe `s.continuity`): o dovadă în zbor care a
        # citit markerul vechi nu mai adoptă nimic; st.txn ar re-lua bariera (asyncio.Lock nu e
        # reentrant), deci tranzacţia direct pe firul DB, ca în try_prove
        try:
            await st.io(st._run_txn, lambda c: _set_json(c, "continuity", new))
        except txstore.Uncertain:
            # rezultat necunoscut: markerul în memorie rămâne cel vechi (mai strict); boot-ul îl
            # citeşte din DB oricum ar fi fost
            raise ErasureError("transcript.erasureUncertain",
                               "the change did not finish; restart the gateway", 503) from None
        s.continuity = new
    return {"required": left, "known_head": terms.known.get(dest_id, 0)}


async def status_of(st, sid):
    rows = await st.read(lambda c: c.execute("SELECT kind, status FROM tx_descriptors WHERE sid=?",
                                             (sid,)).fetchall())
    return {k: s for k, s in rows}


# ── janitor ──────────────────────────────────────────────────────────────────


def start(st):
    s = _s
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if s.task is None:
        s.wake = asyncio.Event()
        s.task = loop.create_task(_loop(st))


async def stop():
    t = _s.task
    _s.task = None
    if t is not None:
        t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass


async def _loop(st):
    last_prove = 0.0
    while True:
        try:
            await attest_once(st)
            if _s.continuity and time.time() - last_prove > PROVE_INTERVAL:
                last_prove = time.time()
                await try_prove(st)
        except asyncio.CancelledError:
            raise
        except ErasureConflict as e:
            _s.conflict = str(e)
        except Exception as e:                   # noqa: BLE001 — bucla nu moare
            log.warning("erasure janitor: %s", type(e).__name__)
        try:
            await asyncio.wait_for(_s.wake.wait(), ATTEST_INTERVAL)
        except asyncio.TimeoutError:
            pass
        _s.wake.clear()


# ── System health (Q2) ───────────────────────────────────────────────────────


def health_has(key):
    return any(i[1] == key for i in health())


def health():
    """[(severity, key, params)] for System health; [] when inactive."""
    s = _s
    if not s.booted:
        return []
    out = []
    if s.diag:
        out.append(("critical", "erasure_journal_broken", {"diag": s.diag}))
    if s.uncertain:
        out.append(("critical", "erasure_uncertain", {"diag": s.uncertain}))
    if s.parsed is not None and s.parsed.n >= WARN_AT:
        out.append(("warning", "erasure_journal_full" if s.parsed.n >= CAP else "erasure_journal_near_cap",
                    {"n": s.parsed.n, "cap": CAP}))
    if s.continuity and s.continuity.get("state") == "unproven":
        out.append(("warning", "erasure_unproven",
                    {"date": time.strftime("%Y-%m-%d", time.gmtime(s.continuity.get("since") or 0))}))
    if s.conflict:
        out.append(("critical", "erasure_conflict", {}))
    head = s.head_db.n
    if head and s.dest_ids == []:
        # Q2: fără destinaţie off-host, ştergerea supravieţuieşte restore-urilor doar pe volumul ăsta
        out.append(("info", "erasure_local_only", {"n": head}))
    for did in sorted(s.dest_ids or ()):
        info = s.dests.get(did) or {}
        if head > s.attested.get(did, {}).get("n", 0) or info.get("state") == "missing":
            since = info.get("since")
            out.append(("warning", "erasure_unattested",
                        {"n": head, "destination": did[:120],
                         "since": time.strftime("%Y-%m-%d %H:%M", time.gmtime(since)) if since else "-"}))
    for did in sorted(s.rolled_back):
        out.append(("critical", "erasure_rolled_back", {"destination": did[:120]}))
    return out
