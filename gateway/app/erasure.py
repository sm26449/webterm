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
* **Owner recovery** (`list_quarantined`, `recover`, `release`, `requarantine`): only recordings
  quarantined for missing continuity proof, one at a time.
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

_OBJ_RE = re.compile(r"^([0-9a-f]{32})\.erasures\.([0-9a-f]{16})(?:\.([0-9a-f]{8,32}))?\.wtj$")
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


def _quarantine_all_sync(c, reason, now):
    """Every recording that is readable now (ok / recovery) → quarantined, with its reason."""
    rows = c.execute("SELECT sid, kind FROM tx_descriptors WHERE status IN ('ok','recovery')").fetchall()
    for sid, kind in rows:
        c.execute("INSERT INTO tx_quarantine(sid, kind, reason, since) VALUES(?,?,?,?) "
                  "ON CONFLICT(sid, kind) DO UPDATE SET reason=excluded.reason, since=excluded.since",
                  (sid, kind, reason, now))
    c.execute("UPDATE tx_descriptors SET status='quarantined' WHERE status IN ('ok','recovery')")
    return len(rows)


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
        rep.quarantined = await st.txn(lambda c: _quarantine_all_sync(c, "journal:" + rep.diag, now))
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


async def erase(st, sid, *, clock=time.time):
    """Steps 1–3; step 4 (attestation) is the janitor's. Returns {erased, n, attested}."""
    s = _s
    if not s.booted or s.store is not st:
        raise ErasureError("transcript.erasureUnavailable", "the erasure journal is not ready", 503)
    if s.diag or s.parsed is None:
        raise ErasureError("transcript.erasureJournalBroken",
                           "the erasure journal is damaged (%s); erasure is refused" % (s.diag or "?"), 503)
    if s.uncertain:
        raise ErasureError("transcript.erasureUncertain",
                           "an earlier erasure did not finish; restart the gateway first", 503)
    txstore._sid_bytes(sid)
    rec = st.recorders.get(sid)
    if sid in st._starting or (rec is not None and rec.state not in ("closed", "lost", "replaced")):
        raise ErasureError("session.live", "the session is live; close it first", 409)
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
            if gens is None:
                gens = []
                s.uncertain = "commit-uncertain"
            else:
                s.head_db = Head(n, t_ms, e.mac)
            st._fault("erase-committed")
        for hexid, kind in gens:
            await st.retire(sid, kind, hexid)
    _kick()
    return {"erased": True, "n": n, "attested": await attested_everywhere(n)}


async def attested_everywhere(n):
    """True when every configured destination holds a head ≥ n (no destination → False)."""
    ds = await destinations()
    return bool(ds) and all(_s.attested.get(d.id, {}).get("n", 0) >= n for d in ds)


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


async def _commit_attested(st, dest_id, head, name):
    def fn(c):
        cur = _get_json(c, "attested_heads") or {}
        if not isinstance(cur, dict):
            cur = {}
        if cur.get(dest_id, {}).get("n", -1) < head.n:
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
        if head.n == 0 or (rec and rec.get("n", 0) >= head.n):
            out[d.id] = s.dests.get(d.id, {}).get("state", "ok") if head.n else "ok"
            if head.n and out[d.id] != "rolled-back":
                out[d.id] = "ok"
            continue
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
            s.attested = await _commit_attested(st, d.id, head, name)
            s.dests[d.id] = {"state": "ok", "since": None, "error": "", "next": 0, "tries": 0}
            out[d.id] = "ok"
        except Exception as e:                   # noqa: BLE001 — o destinaţie căzută nu opreşte celelalte
            prevs = s.dests.get(d.id) or {}
            tries = prevs.get("tries", 0) + 1
            since = prevs.get("since") or clock()
            delay = min(ATTEST_BACKOFF_MAX, ATTEST_INTERVAL * (2 ** min(tries, 6)))
            err = getattr(e, "reason", "") or type(e).__name__
            s.dests[d.id] = {"state": "failing", "since": since, "error": err, "next": clock() + delay,
                             "tries": tries, "n": head.n}
            out[d.id] = "failing"
            log.warning("erasure n=%d not attested on %s: %s", head.n, d.id, err)
    return out


async def fetch_head(d, k_erase, inst):
    """The newest authentic journal a destination holds for `inst`: (Parsed, bytes) or None when it
    holds none; raises on an unreachable destination. Objects are tried newest first."""
    names = []
    for n in await d.list():
        p = parse_object_name(n)
        if p is not None and p[0] == bytes(inst):
            names.append((p[1], n))
    names.sort(reverse=True)
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


@dataclass
class DestResult:
    id: str
    ok: bool                       # a răspuns (nimic sau un jurnal autentic)
    parsed: Parsed = None
    data: bytes = None
    error: str = ""


async def fetch_all(dests, k_erase, inst):
    out = []
    for d in dests:
        try:
            got = await fetch_head(d, k_erase, inst)
            out.append(DestResult(d.id, True, got[0] if got else None, got[1] if got else None))
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

    def summary(self, since):
        return {"state": self.state, "proof": self.proof, "since": int(since or 0), "n": self.head.n}


def decide_restore(*, k_erase, inst, j_b=None, tracked=False, j_v=None, dest_results=(),
                   required_dests=(), known_attested=None):
    """The restore's erasure decision. `j_b` = the backup's journal bytes (already checked against
    its manifest), `j_v` = the live volume journal bytes (None = absent), `dest_results` =
    `DestResult`s, `required_dests` = every destination id that must answer for a proof (configured
    in the staged DB, on this host, or named by any attested head), `known_attested` = {dest id: n}
    merged from every source. Raises ErasureConflict on divergent authentic journals."""
    known = dict(known_attested or {})
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
            # coada neautentică după ultimul element (crash în pasul 1) nu anulează prefixul
            cands.append(("volume", pv))
        except JournalError:
            pv = None                              # alt jurnal (alt installation id) / stricat: nu e J_v
    rolled, unreachable = [], []
    answered = set()
    for r in dest_results:
        if not r.ok:
            unreachable.append(r.id)
            continue
        n = r.parsed.n if r.parsed is not None else 0
        if n < known.get(r.id, 0):
            rolled.append(r.id)                    # mai vechi decât ce ştie o sursă: nu e dovadă
            continue
        answered.add(r.id)
        if r.parsed is not None:
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
    req = set(required_dests) | {d for d, n in known.items() if n > head.n}
    # un J_v cu o intrare neautentică în interior nu e dovadă (doar o coadă parţială, crash în pasul 1)
    if pv is not None and pv.bad in ("", "partial"):
        proof = "volume"
    elif req and req <= answered:
        proof = "destinations"
    else:
        proof = "none"
    tracked_any = tracked or head.n > 0 or bool(known) or pv is not None
    if not tracked_any:
        return Decision("not-tracked", proof, None, head, rolled, unreachable)
    return Decision("proven" if proof != "none" else "unproven", proof, star_bytes, head, rolled,
                    unreachable)


def reconcile_apply(*, k_erase, inst, staged_journal=None, live_journal=None, stage_summary=None):
    """The same reconciliation again under the boot lock, immediately before apply: the staged J*
    and the live journal must lie on one chain; the longer one is published. Returns (journal bytes
    to publish or None, proven, head)."""
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
    stage = (stage_summary or {}).get("proof", "none")
    proven = pv is not None or (stage == "destinations")
    if (stage_summary or {}).get("state") == "not-tracked" and head.n == 0:
        proven = True
    return out, proven, head


def mark_unproven_sync(db_path, since, n, now=None):
    """Restore without proof (apply, after the DB copy): every restored recording quarantined with
    reason `continuity`, and the marker the janitor needs to lift it. Idempotent."""
    now = time.time() if now is None else now
    con = sqlite3.connect(str(db_path), isolation_level=None)
    try:
        con.execute("BEGIN IMMEDIATE")
        try:
            _ensure_quarantine_table(con)
            rows = con.execute("SELECT sid, kind FROM tx_descriptors WHERE status IN ('ok','recovery')").fetchall()
            for sid, kind in rows:
                con.execute("INSERT INTO tx_quarantine(sid, kind, reason, since) VALUES(?,?,?,?) "
                            "ON CONFLICT(sid, kind) DO UPDATE SET reason=excluded.reason",
                            (sid, kind, "continuity", now))
            con.execute("UPDATE tx_descriptors SET status='quarantined' WHERE status IN ('ok','recovery')")
            _set_json(con, "continuity", {"state": "unproven", "since": int(since or 0), "n": int(n)})
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


async def try_prove(st=None):
    """With every destination answering an authentic, non-rolled-back head on our chain: apply the
    tombstones the volume does not have and lift the continuity quarantine."""
    s = _s
    st = st or s.store
    if st is None or s.diag or s.parsed is None or not s.continuity:
        return False
    dests = await destinations()
    if not dests:
        return False
    k = s.journal.k
    results = await fetch_all(dests, k, st.inst)
    known = {i: int(v.get("n", 0)) for i, v in s.attested.items() if isinstance(v, dict)}
    dec = decide_restore(k_erase=k, inst=st.inst, j_b=None, tracked=True, j_v=None,
                         dest_results=results, required_dests=[d.id for d in dests], known_attested=known)
    s.rolled_back = set(dec.rolled_back)
    if dec.proof != "destinations":
        return False
    cur = s.parsed
    star = parse(dec.journal, k, st.inst) if dec.journal else cur
    try:
        _on_one_chain([("volume", cur), ("destinations", star)])
    except ErasureConflict as e:
        s.conflict = str(e)
        st.alarm("transcript.erasureConflict", str(e))
        return False
    if star.n > cur.n:
        async with st.barrier:
            await st.io(s.journal.replace, dec.journal)
            s.parsed = star
            for e in star.entries[cur.n:]:
                st.tombstone(e.sid_hex)
        for e in star.entries[cur.n:]:
            gens = await st.txn(lambda c, e=e: _destroy_sync(c, e.sid_hex, Head(e.n, e.time_ms, e.mac)))
            for hexid, kind in gens:
                await st.retire(e.sid_hex, kind, hexid)
        s.head_db = star.head

    def lift(c):
        rows = c.execute("SELECT sid, kind FROM tx_quarantine WHERE reason='continuity'").fetchall()
        for sid, kind in rows:
            c.execute("UPDATE tx_descriptors SET status='ok' WHERE sid=? AND kind=? AND "
                      "status IN ('quarantined','recovery')", (sid, kind))
        c.execute("DELETE FROM tx_quarantine WHERE reason='continuity'")
        c.execute("DELETE FROM tx_state WHERE key='continuity'")
        return len(rows)
    await st.txn(lift)
    s.continuity = None
    st.bump(None)
    return True


# ── Owner recovery (§12.11.4 "Owner recovery mode", Q4) ──────────────────────


async def list_quarantined(st):
    def load(c):
        return c.execute(
            "SELECT d.sid, d.kind, d.status, q.reason, q.since FROM tx_descriptors d "
            "LEFT JOIN tx_quarantine q ON q.sid=d.sid AND q.kind=d.kind "
            "WHERE d.status IN ('quarantined','recovery') ORDER BY d.sid, d.kind").fetchall()
    rows = await st.read(load)
    by = collections.OrderedDict()
    for sid, kind, status, reason, since in rows:
        e = by.setdefault(sid, {"sid": sid, "kinds": [], "status": status, "reason": reason or "unknown",
                                "since": since, "recoverable": True})
        e["kinds"].append(kind)
        if status != e["status"]:
            e["status"] = "mixed"
        if reason != "continuity":
            e["recoverable"] = False
            e["reason"] = reason or "unknown"
    out = list(by.values())
    for e in out:
        e["recoverable"] = e["recoverable"] and e["status"] == "quarantined" and e["sid"] not in st.tombstoned
    return {"items": out, "continuity": _s.continuity}


async def _set_status(st, sid, frm, to, *, need_reason=True):
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
                    # INV-14 (§12.11.4): doar carantina de CONTINUITATE se poate deschide; un
                    # tombstone, o înregistrare stricată sau o carantină de jurnal/epoch niciodată
                    if need_reason and reason != "continuity":
                        raise ErasureError("transcript.notRecoverable",
                                           "only recordings quarantined for missing erasure proof "
                                           "can be recovered", 409)
                c.execute("UPDATE tx_descriptors SET status=? WHERE sid=? AND status=?", (to, sid, frm))
                if to == "ok":
                    c.execute("DELETE FROM tx_quarantine WHERE sid=?", (sid,))
                return [r[0] for r in rows]
            return await st.txn(fn)


async def recover(st, sid):
    """quarantined (continuity) → recovery: readable by Owners only, through the recovery route."""
    return await _set_status(st, sid, "quarantined", "recovery")


async def release(st, sid):
    """recovery → ok (one recording, an explicit Owner action)."""
    return await _set_status(st, sid, "recovery", "ok")


async def requarantine(st, sid):
    return await _set_status(st, sid, "recovery", "quarantined")


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
        if head > s.attested.get(did, {}).get("n", 0):
            info = s.dests.get(did) or {}
            since = info.get("since")
            out.append(("warning", "erasure_unattested",
                        {"n": head, "destination": did[:120],
                         "since": time.strftime("%Y-%m-%d %H:%M", time.gmtime(since)) if since else "-"}))
    for did in sorted(s.rolled_back):
        out.append(("critical", "erasure_rolled_back", {"destination": did[:120]}))
    return out
