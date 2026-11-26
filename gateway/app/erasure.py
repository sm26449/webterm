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
* **Erasure** (`erase`): the four steps of §12.11.4 under the sid's lease and the Store barrier,
  preceded by a durable erase intent (`tx_erase_intents`, R2-H1) that only step 2 clears; the boot
  completes any intent left, so a lost or damaged journal entry never hides an erasure.
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
CLEANUP_BACKOFF = 30.0                           # R5-L1: prima reîncercare a curăţării (s), apoi dublată
CLEANUP_BACKOFF_MAX = 3600.0
CLEANUP_ALARM_AFTER = 3                          # eşecuri consecutive pe un sid → alarmă
PROVE_MAX_OBJECTS = 64                           # try_prove: toate obiectele de după restore, cel mult atâtea
REVERIFY_INTERVAL = 3600.0                       # un read-back vechi nu dovedeşte că obiectul mai există azi
KNOWN_MAX = 64                                   # destinaţii ţinute în pragurile unui restore
# R7-H1: conflictul autentificat (fork) ţinut în marker; limitele încap în flag-ul restore-ului (64 KiB)
CONFLICT_SIDS_MAX = 512
CONFLICT_HEADS_MAX = 16
CONFLICT_DESTS_MAX = 8
REJECTED_MAX = 64

_OBJ_RE = re.compile(r"^([0-9a-f]{32})\.erasures\.([0-9a-f]{16})(?:\.([0-9a-f]{8,32}))?\.wtj$")
_PLAIN_NAME = re.compile(r"^([0-9a-f]{32})\.(out|cast)$")
_RD = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class JournalError(Exception):
    """A journal that is not what the committed state says (reason = short code)."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class Unverifiable(JournalError):
    """R4-H2: a destination holds an object named above its best authentic journal that cannot be
    authenticated: it may hold the erasure we look for, so the destination proves nothing."""

    def __init__(self, n):
        super().__init__("unverifiable", "an erasure journal object n=%d cannot be authenticated" % n)
        self.n = n


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


# ── R7-H1: the authenticated conflict (a fork seen) ─────────────────────────
#
# Două ramuri autentice văzute o dată rămân un conflict până la o decizie explicită: dispariţia
# uneia din listing nu e o reconciliere. Înregistrarea (în markerul de continuitate, în flag-ul
# restore-ului) ţine capetele ramurilor (n + MAC), prefixele comune („bases": orice ramură adoptată
# trebuie să le atingă) şi sid-urile şterse după prefixul comun pe ORICARE ramură. Tombstone-urile
# se aplică la vedere (RK distrus + intenţie durabilă de ştergere): o ştergere pe orice ramură câştigă.


def _sid_list(doc, cap):
    if type(doc) is not list or len(doc) > cap:
        raise JournalError("bad-conflict")
    for x in doc:
        if type(x) is not str or not re.fullmatch(r"[0-9a-f]{32}", x):
            raise JournalError("bad-conflict")
    return sorted(set(doc))


def _head_list(doc, cap):
    if type(doc) is not list or len(doc) > cap:
        raise JournalError("bad-conflict")
    out = {}
    for h in doc:
        try:
            hh = Head.from_json(h)
        except JournalError:
            raise JournalError("bad-conflict") from None
        out[(hh.n, hh.mac)] = hh
    return [out[k] for k in sorted(out)]


def conflict_from_json(doc):
    """The validated conflict record, as a canonical dict; JournalError when malformed."""
    if (type(doc) is not dict
            or not set(doc) <= {"since", "bases", "heads", "sids", "dests", "overflow"}
            or type(doc.get("since", 0)) is not int or type(doc.get("overflow", False)) is not bool):
        raise JournalError("bad-conflict")
    dests = doc.get("dests", [])
    if type(dests) is not list or len(dests) > CONFLICT_DESTS_MAX or not all(
            type(d) is str and 0 < len(d) <= 512 for d in dests):
        raise JournalError("bad-conflict")
    heads = _head_list(doc.get("heads", []), CONFLICT_HEADS_MAX)
    if len(heads) < 2:
        raise JournalError("bad-conflict")       # un conflict are cel puţin două ramuri
    return {"since": doc.get("since", 0), "bases": [h.to_json() for h in _head_list(doc.get("bases", []),
                                                                                   CONFLICT_HEADS_MAX)],
            "heads": [h.to_json() for h in heads], "sids": _sid_list(doc.get("sids", []), CONFLICT_SIDS_MAX),
            "dests": sorted(set(dests)), "overflow": doc.get("overflow", False)}


def _same_chain(a, b):
    """Two authentic prefixes on one chain (the shorter one is a prefix of the longer)."""
    lo, hi = (a, b) if a.n <= b.n else (b, a)
    return lo.n == 0 or hmac.compare_digest(lo.entries[lo.n - 1].mac, hi.entries[lo.n - 1].mac)


def _fork_base(branches):
    """The longest prefix every branch shares (n), by MAC (a MAC chain: equal at m = equal below)."""
    m = min(p.n for p in branches)
    while m > 0:
        mac = branches[0].entries[m - 1].mac
        if all(hmac.compare_digest(p.entries[m - 1].mac, mac) for p in branches):
            break
        m -= 1
    return m


def branch_sids(branches):
    """Every sid an authentic branch erases (all entries: any of them may be missing locally)."""
    return {e.sid_hex for p in branches for e in p.entries}


def merge_conflict(old, branches=(), dests=(), now=None):
    """`old` (a record or None) plus a newly seen set of authentic `branches` (Parsed, n ≥ 1) at
    `dests`. The bases, heads, sids and destinations only ever grow; past a bound the record is
    marked `overflow` (fail closed: an Owner resolution is refused; the tombstones are still applied,
    they become erase intents). Returns None when there is nothing to record."""
    branches = [p for p in branches if p is not None and p.n > 0]
    new = None
    if len(branches) >= 2 and not all(_same_chain(a, b) for a in branches for b in branches):
        m = _fork_base(branches)
        base = branches[0].entries[m - 1] if m else None
        heads = {(p.head.n, p.head.mac): p.head.to_json() for p in branches}
        sids_ = sorted({e.sid_hex for p in branches for e in p.entries[m:]})
        dd = sorted({d for d in dests if type(d) is str and 0 < len(d) <= 512})
        new = {"since": int(time.time() if now is None else now),
               "bases": [Head(base.n, base.time_ms, base.mac).to_json()] if base else [],
               "heads": [heads[k] for k in sorted(heads, reverse=True)][:CONFLICT_HEADS_MAX],
               "sids": sids_[:CONFLICT_SIDS_MAX], "dests": dd[:CONFLICT_DESTS_MAX],
               "overflow": (len(heads) > CONFLICT_HEADS_MAX or len(sids_) > CONFLICT_SIDS_MAX
                            or len(dd) > CONFLICT_DESTS_MAX)}
    return conflict_union(old, new)


def conflict_admits(rec, p):
    """'' when the authentic journal `p` may close the conflict `rec` (it reaches every base and
    erases every sid seen on any branch), else why not."""
    if rec.get("overflow"):
        return "the conflict record overflowed (too many branches or erasures to check)"
    for b in rec["bases"]:
        if not reaches(p, Head.from_json(b)):
            return "the chosen journal does not hold the common prefix n=%d" % b["n"]
    have = {e.sid_hex for e in p.entries}
    miss = [s for s in rec["sids"] if s not in have]
    if miss:
        return "the chosen journal does not erase %d recording(s) erased on another branch" % len(miss)
    return ""


def conflict_union(a, b):
    """Two conflict records (either may be None) → one (every base, head, sid, destination kept)."""
    if a is None or b is None:
        return a if b is None else conflict_from_json(b)
    bases = {(h["n"], h["mac"]): h for h in a["bases"] + b["bases"]}
    heads = {(h["n"], h["mac"]): h for h in a["heads"] + b["heads"]}
    sids_ = sorted(set(a["sids"]) | set(b["sids"]))
    dd = sorted(set(a["dests"]) | set(b["dests"]))
    ovf = (a["overflow"] or b["overflow"] or len(bases) > CONFLICT_HEADS_MAX or len(heads) > CONFLICT_HEADS_MAX
           or len(sids_) > CONFLICT_SIDS_MAX or len(dd) > CONFLICT_DESTS_MAX)
    return conflict_from_json({"since": min(a["since"], b["since"]) or max(a["since"], b["since"]),
                               "overflow": ovf, "bases": [bases[k] for k in sorted(bases)][:CONFLICT_HEADS_MAX],
                               "heads": [heads[k] for k in sorted(heads, reverse=True)][:CONFLICT_HEADS_MAX],
                               "sids": sids_[:CONFLICT_SIDS_MAX], "dests": dd[:CONFLICT_DESTS_MAX]})


@dataclass(frozen=True)
class Terms:
    """What a continuity marker obliges a later proof to reach (R-H1/R-M2): the committed
    threshold, the known per-destination heads, the destinations mandatory at the restore, whether
    the known heads overflowed KNOWN_MAX (then nothing proves), and n of the restore. R5-H1:
    `unverified` = {destination: n} of a newer object a restore saw there and could not
    authenticate (also folded into `known` and `required`): while it is kept, no volume proof.
    R7-H1: `conflict` = the authenticated conflict record (None = none): while it is kept nothing
    lifts the quarantine; `rejected` = branch heads an Owner resolution rejected."""
    threshold: Head = EMPTY_HEAD
    known: dict = field(default_factory=dict)
    required: tuple = ()
    overflow: bool = False
    n: int = 0
    unverified: dict = field(default_factory=dict)
    conflict: dict = None
    rejected: tuple = ()


def terms_of(cont):
    """`Terms` of a continuity marker dict; JournalError when it cannot be read."""
    if type(cont) is not dict:
        raise JournalError("bad-state", "continuity")
    t = Head.from_json(cont["threshold"]) if "threshold" in cont else EMPTY_HEAD
    known = known_from_json(cont.get("known", {}))
    req = tuple(required_from_json(cont.get("required", [])))
    ovf = cont.get("overflow", False)
    r_n = cont.get("n", 0)
    unv = known_from_json(cont.get("unverified", {}))
    if type(ovf) is not bool or type(r_n) is not int or r_n < 0:
        raise JournalError("bad-state", "continuity")
    conf = conflict_from_json(cont["conflict"]) if cont.get("conflict") is not None else None
    rej = tuple(_head_list(cont.get("rejected", []), REJECTED_MAX))
    return Terms(t, known, req, ovf, r_n, unv, conf, rej)


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
    unverified: dict = field(default_factory=dict)      # R5-H1: din markerul viu
    conflict: dict = None                                # R7-H1: conflictul autentificat al markerului viu


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
                frozenset(terms.required), terms.overflow or known_overflow(known, terms.known),
                dict(terms.unverified), terms.conflict)


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
    damaged: Parsed = None         # R2-H1: prefixul autentic citit la un boot cu jurnal stricat (sau None)
    head_known: bool = True        # R2-H1: capul comis s-a putut citi din DB la boot
    cancelled: set = field(default_factory=set)       # R3-M1: sid-uri cu intenţia anulată în zbor
    cleanup: dict = field(default_factory=dict)       # R5-L1: sid → {tries, next}: curăţare fizică de reluat
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


def _destroy_sync(c, sid, head=None, clear_intent=True):
    """Erasure step 2 for one sid, inside the caller's transaction: live share and replay links
    revoked, RK destroyed, descriptors and gaps gone, generations → retired, head advanced
    (monotonic), and (R2-H1) the sid's erase intent cleared in the SAME transaction, unless
    `clear_intent` is False (the erasure has no journal entry yet). Returns the generations to
    retire."""
    c.execute("UPDATE sessions SET share_token=NULL, share_expires=NULL, share_writable=0 WHERE id=?", (sid,))
    c.execute("DELETE FROM replay_opens WHERE link_id IN (SELECT id FROM replay_links WHERE sid=?)", (sid,))
    c.execute("DELETE FROM replay_links WHERE sid=?", (sid,))
    gens = c.execute("SELECT gen_id, kind FROM tx_files WHERE sid=? AND state='published'", (sid,)).fetchall()
    c.execute("UPDATE tx_files SET state='retired' WHERE sid=? AND state='published'", (sid,))
    c.execute("DELETE FROM session_keys WHERE sid=?", (sid,))
    c.execute("DELETE FROM tx_descriptors WHERE sid=?", (sid,))
    c.execute("DELETE FROM tx_gaps WHERE sid=?", (sid,))
    c.execute("DELETE FROM tx_quarantine WHERE sid=?", (sid,))
    if clear_intent:
        _ensure_intent_table(c)
        c.execute("DELETE FROM tx_erase_intents WHERE sid=?", (sid,))
    if head is not None:
        cur = _get_json(c, "erasure_head")
        if cur is None or Head.from_json(cur).n < head.n:
            _set_json(c, "erasure_head", head.to_json())
    return [(g[0], g[1]) for g in gens]


# R2-H1: intenţia durabilă de ştergere. Un rând `tx_erase_intents` se comite (FULL fsync pe conexiunea
# Store-ului) ÎNAINTE de pasul 1 şi dispare doar în tranzacţia pasului 2. Un jurnal pierdut / stricat
# după fsync-ul intrării, dar înainte de COMMIT, nu mai poate ascunde ştergerea: boot-ul o duce la
# capăt din intenţie, iar recuperarea Owner refuză un sid cu intenţie.


def _ensure_intent_table(c):
    # DB-ul unui backup / volum mai vechi decât tabela: aceeaşi definiţie ca db.SCHEMA (aditiv)
    c.execute("CREATE TABLE IF NOT EXISTS tx_erase_intents (sid TEXT PRIMARY KEY, kinds TEXT NOT NULL, "
              "since REAL NOT NULL)")


def _put_intent_sync(c, sid, kinds, now):
    _ensure_intent_table(c)
    c.execute("INSERT INTO tx_erase_intents(sid, kinds, since) VALUES(?,?,?) ON CONFLICT(sid) DO NOTHING",
              (sid, ",".join(sorted(k for k in kinds if k in ("out", "cast"))), now))


def _intents_sync(c):
    """{sid: [kinds]} of every outstanding erase intent."""
    _ensure_intent_table(c)
    out = {}
    for sid, kinds in c.execute("SELECT sid, kinds FROM tx_erase_intents ORDER BY since, sid").fetchall():
        out[sid] = [k for k in (kinds or "").split(",") if k in ("out", "cast")]
    return out


def intents_in(db_path):
    """{sid: [kinds]} of the erase intents in the database at `db_path` (a live DB before a restore
    replaces it); {} without the table. An unreadable DB → sqlite3.Error (the caller refuses)."""
    con = sqlite3.connect(pathlib_uri(db_path), uri=True)
    try:
        try:
            rows = con.execute("SELECT sid, kinds FROM tx_erase_intents").fetchall()
        except sqlite3.OperationalError as e:
            # doar tabela lipsă (un DB mai vechi) = nicio intenţie; orice altă eroare → refuz
            if str(e) == "no such table: tx_erase_intents":
                return {}
            raise
    finally:
        con.close()
    return {sid: [k for k in (kinds or "").split(",") if k in ("out", "cast")]
            for sid, kinds in rows if type(sid) is str and re.fullmatch(r"[0-9a-f]{32}", sid)}


def carry_intents_sync(db_path, intents, now=None):
    """Restore apply (R2-H1): the live volume's outstanding erase intents are written into the
    restored database, so the boot that follows completes them (a restore never hides one)."""
    if not intents:
        return
    now = time.time() if now is None else now
    con = sqlite3.connect(str(db_path), isolation_level=None)
    try:
        con.execute("BEGIN IMMEDIATE")
        try:
            for sid, kinds in sorted(intents.items()):
                _put_intent_sync(con, sid, kinds, now)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
    finally:
        con.close()


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
    completed: list = field(default_factory=list)     # R2-H1: intenţii duse la capăt la boot


async def _complete_intents(st, intents, journalled, rep, clock):
    """Boot, healthy journal (R2-H1): an intent whose sid the journal holds is cleared (its DB step
    ran above); any other is an erasure whose entry was lost or never written: it is completed now
    (a new entry + step 2), or, while the journal is behind a restore's threshold (a new entry would
    fork it), destroyed in the database only with the intent kept for a later boot."""
    s = _s
    done = [sid for sid in intents if sid in journalled]
    if done:
        await st.txn(lambda c: [c.execute("DELETE FROM tx_erase_intents WHERE sid=?", (x,)) for x in done])
    for sid, kinds in intents.items():
        if sid in journalled:
            continue
        rep.completed.append(sid)
        if _behind() or s.parsed.n >= CAP or s.uncertain:
            await st.txn(lambda c, sid=sid: _destroy_sync(c, sid, clear_intent=False))
            continue
        env = await st.read(lambda c, sid=sid: c.execute("SELECT envelope FROM session_keys WHERE sid=?",
                                                         (sid,)).fetchone())
        try:
            async with st.barrier:
                await _journal_and_destroy(st, sid, kinds or ["out", "cast"], env, clock)
        except ErasureError as e:
            # incert: sid-ul rămâne tombstone în memorie, intenţia în DB; ştergerile se refuză
            log.warning("erasure boot: intent %s not completed: %s", sid[:8], e.code)
            try:
                await st.txn(lambda c, sid=sid: _destroy_sync(c, sid, clear_intent=False))
            except Exception as x:               # noqa: BLE001 — tombstone-ul din memorie rămâne
                log.warning("erasure boot: intent %s: RK not destroyed: %s", sid[:8], type(x).__name__)


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
    # R2-H1: intenţiile de ştergere se citesc înaintea jurnalului; fiecare sid numit nu mai e servit
    # de aici (fail closed), oricare ar fi starea jurnalului
    try:
        intents = await st.txn(_intents_sync)
    except (sqlite3.Error, txstore.Uncertain):
        intents = {}
        rep.diag = rep.diag or "db-intents"
    # R7-H1: tombstone-urile unui conflict autentificat păstrat de marker (orice ramură, chiar una
    # dispărută de atunci) sunt ştergeri cerute: intenţii durabile, duse la capăt ca oricare alta
    conf = _marker_conflict(cont if isinstance(cont, dict) else None)
    if conf is not None and not rep.diag.startswith("db-intents"):
        add = {sid: ["out", "cast"] for sid in conf["sids"] if sid not in intents}
        if add:
            now0 = clock()
            try:
                await st.txn(lambda c: [_put_intent_sync(c, x, k_, now0) for x, k_ in add.items()])
            except (sqlite3.Error, txstore.Uncertain):
                rep.diag = rep.diag or "db-intents"
            intents.update(add)
    st.tombstoned.update(intents)
    s.head_known = head is not None
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
        s.damaged = parsed
        # R2-H1: o intenţie fără pas DB confirmat se completează în DB (RK distrus), fără intrare de
        # jurnal (jurnalul stricat nu primeşte adăugări); intenţia rămâne: nu e jurnalizată
        for sid in intents:
            await st.txn(lambda c, sid=sid: _destroy_sync(c, sid, clear_intent=False))
            rep.completed.append(sid)
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
        await _complete_intents(st, intents, sids, rep, clock)
    # carantina de continuitate (restore fără dovadă): ce a marcat restore-ul rămâne în carantină
    if s.continuity and s.continuity.get("state") == "unproven":
        st.alarm("transcript.erasureUnproven", "erasures after %s cannot be proven" % s.continuity.get("since"))
    s.quarantine_pass = True
    s.booted = True
    return rep


# ── erase (§12.11.4 "Order of erase(sid)") ───────────────────────────────────


async def _journal_and_destroy(st, sid, kinds, env, clock, *, resuming=False):
    """Erasure steps 1–2 for `sid` (caller holds its lease AND the barrier): one journal entry
    (fsync within APPEND_BUDGET), the in-memory tombstone, then `_destroy_sync` in one transaction.
    → (n, generations to retire). Shared by `erase`, the Owner's discard of a failed migration, the
    boot's intents and `resume_intents` (`resuming`: the uncertain state it is resolving)."""
    s = _s
    # R-M1 (recheck): starea se reverifică SUB barieră; două cereri pot trece de _ready_or_raise
    # înainte ca prima să lase o stare incertă sau un prag nou
    if s.diag or s.parsed is None:
        raise ErasureError("transcript.erasureJournalBroken",
                           "the erasure journal is damaged (%s); erasure is refused" % (s.diag or "?"), 503)
    if s.uncertain and not resuming:
        raise ErasureError("transcript.erasureUncertain",
                           "an earlier erasure did not finish; restart the gateway first", 503)
    if _behind():
        raise ErasureError("transcript.erasureBehind",
                           "erasures committed before the last restore are not on this volume yet; "
                           "erasure is refused until they are proven", 409)
    if s.parsed.n >= CAP:
        raise ErasureError("transcript.erasureJournalFull",
                           "the erasure journal is full; erasure is refused until compaction", 507)
    prev = s.parsed.head
    n = prev.n + 1
    t_ms = int(clock() * 1000)
    rk_hash = keyring.envelope_hash(bytes(env[0])) if env is not None else b"\x00" * 32
    entry = encode_entry(s.journal.k, st.inst, prev.mac, n, t_ms, bytes.fromhex(sid),
                         kinds_bits(kinds), rk_hash)
    # R2-H1: intenţia durabilă ÎNAINTE de pasul 1 (o tranzacţie proprie, comisă): de aici un jurnal
    # pierdut nu mai poate ascunde ştergerea, boot-ul o completează din intenţie.
    # R3-M1: refuzul în memorie se pune ÎNAINTE ca intenţia să ajungă la writer-ul SQLite: o anulare
    # a cererii după COMMIT (Store.io aşteaptă firul, apoi propagă CancelledError) nu mai lasă
    # sid-ul citibil; se ridică doar după un ROLLBACK confirmat
    was = sid in st.tombstoned
    st.tombstone(sid)
    try:
        await st.io(st._run_txn, lambda c: _put_intent_sync(c, sid, kinds, clock()))
    except txstore.Uncertain:
        # poate fi comisă: sid-ul nu mai e servit, boot-ul decide (o intenţie comisă se completează)
        s.uncertain = "intent-uncertain"
        st.alarm("transcript.erasureUncertain", f"{sid}: erase intent commit uncertain")
        raise ErasureError("transcript.erasureUncertain",
                           "the erasure could not be recorded; restart the gateway", 503) from None
    except asyncio.CancelledError:
        # tranzacţia s-a terminat (comisă sau nu); intenţia, dacă e în DB, conduce ştergerea:
        # janitorul (resume_intents) o duce la capăt imediat, altfel boot-ul. Până atunci: refuz.
        if not resuming:
            s.uncertain = "intent-cancelled"
        if not was:
            s.cancelled.add(sid)
        st.alarm("transcript.erasureUncertain", f"{sid}: erase request cancelled at the intent commit")
        _kick()
        raise
    except Exception as x:
        # ROLLBACK confirmat: nimic scris, nimic jurnalizat; refuzul din memorie se ridică
        if not was:
            st.tombstoned.discard(sid)
        log.warning("erasure %s: intent not written: %s", sid[:8], type(x).__name__)
        raise ErasureError("transcript.erasureUnavailable", "the erasure could not be recorded", 503) from None
    st._fault("intent-committed")
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
    except asyncio.CancelledError:
        # R3-M1: intrarea e durabilă, pasul 2 comis sau nu; janitorul îl re-aplică din jurnal
        # (idempotent) şi recitește capul DB, apoi ridică starea incertă
        s.uncertain = "commit-cancelled"
        s.cancelled.add(sid)
        st.alarm("transcript.erasureUncertain", f"{sid}: erase request cancelled at step 2")
        _kick()
        raise
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


_RESUMABLE = ("intent-cancelled", "commit-cancelled")


async def resume_intents(st=None, *, clock=time.time):
    """R3-M1: finish what a cancelled erase request left (the janitor runs this as soon as it is
    woken; the boot does the same from the intents if the process dies first). For every sid whose
    request was cancelled at the intent or at step 2, decided from the database now that its
    transaction is over: an intent whose sid the journal holds → step 2 again (idempotent); an
    intent without an entry → steps 1–2; no intent and no entry → the transaction rolled back, the
    sid is served again. The DB head is re-read, and the uncertain state lifted only when every sid
    is settled. → True when lifted."""
    s = _s
    st = st or s.store
    if st is None or s.uncertain not in _RESUMABLE or s.diag or s.parsed is None:
        return False
    for sid in sorted(s.cancelled):
        # aceeaşi ordine ca erase (lease, apoi bariera): niciun deadlock cu o cerere în aşteptare
        async with st.lease(sid):
            erased = False
            async with st.barrier:
                if s.uncertain not in _RESUMABLE or s.diag or s.parsed is None:
                    return False

                def load(c, sid=sid):
                    try:
                        intent = c.execute("SELECT kinds FROM tx_erase_intents WHERE sid=?", (sid,)).fetchone()
                    except sqlite3.OperationalError as e:
                        if "no such table" not in str(e):
                            raise
                        intent = None
                    return intent, c.execute("SELECT envelope FROM session_keys WHERE sid=?", (sid,)).fetchone()
                intent, env = await st.read(load)
                entry = next((e for e in s.parsed.entries if e.sid_hex == sid), None)
                if entry is not None:
                    if intent is not None:
                        await st.io(st._run_txn, lambda c, sid=sid, e=entry:
                                    _destroy_sync(c, sid, Head(e.n, e.time_ms, e.mac)))
                    erased = True
                elif intent is not None:
                    kinds = [k for k in (intent[0] or "").split(",") if k in ("out", "cast")]
                    _n, _gens, confirmed = await _journal_and_destroy(
                        st, sid, kinds or ["out", "cast"], env, clock, resuming=True)
                    if not confirmed:
                        return False                   # COMMIT incert: rămâne pentru boot
                    erased = True
                else:
                    # ROLLBACK confirmat (niciun rând, nicio intrare): ştergerea n-a avut loc
                    st.tombstoned.discard(sid)
                if erased:
                    # R5-L1: sarcina de curăţare devine explicită ÎNAINTE ca sid-ul să iasă din
                    # `cancelled` (fără await între ele): o eroare de I/O nu o mai poate pierde
                    s.cleanup.setdefault(sid, {"tries": 0, "next": 0.0})
                s.cancelled.discard(sid)
    # R4-M1: curăţarea fizică a lui erase (pasul DB comis de cererea anulată sau re-aplicat aici),
    # după barieră; R5-L1: reîncercată de janitor cu backoff până reuşeşte
    await run_cleanup(st, clock=clock)
    async with st.barrier:
        if s.uncertain not in _RESUMABLE or s.cancelled:
            return False
        doc = await st.read(lambda c: _get_json(c, "erasure_head"))
        head = Head.from_json(doc) if doc is not None else EMPTY_HEAD
        if head.n > s.head_db.n:
            s.head_db = head
        s.uncertain = ""
    return True


async def run_cleanup(st=None, *, clock=time.time):
    """R4-M1 / R5-L1: unlink every `retired` generation of the sids an erase left to clean (a
    cancelled request finished by `resume_intents`), through `st.retire` (idempotent, defers a
    pinned generation). A sid stays in `s.cleanup` until its pass completes; an error (EIO, a full
    disk) keeps it with an exponential backoff, and from CLEANUP_ALARM_AFTER failures on it raises
    the `transcript.erasureCleanup` alarm every time. R6-L1: a generation a reader pins
    (`retire` → `deferred`) keeps the task too, re-checked after CLEANUP_BACKOFF without counting
    as a failure, so a failed unlink after the last unpin is retried here until the row is `gone`.
    The RK is already destroyed: this is only the files. → the sids still pending."""
    s = _s
    st = st or s.store
    if st is None:
        return sorted(s.cleanup)
    now = clock()
    for sid in sorted(s.cleanup):
        job = s.cleanup.get(sid)
        if job is None or job["next"] > now:
            continue
        deferred = False
        try:
            gens = await st.read(lambda c, sid=sid: c.execute(
                "SELECT gen_id, kind FROM tx_files WHERE sid=? AND state='retired'", (sid,)).fetchall())
            for hexid, kind in gens:
                # R6-L1: „deferred" = fişier fixat de un cititor; unlink-ul trece la ultimul unpin, dar
                # dacă acea sarcină eşuează nu o reia nimeni: sarcina rămâne până la rândul `gone`
                deferred = (await st.retire(sid, kind, hexid)) == "deferred" or deferred
        except asyncio.CancelledError:
            raise
        except Exception as e:                   # noqa: BLE001 — rămâne de făcut, cu backoff
            job["tries"] += 1
            job["next"] = clock() + _cleanup_delay(job["tries"])
            log.warning("erasure cleanup of %s failed (%d): %s", sid, job["tries"], type(e).__name__)
            if job["tries"] >= CLEANUP_ALARM_AFTER:
                st.alarm("transcript.erasureCleanup", "%s: the erased recording's files could not be "
                         "removed after %d attempts (%s)" % (sid, job["tries"], type(e).__name__))
            continue
        if deferred:
            job["next"] = clock() + CLEANUP_BACKOFF       # nu e un eşec: fără alarmă, re-verificat
            continue
        s.cleanup.pop(sid, None)
    return sorted(s.cleanup)


def _cleanup_delay(tries):
    """R6-L1: CLEANUP_BACKOFF doubled per failure, capped at CLEANUP_BACKOFF_MAX. The exponent is
    capped first: 30.0 * 2**1100 would overflow a float (OverflowError inside the error path)."""
    return min(CLEANUP_BACKOFF * (2.0 ** min(max(tries - 1, 0), 32)), CLEANUP_BACKOFF_MAX)


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
            # R4-H1: un read-back fără nicio intrare (doar antetul) nu atestă nimic
            if p.n < 1 or p.n != head.n or p.bad or not hmac.compare_digest(p.head.mac, head.mac):
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


async def fetch_head(d, k_erase, inst, check_from=None, ignore=()):
    """The newest authentic journal a destination holds for `inst`: (Parsed, bytes) or None when it
    holds none; raises on an unreachable destination. Objects are tried newest first.

    `check_from` (try_prove, H3/M1): EVERY object named above that n is read (at most
    PROVE_MAX_OBJECTS, else JournalError) and all the authentic ones must lie on one chain
    (ErasureConflict otherwise): after a restore our own uploads can be newer than the
    attestation of the dataset we were restored from, and a fork with it must not hide.

    R4-H1: an object with zero entries (a bare WTJ1 header carries no MAC) is never a journal: it
    proves nothing, not even n=0. R4-H2: an object that cannot be authenticated (bad header, bad
    MAC, partial, a name whose n does not match its entries) and is named above the best authentic
    one is a GAP, never skipped in favour of an older journal: `Unverifiable` (the destination
    answered, but proves nothing). One strictly below the authentic head is covered by it.

    R5-M1: numeric equality is not the same chain. Every object named at the best authentic n is
    read (all variants; one left unread for the budget is a gap → `Unverifiable`), two authentic
    ones that differ → ErasureConflict, and a damaged one AT that n is a gap too (`Unverifiable`).
    The authentic prefix of a damaged object is never a proof, but it is checked against the chain:
    a prefix on another branch → ErasureConflict (it may hold a tombstone or a fork).

    R7-H1: `ignore` = {(n, mac)} of branch heads an audited Owner resolution rejected (their
    tombstones are already erase intents): such an object is neither a candidate nor a gap. Any
    other authentic object still counts; a conflict carries its branches (`e.branches`)."""
    ignore = {(h.n, h.mac) for h in ignore}
    names = []
    for n in await d.list():
        p = parse_object_name(n)
        if p is not None and p[0] == bytes(inst):
            names.append((p[1], n))
    names.sort(reverse=True)
    if check_from is None:
        pick = names[:FETCH_MAX_OBJECTS]
    else:
        above = [x for x in names if x[0] > check_from]
        if len(above) > PROVE_MAX_OBJECTS:
            raise JournalError("too-many", "too many journal objects to check")
        pick = above + [x for x in names if x[0] <= check_from][:FETCH_MAX_OBJECTS]
    got = []
    prefixes = []                                 # R5-M1: prefixe autentice ale obiectelor defecte
    failed = 0                                    # cel mai mare n (din nume sau conţinut) neverificabil
    top_n = None                                  # n-ul celui mai nou obiect autentic (check_from=None)
    read = set()
    for _n, name in pick:
        if check_from is None and top_n is not None and _n < top_n:
            break                                 # toate variantele lui top_n au fost citite
        read.add(name)
        try:
            raw = bytes(await d.get(name))
            p = parse(raw, k_erase, inst)
        except JournalError:
            failed = max(failed, _n)
            continue
        if p.bad or p.n != _n:
            failed = max(failed, _n, p.n)         # neautentic sau nume minţit: nu e dovadă, e un gol
            if p.n:
                prefixes.append((name, p))        # dar intrările lui autentice se compară cu lanţul
            continue
        if p.n == 0:
            continue                              # R4-H1: doar antetul (fără MAC) — nicio dovadă
        if (p.head.n, p.head.mac) in ignore:
            continue                              # R7-H1: ramură respinsă de rezolvarea Owner-ului
        got.append((name, p, raw[:p.valid_len]))
        if top_n is None:
            top_n = _n
    try:
        best = _on_one_chain([(name, p) for name, p, _raw in got]) if got else None
        if prefixes:
            # R5-M1: un prefix autentic pe altă ramură = fork (poate ţine un tombstone), nu „acoperit"
            _on_one_chain([(name, p) for name, p, _raw in got] + prefixes)
    except ErasureConflict as e:
        # R6-H1: fork-ul poartă cel mai mare n listat (o ramură poate ţine o ştergere până acolo):
        # restore-ul îl păstrează ca gol (flag → marker), niciodată ca destinaţie doar „indisponibilă"
        e.n = max(x[0] for x in names)
        # R7-H1: ramurile autentice văzute (şi prefixele autentice ale obiectelor defecte) intră în
        # înregistrarea durabilă a conflictului; tombstone-urile lor se aplică la vedere
        e.branches = [p for _name, p, _raw in got] + [p for _name, p in prefixes]
        raise
    unread = [x[0] for x in names if best is not None and x[0] >= best[1].n and x[1] not in read]
    if unread:
        # R5-M1: o variantă a aceluiaşi n (sau mai nouă) necitită din buget poate fi altă ramură:
        # e un gol ca un obiect neverificabil (restore-ul îl păstrează), niciodată o alegere
        failed = max(failed, max(unread))
    if failed and failed >= (best[1].n if best else 0):
        raise Unverifiable(failed)                # R5-M1: un obiect defect la acelaşi n e tot un gol
    if best is None:
        return None
    return next((p, raw) for name, p, raw in got if name == best[0])


GAP_ERRORS = ("unverifiable", "conflict")   # R5-H1 / R6-H1: destinaţia a răspuns, dar ţine un gol


@dataclass
class DestResult:
    id: str
    ok: bool                       # a răspuns (nimic sau un jurnal autentic); False şi la R4-H2
    parsed: Parsed = None          # None = niciun jurnal autentic: o destinaţie GOALĂ nu e dovadă (M1)
    data: bytes = None
    error: str = ""
    unverified: int = 0            # R4-H2: n-ul unui obiect mai nou neverificabil (error='unverifiable');
    #                                R6-H1: la error='conflict' (fork), cel mai mare n listat acolo
    branches: list = field(default_factory=list)   # R7-H1: la error='conflict', ramurile autentice văzute


async def fetch_all(dests, k_erase, inst, check_from=None, ignore=()):
    out = []
    for d in dests:
        try:
            got = await fetch_head(d, k_erase, inst, check_from, ignore)
            out.append(DestResult(d.id, True, got[0] if got else None, got[1] if got else None))
        except ErasureConflict as e:
            n = getattr(e, "n", 0)
            log.warning("erasure: %s holds diverging erasure journals (fork)", d.id)
            # R6-H1: n ≥ 1 (un fork are intrări autentice); unul necunoscut tot gol rămâne
            out.append(DestResult(d.id, False, error="conflict", unverified=n if type(n) is int and n > 0 else 1,
                                  branches=list(getattr(e, "branches", None) or [])))
        except Unverifiable as e:
            log.warning("erasure: %s holds an unverifiable journal object n=%d", d.id, e.n)
            out.append(DestResult(d.id, False, error="unverifiable", unverified=e.n))
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
    unverified: dict = field(default_factory=dict)  # R5-H1: destinaţie → n al unui obiect neverificabil
    conflict: dict = None           # R7-H1: conflictul autentificat (fork văzut acum sau păstrat de un marker)

    def summary(self, since):
        out = {"state": self.state, "proof": self.proof, "since": int(since or 0), "n": self.head.n,
               "threshold": self.threshold.to_json(), "known": dict(self.known),
               "required": list(self.required), "overflow": bool(self.overflow),
               "unverified": dict(self.unverified)}
        if self.conflict is not None:
            out["conflict"] = self.conflict
        return out


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
    kept (`required`), and an overflow of known heads proves nothing.
    R5-H1: a destination holding a newer object that cannot be authenticated (a fresh result with
    error `unverifiable`, or one kept by a marker as `unverified`) may hold an erasure we do not
    have: its n is folded into the known heads and the destination becomes mandatory (a later
    proof needs an authentic copy there reaching it), the gap is kept in `unverified`, and while
    it is kept the VOLUME never proves (equal numbers are not the same chain). A fresh
    unverifiable result refuses every proof. R6-H1: a destination whose authentic objects diverge
    (error `conflict`, a fork `fetch_head` detected) is the same kind of gap, at the highest n it
    lists: kept in `unverified` (so in the flag and the marker), every proof refused."""
    live = live if live is not None else Live("none")
    staged = staged if staged is not None else Terms()
    same = live.state == "same"
    # R6-H1: un fork la o destinaţie (`conflict`) e un gol ca un obiect neverificabil: păstrat cu n-ul lui
    fresh_unver = {r.id: r.unverified for r in dest_results
                   if not r.ok and r.error in GAP_ERRORS and type(r.unverified) is int and r.unverified > 0}
    unver = merge_known(staged.unverified, live.unverified if same else None, fresh_unver)
    # R7-H1: conflictul autentificat (al backup-ului, al markerului viu, un fork văzut acum) se
    # păstrează întreg (capete + tombstone-uri), nu doar ca număr
    conflict = conflict_union(staged.conflict, live.conflict if same else None)
    for r in dest_results:
        if r.error == "conflict" and r.branches:
            conflict = merge_conflict(conflict, r.branches, [r.id])
    known = merge_known(known_attested, live.attested if same else None, staged.known, unver)
    overflow = (staged.overflow or (same and live.overflow)
                or known_overflow(known_attested, live.attested if same else None, staged.known, unver))
    t = merge_threshold(live.head if same else None, staged.threshold)
    required_all = (set(required_dests) | set(staged.required) | (set(live.required) if same else set())
                    | set(unver))
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
            unreachable.append(r.id)               # inclusiv R4-H2: un obiect mai nou neverificabil
            continue
        if r.parsed is not None and not r.parsed.n:
            # R4-H1: zero intrări = doar antetul, fără MAC; nu e jurnal, nu e dovadă (nici pentru n=0)
            r = DestResult(r.id, True, None, None)
            by_id[r.id] = r
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
        if r is None or not r.ok or r.parsed is None or r.parsed.n < 1 or d in rolled:
            return False
        need = max(known.get(d, 0), t.n, floor)
        return need >= 1 and r.parsed.n >= need and reaches(r.parsed, t)
    # R2-M2: un cap off-host cunoscut (şi al unei destinaţii retrase) peste pragul local e tot o
    # obligaţie: J_v dovedeşte doar dacă îl atinge şi pe el
    top = max([t.n] + list(known.values()))
    if not met or any(r.error in GAP_ERRORS for r in dest_results) or conflict is not None:
        proof = "none"                             # R5-H1 / R6-H1 / R7-H1: un gol, un fork (acum sau păstrat)
    elif live.state == "same" and pv is not None and reaches(pv, t) and pv.n >= top and not unver:
        proof = "volume"
    elif req and all(dest_ok(d) for d in req):
        proof = "destinations"
    else:
        proof = "none"
    tracked_any = (tracked or head.n > 0 or bool(known) or pv is not None or t.n > 0 or bool(fresh_unver)
                   or conflict is not None)
    state = "not-tracked" if not tracked_any else ("proven" if proof != "none" else "unproven")
    return Decision(state, proof, star_bytes if tracked_any else None, head, rolled, unreachable,
                    t, merge_known(known, observed), not met, sorted(required_all), overflow, unver, conflict)


def journal_reaches(raw, k_erase, inst, t):
    """`reaches` for journal bytes (None / unparsable = nothing)."""
    if raw is None:
        return t.n == 0
    try:
        return reaches(parse(raw, k_erase, inst), t)
    except JournalError:
        return t.n == 0


def reconcile_apply(*, k_erase, inst, staged_journal=None, live_journal=None, stage_summary=None,
                    threshold=EMPTY_HEAD, live_ok=False, known=None, unverified=None, conflict=None):
    """The same reconciliation again under the boot lock, immediately before apply: the staged J*
    and the live journal must lie on one chain; the longer one is published. Returns (journal bytes
    to publish or None, proven, head).

    Proof at apply (H1/M1) is the VOLUME only, re-checked now: `live_ok` = the live database is of
    the same installation and readable, `threshold` = the highest committed head known (the stage's
    and the live database's now); J_v must hold it and so must the journal published. A proof by
    destinations at stage is not re-verifiable here: it never lifts the quarantine (the janitor's
    `try_prove` re-fetches them). R2-M2: `known` = the per-destination heads kept (a retired
    destination's too): J_v and the published journal must reach the highest of them as well.
    R5-H1: `unverified` = the gaps kept from the stage, the flag or the live marker (a destination
    holding a newer object nobody could authenticate): while there is one, nothing is proven here
    (the quarantine stays, and only the janitor's `try_prove` lifts it once that destination
    answers with an authentic journal reaching it)."""
    unverified = merge_known(unverified)
    known = merge_known(known, unverified)
    top = max([threshold.n] + list(known.values()))
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
    proven = (live_ok and pv is not None and reaches(pv, threshold) and reaches(final, threshold)
              and pv.n >= top and final.n >= top)
    if (stage_summary or {}).get("state") == "not-tracked" and head.n == 0 and top == 0:
        proven = True                              # nimic urmărit nicăieri: nimic de dovedit
    if unverified or conflict:
        proven = False                             # R5-H1 / R7-H1: un gol sau un conflict nu e acoperit de J_v
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
                       required=None, overflow=False, unverified=None, conflict=None):
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
            if unverified:
                mark["unverified"] = known_from_json(unverified)   # R5-H1: golul rămâne în marker
            if conflict:
                # R7-H1: conflictul autentificat (ramuri + tombstone-uri) rămâne în marker; boot-ul
                # transformă tombstone-urile lui în intenţii de ştergere
                mark["conflict"] = conflict_from_json(conflict)
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
    top = max([terms.threshold.n] + list(terms.known.values()) + list(terms.unverified.values()))
    return not reaches(s.parsed, terms.threshold) or s.parsed.n < top


def _marker_conflict(cont):
    """R7-H1: the authenticated conflict record a continuity marker keeps, or None. A marker that
    cannot be read is handled as unreadable by every caller (no proof), not as "no conflict"."""
    if not cont or cont.get("state") != "unproven":
        return None
    terms = _marker_terms(cont)
    return terms.conflict if terms is not None else None


def conflict_open():
    """R7-H1: an authenticated conflict is recorded and not resolved (System health, release)."""
    return _marker_conflict(_s.continuity) is not None


# INV-14 (docs/design/INVARIANTS.md): o ştergere de pe orice ramură autentică a jurnalului câştigă — se aplică
# imediat şi nimic nu ridică automat carantina cât istoria e nedovedită sau ramificată.
async def _record_conflict_locked(st, branches, dests, gaps, msg, clock=time.time):
    """R7-H1, caller holds the barrier: an authentic fork seen now (`branches`: authentic Parsed, at
    `dests`; `gaps` = {destination: highest n listed} for a fork AT a destination) is made durable
    in the continuity marker (created when there is none: a fork means continuity is unproven), and
    every tombstone of every branch is applied at once: in-memory tombstone, RK destroyed, and a
    durable erase intent for each sid the local journal does not hold yet (when the recording still
    has a key or a descriptor, or the sid is erased after the fork point) — an erasure on ANY
    authentic branch wins, also after that branch disappears. Returns the generations to retire."""
    s = _s
    s.conflict = (msg or "erasure journals diverge")[:300]
    st.alarm("transcript.erasureConflict", s.conflict)
    branches = [p for p in branches if p is not None and p.n > 0]
    cont = s.continuity if s.continuity and s.continuity.get("state") == "unproven" else None
    terms = _marker_terms(cont) if cont is not None else Terms()
    new_cont = None
    rec = None
    if terms is not None:
        rec = merge_conflict(terms.conflict, branches, list(dests) + list(gaps or {}))
    if terms is not None and (cont is not None or rec is not None):
        # fără ramuri autentice divergente (ex.: alt MAC doar la capul comis) nu se creează un marker
        new_cont = dict(cont) if cont is not None else {"state": "unproven", "since": int(clock()),
                                                        "n": s.head_db.n}
        if cont is None and s.head_db.n:
            new_cont["threshold"] = s.head_db.to_json()
        if rec is not None:
            new_cont["conflict"] = rec
        if gaps:
            # R6-H1: un fork la o destinaţie e şi un gol la cel mai mare n listat (obligatoriu)
            new_cont["unverified"] = merge_known(terms.unverified, gaps)
            req = sorted(set(terms.required) | set(gaps))
            if len(req) > KNOWN_MAX:
                new_cont["overflow"] = True
                req = req[:KNOWN_MAX]
            new_cont["required"] = req
    tomb = branch_sids(branches)
    journalled = {e.sid_hex for e in s.parsed.entries} if s.parsed is not None else set()
    # toate sid-urile de după punctul de fork (nu doar cele încăpute în înregistrare): intenţii
    divergent = ({e.sid_hex for p in branches for e in p.entries[_fork_base(branches):]}
                 if len(branches) >= 2 else set())
    for sid in sorted(tomb - st.tombstoned):
        st.tombstone(sid)                          # memoria întâi (fail closed)
        st.drop_key(sid)
    created = cont is None and new_cont is not None
    plain = await st.io(_plain_cohort_fd, st.dir_fd) if created else ()
    now = clock()

    def fn(c):
        have = ({r[0] for r in c.execute("SELECT sid FROM session_keys").fetchall()}
                | {r[0] for r in c.execute("SELECT sid FROM tx_descriptors").fetchall()})
        out = []
        for sid in sorted((tomb - journalled) & (have | divergent)):
            _put_intent_sync(c, sid, ("out", "cast"), now)
        for sid in sorted(tomb & have):
            out += [(sid, kind, hexid) for hexid, kind in _destroy_sync(c, sid, clear_intent=False)]
        if created:
            _quarantine_cohort_sync(c, "continuity", now, plain)
        if new_cont is not None:
            _set_json(c, "continuity", new_cont)
        return out
    try:
        gens = await st.io(st._run_txn, fn)
    except txstore.Uncertain:
        # rezultat necunoscut: memoria ţine starea mai strictă; următoarea observare o rescrie
        log.warning("erasure: the conflict record did not commit (uncertain)")
        gens = []
    if new_cont is not None:
        s.continuity = new_cont
    return gens


async def _record_conflict(st, branches, dests, gaps, msg):
    """`_record_conflict_locked` under the barrier, then the generations retired."""
    async with st.barrier:
        gens = await _record_conflict_locked(st, branches, dests, gaps, msg)
    for sid, kind, hexid in gens:
        await st.retire(sid, kind, hexid)
    st.bump(None)


async def try_prove(st=None):
    """With every required destination answering an authentic, non-rolled-back head on our chain
    that reaches what was known at the restore (the marker's threshold and per-destination heads):
    apply the tombstones the volume does not have and lift the continuity quarantine.

    H3: the decision is taken again UNDER the barrier against the journal as it is now (CAS on the
    file and on `s.parsed`): an erasure appended while we fetched is on the volume journal, and a
    destination chain that does not extend it is a fork → nothing adopted, quarantine kept. The
    adoption (journal replace + in-memory tombstones) and ONE transaction (destroy every new sid,
    advance the DB head monotonically, lift) run in the same critical section as erase's append.

    R7-H1: any fork seen (at a destination, between destinations, or with the volume) is recorded
    durably with its branches and tombstones (`_record_conflict`); while the marker keeps a conflict
    record nothing is lifted here, even when a branch later disappears from the listing. Only an
    Owner resolution (`resolve_conflict`) or the retire of the forking destination clears it."""
    s = _s
    st = st or s.store
    if st is None or s.diag or s.uncertain or s.parsed is None or not s.continuity:
        return False
    cont = s.continuity
    terms = _marker_terms(cont)
    if terms is None or terms.overflow:
        return False                               # R-M2: obligaţii pierdute = nicio dovadă
    # R5-H1: golul păstrat de restore e o obligaţie: destinaţia lui trebuie să răspundă acum cu un
    # jurnal autentic care îl atinge (fetch-ul citeşte tot ce e peste r_n; obiectul defect → nicio dovadă)
    t, known, r_n = terms.threshold, merge_known(terms.known, terms.unverified), terms.n
    dests = await destinations()
    if not dests:
        return False
    k = s.journal.k
    results = await fetch_all(dests, k, st.inst, check_from=r_n, ignore=terms.rejected)
    forks = [r for r in results if r.error == "conflict"]
    if forks:
        await _record_conflict(st, [p for r in forks for p in r.branches], [], {r.id: r.unverified for r in forks},
                               "erasure journals at %s diverge" % forks[0].id[:120])
        return False
    if terms.conflict is not None:
        # R7-H1: un fork autentificat odată rămâne conflict, chiar dacă o ramură a dispărut
        s.conflict = s.conflict or "an erasure journal fork is recorded; an Owner must resolve it"
        return False
    try:
        dec = decide_restore(k_erase=k, inst=st.inst, j_b=None, tracked=True, j_v=None,
                             # R-M2: destinaţiile obligatorii la restore rămân obligatorii chiar
                             # dacă au dispărut din configurare (nu le putem citi → nicio dovadă)
                             dest_results=results,
                             required_dests=(set(d.id for d in dests) | set(terms.required)
                                             | set(terms.unverified)),
                             known_attested=known, live=Live("same", t, {}), mode="prove")
    except ErasureConflict as e:
        ok = [r for r in results if r.ok and r.parsed is not None]
        await _record_conflict(st, [r.parsed for r in ok], [r.id for r in ok], {}, str(e))
        return False
    s.rolled_back = set(dec.rolled_back)
    if dec.proof != "destinations":
        return False
    star = parse(dec.journal, k, st.inst) if dec.journal else None
    gens = []
    fork_gens = None
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
            # o ştergere locală (după restore sau concurentă) şi o ramură a destinaţiei: oprim şi
            # păstrăm conflictul (R7-H1) cu ambele ramuri
            fork_gens = await _record_conflict_locked(
                st, [cur, star], [r.id for r in results if r.ok and r.parsed is not None], {}, str(e))
        if fork_gens is None:
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
    for sid, kind, hexid in (fork_gens if fork_gens is not None else gens):
        await st.retire(sid, kind, hexid)
    st.bump(None)
    return fork_gens is None


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


async def _set_status(st, sid, frm, to, *, allowed=_continuity_only, need_key=False, guard=None):
    txstore._sid_bytes(sid)
    if sid in st.tombstoned:
        raise ErasureError("transcript.missing", "no recording for this session", 404)
    async with st.lease(sid):
        async with st.revoking(sid):
            def fn(c):
                if guard is not None:
                    guard(c)
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


def _refuse_on_conflict():
    """R7-H1: while an authenticated conflict is recorded no recovery path opens anything."""
    if conflict_open():
        raise ErasureError("transcript.recoveryConflict",
                           "the erasure journals diverge (a fork is recorded); recovery is refused until "
                           "an Owner resolves it", 409)


async def recover(st, sid):
    """quarantined (continuity) → recovery: readable by Owners only, through the recovery route.
    R7-H1: refused while an authenticated conflict is recorded (re-checked in the transaction)."""
    _refuse_on_conflict()
    cont0 = _s.continuity

    def guard(_c):
        if _s.continuity is not cont0:
            raise ErasureError("transcript.recoveryState", "the continuity state changed; try again", 409)
        _refuse_on_conflict()
    return await _set_status(st, sid, "quarantined", "recovery", guard=guard)


async def recover_journal(st, sid, diag):
    """Owner decision 2026-11-26: quarantined (`journal:<diag>`) → recovery, one recording, only
    while this boot's journal diagnosis is exactly `diag` (the one System health shows). A sid the
    authentic part of the journal tombstones, or whose RK is gone (an erasure committed in the
    database), is never recovered: there is nothing left to decrypt."""
    if not diag or journal_diag() != diag or not health_has("erasure_journal_broken"):
        raise ErasureError("transcript.journalNotDiagnosed",
                           "System health does not show this erasure journal diagnosis", 409)
    txstore._sid_bytes(sid)
    s = _s
    if sid in st.tombstoned:
        raise ErasureError("transcript.missing", "no recording for this session", 404)
    _refuse_on_conflict()
    intent, key = await st.read(lambda c: (
        _has_intent(c, sid), c.execute("SELECT 1 FROM session_keys WHERE sid=?", (sid,)).fetchone() is not None))
    if intent:
        raise ErasureError("transcript.recoveryErasePending",
                           "an erasure of this recording was requested and may be journalled; "
                           "it is never recovered", 409)
    if not key:
        raise ErasureError("transcript.recoveryNoKey",
                           "this recording's key was destroyed; it cannot be recovered", 409)
    head0, dmg0, cont0 = s.head_db, s.damaged, s.continuity
    # R2-H1: dovada se ia ÎN AFARA barierei (I/O off-host), apoi se re-verifică sub ea
    await _journal_recovery_proof(st, sid)
    want = "journal:" + diag

    def guard(c):
        if (journal_diag() != diag or s.head_db is not head0 or s.damaged is not dmg0
                or s.continuity is not cont0 or sid in st.tombstoned):
            raise ErasureError("transcript.recoveryState", "the erasure journal state changed; try again", 409)
        _refuse_on_conflict()
        if _has_intent(c, sid):
            raise ErasureError("transcript.recoveryErasePending",
                               "an erasure of this recording was requested and may be journalled; "
                               "it is never recovered", 409)
    return await _set_status(st, sid, "quarantined", "recovery",
                             allowed=lambda r: r == want, need_key=True, guard=guard)


def _has_intent(c, sid):
    try:
        return c.execute("SELECT 1 FROM tx_erase_intents WHERE sid=?", (sid,)).fetchone() is not None
    except sqlite3.OperationalError:
        return True                                # tabela nu se poate citi: fail closed


def _known_top():
    """R2-H1: the highest erasure head this volume knows was committed or held anywhere: the DB
    head, every attested head, the continuity marker's threshold and known heads. None = a source
    that cannot be read (fail closed: nothing proves the gap closed)."""
    s = _s
    if not s.head_known:
        return None
    top = s.head_db.n
    for v in (s.attested or {}).values():
        if not isinstance(v, dict) or type(v.get("n", 0)) is not int:
            return None
        top = max(top, v.get("n", 0))
    if s.continuity and s.continuity.get("state") == "unproven":
        terms = _marker_terms(s.continuity)
        if terms is None:
            return None
        top = max([top, terms.threshold.n] + list(terms.known.values()) + list(terms.unverified.values()))
    return top


def _recovery_heads():
    """R3-H2: the committed heads (n AND MAC) a `journal:*` recovery proof must reach: the DB head
    and, while a restore is unproven, the continuity marker's threshold. None = the marker cannot be
    read or its known heads overflowed (fail closed: nothing proves)."""
    s = _s
    heads = [s.head_db]
    if s.continuity and s.continuity.get("state") == "unproven":
        terms = _marker_terms(s.continuity)
        if terms is None or terms.overflow:
            return None
        heads.append(terms.threshold)
    return [h for h in heads if h.n]


def _required_dest_ids():
    """The destinations a restore made mandatory (the continuity marker), even if gone since."""
    s = _s
    if s.continuity and s.continuity.get("state") == "unproven":
        terms = _marker_terms(s.continuity)
        if terms is not None:
            return set(terms.required) | set(terms.unverified)
    return set()


async def _journal_recovery_proof(st, sid):
    """R2-H1 / R3-H1 / R3-H2: before a `journal:*` recovery, an AUTHENTIC OFF-HOST proof, on every
    path (also when nothing was ever committed, or when the local prefix looks complete: neither
    authenticates a history whose journal is damaged). In this order:

    * no destination configured (nor required by a restore) → `recoveryNoDestination`;
    * the configuration or any configured / required destination cannot be read →
      `recoveryUnreachable` (it may hold the tombstone);
    * the authentic journals read (every destination's, the readable local prefix) must lie on ONE
      chain, and none may hold a different MAC at a required head's n (the DB head, the marker's
      threshold) → `recoveryConflict` (signalled), never a numeric choice;
    * an authentic tombstone of `sid` in any of them → `recoveryTombstoned`;
    * a destination holds an object above its best authentic journal that cannot be authenticated
      (R4-H2) → `recoveryGap` (it may hold the tombstone);
    * no destination holds an authentic journal → `recoveryNoJournal` (an empty listing, or an
      object with zero entries — a bare header carries no MAC — proves nothing, R4-H1);
    * at least one destination's authentic chain must reach every required head (n + MAC) and the
      highest head known anywhere (attested, marker's known heads) → else `recoveryGap`. A marker
      that cannot be read, or whose known heads overflowed, is a gap too."""
    s = _s
    top = _known_top()
    heads = _recovery_heads()
    if top is None or heads is None:
        raise ErasureError("transcript.recoveryGap",
                           "the committed erasure head cannot be read; recovery is refused", 409)
    k = s.journal.k
    try:
        dests = list(await _dest_provider()) if _dest_provider is not None else []
    except Exception as e:                       # noqa: BLE001 — configurare ilizibilă ≠ „nicio destinaţie"
        log.warning("erasure: destinations unavailable: %s", type(e).__name__)
        raise ErasureError("transcript.recoveryUnreachable",
                           "the backup destinations cannot be read; recovery is refused", 409) from None
    missing = _required_dest_ids() - {d.id for d in dests}
    if not dests and not missing:
        raise ErasureError("transcript.recoveryNoDestination",
                           "no backup destination holds an off-host erasure journal; a recording "
                           "quarantined for a damaged journal cannot be recovered without one", 409)
    results = await fetch_all(dests, k, st.inst, check_from=top) if dests else []
    forks = [r.id for r in results if r.error == "conflict"]
    # R4-H1: un jurnal fără intrări (antet fără MAC) nu e niciodată dovadă
    good = [r for r in results if r.ok and r.parsed is not None and r.parsed.n > 0]
    local = s.damaged
    try:
        if forks:
            raise ErasureConflict("erasure journals at %s diverge" % forks[0][:120])
        # R3-H2: sursele off-host se compară şi cu prefixul local lizibil, nu doar între ele
        _on_one_chain([(r.id, r.parsed) for r in good]
                      + ([("volume", local)] if local is not None and local.n else []))
        for r in good:
            for h in heads:
                if r.parsed.n >= h.n and not hmac.compare_digest(r.parsed.entries[h.n - 1].mac, h.mac):
                    raise ErasureConflict("the erasure journal at %s holds another entry n=%d than the "
                                          "committed one" % (r.id[:120], h.n))
    except ErasureConflict as e:
        # R7-H1: ramurile autentice văzute rămân durabile (marker), tombstone-urile lor aplicate
        fork_rs = [r for r in results if r.error == "conflict"]
        await _record_conflict(st, [r.parsed for r in good] + [p for r in fork_rs for p in r.branches]
                               + ([local] if local is not None and local.n else []),
                               [r.id for r in good], {r.id: r.unverified for r in fork_rs}, str(e))
        raise ErasureError("transcript.recoveryConflict",
                           "the erasure journals diverge; recovery is refused", 409) from None
    b = bytes.fromhex(sid)
    if any(e.sid == b for r in good for e in r.parsed.entries):
        raise ErasureError("transcript.recoveryTombstoned",
                           "an off-host erasure journal erases this recording; it is never recovered", 409)
    # R4-H2: un obiect mai nou decât jurnalul autentic al destinaţiei, care nu se poate autentifica,
    # poate ţine tocmai tombstone-ul căutat: gol în dovadă, niciodată coborât la copia mai veche
    unver = [r for r in results if r.error == "unverifiable"]
    if unver:
        raise ErasureError("transcript.recoveryGap",
                           "the backup destination %s holds an erasure journal object (n=%d) that cannot "
                           "be authenticated; recovery is refused until it is readable or removed"
                           % (unver[0].id[:120], unver[0].unverified), 409)
    down = sorted(missing) + [r.id for r in results if not r.ok]
    if down:
        raise ErasureError("transcript.recoveryUnreachable",
                           "the backup destination %s cannot be read; recovery is refused" % down[0][:120], 409)
    if not good:
        raise ErasureError("transcript.recoveryNoJournal",
                           "no backup destination holds an authentic erasure journal; recovery is refused", 409)
    if any(all(reaches(r.parsed, h) for h in heads) and r.parsed.n >= top for r in good):
        return
    raise ErasureError("transcript.recoveryGap",
                       "erasures up to n=%d are not readable on any reachable destination; "
                       "recovery is refused until they are" % top, 409)


async def release(st, sid):
    """recovery → ok (one recording, an explicit Owner action). Refused while the local journal is
    behind the restore's threshold (R-H1, "quarantine instead of refuse"): a committed erasure we
    cannot see yet may name this recording, so it may not become normally readable; the audited
    Owner recovery read (`recover`) stays the exceptional access. A recording recovered from a
    `journal:*` quarantine is never released: the erasures it may be named in are unknowable.

    R6-H2: a local journal that reaches the marker's numbers is not a proof of continuity. While
    the marker still owes OFF-HOST proof (a kept gap `unverified`, a mandatory destination in
    `required`, an overflow of known heads) or a fork was seen (`conflict`), release answers
    `transcript.releaseUnproven`: only `try_prove` (that destination answers with an authentic
    chain reaching the head, which lifts the whole marker) or the audited `retire_destination`
    clears that obligation. Checked before, and again in the transaction that changes the status."""
    _release_check()
    cont0 = _s.continuity

    def guard(_c):
        if _s.continuity is not cont0:
            raise ErasureError("transcript.recoveryState", "the continuity state changed; try again", 409)
        _release_check()

    def allowed(reason):
        if (reason or "").startswith("journal:"):
            raise ErasureError("transcript.releaseJournal",
                               "a recording recovered from a damaged erasure journal stays in recovery", 409)
        return reason == "continuity"
    return await _set_status(st, sid, "recovery", "ok", allowed=allowed, guard=guard)


def _release_check():
    """The release refusals (R-H1 behind, R6-H2 an off-host obligation still owed or a fork seen)."""
    if _behind():
        raise ErasureError("transcript.releaseBehind",
                           "erasures committed before the last restore are not on this volume yet; "
                           "the recording stays in recovery until they are proven", 409)
    s = _s
    owed = bool(s.conflict) or conflict_open()     # R7-H1: conflictul durabil, nu doar cel din memorie
    if s.continuity and s.continuity.get("state") == "unproven":
        terms = _marker_terms(s.continuity)
        # R6-H2: poziţia numerică (_behind) nu e dovadă: obligaţia off-host o ridică doar try_prove
        # sau retragerea auditată (un marker ilizibil e deja „behind")
        owed = owed or terms is None or terms.overflow or bool(terms.unverified) or bool(terms.required)
    if owed:
        raise ErasureError("transcript.releaseUnproven",
                           "a backup destination still owes proof of the erasures after the last restore "
                           "(or holds diverging journals); the recording stays in recovery until it is "
                           "proven or that destination is retired", 409)


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


def _configured_in_txn(c):
    """R2-M1: the destination configured NOW, read inside the marker's transaction (BEGIN IMMEDIATE:
    a concurrent settings save commits before it, and is seen, or after it)."""
    try:
        cfg = dict(c.execute("SELECT key, value FROM app_settings WHERE key LIKE 'cloud_%'").fetchall())
    except sqlite3.OperationalError:
        return None                                # nu se poate citi: refuz (apelantul)
    did = dest_id_from_settings({k: v or "" for k, v in cfg.items()})
    return {did} if did else set()


def _audit_sync(c, row):
    c.execute("INSERT INTO audit_log(ts, actor, ip, method, path, status, detail, actor_id, via) "
              "VALUES(?,?,?,?,?,?,?,?,?)",
              (row["ts"], (row.get("actor") or "")[:200], (row.get("ip") or "")[:64], row.get("method", "POST"),
               (row.get("path") or "")[:400], int(row.get("status", 200)), (row.get("detail") or "")[:500],
               row.get("actor_id"), (row.get("via") or "")[:64]))


async def retire_destination(st, dest_id, *, audit_row):
    """Remove `dest_id` from the continuity marker's `required` set (R-M2), an audited Owner
    override for a destination that no longer exists. The quarantine stays; its known head stays
    too (a proof must still reach the highest head that destination was known to hold, so retiring
    it never forgets an erasure it was known to have). Refused for a destination that is still
    configured: `try_prove` requires every configured destination anyway, so retiring it would
    change nothing; remove it from the backup settings first.

    R2-M1: the configuration is checked again inside the marker's transaction, and `audit_row`
    (the route's actor / ip / path) is written to `audit_log` in that SAME transaction, with the
    destination's known head: a retirement is never durable without its audit trail. The audit row
    is mandatory (recheck 6678938): a caller without one is refused before anything changes."""
    if not isinstance(audit_row, dict) or not audit_row.get("ts"):
        raise ValueError("retire_destination needs the audit row of the Owner's request")
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
        known_head = max(terms.known.get(dest_id, 0), terms.unverified.get(dest_id, 0))
        if dest_id in terms.unverified:
            # R5-H1: golul unei destinaţii retrase rămâne obligaţie (cap cunoscut), dar nu o mai cere
            new["known"] = merge_known(terms.known, {dest_id: known_head})
            unv = {d: n for d, n in terms.unverified.items() if d != dest_id}
            if unv:
                new["unverified"] = unv
            else:
                new.pop("unverified", None)

        # R7-H1: retragerea destinaţiei care a arătat fork-ul o scoate din conflict; când nu mai
        # rămâne nicio destinaţie, conflictul se închide, iar tombstone-urile lui rămân intenţii
        # de ştergere durabile (scrise din nou în aceeaşi tranzacţie)
        conf = terms.conflict
        closed = ()
        if conf is not None and dest_id in conf["dests"]:
            left_d = [d for d in conf["dests"] if d != dest_id]
            if left_d:
                new["conflict"] = dict(conf, dests=left_d)
            else:
                new.pop("conflict", None)
                journalled = {e.sid_hex for e in s.parsed.entries} if s.parsed is not None else set()
                closed = [x for x in conf["sids"] if x not in journalled]
        now = time.time()

        def fn(c):
            now_cfg = _configured_in_txn(c)
            if now_cfg is None or dest_id in now_cfg:
                raise ErasureError("transcript.destinationConfigured",
                                   "this destination is still configured; remove it from the backup "
                                   "settings first", 409)
            for x in closed:
                _put_intent_sync(c, x, ("out", "cast"), now)
            _set_json(c, "continuity", new)
            _audit_sync(c, dict(audit_row, detail="owner override: erasure destination %s retired from "
                                "the continuity proof (known head %d, threshold n=%d%s; durable record)"
                                % (dest_id[:120], known_head, terms.threshold.n,
                                   "; erasure conflict closed, %d tombstone(s) kept" % len(conf["sids"])
                                   if conf is not None and "conflict" not in new else "")))
        try:
            await st.io(st._run_txn, fn)
        except txstore.Uncertain:
            # rezultat necunoscut: markerul în memorie rămâne cel vechi (mai strict); boot-ul îl
            # citeşte din DB oricum ar fi fost
            raise ErasureError("transcript.erasureUncertain",
                               "the change did not finish; restart the gateway", 503) from None
        s.continuity = new
        if conf is not None and "conflict" not in new:
            s.conflict = ""                        # R7-L1: diagnosticul se închide cu conflictul durabil
    return {"required": left, "known_head": known_head,
            "conflict_closed": conf is not None and "conflict" not in new}


# ── Owner resolution of an authenticated conflict (R7-H1) ────────────────────


def journal_bytes(inst, p, n):
    """The WTJ1 bytes of the first `n` entries of the authentic prefix `p` (re-encoded as read)."""
    return header(inst) + b"".join(_BODY.pack(e.n, e.time_ms, bytes(e.sid), e.kinds, bytes(e.rk_hash)) + e.mac
                                   for e in p.entries[:n])


async def resolve_conflict(st, n, mac_hex, *, audit_row):
    """R7-H1: the audited Owner resolution of a recorded erasure conflict. The Owner names one
    authentic branch head (n + MAC) visible NOW (at a destination, or the volume's own journal).
    Every configured and required destination must answer; any branch newly visible joins the record
    first (its tombstones applied). The chosen journal must be the newest head of its line, reach
    every common prefix of the record and the marker's threshold, erase EVERY sid erased on any
    branch, and lie on one chain with the volume journal; otherwise `conflictMissingTombstone` /
    `conflictBranchUnknown`, nothing changed. Then, under the barrier (CAS on the marker and the
    journal file) and in ONE transaction with the audit row: the chosen journal adopted (its new
    tombstones destroyed), the conflict record removed, every other visible branch head kept as
    `rejected` (later fetches skip exactly those objects), and for the destinations of the record
    the gap at the fork's n replaced by the adopted head. The continuity quarantine itself stays:
    the next `try_prove` lifts it once every destination proves the adopted chain."""
    if not isinstance(audit_row, dict) or not audit_row.get("ts"):
        raise ValueError("resolve_conflict needs the audit row of the Owner's request")
    s = _s
    cont = s.continuity
    terms = _marker_terms(cont) if cont and cont.get("state") == "unproven" else None
    if terms is None or terms.conflict is None:
        raise ErasureError("transcript.conflictNone", "no erasure conflict is recorded", 404)
    if s.diag or s.parsed is None:
        raise ErasureError("transcript.erasureJournalBroken",
                           "the erasure journal is damaged (%s); a conflict cannot be resolved" % (s.diag or "?"), 503)
    if s.uncertain:
        raise ErasureError("transcript.erasureUncertain", "an erasure did not finish; restart the gateway", 503)
    if type(n) is not int or n < 1 or type(mac_hex) is not str or not re.fullmatch(r"[0-9a-f]{64}", mac_hex):
        raise ErasureError("transcript.conflictBranchUnknown", "name a branch head (n and MAC)", 409)
    want = bytes.fromhex(mac_hex)
    k = s.journal.k
    try:
        dests = list(await _dest_provider()) if _dest_provider is not None else []
    except Exception as e:                       # noqa: BLE001 — configurare ilizibilă = refuz
        log.warning("erasure: destinations unavailable: %s", type(e).__name__)
        raise ErasureError("transcript.conflictUnproven",
                           "the backup destinations cannot be read; the conflict stays", 409) from None
    missing = sorted((set(terms.required) | set(terms.unverified) | set(terms.conflict["dests"]))
                     - {d.id for d in dests})
    results = await fetch_all(dests, k, st.inst, check_from=0, ignore=terms.rejected) if dests else []
    down = missing + [r.id for r in results if not r.ok and r.error != "conflict"]
    if down:
        raise ErasureError("transcript.conflictUnproven",
                           "the backup destination %s cannot be read completely; the conflict stays (retire "
                           "a destination that is gone)" % down[0][:120], 409)
    fork_rs = [r for r in results if r.error == "conflict"]
    ok_rs = [r for r in results if r.ok and r.parsed is not None and r.parsed.n]
    seen = ([r.parsed for r in ok_rs] + [p for r in fork_rs for p in r.branches]
            + ([s.parsed] if s.parsed.n else []))
    if not all(_same_chain(a, b) for a in seen for b in seen):
        # o ramură nouă vizibilă acum intră în înregistrare înainte de alegere (tombstone-uri aplicate)
        await _record_conflict(st, seen, [r.id for r in ok_rs], {r.id: r.unverified for r in fork_rs},
                               "erasure journals diverge (seen at the Owner resolution)")
    cont = s.continuity
    terms = _marker_terms(cont) if cont and cont.get("state") == "unproven" else None
    if terms is None or terms.conflict is None:
        raise ErasureError("transcript.recoveryState", "the continuity state changed; try again", 409)
    rec = terms.conflict
    src = next((p for p in seen if p.n >= n and hmac.compare_digest(p.entries[n - 1].mac, want)), None)
    if src is None:
        raise ErasureError("transcript.conflictBranchUnknown",
                           "no authentic erasure journal visible now holds that head", 409)
    chosen = parse(journal_bytes(st.inst, src, n), k, st.inst)
    longer = [p.n for p in seen if p.n > n and _same_chain(p, chosen)]
    if longer:
        raise ErasureError("transcript.conflictBranchUnknown",
                           "choose the newest head of that branch (n=%d)" % max(longer), 409)
    why = conflict_admits(rec, chosen)
    if not why and not _same_chain(chosen, s.parsed):
        why = "the chosen journal diverges from this volume's erasure journal"
    final = chosen if chosen.n > s.parsed.n else s.parsed
    if not why and not reaches(final, terms.threshold):
        why = "the chosen journal does not hold the restore's committed head n=%d" % terms.threshold.n
    rejected = {(h.n, h.mac): h for h in terms.rejected}
    for p in seen:
        if not _same_chain(p, chosen):
            rejected[(p.head.n, p.head.mac)] = p.head
    if not why and len(rejected) > REJECTED_MAX:
        why = "too many rejected branches to record"
    if why:
        raise ErasureError("transcript.conflictMissingTombstone", why, 409)
    gens = []
    async with st.barrier:
        if s.diag or s.uncertain or s.parsed is None or s.continuity is not cont:
            raise ErasureError("transcript.recoveryState", "the erasure state changed; try again", 409)
        cur = s.parsed
        raw = await st.io(s.journal.read_bytes)
        now_p = parse(raw, k, st.inst) if raw is not None and len(raw) == prefix_len(cur.n) else None
        if (now_p is None or now_p.n != cur.n or now_p.bad
                or not hmac.compare_digest(now_p.head.mac, cur.head.mac) or not _same_chain(chosen, cur)):
            raise ErasureError("transcript.recoveryState", "the erasure journal changed; try again", 409)
        final = chosen if chosen.n > cur.n else cur
        new_entries = list(chosen.entries[cur.n:]) if final is chosen else []
        new = dict(cont)
        new.pop("conflict", None)
        new["rejected"] = [rejected[x].to_json() for x in sorted(rejected)]
        known = dict(terms.known)
        unv = dict(terms.unverified)
        for d in rec["dests"]:
            # golul la n-ul fork-ului (cel mai mare n listat, poate al ramurii respinse) devine capul adoptat
            gap = unv.pop(d, 0)
            known[d] = min(max(known.get(d, 0), gap), final.n)
        new["known"] = known
        if unv:
            new["unverified"] = unv
        else:
            new.pop("unverified", None)
        if new_entries:
            await st.io(s.journal.replace, journal_bytes(st.inst, chosen, chosen.n))
            s.parsed = chosen
            for e in new_entries:
                st.tombstone(e.sid_hex)
                st.drop_key(e.sid_hex)

        def fn(c):
            out = []
            for e in new_entries:
                out += [(e.sid_hex, kind, hexid) for hexid, kind in
                        _destroy_sync(c, e.sid_hex, Head(e.n, e.time_ms, e.mac))]
            _set_json(c, "continuity", new)
            _audit_sync(c, dict(audit_row, detail="owner resolution: erasure conflict resolved by adopting "
                                "the journal n=%d (%s…), %d branch head(s) rejected, %d tombstone(s) checked; "
                                "durable record" % (chosen.n, mac_hex[:16], len(rejected), len(rec["sids"]))))
            return out
        try:
            gens = await st.io(st._run_txn, fn)
        except txstore.Uncertain:
            s.uncertain = "commit-uncertain"
            raise ErasureError("transcript.erasureUncertain",
                               "the change did not finish; restart the gateway", 503) from None
        if new_entries and s.head_db.n < chosen.head.n:
            s.head_db = chosen.head
        s.continuity = new
        s.conflict = ""                            # R7-L1: diagnosticul se închide cu conflictul durabil
    for sid, kind, hexid in gens:
        await st.retire(sid, kind, hexid)
    st.bump(None)
    return {"n": final.n, "rejected": len(rejected), "tombstones": len(rec["sids"])}


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
            if _s.uncertain in _RESUMABLE:
                await resume_intents(st)               # R3-M1: imediat, nu la următorul boot
            if _s.cleanup:
                await run_cleanup(st)                  # R5-L1: curăţarea rămasă, cu backoff
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
    if s.conflict or conflict_open():
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
