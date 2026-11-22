"""`WTX1` generation format: the pure codec of encrypted recordings (ENCRYPTION-AT-REST.md §12.1).

No I/O beyond the bytes / file-like objects handed in, no DB, no config, no writer wired in.
Integers are little-endian except the GCM nonce counter (big-endian, as §12.1 says).

Keys per generation (RK = the session's 32-byte random key, kind = 1 `.out` / 2 `.cast`):

    K_x = HKDF-SHA-256(RK, salt = 32 × 0x00, info = label ‖ 0x00 ‖ kind u8 ‖ gen_id 16 B), 32 B
    labels: "wt/v1/hdr" (header MAC), "wt/v1/rec" (records), "wt/v1/idx" (index MAC)

File layout:

    header   64 B: "WTX1" | ver u8 = 1 | kind u8 | reserved u16 = 0 | gen_id 16 B | sid 16 B
                   | created u64 (unix ms) | reserved 16 B = 0
    hdr_mac  32 B: HMAC-SHA-256(K_hdr, header)
    record*:  type u8 (1 DATA, 2 SEAL) | len u32 | seq u32 | ciphertext (len B) | tag 16 B
              AES-256-GCM(K_rec), nonce = 8 × 0x00 ‖ seq u32 BE,
              AAD = hdr_mac ‖ the 9 record-header bytes exactly as written
    SEAL      at seq = data_count, len 48, plaintext = data_count u64 ‖ plain_len u64
              ‖ SHA-256(tag_0 ‖ … ‖ tag_{n-1}) over the DATA tags (SHA-256("") when n = 0)

Physical length: 96 + Σ(25 + len_i) for the DATA records, + 73 once sealed.

Readers trust the committed watermark `data_count` (exclusive) from the descriptor: they return
DATA seq 0..data_count-1 and ignore every byte after it, authentic or not; inside it a short file,
a bad tag, a wrong type or a gap is a CorruptError. `verify_full` is the separate whole-generation
check (every record, the SEAL, no byte after it).

Index (`.idx`, a cache): "WTI1" | ver u8 = 1 | kind u8 | reserved u16 = 0 | gen_id 16 B
| data_count u64 | n u32 | n × (seq u32 | logical offset u64 | file offset u64)
| mac 32 B = HMAC-SHA-256(K_idx, all bytes before).
"""
import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keyring import hkdf_sha256

MAGIC = b"WTX1"
VERSION = 1
KIND_OUT = 1
KIND_CAST = 2
KINDS = frozenset({KIND_OUT, KIND_CAST})
ID_LEN = 16
KEY_LEN = 32

HEADER_LEN = 64
MAC_LEN = 32
PREFIX_LEN = HEADER_LEN + MAC_LEN
REC_HDR_LEN = 9
TAG_LEN = 16
REC_OVERHEAD = REC_HDR_LEN + TAG_LEN
TYPE_DATA = 1
TYPE_SEAL = 2
MAX_DATA_LEN = 65536
SEAL_LEN = 48
SEAL_PHYS_LEN = REC_OVERHEAD + SEAL_LEN

MAX_DATA_RECORDS = 1 << 20
MAX_PLAIN_BYTES = 64 << 30

LBL_HDR = b"wt/v1/hdr"
LBL_REC = b"wt/v1/rec"
LBL_IDX = b"wt/v1/idx"

IDX_MAGIC = b"WTI1"
IDX_VERSION = 1
IDX_FIXED = 4 + 1 + 1 + 2 + ID_LEN + 8 + 4
IDX_ENTRY_LEN = 20

_HDR = struct.Struct("<4sBBH16s16sQ16s")
_REC = struct.Struct("<BII")
_SEAL = struct.Struct("<QQ32s")
_IDX_HEAD = struct.Struct("<4sBBH16sQI")
_IDX_ENTRY = struct.Struct("<IQQ")


class TxFormatError(Exception):
    """Base class; `reason` is a short stable code (tests, System health, audit)."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class CorruptError(TxFormatError):
    """The bytes contradict the format or the committed state: alarm, never serve them."""


class LimitError(TxFormatError):
    """The writer refuses to go past a generation limit; the caller starts a new generation."""


class StateError(TxFormatError):
    """Misuse of a writer (after SEAL, after an I/O error, bad arguments)."""


@dataclass(frozen=True)
class GenKeys:
    hdr: bytes
    rec: bytes
    idx: bytes


@dataclass(frozen=True)
class Header:
    kind: int
    gen_id: bytes
    sid: bytes
    created_ms: int
    hdr_mac: bytes


@dataclass(frozen=True)
class Record:
    seq: int
    logical_offset: int
    file_offset: int
    data: bytes


@dataclass(frozen=True)
class SealInfo:
    data_count: int
    plain_len: int
    phys_len: int
    tags_hash: bytes
    hdr_mac: bytes


@dataclass(frozen=True)
class IndexEntry:
    seq: int
    logical_offset: int
    file_offset: int


def _need(name, value, n):
    if not isinstance(value, (bytes, bytearray)) or len(value) != n:
        raise StateError("bad-argument", f"{name} must be {n} bytes")
    return bytes(value)


def _need_kind(kind):
    if kind not in KINDS:
        raise StateError("bad-argument", f"unknown kind {kind!r}")
    return kind


def derive_key(rk, label, kind, gen_id):
    """One §12.1 derivation; label is one of LBL_HDR / LBL_REC / LBL_IDX."""
    if label not in (LBL_HDR, LBL_REC, LBL_IDX):
        raise StateError("bad-argument", "unknown label")
    info = label + b"\x00" + bytes([_need_kind(kind)]) + _need("gen_id", gen_id, ID_LEN)
    return hkdf_sha256(_need("rk", rk, KEY_LEN), info)


def generation_keys(rk, kind, gen_id):
    return GenKeys(derive_key(rk, LBL_HDR, kind, gen_id), derive_key(rk, LBL_REC, kind, gen_id),
                   derive_key(rk, LBL_IDX, kind, gen_id))


def nonce(seq):
    """GCM nonce: 8 zero bytes ‖ seq u32 big-endian. Unique per record because K_rec is unique
    per generation and a generation is never reopened for writing (§4.1)."""
    return b"\x00" * 8 + struct.pack(">I", seq)


def phys_len(data_count, plain_len, sealed):
    """Exact file length of a generation (or of its committed prefix when not sealed)."""
    return PREFIX_LEN + plain_len + REC_OVERHEAD * data_count + (SEAL_PHYS_LEN if sealed else 0)


# ── header ───────────────────────────────────────────────────────────────────


def encode_header(keys, *, kind, sid, gen_id, created_ms):
    """64-byte header followed by its 32-byte HMAC (96 bytes)."""
    if not isinstance(created_ms, int) or not 0 <= created_ms < 1 << 64:
        raise StateError("bad-argument", "created_ms")
    hdr = _HDR.pack(MAGIC, VERSION, _need_kind(kind), 0, _need("gen_id", gen_id, ID_LEN),
                    _need("sid", sid, ID_LEN), created_ms, b"\x00" * 16)
    return hdr + hmac.new(keys.hdr, hdr, hashlib.sha256).digest()


def verify_header(blob, keys, *, kind, sid, gen_id):
    """Check a 96-byte header prefix against the expected identity; returns a Header."""
    if len(blob) < PREFIX_LEN:
        raise CorruptError("short-header")
    hdr, mac = bytes(blob[:HEADER_LEN]), bytes(blob[HEADER_LEN:PREFIX_LEN])
    magic, ver, k, res, g, s, created, res2 = _HDR.unpack(hdr)
    if magic != MAGIC:
        raise CorruptError("bad-magic")
    if ver != VERSION:
        raise CorruptError("bad-version")
    if k != kind:
        raise CorruptError("wrong-kind")
    if res != 0 or res2 != b"\x00" * 16:
        raise CorruptError("bad-reserved")
    # Identitatea aşteptată vine din descriptor, nu din fişier: un fişier al altei sesiuni sau
    # al altei generaţii, chiar autentic, nu are ce căuta aici.
    if g != gen_id:
        raise CorruptError("wrong-gen")
    if s != sid:
        raise CorruptError("wrong-sid")
    if not hmac.compare_digest(mac, hmac.new(keys.hdr, hdr, hashlib.sha256).digest()):
        raise CorruptError("bad-hdr-mac")
    return Header(k, g, s, created, mac)


# ── records ──────────────────────────────────────────────────────────────────


def encode_record(keys, hdr_mac, rtype, seq, plaintext):
    """One record: 9-byte header, ciphertext, 16-byte tag."""
    n = len(plaintext)
    if rtype == TYPE_DATA:
        if not 1 <= n <= MAX_DATA_LEN:
            raise StateError("bad-argument", "DATA length must be 1..65536")
    elif rtype == TYPE_SEAL:
        if n != SEAL_LEN:
            raise StateError("bad-argument", "SEAL length must be 48")
    else:
        raise StateError("bad-argument", "record type")
    if not 0 <= seq < 1 << 32:
        raise StateError("bad-argument", "seq")
    head = _REC.pack(rtype, n, seq)
    return head + AESGCM(keys.rec).encrypt(nonce(seq), bytes(plaintext), hdr_mac + head)


def _read_exact(fp, n, reason):
    buf = b""
    while len(buf) < n:
        chunk = fp.read(n - len(buf))
        if not chunk:
            raise CorruptError(reason, f"wanted {n} bytes, got {len(buf)}")
        buf += chunk
    return buf


def _read_record(fp, aes, hdr_mac, expect_seq, first=b""):
    """Read and authenticate the next record; returns (type, plaintext, tag, phys bytes).
    `first` = bytes of the record header already read by the caller (EOF look-ahead)."""
    head = first + _read_exact(fp, REC_HDR_LEN - len(first), "short-record")
    rtype, n, seq = _REC.unpack(head)
    if rtype == TYPE_DATA:
        if not 1 <= n <= MAX_DATA_LEN:
            raise CorruptError("bad-len", str(n))
    elif rtype == TYPE_SEAL:
        if n != SEAL_LEN:
            raise CorruptError("bad-len", str(n))
    else:
        raise CorruptError("bad-type", str(rtype))
    # Succesiune exactă: un record mutat, dublat sau lipsă se vede aici, înainte de decriptare.
    if seq != expect_seq:
        raise CorruptError("bad-seq", f"{seq} != {expect_seq}")
    body = _read_exact(fp, n + TAG_LEN, "short-record")
    try:
        pt = aes.decrypt(nonce(seq), body, hdr_mac + head)
    except InvalidTag:
        raise CorruptError("bad-tag", f"seq {seq}") from None
    return rtype, pt, body[-TAG_LEN:], REC_HDR_LEN + len(body)


def encode_seal(keys, hdr_mac, data_count, plain_len, tags_hash):
    return encode_record(keys, hdr_mac, TYPE_SEAL, data_count,
                         _SEAL.pack(data_count, plain_len, tags_hash))


# ── writer ───────────────────────────────────────────────────────────────────


class Writer:
    """Append-only writer of one generation into a file-like object (`write(bytes)`).

    The header is written by the constructor. After any write error the writer is broken for
    good: the caller must start a new generation (§4.1, a segment is never reopened)."""

    def __init__(self, fp, rk, *, kind, sid, gen_id, created_ms,
                 max_records=MAX_DATA_RECORDS, max_plain=MAX_PLAIN_BYTES):
        # Limitele pot fi doar coborâte (teste); niciodată ridicate peste §12.1.
        if not 1 <= max_records <= MAX_DATA_RECORDS or not 1 <= max_plain <= MAX_PLAIN_BYTES:
            raise StateError("bad-argument", "limits can only be lowered")
        self._fp = fp
        self._keys = generation_keys(rk, kind, gen_id)
        self._aes = AESGCM(self._keys.rec)
        self.kind, self.sid, self.gen_id = kind, bytes(sid), bytes(gen_id)
        self.max_records, self.max_plain = max_records, max_plain
        self.data_count = 0
        self.plain_len = 0
        self.sealed = False
        self._broken = False
        self._tags = hashlib.sha256()
        prefix = encode_header(self._keys, kind=kind, sid=sid, gen_id=gen_id, created_ms=created_ms)
        self.hdr_mac = prefix[HEADER_LEN:]
        self.created_ms = created_ms
        self.phys_len = 0
        self._write(prefix)

    def _write(self, b):
        try:
            n = self._fp.write(b)
        except BaseException:
            self._broken = True
            raise
        if n is not None and n != len(b):
            # Scriere parţială = stare ambiguă pe disc; nu continuăm în aceeaşi generaţie.
            self._broken = True
            raise OSError(f"short write ({n} of {len(b)} bytes)")
        self.phys_len += len(b)

    def _usable(self):
        if self._broken:
            raise StateError("broken", "a write failed; start a new generation")
        if self.sealed:
            raise StateError("sealed", "generation already sealed")

    def can_append(self, nbytes, nrecords=1):
        return (self.data_count + nrecords <= self.max_records
                and self.plain_len + nbytes <= self.max_plain)

    def should_roll(self):
        """True from 90 % of either limit on: the caller seals and opens a new generation."""
        return (self.data_count * 10 >= self.max_records * 9
                or self.plain_len * 10 >= self.max_plain * 9)

    def append(self, data):
        """One DATA record (1..65 536 bytes); returns its seq."""
        self._usable()
        if not 1 <= len(data) <= MAX_DATA_LEN:
            raise StateError("bad-argument", "DATA length must be 1..65536")
        if not self.can_append(len(data)):
            raise LimitError("limit", "generation full; seal it and start a new one")
        seq = self.data_count
        head = _REC.pack(TYPE_DATA, len(data), seq)
        rec = head + self._aes.encrypt(nonce(seq), bytes(data), self.hdr_mac + head)
        self._write(rec)
        self._tags.update(rec[-TAG_LEN:])
        self.data_count += 1
        self.plain_len += len(data)
        return seq

    def write(self, data):
        """Any length ≥ 1, split into records of at most 65 536 bytes; all or nothing on limits."""
        self._usable()
        if not data:
            raise StateError("bad-argument", "empty write")
        nrec = -(-len(data) // MAX_DATA_LEN)
        if not self.can_append(len(data), nrec):
            raise LimitError("limit", "generation full; seal it and start a new one")
        mv = memoryview(bytes(data))
        for i in range(0, len(mv), MAX_DATA_LEN):
            self.append(mv[i:i + MAX_DATA_LEN])

    def seal(self):
        """Write the single SEAL; nothing may be written after it."""
        self._usable()
        rec = encode_seal(self._keys, self.hdr_mac, self.data_count, self.plain_len,
                          self._tags.digest())
        self._write(rec)
        self.sealed = True
        return SealInfo(self.data_count, self.plain_len, self.phys_len, self._tags.digest(),
                        self.hdr_mac)


# ── readers ──────────────────────────────────────────────────────────────────


class Reader:
    """Reads the committed prefix of a generation: DATA seq 0..data_count-1, nothing after.

    `data_count` is the exclusive watermark from the authenticated descriptor. When the
    descriptor's `plain_len` / `hdr_mac` are given they are checked too."""

    def __init__(self, fp, rk, *, kind, sid, gen_id, data_count, plain_len=None, hdr_mac=None):
        if not isinstance(data_count, int) or not 0 <= data_count <= MAX_DATA_RECORDS:
            raise CorruptError("bad-watermark", str(data_count))
        if plain_len is not None and not data_count <= plain_len <= data_count * MAX_DATA_LEN:
            raise CorruptError("bad-watermark", "plain_len out of range")
        self._fp = fp
        self._keys = generation_keys(rk, kind, gen_id)
        self.data_count = data_count
        self.plain_len = plain_len
        self.header = verify_header(_read_exact(fp, PREFIX_LEN, "short-header"), self._keys,
                                    kind=kind, sid=bytes(sid), gen_id=bytes(gen_id))
        if hdr_mac is not None and not hmac.compare_digest(bytes(hdr_mac), self.header.hdr_mac):
            raise CorruptError("hdr-mac-mismatch")
        self._done = False

    def records(self):
        """Generator of Record; reads strictly forward from just after the header."""
        if self._done:
            raise StateError("consumed")
        self._done = True
        aes = AESGCM(self._keys.rec)
        logical, foff = 0, PREFIX_LEN
        for seq in range(self.data_count):
            rtype, pt, _tag, n = _read_record(self._fp, aes, self.header.hdr_mac, seq)
            if rtype != TYPE_DATA:
                # Un SEAL sub watermark: descriptorul promite mai multe date decât are generaţia.
                raise CorruptError("bad-type", f"SEAL at seq {seq} below the watermark")
            yield Record(seq, logical, foff, pt)
            logical += len(pt)
            foff += n
        if self.plain_len is not None and logical != self.plain_len:
            raise CorruptError("plain-len-mismatch", f"{logical} != {self.plain_len}")

    def read_all(self):
        return b"".join(r.data for r in self.records())


def verify_full(fp, rk, *, kind, sid, gen_id, data_count=None, plain_len=None, phys_len=None,
                hdr_mac=None):
    """Whole-generation integrity: header, every record in succession, exactly one SEAL that
    matches count, length and the hash of the DATA tags, and no byte after it. Expected values
    (from the descriptor) are compared when given. Returns SealInfo."""
    keys = generation_keys(rk, kind, gen_id)
    hdr = verify_header(_read_exact(fp, PREFIX_LEN, "short-header"), keys, kind=kind,
                        sid=bytes(sid), gen_id=bytes(gen_id))
    if hdr_mac is not None and not hmac.compare_digest(bytes(hdr_mac), hdr.hdr_mac):
        raise CorruptError("hdr-mac-mismatch")
    aes = AESGCM(keys.rec)
    tags = hashlib.sha256()
    count, plain, phys = 0, 0, PREFIX_LEN
    while True:
        # EOF exact la o graniţă de record = generaţie nesigilată (live sau oprită de crash);
        # verificarea completă cere SEAL, deci e eroare, distinctă de un record trunchiat.
        first = fp.read(1)
        if not first:
            raise CorruptError("missing-seal")
        rtype, pt, tag, n = _read_record(fp, aes, hdr.hdr_mac, count, first)
        phys += n
        if rtype == TYPE_DATA:
            tags.update(tag)
            count += 1
            plain += len(pt)
            if count > MAX_DATA_RECORDS or plain > MAX_PLAIN_BYTES:
                raise CorruptError("too-many-records")
            continue
        s_count, s_plain, s_hash = _SEAL.unpack(pt)
        if s_count != count or s_plain != plain or not hmac.compare_digest(s_hash, tags.digest()):
            raise CorruptError("bad-seal")
        break
    if fp.read(1):
        raise CorruptError("trailing-bytes")
    if data_count is not None and data_count != count:
        raise CorruptError("count-mismatch", f"{count} != {data_count}")
    if plain_len is not None and plain_len != plain:
        raise CorruptError("plain-len-mismatch", f"{plain} != {plain_len}")
    if phys_len is not None and phys_len != phys:
        raise CorruptError("phys-len-mismatch", f"{phys} != {phys_len}")
    return SealInfo(count, plain, phys, tags.digest(), hdr.hdr_mac)


# ── index ────────────────────────────────────────────────────────────────────


def _check_entries(entries, data_count):
    prev = None
    for e in entries:
        if not 0 <= e.seq < data_count:
            raise CorruptError("bad-index", f"seq {e.seq} outside the watermark")
        if prev is not None and e.seq <= prev.seq:
            raise CorruptError("bad-index", "entries not strictly ascending")
        # Toate recordurile de sub watermark sunt DATA, deci offsetul în fişier e determinat:
        # 96 + octeţii logici dinainte + 25 × seq. Orice altă valoare e un index fals.
        if not e.seq <= e.logical_offset <= e.seq * MAX_DATA_LEN:
            raise CorruptError("bad-index", f"logical offset of seq {e.seq}")
        if e.file_offset != PREFIX_LEN + e.logical_offset + REC_OVERHEAD * e.seq:
            raise CorruptError("bad-index", f"file offset of seq {e.seq}")
        if prev is not None and not (e.seq - prev.seq <= e.logical_offset - prev.logical_offset
                                     <= (e.seq - prev.seq) * MAX_DATA_LEN):
            raise CorruptError("bad-index", f"logical step before seq {e.seq}")
        prev = e


def encode_index(rk, *, kind, gen_id, data_count, entries):
    if not isinstance(data_count, int) or not 0 <= data_count <= MAX_DATA_RECORDS:
        raise StateError("bad-argument", "data_count")
    entries = [IndexEntry(e.seq, e.logical_offset, e.file_offset) for e in entries]
    try:
        _check_entries(entries, data_count)
    except CorruptError as e:
        raise StateError("bad-argument", str(e)) from None
    keys = generation_keys(rk, kind, gen_id)
    out = bytearray(_IDX_HEAD.pack(IDX_MAGIC, IDX_VERSION, kind, 0, bytes(gen_id), data_count,
                                   len(entries)))
    for e in entries:
        out += _IDX_ENTRY.pack(e.seq, e.logical_offset, e.file_offset)
    out += hmac.new(keys.idx, bytes(out), hashlib.sha256).digest()
    return bytes(out)


def verify_index(blob, rk, *, kind, gen_id, data_count):
    """Entries of an index bound to (kind, gen_id, data_count); CorruptError on any mismatch.
    A stale index (another watermark) fails too: the caller rebuilds it."""
    blob = bytes(blob)
    max_len = IDX_FIXED + MAX_DATA_RECORDS * IDX_ENTRY_LEN + MAC_LEN
    if not IDX_FIXED + MAC_LEN <= len(blob) <= max_len:
        raise CorruptError("bad-index", "size")
    keys = generation_keys(rk, kind, gen_id)
    body, mac = blob[:-MAC_LEN], blob[-MAC_LEN:]
    if not hmac.compare_digest(mac, hmac.new(keys.idx, body, hashlib.sha256).digest()):
        raise CorruptError("bad-index-mac")
    magic, ver, k, res, g, dc, n = _IDX_HEAD.unpack_from(body, 0)
    if magic != IDX_MAGIC or ver != IDX_VERSION or res != 0:
        raise CorruptError("bad-index", "header")
    if k != kind or g != bytes(gen_id):
        raise CorruptError("bad-index", "identity")
    if dc != data_count:
        raise CorruptError("stale-index", f"{dc} != {data_count}")
    if len(body) != IDX_FIXED + n * IDX_ENTRY_LEN:
        raise CorruptError("bad-index", "length")
    entries = [IndexEntry(*_IDX_ENTRY.unpack_from(body, IDX_FIXED + i * IDX_ENTRY_LEN))
               for i in range(n)]
    _check_entries(entries, data_count)
    return entries
