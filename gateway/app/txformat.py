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

Nonce uniqueness: the only code that encrypts records is `Writer`, which has a single owner. Each
record's seq is reserved (the counter advanced) under a non-blocking lock *before* encryption; a
second caller (another thread, or re-entry from the file object's `write`) gets StateError("busy")
without touching the counter, and any exception after a reservation breaks the writer for good.
`fp.write` must return exactly len(buf); anything else (None, a short count, a non-int, an
exception) is an ambiguous write and breaks the writer, whose counters then still describe the
last fully written record. A Writer never reopens a generation: (RK, kind, gen_id) must be fresh.

Readers trust the committed watermark `data_count` (exclusive) from the descriptor: they return
DATA seq 0..data_count-1 and ignore every byte after it, authentic or not; inside it a short file,
a bad tag, a wrong type or a gap is a CorruptError. `verify_full` is the separate whole-generation
check (every record, the SEAL, no byte after it).

Budgets: record lengths are checked before a body is read; `Reader.read_all` requires an explicit
`max_bytes`; `verify_full` stops as soon as the generation exceeds the descriptor's expected
data_count / plain_len / phys_len when given; `verify_index` refuses more than `max_entries`
(default 65 536) by size, before copying or MAC-ing the blob.

Index (`.idx`, a cache): "WTI1" | ver u8 = 1 | kind u8 | reserved u16 = 0 | gen_id 16 B
| data_count u64 | n u32 | n × (seq u32 | logical offset u64 | file offset u64)
| mac 32 B = HMAC-SHA-256(K_idx, all bytes before).

Version 2 (compressed records, §12.11.14): the same layout with header `ver = 2` (covered by
hdr_mac) and two DATA types instead of type 1: 3 ZSTART (a fresh raw-deflate context) and
4 ZCONT (continues the previous record's context). A DATA plaintext is `ulen u32 ‖ z`, where z is
the deflate output of the record's `ulen` bytes (1..65 536) ended by a Z_SYNC_FLUSH, at most
ulen + 64 bytes. Seq 0, every index entry and at least every 1 MiB of plaintext are ZSTART, so a
reader starting at any of them decodes on its own. SEAL, plain_len (decompressed), the tag hash,
the nonces and the keys are those of version 1; phys_len is no longer a function of plain_len
(the descriptor carries it, within `phys_bounds`). The index of a version-2 generation has
`ver = 2`. Readers keep reading version 1.
"""
import hashlib
import hmac
import struct
import threading
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keyring import hkdf_sha256

MAGIC = b"WTX1"
VERSION = 1
# §12.11.14: versiunea 2 = recorduri comprimate (deflate brut). Versiunea 1 rămâne implicită în
# codec (vectorii v1, cititorii vechi); txstore alege explicit versiunea la scriere.
VERSION_Z = 2
VERSIONS = frozenset({VERSION, VERSION_Z})
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
TYPE_ZSTART = 3
TYPE_ZCONT = 4
Z_PREFIX = 4                       # ulen u32 LE în faţa ieşirii deflate
Z_SLACK = 64                       # ieşirea deflate a unui record: cel mult ulen + 64 octeţi
MIN_ZREC_LEN = Z_PREFIX + 1
MAX_ZREC_LEN = Z_PREFIX + MAX_DATA_LEN + Z_SLACK
Z_BLOCK = 1 << 20                  # contextul se resetează cel târziu la 1 MiB de text clar
Z_LEVEL = 6
Z_WBITS = -15                      # deflate brut, fereastră de 32 KiB
# Cel mai rău caz fizic per record v2, peste octeţii lui în clar (bugete, limitele descriptorului).
ZREC_MIN_PHYS = REC_OVERHEAD + MIN_ZREC_LEN
ZREC_MAX_EXTRA = REC_OVERHEAD + Z_PREFIX + Z_SLACK

MAX_DATA_RECORDS = 1 << 20
MAX_PLAIN_BYTES = 64 << 30

LBL_HDR = b"wt/v1/hdr"
LBL_REC = b"wt/v1/rec"
LBL_IDX = b"wt/v1/idx"

IDX_MAGIC = b"WTI1"
IDX_VERSION = 1
IDX_FIXED = 4 + 1 + 1 + 2 + ID_LEN + 8 + 4
IDX_ENTRY_LEN = 20
# Bugetul implicit al unui index: ~1,3 MiB pe disc, 65 536 obiecte. Un index dens pentru o
# generaţie de 1 M recorduri nu are sens în gateway; cine chiar vrea mai mult o cere explicit.
DEFAULT_MAX_INDEX_ENTRIES = 65536

_HDR = struct.Struct("<4sBBH16s16sQ16s")
_REC = struct.Struct("<BII")
_SEAL = struct.Struct("<QQ32s")
_IDX_HEAD = struct.Struct("<4sBBH16sQI")
_IDX_ENTRY = struct.Struct("<IQQ")
_ZLEN = struct.Struct("<I")


class TxFormatError(Exception):
    """Base class; `reason` is a short stable code (tests, System health, audit)."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class CorruptError(TxFormatError):
    """The bytes contradict the format or the committed state: alarm, never serve them."""


class LimitError(TxFormatError):
    """A generation limit or a caller's budget would be exceeded (writer: start a new
    generation; reader: the caller asked for less than the generation holds)."""


class StateError(TxFormatError):
    """Misuse of a writer (after SEAL, after an I/O error, concurrent use, bad arguments)."""


class WriteError(TxFormatError):
    """`fp.write` did not confirm the whole buffer (None, short or non-int count): the state on
    disk is ambiguous, the writer is broken and the generation is abandoned."""


@dataclass(frozen=True)
class GenKeys:
    # repr=False: cheile derivate nu au ce căuta într-un log, traceback cu locals sau f-string.
    hdr: bytes = field(repr=False)
    rec: bytes = field(repr=False)
    idx: bytes = field(repr=False)


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
    # True = un cititor poate începe aici (v1: orice record; v2: ZSTART). Un index nu numeşte altceva.
    reset: bool = True


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


def _is_int(v):
    # bool e subclasă de int: True ar trece drept kind 1 sau count 1. Îl refuzăm explicit.
    return isinstance(v, int) and not isinstance(v, bool)


def _need(name, value, n):
    if not isinstance(value, (bytes, bytearray)) or len(value) != n:
        raise StateError("bad-argument", name)
    return bytes(value)


def _need_int(name, value, lo, hi):
    """lo <= value < hi, a real int (not bool)."""
    if not _is_int(value) or not lo <= value < hi:
        raise StateError("bad-argument", name)
    return value


def _need_kind(kind):
    if not _is_int(kind) or kind not in KINDS:
        raise StateError("bad-argument", "kind")
    return kind


def _need_ver(ver):
    if not _is_int(ver) or ver not in VERSIONS:
        raise StateError("bad-argument", "version")
    return ver


def _need_data(data):
    # Copia se face după verificarea tipului: bytes(5) ar însemna 5 octeţi zero, nu o eroare.
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise StateError("bad-argument", "data must be bytes")
    return bytes(data)


def derive_key(rk, label, kind, gen_id):
    """One §12.1 derivation; label is one of LBL_HDR / LBL_REC / LBL_IDX."""
    if not isinstance(label, bytes) or label not in (LBL_HDR, LBL_REC, LBL_IDX):
        raise StateError("bad-argument", "label")
    info = label + b"\x00" + bytes([_need_kind(kind)]) + _need("gen_id", gen_id, ID_LEN)
    return hkdf_sha256(_need("rk", rk, KEY_LEN), info)


def generation_keys(rk, kind, gen_id):
    return GenKeys(derive_key(rk, LBL_HDR, kind, gen_id), derive_key(rk, LBL_REC, kind, gen_id),
                   derive_key(rk, LBL_IDX, kind, gen_id))


def nonce(seq):
    """GCM nonce: 8 zero bytes ‖ seq u32 big-endian. Unique per record because K_rec is unique
    per generation, a generation is never reopened for writing (§4.1) and the single-owner
    Writer reserves every seq before it encrypts."""
    return b"\x00" * 8 + struct.pack(">I", _need_int("seq", seq, 0, 1 << 32))


def phys_len(data_count, plain_len, sealed):
    """Exact file length of a version-1 generation (or of its committed prefix when not sealed)."""
    return PREFIX_LEN + plain_len + REC_OVERHEAD * data_count + (SEAL_PHYS_LEN if sealed else 0)


def phys_bounds(ver, data_count, plain_len, sealed):
    """(lo, hi) of the file length: v1 exact (lo == hi), v2 from the per-record bounds
    (25 + 5 … 25 + 4 + ulen + 64 bytes per DATA record)."""
    seal = SEAL_PHYS_LEN if sealed else 0
    if ver == VERSION:
        n = phys_len(data_count, plain_len, sealed)
        return n, n
    return (PREFIX_LEN + ZREC_MIN_PHYS * data_count + seal,
            PREFIX_LEN + plain_len + ZREC_MAX_EXTRA * data_count + seal)


def _offset_ok(ver, seq, logical, foff):
    """A DATA record boundary (seq, logical, file offset) possible for the version."""
    if ver == VERSION:
        return foff == PREFIX_LEN + logical + REC_OVERHEAD * seq
    return PREFIX_LEN + ZREC_MIN_PHYS * seq <= foff <= PREFIX_LEN + logical + ZREC_MAX_EXTRA * seq


# ── header ───────────────────────────────────────────────────────────────────


def _need_keys(keys):
    if not isinstance(keys, GenKeys):
        raise StateError("bad-argument", "keys")
    return keys


def encode_header(keys, *, kind, sid, gen_id, created_ms, ver=VERSION):
    """64-byte header followed by its 32-byte HMAC (96 bytes)."""
    _need_keys(keys)
    _need_int("created_ms", created_ms, 0, 1 << 64)
    hdr = _HDR.pack(MAGIC, _need_ver(ver), _need_kind(kind), 0, _need("gen_id", gen_id, ID_LEN),
                    _need("sid", sid, ID_LEN), created_ms, b"\x00" * 16)
    return hdr + hmac.new(keys.hdr, hdr, hashlib.sha256).digest()


def verify_header(blob, keys, *, kind, sid, gen_id, ver=VERSION):
    """Check a 96-byte header prefix against the expected identity and version (from the
    descriptor); returns a Header."""
    _need_keys(keys)
    kind = _need_kind(kind)
    ver = _need_ver(ver)
    sid = _need("sid", sid, ID_LEN)
    gen_id = _need("gen_id", gen_id, ID_LEN)
    if not isinstance(blob, (bytes, bytearray)):
        raise StateError("bad-argument", "blob")
    if len(blob) < PREFIX_LEN:
        raise CorruptError("short-header")
    hdr, mac = bytes(blob[:HEADER_LEN]), bytes(blob[HEADER_LEN:PREFIX_LEN])
    magic, hver, k, res, g, s, created, res2 = _HDR.unpack(hdr)
    if magic != MAGIC:
        raise CorruptError("bad-magic")
    # Versiunea aşteptată vine din descriptorul autentic; cea din fişier e sub hdr_mac. Un octet
    # de versiune schimbat (v2 → v1 sau invers) cade aici sau la MAC, niciodată nu schimbă parserul.
    if ver != hver:
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


def _encode_record(aes, hdr_mac, rtype, seq, plaintext):
    """One record: 9-byte header, ciphertext, 16-byte tag.

    STATELESS PRIMITIVE, private on purpose: it encrypts under (K_rec, seq) without knowing
    whether that pair was used before. Only `Writer`, after reserving `seq`, may call it."""
    n = len(plaintext)
    if rtype == TYPE_DATA:
        if not 1 <= n <= MAX_DATA_LEN:
            raise StateError("bad-argument", "DATA length must be 1..65536")
    elif rtype in (TYPE_ZSTART, TYPE_ZCONT):
        if not MIN_ZREC_LEN <= n <= MAX_ZREC_LEN:
            raise StateError("bad-argument", "compressed DATA length")
    elif rtype == TYPE_SEAL:
        if n != SEAL_LEN:
            raise StateError("bad-argument", "SEAL length must be 48")
    else:
        raise StateError("bad-argument", "record type")
    head = _REC.pack(rtype, n, _need_int("seq", seq, 0, 1 << 32))
    return head + aes.encrypt(nonce(seq), bytes(plaintext), hdr_mac + head)


def _read_exact(fp, n, reason):
    # bytearray: short reads repetate nu mai recopiază tot bufferul la fiecare bucată.
    buf = bytearray()
    while len(buf) < n:
        chunk = fp.read(n - len(buf))
        if not chunk:
            raise CorruptError(reason, f"wanted {n} bytes, got {len(buf)}")
        if not isinstance(chunk, (bytes, bytearray)) or len(chunk) > n - len(buf):
            # Un file-like care dă mai mult decât s-a cerut ar strica bugetul şi poziţia.
            raise CorruptError("bad-read")
        buf += chunk
    return bytes(buf)


def _is_data(ver, rtype):
    return rtype == TYPE_DATA if ver == VERSION else rtype in (TYPE_ZSTART, TYPE_ZCONT)


def _read_record(fp, aes, hdr_mac, expect_seq, first=b"", ver=VERSION):
    """Read and authenticate the next record; returns (type, plaintext, tag, phys bytes).
    `first` = bytes of the record header already read by the caller (EOF look-ahead).
    The length field is checked before the body is read (at most 65 604 + 16 bytes). The
    record types are those of the generation's version: a v1 DATA in a v2 generation (or the
    reverse) is refused before decryption."""
    head = first + _read_exact(fp, REC_HDR_LEN - len(first), "short-record")
    rtype, n, seq = _REC.unpack(head)
    if rtype == TYPE_DATA and ver == VERSION:
        if not 1 <= n <= MAX_DATA_LEN:
            raise CorruptError("bad-len", str(n))
    elif rtype in (TYPE_ZSTART, TYPE_ZCONT) and ver == VERSION_Z:
        if not MIN_ZREC_LEN <= n <= MAX_ZREC_LEN:
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


class _Inflate:
    """The DATA plaintext of each record, in succession. v1: the record's bytes. v2: `ulen ‖ z`
    inflated in the current block's context (ZSTART opens a fresh one; a ZCONT with no open
    context, i.e. a parse that did not start at a block start, is corrupt). Output is capped at
    `ulen` (≤ 64 KiB) per record before inflating: z must yield exactly ulen bytes, be consumed
    whole and never end the deflate stream."""

    def __init__(self, ver):
        self.ver = ver
        self._d = None

    def data(self, rtype, pt):
        if self.ver == VERSION:
            return pt
        if rtype == TYPE_ZSTART:
            self._d = zlib.decompressobj(Z_WBITS)
        elif self._d is None:
            raise CorruptError("bad-block", "a continuation record where a block must start")
        (ulen,) = _ZLEN.unpack_from(pt, 0)
        z = pt[Z_PREFIX:]
        if not 1 <= ulen <= MAX_DATA_LEN or not 1 <= len(z) <= ulen + Z_SLACK:
            raise CorruptError("bad-zlen", str(ulen))
        d = self._d
        try:
            out = d.decompress(z, ulen)
            # Ieşirea s-a oprit la ulen: ce a rămas din z nu are voie să mai producă vreun octet.
            extra = d.decompress(d.unconsumed_tail, 1) if d.unconsumed_tail else b""
        except zlib.error:
            raise CorruptError("bad-deflate") from None
        if len(out) != ulen or extra or d.unconsumed_tail or d.eof or d.unused_data:
            raise CorruptError("bad-zlen", f"{len(out)} != {ulen}")
        return out


# ── writer ───────────────────────────────────────────────────────────────────


class Writer:
    """Append-only writer of one generation into a file-like object (`write(bytes) -> int`).

    Single owner: append / write / seal hold a non-blocking lock for the whole operation; a
    concurrent or re-entrant call raises StateError("busy") before any encryption. The seq is
    reserved before encrypting, so no (K_rec, seq) is ever used twice by this object. After any
    failure past a reservation (encryption, I/O, ambiguous write) the writer is broken for good:
    the caller abandons the generation and starts a new one (§4.1, a segment is never reopened).
    `phys_len`, `data_count` and `plain_len` only ever count fully written records.

    The header is written by the constructor. `ver = VERSION_Z` writes compressed records: one
    deflate context per block, a new block at seq 0, at `append(..., reset=True)` (the caller's
    index points) and once the block holds Z_BLOCK bytes; compressing advances the context, so
    any failure from there on breaks the writer too."""

    def __init__(self, fp, rk, *, kind, sid, gen_id, created_ms,
                 max_records=MAX_DATA_RECORDS, max_plain=MAX_PLAIN_BYTES, ver=VERSION):
        # Limitele pot fi doar coborâte (teste); niciodată ridicate peste §12.1.
        if (not _is_int(max_records) or not _is_int(max_plain)
                or not 1 <= max_records <= MAX_DATA_RECORDS or not 1 <= max_plain <= MAX_PLAIN_BYTES):
            raise StateError("bad-argument", "limits can only be lowered")
        self.ver = _need_ver(ver)
        self._lock = threading.Lock()
        self._fp = fp
        self._z = None
        self._block = 0
        self._keys = generation_keys(rk, kind, gen_id)
        self._aes = AESGCM(self._keys.rec)
        self.kind = kind
        self.sid = _need("sid", sid, ID_LEN)
        self.gen_id = _need("gen_id", gen_id, ID_LEN)
        self.max_records, self.max_plain = max_records, max_plain
        self.data_count = 0
        self.plain_len = 0
        self.sealed = False
        self._broken = False
        # Contorul de nonce: avansează la rezervare, înainte de criptare, şi nu revine niciodată.
        self._next_seq = 0
        self._tags = hashlib.sha256()
        prefix = encode_header(self._keys, kind=kind, sid=sid, gen_id=gen_id, created_ms=created_ms,
                               ver=self.ver)
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
        if not _is_int(n) or n != len(b):
            # None (raw non-blocking), scurt sau non-int = stare ambiguă pe disc; nu numărăm
            # nimic din buffer şi nu mai continuăm în aceeaşi generaţie.
            self._broken = True
            raise WriteError("ambiguous-write", "write() did not confirm the whole buffer")
        self.phys_len += len(b)

    def _usable(self):
        if self._broken:
            raise StateError("broken", "a write failed; start a new generation")
        if self.sealed:
            raise StateError("sealed", "generation already sealed")

    @contextmanager
    def _owned(self):
        # Non-blocking: un al doilea thread sau o reintrare din fp.write (acelaşi thread, Lock
        # nereentrant) e refuzat imediat, înainte să citească sau să atingă contorul.
        if not self._lock.acquire(blocking=False):
            # Varianta strictă: orice încercare concurentă sau reintrantă strică writer-ul pentru
            # totdeauna — un apelant care ajunge aici are deja o eroare de proprietate, iar generaţia
            # nu mai trebuie continuată (se deschide alta, cu gen_id nou).
            self._broken = True
            raise StateError("busy", "writer already in use")
        try:
            self._usable()
            yield
        finally:
            self._lock.release()

    def _reserve(self):
        """Reserve the next seq (under the lock). From here on, any exception breaks the writer."""
        seq = self._next_seq
        if seq != self.data_count:
            # Nu se poate întâmpla fără un bug; dacă se întâmplă, nonce-ul nu mai e sigur.
            self._broken = True
            raise StateError("broken", "seq counter out of step")
        self._next_seq = seq + 1
        return seq

    def can_append(self, nbytes, nrecords=1):
        return (self.data_count + nrecords <= self.max_records
                and self.plain_len + nbytes <= self.max_plain)

    def should_roll(self):
        """True from 90 % of either limit on: the caller seals and opens a new generation."""
        return (self.data_count * 10 >= self.max_records * 9
                or self.plain_len * 10 >= self.max_plain * 9)

    def _compress(self, data, reset):
        """(record type, record plaintext) of a v2 DATA record. Advances the deflate context:
        the caller breaks the writer on any exception from here on."""
        start = reset or self._z is None or self._block >= Z_BLOCK
        if start:
            self._z = zlib.compressobj(Z_LEVEL, zlib.DEFLATED, Z_WBITS)
            self._block = 0
        z = self._z.compress(data) + self._z.flush(zlib.Z_SYNC_FLUSH)
        if not 1 <= len(z) <= len(data) + Z_SLACK:
            raise StateError("broken", "deflate output outside its bound")
        self._block += len(data)
        return (TYPE_ZSTART if start else TYPE_ZCONT), _ZLEN.pack(len(data)) + z

    def _append_locked(self, data, reset=False):
        n = len(data)
        if not 1 <= n <= MAX_DATA_LEN:
            raise StateError("bad-argument", "DATA length must be 1..65536")
        if not self.can_append(n):
            raise LimitError("limit", "generation full; seal it and start a new one")
        rtype, body = TYPE_DATA, data
        if self.ver == VERSION_Z:
            try:
                rtype, body = self._compress(data, reset)
            except BaseException:
                self._broken = True
                raise
        seq = self._reserve()
        try:
            rec = _encode_record(self._aes, self.hdr_mac, rtype, seq, body)
            self._write(rec)
            self._tags.update(rec[-TAG_LEN:])
            self.data_count += 1
            self.plain_len += n
        except BaseException:
            self._broken = True
            raise
        return seq

    def append(self, data, *, reset=False):
        """One DATA record (1..65 536 bytes); returns its seq. v2: `reset` starts a new block
        (the record can be an index entry); ignored by v1, where every record is one."""
        data = _need_data(data)
        with self._owned():
            return self._append_locked(data, reset is True)

    def write(self, data, *, reset=False):
        """Any length ≥ 1, split into records of at most 65 536 bytes; all or nothing on limits
        (an I/O failure in the middle breaks the writer, as for append). `reset` applies to the
        first record."""
        data = _need_data(data)
        with self._owned():
            if not data:
                raise StateError("bad-argument", "empty write")
            nrec = -(-len(data) // MAX_DATA_LEN)
            if not self.can_append(len(data), nrec):
                raise LimitError("limit", "generation full; seal it and start a new one")
            for i in range(0, len(data), MAX_DATA_LEN):
                self._append_locked(data[i:i + MAX_DATA_LEN], reset is True and i == 0)

    def seal(self):
        """Write the single SEAL; nothing may be written after it."""
        with self._owned():
            seq = self._reserve()
            try:
                digest = self._tags.digest()
                rec = _encode_record(self._aes, self.hdr_mac, TYPE_SEAL, seq,
                                     _SEAL.pack(self.data_count, self.plain_len, digest))
                self._write(rec)
                self.sealed = True
            except BaseException:
                self._broken = True
                raise
            return SealInfo(self.data_count, self.plain_len, self.phys_len, digest, self.hdr_mac)


# ── readers ──────────────────────────────────────────────────────────────────


def _expected(name, value, hi):
    """An optional expected value from the descriptor: None or an int in 0..hi."""
    if value is not None and (not _is_int(value) or not 0 <= value <= hi):
        raise CorruptError("bad-watermark", name)
    return value


class Reader:
    """Reads the committed prefix of a generation: DATA seq 0..data_count-1, nothing after.

    `data_count` is the exclusive watermark from the authenticated descriptor. When the
    descriptor's `plain_len` / `hdr_mac` are given they are checked too. `records()` streams
    (one record of at most 64 KiB in memory at a time); `read_all` needs an explicit budget."""

    def __init__(self, fp, rk, *, kind, sid, gen_id, data_count, plain_len=None, hdr_mac=None,
                 ver=VERSION):
        self.ver = _need_ver(ver)
        if not _is_int(data_count) or not 0 <= data_count <= MAX_DATA_RECORDS:
            raise CorruptError("bad-watermark", "data_count")
        _expected("plain_len", plain_len, MAX_PLAIN_BYTES)
        if plain_len is not None and not data_count <= plain_len <= data_count * MAX_DATA_LEN:
            raise CorruptError("bad-watermark", "plain_len out of range")
        if hdr_mac is not None:
            hdr_mac = _need("hdr_mac", hdr_mac, MAC_LEN)
        self._fp = fp
        self._keys = generation_keys(rk, kind, gen_id)
        self.data_count = data_count
        self.plain_len = plain_len
        self.header = verify_header(_read_exact(fp, PREFIX_LEN, "short-header"), self._keys,
                                    kind=kind, sid=sid, gen_id=gen_id, ver=self.ver)
        if hdr_mac is not None and not hmac.compare_digest(hdr_mac, self.header.hdr_mac):
            raise CorruptError("hdr-mac-mismatch")
        self._done = False

    def records(self):
        """Generator of Record; reads strictly forward from just after the header."""
        if self._done:
            raise StateError("consumed")
        self._done = True
        aes = AESGCM(self._keys.rec)
        inf = _Inflate(self.ver)
        logical, foff = 0, PREFIX_LEN
        for seq in range(self.data_count):
            rtype, pt, _tag, n = _read_record(self._fp, aes, self.header.hdr_mac, seq, ver=self.ver)
            if not _is_data(self.ver, rtype):
                # Un SEAL sub watermark: descriptorul promite mai multe date decât are generaţia.
                raise CorruptError("bad-type", f"SEAL at seq {seq} below the watermark")
            data = inf.data(rtype, pt)
            if self.plain_len is not None and logical + len(data) > self.plain_len:
                raise CorruptError("plain-len-mismatch", f"more than {self.plain_len}")
            yield Record(seq, logical, foff, data, rtype != TYPE_ZCONT)
            logical += len(data)
            foff += n
        if self.plain_len is not None and logical != self.plain_len:
            raise CorruptError("plain-len-mismatch", f"{logical} != {self.plain_len}")

    def read_all(self, *, max_bytes):
        """The whole committed plaintext, at most `max_bytes` (required: there is no implicit
        budget, a generation may hold 64 GiB). LimitError when the generation is larger; when
        the descriptor's plain_len is known the refusal comes before any record is read."""
        _need_int("max_bytes", max_bytes, 0, MAX_PLAIN_BYTES + 1)
        if self.plain_len is not None and self.plain_len > max_bytes:
            raise LimitError("budget", "generation larger than max_bytes")
        out = bytearray()
        for r in self.records():
            if len(out) + len(r.data) > max_bytes:
                raise LimitError("budget", "generation larger than max_bytes")
            out += r.data
        return bytes(out)


class RecordCursor:
    """Verified forward parse of the committed DATA records of a generation from a known record
    boundary (§12.11.2 range rule): either seq 0 (just after the header) or an entry of an
    authenticated index. Each record is checked for type, exact seq succession and tag before
    its plaintext is returned; the logical offset of a returned byte is the start offset plus the
    lengths of verified records only. `fp` must be positioned at `file_offset`.

    The header is not read here: the caller has verified it (and its hdr_mac) when it opened the
    generation. `seal()` reads the record after the watermark and checks it is the SEAL matching
    what was parsed (only meaningful from seq 0, where every DATA tag was seen)."""

    def __init__(self, fp, rk, *, kind, gen_id, hdr_mac, data_count, seq=0, logical_offset=0,
                 file_offset=PREFIX_LEN, ver=VERSION, plain_len=None):
        self.ver = _need_ver(ver)
        _need_int("data_count", data_count, 0, MAX_DATA_RECORDS + 1)
        if plain_len is not None:
            _need_int("plain_len", plain_len, 0, MAX_PLAIN_BYTES + 1)
        _need_int("seq", seq, 0, data_count + 1)
        _need_int("logical_offset", logical_offset, 0, MAX_PLAIN_BYTES + 1)
        if not seq <= logical_offset <= seq * MAX_DATA_LEN:
            raise StateError("bad-argument", "logical offset")
        # Aceeaşi relaţie ca la index: o poziţie de start inventată nu ajunge la decriptare
        # (v2: doar limitele; primul record citit trebuie apoi să fie un ZSTART).
        if not _is_int(file_offset) or not _offset_ok(self.ver, seq, logical_offset, file_offset):
            raise StateError("bad-argument", "file offset")
        self._fp = fp
        self._aes = AESGCM(generation_keys(rk, kind, gen_id).rec)
        self._hdr_mac = _need("hdr_mac", hdr_mac, MAC_LEN)
        self.data_count = data_count
        self.seq = seq
        self.logical_offset = logical_offset
        self.file_offset = file_offset
        self._from_zero = seq == 0
        self._tags = hashlib.sha256()
        self._inf = _Inflate(self.ver)
        self.plain_len = plain_len

    def next(self):
        """The next DATA record, or None at the watermark (nothing after it is read). With the
        descriptor's `plain_len`, the decoded total is checked against it record by record and
        must equal it at the watermark."""
        if self.seq >= self.data_count:
            if self.plain_len is not None and self.logical_offset != self.plain_len:
                raise CorruptError("plain-len-mismatch", f"{self.logical_offset} != {self.plain_len}")
            return None
        rtype, pt, tag, n = _read_record(self._fp, self._aes, self._hdr_mac, self.seq, ver=self.ver)
        if not _is_data(self.ver, rtype):
            raise CorruptError("bad-type", f"SEAL at seq {self.seq} below the watermark")
        pt = self._inf.data(rtype, pt)
        if self.plain_len is not None and self.logical_offset + len(pt) > self.plain_len:
            raise CorruptError("plain-len-mismatch", f"more than {self.plain_len}")
        rec = Record(self.seq, self.logical_offset, self.file_offset, pt, rtype != TYPE_ZCONT)
        self._tags.update(tag)
        self.seq += 1
        self.logical_offset += len(pt)
        self.file_offset += n
        return rec

    def seal(self):
        """After the watermark: the SEAL must follow and match; returns SealInfo."""
        if not self._from_zero or self.seq != self.data_count:
            raise StateError("bad-argument", "seal check needs a full parse from seq 0")
        first = self._fp.read(1)
        if not first:
            raise CorruptError("missing-seal")
        rtype, pt, _tag, n = _read_record(self._fp, self._aes, self._hdr_mac, self.seq, first,
                                          ver=self.ver)
        if rtype != TYPE_SEAL:
            raise CorruptError("count-mismatch", "DATA after the watermark where SEAL expected")
        s_count, s_plain, s_hash = _SEAL.unpack(pt)
        digest = self._tags.digest()
        if (s_count != self.data_count or s_plain != self.logical_offset
                or not hmac.compare_digest(s_hash, digest)):
            raise CorruptError("bad-seal")
        self.file_offset += n
        return SealInfo(s_count, s_plain, self.file_offset, digest, self._hdr_mac)


def verify_full(fp, rk, *, kind, sid, gen_id, data_count=None, plain_len=None, phys_len=None,
                hdr_mac=None, ver=VERSION):
    """Whole-generation integrity: header, every record in succession, exactly one SEAL that
    matches count, length and the hash of the DATA tags, and no byte after it. Expected values
    (from the descriptor) are compared when given, and they are also budgets: the scan stops
    as soon as the generation goes past any of them. Without them the only bounds are the
    §12.1 limits (up to 64 GiB to read): callers on a request path pass them. Returns SealInfo."""
    _expected("data_count", data_count, MAX_DATA_RECORDS)
    _expected("plain_len", plain_len, MAX_PLAIN_BYTES)
    _expected("phys_len", phys_len, 1 << 64)
    if hdr_mac is not None:
        hdr_mac = _need("hdr_mac", hdr_mac, MAC_LEN)
    keys = generation_keys(rk, kind, gen_id)
    ver = _need_ver(ver)
    hdr = verify_header(_read_exact(fp, PREFIX_LEN, "short-header"), keys, kind=kind,
                        sid=sid, gen_id=gen_id, ver=ver)
    if hdr_mac is not None and not hmac.compare_digest(hdr_mac, hdr.hdr_mac):
        raise CorruptError("hdr-mac-mismatch")
    aes = AESGCM(keys.rec)
    inf = _Inflate(ver)
    tags = hashlib.sha256()
    count, plain, phys = 0, 0, PREFIX_LEN
    while True:
        # EOF exact la o graniţă de record = generaţie nesigilată (live sau oprită de crash);
        # verificarea completă cere SEAL, deci e eroare, distinctă de un record trunchiat.
        first = fp.read(1)
        if not first:
            raise CorruptError("missing-seal")
        rtype, pt, tag, n = _read_record(fp, aes, hdr.hdr_mac, count, first, ver=ver)
        phys += n
        if phys_len is not None and phys > phys_len:
            raise CorruptError("phys-len-mismatch", f"more than {phys_len}")
        if _is_data(ver, rtype):
            tags.update(tag)
            count += 1
            plain += len(inf.data(rtype, pt))
            if count > MAX_DATA_RECORDS or plain > MAX_PLAIN_BYTES:
                raise CorruptError("too-many-records")
            if data_count is not None and count > data_count:
                raise CorruptError("count-mismatch", f"more than {data_count}")
            if plain_len is not None and plain > plain_len:
                raise CorruptError("plain-len-mismatch", f"more than {plain_len}")
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


def _check_entries(entries, data_count, ver=VERSION):
    prev = None
    for e in entries:
        if not (_is_int(e.seq) and _is_int(e.logical_offset) and _is_int(e.file_offset)):
            raise CorruptError("bad-index", "entry types")
        if not 0 <= e.seq < data_count:
            raise CorruptError("bad-index", f"seq {e.seq} outside the watermark")
        if prev is not None and e.seq <= prev.seq:
            raise CorruptError("bad-index", "entries not strictly ascending")
        # Toate recordurile de sub watermark sunt DATA, deci offsetul în fişier e determinat (v1):
        # 96 + octeţii logici dinainte + 25 × seq. Orice altă valoare e un index fals. v2: doar
        # limitele per record; recordul numit trebuie să fie un ZSTART (cititorul îl verifică).
        if not e.seq <= e.logical_offset <= e.seq * MAX_DATA_LEN:
            raise CorruptError("bad-index", f"logical offset of seq {e.seq}")
        if not _offset_ok(ver, e.seq, e.logical_offset, e.file_offset):
            raise CorruptError("bad-index", f"file offset of seq {e.seq}")
        if prev is not None and not (e.seq - prev.seq <= e.logical_offset - prev.logical_offset
                                     <= (e.seq - prev.seq) * MAX_DATA_LEN):
            raise CorruptError("bad-index", f"logical step before seq {e.seq}")
        if prev is not None and ver == VERSION_Z and not (
                (e.seq - prev.seq) * ZREC_MIN_PHYS <= e.file_offset - prev.file_offset
                <= e.logical_offset - prev.logical_offset + (e.seq - prev.seq) * ZREC_MAX_EXTRA):
            raise CorruptError("bad-index", f"file step before seq {e.seq}")
        prev = e


def encode_index(rk, *, kind, gen_id, data_count, entries, ver=VERSION):
    _need_int("data_count", data_count, 0, MAX_DATA_RECORDS + 1)
    ver = _need_ver(ver)
    keys = generation_keys(rk, kind, gen_id)
    try:
        entries = [IndexEntry(e.seq, e.logical_offset, e.file_offset) for e in entries]
        _check_entries(entries, data_count, ver)
    except CorruptError as e:
        raise StateError("bad-argument", str(e)) from None
    except (TypeError, AttributeError):
        raise StateError("bad-argument", "entries") from None
    out = bytearray(_IDX_HEAD.pack(IDX_MAGIC, ver, kind, 0, bytes(gen_id), data_count,
                                   len(entries)))
    for e in entries:
        out += _IDX_ENTRY.pack(e.seq, e.logical_offset, e.file_offset)
    out += hmac.new(keys.idx, bytes(out), hashlib.sha256).digest()
    return bytes(out)


def verify_index(blob, rk, *, kind, gen_id, data_count, max_entries=DEFAULT_MAX_INDEX_ENTRIES,
                 ver=VERSION):
    """Entries of an index bound to (kind, gen_id, data_count); CorruptError on any mismatch.
    A stale index (another watermark) fails too: the caller rebuilds it.

    Budget: an index with more than `max_entries` entries (default 65 536, at most the §12.1
    record limit) is refused by its size, before the blob is copied or MAC-ed."""
    _need_int("data_count", data_count, 0, MAX_DATA_RECORDS + 1)
    _need_int("max_entries", max_entries, 0, MAX_DATA_RECORDS + 1)
    ver = _need_ver(ver)
    if not isinstance(blob, (bytes, bytearray)):
        raise StateError("bad-argument", "blob")
    if not IDX_FIXED + MAC_LEN <= len(blob) <= IDX_FIXED + max_entries * IDX_ENTRY_LEN + MAC_LEN:
        raise CorruptError("bad-index", "size")
    keys = generation_keys(rk, kind, gen_id)
    blob = bytes(blob)
    body, mac = blob[:-MAC_LEN], blob[-MAC_LEN:]
    if not hmac.compare_digest(mac, hmac.new(keys.idx, body, hashlib.sha256).digest()):
        raise CorruptError("bad-index-mac")
    magic, iver, k, res, g, dc, n = _IDX_HEAD.unpack_from(body, 0)
    if magic != IDX_MAGIC or iver != ver or res != 0:
        raise CorruptError("bad-index", "header")
    if k != kind or g != bytes(gen_id):
        raise CorruptError("bad-index", "identity")
    if dc != data_count:
        raise CorruptError("stale-index", f"{dc} != {data_count}")
    if len(body) != IDX_FIXED + n * IDX_ENTRY_LEN:
        raise CorruptError("bad-index", "length")
    entries = [IndexEntry(*_IDX_ENTRY.unpack_from(body, IDX_FIXED + i * IDX_ENTRY_LEN))
               for i in range(n)]
    _check_entries(entries, data_count, ver)
    return entries
