"""Recording descriptors: the authenticated commit state of one (sid, kind) (ENCRYPTION-AT-REST.md §12.3).

Pure types and functions; nothing here reads or writes the database (publication is §12.8
contract 1). Canonical binary encoding, integers little-endian:

    "WTD1" | ver u8 = 1 | kind u8 | reserved u16 = 0 | installation_id 16 B | sid 16 B
    | version u64 | rk_hash 32 B (SHA-256 of the session's wrapped-RK envelope)
    | n_gen u16 | n_gen × generation | mac 32 B = HMAC-SHA-256(K_desc, all bytes before)

    generation (73 B): gen_id 16 B | state u8 (1 live, 2 sealed, 3 recovered)
                       | data_count u64 | plain_len u64 | phys_len u64 | hdr_mac 32 B

K_desc = HKDF(KWK, "wt/v1/desc") (keyring.desc_key). The list keeps the recording order (oldest
first). Rules checked on encode and decode (fail closed): gen_ids unique, at most one `live`
generation and only as the last one, data_count / plain_len within the §12.1 limits and
consistent with each other, phys_len exact for the state: the committed prefix for live and
recovered, the whole file including the 73-byte SEAL for sealed (txformat.phys_len).
"""
import hashlib
import hmac
import struct
from dataclasses import dataclass

from . import keyring
from . import txformat

MAGIC = b"WTD1"
VERSION = 1
ID_LEN = 16
MAC_LEN = 32
MAX_GENERATIONS = 4096
STATE_LIVE = 1
STATE_SEALED = 2
STATE_RECOVERED = 3
STATES = frozenset({STATE_LIVE, STATE_SEALED, STATE_RECOVERED})

_HEAD = struct.Struct("<4sBBH16s16sQ32sH")
_GEN = struct.Struct("<16sBQQQ32s")
MAX_LEN = _HEAD.size + MAX_GENERATIONS * _GEN.size + MAC_LEN


class DescriptorError(Exception):
    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class Generation:
    gen_id: bytes
    state: int
    data_count: int
    plain_len: int
    phys_len: int
    hdr_mac: bytes


@dataclass(frozen=True)
class Descriptor:
    installation_id: bytes
    sid: bytes
    kind: int
    version: int
    rk_hash: bytes
    generations: tuple = ()


def _b(v, n):
    return isinstance(v, bytes) and len(v) == n


def _check(d):
    if not _b(d.installation_id, ID_LEN) or not _b(d.sid, ID_LEN):
        raise DescriptorError("bad-identity")
    if d.kind not in txformat.KINDS:
        raise DescriptorError("bad-kind")
    if not isinstance(d.version, int) or not 0 <= d.version < 1 << 64:
        raise DescriptorError("bad-version")
    if not _b(d.rk_hash, 32):
        raise DescriptorError("bad-rk-hash")
    gens = tuple(d.generations)
    if len(gens) > MAX_GENERATIONS:
        raise DescriptorError("too-many-generations")
    seen = set()
    for i, g in enumerate(gens):
        if not _b(g.gen_id, ID_LEN) or not _b(g.hdr_mac, MAC_LEN):
            raise DescriptorError("bad-generation", f"#{i} ids")
        if g.gen_id in seen:
            raise DescriptorError("duplicate-generation")
        seen.add(g.gen_id)
        if g.state not in STATES:
            raise DescriptorError("bad-state", f"#{i}")
        # O singură generaţie live, şi doar ultima: writerul scrie mereu la coada înregistrării.
        if g.state == STATE_LIVE and i != len(gens) - 1:
            raise DescriptorError("live-not-last", f"#{i}")
        if not isinstance(g.data_count, int) or not 0 <= g.data_count <= txformat.MAX_DATA_RECORDS:
            raise DescriptorError("bad-count", f"#{i}")
        if (not isinstance(g.plain_len, int) or g.plain_len > txformat.MAX_PLAIN_BYTES
                or not g.data_count <= g.plain_len <= g.data_count * txformat.MAX_DATA_LEN):
            raise DescriptorError("bad-plain-len", f"#{i}")
        want = txformat.phys_len(g.data_count, g.plain_len, g.state == STATE_SEALED)
        if g.phys_len != want:
            raise DescriptorError("bad-phys-len", f"#{i}: {g.phys_len} != {want}")


def _mac(kwk, body):
    return hmac.new(keyring.desc_key(kwk), body, hashlib.sha256).digest()


def encode_descriptor(d, kwk):
    _check(d)
    out = bytearray(_HEAD.pack(MAGIC, VERSION, d.kind, 0, d.installation_id, d.sid, d.version,
                               d.rk_hash, len(d.generations)))
    for g in d.generations:
        out += _GEN.pack(g.gen_id, g.state, g.data_count, g.plain_len, g.phys_len, g.hdr_mac)
    return bytes(out) + _mac(kwk, bytes(out))


def decode_descriptor(blob, kwk, *, installation_id, sid, kind, rk_envelope=None):
    """Verify a descriptor and its binding to this installation, session and kind; when
    `rk_envelope` (the wrapped RK from `session_keys`) is given, its hash must match too."""
    if not isinstance(blob, (bytes, bytearray)):
        raise DescriptorError("bad-input")
    blob = bytes(blob)
    if not _HEAD.size + MAC_LEN <= len(blob) <= MAX_LEN:
        raise DescriptorError("bad-size")
    body, mac = blob[:-MAC_LEN], blob[-MAC_LEN:]
    # MAC-ul acoperă instalaţia, sid-ul şi kind-ul: un descriptor autentic mutat pe alt rând
    # (altă sesiune, celălalt kind, altă instalaţie) e respins mai jos, nu doar la MAC.
    if not hmac.compare_digest(mac, _mac(kwk, body)):
        raise DescriptorError("bad-mac")
    magic, ver, k, res, inst, s, version, rk_hash, n = _HEAD.unpack_from(body, 0)
    if magic != MAGIC or ver != VERSION or res != 0:
        raise DescriptorError("bad-header")
    if inst != installation_id:
        raise DescriptorError("wrong-installation")
    if s != sid:
        raise DescriptorError("wrong-sid")
    if k != kind:
        raise DescriptorError("wrong-kind")
    if len(body) != _HEAD.size + n * _GEN.size:
        raise DescriptorError("bad-size")
    gens = tuple(Generation(*_GEN.unpack_from(body, _HEAD.size + i * _GEN.size)) for i in range(n))
    d = Descriptor(inst, s, k, version, rk_hash, gens)
    _check(d)
    if rk_envelope is not None and not hmac.compare_digest(keyring.envelope_hash(rk_envelope),
                                                           rk_hash):
        raise DescriptorError("rk-mismatch")
    return d
