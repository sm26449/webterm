"""Recording descriptors: the authenticated commit state of one (sid, kind) (ENCRYPTION-AT-REST.md §12.3).

Pure types and functions; nothing here reads or writes the database (publication is §12.8
contract 1). Canonical binary encoding, integers little-endian:

    "WTD1" | ver u8 = 1 | kind u8 | flags u16 | installation_id 16 B | sid 16 B
    | version u64 | rk_hash 32 B (SHA-256 of the session's wrapped-RK envelope)
    | n_gen u16 | n_gen × generation | mac 32 B = HMAC-SHA-256(K_desc, all bytes before)

    generation (73 B): gen_id 16 B | state u8 (1 live, 2 sealed, 3 recovered)
                       | data_count u64 | plain_len u64 | phys_len u64 | hdr_mac 32 B

K_desc = HKDF(KWK, "wt/v1/desc") (keyring.desc_key). The list keeps the recording order (oldest
first). Rules checked on encode and decode (fail closed): gen_ids unique, at most one `live`
generation and only as the last one, data_count / plain_len within the §12.1 limits and
consistent with each other, flags only from KNOWN_FLAGS (bit 0 = converted: migrated from
plaintext, §12.11.0; any other bit → refused), phys_len exact for the state: the committed prefix for live and
recovered, the whole file including the 73-byte SEAL for sealed (txformat.phys_len).

`decode_descriptor` always needs the session's wrapped-RK envelope (from `session_keys`): its
type must be RK and its hash must equal the descriptor's `rk_hash` before anything is returned,
so a caller cannot forget the binding. Type and size are checked before the blob is copied.
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
# §12.11.0: fostul `reserved u16` devine `flags u16`; ver rămâne 1 (niciun WTD1 nu există încă în
# afara testelor). Un bit necunoscut = refuz: un cititor vechi nu are voie să ignore un sens nou.
FLAG_CONVERTED = 0x0001
KNOWN_FLAGS = FLAG_CONVERTED

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
    flags: int = 0


def _b(v, n):
    return isinstance(v, bytes) and len(v) == n


def _is_int(v):
    # bool refuzat: True ar trece drept kind 1, state 1 (live) sau count 1.
    return isinstance(v, int) and not isinstance(v, bool)


def _check(d):
    if not isinstance(d, Descriptor) or not isinstance(d.generations, (tuple, list)):
        raise DescriptorError("bad-input")
    if not _b(d.installation_id, ID_LEN) or not _b(d.sid, ID_LEN):
        raise DescriptorError("bad-identity")
    if not _is_int(d.kind) or d.kind not in txformat.KINDS:
        raise DescriptorError("bad-kind")
    if not _is_int(d.version) or not 0 <= d.version < 1 << 64:
        raise DescriptorError("bad-version")
    if not _b(d.rk_hash, 32):
        raise DescriptorError("bad-rk-hash")
    if not _is_int(d.flags) or not 0 <= d.flags < 1 << 16 or d.flags & ~KNOWN_FLAGS:
        raise DescriptorError("bad-flags")
    gens = tuple(d.generations)
    if len(gens) > MAX_GENERATIONS:
        raise DescriptorError("too-many-generations")
    seen = set()
    for i, g in enumerate(gens):
        if not isinstance(g, Generation):
            raise DescriptorError("bad-generation", f"#{i}")
        if not _b(g.gen_id, ID_LEN) or not _b(g.hdr_mac, MAC_LEN):
            raise DescriptorError("bad-generation", f"#{i} ids")
        if g.gen_id in seen:
            raise DescriptorError("duplicate-generation")
        seen.add(g.gen_id)
        if not _is_int(g.state) or g.state not in STATES:
            raise DescriptorError("bad-state", f"#{i}")
        # O singură generaţie live, şi doar ultima: writerul scrie mereu la coada înregistrării.
        if g.state == STATE_LIVE and i != len(gens) - 1:
            raise DescriptorError("live-not-last", f"#{i}")
        if not _is_int(g.data_count) or not 0 <= g.data_count <= txformat.MAX_DATA_RECORDS:
            raise DescriptorError("bad-count", f"#{i}")
        if (not _is_int(g.plain_len) or g.plain_len > txformat.MAX_PLAIN_BYTES
                or not g.data_count <= g.plain_len <= g.data_count * txformat.MAX_DATA_LEN):
            raise DescriptorError("bad-plain-len", f"#{i}")
        want = txformat.phys_len(g.data_count, g.plain_len, g.state == STATE_SEALED)
        if not _is_int(g.phys_len) or g.phys_len != want:
            raise DescriptorError("bad-phys-len", f"#{i}: {g.phys_len} != {want}")


def _mac(kwk, body):
    return hmac.new(keyring.desc_key(kwk), body, hashlib.sha256).digest()


def encode_descriptor(d, kwk):
    _check(d)
    out = bytearray(_HEAD.pack(MAGIC, VERSION, d.kind, d.flags, d.installation_id, d.sid, d.version,
                               d.rk_hash, len(d.generations)))
    for g in d.generations:
        out += _GEN.pack(g.gen_id, g.state, g.data_count, g.plain_len, g.phys_len, g.hdr_mac)
    return bytes(out) + _mac(kwk, bytes(out))


def decode_descriptor(blob, kwk, *, installation_id, sid, kind, rk_envelope):
    """Verify a descriptor and its binding to this installation, session, kind and wrapped RK.

    `rk_envelope` is required (no default): the session's RK envelope from `session_keys`; it
    must be an RK envelope and its SHA-256 must equal the descriptor's `rk_hash`, checked before
    the generation list is parsed. The caller unwraps that same envelope afterwards."""
    if not _b(installation_id, ID_LEN) or not _b(sid, ID_LEN) or not _is_int(kind):
        raise DescriptorError("bad-argument")
    try:
        if keyring.parse_envelope(rk_envelope)[0] != keyring.KT_RK:
            raise DescriptorError("bad-rk-envelope")
    except keyring.EnvelopeError:
        raise DescriptorError("bad-rk-envelope") from None
    # Tip şi mărime înainte de copie: un int sau un blob uriaş nu ajung la bytes(...).
    if not isinstance(blob, (bytes, bytearray)):
        raise DescriptorError("bad-input")
    if not _HEAD.size + MAC_LEN <= len(blob) <= MAX_LEN:
        raise DescriptorError("bad-size")
    blob = bytes(blob)
    body, mac = blob[:-MAC_LEN], blob[-MAC_LEN:]
    # MAC-ul acoperă instalaţia, sid-ul şi kind-ul: un descriptor autentic mutat pe alt rând
    # (altă sesiune, celălalt kind, altă instalaţie) e respins mai jos, nu doar la MAC.
    if not hmac.compare_digest(mac, _mac(kwk, body)):
        raise DescriptorError("bad-mac")
    magic, ver, k, flags, inst, s, version, rk_hash, n = _HEAD.unpack_from(body, 0)
    if magic != MAGIC or ver != VERSION:
        raise DescriptorError("bad-header")
    if flags & ~KNOWN_FLAGS:
        raise DescriptorError("bad-flags")
    if inst != installation_id:
        raise DescriptorError("wrong-installation")
    if s != sid:
        raise DescriptorError("wrong-sid")
    if k != kind:
        raise DescriptorError("wrong-kind")
    # Legătura cu plicul RK înainte de lista de generaţii şi înainte de orice acces la fişiere:
    # un plic RK autentic al altei sesiuni (acelaşi KWK) ar despacheta fără eroare.
    if not hmac.compare_digest(keyring.envelope_hash(rk_envelope), rk_hash):
        raise DescriptorError("rk-mismatch")
    if len(body) != _HEAD.size + n * _GEN.size:
        raise DescriptorError("bad-size")
    gens = tuple(Generation(*_GEN.unpack_from(body, _HEAD.size + i * _GEN.size)) for i in range(n))
    d = Descriptor(inst, s, k, version, rk_hash, gens, flags)
    _check(d)
    return d
