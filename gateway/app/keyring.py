"""Key hierarchy primitives for encryption at rest (3.8, docs/design/ENCRYPTION-AT-REST.md §3.1, §12.2).

Pure functions and internal types only: no file I/O, no config, no DB, nothing that runs at
boot. Publication of `keys.wtk`, key sources, the boot contract and migration are the open
contracts of §12.8 and are deliberately NOT here.

Derivations (HKDF-SHA-256, salt = 32 zero bytes, output 32 B, info = ASCII label ‖ 0x00):

    K_man = HKDF(MK,  "wt/v1/manifest")   MAC of the key manifest
    K_mw  = HKDF(MK,  "wt/v1/mkwrap")     wraps the stable keys KWK and SNK
    K_desc = HKDF(KWK, "wt/v1/desc")      descriptor MAC (txdesc.py)
    K_erase = HKDF(KWK, "wt/v1/erase")    erasure journal chain (not used yet)

    key_id(K) = HMAC-SHA-256(K, "id")[:16]   (MK id of §3.2; also the id of any wrapping key)

Envelope (one wrapped key), all integers little-endian:

    ver u8 = 1 | type u8 | kek_id 16 B | wlen u16 | wrapped (wlen B)
    wrapped = AES-KWP(KEK, ver u8 ‖ type u8 ‖ kek_id 16 B ‖ key 32 B)      (RFC 5649)

The type and the wrapping-key id are repeated inside the wrapped plaintext, so the KWP integrity
check binds them: an envelope moved into another slot, or relabelled, fails to unwrap.
KWK and SNK are wrapped by K_mw; FK_legacy, FK, DBK and the per-session RKs by KWK.

Key manifest (`keys.wtk` content), canonical binary:

    "WTKM" | ver u8 = 1 | reserved u8 = 0 | reserved u16 = 0 | installation_id 16 B
    | epoch u64 | mk_id 16 B | n_retired u8 | retired MK ids (16 B each, strictly ascending,
    never the current one) | n_env u8 | n_env × (len u16 | envelope), strictly ascending by type,
    one per type, KWK required, RK forbidden | mac 32 B = HMAC-SHA-256(K_man, all bytes before)

Decoding is strict: size limits first, the current MK id is compared before the MAC (so a wrong
key is reported as such, not as tampering), the MAC is checked before any other field is trusted,
and any non-canonical form (order, duplicates, trailing bytes, reserved bits) is refused.
"""
import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap_with_padding,
)

KEY_LEN = 32
ID_LEN = 16
HKDF_SALT = b"\x00" * 32

LBL_MANIFEST = b"wt/v1/manifest"
LBL_MKWRAP = b"wt/v1/mkwrap"
LBL_DESC = b"wt/v1/desc"
LBL_ERASE = b"wt/v1/erase"

# Tipurile de chei. Valorile sunt pe disc: nu se renumerotează niciodată.
KT_KWK = 1
KT_SNK = 2
KT_FK_LEGACY = 3
KT_FK = 4
KT_DBK = 5
KT_RK = 6
MK_WRAPPED = frozenset({KT_KWK, KT_SNK})
KWK_WRAPPED = frozenset({KT_FK_LEGACY, KT_FK, KT_DBK, KT_RK})

ENV_VERSION = 1
# KWP pentru 32 B de cheie + 18 B de context = 50 B → completat la 56 + 8 B IV = 64 B; o limită fixă taie
# devreme orice câmp de lungime manipulat, înainte să atingem criptografia.
ENV_INNER_LEN = 2 + ID_LEN + KEY_LEN
ENV_WRAPPED_LEN = 64
ENV_LEN = 2 + ID_LEN + 2 + ENV_WRAPPED_LEN

MAN_MAGIC = b"WTKM"
MAN_VERSION = 1
MAN_MAX_LEN = 16 * 1024
MAN_MAX_RETIRED = 64
MAN_MAX_ENVELOPES = 16
MAC_LEN = 32
_MAN_FIXED = 4 + 1 + 1 + 2 + ID_LEN + 8 + ID_LEN  # până la mk_id inclusiv
_MAN_MKID_AT = 4 + 1 + 1 + 2 + ID_LEN + 8


class KeyringError(Exception):
    """Base class; `reason` is a short stable code for tests and System health."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class EnvelopeError(KeyringError):
    pass


class WrongKeyError(KeyringError):
    pass


class ManifestError(KeyringError):
    pass


def _need_key(name, key):
    # Toate cheile ierarhiei sunt exact 32 B aleatori; orice altă lungime e o greşeală de apel,
    # iar HKDF ar „accepta” tăcut şi o cheie scurtă.
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
        raise KeyringError("bad-key", f"{name} must be {KEY_LEN} bytes")
    return bytes(key)


def hkdf_sha256(ikm, info):
    """HKDF-SHA-256, salt of 32 zero bytes, 32-byte output (§12.1)."""
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=HKDF_SALT, info=info).derive(ikm)


def derive(ikm, label):
    """Context-free derivation: info = label ‖ 0x00 (the NUL ends the label, so no label is
    a prefix of another one's info, including the per-generation infos of txformat)."""
    return hkdf_sha256(_need_key("ikm", ikm), label + b"\x00")


def manifest_key(mk):
    return derive(mk, LBL_MANIFEST)


def mkwrap_key(mk):
    return derive(mk, LBL_MKWRAP)


def desc_key(kwk):
    return derive(kwk, LBL_DESC)


def erase_key(kwk):
    return derive(kwk, LBL_ERASE)


def key_id(key):
    """16-byte public id of a key: HMAC-SHA-256(key, "id")[:16] (§3.2 "MK id")."""
    return hmac.new(_need_key("key", key), b"id", hashlib.sha256).digest()[:ID_LEN]


def envelope_hash(env):
    """SHA-256 of an envelope's exact bytes (the descriptor binds the session's wrapped RK)."""
    return hashlib.sha256(bytes(env)).digest()


# ── envelope ─────────────────────────────────────────────────────────────────


def wrap_key(kek, ktype, key):
    """Wrap `key` (32 B) of type `ktype` under `kek` with AES-KWP; returns the envelope bytes."""
    kek = _need_key("kek", kek)
    key = _need_key("key", key)
    if ktype not in MK_WRAPPED | KWK_WRAPPED:
        raise EnvelopeError("bad-type", str(ktype))
    kid = key_id(kek)
    inner = bytes([ENV_VERSION, ktype]) + kid + key
    wrapped = aes_key_wrap_with_padding(kek, inner)
    if len(wrapped) != ENV_WRAPPED_LEN:  # nu assert: dispare sub python -O
        raise EnvelopeError("bad-length")
    return bytes([ENV_VERSION, ktype]) + kid + struct.pack("<H", len(wrapped)) + wrapped


def parse_envelope(env):
    """(type, kek_id, wrapped) from the outer bytes, without any key; strict on length."""
    if not isinstance(env, (bytes, bytearray)) or len(env) != ENV_LEN:
        raise EnvelopeError("bad-length")
    env = bytes(env)
    if env[0] != ENV_VERSION:
        raise EnvelopeError("bad-version")
    (wlen,) = struct.unpack_from("<H", env, 2 + ID_LEN)
    if wlen != ENV_WRAPPED_LEN:
        raise EnvelopeError("bad-length")
    return env[1], env[2:2 + ID_LEN], env[2 + ID_LEN + 2:]


def unwrap_key(kek, env, expected_type):
    """Unwrap an envelope; refuses another type, another wrapping key or a failed KWP check."""
    kek = _need_key("kek", kek)
    ktype, kid, wrapped = parse_envelope(env)
    if ktype != expected_type:
        raise EnvelopeError("wrong-type", f"{ktype} != {expected_type}")
    if not hmac.compare_digest(kid, key_id(kek)):
        raise WrongKeyError("wrong-kek")
    try:
        inner = aes_key_unwrap_with_padding(kek, wrapped)
    except InvalidUnwrap:
        raise EnvelopeError("unwrap-failed") from None
    # Antetul exterior nu e autentificat de KWP; doar copia lui din interior este. Le cerem egale,
    # altfel un plic reetichetat ar trece de verificarea de tip de mai sus.
    if len(inner) != ENV_INNER_LEN or inner[:2 + ID_LEN] != bytes([ENV_VERSION, ktype]) + kid:
        raise EnvelopeError("inner-mismatch")
    return inner[2 + ID_LEN:]


def wrap_under_mk(mk, ktype, key):
    if ktype not in MK_WRAPPED:
        raise EnvelopeError("wrong-wrapper", f"type {ktype} is not wrapped by the MK")
    return wrap_key(mkwrap_key(mk), ktype, key)


def unwrap_under_mk(mk, env, ktype):
    if ktype not in MK_WRAPPED:
        raise EnvelopeError("wrong-wrapper", f"type {ktype} is not wrapped by the MK")
    return unwrap_key(mkwrap_key(mk), env, ktype)


def wrap_under_kwk(kwk, ktype, key):
    if ktype not in KWK_WRAPPED:
        raise EnvelopeError("wrong-wrapper", f"type {ktype} is not wrapped by KWK")
    return wrap_key(kwk, ktype, key)


def unwrap_under_kwk(kwk, env, ktype):
    if ktype not in KWK_WRAPPED:
        raise EnvelopeError("wrong-wrapper", f"type {ktype} is not wrapped by KWK")
    return unwrap_key(kwk, env, ktype)


# ── key manifest ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class KeyManifest:
    installation_id: bytes
    epoch: int
    mk_id: bytes
    retired_mk_ids: tuple = ()
    envelopes: tuple = ()  # envelope bytes, ascending by type

    def envelope(self, ktype):
        for env in self.envelopes:
            if env[1] == ktype:
                return env
        return None


def _check_manifest(m):
    if not isinstance(m.installation_id, bytes) or len(m.installation_id) != ID_LEN:
        raise ManifestError("bad-installation-id")
    if not isinstance(m.epoch, int) or not 1 <= m.epoch < 1 << 64:
        raise ManifestError("bad-epoch")
    if not isinstance(m.mk_id, bytes) or len(m.mk_id) != ID_LEN:
        raise ManifestError("bad-mk-id")
    ret = tuple(m.retired_mk_ids)
    if len(ret) > MAN_MAX_RETIRED:
        raise ManifestError("too-many-retired")
    if any(not isinstance(r, bytes) or len(r) != ID_LEN for r in ret):
        raise ManifestError("bad-retired-id")
    # Ordine strict crescătoare = o singură codificare posibilă şi fără duplicate.
    if any(a >= b for a, b in zip(ret, ret[1:])) or m.mk_id in ret:
        raise ManifestError("non-canonical-retired")
    envs = tuple(m.envelopes)
    if len(envs) > MAN_MAX_ENVELOPES:
        raise ManifestError("too-many-envelopes")
    types = [parse_envelope(e)[0] for e in envs]
    if any(a >= b for a, b in zip(types, types[1:])):
        raise ManifestError("non-canonical-envelopes")
    if KT_RK in types:
        raise ManifestError("rk-in-manifest")
    if KT_KWK not in types:
        raise ManifestError("missing-kwk")


def encode_manifest(m, mk):
    """Canonical bytes of the manifest, MAC included. `m.mk_id` must be the id of `mk`."""
    _check_manifest(m)
    if not hmac.compare_digest(m.mk_id, key_id(mk)):
        raise WrongKeyError("wrong-mk")
    out = bytearray(MAN_MAGIC)
    out += bytes([MAN_VERSION, 0]) + b"\x00\x00"
    out += m.installation_id + struct.pack("<Q", m.epoch) + m.mk_id
    out += bytes([len(m.retired_mk_ids)]) + b"".join(m.retired_mk_ids)
    out += bytes([len(m.envelopes)])
    for env in m.envelopes:
        out += struct.pack("<H", len(env)) + bytes(env)
    out += hmac.new(manifest_key(mk), bytes(out), hashlib.sha256).digest()
    if len(out) > MAN_MAX_LEN:
        raise ManifestError("too-large")
    return bytes(out)


def decode_manifest(data, mk):
    """Verify and parse a manifest under `mk`. Raises WrongKeyError when the manifest names
    another MK, ManifestError on any tamper or non-canonical form."""
    if not isinstance(data, (bytes, bytearray)):
        raise ManifestError("bad-input")
    data = bytes(data)
    if len(data) > MAN_MAX_LEN:
        raise ManifestError("too-large")
    if len(data) < _MAN_FIXED + 2 + MAC_LEN or data[:4] != MAN_MAGIC:
        raise ManifestError("bad-magic")
    # Întâi id-ul MK (câmp la poziţie fixă): „cheie greşită” trebuie să se distingă de
    # „fişier modificat”, fără să parsăm altceva înainte de MAC.
    if not hmac.compare_digest(data[_MAN_MKID_AT:_MAN_MKID_AT + ID_LEN], key_id(mk)):
        raise WrongKeyError("wrong-mk")
    body, mac = data[:-MAC_LEN], data[-MAC_LEN:]
    if not hmac.compare_digest(mac, hmac.new(manifest_key(mk), body, hashlib.sha256).digest()):
        raise ManifestError("bad-mac")
    if body[4] != MAN_VERSION:
        raise ManifestError("bad-version")
    if body[5:8] != b"\x00\x00\x00":
        raise ManifestError("bad-reserved")
    p = 8
    inst = body[p:p + ID_LEN]
    p += ID_LEN
    (epoch,) = struct.unpack_from("<Q", body, p)
    p += 8
    mk_id = body[p:p + ID_LEN]
    p += ID_LEN
    n_ret = body[p]
    p += 1
    if p + n_ret * ID_LEN + 1 > len(body):
        raise ManifestError("truncated")
    retired = tuple(body[p + i * ID_LEN:p + (i + 1) * ID_LEN] for i in range(n_ret))
    p += n_ret * ID_LEN
    n_env = body[p]
    p += 1
    envs = []
    for _ in range(n_env):
        if p + 2 > len(body):
            raise ManifestError("truncated")
        (ln,) = struct.unpack_from("<H", body, p)
        p += 2
        if ln != ENV_LEN or p + ln > len(body):
            raise ManifestError("bad-envelope-length")
        envs.append(body[p:p + ln])
        p += ln
    if p != len(body):
        raise ManifestError("trailing-bytes")
    m = KeyManifest(inst, epoch, mk_id, retired, tuple(envs))
    try:
        _check_manifest(m)
    except EnvelopeError as e:
        raise ManifestError("bad-envelope", e.reason) from None
    return m


@dataclass(frozen=True)
class Keyring:
    kwk: bytes
    snk: bytes = None
    fk_legacy: bytes = None
    fk: bytes = None
    dbk: bytes = None


def open_keyring(m, mk):
    """Unwrap every envelope of a verified manifest. Any failure is fatal (no partial keyring)."""
    if not hmac.compare_digest(m.mk_id, key_id(mk)):
        raise WrongKeyError("wrong-mk")
    _check_manifest(m)
    kwk = unwrap_under_mk(mk, m.envelope(KT_KWK), KT_KWK)

    def opt(t, under_mk):
        env = m.envelope(t)
        if env is None:
            return None
        return unwrap_under_mk(mk, env, t) if under_mk else unwrap_under_kwk(kwk, env, t)

    return Keyring(kwk=kwk, snk=opt(KT_SNK, True), fk_legacy=opt(KT_FK_LEGACY, False),
                   fk=opt(KT_FK, False), dbk=opt(KT_DBK, False))
