"""Key hierarchy primitives (gateway/app/keyring.py) and recording descriptors
(gateway/app/txdesc.py), ENCRYPTION-AT-REST.md §3.1, §12.2, §12.3: fixed vectors for every
derivation, AES-KWP envelopes with their type / wrapping-key binding, the key manifest's MAC and
canonical form, and the descriptor MAC's binding to installation, sid and kind. Pure: no file,
no DB, nothing that runs at boot.

Vectorii sunt şi în ENCRYPTION-AT-REST.md, "Appendix: Test vectors (v1)"."""
import hashlib
import hmac
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
from app import keyring as kr  # noqa: E402
from app import txdesc as td  # noqa: E402
from app import txformat as tx  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding, aes_key_wrap_with_padding  # noqa: E402

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


def raises(fn, exc, reason=None):
    try:
        fn()
    except exc as e:
        return reason is None or getattr(e, "reason", None) == reason
    except Exception as e:  # noqa: BLE001
        print(f"      (unexpected {type(e).__name__}: {e})")
        return False
    return False


MK = bytes(range(0x40, 0x60))
KWK = bytes(range(0x60, 0x80))
FK = bytes(range(0x80, 0xA0))
INST = bytes(range(0xA0, 0xB0))
RK = bytes(range(32))
GEN = bytes(range(0x10, 0x20))
SID = bytes.fromhex("00112233445566778899aabbccddeeff")
HDR_MAC = bytes.fromhex("bba285dcda26b655a9f417b309c4cda2ff8d317dca59ed35b7278f8612f7d304")

V_MK_ID = "52062057e5bbb03e34bb12c0d05de434"
V_K_MAN = "071c9f0dce956063b924440880505ea8f4df662d9a0395e4a984ec344e3f8933"
V_K_MW = "09f2a4c3196240724b7d9582a2b26e088c0db5320a2d2000eff8d46627b9c19b"
V_K_DESC = "804e4639edacf6eb3b2d9f2316c4c8745bebc186c47e44ef3ab62a2881b9f3f5"
V_K_ERASE = "ee47abe8074d9cf1b1afcd0bb95415e16a0efd293e5a9c78b2ba9cb1e0687774"
V_ENV_KWK = ("01017614b7d76f52d1a0fbd2299ee87b3ac54000d93a0b9a73b07151fcca76e53d94d458583c1e9e012ba35c38d5023aae6a"
             "2fab369e007273298558513fd30cb7cb57ef2ffe18e7931c53f120c4b223d2b4526b")
V_ENV_FK = ("0104f11f697470f59679fa2294223bae52cd4000a7d79b9971b751f4048a96b74ae41e2f5d2ca92750ef2b3b732c1714d705"
            "a675d7a0f10283ffd3a95a45dad3768582c67283c799ae55b9fd8d5684bcb35bb8b8")
V_ENV_RK = ("0106f11f697470f59679fa2294223bae52cd40009cab90a76f09514cc0cbc9713a516f12470584239e7c0702a63c4de1ad"
            "fe146bfc0413330f3b724ade21506857c85af97be734dee47f2e1f1b5c8bf75baf5c53")
V_MANIFEST = ("57544b4d01000000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf010000000000000052062057e5bbb03e34bb12c0d05de434"
              "00025400" + V_ENV_KWK + "5400" + V_ENV_FK +
              "b1e621dcef08ec41607f045a18e1d345c3a5a10235d73ecbb757907b4827080b")
V_DESC = ("5754443101010000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00112233445566778899aabbccddeeff0300000000000000"
          "8e48527f10ac19ed28318060b2fc672da8c3966d74d969c5fb053a4c6894f22b0100"
          "101112131415161718191a1b1c1d1e1f020200000000000000"
          "0d00000000000000e800000000000000" + HDR_MAC.hex() +
          "d9cff1271b174d9e23ad93253030e9438c64226d3f2ceff045b8134cfcf16716")

print("== derivations (vectors + raw HKDF) ==")


def hk(ikm, label):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=label + b"\x00").derive(ikm)


check("MK id = HMAC-SHA-256(MK, 'id')[:16] vector",
      kr.key_id(MK).hex() == V_MK_ID == hmac.new(MK, b"id", hashlib.sha256).hexdigest()[:32])
check("K_man vector = HKDF(MK, 'wt/v1/manifest' ‖ 00)", kr.manifest_key(MK).hex() == V_K_MAN == hk(MK, b"wt/v1/manifest").hex())
check("K_mw vector = HKDF(MK, 'wt/v1/mkwrap' ‖ 00)", kr.mkwrap_key(MK).hex() == V_K_MW == hk(MK, b"wt/v1/mkwrap").hex())
check("K_desc vector = HKDF(KWK, 'wt/v1/desc' ‖ 00)", kr.desc_key(KWK).hex() == V_K_DESC == hk(KWK, b"wt/v1/desc").hex())
check("K_erase vector = HKDF(KWK, 'wt/v1/erase' ‖ 00)", kr.erase_key(KWK).hex() == V_K_ERASE == hk(KWK, b"wt/v1/erase").hex())
check("all derived keys distinct", len({kr.manifest_key(MK), kr.mkwrap_key(MK), kr.desc_key(MK), kr.erase_key(MK), MK}) == 5)
check("short MK refused", raises(lambda: kr.manifest_key(b"x" * 31), kr.KeyringError, "bad-key"))
check("long MK refused", raises(lambda: kr.key_id(b"x" * 33), kr.KeyringError, "bad-key"))

print("== envelopes (AES-KWP) ==")
env_kwk = kr.wrap_under_mk(MK, kr.KT_KWK, KWK)
env_fk = kr.wrap_under_kwk(KWK, kr.KT_FK, FK)
env_rk = kr.wrap_under_kwk(KWK, kr.KT_RK, RK)
check("KWK envelope vector", env_kwk.hex() == V_ENV_KWK)
check("FK envelope vector", env_fk.hex() == V_ENV_FK)
check("RK envelope vector", env_rk.hex() == V_ENV_RK)
check("envelope = ver | type | kek_id | wlen u16 LE | 64 B", len(env_kwk) == 84 and env_kwk[:2] == b"\x01\x01"
      and env_kwk[2:18] == kr.key_id(kr.mkwrap_key(MK)) and env_kwk[18:20] == struct.pack("<H", 64))
inner = aes_key_unwrap_with_padding(kr.mkwrap_key(MK), env_kwk[20:])
check("wrapped plaintext = ver | type | kek_id | key (RFC 5649 under K_mw)", inner == env_kwk[:18] + KWK)
check("KWP is deterministic (same envelope twice)", kr.wrap_under_mk(MK, kr.KT_KWK, KWK) == env_kwk)
check("unwrap KWK under MK", kr.unwrap_under_mk(MK, env_kwk, kr.KT_KWK) == KWK)
check("unwrap FK under KWK", kr.unwrap_under_kwk(KWK, env_fk, kr.KT_FK) == FK)
check("wrong MK → wrong-kek", raises(lambda: kr.unwrap_under_mk(bytes(32), env_kwk, kr.KT_KWK), kr.WrongKeyError, "wrong-kek"))
check("wrong KWK → wrong-kek", raises(lambda: kr.unwrap_under_kwk(bytes(32), env_fk, kr.KT_FK), kr.WrongKeyError, "wrong-kek"))
check("expected another type → wrong-type", raises(lambda: kr.unwrap_under_kwk(KWK, env_fk, kr.KT_DBK), kr.EnvelopeError, "wrong-type"))
relabel = env_fk[:1] + bytes([kr.KT_DBK]) + env_fk[2:]
check("outer type relabelled FK→DBK → inner-mismatch (KWP binds the type)",
      raises(lambda: kr.unwrap_under_kwk(KWK, relabel, kr.KT_DBK), kr.EnvelopeError, "inner-mismatch"))
t = bytearray(env_fk)
t[30] ^= 1
check("wrapped byte flipped → unwrap-failed", raises(lambda: kr.unwrap_under_kwk(KWK, bytes(t), kr.KT_FK), kr.EnvelopeError, "unwrap-failed"))
check("truncated envelope → bad-length", raises(lambda: kr.unwrap_under_kwk(KWK, env_fk[:-1], kr.KT_FK), kr.EnvelopeError, "bad-length"))
check("bad wlen field → bad-length", raises(lambda: kr.unwrap_under_kwk(KWK, env_fk[:18] + b"\x40\x01" + env_fk[20:], kr.KT_FK),
                                            kr.EnvelopeError, "bad-length"))
check("envelope version 2 → bad-version", raises(lambda: kr.unwrap_under_kwk(KWK, b"\x02" + env_fk[1:], kr.KT_FK),
                                                 kr.EnvelopeError, "bad-version"))
check("KWK cannot be wrapped under KWK", raises(lambda: kr.wrap_under_kwk(KWK, kr.KT_KWK, KWK), kr.EnvelopeError, "wrong-wrapper"))
check("RK cannot be wrapped under the MK", raises(lambda: kr.wrap_under_mk(MK, kr.KT_RK, RK), kr.EnvelopeError, "wrong-wrapper"))
check("RK envelope cannot be unwrapped as an MK-wrapped key", raises(lambda: kr.unwrap_under_mk(MK, env_rk, kr.KT_RK), kr.EnvelopeError, "wrong-wrapper"))
# Un plic ambalat corect de alt KEK cu acelaşi id fals: KWP pică (id-ul nu e secret, cheia da).
forged_inner = env_fk[:18] + FK
forged = env_fk[:20] + aes_key_wrap_with_padding(bytes(32), forged_inner)
check("envelope wrapped by another key but claiming this kek_id → unwrap-failed",
      raises(lambda: kr.unwrap_under_kwk(KWK, forged, kr.KT_FK), kr.EnvelopeError, "unwrap-failed"))
check("unknown key type refused", raises(lambda: kr.wrap_key(KWK, 9, FK), kr.EnvelopeError, "bad-type"))
check("16-byte key refused", raises(lambda: kr.wrap_under_kwk(KWK, kr.KT_FK, b"x" * 16), kr.KeyringError, "bad-key"))

print("== key manifest ==")
man = kr.KeyManifest(INST, 1, kr.key_id(MK), (), (env_kwk, env_fk))
mb = kr.encode_manifest(man, MK)
check("manifest vector", mb.hex() == V_MANIFEST)
check("manifest MAC = HMAC-SHA-256(K_man, body)", mb[-32:] == hmac.new(kr.manifest_key(MK), mb[:-32], hashlib.sha256).digest())


def opn(b, mk=MK, profile=kr.PROFILE_V1):
    return kr.open_keyring_bytes(b, mk, profile)


check("structural parse round trip (private, unauthenticated)", kr._parse_manifest_unauthenticated(mb) == man)
check("open_keyring_bytes carries the manifest identity", (lambda r: (r.installation_id, r.epoch, r.mk_id, r.retired_mk_ids))(opn(mb))
      == (INST, 1, kr.key_id(MK), ()))
check("no public unauthenticated decoder / open of a parsed object",
      not hasattr(kr, "decode_manifest") and not hasattr(kr, "open_keyring"))
check("decode with another MK → WrongKeyError (before the MAC)", raises(lambda: opn(mb, bytes(32)), kr.WrongKeyError, "wrong-mk"))
for pos, what in ((9, "installation id"), (24, "epoch"), (len(mb) - 40, "envelope"), (len(mb) - 1, "MAC")):
    t = bytearray(mb)
    t[pos] ^= 1
    check(f"{what} byte flipped → bad-mac", raises(lambda: opn(bytes(t), MK), kr.ManifestError, "bad-mac"))
t = bytearray(mb)
t[40] ^= 1
check("mk_id flipped → WrongKeyError", raises(lambda: opn(bytes(t), MK), kr.WrongKeyError))


def remac(body):
    return body + hmac.new(kr.manifest_key(MK), body, hashlib.sha256).digest()


check("authentic but trailing byte → trailing-bytes", raises(lambda: opn(remac(mb[:-32] + b"\x00"), MK),
                                                              kr.ManifestError, "trailing-bytes"))
check("authentic but version 2 → bad-version", raises(lambda: opn(remac(mb[:4] + b"\x02" + mb[5:-32]), MK),
                                                      kr.ManifestError, "bad-version"))
check("authentic but reserved ≠ 0 → bad-reserved", raises(lambda: opn(remac(mb[:6] + b"\x01" + mb[7:-32]), MK),
                                                          kr.ManifestError, "bad-reserved"))
# Plicurile în ordine inversă: aceeaşi informaţie, altă codificare → refuz (o singură formă canonică).
swapped = mb[:50] + b"\x54\x00" + env_fk + b"\x54\x00" + env_kwk
check("authentic but envelopes out of order → non-canonical", raises(lambda: opn(remac(swapped), MK),
                                                                     kr.ManifestError, "non-canonical-envelopes"))
check("oversized manifest refused before parsing", raises(lambda: opn(b"WTKM" + bytes(kr.MAN_MAX_LEN), MK),
                                                          kr.ManifestError, "too-large"))
check("truncated manifest refused", raises(lambda: opn(mb[:50], MK), kr.ManifestError))
check("empty input refused", raises(lambda: opn(b"", MK), kr.ManifestError, "bad-magic"))
check("manifest without KWK refused", raises(lambda: kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(MK), (), (env_fk,)), MK),
                                             kr.ManifestError, "missing-kwk"))
check("manifest holding an RK refused", raises(lambda: kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(MK), (), (env_kwk, env_rk)), MK),
                                               kr.ManifestError, "rk-in-manifest"))
check("duplicate envelope type refused", raises(lambda: kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(MK), (), (env_kwk, env_fk, env_fk)), MK),
                                                kr.ManifestError, "non-canonical-envelopes"))
check("epoch 0 refused", raises(lambda: kr.encode_manifest(kr.KeyManifest(INST, 0, kr.key_id(MK), (), (env_kwk,)), MK), kr.ManifestError, "bad-epoch"))
check("mk_id of another MK refused on encode", raises(lambda: kr.encode_manifest(kr.KeyManifest(INST, 1, bytes(16), (), (env_kwk,)), MK),
                                                      kr.WrongKeyError))
ids = sorted(os.urandom(16) for _ in range(3))
m2 = kr.KeyManifest(INST, 7, kr.key_id(MK), tuple(ids), (env_kwk,))
check("retired MK ids round trip (ascending)", opn(kr.encode_manifest(m2, MK)).retired_mk_ids == m2.retired_mk_ids)
check("retired ids unordered refused", raises(lambda: kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(MK), tuple(reversed(ids)), (env_kwk,)), MK),
                                              kr.ManifestError, "non-canonical-retired"))
check("current MK id among retired refused", raises(lambda: kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(MK), (kr.key_id(MK),), (env_kwk,)), MK),
                                                    kr.ManifestError, "non-canonical-retired"))
check("more than 64 retired ids refused", raises(lambda: kr.encode_manifest(
    kr.KeyManifest(INST, 1, kr.key_id(MK), tuple(sorted(os.urandom(16) for _ in range(65))), (env_kwk,)), MK), kr.ManifestError, "too-many-retired"))

print("== keyring open and MK rotation ==")
ring = opn(mb)
check("open_keyring unwraps KWK and FK", ring.kwk == KWK and ring.fk == FK and ring.snk is None)
check("open_keyring with another MK refused", raises(lambda: opn(mb, bytes(32)), kr.WrongKeyError))
MK2 = bytes(range(0xC0, 0xE0))
# Rotaţia MK (§12.2 v4): aceleaşi chei stabile, reîmpachetate; doar plicurile sub K_mw şi MAC-ul se schimbă.
rot = kr.KeyManifest(INST, 2, kr.key_id(MK2), (kr.key_id(MK),), (kr.wrap_under_mk(MK2, kr.KT_KWK, KWK), env_fk))
rb = kr.encode_manifest(rot, MK2)
ring2 = opn(rb, MK2)
check("rotated manifest opens with the new MK and yields the same stable keys", (ring2.kwk, ring2.fk) == (KWK, FK))
check("rotated manifest refuses the old MK", raises(lambda: opn(rb, MK), kr.WrongKeyError))
check("KWK-wrapped envelopes unchanged by MK rotation", rot.envelope(kr.KT_FK) == env_fk)
bad_kwk_env = kr.wrap_under_mk(MK, kr.KT_KWK, KWK)  # încă sub vechiul MK
mixed = kr.KeyManifest(INST, 2, kr.key_id(MK2), (), (bad_kwk_env, env_fk))
check("manifest MAC'd by MK2 but KWK still under MK → wrong-kek on open (no partial keyring)",
      raises(lambda: opn(kr.encode_manifest(mixed, MK2), MK2), kr.WrongKeyError, "wrong-kek"))

print("== profiles: required / allowed envelope types (M4) ==")


def env_of_type(ktype, kek, key):
    # Plic construit de mână (wrap_key refuză tipurile necunoscute): autentic sub KEK-ul dat.
    kid = kr.key_id(kek)
    return bytes([1, ktype]) + kid + struct.pack("<H", 64) + aes_key_wrap_with_padding(kek, bytes([1, ktype]) + kid + key)


env7 = env_of_type(7, kr.mkwrap_key(MK), FK)
check("encode_manifest refuses to write a manifest the opener would refuse (unknown type)",
      raises(lambda: kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(MK), (), (env_kwk, env_fk, env7)), MK),
             kr.ManifestError, "unexpected-envelope"))
unk = kr._encode_manifest_unchecked(kr.KeyManifest(INST, 1, kr.key_id(MK), (), (env_kwk, env_fk, env7)), MK)
check("authentic manifest with an unknown envelope type → unexpected-envelope",
      raises(lambda: opn(unk), kr.ManifestError, "unexpected-envelope"))
only_kwk = kr.Profile("kwk-only", frozenset({kr.KT_KWK}), frozenset({kr.KT_KWK}))
check("authentic known type outside the profile → unexpected-envelope",
      raises(lambda: opn(mb, profile=only_kwk), kr.ManifestError, "unexpected-envelope"))
needs_fk = kr.Profile("fk", frozenset({kr.KT_KWK, kr.KT_FK}), frozenset({kr.KT_KWK, kr.KT_FK}))
check("profile requiring FK opens a manifest that has it", opn(mb, profile=needs_fk).fk == FK)
check("profile requiring FK refuses a manifest without it → missing-envelope",
      raises(lambda: opn(kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(MK), (), (env_kwk,)), MK), profile=needs_fk),
             kr.ManifestError, "missing-envelope"))
check("a profile cannot allow RK", raises(lambda: kr.Profile("x", frozenset({kr.KT_KWK}), frozenset({kr.KT_KWK, kr.KT_RK})),
                                          kr.KeyringError, "bad-profile"))
check("a profile must require KWK", raises(lambda: kr.Profile("x", frozenset(), frozenset({kr.KT_KWK})), kr.KeyringError, "bad-profile"))
check("a profile with bool types refused", raises(lambda: kr.Profile("x", frozenset({True}), frozenset({kr.KT_KWK})),
                                                  kr.KeyringError, "bad-profile"))
check("open without a Profile object refused", raises(lambda: kr.open_keyring_bytes(mb, MK, None), kr.KeyringError, "bad-profile"))
t = bytearray(mb)
t[len(mb) - 1] ^= 1
check("the structural parser does not authenticate (tampered MAC still parses)",
      kr._parse_manifest_unauthenticated(bytes(t)) == man)
check("…while open_keyring_bytes refuses the same bytes", raises(lambda: opn(bytes(t)), kr.ManifestError, "bad-mac"))
fk_bad = env_fk[:30] + bytes([env_fk[30] ^ 1]) + env_fk[31:]
bad_inner = kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(MK), (), (env_kwk, fk_bad)), MK)
check("authentic manifest whose FK envelope fails to unwrap → refused (every envelope is unwrapped)",
      raises(lambda: opn(bad_inner), kr.EnvelopeError, "unwrap-failed"))

print("== repr never shows keys (M2) ==")
gk = tx.generation_keys(RK, 1, GEN)
texts = (repr(ring), str(ring), f"{ring}", f"{ring!r}", repr(gk), str(gk), f"{gk}", repr([ring, gk]))
secrets = (KWK, FK, gk.hdr, gk.rec, gk.idx)
check("repr / str / f-string of Keyring and GenKeys contain no key hex",
      not any(k.hex() in x for k in secrets for x in texts))
check("…nor the bytes literal of a key", not any(repr(k) in x or repr(k)[2:-1] in x for k in secrets for x in texts))
check("…but the identity stays visible and key field names are absent",
      "epoch=1" in repr(ring) and not any(f"{n}=" in repr(ring) for n in ("kwk", "snk", "fk", "dbk")) and "rec=" not in repr(gk))

print("== API input types (L1) ==")
check("bool key type refused on wrap", raises(lambda: kr.wrap_key(KWK, True, FK), kr.EnvelopeError, "bad-type"))
check("bool expected type refused on unwrap", raises(lambda: kr.unwrap_under_mk(MK, env_kwk, True), kr.EnvelopeError, "wrong-wrapper"))
check("bool expected type refused (raw unwrap)", raises(lambda: kr.unwrap_key(kr.mkwrap_key(MK), env_kwk, True), kr.EnvelopeError, "bad-type"))
check("bool epoch refused", raises(lambda: kr.encode_manifest(kr.KeyManifest(INST, True, kr.key_id(MK), (), (env_kwk,)), MK),
                                   kr.ManifestError, "bad-epoch"))
check("non-KeyManifest refused on encode", raises(lambda: kr.encode_manifest(object(), MK), kr.ManifestError, "bad-input"))
check("int instead of manifest bytes → bad-input (no bytes(n) allocation)", raises(lambda: opn(10 ** 9), kr.ManifestError, "bad-input"))
check("oversized bytearray refused before copy", raises(lambda: opn(bytearray(kr.MAN_MAX_LEN + 1)), kr.ManifestError, "too-large"))
check("str MK refused", raises(lambda: kr.open_keyring_bytes(mb, "x" * 32, kr.PROFILE_V1), kr.KeyringError, "bad-key"))
check("envelope_hash of a non-envelope refused", raises(lambda: kr.envelope_hash(5), kr.EnvelopeError, "bad-length"))

print("== descriptors ==")
gen = td.Generation(GEN, td.STATE_SEALED, 2, 13, 232, HDR_MAC)
desc = td.Descriptor(INST, SID, tx.KIND_OUT, 3, kr.envelope_hash(env_rk), (gen,))
db = td.encode_descriptor(desc, KWK)
check("descriptor vector", db.hex() == V_DESC)
check("descriptor MAC = HMAC-SHA-256(K_desc, body)", db[-32:] == hmac.new(kr.desc_key(KWK), db[:-32], hashlib.sha256).digest())
dec = dict(installation_id=INST, sid=SID, kind=tx.KIND_OUT, rk_envelope=env_rk)
check("decode round trip + RK envelope hash binding", td.decode_descriptor(db, KWK, **dec) == desc)
check("another installation → wrong-installation", raises(lambda: td.decode_descriptor(db, KWK, installation_id=bytes(16), sid=SID, kind=1, rk_envelope=env_rk),
                                                          td.DescriptorError, "wrong-installation"))
check("another session → wrong-sid", raises(lambda: td.decode_descriptor(db, KWK, installation_id=INST, sid=bytes(16), kind=1, rk_envelope=env_rk),
                                            td.DescriptorError, "wrong-sid"))
check("the other kind → wrong-kind", raises(lambda: td.decode_descriptor(db, KWK, installation_id=INST, sid=SID, kind=2, rk_envelope=env_rk),
                                            td.DescriptorError, "wrong-kind"))
check("another session's RK envelope → rk-mismatch",
      raises(lambda: td.decode_descriptor(db, KWK, **{**dec, "rk_envelope": kr.wrap_under_kwk(KWK, kr.KT_RK, bytes(32))}),
             td.DescriptorError, "rk-mismatch"))
dec_norek = {k: v for k, v in dec.items() if k != "rk_envelope"}
check("rk_envelope is required (no default)", raises(lambda: td.decode_descriptor(db, KWK, **dec_norek), TypeError))
check("rk_envelope None → bad-rk-envelope", raises(lambda: td.decode_descriptor(db, KWK, **{**dec, "rk_envelope": None}),
                                                  td.DescriptorError, "bad-rk-envelope"))
check("an authentic FK envelope given as the RK → bad-rk-envelope",
      raises(lambda: td.decode_descriptor(db, KWK, **{**dec, "rk_envelope": env_fk}), td.DescriptorError, "bad-rk-envelope"))
# Plic RK autentic substituit (acelaşi KWK, altă cheie): ar despacheta fără eroare, deci hash-ul e singura legătură.
sub_rk = kr.wrap_under_kwk(KWK, kr.KT_RK, os.urandom(32))
check("substituted authentic RK envelope → rk-mismatch (and it would unwrap fine)",
      kr.unwrap_under_kwk(KWK, sub_rk, kr.KT_RK) is not None
      and raises(lambda: td.decode_descriptor(db, KWK, **{**dec, "rk_envelope": sub_rk}), td.DescriptorError, "rk-mismatch"))
check("bool kind refused on decode", raises(lambda: td.decode_descriptor(db, KWK, **{**dec, "kind": True}), td.DescriptorError, "bad-argument"))
check("int blob refused before any copy", raises(lambda: td.decode_descriptor(10 ** 9, KWK, **dec), td.DescriptorError, "bad-input"))
check("oversized bytearray refused before copy", raises(lambda: td.decode_descriptor(bytearray(td.MAX_LEN + 1), KWK, **dec),
                                                        td.DescriptorError, "bad-size"))
check("another KWK → bad-mac", raises(lambda: td.decode_descriptor(db, bytes(32), **dec), td.DescriptorError, "bad-mac"))
for pos, what in ((5, "kind"), (10, "installation id"), (30, "sid"), (42, "version"), (60, "rk hash"), (90, "gen_id"), (98, "state"),
                  (100, "data_count"), (110, "plain_len"), (118, "phys_len"), (len(db) - 40, "hdr_mac")):
    t = bytearray(db)
    t[pos] ^= 1
    check(f"{what} byte flipped → bad-mac", raises(lambda: td.decode_descriptor(bytes(t), KWK, **dec), td.DescriptorError, "bad-mac"))
check("truncated → bad-size or bad-mac", raises(lambda: td.decode_descriptor(db[:-1], KWK, **dec), td.DescriptorError))
check("oversized refused", raises(lambda: td.decode_descriptor(bytes(td.MAX_LEN + 1), KWK, **dec), td.DescriptorError, "bad-size"))
live = td.Generation(bytes(range(0x30, 0x40)), td.STATE_LIVE, 1, 7, tx.phys_len(1, 7, False), HDR_MAC)
rec = td.Generation(bytes(range(0x50, 0x60)), td.STATE_RECOVERED, 0, 0, 96, HDR_MAC)
ok3 = td.Descriptor(INST, SID, 1, 4, kr.envelope_hash(env_rk), (rec, gen, live))
check("recovered + sealed + live (last) round trip", td.decode_descriptor(td.encode_descriptor(ok3, KWK), KWK, **dec) == ok3)
check("empty generation list accepted", td.decode_descriptor(td.encode_descriptor(td.Descriptor(INST, SID, 1, 0, kr.envelope_hash(env_rk)), KWK), KWK, **dec).generations == ())


def bad(d, reason):
    return raises(lambda: td.encode_descriptor(d, KWK), td.DescriptorError, reason)


check("live not last refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), (live, gen)), "live-not-last"))
check("two live refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), (live, td.Generation(GEN, 1, 1, 7, 128, HDR_MAC))), "live-not-last"))
check("duplicate gen_id refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), (gen, gen)), "duplicate-generation"))
check("sealed phys_len without the SEAL refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), (td.Generation(GEN, 2, 2, 13, 159, HDR_MAC),)), "bad-phys-len"))
check("live phys_len including a SEAL refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), (td.Generation(GEN, 1, 2, 13, 232, HDR_MAC),)), "bad-phys-len"))
check("plain_len < data_count refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), (td.Generation(GEN, 1, 2, 1, 147, HDR_MAC),)), "bad-plain-len"))
check("data_count above the limit refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), (td.Generation(GEN, 2, tx.MAX_DATA_RECORDS + 1, 2 ** 21, 0, HDR_MAC),)), "bad-count"))
check("unknown state refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), (td.Generation(GEN, 4, 0, 0, 96, HDR_MAC),)), "bad-state"))
check("unknown kind refused", bad(td.Descriptor(INST, SID, 3, 4, bytes(32)), "bad-kind"))
check("bool kind refused", bad(td.Descriptor(INST, SID, True, 4, bytes(32)), "bad-kind"))
check("bool state refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), (td.Generation(GEN, True, 1, 7, 128, HDR_MAC),)), "bad-state"))
check("bool version refused", bad(td.Descriptor(INST, SID, 1, True, bytes(32)), "bad-version"))
check("non-Generation entry refused", bad(td.Descriptor(INST, SID, 1, 4, bytes(32), ((GEN, 2, 0, 0, 169, HDR_MAC),)), "bad-generation"))
# MAC valid peste o listă incoerentă (KWK compromis / bug de writer): verificarea structurală după MAC o prinde.
raw = bytearray(db[:-32])
raw[115:123] = struct.pack("<Q", 999)  # phys_len
remac_d = bytes(raw) + hmac.new(kr.desc_key(KWK), bytes(raw), hashlib.sha256).digest()
check("RK binding is checked before the generation list (wrong RK wins over bad phys_len)",
      raises(lambda: td.decode_descriptor(remac_d, KWK, **{**dec, "rk_envelope": sub_rk}), td.DescriptorError, "rk-mismatch"))
check("authentic MAC over an inconsistent phys_len → bad-phys-len",
      raises(lambda: td.decode_descriptor(bytes(raw) + hmac.new(kr.desc_key(KWK), bytes(raw), hashlib.sha256).digest(), KWK, **dec),
             td.DescriptorError, "bad-phys-len"))

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
