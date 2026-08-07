"""Known-answer + negative tests for the agent's hand-rolled Ed25519 verifier
(agent/ptyd.py). A crypto primitive that gates RCE across the fleet must be
pinned by RFC 8032 test vectors AND a "tampered → rejected" test, so a future
refactor can't silently make it lenient. No gateway/agent process needed."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import ptyd  # noqa: E402

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


# RFC 8032, section 7.1 — (public key, message, signature), all hex/bytes
VECTORS = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     b"",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     bytes.fromhex("72"),
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     bytes.fromhex("af82"),
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]

for i, (pk_hex, msg, sig_hex) in enumerate(VECTORS):
    pk, sig = bytes.fromhex(pk_hex), bytes.fromhex(sig_hex)
    check(f"KAT #{i}: valid RFC-8032 signature verifies", ptyd.ed25519_verify(pk, sig, msg))
    check(f"KAT #{i}: tampered message rejected", not ptyd.ed25519_verify(pk, sig, msg + b"\x00"))
    bad_sig = bytearray(sig); bad_sig[10] ^= 1
    check(f"KAT #{i}: tampered signature rejected", not ptyd.ed25519_verify(pk, bytes(bad_sig), msg))
    bad_pk = bytearray(pk); bad_pk[5] ^= 1
    check(f"KAT #{i}: wrong public key rejected", not ptyd.ed25519_verify(bytes(bad_pk), sig, msg))

# malformed inputs must not raise, just return False
check("empty sig rejected", not ptyd.ed25519_verify(bytes.fromhex(VECTORS[0][0]), b"", b"m"))
check("short pubkey rejected", not ptyd.ed25519_verify(b"\x00" * 31, bytes(64), b"m"))

# S non-canonic (S >= l) respins (RFC 8032 §5.1.7, anti-malleabilitate): luăm o semnătură
# validă și adăugăm l la S; verificarea trebuie să pice pe garda `S >= _ed_l`.
pk0, sig0 = bytes.fromhex(VECTORS[0][0]), bytes.fromhex(VECTORS[0][2])
S0 = int.from_bytes(sig0[32:], "little")
mal = sig0[:32] + (S0 + ptyd._ed_l).to_bytes(32, "little")
check("semnătură cu S non-canonic (S+l) respinsă", not ptyd.ed25519_verify(pk0, mal, VECTORS[0][1]))

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
