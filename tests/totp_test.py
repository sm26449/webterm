"""TOTP: vectorii de test din RFC 6238 (Appendix B) + verificarea ferestrei.
Rulează standalone (doar stdlib), fără deps-urile gateway-ului."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import totp  # noqa: E402

ok = 0
total = 0


def check(name, cond):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


# RFC 6238 Appendix B: seed ASCII "12345678901234567890" (20 octeți) în base32,
# SHA1, 8 cifre. Perechile (T unix, cod așteptat).
_SEED = "12345678901234567890".encode()
import base64  # noqa: E402
SECRET = base64.b32encode(_SEED).decode().rstrip("=")

RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]

for t, expected in RFC_VECTORS:
    got = totp.generate(SECRET, at=t, digits=8)
    check(f"RFC6238 T={t} -> {expected}", got == expected)

# fereastra de drift: un cod din pasul anterior/următor trece cu window=1
now = 1234567890
prev = totp.generate(SECRET, at=now - totp.STEP)
nxt = totp.generate(SECRET, at=now + totp.STEP)
cur = totp.generate(SECRET, at=now)
check("cod curent valid", totp.verify(SECRET, cur, at=now))
check("cod din pasul anterior valid (drift)", totp.verify(SECRET, prev, at=now))
check("cod din pasul următor valid (drift)", totp.verify(SECRET, nxt, at=now))

# în afara ferestrei: un cod cu 2 pași în urmă e respins cu window=1
old = totp.generate(SECRET, at=now - 2 * totp.STEP)
check("cod vechi (2 pași) respins", not totp.verify(SECRET, old, window=1, at=now))

# verify_counter (anti-replay): întoarce pasul de timp care a potrivit, ca apelantul
# să respingă reutilizarea. verify() e acum un wrapper peste el.
step = int(now // totp.STEP)
check("verify_counter întoarce counter-ul curent", totp.verify_counter(SECRET, cur, at=now) == step)
check("verify_counter pt. pasul anterior", totp.verify_counter(SECRET, prev, at=now) == step - 1)
check("verify_counter None la cod greșit", totp.verify_counter(SECRET, "000000", at=now) is None
      or cur == "000000")
# anti-replay: pași diferiți au counter-e diferite → un cod reutilizat are counter <= ultimul
c_prev = totp.verify_counter(SECRET, prev, at=now)
c_cur = totp.verify_counter(SECRET, cur, at=now)
check("counter crește cu pasul (anti-replay discrimină)", c_cur > c_prev)

# intrări invalide
check("cod gol respins", not totp.verify(SECRET, "", at=now))
check("cod nenumeric respins", not totp.verify(SECRET, "abcdef", at=now))
check("cod greșit respins", not totp.verify(SECRET, "000000", at=now)
      or cur == "000000")

# secret nou: 32 caractere base32, cod de 6 cifre
s = totp.new_secret()
check("secret base32 valid", len(s) >= 32 and all(c in
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in s))
check("cod curent are 6 cifre", len(totp.generate(s)) == 6)

# provisioning URI conține secretul și issuer-ul
uri = totp.provisioning_uri(s, "admin@example.com")
check("otpauth URI bine format", uri.startswith("otpauth://totp/")
      and f"secret={s}" in uri and "issuer=WebTerm" in uri)

print(f"\n{ok}/{total} PASS")
sys.exit(0 if ok == total else 1)
