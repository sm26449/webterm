#!/usr/bin/env python3
"""Generează o cheie NOUĂ de semnare a agentului pentru instalația ta:
creează perechea Ed25519, scrie cheia publică în agent/ptyd.py (UPDATE_PUBKEY)
și re-semnează agentul. Obligatoriu pentru fork-uri / build-uri proprii —
altfel rămâi cu cheia publică a upstream-ului pinuită în agent și nu vei putea
semna niciodată update-uri.

  scripts/gen-signing-key.py /cale/sigură/webterm-signing-key.pem

ATENȚIE:
- Rulează ÎNAINTE de a instala agenți pe host-uri. Agenții deja instalați au
  cheia publică veche pinuită și vor REFUZA update-urile semnate cu cheia nouă
  (singura soluție: reinstalezi agentul pe fiecare host).
- Cheia privată NU se comite în repo (e în .gitignore) și nu se pune pe gateway.
  Păstrează o copie de siguranță offline: fără ea, agenții desfășurați nu mai
  acceptă niciun update, niciodată.
"""
import base64
import getpass
import os
import re
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "agent", "ptyd.py")

if len(sys.argv) != 2:
    sys.exit(__doc__.strip().splitlines()[6].strip())  # linia cu usage
key_path = sys.argv[1]
if os.path.exists(key_path):
    sys.exit("refuz să suprascriu %s — șterge-l explicit dacă chiar vrei o cheie nouă" % key_path)

pw = getpass.getpass("Parolă pentru cheie (recomandat; gol = necriptată): ")
if pw:
    if getpass.getpass("Repetă parola: ") != pw:
        sys.exit("parolele nu coincid")
    enc = BestAvailableEncryption(pw.encode())
else:
    print("! cheia va fi scrisă NECRIPTATĂ — protejeaz-o prin permisiuni și backup atent")
    enc = NoEncryption()

sk = Ed25519PrivateKey.generate()
pub_hex = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

with open(key_path, "wb") as f:
    f.write(sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc))
os.chmod(key_path, 0o600)

src = open(AGENT).read()
new_src, n = re.subn(
    r'(UPDATE_PUBKEY = bytes\.fromhex\(\s*")[0-9a-f]+(")',
    r"\g<1>%s\g<2>" % pub_hex, src)
if n != 1:
    os.unlink(key_path)
    sys.exit("nu am găsit UPDATE_PUBKEY în agent/ptyd.py — structură neașteptată, nimic modificat")
open(AGENT, "w").write(new_src)

# semnează agentul proaspăt modificat cu cheia nouă
content = open(AGENT, "rb").read()
with open(AGENT + ".sig", "w") as f:
    f.write(base64.b64encode(sk.sign(content)).decode() + "\n")

print("✓ cheie nouă: %s (chmod 600)" % key_path)
print("✓ UPDATE_PUBKEY actualizat în agent/ptyd.py: %s" % pub_hex)
print("✓ agent/ptyd.py.sig re-semnat")
try:
    dirty = subprocess.run(["git", "-C", ROOT, "status", "--porcelain", "agent/"],
                           capture_output=True).stdout.decode().strip()
    if dirty:
        print("\nUrmează: comite agent/ptyd.py + agent/ptyd.py.sig (cheia NU — e în .gitignore),")
        print("apoi fă backup offline cheii. La fiecare modificare viitoare de ptyd.py:")
        print("  WEBTERM_AGENT_SIGNING_KEY=%s scripts/sign-agent.py" % key_path)
except OSError:
    pass
