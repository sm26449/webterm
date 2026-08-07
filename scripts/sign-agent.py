#!/usr/bin/env python3
"""Sign agent/ptyd.py with the release Ed25519 key so the gateway can push
updates the agent will accept. Run this whenever ptyd.py changes.

The private key MUST NOT live in the repo or on the gateway — only the public
key is embedded in the agent (UPDATE_PUBKEY). Keep the key offline / in CI secrets.

  WEBTERM_AGENT_SIGNING_KEY=/path/to/key.pem  scripts/sign-agent.py
  scripts/sign-agent.py /path/to/key.pem
"""
import base64
import os
import sys

from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_private_key,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "agent", "ptyd.py")
key_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("WEBTERM_AGENT_SIGNING_KEY", "")
if not key_path or not os.path.exists(key_path):
    sys.exit("set WEBTERM_AGENT_SIGNING_KEY=<key.pem> or pass the path as an argument")

pem = open(key_path, "rb").read()
try:
    sk = load_pem_private_key(pem, password=None)
except TypeError:                       # cheie criptată — cere parola
    import getpass
    sk = load_pem_private_key(pem, password=getpass.getpass("Key passphrase: ").encode())
content = open(AGENT, "rb").read()
sig = sk.sign(content)
with open(AGENT + ".sig", "w") as f:
    f.write(base64.b64encode(sig).decode() + "\n")

# Cine a semnat, declarat explicit. De obicei e chiar cheia din `UPDATE_PUBKEY`, dar la o
# ROTAŢIE de cheie cele două diferă intenţionat: fişierul poartă cheia NOUĂ, iar semnătura e
# făcută cu cea VECHE — singura pe care agenţii instalaţi o au şi o acceptă. Fără declaraţia
# asta, verificarea din CI (care compara semnătura cu cheia din fişier) ar fi respins tocmai
# calea corectă de rotaţie, iar singura alternativă ar fi fost reinstalarea fiecărui agent.
pub_hex = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
with open(AGENT + ".signer", "w") as f:
    f.write(pub_hex + "\n")
print("signed %s -> %s (%d bytes)" % (AGENT, AGENT + ".sig", len(content)))
print("signed with: %s" % pub_hex)

embedded = ""
import re  # noqa: E402
m = re.search(r'UPDATE_PUBKEY = bytes\.fromhex\(\s*"([0-9a-f]+)"', content.decode())
if m:
    embedded = m.group(1)
if embedded and embedded != pub_hex:
    print("\n⚠ KEY ROLLOVER: the file carries %s…, the signature is with %s…" % (embedded[:16], pub_hex[:16]))
    print("  Installed agents must have %s… as UPDATE_PUBKEY, or they will refuse." % pub_hex[:16])
    print("  Check first:  scripts/check-rollover.py")
