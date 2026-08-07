#!/usr/bin/env python3
"""Verifică o ROTAŢIE de cheie de semnare a agentului, ÎNAINTE de deploy.

Rotaţia funcţionează aşa: fişierul `agent/ptyd.py` poartă cheia NOUĂ, dar semnătura
`agent/ptyd.py.sig` e făcută cu cheia VECHE — singura pe care agenţii deja instalaţi o au
încorporată. Ei verifică semnătura cu cheia lor, acceptă, scriu fişierul nou pe disc şi
repornesc cu cheia nouă. Zero reinstalări, sesiunile tmux supravieţuiesc.

Preţul e că o greşeală nu se vede până când flota refuză update-ul. Cele patru condiţii:

  1. semnătura corespunde CU ADEVĂRAT fişierului (nu ai uitat să re-semnezi după o editare);
  2. semnătura e făcută cu cheia declarată în `agent/ptyd.py.signer`;
  3. cheia aia e exact cea pe care o au agenţii ACUM — o citim din `agent/ptyd.py` aşa cum e
     comis la HEAD, adică versiunea din care s-a construit imaginea desfăşurată;
  4. `AGENT_VERSION` a crescut, altfel gateway-ul nu împinge nimic (versiuni egale) şi
     rotaţia pare că „nu face nimic".

  scripts/check-rollover.py            # compară cu ultimul tag de release (= ce e desfăşurat)
  scripts/check-rollover.py <ref>      # sau cu alt commit/tag desfăşurat
"""
import base64
import os
import re
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "agent", "ptyd.py")


def _deployed_ref():
    """Ce rulează flota ACUM = ultimul tag de release, nu HEAD.

    HEAD ca implicit e o capcană: din clipa în care comiţi rotaţia, HEAD conţine deja cheia
    NOUĂ, deci verificarea compară fişierul cu el însuşi şi raportează „semnatarul nu e cheia
    agenţilor" — un fals alarmant exact în momentul în care totul e corect. Releases sunt
    tag-uite `vX.Y.Z` şi din ele se construieşte imaginea desfăşurată, deci ăla e reperul."""
    try:
        out = subprocess.run(["git", "-C", ROOT, "tag", "--sort=-creatordate", "--list", "v*"],
                             capture_output=True, check=True).stdout.decode().split()
        return out[0] if out else "HEAD"
    except (OSError, subprocess.CalledProcessError):
        return "HEAD"


REF = sys.argv[1] if len(sys.argv) > 1 else _deployed_ref()

_PUB = re.compile(r'UPDATE_PUBKEY = bytes\.fromhex\(\s*"([0-9a-f]{64})"')
_VER = re.compile(r"^AGENT_VERSION = (\d+)", re.M)

problems = []


def fail(msg):
    problems.append(msg)
    print("  ✗ %s" % msg)


def good(msg):
    print("  ✓ %s" % msg)


def warn(msg):
    """Semnalăm, dar NU blocăm: priveşte canalul oficial, nu flota locală."""
    print("  ! %s" % msg)


src = open(AGENT, "rb").read()
text = src.decode()
new_pub = _PUB.search(text)
new_ver = _VER.search(text)
if not new_pub or not new_ver:
    sys.exit("nu am găsit UPDATE_PUBKEY / AGENT_VERSION în agent/ptyd.py")
new_pub, new_ver = new_pub.group(1), int(new_ver.group(1))

try:
    old_text = subprocess.run(["git", "-C", ROOT, "show", "%s:agent/ptyd.py" % REF],
                              capture_output=True, check=True).stdout.decode()
except subprocess.CalledProcessError:
    sys.exit("nu pot citi agent/ptyd.py la %s" % REF)
old_pub = _PUB.search(old_text)
old_ver = _VER.search(old_text)
old_pub = old_pub.group(1) if old_pub else ""
old_ver = int(old_ver.group(1)) if old_ver else 0

signer_path = AGENT + ".signer"
signer = open(signer_path).read().strip() if os.path.exists(signer_path) else ""

print("flota rulează acum (%s): v%d, cheie %s…" % (REF, old_ver, old_pub[:16]))
print("fişierul de acum:        v%d, cheie %s…" % (new_ver, new_pub[:16]))
print("semnat cu:               %s…\n" % (signer[:16] if signer else "(nedeclarat)"))

rollover = new_pub != old_pub
print("ROTAŢIE DE CHEIE" if rollover else "update obişnuit (aceeaşi cheie)")

# Un deployment cu cheie PROPRIE nu foloseşte deloc semnătura din repo: `_agent_update_payload`
# substituie `UPDATE_PUBKEY` cu cheia lui şi RE-SEMNEAZĂ în memorie, la fiecare push. Deci ce
# scrie în repo priveşte doar CANALUL OFICIAL — instalările fără cheie proprie. Fără nota asta,
# verificarea dădea o alarmă gravă („TOATĂ flota va refuza") exact când flota nu era în pericol.
def _own_pubkey():
    """Cheia de deployment a instanţei LOCALE, dacă există.

    Scriptul rulează pe HOST, iar `/data` e în container — deci calea directă nu se vede.
    Ordinea: variabilă explicită (funcţionează oriunde, inclusiv în CI), apoi `/data` pentru
    când rulezi înăuntru, apoi containerul care rulează. Fără asta, verificarea nu ştie că
    flota locală e imună şi dă o alarmă gravă degeaba."""
    env = (os.environ.get("WEBTERM_DEPLOYMENT_PUBKEY") or "").strip()
    if env:
        return env
    try:
        return open("/data/agent-signing.pub").read().strip()
    except OSError:
        pass
    try:
        out = subprocess.run(["docker", "exec", os.environ.get("WEBTERM_CONTAINER", "webterm-app-1"),
                              "cat", "/data/agent-signing.pub"],
                             capture_output=True, timeout=15)
        if out.returncode == 0:
            return out.stdout.decode().strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


local = _own_pubkey()
own_key = bool(local)
if own_key:
    print("NB: acest deployment are cheie proprie (%s…) — îşi re-semnează singur agenţii," % local[:16])
    print("    deci verificările de mai jos privesc CANALUL OFICIAL, nu flota ta.")
print()

# 1. semnătura corespunde fişierului, sub cheia declarată
try:
    sig = base64.b64decode(open(AGENT + ".sig").read().strip())
except OSError:
    sig = None
    fail("agent/ptyd.py.sig lipseşte — rulează scripts/sign-agent.py")

if sig is not None:
    if not signer:
        fail("agent/ptyd.py.signer lipseşte — re-semnează cu scripts/sign-agent.py")
    else:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(sig, src)
            good("semnătura corespunde fişierului, sub cheia declarată")
        except Exception:
            fail("semnătura NU corespunde fişierului (ai editat ptyd.py după semnare?)")

# 2+3. semnatarul trebuie să fie cheia pe care flota o are ACUM
if signer and old_pub:
    if signer == old_pub:
        good("semnatarul e cheia pe care agenţii o au acum — o vor accepta")
    elif own_key:
        warn("semnatarul (%s…) diferă de cheia din release-ul precedent (%s…); flota TA nu e "
             "afectată (gateway-ul re-semnează), dar instalările de pe canalul oficial care au "
             "cheia veche vor refuza acest update" % (signer[:16], old_pub[:16]))
    else:
        fail("semnatarul (%s…) NU e cheia agenţilor (%s…) — TOATĂ flota va refuza update-ul"
             % (signer[:16], old_pub[:16]))

# 4. fără bump, gateway-ul nu împinge nimic
if new_ver > old_ver:
    good("AGENT_VERSION a crescut %d → %d, deci update-ul se împinge automat" % (old_ver, new_ver))
else:
    fail("AGENT_VERSION nu a crescut (%d → %d): gateway-ul nu împinge nimic, rotaţia nu se aplică"
         % (old_ver, new_ver))

if rollover and not own_key:
    print("\nDupă deploy, importă cheia privată NOUĂ în gateway")
    print("(Setări → Securitate → Importă cheie existentă), altfel auto-update-ul rămâne")
    print("pe pauză: gateway-ul ar semna cu cheia veche, iar agenţii au deja cheia nouă.")

print("\n%s" % ("TOTUL E ÎN REGULĂ" if not problems else "%d PROBLEME — NU face deploy" % len(problems)))
sys.exit(1 if problems else 0)
