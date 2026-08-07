"""Cheie de semnare a agentului per-deployment (vezi docs/design/SIGNED-UPDATES.md).

Fiecare deployment își generează propria cheie ed25519. La servirea lui `ptyd.py` (instalare +
auto-update), gateway-ul SUBSTITUIE `UPDATE_PUBKEY` cu cheia publică a acestui deployment și
RE-SEMNEAZĂ conținutul cu cheia privată. Agentul verifică update-urile contra cheii baked-in
(TOFU la instalare). Nimeni nu mai depinde de o cheie externă.

Modul PUR (crypto + fișiere), fără DB/async: apelat din api.py/core.py.
- cheia PRIVATĂ: `data/agent-signing.key` (PEM PKCS8; criptată cu parolă = PEM encryption, sau 0600 în clar);
- cheia PUBLICĂ: `data/agent-signing.pub` (hex, publică) — mereu disponibilă, chiar când privata e BLOCATĂ,
  ca instalarea de agenți noi să meargă (doar auto-update-ul cere deblocare).

Compatibilitate: semnăm cu `cryptography` (Ed25519PrivateKey.sign), iar agentul verifică cu verificatorul
ed25519 hand-rolled din ptyd.py — ambele RFC 8032, deci semnăturile sunt interschimbabile (testat).
"""
import base64
import os
import re
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import config

# cheia privată DEBLOCATĂ, ținută doar în memorie (niciodată re-scrisă în clar dacă e criptată)
_loaded: Optional[Ed25519PrivateKey] = None

# UPDATE_PUBKEY = bytes.fromhex(\n    "<64 hex>")  — captăm cadrul, înlocuim doar hex-ul
_PUBKEY_RE = re.compile(rb'(UPDATE_PUBKEY = bytes\.fromhex\(\s*")[0-9a-fA-F]{64}("\s*\))')
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def _key_path():
    return config.DATA_DIR / "agent-signing.key"


def _pub_path():
    return config.DATA_DIR / "agent-signing.pub"


def key_exists() -> bool:
    return _key_path().exists()


def should_autogenerate(has_hosts: bool) -> bool:
    """Generăm automat cheia de deployment DOAR la o instalare încă goală.

    Sursa publică a agentului are încorporată cheia MENTAINERULUI: fără o cheie proprie, toate
    instalările din lume ar împărţi aceeaşi ancoră de încredere pentru update-uri. La instalare
    nouă generarea e gratuită. Cu hosturi deja înrolate NU e: agenţii au alt pubkey în ei şi ar
    refuza (corect) update-urile semnate cu cheia nouă, până la reinstalarea fiecăruia — deci
    rotaţia rămâne o decizie explicită a operatorului."""
    return not key_exists() and not has_hosts


def key_bytes() -> bytes:
    """Octeții fișierului cheii private (PEM, criptat sau nu) — pentru backup criptat la descărcare."""
    return _key_path().read_bytes()


def _pub_hex_of(priv: Ed25519PrivateKey) -> str:
    raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def generate(passphrase: Optional[str] = None) -> str:
    """Generează o cheie ed25519 nouă, o stochează (privata criptată dacă e parolă; publica în clar) și
    o încarcă în memorie (o cheie nouă e deblocată imediat). Întoarce pubkey-ul hex. Refuză suprascrierea
    unei chei existente (rotația = decizie explicită, altă operație)."""
    global _loaded
    if key_exists():
        raise ValueError("a signing key already exists")
    config.ensure_dirs()
    priv = Ed25519PrivateKey.generate()
    enc = (serialization.BestAvailableEncryption(passphrase.encode())
           if passphrase else serialization.NoEncryption())
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    pub_hex = _pub_hex_of(priv)
    _atomic_write(_key_path(), pem, 0o600)
    _atomic_write(_pub_path(), (pub_hex + "\n").encode(), 0o644)
    _loaded = priv
    return pub_hex


def import_key(pem: bytes, load_passphrase: Optional[str] = None,
               store_passphrase: Optional[str] = None) -> str:
    """Importă o cheie ed25519 EXISTENTĂ (PEM). `load_passphrase` deblochează PEM-ul dacă e criptat;
    `store_passphrase` (opțional) o re-criptează la repaus. Întoarce pubkey-ul hex, o încarcă în memorie.
    Refuză dacă există deja o cheie. Util pentru: migrarea unei flote existente (importezi cheia cu care
    agenții au fost deja semnați → o adoptă fără re-înrolare), restore dintr-un backup, sau cheie externă."""
    global _loaded
    if key_exists():
        raise ValueError("a signing key already exists")
    try:
        pw = load_passphrase.encode() if load_passphrase else None
        priv = serialization.load_pem_private_key(pem, password=pw)
    except Exception as e:  # noqa: BLE001
        raise ValueError("invalid PEM or wrong passphrase (%s)" % type(e).__name__)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("the key is not ed25519 (WebTerm uses ed25519 only)")
    config.ensure_dirs()
    enc = (serialization.BestAvailableEncryption(store_passphrase.encode())
           if store_passphrase else serialization.NoEncryption())
    out_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    pub_hex = _pub_hex_of(priv)
    _atomic_write(_key_path(), out_pem, 0o600)
    _atomic_write(_pub_path(), (pub_hex + "\n").encode(), 0o644)
    _loaded = priv
    return pub_hex


def _atomic_write(path, data: bytes, mode: int) -> None:
    tmp = str(path) + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, str(path))


def is_encrypted() -> bool:
    """True dacă fișierul cheii private e protejat cu parolă (nu se încarcă fără ea)."""
    if not key_exists():
        return False
    try:
        serialization.load_pem_private_key(_key_path().read_bytes(), password=None)
        return False
    except TypeError:               # cheie criptată → load fără parolă ridică TypeError
        return True
    except Exception:
        return True                 # coruptă/necunoscută → tratăm ca „nedisponibilă fără parolă"


def load(passphrase: Optional[str] = None) -> bool:
    """Deblochează: încarcă cheia privată în memorie. True la succes (parolă corectă / cheie în clar)."""
    global _loaded
    if not key_exists():
        return False
    try:
        pw = passphrase.encode() if passphrase else None
        _loaded = serialization.load_pem_private_key(_key_path().read_bytes(), password=pw)
        return True
    except Exception:
        _loaded = None
        return False


def is_loaded() -> bool:
    return _loaded is not None


def lock() -> None:
    """Scoate cheia privată din memorie (rămâne pe disc)."""
    global _loaded
    _loaded = None


def pubkey_hex() -> Optional[str]:
    """Pubkey-ul hex al deployment-ului — din fișierul public (disponibil chiar când privata e blocată)."""
    try:
        h = _pub_path().read_text().strip().lower()
        return h if _HEX64.match(h) else None
    except OSError:
        return None


def substitute_pubkey(source: bytes, pub_hex: str) -> bytes:
    """Înlocuiește UPDATE_PUBKEY din sursa ptyd.py cu pubkey-ul dat. FAIL-CLOSED: dacă nu găsește exact
    o potrivire, ridică ValueError (nu servim niciodată o sursă cu cheie greșită/ambiguă)."""
    if not pub_hex or not _HEX64.match(pub_hex.lower()):
        raise ValueError("invalid hex public key")
    new, n = _PUBKEY_RE.subn(rb"\g<1>" + pub_hex.lower().encode() + rb"\g<2>", source)
    if n != 1:
        raise ValueError("UPDATE_PUBKEY not found, or ambiguous in the source (matches=%d)" % n)
    return new


def sign(content: bytes) -> str:
    """Semnează conținutul cu cheia deblocată → semnătură base64. Ridică dacă e blocată/absentă."""
    if _loaded is None:
        raise RuntimeError("the signing key is locked or absent")
    return base64.b64encode(_loaded.sign(content)).decode()


def sign_agent(source: bytes) -> Tuple[bytes, str]:
    """Substituie pubkey-ul deployment-ului în sursă + semnează REZULTATUL. Întoarce
    (sursă_substituită, sig_b64). Semnătura e peste EXACT octeții pe care agentul îi va avea și verifica."""
    ph = pubkey_hex()
    if not ph:
        raise RuntimeError("pubkey de deployment absent")
    sub = substitute_pubkey(source, ph)
    return sub, sign(sub)
