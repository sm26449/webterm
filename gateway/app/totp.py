"""TOTP (RFC 6238) — al doilea factor la login, opțional.

Implementare pe stdlib (hmac/struct/base64), fără dependență nouă: deps-urile
backend sunt pinuite cu hash în requirements.lock, iar TOTP e standardizat și
mic. Corectitudinea e verificată în tests/totp_test.py cu vectorii din RFC 6238.
"""

import base64
import hmac
import secrets
import struct
import time as _time
from urllib.parse import quote

DIGITS = 6
STEP = 30                 # secunde per cod (standard)
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def new_secret() -> str:
    """Secret base32 nou (160 biți — recomandarea RFC 4226)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    # base32 fără padding: readaugă padding-ul înainte de decodare
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    mac = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def generate(secret_b32: str, at: float = None, digits: int = DIGITS,
             step: int = STEP) -> str:
    """Codul valid la momentul `at` (implicit: acum)."""
    at = _time.time() if at is None else at
    return _hotp(secret_b32, int(at // step), digits)


def verify_counter(secret_b32: str, code: str, window: int = 1, at: float = None):
    """Ca `verify`, dar întoarce COUNTER-ul (pasul de timp) care a potrivit, sau None.
    Necesar pentru anti-replay: apelantul reține ultimul counter folosit și respinge
    reutilizarea aceluiași cod (sau a unuia dintr-un pas anterior) în fereastra de valabilitate."""
    if not code or not code.isdigit():
        return None
    at = _time.time() if at is None else at
    counter = int(at // STEP)
    for delta in range(-window, window + 1):
        if hmac.compare_digest(code, _hotp(secret_b32, counter + delta)):
            return counter + delta
    return None


def verify(secret_b32: str, code: str, window: int = 1, at: float = None) -> bool:
    """Adevărat dacă `code` e valid în intervalul ±window pași (drift de ceas).
    Comparație în timp constant."""
    return verify_counter(secret_b32, code, window, at) is not None


def provisioning_uri(secret_b32: str, account: str, issuer: str = "WebTerm") -> str:
    """otpauth:// pe care aplicațiile de authenticator îl citesc din QR."""
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}")
