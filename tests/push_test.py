"""Web Push (Faza 2) — stratul crypto/trimitere din gateway/app/push.py.

Hermetic, fără rețea: cheia VAPID se creează/persistă (0600), cheia publică are forma de punct EC
necomprimat, JWT-ul VAPID e un ES256 valid pe originea endpoint-ului, criptarea aes128gcm face
round-trip cu http_ece.decrypt (adică un browser real ar putea decripta), iar lipsa cheii =
fail-closed (push oprit, nu crash). Trimiterea pe rețea (_send_one) NU se atinge."""
import base64
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
_here = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_here, "..", "gateway"))

from app import config, push  # noqa: E402

import http_ece  # noqa: E402
import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def main():
    # --- cheia VAPID: creată, publică, persistată 0600 ---
    check("push activat cu o cheie proaspătă", push.enabled() is True)
    pub = push.public_key_b64()
    raw = base64.urlsafe_b64decode(pub + "=" * (-len(pub) % 4)) if pub else b""
    check("cheia publică = punct EC P-256 necomprimat (65 octeți, 0x04)",
          len(raw) == 65 and raw[0] == 0x04, f"len={len(raw)}")
    check("cheia publică e base64url fără padding", bool(pub) and "=" not in pub)
    keyf = config.DATA_DIR / "vapid.key"
    check("cheia privată persistată", keyf.exists())
    check("cheia privată e 0600", oct(keyf.stat().st_mode)[-3:] == "600",
          oct(keyf.stat().st_mode)[-3:])

    # --- stabilă între încărcări (nu regenerează) ---
    before = push._priv
    push._priv = None
    push._load_or_create()
    check("cheia se reîncarcă din fișier (nu se regenerează)", push.public_key_b64() == pub)
    push._priv = before

    # --- payload generic ---
    import json
    d = json.loads(push.payload("Task eșuat pe web1", "exit 1", tag="t", url="/"))
    check("payload JSON generic", d == {"title": "Task eșuat pe web1", "body": "exit 1",
                                        "tag": "t", "url": "/"})

    # --- VAPID JWT ES256 valid pe originea endpoint-ului ---
    endpoint = "https://fcm.googleapis.com/fcm/send/abc123"
    header = push._vapid_auth(endpoint)
    tok = header.split("t=", 1)[1].split(",", 1)[0] if "t=" in header else ""
    try:
        claims = jwt.decode(tok, push._priv.public_key(), algorithms=["ES256"],
                            audience="https://fcm.googleapis.com")
        jwt_ok = (claims["aud"] == "https://fcm.googleapis.com"
                  and claims["sub"] == config.PUBLIC_URL and claims["exp"] > 0)
    except Exception as e:  # noqa: BLE001
        jwt_ok = False
        claims = str(e)
    check("Authorization: schema vapid", header.startswith("vapid t="))
    check("JWT VAPID e ES256 valid (aud=originea push, sub=instanța)", jwt_ok, str(claims))

    # --- criptare aes128gcm: un receptor real decriptează ---
    recv = ec.generate_private_key(ec.SECP256R1())
    p256dh = _b64u(recv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    auth = _b64u(os.urandom(16))
    enc = push._encrypt(b"salut-telefon", p256dh, auth)
    try:
        out = http_ece.decrypt(enc, private_key=recv,
                               auth_secret=base64.urlsafe_b64decode(auth + "=="),
                               version="aes128gcm")
    except Exception as e:  # noqa: BLE001
        out = repr(e)
    check("aes128gcm face round-trip cu un receptor real", out == b"salut-telefon", repr(out))

    # --- SSRF: allowlist de endpoint (fix review Faza 2) ---
    check("accept fcm https", push.endpoint_allowed("https://fcm.googleapis.com/fcm/send/abc"))
    check("accept mozilla", push.endpoint_allowed("https://updates.push.services.mozilla.com/wpush/v2/x"))
    check("accept apple", push.endpoint_allowed("https://web.push.apple.com/xyz"))
    check("respinge http (nu https)", not push.endpoint_allowed("http://fcm.googleapis.com/x"))
    check("respinge localhost", not push.endpoint_allowed("https://localhost/x"))
    check("respinge IP de metadata", not push.endpoint_allowed("https://169.254.169.254/latest"))
    check("respinge loopback", not push.endpoint_allowed("https://127.0.0.1/x"))
    check("respinge domeniu necunoscut", not push.endpoint_allowed("https://evil.example.com/x"))
    check("respinge sufix-spoof", not push.endpoint_allowed("https://fcm.googleapis.com.evil.com/x"))

    # --- fail-closed: fără cheie, nu trimite și nu aruncă ---
    push._priv = None
    push._pub_b64 = None
    push._disabled = True
    check("fără cheie → push dezactivat", push.enabled() is False)
    check("fără cheie → cheia publică None", push.public_key_b64() is None)
    check("fără cheie → send() nu trimite nimic",
          push.send([("https://x/y", "a", "b")], "t", "b") == [])

    print(f"\n{ok}/{total} teste trecute")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
