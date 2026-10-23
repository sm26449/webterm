"""Web Push (Faza 2) — notificări pe telefon chiar cu aplicația ÎNCHISĂ.

De ce aici, server-side: când browserul/PWA e închis, detecția din Faza 1 (în browser) nu mai
rulează. Hub-ul gateway-ului scanează fluxul sesiunii și cu zero clienți conectați (vezi
core.SessionHub / osc133), deci SERVERUL vede „task terminat" și poate trimite un push către
abonamentele contului (tabela push_subscriptions). Protocol: RFC 8291 (criptare) + RFC 8292 (VAPID).

Acest modul e stratul de CRIPTARE + TRIMITERE, fără DB (testabil, sincron; apelat prin
asyncio.to_thread din core). Orchestrarea async (încarcă abonamentele, șterge-le pe cele moarte)
stă la apelant.

Dependințe (minime, deliberat — vezi gateway/requirements.txt):
  - cheia VAPID (ES256) = EC P-256, persistată în DATA_DIR/vapid.key (ca agent-signing.key); JWT-ul
    de autorizare îl semnăm cu PyJWT (deja prezent);
  - payload-ul se criptează aes128gcm cu `http_ece` (singura dependință nouă; trage doar cryptography);
  - POST-ul prin urllib.request (stdlib), ca tot HTTP-ul outbound al gateway-ului.

FAIL-CLOSED: dacă o dependință crypto lipsește sau cheia VAPID nu se poate crea/încărca, push-ul e
pur și simplu DEZACTIVAT (`enabled()` False); restul aplicației merge. SECURITATE: payload-ul trece
prin serviciul de push al vendorului (Apple/Google/Mozilla) — apelantul NU trebuie să pună în el
text de terminal / de comandă, doar un rezumat generic („task eșuat pe <host>")."""
import base64
import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from . import config

log = logging.getLogger("webterm")

# SSRF (clasa din audit, ca la webhook în email_alerts): endpoint-ul de abonament vine de la client,
# iar SERVERUL face POST la el — fără filtru, ar fi un primitiv de cerere internă pentru orice cont.
# Serviciile de push ale vendorilor sunt SINGURELE destinaţii legitime, deci le punem pe allowlist
# (apărare completă: nu se poate ţinti nimic intern). https obligatoriu. Redirect-urile NU se
# urmăresc (un 30x ar ocoli orice verificare → _NoRedirect).
_PUSH_HOSTS = (
    "fcm.googleapis.com",            # Chrome / Edge / Chromium (desktop + Android)
    ".push.services.mozilla.com",    # Firefox
    ".notify.windows.com",           # Edge / WNS
    ".wns.windows.com",
    ".push.apple.com",               # Safari / iOS (web.push.apple.com)
)


def endpoint_allowed(endpoint: str) -> bool:
    """True doar pentru un endpoint https către un serviciu de push cunoscut — restul = SSRF."""
    try:
        u = urlsplit(endpoint)
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    if u.scheme != "https" or not host:
        return False
    return any(host == h or (h[0] == "." and host.endswith(h)) for h in _PUSH_HOSTS)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Nu urmări redirect-uri: un 30x de la un endpoint ostil ar ocoli allowlist-ul (anti-SSRF)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_opener = urllib.request.build_opener(_NoRedirect)

# cheia privată VAPID (EC P-256), ținută în memorie după prima încărcare; cheia publică (punctul
# necomprimat, base64url) e „application server key"-ul trimis browserului pentru pushManager.subscribe
_priv = None
_pub_b64: Optional[str] = None
_disabled = False     # crypto/http_ece lipsă SAU cheia nu se poate crea → push oprit (fail-closed)


def _b64u(b: bytes) -> str:
    """base64url FĂRĂ padding (forma din Web Push / JWT)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64u(s: str) -> bytes:
    """base64url al clientului (p256dh/auth) — padding-ul lipsește, îl adăugăm la loc."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key_path():
    return config.DATA_DIR / "vapid.key"


def _load_or_create() -> None:
    global _priv, _pub_b64, _disabled
    if _priv is not None or _disabled:
        return
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        config.ensure_dirs()
        p = _key_path()
        if p.exists():
            _priv = serialization.load_pem_private_key(p.read_bytes(), password=None)
        else:
            _priv = ec.generate_private_key(ec.SECP256R1())
            pem = _priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),   # necriptat, dar 0600 de la creare (ca data/secret)
            )
            # 0600 ATOMIC (nu write + chmod separat): altfel cheia privată ar purta o clipă umask-ul
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, pem)
            finally:
                os.close(fd)
        pub = _priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        _pub_b64 = _b64u(pub)
    except Exception as e:   # noqa: BLE001 — orice eșec = push dezactivat, nu crash de boot
        _disabled = True
        log.warning("Web Push dezactivat (cheia VAPID nu s-a putut încărca/crea): %s", e)


def enabled() -> bool:
    """True = avem cheie VAPID și crypto-ul necesar; altfel push-ul e oprit (fail-closed)."""
    _load_or_create()
    return _priv is not None and not _disabled


def public_key_b64() -> Optional[str]:
    """Application server key (base64url) pentru pushManager.subscribe; None dacă push-ul e oprit."""
    _load_or_create()
    return _pub_b64 if enabled() else None


# Textul notificării PUSH (generat SERVER-side, cu aplicația închisă): nu poate folosi catalogul de
# limbă din browser (localStorage), deci ținem aici cele câteva șiruri, în limba aleasă la abonare
# (users.push_lang). GENERIC — fără text de comandă. Doar en + ro, ca restul UI-ului. (Notificările
# din Faza 1, cât aplicația e deschisă, SUNT localizate normal prin catalogul frontend.)
_STRINGS = {
    "en": {"failed_title": "Task failed", "failed_body": "exit {code} · {host}",
           "test_title": "WebTerm", "test_body": "Test notification — push works."},
    "ro": {"failed_title": "Task eșuat", "failed_body": "exit {code} · {host}",
           "test_title": "WebTerm", "test_body": "Notificare de test — push-ul merge."},
}


def strings(lang: Optional[str]) -> dict:
    """Șirurile de notificare în limba contului (en implicit / necunoscut)."""
    return _STRINGS.get(lang or "en", _STRINGS["en"])


def payload(title: str, body: str, tag: Optional[str] = None, url: Optional[str] = None) -> bytes:
    """Corpul JSON citit de service worker. GENERIC — fără text de terminal (trece prin vendor)."""
    d = {"title": title, "body": body}
    if tag:
        d["tag"] = tag
    if url:
        d["url"] = url
    return json.dumps(d, ensure_ascii=False).encode("utf-8")


def _vapid_auth(endpoint: str) -> str:
    """Antetul Authorization pentru schema `vapid` (aes128gcm): JWT ES256 + cheia publică."""
    import jwt

    parts = urlsplit(endpoint)
    claims = {
        "aud": "%s://%s" % (parts.scheme, parts.netloc),   # originea serviciului de push
        "exp": int(time.time()) + 12 * 3600,               # ≤24h cerut de RFC 8292; 12h cu marjă
        "sub": config.PUBLIC_URL,                          # contactul expeditorului (URL-ul instanței)
    }
    token = jwt.encode(claims, _priv, algorithm="ES256")
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return "vapid t=%s, k=%s" % (token, _pub_b64)


def _encrypt(data: bytes, p256dh_b64: str, auth_b64: str) -> bytes:
    """aes128gcm (RFC 8188/8291): cheie efemeră proaspătă per mesaj; http_ece înglobează automat
    cheia publică efemeră în antet. `dh` = cheia publică a clientului, `auth_secret` = secretul lui."""
    import http_ece
    from cryptography.hazmat.primitives.asymmetric import ec

    eph = ec.generate_private_key(ec.SECP256R1())
    return http_ece.encrypt(
        data,
        private_key=eph,
        dh=_unb64u(p256dh_b64),
        auth_secret=_unb64u(auth_b64),
        version="aes128gcm",
    )


class SendResult:
    """`ok` = acceptat; `gone` = 404/410 (abonament mort, de șters); `status` = codul HTTP."""

    __slots__ = ("ok", "gone", "status")

    def __init__(self, ok: bool, gone: bool = False, status: int = 0) -> None:
        self.ok, self.gone, self.status = ok, gone, status


def _send_one(endpoint: str, p256dh: str, auth: str, body: bytes) -> SendResult:
    if not endpoint_allowed(endpoint):        # SSRF: nu trimitem niciodată spre un host necunoscut
        log.warning("push: endpoint respins (nu e serviciu de push cunoscut)")
        return SendResult(False)
    try:
        enc = _encrypt(body, p256dh, auth)
    except Exception as e:   # noqa: BLE001
        log.warning("push: criptare eșuată: %s", e)
        return SendResult(False)
    req = urllib.request.Request(endpoint, data=enc, method="POST")
    req.add_header("Authorization", _vapid_auth(endpoint))
    req.add_header("Content-Encoding", "aes128gcm")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("TTL", "2419200")   # 4 săptămâni: serviciul reține dacă telefonul e offline
    try:
        with _opener.open(req, timeout=10) as r:   # opener FĂRĂ redirect (anti-SSRF)
            return SendResult(True, status=getattr(r, "status", 0) or 0)
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):          # RFC 8030: abonament expirat/dezabonat → de șters
            return SendResult(False, gone=True, status=e.code)
        log.warning("push: HTTP %s de la serviciul de push", e.code)
        return SendResult(False, status=e.code)
    except Exception as e:   # noqa: BLE001 — rețea/timeout: best-effort, nu stricăm nimic
        log.warning("push: POST eșuat: %s", e)
        return SendResult(False)


def send(subs: Iterable[Tuple[str, str, str]], title: str, body: str,
         tag: Optional[str] = None, url: Optional[str] = None) -> List[str]:
    """Trimite ACELAȘI mesaj către `subs` = (endpoint, p256dh, auth). SINCRON (urllib) — apelează-l
    prin asyncio.to_thread. Întoarce lista endpoint-urilor MOARTE (404/410), ca apelantul să le șteargă
    din DB. Dacă push-ul e oprit (fail-closed), nu trimite nimic și întoarce []."""
    if not enabled():
        return []
    data = payload(title, body, tag, url)
    gone: List[str] = []
    for endpoint, p256dh, auth in subs:
        r = _send_one(endpoint, p256dh, auth, data)
        if r.gone:
            gone.append(endpoint)
    return gone
