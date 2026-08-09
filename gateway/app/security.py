"""Passwords, web sessions, host tokens, secret vault, brute-force protection."""

import base64
import hashlib
import hmac
import ipaddress
import secrets
import time
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException, Request, WebSocket

from . import config, db, email_alerts, totp

# ── Vault (secrete criptate la repaus: token agent, parole/chei SSH) ──────────
_fernet: Optional[Fernet] = None
_secret_key: bytes = b""            # subcheie HMAC (token-uri de forward), separată de cheia seifului


def init_crypto(secret: bytes) -> None:
    global _fernet, _secret_key
    # L1: separare de scop. Cheia seifului rămâne pe secretul BRUT (schimbarea ei ar face
    # nedecriptabile toate secretele deja stocate). Cheia HMAC de forward e o subcheie derivată
    # cu HKDF, ca aceleași 32 de octeți să nu servească simultan drept cheie Fernet și cheie HMAC.
    # (Doar cookie-urile de forward existente se invalidează — au TTL scurt și se rotesc oricum.)
    _fernet = Fernet(base64.urlsafe_b64encode(secret))
    _secret_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"webterm/forward-token").derive(secret)


# ── Token-uri de forward (auth pe subdomeniile de port-forward) ───────────────
# HMAC legat de slug + expirare. Semnat pe domeniul principal (unde e sesiunea),
# validat pe subdomeniu. Nu se poate forja fără cheie și nu se poate replay pe alt
# forward (slug-ul intră în semnătură).
FORWARD_TOKEN_TTL = 12 * 3600

# M3: token-urile de forward sunt HMAC pe slug+exp, fără legătură cu sesiunea web — la logout
# rămâneau valide până expirau (12h), deci un cookie furat + un token de forward încă mergea după
# ce „ieșeai". Legăm un epoch în semnătură: bumpat la logout / schimbare de parolă → invalidează
# INSTANT toate token-urile de forward. Epoch-ul e efemer (per proces): un restart de gateway le
# invalidează oricum (mai sigur decât să persiste).
_forward_epoch: str = secrets.token_hex(8)

# …dar epoch-ul singur e GLOBAL, iar de la conturile multiple asta însemna că logout-ul lui A
# rupea tunelurile lui B. Share-urile au primit deja tratamentul ăsta (`_revoke_all_shares`
# ia un `owner_email`); token-urile de forward au rămas în urmă, în ACELAŞI handler de logout.
# Semnalat de un audit extern, ca „DoS colateral pe tuneluri".
#
# Deci două epoci, ambele în semnătură:
#   · cea globală — pentru cazurile care CHIAR trebuie să lovească pe toată lumea: rotirea
#     parolei (compromitere), ştergerea unui forward (slug-ul se reciclează), marcarea unui
#     host ca „cere 2FA";
#   · una per cont — bumpată la logout, ca să moară numai biletele emise de acel cont.
# Ca să ştim a cui e biletul la validare, contul intră în token (`exp.uid.sig`) ŞI în mesajul
# semnat: un uid schimbat de mână strică semnătura, nu deschide biletul altcuiva.
_forward_epoch_user: dict[int, str] = {}


def bump_forward_epoch(user_id: Optional[int] = None) -> None:
    """Fără argument: invalidează TOATE biletele de forward din instanţă.
    Cu `user_id`: doar biletele emise de acel cont."""
    global _forward_epoch
    if user_id is None:
        _forward_epoch = secrets.token_hex(8)
        _forward_epoch_user.clear()
    else:
        _forward_epoch_user[user_id] = secrets.token_hex(8)


def _forward_msg(slug: str, exp: int, uid: int) -> bytes:
    return b"wtfwd:%s:%d:%d:%s:%s" % (
        slug.encode(), exp, uid, _forward_epoch.encode(),
        _forward_epoch_user.get(uid, "").encode())


def make_forward_token(slug: str, user_id: int, ttl: int = FORWARD_TOKEN_TTL) -> str:
    exp = int(time.time()) + ttl
    sig = hmac.new(_secret_key, _forward_msg(slug, exp, user_id), hashlib.sha256).hexdigest()
    return "%d.%d.%s" % (exp, user_id, sig)


def verify_forward_token(token: Optional[str], slug: str) -> bool:
    if not token:
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    exp_s, uid_s, sig = parts
    try:
        exp, uid = int(exp_s), int(uid_s)
    except ValueError:
        return False
    if exp < time.time():
        return False
    expected = hmac.new(_secret_key, _forward_msg(slug, exp, uid), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def encrypt_secret(plaintext: str) -> str:
    """Criptează un secret pentru stocare (Fernet = AES-CBC + HMAC autentificat)."""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(blob: str) -> str:
    return _fernet.decrypt(blob.encode()).decode()

_ph = PasswordHasher()
# fixed hash used to keep login timing constant when the email doesn't exist
_DUMMY_HASH = _ph.hash("webterm-timing-equalizer")

WEB_SESSION_TTL = config.WEB_SESSION_TTL
# L2: pe lângă TTL-ul absolut, o sesiune inactivă atâtea secunde e invalidată (front-door-ul e un
# root shell pe flotă → o sesiune uitată deschisă zile e prea generoasă). „Slide"-uim last_seen la
# folosire, dar throttled, ca să nu scriem în DB la fiecare cerere. Ambele valori se pot strânge
# din env (WEBTERM_SESSION_TTL_DAYS / WEBTERM_SESSION_IDLE_HOURS) — vezi config.
WEB_SESSION_IDLE = config.WEB_SESSION_IDLE
_SLIDE_INTERVAL = 120
# __Host- prefix (requires Secure + Path=/ + no Domain) blocks subdomain
# cookie injection; usable only over https
COOKIE_NAME = "__Host-wt_session" if config.PUBLIC_URL.startswith("https://") else "wt_session"
COOKIE_SECURE = config.PUBLIC_URL.startswith("https://")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        _ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False


def dummy_verify() -> None:
    """Burn the same time as a real verify so a missing user can't be told
    apart from a wrong password by timing."""
    try:
        _ph.verify(_DUMMY_HASH, "definitely-wrong")
    except VerifyMismatchError:
        pass


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def _peer_is_trusted(peer: str) -> bool:
    """Doar un peer din reţea privată/loopback poate fi „proxy-ul nostru".

    `X-Forwarded-For` e scris de client dacă cererea ajunge DIRECT la aplicaţie (port expus,
    hop-uri configurate greşit, container accesibil în reţea). Atunci antetul nu spune nimic
    despre client — spune ce a vrut clientul să scriem în jurnal, în rate-limit şi în lockout.
    Într-un deployment normal proxy-ul e pe reţeaua docker, deci privat. Semnalat de un audit
    extern, 2026-08-06."""
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if config.TRUSTED_PROXY_CIDRS:
        # listă explicită → strict. Un CIDR invalid nu deschide poarta: îl ignorăm, iar dacă
        # niciunul nu se potriveşte, antetul nu e crezut (fail-closed).
        for cidr in config.TRUSTED_PROXY_CIDRS:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    return ip.is_private or ip.is_loopback


def client_ip(request: Request) -> str:
    """Real client IP behind the trusted reverse proxy. X-Forwarded-For is
    client-spoofable on the left; only the last N hops (the proxies you run)
    are authoritative, so we count `TRUSTED_PROXY_HOPS` from the right. Behind
    Cloudflare, CF-Connecting-IP is un-spoofable and preferred.

    Eşuăm ÎNCHIS când antetul are mai puţine intrări decât hop-uri de încredere: înainte,
    `max(0, len-hops)` întorcea în cazul ăsta PRIMA valoare — adică exact ce a scris clientul.
    Cine putea ajunge direct la aplicaţie (hop-uri configurate greşit, port expus, container
    accesibil în reţea) îşi putea alege „IP-ul real": scăpa de propriul lockout sau îl provoca
    pe al altcuiva. Fără destule intrări, singura valoare de încredere e peer-ul socketului."""
    peer = request.client.host if request.client else ""
    # CF-Connecting-IP e la fel de scriibil de client ca X-Forwarded-For dacă cererea ajunge
    # DIRECT la aplicaţie. Ramura XFF de mai jos a fost înăsprită; asta rămăsese asimetric
    # deschisă — un audit intern a prins-o. Acelaşi gard pe ambele.
    if config.TRUST_CF_CONNECTING_IP and _peer_is_trusted(peer):
        cf = request.headers.get("cf-connecting-ip")
        if cf:
            return cf.strip()
    xff = request.headers.get("x-forwarded-for") if _peer_is_trusted(peer) else None
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        # `>=`, nu `max(0, ...)`: mai puţine intrări decât hop-uri = antet incomplet sau
        # forjat, deci nu-l credem deloc (vezi docstring).
        if len(parts) >= config.TRUSTED_PROXY_HOPS:
            # the client as seen by the outermost proxy we trust
            return parts[len(parts) - config.TRUSTED_PROXY_HOPS]
    return request.client.host if request.client else "?"


def client_ip_ws(ws) -> str:
    """La fel ca client_ip, dar pentru un WebSocket (agent_ws) — are `.headers` şi `.client`."""
    ws_peer = ws.client.host if ws.client else ""
    if config.TRUST_CF_CONNECTING_IP and _peer_is_trusted(ws_peer):   # aceeaşi paritate ca în client_ip
        cf = ws.headers.get("cf-connecting-ip")
        if cf:
            return cf.strip()
    xff = ws.headers.get("x-forwarded-for") if _peer_is_trusted(ws_peer) else None
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if len(parts) >= config.TRUSTED_PROXY_HOPS:      # fail-closed, ca în client_ip
            return parts[len(parts) - config.TRUSTED_PROXY_HOPS]
    return ws.client.host if ws.client else "?"


async def create_web_session(user_id: int, user_agent: str = "",
                             device_new: bool = False) -> str:
    token = new_token()
    now = time.time()
    await db.execute(
        "INSERT INTO web_sessions(token_hash, user_id, created, expires, user_agent, last_seen,"
        " device_new) VALUES(?,?,?,?,?,?,?)",
        sha256_hex(token), user_id, now, now + WEB_SESSION_TTL, user_agent[:200], now,
        1 if device_new else 0)
    return token


async def session_is_new_device(request: Request) -> bool:
    """A pornit sesiunea asta de pe un loc nemaivăzut la un login al contului?

    Citim ştampila pusă la login, nu tabela `seen_logins`: login-ul reuşit ÎNREGISTRAEZĂ IP-ul,
    deci o interogare de aici ar răspunde mereu „cunoscut" şi verificarea ar arăta că
    funcţionează fără să facă nimic. Verdictul e îngheţat când era încă adevărat."""
    tok = request.cookies.get(COOKIE_NAME)
    if not tok:
        return False
    row = await db.fetchone(
        "SELECT device_new FROM web_sessions WHERE token_hash=?", sha256_hex(tok))
    return bool(row and row["device_new"])


# ── Coduri de confirmare pe email (schimbări de credenţiale de pe un loc nou) ─
# Un cod, nu un link: link-ul e clicabil din inboxul oricui a ajuns la el, iar scanerele de
# mail îl pot deschide singure — adică pot consuma un token single-use înainte să-l vezi tu.
# Codul se tastează în pagina în care eşti deja, deci dovedeşte şi accesul la inbox, şi că eşti
# omul care a pornit acţiunea.
EMAIL_CODE_TTL = 600.0
EMAIL_CODE_MAX_ATTEMPTS = 5


async def issue_email_challenge(user_id: int, purpose: str) -> str:
    code = "%06d" % secrets.randbelow(1_000_000)
    now = time.time()
    await db.execute(
        "INSERT INTO email_challenges(user_id, purpose, code_hash, created, expires, attempts)"
        " VALUES(?,?,?,?,?,0) ON CONFLICT(user_id, purpose) DO UPDATE SET"
        " code_hash=excluded.code_hash, created=excluded.created, expires=excluded.expires,"
        " attempts=0",
        user_id, purpose, sha256_hex(code), now, now + EMAIL_CODE_TTL)
    return code


async def consume_email_challenge(user_id: int, purpose: str, code: str) -> bool:
    """Single-use, expirat după 10 minute, cel mult 5 încercări. Incrementarea şi citirea sunt
    o singură instrucţiune: altfel două cereri concurente citeau acelaşi contor şi plafonul
    devenea decorativ (6 cifre se ghicesc dacă ai voie să încerci de un milion de ori)."""
    row = await db.execute_returning(
        "UPDATE email_challenges SET attempts = attempts + 1"
        " WHERE user_id=? AND purpose=? AND expires > ? AND attempts < ?"
        " RETURNING code_hash", user_id, purpose, time.time(), EMAIL_CODE_MAX_ATTEMPTS)
    if not row:
        return False
    if not tokens_equal(row["code_hash"], sha256_hex((code or "").strip())):
        return False
    await db.execute("DELETE FROM email_challenges WHERE user_id=? AND purpose=?",
                     user_id, purpose)
    return True


async def user_for_token(token: Optional[str]):
    if not token:
        return None
    now = time.time()
    th = sha256_hex(token)
    ws = await db.fetchone(
        "SELECT user_id, expires, last_seen FROM web_sessions WHERE token_hash=? AND expires > ?",
        th, now)
    if not ws:
        return None
    # L2: idle-expiry. last_seen NULL = sesiune dinainte de migrație → o tratăm ca proaspătă
    # (nu deconectăm pe toată lumea la deploy); prima folosire îi setează last_seen.
    last = ws["last_seen"]
    if last is not None and now - last > WEB_SESSION_IDLE:
        await db.execute("DELETE FROM web_sessions WHERE token_hash=?", th)
        return None
    if last is None or now - last > _SLIDE_INTERVAL:      # slide throttled (nu un write/cerere)
        await db.execute("UPDATE web_sessions SET last_seen=? WHERE token_hash=?", now, th)
    return await db.fetchone("SELECT * FROM users WHERE id=?", ws["user_id"])


async def session_valid(token: Optional[str]) -> bool:
    """Revalidare pentru WS-uri de lungă durată: sesiunea încă există, nu e expirată şi nu e
    idle-expired — FĂRĂ a aluneca `last_seen` (altfel un WS deschis ar ţine sesiunea vie la
    nesfârşit). Slide-ul rămâne pe cererile HTTP reale (poll-ul de stare). Prinde logout
    (rândul e şters de `destroy_web_session`) şi idle-expiry pe un socket deja deschis."""
    if not token:
        return False
    now = time.time()
    ws = await db.fetchone(
        "SELECT last_seen FROM web_sessions WHERE token_hash=? AND expires > ?",
        sha256_hex(token), now)
    if not ws:
        return False
    last = ws["last_seen"]
    if last is not None and now - last > WEB_SESSION_IDLE:
        return False
    return True


async def require_user(request: Request):
    user = await user_for_token(request.cookies.get(COOKIE_NAME))
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


# ── Token-uri de automatizare ────────────────────────────────────────────────
# Un token NU e un cont: nu poate crea conturi, nu atinge cheia de semnare, nu descarcă
# backup-uri (ar conţine cheia seifului) şi nu poate deschide share-uri. Endpoint-urile care
# îl acceptă sunt marcate EXPLICIT (listă albă), iar hosturile cu `require_2fa` rămân
# inaccesibile prin token, fiindcă step-up-ul cere o cheie fizică.
TOKEN_PREFIX = "wt_"


async def api_token_principal(request: Request):
    """Întoarce dict-ul token-ului dacă cererea poartă un Bearer valid, altfel None."""
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    raw = auth[7:].strip()
    if not raw.startswith(TOKEN_PREFIX):
        return None
    row = await db.fetchone("SELECT * FROM api_tokens WHERE token_hash=?", sha256_hex(raw))
    if not row or row["expires"] < time.time():
        return None
    # `last_used` e util la audit („tokenul ăsta mai e folosit?"), dar nu merită o scriere la
    # fiecare cerere: îl actualizăm cel mult o dată pe minut.
    if not row["last_used"] or time.time() - row["last_used"] > 60:
        await db.execute("UPDATE api_tokens SET last_used=? WHERE id=?", time.time(), row["id"])
    return dict(row)


def token_scopes(tok: dict) -> set:
    return {s.strip() for s in (tok.get("scopes") or "").split(",") if s.strip()}


def require_scope(scope: str):
    """Dependenţă pentru endpoint-urile deschise automatizării: acceptă ORI cookie de sesiune
    (om în browser), ORI un token cu scope-ul cerut. Restul API-ului rămâne doar pe cookie."""
    async def dep(request: Request):
        tok = await api_token_principal(request)
        if tok is not None:
            if scope not in token_scopes(tok):
                raise HTTPException(403, "the token does not have the '%s' scope" % scope)
            # forma minimă de „principal", ca endpoint-urile să nu ştie diferenţa
            return {"id": None, "email": "token:" + tok["name"], "is_token": True}
        return await require_user(request)
    return dep


async def require_user_ws(websocket: WebSocket):
    return await user_for_token(websocket.cookies.get(COOKIE_NAME))


# Cât trebuie să dureze ca o adresă să devină „un loc al tău". Prima variantă a fost „a mai
# fost văzută măcar o dată", şi se ocolea singură: cine avea parola se loghea o dată de la el
# de-acasă, iar a doua oară adresa lui era deja „cunoscută" — poarta se deschidea atacatorului
# fiindcă atacase de două ori. Un loc obişnuit are ISTORIC: mai multe login-uri, întinse peste
# mai mult de o zi. Iar prima vizită de la o adresă nouă trimite deja alerta de login nou, deci
# fereastra de 24h nu e tăcută — e exact intervalul în care ai ocazia să reacţionezi.
ESTABLISHED_LOGINS = 3
ESTABLISHED_AGE = 24 * 3600


async def ip_is_known(user_id: int, ip: str) -> bool:
    """E adresa asta un loc STABILIT al contului (istoric, nu o singură apariţie)? Doar CITEŞTE
    — spre deosebire de `note_new_login`, care şi înregistrează. IP-ul se compară hash-uit."""
    row = await db.fetchone(
        "SELECT created, logins FROM seen_logins WHERE user_id=? AND ip_hash=?",
        user_id, sha256_hex(ip))
    return _established(row)


def _established(row) -> bool:
    return bool(row and row["logins"] >= ESTABLISHED_LOGINS
                and row["created"] <= time.time() - ESTABLISHED_AGE)


async def note_new_login(user, ip: str, user_agent: str) -> bool:
    """Alertă (best-effort) dacă e primul login reușit de pe acest IP pentru user.

    Întoarce True dacă adresa nu e (încă) un loc stabilit al contului — alerta de email pleacă
    doar la PRIMA apariţie, dar sesiunea rămâne marcată „dispozitiv nou" până când adresa strânge
    istoric. Apelantul foloseşte răspunsul ca să ştampileze
    sesiunea: verdictul trebuie luat AICI, fiindcă exact apelul ăsta înregistrează adresa —
    orice verificare de după ar găsi-o deja cunoscută."""
    ih = sha256_hex(ip)
    row = await db.fetchone(
        "SELECT created, logins FROM seen_logins WHERE user_id=? AND ip_hash=?", user["id"], ih)
    # Verdictul se ia pe starea de DINAINTE de login-ul curent: altfel fiecare primă vizită
    # s-ar valida singură.
    established = _established(row)
    await db.execute(
        "INSERT INTO seen_logins(user_id, ip_hash, created, logins) VALUES(?,?,?,1)"
        " ON CONFLICT(user_id, ip_hash) DO UPDATE SET logins = logins + 1",
        user["id"], ih, time.time())
    if row is None:
        email_alerts.notify_new_login(ip, user_agent, user["email"])
    return not established


async def verify_second_factor(user, code: str) -> bool:
    """Al doilea factor pentru un user cu TOTP activ: cod TOTP valid SAU un cod
    de recuperare nefolosit (care se consumă). Cu rate-limit deja aplicat sus."""
    secret = decrypt_secret(user["totp_secret_encrypted"])
    matched = totp.verify_counter(secret, code.strip())
    if matched is not None:
        # anti-replay: un cod TOTP valid ~90s; fără asta, un cod observat (shoulder-surf,
        # phishing) e reutilizabil în fereastră. Respingem reutilizarea aceluiași pas sau
        # a unuia anterior; la succes reținem counter-ul.
        # anti-replay ATOMIC: UPDATE condiţional + RETURNING într-o singură instrucţiune
        # serializată. Read-check-update în paşi separaţi era TOCTOU — două login-uri
        # concurente cu acelaşi cod citeau ambele counter-ul vechi şi treceau amândouă.
        # `IS NULL` acoperă prima folosire (counter încă nesetat).
        claimed = await db.execute_returning(
            "UPDATE users SET totp_last_counter=? WHERE id=?"
            " AND (totp_last_counter IS NULL OR totp_last_counter < ?) RETURNING id",
            matched, user["id"], matched)
        return claimed is not None
    # fallback: cod de recuperare (single-use, stocat hash-uit)
    ch = sha256_hex(code.strip())
    row = await db.fetchone(
        "SELECT id FROM recovery_codes WHERE user_id=? AND code_hash=? AND used IS NULL",
        user["id"], ch)
    if row:
        # single-use ATOMIC: două cereri concurente cu acelaşi cod → doar una revendică rândul
        claimed = await db.execute_returning(
            "UPDATE recovery_codes SET used=? WHERE id=? AND used IS NULL RETURNING id",
            time.time(), row["id"])
        return claimed is not None
    return False


async def destroy_web_session(token: Optional[str]) -> None:
    if token:
        await db.execute("DELETE FROM web_sessions WHERE token_hash = ?",
                         sha256_hex(token))


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME, token, max_age=WEB_SESSION_TTL,
        httponly=True, samesite="lax", secure=COOKIE_SECURE, path="/")


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/", secure=COOKIE_SECURE, samesite="lax")


# ---------------------------------------------------------------------------
# Brute-force protection: sliding window + temporary lockout, per IP and
# a global backstop against distributed guessing.
# ---------------------------------------------------------------------------

_FAIL_WINDOW = 900         # 15 min
_IP_MAX_FAILS = config.IP_MAX_FAILS   # failures per IP in the window before lockout
_IP_LOCKOUT = 900          # lockout duration once tripped
_GLOBAL_MAX_FAILS = 100    # total failures across all IPs in the window

_ip_fails: dict = {}       # ip -> [timestamps]
_ip_locked: dict = {}      # ip -> unlock_epoch
_global_fails: list = []


def _prune(now: float) -> None:
    """Curăţă ferestrele expirate — inclusiv cele PER-IP.

    Se cureţa doar `_global_fails`; cheile per-IP dispăreau numai la un login REUŞIT de pe acel
    IP, ceea ce un scanner nu face niciodată. Cu IPv6 (adrese practic gratuite) sau o botnetă,
    ambele dicţionare cresc nemărginit — memoria gateway-ului, într-un proces care ţine şi
    sesiunile, şi tunelurile."""
    global _global_fails
    _global_fails = [t for t in _global_fails if now - t < _FAIL_WINDOW]
    for ip, ts in list(_ip_fails.items()):
        fresh = [t for t in ts if now - t < _FAIL_WINDOW]
        if fresh:
            _ip_fails[ip] = fresh
        else:
            _ip_fails.pop(ip, None)
    for ip, unlock in list(_ip_locked.items()):
        if unlock <= now:
            _ip_locked.pop(ip, None)


def login_allowed(ip: str) -> tuple:
    """Returns (allowed, retry_after_seconds)."""
    now = time.time()
    unlock = _ip_locked.get(ip)
    if unlock and unlock > now:
        return False, int(unlock - now)
    _prune(now)
    if len(_global_fails) >= _GLOBAL_MAX_FAILS:
        return False, 60           # whole login surface is under attack; cool off
    return True, 0


def record_login_failure(ip: str) -> tuple:
    """Înregistrează un eșec. Returnează (locked_now, fails) — locked_now e True
    doar la tranziția care declanșează lockout-ul, ca apelantul să poată alerta."""
    now = time.time()
    fails = [t for t in _ip_fails.get(ip, []) if now - t < _FAIL_WINDOW]
    fails.append(now)
    _ip_fails[ip] = fails
    _global_fails.append(now)
    n = len(fails)
    if n >= _IP_MAX_FAILS:
        _ip_locked[ip] = now + _IP_LOCKOUT
        _ip_fails[ip] = []
        email_alerts.notify_lockout(ip, n)
        return True, n
    return False, n


def record_login_success(ip: str) -> None:
    _ip_fails.pop(ip, None)
    _ip_locked.pop(ip, None)


# ---------------------------------------------------------------------------
# Step-up grants: a fresh factor (passkey / password) issues a short-lived,
# single-use token bound to (user, host) that gates connecting to a 2FA host.
# ---------------------------------------------------------------------------

_stepup_grants: dict = {}      # token -> (user_id, host_id, expiry)
STEPUP_TTL = 120               # secunde; deblocarea e efemeră, ca `sudo`


def issue_stepup_grant(user_id: int, host_id: int) -> str:
    now = time.time()
    for k in [k for k, v in _stepup_grants.items() if v[2] < now]:
        _stepup_grants.pop(k, None)
    token = new_token()
    _stepup_grants[token] = (user_id, host_id, now + STEPUP_TTL)
    return token


def consume_stepup_grant(grant: str, user_id: int, host_id: int) -> bool:
    """Single-use: pops the grant and checks it matches this user+host."""
    rec = _stepup_grants.pop(grant or "", None)
    if not rec:
        return False
    uid, hid, exp = rec
    return uid == user_id and hid == host_id and exp >= time.time()


# Fereastră de step-up per (user, host): un grant passkey (sau parola) DESCHIDE fereastra, iar
# acțiunile sensibile ulterioare pe host (run, fs, sesiune, update) o consultă în loc să ceară
# re-verificare per-click (altfel file-browser-ul ar cere passkey la fiecare navigare). Ca `sudo`.
_stepup_windows: dict = {}     # (user_id, host_id) -> (opened_at, expiry)
STEPUP_WINDOW = 300            # 5 min inactivitate → se închide (idle timeout, sliding)
STEPUP_WINDOW_MAX = 3600       # plafon ABSOLUT de la primul step-up: peste atât, re-verificare oricât de activ ai fi


def open_stepup_window(user_id: int, host_id: int) -> float:
    now = time.time()
    exp = now + STEPUP_WINDOW
    _stepup_windows[(user_id, host_id)] = (now, exp)
    return exp


def stepup_window_ok(user_id: int, host_id: int) -> bool:
    now = time.time()
    rec = _stepup_windows.get((user_id, host_id))
    if rec is None:
        return False
    opened_at, exp = rec
    if exp < now:
        _stepup_windows.pop((user_id, host_id), None)
        return False
    # sliding (ca `sudo`): folosirea activă prelungește fereastra (idle timeout de 5 min), ca o editare
    # lungă de fișier să nu ceară re-verificare la 5 min fix — DAR mărginit de un plafon absolut de la
    # primul step-up, ca un cookie furat să nu poată ține „sudo-ul" viu la nesfârșit lovind endpoint-uri.
    _stepup_windows[(user_id, host_id)] = (opened_at, min(now + STEPUP_WINDOW, opened_at + STEPUP_WINDOW_MAX))
    return True


def clear_stepup_for(user_id: int) -> None:
    """Închide ferestrele de step-up + grant-urile în așteptare ale userului. Chemat la
    logout / schimbare de parolă / schimbare de passkey — un cookie furat nu mai păstrează
    „sudo-ul" peste o rotire de credențiale."""
    for k in [k for k in _stepup_windows if k[0] == user_id]:
        _stepup_windows.pop(k, None)
    for t in [t for t, v in _stepup_grants.items() if v[0] == user_id]:
        _stepup_grants.pop(t, None)
