"""REST API, install script, agent + browser websocket endpoints."""

import asyncio
import base64
import hashlib
import html
import json
import logging
import os
import re
import shlex
import socket
import sqlite3
import ssl
import struct
import time
import urllib.parse

import asyncssh

from fastapi import (APIRouter, Depends, HTTPException, Request, Response,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field
from typing import Optional

from urllib.parse import quote, urlparse

from .errors import ApiError
from . import (audit, backup, cloudbackup, config, core, db, email_alerts, health, security,
               signing, totp, updatecheck)

log = logging.getLogger("webterm")
router = APIRouter()

_START_TIME = time.time()      # pentru uptime în /api/status


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class Credentials(BaseModel):
    email: str
    password: str
    setup_token: str = ""
    totp_code: str = ""      # 2FA: cod TOTP sau cod de recuperare, la login


# Setup token gates first-account creation so a bot can't win the race on a
# fresh public deploy. Set at boot (env WEBTERM_SETUP_TOKEN, else generated).
_setup_token: str = None


async def init_setup_token() -> None:
    global _setup_token
    if await db.fetchone("SELECT id FROM users LIMIT 1"):
        _setup_token = None          # already configured; setup is closed
        return
    _setup_token = config.SETUP_TOKEN or security.new_token()
    # `WEBTERM_SETUP_TOKEN=<value>` is a STABLE marker, read by `make token` and by the
    # install scripts. The prose above it is for humans and may be reworded; the marker may not.
    log.warning(
        "\n%s\n  WebTerm: no account yet. Setup token (required for the first "
        "sign-in):\n\n      %s\n\n  WEBTERM_SETUP_TOKEN=%s\n\n"
        "  You can find it again in this log. Create the account and setup closes itself.\n%s",
        "=" * 64, _setup_token, _setup_token, "=" * 64)


def _webauthn_available() -> bool:
    """WebAuthn rp_id must be a domain; IP addresses don't qualify."""
    from urllib.parse import urlparse
    host = urlparse(config.PUBLIC_URL).hostname or ""
    if host == "localhost":
        return True
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return "." in host


@router.get("/healthz")
async def healthz():
    """Sondă de sănătate (fără auth): confirmă că procesul răspunde și că DB-ul
    e accesibil. Folosită de Docker HEALTHCHECK ca să repornească un app blocat."""
    try:
        await db.fetchone("SELECT 1")
    except Exception:
        raise HTTPException(503, "db indisponibil")
    return {"ok": True}


@router.get("/api/state")
async def app_state(request: Request):
    """Bootstrap info for the frontend: setup needed? logged in?"""
    has_user = await db.fetchone("SELECT id FROM users LIMIT 1") is not None
    user = await security.user_for_token(request.cookies.get(security.COOKIE_NAME))
    backup_ready = False
    signing_missing = False
    signing_locked = False
    if user is not None:
        last = float(await _get_setting("backup_last", "0") or 0)
        seen = float(await _get_setting("backup_seen", "0") or 0)
        backup_ready = last > seen
        # nudge pentru cheia de semnare a flotei: lipsă → recomandă generarea înainte de
        # a înrola agenți; criptată & blocată → agenții nu se pot actualiza până la deblocare
        signing_missing = not signing.key_exists()
        signing_locked = signing.key_exists() and signing.is_encrypted() and not signing.is_loaded()
    return {"setup_required": not has_user,
            "authenticated": user is not None,
            "email": user["email"] if user else None,
            "webauthn_available": _webauthn_available(),
            "backup_ready": backup_ready,
            "signing_missing": signing_missing,
            "signing_locked": signing_locked,
            # overlay-ul de identitate; clientul rezolvă ${email}/${host}/${time}
            "watermark": (await _load_watermark()) if user is not None else None,
            # guardrail de comenzi (verificat client-side la Enter, via OSC 133)
            "command_guard": (await _load_command_guard()) if user is not None else None}


@router.post("/api/setup")
async def setup(creds: Credentials, request: Request, response: Response):
    global _setup_token
    if await db.fetchone("SELECT id FROM users LIMIT 1"):
        raise HTTPException(409, "already configured")
    ip = security.client_ip(request)
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        raise HTTPException(429, f"too many attempts; retry in {retry}s")
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    if not _setup_token or not security.tokens_equal(creds.setup_token, _setup_token):
        locked, fails = security.record_login_failure(ip)
        # Spune CÂTE mai ai. Fără asta, omul greşeşte tokenul de câteva ori (32 de caractere
        # copiate dintr-un log, la două minute după clonare), iar a şasea încercare îl blochează
        # 15 minute — inclusiv cu tokenul CORECT, fiindcă lockout-ul e pe IP, nu pe token. Din
        # afară arată ca „produsul e stricat". Semnalat de un audit extern pe traseul primei
        # instalări.
        left = max(config.IP_MAX_FAILS - fails, 0)
        if locked or left == 0:
            raise HTTPException(
                429, "too many wrong setup tokens — locked out for %d minutes. The token is in "
                     "the server logs: docker compose logs app | grep WEBTERM_SETUP_TOKEN"
                     % (security._IP_LOCKOUT // 60))
        raise HTTPException(
            403, "wrong setup token (%d attempt%s left before a %d-minute lockout) — it is in "
                 "the server logs: docker compose logs app | grep WEBTERM_SETUP_TOKEN"
                 % (left, "" if left == 1 else "s", security._IP_LOCKOUT // 60))
    _check_password(creds.password)
    if "@" not in creds.email or len(creds.email) > 200:
        raise ApiError(400, "account.badEmail", "invalid email")
    email = creds.email.strip().lower()
    pw_hash = await security.hash_password_async(creds.password)
    # Revendicare ATOMICĂ a setup-ului: INSERT condiționat de „niciun user încă", într-o
    # singură instrucțiune SQL (existența + insert sunt atomice în SQLite). Fără asta, două
    # cereri concurente cu același token treceau ambele de verificarea de la linia 107
    # (await-ul de hash e ÎNTRE check și insert) și creau două conturi → încălcau
    # invariantul single-account (nu există autorizare pe obiect).
    await db.execute(
        "INSERT INTO users(email, password_hash, created) "
        "SELECT ?,?,? WHERE NOT EXISTS (SELECT 1 FROM users)",
        email, pw_hash, time.time())
    row = await db.fetchone("SELECT id, email FROM users LIMIT 1")
    if not row or row["email"] != email:
        raise HTTPException(409, "already configured")   # altă cerere a câștigat cursa
    _setup_token = None              # single-use; setup is now closed
    security.record_login_success(ip)
    await _issue_cookie(response, row["id"], request)
    return {"ok": True}


# Parola avea doar prag INFERIOR. Nimic nu oprea un body de câţiva MB să ajungă la argon2 —
# şi la fiecare încercare de login, unde e gratuit de repetat. Impactul e mic (intrarea e
# pre-hashuită, login-ul e plafonat), dar un plafon costă un `if`. Generos intenţionat: nu vrem
# să tăiem passphrase-uri lungi, doar body-uri care nu sunt parole.
PASSWORD_MAX = 1024


def _check_password(pw: str, what: str = "password") -> None:
    if len(pw) < 8:
        raise HTTPException(400, "the %s must be at least 8 characters" % what)
    if len(pw) > PASSWORD_MAX:
        raise HTTPException(400, "the %s must be at most %d characters" % (what, PASSWORD_MAX))


@router.post("/api/login")
async def login(creds: Credentials, request: Request, response: Response):
    ip = security.client_ip(request)
    # auditul se scrie din middleware, DUPĂ răspuns — un login eșuat n-are cookie, deci
    # marcăm aici emailul încercat (altfel jurnalul ar arăta doar „cineva, de la IP-ul X")
    audit.actor(request, creds.email.strip().lower())
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        raise HTTPException(429, f"too many attempts; retry in {retry}s",
                            headers={"Retry-After": str(retry)})
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    user = await db.fetchone("SELECT * FROM users WHERE email=?",
                             creds.email.strip().lower())
    # verify (or a dummy verify when the user is absent) so timing can't
    # reveal whether the email exists
    ok = (user is not None and len(creds.password) <= PASSWORD_MAX
          and await security.verify_password_async(creds.password, user["password_hash"]))
    if user is None:
        await security.dummy_verify_async()
    if not ok:
        security.record_login_failure(ip)
        raise ApiError(401, "auth.badCredentials", "wrong email or password")
    # parola e corectă — dacă 2FA e activ, cere al doilea factor
    if user["totp_enabled"]:
        if not creds.totp_code:
            # nu e un eșec (parola era bună): semnalăm clientului să ceară codul
            return {"ok": False, "totp_required": True}
        if not await security.verify_second_factor(user, creds.totp_code):
            security.record_login_failure(ip)
            raise ApiError(401, "auth.bad2fa", "wrong 2FA code")
    security.record_login_success(ip)
    new_device = await security.note_new_login(user, ip, request.headers.get("user-agent", ""))
    await _issue_cookie(response, user["id"], request, new_device)
    return {"ok": True}


async def _issue_cookie(response: Response, user_id: int, request: Request,
                        device_new: bool = False) -> None:
    token = await security.create_web_session(
        user_id, request.headers.get("user-agent", ""), device_new)
    security.set_session_cookie(response, token)


async def _revoke_all_shares(owner_email: str | None = None,
                             owner_id: int | None = None) -> None:
    """Share-urile (PTY live, opţional writable) sunt acces DERIVAT — mor la logout /
    schimbare de parolă, ca token-urile de forward (M3). Altfel un share creat cu un
    cookie furat supravieţuieşte deconectării owner-ului până la expirare (max 24h).

    `owner_email` limitează revocarea la share-urile create de ACEL cont. Înainte era
    global, iar de la conturile multiple (1.0.137) asta însemna: logout-ul lui A omoară
    link-urile lui B, într-un mod imposibil de diagnosticat („de ce a murit share-ul de
    incident?"). Semnalat de un audit extern. Fără argument (sau pe share-uri vechi, fără
    `share_by`) rămâne global — la schimbarea parolei după compromitere vrei exact asta."""
    if owner_email or owner_id is not None:
        # id-ul e cheia; emailul rămâne rezervă pentru share-urile create înainte de migrare.
        # Cheiat DOAR pe email, o schimbare de email scotea share-urile de sub orice revocare.
        where = " WHERE share_token IS NOT NULL AND (share_by_id=? OR share_by=?)"
        args = (owner_id, owner_email)
        rows = await db.fetchall("SELECT id FROM sessions" + where, *args)
        await db.execute("UPDATE sessions SET share_token=NULL, share_expires=NULL,"
                         " share_writable=0" + where, *args)
        sids = {r["id"] for r in rows}
    else:
        await db.execute("UPDATE sessions SET share_token=NULL, share_expires=NULL, share_writable=0"
                         " WHERE share_token IS NOT NULL")
        sids = None
    for sid, hub in list(core.hubs.items()):
        if sids is None or sid in sids:
            await hub.revoke_shares()      # închide invitaţii deja conectaţi (stop broadcast)


@router.post("/api/logout")
async def logout(request: Request, response: Response):
    tok = request.cookies.get(security.COOKIE_NAME)
    u = await security.user_for_token(tok)
    if not u:
        # Fără sesiune validă nu e NIMIC de revocat — şi tocmai asta era gaura: `u` era None,
        # deci `_revoke_all_shares(None)` intra pe ramura GLOBALĂ (gândită pentru „schimbare de
        # parolă după compromitere") şi ştergea toate share-urile din instanţă, iar
        # `bump_forward_epoch()` invalida toate tokenurile de forward. Un simplu
        # `curl -X POST /api/logout`, fără cont şi fără cookie, de oriunde din lume, rupea toate
        # link-urile partajate şi toate tunelurile. Declanşabil şi cross-site: corp gol,
        # fără antete → simple request, fără preflight.
        security.clear_session_cookie(response)
        return {"ok": True}
    security.clear_stepup_for(u["id"])       # H1: nici o fereastră de „sudo" nu supraviețuiește logout-ului
    # M3: token-urile de port-forward mor la logout — dar numai ALE LUI. Global, asta însemna
    # că ieşirea unui cont rupea tunelurile deschise din alt cont, fără nimic în UI care să
    # explice de ce. Vezi `_revoke_all_shares`, care primise deja aceeaşi restrângere.
    security.bump_forward_epoch(u["id"])
    # doar share-urile CONTULUI care se deconectează — vezi _revoke_all_shares
    await _revoke_all_shares(u["email"], u["id"])
    await security.destroy_web_session(tok)
    security.clear_session_cookie(response)
    return {"ok": True}


class AccountUpdate(BaseModel):
    current_password: str
    email: str = None
    new_password: str = None
    email_code: str = ""        # confirmarea cerută când sesiunea vine de pe un dispozitiv nou


async def _verify_reauth_password(user, password: str) -> bool:
    """Verificare de parolă în sesiune (schimbare cont, dezactivare/regenerare 2FA, step-up
    host cu fallback pe parolă), PLAFONATĂ ca /api/login — altfel un cookie furat poate
    brute-forţa parola contului fără niciun lockout (preluare cont / slăbire 2FA / fereastră
    step-up). Cheie pe cont (single-account) → lockout global, indiferent de IP-ul atacatorului."""
    key = "reauth:%d" % user["id"]
    # Parola CORECTĂ trece chiar şi în lockout. Altfel plafonul devenea arma atacatorului
    # împotriva victimei: cu cookie-ul furat trimitea 5 parole greşite, contul intra în lockout
    # 900s, iar proprietarul — cu parola bună — primea 429. Cum schimbarea parolei e SINGURA cale
    # de a invalida sesiunea atacatorului, el repeta la fiecare 15 minute şi ţinea uşa închisă la
    # nesfârşit. Costul: un `verify_password` (argon2) per cerere şi în lockout, deci păstrăm un
    # plafon separat, mult mai larg, ca gard anti-CPU.
    allowed, retry = security.login_allowed(key)
    if not allowed and not security.login_allowed("reauth-hard:%d" % user["id"])[0]:
        raise HTTPException(429, f"too many attempts; retry in {retry}s",
                            headers={"Retry-After": str(retry)})
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    if await security.verify_password_async(password, user["password_hash"]):
        security.record_login_success(key)
        security.record_login_success("reauth-hard:%d" % user["id"])
        return True
    security.record_login_failure(key)
    if not allowed:
        # eşec ÎN lockout: numărăm pe plafonul dur, ca ghicirea să nu devină gratuită
        security.record_login_failure("reauth-hard:%d" % user["id"])
    return False


@router.post("/api/account")
async def update_account(body: AccountUpdate, request: Request, user=Depends(security.require_user)):
    """Change email and/or password. Requires the current password — plus, when the session
    was opened from a device never seen before, a code mailed to the account address."""
    if not await _verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    # Parola singură nu mai ajunge de pe un loc nou. Atacul pe care îl opreşte: cineva care
    # ARE deja parola (reutilizată, scursă, ghicită) şi o roteşte ca să te scoată pe tine
    # afară. Emailul e canalul pe care el nu-l are.
    #
    # Escaladăm, NU refuzăm: „de pe un loc necunoscut nu se poate schimba parola" sună bine
    # până când eşti în tren, tocmai ţi s-a scurs parola, şi tocmai atunci nu ţi se permite
    # s-o schimbi. Codul îl trece pe cel legitim în treizeci de secunde şi pe atacator deloc.
    #
    # Şi schimbarea de EMAIL trece prin aceeaşi poartă, în acelaşi handler: adresa e canalul
    # de recuperare, deci cine o poate muta neconfirmat şi-l poate muta pe el şi apoi schimbă
    # parola „confirmat".
    if (body.new_password or (body.email and body.email.strip().lower() != user["email"])) \
            and await security.session_is_new_device(request) and await email_alerts.smtp_ready():
        what = "change your WebTerm password" if body.new_password else "change your WebTerm email"
        if not body.email_code:
            code = await security.issue_email_challenge(user["id"], "account")
            try:
                await email_alerts.send_account_code(user["email"], code, what)
            except Exception as e:                        # noqa: BLE001
                log.warning("confirmation code could not be sent: %s", e)
                raise ApiError(503, "account.codeSendFailed",
                               "could not send the confirmation code by email")
            raise ApiError(403, "account.codeRequired",
                           "this device is new — enter the code we just emailed to %s"
                           % user["email"])
        if not await security.consume_email_challenge(user["id"], "account", body.email_code):
            raise ApiError(401, "account.badCode", "wrong or expired confirmation code")
    email = user["email"]
    if body.email and body.email.strip().lower() != email:
        email = body.email.strip().lower()
        # `users.email` e UNIQUE, iar `create_user` verifică duplicatele — aici nu. Rezultatul
        # era un IntegrityError nemanipulat, adică „500 Internal Server Error" pentru ceva ce
        # utilizatorul poate repara singur, dacă i se spune ce e.
        if await db.fetchone("SELECT 1 FROM users WHERE lower(email)=? AND id<>?",
                             email, user["id"]):
            raise HTTPException(409, "an account with that email already exists")
    pw_hash = user["password_hash"]
    if body.new_password:
        _check_password(body.new_password, "new password")
        pw_hash = await security.hash_password_async(body.new_password)
    await db.execute("UPDATE users SET email=?, password_hash=? WHERE id=?",
                     email, pw_hash, user["id"])
    # dacă s-a schimbat parola, invalidează celelalte sesiuni web (nu pe cea curentă)
    if body.new_password:
        current = request.cookies.get(security.COOKIE_NAME)
        await db.execute(
            "DELETE FROM web_sessions WHERE user_id=? AND token_hash!=?",
            user["id"], security.sha256_hex(current) if current else "")
        security.clear_stepup_for(user["id"])   # H1: rotirea parolei închide ferestrele de step-up
        security.bump_forward_epoch()           # M3: și invalidează token-urile de port-forward
        await _revoke_all_shares()              # M3-shares: rotirea parolei omoară share-urile derivate
    return {"ok": True, "email": email}


# ---------------------------------------------------------------------------
# TOTP (2FA opțional peste parolă). Passkey-urile rămân o cale separată.
# ---------------------------------------------------------------------------

def _gen_recovery_codes(n: int = 10) -> list:
    # coduri lizibile xxxx-xxxx din alfabet fără caractere ambigue
    import secrets as _s
    alpha = "abcdefghijkmnpqrstuvwxyz23456789"
    return ["-".join("".join(_s.choice(alpha) for _ in range(4)) for _ in range(2))
            for _ in range(n)]


@router.get("/api/totp/status")
async def totp_status(user=Depends(security.require_user)):
    remaining = await db.fetchone(
        "SELECT COUNT(*) AS c FROM recovery_codes WHERE user_id=? AND used IS NULL",
        user["id"])
    # Câte passkey-uri şi câte hosturi cer 2FA. Combinaţia „un singur passkey + hosturi
    # marcate require_2fa" e singurul mod în care te poţi bloca fără cale de întoarcere din
    # UI: pierzi dispozitivul, iar step-up-ul refuză parola cât timp mai există un passkey
    # înrolat. Ieşirea rămâne `python3 -m app.admin` de pe server — dar ăla e un lucru pe
    # care vrei să-l ştii ÎNAINTE, nu în seara în care ţi-a căzut telefonul în apă.
    pk = await db.fetchone(
        "SELECT COUNT(*) AS c FROM webauthn_credentials WHERE user_id=?", user["id"])
    gated = await db.fetchone("SELECT COUNT(*) AS c FROM hosts WHERE require_2fa=1")
    return {"enabled": bool(user["totp_enabled"]),
            "recovery_remaining": remaining["c"] if remaining else 0,
            "passkeys": pk["c"] if pk else 0,
            "hosts_2fa": gated["c"] if gated else 0,
            "single_passkey_risk": bool(pk and pk["c"] == 1 and gated and gated["c"] > 0)}


class TotpSetup(BaseModel):
    current_password: str = ""


# ── Conturi (mai multe, TOATE cu drepturi depline) ───────────────────────────
# Nu e RBAC şi nu pretinde să fie: nu există autorizare la nivel de obiect, deci orice cont
# poate tot. Ce câştigă echipa e ATRIBUIREA — în `audit_log` apare cine a făcut fiecare
# acţiune, iar fiecare om are propriile credenţiale (parolă, passkey, TOTP), deci revocarea
# unui coleg e o ştergere de cont, nu o schimbare de parolă anunţată tuturor.
# Cerut de două audituri externe (2026-08-06) ca fiind costul dominant la 2-3 oameni.

class UserIn(BaseModel):
    email: str
    password: str
    current_password: str = ""     # re-auth: un cont nou = încă o cheie la regat


class ReauthOnly(BaseModel):
    current_password: str = ""


@router.get("/api/users")
async def list_users(user=Depends(security.require_user)):
    rows = await db.fetchall(
        "SELECT u.id, u.email, u.created, u.totp_enabled,"
        " (SELECT COUNT(*) FROM webauthn_credentials c WHERE c.user_id=u.id) AS passkeys"
        " FROM users u ORDER BY u.created")
    return [{"id": r["id"], "email": r["email"], "created": r["created"],
             "totp": bool(r["totp_enabled"]), "passkeys": r["passkeys"],
             "is_self": r["id"] == user["id"]} for r in rows]


@router.post("/api/users")
async def create_user(body: UserIn, user=Depends(security.require_user)):
    if not await _verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongPassword", "wrong password")
    email = body.email.strip().lower()
    if "@" not in email or len(email) > 200:
        raise ApiError(400, "account.badEmail", "invalid email")
    _check_password(body.password)
    if await db.fetchone("SELECT id FROM users WHERE email=?", email):
        raise HTTPException(409, "an account with that email already exists")
    pw = await security.hash_password_async(body.password)
    await db.execute("INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
                     email, pw, time.time())
    log.info("new account created: %s (by %s)", email, user["email"])
    return await list_users(user)


# POST, nu DELETE: ştergerea cere parola în corp, iar un DELETE cu corp e prost suportat de
# clienţi (httpx nici nu-l oferă). Alternativa — parola în query string — ar fi ajuns în
# jurnalul de audit şi în logurile proxy-ului.
@router.post("/api/users/{uid}/delete")
async def delete_user(uid: int, body: ReauthOnly, user=Depends(security.require_user)):
    if not await _verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongPassword", "wrong password")
    if uid == user["id"]:
        # ştergerea propriului cont din propria sesiune = te blochezi la jumătatea operaţiei
        raise HTTPException(400, "you cannot delete your own account; do it from another one")
    row = await db.fetchone("SELECT email FROM users WHERE id=?", uid)
    if not row:
        raise HTTPException(404)
    n = (await db.fetchone("SELECT COUNT(*) AS c FROM users"))["c"]
    if n <= 1:
        raise HTTPException(400, "you cannot delete the last account")
    # tot ce ţinea de el moare odată cu el: sesiuni web, passkey-uri, coduri de recuperare,
    # IP-uri cunoscute. Altfel un cookie al contului şters ar rămâne valid.
    for sql in ("DELETE FROM web_sessions WHERE user_id=?",
                "DELETE FROM webauthn_credentials WHERE user_id=?",
                "DELETE FROM recovery_codes WHERE user_id=?",
                "DELETE FROM seen_logins WHERE user_id=?",
                "DELETE FROM users WHERE id=?"):
        await db.execute(sql, uid)
    # …„tot" trebuia să însemne şi asta. Token-urile de automatizare emise de contul şters îi
    # supravieţuiau până la expirare (până la un an), semnalat de un audit extern. Ele NU cer
    # cont ca să funcţioneze — sunt credenţiale de sine stătătoare — deci ştergerea contului
    # arăta ca o revocare completă fără să fie una. Le numărăm ca să apară în jurnal: cine
    # şterge un cont trebuie să vadă ce automatizări a oprit odată cu el.
    # `created_by_id` ESTE cheia; `created_by` rămâne ca rezervă pentru tokenurile emise
    # înainte de migrare, care n-au id. Fără id-ul ăsta, o simplă schimbare de email lăsa
    # tokenul în viaţă după ştergerea contului — până la un an.
    ntok = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM api_tokens WHERE created_by_id=? OR created_by=?",
        uid, row["email"]))["c"]
    await db.execute("DELETE FROM api_tokens WHERE created_by_id=? OR created_by=?",
                     uid, row["email"])
    security.clear_stepup_for(uid)
    security.bump_forward_epoch(uid)      # şi biletele lui de port-forward, ca la logout
    await _revoke_all_shares(row["email"], uid)
    if ntok:
        log.warning("account deleted: revoked %d automation token(s) issued by %s",
                    ntok, row["email"])
    log.warning("account deleted: %s (by %s)", row["email"], user["email"])
    return await list_users(user)


# ── Token-uri de automatizare ────────────────────────────────────────────────
# Cerute de auditul extern pentru joburi de mentenanţă / monitorizare. Nu sunt conturi:
# merg pe o listă albă mică (`security.require_scope`), au expirare obligatorie şi NU pot
# atinge hosturile cu 2FA. Crearea/revocarea se fac doar din browser, cu re-auth.
TOKEN_SCOPES = ("read", "run")
TOKEN_MAX_DAYS = 365


class TokenIn(BaseModel):
    name: str
    scopes: list[str] = ["read"]
    days: int = 90
    current_password: str = ""


def _token_row(r) -> dict:
    return {"id": r["id"], "name": r["name"], "scopes": r["scopes"], "created": r["created"],
            "created_by": r["created_by"], "expires": r["expires"], "last_used": r["last_used"],
            "expired": r["expires"] < time.time()}


# ── Dispozitivele conectate (sesiuni web) ────────────────────────────────────
# Până acum, dacă bănuiai un cookie furat aveai două opţiuni, amândouă prea mari: schimbi
# parola (omoară TOATE sesiunile, inclusiv a ta) sau intri prin SSH pe server. Lipsea exact
# lucrul dintre ele — „vezi ce dispozitive sunt logate şi scoate-l pe ăla".
#
# Datele existau deja: `web_sessions` ţine user-agent-ul de la autentificare, iar de la 2.0.2
# şi `device_new` (adresa era necunoscută atunci — verdict îngheţat, vezi `session_is_new_device`).
# `rowid` e cheia stabilă a rândului; NU expunem `token_hash`, care e amprenta credenţialei.

def _device_label(ua: str) -> str:
    """Etichetă scurtă din user-agent. Acelaşi raţionament ca `shortAgent` din frontend: un UA
    întreg e 150 de caractere din care nouă zecimi sunt istorie. Ordinea contează — Edge şi
    Chrome se declară amândouă „Chrome", Chrome pe iOS se declară „Safari"."""
    ua = ua or ""
    osn = ("iOS" if ("iPhone" in ua or "iPad" in ua) else
           "Android" if "Android" in ua else
           "macOS" if "Mac OS X" in ua else
           "Windows" if "Windows" in ua else
           "Linux" if "Linux" in ua else "")
    br = ("Edge" if "Edg/" in ua else
          "Opera" if "OPR/" in ua else
          "Firefox" if "Firefox/" in ua else
          "Chrome" if ("CriOS/" in ua or "Chrome/" in ua) else
          "Safari" if "Safari/" in ua else "")
    return " · ".join(x for x in (br, osn) if x) or (ua[:24] or "?")


@router.get("/api/account/sessions")
async def list_web_sessions(request: Request, user=Depends(security.require_user)):
    cur = security.sha256_hex(request.cookies.get(security.COOKIE_NAME) or "")
    rows = await db.fetchall(
        "SELECT rowid AS rid, token_hash, created, last_seen, expires, user_agent, device_new"
        " FROM web_sessions WHERE user_id=? AND expires > ? ORDER BY last_seen DESC",
        user["id"], time.time())
    return [{"id": r["rid"], "label": _device_label(r["user_agent"]),
             "created": r["created"], "last_seen": r["last_seen"], "expires": r["expires"],
             "new_device": bool(r["device_new"]),
             "current": security.tokens_equal(r["token_hash"], cur)} for r in rows]


@router.delete("/api/account/sessions/{rid}")
async def revoke_web_session(rid: int, request: Request,
                             user=Depends(security.require_user)):
    """Scoate un dispozitiv. Fără re-autentificare, deliberat: e o acţiune DEFENSIVĂ, iar
    parola cerută exact când te grăbeşti e frecare pe partea greşită. Cel mai rău lucru pe
    care îl poate face cineva cu cookie-ul tău e să te deconecteze — te loghezi la loc."""
    row = await db.fetchone(
        "SELECT token_hash FROM web_sessions WHERE rowid=? AND user_id=?", rid, user["id"])
    if not row:
        raise HTTPException(404, "no such session")
    await db.execute("DELETE FROM web_sessions WHERE rowid=? AND user_id=?", rid, user["id"])
    audit.detail(request, "revoked a web session")
    return {"ok": True}


@router.post("/api/account/sessions/revoke-others")
async def revoke_other_web_sessions(request: Request, user=Depends(security.require_user)):
    """„Deconectează-mă de peste tot, în afară de aici." Nu atinge parola, spre deosebire de
    singura cale existentă până acum."""
    cur = security.sha256_hex(request.cookies.get(security.COOKIE_NAME) or "")
    n = await db.fetchone(
        "SELECT COUNT(*) c FROM web_sessions WHERE user_id=? AND token_hash!=?",
        user["id"], cur)
    await db.execute("DELETE FROM web_sessions WHERE user_id=? AND token_hash!=?",
                     user["id"], cur)
    # Ferestrele de step-up sunt per (cont, host), nu per dispozitiv: dacă scoţi un dispozitiv
    # suspect, „sudo-ul" lui ar supravieţui pe al tău. Le închidem pe toate — costul e o
    # re-verificare cu passkey, exact lucrul pe care oricum îl vrei după aşa o acţiune.
    security.clear_stepup_for(user["id"])
    security.bump_forward_epoch(user["id"])
    audit.detail(request, "revoked %d other web sessions" % (n["c"] if n else 0))
    return {"ok": True, "revoked": n["c"] if n else 0}


@router.get("/api/tokens")
async def list_tokens(user=Depends(security.require_user)):
    rows = await db.fetchall("SELECT * FROM api_tokens ORDER BY created DESC")
    return [_token_row(r) for r in rows]


@router.post("/api/tokens")
async def create_token(body: TokenIn, user=Depends(security.require_user)):
    if not await _verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongPassword", "wrong password")
    name = body.name.strip()[:60]
    if not name:
        raise HTTPException(400, "give it a name (so you know what you are revoking)")
    scopes = [s for s in body.scopes if s in TOKEN_SCOPES]
    if not scopes:
        raise HTTPException(400, "pick at least one scope (read / run)")
    days = min(max(int(body.days), 1), TOKEN_MAX_DAYS)   # expirarea NU e opțională
    raw = security.TOKEN_PREFIX + security.new_token()
    await db.execute(
        "INSERT INTO api_tokens(name, token_hash, scopes, created, created_by,"
        " created_by_id, expires) VALUES(?,?,?,?,?,?,?)",
        name, security.sha256_hex(raw), ",".join(scopes), time.time(), user["email"],
        user["id"], time.time() + days * 86400)
    log.info("automation token created: %s (%s, %dd) by %s", name, ",".join(scopes), days,
             user["email"])
    # valoarea în clar se întoarce O SINGURĂ DATĂ; în DB stă doar hash-ul
    return {"token": raw, "tokens": await list_tokens(user)}


@router.post("/api/tokens/{tid}/revoke")
async def revoke_token(tid: int, user=Depends(security.require_user)):
    row = await db.fetchone("SELECT name FROM api_tokens WHERE id=?", tid)
    if not row:
        raise HTTPException(404)
    await db.execute("DELETE FROM api_tokens WHERE id=?", tid)
    log.warning("automation token revoked: %s (by %s)", row["name"], user["email"])
    return await list_tokens(user)


@router.post("/api/totp/setup")
async def totp_setup(body: TotpSetup, user=Depends(security.require_user)):
    """Generează un secret nou (încă neactivat) și întoarce QR-ul de înrolat.
    Nu devine efectiv până nu confirmi un cod prin /activate."""
    # M1: înrolarea unui factor 2FA e schimbare de credențiale — cere re-auth cu parola,
    # ca un cookie furat să nu poată înrola un TOTP atacator + să ia codurile de recuperare.
    if not await _verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    if user["totp_enabled"]:
        raise HTTPException(409, "2FA is already on; turn it off first")
    secret = totp.new_secret()
    await db.execute("UPDATE users SET totp_secret_encrypted=?, totp_enabled=0 WHERE id=?",
                     security.encrypt_secret(secret), user["id"])
    return {"secret": secret,
            "otpauth_uri": totp.provisioning_uri(secret, user["email"])}


class TotpActivate(BaseModel):
    code: str
    current_password: str = ""


@router.post("/api/totp/activate")
async def totp_activate(body: TotpActivate, request: Request,
                        user=Depends(security.require_user)):
    """Confirmă înrolarea: un cod valid activează 2FA și emite codurile de
    recuperare (afișate O SINGURĂ DATĂ)."""
    if not await _verify_reauth_password(user, body.current_password):   # M1: re-auth şi la activare
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    if user["totp_enabled"]:
        raise ApiError(409, "totp.alreadyOn", "2FA is already enabled")
    if not user["totp_secret_encrypted"]:
        raise HTTPException(400, "run /api/totp/setup first")
    secret = security.decrypt_secret(user["totp_secret_encrypted"])
    if not totp.verify(secret, body.code.strip()):
        raise HTTPException(400, "wrong code — check your phone clock")
    codes = _gen_recovery_codes()
    await db.execute("UPDATE users SET totp_enabled=1 WHERE id=?", user["id"])
    await db.execute("DELETE FROM recovery_codes WHERE user_id=?", user["id"])
    for c in codes:
        await db.execute(
            "INSERT INTO recovery_codes(user_id, code_hash, created) VALUES(?,?,?)",
            user["id"], security.sha256_hex(c), time.time())
    email_alerts.notify_security_change("2FA (TOTP) enabled", security.client_ip(request), user["email"])
    return {"ok": True, "recovery_codes": codes}


class TotpDisable(BaseModel):
    current_password: str


@router.post("/api/totp/disable")
async def totp_disable(body: TotpDisable, request: Request,
                       user=Depends(security.require_user)):
    """Dezactivează 2FA. Cere parola curentă (re-auth), ca un cookie furat să nu
    poată slăbi singur contul."""
    if not await _verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    await db.execute(
        "UPDATE users SET totp_enabled=0, totp_secret_encrypted=NULL WHERE id=?", user["id"])
    await db.execute("DELETE FROM recovery_codes WHERE user_id=?", user["id"])
    email_alerts.notify_security_change("2FA (TOTP) disabled", security.client_ip(request), user["email"])
    return {"ok": True}


@router.post("/api/totp/recovery-codes")
async def totp_regenerate(body: TotpDisable, user=Depends(security.require_user)):
    """Regenerate the recovery codes (invalidates the old set). Requires the password."""
    if not user["totp_enabled"]:
        raise ApiError(400, "totp.notOn", "2FA is not enabled")
    if not await _verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    codes = _gen_recovery_codes()
    await db.execute("DELETE FROM recovery_codes WHERE user_id=?", user["id"])
    for c in codes:
        await db.execute(
            "INSERT INTO recovery_codes(user_id, code_hash, created) VALUES(?,?,?)",
            user["id"], security.sha256_hex(c), time.time())
    return {"ok": True, "recovery_codes": codes}


# ---------------------------------------------------------------------------
# Setări SMTP (alerte pe email), editabile din UI. Parola stocată criptat.
# ---------------------------------------------------------------------------

class SmtpIn(BaseModel):
    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""          # write-only; gol la salvare = păstrează parola
    from_addr: str = ""
    to_addr: str = ""
    starttls: bool = True
    webhook: str = ""           # alerte şi în chat (Slack/Discord/Teams); independent de SMTP
    current_password: str = ""  # cerut DOAR când se schimbă webhook-ul (destinaţie de exfiltrare)


async def _set_setting(key: str, value) -> None:
    await db.execute(
        "INSERT INTO app_settings(key, value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)


async def _get_setting(key: str, default=None):
    row = await db.fetchone("SELECT value FROM app_settings WHERE key=?", key)
    return row["value"] if row else default


# --- Watermark (overlay de identitate pentru trasabilitatea scurgerilor) -----
# Overlay client-side (tiled canvas) peste workspace-ul autentificat și peste
# link-urile read-only partajate. NU se poate „arde" în transcript (.cast e text
# de terminal), deci rămâne strat de prezentare. Config-ul e un singur JSON în KV.
WATERMARK_DEFAULT = {"enabled": False, "content": "${email} · ${time}",
                     "opacity": 0.08, "angle": -30, "fontSize": 13}


class WatermarkIn(BaseModel):
    enabled: bool = False
    content: str = "${email} · ${time}"
    opacity: float = 0.08
    angle: int = -30
    fontSize: int = 13


async def _load_watermark() -> dict:
    raw = await _get_setting("watermark")
    if not raw:
        return dict(WATERMARK_DEFAULT)
    try:
        cfg = json.loads(raw)
    except (ValueError, TypeError):
        return dict(WATERMARK_DEFAULT)
    # doar cheile cunoscute, peste default (schema-safe la upgrade/downgrade)
    return {**WATERMARK_DEFAULT, **{k: cfg[k] for k in WATERMARK_DEFAULT if k in cfg}}


# --- Guardrail de comenzi (client-side, single-account) ---------------------
# Verificare la Enter în browser (via OSC 133): comenzi periculoase → block/confirm.
# NU e enforcement server-side (ești singurul cont); e o plasă de siguranță contra
# greșelilor (rm -rf /, mkfs, DROP DATABASE…). Reguli regex, editabile din Setări.
COMMAND_GUARD_DEFAULT = {
    "enabled": True,
    "rules": [
        {"pattern": r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)\s+/", "action": "confirm"},
        {"pattern": r"\bmkfs\b", "action": "confirm"},
        {"pattern": r"\bdd\b.*\bof=/dev/", "action": "confirm"},
        {"pattern": r":\s*\(\s*\)\s*\{.*:\s*\|\s*:", "action": "confirm"},   # fork bomb
        {"pattern": r"\bDROP\s+(DATABASE|TABLE)\b", "action": "confirm"},
        {"pattern": r">\s*/dev/sd", "action": "confirm"},
    ],
}


class CommandRuleIn(BaseModel):
    pattern: str
    action: str = "confirm"   # 'confirm' | 'block'


class CommandGuardIn(BaseModel):
    enabled: bool = True
    rules: list[CommandRuleIn] = []


async def _load_command_guard() -> dict:
    raw = await _get_setting("command_guard")
    if not raw:
        return {k: (list(v) if isinstance(v, list) else v) for k, v in COMMAND_GUARD_DEFAULT.items()}
    try:
        cfg = json.loads(raw)
    except (ValueError, TypeError):
        return dict(COMMAND_GUARD_DEFAULT)
    rules = []
    for r in cfg.get("rules", []) if isinstance(cfg.get("rules"), list) else []:
        if isinstance(r, dict) and r.get("pattern"):
            rules.append({"pattern": str(r["pattern"])[:300],
                          "action": "block" if r.get("action") == "block" else "confirm"})
    return {"enabled": bool(cfg.get("enabled", True)), "rules": rules[:100]}


async def _match_guard_rule(cmd: str) -> dict | None:
    """Prima regulă activă care se potriveşte pe comandă, sau None. Regex invalid = ignorat
    (aceeaşi toleranţă ca în client: serverul validează la salvare, dar nu ne oprim aici)."""
    guard = await _load_command_guard()
    if not guard.get("enabled"):
        return None
    # F-09: regulile sunt scrise de admin, iar `re.search` e sincron. O expresie cu
    # backtracking catastrofal (validată azi doar că se compilează) plus o comandă potrivită
    # bloca ÎNTREG event-loop-ul — inclusiv de la un token de automatizare cu scope `run`.
    # Fir separat + buget de 0.25s per regulă: o regulă patologică se pierde, restul merg.
    for r in guard.get("rules", []):
        try:
            if await asyncio.wait_for(
                    asyncio.to_thread(re.search, r["pattern"], cmd, re.IGNORECASE), 0.25):
                return r
        except (re.error, asyncio.TimeoutError):
            continue
    return None


@router.get("/api/settings/command-guard")
async def get_command_guard(user=Depends(security.require_user)):
    return await _load_command_guard()


@router.post("/api/settings/command-guard")
async def save_command_guard(body: CommandGuardIn, user=Depends(security.require_user)):
    import re as _re
    rules = []
    for r in body.rules[:100]:
        pat = (r.pattern or "").strip()[:300]
        if not pat:
            continue
        try:
            _re.compile(pat)   # respinge regex invalid ca să nu strice clientul
        except _re.error:
            raise HTTPException(400, f"invalid regex: {pat}")
        rules.append({"pattern": pat, "action": "block" if r.action == "block" else "confirm"})
    cfg = {"enabled": bool(body.enabled), "rules": rules}
    await _set_setting("command_guard", json.dumps(cfg))
    return cfg


@router.get("/api/settings/watermark")
async def get_watermark(user=Depends(security.require_user)):
    return await _load_watermark()


@router.post("/api/settings/watermark")
async def save_watermark(body: WatermarkIn, user=Depends(security.require_user)):
    content = (body.content or "").strip()[:200]
    cfg = {
        "enabled": bool(body.enabled),
        "content": content or WATERMARK_DEFAULT["content"],
        "opacity": min(0.5, max(0.02, float(body.opacity))),
        "angle": min(90, max(-90, int(body.angle))),
        "fontSize": min(40, max(8, int(body.fontSize))),
    }
    await _set_setting("watermark", json.dumps(cfg))
    return cfg


@router.get("/api/settings/smtp")
async def get_smtp(user=Depends(security.require_user)):
    """The current SMTP config, WITHOUT the password (only whether one is set)."""
    cfg = await email_alerts.load_config()
    return {"host": cfg["host"], "port": cfg["port"], "user": cfg["user"],
            "from_addr": cfg["from"], "to_addr": cfg["to"], "webhook": cfg["webhook"],
            "starttls": cfg["starttls"], "has_password": bool(cfg["password"]),
            "configured": bool(cfg["host"] and cfg["to"] and cfg["from"])}


@router.post("/api/settings/smtp")
async def save_smtp(body: SmtpIn, request: Request, user=Depends(security.require_user)):
    # Webhook-ul e un canal prin care gateway-ul TRIMITE date în afară, la o adresă aleasă de
    # cine configurează. Restul canalelor de exfiltrare (backup, tokenuri, share) cer deja
    # re-autentificare; ăsta nu cerea, deci un cookie furat putea îndrepta alertele spre orice
    # gazdă. Şi era acceptat orice şir: `file://…`, `gopher://…`, sau adresa de metadate a
    # cloudului. Nu blocăm reţelele private — un Mattermost în LAN e o ţintă legitimă pentru un
    # produs self-hosted — dar blocăm schemele care nu sunt HTTP şi adresa de metadate.
    wh = body.webhook.strip()
    if wh:
        from urllib.parse import urlparse
        u = urlparse(wh)
        if u.scheme not in ("http", "https"):
            raise ApiError(400, "settings.webhookScheme",
                           "the webhook must be an http:// or https:// URL")
        if (u.hostname or "").strip("[]") in ("169.254.169.254", "metadata.google.internal",
                                              "fd00:ec2::254"):
            raise ApiError(400, "settings.webhookBlocked",
                           "that address is the cloud metadata service, not a chat webhook")
    if wh != (await _get_setting("alert_webhook") or ""):
        await _require_reauth_for_secret(user, body.current_password,
                                        "changing the alert webhook")
    # Aceeaşi poartă ca la webhook, altfel asimetria e greu de apărat: acolo blocăm adresa
    # de metadate, aici acceptam orice gazdă:port şi `/api/settings/smtp/test` o contacta la
    # comandă — un scaner de porturi din interiorul reţelei. Reţelele private rămân permise
    # (un Postfix în LAN e legitim la un produs self-hosted); blocăm doar metadatele cloud.
    sh = body.host.strip()
    if sh.strip("[]").lower() in ("169.254.169.254", "metadata.google.internal", "fd00:ec2::254"):
        raise ApiError(400, "settings.smtpBlocked",
                       "that address is the cloud metadata service, not an SMTP server")
    await _set_setting("smtp_host", sh)
    await _set_setting("smtp_port", str(body.port))
    await _set_setting("smtp_user", body.user.strip())
    await _set_setting("smtp_from", body.from_addr.strip())
    await _set_setting("smtp_to", body.to_addr.strip())
    await _set_setting("smtp_starttls", "1" if body.starttls else "0")
    await _set_setting("alert_webhook", body.webhook.strip())
    # parola: doar dacă a fost furnizată (gol = păstreaz-o pe cea existentă)
    if body.password:
        await _set_setting("smtp_password_enc", security.encrypt_secret(body.password))
    return {"ok": True}


@router.post("/api/settings/smtp/test")
async def test_smtp(user=Depends(security.require_user)):
    """Send a test email to the destination address and report the result."""
    try:
        await email_alerts.send_test()
    except Exception as e:
        raise HTTPException(400, f"sending failed: {e}")
    return {"ok": True}


class ThresholdsIn(BaseModel):
    cpu: int = 90
    mem: int = 90
    disk: int = 90


class UpdateCheckIn(BaseModel):
    enabled: bool


@router.get("/api/settings/alerts")
async def get_alert_thresholds(user=Depends(security.require_user)):
    """Praguri de alertă pe resurse (0 = metrica dezactivată)."""
    return await email_alerts.load_thresholds()


@router.post("/api/settings/alerts")
async def save_alert_thresholds(body: ThresholdsIn, user=Depends(security.require_user)):
    for key, value in (("cpu", body.cpu), ("mem", body.mem), ("disk", body.disk)):
        if not 0 <= value <= 100:
            raise HTTPException(400, "thresholds must be between 0 and 100")
        await _set_setting(f"alert_{key}", str(value))
    email_alerts.invalidate_thresholds()   # cache-ul de la check_metrics
    return {"ok": True}


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

class HostIn(BaseModel):
    name: str
    note: str = ""
    folder: str = ""
    # conectare directă (agent = comportamentul clasic, fără câmpurile de mai jos)
    connection_type: str = "agent"       # agent | ssh | telnet
    hostname: str = ""
    ssh_username: str = ""
    ssh_port: int = 22
    auth_method: str = "password"        # password | key
    credential: str = ""                 # write-only: parola sau cheia privată
    passphrase: str = ""                 # write-only: passphrase-ul cheii
    require_2fa: bool = False
    credential_policy: str = "stored"    # stored | ask | ephemeral


def _credential_blob(h: "HostIn"):
    """Fernet blob holding the credentials, or None (agent host / `ask` policy / empty)."""
    if h.connection_type == "agent" or h.credential_policy == "ask" or not h.credential:
        return None
    if h.auth_method == "key":
        payload = {"key": h.credential}
        if h.passphrase:
            payload["passphrase"] = h.passphrase
    else:
        payload = {"password": h.credential}
    return security.encrypt_secret(json.dumps(payload))


def _resolve_credential(row, body_credential="", body_passphrase=""):
    """Credențialele de folosit la conectare: din request (politică `ask`) sau
    decriptate din seif. Returnează dict {password} sau {key, passphrase?}."""
    if row["credential_policy"] == "ask":
        if not body_credential:
            raise HTTPException(400, "credentials required (policy: ask every time)")
        if row["auth_method"] == "key":
            return {"key": body_credential, "passphrase": body_passphrase or None}
        return {"password": body_credential}
    if not row["credential_encrypted"]:
        raise HTTPException(400, "no stored credentials for this host")
    return json.loads(security.decrypt_secret(row["credential_encrypted"]))


async def _connect_direct(row, request, body_credential="", body_passphrase=""):
    """Ensure a connected SSH source for the host (dial + pin the host key). Rate-limited."""
    if isinstance(core.sources.get(row["id"]), core.SshSource):
        return
    ip = security.client_ip(request)
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        raise HTTPException(429, f"too many attempts; retry in {retry}s",
                            headers={"Retry-After": str(retry)})
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    cred = _resolve_credential(row, body_credential, body_passphrase)
    try:
        await core.dial_ssh(row, cred)
    except core.HostKeyMismatch:
        raise HTTPException(409, "the host key fingerprint changed — possible MITM; connection refused")
    except asyncssh.PermissionDenied:
        security.record_login_failure(ip)
        raise HTTPException(401, "SSH authentication failed")
    except (asyncssh.Error, OSError, asyncio.TimeoutError) as e:
        raise HTTPException(502, f"cannot connect over SSH: {e}")
    security.record_login_success(ip)


async def _connect_telnet(row, request, body_credential=""):
    """Asigură o sursă Telnet conectată (dial + auto-login best-effort). Rate-limited."""
    if isinstance(core.sources.get(row["id"]), core.TelnetSource):
        return
    ip = security.client_ip(request)
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        raise HTTPException(429, f"too many attempts; retry in {retry}s",
                            headers={"Retry-After": str(retry)})
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    password = ""
    if row["credential_policy"] == "ask":
        password = body_credential or ""
    elif row["credential_encrypted"]:
        password = json.loads(security.decrypt_secret(row["credential_encrypted"])).get("password", "")
    creds = {"username": row["ssh_username"] or "", "password": password}
    try:
        await core.dial_telnet(row, creds)
    except (OSError, asyncio.TimeoutError, ConnectionRefusedError) as e:
        raise HTTPException(502, f"cannot connect over Telnet: {e}")
    security.record_login_success(ip)


def _host_json(row) -> dict:
    conn = core.sources.get(row["id"])
    ctype = row["connection_type"] or "agent"
    is_agent = ctype == "agent"
    expected = core.agent_expected()["version"]
    return {
        "id": row["id"], "name": row["name"], "note": row["note"],
        "online": conn is not None, "hostname": row["hostname"],
        "agent_user": row["agent_user"], "agent_version": row["agent_version"],
        "backend": row["backend"], "last_heartbeat": row["last_heartbeat"],
        "folder": (row["folder"] or "") if "folder" in row.keys() else "",
        "conflict": core.host_conflict(row["id"]),
        # Agentul a fost scos de pe host. Hostul rămâne până când cineva confirmă în UI —
        # poate nu vrei să-l ştergi, ci doar să-l reinstalezi, caz în care marcajul dispare
        # singur la reconectare. Expus DOAR când e credibil (heartbeat-urile s-au oprit
        # imediat după marcaj): un marcaj plantat de cineva cu shell pe host nu ajunge
        # badge în UI, deci nu poate invita operatorul să şteargă un host viu.
        "uninstalled_at": (row["uninstalled_at"]
                           if "uninstalled_at" in row.keys()
                           and core.uninstall_marker_credible(row["uninstalled_at"],
                                                              row["last_heartbeat"])
                           else None),
        "metrics": conn.metrics if conn else None,
        "agent_latest": expected,
        # de ce NU se poate actualiza (dacă e cazul) — altfel UI-ul arată „update disponibil"
        # la infinit, fără motiv şi fără remediu
        "update_blocked": (row["update_blocked"] if "update_blocked" in row.keys() else None),
        "update_pending": is_agent and (bool(core.pending_updates.get(row["id"]))
            or (conn is not None and expected is not None
                and (conn.agent_version or 0) < expected)),
        # conectare directă (niciun secret nu iese de aici)
        "connection_type": ctype,
        "ssh_username": row["ssh_username"],
        "ssh_port": row["ssh_port"],
        "auth_method": row["auth_method"],
        "require_2fa": bool(row["require_2fa"]),
        "credential_policy": row["credential_policy"],
        "has_credentials": bool(row["credential_encrypted"]),
    }


AGENT_USER = "webterm"          # userul dedicat propus în varianta cu privilegii minime


async def _require_session_host_stepup(sid: str, user) -> None:
    """Step-up pe hostul unei SESIUNI, pentru căile care citesc conţinutul ei.

    Enforcement-ul de `require_2fa` era complet pe acţiuni (run, fs, kill, share) şi pe fluxul
    live — `browser_ws` refuză chiar să trimită scrollback-ul unei sesiuni idle-locked. Dar
    transcriptul, previzualizarea şi căutarea livrau acelaşi conţinut printr-un simplu GET, cu
    un cookie valid: adică exact ce vede omul pe terminalul unui host cu 2FA, inclusiv secrete
    afişate în output. Semnalat de auditul intern din 2026-08-06."""
    row = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
    if row and row["host_id"]:
        await _require_host_stepup(row["host_id"], user)


async def _require_reauth_for_secret(user, password: str, what: str) -> None:
    """Re-autentificare cu parola CONTULUI pentru operaţiile care scot secrete din instanţă
    sau o pot prelua.

    Parola de criptare a arhivei nu e o barieră: o alege cel care cere descărcarea. Deci, fără
    asta, un cookie furat (XSS, extensie de browser, malware pe staţie) însemna: descarci
    arhiva → ai `data/secret` → ai toate credenţialele SSH şi tokenurile de agent. Sau invers:
    ÎNCARCI o arhivă a ta prin restore şi preiei instanţa cu contul tău.

    Semnalat de auditul extern (2026-08-06). Restul API-ului cerea deja re-auth pentru lucruri
    mai mici (creare de cont, token de automatizare) — incoerenţa era chiar pe operaţiile grele."""
    if not await _verify_reauth_password(user, password):
        raise HTTPException(401, "wrong account password — required for %s" % what)


def _install_command(enroll_token: str) -> str:
    # self-signed gateway: the one-liner itself must skip cert verification
    flags = "-fsSk" if config.AGENT_INSECURE else "-fsS"
    wflags = "--no-check-certificate " if config.AGENT_INSECURE else ""
    url = "%s/install/%s.sh" % (config.PUBLIC_URL, enroll_token)
    # Fallback pe wget: scriptul PE CARE îl aducem are deja fallback curl→wget, dar comanda
    # care îl aduce nu avea, deci pe o imagine minimală fără curl (debian-slim, alpine)
    # înrolarea murea cu `sh: 1: curl: not found` înainte să apuce să ruleze ceva. Ironia e
    # că exact acel caz e explicat într-un comentariu din scriptul nelivrat.
    return ("(command -v curl >/dev/null && curl %s %s || wget %s-qO- %s) | sh"
            % (flags, url, wflags, url))


def _install_command_dedicated(enroll_token: str) -> str:
    """Aceeaşi instalare, dar sub un user dedicat, fără drepturi.

    Rulat ca root, agentul înseamnă root shell pe host: cine compromite gateway-ul sau contul
    tău are hostul. Sub `webterm`, are doar ce are `webterm`.

    `loginctl enable-linger` NU e opţional aici: fără el, `systemd --user` opreşte serviciul
    când userul n-are sesiune de login şi nu-l porneşte la boot — agentul ar părea că moare
    singur. `useradd` e tolerat dacă userul există deja (|| true), ca să poţi relua comanda."""
    inner = _install_command(enroll_token)
    return ("sudo useradd -m -s /bin/bash %s 2>/dev/null || true; "
            "sudo loginctl enable-linger %s; "
            "sudo -iu %s sh -c '%s'" % (AGENT_USER, AGENT_USER, AGENT_USER, inner))


@router.get("/api/status")
async def status(user=Depends(security.require_scope("read"))):
    """Rezumat operațional: hosturi online, sesiuni, disc (transcripturi +
    arhivă), uptime și versiuni. Alimentează panoul de status."""
    hosts = await db.fetchall("SELECT id FROM hosts")
    online = sum(1 for h in hosts if h["id"] in core.sources)
    rows = await db.fetchall("SELECT state, COUNT(*) AS c FROM sessions GROUP BY state")
    by_state = {r["state"]: r["c"] for r in rows}
    return {
        "uptime_seconds": time.time() - _START_TIME,
        "gateway_version": config.GATEWAY_VERSION,
        "image": config.IMAGE_REF or None,
        "agent_latest": core.agent_expected()["version"],
        "hosts": {"total": len(hosts), "online": online, "offline": len(hosts) - online},
        "sessions": {
            "live": by_state.get("live", 0) + by_state.get("creating", 0),
            "closed": by_state.get("closed", 0),
            "lost": by_state.get("lost", 0),
        },
        "storage": await asyncio.to_thread(core.storage_stats),
        "gateway": await health.snapshot(core, db),
    }


def _with_command(data: dict) -> dict:
    """Only issue an update command when there is really something to update — otherwise it is noise."""
    out = {**data, "configurable": config.UPDATE_CHECK}
    if data.get("update_available") and data.get("latest"):
        out["update_command"] = config.UPDATE_COMMAND.replace("{version}", data["latest"])
    return out


async def _update_check_enabled() -> bool:
    """Comutatorul din Setări; implicit pornit, dar `WEBTERM_UPDATE_CHECK=0` bate setarea."""
    return (await _get_setting("update_check", "1")) == "1"


@router.get("/api/version")
async def version_info(user=Depends(security.require_user)):
    """Versiunea curentă + dacă există una mai nouă pe GitHub.
    Rezultatul e cache-uit (o zi la succes, o oră la eșec), deci sigur de apelat des."""
    return _with_command(await updatecheck.check(enabled=await _update_check_enabled()))


@router.post("/api/version/check")
async def version_check_toggle(body: UpdateCheckIn, user=Depends(security.require_user)):
    """Pornește/oprește verificarea. Oprită, gateway-ul nu mai face NICIO conexiune
    din proprie inițiativă spre exterior — de-aia merită să fie la un click."""
    await _set_setting("update_check", "1" if body.enabled else "0")
    updatecheck.reset_cache()          # răspuns imediat, nu la următoarea fereastră
    return await updatecheck.check(force=True, enabled=body.enabled)


@router.post("/api/version/refresh")
async def version_refresh(user=Depends(security.require_user)):
    """„Verifică acum" — automat întrebăm o dată pe zi, dar când chiar aștepți o
    versiune n-are rost să aștepți fereastra."""
    enabled = await _update_check_enabled()
    if not enabled:
        raise HTTPException(400, "the version check is turned off")
    return _with_command(await updatecheck.check(force=True, enabled=True))


@router.get("/api/hosts")
async def list_hosts(user=Depends(security.require_scope("read"))):
    rows = await db.fetchall("SELECT * FROM hosts ORDER BY name")
    return [_host_json(r) for r in rows]


@router.post("/api/hosts")
async def create_host(host: HostIn, user=Depends(security.require_user)):
    ctype = host.connection_type if host.connection_type in ("agent", "ssh", "telnet") else "agent"
    if ctype in ("ssh", "telnet") and not host.hostname.strip():
        raise ApiError(400, "host.hostnameRequired", "hostname required for a direct connection")
    if ctype == "ssh" and not host.ssh_username.strip():
        raise ApiError(400, "ssh.userRequired", "an SSH username is required")
    token = security.new_token()
    enroll = security.new_token()[:32]
    host_id = await db.execute(
        # `folder` lipsea din INSERT deşi `HostIn` îl acceptă: hostul creat direct într-un grup
        # ieşea mereu în afara lui, fără nicio eroare. Aceeaşi clasă cu PATCH-ul care accepta
        # câmpuri de conexiune şi le ignora.
        "INSERT INTO hosts(name, note, folder, token_hash, token_encrypted, enroll_token,"
        " enroll_expires, created, connection_type, hostname, ssh_username, ssh_port,"
        " auth_method, credential_encrypted, require_2fa, credential_policy)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        host.name.strip(), host.note, host.folder.strip(), security.sha256_hex(token),
        security.encrypt_secret(token), enroll,
        time.time() + 24 * 3600, time.time(),
        ctype, host.hostname.strip() or None, host.ssh_username.strip() or None,
        host.ssh_port, host.auth_method, _credential_blob(host),
        int(host.require_2fa), host.credential_policy)
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    return dict(_host_json(row), install_command=_install_command(enroll),
                install_command_dedicated=_install_command_dedicated(enroll),
                enroll_expires=row["enroll_expires"])


@router.post("/api/hosts/{host_id}/enroll")
async def renew_enroll(host_id: int, user=Depends(security.require_user)):
    """New install one-liner for an existing host (reinstall / new enroll)."""
    await _require_host_stepup(host_id, user)   # H1: enroll nou = clasă de provisioning
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise HTTPException(404)
    enroll = security.new_token()[:32]
    await db.execute(
        "UPDATE hosts SET enroll_token=?, enroll_expires=?, instance_id=NULL WHERE id=?",
        enroll, time.time() + 24 * 3600, host_id)
    return {"install_command": _install_command(enroll),
            "install_command_dedicated": _install_command_dedicated(enroll),
            "enroll_expires": time.time() + 24 * 3600}


@router.get("/api/hosts/{host_id}/fs")
async def fs_list(host_id: int, path: str = "~", user=Depends(security.require_user)):
    await _require_host_stepup(host_id, user)   # H1
    try:
        return await core.fs_list(host_id, path)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise HTTPException(400, str(e))


@router.get("/api/hosts/{host_id}/fs/cwd")
async def fs_cwd(host_id: int, sid: str, user=Depends(security.require_user)):
    """The session shell's cwd (so the panel opens where you actually are)."""
    await _require_host_stepup(host_id, user)   # H1
    try:
        return {"cwd": await core.session_cwd(host_id, sid)}
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise HTTPException(400, str(e))


@router.get("/api/hosts/{host_id}/fs/download")
async def fs_download(host_id: int, path: str, user=Depends(security.require_user)):
    await _require_host_stepup(host_id, user)   # H1
    from fastapi.responses import StreamingResponse
    name = os.path.basename(path.rstrip("/")) or "download"
    # un nume de fișier ostil (ghilimele/newline) ar sparge headerul
    # Content-Disposition → curățăm caracterele periculoase
    name = name.replace('"', "").replace("\r", "").replace("\n", "").replace("\\", "")
    try:
        # probe first chunk so errors surface as HTTP status, not mid-stream
        agen = core.fs_read_all(host_id, path)
        first = await agen.__anext__()
    except StopAsyncIteration:
        first = b""
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except TimeoutError:
        raise HTTPException(504, "the host is not responding")
    except core.FileError as e:
        raise HTTPException(400, str(e))

    async def body():
        yield first
        async for chunk in agen:
            yield chunk

    return StreamingResponse(
        body(), media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/api/hosts/{host_id}/fs/upload")
async def fs_upload(host_id: int, request: Request, path: str,
                    if_mtime: int | None = None,
                    user=Depends(security.require_user)):
    """Body is the raw file; `path` is the destination on the host.
    `if_mtime` (opțional): salvare cu verificare de conflict — refuză (409) dacă
    fișierul s-a schimbat de când l-ai deschis în editor."""
    audit.detail(request, path)
    await _require_host_stepup(host_id, user)   # H1
    async def source():
        async for chunk in request.stream():
            yield chunk
    try:
        written = await core.fs_write_stream(host_id, path, source(), if_mtime=if_mtime)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except core.FileConflict as e:
        raise HTTPException(409, str(e))
    except (core.FileError, TimeoutError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "written": written, "path": path}


# praguri editor: sub LIMIT încarci tot (editabil); peste, doar primii HEAD
# bytes (view-only), ca să nu tragi un fișier uriaș în browser
_EDIT_FULL_LIMIT = 1024 * 1024
_PREVIEW_HEAD = 256 * 1024


@router.get("/api/hosts/{host_id}/fs/preview")
async def fs_preview(host_id: int, path: str, user=Depends(security.require_user)):
    """Conținut pentru editor: fișier întreg dacă e mic, altfel doar începutul
    (view-only). Detectează binar și întoarce mtime pentru verificarea de conflict."""
    await _require_host_stepup(host_id, user)   # H1
    try:
        data, size, mtime = await core.fs_read_head(host_id, path, _PREVIEW_HEAD)
        if _PREVIEW_HEAD < size <= _EDIT_FULL_LIMIT:
            data, size, mtime = await core.fs_read_head(host_id, path, _EDIT_FULL_LIMIT)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise HTTPException(400, str(e))
    editable = size <= _EDIT_FULL_LIMIT
    shown = data if editable else data[:_PREVIEW_HEAD]
    binary = b"\x00" in shown
    if not editable:
        # taie ultima linie parțială, ca preview-ul să nu se termine în mijloc
        nl = shown.rfind(b"\n")
        if nl > 0:
            shown = shown[:nl]
    text = "" if binary else shown.decode("utf-8", "replace")
    return {"path": path, "size": size, "mtime": mtime,
            "editable": editable, "truncated": not editable, "binary": binary,
            "text": text}


# ── Port forwarding ──────────────────────────────────────────────────────────
# antete hop-by-hop: nu se propagă printr-un proxy (RFC 7230 §6.1)
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection"}
FWD_MAX_BODY = 100 * 1024 * 1024      # plafon corp cerere prin proxy-ul de forward (anti-OOM)
FWD_RESP_TIMEOUT = 120                # așteptare răspuns de la țintă: generos pt. long-poll
# Plafon AGREGAT peste toate upload-urile forward simultane: plafonul per-request (100 MB) nu
# opreşte N cereri concurente să reţină N×100 MB în RAM → OOM. Contor global + refuz 503 peste prag.
FWD_INFLIGHT_MAX = 256 * 1024 * 1024  # 256 MB reţinuţi simultan în toate corpurile forward
_fwd_inflight = 0
WS_REVALIDATE_SECS = 60               # re-verifică sesiunea pe WS-uri de lungă durată (logout/idle)
                                      # (ex. MikroTik /jsproxy ține conexiunea până la un
                                      # eveniment). Dead target → eșuează după atâta.
# cookie de auth pe subdomeniul de forward: __Host- → host-only (nu se scurge la
# alte subdomenii sau la domeniul principal), HttpOnly, Secure, Path=/
FWD_COOKIE = "__Host-wt_fwd" if config.PUBLIC_URL.startswith("https://") else "wt_fwd"


def _strip_fwd_cookie(cookie_header: str) -> str:
    parts = [c.strip() for c in cookie_header.split(";")]
    kept = [c for c in parts if c and not c.startswith(FWD_COOKIE + "=")]
    return "; ".join(kept)


async def _ensure_forward_source(host_id: int):
    """Sursa capabilă de forward pentru host: conexiunea agent/SSH deja vie sau,
    pentru hosturi SSH cu credențial STOCAT și fără 2FA, una ridicată la nevoie
    (idle-teardown după inactivitate). None dacă nu putem — host offline, ori SSH
    cu 2FA / credențiale ne-stocate (acolo forward-ul cere o sesiune deschisă)."""
    conn = core.source_for(host_id)
    if isinstance(conn, (core.AgentConnection, core.SshSource)):
        return conn
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row or row["connection_type"] != "ssh":
        return None
    if row["require_2fa"] or row["credential_policy"] != "stored" or not row["credential_encrypted"]:
        return None
    try:
        cred = json.loads(security.decrypt_secret(row["credential_encrypted"]))
        return await core.dial_ssh(row, cred)
    except Exception:
        return None


async def _open_target(conn, thost: str, tport: int, scheme: str):
    """Deschide tunelul TCP către țintă și, pentru scheme=https, ridică TLS pe
    ultimul hop (gateway → țintă). Întoarce un obiect cu aceeași interfață
    write/read/close ca ForwardStream."""
    fs = await conn.open_forward(thost, tport)
    if scheme == "https":
        try:
            fs = await core.wrap_tls_forward(fs, thost)
        except core.ForwardError:
            await fs.close()
            raise
        except Exception:
            await fs.close()
            raise core.ForwardError("TLS failed")
    return fs


async def proxy_forward_http(request: Request, host_id: int, thost: str,
                             tport: int, target_path: str, scheme: str = "http"):
    """Reverse-proxy HTTP printr-un tunel de agent. Cererea browserului →
    HTTP/1.0 `Connection: close` către țintă (fără chunked/keep-alive de parsat) →
    răspunsul citit până la EOF, headerele parsate, corpul transmis în streaming."""
    from fastapi.responses import StreamingResponse
    # anti request-smuggling: path-ul ajunge într-o cerere HTTP raw
    if "\r" in target_path or "\n" in target_path:
        raise HTTPException(400, "invalid path")
    conn = await _ensure_forward_source(host_id)
    if conn is None:
        raise HTTPException(409, "the host is offline (or an SSH host that needs an open session)")
    try:
        fs = await _open_target(conn, thost, tport, scheme)
    except core.ForwardError:
        raise HTTPException(502, "the forwarded service is not responding")
    except (core.AgentGone, TimeoutError):
        raise ApiError(409, "host.offline", "the host is offline")
    try:
        # citim corpul cu plafon (anti-OOM): un upload uriaș printr-un forward nu
        # trebuie să umple RAM-ul gateway-ului. Acoperă și cererile chunked (fără
        # Content-Length), nu doar antetul declarat.
        global _fwd_inflight
        body = b""
        try:
            async for chunk in request.stream():
                body += chunk
                _fwd_inflight += len(chunk)
                if len(body) > FWD_MAX_BODY:
                    await fs.close()
                    raise ApiError(413, "forward.bodyTooLarge", "body too large for a forward")
                if _fwd_inflight > FWD_INFLIGHT_MAX:
                    await fs.close()
                    raise HTTPException(503, "too many large uploads through forwards at once; retry")
            lines = ["%s %s HTTP/1.0" % (request.method, target_path)]
            for k, v in request.headers.items():
                kl = k.lower()
                if kl in _HOP_BY_HOP or kl in ("host", "content-length"):
                    continue
                if "\r" in v or "\n" in v:         # anti-injecție de headere
                    continue
                if kl == "cookie":
                    # trimitem cookie-urile PROPRII ale app-ului, dar scoatem cookie-ul
                    # nostru de auth (nu are ce căuta la țintă)
                    v = _strip_fwd_cookie(v)
                    if not v:
                        continue
                lines.append("%s: %s" % (k, v))
            lines.append("Host: %s:%d" % (thost, tport))
            if body:
                lines.append("Content-Length: %d" % len(body))
            lines.append("Connection: close")
            await fs.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin1") + body)
        finally:
            _fwd_inflight -= len(body)   # eliberează bugetul agregat (corpul e trimis / cererea a eşuat)

        # citește antetul răspunsului (până la linia goală)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(fs.read(), timeout=FWD_RESP_TIMEOUT)
            if chunk is None:
                break
            buf += chunk
            if len(buf) > 256 * 1024:          # antet absurd de mare → renunțăm
                await fs.close()
                raise HTTPException(502, "invalid response from the service")
        head, _, rest = buf.partition(b"\r\n\r\n")
        hlines = head.split(b"\r\n")
        parts = hlines[0].split(b" ", 2) if hlines and hlines[0] else []
        # Statusul ţintei se prelua VERBATIM: un echipament cu firmware prost care răspunde
        # `HTTP/1.0 99 Nonsense` făcea uvicorn să crape cu `KeyError: 99`, iar clientul primea
        # un răspuns gol şi un traceback în log. Plafonăm la intervalul valid.
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 502
        if not 100 <= status <= 599:
            status = 502
        resp_headers = {}
        set_cookies = []
        for line in hlines[1:]:
            k, sep, v = line.partition(b":")
            if not sep:
                continue
            name = k.decode("latin1").strip()
            nl = name.lower()
            if nl in _HOP_BY_HOP or nl == "content-length":
                continue                       # transmitem până la EOF, fără content-length
            val = v.decode("latin1").strip()
            # Antetele ţintei se copiau nevalidate: o ţintă care trimite `X-A: v\nSet-Cookie: …`
            # (LF gol, nu CRLF) producea o „valoare" cu `\n` în ea → `RuntimeError: Invalid HTTP
            # header value` din uvicorn şi răspuns gol. Că nu s-a ajuns la response-splitting e
            # meritul validării din uvicorn, nu al nostru — apărarea trebuie să fie aici.
            if any(c in val or c in name for c in ("\r", "\n", "\0")):
                continue
            if not name or not all(32 < ord(c) < 127 and c not in '()<>@,;:\\"/[]?={} \t'
                                   for c in name):
                continue                       # nume de antet care nu e token HTTP valid
            if nl == "set-cookie":
                # Scoatem `Domain=`: fiecare forward stă pe subdomeniul lui tocmai ca să fie
                # izolat, iar un serviciu ostil (sau doar prost configurat) în spatele unui
                # forward putea seta un cookie cu Domain=<domeniul de forward>, care ajungea
                # apoi la TOATE forward-urile surori. Autentificarea nu era afectată (tokenul
                # e legat de slug, cookie-ul nostru e `__Host-`), dar cookie-urile aplicaţiilor
                # forwardate se contaminau între ele. Fără atributul ăsta cookie-ul devine
                # host-only — exact ce vrem de la un proxy per-subdomeniu.
                set_cookies.append(_strip_cookie_domain(val))
            else:
                resp_headers[name] = val
    except HTTPException:
        raise
    except Exception:
        await fs.close()
        raise ApiError(502, "forward.proxyError", "forward proxy error")

    async def body_stream():
        try:
            if rest:
                yield rest
            while True:
                chunk = await fs.read()
                if chunk is None:
                    break
                yield chunk
        finally:
            await fs.close()

    response = StreamingResponse(body_stream(), status_code=status, headers=resp_headers)
    for sc in set_cookies:                     # Set-Cookie multiplu (app-ul forwardat)
        response.raw_headers.append((b"set-cookie", sc.encode("latin1")))
    return response


# ── Probă de accesibilitate (bulinele de stare din UI) ───────────────────────
# Pe FORWARD-ID: folosește ținta STOCATĂ (declarată de admin), nu un host:port din
# URL — fără suprafață SSRF de „probează orice".
@router.get("/api/forwards/{fid}/probe")
async def forward_probe(fid: int, stepup_grant: str = "", stepup_password: str = "",
                        user=Depends(security.require_user)):
    # `enabled=0` era ignorat aici: butonul „Oprit" din UI e singura pârghie de „taie accesul
    # acum", iar pe calea HTTP funcţiona (404). Pe telnet şi pe probă, sesiunea se deschidea şi
    # octeţii curgeau spre echipamentul din LAN, cu forward-ul dezactivat.
    row = await db.fetchone("SELECT * FROM port_forwards WHERE id=? AND enabled=1", fid)
    if not row:
        raise ApiError(404, "forward.missing", "no such forward")
    # Proba spune dacă un port e deschis în reţeaua host-ului — un oracol de recunoaştere,
    # aceeaşi clasă cu restul acţiunilor de host. Fără gard, un cookie furat putea scana
    # ţinte pe un host cu 2FA fără să creeze nimic.
    await _require_host_stepup(row["host_id"], user, stepup_grant, stepup_password)
    conn = await _ensure_forward_source(row["host_id"])
    if conn is None:
        raise HTTPException(409, "the host is offline (or an SSH host that needs an open session)")
    try:
        fs = await _open_target(conn, row["target_host"], row["target_port"], row["scheme"])
    except core.ForwardError as e:
        return {"reachable": False, "detail": str(e)}
    except (core.AgentGone, TimeoutError):
        raise ApiError(409, "host.offline", "the host is offline")
    try:
        await fs.write(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = await asyncio.wait_for(fs.read(), timeout=5)
            except asyncio.TimeoutError:
                break
            if chunk is None:                 # EOF: connect refuzat sau țintă a închis
                break
            buf += chunk
    finally:
        await fs.close()
    # accesibil = am primit octeți înapoi. Portul refuzat: connect() non-blocant
    # reușește „în progres", eșuează async → tunelul se închide fără date → 0 octeți.
    reachable = len(buf) > 0
    status = buf.split(b"\r\n", 1)[0].decode("latin1") if buf else ""
    return {"reachable": reachable, "status_line": status, "bytes": len(buf),
            "head": buf[:400].decode("latin1", "replace")}


# ── Port forwards: declarare & management (CRUD) ─────────────────────────────
# Domeniul de forward: implicit = gazda aplicației (din PUBLIC_URL), dar poate fi
# suprascris din Settings (util dacă vrei forward-urile pe alt domeniu decât app-ul).
# Sursa de adevăr pentru APP e app_settings['forward_domain']; infra (Traefik cert +
# rutare) se aliniază prin FORWARD_DOMAIN în .env — vezi verificarea de readiness.
_FWD_DEFAULT_DOMAIN = os.environ.get("WEBTERM_FORWARD_DOMAIN") or urlparse(config.PUBLIC_URL).hostname or "localhost"
_FWD_SCHEME = urlparse(config.PUBLIC_URL).scheme or "https"   # https în prod; http la test
_fwd_domain_cache = _FWD_DEFAULT_DOMAIN


def forward_domain() -> str:
    """Domeniul de forward curent (memoizat; reîncărcat la pornire și la salvare)."""
    return _fwd_domain_cache


async def load_forward_domain() -> None:
    global _fwd_domain_cache
    row = await db.fetchone("SELECT value FROM app_settings WHERE key='forward_domain'")
    _fwd_domain_cache = (row["value"].strip() if row and row["value"] and row["value"].strip()
                         else _FWD_DEFAULT_DOMAIN)


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _valid_domain(d: str) -> bool:
    return bool(_HOSTNAME_RE.match(d))


def _readiness_blocking(app_domain: str, domain: str) -> dict:
    """DNS wildcard + certificat Traefik pentru domeniu, verificate din exterior.
    Rulează într-un thread (socket/ssl sunt blocante)."""
    server_ip = ""
    try:
        server_ip = socket.gethostbyname(app_domain) if app_domain else ""
    except OSError:
        pass
    probe = "wtcheck." + domain
    dns_ip = ""
    try:
        dns_ip = socket.gethostbyname(probe)
    except OSError:
        dns_ip = ""
    cert_ok = False
    if dns_ip:
        try:
            ctx = ssl.create_default_context()   # verifică față de CA-urile sistemului
            with socket.create_connection((probe, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=probe):
                    cert_ok = True               # handshake valid = cert acoperă *.domeniu
        except Exception:
            cert_ok = False
    return {"server_ip": server_ip, "dns_ip": dns_ip,
            "dns_ok": bool(dns_ip), "cert_ok": cert_ok}


async def _forward_settings_json() -> dict:
    domain = forward_domain()
    app_domain = urlparse(config.PUBLIC_URL).hostname or ""
    st = await asyncio.to_thread(_readiness_blocking, app_domain, domain)
    return {"domain": domain, "app_domain": app_domain,
            "is_custom": domain != app_domain, **st}


class ForwardDomainIn(BaseModel):
    domain: str


@router.get("/api/settings/forward")
async def get_forward_settings(user=Depends(security.require_user)):
    return await _forward_settings_json()


@router.post("/api/settings/forward")
async def save_forward_settings(body: ForwardDomainIn,
                                user=Depends(security.require_user)):
    d = body.domain.strip().lower().rstrip(".")
    if not _valid_domain(d):
        raise HTTPException(400, "invalid domain (e.g. apps.example.com)")
    # Un domeniu de forward care e PĂRINTE al domeniului aplicaţiei o înghite: `route_forward`
    # decide „e subdomeniu de forward" prin `host.endswith("." + forward_domain())` şi nu
    # compară niciodată cu domeniul app-ului. Aplicaţia la `wt.exemplu.com` + forward pe
    # `exemplu.com` → de la cererea următoare TOT (UI, API, inclusiv endpointul ăsta) răspunde
    # 404, iar recuperarea cere editarea manuală a SQLite pe server. Salvarea răspundea 200.
    # ATENŢIE la cazul normal: implicit domeniul de forward E domeniul aplicaţiei, iar
    # slug-urile sunt subdomenii ale lui (`app.exemplu.com` + `x.app.exemplu.com`) —
    # `route_forward` lasă gazda exactă să treacă la app. Periculos e doar când aplicaţia
    # ajunge STRICT SUB domeniul de forward: app la `wt.exemplu.com`, forward pe `exemplu.com`
    # → gazda app-ului devine „slug-ul wt" şi tot UI-ul/API-ul răspunde 404.
    app_host = (urlparse(config.PUBLIC_URL).hostname or "").lower()
    if app_host and app_host != d and app_host.endswith("." + d):
        raise HTTPException(400,
                            "the app domain (%s) would become a forward subdomain — "
                            "pick a domain that does NOT contain it (e.g. apps.%s)" % (app_host, d))
    await _set_setting("forward_domain", d)
    await load_forward_domain()
    return await _forward_settings_json()


# ── Backup / restore (din Settings) ──────────────────────────────────────────
# Un backup conține cheia seifului (decriptează toate credențialele) → descărcările
# sunt MEREU criptate cu o parolă dată de user. Vezi backup.py.

class BackupIn(BaseModel):
    passphrase: str                 # parola de CRIPTARE a arhivei (o alegi acum)
    include_transcripts: bool = False
    current_password: str = ""      # parola CONTULUI — vezi _require_reauth_for_secret


class RestoreIn(BaseModel):
    passphrase: str
    current_password: str = ""


class BackupScheduleIn(BaseModel):
    schedule: str = "off"          # off | daily | weekly
    include_transcripts: bool = False


def _backup_filename() -> str:
    return "webterm-backup-%s.wtbk" % time.strftime("%Y%m%d-%H%M%S")


@router.get("/api/backup/status")
async def backup_status(user=Depends(security.require_user)):
    return {
        "schedule": await _get_setting("backup_schedule", "off"),
        "include_transcripts": (await _get_setting("backup_include_tx", "0")) == "1",
        "last_scheduled": float(await _get_setting("backup_last", "0") or 0),
        "backups": backup.list_backups(),
        "retention_days": backup.RETENTION_DAYS,
    }


@router.post("/api/backup/download")
async def backup_download(body: BackupIn, user=Depends(security.require_user)):
    await _require_reauth_for_secret(user, body.current_password, "downloading the backup")
    if len(body.passphrase) < 8:
        raise HTTPException(400, "the encryption passphrase must be at least 8 characters")
    try:
        blob = await asyncio.to_thread(backup.make_encrypted, body.passphrase, body.include_transcripts)
    except Exception as e:
        raise HTTPException(500, "backup failed: %s" % e)
    return Response(content=blob, media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % _backup_filename()})


@router.post("/api/backup/stored/{name}/download")
async def backup_download_stored(name: str, body: RestoreIn, user=Depends(security.require_user)):
    await _require_reauth_for_secret(user, body.current_password, "downloading the backup")
    if len(body.passphrase) < 8:
        raise HTTPException(400, "the encryption passphrase must be at least 8 characters")
    try:
        blob = await asyncio.to_thread(backup.encrypt_stored, name, body.passphrase)
    except FileNotFoundError:
        raise ApiError(404, "backup.missing", "no such backup")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return Response(content=blob, media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % _backup_filename()})


@router.post("/api/backup/restore")
async def backup_restore(request: Request, user=Depends(security.require_user)):
    # Fișierul .wtbk vine ca body brut (octet-stream), parola într-un header — evităm
    # dependența python-multipart; parola e a userului, peste HTTPS, într-un header pe
    # care reverse-proxy-ul nu-l loghează.
    passphrase = urllib.parse.unquote(request.headers.get("X-Restore-Pass", ""))
    if not passphrase:
        raise HTTPException(400, "the backup passphrase is missing")
    # restore = ÎNLOCUIREA bazei de date, deci şi a conturilor: cu un cookie furat, cineva
    # ar putea încărca o arhivă a lui şi ar prelua instanţa. Aceeaşi clasă cu descărcarea.
    await _require_reauth_for_secret(
        user, urllib.parse.unquote(request.headers.get("X-Reauth-Pass", "")), "restore")
    data = await request.body()
    if len(data) > 512 * 1024 * 1024:
        raise HTTPException(413, "file too large")
    if not data:
        raise HTTPException(400, "empty file")
    try:
        info = await asyncio.to_thread(backup.stage_restore, data, passphrase)
    except ValueError as e:
        raise HTTPException(400, str(e))       # parolă greșită / fișier corupt / DB invalid
    except Exception as e:
        raise HTTPException(500, "restore failed: %s" % e)
    # aplicarea reală se face la boot (apply_pending_restore) după restart. Repornim
    # procesul după ce răspunsul pleacă — containerul (restart: unless-stopped) revine.
    async def _restart_soon():
        await asyncio.sleep(1.0)
        log.warning("restart to apply the restore")
        os._exit(0)
    asyncio.create_task(_restart_soon())
    return {"ok": True, "restarting": True, **info}


@router.post("/api/backup/schedule")
async def backup_schedule(body: BackupScheduleIn, user=Depends(security.require_user)):
    if body.schedule not in ("off", "daily", "weekly"):
        raise HTTPException(400, "invalid schedule (off/daily/weekly)")
    await _set_setting("backup_schedule", body.schedule)
    await _set_setting("backup_include_tx", "1" if body.include_transcripts else "0")
    return await backup_status(user)


@router.delete("/api/backup/stored/{name}")
async def backup_delete_stored(name: str, user=Depends(security.require_user)):
    if "/" in name or "\\" in name or not name.endswith(".wtsnap"):
        raise ApiError(400, "generic.badName", "invalid name")
    p = config.DATA_DIR / "backups" / name
    try:
        p.unlink()
    except FileNotFoundError:
        raise HTTPException(404)
    return {"ok": True}


@router.post("/api/backup/seen")
async def backup_seen(user=Depends(security.require_user)):
    await _set_setting("backup_seen", await _get_setting("backup_last", "0") or "0")
    return {"ok": True}


# ── Backup off-host în cloud (Google Drive / Dropbox) ────────────────────────
# Vezi cloudbackup.py. Un backup care stă doar pe mașina salvată nu te apără de
# pierderea mașinii; aici e varianta la îndemână (rclone rămâne calea de ops).

class CloudConfigIn(BaseModel):
    provider: str
    client_id: str
    client_secret: str = ""        # gol la re-salvare = păstrează secretul existent
    passphrase: str = ""
    keep: int = cloudbackup.DEFAULT_KEEP
    include_transcripts: bool = False
    current_password: str = ""     # re-auth: configurarea creează un canal permanent de ieșire


@router.get("/api/backup/cloud")
async def cloud_status(user=Depends(security.require_user)):
    return await cloudbackup.status()


@router.post("/api/backup/cloud/config")
async def cloud_config(body: CloudConfigIn, user=Depends(security.require_user)):
    # Aceeași poartă ca la passkey/2FA: cine are cookie-ul, dar nu parola, nu poate
    # deschide o cale prin care backup-urile (cheia seifului) pleacă spre contul lui.
    if not await _verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongPassword", "wrong password")
    try:
        await cloudbackup.save_config(body.provider, body.client_id, body.client_secret,
                                      body.passphrase, body.keep, body.include_transcripts)
    except cloudbackup.CloudError as e:
        raise HTTPException(400, str(e))
    return await cloudbackup.status()


@router.get("/api/backup/cloud/authorize")
async def cloud_authorize(user=Depends(security.require_user)):
    try:
        return {"url": await cloudbackup.authorize_url(user["id"])}
    except cloudbackup.CloudError as e:
        raise HTTPException(400, str(e))


@router.get("/api/backup/cloud/callback")
async def cloud_callback(code: str = "", state: str = "", error: str = "",
                         user=Depends(security.require_user)):
    """Întoarcerea de la provider. Pagină simplă, fără JS (CSP-ul nostru interzice
    inline scripts) — fila se închide, iar panoul din Setări se reîmprospătează."""
    if error or not code:
        msg = error or "authorization cancelled"
    else:
        try:
            await cloudbackup.finish_authorization(user["id"], code, state)
            msg = ""
        except cloudbackup.CloudError as e:
            msg = str(e)
    body = ("<!doctype html><meta charset=utf-8><title>WebTerm</title>"
            "<body style='font:15px system-ui;background:#0b1220;color:#e2e8f0;"
            "display:grid;place-items:center;height:100vh;margin:0'><div style='text-align:center'>"
            + ("<h1 style='font-size:18px'>Connected ✓</h1><p style='color:#94a3b8'>"
               "You can close this tab — scheduled backups will go to the cloud automatically.</p>"
               if not msg else
               "<h1 style='font-size:18px;color:#fb7185'>Connection failed</h1>"
               "<p style='color:#94a3b8'>%s</p>" % html.escape(msg))
            + "</div></body>")
    return Response(content=body, media_type="text/html; charset=utf-8")


@router.post("/api/backup/cloud/upload")
async def cloud_upload_now(user=Depends(security.require_user)):
    try:
        name = await cloudbackup.upload_backup()
    except cloudbackup.CloudError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "name": name, "status": await cloudbackup.status()}


@router.post("/api/backup/cloud/disconnect")
async def cloud_disconnect(user=Depends(security.require_user)):
    await cloudbackup.disconnect()
    return await cloudbackup.status()


# ── Cheie de semnare a flotei (per-deployment) ───────────────────────────────
# Vezi docs/design/SIGNED-UPDATES.md. Gateway-ul semnează update-urile de
# agent cu ACEASTĂ cheie → nimeni nu depinde de cheia mentainerului upstream.

class SigningGenIn(BaseModel):
    passphrase: str = ""            # parola cu care se CRIPTEAZĂ cheia la repaus
    current_password: str = ""      # parola contului (re-auth)


class SigningPassIn(BaseModel):
    passphrase: str = ""
    current_password: str = ""


class SigningImportIn(BaseModel):
    current_password: str = ""      # re-auth: cheia flotei nu se schimbă cu un cookie
    pem: str                        # cheia privată ed25519 în format PEM
    load_passphrase: str = ""       # parola PEM-ului importat (dacă e criptat)
    store_passphrase: str = ""      # re-criptare la repaus pe gateway (opțional)


def _signing_status() -> dict:
    return {
        "exists": signing.key_exists(),
        "encrypted": signing.is_encrypted(),
        "unlocked": signing.is_loaded(),
        "pubkey": signing.pubkey_hex(),
    }


@router.get("/api/signing/status")
async def signing_status(user=Depends(security.require_user)):
    return _signing_status()


@router.get("/api/changelog")
async def changelog(user=Depends(security.require_user)):
    """CHANGELOG-ul aplicaţiei, servit din imagine ca UI-ul să-l poată arăta (About →
    „Ce e nou") fără ca utilizatorul să plece pe GitHub. Autentificat: e informaţie de
    produs pentru un operator conectat, nu conţinut public. Textul e Markdown de încredere
    (fişier din imagine); frontend-ul îl randează ca noduri de text, nu ca HTML."""
    try:
        text = await asyncio.to_thread(config.CHANGELOG_FILE.read_text, "utf-8")
    except OSError:
        raise HTTPException(404, "changelog is not available on this gateway")
    return {"text": text, "version": config.GATEWAY_VERSION}


@router.post("/api/signing/generate")
async def signing_generate(body: SigningGenIn, user=Depends(security.require_user)):
    await _require_reauth_for_secret(user, body.current_password, "generating the signing key")
    if signing.key_exists():
        raise ApiError(409, "signing.exists", "a fleet signing key already exists")
    if body.passphrase and len(body.passphrase) < 8:
        raise HTTPException(400, "the key passphrase must be at least 8 characters")
    try:
        await asyncio.to_thread(signing.generate, body.passphrase or None)
    except Exception as e:
        raise HTTPException(500, "generation failed: %s" % e)
    return _signing_status()


@router.post("/api/signing/import")
async def signing_import(body: SigningImportIn, user=Depends(security.require_user)):
    await _require_reauth_for_secret(user, body.current_password, "importing the signing key")
    if signing.key_exists():
        raise ApiError(409, "signing.exists", "a fleet signing key already exists")
    if body.store_passphrase and len(body.store_passphrase) < 8:
        raise HTTPException(400, "the storage passphrase must be at least 8 characters")
    try:
        await asyncio.to_thread(signing.import_key, body.pem.encode(),
                                body.load_passphrase or None, body.store_passphrase or None)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, "import failed: %s" % e)
    return _signing_status()


@router.post("/api/signing/unlock")
async def signing_unlock(body: SigningPassIn, user=Depends(security.require_user)):
    if not signing.key_exists():
        raise ApiError(404, "signing.missing", "no signing key")
    # Generarea, importul şi backupul cheii cer parola contului; deblocarea NU o cerea, deşi e
    # tot o operaţie pe cheia flotei. Efect: (a) endpointul devenea un oracol de ghicire a
    # parolei CHEII, fără nicio limitare — lockout-ul din `security` e pe login, nu aici; şi
    # (b) fiecare încercare consumă un thread din pool pe un KDF, deci un flood autentificat
    # înfunda şi restul muncii off-loop (backup, VACUUM, transcripturi).
    await _require_reauth_for_secret(user, body.current_password, "unlocking the signing key")
    okk = await asyncio.to_thread(signing.load, body.passphrase or None)
    if not okk:
        raise HTTPException(403, "wrong password")
    return _signing_status()


@router.post("/api/signing/lock")
async def signing_lock(body: SigningPassIn, user=Depends(security.require_user)):
    # Blocarea opreşte auto-update-ul pe TOATĂ flota, dintr-un singur POST. Un cookie furat
    # putea face asta fără să dovedească nimic — o negare de serviciu ieftină şi tăcută.
    await _require_reauth_for_secret(user, body.current_password, "locking the signing key")
    signing.lock()
    return _signing_status()


@router.post("/api/signing/backup")
async def signing_backup(body: SigningPassIn, user=Depends(security.require_user)):
    """Descarcă o copie CRIPTATĂ a cheii de semnare (scrypt→AES-GCM, cu parola dată).
    Pierderea cheii = agenții existenți merg mai departe, dar nu mai primesc update-uri."""
    await _require_reauth_for_secret(user, body.current_password, "exporting the signing key")
    if not signing.key_exists():
        raise ApiError(404, "signing.missing", "no signing key")
    if len(body.passphrase) < 8:
        raise HTTPException(400, "the encryption passphrase must be at least 8 characters")
    try:
        blob = await asyncio.to_thread(backup.encrypt, signing.key_bytes(), body.passphrase)
    except Exception as e:
        raise HTTPException(500, "backup failed: %s" % e)
    return Response(content=blob, media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="webterm-signing-key.wtbk"'})


# ── Consola de flotă: rulare non-interactivă a unei comenzi pe un host ────────
# Frontend-ul cheamă endpoint-ul ăsta o dată PER host (în paralel) și umple grila
# de rezultate pe măsură ce fiecare răspunde. Fără stare de „job" pe server.
class RunIn(BaseModel):
    command: str
    timeout: int = 60
    stepup_grant: str = ""     # 2FA: grant/parolă pt. host-uri cu require_2fa (H1)
    stepup_password: str = ""
    confirmed: bool = False    # guardrail: regula „confirm" cere un DA explicit (vezi host_run)


@router.post("/api/hosts/{host_id}/run")
async def host_run(host_id: int, body: RunIn, request: Request,
                   user=Depends(security.require_scope("run"))):
    audit.detail(request, "cmd: " + body.command.strip()[:200])
    await _require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password)   # H1
    cmd = body.command.strip()
    if not cmd:
        raise HTTPException(400, "empty command")
    if len(cmd) > 8000:
        raise HTTPException(400, "command too long")
    # Guardrail-ul de comenzi era verificat DOAR client-side, la Enter în browser. Pe tastarea
    # directă în PTY aşa şi rămâne (nu inspectăm fluxul de taste), dar `/run` e un punct de
    # strangulare curat: cine ocoleşte UI-ul ocolea şi regula. Semnalat de auditul extern
    # (2026-08-06). `block` refuză; `confirm` cere confirmare explicită în cerere — serverul
    # nu poate deschide un dialog, dar poate pretinde că cineva a răspuns la el.
    rule = await _match_guard_rule(cmd)
    if rule and rule["action"] == "block":
        raise HTTPException(403, "command blocked by a guardrail: /%s/" % rule["pattern"])
    if rule and not body.confirmed:
        raise HTTPException(409, "command flagged for confirmation by a guardrail: /%s/"
                                 % rule["pattern"])
    cmd_timeout = min(max(int(body.timeout), 1), 300)
    conn = core.source_for(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise HTTPException(409, "host offline or has no agent")
    try:
        resp = await conn.run_command(cmd, cmd_timeout)
    except (core.AgentGone, TimeoutError, asyncio.TimeoutError):
        raise HTTPException(504, "the host did not answer in time")
    if not resp.get("ok"):
        raise HTTPException(502, resp.get("msg") or "run failed")
    hrow = await db.fetchone("SELECT name FROM hosts WHERE id=?", host_id)
    await _record_history(host_id, hrow["name"] if hrow else "", cmd,
                          resp.get("exit_code"), "", "fleet")
    return {"exit_code": resp.get("exit_code"), "timed_out": bool(resp.get("timed_out")),
            "stdout": resp.get("stdout", ""), "stderr": resp.get("stderr", ""),
            "duration": resp.get("duration")}


# ── Git: status/diff/stage/commit pe repo-ul din cwd-ul sesiunii ─────────────
# Panoul de git rulează subcomenzi git prin op-ul `run` al agentului — NU op-uri
# git noi în ptyd.py, deci FĂRĂ re-semnare. Diferă de /run prin: (1) whitelist
# strict de subcomenzi, (2) argv shell-quotat server-side (fără injecție prin
# cale/mesaj), (3) NU scrie în command_history (status/diff se cer des; ar inunda
# istoricul). Scope: status/diff/stage/commit — merge/rebase/push rămân la CLI.
_GIT_SUBCMDS = {"status", "diff", "rev-parse", "add", "reset", "restore", "commit"}


class GitIn(BaseModel):
    args: list[str]
    cwd: str
    stepup_grant: str = ""     # 2FA: la fel ca /run, orice acțiune pe host 2FA cere step-up
    stepup_password: str = ""


@router.post("/api/hosts/{host_id}/git")
async def host_git(host_id: int, body: GitIn, user=Depends(security.require_user)):
    await _require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password)   # H1
    if not body.args or body.args[0] not in _GIT_SUBCMDS:
        raise HTTPException(400, "git subcommand not allowed")
    cwd = (body.cwd or "").strip()
    if not cwd.startswith("/"):
        raise ApiError(400, "git.cwdAbsolute", "cwd must be an absolute path")
    if len(body.args) > 24:
        raise ApiError(400, "run.tooManyArgs", "too many arguments")
    # argv → linie shell sigură: fiecare argument citat, deci o cale/mesaj cu
    # spații, ghilimele sau `;` nu poate rupe comanda sau injecta alta.
    cmd = " ".join(shlex.quote(p) for p in (["git", "-C", cwd] + list(body.args)))
    if len(cmd) > 8000:
        raise HTTPException(400, "command too long")
    conn = core.source_for(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise HTTPException(409, "host offline or has no agent")
    try:
        resp = await conn.run_command(cmd, 30)
    except (core.AgentGone, TimeoutError, asyncio.TimeoutError):
        raise HTTPException(504, "the host did not answer in time")
    if not resp.get("ok"):
        raise HTTPException(502, resp.get("msg") or "run failed")
    return {"exit_code": resp.get("exit_code"), "stdout": resp.get("stdout", ""),
            "stderr": resp.get("stderr", "")}


# ── Istoric global de comenzi (căutabil, audit-lite) ─────────────────────────
# Comenzile interactive sunt raportate de client (din marcajele OSC 133); cele de
# flotă se scriu automat mai sus. Un singur cont → istoricul e ca `~/.bash_history`,
# doar căutabil peste toate hosturile și sesiunile.
HISTORY_CAP = 10000


async def _record_history(host_id, host_name, command, exit_code, cwd, source):
    cmd = (command or "").strip()
    if not cmd:
        return
    ec = exit_code if isinstance(exit_code, int) else None
    await db.execute(
        "INSERT INTO command_history(host_id, host_name, command, exit_code, cwd, source, created)"
        " VALUES(?,?,?,?,?,?,?)",
        host_id, (host_name or "")[:120], cmd[:4000], ec, (cwd or "")[:500], source, time.time())
    # plafon: păstrează ultimele HISTORY_CAP (id autoincrement ≈ ordine cronologică)
    await db.execute(
        "DELETE FROM command_history WHERE id <= (SELECT MAX(id) - ? FROM command_history)",
        HISTORY_CAP)


class HistoryIn(BaseModel):
    host_id: int | None = None
    command: str
    exit_code: int | None = None
    cwd: str = ""


@router.post("/api/history")
async def add_history(body: HistoryIn, user=Depends(security.require_user)):
    """F-10: rândurile astea sunt RAPORTATE DE CLIENT (OSC 133 din browser), deci pot fi
    forjate de oricine are un cookie valid. Nu sunt probă şi nu trebuie tratate ca atare —
    urma reală e `audit_log`, scrisă de middleware, pe care clientul n-o poate atinge.
    Marcăm sursa explicit ca UI-ul să poată spune diferenţa."""
    hn = ""
    if body.host_id is not None:
        row = await db.fetchone("SELECT name FROM hosts WHERE id=?", body.host_id)
        hn = row["name"] if row else ""
    await _record_history(body.host_id, hn, body.command, body.exit_code, body.cwd, "session")
    return {"ok": True}


@router.get("/api/history")
async def search_history(q: str = "", host_id: int | None = None, limit: int = 200,
                         user=Depends(security.require_user)):
    limit = min(max(limit, 1), 500)
    clauses, params = [], []
    if q.strip():
        clauses.append("command LIKE ?")
        params.append("%" + q.strip() + "%")
    if host_id is not None:
        clauses.append("host_id = ?")
        params.append(host_id)
    # Hosturile cu `require_2fa` intră doar cu o fereastră de step-up deschisă. Istoricul
    # conţine comenzile EXECUTATE şi directorul curent — acelaşi fel de conţinut ca transcriptul
    # şi căutarea globală, care sunt amândouă păzite. Aici lipsea, deci un cookie furat citea de
    # pe un host marcat „cere 2FA" exact ce restul căilor refuzau. Filtrăm TĂCUT, ca la
    # `/api/search`: un 403 ar transforma căutarea într-un oracol pentru „există comenzi pe X".
    gated = {r["id"] for r in await db.fetchall(
        "SELECT id FROM hosts WHERE require_2fa=1")}
    blocked = {hid for hid in gated if not security.stepup_window_ok(user["id"], hid)}
    if blocked:
        clauses.append("(host_id IS NULL OR host_id NOT IN (%s))"
                       % ",".join("?" * len(blocked)))
        params.extend(sorted(blocked))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await db.fetchall(
        "SELECT id, host_id, host_name, command, exit_code, cwd, source, created"
        " FROM command_history" + where + " ORDER BY created DESC LIMIT ?", *params, limit)
    return [dict(r) for r in rows]


@router.delete("/api/history")
async def clear_history(user=Depends(security.require_user)):
    await db.execute("DELETE FROM command_history")
    return {"ok": True}


class ForwardIn(BaseModel):
    label: str
    target_host: str = "127.0.0.1"
    target_port: int
    scheme: str = "http"
    description: str = ""
    enabled: bool = False
    stepup_grant: str = ""
    stepup_password: str = ""


class ForwardPatch(BaseModel):
    label: str | None = None
    target_host: str | None = None
    target_port: int | None = None
    scheme: str | None = None
    description: str | None = None
    enabled: bool | None = None
    stepup_grant: str = ""
    stepup_password: str = ""


def _validate_forward(host: str, port: int, scheme: str):
    if not (1 <= int(port) <= 65535):
        raise ApiError(400, "forward.badPort", "invalid port (1–65535)")
    if scheme not in ("http", "https", "telnet"):
        raise ApiError(400, "forward.badScheme", "scheme must be http, https or telnet")
    # allowlist STRICT (nu blocklist): hostname / IPv4 / IPv6 conțin doar
    # alfanumerice + . - : _ . Blocklist-ul vechi lăsa să treacă ESC (0x1b) și
    # restul C0 → un target_host cu secvențe ANSI ajungea în terminal/transcript
    # prin marcajul de reconectare (core.py), ocolind și filtrul OSC. Allowlist-ul
    # elimină întreaga clasă de injecție de secvențe în terminal.
    if not host or len(host) > 255 or not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
        raise ApiError(400, "forward.badTarget", "invalid target_host (letters, digits, . - : _ only)")


async def _unique_slug(label: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:40] or "fwd"
    slug = base
    n = 2
    while await db.fetchone("SELECT 1 FROM port_forwards WHERE slug=?", slug):
        slug = "%s-%d" % (base, n)
        n += 1
    return slug


def _strip_cookie_domain(value: str) -> str:
    """Scoate atributul `Domain=` dintr-un Set-Cookie venit de la serviciul forwardat.

    Atributele sunt separate prin `;` iar valoarea cookie-ului e prima bucată — pe care
    NU o atingem (poate conţine `=` şi chiar textul „domain"). Comparăm doar numele
    atributului, case-insensitive, ca în RFC 6265."""
    parts = value.split(";")
    kept = [parts[0]]
    for attr in parts[1:]:
        if attr.strip().split("=", 1)[0].strip().lower() == "domain":
            continue
        kept.append(attr)
    return ";".join(kept)


def _forward_json(row) -> dict:
    return {
        "id": row["id"], "host_id": row["host_id"], "label": row["label"],
        "slug": row["slug"], "target_host": row["target_host"],
        "target_port": row["target_port"], "scheme": row["scheme"],
        "description": row["description"] or "", "enabled": bool(row["enabled"]),
        "created": row["created"],
        # subdomeniul pe care se accesează (izolare de origin)
        "url": "%s://%s.%s" % (_FWD_SCHEME, row["slug"], forward_domain()),
    }


@router.get("/api/hosts/{host_id}/forwards")
async def list_forwards(host_id: int, stepup_grant: str = "", stepup_password: str = "",
                        user=Depends(security.require_user)):
    # Lista arată `target_host:target_port` pentru fiecare tunel — exact informaţia pentru care
    # s-a pus step-up pe probă („ce port intern e deschis"). Create/patch/delete/probe/telnet îl
    # cereau toate; lista o dădea gratis, deci gardul era ocolibil prin simpla citire.
    await _require_host_stepup(host_id, user, stepup_grant, stepup_password)
    rows = await db.fetchall(
        "SELECT * FROM port_forwards WHERE host_id=? ORDER BY created", host_id)
    return [_forward_json(r) for r in rows]


@router.get("/api/audit")
async def audit_list(limit: int = 200, before: float = 0.0, q: str = "",
                     failed_only: bool = False,
                     user=Depends(security.require_user)):
    # `require_user`, nu `require_scope("read")`. Coloana `detail` conţine textul COMPLET al
    # comenzilor rulate pe flotă, interogările de căutare, emailul şi IP-ul fiecărui operator —
    # adică exact conţinutul pe care toate celelalte citiri (`/transcript`, `/preview`,
    # `/search`, `/agent-log`) îl ţin deliberat în afara tokenurilor. Un token de automatizare
    # ajunge în loguri de CI, în `.env`, în scripturi; nu are ce căuta în istoricul operaţional.
    """Jurnalul de audit: ce s-a schimbat prin UI/API, de către cine și de la ce IP.
    Paginare în trecut cu `before` (ts-ul ultimei linii primite)."""
    return {"entries": await audit.recent(limit, before, q.strip(), failed_only),
            "retention_days": config.AUDIT_RETENTION_DAYS}


@router.get("/api/hosts/{host_id}/events")
async def host_events(host_id: int, user=Depends(security.require_user)):
    """Jurnal de conexiune al agentului (ultimele 7 zile) + starea curentă — pentru panoul
    de diagnostic: cine a conectat/deconectat şi DE CE, când a venit un update etc."""
    await _require_host_stepup(host_id, user)   # F-05: IP-uri, versiuni, motive de reconectare
    hrow = await db.fetchone(
        "SELECT last_heartbeat, agent_version, connection_type, agent_ip FROM hosts WHERE id=?", host_id)
    if not hrow:
        raise HTTPException(404)
    rows = await db.fetchall(
        "SELECT ts, event, reason, detail FROM agent_events WHERE host_id=?"
        " ORDER BY ts DESC LIMIT 200", host_id)
    conn = core.sources.get(host_id)
    return {
        "online": conn is not None,
        "last_heartbeat": hrow["last_heartbeat"],
        "agent_version": hrow["agent_version"],
        "connection_type": hrow["connection_type"],
        "agent_ip": hrow["agent_ip"],
        # health de link raportat de agent (uptime/reconnects/rtt_ms) — Faza 3
        "link": (conn.link if isinstance(conn, core.AgentConnection) else {}),
        "events": [dict(r) for r in rows],
    }


@router.get("/api/hosts/{host_id}/agent-log")
async def agent_log(host_id: int, user=Depends(security.require_user)):
    """Tail-ul logului agentului (ptyd.log) — debug din UI, fără SSH pe host."""
    # H1: logul agentului conţine ce s-a întâmplat pe host şi poate include conţinut
    # scris de utilizator. `audit.py` îl clasifică drept citire care SCOATE date; poarta
    # de step-up îi lipsea, deci un cookie furat citea de pe un host marcat „cere 2FA"
    # exact ce restul căilor (transcript, fs-download, forwards) refuzau.
    await _require_host_stepup(host_id, user)
    conn = core.sources.get(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise ApiError(409, "host.offline", "the host is offline, or has no agent connected")
    try:
        return {"log": await conn.get_agent_log()}
    except core.ForwardError as e:
        raise HTTPException(502, str(e))
    except (core.AgentGone, TimeoutError):
        raise HTTPException(409, "host offline")


@router.post("/api/hosts/{host_id}/forwards")
async def create_forward(host_id: int, body: ForwardIn,
                         user=Depends(security.require_user)):
    # Un forward e o gaură făcută la comandă în reţeaua host-ului: `127.0.0.1:2375` (API-ul
    # Docker) devine accesibil din afară. Pe un host cu 2FA, asta trebuie să coste un factor.
    # Comentariul de dinainte spunea că e „aceeaşi categorie ca citirea istoricului" — dar
    # citirea istoricului a fost închisă cu step-up între timp, deci premisa a căzut şi
    # forward-urile rămăseseră singura acţiune de host descoperită. Vezi şi `forward_auth`,
    # care apără ACCESUL: fără el, gardul de aici ar opri doar crearea de forward-uri noi.
    await _require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password)
    _validate_forward(body.target_host, body.target_port, body.scheme)
    label = body.label.strip()[:60] or "forward"
    # _unique_slug + INSERT NU e atomic: două creări concurente (double-click / două tab-uri)
    # pot alege același slug și apoi ciocni pe constrângerea UNIQUE → 500. Reîncercăm: la tura
    # următoare _unique_slug vede slug-ul deja ocupat și alege sufixul următor, deci converge.
    slug = None
    for _ in range(5):
        slug = await _unique_slug(label)
        try:
            await db.execute(
                "INSERT INTO port_forwards(host_id, label, slug, target_host, target_port,"
                " scheme, description, enabled, created) VALUES(?,?,?,?,?,?,?,?,?)",
                host_id, label, slug, body.target_host, int(body.target_port),
                body.scheme, (body.description or "")[:500], int(body.enabled), time.time())
            break
        except sqlite3.IntegrityError:
            slug = None
    if slug is None:
        raise HTTPException(409, "slug taken, retry")
    row = await db.fetchone("SELECT * FROM port_forwards WHERE slug=?", slug)
    return _forward_json(row)


@router.patch("/api/forwards/{fid}")
async def update_forward(fid: int, body: ForwardPatch,
                         user=Depends(security.require_user)):
    row = await db.fetchone("SELECT * FROM port_forwards WHERE id=?", fid)
    if not row:
        raise ApiError(404, "forward.missing", "no such forward")
    # re-ţintirea unui forward existent e la fel de puternică precum crearea lui
    await _require_host_stepup(row["host_id"], user, body.stepup_grant, body.stepup_password)
    host = body.target_host if body.target_host is not None else row["target_host"]
    port = body.target_port if body.target_port is not None else row["target_port"]
    scheme = body.scheme if body.scheme is not None else row["scheme"]
    _validate_forward(host, port, scheme)
    label = (body.label.strip()[:60] or row["label"]) if body.label is not None else row["label"]
    desc = (body.description or "")[:500] if body.description is not None else row["description"]
    enabled = int(body.enabled) if body.enabled is not None else row["enabled"]
    await db.execute(
        "UPDATE port_forwards SET label=?, target_host=?, target_port=?, scheme=?,"
        " description=?, enabled=? WHERE id=?",
        label, host, int(port), scheme, desc, enabled, fid)
    return _forward_json(await db.fetchone("SELECT * FROM port_forwards WHERE id=?", fid))


@router.delete("/api/forwards/{fid}")
async def delete_forward(fid: int, stepup_grant: str = "", stepup_password: str = "",
                         user=Depends(security.require_user)):
    row = await db.fetchone("SELECT host_id FROM port_forwards WHERE id=?", fid)
    if not row:
        return {"ok": True}                     # idempotent: deja nu există
    # ştergerea nu deschide acces, dar e o schimbare de configurare a unui host cu 2FA —
    # şi, mai practic, cine poate şterge poate re-crea imediat cu altă ţintă
    await _require_host_stepup(row["host_id"], user, stepup_grant, stepup_password)
    await db.execute("DELETE FROM port_forwards WHERE id=?", fid)
    # Biletul e semnat pe SLUG, iar `_unique_slug` recicla slug-ul unui forward şters: un bilet
    # vechi (emis pentru altă ţintă) redevenea valid pe forward-ul nou cu acelaşi nume. Verificat:
    # `web`→:19999 şters, recreat `web`→:19997 — acelaşi cookie deschidea noua ţintă. Bumpăm epoca,
    # ca la logout: toate biletele mor, iar handshake-ul se reface transparent (un redirect).
    security.bump_forward_epoch()
    return {"ok": True}


class TelnetOpenIn(BaseModel):
    title: str = ""
    rows: int = 24
    cols: int = 80
    tz: str | None = None
    stepup_grant: str = ""
    stepup_password: str = ""


@router.post("/api/forwards/{fid}/telnet")
async def open_forward_telnet(fid: int, body: TelnetOpenIn,
                              user=Depends(security.require_user)):
    """Bastion telnet: deschide o sesiune de terminal către ținta unui forward
    (scheme=telnet), tunelată prin agentul host-ului. Spre deosebire de forward-urile
    web (subdomeniu + proxy HTTP), aici suprafața de acces e un TERMINAL pe originul
    principal — fără DNS/cert/cookie nou (vezi docs/design/TELNET-BASTION.md §3)."""
    # `enabled=0` era ignorat aici: butonul „Oprit" din UI e singura pârghie de „taie accesul
    # acum", iar pe calea HTTP funcţiona (404). Pe telnet şi pe probă, sesiunea se deschidea şi
    # octeţii curgeau spre echipamentul din LAN, cu forward-ul dezactivat.
    row = await db.fetchone("SELECT * FROM port_forwards WHERE id=? AND enabled=1", fid)
    if not row:
        raise ApiError(404, "forward.missing", "no such forward")
    # H1: sesiune interactivă prin agentul host-ului — aceeași poartă ca create_session
    await _require_host_stepup(row["host_id"], user, body.stepup_grant, body.stepup_password)
    if row["scheme"] != "telnet":
        raise ApiError(400, "forward.notTelnet", "this forward is not a telnet forward")
    title = body.title.strip() or row["label"] or f'{row["target_host"]}:{row["target_port"]}'
    try:
        return await core.create_telnet_session(row, title[:60], body.rows, body.cols, body.tz)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")
    except core.SessionLimitReached:
        raise ApiError(409, "telnet.limit", "the telnet session limit was reached — close one first")
    except RuntimeError as e:
        raise HTTPException(502, str(e))


# ── Console seriale (RS232/RS485/USB) prin agent ─────────────────────────────
class SerialOpenIn(BaseModel):
    device: str
    baud: int = 115200
    bits: int = 8
    parity: str = "none"      # none | even | odd
    stop: int = 1             # 1 | 2
    flow: str = "none"        # none | rtscts | xonxoff
    title: str = ""
    rows: int = 24
    cols: int = 80
    tz: str | None = None
    stepup_grant: str = ""
    stepup_password: str = ""


@router.post("/api/hosts/{host_id}/serial/discover")
async def serial_discover(host_id: int, user=Depends(security.require_user)):
    """List the real serial ports on the host (discovery, read-only)."""
    row = await db.fetchone("SELECT id FROM hosts WHERE id=?", host_id)
    if not row:
        raise HTTPException(404)
    # H1: e pasul dinaintea deschiderii unei console seriale, pe care `serial/open` o
    # păzeşte deja — iar lista în sine spune ce echipamente sunt legate la host.
    await _require_host_stepup(host_id, user)
    try:
        return {"ports": await core.serial_discover(host_id)}
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")


@router.post("/api/hosts/{host_id}/serial/open")
async def serial_open(host_id: int, body: SerialOpenIn, user=Depends(security.require_user)):
    """Deschide o sesiune de consolă serială pe host. Interactiv → aceeași poartă de
    step-up ca sesiunile normale."""
    row = await db.fetchone("SELECT id FROM hosts WHERE id=?", host_id)
    if not row:
        raise HTTPException(404)
    await _require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password)
    device = (body.device or "").strip()
    if not device.startswith("/dev/") or "\x00" in device:
        raise ApiError(400, "serial.badDevice", "invalid serial device (/dev/* only)")
    if body.parity not in ("none", "even", "odd") or body.flow not in ("none", "rtscts", "xonxoff"):
        raise ApiError(400, "serial.badParity", "invalid parity/flow")
    params = {"baud": body.baud, "bits": body.bits, "parity": body.parity,
              "stop": body.stop, "flow": body.flow}
    title = (body.title or "").strip() or device.rsplit("/", 1)[-1]
    try:
        return await core.create_serial_session(host_id, device, params, title[:60],
                                                body.rows, body.cols, body.tz or None)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")
    except core.SessionLimitReached:
        raise ApiError(409, "serial.limit", "the serial session limit was reached — close one first")
    except RuntimeError as e:
        raise HTTPException(502, str(e))


# ── Routing pe subdomeniu + handshake de auth ────────────────────────────────
async def _forward_stepup_ok(slug: str, request: Request) -> bool:
    """Pe hosturile marcate `require_2fa`, un tunel deschis se închide când se închide
    fereastra de step-up. Pentru restul, mereu adevărat (zero cost).

    Verificarea stă pe calea prin care trece TOT traficul forwardat, deci o excepţie aici nu
    e o poartă închisă, ci 500 la fiecare cerere. Prima versiune interoga o tabelă inexistentă
    (`forwards` în loc de `port_forwards`) şi exact asta s-a întâmplat: opt teste de forward
    au picat, jumătate cu 500.

    Nu o înfăşurăm într-un `try/except` care întoarce True: pe o verificare de securitate,
    „n-am putut afla, deci las să treacă" e o apărare de faţadă. Dacă interogarea moare, moare
    şi căutarea ţintei de imediat după, deci cererea eşuează oricum — vizibil, nu tăcut.
    `tests/forward_stepup_test.py` execută funcţia pe o bază reală, cu schema reală, ceea ce
    e singurul lucru care ar fi prins un nume de tabelă greşit."""
    row = await db.fetchone(
        "SELECT f.host_id, h.require_2fa FROM port_forwards f JOIN hosts h ON h.id=f.host_id"
        " WHERE f.slug=? AND f.enabled=1", slug)
    if not row or not row["require_2fa"]:
        return True
    user = await security.user_for_token(request.cookies.get(security.COOKIE_NAME))
    return bool(user and security.stepup_window_ok(user["id"], row["host_id"]))


async def route_forward(request: Request):
    """Dacă cererea e pentru un subdomeniu de forward, o tratează (auth / redirect /
    proxy) și întoarce un Response; altfel None (merge la rutele normale).
    Apelat din middleware-ul din main.py, ÎNAINTE de restul rutelor."""
    host = (request.headers.get("host") or "").split(":")[0].lower()
    if not host or host == forward_domain() or not host.endswith("." + forward_domain()):
        return None                            # domeniul principal → app normal
    # Plasă de siguranţă pentru o instanţă deja configurată greşit (sau pentru o setare care
    # ajunge în DB pe altă cale decât endpointul validat): domeniul APLICAŢIEI nu poate fi
    # niciodată tratat ca subdomeniu de forward. Fără asta, un `forward_domain` părinte făcea
    # ca UI-ul, API-ul şi chiar endpointul de reparare să răspundă 404 — recuperabil doar
    # editând SQLite pe server.
    if host == (urlparse(config.PUBLIC_URL).hostname or "").lower():
        return None
    slug = host[:-(len(forward_domain()) + 1)]
    if not slug or "." in slug:
        return PlainTextResponse("no such forward", status_code=404)
    # pasul 3 din handshake: setează cookie-ul pe subdomeniu
    if request.url.path == "/__wtfwd/set":
        return await _forward_set_cookie(request, slug)
    row = await db.fetchone(
        "SELECT * FROM port_forwards WHERE slug=? AND enabled=1", slug)
    if not row:
        return PlainTextResponse("no such forward, or it is disabled", status_code=404)
    # fără cookie valid → trimite la handshake pe domeniul principal (unde e sesiunea)
    # F-06 partea a doua: biletul e valid criptografic, dar pe un host cu 2FA întrebăm şi
    # dacă fereastra care l-a autorizat mai e deschisă. Fără asta, un tunel deja deschis
    # supravieţuia închiderii ferestrei — e o căutare într-un dict, deci practic gratis.
    if not await _forward_stepup_ok(slug, request):
        return RedirectResponse("/__wtfwd/auth?slug=%s&next=%s" % (
            urllib.parse.quote(slug), urllib.parse.quote(str(request.url.path))), 302)
    if not security.verify_forward_token(request.cookies.get(FWD_COOKIE), slug):
        nxt = request.url.path + (("?" + request.url.query) if request.url.query else "")
        loc = "%s/__wtfwd/auth?slug=%s&next=%s" % (config.PUBLIC_URL, slug, quote(nxt, safe=""))
        return RedirectResponse(loc, status_code=302)
    # autorizat → proxy către ținta STOCATĂ (anti-SSRF: nu din URL)
    tp = request.url.path + (("?" + request.url.query) if request.url.query else "")
    return await proxy_forward_http(request, row["host_id"], row["target_host"],
                                    row["target_port"], tp, row["scheme"])


async def _forward_set_cookie(request: Request, slug: str):
    token = request.query_params.get("t", "")
    nxt = request.query_params.get("next", "/")
    if not nxt.startswith("/"):                 # anti open-redirect: doar căi relative
        nxt = "/"
    if not security.verify_forward_token(token, slug):
        return PlainTextResponse("invalid or expired token", status_code=403)
    resp = RedirectResponse("%s://%s.%s%s" % (_FWD_SCHEME, slug, forward_domain(), nxt), status_code=302)
    resp.set_cookie(FWD_COOKIE, token, max_age=security.FORWARD_TOKEN_TTL,
                    httponly=True, secure=config.PUBLIC_URL.startswith("https://"),
                    samesite="lax", path="/")
    return resp


@router.get("/__wtfwd/auth")
async def forward_auth(request: Request, slug: str, next: str = "/"):
    """Pe domeniul PRINCIPAL (unde ajunge cookie-ul de sesiune): dacă ești
    autentificat, emite un token semnat pentru forward-ul cerut și redirect la
    subdomeniu. Nu setează nimic aici — doar semnează după require_user."""
    user = await security.user_for_token(request.cookies.get(security.COOKIE_NAME))
    if not user:                                # nelogat → la login, apoi redeschizi forward-ul
        return RedirectResponse(config.PUBLIC_URL + "/", status_code=302)
    row = await db.fetchone(
        "SELECT slug, host_id FROM port_forwards WHERE slug=? AND enabled=1", slug)
    if not row:
        raise ApiError(404, "forward.missing", "no such forward, or it is disabled")
    # Pe un host cu 2FA, cookie-ul singur nu deschide tunelul. Aici NU putem rula ceremonia
    # passkey (suntem pe un redirect de pagină, în afara SPA-ului), deci cerem o fereastră de
    # step-up deja deschisă din aplicaţie şi, dacă lipseşte, trimitem omul exact acolo unde o
    # poate deschide — un 403 sec l-ar lăsa fără nicio indicaţie ce să facă.
    host = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", row["host_id"])
    if host and host["require_2fa"] and not security.stepup_window_ok(user["id"], row["host_id"]):
        # Parametrii merg în QUERY, nu după hash: ruta SPA e `^#/h/(\d+)$`, ancorată la final,
        # deci `#/h/5?stepup=...` n-ar mai fi recunoscută şi omul ar ateriza pe dashboard.
        # `next` călătoreşte prin ocol ca să revii pe pagina cerută, nu pe rădăcina forward-ului.
        return RedirectResponse(
            "%s/?stepup=forward&slug=%s&next=%s#/h/%d"
            % (config.PUBLIC_URL, quote(slug, safe=""), quote(next, safe=""), row["host_id"]),
            status_code=302)
    if not next.startswith("/"):
        next = "/"
    # F-06: pe un host cu 2FA, biletul NU poate trăi mai mult decât autorizarea care l-a
    # emis. Înainte, un step-up de 5 minute cumpăra 12 ore de tunel — adică exact factorul
    # pe care operatorul l-a cerut nu se aplica serviciului forwardat. Browserul reface
    # handshake-ul singur, deci pentru om e o redirectare, nu o eroare.
    ttl = (security.STEPUP_WINDOW_MAX if (host and host["require_2fa"])
           else security.FORWARD_TOKEN_TTL)
    token = security.make_forward_token(slug, user["id"], ttl)
    loc = "%s://%s.%s/__wtfwd/set?t=%s&next=%s" % (_FWD_SCHEME, slug, forward_domain(), token, quote(next, safe=""))
    return RedirectResponse(loc, status_code=302)


# ── WebSocket proxy prin tunel (codec propriu: gateway = client WS către țintă) ─
# L3: plafon anti-OOM pe un singur frame WS și pe reasamblarea continuărilor. Un dispozitiv ostil din
# spatele unui forward putea anunța un frame de 2^64 octeți → pbuf/acc creșteau nemărginit.
FWD_WS_MAX_FRAME = 8 * 1024 * 1024


class _WSFrameTooLarge(Exception):
    pass


def _ws_frame(payload: bytes, opcode: int) -> bytes:
    """Frame WS client→server (MASK obligatoriu). opcode: 1 text, 2 binary, 9/10 ping/pong."""
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n = len(payload)
    if n < 126:
        hdr = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
    elif n < 65536:
        hdr = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
    return hdr + mask + masked


def _ws_parse(buf: bytes):
    """Parsează frame-urile complete din buf. Întoarce (frames, rest). Fiecare frame
    = (opcode, payload, fin). Suportă payload mascat sau nu."""
    frames = []
    while len(buf) >= 2:
        b0, b1 = buf[0], buf[1]
        opcode = b0 & 0x0f
        ln = b1 & 0x7f
        idx = 2
        if ln == 126:
            if len(buf) < 4:
                break
            ln = struct.unpack("!H", buf[2:4])[0]
            idx = 4
        elif ln == 127:
            if len(buf) < 10:
                break
            ln = struct.unpack("!Q", buf[2:10])[0]
            idx = 10
        if ln > FWD_WS_MAX_FRAME:                 # L3: nu aștepta (și nu tampona) un frame uriaș
            raise _WSFrameTooLarge()
        mask = b""
        if b1 & 0x80:
            if len(buf) < idx + 4:
                break
            mask = buf[idx:idx + 4]
            idx += 4
        if len(buf) < idx + ln:
            break
        payload = buf[idx:idx + ln]
        if mask:
            payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        frames.append((opcode, payload, bool(b0 & 0x80)))
        buf = buf[idx + ln:]
    return frames, buf


def _parse_cookie_header(header: str) -> dict:
    out = {}
    for part in header.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k] = v
    return out


async def handle_forward_ws(scope, receive, send):
    """Proxy WebSocket pentru un subdomeniu de forward. Auth-ul se bazează pe cookie-ul
    __Host-wt_fwd (setat de handshake-ul HTTP, care rulează la încărcarea app-ului)."""
    headers = {k.decode("latin1").lower(): v.decode("latin1")
               for k, v in scope.get("headers", [])}
    host = headers.get("host", "").split(":")[0].lower()
    slug = host[:-(len(forward_domain()) + 1)] if host.endswith("." + forward_domain()) else ""
    if (await receive())["type"] != "websocket.connect":
        return
    # anti-CSWSH: browserul atașează cookie-ul de forward chiar și la un handshake WS
    # pornit de pe o pagină ostilă (SameSite=Lax nu acoperă sigur upgrade-urile WS).
    # Cerem ca Origin-ul să fie chiar subdomeniul de forward — doar pagina forwardată
    # (servită la slug.<domeniu>) îl are; altfel un site ostil ar deschide un WS
    # interactiv către serviciul din spatele forward-ului. La fel ca browser_ws/shared_ws.
    origin = headers.get("origin")
    cookies = _parse_cookie_header(headers.get("cookie", ""))
    if (not origin or urlparse(origin).hostname != host or not slug or "." in slug
            or not security.verify_forward_token(cookies.get(FWD_COOKIE), slug)):
        await send({"type": "websocket.close", "code": 1008})
        return
    row = await db.fetchone("SELECT * FROM port_forwards WHERE slug=? AND enabled=1", slug)
    conn = await _ensure_forward_source(row["host_id"]) if row else None
    if not row or conn is None:
        await send({"type": "websocket.close", "code": 1011})
        return
    try:
        fs = await _open_target(conn, row["target_host"], row["target_port"], row["scheme"])
    except Exception:
        await send({"type": "websocket.close", "code": 1011})
        return
    try:
        path = scope.get("path", "/")
        if scope.get("query_string"):
            path += "?" + scope["query_string"].decode("latin1")
        # anti request-smuggling: path-ul (percent-decodat de ASGI) ajunge în request-line-ul
        # HTTP raw trimis ţintei → respinge CRLF/NUL, ca şi calea HTTP de forward.
        if "\r" in path or "\n" in path or "\0" in path:
            await send({"type": "websocket.close", "code": 1008})
            return
        key = base64.b64encode(os.urandom(16)).decode()
        hs = ["GET %s HTTP/1.1" % path,
              "Host: %s:%d" % (row["target_host"], row["target_port"]),
              "Upgrade: websocket", "Connection: Upgrade",
              "Sec-WebSocket-Key: %s" % key, "Sec-WebSocket-Version: 13"]
        # Se trimitea ţintei DOAR `sec-websocket-protocol`: nicio aplicaţie care îşi
        # autentifică WebSocket-ul prin cookie de sesiune (Jupyter, code-server, Home Assistant,
        # noVNC, Grafana Live) nu putea funcţiona în spatele unui forward — pagina se încărca
        # (HTTP-ul propagă cookie-urile), iar terminalul/graficele rămâneau moarte, fără eroare.
        # Ţinta WS din testul de integrare e un `echo` fără autentificare, deci poarta trecea
        # verde fără să verifice nimic din ce contează. Propagăm acelaşi set ca pe calea HTTP.
        _WS_SKIP = {"host", "connection", "upgrade", "sec-websocket-key",
                    "sec-websocket-version", "sec-websocket-extensions",
                    "keep-alive", "proxy-authenticate", "proxy-authorization",
                    "te", "trailer", "transfer-encoding"}
        for h, v in headers.items():
            if h in _WS_SKIP:
                continue
            if h == "cookie":
                v = _strip_fwd_cookie(v)       # cookie-ul NOSTRU nu iese către ţintă
                if not v:
                    continue
            # CRLF/NUL în valoare = injectare în handshake-ul brut
            if "\r" in v or "\n" in v or "\0" in v:
                continue
            hs.append("%s: %s" % (h, v))
        await fs.write(("\r\n".join(hs) + "\r\n\r\n").encode("latin1"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(fs.read(), timeout=15)
            if chunk is None or len(buf) > 65536:
                await send({"type": "websocket.close", "code": 1011}); return
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0]:
            await send({"type": "websocket.close", "code": 1011}); return
        accept = {"type": "websocket.accept"}
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"sec-websocket-protocol:"):
                accept["subprotocol"] = line.split(b":", 1)[1].decode("latin1").strip()
        await send(accept)

        closed = asyncio.Event()

        async def revalidate():
            # M3: token-urile de forward mor la logout / schimbare de parolă (epoch bump).
            # Verificarea de la connect e o singură dată; re-verificăm periodic ca un tunel
            # ACTIV să se închidă când owner-ul face logout — la fel ca browser_ws/shared_ws.
            try:
                while not closed.is_set():
                    await asyncio.sleep(WS_REVALIDATE_SECS)
                    if not security.verify_forward_token(cookies.get(FWD_COOKIE), slug):
                        break
            finally:
                closed.set()

        async def browser_to_target():
            try:
                while not closed.is_set():
                    m = await receive()
                    if m["type"] == "websocket.receive":
                        if m.get("text") is not None:
                            await fs.write(_ws_frame(m["text"].encode(), 0x1))
                        elif m.get("bytes") is not None:
                            await fs.write(_ws_frame(m["bytes"], 0x2))
                    elif m["type"] == "websocket.disconnect":
                        break
            except Exception:
                pass
            finally:
                closed.set()

        async def target_to_browser(pbuf):
            acc, acc_op = b"", None
            try:
                while not closed.is_set():
                    try:
                        frames, pbuf = _ws_parse(pbuf)
                    except _WSFrameTooLarge:
                        # L3: frame peste plafon → 1009 (Message Too Big) și închide
                        await send({"type": "websocket.close", "code": 1009})
                        closed.set(); break
                    for opcode, payload, fin in frames:
                        if opcode == 0x8:                 # close
                            closed.set(); break
                        if opcode == 0x9:                 # ping → pong
                            await fs.write(_ws_frame(payload, 0xa)); continue
                        if opcode == 0xa:                 # pong (ignoră)
                            continue
                        if opcode in (0x1, 0x2):
                            acc, acc_op = payload, opcode
                        elif opcode == 0x0:               # continuation
                            acc += payload
                        if len(acc) > FWD_WS_MAX_FRAME:   # L3: reasamblare de continuări plafonată
                            await send({"type": "websocket.close", "code": 1009})
                            closed.set(); break
                        if fin and acc_op is not None:
                            if acc_op == 0x1:
                                await send({"type": "websocket.send", "text": acc.decode("utf-8", "replace")})
                            else:
                                await send({"type": "websocket.send", "bytes": acc})
                            acc, acc_op = b"", None
                    if closed.is_set():
                        break
                    chunk = await fs.read()
                    if chunk is None:
                        break
                    pbuf += chunk
            except Exception:
                pass
            finally:
                closed.set()

        tb = asyncio.create_task(browser_to_target())
        tt = asyncio.create_task(target_to_browser(rest))
        tr = asyncio.create_task(revalidate())
        await closed.wait()
        tb.cancel(); tt.cancel(); tr.cancel()
        # așteaptă finalizarea anulării, altfel cleanup-ul taskurilor poate rămâne
        # în aer (și tunelul închis mai jos peste taskuri încă vii)
        await asyncio.gather(tb, tt, tr, return_exceptions=True)
    finally:
        await fs.close()
        try:
            await send({"type": "websocket.close"})
        except Exception:
            pass


class FsRename(BaseModel):
    path: str
    to: str


class FsPath(BaseModel):
    path: str
    parents: bool = False


class FsDelete(BaseModel):
    path: str
    recursive: bool = False


@router.post("/api/hosts/{host_id}/fs/mkdir")
async def fs_mkdir(host_id: int, body: FsPath, user=Depends(security.require_user)):
    await _require_host_stepup(host_id, user)   # H1
    try:
        await core.fs_mkdir(host_id, body.path, body.parents)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@router.post("/api/hosts/{host_id}/fs/rename")
async def fs_rename(host_id: int, body: FsRename, user=Depends(security.require_user)):
    await _require_host_stepup(host_id, user)   # H1
    try:
        await core.fs_rename(host_id, body.path, body.to)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


# POST, nu DELETE: unele proxy-uri/clienți refuză body pe DELETE, iar avem nevoie
# de flag-ul `recursive`. Ștergerea recursivă e explicită, cerută din UI cu confirmare.
@router.post("/api/hosts/{host_id}/fs/delete")
async def fs_delete(host_id: int, body: FsDelete, request: Request,
                    user=Depends(security.require_user)):
    audit.detail(request, body.path + (" (recursiv)" if body.recursive else ""))
    await _require_host_stepup(host_id, user)   # H1
    try:
        await core.fs_delete(host_id, body.path, body.recursive)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@router.post("/api/hosts/{host_id}/update")
async def update_agent(host_id: int, user=Depends(security.require_user)):
    """Update/restart the agent now; tmux sessions survive the restart."""
    await _require_host_stepup(host_id, user)   # H1
    try:
        result = await core.force_update_agent(host_id)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (RuntimeError, TimeoutError) as e:
        raise HTTPException(502, str(e))
    if result["deferred"]:
        # agent vechi (pre-v4) care nu onorează forțarea cât are sesiuni live
        raise HTTPException(
            409,
            "The agent is an old version and will update once you close "
            "the live sessions on this host (the new file is already staged).")
    return {"ok": True}


@router.get("/api/search")
async def search(q: str, request: Request, user=Depends(security.require_user)):
    """Search hosts, session titles/notes and transcript contents."""
    q = q.strip()
    if len(q) < 2:
        return {"sessions": []}
    # CE s-a căutat, nu doar că s-a căutat: „a rulat o căutare" nu răspunde la întrebarea
    # de după un cookie furat, iar interogarea E lucrul care spune ce urmărea atacatorul.
    audit.detail(request, "search: " + q)
    rows = await db.fetchall("SELECT * FROM sessions ORDER BY created DESC LIMIT 500")
    # Căutarea citeşte CONŢINUTUL transcripturilor, deci e aceeaşi clasă cu /transcript:
    # sesiunile de pe hosturi cu `require_2fa` intră doar dacă ai o fereastră de step-up
    # deschisă pentru hostul ăla. Filtrăm TĂCUT (nu 403): altfel căutarea globală ar deveni
    # un oracol pentru „există sesiuni pe hostul X".
    gated = {r["id"] for r in await db.fetchall(
        "SELECT id FROM hosts WHERE require_2fa=1")}
    if gated:
        allowed = {hid for hid in gated if security.stepup_window_ok(user["id"], hid)}
        rows = [r for r in rows if r["host_id"] not in gated or r["host_id"] in allowed]
    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(None, core.search_transcripts, rows, q)
    return {"sessions": results}


class HostPatch(BaseModel):
    """Editare PARȚIALĂ: doar câmpurile trimise se aplică.

    Vechiul PATCH lua un `HostIn` întreg și scria doar name/note/folder. Două consecințe:
    câmpurile de conexiune (hostname, user, port, credențiale) erau acceptate și IGNORATE
    tăcut — clientul primea `ok: true` fără să se fi schimbat nimic — iar un PATCH parțial
    ȘTERGEA nota și folderul, fiindcă lipsa lor din corp înseamnă `""` în `HostIn`.
    Cu `None` ca „netrimis", ambele dispar."""
    name: Optional[str] = None
    note: Optional[str] = None
    folder: Optional[str] = None
    connection_type: Optional[str] = None
    hostname: Optional[str] = None
    ssh_username: Optional[str] = None
    ssh_port: Optional[int] = None
    auth_method: Optional[str] = None
    credential: Optional[str] = None      # write-only; netrimis = păstrează ce e stocat
    passphrase: Optional[str] = None
    credential_policy: Optional[str] = None
    stepup_grant: str = ""
    stepup_password: str = ""


# câmpurile care schimbă UNDE și CU CE ne conectăm — aceeași clasă cu provisioning-ul
_CONN_FIELDS = ("connection_type", "hostname", "ssh_username", "ssh_port",
                "auth_method", "credential", "credential_policy")


@router.patch("/api/hosts/{host_id}")
async def update_host(host_id: int, host: HostPatch, user=Depends(security.require_user)):
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise HTTPException(404)
    given = host.model_dump(exclude_unset=True)
    # `touches_conn` = un câmp de conexiune se SCHIMBĂ efectiv, nu doar e prezent în payload.
    # UI-ul (AddHostModal) trimite MEREU `connection_type`, chiar şi la o redenumire pură, deci
    # „prezent" însemna că ORICE editare pica pe calea de re-provisioning: agentul deconectat
    # degeaba (host offline câteva secunde), step-up cerut inutil pe hosturi 2FA, iar terminalul
    # deschis rămânea fără input. Comparăm cu valoarea curentă; `credential` e write-only, deci
    # o valoare prezentă = schimbare. (Bug raportat: redenumire → nu mai poţi scrie.)
    def _conn_changed(f):
        if f not in given:
            return False
        if f == "credential":
            return bool(given[f])
        return given[f] != row[f]
    touches_conn = any(_conn_changed(f) for f in _CONN_FIELDS)
    if touches_conn:
        # Repointarea unui host către altă mașină (sau altă credențială) e echivalentă cu
        # provisioning-ul: cine are doar cookie-ul nu trebuie să poată face asta pe un host 2FA.
        await _require_host_stepup(host_id, user, host.stepup_grant, host.stepup_password)

    old_type = row["connection_type"] or "agent"
    new_type = given.get("connection_type", old_type)
    if new_type not in ("agent", "ssh", "telnet"):
        raise ApiError(400, "host.badType", "unknown connection type")
    eff = lambda f, col=None: (given[f] if f in given else row[col or f])   # noqa: E731
    hostname = (eff("hostname") or "").strip()
    ssh_username = (eff("ssh_username") or "").strip()
    policy = eff("credential_policy") or "stored"
    auth_method = eff("auth_method") or "password"

    if new_type in ("ssh", "telnet") and not hostname:
        raise ApiError(400, "host.hostnameRequired", "hostname required for a direct connection")
    if new_type == "ssh" and not ssh_username:
        raise ApiError(400, "ssh.userRequired", "an SSH username is required")
    # Întoarcerea la SSH după ce agentul a preluat: detaliile de conexiune supraviețuiesc
    # provisioning-ului, dar credențialul e ȘTERS dacă politica era `ephemeral`. Fără el nu
    # ne putem conecta, deci cerem unul acum, în loc să eșuăm abia la prima conectare.
    if (new_type == "ssh" and policy == "stored"
            and not given.get("credential") and not row["credential_encrypted"]):
        raise HTTPException(400, "the host no longer has stored SSH credentials "
                                 "(removed when the agent was installed) — enter the password or key")

    sets, vals = [], []
    for col, key in (("name", "name"), ("note", "note"), ("folder", "folder"),
                     ("hostname", "hostname"), ("ssh_username", "ssh_username"),
                     ("auth_method", "auth_method"), ("credential_policy", "credential_policy")):
        if key in given:
            v = given[key]
            sets.append(f"{col}=?")
            vals.append(v.strip() if isinstance(v, str) else v)
    if "ssh_port" in given:
        sets.append("ssh_port=?"); vals.append(given["ssh_port"])
    if "connection_type" in given:
        sets.append("connection_type=?"); vals.append(new_type)
    if given.get("credential"):
        blob = _credential_blob(HostIn(
            name=row["name"], connection_type=new_type, auth_method=auth_method,
            credential=given["credential"], passphrase=given.get("passphrase") or "",
            credential_policy=policy))
        sets.append("credential_encrypted=?"); vals.append(blob)
    # Pinul de host-key aparține MAȘINII vechi: dacă am mutat hostul în altă parte, pinul
    # respinge noua mașină la fiecare încercare, iar mesajul arată ca un MITM. Îl resetăm
    # explicit (TOFU repinează la prima conectare) și O SPUNEM în răspuns.
    repinned = (("hostname" in given and hostname != (row["hostname"] or ""))
                or ("ssh_port" in given and given["ssh_port"] != row["ssh_port"]))
    if repinned:
        sets.append("known_hosts=NULL")
    if not sets:
        return {"ok": True, "changed": False}
    vals.append(host_id)
    await db.execute("UPDATE hosts SET %s WHERE id=?" % ", ".join(sets), *vals)

    # O conexiune vie ține parametrii VECHI: fără demontare, editarea pare fără efect până
    # la următoarea deconectare accidentală.
    dropped = False
    if touches_conn:
        conn = core.sources.pop(host_id, None)
        if conn:
            dropped = True
            try:
                await conn.disconnect()
            except Exception:
                pass
        # Detaşăm EXPLICIT hub-urile hostului. `sources.pop` de mai sus face ca `was_current`
        # din `_shutdown` să fie False (sursa nu mai e în dicţionar când agentul cade), deci
        # `on_detached` NU rulează şi hub-urile rămân `attached=True`. La reconectarea agentului
        # `ensure_attached` iese imediat (no-op), aşa că noua conexiune nu re-primeşte niciodată
        # `attach` pentru sesiunile vii → terminalul deschis nu mai poate scrie deşi hostul e
        # online şi sesiunea „live". (Bug raportat: editarea unui host agent → nu mai poţi tasta.)
        core.detach_host_hubs(host_id)
    return {"ok": True, "changed": True, "connection_type": new_type,
            "host_key_reset": repinned, "disconnected": dropped}


class Toggle2fa(BaseModel):
    enabled: bool
    stepup_grant: str = ""
    stepup_password: str = ""


@router.post("/api/hosts/{host_id}/require-2fa")
async def set_require_2fa(host_id: int, body: Toggle2fa, user=Depends(security.require_user)):
    """Activează/dezactivează cererea de 2FA la conectarea pe acest host.
    GAP-fix: DEZACTIVAREA cere step-up — altfel un cookie furat stingea 2FA pe host și tot
    gard-ul H1 devenea no-op. `_require_host_stepup` citește valoarea CURENTĂ (încă 1 la
    dezactivare → cere step-up; 0 la activare → no-op, întărirea securității nu cere factor)."""
    await _require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password)
    await db.execute("UPDATE hosts SET require_2fa=? WHERE id=?", int(body.enabled), host_id)
    if body.enabled:
        # Biletul de forward e valabil 12h şi nu ştie de host. Cine marchează un host „cere 2FA"
        # tocmai fiindcă e îngrijorat rămânea cu tunelurile deschise până la expirare: handshake-ul
        # NOU cerea step-up, cel vechi mergea în continuare. `logout` bumpează deja epoch-ul.
        security.bump_forward_epoch()
    return {"ok": True}


@router.post("/api/hosts/{host_id}/provision")
async def provision_agent(host_id: int, request: Request, user=Depends(security.require_user)):
    """Instalează agentul pe un host SSH: se conectează prin SSH, rulează
    installer-ul, AȘTEAPTĂ ca agentul să se conecteze (test), apoi trece host-ul
    în mod agent și șterge credențialele dacă politica e `ephemeral`."""
    await _require_host_stepup(host_id, user)   # H1
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise HTTPException(404)
    if (row["connection_type"] or "agent") != "ssh":
        raise ApiError(400, "provision.sshOnly", "provisioning is only available for SSH hosts")
    # 1) conexiune SSH (creds stocate; rate-limited; pin host-key)
    await _connect_direct(row, request)
    src = core.sources.get(host_id)
    if not isinstance(src, core.SshSource):
        raise HTTPException(502, "the SSH connection is not available")
    # 2) enroll token proaspăt + rulează installer-ul prin canalul SSH
    enroll = security.new_token()[:32]
    await db.execute("UPDATE hosts SET enroll_token=?, enroll_expires=?, instance_id=NULL WHERE id=?",
                     enroll, time.time() + 3600, host_id)
    try:
        result = await asyncio.wait_for(src._conn.run(_install_command(enroll), check=False), 150)
    except Exception as e:
        raise HTTPException(502, f"install over SSH failed: {e}")
    out = ((result.stdout or "") + (result.stderr or ""))[-1200:]
    # 3) TEST: așteaptă agentul să sune acasă (dovada că merge)
    connected = False
    for _ in range(40):
        await asyncio.sleep(1)
        if isinstance(core.sources.get(host_id), core.AgentConnection):
            connected = True
            break
    if not connected:
        raise HTTPException(504, "the installed agent did not connect in time.\n\n" + out)
    # 4) succes: mod agent + ștergere credențiale după politică
    delete_creds = row["credential_policy"] == "ephemeral"
    await db.execute("UPDATE hosts SET connection_type='agent' WHERE id=?", host_id)
    if delete_creds:
        await db.execute(
            "UPDATE hosts SET credential_encrypted=NULL, credential_policy='stored' WHERE id=?",
            host_id)
        await _drop_ssh_credential_in_memory(host_id)   # vezi helperul: DB-ul singur nu ajunge
    return {"ok": True, "credentials_deleted": delete_creds}


async def _drop_ssh_credential_in_memory(host_id: int) -> bool:
    """Închide conexiunea SSH vie a hostului, dacă există. Întoarce True dacă a fost una.

    Ştergerea rândului din DB nu e suficientă ca „uită credenţialele" să fie adevărat:
    `asyncssh` păstrează `password` şi `client_keys` ÎN CLAR în opţiunile conexiunii
    (`SSHClientConnectionOptions`), iar `SSHClientConnection` le ţine cât trăieşte ea. Deci
    parola rămânea în memoria gateway-ului până când conexiunea pica singură — uneori ore.

    Nu e o escaladare (ca s-o citeşti îţi trebuie execuţie de cod în proces, iar atunci ai
    şi cheia seifului), dar butonul promite ceva şi oamenii îl apasă tocmai ca acel ceva să
    nu mai existe. O promisiune pe jumătate adevărată e mai rea decât una absentă.

    Costul asumat: sesiunile SSH vii de pe hostul ăla se termină. E consecinţa corectă —
    „uită credenţialele" se apasă când calea SSH nu mai e necesară (agentul a preluat), iar
    o conexiune care supravieţuieşte ştergerii credenţialei e exact ce voiai să eviţi.
    Semnalat ca zonă neexaminată de un audit extern; verificat şi confirmat în asyncssh."""
    src = core.sources.get(host_id)
    if not isinstance(src, core.SshSource):
        return False
    core.sources.pop(host_id, None)
    try:
        await src.disconnect()
    except Exception:                       # noqa: BLE001 — închiderea e best-effort
        log.warning("closing the ssh connection for host=%s failed", host_id, exc_info=True)
    return True


class ForgetCredsIn(BaseModel):
    current_password: str = ""


@router.post("/api/hosts/{host_id}/forget-credentials")
async def forget_credentials(host_id: int, body: ForgetCredsIn,
                             user=Depends(security.require_user)):
    """Delete the stored SSH credentials (once the agent has taken over, or at any time).

    F-05: ştergerea e IREVERSIBILĂ — dacă hostul nu mai are agent, credenţiala aia era
    singurul mod de a ajunge la el din WebTerm. Cerea doar un cookie valid, deci era şi
    ţinta ideală a unui CSRF (endpoint fără body, deci cerere „simplă"). Acum are body,
    step-up pe hosturile cu 2FA, şi re-autentificare cu parola."""
    await _require_host_stepup(host_id, user)
    if not await _verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword",
                       "re-enter your account password to forget the stored credentials")
    await db.execute("UPDATE hosts SET credential_encrypted=NULL WHERE id=?", host_id)
    dropped = await _drop_ssh_credential_in_memory(host_id)
    return {"ok": True, "connection_closed": dropped}


# ── Snippets (comenzi salvate) ───────────────────────────────────────────

class SnippetIn(BaseModel):
    title: str
    body: str


# Snippet-uri de transfer gata făcute: fișiere mari sau host↔host se fac cu comenzi
# shell (rsync/scp/curl), nu prin UI. `{{var}}` devin câmpuri în panoul de snippets.
DEFAULT_SNIPPETS = [
    ("Transfer: rsync push (→ another server)",
     "rsync -avz --progress {{source}} {{user}}@{{host}}:{{destination}}"),
    ("Transfer: rsync pull (← another server)",
     "rsync -avz --progress {{user}}@{{host}}:{{source}} {{destination}}"),
    ("Transfer: scp a file (→ another server)",
     "scp {{file}} {{user}}@{{host}}:{{destination}}"),
    ("Transfer: download onto the host (curl)",
     "curl -fSL -o {{local_file}} {{url}}"),
]


async def seed_default_snippets() -> None:
    """Seed o singură dată snippet-urile de transfer. Idempotent (flag în KV); pe
    instalări existente rulează o dată, apoi niciodată. Utilizatorul le poate
    edita/șterge ca pe orice snippet."""
    if await _get_setting("snippets_seeded"):
        return
    for title, body in DEFAULT_SNIPPETS:
        dup = await db.fetchone("SELECT id FROM snippets WHERE title=? AND body=?", title, body)
        if not dup:
            await db.execute("INSERT INTO snippets(title, body, created) VALUES(?,?,?)",
                             title, body, time.time())
    await _set_setting("snippets_seeded", "1")


@router.get("/api/snippets")
async def list_snippets(user=Depends(security.require_user)):
    rows = await db.fetchall("SELECT * FROM snippets ORDER BY title")
    return [{"id": r["id"], "title": r["title"], "body": r["body"]} for r in rows]


@router.post("/api/snippets")
async def create_snippet(s: SnippetIn, user=Depends(security.require_user)):
    if not s.title.strip() or not s.body:
        raise HTTPException(400, "title and body required")
    # idempotent: același titlu+conținut nu creează un duplicat
    dup = await db.fetchone("SELECT id FROM snippets WHERE title=? AND body=?",
                            s.title.strip(), s.body)
    if dup:
        return {"id": dup["id"]}
    sid = await db.execute("INSERT INTO snippets(title, body, created) VALUES(?,?,?)",
                           s.title.strip(), s.body, time.time())
    return {"id": sid}


@router.patch("/api/snippets/{sid}")
async def update_snippet(sid: int, s: SnippetIn, user=Depends(security.require_user)):
    await db.execute("UPDATE snippets SET title=?, body=? WHERE id=?",
                     s.title.strip(), s.body, sid)
    return {"ok": True}


@router.delete("/api/snippets/{sid}")
async def delete_snippet(sid: int, user=Depends(security.require_user)):
    await db.execute("DELETE FROM snippets WHERE id=?", sid)
    return {"ok": True}


@router.delete("/api/hosts/{host_id}")
async def delete_host(host_id: int, user=Depends(security.require_user)):
    await _require_host_stepup(host_id, user)   # F-05: ştergerea unui host cu 2FA e o acţiune de host
    live = await db.fetchone(
        "SELECT id FROM sessions WHERE host_id=? AND state IN ('creating','live')",
        host_id)
    if live:
        raise HTTPException(409, "the host has live sessions; close them first")
    conn = core.sources.pop(host_id, None)
    if conn:
        try:
            # prin interfața SessionSource, NU `conn.ws` — doar AgentConnection are `.ws`;
            # pt. un host SSH (SshSource) `conn.ws` dădea AttributeError înghițit → conexiunea
            # SSH nu se închidea niciodată (leak). `disconnect()` e definit pt. toate sursele.
            await conn.disconnect()
        except Exception:
            pass
    await db.execute("DELETE FROM hosts WHERE id=?", host_id)
    return {"ok": True}


@router.post("/api/hosts/{host_id}/uninstall")
async def uninstall_host(host_id: int, force: bool = False,
                         user=Depends(security.require_user)):
    """Dezinstalează COMPLET agentul de pe server: îi cere să-și scoată supravegherea
    (systemd/cron) + serverul tmux + fișierele din ~/.webterm/ și să iasă, apoi îl scoate din
    WebTerm. Hosturile directe SSH/telnet n-au nimic instalat → doar scoatere din WebTerm.
    `force=1`: scoate doar din WebTerm chiar dacă agentul e offline (fișierele rămân pe host)."""
    await _require_host_stepup(host_id, user)   # H1
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise HTTPException(404)
    live = await db.fetchone(
        "SELECT id FROM sessions WHERE host_id=? AND state IN ('creating','live')", host_id)
    if live:
        raise HTTPException(409, "the host has live sessions; close them first")

    ctype = row["connection_type"] or "agent"
    uninstalled = False
    warnings = []
    if ctype == "agent":
        conn = core.sources.get(host_id)
        if isinstance(conn, core.AgentConnection):
            try:
                resp = await conn.request("uninstall", timeout=20)
                uninstalled = bool(resp.get("ok"))
                warnings = resp.get("warnings", []) or []
            except (core.AgentGone, asyncio.TimeoutError):
                if not force:
                    raise HTTPException(409, "the agent did not answer; retry while it is online, "
                                             "or pass force=1 to drop it from WebTerm only "
                                             "(the files stay on the server, to be cleaned up by hand)")
        elif not force:
            raise HTTPException(409, "the agent is offline; it cannot be uninstalled remotely "
                                     "right now. Bring it online and retry, or pass force=1 to "
                                     "drop it from WebTerm only.")

    c = core.sources.pop(host_id, None)
    if c and not uninstalled:
        try:
            await c.disconnect()
        except Exception:
            pass
    await db.execute("DELETE FROM hosts WHERE id=?", host_id)
    return {"ok": True, "uninstalled": uninstalled, "warnings": warnings}


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

class SessionIn(BaseModel):
    title: str = ""
    # Plafoanele există în `SessionHub.resize`, dar NU şi la creare: se accepta orice întreg,
    # se scria în DB, se trimitea agentului (care re-plafonează la 1..65535) şi se anunţa
    # browserului în `init`. DB-ul, hub-ul şi PTY-ul real ajungeau să nu fie de acord, iar
    # clientul primea o grilă imposibilă. Aceleaşi limite ca la resize, de la primul contact.
    rows: int = Field(24, ge=2, le=500)
    cols: int = Field(80, ge=2, le=1000)
    tz: str = None
    credential: str = ""     # politică `ask`: parola/cheia introdusă la conectare
    passphrase: str = ""
    stepup_grant: str = ""   # 2FA: grant din ceremonia passkey
    stepup_password: str = ""  # 2FA fallback (deploy IP-only, fără passkey)


class SessionPatch(BaseModel):
    title: str = None
    note: str = None


def _session_json(row) -> dict:
    return {
        "id": row["id"], "host_id": row["host_id"], "title": row["title"],
        "note": row["note"], "state": row["state"], "created": row["created"],
        "closed_at": row["closed_at"], "exit_status": row["exit_status"],
        "close_reason": row["close_reason"], "rows": row["rows"], "cols": row["cols"],
        "kind": row["kind"] or "shell",   # shell | telnet (bastion) — UI arată Reconectează pe telnet
        "connected_clients": len(core.hubs[row["id"]].clients)
            if row["id"] in core.hubs else 0,
        # offset-ul absolut al stream-ului de output (live din hub, altfel din DB):
        # UI-ul îl compară cu ultimul offset „văzut" ca să pună punct de activitate
        # pe tab-urile din fundal; tmux rulează cu status off, deci idle = 0 octeți
        "out_offset": core.hubs[row["id"]].agent_offset
            if row["id"] in core.hubs else (row["agent_offset"] or 0),
    }


# the 5s poll must not grow with the full (ever-growing) session history: return
# ALL active sessions (indexed, naturally bounded ~32/host) + only the most recent
# closed/lost. Older closed sessions are reached per-host (GET below) or via search.
CLOSED_SESSIONS_LIMIT = 200


@router.get("/api/sessions")
async def list_sessions(user=Depends(security.require_scope("read"))):
    active = await db.fetchall(
        "SELECT * FROM sessions WHERE state IN ('creating','live') ORDER BY created DESC")
    closed = await db.fetchall(
        "SELECT * FROM sessions WHERE state NOT IN ('creating','live') "
        "ORDER BY created DESC LIMIT ?", CLOSED_SESSIONS_LIMIT)
    return [_session_json(r) for r in list(active) + list(closed)]


@router.get("/api/hosts/{host_id}/sessions")
async def host_sessions(host_id: int, limit: int = 200, offset: int = 0,
                        user=Depends(security.require_user)):
    """Complete session history for one host (active + closed), paginated — used
    by the host page so it isn't limited by the global recent-closed window."""
    limit = max(1, min(limit, 500))
    rows = await db.fetchall(
        "SELECT * FROM sessions WHERE host_id=? ORDER BY created DESC LIMIT ? OFFSET ?",
        host_id, limit, max(0, offset))
    return [_session_json(r) for r in rows]


async def _require_host_stepup(host_id: int, user, grant: str = "", password: str = "") -> None:
    """H1: pe un host cu `require_2fa`, ORICE acțiune sensibilă (sesiune, `run`, `fs/*`, update,
    provision) cere step-up — nu doar deschiderea unei sesiuni. Un grant passkey (single-use) sau
    parola contului (fallback fără WebAuthn) deschide o FEREASTRĂ de step-up pe host (5 min); în
    fereastră, acțiunile ulterioare trec fără re-verificare (ca `sudo`), ca file-browser-ul să nu
    ceară passkey per-click. Fără 2FA pe host → no-op. Ridică 403 dacă lipsește step-up-ul."""
    row = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", host_id)
    if not row or not row["require_2fa"]:
        return
    # Un token de automatizare NU poate face step-up (passkey = cheie fizică): pe hosturile
    # marcate 2FA îl refuzăm din start, în loc să-i cerem ceva imposibil. Aşa „2FA pe host"
    # rămâne o graniţă reală — acele hosturi sunt accesibile doar dintr-un browser, de un om.
    # `require_user` întoarce un sqlite3.Row (fără `.get`), `require_scope` un dict — deci
    # verificăm TIPUL, nu doar cheia. Fără isinstance, orice acţiune pe un host cu 2FA dintr-un
    # browser crăpa cu AttributeError → 500. Prins de `stepup_test` în CI, nu în producţie.
    if isinstance(user, dict) and user.get("is_token"):
        raise ApiError(403, "host.needs2faNoToken", "the host requires 2FA — not reachable with an automation token")
    if security.stepup_window_ok(user["id"], host_id):
        return
    # Ramura de passkey se alegea după URL-ul public (`_webauthn_available` verifică doar că
    # rp_id e un domeniu, nu un IP) — NU după faptul că userul chiar are un passkey înrolat.
    # Cine marca un host „cere 2FA" fără să aibă passkey rămânea blocat afară definitiv: orice
    # acţiune dădea 403, parola contului era refuzată, iar DEZACTIVAREA 2FA trece prin acelaşi
    # gard, deci nici înapoi nu se putea. Verificăm existenţa unei credenţiale.
    # Un grant passkey VALID e acceptat întotdeauna — e cel mai tare factor pe care îl avem.
    if grant and security.consume_stepup_grant(grant, user["id"], host_id):
        security.open_stepup_window(user["id"], host_id)
        return
    # Cerem passkey doar dacă omul CHIAR are unul. Ramura se alegea după URL-ul public
    # (`_webauthn_available` verifică doar că rp_id e un domeniu, nu un IP), nu după credenţialele
    # userului: cine marca un host „cere 2FA" fără passkey rămânea blocat afară definitiv — orice
    # acţiune dădea 403, parola era refuzată, iar DEZACTIVAREA trece prin acelaşi gard.
    has_passkey = await db.fetchone(
        "SELECT 1 FROM webauthn_credentials WHERE user_id=? LIMIT 1", user["id"])
    if _webauthn_available() and has_passkey:
        raise ApiError(403, "stepup.passkey", "2FA verification (passkey) required")
    if password and await _verify_reauth_password(user, password):
        security.open_stepup_window(user["id"], host_id)
        return
    raise ApiError(403, "stepup.password", "re-enter your account password (2FA)")


@router.post("/api/hosts/{host_id}/stepup")
async def host_stepup(host_id: int, body: SessionIn, user=Depends(security.require_user)):
    """Deschide fereastra de step-up pe un host cu 2FA (din passkey grant sau parolă), ca
    frontend-ul să deblocheze file-browser-ul / fleet-run înainte de acțiuni. Idempotent."""
    await _require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password)
    return {"ok": True, "window": security.STEPUP_WINDOW}


@router.post("/api/hosts/{host_id}/sessions")
async def create_session(host_id: int, body: SessionIn, request: Request,
                         user=Depends(security.require_user)):
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise HTTPException(404)
    # 2FA step-up (server-side; bifa din client nu e de încredere) — deschide/consultă fereastra
    await _require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password)
    ctype = row["connection_type"] or "agent"
    if ctype == "ssh":
        await _connect_direct(row, request, body.credential, body.passphrase)
    elif ctype == "telnet":
        await _connect_telnet(row, request, body.credential)
    title = body.title.strip()
    if not title:
        # unique default title per host: "Session N". The timestamp this replaced
        # ("Session 10 Jul 17:17") produced identical titles, impossible to
        # tell apart in tabs, the palette and the dashboard.
        existing = await db.fetchall("SELECT title FROM sessions WHERE host_id=?", host_id)
        top = 0
        for r in existing:
            m = re.fullmatch(r"(?:Session|Sesiune) (\d+)", r["title"] or "")
            if m:
                top = max(top, int(m.group(1)))
        title = f"Session {top + 1}"
    try:
        result = await core.create_session(host_id, title, body.rows, body.cols, body.tz)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")
    except core.SessionLimitReached:
        raise HTTPException(409, f"the host reached its limit of {core.MAX_SESSIONS_HINT} sessions — close one first")
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    return result


@router.patch("/api/sessions/{sid}")
async def update_session(sid: str, patch: SessionPatch,
                         user=Depends(security.require_user)):
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    if not row:
        raise HTTPException(404)
    title = patch.title if patch.title is not None else row["title"]
    note = patch.note if patch.note is not None else row["note"]
    await db.execute("UPDATE sessions SET title=?, note=? WHERE id=?",
                     title.strip(), note, sid)
    return {"ok": True}


@router.post("/api/sessions/{sid}/reconnect")
async def reconnect_session(sid: str, user=Depends(security.require_user)):
    """Reconectează o sesiune telnet-bastion căzută: telnet nou spre aceeași țintă,
    același tab/transcript. Doar pentru sesiuni telnet (nu shell/tmux — alea se
    re-adoptă singure la revenirea agentului)."""
    srow = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
    if srow:   # H1: telnet nou prin agentul host-ului = poartă ca la create_session
        await _require_host_stepup(srow["host_id"], user)
    try:
        return await core.reconnect_telnet_session(sid)
    except KeyError:
        raise HTTPException(404, "no such session, or not a telnet bastion")
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")
    except core.SessionLimitReached:
        raise ApiError(409, "telnet.limit", "the telnet session limit was reached — close one first")
    except RuntimeError as e:
        raise HTTPException(502, str(e))


@router.post("/api/sessions/{sid}/kill")
async def kill_session(sid: str, user=Depends(security.require_user)):
    srow = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
    if srow:   # H1: a termina o sesiune pe un host cu 2FA e o acţiune de host → cere step-up
        await _require_host_stepup(srow["host_id"], user)
    try:
        await core.kill_session(sid)
    except KeyError:
        raise HTTPException(404)
    except core.AgentGone:
        raise HTTPException(409, "the host is offline; the session cannot be closed right now")
    return {"ok": True}


@router.delete("/api/sessions/{sid}")
async def delete_session(sid: str, user=Depends(security.require_user)):
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    if not row:
        raise HTTPException(404)
    if row["state"] in ("creating", "live"):
        raise HTTPException(409, "the session is live; close it first")
    await db.execute("DELETE FROM sessions WHERE id=?", sid)
    # nu ștergem transcriptul pe loc: îl arhivăm (recuperabil ~120 zile), apoi
    # janitor-ul îl curăță definitiv după retenție
    core.archive_transcript(sid)
    return {"ok": True}


class ShareIn(BaseModel):
    writable: bool = False
    expires_minutes: int = 1440   # 24h implicit
    stepup_grant: str = ""        # 2FA: pe host cu require_2fa, crearea share-ului cere step-up (H1)
    stepup_password: str = ""


@router.post("/api/sessions/{sid}/share")
async def create_share(sid: str, request: Request, body: ShareIn = ShareIn(),
                       user=Depends(security.require_user)):
    """Link public, temporizat, către o sesiune. `writable` lasă vizitatorul să și
    TASTEZE (lărgește suprafața de încredere — opt-in per share); altfel doar vizualizare."""
    audit.detail(request, "writable" if body.writable else "read-only")
    row = await db.fetchone("SELECT id, host_id FROM sessions WHERE id=?", sid)
    if not row:
        raise HTTPException(404)
    # H1: un share (mai ales writable) e o cale de acces DURABILĂ, cookie-free, către terminalul
    # unui host — pe un host cu require_2fa e o acțiune sensibilă ca `run`/`kill`, deci cere step-up.
    # (Fără asta, un share writable ținea sesiunea trează — inputul invitatului resetează idle-lock-ul
    # — ocolind 2FA-ul care altfel s-ar re-cere.)
    await _require_host_stepup(row["host_id"], user, body.stepup_grant, body.stepup_password)
    mins = max(1, min(1440, int(body.expires_minutes)))   # 1 min … 24h
    expires = time.time() + mins * 60
    token = security.new_token()
    # token-ul de share e stocat HASH-uit (ca token-urile de sesiune) — o scurgere de backup
    # necriptat nu mai expune URL-uri de terminal live. URL-ul întors conține token-ul în clar.
    await db.execute(
        "UPDATE sessions SET share_token=?, share_expires=?, share_writable=?,"
        " share_by=?, share_by_id=?"
        " WHERE id=?",
        security.sha256_hex(token), expires, 1 if body.writable else 0,
        user["email"], user["id"], sid)
    return {"url": f"{config.PUBLIC_URL}/#/shared/{token}",
            "expires": expires, "writable": bool(body.writable)}


@router.delete("/api/sessions/{sid}/share")
async def revoke_share(sid: str, user=Depends(security.require_user)):
    await db.execute("UPDATE sessions SET share_token=NULL, share_expires=NULL WHERE id=?", sid)
    hub = core.hubs.get(sid)
    if hub:
        await hub.revoke_shares()   # închide invitaţii deja conectaţi (notificare + stop broadcast)
    return {"ok": True}


@router.get("/api/shared/{token}")
async def shared_meta(token: str):
    """Public: minimal session info for the read-only shared view."""
    row = await db.fetchone(
        "SELECT * FROM sessions WHERE share_token=? AND share_expires > ?",
        security.sha256_hex(token), time.time())
    if not row:
        raise ApiError(404, "link.invalid", "invalid or expired link")
    # watermark pe link-ul partajat = trasabilitatea celei mai riscante suprafețe
    # (sesiune vizibilă unui terț). Rezolvăm ${email}/${host} SERVER-SIDE, ca să nu
    # expunem emailul dacă template-ul nu-l folosește; ${time}/${date} le lasă clientul.
    wm = await _load_watermark()
    if wm.get("enabled"):
        # emailul celui care A CREAT share-ul (share_by); pentru share-uri de dinainte de
        # conturile multiple, revenim la primul cont — comportamentul de până acum
        owner_email = row["share_by"] if "share_by" in row.keys() and row["share_by"] else ""
        if not owner_email:
            first = await db.fetchone("SELECT email FROM users ORDER BY created LIMIT 1")
            owner_email = first["email"] if first else ""
        content = (wm["content"]
                   .replace("${email}", owner_email)
                   .replace("${host}", row["title"] or ""))
        wm = {**wm, "content": content}
    else:
        wm = {"enabled": False}
    return {"title": row["title"], "state": row["state"],
            "rows": row["rows"], "cols": row["cols"], "watermark": wm,
            "writable": bool(row["share_writable"])}


TEXT_VIEW_TAIL = 2 * 1024 * 1024       # cât citim pentru vizualizarea din UI (coada)


@router.get("/api/sessions/{sid}/transcript")
async def get_transcript(sid: str, format: str = "out", tail: bool = False,
                         user=Depends(security.require_user)):
    """`out` = fluxul brut, `cast` = asciicast (redare cu timing), `txt` = text citibil.
    `tail=true` (doar pentru txt) întoarce doar coada — vizualizarea din UI nu trage
    zeci de MB ca să arate ce s-a întâmplat ultima dată."""
    if not core.valid_sid(sid):
        raise HTTPException(404)
    await _require_session_host_stepup(sid, user)
    out_path, cast_path = core.transcript_paths(sid)
    if format == "txt":
        if not out_path.exists():
            raise HTTPException(404)
        text = await asyncio.to_thread(core.transcript_text, sid,
                                       TEXT_VIEW_TAIL if tail else 0)
        return Response(content=text, media_type="text/plain; charset=utf-8",
                        headers={} if tail else
                        {"Content-Disposition": 'attachment; filename="%s.txt"' % sid[:8]})
    path = cast_path if format == "cast" else out_path
    if not path.exists():
        raise HTTPException(404)
    return FileResponse(path, filename="%s.%s" % (sid[:8], format),
                        media_type="application/octet-stream")


@router.get("/api/sessions/{sid}/preview")
async def session_preview(sid: str, user=Depends(security.require_user)):
    """Coada recentă a transcriptului (pentru previzualizare read-only în UI),
    fără secvențele de alt-screen care ar goli ecranul."""
    if not await db.fetchone("SELECT id FROM sessions WHERE id=?", sid):
        raise HTTPException(404)
    await _require_session_host_stepup(sid, user)
    data = await asyncio.to_thread(core.read_tail, sid, limit=32 * 1024)
    return Response(content=data, media_type="application/octet-stream")


# ---------------------------------------------------------------------------
# Agent install (public: token-in-URL bootstrap)
# ---------------------------------------------------------------------------

INSTALL_SCRIPT = r"""#!/bin/sh
# WebTerm agent installer - generated for one host, expires 24h after issuing.
set -eu
GW="{public_url}"
WS_URL="{ws_url}/agent/ws"
TOKEN="{token}"
INSECURE={insecure}

# `curl` is missing on many minimal images (debian-slim, alpine without curl). Without this
# check the script died on the first download with "curl: not found" — a message that says
# neither what is missing nor that the rest of the install was fine. We fall back to `wget`,
# because images without curl often have it.
if command -v curl >/dev/null 2>&1; then
  CURL="curl -fsS"
  [ "$INSECURE" = "true" ] && CURL="curl -fsSk"
  FETCH_OUT="-o"
elif command -v wget >/dev/null 2>&1; then
  CURL="wget -q"
  [ "$INSECURE" = "true" ] && CURL="wget -q --no-check-certificate"
  FETCH_OUT="-O"
else
  echo "ERROR: neither curl nor wget is available on this server."
  echo "       Install one of them and run the command again:"
  echo "          apt install curl    (Debian/Ubuntu)"
  echo "          yum install curl    (RHEL/CentOS)"
  echo "          apk add curl        (Alpine)"
  exit 1
fi

command -v python3 >/dev/null 2>&1 || {{
  echo "ERROR: python3 is missing on this server."
  echo "       The agent is a single Python file with no dependencies — but it needs python3:"
  echo "          apt install python3 / yum install python3 / apk add python3"
  exit 1
}}

# The agent runs with the rights of whoever installs it: it never asks for root and never
# escalates. Installed as root, WebTerm becomes a root shell on this host — convenient, but a
# compromise of the gateway or of your account then owns the machine. Prefer a dedicated user
# (`useradd -m webterm && su - webterm`), with sudo only where you genuinely need it.
[ "$(id -u)" = 0 ] && echo "WARNING: you are installing the agent as ROOT — it will have root on this host. Prefer a dedicated user."
command -v tmux >/dev/null 2>&1 || echo "WARNING: tmux is missing — sessions will not survive an agent restart. Install it (apt install tmux / yum install tmux)."

mkdir -p "$HOME/.webterm" && chmod 700 "$HOME/.webterm"
$CURL "$GW/agent/ptyd.py" $FETCH_OUT "$HOME/.webterm/ptyd.py"
chmod 700 "$HOME/.webterm/ptyd.py"

# Octeţii aduşi trebuie să fie cei pe care gateway-ul i-a măsurat când a generat scriptul.
# Contează mai ales în modul insecure (`curl -k`), unde pin-ul de certificat se stabileşte
# abia la prima conectare, deci ACEASTĂ descărcare e neautentificată. Fără verificare,
# rulăm ce ne-a dat reţeaua.
AGENT_SHA256="{agent_sha256}"
if [ -n "$AGENT_SHA256" ]; then
  GOT=$(sha256sum "$HOME/.webterm/ptyd.py" 2>/dev/null | cut -d" " -f1)
  [ -n "$GOT" ] || GOT=$(shasum -a 256 "$HOME/.webterm/ptyd.py" 2>/dev/null | cut -d" " -f1)
  if [ -z "$GOT" ]; then
    echo "WARNING: no sha256sum/shasum on this host — the agent could not be verified."
  elif [ "$GOT" != "$AGENT_SHA256" ]; then
    rm -f "$HOME/.webterm/ptyd.py"
    echo "ERROR: the downloaded agent does not match the expected checksum." >&2
    echo "  expected $AGENT_SHA256" >&2
    echo "  got      $GOT" >&2
    echo "  Someone may be intercepting this download. Nothing was installed." >&2
    exit 1
  fi
fi

cat > "$HOME/.webterm/agent.json" <<EOF
{{"url": "$WS_URL", "token": "$TOKEN", "insecure": $INSECURE}}
EOF
chmod 600 "$HOME/.webterm/agent.json"

PY=$(command -v python3)
AGENT="$HOME/.webterm/ptyd.py"
"$PY" "$AGENT" stop >/dev/null 2>&1 || true

# Shell integration (OSC 133): commands become objects in the UI — searchable history, exit
# code, duration, the guardrail at Enter, and the file panel that follows `cd`. Without it
# WebTerm still works, but half the features stay empty, and the manual step is forgotten
# exactly when you need it.
# It TOUCHES ~/.bashrc / ~/.zshrc — which is why we say so explicitly, and why it can be refused:
#   WEBTERM_NO_SHELL_INTEGRATION=1 before the install command.
# sha256 computed by the gateway when it generated this script: the file is sourced in EVERY
# shell, so we do not write it to disk without checking its bytes.
if [ "${{WEBTERM_NO_SHELL_INTEGRATION:-0}}" = "1" ]; then
  echo "Shell integration: skipped (WEBTERM_NO_SHELL_INTEGRATION=1)."
elif "$PY" -c "import os,ssl,hashlib,urllib.request;\
d=urllib.request.urlopen('{public_url}/agent/shell-integration.sh',context={ssl_ctx},timeout=15).read();\
exit(1) if hashlib.sha256(d).hexdigest()!='{integration_sha256}' else None;\
dd=os.path.expanduser('~/.webterm');os.makedirs(dd,0o700,exist_ok=True);\
p=os.path.join(dd,'shell-integration.sh');\
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600);os.write(fd,d);os.close(fd)" 2>/dev/null; then
  for f in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$f" ] || [ "$f" = "$HOME/.bashrc" ] && touch "$f"
    if [ -f "$f" ] && ! grep -q 'webterm/shell-integration' "$f"; then
      printf '\n# WebTerm shell integration (OSC 133)\n[ -f ~/.webterm/shell-integration.sh ] && . ~/.webterm/shell-integration.sh\n' >> "$f"
      echo "Shell integration enabled in $f (remove the line to turn it off)."
    fi
  done
else
  echo "WARNING: shell integration was not installed (download or hash check failed) — you can enable it from the UI, inside a session."
fi

# Supervision: restart on kill AND on reboot. We prefer systemd --user
# (Restart=always), altfel cron @reboot + watchdog la fiecare minut.
SUP=""
if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/webterm-agent.service" <<UNIT
[Unit]
Description=WebTerm agent (ptyd)
After=network-online.target

[Service]
Type=simple
ExecStart=$PY $AGENT run
Restart=always
RestartSec=3
# Watchdog: if the agent's event loop blocks and stops sending WATCHDOG=1 within this
# interval, systemd kills and restarts it (complementary to the G1 liveness check over
# cron, which does not run under systemd). The agent pings at about half the interval.
WatchdogSec=45

[Install]
WantedBy=default.target
UNIT
  # clean up the old cron entry so we do not end up with two mechanisms
  # `if`, nu pipe necondiţionat: când `crontab -l` eşuează, pipe-ul e gol şi `crontab -`
  # scrie înapoi un crontab GOL — adică ştergem tot ce avea omul acolo, ca să curăţăm
  # două rânduri de-ale noastre. Scriem înapoi doar dacă chiar am putut citi.
  if command -v crontab >/dev/null 2>&1 && CUR=$(crontab -l 2>/dev/null); then
    printf '%s\n' "$CUR" | grep -v 'webterm/ptyd.py' | grep -v 'webterm-watchdog' | crontab - 2>/dev/null || true
  fi
  systemctl --user daemon-reload
  if systemctl --user enable --now webterm-agent.service >/dev/null 2>&1; then
    SUP="systemd"
    if ! loginctl enable-linger "$(id -un)" >/dev/null 2>&1; then
      echo "NOTE: so the agent starts after a reboot even with nobody logged in, run once: sudo loginctl enable-linger $(id -un)"
    fi
  fi
fi

if [ -z "$SUP" ] && command -v crontab >/dev/null 2>&1; then
  # @reboot starts it at boot; the watchdog restarts it if the process dies
  ( crontab -l 2>/dev/null | grep -v 'webterm/ptyd.py' | grep -v 'webterm-watchdog' ; \
    echo "@reboot $PY $AGENT start # webterm" ; \
    echo "* * * * * $PY $AGENT start # webterm-watchdog" ) | crontab - && SUP="cron"
  "$PY" "$AGENT" start
fi

if [ -z "$SUP" ]; then
  echo "WARNING: neither systemd --user nor crontab is available — the agent will NOT restart by itself."
  echo "         Start it by hand when needed: $PY $AGENT start"
  "$PY" "$AGENT" start
fi

sleep 1
if "$PY" "$AGENT" status >/dev/null 2>&1; then
  echo ""
  echo "────────────────────────────────────────────────────────"
  echo " ✓ The WebTerm agent is running. The host appears online within seconds."
  echo "────────────────────────────────────────────────────────"
  echo " User:          $(id -un)   (the shell sessions run as)"
  echo " Agent:         $AGENT"
  echo " Config:        $HOME/.webterm/agent.json"
  echo " Log:           $HOME/.webterm/ptyd.log"
  if [ -n "$SUP" ]; then
    echo " Supervision:   $SUP (restarts on kill and on reboot)"
  else
    echo " Supervision:   manual (no automatic restart — see the warning above)"
  fi
  # Userul dedicat NU poate sudo — asta e chiar rostul lui, dar e şi prima surpriză:
  # instalezi, dai `sudo apt install`, primeşti „Sorry, try again" şi n-ai de unde şti că e
  # intenţionat. Nu generăm o parolă ca s-o evităm (ar face contul loginabil prin SSH pe orice
  # instalare, şi tot n-ar da sudo fără o schimbare de grup). Spunem, exact unde te loveşti.
  if [ "$(id -u)" != 0 ] && ! sudo -n true >/dev/null 2>&1; then
    echo ""
    echo " NOTE: this user has no sudo — by design. Sessions open a shell as $(id -un),"
    echo "       so installing packages or editing root-owned files will fail until you"
    echo "       grant it. From a ROOT shell on this host:"
    echo ""
    echo "         passwd $(id -un) && usermod -aG sudo $(id -un)   # then reopen the tab"
    echo ""
    echo "       Narrower options, and what each one costs:"
    echo "       {public_url_docs}"
  fi
  echo ""
  echo " Full details any time:  $PY $AGENT info"
  echo " Files uploaded from the UI are saved into the directory currently open"
  echo " in the Files panel (navigate or type the path you want before uploading)."
  echo "────────────────────────────────────────────────────────"
else
  echo "ERROR: the agent did not start; see $HOME/.webterm/ptyd.log"
  exit 1
fi
"""


@router.get("/install/{enroll_token}", response_class=PlainTextResponse)
async def install_script(enroll_token: str):
    enroll_token = enroll_token[:-3] if enroll_token.endswith(".sh") else enroll_token
    # single-use, atomically: claim + invalidate the token in ONE serialized
    # write so two concurrent requests can't both be handed the permanent host
    # token (TOCTOU). Only the winner gets the row back.
    row = await db.execute_returning(
        "UPDATE hosts SET enroll_token=NULL, enroll_expires=0 "
        "WHERE enroll_token=? AND enroll_expires>? RETURNING *",
        enroll_token, time.time())
    if not row:
        raise ApiError(404, "enroll.invalid", "invalid or expired enroll token")
    token = security.decrypt_secret(row["token_encrypted"])
    return INSTALL_SCRIPT.format(
        public_url=config.PUBLIC_URL, ws_url=config.ws_public_url(),
        token=token, insecure="true" if config.AGENT_INSECURE else "false",
        public_url_docs="https://github.com/sm26449/webterm#provisioning-a-server",
        integration_sha256=_shell_integration_digest(),
        agent_sha256=_agent_digest(),
        ssl_ctx="ssl._create_unverified_context()" if config.AGENT_INSECURE else "None")


@router.post("/agent/uninstalled")
async def agent_uninstalled(request: Request):
    """Agentul declară că a fost scos de pe host (`ptyd.py uninstall`).

    NU ştergem hostul. Ştergerea duce cu ea numele, forward-urile şi legătura sesiunilor —
    şi, mai important, ar pune o acţiune distructivă din UI la îndemâna oricui are shell pe
    maşina aia: hostul ar dispărea din tabloul operatorului fără ca el să decidă. Marcăm
    hostul, iar interfaţa cere confirmarea. Agentul spune ce s-a întâmplat; ce facem cu
    evidenţa rămâne o decizie autentificată.

    Dacă agentul e reinstalat, marcajul se şterge singur la următoarea conectare."""
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    row = await db.fetchone("SELECT id, name, uninstalled_at FROM hosts WHERE token_hash=?",
                            security.sha256_hex(token)) if token else None
    if not row:
        raise HTTPException(401, "invalid agent token")
    if row["uninstalled_at"]:
        # deja marcat: POST-urile repetate (retry-ul agentului, sau spam cu tokenul citit
        # de pe host) nu mai scriu NIMIC — nici timestamp (păstrat pentru curăţarea pe
        # heartbeat din core), nici agent_events/audit (altfel un shell pe host umplea
        # ambele tabele nelimitat, o găleată de scris fără nicio frână).
        return {"ok": True, "host_kept": True}
    await db.execute("UPDATE hosts SET uninstalled_at=? WHERE id=?", time.time(), row["id"])
    await core.record_agent_event(row["id"], "uninstalled",
                                  detail="removed on the host with `ptyd.py uninstall`")
    await audit.record(time.time(), "agent:" + row["name"], security.client_ip(request),
                       "POST", "/agent/uninstalled", 200,
                       "agent removed itself on the host; awaiting confirmation in the UI")
    log.warning("agent uninstalled itself on host=%s(%s) — the host is kept until confirmed",
                row["name"], row["id"])
    return {"ok": True, "host_kept": True}


@router.get("/agent/ptyd.py", response_class=PlainTextResponse)
async def agent_source():
    if not config.AGENT_FILE.exists():
        raise HTTPException(500, "agent file missing on gateway")
    # cu o cheie de deployment, agentul primește sursa cu UPDATE_PUBKEY-ul acestui deployment
    # (TOFU peste TLS); fără cheie → sursa brută (canalul oficial). Vezi core.agent_install_source.
    try:
        return core.agent_install_source()
    except Exception as e:
        raise HTTPException(500, "agent source signing failed: %s" % e)


def _agent_digest() -> str:
    """sha256 al `ptyd.py` LIVRAT. Scriptul de instalare îl verifică după descărcare.

    F-11 din auditul extern: în modul insecure, primul `curl -k` aduce codul care devine
    agentul — adică, de regulă, un proces cu drepturile userului care instalează — iar
    pin-ul de certificat se stabileşte abia DUPĂ. Cine interceptează exact acea descărcare
    livrează propriul agent. Semnătura Ed25519 nu ajută aici: ea păzeşte canalul de UPDATE,
    nu prima aducere, iar agentul care ar verifica-o e chiar cel descărcat.

    Digest-ul nu rezolvă complet problema — vine pe aceeaşi conexiune — dar mută atacul de la
    „interceptez o descărcare" la „interceptez descărcarea ŞI scriptul care o verifică", şi
    dă operatorului o valoare pe care o poate compara din altă parte.
    Mecanismul e acelaşi cu cel deja folosit pentru `shell-integration.sh`.

    ATENŢIE la ce se măsoară: `/agent/ptyd.py` NU serveşte fişierul de pe disc. Cu o cheie de
    flotă — pe care gateway-ul şi-o generează singur la prima pornire, deci cazul OBIŞNUIT —
    `agent_install_source()` substituie `UPDATE_PUBKEY` cu cheia acelui deployment. Un digest
    calculat pe fişierul din repo n-ar corespunde niciodată octeţilor livraţi, iar verificarea
    ar respinge FIECARE instalare. Măsurăm exact ce iese pe endpoint."""
    try:
        return hashlib.sha256(core.agent_install_source().encode()).hexdigest()
    except Exception:                       # noqa: BLE001 — fără digest, scriptul sare verificarea
        return ""


def _shell_integration_digest() -> str:
    """sha256 al scriptului de integrare, calculat AICI şi transportat prin canale de
    încredere (răspuns API autentificat / scriptul de instalare peste TLS). Destinatarul
    verifică octeţii descărcaţi faţă de el — scriptul se sursează în fiecare shell, deci
    un MITM care l-ar substitui ar rula cod la fiecare prompt."""
    path = config.AGENT_FILE.parent / "shell-integration.sh"
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise HTTPException(500, "shell-integration.sh is missing on the gateway")


@router.get("/agent/shell-integration.sh", response_class=PlainTextResponse)
async def shell_integration_source():
    """Scriptul de integrare shell (OSC 133). Public, ca și sursa agentului:
    host-ul îl descarcă cu curl din sesiune (nu are cookie-ul browserului), iar
    conținutul nu e secret — doar marcaje de prompt, fără date."""
    path = config.AGENT_FILE.parent / "shell-integration.sh"
    if not path.exists():
        raise HTTPException(500, "shell-integration.sh is missing on the gateway")
    return path.read_text()


@router.get("/api/shell-integration/command")
async def shell_integration_command(user=Depends(security.require_user)):
    """Comanda pe care o rulăm ÎN sesiune ca să activăm integrarea: descarcă
    scriptul în ~/.webterm/ și îl sursează din rc-ul shell-ului. Transparentă
    (o vezi tastată în terminal) și reversibilă — ștergi linia din ~/.bashrc."""
    url = f"{config.PUBLIC_URL}/agent/shell-integration.sh"
    # sha256 al scriptului, calculat AICI și trimis prin canalul autentificat+TLS
    # al browserului. Fetch-ul (care pe AGENT_INSECURE nu verifică TLS) validează
    # bytes-ii descărcați față de acest hash → un MITM nu poate substitui scriptul
    # care se sursează în fiecare shell. Închide gap-ul fără cheie de semnare.
    digest = _shell_integration_digest()
    # Descărcarea se face cu python3, nu cu curl: python3 e singura dependență
    # pe care agentul o cere oricum, iar curl lipsește pe destule imagini.
    # Scrierea: os.open cu 0o600 (dir 0o700) — fișierul e sursat în fiecare shell,
    # deci nu trebuie să fie group/world-writable indiferent de umask.
    ctx = ("ssl._create_unverified_context()" if config.AGENT_INSECURE else "None")
    fetch = (
        "python3 -c \"import os,ssl,hashlib,urllib.request;"
        f"d=urllib.request.urlopen('{url}',context={ctx},timeout=15).read();"
        f"h=hashlib.sha256(d).hexdigest();"
        f"exit(1) if h!='{digest}' else None;"
        "dd=os.path.expanduser('~/.webterm');os.makedirs(dd,0o700,exist_ok=True);"
        "p=os.path.join(dd,'shell-integration.sh');"
        "fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600);"
        "os.write(fd,d);os.close(fd)\""
    )
    # idempotent: re-rularea nu dublează linia din rc
    rc = (
        "for f in ~/.bashrc ~/.zshrc; do "
        "[ -f \"$f\" ] || [ \"$f\" = \"$HOME/.bashrc\" ] && touch \"$f\"; "
        "[ -f \"$f\" ] && ! grep -q 'webterm/shell-integration' \"$f\" && "
        "printf '\\n# WebTerm shell integration (OSC 133)\\n"
        "[ -f ~/.webterm/shell-integration.sh ] && . ~/.webterm/shell-integration.sh\\n' >> \"$f\"; "
        "done"
    )
    cmd = f"{fetch} && {{ {rc}; }}; . ~/.webterm/shell-integration.sh && echo 'Shell integration enabled.'"
    return {"command": cmd}


# ---------------------------------------------------------------------------
# Agent websocket
# ---------------------------------------------------------------------------

@router.websocket("/agent/ws")
async def agent_ws(ws: WebSocket):
    auth = ws.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    row = await db.fetchone("SELECT * FROM hosts WHERE token_hash=?",
                            security.sha256_hex(token)) if token else None
    if not row:
        await ws.close(code=4401)
        return
    # Dacă hostul era marcat „dezinstalat" şi agentul se conectează din nou, înseamnă că a
    # fost reinstalat: marcajul dispare singur, fără ca cineva să apese ceva.
    if row["uninstalled_at"]:
        await db.execute("UPDATE hosts SET uninstalled_at=NULL WHERE id=?", row["id"])
    # anti-clone: bind the token to a single machine. Pin the reported instance
    # id on first connect; a different machine on the same token is refused
    # (4409) instead of swapping the source — otherwise a cloned VM image with
    # the agent baked in makes the gateway flap and can route keystrokes to the
    # wrong host. Once a host is pinned, the connection MUST present the matching
    # instance — including agents that omit the header — so a stolen token can't
    # dodge the fence by simply dropping it. Legitimate re-provisioning clears
    # the pin via the enroll flow (instance_id=NULL). Hosts that never saw a
    # modern (header-sending) agent stay unpinned and keep working.
    instance = ws.headers.get("x-webterm-instance", "")
    pinned = row["instance_id"]
    if pinned and instance != pinned:
        log.warning("host %s(%s): refusing agent — instance %s (pinned %s). "
                    "Cloned image, shared token, or dropped fence header?",
                    row["name"], row["id"],
                    (instance or "<none>")[:8], pinned[:8])
        await core.record_agent_event(row["id"], "disconnect", reason="instance_refused",
                                      detail="instance %s does not match the pinned one (cloned image / shared token?)"
                                             % (instance or "<none>")[:8])
        email_alerts.notify_agent_relocation(row["name"], (instance or "<none>")[:8])
        await ws.close(code=4409)
        return
    if instance and not pinned:
        # Fixare ATOMICĂ: `WHERE instance_id IS NULL` + re-citire. Fără condiţie, două clone
        # care se conectează în acelaşi moment vedeau amândouă „nefixat", amândouă erau
        # acceptate, iar `register_agent` intra în supersede/flap — adică taste rutate spre
        # maşina greşită până se stabiliza conflictul. Fereastra e îngustă, dar exact aici
        # apare: provisioning automat dintr-o imagine clonată. Semnalat de un audit extern.
        await db.execute("UPDATE hosts SET instance_id=? WHERE id=? AND instance_id IS NULL",
                         instance, row["id"])
        won = await db.fetchone("SELECT instance_id FROM hosts WHERE id=?", row["id"])
        if won and won["instance_id"] and won["instance_id"] != instance:
            log.warning("host %s(%s): another instance pinned the host between the check and the write "
                        "(%s ≠ %s) — refuz", row["id"], row["name"],
                        instance[:8], won["instance_id"][:8])
            await core.record_agent_event(row["id"], "disconnect", reason="instance_refused",
                                          detail="pinning race: another instance won")
            email_alerts.notify_agent_relocation(row["name"], instance[:8])
            await ws.close(code=4409)
            return
    # observabilitate IP: unde e văzut agentul (IP sursă prin proxy). IP-urile se schimbă legitim
    # (DHCP/reboot/NAT) → informativ, NU enforcement; jurnalizăm + alertăm DOAR la schimbare.
    ip = security.client_ip_ws(ws)
    if ip and ip != "?" and ip != row["agent_ip"]:
        if row["agent_ip"]:                 # nu la primul connect, doar la o schimbare reală
            await core.record_agent_event(row["id"], "ip_change", reason="ip_nou",
                                          detail="%s → %s" % (row["agent_ip"], ip))
            # Email DOAR pe host nepinned. Pe un host PINNED, fence-ul a garantat că e ACEEAŞI
            # maşină (alta ar fi fost refuzată), deci o schimbare de IP e doar rută de reţea —
            # dual-WAN, DHCP — nu o relocare. Pe un server cu 2 WAN-uri, IP-ul pâlpâie între
            # aceleaşi două adrese; fără garda asta primeai un email „IP nou" în fiecare oră,
            # deşi nu s-a mutat nimic. Evenimentul rămâne în jurnal pentru audit. (Consecvent
            # cu suprimarea alarmei de conflict pe hosturi pinned.)
            if not row["instance_id"]:
                email_alerts.notify_agent_ip_change(row["name"], row["agent_ip"], ip)
        await db.execute("UPDATE hosts SET agent_ip=? WHERE id=?", ip, row["id"])
    await ws.accept()
    # `pinned` = fence-ul anti-clonă e activ (instance_id fixat). Un supersede pe un host pinned
    # e garantat aceeaşi mașină (alta ar fi fost refuzată mai sus) → dual-WAN, nu token partajat.
    conn = await core.register_agent(ws, row["id"], pinned=bool(row["instance_id"]))
    log.info("agent connected: host=%s(%s)", row["name"], row["id"])
    try:
        await conn.run()
    except WebSocketDisconnect:
        pass
    except Exception as e:
        conn._stop_reason = conn._stop_reason or "ws_error"
        log.warning("agent ws error host=%s: %s", row["id"], e)
    finally:
        reason = conn._stop_reason or "closed"
        await core.record_agent_event(row["id"], "disconnect", reason=reason,
                                      detail=("v%s" % conn.agent_version) if conn.agent_version else "")
        log.info("agent disconnected: host=%s reason=%s", row["id"], reason)


# ---------------------------------------------------------------------------
# Browser terminal websocket
# ---------------------------------------------------------------------------

def _origin_ok(ws: WebSocket) -> bool:
    """Block Cross-Site WebSocket Hijacking: the browser sends the cookie on a
    WS handshake even from a hostile page, so we require the Origin to be our
    own public origin. (SameSite=Lax does not reliably cover WS upgrades.)"""
    from urllib.parse import urlparse
    origin = ws.headers.get("origin")
    if origin is None:
        return False          # real browsers always send Origin for WS
    return urlparse(origin).netloc == urlparse(config.PUBLIC_URL).netloc


@router.websocket("/ws/shared/{token}")
async def shared_ws(ws: WebSocket, token: str):
    """Vizitator prin link de share. `share_writable` → poate și TASTA (opt-in la
    creare); altfel doar vizualizare. Nu are cont — identitate „guest" în roster."""
    if not _origin_ok(ws):
        await ws.close(code=4403)
        return
    row = await db.fetchone(
        "SELECT * FROM sessions WHERE share_token=? AND share_expires > ?",
        security.sha256_hex(token), time.time())
    if not row:
        await ws.close(code=4404)
        return
    await ws.accept()
    writable = bool(row["share_writable"])
    live = row["state"] in ("creating", "live")
    hub = core.get_or_create_hub(row) if live else None
    client = core.BrowserClient(ws, hub) if hub else None
    if client:
        client.id = "g_" + security.new_token()[:10]
        client.is_owner = False
        client.writable = writable
        client.label = "guest"          # identificator, nu text: clientul îl traduce
        client.remote_addr = security.client_ip(ws)
        client.user_agent = ws.headers.get("user-agent", "")
        client.attached_at = time.time()
        # Un invitat nu e niciodată „dispozitivul tău": link-ul a fost dat deliberat, dar
        # MOMENTUL în care cineva îl foloseşte e exact ce vrei să afli. Deci mereu necunoscut.
        client.known = False
    await ws.send_text(json.dumps({"type": "init", "state": row["state"],
                                   "title": row["title"], "readonly": not writable,
                                   "writable": writable,
                                   # dimensiunea PTY-ului: invitatul oglindeşte EXACT grila owner-ului
                                   # (altfel fit()-ul la containerul lui împachetează output-ul greşit)
                                   "rows": row["rows"] or 24, "cols": row["cols"] or 80}))
    # Invitatul prin share NU poate face step-up — n-are cont, are doar tokenul din URL. Deci
    # pe un host cu 2FA regula lui e: vede sesiunea DOAR cât timp owner-ul verificat e ataşat.
    # Aici era aceeaşi gaură ca în `browser_ws`: decizia se lua din `hub.last_interaction`, pe
    # care fiecare `SessionHub` nou îl pune la `time.time()`, deci după orice repornire de
    # gateway un link de share pe un host 2FA livra scrollback-ul (şi accepta input, dacă era
    # writable) fără nimic în cale. Suprafaţa e mai rea decât la browser_ws: nu e nevoie nici
    # măcar de un cookie furat, doar de URL.
    # Decis ÎNAINTE de replay: dacă e blocată, nu scurgem scrollback-ul (read_tail).
    start_locked = False
    if hub:
        hrow2 = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", row["host_id"])
        if hrow2 and hrow2["require_2fa"]:
            hub.lock_idle = config.IDLE_LOCK_SECS
            owner_present = any(getattr(c, "is_owner", False) for c in hub.clients)
            start_locked = hub.locked or not owner_present
    if not start_locked:
        await ws.send_bytes(await asyncio.to_thread(core.read_tail, row["id"]))
    if hub:
        hub.clients.add(client)
        client.sender_task = asyncio.create_task(client.sender())
        conn = core.sources.get(row["host_id"])
        if conn:
            await hub.ensure_attached(conn)
        if not start_locked:
            # tail-ul redă doar diff-urile transmise; părțile statice ale unui TUI pot
            # lipsi din fereastră → repaint complet, ca la resume (vezi request_redraw)
            hub.request_redraw()
        await hub.broadcast_roster()
        await hub.announce_attach(client)
        # Un invitat cu drept de scriere putea tasta într-un terminal fără să lase o urmă
        # ATRIBUIBILĂ: jurnalul arăta „cineva prin share". Nu are cont, deci nu-l putem numi
        # — dar îi putem da identitatea pe care o are: id-ul clientului (acelaşi din roster,
        # deci acelaşi pe care apare butonul de kick), adresa şi browserul. Suficient ca
        # „cine a rulat asta" să aibă un răspuns când share-ul a fost dat la trei oameni.
        await audit.record(time.time(), "guest:" + client.id, client.remote_addr,
                           "WS", "/ws/shared", 101,
                           "share attach sid=%s writable=%s agent=%s"
                           % (row["id"], writable, client.user_agent[:60]))
        email_alerts.notify_session_attach(
            row["title"], client.remote_addr, client.user_agent, row["share_by"] or "")
        if start_locked:
            # invitatul NU poate debloca (n-are passkey) — doar aşteaptă re-auth-ul owner-ului.
            # Nu forţăm hub.lock() dintr-un invitat; sweep-ul de idle blochează hub-ul la nivel global.
            client.lock()
            await client.send_text(json.dumps({"type": "locked"}))

    # revalidare periodică: linkul de share poate fi REVOCAT sau poate EXPIRA cât invitatul e
    # conectat. Fără asta, socketul deschis (validat doar la handshake) continuă broadcast-ul.
    # (Revocarea activă via hub.revoke_shares() e instant; asta e plasa de siguranţă + expirarea.)
    async def _revalidate_share():
        while True:
            await asyncio.sleep(WS_REVALIDATE_SECS)
            r = await db.fetchone(
                "SELECT 1 FROM sessions WHERE share_token=? AND share_expires > ?",
                security.sha256_hex(token), time.time())
            if not r:
                try:
                    if client:
                        await client.send_text(json.dumps({"type": "revoked"}))
                    else:
                        await ws.send_text(json.dumps({"type": "revoked"}))
                    await ws.close(code=4403)
                except Exception:                # noqa: BLE001
                    pass
                return

    reval_task = asyncio.create_task(_revalidate_share())
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            # writable: input-ul vizitatorului merge la PTY (dimensiunea rămâne a
            # owner-ului — vizitatorul nu poate redimensiona). read-only: doar pong.
            if writable and msg.get("bytes") is not None and hub and client:
                await hub.handle_input(client, msg["bytes"])
            elif msg.get("text") and hub and client:
                try:
                    if json.loads(msg["text"]).get("type") == "pong":
                        client.on_pong(json.loads(msg["text"]).get("n", 0))
                except ValueError:
                    pass
    except WebSocketDisconnect:
        pass
    finally:
        reval_task.cancel()
        if hub and client:
            hub.clients.discard(client)
            if client.sender_task:
                client.sender_task.cancel()
            await hub.broadcast_roster()


@router.websocket("/ws/sessions/{sid}")
async def browser_ws(ws: WebSocket, sid: str):
    if not _origin_ok(ws):
        await ws.close(code=4403)
        return
    # NOTĂ despre codurile de închidere de mai jos (4401/4403/4404): `ws.close()` apelat
    # ÎNAINTE de `ws.accept()` face Starlette să respingă handshake-ul cu HTTP 403, iar codul
    # nostru nu ajunge niciodată la client — toate trei se văd identic, ca 403. E acceptabil
    # (nu divulgă ce SID-uri există, iar frontend-ul nu se uită la ele), dar nu te baza pe
    # ele pentru diagnostic: ca să ajungă, ar trebui `accept()` întâi, ceea ce înseamnă să
    # accepți un socket neautentificat doar ca să-i spui de ce l-ai refuzat.
    user = await security.require_user_ws(ws)
    if not user:
        await ws.close(code=4401)
        return
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    if not row:
        await ws.close(code=4404)
        return
    await ws.accept()

    live = row["state"] in ("creating", "live")
    hub = core.get_or_create_hub(row) if live else None
    client = core.BrowserClient(ws, hub) if hub else None
    if client:
        client.id = "o_" + security.new_token()[:10]
        client.is_owner = True
        client.writable = True
        client.label = "self"           # idem
        client.remote_addr = security.client_ip(ws)
        client.user_agent = ws.headers.get("user-agent", "")
        client.attached_at = time.time()
        # „Cunoscut" = IP-ul a mai apărut la un login reuşit al ACESTUI cont. Deliberat un
        # semnal slab: decide doar dacă facem zgomot, niciodată dacă sărim o verificare.
        client.known = await security.ip_is_known(user["id"], client.remote_addr)

    await ws.send_text(json.dumps({
        "type": "init", "state": row["state"], "title": row["title"],
        "rows": row["rows"], "cols": row["cols"],
        "exit_status": row["exit_status"], "close_reason": row["close_reason"],
        "host_online": row["host_id"] in core.sources,
        "your_id": client.id if client else None,
    }))
    # ATAŞAREA la o sesiune de pe un host cu 2FA cere step-up — fail-closed.
    # Aici era gaura prin care un cookie furat ajungea la un shell root: `browser_ws` cerea doar
    # autentificare (crearea unei sesiuni cerea step-up, ataşarea la una existentă nu), iar
    # singura apărare era idle-lock-ul. Acela se calcula din `hub.last_interaction`, pe care
    # fiecare `SessionHub` NOU îl pune la `time.time()`; după orice repornire de gateway —
    # adică după fiecare upgrade — dicţionarul de hub-uri e gol, deci prima ataşare la ORICE
    # sesiune 2FA pornea DEBLOCATĂ, oricât de veche era. Reprodus: idle 4000s → blocată;
    # `hubs.clear()` → aceeaşi sesiune, deblocată, `last_interaction` la 0s.
    # Acum: fără fereastră de step-up deschisă, ataşarea începe blocată. Crearea sesiunii şi
    # deblocarea deschid fereastra, deci nu apare dublu-prompt în fluxul normal.
    # DECIS ÎNAINTE de replay-ul scrollback-ului: altfel o sesiune 2FA blocată își scurgea
    # buffer-ul (read_tail) la conectare, chiar înainte de a afișa overlay-ul de blocare.
    start_locked = False
    if hub:
        hrow2 = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", row["host_id"])
        if hrow2 and hrow2["require_2fa"]:
            hub.lock_idle = config.IDLE_LOCK_SECS      # 0 = fără idle-lock ÎN sesiune
            start_locked = hub.locked or not security.stepup_window_ok(user["id"], row["host_id"])

    # closed sessions: replaying the alt-screen exit would blank the history.
    # Sesiune blocată → NU replaya scrollback-ul; la deblocare (passkey), hub.unlock() pune
    # un _RESYNC în coadă care-l retrimite din transcript. Astfel bufferul nu se scurge cât e blocat.
    if not start_locked:
        await ws.send_bytes(await asyncio.to_thread(core.read_tail, sid))

    if hub:
        hub.clients.add(client)
        client.sender_task = asyncio.create_task(client.sender())
        if not start_locked:
            # F5 / al doilea dispozitiv cu aceeași mărime: tail-ul redă doar diff-urile
            # transmise, deci chenarele statice ale unui TUI pot lipsi, iar resize-ul
            # dedupat (aceeași dimensiune) nu declanșează niciun repaint tmux. Cerem
            # explicit unul, ca la resume — altfel simptomul „linii lipsă până la A±"
            # rămânea exact pe calea cea mai comună: reload-ul de pagină.
            hub.request_redraw()
        await hub.broadcast_roster()             # cine e conectat (owner + invitați)
        # Cine era deja ataşat AFLĂ că ai venit; dacă locul e nou, pleacă şi un email — ca să
        # afli şi când nu te uitai. E singurul efect al lui `known`: volum de alertă.
        await hub.announce_attach(client)
        if not client.known:
            email_alerts.notify_session_attach(
                row["title"], client.remote_addr, client.user_agent, user["email"])
        if start_locked:
            if not hub.locked:
                await hub.lock()                 # idle → blochează toţi clienţii + broadcast
            else:
                client.lock()
                await client.send_text(json.dumps({"type": "locked"}))
        conn = core.sources.get(row["host_id"])
        # sesiune SSH live fără sursă = gateway repornit; re-dial cu creds stocate
        # și re-atașează tmux-ul remote (persistență peste restart)
        if conn is None:
            host = await db.fetchone("SELECT * FROM hosts WHERE id=?", row["host_id"])
            if host and host["connection_type"] == "ssh" and host["credential_encrypted"]:
                try:
                    cred = json.loads(security.decrypt_secret(host["credential_encrypted"]))
                    conn = await core.dial_ssh(host, cred)
                    await conn.create(sid, row["rows"], row["cols"], "xterm-256color")
                except Exception as e:
                    log.warning("re-dial ssh %s: %s", sid, e)
                    conn = None
        if conn:
            await hub.ensure_attached(conn)

    # revalidare periodică: WS-ul e autorizat DOAR la handshake. Fără asta, un terminal deschis
    # supravieţuieşte logout-ului/idle-expiry (tokenul e revocat server-side de destroy_web_session,
    # dar socketul rămâne şi acceptă input la nesfârşit). La invalidare → închide (4401).
    tok = ws.cookies.get(security.COOKIE_NAME)

    async def _revalidate():
        while True:
            await asyncio.sleep(WS_REVALIDATE_SECS)
            if not await security.session_valid(tok):
                try:
                    await ws.close(code=4401)
                except Exception:                    # noqa: BLE001
                    pass
                return

    reval_task = asyncio.create_task(_revalidate())
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            if msg.get("bytes") is not None and hub:
                await hub.handle_input(client, msg["bytes"])
            elif msg.get("text") and hub:
                try:
                    ctl = json.loads(msg["text"])
                except ValueError:
                    continue
                if ctl.get("type") == "pong":
                    client.on_pong(ctl.get("n", 0))
                elif ctl.get("type") == "unlock":
                    # Deblocare: aceeaşi regulă ca ORICE acţiune de host cu 2FA — grant passkey,
                    # sau parola contului acolo unde WebAuthn nu e disponibil.
                    # Se accepta DOAR grant de passkey, iar pe o instalare fără WebAuthn (IP gol,
                    # fără HTTPS → context nesigur, deci fără passkey) o sesiune blocată devenea
                    # IRECUPERABILĂ: nu exista nicio cale de deblocare. Cu ataşarea acum
                    # fail-closed, asta ar fi însemnat blocarea definitivă a oamenilor afară.
                    # `_require_host_stepup` conţine deja ambele ramuri şi deschide fereastra,
                    # deci ataşările următoare din fereastră nu mai cer nimic.
                    try:
                        await _require_host_stepup(row["host_id"], user, ctl.get("grant", ""),
                                                   ctl.get("password", ""))
                    except HTTPException:
                        await client.send_text(json.dumps({"type": "unlock_failed"}))
                    else:
                        await hub.unlock()
                elif ctl.get("type") == "kick":
                    # DOAR owner-ul (client autentificat) scoate un INVITAT (nu owner).
                    # Închide WS-ul țintei → bucla ei se termină + roster rebroadcast.
                    if client.is_owner:
                        tid = ctl.get("id", "")
                        for c in list(hub.clients):
                            if c.id == tid and not c.is_owner:
                                try:
                                    await c.ws.close(code=4408)
                                except Exception:
                                    pass
                                break
                elif ctl.get("type") == "pause":
                    # tab inactiv: nu mai trimite output live acestui client
                    client.pause()
                elif ctl.get("type") == "resume":
                    # tab redevenit vizibil: resync complet din transcript
                    client.resume()
                elif ctl.get("type") == "rtt":
                    # echo pentru măsurarea RTT în UI. Coerce n la întreg: fără
                    # asta, un client putea trimite un payload arbitrar (string
                    # de MB) și-l primea reflectat 1:1 — reflexie inutilă.
                    try:
                        n = int(ctl.get("n", 0))
                    except (TypeError, ValueError):
                        n = 0
                    await client.send_text(json.dumps({"type": "rtt", "n": n}))
                elif ctl.get("type") == "resize":
                    # last-writer-wins, but a viewer that hasn't interacted
                    # recently must not yank the size from the active device.
                    # EXCEPȚIE: un client care tocmai a devenit activ (focus/tab
                    # vizibil/click) trimite active=True și își poate RECLAMA
                    # dimensiunea oricând — altfel, după ce alt dispozitiv l-a
                    # micșorat, rămânea mic până la A−/A+ (bug raportat pe desktop).
                    others = len(hub.clients) > 1
                    idle = time.time() - client.last_interaction > 30
                    active = bool(ctl.get("active"))
                    if others and idle and not active:
                        continue
                    if active:
                        # activarea contează ca interacțiune, altfel următoarea
                        # reclamare (ex. un al doilea click) ar fi din nou respinsă
                        client.last_interaction = time.time()
                    await hub.resize(int(ctl["rows"]), int(ctl["cols"]))
    except WebSocketDisconnect:
        pass
    finally:
        reval_task.cancel()
        if hub and client:
            hub.clients.discard(client)
            if client.sender_task:
                client.sender_task.cancel()
            await hub.broadcast_roster()
