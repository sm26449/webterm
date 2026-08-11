"""Passkey (WebAuthn) registration and login."""

import base64
import json
import time
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from webauthn import (generate_authentication_options,
                      generate_registration_options, options_to_json,
                      verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
                                      PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)

from . import config, db, email_alerts, security
from .errors import ApiError

router = APIRouter(prefix="/api/webauthn")

# issued challenges (single-user tool: a small in-memory set is plenty)
_challenges = {}          # b64url(challenge) -> expiry epoch
CHALLENGE_TTL = 300


def _rp_id() -> str:
    return urlparse(config.PUBLIC_URL).hostname or "localhost"


CHALLENGE_MAX = 256          # bound memory: login/options is unauthenticated

# Cozi SEPARATE pentru cererile anonime şi cele autentificate. Plafonul era comun, iar evacuarea
# FIFO: 256 de apeluri pe `/login/options` (endpoint neautentificat, câteva zeci de ms) scoteau
# challenge-ul pe care utilizatorul tocmai îl primise şi nu-l atinsese încă cu cheia. Sub flood:
# login cu passkey imposibil, ÎNROLARE imposibilă şi step-up 2FA imposibil — adică hosturile
# marcate „cere 2FA" deveneau inaccesibile, cu mesajul „challenge necunoscut sau expirat;
# reîncearcă", care trimite omul într-o buclă. Plafonul apăra memoria şi deschidea o negare de
# serviciu; separarea păstrează prima proprietate fără a doua.
_challenges_anon: dict = {}


def _remember(challenge: bytes, anon: bool = False) -> None:
    store = _challenges_anon if anon else _challenges
    now = time.time()
    for key in [k for k, v in store.items() if v < now]:
        del store[key]
    # hard cap: drop the oldest if an attacker floods login/options
    while len(store) >= CHALLENGE_MAX:
        store.pop(next(iter(store)))
    store[base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()] = now + CHALLENGE_TTL


def _consume(credential: dict) -> bytes:
    """Validate the challenge inside the client response is one we issued."""
    try:
        client_data = json.loads(base64url_to_bytes(credential["response"]["clientDataJSON"]))
        challenge_b64 = client_data["challenge"]
    except (KeyError, ValueError):
        raise HTTPException(400, "malformed credential")
    expiry = _challenges.pop(challenge_b64, None)
    if expiry is None:
        expiry = _challenges_anon.pop(challenge_b64, None)
    if not expiry or expiry < time.time():
        raise HTTPException(400, "unknown or expired challenge; try again")
    return base64url_to_bytes(challenge_b64)


class CredentialBody(BaseModel):
    credential: dict
    name: str = ""
    password: str = ""      # M1: re-autentificare la înrolarea unui passkey nou
    totp_code: str = ""     # al doilea factor, când contul are TOTP activ
    email_code: str = ""    # alternativa, când n-are TOTP şi vine de pe un dispozitiv nou


@router.post("/register/options")
async def register_options(user=Depends(security.require_user)):
    existing = await db.fetchall(
        "SELECT credential_id FROM webauthn_credentials WHERE user_id=?", user["id"])
    options = generate_registration_options(
        rp_id=_rp_id(),
        rp_name="WebTerm",
        user_id=str(user["id"]).encode(),
        user_name=user["email"],
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=row["credential_id"]) for row in existing],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED),
    )
    _remember(options.challenge)
    return Response(options_to_json(options), media_type="application/json")


async def _verify_reauth(user, password: str) -> bool:
    """Re-autentificare cu parola în sesiune, PLAFONATĂ ca /api/login (cheie pe cont) — la fel ca
    `_verify_reauth_password` din api.py. FĂRĂ plafonare, un cookie furat ar avea un oracle de
    ghicire a parolei ne-throttled pe endpoint-urile de credențiale (enroll/delete passkey)."""
    key = "reauth:%d" % user["id"]
    allowed, retry = security.login_allowed(key)
    if not allowed:
        raise HTTPException(429, "too many attempts; retry in %ds" % retry,
                            headers={"Retry-After": str(retry)})
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    if await security.verify_password_async(password, user["password_hash"]):
        security.record_login_success(key)
        return True
    security.record_login_failure(key)
    return False


async def _second_gate(user, request: Request, body, what: str) -> None:
    """Al doilea factor peste parolă, pentru operaţiile care schimbă SETUL de passkey-uri.

    Parola singură nu mai ajunge: cine o are (reutilizată, scursă, ghicită) îşi putea înrola
    propriul passkey — adică îşi făcea o cheie permanentă, rezistentă la phishing, la contul
    tău — sau ţi-l putea şterge pe al tău. Amândouă sunt schimbări de credenţiale, nu setări.

    Cu TOTP activ cerem codul de pe telefon (sau un cod de recuperare, pe care `verify_second_factor`
    îl acceptă la fel). Fără TOTP, singurul canal separat rămas e emailul, şi îl cerem doar de pe
    un dispozitiv nestabilit — de pe maşina ta obişnuită parola rămâne suficientă, ca până acum.

    Nu acceptăm emailul CA ÎNLOCUITOR pentru TOTP: dacă ar merge şi aşa, 2FA-ul ar valora exact
    cât accesul la inbox, iar telefonul n-ar mai apăra nimic. Pentru telefonul pierdut există
    codurile de recuperare, iar dacă s-au pierdut şi ele, `python3 -m app.admin` de pe server —
    o poartă mult mai înaltă decât o cutie poştală."""
    if user["totp_enabled"]:
        if not body.totp_code:
            raise ApiError(403, "passkey.totpRequired",
                           "enter your 2FA code to %s" % what)
        # Contor SEPARAT, şi asta e miezul: `_verify_reauth` de mai sus apelează
        # `record_login_success` când parola e corectă, ceea ce ŞTERGE contorul de eşecuri.
        # Un atacator care deja are parola trimitea la nesfârşit (parolă bună + cod ghicit):
        # fiecare încercare îşi curăţa singură urma, deci codul din şase cifre se putea ghici
        # fără niciun lockout, limitat doar de costul argon2. Cheia asta n-o resetează nimeni
        # altcineva. Semnalat de un audit extern pe 2026-08-09, pe cod scris în aceeaşi zi.
        key = "passkey2fa:%d" % user["id"]
        allowed, retry = security.login_allowed(key)
        if not allowed:
            raise ApiError(429, "passkey.tooManyTotp",
                           "too many wrong 2FA codes; retry in %ds" % retry)
        await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
        if not await security.verify_second_factor(user, body.totp_code):
            # FĂRĂ portiţă „codul corect trece oricum în lockout", spre deosebire de calea cu
            # parola: acolo portiţa există ca atacatorul să nu poată închide contul proprietarului
            # cu parole greşite. Aici ar anula exact apărarea — ghicitorul are nevoie de o
            # singură nimereală, iar dacă aceea trece, plafonul n-a existat. Costul asumat: cine
            # îţi ştie deja parola îţi poate bloca 15 minute administrarea passkey-urilor.
            security.record_login_failure(key)
            raise ApiError(401, "passkey.badTotp", "wrong or already-used 2FA code")
        security.record_login_success(key)
        return
    if not await security.session_is_new_device(request):
        return
    if not await email_alerts.smtp_ready():
        return
    if not body.email_code:
        code = await security.issue_email_challenge(user["id"], "passkey")
        try:
            await email_alerts.send_account_code(user["email"], code, what)
        except Exception as e:                       # noqa: BLE001
            raise ApiError(503, "account.codeSendFailed",
                           "could not send the confirmation code by email: %s" % e)
        raise ApiError(403, "account.codeRequired",
                       "this device is new — enter the code we just emailed to %s"
                       % user["email"])
    if not await security.consume_email_challenge(user["id"], "passkey", body.email_code):
        raise ApiError(401, "account.badCode", "wrong or expired confirmation code")


@router.post("/register/verify")
async def register_verify(body: CredentialBody, request: Request,
                          user=Depends(security.require_user)):
    # M1: înrolarea unui passkey e o schimbare de credențiale — un cookie furat NU trebuie să poată
    # adăuga un factor persistent. Cerem re-autentificare cu parola contului (plafonată) + notificare.
    if not await _verify_reauth(user, body.password):
        raise HTTPException(401, "re-enter your account password to add a passkey")
    await _second_gate(user, request, body, "enrol a passkey on your WebTerm account")
    expected = _consume(body.credential)
    try:
        result = verify_registration_response(
            credential=body.credential,
            expected_challenge=expected,
            expected_rp_id=_rp_id(),
            expected_origin=config.PUBLIC_URL,
        )
    except Exception as e:
        raise HTTPException(400, "verification failed: %s" % e)
    await db.execute(
        "INSERT INTO webauthn_credentials(user_id, credential_id, public_key,"
        " sign_count, name, created) VALUES(?,?,?,?,?,?)",
        user["id"], result.credential_id, result.credential_public_key,
        result.sign_count, body.name[:60] or "passkey", time.time())
    email_alerts.notify_security_change(
        "new passkey enrolled", security.client_ip(request), user["email"])
    return {"ok": True}


@router.post("/login/options")
async def login_options():
    options = generate_authentication_options(
        rp_id=_rp_id(),
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    _remember(options.challenge, anon=True)   # endpoint neautentificat
    return Response(options_to_json(options), media_type="application/json")


@router.post("/login/verify")
async def login_verify(body: CredentialBody, request: Request, response: Response):
    ip = security.client_ip(request)
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        raise HTTPException(429, f"too many attempts; retry in {retry}s",
                            headers={"Retry-After": str(retry)})
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    expected = _consume(body.credential)
    cred_id = base64url_to_bytes(body.credential.get("rawId", ""))
    row = await db.fetchone(
        "SELECT * FROM webauthn_credentials WHERE credential_id=?", cred_id)
    if not row:
        security.record_login_failure(ip)
        raise HTTPException(401, "unknown passkey")
    try:
        result = verify_authentication_response(
            credential=body.credential,
            expected_challenge=expected,
            expected_rp_id=_rp_id(),
            expected_origin=config.PUBLIC_URL,
            credential_public_key=row["public_key"],
            credential_current_sign_count=row["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        security.record_login_failure(ip)
        raise HTTPException(401, "authentication failed: %s" % e)
    await db.execute("UPDATE webauthn_credentials SET sign_count=? WHERE id=?",
                     result.new_sign_count, row["id"])
    security.record_login_success(ip)
    user = await db.fetchone("SELECT * FROM users WHERE id=?", row["user_id"])
    new_device = False
    if user:
        new_device = await security.note_new_login(
            user, ip, request.headers.get("user-agent", ""))
    token = await security.create_web_session(
        row["user_id"], request.headers.get("user-agent", ""), new_device)
    security.set_session_cookie(response, token)
    return {"ok": True}


# ── Step-up: dovada unui passkey înainte de a conecta un host cu 2FA ──────────

class StepupOptions(BaseModel):
    host_id: int


class StepupVerify(BaseModel):
    host_id: int
    credential: dict


@router.post("/stepup/options")
async def stepup_options(body: StepupOptions, user=Depends(security.require_user)):
    """La fel ca login/options, dar autentificat și limitat la passkey-urile
    utilizatorului curent (nu e un login nou, ci o re-verificare)."""
    creds = await db.fetchall(
        "SELECT credential_id FROM webauthn_credentials WHERE user_id=?", user["id"])
    options = generate_authentication_options(
        rp_id=_rp_id(),
        user_verification=UserVerificationRequirement.REQUIRED,
        allow_credentials=[PublicKeyCredentialDescriptor(id=r["credential_id"])
                           for r in creds] or None,
    )
    _remember(options.challenge)
    return Response(options_to_json(options), media_type="application/json")


@router.post("/stepup/verify")
async def stepup_verify(body: StepupVerify, request: Request,
                        user=Depends(security.require_user)):
    ip = security.client_ip(request)
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        raise HTTPException(429, f"too many attempts; retry in {retry}s",
                            headers={"Retry-After": str(retry)})
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    expected = _consume(body.credential)
    cred_id = base64url_to_bytes(body.credential.get("rawId", ""))
    # legat de utilizatorul curent: un passkey al altcuiva nu deblochează nimic
    row = await db.fetchone(
        "SELECT * FROM webauthn_credentials WHERE credential_id=? AND user_id=?",
        cred_id, user["id"])
    if not row:
        security.record_login_failure(ip)
        raise HTTPException(401, "unknown passkey")
    try:
        result = verify_authentication_response(
            credential=body.credential,
            expected_challenge=expected,
            expected_rp_id=_rp_id(),
            expected_origin=config.PUBLIC_URL,
            credential_public_key=row["public_key"],
            credential_current_sign_count=row["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        security.record_login_failure(ip)
        raise HTTPException(401, "2FA verification failed: %s" % e)
    await db.execute("UPDATE webauthn_credentials SET sign_count=? WHERE id=?",
                     result.new_sign_count, row["id"])
    security.record_login_success(ip)
    return {"grant": security.issue_stepup_grant(user["id"], body.host_id)}


@router.get("/credentials")
async def list_credentials(user=Depends(security.require_user)):
    rows = await db.fetchall(
        "SELECT id, name, created FROM webauthn_credentials WHERE user_id=?", user["id"])
    return [{"id": r["id"], "name": r["name"], "created": r["created"]} for r in rows]


class CredDelete(BaseModel):
    password: str = ""
    totp_code: str = ""
    email_code: str = ""


@router.delete("/credentials/{cred_id}")
async def delete_credential(cred_id: int, body: CredDelete, request: Request,
                            user=Depends(security.require_user)):
    # M1: scoaterea unui factor rezistent la phishing e schimbare de credențiale — cere parola
    # (plafonată, ca un cookie furat să nu aibă un oracle de ghicire ne-throttled).
    if not await _verify_reauth(user, body.password):
        raise HTTPException(401, "wrong account password")
    await _second_gate(user, request, body, "remove a passkey from your WebTerm account")
    await db.execute("DELETE FROM webauthn_credentials WHERE id=? AND user_id=?",
                     cred_id, user["id"])
    # scoaterea unui factor e o schimbare de credențiale: închide ferestrele de step-up (H1) și anunță
    security.clear_stepup_for(user["id"])
    email_alerts.notify_security_change(
        "passkey deleted", security.client_ip(request), user["email"])
    return {"ok": True}
