"""SSO / OIDC endpoints (login federat, ex. Authentik). Vezi `oidc.py` pentru flow + validare.

Trei rute PUBLICE (nu există sesiune încă la login):
  · GET /api/oidc/status   — dacă SSO e activ + numele providerului (frontend afişează butonul)
  · GET /api/oidc/login    — porneşte flow-ul (redirect la IdP); intent=login|stepup
  · GET /api/oidc/callback — întoarcere de la IdP: validează, provizionează, emite sesiunea

Adminul local rămâne break-glass (parolă/passkey). Userii SSO sunt admin complet pe această
instanţă (WebTerm n-are RBAC — vezi THREAT-MODEL); „cine ajunge aici" se decide în IdP + prin
`OIDC_ALLOWED_GROUPS`.
"""
import time
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from . import audit, config, db, oidc, security

router = APIRouter(prefix="/api/oidc")

# Cookie care leagă `state` de BROWSERUL care a pornit login-ul (anti login-CSRF / fixare de
# sesiune): fără el, cineva ar putea captura un code+state valid pentru contul LUI şi păcăli
# victima să-l „finalizeze", logând-o în contul atacatorului. Acelaşi prefix `__Host-` ca la sesiune.
STATE_COOKIE = "__Host-wt_oidc" if security.COOKIE_SECURE else "wt_oidc"


def _set_state_cookie(resp, state: str) -> None:
    # Path=/ (obligatoriu pentru prefixul __Host-); samesite=lax lasă cookie-ul să însoţească
    # redirectul top-level de întoarcere de la IdP, dar nu cererile cross-site din alte contexte.
    resp.set_cookie(STATE_COOKIE, state, max_age=int(oidc._TXN_TTL), httponly=True,
                    samesite="lax", secure=security.COOKIE_SECURE, path="/")


def _clear_state_cookie(resp) -> None:
    resp.delete_cookie(STATE_COOKIE, path="/", secure=security.COOKIE_SECURE, samesite="lax")


@router.get("/status")
async def status():
    """Public: doar dacă SSO e activ + eticheta butonului. Nu scurge issuer/client_id."""
    return {"enabled": config.OIDC_ENABLED, "provider_name": config.OIDC_PROVIDER_NAME}


@router.get("/login")
async def login(request: Request, intent: str = "login", host_id: int = 0):
    """Porneşte flow-ul OIDC. `intent=stepup&host_id=N` pentru re-auth pe un host cu 2FA."""
    if not config.OIDC_ENABLED:
        return RedirectResponse("/?sso=disabled", status_code=303)
    intent = "stepup" if intent == "stepup" else "login"
    url = oidc.begin(intent=intent, host_id=host_id or None)
    state = parse_qs(urlparse(url).query).get("state", [""])[0]
    resp = RedirectResponse(url, status_code=303)
    _set_state_cookie(resp, state)   # legăm state-ul de acest browser (verificat la callback)
    return resp


def _redirect_err(reason: str) -> RedirectResponse:
    # niciodată redirect către un `next` din request (anti open-redirect): mereu spre rădăcină
    return RedirectResponse("/?sso_error=" + reason, status_code=303)


@router.get("/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    if not config.OIDC_ENABLED:
        return _redirect_err("disabled")
    if not code or not state:
        return _redirect_err("bad_request")
    ip = security.client_ip(request)
    # H2: `state` trebuie să corespundă cookie-ului setat la /login în ACELAŞI browser. Un code+state
    # capturat de atacator (pentru contul lui) livrat victimei nu va avea cookie-ul potrivit → refuz.
    if request.cookies.get(STATE_COOKIE, "") != state:
        await audit.record(time.time(), "sso", ip, "GET", "/api/oidc/callback", 403,
                           "SSO: state nelegat de browser (login-CSRF blocat)")
        resp = _redirect_err("state_mismatch")
        _clear_state_cookie(resp)
        return resp
    try:
        info = oidc.complete(state, code)
    except oidc.OidcError as e:
        # refuz (grup lipsă, token invalid, state expirat) — auditat, ca să poţi face debug
        await audit.record(time.time(), "sso", ip, "GET", "/api/oidc/callback", 403,
                           "SSO refuzat: %s" % str(e)[:120])
        return _redirect_err("denied")

    sub, email = info["sub"], info["email"]

    # --- step-up: userul e DEJA logat; re-auth-ul deschide fereastra pe host ---
    if info["intent"] == "stepup":
        # un step-up FĂRĂ host nu are ce deschide — îl respingem explicit, nu-l lăsăm să cadă
        # în calea de login (care ar emite o sesiune nouă, surprinzător).
        if not info["host_id"]:
            return _redirect_err("bad_request")
        cur = await security.user_for_token(request.cookies.get(security.COOKIE_NAME))
        if not cur or cur["sso_subject"] != sub:
            await audit.record(time.time(), email or "sso", ip, "GET", "/api/oidc/callback", 403,
                               "step-up SSO: identitate nepotrivită cu sesiunea")
            return _redirect_err("stepup_mismatch")
        security.open_stepup_window(cur["id"], info["host_id"])
        await audit.record(time.time(), cur["email"], ip, "GET", "/api/oidc/callback", 200,
                           "step-up SSO reuşit pe host %d" % info["host_id"])
        # fereastra e deschisă; frontend-ul reia acţiunea (tiparul withStepup). Semnalăm prin
        # query, nu printr-un hash arbitrar (anti open-redirect).
        resp = RedirectResponse("/?stepup=ok", status_code=303)
        _clear_state_cookie(resp)
        return resp

    # --- login: provizionare / potrivire cont, apoi sesiune ---
    user = await db.fetchone("SELECT * FROM users WHERE sso_subject=?", sub)
    if user is None:
        existing = await db.fetchone("SELECT * FROM users WHERE email=?", email) if email else None
        if existing is not None:
            if existing["sso_subject"] and existing["sso_subject"] != sub:
                await audit.record(time.time(), email, ip, "GET", "/api/oidc/callback", 409,
                                   "SSO: email deja legat de alt subiect IdP")
                return _redirect_err("conflict")
            # ADOPŢIE — calea sensibilă la preluare de cont: legarea identităţii IdP de un cont
            # local existent (inclusiv adminul) se face DOAR dacă IdP-ul confirmă emailul verificat.
            # Altfel, un IdP care lasă emailuri nevalidate ar permite revendicarea contului cuiva.
            # `email_verified` absent (None) e tratat ca NEVERIFICAT: refuzăm, nu ghicim.
            if info.get("email_verified") not in (True, "true", "True", 1):
                await audit.record(time.time(), email, ip, "GET", "/api/oidc/callback", 403,
                                   "SSO: adopţie refuzată — email neverificat de IdP")
                return _redirect_err("email_unverified")
            # (Vrei adminul imun la SSO? dă-i un email inexistent în IdP.)
            await db.execute("UPDATE users SET sso_subject=? WHERE id=?", sub, existing["id"])
            user = await db.fetchone("SELECT * FROM users WHERE id=?", existing["id"])
            await audit.record(time.time(), email, ip, "GET", "/api/oidc/callback", 200,
                               "SSO legat de cont existent (adopţie după email)")
        else:
            if not email:
                return _redirect_err("no_email")
            # parolă locală IMPOSIBILĂ pentru userii SSO: hash pe un secret aleator pe care
            # nimeni nu-l ştie → login-ul local nu poate reuşi vreodată pentru ei.
            locked = await security.hash_password_async(security.new_token())
            await db.execute(
                "INSERT INTO users(email, password_hash, created, sso_subject) VALUES(?,?,?,?)",
                email, locked, time.time(), sub)
            user = await db.fetchone("SELECT * FROM users WHERE sso_subject=?", sub)
            await audit.record(time.time(), email, ip, "GET", "/api/oidc/callback", 201,
                               "cont nou provizionat prin SSO")

    new_device = await security.note_new_login(user, ip, request.headers.get("user-agent", ""))
    token = await security.create_web_session(
        user["id"], request.headers.get("user-agent", ""), new_device)
    resp = RedirectResponse("/", status_code=303)
    security.set_session_cookie(resp, token)
    _clear_state_cookie(resp)   # state consumat — nu-l mai lăsăm în browser
    await audit.record(time.time(), user["email"], ip, "GET", "/api/oidc/callback", 200,
                       "login SSO reuşit (sub=%s)" % sub[:16])
    return resp
