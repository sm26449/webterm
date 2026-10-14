"""SSO / OIDC endpoints (login federat, ex. Authentik). Vezi `oidc.py` pentru flow + validare.

Trei rute PUBLICE (nu există sesiune încă la login):
  · GET /api/oidc/status   — dacă SSO e activ + numele providerului (frontend afişează butonul)
  · GET /api/oidc/login    — porneşte flow-ul (redirect la IdP); intent=login|stepup
  · GET /api/oidc/callback — întoarcere de la IdP: validează, provizionează, emite sesiunea

Adminul local rămâne break-glass (parolă/passkey). Un cont SSO NOU nu primeşte niciun rol din
oficiu; de la 3.6.2 primeşte ce îi dau grupurile lui prin maparea grup → rol (ssomap.py),
re-sincronizată la FIECARE login şi step-up SSO (legăturile `source='sso'`; cele manuale nu se
ating). Fără niciun grup mapat: „fără acces încă". „Cine ajunge aici" se decide în IdP + prin
`OIDC_ALLOWED_GROUPS`.
"""
import logging
import time
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from . import audit, authz, config, db, oidc, security, ssomap

router = APIRouter(prefix="/api/oidc", dependencies=[Depends(authz.declared)])
log = logging.getLogger("webterm")

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
    try:
        url = oidc.begin(intent=intent, host_id=host_id or None)
    except oidc.OidcError as e:
        # 3.6.8: the IdP's discovery document is unreachable — before, a raw exception → 500.
        # Counted (System health "SSO is broken"), and the person gets the login page back.
        oidc.note_failure(e.kind, security.client_ip(request))
        log.warning("SSO login could not start (%s): %s", e.kind, str(e)[:200])
        return _redirect_err("unavailable")
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
        # refuz (grup lipsă, token invalid, state expirat) — auditat, ca să poţi face debug.
        # 3.6.8: clasificat (e.kind) şi numărat — un IdP căzut nu mai arată ca o zi liniştită.
        oidc.note_failure(e.kind, security.client_ip(request))
        await audit.record(time.time(), "sso", ip, "GET", "/api/oidc/callback", 403,
                           "SSO refuzat (%s): %s" % (e.kind, str(e)[:120]))
        return _redirect_err("unavailable" if e.kind in ("discovery", "token_endpoint")
                             else "denied")
    oidc.note_success()

    sub, email = info["sub"], info["email"]

    # --- step-up: userul e DEJA logat; re-auth-ul deschide fereastra pe host ---
    if info["intent"] == "stepup":
        cur = await security.user_for_token(request.cookies.get(security.COOKIE_NAME))
        if not cur or cur["sso_subject"] != sub:
            await audit.record(time.time(), email or "sso", ip, "GET", "/api/oidc/callback", 403,
                               "step-up SSO: identitate nepotrivită cu sesiunea")
            return _redirect_err("stepup_mismatch")
        # 3.6.2 (§A.7, Q8 b): step-up-ul SSO aduce un id_token PROASPĂT, cu grupurile de acum —
        # momentele sensibile primesc date de grup proaspete. Sincronizăm ÎNAINTE de verificarea
        # host.view de mai jos, ca un grup scos în IdP să nu mai deschidă fereastra.
        await ssomap.sync_user(cur["id"], cur["email"],
                               info["groups"] if info.get("groups_present") else None,
                               ip=ip, via="step-up", readable=info.get("groups_readable", True))
        # host_id=0 (sau lipsă) = re-auth account-scope: schimbarea emailului/parolei unui cont SSO
        # (fix 7), unde parola locală e un hash aleator. Altfel, fereastră per-host ca până acum.
        hid = info["host_id"] or 0
        # 3.6 (§A.6.7): ceremonia de step-up nu are voie să confirme existenţa/2FA-ul unui host
        # pe care contul nu-l vede, nici să deschidă o fereastră pe el — `host.view` întâi.
        if hid and "host.view" not in await authz.perms_on(
                await authz.grants_for_user(cur["id"]), hid):
            await audit.record(time.time(), cur["email"], ip, "GET", "/api/oidc/callback", 404,
                               "step-up SSO refuzat: host invizibil sau inexistent",
                               actor_id=cur["id"])
            resp = _redirect_err("denied")
            _clear_state_cookie(resp)
            return resp
        security.open_stepup_window(cur["id"], hid)
        await audit.record(time.time(), cur["email"], ip, "GET", "/api/oidc/callback", 200,
                           ("step-up SSO reuşit, account-scope" if not hid
                            else "step-up SSO reuşit pe host %d" % hid))
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
            # 3.6.2 (revizuirea de securitate): contul adoptat ÎŞI PĂSTREAZĂ parola locală (şi
            # passkey-urile, TOTP-ul) — dar cu o parolă locală, grupurile SSO nu-i mai dau NICIUN
            # rol (ssomap.sync_user). Altfel cine a pus parola (un Admin care a creat contul
            # înaintea primului login SSO al omului) ar moşteni ce îi dau omului grupurile.
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
                "INSERT INTO users(id, email, password_hash, created, sso_subject, local_password)"
                " VALUES(" + db.NEXT_USER_ID_SQL + ",?,?,?,?,0)",
                email, locked, time.time(), sub)
            user = await db.fetchone("SELECT * FROM users WHERE sso_subject=?", sub)
            await audit.record(time.time(), email, ip, "GET", "/api/oidc/callback", 201,
                               "cont nou provizionat prin SSO")

    # 3.6.2: legăturile SSO după grupurile de ACUM, înainte de a emite sesiunea
    await ssomap.sync_user(user["id"], user["email"],
                           info["groups"] if info.get("groups_present") else None,
                           ip=ip, via="login", readable=info.get("groups_readable", True))
    new_device = await security.note_new_login(user, ip, request.headers.get("user-agent", ""))
    token = await security.create_web_session(
        user["id"], request.headers.get("user-agent", ""), new_device, method="sso")
    resp = RedirectResponse("/", status_code=303)
    security.set_session_cookie(resp, token)
    _clear_state_cookie(resp)   # state consumat — nu-l mai lăsăm în browser
    await audit.record(time.time(), user["email"], ip, "GET", "/api/oidc/callback", 200,
                       "login SSO reuşit (sub=%s)" % sub[:16])
    return resp
