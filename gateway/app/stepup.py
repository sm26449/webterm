"""Step-up and re-auth policy: who must present which factor, before what.

Moved out of api.py (3.6.36) so the whole policy reads in one file. `security.py` keeps the
mechanics (grants, windows, lockout counters, password and TOTP verification); this module
decides when they are required:

  * `require_host_stepup`: any sensitive action on a `require_2fa` host (INV-04);
  * `require_session_host_stepup`: the same, keyed by a session id (transcripts, search);
  * `require_fresh_factor`: durable access grants (deploy keys, gateway root terminal), any host;
  * `consume_factor`: the shared ladder passkey -> SSO -> TOTP -> password;
  * `verify_reauth_password`, `require_reauth_for_secret`, `reauth_for_access_change`: the
    account password (rate-limited) before secrets or access change hands.

The routes that call it are in api.py (`[stepup]`, `[install]`...) and the `*_api.py` route modules
(`deploy_keys_api.py`, `hosts_api.py`, `docker_api.py`...); nothing here imports api.py.
"""
from . import config, db, security, webauthn_api
from .errors import ApiError, rate_limited


_NEEDS_FACTOR_MSG = ("set up a passkey or an authenticator code (TOTP) to access hosts "
                     "that require 2FA")
# OP-01: the root terminal on the gateway host (certificate renewal, System health fix)
_NEEDS_FACTOR_GATEWAY_MSG = ("a root command on the gateway host always needs a second factor: "
                             "set up a passkey or an authenticator code (TOTP) in Settings → "
                             "Sign-in & 2FA first — the account password alone is not accepted")


async def method(user) -> str:
    """Factorul pe care scara de step-up (consume_factor) îl va cere ACESTUI cont pe un
    host 2FA, în aceeaşi ordine: passkey → sso → totp; `none` = niciun factor real (3.5.13)."""
    if webauthn_api.available() and await db.fetchone(
            "SELECT 1 FROM webauthn_credentials WHERE user_id=? LIMIT 1", user["id"]):
        return "passkey"
    if user["sso_subject"] and config.OIDC_ENABLED:
        return "sso"
    if user["totp_enabled"]:
        return "totp"
    return "none"


async def user_has_factor(user) -> bool:
    """Are contul un factor REAL de step-up pe un host 2FA? passkey (cu WebAuthn disponibil),
    TOTP, sau SSO (re-auth la IdP). Parola singură nu e un al doilea factor (3.5.13)."""
    return (await method(user)) != "none"


async def consume_factor(host_id: int, user, grant: str, password: str,
                                 totp: str, what: str = "", host_2fa: bool = True) -> None:
    """Scara comună de factor pentru step-up (host ŞI fresh-factor), apelată DUPĂ ce apelantul a
    tratat grant-ul şi fereastra: passkey → SSO → TOTP → parolă. Deschide fereastra la succes;
    ridică ApiError altfel. `what` doar nuanţează mesajul uman (codurile rămân stabile).

    H3→MED (fix TOTP, audit 2026-10-05): înainte ordinea era passkey → SSO → parolă, deci un cont
    cu TOTP activ dar FĂRĂ passkey deschidea fereastra pe un host 2FA cu PAROLA singură — adică
    hostul „cu 2FA" nu primea niciun al doilea factor real. Acum, dacă `totp_enabled` şi nu există
    passkey, cerem codul TOTP (sau un cod de recuperare), verificat+consumat ATOMIC prin
    `verify_second_factor` (exact anti-replay-ul de la login: un cod observat/reluat e respins).
    Parola singură NU mai deschide fereastra pe un host `require_2fa` (3.5.13, decizie de
    politică): un cont fără passkey şi fără TOTP primea pe hostul „cu 2FA" exact acelaşi factor
    ca la login — adică niciun al doilea factor. Acum primeşte `stepup.needsFactor` (403) cu
    îndrumarea spre Setări → Autentificare & 2FA. `host_2fa=False` (gate-ul de „factor proaspăt"
    pe o ţintă FĂRĂ 2FA — deploy de cheie) păstrează parola: acolo e re-auth tip `sudo`, nu 2FA."""
    has_passkey = await db.fetchone(
        "SELECT 1 FROM webauthn_credentials WHERE user_id=? LIMIT 1", user["id"])
    if webauthn_api.available() and has_passkey:
        raise ApiError(403, "stepup.passkey", ("2FA verification (passkey) required" + what))
    # User SSO: parola locală e blocată (nu o ştie) → re-auth PROASPĂT la IdP deschide fereastra.
    if user["sso_subject"] and config.OIDC_ENABLED:
        raise ApiError(403, "host.needs2faSso", ("re-authenticate with SSO (2FA)" + what))
    if user["totp_enabled"]:
        # Al doilea factor REAL: codul TOTP (sau recovery). Fără el, parola singură NU mai trece.
        if not totp:
            raise ApiError(403, "stepup.totp", ("enter your 2FA code" + what))
        # Contor de lockout dedicat (ca la login/passkey2fa), pe cont — un cookie furat cu parola
        # ştiută nu poate brute-forţa codul din 6 cifre fără plafon. Replay-ul e oprit oricum de
        # anti-replay-ul atomic din verify_second_factor (counter-ul nu mai avansează).
        key = "stepup-totp:%d" % user["id"]
        allowed, retry = security.login_allowed(key)
        if not allowed:
            raise ApiError(429, "auth.rateLimited", "too many 2FA attempts; retry in %ds" % retry,
                           headers={"Retry-After": str(retry)}, vars={"retry": int(retry)})
        await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
        if not await security.verify_second_factor(user, totp):
            security.record_login_failure(key)
            raise ApiError(403, "stepup.totp", "wrong or already-used 2FA code")
        security.record_login_success(key)
        security.open_stepup_window(user["id"], host_id)
        return
    if host_2fa:
        # Niciun factor real (fără passkey, fără TOTP, fără SSO): refuz, ORICE parolă ar veni.
        # Nu verificăm parola deloc — n-ar schimba decizia, iar o verificare ar face din acest
        # endpoint un oracol de parolă fără niciun câştig.
        raise ApiError(403, "stepup.needsFactor", _NEEDS_FACTOR_MSG)
    if password and await verify_reauth_password(user, password):
        security.open_stepup_window(user["id"], host_id)
        _mark_password_window(user["id"], host_id)
        return
    raise ApiError(403, "stepup.password", ("re-enter your account password" + what))


# OP-01: which step-up windows the PASSWORD alone opened ((user_id, host_id) → opened_at of
# that window). A window record (security.stepup_window_record) does not say what opened it, and
# the gateway root terminal must not accept one the password opened on a host without 2FA.
# The mark is tied to the window's own `opened_at`: a later passkey / TOTP / SSO window on the
# same host has a newer timestamp, so the mark no longer matches. Bounded by users × hosts;
# entries whose window is gone are dropped at every mark.
_password_windows: dict = {}


def _mark_password_window(user_id: int, host_id: int) -> None:
    rec = security.stepup_window_record(user_id, host_id)
    for k in [k for k in _password_windows if security.stepup_window_record(*k) is None]:
        _password_windows.pop(k, None)
    if rec:
        _password_windows[(user_id, host_id)] = rec[0]


def _window_opened_by_password(user_id: int, host_id: int) -> bool:
    rec = security.stepup_window_record(user_id, host_id)
    return bool(rec) and _password_windows.get((user_id, host_id)) == rec[0]


# INV-04 (docs/design/INVARIANTS.md): parola singură nu e niciodată al doilea factor.
async def require_host_stepup(host_id: int, user, grant: str = "", password: str = "",
                               totp: str = "") -> None:
    """H1: pe un host cu `require_2fa`, ORICE acțiune sensibilă (sesiune, `run`, `fs/*`, update,
    provision) cere step-up — nu doar deschiderea unei sesiuni. Un grant passkey (single-use), un
    cod TOTP sau re-auth-ul SSO (NU parola singură, 3.5.13) deschide o FEREASTRĂ de step-up pe host (5 min); în
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
    # Un grant passkey VALID e acceptat întotdeauna — e cel mai tare factor pe care îl avem —
    # şi se verifică ÎNAINTEA ferestrei deschise: prezentarea unui factor proaspăt trebuie să
    # REÎMPROSPĂTEZE `opened_at`, nu să fie scurtcircuitată de o fereastră veche încă validă.
    # Fără asta, un gate de „factor proaspăt" (deploy de cheie, require_fresh_factor) intra în
    # DEADLOCK: /stepup nu reînnoia niciodată opened_at cât fereastra era deschisă, deci
    # freshness-ul nu putea fi atins prin ceremonia normală din client. (audit v54)
    if grant and security.consume_stepup_grant(grant, user["id"], host_id):
        security.open_stepup_window(user["id"], host_id)
        return
    # Când se prezintă un factor (grant/parolă), fereastra veche NU mai scurtcircuitează:
    # lăsăm scara de mai jos să ruleze, ca factorul să reîmprospăteze `opened_at`. Fără asta,
    # un gate de „factor proaspăt" (deploy de cheie) rămânea în deadlock — /stepup returna pe
    # fereastra deschisă fără s-o reînnoiască. Parola NU sare peste passkey: ordinea de mai jos
    # (passkey → sso → parolă) rămâne, deci un user cu passkey tot passkey trebuie să dea. (audit v54)
    if not (grant or password or totp) and security.stepup_window_ok(user["id"], host_id):
        return
    # Cerem passkey doar dacă omul CHIAR are unul. Ramura se alegea după URL-ul public
    # (`_webauthn_available` verifică doar că rp_id e un domeniu, nu un IP), nu după credenţialele
    # userului: cine marca un host „cere 2FA" fără passkey rămânea blocat afară definitiv — orice
    # acţiune dădea 403, parola era refuzată, iar DEZACTIVAREA trece prin acelaşi gard.
    await consume_factor(host_id, user, grant, password, totp)


async def verify_reauth_password(user, password: str) -> bool:
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
        raise rate_limited(retry)
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


async def reauth_for_access_change(user, request, body, what: str) -> None:
    """Parola contului (conturile SSO: grant passkey account-scope sau fereastra SSO
    account-scope, ca la /api/account) + al doilea factor. Aceeaşi poartă ca la crearea unui
    cont: o legătură de rol e o cheie în plus la flotă."""
    if user["sso_subject"] and config.OIDC_ENABLED:
        ok_reauth = (bool(body.stepup_grant)
                     and security.consume_stepup_grant(body.stepup_grant, user["id"], 0)) \
            or security.stepup_window_is_open(user["id"], 0)
        if not ok_reauth:
            raise ApiError(403, "account.ssoReauth",
                           "re-authenticate with SSO or a passkey to change access")
    elif not await verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongPassword", "wrong password")
    await webauthn_api.second_gate(user, request, body, what)


async def require_session_host_stepup(sid: str, user) -> None:
    """Step-up pe hostul unei SESIUNI, pentru căile care citesc conţinutul ei.

    Enforcement-ul de `require_2fa` era complet pe acţiuni (run, fs, kill, share) şi pe fluxul
    live — `browser_ws` refuză chiar să trimită scrollback-ul unei sesiuni idle-locked. Dar
    transcriptul, previzualizarea şi căutarea livrau acelaşi conţinut printr-un simplu GET, cu
    un cookie valid: adică exact ce vede omul pe terminalul unui host cu 2FA, inclusiv secrete
    afişate în output. Semnalat de auditul intern din 2026-08-06."""
    row = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
    if row and row["host_id"]:
        await require_host_stepup(row["host_id"], user)


async def require_reauth_for_secret(user, password: str, what: str) -> None:
    """Re-autentificare cu parola CONTULUI pentru operaţiile care scot secrete din instanţă
    sau o pot prelua.

    Parola de criptare a arhivei nu e o barieră: o alege cel care cere descărcarea. Deci, fără
    asta, un cookie furat (XSS, extensie de browser, malware pe staţie) însemna: descarci
    arhiva → ai `data/secret` → ai toate credenţialele SSH şi tokenurile de agent. Sau invers:
    ÎNCARCI o arhivă a ta prin restore şi preiei instanţa cu contul tău.

    Semnalat de auditul extern (2026-08-06). Restul API-ului cerea deja re-auth pentru lucruri
    mai mici (creare de cont, token de automatizare) — incoerenţa era chiar pe operaţiile grele."""
    if not await verify_reauth_password(user, password):
        raise ApiError(401, "auth.wrongPassword", "wrong account password — required for %s" % what)


async def require_fresh_factor(host_id: int, user, grant: str = "", password: str = "",
                                totp: str = "", real_factor: bool = False) -> None:
    """Gate-ul „acordare de acces durabil" (H-3): spre deosebire de require_host_stepup, se
    aplică şi pe hosturi FĂRĂ require_2fa şi NU se mulţumeşte cu o fereastră de step-up veche —
    factorul trebuie prezentat ACUM (grant nou, parolă în corp, sau fereastră deschisă ≤120s,
    cum lasă ceremonia de step-up / callback-ul OIDC intent=stepup).
    `real_factor=True` (OP-01, audit 2026-10-17 — terminalul root de pe hostul gateway): un al
    doilea factor REAL indiferent de `require_2fa` al hostului, iar o fereastră proaspătă
    deschisă de parola singură (/stepup pe un host fără 2FA) nu e primită."""
    if isinstance(user, dict) and user.get("is_token"):
        raise ApiError(403, "host.needs2faNoToken", "deploy keys are not reachable with an automation token")
    if grant and security.consume_stepup_grant(grant, user["id"], host_id):
        security.open_stepup_window(user["id"], host_id)
        return
    if security.stepup_window_fresh(user["id"], host_id) \
            and not (real_factor and _window_opened_by_password(user["id"], host_id)):
        return
    # aceeaşi scară ca require_host_stepup (passkey → SSO → TOTP → parolă), inclusiv ramura TOTP
    # (fix 3): un cont cu TOTP fără passkey nu mai acordă acces SSH durabil cu parola singură.
    # Pe o ţintă `require_2fa` (şi la deblocarea terminalului) parola singură e refuzată ca la
    # require_host_stepup; pe o ţintă fără 2FA rămâne re-auth-ul de tip `sudo` (3.5.13).
    if real_factor:
        if not await user_has_factor(user):
            # said before any password is looked at (no oracle), with the way out
            raise ApiError(403, "stepup.needsFactor", _NEEDS_FACTOR_GATEWAY_MSG)
        await consume_factor(host_id, user, grant, password, totp, host_2fa=True)
        return
    hrow = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", host_id)
    await consume_factor(host_id, user, grant, password, totp, " to grant SSH access",
                                 host_2fa=bool(hrow and hrow["require_2fa"]))
