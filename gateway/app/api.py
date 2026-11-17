"""REST API, install script, agent + browser websocket endpoints."""

import asyncio
import csv
import hashlib
import io
import json
import logging
import math
import os
import re
import shlex
import sqlite3
import time

import asyncssh

from fastapi import (APIRouter, Depends, HTTPException, Query, Request, Response,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field, ValidationError
from typing import Optional


from .errors import ApiError, rate_limited
from . import gitpanel, owners
from . import webauthn_api
from . import (accounts, alert_history, audit, authz, backup, certmon, cloudbackup, cmdguard, config,
               core, db, email_alerts, errors, fserrors, health, healthcmd, hostcmd, hostmodel, push,
               pyruntime, replay, scim, security, shares, conntypes, fwddomain, signing, ssomap,
               stepup, syshealth, totp, updatecheck)

log = logging.getLogger("webterm")
# Garda de la nivel de router (3.6, fail-closed): o rută care nu-şi declară permisiunea
# (`authz.perm(...)`, sau o intrare în authz.PUBLIC/SELF) răspunde 500 `authz.undeclared`.
router = APIRouter(dependencies=[Depends(authz.declared)])

# ── [setup] First-run setup token, /healthz, /api/state, /api/setup ───────────────────────────────

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

# Fişierul numai-owner (0600) în care punem tokenul GENERAT, ca `make token`/setup.sh să-l
# recupereze. DE CE un fişier şi nu logul: până la 3.2.0 tokenul întreg se scria în logul
# aplicaţiei (marker-ul `WEBTERM_SETUP_TOKEN=<value>`). Înainte de primul setup, oricine poate
# citi `docker compose logs app` — colectoare de loguri, operatori fără drepturi de admin —
# obţinea tokenul şi putea crea contul de admin. Logul nu e un loc pentru un secret viu, aşa
# că tokenul generat ajunge într-un fişier 0600 în directorul de date, nu în istoria logului.
_SETUP_TOKEN_FILE = config.DATA_DIR / "setup-token"


def _write_setup_token_file(token: str) -> None:
    """Scrie tokenul de setup într-un fişier numai-owner (0600), best-effort.

    DE CE `os.open(..., 0o600)` şi nu write + chmod: creând fişierul cu drepturi largi şi
    strângându-le abia după, ar exista o fereastră în care alt user de pe host îl poate citi.
    Dacă scrierea eşuează (FS read-only etc.) nu crăpăm: tokenul rămâne în memorie, deci
    setup-ul din UI merge — doar recuperarea prin `make token` nu mai are de unde citi."""
    try:
        config.ensure_dirs()
        fd = os.open(_SETUP_TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, token.encode())
        finally:
            os.close(fd)
        os.chmod(_SETUP_TOKEN_FILE, 0o600)   # fişier preexistent cu alt mod → strânge-l oricum
    except OSError as e:
        log.warning("could not persist the setup token to %s (%s)", _SETUP_TOKEN_FILE, e)


def _clear_setup_token_file() -> None:
    """Şterge fişierul 0600 (best-effort) când setup-ul s-a închis, ca secretul să nu zăbovească
    pe disc după ce nu mai e folositor."""
    try:
        os.unlink(_SETUP_TOKEN_FILE)
    except OSError:
        pass        # deja absent sau FS read-only — nimic de făcut


async def init_setup_token() -> None:
    global _setup_token
    if await db.fetchone("SELECT id FROM users LIMIT 1"):
        _setup_token = None          # already configured; setup is closed
        _clear_setup_token_file()    # curăţă un eventual fişier rămas de la o pornire anterioară
        return
    provided = bool(config.SETUP_TOKEN)
    _setup_token = config.SETUP_TOKEN or security.new_token()
    if provided:
        # Tokenul vine din mediu (WEBTERM_SETUP_TOKEN) — calea de install/ci-local. Operatorul ÎL
        # ARE deja, deci nu-l scriem în fişier şi mai ales nu-l logăm: ar fi scurgerea gratuită a
        # unui secret deja cunoscut. Ştergem şi un fişier generat anterior, ca să nu rămână unul
        # vechi lângă tokenul configurat.
        _clear_setup_token_file()
        log.warning(
            "WebTerm: no account yet. Setup is open using the configured WEBTERM_SETUP_TOKEN "
            "(not logged — you already have it). Create the account and setup closes itself.")
        return
    # Token GENERAT de noi: trebuie recuperabil, dar NU prin log. Îl punem în fişierul 0600 şi
    # logăm DOAR un prefix scurt (verificare „la ochi") plus cum se ia valoarea întreagă. Marker-ul
    # vechi `WEBTERM_SETUP_TOKEN=<value>` rămâne, dar MASCAT: orice unealtă care încă îl caută
    # vede o valoare evident redactată, nu secretul real.
    _write_setup_token_file(_setup_token)
    log.warning(
        "\n%s\n  WebTerm: no account yet. A setup token was generated (prefix %s…).\n"
        "  Get the full token with:  make token\n"
        "  or read the owner-only file:  %s\n\n"
        "  WEBTERM_SETUP_TOKEN=<redacted — run `make token`>\n\n"
        "  Create the account and setup closes itself.\n%s",
        "=" * 64, _setup_token[:6], _SETUP_TOKEN_FILE, "=" * 64)


@router.get("/healthz")
async def healthz():
    """Sondă de sănătate (fără auth): confirmă că procesul răspunde și că DB-ul
    e accesibil. Folosită de Docker HEALTHCHECK ca să repornească un app blocat."""
    try:
        await db.fetchone("SELECT 1")
    except Exception:
        raise ApiError(503, "gateway.dbUnavailable", "database unavailable")
    return {"ok": True}


# Punctul de pe rotiţa Settings (din /api/state). Cheile le scrie backup_api.scheduled_backup_tick.
async def _backup_needs_attention() -> bool:
    last = float(await db.get_setting("backup_last", "0") or 0)
    err_ts = float((await db.get_json_setting("backup_last_error")).get("ts") or 0)
    seen = float(await db.get_setting("backup_seen", "0") or 0)
    return max(last, err_ts) > seen


@router.get("/api/state")
async def app_state(request: Request):
    """Bootstrap info for the frontend: setup needed? logged in?"""
    has_user = await db.fetchone("SELECT id FROM users LIMIT 1") is not None
    user = await security.user_for_token(request.cookies.get(security.COOKIE_NAME))
    backup_ready = False
    signing_missing = False
    signing_locked = False
    health_attention = None
    hostkey_changed = []
    if user is not None:
        # 3.6: totul de mai jos e filtrat pe rolul contului — alarmele doar pe hosturile pe care
        # le vede, punctele de backup/semnare doar pentru cine le poate rezolva.
        grants = await authz.grants_for_user(user["id"])
        vis = await authz.visible_hosts(grants, "host.view")
        # alarme de host-key NEREZOLVATE (SSH direct/jump): UI-ul le arată persistent, nu ca
        # toast de 12 s. Un SELECT pe o coloană aproape mereu NULL — ieftin.
        for h in await db.fetchall(
                "SELECT id, name, hostkey_alarm FROM hosts WHERE hostkey_alarm IS NOT NULL"):
            if not authz.in_visible(vis, h["id"]):
                continue
            a = hostmodel.hostkey_alarm(h)
            if a:
                hostkey_changed.append({"host_id": h["id"], "host_name": h["name"], **a})
        # punctul de pe rotiţă: backup nou de descărcat SAU un eşec de backup programat
        # nevăzut încă (înainte eşecul era complet tăcut în UI — audit UX §7.f1)
        if grants.has_global("backups.manage"):
            backup_ready = await _backup_needs_attention()
        # nudge pentru cheia de semnare a flotei: lipsă → recomandă generarea înainte de
        # a înrola agenți; criptată & blocată → agenții nu se pot actualiza până la deblocare
        if grants.has_global("signing.manage"):
            signing_missing = not signing.key_exists()
            signing_locked = (signing.key_exists() and signing.is_encrypted()
                              and not signing.is_loaded())
        # 3.6.8: „N items need attention" (System health) — warning/critical, not muted. From
        # memory (the last run), so /api/state stays cheap.
        if grants.has_global("security.view"):
            health_attention = syshealth.attention(await syshealth.rows())
    return {"setup_required": not has_user,
            "authenticated": user is not None,
            "email": user["email"] if user else None,
            # id-ul contului: clientul îşi cheiază după el stările locale per cont (ex. descărcările
            # întrerupte din IndexedDB) — alt cont în acelaşi browser nu le vede pe ale primului
            "user_id": user["id"] if user else None,
            "webauthn_available": webauthn_api.available(),
            # cum face ACEST cont step-up pe un host 2FA: passkey | sso | totp | none (3.5.13:
            # parola singură nu mai e acceptată — `none` = UI-ul trimite la Setări → 2FA)
            "stepup_method": (await stepup.method(user)) if user is not None else None,
            "backup_ready": backup_ready,
            "signing_missing": signing_missing,
            "signing_locked": signing_locked,
            "health_attention": health_attention,
            # overlay-ul de identitate; clientul rezolvă ${email}/${host}/${time}
            "watermark": (await _load_watermark()) if user is not None else None,
            # guardrail de comenzi (verificat client-side la Enter, via OSC 133)
            "command_guard": (await cmdguard.load_command_guard()) if user is not None else None,
            # Idle-lock-ul e PER SESIUNE DE TERMINAL pe hosturile cu require_2fa (core.sweep_idle_locks),
            # nu per sesiune web: cronometrul îl resetează DOAR input-ul în terminal (şi mesajul WS
            # `touch`), nu orice cerere HTTP autentificată. Aici dăm pragul configurat (0 = oprit),
            # ca UI-ul să poată avertiza înainte; momentul exact al blocării vine per sesiune, în
            # mesajul `init` al WS-ului (`lock_idle`, `lock_at`) — de aceea `idle_lock_at` e null aici.
            "idle_lock_seconds": int(config.IDLE_LOCK_SECS or 0) if user is not None else 0,
            "idle_lock_at": None,
            # eveniment de stare `hostkey_changed`: lista alarmelor nerezolvate (vezi _host_json)
            "hostkey_changed": hostkey_changed}


@router.post("/api/setup")
async def setup(creds: Credentials, request: Request, response: Response):
    global _setup_token
    if await db.fetchone("SELECT id FROM users LIMIT 1"):
        raise ApiError(409, "setup.alreadyConfigured", "already configured")
    ip = security.client_ip(request)
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        raise rate_limited(retry)
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    if not _setup_token or not security.tokens_equal(creds.setup_token, _setup_token):
        locked, fails = security.record_login_failure(ip)
        # Spune CÂTE mai ai. Fără asta, omul greşeşte tokenul de câteva ori (32 de caractere
        # copiate dintr-un log, la două minute după clonare), iar a şasea încercare îl blochează
        # 15 minute — inclusiv cu tokenul CORECT, fiindcă lockout-ul e pe IP, nu pe token. Din
        # afară arată ca „produsul e stricat". Semnalat de un audit extern pe traseul primei
        # instalări.
        left = max(config.IP_MAX_FAILS - fails, 0)
        minutes = security._IP_LOCKOUT // 60
        if locked or left == 0:
            raise ApiError(
                429, "setup.lockedOut",
                "too many wrong setup tokens — locked out for %d minutes. "
                "Recover the token with: make token" % minutes,
                vars={"minutes": minutes})
        raise ApiError(
            403, "setup.wrongToken",
            "wrong setup token (%d attempt%s left before a %d-minute lockout) — "
            "recover it with: make token"
            % (left, "" if left == 1 else "s", minutes),
            vars={"left": left, "minutes": minutes})
    _check_password(creds.password)
    email = creds.email.strip().lower()
    if not security.valid_email(email):      # aceeaşi regulă ca la PATCH /account şi create_user
        raise ApiError(400, "account.badEmail", "invalid email")
    pw_hash = await security.hash_password_async(creds.password)
    # Revendicare ATOMICĂ a setup-ului: INSERT condiționat de „niciun user încă", într-o
    # singură instrucțiune SQL (existența + insert sunt atomice în SQLite). Fără asta, două
    # cereri concurente cu același token treceau ambele de verificarea de la linia 107
    # (await-ul de hash e ÎNTRE check și insert) și creau două conturi → încălcau
    # invariantul single-account (nu există autorizare pe obiect).
    await db.execute(
        "INSERT INTO users(id, email, password_hash, created) "
        "SELECT " + db.NEXT_USER_ID_SQL + ",?,?,? WHERE NOT EXISTS (SELECT 1 FROM users)",
        email, pw_hash, time.time())
    row = await db.fetchone("SELECT id, email FROM users LIMIT 1")
    if not row or row["email"] != email:
        raise ApiError(409, "setup.alreadyConfigured", "already configured")   # altă cerere a câștigat cursa
    # Primul cont = Owner peste toată flota (3.6). Legătura se scrie ÎNAINTE de cookie: nu
    # există nicio clipă în care singurul cont al instalării să fie fără drepturi.
    await db.execute(
        "INSERT OR IGNORE INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
        " created) SELECT ?, id, 'all', '', 'manual', ? FROM roles WHERE key='owner'",
        row["id"], time.time())
    authz.bump_epoch()
    _setup_token = None              # single-use; setup is now closed
    # Contul e creat → fişierul 0600 nu mai are rost. Îl ştergem (best-effort) ca tokenul de setup
    # să nu zăbovească pe disc după ce şi-a făcut treaba.
    _clear_setup_token_file()
    security.record_login_success(ip)
    await _issue_cookie(response, row["id"], request, method="password")
    return {"ok": True}


# ── [errors] Password policy + shared ApiError mappers (fs, runtime, signing, hostkey alarm) ─────────

# Parola avea doar prag INFERIOR. Nimic nu oprea un body de câţiva MB să ajungă la argon2 —
# şi la fiecare încercare de login, unde e gratuit de repetat. Impactul e mic (intrarea e
# pre-hashuită, login-ul e plafonat), dar un plafon costă un `if`. Generos intenţionat: nu vrem
# să tăiem passphrase-uri lungi, doar body-uri care nu sunt parole.
PASSWORD_MAX = 1024


def _check_password(pw: str, what: str = "password") -> None:
    if len(pw) < 8:
        raise ApiError(400, "account.passwordTooShort",
                       "the %s must be at least 8 characters" % what, vars={"min": 8})
    if len(pw) > PASSWORD_MAX:
        raise ApiError(400, "account.passwordTooLong",
                       "the %s must be at most %d characters" % (what, PASSWORD_MAX),
                       vars={"max": PASSWORD_MAX})


def _signing_value_error(e: Exception) -> ApiError:
    msg = str(e) or "invalid key"
    low = msg.lower()
    if "already exists" in low:
        return ApiError(409, "signing.exists", msg)
    if "not ed25519" in low:
        return ApiError(400, "signing.notEd25519", msg)
    return ApiError(400, "signing.badKey", msg)


# ── [auth] Login, session cookie, logout, share/replay link revocation ────────────────────────────

LOGIN_MAX_BODY = 4096   # 4 KiB: un corp de login legitim are ~200 B; peste atât e abuz pre-auth


async def _read_capped_body(request: Request, cap: int) -> bytes:
    """Citeşte corpul cererii cu un PLAFON real, ÎNAINTE de orice parse. `Content-Length` e doar
    un indiciu (poate lipsi sau minţi), deci numărăm octeţii pe măsură ce curg şi tăiem la
    depăşire (413) — un corp pre-auth mare, neautentificat (deci nelimitat de altceva), nu trebuie
    să ajungă în memorie sau pe calea scumpă (json.loads / argon2)."""
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > cap:
                raise ApiError(413, "req.tooLarge", "request body too large")
        except ValueError:
            pass
    total, chunks = 0, []
    async for chunk in request.stream():
        total += len(chunk)
        if total > cap:
            raise ApiError(413, "req.tooLarge", "request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/api/login")
async def login(request: Request, response: Response):
    # fix 9: plafon pe corp ÎNAINTE de parse (Credentials nu mai e parametru de corp, altfel
    # FastAPI ar fi citit+parsat corpul înainte să ajungem aici). Un 5 MB pre-auth → 413 rapid.
    raw = await _read_capped_body(request, LOGIN_MAX_BODY)
    try:
        creds = Credentials.model_validate_json(raw or b"{}")
    except ValidationError:
        # corp malformat = cerere invalidă; refolosim codul existent (fără cheie nouă de catalog)
        raise ApiError(400, "auth.badCredentials", "wrong email or password")
    ip = security.client_ip(request)
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        # Lockout: NU marcăm actorul şi NU scriem rând de audit (429 fără actor e picat în
        # audit.record). Altfel un neautentificat putea, cu `email` arbitrar, (a) injecta atribuire
        # falsă şi (b) inunda jurnalul până roteşte afară intrările reale de incident — exact
        # invariantul pe care auditul trebuie să-l apere. Emailul încercat se marchează DOAR după
        # ce trecem de lockout, deci doar pentru un număr mărginit de încercări reale per IP.
        raise rate_limited(retry)
    # auditul se scrie din middleware, DUPĂ răspuns — un login eșuat n-are cookie, deci
    # marcăm aici emailul încercat (altfel jurnalul ar arăta doar „cineva, de la IP-ul X")
    audit.actor(request, creds.email.strip().lower())
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    user = await db.fetchone("SELECT * FROM users WHERE email=?",
                             creds.email.strip().lower())
    # verify (or a dummy verify when the real one is skipped) so timing can't reveal whether the
    # email exists. ATENŢIE: verify-ul real e sărit ŞI când userul lipseşte, ŞI când parola trece
    # de PASSWORD_MAX (scurtcircuit înainte de argon2). Dacă dummy-ul rula doar pe `user is None`,
    # o parolă >MAX diferenţia un cont existent (rapid) de unul inexistent (lent) — enumerare.
    did_verify = user is not None and len(creds.password) <= PASSWORD_MAX
    ok = did_verify and await security.verify_password_async(creds.password, user["password_hash"])
    if not did_verify:
        await security.dummy_verify_async()
    if ok and "local_password" in user.keys() and user["local_password"] == 0:
        ok = False      # 3.6.2: contul n-are parolă locală (SSO-only) — nicio parolă nu-l deschide
    if not ok:
        security.record_login_failure(ip)
        raise ApiError(401, "auth.badCredentials", "wrong email or password")
    # 3.6.11: contul dezactivat (SCIM) — spus DOAR după parola corectă (altfel ar fi un oracol
    # de existenţă), auditat; nicio sesiune, niciun al doilea factor cerut
    if user["disabled"]:
        audit.detail(request, "sign-in refused: the account is disabled")
        raise ApiError(403, "auth.accountDisabled",
                       "this account is disabled; an Owner can re-enable it")
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
    await _issue_cookie(response, user["id"], request, new_device,
                        method="password_2fa" if user["totp_enabled"] else "password")
    return {"ok": True}


async def _issue_cookie(response: Response, user_id: int, request: Request,
                        device_new: bool = False, method: str = "") -> None:
    token = await security.create_web_session(
        user_id, request.headers.get("user-agent", ""), device_new, method=method)
    security.set_session_cookie(response, token)


@router.post("/api/logout")
async def logout(request: Request, response: Response):
    tok = request.cookies.get(security.COOKIE_NAME)
    u = await security.user_for_token(tok)
    if not u:
        # Fără sesiune validă nu e NIMIC de revocat — şi tocmai asta era gaura: `u` era None,
        # deci `shares.revoke_all_shares(None)` intra pe ramura GLOBALĂ (gândită pentru „schimbare de
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
    # explice de ce. Vezi `shares.revoke_all_shares`, care primise deja aceeaşi restrângere.
    security.bump_forward_epoch(u["id"])
    # doar share-urile CONTULUI care se deconectează — vezi shares.revoke_all_shares
    await shares.revoke_all_shares(u["email"], u["id"])
    await security.destroy_web_session(tok)
    security.clear_session_cookie(response)
    return {"ok": True}


# ── [account] Account self-service: password/email change, re-auth, break-glass guard ─────────────

class AccountUpdate(BaseModel):
    current_password: str = ""
    email: str = None
    new_password: str = None
    email_code: str = ""        # confirmarea cerută când sesiunea vine de pe un dispozitiv nou
    totp_code: str = ""         # al doilea factor (webauthn_api.second_gate) cu TOTP activ
    stepup_grant: str = ""      # fix 7: re-auth account-scope cu passkey (host_id=0) pt. conturi SSO
    # 3.6.2: un cont legat de SSO îşi scoate parola LOCALĂ (devine SSO-only) — abia atunci
    # grupurile SSO îi pot da roluri. Scoate ŞI passkey-urile, TOTP-ul, codurile de recuperare şi
    # celelalte sesiuni: oricine a ştiut parola (ex. cine a creat contul) şi-a putut lăsa acolo un
    # passkey care ar fi moştenit rolurile din grupuri.
    remove_password: bool = False


async def _refuse_last_break_glass(user) -> None:
    """RB-01 (audit 2026-10-17): `python3 -m app.admin sso-only` refuses to make the last Owner
    with a local password SSO-only — the UI route (Your access → Remove local password) did not,
    and the banner even recommends it. Same rule here, same definition: a PERMANENT Owner @ all
    keeps its local password while no OTHER active permanent Owner has one (a time-bound Owner
    does not count — it expires). Without that account an IdP outage locks every Owner out
    (passkeys go with the password), and the only way back is a shell on the server.
    RB-06: the decision is `owners.last_break_glass` — shared with delete_user, remove_binding,
    the expiry route and accounts.disable (SCIM); nothing to protect when the account has no
    local password already (COALESCE(local_password, 1)=0: an SSO-only account is not the
    break-glass one, whatever the count)."""
    if await owners.last_break_glass(user["id"]):
        raise ApiError(409, "account.lastBreakGlass", owners.LAST_BREAK_GLASS_DETAIL % "you are")


@router.post("/api/account")
async def update_account(body: AccountUpdate, request: Request, user=Depends(security.require_user)):
    """Change email and/or password. Requires the current password — plus, when the session
    was opened from a device never seen before, a code mailed to the account address."""
    # 3.6.11 (revizuirea de securitate): un cont administrat prin SCIM e al IdP-ului — o parolă
    # locală l-ar scoate de sub dezactivarea din IdP (SCIM nu atinge conturile cu parolă locală),
    # iar emailul îl schimbă IdP-ul. Break-glass: `python3 -m app.admin passwd` îl desprinde.
    if (body.new_password or (body.email and body.email.strip().lower() != user["email"])) \
            and user["scim_managed"]:
        raise ApiError(409, "account.scimManaged",
                       "this account is managed by your identity provider (SCIM): change it there")
    # fix 7: parola locală a unui cont SSO e un hash pe un secret aleator — `current_password` NU
    # poate trece NICIODATĂ, deci userii SSO nu-şi puteau schimba emailul deloc. Pentru ei acceptăm
    # re-auth-ul lor real: un grant passkey account-scope (host_id=0, din ceremonia
    # /api/webauthn/stepup/verify cu host_id=0) SAU o re-autentificare OIDC proaspătă (fereastra
    # account-scope, host_id=0, deschisă de callback-ul intent=stepup fără host). Fereastra e
    # per-cont, se închide la logout/clear_stepup_for ca orice step-up.
    if user["sso_subject"] and config.OIDC_ENABLED:
        ok_reauth = (bool(body.stepup_grant)
                     and security.consume_stepup_grant(body.stepup_grant, user["id"], 0)) \
            or security.stepup_window_is_open(user["id"], 0)
        if not ok_reauth:
            raise ApiError(403, "account.ssoReauth",
                           "re-authenticate with SSO or a passkey to change your account")
    elif not await stepup.verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    # G-34: adresa devine canalul de login ŞI de recuperare — `{"email":"foo"}` trecea, iar
    # codurile pe email nu mai ajungeau nicăieri. Verificăm forma ÎNAINTE de al doilea factor,
    # ca să nu trimitem un cod de confirmare pentru o schimbare pe care oricum o refuzăm.
    if body.email and body.email.strip().lower() != user["email"] \
            and not security.valid_email(body.email.strip().lower()):
        raise ApiError(400, "account.badEmail", "invalid email")
    # Parola singură nu mai ajunge. Atacul pe care îl opreşte: cineva care ARE deja parola
    # (reutilizată, scursă, ghicită) şi o roteşte ca să te scoată pe tine afară — sau mută
    # emailul (canalul de recuperare) şi apoi schimbă parola „confirmat".
    #
    # Auditul intern (2026-09-23) a unificat poarta cu `second_gate`, aceeaşi de la passkey-uri,
    # tokenuri şi coduri de recuperare — politica devine uniformă: tot ce atinge materialul de
    # autentificare cere al doilea factor. Cu TOTP activ: codul de pe telefon (contor de lockout
    # separat, care nu se resetează la parola corectă). Fără TOTP rămâne exact comportamentul
    # vechi: cod pe email, DOAR de pe un dispozitiv nestabilit — escaladăm, nu refuzăm („de pe
    # un loc necunoscut nu se poate schimba parola" sună bine până eşti în tren cu parola
    # tocmai scursă; codul îl trece pe cel legitim în 30 de secunde şi pe atacator deloc).
    if body.remove_password:
        if not (user["sso_subject"] and config.OIDC_ENABLED):
            raise ApiError(400, "account.passwordRequired",
                           "only an account linked to SSO can remove its local password")
        if body.new_password:
            raise ApiError(400, "account.passwordRequired",
                           "set a new password or remove it, not both")
        await _refuse_last_break_glass(user)     # RB-01: before the second factor, clear message
    if body.new_password or body.remove_password \
            or (body.email and body.email.strip().lower() != user["email"]):
        what = ("remove your local WebTerm password" if body.remove_password
                else "change your WebTerm password" if body.new_password
                else "change your WebTerm email")
        await webauthn_api.second_gate(user, request, body, what)
    email = user["email"]
    if body.email and body.email.strip().lower() != email:
        email = body.email.strip().lower()
        # `users.email` e UNIQUE, iar `create_user` verifică duplicatele — aici nu. Rezultatul
        # era un IntegrityError nemanipulat, adică „500 Internal Server Error" pentru ceva ce
        # utilizatorul poate repara singur, dacă i se spune ce e.
        if await db.fetchone("SELECT 1 FROM users WHERE lower(email)=? AND id<>?",
                             email, user["id"]):
            raise ApiError(409, "account.emailTaken", "an account with that email already exists")
    pw_hash = user["password_hash"]
    local_pw = user["local_password"] if "local_password" in user.keys() else 1
    if body.new_password:
        _check_password(body.new_password, "new password")
        pw_hash = await security.hash_password_async(body.new_password)
        local_pw = 1
    if body.remove_password:
        pw_hash = await security.hash_password_async(security.new_token())   # nimeni n-o ştie
        local_pw = 0
    # revizuirea 3.6.11 (cursă): între verificarea `scim_managed` de sus şi scriere a trecut al
    # doilea factor — SCIM a putut adopta contul între timp. Re-verificat ÎN scriere (atomic).
    guarded = bool(body.new_password) or email != user["email"]
    async with authz.bindings_lock:
        if body.remove_password:
            # RB-01: the second factor above was a suspension point — the other break-glass
            # Owner may have lost its password or its Owner role meanwhile; decided again under
            # the lock that every binding change takes, right before the write
            await _refuse_last_break_glass(user)
        done = await db.execute_returning(
            "UPDATE users SET email=?, password_hash=?, local_password=? WHERE id=?"
            + (" AND COALESCE(scim_managed, 0)=0" if guarded else "") + " RETURNING id",
            email, pw_hash, local_pw, user["id"])
    if done is None:
        raise ApiError(409, "account.scimManaged",
                       "this account is managed by your identity provider (SCIM): change it there")
    if body.new_password:
        # 3.6.2: o parolă locală nouă = rolurile din grupuri SSO pleacă ACUM (cine ştie parola nu
        # moşteneşte ce dau grupurile); legăturile manuale rămân
        async with authz.bindings_lock:
            n = 0
            for b in await db.fetchall(
                    "SELECT b.id, b.scope_kind, r.key FROM role_bindings b JOIN roles r"
                    " ON r.id=b.role_id WHERE b.user_id=? AND b.source='sso'", user["id"]):
                if b["key"] == "owner" and b["scope_kind"] == "all":
                    if await owners.owner_count(exclude_binding=b["id"]) < 1:
                        # ultimul Owner: instanţa nu se blochează (aceeaşi regulă ca la sincronizare)
                        log.error("local password set on %s, the LAST Owner: its SSO Owner "
                                  "binding is kept", user["email"])
                        continue
                    # RB-06 (revizuirea P1): nici ultimul Owner permanent CU PAROLĂ LOCALĂ nu-şi
                    # pierde legătura Owner la o schimbare de rutină a parolei — altfel rămân
                    # doar Owneri SSO-only (contul break-glass dispare la prima rotire a parolei,
                    # iar o pană a IdP-ului nu mai lasă pe nimeni să intre). local_password e deja
                    # 1 (scris mai sus), deci regula vede contul ca break-glass dacă e cazul.
                    if await owners.last_break_glass(user["id"], exclude_binding=b["id"]):
                        log.error("local password set on %s, the last permanent Owner with a "
                                  "local password (break-glass): its SSO Owner binding is kept",
                                  user["email"])
                        continue
                await db.execute("DELETE FROM role_bindings WHERE id=?", b["id"])
                n += 1
            if n:
                await _after_access_change(user["id"])
        if n:
            audit.detail(request, "local password set: %d SSO-derived role binding(s) removed" % n)
    if body.remove_password:
        current = request.cookies.get(security.COOKIE_NAME)
        for sql in ("DELETE FROM webauthn_credentials WHERE user_id=?",
                    "DELETE FROM recovery_codes WHERE user_id=?",
                    "UPDATE users SET totp_enabled=0, totp_secret_encrypted=NULL,"
                    " totp_last_counter=NULL WHERE id=?"):
            await db.execute(sql, user["id"])
        await db.execute("DELETE FROM web_sessions WHERE user_id=? AND token_hash!=?",
                         user["id"], security.sha256_hex(current) if current else "")
        security.clear_stepup_for(user["id"])
        security.bump_forward_epoch(user["id"])
        audit.detail(request, "local password removed (SSO-only from now on; passkeys, 2FA and "
                              "other sessions revoked)")
        email_alerts.notify_security_change(
            "local password removed; the account signs in with SSO only", security.client_ip(request),
            user["email"], user_id=user["id"], what_key="local_password_removed")
        return {"ok": True, "email": email}
    # dacă s-a schimbat parola, invalidează celelalte sesiuni web (nu pe cea curentă)
    if body.new_password:
        current = request.cookies.get(security.COOKIE_NAME)
        await db.execute(
            "DELETE FROM web_sessions WHERE user_id=? AND token_hash!=?",
            user["id"], security.sha256_hex(current) if current else "")
        security.clear_stepup_for(user["id"])   # H1: rotirea parolei închide ferestrele de step-up
        security.bump_forward_epoch()           # M3: și invalidează token-urile de port-forward
        await shares.revoke_all_shares()              # M3-shares: rotirea parolei omoară share-urile derivate
        await shares.revoke_replay_links()            # …şi link-urile de replay (aceeaşi regulă, globală)
    # Modulul de alerte promitea asta din prima zi („schimbare de parolă"), dar nimeni nu chema
    # alerta: o parolă schimbată de un cookie furat trecea neanunţată (3.5.2). Emailul vechi
    # primeşte tot alerta — `cfg["to"]` e cutia de alerte a instanţei, nu adresa contului.
    changed = [w for w, on in (("password", bool(body.new_password)),
                               ("email (%s → %s)" % (user["email"], email), email != user["email"])) if on]
    if changed:
        pw_on, em_on = bool(body.new_password), email != user["email"]
        email_alerts.notify_security_change("account %s changed" % " and ".join(changed),
                                            security.client_ip(request), user["email"],
                                            user_id=user["id"],
                                            what_key=("password_email_changed" if pw_on and em_on else
                                                      "password_changed" if pw_on else "email_changed"),
                                            what_params={"old": user["email"], "new": email})
    return {"ok": True, "email": email}


# ---------------------------------------------------------------------------
# TOTP (2FA opțional peste parolă). Passkey-urile rămân o cale separată.
# ---------------------------------------------------------------------------

# ── [totp] TOTP status + recovery codes (setup/activate further down, [totp]) ─────────────────────

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
    # 3.6: doar hosturile pe care contul le VEDE — numărul total ar fi un oracol de flotă
    vis = await authz.visible_hosts(await authz.grants_for_user(user["id"]), "host.view")
    n2fa = sum(1 for r in await db.fetchall("SELECT id FROM hosts WHERE require_2fa=1")
               if authz.in_visible(vis, r["id"]))
    return {"enabled": bool(user["totp_enabled"]),
            "recovery_remaining": remaining["c"] if remaining else 0,
            "passkeys": pk["c"] if pk else 0,
            "hosts_2fa": n2fa,
            "single_passkey_risk": bool(pk and pk["c"] == 1 and n2fa > 0)}


class TotpSetup(BaseModel):
    current_password: str = ""


# ── [accounts] Conturi + roluri (3.6.0) ─────────────────────────────────────────────────
# Până la 3.5 orice cont era administrator deplin peste toată flota (atribuire, nu izolare).
# De la 3.6 fiecare cont are LEGĂTURI de rol (docs/design/ROLES-AND-SSH.md, authz.py): Owner /
# Admin / Operator / Viewer peste un scope (toată flota, un folder, un tag, un host). Migrarea a
# făcut din fiecare cont existent Owner @ all, deci o instalare cu un singur om nu vede nimic nou.
# Un cont NOU nu primeşte nimic implicit („fără acces încă"); rolul se alege în acelaşi dialog.
# Schimbările de legături sunt de clasa credenţialelor: parolă (sau re-auth SSO) + al doilea
# factor, auditate, alertate. Regulile anti-escaladare stau în `authz.check_can_grant`.

class UserIn(BaseModel):
    email: str
    password: str
    current_password: str = ""     # re-auth: un cont nou = încă o cheie la regat
    totp_code: str = ""            # al doilea factor (second_gate): TOTP/recovery dacă 2FA e activ
    email_code: str = ""           # …sau codul pe email, de pe un dispozitiv nou fără 2FA
    stepup_grant: str = ""         # conturi SSO: grant passkey account-scope (host_id=0)
    # rolul iniţial (opţional): gol = fără acces încă (implicit, NICIODATĂ Owner din oficiu)
    role: str = ""
    role_id: int = 0               # 3.6.2: orice rol (şi custom) după id
    scope_kind: str = "folder"
    scope_value: str = ""
    # 3.6.10: rolul iniţial poate fi temporar (None = permanent) — şi TREBUIE să fie, cel mult până
    # la sfârşitul dreptului tău, dacă tu însuţi ai acces temporar (revizuirea 3.6.10)
    expires: Optional[float] = None
    # 3.6.10: un rol cu ⚑ peste un scope cu un host „crown jewel" se acordă doar confirmat
    confirm_crown_jewel: bool = False


class ReauthOnly(BaseModel):
    current_password: str = ""
    totp_code: str = ""         # al doilea factor (second_gate) — folosit la ştergerea de cont
    email_code: str = ""
    stepup_grant: str = ""


class BindingIn(BaseModel):
    role: str = ""                 # rol predefinit după cheie…
    role_id: int = 0               # …sau orice rol (şi custom, 3.6.2) după id
    scope_kind: str = "all"
    scope_value: str = ""
    # 3.6.10: legătură temporară — momentul (epoch) la care expiră; None = permanentă
    expires: Optional[float] = None
    confirm_crown_jewel: bool = False
    current_password: str = ""
    totp_code: str = ""
    email_code: str = ""
    stepup_grant: str = ""


class BindingExpiryIn(BaseModel):
    """3.6.10: schimbă sfârşitul unei legături existente (None = devine permanentă)."""
    expires: Optional[float] = None
    # o prelungire e o acordare: ⚑ peste un host crown-jewel cere confirmare (revizuirea 3.6.10)
    confirm_crown_jewel: bool = False
    current_password: str = ""
    totp_code: str = ""
    email_code: str = ""
    stepup_grant: str = ""


async def _user_bindings(uid: int) -> list:
    return [authz.binding_json(b) for b in await authz.load_bindings(uid)]


async def _users_json(user, grants) -> list:
    manage = grants.has_global("users.manage")
    rows = await db.fetchall(
        "SELECT u.id, u.email, u.created, u.totp_enabled, u.sso_subject, u.local_password,"
        " u.last_login, u.last_login_method, u.disabled, u.disabled_at, u.disabled_by,"
        " u.scim_managed, u.scim_id, u.scim_display_name,"
        " (SELECT COUNT(*) FROM webauthn_credentials c WHERE c.user_id=u.id) AS passkeys"
        " FROM users u ORDER BY u.created")
    since = None
    if manage:
        s = await db.fetchone("SELECT value FROM app_settings WHERE key='last_login_since'")
        try:
            since = float(s["value"]) if s else None
        except (TypeError, ValueError):
            since = None
    shown = [r for r in rows if manage or r["id"] == user["id"]]   # fără users.manage: doar propriul rând (§A.6.3)
    # PF-01/SC-14: legăturile tuturor conturilor afişate într-O interogare, nu una pe cont
    bindings_by_uid = await authz.load_bindings_for([r["id"] for r in shown])
    out = []
    for r in shown:
        row = {"id": r["id"], "email": r["email"], "created": r["created"],
               "totp": bool(r["totp_enabled"]), "passkeys": r["passkeys"],
               "sso": bool(r["sso_subject"]),
               # 3.6.2: cu parolă locală, grupurile SSO nu-i dau roluri (ssomap)
               "local_password": r["local_password"] is None or bool(r["local_password"]),
               "is_self": r["id"] == user["id"],
               "bindings": [authz.binding_json(b) for b in bindings_by_uid.get(r["id"], [])],
               # 3.6.11: dezactivat (SCIM) + administrat de IdP prin SCIM
               "disabled": bool(r["disabled"]),
               "disabled_at": r["disabled_at"] if r["disabled"] else None,
               "disabled_by": (r["disabled_by"] or None) if r["disabled"] else None,
               "scim": bool(r["scim_managed"]),
               "scim_linked": bool(r["scim_id"]),
               "display_name": r["scim_display_name"] or None}
        if manage:
            # 3.6.10: ultima autentificare şi cum — doar pentru users.manage (cine administrează
            # conturile vede conturile nefolosite). `tracked_since`: un cont mai vechi decât
            # înregistrarea, fără ştampilă, e „neînregistrat", nu „niciodată".
            row["last_login"] = r["last_login"]
            row["last_login_method"] = r["last_login_method"] or None
            row["last_login_tracked_since"] = since
        out.append(row)
    return out


@router.get("/api/users")
async def list_users(request: Request, user=Depends(authz.perm('users.manage', list=True))):
    return await _users_json(user, authz.grants_of(request))


async def _after_access_change(uid: int) -> None:
    """O legătură s-a schimbat: cache-ul de permisiuni moare, socket-urile lungi re-verifică
    ACUM, biletele de forward ale contului mor (re-handshake → forward.use re-verificat), iar
    accesul DERIVAT pe care nu-l mai poate acorda (share live, share writable, link de replay)
    e retras pe hosturile unde a pierdut dreptul."""
    authz.bump_epoch()
    security.bump_forward_epoch(uid)
    await shares.revoke_unauthorized_derived(uid)


def _role_label(role) -> str:
    """Cheia unui rol predefinit (ca în 3.6.0), numele unuia custom."""
    return role.key or role.name


def _crown_note(names: list) -> str:
    """3.6.10: sufixul de audit al unei acordări CONFIRMATE peste hosturi crown-jewel."""
    if not names:
        return ""
    return " — CONFIRMED over crown-jewel host(s): %s" % ", ".join(names[:authz.CROWN_LIST_MAX])


def _expiry_label(expires) -> str:
    return "" if expires is None else " until %s" % time.strftime(
        "%Y-%m-%d %H:%M UTC", time.gmtime(expires))


# un rol dispărut (n-ar trebui: un rol legat nu se poate şterge) e tratat ca „toate
# permisiunile" — deci doar cine le are pe toate (un Owner) mai poate atinge legătura (fail-closed)
_UNKNOWN_ROLE = authz.RoleInfo(0, "", "?", authz.HOST_PERMS | authz.GLOBAL_PERMS, False)


async def _fresh_grants(user, perm: str):
    """Drepturile CURENTE ale contului (fără cache: epoca s-a putut schimba chiar acum). Pentru
    re-verificarea de sub `authz.bindings_lock`, imediat înainte de scriere (tiparul cursei din 3.6.0)."""
    authz.forget_cached(user["id"])
    g = await authz.grants_for_user(user["id"])
    if not g.has_global(perm):
        raise ApiError(403, "authz.denied", "your role does not allow this here (%s)" % perm,
                       vars={"perm": perm})
    return g


_NOT_A_GRANT = object()


async def _recheck_granter(user, role, kind, value, target_uid, removing=False,
                           expires=_NOT_A_GRANT):
    """Regulile de acordare, din nou, pe drepturile CURENTE ale celui care acordă ŞI pe definiţia
    CURENTĂ a rolului (un rol custom s-a putut edita între timp). Chemată sub `authz.bindings_lock`,
    imediat înainte de scriere. `expires` (sfârşitul acordării, None = permanentă): şi regula
    „nu acorzi mai mult decât ţine propriul tău drept" (revizuirea 3.6.10). → rolul proaspăt."""
    g = await _fresh_grants(user, "users.manage")
    if target_uid is not None:
        await authz.check_target(g, target_uid)
    fresh = (await authz.role_by_id(role.id)) if role.id else role
    if fresh is None:
        raise ApiError(409, "role.gone", "that role was deleted meanwhile")
    await authz.check_can_grant(g, fresh, kind, value, removing=removing)
    if expires is not _NOT_A_GRANT:
        await authz.check_grant_lifetime(g, fresh, kind, value, expires)
    return fresh


async def _check_can_strip(g, uid: int) -> None:
    """Ştergerea unui cont = scoaterea TUTUROR legăturilor lui: o poţi face doar dacă ai putea
    scoate fiecare legătură (3.6.2 — cu rolurile custom, „doar Owner atinge Owner" nu mai ajunge)."""
    await authz.check_target(g, uid)
    for b in await authz.load_bindings(uid):
        info = (await authz.role_by_id(b.role_id)) or _UNKNOWN_ROLE
        await authz.check_can_grant(g, info, b.scope_kind, b.scope_value, removing=True)


@router.post("/api/users")
async def create_user(body: UserIn, request: Request, user=Depends(authz.perm('users.manage'))):
    grants = authz.grants_of(request)
    role = None
    kind = value = expires = None
    if (body.role or "").strip() or body.role_id:
        role = await authz.resolve_role(body.role, body.role_id)
        kind, value = authz.normalize_scope(body.scope_kind, body.scope_value)
        expires = authz.normalize_expiry(body.expires)
        # anti-escaladare ÎNAINTE de orice efect (şi înainte de a consuma al doilea factor)
        await authz.check_can_grant(grants, role, kind, value)
        await authz.check_grant_lifetime(grants, role, kind, value, expires)
        await authz.check_crown(role, kind, value, body.confirm_crown_jewel)
    await stepup.reauth_for_access_change(user, request, body, "create a new WebTerm account")
    email = body.email.strip().lower()
    if not security.valid_email(email):
        raise ApiError(400, "account.badEmail", "invalid email")
    _check_password(body.password)
    if await db.fetchone("SELECT id FROM users WHERE email=?", email):
        raise ApiError(409, "account.emailTaken", "an account with that email already exists")
    pw = await security.hash_password_async(body.password)
    crown = []
    async with authz.bindings_lock:
        if role:
            role = await _recheck_granter(user, role, kind, value, None, expires=expires)
            crown = await authz.check_crown(role, kind, value, body.confirm_crown_jewel)
            await authz.check_owner_expiry(role, kind, expires, 0)
        uid = await db.execute("INSERT INTO users(id, email, password_hash, created)"
                               " VALUES(" + db.NEXT_USER_ID_SQL + ",?,?,?)",
                               email, pw, time.time())
        if role:
            await db.execute(
                "INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                " expires, created, created_by_id) VALUES(?,?,?,?,'manual',?,?,?)",
                uid, role.id, kind, value, expires, time.time(), user["id"])
        authz.bump_epoch()
    rdesc = ("%s @ %s%s" % (_role_label(role), authz.scope_label(kind, value), _expiry_label(expires))
             if role else "none")
    log.info("new account created: %s (by %s, role %s)", email, user["email"], rdesc)
    audit.detail(request, "account %s created, role %s%s" % (email, rdesc, _crown_note(crown)))
    # un cont nou: cel mai valoros eveniment de securitate. Ajunge pe email ŞI webhook (via
    # _fire) şi în istoricul celor cu security.view, ca oricare schimbare de credenţiale.
    email_alerts.notify_security_change("a new WebTerm account was created (%s)" % email,
                                        security.client_ip(request), user["email"], fleet=True,
                                        what_key="account_created", what_params={"account": email})
    return await _users_json(user, grants)


# POST, nu DELETE: ştergerea cere parola în corp, iar un DELETE cu corp e prost suportat de
# clienţi (httpx nici nu-l oferă). Alternativa — parola în query string — ar fi ajuns în
# jurnalul de audit şi în logurile proxy-ului.
@router.post("/api/users/{uid}/delete")
async def delete_user(uid: int, body: ReauthOnly, request: Request,
                      user=Depends(authz.perm('users.manage'))):
    grants = authz.grants_of(request)
    if uid == user["id"]:
        # ştergerea propriului cont din propria sesiune = te blochezi la jumătatea operaţiei
        raise ApiError(400, "account.deleteSelf", "you cannot delete your own account; do it from another one")
    row = await db.fetchone("SELECT email FROM users WHERE id=?", uid)
    if not row:
        raise ApiError(404, "user.missing", "no such account")
    # Admin nu atinge Owner-ii (§A.5): ştergerea unui Owner e preluarea instanţei.
    if await authz.is_owner_user(uid) and not grants.is_owner():
        raise ApiError(403, "authz.ownerOnly", "only an Owner can delete an Owner")
    await _check_can_strip(grants, uid)
    await stepup.reauth_for_access_change(user, request, body, "delete a WebTerm account")
    async with authz.bindings_lock:
        # drepturile celui care şterge, pe starea de ACUM (o retrogradare concurentă contează)
        authz.forget_cached(user["id"])
        g = await authz.grants_for_user(user["id"])
        if not g.has_global("users.manage"):
            raise ApiError(403, "authz.denied", "your role does not allow this here (users.manage)",
                           vars={"perm": "users.manage"})
        if await authz.is_owner_user(uid) and not g.is_owner():
            raise ApiError(403, "authz.ownerOnly", "only an Owner can delete an Owner")
        await _check_can_strip(g, uid)
        # verificările care contează pentru blocare se refac SUB lock (check-then-act atomic)
        n = (await db.fetchone("SELECT COUNT(*) AS c FROM users"))["c"]
        if n <= 1:
            raise ApiError(400, "account.deleteLast", "you cannot delete the last account")
        # „ultimul Owner" = ultimul ACTIV (un Owner dezactivat nu numără — owner_count): un cont
        # dezactivat se poate şterge fără să conteze ca ultimul (is_owner_user îl vede ca Owner)
        if (await authz.grants_for_user(uid)).is_owner() \
                and await owners.owner_count(exclude_user=uid) < 1:
            raise ApiError(400, "authz.lastOwner", "you cannot remove the last Owner")
        # RB-06: nici ultimul Owner permanent CU PAROLĂ LOCALĂ (contul break-glass) — altfel o
        # pană a IdP-ului nu mai lasă pe nimeni să intre; aceeaşi regulă ca la remove_password
        if await owners.last_break_glass(uid):
            raise ApiError(409, "account.lastBreakGlassTarget",
                           owners.LAST_BREAK_GLASS_DETAIL % "this account is")
        # tot ce ţinea de el moare odată cu el: sesiuni web, passkey-uri, coduri de recuperare,
        # IP-uri cunoscute, legături de rol. Altfel un cookie al contului şters ar rămâne valid.
        for sql in ("DELETE FROM web_sessions WHERE user_id=?",
                    "DELETE FROM webauthn_credentials WHERE user_id=?",
                    "DELETE FROM recovery_codes WHERE user_id=?",
                    "DELETE FROM seen_logins WHERE user_id=?",
                    "DELETE FROM alerts WHERE user_id=?",          # istoricul de alerte (3.5.11)
                    "DELETE FROM alert_prefs WHERE user_id=?",
                    "DELETE FROM role_bindings WHERE user_id=?",   # 3.6
                    "DELETE FROM scim_group_members WHERE user_id=?",   # 3.6.18: fără FK/cascade (SC-02)
                    "DELETE FROM split_views WHERE user_id=?",
                    "DELETE FROM pending_ssh_keys WHERE user_id=?",
                    "DELETE FROM push_subscriptions WHERE user_id=?",   # abonamentele de push
                    "DELETE FROM users WHERE id=?"):
            await db.execute(sql, uid)
        # 3.6: id-ul nu se mai refoloseşte (prag monoton), iar urmele lui primesc id-ul NEGAT —
        # rămân în jurnal (emailul e în `actor`), dar nu mai sunt „ale" nimănui: un snippet sau o
        # sesiune vie a contului şters nu devin editabile de un cont nou, rândurile de audit nu
        # devin „propriile rânduri" ale altcuiva.
        await db.raise_user_id_floor(uid, row["email"])
        for sql in ("UPDATE audit_log SET actor_id=? WHERE actor_id=?",
                    "UPDATE snippets SET created_by_id=? WHERE created_by_id=?",
                    "UPDATE sessions SET created_by_id=? WHERE created_by_id=?",
                    "UPDATE sessions SET share_by_id=? WHERE share_by_id=?",
                    "UPDATE command_history SET user_id=? WHERE user_id=?",
                    "UPDATE role_bindings SET created_by_id=? WHERE created_by_id=?",
                    "UPDATE oidc_group_roles SET created_by_id=? WHERE created_by_id=?"):
            await db.execute(sql, -uid, uid)
        authz.bump_epoch()
    # …„tot" trebuia să însemne şi asta. Token-urile de automatizare emise de contul şters îi
    # supravieţuiau până la expirare (până la un an), semnalat de un audit extern. Ele NU cer
    # cont ca să funcţioneze — sunt credenţiale de sine stătătoare — deci ştergerea contului
    # arăta ca o revocare completă fără să fie una. Le numărăm ca să apară în jurnal: cine
    # şterge un cont trebuie să vadă ce automatizări a oprit odată cu el.
    # `created_by_id` ESTE cheia — şi singura (a doua re-revizuire 3.6.11): tokenurile de dinainte
    # de migrare au primit id-ul o dată, din email (authz.seed, la pornire); unul rămas fără id e
    # deja mort (grants_for_token). După email NU mai ştergem: adresa poate fi acum în
    # `created_by` la tokenurile ALTUI cont (email refolosit) — le-am fi revocat din greşeală.
    ntok = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM api_tokens WHERE created_by_id=?", uid))["c"]
    await db.execute("DELETE FROM api_tokens WHERE created_by_id=?", uid)
    await accounts.revoke_enroll_groups(uid, row["email"])   # revizuirea 3.6.11: şi tokenurile de grup
    security.clear_stepup_for(uid)
    security.bump_forward_epoch(uid)      # şi biletele lui de port-forward, ca la logout
    await shares.revoke_all_shares(row["email"], uid)
    await shares.revoke_replay_links(uid)
    if ntok:
        log.warning("account deleted: revoked %d automation token(s) issued by %s",
                    ntok, row["email"])
    log.warning("account deleted: %s (by %s)", row["email"], user["email"])
    return await _users_json(user, grants)


@router.get("/api/users/{uid}/bindings")
async def list_bindings(uid: int, user=Depends(authz.perm('users.manage'))):
    if not await db.fetchone("SELECT 1 FROM users WHERE id=?", uid):
        raise ApiError(404, "user.missing", "no such account")
    return {"bindings": await _user_bindings(uid)}


@router.post("/api/users/{uid}/bindings")
async def add_binding(uid: int, body: BindingIn, request: Request,
                      user=Depends(authz.perm('users.manage'))):
    """Adaugă o legătură (rol @ scope). Reguli (§A.6.6): niciodată pe tine însuţi; doar un
    Owner atinge Owner-ii sau acordă Owner; rolul nu poate depăşi ce ai tu peste acel scope."""
    grants = authz.grants_of(request)
    if uid == user["id"]:
        raise ApiError(403, "authz.selfBinding", "you cannot change your own access")
    target = await db.fetchone("SELECT email FROM users WHERE id=?", uid)
    if not target:
        raise ApiError(404, "user.missing", "no such account")
    role = await authz.resolve_role(body.role, body.role_id)
    kind, value = authz.normalize_scope(body.scope_kind, body.scope_value)
    expires = authz.normalize_expiry(body.expires)
    await authz.check_target(grants, uid)
    await authz.check_can_grant(grants, role, kind, value)
    await authz.check_grant_lifetime(grants, role, kind, value, expires)
    # 3.6.10: ⚑ peste un host crown-jewel — refuzat fără confirmare, ÎNAINTE de re-auth (al doilea
    # factor nu se consumă pe o cerere care oricum se întoarce cu 409)
    await authz.check_crown(role, kind, value, body.confirm_crown_jewel)
    await stepup.reauth_for_access_change(user, request, body, "change a WebTerm account's access")
    async with authz.bindings_lock:
        # 3.6 (cursă): între verificare şi scriere au trecut re-auth-ul şi al doilea factor — un
        # Admin retrogradat între timp nu are voie să-şi vadă acordarea aterizând. Re-verificăm
        # SUB lock, pe drepturile de ACUM (şi pe definiţia de ACUM a rolului).
        role = await _recheck_granter(user, role, kind, value, uid, expires=expires)
        crown = await authz.check_crown(role, kind, value, body.confirm_crown_jewel)
        await authz.check_owner_expiry(role, kind, expires, uid)
        dup = await db.fetchone(
            "SELECT id, source FROM role_bindings WHERE user_id=? AND role_id=? AND scope_kind=?"
            " AND scope_value=?", uid, role.id, kind, value)
        if dup and dup["source"] == "sso" and expires is None:
            # 3.6.2: aceeaşi legătură venită din SSO devine MANUALĂ (nu mai pleacă la următoarea
            # sincronizare) — exact ce a cerut cel care acordă, cu aceleaşi verificări trecute
            await db.execute("UPDATE role_bindings SET source='manual', created_by_id=?"
                             " WHERE id=?", user["id"], dup["id"])
        elif dup:
            # 3.6.10: o legătură temporară peste una SSO ar SCURTA accesul dat de grup (la expirare
            # pleacă amândouă) — refuzăm, în loc să schimbăm tăcut sensul legăturii existente
            raise ApiError(409, "authz.bindingExists", "that account already has this role here")
        else:
            try:
                await db.execute(
                    "INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                    " expires, created, created_by_id) VALUES(?,?,?,?,'manual',?,?,?)",
                    uid, role.id, kind, value, expires, time.time(), user["id"])
            except sqlite3.IntegrityError:
                raise ApiError(409, "authz.bindingExists", "that account already has this role here")
        await _after_access_change(uid)
    role = _role_label(role)
    what = "%s granted %s @ %s%s" % (target["email"], role, authz.scope_label(kind, value),
                                     _expiry_label(expires))
    audit.detail(request, "role " + what + _crown_note(crown))
    log.warning("role binding added: %s (by %s)", what, user["email"])
    ip = security.client_ip(request)
    email_alerts.notify_security_change("role granted: " + what, ip, user["email"], fleet=True,
                                        what_key="role_granted",
                                        what_params={"account": target["email"], "role": role,
                                                     "scope": authz.scope_label(kind, value)})
    email_alerts.notify_security_change("your access changed: " + what, ip, target["email"],
                                        user_id=uid, what_key="access_changed",
                                        what_params={"role": role,
                                                     "scope": authz.scope_label(kind, value)})
    return {"bindings": await _user_bindings(uid)}


@router.post("/api/users/{uid}/bindings/{bid}/delete")
async def remove_binding(uid: int, bid: int, body: ReauthOnly, request: Request,
                         user=Depends(authz.perm('users.manage'))):
    """Scoate o legătură. POST cu corp (re-auth), ca ştergerea de cont. Ultimul Owner rămâne.
    RB-02 (audit 2026-10-17): o legătură venită din SSO (`source='sso'`) NU se scoate de aici —
    ssomap._apply_locked o re-adaugă la următorul login/step-up SSO sau push SCIM, deci
    „revocarea" era o iluzie (audit „lost …", alertă, iar rolul revenea în câteva ore). Acelaşi
    409 ca ruta soră de expiry: se schimbă maparea grupului (sau grupul din IdP)."""
    grants = authz.grants_of(request)
    if uid == user["id"]:
        raise ApiError(403, "authz.selfBinding", "you cannot change your own access")
    row = await db.fetchone(
        "SELECT b.id, b.role_id, b.scope_kind, b.scope_value, b.source, r.key AS role_key,"
        " r.name AS role_name, u.email FROM role_bindings b JOIN roles r ON r.id=b.role_id"
        " JOIN users u ON u.id=b.user_id WHERE b.id=? AND b.user_id=?", bid, uid)
    if not row:
        raise ApiError(404, "authz.bindingMissing", "no such role binding")
    if (row["source"] or "") == "sso":
        raise ApiError(409, "authz.ssoBinding",
                       "this role comes from an SSO group; change the group mapping instead")
    if (row["role_key"] == "owner" or await authz.is_owner_user(uid)) and not grants.is_owner():
        raise ApiError(403, "authz.ownerOnly", "only an Owner can change an Owner's access")
    await authz.check_target(grants, uid)
    # a scoate un rol e tot o schimbare de acces asupra cuiva — doar în interiorul scope-ului tău.
    # 3.6.2: şi pentru rolurile custom (înainte erau sărite: nu existau)
    info = (await authz.role_by_id(row["role_id"])) or _UNKNOWN_ROLE
    await authz.check_can_grant(grants, info, row["scope_kind"], row["scope_value"], removing=True)
    await stepup.reauth_for_access_change(user, request, body, "change a WebTerm account's access")
    async with authz.bindings_lock:
        await _recheck_granter(user, info, row["scope_kind"], row["scope_value"], uid,
                               removing=True)
        if (row["role_key"] == "owner" and row["scope_kind"] == "all"
                and await owners.owner_count(exclude_binding=bid) < 1):
            raise ApiError(400, "authz.lastOwner", "you cannot remove the last Owner")
        # RB-06: legătura Owner @ all a ultimului Owner permanent cu parolă locală rămâne (contul
        # break-glass) — un alt Owner permanent fără parolă nu ţine locul la o pană a IdP-ului
        if await owners.last_break_glass(uid, exclude_binding=bid):
            raise ApiError(409, "account.lastBreakGlassTarget",
                           owners.LAST_BREAK_GLASS_DETAIL % "this account is")
        # RB-02: re-auth-ul a fost un punct de suspendare — o sincronizare SSO a putut adopta
        # legătura între timp; ştergem DOAR ce nu e din SSO (fail closed: 0 rânduri = 409)
        gone = await db.execute_returning(
            "DELETE FROM role_bindings WHERE id=? AND user_id=? AND COALESCE(source, '')<>'sso'"
            " RETURNING id", bid, uid)
        if gone is None:
            raise ApiError(409, "authz.ssoBinding",
                           "this role comes from an SSO group; change the group mapping instead")
        await _after_access_change(uid)
    rlabel = row["role_key"] or row["role_name"]
    what = "%s lost %s @ %s" % (row["email"], rlabel,
                                authz.scope_label(row["scope_kind"], row["scope_value"]))
    audit.detail(request, "role " + what)
    log.warning("role binding removed: %s (by %s)", what, user["email"])
    ip = security.client_ip(request)
    scope = authz.scope_label(row["scope_kind"], row["scope_value"])
    email_alerts.notify_security_change("role removed: " + what, ip, user["email"], fleet=True,
                                        what_key="role_removed",
                                        what_params={"account": row["email"],
                                                     "role": rlabel, "scope": scope})
    email_alerts.notify_security_change("your access changed: " + what, ip, row["email"],
                                        user_id=uid, what_key="access_changed",
                                        what_params={"role": rlabel, "scope": scope})
    return {"bindings": await _user_bindings(uid)}


async def sweep_expired_bindings() -> int:
    """3.6.10, from the reaper (main._session_reaper, every minute): delete the bindings whose
    time is up. Access already ended at read time (authz.load_bindings) — this tidies the rows,
    wakes live sockets (epoch), revokes derived access (live shares, replay links) the account
    can no longer create, leaves one audit row per binding and tells the person."""
    gone = await authz.sweep_expired_bindings()
    for uid in {g["user_id"] for g in gone}:
        security.bump_forward_epoch(uid)
        await shares.revoke_unauthorized_derived(uid)
    for g in gone:
        scope = authz.scope_label(g["scope_kind"], g["scope_value"])
        what = "role binding expired: %s lost %s @ %s" % (g["email"] or "#%s" % g["user_id"],
                                                          g["role"], scope)
        await audit.record(time.time(), "system", "-", "SYSTEM", "/janitor/binding-expired", 200,
                           what, actor_id=None, via="janitor")
        log.warning(what)
        if g["email"]:
            email_alerts.notify_security_change(
                "your access changed: " + what, "-", g["email"], user_id=g["user_id"],
                what_key="access_expired", what_params={"role": g["role"], "scope": scope})
    return len(gone)


@router.post("/api/users/{uid}/bindings/{bid}/expiry")
async def set_binding_expiry(uid: int, bid: int, body: BindingExpiryIn, request: Request,
                             user=Depends(authz.perm('users.manage'))):
    """3.6.10: change when a binding ends — `expires: null` makes it permanent. Making it last
    LONGER (or forever) is a grant: the granting rules apply. Making it end SOONER is a removal:
    the removal rules apply, plus the last permanent Owner can never be made time-bound. SSO
    bindings follow their group (change the mapping instead); an expired binding is gone."""
    grants = authz.grants_of(request)
    if uid == user["id"]:
        raise ApiError(403, "authz.selfBinding", "you cannot change your own access")
    new = authz.normalize_expiry(body.expires)

    async def _current():
        row = await db.fetchone(
            "SELECT b.id, b.role_id, b.scope_kind, b.scope_value, b.source, b.expires,"
            " r.key AS role_key, r.name AS role_name, u.email FROM role_bindings b"
            " JOIN roles r ON r.id=b.role_id JOIN users u ON u.id=b.user_id"
            " WHERE b.id=? AND b.user_id=?", bid, uid)
        if not row or (row["expires"] is not None and row["expires"] <= time.time()):
            raise ApiError(404, "authz.bindingMissing", "no such role binding")
        if (row["source"] or "") == "sso":
            raise ApiError(409, "authz.ssoBinding",
                           "this role comes from an SSO group; change the group mapping instead")
        old = row["expires"]
        return row, old, new is not None and (old is None or new < old)

    row, old, shorter = await _current()
    if (row["role_key"] == "owner" or await authz.is_owner_user(uid)) and not grants.is_owner():
        raise ApiError(403, "authz.ownerOnly", "only an Owner can change an Owner's access")
    await authz.check_target(grants, uid)
    info = (await authz.role_by_id(row["role_id"])) or _UNKNOWN_ROLE
    await authz.check_can_grant(grants, info, row["scope_kind"], row["scope_value"],
                                removing=shorter)
    if not shorter:
        # mai lung (sau permanent) = o acordare: nu peste sfârşitul propriului tău drept, şi ⚑ peste
        # un host crown-jewel cere confirmarea explicită, ca la o legătură nouă (înainte de re-auth)
        await authz.check_grant_lifetime(grants, info, row["scope_kind"], row["scope_value"], new)
        await authz.check_crown(info, row["scope_kind"], row["scope_value"], body.confirm_crown_jewel)
    await stepup.reauth_for_access_change(user, request, body, "change a WebTerm account's access")
    async with authz.bindings_lock:
        # revizuirea 3.6.10: re-auth-ul a fost un punct de suspendare — legătura s-a putut schimba
        # (alt sfârşit, scoasă, expirată). Totul se decide din nou pe rândul de ACUM: „mai scurt"
        # (reguli de scoatere) sau „mai lung" (reguli de acordare) se recalculează aici.
        before = old
        row, old, shorter = await _current()
        if old != before:
            raise ApiError(409, "authz.bindingChanged",
                           "this role binding was changed meanwhile; reload and try again")
        info = (await authz.role_by_id(row["role_id"])) or _UNKNOWN_ROLE
        info = await _recheck_granter(user, info, row["scope_kind"], row["scope_value"], uid,
                                      removing=shorter,
                                      **({} if shorter else {"expires": new}))
        crown = [] if shorter else await authz.check_crown(info, row["scope_kind"], row["scope_value"],
                                                           body.confirm_crown_jewel)
        if old is None and new is not None:
            await authz.check_owner_expiry(info, row["scope_kind"], new, uid, exclude_binding=bid)
        # gardă de concurenţă pe valoarea citită (toate scrierile de legături ţin lock-ul, deci
        # n-ar trebui să se întâmple — dar dacă se întâmplă, refuzăm în loc să scriem pe ghicite)
        if not await db.execute_returning(
                "UPDATE role_bindings SET expires=? WHERE id=? AND user_id=? AND expires IS ?"
                " RETURNING id", new, bid, uid, old):
            raise ApiError(409, "authz.bindingChanged",
                           "this role binding was changed meanwhile; reload and try again")
        await _after_access_change(uid)
    rlabel = row["role_key"] or row["role_name"]
    scope = authz.scope_label(row["scope_kind"], row["scope_value"])
    what = "%s: %s @ %s now %s" % (row["email"], rlabel, scope,
                                   "permanent" if new is None else "ends" + _expiry_label(new))
    audit.detail(request, "role " + what + _crown_note(crown))
    log.warning("role binding expiry changed: %s (by %s)", what, user["email"])
    email_alerts.notify_security_change("your access changed: " + what, security.client_ip(request),
                                        row["email"], user_id=uid, what_key="access_changed",
                                        what_params={"role": rlabel, "scope": scope})
    return {"bindings": await _user_bindings(uid)}


@router.get("/api/authz/explain")
async def explain_access(request: Request, user_id: int = Query(..., alias="user"),
                         host_id: int = Query(..., alias="host"),
                         user=Depends(security.require_user)):
    """3.6.10 (§A.9, §A.11.9): why an account can — or cannot — do things on one host.

    Who may ask: anyone about THEMSELVES; about someone else only with `users.manage`. Either
    way the host must be visible to the CALLER (404, the same body as a host that does not exist
    — a scoped admin learns nothing about hosts outside their scope, and a 403 is never given
    for a host the caller cannot see). The target account is looked up only after the caller
    proved users.manage, so a plain user cannot probe which account ids exist."""
    grants = await authz.grants_for_user(user["id"])
    if user_id != user["id"]:
        if not grants.has_global("users.manage"):
            raise ApiError(403, "authz.denied", "your role does not allow this here (users.manage)",
                           vars={"perm": "users.manage"})
    ref = await authz.host_ref(host_id)
    if ref is None or "host.view" not in grants.on(ref):
        raise authz.not_found("host_id")
    if user_id != user["id"]:
        target = await db.fetchone("SELECT id, email FROM users WHERE id=?", user_id)
        if not target:
            raise ApiError(404, "user.missing", "no such account")
        email = target["email"]
    else:
        email = user["email"]
    # 3.6.10 (review): the crown-jewel mark only for an Owner or users.manage (as in /api/hosts)
    out = await authz.explain(user_id, host_id, ref,
                              crown=grants.is_owner() or grants.has_global("users.manage"))
    out["user"] = {"id": user_id, "email": email, "self": user_id == user["id"]}
    return out


@router.get("/api/roles")
async def list_roles(request: Request,
                     user=Depends(authz.perm(('users.manage', 'roles.manage')))):
    """Catalogul de permisiuni (cu ⚑ = echivalent cu un shell) + rolurile predefinite (cu id)
    + rolurile custom (3.6.2), cu cât sunt folosite. `users.manage` are nevoie de listă ca să
    acorde, `roles.manage` ca să editeze."""
    return await authz.roles_json(authz.grants_of(request))


# ── [roles] Roluri custom (3.6.2; design „3.6.1", §A.6.6 regula 5) ───────────────────────────────
# Un rol custom = un set de permisiuni din catalog. Reguli, toate pe server:
#   * rolurile predefinite sunt IMUABILE (codul e sursa lor de adevăr, re-scrise la boot);
#   * anti-escaladare: orice permisiune din rol (setul VECHI şi cel NOU, la editare) trebuie
#     s-o ai tu peste toată instanţa (globale + cele de host de la o legătură `all`);
#   * editarea unui rol FOLOSIT (legături sau mapări SSO) schimbă accesul altora: cere şi
#     `users.manage`, şi aceeaşi regulă de ţintă ca la legături (doar un Owner atinge un rol pe
#     care-l are un Owner; nimeni nu atinge contul cuiva care are mai mult decât el);
#   * ştergerea unui rol folosit e REFUZATĂ (409 cu numărători) — întâi scoţi legăturile şi
#     mapările. Alegerea mai sigură: nicio revocare în masă tăcută dintr-un singur click;
#   * re-auth + al doilea factor, ca la legături; verificările se refac SUB `authz.bindings_lock`
#     imediat înainte de scriere; epoca creşte imediat (socket-urile re-verifică ACUM).

class RoleIn(BaseModel):
    name: str = ""
    description: str = ""
    perms: list[str] = []
    current_password: str = ""
    totp_code: str = ""
    email_code: str = ""
    stepup_grant: str = ""


async def _role_name_free(name: str, rid: Optional[int]) -> None:
    low = name.lower()
    clash = await db.fetchone(
        "SELECT 1 FROM roles WHERE (lower(name)=? OR lower(COALESCE(key,''))=?) AND id<>?",
        low, low, rid or 0)
    if clash or low in authz.BUILTIN_ROLES:
        raise ApiError(409, "role.nameTaken", "a role with that name already exists")
    # revizuirea 3.6.2: „Оwner" (O chirilic) nu e „Owner" pentru SQL, dar e pentru ochi
    others = [r["name"] for r in await db.fetchall(
        "SELECT name FROM roles WHERE builtin=0 AND id<>?", rid or 0)]
    authz.check_role_name_confusable(name, others)


async def _custom_role(rid: int) -> "authz.RoleInfo":
    role = await authz.role_by_id(rid)
    if role is None:
        raise ApiError(404, "role.missing", "no such role")
    if role.builtin:
        raise ApiError(403, "role.builtin", "built-in roles cannot be changed")
    return role


async def _role_users(rid: int) -> list:
    return [r["user_id"] for r in await db.fetchall(
        "SELECT DISTINCT user_id FROM role_bindings WHERE role_id=?", rid)]


async def _check_role_targets(g, rid: int) -> list:
    """Cine primeşte efectul unei editări. Un rol folosit = schimbare de acces asupra altora."""
    uids = await _role_users(rid)
    maps = (await db.fetchone("SELECT COUNT(*) AS c FROM oidc_group_roles WHERE role_id=?",
                              rid))["c"]
    if (uids or maps) and not g.has_global("users.manage"):
        raise ApiError(403, "authz.denied", "your role does not allow this here (users.manage)",
                       vars={"perm": "users.manage"})
    for uid in uids:
        await authz.check_target(g, uid)
    return uids


async def _role_used(rid: int) -> bool:
    """Legat de cineva sau mapat unui grup SSO (o editare schimbă accesul altora)."""
    use = await _role_in_use(rid)
    return bool(use["bindings"] or use["mappings"] or use["tokens"])   # a token's cap is access too


async def _role_in_use(rid: int) -> dict:
    b = (await db.fetchone("SELECT COUNT(*) AS c FROM role_bindings WHERE role_id=?", rid))["c"]
    m = (await db.fetchone("SELECT COUNT(*) AS c FROM oidc_group_roles WHERE role_id=?", rid))["c"]
    t = (await db.fetchone("SELECT COUNT(*) AS c FROM api_tokens WHERE role_id=?", rid))["c"]
    return {"bindings": b, "mappings": m, "tokens": t}


@router.post("/api/roles")
async def create_role(body: RoleIn, request: Request, user=Depends(authz.perm('roles.manage'))):
    grants = authz.grants_of(request)
    name, desc, perms = authz.validate_role_fields(body.name, body.description, body.perms)
    authz.check_can_define(grants, perms)
    await _role_name_free(name, None)
    await stepup.reauth_for_access_change(user, request, body, "create a role")
    async with authz.bindings_lock:
        g = await _fresh_grants(user, "roles.manage")
        authz.check_can_define(g, perms)
        await _role_name_free(name, None)
        n = (await db.fetchone("SELECT COUNT(*) AS c FROM roles WHERE builtin=0"))["c"]
        if n >= authz.CUSTOM_ROLES_MAX:
            raise ApiError(400, "role.tooMany", "too many custom roles (%d)" % authz.CUSTOM_ROLES_MAX,
                           vars={"max": authz.CUSTOM_ROLES_MAX})
        now = time.time()
        rid = await db.execute(
            "INSERT INTO roles(key, name, description, perms, builtin, created, updated)"
            " VALUES(NULL,?,?,?,0,?,?)", name, desc, json.dumps(sorted(perms)), now, now)
        authz.bump_epoch()
    shell = sorted(perms & authz.SHELL_PERMS)
    what = "role '%s' created: %s" % (name, ", ".join(sorted(perms)))
    audit.detail(request, what + (" (shell-equivalent: %s)" % ", ".join(shell) if shell else ""))
    log.warning("%s (by %s)", what, user["email"])
    email_alerts.notify_security_change(what, security.client_ip(request), user["email"],
                                        fleet=True, what_key="role_created",
                                        what_params={"role": name, "perms": ", ".join(sorted(perms))})
    out = await authz.roles_json(g)
    out["id"] = rid
    return out


async def _config_maps_of_role(rid: int) -> list:
    return [r["grp"] for r in await db.fetchall(
        "SELECT grp FROM oidc_group_roles WHERE role_id=? AND source='config' ORDER BY grp", rid)]


async def _check_config_map_role(rid: int, perms) -> None:
    """3.6.5 (revizuirea de securitate): configuraţia nu acordă niciodată Owner — deci un rol
    folosit de o mapare din WEBTERM_OIDC_ROLE_MAP nu poate primi o permisiune doar-de-Owner:
    legăturile deja derivate din ea ar purta-o până la următorul login SSO al fiecăruia."""
    if not (frozenset(perms) & ssomap._OWNER_ONLY):
        return
    maps = await _config_maps_of_role(rid)
    if maps:
        raise ApiError(409, "role.usedByConfigMap",
                       "this role is mapped from WEBTERM_OIDC_ROLE_MAP (%s), which never grants "
                       "Owner-only permissions; remove it from WEBTERM_OIDC_ROLE_MAP and restart "
                       "WebTerm first" % ", ".join(maps)[:200],
                       vars={"groups": ", ".join(maps)[:200]})


@router.patch("/api/roles/{rid}")
async def edit_role(rid: int, body: RoleIn, request: Request,
                    user=Depends(authz.perm('roles.manage'))):
    grants = authz.grants_of(request)
    role = await _custom_role(rid)
    name, desc, perms = authz.validate_role_fields(body.name, body.description, body.perms)
    # §A.6.6 regula 5: un rol care are (sau ar avea) o permisiune pe care n-o ai nu-l editezi
    authz.check_can_define(grants, role.perms | perms)
    await _check_role_targets(grants, rid)
    # revizuirea 3.6.10: a adăuga permisiuni unui rol FOLOSIT le acordă deţinătorilor lui — nu pe
    # baza unui drept temporar (altfel „Admin 4 ore" lărgea pe termen nelimitat un rol permanent)
    authz.check_define_lifetime(grants, perms - role.perms, await _role_used(rid))
    await _role_name_free(name, rid)
    await _check_config_map_role(rid, perms)
    await stepup.reauth_for_access_change(user, request, body, "change a role")
    async with authz.bindings_lock:
        g = await _fresh_grants(user, "roles.manage")
        role = await _custom_role(rid)                 # definiţia de ACUM, nu cea de mai sus
        authz.check_can_define(g, role.perms | perms)
        uids = await _check_role_targets(g, rid)
        authz.check_define_lifetime(g, perms - role.perms, await _role_used(rid))
        await _role_name_free(name, rid)
        await _check_config_map_role(rid, perms)
        cfg_maps = await _config_maps_of_role(rid)
        await db.execute("UPDATE roles SET name=?, description=?, perms=?, updated=?"
                         " WHERE id=? AND builtin=0", name, desc, json.dumps(sorted(perms)),
                         time.time(), rid)
        # efect IMEDIAT: cache-ul moare, socket-urile lungi re-verifică acum (un terminal deschis
        # trece pe doar-citire sau se închide), biletele de forward mor, accesul derivat pe care
        # cei afectaţi nu-l mai pot acorda (share live / replay) se retrage
        authz.bump_epoch()
        for uid in uids:
            security.bump_forward_epoch(uid)
            await shares.revoke_unauthorized_derived(uid)
    added, removed = sorted(perms - role.perms), sorted(role.perms - perms)
    what = "role '%s' changed: +%s -%s" % (name, ",".join(added) or "none",
                                           ",".join(removed) or "none")
    if name != role.name:
        what += " (renamed from '%s')" % role.name
    audit.detail(request, "%s; %d account(s) affected" % (what, len(uids)))
    log.warning("%s (by %s, %d account(s) affected)", what, user["email"], len(uids))
    if name != role.name and cfg_maps:
        # 3.6.5: WEBTERM_OIDC_ROLE_MAP numeşte rolul după NUME şi e citită doar la pornire —
        # maparea rămâne (pe id) până la următoarea pornire, apoi „<nume vechi>" nu mai există
        log.warning("role '%s' was renamed to '%s', but WEBTERM_OIDC_ROLE_MAP refers to it by name "
                    "(%s): update .env, otherwise the next restart skips the entry and removes the "
                    "mapping", role.name, name, ", ".join(cfg_maps))
        audit.detail(request, "%s; %d account(s) affected; WEBTERM_OIDC_ROLE_MAP still names it "
                              "'%s' (%s) — update .env before the next restart"
                     % (what, len(uids), role.name, ", ".join(cfg_maps)))
    ip = security.client_ip(request)
    email_alerts.notify_security_change(what, ip, user["email"], fleet=True, what_key="role_changed",
                                        what_params={"role": name, "added": ", ".join(added) or "—",
                                                     "removed": ", ".join(removed) or "—",
                                                     "n": len(uids)})
    if added or removed:
        for uid in uids[:50]:          # plafon: un rol legat de sute de conturi nu inundă alertele
            row = await db.fetchone("SELECT email FROM users WHERE id=?", uid)
            if row:
                email_alerts.notify_security_change(
                    "your access changed: " + what, ip, row["email"], user_id=uid,
                    what_key="role_changed_you", what_params={"role": name})
    return await authz.roles_json(g)


@router.post("/api/roles/{rid}/delete")
async def delete_role(rid: int, body: ReauthOnly, request: Request,
                      user=Depends(authz.perm('roles.manage'))):
    grants = authz.grants_of(request)
    role = await _custom_role(rid)
    authz.check_can_define(grants, role.perms)

    async def _refuse_if_used():
        use = await _role_in_use(rid)
        if any(use.values()):
            raise ApiError(409, "role.inUse",
                           "the role is still in use (%(bindings)d binding(s), %(mappings)d SSO "
                           "mapping(s), %(tokens)d token(s)) — remove those first" % use, vars=use)
    await _refuse_if_used()
    await stepup.reauth_for_access_change(user, request, body, "delete a role")
    async with authz.bindings_lock:
        g = await _fresh_grants(user, "roles.manage")
        role = await _custom_role(rid)
        authz.check_can_define(g, role.perms)
        await _refuse_if_used()
        await db.execute("DELETE FROM roles WHERE id=? AND builtin=0", rid)
        authz.bump_epoch()
    what = "role '%s' deleted" % role.name
    audit.detail(request, what)
    log.warning("%s (by %s)", what, user["email"])
    email_alerts.notify_security_change(what, security.client_ip(request), user["email"],
                                        fleet=True, what_key="role_deleted",
                                        what_params={"role": role.name})
    return await authz.roles_json(g)


# ── [sso] Maparea grupurilor SSO → roluri (3.6.2; design „3.6.1", §A.7; logica în ssomap.py) ────
# Cine mapează un grup la un rol îl ACORDĂ (la următorul login SSO) oricui e în grup: aceleaşi
# reguli ca o legătură — users.manage, anti-escaladare peste scope, doar un Owner mapează la
# Owner — plus re-auth + al doilea factor, audit, alertă. O mapare NOUĂ are efect la următorul
# login / step-up SSO al fiecăruia; una ŞTEARSĂ retrage imediat legăturile derivate.

class OidcRoleIn(BaseModel):
    group: str = ""
    role: str = ""
    role_id: int = 0
    scope_kind: str = "all"
    scope_value: str = ""
    confirm_crown_jewel: bool = False      # 3.6.10: ⚑ peste un host crown-jewel = confirmare explicită
    current_password: str = ""
    totp_code: str = ""
    email_code: str = ""
    stepup_grant: str = ""


def _check_wildcard(g, grp: str, role, kind: str) -> None:
    """`*` = fiecare cont SSO al IdP-ului. Cu o permisiune de instanţă, una ⚑ (shell) sau pe
    toată flota, maparea (şi scoaterea ei) e doar a unui Owner (revizuirea 3.6.2)."""
    if grp != ssomap.WILDCARD or g.is_owner():
        return
    if kind == "all" or role.perms & authz.GLOBAL_PERMS or role.perms & authz.SHELL_PERMS:
        raise ApiError(403, "authz.ownerOnly",
                       "only an Owner can map every SSO user (*) to a role with instance or "
                       "shell-equivalent permissions, or over all hosts")


async def _oidc_roles_json() -> dict:
    rows = await db.fetchall(
        "SELECT m.id, m.grp, m.role_id, m.scope_kind, m.scope_value, m.created,"
        " COALESCE(m.source, 'ui') AS source,"
        " r.key AS role_key, r.name AS role_name FROM oidc_group_roles m"
        " LEFT JOIN roles r ON r.id=m.role_id ORDER BY m.grp, m.id")
    users = {}
    for r in await db.fetchall(
            "SELECT role_id, scope_kind, scope_value, COUNT(*) AS c FROM role_bindings"
            " WHERE source='sso' GROUP BY role_id, scope_kind, scope_value"):
        users[(r["role_id"], r["scope_kind"], r["scope_value"])] = r["c"]
    # conturile SSO care încă au parolă locală: grupurile nu le dau roluri (le arătăm în UI)
    lp = (await db.fetchone("SELECT COUNT(*) AS c FROM users WHERE sso_subject IS NOT NULL"
                            " AND COALESCE(local_password, 1)<>0"))["c"]
    return {"enabled": config.OIDC_ENABLED, "claim": "groups", "wildcard": ssomap.WILDCARD,
            "local_password_accounts": lp,
            "max": ssomap.MAPPINGS_MAX,
            "mappings": [{"id": r["id"], "group": r["grp"], "role": r["role_key"] or "",
                          "role_id": r["role_id"], "role_name": r["role_name"] or "?",
                          "scope_kind": r["scope_kind"], "scope_value": r["scope_value"] or "",
                          "created": r["created"],
                          # 3.6.5: 'config' = din WEBTERM_OIDC_ROLE_MAP (doar citire în UI)
                          "source": "config" if r["source"] == "config" else "ui",
                          "sso_bindings": users.get((r["role_id"], r["scope_kind"],
                                                     r["scope_value"] or ""), 0)}
                         for r in rows]}


def _check_not_config(row) -> None:
    """3.6.5: o mapare din WEBTERM_OIDC_ROLE_MAP aparţine .env-ului: din UI nu se şterge (ar
    reveni la următoarea pornire, iar până atunci UI-ul ar minţi despre ce e configurat)."""
    if "source" in row.keys() and row["source"] == "config":
        raise ApiError(409, "ssoMap.fromConfig",
                       "this mapping comes from WEBTERM_OIDC_ROLE_MAP in the server's .env; "
                       "change it there and restart WebTerm")


@router.get("/api/settings/oidc-roles")
async def list_oidc_roles(user=Depends(authz.perm('users.manage'))):
    return await _oidc_roles_json()


@router.post("/api/settings/oidc-roles")
async def add_oidc_role(body: OidcRoleIn, request: Request,
                        user=Depends(authz.perm('users.manage'))):
    grants = authz.grants_of(request)
    grp = ssomap.normalize_group(body.group)
    if grp is None:
        raise ApiError(400, "ssoMap.badGroup",
                       "give the exact group name from the IdP (1–256 printable characters), "
                       "or * for every SSO user")
    role = await authz.resolve_role(body.role, body.role_id)
    kind, value = authz.normalize_scope(body.scope_kind, body.scope_value)
    # o mapare acordă rolul fiecărui membru al grupului: exact regulile unei legături
    await authz.check_can_grant(grants, role, kind, value)
    # o mapare e PERMANENTĂ (dă rolul la fiecare login): cere un drept de acordare permanent
    await authz.check_grant_lifetime(grants, role, kind, value, None)
    _check_wildcard(grants, grp, role, kind)
    await authz.check_crown(role, kind, value, body.confirm_crown_jewel)
    await stepup.reauth_for_access_change(user, request, body, "map an SSO group to a role")
    async with authz.bindings_lock:
        g = await _fresh_grants(user, "users.manage")
        fresh = await authz.role_by_id(role.id)
        if fresh is None:
            raise ApiError(409, "role.gone", "that role was deleted meanwhile")
        await authz.check_can_grant(g, fresh, kind, value)
        await authz.check_grant_lifetime(g, fresh, kind, value, None)
        _check_wildcard(g, grp, fresh, kind)
        crown = await authz.check_crown(fresh, kind, value, body.confirm_crown_jewel)
        n = (await db.fetchone("SELECT COUNT(*) AS c FROM oidc_group_roles"))["c"]
        if n >= ssomap.MAPPINGS_MAX:
            raise ApiError(400, "ssoMap.tooMany", "too many SSO mappings (%d)" % ssomap.MAPPINGS_MAX,
                           vars={"max": ssomap.MAPPINGS_MAX})
        try:
            await db.execute(
                "INSERT INTO oidc_group_roles(grp, role_id, scope_kind, scope_value, created,"
                " created_by_id) VALUES(?,?,?,?,?,?)", grp, fresh.id, kind, value, time.time(),
                user["id"])
        except sqlite3.IntegrityError:
            raise ApiError(409, "ssoMap.exists", "that group already maps to this role there")
        authz.bump_epoch()
    what = "SSO group '%s' mapped to %s @ %s" % (grp, _role_label(fresh), authz.scope_label(kind, value))
    audit.detail(request, what + _crown_note(crown))
    log.warning("%s (by %s)", what, user["email"])
    # `*` = FIECARE cont SSO: întotdeauna alertă critică, oricât de mic e rolul
    email_alerts.notify_security_change(what, security.client_ip(request), user["email"],
                                        fleet=True, what_key="sso_mapping_added",
                                        severity="critical" if grp == ssomap.WILDCARD else "warning",
                                        what_params={"group": grp, "role": _role_label(fresh),
                                                     "scope": authz.scope_label(kind, value)})
    return await _oidc_roles_json()


@router.post("/api/settings/oidc-roles/{mid}/delete")
async def delete_oidc_role(mid: int, body: ReauthOnly, request: Request,
                           user=Depends(authz.perm('users.manage'))):
    grants = authz.grants_of(request)
    row = await db.fetchone("SELECT * FROM oidc_group_roles WHERE id=?", mid)
    if not row:
        raise ApiError(404, "ssoMap.missing", "no such SSO mapping")
    _check_not_config(row)
    info = (await authz.role_by_id(row["role_id"])) or _UNKNOWN_ROLE
    # retragerea unei mapări scoate legături de la alţii: doar în interiorul a ce poţi acorda
    await authz.check_can_grant(grants, info, row["scope_kind"], row["scope_value"], removing=True)
    _check_wildcard(grants, row["grp"], info, row["scope_kind"])
    await stepup.reauth_for_access_change(user, request, body, "remove an SSO group mapping")
    async with authz.bindings_lock:
        g = await _fresh_grants(user, "users.manage")
        row = await db.fetchone("SELECT * FROM oidc_group_roles WHERE id=?", mid)
        if not row:
            raise ApiError(404, "ssoMap.missing", "no such SSO mapping")
        _check_not_config(row)
        info = (await authz.role_by_id(row["role_id"])) or _UNKNOWN_ROLE
        await authz.check_can_grant(g, info, row["scope_kind"], row["scope_value"], removing=True)
        _check_wildcard(g, row["grp"], info, row["scope_kind"])
        # revizuirea 3.6.2: ştergerea mapării ar scoate legături de la conturi care au MAI MULT
        # decât tine — exact ce /bindings/{bid}/delete refuză. Refuzăm tot, nu scoatem nimic.
        outr = []
        for uid in await ssomap.prune_plan(mid):
            tg = await authz.target_grants(uid)      # şi un cont dezactivat (revizuirea 3.6.11)
            if (tg.is_owner() and not g.is_owner()) or authz.outranked_by(tg, g):
                outr.append(uid)
        if outr:
            raise ApiError(403, "authz.outranked",
                           "removing this mapping would change the access of %d account(s) that "
                           "hold permissions you do not" % len(outr),
                           vars={"perm": "users.manage", "n": len(outr)})
        await db.execute("DELETE FROM oidc_group_roles WHERE id=?", mid)
        # IMEDIAT, nu la următorul login: legăturile pe care nicio mapare rămasă nu le mai
        # justifică (după grupurile văzute la ultima sincronizare) pleacă acum. Doar retragere.
        changed = await ssomap.prune_locked()
        authz.bump_epoch()
    what = "SSO group '%s' no longer maps to %s @ %s" % (
        row["grp"], _role_label(info), authz.scope_label(row["scope_kind"], row["scope_value"]))
    removed = sum(len(r["removed"]) for _u, _e, r in changed)
    audit.detail(request, "%s; %d SSO binding(s) removed" % (what, removed))
    log.warning("%s (by %s; %d SSO binding(s) removed)", what, user["email"], removed)
    ip = security.client_ip(request)
    email_alerts.notify_security_change(what, ip, user["email"], fleet=True,
                                        what_key="sso_mapping_removed",
                                        what_params={"group": row["grp"], "role": _role_label(info),
                                                     "scope": authz.scope_label(row["scope_kind"],
                                                                           row["scope_value"]),
                                                     "n": removed})
    for uid, email, res in changed[:50]:
        if res["removed"]:
            email_alerts.notify_security_change(
                "your access changed: " + ", ".join(res["removed"]) + " removed", ip, email,
                user_id=uid, what_key="sso_access_changed",
                what_params={"account": email, "added": "—", "removed": ", ".join(res["removed"])})
        if res["kept_last_owner"]:
            owners.report_last_owner(uid, email, ip, res["kept_last_owner"])
    return await _oidc_roles_json()


# ── [scim] SCIM provisioning (3.6.11, scim.py) ─────────────────────────────────────────────────────
# Starea o vede oricine administrează conturile (users.manage — vede oricum conturile „gestionate
# de SCIM"); tokenul îl creează / roteşte / revocă şi provizionarea o porneşte DOAR un Owner, cu
# parola contului + al doilea factor: tokenul SCIM creează conturi şi le dezactivează. Oprirea
# (fără revocare) nu cere re-autentificare — reduce doar accesul, şi trebuie să fie rapidă.
class ScimEnabledIn(ReauthOnly):
    enabled: bool = False


def _owner_only(grants, what: str) -> None:
    if not grants.is_owner():
        raise ApiError(403, "authz.ownerOnly", "only an Owner can %s" % what)


@router.get("/api/settings/scim")
async def scim_status(user=Depends(authz.perm('users.manage'))):
    return await scim.status_json()


@router.post("/api/settings/scim/token")
async def scim_token(body: ReauthOnly, request: Request, user=Depends(authz.perm('users.manage'))):
    """Creează sau ROTEŞTE tokenul SCIM (cel vechi moare pe loc). Arătat O SINGURĂ DATĂ."""
    _owner_only(authz.grants_of(request), "manage SCIM provisioning")
    await stepup.reauth_for_access_change(user, request, body, "create a SCIM provisioning token")
    async with authz.bindings_lock:
        _owner_only(await _fresh_grants(user, "users.manage"), "manage SCIM provisioning")
        rotated = (await scim.status_json())["configured"]
        raw = scim.new_token()
        await scim.set_token(raw, user["email"])
    what = "SCIM provisioning token %s" % ("rotated (the old one stopped working)" if rotated
                                           else "created")
    audit.detail(request, what)
    log.warning("%s by %s", what, user["email"])
    email_alerts.notify_security_change(what, security.client_ip(request), user["email"],
                                        fleet=True, severity="critical",
                                        what_key="scim_token_rotated" if rotated
                                        else "scim_token_created")
    return dict(await scim.status_json(), token=raw)


@router.post("/api/settings/scim/revoke")
async def scim_revoke(body: ReauthOnly, request: Request, user=Depends(authz.perm('users.manage'))):
    _owner_only(authz.grants_of(request), "manage SCIM provisioning")
    await stepup.reauth_for_access_change(user, request, body, "revoke the SCIM provisioning token")
    async with authz.bindings_lock:
        _owner_only(await _fresh_grants(user, "users.manage"), "manage SCIM provisioning")
        await scim.revoke_token()
    audit.detail(request, "SCIM provisioning token revoked")
    log.warning("SCIM provisioning token revoked by %s", user["email"])
    email_alerts.notify_security_change("SCIM provisioning token revoked",
                                        security.client_ip(request), user["email"], fleet=True,
                                        what_key="scim_token_revoked")
    return await scim.status_json()


@router.post("/api/settings/scim/enabled")
async def scim_enabled(body: ScimEnabledIn, request: Request,
                       user=Depends(authz.perm('users.manage'))):
    _owner_only(authz.grants_of(request), "manage SCIM provisioning")
    if body.enabled:
        if not (await scim.status_json())["configured"]:
            raise ApiError(409, "scim.noToken", "create a SCIM token first")
        await stepup.reauth_for_access_change(user, request, body, "turn SCIM provisioning on")
    async with authz.bindings_lock:
        _owner_only(await _fresh_grants(user, "users.manage"), "manage SCIM provisioning")
        await scim.set_enabled(body.enabled)
    what = "SCIM provisioning turned %s" % ("on" if body.enabled else "off")
    audit.detail(request, what)
    log.warning("%s by %s", what, user["email"])
    email_alerts.notify_security_change(what, security.client_ip(request), user["email"],
                                        fleet=True, what_key="scim_enabled" if body.enabled
                                        else "scim_disabled")
    return await scim.status_json()


@router.post("/api/users/{uid}/enable")
async def enable_user(uid: int, body: ReauthOnly, request: Request,
                      user=Depends(authz.perm('users.manage'))):
    """Reactivează un cont dezactivat (de SCIM). Doar un Owner: un cont reactivat îşi recapătă
    TOATE legăturile, deci e o acordare la fel de mare ca cea mai mare dintre ele."""
    _owner_only(authz.grants_of(request), "re-enable a disabled account")
    row = await db.fetchone("SELECT email, COALESCE(disabled, 0) AS d FROM users WHERE id=?", uid)
    if not row:
        raise ApiError(404, "user.missing", "no such account")
    if not row["d"]:
        raise ApiError(409, "account.notDisabled", "this account is not disabled")
    await stepup.reauth_for_access_change(user, request, body, "re-enable a disabled account")
    async def recheck():
        _owner_only(await _fresh_grants(user, "users.manage"), "re-enable a disabled account")
    email = await accounts.enable(uid, actor=user["email"], ip=security.client_ip(request),
                                  how="by an Owner in Settings", actor_id=user["id"],
                                  path="/api/users/%d/enable" % uid, recheck=recheck)
    if email:
        audit.detail(request, "account %s re-enabled" % email)
    return await _users_json(user, authz.grants_of(request))


@router.get("/api/me/permissions")
async def me_permissions(user=Depends(security.require_user)):
    """Ce poate contul curent, pentru gating-ul din UI (cosmetic — serverul decide oricum).

    Implicit de securitate (revizuirea 3.6): NU listăm emailurile Owner-ilor/Admin-ilor — un cont
    fără niciun acces (ex. un SSO nou provizionat) ar afla altfel cine sunt ţintele cu cele mai
    multe drepturi. Doar un flag; UI-ul spune generic „cere unui administrator"."""
    grants = await authz.grants_for_user(user["id"])
    out = authz.me_json(grants, await authz.host_refs())
    out["has_admins"] = bool(await db.fetchone(
        "SELECT 1 FROM role_bindings b JOIN roles r ON r.id=b.role_id"
        " WHERE b.scope_kind='all' AND r.key IN ('owner','admin') LIMIT 1"))
    return out


# ── [tokens] Token-uri de automatizare ────────────────────────────────────────────────
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
    stepup_grant: str = ""         # conturi SSO fără parolă: grant passkey / fereastră SSO account-scope (RB-03)
    totp_code: str = ""            # al doilea factor (second_gate): un token e o credenţială persistentă
    email_code: str = ""
    # 3.6: plafon opţional de rol + scope. Efectivul tokenului = scopes ∩ rol ∩ ce poate
    # creatorul ACUM (authz.grants_for_token) — deci nu poate depăşi niciodată contul care l-a emis.
    role: str = ""
    role_id: int = 0               # 3.6.10: orice rol (şi custom) după id; Owner refuzat
    scope_kind: str = "all"
    scope_value: str = ""


def _token_row(r) -> dict:
    keys = r.keys()
    return {"id": r["id"], "name": r["name"], "scopes": r["scopes"], "created": r["created"],
            "created_by": r["created_by"], "expires": r["expires"], "last_used": r["last_used"],
            "expired": r["expires"] < time.time(),
            "role": (r["role_key"] if "role_key" in keys else None) or "",
            # 3.6.10: rolul plafonului (şi custom: după nume); null = token vechi, fără plafon de rol
            "role_id": (r["role_id"] if "role_id" in keys else None) or None,
            "role_name": (r["role_name"] if "role_name" in keys else None) or "",
            "scope_kind": (r["scope_kind"] if "scope_kind" in keys else None) or "all",
            "scope_value": (r["scope_value"] if "scope_value" in keys else None) or ""}


async def _tokens_json(user, grants) -> list:
    """Tokenurile PROPRII; toate, doar cu `tokens.manage` (§A.6.3)."""
    sql = ("SELECT t.*, r.key AS role_key, r.name AS role_name FROM api_tokens t"
           " LEFT JOIN roles r ON r.id=t.role_id")
    if grants.has_global("tokens.manage"):
        rows = await db.fetchall(sql + " ORDER BY t.created DESC")
    else:
        rows = await db.fetchall(sql + " WHERE t.created_by_id=? ORDER BY t.created DESC",
                                 user["id"])
    return [_token_row(r) for r in rows]


# ── [enroll] Token de înrolare DE GRUP (onboarding la scară de flotă) ─────────────────
ENROLL_GROUP_MAX_DAYS = 365
ENROLL_GROUP_MAX_USES = 10000


class EnrollGroupIn(BaseModel):
    name: str
    days: int = 30
    max_uses: int = 0              # 0 = nelimitat (dar expirarea e OBLIGATORIE)
    folder: str = ""              # hosturile noi aterizează aici
    require_2fa: bool = False     # hosturile noi moştenesc asta
    current_password: str = ""    # re-auth: un token reutilizabil de creare hosturi = provisioning
    totp_code: str = ""           # second_gate (ca la crearea de cont)
    email_code: str = ""
    enroll_password: str = ""     # parolă opţională cerută la fiecare instalare (header, nu URL)


def _enroll_group_row(r) -> dict:
    return {"id": r["id"], "name": r["name"], "created": r["created"], "created_by": r["created_by"],
            "expires": r["expires"], "max_uses": r["max_uses"], "uses": r["uses"],
            "folder": r["folder"], "require_2fa": bool(r["require_2fa"]),
            "revoked": bool(r["revoked"]), "expired": r["expires"] < time.time(),
            # second re-review 3.6.11: no account behind it (pre-3.6.11 token whose creator was
            # gone at the one-time backfill) — no offboarding will ever revoke it; shown, not
            # auto-revoked (System health warns too)
            "creator_gone": not r["creator_ok"]}


# ── [devices] Dispozitivele conectate (sesiuni web) ────────────────────────────────────
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
        raise ApiError(404, "websession.missing", "no such session")
    await db.execute("DELETE FROM web_sessions WHERE rowid=? AND user_id=?", rid, user["id"])
    # Ca la revoke-others (M3): ferestrele de step-up sunt per (cont, host), nu per dispozitiv,
    # iar biletele de forward supravieţuiesc scoaterii unui singur dispozitiv. Scoţi un dispozitiv
    # suspect → „sudo-ul" lui şi tunelurile lui trebuie să moară şi ele, altfel trăiesc pe al tău.
    security.clear_stepup_for(user["id"])
    security.bump_forward_epoch(user["id"])
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


# ── [tokens] Automation token routes ──────────────────────────────────────────────────────────────

@router.get("/api/tokens")
async def list_tokens(request: Request, user=Depends(authz.perm('tokens.create'))):
    return await _tokens_json(user, authz.grants_of(request))


@router.post("/api/tokens")
async def create_token(body: TokenIn, request: Request, user=Depends(authz.perm('tokens.create'))):
    grants = authz.grants_of(request)
    role = None
    tkind, tvalue = authz.normalize_scope(body.scope_kind, body.scope_value)
    if (body.role or "").strip() or body.role_id:
        role = await authz.resolve_role(body.role, body.role_id)
        # 3.6.10: un token nu e niciodată „proprietarul instanţei"
        if role.key in authz.TOKEN_ROLE_REFUSED:
            raise ApiError(400, "token.roleNotAllowed",
                           "an automation token cannot have the Owner role; pick a narrower one")
        # rolul plafonului nu poate depăşi ce ai tu peste scope-ul tokenului (anti-escaladare);
        # oricum efectivul e intersectat cu creatorul la FIECARE cerere
        await authz.check_can_grant(grants, role, tkind, tvalue)
    elif tkind == "host":
        # un host inexistent nu e un scope (id-urile se reutilizează); unul invizibil = la fel
        if (await authz.host_ref(tvalue) is None
                or "host.view" not in await authz.perms_on(grants, tvalue)):
            raise authz.not_found("host_id")
    # Un token de automatizare e o credenţială persistentă (scope `run` = shell pe flotă) — la fel
    # ca înrolarea unui passkey. Aceeaşi poartă ca la o schimbare de acces: parola contului (401 dacă
    # e greşită) sau, pentru un cont SSO fără parolă, grant-ul passkey / fereastra SSO account-scope
    # (403 account.ssoReauth altfel), apoi al doilea factor (audit P1, RB-03 — înainte doar parola,
    # deci un Owner SSO-only nu putea crea tokenuri din UI)
    await stepup.reauth_for_access_change(user, request, body, "create an automation token")
    name = body.name.strip()[:60]
    if not name:
        raise ApiError(400, "token.nameRequired", "give it a name (so you know what you are revoking)")
    scopes = [s for s in body.scopes if s in TOKEN_SCOPES]
    if not scopes:
        raise ApiError(400, "token.scopeRequired", "pick at least one scope (read / run)")
    days = min(max(int(body.days), 1), TOKEN_MAX_DAYS)   # expirarea NU e opțională
    raw = security.TOKEN_PREFIX + security.new_token()
    await db.execute(
        "INSERT INTO api_tokens(name, token_hash, scopes, created, created_by,"
        " created_by_id, expires, role_id, scope_kind, scope_value) VALUES(?,?,?,?,?,?,?,?,?,?)",
        name, security.sha256_hex(raw), ",".join(scopes), time.time(), user["email"],
        user["id"], time.time() + days * 86400,
        role.id if role else None, tkind, tvalue)
    cap = "%s @ %s" % (_role_label(role), authz.scope_label(tkind, tvalue)) if role else "no role cap"
    log.info("automation token created: %s (%s, %dd, %s) by %s", name, ",".join(scopes), days,
             cap, user["email"])
    audit.detail(request, "automation token %s created (%s; %s; %d days)" % (
        name, ",".join(scopes), cap, days))
    # un token nou = o credenţială de automatizare care poate citi/rula fără browser: notificăm
    # (email + webhook), la fel ca un passkey nou sau un cont nou.
    email_alerts.notify_security_change(
        "an automation token was created (%s, scopes: %s)" % (name, ",".join(scopes)),
        security.client_ip(request), user["email"], fleet=True,
        what_key="api_token_created", what_params={"name": name, "scopes": ",".join(scopes)})
    # valoarea în clar se întoarce O SINGURĂ DATĂ; în DB stă doar hash-ul
    return {"token": raw, "tokens": await _tokens_json(user, grants)}


@router.post("/api/tokens/{tid}/revoke")
async def revoke_token(tid: int, request: Request, user=Depends(authz.perm('tokens.create'))):
    grants = authz.grants_of(request)
    row = await db.fetchone("SELECT name, created_by_id FROM api_tokens WHERE id=?", tid)
    # al altui cont fără `tokens.manage` = la fel de inexistent ca unul şters (fără oracol)
    if not row or (row["created_by_id"] != user["id"] and not grants.has_global("tokens.manage")):
        raise ApiError(404, "token.missing", "no such token")
    await db.execute("DELETE FROM api_tokens WHERE id=?", tid)
    log.warning("automation token revoked: %s (by %s)", row["name"], user["email"])
    return await _tokens_json(user, grants)


# ── [enroll] Group enrolment token routes ─────────────────────────────────────────────────────────

@router.get("/api/enroll-groups")
async def list_enroll_groups(user=Depends(authz.perm('hosts.create'))):
    rows = await db.fetchall(
        "SELECT g.*, (SELECT 1 FROM users u WHERE u.id=g.created_by_id) AS creator_ok"
        " FROM enroll_groups g ORDER BY g.created DESC")
    return [_enroll_group_row(r) for r in rows]


@router.post("/api/enroll-groups")
async def create_enroll_group(body: EnrollGroupIn, request: Request,
                              user=Depends(authz.perm('hosts.create'))):
    if not await stepup.verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongPassword", "wrong password")
    # Un token reutilizabil care poate CREA hosturi e clasă de provisioning — ca enroll-ul unui
    # host cu 2FA. Trece prin acelaşi al doilea factor ca înrolarea unui passkey / crearea unui cont.
    await webauthn_api.second_gate(user, request, body, "create a group enrollment token")
    name = body.name.strip()[:60]
    if not name:
        raise ApiError(400, "token.nameRequired", "give it a name (so you know what you are revoking)")
    days = min(max(int(body.days), 1), ENROLL_GROUP_MAX_DAYS)     # expirarea NU e opțională
    max_uses = max(0, min(int(body.max_uses), ENROLL_GROUP_MAX_USES))
    raw = security.new_token()
    pw = hostmodel.clean_enroll_pass(body.enroll_password)
    pass_hash = await security.hash_password_async(pw) if pw else None
    await db.execute(
        "INSERT INTO enroll_groups(name, token_hash, created, created_by, created_by_id, expires,"
        " max_uses, folder, require_2fa, pass_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
        name, security.sha256_hex(raw), time.time(), user["email"], user["id"],
        time.time() + days * 86400,
        max_uses, body.folder.strip(), int(body.require_2fa), pass_hash)
    log.info("group enroll token created: %s (max_uses=%d, %dd, 2fa=%s, pass=%s) by %s",
             name, max_uses, days, bool(body.require_2fa), bool(pw), user["email"])
    # un token de grup = o cheie care poate înmatricula hosturi noi în flotă: eveniment de securitate
    email_alerts.notify_security_change("a group enrollment token was created (%s)" % name,
                                        security.client_ip(request), user["email"], fleet=True,
                                        what_key="enroll_token_created", what_params={"name": name})
    # valoarea în clar se întoarce O SINGURĂ DATĂ; în DB stă doar hash-ul
    return {"token": raw, "install_command": hostmodel.install_command(raw, pw, group=True),
            "groups": await list_enroll_groups(user)}


@router.post("/api/enroll-groups/{gid}/revoke")
async def revoke_enroll_group(gid: int, user=Depends(authz.perm('hosts.create'))):
    row = await db.fetchone("SELECT name FROM enroll_groups WHERE id=?", gid)
    if not row:
        raise ApiError(404, "enrollgroup.missing", "no such enrollment group")
    # revocare, nu ştergere: păstrăm evidenţa (cine/când a putut înmatricula) pentru audit
    await db.execute("UPDATE enroll_groups SET revoked=1 WHERE id=?", gid)
    log.warning("group enroll token revoked: %s (by %s)", row["name"], user["email"])
    return await list_enroll_groups(user)


# ── [totp] TOTP setup / activate / disable / recovery codes ───────────────────────────────────────

@router.post("/api/totp/setup")
async def totp_setup(body: TotpSetup, user=Depends(security.require_user)):
    """Generează un secret nou (încă neactivat) și întoarce QR-ul de înrolat.
    Nu devine efectiv până nu confirmi un cod prin /activate."""
    # M1: înrolarea unui factor 2FA e schimbare de credențiale — cere re-auth cu parola,
    # ca un cookie furat să nu poată înrola un TOTP atacator + să ia codurile de recuperare.
    if not await stepup.verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    if user["totp_enabled"]:
        raise ApiError(409, "totp.alreadyOn", "2FA is already on; turn it off first")
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
    if not await stepup.verify_reauth_password(user, body.current_password):   # M1: re-auth şi la activare
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    if user["totp_enabled"]:
        raise ApiError(409, "totp.alreadyOn", "2FA is already enabled")
    if not user["totp_secret_encrypted"]:
        raise ApiError(400, "totp.setupFirst", "run /api/totp/setup first")
    secret = security.decrypt_secret(user["totp_secret_encrypted"])
    if not totp.verify(secret, body.code.strip()):
        raise ApiError(400, "totp.badCode", "wrong code — check your phone clock")
    codes = _gen_recovery_codes()
    await db.execute("UPDATE users SET totp_enabled=1 WHERE id=?", user["id"])
    await db.execute("DELETE FROM recovery_codes WHERE user_id=?", user["id"])
    for c in codes:
        await db.execute(
            "INSERT INTO recovery_codes(user_id, code_hash, created) VALUES(?,?,?)",
            user["id"], security.sha256_hex(c), time.time())
    email_alerts.notify_security_change("2FA (TOTP) enabled", security.client_ip(request), user["email"],
                                        user_id=user["id"], what_key="totp_enabled")
    return {"ok": True, "recovery_codes": codes}


class TotpDisable(BaseModel):
    current_password: str
    totp_code: str = ""            # second_gate: dovada că deţii factorul pe care-l dezactivezi
    email_code: str = ""


@router.post("/api/totp/disable")
async def totp_disable(body: TotpDisable, request: Request,
                       user=Depends(security.require_user)):
    """Dezactivează 2FA. Cere parola curentă (re-auth) PLUS dovada că deţii factorul pe care-l
    scoţi: cu 2FA activ, second_gate cere codul TOTP/recovery — un cookie furat + parola ştiută
    nu mai pot slăbi singure contul dezactivând al doilea factor."""
    if not await stepup.verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    await webauthn_api.second_gate(user, request, body, "disable two-factor authentication")
    await db.execute(
        "UPDATE users SET totp_enabled=0, totp_secret_encrypted=NULL WHERE id=?", user["id"])
    await db.execute("DELETE FROM recovery_codes WHERE user_id=?", user["id"])
    # Dezactivarea unui factor e o schimbare de credenţiale: închidem ferestrele de step-up, ca un
    # „sudo" deschis cât timp 2FA era activ să nu supravieţuiască slăbirii contului (ca la rotirea
    # parolei / schimbarea passkey-ului).
    security.clear_stepup_for(user["id"])
    email_alerts.notify_security_change("2FA (TOTP) disabled", security.client_ip(request), user["email"],
                                        severity="critical", user_id=user["id"], what_key="totp_disabled")
    return {"ok": True}


@router.post("/api/totp/recovery-codes")
async def totp_regenerate(body: TotpDisable, request: Request, user=Depends(security.require_user)):
    """Regenerate the recovery codes (invalidates the old set). Cere parola PLUS al doilea factor:
    codurile de recuperare noi sunt ele însele un al doilea factor valid, iar cine le are poate
    trece `second_gate` (deci dezactiva 2FA). Fără gate-ul ăsta, cine ştie doar parola şi-ar emite
    coduri proaspete → ar ocoli 2FA — exact ce factorul al doilea trebuie să oprească."""
    if not user["totp_enabled"]:
        raise ApiError(400, "totp.notOn", "2FA is not enabled")
    if not await stepup.verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword", "the current password is wrong")
    await webauthn_api.second_gate(user, request, body, "regenerate recovery codes")
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
    current_password: str = ""  # cerut la ORICE schimbare (SMTP-ul poartă codurile de email)


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
    raw = await db.get_setting("watermark")
    if not raw:
        return dict(WATERMARK_DEFAULT)
    try:
        cfg = json.loads(raw)
    except (ValueError, TypeError):
        return dict(WATERMARK_DEFAULT)
    # doar cheile cunoscute, peste default (schema-safe la upgrade/downgrade)
    return {**WATERMARK_DEFAULT, **{k: cfg[k] for k in WATERMARK_DEFAULT if k in cfg}}


class CommandRuleIn(BaseModel):
    pattern: str
    action: str = "confirm"   # 'confirm' | 'block'


class CommandGuardIn(BaseModel):
    enabled: bool = True
    rules: list[CommandRuleIn] = []


# Corpus de fuzz la SALVARE: şiruri lungi şi uniforme pe clasele pe care le folosesc regulile
# reale (litere, cifre, spaţii, separatori de shell), cu un caracter final care STRICĂ
# potrivirea — exact forma care face `(a+)+$` sau `(\w+\s?)+$` să exploreze 2^n căi. 40 de
# caractere: pentru o regulă patologică bugetul expiră cu siguranţă, pentru una polinomială
# (`.*.*=`) tot sub o milisecundă.
_GUARD_FUZZ = [c * 40 + "!" for c in "a A x 0 - / . _ \\ :".split(" ")] + [
    " " * 40 + "!", "\t" * 40 + "!", "ab" * 20 + "!", "word " * 8 + "!", "a b " * 10 + "!",
    "rm -rf /" + "a" * 40, "sudo " * 8 + "!", "/dev/sd" + "a" * 40, "x=" * 20 + "!"]


# ── [settings] Command guard, watermark, SMTP, webhook, alert settings ────────────────────────────

@router.get("/api/settings/command-guard")
async def get_command_guard(user=Depends(authz.perm("settings.manage"))):
    return await cmdguard.load_command_guard()


@router.post("/api/settings/command-guard")
async def save_command_guard(body: CommandGuardIn, user=Depends(authz.perm('settings.manage'))):
    rules = []
    try:
        for r in body.rules[:100]:
            pat = (r.pattern or "").strip()[:300]
            if not pat:
                continue
            try:
                re.compile(pat)   # respinge regex invalid ca să nu strice clientul
            except re.error:
                raise ApiError(400, "guard.badRegex", f"invalid regex: {pat}", vars={"pattern": pat})
            # F-09, a doua barieră: o regulă cu backtracking catastrofal e refuzată LA SALVARE,
            # rulată pe corpusul de fuzz cu acelaşi buget ca la `/run`. Aşa adminul află pe loc
            # că regula lui e inutilizabilă, în loc s-o vadă sărită în audit la prima comandă.
            if await security.regex_search_budget(pat, _GUARD_FUZZ, re.IGNORECASE,
                                                  cmdguard.GUARD_RE_BUDGET) is None:
                await cmdguard.guard_rule_over_budget(pat, "save")
                raise ApiError(
                    400, "guard.regexTooSlow",
                    f"regex too slow (catastrophic backtracking) — rule rejected: {pat}",
                    vars={"pattern": pat})
            rules.append({"pattern": pat, "action": "block" if r.action == "block" else "confirm"})
    finally:
        security.regex_worker_release()
    cfg = {"enabled": bool(body.enabled), "rules": rules}
    await db.set_setting("command_guard", json.dumps(cfg))
    return cfg


@router.get("/api/settings/watermark")
async def get_watermark(user=Depends(security.require_user)):
    return await _load_watermark()


@router.post("/api/settings/watermark")
async def save_watermark(body: WatermarkIn, user=Depends(authz.perm('settings.manage'))):
    content = (body.content or "").strip()[:200]
    cfg = {
        "enabled": bool(body.enabled),
        "content": content or WATERMARK_DEFAULT["content"],
        "opacity": min(0.5, max(0.02, float(body.opacity))),
        "angle": min(90, max(-90, int(body.angle))),
        "fontSize": min(40, max(8, int(body.fontSize))),
    }
    await db.set_setting("watermark", json.dumps(cfg))
    return cfg


@router.get("/api/settings/smtp")
async def get_smtp(user=Depends(authz.perm('settings.manage'))):
    """The current SMTP config, WITHOUT the password (only whether one is set)."""
    cfg = await email_alerts.load_config()
    return {"host": cfg["host"], "port": cfg["port"], "user": cfg["user"],
            "from_addr": cfg["from"], "to_addr": cfg["to"], "webhook": cfg["webhook"],
            "starttls": cfg["starttls"], "has_password": bool(cfg["password"]),
            "configured": bool(cfg["host"] and cfg["to"] and cfg["from"]),
            # ultimul email/webhook trimis + ultimul eşuat — „au plecat alertele?" (UX §7)
            "status": await email_alerts.alert_status()}


@router.post("/api/settings/smtp")
async def save_smtp(body: SmtpIn, request: Request, user=Depends(authz.perm('settings.manage'))):
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
    # Aceeaşi poartă ca la webhook, altfel asimetria e greu de apărat: acolo blocăm adresa
    # de metadate, aici acceptam orice gazdă:port şi `/api/settings/smtp/test` o contacta la
    # comandă — un scaner de porturi din interiorul reţelei. Reţelele private rămân permise
    # (un Postfix în LAN e legitim la un produs self-hosted); blocăm doar metadatele cloud.
    sh = body.host.strip()
    if sh.strip("[]").lower() in ("169.254.169.254", "metadata.google.internal", "fd00:ec2::254"):
        raise ApiError(400, "settings.smtpBlocked",
                       "that address is the cloud metadata service, not an SMTP server")
    # Auditul intern (2026-09-23): DOAR webhook-ul cerea re-autentificare — dar serverul SMTP e
    # el însuşi o destinaţie de exfiltrare: pe el circulă codurile de email (al doilea factor de
    # rezervă pentru conturile fără TOTP), iar gateway-ul se autentifică la el cu parola SMTP
    # stocată. Un cookie furat putea repointa `smtp_host` la un releu ostil şi primea şi
    # credenţialul, şi toate codurile viitoare. Orice schimbare de câmp cere parola contului;
    # o salvare fără schimbări rămâne tăcută (formularul retrimite mereu tot).
    new_vals = {"smtp_host": sh, "smtp_port": str(body.port), "smtp_user": body.user.strip(),
                "smtp_from": body.from_addr.strip(), "smtp_to": body.to_addr.strip(),
                "smtp_starttls": "1" if body.starttls else "0", "alert_webhook": wh}
    changed = bool(body.password)          # parolă SMTP nouă = schimbare (nu o putem compara)
    for k, v in new_vals.items():
        if ((await db.get_setting(k)) or "") != v:
            changed = True
            break
    if changed:
        await stepup.require_reauth_for_secret(user, body.current_password,
                                        "changing the alert/SMTP settings")
    await db.set_setting("smtp_host", sh)
    await db.set_setting("smtp_port", str(body.port))
    await db.set_setting("smtp_user", body.user.strip())
    await db.set_setting("smtp_from", body.from_addr.strip())
    await db.set_setting("smtp_to", body.to_addr.strip())
    await db.set_setting("smtp_starttls", "1" if body.starttls else "0")
    await db.set_setting("alert_webhook", body.webhook.strip())
    # parola: doar dacă a fost furnizată (gol = păstreaz-o pe cea existentă)
    if body.password:
        await db.set_setting("smtp_password_enc", security.encrypt_secret(body.password))
    return {"ok": True}


@router.post("/api/settings/webhook/test")
async def test_webhook(user=Depends(authz.perm('settings.manage'))):
    """Posts a test alert to the configured webhook and reports the result (the SMTP test sent
    an email only, so a broken webhook stayed invisible until a real alert was lost)."""
    try:
        await email_alerts.send_webhook_test()
    except Exception as e:
        log.warning("webhook test failed: %s: %s", type(e).__name__, e)
        raise ApiError(400, "settings.webhookSendFailed", f"sending failed: {e}")
    return {"ok": True}


@router.post("/api/settings/smtp/test")
async def test_smtp(user=Depends(authz.perm('settings.manage'))):
    """Send a test email to the destination address and report the result."""
    try:
        await email_alerts.send_test()
    except Exception as e:
        log.warning("SMTP test failed: %s: %s", type(e).__name__, e)
        raise ApiError(400, "settings.smtpSendFailed", f"sending failed: {e}")
    return {"ok": True}


class ThresholdsIn(BaseModel):
    cpu: int = 90
    mem: int = 90
    disk: int = 90


class UpdateCheckIn(BaseModel):
    enabled: bool


@router.get("/api/settings/alerts")
async def get_alert_thresholds(user=Depends(authz.perm('settings.manage'))):
    """Praguri de alertă pe resurse (0 = metrica dezactivată)."""
    return await email_alerts.load_thresholds()


@router.post("/api/settings/alerts")
async def save_alert_thresholds(body: ThresholdsIn, user=Depends(authz.perm('settings.manage'))):
    for key, value in (("cpu", body.cpu), ("mem", body.mem), ("disk", body.disk)):
        if not 0 <= value <= 100:
            raise ApiError(400, "settings.badThreshold", "thresholds must be between 0 and 100")
        await db.set_setting(f"alert_{key}", str(value))
    email_alerts.invalidate_thresholds()   # cache-ul de la check_metrics
    return {"ok": True}


# ---------------------------------------------------------------------------
# Istoricul de alerte în aplicaţie + preferinţe per eveniment (3.5.11, alert_history.py)
# ---------------------------------------------------------------------------
# Doar cookie (require_user), ca restul API-ului: un token de automatizare NU e un cont, deci
# n-are un istoric al lui, iar „ce alerte de securitate a văzut omul" nu e treaba unui cron.
# Fiecare interogare e filtrată pe `user["id"]` — un cont nu vede, nu marchează şi nu şterge
# rândurile altuia (fan-out-ul evenimentelor de flotă îi dă fiecăruia propria copie).

class AlertsReadIn(BaseModel):
    ids: Optional[list[int]] = None        # lipsă = toate
    all: bool = False


class AlertPrefIn(BaseModel):
    email: bool = True
    inapp: bool = True


class AlertPrefsIn(BaseModel):
    prefs: dict[str, AlertPrefIn]


# ── [alerts] In-app alerts + per-user alert prefs ─────────────────────────────────────────────────

@router.get("/api/alerts")
async def list_alerts(limit: int = 50, before: Optional[int] = None, unread: bool = False,
                      user=Depends(security.require_user)):
    """Alertele contului, cele mai noi primele; `before` = id-ul ultimului rând văzut (paginare)."""
    return await alert_history.list_for(user["id"], limit=limit, before=before, unread_only=unread)


@router.get("/api/alerts/unread")
async def alerts_unread(user=Depends(security.require_user)):
    """Doar contorul — poll-ul ieftin al clopoţelului (o interogare pe index)."""
    return {"unread": await alert_history.unread_count(user["id"])}


@router.post("/api/alerts/read")
async def alerts_mark_read(body: AlertsReadIn, user=Depends(security.require_user)):
    if not body.all and not body.ids:
        raise ApiError(400, "alerts.nothingToMark", "pass `ids` or `all: true`")
    n = await alert_history.mark_read(user["id"], None if body.all else body.ids)
    return {"ok": True, "unread": n}


@router.delete("/api/alerts")
async def alerts_clear(request: Request, user=Depends(security.require_user)):
    n = await alert_history.clear(user["id"])
    audit.detail(request, "cleared %d in-app alert(s)" % n)
    return {"ok": True, "cleared": n}


@router.get("/api/alerts/prefs")
async def get_alert_prefs(user=Depends(security.require_user)):
    return {"prefs": await alert_history.get_prefs(user["id"])}


@router.post("/api/alerts/prefs")
async def save_alert_prefs(body: AlertPrefsIn, request: Request, user=Depends(security.require_user)):
    """Toggle-uri per tip: email (+ webhook) şi în aplicaţie. Tipurile de securitate rămân
    înregistrate în aplicaţie oricum (`inapp` e ignorat pentru ele) — vezi alert_history.py."""
    try:
        prefs = await alert_history.set_prefs(
            user["id"], {k: v.model_dump() for k, v in body.prefs.items()})
    except ValueError as e:
        raise ApiError(400, "alerts.unknownKind", "unknown alert kind: %s" % e,
                       vars={"kind": str(e)[:40]})
    off = [k for k, v in body.prefs.items() if not v.email]
    if off:
        audit.detail(request, "alert email off for: %s" % ",".join(sorted(off))[:300])
    return {"prefs": prefs}


# ---------------------------------------------------------------------------
# Web Push — notificări pe telefon cu aplicaţia ÎNCHISĂ (Faza 2). Detecţia e server-side
# (core.SessionHub._detect_task_event); aici doar abonamentul + preferinţele contului. Payload-ul
# e GENERIC (push.py) — fără text de terminal, fiindcă trece prin serviciul vendorului.
# ---------------------------------------------------------------------------
class PushSubIn(BaseModel):
    endpoint: str
    p256dh: str
    auth: str


class PushSubscribeIn(BaseModel):
    subscription: PushSubIn
    lang: str = "en"


class PushPrefsIn(BaseModel):
    enabled: bool
    minSeconds: int = 30


def _clamp_push_seconds(n) -> int:
    try:
        return max(1, min(3600, int(n)))
    except (TypeError, ValueError):
        return 30


MAX_PUSH_SUBS = 20                 # plafon de dispozitive/cont (anti-DoS + limitează amplificarea)
_push_test_at: dict = {}           # user_id → ultimul /api/push/test (rate-limit în memorie)


# ── [push] Web Push subscriptions ─────────────────────────────────────────────────────────────────

@router.get("/api/push/status")
async def push_status(user=Depends(security.require_user)):
    """Starea push a contului + cheia publică VAPID (pentru pushManager.subscribe). `available` =
    push-ul e configurat server-side (cheia VAPID există); fără ea, UI-ul ascunde opţiunea."""
    urow = await db.fetchone(
        "SELECT push_task_enabled, push_task_min_seconds FROM users WHERE id=?", user["id"])
    cnt = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM push_subscriptions WHERE user_id=?", user["id"]))["c"]
    return {
        "available": push.enabled(),
        "publicKey": push.public_key_b64(),
        "enabled": bool(urow and urow["push_task_enabled"]),
        "minSeconds": (urow["push_task_min_seconds"] if urow else 30) or 30,
        "devices": cnt,
    }


@router.post("/api/push/subscribe")
async def push_subscribe(body: PushSubscribeIn, request: Request, user=Depends(security.require_user)):
    """Înregistrează abonamentul acestui dispozitiv şi porneşte push-ul pentru cont. `endpoint` e
    unic global: la re-abonare actualizăm cheile (ON CONFLICT)."""
    if not push.enabled():
        raise ApiError(503, "push.unavailable", "web push is not configured on this server")
    s = body.subscription
    if not push.endpoint_allowed(s.endpoint):     # SSRF: doar servicii de push cunoscute, https
        raise ApiError(400, "push.badEndpoint", "not a recognised web-push endpoint")
    existing = await db.fetchone(
        "SELECT 1 FROM push_subscriptions WHERE user_id=? AND endpoint=?", user["id"], s.endpoint)
    if not existing:
        n = (await db.fetchone(
            "SELECT COUNT(*) AS c FROM push_subscriptions WHERE user_id=?", user["id"]))["c"]
        if n >= MAX_PUSH_SUBS:
            raise ApiError(400, "push.tooMany", "too many devices subscribed on this account",
                           vars={"max": MAX_PUSH_SUBS})
    ua = (request.headers.get("user-agent") or "")[:200]
    lang = body.lang if body.lang in ("en", "ro") else "en"
    await db.execute(
        "INSERT INTO push_subscriptions(user_id, endpoint, p256dh, auth, ua, created)"
        " VALUES(?,?,?,?,?,?)"
        " ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id, p256dh=excluded.p256dh,"
        " auth=excluded.auth, ua=excluded.ua, fail_count=0",
        user["id"], s.endpoint, s.p256dh, s.auth, ua, time.time())
    await db.execute("UPDATE users SET push_task_enabled=1, push_lang=? WHERE id=?", lang, user["id"])
    cnt = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM push_subscriptions WHERE user_id=?", user["id"]))["c"]
    audit.detail(request, "push subscribed (%d device(s))" % cnt)
    return {"ok": True, "devices": cnt}


@router.post("/api/push/unsubscribe")
async def push_unsubscribe(body: PushSubIn, user=Depends(security.require_user)):
    """Scoate abonamentul acestui dispozitiv (doar al contului curent)."""
    await db.execute("DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?",
                     user["id"], body.endpoint)
    cnt = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM push_subscriptions WHERE user_id=?", user["id"]))["c"]
    return {"ok": True, "devices": cnt}


@router.post("/api/push/prefs")
async def push_prefs(body: PushPrefsIn, user=Depends(security.require_user)):
    """Pornit/oprit + pragul (secunde). NU şterge abonamentele — oprit = pur şi simplu nu trimitem."""
    await db.execute("UPDATE users SET push_task_enabled=?, push_task_min_seconds=? WHERE id=?",
                     1 if body.enabled else 0, _clamp_push_seconds(body.minSeconds), user["id"])
    return {"ok": True}


@router.post("/api/push/test")
async def push_test(user=Depends(security.require_user)):
    """Push de test către dispozitivele contului — ca butonul de test SMTP/webhook."""
    now = time.time()
    if now - _push_test_at.get(user["id"], 0) < 30:   # rate-limit: nu transforma /test în scanner
        raise ApiError(429, "push.testRate", "wait a few seconds before testing again")
    _push_test_at[user["id"]] = now
    subs = await db.fetchall(
        "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id=?", user["id"])
    if not subs:
        raise ApiError(400, "push.noDevices", "no device is subscribed on this account")
    urow = await db.fetchone("SELECT push_lang FROM users WHERE id=?", user["id"])
    st = push.strings(urow["push_lang"] if urow else "en")
    gone = await asyncio.to_thread(
        push.send, [(s["endpoint"], s["p256dh"], s["auth"]) for s in subs],
        st["test_title"], st["test_body"], "push-test")
    for ep in gone:
        await db.execute("DELETE FROM push_subscriptions WHERE endpoint=?", ep)
    return {"ok": True, "sent": len(subs) - len(gone), "gone": len(gone)}


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------


# ── [status] /api/status, version + update check ──────────────────────────────────────────────────

@router.get("/api/status")
async def status(request: Request, user=Depends(authz.perm('host.view', list=True, tokens='read'))):
    """Rezumat operațional: hosturi online, sesiuni, disc (transcripturi +
    arhivă), uptime și versiuni. Alimentează panoul de status.
    3.6: totalurile numără DOAR hosturile vizibile contului (fără oracol de mărimea flotei),
    sesiunile doar pe hosturile unde le poate vedea; discul şi sănătatea gateway-ului (date de
    instanţă) doar cu `security.view`."""
    grants = authz.grants_of(request)
    vis = await authz.visible_hosts(grants, "host.view")
    hosts = [h for h in await db.fetchall("SELECT id, connection_type, via_host_id FROM hosts")
             if authz.in_visible(vis, h["id"])]
    online = sum(1 for h in hosts if hostmodel.host_online(h))   # jump = agentul părinte (vezi hostmodel.host_online)
    svis = await authz.visible_hosts(grants, "session.watch", "recording.view")
    if svis is None:
        rows = await db.fetchall("SELECT state, COUNT(*) AS c FROM sessions GROUP BY state")
    elif svis:
        rows = await db.fetchall(
            "SELECT state, COUNT(*) AS c FROM sessions WHERE host_id IN (%s) GROUP BY state"
            % ",".join("?" * len(svis)), *sorted(svis))
    else:
        rows = []
    by_state = {r["state"]: r["c"] for r in rows}
    instance = grants.has_global("security.view")
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
        "storage": (await asyncio.to_thread(core.storage_stats)) if instance else None,
        "gateway": (await health.snapshot(core, db)) if instance else None,
    }


def _with_command(data: dict) -> dict:
    """Only issue an update command when there is really something to update — otherwise it is noise."""
    out = {**data, "configurable": config.UPDATE_CHECK}
    if data.get("update_available") and data.get("latest"):
        out["update_command"] = config.UPDATE_COMMAND.replace("{version}", data["latest"])
        # changelog-ul din aplicaţie e al versiunii INSTALATE; ce aduce cea nouă stă în release
        # notes-urile ei. Construit doar din valori validate (owner/repo + tag), nu din text liber.
        if (re.fullmatch(r"[\w.-]+/[\w.-]+", config.UPDATE_REPO)
                and re.fullmatch(r"v?\d+(\.\d+)*", data["latest"])):
            out["release_url"] = "https://github.com/%s/releases/tag/%s" % (config.UPDATE_REPO, data["latest"])
    return out


async def _update_check_enabled() -> bool:
    """Comutatorul din Setări; implicit pornit, dar `WEBTERM_UPDATE_CHECK=0` bate setarea."""
    return (await db.get_setting("update_check", "1")) == "1"


@router.get("/api/version")
async def version_info(user=Depends(security.require_user)):
    """Versiunea curentă + dacă există una mai nouă pe GitHub.
    Rezultatul e cache-uit (o zi la succes, o oră la eșec), deci sigur de apelat des."""
    return _with_command(await updatecheck.check(enabled=await _update_check_enabled()))


@router.post("/api/version/check")
async def version_check_toggle(body: UpdateCheckIn, user=Depends(authz.perm('settings.manage'))):
    """Pornește/oprește verificarea. Oprită, gateway-ul nu mai face NICIO conexiune
    din proprie inițiativă spre exterior — de-aia merită să fie la un click."""
    await db.set_setting("update_check", "1" if body.enabled else "0")
    updatecheck.reset_cache()          # răspuns imediat, nu la următoarea fereastră
    # aceeaşi formă ca GET /api/version şi /refresh: UI-ul înlocuieşte starea cu acest răspuns,
    # deci fără comanda şi link-ul de release notes ele dispăreau până la redeschiderea panoului
    return _with_command(await updatecheck.check(force=True, enabled=body.enabled))


@router.post("/api/version/refresh")
async def version_refresh(user=Depends(authz.perm('settings.manage'))):
    """„Verifică acum" — automat întrebăm o dată pe zi, dar când chiar aștepți o
    versiune n-are rost să aștepți fereastra."""
    enabled = await _update_check_enabled()
    if not enabled:
        raise ApiError(400, "updates.checkOff", "the version check is turned off")
    return _with_command(await updatecheck.check(force=True, enabled=True))


# ── [hosts-csv] Export / import CSV ──────────────────────────────────────────────────────
# Mutarea unui subset de hosturi pe alt gateway, sau o listă editabilă într-un spreadsheet.
# NICIUN secret nu intră în fişier: nici credenţiale/chei/passphrase-uri, nici tokenuri de
# enroll/agent, nici instance id-uri, nici pinurile known_hosts, nici tokenuri de share. Exportul
# construieşte fiecare rând dintr-o listă ALBĂ de coloane — nu din `SELECT *` filtrat — ca o
# coloană secretă adăugată mâine să nu ajungă singură în CSV.
HOSTS_CSV_COLUMNS = ("name", "connection_type", "hostname", "port", "username", "via_host",
                     "folder", "tags", "note", "require_2fa", "credential_policy", "auth_method",
                     "agent_note")
HOSTS_CSV_AGENT_NOTE = "reinstall the agent on the new gateway"
HOSTS_IMPORT_MAX = 500
# CSV injection: o celulă care începe cu = + - @ (sau TAB/CR) e o FORMULĂ pentru Excel/LibreOffice
# („=HYPERLINK(...)" într-o notă). O prefixăm cu `'`, pe care spreadsheet-ul îl ia drept „text".
# Prefixăm şi celulele care încep deja cu apostroafe urmate de un declanşator, ca importul (care
# scoate EXACT un `'`, vezi `lib/hostscsv.ts`) să fie fără pierderi: „'=x" → „''=x" → „'=x".
_CSV_FORMULA_RE = re.compile(r"^'*[=+\-@\t\r]")


def _csv_cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if _CSV_FORMULA_RE.match(s) else s


def _hosts_csv(rows, names_by_id: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")          # RFC 4180: CRLF, ghilimele doar la nevoie
    w.writerow(HOSTS_CSV_COLUMNS)
    for r in rows:
        ctype = conntypes.of(r)
        agent = ctype == "agent"
        via = r["via_host_id"] if ctype in conntypes.JUMP else None
        w.writerow([_csv_cell(x) for x in (
            r["name"], ctype, r["hostname"] or "",
            "" if agent else (r["ssh_port"] or ""),
            "" if agent else (r["ssh_username"] or ""),
            names_by_id.get(via, "") if via else "",
            r["folder"] or "", " ".join(hostmodel.tag_list(r["tags"] or "", None)), r["note"] or "",
            1 if r["require_2fa"] else 0,
            "" if agent else (r["credential_policy"] or ""),
            (r["auth_method"] or "") if ctype in conntypes.SSH_FAMILY else "",
            HOSTS_CSV_AGENT_NOTE if agent else "")])
    return buf.getvalue()


@router.get("/api/hosts/export.csv")
async def export_hosts_csv(request: Request, ids: str = "", user=Depends(authz.perm('hosts.export'))):
    """Exportă hosturile alese ca CSV. Doar cookie (`require_user`): un token de automatizare
    nu scoate inventarul flotei.

    Vizibilitate = lista de hosturi din sidebar: ţintele efemere („conectează o dată") NU intră.
    Hosturile cu `require_2fa` INTRĂ, fără step-up: exportul e doar metadate (nume, adresă,
    port, user, folder) — exact ce `GET /api/hosts` arată deja aceluiaşi cookie fără step-up.
    Step-up-ul păzeşte accesul LA host (shell, fişiere, credenţiale), nu numele lui."""
    try:
        wanted = sorted({int(x) for x in ids.replace(" ", "").split(",") if x})
    except ValueError:
        raise ApiError(400, "hostcsv.badIds", "ids must be a comma-separated list of host ids")
    if not wanted:
        raise ApiError(400, "hostcsv.noIds", "pick at least one host to export")
    if len(wanted) > 10000:
        raise ApiError(400, "hostcsv.badIds", "ids must be a comma-separated list of host ids")
    # 3.6: doar hosturile vizibile (un id cerut din afara scope-ului dispare tăcut, ca unul
    # inexistent); numele `via` al unui jump se exportă doar dacă şi agentul e vizibil
    vis = await authz.visible_hosts(authz.grants_of(request), "host.view")
    rows = [r for r in await db.fetchall(
        "SELECT * FROM hosts WHERE ephemeral=0 AND id IN (%s) ORDER BY name COLLATE NOCASE, id"
        % ",".join("?" * len(wanted)), *wanted) if authz.in_visible(vis, r["id"])]
    names = {r["id"]: r["name"] for r in await db.fetchall("SELECT id, name FROM hosts")
             if authz.in_visible(vis, r["id"])}
    body = "﻿" + _hosts_csv(rows, names)     # BOM: Excel deschide diacriticele corect
    audit.detail(request, "exported %d hosts as CSV" % len(rows))
    fname = "webterm-hosts-%s.csv" % time.strftime("%Y%m%d")
    return Response(content=body.encode("utf-8"), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % fname,
                             "Cache-Control": "no-store"})


class HostCsvRow(BaseModel):
    """Un rând de CSV, ca şiruri (aşa cum le-a parsat clientul). Coloanele necunoscute — inclusiv
    `agent_note` — sunt ignorate; nimic de aici nu e un secret."""
    model_config = {"coerce_numbers_to_str": True}
    name: str = ""
    connection_type: str = ""
    hostname: str = ""
    port: str = ""
    username: str = ""
    via_host: str = ""
    folder: str = ""
    tags: str = ""
    note: str = ""
    require_2fa: str = ""
    credential_policy: str = ""
    auth_method: str = ""


class HostImportOptions(BaseModel):
    folder: str = ""                 # gol = folderul din fişier
    tags: str = ""                   # etichete ADĂUGATE fiecărui rând
    credential_policy: str = ""      # rândurile SSH/telnet; gol = coloana din fişier, apoi `ask`
    enroll_ttl: int = 86400          # link-urile de instalare ale agenţilor (implicit 24h)


class HostImportIn(BaseModel):
    rows: list = []
    options: HostImportOptions = HostImportOptions()


def _csv_bool(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "y", "da")


def _csv_port(v) -> Optional[int]:
    s = str(v or "").strip()
    if not s:
        return None
    if not s.isdigit() or not 1 <= int(s) <= 65535:
        raise ApiError(400, "host.badPort", "the port must be between 1 and 65535")
    return int(s)


async def _resolve_via(name: str) -> int:
    """`via_host` e NUMELE agentului (id-urile nu supravieţuiesc mutării pe alt gateway).
    Mai multe agente cu acelaşi nume = ambiguu; un host non-agent cu numele ăsta trece mai
    departe, ca validarea comună să-l refuze cu codul ei (`sshjump.needsAgent`)."""
    name = name.strip()
    if not name:
        raise ApiError(400, "hostcsv.viaRequired", "a jump host needs via_host (the agent's name)")
    cands = await db.fetchall(
        "SELECT id, connection_type FROM hosts WHERE ephemeral=0 AND lower(name)=lower(?)", name)
    agents = [c for c in cands if conntypes.is_agent(c)]
    if len(agents) > 1:
        raise ApiError(400, "hostcsv.viaAmbiguous", "more than one agent host has this name",
                       vars={"name": name})
    if agents:
        return agents[0]["id"]
    if cands:
        return cands[0]["id"]
    raise ApiError(400, "hostcsv.viaMissing", "no agent host with this name", vars={"name": name})


async def _check_duplicate(h: hostmodel.HostIn, v: dict) -> None:
    """Serverul re-verifică duplicatele — statusul din previzualizarea clientului nu contează.
    Duplicat = acelaşi nume (fără diferenţă de majuscule) SAU, la conexiunile directe, aceeaşi
    adresă + port + user. Ţintele efemere nu contează (dispar singure)."""
    dup = await db.fetchone("SELECT 1 FROM hosts WHERE ephemeral=0 AND lower(name)=lower(?)",
                            h.name.strip())
    if not dup and v["ctype"] != "agent":
        dup = await db.fetchone(
            "SELECT 1 FROM hosts WHERE ephemeral=0 AND NOT " + conntypes.SQL_IS_AGENT +
            " AND lower(hostname)=lower(?) AND ssh_port=?"
            " AND lower(coalesce(ssh_username,''))=lower(?)",
            h.hostname.strip(), v["port"], h.ssh_username.strip())
    if dup:
        raise ApiError(409, "hostcsv.duplicate", "a host with this name or address already exists",
                       vars={"name": h.name.strip()})


async def _import_row(r: HostCsvRow, opts: HostImportOptions, user, grants=None) -> tuple:
    """Un rând → host nou. Ordinea verificărilor e oglindită de previzualizarea din
    `lib/hostscsv.ts` (acelaşi cod de eroare pe acelaşi rând)."""
    ctype = r.connection_type.strip().lower()
    if not ctype:
        raise ApiError(400, "hostcsv.typeRequired", "connection_type is required")
    agent = ctype == "agent"
    port = None if agent else _csv_port(r.port)
    via_id = await _resolve_via(r.via_host) if ctype in conntypes.JUMP else 0
    h = hostmodel.HostIn(
        name=r.name, note=r.note, folder=opts.folder.strip() or r.folder,
        connection_type=ctype, hostname=r.hostname, ssh_username="" if agent else r.username,
        ssh_port=port, via_host_id=via_id,
        auth_method=r.auth_method.strip().lower() or "password",
        require_2fa=_csv_bool(r.require_2fa),
        # agentul n-are credenţiale (ca la Add host → Agent); restul: opţiunea, apoi fişierul,
        # apoi `ask` — CSV-ul nu duce parole, deci `stored` ar însemna „fără nimic stocat"
        credential_policy="stored" if agent else (
            opts.credential_policy or r.credential_policy.strip().lower() or "ask"),
        tags=" ".join(x for x in (r.tags, opts.tags) if x.strip()), enroll_ttl=opts.enroll_ttl)
    v = await hostmodel.validate_host(h, user, grants)
    await _check_duplicate(h, v)
    return await hostmodel.insert_host(h, user, v)


@router.post("/api/hosts/import")
async def import_hosts(body: HostImportIn, request: Request, user=Depends(authz.perm("hosts.create"))):
    """Importă hosturi dintr-un CSV parsat de client. Fiecare rând trece prin EXACT validarea
    lui `POST /api/hosts` (`hostmodel.validate_host`); duplicatele sunt sărite. Rândurile agent intră
    PRIMELE, ca ţintele ssh-jump/telnet-jump din acelaşi fişier să-şi găsească agentul după nume.

    Agenţii importaţi sunt hosturi în aşteptare, ca la Add host → Agent: token propriu + link de
    instalare cu TTL. Un link de GRUP nu se poate folosi aici — `/install/group` CREEAZĂ un host
    nou la fiecare rulare, nu se leagă de unul existent — deci întoarcem comanda per host."""
    if len(body.rows) > HOSTS_IMPORT_MAX:
        raise ApiError(400, "hostcsv.tooMany", "at most %d rows per import" % HOSTS_IMPORT_MAX,
                       vars={"max": HOSTS_IMPORT_MAX})
    opts = body.options
    if opts.credential_policy:
        hostmodel.check_cred_policy(opts.credential_policy)
    parsed = []
    for i, raw in enumerate(body.rows):
        try:
            parsed.append((i, HostCsvRow.model_validate(raw if isinstance(raw, dict) else None)))
        except ValidationError:
            parsed.append((i, None))
    is_agent = lambda p: p[1] is not None and p[1].connection_type.strip().lower() == "agent"  # noqa: E731
    order = [p for p in parsed if is_agent(p)] + [p for p in parsed if not is_agent(p)]
    results = {}
    created = 0
    for i, r in order:
        try:
            if r is None:
                raise ApiError(400, "hostcsv.badRow", "a row must be an object of text cells")
            row, enroll, pw = await _import_row(r, opts, user, authz.grants_of(request))
        except ApiError as e:
            results[i] = {"index": i, "ok": False, "code": e.code, "vars": e.vars,
                          "skipped": e.code == "hostcsv.duplicate"}
            continue
        created += 1
        res = {"index": i, "ok": True, "id": row["id"], "name": row["name"]}
        if conntypes.is_agent(row):
            res.update(install_command=hostmodel.install_command(enroll, pw),
                       install_command_dedicated=hostmodel.install_command_dedicated(enroll, pw),
                       enroll_expires=row["enroll_expires"])
        results[i] = res
    skipped = len(body.rows) - created
    audit.detail(request, "imported %d hosts (%d skipped)" % (created, skipped))
    return {"results": [results[i] for i in sorted(results)], "created": created,
            "skipped": skipped}


# ── [enroll] New install one-liner for an existing host ────────────────────────────────────────
class EnrollRenew(BaseModel):
    enroll_ttl: int = 3600           # secunde; implicit 1h (plafonat 5min..30 zile)
    enroll_password: str = ""        # write-only; gol = fără parolă


@router.post("/api/hosts/{host_id}/enroll")
async def renew_enroll(host_id: int, user=Depends(authz.perm('host.admin', host='host_id')),
                       body: EnrollRenew = EnrollRenew()):
    """New install one-liner for an existing host (reinstall / new enroll). Body optional:
    fără el → 1h, fără parolă (retrocompatibil cu clienţii care nu trimit nimic)."""
    await stepup.require_host_stepup(host_id, user)   # H1: enroll nou = clasă de provisioning
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    enroll = security.new_token()[:32]
    ttl = max(300, min(30 * 86400, int(body.enroll_ttl or 3600)))
    pw = hostmodel.clean_enroll_pass(body.enroll_password)
    pass_hash = await security.hash_password_async(pw) if pw else None
    exp = time.time() + ttl
    await db.execute(
        "UPDATE hosts SET enroll_token=?, enroll_expires=?, enroll_pass_hash=?, instance_id=NULL"
        " WHERE id=?", enroll, exp, pass_hash, host_id)
    return {"install_command": hostmodel.install_command(enroll, pw),
            "install_command_dedicated": hostmodel.install_command_dedicated(enroll, pw),
            "enroll_expires": exp}


# ── [certs] TLS certificates (3.6.7) ─────────────────────────────────────────────────


async def _certs_json(request: Request) -> dict:
    grants = getattr(request.state, "grants", None)
    can_renew = bool(grants and grants.has_global("certs.renew"))
    st = certmon.status()
    fwd = fwddomain.forward_domain()
    allowed = certmon.renew_domains(fwd)
    items = []
    for it in st["items"]:
        it = dict(it)
        cmd = ""
        if it.get("renew_domain") in allowed:
            try:
                cmd = certmon.renew_command(it["renew_domain"])
            except ValueError:
                cmd = ""                    # fail closed: no command rather than a wrong one
        it["renew_command"] = cmd
        # the exact incident: a wildcard Traefik keeps serving although it is not renewing, or a
        # wildcard on an HTTP-01 install. A HINT only — the ACME store is not ours to read; the
        # host script (`cert-renew.sh --report`) is what sees which store holds it.
        it["wildcard_hint"] = bool(it.get("wildcard")) and (
            it.get("level", 0) > 0 or config.CERT_RESOLVER == "le")
        items.append(it)
    host_id = await certmon.cert_renew_host_id()
    host = None
    if host_id:
        row = await db.fetchone("SELECT id, name, connection_type FROM hosts WHERE id=?", host_id)
        if row:
            host = {"id": row["id"], "name": row["name"]}
    return {
        "enabled": bool(certmon.targets(fwd)),
        "checked_at": st["checked_at"], "running": st["running"], "items": items,
        "warn_days": certmon.WARN_DAYS, "crit_days": certmon.CRIT_DAYS,
        "resolver": config.CERT_RESOLVER, "can_renew": can_renew,
        "renew_host": host if can_renew else None,
        "retry_after": certmon.manual_retry_after(),
    }


@router.get("/api/certs")
async def certs_status(request: Request, user=Depends(authz.perm('settings.manage'))):
    return await _certs_json(request)


@router.post("/api/certs/check")
async def certs_check(request: Request, user=Depends(authz.perm('settings.manage'))):
    """"Check now". Rate-limited instance-wide (it opens outbound TLS connections)."""
    retry = certmon.manual_retry_after()
    if retry:
        raise ApiError(429, "certs.rateLimited", "a check just ran; retry in %ds" % retry,
                       headers={"Retry-After": str(retry)}, vars={"retry": retry})
    certmon.mark_manual()
    await certmon.check_all(fwddomain.forward_domain())
    return await _certs_json(request)


class CertRenewHostIn(BaseModel):
    host_id: int = 0                # 0 = forget the choice


@router.put("/api/certs/renew-host")
async def certs_renew_host(body: CertRenewHostIn, request: Request,
                           user=Depends(authz.perm('certs.renew'))):
    """Which enrolled host IS the gateway host (picked once by an Owner). Opening the terminal
    there still needs `session.open` on it and a fresh factor, checked at use time."""
    if body.host_id:
        row = await db.fetchone("SELECT id, name, connection_type FROM hosts WHERE id=?",
                                body.host_id)
        if not row:
            raise ApiError(404, "host.missing", "no such host")
        if not conntypes.is_agent(row):
            raise ApiError(400, "certs.renewAgentOnly", "pick an agent host (the gateway host itself)")
        await authz.require_on(request, body.host_id, "session.open")
        await db.set_setting(certmon.K_CERT_RENEW_HOST, str(row["id"]))
        audit.detail(request, "certificate renewal host set to %s (#%d)" % (row["name"], row["id"]))
    else:
        await db.execute("DELETE FROM app_settings WHERE key=?", certmon.K_CERT_RENEW_HOST)
        audit.detail(request, "certificate renewal host cleared")
    return await _certs_json(request)


class CertRenewIn(BaseModel):
    domain: str = Field("", max_length=260)
    rows: int = Field(24, ge=2, le=500)
    cols: int = Field(80, ge=2, le=1000)
    tz: str = None
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""


@router.post("/api/hosts/{host_id}/cert-renew")
async def cert_renew_session(host_id: int, body: CertRenewIn, request: Request,
                             user=Depends(authz.perm('certs.renew'))):
    """Open a terminal on the gateway host with the renewal command typed, NOT executed.

    Gates, in order (fail closed at each): `certs.renew` (Owner-only, the route's declared
    permission) → `session.open` on that host (404 when it is not visible, like any host route)
    → the host is the one the Owner designated → the name is one WebTerm monitors (an allow-list,
    then the strict regex inside `renew_command`) → a FRESH second factor, also on hosts without
    require_2fa (`stepup.require_fresh_factor`, the deploy-key gate). Tokens never pass (`perm` without
    `tokens=`, and the fresh-factor gate refuses them again)."""
    await authz.require_on(request, host_id, "session.open")
    want = await certmon.cert_renew_host_id()
    if not want:
        raise ApiError(409, "certs.noRenewHost",
                       "pick the gateway host first (Settings → Infrastructure → Certificates)")
    if want != host_id:
        raise ApiError(409, "certs.wrongRenewHost", "this is not the host picked for renewals")
    domain = (body.domain or "").strip()
    if domain not in certmon.renew_domains(fwddomain.forward_domain()):
        raise ApiError(400, "certs.badDomain", "not a certificate name WebTerm monitors")
    try:
        command = certmon.renew_command(domain)
    except ValueError:
        raise ApiError(400, "certs.badDomain", "not a certificate name WebTerm monitors")
    result = await _open_gateway_terminal(
        host_id, user, body, command, "TLS renew: %s" % domain[:60], CERT_RENEW_ORIGIN,
        certmon.HEADER_CERT)
    audit.detail(request, "certificate renewal terminal for %s (command typed, not run)" % domain)
    log.warning("certificate renewal terminal opened on host #%d for %s by %s",
                host_id, domain, user["email"] if not isinstance(user, dict) else user.get("email"))
    return dict(result, command=command)


async def _open_gateway_terminal(host_id: int, user, body, command: str, title: str,
                                 origin: str, header: str) -> dict:
    """The ONE path that types a root command into a terminal on the gateway host (3.6.7 cert
    renewal, generalised in 3.6.8 for System health). The caller has already checked its own
    permission (`certs.renew`, Owner-only), `session.open` on the host, that the host is the one
    the Owner designated, and built `command` from a server-side allow-list (certmon.renew_command
    / healthcmd.render). Here: an agent host only → a FRESH second factor (also without
    require_2fa; tokens never) → the session, created already owned by this Owner with an origin
    that makes it private (read-only for everyone else, never shareable). The command is TYPED by
    a readline prompt, never run by us (certmon.typed_session_cmd)."""
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    if not conntypes.is_agent(row):
        raise ApiError(400, "certs.renewAgentOnly", "pick an agent host (the gateway host itself)")
    # OP-01 (audit 2026-10-17): the gateway host is the crown jewel (database + vault) and the
    # command typed here runs as root — a real second factor ALWAYS, whatever the host's
    # `require_2fa` flag says, and never a window the password alone opened (/stepup on a host
    # without 2FA). An account with no factor gets `stepup.needsFactor`, which the UI turns into
    # the way to Settings → Sign-in & 2FA.
    await stepup.require_fresh_factor(host_id, user, body.stepup_grant, body.stepup_password,
                                body.stepup_totp, real_factor=True)
    try:
        # creator + origin go into the INSERT itself (no separate stamp afterwards): the row is
        # never visible as "everyone's" or as a plain web session, not even while 'creating'
        return await core.create_session(host_id, title, body.rows, body.cols, body.tz,
                                         certmon.typed_session_cmd(command, header),
                                         created_by_id=user["id"], origin=origin)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")
    except core.SessionLimitReached:
        raise ApiError(409, "session.limit",
                       f"the host reached its limit of {core.MAX_SESSIONS_HINT} sessions — close one first",
                       vars={"limit": core.MAX_SESSIONS_HINT})
    except RuntimeError as e:
        raise errors.runtime_api_error(e, "session.createFailed")


# ── [health] System health (3.6.8, syshealth.py) ──────────────────────────────────────
# One list of everything that can fail silently, with why it matters, what to do, and — when the
# fix needs root on the gateway host — the exact command (copy, or for an Owner: typed, not run,
# into a terminal there; the same gates as the certificate renewal above).
async def _health_json(request: Request) -> dict:
    grants = getattr(request.state, "grants", None)
    can_manage = bool(grants and grants.has_global("settings.manage"))
    can_terminal = bool(grants and grants.has_global("certs.renew"))
    rows = await syshealth.rows()
    # host ids → names, ONLY for hosts this principal may see (the rest are counted, not named)
    ids = set()
    for r in rows:
        try:
            ids.update(h for h in json.loads(r.get("hosts") or "[]") if isinstance(h, int))
        except ValueError:
            pass
    names = {}
    if ids:
        vis = await authz.visible_hosts(grants, "host.view") if grants else set()
        for h in await db.fetchall("SELECT id, name FROM hosts WHERE id IN (%s)"
                                   % ",".join("?" * len(ids)), *sorted(ids)):
            if authz.in_visible(vis, h["id"]):
                names[h["id"]] = h["name"]
    now = time.time()
    checks = [syshealth.view(r, now, names) for r in rows]
    checks.sort(key=lambda c: (c["muted"], -syshealth.RANK.get(c["severity"], 0), c["id"]))
    if not can_manage:
        # commands are for the people who can act on them; a viewer sees what and why
        for c in checks:
            c["commands"] = []
    host = None
    if can_terminal:
        hid = await certmon.cert_renew_host_id()
        if hid:
            row = await db.fetchone("SELECT id, name FROM hosts WHERE id=?", hid)
            if row:
                host = {"id": row["id"], "name": row["name"]}
    last = syshealth.last_run()   # PF-02: in-memory, not a DB read (the DB copy lags ≤10 min)
    return {"checks": checks, "attention": syshealth.attention(rows, now),
            "checked_at": last or None, "can_manage": can_manage, "can_terminal": can_terminal,
            "can_mute_critical": can_manage and can_terminal, "terminal_host": host, "retry_after": syshealth.manual_retry_after()}


@router.get("/api/health")
async def health_status(request: Request, user=Depends(authz.perm('security.view'))):
    # cookie only: the automation-token allow-list stays exactly what it was (route_auth_test)
    return await _health_json(request)


HEALTH_RECHECK_BUDGET = 45.0


@router.post("/api/health/check")
async def health_recheck(request: Request, user=Depends(authz.perm('settings.manage'))):
    """"Re-check now": every tier, rate-limited instance-wide (it opens outbound connections)."""
    retry = syshealth.manual_retry_after()
    if retry:
        raise ApiError(429, "health.rateLimited", "a check just ran; retry in %ds" % retry,
                       headers={"Retry-After": str(retry)}, vars={"retry": retry})
    syshealth.mark_manual()
    try:
        await asyncio.wait_for(syshealth.run_all(), timeout=HEALTH_RECHECK_BUDGET)
    except asyncio.TimeoutError:
        log.warning("system health: the manual re-check exceeded %.0f s", HEALTH_RECHECK_BUDGET)
    return await _health_json(request)


_CHECK_ID_RE = re.compile(r"^[a-z_]{1,24}(?:\.[a-z_]{1,24})?$")


class HealthMuteIn(BaseModel):
    mode: str = Field(..., max_length=8)        # 7d | 30d | change | off


@router.post("/api/health/{check_id}/mute")
async def health_mute(check_id: str, body: HealthMuteIn, request: Request,
                      user=Depends(authz.perm('settings.manage'))):
    if not _CHECK_ID_RE.match(check_id or "") or body.mode not in syshealth.MUTE_MODES:
        raise ApiError(400, "health.badMute", "unknown check or mute mode")
    grants = getattr(request.state, "grants", None)
    owner = bool(grants and grants.has_global("certs.renew"))
    who = (user.get("email") if isinstance(user, dict) else user["email"]) or ""
    try:
        row = await syshealth.mute(check_id, body.mode, who, owner=owner)
    except KeyError:
        raise ApiError(404, "health.missing", "no such check")
    except syshealth.MuteDenied:
        # security review 3.6.8 (L1): a check that is, or can become, critical is muted by the
        # Owner only — an Admin cannot hide it from the Owner
        audit.detail(request, "system health check %s: mute %s REFUSED (critical-capable)"
                     % (check_id, body.mode))
        raise ApiError(403, "health.muteOwnerOnly",
                       "only the Owner can mute a check that can become critical")
    audit.detail(request, "system health check %s: mute %s" % (check_id, body.mode))
    if not owner and syshealth.MUTE_MODES[body.mode] != 0:
        # …and every mute by someone else is told to everyone with security.view (in-app only)
        syshealth.notify_muted(check_id, body.mode, who, row)
    return await _health_json(request)


HEALTH_FIX_ORIGIN = "health-fix"


class HealthTerminalIn(BaseModel):
    check_id: str = Field("", max_length=50)
    index: int = Field(0, ge=0, le=healthcmd.MAX_COMMANDS - 1)
    rows: int = Field(24, ge=2, le=500)
    cols: int = Field(80, ge=2, le=1000)
    tz: str = None
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""


@router.post("/api/hosts/{host_id}/health-terminal")
async def health_terminal(host_id: int, body: HealthTerminalIn, request: Request,
                          user=Depends(authz.perm('certs.renew'))):
    """Open a terminal on the gateway host with a System health fix TYPED, not run.

    The client names a CHECK and which of its commands (index) — never a command, a template or a
    parameter. The command is the one the server derived for that check's CURRENT result,
    re-rendered from the allow-list now (healthcmd.render). Gates, in order, like the certificate
    renewal: `certs.renew` (Owner-only) → `session.open` on the host → it is the designated
    gateway host → the check exists and has that command (a certificate name must still be one
    WebTerm monitors) → a fresh second factor → a private session (origin `health-fix`)."""
    await authz.require_on(request, host_id, "session.open")
    want = await certmon.cert_renew_host_id()
    if not want:
        raise ApiError(409, "certs.noRenewHost",
                       "pick the gateway host first (Settings → Infrastructure → Certificates)")
    if want != host_id:
        raise ApiError(409, "certs.wrongRenewHost", "this is not the host picked for renewals")
    cid = body.check_id or ""
    row = None
    if _CHECK_ID_RE.match(cid):
        row = next((r for r in await syshealth.rows() if r.get("id") == cid), None)
    if row is None:
        raise ApiError(404, "health.missing", "no such check")
    try:
        stored = json.loads(row.get("commands") or "[]")
    except ValueError:
        stored = []
    if (not isinstance(stored, list) or body.index >= len(stored)
            or not isinstance(stored[body.index], dict)):
        raise ApiError(400, "health.noCommand", "this check has no such command")
    spec = stored[body.index]
    if spec.get("t") == "cert_renew" and (spec.get("p") or {}).get("domain") not in \
            certmon.renew_domains(fwddomain.forward_domain()):
        raise ApiError(400, "certs.badDomain", "not a certificate name WebTerm monitors")
    try:
        command = healthcmd.render(spec.get("t"), spec.get("p") or {})["text"]
    except healthcmd.CommandError:
        raise ApiError(400, "health.noCommand", "this check has no such command")
    result = await _open_gateway_terminal(host_id, user, body, command, "Health fix: %s" % cid,
                                          HEALTH_FIX_ORIGIN, certmon.HEADER_HEALTH)
    audit.detail(request, "system health terminal for %s: %s (command typed, not run)"
                 % (cid, command[:200]))
    log.warning("system health terminal opened on host #%d for %s by %s", host_id, cid,
                (user.get("email") if isinstance(user, dict) else user["email"]) or "?")
    return dict(result, command=command)


# ── [signing] Cheie de semnare a flotei (per-deployment) ───────────────────────────────
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
async def signing_status(user=Depends(authz.perm('signing.manage'))):
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
        raise ApiError(404, "changelog.unavailable", "changelog is not available on this gateway")
    return {"text": text, "version": config.GATEWAY_VERSION}


@router.post("/api/signing/generate")
async def signing_generate(body: SigningGenIn, user=Depends(authz.perm('signing.manage'))):
    await stepup.require_reauth_for_secret(user, body.current_password, "generating the signing key")
    if signing.key_exists():
        raise ApiError(409, "signing.exists", "a fleet signing key already exists")
    if body.passphrase and len(body.passphrase) < 8:
        raise ApiError(400, "signing.passphraseTooShort", "the key passphrase must be at least 8 characters")
    try:
        await asyncio.to_thread(signing.generate, body.passphrase or None)
    except Exception as e:
        log.exception("signing key generation failed")
        raise ApiError(500, "signing.generateFailed", "generation failed: %s" % e)
    return _signing_status()


@router.post("/api/signing/import")
async def signing_import(body: SigningImportIn, user=Depends(authz.perm('signing.manage'))):
    await stepup.require_reauth_for_secret(user, body.current_password, "importing the signing key")
    if signing.key_exists():
        raise ApiError(409, "signing.exists", "a fleet signing key already exists")
    if body.store_passphrase and len(body.store_passphrase) < 8:
        raise ApiError(400, "signing.passphraseTooShort", "the storage passphrase must be at least 8 characters")
    try:
        await asyncio.to_thread(signing.import_key, body.pem.encode(),
                                body.load_passphrase or None, body.store_passphrase or None)
    except ValueError as e:
        raise _signing_value_error(e)
    except Exception as e:
        log.exception("signing key import failed")
        raise ApiError(500, "signing.importFailed", "import failed: %s" % e)
    return _signing_status()


@router.post("/api/signing/unlock")
async def signing_unlock(body: SigningPassIn, user=Depends(authz.perm('signing.manage'))):
    if not signing.key_exists():
        raise ApiError(404, "signing.missing", "no signing key")
    # Generarea, importul şi backupul cheii cer parola contului; deblocarea NU o cerea, deşi e
    # tot o operaţie pe cheia flotei. Efect: (a) endpointul devenea un oracol de ghicire a
    # parolei CHEII, fără nicio limitare — lockout-ul din `security` e pe login, nu aici; şi
    # (b) fiecare încercare consumă un thread din pool pe un KDF, deci un flood autentificat
    # înfunda şi restul muncii off-loop (backup, VACUUM, transcripturi).
    await stepup.require_reauth_for_secret(user, body.current_password, "unlocking the signing key")
    okk = await asyncio.to_thread(signing.load, body.passphrase or None)
    if not okk:
        raise ApiError(403, "auth.wrongPassword", "wrong password")
    return _signing_status()


@router.post("/api/signing/lock")
async def signing_lock(body: SigningPassIn, user=Depends(authz.perm('signing.manage'))):
    # Blocarea opreşte auto-update-ul pe TOATĂ flota, dintr-un singur POST. Un cookie furat
    # putea face asta fără să dovedească nimic — o negare de serviciu ieftină şi tăcută.
    await stepup.require_reauth_for_secret(user, body.current_password, "locking the signing key")
    signing.lock()
    return _signing_status()


@router.post("/api/signing/backup")
async def signing_backup(body: SigningPassIn, user=Depends(authz.perm('signing.manage'))):
    """Descarcă o copie CRIPTATĂ a cheii de semnare (scrypt→AES-GCM, cu parola dată).
    Pierderea cheii = agenții existenți merg mai departe, dar nu mai primesc update-uri."""
    await stepup.require_reauth_for_secret(user, body.current_password, "exporting the signing key")
    if not signing.key_exists():
        raise ApiError(404, "signing.missing", "no signing key")
    if len(body.passphrase) < 8:
        raise ApiError(400, "backup.passphraseTooShort", "the encryption passphrase must be at least 8 characters")
    try:
        blob = await asyncio.to_thread(backup.encrypt, signing.key_bytes(), body.passphrase)
    except Exception as e:
        log.exception("backup failed")
        raise ApiError(500, "backup.failed", "backup failed: %s" % e)
    return Response(content=blob, media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="webterm-signing-key.wtbk"'})


# ── [run] Consola de flotă: rulare non-interactivă a unei comenzi pe un host ────────
# Frontend-ul cheamă endpoint-ul ăsta o dată PER host (în paralel) și umple grila
# de rezultate pe măsură ce fiecare răspunde. Fără stare de „job" pe server.
class RunIn(BaseModel):
    command: str
    timeout: int = 60
    stepup_grant: str = ""     # 2FA: grant/parolă pt. host-uri cu require_2fa (H1)
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)
    confirmed: bool = False    # guardrail: regula „confirm" cere un DA explicit (vezi host_run)


@router.post("/api/hosts/{host_id}/run")
async def host_run(host_id: int, body: RunIn, request: Request,
                   user=Depends(authz.perm('run', host='host_id', tokens='run'))):
    audit.detail(request, "cmd: " + body.command.strip()[:200])
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)   # H1
    cmd = body.command.strip()
    if not cmd:
        raise ApiError(400, "run.empty", "empty command")
    if len(cmd) > 8000:
        raise ApiError(400, "run.tooLong", "command too long")
    # Guardrail-ul de comenzi era verificat DOAR client-side, la Enter în browser. Pe tastarea
    # directă în PTY aşa şi rămâne (nu inspectăm fluxul de taste), dar `/run` e un punct de
    # strangulare curat: cine ocoleşte UI-ul ocolea şi regula. Semnalat de auditul extern
    # (2026-08-06). `block` refuză; `confirm` cere confirmare explicită în cerere — serverul
    # nu poate deschide un dialog, dar poate pretinde că cineva a răspuns la el.
    await cmdguard.enforce_guard(cmd, body.confirmed)
    cmd_timeout = min(max(int(body.timeout), 1), 300)
    conn = core.source_for(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise ApiError(409, "host.offline", "host offline or has no agent")
    try:
        resp = await conn.run_command(cmd, cmd_timeout)
    except (core.AgentGone, TimeoutError, asyncio.TimeoutError):
        raise ApiError(504, "host.noAnswer", "the host did not answer in time")
    if not resp.get("ok"):
        raise ApiError(502, "run.failed", resp.get("msg") or "run failed")
    hrow = await db.fetchone("SELECT name FROM hosts WHERE id=?", host_id)
    await _record_history(host_id, hrow["name"] if hrow else "", cmd,
                          resp.get("exit_code"), "", "fleet",
                          user.get("actor_id") if isinstance(user, dict) else user["id"])
    return {"exit_code": resp.get("exit_code"), "timed_out": bool(resp.get("timed_out")),
            "stdout": resp.get("stdout", ""), "stderr": resp.get("stderr", ""),
            "duration": resp.get("duration")}


# ── [git] Git panel: fixed operations, root-relative literal paths ─────────────────
class GitIn(BaseModel):
    cwd: str = ""
    operation: str = ""
    path: str = ""
    orig: str = ""          # original path of a staged rename (unstage resets both sides)
    revision: str = ""
    message: str = ""
    sid: str = ""
    args: Optional[list[str]] = None  # strictly validated compatibility for cached clients
    confirmed: bool = False
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""


@router.post("/api/hosts/{host_id}/git")
async def host_git(host_id: int, body: GitIn, user=Depends(authz.perm('run', host='host_id'))):
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    operation = body.operation
    params = {"path": body.path, "revision": body.revision, "message": body.message, "orig": body.orig}
    if body.args is not None:
        if operation:
            raise ApiError(400, "git.badSubcommand", "choose one git request format")
        if len(body.args) > 24:
            raise ApiError(400, "run.tooManyArgs", "too many arguments")
        operation, params = gitpanel.legacy_operation(body.args)
    if operation == "cwd":
        # Git uses run permission, including cwd discovery; it does not require files.read.
        row = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", body.sid)
        if row is None or row["host_id"] != host_id:
            raise ApiError(404, "session.missing", "session not found")
        try:
            return {"cwd": await core.session_cwd(host_id, body.sid)}
        except core.AgentGone:
            raise ApiError(409, "host.offline", "host offline or has no agent")
        except (core.FileError, TimeoutError) as e:
            raise fserrors.file_api_error(e)
    cmd, guard = gitpanel.command(body.cwd, operation, **params)
    if operation in gitpanel.WRITE_OPS:
        await cmdguard.enforce_guard(guard, body.confirmed)
    conn = core.source_for(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise ApiError(409, "host.offline", "host offline or has no agent")
    try:
        resp = await conn.run_command(cmd, 30)
    except (core.AgentGone, TimeoutError, asyncio.TimeoutError):
        raise ApiError(504, "host.noAnswer", "the host did not answer in time")
    if not resp.get("ok"):
        raise ApiError(502, "run.failed", resp.get("msg") or "run failed")
    stdout = resp.get("stdout", "")
    # A read that could not open the directory carries a structured diagnosis (gitpanel._cd_or_diag);
    # turn it into an access decision for the panel and strip it from the visible output. Policy lives
    # in gitpanel.access_fix — the gateway never proposes a grant for a system path or a root agent.
    access = None
    stdout, diag = gitpanel.parse_diag(stdout)
    if diag is not None:
        access = gitpanel.access_fix(diag)
    return {"exit_code": resp.get("exit_code"), "stdout": stdout,
            "stderr": resp.get("stderr", ""), "access": access}


# ── [toolbox-db] Database connection launchers ────────────────────────────────────────────
# O conexiune salvată → o sesiune care rulează CLI-ul potrivit pe hostul agentului, cu ţinta
# pre-completată. Lansator, nu client. Slice 1: politica `ask` — clientul îşi cere singur parola,
# deci WebTerm nu atinge niciun secret (cel mai sigur). Comanda e construită dintr-o hartă FIXĂ
# pe engine, cu shlex.quote pe fiecare câmp — niciun input liber ajunge la shell.
_CONN_ENGINES = {
    "postgres":   {"bin": "psql", "port": 5432, "label": "PostgreSQL"},
    "mysql":      {"bin": "mysql", "port": 3306, "label": "MySQL / MariaDB"},
    "mongodb":    {"bin": "mongosh", "port": 27017, "label": "MongoDB"},
    "clickhouse": {"bin": "clickhouse-client", "port": 9000, "label": "ClickHouse"},
    "redis":      {"bin": "redis-cli", "port": 6379, "label": "Redis"},
    # InfluxDB vine în două lumi incompatibile: 1.x = user/parolă cu prompt „password:" (intră
    # perfect pe ask/stored — injecţia agentului matchuieşte exact promptul ăsta), 2.x/3.x =
    # token FĂRĂ prompt, deci un token „stored" ar trebui să treacă prin argv/env → vizibil în
    # ps/transcript, exact ce interzice modelul. Pentru 2.x lansăm `influx v1 shell` pe config-ul
    # LOCAL al hostului (`influx config`) — WebTerm nu stochează şi nu atinge token-ul.
    "influxdb":   {"bin": "influx", "port": 8086, "label": "InfluxDB 1.x"},
    "influxdb2":  {"bin": "influx", "port": 8086, "label": "InfluxDB 2.x"},
}
# câmpurile stocate sunt admin-only, dar validăm oricum: fără spaţii/metacaractere de shell
_CONN_FIELD = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})?$")


def _connection_json(r) -> dict:
    return {"id": r["id"], "host_id": r["host_id"], "label": r["label"], "engine": r["engine"],
            "target_host": r["target_host"] or "", "target_port": r["target_port"],
            "username": r["username"] or "", "dbname": r["dbname"] or "",
            "cred_policy": r["cred_policy"] or "ask"}   # credential_encrypted NU se expune


def _connection_command(row) -> str:
    """Comanda `ask` (fără parolă) pentru engine-ul dat. Preflight: dacă lipseşte clientul, mesaj
    clar + shell, nu o sesiune care moare instant."""
    eng = _CONN_ENGINES[row["engine"]]
    h = row["target_host"] or "127.0.0.1"
    p = int(row["target_port"] or eng["port"])
    u, db, q = row["username"] or "", row["dbname"] or "", shlex.quote
    if row["engine"] == "postgres":
        parts = ["psql", "-h", q(h), "-p", str(p)] + (["-U", q(u)] if u else []) + (["-d", q(db)] if db else [])
    elif row["engine"] == "mysql":
        parts = ["mysql", "-h", q(h), "-P", str(p)] + (["-u", q(u), "-p"] if u else []) + ([q(db)] if db else [])
    elif row["engine"] == "mongodb":
        parts = ["mongosh", q("mongodb://%s:%d/%s" % (h, p, db))] + (["--username", q(u)] if u else [])
    elif row["engine"] == "clickhouse":
        parts = ["clickhouse-client", "--host", q(h), "--port", str(p), "--ask-password"] \
            + (["--user", q(u)] if u else []) + (["--database", q(db)] if db else [])
    elif row["engine"] == "influxdb":
        # `-password ''` (explicit gol) = CLI-ul 1.x CERE parola la prompt („password:") în loc
        # s-o ia din argv — fix forma pe care o injectează agentul la `stored`.
        parts = ["influx", "-host", q(h), "-port", str(p)] \
            + (["-username", q(u), "-password", "''"] if u else []) \
            + (["-database", q(db)] if db else [])
    elif row["engine"] == "influxdb2":
        # 2.x n-are prompt propriu de token → îl emitem NOI: wrapper-ul afişează un prompt care
        # conţine „password:" (fix tiparul pe care îl injectează agentul la `stored`), citeşte
        # token-ul cu echo OFF (nu ajunge în transcript) şi îl dă lui influx DOAR prin env-ul
        # procesului (owner-only în /proc — nu în argv/ps, nu pe disc). `ask` = acelaşi prompt,
        # doar că tastează omul. Token gol → env rămâne nesetat → influx cade pe `influx config`-ul
        # local al hostului (fallback-ul vechi). `username` = org-ul (opţional).
        script = ("printf 'InfluxDB token password: '; stty -echo; IFS= read -r WT_T; stty echo; "
                  "printf '\\n'; [ -n \"$WT_T\" ] && export INFLUX_TOKEN=\"$WT_T\"; "
                  "exec influx v1 shell --host %s%s"
                  % (q("http://%s:%d" % (h, p)), (" --org %s" % q(u)) if u else ""))
        parts = ["sh", "-c", q(script)]
    else:  # redis
        parts = ["redis-cli", "-h", q(h), "-p", str(p)] + (["-n", q(db)] if db and db.isdigit() else [])
    inner = " ".join(parts)
    # Pt. `stored`: dacă clientul lipseşte NU cădem într-un shell interactiv — agentul are `pw` armat
    # 15s, iar un shell în care userul tastează poate produce output cu "password:" (ex. `sudo`) →
    # injecţie greşită, posibil în transcript. Fără client => mesaj + sesiunea se încheie (pw nu se
    # injectează niciodată într-un shell). Pt. `ask` (fără parolă) păstrăm shell-ul, util ca să instaleze clientul. (audit v53)
    if (row["cred_policy"] or "ask") == "stored":
        return ('command -v %s >/dev/null 2>&1 || { printf "\\n[WebTerm] %s is not installed on this host.\\n\\n"; '
                'exit 0; }; exec %s') % (q(eng["bin"]), eng["bin"], inner)
    return ('command -v %s >/dev/null 2>&1 || { printf "\\n[WebTerm] %s is not installed on this host.\\n\\n"; '
            'exec "${SHELL:-/bin/sh}"; }; exec %s') % (q(eng["bin"]), eng["bin"], inner)


class ConnectionIn(BaseModel):
    label: str
    engine: str
    target_host: str = ""
    target_port: Optional[int] = None
    username: str = ""
    dbname: str = ""
    cred_policy: str = "ask"
    credential: str = ""      # write-only; doar pt. `stored`. Gol la editare = păstrează ce e stocat.
    stepup_grant: str = ""    # 2FA: orice mutaţie pe host require_2fa cere step-up (H1) — vezi audit v53
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


def _validate_connection(body: ConnectionIn) -> None:
    if body.engine not in _CONN_ENGINES:
        raise ApiError(400, "connection.badEngine", "unknown database engine")
    if not (body.label or "").strip():
        raise ApiError(400, "connection.noLabel", "give the connection a name")
    for val in (body.target_host, body.username, body.dbname):
        if val and not _CONN_FIELD.match(val):
            raise ApiError(400, "connection.badField", "host/user/db: letters, digits and . _ - only")
    if body.target_port is not None and not (0 < int(body.target_port) <= 65535):
        raise ApiError(400, "connection.badPort", "invalid port")
    if body.cred_policy not in ("ask", "stored"):
        raise ApiError(400, "connection.badPolicy", "unknown credential policy")
    if body.cred_policy == "stored" and body.engine == "redis":
        # redis-cli n-are prompt de parolă → injecţia în PTY n-are unde să intre. Rămâne pe `ask`.
        raise ApiError(400, "connection.noStoredRedis", "redis has no password prompt — use 'ask'")
    if body.cred_policy == "stored" and body.engine == "influxdb" and not (body.username or "").strip():
        # influx 1.x emite promptul „password:" DOAR când dai `-username` (vezi _connection_command).
        # Fără user, parola din vault s-ar arma dar n-ar avea unde să intre — exact capcana tăcută
        # pentru care redis+stored e refuzat. Cere user, ca secretul stocat chiar să fie folosit. (audit v54)
        raise ApiError(400, "connection.influxNeedsUser",
                       "InfluxDB 1.x needs a username for a stored password")


@router.get("/api/hosts/{host_id}/connections")
async def list_connections(host_id: int, stepup_grant: str = "", stepup_password: str = "", stepup_totp: str = "",
                           user=Depends(authz.perm('toolbox.use', host='host_id'))):
    # Aceeaşi poartă ca `list_forwards`: lista arată `target_host:target_port`, user, dbname şi
    # motor pentru fiecare bază de pe host — harta internă a datelor. Create/patch/delete pe
    # aceeaşi resursă cereau step-up; citirea o dădea gratis unui cookie furat (audit 2026-10-04).
    await stepup.require_host_stepup(host_id, user, stepup_grant, stepup_password, stepup_totp)
    rows = await db.fetchall("SELECT * FROM connections WHERE host_id=? ORDER BY label", host_id)
    return {"connections": [_connection_json(r) for r in rows]}


@router.post("/api/hosts/{host_id}/connections")
async def create_connection(host_id: int, body: ConnectionIn, user=Depends(authz.perm('toolbox.manage', host='host_id'))):
    if not await db.fetchone("SELECT id FROM hosts WHERE id=?", host_id):
        raise ApiError(404, "host.missing", "no such host")
    # H1: o conexiune `stored` ţine o parolă DB care poate fi exfiltrată redirectând target_host →
    # pe host-uri 2FA orice mutaţie CRUD trebuie să coste un factor (ca /forwards, /run). audit v53.
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    _validate_connection(body)
    # `stored` → parola criptată în vault (acelaşi mecanism ca la SSH). `ask` → nimic stocat.
    blob = security.encrypt_secret(body.credential) if (body.cred_policy == "stored" and body.credential) else None
    cid = await db.execute(
        "INSERT INTO connections(host_id, label, engine, target_host, target_port, username,"
        " dbname, cred_policy, credential_encrypted, created) VALUES(?,?,?,?,?,?,?,?,?,?)",
        host_id, body.label.strip()[:80], body.engine, body.target_host.strip(), body.target_port,
        body.username.strip(), body.dbname.strip(), body.cred_policy, blob, time.time())
    return _connection_json(await db.fetchone("SELECT * FROM connections WHERE id=?", cid))


# INV-01 (docs/design/INVARIANTS.md): parola unei conexiuni Toolbox DB rămâne legată de destinația ei.
@router.patch("/api/hosts/{host_id}/connections/{conn_id}")
async def update_connection(host_id: int, conn_id: int, body: ConnectionIn,
                            user=Depends(authz.perm('toolbox.manage', host='host_id'))):
    cur = await db.fetchone("SELECT * FROM connections WHERE id=? AND host_id=?", conn_id, host_id)
    if not cur:
        raise ApiError(404, "connection.missing", "no such connection")
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)   # H1 (audit v53)
    _validate_connection(body)
    # Lot 3 (raport de securitate 2026-11): parola stocată e a serverului de baze de date pentru care
    # a fost salvată. Gol = „păstrează" o trimitea, la următoarea lansare, oricărui `target_host`
    # pus între timp — inclusiv unui server al celui care a editat conexiunea.
    moved = ((cur["engine"] or "", (cur["target_host"] or "").strip().lower(), int(cur["target_port"] or 0))
             != (body.engine, body.target_host.strip().lower(), int(body.target_port or 0)))
    if (moved and body.cred_policy == "stored" and cur["credential_encrypted"]
            and not body.credential):
        raise ApiError(400, "connection.retargetNeedsPassword",
                       "the connection now points to another server — enter its password again")
    await db.execute(
        "UPDATE connections SET label=?, engine=?, target_host=?, target_port=?, username=?,"
        " dbname=?, cred_policy=? WHERE id=? AND host_id=?",
        body.label.strip()[:80], body.engine, body.target_host.strip(), body.target_port,
        body.username.strip(), body.dbname.strip(), body.cred_policy, conn_id, host_id)
    # parola: gol la editare = păstrează ce e stocat; setată = re-criptează; trecerea la `ask`
    # şterge secretul stocat (nu ţinem o parolă pentru o conexiune care nu o mai foloseşte).
    if body.cred_policy != "stored":
        await db.execute("UPDATE connections SET credential_encrypted=NULL WHERE id=?", conn_id)
    elif body.credential:
        await db.execute("UPDATE connections SET credential_encrypted=? WHERE id=?",
                         security.encrypt_secret(body.credential), conn_id)
    return _connection_json(await db.fetchone("SELECT * FROM connections WHERE id=?", conn_id))


@router.delete("/api/hosts/{host_id}/connections/{conn_id}")
async def delete_connection(host_id: int, conn_id: int, stepup_grant: str = "",
                            stepup_password: str = "", stepup_totp: str = "", user=Depends(authz.perm('toolbox.manage', host='host_id'))):
    await stepup.require_host_stepup(host_id, user, stepup_grant, stepup_password, stepup_totp)   # H1 (audit v53)
    await db.execute("DELETE FROM connections WHERE id=? AND host_id=?", conn_id, host_id)
    return {"ok": True}


# ── [split-views] Split-views: layout-uri denumite de 2-4 sesiuni, per user, sincronizate ──────
# Un split-view NU ţine niciun secret — e metadată de layout care REFERĂ sesiuni
# gated independent la attach. Deci CRUD = doar require_user, FĂRĂ step-up (spre
# deosebire de conexiunile `stored`). Vezi docs/design/SPLIT-VIEWS.md.
SPLIT_RATIO_MIN, SPLIT_RATIO_MAX = 0.15, 0.85
# 3.6.12: forma layout-ului → (număr de panouri, grupurile de dimensiuni). Fiecare grup = fracţii
# care însumează 1: coloanele, apoi (unde există) rândurile. `main-left` = 1 mare stânga + 2
# stivuite dreapta [col0, col1, rând0, rând1 (ale stivei)], `main-top` = 1 mare sus + 2 jos
# [rând0, rând1, col0, col1 (ale rândului de jos)], `grid` = 2×2 [col0, col1, rând0, rând1].
# Aceeaşi tabelă e în frontend/src/lib/splitLayout.ts — o schimbare se face în ambele locuri.
SPLIT_LAYOUTS = {
    "cols2": (2, (2,)),
    "cols3": (3, (3,)),
    "main-left": (3, (2, 2)),
    "main-top": (3, (2, 2)),
    "grid": (4, (2, 2)),
}
SPLIT_DEFAULT_LAYOUT = {2: "cols2", 3: "main-left", 4: "grid"}
SPLIT_SIZE_MIN, SPLIT_SIZE_MAX = 0.1, 0.9
SPLIT_SUM_TOLERANCE = 0.02
SPLIT_MAX_PER_USER = 50
SPLIT_POSITION_MAX = 1000
# ce înseamnă „poţi pune sesiunea într-un panou": s-o urmăreşti sau s-o deschizi. `recording.view`
# singur (doar replay-ul unei sesiuni închise) NU mai ajunge din 3.6.12 — un panou e un terminal viu.
_SPLIT_PANE_PERMS = frozenset({"session.watch", "session.open"})


def _split_ratio(v) -> float:
    try:
        return max(SPLIT_RATIO_MIN, min(SPLIT_RATIO_MAX, float(v)))
    except (TypeError, ValueError):
        return 0.5


def _split_panes_of(row) -> list:
    try:
        p = json.loads(row["panes"] or "[]")
    except (TypeError, ValueError):
        return []
    return [s for s in p if isinstance(s, str)] if isinstance(p, list) else []


def _split_equal(layout: str) -> list:
    out = []
    for n in SPLIT_LAYOUTS[layout][1]:
        out += [round(1.0 / n, 4)] * n
    return out


def _split_fit_group(vals: list) -> list:
    """Clamp fiecare fracţie în [MIN, MAX] şi renormalizează grupul la suma 1. Iterativ: o
    renormalizare poate împinge din nou o valoare sub MIN (ex. [0.05, 0.05, 0.9])."""
    v = list(vals)
    for _ in range(12):
        v = [min(SPLIT_SIZE_MAX, max(SPLIT_SIZE_MIN, x)) for x in v]
        tot = sum(v)
        v = [x / tot for x in v]
        if all(SPLIT_SIZE_MIN - 1e-9 <= x <= SPLIT_SIZE_MAX + 1e-9 for x in v):
            break
    return [round(x, 4) for x in v]


def _split_sizes(layout: str, sizes) -> list:
    """Validează dimensiunile pentru `layout`: exact câte cere forma, numere finite în (0, 1), fiecare
    grup cu suma ≈ 1 (±SPLIT_SUM_TOLERANCE). Apoi clamp + renormalizare pe grup. Altfel 400."""
    groups = SPLIT_LAYOUTS[layout][1]
    if not isinstance(sizes, list) or len(sizes) != sum(groups):
        raise ApiError(400, "splitview.badSizes", "pane sizes do not match the layout")
    vals = []
    for x in sizes:
        if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) or not (0 < x < 1):
            raise ApiError(400, "splitview.badSizes", "pane sizes must be fractions between 0 and 1")
        vals.append(float(x))
    out, i = [], 0
    for n in groups:
        g = vals[i:i + n]
        i += n
        if abs(sum(g) - 1.0) > SPLIT_SUM_TOLERANCE:
            raise ApiError(400, "splitview.badSizes", "pane sizes must add up to 1")
        out += _split_fit_group(g)
    return out


def _split_layout_of(row, count: int) -> tuple:
    """(layout, sizes) EFECTIVE ale unui rând: cele stocate dacă se potrivesc cu numărul de
    panouri, altfel implicitul (un rând dinainte de 3.6.12 are doar `ratio`)."""
    layout = row["layout"] or ""
    stored = None
    if layout not in SPLIT_LAYOUTS or SPLIT_LAYOUTS[layout][0] != count:
        layout = SPLIT_DEFAULT_LAYOUT.get(count, "cols2")
    else:
        try:
            stored = json.loads(row["sizes"] or "null")
        except (TypeError, ValueError):
            stored = None
    sizes = None
    if stored is not None:
        try:
            sizes = _split_sizes(layout, stored)
        except ApiError:
            sizes = None
    if sizes is None:
        if layout == "cols2" and row["ratio"] is not None:
            r = _split_ratio(row["ratio"])
            sizes = [round(r, 4), round(1 - r, 4)]
        else:
            sizes = _split_equal(layout)
    return layout, sizes


def _split_view_json(row, panes=None, hidden=0):
    p = panes if panes is not None else _split_panes_of(row)
    # forma se alege după numărul TOTAL de panouri vii (inclusiv cele ascunse acum): UI-ul care
    # vede mai puţine (hidden > 0) randează local o formă implicită, fără s-o persiste
    layout, sizes = _split_layout_of(row, len(p) + hidden)
    return {"id": row["id"], "name": row["name"] or "", "panes": p,
            "ratio": row["ratio"] if row["ratio"] is not None else 0.5,
            "layout": layout, "sizes": sizes, "hidden": hidden,
            "broadcast": bool(row["broadcast"]), "position": row["position"] or 0}


async def _split_pane_access(user, sids) -> dict:
    """sid → vizibil ACUM pentru cont: sesiunea există, rolul dă `session.watch`/`session.open` pe
    hostul ei şi — pe un host `require_2fa` — fereastra de step-up e deschisă (aceeaşi regulă ca
    /api/sessions: metadata unei sesiuni 2FA cere step-up). Un sid absent din dict = inexistent.
    Citire PASIVĂ (`stepup_window_is_open` nu glisează fereastra); interogăm doar sid-urile cerute."""
    sids = sorted({s for s in sids if isinstance(s, str)})
    if not sids:
        return {}
    rows = []
    for i in range(0, len(sids), 500):
        chunk = sids[i:i + 500]
        rows += await db.fetchall("SELECT id, host_id FROM sessions WHERE id IN (%s)"
                                  % ",".join("?" * len(chunk)), *chunk)
    hosts = sorted({r["host_id"] for r in rows})
    gated = set()
    if hosts:
        gated = {r["id"] for r in await db.fetchall(
            "SELECT id FROM hosts WHERE require_2fa=1 AND id IN (%s)" % ",".join("?" * len(hosts)), *hosts)}
    grants = await authz.grants_for_user(user["id"])
    ok_host = {}
    for h in hosts:
        vis = bool(await authz.perms_on(grants, h) & _SPLIT_PANE_PERMS)
        if vis and h in gated:
            vis = security.stepup_window_is_open(user["id"], h)
        ok_host[h] = vis
    return {r["id"]: ok_host[r["host_id"]] for r in rows}


async def _validate_split_panes(panes, user) -> list:
    """2-4 sid-uri DISTINCTE, fiecare o sesiune pe care contul o vede ACUM. Aceeaşi sesiune de
    două ori = doi clienţi tmux la două dimensiuni (război de resize) → respins, ca invariantul
    primary≠second. Inexistentă / fără drept / 2FA blocat = acelaşi 400 (fără oracol)."""
    if not isinstance(panes, list) or not (2 <= len(panes) <= 4):
        raise ApiError(400, "splitview.badCount", "a split view needs 2 to 4 sessions")
    if any(not isinstance(s, str) for s in panes):
        raise ApiError(400, "splitview.badPane", "invalid session id")
    if len(set(panes)) != len(panes):
        raise ApiError(400, "splitview.dupPane", "the same session cannot appear twice")
    access = await _split_pane_access(user, panes)
    if not all(access.get(sid) for sid in panes):
        raise ApiError(400, "splitview.badPane", "unknown session in split view")
    return panes


def _split_layout_arg(layout, count: int) -> str:
    if not isinstance(layout, str) or layout not in SPLIT_LAYOUTS:
        raise ApiError(400, "splitview.badLayout", "unknown split layout")
    if SPLIT_LAYOUTS[layout][0] != count:
        raise ApiError(400, "splitview.badLayout", "that layout does not fit this number of panes")
    return layout


def _split_position(v) -> int:
    try:
        return max(0, min(SPLIT_POSITION_MAX, int(v)))
    except (TypeError, ValueError, OverflowError):
        return 0


class SplitViewIn(BaseModel):
    # câmpuri opţionale: POST cere name+panes; PATCH actualizează doar ce trimiţi
    name: Optional[str] = None
    panes: Optional[list[str]] = None
    ratio: Optional[float] = None
    layout: Optional[str] = None
    sizes: Optional[list[float]] = None
    broadcast: Optional[bool] = None
    position: Optional[int] = None


async def _split_view_out(user, row) -> dict:
    cur = _split_panes_of(row)
    access = await _split_pane_access(user, cur)
    alive = [s for s in cur if s in access]
    visible = [s for s in alive if access[s]]
    return _split_view_json(row, visible, len(alive) - len(visible))


@router.get("/api/split-views")
async def list_split_views(user=Depends(security.require_user)):
    # 3.6.12: GET nu mai SCRIE (curăţarea panourilor moarte e în reaper şi la ştergerea unei
    # sesiuni/host — core.prune_split_views) şi interoghează doar sesiunile referite. Un panou pe
    # care contul nu-l poate vedea ACUM (rol schimbat, host 2FA fără step-up) e ASCUNS, nu şters:
    # layout-ul revine întreg după deblocare. `hidden` = câte panouri vii lipsesc din listă.
    rows = await db.fetchall(
        "SELECT * FROM split_views WHERE user_id=? ORDER BY position, id", user["id"])
    panes_of = {r["id"]: _split_panes_of(r) for r in rows}
    access = await _split_pane_access(user, [s for p in panes_of.values() for s in p])
    out = []
    for r in rows:
        alive = [s for s in panes_of[r["id"]] if s in access]
        if len(alive) < 2:
            continue                     # <2 sesiuni vii: îl şterge reaper-ul; aici doar nu-l arătăm
        visible = [s for s in alive if access[s]]
        out.append(_split_view_json(r, visible, len(alive) - len(visible)))
    return {"split_views": out}


@router.post("/api/split-views")
async def create_split_view(body: SplitViewIn, user=Depends(security.require_user)):
    name = (body.name or "").strip()[:80]
    if not name:
        raise ApiError(400, "splitview.noName", "a split view needs a name")
    # Verificare rapidă (răspuns clar fără validarea panourilor); plafonul REAL e atomic, în
    # INSERT-ul de mai jos — două POST-uri concurente nu mai trec amândouă de COUNT (review 3.6.12).
    n = await db.fetchone("SELECT COUNT(*) AS n FROM split_views WHERE user_id=?", user["id"])
    if n and n["n"] >= SPLIT_MAX_PER_USER:
        raise ApiError(400, "splitview.tooMany", "too many split views — delete one first")
    panes = await _validate_split_panes(body.panes or [], user)
    layout = (_split_layout_arg(body.layout, len(panes)) if body.layout is not None
              else SPLIT_DEFAULT_LAYOUT[len(panes)])
    sizes = _split_sizes(layout, body.sizes) if body.sizes is not None else None
    ratio = _split_ratio(body.ratio if body.ratio is not None else 0.5)
    if layout == "cols2":
        if sizes is None and body.ratio is not None:
            sizes = [round(ratio, 4), round(1 - ratio, 4)]
        elif sizes is not None:
            ratio = _split_ratio(sizes[0])
    now = time.time()
    # INSERT…SELECT…WHERE COUNT < plafon: o singură instrucţiune serializată de SQLite, deci
    # plafonul ţine şi sub POST-uri concurente (fără RETURNING → niciun rând inserat → refuz).
    ins = await db.execute_returning(
        "INSERT INTO split_views(user_id, name, panes, ratio, layout, sizes, broadcast, position,"
        " created, updated) SELECT ?,?,?,?,?,?,?,?,?,?"
        " WHERE (SELECT COUNT(*) FROM split_views WHERE user_id=?) < ? RETURNING id",
        user["id"], name, json.dumps(panes), ratio, layout, json.dumps(sizes) if sizes else "",
        1 if body.broadcast else 0, _split_position(body.position or 0), now, now,
        user["id"], SPLIT_MAX_PER_USER)
    if not ins:
        raise ApiError(400, "splitview.tooMany", "too many split views — delete one first")
    new_id = ins["id"]
    return await _split_view_out(user, await db.fetchone("SELECT * FROM split_views WHERE id=?", new_id))


@router.patch("/api/split-views/{sv_id}")
async def update_split_view(sv_id: int, body: SplitViewIn, user=Depends(security.require_user)):
    row = await db.fetchone("SELECT * FROM split_views WHERE id=? AND user_id=?", sv_id, user["id"])
    if not row:
        raise ApiError(404, "splitview.missing", "no such split view")
    sets, vals = [], []
    if body.name is not None:
        name = body.name.strip()[:80]
        if not name:
            raise ApiError(400, "splitview.noName", "a split view needs a name")
        sets.append("name=?"); vals.append(name)
    if (body.panes is not None or body.layout is not None or body.sizes is not None
            or body.ratio is not None):
        # Un client care NU vede toate panourile (2FA fără step-up, rol restrâns) ar rescrie
        # layout-ul doar cu ce vede şi ar pierde tăcut panourile ascunse → refuzat până la deblocare.
        cur = _split_panes_of(row)
        access = await _split_pane_access(user, cur)
        alive = [s for s in cur if s in access]
        if any(not access[s] for s in alive):
            raise ApiError(409, "splitview.hiddenPanes",
                           "some sessions of this split view are hidden right now — unlock them first")
        panes = await _validate_split_panes(body.panes, user) if body.panes is not None else alive
        if len(panes) < 2:
            raise ApiError(400, "splitview.badCount", "a split view needs 2 to 4 sessions")
        count_changed = len(panes) != len(alive)
        if body.panes is not None or len(alive) != len(cur):
            sets.append("panes=?"); vals.append(json.dumps(panes))
        cur_layout, cur_sizes = _split_layout_of(row, len(alive))
        if body.layout is not None:
            layout = _split_layout_arg(body.layout, len(panes))
        elif count_changed:
            layout = SPLIT_DEFAULT_LAYOUT[len(panes)]
        else:
            layout = cur_layout
        if body.sizes is not None:
            sizes = _split_sizes(layout, body.sizes)
        elif body.ratio is not None and layout == "cols2":
            r = _split_ratio(body.ratio)
            sizes = [round(r, 4), round(1 - r, 4)]
        elif layout == cur_layout and not count_changed:
            sizes = cur_sizes
        else:
            sizes = _split_equal(layout)
        sets += ["layout=?", "sizes=?"]; vals += [layout, json.dumps(sizes)]
        if layout == "cols2":
            sets.append("ratio=?"); vals.append(_split_ratio(sizes[0]))
    if body.broadcast is not None:
        sets.append("broadcast=?"); vals.append(1 if body.broadcast else 0)
    if body.position is not None:
        sets.append("position=?"); vals.append(_split_position(body.position))
    if sets:
        sets.append("updated=?"); vals.append(time.time())
        await db.execute("UPDATE split_views SET %s WHERE id=?" % ", ".join(sets), *vals, sv_id)
    row = await db.fetchone("SELECT * FROM split_views WHERE id=? AND user_id=?", sv_id, user["id"])
    if not row:     # şters între timp (DELETE concurent / prune) → 404, nu 500
        raise ApiError(404, "splitview.missing", "no such split view")
    return await _split_view_out(user, row)


@router.delete("/api/split-views/{sv_id}")
async def delete_split_view(sv_id: int, user=Depends(security.require_user)):
    await db.execute("DELETE FROM split_views WHERE id=? AND user_id=?", sv_id, user["id"])
    return {"ok": True}


# ── [wol] Wake-on-LAN: un agent VECIN trezeşte o maşină oprită din acelaşi LAN ──────
# Prefixe de interfeţe virtuale (bridge-uri, veth-uri, VPN-uri): n-au NIC fizic în spate, deci
# MAC-ul lor nu poate fi trezit şi subnetul lor (ex. 172.17/16 al Docker-ului) nu e un LAN real.
_VIRTUAL_IF_PREFIXES = ("docker", "br-", "virbr", "veth", "vnet", "tap", "tun",
                        "wg", "tailscale", "zt", "lxcbr", "lxdbr", "cni", "flannel", "cilium")


def _host_ipv4_ifaces(diag_json):
    """Interfeţele IPv4 non-loopback dintr-un snapshot de diagnostic: [(mac, ip_interface)]."""
    import ipaddress
    out = []
    try:
        d = json.loads(diag_json)
    except (TypeError, ValueError):
        return out
    # acelaşi guard ca hostmodel.host_updates: un diagnostics top-level non-obiect ar arunca AttributeError
    net = d.get("network") if isinstance(d, dict) else None
    ifaces = (net.get("interfaces") if isinstance(net, dict) else None) or []
    for f in ifaces:
        name, mac = (f.get("name") or ""), (f.get("mac") or "").strip()
        if name == "lo" or not mac or mac == "00:00:00:00:00:00":
            continue
        # interfeţele VIRTUALE ies: diagnosticele listează /sys/class/net sortat, deci pe un host
        # cu Docker `br-…`/`docker0` vin ÎNAINTEA lui `eth0` — fără filtru, ţinta „preferată" era
        # MAC-ul bridge-ului (WoL inutil), iar subnetul 172.17/16 „găsea" drept peer ORICE alt
        # host cu Docker, chiar de pe alt LAN fizic → fals succes silenţios (audit 2026-09).
        # Agenţii v51+ raportează `physical` (are /sys/class/net/<n>/device) — sursa de adevăr;
        # prefixele de nume rămân fallback-ul pentru diagnosticele v50, care n-au flagul.
        if f.get("physical") is False:
            continue
        if name.startswith(_VIRTUAL_IF_PREFIXES):
            continue
        for c in f.get("ipv4") or []:
            try:
                ipi = ipaddress.ip_interface(c)
            except ValueError:
                continue
            # /31 şi /32 n-au adresă de broadcast reală: „broadcastul" ar fi chiar IP-ul maşinii
            # oprite — un unicast garantat pierdut, raportat ca succes. Nu candidează.
            if ipi.network.prefixlen >= 31:
                continue
            out.append((mac, ipi))
    return out


@router.post("/api/hosts/{host_id}/wake")
async def wake_host(host_id: int, request: Request, user=Depends(authz.perm('host.wake', host='host_id'))):
    """Trimite un magic packet Wake-on-LAN către un host de agent OPRIT. WoL e broadcast L2, deci
    gateway-ul nu poate ajunge direct — cere unui agent ONLINE din ACELAŞI LAN să-l trimită. MAC-ul
    şi subnetul ţintei vin din ultimul diagnostic; peer-ul se alege după IP-urile LAN din
    diagnosticul lui (NU după `agent_ip`, care e IP-ul public văzut prin NAT)."""
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    if not conntypes.is_agent(row):
        raise ApiError(400, "wake.notAgent", "Wake-on-LAN is only for agent hosts")
    await stepup.require_host_stepup(host_id, user)   # acţiune de host
    # MAC + subnet al ţintei: preferă interfaţa cu IP-ul pe care gateway-ul l-a văzut ultima dată
    target = None
    for mac, ipi in _host_ipv4_ifaces(row["diagnostics"] if "diagnostics" in row.keys() else None):
        if row["agent_ip"] and str(ipi.ip) == row["agent_ip"]:
            target = (mac, ipi); break
        target = target or (mac, ipi)
    if not target:
        raise ApiError(400, "wake.noMac",
                       "no MAC/IPv4 known — the host must report diagnostics at least once while online")
    mac, ipi = target
    subnet = ipi.network
    bcast = str(subnet.broadcast_address)
    # peer: un agent ONLINE, alt host, cu o interfaţă LAN în acelaşi subnet
    peer_conn = peer_name = None
    # 3.6: doar un vecin pe care contul are el însuşi `host.wake` — trimiterea pachetului e o
    # ACŢIUNE pe vecin, iar răspunsul îl numeşte (`via`): un vecin doar vizibil (sau invizibil)
    # n-are voie să fie folosit (şi n-ar trebui nici să-i apară numele)
    peers_vis = await authz.visible_hosts(authz.grants_of(request), "host.wake")
    for h in await db.fetchall("SELECT id, name, diagnostics FROM hosts WHERE " + conntypes.SQL_IS_AGENT):
        if h["id"] == host_id or not authz.in_visible(peers_vis, h["id"]):
            continue
        conn = core.source_for(h["id"])
        if not isinstance(conn, core.AgentConnection):      # online = are sursă
            continue
        if (conn.agent_version or 0) < 50:
            continue        # `wake` există abia din v50 — un vecin v49 ar da bad_op degeaba,
        #                     deşi poate există un v50 două rânduri mai jos (fereastra de rollout)
        if any(pipi.ip in subnet for _, pipi in _host_ipv4_ifaces(h["diagnostics"])):
            peer_conn, peer_name = conn, h["name"]; break
    if not peer_conn:
        raise ApiError(400, "wake.noPeer",
                       "no online agent on the same LAN to send the packet (Wake-on-LAN needs a neighbour)")
    audit.detail(request, "wake %s via %s" % (mac, peer_name))
    try:
        resp = await peer_conn.wake(mac, broadcast=bcast)
    except (core.AgentGone, TimeoutError, asyncio.TimeoutError):
        raise ApiError(504, "wake.noAnswer", "the neighbour agent did not answer in time")
    if not resp.get("ok"):
        # agent < v50 răspunde err("bad_op", "wake") — msg-ul e literalul "wake", inutil ca text;
        # traducem noi. (Aproape de neatins acum, că selecţia filtrează v49 — dar corect oricum.)
        if resp.get("code") == "bad_op":
            raise ApiError(502, "wake.oldPeer", "wake failed: the neighbour agent is older than v50")
        raise ApiError(502, "wake.failed", resp.get("msg") or "wake failed")
    return {"ok": True, "via": peer_name, "mac": resp.get("sent", mac)}


# ── [history] Istoric global de comenzi (căutabil, audit-lite) ─────────────────────────
# Comenzile interactive sunt raportate de client (din marcajele OSC 133); cele de
# flotă se scriu automat mai sus. Un singur cont → istoricul e ca `~/.bash_history`,
# doar căutabil peste toate hosturile și sesiunile.
HISTORY_CAP = 10000


async def _record_history(host_id, host_name, command, exit_code, cwd, source, user_id=None):
    cmd = (command or "").strip()
    if not cmd:
        return
    ec = exit_code if isinstance(exit_code, int) else None
    await db.execute(
        "INSERT INTO command_history(host_id, host_name, command, exit_code, cwd, source, created,"
        " user_id) VALUES(?,?,?,?,?,?,?,?)",
        host_id, (host_name or "")[:120], cmd[:4000], ec, (cwd or "")[:500], source, time.time(),
        user_id)
    # plafon: păstrează ultimele HISTORY_CAP (id autoincrement ≈ ordine cronologică)
    await db.execute(
        "DELETE FROM command_history WHERE id <= (SELECT MAX(id) - ? FROM command_history)",
        HISTORY_CAP)


class HistoryIn(BaseModel):
    host_id: int | None = None
    command: str
    exit_code: int | None = None
    cwd: str = ""


def _user_has_unlocked_terminal(user_id: int, host_id: int) -> bool:
    """Contul are ACUM un terminal viu şi deblocat pe host, ataşat ca owner (nu invitat)?"""
    for hub in list(core.hubs.values()):
        if hub.host_id != host_id or hub.locked or hub.closed:
            continue
        for c in list(hub.clients):
            if c.is_owner and c.user_id == user_id and not c.locked:
                return True
    return False


@router.post("/api/history")
async def add_history(body: HistoryIn, user=Depends(authz.perm('session.open', host='body:host_id', optional_host=True))):
    """F-10: rândurile astea sunt RAPORTATE DE CLIENT (OSC 133 din browser), deci pot fi
    forjate de oricine are un cookie valid. Nu sunt probă şi nu trebuie tratate ca atare —
    urma reală e `audit_log`, scrisă de middleware, pe care clientul n-o poate atinge.
    Marcăm sursa explicit ca UI-ul să poată spune diferenţa."""
    hn = ""
    if body.host_id is not None:
        row = await db.fetchone("SELECT name, require_2fa FROM hosts WHERE id=?", body.host_id)
        hn = row["name"] if row else ""
        # Pe un host 2FA, scrierea în istoric cere ACELAŞI drept ca citirea lui: o fereastră de
        # step-up deschisă — SAU un terminal DEBLOCAT pe acel host, ataşat chiar de acest cont
        # (comenzile vin dintr-un terminal activ a cărui fereastră se poate fi închis între timp;
        # nu pierdem istoricul unei lucrări legitime). Altfel, un cookie furat putea injecta
        # comenzi false în istoricul unui host protejat. Refuzul e un 403 opac (fără nume de
        # host, fără „există/nu există"): clientul raportează best-effort şi îl ignoră.
        if row and row["require_2fa"] and not (
                security.stepup_window_is_open(user["id"], body.host_id)
                or _user_has_unlocked_terminal(user["id"], body.host_id)):
            raise ApiError(403, "history.denied", "not recorded")
    await _record_history(body.host_id, hn, body.command, body.exit_code, body.cwd, "session",
                          user["id"])
    return {"ok": True}


@router.get("/api/history")
async def search_history(request: Request, q: str = "", host_id: int | None = None,
                         limit: int = 200,
                         user=Depends(authz.perm('recording.view', list=True))):
    limit = min(max(limit, 1), 500)
    clauses, params = [], []
    # 3.6: doar hosturile cu `recording.view`; rândurile fără host (NULL) doar cu `audit.view`.
    # Filtru TĂCUT, în SQL — ca regula 2FA de mai jos.
    grants = authz.grants_of(request)
    vis = await authz.visible_hosts(grants, "recording.view")
    if vis is not None:
        null_ok = "host_id IS NULL OR " if grants.has_global("audit.view") else ""
        if vis:
            clauses.append("(%shost_id IN (%s))" % (null_ok, ",".join("?" * len(vis))))
            params.extend(sorted(vis))
        else:
            clauses.append("(host_id IS NULL)" if null_ok else "0")
    elif not grants.has_global("audit.view"):
        clauses.append("host_id IS NOT NULL")
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
    blocked = {hid for hid in gated if not security.stepup_window_is_open(user["id"], hid)}
    if blocked:
        clauses.append("(host_id IS NULL OR host_id NOT IN (%s))"
                       % ",".join("?" * len(blocked)))
        params.extend(sorted(blocked))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await db.fetchall(
        "SELECT id, host_id, host_name, command, exit_code, cwd, source, created"
        " FROM command_history" + where + " ORDER BY created DESC LIMIT ?", *params, limit)
    return [dict(r) for r in rows]


class ClearHistoryIn(BaseModel):
    current_password: str = ""
    stepup_grant: str = ""      # conturi SSO: grant passkey account-scope (host_id=0)


@router.delete("/api/history")
async def clear_history(request: Request, body: ClearHistoryIn | None = None,
                        user=Depends(authz.perm('history.clear'))):
    """Şterge TOT istoricul de comenzi (toate conturile, toate hosturile, inclusiv cele 2FA pe
    care istoricul nici nu le arată fără step-up). E o ştergere globală şi ireversibilă de urme,
    deci cere re-auth ca „Revocă tot" (parola contului; SSO: grant passkey / fereastra
    account-scope) şi rămâne în jurnalul de audit — un cookie furat nu-şi mai poate şterge
    urmele dintr-un singur DELETE."""
    body = body or ClearHistoryIn()
    if user["sso_subject"] and config.OIDC_ENABLED:
        ok_reauth = (bool(body.stepup_grant)
                     and security.consume_stepup_grant(body.stepup_grant, user["id"], 0)) \
            or security.stepup_window_is_open(user["id"], 0)
        if not ok_reauth:
            raise ApiError(403, "history.ssoReauth",
                           "re-authenticate with SSO or a passkey to clear the command history")
    else:
        await stepup.require_reauth_for_secret(user, body.current_password, "clearing the command history")
    n = await db.fetchone("SELECT COUNT(*) AS c FROM command_history")
    await db.execute("DELETE FROM command_history")
    count = n["c"] if n else 0
    audit.detail(request, "cleared the command history (%d entries)" % count)
    log.warning("command history cleared (%d entries) by %s", count, user["email"])
    return {"ok": True, "deleted": count}


# ── [audit] Audit log ──────────────────────────────────────────────────────────────────────────

@router.get("/api/audit")
async def audit_list(request: Request, limit: int = 200, before: float = 0.0, q: str = "",
                     failed_only: bool = False,
                     user=Depends(authz.perm('audit.view', list=True))):
    # `require_user`, nu `require_scope("read")`. Coloana `detail` conţine textul COMPLET al
    # comenzilor rulate pe flotă, interogările de căutare, emailul şi IP-ul fiecărui operator —
    # adică exact conţinutul pe care toate celelalte citiri (`/transcript`, `/preview`,
    # `/search`, `/agent-log`) îl ţin deliberat în afara tokenurilor. Un token de automatizare
    # ajunge în loguri de CI, în `.env`, în scripturi; nu are ce căuta în istoricul operaţional.
    """Jurnalul de audit: ce s-a schimbat prin UI/API, de către cine și de la ce IP.
    Paginare în trecut cu `before` (ts-ul ultimei linii primite)."""
    # 3.6: fără `audit.view` — doar propriile rânduri; cu el — rândurile fără host sau de pe
    # hosturile vizibile (host_id-ul din coloană, sau din cale pe rândurile de dinainte de 3.6).
    grants = authz.grants_of(request)
    if grants.has_global("audit.view"):
        vis = await authz.visible_hosts(grants, "host.view")
        entries = await audit.recent(limit, before, q.strip(), failed_only, visible_hosts=vis)
    else:
        entries = await audit.recent(limit, before, q.strip(), failed_only, actor_id=user["id"])
    # meta-leak: `detail` conţine textul COMPLET al comenzilor rulate pe flotă — pe un host
    # `require_2fa` e exact conţinutul pe care /transcript, /search şi /history îl ţin în spatele
    # step-up-ului. Redactăm detaliul intrărilor care ţintesc un host 2FA fără fereastră deschisă
    # (păstrăm rândul — că s-a întâmplat o acţiune e metadata utilă — dar nu şi comanda executată).
    # Calea e `/api/hosts/{id}/...`, de unde scoatem host_id-ul. Citire pasivă → `stepup_window_is_open`.
    gated = {r["id"] for r in await db.fetchall("SELECT id FROM hosts WHERE require_2fa=1")}
    blocked = {hid for hid in gated if not security.stepup_window_is_open(user["id"], hid)}
    if blocked:
        for e in entries:
            m = re.search(r"/api/hosts/(\d+)", e.get("path") or "")
            if m and int(m.group(1)) in blocked and e.get("detail"):
                e["detail"] = "[redactat — host 2FA, step-up necesar]"
    return {"entries": entries,
            "retention_days": config.AUDIT_RETENTION_DAYS}


# ── [agent] Agent events, agent log, diagnostics refresh ──────────────────────────────────────────

@router.get("/api/hosts/{host_id}/events")
async def host_events(host_id: int, user=Depends(authz.perm('host.diagnostics', host='host_id'))):
    """Jurnal de conexiune al agentului (ultimele 7 zile) + starea curentă — pentru panoul
    de diagnostic: cine a conectat/deconectat şi DE CE, când a venit un update etc."""
    await stepup.require_host_stepup(host_id, user)   # F-05: IP-uri, versiuni, motive de reconectare
    hrow = await db.fetchone(
        "SELECT id, last_heartbeat, agent_version, connection_type, via_host_id, agent_ip,"
        " diagnostics, diagnostics_at FROM hosts WHERE id=?", host_id)
    if not hrow:
        raise ApiError(404, "host.missing", "no such host")
    rows = await db.fetchall(
        "SELECT ts, event, reason, detail FROM agent_events WHERE host_id=?"
        " ORDER BY ts DESC LIMIT 200", host_id)
    conn = core.sources.get(host_id)
    # ultimul snapshot persistat: vizibil ŞI când hostul e down (ce IP-uri/rute/discuri avea)
    diag = None
    if hrow["diagnostics"]:
        try:
            diag = json.loads(hrow["diagnostics"])
        except (ValueError, TypeError):
            diag = None
    return {
        "online": hostmodel.host_online(hrow),
        "last_heartbeat": hrow["last_heartbeat"],
        "agent_version": hrow["agent_version"],
        "connection_type": hrow["connection_type"],
        "agent_ip": hrow["agent_ip"],
        # health de link raportat de agent (uptime/reconnects/rtt_ms) — Faza 3
        "link": (conn.link if isinstance(conn, core.AgentConnection) else {}),
        "events": [dict(r) for r in rows],
        # snapshot complet (ultimul cunoscut) + momentul colectării pentru eticheta „acum X"
        "diagnostics": diag,
        "diagnostics_at": hrow["diagnostics_at"],
    }


@router.get("/api/hosts/{host_id}/agent-log")
async def agent_log(host_id: int, user=Depends(authz.perm('host.diagnostics', host='host_id'))):
    """Tail-ul logului agentului (ptyd.log) — debug din UI, fără SSH pe host."""
    # H1: logul agentului conţine ce s-a întâmplat pe host şi poate include conţinut
    # scris de utilizator. `audit.py` îl clasifică drept citire care SCOATE date; poarta
    # de step-up îi lipsea, deci un cookie furat citea de pe un host marcat „cere 2FA"
    # exact ce restul căilor (transcript, fs-download, forwards) refuzau.
    await stepup.require_host_stepup(host_id, user)
    conn = core.sources.get(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise ApiError(409, "host.offline", "the host is offline, or has no agent connected")
    try:
        return {"log": await conn.get_agent_log()}
    except core.ForwardError as e:
        raise ApiError(502, "agent.requestFailed", str(e) or "the agent could not answer")
    except (core.AgentGone, TimeoutError):
        raise ApiError(409, "host.offline", "host offline")


@router.post("/api/hosts/{host_id}/diagnostics/refresh")
async def diagnostics_refresh(host_id: int, user=Depends(authz.perm('host.diagnostics', host='host_id'))):
    """Snapshot proaspăt cerut acum de la agent (butonul Refresh). Doar când hostul e online;
    altfel UI-ul arată ultimul snapshot persistat din `/events`. Aceeaşi poartă de step-up ca
    restul citirilor de host (scoate IP-uri, rute, mounturi)."""
    await stepup.require_host_stepup(host_id, user)
    conn = core.sources.get(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise ApiError(409, "host.offline", "the host is offline, or has no agent connected")
    try:
        return {"diagnostics": await conn.get_diagnostics()}
    except core.ForwardError as e:
        raise ApiError(502, "agent.requestFailed", str(e) or "the agent could not answer")
    except (core.AgentGone, TimeoutError):
        raise ApiError(409, "host.offline", "host offline")


# ── [serial] Console seriale (RS232/RS485/USB) prin agent ─────────────────────────────
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
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


@router.post("/api/hosts/{host_id}/serial/discover")
async def serial_discover(host_id: int, user=Depends(authz.perm('serial.use', host='host_id'))):
    """List the real serial ports on the host (discovery, read-only)."""
    row = await db.fetchone("SELECT id FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    # H1: e pasul dinaintea deschiderii unei console seriale, pe care `serial/open` o
    # păzeşte deja — iar lista în sine spune ce echipamente sunt legate la host.
    await stepup.require_host_stepup(host_id, user)
    try:
        return {"ports": await core.serial_discover(host_id)}
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")


@router.post("/api/hosts/{host_id}/serial/open")
async def serial_open(host_id: int, body: SerialOpenIn, user=Depends(authz.perm('serial.use', host='host_id'))):
    """Deschide o sesiune de consolă serială pe host. Interactiv → aceeași poartă de
    step-up ca sesiunile normale."""
    row = await db.fetchone("SELECT id FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    # normpath colapsează `..` ÎNAINTE de verificare: `/dev/../etc/shadow` → `/etc/shadow` → refuzat.
    # Nu e o gaură (agentul respinge oricum ne-tty-urile prin `os.isatty`, iar /dev/* e deja permis),
    # dar închide explicit intenţia „doar sub /dev/" în planul de control, semnalat de audit.
    device = os.path.normpath((body.device or "").strip())
    if "\x00" in device or not device.startswith("/dev/") or device == "/dev":
        raise ApiError(400, "serial.badDevice", "invalid serial device (/dev/* only)")
    if body.parity not in ("none", "even", "odd") or body.flow not in ("none", "rtscts", "xonxoff"):
        raise ApiError(400, "serial.badParity", "invalid parity/flow")
    params = {"baud": body.baud, "bits": body.bits, "parity": body.parity,
              "stop": body.stop, "flow": body.flow}
    title = (body.title or "").strip() or device.rsplit("/", 1)[-1]
    try:
        result = await core.create_serial_session(host_id, device, params, title[:60],
                                                  body.rows, body.cols, body.tz or None)
        await core.stamp_session(result, user)
        return result
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")
    except core.SessionLimitReached:
        raise ApiError(409, "serial.limit", "the serial session limit was reached — close one first")
    except RuntimeError as e:
        raise errors.runtime_api_error(e, "session.createFailed")


# ── [agent] Agent update trigger ──────────────────────────────────────────────────────────────────

@router.post("/api/hosts/{host_id}/update")
async def update_agent(host_id: int, user=Depends(authz.perm('host.admin', host='host_id'))):
    """Update/restart the agent now; tmux sessions survive the restart."""
    await stepup.require_host_stepup(host_id, user)   # H1
    try:
        result = await core.force_update_agent(host_id)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (RuntimeError, TimeoutError) as e:
        raise errors.runtime_api_error(e, "update.failed")
    if result["deferred"]:
        # agent vechi (pre-v4) care nu onorează forțarea cât are sesiuni live
        raise ApiError(
            409, "update.deferred",
            "The agent is an old version and will update once you close "
            "the live sessions on this host (the new file is already staged).")
    return {"ok": True}


# ── [search] Global search ────────────────────────────────────────────────────────────────────────

@router.get("/api/search")
async def search(q: str, request: Request, user=Depends(authz.perm('recording.view', list=True))):
    """Search hosts, session titles/notes and transcript contents."""
    q = q.strip()
    if len(q) < 2:
        return {"sessions": []}
    # CE s-a căutat, nu doar că s-a căutat: „a rulat o căutare" nu răspunde la întrebarea
    # de după un cookie furat, iar interogarea E lucrul care spune ce urmărea atacatorul.
    audit.detail(request, "search: " + q)
    # 3.6 (§A.11.12): filtrul de vizibilitate e în SQL, ÎNAINTE de a citi vreun transcript —
    # filtrat după citire ar fi şi o scurgere prin timp, şi un amplificator de DoS.
    vis = await authz.visible_hosts(authz.grants_of(request), "recording.view")
    if vis is None:
        rows = await db.fetchall("SELECT * FROM sessions ORDER BY created DESC LIMIT 500")
    elif vis:
        rows = await db.fetchall(
            "SELECT * FROM sessions WHERE host_id IN (%s) ORDER BY created DESC LIMIT 500"
            % ",".join("?" * len(vis)), *sorted(vis))
    else:
        rows = []
    # Căutarea citeşte CONŢINUTUL transcripturilor, deci e aceeaşi clasă cu /transcript:
    # sesiunile de pe hosturi cu `require_2fa` intră doar dacă ai o fereastră de step-up
    # deschisă pentru hostul ăla. Filtrăm TĂCUT (nu 403): altfel căutarea globală ar deveni
    # un oracol pentru „există sesiuni pe hostul X".
    gated = {r["id"] for r in await db.fetchall(
        "SELECT id FROM hosts WHERE require_2fa=1")}
    if gated:
        # read-only: o căutare nu trebuie să prelungească fereastra de step-up pe hosturile potrivite
        allowed = {hid for hid in gated if security.stepup_window_is_open(user["id"], hid)}
        rows = [r for r in rows if r["host_id"] not in gated or r["host_id"] in allowed]
    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(None, core.search_transcripts, rows, q)
    return {"sessions": results}


# ── [snippets] Snippets (comenzi salvate) ───────────────────────────────────────────

class SnippetIn(BaseModel):
    title: str
    body: str
    # Ţinte implicite pentru consola de flotă: {"tags": [...]} sau null. `object`, nu un model
    # tipat: o formă greşită trebuie să dea 400 cu cod (`snippet.badTargets`, tradus în UI),
    # nu 422-ul generic al Pydantic. Absent din corp = clienţii vechi → nu atingem coloana.
    targets: Optional[object] = None


def _snippet_targets(raw) -> Optional[str]:
    """Validează + normalizează ţintele unui snippet → JSON de stocat sau None (fără ţinte).
    Etichetele se normalizează EXACT ca la hosturi (`hostmodel.tag_list`), ca „Prod" să nimerească
    hostul etichetat „prod". Peste hostmodel.MAX_TAGS → 400, nu tăiere tăcută."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) - {"tags"}:
        raise ApiError(400, "snippet.badTargets", 'targets must be null or {"tags": [...]}')
    tags = raw.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(x, str) for x in tags):
        raise ApiError(400, "snippet.badTargets", "targets.tags must be a list of strings")
    norm = hostmodel.tag_list(" ".join(tags), limit=None)
    if len(norm) > hostmodel.MAX_TAGS:
        raise ApiError(400, "snippet.tooManyTags", "at most %d target tags" % hostmodel.MAX_TAGS,
                       vars={"limit": hostmodel.MAX_TAGS})
    return json.dumps({"tags": norm}) if norm else None


def _snippet_out(r) -> dict:
    """Rândul din DB → JSON-ul API. `targets` e null pe rândurile vechi (coloană NULL) sau
    stricate — un JSON corupt nu are voie să rupă toată lista de snippet-uri."""
    targets = None
    if r["targets"]:
        try:
            t = json.loads(r["targets"])
            if isinstance(t, dict) and isinstance(t.get("tags"), list) and t["tags"]:
                targets = {"tags": [str(x) for x in t["tags"]]}
        except ValueError:
            targets = None
    keys = r.keys()
    return {"id": r["id"], "title": r["title"], "body": r["body"], "targets": targets,
            # 3.6 (§A.11.11): biblioteca e comună — arătăm cine a scris snippet-ul, ca un Owner
            # să nu ruleze orbeşte o comandă pusă acolo de altcineva
            "created_by_id": r["created_by_id"] if "created_by_id" in keys else None,
            "created_by": (r["creator_email"] if "creator_email" in keys else None) or ""}


async def _snippet_editable(sid: int, user) -> None:
    """Un snippet al altcuiva (sau unul vechi, fără autor) se editează/şterge doar cu
    `snippets.manage`. Fail-closed pe rândurile vechi: biblioteca e comună, iar un snippet
    modificat e o comandă pe care altcineva o va rula."""
    row = await db.fetchone("SELECT created_by_id FROM snippets WHERE id=?", sid)
    if not row:
        return                          # inexistent: comportamentul de dinainte (no-op 200)
    if row["created_by_id"] is not None and row["created_by_id"] == user["id"]:
        return
    if not (await authz.grants_for_user(user["id"])).has_global("snippets.manage"):
        raise ApiError(403, "authz.denied", "your role does not allow this here (snippets.manage)",
                       vars={"perm": "snippets.manage"})


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
    if await db.get_setting("snippets_seeded"):
        return
    for title, body in DEFAULT_SNIPPETS:
        dup = await db.fetchone("SELECT id FROM snippets WHERE title=? AND body=?", title, body)
        if not dup:
            await db.execute("INSERT INTO snippets(title, body, created) VALUES(?,?,?)",
                             title, body, time.time())
    await db.set_setting("snippets_seeded", "1")


@router.get("/api/snippets")
async def list_snippets(user=Depends(security.require_user)):
    rows = await db.fetchall("SELECT s.*, u.email AS creator_email FROM snippets s"
                             " LEFT JOIN users u ON u.id = s.created_by_id ORDER BY s.title")
    return [_snippet_out(r) for r in rows]


@router.post("/api/snippets")
async def create_snippet(s: SnippetIn, user=Depends(security.require_user)):
    if not s.title.strip() or not s.body:
        raise ApiError(400, "snippet.required", "title and body required")
    targets = _snippet_targets(s.targets)
    # idempotent: același titlu+conținut nu creează un duplicat. Dacă vin ţinte pe un
    # duplicat, le adoptăm (re-salvarea din consola de flotă cu „ţine minte etichetele")
    dup = await db.fetchone("SELECT id FROM snippets WHERE title=? AND body=?",
                            s.title.strip(), s.body)
    if dup:
        if targets is not None:
            await _snippet_editable(dup["id"], user)    # 3.6: nu re-ţinteşti snippet-ul altcuiva
            await db.execute("UPDATE snippets SET targets=? WHERE id=?", targets, dup["id"])
        return {"id": dup["id"]}
    sid = await db.execute("INSERT INTO snippets(title, body, created, targets, created_by_id)"
                           " VALUES(?,?,?,?,?)",
                           s.title.strip(), s.body, time.time(), targets, user["id"])
    return {"id": sid}


@router.patch("/api/snippets/{sid}")
async def update_snippet(sid: int, s: SnippetIn, user=Depends(security.require_user)):
    if not s.title.strip() or not s.body:
        raise ApiError(400, "snippet.required", "title and body required")
    await _snippet_editable(sid, user)
    # `targets` absent din corp (clienţii vechi trimit doar title+body) → ţintele rămân;
    # `targets: null` explicit → se şterg.
    if "targets" in s.model_fields_set:
        await db.execute("UPDATE snippets SET title=?, body=?, targets=? WHERE id=?",
                         s.title.strip(), s.body, _snippet_targets(s.targets), sid)
    else:
        await db.execute("UPDATE snippets SET title=?, body=? WHERE id=?",
                         s.title.strip(), s.body, sid)
    return {"ok": True}


@router.delete("/api/snippets/{sid}")
async def delete_snippet(sid: int, user=Depends(security.require_user)):
    await _snippet_editable(sid, user)
    await db.execute("DELETE FROM snippets WHERE id=?", sid)
    return {"ok": True}


# ── [sessions] Session request models + JSON ────────────────────────────────────────────────────

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
    stepup_totp: str = ""    # 2FA: cod TOTP/recovery pt. conturi cu TOTP fără passkey (fix 3)
    docker_container: str = ""  # dacă e setat: sesiunea e un shell ÎN acest container (docker exec)
    docker_logs: str = ""       # dacă e setat: sesiunea urmăreşte `docker logs -f` al containerului
    os_upgrade: bool = False    # dacă e True: sesiunea rulează comanda INTERACTIVĂ de upgrade OS
    connection_id: int = 0      # dacă e setat: sesiunea rulează CLI-ul DB al conexiunii salvate
    journal_unit: str = ""      # dacă e setat: sesiunea urmăreşte `journalctl -u <unit> -f`


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
        # cine a deschis-o (3.6; NULL = dinainte de roluri) — UI-ul ştie dacă poţi tasta în ea
        "created_by_id": row["created_by_id"] if "created_by_id" in row.keys() else None,
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


# ── [sessions] List sessions, open a session on a host ────────────────────────────────────────────

@router.get("/api/sessions")
async def list_sessions(request: Request,
                        user=Depends(authz.perm(('session.watch', 'recording.view'), list=True, tokens='read'))):
    # 3.6: doar sesiunile de pe hosturile unde contul (sau tokenul ∩ creatorul) le poate vedea —
    # filtrul e în SQL, ca fereastra celor 200 de sesiuni închise să fie a LUI, nu a flotei
    vis = await authz.visible_hosts(authz.grants_of(request), "session.watch", "recording.view")
    if vis is not None and not vis:
        return []
    hf, hargs = "", []
    if vis is not None:
        hf = " AND host_id IN (%s)" % ",".join("?" * len(vis))
        hargs = sorted(vis)
    active = await db.fetchall(
        "SELECT * FROM sessions WHERE state IN ('creating','live')" + hf
        + " ORDER BY created DESC", *hargs)
    closed = await db.fetchall(
        "SELECT * FROM sessions WHERE state NOT IN ('creating','live')" + hf
        + " ORDER BY created DESC LIMIT ?", *hargs, CLOSED_SESSIONS_LIMIT)
    rows = list(active) + list(closed)
    # meta-leak: lista (titluri, host, stare) de pe un host `require_2fa` e metadata la fel de
    # sensibilă ca transcriptul — o arătăm doar cu o fereastră de step-up deschisă pe hostul ăla.
    # Un TOKEN de automatizare nu poate face step-up (cheie fizică), deci pentru el ascundem TOATE
    # sesiunile hosturilor 2FA. Citire pasivă → `stepup_window_is_open` (nu glisează fereastra).
    gated = {r["id"] for r in await db.fetchall("SELECT id FROM hosts WHERE require_2fa=1")}
    if gated:
        is_token = isinstance(user, dict) and user.get("is_token")
        allowed = set() if is_token else {
            hid for hid in gated if security.stepup_window_is_open(user["id"], hid)}
        rows = [r for r in rows if r["host_id"] not in gated or r["host_id"] in allowed]
    return [_session_json(r) for r in rows]


@router.get("/api/hosts/{host_id}/sessions")
async def host_sessions(host_id: int, limit: int = 200, offset: int = 0,
                        stepup_grant: str = "", stepup_password: str = "", stepup_totp: str = "",
                        user=Depends(authz.perm(('session.watch', 'recording.view'), host='host_id'))):
    """Complete session history for one host (active + closed), paginated — used
    by the host page so it isn't limited by the global recent-closed window."""
    # meta-leak: titlurile/istoricul sesiunilor de pe un host 2FA cer step-up, ca restul citirilor
    # de host (fs/services/deploy-key). Fără 2FA pe host → no-op.
    await stepup.require_host_stepup(host_id, user, stepup_grant, stepup_password, stepup_totp)
    limit = max(1, min(limit, 500))
    rows = await db.fetchall(
        "SELECT * FROM sessions WHERE host_id=? ORDER BY created DESC LIMIT ? OFFSET ?",
        host_id, limit, max(0, offset))
    return [_session_json(r) for r in rows]


# ── [stepup] Per-host step-up (2FA window) ────────────────────────────────────────────────────────

@router.post("/api/hosts/{host_id}/stepup")
async def host_stepup(host_id: int, body: SessionIn, request: Request,
                      user=Depends(authz.perm('host.view', host='host_id'))):
    """Deschide fereastra de step-up pe un host cu 2FA (din passkey grant sau parolă), ca
    frontend-ul să deblocheze file-browser-ul / fleet-run înainte de acțiuni. Idempotent."""
    t_call = time.time()
    was_open = security.stepup_window_ok(user["id"], host_id)
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password,
                              body.stepup_totp)
    row = await db.fetchone("SELECT name, require_2fa FROM hosts WHERE id=?", host_id)
    # Pe un host FĂRĂ 2FA gard-ul de mai sus e no-op şi nu deschide nicio fereastră — dar
    # gate-ul de „factor proaspăt" (deploy-key, H-3) consultă fereastra şi pe astfel de
    # hosturi. Dacă clientul chiar a prezentat un factor valid, îl onorăm şi aici, ca
    # ceremonia din client (403 stepup.* → passkey/parolă → retry) să funcţioneze identic
    # indiferent de flag-ul 2FA al ţintei.
    #
    # NB (3.6.7, security review F2): fereastra deschisă aici CONTEAZĂ — `stepup.require_fresh_factor`
    # (deploy keys H-3, reînnoirea certificatelor) o acceptă. Ramura asta deschidea fereastra cu
    # PAROLA singură chiar pentru conturile cu passkey/TOTP, şi ignora tăcut un cod TOTP trimis.
    # Acum foloseşte aceeaşi scară ca restul (passkey → SSO → TOTP cu lockout → parolă), deci
    # un cont cu al doilea factor trebuie să-l dea şi aici. Un corp fără niciun factor rămâne
    # un no-op idempotent (nu deschide nimic).
    if row and not row["require_2fa"]:
        if body.stepup_grant and security.consume_stepup_grant(
                body.stepup_grant, user["id"], host_id):
            security.open_stepup_window(user["id"], host_id)
        elif body.stepup_password or body.stepup_totp:
            await stepup.consume_factor(host_id, user, "", body.stepup_password,
                                         body.stepup_totp, host_2fa=False)
    # deblocare PROASPĂTĂ (nu re-apel idempotent cât fereastra e deschisă) a unui host marcat 2FA
    # = un host protejat tocmai a fost accesat: notificăm (email + webhook), throttle-uit per host.
    if not was_open and row and row["require_2fa"]:
        email_alerts.notify_host_unlocked(row["name"], security.client_ip(request), user["email"],
                                          host_id=host_id, user_id=user["id"])
    # Say what happened (3.6.7 follow-up): it answered `window: 300` even when NOTHING opened (a
    # body without a factor on a host without 2FA), which reads as "you are stepped up".
    # `opened` = this call opened/refreshed the window; `window` = seconds left on it now (0 = none).
    rec = security.stepup_window_record(user["id"], host_id)
    now = time.time()
    opened = bool(rec and rec[0] >= t_call)
    left = int(rec[1] - now) if rec and rec[1] > now else 0
    return {"ok": True, "opened": opened, "window": max(0, left)}


# ── [ssh-keys] SSH key generated at host creation ─────────────────────────────────────────────────

@router.post("/api/hosts/{host_id}/ssh-key/generate")
async def host_generate_ssh_key(host_id: int, body: SessionIn, user=Depends(authz.perm('host.edit', host='host_id'))):
    """Generează o pereche de chei Ed25519 PENTRU un host SSH: stochează privata ca credenţial
    (criptată în seif) şi întoarce PUBLICA o singură dată, ca s-o pui în `authorized_keys` pe
    server. Scuteşte userul de `ssh-keygen` + mutat fişiere. Schimbă credenţialul → clasă de
    provisioning, deci cere step-up pe hosturile 2FA (ca update_host)."""
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    if conntypes.of(row) not in conntypes.SSH_FAMILY:
        raise ApiError(400, "sshkey.notSsh", "SSH key generation is only for SSH hosts")
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    k = asyncssh.generate_private_key("ssh-ed25519")
    # ACELAŞI format de blob ca `hostmodel.credential_blob` ({"key": PEM}). Până în 3.5.4 aici se scria
    # PEM-ul gol, iar conectarea cu cheia generată crăpa la json.loads (vezi hostmodel.decode_credential).
    await db.execute(
        "UPDATE hosts SET auth_method='key', credential_policy='stored', credential_encrypted=? WHERE id=?",
        security.encrypt_secret(json.dumps({"key": k.export_private_key().decode()})), host_id)
    log.info("generated a new SSH key for host #%d (by %s)", host_id, user["email"])
    return {"public_key": k.export_public_key().decode().strip(), "fingerprint": k.get_fingerprint()}


@router.post("/api/hosts/{host_id}/ssh-key/public")
async def host_ssh_key_public(host_id: int, body: SessionIn, user=Depends(authz.perm('host.edit', host='host_id'))):
    """Derivă cheia PUBLICĂ din privata stocată (ca s-o re-copiezi în authorized_keys) + arată
    known_hosts-ul pinuit. POST (nu GET) fiindcă are nevoie de credenţialele de step-up în corp."""
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    if not row["credential_encrypted"] or (row["auth_method"] or "") != "key":
        raise ApiError(400, "sshkey.none", "this host has no stored SSH key")
    try:
        # blobul e {"key": PEM, "passphrase"?} (sau PEM gol, pe rânduri dinainte de 3.5.4);
        # înainte se importa blobul JSON ca atare, deci „Show public key" pica pe ORICE cheie lipită
        cred = hostmodel.decode_credential(row["credential_encrypted"])
        k = asyncssh.import_private_key(cred["key"], cred.get("passphrase") or None)
    except Exception:                                   # noqa: BLE001
        raise ApiError(400, "sshkey.badKey", "the stored SSH credential is not a private key (it may be a password)")
    return {"public_key": k.export_public_key().decode().strip(), "fingerprint": k.get_fingerprint(),
            "known_hosts": row["known_hosts"] or ""}


# ── [sessions] Session control (owner or session.manage), open a session on a host ────────────
async def _require_session_control(request, sid: str, user) -> None:
    """Mutaţiile pe o sesiune (titlu, kill, ştergere, reconectare): `session.open` (verificat de
    rută) + sesiunea e a ta — sau ai `session.manage` pe host (Q5: Operatorii urmăresc sesiunile
    altora, dar nu le controlează)."""
    row = await db.fetchone("SELECT host_id, created_by_id FROM sessions WHERE id=?", sid)
    if not row:
        return                                    # handlerul răspunde cu 404-ul lui
    if row["created_by_id"] is None or row["created_by_id"] == user["id"]:
        return
    have = await authz.require_on(request, row["host_id"], "session.open", "sid")
    if "session.manage" not in have:
        raise ApiError(403, "authz.denied", "your role does not allow this here (session.manage)",
                       vars={"perm": "session.manage"})


@router.post("/api/hosts/{host_id}/sessions")
async def create_session(host_id: int, body: SessionIn, request: Request,
                         user=Depends(authz.perm('session.open', host='host_id'))):
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    # 3.6: un lansator DB e o sesiune (session.open, verificat de rută) care rulează clientul cu
    # parola STOCATĂ a conexiunii → cere şi `toolbox.use`. Înainte de step-up (authz → 2FA).
    if body.connection_id:
        await authz.require_on(request, host_id, "toolbox.use")
    # 2FA step-up (server-side; bifa din client nu e de încredere) — deschide/consultă fereastra
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    ctype = conntypes.of(row)
    if ctype in conntypes.SSH_FAMILY:
        await hostmodel.connect_direct(row, request, body.credential, body.passphrase)
    elif ctype == "telnet":
        await hostmodel.connect_telnet(row, request, body.credential)
    # telnet-jump: nicio pre-conectare per-host — sesiunea (ForwardTelnetSource) deschide
    # singură tunelul prin agentul `via_host_id` în create_telnet_jump_session (mai jos).
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
    cmd = None
    db_pw = None   # parola unei conexiuni `stored` — injectată de agent în PTY la prompt (v53)
    if body.docker_container:
        # shell ÎN container: sesiunea rulează `docker exec` în loc de shell-ul de login.
        # Doar host-uri de agent (docker e local pe host). Id-ul de container e validat strict.
        if ctype != "agent":
            raise ApiError(400, "session.containerAgentOnly", "container shells are only available on agent hosts")
        if not hostcmd.DOCKER_ID.match(body.docker_container):
            raise ApiError(400, "docker.badContainer", "invalid container id")
        cmd = hostcmd.docker_exec_cmd(body.docker_container)
        if not title.strip() or title.startswith("Session "):
            title = "docker: " + body.docker_container[:24]
    elif body.docker_logs:
        # „Logs" dintr-un container: sesiune cu `docker logs --tail 500 -f` — acelaşi model ca
        # journal_unit din Services (terminal real: culori, scrollback, căutare, Ctrl+C opreşte).
        # Ca „Logs" din Services şi ca lista Docker, NU trece prin guardrail: e o citire (vezi
        # docs/GUARDRAIL.md, „read-only panel calls"). Step-up-ul pe host 2FA s-a cerut mai sus.
        if ctype != "agent":
            raise ApiError(400, "session.containerAgentOnly", "container shells are only available on agent hosts")
        if not hostcmd.DOCKER_ID.match(body.docker_logs):
            raise ApiError(400, "docker.badContainer", "invalid container id")
        cmd = hostcmd.docker_logs_cmd(body.docker_logs)
        if not title.strip() or title.startswith("Session "):
            title = "logs: " + body.docker_logs[:24]
    elif body.os_upgrade:
        # „Upgrade într-un terminal": deschidem o sesiune care rulează comanda INTERACTIVĂ de
        # upgrade pentru managerul detectat (din diagnostics). NU input arbitrar — o hartă fixă,
        # ca la docker_container. Glue, nu un package-manager reimplementat.
        if ctype != "agent":
            raise ApiError(400, "session.upgradeAgentOnly", "OS upgrade is only available on agent hosts")
        mgr = (hostmodel.host_updates(row) or {}).get("manager")
        base = {"apt": "apt-get update && apt-get upgrade", "dnf": "dnf upgrade"}.get(mgr)
        if not base:
            raise ApiError(400, "updates.noManager", "no known OS package manager on this host")
        # CONŞTIENT DE PRIVILEGII: instalarea implicită rulează ca userul dedicat `webterm`, FĂRĂ
        # sudo — un `sudo` fix îl bloca la un prompt de parolă imposibil (raportat 2026-09). Deci:
        # root → direct; sudo passwordless → sudo; altfel → mesaj clar cu comanda exactă (userul
        # cu sudo-parolă o poate lipi şi tasta parola), NICIODATĂ un prompt agăţat.
        #
        # `exec $SHELL` DOAR în ramura de ghidare — acolo ai nevoie de un shell ca să acţionezi.
        # După un upgrade REUŞIT (root/sudo) sesiunea se ÎNCHEIE: terminalul e task-scoped, iar pe
        # un host unde agentul e root un `exec $SHELL` lăsa un shell ROOT persistent după task
        # (raportat 2026-09). Scrollback-ul rămâne vizibil oricum; pentru un shell obişnuit deschizi
        # o sesiune normală.
        # hint-ul PRINTAT foloseşte tot `sudo sh -c '<base>'`: un `sudo %s` naiv ar da
        # `sudo apt-get update && apt-get upgrade` → sudo prinde doar `update`, iar `upgrade`
        # rulează neprivilegiat şi pică (audit 2026-09). Deci compunerea întreagă sub un singur sudo.
        # Ramura de ghidare (nici root, nici sudo passwordless) NU rulează nimic — arată OPŢIUNILE
        # şi lasă alegerea utilizatorului (raportat 2026-09): (a) rulează chiar el ca root, sau
        # (b) acordă userului agentului sudo (comandă gata de copiat) ca butonul să meargă data
        # viitoare. `echo`-uri, nu printf — evită dublul nivel de `%`. `exec $SHELL` doar aici.
        qbase = shlex.quote(base)
        # binarul pe care îl acordăm în sudoers: EXACT cel pe care îl rulează `base`, nu `ALL`.
        # `NOPASSWD:ALL` pentru userul agentului e echivalent cu root pe host — anulează tăcut
        # tocmai bariera „agent neprivilegiat" din THREAT-MODEL (semnalat de auditul din 2026-10).
        mgr_bin = {"apt": "apt-get", "dnf": "dnf"}.get(mgr, "apt-get")
        guide = (
            'u=$(whoami); echo; '
            'echo "[WebTerm] OS upgrade needs root. This agent runs as $u, without passwordless sudo."; '
            'echo; echo "Your options — your call:"; '
            'echo "  1) Run it now as root yourself:"; '
            'echo "       sudo sh -c ' + qbase.replace('"', '\\"') + '"; '
            'echo "  2) Or let this button work next time — allow the agent user to run ONLY the"; '
            'echo "     package manager as root (sudoers, as root):"; '
            'echo "       echo \\"$u ALL=(root) NOPASSWD: $(command -v ' + mgr_bin + ')\\" | sudo tee /etc/sudoers.d/$u"; '
            'echo "     Do NOT use NOPASSWD:ALL — that makes the agent user root-equivalent and"; '
            'echo "     removes the protection of running the agent unprivileged."; echo; '
            'exec "${SHELL:-/bin/sh}"')
        sh = ('if [ "$(id -u)" = 0 ]; then %s; '
              'elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then sudo sh -c %s; '
              'else %s; fi') % (base, qbase, guide)
        cmd = "sh -c %s" % shlex.quote(sh)
        if not title.strip() or title.startswith("Session "):
            title = "OS upgrade (%s)" % mgr
    elif body.journal_unit:
        # „Logs" dintr-o unitate systemd: o sesiune care urmăreşte `journalctl -u <unit> -f`,
        # exact tiparul docker-logs/os_upgrade (glue peste journalctl, nu un UI de loguri fals).
        # Fără root journalctl arată doar ce poate — acceptabil, e un terminal, userul vede.
        if ctype != "agent":
            raise ApiError(400, "session.journalAgentOnly", "journal follow is only available on agent hosts")
        if not hostcmd.UNIT_RE.match(body.journal_unit):
            raise ApiError(400, "services.badUnit", "invalid unit name")
        u = shlex.quote(body.journal_unit)
        cmd = "journalctl -u %s -n 200 -f --no-pager" % u
        if not title.strip() or title.startswith("Session "):
            title = "journal: " + body.journal_unit[:28]
    elif body.connection_id:
        # Lansator de conexiune DB: sesiunea rulează CLI-ul salvat (psql/mysql/…) cu ţinta
        # pre-completată. Doar host-uri de agent. Politica `ask` → clientul cere parola singur
        # (fără secrete la noi). Step-up-ul pentru sesiuni pe host 2FA se aplică deja mai sus.
        if ctype != "agent":
            raise ApiError(400, "session.dbAgentOnly", "database connections are only available on agent hosts")
        conn = await db.fetchone("SELECT * FROM connections WHERE id=? AND host_id=?",
                                 body.connection_id, host_id)
        if not conn:
            raise ApiError(404, "connection.missing", "connection not found")
        cmd = _connection_command(conn)
        # `stored`: decriptăm parola din vault şi o dăm agentului (canal WS criptat); el o injectează
        # în stdin-ul PTY la promptul „password" — nu atinge argv/env/ps/transcript. Citirea
        # secretului pe un host 2FA e deja păzită de step-up-ul de sesiune (verificat mai sus).
        if (conn["cred_policy"] or "ask") == "stored" and conn["credential_encrypted"]:
            db_pw = security.decrypt_secret(conn["credential_encrypted"])
        if not title.strip() or title.startswith("Session "):
            title = "%s: %s" % (conn["engine"], conn["label"][:32])
    try:
        if ctype == "telnet-jump":
            # telnet-bastion spre o ţintă salvată din LAN-ul agentului `via_host_id`
            result = await core.create_telnet_jump_session(row, title, body.rows, body.cols, body.tz)
        else:
            result = await core.create_session(host_id, title, body.rows, body.cols, body.tz, cmd, db_pw)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")
    except core.SessionLimitReached:
        raise ApiError(409, "session.limit",
                       f"the host reached its limit of {core.MAX_SESSIONS_HINT} sessions — close one first",
                       vars={"limit": core.MAX_SESSIONS_HINT})
    except RuntimeError as e:
        raise errors.runtime_api_error(e, "session.createFailed")
    await core.stamp_session(result, user)
    return result


# ── [sessions] Session rename / reconnect / kill / delete ─────────────────────────────────────────

@router.patch("/api/sessions/{sid}")
async def update_session(sid: str, patch: SessionPatch, request: Request,
                         user=Depends(authz.perm('session.open', host='sid'))):
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    if not row:
        raise ApiError(404, "session.missing", "no such session")
    await _require_session_control(request, sid, user)
    # titlul/nota unei sesiuni de pe un host 2FA = mutaţie pe acel host, ca restul rutelor de
    # sesiune (kill/share/transcript): fără step-up, un cookie furat redenumea terminale protejate
    await stepup.require_session_host_stepup(sid, user)
    title = patch.title if patch.title is not None else row["title"]
    note = patch.note if patch.note is not None else row["note"]
    await db.execute("UPDATE sessions SET title=?, note=? WHERE id=?",
                     title.strip(), note, sid)
    return {"ok": True}


@router.post("/api/sessions/{sid}/reconnect")
async def reconnect_session(sid: str, request: Request,
                            user=Depends(authz.perm('session.open', host='sid'))):
    """Reconectează o sesiune telnet-bastion căzută: telnet nou spre aceeași țintă,
    același tab/transcript. Doar pentru sesiuni telnet (nu shell/tmux — alea se
    re-adoptă singure la revenirea agentului)."""
    await _require_session_control(request, sid, user)
    srow = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
    if srow:   # H1: telnet nou prin agentul host-ului = poartă ca la create_session
        await stepup.require_host_stepup(srow["host_id"], user)
    try:
        return await core.reconnect_telnet_session(sid)
    except KeyError:
        raise ApiError(404, "session.notTelnet", "no such session, or not a telnet bastion")
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")
    except core.SessionLimitReached:
        raise ApiError(409, "telnet.limit", "the telnet session limit was reached — close one first")
    except RuntimeError as e:
        raise errors.runtime_api_error(e, "session.createFailed")


@router.post("/api/sessions/{sid}/kill")
async def kill_session(sid: str, request: Request,
                       user=Depends(authz.perm('session.open', host='sid'))):
    await _require_session_control(request, sid, user)
    srow = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
    if srow:   # H1: a termina o sesiune pe un host cu 2FA e o acţiune de host → cere step-up
        await stepup.require_host_stepup(srow["host_id"], user)
    try:
        await core.kill_session(sid)
    except KeyError:
        raise ApiError(404, "session.missing", "no such live session")
    except core.AgentGone:
        raise ApiError(409, "session.hostOfflineKill", "the host is offline; the session cannot be closed right now")
    return {"ok": True}


@router.delete("/api/sessions/{sid}")
async def delete_session(sid: str, request: Request,
                         user=Depends(authz.perm('session.open', host='sid'))):
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    if not row:
        raise ApiError(404, "session.missing", "no such session")
    await _require_session_control(request, sid, user)
    # H1: ştergerea (arhivarea) transcriptului unei sesiuni de pe un host 2FA e o acţiune de
    # host — aceeaşi poartă ca `kill`. Fără asta, un cookie furat putea arhiva/scoate din listă
    # sesiuni 2FA fără step-up, deşi citirea lor îl cere.
    await stepup.require_host_stepup(row["host_id"], user)
    if row["state"] in ("creating", "live"):
        raise ApiError(409, "session.live", "the session is live; close it first")
    await db.execute("DELETE FROM sessions WHERE id=?", sid)
    await shares.delete_replay_links(" WHERE sid=?", sid)     # înregistrarea nu mai e de partajat
    await core.prune_split_views()                      # split-urile care o refereau (3.6.12)
    # nu ștergem transcriptul pe loc: îl arhivăm (recuperabil ~120 zile), apoi
    # janitor-ul îl curăță definitiv după retenție
    core.archive_transcript(sid)
    return {"ok": True}


class ShareIn(BaseModel):
    writable: bool = False
    expires_minutes: int = 1440   # 24h implicit
    stepup_grant: str = ""        # 2FA: pe host cu require_2fa, crearea share-ului cere step-up (H1)
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


# ── [share] Create / revoke a live share link ─────────────────────────────────────────────────────

@router.post("/api/sessions/{sid}/share")
async def create_share(sid: str, request: Request, body: ShareIn = ShareIn(),
                       user=Depends(authz.perm('share.live', host='sid'))):
    """Link public, temporizat, către o sesiune. `writable` lasă vizitatorul să și
    TASTEZE (lărgește suprafața de încredere — opt-in per share); altfel doar vizualizare."""
    audit.detail(request, "writable" if body.writable else "read-only")
    row = await db.fetchone("SELECT id, host_id, origin, state FROM sessions WHERE id=?", sid)
    if not row:
        raise ApiError(404, "session.missing", "no such session")
    # un link LIVE către o sesiune încheiată publica înregistrarea fără `recording.view` /
    # `share.replay` (raport de securitate 2026-11, lot 1) — pentru asta există linkurile de replay
    if row["state"] not in ("creating", "live"):
        raise ApiError(409, "session.notLive", "only a running session can be shared live")
    # 3.6.7 (review F4): a certificate-renewal terminal (sudo on the gateway host) is never shared
    if _origin(row) in ROOT_TERMINAL_ORIGINS:
        raise ApiError(403, "certs.renewSessionPrivate",
                       "a certificate renewal terminal cannot be shared")
    # 3.6: link-ul public e o extensie a sesiunii — doar pe a TA (sau pre-3.6, sau cu
    # session.manage); altfel un Operator ar putea expune / înlocui link-ul altcuiva
    await _require_session_control(request, sid, user)
    # 3.6: un share WRITABLE dă tastatura unui vizitator anonim → permisiune separată (⚑)
    if body.writable:
        await authz.require_on(request, row["host_id"], "share.live_write", "sid")
    # H1: un share (mai ales writable) e o cale de acces DURABILĂ, cookie-free, către terminalul
    # unui host — pe un host cu require_2fa e o acțiune sensibilă ca `run`/`kill`, deci cere step-up.
    # (Fără asta, un share writable ținea sesiunea trează — inputul invitatului resetează idle-lock-ul
    # — ocolind 2FA-ul care altfel s-ar re-cere.)
    await stepup.require_host_stepup(row["host_id"], user, body.stepup_grant, body.stepup_password, body.stepup_totp)
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


@router.get("/api/sessions/{sid}/share")
async def share_state(sid: str, user=Depends(authz.perm('session.watch', host='sid'))):
    """Starea share-ului activ al unei sesiuni — ca owner-ul să-şi regăsească link-ul activ şi
    butonul de revocare după un reload (până în 3.5.3 starea trăia doar în memoria tab-ului).

    URL-ul NU se întoarce, nici aici: token-ul e stocat HASH-uit (vezi create_share), deci nu
    poate fi reconstruit — se arată o singură dată, la creare. Întoarcem doar ce e nevoie pentru
    UI (activ / expirare / writable / al meu) şi DOAR unui utilizator de browser (`require_user`,
    nu token de automatizare). Pe un host 2FA fără fereastră de step-up deschisă răspundem
    „inactiv", ca la lista de sesiuni (meta-leak): citire PASIVĂ, nu glisează fereastra."""
    row = await db.fetchone(
        "SELECT host_id, share_token, share_expires, share_writable, share_by_id"
        " FROM sessions WHERE id=?", sid)
    if not row:
        raise ApiError(404, "session.missing", "no such session")
    hrow = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", row["host_id"])
    if hrow and hrow["require_2fa"] and not security.stepup_window_is_open(user["id"], row["host_id"]):
        return {"active": False}
    active = bool(row["share_token"]) and (row["share_expires"] or 0) > time.time()
    if not active:
        return {"active": False}
    return {"active": True, "expires": row["share_expires"],
            "writable": bool(row["share_writable"]),
            "mine": row["share_by_id"] == user["id"]}


@router.delete("/api/sessions/{sid}/share")
async def revoke_share(sid: str, request: Request,
                       user=Depends(authz.perm('share.live', host='sid'))):
    await _require_session_control(request, sid, user)    # 3.6: doar pe sesiunea ta / manage
    # H1: pe un host 2FA, revocarea share-ului e o acţiune de host (simetric cu crearea lui, care
    # cere step-up). Fără gard, un cookie furat putea manipula share-urile fără al doilea factor.
    srow = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
    if srow:
        await stepup.require_host_stepup(srow["host_id"], user)
    await db.execute("UPDATE sessions SET share_token=NULL, share_expires=NULL WHERE id=?", sid)
    hub = core.hubs.get(sid)
    if hub:
        await hub.revoke_shares()   # închide invitaţii deja conectaţi (notificare + stop broadcast)
    return {"ok": True}


# ── [share] Inventarul share-urilor + rezumatul de securitate (3.5.4) ────────────────────────────
# Până acum, „e totul în regulă acum?" cerea patru locuri (Setări → Securitate, sesiunile
# partajate, guardrail-ul, cheia de semnare), iar link-urile de share live din flotă nu le
# lista nimic. Ambele endpoint-uri doar AGREGĂ starea existentă — nicio stocare nouă — şi
# sunt DOAR pe cookie (`require_user`): un token de automatizare nu vede inventarul de acces.

def _share_guests(sid: str) -> int:
    """Invitaţii conectaţi ACUM printr-un link de share: clienţii hub-ului care nu sunt owner
    (exact pe cei pe care `SessionHub.revoke_shares` îi deconectează)."""
    hub = core.hubs.get(sid)
    return sum(1 for c in hub.clients if not c.is_owner) if hub else 0


async def _active_shares(user, grants=None) -> tuple[list, int]:
    """Share-urile active (neexpirate) vizibile userului + câte sunt ASCUNSE.

    Aceeaşi regulă ca lista de sesiuni şi `GET /api/sessions/{sid}/share` (meta-leak): titlul
    şi hostul unei sesiuni de pe un host `require_2fa` se arată doar cu fereastra de step-up
    deschisă pe hostul ăla — citire PASIVĂ, nu glisează fereastra. Ascunsele se NUMĂRĂ totuşi:
    rezumatul care ar spune „0 link-uri" cât există unul pe un host 2FA ar minţi exact la
    întrebarea pentru care există. Tokenul (hash-ul) nu e nici măcar selectat."""
    rows = await db.fetchall(
        "SELECT s.id, s.title, s.host_id, s.share_expires, s.share_writable, s.share_by,"
        " s.share_by_id, h.name AS host_name, h.require_2fa"
        " FROM sessions s LEFT JOIN hosts h ON h.id = s.host_id"
        " WHERE s.share_token IS NOT NULL AND s.share_expires > ?"
        " ORDER BY s.share_expires", time.time())
    # 3.6: fără `shares.manage` — doar share-urile tale; cu el — toate, dar tot DOAR de pe
    # hosturile vizibile. Rândurile din afara scope-ului nici nu se numără în `hidden`
    # (numărul ar fi un oracol de activitate pe hosturi pe care nu le vezi).
    if grants is None:
        grants = await authz.grants_for_user(user["id"])
    manage = grants.has_global("shares.manage")
    vis = await authz.visible_hosts(grants, "host.view")
    out, hidden = [], 0
    for r in rows:
        if not authz.in_visible(vis, r["host_id"]):
            continue
        if not manage and r["share_by_id"] != user["id"]:
            continue
        if r["require_2fa"] and not security.stepup_window_is_open(user["id"], r["host_id"]):
            hidden += 1
            continue
        out.append({"sid": r["id"], "title": r["title"] or "", "host_id": r["host_id"],
                    "host_name": r["host_name"] or "", "by": r["share_by"] or "",
                    "writable": bool(r["share_writable"]), "expires": r["share_expires"],
                    "viewers": _share_guests(r["id"])})
    return out, hidden


@router.get("/api/shares")
async def list_shares(request: Request, user=Depends(authz.perm('shares.manage', list=True))):
    """Toate link-urile de share active din flotă — FĂRĂ token şi fără URL: în DB stă doar
    hash-ul, iar URL-ul se arată o singură dată, la creare (vezi create_share)."""
    shares, hidden = await _active_shares(user, authz.grants_of(request))
    return {"shares": shares, "hidden": hidden}


class RevokeAllSharesIn(BaseModel):
    current_password: str = ""
    stepup_grant: str = ""      # conturi SSO: grant passkey account-scope (host_id=0)


@router.post("/api/shares/revoke-all")
async def revoke_all_shares(body: RevokeAllSharesIn, request: Request,
                            user=Depends(authz.perm('shares.manage', list=True))):
    """„Revocă tot": butonul de panică din inventar. Global (toate conturile, toate hosturile,
    inclusiv cele 2FA ascunse din listă) — exact ramura folosită la schimbarea parolei.

    Cere parola CONTULUI, ca restul operaţiilor cu greutate: un cookie furat singur nu poate
    rupe dintr-un POST toate link-urile pe care un coleg le-a dat la un incident. Conturile SSO
    n-au parolă locală utilizabilă → acceptăm re-auth-ul lor real (grant passkey sau fereastra
    account-scope deschisă de SSO), ca la `/api/account`."""
    if user["sso_subject"] and config.OIDC_ENABLED:
        ok_reauth = (bool(body.stepup_grant)
                     and security.consume_stepup_grant(body.stepup_grant, user["id"], 0)) \
            or security.stepup_window_is_open(user["id"], 0)
        if not ok_reauth:
            raise ApiError(403, "shares.ssoReauth",
                           "re-authenticate with SSO or a passkey to revoke all share links")
    else:
        await stepup.require_reauth_for_secret(user, body.current_password, "revoking all share links")
    if authz.grants_of(request).has_global("shares.manage"):
        n = await shares.revoke_all_shares()       # global + deconectează invitaţii live (hub.revoke_shares)
        n += await shares.revoke_replay_links()    # butonul de panică acoperă şi link-urile de replay
    else:
        # 3.6: fără `shares.manage`, „Revocă tot" = toate link-urile TALE (doar reduce acces)
        n = await shares.revoke_all_shares(user["email"], user["id"])
        n += await shares.revoke_replay_links(user["id"])
    audit.detail(request, "revoked all share links (%d active)" % n)
    log.warning("all share links revoked (%d active) by %s", n, user["email"])
    email_alerts.notify_security_change("all share links were revoked (%d active)" % n,
                                        security.client_ip(request), user["email"], fleet=True,
                                        what_key="shares_revoked", what_params={"n": n})
    return {"ok": True, "revoked": n}


# Vârsta peste care ultimul backup reuşit devine „vechi": perioada programării + o zi de
# toleranţă (un daily ratat o dată = avertisment; un weekly nu avertizează în ziua a 3-a).
# Fără programare, pragul e cel al unui daily: „~2 zile".
_BACKUP_GRACE = 86400


async def _check_backup() -> dict:
    sched = await db.get_setting("backup_schedule", "off")
    last_local = float(await db.get_setting("backup_last", "0") or 0)
    stored = backup.list_backups()
    if stored:
        last_local = max(last_local, float(stored[0]["created"]))
    err = await db.get_json_setting("backup_last_error")
    cloud = await cloudbackup.status()
    offsite = bool(cloud.get("configured"))
    last_cloud = float(cloud.get("last_ok") or 0) if offsite else 0.0
    last_ok = max(last_local, last_cloud)
    value = {"last_ok": last_ok or None, "schedule": sched,
             "failed_at": (float(err.get("ts") or 0) or None) if err else None,
             "failed_stage": (err.get("stage") or "") if err else "",
             # copiile OFF-HOST sunt mereu criptate (cloudbackup refuză upload-ul fără parolă);
             # snapshot-urile locale stau necriptate prin design (serverul are oricum cheia)
             "offsite": offsite, "encrypted": offsite and bool(cloud.get("has_passphrase"))}
    period = backup.SCHEDULE_PERIODS.get(sched, 86400)
    if err or not last_ok:
        status = "bad"
    elif time.time() - last_ok > period + _BACKUP_GRACE:
        status = "warn"
    else:
        status = "ok"
    return {"id": "backup", "status": status, "value": value}


async def _security_checks(user, grants=None) -> list:
    checks = []
    if grants is None:
        grants = await authz.grants_for_user(user["id"])
    # 3.6: verificările de INSTANŢĂ doar cu `security.view`; fără el rămân cele ale contului tău,
    # calculate peste hosturile pe care le vezi (fără oracol de mărimea flotei)
    instance = grants.has_global("security.view")
    vis = await authz.visible_hosts(grants, "host.view")
    hosts = [h for h in await db.fetchall(
        "SELECT id, require_2fa, connection_type, agent_version, uninstalled_at"
        " FROM hosts WHERE COALESCE(ephemeral, 0) = 0") if authz.in_visible(vis, h["id"])]
    any_2fa = any(h["require_2fa"] for h in hosts)

    # 1. al doilea factor al contului CURENT
    pk = await db.fetchone("SELECT COUNT(*) c FROM webauthn_credentials WHERE user_id=?", user["id"])
    passkeys = pk["c"] if pk else 0
    totp = bool(user["totp_enabled"])
    sso = bool(user["sso_subject"]) and config.OIDC_ENABLED
    if passkeys == 0 and not totp:
        # contul SSO îşi face al doilea factor la IdP — nu-l putem vedea, deci nu-l declarăm „rău"
        st = "info" if sso else "bad"
    elif passkeys == 1 and not totp and any_2fa:
        st = "warn"          # o singură cheie fizică pierdută = hosturile 2FA închise
    else:
        st = "ok"
    checks.append({"id": "account2fa", "status": st,
                   "value": {"passkeys": passkeys, "totp": totp, "sso": sso, "hosts2fa": any_2fa}})
    if not instance:
        return checks

    # 2. link-urile de share active (toate, inclusiv cele ascunse de pe hosturi 2FA)
    rows = await db.fetchall(
        "SELECT share_writable FROM sessions WHERE share_token IS NOT NULL AND share_expires > ?",
        time.time())
    writable = sum(1 for r in rows if r["share_writable"])
    # 3.5.15: şi link-urile de REPLAY active (3.5.12) sunt o cale publică de acces fără cont —
    # numărate separat (pe toată instanţa, ca share-urile live: orice cont e admin), cu cele
    # FĂRĂ mascarea secretelor scoase în evidenţă. Fără scriere, deci niciodată „bad" singure.
    rp = await db.fetchone(
        "SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN redact=0 THEN 1 ELSE 0 END), 0) AS raw"
        " FROM replay_links WHERE expires > ?", time.time())
    replay_n, replay_raw = (int(rp["n"]), int(rp["raw"])) if rp else (0, 0)
    checks.append({"id": "shares",
                   "status": "bad" if writable else ("warn" if rows or replay_n else "ok"),
                   "value": {"active": len(rows), "writable": writable,
                             "replay": replay_n, "replay_unmasked": replay_raw}})

    # 3. guardrail-ul de comenzi
    g = await cmdguard.load_command_guard()
    rules = len(g.get("rules") or [])
    checks.append({"id": "guardrail",
                   "status": "ok" if g.get("enabled") and rules else "warn",
                   "value": {"enabled": bool(g.get("enabled")), "rules": rules}})

    # 4. cheia de semnare — aceeaşi definiţie ca punctul de pe rotiţa Setărilor (/api/state)
    if not signing.key_exists():
        key_state, st = "missing", "warn"
    elif signing.is_encrypted() and not signing.is_loaded():
        key_state, st = "locked", "bad"
    else:
        key_state, st = "ok", "ok"
    checks.append({"id": "signingKey", "status": st, "value": {"state": key_state}})

    # 5. câte hosturi cer 2FA (informativ: alegerea e per host)
    checks.append({"id": "hosts2fa", "status": "info",
                   "value": {"on": sum(1 for h in hosts if h["require_2fa"]), "total": len(hosts)}})

    # 6. backup
    checks.append(await _check_backup())

    # 7. canalele de alertă — doar DACĂ sunt configurate, niciodată valorile (parola SMTP,
    #    URL-ul webhook-ului poartă adesea un secret în path)
    cfg = await email_alerts.load_config()
    smtp, webhook = email_alerts._configured(cfg), bool(cfg.get("webhook"))
    checks.append({"id": "alerts", "status": "ok" if smtp or webhook else "warn",
                   "value": {"smtp": smtp, "webhook": webhook}})

    # 8. agenţii: versiunea celor ONLINE faţă de cea livrată cu gateway-ul. Offline nu e o
    #    problemă de securitate (se actualizează la reconectare) — se numără separat.
    expected = core.agent_expected().get("version")
    agents = [h for h in hosts
              if conntypes.is_agent(h) and not h["uninstalled_at"]]
    online = outdated = 0
    for h in agents:
        src = core.sources.get(h["id"])
        if src is None:
            continue
        online += 1
        v = getattr(src, "agent_version", None) or h["agent_version"] or 0
        if expected and v < expected:
            outdated += 1
    checks.append({"id": "agents", "status": "warn" if outdated else "ok",
                   "value": {"expected": expected, "online": online, "outdated": outdated,
                             "offline": len(agents) - online}})

    # TLS: expirarea certificatului NU e cunoscută din aplicaţie — certul îl serveşte Traefik, iar
    # verificarea lui trăieşte pe host (scripts/cert-check.sh, timer systemd). Nu inventăm o
    # sondă aici; check-ul lipseşte în loc să spună ceva neverificat.
    return checks


@router.get("/api/security/summary")
async def security_summary(request: Request, user=Depends(authz.perm('security.view', list=True))):
    """„E totul în regulă acum?" — o listă de verificări {id, status, value}. Fără proză:
    frontend-ul compune textul din i18n după `id` + `value`."""
    return {"checks": await _security_checks(user, authz.grants_of(request)), "ts": time.time()}


async def _public_watermark(owner_email: str, title: str) -> dict:
    """Watermark-ul unei suprafeţe PUBLICE (share live, link de replay), cu ${email}/${host}
    rezolvate server-side — emailul nu pleacă dacă template-ul nu-l foloseşte."""
    wm = await _load_watermark()
    if not wm.get("enabled"):
        return {"enabled": False}
    if not owner_email:
        first = await db.fetchone("SELECT email FROM users ORDER BY created LIMIT 1")
        owner_email = first["email"] if first else ""
    content = (wm["content"]
               .replace("${email}", owner_email)
               .replace("${host}", title or ""))
    return {**wm, "content": content}


def _share_gate(ip: str) -> None:
    """Limita per IP pe share-ul LIVE (3.5.15) — acelaşi limitator ca link-urile de replay, cu
    găleată proprie (`replay.SHARE_LIMIT`): total + eşecuri, blocarea pe eşecuri valabilă pentru
    ORICE token (şi unul valid), ca blocajul să nu fie un oracol."""
    retry = replay.SHARE_LIMIT.gate(ip)
    if retry:
        raise ApiError(429, "share.rateLimited", "too many requests; retry in %ds" % retry,
                       headers={"Retry-After": str(retry)}, vars={"retry": retry})


# ── [share] Shared-link meta (guest side) ─────────────────────────────────────────────────────────

@router.get("/api/shared/{token}")
async def shared_meta(token: str, request: Request):
    """Public: minimal session info for the read-only shared view."""
    ip = security.client_ip(request)
    _share_gate(ip)
    row = None
    if 8 <= len(token) <= 128:
        row = await db.fetchone(
            "SELECT * FROM sessions WHERE share_token=? AND share_expires > ?",
            security.sha256_hex(token), time.time())
    if not row:
        replay.SHARE_LIMIT.record_miss(ip)
        raise ApiError(404, "link.invalid", "invalid or expired link")
    if row["state"] not in ("creating", "live"):
        # ca /ws/shared: un link live nu mai arată nimic dintr-o sesiune încheiată (nici titlul)
        raise ApiError(404, "link.invalid", "invalid or expired link")
    # watermark pe link-ul partajat = trasabilitatea celei mai riscante suprafețe
    # (sesiune vizibilă unui terț). Rezolvăm ${email}/${host} SERVER-SIDE, ca să nu
    # expunem emailul dacă template-ul nu-l folosește; ${time}/${date} le lasă clientul.
    # emailul celui care A CREAT share-ul (share_by); pentru share-uri de dinainte de
    # conturile multiple, revenim la primul cont — comportamentul de până acum
    owner_email = row["share_by"] if "share_by" in row.keys() and row["share_by"] else ""
    wm = await _public_watermark(owner_email, row["title"])
    return {"title": row["title"], "state": row["state"],
            "rows": row["rows"], "cols": row["cols"], "watermark": wm,
            "writable": bool(row["share_writable"])}


TEXT_VIEW_TAIL = 2 * 1024 * 1024       # cât citim pentru vizualizarea din UI (coada)


# ── [replay] Transcripts + replay links ───────────────────────────────────────────────────────────

@router.get("/api/sessions/{sid}/transcript")
async def get_transcript(sid: str, format: str = "out", tail: bool = False,
                         user=Depends(authz.perm('recording.view', host='sid'))):
    """`out` = fluxul brut, `cast` = asciicast (redare cu timing), `txt` = text citibil.
    `tail=true` (doar pentru txt) întoarce doar coada — vizualizarea din UI nu trage
    zeci de MB ca să arate ce s-a întâmplat ultima dată."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    await stepup.require_session_host_stepup(sid, user)
    out_path, cast_path = core.transcript_paths(sid)
    if format == "txt":
        if not out_path.exists():
            raise ApiError(404, "transcript.missing", "no transcript for this session")
        text = await asyncio.to_thread(core.transcript_text, sid,
                                       TEXT_VIEW_TAIL if tail else 0)
        return Response(content=text, media_type="text/plain; charset=utf-8",
                        headers={} if tail else
                        {"Content-Disposition": 'attachment; filename="%s.txt"' % sid[:8]})
    path = cast_path if format == "cast" else out_path
    if not path.exists():
        raise ApiError(404, "transcript.missing", "no transcript for this session")
    return FileResponse(path, filename="%s.%s" % (sid[:8], format),
                        media_type="application/octet-stream")


@router.get("/api/sessions/{sid}/preview")
async def session_preview(sid: str, user=Depends(authz.perm('recording.view', host='sid'))):
    """Coada recentă a transcriptului (pentru previzualizare read-only în UI),
    fără secvențele de alt-screen care ar goli ecranul."""
    if not await db.fetchone("SELECT id FROM sessions WHERE id=?", sid):
        raise ApiError(404, "session.missing", "no such session")
    await stepup.require_session_host_stepup(sid, user)
    data = await asyncio.to_thread(core.read_tail, sid, limit=32 * 1024)
    return Response(content=data, media_type="application/octet-stream")


# ---------------------------------------------------------------------------
# Link-uri de replay (3.5.12): înregistrarea unei sesiuni ÎNCHISE, partajată public, doar-citire
# ---------------------------------------------------------------------------
# Modelul de securitate e cel al share-urilor live, cu câteva strângeri:
#   * tokenul: 256 de biţi (`security.new_token`), stocat DOAR ca sha256 — URL-ul se arată o
#     singură dată, la creare; în listă nu există nici token, nici URL;
#   * tokenul călătoreşte în FRAGMENTUL paginii (`/#/replay/<token>`, nu ajunge la server la
#     încărcare) şi în antetul `X-Replay-Token` la API — nu în cale, deci nu în jurnalul de
#     acces al unui proxy şi nici în `audit_log.path`;
#   * expirare obligatorie (1 h / 24 h / 7 zile), revocare per link / toate, plus pe căile pe
#     care mor share-urile (schimbare de parolă, ştergere de cont, „Revocă tot");
#   * crearea: doar din browser (`require_user`, cookie), cu step-up pe hosturile 2FA — aceeaşi
#     poartă ca citirea transcriptului; doar sesiuni ÎNCHISE (o sesiune vie încă scrie);
#   * public: 404 IDENTIC pentru necunoscut / expirat / revocat / sesiune ştearsă (fără oracol),
#     limită de rată per IP, `Cache-Control: no-store`, `X-Robots-Tag: noindex`;
#   * fiecare deschidere: rând în audit_log (IP prin `client_ip`, user-agent trunchiat), contor +
#     „ultima deschidere" în listă, alertă în aplicaţie către cel care a creat link-ul (cel mult
#     una per link la 10 minute).

_REPLAY_HEADERS = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow",
                   "Referrer-Policy": "no-referrer"}
_LABEL_BAD = re.compile(r"[\x00-\x1f\x7f  ‪-‮⁦-⁩]")


class ReplayLinkIn(BaseModel):
    expires_hours: int = replay.DEFAULT_EXPIRY_HOURS
    label: str = ""
    redact: bool = True               # „ascunde secretele probabile" — implicit PORNIT
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


def _replay_link_json(r) -> dict:
    return {"id": r["id"], "sid": r["sid"], "title": r["title"] or "",
            "host_id": r["host_id"], "host_name": r["host_name"] or "",
            "label": r["label"] or "", "redact": bool(r["redact"]),
            "created": r["created"], "expires": r["expires"],
            "opens": r["open_count"] or 0, "last_opened": r["last_opened"],
            "last_ip": r["last_ip"] or ""}


@router.post("/api/sessions/{sid}/replay-links")
async def create_replay_link(sid: str, request: Request, body: ReplayLinkIn = ReplayLinkIn(),
                             user=Depends(authz.perm('share.replay', host='sid'))):
    """Link public, doar-citire, către ÎNREGISTRAREA unei sesiuni închise. URL-ul (cu tokenul)
    se întoarce o singură dată, aici."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    row = await db.fetchone("SELECT id, host_id, state, title FROM sessions WHERE id=?", sid)
    if not row:
        raise ApiError(404, "session.missing", "no such session")
    # 3.6: înregistrarea ALTCUIVA nu se publică fără session.manage pe host
    await _require_session_control(request, sid, user)
    # aceeaşi poartă ca GET /transcript: pe un host 2FA, a scoate înregistrarea din instanţă
    # (şi încă printr-un link fără cont) cere al doilea factor
    await stepup.require_host_stepup(row["host_id"], user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    if row["state"] != "closed":
        raise ApiError(409, "replay.notClosed",
                       "only the recording of a closed session can be shared")
    _, cast_path = core.transcript_paths(sid)
    if not cast_path.exists():
        raise ApiError(404, "transcript.missing", "no transcript for this session")
    if body.expires_hours not in replay.EXPIRY_HOURS:
        raise ApiError(400, "replay.badExpiry", "expiry must be 1 hour, 24 hours or 7 days")
    label = _LABEL_BAD.sub("", body.label or "").strip()[:replay.LABEL_MAX]
    now = time.time()
    await shares.delete_replay_links(" WHERE expires <= ?", now)
    mine = await db.fetchone("SELECT COUNT(*) AS c FROM replay_links WHERE user_id=?", user["id"])
    here = await db.fetchone("SELECT COUNT(*) AS c FROM replay_links WHERE user_id=? AND sid=?",
                             user["id"], sid)
    if mine["c"] >= replay.MAX_ACTIVE_PER_USER or here["c"] >= replay.MAX_ACTIVE_PER_SESSION:
        raise ApiError(409, "replay.tooMany",
                       "too many active replay links — revoke some first")
    token = security.new_token()
    expires = now + body.expires_hours * 3600
    link_id = await db.execute(
        "INSERT INTO replay_links(token_hash, sid, user_id, label, redact, created, expires)"
        " VALUES(?,?,?,?,?,?,?)",
        security.sha256_hex(token), sid, user["id"], label, 1 if body.redact else 0, now, expires)
    audit.detail(request, "replay link #%d for %s (%dh, %s)%s" % (
        link_id, sid[:8], body.expires_hours, "masked" if body.redact else "UNMASKED",
        (" label=%r" % label) if label else ""))
    email_alerts.notify_replay_created(row["title"] or "", label, body.expires_hours,
                                       bool(body.redact), security.client_ip(request),
                                       user["email"], user_id=user["id"])
    return {"id": link_id, "url": f"{config.PUBLIC_URL}/#/replay/{token}", "sid": sid,
            "label": label, "redact": bool(body.redact), "created": now, "expires": expires}


@router.get("/api/replay-links")
async def list_replay_links(sid: str = "", user=Depends(security.require_user)):
    """Link-urile de replay ACTIVE ale contului (nu ale altora) — fără token şi fără URL.
    Pe un host 2FA, rândul apare doar cu fereastra de step-up deschisă (ca lista de share-uri:
    titlul sesiunii e conţinut); restul se NUMĂRĂ în `hidden`."""
    now = time.time()
    await shares.delete_replay_links(" WHERE expires <= ?", now)
    sql = ("SELECT r.*, s.title, s.host_id, h.name AS host_name, h.require_2fa"
           " FROM replay_links r LEFT JOIN sessions s ON s.id = r.sid"
           " LEFT JOIN hosts h ON h.id = s.host_id WHERE r.user_id=? AND r.expires > ?")
    args: list = [user["id"], now]
    if sid:
        sql += " AND r.sid=?"
        args.append(sid)
    rows = await db.fetchall(sql + " ORDER BY r.created DESC", *args)
    # 3.6: un link al tău pe un host pe care nu-l mai vezi nu se arată (nici nu se numără);
    # oricum a fost revocat la schimbarea rolului (`shares.revoke_unauthorized_derived`)
    vis = await authz.visible_hosts(await authz.grants_for_user(user["id"]), "host.view")
    out, hidden = [], 0
    for r in rows:
        if r["host_id"] is not None and not authz.in_visible(vis, r["host_id"]):
            continue
        if r["require_2fa"] and not security.stepup_window_is_open(user["id"], r["host_id"]):
            hidden += 1
            continue
        out.append(_replay_link_json(r))
    return {"links": out, "hidden": hidden}


@router.delete("/api/replay-links/{link_id}")
async def revoke_replay_link(link_id: int, request: Request, user=Depends(authz.perm('share.replay', host='link_id'))):
    row = await db.fetchone(
        "SELECT r.id, r.sid, s.host_id FROM replay_links r LEFT JOIN sessions s ON s.id = r.sid"
        " WHERE r.id=? AND r.user_id=?", link_id, user["id"])
    if not row:
        # al altui cont = la fel de inexistent ca unul şters: nicio confirmare a id-ului
        raise ApiError(404, "replay.missing", "no such replay link")
    if row["host_id"]:
        await stepup.require_host_stepup(row["host_id"], user)   # simetric cu crearea (H1)
    await shares.delete_replay_links(" WHERE id=?", link_id)
    audit.detail(request, "replay link #%d for %s revoked" % (link_id, row["sid"][:8]))
    return {"ok": True}


@router.post("/api/replay-links/revoke-all")
async def revoke_all_replay_links(request: Request, user=Depends(security.require_user)):
    """Toate link-urile de replay ale CONTULUI. Fără re-autentificare: revocarea doar reduce
    accesul, iar link-urile altor conturi nu sunt atinse (butonul global e /api/shares/revoke-all)."""
    n = await shares.revoke_replay_links(user["id"])
    audit.detail(request, "all own replay links revoked (%d active)" % n)
    return {"ok": True, "revoked": n}


async def _replay_lookup(request: Request):
    """Rezolvă tokenul din antet la (link, sesiune). ORICE eşec → acelaşi 404 (necunoscut,
    expirat, revocat, sesiune ştearsă/neînchisă, înregistrare dispărută) — şi se numără la
    limita de rată, ca un scanner să fie oprit devreme."""
    ip = security.client_ip(request)
    retry = replay.gate(ip)
    if retry:
        raise ApiError(429, "replay.rateLimited", "too many requests; retry in %ds" % retry,
                       headers={**_REPLAY_HEADERS, "Retry-After": str(retry)},
                       vars={"retry": retry})
    token = request.headers.get("x-replay-token") or ""
    row = None
    if 20 <= len(token) <= 128:
        h = security.sha256_hex(token)
        row = await db.fetchone(
            "SELECT r.*, s.title, s.state, s.created AS s_created, s.closed_at, s.rows, s.cols,"
            " u.email AS owner_email"
            " FROM replay_links r JOIN sessions s ON s.id = r.sid"
            " LEFT JOIN users u ON u.id = r.user_id"
            " WHERE r.token_hash=? AND r.expires > ?", h, time.time())
        if row is not None and not security.tokens_equal(row["token_hash"], h):
            row = None
    if row is not None:
        if row["state"] != "closed" or not core.valid_sid(row["sid"]) \
                or not core.transcript_paths(row["sid"])[1].exists():
            row = None
    if row is None:
        replay.record_miss(ip)
        raise ApiError(404, "link.invalid", "invalid or expired link", headers=_REPLAY_HEADERS)
    return row


async def _replay_opened(request: Request, row, what: str) -> None:
    """Contabilizează o deschidere: contor + ultima deschidere, jurnalul per link (ultimele
    OPENS_KEPT), un rând în audit_log (prin middleware: actor = link-ul, IP = client_ip) şi
    alerta în aplicaţie către cel care l-a creat (throttle per link)."""
    ip = security.client_ip(request)
    ua = (request.headers.get("user-agent") or "")[:160]
    now = time.time()
    await db.execute("UPDATE replay_links SET open_count=open_count+1, last_opened=?, last_ip=?"
                     " WHERE id=?", now, ip[:64], row["id"])
    await db.execute("INSERT INTO replay_opens(link_id, ts, ip, user_agent) VALUES(?,?,?,?)",
                     row["id"], now, ip[:64], ua)
    await db.execute(
        "DELETE FROM replay_opens WHERE link_id=? AND id <= COALESCE((SELECT id FROM replay_opens"
        " WHERE link_id=? ORDER BY id DESC LIMIT 1 OFFSET ?), -1)",
        row["id"], row["id"], replay.OPENS_KEPT)
    audit.actor(request, "replay-link #%d" % row["id"])
    audit.detail(request, "replay %s of %s via link #%d%s · ua=%s" % (
        what, row["sid"][:8], row["id"], (" (%s)" % row["label"]) if row["label"] else "", ua))
    if row["owner_email"]:
        email_alerts.notify_replay_opened(row["id"], row["title"] or "", row["label"] or "",
                                          ip, ua, row["owner_email"], user_id=row["user_id"])


@router.get("/api/replay/meta")
async def replay_meta(request: Request):
    """Public (tokenul din `X-Replay-Token` E credenţialul): ce îi trebuie paginii de replay ca
    să se aşeze — titlu, eticheta link-ului, momentele sesiunii, dacă e mascată. Nimic despre
    host, cont sau alte sesiuni. Nu se numără ca deschidere (nu scoate conţinut)."""
    row = await _replay_lookup(request)
    wm = await _public_watermark(row["owner_email"] or "", row["title"])
    return Response(content=json.dumps({
        "title": row["title"] or "", "label": row["label"] or "", "redact": bool(row["redact"]),
        "expires": row["expires"], "started": row["s_created"], "closed_at": row["closed_at"],
        "rows": row["rows"], "cols": row["cols"], "watermark": wm}),
        media_type="application/json", headers=_REPLAY_HEADERS)


@router.get("/api/replay/cast")
async def replay_cast(request: Request):
    """Public: înregistrarea (asciicast v2, formatul player-ului), mascată dacă link-ul o cere."""
    row = await _replay_lookup(request)
    _, cast_path = core.transcript_paths(row["sid"])
    try:
        if row["redact"]:
            data = await asyncio.to_thread(replay.redacted_cast_file, cast_path)
        else:
            data = await asyncio.to_thread(cast_path.read_bytes)
    except OSError:
        replay.record_miss(security.client_ip(request))
        raise ApiError(404, "link.invalid", "invalid or expired link", headers=_REPLAY_HEADERS)
    await _replay_opened(request, row, "played")
    return Response(content=data, media_type="application/octet-stream", headers=_REPLAY_HEADERS)


@router.get("/api/replay/text")
async def replay_text(request: Request):
    """Public: vizualizarea TEXT (fără secvenţe de control, coada de 2 MB), mascată la fel."""
    row = await _replay_lookup(request)
    text = await asyncio.to_thread(core.transcript_text, row["sid"], TEXT_VIEW_TAIL)
    if row["redact"]:
        text = await asyncio.to_thread(replay.mask_secrets, text)
    await _replay_opened(request, row, "read as text")
    return Response(content=text, media_type="text/plain; charset=utf-8", headers=_REPLAY_HEADERS)


# ---------------------------------------------------------------------------
# Agent install (public: token-in-URL bootstrap)
# ---------------------------------------------------------------------------

# Unit-ul systemd din script are `KillMode=process` (audit 2026-10-04, HIGH #2): serverul tmux
# e pornit de un copil al agentului, deci moşteneşte cgroup-ul unităţii, iar implicitul
# `control-group` îl omora la ORICE stop/restart/watchdog — adică exact invariantul
# „sesiunile supravieţuiesc agentului" din docs/design/ARCHITECTURE.md ţinea doar pe cron.
# Scriptul rescrie unit-ul necondiţionat la fiecare rulare, deci un re-run al instalării
# vindecă şi hosturile vechi (agentul îşi repară singur unit-ul la pornire, separat).
# Fără `TimeoutStopSec`: cu `process` systemd aşteaptă doar PID-ul principal, nu tmux-ul.
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

# ── Python (3.6.9) ──────────────────────────────────────────────────────────────────────────
# The agent needs Python 3.6+. On 3.5 (Ubuntu 16.04, Debian 9) it would connect and run terminals,
# but every file operation — the Files panel, uploads, downloads — fails. A host whose python3 is
# missing or too old gets a PORTABLE Python (python-build-standalone {pyrt_python}, pinned by
# SHA-256, served by the gateway) in ~/.webterm/python/, owned by this user; the system python3 is
# left alone. Choices:
#   WEBTERM_PYTHON=/path/to/python3.x  use that interpreter (must be 3.6+)
#   --portable-python  (… | sh -s -- --portable-python)  or WEBTERM_PORTABLE_PYTHON=1: always portable
#   WEBTERM_ALLOW_OLD_PYTHON=1  keep an old python3 when no portable build fits (terminals only)
PORTABLE=0
[ "${{WEBTERM_PORTABLE_PYTHON:-0}}" = "1" ] && PORTABLE=1
for a in "$@"; do [ "$a" = "--portable-python" ] && PORTABLE=1; done
PYRT_DIR="$HOME/.webterm/python"
PY="${{WEBTERM_PYTHON:-$(command -v python3 2>/dev/null || true)}}"
py_ok() {{ [ -n "$1" ] && [ -x "$1" ] && "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' >/dev/null 2>&1; }}
PYV="none"
[ -n "$PY" ] && [ -x "$PY" ] && PYV=$("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo unknown)
if [ -n "${{WEBTERM_PYTHON:-}}" ] && ! py_ok "$PY"; then
  echo "ERROR: WEBTERM_PYTHON=$WEBTERM_PYTHON is not a Python 3.6+ interpreter (found: $PYV)."
  echo "       Nothing was installed."
  exit 1
fi

# The interpreter and agent paths go into the systemd unit and the crontab: absolute, and only
# characters that need no escaping there (no quotes, backslash, `$`, `%`, control characters).
path_ok() {{
  case "$1" in /*) ;; *) return 1 ;; esac
  case "$1" in *[!A-Za-z0-9._/+@=:,\ -]*) return 1 ;; esac
  return 0
}}
# Installed as ROOT, the agent runs the interpreter as root at every start: whoever can write it,
# or any folder above it, gets root. Every component (the path as given AND as resolved) must be
# owned by root and not group/world-writable. Prints why not; 2 = cannot check (no stat -c).
root_chain_ok() {{
  p=$1
  while :; do
    st=$(stat -c '%u %a %F' -- "$p" 2>/dev/null) || {{ command -v stat >/dev/null 2>&1 || return 2; echo "$p cannot be inspected"; return 1; }}
    o=${{st%% *}}; r=${{st#* }}; m=${{r%% *}}; ft=${{r#* }}
    [ "$o" = 0 ] || {{ echo "$p is owned by uid $o, not root"; return 1; }}
    # a sticky folder above (/tmp, 1777) is fine: nobody else may rename or delete the root-owned
    # entry in it, and that entry is checked on the previous round
    if [ "$ft" != "symbolic link" ] && [ $(( 0$m & 022 )) -ne 0 ] \
       && ! {{ [ "$ft" = directory ] && [ "$p" != "$1" ] && [ $(( 0$m & 01000 )) -ne 0 ]; }}; then
      echo "$p is group- or world-writable (mode $m)"; return 1
    fi
    [ "$p" = / ] && return 0
    p=${{p%/*}}; [ -n "$p" ] || p=/
  done
}}
check_root_python() {{
  [ "$(id -u)" = 0 ] || return 0
  RP=$(readlink -f -- "$1" 2>/dev/null || true)
  for c in "$1" "$RP"; do
    [ -n "$c" ] || continue
    if WHYNOT=$(root_chain_ok "$c"); then rc=0; else rc=$?; fi
    if [ "$rc" = 2 ]; then
      echo "WARNING: installing as ROOT, and this host has no 'stat -c' to check that $1 and its folders"
      echo "         are owned by root and not writable by others. Check it yourself: whoever can write"
      echo "         the interpreter or a folder above it gets root through the agent."
      return 0
    elif [ "$rc" != 0 ]; then
      echo "ERROR: installing as ROOT, but the interpreter $1 is not safe to run as root: $WHYNOT."
      echo "       Whoever can write it (or a folder above it) would get root through the agent."
      echo "       Use a root-owned interpreter (e.g. /usr/bin/python3) or install as a dedicated user."
      echo "       Nothing was installed."
      exit 1
    fi
  done
}}
if [ -n "${{WEBTERM_PYTHON:-}}" ]; then
  if ! path_ok "$PY"; then
    echo "ERROR: WEBTERM_PYTHON must be an absolute path made of plain characters (letters, digits,"
    echo "       space and ._/+@=:,-): it is written into the service file and the crontab. Got: $PY"
    echo "       Nothing was installed."
    exit 1
  fi
fi
NEED_PORTABLE=0
if [ "$PORTABLE" = 1 ] || ! py_ok "$PY"; then NEED_PORTABLE=1; fi

# The pinned builds: target → file + SHA-256 (from the gateway's pyruntime.json)
pyrt_file() {{ case "$1" in
{pyrt_files}
  *) return 1 ;; esac; }}
pyrt_sha() {{ case "$1" in
{pyrt_shas}
  *) return 1 ;; esac; }}

PYRT_TARGET=""
if [ "$NEED_PORTABLE" = 1 ]; then
  M=$(uname -m 2>/dev/null || echo unknown)
  LIBC=gnu
  if ldd --version 2>&1 | grep -qi musl || ls /lib/ld-musl-* >/dev/null 2>&1; then LIBC=musl; fi
  case "$M" in
    x86_64|amd64) A=x86_64 ;;
    aarch64|arm64) A=aarch64 ;;
    armv7l|armv7|armv7hl) A=armv7 ;;
    *) A="" ;;
  esac
  case "$A-$LIBC" in
    x86_64-gnu|aarch64-gnu|x86_64-musl|aarch64-musl) PYRT_TARGET="$A-$LIBC" ;;
    armv7-gnu) PYRT_TARGET="armv7-gnueabihf" ;;
  esac
  WHY="python3 is missing"
  [ "$PYV" != "none" ] && WHY="python3 is $PYV (the agent needs 3.6+)"
  [ "$PORTABLE" = 1 ] && WHY="--portable-python was asked for"
  REFUSE=""
  if [ -z "$PYRT_TARGET" ]; then
    REFUSE="there is no portable Python for this machine ($M, $LIBC libc)"
  elif [ "$LIBC" = gnu ]; then
    GLIBC=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{{print $2}}')
    [ -n "$GLIBC" ] || GLIBC=$(ldd --version 2>/dev/null | head -n1 | awk '{{print $NF}}')
    if ! printf '%s\n' "$GLIBC" | awk -F. '{{ exit !(($1 > 2) || ($1 == 2 && $2 >= {pyrt_glibc_minor})) }}'; then
      REFUSE="glibc ${{GLIBC:-unknown}} is older than {pyrt_glibc} (the portable Python's minimum)"
    fi
  fi
  if [ -n "$REFUSE" ]; then
    if py_ok "$PY"; then
      echo "NOTE: --portable-python: $REFUSE — using $PY (Python $PYV) instead."
      NEED_PORTABLE=0
    elif [ "$PYV" != "none" ] && [ "${{WEBTERM_ALLOW_OLD_PYTHON:-0}}" = "1" ]; then
      echo "WARNING: $WHY and $REFUSE. Continuing with Python $PYV (WEBTERM_ALLOW_OLD_PYTHON=1):"
      echo "         terminals will work, the Files panel and uploads will NOT."
      NEED_PORTABLE=0
    else
      echo "ERROR: $WHY, and $REFUSE."
      echo "       Install Python 3.6 or newer next to the system one, then re-run the install command"
      echo "       with it:   ... | WEBTERM_PYTHON=/path/to/python3.x sh"
      [ "$PYV" != "none" ] && echo "       Terminals only, knowingly:  ... | WEBTERM_ALLOW_OLD_PYTHON=1 sh"
      echo "       Details: {docs_hosts}"
      echo "       Nothing was installed."
      exit 1
    fi
  else
    echo "Python: $WHY → installing a portable Python {pyrt_python} ($PYRT_TARGET) in $PYRT_DIR"
  fi
fi

# The agent runs with the rights of whoever installs it: it never asks for root and never
# escalates. Installed as root, WebTerm becomes a root shell on this host — convenient, but a
# compromise of the gateway or of your account then owns the machine. Prefer a dedicated user
# (`useradd -m webterm && su - webterm`), with sudo only where you genuinely need it.
[ "$(id -u)" = 0 ] && echo "WARNING: you are installing the agent as ROOT — it will have root on this host. Prefer a dedicated user."
command -v tmux >/dev/null 2>&1 || echo "WARNING: tmux is missing — sessions will not survive an agent restart. Install it (apt install tmux / yum install tmux)."

if ! path_ok "$HOME/.webterm/ptyd.py"; then
  echo "ERROR: the home folder $HOME has characters that cannot be written safely into the service"
  echo "       file and the crontab (quotes, backslash, \$, %, control characters). Nothing was installed."
  exit 1
fi
if [ "$NEED_PORTABLE" = 0 ]; then
  if ! path_ok "$PY"; then
    echo "ERROR: the interpreter path $PY has characters that cannot be written safely into the service"
    echo "       file and the crontab. Point WEBTERM_PYTHON at a plain path. Nothing was installed."
    exit 1
  fi
  check_root_python "$PY"
fi

mkdir -p "$HOME/.webterm" && chmod 700 "$HOME/.webterm"

if [ "$NEED_PORTABLE" = 1 ]; then
  # Fetched from the gateway with this host's token, checked against the SHA-256 pinned in this
  # script, listed BEFORE extraction (no absolute paths, no `..`, every symlink stays inside the
  # tree), extracted into a fresh temp dir and moved into place. Nothing runs as root.
  PYRT_FILE=$(pyrt_file "$PYRT_TARGET"); PYRT_SHA=$(pyrt_sha "$PYRT_TARGET")
  T=$(mktemp -d "$HOME/.webterm/.pyrt.XXXXXX") || {{ echo "ERROR: cannot create a temp dir in ~/.webterm"; exit 1; }}
  trap 'rm -rf "$T"' EXIT
  umask 077
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > "$T/curlrc"
  printf 'header = Authorization: Bearer %s\n' "$TOKEN" > "$T/wgetrc"
  umask 022
  # The token goes in a 0600 file, never on the command line (/proc/*/cmdline is readable by every
  # user). curl reads it with -K, GNU wget from WGETRC. BusyBox wget (minimal Alpine) ignores
  # WGETRC and only takes --header on argv — so without curl or GNU wget we stop and say so.
  if command -v curl >/dev/null 2>&1; then
    PYRT_GET=curl
  elif wget --version 2>/dev/null | grep -q "GNU Wget"; then
    PYRT_GET=wget
  else
    echo "ERROR: downloading the portable Python needs curl (or GNU wget). This wget (BusyBox?) can"
    echo "       send the host's token only on its command line, where other users of this machine"
    echo "       could read it. Install curl and run the install command again:"
    echo "          apk add curl        (Alpine)"
    echo "          apt install curl    (Debian/Ubuntu)"
    echo "       Nothing was installed."
    exit 1
  fi
  if [ "$PYRT_GET" = curl ]; then
    $CURL -K "$T/curlrc" "$GW/agent/python/$PYRT_TARGET.tar.gz" -o "$T/py.tgz"
  else
    WGETRC="$T/wgetrc" $CURL "$GW/agent/python/$PYRT_TARGET.tar.gz" -O "$T/py.tgz"
  fi || {{ echo "ERROR: the portable Python could not be downloaded from the gateway (see its log)."; exit 1; }}
  rm -f "$T/curlrc" "$T/wgetrc"
  GOT=$(sha256sum "$T/py.tgz" 2>/dev/null | cut -d" " -f1)
  [ -n "$GOT" ] || GOT=$(shasum -a 256 "$T/py.tgz" 2>/dev/null | cut -d" " -f1)
  if [ "$GOT" != "$PYRT_SHA" ]; then
    echo "ERROR: the portable Python does not match its pinned SHA-256 — refused, nothing installed." >&2
    echo "  expected $PYRT_SHA" >&2
    echo "  got      ${{GOT:-<no sha256sum/shasum on this host>}}" >&2
    exit 1
  fi
  # names: all under python/, none absolute, no `..` component
  tar tzf "$T/py.tgz" > "$T/names" || {{ echo "ERROR: the portable Python archive cannot be read."; exit 1; }}
  if grep -v '^python/' "$T/names" | grep -q . || grep -Eq '(^|/)\.\.(/|$)' "$T/names"; then
    echo "ERROR: the portable Python archive has entries outside python/ — refused." >&2; exit 1
  fi
  # entry types: files, dirs, symlinks only; every symlink target resolves inside python/
  tar tzvf "$T/py.tgz" > "$T/long" || exit 1
  if ! awk '
    {{ t = substr($1, 1, 1) }}
    t != "-" && t != "d" && t != "l" {{ print "unexpected entry type: " $0; bad = 1; next }}
    t == "l" {{
      i = index($0, " -> "); if (!i) {{ print "unparsable link: " $0; bad = 1; next }}
      tgt = substr($0, i + 4); pre = substr($0, 1, i - 1); n = split(pre, w, " "); name = w[n]
      if (substr(tgt, 1, 1) == "/") {{ print "absolute link: " name; bad = 1; next }}
      k = split(name, p, "/"); depth = 0
      for (j = 1; j < k; j++) if (p[j] != "" && p[j] != ".") st[++depth] = p[j]
      m = split(tgt, q, "/")
      for (j = 1; j <= m; j++) {{
        if (q[j] == "" || q[j] == ".") continue
        if (q[j] == "..") {{ if (depth <= 1) {{ print "link escapes: " name " -> " tgt; bad = 1; break }} depth-- }}
        else st[++depth] = q[j]
      }}
    }}
    END {{ exit bad }}' "$T/long"; then
    echo "ERROR: the portable Python archive has unsafe entries — refused." >&2; exit 1
  fi
  # -o (--no-same-owner): as root, GNU tar would otherwise keep the archive's owners (uids of
  # the build machine) and modes; then nothing in the tree may be writable by group/others, and
  # as root it all belongs to root (the agent runs this interpreter as root at every start).
  mkdir "$T/x" && (cd "$T/x" && tar xzof ../py.tgz) || {{ echo "ERROR: extracting the portable Python failed."; exit 1; }}
  if [ "$(id -u)" = 0 ]; then
    chown -hR 0:0 "$T/x/python" || {{ echo "ERROR: cannot give the portable Python to root."; exit 1; }}
  fi
  chmod -R go-w "$T/x/python" || {{ echo "ERROR: cannot tighten the portable Python's permissions."; exit 1; }}
  if ! py_ok "$T/x/python/bin/python3"; then
    echo "ERROR: the portable Python does not run on this machine (libc/CPU?) — nothing installed."; exit 1
  fi
  rm -rf "$PYRT_DIR.old"
  [ -e "$PYRT_DIR" ] && mv "$PYRT_DIR" "$PYRT_DIR.old"
  mv "$T/x/python" "$PYRT_DIR" && rm -rf "$PYRT_DIR.old"
  rm -rf "$T"; trap - EXIT
  PY="$PYRT_DIR/bin/python3"
  if ! path_ok "$PY"; then
    echo "ERROR: the portable Python's path $PY cannot be written safely into the service file."; exit 1
  fi
  check_root_python "$PY"
  echo "Python: installed $("$PY" -c 'import sys; print(sys.version.split()[0])') in $PYRT_DIR"
  echo "        from $PYRT_FILE (sha256 verified: $PYRT_SHA);"
  echo "        the agent will run with $PY. The system python3 was not touched."
fi

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
  # Întărire OPŢIONALĂ (NU implicit): WEBTERM_AGENT_HARDENED=1 la instalare adaugă
  # NoNewPrivileges=true în unit. ATENŢIE: asta blochează escaladarea prin binare setuid, deci
  # `sudo` NU mai merge ÎN SESIUNI — butonul de OS-upgrade şi fallback-ul docker-sudo pică. Nu
  # forţăm nimic altceva (ProtectSystem=strict / ProtectHome / SystemCallFilter ar rupe browsing-ul
  # de fişiere din home şi shell-urile arbitrare pe care agentul le rulează intenţionat ca userul
  # lui). Operatorul optează conştient; implicitul rămâne ca azi (fără NoNewPrivileges).
  HARDENING=""
  if [ "${{WEBTERM_AGENT_HARDENED:-}}" = "1" ]; then
    HARDENING="# Hardening opt-in (WEBTERM_AGENT_HARDENED=1): blochează escaladarea prin setuid.
# Efect secundar INTENŢIONAT: sudo nu mai funcţionează în sesiuni → OS-upgrade + docker-sudo pică.
NoNewPrivileges=true"
  fi
  # Unit-ul are o COPIE în agent (agent/ptyd.py, `_UNIT_TEMPLATE`), folosită când operatorul
  # activează pornirea la boot din UI (op-ul `autostart`). Ţine-le SEMANTIC în sincron.
  cat > "$HOME/.config/systemd/user/webterm-agent.service" <<UNIT
[Unit]
Description=WebTerm agent (ptyd)
After=network-online.target

[Service]
Type=simple
ExecStart="$PY" "$AGENT" run
Restart=always
RestartSec=3
# KillMode=process: the tmux server that HOLDS the sessions is started by a child of the agent,
# so it lives in this unit's cgroup. The default (control-group) would kill it on every
# stop/restart/watchdog kill of the agent — i.e. every session on the host would die on an
# agent crash or a `systemctl --user restart`. With `process` systemd stops only the agent;
# tmux keeps running and the restarted agent re-adopts the sessions.
KillMode=process
# Watchdog: if the agent's event loop blocks and stops sending WATCHDOG=1 within this
# interval, systemd kills and restarts it (complementary to the G1 liveness check over
# cron, which does not run under systemd). The agent pings at about half the interval.
WatchdogSec=45
$HARDENING

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
  # (aceleaşi linii şi în agent: agent/ptyd.py `_cron_lines`, pentru comutarea din UI)
  ( crontab -l 2>/dev/null | grep -v 'webterm/ptyd.py' | grep -v 'webterm-watchdog' ; \
    echo "@reboot '$PY' '$AGENT' start # webterm" ; \
    echo "* * * * * '$PY' '$AGENT' start # webterm-watchdog" ) | crontab - && SUP="cron"
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


def _pyrt_script_fields() -> dict:
    """The portable-Python part of the install script, from the pinned manifest (pyruntime.json):
    shell `case` arms target → file / SHA-256. Every value passed the manifest's strict regexes
    (pyruntime.load_manifest), so nothing here needs shell quoting beyond the double quotes."""
    m = pyruntime.MANIFEST
    tg = m["targets"]
    files = "\n".join('  %s) echo "%s" ;;' % (k, t["file"]) for k, t in sorted(tg.items()))
    shas = "\n".join('  %s) echo "%s" ;;' % (k, t["sha256"]) for k, t in sorted(tg.items()))
    g = str(m.get("min_glibc") or "2.17")
    minor = g.split(".")[1] if re.match(r"^2\.[0-9]{1,3}$", g) else "17"
    return {"pyrt_files": files or "  none) return 1 ;;", "pyrt_shas": shas or "  none) return 1 ;;",
            "pyrt_python": re.sub(r"[^0-9.]", "", str(m.get("python") or "")) or "3",
            "pyrt_glibc": "2." + minor, "pyrt_glibc_minor": minor,
            "docs_hosts": DOCS_SUPPORTED_HOSTS}


DOCS_SUPPORTED_HOSTS = "https://github.com/sm26449/webterm/blob/main/docs/INSTALL.md#supported-hosts"


def _install_script_for(token: str) -> str:
    """Corpul scriptului de instalare pentru un token de agent permanent (comun între enroll-ul
    per-host şi cel de grup)."""
    return INSTALL_SCRIPT.format(
        public_url=config.PUBLIC_URL, ws_url=config.ws_public_url(),
        token=token, insecure="true" if config.AGENT_INSECURE else "false",
        public_url_docs="https://github.com/sm26449/webterm#provisioning-a-server",
        integration_sha256=_shell_integration_digest(),
        **_pyrt_script_fields(),
        agent_sha256=_agent_digest(),
        ssl_ctx="ssl._create_unverified_context()" if config.AGENT_INSECURE else "None")


# ── [install] Installer endpoints ─────────────────────────────────────────────────────────────────

@router.get("/install/{enroll_token}", response_class=PlainTextResponse)
async def install_script(enroll_token: str, request: Request):
    enroll_token = enroll_token[:-3] if enroll_token.endswith(".sh") else enroll_token
    # Dacă hostul are o parolă de înrolare, o verificăm ÎNAINTE de revendicare (parola vine din
    # header, nu din URL — vezi hostmodel.install_command). Verificarea e SEPARATĂ de claim-ul single-use:
    # o parolă greşită NU consumă tokenul (altfel o singură greşeală ar omorî înrolarea), dar e
    # plafonată per-host, ca tokenul din URL să nu poată fi folosit ca oracol de brute-force pe parolă.
    probe = await db.fetchone(
        "SELECT * FROM hosts WHERE enroll_token=? AND enroll_expires>?", enroll_token, time.time())
    if not probe:
        raise ApiError(404, "enroll.invalid", "invalid or expired enroll token")
    if probe["enroll_pass_hash"]:
        key = "enroll:%d" % probe["id"]
        allowed, retry = security.login_allowed(key)
        if not allowed:
            raise ApiError(429, "enroll.tooMany", "too many wrong enroll passwords; retry in %ds" % retry)
        supplied = request.headers.get("x-enroll-pass", "")
        if not supplied or not await security.verify_password_async(supplied, probe["enroll_pass_hash"]):
            security.record_login_failure(key)
            raise ApiError(403, "enroll.badPass",
                           "this enrollment link needs its password (X-Enroll-Pass header)")
        security.record_login_success(key)
    # single-use, atomically: claim + invalidate the token in ONE serialized write so two
    # concurrent requests can't both be handed the permanent host token (TOCTOU). Only the winner
    # gets the row back. (Password already verified above; a race loser just gets 404.)
    row = await db.execute_returning(
        "UPDATE hosts SET enroll_token=NULL, enroll_expires=0, enroll_pass_hash=NULL "
        "WHERE enroll_token=? AND enroll_expires>? RETURNING *",
        enroll_token, time.time())
    if not row:
        raise ApiError(404, "enroll.invalid", "invalid or expired enroll token")
    return _install_script_for(security.decrypt_secret(row["token_encrypted"]))


@router.get("/install/group/{group_token}", response_class=PlainTextResponse)
async def group_install_script(group_token: str, request: Request):
    """Onboarding la scară: un token de grup rulat pe N maşini. La fiecare rulare AUTO-CREĂM un
    host nou cu PROPRIUL token permanent (revocabil individual — modelul per-host rămâne intact),
    apoi livrăm scriptul cu acel token. Tokenul de grup doar autorizează crearea."""
    group_token = group_token[:-3] if group_token.endswith(".sh") else group_token
    th = security.sha256_hex(group_token)
    # Dacă grupul are parolă, o verificăm ÎNAINTE de a consuma o utilizare (o greşeală n-ar trebui
    # să ardă un `uses`), plafonat per-grup ca tokenul din URL să nu fie oracol de brute-force.
    probe = await db.fetchone(
        "SELECT id, pass_hash FROM enroll_groups WHERE token_hash=? AND revoked=0 AND expires>?"
        " AND (max_uses=0 OR uses<max_uses)", th, time.time())
    if not probe:
        raise ApiError(404, "enroll.invalid", "invalid, expired, revoked or exhausted enroll token")
    if probe["pass_hash"]:
        key = "genroll:%d" % probe["id"]
        allowed, retry = security.login_allowed(key)
        if not allowed:
            raise ApiError(429, "enroll.tooMany", "too many wrong enroll passwords; retry in %ds" % retry)
        supplied = request.headers.get("x-enroll-pass", "")
        if not supplied or not await security.verify_password_async(supplied, probe["pass_hash"]):
            security.record_login_failure(key)
            raise ApiError(403, "enroll.badPass",
                           "this enrollment link needs its password (X-Enroll-Pass header)")
        security.record_login_success(key)
    # atomic, TOCTOU-safe ca la per-host: verificăm valid + incrementăm `uses` într-o SINGURĂ
    # scriere serializată, ca două instalări concurente să nu poată trece amândouă de un max_uses=1.
    grp = await db.execute_returning(
        "UPDATE enroll_groups SET uses = uses + 1 "
        "WHERE token_hash=? AND revoked=0 AND expires>? AND (max_uses=0 OR uses<max_uses) "
        "RETURNING *", th, time.time())
    if not grp:
        raise ApiError(404, "enroll.invalid", "invalid, expired, revoked or exhausted enroll token")
    # host nou cu token PROPRIU; numele e placeholder până raportează agentul hostname-ul (name_auto)
    token = security.new_token()
    host_id = await db.execute(
        "INSERT INTO hosts(name, note, folder, token_hash, token_encrypted, created,"
        " connection_type, require_2fa, credential_policy, name_auto)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        "(enrolling…)", "", grp["folder"] or "", security.sha256_hex(token),
        security.encrypt_secret(token), time.time(), "agent", int(grp["require_2fa"]), "stored", 1)
    log.info("host #%d auto-enrolled via group token '%s' from %s",
             host_id, grp["name"], security.client_ip(request))
    await audit.record(time.time(), "group:" + grp["name"], security.client_ip(request), "POST",
                       "/install/group", 200, "host #%d auto-enrolled (group '%s')" % (host_id, grp["name"]))
    email_alerts.notify_host_enrolled(grp["name"], security.client_ip(request), host_id=host_id)
    return _install_script_for(token)


# ── [agent] Agent-facing HTTP: uninstall marker, portable Python, ptyd.py, shell integration ──────

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


@router.get("/agent/python/{target}")
async def agent_python_runtime(target: str, request: Request):
    """The pinned portable Python (pyruntime.py) for a host whose python3 is missing or < 3.6.
    Credential: the HOST's agent token (`Authorization: Bearer`), which the install script
    carries — not public, so the gateway is no anonymous download proxy. `target` is a key of the
    pinned manifest (`x86_64-gnu.tar.gz`…), never a name or URL. The file is fetched from the pinned
    release URL on first use, verified against its pinned SHA-256 and only then cached and served."""
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    row = await db.fetchone("SELECT id FROM hosts WHERE token_hash=?",
                            security.sha256_hex(token)) if token else None
    if not row:
        raise HTTPException(401, "invalid agent token")
    key = target[:-7] if target.endswith(".tar.gz") else target
    if not pyruntime.target(key):
        raise ApiError(404, "pyruntime.unknownTarget", "no portable Python for that target")
    try:
        path, t = await pyruntime.get(key)
    except pyruntime.RuntimeUnavailable as e:
        log.warning("portable python for host #%d (%s) unavailable: %s", row["id"], key, e)
        raise ApiError(503, e.code, "the portable Python is not available: %s" % e)
    log.info("portable python %s served to host #%d", t["file"], row["id"])
    return FileResponse(path, media_type="application/gzip", filename=t["file"],
                        headers={"X-Checksum-Sha256": t["sha256"]})


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

# ── [ws] /agent/ws — agent websocket ──────────────────────────────────────────────────────────────

@router.websocket("/agent/ws")
async def agent_ws(ws: WebSocket):
    auth = ws.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    row = await db.fetchone("SELECT * FROM hosts WHERE token_hash=?",
                            security.sha256_hex(token)) if token else None
    ip = security.client_ip_ws(ws)
    if not row:
        # Un `close()` înainte de `accept()` iese la agent ca „HTTP 403" — identic cu refuzul de
        # instanţă — iar aici nu rămânea NIMIC: nici log, nici eveniment. Omul vedea „Waiting for
        # the agent connection…" la nesfârşit (audit UX §1.2). Un token necunoscut n-are host, dar
        # omul care aşteaptă e pe un host care nu s-a conectat niciodată: acolo scriem evenimentul.
        if core.handshake_log_allowed("ip:" + ip):
            log.warning("agent handshake refused: unknown token from %s "
                        "(reinstall the agent with a fresh install link)", ip)
        for h in await core.hosts_awaiting_first_agent():
            await core.record_handshake_refusal(h["id"], "handshake_bad_token", ip)
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
        log.warning("host %s(%s): refusing agent from %s — instance %s (pinned %s). "
                    "Cloned image, shared token, or dropped fence header?",
                    row["name"], row["id"], ip,
                    (instance or "<none>")[:8], pinned[:8])
        await core.record_agent_event(row["id"], "disconnect", reason="instance_refused",
                                      detail="instance %s does not match the pinned one (cloned image / shared token?)"
                                             % (instance or "<none>")[:8])
        await core.record_handshake_refusal(row["id"], "handshake_instance_conflict", ip,
                                            detail="instance %s ≠ pinned %s"
                                                   % ((instance or "<none>")[:8], pinned[:8]))
        email_alerts.notify_agent_relocation(row["name"], (instance or "<none>")[:8], host_id=row["id"])
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
            await core.record_handshake_refusal(row["id"], "handshake_instance_conflict", ip,
                                                detail="pinning race: another instance won")
            email_alerts.notify_agent_relocation(row["name"], instance[:8], host_id=row["id"])
            await ws.close(code=4409)
            return
    # observabilitate IP: unde e văzut agentul (IP sursă prin proxy). IP-urile se schimbă legitim
    # (DHCP/reboot/NAT) → informativ, NU enforcement; jurnalizăm + alertăm DOAR la schimbare.
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
                email_alerts.notify_agent_ip_change(row["name"], row["agent_ip"], ip, host_id=row["id"])
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
    origin = ws.headers.get("origin")
    if origin is None:
        return False          # real browsers always send Origin for WS
    # Origin = scheme + host + port (RFC 6454). Comparam doar netloc-ul, deci o pagină servită
    # pe http://<acelaşi host> (MITM pe HTTP-ul simplu, alt serviciu pe portul 80 al aceluiaşi
    # nume) trecea drept „originul nostru" pe o instalare https. Porturile implicite se
    # normalizează (https://x == https://x:443).
    mine = security.origin_tuple(config.PUBLIC_URL)
    return mine is not None and security.origin_tuple(origin) == mine


async def _send_osc133(client, hub, span: Optional[dict]) -> None:
    """Starea OSC 133 a hub-ului, trimisă imediat după `hub.clients.add(client)` (3.6.13).

    Instantaneul se ia SINCRON cu adăugarea (fără await între ele): de aici încolo tot output-ul
    procesat de hub intră în coada clientului, deci `last` e exact starea de la care curge fluxul
    live spre el. Mesajul pleacă înaintea oricărui octet live — sender-ul porneşte abia după.
    `span` = None (replay netrimis / blocat): doar `integrated` + `last`, niciodată `synced`.
    Fără replay trimis (sesiune blocată) nu trimitem nimic: deblocarea face un resync, care
    îşi trimite propria stare (BrowserClient._resync)."""
    if span is None:
        return
    state = hub.osc133_state(span or None)       # {} = fereastra cozii nu e sigură → nesincronizat
    try:
        await client.send_text(json.dumps({"type": "osc133", **state}))
    except Exception:                    # noqa: BLE001 — socket închis: endpoint-ul face curăţenia
        pass


# ── [ws] /ws/shared/{token} — share-link guest websocket ──────────────────────────────────────────

@router.websocket("/ws/shared/{token}")
async def shared_ws(ws: WebSocket, token: str):
    """Vizitator prin link de share. `share_writable` → poate și TASTA (opt-in la
    creare); altfel doar vizualizare. Nu are cont — identitate „guest" în roster."""
    if not _origin_ok(ws):
        await ws.close(code=4403)
        return
    # 3.5.15: aceeaşi limită per IP ca /api/shared/{token} (aceeaşi găleată: o pagină de share
    # face o cerere meta + un WS, plus reconectări). 4429 = prea multe; ÎNAINTE de lookup, deci
    # un IP blocat nu mai află nimic — nici despre un token valid.
    ip = security.client_ip(ws)
    if replay.SHARE_LIMIT.gate(ip):
        await ws.close(code=4429)
        return
    row = None
    if 8 <= len(token) <= 128:
        row = await db.fetchone(
            "SELECT * FROM sessions WHERE share_token=? AND share_expires > ?",
            security.sha256_hex(token), time.time())
    if not row:
        replay.SHARE_LIMIT.record_miss(ip)
        await ws.close(code=4404)
        return
    # Linkul de share e o vedere LIVE. Pe o sesiune încheiată nu exista hub, deci poarta de
    # prezenţă/2FA de mai jos era sărită şi invitatul primea coada transcriptului — adică o
    # înregistrare publicată prin `share.live`, fără `recording.view`/`share.replay` şi fără
    # verificările lor (raport de securitate 2026-11, lot 1). Înregistrările au fluxul lor de replay.
    # O sesiune `lost` care revine `live` (reconciliere după restart) redevine accesibilă.
    if row["state"] not in ("creating", "live"):
        await ws.close(code=4404)
        return
    await ws.accept()
    writable = bool(row["share_writable"])
    hub = core.get_or_create_hub(row)
    client = core.BrowserClient(ws, hub)
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
    share_2fa = False
    if hub:
        hrow2 = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", row["host_id"])
        if hrow2 and hrow2["require_2fa"]:
            share_2fa = True
            hub.lock_idle = config.IDLE_LOCK_SECS
            hub.stepup_cap = True        # plafonul absolut de step-up blochează şi invitaţii
            # operator VERIFICAT (deblocat, poate scrie), nu orice client-owner — vezi has_operator
            start_locked = not hub.has_operator()
    # Aceeaşi politică de replay ca owner-ul (istoric tmux inclus), sub ACEEAŞI condiţie: fără
    # owner prezent pe un host 2FA, invitatul nu primeşte nimic din scrollback.
    sb, sb_rows = core.parse_replay_params(getattr(ws, "query_params", None) or {})
    if client:
        client.replay_limit = core.replay_tail_limit(sb, core.stream_is_plain(hub))
        client.replay_sb = sb             # resync-ul FULL (resume/unlock) readuce şi istoricul tmux
    osc_span: dict = {}
    replay_sent = False
    if not start_locked:
        replay_bytes = await core.attach_replay(row["id"], hub, sb, sb_rows, span=osc_span)
        if hub and (hub.locked or (share_2fa and not hub.has_operator())):
            start_locked = True          # blocată / owner plecat cât aşteptam agentul → nimic scurs
        else:
            await ws.send_bytes(replay_bytes)
            replay_sent = True
    if hub:
        # Blocat ÎNAINTE de a intra în hub: între `clients.add` şi sfârşitul ataşării sunt mai multe
        # await-uri (ensure_attached = drum la agent, audit, roster) în care `push` livra output-ul
        # live unui invitat încă nemarcat blocat (review lot 1, F1).
        if start_locked:
            client.lock()
        hub.clients.add(client)
        # re-verificat SINCRON cu adăugarea: operatorul poate pleca în timpul `send_bytes` de mai
        # sus, iar `sync_guests` din plecarea lui nu-l vedea încă pe acest invitat
        if share_2fa and not start_locked and not hub.has_operator():
            start_locked = True
            client.lock()
        await _send_osc133(client, hub, osc_span if replay_sent else None)
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
            await client.send_text(json.dumps({"type": "locked", "reason": hub.lock_reason or "owner"}))
        if share_2fa:
            # starea de ACUM, nu cea de la începutul ataşării: un operator sosit între timp îl
            # deblochează, unul plecat îl blochează
            await hub.sync_guests()

    # revalidare periodică: linkul de share poate fi REVOCAT sau poate EXPIRA cât invitatul e
    # conectat. Fără asta, socketul deschis (validat doar la handshake) continuă broadcast-ul.
    # (Revocarea activă via hub.revoke_shares() e instant; asta e plasa de siguranţă + expirarea.)
    async def _revalidate_share():
        while True:
            await asyncio.sleep(security.WS_REVALIDATE_SECS)
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


async def _fresh_user(user):
    """Rândul CURENT al contului. `browser_ws` îl citeşte o dată, la handshake — dar un terminal
    trăieşte ore: dacă omul îşi înrolează TOTP/passkey (sau îşi schimbă parola) cât e deschis,
    deblocarea trebuie să vadă factorii de ACUM, nu pe cei de la ataşare."""
    return (await db.fetchone("SELECT * FROM users WHERE id=?", user["id"])) or user


CERT_RENEW_ORIGIN = "cert-renew"
# 3.6.8: every session that types a ROOT command on the gateway host (cert renewal, System health
# fixes) is private: only its Owner types, others may watch, nobody can share it.
ROOT_TERMINAL_ORIGINS = frozenset({CERT_RENEW_ORIGIN, "health-fix"})


def _origin(row) -> str:
    return (row["origin"] if "origin" in row.keys() else "") or ""


async def _ws_access(user_id: int, row) -> str:
    """Ce poate contul pe sesiunea asta (3.6, §A.6.4 + Q5): 'rw' | 'ro' | 'replay' | 'none' |
    'hidden'. `hidden` = hostul nu e vizibil (răspunsul e identic cu o sesiune inexistentă).
      · rw     — `session.open` ŞI (sesiunea e a ta / pre-3.6 / ai `session.manage`)
      · ro     — sesiune VIE, cu `session.watch` (sau `session.open` pe sesiunea altcuiva)
      · replay — sesiune ÎNCHISĂ, cu `recording.view`"""
    have = await authz.perms_on(await authz.grants_for_user(user_id), row["host_id"])
    if "host.view" not in have:
        return "hidden"
    live = row["state"] in ("creating", "live")
    mine = row["created_by_id"] is None or row["created_by_id"] == user_id
    # 3.6.7 (security review F4): a certificate-renewal terminal runs `sudo` on the gateway host.
    # Only the Owner who opened it may type there — not an Admin with session.manage, who could
    # otherwise type into it right after the Owner entered the sudo password. Others may watch.
    if live and _origin(row) in ROOT_TERMINAL_ORIGINS and row["created_by_id"] != user_id:
        if "session.watch" in have or "session.open" in have:
            return "ro"
        return "none"
    if live:
        if "session.open" in have and (mine or "session.manage" in have):
            return "rw"
        if "session.watch" in have or "session.open" in have:
            return "ro"
        return "none"
    if "recording.view" in have:
        return "replay"
    return "none"


# ── [ws] /ws/sessions/{sid} — browser terminal websocket ──────────────────────────────────────────

@router.websocket("/ws/sessions/{sid}")
@authz.ws_perm(("session.open", "session.watch", "recording.view"), host="sid")
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
    # 3.6: autorizare ÎNAINTE de accept şi de orice replay. Host invizibil → 4404, exact ca o
    # sesiune inexistentă; vizibil dar fără drept → 4403. (Înainte de accept() ambele ajung la
    # client ca 403 de handshake — vezi nota de mai sus — deci nu scurg nimic.)
    access = await _ws_access(user["id"], row)
    if access in ("hidden", "none"):
        await ws.close(code=4404 if access == "hidden" else 4403)
        return
    await ws.accept()

    live = row["state"] in ("creating", "live")
    hub = core.get_or_create_hub(row) if live else None
    client = core.BrowserClient(ws, hub) if hub else None
    if client:
        client.id = "o_" + security.new_token()[:10]
        client.is_owner = True
        # read-only (session.watch): tastatura e inertă, ca la un invitat read-only — octeţii
        # de input se aruncă AICI şi în hub.handle_input (apărare în adâncime)
        client.writable = access == "rw"
        client.label = "self"           # idem
        client.user_id = user["id"]
        client.remote_addr = security.client_ip(ws)
        client.user_agent = ws.headers.get("user-agent", "")
        client.attached_at = time.time()
        # „Cunoscut" = IP-ul a mai apărut la un login reuşit al ACESTUI cont. Deliberat un
        # semnal slab: decide doar dacă facem zgomot, niciodată dacă sărim o verificare.
        client.known = await security.ip_is_known(user["id"], client.remote_addr)

    # host_online pe aceeaşi regulă ca `_host_json` (jump = agentul părinte), nu `in sources`:
    # o sesiune telnet-jump e pe un host fără sursă proprie şi apărea „host offline" deşi era vie
    hrow = await db.fetchone("SELECT id, connection_type, via_host_id FROM hosts WHERE id=?",
                             row["host_id"])
    await ws.send_text(json.dumps({
        "type": "init", "state": row["state"], "title": row["title"],
        "rows": row["rows"], "cols": row["cols"],
        "exit_status": row["exit_status"], "close_reason": row["close_reason"],
        "host_online": bool(hrow) and hostmodel.host_online(hrow),
        "your_id": client.id if client else None,
        # idle-lock (host 2FA): pragul şi momentul estimat al blocării, ca UI-ul să poată
        # avertiza („se blochează în 60 s") în loc să blocheze din senin (audit UX §6.c1)
        "lock_idle": hub.lock_idle if hub else 0,
        "lock_at": (hub.last_interaction + hub.lock_idle) if hub and hub.lock_idle else None,
        # 3.6: „watching (read-only)" — UI-ul face tastatura inertă şi arată pastila
        "readonly": access != "rw",
        # 3.6.13: starea OSC 133 NU pleacă aici — `init` precede verificarea de step-up / blocare
        # (review 3.6.13, L7); vine în mesajul `osc133`, doar după un replay trimis (deblocat)
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
    # H-1: decidem DACĂ afişăm scrollback-ul din flag-ul HOSTULUI, INDIFERENT de existenţa unui
    # hub. Pentru o sesiune LIVE, `hub` ţine şi idle-lock-ul; pentru una ÎNCHISĂ nu există hub —
    # dar `read_tail(sid)` tot ar scurge transcriptul unui host 2FA fără step-up (exact gaura din
    # audit: pasul de step-up stătea sub `if hub:`, deci sesiunile închise nu erau niciodată
    # blocate). Verificare PASIVĂ a ferestrei (fix 5): ataşarea nu trebuie să prelungească
    # „sudo-ul", deci `stepup_window_is_open` (fără sliding), nu `stepup_window_ok`.
    hrow2 = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", row["host_id"])
    host_2fa = bool(hrow2 and hrow2["require_2fa"])
    start_locked = False
    if host_2fa:
        if hub:
            hub.lock_idle = config.IDLE_LOCK_SECS      # 0 = fără idle-lock ÎN sesiune
            hub.stepup_cap = True                      # plafon absolut 60 min (sweep_stepup_caps)
        opened_at = security.stepup_window_opened_at(user["id"], row["host_id"])
        start_locked = (hub.locked if hub else False) or opened_at is None
        if hub and not start_locked:
            # ataşare deblocată = autorizată de factorul care a deschis fereastra (opened_at, NU
            # momentul ataşării — altfel o reataşare ar prelungi plafonul fără niciun factor nou)
            hub.note_authorized(opened_at)

    # closed sessions: replaying the alt-screen exit would blank the history.
    # Sesiune blocată → NU replaya scrollback-ul; la deblocare (passkey), hub.unlock() pune
    # un _RESYNC în coadă care-l retrimite din transcript. Astfel bufferul nu se scurge cât e blocat.
    # `?sb=&rows=` (scrollback-ul şi rândurile browserului): istoric tmux deasupra cozii pe o
    # sesiune live sub tmux, fereastră mai mare pe un flux fără tmux — vezi `core.attach_replay`.
    sb, sb_rows = core.parse_replay_params(getattr(ws, "query_params", None) or {})
    if client:
        client.replay_limit = core.replay_tail_limit(sb, core.stream_is_plain(hub))
        client.replay_sb = sb             # resync-ul FULL (resume/unlock) readuce şi istoricul tmux
    osc_span: dict = {}
    replay_sent = False
    if not start_locked:
        replay = await core.attach_replay(sid, hub, sb, sb_rows, span=osc_span)
        if hub and hub.locked:
            # blocată (idle-lock) cât aşteptam istoricul de la agent: nu scurgem nimic; calea
            # `start_locked` de mai jos ne blochează clientul şi trimite „locked"
            start_locked = True
        else:
            await ws.send_bytes(replay)
            replay_sent = True
    elif not hub:
        # Sesiune ÎNCHISĂ pe host 2FA fără fereastră de step-up: nu există hub care să trimită un
        # „locked" prin broadcast, deci semnalăm direct pe acest socket şi NU trimitem scrollback.
        # `unlock` (bucla de mai jos) deschide fereastra cu factor PROASPĂT, apoi redă transcriptul.
        await ws.send_text(json.dumps({"type": "locked"}))

    if hub:
        # Fără step-up: blocat ÎNAINTE de a intra în hub. Altfel, până la decizia de mai jos (după
        # roster/announce/audit), clientul primea output live şi conta drept operator verificat
        # (`has_operator`) — un invitat ataşat în fereastra asta trecea de poarta lui (review lot 1, F2).
        if start_locked:
            client.lock()
        hub.clients.add(client)
        await _send_osc133(client, hub, osc_span if replay_sent else None)
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
        # Atribuire „cine a ajuns pe ce host": reataşarea pe WS NU trece prin middleware-ul de
        # audit (nu e o cerere HTTP care schimbă ceva), deci o consemnăm explicit aici. Crearea
        # unei sesiuni noi e deja auditată (POST /api/hosts/{id}/sessions). Împreună, jurnalul
        # răspunde la „userul X, pe ce hosturi/sesiuni a fost" — util la debug şi pentru SSO.
        await audit.record(time.time(), user["email"], client.remote_addr, "WS",
                           "/ws/sessions/%s" % sid, 200,
                           "ataşat la sesiune pe host %s" % row["host_id"])
        if not client.known:
            email_alerts.notify_session_attach(
                row["title"], client.remote_addr, client.user_agent, user["email"],
                user_id=user["id"])
        if start_locked:
            # alt cont lucrează deja DEBLOCAT pe terminal → blocăm doar acest client (OPEN1): un al
            # doilea cont fără fereastră nu are voie să închidă terminalul celui care lucrează
            others_working = any(
                c is not client and c.is_owner and c.writable and not c.locked
                and c.user_id != user["id"] for c in hub.clients)
            if not hub.locked and client.writable and not others_working:
                await hub.lock("stepup")         # fără fereastră → blochează toţi clienţii + broadcast
            else:
                # hub deja blocat, SAU un watcher read-only fără fereastră (3.6): blocăm DOAR acest
                # client — un cont care nu poate tasta nu are voie să închidă terminalul celui care
                # lucrează (DoS), iar output-ul nu-i ajunge până nu-şi prezintă propriul factor
                client.lock()
                await client.send_text(json.dumps({"type": "locked", "reason": hub.lock_reason}))
        # un operator verificat tocmai a sosit → invitaţii blocaţi în lipsa lui se deblochează
        await hub.sync_guests()
        conn = core.sources.get(row["host_id"])
        # sesiune SSH live fără sursă = gateway repornit; re-dial cu creds stocate
        # și re-atașează tmux-ul remote (persistență peste restart)
        if conn is None:
            host = await db.fetchone("SELECT * FROM hosts WHERE id=?", row["host_id"])
            if host and host["connection_type"] == "ssh" and host["credential_encrypted"]:
                try:
                    cred = hostmodel.decode_credential(host["credential_encrypted"])
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
    wake = authz.subscribe()      # 3.6: o schimbare de rol re-verifică ACUM, nu la următorul tick

    async def _revalidate():
        nonlocal access
        while True:
            try:
                await asyncio.wait_for(wake.wait(), security.WS_REVALIDATE_SECS)
            except asyncio.TimeoutError:
                pass
            wake.clear()
            if not await security.session_valid(tok):
                try:
                    await ws.close(code=4401)
                except Exception:                    # noqa: BLE001
                    pass
                return
            # 3.6 (§A.6.4): drepturile se re-evaluează: pierdut → închis (4403); retrogradat de la
            # scriere la urmărire → `writable` cade pe loc, iar clientul primeşte `readonly`.
            cur = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
            now_access = await _ws_access(user["id"], cur) if cur else "hidden"
            if now_access in ("hidden", "none") or (
                    now_access == "replay" and access in ("rw", "ro") and hub is not None):
                try:
                    await ws.close(code=4403)
                except Exception:                    # noqa: BLE001
                    pass
                return
            if access == "rw" and now_access != "rw" and client is not None:
                client.writable = False
                if hub is not None:
                    # ÎNAINTE de orice await: un watcher nu mai ţine invitaţii înăuntru
                    await hub.sync_guests()
                try:
                    await client.send_text(json.dumps({"type": "readonly"}))
                except Exception:                    # noqa: BLE001
                    pass
            access = now_access if not (access != "rw" and now_access == "rw") else access

    reval_task = asyncio.create_task(_revalidate())
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            if not hub:
                # Sesiune ÎNCHISĂ pe host 2FA (fără hub): singurul control relevant e `unlock` —
                # deschide fereastra cu factor PROASPĂT (fix 5), apoi redă scrollback-ul reţinut.
                # Fără hub nu există input/kick/pong de procesat, deci consumăm mesajul şi mergem mai departe.
                if start_locked and msg.get("text"):
                    try:
                        cc = json.loads(msg["text"])
                    except ValueError:
                        continue
                    if cc.get("type") == "unlock":
                        try:
                            await stepup.require_fresh_factor(row["host_id"], await _fresh_user(user),
                                                        cc.get("grant", ""), cc.get("password", ""),
                                                        cc.get("totp", ""))
                        except HTTPException as e:
                            await ws.send_text(json.dumps(
                                {"type": "unlock_failed", "code": getattr(e, "code", "")}))
                        else:
                            start_locked = False
                            await ws.send_text(json.dumps({"type": "unlocked"}))
                            await ws.send_bytes(await asyncio.to_thread(core.read_tail, sid))
                continue
            if msg.get("bytes") is not None and hub:
                if client.writable:          # 3.6: un client read-only nu scrie în PTY
                    await hub.handle_input(client, msg["bytes"])
            elif msg.get("text") and hub:
                try:
                    ctl = json.loads(msg["text"])
                except ValueError:
                    continue
                if ctl.get("type") == "pong":
                    client.on_pong(ctl.get("n", 0))
                elif ctl.get("type") == "unlock":
                    # 3.6: un client READ-ONLY nu deblochează terminalul pentru cei care scriu —
                    # factorul lui îi deblochează cel mult propria vedere (dacă hub-ul nu e blocat)
                    if hub.locked and not client.writable:
                        await client.send_text(json.dumps(
                            {"type": "unlock_failed", "code": "authz.denied"}))
                        continue
                    # Deblocare: fix 5 — cerem un factor PROASPĂT (grant consumat / parolă / TOTP
                    # prezentate ACUM), NU doar o fereastră de step-up deschisă. Un terminal blocat
                    # nu trebuie să se deblocheze fiindcă activitatea a ţinut o fereastră în viaţă:
                    # `stepup.require_fresh_factor` acceptă grant nou sau o fereastră deschisă ≤120s
                    # (ceremonia de step-up / callback-ul OIDC), dar NU una veche glisată de trafic.
                    # Pe o instalare fără WebAuthn deblocarea merge pe parolă/TOTP, deci o sesiune
                    # blocată nu devine irecuperabilă.
                    try:
                        await stepup.require_fresh_factor(row["host_id"], await _fresh_user(user),
                                                    ctl.get("grant", ""), ctl.get("password", ""),
                                                    ctl.get("totp", ""))
                    except HTTPException as e:
                        await client.send_text(json.dumps(
                            {"type": "unlock_failed", "code": getattr(e, "code", "")}))
                    else:
                        opened = security.stepup_window_opened_at(user["id"], row["host_id"])
                        if hub.locked:
                            # factorul tocmai prezentat (fereastră proaspătă) reporneşte plafonul.
                            # 3.6: factorul unui cont NU deblochează clienţii ALTUI cont — cine nu
                            # are propria fereastră de step-up nu e deblocat deloc (predicat, nu
                            # deblocare-apoi-reblocare); invitaţii prin share păstrează regula lor
                            hid_ = row["host_id"]
                            uid_ = user["id"]
                            await hub.unlock(opened, allow=lambda c: (
                                c is client or not c.is_owner or c.user_id == uid_
                                or security.stepup_window_is_open(c.user_id, hid_)))
                        elif client.locked:
                            # hub-ul merge, doar ACEST client era blocat (watcher sau alt cont fără
                            # fereastră): factorul lui îi deblochează propria vedere
                            client.unlock()
                            await client.send_text(json.dumps({"type": "unlocked"}))
                        await hub.sync_guests()
                elif ctl.get("type") == "kick":
                    # DOAR owner-ul (client autentificat) scoate un INVITAT (nu owner).
                    # Închide WS-ul țintei → bucla ei se termină + roster rebroadcast.
                    # 3.6: şi doar dacă poate scrie (un watcher read-only nu dă afară pe nimeni)
                    if client.is_owner and client.writable:
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
                elif ctl.get("type") == "touch":
                    # prezenţă FĂRĂ taste (scroll, selecţie, mouse): amână idle-lock-ul exact
                    # ca o tastă — acelaşi client, acelaşi canal, aceeaşi încredere. Pe WS, nu
                    # pe HTTP: un POST la 30 s ar umple jurnalul de audit cu zgomot. Un hub
                    # deja blocat NU se deblochează aşa (doar step-up-ul o face).
                    hub.touch(client)
                    await client.send_text(json.dumps({
                        "type": "lock_at",
                        "lock_at": (hub.last_interaction + hub.lock_idle) if hub.lock_idle else None}))
                elif ctl.get("type") == "unscroll":
                    # „întoarce-mă la prompt" (agent 59): scoate sesiunea din istoricul tmux fără
                    # nicio tastă. Porţile (writable, blocare, ritm) sunt în hub; răspundem MEREU,
                    # ca UI-ul să nu aştepte un timeout când răspunsul e „nu era în istoric".
                    was = await hub.scroll_exit(client)
                    await client.send_text(json.dumps({"type": "unscrolled", "was": was}))
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
                    if not client.writable:
                        continue             # 3.6: read-only nu schimbă grila celorlalţi
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
        authz.unsubscribe(wake)
        if hub and client:
            hub.clients.discard(client)
            if client.sender_task:
                client.sender_task.cancel()
            # ultimul operator verificat a plecat → invitaţii prin share se blochează ACUM, nu la
            # idle-lock (raport de securitate 2026-11, lot 1)
            await hub.sync_guests()
            await hub.broadcast_roster()
