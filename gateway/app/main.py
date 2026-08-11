"""WebTerm gateway entrypoint."""

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from urllib.parse import urlparse

from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

from . import (api, audit, backup, cloudbackup, config, core, db, email_alerts, health,
               security, signing, webauthn_api)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("webterm")

_JANITOR_INTERVAL = 24 * 3600      # curățare arhivă o dată pe zi


# Sub pragul ăsta, discul gateway-ului e o problemă operaţională, nu o curiozitate:
# SQLite şi transcripturile devin nescriibile, iar produsul pare sănătos până la primul login.
_DISK_WARN_PCT = 10.0


async def _warn_if_insecure_forwards() -> None:
    """F-08: pe http://, `COOKIE_NAME` pierde prefixul `__Host-`, iar un cookie fără el poate
    fi scris de pe un subdomeniu cu `domain=.exemplu.com`. Cu forward-urile pornite, asta
    înseamnă că o pagină de echipament poate INJECTA o sesiune în originea aplicaţiei —
    fixare de sesiune. Nu refuzăm pornirea (o instalare de laborator pe IP e legitimă), dar
    o spunem tare: tăcerea aici e cea care lasă pe cineva să creadă că e în regulă."""
    if config.PUBLIC_URL.startswith("http://") and api.forward_domain():
        log.error(
            "INSECURE: WEBTERM_PUBLIC_URL is http:// while port-forwarding is configured. "
            "Without https the session cookie loses its __Host- prefix, so a forwarded page "
            "on a subdomain can write a cookie into the app origin (session fixation). "
            "Use https, or disable forwarding.")


async def _warn_if_disk_low() -> None:
    """Alertă când discul gateway-ului se umple.

    Rulează din bucla reaper-ului (60s), nu din janitor (24h): un disc se umple în minute
    sub un `yes`, iar o fereastră de o zi înseamnă că afli după ce s-a rupt. Folosim direct
    `statvfs`, nu `storage_stats` — acela parcurge directoarele de transcripturi şi ar fi
    prea scump pe minut; aici avem nevoie doar de spaţiul liber."""
    try:
        st = await asyncio.to_thread(os.statvfs, config.DATA_DIR)
    except OSError:
        return
    free, total = st.f_bavail * st.f_frsize, st.f_blocks * st.f_frsize
    # `not free` era adevărat şi pentru 0 — adică alerta tăcea exact pe discul COMPLET plin,
    # starea cea mai gravă. Comparăm explicit.
    if total <= 0:
        return
    pct = free * 100.0 / total
    if pct < _DISK_WARN_PCT:
        log.warning("gateway disk low: %.1f%% free (%d of %d bytes)", pct, free, total)
        email_alerts.notify_disk_low(free, total, pct)


async def _warn_if_signing_locked() -> None:
    """Cheie de semnare blocată + agenţi în urmă → alertă (throttled la 12h).

    Punctul roşu din UI ajută pe cineva care se uită la UI. Dar upgrade-urile se dau din cron
    sau de la distanţă, iar flota rămâne tăcut pe o versiune veche. Alertăm doar dacă există
    şi consecinţă (agenţi efectiv în urmă), nu doar pentru că o cheie e blocată."""
    if not (signing.key_exists() and not signing.is_loaded()):
        return
    expected = core.agent_expected().get("version")
    if not expected:
        return
    row = await db.fetchone(
        "SELECT COUNT(*) AS c FROM hosts WHERE connection_type='agent'"
        " AND agent_version IS NOT NULL AND agent_version < ?", expected)
    if row and row["c"]:
        email_alerts.notify_signing_locked(row["c"])


async def _janitor() -> None:
    """Șterge periodic transcripturile arhivate mai vechi de retenție."""
    while True:
        try:
            archived = await core.archive_closed_transcripts()
            removed = await asyncio.to_thread(core.purge_archive)
            await audit.prune()             # aceeași fereastră de retenție ca arhiva
            await _warn_if_signing_locked()
            await _warn_if_insecure_forwards()
            if archived:
                log.info("janitor: archived %d transcripts of sessions closed >%d days ago",
                         archived, config.CLOSED_ARCHIVE_DAYS)
            if removed:
                log.info("janitor: deleted %d archived transcripts (>%d days)",
                         removed, config.ARCHIVE_RETENTION_DAYS)
        except Exception:
            log.exception("the janitor failed")
        await asyncio.sleep(_JANITOR_INTERVAL)


_REAPER_INTERVAL = 60.0        # cât de des verificăm liveness-ul sesiunilor
_REAPER_GRACE = 180.0          # nu reapa în primele ~3 min după pornire: lasă agenții
                               # să reconecteze (heartbeat proaspăt) și reconcile() să ruleze


async def _session_reaper() -> None:
    """Reconciliază starea 'live' din DB cu realitatea backendului: sesiuni fantomă
    (telnet fără sursă, shell de pe hosturi offline) → 'lost'. Vezi
    core.sweep_stale_sessions. Grație de pornire ca să nu marcheze prematur sesiuni ale
    unui agent care tocmai reconectează."""
    await asyncio.sleep(_REAPER_GRACE)
    while True:
        try:
            await core.sweep_stale_sessions()
            await core.prune_agent_events()      # retenţie 7 zile pe jurnalul de conexiune agent
            await core.sweep_hosts_offline()     # alertă la host căzut / revenit
            await _warn_if_disk_low()
        except Exception:
            log.exception("the session reaper failed")
        await asyncio.sleep(_REAPER_INTERVAL)


_IDLE_LOCK_INTERVAL = 15.0     # cât de des verificăm idle-lock-ul (host cu 2FA)


async def _idle_lock_sweep() -> None:
    """Blochează sesiunile 2FA idle > prag (output suprimat + input refuzat până la passkey).
    Vezi core.sweep_idle_locks. Cadenţă mică → lock la max ~15s după atingerea pragului."""
    while True:
        try:
            await core.sweep_idle_locks()
        except Exception:
            log.exception("the idle-lock sweep failed")
        await asyncio.sleep(_IDLE_LOCK_INTERVAL)

FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

# App-level so the headers travel with any deployment (Docker+Caddy or bare
# uvicorn). HSTS is left to the TLS terminator (Caddy) since it's https-only.
CSP = (
    "default-src 'self'; "
    "connect-src 'self'; "                 # 'self' acoperă și WS same-origin (ws/wss) pe
                                           # browsere moderne; wildcardul ws:/wss: permitea
                                           # exfiltrare WS către orice host la un XSS. e2e-ul
                                           # din CI deschide o sesiune WS reală → verifică.
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "   # xterm sets inline element styles
    "script-src 'self' 'wasm-unsafe-eval'; "   # WASM pt. addon-ul de imagini (sixel); NU permite eval()
    "font-src 'self' data:; "
    "base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
)


_BACKUP_TICK = 3600.0          # verificăm o dată pe oră dacă e timpul de un backup programat


async def _scheduled_backup() -> None:
    """Backup automat (off/daily/weekly), scris necriptat în data/backups/ (serverul are
    oricum cheia). Retenție 7 zile. La final ridică flagul de notificare (backup_last) ca
    UI-ul să ofere userului descărcarea (criptată cu parola lui)."""
    while True:
        await asyncio.sleep(_BACKUP_TICK)
        try:
            sched = await api._get_setting("backup_schedule", "off")
            if sched not in ("daily", "weekly"):
                continue
            last = float(await api._get_setting("backup_last", "0") or 0)
            period = 86400 if sched == "daily" else 7 * 86400
            now = time.time()
            if now - last < period:
                continue
            inc = (await api._get_setting("backup_include_tx", "0")) == "1"
            name = await asyncio.to_thread(backup.run_scheduled_backup, inc)
            await api._set_setting("backup_last", str(now))
            log.info("scheduled backup (%s) written: %s", sched, name)
            # copie off-host, dacă e configurat un cloud: criptată cu parola userului,
            # eșecul se raportează în UI dar nu invalidează backup-ul local
            await cloudbackup.upload_scheduled(name)
        except Exception:
            log.exception("the scheduled backup failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.ensure_dirs()
    # Un restore pus în staging din UI se aplică ACUM, înainte de a citi cheia/DB-ul:
    # swap DB + data/secret. Vezi backup.apply_pending_restore.
    try:
        if backup.apply_pending_restore():
            log.warning("restore applied at boot from the uploaded backup")
    except Exception:
        # Un restore PORNIT dar ne-terminat nu trebuie să lase aplicația să pornească cu o
        # stare pe jumătate aplicată (DB nou + cheie veche = seif nedecriptabil). Staging-ul
        # + flagul rămân intacte (apply_pending_restore e reîncercabil) → repornirea reia și
        # converge. Eșuăm zgomotos în loc să servim un seif rupt.
        log.exception("applying the restore at boot failed — refusing to start with "
                      "partial state; the next restart resumes from staging")
        raise
    security.init_crypto(config.load_secret())
    await db.connect()
    # Guard: if we just minted a fresh vault key but the DB already holds
    # encrypted secrets, that key can never decrypt them — fail loud instead of
    # silently serving a broken vault (agent tokens + SSH creds unrecoverable).
    if config.secret_was_generated:
        enc = await db.fetchone(
            "SELECT 1 FROM hosts WHERE token_encrypted IS NOT NULL"
            " OR credential_encrypted IS NOT NULL LIMIT 1")
        if enc:
            raise RuntimeError(
                "data/secret is missing but the database contains encrypted "
                "secrets (agent tokens / SSH credentials). A new key was just "
                "generated and CANNOT decrypt them. Restore the original "
                "data/secret from backup before starting. Refusing to boot.")
    # Instalare NOUĂ → cheie proprie din prima secundă. Sursa publică a agentului are încorporată
    # cheia MENTAINERULUI; fără o cheie de deployment, fiecare instalare din lume ar împărţi
    # aceeaşi ancoră de încredere pentru update-uri, iar o scurgere a acelei chei ar însemna cod
    # arbitrar pe toate flotele. O generăm automat DOAR cât timp nu e înrolat niciun host: după
    # aceea agenţii au deja alt pubkey încorporat şi ar refuza (corect) update-urile semnate cu
    # cheia nouă, iar reparaţia e reinstalarea fiecărui agent — deci rotaţia rămâne o decizie
    # explicită a operatorului, semnalată în UI prin `signing_missing`.
    if not signing.key_exists():
        has_hosts = bool(await db.fetchone("SELECT 1 FROM hosts LIMIT 1"))
        if not signing.should_autogenerate(has_hosts):
            log.warning("no fleet signing key, but hosts are already enrolled: "
                        "the agents use the maintainer's key. Generating one now would then require "
                        "reinstalling every agent — see Settings → Security")
        else:
            try:
                pub = await asyncio.to_thread(signing.generate, None)
                log.info("fleet signing key generated automatically (new install): %s", pub)
            except Exception:
                log.exception("automatic generation of the signing key failed — the agents will "
                              "stay on the maintainer's key")
    # Cheia de semnare a flotei, dacă e stocată FĂRĂ parolă, se încarcă la pornire.
    # Altfel `signing.load()` era chemat doar din endpoint-ul de deblocare, deci după orice
    # repornire (adică după fiecare upgrade) auto-update-ul agenţilor rămânea mort până
    # apăsa cineva un buton — fără niciun semnal, fiindcă UI-ul marchează „blocată" doar
    # cheile CRIPTATE. O cheie fără parolă nu are ce debloca: e disponibilă, deci o folosim.
    # Cheile criptate rămân blocate până la deblocare manuală — ăsta e chiar rostul lor.
    if signing.key_exists() and not signing.is_encrypted():
        if await asyncio.to_thread(signing.load, None):
            log.info("the fleet signing key (no passphrase) is loaded — agents can update")
        else:
            log.warning("the fleet signing key exists but could not be loaded — "
                        "agents will NOT be able to update")
    elif signing.key_exists():
        log.warning("the fleet signing key is ENCRYPTED and locked — agent auto-update "
                    "is paused until you unlock it in Settings → Security")
    await api.init_setup_token()
    await api.load_forward_domain()            # domeniul de forward configurabil din Settings
    await api.seed_default_snippets()          # snippet-uri de transfer gata făcute (o singură dată)
    await core.reconcile_telnet_on_start()     # sesiunile telnet nu supraviețuiesc restartului → lost
    janitor = asyncio.create_task(_janitor())
    reaper = asyncio.create_task(_session_reaper())   # reconciliere liveness sesiuni 'live'
    idlelock = asyncio.create_task(_idle_lock_sweep())  # blocare terminal idle pe host 2FA
    lagmon = asyncio.create_task(health.loop_lag_monitor())   # sănătatea gateway-ului
    backupt = asyncio.create_task(_scheduled_backup())        # backup-uri programate (off/daily/weekly)
    yield
    janitor.cancel()
    reaper.cancel()
    idlelock.cancel()
    lagmon.cancel()
    backupt.cancel()
    await db.close()


# `/docs`, `/redoc` şi `/openapi.json` sunt PUBLICE la FastAPI implicit, iar aici asta
# însemna 98 de căi cu tot cu scheme de request, servite oricui, fără cont. Nu e o gaură
# (rutele rămân păzite), dar e o hartă completă a suprafeţei de atac oferită gratis pe un
# produs care e root-shell pe o flotă — şi nu apărea în niciun test, fiindcă rutele nu sunt
# într-un router al nostru. Le stingem: schema se generează oricând local, din cod.
app = FastAPI(title="WebTerm", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


_AUDIT_METHODS = ("POST", "PUT", "PATCH", "DELETE")


@app.middleware("http")
async def audit_log(request: Request, call_next):
    # Cel mai INTERIOR middleware (înregistrat primul): cererile către subdomeniile de
    # forward sunt scurtcircuitate mai sus de `forward_router`, deci aplicația de pe host
    # nu ne umple jurnalul cu propriile ei /api/*.
    resp = await call_next(request)
    # Metodele care SCHIMBĂ ceva, plus citirile care SCOT DATE (transcript, download, preview,
    # jurnal de agent). Doar-mutaţiile lăsau exfiltrarea invizibilă — exact scenariul pentru
    # care există jurnalul: „mi-a fost furat cookie-ul, ce a scos de aici?".
    path = request.url.path
    if not path.startswith("/api/"):
        return resp
    if request.method not in _AUDIT_METHODS and not (
            request.method == "GET" and audit.audited_read(path)):
        return resp
    try:
        actor = getattr(request.state, "audit_actor", "")
        if not actor:
            user = await security.user_for_token(request.cookies.get(security.COOKIE_NAME))
            actor = user["email"] if user else ""
        if not actor:
            # cererile de automatizare poartă Bearer, nu cookie: în jurnal apar ca
            # „token:<nume>", ca să nu pară acţiuni anonime
            tok = await security.api_token_principal(request)
            actor = ("token:" + tok["name"]) if tok else ""
        await audit.record(time.time(), actor, security.client_ip(request),
                           request.method, request.url.path, resp.status_code,
                           getattr(request.state, "audit_detail", ""))
    except Exception:                       # noqa: BLE001 — auditul nu rupe cererea
        log.exception("writing the audit log failed")
    return resp


@app.middleware("http")
async def forward_router(request: Request, call_next):
    # Subdomeniile de forward (<slug>.<domeniu>) sunt tratate separat: auth +
    # proxy către serviciul de pe host. Se întorc FĂRĂ CSP-ul WebTerm (care ar
    # bloca app-ul forwardat) și pe origin izolat.
    # NB: `security_headers` e înregistrat DUPĂ acesta, deci ACELA e cel exterior — comentariul
    # de aici susţinea invers. Funcţionează fiindcă `security_headers` sare peste gazdele de
    # forward; cine mută middleware-urile bazându-se pe vechea afirmaţie ar rupe izolarea.
    try:
        resp = await api.route_forward(request)
    except HTTPException as e:
        # Rulăm ca middleware ASGI, deci ÎN AFARA stivei de excepţii a FastAPI: orice
        # `raise HTTPException` din proxy ajungea la handler-ul de erori de server şi ieşea ca
        # „500 Internal Server Error" cu traceback în log. Mesajele scrise anume pentru om —
        # „host-ul e offline", „corp prea mare pentru forward" — nu ajungeau niciodată la el.
        return PlainTextResponse(str(e.detail), status_code=e.status_code)
    if resp is not None:
        return resp
    return await call_next(request)


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    """Refuză cererile care schimbă ceva şi vin de pe alt origin.

    Până acum singura apărare CSRF pe HTTP era `SameSite=Lax` — iar asta nu apără NIMIC
    aici, fiindcă produsul îşi serveşte deliberat forward-urile pe SUBDOMENII ale propriului
    domeniu, iar subdomeniile sunt *same-site*. Deci o pagină de pe `cam1.term.example.com`
    — un UI de echipament, exact conţinutul pe care restul codului îl tratează ca ostil
    (`telnet.py` îi taie secvenţele OSC) — putea trimite POST-uri cu cookie-ul de sesiune
    către `term.example.com`. Fără să citească răspunsul, dar cu efect: dezinstalare de
    agent, ştergere de host, uitarea credenţialelor SSH, omorârea sesiunilor.

    NU acoperă endpointurile cu body JSON: acelea cer `Content-Type: application/json`, care
    declanşează un preflight CORS pe care noi nu-l onorăm — verificat pe versiunile livrate
    (fastapi 0.139.0 / starlette 1.3.1): un body fără antet, sau cu `text/plain`, întoarce
    422, nu e parsat ca JSON. Un audit extern a susţinut contrariul; testul l-a infirmat.
    Verificarea de mai jos e oricum generală, ca să nu depindem de comportamentul acela.

    `Origin` lipsă = refuz, nu permisiune. Browserele moderne îl trimit mereu la cererile
    care schimbă ceva; aceeaşi poziţie o are deja `_origin_ok` pentru WebSocket. Clienţii
    non-browser (curl, scripturi, CI) nu folosesc cookie-uri, ci `Authorization: Bearer`,
    deci nu trec pe aici — iar cine trimite şi cookie, şi Bearer, primeşte refuz corect."""
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        host = (request.headers.get("host") or "").split(":")[0].lower()
        fdom = api.forward_domain()
        forwarded = bool(host and fdom and host != fdom and host.endswith("." + fdom))
        # Subdomeniile de forward nu sunt API-ul nostru: cererile lor merg la echipament.
        if not forwarded and request.url.path.startswith(("/api/", "/__wtfwd/")):
            # Token-urile de automatizare nu sunt vulnerabile la CSRF (nu se trimit automat
            # de browser), deci nu le cerem Origin — altfel am rupe orice integrare.
            auth = (request.headers.get("authorization") or "").lower()
            if not auth.startswith("bearer "):
                origin = request.headers.get("origin") or request.headers.get("referer") or ""
                ours = urlparse(config.PUBLIC_URL).netloc.lower()
                if not origin or urlparse(origin).netloc.lower() != ours:
                    log.warning("CSRF refused: %s %s origin=%r",
                                request.method, request.url.path, origin or None)
                    return PlainTextResponse("cross-origin request refused", status_code=403)
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    # Răspunsurile de forward (subdomenii <slug>.<domeniu>) sunt ALT origin / altă
    # aplicație — NU le aplicăm CSP-ul/headerele WebTerm. CSP-ul nostru (fără
    # unsafe-inline/unsafe-eval) rupe UI-uri de echipamente (ex. MikroTik Webfig
    # folosește inline scripts + eval). Izolarea rămâne prin subdomeniu + cookie
    # __Host-; echipamentul își aduce propriile headere de securitate.
    host = (request.headers.get("host") or "").split(":")[0].lower()
    fdom = api.forward_domain()
    if host and host != fdom and host.endswith("." + fdom):
        # F-08: CSP-ul nostru rupe UI-uri de echipamente, dar ASTEA trei nu rup nimic —
        # niciun UI de router nu are nevoie să fie încadrat de alt site sau să scurgă
        # referrer. Fără ele, o pagină forwardată e „iframe-abilă" de oriunde.
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Content-Security-Policy", "frame-ancestors 'self'")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault("Content-Security-Policy", CSP)
    # frontend-ul compară versiunea cu cea văzută la pornire; la deploy nou
    # afișează bannerul „Versiune nouă — Reîncarcă" (vezi lib/api.ts).
    #
    # „Doar pe /api/" NU însemna „doar pentru cine e autentificat", deşi asta spunea intenţia:
    # `/api/login` şi `/api/state` sunt publice, deci oricine putea citi versiunea exactă a
    # gateway-ului fără să aibă cont — adică putea potrivi o instalaţie cu un CVE viitor
    # înainte să încerce ceva. Cerem cookie-ul de sesiune: bannerul de versiune îl vede oricum
    # doar cine e logat. Semnalat de un audit extern, 2026-08-09.
    if request.url.path.startswith("/api/") and request.cookies.get(security.COOKIE_NAME):
        resp.headers.setdefault("X-Webterm-Version", config.GATEWAY_VERSION)
    # asset-urile au nume cu hash → cache lung; restul (index.html, API) revalidate
    # mereu, ca un deploy nou să apară imediat fără hard-refresh
    if request.url.path.startswith("/assets/"):
        resp.headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
    else:
        resp.headers.setdefault("Cache-Control", "no-cache")
    return resp


# WebSocket-urile către subdomeniile de forward: middleware-ul HTTP nu vede scope-ul
# „websocket", deci le prindem la nivel ASGI și le proxy-ăm prin tunel.
class ForwardWSMiddleware:
    def __init__(self, asgi_app):
        self.app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket":
            hdrs = dict(scope.get("headers", []))
            host = hdrs.get(b"host", b"").decode("latin1").split(":")[0].lower()
            main = api.forward_domain()
            if host and host != main and host.endswith("." + main):
                await api.handle_forward_ws(scope, receive, send)
                return
        await self.app(scope, receive, send)


# Nimic nu comprima nimic: nici aplicaţia, nici `Caddyfile`, nici Traefik (care are un singur
# middleware, cel de HSTS). Deci fiecare încărcare la rece căra 904 KB pe sârmă. Măsurat de un
# audit extern cu throttling de browser: 113 ms fără limitare, dar 4,7 s pe Slow-4G şi **18,6 s**
# pe Regular-3G până la prima randare — pentru un produs a cărui promisiune de bază e „îl verifici
# de pe telefon". Compresia dă 3,46× pe calea critică (902 KB → 261 KB).
# Aici, în aplicaţie, nu în proxy: acoperă TOATE căile de deploy (Caddy, Traefik, direct), nu doar
# pe cea configurată azi. `minimum_size` sare peste răspunsurile mici, unde antetele costă mai
# mult decât economisesc.
# `compresslevel=6`, nu 9 (implicit). Starlette comprimă în `send`, adică PE EVENT-LOOP, iar
# middleware-ul prinde fiecare răspuns HTTP — inclusiv descărcările de fişiere şi proxy-ul de
# forward, nu doar bundle-ul SPA pentru care a fost măsurat câştigul. Nivelul 9 pe un fişier de
# sute de MB ar consuma bucla care multiplexează toate terminalele. La 6, raportul pe bundle
# rămâne practic acelaşi (măsurat: 3,5x vs 3,55x) pentru o fracţiune din CPU.
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=6)
app.add_middleware(ForwardWSMiddleware)

app.include_router(api.router)
app.include_router(webauthn_api.router)

if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")
    _DIST = FRONTEND_DIST.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str):
        # resolve and contain: '..' segments must not escape the dist dir
        # (raw ASGI clients don't normalize the path for us)
        target = (_DIST / path).resolve()
        if path and target.is_file() and target.is_relative_to(_DIST):
            return FileResponse(target)
        return FileResponse(_DIST / "index.html")
