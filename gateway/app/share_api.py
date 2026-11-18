"""Sharing a session and its recording: live share links (create / revoke, writable opt-in behind
`share.live_write`, step-up on `require_2fa` hosts), the share inventory and the security summary
("is everything fine right now?"), the guest-side shared-link meta, and transcripts + public,
read-only replay links (`/api/replay/*`: masking and rate limiting in `replay.py`). The guest
websocket `/ws/shared/{token}` stays in api.py `[ws]`. Revoking derived access lives in
`shares.py`. Moved out of api.py; nothing here imports api.py.
"""
import asyncio
import json
import logging
import re
import time

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .errors import ApiError
from . import (audit, authz, backup, cloudbackup, cmdguard, config, conntypes, core, db, email_alerts,
               replay, security, sessctl, shares, signing, stepup, watermark)

log = logging.getLogger("webterm")
# Aceeaşi gardă ca api.router (fail-closed): o rută fără permisiune declarată → 500 authz.undeclared.
router = APIRouter(dependencies=[Depends(authz.declared)])


# ── [share] Create / revoke a live share link ─────────────────────────────────────────────────────
class ShareIn(BaseModel):
    writable: bool = False
    expires_minutes: int = 1440   # 24h implicit
    stepup_grant: str = ""        # 2FA: pe host cu require_2fa, crearea share-ului cere step-up (H1)
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


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
    if sessctl.session_origin(row) in sessctl.ROOT_TERMINAL_ORIGINS:
        raise ApiError(403, "certs.renewSessionPrivate",
                       "a certificate renewal terminal cannot be shared")
    # 3.6: link-ul public e o extensie a sesiunii — doar pe a TA (sau pre-3.6, sau cu
    # session.manage); altfel un Operator ar putea expune / înlocui link-ul altcuiva
    await sessctl.require_session_control(request, sid, user)
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
    await sessctl.require_session_control(request, sid, user)    # 3.6: doar pe sesiunea ta / manage
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
    wm = await watermark.load_watermark()
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


# ── [replay] Link-uri de replay (3.5.12): sesiune ÎNCHISĂ, partajată public, doar-citire ───────
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
    await sessctl.require_session_control(request, sid, user)
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
