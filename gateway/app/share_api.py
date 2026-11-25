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
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from .errors import ApiError
from . import (audit, authz, backup, cloudbackup, cmdguard, config, conntypes, core, db, email_alerts,
               erasure, migration, replay, security, sessctl, shares, signing, stepup, txhub, txstore, watermark)

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
    async with txhub.revoking(sid):           # 3.8: gardul de revocare (no-op când e oprit)
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
async def get_transcript(sid: str, request: Request, format: str = "out", tail: bool = False,
                         user=Depends(authz.perm('recording.view', host='sid'))):
    """`out` = fluxul brut, `cast` = asciicast (redare cu timing), `txt` = text citibil.
    `tail=true` (doar pentru txt) întoarce doar coada — vizualizarea din UI nu trage
    zeci de MB ca să arate ce s-a întâmplat ultima dată."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    await stepup.require_session_host_stepup(sid, user)
    if txhub.active():
        return await _tx_transcript(request, sid, format, tail)
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
async def session_preview(sid: str, request: Request,
                          user=Depends(authz.perm('recording.view', host='sid'))):
    """Coada recentă a transcriptului (pentru previzualizare read-only în UI),
    fără secvențele de alt-screen care ar goli ecranul."""
    if not await db.fetchone("SELECT id FROM sessions WHERE id=?", sid):
        raise ApiError(404, "session.missing", "no such session")
    await stepup.require_session_host_stepup(sid, user)
    if txhub.active():
        return await _tx_preview(request, sid)
    data = await asyncio.to_thread(core.read_tail, sid, limit=32 * 1024)
    return Response(content=data, media_type="application/octet-stream")


# ── [replay] 3.8: encrypted recordings (txhub active; ENCRYPTION-AT-REST.md §12.11.2) ───────────
# Fiecare rută îşi construieşte `Access`-ul din PROPRIA autorizare: contoarele de revocare se
# capturează ÎNAINTE de decizie (txhub.snapshot), decizia se reface (cookie → grant-uri proaspete →
# recording.view pe host → step-up), iar `not_after` = cea mai apropiată limită de timp folosită
# (sesiunea web: absolută + inactivitate, legătura temporară, fereastra de step-up, link-ul de replay).
# Aceeaşi funcţie e şi re-autorizarea unui flux după un bump global sau o expirare. Autorizarea ţine
# PÂNĂ LA EMITERE (§12.11.10): fiecare bucată a unui corp (flux, text, previzualizare, cache) e
# re-verificată (`txhub.Grant.before_emit`) imediat înainte de a fi predată transportului.
_REDACTED_CACHE = {}


def _tx_api_error(e) -> ApiError:
    """txstore refusal → the route's error (codes as literals: tests/i18n_catalog_test.py)."""
    if isinstance(e, ApiError):
        return e
    r = getattr(e, "reason", "")
    if isinstance(e, txstore.Revoked) or r in ("revoked", "bad-access"):
        return ApiError(404, "session.missing", "no such session")
    if r == "notFound":
        return ApiError(404, "transcript.missing", "no transcript for this session")
    if r == "busy":
        return ApiError(503, "transcript.busy", "recordings are busy; retry in a few seconds",
                        headers={"Retry-After": "5"})
    if r == "corrupt":
        return ApiError(500, "transcript.corrupt", "this recording failed its integrity check")
    if r == "damaged":
        return ApiError(500, "transcript.damaged", "this recording is damaged")
    if r == "quarantined":
        return ApiError(423, "transcript.quarantined", "this recording is quarantined")
    if r == "keyError":
        return ApiError(500, "transcript.keyError", "the key of this recording cannot be used")
    if r == "downgrade":
        return ApiError(500, "transcript.downgrade", "refused: a plaintext copy of an encrypted recording")
    if r == "limitExceeded":
        return ApiError(413, "transcript.limitExceeded", "this recording is too large for this view")
    return ApiError(503, "transcript.unavailable", "the recording is unavailable right now")


async def _tx_user_access(request: Request, sid: str, route: str):
    """The authenticated recording routes' authorization, re-run with the counters captured first."""
    for _attempt in (0, 1):
        snap = txhub.snapshot()
        tok = request.cookies.get(security.COOKIE_NAME)
        user = await security.user_for_token(tok)
        if not user:
            raise ApiError(401, "auth.required", "not authenticated")
        srow = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
        if not srow:
            raise ApiError(404, "session.missing", "no such session")
        g = await authz.grants_for_user(user["id"])
        if "recording.view" not in await authz.perms_on(g, srow["host_id"]):
            raise ApiError(404, "session.missing", "no such session")
        await stepup.require_session_host_stepup(sid, user)
        limits = await txhub.web_session_limits(tok, g)
        hrow = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", srow["host_id"])
        if hrow is not None and hrow["require_2fa"]:
            limits.append(txhub.stepup_deadline(user["id"], srow["host_id"]))
        acc = txhub.access_since(snap, sid, "user:%d" % user["id"], route,
                                 not_after=txhub.earliest(limits))
        if acc is not None:
            return acc
    raise txstore.Revoked("revoked", "access changed during the authorization")


async def _tx_open(sid: str, kind: str, grant):
    st = txhub.store()
    try:
        return await st.open(sid, kind, access=await grant.authorize(), reauthorize=grant.authorize)
    except (txstore.TxStoreError, ApiError) as e:
        raise _tx_api_error(e) from None


async def _tx_emit_ready(grant, on_refuse) -> None:
    """Before the status line of an in-memory body: the authorization still holds (H2). A refusal
    here is a clean error response; after the headers each chunk is checked (`txhub.emit_chunks`)."""
    if not await grant.before_emit():
        raise on_refuse(txstore.Revoked("revoked", "access changed before emission"))


async def _tx_transcript(request: Request, sid: str, fmt: str, tail: bool):
    """Download (`out`/`cast`, streamed, one Range on PLAINTEXT offsets, no ETag yet) or the text
    view, from the committed recording."""
    kind = "cast" if fmt == "cast" else "out"
    route = "transcript-txt" if fmt == "txt" else "transcript-" + kind

    async def authorize():
        return await _tx_user_access(request, sid, route)
    grant = txhub.Grant(authorize)
    snap = await _tx_open(sid, kind, grant)
    if fmt == "txt":
        try:
            start = max(0, snap.length - TEXT_VIEW_TAIL) if tail else 0
            raw = await snap.read(start, snap.length, reauthorize=grant.authorize)
        except (txstore.TxStoreError, ApiError) as e:
            raise _tx_api_error(e) from None
        finally:
            snap.close()
        text = (await asyncio.to_thread(core.text_of_output, raw)).encode("utf-8")
        del raw
        # H2: conversia a durat (worker): autorizarea se re-verifică înainte de antete şi apoi
        # înaintea fiecărei bucăţi; un refuz nu emite nimic din textul acumulat
        await _tx_emit_ready(grant, _tx_api_error)
        headers = {"Cache-Control": "no-store", "Content-Length": str(len(text))}
        if not tail:
            headers["Content-Disposition"] = 'attachment; filename="%s.txt"' % sid[:8]
        return StreamingResponse(txhub.emit_chunks(grant, text),
                                 media_type="text/plain; charset=utf-8", headers=headers)
    length = snap.length
    status, start, end = txstore.parse_range(request.headers.get("range"), length)
    if request.headers.get("if-range"):
        status, start, end = 200, 0, length   # fără ETag încă: un If-Range nu se poate potrivi
    if status == 416:
        snap.close()
        return Response(status_code=416, headers={"Content-Range": "bytes */%d" % length,
                                                  "Cache-Control": "no-store"})
    it = snap.iter(start, end, reauthorize=grant.authorize)
    first = None
    try:
        if end > start:
            # antetele pleacă abia după ce parse-ul până la primul octet întors s-a verificat
            first = await it.__anext__()
    except StopAsyncIteration:
        first = None
    except BaseException as e:
        await it.aclose()
        snap.close()
        if isinstance(e, (txstore.TxStoreError, ApiError)):
            raise _tx_api_error(e) from None
        raise
    headers = {"Accept-Ranges": "bytes", "Cache-Control": "no-store",
               "Content-Length": str(end - start),
               "Content-Disposition": 'attachment; filename="%s.%s"' % (sid[:8], fmt)}
    if status == 206:
        headers["Content-Range"] = "bytes %d-%d/%d" % (start, end - 1, length)
        # un interval e din octeţii în clar: GZipMiddleware nu are voie să-l re-codeze
        headers["Content-Encoding"] = "identity"

    async def body():
        try:
            if first is not None:
                yield first
            async for piece in it:
                yield piece
        except Exception as e:
            # după antete: conexiunea se taie (fără trailer), refuzul rămâne în jurnal
            log.warning("transcript stream %s aborted: %s", sid[:8], getattr(e, "reason", type(e).__name__))
            raise
        finally:
            await it.aclose()
            snap.close()
    return StreamingResponse(body(), status_code=status, media_type="application/octet-stream",
                             headers=headers)


async def _tx_preview(request: Request, sid: str):
    async def authorize():
        return await _tx_user_access(request, sid, "preview")
    grant = txhub.Grant(authorize)
    st = txhub.store()
    try:
        data, _e, _le = await st.tail(sid, "out", 32 * 1024, access=await grant.authorize(),
                                      reauthorize=grant.authorize)
    except (txstore.TxStoreError, ApiError) as e:
        if getattr(e, "reason", "") == "notFound":
            return Response(content=b"", media_type="application/octet-stream")  # ca read_tail
        raise _tx_api_error(e) from None
    data = core.ALT_SCREEN_RE.sub(b"", data)
    await _tx_emit_ready(grant, _tx_api_error)
    return StreamingResponse(txhub.emit_chunks(grant, data), media_type="application/octet-stream",
                             headers={"Cache-Control": "no-store", "Content-Length": str(len(data))})


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


_LABEL_BAD = re.compile(r"[\x00-\x1f\x7f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


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
    row = await db.fetchone("SELECT id, host_id, state, title, origin FROM sessions WHERE id=?", sid)
    if not row:
        raise ApiError(404, "session.missing", "no such session")
    # 3.6: înregistrarea ALTCUIVA nu se publică fără session.manage pe host
    await sessctl.require_session_control(request, sid, user)
    # aceeaşi poartă ca GET /transcript: pe un host 2FA, a scoate înregistrarea din instanţă
    # (şi încă printr-un link fără cont) cere al doilea factor
    await stepup.require_host_stepup(row["host_id"], user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    # audit 2026-11-18: un terminal ROOT de pe hostul gateway-ului (reînnoire certificate, reparaţii
    # din System health) rămâne privat şi după ce s-a închis — înregistrarea lui nu iese ca link
    # public, la fel cum terminalul viu nu se partajează (sessctl.ROOT_TERMINAL_ORIGINS). Abia după
    # controlul sesiunii şi step-up: cine n-are voie nu află nici ce fel de sesiune e.
    if sessctl.session_origin(row) in sessctl.ROOT_TERMINAL_ORIGINS:
        raise ApiError(403, "replay.privateSession",
                       "the recording of a maintenance terminal cannot be shared")
    if row["state"] != "closed":
        raise ApiError(409, "replay.notClosed",
                       "only the recording of a closed session can be shared")
    if not await _recording_exists(sid):
        raise ApiError(404, "transcript.missing", "no transcript for this session")
    if body.expires_hours not in replay.EXPIRY_HOURS:
        raise ApiError(400, "replay.badExpiry", "expiry must be 1 hour, 24 hours or 7 days")
    label = _LABEL_BAD.sub("", body.label or "").strip()[:replay.LABEL_MAX]
    now = time.time()
    await shares.delete_replay_links(" WHERE expires <= ?", now)
    token = security.new_token()
    expires = now + body.expires_hours * 3600
    # audit 2026-11-18: limitele se verifică în ACEEAŞI instrucţiune cu inserarea. Cu COUNT-uri
    # separate, două cereri simultane vedeau amândouă loc sub plafon şi inserau amândouă.
    # `expires > now`: plafonul numără doar link-uri active, oricât ar întârzia curăţarea.
    ins = await db.execute_returning(
        "INSERT INTO replay_links(token_hash, sid, user_id, label, redact, created, expires)"
        " SELECT ?,?,?,?,?,?,?"
        " WHERE (SELECT COUNT(*) FROM replay_links WHERE user_id=? AND expires > ?) < ?"
        " AND (SELECT COUNT(*) FROM replay_links WHERE user_id=? AND sid=? AND expires > ?) < ?"
        " RETURNING id",
        security.sha256_hex(token), sid, user["id"], label, 1 if body.redact else 0, now, expires,
        user["id"], now, replay.MAX_ACTIVE_PER_USER,
        user["id"], sid, now, replay.MAX_ACTIVE_PER_SESSION)
    if ins is None:
        raise ApiError(409, "replay.tooMany",
                       "too many active replay links — revoke some first")
    link_id = ins["id"]
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


async def _replay_issuer_ok(row, limits: Optional[list] = None) -> bool:
    """Emitentul are ACUM `share.replay` pe hostul înregistrării (cont activ, legături neexpirate:
    `grants_for_user` le citeşte pe toate) şi, dacă a publicat înregistrarea ALTCUIVA, şi
    `session.manage`, ca la creare. Sesiunea nu e un terminal root de mentenanţă (link-urile create
    înainte de regula de la creare cad şi ele aici). Orice lipsă = refuz.
    3.8 (M1): `limits` primeşte termenul CONSERVATOR al acestei decizii — cea mai apropiată expirare
    a legăturilor emitentului (aceleaşi grant-uri cu care s-a decis), ca fluxul să se re-autorizeze
    atunci, nu abia la expirarea link-ului."""
    if sessctl.session_origin(row) in sessctl.ROOT_TERMINAL_ORIGINS:
        return False
    if row["host_id"] is None or row["user_id"] is None:
        return False
    g = await authz.grants_for_user(row["user_id"])
    have = await authz.perms_on(g, row["host_id"])
    ok = "share.replay" in have and \
        shares.may_publish_recording(have, row["s_created_by_id"], row["user_id"])
    if ok and limits is not None:
        limits.append(authz.earliest_expiry(g.bindings))
    return ok


async def _recording_exists(sid: str) -> bool:
    """The `.cast` a replay link plays: the 3.7 file, or (txhub active) an `ok` descriptor that is
    not erased / quarantined / in recovery."""
    if txhub.active():
        try:
            return await txhub.store().exists(sid, "cast")
        except Exception:                     # noqa: BLE001 — nesigur = nu există (acelaşi 404)
            return False
    return core.transcript_paths(sid)[1].exists()


async def _replay_row(h: str, limits: Optional[list] = None):
    """The link row for a token hash, with every check of `_replay_lookup` (also the re-check of a
    replay stream after a revocation bump); None = the same 404. `limits` (3.8): receives the
    deadlines of this decision (the link's expiry, the issuer's earliest binding expiry)."""
    row = await db.fetchone(
        "SELECT r.*, s.title, s.state, s.created AS s_created, s.closed_at, s.rows, s.cols,"
        " s.host_id, s.origin, s.created_by_id AS s_created_by_id, u.email AS owner_email"
        " FROM replay_links r JOIN sessions s ON s.id = r.sid"
        " LEFT JOIN users u ON u.id = r.user_id"
        " WHERE r.token_hash=? AND r.expires > ?", h, time.time())
    if row is not None and not security.tokens_equal(row["token_hash"], h):
        row = None
    if row is not None:
        if row["state"] != "closed" or not core.valid_sid(row["sid"]) \
                or not await _recording_exists(row["sid"]):
            row = None
    if row is not None and not await _replay_issuer_ok(row, limits):
        # INV-05 (docs/design/INVARIANTS.md): link-ul de replay moare cu dreptul celui care l-a dat, verificat la fiecare citire.
        # Curăţarea periodică (`revoke_unauthorized_derived`, expirarea rolurilor) rămâne, dar nu
        # mai e ea bariera: cu planificatorul oprit sau întârziat, linkul tot nu mai deschide nimic.
        await shares.delete_replay_links(" WHERE id=?", row["id"])
        row = None
    if row is not None and limits is not None:
        limits.append(row["expires"])
    return row


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
        row = await _replay_row(security.sha256_hex(token))
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
    if txhub.active():
        return await _tx_replay_cast(request, row)
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
    if txhub.active():
        return await _tx_replay_text(request, row)
    text = await asyncio.to_thread(core.transcript_text, row["sid"], TEXT_VIEW_TAIL)
    if row["redact"]:
        text = await asyncio.to_thread(replay.mask_secrets, text)
    await _replay_opened(request, row, "read as text")
    return Response(content=text, media_type="text/plain; charset=utf-8", headers=_REPLAY_HEADERS)


# ── [replay] 3.8: public replay readers on encrypted recordings ───────────────────────────────────
def _tx_link_authorizer(request: Request, row, route: str):
    """`Grant` from the LINK TOKEN (never from an authenticated download's authorization):
    counters captured first, then the link row re-checked (`_replay_row`: expiry, revocation,
    issuer's rights, recording state); `not_after` = the earliest of the link's expiry and the
    issuer's time-bound bindings (M1: the same grants the decision used)."""
    h = security.sha256_hex(request.headers.get("x-replay-token") or "")
    sid, link_id = row["sid"], row["id"]

    async def decide():
        limits = []
        r = await _replay_row(h, limits)
        if r is None or r["id"] != link_id or r["sid"] != sid:
            raise txstore.Revoked("revoked", "replay link no longer valid")
        return txhub.earliest(limits)
    return txhub.Grant(txhub.authorizer(sid, "replay-link:%d" % link_id, route, decide))


def _tx_link_error(request: Request, e) -> ApiError:
    """Every failure of a public replay read is the same 404 (no oracle), except a busy store."""
    if getattr(e, "reason", "") == "busy":
        return _tx_api_error(e)
    replay.record_miss(security.client_ip(request))
    return ApiError(404, "link.invalid", "invalid or expired link", headers=_REPLAY_HEADERS)


async def _tx_replay_cast(request: Request, row):
    """`.cast` from the decrypted logical stream (record boundaries invisible to the redaction);
    every emitted chunk (≤ 64 KiB) is checked against the revocation counters and the link expiry."""
    st = txhub.store()
    grant = _tx_link_authorizer(request, row, "replay-cast")
    try:
        snap = await st.open(row["sid"], "cast", access=await grant.authorize(),
                             reauthorize=grant.authorize)
    except (txstore.TxStoreError, ApiError) as e:
        raise _tx_link_error(request, e) from None
    try:
        if row["redact"]:
            cache = _REDACTED_CACHE.get(id(st))
            if cache is None:
                _REDACTED_CACHE.clear()
                cache = _REDACTED_CACHE[id(st)] = txstore.ResponseCache(st, size=1)
            key = cache.key(snap, replay.REDACTION_POLICY, representation="redacted")
            data = cache.get(key, snap.access)
            if data is None:
                raw = b"".join([c async for c in snap.iter(0, snap.length,
                                                          reauthorize=grant.authorize)])
                data = await asyncio.to_thread(replay.redact_cast, raw)
                cache.put(key, data, snap.access)
        else:
            data = None
            # brut: fluxul decriptat, verificat la fiecare chunk
            it = snap.iter(0, snap.length, reauthorize=grant.authorize)
            first = None
            try:
                first = await it.__anext__()
            except StopAsyncIteration:
                pass
    except (txstore.TxStoreError, ApiError) as e:
        snap.close()
        raise _tx_link_error(request, e) from None
    except BaseException:
        snap.close()
        raise
    if data is not None:
        snap.close()
        # (b) înainte de antete, apoi înaintea fiecărei bucăţi (txhub.emit_chunks)
        await _tx_emit_ready(grant, lambda e: _tx_link_error(request, e))
    await _replay_opened(request, row, "played")
    if data is not None:
        return StreamingResponse(txhub.emit_chunks(grant, data), media_type="application/octet-stream",
                                 headers={**_REPLAY_HEADERS, "Content-Length": str(len(data))})

    async def raw_body():
        try:
            if first is not None:
                yield first
            async for piece in it:
                yield piece
        finally:
            await it.aclose()
            snap.close()
    return StreamingResponse(raw_body(), media_type="application/octet-stream",
                             headers={**_REPLAY_HEADERS, "Content-Length": str(snap.length)})


async def _tx_replay_text(request: Request, row):
    st = txhub.store()
    grant = _tx_link_authorizer(request, row, "replay-text")
    try:
        snap = await st.open(row["sid"], "out", access=await grant.authorize(),
                             reauthorize=grant.authorize)
        try:
            raw = await snap.read(max(0, snap.length - TEXT_VIEW_TAIL), snap.length,
                                  reauthorize=grant.authorize)
        finally:
            snap.close()
    except (txstore.TxStoreError, ApiError) as e:
        raise _tx_link_error(request, e) from None
    text = await asyncio.to_thread(core.text_of_output, raw)
    del raw
    if row["redact"]:
        text = await asyncio.to_thread(replay.mask_secrets, text)
    body = text.encode("utf-8")
    del text
    # H2: conversia şi mascarea au durat — re-verificat înainte de antete şi pe fiecare bucată
    await _tx_emit_ready(grant, lambda e: _tx_link_error(request, e))
    await _replay_opened(request, row, "read as text")
    return StreamingResponse(txhub.emit_chunks(grant, body), media_type="text/plain; charset=utf-8",
                             headers={**_REPLAY_HEADERS, "Content-Length": str(len(body))})


# ── [replay] 3.8 PR6a: erasure and Owner recovery (ENCRYPTION-AT-REST.md §12.11.4, §12.11.8 Q1/Q2/Q4) ──
# Ştergerea (erasure) e o acţiune EXPLICITĂ de Owner cu factor proaspăt (Q1): tombstone în jurnalul
# WTJ1, cheia RK distrusă, fişierele retrase; supravieţuieşte restore-urilor. Owner recovery deschide
# doar carantina de CONTINUITATE (restore fără dovada ştergerilor), câte o înregistrare, fiecare
# citire auditată, fără share / link de replay / căutare pentru altcineva (Q4).


class EraseIn(BaseModel):
    confirm: str = ""             # tastat: primele 8 caractere ale sesiunii (nu un clic din greşeală)
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""


class RecoveryIn(BaseModel):
    confirm: str = ""             # recover: data backup-ului (YYYY-MM-DD), tastată
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""


def _erasure_error(e) -> ApiError:
    """erasure.ErasureError → the route's error (codes as literals: tests/i18n_catalog_test.py)."""
    c = getattr(e, "code", "")
    msg = str(e)
    if c == "session.live":
        return ApiError(409, "session.live", "the session is live; close it first")
    if c == "transcript.missing":
        return ApiError(404, "transcript.missing", "no transcript for this session")
    if c == "transcript.erasePlaintext":
        return ApiError(409, "transcript.erasePlaintext", msg)
    if c == "transcript.erasureJournalFull":
        return ApiError(507, "transcript.erasureJournalFull", msg)
    if c == "transcript.erasureJournalBroken":
        return ApiError(503, "transcript.erasureJournalBroken", msg)
    if c == "transcript.erasureUncertain":
        return ApiError(503, "transcript.erasureUncertain", msg)
    if c == "transcript.recoveryState":
        return ApiError(409, "transcript.recoveryState", msg)
    if c == "transcript.notRecoverable":
        return ApiError(409, "transcript.notRecoverable", msg)
    if c == "transcript.notFailed":
        return ApiError(409, "transcript.notFailed", msg)
    return ApiError(503, "transcript.erasureUnavailable", "erasure is not available on this volume")


def _erasure_store():
    st = txhub.store()
    if st is None or not erasure.active():
        raise ApiError(503, "transcript.erasureUnavailable", "erasure is not available on this volume")
    return st


async def _require_owner(user) -> None:
    """Owner @ all (not a custom copy, not a token): the erasure and recovery contract is the
    instance owner's (§12.11.8 Q1/Q4). The route's permission (`backups.manage`) is checked too."""
    if isinstance(user, dict) and user.get("is_token"):
        raise ApiError(403, "transcript.ownerOnly", "only an Owner can do this")
    if not await authz.is_owner_user(user["id"]):
        raise ApiError(403, "transcript.ownerOnly", "only an Owner can do this")


async def _owner_fresh_factor(user, sid: str, body) -> None:
    await _require_owner(user)
    srow = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
    # factor REAL proaspăt (passkey / TOTP / SSO), nu o fereastră veche şi nu parola singură
    await stepup.require_fresh_factor(srow["host_id"] if srow else 0, user, body.stepup_grant,
                                      body.stepup_password, body.stepup_totp, real_factor=True)


@router.post("/api/sessions/{sid}/erase")
async def erase_recording(sid: str, body: EraseIn, request: Request,
                          user=Depends(authz.perm('backups.manage'))):
    """Erase a closed session's recording for good (survives restores; §12.11.4). Owner, fresh factor,
    typed confirmation. `attested: false` = done on this volume, not yet proven off-host (Q2);
    `state: journalled` = durable in the journal, the database step completes at the next boot."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    st = _erasure_store()
    if body.confirm.strip() != sid[:8]:
        raise ApiError(400, "transcript.eraseConfirm", "type the first 8 characters of the session id to confirm")
    row = await db.fetchone("SELECT state FROM sessions WHERE id=?", sid)
    if row is not None and row["state"] in ("creating", "live"):
        raise ApiError(409, "session.live", "the session is live; close it first")
    await _owner_fresh_factor(user, sid, body)
    try:
        res = await erasure.erase(st, sid)
    except erasure.ErasureError as e:
        raise _erasure_error(e) from None
    hub = core.hubs.get(sid)
    if hub is not None:
        await hub.revoke_shares()             # invitaţii unui share (dacă mai există hub-ul) afară
    audit.detail(request, "recording erased (journal n=%d, %s, attested=%s)" % (res["n"], res["state"], res["attested"]))
    email_alerts.notify_security_change("a recording was erased (session %s)" % sid[:8],
                                        security.client_ip(request), user["email"], fleet=True,
                                        user_id=user["id"])
    return res


@router.get("/api/recordings/quarantine")
async def list_quarantined_recordings(user=Depends(authz.perm('backups.manage'))):
    """Recordings not served pending proof, with why (Owner only; metadata, no content)."""
    await _require_owner(user)
    st = _erasure_store()
    return await erasure.list_quarantined(st)


@router.post("/api/sessions/{sid}/recovery")
async def recover_recording(sid: str, body: RecoveryIn, request: Request,
                            user=Depends(authz.perm('backups.manage'))):
    """Owner recovery mode for ONE recording quarantined for missing erasure proof: → `recovery`
    (readable by Owners only, through the recovery route). Typed confirmation = the backup date."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    st = _erasure_store()
    cont = erasure.continuity()
    date = time.strftime("%Y-%m-%d", time.gmtime((cont or {}).get("since") or 0))
    if cont is None or body.confirm.strip() != date:
        raise ApiError(400, "transcript.recoveryConfirm",
                       "type the backup date to confirm that erasures after it cannot be re-applied")
    await _owner_fresh_factor(user, sid, body)
    try:
        kinds = await erasure.recover(st, sid)
    except erasure.ErasureError as e:
        raise _erasure_error(e) from None
    audit.detail(request, "owner recovery: recording %s opened without erasure proof (backup of %s)"
                 % (sid[:8], date))
    email_alerts.notify_security_change("a recording was recovered without erasure proof (session %s)"
                                        % sid[:8], security.client_ip(request), user["email"],
                                        fleet=True, user_id=user["id"])
    return {"ok": True, "status": "recovery", "kinds": kinds}


@router.post("/api/sessions/{sid}/recovery/release")
async def release_recording(sid: str, body: RecoveryIn, request: Request,
                            user=Depends(authz.perm('backups.manage'))):
    """recovery → normal access, one recording, an explicit Owner action with a fresh factor."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    st = _erasure_store()
    await _owner_fresh_factor(user, sid, body)
    try:
        kinds = await erasure.release(st, sid)
    except erasure.ErasureError as e:
        raise _erasure_error(e) from None
    audit.detail(request, "owner recovery: recording %s released to normal access" % sid[:8])
    email_alerts.notify_security_change("a recovered recording was released to normal access (session %s)"
                                        % sid[:8], security.client_ip(request), user["email"],
                                        fleet=True, user_id=user["id"])
    return {"ok": True, "status": "ok", "kinds": kinds}


@router.post("/api/sessions/{sid}/recovery/requarantine")
async def requarantine_recording(sid: str, request: Request,
                                 user=Depends(authz.perm('backups.manage'))):
    """recovery → quarantined again (reduces access: no fresh factor needed)."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    st = _erasure_store()
    await _require_owner(user)
    try:
        kinds = await erasure.requarantine(st, sid)
    except erasure.ErasureError as e:
        raise _erasure_error(e) from None
    audit.detail(request, "owner recovery: recording %s quarantined again" % sid[:8])
    return {"ok": True, "status": "quarantined", "kinds": kinds}


async def _recovery_decide(request: Request, uid_expected: int):
    """The recovery read's own decision, re-run at every re-authorization: the same cookie, still
    an Owner with `backups.manage`; the deadline = the web session's limits."""
    tok = request.cookies.get(security.COOKIE_NAME)
    user = await security.user_for_token(tok)
    if not user or user["id"] != uid_expected:
        raise txstore.Revoked("revoked", "web session ended")
    g = await authz.grants_for_user(user["id"])
    if "backups.manage" not in g.global_perms or not await authz.is_owner_user(user["id"]):
        raise txstore.Revoked("revoked", "no longer an Owner")
    return txhub.earliest(await txhub.web_session_limits(tok, g))


@router.get("/api/sessions/{sid}/recovery/transcript")
async def recovery_transcript(sid: str, request: Request, format: str = "out",
                              user=Depends(authz.perm('backups.manage'))):
    """Owner recovery read of a `recovery` recording (audited read, every time; streamed)."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    st = _erasure_store()
    await _require_owner(user)
    kind = "cast" if format == "cast" else "out"
    if (await erasure.status_of(st, sid)).get(kind) != "recovery":
        raise ApiError(409, "transcript.recoveryState", "this recording is not in recovery")
    uid = user["id"]

    async def decide():
        return await _recovery_decide(request, uid)
    grant = txhub.Grant(txhub.recovery_authorizer(sid, "owner:%d" % uid, decide))
    try:
        snap = await st.open(sid, kind, access=await grant.authorize(), reauthorize=grant.authorize)
    except (txstore.TxStoreError, ApiError) as e:
        raise _tx_api_error(e) from None
    audit.detail(request, "owner recovery read: recording %s.%s without erasure proof" % (sid[:8], kind))
    it = snap.iter(0, snap.length, reauthorize=grant.authorize)

    async def body():
        try:
            async for piece in it:
                yield piece
        except Exception as e:
            log.warning("recovery stream %s aborted: %s", sid[:8], getattr(e, "reason", type(e).__name__))
            raise
        finally:
            await it.aclose()
            snap.close()
    return StreamingResponse(body(), media_type="application/octet-stream",
                             headers={"Cache-Control": "no-store", "Content-Length": str(snap.length),
                                      "Content-Disposition": 'attachment; filename="%s.%s"' % (sid[:8], kind),
                                      "X-Recording-Recovery": "unproven"})


# ── [replay] 3.8 PR6c: Owner resolution of a failed plaintext migration (§12.11.12) ──
# Un rând `failed` blochează writer-ul sesiunii (textul clar nu se poate converti). Owner-ul (acelaşi
# contract ca ştergerea: backups.manage + Owner @ all + factor real proaspăt + audit) alege: retry
# (fişierul de acum, re-inventariat, convertit) sau discard (textul clar şters verificat + tombstone
# în jurnal: o ştergere). După oricare, writer-ul sesiunii poate porni.


def _migration_store():
    st = txhub.store()
    if st is None or not migration.active():
        raise ApiError(503, "transcript.migrationUnavailable", "the recording migration is not active")
    return st


@router.post("/api/recordings/migration/{sid}/retry")
async def retry_failed_migration(sid: str, body: RecoveryIn, request: Request,
                                 user=Depends(authz.perm('backups.manage'))):
    """Owner: convert a session's failed plaintext again, from the file now under its name."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    st = _migration_store()
    await _owner_fresh_factor(user, sid, body)
    srow = await db.fetchone("SELECT state FROM sessions WHERE id=?", sid)
    live = srow is not None and srow["state"] in ("creating", "live")
    try:
        states = await migration.retry(st, sid, live=live)
    except txstore.TxStoreError as e:
        if e.reason == "notFailed":
            raise ApiError(409, "transcript.notFailed", "no failed migration for this session") from None
        if e.reason == "encrypted":
            raise ApiError(409, "transcript.retryEncrypted", str(e)) from None
        if e.reason == "disabled":
            raise ApiError(503, "transcript.migrationUnavailable", "the recording migration is not active") from None
        raise ApiError(409, "transcript.retryFailed", "the migration failed again: %s" % e.reason) from None
    audit.detail(request, "owner: migration of recording %s retried → %s" % (
        sid[:8], ", ".join("%s=%s" % kv for kv in sorted(states.items()))))
    if any(v in ("failed", "pending", "orphan") for v in states.values()):
        raise ApiError(409, "transcript.retryFailed", "the migration did not complete; see System health")
    return {"ok": True, "kinds": states}


@router.post("/api/recordings/migration/{sid}/discard")
async def discard_failed_migration(sid: str, body: EraseIn, request: Request,
                                   user=Depends(authz.perm('backups.manage'))):
    """Owner: delete a session's failed plaintext (identity-checked) and tombstone the session in the
    erasure journal (an erasure: it survives restores). The session must be closed; typed
    confirmation = the first 8 characters of the session id."""
    if not core.valid_sid(sid):
        raise ApiError(404, "session.missing", "no such session")
    st = _erasure_store()
    _migration_store()
    if body.confirm.strip() != sid[:8]:
        raise ApiError(400, "transcript.eraseConfirm", "type the first 8 characters of the session id to confirm")
    row = await db.fetchone("SELECT state FROM sessions WHERE id=?", sid)
    if row is not None and row["state"] in ("creating", "live"):
        raise ApiError(409, "session.live", "the session is live; close it first")
    await _owner_fresh_factor(user, sid, body)
    try:
        res = await erasure.discard_failed(st, sid)
    except erasure.ErasureError as e:
        raise _erasure_error(e) from None
    except txstore.TxStoreError as e:
        raise ApiError(409, "transcript.retryFailed", "the plaintext could not be re-checked: %s" % e.reason) from None
    audit.detail(request, "owner: failed plaintext of recording %s discarded (journal n=%d, %s, plaintext %s)" % (
        sid[:8], res["n"], res["state"], ", ".join("%s=%s" % kv for kv in sorted(res["plaintext"].items()))))
    email_alerts.notify_security_change("a recording's unmigrated plaintext was discarded (session %s)" % sid[:8],
                                        security.client_ip(request), user["email"], fleet=True,
                                        user_id=user["id"])
    return res
