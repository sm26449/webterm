"""Backup / restore from Settings: download (passphrase-encrypted), restore and verify,
stored backups, the backup schedule with its persisted state and `scheduled_backup_tick` (called
by main.py's scheduler), and off-host backup (Google Drive / Dropbox, or direct SFTP / FTPS
targets). The archive format and crypto live in `backup.py`, the providers in `cloudbackup.py`.
Moved out of api.py; nothing here imports api.py.
"""
import asyncio
import html
import json
import logging
import os
import time
import urllib.parse

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel

from .errors import ApiError
from . import audit, authz, backup, bgtasks, cloudbackup, config, db, email_alerts, security, stepup, syshealth

log = logging.getLogger("webterm")
# Aceeaşi gardă ca api.router (fail-closed): o rută fără permisiune declarată → 500 authz.undeclared.
router = APIRouter(dependencies=[Depends(authz.declared)])


# ── [backup] Error mappers: backup.py / cloudbackup.py errors → stable codes ────────────

def _backup_value_error(e: Exception) -> ApiError:
    """ValueError din backup.py (parolă greşită / fişier corupt / arhivă-bombă / fără cheia
    seifului) → cod. Pe aceeaşi rută un singur status (400), deci codul e singura distincţie."""
    msg = str(e) or "invalid backup"
    low = msg.lower()
    if "passphrase" in low and "wrong" in low:
        code = "backup.badPassphrase"
    elif "too large" in low or "bomb" in low:
        code = "backup.tooLarge"
    elif "vault key" in low:
        code = "backup.noVaultKey"
    else:
        code = "backup.badFile"
    return ApiError(400, code, msg)


def _cloud_api_error(e: Exception) -> ApiError:
    """CloudError (provider/reţea/validare) → cod; detaliul providerului rămâne în `detail`."""
    msg = str(e) or "cloud backup failed"
    low = msg.lower()
    if "passphrase" in low:
        code = "backup.passphraseTooShort"
    elif "destination changed" in low:
        code = "cloud.retargetNeedsSecret"
    elif "was not seen for this server" in low:
        code = "cloud.hostKeyNotProbed"
    elif "alt" in low and "cheie de host" in low:
        code = "cloud.hostKeyMismatch"
    elif "host key" in low:
        code = "cloud.hostKeyRequired"
    elif "host and user" in low:
        code = "cloud.hostUserRequired"
    elif "refresh token" in low:
        code = "cloud.noRefreshToken"
    elif low.startswith("network"):
        code = "cloud.network"
    elif "necunoscut" in low or "unknown provider" in low:
        code = "cloud.badProvider"
    else:
        code = "cloud.failed"
    return ApiError(400, code, msg)


# ── [backup] Backup / restore (din Settings) ──────────────────────────────────────────
# Un backup conține cheia seifului (decriptează toate credențialele) → descărcările
# sunt MEREU criptate cu o parolă dată de user. Vezi backup.py.

class BackupIn(BaseModel):
    passphrase: str                 # parola de CRIPTARE a arhivei (o alegi acum)
    include_transcripts: bool = False
    current_password: str = ""      # parola CONTULUI — vezi stepup.require_reauth_for_secret


class RestoreIn(BaseModel):
    passphrase: str
    current_password: str = ""


class BackupScheduleIn(BaseModel):
    schedule: str = "off"          # off | daily | weekly
    include_transcripts: bool = False


def _backup_filename() -> str:
    return "webterm-backup-%s.wtbk" % time.strftime("%Y%m%d-%H%M%S")


# ── [backup] backup programat: scadenţă, rulare, stare persistată ────────────────────────
# Chei în app_settings (fără schimbare de schemă):
#   backup_last        ts al ultimului backup programat REUŞIT (scadenţa se calculează faţă de el)
#   backup_last_run    JSON {ts, ok, name, error}: ultima ÎNCERCARE, reuşită sau nu
#   backup_last_error  JSON {ts, error, stage}: ultimul eşec; GOLIT la următorul succes complet
#   backup_seen        ts până la care userul a „văzut" starea (stinge punctul de pe rotiţă)
_backup_lock = asyncio.Lock()           # niciodată două backup-uri simultan (tick + catch-up)


async def scheduled_backup_tick(now: float | None = None, force: bool = False) -> dict:
    """Un „tick" al scheduler-ului: dacă backup-ul programat e scadent, îl face ACUM.

    Scadenţa = faţă de ultimul backup REUŞIT (`backup.is_due`), nu faţă de boot — deci o
    rulare pierdută (gateway oprit / crash-loop / health-gate la deploy) se recuperează la
    primul tick după pornire (audit G-13). Eşecul se PERSISTĂ în `backup_last_error`, ridică
    punctul de notificare şi trimite alerta pe email/webhook (dacă sunt configurate); succesul
    complet (local + off-host, dacă există) îl goleşte. Întoarce un dict de diagnostic
    (`skipped` / `ok` / `error`) — util testelor şi logului."""
    now = time.time() if now is None else now
    sched = await db.get_setting("backup_schedule", "off")
    if sched not in ("daily", "weekly") and not force:
        return {"skipped": "off"}
    last_ok = float(await db.get_setting("backup_last", "0") or 0)
    if not force and not backup.is_due(sched, last_ok, now):
        return {"skipped": "not_due", "next_due": backup.next_due(sched, last_ok, now)}
    if _backup_lock.locked():
        return {"skipped": "running"}       # un alt tick (sau un catch-up) e deja în lucru
    async with _backup_lock:
        inc = (await db.get_setting("backup_include_tx", "0")) == "1"
        try:
            name = await asyncio.to_thread(backup.run_scheduled_backup, inc)
        except Exception as e:              # noqa: BLE001 — orice eşec trebuie VĂZUT, nu doar logat
            err = str(e)[:300] or e.__class__.__name__
            log.exception("the scheduled backup failed")
            await db.set_setting("backup_last_run", json.dumps(
                {"ts": now, "ok": False, "name": "", "error": err}))
            await db.set_setting("backup_last_error", json.dumps(
                {"ts": now, "error": err, "stage": "snapshot"}))
            try:
                email_alerts.notify_local_backup_failed(err, last_ok)
            except Exception:               # noqa: BLE001 — alerta nu rupe programarea
                log.exception("backup-failure alert could not be sent")
            return {"error": err}
        await db.set_setting("backup_last", str(now))
        await db.set_setting("backup_last_run", json.dumps(
            {"ts": now, "ok": True, "name": name, "error": ""}))
        log.info("scheduled backup (%s) written: %s", sched, name)
        # copie off-host, dacă e configurat un cloud: criptată cu parola userului; eşecul
        # NU invalidează backup-ul local, dar apare ca eroare (cu destinaţia) şi în secţiunea
        # de backup, nu doar în cea de cloud (audit G-14 / UX §7.f2)
        cloud_err = await cloudbackup.upload_scheduled(name)
        if cloud_err:
            await db.set_setting("backup_last_error", json.dumps(
                {"ts": time.time(), "error": cloud_err, "stage": "cloud"}))
            return {"ok": True, "name": name, "error": cloud_err}
        await db.set_setting("backup_last_error", "")
        return {"ok": True, "name": name}


@router.get("/api/backup/status")
async def backup_status(user=Depends(authz.perm('backups.manage'))):
    sched = await db.get_setting("backup_schedule", "off")
    last = float(await db.get_setting("backup_last", "0") or 0)
    return {
        "schedule": sched,
        "include_transcripts": (await db.get_setting("backup_include_tx", "0")) == "1",
        "last_scheduled": last,
        "last_run": (await db.get_json_setting("backup_last_run")) or None,
        "last_error": (await db.get_json_setting("backup_last_error")) or None,
        "next_due": backup.next_due(sched, last),
        "backups": backup.list_backups(),
        "retention_days": backup.RETENTION_DAYS,
        "restore_verified_at": float(await db.get_setting(syshealth.K_RESTORE_VERIFIED, "0") or 0) or None,
    }


@router.post("/api/backup/download")
async def backup_download(body: BackupIn, user=Depends(authz.perm('backups.manage'))):
    await stepup.require_reauth_for_secret(user, body.current_password, "downloading the backup")
    if len(body.passphrase) < 8:
        raise ApiError(400, "backup.passphraseTooShort", "the encryption passphrase must be at least 8 characters")
    try:
        blob = await asyncio.to_thread(backup.make_encrypted, body.passphrase, body.include_transcripts)
    except Exception as e:
        log.exception("backup failed")
        raise ApiError(500, "backup.failed", "backup failed: %s" % e)
    return Response(content=blob, media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % _backup_filename()})


@router.post("/api/backup/stored/{name}/download")
async def backup_download_stored(name: str, body: RestoreIn, user=Depends(authz.perm('backups.manage'))):
    await stepup.require_reauth_for_secret(user, body.current_password, "downloading the backup")
    if len(body.passphrase) < 8:
        raise ApiError(400, "backup.passphraseTooShort", "the encryption passphrase must be at least 8 characters")
    try:
        blob = await asyncio.to_thread(backup.encrypt_stored, name, body.passphrase)
    except FileNotFoundError:
        raise ApiError(404, "backup.missing", "no such backup")
    except ValueError as e:
        raise _backup_value_error(e)
    return Response(content=blob, media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % _backup_filename()})


@router.post("/api/backup/restore")
async def backup_restore(request: Request, user=Depends(authz.perm('backups.manage'))):
    # Fișierul .wtbk vine ca body brut (octet-stream), parola într-un header — evităm
    # dependența python-multipart; parola e a userului, peste HTTPS, într-un header pe
    # care reverse-proxy-ul nu-l loghează.
    passphrase = urllib.parse.unquote(request.headers.get("X-Restore-Pass", ""))
    if not passphrase:
        raise ApiError(400, "backup.passphraseMissing", "the backup passphrase is missing")
    # restore = ÎNLOCUIREA bazei de date, deci şi a conturilor: cu un cookie furat, cineva
    # ar putea încărca o arhivă a lui şi ar prelua instanţa. Aceeaşi clasă cu descărcarea.
    await stepup.require_reauth_for_secret(
        user, urllib.parse.unquote(request.headers.get("X-Reauth-Pass", "")), "restore")
    data = await request.body()
    if len(data) > 512 * 1024 * 1024:
        raise ApiError(413, "backup.tooLarge", "file too large")
    if not data:
        raise ApiError(400, "backup.emptyFile", "empty file")
    try:
        info = await asyncio.to_thread(backup.stage_restore, data, passphrase)
    except ValueError as e:
        raise _backup_value_error(e)           # parolă greșită / fișier corupt / DB invalid
    except Exception as e:
        log.exception("restore failed")
        raise ApiError(500, "backup.restoreFailed", "restore failed: %s" % e)
    # aplicarea reală se face la boot (apply_pending_restore) după restart. Repornim
    # procesul după ce răspunsul pleacă — containerul (restart: unless-stopped) revine.
    async def _restart_soon():
        await asyncio.sleep(1.0)
        log.warning("restart to apply the restore")
        os._exit(0)
    bgtasks.spawn(_restart_soon(), "restart after restore")
    return {"ok": True, "restarting": True, **info}


async def _restore_verified(request: Request, what: str) -> None:
    """3.6.8: a backup that was never restored is a hope, not a backup. A successful verification
    is recorded (System health → "backup.restore") and audited."""
    await db.set_setting(syshealth.K_RESTORE_VERIFIED, str(time.time()))
    audit.detail(request, "backup verified (decrypted, unpacked, database integrity OK): %s" % what)


@router.post("/api/backup/stored/{name}/verify")
async def backup_verify_stored(name: str, request: Request,
                               user=Depends(authz.perm('backups.manage'))):
    """Verify a stored scheduled snapshot: unpack + `PRAGMA integrity_check` + the vault key is
    there. Nothing is restored, nothing leaves the server."""
    try:
        info = await asyncio.to_thread(backup.verify_stored, name)
    except FileNotFoundError:
        raise ApiError(404, "backup.missing", "no such backup")
    except ValueError as e:
        raise _backup_value_error(e)
    await _restore_verified(request, name[:80])
    return {"ok": True, **info}


@router.post("/api/backup/verify")
async def backup_verify_upload(request: Request, user=Depends(authz.perm('backups.manage'))):
    """Verify a downloaded .wtbk (the file in the body, the passphrase in X-Restore-Pass, like
    restore): decrypt + unpack + integrity check, WITHOUT staging anything."""
    passphrase = urllib.parse.unquote(request.headers.get("X-Restore-Pass", ""))
    if not passphrase:
        raise ApiError(400, "backup.passphraseMissing", "the backup passphrase is missing")
    data = await request.body()
    if len(data) > 512 * 1024 * 1024:
        raise ApiError(413, "backup.tooLarge", "file too large")
    if not data:
        raise ApiError(400, "backup.emptyFile", "empty file")
    try:
        info = await asyncio.to_thread(backup.verify_restorable, data, passphrase)
    except ValueError as e:
        raise _backup_value_error(e)
    await _restore_verified(request, "uploaded file")
    return {"ok": True, **info}


@router.post("/api/backup/schedule")
async def backup_schedule(body: BackupScheduleIn, user=Depends(authz.perm('backups.manage'))):
    if body.schedule not in ("off", "daily", "weekly"):
        raise ApiError(400, "backup.badSchedule", "invalid schedule (off/daily/weekly)")
    await db.set_setting("backup_schedule", body.schedule)
    await db.set_setting("backup_include_tx", "1" if body.include_transcripts else "0")
    return await backup_status(user)


@router.delete("/api/backup/stored/{name}")
async def backup_delete_stored(name: str, user=Depends(authz.perm('backups.manage'))):
    if "/" in name or "\\" in name or not name.endswith((".wtsnap", backup.WTS_EXT)):
        raise ApiError(400, "generic.badName", "invalid name")
    p = config.DATA_DIR / "backups" / name
    try:
        p.unlink()
    except FileNotFoundError:
        raise ApiError(404, "backup.missing", "no such backup")
    return {"ok": True}


@router.post("/api/backup/seen")
async def backup_seen(user=Depends(authz.perm('backups.manage'))):
    # „văzut" acoperă şi ultimul eşec, nu doar ultimul succes (tab-ul Backup arată ambele)
    last = float(await db.get_setting("backup_last", "0") or 0)
    err_ts = float((await db.get_json_setting("backup_last_error")).get("ts") or 0)
    await db.set_setting("backup_seen", str(max(last, err_ts)))
    return {"ok": True}


# ── [backup] Backup off-host în cloud (Google Drive / Dropbox) ────────────────────────
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


class DirectConfigIn(BaseModel):
    kind: str                      # "sftp" | "ftps"
    host: str
    port: int = 0
    user: str
    path: str = ""
    ssh_key: str = ""              # gol la re-salvare = păstrează secretul existent
    password: str = ""
    hostkey: str = ""              # cheia de host confirmată (din /probe) — obligatorie prima dată la sftp
    ca: str = ""                   # opţional: CA/cert PEM pentru FTPS self-signed
    passphrase: str = ""
    keep: int = cloudbackup.DEFAULT_KEEP
    include_transcripts: bool = False
    current_password: str = ""     # re-auth: la fel ca la cloud — un canal permanent de ieşire


class ProbeIn(BaseModel):
    host: str
    port: int = 0
    user: str
    ssh_key: str = ""
    password: str = ""
    trust_hostkey: str = ""        # lot 3: cheia confirmată vizual — abia cu ea pleacă parola
    current_password: str = ""


@router.get("/api/backup/cloud")
async def cloud_status(user=Depends(authz.perm('backups.manage'))):
    return await cloudbackup.status()


@router.post("/api/backup/cloud/config")
async def cloud_config(body: CloudConfigIn, user=Depends(authz.perm('backups.manage'))):
    # Aceeași poartă ca la passkey/2FA: cine are cookie-ul, dar nu parola, nu poate
    # deschide o cale prin care backup-urile (cheia seifului) pleacă spre contul lui.
    if not await stepup.verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongPassword", "wrong password")
    try:
        await cloudbackup.save_config(body.provider, body.client_id, body.client_secret,
                                      body.passphrase, body.keep, body.include_transcripts)
    except cloudbackup.CloudError as e:
        raise _cloud_api_error(e)
    return await cloudbackup.status()


@router.post("/api/backup/cloud/probe")
async def cloud_probe(body: ProbeIn, request: Request, user=Depends(authz.perm('backups.manage'))):
    """SFTP TOFU: testează conexiunea + întoarce amprenta host-key-ului de confirmat. Re-auth ca la
    config: cine are doar cookie-ul nu poate sonda servere arbitrare cu credenţiale scrise aici."""
    if not await stepup.verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongPassword", "wrong password")
    try:
        return await cloudbackup.probe(body.host, body.port, body.user, body.ssh_key, body.password,
                                       body.trust_hostkey)
    except cloudbackup.CloudError as e:
        raise _cloud_api_error(e)


@router.post("/api/backup/cloud/direct")
async def cloud_config_direct(body: DirectConfigIn, request: Request,
                              user=Depends(authz.perm('backups.manage'))):
    """Configurează o destinaţie DIRECTĂ (SFTP/FTPS). Aceeaşi poartă de re-auth ca la cloud: un
    cookie furat nu trebuie să poată deschide o cale prin care backup-urile (cheia seifului) pleacă
    spre serverul atacatorului. Auditat."""
    if not await stepup.verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongPassword", "wrong password")
    try:
        await cloudbackup.save_config_direct(
            body.kind, body.host, body.port, body.user, body.path, body.ssh_key, body.password,
            body.hostkey, body.ca, body.passphrase, body.keep, body.include_transcripts)
    except cloudbackup.CloudError as e:
        raise _cloud_api_error(e)
    await audit.record(time.time(), user["email"], security.client_ip(request), "POST",
                       "/api/backup/cloud/direct", 200,
                       "destinaţie backup %s setată: %s@%s" % (body.kind, body.user, body.host))
    return await cloudbackup.status()


@router.get("/api/backup/cloud/authorize")
async def cloud_authorize(user=Depends(authz.perm('backups.manage'))):
    try:
        return {"url": await cloudbackup.authorize_url(user["id"])}
    except cloudbackup.CloudError as e:
        raise _cloud_api_error(e)


@router.get("/api/backup/cloud/callback")
async def cloud_callback(code: str = "", state: str = "", error: str = "",
                         user=Depends(authz.perm('backups.manage'))):
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
async def cloud_upload_now(user=Depends(authz.perm('backups.manage'))):
    try:
        name = await cloudbackup.upload_backup()
    except cloudbackup.CloudError as e:
        raise _cloud_api_error(e)
    return {"ok": True, "name": name, "status": await cloudbackup.status()}


@router.post("/api/backup/cloud/disconnect")
async def cloud_disconnect(user=Depends(authz.perm('backups.manage'))):
    await cloudbackup.disconnect()
    return await cloudbackup.status()
