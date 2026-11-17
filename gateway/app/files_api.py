"""Files on a host: browse, cwd, download (ranges + ETag), folder archive, resumable upload (status /
commit / abort), mkdir / rename / delete, the editor preview, upload-and-move-as-root (`root-move`:
staged in the agent's inbox, SHA-256-bound, the `sudo` command typed into the person's terminal,
never run), and the server-side host-to-host copy (`/api/fs/copy`, jobs in `fscopy.py`). Agent
file errors become stable codes in `fserrors.py`. Moved out of api.py; nothing here imports api.py.
"""
import asyncio
import logging
import os
import time
from email.utils import formatdate
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from .errors import ApiError
from . import audit, authz, conntypes, core, db, fscopy, fserrors, rootmove, security, stepup

log = logging.getLogger("webterm")
# Aceeaşi gardă ca api.router (fail-closed): o rută fără permisiune declarată → 500 authz.undeclared.
router = APIRouter(dependencies=[Depends(authz.declared)])


# task-uri de fundal fire-and-forget (ex. curăţenie după un răspuns anulat) — ţinem referinţe
# ca event loop-ul să nu le colecteze înainte să ruleze
_bg_tasks: set = set()


# ── [files] Browse, download, archive, resumable upload ────────────────────────────────────────

@router.get("/api/hosts/{host_id}/fs")
async def fs_list(host_id: int, path: str = "~", user=Depends(authz.perm('files.read', host='host_id'))):
    await stepup.require_host_stepup(host_id, user)   # H1
    try:
        return await core.fs_list(host_id, path)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise fserrors.file_api_error(e)


@router.get("/api/hosts/{host_id}/fs/cwd")
async def fs_cwd(host_id: int, sid: str, user=Depends(authz.perm('files.read', host='host_id'))):
    """The session shell's cwd (so the panel opens where you actually are)."""
    await stepup.require_host_stepup(host_id, user)   # H1
    try:
        return {"cwd": await core.session_cwd(host_id, sid)}
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise fserrors.file_api_error(e)


def _parse_range(header: str, size: int):
    """Un singur interval `bytes=start-end` / `bytes=start-` / `bytes=-suffix` → (start, end_inclusive)
    sau None dacă lipseşte / e nevalid / nesatisfăcut (apelantul întoarce 200 întreg, resp. 416).
    Mai multe intervale nu se suportă (download-ul resumabil cere mereu unul singur)."""
    if not header or not header.strip().lower().startswith("bytes="):
        return None
    spec = header.split("=", 1)[1].strip()
    if "," in spec:
        return None
    lo, _, hi = spec.partition("-")
    try:
        if lo == "":                       # suffix: ultimii N octeţi
            n = int(hi)
            if n <= 0:
                return None
            return (max(0, size - n), size - 1)
        start = int(lo)
        end = int(hi) if hi != "" else size - 1
    except ValueError:
        return None
    if start < 0 or start >= size or end < start:
        return "unsatisfiable"
    return (start, min(end, size - 1))


def download_etag(size, mtime) -> Optional[str]:
    """ETag slab `W/"<size>-<mtime>"` din `fs_stat` — None dacă lipseşte oricare (agent vechi,
    symlink): fără validator, clientul nu oferă reluare după reload."""
    if size is None or mtime is None:
        return None
    return 'W/"%d-%d"' % (int(size), int(mtime))


@router.get("/api/hosts/{host_id}/fs/download")
async def fs_download(host_id: int, request: Request, path: str, user=Depends(authz.perm('files.read', host='host_id'))):
    """Streamează un fişier de pe host. Suportă `Range: bytes=start-[end]` (HTTP 206) ca motorul de
    transfer din browser (phase 2) să descarce în felii, cu progres, retry şi reluare de la offset.
    Fără Range (sau pe agenţi fără fs_stat) → 200 întreg, exact ca înainte. Nu schimbă agentul:
    fs_read citeşte deja de la orice offset."""
    await stepup.require_host_stepup(host_id, user)   # H1
    from fastapi.responses import StreamingResponse
    name = os.path.basename(path.rstrip("/")) or "download"
    # un nume de fișier ostil (ghilimele/newline) ar sparge headerul
    # Content-Disposition → curățăm caracterele periculoase
    name = name.replace('"', "").replace("\r", "").replace("\n", "").replace("\\", "")

    # Dimensiunea (dacă o putem afla ieftin) deschide Range + Content-Length. Best-effort: dacă
    # fs_stat nu există / eşuează, cădem pe streamingul de dintotdeauna, fără Range.
    size = mtime = None
    try:
        st = await core.fs_stat_file(host_id, path)
        if st:
            size, mtime = st
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError):
        size = None

    rng = _parse_range(request.headers.get("range", ""), size) if size is not None else None
    if rng == "unsatisfiable":
        raise ApiError(416, "files.rangeNotSatisfiable", "requested range not satisfiable")

    start, end = (rng if isinstance(rng, tuple) else (0, (size - 1) if size else 0))
    limit = (end - start + 1) if isinstance(rng, tuple) else None

    try:
        # probe first chunk so errors surface as HTTP status, not mid-stream
        agen = core.fs_read_all(host_id, path, start=start, limit=limit)
        first = await agen.__anext__()
    except StopAsyncIteration:
        first = b""
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except TimeoutError:
        raise ApiError(504, "files.timeout", "the host is not responding")
    except core.FileError as e:
        raise fserrors.file_api_error(e)

    async def body():
        yield first
        async for chunk in agen:
            yield chunk

    headers = {"Content-Disposition": f'attachment; filename="{name}"'}
    if size is not None:
        headers["Accept-Ranges"] = "bytes"          # anunţă clientului că poate cere felii
    etag = download_etag(size, mtime)
    if etag:
        # Validatorul pentru reluarea DUPĂ RELOAD (3.5.13): browserul ţine în IndexedDB ETag-ul de
        # la începutul descărcării şi îl compară cu cel al fiecărui răspuns 206 — dacă fişierul de pe
        # host s-a schimbat între timp (alt size sau alt mtime), nu lipeşte octeţi noi peste cei
        # vechi, ci cere „Start over". Slab (W/): size+mtime nu garantează octeţi identici (o
        # rescriere în aceeaşi secundă cu aceeaşi mărime trece), dar e tot ce dă `fs_stat` fără un
        # hash pe host — iar un hash al unui fişier de 40 GB la fiecare felie nu e o opţiune.
        headers["ETag"] = etag
        headers["Last-Modified"] = formatdate(mtime, usegmt=True)
    if isinstance(rng, tuple):
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"
        headers["Content-Length"] = str(limit)
        status = 206
    else:
        if size is not None:
            headers["Content-Length"] = str(size)
        status = 200

    return StreamingResponse(
        body(), status_code=status, media_type="application/octet-stream", headers=headers)


@router.get("/api/hosts/{host_id}/fs/archive")
async def fs_archive(host_id: int, path: str, user=Depends(authz.perm('files.read', host='host_id'))):
    """Descarcă un fişier sau un DIRECTOR ca tar.gz. Arhiva se face pe host (tar prin op-ul
    `run` — agentul rămâne neschimbat), curge prin acelaşi streaming ca /fs/download, iar
    temp-ul de pe host se şterge când transferul se termină (sau pică)."""
    await stepup.require_host_stepup(host_id, user)
    from fastapi.responses import StreamingResponse
    name = os.path.basename(path.rstrip("/")) or "archive"
    name = name.replace('"', "").replace("\r", "").replace("\n", "").replace("\\", "") + ".tgz"
    tmp = None
    try:
        tmp = await core.fs_archive_prepare(host_id, path)
        # primul chunk ÎNAINTE de StreamingResponse: erorile devin status HTTP, nu stream rupt
        agen = core.fs_read_all(host_id, tmp)
        try:
            first = await agen.__anext__()
        except StopAsyncIteration:
            first = b""
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")   # agent plecat: temp inaccesibil oricum
    except (TimeoutError, core.FileError) as e:
        # arhiva s-a creat pe host dar citirea primului chunk a eşuat (host lent / eroare de citire),
        # iar `body()` nu se mai execută niciodată → temp-ul ar rămâne orfan (n-are GC). Curăţăm aici.
        if tmp:
            task = asyncio.ensure_future(core.fs_archive_cleanup(host_id, tmp))
            _bg_tasks.add(task); task.add_done_callback(_bg_tasks.discard)
        raise fserrors.file_api_error(e, 504 if isinstance(e, TimeoutError) else 400)

    async def body():
        try:
            yield first
            async for chunk in agen:
                yield chunk
        finally:
            # şi la succes, şi la client care închide mid-stream: temp-ul nu rămâne pe host.
            # Task DETAŞAT: dacă clientul abandonează, Starlette anulează corpul cu CancelledError
            # chiar la `yield`, iar un `await` aici ar fi anulat înainte să apuce să trimită
            # fs_delete → temp orfan (nu există GC pentru .wtarch). Aşa ştergerea rulează pe buclă
            # independent de anularea răspunsului. Ţinem o referinţă ca task-ul să nu fie colectat.
            task = asyncio.ensure_future(core.fs_archive_cleanup(host_id, tmp))
            _bg_tasks.add(task)
            task.add_done_callback(_bg_tasks.discard)

    return StreamingResponse(
        body(), media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{name}"'})


# Rândul de audit se scrie la FINALUL feliei. O felie care se opreşte la mijlocul corpului (clientul
# a încetat să trimită — incidentul cu upload-ul de 17 GB oprit la felia 1579) nu lăsa deci NICIO
# urmă pe gateway: din log, serverul părea să nu fi primit nimic. O linie INFO la START, limitată
# la una la 10 s per upload (nu per felie: la 24 MB/s sunt 3 felii/s), spune cel puţin până unde
# a ajuns clientul şi când a amuţit.
_chunk_log_at: dict[str, float] = {}


def _check_upload_id(upload_id: str) -> None:
    """Validăm `upload_id` la GRANIŢA API — înainte de orice folosire. `core.upload_tmp` îl
    re-validează (apărare în adâncime), dar id-ul brut ajungea întâi în `_log_chunk_start`
    (`log.info(... upload_id=%s ...)`): un id cu `\\n`/`\\r` putea forja linii de log, iar unul
    arbitrar de lung umfla cheia din `_chunk_log_at`. Refuzăm devreme, cu ACELAŞI tipar strict
    (`core._UPLOAD_UID`) ca în core — o singură sursă de adevăr, fără regex-uri divergente."""
    if not core._UPLOAD_UID.match(upload_id or ""):
        raise ApiError(400, "files.badUpload", "invalid upload_id")


def _log_chunk_start(host_id: int, upload_id: str, offset: int) -> None:
    now = time.monotonic()
    if now - _chunk_log_at.get(upload_id, 0.0) < 10:
        return
    if len(_chunk_log_at) > 1000:            # upload-uri vechi: nu ţinem dict-ul la infinit
        for k, at in list(_chunk_log_at.items()):
            if now - at > 3600:
                _chunk_log_at.pop(k, None)
    _chunk_log_at[upload_id] = now
    log.info("fs upload chunk start host=%s upload_id=%s offset=%s", host_id, upload_id, offset)


@router.post("/api/hosts/{host_id}/fs/upload")
async def fs_upload(host_id: int, request: Request, path: str,
                    if_mtime: int | None = None, upload_id: str | None = None,
                    offset: int = 0, user=Depends(authz.perm('files.write', host='host_id'))):
    """Body is the raw file (or, cu `upload_id`, o FELIE care începe la `offset`).
    Fără `upload_id`: one-shot — stream + commit atomic (ca înainte). Cu `upload_id`: append
    la temp-ul resumabil, fără commit (vezi /commit). `if_mtime` (opțional): salvare cu
    verificare de conflict — refuză (409) dacă ținta s-a schimbat de când ai deschis-o."""
    audit.detail(request, path)
    await stepup.require_host_stepup(host_id, user)   # H1
    _check_staged_owner(host_id, path, user)    # a staged "move as root" file: its planner only
    if upload_id:
        _check_upload_id(upload_id)              # validează ÎNAINTE de log (anti log-injection) + core
        _log_chunk_start(host_id, upload_id, offset)
    async def source():
        async for chunk in request.stream():
            yield chunk
    try:
        if upload_id:
            total = await core.fs_upload_chunk(host_id, path, upload_id, offset, source(), user=user["id"])
            return {"ok": True, "offset": total}
        written = await core.fs_write_stream(host_id, path, source(), if_mtime=if_mtime)
        return {"ok": True, "written": written, "path": path}
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except core.UploadBusy as e:
        # Fereastra de reordonare e plină (upload pipelined: prea multe felii înaintea rândului lor).
        # 429 = backpressure, NU eroare: clientul dă un backoff scurt şi reîncearcă ACEEAŞI felie.
        raise ApiError(429, "files.uploadBusy", str(e))
    except core.FileConflict as e:
        raise fserrors.file_api_error(e)
    except (core.FileError, TimeoutError) as e:
        raise await fserrors.fs_write_error(host_id, e, path)


@router.get("/api/hosts/{host_id}/fs/upload/status")
async def fs_upload_status(host_id: int, path: str, upload_id: str,
                           user=Depends(authz.perm('files.write', host='host_id'))):
    """Câţi octeţi au aterizat deja pentru `upload_id` — clientul reia de acolo. Cu agent v55
    răspunsul include şi `crc32` (CRC-ul octeţilor deja pe disc), ca clientul să continue
    verificarea de integritate şi după un resume, nu doar pe upload-urile din offset 0."""
    await stepup.require_host_stepup(host_id, user)
    _check_upload_id(upload_id)
    _check_staged_owner(host_id, path, user)
    try:
        st = await core.fs_upload_status(host_id, path, upload_id, user=user["id"])
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise fserrors.file_api_error(e)
    return st


@router.post("/api/hosts/{host_id}/fs/upload/commit")
async def fs_upload_commit(host_id: int, request: Request, path: str, upload_id: str,
                           if_mtime: int | None = None, crc32: int | None = None,
                           user=Depends(authz.perm('files.write', host='host_id'))):
    """Finalizează un upload resumabil: rename atomic temp → ţintă. `crc32` (opţional): verificare
    de integritate — dacă nu se potriveşte, temp-ul e şters şi commit-ul eşuează (fişier corupt
    nu ajunge la ţintă)."""
    audit.detail(request, path)
    await stepup.require_host_stepup(host_id, user)
    _check_upload_id(upload_id)
    _check_staged_owner(host_id, path, user)
    try:
        written = await core.fs_upload_commit(host_id, path, upload_id, if_mtime=if_mtime, crc32=crc32,
                                              user=user["id"])
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except core.FileConflict as e:
        raise fserrors.file_api_error(e)
    except (core.FileError, TimeoutError) as e:
        raise await fserrors.fs_write_error(host_id, e, path, missing_is_dir=False)
    return {"ok": True, "written": written, "path": path}


@router.delete("/api/hosts/{host_id}/fs/upload")
async def fs_upload_abort(host_id: int, path: str, upload_id: str,
                          user=Depends(authz.perm('files.write', host='host_id'))):
    """Anulează un upload resumabil şi şterge temp-ul de pe host."""
    await stepup.require_host_stepup(host_id, user)
    _check_upload_id(upload_id)
    _check_staged_owner(host_id, path, user)
    try:
        await core.fs_upload_abort(host_id, path, upload_id, user=user["id"])
    except core.UploadForeign as e:
        raise fserrors.file_api_error(e)
    return {"ok": True}


# ── [files-root] Upload and move as root (3.6.9, rootmove.py) ────────────────────────────────────────
# Files writes as the agent's user. For a folder that user cannot write (root-owned
# /srv/bin/lists), the file is staged in the agent's inbox and the client TYPES — never runs — a
# `sudo` command into the person's own terminal. Two steps:
#   1. POST …/fs/root-move names the staging files (a plan). The bytes go through the normal
#      upload route (same `files.write`, same step-up); the gateway hashes them on the way
#      (core.stage_*), and only the planner may upload into a staged path while the plan lives;
#   2. POST …/fs/root-move/{plan_id}/command, after the uploads: the command. It reads each staged
#      file AS the agent's user and installs it only if its SHA-256 matches what passed through
#      here (the inbox belongs to that user, who could swap the file in between).
# The typing goes through the terminal's normal input path (same read-only checks as a
# keystroke). Nothing here runs anything on the host besides `mkdir -p ~/.webterm/inbox`.
class RootMoveIn(BaseModel):
    dir: str = Field(..., max_length=rootmove.MAX_PATH)
    names: list = Field(default_factory=list, max_length=rootmove.MAX_FILES)


async def _agent_user_of(host_id: int) -> str:
    """The agent's user as a validated plain user name, or 409 (fail closed: without it the
    command cannot read the staged files as that user)."""
    row = await db.fetchone("SELECT agent_user FROM hosts WHERE id=?", host_id)
    try:
        return rootmove.check_user((row["agent_user"] if row else None) or "")
    except rootmove.MoveError:
        raise ApiError(409, "files.rootMoveNoUser",
                       "the agent's user is unknown or not a plain user name")


def _forget_plans(plans: list) -> None:
    """The stage hashes of plans that are gone (expired, evicted, used or refused)."""
    for old in plans:
        for u in old["uploads"]:
            core.stage_forget(old["host_id"], u["upload_path"])


def _check_staged_owner(host_id: int, path: str, user) -> None:
    """A staged "move as root" file takes uploads only from the user who planned it."""
    owner = rootmove.staged_owner(host_id, path)
    if owner is not None and owner != user["id"]:
        raise ApiError(403, "files.rootMoveForeign", "this file is staged by another user")


@router.post("/api/hosts/{host_id}/fs/root-move")
async def fs_root_move(host_id: int, body: RootMoveIn, request: Request,
                       user=Depends(authz.perm('files.write', host='host_id'))):
    """Plan an "upload and move as root": → {plan_id, uploads: [{name, upload_path}], inbox}.
    Gates: `files.write` on the host (as for any upload; tokens never) → step-up (H1) → strict
    validation of the folder and names (rootmove.check_*; 400 `files.rootMoveBad`, or
    `files.rootMoveBackslash` for a backslash) → the agent's
    user must be a known plain user name (409 `files.rootMoveNoUser`) → the agent creates its
    inbox and reports its absolute path, which is validated too. No command yet: it needs the
    hashes of the uploaded bytes (…/command)."""
    await stepup.require_host_stepup(host_id, user)
    try:
        rootmove.check_dir(body.dir)
        names = [rootmove.check_name(n) for n in body.names]
        if not names:
            raise rootmove.MoveError("no files")
    except rootmove.MoveBackslash as e:
        raise ApiError(400, "files.rootMoveBackslash", str(e))
    except rootmove.MoveError as e:
        raise ApiError(400, "files.rootMoveBad", str(e))
    await _agent_user_of(host_id)
    try:
        inbox = await core.fs_mkdir(host_id, rootmove.INBOX_REL, True)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise fserrors.file_api_error(e)
    try:
        plan, dropped = rootmove.new_plan(host_id, user["id"], inbox or "", body.dir, names)
    except rootmove.MoveBusy as e:
        _forget_plans(e.dropped)
        raise ApiError(429, "files.rootMoveBusy", str(e))
    except rootmove.MoveError as e:
        raise ApiError(400, "files.rootMoveBad", str(e))
    _forget_plans(dropped)
    if not all([core.stage_track(host_id, u["upload_path"]) for u in plan["uploads"]]):
        # no room for the hash state without evicting a live one (re-review L3): no plan at all
        rootmove.drop_plan(plan["plan_id"])
        _forget_plans([plan])
        raise ApiError(429, "files.rootMoveBusy", "too many open move-as-root uploads")
    audit.detail(request, "upload and move as root: %d file(s) into %s (planned)"
                 % (len(names), fserrors.show_path(body.dir)))
    log.info("upload-and-move-as-root planned on host #%d: %d file(s) into %s",
             host_id, len(names), fserrors.show_path(body.dir))
    return {"ok": True, "plan_id": plan["plan_id"], "inbox": inbox, "uploads": plan["uploads"]}


@router.post("/api/hosts/{host_id}/fs/root-move/{plan_id}/command")
async def fs_root_move_command(host_id: int, plan_id: str, request: Request,
                               user=Depends(authz.perm('files.write', host='host_id'))):
    """→ {command}: the command for a plan whose files were all uploaded. Same gates as the plan;
    only its planner, on its host; every staged file must have committed with all of its bytes
    hashed by this gateway (409 `files.rootMoveNotStaged` otherwise: upload again). The plan is
    used up — one command per plan. The command is built from validated values only and must
    round-trip through shlex (fail closed)."""
    await stepup.require_host_stepup(host_id, user)
    plan = rootmove.get_plan(plan_id)
    if not plan or plan["host_id"] != host_id or plan["user_id"] != user["id"]:
        raise ApiError(404, "files.rootMoveGone", "no such upload plan (expired, used, or not yours)")
    agent_user = await _agent_user_of(host_id)
    items = []
    for u in plan["uploads"]:
        got = core.stage_result(host_id, u["upload_path"])
        if not got:
            raise ApiError(409, "files.rootMoveNotStaged",
                           "a staged file was not uploaded completely through this gateway")
        items.append({**u, "sha256": got[0], "size": got[1]})
    try:
        cmd = rootmove.command(agent_user, plan["inbox"], plan["dir"], items)
    except rootmove.MoveError as e:
        raise ApiError(400, "files.rootMoveBad", str(e))
    rootmove.drop_plan(plan_id)
    for u in plan["uploads"]:
        core.stage_forget(host_id, u["upload_path"])
    audit.detail(request, "upload and move as root: %d file(s) into %s (command typed or copied, not run)"
                 % (len(items), fserrors.show_path(plan["dir"])))
    return {"ok": True, "command": cmd}


# ── [files-copy] Copiere host → host, pe server (3.5.5) ───────────────────────────────────────────────
# Octeţii curg agent A → gateway → agent B (fs_read + maşinăria de upload resumabil), nu prin
# browser. Aceleaşi porţi ca rutele fs: cookie (`require_user` — un token de automatizare primeşte
# 401), step-up pe AMBELE hosturi (citire pe sursă = /fs/download, scriere pe destinaţie =
# /fs/upload; fiecare cere `stepup.require_host_stepup` pe hostul ei). Job-ul trăieşte în memorie (vezi
# fscopy.py); GET/DELETE văd doar job-urile userului care le-a pornit.
class FsCopyIn(BaseModel):
    src_host: int
    paths: list = Field(default_factory=list)
    dst_host: int
    dst_dir: str
    on_conflict: str = "skip"


def _copy_refused(e: "fscopy.CopyRefused") -> ApiError:
    status = 429 if e.code == "copy.busy" else 400
    return ApiError(status, e.code, str(e), vars=e.vars or None)


async def _copy_host(host_id: int, what: str):
    """Hostul unei copieri: există, e cu agent şi agentul e conectat ACUM."""
    row = await db.fetchone("SELECT id, name, connection_type FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    if not conntypes.is_agent(row):
        raise ApiError(400, "copy.notAgent", "the %s host has no agent (file copy needs one)" % what)
    return row


def _copy_code_of(msg: str) -> str:
    code = fserrors.file_api_error(core.FileError(msg)).code
    # copy rows carry a code but no vars: for texts that need {reason}, the raw message is better
    return "files.failed" if code in ("files.failedReason", "files.agentInternal") else code


@router.post("/api/fs/copy")
async def fs_copy_start(body: FsCopyIn, request: Request, user=Depends(authz.perm('files.read', host='body:src_host'))):
    """Porneşte o copiere de fişiere de pe `src_host` în `dst_dir` pe `dst_host` → `{job_id}`.
    `on_conflict`: skip | overwrite | rename („nume (1).ext"). src == dst e permis (duplicat /
    copiere în alt director pe acelaşi host). Folderele (3.6, agent 58) se copiază cu tot arborele;
    modul sursei se păstrează doar pe o destinaţie cu agent ≥ 58 (vezi fscopy)."""
    if body.on_conflict not in fscopy.CONFLICT_MODES:
        raise ApiError(400, "copy.badConflict", "on_conflict must be skip, overwrite or rename")
    paths = body.paths
    if not paths:
        raise ApiError(400, "copy.empty", "nothing to copy")
    if len(paths) > fscopy.COPY_MAX_FILES:
        raise ApiError(400, "copy.tooMany", "at most %d files per copy" % fscopy.COPY_MAX_FILES,
                       vars={"max": fscopy.COPY_MAX_FILES})
    try:
        for p in paths:
            fscopy.check_path(p, "path")
        fscopy.check_path(body.dst_dir, "dst_dir")
        names = [fscopy.src_name(p) for p in paths]
    except fscopy.CopyRefused as e:
        raise _copy_refused(e)
    if len(set(names)) != len(names):
        raise ApiError(400, "copy.duplicateNames", "two sources have the same file name")
    # 3.6: `files.read` pe sursă e verificat de dependenţa rutei; destinaţia cere `files.write`
    # (o copiere host→host = download + upload, deci exact drepturile celor două, §A.4)
    await authz.require_on(request, body.dst_host, "files.write")
    src = await _copy_host(body.src_host, "source")
    dst = await _copy_host(body.dst_host, "destination")
    # step-up pe AMBELE capete, ca la /fs/download (sursa) şi /fs/upload (destinaţia)
    await stepup.require_host_stepup(body.src_host, user)
    if body.dst_host != body.src_host:
        await stepup.require_host_stepup(body.dst_host, user)
    try:
        core.agent_or_raise(body.src_host)
        core.agent_or_raise(body.dst_host)
        # dst_dir canonic (absolut) + verificat că e un director: fs_list pe destinaţie
        listing = await core.fs_list(body.dst_host, body.dst_dir)
        dst_dir = listing.get("path") or body.dst_dir
        src_home = None
        if body.src_host == body.dst_host and any(p == "~" or p.startswith("~/") for p in paths):
            src_home = (await core.fs_list(body.src_host, "~")).get("path")
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise fserrors.file_api_error(e)
    first = paths[0] if len(paths) == 1 else (paths[0].rstrip("/").rsplit("/", 1)[0] or "/")
    # „copy 2 files, 1 folder alpha:/srv → beta:/backup": tipul căilor cerute vine de pe sursă (stat,
    # plafonat în timp); înainte scria „copy N files" şi când selecţia era făcută din foldere
    nf, nd, nu = await fscopy.count_kinds(body.src_host, paths, src_home)
    audit.detail(request, "copy %s %s:%s → %s:%s" % (
        fscopy.audit_what(nf, nd, nu), src["name"], first, dst["name"], dst_dir))
    try:
        job = fscopy.start(user["id"], body.src_host, src["name"], body.dst_host, dst["name"],
                           dst_dir, paths, body.on_conflict, src_home=src_home)
    except fscopy.CopyRefused as e:
        raise _copy_refused(e)
    log.info("fs copy %s started: %s host=%s → host=%s:%s", job.id, fscopy.audit_what(nf, nd, nu),
             body.src_host, body.dst_host, dst_dir)
    return {"job_id": job.id, "dst_dir": dst_dir}


@router.get("/api/fs/copy/{job_id}")
async def fs_copy_status(job_id: str, files: int = 0, user=Depends(security.require_user)):
    """Progresul: totaluri, stare, erorile per fişier; `files=1` adaugă toate rândurile."""
    job = fscopy.get(job_id, user["id"])
    if not job:
        raise ApiError(404, "copy.missing", "no such copy job (finished jobs expire after an hour)")
    return fscopy.to_dict(job, bool(files), code_of=_copy_code_of)


@router.delete("/api/fs/copy/{job_id}")
async def fs_copy_cancel(job_id: str, request: Request, user=Depends(security.require_user)):
    """Anulează: fişierul în zbor se opreşte şi temp-ul lui de pe destinaţie se şterge; fişierele
    deja copiate RĂMÂN. Idempotent pe un job terminat."""
    job = fscopy.get(job_id, user["id"])
    if not job:
        raise ApiError(404, "copy.missing", "no such copy job (finished jobs expire after an hour)")
    audit.detail(request, "cancel copy %s → %s:%s" % (job.src_host_name, job.dst_host_name, job.dst_dir))
    await fscopy.cancel(job)
    return fscopy.to_dict(job, False, code_of=_copy_code_of)


@router.post("/api/fs/copy/{job_id}/retry")
async def fs_copy_retry(job_id: str, request: Request, user=Depends(security.require_user)):
    """Re-porneşte (job NOU) ce a eşuat într-o copiere terminată, cu aceleaşi opţiuni. Un folder se
    îmbină în EXACT folderul de data trecută, sărind ce există deja (fscopy.retry). Aceleaşi porţi
    ca la pornire: step-up pe ambele capete, ambii agenţi conectaţi."""
    old = fscopy.get(job_id, user["id"])
    if not old:
        raise ApiError(404, "copy.missing", "no such copy job (finished jobs expire after an hour)")
    if old.finished is None:
        raise ApiError(409, "copy.running", "the copy is still running")
    # 3.6: drepturile se RE-verifică (pot fi fost retrase între timp) — ca la pornire
    g = await authz.grants_for_user(user["id"])
    await authz.require_on(g, old.src_host, "files.read")
    await authz.require_on(g, old.dst_host, "files.write")
    await _copy_host(old.src_host, "source")
    await _copy_host(old.dst_host, "destination")
    await stepup.require_host_stepup(old.src_host, user)
    if old.dst_host != old.src_host:
        await stepup.require_host_stepup(old.dst_host, user)
    try:
        core.agent_or_raise(old.src_host)
        core.agent_or_raise(old.dst_host)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    try:
        job = fscopy.retry(old)
    except fscopy.CopyRefused as e:
        raise _copy_refused(e)
    old_dirs = {f.src for f in old.files if f.root is None and f.kind == "dir"}
    top = [f.src for f in job.files if f.root is None]
    nd = sum(1 for p in top if p in old_dirs)
    audit.detail(request, "retry copy %s %s → %s:%s" % (
        fscopy.audit_what(len(top) - nd, nd), old.src_host_name, old.dst_host_name, old.dst_dir))
    log.info("fs copy %s retried as %s", old.id, job.id)
    return {"job_id": job.id, "dst_dir": job.dst_dir}


# ── [files] Preview for the editor ────────────────────────────────────────────────────────────
# praguri editor: sub LIMIT încarci tot (editabil); peste, doar primii HEAD
# bytes (view-only), ca să nu tragi un fișier uriaș în browser
_EDIT_FULL_LIMIT = 1024 * 1024


_PREVIEW_HEAD = 256 * 1024


@router.get("/api/hosts/{host_id}/fs/preview")
async def fs_preview(host_id: int, path: str, user=Depends(authz.perm('files.read', host='host_id'))):
    """Conținut pentru editor: fișier întreg dacă e mic, altfel doar începutul
    (view-only). Detectează binar și întoarce mtime pentru verificarea de conflict."""
    await stepup.require_host_stepup(host_id, user)   # H1
    try:
        data, size, mtime = await core.fs_read_head(host_id, path, _PREVIEW_HEAD)
        if _PREVIEW_HEAD < size <= _EDIT_FULL_LIMIT:
            data, size, mtime = await core.fs_read_head(host_id, path, _EDIT_FULL_LIMIT)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise fserrors.file_api_error(e)
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


# ── [files] mkdir / rename / delete ───────────────────────────────────────────────────────────────

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
async def fs_mkdir(host_id: int, body: FsPath, user=Depends(authz.perm('files.write', host='host_id'))):
    await stepup.require_host_stepup(host_id, user)   # H1
    try:
        await core.fs_mkdir(host_id, body.path, body.parents)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        raise await fserrors.fs_write_error(host_id, e, body.path)
    return {"ok": True}


@router.post("/api/hosts/{host_id}/fs/rename")
async def fs_rename(host_id: int, body: FsRename, user=Depends(authz.perm('files.write', host='host_id'))):
    await stepup.require_host_stepup(host_id, user)   # H1
    try:
        await core.fs_rename(host_id, body.path, body.to)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        # a rename writes into BOTH parents; name the folder only when it is one and the same
        same = os.path.dirname(body.path.rstrip("/")) == os.path.dirname(body.to.rstrip("/"))
        if not same:
            raise fserrors.file_api_error(e)
        raise await fserrors.fs_write_error(host_id, e, body.to, missing_is_dir=False)
    return {"ok": True}


# POST, nu DELETE: unele proxy-uri/clienți refuză body pe DELETE, iar avem nevoie
# de flag-ul `recursive`. Ștergerea recursivă e explicită, cerută din UI cu confirmare.
@router.post("/api/hosts/{host_id}/fs/delete")
async def fs_delete(host_id: int, body: FsDelete, request: Request,
                    user=Depends(authz.perm('files.delete', host='host_id'))):
    audit.detail(request, body.path + (" (recursiv)" if body.recursive else ""))
    await stepup.require_host_stepup(host_id, user)   # H1
    try:
        await core.fs_delete(host_id, body.path, body.recursive)
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline")
    except (core.FileError, TimeoutError) as e:
        if body.recursive:              # the denial may be deep inside the tree, not here
            raise fserrors.file_api_error(e)
        raise await fserrors.fs_write_error(host_id, e, body.path, missing_is_dir=False)
    return {"ok": True}
