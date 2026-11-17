"""Agent file-operation errors → ApiError with a stable code (the UI translates `err.<code>` and can
offer a fix), shared by the Files routes (`files_api.py`) and the git panel (api.py). `file_api_error`
maps by exception type and by substring of the agent's strerror; `fs_write_error` adds who cannot
write where (the agent's user, the folder, its mode). Moved out of api.py.
"""
import asyncio
import os

from .errors import ApiError
from . import core, db, rootmove


# Erorile de fişiere vin de la agent ca text de `strerror` („/etc/shadow: Permission denied").
# Le dăm un COD după substring — UI-ul traduce şi poate oferi un remediu („rulează ca alt
# user", „eliberează spaţiu"); mesajul brut (cu calea) rămâne în `detail`. (audit UX §4.3/§8.F3)
_FILE_ERROR_CODES = (
    # copierea host → host (fscopy): mesajele ei proprii, înaintea celor generice
    ("cannot copy a folder into itself", "copy.intoItself"),
    ("folder too large", "copy.folderTooLarge"),
    ("folder too deep", "copy.folderTooDeep"),
    ("parent folder could not be created", "copy.parentFailed"),
    ("source file changed", "copy.sourceChanged"),
    ("destination appeared", "copy.appeared"),
    ("no free name", "copy.noFreeName"),
    ("host offline", "host.offline"),
    ("not a regular file", "files.notRegular"),
    ("permission denied", "files.permissionDenied"),
    ("operation not permitted", "files.permissionDenied"),
    ("read-only file system", "files.readOnly"),
    ("no such file", "files.notFound"),
    ("not found", "files.notFound"),
    ("no space left", "files.noSpace"),
    ("disk quota", "files.noSpace"),
    ("is a directory", "files.isDirectory"),
    ("not a directory", "files.notDirectory"),
    ("file exists", "files.exists"),
    ("already exists", "files.exists"),
    ("too large", "files.tooLarge"),
    ("too big", "files.tooLarge"),
    ("crc mismatch", "files.crcMismatch"),
    ("integrity check", "files.crcMismatch"),
    ("upload_id", "files.badUpload"),
    ("timed out", "files.timeout"),
    ("filesystem root", "files.rootRefused"),
    ("archiv", "files.archiveFailed"),
    ("tar failed", "files.archiveFailed"),
)


def file_api_error(e: Exception, status: int = 400) -> ApiError:
    """FileError/FileConflict/TimeoutError de la operaţiile fs → ApiError cu cod stabil.
    Statusul HTTP rămâne cel al rutei (400, sau 504 unde era deja)."""
    if isinstance(e, core.UploadForeign):
        return ApiError(409, "files.uploadForeign", str(e) or "this upload was started by another user")
    if isinstance(e, core.FileConflict):
        return ApiError(409, "files.conflict", str(e) or "the file changed on the host")
    if isinstance(e, (TimeoutError, asyncio.TimeoutError)):
        return ApiError(status, "files.timeout", "the host did not answer in time")
    msg = str(e) or "file operation failed"
    low = msg.lower()
    if low.startswith("agent internal error:"):
        # 3.6.9: an exception the agent did not expect (core tags code `internal`). Show its own
        # text (sanitised) and say where to look — never just "the operation failed". On a
        # Python < 3.6 agent this is "'__enter__'" (os.scandir), see core.agent_python_old.
        why = rootmove.clean_text(msg[len("agent internal error:"):].strip())
        return ApiError(status, "files.agentInternal", msg, vars={"reason": why or "unknown"})
    for needle, code in _FILE_ERROR_CODES:
        if needle in low:
            return ApiError(status, code, msg)
    # 3.6.9: no specific text for this one — the generic message plus the agent's own reason
    # (strerror, sanitised and truncated; the path is dropped, the UI already shows it)
    why = rootmove.reason(msg) if msg != "eroare" else ""     # "eroare" = core's "agent sent no msg"
    if why:
        return ApiError(status, "files.failedReason", msg, vars={"reason": why})
    return ApiError(status, "files.failed", msg)


# 3.6.9 — write errors that name WHO cannot write WHERE. The file APIs act as the agent's user
# (often an unprivileged `webterm`), not as the terminal's sudo user; "Permission denied" alone
# told the Owner nothing they could act on. These codes carry {user, dir[, mode]} so the UI can
# say "the agent runs as webterm and cannot write in /srv/bin/lists (mode 755)" and offer the
# three ways out (grant access, upload and move as root, upload to the agent's home). The owner of
# the folder is NOT known: fs_list/fs_stat report the mode but no uid (agent v58), and changing
# the agent forces a fleet update — so we say what we know, and nothing we would have to guess.
_WRITE_CODES = {
    "files.permissionDenied": ("files.writeDenied", "files.writeDeniedMode"),
    "files.readOnly": ("files.readOnlyAt", None),
    "files.noSpace": ("files.noSpaceAt", None),
    "files.notFound": ("files.dirMissing", None),
}


def show_path(p: str) -> str:
    """A path for a message: control/format characters out, length capped (it is displayed,
    never typed — the typed command is rootmove's job)."""
    p = "".join("?" if rootmove.has_bad_chars(ch) else ch for ch in (p or ""))
    return p if len(p) <= 300 else "…" + p[-299:]


async def fs_write_error(host_id: int, e: Exception, path: str, status: int = 400,
                          missing_is_dir: bool = True) -> ApiError:
    """`file_api_error` for an operation that WRITES into `dirname(path)`, enriched with the
    agent's user and that folder (+ its mode on permission denied, best effort, 3 s). Never
    raises: any failure while enriching returns the plain error. `missing_is_dir=False` where
    "No such file" may be about the file itself (delete, commit), not the folder."""
    base = file_api_error(e, status)
    spec = _WRITE_CODES.get(base.code)
    if base.code == "files.notFound" and not missing_is_dir:
        return base
    if not spec or not isinstance(path, str) or not path.startswith("/"):
        return base
    d = os.path.dirname(path.rstrip("/")) or "/"
    try:
        row = await db.fetchone("SELECT agent_user FROM hosts WHERE id=?", host_id)
        user = show_path((row["agent_user"] if row else "") or "")[:64]
    except Exception:
        user = ""
    if spec[1] and not user:          # "the agent runs as …" needs the user; the others do not
        return base
    vars = {"dir": show_path(d)}
    if spec[1]:
        vars["user"] = user
    code = spec[0]
    if spec[1]:
        try:
            resp = await core.agent_or_raise(host_id).request("fs_stat", path=d, timeout=3)
            mode = resp.get("mode") if resp.get("ok") and resp.get("exists") else None
            if isinstance(mode, int) and not isinstance(mode, bool) and 0 <= mode <= 0o777:
                vars["mode"] = "%03o" % mode
                code = spec[1]
        except Exception:
            pass
    return ApiError(base.status_code, code, base.detail, vars=vars)
