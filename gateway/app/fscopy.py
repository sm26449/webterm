"""Copiere de fişiere host → host (agent → agent), făcută pe SERVER (WebTerm 3.5.5).

De ce pe server: „descarcă de pe A, urcă pe B" prin browser trece fiecare octet de DOUĂ ori prin
legătura omului (de multe ori un telefon pe 4G), deşi ambii agenţi stau lângă gateway. Aici
octeţii curg agent A → gateway → agent B şi nu ating browserul; omul vede doar progresul.

Agentul NU se schimbă (v57 rămâne): sursa se citeşte cu `fs_read` (felii de 256 KiB, ca la
download), destinaţia se scrie prin EXACT maşinăria de upload resumabil din core —
`fs_upload_chunk` (fereastra `_UploadWindow`, FRAME_FSWRITE binar pe agent ≥55, CRC incremental)
şi `fs_upload_commit` (verificare CRC-32 apoi rename atomic temp → ţintă). Deci destinaţia vede
acelaşi `.wtpart.<id>` temporar ca orice upload: un fişier pe jumătate copiat nu apare niciodată
sub numele final, iar un temp rămas după o cădere de gateway e măturat de `_upload_gc`.

Backpressure: un cititor şi un scriitor per fişier, legaţi printr-o coadă MĂRGINITĂ
(COPY_PREFETCH felii). Cititorul se opreşte când coada e plină, scriitorul aşteaptă ack-ul
agentului destinaţie pentru fiecare bloc de 1 MiB. Memoria ţinută de un fişier în zbor e deci
≤ COPY_PREFETCH × 256 KiB + un bloc de 1 MiB (+ o felie) — niciodată fişierul întreg. Cel mult
COPY_PARALLEL fişiere per job rulează simultan; numărul de job-uri vii e plafonat per user şi global.

Folderele NU se copiază (decizie 3.5.5): fără un op de `chmod` pe agent, o copiere pe arbore
(fs_list + fs_mkdir + fişiere) ar pierde biţii de execuţie (un `deploy.sh` ar ateriza
ne-executabil) şi ar urma symlink-urile — o copie care arată completă dar nu se poartă la fel.
Refuzăm explicit („vine cu următorul update de agent"), cu cod stabil (`copy.folder`).

Job-urile trăiesc în MEMORIA gateway-ului (TTL după terminare). Un restart de gateway pierde
job-urile în curs: fişierele deja comise rămân, temp-ul celui în zbor e curăţat oportunist de
`_upload_gc` (după 24 h) — documentat în docs/TRANSFERS.md.
"""
import asyncio
import base64
import posixpath
import re
import time
import uuid
import zlib
from typing import Optional

from . import core

COPY_MAX_FILES = 1000                # fişiere per job
COPY_PARALLEL = 2                    # fişiere copiate simultan într-un job
COPY_PREFETCH = 4                    # felii fs_read ţinute în coada cititor → scriitor (backpressure)
COPY_TTL = 3600                      # cât rămâne un job TERMINAT interogabil
COPY_JOBS_MAX = 256                  # job-uri reţinute în memorie (cele terminate se evacuează primele)
COPY_RUNNING_PER_USER = 4            # job-uri VII per user
COPY_RUNNING_MAX = 16                # job-uri vii pe tot gateway-ul
COPY_RENAME_MAX = 999                # „nume (n).ext": până la n = 999
COPY_CANCEL_WAIT = 20.0              # cât aşteaptă DELETE curăţenia temp-urilor de pe destinaţie
CONFLICT_MODES = ("skip", "overwrite", "rename")

# extensii compuse: „backup.tar.gz" → „backup (1).tar.gz", nu „backup.tar (1).gz"
_COMPOUND_EXT = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")

_jobs: dict = {}                     # job_id -> CopyJob


class CopyRefused(Exception):
    """Cerere de copiere invalidă (validare, înainte să pornească ceva). `code` = cod de API stabil."""

    def __init__(self, code: str, msg: str, vars=None):
        super().__init__(msg)
        self.code = code
        self.vars = vars or {}


# ── validarea căilor ───────────────────────────────────────────────────────────────────────
# Rutele fs existente dau calea agentului (care face expanduser + abspath). Aici căile devin şi
# NUME pe destinaţie (`dst_dir/<basename>`), deci suntem stricţi: absolute sau `~/…`, fără
# octeţi de control, fără segmente `..` (un `/a/b/..` ar face ca „numele" copiat să fie `..`, iar
# destinaţia — părintele lui dst_dir), fără rădăcina însăşi.
def check_path(p, what: str = "path") -> str:
    if not isinstance(p, str) or not p or len(p) > 4096:
        raise CopyRefused("copy.badPath", "invalid %s" % what)
    if _CTRL.search(p):
        raise CopyRefused("copy.badPath", "control characters in %s" % what)
    if not (p.startswith("/") or p == "~" or p.startswith("~/")):
        raise CopyRefused("copy.badPath", "%s must be absolute (/…) or start with ~/" % what)
    if ".." in p.split("/"):
        raise CopyRefused("copy.badPath", "'..' is not allowed in %s" % what)
    return p


def src_name(p: str) -> str:
    """Numele cu care fişierul aterizează pe destinaţie (ultimul segment al căii sursă)."""
    name = p.rstrip("/").rsplit("/", 1)[-1]
    if name in ("", ".", "..", "~"):
        raise CopyRefused("copy.badPath", "not a file path: %s" % p)
    return name


def rename_candidate(name: str, n: int) -> str:
    """`raport.pdf` → `raport (n).pdf`; `.bashrc` → `.bashrc (n)`; `a.tar.gz` → `a (n).tar.gz`."""
    low = name.lower()
    stem, ext = name, ""
    for ce in _COMPOUND_EXT:
        if low.endswith(ce) and len(name) > len(ce):
            stem, ext = name[:-len(ce)], name[-len(ce):]
            break
    else:
        dot = name.rfind(".")
        if dot > 0:
            stem, ext = name[:dot], name[dot:]
    return "%s (%d)%s" % (stem, n, ext)


def _join(d: str, name: str) -> str:
    return d.rstrip("/") + "/" + name if d != "/" else "/" + name


# ── modelul ────────────────────────────────────────────────────────────────────────────────
class CopyFile:
    __slots__ = ("src", "name", "dst", "size", "done", "state", "error")

    def __init__(self, src: str):
        self.src = src
        self.name = src_name(src)
        self.dst = ""                 # calea finală pe destinaţie (după regula de conflict)
        self.size = 0
        self.done = 0
        self.state = "queued"         # queued | running | done | skipped | err | cancelled
        self.error = ""               # mesajul brut (englez); ruta îi dă un cod stabil


class CopyJob:
    def __init__(self, user_id, src_host, src_name_, dst_host, dst_name_, dst_dir, paths, on_conflict,
                 src_home=None):
        self.id = uuid.uuid4().hex
        self.user_id = user_id
        self.src_host = src_host
        self.src_host_name = src_name_
        self.dst_host = dst_host
        self.dst_host_name = dst_name_
        self.dst_dir = dst_dir         # canonic (absolut, din fs_list pe destinaţie)
        self.on_conflict = on_conflict
        self.src_home = src_home       # home-ul absolut al sursei (doar src==dst, pt. „acelaşi fişier")
        self.files = [CopyFile(p) for p in paths]
        self.state = "running"         # running | done | failed | cancelled
        self.created = time.time()
        self.finished: Optional[float] = None
        self.cancelled = False
        self.task: Optional[asyncio.Task] = None
        self.buffered = 0              # octeţi ţinuţi ACUM în gateway (cozi + blocuri în curs)
        self.peak_buffered = 0         # vârful — testele verifică plafonul de memorie
        self._claimed: set = set()     # căi de destinaţie deja alese în job (rename fără coliziuni interne)

    def _hold(self, n: int) -> None:
        self.buffered += n
        if self.buffered > self.peak_buffered:
            self.peak_buffered = self.buffered

    def totals(self):
        live = [f for f in self.files if f.state != "skipped"]
        return sum(f.size for f in live), sum(f.done for f in live)


def _abs_src(job: CopyJob, p: str) -> str:
    if job.src_home and (p == "~" or p.startswith("~/")):
        p = job.src_home.rstrip("/") + p[1:]
    return posixpath.normpath(p)


async def _stat(host_id: int, path: str) -> dict:
    resp = await core._agent_or_raise(host_id).request("fs_stat", path=path, timeout=30)
    if not resp.get("ok"):
        raise core.FileError(resp.get("msg", "eroare"))
    return resp


async def _prepare(job: CopyJob, f: CopyFile) -> None:
    """Faza 1 (toate fişierele, înainte de copiere): tipul şi mărimea pe sursă → totalul afişat."""
    st = await _stat(job.src_host, f.src)
    if not st.get("exists"):
        raise core.FileError("%s: No such file or directory" % f.src)
    if st.get("dir"):
        raise core.FileError("folders cannot be copied between hosts yet (needs the next agent update)")
    # symlink: lstat-ul dă mărimea LINK-ului; mărimea reală vine din primul fs_read (care urmează
    # link-ul doar spre un fişier obişnuit — exact ca download-ul)
    f.size = 0 if st.get("link") else int(st.get("size", 0))


async def _resolve_dst(job: CopyJob, f: CopyFile) -> bool:
    """Alege calea finală după `on_conflict`. False = fişierul se sare (skip / acelaşi fişier)."""
    want = _join(job.dst_dir, f.name)
    same_file = job.src_host == job.dst_host and _abs_src(job, f.src) == posixpath.normpath(want)
    st = await _stat(job.dst_host, want)
    if not st.get("exists") and want not in job._claimed:
        f.dst = want
        job._claimed.add(want)
        return True
    if job.on_conflict == "skip":
        return False
    if job.on_conflict == "overwrite":
        if same_file:
            return False                      # un fişier peste el însuşi: nimic de făcut
        if st.get("dir"):
            raise core.FileError("a folder with that name already exists on the destination")
        f.dst = want
        job._claimed.add(want)
        return True
    for n in range(1, COPY_RENAME_MAX + 1):   # rename: „nume (n).ext", primul liber
        cand = _join(job.dst_dir, rename_candidate(f.name, n))
        if cand in job._claimed:
            continue
        if not (await _stat(job.dst_host, cand)).get("exists"):
            f.dst = cand
            job._claimed.add(cand)
            return True
    raise core.FileError("no free name for %s (tried %d)" % (f.name, COPY_RENAME_MAX))


async def _copy_file(job: CopyJob, f: CopyFile) -> None:
    if not await _resolve_dst(job, f):
        f.state = "skipped"
        return
    f.state = "running"
    uid = uuid.uuid4().hex                     # 32 hex: tiparul `_UPLOAD_UID` + `_upload_gc`
    src_conn = core._agent_or_raise(job.src_host)
    q: asyncio.Queue = asyncio.Queue(maxsize=COPY_PREFETCH)
    first: dict = {}

    async def reader():
        """fs_read felie cu felie; se blochează pe coada plină (backpressure spre agentul sursă).
        O eroare NU omoară doar cititorul: o punem în coadă, altfel scriitorul ar aştepta la
        nesfârşit o felie care nu mai vine."""
        try:
            offset = 0
            while True:
                resp = await src_conn.request("fs_read", path=f.src, offset=offset, timeout=60)
                if not resp.get("ok"):
                    raise core.FileError(resp.get("msg", "eroare"))
                size, mtime = int(resp.get("size", 0)), int(resp.get("mtime", 0))
                if not first:
                    first.update(size=size, mtime=mtime)
                    f.size = size              # mărimea reală (şi pentru symlink-uri)
                elif (size, mtime) != (first["size"], first["mtime"]):
                    raise core.FileError("the source file changed during the copy")
                chunk = base64.b64decode(resp.get("data_b64") or "")
                if chunk:
                    job._hold(len(chunk))
                    await q.put(chunk)
                offset += len(chunk)
                if resp.get("eof") or not chunk:
                    break
            await q.put(None)
        except asyncio.CancelledError:
            raise
        except Exception as e:         # noqa: BLE001 — predată scriitorului, care o ridică
            await q.put(e)

    async def one(block):
        yield block

    buf = bytearray()                          # blocul în formare (vizibil şi din `finally`)

    async def writer() -> int:
        """Lipeşte felii în blocuri de FS_CHUNK şi le aplică prin fs_upload_chunk (în ordine,
        aşteptând ack-ul agentului destinaţie). Întoarce CRC-32 al octeţilor CITIŢI din sursă."""
        off = 0
        crc = 0
        while True:
            item = await q.get()
            if item is None:
                break
            if isinstance(item, BaseException):
                raise item
            buf.extend(item)                   # mutat din coadă în buffer: `buffered` neschimbat
            while len(buf) >= core.FS_CHUNK:
                block = bytes(buf[:core.FS_CHUNK])
                del buf[:core.FS_CHUNK]
                try:                           # blocul în zbor spre agent e tot în memorie până la ack
                    await core.fs_upload_chunk(job.dst_host, f.dst, uid, off, one(block))
                finally:
                    job._hold(-len(block))
                crc = zlib.crc32(block, crc)
                off += len(block)
                f.done = off
        if buf or off == 0:                    # coada (sau fişierul GOL: creează temp-ul de 0 octeţi)
            block = bytes(buf)
            buf.clear()
            try:
                await core.fs_upload_chunk(job.dst_host, f.dst, uid, off, one(block))
            finally:
                job._hold(-len(block))
            crc = zlib.crc32(block, crc)
            off += len(block)
            f.done = off
        return crc & 0xffffffff

    rtask = asyncio.ensure_future(reader())
    committed = False
    try:
        crc = await writer()
        await rtask                            # erorile cititorului ies aici (deja terminat)
        if first and f.done != first["size"]:
            raise core.FileError("short read: %d of %d bytes" % (f.done, first["size"]))
        # skip/rename: ţinta poate să fi apărut între alegere şi commit (alt proces) — nu o
        # strivim. overwrite: commit-ul o înlocuieşte atomic (os.replace; modul ţintei rămâne).
        if job.on_conflict != "overwrite" and (await _stat(job.dst_host, f.dst)).get("exists"):
            raise core.FileError("the destination appeared during the copy: %s" % f.dst)
        await core.fs_upload_commit(job.dst_host, f.dst, uid, crc32=crc)
        committed = True
        f.state = "done"
    finally:
        if not rtask.done():
            rtask.cancel()
            try:
                await rtask
            except BaseException:      # noqa: BLE001 — cititorul oprit; eroarea lui nu mai contează
                pass
        # ce a rămas ţinut (coadă + buffer) nu mai e în memorie odată cu fişierul
        while not q.empty():
            item = q.get_nowait()
            if isinstance(item, (bytes, bytearray)):
                job._hold(-len(item))
        if buf:
            job._hold(-len(buf))
            buf.clear()
        if not committed:
            try:
                await core.fs_upload_abort(job.dst_host, f.dst, uid)    # temp-ul de pe destinaţie
            except Exception:          # noqa: BLE001 — agent plecat: GC-ul de upload îl ia la 24 h
                pass


def _fail(f: CopyFile, e: BaseException) -> None:
    f.state = "err"
    if isinstance(e, core.AgentGone):
        f.error = "host offline"
    elif isinstance(e, (TimeoutError, asyncio.TimeoutError)):
        f.error = "timed out"
    else:
        f.error = str(e) or type(e).__name__


async def _run(job: CopyJob) -> None:
    tasks: list = []
    try:
        for f in job.files:                    # faza 1: tip + mărime, ca totalul să se vadă devreme
            if job.cancelled:
                break
            try:
                await _prepare(job, f)
            except asyncio.CancelledError:
                raise
            except Exception as e:             # noqa: BLE001 — eroare PER FIŞIER, jobul continuă
                _fail(f, e)
        sem = asyncio.Semaphore(COPY_PARALLEL)

        async def one(f: CopyFile):
            async with sem:
                if job.cancelled:
                    return
                try:
                    await _copy_file(job, f)
                except asyncio.CancelledError:
                    raise
                except Exception as e:         # noqa: BLE001 — eroare PER FIŞIER, jobul continuă
                    f.done = 0
                    _fail(f, e)

        tasks = [asyncio.ensure_future(one(f)) for f in job.files if f.state == "queued"]
        if tasks:
            await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        # DELETE: oprim fişierele în zbor; fiecare îşi şterge temp-ul în `finally` (await permis —
        # anularea se livrează o singură dată), deci aşteptăm curăţenia înainte să raportăm.
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for f in job.files:
            if f.state in ("queued", "running"):
                f.state = "cancelled"
                f.done = 0
        job.finished = time.time()
        if job.cancelled:
            job.state = "cancelled"
        elif any(f.state == "err" for f in job.files):
            job.state = "failed"
        else:
            job.state = "done"


# ── registrul de job-uri ───────────────────────────────────────────────────────────────────
def purge(now: Optional[float] = None) -> None:
    now = time.time() if now is None else now
    for jid, j in list(_jobs.items()):
        if j.finished is not None and now - j.finished > COPY_TTL:
            del _jobs[jid]
    if len(_jobs) >= COPY_JOBS_MAX:
        done = sorted((j for j in _jobs.values() if j.finished is not None), key=lambda j: j.finished)
        for j in done[:len(_jobs) - COPY_JOBS_MAX + 1]:
            _jobs.pop(j.id, None)


def running(user_id=None) -> int:
    return sum(1 for j in _jobs.values()
               if j.finished is None and (user_id is None or j.user_id == user_id))


def start(user_id, src_host, src_host_name, dst_host, dst_host_name, dst_dir, paths, on_conflict,
          src_home=None) -> CopyJob:
    purge()
    if running(user_id) >= COPY_RUNNING_PER_USER or running() >= COPY_RUNNING_MAX:
        raise CopyRefused("copy.busy", "too many copy jobs running; wait for one to finish",
                          {"max": COPY_RUNNING_PER_USER})
    if len(_jobs) >= COPY_JOBS_MAX:
        raise CopyRefused("copy.busy", "too many copy jobs in memory; retry later",
                          {"max": COPY_RUNNING_PER_USER})
    job = CopyJob(user_id, src_host, src_host_name, dst_host, dst_host_name, dst_dir, paths,
                  on_conflict, src_home=src_home)
    _jobs[job.id] = job
    job.task = asyncio.ensure_future(_run(job))
    return job


def get(job_id: str, user_id) -> Optional[CopyJob]:
    """Job-ul DOAR pentru userul care l-a pornit (al altcuiva = inexistent, 404)."""
    purge()
    j = _jobs.get(job_id or "")
    return j if j is not None and j.user_id == user_id else None


async def cancel(job: CopyJob) -> None:
    """Opreşte job-ul şi AŞTEAPTĂ curăţenia (temp-urile de pe destinaţie şterse); fişierele deja
    comise rămân. Idempotent pe un job terminat."""
    if job.finished is not None or job.task is None:
        return
    job.cancelled = True
    job.task.cancel()
    await asyncio.wait({job.task}, timeout=COPY_CANCEL_WAIT)


def to_dict(job: CopyJob, files: bool, code_of=None) -> dict:
    """Starea pentru GET. `files=False` (polling-ul widgetului) = doar totaluri + erorile (plafonate),
    ca un job de 1000 de fişiere să nu trimită 1000 de rânduri pe secundă. `code_of(msg)` dă
    codul stabil al unei erori (maparea din api, aceeaşi ca la rutele fs)."""
    total, done = job.totals()
    code_of = code_of or (lambda m: "files.failed")

    def row(f: CopyFile) -> dict:
        r = {"src": f.src, "name": f.name, "dst": f.dst, "size": f.size, "done": f.done, "state": f.state}
        if f.error:
            r.update(error=f.error, code=code_of(f.error))
        return r

    errs = [f for f in job.files if f.state == "err"]
    out = {
        "job_id": job.id, "state": job.state,
        "src_host": job.src_host, "src_host_name": job.src_host_name,
        "dst_host": job.dst_host, "dst_host_name": job.dst_host_name,
        "dst_dir": job.dst_dir, "on_conflict": job.on_conflict,
        "total_bytes": total, "done_bytes": done,
        "files_total": len(job.files),
        "files_done": sum(1 for f in job.files if f.state == "done"),
        "files_skipped": sum(1 for f in job.files if f.state == "skipped"),
        "files_failed": len(errs),
        "created": job.created, "finished": job.finished,
        "errors": [row(f) for f in errs[:50]],
    }
    if files:
        out["files"] = [row(f) for f in job.files]
    return out
