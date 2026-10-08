"""Copiere de fişiere host → host (agent → agent), făcută pe SERVER (WebTerm 3.5.5).

De ce pe server: „descarcă de pe A, urcă pe B" prin browser trece fiecare octet de DOUĂ ori prin
legătura omului (de multe ori un telefon pe 4G), deşi ambii agenţi stau lângă gateway. Aici
octeţii curg agent A → gateway → agent B şi nu ating browserul; omul vede doar progresul.

Pentru fişiere agentul nu are nimic special: sursa se citeşte cu `fs_read` (felii de 256 KiB, ca la
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

Foldere (agent v58, WebTerm 3.6): arborele sursei se parcurge cu `fs_list` (deja existent), pe
destinaţie se creează directoarele (`fs_mkdir`), fişierele trec prin aceeaşi maşinărie de mai sus,
iar modul sursei (biţii 0o777 — fără setuid/setgid/sticky) se aplică DUPĂ commit cu op-ul nou
`fs_chmod` (doar destinaţie cu agent ≥ 58; mai vechi → copiem fără mod şi spunem asta în job:
`copy.noModes`). Directoarele îşi primesc modul LA FINAL, cel mai adânc primul — un director 0555
pe sursă n-ar mai accepta fişierele dacă l-am închide înainte. Limitele parcurgerii:
COPY_MAX_FILES fişiere şi COPY_MAX_DIRS directoare per job, adâncime COPY_MAX_DEPTH; un director
listat trunchiat (peste FS_MAX_LIST intrări) e o eroare, nu o copie incompletă tăcută.
Symlink-urile din interiorul unui folder NU se copiază (decizie 3.6): ţinta unui link e o cale a
SURSEI (adesea absolută) — pe alt host ar arăta altundeva sau nicăieri, iar urmarea lui ar putea
ieşi din arbore sau intra în buclă. Rândul lor e „skipped" cu o notă vizibilă (`copy.symlinkSkipped`).
Fişierele speciale (FIFO, device, socket) din arbore: tot „skipped" cu notă (fs_read le refuză oricum).
Regula „dacă există" pentru un folder: skip / overwrite = ÎMBINARE în folderul existent (fişierele
existente sărite, respectiv înlocuite — ca `cp -rn` / `cp -r`), rename = „nume (1)" nou.

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

COPY_MAX_FILES = 1000                # fişiere per job (inclusiv cele din foldere)
COPY_MAX_DIRS = 1000                 # directoare per job (foldere copiate, v58)
COPY_MAX_DEPTH = 32                  # adâncimea maximă sub un folder copiat
COPY_CHMOD_MIN_AGENT = 58            # `fs_chmod` există din agentul v58
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
    """Un rând al job-ului: fişier, director sau symlink (sărit). Rândurile de sus sunt căile cerute;
    copiii unui folder (v58) au `root` = rândul folderului şi `rel` = calea relativă în el."""
    __slots__ = ("src", "name", "dst", "size", "done", "state", "error", "kind", "root", "rel",
                 "depth", "mode", "note", "overwrite", "merge", "created", "fixed_dst")

    def __init__(self, src: str, name: Optional[str] = None, kind: str = "file",
                 root: "Optional[CopyFile]" = None, rel: str = "", depth: int = 0):
        self.src = src
        self.name = name if name is not None else src_name(src)
        self.dst = ""                 # calea finală pe destinaţie (după regula de conflict)
        self.size = 0
        self.done = 0
        self.state = "queued"         # queued | running | done | skipped | err | cancelled
        self.error = ""               # mesajul brut (englez); ruta îi dă un cod stabil
        self.kind = kind              # file | dir | link (link = doar în interiorul unui folder, sărit)
        self.root = root              # rândul folderului de sus (copiii), None = cale cerută
        self.rel = rel                # calea relativă sub folderul de sus („sub/x.sh")
        self.depth = depth
        self.mode = None              # biţii 0o777 ai sursei; None = necunoscut (nu se aplică)
        self.note = ""                # informaţie fără eroare („symlink nu se copiază")
        self.overwrite = False        # commit-ul are voie să înlocuiască o ţintă existentă
        self.merge = False            # (folder) destinaţia exista deja → îmbinare
        self.created = False          # (folder) l-am creat noi → îi aplicăm modul
        self.fixed_dst = ""           # (retry) folderul de sus aterizează EXACT aici, îmbinat


class CopyJob:
    def __init__(self, user_id, src_host, src_name_, dst_host, dst_name_, dst_dir, paths, on_conflict,
                 src_home=None, files=None):
        self.id = uuid.uuid4().hex
        self.user_id = user_id
        self.src_host = src_host
        self.src_host_name = src_name_
        self.dst_host = dst_host
        self.dst_host_name = dst_name_
        self.dst_dir = dst_dir         # canonic (absolut, din fs_list pe destinaţie)
        self.on_conflict = on_conflict
        self.src_home = src_home       # home-ul absolut al sursei (doar src==dst, pt. „acelaşi fişier")
        self.files = files if files is not None else [CopyFile(p) for p in paths]
        self.state = "running"         # running | done | failed | cancelled
        self.created = time.time()
        self.finished: Optional[float] = None
        self.cancelled = False
        self.task: Optional[asyncio.Task] = None
        self.buffered = 0              # octeţi ţinuţi ACUM în gateway (cozi + blocuri în curs)
        self.peak_buffered = 0         # vârful — testele verifică plafonul de memorie
        self._claimed: set = set()     # căi de destinaţie deja alese în job (rename fără coliziuni interne)
        self.modes: Optional[bool] = None   # True = destinaţia aplică modul (agent ≥ 58); None = încă nu ştim
        self.notes: list = []          # note la nivel de job (ex. copy.noModes)
        self._parent_modes: dict = {}  # director-părinte pe sursă → {nume: mod} (agent sursă < 58)

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


def _mode_of(v) -> Optional[int]:
    return v & 0o777 if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


async def _src_mode(job: CopyJob, path: str, st: dict) -> Optional[int]:
    """Modul unei căi cerute: din `fs_stat` (agent sursă ≥ 58), altfel din listarea părintelui
    (fs_list dă `mode` de mult) — o singură listare per părinte per job. Fără destinaţie care
    aplică modul nu-l căutăm deloc."""
    m = _mode_of(st.get("mode"))
    if m is not None or not job.modes:
        return m
    parent, _, name = path.rstrip("/").rpartition("/")
    parent = parent or "/"
    if parent not in job._parent_modes:
        try:
            listing = await core.fs_list(job.src_host, parent)
            job._parent_modes[parent] = {e.get("name"): _mode_of(e.get("mode"))
                                         for e in listing.get("entries") or [] if isinstance(e, dict)}
        except (core.FileError, TimeoutError):
            job._parent_modes[parent] = {}
    return job._parent_modes[parent].get(name)


def _budget(job: CopyJob):
    """(fişiere, directoare) deja în job — plafoanele se aplică pe tot job-ul."""
    nf = sum(1 for f in job.files if f.kind != "dir")
    nd = sum(1 for f in job.files if f.kind == "dir")
    return nf, nd


async def _walk(job: CopyJob, root: CopyFile) -> list:
    """Arborele unui folder de sus → rândurile copiilor (pre-ordine: un director înaintea
    conţinutului lui). Plafoane: fişiere/directoare per job, adâncime. Un subdirector ilizibil
    devine un rând `err` (restul arborelui continuă); unul trunchiat (prea mare de listat) sau
    depăşirea unui plafon = eroarea FOLDERULUI întreg (nu o copie parţială tăcută)."""
    nf, nd = _budget(job)
    listing = await core.fs_list(job.src_host, root.src)
    top = listing.get("path") or _abs_src(job, root.src)
    if job.src_host == job.dst_host:
        d = job.dst_dir.rstrip("/") + "/"
        if d.startswith(top.rstrip("/") + "/"):
            raise core.FileError("cannot copy a folder into itself: %s" % top)
    kids: list = []
    stack = [(listing, top, "", 0)]
    while stack:
        lst, path, rel, depth = stack.pop()
        if lst.get("truncated"):
            raise core.FileError("folder too large to list (over %d entries in one folder): %s"
                                 % (len(lst.get("entries") or []), path))
        out: list = []
        subdirs: list = []
        for e in lst.get("entries") or []:
            if not isinstance(e, dict) or not isinstance(e.get("name"), str):
                continue
            name = e["name"]
            if name in ("", ".", "..") or "/" in name or _CTRL.search(name):
                continue                      # un agent nu dă aşa ceva; nu-l transformăm în cale
            crel = rel + "/" + name if rel else name
            csrc = path.rstrip("/") + "/" + name
            disp = root.name + "/" + crel
            if e.get("link"):
                c = CopyFile(csrc, disp, "link", root, crel, depth + 1)
                c.state, c.note = "skipped", "symbolic link — not copied"
                nf += 1
            elif e.get("dir"):
                if depth + 1 > COPY_MAX_DEPTH:
                    raise core.FileError("folder too deep (more than %d levels): %s" % (COPY_MAX_DEPTH, top))
                c = CopyFile(csrc, disp, "dir", root, crel, depth + 1)
                c.mode = _mode_of(e.get("mode"))
                nd += 1
                subdirs.append(c)
            else:
                c = CopyFile(csrc, disp, "file", root, crel, depth + 1)
                c.size = int(e.get("size") or 0)
                c.mode = _mode_of(e.get("mode"))
                nf += 1
            if nf > COPY_MAX_FILES:
                raise core.FileError("folder too large: more than %d files in one copy" % COPY_MAX_FILES)
            if nd > COPY_MAX_DIRS:
                raise core.FileError("folder too large: more than %d folders in one copy" % COPY_MAX_DIRS)
            out.append(c)
        kids.extend(out)
        # parcurgere în adâncime cu stivă: subdirectoarele în ordine inversă, ca primul să iasă
        # primul; copiii unui subdirector se adaugă oricum DUPĂ el în `kids` (pre-ordine)
        for c in reversed(subdirs):
            try:
                sub = await core.fs_list(job.src_host, c.src)
            except core.FileError as e:
                c.state, c.error = "err", str(e) or "cannot list"
                continue
            stack.append((sub, c.src, c.rel, c.depth))
    return kids


async def _prepare(job: CopyJob, f: CopyFile) -> None:
    """Faza 1 (toate căile cerute, înainte de copiere): tipul şi mărimea pe sursă → totalul afişat;
    un folder îşi parcurge arborele (copiii intră în job imediat după el)."""
    st = await _stat(job.src_host, f.src)
    if not st.get("exists"):
        raise core.FileError("%s: No such file or directory" % f.src)
    if st.get("dir"):
        f.kind = "dir"
        f.mode = await _src_mode(job, f.src, st)
        kids = await _walk(job, f)
        i = job.files.index(f)
        job.files[i + 1:i + 1] = kids
        return
    # symlink cerut explicit: lstat-ul dă mărimea LINK-ului; mărimea reală vine din primul fs_read
    # (care urmează link-ul doar spre un fişier obişnuit — exact ca download-ul). Modul link-ului
    # (0777) nu spune nimic despre ţintă → nu aplicăm niciunul.
    if st.get("link"):
        f.size = 0
    else:
        f.size = int(st.get("size", 0))
        f.mode = await _src_mode(job, f.src, st)


async def _free_name(job: CopyJob, f: CopyFile) -> str:
    for n in range(1, COPY_RENAME_MAX + 1):   # rename: „nume (n).ext" (folder: „nume (n)"), primul liber
        cand = _join(job.dst_dir, "%s (%d)" % (f.name, n) if f.kind == "dir" else rename_candidate(f.name, n))
        if cand in job._claimed:
            continue
        if not (await _stat(job.dst_host, cand)).get("exists"):
            return cand
    raise core.FileError("no free name for %s (tried %d)" % (f.name, COPY_RENAME_MAX))


async def _resolve_dst(job: CopyJob, f: CopyFile) -> bool:
    """Alege calea finală după `on_conflict`. False = fişierul se sare (skip / acelaşi fişier)."""
    if f.root is not None:
        return await _resolve_child(job, f)
    want = _join(job.dst_dir, f.name)
    same_file = job.src_host == job.dst_host and _abs_src(job, f.src) == posixpath.normpath(want)
    st = await _stat(job.dst_host, want)
    f.overwrite = job.on_conflict == "overwrite"
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
    f.dst = await _free_name(job, f)
    job._claimed.add(f.dst)
    return True


async def _resolve_child(job: CopyJob, f: CopyFile) -> bool:
    """Un fişier din interiorul unui folder: calea e fixată de folder (`root.dst/rel`). Conflictul
    contează doar la îmbinare: skip (şi retry) → sărit, overwrite → înlocuit (un director sau link
    cu acelaşi nume → eroare). Într-un folder nou creat nu există nimic; commit-ul re-verifică."""
    f.dst = f.root.dst.rstrip("/") + "/" + f.rel
    if not f.root.merge:
        return True
    st = await _stat(job.dst_host, f.dst)
    if not st.get("exists"):
        return True
    if job.on_conflict != "overwrite" or f.root.fixed_dst:
        return False
    if st.get("dir") or st.get("link"):
        raise core.FileError("a folder or link with that name already exists on the destination")
    f.overwrite = True
    return True


def _skip_tree(root: CopyFile, kids: list) -> None:
    root.state = "skipped"
    for c in kids:
        if c.state == "queued":
            c.state = "skipped"


async def _mkdirs(job: CopyJob, root: CopyFile) -> None:
    """Faza 2a pentru un folder de sus: alege destinaţia (regula de conflict), creează folderul şi
    subdirectoarele în pre-ordine. Un subdirector care nu se poate crea îşi trage după el tot
    conţinutul (rânduri `err` — nu scriem în ceva ce nu există)."""
    kids = [c for c in job.files if c.root is root]
    want = _join(job.dst_dir, root.name)
    if root.fixed_dst:                        # retry: îmbinare în EXACT folderul de data trecută
        st = await _stat(job.dst_host, root.fixed_dst)
        if st.get("exists") and (not st.get("dir") or st.get("link")):
            raise core.FileError("a file with that name already exists on the destination")
        root.dst, root.merge = root.fixed_dst, bool(st.get("exists"))
    else:
        st = await _stat(job.dst_host, want)
        same = job.src_host == job.dst_host and _abs_src(job, root.src) == posixpath.normpath(want)
        if not st.get("exists") and want not in job._claimed:
            root.dst = want
        elif job.on_conflict == "rename":
            root.dst = await _free_name(job, root)
        elif same:
            return _skip_tree(root, kids)     # un folder peste el însuşi: nimic de făcut
        elif not st.get("dir") or st.get("link"):
            if job.on_conflict == "skip":
                return _skip_tree(root, kids)
            raise core.FileError("a file with that name already exists on the destination")
        else:
            root.dst, root.merge = want, True  # skip / overwrite pe un folder existent = îmbinare
    job._claimed.add(root.dst)
    if not root.merge:
        await core.fs_mkdir(job.dst_host, root.dst, parents=False)
        root.created = True
    root.state = "running"
    failed: list = []                         # prefixe `rel/` ale directoarelor eşuate
    for c in kids:
        if job.cancelled:
            return
        under = next((p for p in failed if c.rel.startswith(p)), None)
        if c.state == "err" and c.kind == "dir":
            failed.append(c.rel + "/")        # subdirector ilizibil pe sursă (din _walk)
            continue
        if c.state != "queued":
            continue
        if under is not None:
            c.state, c.error = "err", "parent folder could not be created: %s" % under.rstrip("/")
            if c.kind == "dir":
                failed.append(c.rel + "/")
            continue
        if c.kind != "dir":
            continue
        c.dst = root.dst.rstrip("/") + "/" + c.rel
        try:
            st = await _stat(job.dst_host, c.dst) if root.merge else {}
            if st.get("exists"):
                if not st.get("dir") or st.get("link"):
                    raise core.FileError("a file with that name already exists on the destination")
            else:
                await core.fs_mkdir(job.dst_host, c.dst, parents=False)
                c.created = True
            c.state = "running"
        except asyncio.CancelledError:
            raise
        except Exception as e:             # noqa: BLE001 — eroare PER DIRECTOR
            _fail(c, e)
            failed.append(c.rel + "/")


async def _chmod(job: CopyJob, f: CopyFile) -> None:
    """Modul sursei pe destinaţie (agent ≥ 58). Un eşec NU strică fişierul copiat: rămâne `done`,
    cu o notă (păstrează permisiunile implicite ale destinaţiei)."""
    if not job.modes or f.mode is None or not f.dst:
        return
    try:
        resp = await core._agent_or_raise(job.dst_host).request("fs_chmod", path=f.dst,
                                                                mode=f.mode & 0o777, timeout=30)
        if not resp.get("ok"):
            raise core.FileError(resp.get("msg") or resp.get("code") or "chmod failed")
    except asyncio.CancelledError:
        raise
    except Exception as e:                 # noqa: BLE001
        f.note = "permissions not applied: %s" % (str(e) or type(e).__name__)


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
        # strivim. overwrite: commit-ul o înlocuieşte atomic (os.replace; modul ţintei rămâne —
        # până la `_chmod` de mai jos, care pune modul SURSEI pe agent ≥ 58).
        if not f.overwrite and (await _stat(job.dst_host, f.dst)).get("exists"):
            raise core.FileError("the destination appeared during the copy: %s" % f.dst)
        await core.fs_upload_commit(job.dst_host, f.dst, uid, crc32=crc)
        committed = True
        await _chmod(job, f)
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
        # destinaţia aplică modul sursei? (`fs_chmod`, agent ≥ 58) — altfel copiem şi SPUNEM
        ver = getattr(core.sources.get(job.dst_host), "agent_version", 0) or 0
        job.modes = ver >= COPY_CHMOD_MIN_AGENT
        if not job.modes:
            job.notes.append({"code": "copy.noModes",
                              "msg": "permissions not preserved (destination agent < %d)" % COPY_CHMOD_MIN_AGENT})
        for f in [f for f in job.files if f.root is None]:   # faza 1: tip + mărime (+ arbore)
            if job.cancelled:
                break
            try:
                await _prepare(job, f)
            except asyncio.CancelledError:
                raise
            except Exception as e:             # noqa: BLE001 — eroare PER CALE, jobul continuă
                _fail(f, e)
        # faza 2a: folderele de sus — destinaţia + directoarele, în ordine (înaintea fişierelor)
        for root in [f for f in job.files if f.root is None and f.kind == "dir" and f.state == "queued"]:
            if job.cancelled:
                break
            try:
                await _mkdirs(job, root)
            except asyncio.CancelledError:
                raise
            except Exception as e:             # noqa: BLE001 — folderul eşuează, jobul continuă
                _fail(root, e)
                for c in job.files:
                    if c.root is root and c.state == "queued":
                        c.state, c.note = "skipped", "not copied: the folder could not be created"
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
                    if f.root is not None and "not a regular file" in str(e):
                        # FIFO / device / socket în interiorul unui folder: fs_list nu le deosebeşte
                        # de un fişier, fs_read le refuză. Sărit cu notă, nu eroare (ca symlink-urile).
                        f.state, f.size = "skipped", 0
                        f.note = "not a regular file (device, FIFO or socket) — not copied"
                    else:
                        _fail(f, e)

        tasks = [asyncio.ensure_future(one(f)) for f in job.files
                 if f.state == "queued" and f.kind == "file"
                 and (f.root is None or f.root.state == "running")]
        if tasks:
            await asyncio.gather(*tasks)
        # faza 2c: modul directoarelor create de noi, cel mai adânc primul (copiii stau mereu DUPĂ
        # părinte în listă) — la final, ca un director read-only pe sursă să fi primit fişierele
        for f in reversed(job.files):
            if f.kind == "dir" and f.state == "running":
                if f.created:
                    await _chmod(job, f)
                f.state = "done"
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
          src_home=None, files=None) -> CopyJob:
    purge()
    if running(user_id) >= COPY_RUNNING_PER_USER or running() >= COPY_RUNNING_MAX:
        raise CopyRefused("copy.busy", "too many copy jobs running; wait for one to finish",
                          {"max": COPY_RUNNING_PER_USER})
    if len(_jobs) >= COPY_JOBS_MAX:
        raise CopyRefused("copy.busy", "too many copy jobs in memory; retry later",
                          {"max": COPY_RUNNING_PER_USER})
    job = CopyJob(user_id, src_host, src_host_name, dst_host, dst_host_name, dst_dir, paths,
                  on_conflict, src_home=src_home, files=files)
    _jobs[job.id] = job
    job.task = asyncio.ensure_future(_run(job))
    return job


def retry(old: CopyJob) -> CopyJob:
    """Un job NOU cu ce n-a reuşit în `old` (eşuat / anulat), cu aceleaşi opţiuni. Retry-ul unui
    folder NU poate fi „re-trimite căile eşuate" (un fişier din `a/b/` ar ateriza în dst_dir, iar
    la rename folderul are alt nume pe destinaţie): re-parcurgem folderul şi îl ÎMBINĂM în EXACT
    folderul de data trecută (`fixed_dst`), sărind ce există deja — adică exact ce a reuşit
    (commit-ul e atomic: un fişier eşuat nu există sub numele final)."""
    if old.finished is None:
        raise CopyRefused("copy.running", "the copy is still running")
    files = []
    for f in old.files:
        if f.root is not None:
            continue
        if f.kind == "dir":
            bad = f.state in ("err", "cancelled") or any(
                c.state in ("err", "cancelled") for c in old.files if c.root is f)
            if bad:
                nf = CopyFile(f.src)
                nf.fixed_dst = f.dst            # "" = destinaţia nu se alesese → regula normală
                files.append(nf)
        elif f.state in ("err", "cancelled"):
            files.append(CopyFile(f.src))
    if not files:
        raise CopyRefused("copy.nothingToRetry", "nothing failed in that copy")
    return start(old.user_id, old.src_host, old.src_host_name, old.dst_host, old.dst_host_name,
                 old.dst_dir, [], old.on_conflict, src_home=old.src_home, files=files)


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


_NOTE_CODES = (("symbolic link", "copy.symlinkSkipped"), ("not a regular file", "copy.specialSkipped"),
               ("permissions not applied", "copy.modeFailed"), ("not copied: the folder", "copy.parentFailed"))


def to_dict(job: CopyJob, files: bool, code_of=None) -> dict:
    """Starea pentru GET. `files=False` (polling-ul widgetului) = doar totaluri + erorile (plafonate),
    ca un job de 1000 de fişiere să nu trimită 1000 de rânduri pe secundă. `code_of(msg)` dă
    codul stabil al unei erori (maparea din api, aceeaşi ca la rutele fs).

    `files_*` numără fişierele (inclusiv symlink-urile sărite din foldere), `folders_*` directoarele;
    `files_failed` = TOATE rândurile eşuate (şi folderele), ca un job `failed` să nu arate „0 eşuate".
    `current` = fişierele în zbor (progresul per fişier din Transferuri), `notes` = note de job
    (ex. `copy.noModes`), `noted` = rânduri cu o notă (symlink / fişier special sărit, mod neaplicat)."""
    total, done = job.totals()
    code_of = code_of or (lambda m: "files.failed")

    def row(f: CopyFile) -> dict:
        r = {"src": f.src, "name": f.name, "dst": f.dst, "size": f.size, "done": f.done, "state": f.state,
             "kind": f.kind}
        if f.error:
            r.update(error=f.error, code=code_of(f.error))
        if f.note:
            r["note"] = f.note
            r["note_code"] = next((c for pre, c in _NOTE_CODES if f.note.startswith(pre)), "copy.note")
        return r

    errs = [f for f in job.files if f.state == "err"]
    fl = [f for f in job.files if f.kind != "dir"]
    dirs = [f for f in job.files if f.kind == "dir"]
    noted = [f for f in job.files if f.note]
    out = {
        "job_id": job.id, "state": job.state,
        "src_host": job.src_host, "src_host_name": job.src_host_name,
        "dst_host": job.dst_host, "dst_host_name": job.dst_host_name,
        "dst_dir": job.dst_dir, "on_conflict": job.on_conflict,
        "total_bytes": total, "done_bytes": done,
        "files_total": len(fl),
        "files_done": sum(1 for f in fl if f.state == "done"),
        "files_skipped": sum(1 for f in fl if f.state == "skipped"),
        "files_failed": len(errs),
        "folders_total": len(dirs),
        "folders_done": sum(1 for f in dirs if f.state == "done"),
        "modes": job.modes,
        "notes": list(job.notes),
        "current": [f.name for f in fl if f.state == "running"][:COPY_PARALLEL],
        "created": job.created, "finished": job.finished,
        "errors": [row(f) for f in errs[:50]],
        "noted": [row(f) for f in noted[:50]],
        "noted_total": len(noted),
    }
    if files:
        out["files"] = [row(f) for f in job.files]
    return out
