"""Migration of 3.7 plaintext recordings to WTX1 (ENCRYPTION-AT-REST.md §12.11.5, PR6b).

Active only with encrypted recordings on (`txhub.boot` → `boot(st)` after the erasure journal and
`Store.recover()`, before reconcile and before any writer). Pieces:

* **Inventory** (`boot`, once per volume, `tx_state.migration_inventory`): one listing of
  `transcripts/` and `transcripts/arhiva/` through their fds (no link followed) fills `tx_migration`
  in one transaction: `<sid>.out|.cast` regular files with one link → `pending` (`orphan` when the
  session row is gone); the absent kind of a one-kind pair → `missing`; anything else (a name outside
  the allowlist, a link, a non-regular file, a hard link, the same recording in both directories) →
  `failed` with the reason, never migrated. The inventory is the only source of "this sid may
  still be plaintext" (`Store._open_plain`). Generation files, `.wt-del-*` and `.cap-tmp` names are
  not plaintext recordings and are not inventoried.
* **Conversion** (`process`, under the sid's lease): `Store.convert_plain` (steps 1–5: pinned fd,
  free space, RK, encrypt + hash, seal + fsync, read-back through the reader, one transaction with
  both descriptors flagged `converted`), then step 6 per kind: `renameat2(RENAME_NOREPLACE)` to a
  private name, identity check against the pinned fd and the row, `unlinkat`, directory fsync, row
  → `unlinked`. Only the verified inode is ever deleted; a mismatch is renamed back, the row goes
  `failed` and an alarm is raised. Without `renameat2` nothing is deleted (the row stays
  `converted`, listed).
* **Order** (janitor, one sid at a time): closed sessions, then `arhiva/`, then `lost`, then the
  rest (orphans in `transcripts/`). A `creating` / `live` session is converted at its writer start
  instead (`at_writer_start`, the Store's `before_writer` hook; at most 2 at once); its writer is
  refused while a kind is still `pending` / `orphan` / `failed` (a protected session never writes
  next to plaintext it could not convert).
* **Crash rules** (`boot`): `converted` with the file present → step 4 again against the published
  descriptor (plaintext hash = decrypted prefix hash = the row's), then step 6; `converted` with the
  file absent → a `.wt-del-*` name holding the row's identity is unlinked, the row → `unlinked`;
  `pending` next to an RK or a descriptor of the same sid → `failed` + integrity alarm. A leftover
  private name that no row explains is listed, never deleted.
* **Erased sids**: the plaintext of a tombstoned sid is removed through the same identity-checked
  unlink (the journal entry is the intent), row → `unlinked` with `error = erased`.
* **Global flag**: `tx_state.recordings_format = wtx1` once no row is `pending`, `orphan`, `failed`
  or `converted` (stricter than §12.11.5, which names only pending/failed: a converted row still has
  its plaintext on disk) AND a residual inventory under the Store barrier finds no plaintext name
  and no unexplained private name; then an empty `arhiva/` is removed.
* **Health** (`status`): migrated n / N, bytes left, one-kind, orphans, failed, stray plaintext (a
  file that appeared after the inventory: never served), leftover private names, last error.
* **Recompaction** (§12.11.14, `recompact_once`, every janitor pass after the plaintext
  migration): closed recordings that still hold WTX1 version-1 generations are rewritten into one
  compressed generation per kind (`Store.recompact`, under the sid's lease), at most
  RECOMPACT_PASS_BYTES of old generations per pass, largest first. A sid with a running writer,
  in quarantine or erased is skipped; an error leaves the old generations served and retries
  after RETRY_SECS. No operator command: it starts on its own once compression is on.
"""
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import stat
import time
from dataclasses import dataclass, field

from . import keys, txformat, txstore

log = logging.getLogger("webterm.migration")

_PLAIN_RE = re.compile(r"^([0-9a-f]{32})\.(out|cast)$")
# = core.CAP_TMP_SUFFIX (core importă txhub → txhub importă migration: nu importăm core)
CAP_TMP_SUFFIX = ".cap-tmp"
RETRY_SECS = 3600.0               # §12.11.5: o eroare lasă textul clar pe loc, reîncercare peste 1 h
PINNED_RETRY_SECS = 60.0          # unlink amânat cât un backup copiază textul clar (PR6c)
FAILED_LIST_MAX = 20              # System health: câte sesiuni cu rânduri eşuate se numesc
INTERVAL = 60.0
LIVE_CONCURRENCY = 2              # conversii simultane la pornirea writer-elor (reconcile la boot)
RECOMPACT_PASS_BYTES = 256 * 1024 * 1024    # §12.11.14: generaţii v1 rescrise pe trecere (~1/min)
WORK_STATES = ("pending", "orphan", "converted")
BLOCKING = ("pending", "orphan", "failed", "converted")     # ţin flag-ul global jos
_MAX_ERR = 300


@dataclass
class _State:
    store: object = None
    booted: bool = False
    task: object = None
    wake: object = None
    sem: object = None
    backoff: dict = field(default_factory=dict)     # sid → momentul următoarei încercări
    last_error: str = ""
    stray: list = field(default_factory=list)
    leftovers: list = field(default_factory=list)
    format_block: str = ""        # M2: de ce nu e publicat recordings_format (rows | residual | leftovers)
    # §12.11.14 recompactare: progres de la boot (System health), erori pe sid, backoff propriu
    rc_backoff: dict = field(default_factory=dict)
    rc_failed: dict = field(default_factory=dict)
    rc_done: int = 0
    rc_before: int = 0
    rc_after: int = 0
    rc_left: tuple = (0, 0)


_s = _State()


def reset():
    t = _s.task
    if t is not None:
        t.cancel()
    st = _s.store
    if st is not None and getattr(st, "before_writer", None) is at_writer_start:
        st.before_writer = None
    globals()["_s"] = _State()


def ready() -> bool:
    """§12.11 PR5/PR6 gate: the inventory exists and the crash pass ran at this boot."""
    return _s.booted


def active() -> bool:
    return _s.booted and _s.store is not None


def _err(e) -> str:
    return str(e)[:_MAX_ERR]


# ── inventory ────────────────────────────────────────────────────────────────


def _skip(name) -> bool:
    return (keys.is_reserved_name(name, "transcripts") or name.startswith(txstore.DEL_PREFIX)
            or name.endswith(CAP_TMP_SUFFIX))


def _entry(dirn, name, dfd) -> dict:
    e = {"dir": dirn, "name": name, "sid": None, "kind": None, "ident": None, "reason": ""}
    m = _PLAIN_RE.match(name)
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except OSError as x:
        e["reason"] = "cannot stat: %s" % x.strerror
        return e
    if m:
        e["sid"], e["kind"] = m.group(1), m.group(2)
    if not m:
        e["reason"] = "name outside the recording allowlist"
    elif stat.S_ISLNK(st.st_mode):
        e["reason"] = "symbolic link"
    elif not stat.S_ISREG(st.st_mode):
        e["reason"] = "not a regular file"
    elif st.st_nlink != 1:
        e["reason"] = "hard link (%d links)" % st.st_nlink
    else:
        e["ident"] = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    return e


def list_plain_sync(st) -> list:
    """Every non-generation entry of `transcripts/` and `transcripts/arhiva/` (through fds, no
    link followed), as dicts {dir, name, sid, kind, ident, reason}."""
    out = []
    for n in sorted(os.listdir(st.dir_fd)):
        if _skip(n):
            continue
        if n == "arhiva":
            lst = os.stat(n, dir_fd=st.dir_fd, follow_symlinks=False)
            if stat.S_ISDIR(lst.st_mode):
                dfd, _own = st.plain_dir_fd("arhiva")
                try:
                    for m in sorted(os.listdir(dfd)):
                        if not _skip(m):
                            out.append(_entry("arhiva", m, dfd))
                finally:
                    os.close(dfd)
                continue
        out.append(_entry("transcripts", n, st.dir_fd))
    return out


def _row_key(e):
    """(sid, kind) of the row: the recording's own for an allowlisted name, else the path."""
    if e["sid"] and e["kind"]:
        return e["sid"], e["kind"]
    return "%s/%s" % (e["dir"], e["name"]), "-"


def _inventory_txn(entries, now):
    def fn(c):
        if c.execute("SELECT 1 FROM tx_state WHERE key='migration_inventory'").fetchone():
            return False
        rows = {}
        for e in entries:
            key = _row_key(e)
            if key in rows:
                # două fişiere pentru acelaşi rând (transcripts/ şi arhiva/): refuzat, niciodată ghicit
                rows[key]["reason"] = "duplicate: the same recording in transcripts/ and arhiva/"
                rows[key]["ident"] = None
                continue
            rows[key] = dict(e)
        sids = {k[0] for k, e in rows.items() if e["kind"]}
        with_row = {r[0] for r in c.execute("SELECT id FROM sessions").fetchall()}
        for (sid, kind), e in rows.items():
            ident = e["ident"] or (None, None, None, None)
            if e["reason"] or e["ident"] is None:
                state, err = "failed", e["reason"] or "unreadable"
            else:
                state, err = ("pending" if sid in with_row else "orphan"), None
            c.execute("INSERT INTO tx_migration(sid, kind, dir, name, dev, ino, size, mtime_ns, state, error) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?)", (sid, kind, e["dir"], e["name"]) + tuple(ident) + (state, err))
        for sid in sids:
            for kind in txstore.KIND_NAMES:
                if (sid, kind) not in rows:
                    other = rows[(sid, "out" if kind == "cast" else "cast")]
                    c.execute("INSERT INTO tx_migration(sid, kind, dir, name, state) VALUES(?,?,?,?,'missing')",
                              (sid, kind, other["dir"], sid + "." + kind))
        c.execute("INSERT INTO tx_state(key, value) VALUES('migration_inventory', ?)",
                  (json.dumps({"time": now, "rows": len(rows)}, sort_keys=True),))
        return True
    return fn


# ── per-row helpers ──────────────────────────────────────────────────────────


async def _set_row(st, sid, kind, state, error=None, *, expect=None):
    def fn(c):
        q = "UPDATE tx_migration SET state=?, error=? WHERE sid=? AND kind=?"
        a = (state, error, sid, kind)
        if expect:
            q += " AND state IN (%s)" % ",".join("?" * len(expect))
            a += tuple(expect)
        c.execute(q, a)
    await st.txn(fn)


async def _fail(st, sid, kind, why, alarm="transcript.migrationFailed"):
    await _set_row(st, sid, kind, "failed", _err(why))
    st.alarm(alarm, "%s.%s: %s" % (sid, kind, why))


def _hash_fd_sync(fd, size):
    h = hashlib.sha256()
    pos = 0
    while pos < size:
        b = os.pread(fd, min(txstore.CAP_CHUNK, size - pos), pos)
        if not b:
            break
        h.update(b)
        pos += len(b)
    return h.hexdigest(), pos


async def _unlink_step(st, sid, kind, dirn, name, ident, pin_fd, *, ok_error=None):
    """Step 6 for one kind, the plaintext pinned by `pin_fd`. Returns the row's new state."""
    pin_st = os.fstat(pin_fd)
    if getattr(st, "plain_pinned", None) is not None and st.plain_pinned(dirn, name):
        # PR6c (§12.11.3): un backup copiază acum textul ăsta (DB-ul lui copiat îl ţine `pending`):
        # unlink-ul se amână, rândul rămâne `converted`, janitorul îl reia după backup
        _s.backoff[sid] = time.time() + PINNED_RETRY_SECS
        return "kept"
    try:
        priv = await st.io(st.rename_private_sync, dirn, name)
    except FileNotFoundError:
        return await _absent(st, sid, kind, dirn, ident, ok_error=ok_error)
    except OSError as e:
        # fără renameat2 (sau un FS care refuză NOREPLACE) nu ştergem nimic: rândul îşi păstrează
        # starea (converted / pending), doar eroarea se notează; reîncercare cu backoff
        err = "plaintext kept: identity-checked unlink unavailable (%s)" % (e.strerror or e)
        await st.txn(lambda c: c.execute("UPDATE tx_migration SET error=? WHERE sid=? AND kind=?",
                                         (_err(err), sid, kind)))
        _s.backoff[sid] = time.time() + RETRY_SECS
        _s.last_error = err
        st.alarm("transcript.migrationUnlink", "%s.%s: %s" % (sid, kind, err))
        return "kept"
    st._fault("mig-renamed")
    res = await st.io(st.unlink_private_sync, dirn, name, priv, ident, pin_st)
    if res != "unlinked":
        why = "identity check failed at unlink (%s%s)" % (res, ": " + priv if res == "stuck" else "")
        await _fail(st, sid, kind, why, "transcript.migrationUnlink")
        return "failed"
    st._fault("mig-unlinked")
    await _set_row(st, sid, kind, "unlinked", ok_error)
    return "unlinked"


async def _absent(st, sid, kind, dirn, ident, *, ok_error=None):
    """The plaintext is not under its name any more (crash after the rename or after unlinkat):
    a private name holding exactly the row's identity is unlinked; the row → unlinked.

    M2: otherwise "verified absent" (no private name at all: the row → unlinked with error
    `absent`) is told apart from a CONFLICT (a private name with another identity is there: we
    cannot say where the plaintext went → `failed`, the Owner resolves it; the global format flag
    stays down). The identity check assumes no other process with write access to the directory
    races us, and an unlink never removes copies made elsewhere (backups, snapshots)."""
    other = False
    for priv in await st.io(st.list_private_sync, dirn):
        res = await st.io(st.unlink_held_sync, dirn, priv, ident)
        if res == "unlinked":
            await _set_row(st, sid, kind, "unlinked", ok_error)
            return "unlinked"
        other = other or res == "other"
    if other:
        await _fail(st, sid, kind, "conflict: gone from its name while a private name holds another file",
                    "transcript.migrationUnlink")
        return "failed"
    await _set_row(st, sid, kind, "unlinked", ("%s; absent" % ok_error) if ok_error else "absent")
    return "absent"


def physical_outcome(r) -> str:
    """What happened to a row's plaintext on disk: unlinked (identity-checked delete) | absent
    (verified gone: neither under its name nor under a private name) | kept (still on disk, retried
    later: backup pin, no renameat2, pending) | failed (identity changed / conflict: still there)."""
    state, err = r["state"], r.get("error") or ""
    if state == "unlinked":
        return "absent" if err.endswith("absent") else "unlinked"
    if state == "missing":
        return "absent"
    if state == "failed":
        return "failed"
    return "kept"


def _ident(r):
    return (r["dev"], r["ino"], r["size"], r["mtime_ns"])


async def _finish_converted(st, r):
    """A `converted` row (crash rule, or an earlier unlink that could not run): step 4 again
    against the published descriptor, then step 6."""
    sid, kind, dirn, name = r["sid"], r["kind"], r["dir"], r["name"]
    ident = _ident(r)
    try:
        fd = await st.io(st._pin_plain_sync, dirn, name, ident)
    except txstore.TxStoreError as e:
        if e.reason == "absent":
            return await _absent(st, sid, kind, dirn, ident)
        await _fail(st, sid, kind, "changed after conversion: %s" % e)
        return "failed"
    try:
        plain, n = await st.io(_hash_fd_sync, fd, ident[2])
        try:
            dec, m = await st.converted_prefix_digest(sid, kind, ident[2])
        except txstore.TxStoreError as e:
            if e.reason == "quarantined":
                return "converted"            # se reîncearcă după ridicarea carantinei
            await _fail(st, sid, kind, "cannot re-verify the conversion: %s" % e, "transcript.integrity")
            return "failed"
        if not (plain == dec == r["sha256"] and n == m == ident[2]):
            await _fail(st, sid, kind, "read-back differs from the converted plaintext", "transcript.integrity")
            return "failed"
        return await _unlink_step(st, sid, kind, dirn, name, ident, fd)
    finally:
        os.close(fd)


async def _drop_erased(st, r):
    """The plaintext of an erased (tombstoned) sid: identity-checked unlink, no conversion."""
    sid, kind, dirn, name = r["sid"], r["kind"], r["dir"], r["name"]
    ident = _ident(r)
    try:
        fd = await st.io(st._pin_plain_sync, dirn, name, ident)
    except txstore.TxStoreError as e:
        if e.reason == "absent":
            return await _absent(st, sid, kind, dirn, ident, ok_error="erased")
        await _fail(st, sid, kind, "erased, but the plaintext changed since the inventory: %s" % e)
        return "failed"
    try:
        return await _unlink_step(st, sid, kind, dirn, name, ident, fd, ok_error="erased")
    finally:
        os.close(fd)


async def _rows(st, sid):
    def load(c):
        cur = c.execute("SELECT sid, kind, dir, name, dev, ino, size, mtime_ns, sha256, state, error "
                        "FROM tx_migration WHERE sid=? ORDER BY kind", (sid,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
    return await st.read(load)


async def _has_encrypted(st, sid):
    return await st.read(lambda c: bool(
        c.execute("SELECT 1 FROM session_keys WHERE sid=?", (sid,)).fetchone()
        or c.execute("SELECT 1 FROM tx_descriptors WHERE sid=?", (sid,)).fetchone()))


# ── one session ──────────────────────────────────────────────────────────────


async def process(st, sid, *, live=False):
    """Everything pending for `sid`, under its lease. Returns {kind: state} after the pass."""
    async with st.lease(sid):
        rows = await _rows(st, sid)
        if sid in st.tombstoned:
            for r in rows:
                if r["state"] in WORK_STATES:
                    await _drop_erased(st, r)
            return {r["kind"]: r["state"] for r in await _rows(st, sid)}
        work = [r for r in rows if r["state"] in ("pending", "orphan")]
        if work:
            if await _has_encrypted(st, sid):
                # §12.11.5: pending lângă un descriptor/RK nu poate apărea (pasul 5 e o tranzacţie)
                for r in work:
                    await _fail(st, sid, r["kind"], "integrity: an encrypted recording exists for a "
                                "pending plaintext", "transcript.integrity")
            else:
                await _convert(st, sid, work, live)
        else:
            for r in rows:
                if r["state"] == "converted":
                    await _finish_converted(st, r)
        return {r["kind"]: r["state"] for r in await _rows(st, sid)}


async def _convert(st, sid, work, live):
    origin = "orphan" if any(r["state"] == "orphan" for r in work) else "migrated"
    spec = {r["kind"]: (r["dir"], r["name"], _ident(r)) for r in work}
    try:
        _sha, fds = await st.convert_plain(sid, spec, origin=origin, live=live)
    except txstore.TxStoreError as e:
        k = getattr(e, "kind", None)
        if e.reason in ("absent", "changed") and k:
            await _fail(st, sid, k, ("missing since the inventory" if e.reason == "absent"
                                     else "changed since the inventory") + ": %s" % e)
            rest = [r for r in work if r["kind"] != k]
            if rest and not await _has_encrypted(st, sid):
                # celălalt kind al perechii e încă bun: convertit singur (o înregistrare one-kind)
                await _convert(st, sid, rest, live)
        else:
            # disc plin, read-back greşit, CAS, eroare de I/O: textul clar rămâne, reîncercare
            _s.backoff[sid] = time.time() + RETRY_SECS
            _s.last_error = "%s: %s" % (sid[:8], _err(e))
            for r in work:
                await _set_row(st, sid, r["kind"], r["state"], _err(e), expect=(r["state"],))
            st.alarm("transcript.migrationRetry", "%s: %s" % (sid, e))
        return
    _s.backoff.pop(sid, None)
    try:
        for r in work:
            await _unlink_step(st, sid, r["kind"], r["dir"], r["name"], _ident(r), fds[r["kind"]])
    finally:
        for fd in fds.values():
            with contextlib.suppress(OSError):
                os.close(fd)


# ── writer start, erase ──────────────────────────────────────────────────────


async def _open_states(st, sid):
    return await st.read(lambda c: {r[0]: r[1] for r in c.execute(
        "SELECT kind, state FROM tx_migration WHERE sid=?", (sid,)).fetchall()})


async def at_writer_start(sid):
    """The Store's `before_writer` hook: a live session is converted before its first generation.
    Refuses the writer (TxStoreError `migrationPending`) while plaintext of the sid could not be
    converted."""
    st = _s.store
    if st is None or not _s.booted:
        raise txstore.TxStoreError("migrationPending", "the migration is not ready")
    states = await _open_states(st, sid)
    if not any(v in BLOCKING for v in states.values()):
        return
    if _s.sem is None:
        _s.sem = asyncio.Semaphore(LIVE_CONCURRENCY)
    async with _s.sem:
        await process(st, sid, live=True)
    left = {k: v for k, v in (await _open_states(st, sid)).items() if v in ("pending", "orphan", "failed")}
    if left:
        raise txstore.TxStoreError("migrationPending", "%s: plaintext not migrated (%s)" % (
            sid, ", ".join("%s=%s" % kv for kv in sorted(left.items()))))


async def before_erase(st, sid):
    """Erasure of a recording still in plaintext = migrate it first, then the normal erasure
    (destroying the RK makes the converted copy unreadable; the plaintext is already gone through
    the identity-checked unlink). Whatever cannot be migrated stays refused by `erasure.erase`."""
    if not active() or _s.store is not st:
        return
    states = await _open_states(st, sid)
    if any(v in WORK_STATES for v in states.values()):
        await process(st, sid)


# ── Owner resolution of failed rows (PR6c) ───────────────────────────────────


def _repin_sync(st, dirn, name):
    """The plaintext under its row's name NOW, through its dir fd (O_NOFOLLOW): regular and one
    link, or TxStoreError. → (dev, ino, size, mtime_ns); None when it is absent."""
    try:
        dfd, own = st.plain_dir_fd(dirn)
    except FileNotFoundError:
        return None
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
        except FileNotFoundError:
            return None
        except OSError as e:
            raise txstore.TxStoreError("changed", "%s/%s: %s" % (dirn, name, e.strerror)) from None
    finally:
        if own:
            os.close(dfd)
    try:
        fs = os.fstat(fd)
    finally:
        os.close(fd)
    if not stat.S_ISREG(fs.st_mode) or fs.st_nlink != 1:
        raise txstore.TxStoreError("changed", "%s/%s: not a plain single-link file" % (dirn, name))
    return (fs.st_dev, fs.st_ino, fs.st_size, fs.st_mtime_ns)


async def failed_rows(st, sid):
    """The sid's `failed` rows that name a recording (`<sid>.<kind>`), not a stray path."""
    return [r for r in await _rows(st, sid)
            if r["state"] == "failed" and r["kind"] in txstore.KINDS and r["dir"] in ("transcripts", "arhiva")
            and r["name"] == "%s.%s" % (sid, r["kind"])]


async def rebind_failed(st, sid, rows, *, state):
    """Caller holds the sid's lease. Each failed row is re-inventoried from the file now under its
    name (the Owner vouches for it): identity refreshed, hash cleared, → `state`; a file that is
    gone → `missing` (nothing left to protect, the writer may start)."""
    for r in rows:
        ident = await st.io(_repin_sync, st, r["dir"], r["name"])
        if ident is None:
            await _set_row(st, sid, r["kind"], "missing", "absent when the Owner resolved it", expect=("failed",))
            continue

        def fn(c, r=r, ident=ident):
            c.execute("UPDATE tx_migration SET state=?, error=NULL, sha256=NULL, dev=?, ino=?, size=?, "
                      "mtime_ns=? WHERE sid=? AND kind=? AND state='failed'", (state, *ident, sid, r["kind"]))
        await st.txn(fn)


async def retry(st, sid, *, live=False):
    """Owner retry (`POST /api/recordings/migration/{sid}/retry`): the failed rows → `pending` with
    the current file's identity, then one conversion pass. Refused when the sid already has an
    encrypted recording (the plaintext cannot be merged into it; discard is the way out). Returns
    {kind: state} after the pass."""
    if not active() or _s.store is not st:
        raise txstore.TxStoreError("disabled", "the migration is not active")
    async with st.lease(sid):
        rows = await failed_rows(st, sid)
        if not rows:
            raise txstore.TxStoreError("notFailed", "no failed migration for this session")
        if await _has_encrypted(st, sid):
            raise txstore.TxStoreError("encrypted", "this session already has an encrypted recording; "
                                       "its failed plaintext can only be discarded")
        await rebind_failed(st, sid, rows, state="pending")
    _s.backoff.pop(sid, None)
    return await process(st, sid, live=live)


async def failed_sessions(st, limit=FAILED_LIST_MAX):
    return await st.read(lambda c: [r[0] for r in c.execute(
        "SELECT DISTINCT sid FROM tx_migration WHERE state='failed' AND kind IN ('out','cast') "
        "ORDER BY sid LIMIT ?", (limit,)).fetchall()])


# ── boot ─────────────────────────────────────────────────────────────────────


async def boot(st, clock=time.time):
    """Inventory (first boot of the volume), then the crash rules. After `Store.recover()`."""
    reset()
    s = _s
    s.store = st
    have = await st.read(lambda c: c.execute(
        "SELECT 1 FROM tx_state WHERE key='migration_inventory'").fetchone())
    if have is None:
        entries = await st.io(list_plain_sync, st)
        await st.txn(_inventory_txn(entries, clock()))
    sids = await st.read(lambda c: sorted({r[0] for r in c.execute(
        "SELECT sid FROM tx_migration WHERE state IN ('pending','orphan','converted')").fetchall()}))
    for sid in sids:
        rows = await _rows(st, sid)
        if sid in st.tombstoned:
            await process(st, sid)
            continue
        if any(r["state"] in ("pending", "orphan") for r in rows) and await _has_encrypted(st, sid):
            async with st.lease(sid):
                for r in rows:
                    if r["state"] in ("pending", "orphan"):
                        await _fail(st, sid, r["kind"], "integrity: an encrypted recording exists for "
                                    "a pending plaintext", "transcript.integrity")
        if any(r["state"] == "converted" for r in rows):
            async with st.lease(sid):
                for r in await _rows(st, sid):
                    if r["state"] == "converted":
                        await _finish_converted(st, r)
    await _scan(st)
    st.before_writer = at_writer_start
    s.booted = True


# ── janitor ──────────────────────────────────────────────────────────────────


def _rank(dirn, sess_state):
    if sess_state == "closed" and dirn == "transcripts":
        return 0
    if dirn == "arhiva":
        return 1
    if sess_state == "lost":
        return 2
    return 3


async def run_once(st, now=None):
    """One janitor pass: every eligible sid in order, the stray scan, the global flag."""
    now = time.time() if now is None else now
    rows = await st.read(lambda c: c.execute(
        "SELECT m.sid, m.dir, s.state FROM tx_migration m LEFT JOIN sessions s ON s.id = m.sid "
        "WHERE m.state IN ('pending','orphan','converted')").fetchall())
    order = {}
    for sid, dirn, sess in rows:
        if sess in ("creating", "live"):
            continue                               # convertită la pornirea writer-ului
        order[sid] = min(order.get(sid, 9), _rank(dirn, sess))
    for sid in sorted(order, key=lambda x: (order[x], x)):
        rec = st.recorders.get(sid)
        if sid in st._starting or (rec is not None and rec.state == "running"):
            continue
        if _s.backoff.get(sid, 0) > now:
            continue
        await process(st, sid)
    await _scan(st)
    await maybe_publish_format(st)
    await recompact_once(st, now)


# ── recompaction (§12.11.14) ─────────────────────────────────────────────────


async def recompact_once(st, now=None, budget=RECOMPACT_PASS_BYTES):
    """One pass: closed recordings with version-1 generations, largest first, until `budget`
    bytes of old generations were rewritten (the first one always runs). Returns the number of
    sids rewritten."""
    s = _s
    if getattr(st, "write_ver", None) != txformat.VERSION_Z:
        return 0
    now = time.time() if now is None else now
    cands = await st.recompact_candidates()
    left = {sid: n for sid, n in cands}
    spent = done = 0
    for sid, n in cands:
        if spent and spent + n > budget:
            continue
        rec = st.recorders.get(sid)
        if sid in st._starting or (rec is not None and rec.state == "running"):
            continue                               # o sesiune cu writer: reluată după închidere
        if s.rc_backoff.get(sid, 0) > now:
            continue
        try:
            async with st.lease(sid):
                res = await st.recompact(sid)
        except Exception as e:                      # noqa: BLE001 — un sid nu opreşte trecerea
            reason = getattr(e, "reason", "")
            if reason in ("erased", "cas"):
                continue                            # şters / schimbat între timp: trecerea următoare decide
            s.rc_backoff[sid] = now + RETRY_SECS
            if reason != "disk":
                s.rc_failed[sid] = _err(e)
                st.alarm("transcript.recompactRetry", "%s: %s" % (sid, e))
            continue
        if not res:
            continue
        s.rc_failed.pop(sid, None)
        s.rc_backoff.pop(sid, None)
        left.pop(sid, None)
        before = sum(a for a, _b in res.values())
        s.rc_done += 1
        s.rc_before += before
        s.rc_after += sum(b for _a, b in res.values())
        spent += before
        done += 1
        if spent >= budget:
            break
    s.rc_failed = {k: v for k, v in s.rc_failed.items() if k in left}
    s.rc_left = (len(left), sum(left.values()))
    return done


def recompact_status():
    s = _s
    return {"left": s.rc_left[0], "left_bytes": s.rc_left[1], "done": s.rc_done,
            "saved_bytes": max(0, s.rc_before - s.rc_after), "failed": len(s.rc_failed),
            "error": next(iter(s.rc_failed.values()), "")}


async def _scan(st):
    """Stray plaintext (not in the inventory: never served) and unexplained private names."""
    entries = await st.io(list_plain_sync, st)
    known = await st.read(lambda c: {(r[0], r[1]) for r in c.execute(
        "SELECT dir, name FROM tx_migration WHERE state IN ('pending','orphan','failed','converted')").fetchall()})
    stray = ["%s/%s" % (e["dir"], e["name"]) for e in entries if (e["dir"], e["name"]) not in known]
    left = []
    for d in ("transcripts", "arhiva"):
        left += ["%s/%s" % (d, n) for n in await st.io(st.list_private_sync, d)]
    for x in set(stray) - set(_s.stray):
        st.alarm("transcript.migrationStray", "%s: plaintext outside the inventory (never served)" % x)
    for x in set(left) - set(_s.leftovers):
        st.alarm("transcript.migrationLeftover", "%s: private name left by an interrupted unlink" % x)
    _s.stray, _s.leftovers = stray, left


async def maybe_publish_format(st):
    """`recordings_format = wtx1` once nothing is pending, orphan, failed or converted AND (M2) a
    residual inventory taken now finds nothing: no plaintext name outside the inventory, no
    private `.wt-del-*` name nobody explains. The listing and the publication run under the
    Store's barrier (no conversion, erasure, backup step 1 or writer ledger commit in between: the
    only processes that create names under `transcripts/` while the gateway runs) and inside ONE
    transaction with the row check. A residue blocks the flag until the Owner resolves it
    (`_s.format_block` names why; System health lists stray / leftovers)."""
    async with st.barrier:
        if await st.read(lambda c: c.execute(
                "SELECT value FROM tx_state WHERE key='recordings_format'").fetchone()) is not None:
            _s.format_block = ""
            return True
        entries = await st.io(list_plain_sync, st)
        left = []
        for d in ("transcripts", "arhiva"):
            left += ["%s/%s" % (d, n) for n in await st.io(st.list_private_sync, d)]

        def fn(c):
            if c.execute("SELECT 1 FROM tx_migration WHERE state IN ('pending','orphan','failed','converted') "
                         "LIMIT 1").fetchone():
                return "rows"
            # niciun rând activ: orice nume listat e text clar rezidual (apărut după inventar)
            if entries:
                return "residual"
            if left:
                return "leftovers"
            c.execute("INSERT OR IGNORE INTO tx_state(key, value) VALUES('recordings_format', 'wtx1')")
            return ""
        why = await st.io(st._run_txn, fn)
    _s.format_block = why
    if why in ("residual", "leftovers"):
        st.alarm("transcript.migrationResidual", "recordings_format held back: %s (%s)" % (
            why, ", ".join(["%s/%s" % (e["dir"], e["name"]) for e in entries][:3] or left[:3])))
    done = not why
    if done:
        with contextlib.suppress(OSError):
            os.rmdir("arhiva", dir_fd=st.dir_fd)      # doar dacă e gol
    return done


def start(st):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _s.task is None:
        _s.wake = asyncio.Event()
        _s.task = loop.create_task(_loop(st))


async def stop():
    t = _s.task
    _s.task = None
    if t is not None:
        t.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await t


async def _loop(st):
    while True:
        try:
            await run_once(st)
        except asyncio.CancelledError:
            raise
        except Exception as e:                   # noqa: BLE001 — bucla nu moare
            _s.last_error = _err("%s: %s" % (type(e).__name__, e))
            log.warning("recording migration: %s", type(e).__name__)
        try:
            await asyncio.wait_for(_s.wake.wait(), INTERVAL)
        except asyncio.TimeoutError:
            pass
        _s.wake.clear()


# ── health ───────────────────────────────────────────────────────────────────


async def status():
    """Counts for System health (None when the migration is not active)."""
    st = _s.store
    if not active():
        return None

    def load(c):
        rows = c.execute("SELECT state, COUNT(*), COALESCE(SUM(size), 0) FROM tx_migration GROUP BY state").fetchall()
        fmt = c.execute("SELECT value FROM tx_state WHERE key='recordings_format'").fetchone()
        err = c.execute("SELECT error FROM tx_migration WHERE state='failed' AND error IS NOT NULL "
                        "ORDER BY sid LIMIT 1").fetchone()
        return rows, fmt, err
    rows, fmt, err = await st.read(load)
    n = {state: (cnt, size) for state, cnt, size in rows}
    c = {k: n.get(k, (0, 0))[0] for k in ("pending", "orphan", "converted", "unlinked", "missing", "failed")}
    todo = c["pending"] + c["orphan"] + c["converted"]
    return {
        "format": fmt[0] if fmt else "",
        "total": todo + c["unlinked"],
        "done": c["unlinked"],
        "left_bytes": n.get("pending", (0, 0))[1] + n.get("orphan", (0, 0))[1],
        "todo": todo,
        "converted": c["unlinked"],
        "one_kind": c["missing"],
        "orphans": c["orphan"],
        "failed": c["failed"],
        "stray": len(_s.stray),
        "leftovers": len(_s.leftovers),
        "error": (err[0] if err else "") or _s.last_error,
        "format_block": _s.format_block,
        "failed_sids": await failed_sessions(st),
        "recompaction": recompact_status(),
    }
