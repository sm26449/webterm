"""Encrypted recordings wired into the live hub and the readers (ENCRYPTION-AT-REST.md §12.11, PR5b).

Everything here is inert unless `txstore.enabled()` (`WEBTERM_TX_RECORDINGS=1`) **and** a
`txstore.Store` was opened at boot (`boot`). The flag is off by default (no compose file, example
or installer sets it), so on every real installation `active()` is False and core.py, the routes
and the backup keep the 3.7 code byte for byte (§12.11 "PR5/PR6 boundary"). Since PR6b the flag
on a protected volume opens it and migrates its plaintext recordings (`migration.py`).

Pieces:

* `boot(ring)`: the boot decision. Flag off with encrypted rows / generation files on the volume →
  refused ("recordings encrypted by a newer build"), never read as absent. Flag on without a
  protected keyring (a legacy volume) → refused. A `tx_state.test_volume` marker outside a test
  gate → refused. Flag on with a protected keyring (PR6b): the real volume opens, then the erasure
  journal, crash recovery and the plaintext migration (`migration.boot`) must all report ready,
  before any hub exists; otherwise refused.
* `Recording`: the per-hub adapter that owns the sid's `txstore.Recorder` and follows the §12.11.10
  Admission contract (`at` on every chunk, retryable vs terminal refusals, `skip_to` when the
  source position jumps past the recorder's, overlap trimmed, `change_epoch` on a new agent epoch,
  same-epoch reattach as a no-op, `resume()` after an overflow, `close(cast_ts)`).
* Counters: `bump` / `revoking` (the §12.11.2 fences) and the `tx_state.access_gen` poller for
  writers in another process (`python3 -m app.admin`).
* Authorization until emission (§12.11.10): `authorizer` + `Grant`. Every reader (HTTP route,
  WebSocket history, search) builds its `Access` from its OWN decision, re-run with the counters
  captured first, and checks it again immediately before anything derived from the recording is
  handed to the transport (`Grant.before_emit` / `Grant.emit_ok`, `emit_chunks`, `search_emit`).
* Readers used by core.py: `tail_out` (attach replay, resync, closed-session replay).
  Route-level readers live in the route modules, which own the authorization (share_api.py).
"""
import asyncio
import collections
import contextlib
import dataclasses
import json
import logging
import os
import time

from . import authz, cloudbackup, config, db, erasure, migration, security, txstore

log = logging.getLogger("webterm.txhub")

_store = None
_poll_task = None
_recordings = {}               # sid → Recording (hub-uri vii)
_finalizers = set()
# sid → momentul ultimului commit care a crescut .out (indiciu de UI, ca mtime-ul din 3.7)
committed_at = {}

POLL_SECS = 1.0
SHUTDOWN_SECS = txstore.SHUTDOWN_SECS
BACKLOG_CAP = 8 * 1024 * 1024
# plafonul de INTRĂRI (M2): placeholder-ele disjuncte nu mai pot adăuga obiecte la nesfârşit
BACKLOG_MAX_ITEMS = 4096
RETRY_SECS = 1.0
CHECKPOINT_BYTES = 65536
CHECKPOINT_SECS = 2.0


class BootRefused(Exception):
    """The boot must stop (§12.11 PR5/PR6 boundary); the message is Owner-facing, never key material."""


def active() -> bool:
    return _store is not None


def store():
    return _store


# ── boot / shutdown ──────────────────────────────────────────────────────────


TX_TABLES = txstore.TX_TABLES
# Inventarul e UNA singură definiţie (txstore.inventory), comună boot-ului, backup-ului şi restore-ului.
recording_files_present = txstore.recording_files_present


async def encrypted_recordings_present() -> str:
    """'' when the volume holds no encrypted-recording artefact; otherwise the first one found (a
    table, a tx_state key, the erasure journal, a generation file)."""
    found = await asyncio.to_thread(txstore.inventory, config.DATA_DIR, config.DB_PATH)
    return found[0] if found else ""


async def boot(ring, env=None):
    """The boot decision (module docstring). `ring` = the protected keyring (None on a legacy
    volume). Returns the Store when encrypted recordings are active, None when they are off."""
    env = os.environ if env is None else env
    row = await db.fetchone("SELECT value FROM tx_state WHERE key='test_volume'")
    if row is not None and not txstore.test_gate(env):
        raise BootRefused("this data volume was created by a test fixture (tx_state.test_volume); "
                          "it is never served outside a test gate")
    if not txstore.enabled(env):
        found = await encrypted_recordings_present()
        if found:
            raise BootRefused("recordings encrypted by a newer build were found (%s); this build "
                              "cannot serve them and will not read them as absent. Upgrade, or "
                              "restore a backup taken before they were written" % found)
        return None
    if ring is None:
        raise BootRefused("%s=1 needs a protected volume (master key); remove the flag"
                          % txstore.ENV_FLAG)
    try:
        # PR6b: un volum real PROTEJAT (ring nu e None, verificat mai sus) se deschide; un volum de
        # test rămâne legat de poarta de test. Volumul legacy e refuzat mai sus.
        st = txstore.Store(transcripts_dir=config.TRANSCRIPT_DIR, kwk=ring.kwk,
                           installation_id=ring.installation_id, env=env, real_volume=True)
    except txstore.TxStoreError as e:
        raise BootRefused("%s=1 refused: %s (remove the flag)" % (txstore.ENV_FLAG, e)) from None
    try:
        # PR6a (§12.11.4 "Every boot"): jurnalul de ştergeri verificat faţă de capul comis şi
        # tombstone-urile re-aplicate ÎNAINTE de recovery şi de orice cititor
        await erasure.boot(st)
        if not (erasure.journal_ready() and erasure.quarantine_ready()):
            raise BootRefused("%s=1 refused: the erasure journal or the quarantine pass is not ready"
                              % txstore.ENV_FLAG)
        await st.recover()
        # PR6b (§12.11.5): inventarul textului clar (o dată per volum) şi regulile de crash ale
        # migrării, după recovery (generaţiile `created` ale unei conversii întrerupte sunt deja
        # şterse) şi înainte de reconcile / orice writer.
        await migration.boot(st)
        if not migration.ready():
            raise BootRefused("%s=1 refused: the recording migration is not ready" % txstore.ENV_FLAG)
    except BaseException:
        migration.reset()
        erasure.reset()
        st.close()
        raise
    install(st)
    erasure.set_destinations(cloudbackup.attest_destinations)
    erasure.start(st)
    migration.start(st)
    # M3: baseline-ul lui access_gen se citeşte ÎNAINTE de a servi şi înainte de bucla de poll; o
    # mutaţie CLI comisă după el se vede ca bump. Necitibil → `have` fals → primul poll face bump.
    await poll_once(baseline=True)
    start_poller()
    return st


def install(st) -> None:
    """Make `st` the process Store (boot, or a test fixture): readopt hook, alarm sink, authz
    listener. The access_gen poller starts separately (`start_poller`), after the baseline."""
    global _store
    _store = st
    st.on_readopt = _on_readopt
    _wrap_alarm(st)
    if _on_authz_bump not in authz.epoch_listeners:
        authz.epoch_listeners.append(_on_authz_bump)
    if _authz_fence not in authz.change_fences:
        authz.change_fences.append(_authz_fence)


def start_poller() -> None:
    global _poll_task
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None and _poll_task is None:
        _poll_task = loop.create_task(_poll_loop())


async def shutdown() -> None:
    """Finalize every hub's recording (bounded), then the Store."""
    global _store, _poll_task
    st = _store
    if _poll_task is not None:
        _poll_task.cancel()
        _poll_task = None
    await erasure.stop()
    await migration.stop()
    if st is None:
        return
    for r in list(_recordings.values()):
        r.begin_close()
    if _finalizers:
        await asyncio.wait(list(_finalizers), timeout=SHUTDOWN_SECS)
    left = await st.shutdown()
    if left:
        log.error("encrypted recordings: workers abandoned at shutdown: %s", left)
    st.close()
    uninstall()


def uninstall() -> None:
    global _store, _poll_task
    _store = None
    erasure.reset()
    migration.reset()
    if _poll_task is not None:
        _poll_task.cancel()
        _poll_task = None
    with contextlib.suppress(ValueError):
        authz.epoch_listeners.remove(_on_authz_bump)
    if _authz_fence in authz.change_fences:
        authz.change_fences.remove(_authz_fence)
    _recordings.clear()
    committed_at.clear()
    _poll_state.update(have=False, last=None, fails=0)


def _wrap_alarm(st) -> None:
    orig = st.alarm

    def alarm(code, detail):
        orig(code, detail)
        # System health citeşte `store().alarms`; aici rămâne şi o linie de jurnal (fără conţinut)
        log.warning("encrypted recordings: %s: %s", code, detail)
    st.alarm = alarm


# ── counters (§12.11.2 Revocation, Commit/bump fence) ───────────────────────


def bump(sid=None) -> None:
    """Synchronous, on the loop: a revocation of `sid` (None = a global access change)."""
    if _store is not None:
        _store.bump(sid)


def _on_authz_bump() -> None:
    bump(None)


def _authz_fence():
    """`authz.access_change()`'s fence: a GLOBAL revocation fence around the access change."""
    return revoking(None)


@contextlib.asynccontextmanager
async def revoking(sid=None):
    """Bump + fence BEFORE an access-reducing write, bump again after it (no-op when inactive)."""
    if _store is None:
        yield
        return
    async with _store.revoking(sid):
        yield


@contextlib.asynccontextmanager
async def revoking_many(sids):
    """`revoking` for several sids (a link sweep). An empty set still runs the body."""
    async with contextlib.AsyncExitStack() as stack:
        if _store is not None:
            for s in sorted(set(sids)):
                await stack.enter_async_context(_store.revoking(s))
        yield


async def _read_access_gen():
    row = await db.fetchone("SELECT value FROM tx_state WHERE key='access_gen'")
    return row["value"] if row else None


_poll_state = {"have": False, "last": None, "fails": 0}


async def poll_once(baseline=False) -> None:
    """Writers in another process stamp `tx_state.access_gen` in the same transaction as their
    access change; a change, or two failed polls in a row, bumps the global counter. Only the
    boot's baseline read (`baseline=True`, before serving) learns the value silently: any later
    first read (the baseline failed, or a Store installed without boot) bumps, because what
    happened before it is unknown (M3)."""
    s = _poll_state
    try:
        val = await _read_access_gen()
    except Exception:                            # noqa: BLE001 — un poll nu opreşte bucla
        s["fails"] += 1
        if s["fails"] >= 2:
            s["fails"] = 0
            bump(None)
        return
    s["fails"] = 0
    if (s["have"] and val != s["last"]) or (not s["have"] and not baseline):
        bump(None)
    s["have"], s["last"] = True, val


async def _poll_loop() -> None:
    while True:
        await poll_once()
        if _store is not None:
            _store.sweep_idle()                  # un snapshot fără citire de 60 s se închide
        await asyncio.sleep(POLL_SECS)


# ── epochs snapshot: counters captured BEFORE a route's authorization decision ──


def snapshot():
    """(sid counters, global counter) captured before an authorization decision."""
    st = _store
    return (dict(st.sid_epoch), st.access_epoch) if st is not None else None


def sid_unchanged(snap, sid) -> bool:
    """Synchronous: no revocation of `sid` began since `snap` (its counter is the same). False
    when inactive or without a snapshot (fail closed: the caller re-checks its credential)."""
    st = _store
    return st is not None and snap is not None and st.sid_epoch[sid] == snap[0].get(sid, 0)


def access_since(snap, sid, principal, route, *, not_after=None):
    """An Access for `sid` whose counters are the ones of `snap` (captured before the decision);
    None when a counter moved since (the decision may be stale: the caller refuses or retries)."""
    st = _store
    if st is None or snap is None:
        return None
    sids, glob = snap
    if st.sid_epoch[sid] != sids.get(sid, 0) or st.access_epoch != glob:
        return None
    acc = st.access(sid, principal, route)
    return dataclasses.replace(acc, not_after=not_after) if not_after is not None else acc


# ── authorization until emission (§12.11.10) ─────────────────────────────────


def earliest(limits):
    """The nearest deadline among `limits` (None entries ignored); None = no deadline."""
    vals = [x for x in limits if x is not None]
    return min(vals) if vals else None


async def web_session_limits(tok, grants) -> list:
    """Deadlines of a cookie-authenticated decision: the web session's absolute and idle expiry
    and the earliest time-bound binding. The session row gone (logout) → refused."""
    row = await db.fetchone("SELECT expires, last_seen FROM web_sessions WHERE token_hash=?",
                            security.sha256_hex(tok or ""))
    if row is None:
        raise txstore.Revoked("revoked", "web session ended")
    limits = [authz.earliest_expiry(grants.bindings), row["expires"]]
    if row["last_seen"] is not None:
        limits.append(row["last_seen"] + security.WEB_SESSION_IDLE)
    return limits


def stepup_deadline(user_id, host_id) -> float:
    """The step-up window's end on a 2FA host (0.0 = none: already expired)."""
    rec = security.stepup_window_record(user_id, host_id)
    return rec[1] if rec else 0.0


def authorizer(sid, principal, route, decide):
    """An `authorize()` for `Grant` / `Store.open(reauthorize=)`: counters captured FIRST, then
    `decide()` (the route's own decision from its credential and scope; it returns the deadline,
    None = none, or raises), then an `Access` bound to those counters. A counter that moved during
    the decision → the decision runs once more; twice → refused."""
    async def authorize():
        for _attempt in (0, 1):
            snap = snapshot()
            if snap is None:
                raise txstore.Revoked("revoked", "encrypted recordings inactive")
            not_after = await decide()
            acc = access_since(snap, sid, principal, route, not_after=not_after)
            if acc is not None:
                return acc
        raise txstore.Revoked("revoked", "access changed during the authorization")
    return authorize


def recovery_authorizer(sid, principal, decide):
    """`authorizer` for the Owner recovery read (§12.11.4): the same counters-first discipline, and
    an `Access` for `txstore.OWNER_RECOVERY_ROUTE` — the only route the Store lets open a
    `recovery` recording. `decide()` re-checks the Owner (never a parameter of the request)."""
    async def authorize():
        for _attempt in (0, 1):
            snap = snapshot()
            st = _store
            if snap is None or st is None:
                raise txstore.Revoked("revoked", "encrypted recordings inactive")
            not_after = await decide()
            if st.sid_epoch[sid] != snap[0].get(sid, 0) or st.access_epoch != snap[1]:
                continue
            return st.access(sid, principal, txstore.OWNER_RECOVERY_ROUTE, not_after=not_after,
                             owner_recovery=True)
        raise txstore.Revoked("revoked", "access changed during the authorization")
    return authorize


class Grant:
    """One reader's authorization for one sid until emission (§12.11.10). `authorize` is the
    route's `authorizer`; the Grant keeps the latest `Access` (also the one the Store obtained when it
    re-authorized mid-read) and refuses a re-authorization that would move the sid's counter: what
    was read under one sid epoch is never emitted under the next (a sid revocation is final)."""

    def __init__(self, authorize):
        self._authorize = authorize
        self.access = None

    async def authorize(self):
        if self._authorize is None:
            raise txstore.Revoked("revoked", "no authorization for this reader")
        acc = await self._authorize()
        old = self.access
        if old is not None and (acc.sid != old.sid or acc.sid_epoch != old.sid_epoch):
            raise txstore.Revoked("revoked", "sid revoked since the read")
        self.access = acc
        return acc

    def emit_ok(self) -> bool:
        """Synchronous: the latest Access still holds (counters, fences, deadline). Call it with
        nothing awaited between it and the hand-off to the transport."""
        st = _store
        if st is None or self.access is None:
            return False
        try:
            st.check(self.access)
        except txstore.TxStoreError:
            return False
        return True

    async def before_emit(self) -> bool:
        """The last check before emission. A sid revocation → False. A global change or the
        deadline → the decision is re-run (new counters, same sid epoch) and checked again; True
        means: emit NOW, with nothing awaited in between."""
        st = _store
        if st is None or self.access is None:
            return False
        try:
            st.check(self.access)
            return True
        except txstore.NeedsReauth:
            pass
        except txstore.TxStoreError:
            return False
        try:
            await st.wait_fences(self.access.sid)
            await self.authorize()
            st.check(self.access)
        except Exception as e:                   # noqa: BLE001 — orice refuz = nimic emis
            log.info("recording %s: emission refused (%s)", self.access.sid[:8],
                     getattr(e, "reason", type(e).__name__))
            return False
        return True


async def emit_chunks(grant, data, chunk=None):
    """A response body built in memory (text view, preview, a cached redaction), emitted in
    chunks, each one checked immediately before it is handed over; a refusal cuts the body."""
    step = chunk or txstore.STREAM_CHUNK
    for i in range(0, len(data), step):
        if not await grant.before_emit():
            raise txstore.Revoked("revoked", "access changed before emission")
        yield data[i:i + step]


def search_emit(snap, found, deadline, visible=None):
    """Search results at emission (synchronous, H2). None = the decision itself is stale (a
    global counter or fence moved, or the caller's own deadline passed): re-run or refuse. Per
    result, content (snippet, count) read under an `Access` that no longer holds is dropped; a
    result that matched only through that content is dropped whole. `visible(res, now)` (recheck
    R-M1) = may this result be shown AT ALL now (its host's step-up window still open), checked
    independently of any content match: False drops the whole result (id, title, note, host)."""
    st = _store
    if st is None or snap is None:
        return None
    now = st.clock()
    if st.access_epoch != snap[1] or st.fenced(None) or (deadline is not None and now >= deadline):
        return None
    out = []
    for res, acc, meta_hit in found:
        if visible is not None and not visible(res, now):
            continue                             # R-M1: nici metadatele (titlu, notă, id, host)
        if res["matches"] or res["snippet"]:
            try:
                if acc is None:
                    raise txstore.Revoked("revoked", "no access")
                st.check(acc)
            except txstore.TxStoreError:
                if not meta_hit:
                    continue
                res = dict(res, snippet="", matches=0)
        out.append(res)
    return out


# ── readers for core.py (attach replay, resync, closed-session replay) ───────


async def tail_out(sid, limit, *, grant, end=None):
    """(bytes, end, list_epoch) of the committed `.out` (up to `end`), read under `grant` (the
    WebSocket's own decision, §12.11.10), or (b"", None, None) when there is nothing to serve (no
    recording yet, refused, a fault: fail closed, logged). The caller still calls
    `grant.before_emit()` / `emit_ok()` before handing the bytes to the transport."""
    st = _store
    if st is None or grant is None:
        return b"", None, None
    try:
        acc = await grant.authorize()
        return await st.tail(sid, "out", limit, access=acc, end=end, reauthorize=grant.authorize)
    except txstore.TxStoreError as e:
        if e.reason != "notFound":
            log.warning("recording tail %s refused: %s", sid[:8], e.reason)
        return b"", None, None
    except Exception as e:                       # noqa: BLE001 — decizia a refuzat: nimic servit
        log.info("recording tail %s refused: %s", sid[:8], type(e).__name__)
        return b"", None, None


def last_output_at(sid, hub):
    """§12.11.6: the newest of the hub's live output and the last commit; None = unknown (fail
    closed: never read as idle)."""
    r = _recordings.get(sid)
    if r is None or not r.activity_known():
        return None
    vals = [v for v in (getattr(hub, "last_output_at", None), committed_at.get(sid)) if v]
    return max(vals) if vals else None


async def committed_at_db(sid):
    st = _store
    if st is None:
        return None
    try:
        return await st.last_output_at(sid)
    except Exception:                            # noqa: BLE001 — indiciu, nu decizie
        return None


async def archive(sid) -> None:
    """Archiving is a database state (§12.11.0): `archived_at`, under the sid's lease."""
    st = _store
    if st is None:
        return
    now = time.time()
    async with st.lease(sid):
        await st.txn(lambda c: c.execute(
            "UPDATE tx_descriptors SET archived_at=? WHERE sid=? AND archived_at IS NULL", (now, sid)))
    bump(sid)


# ── the hub adapter ──────────────────────────────────────────────────────────


def cast_line(t, data) -> bytes:
    """One asciicast output event, exactly as 3.7 wrote it (`SessionHub._cast_event`)."""
    return (json.dumps([t, "o", data.decode("utf-8", errors="replace")]) + "\n").encode()


def cast_header(cols, rows, created) -> bytes:
    return (json.dumps({"version": 2, "width": cols, "height": rows,
                        "timestamp": int(created)}) + "\n").encode()


class _Item:
    __slots__ = ("hub_at", "pos", "data", "n", "t")

    def __init__(self, hub_at, data, t, n=None):
        self.hub_at = hub_at          # (epoch, offset) as the hub counted it
        self.pos = None               # (epoch, offset) offered to the recorder
        self.data = data              # None = placeholder for bytes dropped from the backlog
        self.n = len(data) if data is not None else n
        self.t = t


class Recording:
    """One hub's recording (§12.11.10 Admission). Loop-only, synchronous on the hot path.

    Positions: an agent source (`ring=True`) offers the agent's own (epoch, offset); any other
    source (SSH, telnet, serial: no ring, `track_agent=False`) offers a virtual offset counted
    here, epoch None. Chunks go through a FIFO backlog; the head is admitted when the recorder is
    open and no adapter operation (epoch switch, skip, resume) is pending. A position below the
    recorder's `received` is trimmed (overlap), above it is a skip (ONE marker for the hole), a new
    epoch is a `change_epoch` first. An overflow is followed by `resume()`; bytes not replayed
    (this adapter never re-attaches the agent for the recorder alone) become the skip marker of
    the next position. The backlog is bounded; dropped bytes keep their positions, so they too end
    as a marker."""

    def __init__(self, sid, created, cols, rows, *, live_end=None, on_desync=None, on_rebase=None,
                 clock=time.time):
        self.sid = sid
        self.created = created
        self.header = cast_header(cols, rows, created)
        self.rec = None
        self.ring = None
        self.backlog = collections.deque()
        self.backlog_bytes = 0
        self.virt = 0
        self.op = None
        self.ckpt = None
        self.failed = None
        self.closed = False
        self.close_task = None
        self.live_end = live_end
        self.on_desync = on_desync or (lambda: None)
        self.on_rebase = on_rebase or (lambda: None)
        self.clock = clock
        self._start_lock = asyncio.Lock()
        self._list_epoch = None
        self._in_sync = True
        self._retry = None
        # M2: octeţi aruncaţi fără poziţie (plafonul de intrări atins, alt epoch decât ultima
        # intrare): nu pot deveni marker, doar alarmă explicită la închidere
        self.unpositioned = 0
        self.close_report = None

    # ── lifecycle ──

    def ts(self):
        return round(self.clock() - self.created, 6)

    async def start(self, ring: bool) -> bool:
        """Own the sid's Recorder (before any output is admitted). False = the hub must not attach
        (a key or volume fault: a protected session is never run unrecorded, §12.11.1 RK)."""
        if self.rec is not None and self.rec.state == "running":
            return True
        if self.closed or _store is None:
            return False
        async with self._start_lock:
            if self.rec is not None and self.rec.state == "running":
                return True
            st = _store
            prev = st.recorders.get(self.sid)
            try:
                rec = await st.start_recorder(self.sid, track_agent=bool(ring))
            except txstore.TxStoreError as e:
                if e.reason == "busy" and prev is not None and prev.state == "running" and prev.closing:
                    # finalizarea hub-ului anterior al aceluiaşi sid încă rulează: aşteptăm, o dată
                    await self._await_prev(prev)
                    try:
                        rec = await st.start_recorder(self.sid, track_agent=bool(ring))
                    except txstore.TxStoreError as e2:
                        return self._start_failed(e2)
                else:
                    return self._start_failed(e)
            self.ring = bool(ring)
            self._adopt(rec, first=True)
            _recordings[self.sid] = self
            return True

    async def _await_prev(self, prev):
        task = getattr(prev, "_task", None)
        if task is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait([task], timeout=SHUTDOWN_SECS)

    def _start_failed(self, e) -> bool:
        self.failed = e
        log.error("recording %s cannot start (%s): the session is not attached", self.sid[:8], e.reason)
        if _store is not None:
            _store.alarm("transcript.keyError" if e.reason == "keyError" else "transcript.startFailed",
                         "%s: %s" % (self.sid, e.reason))
        return False

    def _adopt(self, rec, *, first=False, old=None):
        """A new Recorder for this sid (start or re-adoption): positions realigned, the cast header
        written once if the committed `.cast` is empty, then the backlog resumes."""
        if not self.ring:
            if first:
                base = rec.received[1]
                for it in self.backlog:
                    if it.pos is None:
                        it.pos = (None, base)
                        base += it.n
                self.virt = base
            else:
                # Recorder fără ring readoptat: porneşte de la ce e publicat. Octeţii pe care cel vechi
                # îi ţinea nepublicaţi devin o gaură (deci un marker), poziţiile din backlog se mută.
                cov = old._covered[1] if old is not None and old._covered[0] is None else rec.received[1]
                shift = rec.received[1] - cov
                for it in self.backlog:
                    if it.pos is not None:
                        it.pos = (None, it.pos[1] + shift)
                self.virt += shift
        else:
            for it in self.backlog:
                if it.pos is None:
                    it.pos = it.hub_at
        self.rec = rec
        self.op = None
        self.ckpt = None
        self._list_epoch = rec.list_epoch
        if rec.committed_len("cast") == 0 and rec.cast_pos == 0:
            try:
                rec.feed_cast_only(self.header, at=rec.received)
            except txstore.TxStoreError as e:
                log.warning("recording %s: cast header refused (%s)", self.sid[:8], e.reason)
        if not first:
            self._desync()
        self._pump()

    def begin_close(self):
        """Teardown (synchronous): stop ingress at the hub, finalize in the background."""
        if self.close_task is not None:
            return self.close_task
        self.closed = True
        loop = asyncio.get_running_loop()
        t = self.close_task = loop.create_task(self._finalize())
        _finalizers.add(t)
        t.add_done_callback(_finalizers.discard)
        return t

    def _held(self):
        """(the backlog's positioned extents `(epoch, offset, n)` for `Recorder.close(held=)`, bytes
        without a position). The recorder's WORKER splits the extents against its cursor once the
        jobs queued before the close have run (recheck R-M2); used once per close attempt."""
        held, other = [], self.unpositioned
        for it in self.backlog:
            if it.pos is not None:
                held.append((it.pos[0], it.pos[1], it.n))
            else:
                other += it.n
        return held, other

    async def _finalize(self):
        """Drain under ONE deadline (every pending epoch switch / skip / resume, as many passes as
        they need), then close the recorder. Whatever the backlog still holds is accounted: the
        recorder's worker splits it (`close(held=)`, after the jobs queued before the close): the
        current epoch's bytes join the close marker (durable), the rest is alarmed with its size
        (`transcript.gapUnrecorded`). The backlog is emptied only on a confirmed close result; a
        replaced recorder, a timeout or a malformed result leave every held byte alarmed as not
        covered by a confirmed marker (recheck R-M2). `close_report` keeps the numbers."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + SHUTDOWN_SECS
        report = self.close_report = {"unoffered": 0, "unrecorded": 0, "closed": False}
        try:
            for _ in range(256):
                op = self.op
                if op is not None:
                    left = deadline - loop.time()
                    if left > 0:
                        await asyncio.wait([op[1]], timeout=left)
                    if self.op is op:            # nu s-a rezolvat în timp
                        break
                    continue
                self._pump()
                if self.op is None:
                    break
            for _attempt in (0, 1):
                # un recorder readoptat în timpul închiderii (worker pierdut) se închide şi el
                rec = self.rec
                if rec is None or rec.state != "running":
                    break
                held, other = self._held()
                try:
                    res = await asyncio.wait_for(rec.close(cast_ts=self.ts(), held=held),
                                                 SHUTDOWN_SECS * 2)
                except txstore.RecorderLost:
                    await asyncio.sleep(0)
                    continue
                # R-M2: doar un rezultat CONFIRMAT (markerul de close publicat) goleşte backlog-ul;
                # altfel octeţii rămân număraţi şi `finally` îi alarmează ca neconfirmaţi
                if not isinstance(res, dict) or not isinstance(res.get("unoffered"), int) \
                        or not isinstance(res.get("unrecorded"), int):
                    log.warning("recording %s: close not confirmed (%r)", self.sid[:8], type(res).__name__)
                    break
                report.update(unoffered=res["unoffered"], unrecorded=other + res["unrecorded"], closed=True)
                self.backlog.clear()
                self.backlog_bytes = 0
                self.unpositioned = 0
                break
        except Exception as e:                   # noqa: BLE001 — închiderea nu rupe teardown-ul
            log.warning("recording %s: close failed: %r", self.sid[:8], e)
        finally:
            left = self.unpositioned + sum(it.n for it in self.backlog)
            if not report["closed"]:
                report["unrecorded"] = left
            if report["unrecorded"] and _store is not None:
                _store.alarm("transcript.gapUnrecorded",
                             "%s: %d bytes held by the hub at close are not covered by a confirmed marker"
                             % (self.sid, report["unrecorded"]))
            self.backlog.clear()
            self.backlog_bytes = 0
            self.unpositioned = 0
            if self._retry is not None:
                self._retry.cancel()
            if _recordings.get(self.sid) is self:
                del _recordings[self.sid]

    # ── hot path (loop, synchronous) ──

    def feed(self, hub_at, data, t=None):
        if self.closed or not data:
            return
        it = _Item(hub_at, bytes(data), self.ts() if t is None else t)
        if self.ring is False:
            it.pos = (None, self.virt)
            self.virt += it.n
        elif self.ring:
            it.pos = hub_at
        blocked = self.rec is None or self.op is not None or bool(self.backlog)
        self._push(it)
        if blocked:
            self._desync()
        self._pump()

    def _push(self, it):
        full = len(self.backlog) >= BACKLOG_MAX_ITEMS
        if self.backlog_bytes + it.n > BACKLOG_CAP or full:
            # Plafonul backlog-ului: octeţii se pierd, dar poziţia lor rămâne ocupată → marker.
            last = self.backlog[-1] if self.backlog else None
            if last is not None and last.pos is not None and it.pos is not None \
                    and last.pos[0] == it.pos[0] and last.pos[1] + last.n <= it.pos[1] \
                    and (last.data is None or full):
                # acelaşi epoch: ultima intrare se extinde până la capătul celei noi (gaura dintre
                # ele era oricum pierdută) — numărul de intrări nu creşte
                if last.data is not None:
                    self.backlog_bytes -= last.n
                    last.data = None
                last.n = it.pos[1] + it.n - last.pos[1]
                return
            if full:
                # fără poziţie comparabilă: nu mai adăugăm obiecte; pierderea rămâne numărată
                self.unpositioned += it.n
                return
            it.data = None
            self.backlog.append(it)
            return
        self.backlog.append(it)
        self.backlog_bytes += it.n

    def _pop(self):
        it = self.backlog.popleft()
        if it.data is not None:
            self.backlog_bytes -= it.n
        return it

    def _desync(self):
        # offseturile prezise de hub nu mai sunt sigure: starea OSC 133 devine „necunoscută"
        if self._in_sync:
            self._in_sync = False
            self.on_desync()

    def in_sync(self) -> bool:
        r = self.rec
        return (r is not None and r.state == "running" and r.ingress() == "open" and self.op is None
                and not self.backlog)

    def out_pos(self) -> int:
        """Predicted logical `.out` position after everything offered so far."""
        r = self.rec
        return (r.out_pos if r is not None else 0) + self.backlog_bytes

    def _live_end(self):
        if self.ring:
            le = self.live_end() if self.live_end is not None else None
            return le if le is not None and le[0] is not None else None
        return (None, self.virt)

    def _pump(self):
        r = self.rec
        if r is None or self.op is not None:
            return
        while True:
            if r.state != "running":
                return                           # readoptarea (supervizorul) ne dă recorderul nou
            ing = r.ingress()
            if ing == "overflow":
                self._begin("resume", lambda: asyncio.ensure_future(r.resume()))
                return
            if ing != "open":
                return
            if not self.backlog:
                self._check_live_end()
                if self.op is None and not self.backlog and not self._in_sync:
                    self._in_sync = True
                return
            it = self.backlog[0]
            if it.pos is None:
                return                           # nepornit încă
            e, o = it.pos
            re_, ro = r.received
            if e != re_:
                if e is None:                    # sursă cu ring fără epoch (nu ar trebui): aruncat
                    self._pop()
                    continue
                self._begin("epoch", lambda: r.change_epoch(e))
                return
            if o + it.n <= ro:
                self._pop()                      # deja primit (suprapunere): tăiat
                continue
            if it.data is None:
                self._pop()                      # pierdut din backlog: gaura o acoperă skip-ul următor
                continue
            if o > ro:
                self._begin("skip", lambda: r.skip_to(e, o, "ring" if self.ring else "dropped",
                                                      cast_ts=self.ts()))
                return
            data = it.data if o == ro else it.data[ro - o:]
            try:
                ok = r.feed(data, cast_line(it.t, data), at=(e, ro))
            except txstore.TxStoreError as ex:
                # Refuz reîncercabil (ordine / busy): nimic admis; reluăm după o pauză.
                log.warning("recording %s: chunk at %s refused (%s)", self.sid[:8], (e, o), ex.reason)
                self._schedule_retry()
                return
            self._pop()
            if not ok and r.ingress() != "overflow":
                return

    def _check_live_end(self):
        le = self._live_end()
        r = self.rec
        if le is None or r is None:
            return
        re_, ro = r.received
        if le[0] != re_:
            self._begin("epoch", lambda: r.change_epoch(le[0]))
        elif le[1] > ro:
            self._begin("skip", lambda: r.skip_to(le[0], le[1], "ring" if self.ring else "dropped",
                                                  cast_ts=self.ts()))

    def poke(self):
        """Re-check after the hub moved its position without output (attach)."""
        self._pump()

    def _begin(self, kind, make):
        try:
            fut = make()
        except txstore.RecorderLost:
            return                               # readoptarea vine prin _on_readopt
        except txstore.TxStoreError as e:
            log.warning("recording %s: %s refused (%s)", self.sid[:8], kind, e.reason)
            self._schedule_retry()
            return
        self._desync()
        self.op = (kind, fut)
        fut.add_done_callback(lambda f, k=kind: self._op_done(k, f))

    def _schedule_retry(self):
        if self._retry is None or self._retry.cancelled():
            loop = asyncio.get_running_loop()

            def again():
                self._retry = None
                self._pump()
            self._retry = loop.call_later(RETRY_SECS, again)

    def _op_done(self, kind, fut):
        if self.op is None or self.op[1] is not fut:
            return
        self.op = None
        exc = fut.exception() if not fut.cancelled() else asyncio.CancelledError()
        r = self.rec
        if exc is None:
            if kind in ("skip", "resume") or (kind == "epoch" and fut.result() is not None):
                self.on_desync()                 # un marker publicat / poziţii realiniate
            self._check_list_epoch()
            self._pump()
            return
        if isinstance(exc, txstore.RecorderLost) or r is None or r.state != "running":
            return                               # readoptare
        log.warning("recording %s: %s failed (%s)", self.sid[:8], kind,
                    getattr(exc, "reason", type(exc).__name__))
        if kind == "skip" and r.ingress() != "overflow":
            self._begin("resume", lambda: asyncio.ensure_future(r.resume()))
            return
        if kind == "skip":
            self._pump()                         # overflow → resume, apoi skip din nou
            return
        self._schedule_retry()

    def _check_list_epoch(self):
        r = self.rec
        if r is not None and r.list_epoch != self._list_epoch:
            self._list_epoch = r.list_epoch
            self.on_rebase()

    # ── checkpoints (hub triggers: 64 KiB / 2 s / idle / forced) ──

    def checkpoint_busy(self) -> bool:
        return self.ckpt is not None

    def checkpoint(self) -> bool:
        r = self.rec
        if r is None or r.state != "running" or self.ckpt is not None or r.closing:
            return False
        try:
            fut = r.checkpoint()
        except txstore.TxStoreError:
            return False
        before = r.committed_len("out")
        self.ckpt = fut

        def done(f):
            if self.ckpt is fut:
                self.ckpt = None
            if f.cancelled() or f.exception() is not None:
                return
            if self.rec is r and r.committed_len("out") > before:
                committed_at[self.sid] = time.time()
            self._check_list_epoch()
        fut.add_done_callback(done)
        return True

    async def commit_through(self, cutoff) -> bool:
        """Forced checkpoint for a resync whose cutoff is `cutoff` (a `.out` position taken in sync):
        True only when the committed `.out` covers it and the list epoch did not move."""
        r = self.rec
        if r is None or r.state != "running":
            return False
        le = r.list_epoch
        try:
            while self.ckpt is not None:
                await asyncio.shield(self.ckpt)
            fut = r.checkpoint()
            await fut
        except Exception:                        # noqa: BLE001 — fără commit = cutoff necunoscut
            return False
        return self.rec is r and r.list_epoch == le and r.committed_len("out") >= cutoff

    def activity_known(self) -> bool:
        """§12.11.6 "unknown" cases: degraded, not adopted, a checkpoint behind, backlog/ops."""
        r = self.rec
        if r is None or r.state != "running" or r.degraded or self.op is not None or self.backlog:
            return False
        return not r.inflight and not any(len(b) for b in r.pending.values()) and self.ckpt is None


def _on_readopt(sid, new):
    r = _recordings.get(sid)
    if r is None:
        return
    old = r.rec
    if r.closed:
        r.rec = new
        r.op = None
        return
    r._adopt(new, old=old)
