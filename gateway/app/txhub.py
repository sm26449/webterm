"""Encrypted recordings wired into the live hub and the readers (ENCRYPTION-AT-REST.md §12.11, PR5b).

Everything here is inert unless `txstore.enabled()` (`WEBTERM_TX_RECORDINGS=1`) **and** a
`txstore.Store` was opened at boot (`boot`). In a PR5 build the Store only opens on a test-fixture
volume under a test gate, so on every real installation `active()` is False and core.py, the
routes and the backup keep the 3.7 code byte for byte (§12.11 "PR5/PR6 boundary").

Pieces:

* `boot(ring)`: the boot decision. Flag off with encrypted rows / generation files on the volume →
  refused ("recordings encrypted by a newer build"), never read as absent. Flag on without a
  protected keyring, or on a volume the Store refuses (no test volume, no test gate) → refused.
  A `tx_state.test_volume` marker outside a test gate → refused. Then crash recovery, before any
  hub exists.
* `Recording`: the per-hub adapter that owns the sid's `txstore.Recorder` and follows the §12.11.10
  Admission contract (`at` on every chunk, retryable vs terminal refusals, `skip_to` when the
  source position jumps past the recorder's, overlap trimmed, `change_epoch` on a new agent epoch,
  same-epoch reattach as a no-op, `resume()` after an overflow, `close(cast_ts)`).
* Counters: `bump` / `revoking` (the §12.11.2 fences) and the `tx_state.access_gen` poller for
  writers in another process (`python3 -m app.admin`).
* Readers used by core.py: `tail_out` (attach replay, resync, closed-session replay, preview).
  Route-level readers live in the route modules, which own the authorization (share_api.py).
"""
import asyncio
import collections
import contextlib
import dataclasses
import json
import logging
import os
import re
import time

from . import authz, config, db, txstore

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
RETRY_SECS = 1.0
CHECKPOINT_BYTES = 65536
CHECKPOINT_SECS = 2.0
# numele generaţiilor WTX1 (§12.11.0); aceeaşi formă ca txstore, citită aici doar ca să REFUZE boot-ul
_GEN_NAME = re.compile(r"^[0-9a-f]{32}\.(out|cast)\.[0-9a-f]{32}\.(wtx|idx)$")


class BootRefused(Exception):
    """The boot must stop (§12.11 PR5/PR6 boundary); the message is Owner-facing, never key material."""


def active() -> bool:
    return _store is not None


def store():
    return _store


# ── boot / shutdown ──────────────────────────────────────────────────────────


async def encrypted_recordings_present() -> str:
    """'' when the volume holds no encrypted recording; otherwise what was found (a table or a file)."""
    for table in ("session_keys", "tx_descriptors", "tx_files"):
        try:
            if await db.fetchone("SELECT 1 FROM %s LIMIT 1" % table):
                return table
        except Exception as e:                       # noqa: BLE001 — necitibil ≠ absent
            return "%s (unreadable: %s)" % (table, type(e).__name__)
    try:
        names = os.listdir(config.TRANSCRIPT_DIR)
    except FileNotFoundError:
        return ""
    except OSError as e:
        return "transcripts/ (unreadable: %s)" % e.strerror
    for n in names:
        if _GEN_NAME.match(n):
            return "transcripts/" + n
    return ""


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
        st = txstore.Store(transcripts_dir=config.TRANSCRIPT_DIR, kwk=ring.kwk,
                           installation_id=ring.installation_id, env=env)
    except txstore.TxStoreError as e:
        raise BootRefused("%s=1 refused: %s (encrypted recordings need the migration, the erasure "
                          "journal and the quarantine of a later build; remove the flag)"
                          % (txstore.ENV_FLAG, e)) from None
    try:
        await st.recover()
    except BaseException:
        st.close()
        raise
    install(st)
    return st


def install(st) -> None:
    """Make `st` the process Store (boot, or a test fixture): readopt hook, alarm sink, authz
    listener and the access_gen poller."""
    global _store, _poll_task
    _store = st
    st.on_readopt = _on_readopt
    _wrap_alarm(st)
    if _on_authz_bump not in authz.epoch_listeners:
        authz.epoch_listeners.append(_on_authz_bump)
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
    if _poll_task is not None:
        _poll_task.cancel()
        _poll_task = None
    with contextlib.suppress(ValueError):
        authz.epoch_listeners.remove(_on_authz_bump)
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


async def poll_once() -> None:
    """Writers in another process stamp `tx_state.access_gen` in the same transaction as their
    access change; a change, or two failed polls in a row, bumps the global counter. The first
    read only learns the value."""
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
    if s["have"] and val != s["last"]:
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


# ── readers for core.py (attach replay, resync, preview, closed-session replay) ──


async def tail_out(sid, limit, *, principal, route, end=None):
    """(bytes, end, list_epoch) of the committed `.out` (up to `end`), or (b"", None, None) when
    there is nothing to serve (no recording yet, revoked, a fault: fail closed, logged)."""
    st = _store
    if st is None:
        return b"", None, None
    acc = st.access(sid, principal, route)
    try:
        return await st.tail(sid, "out", limit, access=acc, end=end)
    except txstore.TxStoreError as e:
        if e.reason != "notFound":
            log.warning("recording tail %s refused: %s", sid[:8], e.reason)
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

    async def _finalize(self):
        try:
            for _ in range(4):
                op = self.op
                if op is not None:
                    await asyncio.wait([op[1]], timeout=SHUTDOWN_SECS)
                    if self.op is op:            # nu s-a rezolvat în timp
                        break
                self._pump()
                if self.op is None:
                    break
            for _attempt in (0, 1):
                # un recorder readoptat în timpul închiderii (worker pierdut) se închide şi el
                rec = self.rec
                if rec is None or rec.state != "running":
                    break
                try:
                    await asyncio.wait_for(rec.close(cast_ts=self.ts()), SHUTDOWN_SECS * 2)
                except txstore.RecorderLost:
                    await asyncio.sleep(0)
                    continue
                break
        except Exception as e:                   # noqa: BLE001 — închiderea nu rupe teardown-ul
            log.warning("recording %s: close failed: %r", self.sid[:8], e)
        finally:
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
        if self.backlog_bytes + it.n > BACKLOG_CAP:
            # Plafonul backlog-ului: octeţii se pierd, dar poziţia lor rămâne ocupată → marker.
            last = self.backlog[-1] if self.backlog else None
            if last is not None and last.data is None and last.pos is not None and it.pos is not None \
                    and last.pos[0] == it.pos[0] and last.pos[1] + last.n == it.pos[1]:
                last.n += it.n
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
