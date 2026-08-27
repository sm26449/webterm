"""Gateway core: agent connections, session hubs, reconciliation.

Data flow:
  agent ws  ->  AgentConnection.run()  ->  SessionHub.on_output()
                                             |-> transcript files (.out raw, .cast asciicast)
                                             '-> BrowserClient queues -> browser websockets
  browser ws input -> SessionHub.handle_input() -> AgentConnection.send_data()
"""

import asyncio
import base64
import json
import logging
import math
import os
import re
import shlex
import ssl
import time
import uuid
from pathlib import Path
from typing import Dict, Optional, Set

import asyncssh
import telnetlib3

from . import config, db, email_alerts, signing, telnet

log = logging.getLogger("webterm")

FRAME_CTRL = b"J"
FRAME_DATA = b"D"
FRAME_FWD = b"F"                       # port-forward: FRAME_FWD + stream_id(32) + bytes
SID_LEN = 32

GAP_MARKER = b"\r\n\x1b[7m[webterm: unele date au fost pierdute aici]\x1b[0m\r\n"

sources: Dict[int, "SessionSource"] = {}

# Lock per-host pentru dial-ul direct SSH/telnet: `dial_*` fac check-then-act cu un `await`
# la mijloc (conectarea) → două cereri simultane către un host fără sursă ar deschide DOUĂ
# conexiuni (a doua o suprascrie pe prima → socket orfan + auth dublu = fail2ban/MaxStartups).
# Lock-ul serializează + re-verifică sursa după acquire.
_dial_locks: Dict[int, "asyncio.Lock"] = {}


def _dial_lock(host_id: int) -> "asyncio.Lock":
    lock = _dial_locks.get(host_id)
    if lock is None:
        lock = _dial_locks[host_id] = asyncio.Lock()
    return lock


# Surse PER-SESIUNE (cheie = sid), pentru sesiuni al căror backend NU e per-host:
# telnet-via-agent (bastion) deschide un sub-stream al tunelului agentului per
# sesiune, deci sursa nu poate sta în `sources` (cheiat pe host_id, o singură sursă
# per host). SessionHub le preferă acestora înaintea `source_for(host_id)`.
session_sources: Dict[str, "SessionSource"] = {}


def source_for(host_id: int) -> Optional["SessionSource"]:
    """The active session source for a host: an AgentConnection (reverse ws) or
    a direct SshSource/TelnetSource. SessionHub talks only through this."""
    return sources.get(host_id)
hubs: Dict[str, "SessionHub"] = {}
# timestamps of live-connection replacements per host: repeated replacements
# mean two agents share one token (two machines enrolled on the same host)
replacements: Dict[int, list] = {}

# hosts whose agent acknowledged an update but deferred it (live sessions)
pending_updates: Dict[int, bool] = {}
# host_id → motivul pentru care agentul a REFUZAT update-ul (cod de la agent).
# Calea automată înghiţea refuzul: agentul rămânea pe versiunea veche la nesfârşit, iar UI-ul
# arăta doar „update disponibil", fără să spună de ce nu se aplică. Cazul realist: hosturi
# înrolate ÎNAINTE de generarea cheii de deployment — au pubkey-ul vechi încorporat şi refuză
# (corect) orice update semnat cu cheia nouă. Reînrolarea agentului e singura reparaţie.
update_blocked: Dict[int, str] = {}


def host_conflict(host_id: int) -> bool:
    now = time.time()
    recent = [t for t in replacements.get(host_id, []) if now - t < 300]
    replacements[host_id] = recent
    return len(recent) >= 3


AGENT_EVENTS_RETAIN = 7 * 24 * 3600      # jurnal de conexiune agent: retenţie 7 zile


async def record_agent_event(host_id: int, event: str, reason: str = "", detail: str = "") -> None:
    """Scrie un eveniment de conexiune agent (connect/disconnect/update/conflict) în jurnal.
    Observabilitatea NU trebuie să rupă calea principală → înghite orice eroare."""
    try:
        await db.execute(
            "INSERT INTO agent_events(host_id, ts, event, reason, detail) VALUES(?,?,?,?,?)",
            host_id, time.time(), event, reason, detail)
    except Exception:                     # noqa: BLE001
        pass


async def prune_agent_events() -> None:
    """Retenţie 7 zile pe jurnalul de conexiune (rulat periodic din reaper)."""
    try:
        await db.execute("DELETE FROM agent_events WHERE ts < ?",
                         time.time() - AGENT_EVENTS_RETAIN)
    except Exception:                     # noqa: BLE001
        pass


def new_sid() -> str:
    return uuid.uuid4().hex


# Session ids are always uuid4 hex (new_sid). Anything else reaching a filesystem
# path is untrusted — an agent-reported "adopted" sid or a URL param — and a sid
# with `..`/`/` would let `TRANSCRIPT_DIR / sid` escape the transcript dir.
_SID_RE = re.compile(r"\A[0-9a-f]{%d}\Z" % SID_LEN)


def valid_sid(sid: str) -> bool:
    return bool(_SID_RE.match(sid or ""))


def transcript_paths(sid: str):
    if not valid_sid(sid):
        raise ValueError("invalid session id")
    return (config.TRANSCRIPT_DIR / (sid + ".out"),
            config.TRANSCRIPT_DIR / (sid + ".cast"))


def archive_transcript(sid: str) -> None:
    """Mută transcripturile unei sesiuni în arhivă în loc să le șteargă direct.
    Ceasul de retenție pornește acum: fixăm mtime la momentul arhivării, ca
    purge_archive să numere cele 120 de zile din clipa asta, nu de la ultima
    scriere în sesiune."""
    config.ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()
    for path in transcript_paths(sid):
        if not path.exists():
            continue
        dest = config.ARCHIVE_DIR / path.name
        try:
            path.replace(dest)          # atomic pe același filesystem
            import os
            os.utime(dest, (now, now))
        except OSError:
            log.exception("cannot archive %s", path)


def _dir_file_stats(path) -> tuple:
    """(număr fișiere, total bytes) pentru fișierele directe dintr-un director."""
    count = total = 0
    if not path.exists():
        return (0, 0)
    for f in path.iterdir():
        try:
            if f.is_file():
                count += 1
                total += f.stat().st_size
        except OSError:
            pass
    return (count, total)


_stats_cache: dict = {"t": 0.0, "v": None}


def storage_stats() -> dict:
    # stat-walks the transcript dirs; cache for 30s and call it via a thread
    # (see api.status) so thousands of files don't stall the event loop.
    now = time.time()
    cached = _stats_cache["v"]
    if cached is not None and now - _stats_cache["t"] < 30:
        return cached
    tc, tb = _dir_file_stats(config.TRANSCRIPT_DIR)      # doar transcripturile active
    ac, ab = _dir_file_stats(config.ARCHIVE_DIR)
    # Cât spaţiu a MAI RĂMAS, nu doar cât ocupăm. Fără asta, un disc plin arăta identic cu
    # unul gol: healthcheck-ul nu atinge discul, `db_ping` e o citire (reuşeşte cât timp
    # scrierile pică), iar panoul de status raporta doar cât ocupă transcripturile. Efectul
    # real, măsurat: `healthy` + `/api/status` verde, în timp ce login-ul dă 500 cu
    # „database or disk is full". Pragurile de alertă existau doar pentru hosturile
    # administrate — singura maşină a cărei umplere opreşte tot produsul era nemonitorizată.
    free = total = None
    try:
        st = os.statvfs(config.DATA_DIR)
        free = st.f_bavail * st.f_frsize
        total = st.f_blocks * st.f_frsize
    except OSError:
        pass
    result = {"transcripts_files": tc, "transcripts_bytes": tb,
              "archive_files": ac, "archive_bytes": ab,
              "retention_days": config.ARCHIVE_RETENTION_DAYS,
              "disk_free_bytes": free, "disk_total_bytes": total}
    _stats_cache["t"] = now
    _stats_cache["v"] = result
    return result


async def archive_closed_transcripts(now: Optional[float] = None) -> int:
    """Mută în arhivă transcripturile sesiunilor închise de mai mult de
    `CLOSED_ARCHIVE_DAYS`. Fără asta, `purge_archive` păzeşte un director în care nimic nu
    intra de la sine: arhivarea se făcea doar din `DELETE /api/sessions/{sid}`, deci retenţia
    documentată se aplica exclusiv sesiunilor şterse cu mâna, iar cele închise normal rămâneau
    pe disc la nesfârşit. Rândul din `sessions` rămâne (istoricul e util); doar octeţii pleacă.
    """
    days = config.CLOSED_ARCHIVE_DAYS
    if days <= 0:
        return 0
    cutoff = (now or time.time()) - days * 86400
    rows = await db.fetchall(
        # DOAR `closed`. `lost` înseamnă „agentul a dispărut", nu „s-a terminat": reconcilierea
        # o readuce la `live` când hostul revine (vezi bucla din `reconcile`). Un host offline
        # peste `CLOSED_ARCHIVE_DAYS` care se întoarce ar fi primit sesiunea înviată cu
        # transcriptul deja mutat în arhivă — adică scrollback gol, fix la revenirea din pană.
        "SELECT id FROM sessions WHERE state='closed'"
        " AND COALESCE(closed_at, created) < ?", cutoff)
    moved = 0
    for r in rows:
        out_path, cast_path = transcript_paths(r["id"])
        if not out_path.exists() and not cast_path.exists():
            continue          # deja arhivat la o trecere anterioară
        await asyncio.to_thread(archive_transcript, r["id"])
        moved += 1
    return moved


def purge_archive(now: Optional[float] = None) -> int:
    """Șterge definitiv transcripturile arhivate mai vechi de retenție. Rulat
    de janitor. Întoarce câte fișiere a șters."""
    if not config.ARCHIVE_DIR.exists():
        return 0
    cutoff = (now or time.time()) - config.ARCHIVE_RETENTION_DAYS * 86400
    removed = 0
    for f in config.ARCHIVE_DIR.iterdir():
        try:
            if f.is_file() and f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        except OSError:
            log.exception("cannot delete from the archive %s", f)
    return removed


# a dead tmux client's shutdown sequence ends with clear-screen + leave-alt-
# screen, which would wipe everything just replayed into a closed-session
# view; strip screen switches, full clears and scrollback wipes on replay
ALT_SCREEN_RE = re.compile(
    rb"\x1b\[\?(?:1049|1047|1048|47)[hl]"   # alt screen enter/leave
    rb"|\x1b\[[23]J"                        # clear screen / clear scrollback
    rb"|\x1bc"                              # full terminal reset
)


def read_tail(sid: str, limit: int = config.BROWSER_TAIL_BYTES,
              end: Optional[int] = None) -> bytes:
    # Reads only the FLUSHED bytes on disk (up to the last checkpoint). We must
    # NOT include the most recent unflushed window: replaying it into a small
    # (mobile) terminal collides with the tmux resize redraw and wipes the whole
    # visible history — verified repeatedly, on multi-device is a shipped feature.
    # The cost is a bounded gap on a fresh live subscribe: up to the 2s/64KiB checkpoint
    # window. Measured, not estimated — an external audit attached and detached six times
    # against a session printing every 200ms and lost 3–9 markers (0.6–1.8s of output) EVERY
    # time, reproducibly.
    #
    # This used to say "self-healing", which is false and worth being precise about: what
    # converges is the visible SCREEN, on the next output. Those bytes never reach that
    # client, and they are absent from its scrollback with nothing to show they were dropped
    # — while every other discontinuity in this file gets a `GAP_MARKER` (see
    # `_write_gap_marker`). So the scrollback is quietly incomplete rather than visibly so.
    # The same "the live stream converges" reasoning was already retracted a few lines below,
    # for the idle case, and fixed only there.
    #
    # Closing it needs client-size negotiation before replay (a larger protocol change) —
    # tracked as future work. Until then the honest summary is: attaching can silently cost
    # you up to two seconds of history.
    #
    # EXCEPȚIE, închisă: pentru RESUME/UNLOCK (`BrowserClient._resync`) raționamentul de
    # mai sus nu se aplică — clientul acela avea DEJA dimensiunea sesiunii, deci nu există
    # coliziune cu vreun redraw de resize. Acolo hub-ul face flush înainte și ne dă `end`
    # (offsetul de la flush): citim exact până la el, ca un checkpoint concurent (apărut
    # cât citim pe thread) să nu ne strecoare octeți care sunt deja în coada clientului —
    # ar ajunge dublați. Fără `end`, comportamentul de attach rămâne neschimbat.
    out_path, _ = transcript_paths(sid)
    try:
        size = out_path.stat().st_size
        if end is not None:
            size = min(size, end)
        start = max(0, size - limit)
        with open(out_path, "rb") as f:
            f.seek(start)
            data = f.read(size - start)
    except OSError:
        return b""
    # Comutările de ecran alternativ se scot ÎNTOTDEAUNA din replay. Motivul e tmux: el
    # intră în alt-screen (`ESC[?1049h`) când i se ataşează un client şi iese abia la
    # detach — deci fluxul oricărei sesiuni tmux ÎNCEPE cu o intrare fără pereche. Redată
    # în browser, terminalul rămâne în alt-screen cât ţine sesiunea, iar de acolo:
    #   · fără scrollback (ecranul alternativ nu are);
    #   · tracker-ul de comenzi ignoră deliberat marcajele OSC 133 din alt-screen (rândurile
    #     de acolo dispar la ieşire) → panoul ⌘ rămâne pe „activează integrarea" şi istoricul
    #     global gol, deşi shell-ul emite corect.
    # Simptomele arătau fără legătură; cauza era una. Sesiunile vechi „mergeau" doar fiindcă
    # intrarea ieşise din fereastra de 256 KB — adică exact invers decât s-ar crede.
    # Diagnosticat pe hosturi reale, 2026-08-05. Conţinutul rămâne; starea reală a panoului
    # o restabileşte prima redesenare tmux (la ataşare trimitem oricum un resize).
    return ALT_SCREEN_RE.sub(b"", data)


# ---------------------------------------------------------------------------
# Browser client (one websocket attached to a hub)
# ---------------------------------------------------------------------------

_RESYNC = object()


PING_EVERY = 256 * 1024      # app-level ack interval: uvicorn's ws send has no
PONG_TIMEOUT = 20.0          # backpressure, so we stop-and-wait ourselves
PONG_HARD_TIMEOUT = 40.0     # after this, treat the client as half-open and drop it
KEEPALIVE_SECS = 25.0        # idle keepalive: a session with no output would otherwise
                             # send ZERO ws traffic — a NAT/proxy on the path drops the
                             # idle TCP after minutes (half-open, no FIN), the browser
                             # never sees onclose and shows a frozen screen until reload.
                             # Ping every KEEPALIVE_SECS while idle keeps the path warm,
                             # feeds the client watchdog, and runs dead-client detection.


class BrowserClient:
    def __init__(self, ws, hub: "SessionHub"):
        self.ws = ws
        self.hub = hub
        self.queue: asyncio.Queue = asyncio.Queue()
        self.buffered = 0
        self.sender_task: Optional[asyncio.Task] = None
        self.last_interaction = 0.0
        # identitate pt. roster + kick (setate de handler-ul WS): owner = clientul
        # autentificat; guest = vizitator prin link de share (writable sau read-only)
        self.id = ""
        self.label = "client"
        self.is_owner = False
        self.writable = True
        self.remote_addr = ""
        # De unde şi cu ce s-a ataşat. Roster-ul arăta doar CÂŢI sunt conectaţi, deci vedeai
        # că mai e cineva, dar nu puteai deosebi telefonul tău de altcineva — iar dacă nu te
        # uitai exact atunci, nu aflai deloc. `known=False` înseamnă „IP nemaivăzut la un login
        # al acestui cont", singurul semnal de care avem nevoie ca să facem zgomot.
        self.user_agent = ""
        self.known = True
        self.attached_at = 0.0
        self._sent_since_ping = 0
        self._ping_seq = 0
        self._pong_fut: Optional[asyncio.Future] = None
        # Serializează TOATE scrierile pe acest ws: coroutina sender() și broadcast-urile
        # hub-ului (locked/unlocked/roster) scriu pe același socket. Fără lock, un unlock
        # (broadcast {"type":"unlocked"} din hub + resync/tail pus în coadă → sender) trimite
        # concurent pe același ws → frame-uri întreţesute → ecran gol până la reload.
        self._send_lock = asyncio.Lock()
        # tab inactiv în UI: clientul cere „pause" și nu mai primește output
        # live (economie de trafic/CPU pe tab-urile din fundal); la „resume"
        # primește un resync din transcript DOAR dacă a pierdut ceva —
        # o sesiune liniștită comută instant, fără flash de re-sincronizare
        self.paused = False
        self._missed_while_paused = False
        # blocaj de securitate (idle-lock pe host cu 2FA): output-ul e SUPRIMAT și
        # input-ul REFUZAT până la re-autentificare cu passkey. Diferă de `paused`:
        # clientul NU se poate debloca singur (cere un grant de step-up).
        self.locked = False

    def pause(self) -> None:
        self.paused = True
        self._missed_while_paused = False
        self._drain_queue()

    def resume(self) -> None:
        if not self.paused:
            return
        self.paused = False
        if self._missed_while_paused:
            self._missed_while_paused = False
            self.queue.put_nowait(_RESYNC)

    def lock(self) -> None:
        self.locked = True
        self._missed_while_paused = False
        self._drain_queue()             # nu lăsa output vechi în coadă cât e blocat

    def unlock(self) -> None:
        if not self.locked:
            return
        self.locked = False
        self.queue.put_nowait(_RESYNC)  # resync din transcript ce s-a pierdut cât era blocat

    def push(self, data: bytes) -> None:
        # `self.hub.locked` = gardă defensivă: un client adăugat în hub.clients în fereastra
        # de cursă de după hub.lock() (ex. invitat prin share pe o sesiune 2FA blocată) moşteneşte
        # blocarea chiar dacă lock()-ul per-client n-a apucat să-l prindă → fără scurgere de output.
        if self.paused or self.locked or self.hub.locked:
            self._missed_while_paused = True
            return                      # la resume/unlock vine tail-ul din transcript
        if self.buffered + len(data) > config.CLIENT_BUFFER_LIMIT:
            # slow client: drop backlog, tell it to resync from the transcript
            self._drain_queue()
            self.queue.put_nowait(_RESYNC)
            return
        self.buffered += len(data)
        self.queue.put_nowait(data)

    def _drain_queue(self) -> None:
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self.buffered = 0

    def on_pong(self, n) -> None:
        if self._pong_fut and not self._pong_fut.done() and n >= self._ping_seq:
            self._pong_fut.set_result(None)

    async def send_text(self, s: str) -> None:
        async with self._send_lock:
            await self.ws.send_text(s)

    async def send_bytes(self, b: bytes) -> None:
        async with self._send_lock:
            await self.ws.send_bytes(b)

    async def _resync(self) -> None:
        # Închide gaura de checkpoint (2s/64KiB) din `read_tail` pentru resume/unlock:
        # clientul ăsta avea deja dimensiunea sesiunii, deci motivul pentru care fereastra
        # neflush-uită nu se redă la attach (coliziunea cu redraw-ul de resize al unui client
        # de altă mărime) nu se aplică aici. Fără flush, un TUI rămânea cu golurile ferestrei
        # pierdute — chenarul static (prompterul Claude Code) nu se mai redesena singur, iar
        # simptomul („linii dispărute până la A±/reload") apărea la fiecare revenire pe tab
        # în timpul unui output intens.
        #
        # Ordinea drain → flush → tell e ATOMICĂ (sincronă, același tick de event-loop):
        # tot ce e ≤ cutoff e pe disc și NU e în coadă; tot ce vine după e în coadă și NU e
        # în tail. De-aia nu mai golim coada după trimitere — chunk-urile sosite cât citeam
        # pe thread se trimit la rând, fără gaură și fără dublură.
        self._drain_queue()
        cutoff = None
        if not self.hub.closed:
            try:
                self.hub._flush()
                cutoff = self.hub.out_f.tell()
            except (OSError, ValueError):
                cutoff = None       # handle închis în cursă cu teardown → attach-behaviour
        await self.send_text(json.dumps({"type": "resync"}))
        # read_tail face I/O blocant (până la 256 KB): pe thread, ca un resync
        # (posibil declanșat repetat prin pause/resume) să nu blocheze event-loop-ul.
        # Mărginit la `cutoff`: un checkpoint concurent (cât citim) poate flush-ui octeți
        # care sunt DEJA în coada noastră — fără margine ar ajunge și în tail, și din coadă.
        tail = await asyncio.to_thread(read_tail, self.hub.sid, end=cutoff)
        await self.send_bytes(tail)
        self._sent_since_ping += len(tail)
        # Tail-ul redă ce s-a TRANSMIS, nu ce e PE ECRAN: tmux trimite diff-uri, deci
        # chenarele statice ale unui TUI pot lipsi din orice fereastră de replay. Cerem
        # sursei un repaint complet — vine prin flux, după cutoff, și închide golurile.
        self.hub.request_redraw()   # tails count toward flow control too

    async def _flow_control(self) -> None:
        """Stop-and-wait ack every PING_EVERY bytes. If the client stalls
        beyond PONG_TIMEOUT, drop its backlog and resync when it comes back."""
        self._sent_since_ping = 0
        self._ping_seq += 1
        self._pong_fut = asyncio.get_running_loop().create_future()
        await self.send_text(json.dumps({"type": "ping", "n": self._ping_seq}))
        try:
            await asyncio.wait_for(asyncio.shield(self._pong_fut), PONG_TIMEOUT)
        except asyncio.TimeoutError:
            self._drain_queue()
            # bounded grace: a genuinely half-open client (dead TCP, no FIN)
            # would otherwise wedge this sender forever and leak the client slot.
            try:
                await asyncio.wait_for(asyncio.shield(self._pong_fut), PONG_HARD_TIMEOUT)
            except asyncio.TimeoutError:
                self.hub.clients.discard(self)      # stop fanning output to it
                try:
                    await self.ws.close(code=4408)
                except Exception:
                    pass
                raise RuntimeError("client pong timeout")   # unwind the sender
            await self._resync()      # follow-up ping handled by the sender loop
        finally:
            self._pong_fut = None

    async def sender(self) -> None:
        try:
            while True:
                try:
                    item = await asyncio.wait_for(self.queue.get(), KEEPALIVE_SECS)
                except asyncio.TimeoutError:
                    # sesiune inactivă: fără keepalive, sender() ar bloca la nesfârșit în
                    # queue.get() și nimeni n-ar mai trimite vreun octet → conexiunea moare
                    # tăcut. Ping-ul reia și detecția de client half-open (via _flow_control).
                    await self._flow_control()
                    continue
                if item is _RESYNC:
                    await self._resync()
                else:
                    chunks = [item]
                    total = len(item)
                    self.buffered -= len(item)
                    # coalesce whatever is already queued (≤64 KiB per message)
                    while total < 65536 and not self.queue.empty():
                        nxt = self.queue._queue[0]
                        if nxt is _RESYNC:
                            break
                        self.queue.get_nowait()
                        self.buffered -= len(nxt)
                        chunks.append(nxt)
                        total += len(nxt)
                    await self.send_bytes(b"".join(chunks))
                    self._sent_since_ping += total
                while self._sent_since_ping >= PING_EVERY:
                    await self._flow_control()
        except Exception:
            pass  # ws closed; disconnect handled by the endpoint


# ---------------------------------------------------------------------------
# SessionHub
# ---------------------------------------------------------------------------

class SessionHub:
    def __init__(self, row):
        self.sid: str = row["id"]
        self.host_id: int = row["host_id"]
        self.rows: int = row["rows"] or 24
        self.cols: int = row["cols"] or 80
        self.agent_epoch: Optional[str] = row["agent_epoch"]
        self.agent_offset: int = row["agent_offset"] or 0
        self.created: float = row["created"]
        self.attached = False
        self._attach_lock = asyncio.Lock()
        self._attach_buffer: Optional[list] = None   # buffers output during attach
        self._replay_end = asyncio.Event()
        self.clients: Set[BrowserClient] = set()
        self.closed = False
        # idle-lock de securitate (host cu 2FA): dacă nu vine input de operator
        # `lock_idle` secunde, blocăm terminalul (output suprimat + input refuzat) până
        # la re-auth cu passkey. `lock_idle=0` → dezactivat. Setat la connect din host.
        self.lock_idle = 0
        self.locked = False
        self.last_interaction = time.time()
        self._last_checkpoint = 0.0
        self._unpersisted = 0
        self._idle_flush: Optional[asyncio.Task] = None
        self._last_resize = (self.rows, self.cols)
        self._redraw_task: Optional[asyncio.Task] = None

        out_path, cast_path = transcript_paths(self.sid)
        is_new = not cast_path.exists()
        self.out_f = open(out_path, "ab")
        self.cast_f = open(cast_path, "a", encoding="utf-8")
        if is_new:
            header = {"version": 2, "width": self.cols, "height": self.rows,
                      "timestamp": int(self.created)}
            self.cast_f.write(json.dumps(header) + "\n")
            self.cast_f.flush()

    # -- transcript ---------------------------------------------------------

    def _cast_event(self, kind: str, data: bytes) -> None:
        t = round(time.time() - self.created, 6)
        text = data.decode("utf-8", errors="replace")
        self.cast_f.write(json.dumps([t, kind, text]) + "\n")

    def _write_gap_marker(self) -> None:
        self.out_f.write(GAP_MARKER)
        self._cast_event("o", GAP_MARKER)
        self._flush()

    def _flush(self) -> None:
        self.out_f.flush()
        self.cast_f.flush()

    def _maybe_cap(self) -> None:
        """Head-truncate the transcript when .out exceeds the cap: keep the last
        KEEP bytes, gap-marked. Bounds disk for a runaway `yes`/`cat bigfile`.
        Rare (only past MAX), so the rewrite cost is acceptable.

        NB: SINCRON intenționat (fără `await` între close→reopen al handle-urilor) — pe
        event-loop-ul single-thread asta e atomic față de teardown/mark_lost/on_exit, care
        închid out_f/cast_f fără să treacă prin _attach_lock. O versiune off-loop (to_thread)
        deschide o fereastră în care acele căi de lifecycle ating handle-uri în curs de reschimbare
        → ValueError pe handle închis → cade conexiunea agentului. (vezi audit v1.0.117; TODO:
        variantă off-loop CORECTĂ cu coordonare de lock-uri, ca să nu mai înghețe la runaway output)."""
        try:
            out_sz = self.out_f.tell()
            cast_sz = self.cast_f.tell()
        except OSError:
            return
        # Declanşarea se uita DOAR la `.out`, dar `.cast` creşte mai repede (JSON-escaped:
        # măsurat ×1,35). Când `.out` atingea 64 MiB, `.cast` era pe la 86 MiB — deci
        # plafonul real per sesiune era ~150 MiB, nu 64, iar dimensionarea discului după
        # documentaţie ieşea la mai puţin de jumătate din realitate. Taie oricare dintre ele.
        if out_sz < config.TRANSCRIPT_MAX_BYTES and cast_sz < config.TRANSCRIPT_MAX_BYTES:
            return
        keep = config.TRANSCRIPT_KEEP_BYTES
        out_path, cast_path = transcript_paths(self.sid)
        gap_ts = round(time.time() - self.created, 6)
        gap_cast = (json.dumps([gap_ts, "o", GAP_MARKER.decode("utf-8", "replace")]) + "\n").encode()
        try:
            self.out_f.flush(); self.out_f.close()
            with open(out_path, "rb") as f:
                f.seek(max(0, out_sz - keep))
                tail = f.read()
            with open(out_path, "wb") as f:
                f.write(GAP_MARKER + tail)
            self.out_f = open(out_path, "ab")
            # .cast: keep the header line + a gap event + the tail (snap to a line)
            self.cast_f.flush(); self.cast_f.close()
            with open(cast_path, "rb") as f:
                header = f.readline()
                csz = f.seek(0, 2)
                f.seek(max(len(header), csz - keep))
                chunk = f.read()
            nl = chunk.find(b"\n")
            tail_lines = chunk[nl + 1:] if nl >= 0 else b""
            with open(cast_path, "wb") as f:
                f.write(header + gap_cast + tail_lines)
            self.cast_f = open(cast_path, "a", encoding="utf-8")
        except OSError:
            log.exception("transcript cap %s failed", self.sid)

    def _schedule_idle_flush(self) -> None:
        """Persistă coada de output dacă sesiunea tace.

        `_checkpoint` se cheamă DOAR din `_process_output`, iar el sare peste scriere sub
        64 KiB / 2 s. Dacă nu mai vine niciun octet — starea normală a unui terminal lăsat
        deschis — ultimul val rămâne în bufferul Python la infinit: reîncarci pagina şi
        scrollback-ul e gol, `/transcript`, `/preview` şi căutarea nu văd ultima comandă, iar o
        repornire de gateway (adică fiecare upgrade) o pierde definitiv din pista de audit.
        Comentariul din `read_tail` justifica fereastra cu „fluxul live converge terminalul la
        următorul output" — dar „următorul output" nu există pentru o sesiune inactivă."""
        if self._idle_flush and not self._idle_flush.done():
            self._idle_flush.cancel()

        async def _later():
            try:
                await asyncio.sleep(2.5)
                if self._unpersisted:
                    await self._checkpoint(force=True)
            except asyncio.CancelledError:
                pass
            except Exception:                 # noqa: BLE001 — persistenţa nu rupe sesiunea
                log.exception("delayed flush failed for %s", self.sid)

        self._idle_flush = asyncio.create_task(_later())

    async def _checkpoint(self, force: bool = False) -> None:
        now = time.time()
        if not force and self._unpersisted < 65536 and now - self._last_checkpoint < 2.0:
            self._schedule_idle_flush()       # nu scriem ACUM, dar nu uităm nici la nesfârşit
            return
        self._flush()
        self._maybe_cap()                     # sync: rescrie fișierul atomic față de loop
        try:
            # fsync-ul (sincronizarea pe disc) e costul care blochează loop-ul pe
            # calea fierbinte de output — îl mutăm pe un thread. _flush/_maybe_cap
            # rămân sincrone ca să nu concureze cu scrierile de la attach.
            fd = self.out_f.fileno()
            await asyncio.to_thread(os.fsync, fd)   # durability: survive power loss
        except OSError:
            pass
        self._last_checkpoint = now
        self._unpersisted = 0
        await db.execute(
            "UPDATE sessions SET agent_epoch = ?, agent_offset = ? WHERE id = ?",
            self.agent_epoch, self.agent_offset, self.sid)

    # -- attach / output ------------------------------------------------------

    async def ensure_attached(self, source: "SessionSource") -> None:
        if self.attached or self.closed:
            return
        async with self._attach_lock:
            if self.attached or self.closed:
                return
            if source.epoch != self.agent_epoch:
                # agent restarted: its offsets reset; replay from its ring base
                if self.agent_epoch is not None and self.agent_offset > 0:
                    self._write_gap_marker()
                from_offset = None
            else:
                from_offset = self.agent_offset
            # replay bytes may start arriving before we processed the attach
            # response (they follow it on the same ws); buffer them so the
            # offset bookkeeping below happens first
            self._attach_buffer = []
            self._replay_end.clear()
            try:
                resp = await source.attach(self.sid, from_offset)
            except (AgentGone, asyncio.TimeoutError):
                resp = {}
            buffered, self._attach_buffer = self._attach_buffer, None
            if not resp.get("ok"):
                log.warning("attach %s failed: %s", self.sid, resp.get("code"))
                for chunk in buffered:
                    await self._process_output(chunk)
                return
            replay_start = resp.get("replay_start", 0)
            if from_offset is not None and replay_start > from_offset:
                self._write_gap_marker()
            self.agent_epoch = source.epoch
            self.agent_offset = replay_start
            self.attached = True
            # Drenăm replay-ul bufferat ÎNAINTE de await-ul de resize (o RTT la agent):
            # `_attach_buffer` e deja None, deci output live sosit în fereastra acelui await
            # ar merge direct în _process_output — scris în transcript ÎNAINTEA acestor chunk-uri
            # sosite mai devreme → reordonare a scrollback-ului la attach. Drenarea întâi păstrează ordinea.
            for chunk in buffered:
                await self._process_output(chunk)
            # Agentul poate fi fost repornit între timp: sesiunile tmux sunt
            # re-adoptate cu 80×24 hardcodat, iar browserul retrimite aceeași
            # dimensiune ca înainte — pe care dedup-ul din resize() ar tăia-o.
            # Retrimitem necondiționat dimensiunea cunoscută la fiecare attach.
            self._last_resize = (self.rows, self.cols)
            try:
                await source.resize(self.sid, self.rows, self.cols)
            except (AgentGone, asyncio.TimeoutError):
                pass
            await self._checkpoint(force=True)

    async def wait_replay_end(self, timeout: float = 10.0) -> None:
        try:
            await asyncio.wait_for(self._replay_end.wait(), timeout)
        except asyncio.TimeoutError:
            pass

    def on_replay_end(self) -> None:
        self._replay_end.set()

    def on_detached(self) -> None:
        self.attached = False

    async def on_output(self, data: bytes) -> None:
        if self.closed:
            return
        if self._attach_buffer is not None:
            self._attach_buffer.append(data)
            return
        await self._process_output(data)

    async def _process_output(self, data: bytes) -> None:
        if self.closed:
            return
        self.agent_offset += len(data)
        self._unpersisted += len(data)
        self.out_f.write(data)
        self._cast_event("o", data)
        for client in self.clients:
            client.push(data)
        await self._checkpoint()

    async def on_exit(self, status, sig) -> None:
        if self.closed:
            return
        self.attached = False
        await self._checkpoint(force=True)
        await db.execute(
            "UPDATE sessions SET state='closed', closed_at=?, exit_status=?,"
            " close_reason='exited' WHERE id=?",
            time.time(), status, self.sid)
        await self.broadcast_json({"type": "exit", "status": status, "signal": sig})
        source = self._source()
        if source:
            try:
                await source.reap(self.sid)
            except (AgentGone, asyncio.TimeoutError):
                pass
        self.teardown()

    async def mark_lost(self, reason: str = "lost") -> None:
        if self.closed:
            return
        self.attached = False
        await self._checkpoint(force=True)
        await db.execute(
            "UPDATE sessions SET state='lost', closed_at=?, close_reason=? WHERE id=?",
            time.time(), reason, self.sid)
        await self.broadcast_json({"type": "lost", "reason": reason})
        self.teardown()

    def teardown(self) -> None:
        self.closed = True
        # taskul de flush întârziat ar scrie într-un fişier deja închis
        if self._idle_flush and not self._idle_flush.done():
            self._idle_flush.cancel()
        hubs.pop(self.sid, None)
        session_sources.pop(self.sid, None)   # plasă de siguranță; sursa își face close-ul
        try:
            self._flush()
            self.out_f.close()
            self.cast_f.close()
        except OSError:
            pass

    # -- browser side ---------------------------------------------------------

    async def broadcast_json(self, obj: dict) -> None:
        payload = json.dumps(obj)
        for client in list(self.clients):
            try:
                await client.send_text(payload)   # prin lock-ul per-client: nu se întreţese cu sender()
            except Exception:
                pass

    def roster(self) -> list:
        """Who is attached to the session (for the owner's UI: roster + kick)."""
        return [{"id": c.id, "label": c.label, "owner": c.is_owner, "writable": c.writable,
                 "ip": c.remote_addr, "agent": c.user_agent[:120], "known": c.known,
                 "since": round(c.attached_at)}
                for c in self.clients if c.id]

    async def announce_attach(self, joining) -> None:
        """Spune CELORLALŢI clienţi că altcineva tocmai s-a ataşat. Roster-ul se actualiza
        tăcut, deci aflai doar dacă priveai în secunda aia. Evenimentul ăsta e ce transformă
        „se vede în listă" în „ştiu că s-a întâmplat" — iar clientul îl ridică la notificare de
        sistem când dispozitivul e necunoscut. Nu se trimite celui care tocmai a intrat."""
        msg = json.dumps({"type": "attached", "client": {
            "id": joining.id, "label": joining.label, "owner": joining.is_owner,
            "writable": joining.writable, "ip": joining.remote_addr,
            "agent": joining.user_agent[:120], "known": joining.known}})
        for c in list(self.clients):
            if c is joining:
                continue
            try:
                await c.send_text(msg)
            except Exception:            # noqa: BLE001 — un client mort nu opreşte anunţul
                pass

    async def broadcast_roster(self) -> None:
        await self.broadcast_json({"type": "roster", "clients": self.roster()})

    async def revoke_shares(self) -> None:
        """Owner-ul a revocat share-ul: notifică invitaţii (`revoked`) şi le închide socketul,
        oprind broadcast-ul. Clienţii-owner (autentificaţi) rămân. Instant; revalidarea din
        shared_ws e plasa de siguranţă (prinde şi expirarea cât e conectat)."""
        for c in list(self.clients):
            if not c.is_owner:
                self.clients.discard(c)          # opreşte fan-out-ul imediat
                try:
                    await c.send_text(json.dumps({"type": "revoked"}))
                    await c.ws.close(code=4403)
                except Exception:                # noqa: BLE001
                    pass
        await self.broadcast_roster()

    async def lock(self) -> None:
        """Blochează sesiunea (idle-lock 2FA): output suprimat + input refuzat până la
        re-auth cu passkey. Sesiunea (tmux) rulează mai departe — doar accesul e blocat."""
        if self.locked:
            return
        self.locked = True
        for c in list(self.clients):
            c.lock()
        await self.broadcast_json({"type": "locked"})
        log.info("session %s: locked (2FA idle-lock, %ds with no input)", self.sid, self.lock_idle)

    async def unlock(self) -> None:
        """Deblochează după un step-up passkey valid (vezi endpoint-ul WS 'unlock')."""
        if not self.locked:
            return
        self.locked = False
        self.last_interaction = time.time()
        for c in list(self.clients):
            c.unlock()
        await self.broadcast_json({"type": "unlocked"})
        log.info("session %s: unlocked (passkey re-auth)", self.sid)

    def _source(self):
        """Sursa care servește ACEASTĂ sesiune: una per-sesiune (telnet-via-agent)
        dacă există, altfel sursa per-host. Fallback-ul păstrează exact semantica
        de reconnect a surselor per-host (agent/SSH re-dial)."""
        ss = session_sources.get(self.sid)
        return ss if ss is not None else source_for(self.host_id)

    async def handle_input(self, client: BrowserClient, data: bytes) -> None:
        if self.closed:
            return                     # sesiune terminată/teardown: cast_f e închis →
                                       # _cast_event ar arunca ValueError și ar crăpa WS-ul
        if self.locked or getattr(client, "locked", False):
            # ŞI per-client: `shared_ws` blochează invitatul cu `client.lock()`, nu cu
            # `hub.lock()` (corect — un invitat n-are voie să blocheze sesiunea owner-ului).
            # Dar aici se verifica doar `self.locked`, deci tastele invitatului treceau, iar
            # fiecare tastă împrospăta `last_interaction` → hub-ul nu se mai bloca NICIODATĂ.
            # Rezultat: pe un host cu require_2fa, un share writable ocolea complet poarta de
            # passkey. Reprodus de auditul intern (2026-08-06): octeţii ajungeau la PTY.
            return
        now = time.time()
        client.last_interaction = now
        self.last_interaction = now    # activitate de operator la nivel de sesiune (idle-lock)
        source = self._source()
        # NU înregistrăm input-ul în transcript (.cast). Player-ul redă DOAR output-ul
        # ("o"), iar input-ul echoed apare oricum acolo — dar la un prompt de parolă
        # (echo off: sudo/ssh/mysql -p) input-ul NU apare în output, deci înregistrarea
        # lui ar scurge parole downstream în .cast + backup-uri (păstrate ~120 zile,
        # descărcabile). Octeții reali merg oricum la sursă mai jos. `redact_input` de pe
        # sursa telnet devine redundant, dar rămâne corect (input-ul tot nu se scrie).
        self._unpersisted += len(data)
        if source:
            await self.ensure_attached(source)
            try:
                await source.send_data(self.sid, data)
            except Exception:
                pass

    async def resize(self, rows: int, cols: int) -> None:
        if self.closed:
            return
        rows = max(2, min(500, rows))
        cols = max(2, min(1000, cols))
        if (rows, cols) == self._last_resize:
            return
        self._last_resize = (rows, cols)
        self.rows, self.cols = rows, cols
        await db.execute("UPDATE sessions SET rows=?, cols=? WHERE id=?",
                         rows, cols, self.sid)
        source = self._source()
        if source:
            try:
                await source.resize(self.sid, rows, cols)
            except (AgentGone, asyncio.TimeoutError):
                pass
        await self.broadcast_json({"type": "resize", "rows": rows, "cols": cols})

    def request_redraw(self) -> None:
        """Cere sursei o retransmitere completă a ecranului (tmux `refresh-client`).

        Chemat după un resync de resume: tail-ul reconstruiește ce s-a TRANSMIS, dar tmux
        transmite doar diff-uri — părțile statice ale unui TUI (chenarul prompterului
        Claude Code) pot să nu fi fost retransmise de mult, deci lipsesc din orice
        fereastră de replay. Redraw-ul curge prin fluxul normal (transcript + cozi), adică
        ajunge DUPĂ tail (post-cutoff) și repară ecranul pentru toți clienții. Debounced:
        mai multe taburi pot da resume aproape simultan, un singur repaint ajunge.
        Fire-and-forget: un agent vechi (fără op-ul `redraw`) răspunde cu eroare — ignorată,
        comportamentul rămâne cel de dinainte."""
        if self.closed or (self._redraw_task and not self._redraw_task.done()):
            return

        async def _go():
            await asyncio.sleep(0.2)
            source = self._source()
            if source:
                try:
                    await source.redraw(self.sid)
                except Exception:
                    pass              # agent vechi / plecat / timeout — nimic de reparat aici

        self._redraw_task = asyncio.create_task(_go())


def get_or_create_hub(row) -> SessionHub:
    hub = hubs.get(row["id"])
    if hub is None:
        hub = SessionHub(row)
        hubs[row["id"]] = hub
    return hub


# ---------------------------------------------------------------------------
# AgentConnection
# ---------------------------------------------------------------------------

class AgentGone(Exception):
    pass


# limita e impusă de agent (MAX_SESSIONS din ptyd.py); o replicăm aici doar
# pentru mesajul de eroare lizibil (nu e sursa de adevăr)
MAX_SESSIONS_HINT = 32

# Metricile pe care agentul le trimite şi UI-ul le afişează. Orice altceva se aruncă:
# dicţionarul ăsta pleacă în fiecare răspuns de host-detail.
METRIC_KEYS = frozenset((
    "cpu_pct", "load1", "load5", "load15",
    "mem_total", "mem_used", "disk_total", "disk_used", "uptime",
))


class SessionLimitReached(Exception):
    """The host hit MAX_SESSIONS — a normal condition, mapped to 409 (not 502)."""
    pass


class SessionSource:
    """A backend that hosts PTY sessions and feeds SessionHubs. Implemented by
    AgentConnection (reverse-ws agent) and — for direct connections — SshSource /
    TelnetSource (gateway dial-out). SessionHub touches a source only through
    the methods below plus the `epoch` attribute; everything else is optional
    metadata surfaced in the UI."""
    epoch: Optional[str] = None
    backend: Optional[str] = None
    agent_version: Optional[int] = None
    metrics: Optional[dict] = None

    async def create(self, sid: str, rows: int, cols: int, term: str,
                     tz: Optional[str] = None) -> dict:
        raise NotImplementedError

    async def attach(self, sid: str, from_offset) -> dict:
        raise NotImplementedError

    async def send_data(self, sid: str, data: bytes) -> None:
        raise NotImplementedError

    async def resize(self, sid: str, rows: int, cols: int) -> None:
        raise NotImplementedError

    async def redraw(self, sid: str) -> None:
        # Retransmiterea completă a ecranului (tmux `refresh-client`), cerută după un
        # resume de tab: tmux trimite doar diff-uri, deci un replay din transcript nu
        # poate reconstrui părțile statice ale unui TUI. Implicit no-op — sursele fără
        # tmux (ssh/telnet/serial) n-au echivalent fără să schimbe dimensiunea.
        return None

    async def reap(self, sid: str) -> None:
        raise NotImplementedError

    async def kill(self, sid: str) -> None:
        raise NotImplementedError

    async def disconnect(self) -> None:
        """Închide transportul sursei (la înlocuire / oprire)."""


class ForwardError(Exception):
    pass


# Plafon de octeți „în zbor" per stream de forward: octeții primiți de la țintă dar
# încă ne-drenați de consumator (browser/HTTP lent). `_feed` e apelat din bucla unică
# de recv a agentului, care servește TOATE stream-urile — deci NU putem bloca acolo
# (ar fi head-of-line blocking pe tot agentul). Fără plafon, un slow consumer +
# țintă rapidă = creștere de memorie nemărginită. Pentru un proxy TCP brut, drop-ul
# silențios ar corupe stream-ul, așa că la depășire închidem stream-ul (EOF). Plafonul
# e generos ca să nu afecteze transferuri legitime care progresează.
FWD_MAX_BUFFER = 32 * 1024 * 1024


class ForwardStream:
    """Un tunel TCP prin agent (port forwarding): scrii octeți către țintă cu
    `write`, citești ce vine înapoi cu `read` (None = țintă închisă/EOF). Reverse
    proxy-ul de forward construiește deasupra HTTP/WebSocket."""

    def __init__(self, conn: "AgentConnection", stream_id: str):
        self._conn = conn
        self.stream_id = stream_id
        self._q: "asyncio.Queue" = asyncio.Queue()
        self._buffered = 0          # octeți în coadă, ne-drenați (vezi FWD_MAX_BUFFER)
        self._closed = False
        self._eof_seen = False   # EOF lipicios (vezi read)
        self.overflowed = False     # închis fiindcă consumatorul n-a ținut pasul
        self.tunnel_lost = False    # închis fiindcă a căzut agentul (nu ținta) → reconectabil

    async def write(self, data: bytes) -> None:
        await self._conn.send_fwd(self.stream_id, data)

    async def read(self):
        """Următorul bloc de octeți de la țintă; None la EOF/închidere.

        EOF-ul e LIPICIOS. `_eof()` pune un singur `None` în coadă; cine îl consuma îl scotea
        definitiv, iar următorul `read()` aştepta la infinit pe o coadă în care nu mai vine
        nimic. Exact ce se întâmpla la un forward către o ţintă moartă: bucla care citeşte
        antetul consuma `None`-ul şi răspundea 502, apoi `body_stream()` mai chema o dată
        `read()` — antetul ajungea instant în browser, corpul nu se termina NICIODATĂ, tab-ul
        se învârtea, iar tunelul rămânea alocat. Cu `curl` părea corect, fiindcă `head -1`
        închide pipe-ul; de-asta nu s-a văzut."""
        if self._eof_seen:
            return None
        item = await self._q.get()
        if item is None:
            self._eof_seen = True
        else:
            self._buffered -= len(item)
        return item

    def _feed(self, data: bytes) -> None:      # din recv loop
        if self._closed:
            return
        if self._buffered + len(data) > FWD_MAX_BUFFER:
            # consumator prea lent: peste plafon → închidem în loc să creștem memoria
            log.warning("forward %s: %d bytes in flight over the cap (%d) — tearing down "
                        "(slow consumer)", self.stream_id,
                        self._buffered + len(data), FWD_MAX_BUFFER)
            self.overflowed = True
            self._eof()
            return
        self._buffered += len(data)
        self._q.put_nowait(data)

    def _eof(self) -> None:                    # ținta a închis / conexiune pierdută
        if not self._closed:
            self._closed = True
            self._q.put_nowait(None)

    async def close(self) -> None:
        if self._closed:
            self._conn.forwards.pop(self.stream_id, None)
            return
        self._closed = True
        self._conn.forwards.pop(self.stream_id, None)
        self._q.put_nowait(None)
        try:
            await self._conn.request("fwd_close", stream=self.stream_id, timeout=5)
        except (AgentGone, asyncio.TimeoutError):
            pass


class TlsForwardStream:
    """TLS pe ultimul hop, gateway → țintă `https`, peste un ForwardStream.
    ssl.SSLObject + BIO-uri în memorie (nu avem un socket real — octeții curg prin
    tunelul agentului). Ținta e pe loopback-ul host-ului (nu ajunge pe fir), iar
    panourile de admin folosesc uzual certificate self-signed, deci NU verificăm
    certificatul: confidențialitatea pe fir e deja dată de TLS-ul browser→Traefik
    și de WSS-ul gateway→agent; aici doar vorbim protocolul corect cu ținta."""

    def __init__(self, fs: "ForwardStream", server_hostname: Optional[str] = None):
        self._fs = fs
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # SNI doar pentru nume reale (nu pentru IP-uri literale)
        sni = server_hostname if server_hostname and any(
            c.isalpha() for c in server_hostname) else None
        self._obj = ctx.wrap_bio(self._in, self._out, server_hostname=sni)

    async def _flush(self) -> None:
        data = self._out.read()
        if data:
            await self._fs.write(data)

    async def _feed(self) -> bool:
        chunk = await self._fs.read()
        if chunk is None:
            self._in.write_eof()
            return False
        self._in.write(chunk)
        return True

    async def handshake(self) -> None:
        while True:
            try:
                self._obj.do_handshake()
                await self._flush()
                return
            except ssl.SSLWantReadError:
                await self._flush()
                if not await self._feed():
                    raise ForwardError("TLS handshake: EOF from the target")
            except ssl.SSLError as e:
                raise ForwardError("TLS handshake failed: %s" % e)

    async def write(self, data: bytes) -> None:
        view = memoryview(data)
        off = 0
        while off < len(view):
            try:
                off += self._obj.write(view[off:])
            except ssl.SSLWantReadError:      # renegociere rară
                await self._flush()
                if not await self._feed():
                    raise ForwardError("TLS write: EOF from the target")
        await self._flush()

    async def read(self):
        while True:
            try:
                data = self._obj.read(65536)
                return data or None
            except ssl.SSLWantReadError:
                await self._flush()
                if not await self._feed():
                    # ținta a închis — mai scoate ce a rămas decriptat, apoi EOF
                    try:
                        data = self._obj.read(65536)
                        return data or None
                    except ssl.SSLError:
                        return None
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return None
            except ssl.SSLError:
                return None

    async def close(self) -> None:
        await self._fs.close()


async def wrap_tls_forward(fs: "ForwardStream",
                           server_hostname: Optional[str] = None) -> TlsForwardStream:
    t = TlsForwardStream(fs, server_hostname)
    await t.handshake()
    return t


class AgentConnection(SessionSource):
    def __init__(self, ws, host_id: int):
        self.ws = ws
        self.host_id = host_id
        self.host_name: Optional[str] = None   # memoizat la primul heartbeat cu metrice
        self.epoch: Optional[str] = None
        self.backend: Optional[str] = None
        self.agent_version: Optional[int] = None
        self.metrics: Optional[dict] = None
        self._req_id = 0
        self._pending: Dict[int, asyncio.Future] = {}
        self.forwards: Dict[str, ForwardStream] = {}   # stream_id -> tunel activ
        self._tasks: Set[asyncio.Task] = set()
        self.connected_at = time.time()
        # reconcile serializat + coalescat per conexiune (vezi schedule_reconcile)
        self._reconcile_latest: Optional[dict] = None
        self._reconcile_saw_hello = False
        self._reconcile_running = False
        self._stop_reason = ""        # motivul deconectării (jurnal): heartbeat_stale/superseded/…
        self._connect_logged = False  # jurnal: scriem evenimentul `connect` o dată, la primul hello
        self.link = {}                # health de link raportat de agent: uptime/reconnects/rtt_ms
        # Serializează scrierile pe ws-ul agentului: send_ctrl (request-uri fs/resize/run),
        # send_data (input din fiecare browser_ws) și send_fwd (proxy forward, bucăţi de 1 MB)
        # rulează din coroutine concurente. Fără lock, două send_bytes se întreţes pe fir →
        # frame WS corupt → agentul citește lungime/opcode greşit → cade TOT hostul (toate
        # sesiunile + forward-urile). Lock-ul e per-frame (nu pe tot send_fwd), ca un upload
        # mare să nu blocheze tastarea — frame-urile complete se pot intercala în siguranţă.
        self._send_lock = asyncio.Lock()

    # Un corp de upload prin forward poate ajunge la ~100 MB (FWD_MAX_BODY); trimis
    # ca UN singur frame WS ar depăși plafonul agentului (16 MB/frame, 32 MB reasamblat)
    # → agentul închide conexiunea. Fragmentăm sub plafon.
    FWD_SEND_CHUNK = 1024 * 1024

    async def send_ctrl(self, obj: dict) -> None:
        try:
            async with self._send_lock:
                await self.ws.send_bytes(FRAME_CTRL + json.dumps(obj).encode())
        except Exception:
            raise AgentGone()

    async def send_data(self, sid: str, data: bytes) -> None:
        try:
            async with self._send_lock:
                await self.ws.send_bytes(FRAME_DATA + sid.encode() + data)
        except Exception:
            raise AgentGone()

    async def send_fwd(self, stream: str, data: bytes) -> None:
        prefix = FRAME_FWD + stream.encode()
        try:
            # fragmentare sub plafonul de frame al agentului (vezi FWD_SEND_CHUNK). Lock
            # per-frame: fiecare send_bytes e atomic, dar între bucăţi se pot intercala
            # frame-uri complete de input/ctrl (tastarea nu îngheaţă în timpul unui upload).
            for i in range(0, len(data), self.FWD_SEND_CHUNK):
                async with self._send_lock:
                    await self.ws.send_bytes(prefix + data[i:i + self.FWD_SEND_CHUNK])
        except Exception:
            raise AgentGone()

    async def open_forward(self, host: str, port: int) -> ForwardStream:
        """Deschide un tunel TCP către host:port văzut de agent (ex. 127.0.0.1:3000
        pe host-ul remote). Se deschide DOAR la trafic real, nu pentru forward-urile
        doar declarate. Ridică ForwardError dacă agentul refuză/nu ajunge la țintă."""
        stream = uuid.uuid4().hex            # 32 hex = SID_LEN
        resp = await self.request("fwd_open", stream=stream, host=host, port=port, timeout=15)
        if not resp.get("ok"):
            raise ForwardError(resp.get("msg") or resp.get("code") or "forward refuzat")
        fs = ForwardStream(self, stream)
        self.forwards[stream] = fs
        return fs

    async def serial_list(self) -> list:
        """Porturile seriale reale de pe host (discovery)."""
        resp = await self.request("serial_list", timeout=10)
        if not resp.get("ok"):
            raise ForwardError(resp.get("msg") or resp.get("code") or "serial_list failed")
        return resp.get("ports", [])

    async def get_agent_log(self) -> str:
        """Tail-ul logului agentului (ptyd.log) — pentru panoul de Diagnostic, debug fără SSH."""
        resp = await self.request("get_log", timeout=10)
        if not resp.get("ok"):
            raise ForwardError(resp.get("msg") or resp.get("code") or "get_log failed")
        return resp.get("log", "")

    async def open_serial(self, device: str, baud: int, bits: int, parity: str,
                          stop: int, flow: str) -> ForwardStream:
        """Deschide o consolă serială pe host (fd `/dev/tty*` + termios), bridge la
        gateway prin ACELAȘI transport ca forward-urile (FRAME_FWD → ForwardStream)."""
        stream = uuid.uuid4().hex
        resp = await self.request("serial_open", stream=stream, device=device, baud=baud,
                                  bits=bits, parity=parity, stop=stop, flow=flow, timeout=15)
        if not resp.get("ok"):
            raise ForwardError(resp.get("msg") or resp.get("code") or "serial refuzat")
        fs = ForwardStream(self, stream)
        self.forwards[stream] = fs
        return fs

    async def request(self, op: str, timeout: float = 20.0, **fields) -> dict:
        self._req_id += 1
        rid = self._req_id
        fut = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        try:
            await self.send_ctrl(dict(fields, op=op, id=rid))
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(rid, None)

    # -- SessionSource interface (delegates to the agent's control channel) ----
    async def create(self, sid, rows, cols, term, tz=None) -> dict:
        fields = dict(sid=sid, rows=rows, cols=cols, term=term)
        if tz:
            fields["tz"] = tz
        return await self.request("create", **fields)

    async def attach(self, sid, from_offset) -> dict:
        return await self.request("attach", sid=sid, from_offset=from_offset)

    async def resize(self, sid, rows, cols) -> None:
        await self.request("resize", sid=sid, rows=rows, cols=cols)

    async def redraw(self, sid) -> None:
        await self.request("redraw", sid=sid)

    async def reap(self, sid) -> None:
        await self.request("reap", sid=sid)

    async def kill(self, sid) -> None:
        await self.request("kill", sid=sid)

    async def run_command(self, command: str, cmd_timeout: int = 60) -> dict:
        """Rulare non-interactivă a unei comenzi pe host (consola de flotă).
        Așteaptă puțin peste timeout-ul comenzii, ca reply-ul agentului (inclusiv
        pe timeout) să ajungă înaintea expirării cererii."""
        return await self.request("run", timeout=cmd_timeout + 15,
                                  cmd=command, cmd_timeout=cmd_timeout)

    async def disconnect(self) -> None:
        try:
            await self.ws.close()
        except Exception:
            pass

    async def run(self) -> None:
        """Receive loop; returns when the agent disconnects."""
        try:
            while True:
                try:
                    # liveness: the agent sends a heartbeat every 30s, so no frame
                    # for HEARTBEAT_STALE means a half-open TCP (no FIN) — drop it
                    # instead of keeping a dead host "online" forever.
                    data = await asyncio.wait_for(self.ws.receive_bytes(),
                                                  timeout=config.HEARTBEAT_STALE)
                except asyncio.TimeoutError:
                    log.warning("host %s: no frames for %.0fs — dropping half-open agent",
                                self.host_id, config.HEARTBEAT_STALE)
                    self._stop_reason = "heartbeat_stale"
                    break
                if not data:
                    continue
                # a superseded agent (replaced by a reconnect, or a duplicate
                # machine on the same token) must NOT write into hubs or process
                # events — only the current source for this host may. Prevents
                # doubled output and wrong-host command routing.
                if sources.get(self.host_id) is not self:
                    continue
                ftype, body = data[:1], data[1:]
                if ftype == FRAME_DATA:
                    sid = body[:SID_LEN].decode(errors="replace")
                    hub = hubs.get(sid)
                    # izolare între hosturi: un agent poate scrie DOAR în sesiunile
                    # host-ului său, chiar dacă ar afla un sid al altui host.
                    if hub and hub.host_id == self.host_id:
                        await hub.on_output(body[SID_LEN:])
                elif ftype == FRAME_FWD:
                    stream = body[:SID_LEN].decode(errors="replace")
                    fs = self.forwards.get(stream)
                    if fs:
                        fs._feed(body[SID_LEN:])
                elif ftype == FRAME_CTRL:
                    # un frame de control corupt de la agent NU trebuie să doboare toată
                    # conexiunea (toate sesiunile + forward-urile hostului) — log + skip.
                    try:
                        await self._on_ctrl(json.loads(body.decode()))
                    except (ValueError, UnicodeDecodeError) as e:
                        log.warning("host %s: invalid control frame ignored: %s", self.host_id, e)
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        # only detach hubs if THIS conn was the current source — otherwise a
        # superseded agent disconnecting would flip the live (new) agent's hubs
        # to "detached".
        was_current = sources.get(self.host_id) is self
        if was_current:
            sources.pop(self.host_id, None)
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(AgentGone())
        self._pending.clear()
        for fs in list(self.forwards.values()):   # tunelurile cad odată cu agentul
            fs.tunnel_lost = True                  # cădere de agent, nu de țintă → reconectabil
            fs._eof()
        self.forwards.clear()
        for task in self._tasks:
            task.cancel()
        if was_current:
            for hub in hubs.values():
                if hub.host_id == self.host_id:
                    hub.on_detached()

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def schedule_reconcile(self, msg: dict) -> None:
        """Serializează + coalescează reconcile pe conexiune. reconcile() e declanșat
        la FIECARE hello/heartbeat; două rulând concurent fac read-modify-write pe
        aceleași rânduri de sesiune (adopție dublă → INSERT duplicat, mark_lost /
        ensure_attached în cursă). Rulăm cel mult unul odată; dacă sosesc mai multe
        cât timp unul rulează, păstrăm doar ULTIMUL (starea agentului e cumulativă —
        heartbeat-ul nou o înlocuiește complet pe cel vechi), dar reținem dacă vreunul
        a fost 'hello', ca declanșarea upgrade-ului să nu se piardă. Sigur în asyncio
        single-thread: între verificarea buclei și resetarea flag-ului nu există await."""
        self._reconcile_latest = msg
        if msg.get("event") == "hello":
            self._reconcile_saw_hello = True
        if not self._reconcile_running:
            self._reconcile_running = True
            self._spawn(self._reconcile_runner())

    async def _reconcile_runner(self) -> None:
        try:
            while self._reconcile_latest is not None:
                msg = self._reconcile_latest
                self._reconcile_latest = None
                if self._reconcile_saw_hello:
                    self._reconcile_saw_hello = False
                    msg = dict(msg, event="hello")   # nu pierde declanșarea upgrade-ului
                try:
                    await reconcile(self, msg)
                except Exception:
                    # Un raport malformat de la agent (câmp lipsă, tip greşit) ridica aici, iar
                    # `maybe_upgrade_agent` — ULTIMA linie din `reconcile` — nu mai rula. Un host
                    # compromis îşi putea VETA propriile actualizări la nesfârşit, rămânând verde
                    # în UI: online, heartbeat proaspăt, `update_blocked=None`, zero evenimente.
                    # Singura urmă era o linie în `docker logs`. Deci: raportăm vizibil ŞI
                    # împingem update-ul oricum, fiindcă el nu depinde de starea sesiunilor.
                    log.exception("reconcile failed for host %s", self.host_id)
                    try:
                        await record_agent_event(self.host_id, "reconcile_failed",
                                                 detail="invalid session report from the agent")
                    except Exception:         # noqa: BLE001
                        pass
                    if msg.get("event") == "hello":
                        try:
                            await maybe_upgrade_agent(self)
                        except Exception:     # noqa: BLE001
                            log.exception("the post-reconcile upgrade failed, host %s", self.host_id)
        finally:
            self._reconcile_running = False

    async def _on_ctrl(self, msg: dict) -> None:
        """Dispatch a control message. Anything that awaits a request back to
        the agent MUST run as a separate task: awaiting it here would deadlock,
        because this receive loop is what delivers the response."""
        if "id" in msg and "op" not in msg:
            fut = self._pending.get(msg["id"])
            if fut and not fut.done():
                fut.set_result(msg)
            return
        event = msg.get("event")
        if event == "fwd_close":               # ținta a închis tunelul din partea agentului
            fs = self.forwards.pop(msg.get("stream"), None)
            if fs:
                fs._eof()
            return
        if event in ("hello", "heartbeat"):
            seq = msg.get("hb_seq")
            if seq is not None:
                await self.send_ctrl({"type": "hb_ack", "seq": seq})   # confirmă → agentul măsoară RTT + detectează half-open
            # health de link raportat de agent (pentru panoul Diagnostic)
            self.link = {"uptime": msg.get("uptime"), "reconnects": msg.get("reconnects"),
                         "rtt_ms": msg.get("rtt_ms")}
            if event == "hello" and not self._connect_logged:
                self._connect_logged = True   # jurnal: connect cu versiunea raportată la hello
                v = msg.get("agent_version")
                await record_agent_event(self.host_id, "connect", detail=("v%s" % v) if v else "")
            self.schedule_reconcile(msg)
        elif event == "exit":
            hub = hubs.get(msg.get("sid", ""))
            if hub and hub.host_id == self.host_id:   # doar sesiunile host-ului său
                self._spawn(hub.on_exit(msg.get("status"), msg.get("signal")))
        elif event == "replay_end":
            hub = hubs.get(msg.get("sid", ""))
            if hub and hub.host_id == self.host_id:
                hub.on_replay_end()


# ---------------------------------------------------------------------------
# Reconciliation: agent report (hello/heartbeat) vs DB
# ---------------------------------------------------------------------------

_agent_cache = {"source": None, "version": None, "mtime": None}


def agent_expected() -> dict:
    """Agent source + version shipped with this gateway (cached by mtime)."""
    try:
        mtime = config.AGENT_FILE.stat().st_mtime
        if _agent_cache["mtime"] != mtime:
            source = config.AGENT_FILE.read_text()
            match = re.search(r"^AGENT_VERSION = (\d+)", source, re.M)
            try:
                sig = Path(str(config.AGENT_FILE) + ".sig").read_text().strip()
            except OSError:
                sig = None
            _agent_cache.update(source=source, mtime=mtime, sig=sig,
                                version=int(match.group(1)) if match else None)
    except OSError:
        pass
    return _agent_cache


def agent_install_source() -> str:
    """Sursa `ptyd.py` servită la INSTALARE (GET /agent/ptyd.py). Cu o cheie de deployment,
    substituie `UPDATE_PUBKEY` cu pubkey-ul ei (disponibil chiar dacă privata e blocată → înrolarea
    de agenți noi merge; doar auto-update-ul cere deblocare). Fără cheie → sursa brută = canalul
    oficial semnat de mentainer. Fail-closed: dacă substituția nu potrivește, ridică (nu servim
    o sursă cu cheie greșită)."""
    src = agent_expected().get("source")
    if src is None:
        raise RuntimeError("agent source missing on gateway")
    pub = signing.pubkey_hex()
    if pub:
        return signing.substitute_pubkey(src.encode(), pub).decode()
    return src


def _agent_update_payload(expected: dict):
    """(content_b64, sig_b64) pentru push-ul de update. Cu cheie de deployment DEBLOCATĂ →
    substituie + re-semnează cu ea. Fără cheie → sursa repo + semnătura mentainerului (canalul
    oficial). Întoarce None dacă nu putem servi un update SEMNAT (cheie blocată, sau sig repo lipsă)."""
    src_bytes = expected["source"].encode()
    if signing.key_exists():
        if not signing.is_loaded():
            return None                      # cheie de deployment blocată → pauză auto-update
        try:
            sub, sig_b64 = signing.sign_agent(src_bytes)
        except (ValueError, RuntimeError) as e:
            # Re-semnarea înseamnă substituirea `UPDATE_PUBKEY` în sursa NOUĂ de agent, iar
            # substituţia e fail-closed: dacă linia şi-a schimbat forma într-o versiune nouă,
            # ridică. Fără prinderea asta, excepţia urca în handler-ul de `hello` al agentului
            # — adică o refactorizare a lui ptyd.py ar fi rupt conectarea agenţilor la TOATE
            # instanţele cu cheie proprie, nu doar auto-update-ul lor.
            log.error("cannot re-sign the agent with the deployment key: %s "
                      "(does the new source have a substitutable UPDATE_PUBKEY?) — auto-update stopped", e)
            return None
        return base64.b64encode(sub).decode(), sig_b64
    if not expected.get("sig"):
        return None                          # canal oficial fără semnătură → nu împingem nesemnat
    return base64.b64encode(src_bytes).decode(), expected["sig"]


def _refusal_hint(code: str) -> str:
    """Traduce codul de refuz în ce trebuie să facă omul — un cod fără remediu e zgomot."""
    if "unsigned" in code or "signature" in code:
        return ("the agent has a different public key embedded (it was enrolled before the "
                "deployment key was generated) — reinstall the agent on that host")
    if "downgrade" in code:
        return "the gateway is serving an OLDER version than the one on the host (anti-rollback)"
    return "see ~/.webterm/ptyd.log on the host"


async def maybe_upgrade_agent(conn: AgentConnection) -> None:
    expected = agent_expected()
    if not expected["version"] or conn.agent_version is None:
        return
    if conn.agent_version >= expected["version"]:
        # agentul e la zi → orice motiv de blocare vechi e caduc; altfel rămâne lipicios în DB
        if update_blocked.pop(conn.host_id, None) is not None or True:
            await db.execute(
                "UPDATE hosts SET update_blocked=NULL WHERE id=? AND update_blocked IS NOT NULL",
                conn.host_id)
        return
    payload = _agent_update_payload(expected)
    if payload is None:
        if signing.key_exists() and not signing.is_loaded():
            log.info("host %s: an update is available but the fleet signing key is LOCKED — "
                     "unlock it in the UI so agents can update", conn.host_id)
        else:
            log.error("host %s: update available but agent/ptyd.py.sig is missing — "
                      "refusing to push an unsigned update (run scripts/sign-agent.py)",
                      conn.host_id)
            # Cod stabil, nu propoziţie: agentul trimite deja coduri (`update_unsigned`,
            # `update_downgrade`, `update_badcode`), dar aici scriam engleză curgătoare, iar
            # clientul alegea sfatul potrivit cu un regex peste ea. Acelaşi tipar a rupt deja
            # dezinstalarea şi recuperarea unui host offline: un text care se traduce mută
            # decizia sub picioarele codului care îl citeşte.
            await db.execute("UPDATE hosts SET update_blocked=? WHERE id=?",
                             "signature_missing", conn.host_id)
            email_alerts.notify_update_refused(
                conn.host_id, "signature missing",
                "the image has no agent/ptyd.py.sig — the gateway refuses (correctly) to push "
                "unsigned code; use an official image or sign it with scripts/sign-agent.py")
        return
    content_b64, sig_b64 = payload
    log.info("host %s: agent v%s < v%s, pushing signed update",
             conn.host_id, conn.agent_version, expected["version"])
    await record_agent_event(conn.host_id, "update_pushed",
                             detail="v%s → v%s" % (conn.agent_version, expected["version"]))
    try:
        resp = await conn.request("update", content_b64=content_b64, sig_b64=sig_b64)
        if not resp.get("ok") and not resp.get("deferred"):
            # Refuz explicit al agentului. NU-l înghiţim: fără semnal, flota rămâne pe o
            # versiune veche şi nimeni nu află de ce.
            code = resp.get("code") or resp.get("msg") or "necunoscut"
            code = _clip(str(code), 200) or "unknown"   # şir de la agent: mărginit ca restul
            update_blocked[conn.host_id] = code
            await db.execute("UPDATE hosts SET update_blocked=? WHERE id=?",
                             str(code), conn.host_id)
            log.error("host %s: the agent REFUSED the update (%s)", conn.host_id, code)
            await record_agent_event(conn.host_id, "update_refused", reason=str(code),
                                     detail=_refusal_hint(str(code)))
            email_alerts.notify_update_refused(conn.host_id, code, _refusal_hint(str(code)))
            return
        # NECONDIŢIONAT, nu gardat de dict-ul din memorie: orice upgrade reporneşte
        # gateway-ul, deci dict-ul e garantat gol exact când fix-ul ajunge la agent. Gardat,
        # motivul rămânea în DB pe viaţă, iar UI-ul şi upgrade.sh raportau „update blocat"
        # după ce problema fusese rezolvată. Semnalat independent de doi auditori.
        update_blocked.pop(conn.host_id, None)
        await db.execute("UPDATE hosts SET update_blocked=NULL WHERE id=?", conn.host_id)
        if resp.get("deferred"):
            pending_updates[conn.host_id] = True
            log.info("host %s: update deferred until sessions end", conn.host_id)
            await record_agent_event(conn.host_id, "update_deferred",
                                     detail="applied when the sessions close")
    except (AgentGone, asyncio.TimeoutError):
        pass


async def force_update_agent(host_id: int) -> dict:
    """User-requested update/restart: the agent re-execs immediately; tmux
    sessions survive and are re-adopted by the new process. Returns whether
    the agent applied it now or deferred (old agents that ignore `force`)."""
    conn = sources.get(host_id)
    if not isinstance(conn, AgentConnection):
        raise AgentGone("host offline")
    expected = agent_expected()
    if not expected["source"]:
        raise RuntimeError("agent source missing on gateway")
    # H2: aceeași cale ca auto-update-ul — substituie UPDATE_PUBKEY + re-semnează cu cheia
    # de deployment. Vechiul cod trimitea sursa+semnătura mentainerului, pe care un agent cu
    # cheie proprie o RESPINGE, iar gateway-ul raporta fals succes (fals-asigurare că un fix
    # de securitate a fost livrat).
    payload = _agent_update_payload(expected)
    if payload is None:
        if signing.key_exists() and not signing.is_loaded():
            raise RuntimeError("the fleet signing key is LOCKED — unlock it from "
                               "Settings → Security to update agents")
        raise RuntimeError("agent/ptyd.py.sig missing — run scripts/sign-agent.py")
    content_b64, sig_b64 = payload
    resp = await conn.request("update", force=True, content_b64=content_b64, sig_b64=sig_b64)
    # agentul poate refuza (semnătură/versiune) — NU raporta succes fals
    if not resp.get("ok"):
        # Calea AUTOMATĂ înregistra refuzul (DB + eveniment + alertă + remediu); calea asta —
        # butonul din UI — arunca doar codul brut şi nu marca hostul. Efectul: „update_unsigned"
        # fără nicio indicaţie ce să faci, iar lista de hosturi rămânea curată, deci problema
        # devenea invizibilă imediat ce închideai dialogul. Ambele căi trebuie să lase aceeaşi urmă.
        code = str(resp.get("code") or resp.get("msg") or "necunoscut")
        hint = _refusal_hint(code)
        update_blocked[host_id] = code
        await db.execute("UPDATE hosts SET update_blocked=? WHERE id=?", code, host_id)
        await record_agent_event(host_id, "update_refused", reason=code, detail=hint)
        raise RuntimeError("the agent refused the update (%s)%s" % (code, " — " + hint if hint else ""))
    deferred = bool(resp.get("deferred"))
    if not deferred:
        pending_updates.pop(host_id, None)
    update_blocked.pop(host_id, None)
    await db.execute("UPDATE hosts SET update_blocked=NULL WHERE id=?", host_id)
    return {"deferred": deferred, "agent_version": conn.agent_version}


def _clip(v, limit: int = 255):
    """Şir raportat de agent, mărginit. `None` rămâne `None` (COALESCE păstrează valoarea)."""
    return v[:limit] if isinstance(v, str) else None


async def reconcile(conn: AgentConnection, msg: dict) -> None:
    conn.epoch = msg.get("epoch")
    conn.backend = msg.get("backend")
    conn.agent_version = msg.get("agent_version")
    if msg.get("metrics"):
        # Mărginit: agentul trimite şase numere, dar un host compromis poate trimite orice, iar
        # dicţionarul ăsta ajunge în FIECARE răspuns de host-detail către browser. Păstrăm doar
        # cheile pe care le înţelegem şi doar dacă sunt numere — restul se aruncă tăcut.
        # Listă ALBĂ, plafon de număr şi doar valori finite. Varianta dinainte spunea în
        # comentariu „doar cheile pe care le înţelegem", dar accepta orice cheie ≤32 de
        # caractere cu valoare numerică: 50 000 de chei treceau, ~819 KB, în fiecare răspuns de
        # host-detail. Iar `json.loads` acceptă literalul `Infinity` de pe fir, în timp ce
        # `JSONResponse` refuză să-l serializeze — deci un agent care trimite `inf` transforma
        # `GET /api/hosts/{id}` în 500 până când se cuminţea. Un host compromis nu trebuie să
        # poată strica pagina hostului.
        raw = msg["metrics"] if isinstance(msg.get("metrics"), dict) else {}
        conn.metrics = {
            k: v for k, v in list(raw.items())[:64]
            if k in METRIC_KEYS and isinstance(v, (int, float))
            and not isinstance(v, bool) and math.isfinite(v)}
        # alerte pe praguri (CPU/RAM/disc) — evaluare la fiecare heartbeat;
        # trimiterea e best-effort și throttled în email_alerts. Pragurile sunt
        # cache-uite, iar numele hostului e memoizat pe conn → zero query-uri DB
        # pe calea fierbinte (un agent compromis nu mai poate amplifica floodul).
        try:
            thresholds = await email_alerts.load_thresholds()
            if conn.host_name is None:
                row = await db.fetchone("SELECT name FROM hosts WHERE id=?", conn.host_id)
                conn.host_name = row["name"] if row else str(conn.host_id)
            email_alerts.check_metrics(conn.host_id, conn.host_name, conn.metrics, thresholds)
        except Exception as e:                       # nicio alertă nu merită un heartbeat pierdut
            log.debug("threshold check failed for host %s: %s", conn.host_id, e)
    expected_v = agent_expected()["version"]
    if expected_v and (conn.agent_version or 0) >= expected_v:
        pending_updates.pop(conn.host_id, None)
    await db.execute(
        "UPDATE hosts SET agent_version=?, backend=?, last_heartbeat=?,"
        " hostname=COALESCE(?, hostname), agent_user=COALESCE(?, agent_user)"
        " WHERE id=?",
        conn.agent_version, conn.backend, time.time(),
        # tăiate: se scriu în `hosts` şi se întorc la fiecare listare; un agent compromis
        # putea umfla rândul şi fiecare răspuns cu şiruri de orice lungime
        _clip(msg.get("hostname")), _clip(msg.get("user")), conn.host_id)

    reported = {s["sid"]: s for s in msg.get("sessions", [])}
    # includem și 'lost': o sesiune tmux SUPRAVIEȚUIEȘTE restartului de agent, deci
    # una marcată 'lost' (agent picat / reaper) trebuie readusă la 'live' dacă agentul
    # o re-adoptă (o raportează vie). Fără asta ar rămâne 'lost' permanent, deși e vie.
    # ATENŢIE la `kind`: agentul raportează DOAR sesiunile lui de shell (pty/tmux). Sesiunile
    # bastion-telnet şi seriale trăiesc pe GATEWAY, în `session_sources` — nu apar niciodată în
    # lista lui. Fără filtrul ăsta, primul heartbeat le marca `lost („gone_from_agent")` şi le
    # dărâma hub-ul, deşi erau vii: adică bastionul telnet şi consola serială se rupeau singure
    # în ≤30s de la deschidere. `sweep_stale_sessions` şi `reconcile_telnet_on_start` filtrau
    # corect; doar aici lipsea. Prins prin rulare de auditul intern (2026-08-06).
    rows = await db.fetchall(
        "SELECT * FROM sessions WHERE host_id=? AND state IN ('creating','live','lost')"
        " AND (kind IS NULL OR kind='shell')",
        conn.host_id)

    for row in rows:
        info = reported.pop(row["id"], None)
        if info is None:
            if row["state"] == "live":
                hub = get_or_create_hub(row)
                await hub.mark_lost("gone_from_agent")
            elif row["state"] == "creating" and time.time() - (row["created"] or 0) > 60:
                # 'creating' vechi pe care agentul nu-l raportează = create eșuat/pierdut
                # (ex. restart de gateway fix în timpul create). Fără asta rămânea fantomă
                # permanentă, neștergibilă (delete refuză cu 409). Îl închidem.
                await db.execute(
                    "UPDATE sessions SET state='closed', closed_at=?, close_reason='create-failed'"
                    " WHERE id=?", time.time(), row["id"])
            # 'lost' neraportat: rămâne (reconectabil / reaper)
            continue
        # `alive` ABSENT nu înseamnă „a murit". `info["alive"]` ridica KeyError pe un raport
        # malformat; înlocuirea cu `.get()` a făcut ca lipsa câmpului să dea `None`, adică falsy,
        # adică exact ramura de închidere: `on_exit` + `reap`, care omoară şi sesiunea tmux REALĂ
        # de pe host. Un câmp lipsă dintr-un mesaj trunchiat sau dintr-un drift de protocol
        # devenea o comandă de închidere. Toleranţa mutase problema din „excepţie" în „pierdere
        # tăcută de date". Absent = nu ştim = nu atingem nimic.
        alive = info.get("alive")
        if alive is None:
            continue
        if not alive:
            hub = get_or_create_hub(row)
            # drain any output still in the agent ring, then close
            await hub.ensure_attached(conn)
            await hub.wait_replay_end()
            await hub.on_exit(info.get("exit_status"), info.get("exit_signal"))
            continue
        if row["state"] in ("creating", "lost"):
            # 're-adoptată': readu-o la viață (curăță și motivul de închidere)
            await db.execute(
                "UPDATE sessions SET state='live', closed_at=NULL, close_reason=NULL,"
                " exit_status=NULL WHERE id=?", row["id"])
        hub = get_or_create_hub(row)
        await hub.ensure_attached(conn)

    # sessions living on the agent that the DB does not know (e.g. gateway DB
    # reset, or tmux sessions surviving a host-side mishap): adopt them
    # Plafon la ADOPŢIE, nu doar la creare. Comentariul de la `MAX_SESSIONS_HINT` spunea că
    # limita „e impusă de agent, nu e sursa de adevăr" — exact garanţia pe care un agent
    # COMPROMIS o ignoră. Un singur heartbeat cu 3000 de sid-uri uuid4 valide producea 3000 de
    # rânduri în DB şi 6000 de fişiere deschise (`.out` + `.cast` se creează în
    # `SessionHub.__init__`, înainte de orice octet de output), repetabil la fiecare heartbeat
    # cu sid-uri noi, până se umple discul. Rezultatul nu e „hostul ăla e stricat", ci gateway
    # jos şi toată flota inaccesibilă — cel mai bun raport efort/pagubă pe care îl are un host
    # compromis. Reprodus de un audit extern.
    adopted_room = MAX_SESSIONS_HINT - (await db.fetchone(
        "SELECT COUNT(*) AS c FROM sessions WHERE host_id=? AND state IN ('live','creating')",
        conn.host_id))["c"]
    refused = 0
    # Sid-urile pe care le ştim deja, într-o singură interogare. Înainte era un
    # `SELECT ... WHERE id=?` per sesiune raportată, adică N round-trip-uri la DB pentru un
    # agent care raportează N sesiuni — exact pârghia pe care o are un host compromis.
    # Doar ale HOSTULUI ăstuia. `SELECT id FROM sessions` încărca fiecare sesiune din instanţă
    # la fiecare heartbeat al fiecărui host, iar rândurile se păstrează pentru totdeauna
    # („istoricul e util") — deci setul creştea nemărginit pe viaţa instalării. Reparând N
    # round-trip-uri, introdusesem un scan complet de tabel. Sid-urile sunt uuid4, deci o
    # sesiune a altui host n-are cum să se potrivească.
    known = {r["id"] for r in await db.fetchall(
        "SELECT id FROM sessions WHERE host_id=?", conn.host_id)}
    for sid, info in reported.items():
        # a malicious agent could report a crafted sid; only adopt real ones
        # (uuid4 hex) so it can never become a filesystem path outside the dir
        if not valid_sid(sid):
            continue
        # Aceeaşi grijă la adopţie: un raport fără `alive` nu justifică nici adoptarea, nici
        # un `reap`. Aici `info["alive"]` ridica KeyError şi rupea tot ciclul de reconciliere.
        if info.get("alive") is None:
            continue
        if not info["alive"]:
            try:
                await conn.request("reap", sid=sid)
            except (AgentGone, asyncio.TimeoutError):
                pass
            continue
        if sid in known:
            continue  # belongs to another state; leave alone
        # Plafonul se aplică DOAR sesiunilor cu adevărat noi. Verificarea stătea înaintea celei
        # de existenţă, ca să nu plătim o interogare pentru fiecare din cele 3000 de sid-uri ale
        # unui agent ostil — dar aşa o sesiune pe care o ştiam deja se număra drept „refuzată",
        # iar un host legitim ajuns la plafon ar fi produs alerte false la fiecare heartbeat.
        # `known` rezolvă ambele: o singură interogare în loc de N, şi ordinea corectă.
        if adopted_room <= 0:
            refused += 1
            continue
        adopted_room -= 1
        await db.execute(
            "INSERT INTO sessions(id, host_id, title, state, created, rows, cols)"
            " VALUES(?,?,?,?,?,?,?)",
            sid, conn.host_id, "Adopted session", "live",
            info.get("created", time.time()), info.get("rows", 24), info.get("cols", 80))
        row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
        hub = get_or_create_hub(row)
        await hub.ensure_attached(conn)

    if refused:
        # Vizibil, nu tăcut: un agent care raportează mai multe sesiuni decât poate avea ori e
        # stricat, ori minte. În ambele cazuri operatorul trebuie să afle, iar `agent_events`
        # e locul unde se uită deja când un host se poartă ciudat.
        log.warning("host %s reported %d sessions over the cap of %d — refused to adopt them",
                    conn.host_id, refused, MAX_SESSIONS_HINT)
        await record_agent_event(conn.host_id, "adoption_refused",
                                 reason="over session cap",
                                 detail="%d session(s) beyond %d" % (refused, MAX_SESSIONS_HINT))

    if msg.get("event") == "hello":
        await maybe_upgrade_agent(conn)


# ---------------------------------------------------------------------------
# Reconciliere de liveness: starea DB ('live') trebuie să corespundă realității
# backendului (agent/telnet viu). Fără asta, sesiuni fantomă rămân 'live' la infinit
# (telnet după restart de gateway, shell de pe hosturi care nu mai revin) — vezi
# docs/design/SESSION-LIFECYCLE.md.
# ---------------------------------------------------------------------------
SESSION_STALE_AFTER = 2 * config.HEARTBEAT_STALE   # host mut atâta (180s) → offline


async def reconcile_telnet_on_start() -> None:
    """La pornirea gateway-ului: sursele care trăiesc DOAR în memoria gateway-ului nu
    supraviețuiesc restartului → orice sesiune 'live'/'creating' pe ele e o fantomă → 'lost'
    (reconectabilă). Acoperă:
      - telnet-bastion (kind='telnet', ForwardTelnetSource);
      - hosturi DIRECTE SSH/telnet (connection_type ssh/telnet, SshSource/TelnetSource în
        `sources`) — socketul lor moare cu procesul vechi.
    Sesiunile de AGENT (connection_type='agent') NU se ating: tmux le supraviețuiește, iar
    reconcile() le readuce 'live' când agentul reconectează. Fără asta, sesiunile directe
    rămâneau 'live' fantomă la infinit (sweep-ul periodic nu le reapează — corect, sunt
    re-dial-abile —, dar la startup sursa lor sigur a dispărut)."""
    q = ("state IN ('live','creating') AND (kind='telnet' OR host_id IN"
         " (SELECT id FROM hosts WHERE connection_type IN ('ssh','telnet')))")
    ghosts = await db.fetchall("SELECT id FROM sessions WHERE " + q)
    if not ghosts:
        return
    await db.execute(
        "UPDATE sessions SET state='lost', close_reason='gateway-restart', closed_at=?"
        " WHERE " + q, time.time())
    log.info("startup: %d ephemeral sessions (telnet/SSH/direct telnet) 'live' → 'lost'"
             " (they do not survive a restart)", len(ghosts))


async def _reap_ghost(sid: str, reason: str) -> None:
    """Marchează o sesiune fantomă 'lost' — prin hub dacă are clienți conectați
    (îi notifică), altfel direct în DB."""
    hub = hubs.get(sid)
    if hub:
        await hub.mark_lost(reason)
    else:
        await db.execute(
            "UPDATE sessions SET state='lost', close_reason=?, closed_at=? WHERE id=?",
            reason, time.time(), sid)
    log.info("reaper: session %s → 'lost' (%s)", sid, reason)


async def sweep_hosts_offline() -> None:
    """Alertează când un host care raporta a tăcut, şi când revine. Rulat din reaper.

    Aveam alerte pentru lockout, relocare de agent, IP schimbat şi praguri de resurse, dar
    nu şi pentru evenimentul cel mai banal dintr-o flotă: „agentul nu mai răspunde". Semnalat
    de auditul extern (2026-08-06). Sursa de adevăr e `last_heartbeat`, nu prezenţa unui
    obiect în RAM: gateway-ul tocmai repornit n-are conexiuni, dar hosturile sunt vii."""
    now = time.time()
    try:
        rows = await db.fetchall(
            "SELECT id, name, last_heartbeat FROM hosts WHERE connection_type='agent'")
    except Exception:                       # noqa: BLE001 — observabilitatea nu rupe reaper-ul
        return
    for row in rows:
        hb = row["last_heartbeat"] or 0
        if not hb:
            continue                        # niciodată conectat: nu e o cădere, e o neînrolare
        silent = now - hb
        if silent > config.HEARTBEAT_STALE:
            email_alerts.notify_host_offline(row["id"], row["name"], silent)
        else:
            email_alerts.notify_host_online(row["id"], row["name"])


async def sweep_stale_sessions() -> None:
    """Reaper periodic (main._session_reaper). Marchează 'lost' sesiunile 'live' fără
    backend viu:
      - telnet: fără sursă în `session_sources` (pump-ul a murit) → lost
      - shell:  fără AgentConnection vie ȘI host mut de > SESSION_STALE_AFTER → lost
    Sesiunile SERVITE activ (au sursă / host online) nu se ating — `reconcile()` se
    ocupă de moartea tmux când agentul e conectat. Marcarea nu e permanentă dacă a fost
    greșită: `reconcile()` readuce 'lost'→'live' când agentul re-adoptă sesiunea."""
    now = time.time()
    rows = await db.fetchall(
        "SELECT s.id, s.host_id, s.kind, h.last_heartbeat, h.connection_type "
        "FROM sessions s LEFT JOIN hosts h ON h.id=s.host_id "
        "WHERE s.state IN ('live','creating')")
    for row in rows:
        sid, kind = row["id"], (row["kind"] or "shell")
        if kind == "telnet":
            if session_sources.get(sid) is None:
                await _reap_ghost(sid, "telnet-dead")
            continue
        # sursă vie de ORICE tip (agent / SSH direct / telnet direct) = sesiune servită
        # activ → nu o atinge. BUG reparat: verificarea veche `isinstance(...,
        # AgentConnection)` omora sesiunile directe SSH/Telnet vii (SshSource/TelnetSource
        # nu sunt AgentConnection, iar hosturile lor n-au niciodată `last_heartbeat`).
        if source_for(row["host_id"]) is not None:
            continue
        # fără sursă vie: doar hosturile de AGENT au heartbeat semnificativ; le reapăm
        # când e stale. Hosturile SSH/telnet DIRECTE n-au heartbeat și se re-dial-uiesc
        # la reconectarea browserului (api.py) — NU le reapăm pe absența sursei.
        if (row["connection_type"] or "agent") == "agent":
            hb = row["last_heartbeat"] or 0
            if now - hb > SESSION_STALE_AFTER:
                await _reap_ghost(sid, "host-offline")


async def sweep_idle_locks() -> None:
    """Blochează sesiunile cu idle-lock activ (host require_2fa) care n-au primit input
    de operator de peste `lock_idle` secunde. Rulat periodic din main._idle_lock_sweep.
    Blochează chiar fără clienți conectați — starea e corectă când (re)apare unul."""
    now = time.time()
    for hub in list(hubs.values()):
        if hub.lock_idle and not hub.locked and now - hub.last_interaction > hub.lock_idle:
            await hub.lock()


async def register_agent(ws, host_id: int) -> AgentConnection:
    old = sources.get(host_id)
    if old:
        replacements.setdefault(host_id, []).append(time.time())
        old._stop_reason = "superseded"        # jurnal: deconectat fiindcă a reconectat un agent nou
        if host_conflict(host_id):
            log.warning("host %s: repeated agent replacements — two machines "
                        "are probably enrolled with the same host token", host_id)
            await record_agent_event(host_id, "conflict",
                                     detail="repeated agent replacements (shared token?)")
        await old.disconnect()
    conn = AgentConnection(ws, host_id)
    sources[host_id] = conn
    return conn


# ---------------------------------------------------------------------------
# Session operations used by the REST API
# ---------------------------------------------------------------------------

# ANSI/control sequences stripped when searching transcript text
ANSI_RE = re.compile(
    rb"\x1b(?:\[[0-9;?<=>]*[a-zA-Z@`~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[PX^_][^\x1b]*\x1b\\"
    # secvenţe de 3 octeţi: desemnare de set de caractere `ESC ( B` (tmux o emite des) şi
    # SS3 `ESC O <literă>`. Fără ele, ramura generică `.` mânca doar 2 octeţi şi lăsa
    # litera în text — de-aia apăreau „B"-uri lipite de cuvinte („re-semneazăBRulează").
    rb"|[()*+][A-Za-z0-9]|O[A-Za-z]|.)"
)
# mişcări de cursor pe VERTICALĂ: o aplicaţie pe tot ecranul nu emite „\n", ci sare cu
# cursorul. Convertindu-le în linii noi, textul rezultat păstrează structura vizuală în
# loc să lipească tot într-un şir continuu.
CURSOR_MOVE_RE = re.compile(rb"\x1b\[[0-9;]*[HfABEFd]")
# mişcare pe ORIZONTALĂ: aplicaţiile aliniază coloane sărind cu cursorul, nu cu spaţii.
# Ştergând-o pur şi simplu, cuvintele se lipeau („key.pempython3scripts/..."), deci o
# redăm ca spaţii — câte coloane a sărit, plafonat ca o valoare absurdă să nu umfle textul.
CURSOR_FWD_RE = re.compile(rb"\x1b\[([0-9]*)C")
SEARCH_READ_CAP = 4 * 1024 * 1024      # max bytes read per transcript


def transcript_text(sid: str, tail_bytes: int = 0) -> str:
    """Transcriptul ca TEXT citibil: fără secvenţe de control, cu CR şi backspace aplicate.

    De ce există: redarea brută a unei sesiuni închise funcţionează pentru un shell, dar nu
    pentru aplicaţii pe tot ecranul (Claude Code, vim, htop) — acelea REPICTEAZĂ acelaşi ecran
    cu poziţionare de cursor, deci sute de KB de redesenări se prăbuşesc într-un singur ecran
    şi pare că „nu există istoric". Aici scoatem ce s-a scris efectiv, în ordine.

    `tail_bytes` > 0 → citim doar coada fişierului (pentru vizualizarea din UI); 0 = tot.
    """
    out_path, _ = transcript_paths(sid)
    try:
        size = out_path.stat().st_size
        with open(out_path, "rb") as f:
            if tail_bytes and size > tail_bytes:
                f.seek(size - tail_bytes)
            raw = f.read()
    except OSError:
        return ""
    raw = CURSOR_FWD_RE.sub(lambda m: b" " * min(int(m.group(1) or 1), 200), raw)
    raw = CURSOR_MOVE_RE.sub(b"\n", raw)
    raw = ANSI_RE.sub(b"", raw).replace(b"\r\n", b"\n")
    out = []
    for line in raw.split(b"\n"):
        # CR = „scrie peste linia curentă" (bare de progres, prompturi rescrise): păstrăm
        # ce a rămas vizibil la final, nu concatenarea tuturor versiunilor
        line = line.split(b"\r")[-1]
        if b"\x08" in line:                     # backspace: ştergem caracterul dinainte
            buf = bytearray()
            for ch in line:
                if ch == 0x08:
                    if buf:
                        buf.pop()
                else:
                    buf.append(ch)
            line = bytes(buf)
        out.append(line.decode("utf-8", "replace").rstrip())
    # comprimăm rafalele de linii goale lăsate de redesenări, dar păstrăm o separare
    text, blanks = [], 0
    for line in out:
        if line:
            blanks = 0
            text.append(line)
        elif blanks == 0:
            blanks = 1
            text.append("")
    return "\n".join(text)
SEARCH_TOTAL_CAP = 128 * 1024 * 1024   # max bytes read across ALL transcripts per query
SEARCH_MAX_RESULTS = 20


def search_transcripts(rows, query: str):
    """Runs in a thread: scan session metadata + transcript files for `query`.
    Returns [{id, title, host_id, state, created, snippet, matches}]."""
    needle = query.lower().encode("utf-8", errors="ignore")
    results = []
    total_read = 0
    for row in rows:
        meta_hit = (query.lower() in (row["title"] or "").lower()
                    or query.lower() in (row["note"] or "").lower())
        snippet, count = "", 0
        out_path, _ = transcript_paths(row["id"])
        try:
            size = out_path.stat().st_size
            # bound total I/O per query: past the budget, only meta (title/note)
            # is searched so one query can't read gigabytes on the thread pool
            if total_read >= SEARCH_TOTAL_CAP:
                raise OSError("search budget exhausted")
            with open(out_path, "rb") as f:
                if size > SEARCH_READ_CAP:
                    f.seek(size - SEARCH_READ_CAP)
                chunk = f.read()
                total_read += len(chunk)
                text = ANSI_RE.sub(b"", chunk)
            lower = text.lower()
            pos = lower.find(needle)
            if pos >= 0:
                count = lower.count(needle)
                start = max(0, pos - 60)
                raw = text[start:pos + len(needle) + 60]
                snippet = raw.decode("utf-8", errors="replace")
                snippet = "".join(c if c.isprintable() or c == " " else " " for c in snippet)
                snippet = " ".join(snippet.split())
        except OSError:
            pass
        if meta_hit or count:
            results.append({
                "id": row["id"], "title": row["title"], "host_id": row["host_id"],
                "state": row["state"], "created": row["created"],
                "snippet": snippet, "matches": count,
            })
            if len(results) >= SEARCH_MAX_RESULTS:
                break
    return results


async def create_session(host_id: int, title: str, rows: int = 24, cols: int = 80,
                         tz: Optional[str] = None) -> dict:
    source = source_for(host_id)
    if source is None:
        raise AgentGone("host offline")
    sid = new_sid()
    await db.execute(
        "INSERT INTO sessions(id, host_id, title, state, created, rows, cols, agent_epoch)"
        " VALUES(?,?,?,?,?,?,?,?)",
        sid, host_id, title, "creating", time.time(), rows, cols, source.epoch)
    try:
        resp = await source.create(sid, rows, cols, "xterm-256color", tz)
    except Exception:
        # agentul a căzut / timeout FIX în timpul create → rândul rămânea 'creating'
        # pentru totdeauna (delete-ul îl refuză cu 409, reconcile/reaper îl sar). Curăță.
        await db.execute("DELETE FROM sessions WHERE id=?", sid)
        raise
    if not resp.get("ok"):
        await db.execute("DELETE FROM sessions WHERE id=?", sid)
        code = resp.get("code")
        # atingerea plafonului de sesiuni e o condiție NORMALĂ, nu o defecțiune:
        # semnalăm distinct ca API-ul să întoarcă 409 (nu 502 = „gateway crăpat")
        if code == "limit":
            raise SessionLimitReached("host at session limit")
        raise RuntimeError("agent refused: %s" % code)
    await db.execute("UPDATE sessions SET state='live' WHERE id=?", sid)
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    hub = get_or_create_hub(row)
    await hub.ensure_attached(source)
    return {"id": sid}


async def kill_session(sid: str) -> None:
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    if not row:
        raise KeyError(sid)
    source = session_sources.get(sid) or source_for(row["host_id"])
    # Starea `lost` înseamnă „gateway-ul a pierdut evidenţa, dar tmux-ul e probabil VIU pe host"
    # — adică exact cazul în care ai nevoie să opreşti sesiunea. Se ieşea tăcut cu `ok: true`:
    # utilizatorul credea că a terminat un shell (de regulă root), nu-l terminase, iar pe un host
    # cu 2FA făcea şi ceremonia passkey degeaba.
    if row["state"] not in ("live", "creating", "lost"):
        return                                  # deja închisă definitiv: nimic de oprit
    if source is None:
        raise AgentGone("host offline")
    await source.kill(sid)


# ---------------------------------------------------------------------------
# Telnet prin agent (bastion) — sursă PER-SESIUNE peste tunelul TCP al agentului
# ---------------------------------------------------------------------------

# Plafon separat de forward-urile web (cele 64 = MAX_FORWARDS pe agent): sesiunile
# telnet sunt interactive și long-lived, nu vrem ca ele să blocheze accesul web.
MAX_TELNET_SESSIONS = 32
MAX_SERIAL_SESSIONS = 16

# F3 — detecția ferestrei de parolă din output-ul device-ului. Login-ul telnet e
# in-band, deci parola tastată la promptul de parolă ar ajunge în transcript. Când
# device-ul cere parolă, intrăm în redactare până la submit (Enter). Heuristica e
# textuală (portabilă între Cisco/MikroTik/etc.): un prompt care se termină în
# „password:" / „passcode:" / „passphrase:" fără newline după el (așteaptă input).
# Semnal secundar posibil: device a trimis WONT ECHO (echo suprimat) — vezi
# TelnetShim.them_will_echo — dar textul e suficient și mai robust între device-uri.
_PW_PROMPT = re.compile(rb"(?i)(?:password|passcode|passphrase)\s*:?\s*$")


class ForwardTelnetSource(SessionSource):
    """O sesiune telnet către un device din LAN-ul host-ului, tunelată prin agent.
    Per-SESIUNE (nu per-host): deschide un `ForwardStream` prin `AgentConnection` și
    vorbește telnet peste el (shim IAC — vezi app/telnet.py). Bridge la hub prin
    `sid`, exact ca SshSource/TelnetSource. Fără PTY, fără persistență: dacă tunelul
    cade, sesiunea moare (raw TCP, stateful)."""
    backend = "telnet-fwd"

    def __init__(self, sid, host_id, agent_conn, target_host, target_port, rows, cols):
        self.sid = sid
        self.host_id = host_id
        self._agent = agent_conn
        self._thost = target_host
        self._tport = int(target_port)
        self.epoch = "tnf-" + uuid.uuid4().hex
        self._shim = telnet.TelnetShim(rows=rows, cols=cols)
        self._osc = telnet.OscFilter()   # F5: elimină OSC 133/52 de la device ne-de-încredere
        self._fs = None
        self._task = None
        self._closed = False
        # fereastra de redactare a parolei (Faza 3): setată de pump când device-ul
        # cere parolă; consultată de hub înainte de a scrie input în transcript.
        self.redact_input = False
        self._pw_tail = b""      # coada recentă de output, pt. prompt tăiat între recv-uri

    async def create(self, sid, rows, cols, term, tz=None) -> dict:
        try:
            self._fs = await self._agent.open_forward(self._thost, self._tport)
        except ForwardError as e:
            return {"ok": False, "code": "connect", "msg": str(e)}
        except AgentGone:
            return {"ok": False, "code": "offline", "msg": "host offline"}
        self._task = asyncio.create_task(self._pump(sid))
        return {"ok": True}

    async def _pump(self, sid) -> None:
        lost = False
        try:
            while True:
                chunk = await self._fs.read()
                if chunk is None:           # țintă a închis / tunel căzut → EOF
                    # a căzut AGENTUL (tunel), nu device-ul? atunci sesiunea e
                    # reconectabilă (`lost`), nu terminată (`exited`) — vezi reconnect
                    lost = bool(self._fs and self._fs.tunnel_lost)
                    break
                clean = self._shim.receive(chunk)
                resp = self._shim.drain()   # răspunsuri de protocol (IAC) către device
                if resp:
                    await self._fs.write(resp)
                if clean:
                    # F5: scoate OSC 133/52 (spoof de marcaje / clipboard) ÎNAINTE de
                    # transcript și browser — device-ul e ne-de-încredere.
                    clean = self._osc.filter(clean)
                if clean:
                    self._observe_output(clean)   # F3: intră în redactare la promptul de parolă
                    hub = hubs.get(sid)
                    if hub:
                        await hub.on_output(clean)
        except asyncio.CancelledError:
            raise
        except Exception:                   # noqa: BLE001 — orice eroare de transport = EOF
            pass
        finally:
            self._task = None
            self._closed = True
            # pop condiţional: dacă un reconnect a înlocuit deja sursa pentru acest sid, NU-l
            # şterge pe cel nou (altfel pump-ul vechi ar orfana sursa vie şi ar marca hub-ul pierdut).
            if session_sources.get(self.sid) is self:
                session_sources.pop(self.sid, None)
            hub = hubs.get(sid)
            if hub:
                # tunel căzut → `lost` (tab-ul păstrează butonul Reconectează);
                # device-ul a închis → `exited` (sesiune terminată normal)
                if lost:
                    await hub.mark_lost("agent-gone")
                else:
                    await hub.on_exit(0, None)

    async def attach(self, sid, from_offset) -> dict:
        return {"ok": True, "replay_start": from_offset or 0}

    def _observe_output(self, clean: bytes) -> None:
        """F3: pornește redactarea input-ului dacă device-ul afișează un prompt de
        parolă. Ținem o coadă scurtă ca promptul tăiat între două recv-uri să fie tot
        detectat. Un newline nou înseamnă că nu mai suntem la finalul unui prompt de
        parolă (device-ul a mers mai departe), deci ieșim din redactare."""
        self._pw_tail = (self._pw_tail + clean)[-80:]
        # ultima „linie" a output-ului (după ultimul newline) — acolo stă promptul
        line = self._pw_tail.rsplit(b"\n", 1)[-1].rsplit(b"\r", 1)[-1]
        if _PW_PROMPT.search(line):
            self.redact_input = True
        elif b"\n" in clean or b"\r" in clean:
            # output cu linie nouă care NU se termină în prompt de parolă → fereastra
            # s-a închis (ex. „Login incorrect", alt prompt). Fără asta, o redactare
            # rămasă din eroare ar putea persista.
            self.redact_input = False

    async def send_data(self, sid, data: bytes) -> None:
        # F3: submit-ul (Enter) închide fereastra de parolă. Enter-ul curent e tot
        # redactat de hub (l-a citit înainte de a ne chema pe noi), iar linia următoare
        # se înregistrează normal. Resetăm coada ca promptul consumat să nu re-declanșeze.
        if self.redact_input and (b"\r" in data or b"\n" in data):
            self.redact_input = False
            self._pw_tail = b""
        if self._fs and not self._closed:
            try:
                await self._fs.write(self._shim.send(data))
            except Exception:
                pass

    async def resize(self, sid, rows, cols) -> None:
        naws = self._shim.resize(rows, cols)
        if naws and self._fs and not self._closed:
            try:
                await self._fs.write(naws)
            except Exception:
                pass

    async def reap(self, sid) -> None:
        await self.close(sid)

    async def kill(self, sid) -> None:
        await self.close(sid)

    async def close(self, sid=None) -> None:
        if self._closed:
            return
        self._closed = True
        if self._task:
            self._task.cancel()
            self._task = None
        if self._fs:
            try:
                await self._fs.close()
            except Exception:
                pass
        if session_sources.get(self.sid) is self:   # nu clobbera o sursă înlocuită de reconnect
            session_sources.pop(self.sid, None)

    async def disconnect(self) -> None:
        await self.close(self.sid)


class ForwardSerialSource(SessionSource):
    """O consolă serială (RS232/RS485/USB) atașată la host, tunelată prin agent.
    Ca ForwardTelnetSource, dar octeți BRUȚI — fără shim/negociere (serialul n-are
    protocol). Device-ul e ne-de-încredere → păstrăm OscFilter (F5) + redactarea de
    parolă (F3). Dimensiunea NU se propagă (serialul n-are winsize)."""
    backend = "serial-fwd"

    def __init__(self, sid, host_id, agent_conn, device, params):
        self.sid = sid
        self.host_id = host_id
        self._agent = agent_conn
        self._device = device
        self._params = params           # {baud, bits, parity, stop, flow}
        self.epoch = "ser-" + uuid.uuid4().hex
        self._osc = telnet.OscFilter()
        self._fs = None
        self._task = None
        self._closed = False
        self.redact_input = False
        self._pw_tail = b""

    async def create(self, sid, rows, cols, term, tz=None) -> dict:
        p = self._params
        try:
            self._fs = await self._agent.open_serial(
                self._device, int(p.get("baud", 115200)), int(p.get("bits", 8)),
                p.get("parity", "none"), int(p.get("stop", 1)), p.get("flow", "none"))
        except ForwardError as e:
            return {"ok": False, "code": "open", "msg": str(e)}
        except AgentGone:
            return {"ok": False, "code": "offline", "msg": "host offline"}
        self._task = asyncio.create_task(self._pump(sid))
        return {"ok": True}

    async def _pump(self, sid) -> None:
        lost = False
        try:
            while True:
                chunk = await self._fs.read()
                if chunk is None:
                    lost = bool(self._fs and self._fs.tunnel_lost)
                    break
                clean = self._osc.filter(chunk)   # F5: OSC 133/52 de la device ne-de-încredere
                if clean:
                    self._observe_output(clean)
                    hub = hubs.get(sid)
                    if hub:
                        await hub.on_output(clean)
        except asyncio.CancelledError:
            raise
        except Exception:                         # noqa: BLE001
            pass
        finally:
            self._task = None
            self._closed = True
            # pop condiţional: dacă un reconnect a înlocuit deja sursa pentru acest sid, NU-l
            # şterge pe cel nou (altfel pump-ul vechi ar orfana sursa vie şi ar marca hub-ul pierdut).
            if session_sources.get(self.sid) is self:
                session_sources.pop(self.sid, None)
            hub = hubs.get(sid)
            if hub:
                if lost:
                    await hub.mark_lost("agent-gone")
                else:
                    await hub.on_exit(0, None)

    async def attach(self, sid, from_offset) -> dict:
        return {"ok": True, "replay_start": from_offset or 0}

    def _observe_output(self, clean: bytes) -> None:
        self._pw_tail = (self._pw_tail + clean)[-80:]
        line = self._pw_tail.rsplit(b"\n", 1)[-1].rsplit(b"\r", 1)[-1]
        if _PW_PROMPT.search(line):
            self.redact_input = True
        elif b"\n" in clean or b"\r" in clean:
            self.redact_input = False

    async def send_data(self, sid, data: bytes) -> None:
        if self.redact_input and (b"\r" in data or b"\n" in data):
            self.redact_input = False
            self._pw_tail = b""
        if self._fs and not self._closed:
            try:
                await self._fs.write(data)        # RAW: fără shim
            except Exception:
                pass

    async def resize(self, sid, rows, cols) -> None:
        pass                                      # serialul n-are dimensiune

    async def reap(self, sid) -> None:
        await self.close(sid)

    async def kill(self, sid) -> None:
        await self.close(sid)

    async def close(self, sid=None) -> None:
        if self._closed:
            return
        self._closed = True
        if self._task:
            self._task.cancel()
            self._task = None
        if self._fs:
            try:
                await self._fs.close()
            except Exception:
                pass
        if session_sources.get(self.sid) is self:   # nu clobbera o sursă înlocuită de reconnect
            session_sources.pop(self.sid, None)

    async def disconnect(self) -> None:
        await self.close(self.sid)


async def serial_discover(host_id: int) -> list:
    """Porturile seriale reale de pe host (via agent). AgentGone dacă offline."""
    agent = source_for(host_id)
    if not isinstance(agent, AgentConnection):
        raise AgentGone("host offline")
    return await agent.serial_list()


async def create_serial_session(host_id: int, device: str, params: dict, title: str,
                                rows: int = 24, cols: int = 80,
                                tz: Optional[str] = None) -> dict:
    """Deschide o sesiune de consolă serială pe host. Ridică AgentGone (offline),
    SessionLimitReached (plafon), RuntimeError (device-ul refuză)."""
    agent = source_for(host_id)
    if not isinstance(agent, AgentConnection):
        raise AgentGone("host offline")
    active = sum(1 for s in session_sources.values() if isinstance(s, ForwardSerialSource))
    if active >= MAX_SERIAL_SESSIONS:
        raise SessionLimitReached("serial session limit")
    sid = new_sid()
    src = ForwardSerialSource(sid, host_id, agent, device, params)
    session_sources[sid] = src
    cfg = json.dumps({"device": device, **{k: params.get(k) for k in ("baud", "bits", "parity", "stop", "flow")}})
    await db.execute(
        "INSERT INTO sessions(id, host_id, title, state, created, rows, cols,"
        " agent_epoch, kind, target_host, serial_config) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        sid, host_id, title, "creating", time.time(), rows, cols, src.epoch, "serial",
        device, cfg)
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    hub = get_or_create_hub(row)
    resp = await src.create(sid, rows, cols, "xterm-256color", tz)
    if not resp.get("ok"):
        hub.teardown()
        session_sources.pop(sid, None)
        await db.execute("DELETE FROM sessions WHERE id=?", sid)
        raise RuntimeError(resp.get("msg") or resp.get("code") or "serial open failed")
    await db.execute("UPDATE sessions SET state='live' WHERE id=?", sid)
    await hub.ensure_attached(src)
    return {"id": sid}


async def create_telnet_session(forward_row, title: str, rows: int = 24,
                                cols: int = 80, tz: Optional[str] = None) -> dict:
    """Deschide o sesiune telnet către ținta unui forward (scheme=telnet), tunelată
    prin agentul host-ului. Ridică AgentGone dacă host-ul e offline, SessionLimitReached
    la plafon, RuntimeError dacă ținta refuză conexiunea."""
    host_id = forward_row["host_id"]
    agent = source_for(host_id)
    if not isinstance(agent, AgentConnection):
        raise AgentGone("host offline")     # bastion telnet cere agentul online
    active = sum(1 for s in session_sources.values()
                 if isinstance(s, ForwardTelnetSource))
    if active >= MAX_TELNET_SESSIONS:
        raise SessionLimitReached("telnet session limit")
    thost, tport = forward_row["target_host"], forward_row["target_port"]
    sid = new_sid()
    src = ForwardTelnetSource(sid, host_id, agent, thost, tport, rows, cols)
    session_sources[sid] = src
    await db.execute(
        "INSERT INTO sessions(id, host_id, title, state, created, rows, cols,"
        " agent_epoch, kind, target_host, target_port) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        sid, host_id, title, "creating", time.time(), rows, cols, src.epoch, "telnet",
        thost, int(tport))
    # Creăm hub-ul ÎNAINTE de a porni pump-ul: serverul telnet trimite negocierea +
    # promptul instant la connect, iar pump-ul livrează prin `hubs.get(sid)` — dacă
    # hub-ul n-ar exista încă, primul output (ex. „login:") s-ar pierde.
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    hub = get_or_create_hub(row)
    resp = await src.create(sid, rows, cols, "xterm-256color", tz)
    if not resp.get("ok"):
        hub.teardown()
        session_sources.pop(sid, None)
        await db.execute("DELETE FROM sessions WHERE id=?", sid)
        raise RuntimeError(resp.get("msg") or resp.get("code") or "telnet connect failed")
    await db.execute("UPDATE sessions SET state='live' WHERE id=?", sid)
    await hub.ensure_attached(src)
    return {"id": sid}


async def reconnect_telnet_session(sid: str) -> dict:
    """Reconectează o sesiune telnet-bastion căzută (agentul a picat → `lost`, sau
    device-ul a închis → `exited`): deschide un telnet NOU spre aceeași țintă, pe
    ACELAȘI sid, în același tab, cu transcript continuu (marcaj de reconectare).
    Nu resuscită starea veche a device-ului — telnet e stateful pe socket, aterizezi
    la un prompt nou. Ridică KeyError (necunoscut / nu-i telnet), AgentGone (offline),
    SessionLimitReached, RuntimeError (ținta refuză)."""
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    if not row or row["kind"] != "telnet":
        raise KeyError(sid)
    if row["state"] in ("live", "creating"):
        return {"id": sid}                  # deja activă (alt tab a reconectat)
    thost, tport = row["target_host"], row["target_port"]
    if not thost or not tport:
        raise RuntimeError("unknown target for reconnection")
    host_id = row["host_id"]
    agent = source_for(host_id)
    if not isinstance(agent, AgentConnection):
        raise AgentGone("host offline")
    active = sum(1 for s in session_sources.values()
                 if isinstance(s, ForwardTelnetSource))
    if active >= MAX_TELNET_SESSIONS:
        raise SessionLimitReached("telnet session limit")
    src = ForwardTelnetSource(sid, host_id, agent, thost, tport, row["rows"], row["cols"])
    session_sources[sid] = src
    hub = get_or_create_hub(row)
    # marcaj vizibil de reconectare în transcript (continuu cu ce era înainte).
    # Sanitizăm `thost` la sink (defense-in-depth): deși e validat la creare, un rând
    # DB vechi ar putea conține ESC/C0 → injecție de secvențe în terminal. Păstrăm
    # doar caractere sigure de hostname.
    safe_host = re.sub(r"[^A-Za-z0-9._:-]", "", str(thost))[:255].encode("ascii", "replace")
    await hub.on_output(
        b"\r\n\x1b[7m[webterm: reconectat la %s:%d]\x1b[0m\r\n" % (safe_host, int(tport)))
    resp = await src.create(sid, row["rows"], row["cols"], "xterm-256color")
    if not resp.get("ok"):
        session_sources.pop(sid, None)
        raise RuntimeError(resp.get("msg") or resp.get("code") or "telnet reconnect failed")
    await db.execute(
        "UPDATE sessions SET state='live', closed_at=NULL, close_reason=NULL,"
        " exit_status=NULL WHERE id=?", sid)
    await hub.ensure_attached(src)
    return {"id": sid}


# ---------------------------------------------------------------------------
# Direct SSH source (gateway dials out to host:22)
# ---------------------------------------------------------------------------

SSH_CONNECT_TIMEOUT = 15
SSH_FWD_IDLE = 300         # conexiune SSH ridicată DOAR pentru forward: teardown după atâtea secunde fără forward/sesiune


class HostKeyMismatch(Exception):
    """Amprenta host key-ului diferă de cea pinată — posibil MITM."""


class SshForwardStream:
    """Un forward printr-un canal direct-tcpip asyncssh. Aceeași interfață
    write/read/close ca ForwardStream, deci proxy-ul HTTP/WebSocket și TLS-spre-țintă
    funcționează neschimbate peste el."""

    def __init__(self, reader, writer, source: "SshSource"):
        self._r = reader
        self._w = writer
        self._src = source
        self._closed = False

    async def write(self, data: bytes) -> None:
        self._w.write(data)
        try:
            await self._w.drain()
        except (asyncssh.Error, OSError, BrokenPipeError):
            raise ForwardError("SSH channel closed")

    async def read(self):
        try:
            data = await self._r.read(65536)
        except (asyncssh.Error, OSError):
            return None
        return data or None            # b'' = EOF

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._w.close()
        except Exception:
            pass
        self._src._fwd_closed(self)


class SshSource(SessionSource):
    """One asyncssh connection per host, one PTY channel per session. Wraps the
    remote shell in tmux so a dropped connection can re-attach. Feeds each
    channel's output into its SessionHub; no ring buffer (browser replay comes
    from the gateway-side transcript)."""
    backend = "ssh"

    def __init__(self, host_id: int, conn: "asyncssh.SSHClientConnection"):
        self.host_id = host_id
        self._conn = conn
        self.epoch = "ssh-" + uuid.uuid4().hex   # stabil pe viața conexiunii
        self._procs: Dict[str, "asyncssh.SSHClientProcess"] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._forwards: Set["SshForwardStream"] = set()   # forward-uri active (țin conexiunea vie)
        self._idle_task: Optional[asyncio.Task] = None

    async def create(self, sid, rows, cols, term, tz=None) -> dict:
        tmux = "wt-" + sid[:16]
        # tmux dacă există (persistență la re-conectare), altfel shell de login
        cmd = ("command -v tmux >/dev/null && exec tmux new -A -s %s "
               "|| exec ${SHELL:-/bin/bash} -l" % shlex.quote(tmux))
        if tz:
            cmd = "TZ=%s %s" % (shlex.quote(tz), cmd)
        try:
            proc = await self._conn.create_process(
                cmd, term_type=term or "xterm-256color",
                term_size=(cols, rows), encoding=None)
        except Exception as e:
            log.warning("ssh create %s: %s", sid, e)
            return {"ok": False, "code": str(e)}
        self._procs[sid] = proc
        self._tasks[sid] = asyncio.create_task(self._pump(sid, proc))
        return {"ok": True}

    async def _pump(self, sid, proc) -> None:
        try:
            while True:
                data = await proc.stdout.read(65536)
                if not data:
                    break
                hub = hubs.get(sid)
                if hub:
                    await hub.on_output(data)
        except (asyncssh.Error, OSError, asyncio.CancelledError):
            pass
        finally:
            self._procs.pop(sid, None)
            self._tasks.pop(sid, None)
            hub = hubs.get(sid)
            if hub:
                status = proc.exit_status if isinstance(proc.exit_status, int) else 0
                await hub.on_exit(status, None)

    async def attach(self, sid, from_offset) -> dict:
        return {"ok": True, "replay_start": from_offset or 0}

    async def send_data(self, sid, data: bytes) -> None:
        proc = self._procs.get(sid)
        if proc:
            proc.stdin.write(data)

    async def resize(self, sid, rows, cols) -> None:
        proc = self._procs.get(sid)
        if proc:
            proc.change_terminal_size(cols, rows)

    async def reap(self, sid) -> None:
        await self.close(sid)

    async def kill(self, sid) -> None:
        proc = self._procs.get(sid)
        if proc:
            try:
                proc.terminate()
            except OSError:
                pass
        await self.close(sid)

    async def close(self, sid) -> None:
        task = self._tasks.pop(sid, None)
        proc = self._procs.pop(sid, None)
        if proc:
            try:
                proc.close()
            except OSError:
                pass
        if task:
            task.cancel()
        # nu mai sunt sesiuni: închidem conexiunea DOAR dacă nici forward-uri active
        # nu sunt. Dacă sunt, conexiunea supraviețuiește sesiunii; idle-teardown-ul
        # pornește când pleacă ultimul forward (_fwd_closed).
        if not self._procs and not self._forwards and sources.get(self.host_id) is self:
            sources.pop(self.host_id, None)
            self._conn.close()

    async def disconnect(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    # -- forwarding: canale direct-tcpip pe aceeași conexiune SSH --------------
    async def open_forward(self, host: str, port: int):
        """Deschide un canal direct-tcpip către host:port (loopback pe hostul SSH,
        de regulă). Ține conexiunea vie cât forward-ul e activ."""
        # anulează idle-teardown-ul ÎNAINTE de await: altfel timer-ul de inactivitate
        # ar putea închide conexiunea fix în timpul lui open_connection (race).
        if self._idle_task:
            self._idle_task.cancel()
            self._idle_task = None
        try:
            reader, writer = await self._conn.open_connection(host, port)
        except (asyncssh.Error, OSError) as e:
            # a eșuat și n-a mai rămas nimic activ → re-programează idle-teardown-ul
            if not self._procs and not self._forwards:
                self._schedule_idle_teardown()
            raise ForwardError("the forwarded service is not responding: %s" % e)
        fs = SshForwardStream(reader, writer, self)
        self._forwards.add(fs)
        return fs

    def _fwd_closed(self, fs: "SshForwardStream") -> None:
        self._forwards.discard(fs)
        # conexiune ridicată DOAR pentru forward (fără sesiune) și rămasă goală →
        # o închidem după un timeout de inactivitate (nu ținem SSH-uri degeaba)
        if not self._procs and not self._forwards:
            self._schedule_idle_teardown()

    def _schedule_idle_teardown(self) -> None:
        if self._idle_task:
            self._idle_task.cancel()
        self._idle_task = asyncio.create_task(self._idle_close())

    async def _idle_close(self) -> None:
        try:
            await asyncio.sleep(SSH_FWD_IDLE)
        except asyncio.CancelledError:
            return
        if not self._procs and not self._forwards and sources.get(self.host_id) is self:
            sources.pop(self.host_id, None)
            self._conn.close()


async def dial_ssh(host_row, credential: dict) -> SshSource:
    """Deschide (și pinează host key-ul) o conexiune SSH și o înregistrează ca
    sursă. `credential` e {password} sau {key, passphrase?} — doar în memorie.
    Lock per-host + re-check: două cereri simultane nu deschid două conexiuni."""
    async with _dial_lock(host_row["id"]):
        existing = sources.get(host_row["id"])
        if isinstance(existing, SshSource):
            return existing

        host = host_row["hostname"]
        port = host_row["ssh_port"] or 22
        stored = host_row["known_hosts"]
        kwargs = dict(host=host, port=port, username=host_row["ssh_username"],
                      connect_timeout=SSH_CONNECT_TIMEOUT,
                      keepalive_interval=30, keepalive_count_max=4)
        if stored:
            # cheie pinată → asyncssh verifică ÎNAINTE de auth (parola nu ajunge la un MITM)
            pub = asyncssh.import_public_key(stored)
            kwargs["known_hosts"] = lambda _h, _a, _p: ([pub], [], [])
        else:
            kwargs["known_hosts"] = None            # TOFU: prima conectare pinează

        if host_row["auth_method"] == "key":
            pk = asyncssh.import_private_key(credential["key"],
                                            credential.get("passphrase") or None)
            kwargs["client_keys"] = [pk]
        else:
            kwargs["password"] = credential.get("password", "")

        try:
            conn = await asyncssh.connect(**kwargs)
        except asyncssh.HostKeyNotVerifiable as e:
            raise HostKeyMismatch(str(e))

        if not stored:
            keyline = conn.get_server_host_key().export_public_key().decode().strip()
            await db.execute("UPDATE hosts SET known_hosts=? WHERE id=?",
                             keyline, host_row["id"])

        src = SshSource(host_row["id"], conn)
        sources[host_row["id"]] = src
        return src


# ---------------------------------------------------------------------------
# Direct Telnet source (legacy/plaintext — gateway dials out to host:23)
# ---------------------------------------------------------------------------


class TelnetSource(SessionSource):
    """O conexiune telnet per host, o singură sesiune. Fără PTY/tmux (telnet e
    un flux brut); auto-login best-effort dacă avem user/parolă. Plaintext —
    de folosit doar pe rețea de încredere."""
    backend = "telnet"

    def __init__(self, host_id, reader, writer, creds):
        self.host_id = host_id
        self._reader = reader
        self._writer = writer
        self._creds = creds or {}
        self.epoch = "telnet-" + uuid.uuid4().hex
        self._task = None
        # Un device telnet e ne-de-încredere (switch/router): scoate OSC 133/52 (spoof de
        # marcaje semantice / scriere clipboard) ÎNAINTE de transcript și browser, la fel
        # ca bastionul (ForwardTelnetSource). Parolele tastate nu mai ajung în transcript
        # (nu mai înregistrăm evenimente „i" deloc — vezi handle_input).
        self._osc = telnet.OscFilter()

    async def create(self, sid, rows, cols, term, tz=None) -> dict:
        # telnet direct = O conexiune per host, O sesiune (share acelaşi StreamReader). O a doua
        # sesiune ar porni un al doilea _pump pe acelaşi reader → citiri concurente, o coroutină
        # eşuează şi ar închide conexiunea comună + prima sesiune. Refuzăm a doua.
        if self._task is not None and not self._task.done():
            return {"ok": False, "code": "single_session",
                    "msg": "direct telnet: one session per host only (use the agent for more)"}
        self._task = asyncio.create_task(self._pump(sid))
        if self._creds.get("username"):
            asyncio.create_task(self._autologin())
        return {"ok": True}

    async def _autologin(self) -> None:
        # telnet cere de obicei „login:" apoi „Password:" — trimitem naiv
        try:
            await asyncio.sleep(0.9)
            self._writer.write(self._creds.get("username", "") + "\r\n")
            if self._creds.get("password"):
                await asyncio.sleep(0.9)
                self._writer.write(self._creds["password"] + "\r\n")
        except Exception:
            pass

    async def _pump(self, sid) -> None:
        try:
            while True:
                data = await self._reader.read(4096)
                if not data:
                    break
                raw = data.encode("utf8", "replace") if isinstance(data, str) else data
                clean = self._osc.filter(raw)      # stateful: bufferează OSC tăiat între recv-uri
                hub = hubs.get(sid)
                if hub and clean:
                    await hub.on_output(clean)
        except Exception:
            pass
        finally:
            self._task = None
            hub = hubs.get(sid)
            if hub:
                await hub.on_exit(0, None)

    async def attach(self, sid, from_offset) -> dict:
        return {"ok": True, "replay_start": from_offset or 0}

    async def send_data(self, sid, data: bytes) -> None:
        try:
            self._writer.write(data.decode("utf8", "replace"))
        except Exception:
            pass

    async def resize(self, sid, rows, cols) -> None:
        pass          # NAWS după conectare: best-effort, ignorăm

    async def reap(self, sid) -> None:
        await self.close(sid)

    async def kill(self, sid) -> None:
        await self.close(sid)

    async def close(self, sid) -> None:
        if self._task:
            self._task.cancel()
            self._task = None
        try:
            self._writer.close()
        except Exception:
            pass
        if sources.get(self.host_id) is self:
            sources.pop(self.host_id, None)

    async def disconnect(self) -> None:
        try:
            self._writer.close()
        except Exception:
            pass


async def dial_telnet(host_row, credential: dict) -> TelnetSource:
    async with _dial_lock(host_row["id"]):          # per-host + re-check (anti conexiuni duble)
        existing = sources.get(host_row["id"])
        if isinstance(existing, TelnetSource):
            return existing
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(
                host_row["hostname"], host_row["ssh_port"] or 23,
                term="xterm-256color", encoding="utf8", connect_minwait=0.05),
            SSH_CONNECT_TIMEOUT)
        src = TelnetSource(host_row["id"], reader, writer, credential)
        sources[host_row["id"]] = src
        return src


# ---------------------------------------------------------------------------
# File transfer (bridged through the agent's fs_* ops)
# ---------------------------------------------------------------------------

FS_CHUNK = 256 * 1024


def _agent_or_raise(host_id: int) -> "AgentConnection":
    conn = sources.get(host_id)
    if not isinstance(conn, AgentConnection):
        raise AgentGone("host offline")
    return conn


async def fs_list(host_id: int, path: str) -> dict:
    resp = await _agent_or_raise(host_id).request("fs_list", path=path or "~")
    if not resp.get("ok"):
        raise FileError(resp.get("msg", "eroare"))
    return resp


async def fs_read_all(host_id: int, path: str):
    """Async generator yielding a remote file's bytes, chunk by chunk."""
    conn = _agent_or_raise(host_id)
    offset = 0
    while True:
        resp = await conn.request("fs_read", path=path, offset=offset, timeout=60)
        if not resp.get("ok"):
            raise FileError(resp.get("msg", "eroare"))
        chunk = base64.b64decode(resp["data_b64"])
        if chunk:
            yield chunk
        offset += len(chunk)
        if resp.get("eof") or not chunk:
            break


async def fs_read_head(host_id: int, path: str, max_bytes: int):
    """Citește primii `max_bytes` dintr-un fișier (pentru preview/editare fără a
    trage un fișier de 40GB în browser). Întoarce (bytes, size_total, mtime)."""
    conn = _agent_or_raise(host_id)
    resp = await conn.request("fs_read", path=path, offset=0, timeout=60)
    if not resp.get("ok"):
        raise FileError(resp.get("msg", "eroare"))
    data = base64.b64decode(resp["data_b64"])
    size = int(resp.get("size", len(data)))
    mtime = int(resp.get("mtime", 0))
    while len(data) < max_bytes and not resp.get("eof"):
        resp = await conn.request("fs_read", path=path, offset=len(data), timeout=60)
        if not resp.get("ok"):
            raise FileError(resp.get("msg", "eroare"))
        data += base64.b64decode(resp["data_b64"])
    return data[:max_bytes], size, mtime


async def fs_write_stream(host_id: int, path: str, source, if_mtime=None) -> int:
    """Stream an upload to a temp file, then atomically rename over the target.
    Un upload/salvare care pică la mijloc NU lasă fișierul final trunchiat —
    important pentru config-uri (un `sshd_config` corupt te blochează afară).
    `if_mtime` (opțional): commit-ul refuză dacă ținta s-a schimbat între timp."""
    conn = _agent_or_raise(host_id)
    # sufix aleator: două upload-uri simultane pe aceeași cale nu se mai calcă pe
    # același temp (conținut amestecat), iar numele nu mai e predictibil (un
    # proces local nu poate pre-crea un symlink cu numele temp-ului)
    tmp = "%s.wtpart.%s" % (path, uuid.uuid4().hex[:12])
    offset = 0
    buf = b""
    try:
        async for part in source:
            buf += part
            while len(buf) >= FS_CHUNK:
                block, buf = buf[:FS_CHUNK], buf[FS_CHUNK:]
                await _fs_write_block(conn, tmp, offset, block)
                offset += len(block)
        if buf or offset == 0:      # write at least once (creates empty files too)
            await _fs_write_block(conn, tmp, offset, buf)
            offset += len(buf)
        # commit atomic: temp → final (os.replace pe agent)
        resp = await conn.request("fs_rename", path=tmp, to=path,
                                  overwrite=True, if_mtime=if_mtime, timeout=60)
        if not resp.get("ok"):
            if resp.get("code") == "conflict":
                raise FileConflict(resp.get("msg", "the file changed"))
            raise FileError(resp.get("msg", "eroare"))
        return offset
    except BaseException:
        # orice eșec (inclusiv anulare): curăță temp-ul, best-effort
        try:
            await conn.request("fs_delete", path=tmp, timeout=15)
        except Exception:
            pass
        raise


async def fs_delete(host_id: int, path: str, recursive: bool = False) -> None:
    resp = await _agent_or_raise(host_id).request(
        "fs_delete", path=path, recursive=recursive)
    if not resp.get("ok"):
        raise FileError(resp.get("msg", "eroare"))


async def fs_rename(host_id: int, path: str, to: str) -> None:
    resp = await _agent_or_raise(host_id).request(
        "fs_rename", path=path, to=to, overwrite=False)
    if not resp.get("ok"):
        raise FileError(resp.get("msg", "eroare"))


async def session_cwd(host_id: int, sid: str) -> str:
    """Directorul curent al shell-ului unei sesiuni (fără shell integration) —
    ca panoul de fișiere să se deschidă unde ești în terminal."""
    resp = await _agent_or_raise(host_id).request("session_cwd", sid=sid)
    if not resp.get("ok"):
        raise FileError(resp.get("msg", "eroare"))
    return resp.get("cwd") or "~"


async def fs_mkdir(host_id: int, path: str, parents: bool = False) -> None:
    resp = await _agent_or_raise(host_id).request("fs_mkdir", path=path, parents=parents)
    if not resp.get("ok"):
        raise FileError(resp.get("msg", "eroare"))


async def _fs_write_block(conn, path, offset, block) -> None:
    resp = await conn.request(
        "fs_write", path=path, offset=offset,
        data_b64=base64.b64encode(block).decode(), timeout=60)
    if not resp.get("ok"):
        raise FileError(resp.get("msg", "eroare"))


class FileError(Exception):
    pass


class FileConflict(FileError):
    """Ținta s-a schimbat între citire și salvare — nu suprascriem orbește."""
    pass
