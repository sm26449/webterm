"""Plafonul de transcript OFF-LOOP (3.5.17): `_maybe_cap` doar declanşează, copierea celor 16 MiB
rulează pe un thread, iar handle-urile vii se schimbă într-un singur pas sincron la final.

Acoperă ce putea strica mutarea de pe loop (vezi comentariul de la `core.CAP_TMP_SUFFIX`):
  · rezultatul e IDENTIC cu implementarea veche (referinţa de mai jos e codul vechi, copiat);
  · octeţii scrişi CÂT copiază thread-ul ajung după coadă, în ordine, fără pierderi/dubluri
    (prin calea reală `_process_output`, inclusiv rafale mai mari decât restul permis pe loop);
  · .cast rămâne asciicast valid (header + gol + linii întregi, timpi monotoni);
  · `out_gen` creşte exact o dată (invalidează cutoff-urile resync-ului);
  · o a doua tăiere nu porneşte cât rulează prima;
  · teardown / on_exit / mark_lost / arhivare în timpul copierii: nicio excepţie, niciun temporar
    rămas, originalele intacte;
  · read_tail / attach_replay în timpul tăierii (inclusiv peste schimbare) văd mereu coada corectă;
  · un eşec (cast corupt) nu iese din task, hub-ul rămâne utilizabil, nu reîncearcă în buclă;
  · crash la jumătate: originalele citibile, temporarele şterse la pornire;
  · event-loop-ul NU e blocat: un heartbeat la 5 ms rămâne < 50 ms pe un transcript de 64 MiB.
Fără gateway/agent reale."""
import asyncio
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time

TMP = tempfile.mkdtemp()
os.environ["WEBTERM_DATA_DIR"] = TMP
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, core, db  # noqa: E402

config.ensure_dirs()
results = []
MiB = 1024 * 1024


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


# ---------------------------------------------------------------------------
# referinţa: `_maybe_cap` de dinainte de 3.5.17 (sincron), pe fişiere, fără hub
# ---------------------------------------------------------------------------
def old_cap(out_path, cast_path, keep, gap_ts):
    out_sz = os.path.getsize(out_path)
    gap_cast = (json.dumps([gap_ts, "o", core.GAP_MARKER.decode("utf-8", "replace")]) + "\n").encode()
    with open(out_path, "rb") as f:
        f.seek(max(0, out_sz - keep))
        tail = f.read()
    with open(out_path, "wb") as f:
        f.write(core.GAP_MARKER + tail)
    with open(cast_path, "rb") as f:
        header = f.readline()
        csz = f.seek(0, 2)
        f.seek(max(len(header), csz - keep))
        chunk = f.read()
    nl = chunk.find(b"\n")
    tail_lines = chunk[nl + 1:] if nl >= 0 else b""
    with open(cast_path, "wb") as f:
        f.write(header + gap_cast + tail_lines)


def make_fixture(out_path, cast_path, out_bytes, seed=1):
    """Un .out de `out_bytes` şi .cast-ul lui (evenimente de lungimi variate, timpi crescători)."""
    rnd = random.Random(seed)
    t = 0.0
    with open(out_path, "wb") as fo, open(cast_path, "w", encoding="utf-8") as fc:
        fc.write(json.dumps({"version": 2, "width": 80, "height": 24, "timestamp": 1}) + "\n")
        written = 0
        alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789 \r\n\x1b[1m\"\\"
        block = bytes(rnd.choice(alphabet) for _ in range(70000))
        while written < out_bytes:
            n = rnd.randint(1, 65536)
            off = rnd.randint(0, len(block) - n)
            data = block[off:off + n]
            fo.write(data)
            t += rnd.random() / 10
            fc.write(json.dumps([round(t, 6), "o", data.decode("utf-8", "replace")]) + "\n")
            written += n


def make_hub(sid):
    row = {"id": sid, "host_id": 1, "rows": 24, "cols": 80,
           "agent_epoch": None, "agent_offset": 0, "created": time.time() - 3600}
    return core.SessionHub(row)


def cast_lines(path):
    return open(path, "rb").read().split(b"\n")


def validate_cast(path):
    """(ok, detail): header v2, apoi doar evenimente [t, "o", str], timpi monotoni, final cu \\n."""
    raw = open(path, "rb").read()
    if not raw.endswith(b"\n"):
        return False, "does not end with a newline"
    lines = raw[:-1].split(b"\n")
    try:
        hdr = json.loads(lines[0])
    except ValueError as e:
        return False, "header: %s" % e
    if hdr.get("version") != 2:
        return False, "header version"
    last = -1.0
    for i, ln in enumerate(lines[1:], 1):
        try:
            ev = json.loads(ln)
        except ValueError as e:
            return False, "line %d: %s" % (i, e)
        if not (isinstance(ev, list) and len(ev) == 3 and ev[1] == "o" and isinstance(ev[2], str)):
            return False, "line %d: not an output event" % i
        if ev[0] < last:
            return False, "line %d: time goes back %r < %r" % (i, ev[0], last)
        last = ev[0]
    return True, ""


def temps():
    return sorted(p.name for p in config.TRANSCRIPT_DIR.glob(".*" + core.CAP_TMP_SUFFIX))


_real_copy = core._cap_copy


def slow_copy(delay):
    """Încetineşte copierea de pe THREAD (nu şi restul de pe loop, apelat cu abort=None)."""
    def wrapped(src, dst, start, end, abort):
        if abort is not None:
            pos = start
            while pos < end:
                if abort.is_set():
                    raise core._CapAborted()
                nxt = min(end, pos + 256 * 1024)
                _real_copy(src, dst, pos, nxt, abort)
                pos = nxt
                time.sleep(delay)
            return pos
        return _real_copy(src, dst, start, end, abort)
    return wrapped


async def wait_thread_started(hub, timeout=5.0):
    t0 = time.monotonic()
    while not temps() and time.monotonic() - t0 < timeout:
        await asyncio.sleep(0.002)


# ---------------------------------------------------------------------------
async def t_equivalence():
    print("-- identical to the old implementation")
    config.TRANSCRIPT_MAX_BYTES = 4 * MiB
    config.TRANSCRIPT_KEEP_BYTES = 1 * MiB
    sid = "1" * 32
    out_path, cast_path = core.transcript_paths(sid)
    make_fixture(out_path, cast_path, 5 * MiB, seed=7)
    ref_dir = tempfile.mkdtemp()
    ref_out, ref_cast = os.path.join(ref_dir, "r.out"), os.path.join(ref_dir, "r.cast")
    shutil.copyfile(out_path, ref_out)
    shutil.copyfile(cast_path, ref_cast)
    old_cap(ref_out, ref_cast, config.TRANSCRIPT_KEEP_BYTES, 99999.0)

    hub = make_hub(sid)
    gen0 = hub.out_gen
    hub._maybe_cap()
    check("cap task started", hub._cap_task is not None)
    await hub._cap_task
    check(".out byte-identical to the old result", open(out_path, "rb").read() == open(ref_out, "rb").read())
    new, old = cast_lines(cast_path), cast_lines(ref_cast)
    check(".cast header identical", new[0] == old[0])
    check(".cast tail events identical", new[2:] == old[2:], "%d vs %d lines" % (len(new), len(old)))
    gap_new, gap_old = json.loads(new[1]), json.loads(old[1])
    check(".cast gap event carries the gap marker", gap_new[1:] == gap_old[1:])
    first_kept = json.loads(new[2])[0]
    check("gap timestamp = first kept event (monotonic, old one was 'now')", gap_new[0] == first_kept,
          (gap_new, first_kept))
    ok, why = validate_cast(cast_path)
    check(".cast valid asciicast", ok, why)
    check("out_gen bumped exactly once", hub.out_gen == gen0 + 1, hub.out_gen)
    check("no temp files left", temps() == [], temps())
    hub.out_f.write(b"AFTER")
    hub._flush()
    check("live handle points at the new file", open(out_path, "rb").read().endswith(b"AFTER"))
    hub.teardown()
    shutil.rmtree(ref_dir)


async def t_writes_during_copy():
    print("-- output written during the background copy (real _process_output path)")
    config.TRANSCRIPT_MAX_BYTES = 4 * MiB
    config.TRANSCRIPT_KEEP_BYTES = 1 * MiB
    sid = "2" * 32
    out_path, cast_path = core.transcript_paths(sid)
    make_fixture(out_path, cast_path, 4 * MiB + 1000, seed=3)
    pre_out = open(out_path, "rb").read()
    hub = make_hub(sid)
    core._cap_copy = slow_copy(0.01)
    try:
        sent = []
        # primul chunk trece de plafon → _checkpoint (forţat de ≥64 KiB) declanşează tăierea
        first = b"<first>" + b"F" * 70000
        await hub._process_output(first)
        sent.append(first)
        task = hub._cap_task
        check("truncation running in the background", task is not None and not task.done())
        await wait_thread_started(hub)
        hub._maybe_cap()
        check("second truncation does not start while one runs", hub._cap_task is task)
        i = 0
        # plafon DUR: scriitorul nu poate întrece copierea la nesfârşit; şi KEEP + buget < MAX,
        # ca checkpoint-urile de după să nu declanşeze legitim o a doua tăiere
        budget = int(2.5 * MiB)
        while not task.done() and budget > 0:
            # rafale variate, unele peste CAP_RESIDUAL_MAX (forţează rundele de catch-up)
            n = 600 * 1024 if i % 7 == 3 else random.randint(10, 5000)
            budget -= n
            data = (b"<%d>" % i) + bytes([65 + i % 26]) * n + b"\r\n"
            await hub._process_output(data)
            sent.append(data)
            i += 1
            await asyncio.sleep(0.001)
        await task
    finally:
        core._cap_copy = _real_copy
    for k in range(5):                       # şi după schimbare, prin noul handle
        data = b"<post%d>\r\n" % k
        await hub._process_output(data)
        sent.append(data)
    await hub._checkpoint(force=True)
    check("no further truncation triggered", hub._cap_task is task)
    got = open(out_path, "rb").read()
    # instantaneul tăierii include primul chunk (cel care a trecut de plafon şi a declanşat-o)
    snap = pre_out + sent[0]
    want = core.GAP_MARKER + snap[len(snap) - config.TRANSCRIPT_KEEP_BYTES:] + b"".join(sent[1:])
    check("chunks written during copy: %d (incl. bursts > residual)" % i, i >= 5, i)
    check(".out = gap + old tail + every later byte, in order", got == want,
          "len %d vs %d" % (len(got), len(want)))
    ok, why = validate_cast(cast_path)
    check(".cast valid asciicast after concurrent writes", ok, why)
    evs = [json.loads(ln) for ln in cast_lines(cast_path)[2:] if ln]
    later = [e[2] for e in evs[-len(sent):]]
    check(".cast ends with exactly the later events, in order",
          later == [d.decode("utf-8", "replace") for d in sent])
    check("out_gen bumped exactly once", hub.out_gen == 1, hub.out_gen)
    check("no temp files left", temps() == [], temps())
    hub.teardown()


async def _teardown_case(label, sid, closer):
    config.TRANSCRIPT_MAX_BYTES = 4 * MiB
    config.TRANSCRIPT_KEEP_BYTES = 2 * MiB
    out_path, cast_path = core.transcript_paths(sid)
    make_fixture(out_path, cast_path, 5 * MiB, seed=11)
    hub = make_hub(sid)
    hub.out_f.write(b"<unflushed-before-close>")      # încă în bufferul Python
    core._cap_copy = slow_copy(0.02)
    try:
        hub._maybe_cap()
        task = hub._cap_task
        await wait_thread_started(hub)
        check("%s: copy in progress when closing" % label, not task.done() and temps() != [])
        size_before = os.path.getsize(out_path)
        await closer(hub)
        try:
            await asyncio.wait_for(task, 10)
            exc = None
        except Exception as e:              # noqa: BLE001
            exc = e
    finally:
        core._cap_copy = _real_copy
    check("%s: task ended without an exception" % label, exc is None and task.exception() is None, exc)
    check("%s: no temp files left" % label, temps() == [], temps())
    return hub, out_path, cast_path, size_before


async def t_close_during_copy():
    print("-- close / exit / lost / archive during the background copy")
    await db.execute("INSERT INTO hosts(id,name,token_hash,token_encrypted,created)"
                     " VALUES(?,?,?,?,?)", 1, "h", "tok", "enc", 0.0)
    for sid in ("3" * 32, "4" * 32, "5" * 32, "6" * 32):
        await db.execute("INSERT INTO sessions(id,host_id,title,state,created) VALUES(?,?,?,?,?)",
                         sid, 1, "t", "live", 0.0)

    async def do_teardown(hub):
        hub.teardown()
    hub, out_path, cast_path, before = await _teardown_case("teardown", "3" * 32, do_teardown)
    check("teardown: original .out intact (untruncated, flushed tail kept)",
          os.path.getsize(out_path) >= before
          and open(out_path, "rb").read().endswith(b"<unflushed-before-close>"))
    ok, why = validate_cast(cast_path)
    check("teardown: original .cast still valid", ok, why)

    async def do_exit(hub):
        await hub.on_exit(0, None)          # calea reală de kill/exit: checkpoint forţat + teardown
    hub, out_path, _, _ = await _teardown_case("on_exit (kill)", "4" * 32, do_exit)
    check("on_exit: hub closed, handles closed", hub.closed and hub.out_f.closed and hub.cast_f.closed)
    r = await db.fetchone("SELECT state FROM sessions WHERE id=?", "4" * 32)
    check("on_exit: session marked closed", r["state"] == "closed", r["state"])

    async def do_lost(hub):
        await hub.mark_lost("lost")
    hub, _, _, _ = await _teardown_case("mark_lost", "5" * 32, do_lost)
    check("mark_lost: hub closed", hub.closed)

    async def do_archive(hub):
        hub.teardown()
        await asyncio.to_thread(core.archive_transcript, hub.sid)   # căile se mută sub thread
    hub, out_path, cast_path, before = await _teardown_case("archive", "6" * 32, do_archive)
    arch = config.ARCHIVE_DIR / out_path.name
    check("archive: transcript moved whole into the archive, nothing left behind",
          arch.exists() and arch.stat().st_size >= before and not out_path.exists()
          and not cast_path.exists())


async def t_readers_during_cap():
    print("-- read_tail / attach_replay during truncation and across the swap")
    config.TRANSCRIPT_MAX_BYTES = 4 * MiB
    config.TRANSCRIPT_KEEP_BYTES = 1 * MiB
    sid = "7" * 32
    out_path, cast_path = core.transcript_paths(sid)
    make_fixture(out_path, cast_path, 5 * MiB, seed=5)
    # coada se termină în octeţi fără secvenţe alt-screen → read_tail o întoarce neschimbată
    with open(out_path, "ab") as f:
        f.write(b"".join(b"line %06d\r\n" % k for k in range(800)))
    want = open(out_path, "rb").read()[-4096:]
    hub = make_hub(sid)
    stop = threading.Event()
    bad = []
    reads = [0]

    def hammer():
        while not stop.is_set():
            got = core.read_tail(sid, limit=4096)
            reads[0] += 1
            if got != want:
                bad.append(len(got))

    th = threading.Thread(target=hammer)
    th.start()
    core._cap_copy = slow_copy(0.005)
    try:
        hub._maybe_cap()
        task = hub._cap_task
        replays = []
        while not task.done():
            replays.append(await core.attach_replay(sid, hub, scrollback=0))
            await asyncio.sleep(0.003)
        await task
        replays.append(await core.attach_replay(sid, hub, scrollback=0))
    finally:
        core._cap_copy = _real_copy
        stop.set()
        th.join()
    check("read_tail always returned the exact tail (%d reads)" % reads[0], reads[0] > 10 and not bad,
          bad[:5])
    lim = core.replay_tail_limit(0, core.stream_is_plain(hub))
    check("attach_replay during and after the swap ends with the tail (%d calls)" % len(replays),
          len(replays) > 2 and all(r.endswith(want) and len(r) <= lim for r in replays))
    check("transcript actually truncated", os.path.getsize(out_path) < 2 * MiB)
    hub.teardown()


async def t_failure_contained():
    print("-- a failure stays inside the task (no retry storm, hub keeps working)")
    config.TRANSCRIPT_MAX_BYTES = 1 * MiB
    config.TRANSCRIPT_KEEP_BYTES = 256 * 1024
    sid = "8" * 32
    out_path, cast_path = core.transcript_paths(sid)
    with open(out_path, "wb") as f:
        f.write(b"x" * (2 * MiB))
    with open(cast_path, "wb") as f:
        f.write(b"{" + b"a" * (100 * 1024))                # header fără newline (corupt)
    hub = make_hub(sid)
    hub._maybe_cap()
    task = hub._cap_task
    await asyncio.wait_for(task, 10)
    check("task finished without raising", task.exception() is None)
    check("original files untouched", os.path.getsize(out_path) == 2 * MiB)
    check("no temp files left", temps() == [], temps())
    check("backoff armed", hub._cap_not_before > time.time() + 30)
    hub._maybe_cap()
    check("no retry on the next checkpoint", hub._cap_task is task)
    hub.out_f.write(b"still-alive")
    hub._flush()
    check("hub still writes", open(out_path, "rb").read().endswith(b"still-alive"))
    hub.teardown()


async def t_crash_mid_copy():
    print("-- crash mid-copy leaves a readable transcript; temps cleaned at boot")
    config.TRANSCRIPT_MAX_BYTES = 4 * MiB
    config.TRANSCRIPT_KEEP_BYTES = 2 * MiB
    sid = "9" * 32
    out_path, cast_path = core.transcript_paths(sid)
    make_fixture(out_path, cast_path, 5 * MiB, seed=9)
    orig = open(out_path, "rb").read()
    hub = make_hub(sid)
    core._cap_copy = slow_copy(0.02)
    try:
        hub._maybe_cap()
        await wait_thread_started(hub)
        # „crash": instantaneul discului acum = ce ar găsi o repornire
        snap = tempfile.mkdtemp()
        for p in config.TRANSCRIPT_DIR.iterdir():
            if p.is_file():
                shutil.copy2(p, snap)
        hub.teardown()
        await hub._cap_task
    finally:
        core._cap_copy = _real_copy
    snap_temps = [n for n in os.listdir(snap) if n.endswith(core.CAP_TMP_SUFFIX)]
    check("mid-copy state has temp files", len(snap_temps) == 2, snap_temps)
    check("mid-copy state has the full original .out",
          open(os.path.join(snap, out_path.name), "rb").read() == orig)
    # pornire pe instantaneu
    for p in config.TRANSCRIPT_DIR.iterdir():
        if p.is_file():
            p.unlink()
    for n in os.listdir(snap):
        shutil.copy2(os.path.join(snap, n), config.TRANSCRIPT_DIR / n)
    removed = core.cleanup_cap_temps()
    check("boot cleanup removes the orphan temps", removed == 2 and temps() == [], removed)
    check("transcript readable after the crash", core.read_tail(sid, limit=100) == orig[-100:])
    shutil.rmtree(snap)


async def t_loop_not_blocked():
    print("-- the event loop keeps ticking while a 64 MiB transcript is truncated")
    config.TRANSCRIPT_MAX_BYTES = 64 * MiB
    config.TRANSCRIPT_KEEP_BYTES = 16 * MiB
    sid = "b" * 32
    out_path, cast_path = core.transcript_paths(sid)
    make_fixture(out_path, cast_path, 64 * MiB + 4096, seed=13)
    ref_dir = tempfile.mkdtemp()
    ref_out, ref_cast = os.path.join(ref_dir, "r.out"), os.path.join(ref_dir, "r.cast")
    shutil.copyfile(out_path, ref_out)
    shutil.copyfile(cast_path, ref_cast)
    hub = make_hub(sid)
    swap_ms = []
    real_swap = hub._cap_swap

    def timed_swap(*a):
        t = time.perf_counter()
        try:
            return real_swap(*a)
        finally:
            swap_ms.append((time.perf_counter() - t) * 1000)
    hub._cap_swap = timed_swap

    gaps = []
    done = asyncio.Event()

    async def heartbeat():
        last = time.perf_counter()
        while not done.is_set():
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    hb = asyncio.create_task(heartbeat())
    await asyncio.sleep(0.05)
    t0 = time.perf_counter()
    t_trigger = time.perf_counter()
    hub._maybe_cap()
    trigger_ms = (time.perf_counter() - t_trigger) * 1000
    await hub._cap_task
    elapsed = (time.perf_counter() - t0) * 1000
    done.set()
    await hb
    worst = max(gaps) * 1000
    print("     cap took %.0f ms off-loop; trigger %.2f ms; swap %.2f ms on the loop; "
          "worst heartbeat gap %.1f ms over %d ticks"
          % (elapsed, trigger_ms, swap_ms[0] if swap_ms else -1, worst, len(gaps)))
    check("truncated (.out ~16 MiB)", os.path.getsize(out_path) < 17 * MiB)
    check("heartbeat never stalled > 50 ms (worst %.1f ms)" % worst, worst < 50, worst)
    check("on-loop swap step < 20 ms (%.2f ms)" % swap_ms[0], swap_ms and swap_ms[0] < 20, swap_ms)
    # referinţa: cât bloca varianta veche loop-ul pe aceleaşi fişiere (informativ)
    t = time.perf_counter()
    old_cap(ref_out, ref_cast, config.TRANSCRIPT_KEEP_BYTES, 0.0)
    print("     old synchronous cap on the same files: %.0f ms on the loop"
          % ((time.perf_counter() - t) * 1000))
    check("same .out as the old implementation at 64/16 MiB",
          open(out_path, "rb").read() == open(ref_out, "rb").read())
    hub.teardown()
    shutil.rmtree(ref_dir)
    os.unlink(out_path)
    os.unlink(cast_path)


async def main():
    await db.connect()
    try:
        await t_equivalence()
        await t_writes_during_copy()
        await t_close_during_copy()
        await t_readers_during_cap()
        await t_failure_contained()
        await t_crash_mid_copy()
        await t_loop_not_blocked()
    finally:
        if hasattr(db, "close"):
            await db.close()


asyncio.run(main())
shutil.rmtree(TMP, ignore_errors=True)
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
