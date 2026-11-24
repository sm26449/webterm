"""txstore (ENCRYPTION-AT-REST.md §12.11, PR5a): Recorder + readers in isolation, not wired.

Groups (§12.11.7): activation guard; publication and commit atomicity (#3); checkpoint ordering
races, lost race, CAS / monotonic refusals, uncertain COMMIT (#14); crash at every row of the
recovery table + idempotent second pass (#1); nonce / gen_id uniqueness and collisions (#2);
roll-over, hard limit in one batch, SEAL at close; cap byte-identical to 3.7 and merge (#7);
readers: watermark, ranges, index rules, budgets, tail/resume/preview, redaction across record
boundaries, revocation counters / fences / expiry, caches, owner recovery, downgrade (#4, #5, #15);
integrity check of the .out/.cast pair; backpressure, worker loss and write faults (#19 subset).
Temp dirs + the real db module; no network, no Docker.
"""
import asyncio
import os
import sqlite3
import sys
import tempfile
import threading
import time

BASE = tempfile.mkdtemp(prefix="wt-txstore-")
os.environ["WEBTERM_DATA_DIR"] = BASE
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
os.environ["WEBTERM_TX_RECORDINGS"] = "1"
os.environ["WEBTERM_TEST_GATE"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, db, keyring as kr, txdesc as td, txformat as tx, txstore as ts  # noqa: E402
from app import core  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {str(detail)[:300]}"))


async def araises(coro, exc, reason=None):
    try:
        await coro
    except exc as e:
        return reason is None or getattr(e, "reason", None) == reason
    except BaseException as e:  # noqa: BLE001
        print("     got", type(e).__name__, e)
        return False
    return False


KWK = bytes(range(0x60, 0x80))
INST = bytes(range(0xa0, 0xb0))
HOST = 1


class Crash(BaseException):
    """Process death at a publication point."""


def faults(points, exc=Crash, times=1):
    """A fault hook raising `exc` at the named point(s), `times` times."""
    state = {"left": times}

    def hook(p):
        if p in points and state["left"] > 0:
            state["left"] -= 1
            raise exc(p)
    return hook


def new_sid():
    return os.urandom(16).hex()


async def add_session(sid, epoch="e1"):
    await db.execute("INSERT INTO sessions(id, host_id, state, created, agent_epoch, agent_offset) "
                     "VALUES(?,?,?,?,?,0)", sid, HOST, "live", time.time(), epoch)


def store(**kw):
    return ts.Store(transcripts_dir=config.TRANSCRIPT_DIR, kwk=KWK, installation_id=INST, **kw)


async def access(st, sid, **kw):
    return st.access(sid, "u1", "test", **kw)


async def read_all(st, sid, kind="out", **kw):
    snap = await st.open(sid, kind, access=await access(st, sid, **kw))
    try:
        return await snap.read(0, snap.length)
    finally:
        snap.close()


def cast_line(t, s):
    import json
    return (json.dumps([t, "o", s]) + "\n").encode()


async def row(sql, *a):
    return await db.fetchone(sql, *a)


async def ledger(sid):
    return {r[0]: r[1] for r in await db.fetchall("SELECT gen_id, state FROM tx_files WHERE sid=?", sid)}


def names(sid):
    return sorted(n for n in os.listdir(config.TRANSCRIPT_DIR) if n.startswith(sid))


async def desc(st, sid, kind="out"):
    r = await row("SELECT blob, version FROM tx_descriptors WHERE sid=? AND kind=?", sid, kind)
    k = await row("SELECT envelope FROM session_keys WHERE sid=?", sid)
    return st.decode((r[0], r[1]), sid, kind, bytes(k[0]))


# ── groups ───────────────────────────────────────────────────────────────────


async def g_activation():
    print("== activation guard (PR5/PR6 boundary) ==")
    env_ok = {"WEBTERM_TX_RECORDINGS": "1", "WEBTERM_TEST_GATE": "1"}
    for v in ("", "0", "true", "yes", " 1"):
        check(f"flag {v!r} → off", not ts.enabled({"WEBTERM_TX_RECORDINGS": v}))
    check("flag absent → off", not ts.enabled({}))
    check("Store refused with the flag off",
          await araises(_mk({}), ts.TxStoreError, "disabled"))
    check("Store refused on a volume without tx_state.test_volume", await araises(_mk(env_ok), ts.TxStoreError, "disabled"))
    check("create_test_volume refused outside a test gate",
          _raises(lambda: ts.create_test_volume(config.DB_PATH, env={}), ts.TxStoreError))
    ts.create_test_volume(config.DB_PATH, env=env_ok)
    check("Store refused on a test volume outside a test gate",
          await araises(_mk({"WEBTERM_TX_RECORDINGS": "1"}), ts.TxStoreError, "disabled"))
    s = store(env=env_ok)
    check("Store opens on a test volume under the gate + flag", s is not None)
    s.close()
    check("GAP_MARKER identical to core.GAP_MARKER", ts.GAP_MARKER == core.GAP_MARKER)
    check("CAP_HEADER_MAX identical to core", ts.CAP_HEADER_MAX == core.CAP_HEADER_MAX)


async def _mk(env):
    return store(env=env)


def _raises(fn, exc):
    try:
        fn()
    except exc:
        return True
    return False


async def g_publication():
    print("== publication, both descriptors + agent offset in one transaction (#3) ==")
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    check("RK committed at writer start", await row("SELECT 1 FROM session_keys WHERE sid=?", sid) is not None)
    check("no descriptor before data (nothing published empty)",
          await row("SELECT 1 FROM tx_descriptors WHERE sid=?", sid) is None)
    lg = await ledger(sid)
    check("two generations reserved + created (inode recorded) at start",
          sorted(lg.values()) == ["created", "created"])
    rec.feed_out(b"hello\r\n")
    rec.feed_cast(b'{"version": 2}\n' + cast_line(0.1, "hello\r\n"))
    S1 = await rec.checkpoint()
    d_out, d_cast = await desc(st, sid, "out"), await desc(st, sid, "cast")
    check("checkpoint: both descriptors version 1, live, counts = S",
          d_out.version == 1 and d_cast.version == 1 and d_out.generations[0].state == td.STATE_LIVE
          and S1["out_len"] == 7 and d_out.generations[0].plain_len == 7)
    ag = await row("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid)
    check("agent offset published with the descriptors", tuple(ag) == ("e1", 7))
    lg = await ledger(sid)
    check("ledger: published rows", sorted(lg.values()) == ["published", "published"])
    check("read back .out", await read_all(st, sid) == b"hello\r\n")
    # Eşec DB între instrucţiuni: nimic nu avansează; următorul checkpoint publică un superset.
    rec.feed_out(b"world\r\n")
    st.fault = faults({"txn-between"}, exc=sqlite3.OperationalError)
    ok = await araises(rec.checkpoint(), sqlite3.OperationalError)
    st.fault = None
    d2 = await desc(st, sid, "out")
    ag2 = await row("SELECT agent_offset FROM sessions WHERE id=?", sid)
    check("DB failure between statements: descriptors and offset unchanged together",
          ok and d2.version == 1 and ag2[0] == 7 and (await desc(st, sid, "cast")).version == 1)
    rec.feed_out(b"!")
    S = await rec.checkpoint()
    check("next checkpoint publishes the superset (no byte lost, none twice)",
          await read_all(st, sid) == b"hello\r\nworld\r\n!" and S["agent"] == ("e1", 15))
    check("committed_at set", await st.last_output_at(sid) is not None)
    check("exists / stats", await st.exists(sid, "out") and (await st.stats())["recordings"] >= 2)
    # COMMIT incert: commis → acceptat; necommis → reîncercat o dată cu ACEEAŞI captură.
    rec.feed_out(b"A")
    st.fault = faults({"post-commit"}, exc=sqlite3.OperationalError)
    v0 = (await desc(st, sid)).version
    await rec.checkpoint()
    check("uncertain COMMIT that committed → resolved from the DB (one version step)",
          (await desc(st, sid)).version == v0 + 1)
    rec.feed_out(b"B")
    st.fault = faults({"pre-commit"}, exc=sqlite3.OperationalError)
    await rec.checkpoint()
    st.fault = None
    check("uncertain COMMIT that did not commit → same capture retried once",
          (await desc(st, sid)).version == v0 + 2 and await read_all(st, sid) == b"hello\r\nworld\r\n!AB")
    await rec.close()
    st.close()


async def g_ordering():
    print("== coordinator: ordering, CAS, monotonic, lost race, cancellation (#14) ==")
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed_out(b"one")
    rec.feed_cast(b"h\n")
    await rec.checkpoint()
    plan_old = rec._plan({k: [rec.cur[k]] for k in ts.KIND_NAMES}, (rec.agent_epoch, rec.agent_offset))
    order = []
    slow = {"n": 0}

    def slow_fsync(p):
        if p == "fsync" and slow["n"] == 0:
            slow["n"] += 1
            time.sleep(0.05)
    st.fault = slow_fsync
    rec.feed_out(b"two")
    c1 = asyncio.ensure_future(rec.checkpoint())
    await asyncio.sleep(0)
    rec.feed_out(b"three")
    c2 = asyncio.ensure_future(rec.checkpoint())
    r1, r2 = await c1, await c2
    order = [r1["out_len"], r2["out_len"]]
    st.fault = None
    check("S2 captured after S1 commits after it (FIFO, lease end to end)", order == [6, 11])
    check("committed agent offset = end of committed prefix",
          (await row("SELECT agent_offset FROM sessions WHERE id=?", sid))[0] == 11)
    # Plan vechi publicat forţat după unul mai nou: CAS refuză.
    async with st.lease(sid):
        ok = await araises(rec._publish(plan_old), ts.Refused, "cas")
    check("stale plan (older capture) refused by the version CAS", ok)
    # Monotonie: versiune curentă, dar prefix mai mic.
    cur_out, cur_cast = await desc(st, sid, "out"), await desc(st, sid, "cast")
    plan_old.start = {"out": (cur_out.version, st.encode(cur_out)), "cast": (cur_cast.version, st.encode(cur_cast))}
    plan_old.agent_prev = rec.agent_committed
    async with st.lease(sid):
        ok = await araises(rec._publish(plan_old), ts.Refused, "regress")
    check("smaller prefix at the current version refused (monotonic check)", ok)
    plan_new = rec._plan({k: [rec.cur[k]] for k in ts.KIND_NAMES}, ("e1", 3))
    async with st.lease(sid):
        ok = await araises(rec._publish(plan_new), ts.Refused, "agent-regress")
    check("older agent offset refused", ok)
    check("refusals left the committed state intact",
          await read_all(st, sid) == b"onetwothree" and (await desc(st, sid)).version == cur_out.version)
    # Anularea apelantului nu anulează un job început.
    st.fault = slow_fsync
    slow["n"] = 0
    rec.feed_out(b"four")
    t = asyncio.ensure_future(rec.checkpoint())
    await asyncio.sleep(0.01)
    t.cancel()
    await asyncio.sleep(0.1)
    st.fault = None
    check("caller cancelled during fsync: the job still commits", await read_all(st, sid) == b"onetwothreefour")
    # Cursa pierdută: alt writer deţine sid-ul → jobul e abandonat, fd-urile închise.
    st.tokens[sid] = b"other"
    rec.feed_out(b"x")
    ok = await araises(rec.checkpoint(), ts.Refused, "stale-writer")
    await asyncio.sleep(0.01)
    check("job of a replaced writer dropped (stale-writer), recorder stops, fds closed",
          ok and rec.state == "replaced" and rec.cur["out"] is None)
    check("nothing published by the dropped job", await read_all(st, sid) == b"onetwothreefour")
    del st.tokens[sid]
    st.close()


async def crash_case(name, setup, expect, *, gen_limits=None):
    """Runs `setup(st, rec)` until a Crash, abandons the process state, boots a new Store and
    checks the recovery report and a second pass."""
    st = store(gen_limits=gen_limits)
    st.readopt_enabled = False
    sid = new_sid()
    await add_session(sid)
    ctx = {"sid": sid}
    try:
        await setup(st, sid, ctx)
    except (Crash, ts.RecorderLost):
        pass
    await asyncio.sleep(0.02)
    rec = st.recorders.get(sid) or ctx.get("rec")
    if rec is not None:
        rec._close_fds()
        if rec._task:
            rec._task.cancel()
    st.close()
    st2 = store(gen_limits=gen_limits)
    rep = await st2.recover()
    try:
        await expect(st2, sid, rep, ctx)
    except AssertionError as e:
        check(name, False, e)
    rep2 = await st2.recover()
    check(f"{name}: second recovery pass changes nothing", not rep2.changed(), rep2)
    st2.close()


async def g_crash():
    print("== crash at every publication point → recovery table (#1) ==")

    async def s_reserved(st, sid, ctx):
        st.fault = faults({"reserved"})
        await st.start_recorder(sid)

    async def e_reserved(st, sid, rep, ctx):
        lg = await ledger(sid)
        check("reservation committed, file absent → row deleted", lg == {} and rep.removed_rows and not names(sid), (lg, rep))
    await crash_case("reserved/absent", s_reserved, e_reserved)

    async def s_unrec(st, sid, ctx):
        st.fault = faults({"created-unrecorded"})
        await st.start_recorder(sid)

    async def e_unrec(st, sid, rep, ctx):
        lg = await ledger(sid)
        check("reservation committed, file present → collision, file left as orphan",
              list(lg.values()) == ["collision"] and len(names(sid)) == 1 and rep.orphans, (lg, rep))
    await crash_case("reserved/present", s_unrec, e_unrec)

    async def s_header(st, sid, ctx):
        st.fault = faults({"header"})
        await st.start_recorder(sid)

    async def e_header(st, sid, rep, ctx):
        lg = await ledger(sid)
        check("created + header, never published → unlinked (identity checked), row gone",
              list(lg.values()) == ["gone"] and not names(sid) and rep.unlinked, (lg, rep))
    await crash_case("created/header", s_header, e_header)

    async def s_unpub(st, sid, ctx):
        rec = await st.start_recorder(sid)
        rec.feed_out(b"never published")
        st.fault = faults({"fsync"})
        await rec.checkpoint()

    async def e_unpub(st, sid, rep, ctx):
        lg = await ledger(sid)
        ag = await row("SELECT agent_offset FROM sessions WHERE id=?", sid)
        check("records written, publication not committed → generations unlinked, offset still 0",
              set(lg.values()) == {"gone"} and not names(sid) and ag[0] == 0, (lg, names(sid)))
    await crash_case("created/records", s_unpub, e_unpub)

    async def s_live(st, sid, ctx):
        rec = await st.start_recorder(sid)
        rec.feed_out(b"committed;")
        rec.feed_cast(b"h\n")
        await rec.checkpoint()
        rec.feed_out(b"lost-tail")
        st.fault = faults({"fsync"})
        await rec.checkpoint()

    async def e_live(st, sid, rep, ctx):
        d = await desc(st, sid)
        data = await read_all(st, sid)
        v = await st.verify(sid)
        check("publication committed + bytes past phys_len → live becomes recovered, tail never read",
              d.generations[-1].state == td.STATE_RECOVERED and data == b"committed;"
              and any("past the committed prefix" in i for i in v["info"]) and v["ok"], (d, data, v))
        ag = await row("SELECT agent_offset FROM sessions WHERE id=?", sid)
        check("restart replays from the committed offset → no duplicate", ag[0] == len(b"committed;"))
        rec = await st.start_recorder(sid)
        rec.feed_out(b"lost-tail")              # re-livrat din ring de la offsetul comis
        await rec.checkpoint()
        check("re-adopted writer: committed prefix + replay, exactly once",
              await read_all(st, sid) == b"committed;lost-tail")
        await rec.close()
    await crash_case("published/live", s_live, e_live)

    async def s_seal(st, sid, ctx):
        rec = await st.start_recorder(sid)
        rec.feed_out(b"data")
        rec.feed_cast(b"h\n")
        await rec.checkpoint()
        n = {"i": 0}

        def hook(p):
            if p == "fsync":
                n["i"] += 1
                if n["i"] == 1:
                    raise Crash(p)
        st.fault = hook
        await rec.close()                       # SEAL scris, fsync-ul rolului pică

    async def e_seal(st, sid, rep, ctx):
        d = await desc(st, sid)
        v = await st.verify(sid)
        check("SEAL written, not published → recovered (the SEAL is a trailing byte)",
              d.generations[-1].state == td.STATE_RECOVERED and await read_all(st, sid) == b"data" and v["ok"], (d, v))
    await crash_case("seal/unpublished", s_seal, e_seal)

    async def s_sealed(st, sid, ctx):
        rec = await st.start_recorder(sid)
        rec.feed_out(b"done")
        rec.feed_cast(b"h\n")
        await rec.close()
        raise Crash("after close")

    async def e_sealed(st, sid, rep, ctx):
        d = await desc(st, sid)
        lg = await ledger(sid)
        check("seal published → nothing to do; never-published generations retired at close",
              [g.state for g in d.generations] == [td.STATE_SEALED] and not rep.changed()
              and sorted(lg.values()) == ["gone", "gone", "published", "published"], (d, lg, rep))
        v = await st.verify(sid)
        check("verify: sealed pair ok, no info", v["ok"] and not v["problems"], v)
    await crash_case("sealed", s_sealed, e_sealed)

    async def s_cap_t(st, sid, ctx):
        st.keep_bytes = 8
        rec = ctx["rec"] = await st.start_recorder(sid)
        rec.feed_out(b"0123456789abcdef")
        rec.feed_cast(b'{"h": 1}\n' + cast_line(0.5, "x") + cast_line(0.6, "y"))
        await rec.checkpoint()
        prefix, le = await rec._submit("roll_all")
        built = await rec._build_compacted(prefix, True)
        ctx["T"] = [g.gen_id.hex() for g in built.values()]
        st.fault = faults({"txn-between"})
        await rec._submit("cap_publish", prefix, built, le, True)

    async def e_cap_t(st, sid, rep, ctx):
        lg = await ledger(sid)
        check("cap T written, not published → T unlinked, P intact",
              all(lg[h] == "gone" for h in ctx["T"]) and await read_all(st, sid) == b"0123456789abcdef", lg)
    await crash_case("cap/T", s_cap_t, e_cap_t)

    async def s_cap_p(st, sid, ctx):
        st.keep_bytes = 8
        rec = ctx["rec"] = await st.start_recorder(sid)
        rec.feed_out(b"0123456789abcdef")
        rec.feed_cast(b'{"h": 1}\n' + cast_line(0.5, "x") + cast_line(0.6, "y"))
        await rec.checkpoint()
        ctx["P"] = [g.gen_id.hex() for g in (await desc(st, sid)).generations]
        st.fault = faults({"retire"})
        await rec.cap_now()

    async def e_cap_p(st, sid, rep, ctx):
        lg = await ledger(sid)
        check("cap published, P not unlinked → P unlinked by recovery, reader sees T",
              all(lg[h] == "gone" for h in ctx["P"]) and await read_all(st, sid) == ts.GAP_MARKER + b"89abcdef",
              (lg, await read_all(st, sid)))
    await crash_case("cap/P", s_cap_p, e_cap_p)

    async def s_orphans(st, sid, ctx):
        rec = await st.start_recorder(sid)
        rec.feed_out(b"x")
        rec.feed_cast(b"h\n")
        await rec.close()
        d = await desc(st, sid)
        ctx["listed"] = d.generations[0].gen_id.hex()
        # Fişier fără rând în registru, în spaţiul rezervat.
        fd = os.open(os.path.join(config.TRANSCRIPT_DIR, ts.gen_name(sid, "out", "ab" * 16)),
                     os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        await db.execute("UPDATE tx_files SET state='created' WHERE gen_id=?", ctx["listed"])
        raise Crash("x")

    async def e_orphans(st, sid, rep, ctx):
        check("file with no ledger row → orphan, left in place",
              ts.gen_name(sid, "out", "ab" * 16) in rep.orphans and ts.gen_name(sid, "out", "ab" * 16) in names(sid))
        check("ledger 'created' for a generation an authentic descriptor lists → never deleted, alarm",
              ("ledger-listed", ctx["listed"]) in rep.alarms and await read_all(st, sid) == b"x")
    await crash_case("orphans", s_orphans, e_orphans)

    async def s_missing(st, sid, ctx):
        rec = await st.start_recorder(sid)
        rec.feed_out(b"y")
        rec.feed_cast(b"h\n")
        await rec.close()
        d = await desc(st, sid)
        os.unlink(os.path.join(config.TRANSCRIPT_DIR, ts.gen_name(sid, "out", d.generations[0].gen_id.hex())))
        raise Crash("x")

    async def e_missing(st, sid, rep, ctx):
        status = (await row("SELECT status FROM tx_descriptors WHERE sid=? AND kind='out'", sid))[0]
        check("descriptor lists a missing file → damaged; readers refuse",
              status == "damaged" and await araises(read_all(st, sid), ts.TxStoreError, "damaged"))
    await crash_case("missing", s_missing, e_missing)

    async def s_rk(st, sid, ctx):
        st.fault = faults({"rk-committed"})
        await st.start_recorder(sid)

    async def e_rk(st, sid, rep, ctx):
        check("RK committed, no descriptor → nothing (empty recording, notFound)",
              await row("SELECT 1 FROM session_keys WHERE sid=?", sid) is not None
              and await araises(read_all(st, sid), ts.TxStoreError, "notFound"))
    await crash_case("rk", s_rk, e_rk)


async def g_nonce():
    print("== nonce: fresh gen_id every time, collisions retried (#2) ==")
    st = store()
    sid = new_sid()
    await add_session(sid)
    fixed = [b"\x11" * 16, b"\x11" * 16, b"\x33" * 16, b"\x22" * 16]
    pre = ts.gen_name(sid, "cast", "33" * 16)
    fd = os.open(os.path.join(config.TRANSCRIPT_DIR, pre), os.O_CREAT | os.O_WRONLY, 0o600)
    os.write(fd, b"not ours")
    os.close(fd)
    seq = iter(fixed)
    st.gen_id_source = lambda n: next(seq)
    rec = await st.start_recorder(sid)
    lg = await ledger(sid)
    check("UNIQUE collision → new id; O_EXCL collision → 'collision' row, new id",
          lg.get("11" * 16) == "created" and lg.get("22" * 16) == "created" and lg.get("33" * 16) == "collision"
          , lg)
    with open(os.path.join(config.TRANSCRIPT_DIR, pre), "rb") as f:
        check("the pre-existing file is never touched", f.read() == b"not ours")
    st.gen_id_source = os.urandom
    rec.feed_out(b"a")
    st.fault = faults({"write"}, exc=OSError)
    ok = await araises(rec.checkpoint(), ts.TxStoreError, "writeFailed")
    st.fault = None
    await rec.resume()
    rec.feed_out(b"a")
    await rec.checkpoint()
    await rec.close()
    all_ids = [r[0] for r in await db.fetchall("SELECT gen_id FROM tx_files WHERE sid=?", sid)]
    check("broken writer → new generation; every gen_id distinct", ok and len(all_ids) == len(set(all_ids)) >= 5, all_ids)
    st.close()


async def g_roll():
    print("== roll-over at 90 %, hard limit inside one batch, SEAL at close ==")
    st = store(gen_limits=(10, 1000))
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed_out(b"r" * 950)
    rec.feed_cast(b"h\n")
    await rec.checkpoint()
    d = await desc(st, sid)
    check("roll at 90 %: generation sealed after a successful checkpoint",
          [g.state for g in d.generations] == [td.STATE_SEALED], d)
    burst = bytes(range(256)) * 14                # 3584 B: crosses 90 % and the hard limit
    rec.feed_out(burst)
    await rec.checkpoint()
    d = await desc(st, sid)
    check("burst over the hard limit split inside the same job (no limit overrun)",
          len(d.generations) >= 4 and all(g.plain_len <= 1000 and g.data_count <= 10 for g in d.generations), d)
    check("burst readable exactly", await read_all(st, sid) == b"r" * 950 + burst)
    await rec.close()
    d = await desc(st, sid)
    v = await st.verify(sid)
    check("close: every generation sealed, verify ok",
          all(g.state == td.STATE_SEALED for g in d.generations) and v["ok"], v)
    lg = await ledger(sid)
    check("never-published generations retired at close (none left 'created')",
          "created" not in lg.values() and sum(1 for n in names(sid) if n.endswith(".wtx")) == len(d.generations)
          + len((await desc(st, sid, "cast")).generations), (lg, names(sid)))
    # Plaintext range reads across generation boundaries.
    data = b"r" * 950 + burst
    snap = await st.open(sid, "out", access=await access(st, sid))
    ok = True
    for a, b in ((0, 1), (990, 1010), (999, 2001), (1500, 4534), (4533, 4534), (100, 100), (4000, 99999)):
        got = await snap.read(a, b)
        ok = ok and got == data[a:b]
    snap.close()
    check("range reads on plaintext offsets across generations", ok)
    st.close()


def cap37(out_bytes, cast_bytes, keep):
    """3.7's `_cap_build` on real plaintext files (core.py), the reference output."""
    d = tempfile.mkdtemp(dir=BASE)
    po, pc = os.path.join(d, "o"), os.path.join(d, "c")
    with open(po, "wb") as f:
        f.write(out_bytes)
    with open(pc, "wb") as f:
        f.write(cast_bytes)
    job = core._CapJob()
    job.out_src, job.cast_src = os.open(po, os.O_RDONLY), os.open(pc, os.O_RDONLY)
    job.out_tmp, job.cast_tmp = open(po + ".t", "wb"), open(pc + ".t", "wb")
    job.out_end, job.cast_end = len(out_bytes), len(cast_bytes)
    job.out_copied = job.cast_copied = 0
    job.keep, job.fallback_ts, job.abort = keep, 0.0, threading.Event()
    core._cap_build(job)
    job.out_tmp.close()
    job.cast_tmp.close()
    os.close(job.out_src)
    os.close(job.cast_src)
    with open(po + ".t", "rb") as f, open(pc + ".t", "rb") as g:
        return f.read(), g.read()


async def g_cap():
    print("== cap byte-identical to 3.7, snapshot isolation, stale result, merge (#7) ==")
    st = store(gen_limits=(6, 700), max_bytes=1 << 30, keep_bytes=900)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    out_a = b"".join(b"line %04d of output\r\n" % i for i in range(120))
    cast_a = b'{"version": 2, "width": 80}\n' + b"".join(cast_line(i * 0.25, "chunk %d\r\n" % i) for i in range(90))
    for i in range(0, len(out_a), 300):
        rec.feed_out(out_a[i:i + 300])
        rec.feed_cast(cast_a[i:i + 300] if i + 300 < len(cast_a) else cast_a[i:])
        await rec.checkpoint()
    rec.feed_cast(cast_a[len(out_a) // 300 * 300 + 300:] if len(cast_a) > len(out_a) // 300 * 300 + 300 else b"")
    await rec.checkpoint()
    check("fixture: committed streams equal the input",
          await read_all(st, sid) == out_a and await read_all(st, sid, "cast") == cast_a)
    old = await st.open(sid, "out", access=await access(st, sid))
    P = [g.gen_id.hex() for g in (await desc(st, sid)).generations]
    le0 = rec.list_epoch
    ok = await rec.cap_now()
    rec.feed_out(b"after cap\r\n")
    rec.feed_cast(cast_line(99.0, "after\r\n"))
    await rec.checkpoint()
    exp_out, exp_cast = cap37(out_a, cast_a, 900)
    check("cap .out byte-identical to 3.7 (+ the tail L kept)", ok and await read_all(st, sid) == exp_out + b"after cap\r\n",
          (len(await read_all(st, sid)), len(exp_out)))
    check("cap .cast byte-identical to 3.7", await read_all(st, sid, "cast") == exp_cast + cast_line(99.0, "after\r\n"))
    check("list_epoch bumped once by the cap", rec.list_epoch == le0 + 1
          and (await row("SELECT list_epoch FROM tx_descriptors WHERE sid=? AND kind='out'", sid))[0] == le0 + 1)
    check("snapshot opened before the cap still reads the old inodes", await old.read(0, old.length) == out_a)
    old.close()
    lg = await ledger(sid)
    check("P retired and unlinked; T published", all(lg[h] == "gone" for h in P)
          and not any(h in n for h in P for n in names(sid)), [n for n in names(sid) if any(h in n for h in P)])
    check("verify after cap ok", (await st.verify(sid))["ok"])
    # Rezultat învechit: lista s-a schimbat între build şi publicare → T retras, nimic publicat.
    prefix, le = await rec._submit("roll_all")
    built = await rec._build_compacted(prefix, True)
    res = await rec._submit("cap_publish", prefix, built, le - 1, True)
    await rec._discard_built(built)
    lg = await ledger(sid)
    check("stale cap (list_epoch moved) → nothing published, T retired",
          res is False and all(lg[g.gen_id.hex()] == "gone" for g in built.values()))
    # Merge: concatenare exactă, fără bump de list_epoch.
    before = await read_all(st, sid)
    n_before = len((await desc(st, sid)).generations)
    le1 = rec.list_epoch
    ok = await rec.cap_now(truncate=False)
    d = await desc(st, sid)
    check("merge: exact concatenation, one generation for P, list_epoch unchanged",
          ok and await read_all(st, sid) == before and len(d.generations) < n_before and rec.list_epoch == le1,
          (n_before, len(d.generations)))
    await rec.close()
    st.close()


async def g_readers():
    print("== readers: watermark, index rules, budgets, tail / resume / preview (#4, #5) ==")
    st = store(gen_limits=(4096, 3 << 20), max_bytes=4 << 20, keep_bytes=0)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    big = os.urandom(3 << 20)
    rec.feed_out(big[:2 << 20])
    rec.feed_cast(b"h\n")
    S = await rec.checkpoint()
    rec.feed_out(big[2 << 20:])
    await rec.checkpoint()
    acc = await access(st, sid)
    data, end, epoch = await st.tail(sid, "out", 1000, access=acc)
    check("fresh attach: tail = last committed bytes, end, list_epoch", data == big[-1000:] and end == len(big) and epoch == 0)
    data, end, _ = await st.tail(sid, "out", 500, access=acc, end=S["out_len"])
    check("resume at an exact committed offset", data == big[S["out_len"] - 500:S["out_len"]] and end == S["out_len"])
    data, _, _ = await st.tail(sid, "out", 32 * 1024, access=acc)
    check("preview (32 KiB)", data == big[-32 * 1024:])
    # Octeţi peste watermark: scriem recorduri autentice fără să publicăm.
    rec.feed_out(b"UNPUBLISHED")
    await st.io(rec._append_run, rec.cur["out"], b"UNPUBLISHED", 0)
    rec.pending["out"] = bytearray()
    snap = await st.open(sid, "out", access=acc)
    check("authentic bytes past the watermark are never returned",
          snap.length == len(big) and (await snap.read(0, snap.length + 100))[-11:] != b"UNPUBLISHED")
    snap.close()
    await rec.close()
    d = await desc(st, sid)
    g0 = d.generations[0]
    idx = os.path.join(config.TRANSCRIPT_DIR, ts.gen_name(sid, "out", g0.gen_id.hex(), "idx"))
    for n in os.listdir(config.TRANSCRIPT_DIR):
        if n.startswith(sid) and n.endswith(".idx"):
            os.unlink(os.path.join(config.TRANSCRIPT_DIR, n))
    snap = await st.open(sid, "out", access=acc)
    ok = await araises(snap.read(g0.plain_len - 10, g0.plain_len, budget=ts.Budget(64 << 20, pre_first=ts.PARSE_WITH_INDEX)),
                       ts.TxStoreError, "limitExceeded")
    check("no index: a parse longer than the pre-first-byte budget is refused (limitExceeded)", ok)
    whole = await snap.read(0, g0.plain_len)
    check("full verified parse rebuilt the .idx (sealed generation)", whole == big[:g0.plain_len] and os.path.exists(idx))
    got = await snap.read(g0.plain_len - 10, g0.plain_len, budget=ts.Budget(64 << 20, pre_first=ts.PARSE_WITH_INDEX))
    check("with the authentic index the same read fits the 1 MiB budget", got == big[g0.plain_len - 10:g0.plain_len])
    snap.close()
    # Index pentru alt gen / alt watermark / alterat → ignorat (reparsare), niciodată folosit.
    good = open(idx, "rb").read()
    for label, blob in (("tampered", good[:-1] + bytes([good[-1] ^ 1])),
                        ("another data_count", tx.encode_index(st.rk_for(sid, bytes((await row("SELECT envelope FROM session_keys WHERE sid=?", sid))[0])),
                                                               kind=1, gen_id=g0.gen_id, data_count=g0.data_count - 1, entries=[]))):
        with open(idx, "wb") as f:
            f.write(blob)
        snap = await st.open(sid, "out", access=acc)
        ok = await araises(snap.read(g0.plain_len - 10, g0.plain_len, budget=ts.Budget(64 << 20, pre_first=ts.PARSE_WITH_INDEX)),
                           ts.TxStoreError, "limitExceeded")
        snap.close()
        check(f"{label} index refused (falls back to the budgeted parse)", ok)
    with open(idx, "wb") as f:
        f.write(good)
    # Record interior alterat în afara ferestrei: citirea ferestrei trece, verify îl prinde.
    path = os.path.join(config.TRANSCRIPT_DIR, ts.gen_name(sid, "out", g0.gen_id.hex()))
    with open(path, "r+b") as f:
        f.seek(g0.phys_len - 73 - 100)
        b = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([b[0] ^ 1]))
    snap = await st.open(sid, "out", access=acc)
    check("tampered record outside the window: range read before it still ok",
          await snap.read(0, 1000) == big[:1000])
    ok = await araises(snap.read(g0.plain_len - 50, g0.plain_len), ts.TxStoreError, "corrupt")
    snap.close()
    check("range read over the tampered record → corrupt + alarm",
          ok and any(a[0] == "transcript.corrupt" for a in st.alarms))
    v = await st.verify(sid)
    check("verify reports the tampered record", not v["ok"] and any("bad-tag" in p for p in v["problems"]), v)
    with open(path, "r+b") as f:
        f.seek(g0.phys_len - 73 - 100)
        b = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([b[0] ^ 1]))
    os.truncate(path, g0.phys_len - 73)
    v = await st.verify(sid)
    check("verify: sealed generation without its SEAL (shorter than phys_len) reported", not v["ok"], v)
    ok = await araises(st.open(sid, "out", access=acc), ts.TxStoreError, "damaged")
    check("open refuses a generation shorter than phys_len", ok)
    # Bugete de admitere.
    sid2 = new_sid()
    await add_session(sid2)
    r2 = await st.start_recorder(sid2)
    r2.feed_out(b"small")
    r2.feed_cast(b"h\n")
    await r2.close()
    a2 = await access(st, sid2)
    old_max = ts.MAX_SNAPSHOTS
    ts.MAX_SNAPSHOTS = len(st._snapshots) + 1
    s1 = await st.open(sid2, "out", access=a2)
    ok = await araises(st.open(sid2, "out", access=a2), ts.TxStoreError, "busy")
    ts.MAX_SNAPSHOTS = old_max
    check("snapshot budget → busy", ok)
    old_wait = ts.READ_WAIT_SECS
    ts.READ_WAIT_SECS = 0.05
    async with st.worker_slot():
        pass                                      # creează semaforul
    for _ in range(ts.READ_WORKERS):
        await st._sem.acquire()
    try:
        await s1.read(0, 5)
        ok = False
    except ts.TxStoreError as e:
        ok = e.reason == "busy"
    for _ in range(ts.READ_WORKERS):
        st._sem.release()
    ts.READ_WAIT_SECS = old_wait
    check("decrypt worker semaphore (4) → busy after the wait", ok)
    fds = st._gen_fds
    s1.last_used -= ts.SNAPSHOT_IDLE_SECS + 1
    st.sweep_idle()
    check("idle snapshot closed by the sweep, fds released", s1.closed and st._gen_fds == fds - 1)
    budget = {"used": ts.SEARCH_TOTAL_CAP - 2, "results": 0}
    got = await st.search_tail(sid2, access=a2, budget=budget)
    check("search: per-query total counted on decrypted bytes", got == b"ll" and budget["used"] == ts.SEARCH_TOTAL_CAP)
    check("search: past the total budget → metadata only (None)",
          await st.search_tail(sid2, access=a2, budget=budget) is None)
    st.close()


async def g_stream_revocation():
    print("== readers × revocation, fences, expiry, caches, redaction (#15) ==")
    clock = {"t": 1000.0}
    st = store(clock=lambda: clock["t"])
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    lines = [b'{"version": 2}\n'] + [cast_line(i, "token=secret%d and more text\r\n" % i) for i in range(40)]
    blob = b"".join(lines)
    for i in range(0, len(blob), 13):            # recorduri mici: liniile trec peste graniţe
        rec.feed_cast(blob[i:i + 13])
        rec.feed_out(b"o")
        await rec.checkpoint()
    await rec.close()

    def redact(line):
        return line.replace(b"secret", b"******")
    snap = await st.open(sid, "cast", access=await access(st, sid))
    got = b"".join([redact(x) async for x in ts.iter_lines(snap.iter(0, snap.length, chunk=7))])
    snap.close()
    check("incremental redaction on the decrypted stream = redaction of the whole (record boundaries invisible)",
          got == b"".join(redact(x) for x in lines))
    # Contorul sid-ului se schimbă în timpul fluxului → tăiat la următorul chunk.
    snap = await st.open(sid, "cast", access=await access(st, sid))
    it = snap.iter(0, snap.length, chunk=100)
    first = await it.__anext__()
    st.bump(sid)
    ok = await araises(it.__anext__(), ts.Revoked)
    snap.close()
    check("sid counter bump cuts an open stream at the next chunk (one chunk authorized)", ok and 0 < len(first) <= 100)
    snap = await st.open(sid, "cast", access=await access(st, sid))
    it = snap.iter(0, snap.length, chunk=100)
    await it.__anext__()
    st.tombstone(sid)
    ok = await araises(it.__anext__(), ts.Revoked)
    snap.close()
    check("erasure tombstone cuts the stream", ok)
    ok = await araises(st.open(sid, "cast", access=await access(st, sid)), ts.TxStoreError, "notFound")
    check("tombstoned recording cannot be opened (Owner recovery included)",
          ok and await araises(st.open(sid, "cast", access=await access(st, sid, owner_recovery=True)), ts.TxStoreError, "notFound"))
    st.tombstoned.discard(sid)
    # Bump global: fără re-autorizare → oprit; cu re-autorizare → continuă; refuzată → oprit.
    snap = await st.open(sid, "cast", access=await access(st, sid))
    it = snap.iter(0, 300, chunk=100)
    await it.__anext__()
    st.bump()
    check("global bump without a re-authorization path → aborted", await araises(it.__anext__(), ts.Revoked))
    snap.close()
    calls = []

    async def reauth_ok():
        calls.append("ok")
        return await access(st, sid)

    async def reauth_denied():
        raise PermissionError("denied")
    snap = await st.open(sid, "cast", access=await access(st, sid))
    it = snap.iter(0, 300, chunk=100, reauthorize=reauth_ok)
    await it.__anext__()
    st.bump()
    nxt = await it.__anext__()
    check("global bump → re-authorization → stream continues", 0 < len(nxt) <= 100 and calls == ["ok"])
    await it.aclose()
    it = snap.iter(0, 300, chunk=100, reauthorize=reauth_denied)
    await it.__anext__()
    st.bump()
    check("re-authorization denied → aborted", await araises(it.__anext__(), PermissionError))
    snap.close()
    # Expirare (not_after): fără bump de contor.
    snap = await st.open(sid, "cast", access=await access(st, sid, not_after=clock["t"] + 10))
    it = snap.iter(0, 300, chunk=100)
    await it.__anext__()
    clock["t"] += 11
    check("not_after passed → stream stops at the next chunk (no counter bump)", await araises(it.__anext__(), ts.Revoked))
    snap.close()
    # Gardul: re-autorizarea aşteaptă commit-ul revocării.
    order = []

    async def reauth_after():
        order.append("reauth")
        return await access(st, sid)
    snap = await st.open(sid, "cast", access=await access(st, sid))
    it = snap.iter(0, 300, chunk=100, reauthorize=reauth_after)
    await it.__anext__()

    async def revoke():
        async with st.revoking():
            await asyncio.sleep(0.05)
            order.append("commit")
    rt = asyncio.ensure_future(revoke())
    await asyncio.sleep(0)
    await it.__anext__()
    await rt
    await it.aclose()
    snap.close()
    check("fence: re-authorization waits for the revocation commit", order == ["commit", "reauth"], order)
    # Între autorizare şi deschiderea fd-urilor: refuz + fd-uri închise; cu re-autorizare → reuşeşte.
    fds = st._gen_fds
    acc = await access(st, sid)
    st.bump(sid)
    ok = await araises(st.open(sid, "cast", access=acc), ts.Revoked)
    check("revocation between authorization and open → refused, every fd closed", ok and st._gen_fds == fds)
    acc = await access(st, sid)
    st.bump(sid)
    snap = await st.open(sid, "cast", access=acc, reauthorize=reauth_ok)
    check("one retry from the authorization step succeeds", snap.length == len(blob))
    # Cache: cheia conţine versiunea, digestul listei, politica şi contoarele.
    cache = ts.ResponseCache(st, size=1)
    k1 = cache.key(snap, policy_version=1)
    check("cache put + get", cache.put(k1, b"R", snap.access) and cache.get(k1, snap.access) == b"R")
    check("cache key differs by redaction policy version", cache.key(snap, 2) != k1)
    st.bump(sid)
    a3 = await access(st, sid)
    check("bump drops the cache; an old key is never served", cache.get(k1, a3) is None)
    k_stale = k1
    check("a just-computed response under a stale key is not cached", cache.put(k_stale, b"R", a3) is False)
    check("serving with a revoked access raises before the cache is read",
          _raises(lambda: cache.get(cache.key(snap, 1), snap.access), ts.Revoked))
    snap.close()
    e1 = (await st.open(sid, "cast", access=a3))
    tag1 = e1.etag()
    e1.close()
    check("ETag stable for the same committed state", tag1 == (await st.open(sid, "cast", access=a3)).etag())
    for s in list(st._snapshots):
        s.close()
    # Range helper (download): offseturi în clar.
    check("Range: absent → 200 full", ts.parse_range(None, 100) == (200, 0, 100))
    check("Range: bytes=10-19 → 206", ts.parse_range("bytes=10-19", 100) == (206, 10, 20))
    check("Range: clamped to the length", ts.parse_range("bytes=90-500", 100) == (206, 90, 100))
    check("Range: suffix", ts.parse_range("bytes=-10", 100) == (206, 90, 100))
    check("Range: start ≥ length → 416", ts.parse_range("bytes=100-", 100)[0] == 416)
    check("Range: several ranges → 200 full", ts.parse_range("bytes=0-1,5-6", 100) == (200, 0, 100))
    # Owner recovery ridică DOAR carantina.
    await db.execute("UPDATE tx_descriptors SET status='quarantined' WHERE sid=? AND kind='cast'", sid)
    ok = await araises(st.open(sid, "cast", access=await access(st, sid)), ts.TxStoreError, "quarantined")
    s = await st.open(sid, "cast", access=await access(st, sid, owner_recovery=True))
    s.close()
    await db.execute("UPDATE tx_descriptors SET status='damaged' WHERE sid=? AND kind='cast'", sid)
    ok2 = await araises(st.open(sid, "cast", access=await access(st, sid, owner_recovery=True)), ts.TxStoreError, "damaged")
    check("quarantined: refused, Owner recovery may open; damaged: refused even for Owner recovery", ok and ok2)
    st.close()


async def g_downgrade():
    print("== plaintext readers and downgrade refusal ==")
    st = store()
    sid = new_sid()
    p = os.path.join(config.TRANSCRIPT_DIR, sid + ".out")
    with open(p, "wb") as f:
        f.write(b"legacy plaintext")
    check("plaintext not in the inventory → downgrade",
          await araises(read_all(st, sid), ts.TxStoreError, "downgrade"))
    s = os.stat(p)
    await db.execute("INSERT INTO tx_migration(sid, kind, dir, name, dev, ino, size, mtime_ns, state) "
                     "VALUES(?,?,?,?,?,?,?,?,'pending')", sid, "out", "transcripts", sid + ".out",
                     s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    check("inventoried pending plaintext readable (PlainSnapshot)", await read_all(st, sid) == b"legacy plaintext")
    await db.execute("INSERT OR REPLACE INTO tx_state(key, value) VALUES('recordings_format', 'wtx1')")
    check("recordings_format = wtx1 → plaintext refused", await araises(read_all(st, sid), ts.TxStoreError, "downgrade"))
    await db.execute("DELETE FROM tx_state WHERE key='recordings_format'")
    await db.execute("UPDATE tx_migration SET state='converted' WHERE sid=?", sid)
    check("converted row, descriptor missing → downgrade (not plaintext)",
          await araises(read_all(st, sid), ts.TxStoreError, "downgrade"))
    await db.execute("UPDATE tx_migration SET state='pending' WHERE sid=?", sid)
    with open(p, "ab") as f:
        f.write(b"!")
    check("plaintext changed since the inventory → refused", await araises(read_all(st, sid), ts.TxStoreError, "downgrade"))
    st.close()


async def g_pair_and_keys():
    print("== integrity of the .out/.cast pair, RK binding ==")
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed_out(b"out bytes")
    rec.feed_cast(b"cast bytes\n")
    await rec.close()
    check("pair verified ok", (await st.verify(sid))["ok"])
    d = await desc(st, sid, "cast")
    path = os.path.join(config.TRANSCRIPT_DIR, ts.gen_name(sid, "cast", d.generations[0].gen_id.hex()))
    with open(path, "r+b") as f:
        f.seek(100)
        b = f.read(1)
        f.seek(100)
        f.write(bytes([b[0] ^ 0xff]))
    v = await st.verify(sid)
    check("corrupt .cast after a good .out → problem names the cast", not v["ok"] and all(p.startswith("cast.") for p in v["problems"]), v)
    sid1 = new_sid()
    await add_session(sid1)
    r1 = await st.start_recorder(sid1)
    r1.feed_out(b"only out")
    await r1.close()
    v = await st.verify(sid1)
    check("one kind only → info, not corruption", v["ok"] and "one kind only" in v["info"], v)
    # Plic RK înlocuit cu un plic autentic al altei chei: hub-ul nu porneşte, cititorii refuză.
    await db.execute("UPDATE session_keys SET envelope=? WHERE sid=?", kr.wrap_under_kwk(KWK, kr.KT_RK, os.urandom(32)), sid1)
    st.drop_key(sid1)
    check("substituted RK envelope → writer refused (keyError)",
          await araises(st.start_recorder(sid1), ts.TxStoreError, "keyError"))
    check("substituted RK envelope → reader refused (keyError)", await araises(read_all(st, sid1), ts.TxStoreError, "keyError"))
    st.close()


async def g_backpressure():
    print("== backpressure, gap marker, write faults, worker loss (#19 subset) ==")
    st = store(pending_cap=100, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed_out(b"a" * 60)
    rec.feed_cast(b"h\n")
    await rec.checkpoint()
    gate = threading.Event()

    def hold(p):
        if p == "fsync":
            gate.wait(2)
    st.fault = hold
    rec.feed_out(b"b" * 60)
    inflight = asyncio.ensure_future(rec.checkpoint())
    await asyncio.sleep(0.02)
    rec.feed_out(b"c" * 30)                       # 60 în zbor + 30 în aşteptare
    rec.feed_out(b"d" * 30)                       # depăşeşte 100 → overflow
    check("overflow: pending dropped, degraded, agent offset not rewound while a job is in flight",
          rec.overflow and rec.degraded and rec.dropped == 60 and rec.agent_offset == 150)
    rec.feed_out(b"e" * 5)
    gate.set()
    await inflight
    st.fault = None
    check("the in-flight batch is never dropped", await read_all(st, sid) == b"a" * 60 + b"b" * 60)
    C = await rec.resume()
    check("resume re-reads the committed position from the DB", C[:3] == ("e1", 120, 120) and C[3] == 65, C)
    rec.feed_out(b"c" * 30)                       # din ring
    rec.gap(35, cast_ts=1.5)                      # ce ringul nu mai are
    await rec.checkpoint()
    data = await read_all(st, sid)
    check("one GAP_MARKER at the committed position, gap (position, size) recorded, degraded cleared",
          data == b"a" * 60 + b"b" * 60 + b"c" * 30 + ts.GAP_MARKER and rec.gaps == [(150, 35)] and not rec.degraded,
          (data[-60:], rec.gaps))
    # Plafonul pe proces.
    st.total_cap = st.buffered_total + 10
    rec.feed_out(b"z" * 11)
    check("process-wide cap (REC_BUFFER_TOTAL) → overflow", rec.overflow)
    st.total_cap = 1 << 20
    await rec.resume()
    # Eroare de scriere: writer stricat → generaţie nouă, live publicată devine recovered, reluare exactă.
    rec.feed_out(b"q" * 10)
    st.fault = faults({"write"}, exc=OSError)
    ok = await araises(rec.checkpoint(), ts.TxStoreError, "writeFailed")
    st.fault = None
    C = await rec.resume()
    rec.feed_out(b"q" * 10)
    await rec.checkpoint()
    d = await desc(st, sid)
    check("write fault: generation abandoned (recovered), new one opened, replay exactly once",
          ok and await read_all(st, sid) == data + b"q" * 10
          and [g.state for g in d.generations][-2:] == [td.STATE_RECOVERED, td.STATE_LIVE], d)
    # Workerul moare în mijlocul unui append → RecorderLost, readoptare din DB.
    readopted = []
    st.on_readopt = lambda s, r: readopted.append(r)
    rec.feed_out(b"lost in flight")
    st.fault = faults({"append"}, exc=ts._KillWorker)
    ok = await araises(rec.checkpoint(), ts.RecorderLost)
    for _ in range(50):
        if readopted:
            break
        await asyncio.sleep(0.02)
    st.fault = None
    check("worker killed mid-append: the caller's future resolves with RecorderLost", ok and rec.state == "lost")
    new = readopted[0] if readopted else None
    check("supervisor re-adopts from the DB only (committed offset, recovered generation)",
          new is not None and new.agent_committed == ("e1", (await row("SELECT agent_offset FROM sessions WHERE id=?", sid))[0])
          and (await desc(st, sid)).generations[-1].state == td.STATE_RECOVERED)
    if new is not None:
        new.feed_out(b"lost in flight")
        await new.checkpoint()
        check("replay after re-adoption: exactly once", await read_all(st, sid) == data + b"q" * 10 + b"lost in flight")
        await new.close()
    st.close()


async def g_misc():
    print("== epoch change, ledger compaction, keyring epoch binding ==")
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed_out(b"before")
    rec.feed_cast(b"h\n")
    await rec.checkpoint()
    await rec.change_epoch("e2")
    ag = await row("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid)
    rec.feed_out(b"after")
    await rec.checkpoint()
    d = await desc(st, sid)
    check("agent epoch change: old generation sealed, new epoch at offset 0, new generation",
          tuple(ag) == ("e2", 0) and [g.state for g in d.generations] == [td.STATE_SEALED, td.STATE_LIVE]
          and await read_all(st, sid) == b"beforeafter", (ag, d))
    await rec.close()
    await db.execute("UPDATE tx_files SET created=0 WHERE sid=? AND state='gone'", sid)
    n = await st.compact_ledger()
    check("ledger compaction drops old gone/collision rows", n >= 1)
    v = ts.keyring_epoch_value(KWK, INST, 5)
    check("keyring epoch binding: ok / DB older / newer / forged",
          ts.check_keyring_epoch(KWK, INST, 5, v) == "ok" and ts.check_keyring_epoch(KWK, INST, 6, v) == "rolled-back"
          and ts.check_keyring_epoch(KWK, INST, 4, v) == "newer"
          and ts.check_keyring_epoch(KWK, INST, 5, "5:" + "0" * 64) == "rolled-back")
    st.close()


async def main():
    await db.connect()
    try:
        await g_activation()
        await g_publication()
        await g_ordering()
        await g_crash()
        await g_nonce()
        await g_roll()
        await g_cap()
        await g_readers()
        await g_stream_revocation()
        await g_downgrade()
        await g_pair_and_keys()
        await g_backpressure()
        await g_misc()
    finally:
        await db.close()


asyncio.run(main())
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
import shutil  # noqa: E402
shutil.rmtree(BASE, ignore_errors=True)
sys.exit(1 if failed else 0)
