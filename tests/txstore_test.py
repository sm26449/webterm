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
import contextlib
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
    route = ts.OWNER_RECOVERY_ROUTE if kw.get("owner_recovery") else "test"
    return st.access(sid, "u1", route, **kw)


async def read_all(st, sid, kind="out", **kw):
    snap = await st.open(sid, kind, access=await access(st, sid, **kw))
    try:
        return await snap.read(0, snap.length)
    finally:
        snap.close()


def gp(rec):
    """(.out position, upstream size) of every published gap."""
    return [(g.out_pos, g.size) for g in rec.gaps]


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
    rec.feed(b"hello\r\n")
    rec.feed_cast_only(b'{"version": 2}\n' + cast_line(0.1, "hello\r\n"))
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
    rec.feed(b"world\r\n")
    st.fault = faults({"txn-between"}, exc=sqlite3.OperationalError)
    ok = await araises(rec.checkpoint(), sqlite3.OperationalError)
    st.fault = None
    d2 = await desc(st, sid, "out")
    ag2 = await row("SELECT agent_offset FROM sessions WHERE id=?", sid)
    check("DB failure between statements: descriptors and offset unchanged together",
          ok and d2.version == 1 and ag2[0] == 7 and (await desc(st, sid, "cast")).version == 1)
    rec.feed(b"!")
    S = await rec.checkpoint()
    check("next checkpoint publishes the superset (no byte lost, none twice)",
          await read_all(st, sid) == b"hello\r\nworld\r\n!" and S["agent"] == ("e1", 15))
    check("committed_at set", await st.last_output_at(sid) is not None)
    check("exists / stats", await st.exists(sid, "out") and (await st.stats())["recordings"] >= 2)
    # COMMIT incert: commis → acceptat; necommis → reîncercat o dată cu ACEEAŞI captură.
    rec.feed(b"A")
    st.fault = faults({"post-commit"}, exc=sqlite3.OperationalError)
    v0 = (await desc(st, sid)).version
    await rec.checkpoint()
    check("uncertain COMMIT that committed → resolved from the DB (one version step)",
          (await desc(st, sid)).version == v0 + 1)
    rec.feed(b"B")
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
    rec.feed(b"one")
    rec.feed_cast_only(b"h\n")
    await rec.checkpoint()
    plan_old = rec._plan((rec.agent_epoch, rec.agent_offset))
    order = []
    slow = {"n": 0}

    def slow_fsync(p):
        if p == "fsync" and slow["n"] == 0:
            slow["n"] += 1
            time.sleep(0.05)
    st.fault = slow_fsync
    rec.feed(b"two")
    c1 = asyncio.ensure_future(rec.checkpoint())
    await asyncio.sleep(0)
    rec.feed(b"three")
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
    plan_new = rec._plan(("e1", 3))
    async with st.lease(sid):
        ok = await araises(rec._publish(plan_new), ts.Refused, "agent-regress")
    check("older agent offset refused", ok)
    check("refusals left the committed state intact",
          await read_all(st, sid) == b"onetwothree" and (await desc(st, sid)).version == cur_out.version)
    # Anularea apelantului nu anulează un job început.
    st.fault = slow_fsync
    slow["n"] = 0
    rec.feed(b"four")
    t = asyncio.ensure_future(rec.checkpoint())
    await asyncio.sleep(0.01)
    t.cancel()
    await asyncio.sleep(0.1)
    st.fault = None
    check("caller cancelled during fsync: the job still commits", await read_all(st, sid) == b"onetwothreefour")
    # Cursa pierdută: alt writer deţine sid-ul → jobul e abandonat, fd-urile închise.
    st.tokens[sid] = b"other"
    rec.feed(b"x")
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
        rec.feed(b"never published")
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
        rec.feed(b"committed;")
        rec.feed_cast_only(b"h\n")
        await rec.checkpoint()
        rec.feed(b"lost-tail")
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
        rec.feed(b"lost-tail")              # re-livrat din ring de la offsetul comis
        await rec.checkpoint()
        check("re-adopted writer: committed prefix + replay, exactly once",
              await read_all(st, sid) == b"committed;lost-tail")
        await rec.close()
    await crash_case("published/live", s_live, e_live)

    async def s_seal(st, sid, ctx):
        rec = await st.start_recorder(sid)
        rec.feed(b"data")
        rec.feed_cast_only(b"h\n")
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
        rec.feed(b"done")
        rec.feed_cast_only(b"h\n")
        await rec.close()
        raise Crash("after close")

    async def e_sealed(st, sid, rep, ctx):
        d = await desc(st, sid)
        lg = await ledger(sid)
        check("seal published → nothing to do; close opens no throw-away generations",
              [g.state for g in d.generations] == [td.STATE_SEALED] and not rep.changed()
              and sorted(lg.values()) == ["published", "published"], (d, lg, rep))
        v = await st.verify(sid)
        check("verify: sealed pair ok, no info", v["ok"] and not v["problems"], v)
    await crash_case("sealed", s_sealed, e_sealed)

    async def s_cap_t(st, sid, ctx):
        st.keep_bytes = 8
        rec = ctx["rec"] = await st.start_recorder(sid)
        rec.feed(b"0123456789abcdef")
        rec.feed_cast_only(b'{"h": 1}\n' + cast_line(0.5, "x") + cast_line(0.6, "y"))
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
        rec.feed(b"0123456789abcdef")
        rec.feed_cast_only(b'{"h": 1}\n' + cast_line(0.5, "x") + cast_line(0.6, "y"))
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
        rec.feed(b"x")
        rec.feed_cast_only(b"h\n")
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
        rec.feed(b"y")
        rec.feed_cast_only(b"h\n")
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
    rec.feed(b"a")
    st.fault = faults({"write"}, exc=OSError)
    ok = await araises(rec.checkpoint(), ts.TxStoreError, "writeFailed")
    st.fault = None
    await rec.resume()
    rec.feed(b"a")
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
    rec.feed(b"r" * 950)
    rec.feed_cast_only(b"h\n")
    await rec.checkpoint()
    d = await desc(st, sid)
    check("roll at 90 %: generation sealed after a successful checkpoint",
          [g.state for g in d.generations] == [td.STATE_SEALED], d)
    burst = bytes(range(256)) * 14                # 3584 B: crosses 90 % and the hard limit
    rec.feed(burst)
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
        rec.feed(out_a[i:i + 300])
        rec.feed_cast_only(cast_a[i:i + 300] if i + 300 < len(cast_a) else cast_a[i:])
        await rec.checkpoint()
    rec.feed_cast_only(cast_a[len(out_a) // 300 * 300 + 300:] if len(cast_a) > len(out_a) // 300 * 300 + 300 else b"")
    await rec.checkpoint()
    check("fixture: committed streams equal the input",
          await read_all(st, sid) == out_a and await read_all(st, sid, "cast") == cast_a)
    old = await st.open(sid, "out", access=await access(st, sid))
    P = [g.gen_id.hex() for g in (await desc(st, sid)).generations]
    le0 = rec.list_epoch
    ok = await rec.cap_now()
    rec.feed(b"after cap\r\n")
    rec.feed_cast_only(cast_line(99.0, "after\r\n"))
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
    rec.feed(big[:2 << 20])
    rec.feed_cast_only(b"h\n")
    S = await rec.checkpoint()
    rec.feed(big[2 << 20:])
    await rec.checkpoint()
    acc = await access(st, sid)
    data, end, epoch = await st.tail(sid, "out", 1000, access=acc)
    check("fresh attach: tail = last committed bytes, end, list_epoch", data == big[-1000:] and end == len(big) and epoch == 0)
    data, end, _ = await st.tail(sid, "out", 500, access=acc, end=S["out_len"])
    check("resume at an exact committed offset", data == big[S["out_len"] - 500:S["out_len"]] and end == S["out_len"])
    data, _, _ = await st.tail(sid, "out", 32 * 1024, access=acc)
    check("preview (32 KiB)", data == big[-32 * 1024:])
    # Octeţi peste watermark: scriem recorduri autentice fără să publicăm.
    rec.feed(b"UNPUBLISHED")
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
    r2.feed(b"small")
    r2.feed_cast_only(b"h\n")
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
        rec.feed_cast_only(blob[i:i + 13])
        rec.feed(b"o")
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
    k1 = cache.key(snap, policy_version=1, representation="redacted")
    check("cache put + get", cache.put(k1, b"R", snap.access) and cache.get(k1, snap.access) == b"R")
    check("cache key differs by redaction policy version", cache.key(snap, 2, representation="redacted") != k1)
    st.bump(sid)
    a3 = await access(st, sid)
    check("bump drops the cache; an old key is never served", cache.get(k1, a3) is None)
    k_stale = k1
    check("a just-computed response under a stale key is not cached", cache.put(k_stale, b"R", a3) is False)
    check("serving with a revoked access raises before the cache is read",
          _raises(lambda: cache.get(cache.key(snap, 1, representation="redacted"), snap.access), ts.Revoked))
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
    # Owner recovery deschide DOAR `recovery` (carantina de continuitate ridicată de ruta ei);
    # `quarantined` nu-şi codifică motivul (ex. epoch keyring) → refuzat pentru oricine (M2).
    await db.execute("UPDATE tx_descriptors SET status='recovery' WHERE sid=? AND kind='cast'", sid)
    ok = await araises(st.open(sid, "cast", access=await access(st, sid)), ts.TxStoreError, "quarantined")
    s = await st.open(sid, "cast", access=await access(st, sid, owner_recovery=True))
    s.close()
    await db.execute("UPDATE tx_descriptors SET status='quarantined' WHERE sid=? AND kind='cast'", sid)
    ok3 = await araises(st.open(sid, "cast", access=await access(st, sid, owner_recovery=True)), ts.TxStoreError, "quarantined")
    await db.execute("UPDATE tx_descriptors SET status='damaged' WHERE sid=? AND kind='cast'", sid)
    ok2 = await araises(st.open(sid, "cast", access=await access(st, sid, owner_recovery=True)), ts.TxStoreError, "damaged")
    check("recovery: refused, Owner recovery may open; quarantined (reason unknown) and damaged: refused even for Owner recovery",
          ok and ok2 and ok3)
    check("owner_recovery cannot be set by another route",
          _raises(lambda: st.access(sid, "u1", "download", owner_recovery=True), ts.TxStoreError))
    forged = ts.Access(sid, "u1", ts.OWNER_RECOVERY_ROUTE, st.sid_epoch[sid], st.access_epoch, None, True)
    check("an Access not issued by the store is refused", await araises(st.open(sid, "cast", access=forged), ts.TxStoreError, "bad-access"))
    await db.execute("UPDATE tx_descriptors SET status='ok' WHERE sid=? AND kind='cast'", sid)
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
    rec.feed(b"out bytes")
    rec.feed_cast_only(b"cast bytes\n")
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
    r1.feed(b"only out")
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
    rec.feed(b"a" * 60)
    rec.feed_cast_only(b"h\n")
    await rec.checkpoint()
    gate = threading.Event()

    def hold(p):
        if p == "fsync":
            gate.wait(2)
    st.fault = hold
    rec.feed(b"b" * 60)
    inflight = asyncio.ensure_future(rec.checkpoint())
    await asyncio.sleep(0.02)
    rec.feed(b"c" * 30)                       # 60 în zbor + 30 în aşteptare
    rec.feed(b"d" * 30)                       # depăşeşte 100 → overflow
    check("overflow: pending dropped, degraded, agent offset not rewound while a job is in flight",
          rec.overflow and rec.degraded and rec.dropped == 60 and rec.agent_offset == 150)
    rec.feed(b"e" * 5)
    gate.set()
    await inflight
    st.fault = None
    check("the in-flight batch is never dropped", await read_all(st, sid) == b"a" * 60 + b"b" * 60)
    C = await rec.resume()
    check("resume re-reads the committed position from the DB", C[:3] == ("e1", 120, 120) and C[3] == 65, C)
    rec.feed(b"c" * 30)                       # din ring
    rec.gap(35, cast_ts=1.5)                      # ce ringul nu mai are
    await rec.checkpoint()
    data = await read_all(st, sid)
    check("one GAP_MARKER at the committed position, gap (position, size) recorded, degraded cleared",
          data == b"a" * 60 + b"b" * 60 + b"c" * 30 + ts.GAP_MARKER and gp(rec) == [(150, 35)] and not rec.degraded,
          (data[-60:], rec.gaps))
    # Plafonul pe proces.
    st.total_cap = st.buffered_total + 10
    rec.feed(b"z" * 11)
    check("process-wide cap (REC_BUFFER_TOTAL) → overflow", rec.overflow)
    st.total_cap = 1 << 20
    await rec.resume()
    # Eroare de scriere: writer stricat → generaţie nouă, live publicată devine recovered, reluare exactă.
    rec.feed(b"q" * 10)
    st.fault = faults({"write"}, exc=OSError)
    ok = await araises(rec.checkpoint(), ts.TxStoreError, "writeFailed")
    st.fault = None
    C = await rec.resume()
    rec.feed(b"q" * 10)
    await rec.checkpoint()
    d = await desc(st, sid)
    check("write fault: generation abandoned (recovered), new one opened, replay exactly once",
          ok and await read_all(st, sid) == data + b"q" * 10
          and [g.state for g in d.generations][-2:] == [td.STATE_RECOVERED, td.STATE_LIVE], d)
    # Workerul moare în mijlocul unui append → RecorderLost, readoptare din DB.
    readopted = []
    st.on_readopt = lambda s, r: readopted.append(r)
    rec.feed(b"lost in flight")
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
        new.feed(b"lost in flight")
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
    rec.feed(b"before")
    rec.feed_cast_only(b"h\n")
    await rec.checkpoint()
    await rec.change_epoch("e2")
    ag = await row("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid)
    rec.feed(b"after")
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


# ── review fixes (audit 2026-11-24, PR5a): every scenario of the review, as a regression ─────


class Hold:
    """A fault hook that parks the worker thread at `point` (the n-th time) until released."""

    def __init__(self, point, nth=1, exc=None):
        self.point, self.nth, self.exc = point, nth, exc
        self.seen = 0
        self.entered = threading.Event()
        self.go = threading.Event()

    def __call__(self, p):
        if p != self.point:
            return
        self.seen += 1
        if self.seen == self.nth:
            self.entered.set()
            self.go.wait(5)
            if self.exc is not None:
                raise self.exc(p)

    async def wait_entered(self):
        for _ in range(250):
            if self.entered.is_set():
                return True
            await asyncio.sleep(0.02)
        return False


def crash_recorder(st, rec):
    """Process death: the in-memory recorder is abandoned without any further publication."""
    rec._close_fds()
    if rec._task:
        rec._task.cancel()
    st.close()


async def g_review_h1():
    print("== review H1: a failed publication stays the retry unit (both kinds + offset together) ==")
    st = store()
    st.readopt_enabled = False
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    c1, c2 = cast_line(0.1, "A"), cast_line(0.2, "B")
    rec.feed(b"A")
    rec.feed_cast_only(b"h\n" + c1)
    await rec.checkpoint()
    # .out + .cast scrise, publicarea pică; următorul lot atinge DOAR .out.
    rec.feed(b"B")
    rec.feed_cast_only(c2)
    st.fault = faults({"txn-between"}, exc=sqlite3.OperationalError)
    ok = await araises(rec.checkpoint(), sqlite3.OperationalError)
    st.fault = None
    rec.feed(b"C")
    await rec.checkpoint()
    ag = await row("SELECT agent_offset FROM sessions WHERE id=?", sid)
    check("failed publication with .cast written, next batch .out only: .cast published WITH the offset",
          ok and ag[0] == 3 and await read_all(st, sid, "cast") == b"h\n" + c1 + c2
          and await read_all(st, sid) == b"ABC", (ag, await read_all(st, sid, "cast")))
    # Eşec, apoi un checkpoint fără date noi: tot ce e scris se publică (nu întoarce watermark-ul vechi).
    rec.feed(b"D")
    rec.feed_cast_only(cast_line(0.3, "D"))
    st.fault = faults({"txn-between"}, exc=sqlite3.OperationalError)
    await araises(rec.checkpoint(), sqlite3.OperationalError)
    st.fault = None
    S = await rec.checkpoint()
    check("failed publication, then an EMPTY checkpoint: the written batch is published",
          S["out_len"] == 4 and S["agent"] == ("e1", 4) and (await desc(st, sid, "cast")).generations[-1].plain_len
          == len(b"h\n" + c1 + c2 + cast_line(0.3, "D")), S)
    # Restart după o publicare eşuată: reluarea de la offsetul comis dă exact octeţii de după el.
    rec.feed(b"E")
    rec.feed_cast_only(cast_line(0.4, "E"))
    st.fault = faults({"txn-between"}, exc=sqlite3.OperationalError)
    await araises(rec.checkpoint(), sqlite3.OperationalError)
    st.fault = None
    crash_recorder(st, rec)
    st2 = store()
    st2.readopt_enabled = False
    await st2.recover()
    r2 = await st2.start_recorder(sid)
    off = r2.agent_committed[1]
    agent_stream = b"ABCDE"                       # ce are ringul agentului
    r2.feed(agent_stream[off:])
    r2.feed_cast_only(cast_line(0.4, "E"))
    await r2.checkpoint()
    check("restart after a failed publication: replay from the committed offset, no byte skipped or doubled",
          off == 4 and await read_all(st2, sid) == b"ABCDE"
          and (await read_all(st2, sid, "cast")).count(cast_line(0.4, "E")) == 1, (off, await read_all(st2, sid)))
    await r2.close()
    st2.close()

    # gap: păstrat până la publicarea reuşită.
    st = store(pending_cap=100, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"a" * 10)
    rec.feed_cast_only(b"h\n")
    await rec.checkpoint()
    rec.feed(b"x" * 200)                       # overflow
    C = await rec.resume()
    rec.gap(200, cast_ts=1.0)
    st.fault = faults({"txn-between"}, exc=sqlite3.OperationalError)
    await araises(rec.checkpoint(), sqlite3.OperationalError)
    st.fault = None
    gaps_after_fail = list(rec.gaps)
    await rec.checkpoint()
    check("gap recorded only once its marker is published (not consumed by a failed publication)",
          gaps_after_fail == [] and gp(rec) == [(10, 200)]
          and await read_all(st, sid) == b"a" * 10 + ts.GAP_MARKER and C[1] == 10, (gaps_after_fail, rec.gaps))
    # Publicare eşuată, apoi overflow + resume: C include octeţii scrişi (publicaţi la resync).
    rec.feed(b"X")
    st.fault = faults({"txn-between"}, exc=sqlite3.OperationalError)
    await araises(rec.checkpoint(), sqlite3.OperationalError)
    st.fault = None
    rec.feed(b"y" * 200)
    C = await rec.resume()
    out_now = await read_all(st, sid)
    check("resume after a failed publication: written bytes published with their offset, C after them",
          C[1] == 11 and out_now.endswith(ts.GAP_MARKER + b"X"), (C, out_now[-5:]))
    # Publicarea pică şi la resync → generaţiile abandonate, C = poziţia comisă, reluare exactă.
    rec.feed(b"Y")
    st.fault = faults({"txn-between"}, exc=sqlite3.OperationalError, times=2)
    await araises(rec.checkpoint(), sqlite3.OperationalError)
    rec.feed(b"z" * 200)
    C = await rec.resume()
    st.fault = None
    rec.feed(b"Y")                             # reluarea hub-ului de la C
    await rec.checkpoint()
    d = await desc(st, sid)
    check("publication failing again at resume: writers abandoned (recovered), offset not advanced, replay once",
          C[1] == 11 and await read_all(st, sid) == out_now + b"Y"
          and td.STATE_RECOVERED in [g.state for g in d.generations], (C, d))
    await rec.close()
    st.close()

    # COMMIT incert + poziţia agentului mutată independent: nu e „committed" → readoptare.
    st = store()
    st.readopt_enabled = False
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"q")
    rec.feed_cast_only(b"h\n")
    await rec.checkpoint()

    def moved(p):
        if p == "post-commit":
            con = sqlite3.connect(str(config.DB_PATH), timeout=5)
            con.execute("UPDATE sessions SET agent_offset=999 WHERE id=?", (sid,))
            con.commit()
            con.close()
            raise sqlite3.OperationalError("lost the COMMIT reply")
    rec.feed(b"r")
    st.fault = moved
    ok = await araises(rec.checkpoint(), ts.RecorderLost)
    st.fault = None
    check("uncertain COMMIT, agent position moved independently: not taken as committed (re-adoption)",
          ok and rec.state == "lost")
    st.close()


async def g_review_h2():
    print("== review H2: epoch change and close are cuts in the FIFO; nothing lost or mis-attributed ==")
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"before")
    rec.feed_cast_only(b"h\n")
    await rec.checkpoint()
    rec.feed(b"-tail")                         # vechiul epoch, încă necapturat
    hold = Hold("fsync")
    st.fault = hold
    fut = asyncio.ensure_future(rec.change_epoch("e2"))
    entered = await hold.wait_entered()
    acc1 = rec.feed(b"NEW1")                   # noul epoch, sosit în timpul comutării
    rec.feed_cast_only(cast_line(0.1, "NEW1"))
    hold.go.set()
    await fut
    st.fault = None
    ag_switch = tuple(await row("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid))
    out_switch = await read_all(st, sid)
    await rec.checkpoint()
    ag = tuple(await row("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid))
    d = await desc(st, sid)
    check("output during the epoch switch: accepted for the new epoch, not published before the switch",
          entered and acc1 is True and ag_switch == ("e2", 0) and out_switch == b"before-tail", (ag_switch, out_switch))
    check("…then published under the new epoch at its own offset, after the old epoch's tail, in order",
          ag == ("e2", 4) and await read_all(st, sid) == b"before-tailNEW1"
          and d.generations[-1].plain_len == 4 and d.generations[-2].state == td.STATE_SEALED, (ag, d))
    rec.feed(b"x")
    f1 = rec.change_epoch("e3")
    try:
        rec.change_epoch("e4")
        two = False
    except ts.TxStoreError as e:
        two = e.reason == "busy"
    await f1
    check("one epoch change at a time (a second one is refused, not interleaved)", two)
    await rec.close()
    st.close()

    # Fără descriptor: comutarea trece prin aceeaşi tranzacţie (CAS pe poziţie).
    st = store()
    st.readopt_enabled = False
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    await db.execute("UPDATE sessions SET agent_offset=77 WHERE id=?", sid)   # mutată din afară
    ok = await araises(rec.change_epoch("e2"), ts.RecorderLost)
    ag = tuple(await row("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid))
    check("epoch switch without a descriptor: CAS on the agent position (moved → refused, re-adopted)",
          ok and ag == ("e1", 77) and rec.state == "lost", ag)
    st.close()
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    await rec.change_epoch("e2")
    ag = tuple(await row("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid))
    check("epoch switch without a descriptor commits (e2, 0)", ag == ("e2", 0) and rec.agent_committed == ("e2", 0))

    # Close: ingress oprit la apel; tot ce s-a acceptat înainte se publică; restul refuzat explicit.
    rec.feed(b"one")
    rec.feed_cast_only(b"h\n")
    hold = Hold("fsync")
    st.fault = hold
    cf = asyncio.ensure_future(rec.close())
    entered = await hold.wait_entered()
    late = rec.feed(b"late")
    state = rec.ingress()
    hold.go.set()
    res = await cf
    st.fault = None
    check("close drains what was accepted before it; output during close refused with a clear state",
          entered and late is False and state == "closing" and rec.rejected == 4
          and await read_all(st, sid) == b"one" and res["rejected"] == 4, (late, state, res))
    st.close()

    # Close în overflow: lipsă explicită (marker la capăt, mărime raportată, alarmă).
    st = store(pending_cap=50, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"k" * 10)
    rec.feed_cast_only(b"h\n")
    await rec.checkpoint()
    rec.feed(b"z" * 100)
    res = await rec.close(cast_ts=9.0)
    ag = await row("SELECT agent_offset FROM sessions WHERE id=?", sid)
    check("close during an overflow: one GAP_MARKER at the end, size reported, offset not advanced",
          await read_all(st, sid) == b"k" * 10 + ts.GAP_MARKER and res["lost"] == 100 and ag[0] == 10
          and any(a[0] == "transcript.gap" for a in st.alarms) and gp(rec) == [(10, 100)], (res, ag))
    st.close()


async def g_review_h3():
    print("== review H3: fd lifetime — close never releases an fd a worker thread still reads ==")
    st = store(gen_limits=(4096, 1 << 20))
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    data = os.urandom(300 * 1024)
    rec.feed(data)
    rec.feed_cast_only(b"h\n")
    await rec.close()
    other = os.path.join(BASE, "other.bin")
    with open(other, "wb") as f:
        f.write(b"\xEE" * (400 * 1024))
    snap = await st.open(sid, "out", access=await access(st, sid))
    fds = [fd for _g, fd, _s in snap.gens]
    gen_fds = st._gen_fds
    hold = Hold("pread")
    st.fault = hold
    rt = asyncio.ensure_future(snap.read(0, snap.length))
    entered = await hold.wait_entered()
    snap.last_used -= ts.SNAPSHOT_IDLE_SECS + 1
    st.sweep_idle()                                # închidere logică în timpul pread-ului
    still_open = all(_fd_open(fd) for fd in fds)
    reused = os.open(other, os.O_RDONLY)          # încercare de reutilizare a numărului de fd
    hold.go.set()
    try:
        got = await rt
    except ts.TxStoreError as e:
        got = e.reason
    st.fault = None
    closed_after = not any(_fd_open(fd) for fd in fds)
    os.close(reused)
    check("snapshot closed during an in-flight read: its fds stay open until the read returns",
          entered and still_open and reused not in fds and st._gen_fds == gen_fds - len(fds) and snap.closed,
          (entered, still_open, reused, fds))
    check("…and the read never returns another file's bytes (data or aborted)",
          got == data or got == "aborted", got if isinstance(got, str) else got[:8])
    check("…the fds are closed once the last reader returned", closed_after)
    # PlainSnapshot: identitatea fd-ului verificată înaintea FIECĂREI citiri.
    psid = new_sid()
    p = os.path.join(config.TRANSCRIPT_DIR, psid + ".out")
    with open(p, "wb") as f:
        f.write(b"P" * 1000)
    s = os.stat(p)
    await db.execute("INSERT INTO tx_migration(sid, kind, dir, name, dev, ino, size, mtime_ns, state) "
                     "VALUES(?,?,?,?,?,?,?,?,'pending')", psid, "out", "transcripts", psid + ".out",
                     s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    ps = await st.open(psid, "out", access=await access(st, psid))
    o = os.open(other, os.O_RDONLY)
    os.dup2(o, ps.fd)                              # numărul de fd arată acum spre alt fişier
    os.close(o)
    ok = await araises(ps.read(0, 100), ts.TxStoreError, "downgrade")
    ps.close()
    check("PlainSnapshot: fd number now naming another inode → refused before any byte is read", ok)
    q = os.path.join(config.TRANSCRIPT_DIR, new_sid() + ".out")
    with open(q, "wb") as f:
        f.write(b"Q" * 10)
    qs = os.stat(q)
    qsid = new_sid()
    await db.execute("INSERT INTO tx_migration(sid, kind, dir, name, dev, ino, size, mtime_ns, state) "
                     "VALUES(?,?,?,?,?,?,?,?,'pending')", qsid, "out", "transcripts", os.path.basename(q),
                     qs.st_dev, qs.st_ino, qs.st_size, qs.st_mtime_ns)
    check("PlainSnapshot: an inventory row naming another sid's file → refused",
          await araises(read_all(st, qsid), ts.TxStoreError, "downgrade"))
    # Anulare (repetată) în timpul deschiderii: nimic construit nu rămâne înregistrat / deschis.
    before = (st._gen_fds, st._slots, len(st._snapshots))
    hold = Hold("open-fds")
    st.fault = hold
    ot = asyncio.ensure_future(st.open(sid, "out", access=await access(st, sid)))
    entered = await hold.wait_entered()
    ot.cancel()
    await asyncio.sleep(0.01)
    ot.cancel()
    hold.go.set()
    try:
        await ot
        cancelled = False
    except asyncio.CancelledError:
        cancelled = True
    st.fault = None
    check("open cancelled twice while the thread builds: the built snapshot is closed, budgets restored",
          entered and cancelled and (st._gen_fds, st._slots, len(st._snapshots)) == before,
          (entered, cancelled, before, (st._gen_fds, st._slots, len(st._snapshots))))
    # Admitere atomică: două deschideri concurente pe ultimul slot → exact una trece.
    old_max = ts.MAX_SNAPSHOTS
    ts.MAX_SNAPSHOTS = st._slots + 1
    a = await access(st, sid)
    r = await asyncio.gather(st.open(sid, "out", access=a), st.open(sid, "out", access=a), return_exceptions=True)
    ts.MAX_SNAPSHOTS = old_max
    oks = [x for x in r if isinstance(x, ts.Snapshot)]
    busy = [x for x in r if isinstance(x, ts.TxStoreError) and x.reason == "busy"]
    for x in oks:
        x.close()
    check("snapshot admission is reserved atomically (concurrent opens on the last slot: one busy)",
          len(oks) == 1 and len(busy) == 1, r)
    # Store.close cu un cititor în zbor: dir_fd şi conexiunile rămân până se întoarce thread-ul.
    st2 = store()
    snap = await st2.open(sid, "out", access=await access(st2, sid))
    hold = Hold("pread")
    st2.fault = hold
    rt = asyncio.ensure_future(snap.read(0, 1000))
    entered = await hold.wait_entered()
    dfd = st2.dir_fd
    st2.close()
    kept = st2.dir_fd is not None and _fd_open(dfd)
    hold.go.set()
    try:
        await rt
    except ts.TxStoreError:
        pass
    check("Store.close during a read: the directory fd is released only after the worker returned",
          entered and kept and st2.dir_fd is None)
    st.close()


def _fd_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


async def g_review_m():
    print("== review M1–M4 + activation gate ==")
    # M1: porniri concurente.
    st = store()
    sid = new_sid()
    await add_session(sid)
    r = await asyncio.gather(st.start_recorder(sid), st.start_recorder(sid), return_exceptions=True)
    recs = [x for x in r if isinstance(x, ts.Recorder)]
    busy = [x for x in r if isinstance(x, ts.TxStoreError) and x.reason == "busy"]
    if recs:
        recs[0].feed(b"one")
        recs[0].feed_cast_only(b"h\n")
        await recs[0].close()
    check("two concurrent start_recorder: one writer, the other refused (no recovery over the first)",
          len(recs) == 1 and len(busy) == 1 and await read_all(st, sid) == b"one", r)
    # M1: ENOSPC la a doua generaţie la pornire → nimic lăsat în urmă.
    sid = new_sid()
    await add_session(sid)
    nfd = len(os.listdir("/proc/self/fd"))
    st.fault = faults({"header"}, exc=lambda p: OSError(28, "No space left on device"), times=1)
    hook = st.fault
    calls = {"n": 0}

    def second_header(p):
        if p == "header":
            calls["n"] += 1
            if calls["n"] == 2:
                hook(p)
    st.fault = second_header
    ok = await araises(st.start_recorder(sid), OSError)
    st.fault = None
    lg = await ledger(sid)
    check("ENOSPC at the second generation on start: fds closed, generations retired, token dropped",
          ok and len(os.listdir("/proc/self/fd")) == nfd and sid not in st.tokens
          and set(lg.values()) <= {"gone"} and not [n for n in names(sid) if n.endswith(".wtx")], (lg, names(sid)))
    rec = await st.start_recorder(sid)
    check("…and a later start works", rec.state == "running")
    # M1: un SEAL/fsync eşuat la roll = defect de scriere, recorderul rămâne utilizabil.
    rec.feed(b"pre")
    rec.feed_cast_only(b"h\n")
    await rec.checkpoint()
    st.fault = faults({"seal"}, exc=OSError)
    ok = await araises(rec.cap_now(), ts.TxStoreError, "writeFailed")
    st.fault = None
    C = await rec.resume()
    rec.feed(b"post")
    await rec.checkpoint()
    check("seal failure during a roll → writeFailed + resume, recorder keeps a current generation",
          ok and rec.state == "running" and all(rec.cur[k] is not None for k in ts.KIND_NAMES)
          and await read_all(st, sid) == b"prepost" and C[1] == 3, (C, await read_all(st, sid)))
    await rec.close()
    # M1: shutdown cu un worker blocat: aşteptat cu limită, fără readoptare, alarmă.
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    old = ts.SHUTDOWN_SECS
    ts.SHUTDOWN_SECS = 0.1
    hold = Hold("fsync")
    st.fault = hold
    rec.feed(b"x")
    cp = asyncio.ensure_future(rec.checkpoint())
    await hold.wait_entered()
    await st.shutdown()
    blocked_alarm = any(a[0] == "transcript.shutdown" and "fds abandoned" in a[1] for a in st.alarms)
    hold.go.set()
    with contextlib.suppress(BaseException):
        await cp
    await asyncio.sleep(0.05)
    ts.SHUTDOWN_SECS = old
    st.fault = None
    check("shutdown with a blocked worker: bounded wait, alarm, no re-adoption",
          blocked_alarm and rec._task.done() and st.recorders.get(sid) is rec and rec.state == "lost",
          (blocked_alarm, rec._task.done(), st.alarms[-3:], list(st.recorders)))
    st.close()

    # M2: re-autorizarea nu poate schimba subiectul; cache-ul e legat de sid şi rută.
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"m2 data")
    rec.feed_cast_only(b"h\n")
    await rec.close()
    other = new_sid()

    async def reauth_other_principal():
        return st.access(sid, "someone-else", "test")
    acc = await access(st, sid)
    st.bump(sid)
    ok = await araises(st.open(sid, "out", access=acc, reauthorize=reauth_other_principal), ts.Revoked, "bad-access")
    check("re-authorization returning another principal's grant → refused", ok)
    snap = await st.open(sid, "out", access=await access(st, sid))
    it = snap.iter(0, snap.length, chunk=2, reauthorize=reauth_other_principal)
    await it.__anext__()
    st.bump()
    ok = await araises(it.__anext__(), ts.Revoked, "bad-access")
    await it.aclose()
    check("stream re-authorization with another grant → aborted", ok)
    snap.close()
    snap = await st.open(sid, "out", access=await access(st, sid))
    cache = ts.ResponseCache(st, size=2)
    k = cache.key(snap, 1, representation="raw")
    cache.put(k, b"R", snap.access)
    check("cache refuses an Access for another sid (or route)",
          _raises(lambda: cache.get(k, st.access(other, "u1", "test")), ts.TxStoreError)
          and _raises(lambda: cache.get(k, st.access(sid, "u1", "replay")), ts.TxStoreError))
    check("raw and redacted responses never share a cache key",
          cache.key(snap, 1, representation="raw") != cache.key(snap, 1, representation="redacted"))
    snap.close()
    clock = {"t": 1000.0}
    st.clock = lambda: clock["t"]

    def expire(p):
        if p == "pread":
            clock["t"] += 100
    snap = await st.open(sid, "out", access=await access(st, sid, not_after=1050.0))
    st.fault = expire
    ok = await araises(snap.read(0, snap.length), ts.Revoked)
    st.fault = None
    snap.close()
    check("access expiring during the decrypt → nothing handed over", ok)
    st.clock = time.time
    st.close()

    # M3: linie completă prea lungă; verify cu buget tare; plafonul fizic la I/O.
    async def one(c):
        yield c
    try:
        [x async for x in ts.iter_lines(one(b"x" * 100 + b"\n"), max_line=10)]
        over = False
    except ts.TxStoreError as e:
        over = e.reason == "limitExceeded"
    check("iter_lines: a complete line longer than the cap is refused before it is yielded", over)
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(os.urandom(64 * 1024))
    rec.feed_cast_only(b"h\n")
    await rec.close()
    v = await st.verify(sid, budget=1024)
    check("verify: a generation larger than the pass budget is not verified (limitExceeded, not ok)",
          not v["ok"] and v["limitExceeded"] and any("limitExceeded" in p for p in v["problems"]), v)
    d = await desc(st, sid)
    fd = os.open(os.path.join(config.TRANSCRIPT_DIR, ts.gen_name(sid, "out", d.generations[0].gen_id.hex())), os.O_RDONLY)
    b = ts.Budget(10, phys=50)
    pr = ts._PRead(fd, 0, limit=40, budget=b)
    first = pr.read(100)
    try:
        pr.read(100)
        cut = len(first) == 40
    except ts.TxStoreError:
        cut = False
    b2 = ts.Budget(10, phys=50)
    try:
        ts._PRead(fd, 0, limit=1000, budget=b2).read(100)
        phys_refused = False
    except ts.TxStoreError as e:
        phys_refused = e.reason == "limitExceeded" and b2.phys_used == 0
    os.close(fd)
    check("parse reads never pass phys_len, and the physical budget is charged BEFORE the pread",
          cut and phys_refused)
    st.close()

    # M4: cap pe o înregistrare istorică cu un singur kind.
    st = store(max_bytes=1 << 30, keep_bytes=100)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    blob = os.urandom(5000)
    rec.feed(blob)
    await rec.checkpoint()
    ok = await rec.cap_now(truncate=True)
    check("cap of a one-kind recording: 3.7 rule on its own stream (no capOneKind failure)",
          ok and await read_all(st, sid) == ts.GAP_MARKER + blob[-100:])
    await rec.close()
    st.close()

    # Poarta de activare.
    env = {"WEBTERM_TX_RECORDINGS": "1", "WEBTERM_TEST_GATE": "0"}
    check("WEBTERM_TEST_GATE=0 is off (not truthy)", not ts.test_gate(env) and not ts.test_gate({"WEBTERM_TEST_GATE": "true"}))
    check("Store refused with WEBTERM_TEST_GATE=0", await araises(_mk(env), ts.TxStoreError, "disabled"))
    outside = os.path.join(os.path.dirname(__file__), "no-such-volume.db")
    check("create_test_volume refused outside a harness temp dir (nothing created)",
          _raises(lambda: ts.create_test_volume(outside), ts.TxStoreError) and not os.path.exists(outside))
    real = os.path.join(BASE, "real.db")
    con = sqlite3.connect(real)
    con.executescript("CREATE TABLE users(id INTEGER); CREATE TABLE hosts(id INTEGER); "
                      "CREATE TABLE tx_state(key TEXT PRIMARY KEY, value TEXT); INSERT INTO users VALUES(1);")
    con.commit()
    con.close()
    check("create_test_volume refused on a DB with users rows (a real installation)",
          _raises(lambda: ts.create_test_volume(real), ts.TxStoreError)
          and sqlite3.connect(real).execute("SELECT COUNT(*) FROM tx_state").fetchone()[0] == 0)
    copy = os.path.join(BASE, "copy.db")
    src = sqlite3.connect(str(config.DB_PATH))
    dst = sqlite3.connect(copy)
    src.backup(dst)
    src.close()
    dst.close()
    check("a copied / restored DB keeps no valid marker (identity binding) → Store refused",
          await araises(_mk_db(copy), ts.TxStoreError, "disabled"))
    missing = os.path.join(BASE, "missing.db")
    check("Store with a missing DB: refused, the file is not created",
          await araises(_mk_db(missing), ts.TxStoreError, "disabled") and not os.path.exists(missing))


async def _mk_db(path):
    return store(db_path=path)



async def _ag(sid):
    return tuple(await row("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid))


def _sql_hook(point, sql, args, exc=sqlite3.OperationalError, when=None):
    """Fault hook: at `point` (once, optionally only when `when()` holds) run `sql` on a separate
    connection, then raise `exc` (a lost COMMIT reply after an independent change)."""
    state = {"done": False}

    def hook(p):
        if p != point or state["done"] or (when is not None and not when()):
            return
        state["done"] = True
        con = sqlite3.connect(str(config.DB_PATH), timeout=5)
        con.execute(sql, args)
        con.commit()
        con.close()
        raise exc("lost the COMMIT reply")
    return hook


async def g_recheck():
    print("== recheck 059f21a: R-H1 epoch cut × overflow, R-H2 atomic admission, R-M1–R-M3 ==")
    # R-H1, proba recenzentului: overflow pe noul epoch ÎNAINTE de jobul comutării.
    st = store(pending_cap=64, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"a" * 9)
    await rec.checkpoint()
    rec.feed(b"b" * 17)
    f = rec.change_epoch("e2")
    refused = rec.feed(b"c" * 80)
    await f
    C = await rec.resume()
    check("R-H1 probe: an overflow of the new epoch never drops the old epoch's accepted bytes",
          refused is False and await read_all(st, sid) == b"a" * 9 + b"b" * 17 and C == ("e2", 0, 26, 80)
          and rec.gaps == [] and await _ag(sid) == ("e2", 0), (C, rec.gaps))
    await rec.close()
    st.close()

    # R-H1: overflow în timpul fsync-ului segmentului vechi (jobul de comutare în zbor).
    st = store(pending_cap=64, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"a" * 9)
    await rec.checkpoint()
    rec.feed(b"b" * 17)
    hold = Hold("fsync")
    st.fault = hold
    f = asyncio.ensure_future(rec.change_epoch("e2"))
    entered = await hold.wait_entered()
    refused = rec.feed(b"c" * 80)
    hold.go.set()
    await f
    st.fault = None
    C = await rec.resume()
    check("R-H1: overflow of the new epoch while the old segment is in fsync: old bytes published",
          entered and refused is False and await read_all(st, sid) == b"a" * 9 + b"b" * 17
          and C == ("e2", 0, 26, 80), C)
    await rec.close()
    st.close()

    # R-H1: overflow în VECHIUL epoch înainte de tăietură → un marker durabil pentru exact acei
    # octeţi, publicat înaintea comutării, apoi alarmă.
    st = store(pending_cap=64, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"a" * 9)
    await rec.checkpoint()
    rec.feed(b"b" * 40)
    rec.feed(b"x" * 30)                            # 70 > 64 → overflow: 40 aruncaţi + 30 refuzaţi
    await rec.change_epoch("e2")
    g = rec.gaps[0] if rec.gaps else None
    check("R-H1: old-epoch overflow before the cut → ONE marker for exactly those 70 upstream bytes, "
          "published before the switch, alarmed",
          await read_all(st, sid) == b"a" * 9 + ts.GAP_MARKER and len(rec.gaps) == 1
          and (g.out_pos, g.size, g.epoch, g.reason, g.out) == (9, 70, "e1", "epoch-cut", 70)
          and await _ag(sid) == ("e2", 0) and any(a[0] == "transcript.gap" for a in st.alarms), rec.gaps)
    await rec.close()
    st.close()

    # R-H1: scrierea segmentului vechi pică → marker pentru exact octeţii lui; noul epoch intact.
    st = store(pending_cap=1 << 20, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"a" * 9)
    await rec.checkpoint()
    rec.feed(b"b" * 17)
    f = rec.change_epoch("e2")
    rec.feed(b"NEW")
    st.fault = faults({"append"}, exc=OSError)
    await f
    st.fault = None
    await rec.checkpoint()
    check("R-H1: old segment write fails → marker for its 17 bytes before the switch; new epoch kept",
          await read_all(st, sid) == b"a" * 9 + ts.GAP_MARKER + b"NEW" and gp(rec) == [(9, 17)]
          and await _ag(sid) == ("e2", 3), (gp(rec), await _ag(sid)))
    await rec.close()
    st.close()

    # R-H1: resume deja în coadă înaintea comutării, apoi overflow pe noul epoch.
    st = store(pending_cap=64, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"a" * 9)
    await rec.checkpoint()
    rec.feed(b"b" * 17)
    lk = st.lease(sid)
    await lk.acquire()                             # worker-ul aşteaptă: ordinea din coadă e cea de aici
    r = asyncio.ensure_future(rec.resume())
    await asyncio.sleep(0.02)
    f = rec.change_epoch("e2")
    rec.feed(b"c" * 80)
    lk.release()
    C = await r
    await f
    check("R-H1: resume queued before the switch + new-epoch overflow: the held old segment survives",
          C == ("e2", 0, 26, 80) and await read_all(st, sid) == b"a" * 9 + b"b" * 17
          and await _ag(sid) == ("e2", 0), C)
    await rec.close()
    st.close()

    # R-H1: close deja în coadă după comutare, overflow pe noul epoch → marker la close, după vechi.
    st = store(pending_cap=64, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"a" * 9)
    await rec.checkpoint()
    rec.feed(b"b" * 17)
    f = rec.change_epoch("e2")
    rec.feed(b"c" * 80)
    cf = rec.close(cast_ts=2.0)
    await f
    res = await cf
    g = rec.gaps[0] if rec.gaps else None
    check("R-H1: close queued behind the switch: old bytes published, then ONE close marker (e2, 80)",
          await read_all(st, sid) == b"a" * 9 + b"b" * 17 + ts.GAP_MARKER and res["lost"] == 80
          and (g.out_pos, g.size, g.epoch, g.reason) == (26, 80, "e2", "close") and await _ag(sid) == ("e2", 0),
          (res, rec.gaps))
    st.close()

    # R-H2: admitere atomică — ambele reprezentări sau niciuna.
    st = store(pending_cap=64, total_cap=1 << 20)
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    ok1 = rec.feed(b"o" * 10, b"c" * 10, at=("e1", 0))
    ok2 = rec.feed(b"p" * 30, b"d" * 30, at=("e1", 10))  # 20 + 60 > 64: niciuna
    check("R-H2: a chunk whose two halves do not both fit is admitted for neither (pending dropped, "
          "loss per kind)",
          ok1 and ok2 is False and not rec.pending["out"] and not rec.pending["cast"] and rec.overflow
          and rec.loss == {"epoch": "e1", "agent": 40, "out": 40, "cast": 40},
          (rec.loss, rec.agent_offset))
    C = await rec.resume()
    await rec.checkpoint()
    check("R-H2: the published offset covers only chunks admitted in both kinds",
          C == ("e1", 0, 0, 40) and await _ag(sid) == ("e1", 0) and not await st.exists(sid, "out"), C)
    ok3 = rec.feed(b"o" * 10, b"c" * 10, at=("e1", 0))
    await rec.checkpoint()
    check("R-H2: after resume, the replayed chunk is published with both halves and its offset",
          ok3 and await _ag(sid) == ("e1", 10) and await read_all(st, sid) == b"o" * 10
          and await read_all(st, sid, "cast") == b"c" * 10)

    def pos_refused(**kw):
        before = (rec.agent_offset, len(rec.pending["out"]), len(rec.pending["cast"]))
        try:
            rec.feed(b"zz", b"ZZ", **kw)
        except ts.TxStoreError as e:
            return e.reason in ("position", "badInput") and before == (
                rec.agent_offset, len(rec.pending["out"]), len(rec.pending["cast"]))
        return False
    check("R-H2: a chunk not starting at the recorder's position (gap / duplicate / other epoch) is refused whole",
          pos_refused(at=("e1", 12)) and pos_refused(at=("e1", 5)) and pos_refused(at=("e9", 10)))
    check("R-H2: invalid admissions refused (non-bytes, negative agent bytes, malformed position)",
          pos_refused(agent_bytes=-1) and pos_refused(at=["e1", 10]) and _raises(lambda: rec.feed("str"), ts.TxStoreError))
    off = rec.agent_offset
    rec.feed_cast_only(b'{"resize"}\n')
    check("R-H2: a .cast-only event never moves the agent offset", rec.agent_offset == off)
    await rec.close()
    st.close()

    # R-H2: gap la close cu eroare de scriere, apoi a doua încercare: acelaşi total, un singur marker.
    for label, point, exc, times in (("write", "append", OSError, 2),
                                     ("publication", "txn-between", sqlite3.OperationalError, 4)):
        st = store(pending_cap=50, total_cap=1 << 20)
        sid = new_sid()
        await add_session(sid)
        rec = await st.start_recorder(sid)
        rec.feed(b"k" * 10, b"h\n")
        await rec.checkpoint()
        rec.feed(b"z" * 100)
        st.fault = faults({point}, exc=exc, times=times)
        first = await araises(rec.close(cast_ts=9.0), ts.TxStoreError, "writeFailed")
        st.fault = None
        res = await rec.close(cast_ts=9.0)
        check(f"R-H2: close gap with a {label} failure, then a retry: same total, one marker, one alarm",
              first and res["lost"] == 100 and gp(rec) == [(10, 100)]
              and await read_all(st, sid) == b"k" * 10 + ts.GAP_MARKER
              and await _ag(sid) == ("e1", 10)
              and sum(a[0] == "transcript.gap" for a in st.alarms) == 1, (first, res, gp(rec)))
        st.close()

    # R-M1: Store.close în timpul construcţiei unui snapshot.
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"data", b"h\n")
    await rec.checkpoint()
    acc = await access(st, sid)
    hold = Hold("open-fds")
    st.fault = hold
    t = asyncio.ensure_future(st.open(sid, "out", access=acc))
    entered = await hold.wait_entered()
    await rec.close()
    st.close()
    hold.go.set()
    ok = await araises(t, ts.TxStoreError, "closed")
    st.fault = None
    check("R-M1: Store.close while a snapshot is being built: no snapshot returned, nothing left open",
          entered and ok and not st._snapshots and st._slots == 0 and st._gen_fds == 0 and st.dir_fd is None,
          (st._snapshots, st._slots, st._gen_fds))
    st = store()
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"x")
    check("R-M1: a clean shutdown says so (no abandoned worker)", await st.shutdown() == [] and st.abandoned == [])
    st.close()

    # R-M2: rezolvarea unui COMMIT incert.
    st = store()
    st.readopt_enabled = False
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"q", b"h\n")
    await rec.checkpoint()
    orig = st.fresh_read

    async def broken(fn):
        raise sqlite3.OperationalError("database is locked")
    st.fresh_read = broken
    st.fault = faults({"post-commit"}, exc=sqlite3.OperationalError)
    rec.feed(b"r")
    ok = await araises(rec.checkpoint(), ts.RecorderLost)
    st.fault = None
    st.fresh_read = orig
    check("R-M2: uncertain COMMIT with the resolver itself failing → re-adoption (never abandon blind)",
          ok and rec.state == "lost")
    st.close()

    st = store()
    st.readopt_enabled = False
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"q", b"h\n")
    await rec.checkpoint()
    st.fault = _sql_hook("post-commit", "UPDATE sessions SET agent_epoch='eX' WHERE id=?", (sid,))
    rec.feed(b"r")
    ok = await araises(rec.checkpoint(), ts.RecorderLost)
    st.fault = None
    check("R-M2: uncertain COMMIT, agent epoch changed independently → unknown → re-adoption",
          ok and rec.state == "lost")
    st.close()

    st = store()
    st.readopt_enabled = False
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    st.fault = _sql_hook("post-commit", "UPDATE tx_files SET ino=ino+1 WHERE sid=? AND state='published'", (sid,))
    rec.feed(b"q", b"h\n")
    ok = await araises(rec.checkpoint(), ts.RecorderLost)
    st.fault = None
    check("R-M2: uncertain COMMIT, a listed ledger row with another identity → not taken as committed",
          ok and rec.state == "lost")
    st.close()

    st = store(max_bytes=1 << 30, keep_bytes=100)
    st.readopt_enabled = False
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(os.urandom(3000), b"h\n")
    await rec.checkpoint()

    def bumped():
        con = sqlite3.connect(str(config.DB_PATH), timeout=5)
        try:
            return con.execute("SELECT list_epoch FROM tx_descriptors WHERE sid=? AND kind='out'",
                               (sid,)).fetchone()[0] > 0
        finally:
            con.close()
    st.fault = _sql_hook("post-commit", "UPDATE tx_descriptors SET list_epoch=list_epoch+5 WHERE sid=?",
                         (sid,), when=bumped)
    ok = await araises(rec.cap_now(truncate=True), ts.RecorderLost)
    st.fault = None
    check("R-M2: uncertain COMMIT of a cap, list_epoch moved independently → unknown → re-adoption",
          ok and rec.state == "lost")
    st.close()

    st = store()
    st.readopt_enabled = False
    sid = new_sid()
    await add_session(sid)
    rec = await st.start_recorder(sid)
    rec.feed(b"q", b"h\n")
    await rec.checkpoint()
    await db.execute("UPDATE tx_descriptors SET version=version+100 WHERE sid=? AND kind='out'", sid)
    rec.feed(b"r")
    refused = await araises(rec.checkpoint(), ts.Refused)
    ok = await araises(rec.resume(), ts.RecorderLost)
    check("R-M2: after a CAS refusal, resync adopts descriptors and cursor together (moved → re-adoption)",
          refused and ok and rec.state == "lost")
    st.close()

    # R-M3: poarta leagă şi directorul de înregistrări.
    other = tempfile.mkdtemp(prefix="wt-txstore-other-")
    inner = os.path.join(BASE, "other-transcripts")
    os.mkdir(inner)
    check("R-M3: Store with a transcripts dir on another root → refused",
          await araises(_mk_dir(other), ts.TxStoreError, "disabled"))
    check("R-M3: Store with another transcripts dir in the same fixture (not the marked one) → refused",
          await araises(_mk_dir(inner), ts.TxStoreError, "disabled"))
    check("R-M3: create_test_volume refuses a transcripts dir outside the fixture dir",
          _raises(lambda: ts.create_test_volume(config.DB_PATH, other), ts.TxStoreError))
    fx = tempfile.mkdtemp(prefix="wt-txstore-fx-")
    fdb = os.path.join(fx, "webterm.db")
    src = sqlite3.connect(str(config.DB_PATH))
    dst = sqlite3.connect(fdb)
    src.backup(dst)
    src.close()
    dst.close()
    os.mkdir(os.path.join(fx, "transcripts"))
    ts.create_test_volume(fdb)
    s2 = ts.Store(transcripts_dir=os.path.join(fx, "transcripts"), kwk=KWK, installation_id=INST, db_path=fdb)
    s2.close()
    os.rename(os.path.join(fx, "transcripts"), os.path.join(fx, "transcripts.old"))
    os.mkdir(os.path.join(fx, "transcripts"))
    check("R-M3: the marked fixture opens; a replaced transcripts dir (same path, new inode) → refused",
          await araises(_mk_dir(os.path.join(fx, "transcripts"), fdb), ts.TxStoreError, "disabled"))
    os.chmod(fx, 0o755)
    check("R-M3: a fixture dir that is not private (0755) → refused",
          _raises(lambda: ts.create_test_volume(fdb), ts.TxStoreError))
    os.chmod(fx, 0o700)
    con = sqlite3.connect(fdb)
    con.execute("DROP TABLE IF EXISTS users")
    con.execute("CREATE VIEW users AS SELECT * FROM no_such_table")
    con.commit()
    con.close()
    check("R-M3: a users object that cannot be read is not proven absent → create_test_volume refused",
          _raises(lambda: ts.create_test_volume(fdb), ts.TxStoreError))
    import shutil
    shutil.rmtree(fx, ignore_errors=True)
    shutil.rmtree(other, ignore_errors=True)


async def _mk_dir(tdir, db_path=None):
    return ts.Store(transcripts_dir=tdir, kwk=KWK, installation_id=INST,
                    **({"db_path": db_path} if db_path else {}))


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
        await g_review_h1()
        await g_review_h2()
        await g_review_h3()
        await g_review_m()
        await g_recheck()
    finally:
        await db.close()


asyncio.run(main())
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
import shutil  # noqa: E402
shutil.rmtree(BASE, ignore_errors=True)
sys.exit(1 if failed else 0)
