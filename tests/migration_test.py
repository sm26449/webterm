"""Migration of plaintext recordings to WTX1 (ENCRYPTION-AT-REST.md §12.11.5, PR6b).

Groups:
  * renameat2(RENAME_NOREPLACE): never replaces an existing name;
  * inventory (taken once): pending / orphan (no session row) / missing (one-kind) / failed (name
    outside the allowlist, symlink, hard link, the same recording in transcripts/ and arhiva/);
    `.cap-tmp` skipped; a file that appears later is stray (reported, never served);
  * order (closed → arhiva → lost → rest; live skipped) and the result: plaintext gone, descriptors
    flagged `converted`, origin migrated / orphan, committed_at = mtime, archived_at = mtime for
    arhiva/, readers serve exactly the plaintext bytes;
  * live session converted at its writer start (list_epoch bumped, new output appended after the
    converted bytes), at most 2 conversions at once, writer refused while a kind failed;
  * crash at every step (reserve, write, sealed, verified, inside the commit, committed, renamed,
    one of the pair unlinked) → the next boot + pass converge, nothing left behind;
  * never deletes unverified plaintext: read-back mismatch, a file replaced before the unlink
    (renamed back, failed), changed during / before the migration, missing since the inventory;
  * downgrade refusal after the conversion, the global flag only when nothing is open, System health;
  * crash rules at boot (pending next to an RK → failed; an unexplained private name listed, kept),
    an erased sid's plaintext removed without conversion, no renameat2 → nothing deleted;
  * a real protected volume (no test marker, no test gate) with the flag on: boots, serves the
    pending plaintext, erases a pending recording (migrate-then-erase), migrates, and serves the
    same transcript bytes as before the migration, also after a restart.
Temp dirs + the real db module; no network, no Docker.
"""
import asyncio
import os
import shutil
import sys
import tempfile
import time

BASE = tempfile.mkdtemp(prefix="wt-migration-")
os.chmod(BASE, 0o700)
os.environ["WEBTERM_DATA_DIR"] = BASE
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
os.environ.setdefault("WEBTERM_UPDATE_CHECK", "0")
os.environ["WEBTERM_TX_RECORDINGS"] = "1"
os.environ["WEBTERM_TEST_GATE"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402

from app import api, config, db, security, syshealth, txdesc, txhub  # noqa: E402
from app import erasure as er  # noqa: E402
from app import migration as mg  # noqa: E402
from app import txstore as ts  # noqa: E402
from app.main import app  # noqa: E402

ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
KWK = bytes(range(0x60, 0x80))
INST = bytes(range(0xa0, 0xb0))
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {str(detail)[-700:]}"))


async def araises(coro, exc, reason=None):
    try:
        await coro
    except exc as e:
        return reason is None or getattr(e, "reason", None) == reason
    except BaseException as e:  # noqa: BLE001
        print("     got", type(e).__name__, e)
        return False
    return False


class Crash(BaseException):
    """Process death at a migration step."""


def fault_at(point):
    state = {"done": False}

    def hook(p):
        if p == point and not state["done"]:
            state["done"] = True
            raise Crash(p)
    return hook


class FakeRing:
    kwk = KWK
    installation_id = INST


TD = str(config.TRANSCRIPT_DIR)
AD = str(config.ARCHIVE_DIR)
MTIME_NS = 1_700_000_000_123_456_789


def sid_new():
    return os.urandom(16).hex()


def write(dirn, name, data, mtime_ns=MTIME_NS):
    p = os.path.join(dirn, name)
    with open(p, "wb") as f:
        f.write(data)
    os.utime(p, ns=(mtime_ns, mtime_ns))
    return p


def pair(dirn, sid, n=1000):
    out = os.urandom(n)
    cast = b'{"version": 2, "width": 80, "height": 24}\n[0.1, "o", "' + sid.encode() + b'"]\n'
    write(dirn, sid + ".out", out)
    write(dirn, sid + ".cast", cast)
    return out, cast


async def add_session(sid, state, host_id=1):
    await db.execute("INSERT INTO sessions(id, host_id, title, state, created, rows, cols) VALUES(?,?,?,?,?,?,?)",
                     sid, host_id, "t", state, time.time(), 24, 80)


async def wipe():
    for t in ("tx_migration", "session_keys", "tx_descriptors", "tx_files", "tx_gaps", "tx_quarantine",
              "sessions"):
        await db.execute("DELETE FROM %s" % t)
    await db.execute("DELETE FROM tx_state WHERE key NOT IN ('test_volume')")
    for d in (TD, AD):
        os.makedirs(d, exist_ok=True)
        for n in os.listdir(d):
            p = os.path.join(d, n)
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)


def new_store():
    return ts.Store(transcripts_dir=config.TRANSCRIPT_DIR, kwk=KWK, installation_id=INST)


async def boot_store():
    st = new_store()
    await st.recover()
    await mg.boot(st)
    return st


async def reboot(st):
    """A process restart: the Store and the migration state are rebuilt from disk."""
    mg.reset()
    st.close()
    return await boot_store()


async def read_all(st, sid, kind="out"):
    snap = await st.open(sid, kind, access=st.access(sid, "t", "test"))
    try:
        return await snap.read(0, snap.length)
    finally:
        snap.close()


async def rows():
    return {(r["sid"], r["kind"]): dict(r) for r in await db.fetchall("SELECT * FROM tx_migration")}


async def state(sid, kind):
    r = await db.fetchone("SELECT state FROM tx_migration WHERE sid=? AND kind=?", sid, kind)
    return r["state"] if r else None


def ls(d=TD):
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def plain_present(sid, d=TD):
    return [n for n in ls(d) if n in (sid + ".out", sid + ".cast")]


def leftovers():
    return [n for d in (TD, AD) for n in ls(d) if n.startswith(ts.DEL_PREFIX)]


async def desc(st, sid, kind):
    r = await db.fetchone("SELECT blob, version FROM tx_descriptors WHERE sid=? AND kind=?", sid, kind)
    k = await db.fetchone("SELECT envelope FROM session_keys WHERE sid=?", sid)
    return st.decode((r["blob"], r["version"]), sid, kind, bytes(k["envelope"]))


async def open_ledger(sid):
    return await db.fetchall("SELECT gen_id, state FROM tx_files WHERE sid=? AND state NOT IN "
                             "('published','gone')", sid)


def gen_files(sid):
    return [n for n in ls() if n.startswith(sid) and n.endswith(".wtx")]


# ── groups ───────────────────────────────────────────────────────────────────


def g_renameat2():
    print("== renameat2(RENAME_NOREPLACE) ==")
    d = os.path.join(BASE, "rn")
    os.makedirs(d)
    for n in ("a", "b"):
        with open(os.path.join(d, n), "w") as f:
            f.write(n)
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            ts.renameat2_noreplace(dfd, "a", "b")
            refused = False
        except OSError as e:
            refused = e.errno == 17
        check("an existing target is never replaced (EEXIST)", refused and open(os.path.join(d, "b")).read() == "b")
        ts.renameat2_noreplace(dfd, "a", "c")
        check("a fresh name is taken atomically", sorted(os.listdir(d)) == ["b", "c"])
        try:
            ts.renameat2_noreplace(dfd, "nope", "x")
            absent = False
        except FileNotFoundError:
            absent = True
        check("an absent source → FileNotFoundError", absent)
    finally:
        os.close(dfd)
        shutil.rmtree(d)


async def g_inventory_order_result():
    print("== inventory, order, result ==")
    await wipe()
    s = {k: sid_new() for k in ("closed", "arch", "orphan", "one", "lost", "live", "dup", "link", "hard",
                                "orphan_t")}
    data = {}
    data["closed"] = pair(TD, s["closed"], 3 * 1024 * 1024 + 17)      # > CAP_CHUNK, > 64 KiB records
    data["arch"] = pair(AD, s["arch"])
    data["orphan"] = pair(AD, s["orphan"])
    data["one"] = (write(TD, s["one"] + ".out", b"only out") and b"only out", None)
    data["lost"] = pair(TD, s["lost"])
    data["live"] = pair(TD, s["live"])
    data["orphan_t"] = pair(TD, s["orphan_t"])
    pair(TD, s["dup"])
    write(AD, s["dup"] + ".out", b"archived twin")
    os.symlink(os.path.join(BASE, "elsewhere"), os.path.join(TD, s["link"] + ".out"))
    hp = write(TD, s["hard"] + ".out", b"hard")
    os.link(hp, os.path.join(BASE, "hard-twin"))
    write(TD, "notes.txt", b"x")
    write(TD, ".%s.out.0123456789abcdef.cap-tmp" % s["closed"], b"tmp")
    for k in ("closed", "arch", "one", "dup", "link", "hard"):
        await add_session(s[k], "closed")
    await add_session(s["lost"], "lost")
    await add_session(s["live"], "live")
    st = await boot_store()
    R = await rows()
    st_of = {k: v["state"] for k, v in R.items()}
    check("closed pair → pending (both kinds)",
          st_of.get((s["closed"], "out")) == "pending" and st_of.get((s["closed"], "cast")) == "pending", st_of)
    check("arhiva/ file with a session row → pending (dir arhiva)",
          st_of.get((s["arch"], "out")) == "pending" and R[(s["arch"], "out")]["dir"] == "arhiva")
    check("arhiva/ file whose session row is gone → orphan", st_of.get((s["orphan"], "out")) == "orphan")
    check("transcripts/ file without a session row → orphan", st_of.get((s["orphan_t"], "cast")) == "orphan")
    check("one-kind recording → the absent kind is `missing`",
          st_of.get((s["one"], "out")) == "pending" and st_of.get((s["one"], "cast")) == "missing")
    check("same recording in transcripts/ and arhiva/ → failed (duplicate), never guessed",
          st_of.get((s["dup"], "out")) == "failed" and "duplicate" in R[(s["dup"], "out")]["error"]
          and st_of.get((s["dup"], "cast")) == "pending")
    check("symbolic link → failed", st_of.get((s["link"], "out")) == "failed"
          and "symbolic" in R[(s["link"], "out")]["error"])
    check("hard link → failed", st_of.get((s["hard"], "out")) == "failed" and "hard link" in R[(s["hard"], "out")]["error"])
    check("a name outside the allowlist → failed, listed by path",
          st_of.get(("transcripts/notes.txt", "-")) == "failed")
    check(".cap-tmp leftovers are not inventoried", not any("cap-tmp" in k[0] for k in R))
    check("inventory marker written", await db.fetchone("SELECT 1 FROM tx_state WHERE key='migration_inventory'"))
    check("pending plaintext readable before the migration (PlainSnapshot)",
          await read_all(st, s["closed"]) == data["closed"][0])
    # a file that appears after the inventory: never inventoried, never served, reported
    late = sid_new()
    write(TD, late + ".out", b"late")
    st = await reboot(st)
    check("the inventory is taken once (a later file has no row)", (late, "out") not in await rows())
    check("…it is never served (downgrade)", await araises(read_all(st, late), ts.TxStoreError, "downgrade"))
    check("…and reported as stray", (await mg.status())["stray"] >= 1)
    os.remove(os.path.join(TD, late + ".out"))

    seen = []
    orig = mg.process

    async def spy(st_, sid, live=False):
        seen.append(sid)
        return await orig(st_, sid, live=live)
    mg.process = spy
    try:
        await mg.run_once(st)
    finally:
        mg.process = orig
    rank = {s["closed"]: 0, s["one"]: 0, s["dup"]: 0, s["arch"]: 1, s["orphan"]: 1, s["lost"]: 2, s["orphan_t"]: 3}
    check("order: closed sessions, then arhiva/, then lost, then the rest",
          [rank.get(x) for x in seen] == sorted(rank.get(x) for x in seen) and set(seen) == set(rank), seen)
    check("a live session is not taken by the janitor", s["live"] not in seen and await state(s["live"], "out") == "pending")
    check("failed-only sessions are not retried automatically", s["link"] not in seen and s["hard"] not in seen)

    R = await rows()
    check("closed pair: both rows unlinked, plaintext gone",
          R[(s["closed"], "out")]["state"] == R[(s["closed"], "cast")]["state"] == "unlinked"
          and plain_present(s["closed"]) == [])
    check("the converted recording serves exactly the plaintext bytes (out and cast)",
          await read_all(st, s["closed"]) == data["closed"][0]
          and await read_all(st, s["closed"], "cast") == data["closed"][1])
    d = await desc(st, s["closed"], "out")
    check("descriptor flagged converted (authenticated), one sealed generation",
          d.flags & txdesc.FLAG_CONVERTED and len(d.generations) == 1
          and d.generations[0].state == txdesc.STATE_SEALED)
    k = await db.fetchone("SELECT origin FROM session_keys WHERE sid=?", s["closed"])
    check("RK origin = migrated", k["origin"] == "migrated")
    dr = await db.fetchone("SELECT committed_at, archived_at, list_epoch FROM tx_descriptors WHERE sid=? AND kind='out'",
                           s["closed"])
    check("committed_at = the plaintext mtime (never now), not archived, list_epoch 0",
          abs(dr["committed_at"] - MTIME_NS / 1e9) < 1e-3 and dr["archived_at"] is None and dr["list_epoch"] == 0)
    da = await db.fetchone("SELECT archived_at FROM tx_descriptors WHERE sid=? AND kind='out'", s["arch"])
    check("arhiva/ file: archived_at = its mtime (retention clock kept), removed from arhiva/",
          da and abs(da["archived_at"] - MTIME_NS / 1e9) < 1e-3 and plain_present(s["arch"], AD) == [])
    ko = await db.fetchone("SELECT origin FROM session_keys WHERE sid=?", s["orphan"])
    check("orphan → converted with origin = orphan", ko and ko["origin"] == "orphan"
          and await read_all(st, s["orphan"]) == data["orphan"][0])
    check("one-kind: out converted, no cast descriptor",
          await read_all(st, s["one"]) == b"only out"
          and await db.fetchone("SELECT 1 FROM tx_descriptors WHERE sid=? AND kind='cast'", s["one"]) is None)
    check("dup: the pending kind converted, the duplicate kept in both places",
          await state(s["dup"], "cast") == "unlinked" and plain_present(s["dup"]) == [s["dup"] + ".out"]
          and plain_present(s["dup"], AD) == [s["dup"] + ".out"])
    check("no generation left unpublished, no private name left", not await open_ledger(s["closed"]) and not leftovers())
    check("global flag NOT published while rows are failed / pending",
          await db.fetchone("SELECT 1 FROM tx_state WHERE key='recordings_format'") is None)
    res = await syshealth.c_crypto_migration()
    check("System health: warning with the failed count while files are failed",
          res.severity == "warning" and res.key == "migration_failed" and int(res.params["failed"]) >= 4, res)

    # downgrade: a converted sid whose plaintext reappears / whose descriptor vanished
    write(TD, s["closed"] + ".out", b"planted")
    check("a planted plaintext next to a converted recording is ignored (encrypted served)",
          await read_all(st, s["closed"]) == data["closed"][0])
    await mg.run_once(st)
    check("…and reported as stray", f"transcripts/{s['closed']}.out" in mg._s.stray)
    os.remove(os.path.join(TD, s["closed"] + ".out"))
    await db.execute("DELETE FROM tx_descriptors WHERE sid=? AND kind='out'", s["lost"])
    write(TD, s["lost"] + ".out", data["lost"][0])
    check("converted sid whose descriptor vanished → plaintext refused (downgrade)",
          await araises(read_all(st, s["lost"]), ts.TxStoreError, "downgrade"))
    os.remove(os.path.join(TD, s["lost"] + ".out"))
    return st, s, data


async def g_live(st, s, data):
    print("== live session: converted at its writer start ==")
    rec = await st.start_recorder(s["live"], track_agent=False)
    check("writer start converted the live plaintext first",
          await state(s["live"], "out") == "unlinked" and plain_present(s["live"]) == [])
    le = await db.fetchone("SELECT list_epoch FROM tx_descriptors WHERE sid=? AND kind='out'", s["live"])
    check("list_epoch bumped for a live conversion", le["list_epoch"] == 1)
    rec.feed(b"NEW OUTPUT", b"", at=rec.received)
    await rec.checkpoint()
    await rec.close()
    check("new output is appended after the converted bytes",
          await read_all(st, s["live"]) == data["live"][0] + b"NEW OUTPUT", (await read_all(st, s["live"]))[-20:])
    d = await desc(st, s["live"], "out")
    check("the descriptor keeps the converted flag after the writer appended",
          d.flags & txdesc.FLAG_CONVERTED and len(d.generations) >= 2)
    check("a failed kind refuses the writer (never next to unconverted plaintext)",
          await araises(st.start_recorder(s["link"], track_agent=False), ts.TxStoreError, "migrationPending"))

    # at most 2 conversions at once
    await wipe()
    lives = [sid_new() for _ in range(4)]
    for x in lives:
        pair(TD, x, 200_000)
        await add_session(x, "live")
    st = await reboot(st)
    cur = {"n": 0, "max": 0}
    orig = st.convert_plain

    async def counted(*a, **kw):
        cur["n"] += 1
        cur["max"] = max(cur["max"], cur["n"])
        try:
            await asyncio.sleep(0.05)
            return await orig(*a, **kw)
        finally:
            cur["n"] -= 1
    st.convert_plain = counted
    recs = await asyncio.gather(*[st.start_recorder(x, track_agent=False) for x in lives])
    st.convert_plain = orig
    check("4 writer starts: at most 2 conversions at once, all converted",
          cur["max"] == 2 and all([await state(x, "out") == "unlinked" for x in lives]), cur)
    for r in recs:
        await r.close()
    return st


CRASH_POINTS = ("pre-commit", "write", "mig-written", "mig-sealed", "mig-verified", "mig-txn-between",
                "mig-committed", "mig-renamed", "mig-unlinked")
BEFORE_COMMIT = ("pre-commit", "write", "mig-written", "mig-sealed", "mig-verified", "mig-txn-between")


async def g_crash(st):
    print("== crash at every step → the next boot converges ==")
    for point in CRASH_POINTS:
        await wipe()
        sid = sid_new()
        out, cast = pair(TD, sid, 300_000)
        await add_session(sid, "closed")
        st = await reboot(st)
        st.fault = fault_at(point)
        try:
            await mg.process(st, sid)
            crashed = False
        except Crash:
            crashed = True
        st.fault = None
        kept = plain_present(sid)
        if point in BEFORE_COMMIT:
            check(f"crash at {point}: nothing published, the plaintext is untouched",
                  crashed and sorted(kept) == sorted([sid + ".out", sid + ".cast"])
                  and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid) is None, (crashed, kept))
        st = await reboot(st)
        await mg.run_once(st)
        ok = (await state(sid, "out") == "unlinked" and await state(sid, "cast") == "unlinked"
              and plain_present(sid) == [] and not leftovers() and not await open_ledger(sid)
              and len(gen_files(sid)) == 2
              and await read_all(st, sid) == out and await read_all(st, sid, "cast") == cast)
        check(f"crash at {point}: boot + pass converge (both unlinked, one generation each, same bytes)",
              crashed and ok, (crashed, await rows(), ls(), await open_ledger(sid)))
    return st


async def g_unverified(st):
    print("== unverified plaintext is never deleted ==")
    # (a) read-back mismatch
    await wipe()
    sid = sid_new()
    out, _cast = pair(TD, sid)
    await add_session(sid, "closed")
    st = await reboot(st)
    orig = st.decrypted_digest

    async def wrong(*a, **kw):
        h, n = await orig(*a, **kw)
        return "0" * 64, n
    st.decrypted_digest = wrong
    await mg.process(st, sid)
    st.decrypted_digest = orig
    r = (await rows())[(sid, "out")]
    check("read-back mismatch → plaintext kept, row pending with the error, nothing published",
          r["state"] == "pending" and "readback" in (r["error"] or "") and len(plain_present(sid)) == 2
          and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid) is None, r)
    check("…the generations written are retired (no file, no open ledger row)",
          gen_files(sid) == [] and not await open_ledger(sid))
    check("…retried only after the backoff", mg._s.backoff.get(sid, 0) > time.time() + 3000)
    seen = []
    o2 = mg.process

    async def spy(st_, s_, live=False):
        seen.append(s_)
        return await o2(st_, s_, live=live)
    mg.process = spy
    await mg.run_once(st)
    mg.process = o2
    check("…the janitor skips it during the backoff", sid not in seen)
    mg._s.backoff.clear()
    await mg.run_once(st)
    check("…and converts it after", await state(sid, "out") == "unlinked" and await read_all(st, sid) == out)

    # (b) the file under the name is replaced after the commit: identity check fails, renamed back
    await wipe()
    sid = sid_new()
    out, _cast = pair(TD, sid)
    await add_session(sid, "closed")
    st = await reboot(st)
    moved = os.path.join(BASE, "moved-original")

    def swap(p):
        if p == "mig-committed":
            os.rename(os.path.join(TD, sid + ".out"), moved)
            write(TD, sid + ".out", b"a different file")
    st.fault = swap
    await mg.process(st, sid)
    st.fault = None
    r = (await rows())[(sid, "out")]
    check("a file replaced before the unlink → renamed back, kept, row failed",
          r["state"] == "failed" and "identity" in r["error"]
          and open(os.path.join(TD, sid + ".out"), "rb").read() == b"a different file"
          and open(moved, "rb").read() == out and not leftovers(), (r, ls()))
    check("…the encrypted copy serves the original", await read_all(st, sid) == out)
    os.remove(moved)

    # (c) changed during the migration (between the write and the read-back)
    await wipe()
    sid = sid_new()
    out, _cast = pair(TD, sid)
    await add_session(sid, "closed")
    st = await reboot(st)

    grown = []

    def grow(p):
        if p == "mig-written" and not grown:
            grown.append(p)
            with open(os.path.join(TD, sid + ".out"), "ab") as f:
                f.write(b"!")
    st.fault = grow
    await mg.process(st, sid)
    st.fault = None
    r = (await rows())[(sid, "out")]
    check("changed during the migration → failed, plaintext kept as it is, its kind not published",
          r["state"] == "failed" and "changed" in r["error"]
          and open(os.path.join(TD, sid + ".out"), "rb").read() == out + b"!"
          and await db.fetchone("SELECT 1 FROM tx_descriptors WHERE sid=? AND kind='out'", sid) is None
          and not await open_ledger(sid), (r, await open_ledger(sid), ls()))
    check("…the unchanged kind converted alone (a one-kind recording)",
          await state(sid, "cast") == "unlinked" and len(gen_files(sid)) == 1)

    # (d) changed after the inventory, (e) missing since the inventory
    await wipe()
    a, b = sid_new(), sid_new()
    pair(TD, a)
    pair(TD, b)
    await add_session(a, "closed")
    await add_session(b, "closed")
    st = await reboot(st)
    write(TD, a + ".out", b"rewritten", mtime_ns=MTIME_NS + 5)
    os.remove(os.path.join(TD, b + ".out"))
    await mg.run_once(st)
    R = await rows()
    check("changed after the inventory → failed, kept",
          R[(a, "out")]["state"] == "failed" and open(os.path.join(TD, a + ".out"), "rb").read() == b"rewritten")
    check("missing since the inventory → failed (listed), the other kind still converted",
          R[(b, "out")]["state"] == "failed" and "missing" in R[(b, "out")]["error"]
          and R[(b, "cast")]["state"] == "unlinked")
    return st


async def g_flag(st):
    print("== global flag, System health ==")
    await wipe()
    sid = sid_new()
    pair(TD, sid)
    a2 = sid_new()
    pair(AD, a2)
    bad = sid_new()
    os.symlink("nowhere", os.path.join(TD, bad + ".out"))
    for x in (sid, a2, bad):
        await add_session(x, "closed")
    st = await reboot(st)
    res = await syshealth.c_crypto_migration()
    check("System health: failed rows → warning", res.severity == "warning" and res.key == "migration_failed", res)
    await db.execute("DELETE FROM tx_migration WHERE sid=? AND kind='out'", bad)   # Owner: failed row removed
    os.remove(os.path.join(TD, bad + ".out"))
    res = await syshealth.c_crypto_migration()
    check("System health: progress while rows are pending",
          res.severity == "info" and res.key == "migration_progress" and str(res.params["total"]) == "4", res)
    await mg.run_once(st)
    fmt = await db.fetchone("SELECT value FROM tx_state WHERE key='recordings_format'")
    check("global flag wtx1 once nothing is pending / failed / converted", fmt and fmt["value"] == "wtx1")
    check("…and the empty arhiva/ removed", not os.path.isdir(AD))
    res = await syshealth.c_crypto_migration()
    check("System health: ok once migrated", res.severity == "ok" and res.key == "migration_done", res)
    os.makedirs(AD, exist_ok=True)
    return st


async def g_rules(st):
    print("== crash rules, erased sids, no renameat2 ==")
    await wipe()
    integ, erased, norn = sid_new(), sid_new(), sid_new()
    pair(TD, integ)
    pair(TD, erased)
    out_n, _c = pair(TD, norn)
    for x in (integ, erased, norn):
        await add_session(x, "closed")
    write(TD, ts.DEL_PREFIX + "0123abcd", b"someone else's file")
    st = await reboot(st)
    await db.execute("INSERT INTO session_keys(sid, envelope, created, origin) VALUES(?,?,?,'session')",
                     integ, b"x" * 80, time.time())
    st = await reboot(st)
    R = await rows()
    check("pending next to an RK of the same sid → failed (integrity), plaintext kept",
          R[(integ, "out")]["state"] == "failed" and "integrity" in R[(integ, "out")]["error"]
          and len(plain_present(integ)) == 2)
    check("a private name no row explains is listed, never deleted",
          (await mg.status())["leftovers"] == 1 and ts.DEL_PREFIX + "0123abcd" in ls())
    os.remove(os.path.join(TD, ts.DEL_PREFIX + "0123abcd"))
    st.tombstoned.add(erased)
    await mg.process(st, erased)
    R = await rows()
    check("an erased (tombstoned) sid: plaintext removed through the identity-checked unlink, never converted",
          plain_present(erased) == [] and R[(erased, "out")]["state"] == "unlinked"
          and R[(erased, "out")]["error"] == "erased"
          and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", erased) is None)
    saved = ts._renameat2
    ts._renameat2 = None
    try:
        await mg.process(st, norn)
    finally:
        ts._renameat2 = saved
    r = (await rows())[(norn, "out")]
    check("without renameat2: converted, plaintext kept (nothing deleted), error listed",
          r["state"] == "converted" and "unavailable" in r["error"] and len(plain_present(norn)) == 2)
    mg._s.backoff.clear()
    st = await reboot(st)
    check("…the next boot re-verifies against the published copy and unlinks",
          await state(norn, "out") == "unlinked" and plain_present(norn) == [] and await read_all(st, norn) == out_n)
    return st


async def g_real_volume():
    print("== real protected volume: boot, erase pending, migrate, same bytes ==")
    await wipe()
    await db.execute("DELETE FROM tx_state")             # nu mai e un volum de test
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", timeout=30, headers=ORIGIN)
    r = await c.post("/api/setup", json={"email": "o@x.co", "password": "parolabuna1", "setup_token": "test-setup"})
    assert r.status_code == 200, r.text
    host_id = (await c.post("/api/hosts", json={"name": "h1"})).json()["id"]
    keep, gone = sid_new(), sid_new()
    out, cast = pair(TD, keep, 500_000)
    pair(AD, gone)
    await add_session(keep, "closed", host_id)
    await add_session(gone, "closed", host_id)
    before = await c.get(f"/api/sessions/{keep}/transcript?format=out")
    check("3.7 (flag off, no Store): the download is the plaintext file", before.status_code == 200
          and before.content == out and not txhub.active())
    orig_start = mg.start
    mg.start = lambda st: None                          # paşii janitorului rulează explicit mai jos
    try:
        st = await txhub.boot(FakeRing(), env={"WEBTERM_TX_RECORDINGS": "1"})
        await er.stop()
        check("flag on + protected keyring + real volume → boots (migration, journal, quarantine ready)",
              st is not None and st.real_volume and mg.ready() and er.journal_ready() and er.quarantine_ready())
        r1 = await c.get(f"/api/sessions/{keep}/transcript?format=out")
        check("pending plaintext served unchanged before its migration", r1.status_code == 200 and r1.content == out)
        res = await er.erase(st, gone)
        check("erase of a pending recording: migrated first, then erased (plaintext gone, RK destroyed)",
              res["erased"] and plain_present(gone, AD) == [] and gen_files(gone) == []
              and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", gone) is None
              and gone in st.tombstoned and await state(gone, "out") == "unlinked", (res, ls(AD)))
        await mg.run_once(st)
        r2 = await c.get(f"/api/sessions/{keep}/transcript?format=out")
        r3 = await c.get(f"/api/sessions/{keep}/transcript?format=cast")
        check("after the migration the download serves the same bytes (out, cast), plaintext gone",
              r2.status_code == 200 and r2.content == out and r3.content == cast and plain_present(keep) == [])
        await g_owner_resolution(st, c, host_id, keep)
        await txhub.shutdown()
        st = await txhub.boot(FakeRing(), env={"WEBTERM_TX_RECORDINGS": "1"})
        await er.stop()
        r4 = await c.get(f"/api/sessions/{keep}/transcript?format=out")
        check("after a restart: still the same bytes, flag published",
              r4.content == out and (await db.fetchone("SELECT value FROM tx_state WHERE key='recordings_format'"))
              ["value"] == "wtx1")
        await txhub.shutdown()
        check("flag on without a protected keyring (legacy volume) → still refused",
              await araises(txhub.boot(None, env={"WEBTERM_TX_RECORDINGS": "1"}), txhub.BootRefused))
        check("flag off on a migrated volume → refused (never read as absent)",
              await araises(txhub.boot(None, env={}), txhub.BootRefused))
    finally:
        mg.start = orig_start
        await txhub.shutdown()
        await c.aclose()


async def fail_rows(sid, why="changed since the inventory"):
    """Both kinds of `sid` → `failed` with an identity that no longer matches (as the migration
    leaves them after a change); the plaintext stays on disk."""
    for k in ("out", "cast"):
        await db.execute("INSERT OR REPLACE INTO tx_migration(sid, kind, dir, name, dev, ino, size, mtime_ns, state, "
                         "error) VALUES(?,?,?,?,?,?,?,?,'failed',?)", sid, k, "transcripts", "%s.%s" % (sid, k),
                         1, 1, 1, 1, why)


async def g_owner_resolution(st, c, host_id, migrated):
    print("== failed migration: System health lists it; Owner retry / discard ==")
    uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]
    grant = security.issue_stepup_grant
    f1, f2 = sid_new(), sid_new()
    out1, cast1 = pair(TD, f1, 2000)
    pair(TD, f2, 900)
    await add_session(f1, "closed", host_id)
    await add_session(f2, "closed", host_id)
    await fail_rows(f1)
    await fail_rows(f2)
    res = await syshealth.c_crypto_migration()
    check("System health lists the sessions with failed rows (first 8 characters)",
          res.severity == "warning" and f1[:8] in res.params.get("sessions", "") and f2[:8] in res.params["sessions"],
          res)
    check("…their writer is refused while failed (transcript.migrationPending)",
          await araises(mg.at_writer_start(f1), ts.TxStoreError, "migrationPending"))
    r = await c.post(f"/api/recordings/migration/{f1}/retry", json={})
    check("retry without a fresh factor → 403", r.status_code == 403, r.text)
    r = await c.post(f"/api/recordings/migration/{f1}/retry", json={"stepup_grant": grant(uid, host_id)})
    check("Owner retry (fresh factor): re-inventoried from the file now there, converted, plaintext gone",
          r.status_code == 200 and r.json()["kinds"] == {"out": "unlinked", "cast": "unlinked"}
          and plain_present(f1) == [] and await read_all(st, f1) == out1 and await read_all(st, f1, "cast") == cast1,
          r.text)
    await mg.at_writer_start(f1)
    check("…after the retry the session's writer may start", True)
    r = await c.post(f"/api/recordings/migration/{f1}/retry", json={"stepup_grant": grant(uid, host_id)})
    check("retry of a session without failed rows → 409 transcript.notFailed",
          r.status_code == 409 and r.json().get("code") == "transcript.notFailed", r.text)
    # o sesiune cu înregistrare criptată + text clar eşuat: retry refuzat (doar discard)
    with open(os.path.join(TD, migrated + ".out"), "wb") as f:
        f.write(b"stale plaintext")
    await db.execute("UPDATE tx_migration SET state='failed', error='x' WHERE sid=? AND kind='out'", migrated)
    r = await c.post(f"/api/recordings/migration/{migrated}/retry", json={"stepup_grant": grant(uid, host_id)})
    check("retry when the session already has an encrypted recording → 409 transcript.retryEncrypted",
          r.status_code == 409 and r.json().get("code") == "transcript.retryEncrypted", r.text)
    os.remove(os.path.join(TD, migrated + ".out"))
    await db.execute("UPDATE tx_migration SET state='unlinked', error=NULL WHERE sid=? AND kind='out'", migrated)
    # discard
    r = await c.post(f"/api/recordings/migration/{f2}/discard", json={"confirm": "nope", "stepup_grant": grant(uid, host_id)})
    check("discard without the typed confirmation → 400", r.status_code == 400, r.text)
    await db.execute("UPDATE sessions SET state='live' WHERE id=?", f2)
    r = await c.post(f"/api/recordings/migration/{f2}/discard", json={"confirm": f2[:8], "stepup_grant": grant(uid, host_id)})
    check("discard of a live session → 409 session.live", r.status_code == 409, r.text)
    await db.execute("UPDATE sessions SET state='closed' WHERE id=?", f2)
    n0 = er._s.parsed.n
    r = await c.post(f"/api/recordings/migration/{f2}/discard", json={"confirm": f2[:8], "stepup_grant": grant(uid, host_id)})
    check("Owner discard: plaintext deleted (identity-checked), sid tombstoned in the journal, rows unlinked",
          r.status_code == 200 and r.json()["n"] == n0 + 1 and plain_present(f2) == [] and f2 in st.tombstoned
          and await state(f2, "out") == "unlinked" and await state(f2, "cast") == "unlinked", r.text)
    await mg.at_writer_start(f2)
    check("…after the discard nothing blocks the session's writer", True)
    audit = await db.fetchall("SELECT detail FROM audit_log WHERE path LIKE '/api/recordings/migration/%' "
                              "AND status=200")
    check("both Owner actions audited", len(audit) >= 2 and any("discarded" in (a["detail"] or "") for a in audit),
          [a["detail"] for a in audit])
    res = await syshealth.c_crypto_migration()
    check("System health no longer lists them", res.key != "migration_failed", res)


async def main():
    g_renameat2()
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    st = None
    try:
        ts.create_test_volume(config.DB_PATH)
        st, s, data = await g_inventory_order_result()
        st = await g_live(st, s, data)
        st = await g_crash(st)
        st = await g_unverified(st)
        st = await g_flag(st)
        st = await g_rules(st)
        mg.reset()
        st.close()
        st = None
        await g_real_volume()
    finally:
        if st is not None:
            st.close()
        await txhub.shutdown()
        await db.close()


asyncio.run(main())
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
shutil.rmtree(BASE, ignore_errors=True)
sys.exit(1 if failed else 0)
