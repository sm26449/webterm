"""Backups of encrypted recordings (ENCRYPTION-AT-REST.md §12.11.3, PR6c).

Groups:
  * backup includes WTX1 recordings: every generation of every pair as `transcripts/<sid>.<k>.<gen>.wtx`
    (exactly phys_len bytes, no `.idx`), manifest `included` / `one-kind` / `not-requested`; restored
    byte-identical (stage verifies, apply rebinds the ledger to the copied inodes, the live
    generation comes back `recovered`); the PR6a `wtx-not-archived` limitation is gone;
  * a damaged pair is excluded as a unit (no member of it, both kinds `excluded` with the reason, an
    alarm), the backup goes on; restored as `absent` and Store.recover keeps it `absent`;
  * a pair whose bytes change between the verify and the emit pass: the container is rebuilt once
    without it; a second change fails the backup;
  * the snapshot under concurrent writes holds committed prefixes only (the stage re-verifies every
    member at exact size); pins defer a retire until the snapshot is released; one snapshot per
    process (busy); the hold budget aborts a snapshot (busy);
  * the control socket: happy path through `hostops --live`, the peer check, framing / op / key
    errors, a slow first request, a third connection, a second start while one is in flight (busy),
    disconnect after submit (the worker removes the spool), spool expiry, symlinked / stale socket
    paths; an unanswered socket → `hostops backup --live` refused;
  * retention purge by `archived_at` (files retired through the ledger, RK and descriptors gone, no
    tombstone), recent / migration-owned recordings kept;
  * a 3.7 (pre-3.8) archive imported onto a migrated volume: its plaintext is inventoried again and
    migrated; a sid erased on the volume is dropped, never converted.
Temp dirs; no network, no Docker.
"""
import asyncio
import contextlib
import errno
import hashlib
import io
import json
import os
import shutil
import socket
import sqlite3
import struct
import sys
import tarfile
import tempfile
import threading
import time
import zlib
from pathlib import Path

BASE = tempfile.mkdtemp(prefix="wt-txbackup-")
os.chmod(BASE, 0o700)
os.environ["WEBTERM_DATA_DIR"] = BASE
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
os.environ.setdefault("WEBTERM_UPDATE_CHECK", "0")
os.environ["WEBTERM_TX_RECORDINGS"] = "1"
os.environ["WEBTERM_TEST_GATE"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import backup, config, ctlsock, db, hostops, txdesc, txhub  # noqa: E402
from app import erasure as er  # noqa: E402
from app import keyring as kr  # noqa: E402
from app import migration as mg  # noqa: E402
from app import snapshot as wts  # noqa: E402
from app import txstore as ts  # noqa: E402
from app import wtbk  # noqa: E402

PASS = "parola-de-test-lunga"
INST = bytes(range(0xa0, 0xb0))
KWK = os.urandom(32)
MK = os.urandom(32)
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {str(detail)[-500:]}"))


def raises(fn, exc):
    try:
        fn()
    except exc:
        return True
    except BaseException as e:  # noqa: BLE001
        print("     got", type(e).__name__, str(e)[:200])
        return False
    return False


# ── volume fixtures ──────────────────────────────────────────────────────────


def use(d):
    config.DATA_DIR = Path(d)
    config.DB_PATH = config.DATA_DIR / "webterm.db"
    config.TRANSCRIPT_DIR = config.DATA_DIR / "transcripts"
    config.ARCHIVE_DIR = config.TRANSCRIPT_DIR / "arhiva"


def keys_blob():
    envs = (kr.wrap_under_mk(MK, kr.KT_KWK, KWK), kr.wrap_under_mk(MK, kr.KT_SNK, os.urandom(32)),
            kr.wrap_under_kwk(KWK, kr.KT_FK, os.urandom(32)))
    return kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(MK), (), envs), MK)


def host_keys():
    blob = (config.DATA_DIR / "keys.wtk").read_bytes()
    return backup.HostKeys(kr.open_keyring_bytes(blob, MK, kr.PROFILE_V1), MK)


def schema(con):
    con.executescript(db.SCHEMA)
    for m in db.MIGRATIONS:
        try:
            con.execute(m)
        except sqlite3.OperationalError:
            pass                               # coloană deja prezentă / tabelă ulterioară


def new_volume():
    use(BASE)
    os.makedirs(config.ARCHIVE_DIR, exist_ok=True)
    con = sqlite3.connect(str(config.DB_PATH))
    schema(con)
    con.commit()
    con.close()
    (config.DATA_DIR / "keys.wtk").write_bytes(keys_blob())
    ts.create_test_volume(config.DB_PATH)
    return host_keys()


def sql(q, *a):
    con = sqlite3.connect(str(config.DB_PATH), isolation_level=None)
    try:
        return con.execute(q, a).fetchall()
    finally:
        con.close()


def remark():
    """After an apply the DB is another inode: the fixture marks it again (no users/hosts rows)."""
    sql("DELETE FROM tx_state WHERE key='test_volume'")
    ts.create_test_volume(config.DB_PATH)


async def open_store(gen_limits=(2, 1 << 20)):
    st = ts.Store(transcripts_dir=config.TRANSCRIPT_DIR, kwk=KWK, installation_id=INST, gen_limits=gen_limits)
    await er.boot(st)
    await st.recover()
    ts.set_backup_source(st, asyncio.get_running_loop())
    return st


async def close_store(st):
    ts.clear_backup_source(st)
    await st.shutdown()
    st.close()
    er.reset()


CAST_HDR = b'{"version": 2, "width": 80, "height": 24}\n'


async def make_rec(st, chunks=5, close=True, size=200):
    sid = os.urandom(16).hex()
    sql("INSERT INTO sessions(id, host_id, title, state, created, rows, cols) VALUES(?,?,?,?,?,?,?)",
        sid, 1, "t", "live", time.time(), 24, 80)
    rec = await st.start_recorder(sid, track_agent=False)
    out, cast = b"", CAST_HDR
    rec.feed_cast_only(CAST_HDR, at=rec.received)
    for i in range(chunks):
        o = os.urandom(size)
        c = json.dumps([0.1 * i, "o", o.hex()[:20]]).encode() + b"\n"
        rec.feed(o, c, at=rec.received)
        out += o
        cast += c
        await rec.checkpoint()
    if close:
        await rec.close()
        sql("UPDATE sessions SET state='closed', closed_at=? WHERE id=?", time.time(), sid)
    return sid, out, cast, rec


async def read_all(st, sid, kind="out"):
    snap = await st.open(sid, kind, access=st.access(sid, "t", "test"))
    try:
        return await snap.read(0, snap.length)
    finally:
        snap.close()


def descs(st, sid):
    out = {}
    env = sql("SELECT envelope FROM session_keys WHERE sid=?", sid)[0][0]
    for kind, blob, version in sql("SELECT kind, blob, version FROM tx_descriptors WHERE sid=?", sid):
        out[kind] = st.decode((blob, version), sid, kind, bytes(env))
    return out


def live_blob(hk):
    """`hostops backup --live` through the socket: the streamed WTBK2 it writes to stdout."""
    out = io.BytesIO()
    hostops._live_via_socket(hk, PASS, True, out)
    return out.getvalue()


def archive(blob, hk):
    raw = backup.decrypt(blob, PASS)
    r = wts.Reader(io.BytesIO(raw))
    r.unlock(snk=hk.ring.snk, installation_id=INST, mk=hk.mk)
    plain = zlib.decompress(b"".join(r.chunks()), 31)
    mem = {}
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as t:
        for m in t.getmembers():
            if m.isfile():
                mem[m.name] = t.extractfile(m).read()
    return mem, json.loads(mem[backup.CONTENT_MANIFEST])


def recs_of(man):
    return {(r["sid"], r["kind"]): (r["state"], r.get("reason", "")) for r in man["recordings"]}


def gen_members(mem, sid=None):
    return sorted(n for n in mem if n.endswith(".wtx") and (sid is None or n.startswith("transcripts/" + sid)))


async def backup_blob(hk, include=True):
    return await asyncio.to_thread(backup.make_encrypted, PASS, include, hk)


def apply(blob, hk, **kw):
    backup.stage_restore(blob, PASS, keys=hk, **kw)
    assert backup.apply_pending_restore(keys=hk) is True
    return host_keys()


# ── 1. included, restored byte-identical ────────────────────────────────────


async def g_included(hk):
    print("== backup includes WTX1 recordings, restore byte-identical ==")
    st = await open_store()
    a, a_out, a_cast, _ = await make_rec(st, chunks=5)
    c, c_out, c_cast, c_rec = await make_rec(st, chunks=3, close=False)
    blob = await backup_blob(hk)
    mem, man = archive(blob, hk)
    rs = recs_of(man)
    da, dc = descs(st, a), descs(st, c)
    want = sorted("transcripts/" + ts.gen_name(s, k, g.gen_id.hex())
                  for s, d in ((a, da), (c, dc)) for k in d for g in d[k].generations)
    check("v2 manifest: both pairs `included`, the PR6a `wtx-not-archived` limitation gone",
          man["format"] == "wts-content-2" and rs[(a, "out")] == ("included", "") and rs[(a, "cast")][0] == "included"
          and rs[(c, "out")][0] == "included" and "wtx-not-archived" not in json.dumps(man), rs)
    check("every generation of both kinds is a member (several generations per kind), no .idx",
          gen_members(mem) == want and len(da["out"].generations) >= 2
          and not any(n.endswith(".idx") for n in mem), (gen_members(mem), want))
    sizes_ok = all(len(mem["transcripts/" + ts.gen_name(s, k, g.gen_id.hex())]) == g.phys_len
                   for s, d in ((a, da), (c, dc)) for k in d for g in d[k].generations)
    check("member size == committed phys_len (the live generation's committed prefix only)", sizes_ok)
    files = {e["name"]: e for e in man["files"]}
    check("each member hashed in the manifest", all(files[n]["sha256"] == hashlib.sha256(mem[n]).hexdigest()
                                                     for n in gen_members(mem)))
    nr = archive(await backup_blob(hk, include=False), hk)
    check("without recordings: no member, every descriptor `not-requested`",
          not gen_members(nr[0]) and {v[0] for v in recs_of(nr[1]).values()} == {"not-requested"}, recs_of(nr[1]))
    # după backup, sesiunea vie mai scrie: nimic din asta nu e în arhivă
    more = os.urandom(300)
    c_rec.feed(more, b"", at=c_rec.received)
    await c_rec.checkpoint()
    await close_store(st)
    hk = apply(blob, hk)
    remark()
    st = await open_store()
    check("restored: A's out and cast byte-identical", await read_all(st, a) == a_out
          and await read_all(st, a, "cast") == a_cast)
    check("restored: C is exactly its committed prefix at backup time, live → recovered",
          await read_all(st, c) == c_out and descs(st, c)["out"].generations[-1].state == txdesc.STATE_RECOVERED)
    led = sql("SELECT gen_id, kind, dev, ino FROM tx_files WHERE sid=? AND state='published'", a)
    bound = all((os.stat(config.TRANSCRIPT_DIR / ts.gen_name(a, k, g)).st_dev,
                 os.stat(config.TRANSCRIPT_DIR / ts.gen_name(a, k, g)).st_ino) == (dev, ino) for g, k, dev, ino in led)
    check("apply rebinds the restored ledger to the copied inodes (retire can unlink them)", led and bound, led)
    return st, hk, a, a_out


# ── 2. damaged pair, rebuild ────────────────────────────────────────────────


async def g_damaged(st, hk, a, a_out):
    print("== a damaged pair is excluded as a unit; a changed pair rebuilds once ==")
    b, _b_out, _b_cast, _ = await make_rec(st, chunks=4)
    db_ = descs(st, b)
    g = db_["cast"].generations[0]
    p = config.TRANSCRIPT_DIR / ts.gen_name(b, "cast", g.gen_id.hex())
    raw = bytearray(p.read_bytes())
    raw[txformat_prefix() + 12] ^= 1
    p.write_bytes(bytes(raw))
    st.alarms.clear()
    blob = await backup_blob(hk)
    mem, man = archive(blob, hk)
    rs = recs_of(man)
    check("damaged pair: BOTH kinds `excluded` with the reason, no member of it",
          rs[(b, "out")][0] == "excluded" and rs[(b, "cast")][0] == "excluded"
          and rs[(b, "out")][1].startswith("generation") and not gen_members(mem, b), rs.get((b, "out")))
    check("…an alarm names it, the other pair is still included",
          any(c == "transcript.backupExcluded" and b in d for c, d in st.alarms) and rs[(a, "out")][0] == "included",
          st.alarms)
    # schimbare între trecerea de verificare şi cea de copiere: o reconstruire fără perechea aceea
    orig = ts.BackupSnapshot.verify_pair
    hits = []

    def flaky(self, pr):
        why = orig(self, pr)
        if not why and pr.sid == a and not hits:
            hits.append(1)
            pr.gens[0].sha = b"\0" * 32
        return why
    ts.BackupSnapshot.verify_pair = flaky
    try:
        blob2 = await backup_blob(hk)
    finally:
        ts.BackupSnapshot.verify_pair = orig
    mem2, man2 = archive(blob2, hk)
    check("changed under a pin: rebuilt once, that pair `excluded` (changed-while-copied), still restorable",
          recs_of(man2)[(a, "out")] == ("excluded", "changed-while-copied") and not gen_members(mem2, a)
          and backup.verify_restorable(blob2, PASS, keys=hk)["restorable"], recs_of(man2).get((a, "out")))

    def always(self, pr):
        why = orig(self, pr)
        if not why:
            pr.gens[0].sha = b"\0" * 32
        return why
    ts.BackupSnapshot.verify_pair = always
    try:
        bad = await asyncio.to_thread(raises, lambda: backup.make_encrypted(PASS, True, hk), ValueError)
    finally:
        ts.BackupSnapshot.verify_pair = orig
    check("a second change → the backup fails (nothing returned)", bad)
    await close_store(st)
    hk = apply(blob, hk)
    remark()
    st = await open_store()
    stat_b = dict(sql("SELECT kind, status FROM tx_descriptors WHERE sid=?", b))
    check("restored: the excluded pair is `absent` and recover keeps it absent (not damaged)",
          stat_b == {"out": "absent", "cast": "absent"} and await read_all(st, a) == a_out, stat_b)
    return st, hk


def txformat_prefix():
    from app import txformat
    return txformat.PREFIX_LEN


# ── 3. concurrency, pins, slot, hold budget ─────────────────────────────────


async def g_concurrent(st, hk):
    print("== snapshot under concurrent writes, pins, one snapshot per process, hold budget ==")
    d, _o, _c, rec = await make_rec(st, chunks=2, close=False)
    stop = asyncio.Event()

    async def writer():
        i = 0
        while not stop.is_set():
            rec.feed(os.urandom(500), b"", at=rec.received)
            await rec.checkpoint()
            i += 1
            await asyncio.sleep(0)
        return i
    wt = asyncio.ensure_future(writer())
    blob = await backup_blob(hk)
    stop.set()
    n = await wt
    mem, man = archive(blob, hk)
    tdir = tempfile.mkdtemp(dir=BASE)
    info = await asyncio.to_thread(backup.verify_restorable, blob, PASS, hk)
    backup.stage_restore(blob, PASS, keys=hk)
    staged = [x for x in os.listdir(BASE) if x.startswith(backup.SET_PREFIX)]
    check("concurrent writes during the backup: every member passes the stage check at its exact committed size",
          n > 0 and recs_of(man)[(d, "out")][0] == "included" and info["restorable"] and staged, (n, staged))
    os.unlink(backup._restore_flag())
    for x in staged:
        shutil.rmtree(os.path.join(BASE, x))
    shutil.rmtree(tdir)
    last = descs(st, d)["out"].generations[-1]
    on_disk = os.path.getsize(config.TRANSCRIPT_DIR / ts.gen_name(d, "out", last.gen_id.hex()))
    member = [len(mem[m]) for m in gen_members(mem, d) if last.gen_id.hex() in m]
    check("…bytes written after the snapshot are not in the archive", not member or member[0] <= on_disk)
    await rec.close()
    # pin-urile amână retragerea până la release
    e, _eo, _ec, _ = await make_rec(st, chunks=2)
    snap = await asyncio.to_thread(ts.backup_snapshot, os.path.join(BASE, "copy.db"), kwk=KWK, inst=INST)
    try:
        await st.txn(lambda c: c.execute("UPDATE tx_descriptors SET archived_at=1 WHERE sid=?", (e,)))
        gens = [ts.gen_name(e, k, g.gen_id.hex()) for k, dd in descs(st, e).items() for g in dd.generations]
        await st.purge(e, time.time())
        still = all((config.TRANSCRIPT_DIR / n).exists() for n in gens)
        busy = await asyncio.to_thread(raises, lambda: backup.make_encrypted(PASS, True, hk), backup.SnapshotBusy)
    finally:
        snap.release()
    await asyncio.sleep(0.05)
    for _ in range(50):
        if not any((config.TRANSCRIPT_DIR / n).exists() for n in gens):
            break
        await asyncio.sleep(0.02)
    check("a purge while a snapshot pins the generations: files kept until release, then unlinked",
          still and not any((config.TRANSCRIPT_DIR / n).exists() for n in gens))
    check("one snapshot per process: a second backup meanwhile → busy (SnapshotBusy → backup.busy)", busy)
    os.unlink(os.path.join(BASE, "copy.db"))
    snap = await asyncio.to_thread(ts.backup_snapshot, os.path.join(BASE, "copy.db"), kwk=KWK, inst=INST, hold_secs=0)
    try:
        held = await asyncio.to_thread(raises, lambda: [snap.verify_pair(p) for p in snap.pairs], ts.BackupBusy)
    finally:
        snap.release()
        os.unlink(os.path.join(BASE, "copy.db"))
    await asyncio.sleep(0.01)
    check("hold budget exceeded → the snapshot is aborted (busy), pins released", held and not st._pins)
    check("txhub.install registers the Store as the backup source, uninstall clears it",
          _install_roundtrip(st))
    ts.set_backup_source(st, asyncio.get_running_loop())


async def g_recompact_backup(st, hk):
    print("== §12.11.14: recompaction under a concurrent backup; v2 members restored byte-identical ==")
    st.write_ver = 1
    sid = os.urandom(16).hex()
    sql("INSERT INTO sessions(id, host_id, title, state, created, rows, cols) VALUES(?,?,?,?,?,?,?)",
        sid, 1, "t", "live", time.time(), 24, 80)
    rec = await st.start_recorder(sid, track_agent=False)
    out = b"".join(b"%06d drwxr-xr-x 2 root root 4096 Nov 27 12:00 gateway\r\n" % i for i in range(4000))
    cast = CAST_HDR + b"".join(json.dumps([0.1 * i, "o", "line %d\r\n" % i]).encode() + b"\n" for i in range(800))
    rec.feed_cast_only(cast, at=rec.received)
    for i in range(0, len(out), 40000):
        rec.feed(out[i:i + 40000], b"", at=rec.received)
        await rec.checkpoint()
    await rec.close()
    sql("UPDATE sessions SET state='closed', closed_at=? WHERE id=?", time.time(), sid)
    st.write_ver = 2
    old = [ts.gen_name(sid, k, g.gen_id.hex()) for k, d in descs(st, sid).items() for g in d.generations]
    check("fixture: a closed v1 recording", all(g.ver == 1 for d in descs(st, sid).values() for g in d.generations))
    # backup pornit înainte (pasul 1 a fixat generaţiile v1): recompactarea publică, unlink-ul aşteaptă
    snap = await asyncio.to_thread(ts.backup_snapshot, os.path.join(BASE, "copy.db"), kwk=KWK, inst=INST)
    try:
        async with st.lease(sid):
            res = await st.recompact(sid)
        kept = all((config.TRANSCRIPT_DIR / n).exists() for n in old)
        pair = [p for p in snap.pairs if p.sid == sid]
        verdict = await asyncio.to_thread(lambda: [snap.verify_pair(p) for p in pair])
        copied = b"".join(await asyncio.to_thread(lambda: [b"".join(snap.gen_chunks(p, bg)) for p in pair for bg in p.gens]))
    finally:
        snap.release()
        os.unlink(os.path.join(BASE, "copy.db"))
    for _ in range(50):
        if not any((config.TRANSCRIPT_DIR / n).exists() for n in old):
            break
        await asyncio.sleep(0.02)
    check("recompaction during a backup: published, the old generations stay pinned; the snapshot still "
          "verifies and copies them whole", res and kept and verdict == [""]
          and len(copied) == sum(bg.g.phys_len for p in pair for bg in p.gens), (res, kept, verdict))
    check("…then unlinked", not any((config.TRANSCRIPT_DIR / n).exists() for n in old))
    blob = await backup_blob(hk)
    mem, man = archive(blob, hk)
    d = descs(st, sid)
    check("a backup after it carries the v2 generations at their exact phys_len",
          all(len(mem["transcripts/" + ts.gen_name(sid, k, g.gen_id.hex())]) == g.phys_len and g.ver == 2
              for k in d for g in d[k].generations) and recs_of(man)[(sid, "out")][0] == "included")
    await close_store(st)
    hk = apply(blob, hk)
    remark()
    st = await open_store()
    check("restored v2 recording: replay byte-identical (both kinds)",
          await read_all(st, sid) == out and await read_all(st, sid, "cast") == cast)
    return st, hk


def _install_roundtrip(st):
    saved = txhub._store
    txhub.install(st)
    ok = ts.backup_source() is not None and ts.backup_source()[0] is st
    txhub._store = None
    ts.clear_backup_source(st)
    ok = ok and ts.backup_source() is None
    txhub._store = saved
    return ok


# ── 4. control socket ───────────────────────────────────────────────────────


def raw_conn(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(path)
    return s


def send(s, obj=None, raw=None):
    b = json.dumps(obj).encode() if raw is None else raw
    try:
        s.sendall(struct.pack(">I", len(b)) + b)
    except OSError:
        pass                                   # serverul a închis deja (refuz înainte de citire)


def recv(s):
    try:
        h = s.recv(4)
        if len(h) < 4:
            return None
        (n,) = struct.unpack(">I", h)
        buf = b""
        while len(buf) < n:
            x = s.recv(n - len(buf))
            if not x:
                break
            buf += x
        return json.loads(buf)
    except (OSError, ValueError):
        return None


def closed(s):
    try:
        return s.recv(1) == b""
    except OSError:
        return True


def spool_files():
    d = config.DATA_DIR / ".ctl" / "spool"
    return sorted(os.listdir(d)) if d.is_dir() else []


async def g_socket(st, hk):
    print("== control socket for hostops backup --live ==")
    audits = []

    async def rec_audit(ts_, actor, ip, method, path, status, det=""):
        audits.append((actor, path, status, det))
    ctlsock.audit.record = rec_audit
    backup.set_host_keys_provider(lambda: hk)
    ok = await ctlsock.start()
    path = ctlsock.socket_path()
    mode = os.stat(path).st_mode & 0o777
    dmode = os.stat(config.DATA_DIR / ".ctl").st_mode & 0o777
    check("created at boot: .ctl 0700, backup.sock 0600, System health ok", ok and mode == 0o600 and dmode == 0o700
          and ctlsock.health() is None, (oct(mode), oct(dmode)))
    # calea fericită, prin hostops (acelaşi consumator ca backup.sh)
    blob = await asyncio.to_thread(live_blob, hk)
    mem, man = archive(blob, hk)
    check("hostops --live through the socket: a verified WTBK2(WTS1) with the recordings included",
          blob[:5] == b"WTBK2" and gen_members(mem) and {v[0] for v in recs_of(man).values()} >= {"included"} and spool_files() == [])
    check("…and the archive restores (stage check)", backup.verify_restorable(blob, PASS, keys=hk)["restorable"])
    r = wtbk.Reader(io.BytesIO(blob), PASS)
    sv = backup.verify_host_stream(r, keys=hk, max_plaintext=r.plain_len, unpacked_len=r.unpacked_len)
    check("…read as a stream (restore.sh): the unpacked size the gateway announced is exact",
          sv["restorable"] and sv["unpacked_len"] == r.unpacked_len and r.done)
    # peer străin (simulat: verificarea SO_PEERCRED refuză uid-ul nostru)
    check("peer rule: uid 0 and the gateway uid only", ctlsock.peer_ok(0) and ctlsock.peer_ok(os.geteuid())
          and not ctlsock.peer_ok(65534))
    saved = ctlsock.peer_ok
    ctlsock.peer_ok = lambda uid: False
    try:
        s = await asyncio.to_thread(raw_conn, path)
        await asyncio.to_thread(send, s, {"v": 1, "op": "snapshot.start", "id": 1, "profile": "portable",
                                          "recordings": "none"})
        refused = await asyncio.to_thread(closed, s)
        s.close()
    finally:
        ctlsock.peer_ok = saved
    check("a foreign peer is closed before any byte is read, audited (uid, pid); no spool",
          refused and spool_files() == [] and any(a[1] == "/ctl/connect" and a[2] == 403 and "pid=" in a[3]
                                                  for a in audits), audits[-3:])
    # erori de protocol
    for name, payload in (("oversized frame", b"x" * (ctlsock.FRAME_MAX + 1)),
                          ("invalid json", b"{nope"),
                          ("unknown op", json.dumps({"v": 1, "op": "shell", "id": 1}).encode()),
                          ("extra key", json.dumps({"v": 1, "op": "snapshot.release", "id": 1, "snap": "x",
                                                    "path": "/etc"}).encode()),
                          ("wrong version", json.dumps({"v": 2, "op": "snapshot.release", "id": 1, "snap": "x"}).encode())):
        s = await asyncio.to_thread(raw_conn, path)
        if name == "oversized frame":
            await asyncio.to_thread(s.sendall, struct.pack(">I", len(payload)))
        else:
            await asyncio.to_thread(send, s, raw=payload)
        ans = await asyncio.to_thread(recv, s)
        gone = await asyncio.to_thread(closed, s)
        s.close()
        check("protocol: %s → one error frame, then close" % name,
              ans is not None and ans.get("ok") is False and gone, ans)
    # cererea întâi prea târzie
    saved_first = ctlsock.FIRST_REQ_SECS
    ctlsock.FIRST_REQ_SECS = 0.3
    try:
        s = await asyncio.to_thread(raw_conn, path)
        slow = await asyncio.to_thread(closed, s)
        s.close()
    finally:
        ctlsock.FIRST_REQ_SECS = saved_first
    check("a peer that sends nothing in time is disconnected", slow)
    # worker injectat care blochează: concurenţă, deconectare după submit
    gate = threading.Event()
    seen = {}

    def blocking(f, include, cancel):
        seen["started"] = True
        while not cancel.is_set() and not gate.is_set():
            time.sleep(0.01)
        seen["cancel"] = cancel.is_set()
        f.write(b"partial")
        if cancel.is_set():
            raise backup.SnapshotBusy("cancelled")
    ctlsock._s.worker = blocking
    try:
        s1 = await asyncio.to_thread(raw_conn, path)
        await asyncio.to_thread(send, s1, {"v": 1, "op": "snapshot.start", "id": 1, "profile": "portable",
                                           "recordings": "all"})
        for _ in range(200):
            if seen.get("started"):
                break
            await asyncio.sleep(0.01)
        s2 = await asyncio.to_thread(raw_conn, path)
        await asyncio.to_thread(send, s2, {"v": 1, "op": "snapshot.start", "id": 1, "profile": "portable",
                                           "recordings": "all"})
        a2 = await asyncio.to_thread(recv, s2)
        check("a second snapshot.start while one is in flight → backup.busy", a2 and a2.get("code") == "backup.busy", a2)
        s3 = await asyncio.to_thread(raw_conn, path)
        third = await asyncio.to_thread(closed, s3)
        s3.close()
        check("a third connection is closed at accept", third)
        s2.close()
        had_spool = spool_files()
        s1.close()                                      # deconectare după submit
        for _ in range(300):
            if "cancel" in seen and ctlsock._s.inflight is None and not spool_files():
                break
            await asyncio.sleep(0.01)
        check("disconnect after submit: the worker sees the cancel and removes its spool; the slot frees",
              had_spool and seen.get("cancel") is True and spool_files() == [] and ctlsock._s.inflight is None,
              (had_spool, seen, spool_files()))
    finally:
        ctlsock._s.worker = None
        gate.set()
    # M3: două conexiuni care cer start în ACELAŞI timp, cât estimarea de spaţiu (primul await)
    # durează: slotul se ia sincron, deci exact una trece; slotul se eliberează după worker
    saved_est = ctlsock._estimate
    calls = {"n": 0, "workers": 0}

    def slow_est():
        calls["n"] += 1
        time.sleep(0.3)
        return 0

    def quick(f, include, cancel):
        calls["workers"] += 1
        f.write(b"x")
    ctlsock._estimate = slow_est
    ctlsock._s.worker = quick
    try:
        start = {"v": 1, "op": "snapshot.start", "id": 1, "profile": "portable", "recordings": "none"}
        s1 = await asyncio.to_thread(raw_conn, path)
        s2 = await asyncio.to_thread(raw_conn, path)
        await asyncio.gather(asyncio.to_thread(send, s1, start), asyncio.to_thread(send, s2, start))
        a1, a2 = await asyncio.gather(asyncio.to_thread(recv, s1), asyncio.to_thread(recv, s2))
        codes = sorted(str((a or {}).get("code")) for a in (a1, a2))
        check("M3: two concurrent starts during the space estimate → exactly one admitted, the other busy",
              codes.count("backup.busy") == 1 and calls["n"] == 1 and calls["workers"] == 1, (a1, a2, calls))
        s1.close()
        s2.close()
        for _ in range(100):
            if ctlsock._s.inflight is None and not spool_files():
                break
            await asyncio.sleep(0.01)
        check("…the slot is free again once the worker finished, nothing spooled",
              ctlsock._s.inflight is None and spool_files() == [])
        # deconectare în faza de estimare: slotul se eliberează, niciun spool, niciun worker
        calls.update(n=0, workers=0)
        s1 = await asyncio.to_thread(raw_conn, path)
        await asyncio.to_thread(send, s1, start)
        await asyncio.sleep(0.05)
        held = ctlsock._s.inflight is not None
        s1.close()
        for _ in range(100):
            if ctlsock._s.inflight is None and calls["n"] == 1:
                break
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.4)
        check("M3: disconnect during the estimate → slot held during it, released after, no spool",
              held and ctlsock._s.inflight is None and spool_files() == [], (held, calls, spool_files()))
        # buget agregat: spool-urile gata + estimarea peste partea permisă din disc → noSpace, slot liber
        saved_share = ctlsock.SPOOL_SHARE
        ctlsock.SPOOL_SHARE = 0.0
        ctlsock._estimate = lambda: 1
        try:
            s1 = await asyncio.to_thread(raw_conn, path)
            await asyncio.to_thread(send, s1, start)
            a1 = await asyncio.to_thread(recv, s1)
            s1.close()
        finally:
            ctlsock.SPOOL_SHARE = saved_share
        check("M3: aggregate spool budget exceeded → backup.noSpace, the slot released",
              a1 and a1.get("code") == "backup.noSpace" and ctlsock._s.inflight is None, a1)
    finally:
        ctlsock._estimate = saved_est
        ctlsock._s.worker = None
    # Codex M2: spaţiul spool-ului pe ACELAŞI volum cu DB-ul viu — estimarea încape, dar nu şi copia
    # DB-ului (snapshot, apoi verificarea) plus rezerva gateway-ului → noSpace înainte de vreun worker
    gib = 1 << 30
    real_f, real_db = os.fstatvfs, backup.db_size

    def fake_vfs(free_spool, free_files):
        def f(fd):
            a = free_spool if fd == ctlsock._s.spool_fd else free_files
            return os.statvfs_result((4096, 4096, (100 * gib) // 4096, a // 4096, a // 4096,
                                      1 << 20, 1 << 20, 1 << 20, 0, 255))
        return f
    start = {"v": 1, "op": "snapshot.start", "id": 7, "profile": "portable", "recordings": "none"}
    est = ctlsock._estimate()
    os.fstatvfs = fake_vfs(int(est * ctlsock.SPACE_SLACK) + 5 * gib + gib, 90 * gib)
    backup.db_size = lambda: 2 * gib                    # un DB „mare": 2 GiB, mai mult decât rămâne
    try:
        s1 = await asyncio.to_thread(raw_conn, path)
        await asyncio.to_thread(send, s1, start)
        a1 = await asyncio.to_thread(recv, s1)
        s1.close()
    finally:
        os.fstatvfs, backup.db_size = real_f, real_db
    check("M2: spool + DB copy + gateway reserve counted on the shared volume → backup.noSpace, nothing spooled",
          a1 and a1.get("code") == "backup.noSpace" and spool_files() == [] and ctlsock._s.inflight is None, a1)
    # bugetul dur al worker-ului: admis (estimarea încape), dar scrierea spool-ului ar trece sub rezervă
    os.fstatvfs = fake_vfs(90 * gib, 5 * gib + (1 << 20))
    try:
        s1 = await asyncio.to_thread(raw_conn, path)
        await asyncio.to_thread(send, s1, start)
        a1 = await asyncio.to_thread(recv, s1)
        s1.close()
    finally:
        os.fstatvfs = real_f
    for _ in range(100):
        if ctlsock._s.inflight is None:
            break
        await asyncio.sleep(0.02)
    check("M2: the spool writer stops at the reserve → backup.noSpace, the spool removed, slot free",
          a1 and a1.get("code") == "backup.noSpace" and spool_files() == [] and ctlsock._s.inflight is None, a1)
    # spool gata, necitit: expiră
    c = await asyncio.to_thread(ctlsock.Client, path)
    try:
        doc = await asyncio.to_thread(c.call, "snapshot.start", 60, profile="portable", recordings="none")
        present = spool_files()
        saved_clock = ctlsock._s.clock
        ctlsock._s.clock = lambda: saved_clock() + ctlsock.SPOOL_IDLE_SECS + 1
        try:
            n = ctlsock.expire_spools()
        finally:
            ctlsock._s.clock = saved_clock
        r = await asyncio.to_thread(c.call, "snapshot.read", None, snap=doc.get("snap"), offset=0, length=10)
    finally:
        c.close()
    check("a ready spool unread for 60 s is removed; a later read is refused",
          doc.get("ok") and present and n == 1 and spool_files() == [] and r.get("ok") is False, (doc, r))
    await ctlsock.stop()
    check("stop: the socket is gone", not os.path.lexists(path))
    # socket fără răspuns → hostops refuză
    refused = await asyncio.to_thread(raises, lambda: live_blob(hk), hostops.Refused)
    check("no socket while the gateway runs → hostops backup --live refused (never a direct read)", refused)
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(path)                                     # legat, fără listen: nimeni nu răspunde
    try:
        refused = await asyncio.to_thread(raises, lambda: live_blob(hk), hostops.Refused)
    finally:
        dead.close()
        os.unlink(path)
    check("a socket that does not answer → refused", refused)
    check("hostops decides it needs the socket (flag on / artefacts)", hostops._needs_socket())
    # creare: socket vechi al nostru → înlocuit; fişier străin → fără socket + alarmă; .ctl symlink → refuz
    old = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old.bind(path)
    old.close()
    ok = await ctlsock.start()
    await ctlsock.stop()
    check("a stale socket of ours is unlinked and rebound", ok)
    Path(path).write_bytes(b"not a socket")
    ok = await ctlsock.start()
    check("a non-socket at backup.sock → no socket, System health warning", not ok
          and ctlsock.health() and ctlsock.health()[1] == "ctl_socket_unavailable")
    os.unlink(path)
    os.rename(config.DATA_DIR / ".ctl", config.DATA_DIR / ".ctl-real")
    os.symlink(config.DATA_DIR / ".ctl-real", config.DATA_DIR / ".ctl")
    ok = await ctlsock.start()
    check("a symlinked .ctl → no socket (alarm)", not ok and ctlsock.health() is not None)
    os.unlink(config.DATA_DIR / ".ctl")
    os.rename(config.DATA_DIR / ".ctl-real", config.DATA_DIR / ".ctl")
    os.chmod(config.DATA_DIR / ".ctl", 0o755)
    ok = await ctlsock.start()
    check("a .ctl that is not 0700 → no socket", not ok)
    os.chmod(config.DATA_DIR / ".ctl", 0o700)
    ok = await ctlsock.start()
    check("fixed → the socket comes back, alarm cleared", ok and ctlsock.health() is None)
    await ctlsock.stop()


# ── 5. retention purge ──────────────────────────────────────────────────────


# Producţia: container read_only, /tmp tmpfs de 64 MiB (3.8 rc3: `hostops backup --live` murea cu
# ENOSPC). Un temporar fără `dir=` explicit (directorul temporar al sistemului) eşuează aici ca acolo.
_TMP_POS = {"mkstemp": 2, "mkdtemp": 2, "TemporaryDirectory": 2, "TemporaryFile": 6,
            "NamedTemporaryFile": 6, "SpooledTemporaryFile": 7}


@contextlib.contextmanager
def system_tmp_full():
    hits = []
    saved = {n: getattr(tempfile, n) for n in _TMP_POS}

    def wrap(n, f):
        def g(*a, **kw):
            d = kw.get("dir", a[_TMP_POS[n]] if len(a) > _TMP_POS[n] else None)
            if d is None:
                hits.append(n)
                raise OSError(errno.ENOSPC, "No space left on device (test: the system temp dir is full)")
            return f(*a, **kw)
        return g
    for n, f in saved.items():
        setattr(tempfile, n, wrap(n, f))
    try:
        yield hits
    finally:
        for n, f in saved.items():
            setattr(tempfile, n, f)


def work_entries():
    d = config.DATA_DIR / "backups" / backup.WORK_DIR
    return sorted(os.listdir(d)) if d.is_dir() else []


async def g_workdir(st, hk):
    print("== protected backups with the system temp dir full (scratch on the data volume) ==")
    backup.set_host_keys_provider(lambda: hk)
    ok = await ctlsock.start()
    try:
        with system_tmp_full() as hits:
            blob = await asyncio.to_thread(live_blob, hk)
            name = await asyncio.to_thread(backup.run_scheduled_backup, True, hk)
            dl = await asyncio.to_thread(backup.make_encrypted, PASS, True, hk)
            v1 = await asyncio.to_thread(backup.verify_restorable, blob, PASS, keys=hk)
            v2 = await asyncio.to_thread(backup.verify_stored, name, keys=hk)
        mem, man = archive(blob, hk)
        check("hostops --live, scheduled, download and both verifies succeed; nothing in the system temp dir",
              ok and gen_members(mem) and v1["restorable"] and v2 and dl[:5] == b"WTBK1" and hits == [], hits)
        check("…the work dir is left empty, the socket spool too", work_entries() == [] and spool_files() == [],
              (work_entries(), spool_files()))
        orig = backup._TarOut.finish

        def boom(self, *a, **kw):
            raise OSError(errno.EIO, "test: I/O error")
        backup._TarOut.finish = boom
        try:
            failed = await asyncio.to_thread(raises, lambda: backup.make_encrypted(PASS, True, hk), OSError)
            live_failed = await asyncio.to_thread(raises, lambda: live_blob(hk),
                                                  hostops.Refused)
        finally:
            backup._TarOut.finish = orig
        check("a failed protected backup (in-app and --live) leaves nothing in the work dir",
              failed and live_failed and work_entries() == [] and spool_files() == [], (work_entries(), spool_files()))
        held = []
        with backup.work_dir("hostops-") as d:
            held.append(sorted(os.listdir(config.DATA_DIR / "backups" / backup.WORK_DIR)))
            with system_tmp_full() as hits2:
                n = backup.sweep_work(grace=0)
            held.append(os.path.isdir(d))
        check("a sweep never removes a work dir held by a live operation", n == 0 and held[1] and not hits2, held)
        with contextlib.ExitStack() as stack:
            on_vol = hostops._verify_scratch(stack)
            vol_ok = on_vol.startswith(str(config.DATA_DIR / "backups" / backup.WORK_DIR) + os.sep)
        saved_wd = backup.work_dir

        def ro(prefix="op-", err=errno.EROFS):
            raise OSError(err, "test")
        backup.work_dir = ro
        try:
            with contextlib.ExitStack() as stack:
                fb = hostops._verify_scratch(stack)
                fb_ok = os.path.isdir(fb) and not fb.startswith(str(config.DATA_DIR))
            backup.work_dir = lambda prefix="op-": ro(prefix, errno.EACCES)
            other = raises(lambda: hostops._verify_scratch(contextlib.ExitStack()), PermissionError)
        finally:
            backup.work_dir = saved_wd
        check("hostops verify: scratch on the volume; only a read-only volume falls back to the system temp "
              "dir (removed after); any other error refuses",
              vol_ok and not os.path.exists(on_vol) and fb_ok and not os.path.exists(fb) and other)
    finally:
        await ctlsock.stop()


async def g_purge(st):
    print("== retention purge by archived_at ==")
    txhub._store = st
    try:
        old, _o, _c, _ = await make_rec(st, chunks=2)
        new, _n, _c2, _ = await make_rec(st, chunks=2)
        mig, _m, _c3, _ = await make_rec(st, chunks=2)
        long_ago = time.time() - (config.ARCHIVE_RETENTION_DAYS + 5) * 86400
        sql("UPDATE tx_descriptors SET archived_at=? WHERE sid IN (?, ?)", long_ago, old, mig)
        sql("UPDATE tx_descriptors SET archived_at=? WHERE sid=?", time.time() - 86400, new)
        sql("INSERT INTO tx_migration(sid, kind, dir, name, state) VALUES(?, 'out', 'transcripts', ?, 'failed')",
            mig, mig + ".out")
        gens = [ts.gen_name(old, k, g.gen_id.hex()) for k, dd in descs(st, old).items() for g in dd.generations]
        jlen = os.path.getsize(config.DATA_DIR / er.JOURNAL_NAME)
        n = await txhub.purge_archived()
        check("archived past the retention: descriptors, RK, files gone; ledger → gone",
              n == 1 and not sql("SELECT 1 FROM tx_descriptors WHERE sid=?", old)
              and not sql("SELECT 1 FROM session_keys WHERE sid=?", old)
              and not any((config.TRANSCRIPT_DIR / g).exists() for g in gens)
              and {r[0] for r in sql("SELECT state FROM tx_files WHERE sid=?", old)} == {"gone"}, n)
        check("…NO tombstone (purge is not erasure): journal unchanged, sid not tombstoned",
              os.path.getsize(config.DATA_DIR / er.JOURNAL_NAME) == jlen and old not in st.tombstoned)
        check("recently archived and migration-owned recordings are kept",
              sql("SELECT 1 FROM tx_descriptors WHERE sid=?", new) and sql("SELECT 1 FROM tx_descriptors WHERE sid=?", mig))
        sql("DELETE FROM tx_migration WHERE sid=?", mig)
    finally:
        txhub._store = None


# ── 5b. H2: the cohort of a restore without proof ───────────────────────────


async def refused_with(coro, reason):
    try:
        r = await coro
    except ts.TxStoreError as e:
        return e.reason == reason
    if hasattr(r, "close"):
        r.close()
    return False


async def g_h2_cohort(st, hk):
    print("== H2: restore without proof quarantines the whole cohort, pending plaintext included ==")
    e, e_out, _ec, _ = await make_rec(st, chunks=2)
    p = os.urandom(16).hex()
    p_out = os.urandom(600)
    (config.TRANSCRIPT_DIR / (p + ".out")).write_bytes(p_out)
    (config.TRANSCRIPT_DIR / (p + ".cast")).write_bytes(CAST_HDR)
    sql("INSERT INTO sessions(id, host_id, title, state, created, rows, cols, closed_at) VALUES(?,?,?,?,?,?,?,?)",
        p, 1, "t", "closed", time.time(), 24, 80, time.time())
    for kind in ("out", "cast"):
        f = os.stat(config.TRANSCRIPT_DIR / ("%s.%s" % (p, kind)))
        sql("INSERT INTO tx_migration(sid, kind, dir, name, dev, ino, size, mtime_ns, state) "
            "VALUES(?,?,?,?,?,?,?,?,'pending')", p, kind, "transcripts", "%s.%s" % (p, kind),
            f.st_dev, f.st_ino, f.st_size, f.st_mtime_ns)
    sql("INSERT OR REPLACE INTO tx_state(key, value) VALUES('migration_inventory', '1')")   # inventarul a rulat
    check("before: the pending plaintext is served (inventoried, identical)", await read_all(st, p) == p_out)
    blob = await backup_blob(hk)
    _mem, man = archive(blob, hk)
    r = recs_of(man)
    check("mixed archive: an encrypted pair (included) and a pending plaintext (legacy)",
          r.get((e, "out"), ("",))[0] == "included" and r.get((p, "out"), ("",))[0] == "legacy", r)
    await close_store(st)
    os.unlink(config.DATA_DIR / er.JOURNAL_NAME)       # alt host: fără jurnal, fără destinaţie
    hk = apply(blob, hk)
    remark()
    q = set(sql("SELECT sid, kind FROM tx_quarantine WHERE reason='continuity'"))
    check("restore without proof: the cohort (descriptors AND plaintext without a descriptor) in tx_quarantine",
          {(p, "out"), (p, "cast"), (e, "out"), (e, "cast")} <= q, q)
    st = await open_store()
    await mg.boot(st)
    check("read BEFORE migration: the pending plaintext is refused (quarantined), so is the encrypted pair",
          await refused_with(read_all(st, p), "quarantined") and await refused_with(read_all(st, e), "quarantined"))
    await mg.run_once(st)
    stat_p = dict(sql("SELECT kind, status FROM tx_descriptors WHERE sid=?", p))
    check("migration converts it into a descriptor that stays quarantined; plaintext unlinked",
          stat_p == {"out": "quarantined", "cast": "quarantined"}
          and not (config.TRANSCRIPT_DIR / (p + ".out")).exists(), stat_p)
    check("read AFTER migration: still refused", await refused_with(read_all(st, p), "quarantined"))
    check("writer start for a cohort member → refused",
          await refused_with(st.start_recorder(p, track_agent=False), "quarantined"))
    await er.recover(st, p)
    snap = await st.open(p, "out", access=st.access(p, "t", ts.OWNER_RECOVERY_ROUTE, owner_recovery=True))
    try:
        got = await snap.read(0, snap.length)
    finally:
        snap.close()
    await er.release(st, p)
    check("explicit Owner recovery → release: the same bytes, served normally",
          got == p_out and await read_all(st, p) == p_out
          and not sql("SELECT 1 FROM tx_quarantine WHERE sid=?", p))
    await er.recover(st, e)
    await er.release(st, e)
    sql("DELETE FROM tx_state WHERE key='continuity'")
    return st, hk


# ── 6. 3.7 archive onto a migrated volume ───────────────────────────────────


def legacy_archive(sids_plain):
    """A pre-3.8 volume (raw vault key + plaintext transcripts) → its 3.7 WTBK1(tar.gz) archive."""
    d = os.path.join(BASE, "legacy37")
    os.makedirs(os.path.join(d, "transcripts", "arhiva"))
    saved = (config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR, config.ARCHIVE_DIR)
    use(d)
    secret = os.urandom(32)
    (config.DATA_DIR / "secret").write_bytes(secret)
    con = sqlite3.connect(str(config.DB_PATH))
    schema(con)
    # fără valori criptate în DB: eligibil (prove_legacy_secret: „no-ciphertext")
    con.execute("INSERT INTO users(email, password_hash, created) VALUES('l@x.co', 'x', 1000)")
    for sid in sids_plain:
        con.execute("INSERT INTO sessions(id, host_id, title, state, created, rows, cols) VALUES(?,?,?,?,?,?,?)",
                    (sid, 1, "t", "closed", time.time(), 24, 80))
    con.commit()
    con.close()
    data = {}
    for sid in sids_plain:
        out = os.urandom(800)
        (config.TRANSCRIPT_DIR / (sid + ".out")).write_bytes(out)
        (config.TRANSCRIPT_DIR / (sid + ".cast")).write_bytes(CAST_HDR)
        data[sid] = out
    os.environ.pop("WEBTERM_TX_RECORDINGS")
    prov = backup._host_keys_provider
    backup.set_host_keys_provider(None)           # procesul ăsta e acum „un 3.7": volum legacy
    backup._invalidate_kind()
    try:
        blob = backup.make_encrypted(PASS, include_transcripts=True)
    finally:
        os.environ["WEBTERM_TX_RECORDINGS"] = "1"
        backup.set_host_keys_provider(prov)
        config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR, config.ARCHIVE_DIR = saved
        backup._invalidate_kind()
    return blob, data


async def g_legacy_onto_migrated(st, hk):
    print("== a 3.7 archive imported onto a migrated volume ==")
    erased, _e, _c, _ = await make_rec(st, chunks=2)
    await txhub_erase(st, erased)
    sql("INSERT OR REPLACE INTO tx_state(key, value) VALUES('recordings_format', 'wtx1')")
    sql("INSERT OR REPLACE INTO tx_state(key, value) VALUES('migration_inventory', '1')")
    keep = os.urandom(16).hex()
    blob, data = legacy_archive([keep, erased])
    await close_store(st)
    hk = apply(blob, hk, legacy_import=True)
    check("the 3.7 DB replaced the volume's (no migration inventory, plaintext in transcripts/)",
          not sql("SELECT 1 FROM tx_state WHERE key='migration_inventory'")
          and (config.TRANSCRIPT_DIR / (keep + ".out")).exists())
    st = ts.Store(transcripts_dir=config.TRANSCRIPT_DIR, kwk=KWK, installation_id=INST, real_volume=True)
    try:
        await er.boot(st)
        await st.recover()
        await mg.boot(st)
        rows = dict(((s, k), v) for s, k, v in sql("SELECT sid, kind, state FROM tx_migration"))
        check("boot: the restored plaintext is inventoried `pending` again",
              rows.get((keep, "out")) in ("pending",) or rows.get((keep, "out")) == "unlinked", rows)
        await mg.run_once(st)
        check("…migrated: served encrypted, byte-identical, plaintext gone",
              await read_all(st, keep) == data[keep] and not (config.TRANSCRIPT_DIR / (keep + ".out")).exists())
        check("a sid erased on the volume (journal) is dropped, never converted",
              erased in st.tombstoned and not (config.TRANSCRIPT_DIR / (erased + ".out")).exists()
              and not sql("SELECT 1 FROM session_keys WHERE sid=?", erased), sql("SELECT * FROM tx_migration WHERE sid=?", erased))
    finally:
        mg.reset()
        er.reset()
        st.close()
    os.environ.pop("WEBTERM_TX_RECORDINGS")
    try:
        off = raises(lambda: backup.make_encrypted(PASS, True, hk), ValueError)
    finally:
        os.environ["WEBTERM_TX_RECORDINGS"] = "1"
    check("flag off (e.g. a hostops container without it): a volume with encrypted recordings is refused, "
          "never archived without them", off)


async def txhub_erase(st, sid):
    mg._s.store = st                  # erase() întreabă migrarea (inactivă aici: nimic de migrat)
    try:
        await er.erase(st, sid)
    finally:
        mg._s.store = None


# ── main ─────────────────────────────────────────────────────────────────────


async def main():
    hk = new_volume()
    st, hk, a, a_out = await g_included(hk)
    st, hk = await g_damaged(st, hk, a, a_out)
    await g_concurrent(st, hk)
    await g_socket(st, hk)
    await g_workdir(st, hk)
    await g_purge(st)
    st, hk = await g_h2_cohort(st, hk)
    st, hk = await g_recompact_backup(st, hk)
    await g_legacy_onto_migrated(st, hk)


try:
    asyncio.run(main())
finally:
    shutil.rmtree(BASE, ignore_errors=True)
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
