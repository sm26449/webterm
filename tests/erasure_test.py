"""Erasure journal WTJ1 + attestation + continuity quarantine + Owner recovery (ENCRYPTION-AT-REST.md
§12.5, §12.11.4, PR6a).

Groups:
  * codec: the appendix vectors (K_erase, entry 1, the 2-entry journal), an independent MAC
    re-derivation, tamper / truncation / gap / kinds / foreign / bad header;
  * boot on a test volume: flag off creates nothing; flag on creates the header-only journal and
    reports ready; the route (auth, typed confirmation, real fresh factor, live session refused);
  * erase: order (tombstone + key destroyed + files retired + links revoked + head), crash at
    every step and the boot that follows (re-apply before readers, idempotent), the cap;
  * boot diagnostics: rollback, fork, missing, broken prefix, foreign → every recording
    quarantined; a tail beyond the committed head is cut and kept; a restored RK of an erased sid
    is destroyed again;
  * attestation: success (immutable object, read back, committed), failure + backoff, read-back
    mismatch, a destination that cannot refuse overwrites (fresh name), System health;
  * freshness (pure): newest authentic head wins, a stale head never overrides, rolled-back
    destination, divergence refused, one destination offline = no proof, J_v with a bad entry;
  * backup / restore on a protected volume: wts-content-2 with the journal cut at the DB head,
    restore with J_v (proven, erasure between stage and apply kept), without proof (quarantine
    marker), divergence refused at stage and again at apply, a tampered v2 manifest, flag off;
  * Owner recovery: list, recover (typed date + fresh factor), normal reads / replay / search still
    refused, the audited recovery read, release, re-quarantine, journal quarantine never opened,
    the janitor lifting the quarantine once every destination proves the head.
Temp dirs + the real db module; no network, no Docker.
"""
import asyncio
import hashlib
import hmac
import io
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import time
import zlib
from pathlib import Path

BASE = tempfile.mkdtemp(prefix="wt-erasure-")
os.environ["WEBTERM_DATA_DIR"] = BASE
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
os.environ.setdefault("WEBTERM_UPDATE_CHECK", "0")
os.environ["WEBTERM_TX_RECORDINGS"] = "1"
os.environ["WEBTERM_TEST_GATE"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402

from app import api, authz, backup, config, db, migration, security, syshealth, txhub  # noqa: E402
from app import erasure as er  # noqa: E402
from app import keyring as kr  # noqa: E402
from app import snapshot as wts  # noqa: E402
from app import txstore as ts  # noqa: E402
from app.main import app  # noqa: E402

ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
KWK = bytes(range(0x60, 0x80))
INST = bytes(range(0xa0, 0xb0))
K = er.k_erase_of(KWK)
PASS = "parola-de-test-lunga"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {str(detail)[:300]}"))


def raises(fn, exc, reason=None):
    try:
        fn()
    except exc as e:
        return reason is None or getattr(e, "reason", None) == reason
    except BaseException as e:  # noqa: BLE001
        print("     got", type(e).__name__, e)
        return False
    return False


class Crash(BaseException):
    """Process death at an erasure step."""


def fault_at(point):
    """`point` or `point#k` (the k-th time that point is reached: `pre-commit#2` = the COMMIT of
    step 2, after the erase intent's own transaction)."""
    name, _, nth = point.partition("#")
    state = {"done": False, "seen": 0}

    def hook(p):
        if p == name and not state["done"]:
            state["seen"] += 1
            if state["seen"] == int(nth or 1):
                state["done"] = True
                raise Crash(p)
    return hook


def build(entries, k=K, inst=INST):
    """[(time_ms, sid bytes, kinds, rk_hash)] → journal bytes."""
    out = er.header(inst)
    prev = er.ZERO_MAC
    for i, (t, sid, kinds, rh) in enumerate(entries, 1):
        e = er.encode_entry(k, inst, prev, i, t, sid, kinds, rh)
        out += e
        prev = e[-32:]
    return out


def sids(n):
    return [bytes([i] * 16) for i in range(1, n + 1)]


# ── 1. codec ─────────────────────────────────────────────────────────────────

V_ENTRY1 = ("010000000000000000748d00a201000000112233445566778899aabbccddeeff038e48527f10ac19ed28318060b2"
            "fc672da8c3966d74d969c5fb053a4c6894f22b02a1a58372b92c4ad2b929a00304c3ebbcc67cfab8459a59c37de1"
            "70e31c05c2")
V_JOURNAL_SHA = "7e6ae2e4e0a2ec1ada1a61563cf79f5899f42611a0513b17efe0aaba1ff6ee6a"
V_ENV_RK = ("0106f11f697470f59679fa2294223bae52cd40009cab90a76f09514cc0cbc9713a516f12470584239e7c0702a63c"
            "4de1adfe146bfc0413330f3b724ade21506857c85af97be734dee47f2e1f1b5c8bf75baf5c53")


def g_codec():
    print("== WTJ1 codec ==")
    check("K_erase = appendix vector", K.hex() == "ee47abe8074d9cf1b1afcd0bb95415e16a0efd293e5a9c78b2ba9cb1e0687774")
    check("header = WTJ1 | 1 | 000000 | installation id (24 B)",
          er.header(INST) == b"WTJ1\x01\x00\x00\x00" + INST and len(er.header(INST)) == 24)
    sid = bytes.fromhex("00112233445566778899aabbccddeeff")
    rh = hashlib.sha256(bytes.fromhex(V_ENV_RK)).digest()
    e1 = er.encode_entry(K, INST, er.ZERO_MAC, 1, 1795305600000, sid, 3, rh)
    check("entry 1 = appendix vector (97 B)", e1.hex() == V_ENTRY1 and len(e1) == 97, e1.hex())
    body = (1).to_bytes(8, "little") + (1795305600000).to_bytes(8, "little") + sid + b"\x03" + rh
    indep = hmac.new(K, b"wt/v1/wtj-entry" + INST + b"\x00" * 32 + body, hashlib.sha256).digest()
    check("MAC re-derived independently (domain ‖ inst ‖ prev ‖ entry)", e1 == body + indep)
    j = er.header(INST) + e1 + er.encode_entry(K, INST, e1[-32:], 2, 1795305601000, bytes(range(16)), 1,
                                               b"\x00" * 32)
    check("2-entry journal SHA-256 = appendix vector", hashlib.sha256(j).hexdigest() == V_JOURNAL_SHA)
    p = er.parse(j, K, INST)
    check("parse: 2 authentic entries, head n=2, no error", p.n == 2 and p.head.n == 2 and not p.bad
          and p.valid_len == len(j))
    t = bytearray(j)
    t[-1] ^= 1
    p = er.parse(bytes(t), K, INST)
    check("tampered mac of entry 2 → prefix stops at 1 (bad-mac)", p.n == 1 and p.bad == "bad-mac")
    t = bytearray(j)
    t[24 + 20] ^= 1
    check("tampered body of entry 1 → no authentic entry", er.parse(bytes(t), K, INST).n == 0)
    p = er.parse(j[:-10], K, INST)
    check("truncated mid-entry → 1 entry + partial tail", p.n == 1 and p.bad == "partial"
          and p.valid_len == 24 + 97)
    swapped = er.header(INST) + j[24 + 97:] + j[24:24 + 97]
    check("entries out of order → gap", er.parse(swapped, K, INST).bad == "gap")
    check("kinds outside 1..3 refused at encode",
          raises(lambda: er.encode_entry(K, INST, er.ZERO_MAC, 1, 0, sid, 4, rh), er.JournalError, "bad-kinds"))
    bad = bytearray(e1)
    bad[32] = 0
    forged = bytes(bad[:65]) + er.entry_mac(K, INST, er.ZERO_MAC, bytes(bad[:65]))
    check("kinds 0 with a valid MAC → bad-kinds", er.parse(er.header(INST) + forged, K, INST).bad == "bad-kinds")
    check("another installation's journal → foreign",
          raises(lambda: er.parse(j, K, bytes(16)), er.JournalError, "foreign"))
    check("bad magic / version / reserved → bad-header",
          raises(lambda: er.parse(b"WTJ2" + j[4:], K), er.JournalError, "bad-header")
          and raises(lambda: er.parse(j[:5] + b"\x01" + j[6:], K), er.JournalError, "bad-header"))
    check("wrong K_erase → nothing authentic", er.parse(j, er.k_erase_of(bytes(32)), INST).n == 0)
    check("object name: <inst>.erasures.<n 16 hex>.wtj, parsed back",
          er.object_name(INST, 2) == INST.hex() + ".erasures.0000000000000002.wtj"
          and er.parse_object_name(er.object_name(INST, 2, "ab12cd34")) == (INST, 2)
          and er.parse_object_name("x.wtj") is None)


# ── fixtures on the test volume ──────────────────────────────────────────────


class FakeRing:
    kwk = KWK
    installation_id = INST


class FakeDest:
    def __init__(self, did, refuses=True):
        self.id = did
        self.refuses_overwrite = refuses
        self.objs = {}
        self.fail = False
        self.corrupt = False
        self.hide_above = None
        self.puts = 0

    async def put_new(self, name, data):
        if self.fail:
            raise OSError("down")
        self.puts += 1
        if name in self.objs and self.refuses_overwrite:
            raise er.DestExists(name)
        self.objs[name] = bytes(data)

    async def list(self):
        if self.fail:
            raise OSError("down")
        out = list(self.objs)
        if self.hide_above is not None:
            out = [n for n in out if er.parse_object_name(n)[1] <= self.hide_above]
        return out

    async def get(self, name):
        if self.fail:
            raise OSError("down")
        b = self.objs[name]
        if self.corrupt:
            b = b[:-1] + bytes([b[-1] ^ 1])
        return b


DESTS = []


async def fake_dests():
    return list(DESTS)


def client(**kw):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", timeout=30,
                             headers=dict(ORIGIN, **kw.pop("headers", {})), **kw)


def feed_at(rec, out, cast=b""):
    return rec.feed(out, cast, at=rec.received)


async def make_rec(st, host_id, data=None, state="closed"):
    sid = os.urandom(16).hex()
    data = data or (b"secret-" + sid.encode() + b"\r\n")
    await db.execute("INSERT INTO sessions(id, host_id, title, state, created, rows, cols) VALUES(?,?,?,?,?,?,?)",
                     sid, host_id, "t-" + sid[:4], "live", time.time(), 24, 80)
    rec = await st.start_recorder(sid, track_agent=False)
    feed_at(rec, data, b'{"version": 2, "width": 80, "height": 24}\n' + json.dumps([0.1, "o", "x"]).encode() + b"\n")
    await rec.checkpoint()
    await rec.close()
    await db.execute("UPDATE sessions SET state=?, closed_at=? WHERE id=?", state, time.time(), sid)
    return sid, data


async def read_all(st, sid, kind="out", owner_recovery=False):
    route = ts.OWNER_RECOVERY_ROUTE if owner_recovery else "test"
    snap = await st.open(sid, kind, access=st.access(sid, "t", route, owner_recovery=owner_recovery))
    try:
        return await snap.read(0, snap.length)
    finally:
        snap.close()


def gen_files(sid):
    return sorted(n for n in os.listdir(config.TRANSCRIPT_DIR) if n.startswith(sid))


async def reboot():
    """A process restart: the Store and the erasure state are rebuilt from disk."""
    await txhub.shutdown()
    st = await txhub.boot(FakeRing())
    er.set_destinations(fake_dests)
    await er.stop()          # janitorul nu concurează cu apelurile explicite ale testului
    await migration.stop()
    return st


def journal_path():
    return Path(config.DATA_DIR) / er.JOURNAL_NAME


async def head_db():
    r = await db.fetchone("SELECT value FROM tx_state WHERE key='erasure_head'")
    return json.loads(r["value"]) if r else None


def grant(uid, host_id):
    return security.issue_stepup_grant(uid, host_id)


async def statuses():
    return {(r["sid"], r["kind"]): r["status"] for r in await db.fetchall("SELECT sid, kind, status FROM tx_descriptors")}


async def set_marker(st, mark):
    """The continuity marker as a restore would have written it (threshold / known heads)."""
    await st.txn(lambda c: er._set_json(c, "continuity", mark))
    er._s.continuity = mark


async def _conflict_snap():
    """Before a check that records a conflict (R7-H1): the marker (DB + memory) and the intents."""
    row = await db.fetchone("SELECT value FROM tx_state WHERE key='continuity'")
    return (row["value"] if row else None, {r["sid"] for r in await db.fetchall("SELECT sid FROM tx_erase_intents")},
            er._s.continuity)


async def _forget_conflict(st, snap):
    """Test reset after a recorded conflict (what an Owner resolution would do): the marker and the
    intents as they were before, the in-memory diagnosis cleared."""
    val, intents, mem = snap

    def fn(c):
        if val is None:
            c.execute("DELETE FROM tx_state WHERE key='continuity'")
        else:
            c.execute("INSERT OR REPLACE INTO tx_state(key, value) VALUES('continuity', ?)", (val,))
        for (x,) in c.execute("SELECT sid FROM tx_erase_intents").fetchall():
            if x not in intents:
                c.execute("DELETE FROM tx_erase_intents WHERE sid=?", (x,))
    await st.txn(fn)
    er._s.continuity = mem
    er._s.conflict = ""


async def unquarantine_all():
    await db.execute("UPDATE tx_descriptors SET status='ok' WHERE status='quarantined'")
    await db.execute("DELETE FROM tx_quarantine")


# ── 2. boot + route ──────────────────────────────────────────────────────────


async def g_boot_and_route(c, uid, host_id):
    print("== boot, readiness, erase route ==")
    check("flag off: boot returns None, no journal written",
          await txhub.boot(None, env={"WEBTERM_TEST_GATE": "1"}) is None and not journal_path().exists()
          and not er.active())
    st = await txhub.boot(FakeRing())
    er.set_destinations(fake_dests)
    check("janitor started at boot", er._s.task is not None)
    await er.stop()
    await migration.stop()
    check("flag on: header-only journal created, journal + quarantine ready",
          journal_path().read_bytes() == er.header(INST) and er.journal_ready() and er.quarantine_ready()
          and er.active())
    sid, data = await make_rec(st, host_id)
    check("recording readable before the erasure", await read_all(st, sid) == data)
    r = await c.post(f"/api/sessions/{sid}/replay-links", json={})
    link_ok = r.status_code == 200
    aid = await db.execute("INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
                           "admin@x.co", security.hash_password("parolabuna1"), time.time())
    await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source, created)"
                     " VALUES(?,?,'all','','manual',?)", aid, await authz.role_id("admin"), time.time())
    authz.bump_epoch()
    adm = client(cookies={security.COOKIE_NAME: await security.create_web_session(aid, "t", False)})
    r = await adm.post(f"/api/sessions/{sid}/erase", json={"confirm": sid[:8]})
    check("Admin (no backups.manage) → 403", r.status_code == 403, r.status_code)
    r = await adm.get("/api/recordings/quarantine")
    check("Admin cannot list the quarantine either", r.status_code == 403, r.status_code)
    anon = client()
    r = await anon.post(f"/api/sessions/{sid}/erase", json={"confirm": sid[:8]})
    check("unauthenticated → 401", r.status_code == 401, r.status_code)
    r = await c.post(f"/api/sessions/{sid}/erase", json={"confirm": "nope"})
    check("wrong typed confirmation → 400 transcript.eraseConfirm",
          r.status_code == 400 and r.json().get("code") == "transcript.eraseConfirm", r.text)
    security._stepup_windows.clear()
    r = await c.post(f"/api/sessions/{sid}/erase", json={"confirm": sid[:8], "stepup_password": "parolabuna1"})
    check("password alone is not a fresh factor → 403", r.status_code == 403, r.text)
    live, _ = await make_rec(st, host_id, state="live")
    r = await c.post(f"/api/sessions/{live}/erase", json={"confirm": live[:8], "stepup_grant": grant(uid, host_id)})
    check("live session → 409 session.live", r.status_code == 409 and r.json().get("code") == "session.live", r.text)
    await db.execute("UPDATE sessions SET state='closed' WHERE id=?", live)
    before = gen_files(sid)
    r = await c.post(f"/api/sessions/{sid}/erase", json={"confirm": sid[:8], "stepup_grant": grant(uid, host_id)})
    body = r.json() if r.status_code == 200 else {}
    check("Owner + fresh factor → erased, not attested (no destination)",
          r.status_code == 200 and body.get("erased") is True and body.get("attested") is False, r.text)
    p = er.parse(journal_path().read_bytes(), K, INST)
    check("journal: one tombstone for the sid, head committed in the DB",
          p.n == 1 and p.entries[0].sid_hex == sid and (await head_db() or {}).get("n") == 1)
    rk = await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid)
    dsc = await db.fetchone("SELECT 1 FROM tx_descriptors WHERE sid=?", sid)
    check("RK destroyed, descriptors gone", rk is None and dsc is None)
    check("generation files retired (unlinked)", before and gen_files(sid) == [], (before, gen_files(sid)))
    check("replay link revoked with it", link_ok and await db.fetchone(
        "SELECT 1 FROM replay_links WHERE sid=?", sid) is None)
    check("sid tombstoned; read refused", sid in st.tombstoned
          and await _refused(read_all(st, sid)))
    r = await c.get(f"/api/sessions/{sid}/transcript?format=out")
    check("download → 404", r.status_code == 404, r.status_code)
    r = await c.post(f"/api/sessions/{sid}/erase", json={"confirm": sid[:8], "stepup_grant": grant(uid, host_id)})
    check("erasing again → 404 transcript.missing", r.status_code == 404, r.text)
    audit = await db.fetchone("SELECT detail FROM audit_log WHERE path=? AND status=200",
                              f"/api/sessions/{sid}/erase")
    check("audited with the journal n", audit is not None and "n=1" in (audit["detail"] or ""), audit)
    return st, live


async def _refused(coro):
    try:
        await coro
    except ts.TxStoreError:
        return True
    return False


# ── 3. crash at every step ───────────────────────────────────────────────────


async def g_crash(st, host_id):
    print("== erase: crash at every step, boot re-applies before readers ==")
    sid, data = await make_rec(st, host_id)
    n0 = er.parse(journal_path().read_bytes(), K, INST).n
    st.fault = fault_at("pre-commit#1")
    try:
        await er.erase(st, sid)
    except Crash:
        pass
    st.fault = None
    st = await reboot()
    check("crash before the erase intent commits → nothing durable: not erased, journal unchanged, readable",
          er.parse(journal_path().read_bytes(), K, INST).n == n0 and await read_all(st, sid) == data
          and await db.fetchone("SELECT 1 FROM tx_erase_intents") is None)
    for point in ("intent-committed", "journal-written", "erase-appended", "pre-commit#2", "erase-committed"):
        sid, _ = await make_rec(st, host_id)
        n0 = er.parse(journal_path().read_bytes(), K, INST).n
        st.fault = fault_at(point)
        try:
            await er.erase(st, sid)
            crashed = False
        except Crash:
            crashed = True
        st.fault = None
        st = await reboot()
        p = er.parse(journal_path().read_bytes(), K, INST)
        rk = await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid)
        check(f"crash at {point}: journal n={n0 + 1}, RK destroyed, head = journal, files gone",
              crashed and p.n == n0 + 1 and rk is None and (await head_db())["n"] == p.n
              and gen_files(sid) == [] and sid in st.tombstoned
              and p.entries[-1].sid_hex == sid
              and await db.fetchone("SELECT 1 FROM tx_erase_intents") is None, (crashed, p.n, n0, rk, gen_files(sid)))
    rep = await er.boot(st)
    check("a second boot is idempotent (nothing re-applied)", rep.reapplied == [] and not rep.diag)
    # un restore a adus înapoi RK-ul unui sid şters: boot-ul îl distruge din nou, înaintea cititorilor
    gone = er.parse(journal_path().read_bytes(), K, INST).entries[0].sid_hex
    await db.execute("INSERT INTO session_keys(sid, envelope, created, origin) VALUES(?,?,?,'session')",
                     gone, kr.wrap_under_kwk(KWK, kr.KT_RK, os.urandom(32)), time.time())
    st = await reboot()
    check("tombstoned sid with an RK again (a restore) → destroyed at boot",
          await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", gone) is None and gone in st.tombstoned)
    # fsync peste buget: rezultatul incert → refuz până la restart, sid-ul nu mai e servit
    sid, _ = await make_rec(st, host_id)
    old_budget, old_append = er.APPEND_BUDGET, er.Journal.append
    er.APPEND_BUDGET = 0.05

    def slow_append(self, entry, expect_len, fault=None):
        time.sleep(0.3)
        return old_append(self, entry, expect_len, fault)
    er.Journal.append = slow_append
    try:
        e = None
        try:
            await er.erase(st, sid)
        except er.ErasureError as x:
            e = x
        await asyncio.sleep(0.5)
    finally:
        er.APPEND_BUDGET, er.Journal.append = old_budget, old_append
    check("journal fsync over budget → 503 uncertain, sid no longer served",
          e is not None and e.code == "transcript.erasureUncertain" and sid in st.tombstoned)
    sid2, _ = await make_rec(st, host_id)
    check("…and further erasures refused until restart", await _erasure_code(er.erase(st, sid2))
          == "transcript.erasureUncertain")
    check("System health says so (critical)", any(i[1] == "erasure_uncertain" for i in er.health()))
    st = await reboot()
    check("after restart the boot decided from the file (entry present → re-applied)",
          await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid) is None and not er.health_has("erasure_uncertain"))
    return st


async def _crash_erase(st, sid, point):
    st.fault = fault_at(point)
    try:
        await er.erase(st, sid)
        crashed = False
    except Crash:
        crashed = True
    st.fault = None
    return crashed


async def g_intents(st, host_id):
    print("== R2-H1: the durable erase intent outlives a lost / damaged journal entry ==")
    good = journal_path().read_bytes()
    n0 = er.parse(good, K, INST).n
    # (a) fsync al intrării, cădere înainte de COMMIT-ul pasului 2, apoi intrarea pierdută CURAT:
    # jurnalul pare sănătos (n = capul DB), dar RK-ul ar fi rămas
    sid, _ = await make_rec(st, host_id)
    crashed = await _crash_erase(st, sid, "pre-commit#2")
    intent = await db.fetchone("SELECT kinds FROM tx_erase_intents WHERE sid=?", sid)
    check("crash between the journal fsync and step 2's COMMIT: the intent is durable",
          crashed and intent is not None and intent["kinds"] == "cast,out"
          and er.parse(journal_path().read_bytes(), K, INST).n == n0 + 1, intent)
    journal_path().write_bytes(good)                       # intrarea n0+1 pierdută
    st = await reboot()
    p = er.parse(journal_path().read_bytes(), K, INST)
    check("…entry lost, journal looks healthy → the boot completes the erasure from the intent "
          "(new entry, RK destroyed, head advanced, intent cleared, not served)",
          not er._s.diag and p.n == n0 + 1 and p.entries[-1].sid_hex == sid
          and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid) is None
          and (await head_db())["n"] == n0 + 1 and sid in st.tombstoned
          and await db.fetchone("SELECT 1 FROM tx_erase_intents") is None and await _refused(read_all(st, sid)),
          (er._s.diag, p.n, n0))
    # (b) aceeaşi cădere, apoi jurnalul STRICAT (intrare ≤ capul comis): diagnostic, carantină
    good = journal_path().read_bytes()
    n1 = er.parse(good, K, INST).n
    keep, _ = await make_rec(st, host_id)
    sid, _ = await make_rec(st, host_id)
    crashed = await _crash_erase(st, sid, "pre-commit#2")
    t = bytearray(good)
    t[er.prefix_len(1) - 5] ^= 1
    journal_path().write_bytes(bytes(t))
    st = await reboot()
    check("…entry fsynced, step 2 lost, journal then damaged → diag prefix, the intent's RK destroyed at "
          "boot, the sid tombstoned, the intent kept (not journalled)",
          crashed and er._s.diag == "prefix" and sid in st.tombstoned
          and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid) is None
          and await db.fetchone("SELECT 1 FROM tx_erase_intents WHERE sid=?", sid) is not None, er._s.diag)
    check("…journal recovery of that sid refused",
          await _erasure_code(er.recover_journal(st, sid, "prefix")) in ("transcript.missing",
                                                                            "transcript.recoveryNoKey"))
    # o intenţie rămasă pe un sid care încă are RK (de ex. pasul DB eşuat): recuperarea o refuză
    await db.execute("INSERT INTO tx_erase_intents(sid, kinds, since) VALUES(?, 'out', 1)", keep)
    check("…a sid with an outstanding erase intent → 409 transcript.recoveryErasePending",
          await _erasure_code(er.recover_journal(st, keep, "prefix")) == "transcript.recoveryErasePending")
    await db.execute("DELETE FROM tx_erase_intents WHERE sid=?", keep)
    journal_path().write_bytes(good)
    await unquarantine_all()
    st = await reboot()
    p = er.parse(journal_path().read_bytes(), K, INST)
    check("journal repaired → the kept intent is journalled now (entry appended, intent cleared), "
          "the other recording untouched",
          not er._s.diag and p.n == n1 + 1 and p.entries[-1].sid_hex == sid
          and await db.fetchone("SELECT 1 FROM tx_erase_intents") is None
          and await read_all(st, keep) is not None, (er._s.diag, p.n, n1))
    return st


async def _cancel_erase(st, sid, point=None, rollback=False):
    """R3-M1: the erase request is cancelled while a transaction runs on the writer thread; the
    thread then COMMITs (`point` = that COMMIT's fault point) or, `rollback`, fails inside the
    intent's transaction (→ ROLLBACK). → True when the request ended with CancelledError."""
    loop = asyncio.get_running_loop()
    box = {}

    def cancel_now():
        loop.call_soon_threadsafe(box["task"].cancel)
        time.sleep(0.1)                  # anularea ajunge cât firul e încă în tranzacţie
    orig = er._put_intent_sync
    if rollback:
        def put(c, *a):
            cancel_now()
            raise sqlite3.OperationalError("disk I/O error (test)")
        er._put_intent_sync = put
    else:
        hook = fault_at(point)

        def fault(p):
            try:
                hook(p)
            except Crash:
                cancel_now()             # nu e o cădere: COMMIT-ul continuă după anulare
        st.fault = fault
    try:
        box["task"] = task = asyncio.ensure_future(er.erase(st, sid))
        try:
            await task
        except asyncio.CancelledError:
            return True
        return False
    finally:
        st.fault = None
        er._put_intent_sync = orig


async def g_cancel(st, host_id):
    print("== R3-M1: the erase request cancelled right after the intent COMMIT ==")
    sid, data = await make_rec(st, host_id)
    other, _ = await make_rec(st, host_id)
    n0 = er.parse(journal_path().read_bytes(), K, INST).n
    snap = await st.open(sid, "out", access=st.access(sid, "t", "test"))
    cancelled = await _cancel_erase(st, sid, "pre-commit#1")
    intent = await db.fetchone("SELECT 1 FROM tx_erase_intents WHERE sid=?", sid)
    check("cancelled after the intent COMMIT: intent durable, journal not appended, sid refused in memory, "
          "state intent-cancelled", cancelled and intent is not None and sid in st.tombstoned
          and er.parse(journal_path().read_bytes(), K, INST).n == n0 and er._s.uncertain == "intent-cancelled",
          (cancelled, intent, er._s.uncertain))
    check("…a reader opened before is cut off", await _refused(snap.read(0, snap.length)))
    snap.close()
    check("…a new read is refused", await _refused(read_all(st, sid)))
    check("…another erasure is refused until it is settled (re-checked under the barrier)",
          await _erasure_code(er.erase(st, other)) == "transcript.erasureUncertain")
    ok = await er.resume_intents(st)
    p = er.parse(journal_path().read_bytes(), K, INST)
    check("the janitor completes it from the intent: entry appended, RK destroyed, intent cleared, head "
          "advanced (DB and memory), state lifted",
          ok and p.n == n0 + 1 and p.entries[-1].sid_hex == sid and not er._s.uncertain
          and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid) is None
          and await db.fetchone("SELECT 1 FROM tx_erase_intents") is None
          and (await head_db())["n"] == n0 + 1 and er._s.head_db.n == n0 + 1 and sid in st.tombstoned,
          (ok, p.n, n0, er._s.uncertain))
    check("R4-M1: …and the retired generation files are unlinked (steps 1–2 from the intent)",
          gen_files(sid) == [], gen_files(sid))
    check("…erasures accepted again", (await er.erase(st, other)).get("state") == "destroyed")
    # ROLLBACK confirmat: nimic durabil, înregistrarea se serveşte din nou
    sid2, data2 = await make_rec(st, host_id)
    n1 = er.parse(journal_path().read_bytes(), K, INST).n
    cancelled = await _cancel_erase(st, sid2, rollback=True)
    check("cancelled while the intent transaction rolls back: no intent, sid refused until settled",
          cancelled and await db.fetchone("SELECT 1 FROM tx_erase_intents") is None and sid2 in st.tombstoned
          and await _refused(read_all(st, sid2)))
    ok = await er.resume_intents(st)
    check("…the janitor sees the rollback: nothing journalled, the recording is served again",
          ok and sid2 not in st.tombstoned and await read_all(st, sid2) == data2 and not er._s.uncertain
          and er.parse(journal_path().read_bytes(), K, INST).n == n1)
    # anulare la pasul 2 (intrarea durabilă, COMMIT-ul DB terminat după anulare)
    sid3, _ = await make_rec(st, host_id)
    cancelled = await _cancel_erase(st, sid3, "pre-commit#2")
    check("cancelled at step 2's COMMIT: journalled, refused, state commit-cancelled",
          cancelled and sid3 in st.tombstoned and er._s.uncertain == "commit-cancelled"
          and er.parse(journal_path().read_bytes(), K, INST).entries[-1].sid_hex == sid3)
    ok = await er.resume_intents(st)
    check("…settled: RK gone, intent cleared, the in-memory head re-read from the database",
          ok and not er._s.uncertain and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid3) is None
          and await db.fetchone("SELECT 1 FROM tx_erase_intents") is None
          and er._s.head_db.n == (await head_db())["n"] == n1 + 1)
    # R4-M1: pasul DB comis înainte de anulare (ramura „intrare prezentă, intenţie absentă"):
    # generaţiile retrase se şterg fizic, ca la erase
    rows = await db.fetchall("SELECT state FROM tx_files WHERE sid=?", sid3)
    check("R4-M1: …the retired generation files are unlinked too (rows gone), not left until a restart",
          gen_files(sid3) == [] and rows and all(r["state"] == "gone" for r in rows),
          (gen_files(sid3), [r["state"] for r in rows]))
    # R4-M1: reaplicarea pasului DB de către janitor (intenţie şi intrare prezente, pasul 2 necomis)
    sid6, _ = await make_rec(st, host_id)
    orig_destroy = er._destroy_sync
    calls = {"n": 0}

    def destroy_fail_once(c, *a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            box_cancel()
            raise sqlite3.OperationalError("disk I/O error (test)")
        return orig_destroy(c, *a, **kw)
    loop = asyncio.get_running_loop()
    task6 = asyncio.ensure_future(er.erase(st, sid6))

    def box_cancel():
        loop.call_soon_threadsafe(task6.cancel)
        time.sleep(0.1)
    er._destroy_sync = destroy_fail_once
    try:
        try:
            await task6
            cancelled6 = False
        except asyncio.CancelledError:
            cancelled6 = True
    finally:
        er._destroy_sync = orig_destroy
    check("R4-M1: cancelled while step 2 rolls back: journalled, intent kept, files still there",
          cancelled6 and er._s.uncertain == "commit-cancelled" and gen_files(sid6) != []
          and await db.fetchone("SELECT 1 FROM tx_erase_intents WHERE sid=?", sid6) is not None,
          (cancelled6, er._s.uncertain, gen_files(sid6)))
    ok = await er.resume_intents(st)
    rows = await db.fetchall("SELECT state FROM tx_files WHERE sid=?", sid6)
    check("R4-M1: the janitor re-applies step 2 AND unlinks the retired generations",
          ok and not er._s.uncertain and gen_files(sid6) == [] and rows
          and all(r["state"] == "gone" for r in rows)
          and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid6) is None,
          (ok, er._s.uncertain, gen_files(sid6), [r["state"] for r in rows]))
    # R5-L1: o eroare de I/O la unlink nu pierde curăţarea: sid-ul rămâne de făcut, cu backoff
    sid7, _ = await make_rec(st, host_id)
    orig_unlink = st._unlink_if_ours_sync
    fails = {"left": er.CLEANUP_ALARM_AFTER}

    def unlink_eio(*a, **kw):
        if fails["left"] > 0:
            fails["left"] -= 1
            raise OSError(5, "Input/output error (test)")
        return orig_unlink(*a, **kw)
    cancelled7 = await _cancel_erase(st, sid7, "pre-commit#1")
    st._unlink_if_ours_sync = unlink_eio
    now = {"t": 1000.0}
    try:
        ok = await er.resume_intents(st, clock=lambda: now["t"])
        check("R5-L1: unlink EIO during the janitor's cleanup → the erasure is settled (RK gone, state "
              "lifted) and the cleanup stays pending, files still there",
              cancelled7 and ok and not er._s.uncertain and sid7 in er._s.cleanup and gen_files(sid7) != []
              and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid7) is None,
              (cancelled7, ok, er._s.uncertain, er._s.cleanup, gen_files(sid7)))
        await er.run_cleanup(st, clock=lambda: now["t"])
        check("R5-L1: …backoff: not retried before its time", fails["left"] == er.CLEANUP_ALARM_AFTER - 1
              and er._s.cleanup[sid7]["tries"] == 1, (fails, er._s.cleanup))
        for _ in range(er.CLEANUP_ALARM_AFTER - 1):
            now["t"] += er.CLEANUP_BACKOFF_MAX
            await er.run_cleanup(st, clock=lambda: now["t"])
        check("R5-L1: …repeated failures raise the transcript.erasureCleanup alarm, the task is kept",
              sid7 in er._s.cleanup and any(a[0] == "transcript.erasureCleanup" and sid7 in a[1] for a in st.alarms),
              (er._s.cleanup, st.alarms[-3:]))
        now["t"] += er.CLEANUP_BACKOFF_MAX
        left = await er.run_cleanup(st, clock=lambda: now["t"])
        rows = await db.fetchall("SELECT state FROM tx_files WHERE sid=?", sid7)
        check("R5-L1: …the disk recovers: the next pass unlinks the retired generations (rows gone), task done",
              left == [] and gen_files(sid7) == [] and rows and all(r["state"] == "gone" for r in rows),
              (left, gen_files(sid7), [r["state"] for r in rows]))
    finally:
        st._unlink_if_ours_sync = orig_unlink
    # R6-L1: exponentul plafonat (30.0 * 2**1100 ar da OverflowError chiar în ramura de eroare)
    check("R6-L1: the backoff exponent is capped (no float overflow after many failures)",
          er._cleanup_delay(1) == er.CLEANUP_BACKOFF and er._cleanup_delay(10 ** 6) == er.CLEANUP_BACKOFF_MAX)
    # R6-L1: o generaţie fixată de un cititor → „deferred"; dacă unlink-ul de la ultimul unpin eşuează,
    # sarcina de curăţare (păstrată) îl reia până la rândul `gone`
    sid8, _ = await make_rec(st, host_id)
    gens8 = [r["gen_id"] for r in await db.fetchall("SELECT gen_id FROM tx_files WHERE sid=?", sid8)]
    cancelled8 = await _cancel_erase(st, sid8, "pre-commit#1")
    st.pin_gens(gens8)
    now = {"t": 5000.0}
    pinned = True
    try:
        ok = await er.resume_intents(st, clock=lambda: now["t"])
        check("R6-L1: a pinned generation at cleanup → deferred, the task is kept (not a failure), files there",
              cancelled8 and ok and sid8 in er._s.cleanup and er._s.cleanup[sid8]["tries"] == 0
              and gen_files(sid8) != [], (cancelled8, ok, er._s.cleanup, gen_files(sid8)))
        er._s.cleanup[sid8]["tries"] = 5000
        fails = {"left": 1}
        st._unlink_if_ours_sync = unlink_eio
        st.unpin_gens(gens8)                                    # ultimul unpin: retire amânat, eşuează (EIO)
        pinned = False
        for _ in range(20):
            await asyncio.sleep(0.01)
            if fails["left"] == 0:
                break
        await asyncio.sleep(0.05)
        check("R6-L1: …the unpin's deferred unlink failed: files and the retired row still there",
              fails["left"] == 0 and gen_files(sid8) != [], (fails, gen_files(sid8)))
        fails["left"] = 1
        now["t"] += er.CLEANUP_BACKOFF
        left = await er.run_cleanup(st, clock=lambda: now["t"])
        check("R6-L1: …a failure after 5000 tries: no overflow, next try at most CLEANUP_BACKOFF_MAX away",
              sid8 in left and er._s.cleanup[sid8]["next"] <= now["t"] + er.CLEANUP_BACKOFF_MAX, er._s.cleanup)
        now["t"] += er.CLEANUP_BACKOFF_MAX
        left = await er.run_cleanup(st, clock=lambda: now["t"])
        rows = await db.fetchall("SELECT state FROM tx_files WHERE sid=?", sid8)
        check("R6-L1: …the kept task re-tries and unlinks (rows gone), task done",
              left == [] and gen_files(sid8) == [] and rows and all(r["state"] == "gone" for r in rows),
              (left, gen_files(sid8), [r["state"] for r in rows]))
    finally:
        st._unlink_if_ours_sync = orig_unlink
        if pinned:
            st.unpin_gens(gens8)
    # janitorul o face singur, imediat (trezit de anulare, nu la următorul interval)
    sid4, _ = await make_rec(st, host_id)
    er.start(st)
    try:
        await asyncio.sleep(0.05)
        cancelled = await _cancel_erase(st, sid4, "pre-commit#1")
        for _ in range(100):
            if not er._s.uncertain:
                break
            await asyncio.sleep(0.02)
        p = er.parse(journal_path().read_bytes(), K, INST)
        check("the running janitor completes the cancelled erasure promptly",
              cancelled and not er._s.uncertain and p.entries[-1].sid_hex == sid4
              and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid4) is None, er._s.uncertain)
    finally:
        await er.stop()
    # o cădere înainte ca janitorul să ajungă: boot-ul o completează din intenţie (ca R2-H1)
    sid5, _ = await make_rec(st, host_id)
    cancelled = await _cancel_erase(st, sid5, "pre-commit#1")
    st = await reboot()
    p = er.parse(journal_path().read_bytes(), K, INST)
    check("…or, process gone first, the boot completes it from the intent",
          cancelled and p.entries[-1].sid_hex == sid5 and sid5 in st.tombstoned and not er._s.uncertain
          and await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid5) is None)
    return st


async def _erasure_code(coro):
    try:
        await coro
    except er.ErasureError as e:
        return e.code
    return None


# ── 4. boot diagnostics ──────────────────────────────────────────────────────


async def g_diagnostics(st, host_id):
    print("== boot: rollback / fork / missing / prefix / foreign → quarantine; tail cut ==")
    keep, _ = await make_rec(st, host_id)
    good = journal_path().read_bytes()
    head = await head_db()
    n = head["n"]

    async def case(name, data, diag):
        nonlocal st
        if data is None:
            journal_path().unlink()
        else:
            journal_path().write_bytes(data)
        st = await reboot()
        s = await statuses()
        q = await db.fetchone("SELECT reason FROM tx_quarantine WHERE sid=? AND kind='out'", keep)
        code = await _erasure_code(er.erase(st, keep))
        check(f"{name} → diag {diag}, recordings quarantined, erasure refused, health critical",
              er._s.diag == diag and s.get((keep, "out")) == "quarantined" and q is not None
              and q["reason"] == "journal:" + diag and code == "transcript.erasureJournalBroken"
              and any(i[0] == "critical" for i in er.health()) and er.journal_ready(),
              (er._s.diag, s.get((keep, "out")), q and q["reason"], code))
        check(f"{name}: a quarantined recording is not served", await _refused(read_all(st, keep)))
        journal_path().write_bytes(good)
        await unquarantine_all()
        st = await reboot()
    await case("journal shorter than the committed head", good[:er.prefix_len(n - 1)], "rollback")
    forged = build([(e.time_ms + (1 if e.n == n else 0), e.sid, e.kinds, e.rk_hash)
                    for e in er.parse(good, K, INST).entries])
    await case("entry n = head with another mac", forged, "fork")
    await case("journal missing with head n > 0", None, "missing")
    t = bytearray(good)
    t[er.prefix_len(1) - 5] ^= 1
    await case("non-authentic entry at/before the head", bytes(t), "prefix")
    await case("another installation's journal", build([(1, bytes(16), 3, bytes(32))], inst=bytes(16)), "foreign")
    check("after repair the volume boots clean", not er._s.diag and (await statuses()).get((keep, "out")) == "ok")
    journal_path().write_bytes(good + b"\x01" * 40)
    st = await reboot()
    tails = [x for x in os.listdir(config.DATA_DIR) if x.startswith(er.TAIL_PREFIX)]
    check("bytes beyond the committed head → cut, kept as erasures.wtj.tail-*, no quarantine",
          journal_path().read_bytes() == good and tails and not er._s.diag
          and (await statuses()).get((keep, "out")) == "ok", (tails, er._s.diag))
    for x in tails:
        os.unlink(os.path.join(config.DATA_DIR, x))
    return st, keep


# ── 5. cap ───────────────────────────────────────────────────────────────────


async def g_cap(st, host_id):
    print("== journal cap ==")
    n = er._s.parsed.n
    old = (er.CAP, er.WARN_AT)
    er.CAP, er.WARN_AT = n + 1, n
    try:
        check("at 90 %: System health warning", any(i[1] == "erasure_journal_near_cap" for i in er.health()))
        a, _ = await make_rec(st, host_id)
        b, _ = await make_rec(st, host_id)
        await er.erase(st, a)
        check("at the cap: erasure refused (507 transcript.erasureJournalFull), history kept",
              await _erasure_code(er.erase(st, b)) == "transcript.erasureJournalFull"
              and er.parse(journal_path().read_bytes(), K, INST).n == n + 1
              and await read_all(st, b) is not None)
    finally:
        er.CAP, er.WARN_AT = old


# ── 6. attestation ───────────────────────────────────────────────────────────


async def g_attest(st, host_id):
    print("== attestation ==")
    head = er._s.parsed.head
    d1, d2 = FakeDest("sftp:u@h:22/x"), FakeDest("ftps:u@h:21/x", refuses=False)
    DESTS[:] = [d1, d2]
    out = await er.attest_once(st)
    name1 = er.object_name(INST, head.n)
    check("SFTP-like: one immutable object per head, read back, committed",
          out == {d1.id: "ok", d2.id: "ok"} and name1 in d1.objs
          and d1.objs[name1] == journal_path().read_bytes()[:er.prefix_len(head.n)])
    check("FTPS-like (cannot refuse overwrites): a fresh name per upload",
          len(d2.objs) == 1 and list(d2.objs)[0] != name1 and er.parse_object_name(list(d2.objs)[0]) == (INST, head.n))
    row = await db.fetchone("SELECT value FROM tx_state WHERE key='attested_heads'")
    att = json.loads(row["value"])
    check("attested_heads in the DB (n, time, object name) per destination",
          att[d1.id]["n"] == head.n and att[d1.id]["name"] == name1 and att[d2.id]["n"] == head.n)
    check("attested everywhere → no health warning", await er.attested_everywhere(head.n)
          and not er.health_has("erasure_unattested"))
    puts = d1.puts
    await er.attest_once(st)
    check("nothing re-uploaded once attested", d1.puts == puts)
    d1.fail = True
    sid, _ = await make_rec(st, host_id)
    res = await er.erase(st, sid)
    out = await er.attest_once(st)
    check("destination down → erase answers attested: false, the destination is 'failing'",
          res["attested"] is False and out[d1.id] == "failing" and out[d2.id] == "ok")
    check("System health: 'erasure n not attested on <destination> since …'",
          any(i[1] == "erasure_unattested" and i[2]["destination"] == d1.id for i in er.health()))
    d1.fail = False
    out = await er.attest_once(st)
    check("retry waits for the backoff", out[d1.id] == "failing")
    er._s.dests[d1.id]["next"] = 0
    d1.corrupt = True
    out = await er.attest_once(st)
    check("read-back mismatch → not attested (failing, error kept)",
          out[d1.id] == "failing" and er._s.dests[d1.id]["error"] == "readback-mismatch"
          and json.loads((await db.fetchone("SELECT value FROM tx_state WHERE key='attested_heads'"))["value"])
          [d1.id]["n"] == head.n)
    d1.corrupt = False
    er._s.dests[d1.id]["next"] = 0
    out = await er.attest_once(st)
    check("after the fix: attested (the object already existed: read back decides)",
          out[d1.id] == "ok" and await er.attested_everywhere(er._s.parsed.n))
    res = await c_health()
    check("System health check crypto.erasure ok", res is not None and res.severity == "ok", res)
    DESTS[:] = []
    await er.attest_once(st)
    check("no destination configured → info 'survives restores on this volume only'",
          er.health_has("erasure_local_only"))
    return d1, d2


async def c_health():
    return await syshealth.c_crypto_erasure()


# ── 7. freshness (pure) ──────────────────────────────────────────────────────


def g_freshness():
    print("== freshness and continuity (pure) ==")
    ents = [(1000 + i, s, 3, bytes(32)) for i, s in enumerate(sids(4))]
    j2, j3, j4 = build(ents[:2]), build(ents[:3]), build(ents[:4])
    fork3 = build(ents[:2] + [(9999, bytes([9] * 16), 1, bytes(32))])

    def dest(did, data, ok=True):
        if not ok:
            return er.DestResult(did, False, error="down")
        p = er.parse(data, K, INST) if data else None
        return er.DestResult(did, True, p, data)

    def live(j, att=None):
        return er.Live("same", er.parse(j, K, INST).head, att or {})
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=j4, live=live(j4))
    check("J_v of the same installation, longer, holding the live head → proven (volume), J* = J_v",
          d.state == "proven" and d.proof == "volume" and d.head.n == 4 and d.journal == j4)
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=j4)
    check("H1: J_v without the live database's head (unknown) → not a proof", d.proof == "none")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=j3, live=live(j4))
    check("H1: J_v cleanly shortened below the live committed head (n=4 → 3) → no proof, threshold unmet",
          d.state == "unproven" and d.proof == "none" and d.short and d.threshold.n == 4 and d.head.n == 3)
    t3 = bytearray(j3)
    t3[er.prefix_len(3) - 1] ^= 1
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=bytes(t3), live=live(j3))
    check("H1: a COMMITTED entry with a bad MAC is never a valid prefix → no proof",
          d.proof == "none" and d.short)
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=bytes(t3), live=live(j2))
    check("H1: a bad entry AFTER the committed head is a crash tail (boot rule) → proof by the volume",
          d.proof == "volume" and d.head.n == 2)
    fork_live = er.Live("same", er.parse(build(ents[:1] + [(5555, bytes([5] * 16), 2, bytes(32))]), K, INST).head)
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=j3, live=fork_live)
    check("H1: J_v whose entry at the live head differs (fork vs the DB) → no proof", d.proof == "none" and d.short)
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=j3, live=er.Live("bad"))
    check("H1: live database unreadable → no threshold known → no proof", d.proof == "none")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=j3, live=live(j2, {"gone": 3}))
    check("M1: the live database's attested heads are merged (n > J* stays an obligation)",
          d.known.get("gone") == 3 and d.proof == "volume")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=None, live=live(j2, {"gone": 3}),
                          dest_results=[dest("a", j2)], required_dests={"a"})
    check("M1: …and block a destination proof while that destination does not answer", d.proof == "none")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, dest_results=[dest("a", None)],
                          required_dests={"a"})
    check("M1: a reachable destination with an EMPTY listing never proves", d.proof == "none" and d.state == "unproven")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, dest_results=[dest("a", j3)],
                          required_dests={"a"}, live=live(j4))
    check("M1: a destination below the live threshold (3 < 4) → no proof", d.proof == "none" and d.short)
    d = er.decide_restore(k_erase=K, inst=INST, j_b=None, tracked=True, dest_results=[dest("a", j3)],
                          required_dests={"a"}, known_attested={}, live=er.Live("same", er.EMPTY_HEAD), mode="prove")
    check("M1: proving later, a destination nobody knew to hold anything (our own upload) proves nothing",
          d.proof == "none")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=None, tracked=True, dest_results=[dest("a", j3)],
                          required_dests={"a"}, known_attested={"a": 3}, live=er.Live("same", er.EMPTY_HEAD),
                          mode="prove")
    check("M1: …one known at the restore to hold n=3 that still does → proof", d.proof == "destinations")
    check("summary carries the threshold and the merged known heads",
          set(d.summary(1)) == {"state", "proof", "since", "n", "threshold", "known", "required", "overflow",
                                "unverified"}
          and d.summary(1)["known"] == {"a": 3} and d.summary(1)["required"] == ["a"])
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j3, tracked=True, dest_results=[dest("a", j2)],
                          required_dests={"a"}, known_attested={"a": 3})
    check("stale authentic head (n=2) where a source recorded 3 → rolled back, no proof; never overrides",
          d.state == "unproven" and d.rolled_back == ["a"] and d.head.n == 3 and d.journal == j3)
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, dest_results=[dest("a", j3)],
                          required_dests={"a"}, known_attested={"a": 2})
    check("every destination answers an authentic, newer head → proven, J* = the longest",
          d.state == "proven" and d.proof == "destinations" and d.head.n == 3 and d.journal == j3)
    check("two authentic journals that diverge → ErasureConflict",
          raises(lambda: er.decide_restore(k_erase=K, inst=INST, j_b=j3, tracked=True,
                                           dest_results=[dest("a", fork3)], required_dests={"a"}),
                 er.ErasureConflict))
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True,
                          dest_results=[dest("a", j2), dest("b", None, ok=False)], required_dests={"a", "b"})
    check("one destination offline out of two → no proof → unproven", d.state == "unproven" and d.unreachable == ["b"])
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, dest_results=[dest("a", j2)],
                          required_dests={"a"}, known_attested={"a": 2, "old": 3})
    check("a destination no longer configured that a source knows holds a NEWER head → still required",
          d.proof == "none" and d.state == "unproven")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, dest_results=[dest("a", j2)],
                          required_dests={"a"}, known_attested={"a": 2, "old": 1})
    check("…one whose known head is already covered by J* is not", d.proof == "destinations")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, required_dests={"a"})
    check("a destination named by the staged config that did not answer → no proof", d.proof == "none")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True)
    check("no J_v, no destination → unproven (quarantine)", d.state == "unproven")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=None, tracked=False)
    check("never tracked (v1 / pre-3.8) and nothing anywhere → not-tracked", d.state == "not-tracked")
    t = bytearray(j3)
    t[er.prefix_len(2) - 1] ^= 1
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=bytes(t))
    check("J_v with a non-authentic entry inside → not proof", d.proof == "none")
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=build(ents[:1], inst=bytes(16)))
    check("J_v of another installation → not a candidate, not proof", d.proof == "none" and d.head.n == 2)
    out, proven, head = er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j3, live_journal=j4,
                                           stage_summary={"state": "proven", "proof": "volume"},
                                           threshold=er.parse(j4, K, INST).head, live_ok=True)
    check("apply: an erasure made between stage and apply (J_v longer) is kept, nothing shorter published",
          out is None and proven and head.n == 4)
    out, proven, head = er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j2, live_journal=j3,
                                           stage_summary={"state": "proven", "proof": "volume"},
                                           threshold=er.parse(j4, K, INST).head, live_ok=True)
    check("H1 apply: the live DB head moved to 4 but J_v holds 3 → not proven (re-checked under the lock)",
          not proven and out is None and head.n == 3)
    out, proven, head = er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j3, live_journal=j3,
                                           stage_summary={"state": "proven", "proof": "volume"},
                                           threshold=er.parse(j3, K, INST).head, live_ok=False)
    check("H1 apply: the live database not of this installation / unreadable → not proven", not proven)
    out, proven, head = er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j3, live_journal=None,
                                           stage_summary={"state": "proven", "proof": "destinations"},
                                           threshold=er.EMPTY_HEAD, live_ok=True)
    check("M1 apply: a stage proof by destinations is not re-verifiable at boot → never lifts the quarantine",
          not proven and out == j3)
    out, proven, head = er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j3, live_journal=None,
                                           stage_summary={"state": "proven", "proof": "volume"})
    check("apply: J_v gone since the stage → J* published, no proof any more", out == j3 and not proven)
    check("apply: divergent J_v → conflict",
          raises(lambda: er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j3, live_journal=fork3,
                                            stage_summary={}), er.ErasureConflict))


def g_recheck_pure():
    print("== recheck (pure): merged thresholds, the backup's own marker, mandatory set, overflow ==")
    ents = [(3000 + i, s, 3, bytes(32)) for i, s in enumerate(sids(3))]
    j1, j2 = build(ents[:1]), build(ents[:2])
    h2 = er.parse(j2, K, INST).head
    other2 = er.Head(2, 1, bytes([5] * 32))
    check("R-H1: merge_threshold keeps the highest head; equal heads merge",
          er.merge_threshold(er.parse(j1, K, INST).head, h2, h2, None) == h2)
    check("R-H1: the same n with another MAC is a conflict, never a numeric choice",
          raises(lambda: er.merge_threshold(h2, other2), er.ErasureConflict))
    staged = er.Terms(h2, {"a": 2}, ("a",), False, 1)
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j1, tracked=True, j_v=j1,
                          live=er.Live("same", er.parse(j1, K, INST).head), staged=staged)
    check("R-H1: a backup carrying an unproven marker (threshold n=2) never proves by a journal at n=1",
          d.proof == "none" and d.threshold == h2 and d.short and d.required == ["a"], d)
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j1, tracked=True, live=er.Live("none"), staged=staged)
    check("…not even on a fresh volume (no live DB): the threshold travels with the dataset",
          d.proof == "none" and d.threshold.n == 2)
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=j2,
                          live=er.Live("same", h2), staged=staged)
    check("…a journal holding it proves (volume)", d.proof == "volume")
    many = {"d%03d" % i: 1 for i in range(er.KNOWN_MAX + 1)}
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, j_v=j2, live=er.Live("same", h2),
                          known_attested=many)
    check("R-M2: more known heads than KNOWN_MAX → overflow kept, no proof at all",
          d.overflow and d.proof == "none" and d.summary(1)["overflow"] is True)
    lv = er.Live("same", h2, {}, frozenset({"sftp:gone"}))
    d = er.decide_restore(k_erase=K, inst=INST, j_b=j2, tracked=True, live=lv,
                          dest_results=[er.DestResult("sftp:new", True, er.parse(j2, K, INST), j2)],
                          required_dests={"sftp:new"})
    check("R-M2: a destination mandatory at an earlier restore stays mandatory (replacing it proves nothing)",
          d.proof == "none" and d.required == ["sftp:gone", "sftp:new"], d)
    check("terms_of: a malformed marker is refused (fail closed)",
          raises(lambda: er.terms_of({"state": "unproven", "required": "x"}), er.JournalError)
          and raises(lambda: er.terms_of({"state": "unproven", "overflow": 1}), er.JournalError))


# ── 8. backup / restore on a protected volume ────────────────────────────────


def prot_volume(name):
    d = os.path.join(BASE, name)
    os.makedirs(os.path.join(d, "transcripts", "arhiva"))
    config.DATA_DIR = Path(d)
    config.DB_PATH = config.DATA_DIR / "webterm.db"
    config.TRANSCRIPT_DIR = config.DATA_DIR / "transcripts"
    con = sqlite3.connect(str(config.DB_PATH))
    con.executescript(db.SCHEMA)
    con.execute("INSERT INTO users(email, password_hash, created) VALUES('a@b.c', 'x', 1000)")
    con.commit()
    con.close()
    mk = os.urandom(32)
    envs = (kr.wrap_under_mk(mk, kr.KT_KWK, KWK), kr.wrap_under_mk(mk, kr.KT_SNK, os.urandom(32)),
            kr.wrap_under_kwk(KWK, kr.KT_FK, os.urandom(32)))
    blob = kr.encode_manifest(kr.KeyManifest(INST, 1, kr.key_id(mk), (), envs), mk)
    (config.DATA_DIR / "keys.wtk").write_bytes(blob)
    ring = kr.open_keyring_bytes(blob, mk, kr.PROFILE_V1)
    return backup.HostKeys(ring, mk)


def reopen(hk):
    """After an apply keys.wtk is the staged keyring re-wrapped (new epoch): the host re-opens it."""
    blob = (config.DATA_DIR / "keys.wtk").read_bytes()
    return backup.HostKeys(kr.open_keyring_bytes(blob, hk.mk, kr.PROFILE_V1), hk.mk)


def set_head(dbp, journal, descs=()):
    p = er.parse(journal, K, INST)
    con = sqlite3.connect(str(dbp))
    con.execute("INSERT OR REPLACE INTO tx_state(key, value) VALUES('erasure_head', ?)", (json.dumps(p.head.to_json()),))
    for sid in descs:
        for kind in ("out", "cast"):
            con.execute("INSERT OR REPLACE INTO tx_descriptors(sid, kind, blob, version, status) VALUES(?,?,?,1,'ok')",
                        (sid, kind, b"x"))
    con.commit()
    con.close()


def plain_tar(blob, hk):
    raw = backup.decrypt(blob, PASS)
    r = wts.Reader(io.BytesIO(raw))
    r.unlock(snk=hk.ring.snk, installation_id=INST, mk=hk.mk)
    return zlib.decompress(b"".join(r.chunks()), 31)


def tar_members(plain):
    out = {}
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as t:
        for m in t.getmembers():
            if m.isfile():
                out[m.name] = t.extractfile(m).read()
    return out


def tx_state(key):
    con = sqlite3.connect(str(config.DB_PATH))
    try:
        r = con.execute("SELECT value FROM tx_state WHERE key=?", (key,)).fetchone()
        return json.loads(r[0]) if r else None
    finally:
        con.close()


def rewrap(hk, members, manifest_doc):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.USTAR_FORMAT) as t:
        for name, data in members.items():
            if name == backup.CONTENT_MANIFEST:
                continue
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        m = json.dumps(manifest_doc, sort_keys=True, separators=(",", ":")).encode()
        ti = tarfile.TarInfo(backup.CONTENT_MANIFEST)
        ti.size = len(m)
        t.addfile(ti, io.BytesIO(m))
    out = io.BytesIO()
    w = wts.Writer(out, installation_id=INST, epoch=hk.ring.epoch, mk_id=hk.ring.mk_id, snk=hk.ring.snk, mk=hk.mk)
    w.write(raw.getvalue())
    w.close()
    return backup.encrypt(out.getvalue(), PASS)


def g_backup_restore():
    print("== backup (wts-content-2) and restore reconciliation ==")
    saved = (config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR)
    try:
        hk = prot_volume("prot1")
        ents = [(1000 + i, s, 3, bytes(32)) for i, s in enumerate(sids(4))]
        j2, j3, j4 = build(ents[:2]), build(ents[:3]), build(ents[:4])
        recsid = "ab" * 16
        set_head(config.DB_PATH, j2, descs=[recsid])
        (config.DATA_DIR / er.JOURNAL_NAME).write_bytes(j3)      # jurnal înaintea DB-ului (pasul 1 fără 2)
        blob = backup.make_encrypted(PASS, keys=hk)
        mem = tar_members(plain_tar(blob, hk))
        man = json.loads(mem[backup.CONTENT_MANIFEST])
        ej = man.get("erasure_journal", {})
        check("manifest wts-content-2, erasure tracked, journal member cut at the DB head (n=2)",
              man.get("format") == "wts-content-2" and man["erasure"] == "tracked"
              and mem.get(backup.JOURNAL_MEMBER) == j2 and ej["head"]["n"] == 2 and ej["length"] == len(j2)
              and ej["sha256"] == hashlib.sha256(j2).hexdigest(), man.get("format"))
        check("every descriptor of the DB copy listed (not-requested without recordings)",
              sorted((r["sid"], r["kind"], r["state"]) for r in man["recordings"])
              == [(recsid, "cast", "not-requested"), (recsid, "out", "not-requested")])
        check("verify accepts it (v2) and says tracked", backup.verify(blob, PASS, keys=hk).get("erasure") == "tracked")
        bad = dict(man, erasure_journal=dict(ej, head={"n": 1, "mac": ej["head"]["mac"]}))
        check("a v2 manifest whose head disagrees with the member → refused before staging",
              raises(lambda: backup.stage_restore(rewrap(hk, mem, bad), PASS, keys=hk), ValueError)
              and not (config.DATA_DIR / ".restore-flag").exists())
        v1 = {"format": "wts-content-1", "files": man["files"]}
        check("a journal member under a v1 manifest → refused",
              raises(lambda: backup.stage_restore(rewrap(hk, mem, v1), PASS, keys=hk), ValueError))
        # restore cu J_v (acelaşi volum): dovedit; o ştergere între stage şi apply rămâne
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("stage with J_v → proven by the volume", info.get("erasure") == "proven"
              and info.get("erasure_proof") == "volume", info)
        (config.DATA_DIR / er.JOURNAL_NAME).write_bytes(j4)
        check("apply", backup.apply_pending_restore(keys=hk) is True)
        hk = reopen(hk)
        check("erasure between stage and apply kept (volume journal n=4, never shorter)",
              (config.DATA_DIR / er.JOURNAL_NAME).read_bytes() == j4 and tx_state("continuity") is None)
        con = sqlite3.connect(str(config.DB_PATH))
        st_rows = con.execute("SELECT status FROM tx_descriptors WHERE sid=?", (recsid,)).fetchall()
        con.close()
        check("recordings the backup did not carry → absent", st_rows and all(r[0] == "absent" for r in st_rows), st_rows)
        # fără J_v şi fără destinaţii: carantină
        (config.DATA_DIR / er.JOURNAL_NAME).unlink()
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("stage without J_v and without a destination → unproven", info.get("erasure") == "unproven", info)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity")
        check("apply without proof: the continuity marker (backup date) + J* published as the volume journal",
              cont is not None and cont["state"] == "unproven" and cont["since"] == man["created"]
              and (config.DATA_DIR / er.JOURNAL_NAME).read_bytes() == j2)
        # o destinaţie care dovedeşte capul la stage (fetcher sincron)
        d = FakeDest("sftp:u@h:22/p")
        d.objs[er.object_name(INST, 3)] = j3
        (config.DATA_DIR / er.JOURNAL_NAME).unlink()

        def fetch(k, inst):
            return [er.DestResult(d.id, True, er.parse(j3, k, inst), j3)], [d.id]
        info = backup.stage_restore(blob, PASS, keys=hk, erasure_fetch=fetch)
        check("every destination answers a newer authentic head → proven by destinations",
              info.get("erasure") == "proven" and info.get("erasure_proof") == "destinations", info)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("…J* (n=3, from the destination) becomes the volume journal; M1: the proof is re-verified live "
              "by the janitor (marker kept, with what it must reach)",
              (config.DATA_DIR / er.JOURNAL_NAME).read_bytes() == j3 and cont.get("state") == "unproven"
              and cont.get("known", {}).get(d.id) == 3 and cont.get("n") == 3, cont)
        # divergenţă la stage
        fork = build(ents[:1] + [(7777, bytes([7] * 16), 1, bytes(32))])
        (config.DATA_DIR / er.JOURNAL_NAME).write_bytes(fork)
        check("a live journal that diverges from the backup's → stage refused (backup.erasureConflict)",
              raises(lambda: backup.stage_restore(blob, PASS, keys=hk), er.ErasureConflict)
              and not (config.DATA_DIR / ".restore-flag").exists())
        # divergenţă apărută între stage şi apply: apply refuză, volumul neatins
        (config.DATA_DIR / er.JOURNAL_NAME).write_bytes(j3)
        backup.stage_restore(blob, PASS, keys=hk)
        (config.DATA_DIR / er.JOURNAL_NAME).write_bytes(fork)
        db_before = config.DB_PATH.read_bytes()
        check("divergence between stage and apply → apply refused, the DB untouched",
              raises(lambda: backup.apply_pending_restore(keys=hk), er.ErasureConflict)
              and config.DB_PATH.read_bytes() == db_before)
        (config.DATA_DIR / er.JOURNAL_NAME).write_bytes(j3)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        # flag oprit: o arhivă cu jurnal nu se restaurează pe calea veche
        os.environ.pop("WEBTERM_TX_RECORDINGS")
        try:
            check("flag off: an archive with an erasure journal → refused (backup.erasureUnsupported)",
                  raises(lambda: backup.stage_restore(blob, PASS, keys=hk), er.ErasureUnsupported))
        finally:
            os.environ["WEBTERM_TX_RECORDINGS"] = "1"
        # mark_unproven pe un DB cu înregistrări servibile
        dbp = os.path.join(BASE, "mark.db")
        con = sqlite3.connect(dbp)
        con.executescript(db.SCHEMA)
        con.execute("INSERT INTO tx_descriptors(sid, kind, blob, version, status) VALUES('s1','out',x'00',1,'ok')")
        con.execute("INSERT INTO tx_descriptors(sid, kind, blob, version, status) VALUES('s2','out',x'00',1,'damaged')")
        con.commit()
        con.close()
        er.mark_unproven_sync(dbp, 1234, 2)
        er.mark_unproven_sync(dbp, 1234, 2)
        con = sqlite3.connect(dbp)
        rows = dict(con.execute("SELECT sid, status FROM tx_descriptors").fetchall())
        q = con.execute("SELECT sid, reason FROM tx_quarantine").fetchall()
        con.close()
        check("restore without proof: readable recordings → quarantined (continuity), damaged untouched, idempotent",
              rows == {"s1": "quarantined", "s2": "damaged"} and q == [("s1", "continuity")])
        hk_inv = ts.inventory(config.DATA_DIR, config.DB_PATH)
        check("shared inventory names the journal and the tx state", "erasures.wtj" in hk_inv
              and "tx_state.erasure_head" in hk_inv and "tx_descriptors" in hk_inv, hk_inv)
    finally:
        config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR = saved


class _Crash(Exception):
    pass


def _crash_at(step):
    def f(name):
        if name == step:
            raise _Crash(name)
    return f


def g_h1_restore():
    print("== H1: restore against the live committed head (stage AND apply) ==")
    saved = (config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR)
    try:
        hk = prot_volume("prot-h1")
        ents = [(2000 + i, s, 3, bytes(32)) for i, s in enumerate(sids(4))]
        j1, j2, j3 = build(ents[:1]), build(ents[:2]), build(ents[:3])
        jp = config.DATA_DIR / er.JOURNAL_NAME
        set_head(config.DB_PATH, j1, descs=["ef" * 16])
        jp.write_bytes(j1)
        blob = backup.make_encrypted(PASS, keys=hk)            # backup la n=1
        # după backup: ştergerea n=2 comisă (jurnal + DB)
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j2)
        h2 = er.parse(j2, K, INST).head
        # (a) jurnalul viu pierde CURAT intrarea 2 (prefixul 1 e compatibil cu backup-ul)
        jp.write_bytes(j1)
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("cleanly shortened live journal (DB head n=2, journal n=1) → stage says unproven",
              info.get("erasure") == "unproven" and info.get("erasure_proof") == "none", info)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("…apply: quarantine + the threshold (n=2, its MAC) kept in the continuity marker",
              cont.get("state") == "unproven" and cont.get("threshold", {}).get("n") == 2
              and cont["threshold"]["mac"] == h2.mac.hex() and cont.get("n") == 1, cont)
        # (b) intrarea comisă n=2 cu MAC stricat: stage şi apply decid la fel
        set_head(config.DB_PATH, j2)
        t = bytearray(j2)
        t[-1] ^= 1
        jp.write_bytes(bytes(t))
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("committed entry with a bad MAC → never a valid prefix: stage unproven",
              info.get("erasure") == "unproven", info)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("…apply (same criterion): unproven, threshold n=2", cont.get("threshold", {}).get("n") == 2, cont)
        # (c) cădere DUPĂ publicarea jurnalului: reluarea nu face din jurnalul publicat o dovadă
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j1)
        d = FakeDest("sftp:u@h:22/h1")

        def fetch(k, inst):
            return [er.DestResult(d.id, True, er.parse(j3, k, inst), j3)], [d.id]
        info = backup.stage_restore(blob, PASS, keys=hk, erasure_fetch=fetch)
        check("a destination holding n=3 (beyond the live head) → stage proven by destinations",
              info.get("erasure_proof") == "destinations", info)
        backup._fault = _crash_at("apply:erasure-journal")
        try:
            crashed = raises(lambda: backup.apply_pending_restore(keys=hk), _Crash)
        finally:
            backup._fault = None
        check("crash right after the journal publication (volume journal = J*, n=3)",
              crashed and jp.read_bytes() == j3)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("…resume: the journal WE published is not J_v → still unproven, threshold from the flag",
              cont.get("state") == "unproven" and cont.get("threshold", {}).get("n") == 2
              and cont.get("known", {}).get(d.id) == 3, cont)
        # (d) dovedit de volum, cădere după DB: reluarea păstrează dovada (jurnalul atinge pragul).
        # R2-M2: markerul ţine capul n=3 al destinaţiei din (c): un J_v n=2 nu-l mai dovedeşte
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j2)
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("R2-M2: a journal holding the live head (n=2) but not the kept off-host head (n=3) → unproven",
              info.get("erasure_proof") == "none", info)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        check("…apply keeps the marker with the off-host head", (tx_state("continuity") or {}).get("known", {})
              .get(d.id) == 3)
        jp.write_bytes(j3)
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("journal holding the live head and the kept off-host head → stage proven by the volume",
              info.get("erasure_proof") == "volume", info)
        backup._fault = _crash_at("apply:db")
        try:
            raises(lambda: backup.apply_pending_restore(keys=hk), _Crash)
        finally:
            backup._fault = None
        check("…crash after the DB copy: the live DB is now the restored one (head n=1)",
              (tx_state("erasure_head") or {}).get("n") == 1)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        check("…resume: proven from the flag and re-checked on the journal left (n=3 ≥ threshold) → no marker",
              tx_state("continuity") is None and jp.read_bytes() == j3)
        # (e) ştergere comisă ÎNTRE stage şi apply, cu jurnalul pierzând-o: apply o vede
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j2)
        info = backup.stage_restore(blob, PASS, keys=hk)
        set_head(config.DB_PATH, j3)                 # capul DB-ului viu avansează la 3 ...
        jp.write_bytes(j2)                           # ... dar jurnalul n-o mai are
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("live head advanced after stage but missing from J_v → apply (re-checked under the lock) unproven",
              info.get("erasure_proof") == "volume" and cont.get("threshold", {}).get("n") == 3, (info, cont))
    finally:
        config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR = saved


def _quarantine_of(dbp, sid):
    con = sqlite3.connect(str(dbp))
    try:
        return (dict(con.execute("SELECT kind, status FROM tx_descriptors WHERE sid=?", (sid,)).fetchall()),
                dict(con.execute("SELECT kind, reason FROM tx_quarantine WHERE sid=?", (sid,)).fetchall()))
    finally:
        con.close()


def g_rh1_consecutive():
    print("== R-H1: the threshold survives consecutive restores and a re-import ==")
    saved = (config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR)
    try:
        hk = prot_volume("prot-rh1")
        victim = bytes([0x5a] * 16)
        ents = [(4000, bytes([0x51] * 16), 3, bytes(32)), (4001, victim, 3, bytes(32))]
        j1, j2 = build(ents[:1]), build(ents[:2])
        h2 = er.parse(j2, K, INST).head
        jp = config.DATA_DIR / er.JOURNAL_NAME
        set_head(config.DB_PATH, j1)
        jp.write_bytes(j1)
        # victima: o înregistrare 3.7 încă în clar (pending), inclusă în backup ca `legacy`
        vp = config.TRANSCRIPT_DIR / (victim.hex() + ".out")
        vp.write_bytes(b"victim-plaintext")
        f = os.stat(vp)
        con = sqlite3.connect(str(config.DB_PATH))
        con.execute("INSERT INTO tx_migration(sid, kind, dir, name, dev, ino, size, mtime_ns, state) "
                    "VALUES(?,?,?,?,?,?,?,?,'pending')", (victim.hex(), "out", "transcripts", vp.name,
                                                          f.st_dev, f.st_ino, f.st_size, f.st_mtime_ns))
        con.execute("INSERT OR REPLACE INTO tx_state(key, value) VALUES('migration_inventory', '1')")
        con.commit()
        con.close()
        old = backup.make_encrypted(PASS, keys=hk)               # backup la n=1, cu victima servibilă
        set_head(config.DB_PATH, j2)                              # ştergerea victimei, n=2, comisă
        jp.write_bytes(j1)                                        # ... dar jurnalul o pierde
        info = backup.stage_restore(old, PASS, keys=hk)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("restore A without proof: threshold n=2 (its MAC) kept, the victim quarantined",
              info.get("erasure") == "unproven" and cont.get("threshold", {}).get("n") == 2
              and cont["threshold"]["mac"] == h2.mac.hex()
              and _quarantine_of(config.DB_PATH, victim.hex())[1] == {"out": "continuity"} and vp.exists(),
              cont)
        # export în carantină (DB cu markerul, jurnal n=1) înainte de al doilea restore
        exported = backup.make_encrypted(PASS, keys=hk)
        # restore B: acelaşi backup vechi; DB-ul viu are capul n=1 şi jurnalul n=1 (fără marker ar
        # fi fost „dovedit de volum")
        info = backup.stage_restore(old, PASS, keys=hk)
        check("restore B from the older backup: stage reads the live marker → still unproven",
              info.get("erasure") == "unproven" and info.get("erasure_proof") == "none", info)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        desc, q = _quarantine_of(config.DB_PATH, victim.hex())
        check("…the threshold never goes down (n=2, same MAC), the erased recording stays unreadable",
              cont.get("threshold", {}).get("n") == 2 and cont["threshold"]["mac"] == h2.mac.hex()
              and vp.exists() and q == {"out": "continuity"}, (cont, desc, q))
        # re-import pe un volum fără DB viu: pragul vine din markerul DB-ului din backup
        os.unlink(config.DB_PATH)
        jp.unlink()
        info = backup.stage_restore(exported, PASS, keys=hk)
        check("re-import of a dataset exported while quarantined (no live DB) → unproven",
              info.get("erasure") == "unproven", info)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("…its marker keeps threshold n=2 and the victim quarantined",
              cont.get("threshold", {}).get("n") == 2
              and _quarantine_of(config.DB_PATH, victim.hex())[1] == {"out": "continuity"} and vp.exists(),
              cont)
        # acelaşi n cu alt MAC în DB-ul viu faţă de marker: conflict, restore refuzat
        con = sqlite3.connect(str(config.DB_PATH))
        con.execute("UPDATE tx_state SET value=? WHERE key='erasure_head'",
                    (json.dumps(er.Head(2, 1, bytes([9] * 32)).to_json()),))
        con.commit()
        con.close()
        check("live head and live marker disagree at the same n → stage refused (conflict)",
              raises(lambda: backup.stage_restore(old, PASS, keys=hk), er.ErasureConflict))
        # cu jurnalul care atinge pragul: dovedit, markerul dispare
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j2)
        info = backup.stage_restore(old, PASS, keys=hk)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        check("a volume journal that reaches the kept threshold proves continuity (marker cleared)",
              info.get("erasure_proof") == "volume" and tx_state("continuity") is None, info)
    finally:
        config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR = saved


def _put_marker(dbp, mark):
    con = sqlite3.connect(str(dbp))
    con.execute("INSERT OR REPLACE INTO tx_state(key, value) VALUES('continuity', ?)", (json.dumps(mark),))
    con.commit()
    con.close()


def g_r2m2_restore():
    print("== R2-M2: a kept off-host head of a retired destination survives the next restore; "
          "R2-H1: erase intents survive a restore ==")
    saved = (config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR)
    try:
        hk = prot_volume("prot-r2m2")
        ents = [(6000 + i, s, 3, bytes(32)) for i, s in enumerate(sids(3))]
        j1, j2, j3 = build(ents[:1]), build(ents[:2]), build(ents[:3])
        jp = config.DATA_DIR / er.JOURNAL_NAME
        set_head(config.DB_PATH, j1)
        jp.write_bytes(j1)
        old = backup.make_encrypted(PASS, keys=hk)                # backup la n=1
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j2)
        h2 = er.parse(j2, K, INST).head
        gone = "sftp:u@h:22/retired"
        # un restore anterior fără dovadă, cu destinaţia „gone" (cap n=3 cunoscut) deja retrasă
        _put_marker(config.DB_PATH, {"state": "unproven", "since": 1, "n": 2, "threshold": h2.to_json(),
                                     "known": {gone: 3}})
        pending = "c4" * 16
        con = sqlite3.connect(str(config.DB_PATH))
        con.execute("INSERT INTO tx_erase_intents(sid, kinds, since) VALUES(?, 'out', 5)", (pending,))
        con.commit()
        con.close()
        info = backup.stage_restore(old, PASS, keys=hk)
        check("J_v reaches the local threshold (n=2) but not the retired destination's kept head (n=3) "
              "→ stage unproven", info.get("erasure") == "unproven" and info.get("erasure_proof") == "none", info)
        backup._fault = _crash_at("apply:db")
        try:
            crashed = raises(lambda: backup.apply_pending_restore(keys=hk), _Crash)
        finally:
            backup._fault = None
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("…apply (resumed after the DB copy): the marker keeps the off-host head n=3 and the threshold",
              crashed and cont.get("state") == "unproven" and cont.get("known", {}).get(gone) == 3
              and cont.get("threshold", {}).get("n") == 2, cont)
        con = sqlite3.connect(str(config.DB_PATH))
        row = con.execute("SELECT kinds FROM tx_erase_intents WHERE sid=?", (pending,)).fetchone()
        con.close()
        check("R2-H1: the live volume's erase intent is carried into the restored database (the boot "
              "completes it)", row == ("out",), row)
        _, proven, _ = er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j1, live_journal=j2,
                                          threshold=h2, live_ok=True, known={gone: 3})
        _, proven3, _ = er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j1, live_journal=j3,
                                           threshold=h2, live_ok=True, known={gone: 3})
        check("reconcile_apply: J_v below a kept off-host head never proves; reaching it does",
              proven is False and proven3 is True)
    finally:
        config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR = saved


R5H1_MARKER = {}


def g_r5h1_restore():
    print("== R5-H1: an unverifiable newer object seen at stage blocks the volume proof (stage → apply → resume) ==")
    saved = (config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR)
    try:
        hk = prot_volume("prot-r5h1")
        ents = [(8000 + i, s, 3, bytes(32)) for i, s in enumerate(sids(4))]
        j1, j2, j3 = build(ents[:1]), build(ents[:2]), build(ents[:3])
        jp = config.DATA_DIR / er.JOURNAL_NAME
        set_head(config.DB_PATH, j1, descs=["e5" * 16])
        jp.write_bytes(j1)
        blob = backup.make_encrypted(PASS, keys=hk)                # backup la n=1
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j2)                                          # J_v ajunge la capul viu n=2
        did = "sftp:u@h:22/r5h1"

        def unverifiable(k, inst):
            return [er.DestResult(did, False, error="unverifiable", unverified=3)], [did]
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("control: no destination, J_v reaches the live head n=2 → stage proven by the volume",
              info.get("erasure_proof") == "volume", info)
        info = backup.stage_restore(blob, PASS, keys=hk, erasure_fetch=unverifiable)
        check("R5-H1: J_v reaches n=2 but a destination shows an unverifiable n=3 → stage unproven",
              info.get("erasure") == "unproven" and info.get("erasure_proof") == "none", info)
        # o dovadă locală concurentă: între stage şi apply J_v ajunge chiar la n=3 (altă ramură posibilă)
        jp.write_bytes(j3)
        backup._fault = _crash_at("apply:db")
        try:
            crashed = raises(lambda: backup.apply_pending_restore(keys=hk), _Crash)
        finally:
            backup._fault = None
        flag = json.loads(backup._restore_flag().read_bytes())
        check("R5-H1: …the gap travels in the flag (destination → n), the proof is not granted",
              crashed and flag.get("erasure_unverified") == {did: 3} and flag.get("erasure_proven") is False, flag)
        backup.apply_pending_restore(keys=hk)                       # reluare după copia DB
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("R5-H1: …resumed apply with a local journal reaching n=3: still quarantined, the gap folded "
              "into the known heads and the mandatory destinations",
              cont.get("state") == "unproven" and cont.get("unverified") == {did: 3}
              and cont.get("known", {}).get(did) == 3 and did in cont.get("required", []), cont)
        R5H1_MARKER.update(cont)
        # fără reluare: acelaşi refuz la primul apply
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j2)
        con = sqlite3.connect(str(config.DB_PATH))
        con.execute("DELETE FROM tx_state WHERE key='continuity'")
        con.commit()
        con.close()
        backup.stage_restore(blob, PASS, keys=hk, erasure_fetch=unverifiable)
        jp.write_bytes(j3)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("R5-H1: first apply (no crash), J_v at n=3 → the restore does not lift: unproven, gap kept",
              cont.get("state") == "unproven" and cont.get("unverified") == {did: 3}, cont)
        # „sau acum": markerul viu ţine golul — un restore următor fără destinaţii nu-l pierde
        set_head(config.DB_PATH, j3)
        jp.write_bytes(j3)
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("R5-H1: the live marker's gap blocks the next restore's volume proof (J_v reaches everything)",
              info.get("erasure_proof") == "none", info)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("…and its apply keeps the gap", cont.get("state") == "unproven"
              and cont.get("unverified") == {did: 3}, cont)
        # pur: J_v la acelaşi n ca obiectul neverificabil şi o altă destinaţie autentică la acelaşi n
        live = er.Live("same", er.parse(j2, K, INST).head)
        other = er.DestResult("sftp:u@h:22/other", True, er.parse(j3, K, INST), j3)
        d = er.decide_restore(k_erase=K, inst=INST, j_b=j1, tracked=True, j_v=j3, live=live,
                              dest_results=[other, er.DestResult(did, False, error="unverifiable", unverified=3)],
                              required_dests={other.id, did})
        check("R5-H1: J_v and another destination at n=3 do not cover an unverifiable n=3 → no proof",
              d.proof == "none" and d.unverified == {did: 3} and d.known.get(did) == 3 and did in d.required, d)
        d = er.decide_restore(k_erase=K, inst=INST, j_b=j1, tracked=True, j_v=j3, live=live,
                              staged=er.Terms(unverified={did: 3}))
        check("R5-H1: a gap kept by the backup's own marker blocks the volume proof too", d.proof == "none", d)
        _, proven, _ = er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j1, live_journal=j3,
                                          threshold=live.head, live_ok=True, unverified={did: 3})
        _, proven0, _ = er.reconcile_apply(k_erase=K, inst=INST, staged_journal=j1, live_journal=j3,
                                           threshold=live.head, live_ok=True)
        check("R5-H1: reconcile_apply never proves with a gap (it does without)", proven is False and proven0 is True)
    finally:
        config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR = saved


def _real_fetch(dests):
    """The stage's `erasure_fetch` through the REAL `fetch_all` / `fetch_head` (own loop, own thread:
    the staging is synchronous and this test runs inside the main loop)."""
    import concurrent.futures

    def fetch(k, inst):
        with concurrent.futures.ThreadPoolExecutor(1) as ex:
            return ex.submit(asyncio.run, er.fetch_all(dests, k, inst)).result(), [d.id for d in dests]
    return fetch


def g_r6h1_restore():
    print("== R6-H1: a fork a destination holds (fetch → conflict) blocks every proof (stage → apply → resume) ==")
    saved = (config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR)
    try:
        hk = prot_volume("prot-r6h1")
        ents = [(8100 + i, s, 3, bytes(32)) for i, s in enumerate(sids(3))]
        j1, j2, j3 = build(ents[:1]), build(ents[:2]), build(ents[:3])
        j3b = _extend(j2, bytes([0x6b] * 16))                     # altă ramură la n=3 (o ştergere absentă local)
        jp = config.DATA_DIR / er.JOURNAL_NAME
        set_head(config.DB_PATH, j1, descs=["e6" * 16])
        jp.write_bytes(j1)
        blob = backup.make_encrypted(PASS, keys=hk)                # backup la n=1
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j2)                                          # J_v ajunge la capul viu n=2
        d = FakeDest("sftp:u@h:22/r6h1")
        d.objs = {er.object_name(INST, 3, "aa11bb22"): j3, er.object_name(INST, 3, "cc33dd44"): j3b}
        fork = _real_fetch([d])
        res, _ids = fork(K, INST)
        check("R6-H1: the real fetch reports the fork as a gap at its n (conflict, n=3)",
              res[0].error == "conflict" and res[0].unverified == 3 and not res[0].ok, res)
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("control: no destination, J_v reaches the live head n=2 → stage proven by the volume",
              info.get("erasure_proof") == "volume", info)
        info = backup.stage_restore(blob, PASS, keys=hk, erasure_fetch=fork)
        check("R6-H1: J_v reaches n=2 but the destination holds two authentic n=3 → stage unproven "
              "(never proof=volume)", info.get("erasure") == "unproven" and info.get("erasure_proof") == "none", info)
        jp.write_bytes(j3)                                          # J_v ajunge şi la n=3 (una dintre ramuri)
        backup._fault = _crash_at("apply:db")
        try:
            crashed = raises(lambda: backup.apply_pending_restore(keys=hk), _Crash)
        finally:
            backup._fault = None
        flag = json.loads(backup._restore_flag().read_bytes())
        check("R6-H1: …the fork travels in the flag as a gap (destination → 3), no proof",
              crashed and flag.get("erasure_unverified") == {d.id: 3} and flag.get("erasure_proven") is False, flag)
        backup.apply_pending_restore(keys=hk)                       # reluare
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("R6-H1: …resumed apply with J_v on one branch at n=3: quarantined, the fork kept in the marker "
              "(known + mandatory)", cont.get("state") == "unproven" and cont.get("unverified") == {d.id: 3}
              and cont.get("known", {}).get(d.id) == 3 and d.id in cont.get("required", []), cont)
        # primul apply, fără crash
        set_head(config.DB_PATH, j2)
        jp.write_bytes(j2)
        con = sqlite3.connect(str(config.DB_PATH))
        con.execute("DELETE FROM tx_state WHERE key='continuity'")
        con.commit()
        con.close()
        backup.stage_restore(blob, PASS, keys=hk, erasure_fetch=fork)
        jp.write_bytes(j3)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        cont = tx_state("continuity") or {}
        check("R6-H1: first apply (no crash) → unproven, the fork kept", cont.get("state") == "unproven"
              and cont.get("unverified") == {d.id: 3}, cont)
        conf = cont.get("conflict") or {}
        check("R7-H1: …the marker keeps the AUTHENTICATED conflict: both branch heads (n + MAC), the common "
              "prefix, and the erasure of the branch the volume does not have",
              sorted((h["n"], h["mac"]) for h in conf.get("heads", []))
              == sorted((3, er.parse(j, K, INST).head.mac.hex()) for j in (j3, j3b))
              and conf.get("bases") == [er.parse(j2, K, INST).head.to_json()]
              and bytes([0x6b] * 16).hex() in conf.get("sids", []) and d.id in conf.get("dests", []), conf)
        set_head(config.DB_PATH, j3)
        jp.write_bytes(j3)
        info = backup.stage_restore(blob, PASS, keys=hk)
        check("R6-H1: the live marker keeps the fork: the next restore without destinations proves nothing",
              info.get("erasure_proof") == "none", info)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        # pur: un fork + o dovadă locală şi o destinaţie autentică altfel suficiente
        live = er.Live("same", er.parse(j2, K, INST).head)
        other = er.DestResult("sftp:u@h:22/other", True, er.parse(j3, K, INST), j3)
        dd = er.decide_restore(k_erase=K, inst=INST, j_b=j1, tracked=True, j_v=j3, live=live,
                               dest_results=[other, res[0]], required_dests={other.id, d.id})
        check("R6-H1: decide_restore: J_v and another destination reaching n=3 do not outweigh a fork → no proof",
              dd.proof == "none" and dd.unverified == {d.id: 3} and d.id in dd.required, dd)
        dd = er.decide_restore(k_erase=K, inst=INST, j_b=j1, tracked=True, j_v=j3, live=live,
                               dest_results=[er.DestResult(d.id, False, error="conflict")])
        check("R6-H1: a conflict result without n still refuses every proof", dd.proof == "none", dd)
    finally:
        config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR = saved


async def g_r5h1_prove(st):
    print("== R5-H1: the janitor lifts the restore's gap only once that destination is readable ==")
    cur = journal_path().read_bytes()
    p = er.parse(cur, K, INST)
    n = p.n
    d = FakeDest(R5H1_MARKER.get("required", ["sftp:u@h:22/r5h1"])[0])
    d.objs[er.object_name(INST, n)] = cur
    victim = bytes([0x5a] * 16)
    newer = _extend(cur, victim)
    d.objs[er.object_name(INST, n + 1)] = newer[:-1] + bytes([newer[-1] ^ 1])   # n+1 neautentic
    DESTS[:] = [d]
    # markerul exact în forma scrisă de apply (g_r5h1_restore), mutat pe capul acestui volum
    mark = {"state": "unproven", "since": 1, "n": n, "threshold": p.head.to_json(),
            "known": {d.id: n + 1}, "required": [d.id], "unverified": {d.id: n + 1}}
    check("the marker shape is the one the apply wrote", set(R5H1_MARKER) <= set(mark) | {"overflow"}
          and "unverified" in R5H1_MARKER, R5H1_MARKER)
    await set_marker(st, mark)
    check("R5-H1: the gap is an unreached head: a new local erasure is refused (behind)", er._behind())
    check("R5-H1: the destination still shows the unverifiable n+1 → try_prove keeps the quarantine",
          await er.try_prove(st) is False and er.continuity() is not None)
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": p.head.to_json(),
                          "unverified": {d.id: n + 1}})
    del d.objs[er.object_name(INST, n + 1)]
    check("R5-H1: a marker gap alone (not in known/required) is still an obligation: the object removed, "
          "the destination at n proves nothing", await er.try_prove(st) is False and er.continuity() is not None)
    await set_marker(st, mark)
    d.objs[er.object_name(INST, n + 1)] = newer                                  # copia autentică
    ok = await er.try_prove(st)
    check("R5-H1: the destination fixed (authentic n+1) → try_prove lifts and adopts its tombstone",
          ok and er.continuity() is None and victim.hex() in st.tombstoned
          and er.parse(journal_path().read_bytes(), K, INST).n == n + 1, (ok, er.continuity()))
    DESTS[:] = []


def g_live_bad_restore():
    print("== recheck 6678938: a restore over an unreadable live erasure state keeps the live intents ==")
    saved = (config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR)
    try:
        hk = prot_volume("prot-livebad")
        j1 = build([(6100, sids(1)[0], 3, bytes(32))])
        jp = config.DATA_DIR / er.JOURNAL_NAME
        set_head(config.DB_PATH, j1)
        jp.write_bytes(j1)
        old = backup.make_encrypted(PASS, keys=hk)
        pending = "d5" * 16
        con = sqlite3.connect(str(config.DB_PATH))
        con.execute("INSERT INTO tx_erase_intents(sid, kinds, since) VALUES(?, 'cast', 5)", (pending,))
        # starea de ştergere vie ilizibilă (marker stricat) → Live("bad")
        con.execute("INSERT OR REPLACE INTO tx_state(key, value) VALUES('continuity', '{bad')")
        con.commit()
        con.close()
        check("baseline: the live erasure state reads as `bad`",
              er.live_state(config.DB_PATH, INST, INST).state == "bad")
        backup.stage_restore(old, PASS, keys=hk)
        backup.apply_pending_restore(keys=hk)
        hk = reopen(hk)
        con = sqlite3.connect(str(config.DB_PATH))
        row = con.execute("SELECT kinds FROM tx_erase_intents WHERE sid=?", (pending,)).fetchone()
        con.close()
        check("Live(bad): the live erase intent is still carried into the restored database", row == ("cast",), row)
        # intenţiile nu se pot inventaria (DB-ul viu nu e o bază SQLite): restore-ul se refuză
        old2 = backup.make_encrypted(PASS, keys=hk)
        backup.stage_restore(old2, PASS, keys=hk)
        live = config.DB_PATH.read_bytes()
        config.DB_PATH.write_bytes(b"not a database" * 100)
        err = None
        try:
            # şi fără copia de siguranţă (care oricum nu s-ar putea face): refuzul e al intenţiilor
            backup.apply_pending_restore(keys=hk, force_without_safety_copy=True)
        except Exception as e:                   # noqa: BLE001
            err = e
        check("Live(bad) and the intents cannot be inventoried → the restore is refused (even forced past the "
              "safety copy), the live DB untouched",
              isinstance(err, er.ErasureConflict) and "intents" in str(err)
              and config.DB_PATH.read_bytes() == b"not a database" * 100, repr(err))
        config.DB_PATH.write_bytes(live)
    finally:
        config.DATA_DIR, config.DB_PATH, config.TRANSCRIPT_DIR = saved


# ── 9. Owner recovery ────────────────────────────────────────────────────────


async def g_recovery(st, c, uid, host_id, keep):
    print("== Owner recovery mode ==")
    rec, data = await make_rec(st, host_id)
    since = int(time.time()) - 86400
    await txhub.shutdown()
    er.mark_unproven_sync(config.DB_PATH, since, er.parse(journal_path().read_bytes(), K, INST).n)
    # o înregistrare în carantină de JURNAL (alt motiv): recovery nu o deschide niciodată
    await db.execute("UPDATE tx_quarantine SET reason='journal:fork' WHERE sid=?", keep)
    st = await reboot()
    check("boot keeps the continuity quarantine; System health says so",
          er.health_has("erasure_unproven") and (await statuses())[(rec, "out")] == "quarantined")
    r = await c.get("/api/recordings/quarantine")
    items = {i["sid"]: i for i in r.json().get("items", [])} if r.status_code == 200 else {}
    check("list: reason and recoverable per recording",
          items.get(rec, {}).get("recoverable") is True and items.get(keep, {}).get("recoverable") is False, r.text)
    r = await c.get(f"/api/sessions/{rec}/transcript?format=out")
    check("normal read of a quarantined recording → 423", r.status_code == 423, r.status_code)
    date = time.strftime("%Y-%m-%d", time.gmtime(since))
    r = await c.post(f"/api/sessions/{rec}/recovery", json={"confirm": "2000-01-01", "stepup_grant": grant(uid, host_id)})
    check("wrong typed backup date → 400 transcript.recoveryConfirm",
          r.status_code == 400 and r.json().get("code") == "transcript.recoveryConfirm", r.text)
    security._stepup_windows.clear()          # fereastra de ≤120 s a factorului anterior s-a închis
    r = await c.post(f"/api/sessions/{rec}/recovery", json={"confirm": date})
    check("no fresh factor → 403", r.status_code == 403, r.text)
    r = await c.post(f"/api/sessions/{keep}/recovery", json={"confirm": date, "stepup_grant": grant(uid, host_id)})
    check("a journal quarantine whose diagnosis System health does not show (healthy journal) → 409 "
          "transcript.journalNotDiagnosed", r.status_code == 409
          and r.json().get("code") == "transcript.journalNotDiagnosed", r.text)
    r = await c.post(f"/api/sessions/{rec}/recovery", json={"confirm": date, "stepup_grant": grant(uid, host_id)})
    check("recover one recording → recovery", r.status_code == 200 and (await statuses())[(rec, "out")] == "recovery", r.text)
    r = await c.get(f"/api/sessions/{rec}/transcript?format=out")
    check("normal route still refuses a recovery recording (423)", r.status_code == 423, r.status_code)
    r = await c.post(f"/api/sessions/{rec}/replay-links", json={})
    check("no replay link for a recovery recording", r.status_code != 200, r.status_code)
    r = await c.get("/api/search", params={"q": "secret-" + rec})
    hits = [x for x in r.json().get("results", r.json() if isinstance(r.json(), list) else [])
            if isinstance(x, dict) and x.get("id") == rec and (x.get("matches") or x.get("snippet"))] \
        if r.status_code == 200 else []
    check("no search hit from a recovery recording", r.status_code == 200 and not hits, r.text[:200])
    check("Store: only the Owner-recovery access opens it",
          await _refused(read_all(st, rec)) and await read_all(st, rec, owner_recovery=True) == data)
    r = await c.get(f"/api/sessions/{rec}/recovery/transcript?format=out")
    check("Owner recovery read → the recording", r.status_code == 200 and r.content == data, r.status_code)
    a = await db.fetchone("SELECT detail FROM audit_log WHERE path=? AND method='GET'",
                          f"/api/sessions/{rec}/recovery/transcript")
    check("…and the read is audited", a is not None and "owner recovery read" in (a["detail"] or ""), a)
    r = await c.post(f"/api/sessions/{rec}/recovery/requarantine")
    check("re-quarantine → quarantined", r.status_code == 200 and (await statuses())[(rec, "out")] == "quarantined")
    r = await c.get(f"/api/sessions/{rec}/recovery/transcript?format=out")
    check("recovery read of a quarantined recording → 409", r.status_code == 409, r.status_code)
    await c.post(f"/api/sessions/{rec}/recovery", json={"confirm": date, "stepup_grant": grant(uid, host_id)})
    security._stepup_windows.clear()
    r = await c.post(f"/api/sessions/{rec}/recovery/release", json={})
    check("release without a fresh factor → 403", r.status_code == 403, r.text)
    r = await c.post(f"/api/sessions/{rec}/recovery/release", json={"stepup_grant": grant(uid, host_id)})
    check("release one recording → normal access", r.status_code == 200
          and (await c.get(f"/api/sessions/{rec}/transcript?format=out")).content == data, r.text)
    # janitorul ridică restul carantinei de continuitate când TOATE destinaţiile dovedesc capul
    other, _ = await make_rec(st, host_id)
    await st.txn(lambda cur: er._quarantine_cohort_sync(cur, "continuity", time.time()))
    await db.execute("UPDATE tx_quarantine SET reason='journal:fork' WHERE sid=?", keep)
    d = FakeDest("sftp:u@h:22/p2")
    DESTS[:] = [d]
    check("no proof while a destination is down", (d.__setattr__("fail", True) or True)
          and await er.try_prove(st) is False and er.continuity() is not None)
    d.fail = False
    await er.attest_once(st)
    check("M1: a destination only WE uploaded to after the restore (nothing known of it) proves nothing",
          await er.try_prove(st) is False and er.continuity() is not None)
    n_now = er._s.parsed.n
    await set_marker(st, {"state": "unproven", "since": since, "n": n_now, "known": {d.id: n_now}})
    junk = er.object_name(INST, n_now + 1)
    d.objs[junk] = b"junk"
    check("R4-H2: a newer object at the destination that cannot be authenticated → not proven",
          await er.try_prove(st) is False and er.continuity() is not None)
    del d.objs[junk]
    ok = await er.try_prove(st)
    s = await statuses()
    check("every destination proves the head → continuity quarantine lifted, journal quarantine kept",
          ok and er.continuity() is None and s[(other, "out")] == "ok" and s[(keep, "out")] == "quarantined"
          and not er.health_has("erasure_unproven"), (ok, s.get((other, "out")), s.get((keep, "out"))))
    DESTS[:] = []
    return st


async def g_behind(st, host_id):
    print("== R-M1 / R-M2: no new branch under an unreached threshold; mandatory destinations ==")
    cur = journal_path().read_bytes()
    n = er.parse(cur, K, INST).n
    head = er.parse(cur, K, INST).head
    rec, data = await make_rec(st, host_id)
    await st.txn(lambda c: er._quarantine_cohort_sync(c, "continuity", time.time()))
    ahead = er.Head(n + 1, 1, os.urandom(32))
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": ahead.to_json()})
    check("R-M1: erase refused while the local journal does not reach the kept threshold",
          await _erasure_code(er.erase(st, rec)) == "transcript.erasureBehind"
          and er.parse(journal_path().read_bytes(), K, INST).n == n)
    check("R-M1: …and so is the discard of a failed migration",
          await _erasure_code(er.discard_failed(st, rec)) == "transcript.erasureBehind")
    await er.recover(st, rec)
    check("the audited Owner recovery (exceptional access) still works", (await statuses())[(rec, "out")] == "recovery")
    check("release (normal access) refused while behind the threshold",
          await _erasure_code(er.release(st, rec)) == "transcript.releaseBehind"
          and (await statuses())[(rec, "out")] == "recovery")
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "known": {"sftp:x": n + 2}})
    check("R-M1: a destination known to hold a higher head also blocks a new local entry",
          await _erasure_code(er.erase(st, rec)) == "transcript.erasureBehind")
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": "junk"})
    check("an unreadable marker counts as behind (fail closed)",
          await _erasure_code(er.erase(st, rec)) == "transcript.erasureBehind")
    # R-M2: destinaţia obligatorie la restore nu mai e configurată
    d = FakeDest("sftp:u@h:22/rm2")
    d.objs[er.object_name(INST, n)] = cur
    DESTS[:] = [d]
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": head.to_json(),
                          "known": {d.id: n}, "required": ["sftp:u@h:22/gone"]})
    check("R-M2: a mandatory destination replaced by another → no proof, quarantine kept",
          await er.try_prove(st) is False and er.continuity() is not None)
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": head.to_json(),
                          "known": {d.id: n}, "overflow": True})
    check("R-M2: a marker whose known heads overflowed never proves",
          await er.try_prove(st) is False and er.continuity() is not None)
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": head.to_json(),
                          "known": {d.id: n}, "required": [d.id]})
    # R6-H2: o destinaţie obligatorie îşi datorează dovada: release refuzat cât timp markerul o cere,
    # chiar dacă jurnalul local atinge numeric totul; try_prove (dovada ei) ridică
    check("…the same destination still mandatory: release refused (R6-H2, it owes proof), try_prove lifts",
          await _erasure_code(er.release(st, rec)) == "transcript.releaseUnproven"
          and (await statuses())[(rec, "out")] == "recovery"
          and await er.try_prove(st) is True and er.continuity() is None
          and (await statuses())[(rec, "out")] == "ok")
    DESTS[:] = []
    await unquarantine_all()


async def g_r6h2_release(st, c, uid, host_id):
    print("== R6-H2: release never lifts a quarantine that still owes off-host proof ==")
    cur = journal_path().read_bytes()
    p = er.parse(cur, K, INST)
    n = p.n
    rec, data = await make_rec(st, host_id)
    await st.txn(lambda cu: er._quarantine_cohort_sync(cu, "continuity", time.time()))
    d = FakeDest("sftp:u@h:22/r6h2")
    d.objs[er.object_name(INST, n)] = cur[:-1] + bytes([cur[-1] ^ 1])          # n neautentic
    DESTS[:] = [d]
    # exact ce scrie restore-ul (R5-H1): golul la n == capul local (numeric atins)
    mark = {"state": "unproven", "since": 1, "n": n, "threshold": p.head.to_json(),
            "known": {d.id: n}, "required": [d.id], "unverified": {d.id: n}}
    await set_marker(st, mark)
    check("R6-H2: local.n == unverified.n → not behind (numerically reached)", not er._behind())
    r = await c.post(f"/api/sessions/{rec}/recovery", json={"confirm": time.strftime("%Y-%m-%d", time.gmtime(1)),
                                                             "stepup_grant": grant(uid, host_id)})
    check("recover (audited Owner read) still works", r.status_code == 200
          and (await statuses())[(rec, "out")] == "recovery", r.text)
    r = await c.post(f"/api/sessions/{rec}/recovery/release", json={"stepup_grant": grant(uid, host_id)})
    check("R6-H2: recover → release with local.n == unverified.n → 409 transcript.releaseUnproven, stays in recovery",
          r.status_code == 409 and r.json().get("code") == "transcript.releaseUnproven"
          and (await statuses())[(rec, "out")] == "recovery"
          and (await c.get(f"/api/sessions/{rec}/transcript?format=out")).status_code == 423, r.text)
    check("R6-H2: …and try_prove keeps it while the destination still holds the damaged object",
          await er.try_prove(st) is False and er.continuity() is not None)
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": p.head.to_json(),
                          "unverified": {d.id: n}})
    check("R6-H2: a gap alone (not mandatory) also refuses release",
          await _erasure_code(er.release(st, rec)) == "transcript.releaseUnproven")
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": p.head.to_json(),
                          "overflow": True})
    check("R6-H2: an overflowed marker refuses release",
          await _erasure_code(er.release(st, rec)) == "transcript.releaseUnproven")
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": p.head.to_json()})
    er._s.conflict = "erasure journals at sftp:x diverge (test)"
    try:
        check("R6-H2: a fork seen (System health conflict) refuses release",
              await _erasure_code(er.release(st, rec)) == "transcript.releaseUnproven")
    finally:
        er._s.conflict = ""
    # retragerea auditată: destinaţia nu mai e configurată, golul devine cap cunoscut, obligaţia e închisă
    DESTS[:] = []
    await set_marker(st, mark)
    await er.retire_destination(st, d.id, audit_row={"ts": time.time(), "actor": "o@x.co", "path": "/t"})
    cont = er.continuity() or {}
    check("R6-H2: after the audited retire (gap → known head, no longer required) the release is allowed",
          "unverified" not in cont and "required" not in cont and cont.get("known", {}).get(d.id) == n
          and await er.release(st, rec) is not None and (await statuses())[(rec, "out")] == "ok"
          and await read_all(st, rec) == data, cont)
    await st.txn(lambda cu: cu.execute("DELETE FROM tx_state WHERE key='continuity'"))
    er._s.continuity = None
    await unquarantine_all()


async def g_r7h1_conflict(st, c, uid, host_id):
    print("== R7-H1: an authenticated fork stays a conflict when one branch vanishes ==")
    cur = journal_path().read_bytes()
    p = er.parse(cur, K, INST)
    n = p.n
    keep, data = await make_rec(st, host_id)
    victim, _ = await make_rec(st, host_id)
    await st.txn(lambda cu: er._quarantine_cohort_sync(cu, "continuity", time.time()))
    x = bytes([0x71] * 16)
    ja = _extend(cur, x)                                   # ramura A: şterge x
    jb = _extend(cur, bytes.fromhex(victim))               # ramura B: şterge o înregistrare prezentă aici
    jc = _extend(ja, bytes.fromhex(victim))                # C extinde A şi conţine ambele ştergeri
    d = FakeDest("sftp:u@h:22/r7h1")
    na, nb, nc = (er.object_name(INST, n + 1, "aaaa1111"), er.object_name(INST, n + 1, "bbbb2222"),
                  er.object_name(INST, n + 2, "cccc3333"))
    d.objs = {na: ja, nb: jb}
    DESTS[:] = [d]
    await set_marker(st, {"state": "unproven", "since": 1, "n": n, "threshold": p.head.to_json(),
                          "known": {d.id: n}, "required": [d.id]})
    ok = await er.try_prove(st)
    conf = (er.continuity() or {}).get("conflict") or {}
    row = await db.fetchone("SELECT value FROM tx_state WHERE key='continuity'")
    check("R7-H1: a fork at the destination → try_prove lifts nothing and RECORDS it (both heads, the common "
          "prefix, both erasures, the destination), in the database too",
          ok is False and len(conf.get("heads", [])) == 2 and conf.get("bases") == [p.head.to_json()]
          and {x.hex(), victim} <= set(conf.get("sids", [])) and conf.get("dests") == [d.id]
          and row is not None and json.loads(row["value"]).get("conflict") == conf, conf)

    async def rk(sid):
        return await db.fetchone("SELECT 1 FROM session_keys WHERE sid=?", sid) is not None

    async def intent(sid):
        return await db.fetchone("SELECT 1 FROM tx_erase_intents WHERE sid=?", sid) is not None
    check("R7-H1: the erasure seen on branch B is applied at once: tombstone, RK destroyed, durable intent",
          victim in st.tombstoned and not await rk(victim) and await intent(victim) and await rk(keep))
    del d.objs[nb]                                         # ramura cu ştergerea dispare din listing
    ok = await er.try_prove(st)
    check("R7-H1: branch B vanished from the listing → try_prove still does NOT lift (conflict kept), "
          "the other recordings stay quarantined",
          ok is False and er.conflict_open() and er.continuity() is not None
          and (await statuses())[(keep, "out")] == "quarantined")
    check("R7-H1: …the vanished branch's erasure still holds (tombstone, no RK, intent)",
          victim in st.tombstoned and not await rk(victim) and await intent(victim))
    r = await c.post(f"/api/sessions/{keep}/recovery", json={"confirm": time.strftime("%Y-%m-%d", time.gmtime(1)),
                                                              "stepup_grant": grant(uid, host_id)})
    check("R7-H1: Owner recovery refused while the conflict is recorded → 409 transcript.recoveryConflict",
          r.status_code == 409 and r.json().get("code") == "transcript.recoveryConflict"
          and (await statuses())[(keep, "out")] == "quarantined", r.text)
    check("R7-H1: release refused while the conflict is recorded (the fork's gap: behind)",
          await _erasure_code(er.release(st, keep)) == "transcript.releaseBehind")
    full = er._s.continuity
    er._s.continuity = {k_: v for k_, v in full.items() if k_ not in ("unverified", "required")}
    er._s.continuity["known"] = {d.id: n}
    er._s.conflict = ""
    try:
        check("R7-H1: …and with every other obligation gone, the recorded conflict alone (not the in-memory "
              "diagnosis) refuses release → transcript.releaseUnproven",
              not er._behind() and await _erasure_code(er.release(st, keep)) == "transcript.releaseUnproven")
    finally:
        er._s.continuity = full
    st = await reboot()
    check("R7-H1: after a restart the conflict is still recorded (System health critical), the erasure "
          "kept (tombstone from the intent, no RK), and try_prove still lifts nothing",
          er.conflict_open() and er.health_has("erasure_conflict") and victim in st.tombstoned
          and not await rk(victim) and await er.try_prove(st) is False and er.conflict_open())
    url = "/api/recordings/continuity/conflict/resolve"
    ha, hc = er.parse(ja, K, INST).head, er.parse(jc, K, INST).head

    def body(h, confirm=None):
        return {"n": h.n, "mac": h.mac.hex(), "confirm": confirm if confirm is not None
                else "%d %s" % (h.n, h.mac.hex()[:16]), "stepup_grant": grant(uid, 0)}
    r = await c.post(url, json=body(ha, confirm="%d" % ha.n))
    check("R7-H1: resolve with a wrong typed head → 400 transcript.conflictConfirm",
          r.status_code == 400 and r.json().get("code") == "transcript.conflictConfirm", r.text)
    security._stepup_windows.clear()
    r = await c.post(url, json=dict(body(ha), stepup_grant=""))
    check("R7-H1: resolve without a fresh factor → 403, conflict kept", r.status_code == 403 and er.conflict_open(),
          r.text)
    r = await c.post(url, json=body(ha))
    check("R7-H1: resolve adopting branch A (it lacks the erasure seen on B) → 409 "
          "transcript.conflictMissingTombstone, conflict kept, nothing adopted",
          r.status_code == 409 and r.json().get("code") == "transcript.conflictMissingTombstone"
          and er.conflict_open() and journal_path().read_bytes() == cur, r.text)
    r = await c.post(url, json=body(hc))
    check("R7-H1: a head no destination holds now → 409 transcript.conflictBranchUnknown",
          r.status_code == 409 and r.json().get("code") == "transcript.conflictBranchUnknown", r.text)
    d.objs[nb] = jb                                        # B din nou vizibil, plus C (superset)
    d.objs[nc] = jc
    r = await c.post(url, json=body(ha))
    check("R7-H1: A is not the newest head of its line any more (C extends it) → conflictBranchUnknown",
          r.status_code == 409 and r.json().get("code") == "transcript.conflictBranchUnknown", r.text)
    with _Mails() as mails:
        r = await c.post(url, json=body(hc))
        check("R7-H1: resolve adopting C (holds every erasure seen on any branch) → conflict cleared, C "
              "adopted, B rejected, and the proof that follows lifts the quarantine",
              r.status_code == 200 and r.json().get("lifted") is True and r.json().get("rejected") == 1
              and not er.conflict_open() and er.continuity() is None
              and journal_path().read_bytes() == jc and (await statuses())[(keep, "out")] == "ok"
              and (await c.get(f"/api/sessions/{keep}/transcript?format=out")).content == data, r.text)
        check("R7-H1: …the erasure is now journalled (intent cleared), the recording stays erased",
              victim in st.tombstoned and not await rk(victim) and not await intent(victim)
              and not er.health_has("erasure_conflict"))
        check("R7-H1: …security e-mail", any("conflict was resolved" in m for m in mails.sent), mails.sent)
    a = await db.fetchone("SELECT detail, actor FROM audit_log WHERE path=? AND detail LIKE '%durable record%'", url)
    check("R7-H1: …audited in the marker's transaction", a is not None and a["actor"] == "o@x.co"
          and "owner resolution" in a["detail"], a)
    r = await c.post(url, json=body(hc))
    check("R7-H1: nothing recorded any more → 404 transcript.conflictNone",
          r.status_code == 404 and r.json().get("code") == "transcript.conflictNone", r.text)
    # retragerea auditată a destinaţiei care a arătat fork-ul închide conflictul, păstrând ştergerile
    cur = journal_path().read_bytes()
    p = er.parse(cur, K, INST)
    victim2, _ = await make_rec(st, host_id)
    y = bytes([0x72] * 16)
    d2 = FakeDest("sftp:u@h:22/r7h1-gone")
    d2.objs = {er.object_name(INST, p.n + 1, "dddd4444"): _extend(cur, bytes.fromhex(victim2)),
               er.object_name(INST, p.n + 1, "eeee5555"): _extend(cur, y)}
    DESTS[:] = [d2]
    await set_marker(st, {"state": "unproven", "since": 1, "n": p.n, "threshold": p.head.to_json(),
                          "known": {d2.id: p.n}, "required": [d2.id]})
    check("R7-H1 (retire): the fork is recorded", await er.try_prove(st) is False and er.conflict_open())
    DESTS[:] = []
    r = await c.post("/api/recordings/continuity/destinations/%s/retire" % d2.id,
                     json={"confirm": d2.id, "stepup_grant": grant(uid, 0)})
    check("R7-H1 (retire): retiring the forking destination closes the conflict (System health clear, "
          "R7-L1), the quarantine stays, and both branches' erasures remain durable intents",
          r.status_code == 200 and not er.conflict_open() and not er.health_has("erasure_conflict")
          and er.continuity() is not None and await intent(victim2) and await intent(y.hex())
          and victim2 in st.tombstoned and not await rk(victim2), r.text)
    await db.execute("DELETE FROM tx_erase_intents WHERE sid IN (?, ?)", victim2, y.hex())
    await st.txn(lambda cu: cu.execute("DELETE FROM tx_state WHERE key='continuity'"))
    er._s.continuity = None
    DESTS[:] = []
    await unquarantine_all()
    return st


async def g_rh2(st, c, uid, host_id):
    print("== R-H2: boot with an invalid journal quarantines pending plaintext too ==")
    sid = os.urandom(16).hex()
    stray = os.urandom(16).hex()
    data = b"plain-" + sid.encode()
    await db.execute("INSERT INTO sessions(id, host_id, title, state, created, rows, cols, closed_at) "
                     "VALUES(?,?,?,?,?,?,?,?)", sid, host_id, "p", "closed", time.time(), 24, 80, time.time())
    Path(config.TRANSCRIPT_DIR, sid + ".out").write_bytes(data)
    await txhub.shutdown()
    # inventarul de text clar se reface la boot (un volum în timpul migrării)
    await db.execute("DELETE FROM tx_state WHERE key IN ('migration_inventory','recordings_format')")
    st = await reboot()
    m = await db.fetchone("SELECT state FROM tx_migration WHERE sid=? AND kind='out'", sid)
    check("baseline: a pending plaintext recording is readable on a healthy journal",
          m is not None and m["state"] == "pending" and await read_all(st, sid) == data, m)
    Path(config.TRANSCRIPT_DIR, stray + ".cast").write_bytes(b"stray")
    # înregistrări criptate pentru recuperarea strictă din carantina de jurnal (decizia 2026-11-26)
    jrec = [await make_rec(st, host_id) for _ in range(3)]
    good = journal_path().read_bytes()
    n = er.parse(good, K, INST).n
    journal_path().write_bytes(good[:er.prefix_len(n - 1)])
    st = await reboot()
    q = await db.fetchone("SELECT reason FROM tx_quarantine WHERE sid=? AND kind='out'", sid)
    qs = await db.fetchone("SELECT reason FROM tx_quarantine WHERE sid=? AND kind='cast'", stray)
    check("invalid journal at boot → the pending plaintext is in the cohort (journal:rollback), and a "
          "3.7-named file without a row too",
          er._s.diag == "rollback" and q is not None and q["reason"] == "journal:rollback"
          and qs is not None and qs["reason"] == "journal:rollback", (er._s.diag, q, qs))
    check("…the pending plaintext is not served", await _refused(read_all(st, sid)))
    check("…a writer does not reopen it", await _refused(st.start_recorder(sid, track_agent=False)))
    out = await migration.process(st, sid)
    s = await statuses()
    q = await db.fetchone("SELECT reason FROM tx_quarantine WHERE sid=? AND kind='out'", sid)
    check("migration converts it: the descriptor is born quarantined, the reason journal:* kept",
          s.get((sid, "out")) == "quarantined" and q is not None and q["reason"] == "journal:rollback"
          and out.get("out") in ("unlinked", "converted"), (out, s.get((sid, "out")), q))
    check("…the plaintext is gone after the verified conversion (hash-only re-check allowed)",
          not Path(config.TRANSCRIPT_DIR, sid + ".out").exists() and out.get("out") == "unlinked", out)
    check("…still not served after migration", await _refused(read_all(st, sid)))
    check("…and the continuity recovery never opens a journal quarantine",
          await _erasure_code(er.recover(st, sid)) == "transcript.notRecoverable")
    await g_journal_recovery(st, c, uid, host_id, jrec, good)
    journal_path().write_bytes(good)
    st = await reboot()
    check("journal repaired: the journal quarantine stays (not lifted by a later clean boot)",
          not er._s.diag and (await statuses()).get((sid, "out")) == "quarantined"
          and await _refused(read_all(st, sid)))
    r = await c.post(f"/api/sessions/{sid}/recovery", json={"confirm": sid[:8] + " rollback",
                                                           "stepup_grant": grant(uid, host_id)})
    check("journal repaired: System health no longer shows the diagnosis → journal recovery refused "
          "(409 transcript.journalNotDiagnosed)",
          r.status_code == 409 and r.json().get("code") == "transcript.journalNotDiagnosed", r.text)
    os.unlink(os.path.join(config.TRANSCRIPT_DIR, stray + ".cast"))
    return st


def _extend(journal, sid, t_ms=7000):
    """`journal` + one authentic entry (another host of the same dataset erasing `sid`)."""
    p = er.parse(journal, K, INST)
    return journal + er.encode_entry(K, INST, p.head.mac, p.n + 1, t_ms, sid, 3, bytes(32))


async def g_r4_fetch():
    print("== R4-H1/R4-H2: what a destination's listing proves ==")
    j3 = build([(1000 + i, s, 3, bytes(32)) for i, s in enumerate(sids(3))])
    j2 = j3[:er.prefix_len(2)]
    bad4 = _extend(j3, bytes([0x44] * 16))
    bad4 = bad4[:-1] + bytes([bad4[-1] ^ 1])            # MAC stricat pe intrarea n=4

    async def one(objs, check_from=None):
        d = FakeDest("sftp:u@h:22/r4")
        d.objs = dict(objs)
        return (await er.fetch_all([d], K, INST, check_from))[0]
    for cf in (None, 0, 2):
        tag = "check_from=%s" % cf
        r = await one({}, cf)
        check(f"[{tag}] an empty listing: answered, no journal (not a proof)", r.ok and r.parsed is None, r)
        r = await one({er.object_name(INST, 0): er.header(INST)}, cf)
        check(f"[{tag}] R4-H1: a header-only object (n=0, no MAC) is never a journal", r.ok and r.parsed is None, r)
        r = await one({er.object_name(INST, 2): er.header(INST)}, cf)
        check(f"[{tag}] R4-H1: a header-only object named n=2 → unverifiable, the destination proves nothing",
              not r.ok and r.error == "unverifiable" and r.parsed is None, r)
        r = await one({er.object_name(INST, 2): j2, er.object_name(INST, 4): bad4}, cf)
        check(f"[{tag}] R4-H2: authentic n=2 + a newer damaged n=4 → unverifiable, never the older journal",
              not r.ok and r.error == "unverifiable" and r.parsed is None and r.unverified == 4, r)
        r = await one({er.object_name(INST, 2): j2, er.object_name(INST, 3): b"junk"}, cf)
        check(f"[{tag}] R4-H2: authentic n=2 + a newer object with a bad header → unverifiable",
              not r.ok and r.error == "unverifiable", r)
        r = await one({er.object_name(INST, 2): j2, er.object_name(INST, 3): j2}, cf)
        check(f"[{tag}] R4-H2: authentic n=2 + an object named n=3 holding n=2 (lying name) → unverifiable",
              not r.ok and r.error == "unverifiable", r)
        r = await one({er.object_name(INST, 3): j3, er.object_name(INST, 2): b"junk"}, cf)
        check(f"[{tag}] an older damaged object below an authentic n=3 is covered → n=3 proves",
              r.ok and r.parsed is not None and r.parsed.n == 3, r)
        r = await one({er.object_name(INST, 3, "aa11bb22"): j3, er.object_name(INST, 3, "cc33dd44"): j3[:-1] + bytes([j3[-1] ^ 1])}, cf)
        # R5-M1: egalitatea numerică nu e acelaşi lanţ — o variantă defectă la acelaşi n e un gol
        check(f"[{tag}] R5-M1: a damaged copy at the SAME n as an authentic one is a gap → unverifiable",
              not r.ok and r.error == "unverifiable" and r.unverified == 3, r)
        j3b = _extend(j2, bytes([0x77] * 16))           # altă ramură la n=3
        r = await one({er.object_name(INST, 3, "aa11bb22"): j3, er.object_name(INST, 3, "cc33dd44"): j3b}, cf)
        check(f"[{tag}] R5-M1: two authentic objects at the same n on different branches → conflict",
              not r.ok and r.error == "conflict", r)
        r = await one({er.object_name(INST, 3, "cc33dd44"): j3b, er.object_name(INST, 3, "aa11bb22"): j3}, cf)
        check(f"[{tag}] R5-M1: …whichever variant sorts first", not r.ok and r.error == "conflict", r)
        j4 = _extend(j3, bytes([0x44] * 16))
        torn = j3b + b"\x00" * 40                        # prefix autentic (altă ramură) + coadă stricată
        r = await one({er.object_name(INST, 4): j4, er.object_name(INST, 4, "dd44ee55"): torn}, cf)
        check(f"[{tag}] R5-M1: a damaged object whose authentic prefix is on another branch, next to a "
              "full journal of that n → conflict, never covered", not r.ok and r.error == "conflict", r)
        r = await one({er.object_name(INST, 4): j4, er.object_name(INST, 2, "dd44ee55"): j3b[:er.prefix_len(2)] + b"zz"}, cf)
        check(f"[{tag}] R5-M1: a damaged older object whose authentic prefix is on the chain → covered (n=4)",
              r.ok and r.parsed is not None and r.parsed.n == 4, r)
        many = {er.object_name(INST, 3, "%08x" % i): j3 for i in range(er.FETCH_MAX_OBJECTS + 1)}
        many.update({er.object_name(INST, 2): j2})
        r = await one(many, cf)
        if cf is None or cf >= 3:
            check(f"[{tag}] R5-M1: more variants of the head than the budget reads → a gap (unverifiable n=3)",
                  not r.ok and r.error == "unverifiable" and r.unverified == 3, r)
        else:
            check(f"[{tag}] R5-M1: every variant above the restore is read → identical copies prove n=3",
                  r.ok and r.parsed is not None and r.parsed.n == 3, r)
    # decide_restore: o destinaţie cu parsed n=0 (chiar dacă cineva o construieşte) nu dovedeşte
    p0 = er.parse(er.header(INST), K, INST)
    dec = er.decide_restore(k_erase=K, inst=INST, tracked=True,
                            dest_results=[er.DestResult("sftp:u@h:22/r4", True, p0, er.header(INST))],
                            required_dests={"sftp:u@h:22/r4"}, mode="prove")
    check("R4-H1: restore decision with a zero-entry destination journal → not proven",
          dec.proof == "none" and dec.state == "unproven", dec)
    dec = er.decide_restore(k_erase=K, inst=INST, tracked=True,
                            dest_results=[er.DestResult("sftp:u@h:22/r4", False, error="unverifiable", unverified=4)],
                            required_dests={"sftp:u@h:22/r4"}, mode="prove")
    check("R4-H2: restore decision with an unverifiable newer object → not proven",
          dec.proof == "none", dec)


async def _until_waiting(task, rounds=50):
    for _ in range(rounds):
        await asyncio.sleep(0.01)
        if task.done():
            return False
    return True


async def g_prove_race(st, host_id):
    print("== H3: proof later, under the barrier, against concurrent erasures ==")
    d = FakeDest("sftp:u@h:22/race")
    DESTS[:] = [d]
    cur = journal_path().read_bytes()
    n0 = er.parse(cur, K, INST).n
    x = bytes([0x42] * 16)
    old = _extend(cur, x)                              # gazda veche a şters x după restore-ul nostru
    d.objs[er.object_name(INST, n0 + 1)] = old
    rec, _ = await make_rec(st, host_id)
    await st.txn(lambda c: er._quarantine_cohort_sync(c, "continuity", time.time()))
    await set_marker(st, {"state": "unproven", "since": 1, "n": n0, "known": {d.id: n0 + 1}})
    async with st.barrier:
        task = asyncio.ensure_future(er.try_prove(st))
        waiting = await _until_waiting(task)
    ok = await task
    check("barrier busy: try_prove waits for it, then adopts the destination's longer chain",
          waiting and ok and journal_path().read_bytes() == old and x.hex() in st.tombstoned
          and er.continuity() is None and er._s.head_db.n == n0 + 1
          and (await head_db())["n"] == n0 + 1 and (await statuses())[(rec, "out")] == "ok")
    # ştergere concurentă ÎNAINTE de adoptare: ramura destinaţiei nu o conţine → fork, nimic adoptat
    cur = journal_path().read_bytes()
    n1 = er.parse(cur, K, INST).n
    y = bytes([0x43] * 16)
    d.objs[er.object_name(INST, n1 + 1)] = _extend(cur, y)
    victim, _ = await make_rec(st, host_id)
    await st.txn(lambda c: er._quarantine_cohort_sync(c, "continuity", time.time()))
    # R-M1: ce ştia restore-ul (n1) e atins local, deci ştergerea e permisă; ramura n1+1 a
    # destinaţiei apare abia după (o ştergere a gazdei vechi)
    await set_marker(st, {"state": "unproven", "since": 1, "n": n1, "known": {d.id: n1}})
    async with st.barrier:
        erase_t = asyncio.ensure_future(er.erase(st, victim))
        e_wait = await _until_waiting(erase_t)
        prove_t = asyncio.ensure_future(er.try_prove(st))
        p_wait = await _until_waiting(prove_t)
    res = await erase_t
    ok = await prove_t
    after = er.parse(journal_path().read_bytes(), K, INST)
    check("concurrent erasure first, then try_prove: fork detected under the barrier → nothing adopted",
          e_wait and p_wait and res["erased"] and ok is False and after.n == n1 + 1
          and after.entries[-1].sid_hex == victim, (ok, after.n))
    conf = (er.continuity() or {}).get("conflict") or {}
    check("…the local tombstone survives, the quarantine stays, the conflict is reported and RECORDED "
          "(R7-H1: both branch heads, both erasures; the other branch's erasure applied: intent + tombstone)",
          victim in st.tombstoned and er.continuity() is not None and er.health_has("erasure_conflict")
          and len(conf.get("heads", [])) == 2 and {victim, y.hex()} <= set(conf.get("sids", []))
          and y.hex() in st.tombstoned
          and await db.fetchone("SELECT 1 FROM tx_erase_intents WHERE sid=?", y.hex()) is not None, conf)
    check("erase answers `destroyed` once the DB step committed (not just journalled)", res.get("state") == "destroyed")
    er._s.conflict = ""
    await db.execute("DELETE FROM tx_erase_intents WHERE sid=?", y.hex())
    await st.txn(lambda c: c.execute("DELETE FROM tx_state WHERE key='continuity'"))
    er._s.continuity = None
    await unquarantine_all()
    # M1: un obiect atestat care a dispărut între timp se încarcă din nou
    d2 = FakeDest("sftp:u@h:22/vanish")
    DESTS[:] = [d2]
    await er.attest_once(st)
    name = er._s.attested[d2.id]["name"]
    del d2.objs[name]
    er._s.dests[d2.id]["verified"] = 0
    out = await er.attest_once(st)
    check("M1: the attested object vanished → re-checked hourly, uploaded again, attested",
          out[d2.id] == "ok" and name in d2.objs and er._s.dests[d2.id]["state"] == "ok")
    puts = d2.puts
    er._s.dests[d2.id]["verified"] = 0
    d2.fail = True
    out = await er.attest_once(st)
    check("…an unreachable destination at the re-check keeps its state (no false alarm, no re-upload)",
          out[d2.id] == "ok" and d2.puts == puts)
    d2.fail = False
    DESTS[:] = []


# ── main ─────────────────────────────────────────────────────────────────────


# ── 11. Owner decisions 2026-11-26: journal recovery, retiring a gone destination ──


class _Mails:
    def __init__(self):
        self.sent = []
        self._orig = None

    def __enter__(self):
        from app import email_alerts
        self._mod = email_alerts
        self._orig = email_alerts.notify_security_change
        email_alerts.notify_security_change = lambda what, *a, **kw: self.sent.append(what)
        return self

    def __exit__(self, *exc):
        self._mod.notify_security_change = self._orig


async def g_journal_recovery(st, c, uid, host_id, jrec, good):
    print("== Owner recovery of a journal:* quarantine (strict) ==")
    (ok_sid, ok_data), (tomb, _), (nokey, _) = jrec
    s = await statuses()
    reasons = [await er.quarantine_reasons(st, x) for x, _ in jrec]
    check("baseline: the encrypted recordings are in the journal:rollback cohort",
          all(s.get((x, "out")) == "quarantined" for x, _ in jrec)
          and all(r == {"journal:rollback"} for r in reasons)
          and er.health_has("erasure_journal_broken") and er.journal_diag() == "rollback")
    # un RK distrus (ştergere comisă în DB, jurnalul care o arăta pierdut) şi un sid tombstone
    await db.execute("DELETE FROM session_keys WHERE sid=?", nokey)
    st.tombstoned.add(tomb)
    r = await c.get("/api/recordings/quarantine")
    items = {i["sid"]: i for i in r.json().get("items", [])} if r.status_code == 200 else {}
    check("list: journal recovery offered with the System health word, never for a sid without its key "
          "or tombstoned", items.get(ok_sid, {}).get("recoverable") is True
          and items[ok_sid].get("recovery") == "journal" and items[ok_sid].get("confirm_word") == "rollback"
          and items.get(nokey, {}).get("recoverable") is False and items.get(tomb, {}).get("recoverable") is False
          and r.json().get("journal_diag") == "rollback", r.text[:400])
    url = f"/api/sessions/{ok_sid}/recovery"
    for bad in (ok_sid[:8], "rollback", ok_sid[:8] + " fork", "2000-01-01"):
        r = await c.post(url, json={"confirm": bad, "stepup_grant": grant(uid, host_id)})
        check("wrong typed confirmation %r → 400 transcript.journalRecoveryConfirm" % bad,
              r.status_code == 400 and r.json().get("code") == "transcript.journalRecoveryConfirm", r.text)
    security._stepup_windows.clear()
    r = await c.post(url, json={"confirm": ok_sid[:8] + " rollback"})
    check("no fresh factor → 403, still quarantined",
          r.status_code == 403 and (await statuses())[(ok_sid, "out")] == "quarantined", r.text)
    # R2-H1 (c): jurnalul local (n-1) e sub capul comis (n); fără o sursă care să-l acopere → refuz
    n = er.parse(good, K, INST).n

    async def code_now():
        r = await c.post(url, json={"confirm": ok_sid[:8] + " rollback", "stepup_grant": grant(uid, host_id)})
        return r.status_code, r.json().get("code")
    DESTS[:] = []
    check("R3-H1: no destination configured → 409 transcript.recoveryNoDestination (never a success)",
          await code_now() == (409, "transcript.recoveryNoDestination")
          and (await statuses())[(ok_sid, "out")] == "quarantined")
    d = FakeDest("sftp:u@h:22/jr")
    d.objs[er.object_name(INST, n)] = good
    d.fail = True
    DESTS[:] = [d]
    check("R3-H1: the destination that would cover it unreachable → 409 transcript.recoveryUnreachable",
          await code_now() == (409, "transcript.recoveryUnreachable"))
    d.fail = False
    d.objs = {}
    check("R3-H1: the destination answers with no journal at all → 409 transcript.recoveryNoJournal",
          await code_now() == (409, "transcript.recoveryNoJournal"))
    saved_provider = er._dest_provider

    async def broken():
        raise OSError("settings unreadable")
    er.set_destinations(broken)
    check("R3-H1: the destination configuration cannot be read → recoveryUnreachable (not \"none configured\")",
          await _erasure_code(er.recover_journal(st, ok_sid, "rollback")) == "transcript.recoveryUnreachable")
    er.set_destinations(saved_provider)
    d2 = FakeDest("ftps:u@h:21/jr2")
    d2.objs[er.object_name(INST, n)] = good
    d.objs = {er.object_name(INST, n): good}
    d2.fail = True
    DESTS[:] = [d, d2]
    check("R3-H1: one destination proves, another configured one is down (it may hold the tombstone) → "
          "recoveryUnreachable", await code_now() == (409, "transcript.recoveryUnreachable"))
    DESTS[:] = [d]
    # R3-H1: ramurile care înainte reuşeau fără nicio dovadă off-host
    s0 = er._s
    saved = (s0.head_db, s0.attested, s0.damaged, s0.continuity)
    try:
        s0.head_db, s0.attested = s0.damaged.head, {}
        DESTS[:] = []
        check("R3-H1: the readable local prefix covers the committed head, but no destination → still "
              "refused (recoveryNoDestination)", await _erasure_code(er.recover_journal(st, ok_sid, "rollback"))
              == "transcript.recoveryNoDestination")
        s0.head_db, s0.damaged = er.EMPTY_HEAD, None
        check("R3-H1: nothing committed or attested anywhere (n=0), no destination → refused",
              await _erasure_code(er.recover_journal(st, ok_sid, "rollback")) == "transcript.recoveryNoDestination")
        DESTS[:] = [FakeDest("sftp:u@h:22/empty")]
        check("R3-H1: n=0 and an empty destination → refused (recoveryNoJournal)",
              await _erasure_code(er.recover_journal(st, ok_sid, "rollback")) == "transcript.recoveryNoJournal")
        dz = FakeDest("sftp:u@h:22/header-only")
        dz.objs[er.object_name(INST, 0)] = er.header(INST)
        DESTS[:] = [dz]
        check("R4-H1: n=0 and a destination holding a header-only object (no MAC) → recoveryNoJournal, "
              "still quarantined", await _erasure_code(er.recover_journal(st, ok_sid, "rollback"))
              == "transcript.recoveryNoJournal" and (await statuses())[(ok_sid, "out")] == "quarantined")
        dz.objs = {er.object_name(INST, 1): er.header(INST)}
        check("R4-H1: a header-only object named n=1 → recoveryGap (an object that cannot be authenticated)",
              await _erasure_code(er.recover_journal(st, ok_sid, "rollback")) == "transcript.recoveryGap"
              and (await statuses())[(ok_sid, "out")] == "quarantined")
        # R3-H2: o ramură autentică a destinaţiei care se desparte de prefixul local lizibil
        s0.damaged = er.parse(good[:er.prefix_len(n - 1)], K, INST)
        other = build([(9000 + i, bytes([0x90 + i] * 16), 3, bytes(32)) for i in range(n)])
        df = FakeDest("sftp:u@h:22/fork")
        df.objs[er.object_name(INST, n)] = other
        DESTS[:] = [df]
        snap = await _conflict_snap()
        check("R3-H2: the only destination's chain diverges from the readable local prefix (head n=0) → "
              "recoveryConflict, signalled", await _erasure_code(er.recover_journal(st, ok_sid, "rollback"))
              == "transcript.recoveryConflict" and er.health_has("erasure_conflict"))
        check("R7-H1: …the fork seen by a journal recovery is recorded durably (a marker created for it)",
              er.conflict_open() and (await db.fetchone("SELECT 1 FROM tx_state WHERE key='continuity' AND "
                                                         "value LIKE '%\"conflict\"%'")) is not None)
        check("R7-H1: …and while it is recorded every later recovery attempt is refused the same way",
              await _erasure_code(er.recover_journal(st, ok_sid, "rollback")) == "transcript.recoveryConflict")
        await _forget_conflict(st, snap)
        # R3-H2: capul DB n, pragul markerului n+1 cu MAC A (ramura care ŞTERGE ok_sid, nevăzută aici);
        # singura destinaţie extinde n cu o intrare n+1 diferită (MAC B), fără ok_sid
        s0.head_db = er.parse(good, K, INST).head
        branch_a = _extend(good, bytes.fromhex(ok_sid))
        branch_b = _extend(good, bytes([0x31] * 16))
        s0.continuity = {"state": "unproven", "since": 1, "n": n,
                         "threshold": er.parse(branch_a, K, INST).head.to_json(), "known": {}}
        db_ = FakeDest("sftp:u@h:22/branch-b")
        db_.objs[er.object_name(INST, n + 1)] = branch_b
        DESTS[:] = [db_]
        snap = await _conflict_snap()
        check("R3-H2: a destination reaching the threshold's NUMBER with another MAC never proves → "
              "recoveryConflict", await _erasure_code(er.recover_journal(st, ok_sid, "rollback"))
              == "transcript.recoveryConflict" and (await statuses())[(ok_sid, "out")] == "quarantined")
        await _forget_conflict(st, snap)
        db_.objs = {er.object_name(INST, n): good}
        check("R3-H2: a destination below the marker's threshold → recoveryGap",
              await _erasure_code(er.recover_journal(st, ok_sid, "rollback")) == "transcript.recoveryGap")
        s0.continuity = dict(s0.continuity, overflow=True)
        db_.objs = {er.object_name(INST, n + 1): branch_a[:er.prefix_len(n)] + branch_b[er.prefix_len(n):]}
        check("R3-H2: a marker whose known heads overflowed → no proof (recoveryGap)",
              await _erasure_code(er.recover_journal(st, ok_sid, "rollback")) == "transcript.recoveryGap")
        s0.continuity = {"state": "unproven", "since": 1, "n": n, "threshold": s0.head_db.to_json(),
                         "known": {}, "required": ["sftp:u@h:22/gone-required"]}
        db_.objs = {er.object_name(INST, n): good}
        check("R3-H1: a destination the restore made mandatory is not configured any more → recoveryUnreachable",
              await _erasure_code(er.recover_journal(st, ok_sid, "rollback")) == "transcript.recoveryUnreachable")
    finally:
        s0.head_db, s0.attested, s0.damaged, s0.continuity = saved
        er._s.conflict = ""
    DESTS[:] = [d]
    d.objs = {er.object_name(INST, n - 1): good[:er.prefix_len(n - 1)]}
    check("…a destination holding only n-1 → still recoveryGap", await code_now() == (409, "transcript.recoveryGap"))
    # (b) un tombstone autentic al sid-ului pe o destinaţie (o ştergere pe care jurnalul local a pierdut-o)
    d.objs = {er.object_name(INST, n + 1): _extend(good, bytes.fromhex(ok_sid))}
    check("an authentic off-host tombstone of the sid → 409 transcript.recoveryTombstoned",
          await code_now() == (409, "transcript.recoveryTombstoned")
          and (await statuses())[(ok_sid, "out")] == "quarantined")
    # R4-H2: A dovedeşte capul n; B are acelaşi n autentic, dar şi un obiect n+1 neverificabil (poate fi
    # tocmai tombstone-ul lui ok_sid): nu se coboară tăcut la copia mai veche
    newer = _extend(good, bytes.fromhex(ok_sid))
    newer = newer[:-1] + bytes([newer[-1] ^ 1])
    d.objs = {er.object_name(INST, n): good}
    d3 = FakeDest("ftps:u@h:21/damaged-newer")
    d3.objs = {er.object_name(INST, n): good, er.object_name(INST, n + 1): newer}
    DESTS[:] = [d, d3]
    check("R4-H2: one destination proves n, another holds a newer object that cannot be authenticated → "
          "409 transcript.recoveryGap, still quarantined", await code_now() == (409, "transcript.recoveryGap")
          and (await statuses())[(ok_sid, "out")] == "quarantined")
    DESTS[:] = [d3]
    check("R4-H2: the same on a single destination → recoveryGap",
          await code_now() == (409, "transcript.recoveryGap"))
    DESTS[:] = [d]
    fork = good[:er.prefix_len(n - 1)]
    fork = _extend(fork, bytes([0x77] * 16))
    d2 = FakeDest("ftps:u@h:21/jr")
    d2.objs[er.object_name(INST, n)] = fork
    DESTS[:] = [d, d2]
    snap = await _conflict_snap()
    check("two destination journals that diverge → 409 transcript.recoveryConflict, signalled",
          await code_now() == (409, "transcript.recoveryConflict") and er.health_has("erasure_conflict"))
    await _forget_conflict(st, snap)
    DESTS[:] = [d]
    # un obiect mai VECHI stricat sub capul autentic e acoperit: nu blochează recuperarea
    d.objs[er.object_name(INST, n - 1)] = b"junk"
    with _Mails() as mails:
        r = await c.post(f"/api/sessions/{tomb}/recovery",
                         json={"confirm": tomb[:8] + " rollback", "stepup_grant": grant(uid, host_id)})
        check("a tombstoned sid is never recovered → 404 transcript.missing",
              r.status_code == 404 and r.json().get("code") == "transcript.missing"
              and (await statuses())[(tomb, "out")] == "quarantined", r.text)
        r = await c.post(f"/api/sessions/{nokey}/recovery",
                         json={"confirm": nokey[:8] + " rollback", "stepup_grant": grant(uid, host_id)})
        check("a sid whose RK was destroyed is never recovered → 409 transcript.recoveryNoKey",
              r.status_code == 409 and r.json().get("code") == "transcript.recoveryNoKey"
              and (await statuses())[(nokey, "out")] == "quarantined", r.text)
        check("…and neither refusal sends a security e-mail", mails.sent == [], mails.sent)
        r = await c.post(url, json={"confirm": "  %s   rollback " % ok_sid[:8], "stepup_grant": grant(uid, host_id)})
        check("typed sid + diagnosis, Owner, real fresh factor → recovery (one recording)",
              r.status_code == 200 and r.json().get("reason") == "journal:rollback"
              and (await statuses())[(ok_sid, "out")] == "recovery", r.text)
        check("…with a security e-mail", any("damaged erasure journal" in m for m in mails.sent), mails.sent)
    a = await db.fetchone("SELECT detail FROM audit_log WHERE path=? AND method='POST' ORDER BY id DESC", url)
    check("…audited with the diagnosis", a is not None and "damaged erasure journal (rollback)" in (a["detail"] or ""), a)
    others = await statuses()
    check("…only that recording changed", others[(tomb, "out")] == "quarantined"
          and others[(nokey, "out")] == "quarantined")
    r = await c.get(f"/api/sessions/{ok_sid}/transcript?format=out")
    check("normal read still refused (423)", r.status_code == 423, r.status_code)
    r = await c.get(f"/api/sessions/{ok_sid}/recovery/transcript?format=out")
    check("the audited Owner recovery read → the recording", r.status_code == 200 and r.content == ok_data,
          r.status_code)
    r = await c.post(f"/api/sessions/{ok_sid}/recovery/release", json={"stepup_grant": grant(uid, host_id)})
    check("release of a journal-recovered recording → 409 transcript.releaseJournal (stays in recovery)",
          r.status_code == 409 and r.json().get("code") == "transcript.releaseJournal"
          and (await statuses())[(ok_sid, "out")] == "recovery", r.text)
    r = await c.post(f"/api/sessions/{ok_sid}/recovery/requarantine")
    check("re-quarantine → quarantined, the journal reason kept",
          r.status_code == 200 and (await statuses())[(ok_sid, "out")] == "quarantined"
          and (await er.quarantine_reasons(st, ok_sid)) == {"journal:rollback"}, r.text)
    check("the module refuses a diagnosis System health does not show",
          await _erasure_code(er.recover_journal(st, ok_sid, "fork")) == "transcript.journalNotDiagnosed")
    st.tombstoned.discard(tomb)
    DESTS[:] = []


async def g_retire(st, c, uid, host_id):
    print("== Owner override: retire a mandatory destination that is gone ==")
    cur = journal_path().read_bytes()
    p = er.parse(cur, K, INST)
    n, head = p.n, p.head
    rec, data = await make_rec(st, host_id)
    await st.txn(lambda cu: er._quarantine_cohort_sync(cu, "continuity", time.time()))
    d = FakeDest("sftp:u@h:22/keep")
    d.objs[er.object_name(INST, n)] = cur
    DESTS[:] = [d]
    gone = "sftp:u@h:22/old/gone"
    base = {"state": "unproven", "since": 1, "n": n, "threshold": head.to_json(), "known": {d.id: n}}
    await set_marker(st, dict(base, required=sorted([d.id, gone])))
    check("baseline: the gone mandatory destination blocks the proof",
          await er.try_prove(st) is False and er.continuity() is not None)
    url = "/api/recordings/continuity/destinations/%s/retire" % gone
    r = await c.post(url, json={"confirm": "gone", "stepup_grant": grant(uid, 0)})
    check("wrong typed destination name → 400 transcript.retireConfirm",
          r.status_code == 400 and r.json().get("code") == "transcript.retireConfirm", r.text)
    security._stepup_windows.clear()
    r = await c.post(url, json={"confirm": gone})
    check("no fresh factor → 403, marker unchanged",
          r.status_code == 403 and gone in er.continuity().get("required", []), r.text)
    r = await c.post("/api/recordings/continuity/destinations/%s/retire" % d.id,
                     json={"confirm": d.id, "stepup_grant": grant(uid, 0)})
    check("a destination still configured (and reachable) → 409 transcript.destinationConfigured",
          r.status_code == 409 and r.json().get("code") == "transcript.destinationConfigured"
          and d.id in er.continuity().get("required", []), r.text)
    r = await c.post("/api/recordings/continuity/destinations/sftp:x@y:22/none/retire",
                     json={"confirm": "sftp:x@y:22/none", "stepup_grant": grant(uid, 0)})
    check("a destination the marker does not require → 404 transcript.destinationUnknown",
          r.status_code == 404 and r.json().get("code") == "transcript.destinationUnknown", r.text)
    # capul cunoscut al destinaţiei retrase rămâne o obligaţie (nicio ştergere ştiută nu se uită)
    await set_marker(st, dict(base, required=sorted([d.id, gone]), known={d.id: n, gone: n + 1}))
    with _Mails() as mails:
        r = await c.post(url, json={"confirm": gone, "stepup_grant": grant(uid, 0)})
        check("retire a gone destination known to hold a HIGHER head → retired, quarantine kept",
              r.status_code == 200 and r.json().get("lifted") is False and er.continuity() is not None
              and gone not in er.continuity().get("required", [])
              and (await statuses())[(rec, "out")] == "quarantined", r.text)
        await set_marker(st, dict(base, required=sorted([d.id, gone])))
        r = await c.post(url, json={"confirm": gone, "stepup_grant": grant(uid, 0)})
        check("retire the gone destination → the remaining one reaches the threshold → quarantine lifted",
              r.status_code == 200 and r.json().get("lifted") is True and er.continuity() is None
              and (await statuses())[(rec, "out")] == "ok"
              and (await c.get(f"/api/sessions/{rec}/transcript?format=out")).content == data, r.text)
        check("…each retire sent a security e-mail", len([m for m in mails.sent if "retired" in m]) == 2, mails.sent)
    a = await db.fetchone("SELECT detail FROM audit_log WHERE path=? AND method='POST' ORDER BY id DESC", url)
    check("…audited", a is not None and "retired from the continuity proof" in (a["detail"] or "")
          and "lifted" in a["detail"], a)
    rows = await db.fetchall("SELECT detail, actor FROM audit_log WHERE path=? AND detail LIKE '%durable record%' "
                             "ORDER BY id", url)
    check("R2-M1: each retirement also has a durable audit row written with the marker (actor, known head)",
          len(rows) == 2 and "known head %d" % (n + 1) in rows[0]["detail"] and rows[0]["actor"] == "o@x.co",
          [dict(r) for r in rows])
    check("…and the marker is gone from the database too",
          await db.fetchone("SELECT 1 FROM tx_state WHERE key='continuity'") is None)
    r = await c.post(url, json={"confirm": gone, "stepup_grant": grant(uid, 0)})
    check("no unproven restore any more → 404 transcript.destinationUnknown",
          r.status_code == 404 and r.json().get("code") == "transcript.destinationUnknown", r.text)
    # R2-M1: o cădere / anulare după COMMIT (înainte de try_prove şi de auditul cererii) lasă urma
    await set_marker(st, dict(base, required=sorted([d.id, gone])))
    row = {"ts": time.time(), "actor": "o@x.co", "actor_id": uid, "ip": "127.0.0.1", "path": "/x/direct"}
    refused = 0
    for bad in (None, {}):
        try:
            await er.retire_destination(st, gone, audit_row=bad)
        except ValueError:
            refused += 1
    check("recheck: a retirement without the request's audit row is refused before anything changes",
          refused == 2 and gone in er.continuity().get("required", []))
    await er.retire_destination(st, gone, audit_row=row)
    a = await db.fetchone("SELECT detail FROM audit_log WHERE path='/x/direct'")
    check("R2-M1: the retirement and its audit row commit together (nothing after the COMMIT is needed)",
          gone not in er.continuity().get("required", []) and a is not None and gone in a["detail"], a)
    # o reconfigurare cât retragerea aşteaptă bariera: verificarea se reface la COMMIT
    await set_marker(st, dict(base, required=sorted([d.id, gone])))
    await st.barrier.acquire()
    task = asyncio.ensure_future(er.retire_destination(st, gone, audit_row=dict(row, path="/x/race")))
    waiting = await _until_waiting(task)
    for k, v in (("cloud_provider", "sftp"), ("cloud_user", "u"), ("cloud_host", "h"), ("cloud_port", "22"),
                 ("cloud_path", "old/gone")):
        await db.execute("INSERT OR REPLACE INTO app_settings(key, value) VALUES(?,?)", k, v)
    st.barrier.release()
    code = await _erasure_code(task)
    check("R2-M1: the destination configured while the retirement waited for the barrier → refused at "
          "COMMIT (transcript.destinationConfigured), marker and audit unchanged",
          waiting and code == "transcript.destinationConfigured" and gone in er.continuity().get("required", [])
          and await db.fetchone("SELECT 1 FROM audit_log WHERE path='/x/race'") is None, code)
    await db.execute("DELETE FROM app_settings WHERE key LIKE 'cloud_%'")
    await st.txn(lambda cu: cu.execute("DELETE FROM tx_state WHERE key='continuity'"))
    er._s.continuity = None
    DESTS[:] = []
    await unquarantine_all()


async def main():
    g_codec()
    g_freshness()
    g_backup_restore()
    g_h1_restore()
    g_recheck_pure()
    g_rh1_consecutive()
    g_r2m2_restore()
    g_r5h1_restore()
    g_r6h1_restore()
    g_live_bad_restore()
    await g_r4_fetch()
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    try:
        ts.create_test_volume(config.DB_PATH)
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", timeout=30,
                              headers=ORIGIN)
        r = await c.post("/api/setup", json={"email": "o@x.co", "password": "parolabuna1",
                                             "setup_token": "test-setup"})
        assert r.status_code == 200, r.text
        uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]
        host_id = (await c.post("/api/hosts", json={"name": "h1"})).json()["id"]
        st, _live = await g_boot_and_route(c, uid, host_id)
        st = await g_crash(st, host_id)
        st = await g_intents(st, host_id)
        st = await g_cancel(st, host_id)
        st, keep = await g_diagnostics(st, host_id)
        await g_cap(st, host_id)
        await g_attest(st, host_id)
        DESTS[:] = []
        st = await g_recovery(st, c, uid, host_id, keep)
        await g_prove_race(st, host_id)
        await g_behind(st, host_id)
        await g_retire(st, c, uid, host_id)
        await g_r5h1_prove(st)
        await g_r6h2_release(st, c, uid, host_id)
        st = await g_r7h1_conflict(st, c, uid, host_id)
        st = await g_rh2(st, c, uid, host_id)
    finally:
        await txhub.shutdown()
        await db.close()


asyncio.run(main())
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
shutil.rmtree(BASE, ignore_errors=True)
sys.exit(1 if failed else 0)
