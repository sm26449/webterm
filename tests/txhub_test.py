"""txhub (ENCRYPTION-AT-REST.md §12.11, PR5b): encrypted recordings wired into the hub and the routes.

Groups:
  * boot decision (§12.11 PR5/PR6 boundary): flag off with encrypted rows → refused; a test-volume
    marker outside a test gate → refused; flag on without a protected keyring → refused;
  * hub adapter with a fake agent stream (§12.11.10 Admission): ring, replay_start past the cursor
    (one marker), same-epoch reattach (no-op), overlap trimmed, a new agent epoch, overflow →
    resume → one marker, a ringless (SSH-like) source, close (sealed, verified);
  * routes in enabled mode (test gate + test volume): download byte-identical to 3.7, Range on
    plaintext offsets / 416 / If-Range, text view, preview, search, replay links (redaction across
    record boundaries, text masking), revocation mid-stream (sid bump, link revoke, role removal,
    logout), expiry (`not_after`), the access_gen poller and the admin transaction;
  * authorization until emission (PR5b review): WebSocket history reads (attach, resync, unlock)
    with logout / share revocation / step-up expiry landing between the read and the send, the
    text view / preview / search emitting nothing read under an authorization that moved, replay
    links bounded by the issuer's time-bound binding;
  * finalize accounting (close after an overflow, a blocked skip, a pending epoch switch, a lost
    recorder; the backlog entry cap), the access_gen baseline, fixed-set revocation fences, the
    admin CLI (3.7 path when the volume is not a tx volume; output only after COMMIT; rollback),
    the boot/backup file inventory;
  * flag off: the same fixed stream through the 3.7 hub writes the same .out/.cast as before
    (and the logical content of the encrypted recording), no tx rows, no generation files.
Temp dirs + the real db module; no network, no Docker.
"""
import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile
import time

BASE = tempfile.mkdtemp(prefix="wt-txhub-")
os.environ["WEBTERM_DATA_DIR"] = BASE
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
os.environ.setdefault("WEBTERM_UPDATE_CHECK", "0")
os.environ["WEBTERM_TX_RECORDINGS"] = "1"
os.environ["WEBTERM_TEST_GATE"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from starlette.requests import Request  # noqa: E402

from app import admin, api, authz, config, core, db, replay, security, share_api, shares, txhub  # noqa: E402
from app import txstore as ts  # noqa: E402
from app.main import app  # noqa: E402

ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
KWK = bytes(range(0x60, 0x80))
INST = bytes(range(0xa0, 0xb0))
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


class Ring:
    """A fake agent: `has_ring`, an epoch, attach(from_offset) → replay_start + replayed chunks."""
    has_ring = True
    backend = "tmux"

    def __init__(self, epoch, ring=True):
        self.epoch = epoch
        self.has_ring = ring
        self.next = None            # (replay_start, [chunks]) for the next attach

    async def attach(self, sid, from_offset):
        rs, chunks = self.next or (from_offset or 0, [])
        self.next = None
        hub = core.hubs.get(sid)
        for c in chunks:            # sosesc ÎNAINTE de răspuns, ca la agent (bufferate de hub)
            await hub.on_output(c)
        return {"ok": True, "replay_start": rs}

    async def resize(self, sid, rows, cols):
        return None


async def settle(r, n=400):
    for _ in range(n):
        if r is not None and r.op is None and not r.backlog and r.ckpt is None:
            return True
        await asyncio.sleep(0.01)
    return False


async def new_session(host_id, sid=None, epoch="e1", state="live"):
    sid = sid or os.urandom(16).hex()
    await db.execute("INSERT INTO sessions(id, host_id, title, state, created, rows, cols, agent_epoch,"
                     " agent_offset) VALUES(?,?,?,?,?,?,?,?,0)", sid, host_id, "t-" + sid[:4], state,
                     1795305600.0, 24, 80, epoch)
    return sid


async def hub_for(sid):
    return core.get_or_create_hub(await db.fetchone("SELECT * FROM sessions WHERE id=?", sid))


async def decrypt(sid, kind="out"):
    st = txhub.store()
    snap = await st.open(sid, kind, access=st.access(sid, "test", "test"))
    try:
        return await snap.read(0, snap.length)
    finally:
        snap.close()


async def close_hub(hub):
    r = hub._tx
    hub.teardown()
    if r is not None and r.close_task is not None:
        await r.close_task


def cast_events(raw):
    lines = [ln for ln in raw.decode().split("\n") if ln]
    return json.loads(lines[0]), [json.loads(ln) for ln in lines[1:]]


def mkreq(headers):
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw, "query_string": b""})


# ── 1. boot decision ─────────────────────────────────────────────────────────


class FakeRing:
    kwk = KWK
    installation_id = INST


async def g_boot_clean():
    print("== boot on a clean volume ==")
    check("clean volume: no encrypted recordings found", await txhub.encrypted_recordings_present() == "")
    check("flag off on a clean volume → boot returns None (3.7 path)",
          await txhub.boot(None, env={}) is None and not txhub.active())
    check("flag on without a protected keyring → refused",
          await araises(txhub.boot(None, env={"WEBTERM_TX_RECORDINGS": "1", "WEBTERM_TEST_GATE": "1"}),
                        txhub.BootRefused))
    check("flag on, no test volume → refused (PR6 needed on a real volume)",
          await araises(txhub.boot(FakeRing(), env={"WEBTERM_TX_RECORDINGS": "1",
                                                    "WEBTERM_TEST_GATE": "1"}), txhub.BootRefused))


async def g_boot_after():
    print("== boot with encrypted recordings on the volume ==")
    found = await txhub.encrypted_recordings_present()
    check("encrypted rows are found", found in ("session_keys", "tx_descriptors", "tx_files"), found)
    check("flag off + encrypted recordings → refused (never read as absent)",
          await araises(txhub.boot(None, env={"WEBTERM_TEST_GATE": "1"}), txhub.BootRefused))
    check("test-volume marker outside a test gate → refused",
          await araises(txhub.boot(FakeRing(), env={"WEBTERM_TX_RECORDINGS": "1"}), txhub.BootRefused))


# ── 2. hub adapter ───────────────────────────────────────────────────────────


async def g_hub_ring(host_id):
    print("== hub adapter: agent ring ==")
    sid = await new_session(host_id)
    hub = await hub_for(sid)
    check("hub uses the encrypted recording (no .out/.cast handles)",
          hub._tx is not None and hub.out_f is None and hub.cast_f is None)
    src = Ring("e1")
    src.next = (0, [b"hello\r\n", b"$ ls\r\n"])
    await hub.ensure_attached(src)
    r = hub._tx
    check("recorder started before output; attach replay admitted",
          r.rec is not None and r.rec.state == "running" and await settle(r))
    expect = b"hello\r\n$ ls\r\n"
    for c in (b"a" * 100, b"b" * 50):
        await hub.on_output(c)
        expect += c
    check("predicted .out position = offered bytes", r.out_pos() == len(expect), (r.out_pos(), len(expect)))
    check("commit_through(cutoff) covers the cutoff", await r.commit_through(r.out_pos()))
    check("committed .out = the stream", await decrypt(sid) == expect)
    row = await db.fetchone("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid)
    check("sessions.agent_offset published by the recorder with the bytes",
          (row["agent_epoch"], row["agent_offset"]) == ("e1", len(expect)), dict(row))
    # Reataşare în acelaşi epoch fără pierdere: no-op.
    hub.on_detached()
    src.next = (hub.agent_offset, [])
    await hub.ensure_attached(src)
    await settle(r)
    check("same-epoch reattach at the cursor: no marker, no reset", not r.rec.gaps and r.rec.received == ("e1", len(expect)))
    # Ring-ul a pierdut 100 de octeţi: replay_start > cursor → UN marker de 100.
    hub.on_detached()
    off = hub.agent_offset
    src.next = (off + 100, [b"after-skip\r\n"])
    await hub.ensure_attached(src)
    check("skip settles", await settle(r))
    gaps = [(g.size, g.reason) for g in r.rec.gaps]
    check("replay_start past the cursor → one marker for exactly the lost interval",
          gaps == [(100, "skip:ring")], gaps)
    expect += ts.GAP_MARKER + b"after-skip\r\n"
    # Suprapunere: un replay care reîncepe sub cursor se taie (fără dubluri).
    hub.on_detached()
    off = hub.agent_offset
    src.next = (off - 5, [expect[-5:] + b"NEW\r\n"])
    await hub.ensure_attached(src)
    await settle(r)
    expect += b"NEW\r\n"
    await r.commit_through(r.out_pos())
    got = await decrypt(sid)
    check("overlapping replay trimmed: no duplicated bytes", got == expect, (got[-40:], expect[-40:]))
    # Agent repornit: epoch nou, ring de la 0 → change_epoch, fără marker (nimic neacoperit).
    hub.on_detached()
    src.epoch = "e2"
    src.next = (0, [b"new agent\r\n"])
    await hub.ensure_attached(src)
    await settle(r)
    expect += b"new agent\r\n"
    await r.commit_through(r.out_pos())
    row = await db.fetchone("SELECT agent_epoch, agent_offset FROM sessions WHERE id=?", sid)
    check("new agent epoch: recorder switched, cursor in the new epoch",
          r.rec.received == ("e2", len(b"new agent\r\n")) and row["agent_epoch"] == "e2", (r.rec.received, dict(row)))
    check("new agent epoch: no marker when nothing was lost", len(r.rec.gaps) == 1)
    check("content after the epoch switch", await decrypt(sid) == expect)
    # Overflow → resume → UN marker pentru tot ce s-a pierdut.
    st = txhub.store()
    old_cap = st.pending_cap
    st.pending_cap = 2000
    before = hub.agent_offset
    for c in (b"1" * 400, b"2" * 400, b"3" * 400, b"4" * 400, b"5" * 400):
        await hub._process_output(c)
    st.pending_cap = old_cap
    check("overflow resolves", await settle(r))
    lost = [g.size for g in r.rec.gaps[1:]]
    check("overflow → resume → one marker for the dropped bytes (3 × 400)", lost == [1200], lost)
    expect += ts.GAP_MARKER + b"4" * 400 + b"5" * 400
    await r.commit_through(r.out_pos())
    check("after the overflow: no duplicate, no unmarked hole", await decrypt(sid) == expect)
    check("cursor at the live end after resume", r.rec.received == ("e2", hub.agent_offset)
          and hub.agent_offset == before + 2000, (r.rec.received, hub.agent_offset))
    # Închidere: sigilat, verificat, cast cu antet + evenimente.
    await close_hub(hub)
    rep = await st.verify(sid)
    check("close: recording sealed and verified (full integrity check)", rep.get("ok") is True, rep)
    hdr, ev = cast_events(await decrypt(sid, "cast"))
    check("cast header exactly as 3.7", hdr == {"version": 2, "width": 80, "height": 24,
                                                "timestamp": 1795305600})
    outs = "".join(e[2] for e in ev if e[1] == "o")
    check("cast events carry the same output (markers included)",
          outs.encode() == expect, (len(outs), len(expect)))
    await db.execute("UPDATE sessions SET state='closed', closed_at=? WHERE id=?", time.time(), sid)
    return sid, expect


async def g_hub_ringless(host_id):
    print("== hub adapter: ringless (SSH-like) source ==")
    sid = await new_session(host_id, epoch=None)
    hub = await hub_for(sid)
    await hub.on_output(b"before attach\r\n")        # SSH: output înaintea ataşării (backlog)
    src = Ring("ssh-1", ring=False)
    await hub.ensure_attached(src)
    r = hub._tx
    for c in (b"one\r\n", b"two\r\n"):
        await hub.on_output(c)
    await settle(r)
    await r.commit_through(r.out_pos())
    check("ringless: output before the attach is recorded in order",
          await decrypt(sid) == b"before attach\r\none\r\ntwo\r\n")
    row = await db.fetchone("SELECT agent_offset FROM sessions WHERE id=?", sid)
    check("ringless: no durable agent offset published", (row["agent_offset"] or 0) == 0, dict(row))
    await close_hub(hub)


# ── 3. routes ────────────────────────────────────────────────────────────────


def client(**kw):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", timeout=30,
                             headers=dict(ORIGIN, **kw.pop("headers", {})), **kw)


async def big_recording(host_id, n=20, size=16 * 1024):
    sid = await new_session(host_id)
    hub = await hub_for(sid)
    await hub.ensure_attached(Ring("e1"))
    data = b""
    for i in range(n):
        c = (b"%04d:" % i) + bytes(65 + (j % 26) for j in range(size - 5))
        await hub.on_output(c)
        data += c
        await asyncio.sleep(0)
    await settle(hub._tx)
    await close_hub(hub)
    await db.execute("UPDATE sessions SET state='closed', closed_at=? WHERE id=?", time.time(), sid)
    return sid, data


async def g_routes(c, host_id, uid, token, sid, expect):
    print("== routes: download, Range, text, preview, search ==")
    r = await c.get(f"/api/sessions/{sid}/transcript?format=out", headers={"Accept-Encoding": "identity"})
    check("download .out: 200, byte-identical to the stream", r.status_code == 200 and r.content == expect,
          (r.status_code, r.text[:200]))
    check("download headers: Accept-Ranges, Content-Length, no-store",
          r.headers.get("accept-ranges") == "bytes" and r.headers.get("content-length") == str(len(expect))
          and r.headers.get("cache-control") == "no-store", dict(r.headers))
    r = await c.get(f"/api/sessions/{sid}/transcript?format=out", headers={"Range": "bytes=5-14"})
    check("Range on plaintext offsets → 206 with the exact bytes (identity encoding)",
          r.status_code == 206 and r.content == expect[5:15]
          and r.headers.get("content-range") == "bytes 5-14/%d" % len(expect)
          and r.headers.get("content-length") == "10", (r.status_code, r.headers))
    r = await c.get(f"/api/sessions/{sid}/transcript?format=out", headers={"Range": "bytes=-7"})
    check("suffix Range → the last 7 bytes", r.status_code == 206 and r.content == expect[-7:])
    r = await c.get(f"/api/sessions/{sid}/transcript?format=out", headers={"Range": "bytes=%d-" % len(expect)})
    check("Range past the end → 416 with Content-Range bytes */length",
          r.status_code == 416 and r.headers.get("content-range") == "bytes */%d" % len(expect))
    r = await c.get(f"/api/sessions/{sid}/transcript?format=out", headers={"Range": "bytes=0-1,4-5"})
    check("multi-range → 200 full", r.status_code == 200 and r.content == expect)
    r = await c.get(f"/api/sessions/{sid}/transcript?format=out",
                    headers={"Range": "bytes=0-3", "If-Range": '"x"'})
    check("If-Range (no ETag yet) → 200 full", r.status_code == 200 and r.content == expect)
    r = await c.get(f"/api/sessions/{sid}/transcript?format=cast")
    hdr, ev = cast_events(r.content)
    check("download .cast: header + events of the stream", r.status_code == 200 and hdr["version"] == 2
          and "".join(e[2] for e in ev).encode() == expect)
    r = await c.get(f"/api/sessions/{sid}/transcript?format=txt")
    check("text view = 3.7's transformation of the same bytes",
          r.status_code == 200 and r.text == core.text_of_output(expect))
    r = await c.get(f"/api/sessions/{sid}/preview")
    check("preview = the committed tail (alt-screen stripped)",
          r.status_code == 200 and r.content == core.ALT_SCREEN_RE.sub(b"", expect[-32 * 1024:]))
    r = await c.get("/api/search?q=after-skip")
    hits = [s["id"] for s in r.json().get("sessions", [])]
    check("search finds text inside the encrypted recording", sid in hits, r.text[:300])
    r = await c.get(f"/api/sessions/{'f' * 32}/transcript?format=out")
    check("unknown session → 404", r.status_code == 404)
    c2 = client()
    r = await c2.get(f"/api/sessions/{sid}/transcript?format=out")
    check("no cookie → refused before any read", r.status_code in (401, 403, 404))


async def g_replay(c, sid, cast_secret_sid):
    print("== routes: replay links (redaction across record boundaries) ==")
    r = await c.post(f"/api/sessions/{cast_secret_sid}/replay-links", json={"expires_hours": 24, "redact": True})
    check("replay link created on an encrypted recording", r.status_code == 200, r.text[:200])
    tok = r.json()["url"].rsplit("/", 1)[1]
    link_id = r.json()["id"]
    pub = client(headers={"X-Replay-Token": tok})
    r = await pub.get("/api/replay/cast")
    raw = await decrypt(cast_secret_sid, "cast")
    check("redacted cast = 3.7's redact_cast of the decrypted stream",
          r.status_code == 200 and r.content == replay.redact_cast(raw), r.status_code)
    check("the secret split across records is masked", b"ghp_" + b"Q" * 8 not in r.content
          and b"Q" * 12 not in r.content, r.content[:300])
    r = await pub.get("/api/replay/text")
    check("replay text masked", r.status_code == 200 and "Q" * 12 not in r.text and "GITHUB_TOKEN" in r.text)
    # Revocare în mijlocul fluxului: link revocat → fluxul cade la următorul chunk.
    big = await db.fetchone("SELECT id FROM sessions WHERE id=?", sid)
    r = await c.post(f"/api/sessions/{big['id']}/replay-links", json={"expires_hours": 1, "redact": False})
    tok2 = r.json()["url"].rsplit("/", 1)[1]
    req = mkreq({"x-replay-token": tok2})
    row = await share_api._replay_lookup(req)
    resp = await share_api._tx_replay_cast(req, row)
    it = resp.body_iterator
    first = await it.__anext__()
    r = await c.delete(f"/api/replay-links/{r.json()['id']}")
    ok = await araises(it.__anext__(), ts.Revoked)
    check("replay link revoked mid-stream → the stream stops at the next chunk",
          r.status_code == 200 and 0 < len(first) <= ts.STREAM_CHUNK and ok)
    await it.aclose()
    # Expirare: ceasul store-ului trece de expirarea link-ului → re-autorizare → refuz.
    r = await c.post(f"/api/sessions/{big['id']}/replay-links", json={"expires_hours": 1, "redact": False})
    tok3 = r.json()["url"].rsplit("/", 1)[1]
    req = mkreq({"x-replay-token": tok3})
    row = await share_api._replay_lookup(req)
    resp = await share_api._tx_replay_cast(req, row)
    it = resp.body_iterator
    await it.__anext__()
    st = txhub.store()
    real = st.clock
    st.clock = lambda: real() + 7200
    ok = await araises(it.__anext__(), Exception)
    st.clock = real
    check("link expiry (not_after) stops the stream without a counter bump", ok)
    await it.aclose()
    await c.delete(f"/api/replay-links/{link_id}")


async def g_stream_revocation(c, uid, token, sid, data):
    print("== routes: revocation mid-stream, re-authorization, expiry ==")
    cookie = {"cookie": f"{security.COOKIE_NAME}={token}"}

    async def stream():
        resp = await share_api._tx_transcript(mkreq(cookie), sid, "out", False)
        return resp.body_iterator
    it = await stream()
    first = await it.__anext__()
    txhub.bump(sid)
    check("sid revocation bump cuts the download at the next chunk (one chunk authorized)",
          await araises(it.__anext__(), ts.Revoked) and 0 < len(first) <= ts.STREAM_CHUNK, len(first))
    await it.aclose()
    it = await stream()
    await it.__anext__()
    authz.bump_epoch()                       # o schimbare de roluri oarecare (nu a lui)
    nxt = await it.__anext__()
    check("global bump → re-authorization passes → the stream continues", len(nxt) > 0)
    await it.aclose()
    it = await stream()
    await it.__anext__()
    saved = await db.fetchall("SELECT * FROM role_bindings WHERE user_id=?", uid)
    await db.execute("DELETE FROM role_bindings WHERE user_id=?", uid)
    authz.bump_epoch()
    ok = await araises(it.__anext__(), Exception)
    check("role removed mid-stream → re-authorization denied → aborted", ok)
    await it.aclose()
    for b in saved:
        await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source, created)"
                         " VALUES(?,?,?,?,?,?)", b["user_id"], b["role_id"], b["scope_kind"],
                         b["scope_value"], b["source"], b["created"])
    authz.bump_epoch()
    # Expirarea sesiunii web (not_after) fără niciun bump.
    it = await stream()
    await it.__anext__()
    st = txhub.store()
    real = st.clock
    await db.execute("UPDATE web_sessions SET expires=? WHERE token_hash=?", time.time() - 1,
                     security.sha256_hex(token))
    st.clock = lambda: real() + 400 * 86400
    ok = await araises(it.__anext__(), Exception)
    st.clock = real
    check("web session expiry (not_after) stops the stream", ok)
    await it.aclose()


async def g_logout(sid):
    print("== routes: logout mid-stream ==")
    c = client()
    r = await c.post("/api/login", json={"email": "o@x.co", "password": "parolabuna1"})
    tok = c.cookies.get(security.COOKIE_NAME)
    check("second login for the logout test", r.status_code == 200 and tok, r.text[:200])
    resp = await share_api._tx_transcript(mkreq({"cookie": f"{security.COOKIE_NAME}={tok}"}), sid, "out", False)
    it = resp.body_iterator
    await it.__anext__()
    r = await c.post("/api/logout")
    ok = await araises(it.__anext__(), Exception)
    check("logout mid-stream → the stream stops (fence + re-authorization)", r.status_code == 200 and ok)
    await it.aclose()


async def g_access_gen():
    print("== access_gen poller + admin transaction ==")
    st = txhub.store()
    txhub._poll_state.update(have=False, last=None, fails=0)
    await txhub.poll_once()
    e0 = st.access_epoch
    await txhub.poll_once()
    check("unchanged access_gen → no bump", st.access_epoch == e0)

    async def change(_args):
        await db.execute("UPDATE users SET totp_enabled=0 WHERE id=-1")
    await admin.run_access_change(change, None)
    await txhub.poll_once()
    check("admin access change → access_gen moved → global bump", st.access_epoch == e0 + 1)
    gen = await db.fetchone("SELECT value FROM tx_state WHERE key='access_gen'")

    async def failing(_args):
        await db.execute("INSERT INTO app_settings(key, value) VALUES('txhub-probe', 'x')")
        raise SystemExit(2)
    try:
        await admin.run_access_change(failing, None)
    except SystemExit:
        pass
    gen2 = await db.fetchone("SELECT value FROM tx_state WHERE key='access_gen'")
    probe = await db.fetchone("SELECT 1 FROM app_settings WHERE key='txhub-probe'")
    check("a failed admin command commits neither its change nor the bump",
          gen2["value"] == gen["value"] and probe is None)
    orig = txhub._read_access_gen

    async def broken():
        raise RuntimeError("db gone")
    txhub._read_access_gen = broken
    e1 = st.access_epoch
    await txhub.poll_once()
    one = st.access_epoch == e1
    await txhub.poll_once()
    txhub._read_access_gen = orig
    check("one failed poll → nothing; two in a row → global bump", one and st.access_epoch == e1 + 1)


async def secret_recording(host_id):
    sid = await new_session(host_id)
    hub = await hub_for(sid)
    await hub.ensure_attached(Ring("e1"))
    for c in (b"$ export GITHUB_TOKEN=gh", b"p_" + b"Q" * 20, b"Q" * 16 + b"\r\n$ echo ok\r\n"):
        await hub.on_output(c)
        await hub._tx.commit_through(hub._tx.out_pos())     # fiecare bucată în propriul record
    await close_hub(hub)
    await db.execute("UPDATE sessions SET state='closed', closed_at=? WHERE id=?", time.time(), sid)
    return sid


# ── 3b. authorization until emission (PR5b review H1, H2, M1) ─────────────────


class FakeWS:
    def __init__(self):
        self.bins, self.texts = [], []

    async def send_bytes(self, b):
        self.bins.append(bytes(b))

    async def send_text(self, t):
        self.texts.append(t)


SECRET = b"secret-history-XYZ"


def leaked(ws):
    return any(SECRET in b for b in ws.bins)


async def live_recorded(host_id):
    sid = await new_session(host_id)
    hub = await hub_for(sid)
    await hub.ensure_attached(Ring("e1"))
    await hub.on_output(SECRET + b"\r\n")
    await settle(hub._tx)
    await hub._tx.commit_through(hub._tx.out_pos())
    return sid, hub


async def login():
    c = client()
    r = await c.post("/api/login", json={"email": "o@x.co", "password": "parolabuna1"})
    assert r.status_code == 200, r.text
    return c, c.cookies.get(security.COOKIE_NAME)


def ws_client(hub, uid=None, decide=None, guest=False):
    ws = FakeWS()
    cl = core.BrowserClient(ws, hub)
    cl.id = ("g_" if guest else "o_") + os.urandom(4).hex()
    cl.is_owner = not guest
    cl.user_id = uid
    cl.tx_decide = decide
    return ws, cl


async def resync_racing(cl, action):
    """A resync whose recording read completes, then `action` lands, then the send."""
    orig = core.read_tail_tx

    async def racing(*a, **kw):
        res = await orig(*a, **kw)
        await action()
        return res
    core.read_tail_tx = racing
    try:
        await cl._resync(False)
    finally:
        core.read_tail_tx = orig


async def g_ws_history(c, host_id, uid, token):
    print("== WebSocket history reads: authorization until emission (H1) ==")
    sid, hub = await live_recorded(host_id)
    c2, tok2 = await login()
    ws, cl = ws_client(hub, uid, api._ws_user_decider(tok2, uid, sid, live=True))
    await cl._resync(False)
    check("resync, nothing changed: the committed history is sent", leaked(ws), ws.bins)
    ws, cl = ws_client(hub, uid, None)
    await cl._resync(False)
    check("resync without the WebSocket's decision: nothing from the recording (fail closed)",
          not leaked(ws) and ws.bins == [b""], ws.bins)

    async def bumping():
        txhub.bump(sid)                       # o revocare în timpul fiecărei decizii
        return None
    data, _e, _l = await core.read_tail_tx(sid, grant=core.ws_grant(sid, "user:%d" % uid, "ws-attach",
                                                                      bumping))
    check("counters captured BEFORE the decision: a revocation during every decision → nothing read",
          data == b"")
    # Share: invitatul, revocarea între citire şi trimitere.
    r = await c.post(f"/api/sessions/{sid}/share", json={"expires_minutes": 60})
    check("share created", r.status_code == 200, r.text[:200])
    gtok = r.json()["url"].rsplit("/", 1)[1]
    gdec = api._ws_guest_decider(security.sha256_hex(gtok), sid)
    gws, g = ws_client(hub, None, gdec, guest=True)
    await g._resync(False)
    check("guest resync with a valid share: history sent", leaked(gws))
    gws, g = ws_client(hub, None, gdec, guest=True)

    async def revoke_share():
        rr = await c.delete(f"/api/sessions/{sid}/share")
        assert rr.status_code == 200, rr.text
    await resync_racing(g, revoke_share)
    check("share revoked between the guest's read and the send → nothing emitted", not leaked(gws), gws.bins)
    # Logout în timpul unui resync deja pornit.
    ws, cl = ws_client(hub, uid, api._ws_user_decider(tok2, uid, sid, live=True))

    async def logout():
        rr = await c2.post("/api/logout")
        assert rr.status_code == 200, rr.text
    await resync_racing(cl, logout)
    check("logout between the resync's read and the send → nothing emitted", not leaked(ws), ws.bins)
    # Ataşare: citire autorizată, logout înainte de trimitere.
    c3, tok3 = await login()
    grant = core.ws_grant(sid, "user:%d" % uid, "ws-attach", api._ws_user_decider(tok3, uid, sid, live=True))
    data = await core.attach_replay(sid, hub, 0, 0, grant=grant)
    ok_before = SECRET in data and grant.emit_ok()
    await c3.post("/api/logout")
    check("attach: authorized read, logout before the send → before_emit refuses",
          ok_before and not await grant.before_emit())
    grant = core.ws_grant(sid, "user:%d" % uid, "ws-attach", api._ws_user_decider(token, uid, sid, live=True))
    await core.attach_replay(sid, hub, 0, 0, grant=grant)
    authz.bump_epoch()
    check("a global change with the rights kept → re-authorized at emission", await grant.before_emit())
    grant = core.ws_grant(sid, "user:%d" % uid, "ws-attach", api._ws_user_decider(token, uid, sid, live=True))
    await core.attach_replay(sid, hub, 0, 0, grant=grant)
    txhub.bump(sid)
    check("a sid revocation after the read → refused, never re-authorized", not await grant.before_emit())
    ws, cl = ws_client(hub, uid, api._ws_user_decider(token, uid, sid, live=True))
    await resync_racing(cl, lambda: hub.lock("stepup"))
    check("hub locked between the read and the send → nothing emitted (lock re-checked at the send)",
          not leaked(ws))
    hub.locked = False
    for x in list(hub.clients):
        hub.clients.discard(x)
    await close_hub(hub)
    # Step-up pe un host 2FA: sesiune închisă, calea de deblocare (fără hub).
    await db.execute("UPDATE sessions SET state='closed', closed_at=? WHERE id=?", time.time(), sid)
    await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", host_id)
    try:
        security.open_stepup_window(uid, host_id)
        grant = core.ws_grant(sid, "user:%d" % uid, "ws-unlock",
                              api._ws_user_decider(token, uid, sid, live=False))
        data, _e, _l = await core.read_tail_tx(sid, grant=grant)
        good = SECRET in data and grant.emit_ok()
        opened = security.stepup_window_record(uid, host_id)[0]
        security._stepup_windows[(uid, host_id)] = (opened, time.time() - 1)
        st = txhub.store()
        real = st.clock
        st.clock = lambda: real() + 400
        try:
            refused = not await grant.before_emit()
        finally:
            st.clock = real
        check("closed 2FA session: read inside the step-up window, window expired before the send → refused",
              good and refused)
        security._stepup_windows.pop((uid, host_id), None)
        grant = core.ws_grant(sid, "user:%d" % uid, "ws-unlock",
                              api._ws_user_decider(token, uid, sid, live=False))
        data, _e, _l = await core.read_tail_tx(sid, grant=grant)
        check("closed 2FA session without a step-up window → nothing read", data == b"")
    finally:
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", host_id)
    return sid


async def g_emission(c, uid, token, big, data):
    print("== HTTP readers: authorization until emission (H2, M1) ==")
    cookie = {"cookie": f"{security.COOKIE_NAME}={token}"}
    resp = await share_api._tx_transcript(mkreq(cookie), big, "txt", False)
    check("text view: no-store, Content-Length", resp.headers.get("cache-control") == "no-store"
          and int(resp.headers.get("content-length", "0")) > ts.STREAM_CHUNK, dict(resp.headers))
    it = resp.body_iterator
    txhub.bump(big)
    check("text view: revoked between the last check and the first chunk → nothing emitted",
          await araises(it.__anext__(), ts.Revoked))
    await it.aclose()
    resp = await share_api._tx_transcript(mkreq(cookie), big, "txt", False)
    it = resp.body_iterator
    first = await it.__anext__()
    txhub.bump(big)
    check("text view: revoked mid-body → the next chunk is refused",
          0 < len(first) <= ts.STREAM_CHUNK and await araises(it.__anext__(), ts.Revoked))
    await it.aclose()
    orig_text = core.text_of_output

    def converting(raw):
        out = orig_text(raw)
        txhub.store().bump(big)          # revocarea cade cât rulează conversia (worker)
        return out
    core.text_of_output = converting
    try:
        ok = await araises(share_api._tx_transcript(mkreq(cookie), big, "txt", False), api.ApiError)
    finally:
        core.text_of_output = orig_text
    check("text view: revoked during the conversion → refused before any byte (no response)", ok)
    resp = await share_api._tx_preview(mkreq(cookie), big)
    it = resp.body_iterator
    txhub.bump(big)
    check("preview: revoked before the send → nothing emitted", await araises(it.__anext__(), ts.Revoked))
    await it.aclose()
    # Căutare: revocarea unui sid în timpul acumulării → conţinutul lui nu iese.
    st = txhub.store()
    orig_tail = st.search_tail

    async def tail_then_revoke(sid, **kw):
        out = await orig_tail(sid, **kw)
        if sid == big:
            st.bump(big)
        return out
    st.search_tail = tail_then_revoke
    try:
        r = await c.get("/api/search?q=0007:")
    finally:
        st.search_tail = orig_tail
    hits = [s["id"] for s in r.json().get("sessions", [])]
    check("search: control — the content is searchable", big in [s["id"] for s in (await c.get(
        "/api/search?q=0007:")).json().get("sessions", [])])
    check("search: sid revoked after its read, before the response → its content is not emitted",
          r.status_code == 200 and big not in hits, r.text[:200])
    check("search response: no-store", r.headers.get("cache-control") == "no-store")
    c5, tok5 = await login()

    async def tail_then_logout(sid, **kw):
        out = await orig_tail(sid, **kw)
        await db.execute("DELETE FROM web_sessions WHERE token_hash=?", security.sha256_hex(tok5))
        st.bump(None)
        return out
    st.search_tail = tail_then_logout
    try:
        r = await c5.get("/api/search?q=0007:")
    finally:
        st.search_tail = orig_tail
    check("search: logout during the accumulation → re-run → refused, nothing emitted",
          r.status_code == 401 and "0007" not in r.text, (r.status_code, r.text[:200]))
    user = await db.fetchone("SELECT * FROM users WHERE id=?", uid)
    resp = await api._search_tx(mkreq(cookie), user, "0007:")
    st.bump(None)                                 # după ultima verificare din rută, înainte de corp
    body = b"".join([x async for x in resp.body_iterator])
    check("search: a global change between the route's check and the body → empty result",
          json.loads(body) == {"sessions": []}, body[:200])
    resp = await api._search_tx(mkreq(cookie), user, "0007:")
    body = b"".join([x async for x in resp.body_iterator])
    check("search: control — the body carries the hit when nothing moved",
          big in [s["id"] for s in json.loads(body)["sessions"]])
    # M1: link-ul de replay se re-autorizează la expirarea legăturii temporare a emitentului.
    role = await db.fetchone("SELECT role_id FROM role_bindings WHERE user_id=? LIMIT 1", uid)
    soon = time.time() + 120
    await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source, expires,"
                     " created) VALUES(?,?,?,?,?,?,?)", uid, role["role_id"], "tag", "txhub-m1", "manual",
                     soon, time.time())
    authz.bump_epoch()
    try:
        r = await c.post(f"/api/sessions/{big}/replay-links", json={"expires_hours": 24, "redact": False})
        tokl = r.json()["url"].rsplit("/", 1)[1]
        req = mkreq({"x-replay-token": tokl})
        row = await share_api._replay_lookup(req)
        acc = await share_api._tx_link_authorizer(req, row, "replay-cast").authorize()
        check("replay link: not_after = the issuer's earliest time-bound binding (not the link's expiry)",
              acc.not_after is not None and abs(acc.not_after - soon) < 1 and acc.not_after < row["expires"],
              (acc.not_after, soon, row["expires"]))
        await c.delete(f"/api/replay-links/{r.json()['id']}")
    finally:
        await db.execute("DELETE FROM role_bindings WHERE scope_value='txhub-m1'")
        authz.bump_epoch()


# ── 3c. finalize accounting, counters, admin, inventory (PR5b review M2–M4) ───


class Pending:
    """A never-resolving adapter operation (a blocked skip / epoch switch)."""

    def __init__(self):
        self.fut = None

    def __call__(self, *a, **kw):
        self.fut = asyncio.get_running_loop().create_future()
        return self.fut


async def fresh_rec(host_id):
    sid = await new_session(host_id)
    hub = await hub_for(sid)
    await hub.ensure_attached(Ring("e1"))
    await hub.on_output(b"base\r\n")
    await settle(hub._tx)
    return sid, hub, hub._tx


async def g_finalize(host_id):
    print("== finalize accounting (M2) ==")
    st = txhub.store()
    old_secs = txhub.SHUTDOWN_SECS
    txhub.SHUTDOWN_SECS = 0.3
    try:
        # Skip blocat: backlog-ul rămas intră în markerul de close (durabil).
        sid, hub, r = await fresh_rec(host_id)
        e, o = r.rec.received
        r.rec.skip_to = Pending()
        r.feed((e, o + 10), b"x" * 5)
        r.feed((e, o + 15), b"y" * 7)
        held = 10 + 5 + 7
        await close_hub(hub)
        gaps = [(g.size, g.reason) for g in r.rec.gaps]
        check("blocked skip at close: the held bytes (hole included) become the close marker",
              r.close_report == {"unoffered": held, "unrecorded": 0, "closed": True}
              and gaps[-1:] == [(held, "close")], (r.close_report, gaps))
        check("blocked skip at close: recording sealed and verified", (await st.verify(sid)).get("ok"))
        # Comutare de epoch blocată: octeţii altui epoch nu pot deveni marker → alarmă explicită.
        sid, hub, r = await fresh_rec(host_id)
        r.rec.change_epoch = Pending()
        r.feed(("e2", 0), b"z" * 9)
        r.feed(("e2", 9), b"z" * 4)
        n0 = len(st.alarms)
        await close_hub(hub)
        al = [a for a in st.alarms[n0:] if a[0] == "transcript.gapUnrecorded"]
        check("pending epoch switch at close: the other epoch's 13 bytes are alarmed with their size",
              r.close_report["unrecorded"] == 13 and r.close_report["closed"] and al
              and " 13 bytes" in al[-1][1], (r.close_report, al))
        # Recorder pierdut, fără readoptare: tot backlog-ul e alarmat.
        sid, hub, r = await fresh_rec(host_id)
        real = r.rec
        r.rec.skip_to = Pending()
        e, o = real.received
        r.feed((e, o + 3), b"q" * 6)

        class Lost:
            state = "lost"
            received = real.received
        r.op = None
        r.rec = Lost()
        n0 = len(st.alarms)
        await close_hub(hub)
        al = [a for a in st.alarms[n0:] if a[0] == "transcript.gapUnrecorded"]
        check("lost recorder at close (no re-adoption): the backlog is alarmed, never silent",
              r.close_report["closed"] is False and r.close_report["unrecorded"] == 6 and al, (r.close_report, al))
        await real.close()
        # Close imediat după un overflow: contabilitate completă (înregistrat + goluri = oferit).
        sid, hub, r = await fresh_rec(host_id)
        old_cap = st.pending_cap
        st.pending_cap = 1500
        offered = len(b"base\r\n")
        try:
            for i in range(8):
                chunk = bytes([65 + i]) * 400
                await hub._process_output(chunk)
                offered += len(chunk)
            hub.teardown()                        # fără settle: chiar după overflow
            await r.close_task
        finally:
            st.pending_cap = old_cap
        out = await decrypt(sid)
        n = out.count(ts.GAP_MARKER)
        recorded = len(out) - n * len(ts.GAP_MARKER)
        lost = sum(g.size for g in r.rec.gaps)
        check("close right after an overflow: recorded + every gap = everything offered",
              r.close_report["closed"] and recorded + lost == offered and n == len(r.rec.gaps),
              (recorded, lost, offered, n, r.close_report))
    finally:
        txhub.SHUTDOWN_SECS = old_secs
    # Plafonul de intrări: placeholder-ele nu cresc nelimitat.
    sid, hub, r = await fresh_rec(host_id)
    old_items = txhub.BACKLOG_MAX_ITEMS
    txhub.BACKLOG_MAX_ITEMS = 4
    try:
        e, o = r.rec.received
        r.rec.skip_to = Pending()
        for k in range(12):
            r.feed((e, o + 10 + k * 20), b"p" * 5)
        last = r.backlog[-1]
        check("backlog entry cap: never more than BACKLOG_MAX_ITEMS entries, positions still covered",
              len(r.backlog) <= 4 and last.pos[1] + last.n == o + 10 + 11 * 20 + 5,
              (len(r.backlog), last.pos, last.n))
    finally:
        txhub.BACKLOG_MAX_ITEMS = old_items
    old_secs = txhub.SHUTDOWN_SECS
    txhub.SHUTDOWN_SECS = 0.3
    try:
        await close_hub(hub)
    finally:
        txhub.SHUTDOWN_SECS = old_secs


async def g_counters(c, host_id, uid, big):
    print("== access_gen baseline and fixed-set revocation fences (M3) ==")
    st = txhub.store()
    txhub._poll_state.update(have=False, last=None, fails=0)
    e0 = st.access_epoch
    await txhub.poll_once(baseline=True)
    check("boot baseline read: learns access_gen without a bump", st.access_epoch == e0)
    txhub._poll_state.update(have=False, last=None, fails=0)
    await txhub.poll_once()
    check("a first read that is not the boot baseline bumps (what came before is unknown)",
          st.access_epoch == e0 + 1)
    a = await new_session(host_id)
    b = await new_session(host_id)
    r = await c.post(f"/api/sessions/{a}/share", json={"expires_minutes": 60})
    check("share on A", r.status_code == 200, r.text[:200])
    fenced = []
    orig = txhub.revoking_many

    @contextlib.asynccontextmanager
    async def spy(sids):
        sids = set(sids)
        fenced.append(sids)
        if len(fenced) == 1:
            # un share nou apare între SELECT şi UPDATE (pe B)
            await db.execute("UPDATE sessions SET share_token=?, share_expires=?, share_by_id=? WHERE id=?",
                             security.sha256_hex("late-" + b), time.time() + 3600, uid, b)
        async with orig(sids):
            yield
    txhub.revoking_many = spy
    try:
        await shares.revoke_all_shares(None, uid)
    finally:
        txhub.revoking_many = orig
    rows = await db.fetchall("SELECT id, share_token FROM sessions WHERE id IN (?,?)", a, b)
    check("revoke-all: a share created between the SELECT and the UPDATE is fenced and revoked too",
          all(x["share_token"] is None for x in rows) and a in fenced[0] and any(b in f for f in fenced),
          (fenced, [dict(x) for x in rows]))
    check("revoke-all: the first fence covers exactly the selected rows (no unfenced extra)",
          b not in fenced[0], fenced)
    r = await c.post(f"/api/sessions/{big}/replay-links", json={"expires_hours": 1, "redact": False})
    check("replay link for the deletion test", r.status_code == 200, r.text[:200])
    fenced.clear()
    txhub.revoking_many = lambda sids: _rec_fence(fenced, orig, sids)
    try:
        n = await shares.delete_replay_links(" WHERE id=?", r.json()["id"])
    finally:
        txhub.revoking_many = orig
    check("replay-link deletion: the fence comes from the same read as the deleted ids",
          n == 1 and fenced == [{big}], (n, fenced))


def _rec_fence(log_, orig, sids):
    sids = set(sids)
    log_.append(sids)
    return orig(sids)


async def g_admin():
    print("== admin CLI: 3.7 path off a tx volume, output after COMMIT, rollback (M4) ==")
    check("the test volume is a tx volume for the CLI (marker), whatever its flag", await admin.tx_volume())
    gen0 = (await db.fetchone("SELECT value FROM tx_state WHERE key='access_gen'"))["value"]

    async def change(_args):
        await db.execute("INSERT INTO app_settings(key, value) VALUES('txhub-m4', 'x')")
        print("✓ done")
    orig_vol = admin.tx_volume

    async def no():
        return False
    admin.tx_volume = no
    try:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            await admin.dispatch("promote", change, None)
    finally:
        admin.tx_volume = orig_vol
    gen1 = (await db.fetchone("SELECT value FROM tx_state WHERE key='access_gen'"))["value"]
    check("not a tx volume: the command runs as in 3.7 (no access_gen write), output printed",
          gen1 == gen0 and out.getvalue() == "✓ done\n"
          and await db.fetchone("SELECT 1 FROM app_settings WHERE key='txhub-m4'"), (gen0, gen1, out.getvalue()))
    await db.execute("DELETE FROM app_settings WHERE key='txhub-m4'")
    orig_bump = admin._bump_tx_access_gen

    async def broken_stamp():
        raise RuntimeError("stamp failed")
    admin._bump_tx_access_gen = broken_stamp
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            ok = await araises(admin.dispatch("promote", change, None), RuntimeError)
    finally:
        admin._bump_tx_access_gen = orig_bump
    gen2 = (await db.fetchone("SELECT value FROM tx_state WHERE key='access_gen'"))["value"]
    check("stamp failure: rolled back, no success printed, the error propagates (non-zero exit)",
          ok and out.getvalue() == "" and gen2 == gen0
          and not await db.fetchone("SELECT 1 FROM app_settings WHERE key='txhub-m4'"), (out.getvalue(), gen2))
    conn = db._conn
    orig_commit = conn.commit

    async def broken_commit():
        raise RuntimeError("commit failed")
    conn.commit = broken_commit
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            ok = await araises(admin.dispatch("promote", change, None), RuntimeError)
    finally:
        conn.commit = orig_commit
    gen3 = (await db.fetchone("SELECT value FROM tx_state WHERE key='access_gen'"))["value"]
    check("commit failure: rolled back, no success printed, the error propagates",
          ok and out.getvalue() == "" and gen3 == gen0
          and not await db.fetchone("SELECT 1 FROM app_settings WHERE key='txhub-m4'"), (out.getvalue(), gen3))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        await admin.dispatch("promote", change, None)
    gen4 = (await db.fetchone("SELECT value FROM tx_state WHERE key='access_gen'"))["value"]
    check("tx volume: committed with the access_gen stamp, output printed after the COMMIT",
          out.getvalue() == "✓ done\n" and gen4 != gen0)
    await db.execute("DELETE FROM app_settings WHERE key='txhub-m4'")


def g_inventory():
    print("== boot / backup inventory of mixed formats ==")
    d = tempfile.mkdtemp(prefix="wt-txinv-")
    try:
        os.makedirs(os.path.join(d, "transcripts", "arhiva"))
        open(os.path.join(d, "keys.wtk"), "wb").close()
        open(os.path.join(d, "transcripts", "a" * 32 + ".out"), "wb").close()
        open(os.path.join(d, "transcripts", "arhiva", "b" * 32 + ".cast"), "wb").close()
        check("legacy files only (keys.wtk at the top ignored): nothing found",
              txhub.recording_files_present(d) == "")
        gen = "c" * 32 + ".out." + "d" * 32 + ".wtx"
        open(os.path.join(d, "transcripts", "arhiva", gen), "wb").close()
        found = txhub.recording_files_present(d)
        check("a generation file in transcripts/arhiva/ is found (same definition as backup/restore)",
              found == "transcripts/arhiva/" + gen, found)
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


# ── 4. flag off: 3.7 files, byte for byte ───────────────────────────────────


async def g_flag_off(host_id, stream, tx_sid):
    print("== flag off: the 3.7 hub writes the same files ==")
    st = txhub.store()
    txhub.uninstall()
    check("flag off: txhub inactive", not txhub.active())
    sid = await new_session(host_id)
    hub = await hub_for(sid)
    check("flag off: the 3.7 handles are open", hub._tx is None and hub.out_f is not None)
    await hub.ensure_attached(Ring("e1"))
    for c in stream:
        await hub.on_output(c)
    hub.teardown()
    out_p, cast_p = core.transcript_paths(sid)
    out = out_p.read_bytes()
    check("flag off: .out = the stream, byte for byte", out == b"".join(stream))
    hdr, ev = cast_events(cast_p.read_bytes())
    check("flag off: .cast header and events as 3.7",
          hdr == {"version": 2, "width": 80, "height": 24, "timestamp": 1795305600}
          and [e[2] for e in ev] == [c.decode() for c in stream] and all(e[1] == "o" for e in ev))
    rows = [await db.fetchone("SELECT 1 FROM %s WHERE sid=?" % t, sid)
            for t in ("session_keys", "tx_descriptors", "tx_files")]
    check("flag off: no tx rows for the session", rows == [None, None, None])
    check("flag off: no generation file for the session",
          not [n for n in os.listdir(config.TRANSCRIPT_DIR) if n.startswith(sid + ".") and n.endswith(".wtx")])
    txhub.install(st)
    check("same stream: the decrypted encrypted .out equals the 3.7 .out", await decrypt(tx_sid) == out)
    _h, tev = cast_events(await decrypt(tx_sid, "cast"))
    check("same stream: same .cast events (times aside)", [e[1:] for e in tev] == [e[1:] for e in ev])
    check("encrypted session wrote no plaintext .out/.cast",
          not any(p.exists() for p in core.transcript_paths(tx_sid)))


async def stream_session(host_id, stream):
    sid = await new_session(host_id)
    hub = await hub_for(sid)
    await hub.ensure_attached(Ring("e1"))
    for c in stream:
        await hub.on_output(c)
    await settle(hub._tx)
    await close_hub(hub)
    return sid


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    try:
        await g_boot_clean()
        ts.create_test_volume(config.DB_PATH)            # înainte de orice users / hosts
        c = client()
        r = await c.post("/api/setup", json={"email": "o@x.co", "password": "parolabuna1",
                                             "setup_token": "test-setup"})
        assert r.status_code == 200, r.text
        token = c.cookies.get(security.COOKIE_NAME)
        uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]
        host_id = (await c.post("/api/hosts", json={"name": "h1"})).json()["id"]
        st = ts.Store(transcripts_dir=config.TRANSCRIPT_DIR, kwk=KWK, installation_id=INST)
        await st.recover()
        txhub.install(st)
        check("txhub active on the test volume", txhub.active())
        sid, expect = await g_hub_ring(host_id)
        await g_hub_ringless(host_id)
        await g_boot_after()
        await g_routes(c, host_id, uid, token, sid, expect)
        big, data = await big_recording(host_id)
        r = await c.get(f"/api/sessions/{big}/transcript?format=out")
        check("multi-chunk download byte-identical", r.status_code == 200 and r.content == data)
        secret = await secret_recording(host_id)
        await g_replay(c, big, secret)
        await g_stream_revocation(c, uid, token, big, data)
        await g_logout(big)
        await g_access_gen()
        c, token = await login()             # cookie-ul iniţial a expirat în g_stream_revocation
        await g_ws_history(c, host_id, uid, token)
        await g_emission(c, uid, token, big, data)
        await g_finalize(host_id)
        await g_counters(c, host_id, uid, big)
        await g_admin()
        g_inventory()
        stream = [b"hello\r\n", b"\x1b[1mbold\x1b[0m\r\n", "ünï\r\n".encode(), b"x" * 3000]
        tx_sid = await stream_session(host_id, stream)
        await g_flag_off(host_id, stream, tx_sid)
    finally:
        await txhub.shutdown()
        await db.close()


asyncio.run(main())
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
import shutil  # noqa: E402
shutil.rmtree(BASE, ignore_errors=True)
sys.exit(1 if failed else 0)
