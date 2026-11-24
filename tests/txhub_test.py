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
  * flag off: the same fixed stream through the 3.7 hub writes the same .out/.cast as before
    (and the logical content of the encrypted recording), no tx rows, no generation files.
Temp dirs + the real db module; no network, no Docker.
"""
import asyncio
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

from app import admin, api, authz, config, core, db, replay, security, share_api, txhub  # noqa: E402
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
