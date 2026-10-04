"""Agent v55 — upload chunk BINAR (FRAME_FSWRITE) + CRC-32 incremental pe host.

Hermetic: fără gateway, fără pty real, fără socketul tmux de producţie. HOME e sandboxat ÎNAINTE
de import, iar op-urile se apelează direct pe un `Agent` construit cu `object.__new__` (fără
`__init__`, care ar scrie tmux.conf), cu `send_ctrl` înlocuit de o captură — exact ca agent_v54_test.

Acoperă: round-trip-ul blocului binar (octeţii aterizează la offset), refuzul la offset_conflict,
refuzul pe fişier ne-obişnuit (symlink prin O_NOFOLLOW / director), CRC-ul incremental == zlib.crc32
peste aceiaşi octeţi (inclusiv după un resume seed-uit de pe worker), calea de resume LA RECE
(crc32=None când baza nu e cunoscută ieftin) şi ignorarea unui frame malformat."""
import os
import queue
import struct
import sys
import tempfile
import threading
import time
import zlib

os.environ["HOME"] = tempfile.mkdtemp(prefix="v55-home-")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import ptyd  # noqa: E402

os.makedirs(ptyd.WEBTERM_DIR, exist_ok=True)
ok_n = 0
total = 0


def check(name, cond, detail=""):
    global ok_n, total
    total += 1
    ok_n += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


def fake_agent():
    ag = object.__new__(ptyd.Agent)
    ag.replies = []
    ag.send_ctrl = ag.replies.append
    ag._crc_q, ag._crc_lock, ag._crc_workers = queue.Queue(), threading.Lock(), 0
    ag._upload_crc, ag._upload_crc_lock = {}, threading.Lock()
    return ag


def by_id(ag, rid):
    return next((r for r in ag.replies if r.get("id") == rid), None)


def wait_for(pred, t=5.0):
    dl = time.time() + t
    while time.time() < dl:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def frame(rid, off, path, data):
    """Corpul unui FRAME_FSWRITE FĂRĂ octetul de tip (dispatch-ul îl decupează înainte de handler)."""
    pb = path.encode("utf-8")
    return struct.pack(">QQH", rid, off, len(pb)) + pb + data


tmp = tempfile.mkdtemp(prefix="v55-")

# ───────────────────────── versiune ─────────────────────────
check("AGENT_VERSION == 55", ptyd.AGENT_VERSION == 55, ptyd.AGENT_VERSION)
check("FRAME_FSWRITE == b'W'", ptyd.FRAME_FSWRITE == b"W", ptyd.FRAME_FSWRITE)
check("antetul binar e >QQH (rid, offset, path_len)", ptyd.FSWRITE_HDR.format in (">QQH", b">QQH"),
      ptyd.FSWRITE_HDR.format)

# ───────────────────────── 1. round-trip binar la offset 0 + append ─────────────────────────
ag = fake_agent()
path = os.path.join(tmp, "up.bin")
d0 = b"primul-bloc-" * 1000
ptyd.Agent._handle_fs_write_bin(ag, frame(1, 0, path, d0))
r = by_id(ag, 1)
check("write binar offset 0: ok + written + offset", r and r["ok"] and r["written"] == len(d0) and r["offset"] == len(d0), r)
check("write binar offset 0: crc32 == zlib.crc32(d0)", r and r["crc32"] == (zlib.crc32(d0) & 0xffffffff), r)
check("octeţii au aterizat pe disc", open(path, "rb").read() == d0)

d1 = b"al-doilea-" * 777
ptyd.Agent._handle_fs_write_bin(ag, frame(2, len(d0), path, d1))
r = by_id(ag, 2)
check("append binar: offset acumulat corect", r and r["ok"] and r["offset"] == len(d0) + len(d1), r)
check("append binar: crc32 incremental == zlib.crc32(d0+d1)",
      r and r["crc32"] == (zlib.crc32(d0 + d1) & 0xffffffff), r)
check("conţinutul concatenat pe disc", open(path, "rb").read() == d0 + d1)

# ───────────────────────── 2. offset_conflict (anti-dublare orbă) ─────────────────────────
ag2 = fake_agent()
pc = os.path.join(tmp, "conf.bin")
ptyd.Agent._handle_fs_write_bin(ag2, frame(10, 0, pc, b"abcd"))
ptyd.Agent._handle_fs_write_bin(ag2, frame(11, 999, pc, b"XXXX"))   # offset != dimensiune
r = by_id(ag2, 11)
check("offset greşit → ok False + code offset_conflict", r and r["ok"] is False and r["code"] == "offset_conflict", r)
check("fişierul NU a fost modificat la conflict", open(pc, "rb").read() == b"abcd")

# ───────────────────────── 3. fişier ne-obişnuit refuzat ─────────────────────────
ag3 = fake_agent()
# symlink: O_NOFOLLOW la offset 0 → ELOOP → fs_error (nu scriem prin link)
link = os.path.join(tmp, "lnk")
os.symlink(os.path.join(tmp, "target-inexistent"), link)
ptyd.Agent._handle_fs_write_bin(ag3, frame(20, 0, link, b"nu"))
r = by_id(ag3, 20)
check("write prin symlink (O_NOFOLLOW) → fs_error", r and r["ok"] is False and r["code"] == "fs_error", r)
# director: append (offset>0) pe un director → EISDIR → fs_error
ptyd.Agent._handle_fs_write_bin(ag3, frame(21, 5, tmp, b"nu"))
r = by_id(ag3, 21)
check("append pe un director → fs_error", r and r["ok"] is False and r["code"] == "fs_error", r)

# ───────────────────────── 4. resume seed-uit de pe worker (fs_crc32 seed=True) ─────────────────────────
ag4 = fake_agent()
pr = os.path.join(tmp, "resume.bin")
prefix = b"prefix-urcat-in-alta-sesiune-" * 500
with open(pr, "wb") as f:
    f.write(prefix)
# starea in-memory e goală (agent repornit / altă sesiune) → seed de pe worker
ptyd.Agent.handle_ctrl(ag4, {"op": "fs_crc32", "id": 30, "path": pr, "seed": True})
check("fs_crc32 seed: handler NU răspunde sincron (lucrul e pe worker)", by_id(ag4, 30) is None)
check("fs_crc32 seed: reply de pe worker cu CRC + size al octeţilor pe disc",
      wait_for(lambda: by_id(ag4, 30) is not None)
      and by_id(ag4, 30)["crc32"] == (zlib.crc32(prefix) & 0xffffffff)
      and by_id(ag4, 30)["size"] == len(prefix), by_id(ag4, 30))
check("seed-ul a populat _upload_crc cu (size, crc)",
      ag4._upload_crc.get(pr) == (len(prefix), zlib.crc32(prefix) & 0xffffffff), ag4._upload_crc.get(pr))
# append-ul de după seed continuă CRC-ul incremental, FĂRĂ a re-citi prefixul pe loop
tail = b"coada-noua-" * 300
ptyd.Agent._handle_fs_write_bin(ag4, frame(31, len(prefix), pr, tail))
r = by_id(ag4, 31)
check("append după resume seed: crc32 == zlib.crc32(prefix+tail)",
      r and r["crc32"] == (zlib.crc32(prefix + tail) & 0xffffffff), r)
check("fişierul de resume e corect pe disc", open(pr, "rb").read() == prefix + tail)

# ───────────────────────── 5. resume LA RECE (fără seed): crc32=None, dar scrie corect ─────────────────────────
ag5 = fake_agent()
pc2 = os.path.join(tmp, "cold.bin")
base = b"deja-pe-disc-" * 100
with open(pc2, "wb") as f:
    f.write(base)
tail2 = b"appendat"
ptyd.Agent._handle_fs_write_bin(ag5, frame(40, len(base), pc2, tail2))
r = by_id(ag5, 40)
check("resume la rece: ok + crc32 None (baza necunoscută ieftin)",
      r and r["ok"] and r["crc32"] is None and r["offset"] == len(base) + len(tail2), r)
check("resume la rece: octeţii aterizează corect oricum", open(pc2, "rb").read() == base + tail2)

# ───────────────────────── 6. frame malformat ignorat (fără rid de încredere) ─────────────────────────
ag6 = fake_agent()
before = len(ag6.replies)
ptyd.Agent._handle_fs_write_bin(ag6, b"\x00\x01")   # prea scurt pt. antet
check("frame malformat: niciun reply (nu putem corela fără rid)", len(ag6.replies) == before)

# ═════════════════════════ GATEWAY: negocierea de versiune v54 vs v55 ═════════════════════════
# Mock la nivel de frame (ca update_check_test): un FakeAgent(core.AgentConnection) ţine fişierele în
# RAM şi numără apelurile. Verificăm că gateway-ul (întotdeauna actualizat ÎNAINTEA agenţilor) vorbeşte
# AMBELE protocoale: base64 `fs_write` + fs_crc32-la-commit către v54, FRAME_FSWRITE + CRC incremental
# (fără re-citire la commit) către v55; şi că la ambele un CRC greşit opreşte commit-ul.
import asyncio  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
from app import core  # noqa: E402


class FakeAgent(core.AgentConnection):
    """Agent fals: fişiere în RAM, numără fs_write binar/base64 şi fs_crc32 (re-citirea completă)."""
    def __init__(self, host_id, ver):
        self.host_id = host_id
        self.agent_version = ver
        self.files = {}          # path -> bytearray
        self.bin_writes = 0
        self.b64_writes = 0
        self.crc_calls = 0

    async def fs_write_bin(self, path, offset, block, timeout=60.0):
        self.bin_writes += 1
        cur = len(self.files.get(path, b""))
        if offset != cur:
            return {"ok": False, "code": "offset_conflict", "msg": "size %d != offset %d" % (cur, offset)}
        self.files.setdefault(path, bytearray()).extend(block)
        return {"ok": True, "written": len(block), "offset": cur + len(block),
                "crc32": zlib.crc32(bytes(self.files[path])) & 0xffffffff}

    async def request(self, op, timeout=20.0, **kw):
        if op == "fs_write":                       # calea base64 (agent v54)
            self.b64_writes += 1
            import base64 as _b64
            data = _b64.b64decode(kw["data_b64"])
            path, offset = kw["path"], kw["offset"]
            cur = len(self.files.get(path, b""))
            if offset != cur:
                return {"ok": False, "code": "offset_conflict", "msg": "conflict"}
            self.files.setdefault(path, bytearray()).extend(data)
            return {"ok": True, "written": len(data)}
        if op == "fs_stat":
            p = kw["path"]
            if p in self.files:
                return {"ok": True, "exists": True, "size": len(self.files[p])}
            return {"ok": True, "exists": False, "size": 0}
        if op == "fs_crc32":                       # re-citirea COMPLETĂ (ce voiam să evităm pe v55)
            self.crc_calls += 1
            return {"ok": True, "crc32": zlib.crc32(bytes(self.files.get(kw["path"], b""))) & 0xffffffff,
                    "size": len(self.files.get(kw["path"], b""))}
        if op == "fs_rename":
            self.files[kw["to"]] = self.files.pop(kw["path"], bytearray())
            return {"ok": True, "path": kw["to"]}
        if op == "fs_delete":
            self.files.pop(kw["path"], None)
            return {"ok": True}
        return {"ok": True}


async def _gw_scenario(ver):
    hid = 900 + ver
    fake = FakeAgent(hid, ver)
    core.sources[hid] = fake
    uid = ("%032x" % ver)                          # 32 hex, trece de _UPLOAD_UID
    dest = "/home/u/big.bin"
    payload = bytes((i * 13 + 7) % 256 for i in range(3 * 1024 * 1024 + 123))   # multi-bloc
    want_crc = zlib.crc32(payload) & 0xffffffff
    try:
        async def src(b):
            yield b
        # două chunk-uri (resumabil): [0, half) apoi [half, end)
        half = 1 * 1024 * 1024
        off = await core.fs_upload_chunk(hid, dest, uid, 0, src(payload[:half]))
        off = await core.fs_upload_chunk(hid, dest, uid, off, src(payload[half:]))
        landed = len(fake.files[core._upload_tmp(dest, uid)])
        # commit cu CRC bun
        written = await core.fs_upload_commit(hid, dest, uid, crc32=want_crc)
        committed = bytes(fake.files.get(dest, b""))
        return fake, off, landed, written, committed
    finally:
        core.sources.pop(hid, None)
        core._upload_offset.pop((hid, uid), None)
        core._upload_crc.pop((hid, uid), None)
        core._upload_locks.pop((hid, uid), None)


async def _gw_mismatch(ver):
    hid = 950 + ver
    fake = FakeAgent(hid, ver)
    core.sources[hid] = fake
    uid = ("%032x" % (ver + 1))
    dest = "/home/u/corrupt.bin"
    payload = b"integritatea-conteaza-" * 1000
    try:
        async def src(b):
            yield b
        await core.fs_upload_chunk(hid, dest, uid, 0, src(payload))
        failed = False
        try:
            await core.fs_upload_commit(hid, dest, uid, crc32=0xDEADBEEF)   # CRC greşit
        except core.FileError:
            failed = True
        tmp_gone = core._upload_tmp(dest, uid) not in fake.files
        committed = dest in fake.files
        return failed, tmp_gone, committed
    finally:
        core.sources.pop(hid, None)
        core._upload_offset.pop((hid, uid), None)
        core._upload_crc.pop((hid, uid), None)
        core._upload_locks.pop((hid, uid), None)


async def _gw_tests():
    # v55: FRAME_FSWRITE, zero apeluri base64, zero re-citiri complete la commit
    f, off, landed, written, committed = await _gw_scenario(55)
    check("v55: gateway a folosit FRAME_FSWRITE (write-uri binare)", f.bin_writes > 0 and f.b64_writes == 0,
          "bin=%d b64=%d" % (f.bin_writes, f.b64_writes))
    check("v55: upload complet + commit, octeţi corecţi",
          written == len(committed) and zlib.crc32(committed) & 0xffffffff
          == zlib.crc32(bytes(bytearray((i * 13 + 7) % 256 for i in range(3 * 1024 * 1024 + 123)))) & 0xffffffff,
          "written=%d landed=%d" % (written, landed))
    check("v55: commit NU a re-citit tot fişierul (CRC incremental cache-uit)", f.crc_calls == 0, f.crc_calls)

    # v54: base64, re-citire completă la commit (fs_crc32), fără write-uri binare
    f, off, landed, written, committed = await _gw_scenario(54)
    check("v54: gateway a folosit base64 fs_write (fără frame-uri binare)", f.b64_writes > 0 and f.bin_writes == 0,
          "bin=%d b64=%d" % (f.bin_writes, f.b64_writes))
    check("v54: commit a verificat CRC prin re-citire completă (fs_crc32)", f.crc_calls >= 1, f.crc_calls)

    # CRC greşit opreşte commit-ul pe AMBELE versiuni (temp şters, ţinta neatinsă)
    for ver in (54, 55):
        failed, tmp_gone, committed = await _gw_mismatch(ver)
        check("v%d: CRC greşit → commit eşuează" % ver, failed)
        check("v%d: temp-ul corupt e şters, ţinta neatinsă" % ver, tmp_gone and not committed)


asyncio.run(_gw_tests())

print("\n%d/%d checks passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
