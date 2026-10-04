"""Fereastra de reordonare a upload-ului PIPELINED (transfers phase 2, gateway core).

Hermetic: fără agent real, fără pty, fără reţea. Un `FakeAgent` ţine temp-ul în RAM şi se poartă
EXACT ca agentul v55 — `fs_write_bin` adaugă la offset şi REFUZĂ cu `offset_conflict` orice scriere
la offset != dimensiunea curentă (constrângerea care obligă gateway-ul să aplice feliile în ordine),
şi întoarce CRC-ul incremental al octeţilor de pe disc.

Acoperă: aplicarea ÎN ORDINE a feliilor secvenţiale, o felie DEZORDONATĂ ţinută în buffer apoi
flush-uită când se umple gap-ul, CRC-ul incremental corect după reordonare, bufferul MĂRGINIT
(peste plafon → UploadBusy/429), şi idempotenţa unui retry al unei felii deja aterizate.
"""
import asyncio
import os
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
from app import core  # noqa: E402

ok_n = 0
total = 0


def check(name, cond, detail=""):
    global ok_n, total
    total += 1
    ok_n += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


class FakeAgent(core.AgentConnection):
    """Agent v55 fals: temp în RAM, fs_write_bin strict-append + offset_conflict, CRC incremental."""

    def __init__(self, host_id, ver=55):
        self.host_id = host_id
        self.agent_version = ver
        self.files = {}          # path -> bytearray

    async def fs_write_bin(self, path, offset, block, timeout=60.0):
        cur = len(self.files.get(path, b""))
        if offset != cur:        # EXACT constrângerea agentului: append strict la dimensiune
            return {"ok": False, "code": "offset_conflict",
                    "msg": "size %d != offset %d" % (cur, offset)}
        self.files.setdefault(path, bytearray()).extend(block)
        return {"ok": True, "written": len(block), "offset": cur + len(block),
                "crc32": zlib.crc32(bytes(self.files[path])) & 0xffffffff}

    async def request(self, op, timeout=20.0, **kw):
        if op == "fs_stat":
            p = kw["path"]
            if p in self.files:
                return {"ok": True, "exists": True, "size": len(self.files[p]), "dir": False}
            return {"ok": True, "exists": False, "size": 0}
        if op == "fs_rename":
            self.files[kw["to"]] = self.files.pop(kw["path"], bytearray())
            return {"ok": True, "path": kw["to"]}
        if op == "fs_delete":
            self.files.pop(kw["path"], None)
            return {"ok": True}
        return {"ok": True}


def _cleanup(hid, uid):
    key = (hid, uid)
    core.sources.pop(hid, None)
    core._upload_offset.pop(key, None)
    core._upload_crc.pop(key, None)
    core._upload_locks.pop(key, None)
    core._upload_windows.pop(key, None)


async def one_chunk(hid, dest, uid, offset, data):
    async def src():
        yield data
    return await core.fs_upload_chunk(hid, dest, uid, offset, src())


async def t_in_order():
    hid, uid, dest = 7001, "a" * 32, "/home/u/seq.bin"
    fake = FakeAgent(hid)
    core.sources[hid] = fake
    tmp = core._upload_tmp(dest, uid)
    payload = bytes((i * 7 + 3) % 256 for i in range(2500))
    C = 1000
    try:
        off = await one_chunk(hid, dest, uid, 0, payload[0:C])
        off = await one_chunk(hid, dest, uid, C, payload[C:2 * C])
        off = await one_chunk(hid, dest, uid, 2 * C, payload[2 * C:])
        landed = bytes(fake.files[tmp])
        check("secvenţial: toate feliile aplicate în ordine, octeţi corecţi", landed == payload, len(landed))
        check("secvenţial: offset final == dimensiunea fişierului", off == len(payload), off)
        check("secvenţial: CRC incremental de pe gateway == zlib al întregului fişier",
              core._upload_crc.get((hid, uid)) == zlib.crc32(payload) & 0xffffffff)
    finally:
        _cleanup(hid, uid)


async def t_out_of_order():
    """Felia a doua soseşte PRIMA (offset > curent): e ţinută în buffer; felia 0 umple gap-ul şi le
    scrie pe ambele, în ordine. Octeţii şi CRC-ul rămân corecţi, deşi cererile au venit răsturnat."""
    hid, uid, dest = 7002, "b" * 32, "/home/u/ooo.bin"
    fake = FakeAgent(hid)
    core.sources[hid] = fake
    tmp = core._upload_tmp(dest, uid)
    payload = bytes((i * 13 + 1) % 256 for i in range(2000))
    C = 1000
    try:
        # felia @C porneşte prima şi se PARCHEAZĂ (gap înaintea ei neumplut)
        task_b = asyncio.create_task(one_chunk(hid, dest, uid, C, payload[C:]))
        # îi dăm timp să depună în pending şi să intre în aşteptare
        for _ in range(50):
            await asyncio.sleep(0.005)
            win = core._upload_windows.get((hid, uid))
            if win and C in win.pending:
                break
        win = core._upload_windows.get((hid, uid))
        held = bool(win and C in win.pending) and bytes(fake.files.get(tmp, b"")) == b""
        check("dezordonat: felia sosită înaintea rândului e ŢINUTĂ în buffer, nescrisă încă", held,
              "pending=%s files=%d" % (list(win.pending) if win else None, len(fake.files.get(tmp, b""))))
        check("dezordonat: bufferul contorizează octeţii ţinuţi", win and win.buffered == C, win.buffered if win else None)
        # felia 0 umple gap-ul → drain în ordine → ambele aterizează, task_b se trezeşte
        off0 = await one_chunk(hid, dest, uid, 0, payload[0:C])
        off_b = await task_b
        landed = bytes(fake.files[tmp])
        check("dezordonat: după umplerea gap-ului, fişierul e complet şi în ordine", landed == payload, len(landed))
        check("dezordonat: ambele cereri raportează offset-ul final", off0 == len(payload) and off_b == len(payload),
              "off0=%s off_b=%s" % (off0, off_b))
        check("dezordonat: CRC incremental corect (octeţii au ajuns la agent în ordine)",
              core._upload_crc.get((hid, uid)) == zlib.crc32(payload) & 0xffffffff)
        check("dezordonat: bufferul s-a golit la zero după flush", core._upload_windows[(hid, uid)].buffered == 0)
    finally:
        _cleanup(hid, uid)


async def t_bounded_buffer():
    """Peste plafonul ferestrei → UploadBusy (429). Micşorăm plafonul ca testul să rămână ieftin."""
    hid, uid, dest = 7003, "c" * 32, "/home/u/big.bin"
    fake = FakeAgent(hid)
    core.sources[hid] = fake
    saved = core.UPLOAD_WINDOW_MAX
    core.UPLOAD_WINDOW_MAX = 150        # plafon minuscul pentru test
    try:
        # o felie dezordonată de 100 octeţi (offset 500 > curent 0) încape
        task = asyncio.create_task(one_chunk(hid, dest, uid, 500, b"x" * 100))
        for _ in range(50):
            await asyncio.sleep(0.005)
            win = core._upload_windows.get((hid, uid))
            if win and 500 in win.pending:
                break
        # a doua felie dezordonată (încă 100) ar depăşi 150 → UploadBusy
        busy = False
        try:
            await one_chunk(hid, dest, uid, 700, b"y" * 100)
        except core.UploadBusy:
            busy = True
        check("plafon: a doua felie peste prag → UploadBusy (429)", busy)
        # curăţăm task-ul parcat (altfel atârnă până la WINDOW_WAIT)
        win = core._upload_windows.get((hid, uid))
        if win:
            win.pending.pop(500, None)
            async with win.cond:
                win.cond.notify_all()
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, core.FileError):
            pass
    finally:
        core.UPLOAD_WINDOW_MAX = saved
        _cleanup(hid, uid)


async def t_idempotent_dup():
    """Un retry al unei felii DEJA aterizate (ack pierdut) e idempotent: întoarce offset-ul curent,
    NU rescrie octeţii (fără dublare în temp, CRC neschimbat)."""
    hid, uid, dest = 7004, "d" * 32, "/home/u/dup.bin"
    fake = FakeAgent(hid)
    core.sources[hid] = fake
    tmp = core._upload_tmp(dest, uid)
    data = b"felia-unu-" * 50
    try:
        off1 = await one_chunk(hid, dest, uid, 0, data)
        crc1 = core._upload_crc.get((hid, uid))
        off2 = await one_chunk(hid, dest, uid, 0, data)      # EXACT aceeaşi felie, din nou
        check("idempotent: retry-ul feliei aterizate întoarce acelaşi offset", off1 == off2 == len(data),
              "%s %s" % (off1, off2))
        check("idempotent: temp-ul NU s-a dublat", bytes(fake.files[tmp]) == data, len(fake.files[tmp]))
        check("idempotent: CRC neschimbat după retry", core._upload_crc.get((hid, uid)) == crc1)
    finally:
        _cleanup(hid, uid)


async def main():
    await t_in_order()
    await t_out_of_order()
    await t_bounded_buffer()
    await t_idempotent_dup()


asyncio.run(main())
print("\n%d/%d checks passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
