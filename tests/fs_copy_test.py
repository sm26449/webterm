"""Copiere host → host pe server (3.5.5): `POST/GET/DELETE /api/fs/copy`.

Hermetic: fără agent real, fără reţea. Doi `FakeAgent` (v57) ţin un sistem de fişiere în RAM şi se
poartă ca agentul: `fs_stat` (lstat), `fs_read` în felii (cu size/mtime/eof şi refuzul fişierelor
speciale), `fs_write_bin` strict-append cu CRC incremental, `fs_rename` (overwrite păstrează modul),
`fs_delete`, `fs_list` (canonizează `~`). Gateway-ul real (ASGI, in-process) face restul — inclusiv
maşinăria de upload (`fs_upload_chunk` / `fs_upload_commit`) prin care trece copierea.

Acoperă: copiere multi-fişier (conţinut identic), CRC verificat (o destinaţie care strică octeţii
e prinsă la commit, fişierul nu aterizează), on_conflict skip / overwrite / rename, anularea la
mijlocul unui fişier (temp-ul de pe destinaţie şters, fişierele deja copiate rămân), eroare de
citire pe sursă raportată per fişier (job-ul continuă), step-up cerut pe ORICARE capăt, token de
automatizare → 401, traversare refuzată, plafonul de 1000 de fişiere, fişier special refuzat,
folderele copiate (detaliile în fs_copy_folders), src == dst, memoria mărginită (câteva felii, nu fişierul întreg),
concurenţa mărginită, izolarea job-urilor pe user + TTL.
"""
import asyncio
import base64
import os
import sys
import tempfile
import zlib

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, fscopy, security  # noqa: E402
from app.main import app  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
PW = "parola-cont-123456"
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


READ_CHUNK = 64 * 1024        # felia de fs_read a agentului fals (cel real: 256 KiB)
HOME = "/home/u"


class FakeAgent(core.AgentConnection):
    """Agent v57 fals: fişiere în RAM (cale absolută → bytearray), directoare ca set."""

    def __init__(self, host_id):
        self.host_id = host_id
        self.agent_version = 57
        self.files = {}
        self.modes = {}
        self.dirs = {"/", "/home", HOME, "/dev", "/tmp"}
        self.special = {"/dev/zero"}
        self.links = {}                 # cale → ţintă (symlink spre fişier)
        self.read_fail = {}             # cale → offset de la care fs_read eşuează
        self.corrupt = False            # destinaţie care strică primul octet al fiecărui bloc
        self.write_gate = None          # asyncio.Event: al DOILEA bloc spre o cale cu `gate_match` aşteaptă
        self.gate_match = ""
        self.write_delay = 0.0
        self.open_tmp = set()
        self.max_open_tmp = 0
        self.mtime = 1700000000

    def _abs(self, p):
        if p == "~":
            return HOME
        if p.startswith("~/"):
            p = HOME + p[1:]
        return os.path.normpath(p)

    async def fs_write_bin(self, path, offset, block, timeout=60.0):
        if (self.write_gate is not None and self.gate_match and self.gate_match in path
                and len(self.files.get(self._abs(path), b""))):
            await self.write_gate.wait()     # temp-ul există deja (primul bloc a aterizat)
        if self.write_delay:
            await asyncio.sleep(self.write_delay)
        p = self._abs(path)
        cur = len(self.files.get(p, b""))
        if offset != cur:
            return {"ok": False, "code": "offset_conflict", "msg": "size %d != offset %d" % (cur, offset)}
        data = bytearray(block)
        if self.corrupt and data:
            data[0] ^= 0xFF
        self.files.setdefault(p, bytearray()).extend(data)
        if ".wtpart." in p:
            self.open_tmp.add(p)
            self.max_open_tmp = max(self.max_open_tmp, len(self.open_tmp))
        return {"ok": True, "written": len(block), "crc32": zlib.crc32(bytes(self.files[p])) & 0xffffffff}

    async def request(self, op, timeout=20.0, **kw):
        await asyncio.sleep(0)
        p = self._abs(kw.get("path") or "~")
        if op == "fs_stat":
            if p in self.dirs:
                return {"ok": True, "exists": True, "size": 4096, "dir": True, "link": False}
            if p in self.links:
                return {"ok": True, "exists": True, "size": len(self.links[p]), "dir": False, "link": True}
            if p in self.files or p in self.special:
                return {"ok": True, "exists": True, "size": len(self.files.get(p, b"")), "dir": False,
                        "link": False, "mtime": self.mtime}
            return {"ok": True, "exists": False, "size": 0}
        if op == "fs_list":
            if p not in self.dirs:
                return {"ok": False, "msg": "%s: No such file or directory" % p}
            pre = p.rstrip("/") + "/"
            entries = [{"name": f[len(pre):], "dir": False, "size": len(b), "mtime": self.mtime}
                       for f, b in self.files.items() if f.startswith(pre) and "/" not in f[len(pre):]]
            return {"ok": True, "path": p, "parent": os.path.dirname(p), "entries": entries, "truncated": False}
        if op == "fs_read":
            real = self.links.get(p, p)
            if real in self.special or real in self.dirs:
                return {"ok": False, "msg": "%s: not a regular file (directory/device/socket/FIFO)" % p}
            if real not in self.files:
                return {"ok": False, "msg": "%s: No such file or directory" % p}
            off = int(kw.get("offset", 0))
            if p in self.read_fail and off >= self.read_fail[p]:
                return {"ok": False, "msg": "%s: Input/output error" % p}
            data = bytes(self.files[real])
            chunk = data[off:off + READ_CHUNK]
            return {"ok": True, "size": len(data), "mtime": self.mtime, "eof": off + len(chunk) >= len(data),
                    "data_b64": base64.b64encode(chunk).decode()}
        if op == "fs_rename":
            to = self._abs(kw["to"])
            if to in self.dirs:
                return {"ok": False, "msg": "Is a directory"}
            keep = self.modes.get(to)
            self.files[to] = self.files.pop(p, bytearray())
            self.open_tmp.discard(p)
            self.modes[to] = keep if keep is not None else 0o644
            return {"ok": True, "path": to}
        if op == "fs_delete":
            self.files.pop(p, None)
            self.open_tmp.discard(p)
            return {"ok": True}
        if op == "fs_crc32":
            return {"ok": True, "crc32": zlib.crc32(bytes(self.files.get(p, b""))) & 0xffffffff}
        return {"ok": True}


def blob(n, seed=1):
    return bytes((i * 31 + seed) % 251 for i in range(n))


async def wait_done(c, jid, ms=15000):
    t = 0
    while t < ms:
        r = await c.get("/api/fs/copy/%s?files=1" % jid)
        j = r.json()
        if j.get("state") != "running":
            return j
        await asyncio.sleep(0.02)
        t += 20
    return j


def tmps(agent):
    return [p for p in agent.files if ".wtpart." in p]


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW, "setup_token": "test-setup"})
        uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]
        A = (await c.post("/api/hosts", json={"name": "alpha"})).json()["id"]
        B = (await c.post("/api/hosts", json={"name": "beta"})).json()["id"]
        a, b = FakeAgent(A), FakeAgent(B)
        core.sources[A], core.sources[B] = a, b
        a.dirs.add(HOME + "/src")
        b.dirs.add(HOME + "/in")

        async def copy(paths, dst_dir=HOME + "/in", on_conflict="skip", src=A, dst=B):
            return await c.post("/api/fs/copy", json={"src_host": src, "paths": paths, "dst_host": dst,
                                                      "dst_dir": dst_dir, "on_conflict": on_conflict})

        # ── multi-fişier: conţinut identic, CRC verificat, fără temp rămas ──
        big = blob(3 * 1024 * 1024 + 12345)          # > un bloc de 1 MiB, nealiniat
        a.files[HOME + "/src/one.bin"] = bytearray(big)
        a.files[HOME + "/src/two.txt"] = bytearray(b"hello copy\n")
        a.files[HOME + "/src/empty"] = bytearray()
        r = await copy(["~/src/one.bin", "~/src/two.txt", HOME + "/src/empty"], dst_dir="~/in")
        check("POST /api/fs/copy → 200 + job_id", r.status_code == 200 and r.json().get("job_id"), r.text[:200])
        check("dst_dir canonizat (fs_list pe destinaţie: ~ → absolut)", r.json().get("dst_dir") == HOME + "/in", r.text)
        j = await wait_done(c, r.json()["job_id"])
        check("job terminat: done, 3/3 fişiere", j["state"] == "done" and j["files_done"] == 3, str(j)[:300])
        check("conţinut identic pe destinaţie (fişier mare)", bytes(b.files.get(HOME + "/in/one.bin", b"")) == big)
        check("fişier mic + fişier GOL copiate", bytes(b.files.get(HOME + "/in/two.txt", b"")) == b"hello copy\n"
              and HOME + "/in/empty" in b.files and len(b.files[HOME + "/in/empty"]) == 0)
        check("totaluri: total_bytes == done_bytes == suma mărimilor",
              j["total_bytes"] == j["done_bytes"] == len(big) + 11, (j["total_bytes"], j["done_bytes"]))
        check("niciun .wtpart rămas pe destinaţie", not tmps(b), tmps(b))
        check("sursa neatinsă", bytes(a.files[HOME + "/src/one.bin"]) == big)
        check("concurenţă mărginită: ≤ COPY_PARALLEL temp-uri deschise simultan",
              b.max_open_tmp <= fscopy.COPY_PARALLEL, b.max_open_tmp)
        rows = await db.fetchall("SELECT detail FROM audit_log WHERE path='/api/fs/copy' ORDER BY id DESC LIMIT 1")
        det = rows[0]["detail"] if rows else ""
        check("audit: „copy 3 files alpha:… → beta:/home/u/in”",
              det.startswith("copy 3 files alpha:") and det.endswith("→ beta:%s/in" % HOME), det)

        # ── CRC: o destinaţie care strică octeţii e prinsă la commit ──
        b.corrupt = True
        a.files[HOME + "/src/crc.bin"] = bytearray(blob(200000, 7))
        j = await wait_done(c, (await copy(["~/src/crc.bin"])).json()["job_id"])
        e = (j.get("errors") or [{}])[0]
        check("CRC nepotrivit → eroare per fişier (files.crcMismatch), job failed",
              j["state"] == "failed" and e.get("code") == "files.crcMismatch", str(j)[:300])
        check("fişierul corupt NU a aterizat (nici temp)", HOME + "/in/crc.bin" not in b.files and not tmps(b))
        b.corrupt = False

        # ── on_conflict ──
        b.files[HOME + "/in/two.txt"] = bytearray(b"OLD")
        b.modes[HOME + "/in/two.txt"] = 0o600
        j = await wait_done(c, (await copy(["~/src/two.txt"], on_conflict="skip")).json()["job_id"])
        check("skip: fişierul existent rămâne neatins, rândul e skipped",
              bytes(b.files[HOME + "/in/two.txt"]) == b"OLD" and j["files_skipped"] == 1 and j["state"] == "done",
              str(j)[:200])
        j = await wait_done(c, (await copy(["~/src/two.txt"], on_conflict="overwrite")).json()["job_id"])
        check("overwrite: conţinutul înlocuit (atomic, prin commit)",
              bytes(b.files[HOME + "/in/two.txt"]) == b"hello copy\n" and j["files_done"] == 1)
        check("overwrite: modul ţintei existente se păstrează (0600)", b.modes.get(HOME + "/in/two.txt") == 0o600)
        j = await wait_done(c, (await copy(["~/src/two.txt"], on_conflict="rename")).json()["job_id"])
        f = j["files"][0]
        check("rename: „two (1).txt”", f["dst"] == HOME + "/in/two (1).txt"
              and bytes(b.files.get(HOME + "/in/two (1).txt", b"")) == b"hello copy\n", str(f))
        j = await wait_done(c, (await copy(["~/src/two.txt"], on_conflict="rename")).json()["job_id"])
        check("rename din nou: „two (2).txt”", j["files"][0]["dst"] == HOME + "/in/two (2).txt", str(j["files"][0]))
        check("rename_candidate: extensii compuse + dotfiles",
              fscopy.rename_candidate("a.tar.gz", 1) == "a (1).tar.gz"
              and fscopy.rename_candidate(".bashrc", 2) == ".bashrc (2)"
              and fscopy.rename_candidate("Makefile", 3) == "Makefile (3)")
        r = await copy(["~/src/two.txt"], on_conflict="clobber")
        check("on_conflict necunoscut → 400 copy.badConflict", r.status_code == 400
              and r.headers.get("x-webterm-error") == "copy.badConflict")

        # ── eroare de citire pe sursă: raportată per fişier, job-ul continuă ──
        a.files[HOME + "/src/bad.bin"] = bytearray(blob(2 * 1024 * 1024, 3))
        a.read_fail[HOME + "/src/bad.bin"] = 1024 * 1024 + READ_CHUNK
        a.files[HOME + "/src/after.txt"] = bytearray(b"still copied")
        j = await wait_done(c, (await copy(["~/src/bad.bin", "~/src/after.txt"])).json()["job_id"])
        errs = {e["name"]: e for e in j.get("errors", [])}
        check("citire eşuată la mijloc → eroare per fişier, mesajul agentului păstrat",
              "bad.bin" in errs and "Input/output error" in errs["bad.bin"]["error"], str(j)[:300])
        check("…iar fişierul următor s-a copiat (job failed, nu oprit)",
              bytes(b.files.get(HOME + "/in/after.txt", b"")) == b"still copied" and j["state"] == "failed"
              and j["files_done"] == 1)
        check("…şi temp-ul fişierului eşuat a fost şters de pe destinaţie",
              HOME + "/in/bad.bin" not in b.files and not tmps(b), tmps(b))

        # ── fişier special + folder: refuzate per fişier ──
        j = await wait_done(c, (await copy(["/dev/zero", "~/src", "~/src/after.txt"], dst_dir="/tmp")).json()["job_id"])
        errs = {e["name"]: e for e in j.get("errors", [])}
        check("fişier special (/dev/zero) refuzat: files.notRegular",
              errs.get("zero", {}).get("code") == "files.notRegular", str(errs)[:300])
        check("folder (3.6 / agent 58): NU mai e refuzat — se copiază cu conţinutul (vezi fs_copy_folders)",
              "src" not in errs and bytes(b.files.get("/tmp/src/two.txt", b"")) == b"hello copy\n",
              str(errs)[:300])
        check("…restul job-ului s-a copiat", bytes(b.files.get("/tmp/after.txt", b"")) == b"still copied")

        # ── symlink spre fişier: se copiază conţinutul ţintei (ca download-ul) ──
        a.links[HOME + "/src/ln"] = HOME + "/src/two.txt"
        j = await wait_done(c, (await copy(["~/src/ln"], dst_dir="/tmp")).json()["job_id"])
        check("symlink → conţinutul ţintei, ca fişier obişnuit",
              bytes(b.files.get("/tmp/ln", b"")) == b"hello copy\n" and j["total_bytes"] == 11, str(j)[:200])

        # ── anulare la mijlocul unui fişier ──
        a.files[HOME + "/src/c1.txt"] = bytearray(b"first")
        a.files[HOME + "/src/c2.bin"] = bytearray(blob(4 * 1024 * 1024, 9))
        saved_par = fscopy.COPY_PARALLEL
        fscopy.COPY_PARALLEL = 1                     # ordine deterministă: c1 complet, apoi c2
        b.write_gate, b.gate_match = asyncio.Event(), "c2.bin"
        r = await copy(["~/src/c1.txt", "~/src/c2.bin"], dst_dir="/tmp")
        jid = r.json()["job_id"]
        for _ in range(1000):                         # c1 aterizat + temp-ul lui c2 început (blocat)
            if "/tmp/c1.txt" in b.files and tmps(b):
                break
            await asyncio.sleep(0.005)
        mid = tmps(b)
        r = await c.delete("/api/fs/copy/" + jid)
        b.write_gate.set()
        b.write_gate, b.gate_match = None, ""
        fscopy.COPY_PARALLEL = saved_par
        jj = r.json()
        check("DELETE → state cancelled", r.status_code == 200 and jj.get("state") == "cancelled", r.text[:200])
        check("anulare la mijlocul fişierului: temp-ul exista înainte", bool(mid), mid)
        check("…şi a fost ŞTERS de pe destinaţie la anulare", not tmps(b), tmps(b))
        check("…fişierul final nu există, cel deja copiat rămâne",
              "/tmp/c2.bin" not in b.files and bytes(b.files.get("/tmp/c1.txt", b"")) == b"first")
        r = await c.delete("/api/fs/copy/" + jid)
        check("DELETE idempotent pe un job terminat", r.status_code == 200 and r.json()["state"] == "cancelled")

        # ── memorie mărginită: destinaţie lentă, coada se umple, cititorul aşteaptă ──
        a.files[HOME + "/src/mem.bin"] = bytearray(blob(6 * 1024 * 1024, 5))
        b.write_delay = 0.01
        r = await copy(["~/src/mem.bin"], dst_dir="/tmp")
        jid = r.json()["job_id"]
        j = await wait_done(c, jid)
        b.write_delay = 0.0
        job = fscopy._jobs[jid]
        cap = fscopy.COPY_PREFETCH * READ_CHUNK + core.FS_CHUNK + READ_CHUNK
        check("memorie mărginită: vârful ţinut în gateway ≤ câteva felii + un bloc (nu fişierul de 6 MiB)",
              0 < job.peak_buffered <= cap, "peak=%d cap=%d" % (job.peak_buffered, cap))
        check("…şi după terminare nu mai ţine nimic", job.buffered == 0, job.buffered)
        check("…iar copia e corectă", bytes(b.files.get("/tmp/mem.bin", b"")) == bytes(a.files[HOME + "/src/mem.bin"]))

        # ── src == dst: permis (alt director / duplicat pe acelaşi host) ──
        a.dirs.add(HOME + "/other")
        j = await wait_done(c, (await copy(["~/src/two.txt"], dst_dir="~/other", dst=A)).json()["job_id"])
        check("acelaşi host, alt director: copiat", bytes(a.files.get(HOME + "/other/two.txt", b"")) == b"hello copy\n"
              and j["state"] == "done")
        j = await wait_done(c, (await copy(["~/src/two.txt"], dst_dir="~/src", dst=A,
                                           on_conflict="overwrite")).json()["job_id"])
        check("acelaşi fişier peste el însuşi (overwrite) → sărit, sursa intactă",
              j["files_skipped"] == 1 and bytes(a.files[HOME + "/src/two.txt"]) == b"hello copy\n", str(j)[:200])
        j = await wait_done(c, (await copy(["~/src/two.txt"], dst_dir="~/src", dst=A,
                                           on_conflict="rename")).json()["job_id"])
        check("acelaşi director + rename → duplicat „two (1).txt”",
              bytes(a.files.get(HOME + "/src/two (1).txt", b"")) == b"hello copy\n")

        # ── validare: traversare, căi relative, octeţi de control, nume duplicate ──
        for bad, why in ((["/home/u/../../etc/passwd"], ".. în sursă"), (["etc/passwd"], "cale relativă"),
                         (["/home/u/src/x\nINJ"], "newline"), (["/"], "rădăcina"), (["~"], "home-ul")):
            r = await copy(bad)
            check("traversare/cale invalidă refuzată (%s) → 400 copy.badPath" % why,
                  r.status_code == 400 and r.headers.get("x-webterm-error") == "copy.badPath", r.text[:200])
        r = await copy(["~/src/two.txt"], dst_dir="/home/u/in/../../../etc")
        check("dst_dir cu .. → 400 copy.badPath", r.status_code == 400
              and r.headers.get("x-webterm-error") == "copy.badPath")
        r = await copy(["~/src/two.txt"], dst_dir="~/nope")
        check("dst_dir inexistent → 400 files.notFound", r.status_code == 400
              and r.headers.get("x-webterm-error") == "files.notFound", r.text[:200])
        r = await copy(["/a/x.txt", "/b/x.txt"])
        check("două surse cu acelaşi nume → 400 copy.duplicateNames", r.status_code == 400
              and r.headers.get("x-webterm-error") == "copy.duplicateNames")
        r = await copy([])
        check("listă goală → 400 copy.empty", r.status_code == 400)

        # ── plafonul de 1000 de fişiere ──
        r = await copy(["/home/u/src/f%d" % i for i in range(fscopy.COPY_MAX_FILES + 1)])
        check("1001 fişiere → 400 copy.tooMany (vars.max=1000)", r.status_code == 400
              and r.headers.get("x-webterm-error") == "copy.tooMany" and '"max":1000' in r.headers.get(
                  "x-webterm-error-vars", ""), r.text[:200])
        for i in range(fscopy.COPY_MAX_FILES):
            a.files[HOME + "/src/m%04d" % i] = bytearray(b"%d" % i)
        b.dirs.add("/tmp/many")
        r = await copy([HOME + "/src/m%04d" % i for i in range(fscopy.COPY_MAX_FILES)], dst_dir="/tmp/many")
        check("exact 1000 fişiere → acceptat", r.status_code == 200, r.text[:200])
        j = await wait_done(c, r.json()["job_id"], ms=60000)
        check("…toate 1000 copiate", j["files_done"] == fscopy.COPY_MAX_FILES
              and bytes(b.files.get("/tmp/many/m0999", b"")) == b"999", str(j)[:200])
        r = await c.get("/api/fs/copy/%s" % r.json()["job_id"])
        check("GET fără files=1: fără lista completă (polling ieftin)", "files" not in r.json())

        # ── hosturi: offline / fără agent / inexistent ──
        core.sources.pop(B)
        r = await copy(["~/src/two.txt"])
        check("destinaţie offline → 409 host.offline", r.status_code == 409
              and r.headers.get("x-webterm-error") == "host.offline")
        core.sources[B] = b
        S = (await c.post("/api/hosts", json={"name": "sshy", "connection_type": "ssh", "hostname": "10.0.0.9",
                                              "ssh_username": "x", "auth_method": "password",
                                              "credential": "p"})).json().get("id")
        r = await copy(["~/src/two.txt"], dst=S) if S else None
        check("destinaţie fără agent → 400 copy.notAgent", r is not None and r.status_code == 400
              and r.headers.get("x-webterm-error") == "copy.notAgent", r.text[:200] if r is not None else S)
        r = await copy(["~/src/two.txt"], dst=99999)
        check("host inexistent → 404 host.missing", r.status_code == 404)

        # ── step-up pe ORICARE capăt ──
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", A)
        security.clear_stepup_for(uid)
        r = await copy(["~/src/two.txt"])
        check("sursa cu 2FA, fără step-up → 403 stepup.*", r.status_code == 403
              and r.headers.get("x-webterm-error", "").startswith("stepup."), r.text[:200])
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", A)
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", B)
        security.clear_stepup_for(uid)
        r = await copy(["~/src/two.txt"])
        check("destinaţia cu 2FA, fără step-up → 403 stepup.*", r.status_code == 403
              and r.headers.get("x-webterm-error", "").startswith("stepup."), r.text[:200])
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", A)
        security.open_stepup_window(uid, A)
        r = await copy(["~/src/two.txt"])
        check("step-up doar pe sursă, destinaţia tot 2FA → 403", r.status_code == 403)
        security.open_stepup_window(uid, B)
        r = await copy(["~/src/two.txt"])
        check("step-up pe AMBELE → 200", r.status_code == 200, r.text[:200])
        await wait_done(c, r.json()["job_id"])
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id IN (?, ?)", A, B)

        # ── izolare pe user + TTL ──
        jid = r.json()["job_id"]
        check("job-ul altui user = inexistent (get → None)", fscopy.get(jid, uid + 999) is None
              and fscopy.get(jid, uid) is not None)
        r = await c.get("/api/fs/copy/" + "0" * 32)
        check("job inexistent → 404 copy.missing", r.status_code == 404
              and r.headers.get("x-webterm-error") == "copy.missing")
        fscopy.purge(fscopy._jobs[jid].finished + fscopy.COPY_TTL + 1)
        check("TTL: job-ul terminat expiră din memorie", jid not in fscopy._jobs)
        r = await c.post("/api/tokens", json={"name": "auto", "scopes": ["read", "run"], "days": 30,
                                              "current_password": PW})
        tok = r.json().get("token", "")
        check("token de automatizare creat (read+run)", tok.startswith(security.TOKEN_PREFIX), r.text[:200])

    # ── automatizare: tokenul NU ajunge aici (doar cookie) ──
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 headers={**_ORIGIN, "Authorization": "Bearer " + tok}) as t:
        check("tokenul e valid în altă parte (/api/hosts → 200)", (await t.get("/api/hosts")).status_code == 200)
        r = await t.post("/api/fs/copy", json={"src_host": A, "paths": ["~/src/two.txt"], "dst_host": B,
                                               "dst_dir": "~/in"})
        check("token de automatizare → 401 (cookie only)", r.status_code == 401, r.status_code)
        r = await t.get("/api/fs/copy/" + "0" * 32)
        check("token de automatizare pe GET → 401", r.status_code == 401)

    await db.close()
    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
