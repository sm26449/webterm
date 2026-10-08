"""Copiere host → host de FOLDERE (WebTerm 3.6, agent 58): arbore + directoare + modul sursei.

Hermetic: doi `FakeAgent` cu un sistem de fişiere în RAM (fişiere, directoare cu mod, symlink-uri,
fişiere speciale) care se poartă ca agentul real: `fs_list` (dir/link/mode, trunchiere), `fs_stat`
(lstat; `mode` doar pe v58), `fs_mkdir` (părintele trebuie să existe, EEXIST), `fs_chmod` (doar v58;
refuză symlink-uri; un agent 57 răspunde `bad_op`), `fs_read`, `fs_write_bin`, `fs_rename`,
`fs_delete`, `fs_crc32`. Gateway-ul real (ASGI, in-process) face restul.

Acoperă: arbore complet (conţinut identic, directoare create, mod aplicat pe fişiere şi directoare,
setuid TĂIAT de gateway chiar dacă sursa îl raportează, directorul read-only închis DUPĂ ce a primit
fişierele), symlink + fişier special sărite cu notă, fişier simplu cu mod (din fs_stat pe sursa v58 /
din listarea părintelui pe sursa v57), destinaţie v57 → copiere fără mod + nota `copy.noModes` şi
NICIUN fs_chmod, regulile de conflict pe folder (skip = îmbinare care sare existentele, overwrite =
îmbinare care înlocuieşte, rename = „nume (1)", fişier cu acelaşi nume), folder în el însuşi,
plafoane (fişiere, adâncime, listare trunchiată), subdirector ilizibil, mkdir eşuat (copiii marcaţi),
retry (îmbinare în ACELAŞI folder, doar ce lipseşte), step-up pe retry, rândurile `kind`/`note_code`.
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


READ_CHUNK = 64 * 1024
HOME = "/home/u"


class FakeAgent(core.AgentConnection):
    def __init__(self, host_id, version=58):
        self.host_id = host_id
        self.agent_version = version
        self.files = {}                  # cale → bytearray
        self.modes = {}                  # cale → mod (fişiere ŞI directoare)
        self.dirs = {"/", "/home", HOME, "/tmp"}
        self.links = {}                  # cale → ţintă
        self.special = set()             # FIFO / device
        self.list_fail = set()
        self.mkdir_fail = set()
        self.truncate = set()
        self.read_fail = set()
        self.chmods = []                 # (cale, mod) în ordinea apelurilor
        self.events = []                 # („commit"|„chmod", cale) — ordinea contează la dir read-only
        self.writes = 0
        self.mtime = 1700000000
        for d in self.dirs:
            self.modes[d] = 0o755

    def _abs(self, p):
        if p == "~":
            return HOME
        if p.startswith("~/"):
            p = HOME + p[1:]
        return os.path.normpath(p)

    def mkdir(self, p, mode=0o755):
        self.dirs.add(p)
        self.modes[p] = mode

    def put(self, p, data, mode=0o644):
        self.files[p] = bytearray(data)
        self.modes[p] = mode

    async def fs_write_bin(self, path, offset, block, timeout=60.0):
        p = self._abs(path)
        cur = len(self.files.get(p, b""))
        if offset != cur:
            return {"ok": False, "code": "offset_conflict", "msg": "size %d != offset %d" % (cur, offset)}
        self.files.setdefault(p, bytearray()).extend(block)
        self.writes += 1
        return {"ok": True, "written": len(block), "crc32": zlib.crc32(bytes(self.files[p])) & 0xffffffff}

    def _exists(self, p):
        return p in self.dirs or p in self.files or p in self.links or p in self.special

    async def request(self, op, timeout=20.0, **kw):
        await asyncio.sleep(0)
        p = self._abs(kw.get("path") or "~")
        if op == "fs_stat":
            if not self._exists(p):
                return {"ok": True, "exists": False, "size": 0}
            r = {"ok": True, "exists": True, "dir": p in self.dirs, "link": p in self.links,
                 "size": len(self.files.get(p, b"")), "mtime": self.mtime}
            if self.agent_version >= 58:
                r["mode"] = 0o777 if p in self.links else self.modes.get(p, 0o644)
            return r
        if op == "fs_list":
            if p in self.list_fail:
                return {"ok": False, "msg": "%s: Permission denied" % p}
            if p not in self.dirs:
                return {"ok": False, "msg": "%s: No such file or directory" % p}
            pre = p.rstrip("/") + "/"
            entries = []
            for coll, kind in ((self.dirs, "d"), (self.files, "f"), (self.links, "l"), (self.special, "s")):
                for x in coll:
                    if x.startswith(pre) and x != p and "/" not in x[len(pre):]:
                        entries.append({"name": x[len(pre):], "dir": kind == "d", "link": kind == "l",
                                        "size": len(self.files.get(x, b"")), "mtime": self.mtime,
                                        "mode": 0o777 if kind == "l" else self.modes.get(x, 0o644)})
            entries.sort(key=lambda e: (not e["dir"], e["name"]))
            return {"ok": True, "path": p, "parent": os.path.dirname(p), "entries": entries,
                    "truncated": p in self.truncate}
        if op == "fs_mkdir":
            if p in self.mkdir_fail:
                return {"ok": False, "msg": "%s: Permission denied" % p}
            if self._exists(p):
                return {"ok": False, "msg": "%s: File exists" % p}
            if os.path.dirname(p) not in self.dirs:
                return {"ok": False, "msg": "%s: No such file or directory" % p}
            self.mkdir(p)
            return {"ok": True, "path": p}
        if op == "fs_chmod":
            if self.agent_version < 58:
                return {"ok": False, "code": "bad_op", "msg": "fs_chmod"}
            if p in self.links:
                return {"ok": False, "code": "fs_error", "msg": "%s: is a symbolic link (not followed)" % p}
            if p not in self.files and p not in self.dirs:
                return {"ok": False, "code": "fs_error", "msg": "%s: No such file or directory" % p}
            mode = kw["mode"] & 0o777
            self.modes[p] = mode
            self.chmods.append((p, kw["mode"]))
            self.events.append(("chmod", p))
            return {"ok": True, "path": p, "mode": mode}
        if op == "fs_read":
            real = self.links.get(p, p)
            if real in self.special or real in self.dirs:
                return {"ok": False, "msg": "%s: not a regular file (directory/device/socket/FIFO)" % p}
            if real not in self.files:
                return {"ok": False, "msg": "%s: No such file or directory" % p}
            if p in self.read_fail:
                return {"ok": False, "msg": "%s: Input/output error" % p}
            off = int(kw.get("offset", 0))
            data = bytes(self.files[real])
            chunk = data[off:off + READ_CHUNK]
            return {"ok": True, "size": len(data), "mtime": self.mtime, "eof": off + len(chunk) >= len(data),
                    "data_b64": base64.b64encode(chunk).decode()}
        if op == "fs_rename":
            to = self._abs(kw["to"])
            if to in self.dirs:
                return {"ok": False, "msg": "Is a directory"}
            if os.path.dirname(to) not in self.dirs:
                return {"ok": False, "msg": "%s: No such file or directory" % to}
            keep = self.modes.get(to)
            self.files[to] = self.files.pop(p, bytearray())
            self.modes[to] = keep if keep is not None else 0o644
            self.events.append(("commit", to))
            return {"ok": True, "path": to}
        if op == "fs_delete":
            self.files.pop(p, None)
            return {"ok": True}
        if op == "fs_crc32":
            return {"ok": True, "crc32": zlib.crc32(bytes(self.files.get(p, b""))) & 0xffffffff}
        return {"ok": True}


async def wait_done(c, jid, ms=20000):
    t = 0
    j = {}
    while t < ms:
        j = (await c.get("/api/fs/copy/%s?files=1" % jid)).json()
        if j.get("state") != "running":
            return j
        await asyncio.sleep(0.02)
        t += 20
    return j


def tree(a, root=HOME + "/proj"):
    """~/proj: run.sh 0755, id_key 0600, README 0644, sub/deep/x.bin 0640, empty 0700, ro 0555 cu
    f.txt, suid 04755 (raportat aşa de un agent sursă stricat), un symlink şi un FIFO."""
    a.mkdir(root, 0o750)
    a.put(root + "/run.sh", b"#!/bin/sh\necho hi\n", 0o755)
    a.put(root + "/id_key", b"PRIVATE", 0o600)
    a.put(root + "/README", b"read me\n", 0o644)
    a.mkdir(root + "/sub", 0o755)
    a.mkdir(root + "/sub/deep", 0o711)
    a.put(root + "/sub/deep/x.bin", bytes(range(256)) * 600, 0o640)
    a.mkdir(root + "/empty", 0o700)
    a.mkdir(root + "/ro", 0o555)
    a.put(root + "/ro/f.txt", b"inside read-only", 0o444)
    a.put(root + "/suid", b"x", 0o4755)
    a.links[root + "/ln"] = "/etc/passwd"
    a.special.add(root + "/fifo")


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
        tree(a)
        b.mkdir(HOME + "/in")

        async def copy(paths, dst_dir=HOME + "/in", on_conflict="skip", src=A, dst=B):
            return await c.post("/api/fs/copy", json={"src_host": src, "paths": paths, "dst_host": dst,
                                                      "dst_dir": dst_dir, "on_conflict": on_conflict})

        # ── v58 → v58: arborele complet, cu modurile ──
        r = await copy(["~/proj"])
        check("POST folder → 200", r.status_code == 200, r.text[:200])
        j = await wait_done(c, r.json()["job_id"])
        D = HOME + "/in/proj"
        check("job done, fără erori", j["state"] == "done" and j["files_failed"] == 0, str(j)[:400])
        check("conţinut identic (fişier mare, adânc)", bytes(b.files.get(D + "/sub/deep/x.bin", b""))
              == bytes(a.files[HOME + "/proj/sub/deep/x.bin"]))
        check("toate fişierele obişnuite au aterizat", all(
            bytes(b.files.get(D + n, b"")) == bytes(a.files[HOME + "/proj" + n])
            for n in ("/run.sh", "/id_key", "/README", "/ro/f.txt", "/suid")))
        check("directoarele create (inclusiv cel gol)", all(D + d in b.dirs for d in ("", "/sub", "/sub/deep",
                                                                                          "/empty", "/ro")))
        check("mod: run.sh 0755 (executabil!), id_key 0600, README 0644, x.bin 0640",
              (b.modes[D + "/run.sh"], b.modes[D + "/id_key"], b.modes[D + "/README"],
               b.modes[D + "/sub/deep/x.bin"]) == (0o755, 0o600, 0o644, 0o640),
              [oct(b.modes.get(D + n, 0)) for n in ("/run.sh", "/id_key", "/README", "/sub/deep/x.bin")])
        check("mod pe directoare: rădăcina 0750, deep 0711, empty 0700, ro 0555",
              (b.modes[D], b.modes[D + "/sub/deep"], b.modes[D + "/empty"], b.modes[D + "/ro"])
              == (0o750, 0o711, 0o700, 0o555), [oct(b.modes.get(D + d, 0)) for d in ("", "/sub/deep", "/empty", "/ro")])
        check("setuid raportat de sursă (04755) → gateway-ul cere 0755", (D + "/suid", 0o755) in b.chmods
              and b.modes[D + "/suid"] == 0o755, [x for x in b.chmods if x[0].endswith("suid")])
        check("niciun fs_chmod nu primeşte biţi peste 0o777", all(m <= 0o777 for _, m in b.chmods), b.chmods)
        ev = b.events
        check("directorul read-only (0555) e închis DUPĂ ce a primit fişierul",
              ev.index(("commit", D + "/ro/f.txt")) < ev.index(("chmod", D + "/ro")), ev)
        check("directoarele: cel mai adânc primul (deep înainte de sub înainte de rădăcină)",
              ev.index(("chmod", D + "/sub/deep")) < ev.index(("chmod", D + "/sub")) < ev.index(("chmod", D)))
        check("symlink-ul NU e copiat (nici ca link, nici ţinta)", D + "/ln" not in b.files and D + "/ln" not in b.links)
        check("FIFO-ul NU e copiat", D + "/fifo" not in b.files)
        rows = {f["name"]: f for f in j["files"]}
        check("rândul symlink: skipped, note_code copy.symlinkSkipped, kind link",
              rows["proj/ln"]["state"] == "skipped" and rows["proj/ln"]["note_code"] == "copy.symlinkSkipped"
              and rows["proj/ln"]["kind"] == "link", rows.get("proj/ln"))
        check("rândul FIFO: skipped, note_code copy.specialSkipped",
              rows["proj/fifo"]["state"] == "skipped" and rows["proj/fifo"]["note_code"] == "copy.specialSkipped",
              rows.get("proj/fifo"))
        check("totaluri: 8 fişiere (6 copiate + 2 sărite), 5 foldere", j["files_total"] == 8 and j["files_done"] == 6
              and j["files_skipped"] == 2 and j["folders_total"] == 5 and j["folders_done"] == 5, str(j)[:300])
        check("modes=True, fără note de job; noted = cele 2 sărite", j["modes"] is True and j["notes"] == []
              and j["noted_total"] == 2, (j["modes"], j["notes"], j["noted_total"]))
        check("niciun .wtpart rămas", not [p for p in b.files if ".wtpart." in p])

        # ── fişier simplu: modul se aplică şi lui (din fs_stat pe sursa v58) ──
        a.put(HOME + "/key.pem", b"K", 0o600)
        j = await wait_done(c, (await copy(["~/key.pem"])).json()["job_id"])
        check("fişier simplu 0600 → 0600 pe destinaţie (înainte: 0644)", j["state"] == "done"
              and b.modes.get(HOME + "/in/key.pem") == 0o600, oct(b.modes.get(HOME + "/in/key.pem", 0)))
        # sursa v57 (fs_stat fără `mode`) → modul din listarea părintelui
        a.agent_version = 57
        a.put(HOME + "/tool", b"T", 0o700)
        j = await wait_done(c, (await copy(["~/tool"])).json()["job_id"])
        check("sursa v57: modul vine din fs_list pe părinte → 0700", b.modes.get(HOME + "/in/tool") == 0o700,
              oct(b.modes.get(HOME + "/in/tool", 0)))
        a.agent_version = 58

        # ── destinaţie v57: copiere fără mod, NOTĂ, niciun fs_chmod ──
        C = (await c.post("/api/hosts", json={"name": "old57"})).json()["id"]
        o = FakeAgent(C, version=57)
        core.sources[C] = o
        o.mkdir(HOME + "/in")
        j = await wait_done(c, (await copy(["~/proj"], dst=C)).json()["job_id"])
        check("destinaţie v57: folderul se copiază (done)", j["state"] == "done"
              and bytes(o.files.get(HOME + "/in/proj/run.sh", b"")) == b"#!/bin/sh\necho hi\n", str(j)[:300])
        check("…fără NICIUN fs_chmod (op-ul nu există pe 57)", o.chmods == [], o.chmods)
        check("…modul rămâne cel implicit (0644)", o.modes.get(HOME + "/in/proj/run.sh") == 0o644)
        check("…şi job-ul spune asta: modes=False + nota copy.noModes",
              j["modes"] is False and [n["code"] for n in j["notes"]] == ["copy.noModes"]
              and "agent < 58" in j["notes"][0]["msg"], (j["modes"], j["notes"]))
        j = await wait_done(c, (await copy(["~/key.pem"], dst=C)).json()["job_id"])
        check("destinaţie v57, fişier simplu: copiat + nota copy.noModes", j["state"] == "done"
              and j["notes"] and j["notes"][0]["code"] == "copy.noModes")

        # ── conflicte pe folder ──
        b.files[D + "/README"] = bytearray(b"EDITED ON B")
        b.modes[D + "/README"] = 0o600
        del b.files[D + "/run.sh"]
        writes = b.writes
        j = await wait_done(c, (await copy(["~/proj"], on_conflict="skip")).json()["job_id"])
        check("skip pe folder existent = ÎMBINARE: fişierul existent neatins",
              bytes(b.files[D + "/README"]) == b"EDITED ON B" and b.modes[D + "/README"] == 0o600)
        check("…iar cel lipsă (run.sh) adăugat, cu modul lui", bytes(b.files.get(D + "/run.sh", b"")) ==
              b"#!/bin/sh\necho hi\n" and b.modes[D + "/run.sh"] == 0o755)
        check("…doar run.sh scris (restul sărite)", b.writes - writes == 1 and j["files_done"] == 1, b.writes - writes)
        check("…directoarele existente nu primesc chmod (nu le-am creat noi)",
              not any(p == D for p, _ in b.chmods[-3:]), b.chmods[-3:])
        j = await wait_done(c, (await copy(["~/proj"], on_conflict="overwrite")).json()["job_id"])
        check("overwrite pe folder existent = îmbinare care înlocuieşte (README rescris, mod 0644)",
              j["state"] == "done" and bytes(b.files[D + "/README"]) == b"read me\n"
              and b.modes[D + "/README"] == 0o644, str(j)[:300])
        j = await wait_done(c, (await copy(["~/proj"], on_conflict="rename")).json()["job_id"])
        check("rename pe folder existent → „proj (1)” complet", j["state"] == "done"
              and bytes(b.files.get(HOME + "/in/proj (1)/sub/deep/x.bin", b"")) == bytes(
                  a.files[HOME + "/proj/sub/deep/x.bin"]), str(j)[:200])
        a.mkdir(HOME + "/same")
        a.put(HOME + "/same/f", b"F")
        b.put(HOME + "/in/same", b"I AM A FILE")
        j = await wait_done(c, (await copy(["~/same"], on_conflict="skip")).json()["job_id"])
        check("un FIŞIER cu numele folderului + skip → folderul sărit", j["state"] == "done"
              and bytes(b.files[HOME + "/in/same"]) == b"I AM A FILE" and j["files_skipped"] == 1, str(j)[:300])
        j = await wait_done(c, (await copy(["~/same"], on_conflict="overwrite")).json()["job_id"])
        check("…+ overwrite → eroare (nu strivim un fişier cu un folder)", j["state"] == "failed"
              and j["errors"][0]["code"] == "files.exists", str(j)[:300])

        # ── acelaşi host: folder în el însuşi / peste el însuşi ──
        r = await copy(["~/proj"], dst_dir="~/proj/sub", dst=A)
        j = await wait_done(c, r.json()["job_id"])
        check("folder copiat în el însuşi → copy.intoItself", j["state"] == "failed"
              and j["errors"][0]["code"] == "copy.intoItself", str(j)[:300])
        j = await wait_done(c, (await copy(["~/proj"], dst_dir="~", dst=A, on_conflict="overwrite")).json()["job_id"])
        check("folder peste el însuşi (acelaşi director) → sărit, nimic scris", j["state"] == "done"
              and j["files_done"] == 0, str(j)[:300])

        # ── plafoane ──
        saved = fscopy.COPY_MAX_FILES
        fscopy.COPY_MAX_FILES = 5
        j = await wait_done(c, (await copy(["~/proj"], dst_dir="/tmp")).json()["job_id"])
        fscopy.COPY_MAX_FILES = saved
        check("peste plafonul de fişiere → copy.folderTooLarge, NIMIC creat", j["state"] == "failed"
              and j["errors"][0]["code"] == "copy.folderTooLarge" and "/tmp/proj" not in b.dirs, str(j)[:300])
        saved = fscopy.COPY_MAX_DEPTH
        fscopy.COPY_MAX_DEPTH = 1
        j = await wait_done(c, (await copy(["~/proj"], dst_dir="/tmp")).json()["job_id"])
        fscopy.COPY_MAX_DEPTH = saved
        check("prea adânc → copy.folderTooDeep", j["state"] == "failed"
              and j["errors"][0]["code"] == "copy.folderTooDeep", str(j)[:300])
        a.truncate.add(HOME + "/proj/sub")
        j = await wait_done(c, (await copy(["~/proj"], dst_dir="/tmp")).json()["job_id"])
        a.truncate.clear()
        check("listare trunchiată (> FS_MAX_LIST) → copy.folderTooLarge, nu copie parţială tăcută",
              j["state"] == "failed" and j["errors"][0]["code"] == "copy.folderTooLarge"
              and "/tmp/proj" not in b.dirs, str(j)[:300])

        # ── subdirector ilizibil pe sursă: rândul lui eşuează, restul se copiază ──
        a.list_fail.add(HOME + "/proj/sub/deep")
        b.mkdir("/tmp/t1")
        j = await wait_done(c, (await copy(["~/proj"], dst_dir="/tmp/t1")).json()["job_id"])
        a.list_fail.clear()
        errs = {e["name"]: e for e in j["errors"]}
        check("subdirector ilizibil → eroare pe rândul lui (files.permissionDenied)",
              errs.get("proj/sub/deep", {}).get("code") == "files.permissionDenied", str(j["errors"])[:300])
        check("…restul arborelui copiat", bytes(b.files.get("/tmp/t1/proj/run.sh", b"")) == b"#!/bin/sh\necho hi\n"
              and j["state"] == "failed")

        # ── mkdir eşuat pe destinaţie: copiii lui marcaţi, nu scrişi ──
        b.mkdir("/tmp/t2")
        b.mkdir_fail.add("/tmp/t2/proj/sub")
        j = await wait_done(c, (await copy(["~/proj"], dst_dir="/tmp/t2")).json()["job_id"])
        b.mkdir_fail.clear()
        errs = {e["name"]: e for e in j["errors"]}
        check("mkdir eşuat → rândul folderului în eroare", errs.get("proj/sub", {}).get("code") == "files.permissionDenied",
              list(errs))
        check("…copiii lui: copy.parentFailed, nimic scris sub el",
              errs.get("proj/sub/deep/x.bin", {}).get("code") == "copy.parentFailed"
              and not any(p.startswith("/tmp/t2/proj/sub/") for p in b.files), list(errs))
        check("…fraţii lui copiaţi normal", bytes(b.files.get("/tmp/t2/proj/README", b"")) == b"read me\n")

        # ── retry: îmbinare în ACELAŞI folder (şi la rename), doar ce lipseşte ──
        b.mkdir("/tmp/t3")
        b.mkdir("/tmp/t3/proj")                       # rename → „proj (1)"
        a.read_fail.add(HOME + "/proj/sub/deep/x.bin")
        r = await copy(["~/proj", "~/key.pem"], dst_dir="/tmp/t3", on_conflict="rename")
        old = r.json()["job_id"]
        j = await wait_done(c, old)
        check("job cu un fişier eşuat în folder → failed", j["state"] == "failed"
              and [e["name"] for e in j["errors"]] == ["proj/sub/deep/x.bin"], str(j["errors"])[:300])
        a.read_fail.clear()
        writes = b.writes
        r = await c.post("/api/fs/copy/%s/retry" % old)
        check("POST /retry → 200 + job nou", r.status_code == 200 and r.json()["job_id"] != old, r.text[:200])
        j = await wait_done(c, r.json()["job_id"])
        check("retry: x.bin aterizează în ACELAŞI „proj (1)” (nu „proj (2)”)", j["state"] == "done"
              and bytes(b.files.get("/tmp/t3/proj (1)/sub/deep/x.bin", b"")) == bytes(
                  a.files[HOME + "/proj/sub/deep/x.bin"]) and "/tmp/t3/proj (2)" not in b.dirs, str(j)[:300])
        check("retry: doar fişierul lipsă scris (restul există → sărite), key.pem nu e reluat",
              j["files_done"] == 1 and "/tmp/t3/key (1).pem" not in b.files, (j["files_done"], b.writes - writes))
        r = await c.post("/api/fs/copy/%s/retry" % r.json()["job_id"])
        check("retry pe un job fără eşecuri → 400 copy.nothingToRetry", r.status_code == 400
              and r.headers.get("x-webterm-error") == "copy.nothingToRetry", r.text[:200])
        r = await c.post("/api/fs/copy/%s/retry" % ("0" * 32))
        check("retry pe un job inexistent → 404 copy.missing", r.status_code == 404)
        a.read_fail.add(HOME + "/key.pem")
        old = (await copy(["~/key.pem"], dst_dir="/tmp")).json()["job_id"]
        await wait_done(c, old)
        a.read_fail.clear()
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", B)
        security.clear_stepup_for(uid)
        r = await c.post("/api/fs/copy/%s/retry" % old)
        check("retry: destinaţia cu 2FA, fără step-up → 403 stepup.*", r.status_code == 403
              and r.headers.get("x-webterm-error", "").startswith("stepup."), r.text[:200])
        security.open_stepup_window(uid, B)
        r = await c.post("/api/fs/copy/%s/retry" % old)
        check("…cu step-up → 200", r.status_code == 200, r.text[:200])
        j = await wait_done(c, r.json()["job_id"])
        check("…şi fişierul ajunge", j["state"] == "done" and b.files.get("/tmp/key.pem") == bytearray(b"K"))
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", B)
        check("job-ul altui user nu poate fi reluat (get → None)", fscopy.get(old, uid + 99) is None)

    await db.close()
    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
