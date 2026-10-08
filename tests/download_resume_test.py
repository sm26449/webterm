"""Validatorul pentru reluarea download-urilor DUPĂ RELOAD (3.5.13): `GET /api/hosts/{id}/fs/download`.

Hermetic: fără agent real, fără reţea. Un `FakeAgent` (v57) ţine fişierele în RAM şi răspunde la
`fs_stat` (lstat: `mtime`, `link`) şi `fs_read` exact ca agentul — agentul NU se schimbă: `mtime`
vine deja în `fs_stat`. Gateway-ul real (ASGI, in-process, cu toate middleware-urile — inclusiv
GZip) face restul.

Acoperă: ETag slab `W/"size-mtime"` + Last-Modified pe 200 şi pe 206 (identic, ca browserul să-l
poată compara cu cel salvat în IndexedDB); ETag-ul se SCHIMBĂ când se schimbă mtime-ul sau mărimea;
Content-Range corect pe o felie de la offset; 416 dincolo de capăt; symlink → fără Range/ETag (lstat
dă lungimea ţintei, iar un Content-Length construit din ea rupea descărcarea) dar conţinutul complet;
agent vechi (<50, fără fs_stat) → 200 fără ETag; `/api/state` expune `user_id` (cheia per cont a
înregistrărilor locale) doar autentificat.
"""
import asyncio
import base64
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402
from app.main import app  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
PW = "parola-cont-123456"
READ_CHUNK = 64 * 1024
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


class FakeAgent(core.AgentConnection):
    def __init__(self, host_id, ver=57):
        self.host_id = host_id
        self.agent_version = ver
        self.files = {}
        self.links = {}
        self.mtime = 1700000000

    async def request(self, op, timeout=20.0, **kw):
        await asyncio.sleep(0)
        p = kw.get("path") or ""
        if op == "fs_stat":
            if p in self.links:      # lstat: mărimea LINK-ului (lungimea ţintei), nu a fişierului
                return {"ok": True, "exists": True, "size": len(self.links[p]), "dir": False,
                        "link": True, "mtime": self.mtime}
            if p in self.files:
                return {"ok": True, "exists": True, "size": len(self.files[p]), "dir": False,
                        "link": False, "mtime": self.mtime}
            return {"ok": True, "exists": False, "size": 0}
        if op == "fs_read":
            real = self.links.get(p, p)
            if real not in self.files:
                return {"ok": False, "msg": "%s: No such file or directory" % p}
            off = int(kw.get("offset", 0))
            data = bytes(self.files[real])
            chunk = data[off:off + READ_CHUNK]
            return {"ok": True, "size": len(data), "mtime": self.mtime,
                    "eof": off + len(chunk) >= len(data), "data_b64": base64.b64encode(chunk).decode()}
        return {"ok": True}


def blob(n, seed=3):
    return bytes((i * 31 + seed) % 251 for i in range(n))


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        r = await c.get("/api/state")
        check("/api/state neautentificat → user_id null", r.json().get("user_id") is None, r.text[:200])
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW, "setup_token": "test-setup"})
        uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]
        r = await c.get("/api/state")
        check("/api/state autentificat → user_id = id-ul contului", r.json().get("user_id") == uid, r.text[:200])

        H = (await c.post("/api/hosts", json={"name": "alpha"})).json()["id"]
        a = FakeAgent(H)
        core.sources[H] = a
        data = blob(300 * 1024 + 7)
        a.files["/home/u/big.bin"] = bytearray(data)
        url = "/api/hosts/%d/fs/download?path=/home/u/big.bin" % H

        r = await c.get(url)
        etag0 = r.headers.get("etag")
        check("200 întreg: conţinut identic", r.status_code == 200 and r.content == data, r.status_code)
        check("200: ETag slab W/\"size-mtime\"", etag0 == 'W/"%d-%d"' % (len(data), a.mtime), etag0)
        check("200: Last-Modified din mtime (HTTP-date)",
              r.headers.get("last-modified") == "Tue, 14 Nov 2023 22:13:20 GMT", r.headers.get("last-modified"))

        r = await c.get(url, headers={"Range": "bytes=100000-"})
        check("206 de la offset: felia corectă", r.status_code == 206 and r.content == data[100000:], r.status_code)
        check("206: Content-Range bytes start-end/total",
              r.headers.get("content-range") == "bytes 100000-%d/%d" % (len(data) - 1, len(data)),
              r.headers.get("content-range"))
        check("206: ACELAŞI ETag ca la început (comparabil cu cel din IndexedDB)",
              r.headers.get("etag") == etag0, r.headers.get("etag"))

        r = await c.get(url, headers={"Range": "bytes=%d-" % len(data)})
        check("Range dincolo de capăt → 416", r.status_code == 416, r.status_code)

        a.mtime += 5
        r = await c.get(url, headers={"Range": "bytes=10-"})
        check("mtime schimbat pe host → ETag diferit", r.headers.get("etag") not in (None, etag0),
              r.headers.get("etag"))
        a.files["/home/u/big.bin"].extend(b"more")
        r2 = await c.get(url, headers={"Range": "bytes=10-"})
        check("mărime schimbată (acelaşi mtime) → ETag diferit",
              r2.headers.get("etag") not in (None, r.headers.get("etag")), r2.headers.get("etag"))

        # symlink: lstat dă lungimea ţintei — nu Range/Content-Length din ea; conţinut complet
        a.links["/home/u/link.bin"] = "/home/u/big.bin"
        r = await c.get("/api/hosts/%d/fs/download?path=/home/u/link.bin" % H, headers={"Range": "bytes=0-"})
        check("symlink: 200 cu TOT conţinutul ţintei (nu trunchiat la lungimea link-ului)",
              r.status_code == 200 and r.content == bytes(a.files["/home/u/big.bin"]),
              (r.status_code, len(r.content)))
        check("symlink: fără ETag / Accept-Ranges (nu se oferă reluare)",
              "etag" not in r.headers and "accept-ranges" not in r.headers, dict(r.headers))

        # agent vechi: fără fs_stat → streaming de dintotdeauna, fără validator
        a.agent_version = 49
        r = await c.get(url, headers={"Range": "bytes=10-"})
        check("agent < 50: 200 întreg, fără ETag", r.status_code == 200 and "etag" not in r.headers,
              (r.status_code, dict(r.headers)))
        a.agent_version = 57

        check("download_etag: lipsă mtime → None", api.download_etag(10, None) is None
              and api.download_etag(None, 5) is None and api.download_etag(0, 5) == 'W/"0-5"')

    await db.close()
    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
