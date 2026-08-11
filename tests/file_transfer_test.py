"""File transfer: upload → list → download round-trip through the real agent."""

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

# Middleware-ul `csrf_guard` cere `Origin` pe metodele care schimbă ceva şi refuză
# lipsa lui (ca `_origin_ok` pentru WebSocket). Testele imită un BROWSER, deci trimit
# antetul; fără el ar testa o cale pe care niciun browser n-o produce.
# Originea e a serverului pe care ÎL PORNEŞTE testul (BASE), nu a suitei.
from tmux_sandbox import agent_env, kill_server

ROOT = Path(__file__).resolve().parent.parent   # rădăcina repo-ului, nu hardcodată
PORT = 8793
BASE = f"http://127.0.0.1:{PORT}"
_ORIGIN = {"origin": BASE}
WS = BASE.replace("http", "ws")
P = []


def ok(name, cond, detail=""):
    P.append((name, cond))
    print(("  PASS " if cond else "  FAIL ") + name + ("" if cond else f"  {detail}"))


async def wait(fn, t=20):
    dl = time.time() + t
    while time.time() < dl:
        if await fn():
            return True
        await asyncio.sleep(0.3)
    return False


async def main():
    tmp = tempfile.mkdtemp(prefix="ft-")
    home = os.path.join(tmp, "home")
    os.makedirs(home)
    env = dict(os.environ, WEBTERM_SETUP_TOKEN="test-setup", WEBTERM_DATA_DIR=os.path.join(tmp, "data"),
               WEBTERM_PUBLIC_URL=BASE, PYTHONPATH=str(ROOT / "gateway"))
    gw = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT),
         "--host", "127.0.0.1", "--log-level", "warning"],
        env=env, cwd=str(ROOT / "gateway"))
    aenv = agent_env(home)          # HOME sandboxat + server tmux propriu (vezi tmux_sandbox)
    agent = None
    try:
        async with httpx.AsyncClient(base_url=BASE, timeout=30, headers=_ORIGIN) as h:
            await wait(lambda: _up(h))
            r = await h.post("/api/setup", json={"email": "a@b.c", "password": "12345678x", "setup_token": "test-setup"})
            hd = {"Cookie": "wt_session=" + r.cookies["wt_session"]}
            inst = (await h.post("/api/hosts", json={"name": "ft"}, headers=hd)).json()["install_command"]
            tok = re.search(r"/install/([\w-]+)\.sh", inst).group(1)
            token = re.search(r'TOKEN="([^"]+)"', (await h.get(f"/install/{tok}.sh")).text).group(1)
            os.makedirs(os.path.join(home, ".webterm"))
            json.dump({"url": WS + "/agent/ws", "token": token},
                      open(os.path.join(home, ".webterm/agent.json"), "w"))
            agent = subprocess.Popen([sys.executable, str(ROOT / "agent/ptyd.py"), "run"],
                                     env=aenv, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

            async def online():
                hh = (await h.get("/api/hosts", headers=hd)).json()
                return bool(hh and hh[0]["online"])
            ok("agent online", await wait(online))

            # list home dir
            r = await h.get("/api/hosts/1/fs?path=~", headers=hd)
            ok("fs list home", r.status_code == 200 and "entries" in r.json(), r.text[:120])
            home_path = r.json()["path"]

            # upload a binary blob (multi-chunk: 600 KB of random-ish bytes)
            blob = bytes((i * 37 + 11) % 256 for i in range(600 * 1024))
            digest = hashlib.sha256(blob).hexdigest()
            dest = f"{home_path}/webterm_test_blob.bin"
            r = await h.post(f"/api/hosts/1/fs/upload?path={dest}", headers=hd, content=blob)
            ok("upload accepted", r.status_code == 200 and r.json()["written"] == len(blob), r.text[:120])

            # file exists on disk with correct size
            disk = os.path.join(home, "webterm_test_blob.bin")
            ok("file written to host disk", os.path.exists(disk) and os.path.getsize(disk) == len(blob))
            ok("uploaded bytes intact on disk",
               hashlib.sha256(open(disk, "rb").read()).hexdigest() == digest)

            # it appears in the listing
            r = await h.get("/api/hosts/1/fs?path=~", headers=hd)
            names = [e["name"] for e in r.json()["entries"]]
            ok("uploaded file appears in listing", "webterm_test_blob.bin" in names)

            # download it back, verify byte-exact
            r = await h.get(f"/api/hosts/1/fs/download?path={dest}", headers=hd)
            ok("download round-trip byte-exact",
               r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == digest,
               f"{len(r.content)} vs {len(blob)}")

            # error handling: missing file
            r = await h.get(f"/api/hosts/1/fs/download?path={home_path}/does_not_exist_xyz", headers=hd)
            ok("download of missing file returns error", r.status_code == 400)
    finally:
        if agent:
            agent.terminate()
        gw.terminate()
        kill_server(aenv)

    failed = [n for n, c in P if not c]
    print(f"\n{len(P) - len(failed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


async def _up(h):
    try:
        return (await h.get("/api/state")).status_code == 200
    except httpx.TransportError:
        return False


asyncio.run(main())
