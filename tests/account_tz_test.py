"""Account (email/password change) + timezone → TZ env in the session."""

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import websockets
from tmux_sandbox import agent_env, kill_server

ROOT = Path(__file__).resolve().parent.parent   # rădăcina repo-ului, nu hardcodată
PORT = 8795
BASE = f"http://127.0.0.1:{PORT}"
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


async def collect(w, needle, t=8):
    buf = b""
    dl = time.time() + t
    while time.time() < dl and needle not in buf:
        try:
            m = await asyncio.wait_for(w.recv(), timeout=3)
        except (asyncio.TimeoutError, websockets.ConnectionClosed):
            break
        if isinstance(m, bytes):
            buf += m
        elif isinstance(m, str):
            d = json.loads(m)
            if d.get("type") == "ping":
                await w.send(json.dumps({"type": "pong", "n": d["n"]}))
    return buf


def cookie_of(r):
    return r.cookies["wt_session"]


async def main():
    tmp = tempfile.mkdtemp(prefix="acct-")
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
        async with httpx.AsyncClient(base_url=BASE) as h:
            await wait(lambda: _up(h))
            r = await h.post("/api/setup", json={"email": "old@e.com", "password": "old-parola-1", "setup_token": "test-setup"})
            hd = {"Cookie": "wt_session=" + cookie_of(r), "Origin": BASE}

            # ── account: change email + password ──
            r = await h.post("/api/account", headers=hd, json={
                "current_password": "wrong", "new_password": "x"})
            ok("wrong current password rejected", r.status_code == 401, r.text)

            r = await h.post("/api/account", headers=hd, json={
                "current_password": "old-parola-1",
                "email": "nou@e.com", "new_password": "parola-noua-2"})
            ok("account update accepted", r.status_code == 200, r.text)

            r = await h.post("/api/login", json={"email": "old@e.com", "password": "old-parola-1"})
            ok("old credentials no longer work", r.status_code == 401)
            r = await h.post("/api/login", json={"email": "nou@e.com", "password": "parola-noua-2"})
            ok("new credentials work", r.status_code == 200)
            hd = {"Cookie": "wt_session=" + cookie_of(r), "Origin": BASE}

            # ── timezone → TZ env in session ──
            inst = (await h.post("/api/hosts", json={"name": "tz"}, headers=hd)).json()["install_command"]
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
            await wait(online)
            hv = (await h.get("/api/hosts", headers=hd)).json()[0]["agent_version"]
            ok("agent v6 reported", hv >= 6, str(hv))

            sid = (await h.post("/api/hosts/1/sessions",
                                json={"title": "tz", "tz": "Asia/Tokyo"},
                                headers=hd)).json()["id"]
            async with websockets.connect(f"{WS}/ws/sessions/{sid}", additional_headers=hd) as w:
                await w.recv()
                await asyncio.sleep(0.6)
                await w.send(b'echo TZ_IS=$TZ\n')
                out = await collect(w, b"TZ_IS=Asia/Tokyo")
                ok("session shell has chosen TZ (Asia/Tokyo)", b"TZ_IS=Asia/Tokyo" in out,
                   repr(out[-120:]))
                await w.send(b'date +%Z\n')
                out = await collect(w, b"JST", t=5)
                ok("date reports the zone abbreviation (JST)", b"JST" in out, repr(out[-120:]))
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
