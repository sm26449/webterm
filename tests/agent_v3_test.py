"""Agent v3: system metrics in heartbeat + forced update that keeps sessions."""

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
PORT = 8791
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


async def main():
    tmp = tempfile.mkdtemp(prefix="v3-")
    home = os.path.join(tmp, "home")
    os.makedirs(home)
    env = dict(os.environ, WEBTERM_SETUP_TOKEN="test-setup", WEBTERM_DATA_DIR=os.path.join(tmp, "data"),
               WEBTERM_PUBLIC_URL=BASE, PYTHONPATH=str(ROOT / "gateway"))
    gw = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT),
         "--host", "127.0.0.1", "--log-level", "warning"],
        env=env, cwd=str(ROOT / "gateway"))
    aenv = agent_env(home)          # HOME sandboxat + server tmux propriu (vezi tmux_sandbox)

    def start_agent():
        return subprocess.Popen([sys.executable, str(ROOT / "agent/ptyd.py"), "run"],
                                env=aenv, stdout=open(os.path.join(home, "a.log"), "ab"),
                                stderr=subprocess.STDOUT)

    agent = None
    try:
        async with httpx.AsyncClient(base_url=BASE) as h:
            await wait(lambda: _up(h))
            r = await h.post("/api/setup", json={"email": "a@b.c", "password": "12345678x", "setup_token": "test-setup"})
            hd = {"Cookie": "wt_session=" + r.cookies["wt_session"], "Origin": BASE}

            async def hosts():
                return (await h.get("/api/hosts", headers=hd)).json()

            inst = (await h.post("/api/hosts", json={"name": "v3"}, headers=hd)).json()["install_command"]
            tok = re.search(r"/install/([\w-]+)\.sh", inst).group(1)
            script = (await h.get(f"/install/{tok}.sh")).text
            token = re.search(r'TOKEN="([^"]+)"', script).group(1)
            os.makedirs(os.path.join(home, ".webterm"))
            json.dump({"url": WS + "/agent/ws", "token": token},
                      open(os.path.join(home, ".webterm/agent.json"), "w"))
            agent = start_agent()

            async def online():
                hh = await hosts()
                return bool(hh and hh[0]["online"])
            await wait(online)

            async def has_metrics():
                m = (await hosts())[0].get("metrics")
                return m and "mem_total" in m and "disk_total" in m
            ok("metrics in host payload (mem+disk)", await wait(has_metrics, 30))
            host = (await hosts())[0]
            m = host["metrics"]
            ok("mem_used <= mem_total", m["mem_used"] <= m["mem_total"])
            ok("disk_used <= disk_total", m["disk_used"] <= m["disk_total"])
            ok("load average present", "load1" in m)
            ok("agent v4 reported", host["agent_version"] >= 4, str(host["agent_version"]))

            sid = (await h.post("/api/hosts/1/sessions", json={"title": "keep"},
                                headers=hd)).json()["id"]
            async with websockets.connect(f"{WS}/ws/sessions/{sid}", additional_headers=hd) as w:
                await w.recv()
                await w.send(b"sleep 500 &\necho STARTED_$((1+1))\n")
                ok("process started before update",
                   b"STARTED_2" in await collect(w, b"STARTED_2"))

            r = await h.post("/api/hosts/1/update", headers=hd)
            ok("force update accepted (HTTP 200)", r.status_code == 200, r.text)
            await asyncio.sleep(3)
            ok("agent reconnected after force update", await wait(online, 15))
            s = [x for x in (await h.get("/api/sessions", headers=hd)).json()
                 if x["id"] == sid][0]
            ok("session survived force update", s["state"] == "live", s["state"])
            async with websockets.connect(f"{WS}/ws/sessions/{sid}", additional_headers=hd) as w:
                await w.recv()
                await asyncio.sleep(1)
                await w.send(b"jobs\n")
                ok("background process survived update (jobs shows sleep)",
                   b"sleep 500" in await collect(w, b"sleep 500"))
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
