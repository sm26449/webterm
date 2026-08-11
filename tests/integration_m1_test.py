"""M1 end-to-end integration test.

Boots the gateway (uvicorn), installs + runs the real agent against it in a
sandboxed HOME, then drives the full flow through the public API exactly like
the browser would: setup -> add host -> enroll -> session -> type -> output ->
browser close/reopen -> agent kill -9 + restart (tmux adoption) -> kill session.

Run: .venv/bin/python tests/integration_m1_test.py
"""

import asyncio
import json
import os
import re
import shutil
import signal
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
import websockets
from tmux_sandbox import agent_env, kill_server

ROOT = Path(__file__).resolve().parent.parent
PORT = 8799
BASE = "http://127.0.0.1:%d" % PORT
_ORIGIN = {"origin": BASE}
WS_BASE = "ws://127.0.0.1:%d" % PORT

passed = []
failed = []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print("  %s %s %s" % ("PASS" if cond else "FAIL", name, detail if not cond else ""))


async def wait_for(fn, timeout=15, interval=0.3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = await fn()
        if result:
            return result
        await asyncio.sleep(interval)
    return None


async def recv_until(ws, needle: bytes, timeout=10) -> bytes:
    """Collect binary frames until needle appears (text frames collected too)."""
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline and needle not in buf:
        try:
            msg = await asyncio.wait_for(ws.recv(), timeout=max(0.1, deadline - time.time()))
        except (asyncio.TimeoutError, websockets.ConnectionClosed):
            break
        if isinstance(msg, bytes):
            buf += msg
    return buf


class AgentProc:
    def __init__(self, home: str):
        self.home = home
        self.proc = None
        # HOME sandboxat + server tmux propriu; păstrat pe obiect ca teardown-ul să dea
        # kill-server exact pe socketul nostru, nu pe cel de producţie (vezi tmux_sandbox)
        self.env = agent_env(home)

    def start(self):
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "agent" / "ptyd.py"), "run"],
            env=self.env, stdout=open(os.path.join(self.home, "agent-stdout.log"), "ab"),
            stderr=subprocess.STDOUT)

    def kill9(self):
        self.proc.send_signal(signal.SIGKILL)
        self.proc.wait()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


async def main():
    tmp = tempfile.mkdtemp(prefix="webterm-test-")
    data_dir = os.path.join(tmp, "data")
    agent_home = os.path.join(tmp, "home")
    os.makedirs(agent_home)

    env = dict(os.environ,
               WEBTERM_DATA_DIR=data_dir,
               WEBTERM_PUBLIC_URL=BASE,
               WEBTERM_SETUP_TOKEN="test-setup",
               PYTHONPATH=str(ROOT / "gateway"))
    gw = subprocess.Popen(
        [str(ROOT / ".venv" / "bin" / "uvicorn"), "app.main:app",
         "--port", str(PORT), "--host", "127.0.0.1", "--log-level", "warning"],
        env=env, cwd=str(ROOT / "gateway"))
    agent = AgentProc(agent_home)

    try:
        async with httpx.AsyncClient(base_url=BASE, headers=_ORIGIN) as http:
            # gateway up?
            async def up():
                try:
                    return (await http.get("/api/state")).status_code == 200
                except httpx.TransportError:
                    return False
            check("gateway boots", await wait_for(up))

            print("== auth ==")
            r = await http.post("/api/setup", json={"email": "admin@example.com",
                                                    "password": "parola-buna-123",
                                                    "setup_token": "test-setup"})
            check("setup creates user + cookie", r.status_code == 200 and "wt_session" in r.cookies)
            cookie = r.cookies["wt_session"]

            r = await http.get("/api/hosts")
            check("hosts requires+accepts cookie", r.status_code == 200 and r.json() == [])

            r = await http.post("/api/login", json={"email": "admin@example.com",
                                                    "password": "gresita"})
            check("wrong password rejected", r.status_code == 401)

            print("== host enroll ==")
            r = await http.post("/api/hosts", json={"name": "local-test"})
            host = r.json()
            check("host created", r.status_code == 200 and "install_command" in host)
            enroll = re.search(r"/install/([a-zA-Z0-9_-]+)\.sh", host["install_command"]).group(1)

            r = await http.get("/install/%s.sh" % enroll)
            check("install script served", r.status_code == 200 and "ptyd.py" in r.text)
            token = re.search(r'TOKEN="([^"]+)"', r.text).group(1)

            r = await http.get("/agent/ptyd.py")
            check("agent source served", r.status_code == 200 and "AGENT_VERSION" in r.text)

            # emulate the installer: write config, start agent
            webterm_dir = os.path.join(agent_home, ".webterm")
            os.makedirs(webterm_dir)
            with open(os.path.join(webterm_dir, "agent.json"), "w") as f:
                json.dump({"url": WS_BASE + "/agent/ws", "token": token}, f)
            agent.start()

            async def online():
                rr = await http.get("/api/hosts")
                hh = rr.json()
                return hh and hh[0]["online"]
            check("agent connects (host online)", bool(await wait_for(online)))
            r = await http.get("/api/hosts")
            check("agent reports tmux backend", r.json()[0]["backend"] == "tmux",
                  str(r.json()))

            print("== session lifecycle ==")
            r = await http.post("/api/hosts/%d/sessions" % host["id"],
                                json={"title": "test", "rows": 24, "cols": 80})
            check("session created", r.status_code == 200, r.text)
            sid = r.json()["id"]

            headers = {"Cookie": "wt_session=" + cookie, "Origin": BASE}
            ws_url = "%s/ws/sessions/%s" % (WS_BASE, sid)

            async with websockets.connect(ws_url, additional_headers=headers) as ws:
                init = json.loads(await ws.recv())
                check("browser ws init", init["type"] == "init" and init["state"] == "live",
                      str(init))
                await ws.recv()  # tail (may be empty)
                await ws.send(b"echo HELLO_$((40+2))\n")
                out = await recv_until(ws, b"HELLO_42")
                check("typed command echoes output", b"HELLO_42" in out,
                      repr(out[-200:]))
                await ws.send(json.dumps({"type": "resize", "rows": 30, "cols": 100}))
                await asyncio.sleep(0.5)

            # browser closed; session must stay live and keep history
            await asyncio.sleep(1)
            r = await http.get("/api/sessions")
            ses = [s for s in r.json() if s["id"] == sid][0]
            check("session survives browser close", ses["state"] == "live", str(ses))

            async with websockets.connect(ws_url, additional_headers=headers) as ws:
                init = json.loads(await ws.recv())
                tail = await recv_until(ws, b"HELLO_42", timeout=5)
                check("history replayed on reconnect", b"HELLO_42" in tail,
                      repr(tail[-200:]))
                # start a marker process that must survive agent death
                await ws.send(b"sleep 1000 &\necho MARKER_STARTED\n")
                out = await recv_until(ws, b"MARKER_STARTED")
                check("background process started", b"MARKER_STARTED" in out)

            print("== agent kill -9 + restart (tmux adoption) ==")
            agent.kill9()
            await asyncio.sleep(1)
            agent.start()
            check("agent reconnects after kill -9", bool(await wait_for(online)))
            await asyncio.sleep(2)  # let reconcile+attach run

            r = await http.get("/api/sessions")
            ses = [s for s in r.json() if s["id"] == sid][0]
            check("session survives agent kill -9", ses["state"] == "live", str(ses))

            async with websockets.connect(ws_url, additional_headers=headers) as ws:
                json.loads(await ws.recv())
                await recv_until(ws, b"$", timeout=3)  # tail/redraw
                await ws.send(b"jobs\n")
                out = await recv_until(ws, b"sleep 1000")
                check("shell state intact after agent restart (jobs shows sleep)",
                      b"sleep 1000" in out, repr(out[-300:]))

            print("== close session ==")
            r = await http.post("/api/sessions/%s/kill" % sid)
            check("kill accepted", r.status_code == 200, r.text)

            async def closed():
                rr = await http.get("/api/sessions")
                s = [x for x in rr.json() if x["id"] == sid][0]
                return s["state"] in ("closed", "lost")
            check("session closes", bool(await wait_for(closed)))

            r = await http.get("/api/sessions/%s/transcript?format=out" % sid)
            check("transcript downloadable, contains history",
                  r.status_code == 200 and b"HELLO_42" in r.content)
            r = await http.get("/api/sessions/%s/transcript?format=cast" % sid)
            # v1.0.67 a scos înregistrarea input-ului din .cast: la un prompt cu echo off
            # (sudo/ssh/mysql -p) parola nu apare în output, deci un eveniment „i" ar scurge-o
            # în transcript + backup-uri. Verificăm invariantul, nu opusul lui (testul cerea
            # până acum exact ce am eliminat din motive de securitate).
            has_input = any('"i"' in line for line in r.text.splitlines())
            check("asciicast fără evenimente de input (parolele nu ajung în transcript)",
                  r.status_code == 200 and not has_input)

            r = await http.delete("/api/sessions/%s" % sid)
            check("closed session deletable", r.status_code == 200)
    finally:
        agent.stop()
        gw.terminate()
        try:
            gw.wait(timeout=5)
        except subprocess.TimeoutExpired:
            gw.kill()
        kill_server(agent.env)
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n%d passed, %d failed" % (len(passed), len(failed)))
    if failed:
        print("FAILED:", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
