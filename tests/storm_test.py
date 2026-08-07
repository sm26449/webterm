"""Output-storm resilience test against a running stack (boot_stack.sh).

Floods a session with fast output while one browser client reads slowly:
the slow client must get a resync (not a dead socket), the gateway must stay
responsive, and the session must remain usable afterwards.
"""

import asyncio
import json
import os
import sys
import time

import httpx
import websockets

BASE = os.environ.get("BASE", "http://localhost:8010")
WS_BASE = BASE.replace("http", "ws")

passed, failed = [], []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print("  %s %s %s" % ("PASS" if cond else "FAIL", name, detail if not cond else ""))


async def main():
    async with httpx.AsyncClient(base_url=BASE) as http:
        r = await http.post("/api/login", json={"email": "admin@example.com",
                                                "password": "parola-buna-123"})
        cookie = r.cookies["wt_session"]
        headers = {"Cookie": "wt_session=" + cookie, "Origin": BASE}

        r = await http.post("/api/hosts/1/sessions", json={"title": "storm"})
        sid = r.json()["id"]
        url = "%s/ws/sessions/%s" % (WS_BASE, sid)

        async with websockets.connect(url, additional_headers=headers) as fast, \
                   websockets.connect(url, additional_headers=headers) as slow:
            await fast.recv()  # init
            await slow.recv()
            t0 = time.time()

            # ~26 MB of output as fast as the pty can produce it
            await fast.send(b"seq 1 3000000; echo STORM_$((40+2))_END\n")

            got_resync = False
            fast_bytes = 0
            done = False
            slow_reads = 0

            async def pong(ws, m):
                if isinstance(m, str):
                    msg = json.loads(m)
                    if msg.get("type") == "ping":
                        await ws.send(json.dumps({"type": "pong", "n": msg["n"]}))
                    return msg
                return None

            async def read_fast():
                nonlocal fast_bytes, done
                while not done and time.time() - t0 < 120:
                    try:
                        m = await asyncio.wait_for(fast.recv(), timeout=30)
                    except asyncio.TimeoutError:
                        return
                    await pong(fast, m)
                    if isinstance(m, bytes):
                        fast_bytes += len(m)
                        if b"STORM_42_END" in m:
                            done = True

            async def read_slow():
                """Reads NOTHING during the storm (kernel buffers fill, the
                gateway-side queue overflows), then must receive a resync."""
                nonlocal got_resync, slow_reads
                while not done and time.time() - t0 < 120:
                    await asyncio.sleep(0.5)
                deadline = time.time() + 30
                while time.time() < deadline and not got_resync:
                    try:
                        m = await asyncio.wait_for(slow.recv(), timeout=5)
                    except (asyncio.TimeoutError, websockets.ConnectionClosed):
                        return
                    slow_reads += 1
                    msg = await pong(slow, m)
                    if msg and msg.get("type") == "resync":
                        got_resync = True

            await asyncio.gather(read_fast(), read_slow())
            dt = time.time() - t0
            check("storm completes", done, "in %.0fs, %d bytes" % (dt, fast_bytes))
            check("fast client received storm stream (>1MB after tmux rate-limit)",
                  fast_bytes > 1e6, str(fast_bytes))
            check("slow client got resync instead of disconnect", got_resync,
                  "reads=%d" % slow_reads)

            # session still usable
            await fast.send(b"echo STILL_$((1000+1))\n")
            buf = b""
            t1 = time.time()
            while time.time() - t1 < 10 and b"STILL_1001" not in buf:
                try:
                    m = await asyncio.wait_for(fast.recv(), timeout=5)
                except asyncio.TimeoutError:
                    break
                await pong(fast, m)
                if isinstance(m, bytes):
                    buf += m
            check("session responsive after storm", b"STILL_1001" in buf)

        # gateway alive and fast
        t2 = time.time()
        r = await http.get("/api/sessions")
        check("api responsive after storm", r.status_code == 200 and time.time() - t2 < 2)

        await http.post("/api/sessions/%s/kill" % sid)

    print("\n%d passed, %d failed" % (len(passed), len(failed)))
    sys.exit(1 if failed else 0)


asyncio.run(main())
