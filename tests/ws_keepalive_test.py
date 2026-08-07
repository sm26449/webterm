"""Keepalive pe idle (anti „ecran înghețat, trebuie Ctrl+R"):
BrowserClient.sender() trebuie să trimită un ping aplicativ după KEEPALIVE_SECS fără
output — altfel o sesiune inactivă nu mai produce niciun octet, un NAT/proxy taie TCP-ul
inactiv (half-open, fără FIN), iar browserul rămâne cu ecranul înghețat. Ping-ul periodic
ține calea caldă, hrănește watchdog-ul clientului și rulează detecția de client mort.
Pur unit pe BrowserClient — fără gateway/agent."""
import asyncio
import json
import os
import sys
import tempfile
import time

TMP = tempfile.mkdtemp()
os.environ["WEBTERM_DATA_DIR"] = TMP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, core  # noqa: E402

config.ensure_dirs()
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


sid = "b" * 32
row = {"id": sid, "host_id": 1, "rows": 24, "cols": 80,
       "agent_epoch": None, "agent_offset": 0, "created": time.time()}
hub = core.SessionHub(row)


class FakeWs:
    """WebSocket fals: reține ping-urile aplicative; on_ping=None simulează un client
    half-open (nu răspunde pong)."""
    def __init__(self):
        self.pings = []
        self.closed = None
        self.on_ping = None

    async def send_text(self, s):
        m = json.loads(s)
        if m.get("type") == "ping":
            self.pings.append(m["n"])
            if self.on_ping:
                self.on_ping(m["n"])          # client sănătos: pong imediat

    async def send_bytes(self, b):
        pass

    async def close(self, code=1000):
        self.closed = code


async def healthy_idle():
    core.KEEPALIVE_SECS = 0.05                 # accelerat pentru test
    ws = FakeWs()
    client = core.BrowserClient(ws, hub)
    ws.on_ping = client.on_pong                # răspunde pong → conexiune vie
    task = asyncio.create_task(client.sender())
    await asyncio.sleep(0.35)                  # mai multe cicluri de keepalive
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    return ws


async def dead_idle():
    core.KEEPALIVE_SECS = 0.05
    core.PONG_TIMEOUT = 0.05
    core.PONG_HARD_TIMEOUT = 0.05
    ws = FakeWs()                              # on_ping=None → nu răspunde niciodată
    client = core.BrowserClient(ws, hub)
    task = asyncio.create_task(client.sender())
    try:
        await asyncio.wait_for(task, 2.0)      # sender trebuie să iasă singur
    except asyncio.TimeoutError:
        task.cancel()
    return ws


ws = asyncio.run(healthy_idle())
check("keepalive: sender trimite ping(uri) pe o sesiune idle", len(ws.pings) >= 1)
check("keepalive: clientul sănătos NU e închis", ws.closed is None)

ws2 = asyncio.run(dead_idle())
check("dead-client: sender închide socketul half-open (cod 4408)", ws2.closed == 4408)


# ── Scriere serializată: sender() și broadcast_json() NU se întreţes pe același ws ──
# Cauza „ecran gol la unlock": hub.unlock() pune resync/tail în coada clientului (→ sender)
# ȘI trimite broadcast {"type":"unlocked"} pe ACELAȘI ws → scrieri concurente → frame corupt.
# Fix: _send_lock per-client serializează toate scrierile. Testăm că adâncimea de scriere ≤ 1.
class OrderWs:
    def __init__(self):
        self.depth = 0
        self.max_depth = 0
        self.on_ping = None

    async def _send(self):
        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        await asyncio.sleep(0)          # puncte de yield: fără lock, altă scriere intră aici
        await asyncio.sleep(0)
        self.depth -= 1

    async def send_text(self, s):
        m = json.loads(s)
        if m.get("type") == "ping" and self.on_ping:
            self.on_ping(m["n"])
        await self._send()

    async def send_bytes(self, b):
        await self._send()

    async def close(self, code=1000):
        pass


async def concurrent_writes():
    core.KEEPALIVE_SECS = 999           # fără keepalive care să adauge zgomot
    ws = OrderWs()
    client = core.BrowserClient(ws, hub)
    ws.on_ping = client.on_pong
    hub.clients.clear()
    hub.clients.add(client)             # ca broadcast_json să scrie pe el
    client.sender_task = asyncio.create_task(client.sender())

    async def feed():                   # alimentează sender-ul REAL (folosește self.send_bytes)
        for _ in range(40):
            client.push(b"Y" * 200)
            await asyncio.sleep(0)

    async def spam_broadcast():         # concurent, pe același ws (ca unlock/roster)
        for _ in range(40):
            await hub.broadcast_json({"type": "unlocked"})
            await asyncio.sleep(0)

    await asyncio.gather(feed(), spam_broadcast())
    await asyncio.sleep(0.05)
    client.sender_task.cancel()
    return ws.max_depth


depth = asyncio.run(concurrent_writes())
check("scrieri serializate: sender + broadcast concurent NU se întreţes (adâncime ≤ 1)", depth == 1)


# ── AgentConnection: send_ctrl/send_data/send_fwd NU se întreţes pe ws-ul agentului ──
# Aceeași clasă de bug ca la BrowserClient, dar mai gravă: un frame corupt către agent pică
# TOT hostul (toate sesiunile + forward-urile). send_ctrl (request-uri fs), send_data (input
# din fiecare browser_ws) și send_fwd (proxy, bucăţi de 1 MB) rulează din coroutine concurente.
async def agent_concurrent_writes():
    ws = OrderWs()
    conn = core.AgentConnection(ws, host_id=1)
    async def spam_ctrl():
        for _ in range(30):
            await conn.send_ctrl({"op": "x"})
    async def spam_data():
        for _ in range(30):
            await conn.send_data("a" * 32, b"Y" * 100)
    async def spam_fwd():
        for _ in range(30):
            await conn.send_fwd("b" * 32, b"Z" * 100)
    await asyncio.gather(spam_ctrl(), spam_data(), spam_fwd())
    return ws.max_depth


adepth = asyncio.run(agent_concurrent_writes())
check("AgentConnection: send_ctrl/data/fwd concurente se serializează (adâncime ≤ 1)", adepth == 1)

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
