"""Idle-lock de securitate (host cu require_2fa): terminalul se blochează după inactivitate
(output suprimat + input refuzat server-side); reluarea cere un step-up passkey.
Testăm mașina de stări a hub-ului + sweep-ul + refuzul de input, fără WS real."""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import core, db  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send_text(self, t):
        self.sent.append(t)


class FakeSource:
    def __init__(self):
        self.epoch = "ep"
        self.got_input = []

    async def attach(self, sid, off):
        return {"ok": True, "replay_start": off or 0}

    async def resize(self, sid, r, c):
        pass

    async def send_data(self, sid, data):
        self.got_input.append(data)


async def main():
    await db.connect()
    sid = "a" * 32
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,rows,cols) VALUES(?,?,?,?,?,?,?)",
        sid, 1, "t", "live", time.time(), 24, 80)
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    hub = core.get_or_create_hub(row)
    src = FakeSource()
    core.session_sources[sid] = src           # sursă per-sesiune (evită source_for/agent)
    client = core.BrowserClient(FakeWS(), hub)
    hub.clients.add(client)

    # ---- lock() ----
    hub.lock_idle = 300
    await hub.lock()
    check("lock: hub.locked", hub.locked is True)
    check("lock: clientul e marcat locked", client.locked is True)
    check("lock: broadcast 'locked' către client", any('"locked"' in t for t in client.ws.sent))

    # ---- input REFUZAT cât e blocat ----
    await hub.handle_input(client, b"secret-typing")
    check("input refuzat server-side cât e blocat", src.got_input == [], src.got_input)

    # ---- output SUPRIMAT cât e blocat ----
    client.push(b"output-secret")
    check("output suprimat (marcat missed, nu în coadă)", client._missed_while_paused is True)

    # ---- unlock() ----
    await hub.unlock()
    check("unlock: hub.locked False", hub.locked is False)
    check("unlock: clientul deblocat", client.locked is False)
    check("unlock: broadcast 'unlocked'", any('"unlocked"' in t for t in client.ws.sent))

    # ---- input ACCEPTAT după unlock ----
    await hub.handle_input(client, b"cmd")
    await asyncio.sleep(0.05)
    check("input acceptat după unlock", b"cmd" in src.got_input, src.got_input)

    # ---- sweep_idle_locks: blochează un hub 2FA idle ----
    hub.locked = False
    hub.lock_idle = 300
    hub.last_interaction = time.time() - 999      # idle demult
    await core.sweep_idle_locks()
    check("sweep: hub idle > prag → blocat", hub.locked is True)

    # hub NEidle → NU se blochează
    hub2row = dict(row); hub2row["id"] = "b" * 32
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,rows,cols) VALUES(?,?,?,?,?,?,?)",
        "b" * 32, 1, "t", "live", time.time(), 24, 80)
    r2 = await db.fetchone("SELECT * FROM sessions WHERE id=?", "b" * 32)
    hub2 = core.get_or_create_hub(r2)
    hub2.lock_idle = 300
    hub2.last_interaction = time.time()           # activ acum
    await core.sweep_idle_locks()
    check("sweep: hub activ recent → NU se blochează", hub2.locked is False)

    # lock_idle=0 (host fără 2FA) → niciodată blocat
    hub2.lock_idle = 0
    hub2.last_interaction = time.time() - 999
    await core.sweep_idle_locks()
    check("sweep: lock_idle=0 (fără 2FA) → nu se blochează", hub2.locked is False)

    for h in list(core.hubs.values()):
        try:
            h.teardown()
        except Exception:
            pass
    print(f"\n{ok}/{total} PASS", flush=True)
    os._exit(0 if ok == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
