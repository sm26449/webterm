"""Jurnal de conexiune al agentului (observabilitate/debug): record_agent_event scrie
evenimente (connect/disconnect+motiv/update/conflict), iar prune_agent_events aplică retenţia
de 7 zile. Pur unit pe DB — fără gateway/agent."""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, db, core  # noqa: E402

config.ensure_dirs()
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


async def main():
    await db.connect()

    await core.record_agent_event(1, "connect", detail="v28")
    await core.record_agent_event(1, "disconnect", reason="heartbeat_stale", detail="v28")
    await core.record_agent_event(1, "update_pushed", detail="v27 → v28")
    rows = await db.fetchall(
        "SELECT event, reason, detail FROM agent_events WHERE host_id=1 ORDER BY ts, id")
    check("evenimentele se scriu în jurnal (connect/disconnect/update)",
          len(rows) == 3 and rows[0]["event"] == "connect"
          and rows[1]["reason"] == "heartbeat_stale" and rows[2]["event"] == "update_pushed")

    # izolare per host
    await core.record_agent_event(2, "connect", detail="v28")
    n1 = (await db.fetchone("SELECT COUNT(*) c FROM agent_events WHERE host_id=1"))["c"]
    check("izolare per host (host 1 nevăzând evenimentele host 2)", n1 == 3)

    # retenţie 7 zile: un eveniment de acum 8 zile e şters, cele recente rămân
    await db.execute("INSERT INTO agent_events(host_id, ts, event) VALUES(?,?,?)",
                     1, time.time() - 8 * 24 * 3600, "connect")
    await core.prune_agent_events()
    n_after = (await db.fetchone("SELECT COUNT(*) c FROM agent_events WHERE host_id=1"))["c"]
    check("retenţie 7 zile: evenimentul de 8 zile e şters, recentele rămân", n_after == 3)

    await db.close()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    sys.stdout.flush()
    os._exit(1 if failed else 0)   # aiosqlite ţine un thread viu → exit forţat, ca celelalte teste


asyncio.run(main())
