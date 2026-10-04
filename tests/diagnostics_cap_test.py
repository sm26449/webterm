"""Plafon pe snapshot-ul de diagnostic (audit 2026-10-04, S-03) + rezumatul de update-uri.

`metrics` şi `hostname` erau mărginite, dar `diagnostics` nu: un agent compromis putea scrie
15 MB la fiecare heartbeat, iar `GET /api/hosts` (poll la 5 s, per client) re-parsa blobul
pentru fiecare host. Verificăm:
  * snapshot normal → stocat, `updates_summary` extras la scriere, badge-ul îl citeşte;
  * un singur şir uriaş → tăiat cu marcaj, snapshot-ul rămâne sub plafon şi se stochează;
  * snapshot peste plafon după tăiere → REFUZAT, eveniment `diagnostics_oversized`, ultimul bun rămâne;
  * refuzurile repetate nu inundă jurnalul (o dată pe oră);
  * imbricare adâncă → tăiată;
  * `GET /api/hosts` întoarce rezumatul fără să parseze blobul; fallback pe rânduri vechi, dar
    numai sub plafon.
Hermetic: agent fals, fără gateway/agent reale.
"""
import asyncio
import json
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {str(detail)[:200]}"))


class FakeAgent(core.AgentConnection):
    """AgentConnection fals: doar ce atinge _store_diagnostics."""
    def __init__(self, host_id):
        self.host_id = host_id
        self.diagnostics = None
        self._diag_refused_at = 0.0


async def _row(hid):
    return await db.fetchone("SELECT * FROM hosts WHERE id=?", hid)


async def _events(hid):
    return await db.fetchall(
        "SELECT reason FROM agent_events WHERE host_id=? AND event='diagnostics_oversized'", hid)


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW, "setup_token": "test-setup"})
        hid = (await c.post("/api/hosts", json={"name": "diag"})).json()["id"]
        agent = FakeAgent(hid)

        # 1) snapshot normal
        good = {"collected_at": time.time(), "system": {"os": "Debian 12", "kernel": "6.1"},
                "updates": {"count": 3, "security": 1, "manager": "apt"}}
        await agent._store_diagnostics(good)
        row = await _row(hid)
        check("snapshot normal → stocat ca JSON", json.loads(row["diagnostics"])["system"]["os"] == "Debian 12")
        check("rezumatul de update-uri e extras LA SCRIERE",
              json.loads(row["updates_summary"]) == {"count": 3, "security": 1, "manager": "apt"},
              row["updates_summary"])
        check("_host_updates citeşte rezumatul", api._host_updates(row) == {"count": 3, "security": 1, "manager": "apt"})

        # 2) un singur şir uriaş → tăiat, snapshot-ul se stochează
        huge = {"system": {"os": "A" * 300_000}, "updates": {"count": 5, "security": 0, "manager": "apt"}}
        await agent._store_diagnostics(huge)
        row = await _row(hid)
        stored = json.loads(row["diagnostics"])
        check("şirul uriaş e tăiat cu marcaj",
              stored["system"]["os"].endswith(core._DIAG_TRUNC)
              and len(stored["system"]["os"]) == core.DIAG_STR_MAX + len(core._DIAG_TRUNC))
        check("snapshot-ul tăiat rămâne sub plafon şi se stochează",
              len(row["diagnostics"]) < core.DIAG_MAX_BYTES and api._host_updates(row)["count"] == 5)
        check("cache-ul live e cel tăiat", agent.diagnostics is stored or agent.diagnostics["system"]["os"] == stored["system"]["os"])

        # 3) peste plafon chiar şi după tăiere (multe chei de 4 KB) → refuzat, ultimul bun rămâne
        flood = {"k%d" % i: "B" * 4000 for i in range(100)}
        flood["updates"] = {"count": 99, "security": 99, "manager": "evil"}
        await agent._store_diagnostics(flood)
        row = await _row(hid)
        check("snapshot peste plafon → REFUZAT (DB neschimbat)", api._host_updates(row)["count"] == 5
              and "k1" not in row["diagnostics"])
        check("cache-ul live NU e înlocuit", "k1" not in (agent.diagnostics or {}))
        evs = await _events(hid)
        check("eveniment diagnostics_oversized în jurnal", len(evs) == 1 and "bytes >" in evs[0]["reason"],
              str([tuple(e) for e in evs]))

        # 4) refuzurile repetate nu inundă jurnalul (o dată pe oră)
        await agent._store_diagnostics(flood)
        check("al doilea refuz în aceeaşi oră nu mai scrie eveniment", len(await _events(hid)) == 1)
        agent._diag_refused_at = 0.0
        await agent._store_diagnostics(flood)
        check("după fereastră, refuzul se înregistrează din nou", len(await _events(hid)) == 2)

        # 5) imbricare adâncă → tăiată (nu recursie infinită la parsare în UI)
        deep = cur = {}
        for _ in range(50):
            cur["n"] = {}
            cur = cur["n"]
        deep["updates"] = {"count": 1, "security": None, "manager": "dnf"}
        await agent._store_diagnostics(deep)
        row = await _row(hid)
        # json.dumps scrie „…" ca \u2026, deci căutăm marcajul în structura PARSATĂ, nu în text
        node, levels = json.loads(row["diagnostics"]), 0
        while isinstance(node, dict) and "n" in node:
            node, levels = node["n"], levels + 1
        check("imbricarea peste DIAG_MAX_DEPTH e tăiată (marcaj la adâncimea plafonului)",
              node == core._DIAG_TRUNC and levels == core.DIAG_MAX_DEPTH, "levels=%d node=%r" % (levels, node))
        check("rezumat fără `security` numeric → None, manager păstrat",
              api._host_updates(row) == {"count": 1, "security": None, "manager": "dnf"})

        # 6) snapshot fără updates → rezumat '' (nu NULL: NULL = rând vechi, fallback)
        await agent._store_diagnostics({"system": {"os": "x"}})
        row = await _row(hid)
        check("fără `updates` → updates_summary='' şi badge None",
              row["updates_summary"] == "" and api._host_updates(row) is None, repr(row["updates_summary"]))
        await agent._store_diagnostics({"updates": {"count": True}})
        check("count bool nu e număr → None", api._host_updates(await _row(hid)) is None)
        await agent._store_diagnostics(["nu", "e", "dict"])
        check("snapshot non-dict ignorat", api._host_updates(await _row(hid)) is None)

        # 7) GET /api/hosts întoarce rezumatul (calea fierbinte)
        await agent._store_diagnostics(good)
        hosts = (await c.get("/api/hosts")).json()
        mine = next(h for h in hosts if h["id"] == hid)
        check("GET /api/hosts întoarce `updates` din rezumat",
              mine["updates"] == {"count": 3, "security": 1, "manager": "apt"}, str(mine.get("updates")))

        # 8) rând de dinaintea coloanei (NULL): fallback pe blob, dar doar sub plafon
        legacy = json.dumps({"updates": {"count": 7, "security": 2, "manager": "apt"}})
        await db.execute("UPDATE hosts SET updates_summary=NULL, diagnostics=? WHERE id=?", legacy, hid)
        check("rând vechi (NULL) → fallback pe blob", api._host_updates(await _row(hid))["count"] == 7)
        big_legacy = json.dumps({"pad": "C" * (core.DIAG_MAX_BYTES + 10),
                                 "updates": {"count": 8, "security": 0, "manager": "apt"}})
        await db.execute("UPDATE hosts SET updates_summary=NULL, diagnostics=? WHERE id=?", big_legacy, hid)
        check("blob vechi peste plafon NU se parsează la fiecare poll", api._host_updates(await _row(hid)) is None)
        hosts = (await c.get("/api/hosts")).json()
        check("listarea rămâne 200 cu blob vechi peste plafon",
              next(h for h in hosts if h["id"] == hid)["updates"] is None)
        await db.execute("UPDATE hosts SET updates_summary='x{' WHERE id=?", hid)
        check("rezumat corupt → None, nu 500", api._host_updates(await _row(hid)) is None)

    print(f"\n{ok}/{total} passed")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()   # altfel firul aiosqlite ţine procesul viu la o excepţie


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
