"""Un host compromis nu poate epuiza resursele gateway-ului prin sesiuni inventate.

Plafonul de sesiuni era impus DOAR de agent (`MAX_SESSIONS` din `ptyd.py`), iar comentariul de
lângă `MAX_SESSIONS_HINT` o spunea pe faţă: „limita e impusă de agent; o replicăm aici doar
pentru mesajul de eroare". Exact garanţia pe care un agent compromis o ignoră.

Un singur heartbeat cu 400 de sid-uri uuid4 valide (auditul a folosit 3000) producea 3000 de rânduri în `sessions` şi
6000 de fişiere pe disc — `.out` şi `.cast` se creează în `SessionHub.__init__`, înainte de
orice octet de output. Repetat cu sid-uri noi la fiecare heartbeat, umple discul gateway-ului,
iar atunci nu cade hostul compromis, ci TOATĂ flota. Găsit de un audit extern.

Testul reproduce atacul şi cere trei lucruri: plafonul ţine, sesiunile legitime dinainte nu
sunt afectate, iar refuzul e VIZIBIL (jurnal de evenimente), nu tăcut — un host care raportează
mai multe sesiuni decât poate avea ori e stricat, ori minte, şi în ambele cazuri se anunţă.
"""
import asyncio
import math
import os
import sys
import tempfile
import uuid

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, core, db, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeConn:
    """Un agent compromis: raportează ce vrea, nu răspunde la nimic."""
    def __init__(self, host_id):
        self.host_id = host_id
        self.epoch = "e1"
        self.backend = "tmux"
        self.agent_version = 38
        self.metrics = {}
        self.host_name = "compromis"
        self.link = {}

    async def request(self, *a, **k):
        raise core.AgentGone()

    async def send_ctrl(self, *a, **k):
        pass

    async def attach(self, *a, **k):
        raise core.AgentGone()


# Hub-ul real deschide fişiere şi vorbeşte cu agentul; noi testăm PLAFONUL, nu ataşarea.
# Îl înlocuim cu un contor, ca testul să rămână despre ce am schimbat.
HUBS = []


def _fake_hub(row):
    """Hub-ul real deschide fişiere şi vorbeşte cu agentul. Stub-ul trebuie să aibă TOATE
    metodele pe care `reconcile` le cheamă — altfel un AttributeError lasă firul aiosqlite viu
    şi testul pare că atârnă, în loc să pice cu traceback."""
    class H:
        sid = row["id"]

        async def ensure_attached(self, conn):
            pass

        async def mark_lost(self, reason):
            pass

        async def detach(self, *a, **k):
            pass
    HUBS.append(row["id"])
    return H()


async def main():
    core.get_or_create_hub = _fake_hub
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await db.execute(
        "INSERT INTO hosts(name, token_hash, token_encrypted, connection_type, created)"
        " VALUES(?,?,?,?,?)",
        "compromis", "h", security.encrypt_secret("t"), "agent", 0)
    hid = (await db.fetchone("SELECT id FROM hosts WHERE name='compromis'"))["id"]
    conn = FakeConn(hid)

    def flood(n):
        return {"event": "heartbeat", "epoch": "e1", "agent_version": 38,
                "sessions": [{"sid": uuid.uuid4().hex, "alive": True,
                              "rows": 24, "cols": 80} for _ in range(n)]}

    # ── atacul: mult peste plafon, dintr-un singur heartbeat ──
    await core.reconcile(conn, flood(400))
    n = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM sessions WHERE host_id=?", hid))["c"]
    check("adopţia e plafonată (nu 400 de sesiuni dintr-un heartbeat)",
          n <= core.MAX_SESSIONS_HINT, f"{n} rânduri adoptate")

    check("nu s-au creat huburi (deci fişiere de transcript) peste plafon",
          len(HUBS) <= core.MAX_SESSIONS_HINT, f"{len(HUBS)} huburi")

    ev = await db.fetchall(
        "SELECT event, detail FROM agent_events WHERE host_id=? AND event='adoption_refused'", hid)
    check("refuzul e VIZIBIL în jurnalul de evenimente, nu tăcut", bool(ev), str(ev))

    # ── al doilea val, cu sid-uri NOI: nu trebuie să mai crească ──
    await core.reconcile(conn, flood(400))
    n2 = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM sessions WHERE host_id=?", hid))["c"]
    check("un al doilea val nu mai adaugă nimic (creşterea nu e nemărginită)",
          n2 == n, f"{n} → {n2}")

    # ── un agent CINSTIT, sub plafon, merge normal ──
    await db.execute("DELETE FROM sessions WHERE host_id=?", hid)
    HUBS.clear()
    await core.reconcile(conn, flood(3))
    n3 = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM sessions WHERE host_id=?", hid))["c"]
    check("adopţia normală (3 sesiuni) nu e afectată de plafon", n3 == 3, str(n3))

    # ── câmpurile raportate de agent sunt mărginite ──
    await core.reconcile(conn, {
        "event": "heartbeat", "epoch": "e1", "sessions": [],
        "hostname": "H" * 10000, "user": "U" * 10000,
        "metrics": {"cpu_pct": 5, "evil": "x" * 10000, "nested": {"a": 1}}})
    row = await db.fetchone("SELECT hostname, agent_user FROM hosts WHERE id=?", hid)
    check("hostname raportat de agent e tăiat", len(row["hostname"]) <= 255,
          str(len(row["hostname"])))
    check("user raportat de agent e tăiat", len(row["agent_user"]) <= 255,
          str(len(row["agent_user"])))
    check("metricile păstrează doar chei cunoscute, numerice",
          conn.metrics == {"cpu_pct": 5}, str(conn.metrics))

    # Un agent ostil nu poate nici umfla răspunsul, nici sparge serializarea JSON.
    # `json.loads` acceptă literalul `Infinity` de pe fir, dar `JSONResponse` refuză să-l
    # serializeze — deci `inf` transforma pagina hostului în 500 până când agentul se cuminţea.
    await core.reconcile(conn, {
        "event": "heartbeat", "epoch": "e1", "sessions": [],
        "metrics": dict({"k%d" % i: i for i in range(50000)},
                        cpu_pct=float("inf"), load1=float("nan"), mem_used=7)})
    check("numărul de chei de metrici e plafonat", len(conn.metrics) <= 64, str(len(conn.metrics)))
    check("cheile inventate sunt aruncate",
          all(k in core.METRIC_KEYS for k in conn.metrics), str(list(conn.metrics)[:5]))
    check("inf/nan nu ajung în răspuns (ar da 500 la GET /api/hosts/{id})",
          all(math.isfinite(v) for v in conn.metrics.values()), str(conn.metrics))
    import json as _json
    _json.dumps(conn.metrics, allow_nan=False)      # exact ce face JSONResponse
    check("metricile chiar se pot serializa ca JSON strict", True)

    await db.close()
    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
