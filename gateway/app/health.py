"""Sănătatea gateway-ului însuși — vizibilă înainte de cădere, nu abia după.

Un tool de administrare trebuie să-și arate propria degradare: dacă event-loop-ul
se blochează, memoria crește sau DB-ul încetinește, vrei să afli din /api/status,
nu când aplicația nu mai răspunde.
"""

import asyncio
import time

# lag-ul event-loop-ului: cât întârzie o sarcină programată la 1s să ruleze de
# fapt. Cel mai bun semnal pentru „event-loop-ul e supraîncărcat / blocat de I/O
# sincron". Reținem ultimul și maximul recent (fereastră glisantă simplă).
_lag_ms = 0.0
_lag_max_ms = 0.0
_lag_reset_at = 0.0


async def loop_lag_monitor():
    """Task de fundal: dormim 1s și măsurăm derapajul. Ieftin (o dată/secundă)."""
    global _lag_ms, _lag_max_ms, _lag_reset_at
    loop = asyncio.get_running_loop()
    _lag_reset_at = loop.time()
    while True:
        t0 = loop.time()
        await asyncio.sleep(1.0)
        lag = (loop.time() - t0 - 1.0) * 1000.0
        _lag_ms = max(0.0, lag)
        # maxim pe fereastră de 60s — un vârf recent rămâne vizibil, dar nu pentru totdeauna
        now = loop.time()
        if now - _lag_reset_at > 60:
            _lag_max_ms = _lag_ms
            _lag_reset_at = now
        else:
            _lag_max_ms = max(_lag_max_ms, _lag_ms)


def _rss_mb() -> float:
    """Rezidentul (RAM) procesului, MiB. Din /proc (Linux) — fără dependințe."""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
    except OSError:
        pass
    return 0.0


async def _db_ping_ms(db) -> float:
    """Latența unei interogări triviale — dacă DB-ul serializează prost sub sarcină,
    se vede aici înainte să afecteze poll-urile reale."""
    t0 = time.perf_counter()
    try:
        await db.fetchone("SELECT 1")
    except Exception:
        return -1.0
    return round((time.perf_counter() - t0) * 1000, 1)


async def snapshot(core, db) -> dict:
    """Blocul „gateway" din /api/status: sănătatea procesului însuși."""
    clients = sum(len(h.clients) for h in core.hubs.values())
    return {
        "rss_mb": _rss_mb(),
        "event_loop_lag_ms": round(_lag_ms, 1),
        "event_loop_lag_max_ms": round(_lag_max_ms, 1),
        "browser_clients": clients,
        "active_hubs": len(core.hubs),
        "agent_connections": len(core.sources),
        "db_ping_ms": await _db_ping_ms(db),
    }
