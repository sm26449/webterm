"""Task-uri asyncio lansate „în fundal" (fără await), ţinute în viaţă până se termină.

Bucla asyncio păstrează doar o referinţă SLABĂ la task-uri: un `asyncio.create_task(...)` al cărui
rezultat nu e reţinut poate fi colectat de garbage collector în timp ce rulează, iar o excepţie a lui
nu ajunge nicăieri (SonarQube S7502, verificat 2026-11-20). `spawn` ţine referinţa într-un set până la
final şi scrie în log excepţia unui task eşuat. Modul fără dependenţe din aplicaţie: îl pot folosi
toate straturile (security, core, rutele)."""
import asyncio
import logging

log = logging.getLogger("webterm.bg")

_tasks: set = set()


def spawn(coro, name: str = "") -> "asyncio.Future":
    task = asyncio.ensure_future(coro)
    _tasks.add(task)

    def _done(t: "asyncio.Future") -> None:
        _tasks.discard(t)
        if t.cancelled():
            return
        exc = t.exception()
        if exc is not None:
            log.error("background task %s failed", name or "?", exc_info=exc)

    task.add_done_callback(_done)
    return task


def pending() -> int:
    """Câte task-uri de fundal sunt încă în viaţă (teste, diagnostic)."""
    return len(_tasks)
