"""Commands sent to a host through the agent's `run` op, shared by several route modules:
`host_run` (agent hosts only; errors mapped to ApiError), the identifiers a Docker container /
systemd unit must match before they reach a shell (`DOCKER_ID`, `UNIT_RE`), and the terminal
commands of the Docker "Logs" / "Shell" sessions. Moved out of api.py.
"""
import asyncio
import re
import shlex

from .errors import ApiError
from . import core


DOCKER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")   # id sau nume de container


DOCKER_ACCESS_HINT = ("[WebTerm] If docker reported a permission error: the agent user cannot reach "
                      "the Docker daemon. The Docker panel shows the fix options.")


def docker_session_cmd(docker_cmd: str) -> str:
    """Învelişul comun al sesiunilor Docker din terminal („Logs", „Shell"): accesul la docker
    urmează `docker_api._docker_run` — direct dacă userul agentului ajunge la socket, altfel `sudo -n`
    (passwordless) dacă există, NICIODATĂ un prompt de parolă agăţat în terminal; altfel rulăm
    comanda simplă, ca omul să vadă eroarea reală a lui docker, plus o indicaţie.
    `docker_cmd` e deja compus din bucăţi shell-quotate de apelant."""
    sh = ('if docker version >/dev/null 2>&1; then exec %s; '
          'elif command -v sudo >/dev/null 2>&1 && sudo -n docker version >/dev/null 2>&1; then exec sudo -n %s; '
          'else %s; echo; echo %s; fi') % (docker_cmd, docker_cmd, docker_cmd, shlex.quote(DOCKER_ACCESS_HINT))
    return "sh -c %s" % shlex.quote(sh)


def docker_logs_cmd(container: str) -> str:
    """Comanda sesiunii „Logs" a unui container: `docker logs --tail 500 -f` într-un terminal
    (culori, scrollback, căutare, Ctrl+C), ca „Logs" din Services (`journalctl -f`). Id-ul e
    validat de apelant cu DOCKER_ID ŞI shell-quotat aici. Acces: `docker_session_cmd`."""
    return docker_session_cmd("docker logs --tail 500 --timestamps -f %s" % shlex.quote(container))


def docker_exec_cmd(container: str) -> str:
    """Comanda sesiunii „Shell" a unui container (3.5.15: acelaşi direct → `sudo -n` → simplu +
    indicaţie ca „Logs"; până acum era `docker exec` gol, care pe un host unde agentul nu e în
    grupul docker murea cu „permission denied" chiar dacă lista şi logurile mergeau prin sudo).

    bash dacă există, altfel sh. NU `exec bash || exec sh`: într-un shell NEinteractiv
    `exec <lipsă>` iese cu 127 ÎNAINTE de `||`, deci pe imaginile fără bash (alpine/busybox)
    sesiunea murea instant cu „bash: not found". `command -v` testează întâi, fără să iasă."""
    inner = "command -v bash >/dev/null 2>&1 && exec bash || exec sh"
    return docker_session_cmd("docker exec -it %s sh -c %s" % (shlex.quote(container), shlex.quote(inner)))


async def host_run(host_id: int, cmd: str, timeout: int = 20) -> dict:
    conn = core.source_for(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise ApiError(409, "host.offline", "host offline or has no agent")
    try:
        resp = await conn.run_command(cmd, timeout)
    except (core.AgentGone, TimeoutError, asyncio.TimeoutError):
        raise ApiError(504, "host.noAnswer", "the host did not answer in time")
    if not resp.get("ok"):
        raise ApiError(502, "run.failed", resp.get("msg") or "run failed")
    return resp


# unitate systemd: nume + tip, fără spaţii/shell (`nginx.service`, `user@1000.service`, `sshd`)
UNIT_RE = re.compile(r"^[A-Za-z0-9@._\\:-]{1,128}$")
