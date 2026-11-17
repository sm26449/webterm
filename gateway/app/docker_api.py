"""Docker panel: containers / volumes / networks, per-container stats and start / stop / restart,
all through the agent's existing `run` op (no new agent op). The terminal sessions for a
container's logs and shell are built in `hostcmd.py` (the session route in api.py uses them too).
Moved out of api.py; nothing here imports api.py.
"""
import asyncio
import json
import logging
import re
import shlex
import time
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from .errors import ApiError
from . import audit, authz, cmdguard, core, db, hostcmd, stepup

log = logging.getLogger("webterm")
# Aceeaşi gardă ca api.router (fail-closed): o rută fără permisiune declarată → 500 authz.undeclared.
router = APIRouter(dependencies=[Depends(authz.declared)])


# ── [docker] Docker: containere / volume / reţele, prin op-ul `run` (agent NEatins) ───
# Acelaşi tipar ca panoul de git: CLI-ul docker rulează prin `run_command`, argv
# shell-quotat server-side, ZERO op-uri noi în agent (deci fără re-semnare). Doar
# citire + acţiuni de lifecycle (start/stop/restart) + logs; shell-ul în container
# se face prin crearea unei sesiuni cu `docker exec` (vezi SessionIn.docker_container).
_DOCKER_KINDS = {
    # kind → (subcomanda de listare, format Go template pe linie = un JSON per rând)
    "containers": ["ps", "-a", "--no-trunc", "--format", "{{json .}}"],
    "images":     ["images", "--format", "{{json .}}"],
    "volumes":    ["volume", "ls", "--format", "{{json .}}"],
    "networks":   ["network", "ls", "--no-trunc", "--format", "{{json .}}"],
}


_DOCKER_ACTIONS = {"start", "stop", "restart"}     # lifecycle; NU rm/prune din UI (distructiv)


def _docker_denied(err: str) -> bool:
    """stderr-ul lui docker când userul agentului nu poate atinge socketul (nu e în grupul docker)."""
    low = (err or "").lower()
    return "permission denied" in low or "/var/run/docker.sock" in low


async def _docker_run(host_id: int, argv: list[str], timeout: int = 20) -> dict:
    """Rulează `docker <argv>` pe host prin op-ul `run`. Dacă userul agentului nu e în grupul
    docker (permission denied pe socket), reîncearcă O DATĂ cu `sudo -n` — ca la os_upgrade: pe
    hosturile unde agentul are sudo passwordless merge transparent; altfel `sudo -n` pică rapid
    şi păstrăm răspunsul original (mesajul „adaugă-l în grupul docker"). Întoarce răspunsul brut."""
    conn = core.source_for(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise ApiError(409, "host.offline", "host offline or has no agent")
    cmd = " ".join(shlex.quote(p) for p in (["docker"] + argv))
    try:
        resp = await conn.run_command(cmd, timeout)
        if resp.get("ok") and resp.get("exit_code") not in (0, None) and _docker_denied(resp.get("stderr") or ""):
            # `sudo -n`: NU agăţăm niciodată la un prompt de parolă — iese cu eroare dacă nu e passwordless
            alt = await conn.run_command("sudo -n " + cmd, timeout)
            if alt.get("ok") and alt.get("exit_code") == 0:
                return alt
    except (core.AgentGone, TimeoutError, asyncio.TimeoutError):
        raise ApiError(504, "host.noAnswer", "the host did not answer in time")
    if not resp.get("ok"):
        raise ApiError(502, "run.failed", resp.get("msg") or "run failed")
    return resp


def _docker_error(err: str) -> ApiError:
    """Eroarea clară pentru un `docker …` cu exit≠0: lipsă / fără acces / altceva. Comună listei
    şi statisticilor, ca acelaşi host să spună acelaşi lucru în ambele locuri."""
    # docker lipseşte / demonul e oprit / userul agentului nu e în grupul docker: mesaj clar,
    # nu o listă goală tăcută (frontend-ul deosebeşte „nu e docker aici" de „zero containere")
    low = (err or "").lower()
    if "command not found" in low or ("not found" in low and "docker" in low):
        return ApiError(400, "docker.absent", "docker is not installed on this host")
    if _docker_denied(err):
        # am încercat deja `sudo -n` în _docker_run şi tot a picat → ghidăm userul să dea acces
        # Onest (audit 2026-10-04, LOW #8): accesul la socketul docker ESTE root pe host, deci
        # orice remediu renunţă la bariera userului dedicat din THREAT-MODEL. O spunem, nu o
        # ascundem după comandă; regula sudoers îngustă e preferată (explicită, jurnalizată,
        # merge imediat prin fallback-ul `sudo -n` de mai sus, fără restart de agent).
        return ApiError(400, "docker.denied",
                        "the agent's user isn't in the docker group and has no passwordless sudo. "
                        "Either fix makes that user root-equivalent on the host (docker access is "
                        "root) and gives up the dedicated-user barrier from the threat model — "
                        "grant it deliberately, as root: a sudoers rule limited to docker "
                        "(preferred), or usermod -aG docker <agent-user> and restart the agent.")
    return ApiError(400, "docker.failed", (err or "").strip()[:300] or "docker failed")


@router.get("/api/hosts/{host_id}/docker")
async def docker_list(host_id: int, kind: str, user=Depends(authz.perm('docker.view', host='host_id'))):
    """Listează containere/imagini/volume/reţele. Fiecare rând e un JSON (format Go template),
    parsat aici într-o listă de obiecte — frontend-ul primeşte date, nu text de ecran."""
    await stepup.require_host_stepup(host_id, user)   # citeşte date de pe host → aceeaşi poartă ca fs_list
    argv = _DOCKER_KINDS.get(kind)
    if not argv:
        raise ApiError(400, "docker.badKind", "unknown docker kind")
    resp = await _docker_run(host_id, argv)
    ec, out, err = resp.get("exit_code"), resp.get("stdout", ""), (resp.get("stderr") or "")
    if ec != 0:
        raise _docker_error(err)
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return {"kind": kind, "rows": rows}


# ── [docker] Statistici per container (`docker stats --no-stream`) ────────────────────
# docker scrie mărimile pentru oameni: memoria în unităţi BINARE („12.3MiB / 7.6GiB", go-units
# BytesSize), reţeaua şi discul în ZECIMALE („1.2kB / 0B", HumanSize), procentele cu „%". Un
# container care porneşte/se opreşte chiar în timpul eşantionării dă „--" (sau „-- / --"). Le
# transformăm AICI în numere (octeţi, procente) — frontend-ul formatează, nu parsează text.
_SIZE_UNITS = {
    "b": 1,
    "kb": 1000, "mb": 1000 ** 2, "gb": 1000 ** 3, "tb": 1000 ** 4, "pb": 1000 ** 5,
    "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "tib": 1024 ** 4, "pib": 1024 ** 5,
}


_SIZE_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE]([+-]?[0-9]{1,3}))?\s*([A-Za-z]*)$")


_STATS_NA = {"", "-", "--", "n/a", "na"}


_DOCKER_STATS_TIMEOUT = 6    # secunde; `--no-stream` eşantionează ~2 s, peste asta hostul e încărcat


_DOCKER_STATS_TTL = 3.0      # mai multe taburi pe acelaşi panou → o singură rulare pe host la ~3 s


_docker_stats_cache: dict = {}      # host_id → (monotonic, rezultat)


_docker_stats_inflight: dict = {}   # host_id → Task (o singură rulare în zbor pe host)


def _parse_size(text) -> Optional[int]:
    """„12.3MiB" → 12897485; „1.2kB" → 1200; „0B" → 0. `None` pentru „--", gol sau unitate
    necunoscută (mai bine «indisponibil» decât un număr inventat)."""
    if not isinstance(text, str):
        return None
    t = text.strip()
    if t.lower() in _STATS_NA:
        return None
    m = _SIZE_RE.match(t)
    if not m:
        return None
    mult = _SIZE_UNITS.get((m.group(3) or "b").lower())
    if mult is None:
        return None
    val = float(m.group(1)) * (10 ** int(m.group(2)) if m.group(2) else 1) * mult
    if val != val or val in (float("inf"), float("-inf")) or val < 0:   # NaN / inf
        return None
    return int(round(val))


def _parse_pct(text) -> Optional[float]:
    """„12.34%" → 12.34. `None` pentru „--"/gol/text. CPU poate trece de 100 (mai multe nuclee)."""
    if not isinstance(text, str):
        return None
    t = text.strip().rstrip("%").strip()
    if t.lower() in _STATS_NA:
        return None
    try:
        v = float(t)
    except ValueError:
        return None
    if v != v or v in (float("inf"), float("-inf")) or v < 0:
        return None
    return round(v, 2)


def _parse_pair(text) -> tuple:
    """„12.3MiB / 7.6GiB" → (12897485, 8160437862). Fiecare jumătate poate lipsi („-- / --")."""
    if not isinstance(text, str) or "/" not in text:
        return (_parse_size(text), None)
    a, _, b = text.partition("/")
    return (_parse_size(a), _parse_size(b))


def _parse_docker_stats(out: str) -> list:
    """Ieşirea lui `docker stats --no-stream --format '{{json .}}'` (un JSON pe linie) → rânduri
    cu numere. Liniile care nu sunt JSON (avertismente, gunoi) sunt sărite, nu fatale."""
    rows = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue
        mem_used, mem_limit = _parse_pair(r.get("MemUsage"))
        mem_pct = _parse_pct(r.get("MemPerc"))
        if mem_pct is None and mem_used is not None and mem_limit:
            mem_pct = round(mem_used * 100.0 / mem_limit, 2)
        net_rx, net_tx = _parse_pair(r.get("NetIO"))
        blk_r, blk_w = _parse_pair(r.get("BlockIO"))
        pids = r.get("PIDs")
        try:
            pids = int(str(pids).strip())
        except (TypeError, ValueError):
            pids = None
        rows.append({
            "id": str(r.get("ID") or r.get("Container") or ""),
            "name": str(r.get("Name") or ""),
            "cpu_pct": _parse_pct(r.get("CPUPerc")),
            "mem_used": mem_used, "mem_limit": mem_limit, "mem_pct": mem_pct,
            "net_rx": net_rx, "net_tx": net_tx,
            "block_read": blk_r, "block_write": blk_w,
            "pids": pids,
        })
    return rows


async def _docker_stats_fetch(host_id: int) -> dict:
    resp = await _docker_run(host_id, ["stats", "--no-stream", "--format", "{{json .}}"],
                             timeout=_DOCKER_STATS_TIMEOUT)
    if resp.get("timed_out") or resp.get("exit_code") is None:
        # hostul n-a terminat în timp (multe containere / încărcat): „indisponibil", NU o eroare —
        # panoul îşi răreşte singur sondajul; nu cache-uim, următorul tick reîncearcă
        return {"available": False, "reason": "timeout", "rows": []}
    if resp.get("exit_code") != 0:
        raise _docker_error(resp.get("stderr") or "")
    out = {"available": True, "rows": _parse_docker_stats(resp.get("stdout", "")),
           "host_cpus": await _host_cpu_count(host_id)}
    _docker_stats_cache[host_id] = (time.monotonic(), out)
    return out


async def _host_cpu_count(host_id: int) -> Optional[int]:
    """Nucleele hostului (3.5.15), ca UI-ul să arate CPU-ul unui container RELATIV la host:
    `docker stats` dă procentul pe UN nucleu (400% = patru nuclee pline), deci pe o maşină de 8
    nuclee „96%" înseamnă 12% din host. Sursa e snapshot-ul de diagnostic pe care agentul îl
    pushează deja (`cpu.cores` din /proc/cpuinfo) — întâi cel din memorie, apoi cel din DB; nicio
    rulare în plus pe host. `None` = necunoscut → UI-ul arată valoarea brută, marcată „per nucleu"."""
    diag = None
    conn = core.source_for(host_id)
    if isinstance(getattr(conn, "diagnostics", None), dict):
        diag = conn.diagnostics
    else:
        row = await db.fetchone("SELECT diagnostics FROM hosts WHERE id=?", host_id)
        if row and row["diagnostics"] and len(row["diagnostics"]) <= core.DIAG_MAX_BYTES:
            try:
                diag = json.loads(row["diagnostics"])
            except ValueError:
                diag = None
    cpu = diag.get("cpu") if isinstance(diag, dict) else None
    n = cpu.get("cores") if isinstance(cpu, dict) else None
    return n if isinstance(n, int) and not isinstance(n, bool) and 0 < n <= 4096 else None


@router.get("/api/hosts/{host_id}/docker/stats")
async def docker_stats(host_id: int, user=Depends(authz.perm('docker.view', host='host_id'))):
    """CPU %, memorie (folosită/limită/%), I/O de reţea şi disc pentru containerele PORNITE.
    Aceleaşi reguli de acces ca docker_list (cookie, step-up pe host 2FA); numere, nu text."""
    await stepup.require_host_stepup(host_id, user)   # EXACT ca docker_list
    hit = _docker_stats_cache.get(host_id)
    if hit and time.monotonic() - hit[0] < _DOCKER_STATS_TTL:
        return hit[1]
    task = _docker_stats_inflight.get(host_id)
    if task is None:
        task = asyncio.ensure_future(_docker_stats_fetch(host_id))
        _docker_stats_inflight[host_id] = task
        task.add_done_callback(lambda _t, h=host_id: _docker_stats_inflight.pop(h, None))
    # shield: un client care închide panoul (cerere anulată) nu anulează rularea pe care o
    # aşteaptă şi celelalte taburi
    return await asyncio.shield(task)


class DockerAction(BaseModel):
    container: str
    action: str
    confirmed: bool = False    # guardrail `confirm`
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


@router.post("/api/hosts/{host_id}/docker/action")
async def docker_action(host_id: int, body: DockerAction, request: Request,
                        user=Depends(authz.perm('docker.act', host='host_id'))):
    """start/stop/restart pe un container. Acţiune pe host → aceeaşi poartă de step-up ca /run."""
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    if body.action not in _DOCKER_ACTIONS:
        raise ApiError(400, "docker.badAction", "unknown docker action")
    if not hostcmd.DOCKER_ID.match(body.container or ""):
        raise ApiError(400, "docker.badContainer", "invalid container id")
    # guardrail pe comanda echivalentă din shell, ca o regulă `docker\s+stop` să oprească şi butonul
    await cmdguard.enforce_guard("docker %s %s" % (body.action, body.container), body.confirmed)
    audit.detail(request, "docker %s %s" % (body.action, body.container))
    resp = await _docker_run(host_id, [body.action, body.container], timeout=30)
    if resp.get("exit_code") != 0:
        raise ApiError(400, "docker.failed", (resp.get("stderr") or "docker failed").strip()[:300])
    return {"ok": True}
