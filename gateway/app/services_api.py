"""Services panel: systemd services (list, start / stop / restart), listening ports and the
diagnostics probes, through the agent's `run` op (`hostcmd.host_run`). Panel actions go through
the command guardrail (`cmdguard.enforce_guard`). Moved out of api.py; nothing here imports api.py.
"""
import logging
import re
import shlex

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from .errors import ApiError
from . import audit, authz, cmdguard, hostcmd, stepup

log = logging.getLogger("webterm")
# Aceeaşi gardă ca api.router (fail-closed): o rută fără permisiune declarată → 500 authz.undeclared.
router = APIRouter(dependencies=[Depends(authz.declared)])


# ── [services] systemd services + listening ports: acelaşi model ca Docker (prin op-ul `run`, ZERO op nou
#    în agent → fără re-semnare). Doar host-uri de agent (systemctl/ss sunt locale pe host). ──


_SERVICE_ACTIONS = {"start", "stop", "restart"}     # lifecycle; NU enable/disable/mask din UI


@router.get("/api/hosts/{host_id}/services")
async def services_list(host_id: int, failed: bool = False, user=Depends(authz.perm('services.view', host='host_id'))):
    """Unităţile systemd de tip service (nume, load/active/sub, descriere). Citire de stare de
    host → aceeaşi poartă de step-up ca docker_list / fs_list. `failed=1` → doar unităţile căzute
    (triajul „ce e stricat pe hostul ăsta"), cu `--state=failed` în loc de `--all`."""
    await stepup.require_host_stepup(host_id, user)
    # --plain fără legendă/paginare: coloane fixe UNIT LOAD ACTIVE SUB DESCRIPTION.
    # `--all` include şi serviciile oprite (altfel n-ai ce porni din UI). NU redirectăm stderr şi
    # NU forţăm exit 0: altfel „systemctl: not found" ajungea în /dev/null şi ramura de absenţă era
    # cod mort — un host fără systemd întorcea o listă goală tăcută, nedistinctă de „zero servicii"
    # (audit 2026-09). Deosebim după exit_code + stderr, exact ca docker_list.
    state = "--state=failed" if failed else "--all"
    resp = await hostcmd.host_run(host_id,
        "systemctl list-units --type=service %s --no-legend --no-pager --plain" % state)
    ec, out, err = resp.get("exit_code"), resp.get("stdout", ""), (resp.get("stderr") or "")
    if ec != 0 and not out.strip():
        low = err.lower()
        if "not found" in low or "command not found" in low or "no such file" in low:
            raise ApiError(400, "services.absent", "systemctl is not available on this host")
        raise ApiError(400, "services.failed", err.strip()[:300] or "systemctl failed")
    rows = []
    for line in out.splitlines():
        # marcajul de stare din prima coloană (●/×) apare doar cu --legend; --plain îl omite,
        # dar tăiem defensiv orice non-alfanumeric de la început
        line = line.lstrip("●×* \t")
        f = line.split(None, 4)
        if len(f) >= 4 and f[0].endswith(".service"):
            rows.append({"unit": f[0], "load": f[1], "active": f[2], "sub": f[3],
                         "desc": f[4] if len(f) == 5 else ""})
    return {"rows": rows}


class ServiceAction(BaseModel):
    unit: str
    action: str
    confirmed: bool = False    # guardrail `confirm`
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


@router.post("/api/hosts/{host_id}/services/action")
async def service_action(host_id: int, body: ServiceAction, request: Request,
                         user=Depends(authz.perm('services.act', host='host_id'))):
    """start/stop/restart pe o unitate. Acţiune pe host → step-up ca /run şi docker_action.
    Rulează ca userul agentului: fără root/policykit, stop/start pe unităţi de sistem eşuează
    cu „access denied" — surfaced ca atare, nu tăcut."""
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    if body.action not in _SERVICE_ACTIONS:
        raise ApiError(400, "services.badAction", "unknown service action")
    if not hostcmd.UNIT_RE.match(body.unit or ""):
        raise ApiError(400, "services.badUnit", "invalid unit name")
    svc_cmd = "systemctl %s %s" % (shlex.quote(body.action), shlex.quote(body.unit))
    await cmdguard.enforce_guard(svc_cmd, body.confirmed)
    audit.detail(request, "service %s %s" % (body.action, body.unit))
    resp = await hostcmd.host_run(host_id, svc_cmd, timeout=30)
    if resp.get("exit_code") != 0:
        raise ApiError(400, "services.failed", (resp.get("stderr") or "systemctl failed").strip()[:300])
    return {"ok": True}


@router.get("/api/hosts/{host_id}/ports")
async def listening_ports(host_id: int, user=Depends(authz.perm('host.diagnostics', host='host_id'))):
    """Socket-urile în ASCULTARE (`ss -tulnH`), parsate. Citire de stare de host → step-up.
    Numele procesului cere de obicei root; fără el coloana `users` lipseşte, restul rămâne util."""
    await stepup.require_host_stepup(host_id, user)
    # `ss -tulnpH`: -p adaugă procesul (cere de obicei root). Dacă `ss` lipseşte, spunem asta —
    # nu întoarcem o listă goală tăcută (ca la services). Prima încercare cu -p pe stderr propriu;
    # fallback fără -p dacă -p n-a mers, dar tot verificăm că `ss` există.
    resp = await hostcmd.host_run(host_id,
        "if command -v ss >/dev/null 2>&1; then ss -tulnpH 2>/dev/null || ss -tulnH; "
        "else echo __NO_SS__; fi")
    out = resp.get("stdout", "")
    if out.strip() == "__NO_SS__":
        raise ApiError(400, "ports.absent", "ss (iproute2) is not available on this host")
    rows = []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        # Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]
        local = f[4]
        addr, _, port = local.rpartition(":")
        proc = ""
        m = re.search(r'\("([^"]+)",pid=(\d+)', line)
        if m:
            proc = "%s (%s)" % (m.group(1), m.group(2))
        rows.append({"proto": f[0], "addr": addr or "*", "port": port, "process": proc})
    # ordonate numeric după port, stabil
    rows.sort(key=lambda r: (int(r["port"]) if r["port"].isdigit() else 1 << 20, r["proto"]))
    return {"rows": rows}


# Probe de diagnostic ON-DEMAND (nu în snapshot-ul orar al agentului, deci fără atingere de agent):
# parsăm utilitarele standard şi întoarcem text ETICHETAT pe secţiuni. Read-only, degradează
# curat fără root (smartctl/nft cer de obicei root → afişăm „needs root", nu listă goală tăcută).
_DIAG_PROBES = {
    "storage": (
        "echo '### lsblk'; command -v lsblk >/dev/null 2>&1 && "
        "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null || echo '(lsblk unavailable)'; "
        "echo; echo '### SMART health'; if command -v smartctl >/dev/null 2>&1; then "
        "for d in $(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2==\"disk\"{print $1}'); do "
        "echo \"/dev/$d:\"; smartctl -H \"/dev/$d\" 2>&1 | "
        "grep -iE 'overall-health|SMART Health|result' || echo '  (no SMART data / needs root)'; "
        "done; else echo '(smartctl not installed)'; fi; "
        "echo; echo '### ZFS'; command -v zpool >/dev/null 2>&1 && zpool status 2>&1 || echo '(no zpool)'"),
    "net": (
        "echo '### neighbors (ARP/ND)'; command -v ip >/dev/null 2>&1 && ip neigh 2>/dev/null || "
        "arp -an 2>/dev/null || echo '(no ip/arp)'; "
        "echo; echo '### firewall'; if command -v nft >/dev/null 2>&1; then "
        "nft list ruleset 2>&1 | head -n 300; "
        "elif command -v iptables-save >/dev/null 2>&1; then iptables-save 2>&1 | head -n 300; "
        "else echo '(no nft / iptables — or needs root)'; fi"),
}


@router.get("/api/hosts/{host_id}/diag-probe")
async def diag_probe(host_id: int, kind: str = "storage", user=Depends(authz.perm('host.diagnostics', host='host_id'))):
    """Probe on-demand (storage: lsblk/SMART/zpool · net: neighbors/firewall). Citire de stare de
    host → step-up ca ports/services. Text brut etichetat pe secţiuni — nu reinterpretăm modelul
    uneltei (glue), doar îl arătăm cohesiv."""
    await stepup.require_host_stepup(host_id, user)
    recipe = _DIAG_PROBES.get(kind)
    if not recipe:
        raise ApiError(400, "diag.badProbe", "unknown probe")
    resp = await hostcmd.host_run(host_id, recipe, timeout=25)
    return {"text": (resp.get("stdout", "") or "")[:60000]}
