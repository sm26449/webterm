"""The command guardrail on the server side: the admin's block / confirm regex rules
(`load_command_guard`, defaults in `COMMAND_GUARD_DEFAULT`), matching a command with a per-rule
time budget in a killable worker (`match_guard_rule`) and `enforce_guard`, which every route that
sends a command to a host calls first (`/run`, the git, Docker and Services panels). The rules
are edited in api.py `[settings]`. Moved out of api.py so the route modules can share it.
"""
import json
import logging
import re
import time

from .errors import ApiError
from . import audit, db, security

log = logging.getLogger("webterm")


# --- Guardrail de comenzi --------------------------------------------------------
# Aceleaşi reguli în două locuri: la Enter în browser (via OSC 133, lib/broadcastGuard.ts) şi aici,
# pe server, pentru comenzile pe care le trimite gateway-ul (`/run`, panourile git/Docker/Services).
# E o plasă de siguranţă contra greşelilor (rm -rf /, mkfs, DROP DATABASE…), nu un control de acces.
# Reguli regex, editabile din Setări.
COMMAND_GUARD_DEFAULT = {
    "enabled": True,
    "rules": [
        {"pattern": r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)\s+/", "action": "confirm"},
        {"pattern": r"\bmkfs\b", "action": "confirm"},
        {"pattern": r"\bdd\b.*\bof=/dev/", "action": "confirm"},
        {"pattern": r":\s*\(\s*\)\s*\{.*:\s*\|\s*:", "action": "confirm"},   # fork bomb
        {"pattern": r"\bDROP\s+(DATABASE|TABLE)\b", "action": "confirm"},
        {"pattern": r">\s*/dev/sd", "action": "confirm"},
    ],
}


async def load_command_guard() -> dict:
    raw = await db.get_setting("command_guard")
    if not raw:
        return {k: (list(v) if isinstance(v, list) else v) for k, v in COMMAND_GUARD_DEFAULT.items()}
    try:
        cfg = json.loads(raw)
    except (ValueError, TypeError):
        return dict(COMMAND_GUARD_DEFAULT)
    rules = []
    for r in cfg.get("rules", []) if isinstance(cfg.get("rules"), list) else []:
        if isinstance(r, dict) and r.get("pattern"):
            rules.append({"pattern": str(r["pattern"])[:300],
                          "action": "block" if r.get("action") == "block" else "confirm"})
    return {"enabled": bool(cfg.get("enabled", True)), "rules": rules[:100]}


# Bugetul per regulă (secunde). Un regex sănătos pe o linie de comandă termină în microsecunde;
# ce depăşeşte asta e backtracking catastrofal, nu „o comandă lungă".
GUARD_RE_BUDGET = security.REGEX_BUDGET


async def guard_rule_over_budget(pattern: str, where: str) -> None:
    """O regulă a depăşit bugetul: worker-ul a fost omorât şi regula NU se aplică pe comanda
    asta. Lăsăm urmă (log + jurnal de audit, cu regula numită) — altfel plasa de siguranţă
    s-ar rări în tăcere, iar adminul n-ar afla decât când o comandă „interzisă" trece."""
    log.warning("command guard: rule %r exceeded the %.2fs budget (%s) — skipped",
                pattern[:120], GUARD_RE_BUDGET, where)
    await audit.record(time.time(), "system:guardrail", "-", "GUARD", "/api/settings/command-guard",
                       408, "regulă de guardrail peste buget (%.2fs), sărită la %s: %s"
                       % (GUARD_RE_BUDGET, where, pattern[:200]))


async def match_guard_rule(cmd: str) -> dict | None:
    """Regula activă care se potriveşte pe comandă, sau None — regulile `block` ÎNAINTEA celor
    `confirm`. Înainte câştiga prima din listă: un `confirm` larg (`rm`) pus deasupra unui
    `block` (`rm -rf /`) făcea blocarea ocolibilă cu `confirmed: true` (3.5.1). Regex invalid =
    ignorat (aceeaşi toleranţă ca în client: serverul validează la salvare)."""
    guard = await load_command_guard()
    if not guard.get("enabled"):
        return None
    # F-09: regulile sunt scrise de admin, iar `re.search` e sincron şi neîntreruptibil. Prima
    # mitigare (`wait_for` peste `to_thread`, buget 0,25 s) nu limita nimic: `wait_for` aşteaptă
    # firul, deci cererea `/run` atârna cât regex-ul (măsurat de auditul din 2026-10-04: 12,9 s
    # pentru `^(a+)+$` pe 28 de caractere) şi fiecare apel ocupa un thread din pool-ul implicit.
    # Acum potrivirea rulează într-un proces separat care e OMORÂT la depăşire — CPU-ul chiar
    # se eliberează, iar regula patologică e sărită cu urmă în audit (vezi
    # `security.regex_search_budget`). Regulile sănătoase se comportă identic.
    try:
        rules = guard.get("rules", [])
        ordered = [r for r in rules if r.get("action") == "block"] + \
                  [r for r in rules if r.get("action") != "block"]
        for r in ordered:
            try:
                hit = await security.regex_search_budget(r["pattern"], [cmd], re.IGNORECASE,
                                                         GUARD_RE_BUDGET)
            except re.error:
                continue
            if hit is None:
                await guard_rule_over_budget(r["pattern"], "run")
                continue
            if hit:
                return r
        return None
    finally:
        security.regex_worker_release()


async def enforce_guard(cmd: str, confirmed: bool) -> None:
    """Aplică guardrail-ul pe o comandă care pleacă spre host: `block` → 403, `confirm` fără un DA
    explicit → 409 (clientul întreabă omul şi retrimite cu `confirmed: true`). Folosit de `/run` ŞI
    de acţiunile din panouri (git care scrie, docker, services): înainte doar `/run` era verificat,
    deci o regulă `systemctl\\s+stop` nu oprea butonul Stop din panoul de servicii (3.5.2)."""
    rule = await match_guard_rule(cmd)
    if rule and rule["action"] == "block":
        raise ApiError(403, "run.guardBlocked", "command blocked by a guardrail: /%s/" % rule["pattern"],
                       vars={"pattern": rule["pattern"]})
    if rule and not confirmed:
        raise ApiError(409, "run.guardConfirm", "command flagged for confirmation by a guardrail: /%s/"
                       % rule["pattern"], vars={"pattern": rule["pattern"]})
