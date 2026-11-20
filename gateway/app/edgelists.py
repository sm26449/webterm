"""Listele allow / deny pentru `/agent/ws`, scrise pentru Traefik (3.6.38).

Traefik nu poate şti dacă un token e valid; gateway-ul ştie. Aşa că gateway-ul îi spune proxy-ului,
printr-un fişier de configurare dinamică (providerul `file` al lui Traefik, recitit la schimbare):

  allow  adresele de pe care s-a conectat un agent VALID. Primesc o limită largă, ca o flotă întreagă
         din spatele unui NAT să treacă oricând, chiar dacă pe aceeaşi adresă e şi un atacator.
         TTL alunecător: cât timp are un agent conectat + `ALLOW_TTL` după ultima conexiune validă.
  deny   adresele blocate de agentgate (tokenuri greşite repetate). Traefik le răspunde direct
         (un ipAllowList care nu permite nimic, 403), fără să ajungă la gateway. TTL = durata blocării
         (10 min, dublată la recidivă, cel mult 24 h).
  restul limita strictă din etichetele compose (routerul `webterm-agent`).

O adresă în ambele liste e tratată ca allow (prioritate mai mare): agenţii dintr-un NAT împărţit cu
un atacator nu sunt blocaţi la proxy; atacatorul e refuzat oricum de gateway, din memorie.

Fail-safe: fişierul conţine DOAR routere pentru calea exactă `/agent/ws`, cu adrese validate prin
`ipaddress`, plafonate (`MAX_ALLOW`, `MAX_DENY`). Dacă lipseşte sau e invalid, Traefik îl ignoră şi
rămâne limita strictă, nu se deschide nimic. Verificat pe Traefik 3.7.10 şi 3.7.19: `ClientIP()`
primeşte o SINGURĂ adresă/CIDR (de aici lanţul `||`), reîncărcarea fişierului nu închide conexiunile
deschise, iar o regulă invalidă scoate doar routerul ei.

Scrierea: atomică (fişier temporar + rename), cel mult o dată la `MIN_WRITE` secunde după o
schimbare şi oricum la `REWRITE` secunde (ca intrările expirate să dispară şi fără activitate).
Persistenţa e chiar fişierul: la pornire îl citim înapoi, ca o repornire a gateway-ului să nu golească
listele."""
import asyncio
import ipaddress
import json
import logging
import os
import re
import time
from typing import Optional

from . import agentgate, config, db, fwddomain

log = logging.getLogger("webterm.edgelists")

FILE_NAME = "agent-lists.yaml"            # JSON e YAML valid; Traefik alege parserul după extensie
MAX_ALLOW = 500
MAX_DENY = 500
MIN_WRITE = 10.0
REWRITE = 60.0

_allow: dict = {}                         # cheie (agentgate.ip_key) → expiră la
_connected: dict = {}                     # host_id → (cheie, marcaj de conexiune)
# Adrese de pe care s-a conectat VREODATĂ (în EVER_VALID_DAYS) un agent valid: nu intră niciodată în
# deny-ul de la proxy, oricât de blocate ar fi în gateway. Review 3.6.38: altfel un agent vechi uitat
# (host şters) care reîncearcă în buclă, sau un atacator dintr-un NAT împărţit, ţinea adresa în deny şi
# Traefik refuza (403) un agent VALID de acolo, fără să-i vadă tokenul. Gateway-ul îl refuză pe atacator
# oricum, din memorie.
_ever_valid: dict = {}                    # cheie → ultima conexiune validă
_ever_dirty = False                       # o adresă NOUĂ a intrat: se salvează în DB la următorul ciclu
_ever_loaded = False
K_EVER_VALID = "edge_ever_valid"
EVER_VALID_DAYS = 30
MAX_EVER_VALID = 2000
# Cât poate sta o adresă în deny-ul de la PROXY, oricât ar dura blocarea în gateway: o adresă nouă
# (niciodată validă) de pe care se înrolează un host chiar acum aşteaptă cel mult atât.
PROXY_DENY_MAX = 3600.0
_write_err_logged = ""
_last_written = ""
_last_write_at = 0.0
_loaded = False
status = {"enabled": False, "supported": True, "off_reason": "", "last_write": 0.0, "error": "",
          "allow": 0, "deny": 0}


def _dir() -> str:
    d = (config.AGENT_LISTS_DIR or "").strip()
    return "" if d.lower() in ("off", "0", "none") else d


def _cidr(key: str) -> Optional[str]:
    """Cheia lui agentgate → un CIDR pe care îl putem pune într-o regulă. Orice altceva (cheia comună
    `unknown`, un text ciudat) NU intră în fişier: refuzăm să scriem ce nu putem valida."""
    try:
        return str(ipaddress.ip_network(key, strict=False))
    except ValueError:
        return None


def note_agent_connected(host_id: int, ip: str, now: Optional[float] = None) -> object:
    """Agent valid conectat. Întoarce un marcaj de conexiune: `note_agent_disconnected` îl şterge doar
    dacă e tot al lui (review 3.6.38: o conexiune veche care se închide după ce a venit una nouă nu mai
    scoate adresa celei noi)."""
    now = now or time.time()
    key = agentgate.ip_key(ip)
    mark = object()
    if _cidr(key) is None:
        return mark
    _connected[host_id] = (key, mark)
    _allow[key] = now + config.AGENT_ALLOW_TTL
    global _ever_dirty
    if key not in _ever_valid:
        _ever_dirty = True
    _ever_valid[key] = now
    if len(_ever_valid) > MAX_EVER_VALID:
        for k, _ in sorted(_ever_valid.items(), key=lambda kv: kv[1])[:len(_ever_valid) - MAX_EVER_VALID]:
            del _ever_valid[k]
    return mark


def note_agent_disconnected(host_id: int, mark: object = None) -> None:
    cur = _connected.get(host_id)
    if cur and (mark is None or cur[1] is mark):
        del _connected[host_id]            # allow-ul rămâne încă ALLOW_TTL, apoi expiră


def _deny_now(now: float) -> dict:
    """Adresele blocate acum de agentgate, MINUS cele care au avut vreodată un agent valid, cu durata la
    proxy plafonată la PROXY_DENY_MAX (de la ultima blocare)."""
    horizon = now - EVER_VALID_DAYS * 86400
    out = {}
    for k, st in agentgate._state.items():
        if st[2] <= now or not _cidr(k) or _ever_valid.get(k, 0) > horizon:
            continue
        until = min(st[2], st[4] + PROXY_DENY_MAX)       # st[4] = ultima atingere (strike)
        if until > now:
            out[k] = until
    return out


def lists_supported() -> bool:
    """Listele lucrează pe adresa pe care o vede TRAEFIK (`ClientIP()` = perechea TCP). Dacă gateway-ul ia
    adresa clientului din antetele unui proxy din faţa lui Traefik (CDN), adresele nu s-ar potrivi şi
    listele n-ar face nimic, deci nu le scriem deloc (review 3.6.38)."""
    return (config.TRUSTED_PROXY_HOPS == 1 and not config.TRUST_CF_CONNECTING_IP
            and int(config.AGENT_RL_IP_DEPTH or 0) == 0)


def _hosts_rule() -> str:
    """Routerele din fişier se potrivesc DOAR pe numele nostru şi pe numele de forward (review 3.6.38:
    fără Host() prindeau /agent/ws pe orice domeniu servit de acelaşi Traefik)."""
    import urllib.parse
    host = (urllib.parse.urlsplit(config.PUBLIC_URL).hostname or "").lower()
    parts = []
    if host and fwddomain.valid_domain(host):
        parts.append("Host(`%s`)" % host)
    # Ambele domenii de forward: cel din .env (acelaşi ca în routerul din etichete) şi cel din Settings.
    # Altfel, cu Settings ≠ .env, deny-ul de la proxy se ocolea prin numele din .env (review 3.6.38).
    for fd in sorted({(fwddomain.DEFAULT_DOMAIN or "").lower(), (fwddomain.forward_domain() or "").lower()}):
        if fd and fwddomain.valid_domain(fd):
            parts.append("HostRegexp(`^[a-z0-9-]+\\.%s$`)" % re.escape(fd).replace("\\-", "-"))
    return "(" + " || ".join(parts) + ")" if parts else ""


def _rule(cidrs: list, hosts: str) -> str:
    return hosts + " && Path(`/agent/ws`) && (" + " || ".join("ClientIP(`%s`)" % c for c in cidrs) + ")"


def render(now: Optional[float] = None) -> dict:
    """Configuraţia dinamică (dict). Doar routere pe /agent/ws; listele goale = niciun router."""
    now = now or time.time()
    hosts = _hosts_rule()
    if not lists_supported():
        status.update(supported=False, off_reason="proxy")      # CDN / alt proxy în faţa lui Traefik
        return {}
    if not hosts:
        status.update(supported=False, off_reason="host")       # PUBLIC_URL fără un nume de domeniu valid
        return {}
    status.update(supported=True, off_reason="")
    for hid, (key, _m) in list(_connected.items()):       # conectat = prelungit
        _allow[key] = max(_allow.get(key, 0), now + config.AGENT_ALLOW_TTL)
        _ever_valid[key] = now
    for k in [k for k, exp in _allow.items() if exp <= now]:
        del _allow[k]
    allow = sorted(_allow.items(), key=lambda kv: -kv[1])[:MAX_ALLOW]
    deny = sorted(_deny_now(now).items(), key=lambda kv: -kv[1])[:MAX_DENY]
    allow_c = sorted({_cidr(k) for k, _ in allow if _cidr(k)})
    deny_c = sorted({_cidr(k) for k, _ in deny if _cidr(k)})
    status.update(allow=len(allow_c), deny=len(deny_c))
    routers, middlewares = {}, {}
    common = {"entryPoints": ["websecure"], "tls": {}}
    if allow_c:
        middlewares["webterm-agent-allow-rl"] = {"rateLimit": {
            "average": config.AGENT_ALLOW_AVERAGE, "burst": config.AGENT_ALLOW_BURST, "period": "1m",
            "sourceCriterion": {"ipStrategy": {"depth": config.AGENT_RL_IP_DEPTH, "ipv6Subnet": 64}}}}
        routers["webterm-agent-allow"] = dict(common, rule=_rule(allow_c, hosts), priority=3000, service="webterm@docker",
                                              middlewares=["webterm-agent-allow-rl@file", "webterm-agent-mark@docker",
                                                           "webterm-agent-bucket@docker", "webterm-agent-all@docker"])
    if deny_c:
        # Refuzul îl dă un ipAllowList care nu permite NICIO adresă (403, din Traefik, fără să atingă
        # gateway-ul). Nu `noop@internal`: Traefik nu-l numără în metricile routerului (verificat în
        # staging), deci refuzurile din deny n-ar fi apărut în System health.
        middlewares["webterm-agent-deny-all"] = {"ipAllowList": {"sourceRange": ["0.0.0.0/32"]}}
        routers["webterm-agent-deny"] = dict(common, rule=_rule(deny_c, hosts), priority=2000, service="webterm@docker",
                                             middlewares=["webterm-agent-deny-all@file"])
    # Fără intrări: un document GOL. Traefik respinge `routers: {}` („routers cannot be a standalone
    # element", verificat în staging) şi, cu el, TOT directorul providerului `file`.
    if not routers:
        return {}
    out = {"http": {"routers": routers}}
    if middlewares:
        out["http"]["middlewares"] = middlewares
    return out


def load(now: Optional[float] = None) -> None:
    """La pornire: allow-ul din fişierul existent revine în memorie (cu TTL plin: nu ştim de când e acolo,
    iar un allow nu deschide nimic, doar lărgeşte limita). Deny-ul NU se reîncarcă: îl decide agentgate,
    care porneşte gol, iar fişierul se rescrie imediat fără el."""
    global _loaded
    if _loaded:
        return
    _loaded = True
    d = _dir()
    if not d:
        return
    try:
        with open(os.path.join(d, FILE_NAME)) as f:
            data = json.load(f)
        rule = ((data or {}).get("http") or {}).get("routers", {}).get("webterm-agent-allow", {}).get("rule", "")
        now = now or time.time()
        for part in rule.split("ClientIP(`")[1:]:
            c = part.split("`", 1)[0]
            if _cidr(c):
                key = c[:-3] if c.endswith("/32") else c          # forma cheilor din agentgate.ip_key
                _allow.setdefault(key, now + config.AGENT_ALLOW_TTL)
                _ever_valid.setdefault(key, now)
    except FileNotFoundError:
        pass
    except Exception as e:                  # noqa: BLE001 — un fişier stricat nu opreşte nimic: îl rescriem
        log.warning("edgelists: could not read the previous lists (%s); starting empty", type(e).__name__)


def write(now: Optional[float] = None, force: bool = False) -> bool:
    """Scrie fişierul dacă s-a schimbat (cel mult la MIN_WRITE s) sau dacă a trecut REWRITE. Întoarce
    True dacă a scris."""
    global _last_written, _last_write_at, _write_err_logged
    now = now or time.time()
    d = _dir()
    status["enabled"] = bool(d)
    if not d:
        return False
    load(now)
    if not force and now - _last_write_at < MIN_WRITE:
        return False
    text = json.dumps(render(now), sort_keys=True, indent=1)
    if text == _last_written and not force and now - _last_write_at < REWRITE:
        return False
    path = os.path.join(d, FILE_NAME)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o644)              # Traefik rulează ca alt utilizator: trebuie să-l poată citi
        os.replace(tmp, path)
    except OSError as e:
        status["error"] = type(e).__name__
        _last_write_at = now                # reîncercăm la MIN_WRITE, nu la fiecare 5 s
        if _write_err_logged != type(e).__name__:     # un singur WARNING pe tip de eroare (review 3.6.38)
            _write_err_logged = type(e).__name__
            log.warning("edgelists: cannot write %s: %s (the fixed limits still apply)", path, type(e).__name__)
        return False
    _last_written, _last_write_at = text, now
    _write_err_logged = ""
    status.update(last_write=now, error="")
    return True


def reset_for_tests() -> None:
    global _last_written, _last_write_at, _loaded
    global _ever_dirty, _ever_loaded
    _allow.clear()
    _connected.clear()
    _ever_valid.clear()
    _ever_dirty, _ever_loaded = False, False
    _last_written, _last_write_at, _loaded = "", 0.0, False
    status.update(enabled=False, supported=True, off_reason="", last_write=0.0, error="", allow=0, deny=0)


async def persist_ever_valid(now: Optional[float] = None) -> None:
    """Excepţia „a avut vreodată un agent valid" trebuie să supravieţuiască repornirii gateway-ului
    (review 3.6.38: altfel, după o repornire, o adresă validă acum 3 zile putea ajunge în deny). Se
    scrie în DB doar când apare o adresă NOUĂ (rar), plus o dată pe zi ca să cadă cele expirate."""
    global _ever_dirty, _ever_loaded
    now = now or time.time()
    if not _ever_loaded:
        _ever_loaded = True
        try:
            stored = json.loads(await db.get_setting(K_EVER_VALID, "{}") or "{}")
            horizon = now - EVER_VALID_DAYS * 86400
            for k, ts in (stored or {}).items():
                if isinstance(ts, (int, float)) and ts > horizon and _cidr(str(k)):
                    _ever_valid[str(k)] = max(_ever_valid.get(str(k), 0), float(ts))
        except Exception:                  # noqa: BLE001 — o stare stricată nu opreşte nimic
            log.warning("edgelists: could not read the stored valid-agent addresses")
    if not _ever_dirty and int(now) % 86400 >= 5:
        return
    horizon = now - EVER_VALID_DAYS * 86400
    keep = {k: v for k, v in _ever_valid.items() if v > horizon}
    await db.set_setting(K_EVER_VALID, json.dumps(keep, sort_keys=True))
    _ever_dirty = False


async def loop() -> None:
    while True:
        try:
            await persist_ever_valid()
            write()
        except Exception:                  # noqa: BLE001 — bucla trebuie să supravieţuiască
            log.exception("edgelists: write failed")
        await asyncio.sleep(5)
