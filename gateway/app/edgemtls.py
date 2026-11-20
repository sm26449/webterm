"""Configuraţia Traefik pentru agenţii cu mTLS (3.7.0). Design: docs/design/AGENT-MTLS.md.

Gateway-ul scrie în volumul comun `edge-lists` (citit read-only de Traefik ca director al providerului
`file`, ca listele allow/deny din edgelists.py):

  agent-ca.pem       certificatul PUBLIC al CA-ului agenţilor (agentca.py); cheia nu iese din gateway
  agent-mtls.yaml    opţiunile TLS `webterm-agents` (cere certificat de client semnat de acel CA) şi
                     routerul `webterm-agent-mtls` pe `Host(<numele de agenţi>) && Path(/agent/ws)`

Routerul pune două antete spre gateway:
  X-Forwarded-Tls-Client-Cert   certificatul văzut în handshake (middleware-ul `passTLSClientCert`)
  X-Webterm-Mtls-Router         un SECRET al instalării, generat o dată şi păstrat în DB

Gateway-ul ia în seamă certificatul DOAR când al doilea antet poartă secretul. Fără secret, oricine
ar putea trimite primul antet pe ruta obişnuită (sau prin „domain fronting": SNI = numele de agenţi,
Host = numele principal), iar certificatul unui agent e o informaţie publică. Secretul stă doar în
fişierul citit de Traefik şi în DB; Traefik îl suprascrie dacă un client trimite antetul cu acelaşi nume.

Fail-safe: fără CA încărcat, fără un nume de agenţi valid sau în spatele unui proxy care termină TLS
(CDN), nu scriem routerul: agenţii rămân pe ruta cu token, cum erau."""
import hmac
import json
import logging
import secrets
import urllib.parse

import asyncio
import time

from . import agentca, config, core, db, edgelists, fwddomain

log = logging.getLogger("webterm.edgemtls")

FILE_NAME = "agent-mtls.yaml"
CA_FILE = "agent-ca.pem"
SECRET_HEADER = "x-webterm-mtls-router"
CERT_HEADER = "x-forwarded-tls-client-cert"
K_SECRET = "agent_mtls_router_secret"

_secret = ""
_last_written = ""
status = {"enabled": False, "reason": "starting", "host": "", "last_write": 0.0, "error": ""}


def agent_host() -> str:
    """Numele pe care se conectează agenţii cu mTLS. Implicit `agents.<domeniul principal>`."""
    h = (config.AGENT_HOST or "").strip().lower()
    if not h:
        main = (urllib.parse.urlsplit(config.PUBLIC_URL).hostname or "").lower()
        h = "agents." + main if main else ""
    main = (urllib.parse.urlsplit(config.PUBLIC_URL).hostname or "").lower()
    # agentul acceptă doar un subdomeniu al numelui pe care s-a înrolat (ptyd._mtls_install)
    return h if h and fwddomain.valid_domain(h) and main and h.endswith("." + main) else ""


def agent_url() -> str:
    h = agent_host()
    return "wss://%s/agent/ws" % h if h else ""


def enabled() -> bool:
    return bool(status["enabled"])


# Motivele pentru care ruta mTLS e oprită INTENŢIONAT sau nu poate exista în configuraţia asta. Doar ele
# ridică clichetul (INV-12: oprirea mTLS e rollback-ul şi nu blochează niciun host). Orice ALTCEVA (CA care
# nu se încarcă, fişier care nu se poate scrie, pornire în curs) e o defecţiune: clichetul rămâne (eşec
# închis), iar System health dă alarmă critică.
LIFTS_RATCHET = ("off", "proxy", "host", "no-dir")


def enforce_ratchet() -> bool:
    return status.get("reason") not in LIFTS_RATCHET


async def load_secret() -> str:
    global _secret
    if not _secret:
        _secret = await db.get_setting(K_SECRET, "") or ""
        if not _secret:
            _secret = secrets.token_urlsafe(32)
            await db.set_setting(K_SECRET, _secret)
    return _secret


def router_secret_ok(headers) -> bool:
    """Cererea a trecut prin routerul mTLS (antetul cu secretul instalării)?"""
    got = headers.get(SECRET_HEADER, "") if headers is not None else ""
    return bool(_secret) and bool(got) and hmac.compare_digest(got.encode(), _secret.encode())


def intent_off_reason() -> str:
    """Motivul pentru care mTLS e oprit INTENŢIONAT sau nu poate exista aici — calculat FĂRĂ CA şi fără
    DB (review 3.7.0: altfel un CA care nu se încarcă bloca rollback-ul `WEBTERM_AGENT_MTLS=off`)."""
    if (config.AGENT_MTLS or "on").strip().lower() in ("off", "0", "no", "false"):
        return "off"
    if not edgelists.lists_supported():
        return "proxy"
    if not agent_host():
        return "host"
    if not edgelists._dir():
        return "no-dir"
    return ""


def render() -> dict:
    host = agent_host()
    reason = (intent_off_reason() or ("ca" if agentca._ca_cert is None else "secret" if not _secret else ""))
    status.update(enabled=not reason, reason=reason, host=host)
    if reason:
        return {}
    tls = {}
    if config.CERT_RESOLVER:
        tls["certResolver"] = config.CERT_RESOLVER
    tls["options"] = "webterm-agents@file"
    return {
        "tls": {"options": {"webterm-agents": {
            "minVersion": "VersionTLS12",
            "clientAuth": {"caFiles": ["/edge/" + CA_FILE], "clientAuthType": "RequireAndVerifyClientCert"},
        }}},
        "http": {
            "routers": {"webterm-agent-mtls": {
                "rule": "Host(`%s`) && Path(`/agent/ws`)" % host,
                "entryPoints": ["websecure"], "priority": 4000, "service": "webterm@docker", "tls": tls,
                "middlewares": ["webterm-agent-mtls-rl@file", "webterm-agent-mtls-cert@file",
                                "webterm-agent-mtls-secret@file"],
            }},
            "middlewares": {
                # cine ajunge aici are deja un certificat semnat de CA-ul nostru; limita largă e doar
                # pentru un certificat revocat folosit în buclă (gateway-ul îl refuză după o citire)
                "webterm-agent-mtls-rl": {"rateLimit": {"average": config.AGENT_ALLOW_AVERAGE,
                                                        "burst": config.AGENT_ALLOW_BURST, "period": "1m",
                                                        "sourceCriterion": {"ipStrategy": {"ipv6Subnet": 64}}}},
                "webterm-agent-mtls-cert": {"passTLSClientCert": {"pem": True}},
                "webterm-agent-mtls-secret": {"headers": {"customRequestHeaders": {"X-Webterm-Mtls-Router": _secret}}},
            },
        },
    }


def write(force: bool = False) -> bool:
    """Scrie CA-ul public şi configuraţia (atomic). Un document gol când mTLS e oprit."""
    global _last_written
    if not edgelists._dir():
        status.update(enabled=False, reason="no-dir")
        return False
    doc = render()
    text = json.dumps(doc, sort_keys=True, indent=1)
    if text == _last_written and not force:
        return False
    try:
        if doc:
            edgelists.atomic_write(CA_FILE, agentca.ca_pem())     # întâi CA-ul: opţiunile îl citesc
        edgelists.atomic_write(FILE_NAME, text)
    except OSError as e:
        # Oprit intenţionat (doc gol): motivul rămâne cel intenţionat, ca rollback-ul să ridice clichetul
        # chiar dacă fişierul vechi nu poate fi înlocuit (audit 3.7.0). Doar o rută care TREBUIA scrisă
        # devine `write-error` (clichetul rămâne, alarmă critică).
        if doc:
            status.update(error=type(e).__name__, reason="write-error", enabled=False)
        else:
            status["error"] = type(e).__name__
        return False
    _last_written = text
    status["error"] = ""
    return True


def reset_for_tests() -> None:
    global _secret, _last_written
    _secret, _last_written = "", ""
    status.update(enabled=False, reason="starting", host="", last_write=0.0, error="")


MTLS_MIN_AGENT = 60                 # primul AGENT_VERSION care ştie `mtls_provision` şi certificatul de client
RENEW_FRACTION = 1 / 3              # reînnoim când a rămas o treime din valabilitate
RETRY_UNUSED = 3600.0               # o reînnoire trimisă dar neraportată se retrimite după atât
RETRY_REISSUE = 86400.0             # un certificat emis pe care agentul nu-l raportează: re-emis cel mult zilnic


async def provision_hook(conn) -> None:
    """După hello: un agent ≥ 60 primeşte certificatul de client când NU îl are (prima dată, sau o
    trimitere pierdută) şi la reînnoire. Decizia se ia după serialul pe care agentul îl RAPORTEAZĂ în
    hello, nu după timp (review 3.7.0):
      - nimic emis → emitem;
      - emis, dar agentul nu-l are (altul / niciunul) → retrimitem, cel mult o dată pe RETRY_UNUSED;
        un agent care îl ARE dar nu ajunge la numele de agenţi nu primeşte altul;
      - o treime din valabilitate rămasă → certificat nou ca `mtls_serial_next`; dacă agentul nu-l
        raportează după RETRY_UNUSED (mesaj pierdut, instalare eşuată), îl retrimitem — altfel un host
        pe clichet ar rămâne fără acces la expirarea celui vechi.
    Cheia călătoreşte pe canalul deja autentificat şi criptat; gateway-ul NU o păstrează."""
    if not enabled() or (conn.agent_version or 0) < MTLS_MIN_AGENT:
        return
    # un singur emitent per host (hello şi sweep-ul pot coincide), şi doar pentru conexiunea CURENTĂ
    lock = _host_locks.setdefault(conn.host_id, asyncio.Lock())
    async with lock:
        cur_src = core.sources.get(conn.host_id)
        if cur_src is not None and cur_src is not conn:
            return
        await _provision_locked(conn)


_host_locks: dict = {}


async def _provision_locked(conn) -> None:
    row = await db.fetchone("SELECT mtls_serial, mtls_serial_next, mtls_not_after, mtls_last, mtls_next_at"
                            " FROM hosts WHERE id=?", conn.host_id)
    if row is None:
        return
    now = time.time()
    life = agentca.CERT_DAYS * 86400
    reported = getattr(conn, "mtls_reported", None)
    cur, nxt = row["mtls_serial"], row["mtls_serial_next"]
    issued_at = (row["mtls_not_after"] or 0) - life
    kind = ""
    if not cur:
        kind = "issue"
    elif nxt:
        if reported != nxt and now - (row["mtls_next_at"] or 0) > RETRY_UNUSED:
            kind = "renew"                         # reînnoirea n-a ajuns: o retrimitem
    elif (row["mtls_not_after"] or 0) - now < life * RENEW_FRACTION:
        kind = "renew"
    elif reported != cur and not conn.via_mtls and now - issued_at > RETRY_REISSUE:
        kind = "issue"                             # emis, dar agentul nu-l are
    if not kind:
        return
    c = agentca.issue(conn.host_id)
    if kind == "issue":
        # (încă) nefolosit: îl înlocuim; un singur serial valabil
        await db.execute("UPDATE hosts SET mtls_serial=?, mtls_serial_next=NULL, mtls_next_at=NULL, mtls_not_after=?"
                         " WHERE id=?", c["serial"], c["not_after"], conn.host_id)
    else:
        # reînnoire: vechiul rămâne valabil până când agentul se conectează cu cel nou (api.agent_ws)
        await db.execute("UPDATE hosts SET mtls_serial_next=?, mtls_next_at=? WHERE id=?", c["serial"], now, conn.host_id)
    await conn.send_ctrl({"op": "mtls_provision", "cert": c["cert"], "key": c["key"], "url": agent_url(),
                          "serial": c["serial"], "not_after": c["not_after"]})
    await core.record_agent_event(conn.host_id, "mtls_provisioned", reason=kind,
                                  detail="serial %s… until %s" % (c["serial"][:8],
                                                                  time.strftime("%Y-%m-%d", time.gmtime(c["not_after"]))))


async def _refresh(force: bool = False) -> None:
    """O trecere: întâi intenţia (oprit / CDN / fără nume) — fără CA, ca rollback-ul să meargă oricând;
    apoi secretul (independent de CA) şi CA-ul, apoi fişierul pentru Traefik."""
    reason = intent_off_reason()
    if reason:
        status.update(enabled=False, reason=reason, error="")
        if reason != "no-dir":
            try:
                write(force=force)               # un document gol: Traefik scoate routerul mTLS
            except Exception:                    # noqa: BLE001
                log.exception("edgemtls: could not clear the mTLS configuration")
        return
    try:
        await load_secret()
    except Exception as e:                       # noqa: BLE001
        status.update(enabled=False, reason="ca-error", error=type(e).__name__)
        log.exception("edgemtls: the router secret could not be loaded")
        return
    try:
        await agentca.ensure_ca()
    except Exception as e:                       # noqa: BLE001 — gateway-ul merge oricum; starea o spune
        status.update(enabled=False, reason="ca-error", error=type(e).__name__)
        log.exception("edgemtls: the agent CA could not be loaded")
        return
    write(force=force)


async def startup() -> None:
    """Înainte ca gateway-ul să accepte conexiuni (main.py, înainte de yield)."""
    await _refresh(force=True)


RENEW_SWEEP = 600.0     # verificarea de reînnoire pentru agenţii care stau conectaţi luni întregi


async def renew_sweep() -> None:
    for src in list(core.sources.values()):
        if getattr(src, "via_mtls", False) and (getattr(src, "agent_version", 0) or 0) >= MTLS_MIN_AGENT:
            try:
                await provision_hook(src)
            except Exception:                    # noqa: BLE001 — un agent nu opreşte bucla
                log.exception("edgemtls: renewal check failed for host %s", getattr(src, "host_id", "?"))


async def loop() -> None:
    """Recitim configuraţia la 30 s (numele de agenţi sau domeniul de forward se pot schimba), iar la
    RENEW_SWEEP trecem prin agenţii CONECTAŢI pe mTLS: unul care stă pe aceeaşi conexiune din momentul
    reînnoirii până la expirare n-ar mai trimite niciun hello, deci n-ar primi certificatul nou, iar la
    următoarea reconectare un host pe clichet ar rămâne fără acces (review 3.7.0)."""
    last_sweep = time.time()
    while True:
        await asyncio.sleep(30)
        await _refresh()
        if enabled() and time.time() - last_sweep >= RENEW_SWEEP:
            last_sweep = time.time()
            await renew_sweep()


core.post_hello_hooks.append(provision_hook)
