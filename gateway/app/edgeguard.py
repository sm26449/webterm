"""Protecţia handshake-ului de agent (`/agent/ws`): ce vede administratorul (3.6.38).

Limitele NU le aplică gateway-ul. Le aplică Traefik, pe un router dedicat `Path(`/agent/ws`)`
(docker-compose.prod.yml): un `rateLimit` per IP sursă şi unul global. O cerere peste prag primeşte
429 (per IP) sau 529 (global) la proxy şi nu ajunge niciodată aici: nici handshake, nici citire
SQLite. Tocmai de aceea gateway-ul nu le poate număra singur. Le citeşte din contoarele lui Traefik
(endpoint Prometheus pe o intrare internă, nepublicată), o dată la `SCRAPE_INTERVAL`.

Două surse, ţinute separat, fiindcă spun lucruri diferite:
  proxy    limită aplicată de Traefik. Rezultatul autentificării e NECUNOSCUT: cererea a fost oprită
           înainte ca cineva să-i verifice tokenul (poate fi un agent legitim într-o furtună de
           reconectări, poate fi un atac).
  gateway  refuz înregistrat aici: `bad_token`, `instance_conflict` (tokenul a fost verificat şi
           respins) sau `bad_path` (o formă codată a căii, `/agent%2Fws`, care ocolea potrivirea
           exactă din Traefik; refuzată înainte de orice citire).

Agregare, nu jurnal per cerere: numărătorile stau în memorie şi se scriu ca EPISOADE (un rând pe
episod, actualizat cel mult o dată pe interval şi pe regulă). Un episod începe la primul refuz
după o pauză de `QUIET` secunde şi se închide după `QUIET` secunde fără refuzuri. Cardinalitate
fixă: 2 surse × 4 reguli; nicio cheie după IP, token sau cale. Retenţie: `RETAIN_DAYS` zile şi cel
mult `MAX_ROWS` rânduri. Începutul şi sfârşitul unui episod intră şi în jurnalul de audit (actor
`system:edgeguard`), deci în aceleaşi export / retenţie ca restul.

Când telemetria de proxy lipseşte (Traefik oprit, URL greşit, stack fără Traefik), episoadele de
proxy nu mai pot fi văzute: starea o spune explicit („indisponibilă din …"), nu tace. Contorul lui
Traefik e cumulativ, deci la revenire diferenţa acoperă şi pauza; o repornire a lui Traefik
(contoarele de la zero) se recunoaşte după `process_start_time_seconds`."""
import asyncio
import json
import logging
import re
import time
import urllib.parse
import urllib.request
from typing import Optional

from . import agentgate, audit, config, db, security

log = logging.getLogger("webterm.edgeguard")

SCRAPE_INTERVAL = 30.0
QUIET = 300.0                 # fără refuzuri atâta timp → episodul se închide
RETAIN_DAYS = 30
MAX_ROWS = 200
FETCH_TIMEOUT = 5.0
MAX_BODY = 4 * 1024 * 1024    # endpointul de metrici e intern, dar nu citim nelimitat

# codul HTTP pe care îl întoarce Traefik → regula care a refuzat (vezi etichetele din compose:
# middleware-ul `errors` rescrie 429-ul limitei GLOBALE în 529, ca metricile să le poată separa)
# „418" e o etichetă internă: TOT ce trece prin routerul de deny (edgelists.py), oricare ar fi codul HTTP
PROXY_CODES = {"429": "ip", "529": "global", "418": "deny"}
GATEWAY_RULES = ("bad_token", "instance_conflict", "bad_path", "blocked", "mtls_missing", "mtls_revoked")
# 3.6.38 (partea 2): acelaşi mecanism pentru restul refuzurilor pe care altfel nu le vedea nimeni
WEB_RULES = ("login_failed", "login_locked", "api_token_bad", "ws_refused")
RULES = ({("proxy", "ip"), ("proxy", "global"), ("proxy", "deny")} | {("gateway", r) for r in GATEWAY_RULES}
         | {("web", r) for r in WEB_RULES})
TOP_SOURCES = 10           # adrese păstrate pe episod (restul se adună în „other")
MAX_PENDING_SOURCES = 200  # adrese distincte numărate pe interval şi regulă, apoi „other"

K_COUNTERS = "edgeguard_counters"     # ultima valoare văzută a contoarelor (supravieţuieşte repornirii)

_pending: dict = {}                   # (source, rule) → refuzuri încă nescrise
_open: dict = {}                      # (source, rule) → {"id", "started", "last_seen", "count"}
_status = {"configured": False, "last_ok": 0.0, "error": "", "error_since": 0.0}
_loaded = False


_pending_src: dict = {}               # (source, rule) → {adresă sau „cale": număr}


def _note(key, src: str = "") -> None:
    _pending[key] = _pending.get(key, 0) + 1
    if src:
        d = _pending_src.setdefault(key, {})
        if src in d or len(d) < MAX_PENDING_SOURCES:
            d[src] = d.get(src, 0) + 1
        else:
            d["other"] = d.get("other", 0) + 1


def _src(ip: str, path: str = "") -> str:
    """Sursa unui refuz: adresa (IPv6 pe /64, ca la blocare) şi, pentru WebSocket-uri, primele două
    segmente ale căii. NICIODATĂ tokenul: în /ws/shared/<token> el e al treilea segment."""
    key = agentgate.ip_key(ip)
    if path:
        segs = [p for p in path.split("?", 1)[0].split("/") if p][:2]
        key += " /" + "/".join(x[:24] for x in segs)
    return key[:80]


def note_gateway_refusal(rule: str, ip: str = "") -> None:
    """Un handshake respins de gateway (token necunoscut, instanţă greşită). Doar un contor în
    memorie: niciun IO pe calea refuzului, ca un flux de tokenuri greşite să nu scrie în SQLite."""
    if rule in GATEWAY_RULES:
        _note(("gateway", rule), _src(ip) if ip else "")


def note_web_refusal(rule: str, ip: str, path: str = "") -> None:
    """Login eşuat / blocat, token API invalid, WebSocket refuzat înainte de accept. La fel: doar
    în memorie, cu adresa sursă (şi calea, plafonată) pentru episodul din System health."""
    if rule in WEB_RULES:
        _note(("web", rule), _src(ip, path))


_LINE = re.compile(r'^traefik_router_requests_total\{([^}]*)\}\s+([0-9.eE+-]+)\s*$')
_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def parse_metrics(text: str, router: str) -> dict:
    """Din expunerea Prometheus a lui Traefik: {"429": n, "529": n, "_start": t} pentru `router`.
    Însumează peste metodă / protocol (aceeaşi regulă poate refuza un GET şi un upgrade WS)."""
    out = {code: 0.0 for code in PROXY_CODES}
    seen = False
    for line in text.splitlines():
        if line.startswith("process_start_time_seconds "):
            try:
                out["_start"] = float(line.split()[1])
            except (IndexError, ValueError):
                pass
            continue
        m = _LINE.match(line)
        if not m:
            continue
        labels = dict(_LABEL.findall(m.group(1)))
        if labels.get("router") not in ((router,) if isinstance(router, str) else router):
            continue
        seen = True
        code = labels.get("code", "")
        if labels["router"].endswith("-deny@file"):
            code = "418"        # tot ce trece prin routerul de deny e un refuz din listă, oricare ar fi codul
        if code in out:
            try:
                out[code] += float(m.group(2))
            except ValueError:
                pass
    out["_router_seen"] = seen
    return out


def deltas(prev: dict, cur: dict) -> dict:
    """Câte refuzuri noi de la citirea anterioară, per cod. Contorul lui Traefik e cumulativ; dacă
    procesul a repornit (alt `_start`, sau o valoare care a scăzut) numărătoarea a luat-o de la zero,
    deci valoarea curentă ÎNTREAGĂ e noutatea. Fără citire anterioară: linia de bază, delta 0 (nu
    ştim ce parte din total a fost deja numărată înainte de pornirea gateway-ului)."""
    if not prev:
        return {code: 0 for code in PROXY_CODES}
    restarted = cur.get("_start") and prev.get("_start") and cur["_start"] != prev["_start"]
    out = {}
    for code in PROXY_CODES:
        c, p = cur.get(code, 0.0), prev.get(code, 0.0)
        out[code] = int(c) if (restarted or c < p) else int(c - p)
    return out


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"Accept": "text/plain"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:  # noqa: S310 — URL din config, intern
        body = r.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError("metrics response larger than %d bytes" % MAX_BODY)
    return body.decode("utf-8", "replace")


async def _load() -> None:
    """La prima rulare: episoadele rămase deschise (gateway repornit în mijlocul unuia) revin în
    memorie, ca să fie continuate sau închise corect, nu dublate."""
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        for r in await db.fetchall("SELECT id, source, rule, started, last_seen, count, sources FROM edge_episodes"
                                   " WHERE ended IS NULL"):
            if (r["source"], r["rule"]) in RULES:
                _open[(r["source"], r["rule"])] = {"id": r["id"], "started": r["started"],
                                                   "last_seen": r["last_seen"], "count": r["count"],
                                                   "sources": _loads(r["sources"])}
    except Exception:                      # noqa: BLE001
        log.exception("edgeguard: could not reload open episodes")


async def _audit(text: str) -> None:
    try:
        await audit.record(time.time(), "system:edgeguard", "-", "EDGE", "/agent/ws", 200, text[:480])
    except Exception:                      # noqa: BLE001 — telemetria nu trebuie să cadă din cauza auditului
        log.exception("edgeguard: audit write failed")


def _label(key) -> str:
    return "%s/%s" % key


def _merge(top: dict, add: dict) -> dict:
    out = dict(top)
    for k, v in (add or {}).items():
        out[k] = out.get(k, 0) + v
    other = out.pop("other", 0)
    keep = dict(sorted(out.items(), key=lambda kv: -kv[1])[:TOP_SOURCES])
    other += sum(v for k, v in out.items() if k not in keep)
    if other:
        keep["other"] = other
    return keep


async def apply(counts: dict, now: float, sources: Optional[dict] = None) -> None:
    """Aplică numărătorile unui interval: deschide / actualizează / închide episoade. Cel mult un
    UPDATE sau INSERT pe regulă şi interval, oricât de mare ar fi numărul de refuzuri."""
    sources = sources or {}
    for key, n in counts.items():
        if n <= 0 or key not in RULES:
            continue
        ep = _open.get(key)
        if ep and now - ep["last_seen"] <= QUIET:
            ep["count"] += n
            ep["last_seen"] = now
            ep["sources"] = _merge(ep.get("sources") or {}, sources.get(key))
            await db.execute("UPDATE edge_episodes SET count=?, last_seen=?, sources=? WHERE id=?",
                             ep["count"], now, json.dumps(ep["sources"]), ep["id"])
            continue
        if ep:                                     # vechi şi uitat deschis: îl închidem întâi
            await _close(key, ep)
        src = _merge({}, sources.get(key))
        row = await db.execute_returning(
            "INSERT INTO edge_episodes(source, rule, started, last_seen, count, sources) VALUES(?,?,?,?,?,?)"
            " RETURNING id", key[0], key[1], now, now, n, json.dumps(src))
        _open[key] = {"id": row["id"] if row else None, "started": now, "last_seen": now, "count": n,
                      "sources": src}
        await _audit("agent handshake protection: episode started — %s, %d refused so far" % (_label(key), n))
    for key, ep in list(_open.items()):
        if now - ep["last_seen"] > QUIET:
            await _close(key, ep)


async def _close(key, ep) -> None:
    _open.pop(key, None)
    if ep.get("id") is not None:
        await db.execute("UPDATE edge_episodes SET ended=? WHERE id=?", ep["last_seen"], ep["id"])
    await _audit("agent handshake protection: episode ended — %s, %d refused in %d s"
                 % (_label(key), ep["count"], int(ep["last_seen"] - ep["started"])))


async def prune(now: Optional[float] = None) -> None:
    now = now or time.time()
    await db.execute("DELETE FROM edge_episodes WHERE ended IS NOT NULL AND ended < ?",
                     now - RETAIN_DAYS * 86400)
    await db.execute("DELETE FROM edge_episodes WHERE ended IS NOT NULL AND id NOT IN"
                     " (SELECT id FROM edge_episodes ORDER BY last_seen DESC LIMIT ?)", MAX_ROWS)


async def tick(now: Optional[float] = None, fetch=None) -> None:
    """O rulare: citeşte contoarele lui Traefik (dacă e configurat), adună refuzurile gateway-ului
    şi aplică totul pe episoade. `fetch` se poate înlocui în teste."""
    now = now or time.time()
    await _load()
    counts = {}
    url = config.AGENT_RL_METRICS_URL
    if url.strip().lower() in ("off", "0", "none"):
        url = ""
    _status["configured"] = bool(url)
    if url:
        try:
            text = await asyncio.to_thread(fetch or _fetch, url)
            cur = parse_metrics(text, config.AGENT_RL_ROUTERS)
            if not cur.pop("_router_seen"):
                # Traefik răspunde, dar routerul nu apare: fie n-a primit încă nicio cerere (Traefik
                # nu emite serii goale), fie etichetele din compose lipsesc. Nu e o eroare de
                # telemetrie; contoarele sunt 0 până la prima cerere.
                pass
            prev = json.loads(await db.get_setting(K_COUNTERS, "{}") or "{}")
            for code, n in deltas(prev, cur).items():
                counts[("proxy", PROXY_CODES[code])] = n
            if cur != {k: prev.get(k) for k in cur}:
                await db.set_setting(K_COUNTERS, json.dumps(cur))
            _status.update(last_ok=now, error="", error_since=0.0)
        except Exception as e:             # noqa: BLE001 — orice eşec = telemetrie indisponibilă, nu crash
            if not _status["error_since"]:
                _status["error_since"] = now
                # doar host:port — URL-ul poate purta credenţiale (review 3.6.38)
                log.warning("edgeguard: proxy telemetry unavailable (%s): %s",
                            urllib.parse.urlsplit(url).hostname or "?", type(e).__name__)
            _status["error"] = type(e).__name__
    taken, srcs = {}, {}
    for key in list(_pending):
        taken[key] = _pending.pop(key)
        counts[key] = counts.get(key, 0) + taken[key]
    for key in list(_pending_src):
        srcs[key] = _pending_src.pop(key)
    try:
        await apply(counts, now, srcs)
    except Exception:
        # refuzurile gateway-ului nu se pierd: revin în coadă pentru intervalul următor
        # (cele de proxy se recuperează singure: contorul lui Traefik e cumulativ)
        for key, n in taken.items():
            _pending[key] = _pending.get(key, 0) + n
        for key, d in srcs.items():
            for k, v in d.items():
                _pending_src.setdefault(key, {})[k] = _pending_src.get(key, {}).get(k, 0) + v
        raise


def status(now: Optional[float] = None) -> dict:
    now = now or time.time()
    s = dict(_status)
    s["available"] = bool(s["configured"] and s["last_ok"] and not s["error_since"])
    return s


def _loads(raw) -> dict:
    try:
        d = json.loads(raw or "{}")
        return {str(k)[:80]: int(v) for k, v in d.items()} if isinstance(d, dict) else {}
    except (ValueError, TypeError):
        return {}


async def episodes(limit: int = 50) -> list:
    rows = await db.fetchall("SELECT id, source, rule, started, last_seen, ended, count, sources FROM edge_episodes"
                             " ORDER BY last_seen DESC LIMIT ?", limit)
    return [{"id": r["id"], "source": r["source"], "rule": r["rule"], "started": r["started"],
             "last_seen": r["last_seen"], "ended": r["ended"], "active": r["ended"] is None,
             "duration": int((r["ended"] or r["last_seen"]) - r["started"]), "count": r["count"],
             "sources": sorted(_loads(r["sources"]).items(), key=lambda kv: (kv[0] == "other", -kv[1])),
             "auth": "unknown" if r["source"] == "proxy" else "refused"} for r in rows]


async def loop() -> None:
    await asyncio.sleep(SCRAPE_INTERVAL)
    n = 0
    while True:
        try:
            await tick()
            n += 1
            if n % 120 == 1:                       # o dată pe oră
                await prune()
        except Exception:                          # noqa: BLE001 — bucla trebuie să supravieţuiască
            log.exception("edgeguard: tick failed")
        await asyncio.sleep(SCRAPE_INTERVAL)


def open_episodes() -> dict:
    """Copie a episoadelor în curs (pentru System health: fără DB, fără reţea)."""
    return {k: dict(v) for k, v in _open.items()}


# Tokenurile API respinse vin din security (strat inferior) printr-un cârlig, nu printr-un import invers.
security.on_bad_api_token = lambda ip: note_web_refusal("api_token_bad", ip)
