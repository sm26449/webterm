"""Port forwards: the HTTP proxy through the agent tunnel, the reachability probe, the forward
domain settings, forward CRUD (+ telnet forwards), the per-host list and the dashboard apps,
subdomain routing with its auth handshake (`/__wtfwd/auth`, the forward cookie and step-up
ticket) and the WebSocket proxy. Moved out of api.py; `main.py` mounts `router` and calls
`route_forward` / `handle_forward_ws` from its middleware. Nothing here imports api.py.
"""
import asyncio
import base64
import logging
import os
import re
import socket
import sqlite3
import ssl
import struct
import time
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from pydantic import BaseModel

from .errors import ApiError
from . import authz, config, core, db, edgemtls, errors, fwddomain, hostmodel, security, stepup

log = logging.getLogger("webterm")
# Aceeaşi gardă ca api.router (fail-closed): o rută fără permisiune declarată → 500 authz.undeclared.
router = APIRouter(dependencies=[Depends(authz.declared)])


# ── [forward] Port forwarding ──────────────────────────────────────────────────────────
# antete hop-by-hop: nu se propagă printr-un proxy (RFC 7230 §6.1). Antetul se numeşte
# `Trailer` (RFC 7230 §4.4); „trailers" e doar o VALOARE posibilă a lui `TE` — cu forma greşită
# în set, un `Trailer:` din browser ajungea la ţintă (audit 2026-10-04; `_WS_SKIP` îl avea bine).
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"}
FWD_MAX_BODY = 100 * 1024 * 1024      # plafon corp cerere prin proxy-ul de forward (anti-OOM)
FWD_RESP_TIMEOUT = 120                # așteptare răspuns de la țintă: generos pt. long-poll
                                      # (ex. MikroTik /jsproxy ține conexiunea până la un
                                      # eveniment). Dead target → eșuează după atâta.
# Plafon AGREGAT peste toate upload-urile forward simultane: plafonul per-request (100 MB) nu
# opreşte N cereri concurente să reţină N×100 MB în RAM → OOM. Contor global + refuz 503 peste prag.
FWD_INFLIGHT_MAX = 256 * 1024 * 1024  # 256 MB reţinuţi simultan în toate corpurile forward
_fwd_inflight = 0
# WS_REVALIDATE_SECS (re-verificarea sesiunii pe WS-urile lungi) stă în security.py: îl citesc şi
# WS-urile de terminal/share din api.py.
# cookie de auth pe subdomeniul de forward: __Host- → host-only (nu se scurge la
# alte subdomenii sau la domeniul principal), HttpOnly, Secure, Path=/
FWD_COOKIE = "__Host-wt_fwd" if config.PUBLIC_URL.startswith("https://") else "wt_fwd"


def _strip_fwd_cookie(cookie_header: str) -> str:
    parts = [c.strip() for c in cookie_header.split(";")]
    kept = [c for c in parts if c and not c.startswith(FWD_COOKIE + "=")]
    return "; ".join(kept)


async def _ensure_forward_source(host_id: int):
    """Sursa capabilă de forward pentru host: conexiunea agent/SSH deja vie sau,
    pentru hosturi SSH cu credențial STOCAT și fără 2FA, una ridicată la nevoie
    (idle-teardown după inactivitate). None dacă nu putem — host offline, ori SSH
    cu 2FA / credențiale ne-stocate (acolo forward-ul cere o sesiune deschisă)."""
    conn = core.source_for(host_id)
    if isinstance(conn, (core.AgentConnection, core.SshSource)):
        return conn
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row or row["connection_type"] != "ssh":
        return None
    if row["require_2fa"] or row["credential_policy"] != "stored" or not row["credential_encrypted"]:
        return None
    try:
        cred = hostmodel.decode_credential(row["credential_encrypted"])
        return await core.dial_ssh(row, cred)
    except Exception:
        return None


async def _open_target(conn, thost: str, tport: int, scheme: str):
    """Deschide tunelul TCP către țintă și, pentru scheme=https, ridică TLS pe
    ultimul hop (gateway → țintă). Întoarce un obiect cu aceeași interfață
    write/read/close ca ForwardStream."""
    fs = await conn.open_forward(thost, tport)
    if scheme == "https":
        try:
            fs = await core.wrap_tls_forward(fs, thost)
        except core.ForwardError:
            await fs.close()
            raise
        except Exception:
            await fs.close()
            raise core.ForwardError("TLS failed")
    return fs


def _host_header_port(host_header: str, scheme: str):
    """Portul din antetul Host (ce vede browserul), altfel cel implicit al schemei — ca să
    comparăm ORIGINEA ÎNTREAGĂ (schemă, gazdă, port), nu doar gazda (raport 2026-11, punct 8)."""
    _h, sep, port = (host_header or "").rpartition(":")
    if sep and port.isdigit() and "]" not in port:
        return int(port)
    return security.DEFAULT_PORTS.get(scheme)


# INV-11 (docs/design/INVARIANTS.md): orice cerere de forward e autentificată; Origin comparat complet, cu port.
def _fwd_origin_for_target(origin: str, fwd_host: str, scheme: str, thost: str, tport: int):
    """Antetul `Origin` trimis ţintei unui forward. Aplicaţiile cu protecţie CSRF proprie
    (Grafana: `POST /api/ds/query`, Grafana Live; la fel Gitea, Home Assistant…) compară
    Origin-ul cu Host-ul primit — iar noi le trimitem `Host: <ţintă>:<port>`, deci Origin-ul
    browserului (`https://slug.<domeniu>`) nu se potrivea niciodată: 403 „origin not allowed",
    grafice goale, WebSocket mort. Verificarea o facem AICI (Origin-ul trebuie să fie chiar
    subdomeniul forward-ului, pe schema PUBLIC_URL — altfel un forward-soră de pe acelaşi
    site, care primeşte cookie-ul nostru SameSite=Lax, ar putea trimite POST-uri), apoi
    rescriem Origin-ul la originea ţintei, ca app-ul să vadă o cerere same-origin.
    Întoarce: None = fără Origin (absent / "null"), str = valoarea de trimis; ridică 403
    dacă Origin-ul e străin."""
    if not origin or origin == "null":
        return None
    o = security.origin_tuple(origin)
    pub = security.origin_tuple(config.PUBLIC_URL)
    if (o is None or pub is None or o[0] != pub[0] or o[1] != fwd_host.split(":")[0].lower()
            or o[2] != _host_header_port(fwd_host, pub[0])):
        raise ApiError(403, "forward.badOrigin", "cross-origin request refused by the forward")
    return "%s://%s:%d" % ("https" if scheme == "https" else "http", thost, tport)


async def proxy_forward_http(request: Request, host_id: int, thost: str,
                             tport: int, target_path: str, scheme: str = "http"):
    """Reverse-proxy HTTP printr-un tunel de agent. Cererea browserului →
    HTTP/1.0 `Connection: close` către țintă (fără chunked/keep-alive de parsat) →
    răspunsul citit până la EOF, headerele parsate, corpul transmis în streaming."""
    from fastapi.responses import StreamingResponse
    # anti request-smuggling: path-ul ajunge într-o cerere HTTP raw
    if "\r" in target_path or "\n" in target_path:
        raise ApiError(400, "forward.badPath", "invalid path")
    fwd_origin = _fwd_origin_for_target(request.headers.get("origin", ""),
                                        request.headers.get("host", ""), scheme, thost, tport)
    conn = await _ensure_forward_source(host_id)
    if conn is None:
        raise ApiError(409, "forward.hostOffline", "the host is offline (or an SSH host that needs an open session)")
    try:
        fs = await _open_target(conn, thost, tport, scheme)
    except core.ForwardError:
        raise ApiError(502, "forward.proxyError", "the forwarded service is not responding")
    except (core.AgentGone, TimeoutError):
        raise ApiError(409, "host.offline", "the host is offline")
    try:
        # citim corpul cu plafon (anti-OOM): un upload uriaș printr-un forward nu
        # trebuie să umple RAM-ul gateway-ului. Acoperă și cererile chunked (fără
        # Content-Length), nu doar antetul declarat.
        global _fwd_inflight
        body = b""
        try:
            async for chunk in request.stream():
                body += chunk
                _fwd_inflight += len(chunk)
                if len(body) > FWD_MAX_BODY:
                    await fs.close()
                    raise ApiError(413, "forward.bodyTooLarge", "body too large for a forward")
                if _fwd_inflight > FWD_INFLIGHT_MAX:
                    await fs.close()
                    raise ApiError(503, "forward.busy", "too many large uploads through forwards at once; retry")
            lines = ["%s %s HTTP/1.0" % (request.method, target_path)]
            for k, v in request.headers.items():
                kl = k.lower()
                if kl in _HOP_BY_HOP or kl in ("host", "content-length", "origin"):
                    continue
                if "\r" in v or "\n" in v:         # anti-injecție de headere
                    continue
                if kl == "cookie":
                    # trimitem cookie-urile PROPRII ale app-ului, dar scoatem cookie-ul
                    # nostru de auth (nu are ce căuta la țintă)
                    v = _strip_fwd_cookie(v)
                    if not v:
                        continue
                lines.append("%s: %s" % (k, v))
            lines.append("Host: %s:%d" % (thost, tport))
            if fwd_origin:
                lines.append("Origin: %s" % fwd_origin)
            if body:
                lines.append("Content-Length: %d" % len(body))
            lines.append("Connection: close")
            await fs.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin1") + body)
        finally:
            _fwd_inflight -= len(body)   # eliberează bugetul agregat (corpul e trimis / cererea a eşuat)

        # citește antetul răspunsului (până la linia goală)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(fs.read(), timeout=FWD_RESP_TIMEOUT)
            if chunk is None:
                break
            buf += chunk
            if len(buf) > 256 * 1024:          # antet absurd de mare → renunțăm
                await fs.close()
                raise ApiError(502, "forward.badResponse", "invalid response from the service")
        head, _, rest = buf.partition(b"\r\n\r\n")
        hlines = head.split(b"\r\n")
        parts = hlines[0].split(b" ", 2) if hlines and hlines[0] else []
        # Statusul ţintei se prelua VERBATIM: un echipament cu firmware prost care răspunde
        # `HTTP/1.0 99 Nonsense` făcea uvicorn să crape cu `KeyError: 99`, iar clientul primea
        # un răspuns gol şi un traceback în log. Plafonăm la intervalul valid.
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 502
        if not 100 <= status <= 599:
            status = 502
        resp_headers = {}
        set_cookies = []
        for line in hlines[1:]:
            k, sep, v = line.partition(b":")
            if not sep:
                continue
            name = k.decode("latin1").strip()
            nl = name.lower()
            if nl in _HOP_BY_HOP or nl == "content-length":
                continue                       # transmitem până la EOF, fără content-length
            val = v.decode("latin1").strip()
            # Antetele ţintei se copiau nevalidate: o ţintă care trimite `X-A: v\nSet-Cookie: …`
            # (LF gol, nu CRLF) producea o „valoare" cu `\n` în ea → `RuntimeError: Invalid HTTP
            # header value` din uvicorn şi răspuns gol. Că nu s-a ajuns la response-splitting e
            # meritul validării din uvicorn, nu al nostru — apărarea trebuie să fie aici.
            if any(c in val or c in name for c in ("\r", "\n", "\0")):
                continue
            if not name or not all(32 < ord(c) < 127 and c not in '()<>@,;:\\"/[]?={} \t'
                                   for c in name):
                continue                       # nume de antet care nu e token HTTP valid
            if nl == "set-cookie":
                # Scoatem `Domain=`: fiecare forward stă pe subdomeniul lui tocmai ca să fie
                # izolat, iar un serviciu ostil (sau doar prost configurat) în spatele unui
                # forward putea seta un cookie cu Domain=<domeniul de forward>, care ajungea
                # apoi la TOATE forward-urile surori. Autentificarea nu era afectată (tokenul
                # e legat de slug, cookie-ul nostru e `__Host-`), dar cookie-urile aplicaţiilor
                # forwardate se contaminau între ele. Fără atributul ăsta cookie-ul devine
                # host-only — exact ce vrem de la un proxy per-subdomeniu.
                set_cookies.append(_strip_cookie_domain(val))
            else:
                resp_headers[name] = val
    except HTTPException:
        raise
    except Exception:
        await fs.close()
        raise ApiError(502, "forward.proxyError", "forward proxy error")

    async def body_stream():
        try:
            if rest:
                yield rest
            while True:
                chunk = await fs.read()
                if chunk is None:
                    break
                yield chunk
        finally:
            await fs.close()

    response = StreamingResponse(body_stream(), status_code=status, headers=resp_headers)
    for sc in set_cookies:                     # Set-Cookie multiplu (app-ul forwardat)
        response.raw_headers.append((b"set-cookie", sc.encode("latin1")))
    return response


# ── [forward] Probă de accesibilitate (bulinele de stare din UI) ───────────────────────


# Pe FORWARD-ID: folosește ținta STOCATĂ (declarată de admin), nu un host:port din
# URL — fără suprafață SSRF de „probează orice".
@router.get("/api/forwards/{fid}/probe")
async def forward_probe(fid: int, stepup_grant: str = "", stepup_password: str = "", stepup_totp: str = "",
                        user=Depends(authz.perm('forward.use', host='fid'))):
    # `enabled=0` era ignorat aici: butonul „Oprit" din UI e singura pârghie de „taie accesul
    # acum", iar pe calea HTTP funcţiona (404). Pe telnet şi pe probă, sesiunea se deschidea şi
    # octeţii curgeau spre echipamentul din LAN, cu forward-ul dezactivat.
    row = await db.fetchone("SELECT * FROM port_forwards WHERE id=? AND enabled=1", fid)
    if not row:
        raise ApiError(404, "forward.missing", "no such forward")
    # Proba spune dacă un port e deschis în reţeaua host-ului — un oracol de recunoaştere,
    # aceeaşi clasă cu restul acţiunilor de host. Fără gard, un cookie furat putea scana
    # ţinte pe un host cu 2FA fără să creeze nimic.
    await stepup.require_host_stepup(row["host_id"], user, stepup_grant, stepup_password, stepup_totp)
    conn = await _ensure_forward_source(row["host_id"])
    if conn is None:
        raise ApiError(409, "forward.hostOffline", "the host is offline (or an SSH host that needs an open session)")
    try:
        fs = await _open_target(conn, row["target_host"], row["target_port"], row["scheme"])
    except core.ForwardError as e:
        # detaliul brut (adresă/eroare de reţea a ţintei) rămâne în logul serverului; clientul
        # primeşte un cod stabil — un Viewer cu `forward.use` nu vede ţinta nici aşa (3.6)
        log.info("forward probe %s: target unreachable: %s", fid, e)
        return {"reachable": False, "code": "forward.unreachable",
                "detail": "the forwarded service is not reachable"}
    except (core.AgentGone, TimeoutError):
        raise ApiError(409, "host.offline", "the host is offline")
    try:
        await fs.write(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = await asyncio.wait_for(fs.read(), timeout=5)
            except asyncio.TimeoutError:
                break
            if chunk is None:                 # EOF: connect refuzat sau țintă a închis
                break
            buf += chunk
    finally:
        await fs.close()
    # accesibil = am primit octeți înapoi. Portul refuzat: connect() non-blocant
    # reușește „în progres", eșuează async → tunelul se închide fără date → 0 octeți.
    reachable = len(buf) > 0
    status = buf.split(b"\r\n", 1)[0].decode("latin1") if buf else ""
    return {"reachable": reachable, "status_line": status, "bytes": len(buf),
            "head": buf[:400].decode("latin1", "replace")}


# ── [forward] Port forwards: declarare & management (CRUD) ─────────────────────────────


# Domeniul de forward: implicit = gazda aplicației (din PUBLIC_URL), dar poate fi
# suprascris din Settings (util dacă vrei forward-urile pe alt domeniu decât app-ul).
# Sursa de adevăr pentru APP e app_settings['forward_domain']; infra (Traefik cert +
# rutare) se aliniază prin FORWARD_DOMAIN în .env — vezi verificarea de readiness.
_FWD_SCHEME = urlparse(config.PUBLIC_URL).scheme or "https"   # https în prod; http la test


def _fwd_port_suffix(public_url: str) -> str:
    """`:PORT` din PUBLIC_URL când e explicit şi nu e portul implicit al schemei, altfel "".
    Linkurile forward-urilor (`slug.<domeniu>`) pierdeau portul gateway-ului: pe o instanţă
    publicată pe :8443, „Open" ducea pe :443, unde nu ascultă nimeni (audit funcţional 3.6.3).
    Rutarea pe subdomeniu şi verificarea Origin-ului (`_fwd_origin_for_target`) ignoră deja
    portul (compară schema + numele de host), deci acceptă exact aceleaşi cereri ca înainte."""
    try:
        p = urlparse(public_url or "")
        port = p.port
    except ValueError:
        return ""
    scheme = (p.scheme or "https").lower()
    if port is None or port == {"http": 80, "https": 443}.get(scheme):
        return ""
    return ":%d" % port


_FWD_PORT = _fwd_port_suffix(config.PUBLIC_URL)


def _fwd_base(slug: str) -> str:
    """Originea publică a unui forward: schema PUBLIC_URL + subdomeniu + (portul, dacă nu e implicit)."""
    return "%s://%s.%s%s" % (_FWD_SCHEME, slug, fwddomain.forward_domain(), _FWD_PORT)


def _readiness_blocking(app_domain: str, domain: str) -> dict:
    """DNS wildcard + certificat Traefik pentru domeniu, verificate din exterior.
    Rulează într-un thread (socket/ssl sunt blocante)."""
    server_ip = ""
    try:
        server_ip = socket.gethostbyname(app_domain) if app_domain else ""
    except OSError:
        pass
    probe = "wtcheck." + domain
    dns_ip = ""
    try:
        dns_ip = socket.gethostbyname(probe)
    except OSError:
        dns_ip = ""
    cert_ok = False
    if dns_ip:
        try:
            ctx = ssl.create_default_context()   # verifică față de CA-urile sistemului
            with socket.create_connection((probe, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=probe):
                    cert_ok = True               # handshake valid = cert acoperă *.domeniu
        except Exception:
            cert_ok = False
    return {"server_ip": server_ip, "dns_ip": dns_ip,
            "dns_ok": bool(dns_ip), "cert_ok": cert_ok}


async def _forward_settings_json() -> dict:
    domain = fwddomain.forward_domain()
    app_domain = urlparse(config.PUBLIC_URL).hostname or ""
    st = await asyncio.to_thread(_readiness_blocking, app_domain, domain)
    return {"domain": domain, "app_domain": app_domain,
            "is_custom": domain != app_domain, **st}


class ForwardDomainIn(BaseModel):
    domain: str


@router.get("/api/settings/forward")
async def get_forward_settings(user=Depends(authz.perm('settings.manage'))):
    return await _forward_settings_json()


@router.post("/api/settings/forward")
async def save_forward_settings(body: ForwardDomainIn,
                                user=Depends(authz.perm('settings.manage'))):
    d = body.domain.strip().lower().rstrip(".")
    if not fwddomain.valid_domain(d):
        raise ApiError(400, "settings.badForwardDomain", "invalid domain (e.g. apps.example.com)")
    # Un domeniu de forward care e PĂRINTE al domeniului aplicaţiei o înghite: `route_forward`
    # decide „e subdomeniu de forward" prin `host.endswith("." + fwddomain.forward_domain())` şi nu
    # compară niciodată cu domeniul app-ului. Aplicaţia la `wt.exemplu.com` + forward pe
    # `exemplu.com` → de la cererea următoare TOT (UI, API, inclusiv endpointul ăsta) răspunde
    # 404, iar recuperarea cere editarea manuală a SQLite pe server. Salvarea răspundea 200.
    # ATENŢIE la cazul normal: implicit domeniul de forward E domeniul aplicaţiei, iar
    # slug-urile sunt subdomenii ale lui (`app.exemplu.com` + `x.app.exemplu.com`) —
    # `route_forward` lasă gazda exactă să treacă la app. Periculos e doar când aplicaţia
    # ajunge STRICT SUB domeniul de forward: app la `wt.exemplu.com`, forward pe `exemplu.com`
    # → gazda app-ului devine „slug-ul wt" şi tot UI-ul/API-ul răspunde 404.
    app_host = (urlparse(config.PUBLIC_URL).hostname or "").lower()
    if app_host and app_host != d and app_host.endswith("." + d):
        raise ApiError(400, "settings.forwardDomainContainsApp",
                       "the app domain (%s) would become a forward subdomain — "
                       "pick a domain that does NOT contain it (e.g. apps.%s)" % (app_host, d),
                       vars={"app_host": app_host, "domain": d})
    await db.set_setting("forward_domain", d)
    await fwddomain.load_forward_domain()
    return await _forward_settings_json()


# ── [forward] Forward model: request bodies, target validation, slug, JSON ──────────────


_APP_TYPES = ("", "proxmox", "portainer", "grafana", "custom",
              # console web de DB/observability (preseturi) — tot un port_forward, doar metadate
              "adminer", "pgadmin", "phpmyadmin", "mongo-express", "kibana", "clickhouse")


class ForwardIn(BaseModel):
    label: str
    target_host: str = "127.0.0.1"
    target_port: int
    scheme: str = "http"
    description: str = ""
    enabled: bool = False
    app_type: str = ""                 # non-gol → apare ca „app" (bookmark) cu icon + pe dashboard
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


class ForwardPatch(BaseModel):
    label: str | None = None
    target_host: str | None = None
    target_port: int | None = None
    scheme: str | None = None
    description: str | None = None
    enabled: bool | None = None
    app_type: str | None = None        # setează/promovează sau scoate (→ "") statutul de app
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


def _validate_forward(host: str, port: int, scheme: str):
    if not (1 <= int(port) <= 65535):
        raise ApiError(400, "forward.badPort", "invalid port (1–65535)")
    if scheme not in ("http", "https", "telnet"):
        raise ApiError(400, "forward.badScheme", "scheme must be http, https or telnet")
    # allowlist STRICT (nu blocklist): hostname / IPv4 / IPv6 conțin doar
    # alfanumerice + . - : _ . Blocklist-ul vechi lăsa să treacă ESC (0x1b) și
    # restul C0 → un target_host cu secvențe ANSI ajungea în terminal/transcript
    # prin marcajul de reconectare (core.py), ocolind și filtrul OSC. Allowlist-ul
    # elimină întreaga clasă de injecție de secvențe în terminal.
    if not host or len(host) > 255 or not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
        raise ApiError(400, "forward.badTarget", "invalid target_host (letters, digits, . - : _ only)")


# 3.7.0: `agents.<domeniu>` e numele pe care se conectează agenţii cu mTLS (edgemtls.py). Când domeniul de
# forward e acelaşi cu cel principal, un forward cu slug-ul `agents` ar fi împărţit numele cu ei.
RESERVED_SLUGS = {"agents"}


async def _unique_slug(label: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:40] or "fwd"
    ah = edgemtls.agent_host()
    reserved = RESERVED_SLUGS | ({ah[:-len(fwddomain.forward_domain()) - 1]}
                                 if ah and ah.endswith("." + fwddomain.forward_domain()) else set())
    if base in reserved:
        base += "-fwd"
    slug = base
    n = 2
    while await db.fetchone("SELECT 1 FROM port_forwards WHERE slug=?", slug):
        slug = "%s-%d" % (base, n)
        n += 1
    return slug


def _strip_cookie_domain(value: str) -> str:
    """Scoate atributul `Domain=` dintr-un Set-Cookie venit de la serviciul forwardat.

    Atributele sunt separate prin `;` iar valoarea cookie-ului e prima bucată — pe care
    NU o atingem (poate conţine `=` şi chiar textul „domain"). Comparăm doar numele
    atributului, case-insensitive, ca în RFC 6265."""
    parts = value.split(";")
    kept = [parts[0]]
    for attr in parts[1:]:
        if attr.strip().split("=", 1)[0].strip().lower() == "domain":
            continue
        kept.append(attr)
    return ";".join(kept)


def _forward_json(row) -> dict:
    return {
        "id": row["id"], "host_id": row["host_id"], "label": row["label"],
        "slug": row["slug"], "target_host": row["target_host"],
        "target_port": row["target_port"], "scheme": row["scheme"],
        "description": row["description"] or "", "enabled": bool(row["enabled"]),
        "created": row["created"],
        "app_type": (row["app_type"] if "app_type" in row.keys() else "") or "",
        # subdomeniul pe care se accesează (izolare de origin)
        "url": _fwd_base(row["slug"]),
    }


# ── [forward] Per-host forwards list, dashboard apps ─────────────────────────────────────────────────


@router.get("/api/hosts/{host_id}/forwards")
async def list_forwards(host_id: int, request: Request, stepup_grant: str = "",
                        stepup_password: str = "", stepup_totp: str = "",
                        user=Depends(authz.perm('forward.use', host='host_id'))):
    # Lista arată `target_host:target_port` pentru fiecare tunel — exact informaţia pentru care
    # s-a pus step-up pe probă („ce port intern e deschis"). Create/patch/delete/probe/telnet îl
    # cereau toate; lista o dădea gratis, deci gardul era ocolibil prin simpla citire.
    await stepup.require_host_stepup(host_id, user, stepup_grant, stepup_password, stepup_totp)
    rows = await db.fetchall(
        "SELECT * FROM port_forwards WHERE host_id=? ORDER BY created", host_id)
    out = [_forward_json(r) for r in rows]
    # 3.6: ţinta (`host:port` intern) doar cu `forward.manage` — cine doar DESCHIDE forward-uri
    # (Viewer, Operator) vede eticheta şi URL-ul, nu harta reţelei interne a hostului
    if "forward.manage" not in await authz.require_on(request, host_id, "forward.use"):
        for f in out:
            f["target_host"], f["target_port"] = "", None
    return out


@router.get("/api/apps")
async def list_apps(request: Request, user=Depends(authz.perm('forward.use', list=True))):
    """Toate forward-urile promovate la „app" (bookmark), agregate din toată flota, pentru strip-ul
    de pe dashboard. NU expune `target_host:port` (motivul step-up-ului pe listarea per-host) — doar
    ce e nevoie ca să afişezi şi deschizi o dală: nume, subdomeniu, tip, host, activ. Deci nu cere
    step-up: nu scurge ce port intern e deschis."""
    rows = await db.fetchall(
        "SELECT f.id, f.label, f.slug, f.scheme, f.enabled, f.app_type, f.host_id, h.name AS host_name"
        " FROM port_forwards f JOIN hosts h ON h.id=f.host_id"
        " WHERE f.app_type IS NOT NULL AND f.app_type<>'' ORDER BY h.name, f.label")
    vis = await authz.visible_hosts(authz.grants_of(request), "forward.use")   # 3.6
    rows = [r for r in rows if authz.in_visible(vis, r["host_id"])]
    return [{
        "id": r["id"], "label": r["label"], "app_type": r["app_type"],
        "host_id": r["host_id"], "host_name": r["host_name"], "enabled": bool(r["enabled"]),
        "url": _fwd_base(r["slug"]),
    } for r in rows]


# ── [forward] Forward create / update / delete, telnet forwards ───────────────────────────────────


@router.post("/api/hosts/{host_id}/forwards")
async def create_forward(host_id: int, body: ForwardIn,
                         user=Depends(authz.perm('forward.manage', host='host_id'))):
    # Un forward e o gaură făcută la comandă în reţeaua host-ului: `127.0.0.1:2375` (API-ul
    # Docker) devine accesibil din afară. Pe un host cu 2FA, asta trebuie să coste un factor.
    # Comentariul de dinainte spunea că e „aceeaşi categorie ca citirea istoricului" — dar
    # citirea istoricului a fost închisă cu step-up între timp, deci premisa a căzut şi
    # forward-urile rămăseseră singura acţiune de host descoperită. Vezi şi `forward_auth`,
    # care apără ACCESUL: fără el, gardul de aici ar opri doar crearea de forward-uri noi.
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    _validate_forward(body.target_host, body.target_port, body.scheme)
    # invalid = 400, nu coerţie tăcută: "Portainer " (majusculă/spaţiu) „reuşea" dar tile-ul
    # nu apărea nicăieri — clientul afla abia căutându-l pe dashboard (audit 2026-09)
    if body.app_type not in _APP_TYPES:
        raise ApiError(400, "forward.badAppType", "unknown app type")
    app_type = body.app_type
    label = body.label.strip()[:60] or "forward"
    # _unique_slug + INSERT NU e atomic: două creări concurente (double-click / două tab-uri)
    # pot alege același slug și apoi ciocni pe constrângerea UNIQUE → 500. Reîncercăm: la tura
    # următoare _unique_slug vede slug-ul deja ocupat și alege sufixul următor, deci converge.
    slug = None
    for _ in range(5):
        slug = await _unique_slug(label)
        try:
            await db.execute(
                "INSERT INTO port_forwards(host_id, label, slug, target_host, target_port,"
                " scheme, description, enabled, created, app_type) VALUES(?,?,?,?,?,?,?,?,?,?)",
                host_id, label, slug, body.target_host, int(body.target_port),
                body.scheme, (body.description or "")[:500], int(body.enabled), time.time(), app_type)
            break
        except sqlite3.IntegrityError:
            slug = None
    if slug is None:
        raise ApiError(409, "forward.slugTaken", "slug taken, retry")
    row = await db.fetchone("SELECT * FROM port_forwards WHERE slug=?", slug)
    return _forward_json(row)


@router.patch("/api/forwards/{fid}")
async def update_forward(fid: int, body: ForwardPatch,
                         user=Depends(authz.perm('forward.manage', host='fid'))):
    row = await db.fetchone("SELECT * FROM port_forwards WHERE id=?", fid)
    if not row:
        raise ApiError(404, "forward.missing", "no such forward")
    # re-ţintirea unui forward existent e la fel de puternică precum crearea lui
    await stepup.require_host_stepup(row["host_id"], user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    host = body.target_host if body.target_host is not None else row["target_host"]
    port = body.target_port if body.target_port is not None else row["target_port"]
    scheme = body.scheme if body.scheme is not None else row["scheme"]
    _validate_forward(host, port, scheme)
    label = (body.label.strip()[:60] or row["label"]) if body.label is not None else row["label"]
    desc = (body.description or "")[:500] if body.description is not None else row["description"]
    enabled = int(body.enabled) if body.enabled is not None else row["enabled"]
    cur_app = (row["app_type"] if "app_type" in row.keys() else "") or ""
    if body.app_type is not None and body.app_type not in _APP_TYPES:
        raise ApiError(400, "forward.badAppType", "unknown app type")   # nu păstra tăcut vechiul
    app_type = body.app_type if body.app_type is not None else cur_app
    await db.execute(
        "UPDATE port_forwards SET label=?, target_host=?, target_port=?, scheme=?,"
        " description=?, enabled=?, app_type=? WHERE id=?",
        label, host, int(port), scheme, desc, enabled, app_type, fid)
    return _forward_json(await db.fetchone("SELECT * FROM port_forwards WHERE id=?", fid))


@router.delete("/api/forwards/{fid}")
async def delete_forward(fid: int, stepup_grant: str = "", stepup_password: str = "", stepup_totp: str = "",
                         user=Depends(authz.perm('forward.manage', host='fid'))):
    row = await db.fetchone("SELECT host_id FROM port_forwards WHERE id=?", fid)
    if not row:
        return {"ok": True}                     # idempotent: deja nu există
    # ştergerea nu deschide acces, dar e o schimbare de configurare a unui host cu 2FA —
    # şi, mai practic, cine poate şterge poate re-crea imediat cu altă ţintă
    await stepup.require_host_stepup(row["host_id"], user, stepup_grant, stepup_password, stepup_totp)
    await db.execute("DELETE FROM port_forwards WHERE id=?", fid)
    # Biletul e semnat pe SLUG, iar `_unique_slug` recicla slug-ul unui forward şters: un bilet
    # vechi (emis pentru altă ţintă) redevenea valid pe forward-ul nou cu acelaşi nume. Verificat:
    # `web`→:19999 şters, recreat `web`→:19997 — acelaşi cookie deschidea noua ţintă. Bumpăm epoca,
    # ca la logout: toate biletele mor, iar handshake-ul se reface transparent (un redirect).
    security.bump_forward_epoch()
    return {"ok": True}


class TelnetOpenIn(BaseModel):
    title: str = ""
    rows: int = 24
    cols: int = 80
    tz: str | None = None
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


@router.post("/api/forwards/{fid}/telnet")
async def open_forward_telnet(fid: int, body: TelnetOpenIn, request: Request,
                              user=Depends(authz.perm('forward.manage', host='fid'))):
    """Bastion telnet: deschide o sesiune de terminal către ținta unui forward
    (scheme=telnet), tunelată prin agentul host-ului. Spre deosebire de forward-urile
    web (subdomeniu + proxy HTTP), aici suprafața de acces e un TERMINAL pe originul
    principal — fără DNS/cert/cookie nou (vezi docs/design/TELNET-BASTION.md §3)."""
    # `enabled=0` era ignorat aici: butonul „Oprit" din UI e singura pârghie de „taie accesul
    # acum", iar pe calea HTTP funcţiona (404). Pe telnet şi pe probă, sesiunea se deschidea şi
    # octeţii curgeau spre echipamentul din LAN, cu forward-ul dezactivat.
    row = await db.fetchone("SELECT * FROM port_forwards WHERE id=? AND enabled=1", fid)
    if not row:
        raise ApiError(404, "forward.missing", "no such forward")
    # 3.6: deschide o SESIUNE (terminal) prin forward → şi `session.open` pe host
    await authz.require_on(request, row["host_id"], "session.open", "fid")
    # H1: sesiune interactivă prin agentul host-ului — aceeași poartă ca create_session
    await stepup.require_host_stepup(row["host_id"], user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    if row["scheme"] != "telnet":
        raise ApiError(400, "forward.notTelnet", "this forward is not a telnet forward")
    title = body.title.strip() or row["label"] or f'{row["target_host"]}:{row["target_port"]}'
    try:
        result = await core.create_telnet_session(row, title[:60], body.rows, body.cols, body.tz)
        await core.stamp_session(result, user)
        return result
    except core.AgentGone:
        raise ApiError(409, "host.offline", "the host is offline (the agent is not connected)")
    except core.SessionLimitReached:
        raise ApiError(409, "telnet.limit", "the telnet session limit was reached — close one first")
    except RuntimeError as e:
        raise errors.runtime_api_error(e, "session.createFailed")


# ── [forward] Routing pe subdomeniu + handshake de auth ────────────────────────────────


async def _forward_stepup_ok(slug: str, request: Request) -> bool:
    """Pe hosturile marcate `require_2fa`, un tunel deschis se închide când se închide
    fereastra de step-up. Pentru restul, mereu adevărat (zero cost).

    Verificarea stă pe calea prin care trece TOT traficul forwardat, deci o excepţie aici nu
    e o poartă închisă, ci 500 la fiecare cerere. Prima versiune interoga o tabelă inexistentă
    (`forwards` în loc de `port_forwards`) şi exact asta s-a întâmplat: opt teste de forward
    au picat, jumătate cu 500.

    Nu o înfăşurăm într-un `try/except` care întoarce True: pe o verificare de securitate,
    „n-am putut afla, deci las să treacă" e o apărare de faţadă. Dacă interogarea moare, moare
    şi căutarea ţintei de imediat după, deci cererea eşuează oricum — vizibil, nu tăcut.
    `tests/forward_stepup_test.py` execută funcţia pe o bază reală, cu schema reală, ceea ce
    e singurul lucru care ar fi prins un nume de tabelă greşit.

    Identitatea vine din BILETUL de forward, nu din cookie-ul de sesiune: sesiunea e `__Host-`
    (host-only pe domeniul principal) şi nu ajunge niciodată pe `slug.<domeniu>`. Versiunea
    care o citea de aici întorcea mereu False pe hosturile 2FA → redirect relativ → acelaşi
    subdomeniu → aceeaşi funcţie → ERR_TOO_MANY_REDIRECTS (audit 2026-10-04): feature mort,
    nedetectat fiindcă testul simula un cookie pe care browserul nu-l trimite."""
    return await _forward_window_ok(slug, request.cookies.get(FWD_COOKIE))


async def _forward_window_ok(slug: str, ticket: str | None) -> bool:
    """Sursa unică de adevăr pentru HTTP ŞI WebSocket: pe un host 2FA, biletul e valid
    criptografic ŞI fereastra de step-up a contului care l-a emis mai e deschisă. `uid`-ul e
    crezut doar după verificarea semnăturii (`forward_token_uid`). Pe hosturi fără 2FA → True,
    fără să atingă biletul (acela e verificat separat, pe ambele căi)."""
    row = await db.fetchone(
        "SELECT f.host_id, h.require_2fa FROM port_forwards f JOIN hosts h ON h.id=f.host_id"
        " WHERE f.slug=? AND f.enabled=1", slug)
    if not row or not row["require_2fa"]:
        return True
    uid = security.forward_token_uid(ticket, slug)
    return uid is not None and security.stepup_window_is_open(uid, row["host_id"])


# INV-06 (docs/design/INVARIANTS.md): biletul de forward e re-verificat pe grant-urile CURENTE la fiecare cerere (și INV-11).
async def _forward_authz_ok(slug: str, ticket: str | None) -> bool:
    """3.6 (§A.6.4): biletul de forward trăieşte până la 12 h, mai mult decât un rol. Deci la
    FIECARE cerere (HTTP) şi la fiecare revalidare (WS) re-verificăm că acel cont care a emis
    biletul are încă `forward.use` pe hostul forward-ului. Cache pe epocă → o căutare în dict.
    Fail-closed: orice nu se poate stabili (bilet invalid, forward dispărut) = refuz."""
    uid = security.forward_token_uid(ticket, slug)
    if uid is None:
        return False
    row = await db.fetchone("SELECT host_id FROM port_forwards WHERE slug=? AND enabled=1", slug)
    if not row:
        return False
    if not await db.fetchone("SELECT 1 FROM users WHERE id=?", uid):
        return False
    grants = await authz.grants_for_user(uid)
    return "forward.use" in await authz.perms_on(grants, row["host_id"])


def _safe_next(nxt: str | None) -> str:
    """`next` e doar o CALE pe subdomeniul de forward: refuză URL-uri absolute, `//evil`
    (schema-relativ → alt host), `/\\evil` (browserele îl normalizează la `//`), control
    chars şi orice duce înapoi în namespace-ul handshake-ului (`/__wtfwd/*` ca `next` ar
    reface bucla de redirect pe care tocmai am închis-o). Altfel → rădăcina."""
    if (not nxt or not nxt.startswith("/") or nxt.startswith(("//", "/\\", "/__wtfwd/"))
            or any(ch in nxt for ch in "\r\n\0")):
        return "/"
    return nxt


async def route_forward(request: Request):
    """Dacă cererea e pentru un subdomeniu de forward, o tratează (auth / redirect /
    proxy) și întoarce un Response; altfel None (merge la rutele normale).
    Apelat din middleware-ul din main.py, ÎNAINTE de restul rutelor."""
    host = (request.headers.get("host") or "").split(":")[0].lower()
    if not host or host == fwddomain.forward_domain() or not host.endswith("." + fwddomain.forward_domain()):
        return None                            # domeniul principal → app normal
    # Plasă de siguranţă pentru o instanţă deja configurată greşit (sau pentru o setare care
    # ajunge în DB pe altă cale decât endpointul validat): domeniul APLICAŢIEI nu poate fi
    # niciodată tratat ca subdomeniu de forward. Fără asta, un `forward_domain` părinte făcea
    # ca UI-ul, API-ul şi chiar endpointul de reparare să răspundă 404 — recuperabil doar
    # editând SQLite pe server.
    if host == (urlparse(config.PUBLIC_URL).hostname or "").lower():
        return None
    slug = host[:-(len(fwddomain.forward_domain()) + 1)]
    if not slug or "." in slug:
        return PlainTextResponse("no such forward", status_code=404)
    # pasul 3 din handshake: setează cookie-ul pe subdomeniu
    if request.url.path == "/__wtfwd/set":
        return await _forward_set_cookie(request, slug)
    row = await db.fetchone(
        "SELECT * FROM port_forwards WHERE slug=? AND enabled=1", slug)
    if not row:
        return PlainTextResponse("no such forward, or it is disabled", status_code=404)
    # fără cookie valid → trimite la handshake pe domeniul principal (unde e sesiunea)
    # F-06 partea a doua: biletul e valid criptografic, dar pe un host cu 2FA întrebăm şi
    # dacă fereastra care l-a autorizat mai e deschisă. Fără asta, un tunel deja deschis
    # supravieţuia închiderii ferestrei — e o căutare într-un dict, deci practic gratis.
    # Ambele redirecturi sunt ABSOLUTE, către domeniul principal: acolo e sesiunea şi acolo
    # `forward_auth` fie re-emite biletul (fereastră deschisă), fie trimite omul în SPA să
    # redeschidă fereastra. Un redirect relativ rămânea pe subdomeniu → buclă infinită.
    # Ordinea: biletul întâi — fără bilet nu ştim al cui e tunelul, deci nu are rost să
    # întrebăm de vreo fereastră.
    ticket = request.cookies.get(FWD_COOKIE)
    if (not security.verify_forward_token(ticket, slug)
            or not await _forward_window_ok(slug, ticket)
            or not await _forward_authz_ok(slug, ticket)):
        nxt = _safe_next(request.url.path + (("?" + request.url.query) if request.url.query else ""))
        loc = "%s/__wtfwd/auth?slug=%s&next=%s" % (config.PUBLIC_URL, slug, quote(nxt, safe=""))
        return RedirectResponse(loc, status_code=302)
    # autorizat → proxy către ținta STOCATĂ (anti-SSRF: nu din URL)
    tp = request.url.path + (("?" + request.url.query) if request.url.query else "")
    return await proxy_forward_http(request, row["host_id"], row["target_host"],
                                    row["target_port"], tp, row["scheme"])


async def _forward_set_cookie(request: Request, slug: str):
    token = request.query_params.get("t", "")
    nxt = _safe_next(request.query_params.get("next", "/"))   # anti open-redirect: doar căi relative
    if not security.verify_forward_token(token, slug):
        return PlainTextResponse("invalid or expired token", status_code=403)
    resp = RedirectResponse(_fwd_base(slug) + nxt, status_code=302)
    resp.set_cookie(FWD_COOKIE, token, max_age=security.FORWARD_TOKEN_TTL,
                    httponly=True, secure=config.PUBLIC_URL.startswith("https://"),
                    samesite="lax", path="/")
    return resp


@router.get("/__wtfwd/auth")
async def forward_auth(request: Request, slug: str, next: str = "/"):
    """Pe domeniul PRINCIPAL (unde ajunge cookie-ul de sesiune): dacă ești
    autentificat, emite un token semnat pentru forward-ul cerut și redirect la
    subdomeniu. Nu setează nimic aici — doar semnează după require_user."""
    user = await security.user_for_token(request.cookies.get(security.COOKIE_NAME))
    if not user:                                # nelogat → la login, apoi redeschizi forward-ul
        return RedirectResponse(config.PUBLIC_URL + "/", status_code=302)
    row = await db.fetchone(
        "SELECT slug, host_id FROM port_forwards WHERE slug=? AND enabled=1", slug)
    if not row:
        raise ApiError(404, "forward.missing", "no such forward, or it is disabled")
    # 3.6: biletul se emite DOAR cu `forward.use` pe hostul forward-ului. Un host invizibil dă
    # exact 404-ul de mai sus (fără oracol); vizibil dar fără permisiune → 403 authz.denied.
    have = await authz.perms_on(await authz.grants_for_user(user["id"]), row["host_id"])
    if "host.view" not in have:
        raise ApiError(404, "forward.missing", "no such forward, or it is disabled")
    if "forward.use" not in have:
        raise ApiError(403, "authz.denied", "your role does not allow this here (forward.use)",
                       vars={"perm": "forward.use"})
    # Pe un host cu 2FA, cookie-ul singur nu deschide tunelul. Aici NU putem rula ceremonia
    # passkey (suntem pe un redirect de pagină, în afara SPA-ului), deci cerem o fereastră de
    # step-up deja deschisă din aplicaţie şi, dacă lipseşte, trimitem omul exact acolo unde o
    # poate deschide — un 403 sec l-ar lăsa fără nicio indicaţie ce să facă.
    host = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", row["host_id"])
    next = _safe_next(next)                     # anti open-redirect, ÎNAINTE de orice redirect
    # read-only: o navigare pe forward NU trebuie să prelungească fereastra de step-up (ţinerea
    # unui tab de forward deschis gliseaza altfel „sudo-ul" la nesfârşit — vezi auditul 2026-10)
    if host and host["require_2fa"] and not security.stepup_window_is_open(user["id"], row["host_id"]):
        # Parametrii merg în QUERY, nu după hash: ruta SPA e `^#/h/(\d+)$`, ancorată la final,
        # deci `#/h/5?stepup=...` n-ar mai fi recunoscută şi omul ar ateriza pe dashboard.
        # `next` călătoreşte prin ocol ca să revii pe pagina cerută, nu pe rădăcina forward-ului.
        return RedirectResponse(
            "%s/?stepup=forward&slug=%s&next=%s#/h/%d"
            % (config.PUBLIC_URL, quote(slug, safe=""), quote(next, safe=""), row["host_id"]),
            status_code=302)
    # F-06: pe un host cu 2FA, biletul NU poate trăi mai mult decât autorizarea care l-a
    # emis. Înainte, un step-up de 5 minute cumpăra 12 ore de tunel — adică exact factorul
    # pe care operatorul l-a cerut nu se aplica serviciului forwardat. Browserul reface
    # handshake-ul singur, deci pentru om e o redirectare, nu o eroare.
    ttl = (security.STEPUP_WINDOW_MAX if (host and host["require_2fa"])
           else security.FORWARD_TOKEN_TTL)
    # 3.6.5 (WEBTERM_OIDC_SESSION_MAX_HOURS): biletul unui cont SSO nu trăieşte mai mult decât
    # sesiunea care l-a emis — altfel un tunel de 12 h ocolea limita de vârstă a sesiunii
    left = await security.sso_session_seconds_left(request.cookies.get(security.COOKIE_NAME), user)
    if left is not None:
        ttl = max(1, min(ttl, int(left)))
    token = security.make_forward_token(slug, user["id"], ttl)
    loc = "%s/__wtfwd/set?t=%s&next=%s" % (_fwd_base(slug), token, quote(next, safe=""))
    return RedirectResponse(loc, status_code=302)


# ── [forward] WebSocket proxy prin tunel (codec propriu: gateway = client WS către țintă) ─


# L3: plafon anti-OOM pe un singur frame WS și pe reasamblarea continuărilor. Un dispozitiv ostil din
# spatele unui forward putea anunța un frame de 2^64 octeți → pbuf/acc creșteau nemărginit.
FWD_WS_MAX_FRAME = 8 * 1024 * 1024


class _WSFrameTooLarge(Exception):
    pass


def _ws_frame(payload: bytes, opcode: int) -> bytes:
    """Frame WS client→server (MASK obligatoriu). opcode: 1 text, 2 binary, 9/10 ping/pong."""
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n = len(payload)
    if n < 126:
        hdr = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
    elif n < 65536:
        hdr = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
    return hdr + mask + masked


def _ws_parse(buf: bytes):
    """Parsează frame-urile complete din buf. Întoarce (frames, rest). Fiecare frame
    = (opcode, payload, fin). Suportă payload mascat sau nu."""
    frames = []
    while len(buf) >= 2:
        b0, b1 = buf[0], buf[1]
        opcode = b0 & 0x0f
        ln = b1 & 0x7f
        idx = 2
        if ln == 126:
            if len(buf) < 4:
                break
            ln = struct.unpack("!H", buf[2:4])[0]
            idx = 4
        elif ln == 127:
            if len(buf) < 10:
                break
            ln = struct.unpack("!Q", buf[2:10])[0]
            idx = 10
        if ln > FWD_WS_MAX_FRAME:                 # L3: nu aștepta (și nu tampona) un frame uriaș
            raise _WSFrameTooLarge()
        mask = b""
        if b1 & 0x80:
            if len(buf) < idx + 4:
                break
            mask = buf[idx:idx + 4]
            idx += 4
        if len(buf) < idx + ln:
            break
        payload = buf[idx:idx + ln]
        if mask:
            payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        frames.append((opcode, payload, bool(b0 & 0x80)))
        buf = buf[idx + ln:]
    return frames, buf


def _parse_cookie_header(header: str) -> dict:
    out = {}
    for part in header.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k] = v
    return out


async def handle_forward_ws(scope, receive, send):
    """Proxy WebSocket pentru un subdomeniu de forward. Auth-ul se bazează pe cookie-ul
    __Host-wt_fwd (setat de handshake-ul HTTP, care rulează la încărcarea app-ului)."""
    headers = {k.decode("latin1").lower(): v.decode("latin1")
               for k, v in scope.get("headers", [])}
    host = headers.get("host", "").split(":")[0].lower()
    slug = host[:-(len(fwddomain.forward_domain()) + 1)] if host.endswith("." + fwddomain.forward_domain()) else ""
    if (await receive())["type"] != "websocket.connect":
        return
    # anti-CSWSH: browserul atașează cookie-ul de forward chiar și la un handshake WS
    # pornit de pe o pagină ostilă (SameSite=Lax nu acoperă sigur upgrade-urile WS).
    # Cerem ca Origin-ul să fie chiar subdomeniul de forward — doar pagina forwardată
    # (servită la slug.<domeniu>) îl are; altfel un site ostil ar deschide un WS
    # interactiv către serviciul din spatele forward-ului. La fel ca browser_ws/shared_ws.
    origin = headers.get("origin")
    cookies = _parse_cookie_header(headers.get("cookie", ""))
    # Şi SCHEMA trebuie să fie a noastră (cea din PUBLIC_URL): o pagină http:// pe acelaşi
    # subdomeniu (MITM pe HTTP-ul simplu) nu e originul forward-ului de pe o instalare https.
    o = security.origin_tuple(origin or "")
    pub = security.origin_tuple(config.PUBLIC_URL)
    if (not origin or o is None or pub is None or o[1] != host or o[0] != pub[0]
            or o[2] != _host_header_port(headers.get("host", ""), pub[0])
            or not slug or "." in slug
            or not security.verify_forward_token(cookies.get(FWD_COOKIE), slug)):
        await send({"type": "websocket.close", "code": 1008})
        return
    # Aceeaşi poartă ca pe HTTP (`route_forward`): pe un host 2FA, biletul singur nu ajunge —
    # fereastra de step-up a contului din bilet trebuie să fie deschisă. Fără asta, politica
    # „tunelul trăieşte cât fereastra" era adevărată pe HTTP şi falsă exact pe canalul
    # interactiv (consolă web, noVNC, code-server). WS nu poate fi redirecţionat la handshake,
    # deci închidem cu 1008 (Policy Violation) — acelaşi cod ca refuzul de bilet/Origin de mai
    # sus; pagina forwardată reîncarcă, HTTP-ul o trimite la step-up.
    if (not await _forward_window_ok(slug, cookies.get(FWD_COOKIE))
            or not await _forward_authz_ok(slug, cookies.get(FWD_COOKIE))):
        await send({"type": "websocket.close", "code": 1008})
        return
    row = await db.fetchone("SELECT * FROM port_forwards WHERE slug=? AND enabled=1", slug)
    conn = await _ensure_forward_source(row["host_id"]) if row else None
    if not row or conn is None:
        await send({"type": "websocket.close", "code": 1011})
        return
    try:
        fs = await _open_target(conn, row["target_host"], row["target_port"], row["scheme"])
    except Exception:
        await send({"type": "websocket.close", "code": 1011})
        return
    try:
        path = scope.get("path", "/")
        if scope.get("query_string"):
            path += "?" + scope["query_string"].decode("latin1")
        # anti request-smuggling: path-ul (percent-decodat de ASGI) ajunge în request-line-ul
        # HTTP raw trimis ţintei → respinge CRLF/NUL, ca şi calea HTTP de forward.
        if "\r" in path or "\n" in path or "\0" in path:
            await send({"type": "websocket.close", "code": 1008})
            return
        key = base64.b64encode(os.urandom(16)).decode()
        hs = ["GET %s HTTP/1.1" % path,
              "Host: %s:%d" % (row["target_host"], row["target_port"]),
              "Upgrade: websocket", "Connection: Upgrade",
              "Sec-WebSocket-Key: %s" % key, "Sec-WebSocket-Version: 13"]
        # Se trimitea ţintei DOAR `sec-websocket-protocol`: nicio aplicaţie care îşi
        # autentifică WebSocket-ul prin cookie de sesiune (Jupyter, code-server, Home Assistant,
        # noVNC, Grafana Live) nu putea funcţiona în spatele unui forward — pagina se încărca
        # (HTTP-ul propagă cookie-urile), iar terminalul/graficele rămâneau moarte, fără eroare.
        # Ţinta WS din testul de integrare e un `echo` fără autentificare, deci poarta trecea
        # verde fără să verifice nimic din ce contează. Propagăm acelaşi set ca pe calea HTTP.
        _WS_SKIP = {"host", "connection", "upgrade", "sec-websocket-key",
                    "sec-websocket-version", "sec-websocket-extensions",
                    "keep-alive", "proxy-authenticate", "proxy-authorization",
                    "te", "trailer", "transfer-encoding"}
        for h, v in headers.items():
            if h in _WS_SKIP:
                continue
            if h == "origin":
                # verificat mai sus (subdomeniul forward-ului); ţinta îl vede ca same-origin
                # (Grafana Live refuza handshake-ul: Origin ≠ Host) — vezi _fwd_origin_for_target
                v = "%s://%s:%d" % ("https" if row["scheme"] == "https" else "http",
                                    row["target_host"], row["target_port"])
            if h == "cookie":
                v = _strip_fwd_cookie(v)       # cookie-ul NOSTRU nu iese către ţintă
                if not v:
                    continue
            # CRLF/NUL în valoare = injectare în handshake-ul brut
            if "\r" in v or "\n" in v or "\0" in v:
                continue
            hs.append("%s: %s" % (h, v))
        await fs.write(("\r\n".join(hs) + "\r\n\r\n").encode("latin1"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(fs.read(), timeout=15)
            if chunk is None or len(buf) > 65536:
                await send({"type": "websocket.close", "code": 1011}); return
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0]:
            await send({"type": "websocket.close", "code": 1011}); return
        accept = {"type": "websocket.accept"}
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"sec-websocket-protocol:"):
                accept["subprotocol"] = line.split(b":", 1)[1].decode("latin1").strip()
        await send(accept)

        closed = asyncio.Event()

        async def revalidate():
            # M3: token-urile de forward mor la logout / schimbare de parolă (epoch bump).
            # Verificarea de la connect e o singură dată; re-verificăm periodic ca un tunel
            # ACTIV să se închidă când owner-ul face logout — la fel ca browser_ws/shared_ws.
            # Şi fereastra de step-up: biletul pe host 2FA trăieşte STEPUP_WINDOW_MAX (1 h), dar
            # fereastra se închide la 5 min de inactivitate sau la `clear_stepup_for` (logout din
            # alt tab, schimbare passkey). Doar pe bilet, un WS deja deschis rămânea viu până la
            # 55 de minute după ce politica spunea „închis". 1008, ca la handshake.
            wake = authz.subscribe()       # 3.6: o schimbare de rol re-verifică ACUM, nu la 60 s
            try:
                while not closed.is_set():
                    try:
                        await asyncio.wait_for(wake.wait(), security.WS_REVALIDATE_SECS)
                    except asyncio.TimeoutError:
                        pass
                    wake.clear()
                    ticket = cookies.get(FWD_COOKIE)
                    if (not security.verify_forward_token(ticket, slug)
                            or not await _forward_window_ok(slug, ticket)
                            or not await _forward_authz_ok(slug, ticket)):
                        try:
                            await send({"type": "websocket.close", "code": 1008})
                        except Exception:
                            pass
                        break
            finally:
                authz.unsubscribe(wake)
                closed.set()

        async def browser_to_target():
            try:
                while not closed.is_set():
                    m = await receive()
                    if m["type"] == "websocket.receive":
                        if m.get("text") is not None:
                            await fs.write(_ws_frame(m["text"].encode(), 0x1))
                        elif m.get("bytes") is not None:
                            await fs.write(_ws_frame(m["bytes"], 0x2))
                    elif m["type"] == "websocket.disconnect":
                        break
            except Exception:
                pass
            finally:
                closed.set()

        async def target_to_browser(pbuf):
            acc, acc_op = b"", None
            try:
                while not closed.is_set():
                    try:
                        frames, pbuf = _ws_parse(pbuf)
                    except _WSFrameTooLarge:
                        # L3: frame peste plafon → 1009 (Message Too Big) și închide
                        await send({"type": "websocket.close", "code": 1009})
                        closed.set(); break
                    for opcode, payload, fin in frames:
                        if opcode == 0x8:                 # close
                            closed.set(); break
                        if opcode == 0x9:                 # ping → pong
                            await fs.write(_ws_frame(payload, 0xa)); continue
                        if opcode == 0xa:                 # pong (ignoră)
                            continue
                        if opcode in (0x1, 0x2):
                            acc, acc_op = payload, opcode
                        elif opcode == 0x0:               # continuation
                            acc += payload
                        if len(acc) > FWD_WS_MAX_FRAME:   # L3: reasamblare de continuări plafonată
                            await send({"type": "websocket.close", "code": 1009})
                            closed.set(); break
                        if fin and acc_op is not None:
                            if acc_op == 0x1:
                                await send({"type": "websocket.send", "text": acc.decode("utf-8", "replace")})
                            else:
                                await send({"type": "websocket.send", "bytes": acc})
                            acc, acc_op = b"", None
                    if closed.is_set():
                        break
                    chunk = await fs.read()
                    if chunk is None:
                        break
                    pbuf += chunk
            except Exception:
                pass
            finally:
                closed.set()

        tb = asyncio.create_task(browser_to_target())
        tt = asyncio.create_task(target_to_browser(rest))
        tr = asyncio.create_task(revalidate())
        await closed.wait()
        tb.cancel(); tt.cancel(); tr.cancel()
        # așteaptă finalizarea anulării, altfel cleanup-ul taskurilor poate rămâne
        # în aer (și tunelul închis mai jos peste taskuri încă vii)
        await asyncio.gather(tb, tt, tr, return_exceptions=True)
    finally:
        await fs.close()
        try:
            await send({"type": "websocket.close"})
        except Exception:
            pass
