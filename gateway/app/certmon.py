"""TLS certificate monitoring + the "renew" command (3.6.7).

Why this exists (incident 2026-10-12): the wildcard `*.wt.safegrid.net` expired. It sat in the
HTTP-01 store (`le`, acme.json), and HTTP-01 cannot renew a wildcard, so Traefik logged
"Error renewing ACME certificate … could not determine solvers" every day for weeks. The routers
asked for it through DNS-01 (`ledns`), but Traefik never requested it there because a certificate
for the name already existed in the `le` store. Browsers then coalesced the expired wildcard onto
the main domain too. Nobody saw any of it until users did.

What this module does — and, deliberately, what it does NOT:
  * it opens a TLS handshake to Traefik (inside the compose network; the public name as a
    fallback for the main domain only) with the SNI of each name we care about and reads the LEAF the server sends. The
    chain is NOT validated: the whole point is to see an expired or a default certificate too;
  * it raises an alert through the existing alert path (in-app history + email/webhook) at < 14
    days left and again at < 3 days, critical when expired, when Traefik's self-signed default is
    served, or when the served certificate does not cover the name. One alert per threshold per
    certificate (persisted, survives restarts), plus an "OK again" once it is fixed;
  * it gets NO new privilege: no ACME store, no docker socket, no way to restart Traefik. Renewal
    is a HOST action (`scripts/cert-renew.sh`, run by a human under sudo); the gateway only builds
    the command line from validated names (`renew_command`) and, for an Owner, types it — not
    runs it — into a terminal on the host the Owner picked (see api.py `cert_renew_session`).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import re
import select
import shlex
import socket
import ssl
import time
from typing import Optional
from urllib.parse import urlparse

from . import audit, config, db, email_alerts

log = logging.getLogger("webterm")

WARN_DAYS = 14                  # first alert
CRIT_DAYS = 3                   # second alert
CHECK_INTERVAL = 24 * 3600      # daily…
STARTUP_DELAY = 45.0            # …plus once shortly after boot (Traefik may still be starting)
CONNECT_TIMEOUT = 5.0           # per connection attempt (connect + handshake, each socket op)
TOTAL_BUDGET = 25.0             # the whole check, all names, both attempts
MANUAL_MIN_INTERVAL = 30.0      # "Check now": at most one manual check per 30 s, instance-wide
MAX_NAMES = 4
MAX_SANS = 50
FORWARD_PROBE = "cert-check"    # the subdomain used to see the forward wildcard
TRAEFIK_DEFAULT_CN = "TRAEFIK DEFAULT CERT"
K_ALERTS = "certmon_alerts"     # app_settings: {name: {"fp": …, "level": n, "ts": …}}

# levels: what was last alerted for a certificate. Monotonic per certificate (fingerprint).
L_OK, L_WARN, L_SOON, L_CRIT = 0, 1, 2, 3
_STATE_LEVEL = {"ok": L_OK, "expiring": L_WARN, "expiring_soon": L_SOON,
                "expired": L_CRIT, "default": L_CRIT, "mismatch": L_CRIT, "error": L_OK}

# A hostname as the routers and the renewal script accept it: lowercase LDH labels, at least two
# labels, optionally ONE leading `*.` (a wildcard). Nothing else — no spaces, quotes, `$`, `;`,
# backticks, newlines, leading `-` (option injection), trailing dot, IDN in Unicode form.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST_RE = re.compile(r"^(?=.{1,253}$)%s(?:\.%s)+$" % (_LABEL, _LABEL))
RENEW_NAME_RE = re.compile(r"^(?:\*\.)?(?=.{1,253}$)%s(?:\.%s)+$" % (_LABEL, _LABEL))
# an absolute path made of plain segments (no `..`, no spaces, no shell metacharacters)
_DIR_RE = re.compile(r"^(?:/[A-Za-z0-9_][A-Za-z0-9._-]{0,63}){1,16}$")


def valid_hostname(name: str) -> bool:
    if not isinstance(name, str) or not HOST_RE.match(name):
        return False
    try:                                            # an IP literal has no certificate name to check
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return True


def renew_command(domain: str, install_dir: Optional[str] = None) -> str:
    """The exact command line the UI shows / types: `sudo -k <dir>/scripts/cert-renew.sh --domain X`.

    Built ONLY from validated pieces — the name must match RENEW_NAME_RE (exact match, no
    normalisation that could smuggle anything in) and the directory _DIR_RE. A wildcard is quoted
    (`'*.example.com'`) so the shell does not glob it. Raises ValueError otherwise; callers fail
    closed (no command rather than a wrong one)."""
    if not isinstance(domain, str) or not RENEW_NAME_RE.match(domain):
        raise ValueError("invalid domain name")
    d = install_dir if install_dir is not None else config.INSTALL_DIR
    if not isinstance(d, str) or not _DIR_RE.match(d) or "/../" in d + "/" or "/./" in d + "/":
        raise ValueError("invalid install directory")
    # `sudo -k`: ignore AND do not refresh sudo's cached credentials (security review F4). Without
    # it, the password typed here leaves a sudo timestamp on this tty that anyone else who can type
    # into the terminal could use for the next minutes.
    cmd = "sudo -k %s/scripts/cert-renew.sh --domain %s" % (d, shlex.quote(domain))
    # belt and braces: the result must be a plain token list identical to what we meant
    if shlex.split(cmd) != ["sudo", "-k", d + "/scripts/cert-renew.sh", "--domain", domain]:
        raise ValueError("command did not round-trip")
    return cmd


# The session command for "Renew in a terminal": it TYPES the command at a readline prompt
# (`read -e -i`) and runs it only when the person presses Enter — they can read it, edit it or
# Ctrl+C out. The command travels as a positional ARGUMENT ($1), never spliced into the script, so
# even a hypothetical bad value would be data, not code (it is validated anyway, see above).
_PROMPT_SH = r"""
printf '\n[WebTerm] TLS certificate renewal on this host.\n'
printf '[WebTerm] The command below is TYPED, NOT RUN. Read it, then press Enter to run it,\n'
printf '[WebTerm] edit it first, or press Ctrl+C to cancel (that closes this terminal).\n\n'
if IFS= read -r -e -i "$1" -p '$ ' line; then
  rc=0
  if [ -n "$line" ]; then history -s "$line"; eval "$line"; rc=$?; fi
  printf '\n[WebTerm] Finished (exit %s). Press Enter to close this terminal.\n' "$rc"
  IFS= read -r _
fi
"""


def typed_session_cmd(command: str) -> str:
    q = shlex.quote(command)
    return ("if command -v bash >/dev/null 2>&1; then exec bash -c %s webterm-cert-renew %s; "
            "else printf '%%s\\n' 'bash not found; run this yourself:' %s; "
            "exec \"${SHELL:-/bin/sh}\"; fi" % (shlex.quote(_PROMPT_SH), q, q))


# ── what to check ────────────────────────────────────────────────────────────────────────────
def _forward_enabled() -> bool:
    if config.CERT_CHECK_FORWARD in ("0", "1"):
        return config.CERT_CHECK_FORWARD == "1"
    # forwards on subdomains get a certificate only through DNS-01 (the wildcard); on HTTP-01
    # the forward router has no certificate by design, so checking it would only be noise
    return config.CERT_RESOLVER == "ledns"


def targets(forward_domain: str = "") -> list:
    """[{name, role, renew_domain, public_port}] — at most MAX_NAMES, all valid hostnames."""
    if not config.CERT_CHECK:
        return []
    u = urlparse(config.PUBLIC_URL)
    if (u.scheme or "").lower() != "https":
        return []
    out = []
    main = (u.hostname or "").lower()
    try:
        port = u.port or 443
    except ValueError:
        port = 443
    if valid_hostname(main):
        out.append({"name": main, "role": "main", "renew_domain": main, "public_port": port})
    fwd = (forward_domain or "").strip().lower().rstrip(".")
    if _forward_enabled() and valid_hostname(fwd):
        probe = "%s.%s" % (FORWARD_PROBE, fwd)
        if valid_hostname(probe):
            out.append({"name": probe, "role": "forward", "renew_domain": "*." + fwd,
                        "public_port": 443})
    ak = config.AUTHENTIK_DOMAIN
    if "authentik" in config.COMPOSE_PROFILES and valid_hostname(ak) and ak != main:
        out.append({"name": ak, "role": "authentik", "renew_domain": ak, "public_port": 443})
    seen, uniq = set(), []
    for t in out:
        if t["name"] not in seen:
            seen.add(t["name"])
            uniq.append(t)
    return uniq[:MAX_NAMES]


def renew_domains(forward_domain: str = "") -> set:
    return {t["renew_domain"] for t in targets(forward_domain)}


# ── reading the certificate ──────────────────────────────────────────────────────────────────
def fetch_leaf(host: str, port: int, sni: str, timeout: float = CONNECT_TIMEOUT) -> bytes:
    """The DER of the leaf certificate `host:port` serves for `sni`. Blocking (run in a thread).
    No chain validation, no hostname check — we want to SEE what is served, good or bad."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # ONE deadline for the whole attempt (security review): a per-operation timeout lets a peer
    # that trickles a byte every few seconds hold the thread indefinitely. Connect gets what is
    # left, then the handshake runs non-blocking against the same deadline.
    deadline = time.monotonic() + timeout

    def left() -> float:
        r = deadline - time.monotonic()
        if r <= 0:
            raise TimeoutError("TLS handshake timed out")
        return r

    with socket.create_connection((host, int(port)), timeout=left()) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni, do_handshake_on_connect=False) as tls:
            tls.setblocking(False)
            while True:
                try:
                    tls.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    ready = select.select([tls], [], [], left())[0]
                except ssl.SSLWantWriteError:
                    ready = select.select([], [tls], [], left())[1]
                if not ready:
                    raise TimeoutError("TLS handshake timed out")
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("the server sent no certificate")
    return der


def _cn(name) -> str:
    from cryptography.x509.oid import NameOID
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(attrs[0].value)[:200] if attrs else ""
    except Exception:                       # noqa: BLE001 — a malformed name is just "no CN"
        return ""


def _org(name) -> str:
    from cryptography.x509.oid import NameOID
    try:
        attrs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return str(attrs[0].value)[:200] if attrs else ""
    except Exception:                       # noqa: BLE001
        return ""


def covers(name: str, sans: list) -> bool:
    """RFC 6125: exact match, or a `*.` wildcard standing for exactly ONE leftmost label."""
    name = name.lower()
    for s in sans:
        s = (s or "").lower()
        if s == name:
            return True
        if s.startswith("*.") and "." in name and name.split(".", 1)[1] == s[2:]:
            return True
    return False


def parse_leaf(der: bytes) -> dict:
    from cryptography import x509
    cert = x509.load_der_x509_certificate(der)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(s)[:253] for s in ext.value.get_values_for_type(x509.DNSName)][:MAX_SANS]
    except x509.ExtensionNotFound:
        sans = []
    subject_cn = _cn(cert.subject)
    issuer_cn = _cn(cert.issuer)
    issuer_org = _org(cert.issuer)
    return {
        "not_after": cert.not_valid_after_utc.timestamp(),
        "not_before": cert.not_valid_before_utc.timestamp(),
        "subject_cn": subject_cn,
        "issuer": ", ".join(x for x in (issuer_cn, issuer_org) if x) or "?",
        "issuer_cn": issuer_cn,
        "sans": sans,
        "fingerprint": hashlib.sha256(der).hexdigest(),
        "self_signed": cert.subject == cert.issuer,
    }


def evaluate(name: str, info: dict, now: Optional[float] = None) -> dict:
    """state + days_left for one served certificate (pure; unit-tested)."""
    now = time.time() if now is None else now
    days = (info["not_after"] - now) / 86400.0
    names = info["sans"] or ([info["subject_cn"]] if info["subject_cn"] else [])
    default = TRAEFIK_DEFAULT_CN in (info.get("subject_cn"), info.get("issuer_cn"))
    if default:
        state = "default"
    elif days < 0:
        state = "expired"
    elif not covers(name, names):
        state = "mismatch"
    elif days < CRIT_DAYS:
        state = "expiring_soon"
    elif days < WARN_DAYS:
        state = "expiring"
    else:
        state = "ok"
    return {"state": state, "level": _STATE_LEVEL[state], "days_left": round(days, 1),
            "covers": covers(name, names),
            "wildcard": any(s.startswith("*.") for s in names)}


def _split_target(target: str):
    host, _, port = (target or "").rpartition(":")
    if not host:
        return target, 443
    try:
        return host, int(port)
    except ValueError:
        return target, 443


def probe(t: dict) -> dict:
    """Blocking: one name → {info…, via} or {error}. Traefik first; the public name only when
    Traefik cannot be reached at all (not when it answers with something we do not like)."""
    host, port = _split_target(config.CERT_CHECK_TARGET)
    errors = []
    attempts = [("traefik", host, port)]
    # The public fallback only for the MAIN domain (it comes from WEBTERM_PUBLIC_URL, set by the
    # operator). `cert-check.<forward domain>` and the Authentik name are not dialled directly:
    # the forward domain is editable in Settings, and dialling it would let a settings.manage
    # holder point the gateway's outbound connections anywhere (security review: SSRF).
    if t.get("role") == "main":
        attempts.append(("public", t["name"], t.get("public_port") or 443))
    for via, h, p in attempts:
        try:
            der = fetch_leaf(h, p, t["name"])
        except (OSError, ssl.SSLError, ValueError) as e:
            errors.append("%s: %s" % (via, (str(e) or e.__class__.__name__)[:160]))
            continue
        try:
            info = parse_leaf(der)
        except Exception as e:              # noqa: BLE001 — a cert we cannot parse is an error, not a crash
            return {"error": "unparsable certificate: %s" % str(e)[:160], "via": via}
        info["via"] = via
        return info
    return {"error": "; ".join(errors)[:400]}


# ── state ────────────────────────────────────────────────────────────────────────────────────
_status: dict = {"checked_at": None, "items": {}}
_lock = asyncio.Lock()
# A pool of its own, small and bounded: the probes never compete with (or exhaust) the default
# executor that file transfers and backups use, and at most MAX_NAMES sockets are ever open.
_pool = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_NAMES, thread_name_prefix="certmon")
_inflight: set = set()
_last_manual = 0.0


def manual_retry_after(now: Optional[float] = None) -> int:
    """Seconds until another manual check is allowed (0 = allowed now)."""
    now = time.time() if now is None else now
    left = MANUAL_MIN_INTERVAL - (now - _last_manual)
    return int(left) + 1 if left > 0 else 0


def mark_manual(now: Optional[float] = None) -> None:
    global _last_manual
    _last_manual = time.time() if now is None else now


async def _load_alerts() -> dict:
    if not db.connected():
        return {}
    row = await db.fetchone("SELECT value FROM app_settings WHERE key=?", K_ALERTS)
    try:
        d = json.loads(row["value"]) if row and row["value"] else {}
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


async def _save_alerts(d: dict) -> None:
    if not db.connected():
        return
    await db.execute("INSERT INTO app_settings(key, value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", K_ALERTS, json.dumps(d))


def _alert_fp(item: dict) -> str:
    # Traefik mints a NEW default certificate at every start: keyed on its fingerprint, each
    # restart would re-alert. "Default served" is one condition, whatever its bytes.
    return "traefik-default" if item.get("state") == "default" else item.get("fingerprint") or ""


async def _maybe_alert(item: dict, store: dict) -> bool:
    """One alert per threshold per certificate; returns whether something was sent."""
    name = item["name"]
    prev = store.get(name) if isinstance(store.get(name), dict) else None
    level = item["level"]
    if item.get("state") == "error":
        return False                        # unreachable ≠ expired: shown in the UI, not alerted
    if level == L_OK:
        if prev and int(prev.get("level") or 0) > L_OK:
            store.pop(name, None)
            email_alerts.notify_cert(item, recovered=True)
            await _audit("TLS certificate for %s is OK again (%s, %.0f days left)"
                         % (name, item.get("issuer", "?"), item.get("days_left") or 0))
            return True
        store.pop(name, None)
        return False
    fp = _alert_fp(item)
    if prev and prev.get("fp") == fp and int(prev.get("level") or 0) >= level:
        return False
    store[name] = {"fp": fp, "level": level, "ts": time.time()}
    email_alerts.notify_cert(item)
    await _audit("TLS certificate alert for %s: %s (%s days left, issuer %s)"
                 % (name, item["state"], item.get("days_left"), item.get("issuer", "?")))
    return True


async def _audit(text: str) -> None:
    await audit.record(time.time(), "system:certmon", "-", "CERT", "/api/certs", 200, text[:480])


async def check_all(forward_domain: str = "") -> dict:
    """Probe every target (in threads, bounded), update the status, alert. Serialised: a second
    caller waits for the running check and gets its result instead of starting another."""
    if _lock.locked():
        async with _lock:
            return status()
    async with _lock:
        ts = targets(forward_domain)
        now = time.time()
        results = []
        if ts:
            _inflight.difference_update({f for f in _inflight if f.done()})
            if _inflight:
                # probes of an earlier check are still stuck in their threads: do not pile more
                # on top (each is bounded by its own deadline, so this clears by itself)
                log.warning("certmon: %d earlier probe(s) still running — this check is skipped",
                            len(_inflight))
                return status()
            loop = asyncio.get_running_loop()
            futs = [loop.run_in_executor(_pool, probe, t) for t in ts]
            _inflight.update(futs)
            done, _pending = await asyncio.wait(futs, timeout=TOTAL_BUDGET)
            for t, fut in zip(ts, futs):
                if fut in done and not fut.cancelled() and fut.exception() is None:
                    results.append((t, fut.result()))
                else:
                    results.append((t, {"error": "timed out"}))
        old = _status["items"]
        items = {}
        for t, res in results:
            item = {"name": t["name"], "role": t["role"], "renew_domain": t["renew_domain"],
                    "checked_at": now, "error": ""}
            if "error" in res:
                # keep what we last knew about the certificate, flag the failed check
                prev = old.get(t["name"]) or {}
                for k in ("not_after", "issuer", "subject_cn", "sans", "fingerprint", "via",
                          "covers", "wildcard", "days_left"):
                    if k in prev:
                        item[k] = prev[k]
                item.update({"state": "error", "level": L_OK, "error": res["error"]})
                if "not_after" in item:
                    item["days_left"] = round((item["not_after"] - now) / 86400.0, 1)
            else:
                item.update({k: res[k] for k in ("not_after", "issuer", "subject_cn", "sans",
                                                 "fingerprint", "via")})
                item.update(evaluate(t["name"], res, now))
            items[t["name"]] = item
        _status["items"] = items
        _status["checked_at"] = now
        try:
            store = await _load_alerts()
            for n in [n for n in store if n not in items]:
                store.pop(n, None)          # a name we no longer check keeps no dedup state
            changed = False
            for item in items.values():
                changed |= await _maybe_alert(item, store)
            await _save_alerts(store)
            if changed:
                log.warning("certmon: TLS certificate alert state changed: %s",
                            ", ".join("%s=%s" % (i["name"], i["state"]) for i in items.values()))
        except Exception:                   # noqa: BLE001 — the status must still update
            log.exception("certmon: alerting failed")
        return status()


def status() -> dict:
    items = list(_status["items"].values())
    return {"checked_at": _status["checked_at"], "items": [dict(i) for i in items],
            "running": _lock.locked()}


def reset_for_tests() -> None:
    global _last_manual
    _status["checked_at"] = None
    _status["items"] = {}
    _last_manual = 0.0
    _inflight.clear()


async def loop(forward_domain_fn) -> None:
    """Background task: once shortly after boot, then daily."""
    await asyncio.sleep(STARTUP_DELAY)
    while True:
        try:
            await check_all(forward_domain_fn())
        except Exception:                   # noqa: BLE001 — the loop must survive anything
            log.exception("certmon: the certificate check failed")
        await asyncio.sleep(CHECK_INTERVAL)
