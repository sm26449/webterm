"""SCIM 2.0 provisioning (3.6.11) — RFC 7643/7644, the subset an IdP's SCIM client uses.

Goal: the IdP (Authentik's SCIM provider, set as a *backchannel* provider of the WebTerm
application) PUSHES user creation, deactivation, deletion and group membership to WebTerm at
once, instead of WebTerm learning about them at the person's next SSO sign-in.

Endpoints (`/scim/v2/…`): Users, Groups (GET list with `filter=<attr> eq "<v>"` + pagination, GET
one, POST, PUT, PATCH, DELETE), ServiceProviderConfig, ResourceTypes, Schemas. Bodies are
`application/scim+json` (plain JSON accepted), errors use the SCIM error schema.

Liberal in what we accept, strict in what we grant:

  * AUTH — a dedicated SCIM bearer token (NOT an automation token, NOT a cookie): created, rotated
    and revoked by an Owner only (Settings → Users & roles → SSO groups → SCIM), stored as a
    SHA-256 hash, shown once, compared in constant time. Failures are rate-limited per IP (10 per
    15 min → 15 min lockout), authenticated traffic is capped (1200 requests/min), bodies are
    capped (1 MiB). An Owner can switch provisioning off without revoking the token. SCIM needs
    SSO (OIDC) configured: a SCIM account can only ever sign in through SSO.
  * WHAT IT CAN DO — create / update / disable (`active:false`) / delete-as-disable accounts, and
    maintain group membership. It can never reach another route (the router-level guard refuses a
    SCIM principal anywhere outside `/scim/v2/`), never touch settings, roles, mappings or hosts,
    never manage an account that has a LOCAL PASSWORD (the break-glass accounts: invisible to
    SCIM, refused with 409 when the IdP tries to create one with the same identity), never disable
    the last permanent Owner (403, audited, critical alert), and never GRANT an Owner-level role:
    group membership re-runs the SSO group → role mapping exactly as a sign-in would (ssomap),
    except that Owner-equivalent roles are only kept, never added, by a push.
  * ACCOUNTS — a SCIM account is an SSO account: no local password (a random hash nobody knows),
    `local_password=0`. It is linked to the OIDC identity at its first SSO sign-in: by
    `externalId == sub` (Authentik's default — both are the user's hashed uid), otherwise the usual
    email adoption rule (email_verified). An existing SSO-only account with the same email (or whose
    `sub` equals the externalId) is ADOPTED by a create instead of duplicated.
  * DISABLE — `active:false` or DELETE disables (accounts.py: sessions, sockets, tokens, shares
    end at once; the row and its history stay). `active:true` re-enables a SCIM account; an Owner
    can re-enable any disabled account in the UI.
  * GROUPS — `displayName` must be EXACTLY what the OIDC `groups` claim carries (the mapping
    compares byte for byte). SCIM is authoritative only for the groups it pushes: a user's
    effective groups = (groups recorded at the last SSO sign-in that SCIM does not manage) ∪ (SCIM
    groups the user is a member of). Nested (parent) groups are not expanded: SCIM membership is
    direct membership.
"""
from __future__ import annotations

import asyncio
import hmac
import sqlite3
import json
import logging
import re
import time
import uuid
from collections import deque
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from . import accounts, audit, authz, config, db, email_alerts, security, ssomap

log = logging.getLogger("webterm")

PREFIX = "/scim/v2"
MEDIA = "application/scim+json"
S_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
S_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
S_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
S_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
S_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
S_SPC = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
S_RT = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
S_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"

TOKEN_PREFIX = "wtscim_"            # never `wt_` (automation tokens): the two cannot be confused
BODY_MAX = 1024 * 1024
OPS_MAX = 1000
MEMBERS_MAX = 50000
PAGE_MAX = 200
STR_MAX = 256
ACTOR = "scim"
DOC = "https://github.com/smaldaianu/webterm/blob/main/docs/SSO.md#scim-provisioning-3611"

_FAIL_MAX = 10
_FAIL_WINDOW = 900.0
_LOCKOUT = 900.0
_FAIL_TRACK_MAX = 10000
_RATE_MAX = 1200
_RATE_WINDOW = 60.0
_fails: dict[str, list] = {}
_locked: dict[str, float] = {}
_hits: deque = deque()
_lock = asyncio.Lock()               # serialises SCIM writes (an IdP may push in parallel)
_seen_at = 0.0                       # last authenticated request (memory, exact)
_touch_at = 0.0                      # last time it was written to app_settings
_err_at = 0.0
_warn_at = 0.0


class ScimError(HTTPException):
    """→ a SCIM error body (RFC 7644 §3.12): {schemas, status, scimType?, detail}."""

    def __init__(self, status: int, detail: str, scim_type: str = "", headers=None):
        super().__init__(status_code=status, detail=detail, headers=headers)
        self.scim_type = scim_type


class _InactiveCreate(ScimError):
    """POST of a user the IdP itself marks inactive, matching no WebTerm account: nothing is
    created (re-review 3.6.11). Quiet: audited once an hour per email, no alert."""

    def __init__(self, email: str):
        super().__init__(400, "WebTerm does not create an account for a user who is inactive in "
                              "the identity provider (active=false); it is created when the user "
                              "is activated", "invalidValue")
        self.email = email


def error_response(exc: ScimError) -> JSONResponse:
    body = {"schemas": [S_ERROR], "status": str(exc.status_code), "detail": exc.detail}
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    return JSONResponse(body, status_code=exc.status_code, headers=exc.headers, media_type=MEDIA)


def _json(data, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, media_type=MEDIA)


# ── settings (app_settings) ──────────────────────────────────────────────────────────────────
_KEYS = ("scim_token_hash", "scim_token_created", "scim_token_created_by", "scim_enabled",
         "scim_last_request", "scim_last_error")


async def _settings() -> dict:
    rows = await db.fetchall("SELECT key, value FROM app_settings WHERE key IN (%s)"
                             % ",".join("?" * len(_KEYS)), *_KEYS)
    return {r["key"]: r["value"] for r in rows}


async def _put(key: str, value: Optional[str]) -> None:
    if value is None:
        await db.execute("DELETE FROM app_settings WHERE key=?", key)
    else:
        await db.execute("INSERT INTO app_settings(key, value) VALUES(?,?) ON CONFLICT(key)"
                         " DO UPDATE SET value=excluded.value", key, value)


def new_token() -> str:
    return TOKEN_PREFIX + security.new_token()


async def set_token(raw: str, by: str) -> None:
    await _put("scim_token_hash", security.sha256_hex(raw))
    await _put("scim_token_created", "%.3f" % time.time())
    await _put("scim_token_created_by", by[:200])
    await _put("scim_enabled", "1")
    await _put("scim_last_error", None)


async def revoke_token() -> None:
    for k in ("scim_token_hash", "scim_token_created", "scim_token_created_by"):
        await _put(k, None)


async def set_enabled(on: bool) -> None:
    await _put("scim_enabled", "1" if on else "0")


async def status_json() -> dict:
    st = await _settings()

    def num(k):
        try:
            return float(st[k]) if st.get(k) else None
        except ValueError:
            return None
    try:
        last_err = json.loads(st.get("scim_last_error") or "null")
    except ValueError:
        last_err = None
    counts = await db.fetchone(
        "SELECT SUM(CASE WHEN COALESCE(scim_managed,0)=1 THEN 1 ELSE 0 END) AS managed,"
        " SUM(CASE WHEN COALESCE(scim_managed,0)=1 AND COALESCE(disabled,0)=1 THEN 1 ELSE 0 END)"
        " AS disabled FROM users")
    ngroups = (await db.fetchone("SELECT COUNT(*) AS c FROM scim_groups"))["c"]
    return {"configured": bool(st.get("scim_token_hash")),
            "enabled": bool(st.get("scim_token_hash")) and st.get("scim_enabled") == "1",
            "oidc_enabled": config.OIDC_ENABLED,
            "url": config.PUBLIC_URL.rstrip("/") + PREFIX,
            "token_created": num("scim_token_created"),
            "token_created_by": st.get("scim_token_created_by") or None,
            "last_request": max(filter(None, [num("scim_last_request"), _seen_at or None]),
                                default=None),
            "last_error": last_err,
            "managed_accounts": int(counts["managed"] or 0),
            "disabled_accounts": int(counts["disabled"] or 0),
            "groups": ngroups}


async def _note_error(status: int, detail: str, force: bool = False) -> None:
    """The last error, for the Owner's status panel (at most one write every 5 s)."""
    global _err_at
    now = time.time()
    if not force and now - _err_at < 5:
        return
    _err_at = now
    try:
        await _put("scim_last_error", json.dumps({"ts": now, "status": status,
                                                  "detail": detail[:300]}))
    except Exception:                       # noqa: BLE001 — status only
        log.exception("SCIM: could not record the last error")


async def _touch(now: float) -> None:
    """The last request, for the status panel: exact in memory, persisted at most every 30 s."""
    global _seen_at, _touch_at
    _seen_at = now
    if now - _touch_at < 30:
        return
    _touch_at = now
    await _put("scim_last_request", "%.3f" % now)


# ── authentication ───────────────────────────────────────────────────────────────────────────
def _prune(now: float) -> None:
    for ip, t in list(_locked.items()):
        if t <= now:
            _locked.pop(ip, None)
    if len(_fails) > _FAIL_TRACK_MAX:
        for ip in sorted(_fails, key=lambda k: _fails[k][-1] if _fails[k] else 0)[
                :len(_fails) - _FAIL_TRACK_MAX // 2]:
            _fails.pop(ip, None)


def _note_fail(ip: str, now: float) -> bool:
    """→ True when this failure trips the lockout."""
    lst = [t for t in _fails.get(ip, []) if now - t < _FAIL_WINDOW]
    lst.append(now)
    _fails[ip] = lst
    if len(lst) >= _FAIL_MAX:
        _locked[ip] = now + _LOCKOUT
        _fails.pop(ip, None)
        return True
    return False


def _rate_ok(now: float) -> bool:
    while _hits and now - _hits[0] > _RATE_WINDOW:
        _hits.popleft()
    if len(_hits) >= _RATE_MAX:
        return False
    _hits.append(now)
    return True


_LOCKOUT_AUDIT_MAX = 20                 # lockout rows per hour, all IPs together
_lockout_rows: deque = deque()
_lockout_suppressed = 0


async def _audit_lockout(now: float, ip: str, path: str) -> None:
    """A lockout is audited — but a spray from many addresses must not flood the audit log
    (review 3.6.11): at most 20 rows an hour in total; the ones held back are counted in the
    next row written. The actor is `unauthenticated` (nobody proved to be the IdP)."""
    global _lockout_suppressed
    while _lockout_rows and now - _lockout_rows[0] > 3600:
        _lockout_rows.popleft()
    if len(_lockout_rows) >= _LOCKOUT_AUDIT_MAX:
        _lockout_suppressed += 1
        return
    _lockout_rows.append(now)
    extra = (" (%d earlier lockout(s) not recorded: more than %d an hour)"
             % (_lockout_suppressed, _LOCKOUT_AUDIT_MAX)) if _lockout_suppressed else ""
    _lockout_suppressed = 0
    await audit.record(now, "unauthenticated", ip, "SCIM", path, 429,
                       ("SCIM: %d failed authentications from %s — locked out for 15 min%s"
                        % (_FAIL_MAX, ip, extra))[:480], via="scim")


def reset_limits() -> None:
    """Tests only."""
    global _seen_at, _touch_at, _lockout_suppressed
    _seen_at = _touch_at = 0.0
    _fails.clear()
    _locked.clear()
    _hits.clear()
    _lockout_rows.clear()
    _lockout_suppressed = 0
    _alerted.clear()


async def require_scim(request: Request) -> dict:
    """THE SCIM principal. Only the SCIM bearer token; cookies are ignored (a browser session can
    never act through SCIM), automation tokens do not match. Marked `__scim__` so the router guard
    (`authz.declared`) accepts it — and only under /scim/v2/."""
    global _warn_at
    ip = security.client_ip(request)
    now = time.time()
    _prune(now)
    until = _locked.get(ip)
    if until and until > now:
        raise ScimError(429, "too many failed authentication attempts; retry later",
                        headers={"Retry-After": str(int(until - now) + 1)})
    auth = request.headers.get("authorization") or ""
    raw = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
    st = await _settings()
    want = st.get("scim_token_hash") or ""
    good = (bool(raw) and bool(want) and len(raw) <= 512
            and hmac.compare_digest(security.sha256_hex(raw), want))
    if not good:
        tripped = _note_fail(ip, now)
        if now - _warn_at > 60 or tripped:
            _warn_at = now
            log.warning("SCIM: authentication failed from %s (%s)%s", ip,
                        "no token configured" if not want else
                        "no bearer token" if not raw else "wrong token",
                        " — locked out for 15 min" if tripped else "")
        if want:
            await _note_error(401, "authentication failed from %s (missing or wrong SCIM token)"
                              % ip)
        if tripped:
            await _audit_lockout(now, ip, request.url.path[:200])
        raise ScimError(401, "missing or invalid SCIM bearer token",
                        headers={"WWW-Authenticate": 'Bearer realm="WebTerm SCIM"'})
    if st.get("scim_enabled") != "1":
        await _note_error(403, "a request arrived while SCIM provisioning is turned off")
        raise ScimError(403, "SCIM provisioning is turned off in WebTerm "
                             "(Settings → Users & roles → SSO groups → SCIM)")
    if not config.OIDC_ENABLED:
        await _note_error(403, "SSO (OIDC) is not configured")
        raise ScimError(403, "SSO (OIDC) is not configured in WebTerm: an account created by "
                             "SCIM could never sign in")
    if not _rate_ok(now):
        raise ScimError(429, "too many SCIM requests; retry later", headers={"Retry-After": "30"})
    _fails.pop(ip, None)
    await _touch(now)
    return {"actor": ACTOR, "ip": ip}


require_scim.__scim__ = True

router = APIRouter(prefix=PREFIX, dependencies=[Depends(authz.declared)])


# ── body / value parsing ─────────────────────────────────────────────────────────────────────
async def _body(request: Request) -> dict:
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > BODY_MAX:
                raise ScimError(413, "the request body is larger than %d bytes" % BODY_MAX)
        except ValueError:
            pass
    total, chunks = 0, []
    async for chunk in request.stream():
        total += len(chunk)
        if total > BODY_MAX:
            raise ScimError(413, "the request body is larger than %d bytes" % BODY_MAX)
        chunks.append(chunk)
    try:
        data = json.loads(b"".join(chunks) or b"{}")
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ScimError(400, "the body is not valid JSON", "invalidSyntax")
    if not isinstance(data, dict):
        raise ScimError(400, "the body must be a JSON object", "invalidSyntax")
    return data


def _lower(d: dict) -> dict:
    """Attribute names are case-insensitive (RFC 7643 §2.1)."""
    return {str(k).lower(): v for k, v in d.items()} if isinstance(d, dict) else {}


def _lower_core(d: dict, schema: str) -> dict:
    """`_lower`, and a fully qualified core attribute name (`urn:…:core:2.0:User:active`) counts
    as the attribute itself (review 3.6.11)."""
    out = {}
    for k, v in (d.items() if isinstance(d, dict) else ()):
        out.setdefault(_strip_schema(str(k), schema).lower(), v)
    return out


def _text(v, what: str, required: bool = False) -> Optional[str]:
    if v is None or v == "":
        if required:
            raise ScimError(400, "%s is required" % what, "invalidValue")
        return None
    if not isinstance(v, str) or len(v) > STR_MAX or not v.isprintable():
        raise ScimError(400, "%s must be printable text of at most %d characters" % (what, STR_MAX),
                        "invalidValue")
    return v


def _bool(v, what: str) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"          # Entra ID sends "True"/"False"
    raise ScimError(400, "%s must be a boolean" % what, "invalidValue")


def _email_of(v) -> Optional[str]:
    """`emails`: the primary one, else the first; a bare string is accepted."""
    if v is None:
        return None
    if isinstance(v, str):
        cands = [v]
    elif isinstance(v, list):
        items = [_lower(x) for x in v if isinstance(x, dict)]
        items.sort(key=lambda x: not _truthy(x.get("primary")))
        cands = [x.get("value") for x in items] + [x for x in v if isinstance(x, str)]
    else:
        raise ScimError(400, "emails must be a list", "invalidValue")
    for c in cands:
        if isinstance(c, str):
            e = c.strip().lower()
            if security.valid_email(e):
                return e
    raise ScimError(400, "no valid email address in emails", "invalidValue")


def _truthy(v) -> bool:
    return v is True or (isinstance(v, str) and v.lower() == "true")


def _user_fields(body: dict) -> dict:
    """The attributes WebTerm keeps, from a User body (POST / PUT: a full resource). Other
    attributes are ignored there; a PATCH path is strict (`_user_path`)."""
    b = _lower_core(body, S_USER)
    out = {}
    if "username" in b:
        out["userName"] = _text(b["username"], "userName")
    if "externalid" in b:
        out["externalId"] = _text(b["externalid"], "externalId")
    if "displayname" in b:
        out["displayName"] = _text(b["displayname"], "displayName")
    elif isinstance(b.get("name"), dict):
        f = _lower(b["name"]).get("formatted")
        if isinstance(f, str) and f.strip():
            out["displayName"] = _text(f.strip()[:STR_MAX], "name.formatted")
    if "emails" in b:
        out["email"] = _email_of(b["emails"])
    if "active" in b:
        out["active"] = _bool(b["active"], "active")
    return out


# ── filter + pagination ──────────────────────────────────────────────────────────────────────
_FILTER_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9._:-]*)\s+(eq)\s+"((?:[^"\\]|\\.)*)"\s*$', re.I)


def _filter(raw: Optional[str], allowed: dict) -> Optional[tuple]:
    """`<attr> eq "<value>"` only (what IdPs use to find an existing resource). → (column,
    value, case_insensitive) or None. Anything else → 400 invalidFilter."""
    if raw is None or raw.strip() == "":
        return None
    if len(raw) > 1024:
        raise ScimError(400, "the filter is too long", "invalidFilter")
    m = _FILTER_RE.match(raw)
    if not m:
        raise ScimError(400, 'only `<attribute> eq "<value>"` filters are supported',
                        "invalidFilter")
    attr = m.group(1).lower()
    if attr not in allowed:
        raise ScimError(400, "filtering on %s is not supported" % m.group(1)[:60], "invalidFilter")
    value = re.sub(r'\\(.)', r'\1', m.group(3))
    col, ci = allowed[attr]
    return col, value, ci


def _page(request: Request) -> tuple[int, int]:
    q = request.query_params
    try:
        start = min(10 ** 9, max(1, int(q.get("startIndex") or 1)))
        count = int(q.get("count") or 100)
    except ValueError:
        raise ScimError(400, "startIndex and count must be integers", "invalidValue")
    return start, max(0, min(PAGE_MAX, count))


def _list(resources: list, total: int, start: int) -> dict:
    return {"schemas": [S_LIST], "totalResults": total, "startIndex": start,
            "itemsPerPage": len(resources), "Resources": resources}


def _iso(ts) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts or 0))


def _loc(kind: str, rid: str) -> str:
    return "%s%s/%s/%s" % (config.PUBLIC_URL.rstrip("/"), PREFIX, kind, rid)


# ── Users ────────────────────────────────────────────────────────────────────────────────────
_USER_FILTERS = {"username": ("scim_user_name", True), "externalid": ("scim_external_id", False),
                 "id": ("scim_id", False), "emails": ("email", True),
                 "emails.value": ("email", True)}
_USER_COLS = ("id, email, created, disabled, scim_id, scim_external_id, scim_user_name,"
              " scim_display_name, scim_updated, sso_subject, COALESCE(scim_created, 0) AS"
              " scim_created")


async def _user_json(u) -> dict:
    groups = await db.fetchall(
        "SELECT g.id, g.display_name FROM scim_group_members m JOIN scim_groups g ON g.id=m.group_id"
        " WHERE m.user_id=? ORDER BY g.display_name", u["id"])
    out = {"schemas": [S_USER], "id": u["scim_id"], "userName": u["scim_user_name"] or u["email"],
           "active": not u["disabled"],
           "emails": [{"value": u["email"], "primary": True, "type": "work"}],
           "groups": [{"value": g["id"], "display": g["display_name"],
                       "$ref": _loc("Groups", g["id"])} for g in groups],
           "meta": {"resourceType": "User", "created": _iso(u["created"]),
                    "lastModified": _iso(u["scim_updated"] or u["created"]),
                    "location": _loc("Users", u["scim_id"])}}
    if u["scim_external_id"]:
        out["externalId"] = u["scim_external_id"]
    if u["scim_display_name"]:
        out["displayName"] = u["scim_display_name"]
        out["name"] = {"formatted": u["scim_display_name"]}
    return out


async def _user(scim_id: str):
    u = await db.fetchone("SELECT " + _USER_COLS + " FROM users WHERE scim_id=?"
                          " AND COALESCE(scim_managed, 0)=1 AND COALESCE(local_password, 1)=0",
                          scim_id)
    if u is None:
        raise ScimError(404, "no such user")
    return u


@router.get("/Users")
async def list_users(request: Request, _p=Depends(require_scim)):
    f = _filter(request.query_params.get("filter"), _USER_FILTERS)
    start, count = _page(request)
    where = (" WHERE scim_id IS NOT NULL AND COALESCE(scim_managed, 0)=1"
             " AND COALESCE(local_password, 1)=0")
    args: list = []
    if f:
        col, value, ci = f
        where += (" AND lower(%s)=lower(?)" if ci else " AND %s=?") % col
        args.append(value)
    total = (await db.fetchone("SELECT COUNT(*) AS c FROM users" + where, *args))["c"]
    rows = await db.fetchall("SELECT " + _USER_COLS + " FROM users" + where
                             + " ORDER BY id LIMIT ? OFFSET ?", *args, count, start - 1)
    return _json(_list([await _user_json(u) for u in rows], total, start))


@router.get("/Users/{scim_id}")
async def get_user(scim_id: str, _p=Depends(require_scim)):
    return _json(await _user_json(await _user(scim_id)))


async def _audit(p: dict, method: str, path: str, status: int, text: str,
                 actor_id: Optional[int] = None) -> None:
    await audit.record(time.time(), ACTOR, p["ip"], method, path[:200], status, text[:480],
                       actor_id=actor_id, via="scim")


async def _refuse(p: dict, method: str, path: str, exc: ScimError) -> None:
    """A refused write: audited (it is the IdP asking for something), shown in the status panel."""
    await _audit(p, method, path, exc.status_code, "SCIM refused: %s" % exc.detail)
    await _note_error(exc.status_code, "%s %s: %s" % (method, path, exc.detail), force=True)


_alerted: dict[tuple, float] = {}
_ALERTED_MAX = 1000


def _first_this_hour(*key) -> bool:
    """True once an hour per `key` (re-review 3.6.11: the IdP repeats a refused request at every
    sync — one alert per account and kind an hour, not one per sync). Bounded: past
    `_ALERTED_MAX` keys the table starts over (worst case: one extra alert)."""
    now = time.time()
    if now - _alerted.get(key, 0) < 3600:
        return False
    if len(_alerted) >= _ALERTED_MAX:
        _alerted.clear()
    _alerted[key] = now
    return True


async def _alert_local_refused(email: str, ip: str) -> None:
    """The IdP asked for an account that has a LOCAL password (a break-glass account): refused —
    and that is worth a critical alert (review 3.6.11: someone may be aiming SCIM at it). Once an
    hour per account: the IdP retries on every sync."""
    if not _first_this_hour("local", email):
        return
    log.error("SCIM: refused to manage %s — it has a local password (break-glass)", email)
    email_alerts.notify_security_change(
        "the identity provider tried to take over %s, an account with a local password "
        "(break-glass); refused" % email, ip, ACTOR, fleet=True, severity="critical",
        what_key="scim_local_refused", what_params={"account": email})


async def _email_free(email: str, uid: Optional[int]) -> None:
    row = await db.fetchone("SELECT id FROM users WHERE email=?", email)
    if row is not None and row["id"] != uid:
        raise ScimError(409, "another WebTerm account already uses %s" % email, "uniqueness")


async def _ext_free(ext: Optional[str], uid: Optional[int]) -> None:
    if not ext:
        return
    row = await db.fetchone("SELECT id FROM users WHERE scim_external_id=?", ext)
    if row is not None and row["id"] != uid:
        raise ScimError(409, "another WebTerm account already has this externalId", "uniqueness")


async def _guard_identity(u, f: dict) -> None:
    """Security review 3.6.11 — the SCIM token must not be able to re-point an identity:
      * `externalId` is write-once (it is what links the account to the OIDC `sub`);
      * an account not yet linked to SSO (`sso_subject` NULL) that holds a role given BY HAND
        cannot have its email changed by SCIM: the next SSO sign-in with that email would adopt
        it, roles included. Once the person has signed in (linked), the email may follow the IdP."""
    ext = f.get("externalId")
    if ext and u["scim_external_id"] and ext != u["scim_external_id"]:
        raise ScimError(409, "externalId cannot change once set", "mutability")
    if f.get("email") and f["email"] != u["email"]:
        # review 3.6.11: SCIM changes the email only of accounts it CREATED — never of an
        # existing account it adopted, and never of one holding an Owner-level role given in
        # WebTerm (the address is the recovery and sign-in channel)
        if not u["scim_created"]:
            raise ScimError(409, "this account existed before SCIM took it over: its email can "
                                 "only be changed in WebTerm", "mutability")
        if await authz.owner_level_given_in_webterm(u["id"]):
            raise ScimError(409, "this account holds an Owner-level role given in WebTerm: its "
                                 "email cannot be changed by SCIM", "mutability")
    if f.get("email") and f["email"] != u["email"] and not u["sso_subject"]:
        manual = await db.fetchone("SELECT 1 FROM role_bindings WHERE user_id=? AND source<>'sso'",
                                   u["id"])
        if manual:
            raise ScimError(409, "the email of an account that has not signed in with SSO yet and "
                                 "holds roles given by hand cannot be changed by SCIM",
                            "mutability")


_OWNER_LEVEL_DETAIL = ("this account holds an Owner-level role given in WebTerm (not by an SSO "
                       "group): only an Owner can %s it, in WebTerm (Settings → Users & roles)")


async def _owner_level_refused(uid: int, what: str, ip: str) -> ScimError:
    """The refusal for an account holding an Owner-level role given in WebTerm. Critical alert
    once an hour per (account, action) — re-review 3.6.11: the IdP retries at every sync."""
    row = await db.fetchone("SELECT email FROM users WHERE id=?", uid)
    email = row["email"] if row else "#%d" % uid
    log.error("SCIM: refused to %s %s — it holds an Owner-level role given in WebTerm", what, email)
    if _first_this_hour("owner", uid, what):
        email_alerts.notify_security_change(
            "the identity provider tried to %s %s, which holds an Owner-level role given in "
            "WebTerm; refused" % (what, email), ip, ACTOR, fleet=True, severity="critical",
            what_key="scim_owner_refused", what_params={"account": email, "action": what})
    return ScimError(403, _OWNER_LEVEL_DETAIL % what)


async def _active_precheck(uid: int, active, ip: str = "-") -> None:
    """Refuse BEFORE any other write (atomicity) — accounts.disable / enable re-check under the
    bindings lock:
      * active:false on the last permanent Owner;
      * active:false or true on an account holding an Owner-level role given in WebTerm (review
        3.6.11: §A.5 "only an Owner can delete an Owner" — and re-enabling it would hand back an
        Owner role without the Owner gate the UI's re-enable has);
      * active:true on an account WebTerm itself disabled (anything but SCIM)."""
    if active is None:
        return
    row = await db.fetchone("SELECT email, COALESCE(disabled, 0) AS d, disabled_by FROM users"
                            " WHERE id=?", uid)
    if row is None:
        return
    if active is False and not row["d"]:
        if await authz.owner_level_given_in_webterm(uid):
            raise await _owner_level_refused(uid, "disable", ip)
        if await accounts.is_permanent_owner(uid) \
                and await authz.owner_count(exclude_user=uid) < 1:
            await accounts.report_last_owner_refused(row["email"], actor=ACTOR, ip=ip,
                                                     reason="SCIM active=false")
            raise ScimError(403, "this account is the last permanent Owner of WebTerm and cannot "
                                 "be disabled; make another account a permanent Owner first")
    if active is True and row["d"]:
        await _enable_check(uid, ip)


async def _enable_check(uid: int, ip: str) -> None:
    """May SCIM re-enable `uid`? (also run under the bindings lock, by accounts.enable)"""
    row = await db.fetchone("SELECT COALESCE(disabled, 0) AS d, disabled_by FROM users WHERE id=?",
                            uid)
    if row is None or not row["d"]:
        return
    if (row["disabled_by"] or "") not in ("scim", "scim-delete"):
        raise ScimError(403, "this account was disabled in WebTerm, not by the identity provider: "
                             "only an Owner can re-enable it (Settings → Users & roles)")
    if await authz.owner_level_given_in_webterm(uid):
        raise await _owner_level_refused(uid, "re-enable", ip)


async def _set_active(p: dict, uid: int, active: bool, path: str) -> None:
    if active:
        async def recheck():
            await _enable_check(uid, p["ip"])
        await accounts.enable(uid, actor=ACTOR, ip=p["ip"], how="identity provider, SCIM",
                              path=path, recheck=recheck)
        return
    try:
        await accounts.disable(uid, by="scim", actor=ACTOR, ip=p["ip"],
                               reason="SCIM active=false")
    except accounts.LastOwner:
        raise ScimError(403, "this account is the last permanent Owner of WebTerm and cannot be "
                             "disabled; make another account a permanent Owner first")
    except accounts.OwnerLevel:
        raise await _owner_level_refused(uid, "disable", p["ip"])


async def _guard_identity_or_drop(u, f: dict) -> Optional[ScimError]:
    """`_guard_identity`, except that an identity refusal never blocks `active:false`
    (re-review 3.6.11: Authentik sends the whole user — a renamed email together with
    active:false — so a 409 there would leave the person enabled until a DELETE). When the request
    deactivates, the identity attributes (email, externalId) are DROPPED from `f` and the refusal
    is returned for `_identity_dropped`; everything else still applies. When it does not
    deactivate, the refusal stands (409): it would keep the account working under a re-pointed
    identity."""
    try:
        await _guard_identity(u, f)
        return None
    except ScimError as e:
        if f.get("active") is not False:
            raise
        for k in ("email", "externalId"):
            f.pop(k, None)
        return e


async def _identity_dropped(p: dict, u, e: ScimError, method: str, path: str) -> None:
    """Audit (every time — it is the IdP asking) + warning alert (once an hour per account)."""
    await _audit(p, method, path, 200, "SCIM deactivating %s: ignored the identity change WebTerm "
                 "refuses (%s)" % (u["email"], e.detail), actor_id=u["id"])
    log.warning("SCIM: deactivating %s, ignored a refused identity change: %s", u["email"], e.detail)
    if _first_this_hour("identity", u["id"]):
        email_alerts.notify_security_change(
            "the identity provider deactivated %s and asked for an identity change WebTerm refuses "
            "(%s); the account was deactivated, the change ignored" % (u["email"], e.detail),
            p["ip"], ACTOR, fleet=True, what_key="scim_identity_ignored",
            what_params={"account": u["email"]})


async def _apply_user(p: dict, u, f: dict, path: str, method: str) -> bool:
    """Write the changed attributes of SCIM account `u` (a row). → True if anything changed."""
    f = dict(f)
    dropped = await _guard_identity_or_drop(u, f)
    await _active_precheck(u["id"], f.get("active"), p["ip"])
    if dropped is not None:
        await _identity_dropped(p, u, dropped, method, path)
    sets, args, what = [], [], []
    if f.get("email") and f["email"] != u["email"]:
        await _email_free(f["email"], u["id"])
        sets.append("email=?")
        args.append(f["email"])
        what.append("email %s → %s" % (u["email"], f["email"]))
    for key, col in (("userName", "scim_user_name"), ("displayName", "scim_display_name"),
                     ("externalId", "scim_external_id")):
        if key in f and (f[key] or None) != (u[col] or None):
            if key == "externalId":
                await _ext_free(f[key], u["id"])
            sets.append("%s=?" % col)
            args.append(f[key])
            what.append(key)
    if sets:
        await db.execute("UPDATE users SET " + ", ".join(sets) + ", scim_updated=? WHERE id=?",
                         *args, time.time(), u["id"])
        await _audit(p, method, path, 200, "SCIM updated %s: %s" % (u["email"], ", ".join(what)),
                     actor_id=u["id"])
    changed = bool(sets)
    if "active" in f and bool(f["active"]) == bool(u["disabled"]):
        await _set_active(p, u["id"], f["active"], path)
        changed = True
    return changed


@router.post("/Users")
async def create_user(request: Request, p=Depends(require_scim)):
    body = await _body(request)
    path = PREFIX + "/Users"
    try:
        async with _lock:
            f = _user_fields(body)
            user_name = f.get("userName") or _text(None, "userName", required=True)
            email = f.get("email")
            if not email:
                if user_name and security.valid_email(user_name.strip().lower()):
                    email = user_name.strip().lower()
                else:
                    raise ScimError(400, "a WebTerm account needs an email address (emails)",
                                    "invalidValue")
            f["email"] = email
            ext = f.get("externalId")
            cands = {}
            if ext:
                for sql in ("SELECT * FROM users WHERE scim_external_id=?",
                            "SELECT * FROM users WHERE sso_subject=?"):
                    r = await db.fetchone(sql, ext)
                    if r is not None:
                        cands[r["id"]] = r
            r = await db.fetchone("SELECT * FROM users WHERE email=?", email)
            if r is not None:
                cands[r["id"]] = r
            if len(cands) > 1:
                raise ScimError(409, "the externalId and the email belong to different WebTerm "
                                     "accounts", "uniqueness")
            target = next(iter(cands.values()), None)
            if target is not None:
                if await ssomap.has_local_password(target["id"]):
                    await _alert_local_refused(target["email"], p["ip"])
                    raise ScimError(409, "a WebTerm account with this identity has a local password "
                                         "(a break-glass account); SCIM never manages it",
                                    "uniqueness")
                if target["scim_id"]:
                    raise ScimError(409, "this user is already provisioned", "uniqueness")
                # review 3.6.11 — taking over an account SCIM did not create:
                #  * only with ITS email (an externalId equal to its OIDC `sub` is not enough: the
                #    token holder would otherwise pick any SSO account and re-point its email);
                #  * never one holding an Owner-level role given in WebTerm (§A.5: only an Owner
                #    disables or deletes an Owner — SCIM could do both once it manages it).
                if not target["scim_created"] and target["email"] != email:
                    raise ScimError(409, "an existing WebTerm account matches this externalId but "
                                         "has a different email; SCIM takes over an existing "
                                         "account only when its email matches too", "uniqueness")
                if await authz.owner_level_given_in_webterm(target["id"]):
                    await _owner_level_refused(target["id"], "take over", p["ip"])
                    raise ScimError(409, "the existing WebTerm account %s holds an Owner-level role "
                                         "given in WebTerm; SCIM never takes it over (an Owner can "
                                         "give that role through an SSO group instead)" % email,
                                    "uniqueness")
                dropped = await _guard_identity_or_drop(target, f)
                if dropped is not None:     # deactivating: adopt under the identity it has
                    email = f["email"] = target["email"]
                    ext = None
                await _active_precheck(target["id"], f.get("active"), p["ip"])
                sid = str(uuid.uuid4())
                await _email_free(email, target["id"])
                await _ext_free(ext, target["id"])
                # local_password re-checked IN the write: a password set meanwhile wins
                done = await db.execute_returning(
                    "UPDATE users SET scim_managed=1, scim_id=?,"
                    " scim_external_id=COALESCE(?, scim_external_id),"
                    " scim_user_name=?, scim_display_name=?, email=?, scim_updated=? WHERE id=?"
                    " AND COALESCE(local_password, 1)=0 RETURNING id",
                    sid, ext, user_name, f.get("displayName"), email, time.time(), target["id"])
                if done is None:
                    raise ScimError(409, "a WebTerm account with this identity has a local "
                                         "password (a break-glass account); SCIM never manages it",
                                    "uniqueness")
                uid = target["id"]
                await _audit(p, "POST", path, 201,
                             "SCIM took over the existing SSO account %s%s" % (
                                 email, "" if target["email"] == email
                                 else " (was %s)" % target["email"]), actor_id=uid)
                log.warning("SCIM: the existing SSO account %s is now managed by the identity "
                            "provider", email)
                if not target["scim_created"]:
                    email_alerts.notify_security_change(
                        "the identity provider took over the existing WebTerm account %s (SCIM): "
                        "it can now disable it and its groups give its roles" % email,
                        p["ip"], ACTOR, fleet=True, severity="critical",
                        what_key="scim_account_adopted", what_params={"account": email})
                if dropped is not None:
                    await _identity_dropped(p, target, dropped, "POST", path)
            elif f.get("active") is False:
                # re-review 3.6.11: a person inactive in the IdP gets NO new account (fail closed;
                # an IdP that pushes its inactive users would otherwise fill WebTerm with disabled
                # accounts and "new account" alerts). 400, audited once an hour per email
                raise _InactiveCreate(email)
            else:
                sid = str(uuid.uuid4())
                locked = await security.hash_password_async(security.new_token())
                now = time.time()
                try:
                    await db.execute(
                        "INSERT INTO users(id, email, password_hash, created, local_password,"
                        " scim_managed, scim_created, scim_id, scim_external_id, scim_user_name,"
                        " scim_display_name, scim_updated) VALUES(" + db.NEXT_USER_ID_SQL
                        + ",?,?,?,0,1,1,?,?,?,?,?)",
                        email, locked, now, sid, ext, user_name, f.get("displayName"), now)
                except sqlite3.IntegrityError:
                    # an SSO sign-in created the same email at this very moment
                    raise ScimError(409, "this user was created meanwhile", "uniqueness")
                uid = (await db.fetchone("SELECT id FROM users WHERE scim_id=?", sid))["id"]
                await _audit(p, "POST", path, 201, "SCIM created the account %s (SSO sign-in only, "
                             "no role until a mapped group gives one)" % email, actor_id=uid)
                log.warning("SCIM: account %s created by the identity provider", email)
                email_alerts.notify_security_change(
                    "a new WebTerm account was created by the identity provider (%s)" % email,
                    p["ip"], ACTOR, fleet=True, what_key="scim_account_created",
                    what_params={"account": email})
            if f.get("active") is False:
                await _set_active(p, uid, False, path)
            elif f.get("active") is True:
                await _set_active(p, uid, True, path)
            u = await db.fetchone("SELECT " + _USER_COLS + " FROM users WHERE id=?", uid)
    except _InactiveCreate as e:
        if _first_this_hour("inactive", e.email):
            await _audit(p, "POST", path, 400, "SCIM refused: %s (%s)" % (e.detail, e.email))
        await _note_error(400, "POST %s: %s" % (path, e.detail))
        raise
    except ScimError as e:
        await _refuse(p, "POST", path, e)
        raise
    return _json(await _user_json(u), 201)


async def _update(request: Request, p: dict, scim_id: str, method: str, f: dict):
    path = PREFIX + "/Users/" + scim_id
    try:
        async with _lock:
            u = await _user(scim_id)
            await _apply_user(p, u, f, path, method)
            u = await _user(scim_id)
    except ScimError as e:
        if e.status_code != 404:
            await _refuse(p, method, path, e)
        raise
    return _json(await _user_json(u))


@router.put("/Users/{scim_id}")
async def put_user(scim_id: str, request: Request, p=Depends(require_scim)):
    body = await _body(request)
    try:
        f = _user_fields(body)
    except ScimError as e:
        await _refuse(p, "PUT", PREFIX + "/Users/" + scim_id, e)
        raise
    # a partial PUT must not blank an account: an absent email / userName / externalId keeps what
    # we have, and an absent `active` changes nothing — re-enabling is a grant, so it must be said
    return await _update(request, p, scim_id, "PUT", f)


_EMAIL_PATH = re.compile(r'^emails(\[[^\]]*\])?(\.value)?$', re.I)
_EXT_PREFIX = "urn:ietf:params:scim:schemas:extension:"
_PATH_BASE = re.compile(r'^([a-z][a-z0-9_$-]*)(\[[^\]]*\])?(\.[a-z][a-z0-9_$-]*)?$', re.I)
# standard User attributes WebTerm does not keep: accepted and ignored (an IdP sends them)
_USER_IGNORED = {"name", "nickname", "profileurl", "title", "usertype", "preferredlanguage",
                 "locale", "timezone", "password", "phonenumbers", "ims", "photos", "addresses",
                 "entitlements", "roles", "x509certificates", "emails"}
_READONLY = {"id", "meta", "groups", "schemas"}
# in a PATCH without a path these may ride along in the value object: readOnly → ignored
# (RFC 7644 §3.5.1), never applied
_VALUE_SKIP = {"id", "meta", "groups", "schemas"}


def _strip_schema(path: str, schema: str) -> str:
    """`urn:ietf:params:scim:schemas:core:2.0:User:active` → `active` (RFC 7644 §3.10: a fully
    qualified attribute name). Case of the rest is kept (a member filter value is case-exact)."""
    p = path.strip()
    pre = schema + ":"
    if p[:len(pre)].lower() == pre.lower():
        p = p[len(pre):].strip()
    return p


def _user_path(path: str) -> str:
    """What a User PATCH path targets. → 'active' | 'username' | 'displayname' |
    'name.formatted' | 'externalid' | 'email' | 'ignore'. Fail closed (review 3.6.11): a path
    WebTerm does not recognise is a 400 invalidPath — never silently ignored (an IdP's
    `urn:…:User:active=false` must not answer 200 and leave the account active)."""
    p = _strip_schema(path, S_USER)
    if p.lower().startswith(_EXT_PREFIX):
        return "ignore"                     # enterprise / custom extension: not kept
    if _EMAIL_PATH.match(p):
        return "email"
    lp = p.lower()
    if lp in ("active", "username", "displayname", "externalid", "name.formatted"):
        return lp
    m = _PATH_BASE.match(p)
    base = m.group(1).lower() if m else ""
    if base in _READONLY:
        raise ScimError(400, "%s is read-only" % p[:80], "mutability")
    if base in _USER_IGNORED:
        return "ignore"
    raise ScimError(400, "unknown attribute path %r" % path[:80], "invalidPath")


def _set_user_attr(f: dict, kind: str, value) -> None:
    if kind == "active":
        f["active"] = _bool(value, "active")
    elif kind == "username":
        f["userName"] = _text(value, "userName")
    elif kind == "displayname":
        f["displayName"] = _text(value, "displayName")
    elif kind == "name.formatted":
        if isinstance(value, str) and value.strip():
            f.setdefault("displayName", _text(value.strip()[:STR_MAX], "name.formatted"))
    elif kind == "externalid":
        f["externalId"] = _text(value, "externalId")
    elif kind == "email":
        if isinstance(value, (str, list)):
            f["email"] = _email_of(value)
        elif isinstance(value, dict):
            f["email"] = _email_of([value])
        elif value is not None:
            raise ScimError(400, "emails must be a list", "invalidValue")


def _patch_user_fields(body: dict) -> dict:
    ops = _ops(body)
    f: dict = {}
    for op, path, value in ops:
        if not path:
            if op == "remove":
                raise ScimError(400, "a remove operation needs a path", "noTarget")
            if not isinstance(value, dict):
                raise ScimError(400, "an operation without a path needs an object value",
                                "invalidValue")
            for k, v in value.items():
                key = _strip_schema(str(k), S_USER)
                if key.lower() in _VALUE_SKIP:
                    continue
                if key.lower() == S_USER.lower() and isinstance(v, dict):
                    raise ScimError(400, "nest the attributes directly in the value",
                                    "invalidValue")
                kind = _user_path(key)
                if kind == "ignore":
                    if key.lower() == "name" and isinstance(v, dict):
                        _set_user_attr(f, "name.formatted", _lower(v).get("formatted"))
                    continue
                _set_user_attr(f, kind, v)
            continue
        kind = _user_path(path)             # validated for every op, remove included
        if op == "remove" or kind == "ignore":
            continue                        # removing a WebTerm-kept attribute: nothing to do
        _set_user_attr(f, kind, value)
    return f


def _ops(body: dict) -> list:
    b = _lower(body)
    ops = b.get("operations")
    if not isinstance(ops, list) or not ops:
        raise ScimError(400, "Operations must be a non-empty list", "invalidSyntax")
    if len(ops) > OPS_MAX:
        raise ScimError(400, "at most %d operations per request" % OPS_MAX, "tooMany")
    out = []
    for o in ops:
        o = _lower(o)
        op = str(o.get("op") or "").lower()
        if op not in ("add", "replace", "remove"):
            raise ScimError(400, "op must be add, replace or remove", "invalidSyntax")
        path = o.get("path")
        if path is not None and (not isinstance(path, str) or len(path) > 512):
            raise ScimError(400, "path must be a string", "invalidPath")
        out.append((op, (path or "").strip(), o.get("value")))
    return out


@router.patch("/Users/{scim_id}")
async def patch_user(scim_id: str, request: Request, p=Depends(require_scim)):
    body = await _body(request)
    try:
        f = _patch_user_fields(body)
    except ScimError as e:
        await _refuse(p, "PATCH", PREFIX + "/Users/" + scim_id, e)
        raise
    return await _update(request, p, scim_id, "PATCH", f)


@router.delete("/Users/{scim_id}")
async def delete_user(scim_id: str, p=Depends(require_scim)):
    """DELETE = disable + unlink (the account and its audit history stay; an Owner can re-enable
    it, and the IdP re-provisioning the same person adopts it again)."""
    path = PREFIX + "/Users/" + scim_id
    try:
        async with _lock:
            u = await _user(scim_id)
            if await authz.owner_level_given_in_webterm(u["id"]):
                raise await _owner_level_refused(u["id"], "delete", p["ip"])
            try:
                await accounts.disable(u["id"], by="scim-delete", actor=ACTOR, ip=p["ip"],
                                       reason="SCIM delete")
            except accounts.LastOwner:
                raise ScimError(403, "this account is the last permanent Owner of WebTerm and "
                                     "cannot be removed; make another account a permanent Owner "
                                     "first")
            except accounts.OwnerLevel:
                raise await _owner_level_refused(u["id"], "delete", p["ip"])
            gids = [r["group_id"] for r in await db.fetchall(
                "SELECT group_id FROM scim_group_members WHERE user_id=?", u["id"])]
            await db.execute("DELETE FROM scim_group_members WHERE user_id=?", u["id"])
            # `disabled_by` was set (or moved from 'scim') by accounts.disable — never over a
            # disable done in WebTerm (re-review 3.6.11)
            await db.execute("UPDATE users SET scim_id=NULL, scim_updated=? WHERE id=?",
                             time.time(), u["id"])
            await _audit(p, "DELETE", path, 204, "SCIM deleted %s: account disabled and unlinked "
                         "(kept for its history)" % u["email"], actor_id=u["id"])
            if gids:
                await _resync({u["id"]}, p["ip"])
    except ScimError as e:
        if e.status_code != 404:
            await _refuse(p, "DELETE", path, e)
        raise
    return Response(status_code=204)


# ── Groups ───────────────────────────────────────────────────────────────────────────────────
_GROUP_FILTERS = {"displayname": ("display_name", False), "externalid": ("external_id", False),
                  "id": ("id", False)}


async def _group(gid: str):
    g = await db.fetchone("SELECT * FROM scim_groups WHERE id=?", gid)
    if g is None:
        raise ScimError(404, "no such group")
    return g


async def _group_json(g, members: bool = True) -> dict:
    out = {"schemas": [S_GROUP], "id": g["id"], "displayName": g["display_name"],
           "meta": {"resourceType": "Group", "created": _iso(g["created"]),
                    "lastModified": _iso(g["updated"]), "location": _loc("Groups", g["id"])}}
    if g["external_id"]:
        out["externalId"] = g["external_id"]
    if members:
        rows = await db.fetchall(
            "SELECT u.scim_id, u.email FROM scim_group_members m JOIN users u ON u.id=m.user_id"
            " WHERE m.group_id=? AND u.scim_id IS NOT NULL ORDER BY u.id", g["id"])
        out["members"] = [{"value": r["scim_id"], "display": r["email"],
                           "$ref": _loc("Users", r["scim_id"])} for r in rows]
    return out


def _excludes_members(request: Request) -> bool:
    ex = (request.query_params.get("excludedAttributes") or "").lower()
    return "members" in {x.strip() for x in ex.split(",")}


@router.get("/Groups")
async def list_groups(request: Request, _p=Depends(require_scim)):
    f = _filter(request.query_params.get("filter"), _GROUP_FILTERS)
    start, count = _page(request)
    where, args = "", []
    if f:
        col, value, _ci = f
        where, args = " WHERE %s=?" % col, [value]
    total = (await db.fetchone("SELECT COUNT(*) AS c FROM scim_groups" + where, *args))["c"]
    rows = await db.fetchall("SELECT * FROM scim_groups" + where
                             + " ORDER BY created, id LIMIT ? OFFSET ?", *args, count, start - 1)
    mem = not _excludes_members(request)
    return _json(_list([await _group_json(g, mem) for g in rows], total, start))


@router.get("/Groups/{gid}")
async def get_group(gid: str, request: Request, _p=Depends(require_scim)):
    return _json(await _group_json(await _group(gid), not _excludes_members(request)))


def _group_name(v) -> str:
    """The group name EXACTLY as the IdP sends it in the OIDC `groups` claim — never trimmed or
    normalised (the mapping compares byte for byte). Control/format characters are refused."""
    if not isinstance(v, str) or not ssomap._clean_name(v):
        raise ScimError(400, "displayName must be 1-%d printable characters" % ssomap.GROUP_MAX_LEN,
                        "invalidValue")
    return v


async def _member_ids(value) -> set:
    """[{value: <scim user id>}] → WebTerm user ids. Unknown ids (not provisioned here, or not
    SCIM accounts) are ignored: membership is only ever recorded for SCIM accounts."""
    if value is None:
        return set()
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise ScimError(400, "members must be a list", "invalidValue")
    if len(value) > MEMBERS_MAX:
        raise ScimError(400, "too many members", "tooMany")
    ids = set()
    for m in value:
        sid = _lower(m).get("value") if isinstance(m, dict) else None
        if isinstance(sid, str) and 0 < len(sid) <= 128:
            ids.add(sid)
    out = set()
    lst = sorted(ids)
    for i in range(0, len(lst), 500):
        chunk = lst[i:i + 500]
        rows = await db.fetchall(
            "SELECT id FROM users WHERE COALESCE(scim_managed, 0)=1"
            " AND COALESCE(local_password, 1)=0 AND scim_id IN (%s)"
            % ",".join("?" * len(chunk)), *chunk)
        out |= {r["id"] for r in rows}
    return out


async def _members(gid: str) -> set:
    return {r["user_id"] for r in await db.fetchall(
        "SELECT user_id FROM scim_group_members WHERE group_id=?", gid)}


async def _name_free(name: str, gid: Optional[str]) -> None:
    row = await db.fetchone("SELECT id FROM scim_groups WHERE display_name=?", name)
    if row is not None and row["id"] != gid:
        raise ScimError(409, "a group named %s already exists" % name[:80], "uniqueness")


async def _resync(uids: set, ip: str, extra_known=()) -> None:
    """Re-run the SSO group → role mapping for these accounts with their groups as SCIM now
    says. SCIM is authoritative only for the groups it manages: groups recorded at the last SSO
    sign-in that SCIM does not push are kept. `extra_known` = names that just stopped being SCIM
    groups (renamed / deleted), so their membership is dropped too."""
    if not uids:
        return
    known = {r["display_name"] for r in await db.fetchall("SELECT display_name FROM scim_groups")}
    known |= set(extra_known)
    for uid in sorted(uids):
        u = await db.fetchone("SELECT id, email, sso_groups, COALESCE(scim_managed, 0) AS sm"
                              " FROM users WHERE id=?", uid)
        if u is None or not u["sm"]:
            continue
        mine = {r["display_name"] for r in await db.fetchall(
            "SELECT g.display_name FROM scim_group_members m JOIN scim_groups g ON g.id=m.group_id"
            " WHERE m.user_id=?", uid)}
        eff = (ssomap._stored(u) - known) | mine
        try:
            await ssomap.sync_user(uid, u["email"], sorted(eff), ip=ip, via="scim",
                                   path=PREFIX + "/Groups", scim=True)
        except Exception:                   # noqa: BLE001 — one account must not stop the rest
            log.exception("SCIM: re-syncing the roles of %s failed", u["email"])


async def _set_members(gid: str, want: set) -> tuple[set, set]:
    have = await _members(gid)
    add, rem = want - have, have - want
    for uid in sorted(add):
        await db.execute("INSERT OR IGNORE INTO scim_group_members(group_id, user_id) VALUES(?,?)",
                         gid, uid)
    for uid in sorted(rem):
        await db.execute("DELETE FROM scim_group_members WHERE group_id=? AND user_id=?", gid, uid)
    return add, rem


@router.post("/Groups")
async def create_group(request: Request, p=Depends(require_scim)):
    body = await _body(request)
    path = PREFIX + "/Groups"
    try:
        async with _lock:
            b = _lower(body)
            name = _group_name(b.get("displayname"))
            ext = _text(b.get("externalid"), "externalId")
            await _name_free(name, None)
            want = await _member_ids(b.get("members"))
            gid, now = str(uuid.uuid4()), time.time()
            await db.execute("INSERT INTO scim_groups(id, display_name, external_id, created,"
                             " updated) VALUES(?,?,?,?,?)", gid, name, ext, now, now)
            await _set_members(gid, want)
            await _audit(p, "POST", path, 201, "SCIM created group %r with %d member(s)"
                         % (name, len(want)))
            await _resync(want, p["ip"])
            g = await _group(gid)
    except ScimError as e:
        await _refuse(p, "POST", path, e)
        raise
    return _json(await _group_json(g), 201)


async def _apply_group(p: dict, g, name: Optional[str], ext, members: Optional[set],
                       add: set, rem: set, method: str) -> None:
    """Rename / set externalId / replace members (`members` not None) / add / remove."""
    path = PREFIX + "/Groups/" + g["id"]
    old = g["display_name"]
    renamed = name is not None and name != old
    if renamed:
        await _name_free(name, g["id"])
    sets, args = [], []
    if renamed:
        sets.append("display_name=?")
        args.append(name)
    if ext is not _KEEP and (ext or None) != (g["external_id"] or None):
        sets.append("external_id=?")
        args.append(ext)
    added, removed = set(), set()
    if members is not None:
        added, removed = await _set_members(g["id"], members)
    have = await _members(g["id"])
    for uid in sorted(add - have):
        await db.execute("INSERT OR IGNORE INTO scim_group_members(group_id, user_id) VALUES(?,?)",
                         g["id"], uid)
        added.add(uid)
    for uid in sorted(rem & (have | added)):
        await db.execute("DELETE FROM scim_group_members WHERE group_id=? AND user_id=?",
                         g["id"], uid)
        removed.add(uid)
        added.discard(uid)
    if sets or added or removed:
        await db.execute("UPDATE scim_groups SET " + ", ".join(sets + ["updated=?"])
                         + " WHERE id=?", *args, time.time(), g["id"])
        bits = []
        if renamed:
            bits.append("renamed %r → %r" % (old, name))
        if added:
            bits.append("+%d member(s)" % len(added))
        if removed:
            bits.append("-%d member(s)" % len(removed))
        if sets and not renamed:
            bits.append("externalId")
        await _audit(p, method, path, 200, "SCIM group %r: %s" % (name or old, ", ".join(bits)))
    touched = added | removed
    if renamed:
        touched |= await _members(g["id"])
    await _resync(touched, p["ip"], extra_known={old} if renamed else ())


_KEEP = object()
_MEMBER_FILTER = re.compile(r'^members\[\s*value\s+eq\s+"((?:[^"\\]|\\.)*)"\s*\]$', re.I)


@router.put("/Groups/{gid}")
async def put_group(gid: str, request: Request, p=Depends(require_scim)):
    body = await _body(request)
    path = PREFIX + "/Groups/" + gid
    try:
        async with _lock:
            g = await _group(gid)
            b = _lower(body)
            name = _group_name(b["displayname"]) if "displayname" in b else None
            ext = _text(b.get("externalid"), "externalId") if "externalid" in b else _KEEP
            # a PUT without `members` keeps them: some IdPs PUT the group, then PATCH members in —
            # clearing them in between would flap everyone's roles (and close their terminals)
            members = await _member_ids(b["members"]) if "members" in b else None
            await _apply_group(p, g, name, ext, members, set(), set(), "PUT")
            g = await _group(gid)
    except ScimError as e:
        if e.status_code != 404:
            await _refuse(p, "PUT", path, e)
        raise
    return _json(await _group_json(g, not _excludes_members(request)))


@router.patch("/Groups/{gid}")
async def patch_group(gid: str, request: Request, p=Depends(require_scim)):
    body = await _body(request)
    path = PREFIX + "/Groups/" + gid
    try:
        async with _lock:
            g = await _group(gid)
            name, ext, members = None, _KEEP, None
            add, rem = set(), set()
            for op, opath, value in _ops(body):
                opath = _strip_schema(opath, S_GROUP)
                lp = opath.lower()
                if not opath:
                    if op == "remove":
                        raise ScimError(400, "a remove operation needs a path", "noTarget")
                    if not isinstance(value, dict):
                        raise ScimError(400, "an operation without a path needs an object value",
                                        "invalidValue")
                    v = _lower_core(value, S_GROUP)
                    unknown = sorted(set(v) - {"displayname", "externalid", "members"}
                                     - _VALUE_SKIP)
                    if unknown:
                        raise ScimError(400, "unknown attribute %r" % unknown[0][:80],
                                        "invalidPath")
                    if "displayname" in v:
                        name = _group_name(v["displayname"])
                    if "externalid" in v:
                        ext = _text(v["externalid"], "externalId")
                    if "members" in v:
                        ids = await _member_ids(v["members"])
                        if op == "replace":
                            members, add, rem = ids, set(), set()
                        elif op == "add":
                            add |= ids
                            rem -= ids
                elif lp == "displayname":
                    if op != "remove":
                        name = _group_name(value)
                elif lp == "externalid":
                    ext = None if op == "remove" else _text(value, "externalId")
                elif lp == "members":
                    ids = await _member_ids(value)
                    if op == "replace":
                        members, add, rem = ids, set(), set()
                    elif op == "add":
                        add |= ids
                        rem -= ids
                    elif value is None:              # remove without a value = remove all
                        members, add, rem = set(), set(), set()
                    else:
                        rem |= ids
                        add -= ids
                elif _MEMBER_FILTER.match(opath) and op == "remove":
                    sid = re.sub(r'\\(.)', r'\1', _MEMBER_FILTER.match(opath).group(1))
                    ids = await _member_ids([{"value": sid}])
                    rem |= ids
                    add -= ids
                elif _PATH_BASE.match(opath) and _PATH_BASE.match(opath).group(1).lower() in (
                        "id", "meta", "schemas"):
                    raise ScimError(400, "%s is read-only" % opath[:80], "mutability")
                else:
                    # fail closed (review 3.6.11): an unrecognised path is an error, never a
                    # silent 200 (e.g. `members[value eq "x"]` with op add/replace)
                    raise ScimError(400, "unsupported attribute path %r" % opath[:80],
                                    "invalidPath")
            if members is not None:
                members = (members | add) - rem
                add, rem = set(), set()
            await _apply_group(p, g, name, ext, members, add, rem, "PATCH")
            g = await _group(gid)
    except ScimError as e:
        if e.status_code != 404:
            await _refuse(p, "PATCH", path, e)
        raise
    return _json(await _group_json(g, not _excludes_members(request)))


@router.delete("/Groups/{gid}")
async def delete_group(gid: str, p=Depends(require_scim)):
    path = PREFIX + "/Groups/" + gid
    async with _lock:
        g = await _group(gid)
        members = await _members(gid)
        await db.execute("DELETE FROM scim_group_members WHERE group_id=?", gid)
        await db.execute("DELETE FROM scim_groups WHERE id=?", gid)
        await _audit(p, "DELETE", path, 204, "SCIM deleted group %r (%d member(s))"
                     % (g["display_name"], len(members)))
        await _resync(members, p["ip"], extra_known={g["display_name"]})
    return Response(status_code=204)


# ── discovery ────────────────────────────────────────────────────────────────────────────────
def _attr(name, typ="string", **kw) -> dict:
    a = {"name": name, "type": typ, "multiValued": False, "required": False,
         "caseExact": False, "mutability": "readWrite", "returned": "default",
         "uniqueness": "none"}
    a.update(kw)
    return a


_SCHEMAS = [
    {"schemas": [S_SCHEMA], "id": S_USER, "name": "User", "description": "WebTerm account",
     "attributes": [
         _attr("userName", required=True, uniqueness="server"),
         _attr("externalId", caseExact=True),
         _attr("displayName"),
         _attr("active", "boolean"),
         _attr("emails", "complex", multiValued=True, required=True, subAttributes=[
             _attr("value"), _attr("type"), _attr("primary", "boolean")]),
         _attr("groups", "complex", multiValued=True, mutability="readOnly", subAttributes=[
             _attr("value", mutability="readOnly"), _attr("display", mutability="readOnly")]),
     ],
     "meta": {"resourceType": "Schema", "location": "%s/Schemas/%s" % (PREFIX, S_USER)}},
    {"schemas": [S_SCHEMA], "id": S_GROUP, "name": "Group",
     "description": "An IdP group; displayName = the name in the OIDC groups claim",
     "attributes": [
         _attr("displayName", required=True, caseExact=True, uniqueness="server"),
         _attr("externalId", caseExact=True),
         _attr("members", "complex", multiValued=True, subAttributes=[
             _attr("value", caseExact=True), _attr("display", mutability="readOnly")]),
     ],
     "meta": {"resourceType": "Schema", "location": "%s/Schemas/%s" % (PREFIX, S_GROUP)}},
]


@router.get("/ServiceProviderConfig")
async def service_provider_config(_p=Depends(require_scim)):
    return _json({
        "schemas": [S_SPC], "documentationUri": DOC,
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": PAGE_MAX},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken", "name": "SCIM bearer token", "primary": True,
            "description": "The token an Owner creates in Settings → Users & roles → SSO groups "
                           "→ SCIM (shown once)."}],
        "meta": {"resourceType": "ServiceProviderConfig",
                 "location": config.PUBLIC_URL.rstrip("/") + PREFIX + "/ServiceProviderConfig"}})


@router.get("/ResourceTypes")
async def resource_types(_p=Depends(require_scim)):
    res = [{"schemas": [S_RT], "id": n, "name": n, "endpoint": "/" + n + "s", "schema": s,
            "meta": {"resourceType": "ResourceType", "location": "%s/ResourceTypes/%s" % (PREFIX, n)}}
           for n, s in (("User", S_USER), ("Group", S_GROUP))]
    return _json(_list(res, len(res), 1))


@router.get("/Schemas")
async def schemas(_p=Depends(require_scim)):
    return _json(_list(_SCHEMAS, len(_SCHEMAS), 1))
