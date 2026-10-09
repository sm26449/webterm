"""Roles and scoped bindings (WebTerm 3.6.0) — the ONE place that decides who may do what, where.

Design: docs/design/ROLES-AND-SSH.md, Part A. In short:

  * a *role* is a named set of permissions (the "what"); a *binding* attaches one role to one
    user over one *scope* — all hosts, a folder, a tag or a single host (the "where");
  * on host H a user's permissions are the UNION of the bindings whose scope matches H
    (no deny rules); GLOBAL permissions (users, settings, backups…) count only from a binding
    at scope `all`, otherwise "Admin on folder lab" would mean "admin of the instance";
  * every route declares its permission with `Depends(authz.perm("files.read", host="host_id"))`.
    A router-level guard (`declared`) refuses at runtime any route that declares nothing
    (fail-closed), and `tests/route_auth_test.py` refuses it in CI;
  * check order: authenticate → authorize (404 when the host is not visible to you — the same
    body as a host that does not exist, so there is no existence oracle; 403 `authz.denied`
    when it is visible but the permission is missing) → the existing 2FA step-up → action.
    Step-up never grants a permission and never runs for a principal who lacks one;
  * automation tokens keep their legacy `read`/`run` scopes and are additionally capped by
    what their creator can do NOW (token ∩ creator); a token whose creator lost every binding
    can do nothing.

What this module does NOT pretend: inside a host where a user already has a shell, finer limits
are guardrails, not boundaries. The catalogue marks those permissions `shell` (⚑) so the UI and
the docs can say so honestly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from fastapi import Request
from starlette.requests import HTTPConnection

from . import db, security
from .errors import ApiError

log = logging.getLogger("webterm")

# ── Permission catalogue (§A.4) ─────────────────────────────────────────────────────────────
# (id, kind, shell_equivalent). Order = display order in the UI. A permission added here in a
# later release reaches the built-in roles automatically (they are re-asserted at every boot).
_CATALOGUE = (
    # host-scoped
    ("host.view", "host", False),
    ("host.diagnostics", "host", False),
    ("session.watch", "host", False),
    ("recording.view", "host", False),
    ("session.open", "host", True),
    ("session.manage", "host", False),
    ("files.read", "host", False),
    ("files.write", "host", True),
    ("files.delete", "host", False),
    ("run", "host", True),
    ("docker.view", "host", False),
    ("docker.act", "host", True),
    ("services.view", "host", False),
    ("services.act", "host", False),
    ("forward.use", "host", False),
    ("forward.manage", "host", False),
    ("serial.use", "host", True),
    ("toolbox.use", "host", True),
    ("toolbox.manage", "host", False),
    ("deploykey.manage", "host", True),
    ("share.live", "host", False),
    ("share.live_write", "host", True),
    ("share.replay", "host", False),
    ("host.wake", "host", False),
    ("host.edit", "host", False),
    ("host.admin", "host", True),
    # global (honoured only from a binding at scope `all`)
    ("hosts.create", "global", False),
    ("hosts.export", "global", False),
    ("settings.manage", "global", False),
    ("users.manage", "global", False),
    ("roles.manage", "global", False),
    ("tokens.create", "global", False),
    ("tokens.manage", "global", False),
    ("shares.manage", "global", False),
    ("snippets.manage", "global", False),
    ("history.clear", "global", False),
    ("audit.view", "global", False),
    ("security.view", "global", False),
    ("backups.manage", "global", False),
    ("signing.manage", "global", False),
)


@dataclass(frozen=True)
class PermSpec:
    id: str
    kind: str            # host | global
    shell: bool          # ⚑ shell-equivalent


PERMS: dict[str, PermSpec] = {p: PermSpec(p, k, s) for p, k, s in _CATALOGUE}
HOST_PERMS = frozenset(p for p, k, _ in _CATALOGUE if k == "host")
GLOBAL_PERMS = frozenset(p for p, k, _ in _CATALOGUE if k == "global")
SHELL_PERMS = frozenset(p for p, _, s in _CATALOGUE if s)

# ── Built-in roles (§A.5) ───────────────────────────────────────────────────────────────────
_VIEWER = frozenset({"host.view", "host.diagnostics", "session.watch", "recording.view",
                     "docker.view", "services.view", "forward.use"})
_OPERATOR = _VIEWER | frozenset({
    "session.open", "files.read", "files.write", "files.delete", "run", "docker.act",
    "services.act", "serial.use", "toolbox.use", "share.live", "share.replay", "host.wake",
    "tokens.create"})
_OWNER = HOST_PERMS | GLOBAL_PERMS
# Admin = everything except taking over the instance: backup download/restore carries the vault
# key, the signing key is fleet code-signing, and the global history wipe destroys evidence.
_ADMIN = _OWNER - {"history.clear", "backups.manage", "signing.manage"}

BUILTIN_ROLES: dict[str, dict] = {
    "owner": {"name": "Owner", "perms": _OWNER,
              "description": "The instance owner(s): everything, including backups and the signing key."},
    "admin": {"name": "Admin", "perms": _ADMIN,
              "description": "Co-admin: everything except taking over the instance."},
    "operator": {"name": "Operator", "perms": _OPERATOR,
                 "description": "Does the work on the hosts in scope (shell, files, run)."},
    "viewer": {"name": "Viewer", "perms": _VIEWER,
               "description": "Watches: host state, live sessions read-only, recordings."},
}
ROLE_ORDER = ("owner", "admin", "operator", "viewer")
SCOPE_KINDS = ("all", "folder", "tag", "host")

# Legacy automation-token scopes → the permissions each one can ever reach (before the creator
# cap). `read` must cover what the read routes need TODAY (status details, the host list and the
# session list), otherwise an upgrade would silently empty an existing monitoring token.
TOKEN_SCOPE_PERMS = {
    "read": frozenset({"host.view", "session.watch", "recording.view", "security.view"}),
    "run": frozenset({"host.view", "run"}),
}

# ── epoch + cache ────────────────────────────────────────────────────────────────────────────
# Single uvicorn process (Dockerfile CMD, no --workers): an in-memory epoch is coherent. The
# admin CLI runs in another process; it writes `app_settings['authz_epoch']`, which the reaper
# loop polls (`poll_external_epoch`), and the cache also expires on its own after _CACHE_TTL.
_epoch = 0
_external_epoch = ""
_CACHE_TTL = 30.0
_cache: dict[int, tuple[int, float, "Grants"]] = {}
_waiters: set = set()                  # asyncio.Event per live WebSocket / forward socket
_lock = asyncio.Lock()                 # serialises binding mutations (check-then-act)


def epoch() -> int:
    return _epoch


def bump_epoch() -> None:
    """Any change to roles, bindings, or to a host's folder/tags/via invalidates every cached
    grant and wakes every long-lived socket so it re-checks NOW, not at the next 60 s tick."""
    global _epoch
    _epoch += 1
    _cache.clear()
    for ev in list(_waiters):
        ev.set()


def subscribe() -> asyncio.Event:
    ev = asyncio.Event()
    _waiters.add(ev)
    return ev


def unsubscribe(ev) -> None:
    _waiters.discard(ev)


async def poll_external_epoch() -> None:
    """The admin CLI (another process) cannot touch our memory; it stamps app_settings."""
    global _external_epoch
    try:
        row = await db.fetchone("SELECT value FROM app_settings WHERE key='authz_epoch'")
    except Exception:                       # noqa: BLE001 — a poll must never kill the loop
        return
    val = (row["value"] if row else "") or ""
    if val != _external_epoch:
        first = _external_epoch == ""
        _external_epoch = val
        if not first:
            bump_epoch()


# ── grants ───────────────────────────────────────────────────────────────────────────────────
def _tags(s) -> frozenset:
    """Same tokenisation as api._tag_list (comma/space separated, lowercase, 32 chars)."""
    return frozenset(t.strip().lower()[:32] for t in (s or "").replace(",", " ").split() if t.strip())


@dataclass(frozen=True)
class HostRef:
    """What scope matching needs to know about a host. An EPHEMERAL jump host inherits the
    scope of its via parent (§A.3), otherwise "connect once" would mint an invisible host."""
    id: int
    folder: str
    tags: frozenset


@dataclass(frozen=True)
class Binding:
    id: int
    role_key: str
    role_name: str
    perms: frozenset
    scope_kind: str
    scope_value: str
    source: str
    expires: Optional[float]

    def matches(self, h: HostRef) -> bool:
        k, v = self.scope_kind, self.scope_value
        if k == "all":
            return True
        if k == "folder":
            return (h.folder or "") == v
        if k == "tag":
            return v in h.tags
        if k == "host":
            return str(h.id) == v
        return False                       # unknown kind: matches nothing (fail-closed)


@dataclass
class Grants:
    user_id: Optional[int]
    bindings: list = field(default_factory=list)
    global_perms: frozenset = frozenset()
    all_host_perms: frozenset = frozenset()     # host perms valid on EVERY host (scope all)

    @classmethod
    def from_bindings(cls, user_id, bindings: list) -> "Grants":
        g, a = set(), set()
        for b in bindings:
            if b.scope_kind == "all":
                g |= b.perms & GLOBAL_PERMS
                a |= b.perms & HOST_PERMS
        return cls(user_id, bindings, frozenset(g), frozenset(a))

    def on(self, h: Optional[HostRef]) -> frozenset:
        if h is None:
            return frozenset()
        out = set(self.all_host_perms)
        for b in self.bindings:
            if b.scope_kind != "all" and b.matches(h):
                out |= b.perms & HOST_PERMS
        if out:
            # every host permission implies host.view (§A.4)
            out.add("host.view")
        return frozenset(out)

    def has_global(self, p: str) -> bool:
        return p in self.global_perms

    def is_owner(self) -> bool:
        return any(b.role_key == "owner" and b.scope_kind == "all" for b in self.bindings)

    def any_host_perm(self, p: str) -> bool:
        return p in self.all_host_perms or any(
            p in b.perms for b in self.bindings if b.scope_kind != "all")


@dataclass
class TokenGrants(Grants):
    """token ∩ creator. `scope_perms` = the legacy scope ceiling (read/run), `role_perms` the
    optional role ceiling, `tscope` the token's own scope (narrower than the creator's)."""
    creator: Optional[Grants] = None
    ceiling: frozenset = frozenset()
    tscope: tuple = ("all", "")

    def _in_scope(self, h: HostRef) -> bool:
        k, v = self.tscope
        return Binding(0, "", "", frozenset(), k, v, "", None).matches(h)

    def on(self, h: Optional[HostRef]) -> frozenset:
        if h is None or self.creator is None or not self._in_scope(h):
            return frozenset()
        return self.creator.on(h) & self.ceiling

    def any_host_perm(self, p: str) -> bool:
        return p in self.ceiling and self.creator is not None and self.creator.any_host_perm(p)


async def _load_bindings(user_id: int) -> list:
    now = time.time()
    rows = await db.fetchall(
        "SELECT b.id, b.scope_kind, b.scope_value, b.source, b.expires,"
        " r.key AS role_key, r.name AS role_name, r.perms AS role_perms, r.builtin"
        " FROM role_bindings b JOIN roles r ON r.id = b.role_id WHERE b.user_id=?", user_id)
    out = []
    for r in rows:
        if r["expires"] is not None and r["expires"] <= now:
            continue                       # time-bound grants (3.6.2): expired = absent
        if r["scope_kind"] not in SCOPE_KINDS:
            continue
        if r["builtin"] and r["role_key"] in BUILTIN_ROLES:
            perms = BUILTIN_ROLES[r["role_key"]]["perms"]   # code is the source of truth
        else:
            try:
                perms = frozenset(p for p in json.loads(r["role_perms"] or "[]") if p in PERMS)
            except (TypeError, ValueError):
                perms = frozenset()        # unreadable custom role = no permissions
        out.append(Binding(r["id"], r["role_key"] or "", r["role_name"] or "", perms,
                           r["scope_kind"], r["scope_value"] or "", r["source"] or "manual",
                           r["expires"]))
    return out


async def grants_for_user(user_id: Optional[int]) -> Grants:
    if not user_id:
        return Grants(None)
    hit = _cache.get(user_id)
    now = time.monotonic()
    if hit and hit[0] == _epoch and now - hit[1] < _CACHE_TTL:
        return hit[2]
    g = Grants.from_bindings(user_id, await _load_bindings(user_id))
    _cache[user_id] = (_epoch, now, g)
    return g


async def grants_for_token(tok: dict) -> TokenGrants:
    creator_id = tok.get("created_by_id")
    if not creator_id and tok.get("created_by"):
        row = await db.fetchone("SELECT id FROM users WHERE email=?", tok["created_by"])
        creator_id = row["id"] if row else None
    if not creator_id or not await db.fetchone("SELECT 1 FROM users WHERE id=?", creator_id):
        return TokenGrants(None)           # creator gone → the token can do nothing
    creator = await grants_for_user(creator_id)
    ceiling = set()
    for s in security.token_scopes(tok):
        ceiling |= TOKEN_SCOPE_PERMS.get(s, frozenset())
    role_id = tok.get("role_id")
    if role_id:
        r = await db.fetchone("SELECT key, perms, builtin FROM roles WHERE id=?", role_id)
        if not r:
            ceiling = set()
        elif r["builtin"] and r["key"] in BUILTIN_ROLES:
            ceiling &= BUILTIN_ROLES[r["key"]]["perms"]
        else:
            try:
                ceiling &= {p for p in json.loads(r["perms"] or "[]") if p in PERMS}
            except (TypeError, ValueError):
                ceiling = set()
    ceiling = frozenset(ceiling)
    kind = tok.get("scope_kind") or "all"
    if kind not in SCOPE_KINDS:
        ceiling = frozenset()
    tscope = (kind, tok.get("scope_value") or "")
    g = TokenGrants(creator_id, [], creator.global_perms & ceiling if kind == "all" else frozenset(),
                    frozenset(), creator=creator, ceiling=ceiling, tscope=tscope)
    # token at scope all over a creator with an all binding → fast path for the host checks
    if kind == "all":
        g.all_host_perms = creator.all_host_perms & ceiling
    return g


# ── hosts ────────────────────────────────────────────────────────────────────────────────────
async def host_refs() -> dict[int, HostRef]:
    """Every host's scope attributes (ephemeral → its via parent's). One cheap query; NOT
    cached across requests: a folder edit must take effect on the very next request."""
    rows = await db.fetchall(
        "SELECT id, folder, tags, ephemeral, via_host_id FROM hosts")
    raw = {r["id"]: r for r in rows}
    out = {}
    for hid, r in raw.items():
        src = r
        if (r["ephemeral"] or 0) and r["via_host_id"] and r["via_host_id"] in raw:
            src = raw[r["via_host_id"]]
        out[hid] = HostRef(src["id"], src["folder"] or "", _tags(src["tags"]))
    return out


async def host_ref(host_id) -> Optional[HostRef]:
    try:
        hid = int(host_id)
    except (TypeError, ValueError):
        return None
    r = await db.fetchone("SELECT id, folder, tags, ephemeral, via_host_id FROM hosts WHERE id=?", hid)
    if not r:
        return None
    if (r["ephemeral"] or 0) and r["via_host_id"]:
        p = await db.fetchone("SELECT id, folder, tags FROM hosts WHERE id=?", r["via_host_id"])
        if p:
            return HostRef(p["id"], p["folder"] or "", _tags(p["tags"]))
    return HostRef(r["id"], r["folder"] or "", _tags(r["tags"]))


async def perms_on(grants: Grants, host_id) -> frozenset:
    """Permisiunile pe un host. Pe un id care nu (mai) există rămân doar cele de la scope `all`
    — exact ce avea un Owner şi înainte; un cont limitat la foldere/hosturi nu primeşte nimic."""
    if grants is None:
        return frozenset()
    ref = await host_ref(host_id)
    if ref is None:
        return grants.all_host_perms
    return grants.on(ref)


async def visible_hosts(grants: Grants, *perms: str) -> Optional[set]:
    """Host ids on which the principal holds ANY of `perms`; None = every host (fast path for
    a scope-`all` holder). Lists filter with this, silently (never a 403)."""
    if grants is None:
        return set()
    if any(p in grants.all_host_perms for p in perms):
        return None
    refs = await host_refs()
    return {hid for hid, h in refs.items() if grants.on(h) & set(perms)}


def in_visible(vis: Optional[set], host_id) -> bool:
    return vis is None or host_id in vis


# ── principals ───────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Principal:
    kind: str                 # user | token
    user_id: Optional[int]    # token → its creator
    email: str
    token_id: Optional[int] = None
    user_row: Any = None

    @property
    def via(self) -> str:
        return "token:%d" % self.token_id if self.kind == "token" else "cookie"


async def authenticate(request: Request, tokens: Optional[str] = None):
    """→ (principal, the object the handler receives as `user`). Bearer tokens are accepted
    only where the route says `tokens=<scope>`, keeping today's short allowlist."""
    if tokens:
        tok = await security.api_token_principal(request)
        if tok is not None:
            if tokens not in security.token_scopes(tok):
                raise ApiError(403, "token.missingScope",
                               "the token does not have the '%s' scope" % tokens,
                               vars={"scope": tokens})
            p = Principal("token", tok.get("created_by_id"), "token:" + tok["name"], tok["id"])
            user = {"id": None, "email": "token:" + tok["name"], "is_token": True,
                    "token_id": tok["id"], "actor_id": tok.get("created_by_id")}
            return p, user, await grants_for_token(tok)
    user = await security.require_user(request)
    p = Principal("user", user["id"], user["email"], None, user)
    return p, user, await grants_for_user(user["id"])


def _denied(perm: str) -> ApiError:
    return ApiError(403, "authz.denied", "your role does not allow this here (%s)" % perm,
                    vars={"perm": perm})


# 404 bodies IDENTICAL to the handlers' own "does not exist" answers: a host you cannot see and
# a host that does not exist must be indistinguishable (same status, code, detail, headers).
_NOT_FOUND = {
    "host_id": ("host.missing", "no such host"),
    "body": ("host.missing", "no such host"),
    "sid": ("session.missing", "no such session"),
    "fid": ("forward.missing", "no such forward"),
    "link_id": ("replay.missing", "no such replay link"),
}


def not_found(kind: str = "host_id") -> ApiError:
    code, msg = _NOT_FOUND.get(kind, _NOT_FOUND["host_id"])
    return ApiError(404, code, msg)


def check_host(grants: Grants, ref: Optional[HostRef], perm, kind: str = "host_id") -> frozenset:
    """404 if not visible (incl. nonexistent), 403 if visible but lacking every perm in `perm`."""
    alts = (perm,) if isinstance(perm, str) else tuple(perm)
    have = grants.on(ref) if ref is not None else frozenset()
    if "host.view" not in have:
        raise not_found(kind)
    if not any(p in have for p in alts):
        raise _denied(alts[0])
    return have


async def require_on(request_or_grants, host_id, perm, kind: str = "host_id") -> frozenset:
    """Handler-level check for a SECOND host (copy destination, deploy-key target, via host…).
    Same 404/403 semantics as the route dependency."""
    grants = request_or_grants
    if not isinstance(grants, Grants):
        grants = getattr(request_or_grants.state, "grants", None)
    if grants is None:
        raise not_found(kind)              # fail closed: no grants on the request = nothing
    alts = (perm,) if isinstance(perm, str) else tuple(perm)
    if any(p in grants.all_host_perms for p in alts):
        return grants.all_host_perms
    return check_host(grants, await host_ref(host_id), perm, kind)


def require_global(request_or_grants, perm: str) -> None:
    grants = request_or_grants
    if not isinstance(grants, Grants):
        grants = getattr(request_or_grants.state, "grants", None)
    if grants is None or perm not in grants.global_perms:
        raise _denied(perm)


def grants_of(request) -> Grants:
    g = getattr(request.state, "grants", None)
    return g if g is not None else Grants(None)


# ── locators ─────────────────────────────────────────────────────────────────────────────────
async def _locate(request: Request, locator: str) -> tuple[str, Optional[int], bool]:
    """→ (kind, host_id or None, present). `present=False` = an optional body locator that the
    request did not carry (e.g. history without a host)."""
    if locator == "host_id":
        try:
            return "host_id", int(request.path_params.get("host_id")), True
        except (TypeError, ValueError):
            return "host_id", None, True
    if locator == "sid":
        sid = request.path_params.get("sid") or ""
        r = await db.fetchone("SELECT host_id FROM sessions WHERE id=?", sid)
        return "sid", (r["host_id"] if r else None), True
    if locator == "fid":
        r = await db.fetchone("SELECT host_id FROM port_forwards WHERE id=?",
                              request.path_params.get("fid"))
        return "fid", (r["host_id"] if r else None), True
    if locator == "link_id":
        r = await db.fetchone(
            "SELECT s.host_id FROM replay_links l JOIN sessions s ON s.id = l.sid WHERE l.id=?",
            request.path_params.get("link_id"))
        return "link_id", (r["host_id"] if r else None), True
    if locator.startswith("body:"):
        name = locator[5:]
        try:
            body = await request.json()
        except Exception:                  # noqa: BLE001 — malformed body: the handler 422s
            body = None
        if not isinstance(body, dict) or body.get(name) in (None, ""):
            return "body", None, False
        try:
            return "body", int(body.get(name)), True
        except (TypeError, ValueError):
            return "body", None, True
    raise RuntimeError("authz: unknown host locator %r" % locator)


# ── the dependency ───────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class RouteSpec:
    perm: tuple                # alternatives (any of)
    host: Optional[str]        # locator, or None
    tokens: Optional[str]      # legacy token scope accepted here, or None (cookie only)
    list: bool                 # list/filter route: never 403s, the handler filters
    optional_host: bool        # body locator may be absent → then the perm on ANY host is needed
    zero_is_self: bool         # body host id 0 = account scope (webauthn step-up)

    @property
    def kind(self) -> str:
        p = self.perm[0]
        if self.list:
            return "L"
        if PERMS[p].kind == "global":
            return "G"
        return "H"


def perm(name, *, host: Optional[str] = None, tokens: Optional[str] = None,
         list: bool = False, optional_host: bool = False, zero_is_self: bool = False):
    """FastAPI dependency factory: authenticates, authorizes and returns what the handler used
    to get from `security.require_user` / `require_scope` (the same object), so a route keeps
    exactly ONE auth dependency.

    name          permission id, or a tuple of alternatives (any of them passes)
    host          'host_id' | 'sid' | 'fid' | 'link_id' | 'body:<field>' — how to find the host
    tokens        'read' | 'run': Bearer tokens with that legacy scope are accepted here
    list          list/filter route: never denies; Grants go on request.state for filtering
    """
    alts = (name,) if isinstance(name, str) else tuple(name)
    for p in alts:
        if p not in PERMS:
            raise RuntimeError("authz: unknown permission %r" % p)
    kinds = {PERMS[p].kind for p in alts}
    if len(kinds) != 1:
        raise RuntimeError("authz: mixed global/host alternatives in %r" % (alts,))
    is_global = kinds == {"global"}
    if not list and not is_global and host is None:
        raise RuntimeError("authz: host permission %r needs a host locator (or list=True)" % (alts,))
    if is_global and host is not None:
        raise RuntimeError("authz: global permission %r cannot take a host locator" % (alts,))
    spec = RouteSpec(alts, host, tokens, bool(list), bool(optional_host), bool(zero_is_self))

    async def dep(request: Request):
        principal, user, grants = await authenticate(request, tokens)
        request.state.principal = principal
        request.state.grants = grants
        if spec.list:
            return user
        if is_global:
            if not any(p in grants.global_perms for p in alts):
                raise _denied(alts[0])
            return user
        kind, hid, present = await _locate(request, host)
        if hid is not None:
            request.state.audit_host = hid
        if not present:
            if spec.optional_host:
                if not any(grants.any_host_perm(p) for p in alts):
                    raise _denied(alts[0])
                return user
            raise not_found(kind)
        if spec.zero_is_self and hid == 0:
            return user
        # fast path: the permission holds on EVERY host → existence is the handler's business,
        # exactly as before 3.6 (an Owner sees the same 404/409 for a missing host as always)
        if any(p in grants.all_host_perms for p in alts):
            return user
        if hid is None:
            raise not_found(kind)
        check_host(grants, await host_ref(hid), alts, kind)
        return user

    dep.__authz__ = spec
    dep.__name__ = "perm_" + alts[0].replace(".", "_")
    return dep


def spec_of(call) -> Optional[RouteSpec]:
    return getattr(call, "__authz__", None)


def ws_perm(name, *, host: str):
    """Marker for WebSocket handlers, which authorize INSIDE the handler (FastAPI dependencies
    cannot close a socket with our codes). Declares the permission for the guard and the CI."""
    alts = (name,) if isinstance(name, str) else tuple(name)

    def deco(fn):
        fn.__authz__ = RouteSpec(alts, host, None, False, False, False)
        return fn
    return deco


# Routes that need no permission, with the reason (moved here from the test, §A.6.2): PUBLIC
# carry their own credential in the request; SELF act only on the caller's own data.
PUBLIC: dict[str, str] = {
    "/healthz": "container liveness probe; touches no data",
    "/api/state": "only says whether the install has an account — the setup screen depends on it",
    "/api/setup": "creates the FIRST account (Owner @ all); closes itself after (atomic claim)",
    "/api/login": "the gate itself",
    "/api/logout": "must work with an already-invalid session",
    "/api/shared/{token}": "the share token IS the credential (hashed, expiring)",
    "/ws/shared/{token}": "idem, on a WebSocket",
    "/api/replay/meta": "the replay token IS the credential; title/label of the recording only",
    "/api/replay/cast": "idem; the recording of ONE closed session (optionally masked), audited",
    "/api/replay/text": "idem; the text view of the same recording, audited",
    "/agent/ws": "the agent authenticates with its host token in the handshake",
    "/agent/uninstalled": ("the agent reports it was removed; authenticated with ITS token, "
                           "never a user session. Deletes nothing — only marks"),
    "/agent/ptyd.py": "agent source: public by construction, verified by signature",
    "/agent/shell-integration.sh": "idem; integrity is checked by sha256, not by auth",
    "/install/{enroll_token}": "the enroll token IS the credential; expires in 24h, single-use",
    "/install/group/{group_token}": ("the group token IS the credential; opt-in, expiring, "
                                     "revocable, capped, auto-enroll audited + alerted"),
    "/__wtfwd/auth": ("forward handshake; validates the session cookie in the handler AND "
                      "checks forward.use on the forward's host before issuing a ticket"),
    "/api/webauthn/login/options": "passkey login ceremony — BEFORE there is a session",
    "/api/webauthn/login/verify": "idem; verifies the assertion and only then opens the session",
    "/api/oidc/status": "only whether SSO is on + the provider name — the login screen needs it",
    "/api/oidc/login": "starts the OIDC flow — BEFORE there is a session (redirect to the IdP)",
    "/api/oidc/callback": ("the IdP return: guarded by `state` (anti-CSRF, single-use) and the "
                           "id_token validation; a step-up callback re-checks host.view"),
}

SELF: dict[tuple, str] = {
    ("POST", "/api/account"): "own email/password; reauth + second factor",
    ("GET", "/api/totp/status"): "own 2FA state (host counts filtered to visible hosts)",
    ("POST", "/api/totp/setup"): "own TOTP enrolment",
    ("POST", "/api/totp/activate"): "own TOTP enrolment",
    ("POST", "/api/totp/disable"): "own TOTP",
    ("POST", "/api/totp/recovery-codes"): "own recovery codes",
    ("GET", "/api/account/sessions"): "own web sessions",
    ("DELETE", "/api/account/sessions/{rid}"): "own web session",
    ("POST", "/api/account/sessions/revoke-others"): "own web sessions",
    ("GET", "/api/alerts"): "own alert rows (the fan-out decides who gets a row)",
    ("GET", "/api/alerts/unread"): "own alert counter",
    ("POST", "/api/alerts/read"): "own alert rows",
    ("DELETE", "/api/alerts"): "own alert rows",
    ("GET", "/api/alerts/prefs"): "own alert preferences",
    ("POST", "/api/alerts/prefs"): "own alert preferences",
    ("GET", "/api/version"): "gateway version + update availability",
    ("GET", "/api/changelog"): "the release notes",
    ("GET", "/api/split-views"): "own layouts (pane sids only)",
    ("POST", "/api/split-views"): "own layout; every pane must be a session the caller can see",
    ("PATCH", "/api/split-views/{sv_id}"): "own layout; idem",
    ("DELETE", "/api/split-views/{sv_id}"): "own layout",
    ("GET", "/api/shell-integration/command"): "the shell-integration one-liner (no secret)",
    ("GET", "/api/settings/watermark"): "everyone needs it to render the watermark",
    ("GET", "/api/replay-links"): "own replay links (filtered to visible hosts)",
    ("POST", "/api/replay-links/revoke-all"): "own replay links (only reduces access)",
    ("GET", "/api/snippets"): "shared snippet library (read by everyone)",
    ("POST", "/api/snippets"): "own snippet (stamped with created_by_id)",
    ("PATCH", "/api/snippets/{sid}"): "own snippet, or any with snippets.manage (handler)",
    ("DELETE", "/api/snippets/{sid}"): "idem",
    ("GET", "/api/fs/copy/{job_id}"): "own copy job (jobs carry the starter's user id)",
    ("DELETE", "/api/fs/copy/{job_id}"): "own copy job",
    ("POST", "/api/fs/copy/{job_id}/retry"): "own copy job; BOTH hosts re-checked in the handler",
    ("GET", "/api/me/permissions"): "own effective permissions (UI gating)",
    ("POST", "/api/webauthn/register/options"): "own passkey enrolment",
    ("POST", "/api/webauthn/register/verify"): "own passkey enrolment (second gate)",
    ("GET", "/api/webauthn/credentials"): "own passkeys",
    ("DELETE", "/api/webauthn/credentials/{cred_id}"): "own passkey (reauth + second gate)",
}


def _route_methods(route) -> tuple:
    m = getattr(route, "methods", None)
    return tuple(sorted(m)) if m else ("WS",)


def route_spec(route) -> tuple[str, Any]:
    """('perm', RouteSpec) | ('public', reason) | ('self', reason) | ('none', None)."""
    ep = getattr(route, "endpoint", None)
    s = spec_of(ep)
    if s is not None:
        return "perm", s
    for dep in getattr(route, "dependencies", []) or []:
        s = spec_of(getattr(dep, "dependency", None))
        if s is not None:
            return "perm", s
    dependant = getattr(route, "dependant", None)
    found = []
    if dependant is not None:
        for d in dependant.dependencies:
            s = spec_of(d.call)
            if s is not None:
                found.append(s)
    if len(found) == 1:
        return "perm", found[0]
    if len(found) > 1:
        return "multi", found
    path = getattr(route, "path", "")
    if path in PUBLIC:
        return "public", PUBLIC[path]
    for m in _route_methods(route):
        if (m, path) in SELF:
            return "self", SELF[(m, path)]
    return "none", None


_declared_ok: dict[int, bool] = {}


async def declared(request: HTTPConnection):
    """Router-level guard (fail-closed at runtime): a route that declares no permission and is
    neither PUBLIC nor SELF answers 500 `authz.undeclared` — unusable, never open."""
    route = request.scope.get("route")
    if route is None:
        return
    key = id(route)
    ok = _declared_ok.get(key)
    if ok is None:
        kind, _ = route_spec(route)
        ok = kind in ("perm", "public", "self")
        _declared_ok[key] = ok
        if not ok:
            log.error("authz: route %s %s declares no permission — refused (fail-closed)",
                      ",".join(_route_methods(route)), getattr(route, "path", "?"))
    if not ok:
        raise ApiError(500, "authz.undeclared", "this route declares no permission")


def route_perms(routers: Iterable) -> dict:
    """{(METHOD, path): (kind, spec_or_reason)} for every route — the data behind the matrix
    test and the doc appendix (scripts/route-matrix.py)."""
    out = {}
    for rt in routers:
        for r in rt.routes:
            path = getattr(r, "path", None)
            if not path:
                continue
            kind, spec = route_spec(r)
            for m in _route_methods(r):
                if m == "HEAD":
                    continue
                out[(m, path)] = (kind, spec)
    return out


# ── roles, bindings, seeding ─────────────────────────────────────────────────────────────────
async def seed(conn) -> None:
    """Idempotent, in db.connect() after the migrations:
      1. upsert the built-in roles from the code catalogue (a new permission reaches them);
      2. once (`rbac_seeded` absent): every existing account → Owner @ all (source=migration),
         so an upgrade changes nothing for anyone — then stamp `rbac_seeded`;
      3. warn about accounts with no binding (they see an empty fleet; nothing is granted)."""
    now = time.time()
    for key in ROLE_ORDER:
        r = BUILTIN_ROLES[key]
        perms = json.dumps(sorted(r["perms"]))
        await conn.execute(
            "INSERT INTO roles(key, name, description, perms, builtin, created, updated)"
            " VALUES(?,?,?,?,1,?,?) ON CONFLICT(key) DO UPDATE SET name=excluded.name,"
            " description=excluded.description, perms=excluded.perms, builtin=1,"
            " updated=excluded.updated", (key, r["name"], r["description"], perms, now, now))
    cur = await conn.execute("SELECT value FROM app_settings WHERE key='rbac_seeded'")
    seeded = await cur.fetchone()
    await cur.close()
    if not seeded:
        cur = await conn.execute("SELECT id FROM roles WHERE key='owner'")
        owner = (await cur.fetchone())[0]
        await cur.close()
        cur = await conn.execute("SELECT id FROM users")
        uids = [r[0] for r in await cur.fetchall()]
        await cur.close()
        for uid in uids:
            await conn.execute(
                "INSERT OR IGNORE INTO role_bindings(user_id, role_id, scope_kind, scope_value,"
                " source, created) VALUES(?,?,'all','','migration',?)", (uid, owner, now))
        await conn.execute(
            "INSERT INTO app_settings(key, value) VALUES('rbac_seeded', ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(int(now)),))
        if uids:
            log.warning("roles: seeded %d existing account(s) as Owner over all hosts "
                        "(3.6 upgrade — nothing changes for them)", len(uids))
    cur = await conn.execute(
        "SELECT email FROM users u WHERE NOT EXISTS"
        " (SELECT 1 FROM role_bindings b WHERE b.user_id=u.id)")
    lonely = [r[0] for r in await cur.fetchall()]
    await cur.close()
    for e in lonely:
        log.warning("roles: account %s has no role binding — it sees an empty fleet until an "
                    "Owner or Admin grants one (or: python3 -m app.admin promote)", e)


async def role_id(key: str) -> Optional[int]:
    r = await db.fetchone("SELECT id FROM roles WHERE key=?", key)
    return r["id"] if r else None


async def owner_count(exclude_binding: Optional[int] = None,
                      exclude_user: Optional[int] = None) -> int:
    """Accounts that hold Owner @ all (the only Owner that can administer the instance)."""
    sql = ("SELECT COUNT(DISTINCT b.user_id) AS c FROM role_bindings b JOIN roles r ON r.id=b.role_id"
           " JOIN users u ON u.id=b.user_id"
           " WHERE r.key='owner' AND b.scope_kind='all' AND (b.expires IS NULL OR b.expires > ?)")
    args: list = [time.time()]
    if exclude_binding is not None:
        sql += " AND b.id<>?"
        args.append(exclude_binding)
    if exclude_user is not None:
        sql += " AND b.user_id<>?"
        args.append(exclude_user)
    row = await db.fetchone(sql, *args)
    return int(row["c"]) if row else 0


async def is_owner_user(user_id: int) -> bool:
    return (await grants_for_user(user_id)).is_owner()


def normalize_scope(kind: str, value) -> tuple[str, str]:
    kind = (kind or "").strip().lower()
    if kind not in SCOPE_KINDS:
        raise ApiError(400, "authz.badScope", "scope must be all, folder, tag or host")
    v = "" if value is None else str(value).strip()
    if kind == "all":
        return "all", ""
    if kind == "tag":
        v = v.lower()[:32]
        if not v or " " in v or "," in v:
            raise ApiError(400, "authz.badScope", "a tag scope needs one tag")
    elif kind == "folder":
        v = v[:120]
        if not v:
            raise ApiError(400, "authz.badScope", "a folder scope needs a folder name")
    elif kind == "host":
        try:
            v = str(int(v))
        except ValueError:
            raise ApiError(400, "authz.badScope", "a host scope needs a host id")
    return kind, v


def _scope_perms(grants: Grants, kind: str, value: str, ref: Optional[HostRef]) -> frozenset:
    """Host perms the granter holds over the WHOLE scope (conservative: for a folder or a tag
    only bindings at exactly that scope, or at all, count)."""
    out = set(grants.all_host_perms)
    if kind == "all":
        return frozenset(out)
    if kind == "host":
        return grants.on(ref) if ref is not None else frozenset(grants.all_host_perms)
    for b in grants.bindings:
        if b.scope_kind == kind and b.scope_value == value:
            out |= b.perms & HOST_PERMS
    return frozenset(out)


async def check_can_grant(granter: Grants, role_key: str, kind: str, value: str,
                          removing: bool = False) -> None:
    """No-escalation (§A.6.6 rule 1–2): the role's permissions must be within the granter's own,
    over the whole scope; only an Owner can hand out Owner. `removing=True`: the same rule for
    taking a binding away, except that a binding left on a host that no longer exists can be
    removed by whoever holds the role's permissions on every host."""
    if role_key not in BUILTIN_ROLES:
        raise ApiError(400, "authz.badRole", "unknown role")
    rperms = BUILTIN_ROLES[role_key]["perms"]
    if role_key == "owner" and not granter.is_owner():
        raise ApiError(403, "authz.ownerOnly", "only an Owner can grant the Owner role")
    ref = None
    if kind == "host":
        ref = await host_ref(value)
        # un host inexistent nu se acordă NICIODATĂ (id-urile se reutilizează: legătura s-ar lipi
        # de următorul host cu acelaşi id) — nici de un Owner
        if ref is None and not removing:
            raise not_found("host_id")
        seen = granter.all_host_perms if ref is None else granter.on(ref)
        if "host.view" not in seen:
            raise not_found("host_id")
    if kind == "all" and not (rperms & GLOBAL_PERMS) <= granter.global_perms:
        raise ApiError(403, "authz.escalation", "you cannot grant permissions you do not hold",
                       vars={"perm": sorted((rperms & GLOBAL_PERMS) - granter.global_perms)[0]})
    have = _scope_perms(granter, kind, value, ref)
    missing = (rperms & HOST_PERMS) - have
    if missing:
        raise ApiError(403, "authz.escalation", "you cannot grant permissions you do not hold",
                       vars={"perm": sorted(missing)[0]})


def binding_json(b: Binding) -> dict:
    return {"id": b.id, "role": b.role_key, "role_name": b.role_name,
            "scope_kind": b.scope_kind, "scope_value": b.scope_value, "source": b.source,
            "expires": b.expires}


def me_json(grants: Grants, host_refs_: dict) -> dict:
    """GET /api/me/permissions: {global, all_hosts, hosts: {id: extra perms}, bindings}.
    `hosts` lists only hosts where scoped bindings ADD to `all_hosts` (the UI unions them)."""
    hosts = {}
    for hid, ref in host_refs_.items():
        extra = grants.on(ref) - grants.all_host_perms
        if extra:
            hosts[str(hid)] = sorted(extra)
    return {"global": sorted(grants.global_perms), "all_hosts": sorted(grants.all_host_perms),
            "hosts": hosts, "bindings": [binding_json(b) for b in grants.bindings],
            "owner": grants.is_owner(), "epoch": _epoch}


def catalogue_json() -> dict:
    return {"perms": [{"id": p, "kind": k, "shell": s} for p, k, s in _CATALOGUE],
            "roles": [{"key": k, "name": BUILTIN_ROLES[k]["name"],
                       "perms": sorted(BUILTIN_ROLES[k]["perms"]),
                       "shell": bool(BUILTIN_ROLES[k]["perms"] & SHELL_PERMS)} for k in ROLE_ORDER],
            "scopes": list(SCOPE_KINDS)}
