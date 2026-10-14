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
import unicodedata
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
    # 3.6.7: open a terminal on the gateway host with the TLS renewal command typed (it runs
    # `sudo …/cert-renew.sh`, which edits the ACME store and restarts Traefik). Owner only.
    # 3.6.8: the same permission types a System health fix (healthcmd.py allow-list) there —
    # one Owner-only door for "a root command typed on the gateway host", not two.
    ("certs.renew", "global", False),
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
_ADMIN = _OWNER - {"history.clear", "backups.manage", "signing.manage", "certs.renew"}

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

# 3.6.10 — what an automation token can NEVER hold, whatever role it is given and whoever created
# it. Today the legacy ceiling above already excludes all of it (a token only reaches the four
# token routes); this list makes the rule explicit and keeps it true if a later release widens a
# ceiling: administering people, roles, settings, tokens, shares, backups, signing, certificates,
# the history wipe and new hosts, plus the host permissions that hand out access or change who
# can reach a host (deploy keys, writable shares, forwards, the 2FA flag/provisioning, other
# people's sessions). `security.view` stays reachable: the legacy `read` scope has always carried
# it (status details), and removing it would silently empty existing monitoring tokens.
TOKEN_NEVER = frozenset({
    "users.manage", "roles.manage", "settings.manage", "tokens.create", "tokens.manage",
    "shares.manage", "snippets.manage", "history.clear", "backups.manage", "signing.manage",
    "certs.renew", "hosts.create", "hosts.export", "audit.view",
    "host.admin", "host.edit", "deploykey.manage", "share.live_write", "session.manage",
    "forward.manage", "toolbox.manage",
})
# A token is never "the owner": the Owner role is refused as a token role at creation (400). A
# token row that ALREADY names it (created through the API before 3.6.10) keeps working exactly as
# before — the Owner role was no cap at all — so it is read as "no role cap": still bounded by its
# legacy read/run ceiling, TOKEN_NEVER and its creator. The boot logs a warning listing them.
TOKEN_ROLE_REFUSED = frozenset({"owner"})

# ── epoch + cache ────────────────────────────────────────────────────────────────────────────
# Single uvicorn process (Dockerfile CMD, no --workers): an in-memory epoch is coherent. The
# admin CLI runs in another process; it writes `app_settings['authz_epoch']`, which the reaper
# loop polls (`poll_external_epoch`), and the cache also expires on its own after _CACHE_TTL.
_epoch = 0
_external_epoch = ""
_CACHE_TTL = 30.0
# user id → (epoch, monotonic load time, the earliest `expires` among the bindings it used or
# None, Grants). 3.6.10 (review): a cached entry is stale the second its earliest binding ends —
# without that, an expired binding kept working for up to _CACHE_TTL.
_cache: dict[int, tuple[int, float, Optional[float], "Grants"]] = {}
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
    role_id: int = 0

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
        "SELECT b.id, b.scope_kind, b.scope_value, b.source, b.expires, b.role_id,"
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
                           r["expires"], r["role_id"]))
    return out


def earliest_expiry(bindings: Iterable) -> Optional[float]:
    ends = [b.expires for b in bindings if b.expires is not None]
    return min(ends) if ends else None


# 3.6.10 (review): live sockets (terminals, forwards) re-check on an epoch bump or every
# WS_REVALIDATE_SECS. So that a time-bound binding ends for them at the second too, not up to a
# minute later, loading grants with a time-bound binding arms one timer per end time that wakes
# every socket right after it; the re-check then reloads (the cache entry is stale by then).
_EXPIRY_TIMERS_MAX = 2048
_expiry_timers: dict[float, tuple] = {}


def _wake_waiters(ts: float) -> None:
    _expiry_timers.pop(ts, None)
    for ev in list(_waiters):
        ev.set()


def _arm_expiry_wake(ts: Optional[float]) -> None:
    if ts is None:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    old = _expiry_timers.get(ts)
    if old is not None and old[0] is loop and not loop.is_closed():
        return
    if len(_expiry_timers) >= _EXPIRY_TIMERS_MAX:
        # bounded; past the bound the 60 s re-check (and the stale cache entry) still apply
        for k, (lp, h) in list(_expiry_timers.items()):
            if lp.is_closed() or k <= time.time():
                h.cancel()
                _expiry_timers.pop(k, None)
        if len(_expiry_timers) >= _EXPIRY_TIMERS_MAX:
            return
    delay = max(0.0, ts - time.time()) + 0.05
    _expiry_timers[ts] = (loop, loop.call_later(delay, _wake_waiters, ts))


async def grants_for_user(user_id: Optional[int]) -> Grants:
    if not user_id:
        return Grants(None)
    hit = _cache.get(user_id)
    now = time.monotonic()
    if (hit and hit[0] == _epoch and now - hit[1] < _CACHE_TTL
            and (hit[2] is None or time.time() < hit[2])):
        return hit[3]
    bindings = await _load_bindings(user_id)
    g = Grants.from_bindings(user_id, bindings)
    ends = earliest_expiry(bindings)
    _cache[user_id] = (_epoch, now, ends, g)
    _arm_expiry_wake(ends)
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
            ceiling = set()                # the role is gone: nothing (fail-closed)
        elif r["builtin"] and (r["key"] or "") in TOKEN_ROLE_REFUSED:
            pass                           # pre-3.6.10 Owner-role token: no role cap (see above)
        elif r["builtin"] and r["key"] in BUILTIN_ROLES:
            ceiling &= BUILTIN_ROLES[r["key"]]["perms"]
        else:
            try:
                ceiling &= {p for p in json.loads(r["perms"] or "[]") if p in PERMS}
            except (TypeError, ValueError):
                ceiling = set()
    ceiling = frozenset(ceiling) - TOKEN_NEVER
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
    "/agent/python/{target}": ("portable Python for old hosts (3.6.9): authenticated with the "
                               "HOST's agent token in the handler; pinned files only, SHA-256 "
                               "verified before caching and again on the host"),
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
    ("GET", "/api/authz/explain"): ("own access on a host you can see (3.6.10); another account's "
                                    "only with users.manage, checked in the handler; a host the "
                                    "caller cannot see is 404"),
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


_AUTH_DEPS = ("require_user", "require_user_ws")


def _dep_calls(dependant, acc=None) -> list:
    acc = [] if acc is None else acc
    for d in getattr(dependant, "dependencies", []) or []:
        acc.append(d.call)
        _dep_calls(d, acc)
    return acc


def has_auth_dep(route) -> bool:
    """Arborele de dependenţe al rutei autentifică: un `perm()` (care cheamă el însuşi
    `require_user` / tokenul) sau `security.require_user[_ws]` direct. Un handler WebSocket
    declarat cu `ws_perm` se autentifică în corp (dependenţele nu pot închide socketul cu codurile
    noastre) — acolo marcajul e declaraţia."""
    if spec_of(getattr(route, "endpoint", None)) is not None:
        return True
    for call in _dep_calls(getattr(route, "dependant", None)):
        if spec_of(call) is not None or getattr(call, "__name__", "") in _AUTH_DEPS:
            return True
    return False


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
        # SELF = „doar datele proprii" — dar tot AUTENTIFICAT: o rută SELF fără dependenţă de
        # autentificare e la fel de nedeclarată ca una fără nimic (fail-closed)
        ok = kind == "public" or (kind in ("perm", "self") and has_auth_dep(route))
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
    # 3.6.10 (review): tokens created with the Owner role before it was refused keep working as
    # before (no role cap); say so once per boot so the Owner can recreate them narrower
    try:
        cur = await conn.execute(
            "SELECT t.id, t.name FROM api_tokens t JOIN roles r ON r.id=t.role_id"
            " WHERE r.key='owner' AND r.builtin=1 AND t.expires > ? ORDER BY t.id", (now,))
        legacy_owner = [(r[0], r[1]) for r in await cur.fetchall()]
        await cur.close()
    except Exception:                      # noqa: BLE001 — a warning must never stop the boot
        legacy_owner = []
    if legacy_owner:
        log.warning("tokens: %d automation token(s) carry the Owner role from before 3.6.10 (%s); "
                    "they work as before (no role cap: read/run scopes and their creator still "
                    "bound them), but new tokens cannot have it — recreate them with a narrower "
                    "role", len(legacy_owner), ", ".join(
                        "#%d %r" % (i, (n or "")[:60]) for i, n in legacy_owner[:20])
                    + (" …" if len(legacy_owner) > 20 else ""))
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
    """Accounts that hold a PERMANENT Owner @ all (the only Owner that can administer the
    instance). 3.6.10: a time-bound Owner binding does not count — "the last Owner cannot be
    removed" means the last one that will still be there tomorrow; otherwise removing the only
    permanent Owner next to a 4-hour one would lock the instance out when the 4 hours end."""
    sql = ("SELECT COUNT(DISTINCT b.user_id) AS c FROM role_bindings b JOIN roles r ON r.id=b.role_id"
           " JOIN users u ON u.id=b.user_id"
           " WHERE r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL")
    args: list = []
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


# ── custom roles (3.6.2) ─────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class RoleInfo:
    """A role as the grant rules see it. Built-in perms always come from the code (§A.3)."""
    id: int
    key: str                  # owner|admin|operator|viewer for built-ins; '' for a custom role
    name: str
    perms: frozenset
    builtin: bool
    description: str = ""


ROLE_NAME_MAX = 60
ROLE_DESC_MAX = 300
CUSTOM_ROLES_MAX = 200        # a bound on the table (the editor is an admin, still: no unbounded rows)


def _row_role(r) -> RoleInfo:
    if r["builtin"] and r["key"] in BUILTIN_ROLES:
        perms = BUILTIN_ROLES[r["key"]]["perms"]
    else:
        try:
            perms = frozenset(p for p in json.loads(r["perms"] or "[]") if p in PERMS)
        except (TypeError, ValueError):
            perms = frozenset()            # unreadable = no permissions (fail-closed)
    return RoleInfo(r["id"], r["key"] or "", r["name"] or "", perms,
                    bool(r["builtin"]) and (r["key"] in BUILTIN_ROLES),
                    r["description"] or "")


async def role_by_id(rid) -> Optional[RoleInfo]:
    try:
        rid = int(rid)
    except (TypeError, ValueError):
        return None
    r = await db.fetchone("SELECT id, key, name, description, perms, builtin FROM roles WHERE id=?",
                          rid)
    return _row_role(r) if r else None


async def resolve_role(key: str = "", rid=0) -> RoleInfo:
    """The role a request names: a built-in `key`, or any role by `role_id`. Unknown → 400."""
    key = (key or "").strip().lower()
    info = None
    if rid:
        info = await role_by_id(rid)
        if info is not None and key and info.key != key:
            info = None                    # contradictory request: refuse, do not guess
    elif key in BUILTIN_ROLES:
        r = await db.fetchone(
            "SELECT id, key, name, description, perms, builtin FROM roles WHERE key=?", key)
        info = _row_role(r) if r else None
    if info is None:
        raise ApiError(400, "authz.badRole", "unknown role")
    return info


def _as_role(role) -> RoleInfo:
    if isinstance(role, RoleInfo):
        return role
    if role not in BUILTIN_ROLES:
        raise ApiError(400, "authz.badRole", "unknown role")
    return RoleInfo(0, role, BUILTIN_ROLES[role]["name"], BUILTIN_ROLES[role]["perms"], True)


# Confusabile (revizuirea 3.6.2): „Оwner" cu O chirilic arăta în UI exact ca rolul predefinit.
# Un schelet mic, deliberat: literele chirilice/greceşti care arată ca latine → latină. Nu e
# tabelul Unicode complet (UTS #39), dar acoperă alfabetele în care există sosii plauzibile
# pentru numele noastre; un nume cu litere din MAI MULTE scripturi e refuzat oricum.
_CONFUSABLE = str.maketrans({
    # chirilic
    "а": "a", "в": "b", "с": "c", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k", "м": "m",
    "н": "h", "о": "o", "р": "p", "ѕ": "s", "т": "t", "у": "y", "х": "x", "ԁ": "d", "ԛ": "q",
    "ԝ": "w", "ӏ": "l", "ь": "b", "г": "r", "п": "n",
    # grecesc
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ω": "w", "μ": "u", "ζ": "z",
    # cifre / latine care se confundă
    "0": "o", "1": "l", "ı": "i",
})


def role_name_skeleton(name: str) -> str:
    """Scheletul unui nume de rol: fără caractere de format (zero-width…), NFKC, casefold,
    confusabilele de mai sus → latină, fără spaţii. Două nume cu acelaşi schelet se confundă."""
    s = "".join(ch for ch in str(name) if unicodedata.category(ch) != "Cf")
    s = unicodedata.normalize("NFKC", s).casefold()
    s = unicodedata.normalize("NFKC", s.translate(_CONFUSABLE))
    return "".join(s.split())


def _scripts(name: str) -> set:
    out = set()
    for ch in name:
        if ch.isalpha():
            n = unicodedata.name(ch, "")
            out.add(n.split(" ", 1)[0] if n else "?")
    return out


def check_role_name_confusable(name: str, others) -> None:
    """400 `role.nameConfusable`: litere din mai multe scripturi, sau un schelet egal cu al unui
    rol predefinit (cheie sau nume) ori al altui rol existent (`others` = numele lor)."""
    if len(_scripts(name)) > 1:
        raise ApiError(400, "role.nameConfusable",
                       "the name mixes letters from several alphabets")
    sk = role_name_skeleton(name)
    reserved = {role_name_skeleton(k) for k in BUILTIN_ROLES} | {
        role_name_skeleton(r["name"]) for r in BUILTIN_ROLES.values()}
    if sk in reserved or sk in {role_name_skeleton(o) for o in others}:
        raise ApiError(400, "role.nameConfusable",
                       "the name looks like the name of another role")


def validate_role_fields(name, description, perms) -> tuple[str, str, frozenset]:
    """Name (1–60 printable chars), description (≤ 300), perms (non-empty, every id in the
    catalogue). Anything unknown is refused, never silently dropped: a typo must not save a
    role that differs from what the editor meant."""
    name = " ".join(str(name or "").split())
    if not name or len(name) > ROLE_NAME_MAX or not name.isprintable():
        raise ApiError(400, "role.badName", "give the role a name (1–60 printable characters)")
    description = str(description or "").strip()
    if len(description) > ROLE_DESC_MAX or not description.replace("\n", " ").isprintable():
        raise ApiError(400, "role.badDescription", "the description is too long (300 characters)")
    if not isinstance(perms, (list, tuple, set, frozenset)):
        raise ApiError(400, "role.badPerm", "permissions must be a list")
    out = set()
    for p in perms:
        if not isinstance(p, str) or p not in PERMS:
            raise ApiError(400, "role.badPerm", "unknown permission",
                           vars={"perm": str(p)[:40]})
        out.add(p)
    if not out:
        raise ApiError(400, "role.noPerms", "a role needs at least one permission")
    return name, description, frozenset(out)


def held_everywhere(g: Grants) -> frozenset:
    """What a principal holds over the WHOLE instance: global perms + host perms at scope all.
    A role definition has no scope, so this is the ceiling for editing one (§A.6.6 rule 5)."""
    return g.global_perms | g.all_host_perms


def check_can_define(editor: Grants, perms) -> None:
    """No-escalation for role definitions: every permission in the role (old AND new set when
    editing) must be one the editor holds over all hosts / the instance."""
    missing = frozenset(perms) - held_everywhere(editor)
    if missing:
        raise ApiError(403, "authz.escalation", "you cannot grant permissions you do not hold",
                       vars={"perm": sorted(missing)[0]})


def outranked_by(target: Grants, granter: Grants) -> Optional[str]:
    """First permission the TARGET account holds over the whole instance that the granter does
    not. Generalises "only an Owner touches an Owner" to custom roles: you cannot change the
    access of an account that holds more than you (otherwise a custom role with, say,
    backups.manage could be stripped by anyone with users.manage)."""
    missing = held_everywhere(target) - held_everywhere(granter)
    return sorted(missing)[0] if missing else None


async def check_target(granter: Grants, target_uid: int) -> None:
    """Shared target rule for binding changes, account deletion and role edits."""
    _cache.pop(target_uid, None)
    tg = await grants_for_user(target_uid)
    if tg.is_owner() and not granter.is_owner():
        raise ApiError(403, "authz.ownerOnly", "only an Owner can change an Owner's access")
    p = outranked_by(tg, granter)
    if p:
        raise ApiError(403, "authz.outranked",
                       "that account holds permissions you do not (%s)" % p, vars={"perm": p})


async def check_can_grant(granter: Grants, role, kind: str, value: str,
                          removing: bool = False) -> None:
    """No-escalation (§A.6.6 rule 1–2): the role's permissions must be within the granter's own,
    over the whole scope; only an Owner can hand out Owner. `removing=True`: the same rule for
    taking a binding away, except that a binding left on a host that no longer exists can be
    removed by whoever holds the role's permissions on every host. `role` is a built-in key or
    a RoleInfo (custom roles, 3.6.2) — the same rule for both."""
    info = _as_role(role)
    role_key = info.key
    rperms = info.perms
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


# ── a grant never outlives the granter's authority (3.6.10 review) ───────────────────────────
# Without this, a time-bound Admin could create a PERMANENT Admin (or two time-bound Admins could
# make each other permanent): "4 hours of Admin" became forever. The rule, fail-closed: when the
# authority for a grant (users.manage at scope all + the granting check above, Owner included)
# holds only thanks to time-bound bindings, the grant may not end later than the moment that
# authority ends — and "permanent" (incl. an SSO group mapping, always permanent) is refused.
def _grant_ok(g: Grants, info: "RoleInfo", kind: str, value: str, ref: Optional[HostRef]) -> bool:
    """`check_can_grant` + users.manage, as a yes/no on a given Grants (no I/O)."""
    if "users.manage" not in g.global_perms:
        return False
    if info.key == "owner" and not g.is_owner():
        return False
    if kind == "host":
        seen = g.all_host_perms if ref is None else g.on(ref)
        if "host.view" not in seen:
            return False
    if kind == "all" and not (info.perms & GLOBAL_PERMS) <= g.global_perms:
        return False
    return (info.perms & HOST_PERMS) <= _scope_perms(g, kind, value, ref)


def _alive_until(g: Grants, t: Optional[float]) -> Grants:
    """The granter's grants counting only bindings that last at least until `t` (None =
    permanent ones only)."""
    return Grants.from_bindings(g.user_id, [b for b in g.bindings if b.expires is None
                                            or (t is not None and b.expires >= t)])


async def grant_authority_until(granter: Grants, role, kind: str, value: str) -> Optional[float]:
    """None = the granter's authority for this grant does not depend on a time-bound binding.
    Otherwise the latest moment until which it still holds (the end of the shortest-lived
    binding it needs). Call after `check_can_grant` passed on the same grants."""
    info = _as_role(role)
    ends = sorted({b.expires for b in granter.bindings if b.expires is not None}, reverse=True)
    if not ends:
        return None
    ref = await host_ref(value) if kind == "host" else None
    if _grant_ok(_alive_until(granter, None), info, kind, value, ref):
        return None
    for t in ends:
        if _grant_ok(_alive_until(granter, t), info, kind, value, ref):
            return t
    return ends[-1]                        # cannot happen after check_can_grant; fail closed


def _utc(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


def granter_expires_error(until: float) -> ApiError:
    return ApiError(403, "authz.granterExpires",
                    "your own right to grant this ends at %s; what you grant cannot outlast it "
                    "(SSO group mappings and role edits are permanent) — pick an end on or "
                    "before that, or ask someone with permanent access" % _utc(until),
                    vars={"until": _utc(until)})


async def check_grant_lifetime(granter: Grants, role, kind: str, value: str,
                               expires: Optional[float]) -> None:
    """403 `authz.granterExpires` when a grant (`expires`: its end, None = permanent) would
    outlast the granter's own authority to make it."""
    until = await grant_authority_until(granter, role, kind, value)
    if until is not None and (expires is None or expires > until):
        raise granter_expires_error(until)


def check_define_lifetime(editor: Grants, perms, used: bool) -> None:
    """Role editing: adding `perms` to a role that is IN USE grants them to its holders for as
    long as their bindings last, so the editor's authority for that (roles.manage, the perms over
    the whole instance, users.manage) must not hang on a time-bound binding. 403 otherwise."""
    if not used or not perms:
        return
    need = frozenset(perms) | {"roles.manage", "users.manage"}
    if need <= held_everywhere(_alive_until(editor, None)):
        return
    ends = [b.expires for b in editor.bindings if b.expires is not None]
    raise granter_expires_error(min(ends) if ends else time.time())


def binding_json(b: Binding) -> dict:
    return {"id": b.id, "role": b.role_key, "role_id": b.role_id, "role_name": b.role_name,
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


async def roles_json(viewer: Grants) -> dict:
    """GET /api/roles: the catalogue, the built-ins (now with their ids, so a binding can name
    any role by id) and the custom roles with how much they are used. `editable` is the
    no-escalation verdict for THIS viewer (cosmetic; the server re-checks on every write)."""
    out = catalogue_json()
    ids = {r["key"]: r["id"] for r in await db.fetchall("SELECT id, key FROM roles WHERE builtin=1")}
    for r in out["roles"]:
        r["id"] = ids.get(r["key"])
    nb = {r["role_id"]: (r["c"], r["s"] or 0) for r in await db.fetchall(
        "SELECT role_id, COUNT(*) AS c, SUM(source='sso') AS s FROM role_bindings GROUP BY role_id")}
    nm = {r["role_id"]: r["c"] for r in await db.fetchall(
        "SELECT role_id, COUNT(*) AS c FROM oidc_group_roles GROUP BY role_id")}
    held = held_everywhere(viewer)
    custom = []
    for r in await db.fetchall("SELECT id, key, name, description, perms, builtin, created, updated"
                               " FROM roles WHERE builtin=0 ORDER BY name COLLATE NOCASE, id"):
        info = _row_role(r)
        custom.append({"id": info.id, "name": info.name, "description": info.description,
                       "perms": sorted(info.perms), "shell": bool(info.perms & SHELL_PERMS),
                       "global_perms": sorted(info.perms & GLOBAL_PERMS),
                       "bindings": nb.get(info.id, (0, 0))[0],
                       "sso_bindings": nb.get(info.id, (0, 0))[1],
                       "mappings": nm.get(info.id, 0),
                       "editable": info.perms <= held,
                       "updated": r["updated"]})
    out["custom"] = custom
    return out


def catalogue_json() -> dict:
    return {"perms": [{"id": p, "kind": k, "shell": s} for p, k, s in _CATALOGUE],
            "roles": [{"key": k, "name": BUILTIN_ROLES[k]["name"],
                       "perms": sorted(BUILTIN_ROLES[k]["perms"]),
                       "shell": bool(BUILTIN_ROLES[k]["perms"] & SHELL_PERMS)} for k in ROLE_ORDER],
            "scopes": list(SCOPE_KINDS)}


# ── time-bound bindings (3.6.10, §A.10) ─────────────────────────────────────────────────────
# `role_bindings.expires` (NULL = permanent) is honoured at READ time (`_load_bindings` skips an
# expired row; a cached grant is stale from its earliest binding end), so HTTP access ends on the
# second even if the janitor is late or stopped, and a timer armed at load time wakes open
# terminals and forward sockets right then (`_arm_expiry_wake`). The janitor
# (`sweep_expired_bindings`, from main._session_reaper, every minute) tidies: it deletes the rows,
# bumps the epoch, revokes the derived access (live shares, replay links) and audits each one.
BINDING_MIN_SECONDS = 60
BINDING_MAX_DAYS = 366


def normalize_expiry(v) -> Optional[float]:
    """None/0/'' = permanent; otherwise an epoch timestamp at least a minute ahead and at most
    BINDING_MAX_DAYS away (a "temporary" grant for ten years is a permanent one in disguise)."""
    if v in (None, "", 0):
        return None
    try:
        ts = float(v)
    except (TypeError, ValueError):
        raise ApiError(400, "authz.badExpiry", "the end of a time-bound role must be a date")
    now = time.time()
    if ts != ts or ts in (float("inf"), float("-inf")) or ts < now + BINDING_MIN_SECONDS:
        raise ApiError(400, "authz.badExpiry", "the end of a time-bound role must be in the future")
    if ts > now + BINDING_MAX_DAYS * 86400:
        raise ApiError(400, "authz.expiryTooFar",
                       "a time-bound role lasts at most %d days" % BINDING_MAX_DAYS,
                       vars={"days": BINDING_MAX_DAYS})
    return ts


async def check_owner_expiry(role, kind: str, expires: Optional[float], target_uid: int,
                             exclude_binding: Optional[int] = None) -> None:
    """The system must never lock itself out: an EXPIRING Owner @ all is allowed only while
    another account keeps a PERMANENT Owner @ all. `exclude_binding` = an existing binding that
    is being made time-bound (otherwise: a new binding for `target_uid`). Call under `_lock`."""
    info = _as_role(role)
    if info.key != "owner" or kind != "all" or expires is None:
        return
    if exclude_binding is not None:
        left = await owner_count(exclude_binding=exclude_binding)
    else:
        left = await owner_count(exclude_user=target_uid)
    if left < 1:
        raise ApiError(400, "authz.lastOwner",
                       "the last permanent Owner cannot be made time-bound")


async def sweep_expired_bindings() -> list:
    """Delete expired bindings → [{user_id, email, role, scope_kind, scope_value, source,
    expires}] (the caller audits and revokes derived access). Bumps the epoch when any went."""
    now = time.time()
    out = []
    async with _lock:
        rows = await db.fetchall(
            "SELECT b.id, b.user_id, b.scope_kind, b.scope_value, b.source, b.expires,"
            " r.key AS role_key, r.name AS role_name, u.email FROM role_bindings b"
            " LEFT JOIN roles r ON r.id=b.role_id LEFT JOIN users u ON u.id=b.user_id"
            " WHERE b.expires IS NOT NULL AND b.expires <= ?", now)
        for r in rows:
            await db.execute("DELETE FROM role_bindings WHERE id=? AND expires IS NOT NULL"
                             " AND expires <= ?", r["id"], now)
            out.append({"user_id": r["user_id"], "email": r["email"] or "",
                        "role": r["role_key"] or r["role_name"] or "?",
                        "scope_kind": r["scope_kind"], "scope_value": r["scope_value"] or "",
                        "source": r["source"] or "manual", "expires": r["expires"]})
        if out:
            bump_epoch()
    return out


# ── crown-jewel hosts (3.6.10, §A.11.2) ─────────────────────────────────────────────────────
# A host that runs the gateway or holds its backups IS the instance: a shell there reads the
# database and the vault key. `hosts.crown_jewel` (Owner-only to set/clear) does not change what
# anyone can do; it makes handing out a shell there a deliberate act: binding a non-Owner role
# with any ⚑ permission over a scope that includes such a host is refused (409
# `authz.crownJewel`) unless the request says `confirm_crown_jewel: true`, and the confirmed
# grant is audited as such.
CROWN_LIST_MAX = 10


def crown_risky(role) -> bool:
    """A grant that matters for a crown-jewel host: not Owner (that is already "everything"), and
    at least one shell-equivalent host permission."""
    info = _as_role(role)
    return info.key != "owner" and bool(info.perms & SHELL_PERMS & HOST_PERMS)


async def crown_hosts() -> list:
    """[(id, name, HostRef)] of the crown-jewel hosts (ephemeral rows never carry the flag)."""
    rows = await db.fetchall("SELECT id, name FROM hosts WHERE COALESCE(crown_jewel, 0)=1"
                             " AND COALESCE(ephemeral, 0)=0 ORDER BY name")
    if not rows:
        return []
    refs = await host_refs()
    return [(r["id"], r["name"], refs[r["id"]]) for r in rows if r["id"] in refs]


async def crown_hosts_in_scope(kind: str, value: str) -> list:
    probe = Binding(0, "", "", frozenset(), kind, value, "", None)
    return [(hid, name) for hid, name, ref in await crown_hosts() if probe.matches(ref)]


def crown_error(names: list) -> ApiError:
    shown = ", ".join(names[:CROWN_LIST_MAX]) + (" …" if len(names) > CROWN_LIST_MAX else "")
    return ApiError(409, "authz.crownJewel",
                    "this gives a shell on a crown-jewel host (%s); anyone with a shell there "
                    "can take over WebTerm. Confirm to grant it anyway" % shown,
                    vars={"hosts": shown, "n": len(names)})


async def check_crown(role, kind: str, value: str, confirm: bool) -> list:
    """→ the names of the crown-jewel hosts this grant covers (for the audit line) when
    confirmed; 409 when it covers any and `confirm` is not set. Call AFTER `check_can_grant`,
    which already proved the granter sees every host of the scope — the names are no oracle."""
    if not crown_risky(role):
        return []
    names = [n for _i, n in await crown_hosts_in_scope(kind, value)]
    if names and not confirm:
        raise crown_error(names)
    return names


async def crown_exposure(ref: HostRef, before: Optional[HostRef] = None) -> list:
    """Bindings and SSO mappings that give a NON-Owner a shell on the host `ref` describes:
    [{kind: 'binding'|'mapping', who, role, scope_kind, scope_value}]. With `before`, only those
    that did NOT already match it there (a crown-jewel host moved into a new folder/tag)."""
    out = []
    now = time.time()

    def hits(info, kind, value) -> bool:
        b = Binding(0, info.key, info.name, info.perms, kind, value or "", "", None)
        return crown_risky(info) and b.matches(ref) and not (before is not None and b.matches(before))

    for r in await db.fetchall(
            "SELECT b.scope_kind, b.scope_value, b.expires, u.email, r.id, r.key, r.name,"
            " r.description, r.perms, r.builtin FROM role_bindings b JOIN roles r ON r.id=b.role_id"
            " JOIN users u ON u.id=b.user_id ORDER BY u.email"):
        if r["expires"] is not None and r["expires"] <= now:
            continue
        info = _row_role(r)
        if hits(info, r["scope_kind"], r["scope_value"]):
            out.append({"kind": "binding", "who": r["email"], "role": info.key or info.name,
                        "scope_kind": r["scope_kind"], "scope_value": r["scope_value"] or ""})
    for r in await db.fetchall(
            "SELECT m.grp, m.scope_kind, m.scope_value, r.id, r.key, r.name, r.description,"
            " r.perms, r.builtin FROM oidc_group_roles m JOIN roles r ON r.id=m.role_id"
            " ORDER BY m.grp"):
        info = _row_role(r)
        if hits(info, r["scope_kind"], r["scope_value"]):
            out.append({"kind": "mapping", "who": r["grp"], "role": info.key or info.name,
                        "scope_kind": r["scope_kind"], "scope_value": r["scope_value"] or ""})
    return out


# ── explain access (3.6.10, §A.9) ───────────────────────────────────────────────────────────
async def explain(target_uid: int, host_id: int, ref: HostRef) -> dict:
    """Why the account has (or lacks) what it has on ONE host. The CALLER's authorization (self,
    or users.manage + the host visible to the caller) is the route's job; this only reads.

    Only bindings that MATCH the host are listed (a binding over another folder says nothing
    about this host, and could name scopes the caller cannot see). Expired bindings that match
    are listed as ignored, so "it expired" is an answer, not a mystery."""
    now = time.time()
    rows = await db.fetchall(
        "SELECT b.id AS bid, b.scope_kind, b.scope_value, b.source, b.expires,"
        " r.id AS id, r.key, r.name, r.description, r.perms, r.builtin FROM role_bindings b"
        " JOIN roles r ON r.id = b.role_id WHERE b.user_id=? ORDER BY b.id", target_uid)
    u = await db.fetchone("SELECT sso_subject, sso_groups, COALESCE(local_password, 1) AS lp"
                          " FROM users WHERE id=?", target_uid)
    try:
        groups = {g for g in json.loads((u["sso_groups"] if u else None) or "[]")
                  if isinstance(g, str)}
    except (TypeError, ValueError):
        groups = set()
    maps: dict = {}
    for m in await db.fetchall("SELECT grp, role_id, scope_kind, scope_value FROM oidc_group_roles"):
        maps.setdefault((m["role_id"], m["scope_kind"], m["scope_value"] or ""), []).append(m["grp"])
    bindings, notes, live = [], [], []
    for r in rows:
        if r["scope_kind"] not in SCOPE_KINDS:
            continue
        info = _row_role(r)
        b = Binding(r["bid"], info.key, info.name, info.perms, r["scope_kind"],
                    r["scope_value"] or "", r["source"] or "manual", r["expires"], info.id)
        if not b.matches(ref):
            continue
        expired = r["expires"] is not None and r["expires"] <= now
        item = dict(binding_json(b), perms=sorted(info.perms & HOST_PERMS), expired=expired,
                    shell=bool(info.perms & SHELL_PERMS & HOST_PERMS),
                    # a CUSTOM role with instance permissions bound below `all` is a likely
                    # mistake worth a note; the built-ins (Operator's tokens.create, an Admin over
                    # a folder) are documented behaviour, and the note would only be noise
                    ignored_global=(sorted(info.perms & GLOBAL_PERMS)
                                    if b.scope_kind != "all" and not info.builtin else []))
        if b.source == "sso":
            item["sso_groups"] = sorted(
                g for g in maps.get((info.id, b.scope_kind, b.scope_value), [])
                if g == "*" or g in groups)
        bindings.append(item)
        if expired:
            notes.append({"code": "expiredIgnored", "binding": b.id})
            continue
        live.append(b)
        if item["ignored_global"]:
            notes.append({"code": "globalNeedsAll", "binding": b.id})
    effective = sorted(Grants.from_bindings(target_uid, live).on(ref))
    if not effective:
        notes.append({"code": "noAccess"})
    h = await db.fetchone("SELECT name, COALESCE(require_2fa, 0) AS r2, COALESCE(crown_jewel, 0)"
                          " AS cj FROM hosts WHERE id=?", host_id)
    if h and h["cj"]:
        notes.append({"code": "crownJewel"})
    if h and h["r2"] and effective:
        notes.append({"code": "stepUp"})
    if u and u["sso_subject"] and u["lp"]:
        notes.append({"code": "ssoLocalPassword"})
    ntok = (await db.fetchone("SELECT COUNT(*) AS c FROM api_tokens WHERE created_by_id=?"
                              " AND expires > ?", target_uid, now))["c"]
    if ntok:
        notes.append({"code": "tokensCapped", "n": ntok})
    return {"host": {"id": host_id, "name": h["name"] if h else "",
                     "folder": ref.folder, "tags": sorted(ref.tags),
                     "crown_jewel": bool(h and h["cj"]), "require_2fa": bool(h and h["r2"])},
            "bindings": bindings, "effective": effective,
            "shell": bool(set(effective) & SHELL_PERMS), "notes": notes}
