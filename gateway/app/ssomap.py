"""SSO group → role mapping (3.6.2; design 3.6.1, docs/design/ROLES-AND-SSH.md §A.7).

An Owner/Admin maps an OIDC group name (from the id_token's `groups` claim, the same claim
`OIDC_ALLOWED_GROUPS` reads) to a role over a scope. At every SSO login AND every SSO step-up
the account's bindings with `source='sso'` are re-synced against the groups the IdP just sent:

  * a mapped group the user is in, whose binding is missing → the binding is added (source sso);
  * an sso binding whose group (or mapping) is gone → removed, at once (epoch bump: open
    terminals downgrade or close, forward tickets die, derived shares are revoked);
  * `manual` and `migration` bindings are NEVER touched; a manual binding for the same
    (role, scope) wins and no sso duplicate is created.

Fail-closed choices (each one documented in docs/ROLES.md):

  * groups claim ABSENT from the id_token → nothing changes (a misconfigured IdP scope must not
    strip everyone's access on the next login), logged as a warning; PRESENT but empty, or of a
    type we cannot read → treated as "no groups": sso bindings are removed;
  * group names: compared EXACTLY, byte for byte, with the raw claim string (no trimming, no
    Unicode normalisation, case-sensitive) — normalising the claim would alias distinct IdP groups
    (`wt-owners ` vs `wt-owners`, NFD vs NFC). A mapping name that normalisation would change, or
    that has control/format characters, is refused when the mapping is created;
  * the groups claim must be a list of strings; anything else (a bare string, an object, items
    that are not strings) is "unreadable": treated as no groups and audited;
  * an account with a usable LOCAL PASSWORD never RECEIVES roles from groups (removals still
    apply): otherwise whoever set that password (an Admin creating the account before the real
    person's first SSO sign-in adopts it by email) would inherit what the person's groups grant.
    The person removes the local password (Settings → Users & roles) to enable group roles;
  * huge claims: only the first 5000 entries are read (a truncated list can only GRANT LESS);
  * `*` = any authenticated SSO user (design §A.7, Warpgate's wildcard);
  * removing a MAPPING removes the derived bindings immediately for the users that got them
    (re-computed from the groups recorded at their last sync — removal only, never an addition
    from stale data); adding a mapping takes effect at each user's next SSO login or step-up;
  * the LAST Owner is never removed by a sync (the instance must not lock itself out): the
    binding is kept, logged as an error, audited and alerted to the security.view holders.
"""
from __future__ import annotations

import json
import logging
import time
import unicodedata
from typing import Optional

from . import audit, authz, db, email_alerts, security

log = logging.getLogger("webterm")

GROUP_MAX_LEN = 256
GROUPS_MAX = 5000
MAPPINGS_MAX = 500
WILDCARD = "*"

_last_owner_alerted: dict[int, float] = {}


def _clean_name(s: str) -> bool:
    return (0 < len(s) <= GROUP_MAX_LEN and s.isprintable()
            and not any(unicodedata.category(ch) == "Cf" for ch in s))


def normalize_group(g) -> Optional[str]:
    """Validates a group name typed into the MAPPING editor. It is never rewritten: a name that
    trimming or NFC would change is refused (None), so what is stored is exactly what the IdP
    must send. `*` = every SSO user."""
    if not isinstance(g, str):
        return None
    if g != g.strip() or unicodedata.normalize("NFC", g) != g or not _clean_name(g):
        return None
    return g


def claim_groups(groups) -> set:
    """The claim's names, RAW (exact match; oidc._claims_groups already kept only strings). A
    name that could never be a valid mapping (too long, control/format characters) is dropped —
    it cannot match anything anyway."""
    out = set()
    lst = list(groups or [])
    if len(lst) > GROUPS_MAX:
        log.warning("SSO: the groups claim has %d entries; only the first %d are read",
                    len(lst), GROUPS_MAX)
        lst = lst[:GROUPS_MAX]
    for g in lst:
        if isinstance(g, str) and g != WILDCARD and _clean_name(g):
            out.add(g)
    return out


def _label(role_name: str, kind: str, value: str) -> str:
    return "%s @ %s" % (role_name, "all hosts" if kind == "all" else "%s %s" % (kind, value))


async def _desired(groups: set, exclude_mid: Optional[int] = None) -> tuple[set, set]:
    """→ ({(role_id, kind, value)}, {matched group names}) from the CURRENT mappings (minus
    `exclude_mid`, for planning a removal)."""
    maps = await db.fetchall(
        "SELECT m.grp, m.role_id, m.scope_kind, m.scope_value FROM oidc_group_roles m"
        " JOIN roles r ON r.id = m.role_id WHERE m.id<>?", exclude_mid or 0)
    hosts = {r["id"] for r in await db.fetchall("SELECT id FROM hosts")}
    desired, matched = set(), set()
    for m in maps:
        g = m["grp"]
        if g != WILDCARD and g not in groups:
            continue
        kind, value = m["scope_kind"], m["scope_value"] or ""
        if kind not in authz.SCOPE_KINDS:
            continue
        if kind == "host":
            try:
                if int(value) not in hosts:
                    continue               # never bind a host id that does not exist (ids recycle)
            except ValueError:
                continue
        desired.add((m["role_id"], kind, value))
        if g != WILDCARD:
            matched.add(g)
    return desired, matched


async def _role_names() -> dict:
    return {r["id"]: (r["key"] or "", r["name"] or "") for r in
            await db.fetchall("SELECT id, key, name FROM roles")}


async def _apply_locked(uid: int, desired: set, *, remove_only: bool,
                        store_groups: Optional[set] = None) -> dict:
    """Make the user's sso bindings equal `desired` (or only remove, `remove_only`). Caller
    holds authz._lock. Manual/migration bindings are read only to avoid duplicates."""
    rows = await db.fetchall(
        "SELECT id, role_id, scope_kind, scope_value, source FROM role_bindings WHERE user_id=?",
        uid)
    sso = {(r["role_id"], r["scope_kind"], r["scope_value"] or ""): r["id"]
           for r in rows if (r["source"] or "") == "sso"}
    other = {(r["role_id"], r["scope_kind"], r["scope_value"] or "")
             for r in rows if (r["source"] or "") != "sso"}
    names = await _role_names()
    owner_rid = next((rid for rid, (k, _n) in names.items() if k == "owner"), None)
    added, removed, kept = [], [], []
    now = time.time()
    if not remove_only:
        for t in sorted(desired - set(sso) - other):
            await db.execute(
                "INSERT OR IGNORE INTO role_bindings(user_id, role_id, scope_kind, scope_value,"
                " source, created) VALUES(?,?,?,?,'sso',?)", uid, t[0], t[1], t[2], now)
            added.append(t)
    for t, bid in sorted(sso.items()):
        if t in desired:
            continue
        if t[0] == owner_rid and t[1] == "all" and await authz.owner_count(exclude_binding=bid) < 1:
            kept.append(t)                 # never lock the instance out (docs/ROLES.md)
            continue
        await db.execute("DELETE FROM role_bindings WHERE id=? AND user_id=? AND source='sso'",
                         bid, uid)
        removed.append(t)
    if store_groups is not None:
        await db.execute("UPDATE users SET sso_groups=?, sso_synced=? WHERE id=?",
                         json.dumps(sorted(store_groups)), now, uid)
    if added or removed:
        authz.bump_epoch()
        security.bump_forward_epoch(uid)
        from . import api                  # late: api imports this module's callers
        await api._revoke_unauthorized_derived(uid)

    def lab(t):
        return _label(names.get(t[0], ("", "?"))[1], t[1], t[2])
    return {"added": [lab(t) for t in added], "removed": [lab(t) for t in removed],
            "kept_last_owner": [lab(t) for t in kept], "skipped": False}


async def has_local_password(uid: int) -> bool:
    """True unless the account was provisioned by SSO or its owner removed the local password.
    Unknown / NULL = True (fail-closed: pre-3.6.2 accounts count as having one)."""
    r = await db.fetchone("SELECT local_password FROM users WHERE id=?", uid)
    return r is None or r["local_password"] is None or bool(r["local_password"])


async def sync_user(uid: int, email: str, groups, *, ip: str, via: str,
                    readable: bool = True) -> dict:
    """Re-sync one account at an SSO login / step-up. `groups=None` = the claim was ABSENT.
    `readable=False` = the claim was there but not a list of strings (treated as no groups)."""
    if not readable:
        log.warning("SSO: the groups claim for %s is not a list of strings — treated as NO "
                    "groups (its SSO-derived roles are removed)", email)
        await audit.record(time.time(), email, ip, "GET", "/api/oidc/callback", 200,
                           "SSO groups claim unreadable (%s): treated as no groups" % via,
                           actor_id=uid)
    if groups is None:
        log.warning("SSO: the id_token for %s has no `groups` claim — its SSO-derived roles are "
                    "left unchanged. Make the IdP send `groups` (Authentik: the 'profile' scope "
                    "mapping) for the group → role mapping to work.", email)
        await audit.record(time.time(), email, ip, "GET", "/api/oidc/callback", 200,
                           "SSO roles NOT synced (%s): no groups claim" % via, actor_id=uid)
        return {"added": [], "removed": [], "kept_last_owner": [], "skipped": True}
    gs = claim_groups(groups)
    async with authz._lock:
        desired, matched = await _desired(gs)
        local_pw = await has_local_password(uid)
        if local_pw:
            have = {(r["role_id"], r["scope_kind"], r["scope_value"] or "") for r in await db.fetchall(
                "SELECT role_id, scope_kind, scope_value FROM role_bindings WHERE user_id=?", uid)}
            skipped = desired - have
        res = await _apply_locked(uid, desired, remove_only=local_pw, store_groups=matched)
    if local_pw and skipped:
        names = await _role_names()
        labs = [_label(names.get(t[0], ("", "?"))[1], t[1], t[2]) for t in sorted(skipped)]
        res["skipped_local_password"] = labs
        log.warning("sso.sync.skippedLocalPassword: %s has a local password, so its groups give "
                    "it no roles (would have added: %s). It can remove the local password in "
                    "Settings → Users & roles to receive them.", email, ", ".join(labs))
        await audit.record(time.time(), email, ip, "GET", "/api/oidc/callback", 200,
                           ("sso.sync.skippedLocalPassword (%s): not added %s" % (via, labs))[:480],
                           actor_id=uid)
    _report(uid, email, ip, via, res)
    if res["added"] or res["removed"] or res["kept_last_owner"]:
        await audit.record(time.time(), email, ip, "GET", "/api/oidc/callback", 200,
                           ("SSO roles synced (%s): +%s -%s%s" % (
                               via, res["added"] or "[]", res["removed"] or "[]",
                               (" KEPT last Owner %s" % res["kept_last_owner"])
                               if res["kept_last_owner"] else ""))[:480], actor_id=uid)
    return res


async def _sso_users():
    return await db.fetchall(
        "SELECT DISTINCT u.id, u.email, u.sso_groups FROM users u JOIN role_bindings b"
        " ON b.user_id = u.id WHERE b.source='sso'")


def _stored(u) -> set:
    try:
        return {g for g in json.loads(u["sso_groups"] or "[]") if isinstance(g, str)}
    except (TypeError, ValueError):
        return set()                       # unreadable = no groups (removal only, fail-closed)


async def prune_plan(exclude_mid: int) -> list:
    """Dry run of prune_locked() as if mapping `exclude_mid` were gone: [uid] of the accounts
    that would lose a binding. Caller holds authz._lock. Nothing is written."""
    out = []
    for u in await _sso_users():
        desired, _m = await _desired(_stored(u), exclude_mid)
        rows = await db.fetchall("SELECT role_id, scope_kind, scope_value FROM role_bindings"
                                 " WHERE user_id=? AND source='sso'", u["id"])
        if any((r["role_id"], r["scope_kind"], r["scope_value"] or "") not in desired for r in rows):
            out.append(u["id"])
    return out


async def prune_locked() -> list:
    """After a mapping was removed: drop, for every account holding sso bindings, those no
    remaining mapping still justifies (from the groups recorded at its last sync). Removal only.
    Caller holds authz._lock. → [(uid, email, result)] for the accounts that changed."""
    out = []
    for u in await _sso_users():
        desired, _m = await _desired(_stored(u))
        res = await _apply_locked(u["id"], desired, remove_only=True)
        if res["removed"] or res["kept_last_owner"]:
            out.append((u["id"], u["email"], res))
    return out


def _report(uid: int, email: str, ip: str, via: str, res: dict) -> None:
    if res["added"] or res["removed"]:
        what = "SSO roles synced for %s: added %s, removed %s" % (
            email, ", ".join(res["added"]) or "none", ", ".join(res["removed"]) or "none")
        log.warning(what + " (%s)" % via)
        params = {"account": email, "added": ", ".join(res["added"]) or "—",
                  "removed": ", ".join(res["removed"]) or "—"}
        email_alerts.notify_security_change(what, ip, email, fleet=True,
                                            what_key="sso_roles_synced", what_params=params)
        email_alerts.notify_security_change("your access changed after an SSO sign-in", ip, email,
                                            user_id=uid, what_key="sso_access_changed",
                                            what_params=params)
    if res["kept_last_owner"]:
        report_last_owner(uid, email, ip, res["kept_last_owner"])


def report_last_owner(uid: int, email: str, ip: str, kept: list) -> None:
    log.error("SSO: %s is the LAST Owner and its only Owner binding comes from SSO, but its "
              "group no longer maps to Owner — the binding was KEPT so the instance is not "
              "locked out. Make another account Owner (Settings → Users & roles, or "
              "python3 -m app.admin promote), then fix the mapping.", email)
    now = time.time()
    if now - _last_owner_alerted.get(uid, 0) < 3600:
        return                             # once an hour per account, not at every login
    _last_owner_alerted[uid] = now
    email_alerts.notify_security_change(
        "the last Owner (%s) lost its SSO Owner group; the binding was kept" % email, ip, email,
        fleet=True, severity="critical", what_key="sso_last_owner_kept",
        what_params={"account": email, "binding": ", ".join(kept)})
