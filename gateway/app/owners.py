"""The last-Owner / break-glass rule (INV-07, docs/design/INVARIANTS.md) in one place.

WebTerm must always keep an account that can administer it, and one that can still sign in when
the identity provider is down:

  * a PERMANENT Owner @ all — a time-bound Owner does not count (it expires), nor a disabled one;
  * the BREAK-GLASS account — a permanent Owner WITH a local password
    (COALESCE(local_password, 1)=1: NULL counts as "has one", fail closed).

Every path that could take one away asks here first: removing or time-bounding a binding
(authz), deleting or disabling an account (api, accounts / SCIM), removing a local password
(api, `admin sso-only`), SSO group sync (ssomap), System health (syshealth). The refusals are
audited and alerted from here too. The callers keep their own error types (ApiError, ScimError).

Below authz in the import order: only db, audit and email_alerts, so authz can use it. The
Owner-LEVEL checks (`authz.owner_level`, `is_owner_user`) stay in authz, because they read the
role model (Binding / Grants).
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from . import audit, db, email_alerts

log = logging.getLogger("webterm")


# ── counting ──


# INV-07 (docs/design/INVARIANTS.md): nicio acțiune nu scoate ultimul Owner / ultimul break-glass.
async def owner_count(exclude_binding: Optional[int] = None,
                      exclude_user: Optional[int] = None,
                      with_local_password: bool = False) -> int:
    """Accounts that hold a PERMANENT Owner @ all (the only Owner that can administer the
    instance). 3.6.10: a time-bound Owner binding does not count — "the last Owner cannot be
    removed" means the last one that will still be there tomorrow; otherwise removing the only
    permanent Owner next to a 4-hour one would lock the instance out when the 4 hours end.
    `with_local_password`: only the BREAK-GLASS ones — permanent Owners that can still sign in
    when the IdP is down (COALESCE(local_password, 1)=1, the same definition as
    `admin sso-only`; audit 2026-10-17 RB-01)."""
    sql = ("SELECT COUNT(DISTINCT b.user_id) AS c FROM role_bindings b JOIN roles r ON r.id=b.role_id"
           " JOIN users u ON u.id=b.user_id"
           " WHERE r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL"
           # 3.6.11: un Owner dezactivat nu poate administra nimic — nu e „încă un Owner"
           " AND COALESCE(u.disabled, 0)=0")
    args: list = []
    if with_local_password:
        sql += " AND COALESCE(u.local_password, 1)=1"
    if exclude_binding is not None:
        sql += " AND b.id<>?"
        args.append(exclude_binding)
    if exclude_user is not None:
        sql += " AND b.user_id<>?"
        args.append(exclude_user)
    row = await db.fetchone(sql, *args)
    return int(row["c"]) if row else 0


# the one message for every way out of the break-glass invariant (%s = "you are" / "this
# account is"). Two codes, one rule: `account.lastBreakGlass` when the caller's OWN account is
# the break-glass one (Remove local password), `account.lastBreakGlassTarget` when an Owner
# touches ANOTHER account (delete, remove / time-bound its Owner binding) — the UI shows
# `err.account.<code>`, and the first-person text would be wrong for the second case
# (re-review P1 RB-06).
LAST_BREAK_GLASS_DETAIL = ("%s the last permanent Owner with a local password (the break-glass "
                           "account): make another account a PERMANENT Owner with a local password "
                           "first — a time-bound Owner does not count")


async def last_break_glass(uid: int, exclude_binding: Optional[int] = None) -> bool:
    """RB-06 (audit 2026-10-17): would taking `uid` out — deleting or disabling it, or, with
    `exclude_binding`, removing / making time-bound that ONE binding of it — leave the instance
    without a break-glass account? Same definition everywhere (`owner_count(with_local_password)`,
    `admin sso-only`, System health): an ACTIVE account holding a PERMANENT Owner @ all with
    COALESCE(local_password, 1)=1 — NULL counts as "has a password" (fail closed, as
    `has_local_password`). Nothing to protect when `uid` is not such an account itself (an
    SSO-only or disabled one, or one whose Owner binding is not the one being removed): then
    the change does not touch the break-glass count, whatever that count is. Call under
    `authz._lock` wherever the caller writes."""
    row = await db.fetchone("SELECT COALESCE(disabled, 0) AS d, COALESCE(local_password, 1) AS lp"
                            " FROM users WHERE id=?", uid)
    if row is None or row["d"] or not row["lp"]:
        return False
    perm = ("SELECT 1 FROM role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=?"
            " AND r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL")
    if exclude_binding is not None:
        if await db.fetchone(perm + " AND b.id<>?", uid, exclude_binding):
            return False                    # another permanent Owner binding keeps it break-glass
    if not await db.fetchone(perm, uid):
        return False                        # not a permanent Owner at all
    return await owner_count(exclude_user=uid, with_local_password=True) < 1


async def is_permanent_owner(uid: int) -> bool:
    row = await db.fetchone(
        "SELECT 1 FROM role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=?"
        " AND r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL", uid)
    return row is not None


async def owner_ids(permanent: bool = False, with_local_password: bool = False) -> set:
    """Owner @ all (încă valabil). `permanent=True`: doar cei care vor mai fi Owner şi mâine
    (revizuirea 3.6.10: un Owner TEMPORAR nu e un cont break-glass — expiră).
    `with_local_password=True`: doar cei care pot intra şi fără IdP (COALESCE(local_password,1)=1,
    NULL = are parolă, ca `owner_count(with_local_password=True)`)."""
    return {r["user_id"] for r in await db.fetchall(
        "SELECT DISTINCT b.user_id FROM role_bindings b JOIN roles r ON r.id=b.role_id"
        " JOIN users u ON u.id=b.user_id AND COALESCE(u.disabled, 0)=0"   # 3.6.11
        " WHERE r.key='owner' AND b.scope_kind='all' AND (b.expires IS NULL OR b.expires > ?)"
        + (" AND b.expires IS NULL" if permanent else "")
        + (" AND COALESCE(u.local_password, 1)=1" if with_local_password else ""), time.time())}


# ── refusals: audit + critical alerts ──


async def report_last_owner_refused(email: str, *, actor: str, ip: str, reason: str) -> None:
    log.error("%s: refused to disable %s — it is the last permanent Owner (%s)", actor, email, reason)
    await audit.record(time.time(), actor, ip, "SCIM", "/scim/v2/Users", 403,
                       "refused to disable %s: the last permanent Owner (%s)" % (email, reason),
                       actor_id=None, via="scim")
    email_alerts.notify_security_change(
        "the identity provider tried to disable the last Owner (%s); refused" % email,
        ip, actor, fleet=True, severity="critical", what_key="scim_last_owner_refused",
        what_params={"account": email})


async def report_last_break_glass_refused(uid: int, email: str, *, actor: str, ip: str,
                                          reason: str) -> None:
    """RB-06 (audit 2026-10-17): the IdP asked to disable the last permanent Owner with a local
    password. Refused, audited and alerted as critical: an identity provider must never be
    able to lock everyone out (with that account gone, an IdP outage leaves no way in but a
    shell on the server). In practice SCIM cannot even see a local-password account
    (`_user`, adoption re-checked in the UPDATE) — this is the fail-closed backstop.
    Every refusal is audited; the CRITICAL alert goes out at most once an hour per account
    (P1 review): Authentik retries the whole sync page periodically, and a misconfigured IdP
    must not page the fleet every sync interval for the same refusal.
    Method/path/via are SCIM's: `disable` has only SCIM callers (`by` = scim*) — a future
    manual-disable route must pass its own actor and path instead."""
    log.error("%s: refused to disable %s — it is the last permanent Owner with a local password "
              "(%s)", actor, email, reason)
    await audit.record(time.time(), actor, ip, "SCIM", "/scim/v2/Users", 400,
                       "refused to disable %s: the last permanent Owner with a local password, "
                       "the break-glass account (%s)" % (email, reason), actor_id=None, via="scim")
    if not email_alerts._throttled("bg:%d" % uid, 3600):
        return
    email_alerts.notify_security_change(
        "the identity provider tried to disable the last Owner with a local password (%s), "
        "the break-glass account; refused" % email,
        ip, actor, fleet=True, severity="critical", what_key="scim_last_break_glass_refused",
        what_params={"account": email})


_last_owner_alerted: dict[int, float] = {}


def report_last_break_glass(email: str, via: str, kept: list) -> None:
    """RB-06: the mapping (or the IdP's groups) would take the Owner @ all binding of the only
    permanent Owner with a local password; it was kept so the instance stays openable without the
    IdP. Log only (the sign-in audit row already says KEPT): nothing was granted, nothing removed."""
    log.warning("SSO: kept the Owner binding of the break-glass account %s (%s) — every other "
                "permanent Owner is SSO-only; give another permanent Owner a local password before "
                "removing this one (%s)", email, ", ".join(kept), via)


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
