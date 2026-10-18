"""Disabled accounts (3.6.11) — the state SCIM `active:false` / DELETE puts an account in.

Disabling is NOT deleting: the row, its audit history, role bindings, passkeys and SSO link stay,
so an Owner (Settings → Users & roles) or the IdP (SCIM `active:true`, SCIM-managed accounts only)
can bring it back as it was. While disabled the account can do nothing:

  * it cannot sign in — password, passkey or SSO (each path refuses after verifying the
    credential, `security.create_web_session` refuses as a backstop);
  * its web sessions are deleted, its live WebSockets close at once (epoch bump → re-check →
    `session_valid` is false), its port-forward tickets die (`bump_forward_epoch`), its step-up
    windows close;
  * `authz.grants_for_user` returns nothing for it (bindings are kept, not read), so anything
    still holding its id — a cached grant, a forward re-check — finds no permission;
  * its automation tokens are REVOKED (deleted, like on account deletion — offboarding must not
    leave a credential that would come back with a re-enable), so are the group enrollment tokens
    it created, its live shares and replay links;
  * an account holding an Owner-level role given in WebTerm (not by an SSO group) is never
    disabled by the IdP (`OwnerLevel`): only an Owner takes an Owner out (§A.5);
  * the last PERMANENT Owner can never be disabled (a disabled Owner does not count as one): the
    instance must not lock itself out because an IdP said so — nor the last permanent Owner
    WITH A LOCAL PASSWORD (`LastBreakGlass`, RB-06): without it an IdP outage locks every
    Owner out.

Every change is audited and alerted to the fleet (security.view holders see it in the in-app
history, and it goes out by email/webhook like any account change).
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from . import audit, authz, db, email_alerts, security

log = logging.getLogger("webterm")


class LastOwner(Exception):
    """Disabling this account would leave no permanent Owner."""


class OwnerLevel(Exception):
    """The account holds an Owner-level role given in WebTerm: the IdP cannot disable it."""


class LastBreakGlass(Exception):
    """Disabling this account would leave no permanent Owner WITH A LOCAL PASSWORD (RB-06)."""


async def is_permanent_owner(uid: int) -> bool:
    row = await db.fetchone(
        "SELECT 1 FROM role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=?"
        " AND r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL", uid)
    return row is not None


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


async def revoke_enroll_groups(uid: int, email: str) -> int:
    """Revoke the live group enrollment tokens this account created (review 3.6.11: they enrol
    hosts into the fleet — offboarding must not leave one behind). Revoked, not deleted: the
    record of who could enrol stays. By creator ID only (re-review 3.6.11): tokens from before
    `created_by_id` got it once from their email (`authz.seed`); one whose creator could not be
    resolved then has no creator account to offboard — it keeps working until it expires or an
    Owner revokes it, and the boot log lists it. `email` is for the log line."""
    rows = await db.fetchall(
        "SELECT id FROM enroll_groups WHERE revoked=0 AND created_by_id=?", uid)
    for r in rows:
        await db.execute("UPDATE enroll_groups SET revoked=1 WHERE id=?", r["id"])
    if rows:
        log.warning("revoked %d group enrollment token(s) created by %s", len(rows), email)
    return len(rows)


async def disable(uid: int, *, by: str, actor: str, ip: str, reason: str) -> Optional[dict]:
    """Disable account `uid` (idempotent: an already disabled account → None, nothing done).
    `by` = 'scim' | 'scim-delete' | 'scim-identity' (final re-review 3.6.11: an account the IdP
    deactivated by its `sub` alone, never linked to SCIM — SCIM can never re-enable it, and it is
    never turned back into 'scim*'). Raises LastOwner (nothing changed, audited, alerted).
    → {"email", "tokens", "shares", "replay_links"} of what was revoked."""
    async with authz._lock:
        row = await db.fetchone("SELECT id, email, COALESCE(disabled, 0) AS d FROM users WHERE id=?",
                                uid)
        if row is None:
            return None
        if row["d"]:
            # already disabled: only the reason may move (active:false → DELETE), and only between
            # the IdP's own reasons — re-review 3.6.11: a disable done in WebTerm (or of unknown
            # origin) must not become 'scim*', which SCIM `active:true` could then undo; a
            # 'scim'/'scim-delete' one may become the stricter 'scim-identity', never the reverse
            await db.execute("UPDATE users SET disabled_by=? WHERE id=?"
                             " AND disabled_by IN ('scim', 'scim-delete')", by, uid)
            return None
        # check-then-act under the bindings lock: a concurrent grant/removal cannot slip between.
        # Review 3.6.11: an Owner-level role given in WebTerm (not by an SSO group) = only an
        # Owner, in WebTerm, can take the account out (§A.5) — never the IdP
        if await authz.owner_level_given_in_webterm(uid):
            raise OwnerLevel(row["email"])
        if await is_permanent_owner(uid) and await authz.owner_count(exclude_user=uid) < 1:
            await report_last_owner_refused(row["email"], actor=actor, ip=ip, reason=reason)
            raise LastOwner(row["email"])
        # RB-06: nor the last permanent Owner WITH A LOCAL PASSWORD — a disabled account does
        # not count as break-glass (owner_count skips it), so this is the same lock-out
        if await authz.last_break_glass(uid):
            await report_last_break_glass_refused(uid, row["email"], actor=actor, ip=ip, reason=reason)
            raise LastBreakGlass(row["email"])
        now = time.time()
        await db.execute("UPDATE users SET disabled=1, disabled_at=?, disabled_by=? WHERE id=?",
                         now, by, uid)
        await db.execute("DELETE FROM web_sessions WHERE user_id=?", uid)
        authz.bump_epoch()                  # live sockets re-check NOW (session gone → 4401)
    email = row["email"]
    security.clear_stepup_for(uid)
    security.bump_forward_epoch(uid)
    # by creator ID only (second re-review 3.6.11): the email may since belong to someone else's
    # tokens' `created_by` text; tokens from before the id were backfilled once (authz.seed) and
    # one without an id is already dead (grants_for_token)
    ntok = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM api_tokens WHERE created_by_id=?", uid))["c"]
    await db.execute("DELETE FROM api_tokens WHERE created_by_id=?", uid)
    ngrp = await revoke_enroll_groups(uid, email)
    from . import api                       # late: api imports this module
    nshare = await api._revoke_all_shares(email, uid)
    nlinks = await api._revoke_replay_links(uid)
    what = ("account %s disabled by the identity provider (%s): sessions ended, %d automation "
            "token(s), %d group enrollment token(s), %d share(s) and %d replay link(s) revoked"
            % (email, reason, ntok, ngrp, nshare, nlinks))
    log.warning(what)
    await audit.record(time.time(), actor, ip, "SCIM", "/scim/v2/Users", 200, what[:480],
                       actor_id=None, via="scim")
    email_alerts.notify_security_change(
        "account %s was disabled by the identity provider (SCIM)" % email, ip, actor, fleet=True,
        what_key="scim_account_disabled", what_params={"account": email})
    return {"email": email, "tokens": ntok, "enroll_groups": ngrp, "shares": nshare,
            "replay_links": nlinks}


async def enable(uid: int, *, actor: str, ip: str, how: str, actor_id: Optional[int] = None,
                 path: str = "/scim/v2/Users", recheck=None) -> Optional[str]:
    """Re-enable (idempotent: an active account → None). `how` goes to the audit/alert text.
    `recheck` = an async callable run under the bindings lock first (the caller's rights, fresh).
    → the account's email when it was re-enabled."""
    async with authz._lock:
        if recheck is not None:
            await recheck()
        row = await db.fetchone("SELECT email, COALESCE(disabled, 0) AS d FROM users WHERE id=?",
                                uid)
        if row is None or not row["d"]:
            return None
        await db.execute("UPDATE users SET disabled=0, disabled_at=NULL, disabled_by=NULL"
                         " WHERE id=?", uid)
        authz.bump_epoch()
    email = row["email"]
    what = "account %s re-enabled (%s)" % (email, how)
    log.warning("%s by %s", what, actor)
    if path.startswith("/scim/"):
        # a UI re-enable is written by the audit middleware (the handler sets the detail)
        await audit.record(time.time(), actor, ip, "SCIM", path, 200, what[:480],
                           actor_id=actor_id, via="scim")
    email_alerts.notify_security_change(what, ip, actor, fleet=True,
                                        what_key="account_reenabled",
                                        what_params={"account": email, "how": how})
    return email
