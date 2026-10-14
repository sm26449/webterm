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
    leave a credential that would come back with a re-enable), its live shares and replay links
    are revoked;
  * the last PERMANENT Owner can never be disabled (a disabled Owner does not count as one): the
    instance must not lock itself out because an IdP said so.

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


async def is_permanent_owner(uid: int) -> bool:
    row = await db.fetchone(
        "SELECT 1 FROM role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=?"
        " AND r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL", uid)
    return row is not None


async def disable(uid: int, *, by: str, actor: str, ip: str, reason: str) -> Optional[dict]:
    """Disable account `uid` (idempotent: an already disabled account → None, nothing done).
    `by` = 'scim' | 'scim-delete'. Raises LastOwner (nothing changed, audited, alerted).
    → {"email", "tokens", "shares", "replay_links"} of what was revoked."""
    async with authz._lock:
        row = await db.fetchone("SELECT id, email, COALESCE(disabled, 0) AS d FROM users WHERE id=?",
                                uid)
        if row is None:
            return None
        if row["d"]:
            # already disabled: only the reason may move (active:false → DELETE)
            await db.execute("UPDATE users SET disabled_by=? WHERE id=?", by, uid)
            return None
        # check-then-act under the bindings lock: a concurrent grant/removal cannot slip between
        if await is_permanent_owner(uid) and await authz.owner_count(exclude_user=uid) < 1:
            email = row["email"]
            log.error("%s: refused to disable %s — it is the last permanent Owner (%s)",
                      actor, email, reason)
            await audit.record(time.time(), actor, ip, "SCIM", "/scim/v2/Users", 403,
                               "refused to disable %s: the last permanent Owner (%s)"
                               % (email, reason), actor_id=None, via="scim")
            email_alerts.notify_security_change(
                "the identity provider tried to disable the last Owner (%s); refused" % email,
                ip, actor, fleet=True, severity="critical", what_key="scim_last_owner_refused",
                what_params={"account": email})
            raise LastOwner(email)
        now = time.time()
        await db.execute("UPDATE users SET disabled=1, disabled_at=?, disabled_by=? WHERE id=?",
                         now, by, uid)
        await db.execute("DELETE FROM web_sessions WHERE user_id=?", uid)
        authz.bump_epoch()                  # live sockets re-check NOW (session gone → 4401)
    email = row["email"]
    security.clear_stepup_for(uid)
    security.bump_forward_epoch(uid)
    ntok = (await db.fetchone(
        "SELECT COUNT(*) AS c FROM api_tokens WHERE created_by_id=? OR created_by=?",
        uid, email))["c"]
    await db.execute("DELETE FROM api_tokens WHERE created_by_id=? OR created_by=?", uid, email)
    from . import api                       # late: api imports this module
    nshare = await api._revoke_all_shares(email, uid)
    nlinks = await api._revoke_replay_links(uid)
    what = ("account %s disabled by the identity provider (%s): sessions ended, %d automation "
            "token(s), %d share(s) and %d replay link(s) revoked" % (email, reason, ntok, nshare,
                                                                      nlinks))
    log.warning(what)
    await audit.record(time.time(), actor, ip, "SCIM", "/scim/v2/Users", 200, what[:480],
                       actor_id=None, via="scim")
    email_alerts.notify_security_change(
        "account %s was disabled by the identity provider (SCIM)" % email, ip, actor, fleet=True,
        what_key="scim_account_disabled", what_params={"account": email})
    return {"email": email, "tokens": ntok, "shares": nshare, "replay_links": nlinks}


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
