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
        "SELECT m.grp, m.role_id, m.scope_kind, m.scope_value, COALESCE(m.source, 'ui') AS source,"
        " r.id, r.key, r.name, r.description, r.perms, r.builtin FROM oidc_group_roles m"
        " JOIN roles r ON r.id = m.role_id WHERE m.id<>?", exclude_mid or 0)
    hosts = {r["id"] for r in await db.fetchall("SELECT id FROM hosts")}
    desired, matched = set(), set()
    for m in maps:
        g = m["grp"]
        if g != WILDCARD and g not in groups:
            continue
        # 3.6.5, apărare în adâncime: o mapare din configuraţie nu acordă NICIODATĂ Owner (nici
        # un rol custom cu permisiuni doar-de-Owner), chiar dacă rândul a ajuns cumva în DB.
        if m["source"] == "config" and not config_role_allowed(authz._row_role(m)):
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
                        store_groups: Optional[set] = None,
                        add_roles: Optional[set] = None) -> dict:
    """Make the user's sso bindings equal `desired` (or only remove, `remove_only`). Caller
    holds authz._lock. Manual/migration bindings are read only to avoid duplicates.
    `add_roles` (3.6.11, SCIM): only these role ids may be ADDED; the rest of `desired` is still
    kept (never removed), just not granted from here."""
    rows = await db.fetchall(
        "SELECT id, role_id, scope_kind, scope_value, source FROM role_bindings WHERE user_id=?",
        uid)
    sso = {(r["role_id"], r["scope_kind"], r["scope_value"] or ""): r["id"]
           for r in rows if (r["source"] or "") == "sso"}
    other = {(r["role_id"], r["scope_kind"], r["scope_value"] or "")
             for r in rows if (r["source"] or "") != "sso"}
    names = await _role_names()
    owner_rid = next((rid for rid, (k, _n) in names.items() if k == "owner"), None)
    added, removed, kept, kept_bg = [], [], [], []
    now = time.time()
    held_back = []
    if not remove_only:
        for t in sorted(desired - set(sso) - other):
            if add_roles is not None and t[0] not in add_roles:
                held_back.append(t)
                continue
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
        # RB-06 (re-review P1): nor the Owner @ all binding of the break-glass account — the last
        # permanent Owner with a local password — while every other permanent Owner is SSO-only
        # (the caller holds authz._lock; same rule as api.update_account / admin passwd)
        if t[0] == owner_rid and t[1] == "all" and await authz.last_break_glass(uid, exclude_binding=bid):
            kept_bg.append(t)
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
    out = {"added": [lab(t) for t in added], "removed": [lab(t) for t in removed],
           "kept_last_owner": [lab(t) for t in kept], "skipped": False}
    if kept_bg:
        out["kept_last_break_glass"] = [lab(t) for t in kept_bg]
    if held_back:
        out["held_back"] = [lab(t) for t in held_back]
    return out


async def has_local_password(uid: int) -> bool:
    """True unless the account was provisioned by SSO or its owner removed the local password.
    Unknown / NULL = True (fail-closed: pre-3.6.2 accounts count as having one)."""
    r = await db.fetchone("SELECT local_password FROM users WHERE id=?", uid)
    return r is None or r["local_password"] is None or bool(r["local_password"])


async def scim_grantable_roles() -> set:
    """3.6.11: the role ids a SCIM push may ADD — every role except Owner and any role with an
    Owner-only permission (the same rule as WEBTERM_OIDC_ROLE_MAP). Owner from a group mapping is
    given only at an interactive SSO sign-in, never by a background push."""
    out = set()
    for r in await db.fetchall("SELECT id, key, name, description, perms, builtin FROM roles"):
        if config_role_allowed(authz._row_role(r)):
            out.add(r["id"])
    return out


async def sync_user(uid: int, email: str, groups, *, ip: str, via: str,
                    readable: bool = True, path: str = "/api/oidc/callback",
                    scim: bool = False) -> dict:
    """Re-sync one account at an SSO login / step-up. `groups=None` = the claim was ABSENT.
    `readable=False` = the claim was there but not a list of strings (treated as no groups).
    `scim=True` (3.6.11): the groups come from a SCIM push — same rules, except that nothing
    Owner-equivalent is ADDED (kept if already there; added at the next SSO sign-in)."""
    if not readable:
        log.warning("SSO: the groups claim for %s is not a list of strings — treated as NO "
                    "groups (its SSO-derived roles are removed)", email)
        await audit.record(time.time(), email, ip, "GET", path, 200,
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
        # sub lock: o editare de rol concurentă nu poate strecura o permisiune doar-de-Owner
        add_roles = await scim_grantable_roles() if scim else None
        desired, matched = await _desired(gs)
        local_pw = await has_local_password(uid)
        if local_pw:
            have = {(r["role_id"], r["scope_kind"], r["scope_value"] or "") for r in await db.fetchall(
                "SELECT role_id, scope_kind, scope_value FROM role_bindings WHERE user_id=?", uid)}
            skipped = desired - have
        res = await _apply_locked(uid, desired, remove_only=local_pw, store_groups=matched,
                                  add_roles=add_roles)
    if res.get("held_back"):
        log.warning("SCIM: %s is in a group mapped to an Owner-level role (%s); a SCIM push never "
                    "grants it — it is added at the person's next SSO sign-in",
                    email, ", ".join(res["held_back"]))
        await audit.record(time.time(), email, ip, "SCIM", path, 200,
                           ("SCIM: Owner-level role not granted by a push (added at the next SSO "
                            "sign-in): %s" % res["held_back"])[:480], actor_id=uid, via="scim")
    if local_pw and skipped:
        names = await _role_names()
        labs = [_label(names.get(t[0], ("", "?"))[1], t[1], t[2]) for t in sorted(skipped)]
        res["skipped_local_password"] = labs
        log.warning("sso.sync.skippedLocalPassword: %s has a local password, so its groups give "
                    "it no roles (would have added: %s). It can remove the local password in "
                    "Settings → Users & roles to receive them.", email, ", ".join(labs))
        await audit.record(time.time(), email, ip, "GET", path, 200,
                           ("sso.sync.skippedLocalPassword (%s): not added %s" % (via, labs))[:480],
                           actor_id=uid)
    _report(uid, email, ip, via, res)
    if res["added"] or res["removed"] or res["kept_last_owner"] or res.get("kept_last_break_glass"):
        await audit.record(time.time(), email, ip, "SCIM" if scim else "GET", path, 200,
                           ("SSO roles synced (%s): +%s -%s%s%s" % (
                               via, res["added"] or "[]", res["removed"] or "[]",
                               (" KEPT last Owner %s" % res["kept_last_owner"])
                               if res["kept_last_owner"] else "",
                               (" KEPT break-glass Owner %s" % res["kept_last_break_glass"])
                               if res.get("kept_last_break_glass") else ""))[:480], actor_id=uid,
                           via="scim" if scim else "")
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
        if res["removed"] or res["kept_last_owner"] or res.get("kept_last_break_glass"):
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
        email_alerts.notify_security_change(
            "your access changed after an SSO sign-in" if via != "scim"
            else "your access changed after a change in your identity provider", ip, email,
                                            user_id=uid, what_key="sso_access_changed",
                                            what_params=params)
    if res["kept_last_owner"]:
        report_last_owner(uid, email, ip, res["kept_last_owner"])
    if res.get("kept_last_break_glass"):
        report_last_break_glass(email, via, res["kept_last_break_glass"])


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


# ── 3.6.5: maparea din configuraţie (WEBTERM_OIDC_ROLE_MAP) ─────────────────────────────────
# Intrări `grup=rol@scope`, separate prin virgulă sau rând nou; scope = all | folder:<nume> |
# tag:<nume> | host:<nume>; rol = cheie predefinită (admin/operator/viewer) sau NUMELE unui rol
# custom existent. Reconciliate DOAR la pornire cu rândurile `source='config'`: ce lipseşte se
# adaugă, ce nu mai e listat se scoate (cu retragerea imediată a legăturilor derivate, ca la
# ştergerea din UI); mapările făcute din UI (`source='ui'`) nu se ating niciodată.
#
# Încrederea: .env-ul e al administratorului SERVERULUI (care are oricum DB-ul şi cheia
# seifului) — totuşi, fail-closed:
#   * Owner NU se acordă niciodată din configuraţie (nici printr-un rol custom cu permisiuni pe
#     care doar Owner le are): intrarea e refuzată, jurnal + audit + alertă critică;
#   * `*` (orice cont SSO) nu se acceptă din configuraţie — e o decizie de luat în UI, unde e
#     doar a unui Owner şi alertată;
#   * o intrare greşită (sintaxă, rol necunoscut/ambiguu, nume de grup pe care normalizarea l-ar
#     schimba, caractere de control, scope invalid) e SĂRITĂ: nu acordă nimic, nu opreşte
#     pornirea, e scrisă în jurnal ca eroare şi auditată;
#   * `host:<nume>` care nu există (încă) → sărită cu avertisment; ambiguu (două hosturi cu
#     acelaşi nume) → sărită cu eroare.
CONFIG_ACTOR = "config:WEBTERM_OIDC_ROLE_MAP"
_CONFIG_PATH = "/config/oidc-role-map"
_ROLE_MAP_MAX_LEN = 64 * 1024
_OWNER_ONLY = authz.BUILTIN_ROLES["owner"]["perms"] - authz.BUILTIN_ROLES["admin"]["perms"]


def config_role_allowed(role) -> bool:
    """Un rol pe care configuraţia are voie să-l dea: nu Owner, şi nicio permisiune doar-de-Owner
    (copiile custom ale Owner-ului sunt Owner sub alt nume)."""
    return role is not None and role.key != "owner" and not (role.perms & _OWNER_ONLY)


def _printable(s: str) -> bool:
    return s.isprintable() and not any(unicodedata.category(ch) == "Cf" for ch in s)


def parse_role_map(raw: str) -> tuple[list, list]:
    """Doar SINTAXA (fără DB). → ([(entry, group, role_token, kind, value)], [(entry, motiv)]).
    Nicio intrare respinsă nu ajunge în prima listă."""
    ok, bad = [], []
    raw = raw or ""
    if len(raw) > _ROLE_MAP_MAX_LEN:
        return [], [(raw[:60] + "…", "the value is longer than %d characters" % _ROLE_MAP_MAX_LEN)]
    for line in raw.replace("\r\n", "\n").split("\n"):
        for part in line.split(","):
            entry = part.strip(" \t")
            if not entry:
                continue
            shown = entry[:120]
            if not _printable(entry):
                bad.append((repr(shown), "control or invisible characters"))
                continue
            grp, eq, rest = entry.partition("=")
            if not eq:
                bad.append((shown, "expected group=role@scope"))
                continue
            role_tok, at, scope = rest.partition("@")
            role_tok, scope = role_tok.strip(), scope.strip()
            if not at or not role_tok or not scope:
                bad.append((shown, "expected group=role@scope (scope: all, folder:<name>, "
                                   "tag:<name> or host:<name>)"))
                continue
            if grp == WILDCARD:
                bad.append((shown, "'*' (every SSO user) cannot be mapped from the configuration "
                                   "— an Owner can map it in Settings → Users & roles"))
                continue
            if normalize_group(grp) is None:
                bad.append((shown, "the group name has surrounding spaces, is not in Unicode NFC "
                                   "form, is empty or longer than %d characters" % GROUP_MAX_LEN))
                continue
            if scope.lower() == "all":
                kind, value = "all", ""
            else:
                kind, colon, value = scope.partition(":")
                kind, value = kind.strip().lower(), value.strip()
                if not colon or kind not in ("folder", "tag", "host") or not value:
                    bad.append((shown, "the scope must be all, folder:<name>, tag:<name> or "
                                       "host:<name>"))
                    continue
            ok.append((shown, grp, role_tok, kind, value))
    return ok, bad


async def _resolve_role_token(tok: str):
    """→ (RoleInfo | None, motiv). Cheie predefinită, altfel numele EXACT (fără diferenţă de
    majuscule) al unui singur rol custom."""
    key = tok.lower()
    if key in authz.BUILTIN_ROLES:
        r = await db.fetchone(
            "SELECT id, key, name, description, perms, builtin FROM roles WHERE key=?", key)
        return (authz._row_role(r) if r else None), "built-in role missing"
    rows = await db.fetchall(
        "SELECT id, key, name, description, perms, builtin FROM roles WHERE builtin=0"
        " AND lower(name)=lower(?)", tok)
    if len(rows) != 1:
        return None, ("no role with that key or name" if not rows else "ambiguous role name")
    return authz._row_role(rows[0]), ""


async def _resolve_entries(raw: str):
    """→ ({(grp, role_id, kind, value): etichetă}, erori [(intrare, motiv)], avertismente
    [(intrare, motiv)], [intrări cu Owner refuzat] — acestea apar şi în erori)."""
    parsed, errors = parse_role_map(raw)
    warnings, owner_refused = [], []
    desired = {}
    for entry, grp, role_tok, kind, value in parsed:
        role, why = await _resolve_role_token(role_tok)
        if role is None:
            errors.append((entry, "unknown role %r (%s): use admin, operator, viewer or the name "
                                  "of an existing custom role" % (role_tok[:60], why)))
            continue
        if not config_role_allowed(role):
            owner_refused.append(entry)
            errors.append((entry, "Owner is never granted from the configuration (role %r)"
                           % role.name))
            continue
        if kind == "host":
            rows = await db.fetchall(
                "SELECT id FROM hosts WHERE name=? AND COALESCE(ephemeral, 0)=0", value)
            if not rows:
                warnings.append((entry, "no host named %r (yet) — skipped" % value[:60]))
                continue
            if len(rows) > 1:
                errors.append((entry, "%d hosts are named %r — ambiguous, skipped"
                               % (len(rows), value[:60])))
                continue
            value = str(rows[0]["id"])
        else:
            limit = {"tag": 32, "folder": 120}.get(kind)
            if limit and len(value) > limit:
                errors.append((entry, "the %s name is longer than %d characters" % (kind, limit)))
                continue
            try:
                kind, value = authz.normalize_scope(kind, value)
            except Exception as e:          # noqa: BLE001 — ApiError: scope invalid
                errors.append((entry, "invalid scope: %s" % getattr(e, "message", e)))
                continue
        desired[(grp, role.id, kind, value)] = "%s=%s" % (grp, _label(role.name, kind, value))
    return desired, errors, warnings, owner_refused


async def note_config_host_change(host_id: int, what: str) -> None:
    """Un host numit de WEBTERM_OIDC_ROLE_MAP (`host:<nume>`, rezolvat la id DOAR la pornire)
    e redenumit sau şters: maparea urmează id-ul până la următoarea pornire (ştergerea o ia cu
    ea), apoi numele din .env e rezolvat din nou. Avertisment + audit, ca nimeni să nu fie
    surprins la restart."""
    try:
        rows = await db.fetchall(
            "SELECT grp FROM oidc_group_roles WHERE source='config' AND scope_kind='host'"
            " AND scope_value=? ORDER BY grp", str(host_id))
        if not rows:
            return
        groups = ", ".join(r["grp"] for r in rows)
        text = ("host %d, used by WEBTERM_OIDC_ROLE_MAP (%s), was %s; the configuration names hosts "
                "and is resolved again only at the next restart — update .env" % (host_id, groups, what))
        log.warning(text)
        await _cfg_audit(200, text)
    except Exception:                       # noqa: BLE001 — un avertisment nu blochează operaţia
        log.exception("could not check WEBTERM_OIDC_ROLE_MAP for host %s", host_id)


async def _cfg_audit(status: int, text: str) -> None:
    await audit.record(time.time(), CONFIG_ACTOR, "-", "BOOT", _CONFIG_PATH, status, text[:480],
                       via="config")


async def reconcile_config(raw: Optional[str] = None) -> dict:
    """La PORNIRE (şi numai atunci): mapările `source='config'` devin exact cele din
    WEBTERM_OIDC_ROLE_MAP. Nu ridică excepţii spre apelant (pornirea nu are voie să cadă din
    cauza unui .env greşit): o eroare neaşteptată e jurnalizată şi NU acordă nimic (scrierile
    în DB sunt doar ADĂUGĂRI de mapări valide deja verificate şi ŞTERGERI)."""
    from . import config
    raw = config.OIDC_ROLE_MAP if raw is None else raw
    out = {"added": [], "removed": [], "kept_ui": [], "errors": [], "warnings": [],
           "owner_refused": [], "pruned": 0}
    changed = []
    try:
        desired, errors, warnings, owner_refused = await _resolve_entries(raw)
        out["errors"], out["warnings"], out["owner_refused"] = errors, warnings, owner_refused
        async with authz._lock:
            rows = await db.fetchall(
                "SELECT id, grp, role_id, scope_kind, scope_value, COALESCE(source, 'ui') AS source"
                " FROM oidc_group_roles")
            have_cfg = {(r["grp"], r["role_id"], r["scope_kind"], r["scope_value"] or ""): r["id"]
                        for r in rows if r["source"] == "config"}
            have_ui = {(r["grp"], r["role_id"], r["scope_kind"], r["scope_value"] or "")
                       for r in rows if r["source"] != "config"}
            names = await _role_names()

            def lab(t):
                return "%s=%s" % (t[0], _label(names.get(t[1], ("", "?"))[1], t[2], t[3]))
            # întâi scoaterile (eliberează locuri sub plafon), apoi adăugările
            for t, mid in sorted(have_cfg.items()):
                if t not in desired:
                    await db.execute("DELETE FROM oidc_group_roles WHERE id=? AND source='config'",
                                     mid)
                    out["removed"].append(lab(t))
            n = (await db.fetchone("SELECT COUNT(*) AS c FROM oidc_group_roles"))["c"]
            for t in sorted(desired):
                if t in have_cfg:
                    continue
                if t in have_ui:
                    out["kept_ui"].append(desired[t])   # există deja din UI: rămâne a UI-ului
                    continue
                if n >= MAPPINGS_MAX:
                    errors.append((desired[t], "too many SSO mappings (%d) — skipped"
                                   % MAPPINGS_MAX))
                    continue
                await db.execute(
                    "INSERT OR IGNORE INTO oidc_group_roles(grp, role_id, scope_kind, scope_value,"
                    " created, created_by_id, source) VALUES(?,?,?,?,?,NULL,'config')",
                    t[0], t[1], t[2], t[3], time.time())
                n += 1
                out["added"].append(desired[t])
            if out["removed"]:
                # ca la ştergerea din UI: legăturile pe care nicio mapare rămasă nu le mai
                # justifică pleacă ACUM (ultimul Owner e păstrat de _apply_locked)
                changed = await prune_locked()
                out["pruned"] = sum(len(r["removed"]) for _u, _e, r in changed)
            if out["added"] or out["removed"]:
                authz.bump_epoch()
    except Exception as e:                  # noqa: BLE001 — pornirea nu cade din cauza .env-ului
        log.exception("WEBTERM_OIDC_ROLE_MAP: reconciling the SSO mappings from the "
                      "configuration failed")
        out["errors"].append(("*", "internal error: %s" % type(e).__name__))
        try:
            await _cfg_audit(500, "WEBTERM_OIDC_ROLE_MAP reconcile failed: %s" % type(e).__name__)
        except Exception:                   # noqa: BLE001
            pass
        return out
    await _report_config(out, changed)
    return out


async def _report_config(out: dict, changed: list) -> None:
    for entry, why in out["errors"]:
        log.error("WEBTERM_OIDC_ROLE_MAP: entry %s SKIPPED — %s (it grants nothing)", entry, why)
        await _cfg_audit(400, "WEBTERM_OIDC_ROLE_MAP entry %s skipped: %s" % (entry, why))
    for entry, why in out["warnings"]:
        log.warning("WEBTERM_OIDC_ROLE_MAP: entry %s: %s", entry, why)
        await _cfg_audit(200, "WEBTERM_OIDC_ROLE_MAP entry %s: %s" % (entry, why))
    for entry in out["kept_ui"]:
        log.info("WEBTERM_OIDC_ROLE_MAP: %s already exists as a mapping made in the UI — left "
                 "as it is (remove it in the UI to let the configuration own it)", entry)
    if out["owner_refused"]:
        what = "Owner refused in WEBTERM_OIDC_ROLE_MAP: %s" % ", ".join(out["owner_refused"])
        email_alerts.notify_security_change(
            what[:400], "-", CONFIG_ACTOR, fleet=True, severity="critical",
            what_key="sso_config_owner_refused",
            what_params={"entries": ", ".join(out["owner_refused"])[:400]})
    n_invalid = len(out["errors"]) - len(out["owner_refused"])
    if n_invalid > 0:
        email_alerts.notify_security_change(
            "%d WEBTERM_OIDC_ROLE_MAP entries skipped as invalid" % n_invalid, "-",
            CONFIG_ACTOR, fleet=True, what_key="sso_config_invalid", what_params={"n": n_invalid})
    if out["added"] or out["removed"]:
        what = ("SSO mappings from the configuration: added %s, removed %s (%d SSO binding(s) "
                "removed)" % (", ".join(out["added"]) or "none",
                              ", ".join(out["removed"]) or "none", out["pruned"]))
        log.warning(what)
        await _cfg_audit(200, what)
        email_alerts.notify_security_change(
            what[:400], "-", CONFIG_ACTOR, fleet=True, what_key="sso_config_mappings_changed",
            what_params={"added": (", ".join(out["added"]) or "—")[:300],
                         "removed": (", ".join(out["removed"]) or "—")[:300],
                         "n": out["pruned"]})
    for uid, email, res in changed[:50]:
        if res["removed"]:
            email_alerts.notify_security_change(
                "your access changed: " + ", ".join(res["removed"]) + " removed", "-", email,
                user_id=uid, what_key="sso_access_changed",
                what_params={"account": email, "added": "—", "removed": ", ".join(res["removed"])})
        if res["kept_last_owner"]:
            report_last_owner(uid, email, "-", res["kept_last_owner"])
        if res.get("kept_last_break_glass"):
            report_last_break_glass(email, "config", res["kept_last_break_glass"])
