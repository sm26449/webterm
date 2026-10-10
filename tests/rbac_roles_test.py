"""Roluri custom (3.6.2; design „3.6.1", §A.6.6 regula 5): editorul nu poate escalada nimic.

Regulile, fiecare cu proba ei (matrice acolo unde se poate):
  * CRUD doar cu `roles.manage` GLOBAL; rolurile predefinite sunt imuabile (PATCH/delete → 403);
  * anti-escaladare: permisiunile rolului (setul vechi ŞI cel nou) ⊆ ce ai tu peste toată
    instanţa — un Admin nu poate crea/edita un rol cu backups.manage, nici edita unul care îl are;
  * un rol FOLOSIT se editează doar cu `users.manage` în plus, şi doar dacă poţi atinge fiecare
    cont legat (un Admin nu editează un rol pe care-l are un Owner);
  * un rol folosit NU se şterge (409 cu numărători) — întâi legăturile / mapările;
  * o editare are efect IMEDIAT: epoca creşte, terminalul deschis trece pe doar-citire sau se
    închide; permisiunile globale dintr-un rol legat pe un folder sunt ignorate;
  * regula de ţintă generalizată: nu atingi (legături, ştergere) contul cuiva care are mai mult
    decât tine — şi pentru roluri custom, nu doar pentru Owner;
  * cursa: re-verificarea SUB lock prinde un editor retrogradat / un rol modificat între
    verificare şi scriere (re-auth-ul e punctul de suspendare).
"""
import asyncio
import json

import rbac_util as U
import rbac_ws_test as W
from app import api, authz, core, db

check = U.Checker()
PW = "parolabuna1"


def rp(perms, name="R", desc="", pw=PW):
    return {"name": name, "description": desc, "perms": perms, "current_password": pw}


def rpo(perms, name="R"):
    return rp(perms, name, pw=U.OWNER_PW)


async def custom_id(name):
    r = await db.fetchone("SELECT id FROM roles WHERE name=? AND builtin=0", name)
    return r["id"] if r else None


async def make_role(name, perms):
    """Rol custom inserat direct (fixture) — calea API e testată separat."""
    import time
    rid = await db.execute("INSERT INTO roles(key, name, description, perms, builtin, created,"
                           " updated) VALUES(NULL,?,?,?,0,?,?)", name, "", json.dumps(perms),
                           time.time(), time.time())
    authz.bump_epoch()
    return rid


async def bind_id(uid, rid, kind="all", value=""):
    import time
    bid = await db.execute(
        "INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source, created)"
        " VALUES(?,?,?,?,'manual',?)", uid, rid, kind, str(value), time.time())
    authz.bump_epoch()
    return bid


async def main():
    await U.boot()
    owner = await U.owner_client()
    a = await U.add_host(owner, "alpha", folder="prod")
    b = await U.add_host(owner, "beta", folder="lab")
    owner_id = (await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL))["id"]
    adm_id = await U.add_user("adm@x.co", bindings=[("admin", "all", "")])
    adm = await U.login("adm@x.co")
    op_id = await U.add_user("op@x.co", bindings=[("operator", "folder", "prod")])
    op = await U.login("op@x.co")
    await U.add_user("sadm@x.co", bindings=[("admin", "folder", "prod")])
    sadm = await U.login("sadm@x.co")

    # ── 1. cine vede catalogul ────────────────────────────────────────────────────────────
    r = await owner.get("/api/roles")
    j = r.json()
    check("GET /api/roles (Owner): predefinitele au acum id", r.status_code == 200
          and all(isinstance(x.get("id"), int) for x in j["roles"]), r.text[:200])
    check("…şi lista custom există (goală)", j.get("custom") == [], str(j.get("custom")))
    for who, c in (("Operator", op), ("Admin@folder (fără roluri globale)", sadm)):
        r = await c.get("/api/roles")
        check("GET /api/roles: %s → 403" % who, r.status_code == 403
              and U.code(r) == "authz.denied", "%s %s" % (r.status_code, U.code(r)))
    # un „manager de roluri" custom: roles.manage + host.view peste tot, fără users.manage
    rm_rid = await make_role("RoleMgr", ["roles.manage", "host.view"])
    rm_id = await U.add_user("rm@x.co")
    await bind_id(rm_id, rm_rid)
    rm = await U.login("rm@x.co")
    r = await rm.get("/api/roles")
    check("GET /api/roles cu roles.manage (fără users.manage) → 200", r.status_code == 200, r.text[:120])

    # ── 2. creare + validare ──────────────────────────────────────────────────────────────
    r = await owner.post("/api/roles", json=rpo(["files.read", "files.write"], "Files-only"))
    fo = await custom_id("Files-only")
    check("Owner creează „Files-only\"", r.status_code == 200 and fo is not None, r.text[:200])
    row = next((x for x in r.json().get("custom", []) if x["id"] == fo), {})
    check("…marcat ⚑ (files.write e echivalent cu un shell)", row.get("shell") is True, str(row))
    bad = [
        (rpo(["files.read", "nope.x"], "X1"), 400, "role.badPerm", "permisiune necunoscută"),
        (rpo([], "X2"), 400, "role.noPerms", "fără permisiuni"),
        (rpo(["files.read"], "files-ONLY"), 409, "role.nameTaken", "nume luat (alt caz)"),
        (rpo(["files.read"], "Owner"), 409, "role.nameTaken", "numele unui rol predefinit"),
        (rpo(["files.read"], "operator"), 409, "role.nameTaken", "cheia unui rol predefinit"),
        (rpo(["files.read"], "x" * 61), 400, "role.badName", "nume prea lung"),
        (rpo(["files.read"], "a\x07b"), 400, "role.badName", "caractere de control"),
        (rpo(["files.read"], "   "), 400, "role.badName", "nume gol"),
        (dict(rp(["files.read"], "X3"), current_password="gresit"), 401, "auth.wrongPassword",
         "parolă greşită"),
    ]
    for body, st, cd, label in bad:
        r = await owner.post("/api/roles", json=body)
        check("creare refuzată: %s → %d %s" % (label, st, cd), r.status_code == st and U.code(r) == cd,
              "%s %s" % (r.status_code, r.text[:120]))
    # revizuirea de securitate 3.6.2 (E4): nume care ARATĂ ca altul (confusabile)
    for nm, label in (("\u041ewner", "„Оwner\" cu O chirilic"), ("0wner", "„0wner\" (cifra 0)"),
                      ("ΑDMIN", "„ΑDMIN\" cu Alfa grecesc"), ("Ops\u0430", "scripturi amestecate"),
                      ("Files-onIy", "„Files-onIy\" ≠ dar arată ca un rol existent? (nu: I ≠ l)"),
                      ("Fi\u217ces-only", "„Fiⅼes-only\" (ⅼ = numeral roman, NFKC → l)")):
        r = await adm.post("/api/roles", json=rp(["host.view"], nm))
        want = 200 if nm == "Files-onIy" else 400
        check("E4: Admin creează rolul %s → %d" % (label, want), r.status_code == want
              and (want == 200 or U.code(r) == "role.nameConfusable"), r.text[:120])
    await db.execute("DELETE FROM roles WHERE name='Files-onIy'")
    n = (await db.fetchone("SELECT COUNT(*) AS c FROM roles WHERE builtin=0"))["c"]
    check("…niciun rol creat de cererile refuzate", n == 2, str(n))

    # ── 3. anti-escaladare la definire (matrice: cine × ce permisiune) ────────────────────
    matrix = [
        ("Admin", adm, ["backups.manage"], 403, "authz.escalation"),
        ("Admin", adm, ["signing.manage", "host.view"], 403, "authz.escalation"),
        ("Admin", adm, ["history.clear"], 403, "authz.escalation"),
        ("Admin", adm, ["session.open", "users.manage"], 200, ""),
        ("RoleMgr", rm, ["session.open"], 403, "authz.escalation"),
        ("RoleMgr", rm, ["roles.manage", "host.view"], 200, ""),
        ("Operator@prod", op, ["host.view"], 403, "authz.denied"),
        ("Admin@folder", sadm, ["host.view"], 403, "authz.denied"),
    ]
    for i, (who, c, perms, st, cd) in enumerate(matrix):
        r = await c.post("/api/roles", json=dict(rp(perms, "M%d" % i)))
        check("%s creează rol cu %s → %d" % (who, perms, st),
              r.status_code == st and (not cd or U.code(r) == cd),
              "%s %s" % (r.status_code, r.text[:120]))
    check("…rolurile refuzate nu există",
          not await db.fetchone("SELECT 1 FROM roles WHERE name IN ('M0','M1','M2','M4','M6','M7')"))

    # ── 4. predefinitele sunt imuabile ────────────────────────────────────────────────────
    for key in authz.ROLE_ORDER:
        rid = await authz.role_id(key)
        r = await owner.patch("/api/roles/%d" % rid, json=rpo(["host.view"], "Hacked"))
        r2 = await owner.post("/api/roles/%d/delete" % rid, json={"current_password": U.OWNER_PW})
        check("rolul predefinit %s: PATCH şi delete → 403 role.builtin" % key,
              r.status_code == 403 and U.code(r) == "role.builtin" and r2.status_code == 403
              and U.code(r2) == "role.builtin", "%s %s / %s" % (r.status_code, U.code(r), r2.status_code))
    row = await db.fetchone("SELECT name, perms FROM roles WHERE key='viewer'")
    check("…şi rândul predefinit e neschimbat", row["name"] == "Viewer"
          and set(json.loads(row["perms"])) == set(authz.BUILTIN_ROLES["viewer"]["perms"]))
    r = await owner.patch("/api/roles/987654", json=rpo(["host.view"], "Nope"))
    check("PATCH pe un rol inexistent → 404 role.missing", r.status_code == 404
          and U.code(r) == "role.missing")

    # ── 5. legarea unui rol custom + efect ────────────────────────────────────────────────
    vault = await make_role("Vault", ["backups.manage", "host.view"])
    r = await adm.post("/api/users/%d/bindings" % op_id,
                       json={"role_id": fo, "scope_kind": "folder", "scope_value": "lab",
                             "current_password": PW})
    check("Admin leagă un rol custom (după id) la un cont", r.status_code == 200, r.text[:160])
    bj = next((x for x in r.json().get("bindings", []) if x.get("role_id") == fo), {})
    check("…legătura arată rolul custom (role '' + role_name)", bj.get("role") == ""
          and bj.get("role_name") == "Files-only", str(bj))
    g = await authz.grants_for_user(op_id)
    check("…files.write pe un host din lab (efectiv)", "files.write" in await authz.perms_on(g, b))
    r = await adm.post("/api/users/%d/bindings" % op_id,
                       json={"role_id": vault, "scope_kind": "all", "current_password": PW})
    check("Admin NU leagă un rol custom cu backups.manage (escaladare)", r.status_code == 403
          and U.code(r) == "authz.escalation", r.text[:120])
    r = await adm.post("/api/users/%d/bindings" % op_id,
                       json={"role": "viewer", "role_id": fo, "scope_kind": "all",
                             "current_password": PW})
    check("cerere contradictorie (cheie ≠ id) → 400 authz.badRole", r.status_code == 400
          and U.code(r) == "authz.badRole", r.text[:120])
    r = await adm.post("/api/users/%d/bindings" % op_id,
                       json={"role_id": 987654, "scope_kind": "all", "current_password": PW})
    check("rol inexistent → 400 authz.badRole", r.status_code == 400 and U.code(r) == "authz.badRole")
    # globalele dintr-un rol legat pe folder sunt IGNORATE
    aud = await make_role("AuditFolder", ["audit.view", "host.view"])
    au_id = await U.add_user("au@x.co")
    await bind_id(au_id, aud, "folder", "prod")
    g = await authz.grants_for_user(au_id)
    check("permisiune globală dintr-un rol legat pe FOLDER: ignorată",
          "audit.view" not in g.global_perms)
    await bind_id(au_id, aud, "all")
    g = await authz.grants_for_user(au_id)
    check("…aceeaşi, legată pe ALL: efectivă", "audit.view" in g.global_perms)

    # ── 6. editare: setul vechi ŞI cel nou, ţintele ──────────────────────────────────────
    r = await adm.patch("/api/roles/%d" % vault, json=rp(["host.view"], "Vault"))
    check("Admin NU editează un rol care ARE backups.manage (chiar ca să-l scoată)",
          r.status_code == 403 and U.code(r) == "authz.escalation", r.text[:120])
    r = await adm.patch("/api/roles/%d" % fo, json=rp(["files.read", "backups.manage"], "Files-only"))
    check("Admin NU adaugă backups.manage într-un rol", r.status_code == 403
          and U.code(r) == "authz.escalation", r.text[:120])
    r = await rm.patch("/api/roles/%d" % fo, json=rp(["files.read"], "Files-only"))
    check("roles.manage fără users.manage NU editează un rol FOLOSIT (are legături)",
          r.status_code in (403,) and U.code(r) in ("authz.denied", "authz.escalation"), r.text[:120])
    m5 = await custom_id("M5")
    r = await rm.patch("/api/roles/%d" % m5, json=rp(["host.view"], "M5"))
    check("…dar editează un rol nefolosit, în limitele lui", r.status_code == 200, r.text[:120])
    tmpb = await bind_id(au_id, m5, "folder", "lab")
    r = await rm.patch("/api/roles/%d" % m5, json=rp(["host.view", "roles.manage"], "M5"))
    check("roles.manage fără users.manage: rolul devine FOLOSIT → editarea cere users.manage",
          r.status_code == 403 and U.code(r) == "authz.denied"
          and (r.json().get("vars") or {}).get("perm", "users.manage") == "users.manage",
          r.text[:160])
    await db.execute("DELETE FROM role_bindings WHERE id=?", tmpb)
    authz.bump_epoch()
    # un rol pe care îl are un Owner
    own2 = await U.add_user("own2@x.co", bindings=[("owner", "all", "")])
    shared = await make_role("Shared", ["host.view", "session.watch"])
    await bind_id(own2, shared, "all")
    r = await adm.patch("/api/roles/%d" % shared, json=rp(["host.view"], "Shared"))
    check("Admin NU editează un rol legat de un Owner (doar Owner atinge Owner-ii)",
          r.status_code == 403 and U.code(r) == "authz.ownerOnly", r.text[:120])
    r = await owner.patch("/api/roles/%d" % shared, json=rpo(["host.view"], "Shared"))
    check("…un Owner da", r.status_code == 200, r.text[:120])
    r = await owner.patch("/api/roles/%d" % shared, json=rpo(["host.view"], "files-only"))
    check("redenumire pe numele altui rol → 409", r.status_code == 409 and U.code(r) == "role.nameTaken")

    # ── 7. efect imediat pe un terminal deschis ──────────────────────────────────────────
    shell = await make_role("Shell", ["session.open", "session.watch", "host.view"])
    sh_id = await U.add_user("sh@x.co")
    await bind_id(sh_id, shell, "folder", "prod")
    sh = await U.login("sh@x.co")
    api.WS_REVALIDATE_SECS = 30
    sid = await U.add_session(a, state="live", created_by=sh_id)
    src = W.FakeSource()
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    hub = core.get_or_create_hub(row)
    hub.attached = True
    hub._source = lambda s=src: s
    ws, t = await W.attach(sh, sid)
    check("rol custom cu session.open: terminal rw", ws.accepted and ws.init().get("readonly") is False,
          str(ws.sent_text[:2]))
    ep = authz.epoch()
    r = await owner.patch("/api/roles/%d" % shell, json=rpo(["session.watch", "host.view"], "Shell"))
    await asyncio.sleep(0.2)
    check("editarea rolului creşte epoca", authz.epoch() > ep)
    check("…terminalul DESCHIS primeşte `readonly` pe loc", "readonly" in ws.types(), str(ws.types()))
    src.data.clear()
    await ws.q.put({"type": "websocket.receive", "bytes": b"id\r"})
    await asyncio.sleep(0.05)
    check("…şi tastele nu mai ajung la PTY", src.data == [], str(src.data))
    r = await owner.patch("/api/roles/%d" % shell, json=rpo(["docker.view"], "Shell"))
    await asyncio.sleep(0.2)
    check("rolul pierde şi session.watch: socketul se închide (4403)", ws.closed == 4403, str(ws.closed))
    await W.finish(ws, t)

    # ── 8. ştergere ──────────────────────────────────────────────────────────────────────
    r = await owner.post("/api/roles/%d/delete" % fo, json={"current_password": U.OWNER_PW})
    check("rol FOLOSIT: ştergerea refuzată (409 role.inUse, cu numărători)",
          r.status_code == 409 and U.code(r) == "role.inUse", r.text[:160])
    check("…rolul există încă", await custom_id("Files-only") == fo)
    r = await adm.post("/api/roles/%d/delete" % vault, json={"current_password": PW})
    check("Admin NU şterge un rol cu backups.manage", r.status_code == 403
          and U.code(r) == "authz.escalation")
    bid = (await db.fetchone("SELECT id FROM role_bindings WHERE user_id=? AND role_id=?",
                             op_id, fo))["id"]
    r = await adm.post("/api/users/%d/bindings/%d/delete" % (op_id, bid), json={"current_password": PW})
    check("legătura custom se scoate (Admin are permisiunile rolului)", r.status_code == 200, r.text[:120])
    r = await owner.post("/api/roles/%d/delete" % fo, json={"current_password": U.OWNER_PW})
    check("nefolosit: rolul se şterge", r.status_code == 200 and await custom_id("Files-only") is None,
          r.text[:120])
    cnt = (await db.fetchone("SELECT COUNT(*) AS c FROM audit_log WHERE detail LIKE 'role ''%'"))["c"]
    check("creare / editare / ştergere de rol: în jurnalul de audit", cnt >= 4, str(cnt))

    # ── 9. regula de ţintă generalizată (rol custom mai puternic decât cel care acordă) ──
    vt_id = await U.add_user("vt@x.co")
    await bind_id(vt_id, vault, "all")
    for label, req in (
            ("adaugă o legătură", lambda: adm.post("/api/users/%d/bindings" % vt_id, json={
                "role": "viewer", "scope_kind": "all", "current_password": PW})),
            ("şterge contul", lambda: adm.post("/api/users/%d/delete" % vt_id,
                                               json={"current_password": PW}))):
        r = await req()
        check("Admin NU %s unui cont cu backups.manage (authz.outranked)" % label,
              r.status_code == 403 and U.code(r) == "authz.outranked", r.text[:120])
    vb = (await db.fetchone("SELECT id FROM role_bindings WHERE user_id=?", vt_id))["id"]
    r = await adm.post("/api/users/%d/bindings/%d/delete" % (vt_id, vb), json={"current_password": PW})
    check("…nici nu-i scoate legătura", r.status_code == 403
          and U.code(r) in ("authz.outranked", "authz.escalation"), r.text[:120])
    check("…contul şi legătura sunt intacte",
          await db.fetchone("SELECT 1 FROM role_bindings WHERE id=?", vb) is not None)
    r = await owner.post("/api/users/%d/delete" % vt_id, json={"current_password": U.OWNER_PW})
    check("un Owner îl poate şterge", r.status_code == 200, r.text[:120])
    # un cont cu o legătură custom pe care Admin o poate scoate: ştergerea merge (nicio regresie)
    plain = await U.add_user("plain@x.co")
    await bind_id(plain, m5, "folder", "prod")
    r = await adm.post("/api/users/%d/delete" % plain, json={"current_password": PW})
    check("Admin şterge un cont cu un rol custom pe care îl stăpâneşte", r.status_code == 200, r.text[:120])

    # ── 10. cursa: re-verificare SUB lock (re-auth-ul e punctul de suspendare) ─────────────
    orig = api._reauth_for_access_change

    async def demote_then(user, request, body, what):
        await orig(user, request, body, what)
        if user["id"] == adm_id:
            await U.unbind_all(adm_id)
            await U.bind(adm_id, "viewer", "all", "")
    api._reauth_for_access_change = demote_then
    try:
        r = await adm.post("/api/roles", json=rp(["host.view"], "RaceRole"))
        check("cursă: Admin retrogradat între verificare şi scriere → creare refuzată",
              r.status_code == 403 and await custom_id("RaceRole") is None, r.text[:120])
    finally:
        api._reauth_for_access_change = orig
    await U.unbind_all(adm_id)
    await U.bind(adm_id, "admin", "all", "")

    async def widen_then(user, request, body, what):
        await orig(user, request, body, what)
        await db.execute("UPDATE roles SET perms=? WHERE id=?",
                         json.dumps(["host.view", "backups.manage"]), m5)
    api._reauth_for_access_change = widen_then
    try:
        tgt = await U.add_user("tgt@x.co")
        r = await adm.post("/api/users/%d/bindings" % tgt,
                           json={"role_id": m5, "scope_kind": "all", "current_password": PW})
        check("cursă: rolul primeşte backups.manage între verificare şi scriere → legare refuzată",
              r.status_code == 403 and U.code(r) == "authz.escalation"
              and not await db.fetchone("SELECT 1 FROM role_bindings WHERE user_id=?", tgt),
              r.text[:120])
    finally:
        api._reauth_for_access_change = orig

    for c in (owner, adm, op, sadm, rm, sh):
        await c.aclose()
    await db.close()
    del owner_id
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
