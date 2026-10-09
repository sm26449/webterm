"""Nicio escaladare prin conturi, legături sau tokenuri; ultimul Owner rămâne (3.6, §A.6.5–6).

Regulile, fiecare cu proba ei:
  * un cont NOU nu primeşte nimic din oficiu (nu Owner) — „fără acces încă";
  * nu-ţi poţi schimba singur accesul; doar un Owner acordă/atinge Owner; un Admin nu şterge Owner-i;
  * rolul acordat nu depăşeşte ce ai TU peste acel scope (verificat şi direct pe `check_can_grant`,
    pentru combinaţiile pe care rolurile predefinite nu le pot produce prin API);
  * ultimul Owner nu poate fi scos — nici prin două cereri concurente (check-then-act sub lock);
  * tokenul = scopes ∩ rol ∩ ce poate creatorul ACUM: se micşorează odată cu creatorul şi moare
    odată cu el; nu poate fi creat peste rolul creatorului;
  * o legătură schimbată retrage pe loc accesul derivat (share live / writable, link de replay).
"""
import asyncio
import time

import rbac_util as U
from app import authz, db

check = U.Checker()
PW = "parolabuna1"


async def main():
    await U.boot()
    owner = await U.owner_client()
    a = await U.add_host(owner, "alpha", folder="prod")
    b = await U.add_host(owner, "beta", folder="lab")
    owner_id = (await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL))["id"]

    # ── crearea de cont: implicit FĂRĂ acces ─────────────────────────────────────────────
    r = await owner.post("/api/users", json={"email": "new@x.co", "password": PW,
                                             "current_password": U.OWNER_PW})
    new = next(u for u in r.json() if u["email"] == "new@x.co")
    check("cont nou fără rol → nicio legătură (NU Owner din oficiu)", new["bindings"] == [],
          str(new))
    nc = await U.login("new@x.co")
    check("…şi vede o flotă GOALĂ", (await nc.get("/api/hosts")).json() == [])
    r = await owner.post("/api/users", json={"email": "op@x.co", "password": PW,
                                             "current_password": U.OWNER_PW,
                                             "role": "operator", "scope_kind": "folder",
                                             "scope_value": "prod"})
    opu = next(u for u in r.json() if u["email"] == "op@x.co")
    check("cont nou cu rol: legătura e creată în acelaşi pas",
          [(x["role"], x["scope_kind"], x["scope_value"]) for x in opu["bindings"]]
          == [("operator", "folder", "prod")], str(opu))

    # ── Admin: tot, mai puţin Owner-ii ───────────────────────────────────────────────────
    adm_id = await U.add_user("adm@x.co", bindings=[("admin", "all", "")])
    adm = await U.login("adm@x.co")
    r = await adm.post("/api/users", json={"email": "evil@x.co", "password": PW,
                                           "current_password": PW, "role": "owner",
                                           "scope_kind": "all"})
    check("Admin NU poate crea un Owner (403, înainte de orice efect)",
          r.status_code == 403 and U.code(r) == "authz.ownerOnly", r.text[:120])
    check("…şi contul nici nu s-a creat",
          not await db.fetchone("SELECT 1 FROM users WHERE email='evil@x.co'"))
    r = await adm.post("/api/users/%d/bindings" % opu["id"],
                       json={"role": "owner", "scope_kind": "all", "current_password": PW})
    check("Admin NU poate acorda Owner", r.status_code == 403 and U.code(r) == "authz.ownerOnly")
    r = await adm.post("/api/users/%d/bindings" % owner_id,
                       json={"role": "viewer", "scope_kind": "all", "current_password": PW})
    check("Admin NU atinge legăturile unui Owner", r.status_code == 403
          and U.code(r) == "authz.ownerOnly", r.text[:120])
    ob = (await db.fetchone("SELECT id FROM role_bindings WHERE user_id=?", owner_id))["id"]
    r = await adm.post("/api/users/%d/bindings/%d/delete" % (owner_id, ob),
                       json={"current_password": PW})
    check("Admin NU scoate rolul unui Owner", r.status_code == 403)
    r = await adm.post("/api/users/%d/delete" % owner_id, json={"current_password": PW})
    check("Admin NU şterge un Owner", r.status_code == 403 and U.code(r) == "authz.ownerOnly")
    r = await adm.post("/api/users/%d/bindings" % adm_id,
                       json={"role": "owner", "scope_kind": "all", "current_password": PW})
    check("nimeni nu-şi schimbă propriul acces", r.status_code == 403
          and U.code(r) == "authz.selfBinding")
    r = await adm.post("/api/users/%d/bindings" % opu["id"],
                       json={"role": "viewer", "scope_kind": "host", "scope_value": str(b),
                             "current_password": PW})
    check("Admin poate acorda Viewer@host", r.status_code == 200, r.text[:160])
    r = await adm.post("/api/users/%d/bindings" % opu["id"],
                       json={"role": "viewer", "scope_kind": "host", "scope_value": str(b),
                             "current_password": PW})
    check("legătura duplicat → 409", r.status_code == 409)
    r = await adm.post("/api/users/%d/bindings" % opu["id"],
                       json={"role": "viewer", "scope_kind": "nope", "current_password": PW})
    check("scope necunoscut → 400", r.status_code == 400 and U.code(r) == "authz.badScope")
    r = await adm.post("/api/users/%d/bindings" % opu["id"],
                       json={"role": "viewer", "scope_kind": "host", "scope_value": "9999",
                             "current_password": PW})
    check("scope pe un host inexistent → 404", r.status_code == 404)
    r = await adm.post("/api/users/%d/bindings" % opu["id"],
                       json={"role": "viewer", "scope_kind": "all", "current_password": "gresit"})
    check("schimbarea de acces cere parola contului", r.status_code == 401)

    # scoped users.manage nu există: Admin@folder nu administrează conturi
    sadm = await U.add_user("sadm@x.co", bindings=[("admin", "folder", "prod")])
    sadm_c = await U.login("sadm@x.co")
    r = await sadm_c.post("/api/users/%d/bindings" % opu["id"],
                          json={"role": "viewer", "scope_kind": "folder", "scope_value": "prod",
                                "current_password": PW})
    check("users.manage e GLOBAL: Admin@folder:prod nu poate acorda nimic (403)",
          r.status_code == 403 and U.code(r) == "authz.denied")
    del sadm

    # ── no-escalation, direct pe funcţie (combinaţii pe care API-ul nu le poate produce) ─
    adm_prod = authz.Grants.from_bindings(99, [authz.Binding(
        1, "admin", "Admin", authz.BUILTIN_ROLES["admin"]["perms"], "folder", "prod", "manual",
        None)])
    try:
        await authz.check_can_grant(adm_prod, "operator", "all", "")
        check("Admin@prod NU acordă Operator@all", False)
    except Exception as e:                                   # noqa: BLE001
        check("Admin@prod NU acordă Operator@all", getattr(e, "code", "") == "authz.escalation")
    try:
        await authz.check_can_grant(adm_prod, "operator", "folder", "lab")
        check("Admin@prod NU acordă Operator@lab", False)
    except Exception as e:                                   # noqa: BLE001
        check("Admin@prod NU acordă Operator@lab", getattr(e, "code", "") == "authz.escalation")
    await authz.check_can_grant(adm_prod, "operator", "folder", "prod")
    check("Admin@prod POATE acorda Operator@prod", True)
    await authz.check_can_grant(adm_prod, "viewer", "host", str(a))
    check("Admin@prod POATE acorda Viewer pe un host din prod", True)
    try:
        await authz.check_can_grant(adm_prod, "viewer", "host", str(b))
        check("Admin@prod: host din lab → 404 (nu-l vede)", False)
    except Exception as e:                                   # noqa: BLE001
        check("Admin@prod: host din lab → 404 (nu-l vede)", getattr(e, "status_code", 0) == 404)
    op_lab = authz.Grants.from_bindings(98, [authz.Binding(
        1, "operator", "Operator", authz.BUILTIN_ROLES["operator"]["perms"], "all", "", "manual",
        None)])
    try:
        await authz.check_can_grant(op_lab, "admin", "folder", "lab")
        check("Operator@all NU acordă Admin (perms de host în plus)", False)
    except Exception as e:                                   # noqa: BLE001
        check("Operator@all NU acordă Admin (perms de host în plus)",
              getattr(e, "code", "") == "authz.escalation")

    # ── ultimul Owner ────────────────────────────────────────────────────────────────────
    o2 = await U.add_user("o2@x.co", bindings=[("owner", "all", "")])
    o2c = await U.login("o2@x.co")
    b1 = (await db.fetchone("SELECT id FROM role_bindings WHERE user_id=?", owner_id))["id"]
    b2 = (await db.fetchone("SELECT id FROM role_bindings WHERE user_id=?", o2))["id"]
    r1, r2 = await asyncio.gather(
        owner.post("/api/users/%d/bindings/%d/delete" % (o2, b2), json={"current_password": U.OWNER_PW}),
        o2c.post("/api/users/%d/bindings/%d/delete" % (owner_id, b1), json={"current_password": PW}))
    codes = sorted([r1.status_code, r2.status_code])
    check("două Owner-e care se scot reciproc CONCURENT: exact unul reuşeşte (lock)",
          codes[0] == 200 and codes[1] in (400, 403), "%s %s / %s %s" % (
              r1.status_code, U.code(r1), r2.status_code, U.code(r2)))
    check("…şi instanţa rămâne cu cel puţin un Owner", await authz.owner_count() >= 1)
    left = owner if r1.status_code == 200 else o2c
    left_id = owner_id if r1.status_code == 200 else o2
    gone_id = o2 if r1.status_code == 200 else owner_id
    r = await left.post("/api/users/%d/delete" % gone_id,
                        json={"current_password": U.OWNER_PW if left is owner else PW})
    check("ştergerea fostului Owner (acum fără rol) merge", r.status_code == 200, r.text[:160])
    check("rămâne exact un Owner", await authz.owner_count() == 1)
    lb = (await db.fetchone("SELECT id FROM role_bindings WHERE user_id=?", left_id))["id"]
    check("ultimul Owner nu-şi poate scoate singur rolul (self)",
          (await left.post("/api/users/%d/bindings/%d/delete" % (left_id, lb),
                           json={"current_password": U.OWNER_PW if left is owner else PW})).status_code == 403)
    check("owner_count exclude legătura scoasă → 0 (protecţia ar refuza)",
          await authz.owner_count(exclude_binding=lb) == 0)
    owner = left
    opw = U.OWNER_PW if left_id == owner_id else PW

    # ── token ∩ creator ──────────────────────────────────────────────────────────────────
    cr = await U.add_user("cr@x.co", bindings=[("operator", "all", "")])
    crc = await U.login("cr@x.co")
    r = await crc.post("/api/tokens", json={"name": "t", "scopes": ["read", "run"],
                                            "current_password": PW})
    check("Operator@all poate crea un token (tokens.create)", r.status_code == 200, r.text[:120])
    tok = U.client(headers={"authorization": "Bearer " + r.json()["token"]})
    r = await tok.get("/api/hosts")
    check("token: vede ce vede creatorul", sorted(h["id"] for h in r.json()) == sorted([a, b]))
    r = await tok.post("/api/hosts/%d/run" % a, json={"command": "id"})
    check("token: run trece de autorizare (cade la host offline)", r.status_code == 409,
          "%s %s" % (r.status_code, U.code(r)))
    await U.unbind_all(cr)
    await U.bind(cr, "viewer", "folder", "prod")
    r = await tok.post("/api/hosts/%d/run" % a, json={"command": "id"})
    check("creator retrogradat la Viewer → tokenul NU mai rulează (403)",
          r.status_code == 403 and U.code(r) == "authz.denied", "%s %s" % (r.status_code, U.code(r)))
    r = await tok.get("/api/hosts")
    check("…şi vede doar scope-ul NOU al creatorului", [h["id"] for h in r.json()] == [a])
    await U.unbind_all(cr)
    r = await tok.get("/api/hosts")
    check("creator fără legături → tokenul nu vede nimic", r.json() == [])
    r = await tok.get("/api/status")
    check("…status: zero, fără date de instanţă", r.json()["hosts"]["total"] == 0
          and r.json()["storage"] is None)
    await U.bind(cr, "operator", "all")
    r = await crc.post("/api/tokens", json={"name": "big", "scopes": ["read"], "role": "admin",
                                            "current_password": PW})
    check("tokenul nu poate fi creat cu un rol PESTE al creatorului", r.status_code == 403
          and U.code(r) == "authz.escalation", r.text[:120])
    r = await owner.post("/api/tokens", json={"name": "narrow", "scopes": ["read", "run"],
                                              "role": "viewer", "scope_kind": "host",
                                              "scope_value": str(a), "current_password": opw})
    check("Owner: token cu plafon Viewer@host:A", r.status_code == 200, r.text[:160])
    nt = U.client(headers={"authorization": "Bearer " + r.json()["token"]})
    check("token plafonat: vede doar A", [h["id"] for h in (await nt.get("/api/hosts")).json()] == [a])
    r = await nt.post("/api/hosts/%d/run" % a, json={"command": "id"})
    check("token plafonat Viewer: run → 403 chiar dacă are scope-ul `run`", r.status_code == 403)
    r = await nt.post("/api/hosts/%d/run" % b, json={"command": "id"})
    check("token plafonat pe A: host B → 404 (invizibil)", r.status_code == 404)
    r = await crc.post("/api/users/%d/delete" % cr, json={"current_password": PW})
    r = await owner.post("/api/users/%d/delete" % cr, json={"current_password": opw})
    check("ştergerea creatorului", r.status_code == 200, r.text[:120])
    r = await tok.get("/api/hosts")
    check("tokenul moare odată cu creatorul (401)", r.status_code == 401)
    for c in (tok, nt):
        await c.aclose()

    # ── acces derivat retras la schimbarea legăturii ─────────────────────────────────────
    sh = await U.add_user("sh@x.co", bindings=[("admin", "all", "")])
    shc = await U.login("sh@x.co")
    s1 = await U.add_session(a, state="live", created_by=sh)
    r = await shc.post("/api/sessions/%s/share" % s1, json={"writable": True})
    check("Admin: share WRITABLE creat", r.status_code == 200, r.text[:120])
    bid = (await db.fetchone("SELECT id FROM role_bindings WHERE user_id=?", sh))["id"]
    r = await owner.post("/api/users/%d/bindings" % sh, json={
        "role": "operator", "scope_kind": "all", "current_password": opw})
    r = await owner.post("/api/users/%d/bindings/%d/delete" % (sh, bid),
                         json={"current_password": opw})
    check("retrogradare Admin → Operator (prin API)", r.status_code == 200, r.text[:120])
    row = await db.fetchone("SELECT share_token FROM sessions WHERE id=?", s1)
    check("share-ul WRITABLE e revocat (Operator n-are share.live_write)", row["share_token"] is None)
    r = await shc.post("/api/sessions/%s/share" % s1, json={"writable": True})
    check("Operator nu mai poate crea un share writable (403)", r.status_code == 403
          and U.code(r) == "authz.denied")
    r = await shc.post("/api/sessions/%s/share" % s1, json={"writable": False})
    check("…dar unul read-only da (share.live)", r.status_code == 200)
    s2 = await U.add_session(a, state="closed", created_by=sh)
    await db.execute("INSERT INTO replay_links(token_hash, sid, user_id, label, redact, created,"
                     " expires) VALUES(?,?,?,?,?,?,?)", "r" * 64, s2, sh, "", 1, time.time(),
                     time.time() + 3600)
    bid = (await db.fetchone("SELECT id FROM role_bindings WHERE user_id=?", sh))["id"]
    r = await owner.post("/api/users/%d/bindings" % sh, json={
        "role": "viewer", "scope_kind": "all", "current_password": opw})
    r = await owner.post("/api/users/%d/bindings/%d/delete" % (sh, bid),
                         json={"current_password": opw})
    row = await db.fetchone("SELECT share_token FROM sessions WHERE id=?", s1)
    check("retrogradat la Viewer → share-ul read-only e revocat (fără share.live)",
          row["share_token"] is None)
    check("…şi link-ul de replay (fără share.replay)",
          not await db.fetchone("SELECT 1 FROM replay_links WHERE user_id=?", sh))
    al = await db.fetchall("SELECT kind, msg_params FROM alerts WHERE user_id=? AND kind='account_change'", sh)
    check("contul afectat e anunţat (accesul tău s-a schimbat)", len(al) >= 1, str(al))
    au = await db.fetchall("SELECT detail FROM audit_log WHERE detail LIKE 'role %'")
    check("fiecare schimbare de legătură e în jurnalul de audit", len(au) >= 4, str(len(au)))

    # ── id-urile de host se reutilizează: o legătură pe un host şters NU se lipeşte de cel nou ──
    x = await U.add_host(owner, "temp", folder="tmp")
    hu = await U.add_user("hu@x.co", bindings=[("operator", "host", x)])
    r = await owner.delete("/api/hosts/%d" % x)
    check("ştergerea hostului", r.status_code == 200, r.text[:120])
    check("legătura host:<id> a murit odată cu hostul",
          not await db.fetchone("SELECT 1 FROM role_bindings WHERE user_id=?", hu))
    r = await owner.post("/api/users/%d/bindings" % hu, json={
        "role": "viewer", "scope_kind": "host", "scope_value": str(x), "current_password": opw})
    check("nici un Owner nu acordă acces pe un host INEXISTENT (404)", r.status_code == 404)
    r = await owner.post("/api/tokens", json={"name": "ghost", "scopes": ["read"],
                                              "scope_kind": "host", "scope_value": str(x),
                                              "current_password": opw})
    check("…nici un token plafonat pe un host inexistent (404)", r.status_code == 404)

    for c in (owner, nc, adm, o2c, crc, shc, sadm_c):
        await c.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
