"""„Explain access" (3.6.10, §A.9 + §A.11.9): GET /api/authz/explain?user=&host=.

Autorizarea (fiecare refuz cu forma lui, fără oracol):
  * oricine îşi explică SIEȘI accesul pe un host pe care îl vede; pe unul pe care nu-l vede →
    404 IDENTIC cu un host inexistent;
  * despre ALT cont doar cu `users.manage` — fără el 403 `authz.denied` ÎNAINTE de orice citire
    (acelaşi răspuns pentru un cont existent şi unul inexistent: nu afli ce id-uri există);
  * un admin restrâns (users.manage @ all, dar hosturi doar într-un folder) primeşte 404 pentru
    un host din afara scope-ului lui — acelaşi corp ca pentru un id inexistent;
  * un token de automatizare nu ajunge aici (ruta e doar pe cookie).
Conţinutul:
  * legăturile care se POTRIVESC hostului (directe şi din SSO, cu grupul), rolul, scope-ul,
    permisiunile fiecăreia, setul efectiv; legăturile peste alte scope-uri NU apar;
  * o legătură expirată apare ca ignorată (nota `expiredIgnored`), nu contribuie;
  * note: host crown-jewel, step-up (2FA), tokenuri plafonate, permisiuni globale ignorate pe o
    legătură care nu e la scope `all`, „niciun acces".
"""
import asyncio
import json
import time

import rbac_util as U
from app import authz, db

check = U.Checker()


async def main():
    await U.boot()
    owner = await U.owner_client()
    a = await U.add_host(owner, "alpha", folder="prod", tags="db")
    b = await U.add_host(owner, "beta", folder="lab")
    owner_id = (await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL))["id"]

    ana_id = await U.add_user("ana@x.co", bindings=[("operator", "folder", "prod"),
                                                    ("viewer", "folder", "lab")])
    ana = await U.login("ana@x.co")
    nobody_id = await U.add_user("nobody@x.co")
    nobody = await U.login("nobody@x.co")
    # admin restrâns: users.manage peste tot, dar hosturi doar în `lab`
    rid = await db.execute(
        "INSERT INTO roles(key, name, description, perms, builtin, created, updated)"
        " VALUES(NULL,'UserMgr','',?,0,?,?)", json.dumps(["users.manage"]), time.time(), time.time())
    sadm_id = await U.add_user("sadm@x.co", bindings=[("operator", "folder", "lab")])
    await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                     " created) VALUES(?,?,'all','','manual',?)", sadm_id, rid, time.time())
    authz.bump_epoch()
    sadm = await U.login("sadm@x.co")

    async def ex(c, uid, hid):
        return await c.get("/api/authz/explain", params={"user": uid, "host": hid})

    # ── autorizare ───────────────────────────────────────────────────────────────────────
    r = await ex(ana, ana_id, a)
    check("self, host vizibil → 200", r.status_code == 200, r.text[:200])
    r_missing = await ex(ana, ana_id, 987654)
    check("self, host inexistent → 404 host.missing",
          r_missing.status_code == 404 and U.code(r_missing) == "host.missing")
    r = await ex(nobody, nobody_id, a)
    check("self fără acces la host → 404 IDENTIC cu inexistent",
          r.status_code == 404 and U.code(r) == "host.missing" and r.text == r_missing.text,
          "%s %s" % (r.status_code, r.text[:120]))
    for label, target in (("alt cont existent", owner_id), ("id inexistent", 999999)):
        r = await ex(ana, target, a)
        check("fără users.manage, despre %s → 403 authz.denied" % label,
              r.status_code == 403 and U.code(r) == "authz.denied", "%s %s" % (r.status_code, r.text[:120]))
    r1, r2 = await ex(ana, owner_id, a), await ex(ana, 999999, a)
    check("…acelaşi corp pentru cont existent şi inexistent (fără oracol de id)", r1.text == r2.text)
    r = await ex(owner, ana_id, a)
    check("users.manage (Owner) despre alt cont → 200", r.status_code == 200, r.text[:160])
    r = await ex(owner, 999999, a)
    check("users.manage despre un cont inexistent → 404 user.missing",
          r.status_code == 404 and U.code(r) == "user.missing")
    r = await ex(sadm, ana_id, b)
    check("admin restrâns, host în scope-ul lui → 200", r.status_code == 200, r.text[:160])
    r_out = await ex(sadm, ana_id, a)
    r_none = await ex(sadm, ana_id, 987654)
    check("admin restrâns, host DIN AFARA scope-ului → 404 host.missing",
          r_out.status_code == 404 and U.code(r_out) == "host.missing", r_out.text[:120])
    check("…corp identic cu un host inexistent", r_out.text == r_none.text)
    # vizualizator: nu are users.manage → 403 pe alţii, 200 pe sine
    vw_id = await U.add_user("vw@x.co", bindings=[("viewer", "all", "")])
    vw = await U.login("vw@x.co")
    r = await ex(vw, ana_id, a)
    check("Viewer despre alt cont → 403", r.status_code == 403 and U.code(r) == "authz.denied")
    r = await ex(vw, vw_id, a)
    check("Viewer despre sine → 200", r.status_code == 200)
    r = await owner.post("/api/tokens", json={"name": "t", "scopes": ["read", "run"], "days": 1,
                                              "current_password": U.OWNER_PW})
    tok = r.json()["token"]
    tc = U.client(headers={"authorization": "Bearer " + tok})
    r = await ex(tc, owner_id, a)
    check("token de automatizare → 401 (ruta nu acceptă tokenuri)", r.status_code == 401,
          "%s %s" % (r.status_code, r.text[:120]))
    await tc.aclose()
    r = await owner.get("/api/authz/explain")
    check("parametri lipsă → 422", r.status_code == 422)

    # ── conţinut ─────────────────────────────────────────────────────────────────────────
    j = (await ex(owner, ana_id, a)).json()
    roles = [(x["role"], x["scope_kind"], x["scope_value"]) for x in j["bindings"]]
    check("pe alpha: doar legătura care se potriveşte (Operator @ folder prod)",
          roles == [("operator", "folder", "prod")], str(roles))
    check("…cu permisiunile ei şi ⚑", "files.read" in j["bindings"][0]["perms"]
          and j["bindings"][0]["shell"] is True)
    check("…setul efectiv = Operator", set(j["effective"]) == authz.BUILTIN_ROLES["operator"]["perms"]
          & authz.HOST_PERMS, str(j["effective"]))
    check("…utilizatorul şi hostul descrise", j["user"]["email"] == "ana@x.co"
          and j["host"]["name"] == "alpha" and j["host"]["folder"] == "prod")
    j = (await ex(owner, ana_id, b)).json()
    check("pe beta: Viewer @ folder lab, fără ⚑", [x["role"] for x in j["bindings"]] == ["viewer"]
          and j["shell"] is False and "files.read" not in j["effective"], str(j)[:200])

    # expirată = ignorată
    bid = await U.bind(ana_id, "admin", "tag", "db")
    await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() - 5, bid)
    authz.bump_epoch()
    j = (await ex(owner, ana_id, a)).json()
    exp = [x for x in j["bindings"] if x["id"] == bid]
    check("legătură expirată: listată, marcată expired", len(exp) == 1 and exp[0]["expired"] is True,
          str(j["bindings"])[:200])
    check("…cu nota expiredIgnored", {"code": "expiredIgnored", "binding": bid} in j["notes"])
    check("…şi NU contribuie (host.admin lipseşte din efectiv)", "host.admin" not in j["effective"])
    check("…iar „globale ignorate\" nu se raportează pentru o legătură expirată",
          {"code": "globalNeedsAll", "binding": bid} not in j["notes"])
    await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() + 3600, bid)
    authz.bump_epoch()
    j = (await ex(owner, ana_id, a)).json()
    check("aceeaşi legătură, încă valabilă: contribuie + nota globalNeedsAll (Admin pe un tag)",
          "host.admin" in j["effective"]
          and {"code": "globalNeedsAll", "binding": bid} in j["notes"], str(j["notes"]))
    await db.execute("DELETE FROM role_bindings WHERE id=?", bid)
    authz.bump_epoch()

    # SSO: grupul de unde vine legătura
    await db.execute("INSERT INTO oidc_group_roles(grp, role_id, scope_kind, scope_value, created)"
                     " VALUES('wt-db', ?, 'tag', 'db', ?)", await authz.role_id("viewer"), time.time())
    await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                     " created) VALUES(?,?,'tag','db','sso',?)", ana_id,
                     await authz.role_id("viewer"), time.time())
    await db.execute("UPDATE users SET sso_groups=? WHERE id=?", json.dumps(["wt-db"]), ana_id)
    authz.bump_epoch()
    j = (await ex(owner, ana_id, a)).json()
    sso = [x for x in j["bindings"] if x["source"] == "sso"]
    check("legătură SSO: sursa + grupul (wt-db)", len(sso) == 1 and sso[0]["sso_groups"] == ["wt-db"],
          str(sso))

    # note: crown-jewel, 2FA, tokenuri
    await db.execute("UPDATE hosts SET crown_jewel=1, require_2fa=1 WHERE id=?", a)
    await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by,"
                     " created_by_id, expires) VALUES('x','h-ana','read',?,?,?,?)", time.time(),
                     "ana@x.co", ana_id, time.time() + 3600)
    j = (await ex(ana, ana_id, a)).json()
    codes = {n["code"] for n in j["notes"]}
    check("note: crownJewel + stepUp + tokensCapped", {"crownJewel", "stepUp", "tokensCapped"} <= codes,
          str(codes))
    check("…şi hostul spune crown_jewel/require_2fa", j["host"]["crown_jewel"] and j["host"]["require_2fa"])
    check("self: user.self = true", j["user"]["self"] is True)
    # niciun acces pe un host pe care îl vede cine întreabă
    j = (await ex(owner, nobody_id, b)).json()
    check("cont fără legături: listă goală + nota noAccess",
          j["bindings"] == [] and j["effective"] == [] and {"code": "noAccess"} in j["notes"], str(j)[:200])
    # o legătură peste ALT scope nu apare (nu dezvăluie scope-uri)
    j = (await ex(sadm, ana_id, b)).json()
    check("admin restrâns: pe beta nu vede legătura lui Ana peste folder prod",
          all(x["scope_value"] != "prod" for x in j["bindings"]), str(j["bindings"]))

    for c in (owner, ana, nobody, sadm, vw):
        await c.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
