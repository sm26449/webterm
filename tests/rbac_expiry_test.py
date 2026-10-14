"""Legături temporare (3.6.10, §A.10): „Operator pe prod pentru 4 ore".

  * acordarea cu `expires` (validat: în viitor, cel mult 366 de zile); listată cu sfârşitul ei;
  * expirarea e aplicată la CITIRE, fără janitor: în secunda în care expiră, hostul dispare
    (listă, rută de host → 404), iar /api/me/permissions nu mai are legătura;
  * janitorul (api.sweep_expired_bindings, din reaper) şterge DOAR rândurile expirate, creşte
    epoca (socket-urile re-verifică), lasă câte un rând de audit „role binding expired";
  * schimbarea sfârşitului (POST …/bindings/{bid}/expiry): „permanent" (extindere = reguli de
    acordare), mai devreme (= reguli de scoatere); legătura SSO refuzată; Admin nu atinge Owner;
  * nu te blochezi niciodată afară: ultimul Owner PERMANENT nu poate fi făcut temporar, nici
    scos, nici şters — un Owner temporar nu „ţine locul" unuia permanent;
  * o legătură temporară peste una venită din SSO e refuzată (ar scurta accesul dat de grup);
  * break-glass `python3 -m app.admin promote` lasă un Owner PERMANENT chiar dacă avea unul
    temporar.
"""
import argparse
import asyncio
import time

import rbac_util as U
from app import admin, api, authz, db

check = U.Checker()
PW = "parolabuna1"


def bb(role, kind="all", value="", expires=None, pw=U.OWNER_PW, **extra):
    return dict({"role": role, "scope_kind": kind, "scope_value": value, "expires": expires,
                 "current_password": pw}, **extra)


async def bindings(uid):
    return await db.fetchall("SELECT b.id, r.key, b.scope_kind, b.scope_value, b.expires, b.source"
                             " FROM role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=?"
                             " ORDER BY b.id", uid)


async def main():
    await U.boot()
    owner = await U.owner_client()
    a = await U.add_host(owner, "alpha", folder="prod")
    owner_id = (await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL))["id"]
    ana_id = await U.add_user("ana@x.co")
    ana = await U.login("ana@x.co")

    # ── acordare temporară + validare ──────────────────────────────────────────────────
    for exp, st, cd, label in ((time.time() - 10, 400, "authz.badExpiry", "în trecut"),
                               (time.time() + 20, 400, "authz.badExpiry", "sub un minut"),
                               (time.time() + 400 * 86400, 400, "authz.expiryTooFar", "peste 366 de zile")):
        r = await owner.post("/api/users/%d/bindings" % ana_id, json=bb("operator", "folder", "prod", exp))
        check("expires %s → %d %s" % (label, st, cd), r.status_code == st and U.code(r) == cd,
              "%s %s" % (r.status_code, r.text[:120]))
    check("…nicio legătură scrisă de cererile refuzate", await bindings(ana_id) == [])
    end = time.time() + 4 * 3600
    r = await owner.post("/api/users/%d/bindings" % ana_id, json=bb("operator", "folder", "prod", end))
    rows = await bindings(ana_id)
    check("Operator @ prod pentru 4 ore → 200, cu expires", r.status_code == 200 and len(rows) == 1
          and abs(rows[0]["expires"] - end) < 1, r.text[:160])
    lst = {u["email"]: u for u in (await owner.get("/api/users")).json()}
    check("…listată cu sfârşitul ei", abs((lst["ana@x.co"]["bindings"][0]["expires"] or 0) - end) < 1)
    check("…Ana vede alpha", any(h["id"] == a for h in (await ana.get("/api/hosts")).json()))
    audit = await db.fetchone("SELECT detail FROM audit_log WHERE detail LIKE '%granted operator%'"
                              " ORDER BY id DESC LIMIT 1")
    check("…auditat cu sfârşitul („until … UTC\")", audit is not None and "until" in audit["detail"],
          str(audit and audit["detail"]))

    # ── aplicată la citire, fără janitor ŞI fără să golim cache-ul (revizuirea 3.6.10) ──
    bid = rows[0]["id"]
    end = time.time() + 1.5
    await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", end, bid)
    authz.bump_epoch()                 # ca după o acordare: cache-ul se reumple la cererea următoare
    wake = authz.subscribe()           # ca un terminal deschis
    check("înainte de sfârşit: alpha vizibilă (cache-ul se umple)",
          any(h["id"] == a for h in (await ana.get("/api/hosts")).json()))
    check("…intrarea din cache ţine minte sfârşitul cel mai apropiat",
          (authz._cache.get(ana_id) or (0, 0, None))[2] == end, str(authz._cache.get(ana_id)))
    tok = {"id": 1, "name": "t", "scopes": "read", "created_by_id": ana_id}
    alpha_ref = await authz.host_ref(a)
    check("…un token al Anei (read) vede alpha cât ţine legătura",
          "host.view" in (await authz.grants_for_token(tok)).on(alpha_ref))
    await asyncio.sleep(max(0.0, end - time.time()) + 0.2)
    check("…după sfârşit tokenul (creator ∩) nu mai vede nimic, tot fără golirea cache-ului",
          not (await authz.grants_for_token(tok)).on(alpha_ref))
    check("…la sfârşit, socket-urile deschise sunt trezite (fără epocă, fără janitor)", wake.is_set())
    authz.unsubscribe(wake)
    check("…cache-ul NU a fost golit manual (epoca e aceeaşi)", ana_id in authz._cache)
    hosts = (await ana.get("/api/hosts")).json()
    check("expirată (janitorul n-a rulat): alpha dispare din listă", all(h["id"] != a for h in hosts),
          str(hosts)[:120])
    r = await ana.get("/api/hosts/%d/events" % a)
    check("…ruta de host → 404 host.missing", r.status_code == 404 and U.code(r) == "host.missing",
          "%s %s" % (r.status_code, r.text[:80]))
    me = (await ana.get("/api/me/permissions")).json()
    check("…/api/me/permissions fără legătură", me["bindings"] == [] and me["all_hosts"] == [])
    check("…rândul e încă în DB (doar janitorul îl şterge)", len(await bindings(ana_id)) == 1)

    # ── janitorul ──────────────────────────────────────────────────────────────────────
    keep = await U.bind(ana_id, "viewer", "folder", "lab")             # permanentă
    later = await U.bind(ana_id, "viewer", "folder", "x")
    await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() + 3600, later)
    ep = authz.epoch()
    n = await api.sweep_expired_bindings()
    left = [r["id"] for r in await bindings(ana_id)]
    check("janitor: şterge exact legătura expirată", n == 1 and bid not in left
          and keep in left and later in left, "%s %s" % (n, left))
    check("…creşte epoca (socket-urile re-verifică acum)", authz.epoch() > ep)
    au = await db.fetchone("SELECT actor, path, detail FROM audit_log WHERE path='/janitor/binding-expired'")
    check("…audit „role binding expired\" (actor system)", au is not None and au["actor"] == "system"
          and "ana@x.co lost operator" in au["detail"], str(au and dict(au)))
    ep = authz.epoch()
    check("a doua trecere: nimic de făcut, epoca neatinsă",
          await api.sweep_expired_bindings() == 0 and authz.epoch() == ep)

    # ── schimbarea sfârşitului ─────────────────────────────────────────────────────────
    def xb(expires, pw=U.OWNER_PW):
        return {"expires": expires, "current_password": pw}
    r = await owner.post("/api/users/%d/bindings/%d/expiry" % (ana_id, later), json=xb(None))
    row = await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", later)
    check("„fă permanentă\" → expires NULL", r.status_code == 200 and row["expires"] is None, r.text[:160])
    soon = time.time() + 3600
    r = await owner.post("/api/users/%d/bindings/%d/expiry" % (ana_id, later), json=xb(soon))
    row = await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", later)
    check("permanentă → temporară (1 h)", r.status_code == 200 and abs(row["expires"] - soon) < 1)
    r = await owner.post("/api/users/%d/bindings/%d/expiry" % (ana_id, later), json=xb(None, "gresit"))
    check("parolă greşită → 401, nimic schimbat", r.status_code == 401
          and (await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", later))["expires"] is not None)
    r = await ana.post("/api/users/%d/bindings/%d/expiry" % (ana_id, later), json=xb(None, PW))
    check("fără users.manage → 403", r.status_code == 403)
    r = await owner.post("/api/users/%d/bindings/%d/expiry" % (ana_id, 987654), json=xb(None))
    check("legătură inexistentă → 404", r.status_code == 404 and U.code(r) == "authz.bindingMissing")
    sso_bid = await db.execute(
        "INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source, created)"
        " VALUES(?,?,'tag','web','sso',?)", ana_id, await authz.role_id("viewer"), time.time())
    authz.bump_epoch()
    r = await owner.post("/api/users/%d/bindings/%d/expiry" % (ana_id, sso_bid), json=xb(soon))
    check("legătură SSO → 409 authz.ssoBinding", r.status_code == 409 and U.code(r) == "authz.ssoBinding")
    r = await owner.post("/api/users/%d/bindings" % ana_id, json=bb("viewer", "tag", "web", soon))
    check("temporară peste una SSO identică → 409 (n-o scurtăm tăcut)",
          r.status_code == 409 and U.code(r) == "authz.bindingExists", r.text[:120])
    r = await owner.post("/api/users/%d/bindings" % ana_id, json=bb("viewer", "tag", "web"))
    src = (await db.fetchone("SELECT source FROM role_bindings WHERE id=?", sso_bid))["source"]
    check("…permanentă peste una SSO: adoptată ca manuală (ca în 3.6.2)", r.status_code == 200
          and src == "manual", r.text[:120])

    # ── ultimul Owner PERMANENT ────────────────────────────────────────────────────────
    o2_id = await U.add_user("o2@x.co", bindings=[("owner", "all", "")])
    o2 = await U.login("o2@x.co")
    o2_bid = (await bindings(o2_id))[0]["id"]
    own_bid = (await bindings(owner_id))[0]["id"]
    r = await owner.post("/api/users/%d/bindings/%d/expiry" % (o2_id, o2_bid), json=xb(soon))
    check("al doilea Owner făcut temporar (primul rămâne permanent) → 200", r.status_code == 200, r.text[:120])
    r = await o2.post("/api/users/%d/bindings/%d/expiry" % (owner_id, own_bid), json=xb(soon, PW))
    check("ultimul Owner permanent făcut temporar → 400 authz.lastOwner",
          r.status_code == 400 and U.code(r) == "authz.lastOwner", "%s %s" % (r.status_code, r.text[:120]))
    check("…rămâne permanent",
          (await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", own_bid))["expires"] is None)
    r = await o2.post("/api/users/%d/bindings/%d/delete" % (owner_id, own_bid),
                      json={"current_password": PW})
    check("…nici scos de un Owner TEMPORAR (nu ţine locul unui permanent) → 400",
          r.status_code == 400 and U.code(r) == "authz.lastOwner", r.text[:120])
    r = await o2.post("/api/users/%d/delete" % owner_id, json={"current_password": PW})
    check("…nici contul lui şters → 400 authz.lastOwner",
          r.status_code == 400 and U.code(r) == "authz.lastOwner", r.text[:120])
    tmp_id = await U.add_user("tmp@x.co")
    r = await owner.post("/api/users/%d/bindings" % tmp_id, json=bb("owner", "all", "", soon))
    check("Owner temporar NOU, cât există un Owner permanent → 200", r.status_code == 200, r.text[:120])
    # stare stricată (doar prin DB): fără niciun Owner permanent în afara ţintei → refuzat
    await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() + 7200, own_bid)
    authz.bump_epoch()
    t2 = await U.add_user("tmp2@x.co")
    r = await o2.post("/api/users/%d/bindings" % t2, json=bb("owner", "all", "", soon, pw=PW))
    check("Owner temporar NOU fără niciun Owner permanent → 400 authz.lastOwner",
          r.status_code == 400 and U.code(r) == "authz.lastOwner", r.text[:120])
    r = await o2.post("/api/users/%d/bindings/%d/expiry" % (owner_id, own_bid), json=xb(None, PW))
    check("…dar a face permanent un Owner temporar merge (repară starea)", r.status_code == 200
          and (await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", own_bid))["expires"] is None,
          r.text[:120])
    # Admin nu atinge un Owner
    adm_id = await U.add_user("adm@x.co", bindings=[("admin", "all", "")])
    adm = await U.login("adm@x.co")
    r = await adm.post("/api/users/%d/bindings/%d/expiry" % (o2_id, o2_bid), json=xb(None, PW))
    check("Admin schimbă sfârşitul unui Owner → 403 authz.ownerOnly",
          r.status_code == 403 and U.code(r) == "authz.ownerOnly")
    r = await adm.post("/api/users/%d/bindings/%d/expiry" % (adm_id, 1), json=xb(None, PW))
    check("propria legătură → 403 authz.selfBinding", r.status_code == 403 and U.code(r) == "authz.selfBinding")

    # ── break-glass: promote lasă un Owner PERMANENT ───────────────────────────────────
    await admin.cmd_promote(argparse.Namespace(email="o2@x.co"))
    row = await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", o2_bid)
    check("admin promote: Owner-ul temporar devine permanent", row["expires"] is None, str(dict(row)))

    for c in (owner, ana, o2, adm):
        await c.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
