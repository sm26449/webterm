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

Revizuirea 3.6.10: expirarea nu aşteaptă cache-ul de 30 s (nici pentru tokenul creatorului), iar
socket-urile deschise sunt trezite la sfârşit; ruta de sfârşit decide pe rândul de sub lock (409
dacă s-a schimbat); o acordare (legătură, prelungire, cont nou cu rol, mapare SSO, permisiune nouă
într-un rol folosit) nu trăieşte mai mult decât dreptul celui care o face (403
`authz.granterExpires`) — şi pentru un Owner temporar.
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

    # ── cursă (revizuirea 3.6.10): legătura se schimbă în timpul re-auth-ului ──────────
    race = await U.bind(ana_id, "viewer", "folder", "race")
    await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() + 7200, race)
    authz.bump_epoch()
    meanwhile = time.time() + 600

    async def exp_of(b):
        r = await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", b)
        return r["expires"] if r else "gone"

    orig_reauth, orig_recheck = api._reauth_for_access_change, api._recheck_granter

    async def reauth_then_shorten(*a, **k):
        await orig_reauth(*a, **k)
        await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", meanwhile, race)
    api._reauth_for_access_change = reauth_then_shorten
    try:
        # cererea: 2 h → 1 h („mai scurt", reguli de scoatere); între timp a devenit 10 min, deci
        # aceeaşi cerere ar fi devenit o EXTINDERE — decisă pe rândul vechi, ar fi ocolit acordarea
        r = await owner.post("/api/users/%d/bindings/%d/expiry" % (ana_id, race), json=xb(time.time() + 3600))
    finally:
        api._reauth_for_access_change = orig_reauth
    check("sfârşitul schimbat în timpul re-auth-ului → 409 authz.bindingChanged",
          r.status_code == 409 and U.code(r) == "authz.bindingChanged", "%s %s" % (r.status_code, r.text[:120]))
    check("…rândul păstrează valoarea de între timp", abs((await exp_of(race)) - meanwhile) < 1)

    async def recheck_then_change(*a, **k):
        out = await orig_recheck(*a, **k)
        await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", meanwhile + 60, race)
        return out
    api._recheck_granter = recheck_then_change
    try:
        r = await owner.post("/api/users/%d/bindings/%d/expiry" % (ana_id, race), json=xb(None))
    finally:
        api._recheck_granter = orig_recheck
    check("…schimbat chiar înainte de UPDATE: gardă `expires IS <vechi>` → 409, nimic scris",
          r.status_code == 409 and U.code(r) == "authz.bindingChanged"
          and abs((await exp_of(race)) - (meanwhile + 60)) < 1, "%s %s" % (r.status_code, r.text[:120]))

    async def reauth_then_delete(*a, **k):
        await orig_reauth(*a, **k)
        await db.execute("DELETE FROM role_bindings WHERE id=?", race)
    api._reauth_for_access_change = reauth_then_delete
    try:
        r = await owner.post("/api/users/%d/bindings/%d/expiry" % (ana_id, race), json=xb(None))
    finally:
        api._reauth_for_access_change = orig_reauth
    check("…scoasă în timpul re-auth-ului → 404, nimic re-creat",
          r.status_code == 404 and await exp_of(race) == "gone", "%s %s" % (r.status_code, r.text[:120]))
    authz.bump_epoch()

    # ── o acordare nu trăieşte mai mult decât dreptul celui care o face (revizuirea 3.6.10) ──
    t_end = time.time() + 3600

    async def temp_user(email, role, kind="all", value=""):
        uid_ = await U.add_user(email)
        b = await U.bind(uid_, role, kind, value)
        await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", t_end, b)
        authz.bump_epoch()
        return uid_, b, await U.login(email)

    ta_id, ta_bid, ta = await temp_user("tadm@x.co", "admin")          # Admin @ all, 1 oră
    tb_id, tb_bid, tb = await temp_user("tadm2@x.co", "admin")         # încă unul, tot 1 oră
    vic = await U.add_user("victim@x.co")
    r = await ta.post("/api/users/%d/bindings" % vic, json=bb("admin", pw=PW))
    check("Admin temporar dă Admin PERMANENT → 403 authz.granterExpires",
          r.status_code == 403 and U.code(r) == "authz.granterExpires", "%s %s" % (r.status_code, r.text[:160]))
    check("…mesajul spune până când ţine dreptul lui", "until" in (r.json().get("vars") or {})
          or "UTC" in r.text, r.text[:200])
    r = await ta.post("/api/users/%d/bindings" % vic, json=bb("admin", expires=t_end + 3600, pw=PW))
    check("…şi un sfârşit DUPĂ al lui → 403", r.status_code == 403 and U.code(r) == "authz.granterExpires")
    check("…nimic scris", await bindings(vic) == [])
    r = await ta.post("/api/users/%d/bindings" % vic, json=bb("operator", "folder", "prod",
                                                              expires=t_end - 600, pw=PW))
    check("…un sfârşit înainte de al lui → 200", r.status_code == 200, r.text[:160])
    r = await ta.post("/api/users/%d/bindings/%d/expiry" % (tb_id, tb_bid), json=xb(None, PW))
    check("doi Admini temporari: unul îl face pe celălalt permanent → 403 authz.granterExpires",
          r.status_code == 403 and U.code(r) == "authz.granterExpires", r.text[:160])
    r = await ta.post("/api/users/%d/bindings/%d/expiry" % (tb_id, tb_bid), json=xb(t_end + 86400, PW))
    check("…nici o prelungire peste sfârşitul lui", r.status_code == 403 and U.code(r) == "authz.granterExpires")
    check("…legătura celuilalt neschimbată",
          abs((await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", tb_bid))["expires"] - t_end) < 1)
    r = await ta.post("/api/users/%d/bindings/%d/expiry" % (tb_id, tb_bid), json=xb(t_end - 900, PW))
    check("…scurtarea (reguli de scoatere) merge", r.status_code == 200, r.text[:160])
    newu = {"email": "fresh@x.co", "password": "parolabuna1", "current_password": PW,
            "role": "admin", "scope_kind": "all", "scope_value": ""}
    r = await ta.post("/api/users", json=newu)
    check("cont nou cu rol PERMANENT de la un Admin temporar → 403, contul nu e creat",
          r.status_code == 403 and U.code(r) == "authz.granterExpires"
          and not await db.fetchone("SELECT 1 FROM users WHERE email='fresh@x.co'"), r.text[:160])
    r = await ta.post("/api/users", json=dict(newu, expires=t_end - 60))
    fresh = await db.fetchone("SELECT id FROM users WHERE email='fresh@x.co'")
    rows_f = await bindings(fresh["id"]) if fresh else []
    check("…cu sfârşit înainte de al lui → 200, legătura iniţială e temporară",
          r.status_code == 200 and len(rows_f) == 1 and abs(rows_f[0]["expires"] - (t_end - 60)) < 1,
          r.text[:160])
    r = await ta.post("/api/settings/oidc-roles", json={"group": "g-tmp", "role": "viewer",
                                                       "scope_kind": "all", "current_password": PW})
    check("mapare SSO (mereu permanentă) de la un Admin temporar → 403 authz.granterExpires",
          r.status_code == 403 and U.code(r) == "authz.granterExpires", r.text[:160])
    rr = await owner.post("/api/roles", json={"name": "Used", "perms": ["host.view"],
                                              "current_password": U.OWNER_PW})
    used_rid = rr.json()["id"]
    await owner.post("/api/users/%d/bindings" % vic, json={"role_id": used_rid, "scope_kind": "all",
                                                          "current_password": U.OWNER_PW})
    r = await ta.patch("/api/roles/%d" % used_rid, json={"name": "Used", "perms": ["host.view", "run"],
                                                         "current_password": PW})
    check("Admin temporar adaugă o permisiune unui rol FOLOSIT → 403 authz.granterExpires",
          r.status_code == 403 and U.code(r) == "authz.granterExpires", r.text[:160])
    r = await ta.patch("/api/roles/%d" % used_rid, json={"name": "Used2", "perms": ["host.view"],
                                                         "current_password": PW})
    check("…redenumirea fără permisiuni noi merge", r.status_code == 200, r.text[:160])
    # re-revizuire: un rol folosit DOAR de un token e tot „folosit" (plafonul tokenului e acces)
    rr = await owner.post("/api/roles", json={"name": "TokOnly", "perms": ["host.view"],
                                              "current_password": U.OWNER_PW})
    tok_rid = rr.json()["id"]
    await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, expires, role_id)"
                     " VALUES('t-only', 'x' || hex(randomblob(16)), 'read', 0, ?, ?)", time.time() + 3600, tok_rid)
    r = await ta.patch("/api/roles/%d" % tok_rid, json={"name": "TokOnly", "perms": ["host.view", "run"],
                                                        "current_password": PW})
    check("Admin temporar adaugă o permisiune unui rol folosit DOAR de un token → 403 authz.granterExpires",
          r.status_code == 403 and U.code(r) == "authz.granterExpires", r.text[:160])
    # Owner temporar: aceeaşi regulă
    to_id, to_bid, to = await temp_user("towner@x.co", "owner")
    r = await to.post("/api/users/%d/bindings" % vic, json=bb("viewer", "folder", "lab", pw=PW))
    check("Owner TEMPORAR dă un rol permanent → 403 authz.granterExpires",
          r.status_code == 403 and U.code(r) == "authz.granterExpires", r.text[:160])
    # drept permanent din altă legătură: fără plafon
    pa_id = await U.add_user("padm@x.co", bindings=[("admin", "all", "")])
    pb = await U.bind(pa_id, "owner", "all", "")
    await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", t_end, pb)
    authz.bump_epoch()
    pa = await U.login("padm@x.co")
    r = await pa.post("/api/users/%d/bindings" % vic, json=bb("viewer", "folder", "lab", pw=PW))
    check("Admin PERMANENT (+ Owner temporar) dă un rol permanent → 200 (dreptul nu depinde "
          "de legătura temporară)", r.status_code == 200, r.text[:160])
    r = await pa.post("/api/users/%d/bindings" % vic, json=bb("owner", pw=PW))
    check("…dar Owner permanent cere Owner-ul lui (temporar) → 403", r.status_code == 403
          and U.code(r) == "authz.granterExpires", r.text[:160])
    for c in (ta, tb, to, pa):
        await c.aclose()
    for u_ in (ta_id, tb_id, to_id, pa_id):
        await U.unbind_all(u_)

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
    check("…un Owner TEMPORAR nu poate face pe altul permanent (403 authz.granterExpires); "
          "repararea = `admin promote`", r.status_code == 403 and U.code(r) == "authz.granterExpires"
          and (await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", own_bid))["expires"] is not None,
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
