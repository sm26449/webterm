"""Hosturi „crown jewel" (3.6.10, §A.11.2): hostul care rulează gateway-ul (sau îi ţine backup-urile)
ESTE instanţa — un shell acolo citeşte DB-ul şi cheia seifului.

  * marcajul: doar un Owner îl pune / scoate (Admin → 403 ownerOnly, Viewer → 403, out-of-scope →
    404); scoaterea cere parola (reduce o protecţie); ambele auditate; răspunsul listează cine
    are DEJA un shell acolo (legături + mapări SSO ne-Owner cu ⚑);
  * o legătură NOUĂ cu un rol ne-Owner care are ⚑, peste un scope care include hostul, e refuzată
    cu 409 `authz.crownJewel` (lista hosturilor în vars) — ÎNAINTE de a consuma al doilea factor —
    şi trece cu `confirm_crown_jewel: true`, auditată ca CONFIRMED; Viewer (fără ⚑) şi Owner nu
    cer confirmare; un scope care nu include hostul nici atât;
  * aceeaşi regulă la crearea unui cont cu rol, la o mapare SSO şi la mutarea hostului
    (folder/tag) într-un scope peste care există deja legături ⚑;
  * /api/hosts şi explain: `crown_jewel` doar pentru Owner şi users.manage (niciodată Viewer sau
    token — revizuirea 3.6.10); indiciul „gateway" doar pentru Owner.
"""
import asyncio
import time

import rbac_util as U
from app import api, authz, db

check = U.Checker()
PW = "parolabuna1"


def bb(role, kind="all", value="", pw=U.OWNER_PW, **extra):
    return dict({"role": role, "scope_kind": kind, "scope_value": value, "current_password": pw},
                **extra)


async def last_audit(like):
    r = await db.fetchone("SELECT detail FROM audit_log WHERE detail LIKE ? ORDER BY id DESC LIMIT 1",
                          like)
    return r["detail"] if r else ""


async def main():
    await U.boot()
    owner = await U.owner_client()
    gw = await U.add_host(owner, "gw01", folder="infra", tags="core")
    web = await U.add_host(owner, "web01", folder="prod")
    adm_id = await U.add_user("adm@x.co", bindings=[("admin", "all", "")])
    adm = await U.login("adm@x.co")
    vw = await U.login((await db.fetchone("SELECT email FROM users WHERE id=?",
                                          await U.add_user("vw@x.co", bindings=[("viewer", "all", "")])))["email"])
    lab_id = await U.add_user("lab@x.co", bindings=[("operator", "folder", "lab")])
    lab = await U.login("lab@x.co")
    ana_id = await U.add_user("ana@x.co")

    # ── marcajul ─────────────────────────────────────────────────────────────────────────
    r = await adm.post("/api/hosts/%d/crown-jewel" % gw, json={"enabled": True})
    check("Admin marchează → 403 authz.ownerOnly", r.status_code == 403 and U.code(r) == "authz.ownerOnly")
    r = await vw.post("/api/hosts/%d/crown-jewel" % gw, json={"enabled": True})
    check("Viewer → 403 authz.denied", r.status_code == 403 and U.code(r) == "authz.denied")
    r = await lab.post("/api/hosts/%d/crown-jewel" % gw, json={"enabled": True})
    check("cont fără acces la host → 404 host.missing", r.status_code == 404 and U.code(r) == "host.missing")
    # o legătură ⚑ existentă peste host, înainte de marcaj
    await U.bind(ana_id, "operator", "tag", "core")
    r = await owner.post("/api/hosts/%d/crown-jewel" % gw, json={"enabled": True})
    j = r.json()
    check("Owner marchează → 200, fără parolă (întăreşte)", r.status_code == 200 and j["crown_jewel"], r.text[:160])
    check("…răspunsul listează cine are DEJA un shell acolo (Admin @ all, Operator @ tag; nu Viewer)",
          sorted((e["kind"], e["who"], e["role"]) for e in j["exposure"])
          == [("binding", "adm@x.co", "admin"), ("binding", "ana@x.co", "operator")],
          str(j["exposure"]))
    check("…auditat", "gw01 marked as a crown jewel" in await last_audit("%crown jewel%"))
    # revizuirea 3.6.10: marcajul spune „aici rulează WebTerm" — doar Owner şi users.manage îl văd
    hosts = {h["id"]: h for h in (await owner.get("/api/hosts")).json()}
    check("/api/hosts: Owner vede crown_jewel", hosts[gw]["crown_jewel"] is True
          and hosts[web]["crown_jewel"] is False)
    hosts = {h["id"]: h for h in (await adm.get("/api/hosts")).json()}
    check("…users.manage (Admin) îl vede", hosts[gw].get("crown_jewel") is True)
    um_id = await U.add_user("um@x.co")
    r = await owner.post("/api/roles", json={"name": "People", "perms": ["users.manage", "host.view"],
                                             "current_password": U.OWNER_PW})
    await U.bind(um_id, "viewer", "folder", "zzz")
    await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                     " created) VALUES(?,?,'all','','manual',0)", um_id, r.json()["id"])
    authz.bump_epoch()
    um = await U.login("um@x.co")
    hosts = {h["id"]: h for h in (await um.get("/api/hosts")).json()}
    check("…un rol custom cu users.manage îl vede", hosts.get(gw, {}).get("crown_jewel") is True,
          str(hosts.get(gw))[:120])
    await um.aclose()
    hosts = {h["id"]: h for h in (await vw.get("/api/hosts")).json()}
    check("…un Viewer (vede hostul) NU primeşte câmpul", gw in hosts and "crown_jewel" not in hosts[gw]
          and "crown_jewel" not in hosts[web])
    r = await owner.post("/api/tokens", json={"name": "mon", "scopes": ["read"], "days": 1,
                                              "current_password": U.OWNER_PW})
    tc = U.client(headers={"authorization": "Bearer " + r.json()["token"]})
    th = {h["id"]: h for h in (await tc.get("/api/hosts")).json()}
    check("…un token read (al Owner-ului) NU primeşte câmpul", gw in th and "crown_jewel" not in th[gw])
    await tc.aclose()
    vw_id = (await db.fetchone("SELECT id FROM users WHERE email='vw@x.co'"))["id"]
    ex = (await vw.get("/api/authz/explain?user=%d&host=%d" % (vw_id, gw))).json()
    check("…explain (Viewer despre el însuşi): fără crown_jewel şi fără nota crownJewel",
          "crown_jewel" not in ex["host"] and all(n["code"] != "crownJewel" for n in ex["notes"]), str(ex)[:200])
    ex = (await owner.get("/api/authz/explain?user=%d&host=%d" % (vw_id, gw))).json()
    check("…explain (Owner): crown_jewel + nota", ex["host"].get("crown_jewel") is True
          and any(n["code"] == "crownJewel" for n in ex["notes"]), str(ex)[:200])
    r = await owner.post("/api/hosts/%d/crown-jewel" % gw, json={"enabled": False})
    check("scoaterea fără parolă → 401", r.status_code == 401 and U.code(r) == "auth.wrongPassword", r.text[:120])
    r = await owner.post("/api/hosts/%d/crown-jewel" % gw,
                         json={"enabled": False, "current_password": U.OWNER_PW})
    check("scoaterea cu parolă → 200", r.status_code == 200 and r.json()["crown_jewel"] is False)
    check("…auditată", "no longer a crown jewel" in await last_audit("%crown jewel%"))
    await owner.post("/api/hosts/%d/crown-jewel" % gw, json={"enabled": True})

    # ── legături noi ─────────────────────────────────────────────────────────────────────
    target = await U.add_user("t1@x.co")
    n_before = len(await db.fetchall("SELECT id FROM role_bindings WHERE user_id=?", target))
    orig = api._reauth_for_access_change
    calls = []

    async def spy(*a, **k):
        calls.append(1)
        return await orig(*a, **k)
    api._reauth_for_access_change = spy
    try:
        r = await owner.post("/api/users/%d/bindings" % target, json=bb("operator", "folder", "infra"))
        check("Operator @ folder cu host crown-jewel → 409 authz.crownJewel",
              r.status_code == 409 and U.code(r) == "authz.crownJewel", r.text[:160])
        check("…lista hosturilor în vars", "gw01" in r.headers.get("x-webterm-error-vars", ""),
              r.headers.get("x-webterm-error-vars", ""))
        check("…ÎNAINTE de re-auth / al doilea factor", calls == [])
    finally:
        api._reauth_for_access_change = orig
    check("…nimic scris", len(await db.fetchall("SELECT id FROM role_bindings WHERE user_id=?",
                                               target)) == n_before)
    r = await owner.post("/api/users/%d/bindings" % target,
                         json=bb("operator", "folder", "infra", confirm_crown_jewel=True))
    check("…cu confirm_crown_jewel → 200", r.status_code == 200, r.text[:160])
    check("…auditat ca CONFIRMED", "CONFIRMED over crown-jewel host(s): gw01" in
          await last_audit("%granted operator @ folder infra%"))
    for role, kind, value, label in (("viewer", "all", "", "Viewer @ all (fără ⚑)"),
                                     ("operator", "folder", "prod", "Operator @ alt folder"),
                                     ("owner", "all", "", "Owner (e deja totul)")):
        t = await U.add_user("t-%s-%s@x.co" % (role, value or "all"))
        r = await owner.post("/api/users/%d/bindings" % t, json=bb(role, kind, value))
        check("%s → fără confirmare, 200" % label, r.status_code == 200, r.text[:160])
    r = await owner.post("/api/users/%d/bindings" % (await U.add_user("t2@x.co")),
                         json=bb("admin", "all", ""))
    check("Admin @ all (are ⚑, scope-ul include tot) → 409", r.status_code == 409
          and U.code(r) == "authz.crownJewel")
    r = await owner.post("/api/users/%d/bindings" % (await U.add_user("t3@x.co")),
                         json=bb("operator", "host", str(gw)))
    check("Operator @ host gw01 → 409", r.status_code == 409 and U.code(r) == "authz.crownJewel")

    # rol custom: ⚑ (files.write) vs fără ⚑
    r = await owner.post("/api/roles", json={"name": "Files", "perms": ["files.read", "files.write"],
                                             "current_password": U.OWNER_PW})
    fid = next(x["id"] for x in r.json()["custom"] if x["name"] == "Files")
    r = await owner.post("/api/roles", json={"name": "Reader", "perms": ["files.read"],
                                             "current_password": U.OWNER_PW})
    rid = next(x["id"] for x in r.json()["custom"] if x["name"] == "Reader")
    t4 = await U.add_user("t4@x.co")
    r = await owner.post("/api/users/%d/bindings" % t4, json={"role_id": fid, "scope_kind": "tag",
                                                               "scope_value": "core", "current_password": U.OWNER_PW})
    check("rol custom cu ⚑ (files.write) @ tag core → 409", r.status_code == 409)
    r = await owner.post("/api/users/%d/bindings" % t4, json={"role_id": rid, "scope_kind": "tag",
                                                               "scope_value": "core", "current_password": U.OWNER_PW})
    check("rol custom fără ⚑ (files.read) → 200", r.status_code == 200, r.text[:120])

    # cont nou cu rol
    r = await owner.post("/api/users", json={"email": "new@x.co", "password": "parolanoua1",
                                             "current_password": U.OWNER_PW, "role": "operator",
                                             "scope_kind": "folder", "scope_value": "infra"})
    check("cont nou cu Operator @ infra → 409, contul NU e creat", r.status_code == 409
          and U.code(r) == "authz.crownJewel"
          and not await db.fetchone("SELECT 1 FROM users WHERE email='new@x.co'"))
    r = await owner.post("/api/users", json={"email": "new@x.co", "password": "parolanoua1",
                                             "current_password": U.OWNER_PW, "role": "operator",
                                             "scope_kind": "folder", "scope_value": "infra",
                                             "confirm_crown_jewel": True})
    check("…confirmat → 200 + audit CONFIRMED", r.status_code == 200
          and "CONFIRMED" in await last_audit("%account new@x.co created%"), r.text[:120])

    # prelungirea unei legături temporare = o acordare (revizuirea 3.6.10)
    ext_id = await U.add_user("ext@x.co")
    ext_bid = await U.bind(ext_id, "operator", "folder", "infra")
    soon = time.time() + 3600
    await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", soon, ext_bid)
    authz.bump_epoch()

    async def ext_exp():
        return (await db.fetchone("SELECT expires FROM role_bindings WHERE id=?", ext_bid))["expires"]
    url = "/api/users/%d/bindings/%d/expiry" % (ext_id, ext_bid)
    r = await owner.post(url, json={"expires": None, "current_password": U.OWNER_PW})
    check("„fă permanentă\" Operator @ infra (crown-jewel) → 409 authz.crownJewel",
          r.status_code == 409 and U.code(r) == "authz.crownJewel" and abs(await ext_exp() - soon) < 1,
          r.text[:160])
    r = await owner.post(url, json={"expires": soon + 86400, "current_password": U.OWNER_PW})
    check("…orice sfârşit MAI TÂRZIU → 409", r.status_code == 409 and U.code(r) == "authz.crownJewel")
    r = await owner.post(url, json={"expires": soon - 600, "current_password": U.OWNER_PW})
    check("…scurtarea nu cere confirmare → 200", r.status_code == 200, r.text[:160])
    r = await owner.post(url, json={"expires": None, "current_password": U.OWNER_PW,
                                    "confirm_crown_jewel": True})
    check("…confirmată → 200, permanentă, audit CONFIRMED", r.status_code == 200
          and await ext_exp() is None and "CONFIRMED" in await last_audit("%ext@x.co: operator%"),
          r.text[:160])
    await U.unbind_all(ext_id)

    # mapare SSO
    m = {"group": "wt-ops", "role": "operator", "scope_kind": "folder", "scope_value": "infra",
         "current_password": U.OWNER_PW}
    r = await owner.post("/api/settings/oidc-roles", json=m)
    check("mapare SSO Operator @ infra → 409", r.status_code == 409 and U.code(r) == "authz.crownJewel",
          r.text[:120])
    r = await owner.post("/api/settings/oidc-roles", json=dict(m, confirm_crown_jewel=True))
    check("…confirmată → 200 + audit CONFIRMED", r.status_code == 200
          and "CONFIRMED" in await last_audit("%SSO group 'wt-ops'%"), r.text[:120])

    # ── mutarea hostului ─────────────────────────────────────────────────────────────────
    r = await owner.patch("/api/hosts/%d" % gw, json={"folder": "lab"})
    check("crown-jewel mutat în folderul `lab` (Operator lab@x.co acolo) → 409 authz.crownJewelMove",
          r.status_code == 409 and U.code(r) == "authz.crownJewelMove", r.text[:160])
    check("…folderul neschimbat",
          (await db.fetchone("SELECT folder FROM hosts WHERE id=?", gw))["folder"] == "infra")
    r = await owner.patch("/api/hosts/%d" % gw, json={"folder": "lab", "confirm_crown_jewel": True})
    check("…confirmat → 200, auditat", r.status_code == 200
          and "lab@x.co" in await last_audit("%crown-jewel host gw01 moved%"), r.text[:160])
    r = await owner.patch("/api/hosts/%d" % gw, json={"folder": "empty"})
    check("mutat într-un folder fără legături ⚑ → 200 fără confirmare", r.status_code == 200, r.text[:120])
    # cursă (revizuirea 3.6.10): o legătură ⚑ peste folderul ţintă apare între verificarea de sus
    # şi scriere — verificarea se repetă sub lock, pe starea de ACUM
    real_exposure = authz.crown_exposure
    calls = []

    async def exposure_then_grant(ref, before=None):
        out = await real_exposure(ref, before=before)
        if not calls:
            await U.bind(ana_id, "operator", "folder", "late")
        calls.append(len(out))
        return out
    authz.crown_exposure = exposure_then_grant
    try:
        r = await owner.patch("/api/hosts/%d" % gw, json={"folder": "late"})
    finally:
        authz.crown_exposure = real_exposure
    check("legătură ⚑ acordată între verificare şi scriere → 409 authz.crownJewelMove (re-verificat sub lock)",
          r.status_code == 409 and U.code(r) == "authz.crownJewelMove" and calls[:1] == [0],
          "%s %s %s" % (r.status_code, r.text[:120], calls))
    check("…folderul neschimbat",
          (await db.fetchone("SELECT folder FROM hosts WHERE id=?", gw))["folder"] == "empty")
    r = await owner.patch("/api/hosts/%d" % gw, json={"folder": "late", "confirm_crown_jewel": True})
    check("…confirmat → 200; auditul numeşte lista FINALĂ (ana@x.co @ folder late)", r.status_code == 200
          and "folder late" in await last_audit("%crown-jewel host gw01 moved%"), r.text[:160])
    r = await owner.patch("/api/hosts/%d" % gw, json={"folder": "empty"})
    r = await owner.patch("/api/hosts/%d" % gw, json={"name": "gw01", "note": "n"})
    check("editare fără schimbare de folder/tag → fără confirmare", r.status_code == 200, r.text[:120])
    r = await owner.patch("/api/hosts/%d" % web, json={"folder": "lab"})
    check("un host OBIŞNUIT mutat în lab → 200 (regula e doar pentru crown-jewel)", r.status_code == 200)

    # ── indiciul „gateway" ───────────────────────────────────────────────────────────────
    await db.execute("INSERT INTO app_settings(key, value) VALUES('cert_renew_host_id', ?)"
                     " ON CONFLICT(key) DO UPDATE SET value=excluded.value", str(web))
    hosts = {h["id"]: h for h in (await owner.get("/api/hosts")).json()}
    check("Owner: indiciu crown_hint=gateway pe hostul gateway-ului (ne-marcat)",
          hosts[web].get("crown_hint") == "gateway" and "crown_hint" not in hosts[gw])
    hosts = {h["id"]: h for h in (await adm.get("/api/hosts")).json()}
    check("Admin: fără indiciu (spune care host rulează gateway-ul)", "crown_hint" not in hosts[web])

    for c in (owner, adm, vw, lab):
        await c.aclose()
    del lab_id, adm_id
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
