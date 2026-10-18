"""„Grupuri SSO din cutie" (3.6.5): WEBTERM_OIDC_ROLE_MAP, revocarea rapidă, `admin sso-only`.

Ce se verifică (instanţă hermetică, callback-ul OIDC REAL cu `oidc.complete` înlocuit de un IdP
fals — validarea id_token-ului are suitele ei):
  * parsarea: intrări valide; sintaxă greşită, Owner (şi un rol custom cu permisiuni doar-de-
    Owner), `*`, rol necunoscut, nume de grup pe care normalizarea l-ar schimba, caractere de
    control, scope invalid, host inexistent / ambiguu — toate SĂRITE, fără să acorde nimic;
  * reconcilierea la pornire: adaugă, e idempotentă, scoate ce nu mai e listat şi retrage
    legăturile SSO derivate DOAR din ea, nu atinge mapările din UI, păstrează ultimul Owner;
    audit + alertă critică la Owner;
  * API-ul: mapările din configuraţie apar cu `source: config` şi NU se pot şterge (409
    ssoMap.fromConfig); cele din UI se şterg ca înainte;
  * WEBTERM_OIDC_SSO_ONLY: login-ul cu passkey ca prim factor e refuzat pentru un cont SSO-only,
    dar nu pentru un cont local;
  * WEBTERM_OIDC_SESSION_MAX_HOURS: sesiunea unui cont SSO expiră la vârsta absolută (şi cele
    create înaintea setării), cea a unui cont local nu; socket-urile lungi (session_valid) la fel;
  * valorile greşite ale celor două setări cad pe partea sigură (fail closed);
  * `python3 -m app.admin sso-only`: efectul complet; refuz pentru cont nelegat de SSO şi pentru
    ultimul Owner cu parolă locală (fără --force).
"""
import argparse
import asyncio
import os
import time
import unicodedata

os.environ["WEBTERM_OIDC_ISSUER"] = "http://127.0.0.1:9"
os.environ["WEBTERM_OIDC_CLIENT_ID"] = "wt-client"
os.environ["WEBTERM_OIDC_CLIENT_SECRET"] = "wt-secret"
os.environ.pop("WEBTERM_OIDC_ALLOWED_GROUPS", None)
os.environ.pop("WEBTERM_OIDC_ROLE_MAP", None)
os.environ.pop("WEBTERM_OIDC_SSO_ONLY", None)
os.environ.pop("WEBTERM_OIDC_SESSION_MAX_HOURS", None)

import rbac_util as U  # noqa: E402
from app import admin, authz, config, db, oidc, oidc_api, security, ssomap, webauthn_api  # noqa: E402

check = U.Checker()
_ABSENT = object()


def idp(sub, email, groups=_ABSENT):
    def complete(state, code):
        return {"sub": sub, "email": email, "email_verified": True,
                "groups": oidc._claims_groups({} if groups is _ABSENT else {"groups": groups}),
                "groups_present": groups is not _ABSENT,
                "groups_readable": oidc._groups_readable({} if groups is _ABSENT else {"groups": groups}),
                "intent": "login", "host_id": None}
    oidc.complete = complete


async def sso_login(sub, email, groups=_ABSENT):
    idp(sub, email, groups)
    c = U.client()
    r = await c.get("/api/oidc/callback", params={"code": "c", "state": "s"},
                    cookies={oidc_api.STATE_COOKIE: "s"}, follow_redirects=False)
    assert r.status_code == 303 and "sso_error" not in r.headers.get("location", ""), \
        (r.status_code, r.headers.get("location"))
    tok = next((v.split("=", 1)[1].split(";")[0] for v in r.headers.get_list("set-cookie")
                if v.startswith(security.COOKIE_NAME + "=")), None)
    await c.aclose()
    return tok


async def uid_of(email):
    return (await db.fetchone("SELECT id FROM users WHERE email=?", email))["id"]


async def bindings(email):
    rows = await db.fetchall(
        "SELECT r.key, r.name, b.scope_kind, b.scope_value, b.source FROM role_bindings b"
        " JOIN roles r ON r.id=b.role_id WHERE b.user_id=?", await uid_of(email))
    return {((x["key"] or x["name"]), x["scope_kind"], x["scope_value"], x["source"]) for x in rows}


async def cfg_rows():
    rows = await db.fetchall(
        "SELECT m.grp, r.key, r.name, m.scope_kind, m.scope_value FROM oidc_group_roles m"
        " JOIN roles r ON r.id=m.role_id WHERE m.source='config'")
    return {(x["grp"], x["key"] or x["name"], x["scope_kind"], x["scope_value"]) for x in rows}


async def audit_rows(status=None):
    sql = "SELECT status, detail FROM audit_log WHERE path='/config/oidc-role-map'"
    rows = await db.fetchall(sql)
    return [(r["status"], r["detail"]) for r in rows if status is None or r["status"] == status]


DEFAULT_MAP = ("wt-admins=admin@all,wt-readonly=viewer@all,\n"
               "wt-db=operator@tag:db, wt-network=operator@tag:network")


async def test_parse():
    print("── parsarea WEBTERM_OIDC_ROLE_MAP (doar sintaxa)")
    ok, bad = ssomap.parse_role_map(DEFAULT_MAP)
    check("harta implicită: 4 intrări valide, nicio eroare", len(ok) == 4 and not bad, "%s %s" % (ok, bad))
    check("…tag:db citit ca (tag, db)", ("wt-db", "operator", "tag", "db") in [e[1:] for e in ok])
    check("virgulă ŞI rând nou ca separatori; intrări goale ignorate",
          len(ssomap.parse_role_map("a=viewer@all,,\n\n b=viewer@all ,")[0]) == 2)
    cases = {
        "lipseşte =": "wt-x viewer@all",
        "lipseşte @scope": "wt-x=viewer",
        "scope necunoscut": "wt-x=viewer@group:x",
        "folder fără nume": "wt-x=viewer@folder:",
        "rol gol": "wt-x=@all",
        "* refuzat din configuraţie": "*=viewer@host:status",
        "grup gol": "=viewer@all",
        "caracter de control (TAB în nume)": "wt\tx=viewer@all",
        "caracter invizibil (ZWSP)": "wt​x=viewer@all",
        "spaţiu înaintea lui = (normalizarea l-ar schimba)": "wt-x =viewer@all",
        "nume NFD (normalizarea NFC l-ar schimba)": unicodedata.normalize("NFD", "grupă-ş") + "=viewer@all",
        "nume prea lung": ("g" * 300) + "=viewer@all",
    }
    for what, entry in cases.items():
        ok, bad = ssomap.parse_role_map(entry)
        check("refuzat: " + what, not ok and len(bad) == 1, "%s %s" % (ok, bad))
    ok, bad = ssomap.parse_role_map("x" * (70 * 1024))
    check("o valoare uriaşă e refuzată întreagă", not ok and len(bad) == 1)


async def test_reconcile(owner):
    print("── reconcilierea la pornire")
    hid = await U.add_host(owner, "status-page", folder="prod")
    await U.add_host(owner, "twin", folder="lab")
    await U.add_host(owner, "twin", folder="lab")
    # un rol custom inofensiv şi o „copie de Owner" (toate permisiunile) — create direct în DB
    now = time.time()
    await db.execute("INSERT INTO roles(key, name, description, perms, builtin, created, updated)"
                     " VALUES(NULL,'DB auditors','',?,0,?,?)", '["host.view","session.watch"]', now, now)
    import json
    await db.execute("INSERT INTO roles(key, name, description, perms, builtin, created, updated)"
                     " VALUES(NULL,'Shadow owner','',?,0,?,?)",
                     json.dumps(sorted(authz.BUILTIN_ROLES["owner"]["perms"])), now, now)
    # o mapare făcută din UI (source implicit 'ui') — nu trebuie atinsă niciodată
    vid = await authz.role_id("viewer")
    await db.execute("INSERT INTO oidc_group_roles(grp, role_id, scope_kind, scope_value, created)"
                     " VALUES('ui-team', ?, 'folder', 'lab', ?)", vid, now)
    raw = (DEFAULT_MAP + ",wt-owners=owner@all,wt-shadow=Shadow owner@all,"
           "wt-aud=db auditors@folder:prod,wt-status=viewer@host:status-page,"
           "wt-ghost=viewer@host:nope,wt-twin=viewer@host:twin,wt-bad=superuser@all,"
           "ui-team=viewer@folder:lab,wt-longtag=viewer@tag:" + "t" * 40)
    res = await ssomap.reconcile_config(raw)
    want = {("wt-admins", "admin", "all", ""), ("wt-readonly", "viewer", "all", ""),
            ("wt-db", "operator", "tag", "db"), ("wt-network", "operator", "tag", "network"),
            ("wt-aud", "DB auditors", "folder", "prod"),
            ("wt-status", "viewer", "host", str(hid))}
    got = await cfg_rows()
    check("se adaugă exact intrările valide (host:<nume> → id, rol custom după nume)",
          got == want, "%s" % (got ^ want))
    check("Owner refuzat (intrarea nu a ajuns în DB)",
          not any(g == "wt-owners" for g, *_ in got) and "wt-owners=owner@all" in res["owner_refused"])
    check("un rol custom cu permisiuni doar-de-Owner e refuzat la fel",
          any("wt-shadow" in e for e in res["owner_refused"]) and
          not any(g == "wt-shadow" for g, *_ in got))
    check("rol necunoscut → eroare, sărit", any("wt-bad" in e for e, _w in res["errors"]))
    check("host inexistent → avertisment, sărit", any("wt-ghost" in e for e, _w in res["warnings"]))
    check("host ambiguu (două cu acelaşi nume) → eroare, sărit",
          any("wt-twin" in e for e, _w in res["errors"]))
    check("tag prea lung → eroare, sărit", any("wt-longtag" in e for e, _w in res["errors"]))
    check("mapare identică făcută din UI: rămâne a UI-ului (nu e dublată, nu e convertită)",
          (await db.fetchone("SELECT COUNT(*) AS c FROM oidc_group_roles WHERE grp='ui-team'"))["c"] == 1
          and (await db.fetchone("SELECT source FROM oidc_group_roles WHERE grp='ui-team'"))["source"] == "ui")
    errs = await audit_rows(400)
    check("fiecare intrare sărită e auditată", len(errs) >= 5 and any("wt-owners" in d for _s, d in errs),
          str(errs)[:300])
    await asyncio.sleep(0.2)          # alertele pleacă pe task-uri de fundal
    crit = await db.fetchall("SELECT title, severity FROM alerts WHERE severity='critical'")
    check("Owner refuzat → alertă critică în istoric", any("Owner refused" in r["title"] or
                                                           "Owner" in r["title"] for r in crit),
          str([dict(r) for r in crit])[:200])

    res2 = await ssomap.reconcile_config(raw)
    check("a doua pornire cu acelaşi .env: nimic de adăugat/scos (idempotent)",
          not res2["added"] and not res2["removed"] and await cfg_rows() == want)

    # ── conturi SSO care primesc roluri din configuraţie ──
    await sso_login("sub-dana", "dana@x.co", ["wt-db", "ui-team"])
    await sso_login("sub-eve", "eve@x.co", ["wt-db", "wt-readonly"])
    b = await bindings("dana@x.co")
    check("primul login SSO: grupul wt-db dă operator @ tag:db (+ maparea din UI)",
          ("operator", "tag", "db", "sso") in b and ("viewer", "folder", "lab", "sso") in b, str(b))
    # Eve primeşte şi o legătură MANUALĂ identică — nu trebuie să plece niciodată
    await db.execute("UPDATE role_bindings SET source='manual' WHERE user_id=? AND scope_kind='all'",
                     await uid_of("eve@x.co"))

    # ── .env schimbat: wt-db şi wt-readonly scoase ──
    raw3 = "wt-admins=admin@all,wt-network=operator@tag:network,wt-aud=DB auditors@folder:prod"
    res3 = await ssomap.reconcile_config(raw3)
    got = await cfg_rows()
    check("intrările scoase din .env dispar din DB",
          not any(g in ("wt-db", "wt-readonly", "wt-status") for g, *_ in got), str(got))
    b = await bindings("dana@x.co")
    check("…legătura SSO derivată DOAR din ele e retrasă imediat",
          ("operator", "tag", "db", "sso") not in b, str(b))
    check("…cea justificată de maparea din UI rămâne", ("viewer", "folder", "lab", "sso") in b, str(b))
    b = await bindings("eve@x.co")
    check("…o legătură manuală nu e atinsă", ("viewer", "all", "", "manual") in b, str(b))
    check("…şi raportul numără legăturile retrase", res3["pruned"] >= 2, str(res3))
    check("mapările din UI au rămas neatinse",
          (await db.fetchone("SELECT COUNT(*) AS c FROM oidc_group_roles WHERE source='ui'"))["c"] == 1)
    check("schimbarea e auditată", any("removed" in d for _s, d in await audit_rows(200)))
    return hid


async def test_last_owner(owner):
    print("── ultimul Owner: o reconciliere nu-l scoate niciodată")
    # Carol e singurul Owner, iar Owner-ul ei vine dintr-o legătură SSO pe care nicio mapare nu o
    # mai justifică (ex. maparea Owner din UI a fost ştearsă direct în DB). O reconciliere care
    # scoate ceva rulează prune_locked() peste toate conturile SSO.
    oid = await authz.role_id("owner")
    await sso_login("sub-carol", "carol@x.co", ["nothing"])
    cid = await uid_of("carol@x.co")
    await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                     " created) VALUES(?,?,'all','','sso',?)", cid, oid, time.time())
    owner_uid = await uid_of(U.OWNER_EMAIL)
    saved = await db.fetchall("SELECT * FROM role_bindings WHERE user_id=? AND role_id=?",
                              owner_uid, oid)
    await db.execute("DELETE FROM role_bindings WHERE role_id=? AND user_id<>?", oid, cid)
    authz.bump_epoch()
    await ssomap.reconcile_config("wt-db=operator@tag:db")
    res = await ssomap.reconcile_config("")          # scoate wt-db → prune peste toţi
    check("reconcilierea a scos maparea", "wt-db" in " ".join(res["removed"]), str(res))
    check("…dar legătura Owner a ultimului Owner e PĂSTRATĂ",
          ("owner", "all", "", "sso") in await bindings("carol@x.co"))
    check("…instanţa are în continuare un Owner", await authz.owner_count() == 1)
    for r in saved:
        await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                         " created) VALUES(?,?,?,?,?,?)", r["user_id"], r["role_id"], r["scope_kind"],
                         r["scope_value"], r["source"], r["created"])
    await db.execute("DELETE FROM role_bindings WHERE user_id=? AND role_id=?", cid, oid)
    authz.bump_epoch()


async def test_api(owner):
    print("── API: mapările din configuraţie sunt doar citire")
    await ssomap.reconcile_config(DEFAULT_MAP)
    r = await owner.get("/api/settings/oidc-roles")
    maps = r.json()["mappings"]
    cfg = [m for m in maps if m["source"] == "config"]
    ui = [m for m in maps if m["source"] == "ui"]
    check("lista marchează sursa (config / ui)", len(cfg) == 4 and len(ui) >= 1, str(maps)[:300])
    r = await owner.post("/api/settings/oidc-roles/%d/delete" % cfg[0]["id"],
                         json={"current_password": U.OWNER_PW})
    check("ştergerea unei mapări din configuraţie → 409 ssoMap.fromConfig",
          r.status_code == 409 and U.code(r) == "ssoMap.fromConfig", "%s %s" % (r.status_code, r.text[:200]))
    check("…şi maparea e tot acolo",
          await db.fetchone("SELECT 1 FROM oidc_group_roles WHERE id=?", cfg[0]["id"]) is not None)
    r = await owner.post("/api/settings/oidc-roles/%d/delete" % cfg[0]["id"], json={})
    check("…refuzul vine înaintea oricărei re-autentificări (fără oracle de parolă)",
          r.status_code == 409 and U.code(r) == "ssoMap.fromConfig", "%s" % r.status_code)
    r = await owner.post("/api/settings/oidc-roles", json={
        "group": "wt-admins", "role": "admin", "scope_kind": "all", "current_password": U.OWNER_PW})
    check("adăugarea din UI a unei mapări identice cu una din configuraţie → 409 ssoMap.exists",
          r.status_code == 409 and U.code(r) == "ssoMap.exists", "%s %s" % (r.status_code, r.text[:200]))
    r = await owner.post("/api/settings/oidc-roles/%d/delete" % ui[0]["id"],
                         json={"current_password": U.OWNER_PW})
    check("o mapare din UI se şterge în continuare", r.status_code == 200, "%s %s" % (r.status_code, r.text[:200]))
    vw = await U.add_user("viewer-only@x.co", bindings=[("viewer", "all", "")])
    c = await U.login("viewer-only@x.co")
    r = await c.post("/api/settings/oidc-roles/%d/delete" % cfg[0]["id"], json={})
    check("fără users.manage: 403 înainte de orice", r.status_code == 403, str(r.status_code))
    await c.aclose()
    del vw


# ── revizuirea de securitate 3.6.5: fiecare exploit trebuie să EŞUEZE acum ───────────────────
async def global_perms(email):
    uid = await uid_of(email)
    authz._cache.pop(uid, None)
    return (await authz.grants_for_user(uid)).global_perms


async def test_secreview(owner):
    print("── revizuire 3.6.5: P1 rol custom mapat din .env nu primeşte permisiuni doar-de-Owner")
    r = await owner.post("/api/roles", json={"name": "Auditors365", "perms": ["audit.view", "host.view"],
                                             "current_password": U.OWNER_PW})
    check("Owner creează rolul custom Auditors365", r.status_code == 200, r.text[:160])
    out = await ssomap.reconcile_config("wt-audit=Auditors365@all")
    check("…mapat din .env (wt-audit=Auditors365@all)", out["added"], str(out))
    await sso_login("sub-aud", "aud@x.co", ["wt-audit"])
    check("…un cont SSO primeşte audit.view prin el", "audit.view" in await global_perms("aud@x.co"))
    rid = (await db.fetchone("SELECT id FROM roles WHERE name='Auditors365'"))["id"]
    for extra in ("backups.manage", "signing.manage", "history.clear"):
        r = await owner.patch("/api/roles/%d" % rid, json={
            "name": "Auditors365", "perms": ["audit.view", "host.view", extra],
            "current_password": U.OWNER_PW})
        check("P1: Owner adaugă %s → 409 role.usedByConfigMap" % extra,
              r.status_code == 409 and U.code(r) == "role.usedByConfigMap",
              "%s %s" % (r.status_code, r.text[:160]))
    r = await owner.patch("/api/roles/%d" % rid, json={
        "name": "Auditors365", "perms": ["audit.view", "host.view", "backups.manage"]})
    check("P1: refuzul vine înaintea re-autentificării (fără oracle de parolă)",
          r.status_code == 409 and U.code(r) == "role.usedByConfigMap", str(r.status_code))
    row = await db.fetchone("SELECT perms FROM roles WHERE id=?", rid)
    check("P1: permisiunile rolului au rămas neschimbate", "backups.manage" not in row["perms"], row["perms"])
    check("P1: contul SSO NU are backups.manage", "backups.manage" not in await global_perms("aud@x.co"))
    r = await owner.patch("/api/roles/%d" % rid, json={
        "name": "Auditors365", "perms": ["audit.view", "host.view", "session.watch"],
        "current_password": U.OWNER_PW})
    check("o editare fără permisiuni doar-de-Owner merge în continuare", r.status_code == 200,
          "%s %s" % (r.status_code, r.text[:160]))
    # defence in depth: un rând modificat direct în DB nu dă nimic la sync
    import json as _json
    await db.execute("UPDATE roles SET perms=? WHERE id=?",
                     _json.dumps(["audit.view", "host.view", "backups.manage"]), rid)
    authz.bump_epoch()
    await sso_login("sub-aud", "aud@x.co", ["wt-audit"])
    check("filtrul de la sync rămâne: rolul devenit Owner-equivalent nu mai e dat din config",
          "backups.manage" not in await global_perms("aud@x.co")
          and "audit.view" not in await global_perms("aud@x.co"))
    await db.execute("UPDATE roles SET perms=? WHERE id=?", _json.dumps(["audit.view", "host.view"]), rid)
    authz.bump_epoch()

    print("── revizuire 3.6.5: P4 redenumirea rolului / hostului numit de .env e semnalată")
    r = await owner.patch("/api/roles/%d" % rid, json={
        "name": "Auditors-renamed", "perms": ["audit.view", "host.view"], "current_password": U.OWNER_PW})
    check("redenumirea rolului reuşeşte", r.status_code == 200, r.text[:160])
    row = await db.fetchone("SELECT detail FROM audit_log WHERE path=? ORDER BY id DESC LIMIT 1",
                            "/api/roles/%d" % rid)
    check("…şi auditul spune că WEBTERM_OIDC_ROLE_MAP încă îl numeşte după numele vechi",
          row and "WEBTERM_OIDC_ROLE_MAP still names it 'Auditors365'" in row["detail"],
          row["detail"] if row else "-")
    hid = await U.add_host(owner, "cfg-host", folder="prod")
    await ssomap.reconcile_config("wt-audit=Auditors-renamed@all,wt-h=viewer@host:cfg-host")
    r = await owner.patch("/api/hosts/%d" % hid, json={"name": "cfg-host-2"})
    check("redenumirea hostului reuşeşte", r.status_code == 200, r.text[:160])
    rows = await audit_rows(200)
    check("…avertisment auditat: hostul numit de .env a fost redenumit",
          any("host %d" % hid in d and "renamed" in d for _s, d in rows), str(rows[-2:]))
    r = await owner.delete("/api/hosts/%d" % hid)
    check("ştergerea hostului reuşeşte", r.status_code == 200, r.text[:160])
    rows = await audit_rows(200)
    check("…avertisment auditat: hostul numit de .env a fost şters",
          any("host %d" % hid in d and "deleted" in d for _s, d in rows), str(rows[-2:]))
    check("…şi maparea pe host a plecat cu el",
          not await db.fetchone("SELECT 1 FROM oidc_group_roles WHERE scope_kind='host' AND scope_value=?",
                                str(hid)))

    print("── revizuire 3.6.5: P3 biletele de forward nu trăiesc mai mult decât sesiunea SSO")
    fh = await U.add_host(owner, "fwd-host", folder="prod")
    await U.add_forward(fh, "graf365")
    await ssomap.reconcile_config("wt-view=viewer@all")
    try:
        config.OIDC_SESSION_MAX_HOURS = 12
        tok = await sso_login("sub-fwd", "fwd@x.co", ["wt-view"])
        # sesiunea are deja 11.5 h: biletul trebuie să expire în cel mult ~30 min, nu în 12 h
        await db.execute("UPDATE web_sessions SET created=created-41400, expires=expires-41400 WHERE"
                         " token_hash=?", security.sha256_hex(tok))
        c = U.client(cookies={security.COOKIE_NAME: tok})
        r = await c.get("/__wtfwd/auth", params={"slug": "graf365"}, follow_redirects=False)
        loc = r.headers.get("location", "")
        import re as _re
        m = _re.search(r"[?&]t=(\d+)\.(\d+)\.", loc)
        left = int(m.group(1)) - time.time() if m else None
        check("P3: biletul unui cont SSO expiră odată cu sesiunea (≤ 30 min rămase)",
              m is not None and 0 < left <= 1800 + 5, "%s %s" % (r.status_code, loc[:160]))
        lt_email = "fwd-local@x.co"
        await U.add_user(lt_email, bindings=[("viewer", "all", "")])
        lc = await U.login(lt_email)
        await db.execute("UPDATE web_sessions SET created=created-41400 WHERE user_id=?",
                         await uid_of(lt_email))
        r2 = await lc.get("/__wtfwd/auth", params={"slug": "graf365"}, follow_redirects=False)
        m2 = _re.search(r"[?&]t=(\d+)\.", r2.headers.get("location", ""))
        check("…un cont local păstrează TTL-ul obişnuit (12 h)",
              m2 is not None and int(m2.group(1)) - time.time() > 11 * 3600, r2.headers.get("location", "")[:160])
        check("P3: sesiune negăsită → 0 s (fail closed)",
              await security.sso_session_seconds_left("nope",
                                                      await db.fetchone("SELECT * FROM users WHERE email='fwd@x.co'")) == 0)
        config.OIDC_SESSION_MAX_HOURS = 0
        r3 = await c.get("/__wtfwd/auth", params={"slug": "graf365"}, follow_redirects=False)
        m3 = _re.search(r"[?&]t=(\d+)\.", r3.headers.get("location", ""))
        check("setarea oprită: TTL-ul obişnuit", m3 is not None and int(m3.group(1)) - time.time() > 11 * 3600)
        await c.aclose()
        await lc.aclose()
    finally:
        config.OIDC_SESSION_MAX_HOURS = 0


class _Verified:
    new_sign_count = 7


async def passkey_login(cred_id: bytes):
    import base64
    raw = base64.urlsafe_b64encode(cred_id).rstrip(b"=").decode()
    c = U.client()
    r = await c.post("/api/webauthn/login/verify", json={"credential": {"rawId": raw, "id": raw}})
    await c.aclose()
    return r


async def test_sso_only():
    print("── WEBTERM_OIDC_SSO_ONLY: passkey ca prim factor")
    orig_v, orig_c = webauthn_api.verify_authentication_response, webauthn_api._consume
    webauthn_api.verify_authentication_response = lambda **kw: _Verified()
    webauthn_api._consume = lambda cred: b"challenge"
    try:
        await sso_login("sub-sso1", "sso1@x.co", [])          # provizionat de SSO: SSO-only
        sid = await uid_of("sso1@x.co")
        lid = await U.add_user("local1@x.co")                   # cont local, cu parolă
        for uid, cid in ((sid, b"cred-sso"), (lid, b"cred-local")):
            await db.execute("INSERT INTO webauthn_credentials(user_id, credential_id, public_key,"
                             " sign_count, name, created) VALUES(?,?,?,0,'k',?)", uid, cid, b"pk",
                             time.time())
        config.OIDC_SSO_ONLY = False
        r = await passkey_login(b"cred-sso")
        check("setarea oprită (implicit): comportamentul vechi, passkey-ul intră", r.status_code == 200,
              "%s %s" % (r.status_code, r.text[:200]))
        config.OIDC_SSO_ONLY = True
        n0 = (await db.fetchone("SELECT COUNT(*) AS c FROM web_sessions WHERE user_id=?", sid))["c"]
        r = await passkey_login(b"cred-sso")
        check("SSO_ONLY=1: contul SSO-only e refuzat (403 auth.ssoOnly)",
              r.status_code == 403 and U.code(r) == "auth.ssoOnly", "%s %s" % (r.status_code, r.text[:200]))
        check("…fără cookie de sesiune", security.COOKIE_NAME not in r.headers.get("set-cookie", ""))
        n1 = (await db.fetchone("SELECT COUNT(*) AS c FROM web_sessions WHERE user_id=?", sid))["c"]
        check("…şi fără sesiune nouă în DB", n1 == n0, "%d → %d" % (n0, n1))
        r = await passkey_login(b"cred-local")
        check("SSO_ONLY=1: un cont local (cu parolă) intră cu passkey ca înainte", r.status_code == 200,
              "%s %s" % (r.status_code, r.text[:200]))
        r = U.client()
        rr = await r.post("/api/login", json={"email": "sso1@x.co", "password": "orice-parola"})
        await r.aclose()
        check("parola nu deschide nici ea contul SSO-only (ca înainte)", rr.status_code == 401)
        tok = await sso_login("sub-sso1", "sso1@x.co", [])
        check("SSO_ONLY=1: login-ul prin SSO merge", bool(tok))
    finally:
        config.OIDC_SSO_ONLY = False
        webauthn_api.verify_authentication_response, webauthn_api._consume = orig_v, orig_c


async def test_session_max():
    print("── WEBTERM_OIDC_SESSION_MAX_HOURS")
    try:
        config.OIDC_SESSION_MAX_HOURS = 0
        tok_old = await sso_login("sub-sso2", "sso2@x.co", [])   # creată ÎNAINTE de setare
        config.OIDC_SESSION_MAX_HOURS = 12
        tok = await sso_login("sub-sso2", "sso2@x.co", [])
        row = await db.fetchone("SELECT created, expires FROM web_sessions WHERE token_hash=?",
                                security.sha256_hex(tok))
        check("sesiunea nouă a unui cont SSO expiră la 12 h (nu la TTL-ul de 30 de zile)",
              abs((row["expires"] - row["created"]) - 12 * 3600) < 5, str(dict(row)))
        check("…şi e valabilă acum", await security.user_for_token(tok) is not None)
        await db.execute("UPDATE web_sessions SET created=created-13*3600, last_seen=? WHERE"
                         " token_hash=?", time.time(), security.sha256_hex(tok_old))
        check("o sesiune creată înainte de setare, mai veche decât limita: session_valid=False "
              "(terminalele deschise urmează expirarea)", not await security.session_valid(tok_old))
        check("…user_for_token o refuză", await security.user_for_token(tok_old) is None)
        check("…şi o şterge", await db.fetchone("SELECT 1 FROM web_sessions WHERE token_hash=?",
                                                security.sha256_hex(tok_old)) is None)
        await U.add_user("local2@x.co")
        lt = await security.create_web_session(await uid_of("local2@x.co"), "t", False)
        await db.execute("UPDATE web_sessions SET created=created-13*3600, last_seen=? WHERE"
                         " token_hash=?", time.time(), security.sha256_hex(lt))
        check("un cont local (fără SSO) nu e afectat", await security.user_for_token(lt) is not None
              and await security.session_valid(lt))
        config.OIDC_SESSION_MAX_HOURS = 0
        tok2 = await sso_login("sub-sso2", "sso2@x.co", [])
        await db.execute("UPDATE web_sessions SET created=created-13*3600, last_seen=? WHERE"
                         " token_hash=?", time.time(), security.sha256_hex(tok2))
        check("setarea oprită: comportamentul vechi (fără limită în plus)",
              await security.user_for_token(tok2) is not None)
    finally:
        config.OIDC_SESSION_MAX_HOURS = 0


def test_config_parsing():
    print("── valorile greşite cad pe partea sigură")
    saved = {k: os.environ.get(k) for k in ("WEBTERM_OIDC_SSO_ONLY", "WEBTERM_OIDC_SESSION_MAX_HOURS")}
    try:
        for val, want in (("", False), ("0", False), ("no", False), ("1", True), ("true", True),
                          ("yes please", True), ("2", True)):
            os.environ["WEBTERM_OIDC_SSO_ONLY"] = val
            check("SSO_ONLY=%r → %s" % (val, want), config._flag_fail_closed("WEBTERM_OIDC_SSO_ONLY") is want)
        for val, want in (("", 0.0), ("0", 0.0), ("12", 12.0), ("0.5", 0.5), ("abc", 12.0),
                          ("-3", 12.0), ("nan", 12.0), ("inf", 12.0), ("99999", 12.0)):
            os.environ["WEBTERM_OIDC_SESSION_MAX_HOURS"] = val
            got = config._hours_fail_closed("WEBTERM_OIDC_SESSION_MAX_HOURS", 12.0)
            check("SESSION_MAX_HOURS=%r → %s" % (val, want), got == want, str(got))
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


async def run_admin(email, force=False):
    try:
        await admin.cmd_sso_only(argparse.Namespace(email=email, force=force))
        return 0
    except SystemExit as e:
        return e.code


async def test_break_glass_api():
    """RB-01 (audit 2026-10-17): POST /api/account {remove_password} — the UI twin of
    `admin sso-only` — now keeps the last PERMANENT Owner with a local password (a time-bound
    Owner does not count), with 409 account.lastBreakGlass; otherwise an IdP outage locked every
    Owner out after one click the UI itself recommended."""
    print("── /api/account remove_password: the last break-glass Owner stays")
    bg = await U.add_user("bg@x.co", bindings=[("owner", "all", "")])
    await db.execute("UPDATE users SET sso_subject='sub-bg' WHERE id=?", bg)
    c = await U.login("bg@x.co")
    await db.execute("UPDATE web_sessions SET device_new=0 WHERE user_id=?", bg)
    # every OTHER permanent Owner with a local password steps aside for the test (restored below)
    others = [r["id"] for r in await db.fetchall(
        "SELECT DISTINCT u.id FROM users u JOIN role_bindings b ON b.user_id=u.id JOIN roles r ON r.id=b.role_id"
        " WHERE r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL AND COALESCE(u.local_password, 1)=1"
        " AND u.id<>?", bg)]
    saved = {o: (await db.fetchone("SELECT local_password FROM users WHERE id=?", o))["local_password"] for o in others}
    bg2 = None
    try:
        for o in others:
            await db.execute("UPDATE users SET local_password=0 WHERE id=?", o)
        r = await c.post("/api/account", json={"remove_password": True})
        check("fără fereastră SSO → 403 account.ssoReauth (ca înainte)", r.status_code == 403
              and U.code(r) == "account.ssoReauth", "%s %s" % (r.status_code, r.text[:120]))
        security.open_stepup_window(bg, 0)
        r = await c.post("/api/account", json={"remove_password": True})
        check("ultimul Owner permanent cu parolă locală → 409 account.lastBreakGlass",
              r.status_code == 409 and U.code(r) == "account.lastBreakGlass", "%s %s" % (r.status_code, r.text[:160]))
        check("…mesajul spune ce să facă (alt Owner PERMANENT cu parolă locală)",
              "PERMANENT Owner with a local password" in r.text, r.text[:200])
        u = await db.fetchone("SELECT local_password, password_hash FROM users WHERE id=?", bg)
        check("…parola locală rămâne, sesiunea rămâne", u["local_password"] != 0
              and (await c.get("/api/me/permissions")).status_code == 200)
        bg2 = await U.add_user("bg2@x.co", bindings=[("owner", "all", "")])
        await db.execute("UPDATE role_bindings SET expires=? WHERE user_id=?", time.time() + 3600, bg2)
        authz.bump_epoch()
        r = await c.post("/api/account", json={"remove_password": True})
        check("un al doilea Owner cu parolă, dar TEMPORAR, nu ţine locul → tot 409",
              r.status_code == 409 and U.code(r) == "account.lastBreakGlass", "%s %s" % (r.status_code, r.text[:120]))
        await db.execute("UPDATE users SET local_password=0 WHERE id=?", bg2)
        await db.execute("UPDATE role_bindings SET expires=NULL WHERE user_id=?", bg2)
        authz.bump_epoch()
        r = await c.post("/api/account", json={"remove_password": True})
        check("…permanent dar FĂRĂ parolă locală (SSO-only) → tot 409",
              r.status_code == 409 and U.code(r) == "account.lastBreakGlass", "%s %s" % (r.status_code, r.text[:120]))
        # RB-06 (revizuirea P1): o schimbare DE RUTINĂ a parolei pe contul break-glass îi ştergea
        # legătura Owner venită din SSO de îndată ce exista alt Owner permanent — chiar SSO-only
        # (bg2 acum) — şi instanţa rămânea doar cu Owneri pe care IdP-ul îi poate lăsa afară
        oid = await authz.role_id("owner")
        await db.execute("UPDATE role_bindings SET source='sso' WHERE user_id=? AND role_id=?", bg, oid)
        authz.bump_epoch()
        security.open_stepup_window(bg, 0)
        r = await c.post("/api/account", json={"new_password": "Parola-noua-123"})
        check("schimbare de parolă pe contul break-glass, celălalt Owner permanent fiind SSO-only → 200 şi "
              "legătura Owner (sso) RĂMÂNE", r.status_code == 200
              and ("owner", "all", "", "sso") in await bindings("bg@x.co"),
              "%s %s %s" % (r.status_code, r.text[:120], await bindings("bg@x.co")))
        check("…bg e în continuare contul break-glass", await authz.last_break_glass(bg))
        await db.execute("UPDATE users SET local_password=1 WHERE id=?", bg2)
        security.open_stepup_window(bg, 0)
        r = await c.post("/api/account", json={"new_password": "Parola-noua-124"})
        check("…cu alt Owner PERMANENT cu parolă locală: legătura Owner (sso) pleacă la schimbarea parolei",
              r.status_code == 200 and ("owner", "all", "", "sso") not in await bindings("bg@x.co"),
              "%s %s %s" % (r.status_code, r.text[:120], await bindings("bg@x.co")))
        await db.execute("UPDATE users SET local_password=0 WHERE id=?", bg2)
        await U.bind(bg, "owner", "all", "")          # Owner manual din nou, pentru paşii de mai jos
        security.open_stepup_window(bg, 0)
        await db.execute("UPDATE users SET local_password=1 WHERE id=?", bg2)
        r = await c.post("/api/account", json={"remove_password": True})
        check("cu alt Owner PERMANENT cu parolă locală → 200, contul devine SSO-only",
              r.status_code == 200 and (await db.fetchone("SELECT local_password FROM users WHERE id=?", bg))
              ["local_password"] == 0, "%s %s" % (r.status_code, r.text[:120]))
    finally:
        for o, lp in saved.items():
            await db.execute("UPDATE users SET local_password=? WHERE id=?", lp, o)
        await U.unbind_all(bg)
        if bg2 is not None:
            await U.unbind_all(bg2)
        await c.aclose()


async def test_break_glass_sync():
    """RB-06 (revizuirea P1, MED): IdP-ul nu trebuie să poată lua legătura Owner @ all (sso) a
    contului break-glass NICI la propriul login SSO al omului (sincronizarea remove_only a unui
    cont cu parolă locală, ssomap.sync_user) cât timp ceilalţi Owneri permanenţi sunt SSO-only —
    altfel rămân doar Owneri pe care o pană a IdP-ului îi lasă afară. Regula e cea din
    `authz.last_break_glass`, aplicată în ramura „kept" din ssomap._apply_locked."""
    print("── sincronizarea SSO: legătura Owner (sso) a contului break-glass rămâne")
    oid = await authz.role_id("owner")
    bgs = await U.add_user("bgs@x.co")
    await db.execute("UPDATE users SET sso_subject='sub-bgs', local_password=1 WHERE id=?", bgs)
    await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                     " created) VALUES(?,?,'all','','sso',?)", bgs, oid, time.time())
    osso = await U.add_user("osso@x.co", bindings=[("owner", "all", "")])
    await db.execute("UPDATE users SET local_password=0, sso_subject='sub-osso' WHERE id=?", osso)
    others = [r["id"] for r in await db.fetchall(
        "SELECT DISTINCT u.id FROM users u JOIN role_bindings b ON b.user_id=u.id JOIN roles r ON r.id=b.role_id"
        " WHERE r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL AND COALESCE(u.local_password, 1)=1"
        " AND u.id<>?", bgs)]
    saved = {o: (await db.fetchone("SELECT local_password FROM users WHERE id=?", o))["local_password"] for o in others}
    try:
        for o in others:                   # ceilalţi Owneri permanenţi devin SSO-only (restauraţi mai jos)
            await db.execute("UPDATE users SET local_password=0 WHERE id=?", o)
        authz.bump_epoch()
        check("pregătire: bgs e contul break-glass, dar NU singurul Owner permanent",
              await authz.last_break_glass(bgs) and await authz.owner_count(exclude_user=bgs) >= 1,
              "%d %d" % (await authz.owner_count(with_local_password=True), await authz.owner_count()))
        await sso_login("sub-bgs", "bgs@x.co", ["nothing"])
        check("login SSO cu grupuri care nu mai dau Owner: legătura Owner (sso) a contului break-glass RĂMÂNE",
              ("owner", "all", "", "sso") in await bindings("bgs@x.co"), str(await bindings("bgs@x.co")))
        au = await db.fetchone("SELECT detail FROM audit_log WHERE actor_id=? AND detail LIKE 'SSO roles synced%'"
                               " ORDER BY ts DESC, rowid DESC LIMIT 1", bgs)
        check("…rândul de audit „SSO roles synced” spune că a fost PĂSTRATĂ (KEPT break-glass Owner)",
              au is not None and "KEPT break-glass Owner" in au["detail"], str(au and dict(au)))
        check("…instanţa are în continuare un cont break-glass", await authz.owner_count(with_local_password=True) == 1)
        await db.execute("UPDATE users SET local_password=1 WHERE id=?", osso)
        authz.bump_epoch()
        await sso_login("sub-bgs", "bgs@x.co", ["nothing"])
        check("…cu alt Owner permanent CU parolă locală: legătura (sso) pleacă la sincronizare",
              ("owner", "all", "", "sso") not in await bindings("bgs@x.co"), str(await bindings("bgs@x.co")))
    finally:
        for o, lp in saved.items():
            await db.execute("UPDATE users SET local_password=? WHERE id=?", lp, o)
        await U.unbind_all(bgs)
        await U.unbind_all(osso)


async def test_admin_cli():
    print("── python3 -m app.admin sso-only")
    owner_uid = await uid_of(U.OWNER_EMAIL)
    check("cont nelegat de SSO → refuzat", await run_admin("local1@x.co") == 2)
    check("…şi neschimbat", (await db.fetchone("SELECT local_password FROM users WHERE email='local1@x.co'"))
          ["local_password"] != 0)
    # Frank: adoptat de SSO, cu parolă, passkey, TOTP, coduri de recuperare şi sesiune
    fid = await U.add_user("frank@x.co")
    await db.execute("UPDATE users SET sso_subject='sub-frank', totp_enabled=1,"
                     " totp_secret_encrypted='x' WHERE id=?", fid)
    await db.execute("INSERT INTO webauthn_credentials(user_id, credential_id, public_key, sign_count,"
                     " name, created) VALUES(?,?,?,0,'k',?)", fid, b"cred-frank", b"pk", time.time())
    await db.execute("INSERT INTO recovery_codes(user_id, code_hash, created) VALUES(?, 'h', ?)", fid,
                     time.time())
    tok = await security.create_web_session(fid, "t", False)
    old_hash = (await db.fetchone("SELECT password_hash FROM users WHERE id=?", fid))["password_hash"]
    check("cont SSO cu parolă locală → acceptat", await run_admin("frank@x.co") == 0)
    u = await db.fetchone("SELECT * FROM users WHERE id=?", fid)
    check("…local_password=0, hash nou (aleator)", u["local_password"] == 0 and u["password_hash"] != old_hash)
    check("…TOTP oprit", not u["totp_enabled"] and u["totp_secret_encrypted"] is None)
    check("…passkey-uri şi coduri de recuperare şterse",
          not await db.fetchone("SELECT 1 FROM webauthn_credentials WHERE user_id=?", fid)
          and not await db.fetchone("SELECT 1 FROM recovery_codes WHERE user_id=?", fid))
    check("…sesiunile închise", await security.user_for_token(tok) is None)
    check("…epoca de autorizare semnalată gateway-ului",
          await db.fetchone("SELECT 1 FROM app_settings WHERE key='authz_epoch'") is not None)
    check("…auditat", await db.fetchone("SELECT 1 FROM audit_log WHERE path='/admin/sso-only'") is not None)

    # ultimul Owner cu parolă locală
    await db.execute("UPDATE users SET sso_subject='sub-owner' WHERE id=?", owner_uid)
    check("ultimul Owner cu parolă locală (break-glass) → refuzat fără --force",
          await run_admin(U.OWNER_EMAIL) == 3)
    check("…şi neschimbat", (await db.fetchone("SELECT local_password FROM users WHERE id=?", owner_uid))
          ["local_password"] != 0)
    # un al doilea Owner, dar FĂRĂ parolă locală, nu e un break-glass
    await U.bind(fid, "owner")
    check("al doilea Owner fără parolă locală nu ajunge → tot refuzat", await run_admin(U.OWNER_EMAIL) == 3)
    gid = await U.add_user("grace@x.co", bindings=[("owner", "all", "")])
    # revizuirea 3.6.10: un Owner TEMPORAR cu parolă locală nu e break-glass (expiră)
    await db.execute("UPDATE role_bindings SET expires=? WHERE user_id=?", time.time() + 3600, gid)
    check("încă un Owner cu parolă locală, dar TEMPORAR → tot refuzat", await run_admin(U.OWNER_EMAIL) == 3)
    await db.execute("UPDATE role_bindings SET expires=NULL WHERE user_id=?", gid)
    check("cu încă un Owner PERMANENT care ARE parolă locală → acceptat", await run_admin(U.OWNER_EMAIL) == 0)
    check("…contul a devenit SSO-only",
          (await db.fetchone("SELECT local_password FROM users WHERE id=?", owner_uid))["local_password"] == 0)
    await db.execute("UPDATE users SET sso_subject='sub-grace' WHERE id=?", gid)
    check("acum grace e ultimul Owner cu parolă: --force trece", await run_admin("grace@x.co", force=True) == 0)
    saved = config.OIDC_ENABLED
    try:
        config.OIDC_ENABLED = False
        hid = await U.add_user("henry@x.co")
        await db.execute("UPDATE users SET sso_subject='sub-henry' WHERE id=?", hid)
        check("SSO neconfigurat → refuzat (contul n-ar mai putea intra)", await run_admin("henry@x.co") == 2)
    finally:
        config.OIDC_ENABLED = saved


async def test_migration():
    print("── migrarea: coloana source")
    cols = {r["name"]: r for r in await db.fetchall("PRAGMA table_info(oidc_group_roles)")}
    check("oidc_group_roles.source există, implicit 'ui'",
          "source" in cols and "ui" in str(cols["source"]["dflt_value"]), str(cols.get("source")))
    await db.close()
    await db.connect()
    check("a doua pornire pe aceeaşi bază: fără eroare (migrare idempotentă)",
          (await db.fetchone("SELECT COUNT(*) AS c FROM oidc_group_roles WHERE source='config'"))["c"] >= 1)


async def main():
    await U.boot()
    owner = await U.owner_client()
    test_config_parsing()
    await test_parse()
    await test_reconcile(owner)
    await test_last_owner(owner)
    await test_api(owner)
    await test_secreview(owner)
    await test_sso_only()
    await test_session_max()
    await test_break_glass_api()
    await test_break_glass_sync()
    await test_admin_cli()
    await test_migration()
    await owner.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
