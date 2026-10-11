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
    check("cu încă un Owner care ARE parolă locală → acceptat", await run_admin(U.OWNER_EMAIL) == 0)
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
    await test_sso_only()
    await test_session_max()
    await test_admin_cli()
    await test_migration()
    await owner.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
