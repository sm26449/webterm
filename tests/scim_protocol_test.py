"""SCIM 2.0 (3.6.11): autentificarea, tokenul, protocolul Users/Groups şi maparea grupurilor.

Instanţă hermetică (DB temporar, fără agent, fără reţea): IdP-ul e simulat cu cereri SCIM
exact în forma pe care o trimite providerul SCIM din Authentik (POST/PUT/PATCH pe Users şi
Groups, `externalId`, `active`, `emails`, `userName`, membri de grup, filtrul `userName eq "x"`
la conflict). Ce se verifică:

  * autentificare: fără token / token greşit / token de AUTOMATIZARE / cookie de Owner → 401 pe
    FIECARE rută SCIM (enumerate din cod), corp de eroare SCIM; blocare per IP după 10 eşecuri
    (429, chiar şi cu tokenul bun); plafon de cereri; corp > 1 MiB → 413; SCIM oprit → 403; fără
    SSO configurat → 403;
  * garda de rute: un principal SCIM e acceptat DOAR sub /scim/v2/ (o rută /api/ cu dependenţa
    SCIM e refuzată 500 `authz.undeclared`), o rută cu SCIM + perm() e ambiguă;
  * ciclul de viaţă al tokenului: doar Owner (un Admin cu users.manage → 403), parolă cerută,
    arătat o singură dată, stocat doar ca hash, rotirea omoară tokenul vechi, revocarea la fel;
  * Users: creare (cont SSO-only, fără parolă locală), câmpuri obligatorii, JSON greşit, email
    invalid, 409 la duplicat + găsirea prin filtru (fluxul Authentik), filtrele suportate şi cele
    refuzate, paginare, PUT/PATCH (inclusiv forma Entra „False" ca text), re-sincronizare
    idempotentă (nicio scriere / niciun rând de audit la un PUT identic);
  * conturile cu parolă LOCALĂ (break-glass): invizibile pentru SCIM, crearea cu aceeaşi identitate
    → 409, nimic atins; un cont SSO-only existent e ADOPTAT (acelaşi id), nu dublat;
  * legarea la OIDC: externalId == sub leagă contul SCIM la primul login SSO fără email_verified;
  * Groups: membrii re-rulează maparea grup → rol imediat (adăugare / scoatere / înlocuire /
    redenumire / ştergere), PUT fără `members` nu atinge membrii, numele EXACT (fără trim), grupuri
    pe care SCIM nu le gestionează rămân, Owner nu se acordă NICIODATĂ printr-un push (dar se
    acordă la login-ul SSO şi se poate retrage prin SCIM), membri necunoscuţi ignoraţi;
  * descoperire: ServiceProviderConfig, ResourceTypes, Schemas.
"""
import asyncio
import json
import os

os.environ["WEBTERM_OIDC_ISSUER"] = "http://127.0.0.1:9"
os.environ["WEBTERM_OIDC_CLIENT_ID"] = "wt-client"
os.environ["WEBTERM_OIDC_CLIENT_SECRET"] = "wt-secret"
os.environ.pop("WEBTERM_OIDC_ALLOWED_GROUPS", None)
os.environ.pop("WEBTERM_OIDC_ROLE_MAP", None)
os.environ.pop("WEBTERM_OIDC_SSO_ONLY", None)

import rbac_util as U  # noqa: E402
from app import authz, config, db, oidc, oidc_api, scim, security, webauthn_api  # noqa: E402

check = U.Checker()
PW = U.OWNER_PW
SCIM_CT = "application/scim+json"
_ABSENT = object()


def sc(token):
    return U.client(headers={"authorization": "Bearer " + token, "content-type": SCIM_CT,
                             "accept": SCIM_CT})


def is_scim_error(r, status):
    try:
        j = r.json()
    except ValueError:
        return False
    return (r.status_code == status and j.get("schemas") == [scim.S_ERROR]
            and j.get("status") == str(status))


def ak_user(username, email, ext=None, active=True, name="Ana Pop"):
    """Corpul pe care îl trimite maparea SCIM implicită din Authentik."""
    given, _, family = name.partition(" ")
    body = {"schemas": [scim.S_USER], "userName": username,
            "name": {"formatted": name, "givenName": given, "familyName": family or " "},
            "displayName": name, "active": active,
            "emails": [{"value": email, "type": "other", "primary": True}]}
    if ext:
        body["externalId"] = ext
    return body


def idp(sub, email, groups=_ABSENT, verified=True):
    def complete(state, code):
        return {"sub": sub, "email": email, "email_verified": verified,
                "groups": oidc._claims_groups({} if groups is _ABSENT else {"groups": groups}),
                "groups_present": groups is not _ABSENT,
                "groups_readable": oidc._groups_readable({} if groups is _ABSENT else {"groups": groups}),
                "intent": "login", "host_id": None}
    oidc.complete = complete


async def sso_login(sub, email, groups=_ABSENT, verified=True):
    idp(sub, email, groups, verified)
    c = U.client()
    r = await c.get("/api/oidc/callback", params={"code": "c", "state": "s"},
                    cookies={oidc_api.STATE_COOKIE: "s"}, follow_redirects=False)
    await c.aclose()
    return r.headers.get("location", "")


async def uid_of(email):
    r = await db.fetchone("SELECT id FROM users WHERE email=?", email)
    return r["id"] if r else None


async def bindings(email):
    rows = await db.fetchall(
        "SELECT r.key, r.name, b.scope_kind, b.scope_value, b.source FROM role_bindings b"
        " JOIN roles r ON r.id=b.role_id WHERE b.user_id=?", await uid_of(email))
    return {((x["key"] or x["name"]), x["scope_kind"], x["scope_value"], x["source"]) for x in rows}


async def scim_audit_rows():
    return (await db.fetchone("SELECT COUNT(*) AS c FROM audit_log WHERE via='scim'"))["c"]


async def test_token_lifecycle(owner):
    print("── tokenul SCIM: doar Owner, arătat o dată, hash, rotire, revocare, oprire")
    r = await owner.get("/api/settings/scim")
    check("status iniţial: neconfigurat, oprit", r.status_code == 200 and not r.json()["configured"]
          and not r.json()["enabled"] and r.json()["url"].endswith("/scim/v2"), r.text[:200])
    await U.add_user("adm@x.co", bindings=[("admin", "all", "")])
    adm = await U.login("adm@x.co")
    r = await adm.get("/api/settings/scim")
    check("un Admin (users.manage) vede starea", r.status_code == 200)
    r = await adm.post("/api/settings/scim/token", json={"current_password": "parolabuna1"})
    check("…dar NU creează tokenul (doar Owner) → 403 authz.ownerOnly",
          r.status_code == 403 and U.code(r) == "authz.ownerOnly", "%s %s" % (r.status_code, r.text[:120]))
    for path in ("/api/settings/scim/revoke", "/api/settings/scim/enabled"):
        r = await adm.post(path, json={"current_password": "parolabuna1", "enabled": False})
        check("Admin pe %s → 403" % path, r.status_code == 403 and U.code(r) == "authz.ownerOnly")
    await U.add_user("vw@x.co", bindings=[("viewer", "all", "")])
    vw = await U.login("vw@x.co")
    r = await vw.get("/api/settings/scim")
    check("un Viewer nu vede nici starea (users.manage) → 403", r.status_code == 403)
    r = await owner.post("/api/settings/scim/token", json={})
    check("Owner fără parolă → 401 auth.wrongPassword", r.status_code == 401
          and U.code(r) == "auth.wrongPassword", r.text[:120])
    r = await owner.post("/api/settings/scim/token", json={"current_password": PW})
    tok = r.json().get("token", "")
    check("Owner cu parolă → token wtscim_… (arătat acum)", r.status_code == 200
          and tok.startswith("wtscim_") and len(tok) > 40, r.text[:200])
    st = (await owner.get("/api/settings/scim")).json()
    check("starea după creare: configurat + pornit, FĂRĂ token în răspuns",
          st["configured"] and st["enabled"] and "token" not in st and tok not in json.dumps(st))
    vals = [r["value"] or "" for r in await db.fetchall("SELECT value FROM app_settings")]
    check("tokenul NU e stocat în clar (doar sha256)", not any(tok in v for v in vals)
          and security.sha256_hex(tok) in vals)
    audit = await db.fetchone("SELECT detail FROM audit_log WHERE path='/api/settings/scim/token'"
                              " AND status=200 ORDER BY id DESC")
    check("crearea e auditată, fără token în jurnal", audit is not None
          and "created" in audit["detail"] and tok not in audit["detail"])
    c = sc(tok)
    r = await c.get("/scim/v2/ServiceProviderConfig")
    check("tokenul merge: ServiceProviderConfig 200 + application/scim+json",
          r.status_code == 200 and r.headers["content-type"].startswith(SCIM_CT)
          and r.json()["patch"]["supported"] is True and r.json()["filter"]["supported"] is True,
          "%s %s" % (r.status_code, r.headers.get("content-type")))
    # rotirea
    r = await owner.post("/api/settings/scim/token", json={"current_password": PW})
    tok2 = r.json().get("token", "")
    check("rotire → token nou, diferit", r.status_code == 200 and tok2 and tok2 != tok)
    r = await c.get("/scim/v2/ServiceProviderConfig")
    check("…tokenul VECHI → 401 imediat", is_scim_error(r, 401), r.text[:120])
    await c.aclose()
    c = sc(tok2)
    check("…tokenul nou merge", (await c.get("/scim/v2/Users")).status_code == 200)
    # oprit / pornit
    r = await owner.post("/api/settings/scim/enabled", json={"enabled": False})
    check("oprirea nu cere parolă (reduce doar accesul)", r.status_code == 200 and not r.json()["enabled"])
    r = await c.get("/scim/v2/Users")
    check("SCIM oprit → 403 cu tokenul bun", is_scim_error(r, 403), r.text[:120])
    r = await owner.post("/api/settings/scim/enabled", json={"enabled": True})
    check("pornirea CERE parola", r.status_code == 401)
    r = await owner.post("/api/settings/scim/enabled", json={"enabled": True, "current_password": PW})
    check("…cu parolă: pornit", r.status_code == 200 and r.json()["enabled"])
    st = (await owner.get("/api/settings/scim")).json()
    check("ultima cerere e raportată", st["last_request"] is not None)
    # revocarea
    r = await owner.post("/api/settings/scim/revoke", json={"current_password": PW})
    check("revocare → neconfigurat", r.status_code == 200 and not r.json()["configured"])
    r = await c.get("/scim/v2/Users")
    check("…tokenul revocat → 401", is_scim_error(r, 401))
    r = await owner.post("/api/settings/scim/enabled", json={"enabled": True, "current_password": PW})
    check("fără token, pornirea → 409 scim.noToken", r.status_code == 409 and U.code(r) == "scim.noToken")
    await c.aclose()
    for x in (adm, vw):
        await x.aclose()
    scim.reset_limits()
    r = await owner.post("/api/settings/scim/token", json={"current_password": PW})
    return r.json()["token"]


async def test_auth_matrix(owner, tok):
    print("── fiecare rută SCIM: fără token / token greşit / token de automatizare / cookie → 401")
    oid = await uid_of(U.OWNER_EMAIL)
    raw_api = "wt_" + security.new_token()
    import time
    await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by,"
                     " created_by_id, expires) VALUES(?,?,?,?,?,?,?)", "auto", security.sha256_hex(raw_api),
                     "read,run", time.time(), U.OWNER_EMAIL, oid, time.time() + 3600)
    routes = sorted(k for k, v in authz.route_perms([scim.router]).items())
    check("rutele SCIM enumerate din cod (15)", len(routes) == 15, str(len(routes)))
    principals = {
        "fără Authorization": U.client(headers={"content-type": SCIM_CT}),
        "token greşit": sc("wtscim_" + "x" * 43),
        "token de automatizare (Owner)": sc(raw_api),
        "Bearer gol": U.client(headers={"authorization": "Bearer ", "content-type": SCIM_CT}),
        "Basic cu tokenul bun": U.client(headers={"authorization": "Basic " + tok}),
        "cookie de Owner": owner,
    }
    bad = []
    for label, c in principals.items():
        for method, path in routes:
            scim.reset_limits()
            url = path.replace("{scim_id}", "u1").replace("{gid}", "g1")
            kw = {"content": b"{}"} if method in ("POST", "PUT", "PATCH") else {}
            r = await c.request(method, url, **kw)
            if not is_scim_error(r, 401):
                bad.append("%s %s %s → %s" % (label, method, path, r.status_code))
        check("%s → 401 SCIM pe toate cele %d rute" % (label, len(routes)),
              not [b for b in bad if b.startswith(label)], str([b for b in bad if b.startswith(label)][:3]))
    r = await principals["fără Authorization"].get("/scim/v2/Users")
    check("401 poartă WWW-Authenticate: Bearer", r.headers.get("www-authenticate", "").startswith("Bearer"))
    for label, c in principals.items():
        if c is not owner:
            await c.aclose()
    # blocare per IP
    scim.reset_limits()
    w = sc("wtscim_wrong")
    for _ in range(scim._FAIL_MAX):
        await w.get("/scim/v2/Users")
    good = sc(tok)
    r = await good.get("/scim/v2/Users")
    check("după %d eşecuri de pe un IP → 429 chiar şi cu tokenul bun (Retry-After)" % scim._FAIL_MAX,
          is_scim_error(r, 429) and r.headers.get("retry-after"), "%s %s" % (r.status_code, r.text[:100]))
    lock = await db.fetchone("SELECT COUNT(*) AS c FROM audit_log WHERE status=429 AND via='scim'")
    check("…blocarea e auditată o dată", lock["c"] == 1, str(lock["c"]))
    row = await db.fetchone("SELECT actor FROM audit_log WHERE status=429 AND via='scim'")
    check("…cu actorul `unauthenticated` (nimeni n-a dovedit că e IdP-ul), nu `scim`",
          row["actor"] == "unauthenticated", row["actor"])
    # revizuirea 3.6.11: un spray din multe IP-uri nu inundă jurnalul de audit
    fn = getattr(scim, "_audit_lockout", None)
    check("plafon global pentru rândurile de audit ale blocărilor (există)", fn is not None)
    if fn is not None:
        import time as _t
        t0 = _t.time()
        n0 = (await db.fetchone("SELECT COUNT(*) AS c FROM audit_log WHERE status=429"))["c"]
        for i in range(30):
            await fn(t0, "198.51.100.%d" % i, "/scim/v2/Users")
        n1 = (await db.fetchone("SELECT COUNT(*) AS c FROM audit_log WHERE status=429"))["c"]
        check("30 blocări din 30 de IP-uri → cel mult 20 de rânduri pe oră (total)",
              n1 - n0 == scim._LOCKOUT_AUDIT_MAX - 1, str(n1 - n0))
        await fn(t0 + 3700, "198.51.100.99", "/scim/v2/Users")
        last = await db.fetchone("SELECT detail FROM audit_log WHERE status=429 ORDER BY id DESC LIMIT 1")
        check("…după o oră, rândul următor spune câte n-au fost scrise",
              "11 earlier lockout(s) not recorded" in last["detail"], last["detail"])
    scim.reset_limits()
    check("după resetare, tokenul bun trece", (await good.get("/scim/v2/Users")).status_code == 200)
    # plafonul de cereri
    old = scim._RATE_MAX
    scim.reset_limits()
    scim._RATE_MAX = 3
    codes = [(await good.get("/scim/v2/Users")).status_code for _ in range(5)]
    scim._RATE_MAX = old
    scim.reset_limits()
    check("plafonul de cereri autentificate → 429", codes[:3] == [200, 200, 200] and codes[3] == 429, str(codes))
    # corp prea mare
    big = json.dumps(ak_user("big", "big@x.co")).encode()[:-1] + b',"pad":"' + b"x" * (1024 * 1024) + b'"}'
    r = await good.post("/scim/v2/Users", content=big)
    check("corp > 1 MiB → 413 (SCIM)", is_scim_error(r, 413), "%s" % r.status_code)
    # fără SSO
    config.OIDC_ENABLED = False
    r = await good.get("/scim/v2/Users")
    config.OIDC_ENABLED = True
    check("SSO neconfigurat → 403 (un cont SCIM n-ar putea intra niciodată)", is_scim_error(r, 403))
    await w.aclose()
    await good.aclose()


async def test_guard():
    print("── garda de rute: principalul SCIM doar sub /scim/v2/")
    from fastapi import APIRouter, Depends, FastAPI
    import httpx
    probe = APIRouter(dependencies=[Depends(authz.declared)])

    @probe.get("/api/__scim_probe")
    async def _p(_x=Depends(scim.require_scim)):      # noqa: ANN202
        return {"open": True}

    @probe.get("/scim/v2/__probe_multi")
    async def _m(_x=Depends(scim.require_scim), _u=Depends(authz.perm("users.manage"))):  # noqa: ANN202
        return {"open": True}
    tapp = FastAPI()
    tapp.include_router(probe)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=tapp), base_url="http://t") as c:
        r = await c.get("/api/__scim_probe")
        check("o rută /api/ cu dependenţa SCIM → 500 authz.undeclared (refuzată)",
              r.status_code == 500 and r.headers.get("x-webterm-error") == "authz.undeclared",
              "%s %s" % (r.status_code, r.text[:80]))
        r = await c.get("/scim/v2/__probe_multi")
        check("o rută cu SCIM + perm() → refuzată (ambiguă)", r.status_code == 500)
    kinds = {authz.route_spec(r)[0] for r in scim.router.routes}
    check("toate rutele SCIM sunt clasificate `scim`", kinds == {"scim"}, str(kinds))


async def test_users(owner, tok):
    print("── Users: creare, validare, conflict + filtru, paginare, PUT/PATCH, idempotenţă")
    c = sc(tok)
    r = await c.post("/scim/v2/Users", json=ak_user("ana", "Ana@X.co", ext="ext-ana"))
    j = r.json()
    check("POST (corp Authentik) → 201 + resursă", r.status_code == 201 and j.get("id")
          and j["userName"] == "ana" and j["active"] is True and j["externalId"] == "ext-ana"
          and j["emails"][0]["value"] == "ana@x.co" and j["meta"]["location"].endswith(j["id"]),
          r.text[:300])
    ana_id = j["id"]
    row = await db.fetchone("SELECT * FROM users WHERE email='ana@x.co'")
    check("contul: SSO-only (local_password=0), administrat SCIM, fără rol",
          row is not None and row["local_password"] == 0 and row["scim_managed"] == 1
          and not await bindings("ana@x.co"))
    lc = U.client()
    for pw in ("", "x", "parolabuna1"):
        r = await lc.post("/api/login", json={"email": "ana@x.co", "password": pw})
        if r.status_code == 200:
            break
    check("…nicio parolă nu-l deschide", r.status_code == 401)
    await lc.aclose()
    r = await c.post("/scim/v2/Users", json=ak_user("ana", "ana@x.co", ext="ext-ana"))
    check("POST duplicat → 409 uniqueness", is_scim_error(r, 409) and r.json().get("scimType") == "uniqueness")
    r = await c.get("/scim/v2/Users", params={"filter": 'userName eq "ANA"'})
    check("…filtrul Authentik `userName eq` (fără majuscule) o găseşte",
          r.status_code == 200 and r.json()["totalResults"] == 1 and r.json()["Resources"][0]["id"] == ana_id,
          r.text[:200])
    for f, n in (('externalId eq "ext-ana"', 1), ('externalId eq "EXT-ANA"', 0),
                 ('emails.value eq "ana@x.co"', 1), ('emails eq "ana@x.co"', 1),
                 ('id eq "%s"' % ana_id, 1), ('userName eq "nobody"', 0),
                 ('userName eq "a\\"b"', 0)):
        r = await c.get("/scim/v2/Users", params={"filter": f})
        check("filtru %s → %d" % (f, n), r.status_code == 200 and r.json()["totalResults"] == n, r.text[:120])
    for f in ('userName co "a"', 'userName eq ana', 'title eq "x"', 'userName eq "a" and active eq "true"',
              "x" * 2000):
        r = await c.get("/scim/v2/Users", params={"filter": f})
        check("filtru nesuportat %r → 400 invalidFilter" % f[:40], is_scim_error(r, 400)
              and r.json().get("scimType") == "invalidFilter")
    # validare
    for what, body in (("fără userName", {"emails": [{"value": "z@x.co"}]}),
                       ("fără email (userName nu e email)", {"userName": "zed"}),
                       ("email invalid", ak_user("zz", "not-an-email")),
                       ("userName cu caracter de control", ak_user("z\x07", "z@x.co")),
                       ("active de alt tip", dict(ak_user("zz", "zz@x.co"), active=3)),
                       ("emails nu e listă", dict(ak_user("zz", "zz@x.co"), emails=7))):
        r = await c.post("/scim/v2/Users", json=body)
        check("POST %s → 400 invalidValue" % what, is_scim_error(r, 400)
              and r.json().get("scimType") == "invalidValue", r.text[:120])
    r = await c.post("/scim/v2/Users", content=b"{nope")
    check("JSON invalid → 400 invalidSyntax", is_scim_error(r, 400) and r.json()["scimType"] == "invalidSyntax")
    r = await c.post("/scim/v2/Users", content=b"[1,2]")
    check("corp care nu e obiect → 400", is_scim_error(r, 400))
    r = await c.post("/scim/v2/Users", json={"userName": "mail@x.co"})
    check("userName = email şi fără emails → acceptat (liberal)", r.status_code == 201
          and r.json()["emails"][0]["value"] == "mail@x.co")
    r = await c.get("/scim/v2/Users/nope")
    check("GET /Users/<inexistent> → 404 SCIM", is_scim_error(r, 404))
    # paginare
    for i in range(5):
        await c.post("/scim/v2/Users", json=ak_user("p%d" % i, "p%d@x.co" % i, ext="ext-p%d" % i))
    r = await c.get("/scim/v2/Users", params={"startIndex": 3, "count": 2})
    j = r.json()
    check("paginare: startIndex=3 count=2", j["totalResults"] == 7 and j["itemsPerPage"] == 2
          and j["startIndex"] == 3 and len(j["Resources"]) == 2, str({k: j[k] for k in j if k != "Resources"}))
    r = await c.get("/scim/v2/Users", params={"count": 100000})
    check("count uriaş plafonat la 200", r.json()["itemsPerPage"] <= 200)
    r = await c.get("/scim/v2/Users", params={"count": "x"})
    check("count invalid → 400", is_scim_error(r, 400))
    # PUT / PATCH
    body = ak_user("ana", "ana@x.co", ext="ext-ana", name="Ana Popescu")
    r = await c.put("/scim/v2/Users/" + ana_id, json=body)
    check("PUT schimbă displayName", r.status_code == 200 and r.json()["displayName"] == "Ana Popescu")
    n = await scim_audit_rows()
    epoch = authz.epoch()
    r = await c.put("/scim/v2/Users/" + ana_id, json=body)
    check("PUT IDENTIC (re-sincronizare orară): nicio scriere, niciun rând de audit, nicio epocă",
          r.status_code == 200 and await scim_audit_rows() == n and authz.epoch() == epoch)
    r = await c.put("/scim/v2/Users/" + ana_id, json=dict(body, emails=[{"value": "p1@x.co", "primary": True}]))
    check("PUT cu emailul ALTUI cont → 409", is_scim_error(r, 409))
    r = await c.put("/scim/v2/Users/" + ana_id, json=dict(body, externalId="ext-p2"))
    check("PUT cu externalId-ul altui cont → 409", is_scim_error(r, 409))
    r = await c.patch("/scim/v2/Users/" + ana_id, json={"schemas": [scim.S_PATCH], "Operations": [
        {"op": "replace", "path": "userName", "value": "ana.pop"},
        {"op": "Replace", "path": 'emails[type eq "work"].value', "value": "ana.pop@x.co"},
        {"op": "add", "path": "title", "value": "ignored"}]})
    check("PATCH userName + emails[...].value (atribut necunoscut ignorat)", r.status_code == 200
          and r.json()["userName"] == "ana.pop" and r.json()["emails"][0]["value"] == "ana.pop@x.co", r.text[:200])
    r = await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [
        {"op": "replace", "path": "externalId", "value": "someone-else"}]})
    check("externalId e scris o singură dată (PATCH → 409 mutability)", is_scim_error(r, 409)
          and r.json().get("scimType") == "mutability", r.text[:160])
    r = await c.get("/scim/v2/Users", params={"startIndex": 10 ** 30})
    check("startIndex uriaş → listă goală, nu 500", r.status_code == 200 and r.json()["Resources"] == [])
    r = await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [
        {"op": "replace", "value": {"displayName": "A. Pop", "active": "False"}}]})
    check("PATCH fără path (obiect) + active \"False\" ca TEXT (Entra) → dezactivat",
          r.status_code == 200 and r.json()["active"] is False and r.json()["displayName"] == "A. Pop", r.text[:200])
    r = await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [
        {"op": "replace", "path": "active", "value": True}]})
    check("PATCH active true → reactivat (cont SCIM)", r.status_code == 200 and r.json()["active"] is True)
    await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [{"op": "replace", "path": "active",
                                                                    "value": False}]})
    nb = {k: v for k, v in body.items() if k != "active"}
    r = await c.put("/scim/v2/Users/" + ana_id, json=dict(nb, userName="ana.pop",
                                                         emails=[{"value": "ana.pop@x.co"}]))
    check("PUT FĂRĂ `active` nu reactivează (o reactivare e o acordare: trebuie spusă)",
          r.status_code == 200 and r.json()["active"] is False, r.text[:160])
    await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [{"op": "replace", "path": "active",
                                                                    "value": True}]})
    deep = b"[" * 100000 + b"]" * 100000
    r = await c.post("/scim/v2/Users", content=deep)
    check("JSON adânc imbricat → 400, nu 500", is_scim_error(r, 400), str(r.status_code))
    for what, ops in (("op necunoscut", [{"op": "move", "path": "active", "value": True}]),
                      ("Operations lipsă", None), ("Operations gol", []),
                      ("fără path, valoare ne-obiect", [{"op": "replace", "value": 3}])):
        r = await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": ops} if ops is not None else {})
        check("PATCH %s → 400" % what, is_scim_error(r, 400), r.text[:100])
    r = await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [{"op": "replace", "path": "active",
                                                                        "value": True}] * (scim.OPS_MAX + 1)})
    check("PATCH cu prea multe operaţii → 400", is_scim_error(r, 400))
    # revizuirea 3.6.11: căile complet calificate se aplică; cele necunoscute → 400 (fail closed)
    urn_active = scim.S_USER + ":active"
    r = await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [
        {"op": "replace", "path": urn_active, "value": False}]})
    check("PATCH path urn:…:User:active=false → APLICAT (dezactivat)", r.status_code == 200
          and r.json()["active"] is False, r.text[:160])
    r = await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [
        {"op": "replace", "value": {urn_active: True}}]})
    check("PATCH fără path cu cheia urn:…:User:active → APLICAT (reactivat)", r.status_code == 200
          and r.json()["active"] is True, r.text[:160])
    before = (await c.get("/scim/v2/Users/" + ana_id)).json()
    for what, op, code in (
            ("cale necunoscută", {"op": "replace", "path": "activ", "value": False}, "invalidPath"),
            ("atribut extern (urn:…:Group:active)", {"op": "replace", "path": scim.S_GROUP + ":active",
                                                     "value": False}, "invalidPath"),
            ("groups (readOnly)", {"op": "add", "path": "groups", "value": [{"value": "x"}]}, "mutability"),
            ("cheie necunoscută fără path", {"op": "replace", "value": {"activ": False}}, "invalidPath"),
            ("remove fără path", {"op": "remove"}, "noTarget")):
        r = await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [
            {"op": "replace", "path": "displayName", "value": "SHOULD-NOT-LAND"}, op]})
        check("PATCH %s → 400 %s, nimic aplicat" % (what, code), is_scim_error(r, 400)
              and r.json().get("scimType") == code
              and (await c.get("/scim/v2/Users/" + ana_id)).json() == before, r.text[:160])
    r = await c.patch("/scim/v2/Users/" + ana_id, json={"Operations": [
        {"op": "replace", "path": "name.givenName", "value": "Ana"},
        {"op": "replace", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
         "value": "Ops"},
        {"op": "replace", "path": 'phoneNumbers[type eq "work"].value', "value": "123"},
        {"op": "replace", "value": {"schemas": [scim.S_USER], "name": {"givenName": "A"}, "locale": "ro"}}]})
    check("atribute standard nepăstrate (name.*, extensie enterprise, phoneNumbers, locale) → 200",
          r.status_code == 200, r.text[:160])
    await c.aclose()


async def test_break_glass_and_adoption(owner, tok):
    print("── conturile cu parolă locală: neatinse; conturile SSO-only: adoptate")
    c = sc(tok)
    before = dict(await db.fetchone("SELECT * FROM users WHERE email=?", U.OWNER_EMAIL))
    n = await scim_audit_rows()
    r = await c.post("/scim/v2/Users", json=ak_user("boss", U.OWNER_EMAIL, ext="ext-boss", active=False))
    check("POST cu emailul Owner-ului break-glass → 409, explicat", is_scim_error(r, 409)
          and "local password" in r.json()["detail"], r.text[:200])
    after = dict(await db.fetchone("SELECT * FROM users WHERE email=?", U.OWNER_EMAIL))
    check("…contul Owner NEATINS (nici dezactivat, nici legat)", before == after)
    al = None
    for _ in range(50):
        al = await db.fetchone("SELECT severity FROM alerts WHERE msg_params LIKE '%scim_local_refused%'")
        if al:
            break
        await asyncio.sleep(0.02)
    check("…alertă CRITICĂ (SCIM a ţintit un cont break-glass)", al is not None
          and al["severity"] == "critical")
    check("…refuzul e auditat", await scim_audit_rows() == n + 1)
    st = (await owner.get("/api/settings/scim")).json()
    check("…şi apare ca ultima eroare în starea SCIM", st["last_error"] and st["last_error"]["status"] == 409
          and "local password" in st["last_error"]["detail"], str(st["last_error"]))
    r = await c.get("/scim/v2/Users", params={"filter": 'emails eq "%s"' % U.OWNER_EMAIL})
    check("contul break-glass e INVIZIBIL pentru SCIM (filtrul nu-l întoarce)", r.json()["totalResults"] == 0)
    oid = await uid_of(U.OWNER_EMAIL)
    await db.execute("UPDATE users SET sso_subject='sub-boss' WHERE id=?", oid)
    r = await c.post("/scim/v2/Users", json=ak_user("boss2", "other-boss@x.co", ext="sub-boss"))
    check("POST cu externalId = sub-ul Owner-ului break-glass → 409 (nimic atins)", is_scim_error(r, 409)
          and (await uid_of("other-boss@x.co")) is None)
    await db.execute("UPDATE users SET sso_subject=NULL WHERE id=?", oid)
    # adopţia unui cont SSO-only creat de un login OIDC
    loc = await sso_login("sub-bob", "bob@x.co", groups=[])
    bob = await uid_of("bob@x.co")
    check("login SSO creează contul bob (SSO-only)", bob is not None and "sso_error" not in loc, loc)
    r = await c.post("/scim/v2/Users", json=ak_user("bob", "bob@x.co", ext="sub-bob"))
    check("POST pentru bob → 201 ADOPTAT (acelaşi id, nu dublat)", r.status_code == 201
          and await uid_of("bob@x.co") == bob
          and (await db.fetchone("SELECT COUNT(*) AS c FROM users WHERE email='bob@x.co'"))["c"] == 1)
    r = await c.post("/scim/v2/Users", json=ak_user("x", "bob-other@x.co", ext="sub-bob-x"))
    r2 = await c.put("/scim/v2/Users/" + r.json()["id"], json=ak_user("x", "bob@x.co", ext="sub-bob-x"))
    check("schimbarea emailului pe al unui cont adoptat → 409", is_scim_error(r2, 409))
    # externalId == sub leagă la primul login, chiar fără email_verified
    r = await c.post("/scim/v2/Users", json=ak_user("cara", "cara@x.co", ext="sub-cara"))
    cid = await uid_of("cara@x.co")
    loc = await sso_login("sub-cara", "cara@x.co", groups=[], verified=False)
    row = await db.fetchone("SELECT sso_subject FROM users WHERE id=?", cid)
    check("contul SCIM se leagă la primul login SSO prin externalId = sub (fără email_verified)",
          "sso_error" not in loc and row["sso_subject"] == "sub-cara", loc)
    # revizuirea de securitate 3.6.11: tokenul SCIM nu poate re-ţinti identitatea unui cont nelegat
    r = await c.post("/scim/v2/Users", json=ak_user("zoe", "zoe@x.co", ext="sub-zoe"))
    zid, zuid = r.json()["id"], await uid_of("zoe@x.co")
    await U.bind(zuid, "admin", "all", "")                      # rol dat DE MÂNĂ înainte de primul login
    r = await c.patch("/scim/v2/Users/" + zid, json={"Operations": [
        {"op": "replace", "path": "emails", "value": [{"value": "mallory@x.co", "primary": True}]}]})
    check("cont nelegat cu rol manual: SCIM NU-i poate schimba emailul (409)", is_scim_error(r, 409)
          and r.json().get("scimType") == "mutability", r.text[:160])
    r = await c.patch("/scim/v2/Users/" + zid, json={"Operations": [
        {"op": "replace", "path": "externalId", "value": "sub-mallory"}]})
    check("…nici externalId-ul (409)", is_scim_error(r, 409))
    loc = await sso_login("sub-zoe", "mallory@x.co", groups=[])
    row = await db.fetchone("SELECT sso_subject FROM users WHERE id=?", zuid)
    check("externalId = sub dar ALT email → nu se leagă de contul lui zoe", row["sso_subject"] is None
          and await uid_of("mallory@x.co") != zuid, loc)
    zc = await U.login("zoe@x.co")
    r = await zc.post("/api/account", json={"new_password": "parolanoua123", "current_password": "x"})
    check("contul SCIM nu-şi poate pune parolă locală (409 account.scimManaged)", r.status_code == 409
          and U.code(r) == "account.scimManaged", "%s %s" % (r.status_code, r.text[:120]))
    await zc.aclose()
    # revizuirea 3.6.11 (cursă): SCIM adoptă contul cât timp utilizatorul trece de al doilea factor
    await U.add_user("racer@x.co")
    rc = await U.login("racer@x.co")
    rid = await uid_of("racer@x.co")
    orig_gate = webauthn_api.second_gate

    async def gate_then_adopt(*a, **kw):
        await orig_gate(*a, **kw)
        await db.execute("UPDATE users SET scim_managed=1 WHERE id=?", rid)
    webauthn_api.second_gate = gate_then_adopt
    try:
        r = await rc.post("/api/account", json={"new_password": "parolanoua123",
                                                "current_password": "parolabuna1"})
    finally:
        webauthn_api.second_gate = orig_gate
    row = await db.fetchone("SELECT password_hash FROM users WHERE id=?", rid)
    check("parolă locală setată în timp ce SCIM adoptă contul → 409 account.scimManaged, nescrisă",
          r.status_code == 409 and U.code(r) == "account.scimManaged"
          and security.verify_password("parolabuna1", row["password_hash"]),
          "%s %s" % (r.status_code, r.text[:120]))
    await rc.aclose()
    r = await c.post("/scim/v2/Users", json=ak_user("dan", "dan@x.co", ext="ext-dan"))
    loc = await sso_login("sub-dan", "dan@x.co", groups=[], verified=False)
    check("externalId ≠ sub şi email neverificat → adopţia prin email refuzată (regula veche)",
          "email_unverified" in loc, loc)
    await c.aclose()


async def map_group(owner, group, role, kind="all", value=""):
    r = await owner.post("/api/settings/oidc-roles", json={
        "group": group, "role": role, "scope_kind": kind, "scope_value": value, "current_password": PW})
    assert r.status_code == 200, r.text


async def test_groups(owner, tok):
    print("── Groups: membri → roluri imediat, PUT fără membri, redenumire, ştergere, Owner reţinut")
    c = sc(tok)
    await map_group(owner, "wt-db", "operator", "tag", "db")
    await map_group(owner, "wt-net", "viewer", "all")
    await map_group(owner, "wt-owners", "owner", "all")
    users = {}
    for n in ("gina", "hugo", "ioana"):
        r = await c.post("/scim/v2/Users", json=ak_user(n, "%s@x.co" % n, ext="sub-" + n))
        users[n] = r.json()["id"]
    # Ioana a intrat prin SSO cu wt-net (grup pe care SCIM NU-l împinge)
    await sso_login("sub-ioana", "ioana@x.co", groups=["wt-net"])
    check("ioana: viewer @ all din login (wt-net)", ("viewer", "all", "", "sso") in await bindings("ioana@x.co"))
    epoch = authz.epoch()
    r = await c.post("/scim/v2/Groups", json={"schemas": [scim.S_GROUP], "displayName": "wt-db",
                                              "externalId": "g-db", "members": [{"value": users["gina"]},
                                                                                {"value": "unknown-id"}]})
    gdb = r.json().get("id")
    check("POST grup cu membri → 201 (membru necunoscut ignorat)", r.status_code == 201
          and [m["value"] for m in r.json()["members"]] == [users["gina"]], r.text[:200])
    check("gina primeşte IMEDIAT operator @ tag:db (sso), epoca creşte",
          ("operator", "tag", "db", "sso") in await bindings("gina@x.co") and authz.epoch() > epoch)
    r = await c.post("/scim/v2/Groups", json={"displayName": "wt-db"})
    check("grup duplicat → 409 + găsit prin filtrul displayName", is_scim_error(r, 409)
          and (await c.get("/scim/v2/Groups", params={"filter": 'displayName eq "wt-db"'})).json()["totalResults"] == 1)
    # forma Authentik: PATCH add / remove pe `members`
    r = await c.patch("/scim/v2/Groups/" + gdb, json={"schemas": [scim.S_PATCH], "Operations": [
        {"op": "add", "path": "members", "value": [{"value": users["hugo"]}, {"value": users["ioana"]}]}]})
    check("PATCH add members → hugo şi ioana primesc operator @ tag:db", r.status_code == 200
          and ("operator", "tag", "db", "sso") in await bindings("hugo@x.co")
          and ("operator", "tag", "db", "sso") in await bindings("ioana@x.co"))
    check("…ioana îşi PĂSTREAZĂ wt-net (grup pe care SCIM nu-l gestionează)",
          ("viewer", "all", "", "sso") in await bindings("ioana@x.co"))
    r = await c.patch("/scim/v2/Groups/" + gdb, json={"Operations": [
        {"op": "remove", "path": "members", "value": [{"value": users["hugo"]}]}]})
    check("PATCH remove members → hugo pierde rolul pe loc", r.status_code == 200
          and ("operator", "tag", "db", "sso") not in await bindings("hugo@x.co"))
    r = await c.patch("/scim/v2/Groups/" + gdb, json={"Operations": [
        {"op": "remove", "path": 'members[value eq "%s"]' % users["ioana"]}]})
    check("PATCH remove cu filtru members[value eq …] → ioana pierde rolul",
          ("operator", "tag", "db", "sso") not in await bindings("ioana@x.co"))
    epoch = authz.epoch()
    r = await c.put("/scim/v2/Groups/" + gdb, json={"displayName": "wt-db", "externalId": "g-db"})
    check("PUT FĂRĂ members păstrează membrii (fără pâlpâit de roluri / epocă)", r.status_code == 200
          and [m["value"] for m in r.json()["members"]] == [users["gina"]] and authz.epoch() == epoch
          and ("operator", "tag", "db", "sso") in await bindings("gina@x.co"))
    r = await c.put("/scim/v2/Groups/" + gdb, json={"displayName": "wt-db", "members": [{"value": users["hugo"]}]})
    check("PUT cu members le ÎNLOCUIEŞTE (gina pierde, hugo câştigă)",
          ("operator", "tag", "db", "sso") not in await bindings("gina@x.co")
          and ("operator", "tag", "db", "sso") in await bindings("hugo@x.co"))
    r = await c.patch("/scim/v2/Groups/" + gdb, json={"Operations": [
        {"op": "replace", "value": {"displayName": "wt-db2"}}]})
    check("redenumire → numele vechi nu mai mapează: hugo pierde rolul",
          r.status_code == 200 and ("operator", "tag", "db", "sso") not in await bindings("hugo@x.co"))
    await c.patch("/scim/v2/Groups/" + gdb, json={"Operations": [
        {"op": "replace", "path": "displayName", "value": "wt-db"}]})
    check("…redenumit înapoi → rolul revine", ("operator", "tag", "db", "sso") in await bindings("hugo@x.co"))
    # revizuirea 3.6.11: căi de grup calificate se aplică; necunoscute → 400 (nimic aplicat)
    r = await c.patch("/scim/v2/Groups/" + gdb, json={"Operations": [
        {"op": "remove", "path": scim.S_GROUP + ":members", "value": [{"value": users["hugo"]}]}]})
    check("PATCH path urn:…:Group:members remove → APLICAT (hugo pierde rolul)", r.status_code == 200
          and ("operator", "tag", "db", "sso") not in await bindings("hugo@x.co"), r.text[:160])
    await c.patch("/scim/v2/Groups/" + gdb, json={"Operations": [
        {"op": "add", "path": "members", "value": [{"value": users["hugo"]}]}]})
    for what, op in (("cale necunoscută", {"op": "add", "path": "owners", "value": [{"value": users["gina"]}]}),
                     ("members[value eq …] cu add", {"op": "add", "path": 'members[value eq "%s"]' % users["gina"],
                                                    "value": [{"value": users["gina"]}]}),
                     ("cheie necunoscută fără path", {"op": "replace", "value": {"owners": []}}),
                     ("id (readOnly)", {"op": "replace", "path": "id", "value": "x"})):
        r = await c.patch("/scim/v2/Groups/" + gdb, json={"Operations": [
            {"op": "remove", "path": "members", "value": [{"value": users["hugo"]}]}, op]})
        check("PATCH grup %s → 400, nimic aplicat" % what, is_scim_error(r, 400)
              and ("operator", "tag", "db", "sso") in await bindings("hugo@x.co"), r.text[:160])
    r = await c.get("/scim/v2/Groups/" + gdb, params={"excludedAttributes": "members"})
    check("excludedAttributes=members", r.status_code == 200 and "members" not in r.json())
    # nume exact: spaţiul final contează
    r = await c.post("/scim/v2/Groups", json={"displayName": "wt-net ", "members": [{"value": users["gina"]}]})
    check("„wt-net ” (cu spaţiu) e alt grup: acceptat exact, NU mapează la wt-net",
          r.status_code == 201 and r.json()["displayName"] == "wt-net "
          and ("viewer", "all", "", "sso") not in await bindings("gina@x.co"))
    for bad in ("", "a\nb", "x" * 300, "zero​width", 7):
        r = await c.post("/scim/v2/Groups", json={"displayName": bad})
        check("displayName invalid %r → 400" % (bad if not isinstance(bad, str) else bad[:12]),
              is_scim_error(r, 400))
    # Owner nu se acordă printr-un push
    r = await c.post("/scim/v2/Groups", json={"displayName": "wt-owners", "members": [{"value": users["gina"]}]})
    gown = r.json()["id"]
    check("membru în wt-owners prin SCIM → Owner NEacordat", r.status_code == 201
          and not any(b[0] == "owner" for b in await bindings("gina@x.co")))
    row = await db.fetchone("SELECT detail FROM audit_log WHERE detail LIKE '%Owner-level role not granted%'")
    check("…reţinerea e auditată", row is not None)
    await sso_login("sub-gina", "gina@x.co", groups=["wt-owners"])
    check("…dar la login-ul SSO interactiv, gina primeşte Owner (regula mapării)",
          ("owner", "all", "", "sso") in await bindings("gina@x.co"))
    epoch = authz.epoch()
    await c.post("/scim/v2/Groups/%s" % gown, json={})            # metodă greşită → 405, nimic
    r = await c.patch("/scim/v2/Groups/" + gown, json={"Operations": [{"op": "remove", "path": "members"}]})
    check("SCIM o scoate din wt-owners → Owner retras pe loc (o retragere, nu o acordare)",
          r.status_code == 200 and not any(b[0] == "owner" for b in await bindings("gina@x.co"))
          and authz.epoch() > epoch)
    r = await c.delete("/scim/v2/Groups/" + gdb)
    check("DELETE grup → 204, hugo pierde rolul", r.status_code == 204
          and ("operator", "tag", "db", "sso") not in await bindings("hugo@x.co"))
    r = await c.get("/scim/v2/Groups/" + gdb)
    check("…grupul nu mai există (404)", is_scim_error(r, 404))
    r = await c.get("/scim/v2/Users/" + users["gina"])
    check("resursa User arată grupurile (readOnly)", r.status_code == 200
          and {g["display"] for g in r.json()["groups"]} == {"wt-net "}, r.text[:300])
    r = await c.get("/scim/v2/Groups", params={"startIndex": 1, "count": 1})
    check("Groups: paginare", r.json()["itemsPerPage"] == 1 and r.json()["totalResults"] >= 2)
    await c.aclose()


async def test_discovery(tok):
    print("── descoperire")
    c = sc(tok)
    r = await c.get("/scim/v2/ResourceTypes")
    check("ResourceTypes: User + Group", r.status_code == 200
          and {x["name"] for x in r.json()["Resources"]} == {"User", "Group"})
    r = await c.get("/scim/v2/Schemas")
    check("Schemas: User + Group", r.status_code == 200
          and {x["id"] for x in r.json()["Resources"]} == {scim.S_USER, scim.S_GROUP})
    r = await c.get("/scim/v2/Nope")
    check("rută SCIM necunoscută → 404 (nu pagina SPA)", r.status_code == 404
          and "<html" not in r.text.lower())
    await c.aclose()


async def main():
    await U.boot()
    owner = await U.owner_client()
    tok = await test_token_lifecycle(owner)
    await test_auth_matrix(owner, tok)
    await test_guard()
    await test_users(owner, tok)
    await test_break_glass_and_adoption(owner, tok)
    await test_groups(owner, tok)
    await test_discovery(tok)
    await owner.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
