"""Maparea grupurilor SSO → roluri (3.6.2; design „3.6.1", §A.7) şi re-sincronizarea legăturilor.

Ce se verifică (callback-ul REAL, cu `oidc.complete` înlocuit de un IdP fals — validarea
id_token-ului are suitele ei: oidc_test, pentest_oidc_alg):
  * cine mapează: `users.manage`, anti-escaladare peste scope, doar un Owner mapează la Owner,
    re-auth; grup invalid / duplicat / host invizibil refuzate;
  * sincronizarea la login ŞI la step-up: adaugă ce lipseşte, scoate legăturile `sso` al căror
    grup a dispărut, NU atinge legăturile manuale;
  * claim `groups` ABSENT → nimic nu se schimbă; PREZENT dar gol → legăturile sso pleacă;
  * nume de grup: exacte (case-sensitive), spaţiile exterioare ignorate; `*` = orice cont SSO;
    o listă uriaşă e citită doar până la plafon (poate doar să acorde MAI PUŢIN);
  * o mapare nouă NU acordă nimic până la următorul login; una ştearsă retrage imediat;
  * ultimul Owner nu e scos niciodată de o sincronizare (păstrat + jurnal);
  * o legătură manuală identică cu una sso o „adoptă" (nu mai pleacă la sincronizare);
  * ştergerea unui host ia cu ea maparea pe `host:<id>`;
  * migrarea pe o copie cu schema 3.6.0 (construită aici, niciodată prod) e idempotentă.
"""
import asyncio
import os
import sqlite3
import tempfile

os.environ["WEBTERM_OIDC_ISSUER"] = "http://127.0.0.1:9"
os.environ["WEBTERM_OIDC_CLIENT_ID"] = "wt-client"
os.environ["WEBTERM_OIDC_CLIENT_SECRET"] = "wt-secret"
os.environ.pop("WEBTERM_OIDC_ALLOWED_GROUPS", None)

import rbac_util as U  # noqa: E402
from app import authz, config, db, oidc, oidc_api, security  # noqa: E402

check = U.Checker()
PW = "parolabuna1"
_ABSENT = object()


def idp(sub, email, groups=_ABSENT, intent="login", host_id=None):
    """Înlocuieşte oidc.complete: ce ar întoarce un IdP după un id_token valid."""
    def complete(state, code):
        return {"sub": sub, "email": email, "email_verified": True,
                "groups": oidc._claims_groups({} if groups is _ABSENT else {"groups": groups}),
                "groups_present": groups is not _ABSENT,
                "intent": intent, "host_id": host_id}
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
    return U.client(cookies={security.COOKIE_NAME: tok})


async def sso_stepup(c, sub, email, groups=_ABSENT, host_id=None):
    idp(sub, email, groups, intent="stepup", host_id=host_id)
    r = await c.get("/api/oidc/callback", params={"code": "c", "state": "s"},
                    cookies={oidc_api.STATE_COOKIE: "s"}, follow_redirects=False)
    return r.headers.get("location", "")


async def sso_set(email):
    row = await db.fetchone("SELECT id FROM users WHERE email=?", email)
    rows = await db.fetchall(
        "SELECT r.key, r.name, b.scope_kind, b.scope_value, b.source FROM role_bindings b"
        " JOIN roles r ON r.id=b.role_id WHERE b.user_id=?", row["id"])
    return {((x["key"] or x["name"]), x["scope_kind"], x["scope_value"], x["source"]) for x in rows}


def mp(group, role="", scope_kind="all", scope_value="", role_id=0, pw=PW):
    return {"group": group, "role": role, "role_id": role_id, "scope_kind": scope_kind,
            "scope_value": scope_value, "current_password": pw}


async def add_map(c, *a, **k):
    return await c.post("/api/settings/oidc-roles", json=mp(*a, **k))


async def map_id(group):
    r = await db.fetchone("SELECT id FROM oidc_group_roles WHERE grp=?", group)
    return r["id"] if r else None


async def main():
    check("SSO activ în test (configuraţia de env)", config.OIDC_ENABLED)
    await U.boot()
    owner = await U.owner_client()
    a = await U.add_host(owner, "alpha", folder="prod")
    b = await U.add_host(owner, "beta", folder="lab")
    OPW = U.OWNER_PW
    await U.add_user("adm@x.co", bindings=[("admin", "all", "")])
    adm = await U.login("adm@x.co")
    await U.add_user("sadm@x.co", bindings=[("admin", "folder", "prod")])
    sadm = await U.login("sadm@x.co")
    await U.add_user("vw@x.co", bindings=[("viewer", "all", "")])
    vw = await U.login("vw@x.co")

    # ── 1. cine mapează (matrice) ─────────────────────────────────────────────────────────
    r = await vw.get("/api/settings/oidc-roles")
    check("Viewer: GET mapări → 403", r.status_code == 403 and U.code(r) == "authz.denied")
    r = await owner.get("/api/settings/oidc-roles")
    check("Owner: GET mapări → listă goală + claim-ul `groups`", r.status_code == 200
          and r.json()["mappings"] == [] and r.json()["claim"] == "groups", r.text[:160])
    matrix = [
        ("Admin → owner@all", adm, mp("wt-owners", "owner"), 403, "authz.ownerOnly"),
        ("Admin@folder → viewer@prod", sadm, mp("g1", "viewer", "folder", "prod"), 403, "authz.denied"),
        ("Viewer → viewer@all", vw, mp("g2", "viewer"), 403, "authz.denied"),
        ("Admin → host inexistent", adm, mp("g3", "viewer", "host", "987654"), 404, "host.missing"),
        ("Admin → grup gol", adm, mp("   ", "viewer"), 400, "ssoMap.badGroup"),
        ("Admin → grup cu caracter de control", adm, mp("a\nb", "viewer"), 400, "ssoMap.badGroup"),
        ("Admin → grup de 300 de caractere", adm, mp("g" * 300, "viewer"), 400, "ssoMap.badGroup"),
        ("Admin → rol necunoscut", adm, mp("g4", "superuser"), 400, "authz.badRole"),
        ("Admin → parolă greşită", adm, mp("g5", "viewer", pw="gresit"), 401, "auth.wrongPassword"),
        ("Admin → operator@folder prod", adm, mp(" ops ", "operator", "folder", "prod"), 200, ""),
        ("Admin → duplicat", adm, mp("ops", "operator", "folder", "prod"), 409, "ssoMap.exists"),
        ("Owner → owner@all", owner, mp("wt-owners", "owner", pw=OPW), 200, ""),
    ]
    for label, c, body, st, cd in matrix:
        r = await c.post("/api/settings/oidc-roles", json=body)
        check("mapare: %s → %d" % (label, st), r.status_code == st and (not cd or U.code(r) == cd),
              "%s %s" % (r.status_code, r.text[:140]))
    check("grupul mapat e normalizat (spaţiile exterioare scoase), nu altfel",
          await map_id("ops") is not None and await map_id(" ops ") is None)
    vault = await db.execute(
        "INSERT INTO roles(key, name, description, perms, builtin, created, updated)"
        " VALUES(NULL,'Vault','','[\"backups.manage\",\"host.view\"]',0,0,0)")
    r = await add_map(adm, "vaulters", role_id=vault)
    check("Admin NU mapează un rol custom cu backups.manage (escaladare)", r.status_code == 403
          and U.code(r) == "authz.escalation", r.text[:120])
    cnt = (await db.fetchone("SELECT COUNT(*) AS c FROM oidc_group_roles"))["c"]
    check("…doar cele 2 mapări permise există", cnt == 2, str(cnt))

    # ── 2. sincronizarea la login ─────────────────────────────────────────────────────────
    alice = await sso_login("sub-alice", "alice@x.co", ["ops", "unrelated"])
    check("login SSO cu grupul `ops` → Operator @ folder prod (source sso)",
          await sso_set("alice@x.co") == {("operator", "folder", "prod", "sso")},
          str(await sso_set("alice@x.co")))
    r = await alice.get("/api/hosts")
    check("…şi vede exact hostul din prod", [h["id"] for h in r.json()] == [a], r.text[:120])
    uid_alice = (await db.fetchone("SELECT id FROM users WHERE email='alice@x.co'"))["id"]
    r = await owner.post("/api/users/%d/bindings" % uid_alice,
                         json={"role": "viewer", "scope_kind": "host", "scope_value": str(b),
                               "current_password": OPW})
    check("Owner îi adaugă manual Viewer pe beta", r.status_code == 200, r.text[:120])
    stored = (await db.fetchone("SELECT sso_groups FROM users WHERE id=?", uid_alice))["sso_groups"]
    check("doar grupurile MAPATE sunt reţinute (nu toată lista IdP-ului)", stored == '["ops"]', stored)

    ep = authz.epoch()
    await sso_login("sub-alice", "alice@x.co", _ABSENT)
    check("claim `groups` ABSENT: legăturile sso rămân (un IdP prost configurat nu taie pe toţi)",
          ("operator", "folder", "prod", "sso") in await sso_set("alice@x.co"))
    check("…şi epoca nu se mişcă", authz.epoch() == ep)
    await sso_login("sub-alice", "alice@x.co", ["Ops"])
    check("nume cu alt caz (`Ops` ≠ `ops`): nu se potriveşte → legătura sso pleacă",
          ("operator", "folder", "prod", "sso") not in await sso_set("alice@x.co"))
    check("…legătura MANUALĂ rămâne", ("viewer", "host", str(b), "manual") in await sso_set("alice@x.co"))
    check("…epoca a crescut (terminalele deschise re-verifică acum)", authz.epoch() > ep)
    await sso_login("sub-alice", "alice@x.co", ["  ops\t"])
    check("spaţii exterioare în claim: se potriveşte", ("operator", "folder", "prod", "sso")
          in await sso_set("alice@x.co"))
    await sso_login("sub-alice", "alice@x.co", [])
    check("claim PREZENT dar gol → legăturile sso pleacă, cea manuală rămâne",
          await sso_set("alice@x.co") == {("viewer", "host", str(b), "manual")},
          str(await sso_set("alice@x.co")))
    await sso_login("sub-alice", "alice@x.co", {"weird": "type"})
    check("claim de tip necitibil = niciun grup (fail-closed)",
          await sso_set("alice@x.co") == {("viewer", "host", str(b), "manual")})
    big = ["g%05d" % i for i in range(6000)]
    big[5500] = "ops"
    await sso_login("sub-alice", "alice@x.co", big)
    check("listă uriaşă: dincolo de plafon nu se citeşte (acordă doar MAI PUŢIN)",
          ("operator", "folder", "prod", "sso") not in await sso_set("alice@x.co"))
    big[10] = "ops"
    await sso_login("sub-alice", "alice@x.co", big)
    check("…în interiorul plafonului: se potriveşte", ("operator", "folder", "prod", "sso")
          in await sso_set("alice@x.co"))
    # un cont SSO nou fără niciun grup mapat: logat, fără acces
    bob = await sso_login("sub-bob", "bob@x.co", ["nothing-mapped"])
    check("SSO fără grup mapat: niciun rol (\"fără acces încă\")", await sso_set("bob@x.co") == set())
    check("…flotă goală", (await bob.get("/api/hosts")).json() == [])

    # ── 3. step-up SSO re-sincronizează (grupuri proaspete la momentele sensibile) ─────────
    await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", a)
    loc = await sso_stepup(alice, "sub-alice", "alice@x.co", ["ops"], host_id=a)
    check("step-up SSO cu grupul încă prezent: fereastra se deschide", "stepup=ok" in loc, loc)
    loc = await sso_stepup(alice, "sub-alice", "alice@x.co", [], host_id=a)
    check("step-up SSO după scoaterea din grup: legătura sso pleacă ÎNAINTE de fereastră",
          ("operator", "folder", "prod", "sso") not in await sso_set("alice@x.co"))
    check("…iar fereastra pe host (acum invizibil) e refuzată", "sso_error=denied" in loc, loc)
    await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", a)

    # ── 4. o mapare nouă aşteaptă login-ul; una ştearsă retrage imediat ──────────────────
    await sso_login("sub-alice", "alice@x.co", ["ops", "lab-team"])
    r = await add_map(adm, "lab-team", "viewer", "folder", "lab")
    check("mapare nouă adăugată", r.status_code == 200, r.text[:120])
    check("…NU acordă nimic până la următorul login (fără date de grup vechi)",
          ("viewer", "folder", "lab", "sso") not in await sso_set("alice@x.co"))
    await sso_login("sub-alice", "alice@x.co", ["ops", "lab-team"])
    check("…după login: acordată", ("viewer", "folder", "lab", "sso") in await sso_set("alice@x.co"))
    # a doua mapare care justifică ACEEAŞI legătură: ştergerea uneia n-o scoate
    r = await add_map(adm, "prod-team", "operator", "folder", "prod")
    await sso_login("sub-alice", "alice@x.co", ["ops", "prod-team", "lab-team"])
    ep = authz.epoch()
    r = await adm.post("/api/settings/oidc-roles/%d/delete" % await map_id("ops"),
                       json={"current_password": PW})
    check("ştergerea mapării `ops`", r.status_code == 200, r.text[:120])
    check("…legătura justificată şi de `prod-team` rămâne",
          ("operator", "folder", "prod", "sso") in await sso_set("alice@x.co"))
    r = await adm.post("/api/settings/oidc-roles/%d/delete" % await map_id("prod-team"),
                       json={"current_password": PW})
    check("ştergerea ultimei mapări care o justifica → legătura pleacă IMEDIAT (fără login)",
          ("operator", "folder", "prod", "sso") not in await sso_set("alice@x.co"))
    check("…epoca a crescut", authz.epoch() > ep)
    check("…cea manuală şi cea din `lab-team` rămân",
          {("viewer", "host", str(b), "manual"), ("viewer", "folder", "lab", "sso")}
          <= await sso_set("alice@x.co"))
    r = await adm.post("/api/settings/oidc-roles/%d/delete" % await map_id("wt-owners"),
                       json={"current_password": PW})
    check("Admin NU şterge maparea la Owner (doar un Owner)", r.status_code == 403
          and U.code(r) == "authz.ownerOnly", r.text[:120])
    check("audit: mapările şi sincronizările sunt în jurnal", (await db.fetchone(
        "SELECT COUNT(*) AS c FROM audit_log WHERE detail LIKE 'SSO %'"))["c"] >= 4)

    # ── 5. wildcard `*` ──────────────────────────────────────────────────────────────────
    r = await add_map(adm, "*", "viewer", "host", str(b))
    await sso_login("sub-bob", "bob@x.co", [])
    check("`*` = orice cont SSO, chiar fără grupuri", ("viewer", "host", str(b), "sso")
          in await sso_set("bob@x.co"))
    await adm.post("/api/settings/oidc-roles/%d/delete" % await map_id("*"),
                   json={"current_password": PW})
    check("…ştersă: retrasă imediat", await sso_set("bob@x.co") == set())

    # ── 6. o legătură manuală identică adoptă una sso ────────────────────────────────────
    uid_bob = (await db.fetchone("SELECT id FROM users WHERE email='bob@x.co'"))["id"]
    await sso_login("sub-bob", "bob@x.co", ["lab-team"])
    r = await adm.post("/api/users/%d/bindings" % uid_bob,
                       json={"role": "viewer", "scope_kind": "folder", "scope_value": "lab",
                             "current_password": PW})
    check("legătura manuală identică cu una sso: acceptată", r.status_code == 200, r.text[:120])
    await sso_login("sub-bob", "bob@x.co", [])
    check("…devine manuală şi NU mai pleacă la sincronizare",
          await sso_set("bob@x.co") == {("viewer", "folder", "lab", "manual")},
          str(await sso_set("bob@x.co")))

    # ── 7. ultimul Owner nu e scos de o sincronizare ─────────────────────────────────────
    await sso_login("sub-carol", "carol@x.co", ["wt-owners"])
    check("`wt-owners` → Owner @ all (sso)", ("owner", "all", "", "sso") in await sso_set("carol@x.co"))
    owner_id = (await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL))["id"]
    await db.execute("DELETE FROM role_bindings WHERE user_id=?", owner_id)  # fixture: carol rămâne singurul
    authz.bump_epoch()
    check("fixture: carol e singurul Owner", await authz.owner_count() == 1)
    await sso_login("sub-carol", "carol@x.co", [])
    check("grupul dispare, dar e ULTIMUL Owner: legătura e PĂSTRATĂ (instanţa nu se blochează)",
          ("owner", "all", "", "sso") in await sso_set("carol@x.co"))
    check("…în jurnal", (await db.fetchone(
        "SELECT COUNT(*) AS c FROM audit_log WHERE detail LIKE '%KEPT last Owner%'"))["c"] >= 1)
    await U.bind(owner_id, "owner", "all", "")
    await sso_login("sub-carol", "carol@x.co", [])
    check("cu încă un Owner: legătura sso de Owner pleacă normal", await sso_set("carol@x.co") == set())

    # ── 8. ştergerea unui host ia maparea pe `host:<id>` ─────────────────────────────────
    h = await U.add_host(owner, "gamma", folder="prod")
    r = await add_map(adm, "gamma-team", "viewer", "host", str(h))
    check("mapare pe un host", r.status_code == 200, r.text[:120])
    r = await owner.delete("/api/hosts/%d" % h)
    check("…ştergerea hostului reuşeşte", r.status_code == 200, "%s %s" % (r.status_code, r.text[:120]))
    check("…şi ia maparea cu ea (un id refolosit nu moşteneşte accesul)", await map_id("gamma-team") is None)

    for c in (owner, adm, sadm, vw, alice, bob):
        await c.aclose()
    await db.close()

    # ── 9. migrarea: o copie cu schema 3.6.0, construită AICI (niciodată prod) ───────────
    d = tempfile.mkdtemp()
    old_path = config.DB_PATH
    config.DB_PATH = os.path.join(d, "webterm.db")
    try:
        await db.connect()
        await db.close()
        con = sqlite3.connect(config.DB_PATH)
        con.executescript("""
            ALTER TABLE users DROP COLUMN sso_groups;
            ALTER TABLE users DROP COLUMN sso_synced;
            DROP INDEX IF EXISTS idx_rb_role;
            DROP TABLE oidc_group_roles;
            CREATE TABLE oidc_group_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT, grp TEXT NOT NULL, role_id INTEGER NOT NULL,
                scope_kind TEXT NOT NULL, scope_value TEXT NOT NULL DEFAULT '',
                UNIQUE(grp, role_id, scope_kind, scope_value));
            INSERT INTO oidc_group_roles(grp, role_id, scope_kind, scope_value)
                VALUES('legacy', (SELECT id FROM roles WHERE key='viewer'), 'all', '');
        """)
        con.commit()
        cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
        con.close()
        check("fixture: schema 3.6.0 (fără coloanele noi)", "sso_groups" not in cols)
        await db.connect()
        ucols = {r["name"] for r in await db.fetchall("PRAGMA table_info(users)")}
        mcols = {r["name"] for r in await db.fetchall("PRAGMA table_info(oidc_group_roles)")}
        check("upgrade: coloanele noi apar", {"sso_groups", "sso_synced"} <= ucols
              and {"created", "created_by_id"} <= mcols, "%s %s" % (ucols, mcols))
        row = await db.fetchone("SELECT grp, created FROM oidc_group_roles")
        check("…maparea veche e păstrată", row and row["grp"] == "legacy" and row["created"] == 0)
        await db.close()
        await db.connect()                 # a doua oară: idempotent (duplicate column ignorat)
        check("a doua pornire pe aceeaşi bază: fără eroare, aceleaşi date",
              (await db.fetchone("SELECT COUNT(*) AS c FROM oidc_group_roles"))["c"] == 1)
        await db.close()
    finally:
        config.DB_PATH = old_path
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
