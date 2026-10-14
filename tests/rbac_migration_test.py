"""Migrarea la 3.6: fiecare cont existent devine Owner @ all — nimeni nu e blocat afară (§A.8).

Pornim de la o bază cu schema 3.5 (SCHEMA + migraţiile de DINAINTE de roluri), cu conturi,
hosturi, sesiuni şi tokenuri vechi, şi o deschidem cu codul 3.6:
  * fiecare cont → Owner @ all (source=migration), iar instanţa e marcată `rbac_seeded`;
  * tokenurile vechi (fără rol) merg exact ca înainte (citire + rulare, cu detaliile de status);
  * idempotent: o a doua (şi a treia) pornire nu dublează nimic şi nu re-acordă nimic;
  * un cont adăugat DUPĂ seeding (ex. din CLI) NU devine Owner din oficiu — doar avertisment;
  * restaurarea unui backup 3.5 (fără `rbac_seeded`) re-rulează seeding-ul;
  * rolurile predefinite sunt re-scrise la fiecare pornire din catalogul din cod;
  * `python3 -m app.admin promote` repară o instalare fără Owner (break-glass).
"""
import asyncio
import os
import sqlite3
import sys
import time

import rbac_util as U
from app import authz, config, db, security

check = U.Checker()


def build_35_db(path):
    """Schema EXACT dinainte de 3.6: tot SCHEMA până la tabelele de roluri + migraţiile vechi."""
    schema = db.SCHEMA.split("-- Roluri şi legături")[0]
    cut = db.MIGRATIONS.index("ALTER TABLE api_tokens ADD COLUMN role_id INTEGER")
    con = sqlite3.connect(path)
    con.executescript(schema)
    for stmt in db.MIGRATIONS[:cut]:
        try:
            con.execute(stmt)
        except sqlite3.OperationalError as e:
            if "duplicate column" not in str(e):
                raise
    now = time.time()
    for i, email in enumerate(("ana@x.co", "bob@x.co", "sso@x.co"), 1):
        con.execute("INSERT INTO users(id, email, password_hash, created, sso_subject)"
                    " VALUES(?,?,?,?,?)", (i, email, security.hash_password("parolabuna1"), now,
                                           "sub-3" if i == 3 else None))
    con.execute("INSERT INTO hosts(id, name, token_hash, token_encrypted, created, folder)"
                " VALUES(1,'h1','th1','x',?, 'prod')", (now,))
    con.execute("INSERT INTO hosts(id, name, token_hash, token_encrypted, created, folder)"
                " VALUES(2,'h2','th2','x',?, 'lab')", (now,))
    con.execute("INSERT INTO sessions(id, host_id, title, state, created) VALUES(?,?,?,?,?)",
                ("a" * 32, 1, "old", "closed", now))
    con.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by,"
                " created_by_id, expires) VALUES(?,?,?,?,?,?,?)",
                ("legacy", security.sha256_hex("wt_legacytoken000000000000000000"), "read,run",
                 now, "bob@x.co", 2, now + 86400))
    # tokenuri de dinainte de `created_by_id` (rezolvate după email la fiecare folosire)
    for name, by in (("pre-id-ana", "ana@x.co"), ("pre-id-ghost", "ghost@x.co")):
        con.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by, expires)"
                    " VALUES(?,?,?,?,?,?)", (name, security.sha256_hex(name), "read", now, by,
                                             now + 86400))
    # tokenuri de grup de dinainte de `created_by_id` (re-review 3.6.11)
    for name, by in (("eg-ana", "ana@x.co"), ("eg-ghost", "ghost@x.co")):
        con.execute("INSERT INTO enroll_groups(name, token_hash, created, created_by, expires)"
                    " VALUES(?,?,?,?,?)", (name, security.sha256_hex(name), now, by, now + 86400))
    con.commit()
    con.close()


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    path = str(config.DB_PATH)
    if os.path.exists(path):
        os.unlink(path)
    build_35_db(path)
    con = sqlite3.connect(path)
    has = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    check("fixture: baza e cu adevărat pre-3.6 (fără tabele de roluri)",
          "roles" not in has and "role_bindings" not in has, str(sorted(has))[:200])

    await db.connect()
    rows = await db.fetchall(
        "SELECT u.email, r.key, b.scope_kind, b.source FROM role_bindings b JOIN roles r"
        " ON r.id=b.role_id JOIN users u ON u.id=b.user_id ORDER BY u.id")
    check("fiecare cont existent → Owner @ all (source=migration)",
          [(r["email"], r["key"], r["scope_kind"], r["source"]) for r in rows] ==
          [("ana@x.co", "owner", "all", "migration"), ("bob@x.co", "owner", "all", "migration"),
           ("sso@x.co", "owner", "all", "migration")], str([dict(r) for r in rows]))
    st = await db.fetchone("SELECT value FROM app_settings WHERE key='rbac_seeded'")
    check("instanţa e marcată `rbac_seeded`", bool(st and st["value"]))
    roles = {r["key"]: r for r in await db.fetchall("SELECT key, builtin FROM roles")}
    check("cele patru roluri predefinite există, read-only (builtin=1)",
          set(roles) == {"owner", "admin", "operator", "viewer"}
          and all(r["builtin"] == 1 for r in roles.values()))

    # comportament: zero diferenţă pentru conturile migrate
    from app import api
    await api.init_setup_token()
    for email in ("ana@x.co", "bob@x.co"):
        c = await U.login(email)
        r = await c.get("/api/hosts")
        check("%s (migrat) vede toată flota, ca înainte" % email,
              sorted(h["id"] for h in r.json()) == [1, 2])
        r = await c.get("/api/settings/smtp")
        check("%s (migrat) are în continuare acces la setări" % email, r.status_code == 200)
        await c.aclose()
    tok = U.client(headers={"authorization": "Bearer wt_legacytoken000000000000000000"})
    r = await tok.get("/api/hosts")
    check("tokenul vechi (fără rol) merge neschimbat — vede flota", r.status_code == 200
          and len(r.json()) == 2, r.text[:120])
    r = await tok.get("/api/status")
    check("…status cu detaliile de instanţă (creatorul e Owner)", r.json().get("storage") is not None)
    r = await tok.get("/api/sessions")
    check("…şi lista de sesiuni", r.status_code == 200 and len(r.json()) == 1)
    r = await tok.post("/api/hosts/1/run", json={"command": "id"})
    check("…şi `run` (trece de autorizare; host offline → 409)", r.status_code == 409,
          "%s %s" % (r.status_code, r.text[:80]))
    await tok.aclose()
    # revizuirea 3.6.11: rezolvarea după email e îngheţată O SINGURĂ DATĂ, apoi fără id = mort
    t = {r["name"]: r["created_by_id"] for r in await db.fetchall(
        "SELECT name, created_by_id FROM api_tokens WHERE name LIKE 'pre-id-%'")}
    check("token fără created_by_id: completat o dată după emailul de ACUM (ana → 1)",
          t == {"pre-id-ana": 1, "pre-id-ghost": None}, str(t))
    await db.close()
    con = sqlite3.connect(path)
    con.execute("INSERT INTO users(email, password_hash, created) VALUES('ghost@x.co','x',?)",
                (time.time(),))
    con.commit()
    con.close()
    await db.connect()
    row = await db.fetchone("SELECT * FROM api_tokens WHERE name='pre-id-ghost'")
    g = await authz.grants_for_token(dict(row))
    check("…un cont creat DUPĂ cu acel email NU moşteneşte tokenul (nici la o repornire)",
          row["created_by_id"] is None and g.user_id is None, str(dict(row)))
    # re-review 3.6.11 (LOW-2): la fel pentru tokenurile de grup — revocate la scoatere DOAR după id
    eg = {r["name"]: r["created_by_id"] for r in await db.fetchall(
        "SELECT name, created_by_id FROM enroll_groups WHERE name LIKE 'eg-%'")}
    check("token de grup fără created_by_id: completat o dată după emailul de ACUM (ana → 1)",
          eg == {"eg-ana": 1, "eg-ghost": None}, str(eg))
    ghost = (await db.fetchone("SELECT id FROM users WHERE email='ghost@x.co'"))["id"]
    from app import accounts
    n_ghost = await accounts.revoke_enroll_groups(ghost, "ghost@x.co")
    n_ana = await accounts.revoke_enroll_groups(1, "ana@x.co")
    rev = {r["name"]: r["revoked"] for r in await db.fetchall(
        "SELECT name, revoked FROM enroll_groups WHERE name LIKE 'eg-%'")}
    check("…scoaterea contului care ia ACUM acel email nu-l atinge; a creatorului (după id) îl revocă",
          n_ghost == 0 and n_ana == 1 and rev == {"eg-ana": 1, "eg-ghost": 0}, str(rev))
    await db.execute("DELETE FROM users WHERE email='ghost@x.co'")
    await db.close()

    # idempotent
    for n in (2, 3):
        await db.connect()
        c = (await db.fetchone("SELECT COUNT(*) AS c FROM role_bindings"))["c"]
        check("pornirea #%d: nicio legătură dublată (3)" % n, c == 3, str(c))
        await db.close()

    # cont nou după seeding (ex. inserat din CLI / SQL): fără acces din oficiu
    con = sqlite3.connect(path)
    con.execute("INSERT INTO users(email, password_hash, created) VALUES('late@x.co','x',?)",
                (time.time(),))
    con.commit()
    con.close()
    await db.connect()
    late = await db.fetchone("SELECT COUNT(*) AS c FROM role_bindings b JOIN users u ON u.id=b.user_id"
                             " WHERE u.email='late@x.co'")
    check("cont adăugat DUPĂ seeding: NU devine Owner automat", late["c"] == 0)
    await db.close()

    # restore al unui backup 3.5: `rbac_seeded` lipseşte → seeding-ul rulează din nou
    con = sqlite3.connect(path)
    con.execute("DELETE FROM role_bindings")
    con.execute("DELETE FROM app_settings WHERE key='rbac_seeded'")
    con.commit()
    con.close()
    await db.connect()
    c = (await db.fetchone("SELECT COUNT(*) AS c FROM role_bindings"))["c"]
    check("restore din 3.5 (fără rbac_seeded): toţi re-seeded ca Owner (4 conturi)", c == 4, str(c))
    await db.close()

    # id-uri de cont nerefolosite, pe o bază venită din 3.5 (fără AUTOINCREMENT, fără reconstrucţie)
    await db.connect()
    top = (await db.fetchone("SELECT MAX(id) AS m FROM users"))["m"]
    await db.raise_user_id_floor(top)
    await db.execute("DELETE FROM users WHERE id=?", top)
    await db.raise_user_id_floor(top)                      # idempotent
    await db.execute("INSERT INTO users(id, email, password_hash, created) VALUES("
                     + db.NEXT_USER_ID_SQL + ",'fresh@x.co','x',?)", time.time())
    nid = (await db.fetchone("SELECT id FROM users WHERE email='fresh@x.co'"))["id"]
    check("id-ul celui mai nou cont şters NU e dat contului următor (bază 3.5)", nid == top + 1,
          "%s vs %s" % (nid, top))
    await db.close()
    await db.connect()
    await db.execute("INSERT INTO users(id, email, password_hash, created) VALUES("
                     + db.NEXT_USER_ID_SQL + ",'fresh2@x.co','x',?)", time.time())
    n2 = (await db.fetchone("SELECT id FROM users WHERE email='fresh2@x.co'"))["id"]
    check("…nici după o repornire", n2 == top + 2, str(n2))
    await db.close()

    # rolurile predefinite sunt re-asertate din cod (un rând modificat de mână e reparat)
    con = sqlite3.connect(path)
    con.execute("UPDATE roles SET perms='[]', name='hacked' WHERE key='viewer'")
    con.commit()
    con.close()
    await db.connect()
    r = await db.fetchone("SELECT name, perms FROM roles WHERE key='viewer'")
    check("rolurile predefinite sunt re-scrise la pornire din catalogul din cod",
          r["name"] == "Viewer" and "host.view" in r["perms"])

    # break-glass: nicio legătură de Owner → `admin promote`
    await db.execute("DELETE FROM role_bindings")
    authz.bump_epoch()
    check("fixture: instanţa nu mai are niciun Owner", await authz.owner_count() == 0)
    from app import admin
    old_argv = sys.argv
    sys.argv = ["app.admin", "promote", "ana@x.co"]
    try:
        await admin.cmd_promote(type("A", (), {"email": "ana@x.co"})())
    finally:
        sys.argv = old_argv
    check("`python3 -m app.admin promote` → Owner @ all", await authz.owner_count() == 1)
    ep = await db.fetchone("SELECT value FROM app_settings WHERE key='authz_epoch'")
    check("…şi semnalează gateway-ului (authz_epoch în app_settings)", bool(ep and ep["value"]))
    au = await db.fetchone("SELECT detail FROM audit_log WHERE path='/admin/promote'")
    check("…auditat", bool(au))
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
