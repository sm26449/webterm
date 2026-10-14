"""Tokenuri de automatizare cu rol + scope (3.6.10, §A.6.5).

Efectivul unui token = plafonul vechi al scope-urilor (read/run) ∩ rolul ales ∩ scope-ul
tokenului ∩ ce poate creatorul ACUM (re-evaluat la fiecare cerere). Se verifică:
  * crearea: rol predefinit sau custom (după id), scope all/folder/tag/host; Owner refuzat
    (400 token.roleNotAllowed); anti-escaladare (rol/scope peste ce ai tu → 403/404);
  * lista arată rolul şi scope-ul (role, role_id, role_name, scope_kind, scope_value);
  * efectul: hosturile din afara scope-ului tokenului sunt invizibile (404 IDENTIC cu inexistent);
    un rol fără `run` nu rulează nimic, chiar cu scope-ul `run`;
  * creatorul retrogradat → tokenul se micşorează pe loc; creator fără legături → nimic;
  * tokenurile vechi (role_id NULL) se comportă EXACT ca înainte;
  * lista neagră (`authz.TOKEN_NEVER`): niciun token nu ajunge la users/roles/settings/…, oricare
    ar fi rolul; un rând cu rolul Owner (creat înainte de 3.6.10) merge ca înainte — fără plafon
    de rol, dar tot read/run ∩ creator − TOKEN_NEVER — şi e semnalat la pornire;
  * hosturile cu 2FA rămân închise oricărui token (step-up imposibil) — şi cu rol;
  * rutele care acceptă tokenuri rămân EXACT cele patru (route_auth_test o verifică şi el).
"""
import asyncio
import logging
import time

import rbac_util as U
from app import authz, db, security

check = U.Checker()
PW = "parolabuna1"


def tb(name, role="", kind="all", value="", scopes=("read", "run"), pw=U.OWNER_PW, **extra):
    return dict({"name": name, "scopes": list(scopes), "days": 1, "role": role,
                 "scope_kind": kind, "scope_value": value, "current_password": pw}, **extra)


def bearer(tok):
    return U.client(headers={"authorization": "Bearer " + tok})


async def run(c, hid):
    return await c.post("/api/hosts/%d/run" % hid, json={"command": "true"})


async def visible(c):
    r = await c.get("/api/hosts")
    return {h["id"] for h in r.json()} if r.status_code == 200 else None


async def main():
    await U.boot()
    owner = await U.owner_client()
    a = await U.add_host(owner, "alpha", folder="prod")
    b = await U.add_host(owner, "beta", folder="lab")
    c2fa = await U.add_host(owner, "gamma", folder="prod")
    await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", c2fa)

    # ── creare ───────────────────────────────────────────────────────────────────────────
    r = await owner.post("/api/tokens", json=tb("own", role="owner"))
    check("rol Owner pe token → 400 token.roleNotAllowed",
          r.status_code == 400 and U.code(r) == "token.roleNotAllowed", r.text[:120])
    r = await owner.post("/api/tokens", json=tb("op-prod", role="operator", kind="folder", value="prod"))
    check("Operator @ folder prod → 200", r.status_code == 200, r.text[:160])
    t_op = r.json()["token"]
    row = next(x for x in r.json()["tokens"] if x["name"] == "op-prod")
    check("lista: rol + scope", row["role"] == "operator" and row["role_name"] == "Operator"
          and isinstance(row["role_id"], int) and row["scope_kind"] == "folder"
          and row["scope_value"] == "prod", str(row))
    r = await owner.post("/api/roles", json={"name": "Runner", "perms": ["host.view", "run"],
                                             "current_password": U.OWNER_PW})
    rid = next(x["id"] for x in r.json()["custom"] if x["name"] == "Runner")
    r = await owner.post("/api/tokens", json=tb("custom", role_id=rid, kind="host", value=str(a)))
    row = next((x for x in r.json().get("tokens", []) if x["name"] == "custom"), {})
    check("rol custom după id @ host → 200, listat cu numele lui", r.status_code == 200
          and row.get("role_name") == "Runner" and row.get("role") == "" and row.get("role_id") == rid,
          r.text[:160])
    t_custom = r.json()["token"]
    r = await owner.post("/api/tokens", json=tb("vw", role="viewer"))
    t_vw = r.json()["token"]
    r = await owner.post("/api/tokens", json=tb("legacy"))
    t_legacy = r.json()["token"]
    row = next(x for x in r.json()["tokens"] if x["name"] == "legacy")
    check("token vechi (fără rol): role_id null, scope all", row["role_id"] is None and row["role"] == ""
          and row["scope_kind"] == "all")

    # ── efect ────────────────────────────────────────────────────────────────────────────
    c = bearer(t_op)
    check("Operator@prod: vede doar hosturile din prod", await visible(c) == {a, c2fa}, str(await visible(c)))
    r = await run(c, a)
    check("…run pe alpha: trece de autorizare (409 host.offline, fără agent)",
          r.status_code == 409 and U.code(r) == "host.offline", "%s %s" % (r.status_code, r.text[:120]))
    r_b, r_none = await run(c, b), await run(c, 987654)
    check("…run pe beta (lab) → 404 IDENTIC cu un host inexistent",
          r_b.status_code == 404 and U.code(r_b) == "host.missing" and r_b.text == r_none.text)
    r = await run(c, c2fa)
    check("…host cu 2FA: închis oricărui token (403 host.needs2faNoToken)",
          r.status_code == 403 and U.code(r) == "host.needs2faNoToken", "%s %s" % (r.status_code, r.text[:120]))
    await c.aclose()
    c = bearer(t_custom)
    check("rol custom @ host alpha: vede doar alpha", await visible(c) == {a})
    check("…şi rulează acolo", U.code(await run(c, a)) == "host.offline")
    await c.aclose()
    c = bearer(t_vw)
    r = await run(c, a)
    check("Viewer cu scope-ul run: run → 403 authz.denied (rolul nu are run)",
          r.status_code == 403 and U.code(r) == "authz.denied", "%s %s" % (r.status_code, r.text[:120]))
    check("…dar citeşte lista", await visible(c) == {a, b, c2fa})
    await c.aclose()
    c = bearer(t_legacy)
    check("token vechi: exact ca înainte (vede tot, rulează)", await visible(c) == {a, b, c2fa}
          and U.code(await run(c, a)) == "host.offline")
    await c.aclose()
    tok = await db.fetchone("SELECT * FROM api_tokens WHERE name='legacy'")
    g = await authz.grants_for_token(dict(tok))
    check("token vechi: plafonul = scope-urile vechi (read ∪ run), neatins de lista neagră",
          g.ceiling == authz.TOKEN_SCOPE_PERMS["read"] | authz.TOKEN_SCOPE_PERMS["run"], str(g.ceiling))

    # ── lista neagră ─────────────────────────────────────────────────────────────────────
    for role in ("admin", "operator", "viewer"):
        rid_ = await authz.role_id(role)
        fake = {"id": 0, "name": "x", "scopes": "read,run", "created_by_id": 1, "role_id": rid_,
                "scope_kind": "all", "scope_value": ""}
        g = await authz.grants_for_token(fake)
        bad = (g.ceiling | g.global_perms) & authz.TOKEN_NEVER
        check("rol %s: nimic din TOKEN_NEVER (users/roles/settings/tokens/…)" % role, not bad, str(bad))
        if role == "operator":
            sh = {"share.live", "share.replay", "serial.use", "host.wake"}
            check("…Operator (care le are): niciun token nu primeşte share.live/share.replay/"
                  "serial.use/host.wake", not (g.ceiling & sh) and sh <= authz.TOKEN_NEVER, str(g.ceiling))
    legacy_all = authz.TOKEN_SCOPE_PERMS["read"] | authz.TOKEN_SCOPE_PERMS["run"]
    check("lista neagră nu atinge plafoanele vechi read/run (comportamentul vechi neschimbat)",
          not (legacy_all & authz.TOKEN_NEVER), str(legacy_all & authz.TOKEN_NEVER))
    owner_rid = await authz.role_id("owner")
    await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by,"
                     " created_by_id, expires, role_id) VALUES('forged', ?, 'read,run', ?, ?, 1, ?, ?)",
                     security.sha256_hex(security.TOKEN_PREFIX + "forged-owner-token-value"),
                     time.time(), U.OWNER_EMAIL, time.time() + 3600, owner_rid)
    c = bearer(security.TOKEN_PREFIX + "forged-owner-token-value")
    # revizuirea 3.6.10: un token creat cu rolul Owner ÎNAINTE de 3.6.10 merge exact ca înainte
    # (rolul Owner nu era un plafon) — fără plafon de rol, dar tot read/run, TOKEN_NEVER şi creatorul
    check("token cu rolul Owner de dinainte de 3.6.10: exact ca un token vechi (vede tot, rulează)",
          await visible(c) == {a, b, c2fa} and U.code(await run(c, a)) == "host.offline")
    otok = await db.fetchone("SELECT * FROM api_tokens WHERE name='forged'")
    g = await authz.grants_for_token(dict(otok))
    check("…plafonul = scope-urile vechi, nimic din TOKEN_NEVER",
          g.ceiling == (authz.TOKEN_SCOPE_PERMS["read"] | authz.TOKEN_SCOPE_PERMS["run"]) - authz.TOKEN_NEVER
          and not (g.ceiling | g.global_perms) & authz.TOKEN_NEVER, str(g.ceiling))
    r = await c.get("/api/users")
    check("…/api/users nu acceptă tokenuri (401)", r.status_code == 401)
    await c.aclose()
    gone = dict(otok, role_id=987654)
    check("…un rând cu un rol care nu (mai) există: nimic", not (await authz.grants_for_token(gone)).ceiling)
    seen = []

    class _H(logging.Handler):
        def emit(self, rec):
            seen.append(rec.getMessage())
    h = _H()
    logging.getLogger("webterm").addHandler(h)
    try:
        await db.close()
        await db.connect()                 # o pornire nouă: authz.seed avertizează
    finally:
        logging.getLogger("webterm").removeHandler(h)
    warn = [m for m in seen if "Owner role from before 3.6.10" in m]
    check("…la pornire: un avertisment cu id-ul şi numele tokenului, fără secret",
          len(warn) == 1 and "'forged'" in warn[0] and "#%d" % otok["id"] in warn[0]
          and otok["token_hash"] not in warn[0], str(seen)[:300])

    # ── creatorul ACUM ───────────────────────────────────────────────────────────────────
    # tokens.create e GLOBAL (doar de la o legătură @ all): un rol custom care dă doar asta
    op_id = await U.add_user("op@x.co", bindings=[("operator", "folder", "prod")])
    r = await owner.post("/api/roles", json={"name": "TokenMaker", "perms": ["tokens.create"],
                                             "current_password": U.OWNER_PW})
    tm = next(x["id"] for x in r.json()["custom"] if x["name"] == "TokenMaker")
    await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                     " created) VALUES(?,?,'all','','manual',?)", op_id, tm, time.time())
    authz.bump_epoch()
    op = await U.login("op@x.co")
    r = await op.post("/api/tokens", json=tb("lab", role="operator", kind="folder", value="lab", pw=PW))
    check("Operator@prod: token peste lab → 403 authz.escalation",
          r.status_code == 403 and U.code(r) == "authz.escalation", r.text[:120])
    r = await op.post("/api/tokens", json=tb("lab-h", role="viewer", kind="host", value=str(b), pw=PW))
    check("…token pe un host invizibil (beta) → 404 host.missing",
          r.status_code == 404 and U.code(r) == "host.missing", r.text[:120])
    r = await op.post("/api/tokens", json=tb("mine", role="operator", pw=PW))
    check("…token Operator @ all (mai larg decât el): 403 authz.escalation",
          r.status_code == 403 and U.code(r) == "authz.escalation", r.text[:120])
    r = await op.post("/api/tokens", json=tb("mine", role="operator", kind="folder", value="prod", pw=PW))
    check("…token Operator @ prod → 200", r.status_code == 200, r.text[:120])
    t_mine = r.json()["token"]
    c = bearer(t_mine)
    check("token-ul lui rulează pe alpha", U.code(await run(c, a)) == "host.offline")
    await db.execute("DELETE FROM role_bindings WHERE user_id=? AND role_id<>?", op_id, tm)
    await U.bind(op_id, "viewer", "folder", "prod")
    r = await run(c, a)
    check("creator retrogradat la Viewer → tokenul nu mai rulează (403)",
          r.status_code == 403 and U.code(r) == "authz.denied", "%s %s" % (r.status_code, r.text[:120]))
    check("…dar încă vede prod (Viewer ∩ Operator)", await visible(c) == {a, c2fa})
    await U.unbind_all(op_id)
    check("creator fără nicio legătură → tokenul nu vede nimic", await visible(c) == set())
    check("…run → 404", (await run(c, a)).status_code == 404)
    await c.aclose()
    await op.aclose()
    await owner.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
