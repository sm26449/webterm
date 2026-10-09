"""Matricea rută × rol, GENERATĂ din declaraţiile din cod (`authz.route_perms`) — nu scrisă de mână.

Pentru fiecare rută (mai puţin cele PUBLICE şi WebSocket-urile, testate în rbac_ws_test) o
chemăm ca:
  · Owner @ all            — trece de autorizare (orice ar spune handlerul după)
  · Admin @ all            — trece, mai puţin permisiunile de preluare (backup, semnare, istoric)
  · Viewer @ host:A        — pe A: trece dacă rolul are permisiunea, altfel 403 `authz.denied`
  · Operator @ folder:lab  — A e în `prod`: 404 IDENTIC cu un id inexistent (fără oracol)
  · cont fără nicio legătură — idem: 404 pe rutele de host, 403 pe cele globale, listele goale
  · token (read+run) al Owner-ului, fără cookie — doar pe lista albă; restul 401
Aşteptările se calculează din rolurile predefinite (`authz.BUILTIN_ROLES`) şi din specificaţia
rutei, deci o rută nouă intră automat în matrice. `route_auth_test` leagă specificaţia de Anexa A.

Separat: ordinea autorizare → step-up (pe un host 2FA, cine n-are acces primeşte 404, nu
`stepup.*` — step-up-ul nu e un oracol; cine are acces dă în continuare de step-up).
"""
import asyncio
import re

import rbac_util as U
from app import api, authz, db, oidc_api, webauthn_api

check = U.Checker()
ROUTERS = [api.router, webauthn_api.router, oidc_api.router]
NOPE = 987654          # id care nu există


def _fill(path, ids):
    def sub(m):
        return str(ids.get(m.group(1), NOPE))
    return re.sub(r"{(\w+)}", sub, path)


def _body(ids):
    hid = ids["host_id"]
    return {"host_id": hid, "src_host": hid, "dst_host": hid, "key_host_id": hid,
            "target_host_id": hid}


def _expect(principal, spec, kind):
    """→ 'ok' | 'denied' | 'hidden' | 'unauth'."""
    role = principal["role"]
    if principal["token"]:
        if kind != "perm" or not spec.tokens:
            return "unauth"
        alts = set(spec.perm)
        return "ok" if alts & (authz.TOKEN_SCOPE_PERMS["read"] | authz.TOKEN_SCOPE_PERMS["run"]) \
            else "denied"
    if kind in ("self",):
        return "ok"
    if spec.list:
        return "ok"
    perms = authz.BUILTIN_ROLES[role]["perms"] if role else frozenset()
    if spec.kind == "G":
        return "ok" if principal["all"] and set(spec.perm) & perms else "denied"
    # host-scoped, pe host A
    if not principal["sees_a"]:
        return "hidden"
    if spec.zero_is_self:
        return "ok" if set(spec.perm) & perms else "denied"
    return "ok" if set(spec.perm) & perms else "denied"


def _verdict(r, loc_code):
    c = U.code(r)
    if c == "auth.required" or (r.status_code == 401 and not c):
        return "unauth"
    if c == "authz.denied":
        return "denied"
    if c == "authz.undeclared":
        return "undeclared"
    if r.status_code == 404 and c == loc_code:
        return "hidden?"           # ori ascuns de authz, ori 404 al handlerului (acelaşi corp)
    return "ok"


LOC_CODE = {"host_id": "host.missing", "body": "host.missing", "sid": "session.missing",
            "fid": "forward.missing", "link_id": "replay.missing"}


async def main():
    await U.boot()
    owner = await U.owner_client()
    a = await U.add_host(owner, "alpha", folder="prod", tags="web")
    await U.add_host(owner, "beta", folder="lab")   # al doilea folder: scope-ul lui `opother`
    sess = await U.add_session(a, state="closed")
    fwd = await U.add_forward(a, "alpha-app", enabled=1, app_type="custom")
    link = await db.execute(
        "INSERT INTO replay_links(token_hash, sid, user_id, label, redact, created, expires)"
        " VALUES(?,?,?,?,?,?,?)", "x" * 64, sess, 1, "", 1, 0, 9e12)
    conn = await db.execute(
        "INSERT INTO connections(host_id, label, engine, created) VALUES(?,?,?,?)",
        a, "db", "postgres", 0)
    ids = {"host_id": a, "sid": sess, "fid": fwd, "link_id": link, "conn_id": conn}

    await U.add_user("viewer@x.co", bindings=[("viewer", "host", a)])
    await U.add_user("admin@x.co", bindings=[("admin", "all", "")])
    await U.add_user("opother@x.co", bindings=[("operator", "folder", "lab")])
    await U.add_user("nobody@x.co")
    r = await owner.post("/api/tokens", json={"name": "ci", "scopes": ["read", "run"],
                                              "current_password": U.OWNER_PW})
    tok = r.json()["token"]
    principals = [
        {"name": "viewer", "c": await U.login("viewer@x.co"), "role": "viewer", "all": False,
         "sees_a": True, "token": False},
        {"name": "opother", "c": await U.login("opother@x.co"), "role": "operator", "all": False,
         "sees_a": False, "token": False},
        {"name": "nobody", "c": await U.login("nobody@x.co"), "role": None, "all": False,
         "sees_a": False, "token": False},
        {"name": "token", "c": U.client(headers={"authorization": "Bearer " + tok}),
         "role": "owner", "all": True, "sees_a": True, "token": True},
        {"name": "admin", "c": await U.login("admin@x.co"), "role": "admin", "all": True,
         "sees_a": True, "token": False},
        # Owner-ul ULTIMUL: handlerele lui chiar rulează (inclusiv cele distructive)
        {"name": "owner", "c": owner, "role": "owner", "all": True, "sees_a": True,
         "token": False},
    ]

    rp = authz.route_perms(ROUTERS)
    routes = sorted((k, v) for k, v in rp.items() if v[0] != "public" and k[0] != "WS")
    check("matricea are rute de testat (generată, nu scrisă de mână)", len(routes) > 150,
          str(len(routes)))
    counts = {"perm": 0, "self": 0}
    by_kind = {"G": 0, "H": 0, "L": 0}
    oracle_fail = []
    for p in principals:
        for (method, path), (kind, spec) in routes:
            if kind == "perm":
                counts["perm"] += p["name"] == "owner"
                by_kind[spec.kind] += p["name"] == "owner"
            else:
                counts["self"] += p["name"] == "owner"
            want = _expect(p, spec, kind)
            url = _fill(path, ids)
            kw = {}
            if method in ("POST", "PATCH", "PUT", "DELETE"):
                kw["json"] = _body(ids)
            r = await p["c"].request(method, url, **kw)
            loc = spec.host.split(":")[0] if kind == "perm" and spec.host else "host_id"
            got = _verdict(r, LOC_CODE.get(loc, "host.missing"))
            if want == "hidden":
                good = got == "hidden?"
                # fără oracol: acelaşi răspuns ca pentru un id INEXISTENT
                nids = {k: (NOPE if isinstance(v, int) else "f" * 32) for k, v in ids.items()}
                kw2 = {"json": _body(nids)} if "json" in kw else {}
                r2 = await p["c"].request(method, _fill(path, nids), **kw2)
                same = (r.status_code == r2.status_code and r.json() == r2.json()
                        and U.code(r) == U.code(r2))
                if not same:
                    oracle_fail.append("%s %s %s: %s %s vs %s %s" % (
                        p["name"], method, path, r.status_code, r.text[:80],
                        r2.status_code, r2.text[:80]))
            elif want == "ok":
                good = got in ("ok", "hidden?") if p["name"] in ("owner", "admin", "token") \
                    else got == "ok"
            else:
                good = got == want
            check("%-8s %-6s %s → %s" % (p["name"], method, path, want), good,
                  "got %s (%s %s)" % (got, r.status_code, r.text[:160]))
    check("niciun 404 de host ascuns nu e un oracol (identic cu id inexistent)",
          not oracle_fail, "\n      " + "\n      ".join(oracle_fail))
    print("  · acoperire: %d rute cu permisiune (%d globale, %d pe host, %d liste) + %d SELF,"
          " × %d principali" % (counts["perm"], by_kind["G"], by_kind["H"], by_kind["L"],
                                counts["self"], len(principals)))

    # ── autorizarea vine ÎNAINTEA step-up-ului ────────────────────────────────────────────
    h2 = await U.add_host(owner, "gamma", folder="prod")
    await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", h2)
    vg = await U.add_user("v2@x.co", bindings=[("operator", "host", h2)])
    cv = await U.login("v2@x.co")
    r = await cv.get("/api/hosts/%d/fs" % h2)
    check("cu acces pe un host 2FA: step-up-ul încă se cere (authz nu-l ocoleşte)",
          r.status_code == 403 and U.code(r).startswith(("stepup.", "host.needs2fa")),
          "%s %s" % (r.status_code, U.code(r)))
    co = await U.login("opother@x.co")
    r = await co.get("/api/hosts/%d/fs" % h2)
    check("fără acces pe un host 2FA: 404 (nu `stepup.*` — step-up-ul nu confirmă hostul)",
          r.status_code == 404 and U.code(r) == "host.missing", "%s %s" % (r.status_code, U.code(r)))
    r = await co.post("/api/hosts/%d/stepup" % h2, json={})
    check("ceremonia de step-up pe un host invizibil → 404", r.status_code == 404)
    r = await co.post("/api/webauthn/stepup/options", json={"host_id": h2})
    check("passkey step-up options pe un host invizibil → 404", r.status_code == 404,
          "%s %s" % (r.status_code, r.text[:100]))
    r = await co.post("/api/webauthn/stepup/options", json={"host_id": 0})
    check("passkey step-up account-scope (host_id 0) rămâne self-service", r.status_code == 200,
          "%s %s" % (r.status_code, r.text[:100]))
    del vg

    for p in principals:
        await p["c"].aclose()
    await cv.aclose()
    await co.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
