"""Fiecare rută îşi DECLARĂ permisiunea — prin enumerare, nu prin listă scrisă de mână.

Istoric: autentificarea era opt-in per rută (`user=Depends(security.require_user)`), adică
FAIL-OPEN — uiţi `Depends` şi ruta devine publică. Testul enumera `router.routes` şi cerea o
dependenţă de autentificare sau o intrare în `PUBLIC`, cu motiv.

De la 3.6 (roluri, docs/design/ROLES-AND-SSH.md §A.6.2) cerinţa e mai strictă: fiecare rută are
EXACT O dependenţă `authz.perm(...)` (care autentifică ŞI autorizează), ori o intrare în
`authz.PUBLIC` (credenţialul e în cerere) ori în `authz.SELF` (doar datele proprii), ambele cu
motiv, în COD — nu în test. Acelaşi tabel îl foloseşte garda de la runtime (`authz.declared`),
deci o rută uitată e inutilizabilă (500 `authz.undeclared`), nu deschisă.

În plus: fiecare localizator de host (`host=`) numeşte un parametru REAL al rutei (prinde
`host="hostid"`), iar permisiunea declarată se potriveşte cu matricea din Anexa A a documentului
de design — documentul şi codul nu au voie să diveargă tăcut.
"""
import os
import pathlib
import re
import sys
import tempfile

os.environ.setdefault("WEBTERM_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gateway"))

from app import api, authz, oidc_api, webauthn_api  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


# TOATE routerele montate în `main.py`, nu doar `api`. Prima versiune a testului enumera
# doar `api.router` şi rata complet `webauthn_api.router` — adică exact suprafaţa care
# manevrează passkey-urile şi step-up-ul 2FA, unde costul unei omisiuni e cel mai mare.
ROUTERS = {"api": api.router, "webauthn_api": webauthn_api.router, "oidc_api": oidc_api.router}
ROOT = pathlib.Path(__file__).resolve().parent.parent


def _methods(r):
    m = getattr(r, "methods", None)
    return sorted(m) if m else ["WS"]


def _body_fields(route) -> set:
    """Câmpurile modelului de corp (pentru localizatorii `body:<câmp>`)."""
    out = set()
    dependant = getattr(route, "dependant", None)
    for p in getattr(dependant, "body_params", []) or []:
        ann = getattr(p, "field_info", None)
        t = getattr(p, "type_", None) or getattr(getattr(p, "field_info", None), "annotation", None)
        model = getattr(p, "type_", None)
        for cand in (model, getattr(ann, "annotation", None), t):
            fields = getattr(cand, "model_fields", None)
            if fields:
                out |= set(fields)
    return out


def _doc_matrix() -> dict:
    """(METHOD, path) → (celula începe cu `—`, prima permisiune din coloana `Perm` a Anexei A)."""
    doc = (ROOT / "docs" / "design" / "ROLES-AND-SSH.md").read_text(encoding="utf-8")
    start = doc.index("## Appendix A")
    end = doc.index("## Appendix B")
    out = {}
    for line in doc[start:end].splitlines():
        if not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        m = re.match(r"`([^`]+)`", cells[0])
        if not m:
            continue
        path = m.group(1)
        perm = re.search(r"`([a-z]+\.[a-z_]+|run)`", cells[2])
        dash = cells[2].startswith("—")
        for meth in re.split(r"[/, ]+", cells[1]):
            meth = meth.strip().upper()
            if meth in ("GET", "POST", "PATCH", "DELETE", "PUT", "WS", "ANY"):
                out[(meth, path)] = (dash, perm.group(1) if perm else None)
    return out


def main():
    routes = [r for rt in ROUTERS.values() for r in rt.routes if getattr(r, "path", None)]
    check("routerul chiar are rute (testul nu e gol)", len(routes) > 50, str(len(routes)))

    # Garda de completitudine: un router nou montat în main.py şi uitat aici → testul CADE.
    main_src = ROOT / "gateway" / "app" / "main.py"
    mounted = set(re.findall(r"app\.include_router\((\w+)\.router\)", main_src.read_text()))
    check("fiecare router montat în main.py e acoperit de test",
          mounted == set(ROUTERS), f"montate: {sorted(mounted)} | acoperite: {sorted(ROUTERS)}")

    # 1. garda de runtime e pe TOATE routerele (plasa care acoperă şi un build patch-uit la cald)
    for name, rt in ROUTERS.items():
        has = any(getattr(d, "dependency", None) is authz.declared for d in rt.dependencies)
        check(f"routerul `{name}` are garda fail-closed `authz.declared`", has)

    # 2. fiecare rută: exact un perm(), sau PUBLIC / SELF cu motiv
    undeclared, multi, both = [], [], []
    for r in routes:
        kind, spec = authz.route_spec(r)
        label = "%s %s" % (",".join(_methods(r)), r.path)
        if kind == "none":
            undeclared.append(label)
        elif kind == "multi":
            multi.append(label)
        elif kind == "perm" and (r.path in authz.PUBLIC
                                 or any((m, r.path) in authz.SELF for m in _methods(r))):
            both.append(label)
    check("nicio rută fără permisiune declarată", not undeclared,
          "adaugă Depends(authz.perm(...)) sau o intrare în authz.PUBLIC/SELF cu motiv: "
          + ", ".join(sorted(undeclared)))
    check("nicio rută cu mai multe dependenţe perm()", not multi, ", ".join(sorted(multi)))
    check("nicio rută cu perm() ŞI în PUBLIC/SELF (ambiguu)", not both, ", ".join(sorted(both)))

    # 3. nicio rută nu mai foloseşte direct require_scope (tokenurile trec prin perm(tokens=…))
    legacy = []
    for r in routes:
        dep = getattr(r, "dependant", None)
        for d in getattr(dep, "dependencies", []) or []:
            q = getattr(d.call, "__qualname__", "")
            if q.startswith("require_scope"):
                legacy.append(r.path)
    check("nicio rută pe `security.require_scope` (înlocuit de perm(tokens=…))", not legacy,
          str(legacy))

    # 4. motive nevide + nicio intrare orfană în PUBLIC/SELF
    paths = {r.path for r in routes}
    pairs = {(m, r.path) for r in routes for m in _methods(r)}
    check("fiecare intrare PUBLIC are motiv", all(v.strip() for v in authz.PUBLIC.values()))
    check("fiecare intrare SELF are motiv", all(v.strip() for v in authz.SELF.values()))
    stale_p = sorted(p for p in authz.PUBLIC if p not in paths)
    check("nicio intrare PUBLIC orfană", not stale_p, str(stale_p))
    stale_s = sorted("%s %s" % k for k in authz.SELF if k not in pairs)
    check("nicio intrare SELF orfană", not stale_s, str(stale_s))

    # 5. localizatorii de host numesc parametri REALI ai rutei
    bad_loc = []
    for r in routes:
        kind, spec = authz.route_spec(r)
        if kind != "perm" or spec.host is None:
            continue
        params = set(re.findall(r"{(\w+)}", r.path))
        if spec.host.startswith("body:"):
            field = spec.host[5:]
            if field not in _body_fields(r):
                bad_loc.append("%s %s: %s" % (",".join(_methods(r)), r.path, spec.host))
        elif spec.host not in params:
            bad_loc.append("%s %s: %s" % (",".join(_methods(r)), r.path, spec.host))
    check("fiecare `host=` numeşte un parametru real (cale sau corp)", not bad_loc, str(bad_loc))

    # 6. permisiunile declarate există în catalog; tokenurile doar pe lista albă scurtă
    unknown, tok_routes = [], set()
    for r in routes:
        kind, spec = authz.route_spec(r)
        if kind == "perm":
            unknown += [p for p in spec.perm if p not in authz.PERMS]
            if spec.tokens:
                tok_routes |= {(m, r.path) for m in _methods(r)}
    check("toate permisiunile declarate sunt în catalog", not unknown, str(unknown))
    expected_tok = {("GET", "/api/status"), ("GET", "/api/hosts"), ("GET", "/api/sessions"),
                    ("POST", "/api/hosts/{host_id}/run")}
    check("tokenurile de automatizare: EXACT lista albă de dinainte (status/hosts/sessions/run)",
          tok_routes == expected_tok, str(sorted(tok_routes ^ expected_tok)))

    # 7. codul ↔ Anexa A din documentul de design
    docm = _doc_matrix()
    mism = []
    for r in routes:
        kind, spec = authz.route_spec(r)
        for m in _methods(r):
            want = docm.get((m, r.path), "MISSING")
            if want == "MISSING":
                mism.append("%s %s: lipseşte din Anexa A" % (m, r.path))
                continue
            dash, dperm = want
            if kind in ("public", "self"):
                good = dash               # fără permisiune în cod ⇔ `—` în document
            elif spec.list:
                good = dperm == spec.perm[0]      # listă: „— / perm" sau „perm", filtrată
            else:
                good = not dash and dperm == spec.perm[0]
            if not good:
                mism.append("%s %s: cod=%s doc=%s" % (
                    m, r.path, spec.perm[0] if kind == "perm" else kind, dperm or "—"))
    check("permisiunea fiecărei rute = cea din Anexa A (docs/design/ROLES-AND-SSH.md)",
          not mism, "\n      " + "\n      ".join(mism))

    # 8. Rutele publice care SCRIU sunt cele mai periculoase: fiecare e ori poarta de
    # autentificare însăşi, ori are credenţialul în cerere. Verificăm METODELE, nu numele.
    WRITE_OK = {"/api/setup", "/api/login", "/api/logout", "/install/{enroll_token}",
                "/api/webauthn/login/options", "/api/webauthn/login/verify",
                "/agent/uninstalled"}
    writers = set()
    for r in routes:
        if r.path not in authz.PUBLIC:
            continue
        if {"POST", "PUT", "PATCH", "DELETE"} & set(getattr(r, "methods", []) or []):
            writers.add(r.path)
    check("orice rută publică ce scrie e declarată ca atare", not (writers - WRITE_OK),
          "publice + scriu, nedeclarate: " + str(sorted(writers - WRITE_OK)))

    # 9. garda de runtime chiar refuză o rută nedeclarată (fail-closed, nu doar în CI)
    import asyncio
    from fastapi import APIRouter, FastAPI
    import httpx
    probe = APIRouter(dependencies=[__import__("fastapi").Depends(authz.declared)])

    @probe.get("/api/__undeclared_probe")
    async def _undeclared():          # noqa: ANN202
        return {"open": True}

    tapp = FastAPI()
    tapp.include_router(probe)

    async def _hit():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=tapp),
                                     base_url="http://t") as c:
            return await c.get("/api/__undeclared_probe")
    resp = asyncio.run(_hit())
    check("o rută NEDECLARATĂ răspunde 500 authz.undeclared (nu e deschisă)",
          resp.status_code == 500 and resp.headers.get("x-webterm-error") == "authz.undeclared",
          "%s %s" % (resp.status_code, resp.text[:120]))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
