"""Straturile de import ale gateway-ului: nimic nu importă înapoi modulul de rute.

De ce: până la 3.6.35, `accounts`, `ssomap` şi `syshealth` făceau `from . import api` ÎN
funcţii (ca să ocolească ciclul de import) şi apelau helperi privaţi de acolo
(`api._revoke_all_shares`, `api.forward_domain`…). Ciclul era ascuns, un refactor în api.py
rupea module care îl importau doar la rulare, iar agenţii nu aveau unde pune un helper comun.
Helperii au coborât în `shares.py` şi `fwddomain.py`.

Regulile, verificate static (AST), fără să importăm aplicaţia:
  1. doar `main.py` importă `api` (oriunde în fişier, inclusiv în funcţii);
  2. importurile locale (în funcţii) între module din `app` sunt EXACT lista de mai jos, fiecare
     cu motiv. Un import local nou e de obicei un ciclu ascuns: coboară codul comun într-un modul
     de jos în loc să adaugi o excepţie aici.
"""
import ast
import pathlib

APP = pathlib.Path(__file__).resolve().parent.parent / "gateway" / "app"

# (modul, modul importat local) → motiv
LOCAL_OK = {
    ("admin", "syshealth"): "CLI: syshealth e greu, se încarcă doar pentru subcomanda care îl foloseşte",
    ("backup_dest", "core"): "peek_host_key; backup_dest nu trage runtime-ul de sesiuni la import",
    ("core", "ssomap"): "purge_host anunţă o mapare SSO din .env care numea hostul (ssomap → shares → core)",
    ("db", "authz"): "connect() seed-uieşte rolurile predefinite; authz foloseşte db la import",
    ("alert_history", "authz"): "filtrarea pe permisiuni; authz → db → … → alert_history",
    ("email_alerts", "security"): "security importă email_alerts (alerte de login)",
    ("syshealth", "certmon"): "verificările rulează rar; modulele lor importă la rândul lor mult",
    ("syshealth", "cloudbackup"): "idem",
    ("syshealth", "core"): "idem",
    ("syshealth", "email_alerts"): "idem",
    ("syshealth", "oidc"): "idem",
    ("syshealth", "signing"): "idem",
    ("syshealth", "updatecheck"): "idem",
}

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def imports(path):
    """[(modul importat, e local?)] pentru importurile relative din pachetul app."""
    mods = {p.stem for p in APP.glob("*.py")}
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []

    def visit(node, local):
        for child in ast.iter_child_nodes(node):
            inner = local or isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            if isinstance(child, ast.ImportFrom) and child.level == 1:
                names = [child.module.split(".")[0]] if child.module else [a.name for a in child.names]
                out.extend((n, local) for n in names if n in mods)
            elif isinstance(child, ast.ImportFrom) and (child.module or "").startswith("app."):
                out.append((child.module.split(".")[1], local))
            visit(child, inner)

    visit(tree, False)
    return out


def main():
    files = sorted(APP.glob("*.py"))
    check("pachetul app are module (testul nu e gol)", len(files) > 20, str(len(files)))

    back = sorted({f.stem for f in files for m, _ in imports(f) if m == "api" and f.stem != "main"})
    check("doar main.py importă api (rutele sunt vârful, nu o bibliotecă)", not back,
          "importă api: %s — mută helperul într-un modul de jos (vezi shares.py, fwddomain.py)" % back)

    # Rutele mutate din api.py în module proprii (hosts_api.py…) sunt tot vârful: doar main.py
    # le montează. Un modul de rute care importă alt modul de rute e începutul ciclului de dinainte.
    route_mods = {"hosts_api", "forward_api", "backup_api", "docker_api", "services_api",
                  "deploy_keys_api", "files_api", "share_api"}
    check("modulele de rute mutate din api.py chiar există", all((APP / (m + ".py")).exists() for m in route_mods),
          str(route_mods))
    back = sorted({(f.stem, m) for f in files for m, _ in imports(f) if m in route_mods and f.stem != "main"})
    check("doar main.py importă modulele de rute (*_api)", not back,
          "%s — helperul comun coboară în hostmodel.py (sau alt modul de jos)" % back)

    local = {(f.stem, m) for f in files for m, is_local in imports(f) if is_local and m != f.stem}
    new = sorted(local - set(LOCAL_OK))
    check("niciun import local nou între module (ar ascunde un ciclu)", not new,
          "%s — coboară codul comun; o excepţie reală intră în LOCAL_OK cu motiv" % new)
    stale = sorted(set(LOCAL_OK) - local)
    check("LOCAL_OK nu are intrări moarte", not stale, str(stale))
    check("fiecare excepţie are motiv", all(v.strip() for v in LOCAL_OK.values()))

    print(f"\n{ok}/{total} passed")
    raise SystemExit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
