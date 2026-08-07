"""Fiecare rută `/api/*` are autentificare — prin enumerare, nu prin listă scrisă de mână.

Autentificarea e opt-in per rută (`user=Depends(security.require_user)`), adică proiectare
FAIL-OPEN: uiți `Depends`, ruta devine publică și nimic nu se plânge. Acoperirea existentă
era o listă albă de 14 rute verificate manual, din 111 — restul de 97 nu erau atinse de
niciun test. O rută nouă fără autentificare trecea verde.

Testul enumeră `router.routes` și cere ca fiecare să aibă ori o dependență de autentificare,
ori o intrare în `PUBLIC` de mai jos, cu motiv. Adăugarea unei rute publice devine astfel o
decizie explicită, scrisă, nu o omisiune.
"""
import inspect
import os
import pathlib
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gateway"))

from app import api, webauthn_api  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


# Rute publice DECLARATE, fiecare cu motivul ei. O intrare nouă aici trebuie să vină cu o
# frază — diferența dintre „știm de ea" și „ne-a scăpat".
PUBLIC = {
    "/healthz": "sonda de liveness a containerului; nu atinge date",
    "/api/state": "spune doar dacă instalarea are cont — ecranul de setup depinde de el",
    "/api/setup": "creează PRIMUL cont; se auto-dezactivează după (revendicare atomică)",
    "/api/login": "poarta însăși",
    "/api/logout": "trebuie să meargă și cu o sesiune deja invalidă",
    "/api/shared/{token}": "tokenul de share ESTE credențialul (hash-uit, cu expirare)",
    "/ws/shared/{token}": "idem, pe WebSocket",
    "/ws/sessions/{sid}": "autentifică în handler cu `require_user_ws` (Depends nu merge pe WS)",
    "/agent/ws": "agentul se autentifică cu tokenul lui de host, în handshake",
    "/agent/ptyd.py": "sursa agentului: publică prin construcție, verificată prin semnătură",
    "/agent/shell-integration.sh": "idem; integritatea se verifică prin sha256, nu prin auth",
    "/install/{enroll_token}": "tokenul de enroll E credențialul; expiră în 24h, single-use",
    "/__wtfwd/auth": "handshake-ul de forward; validează cookie-ul de sesiune în corp",
    "/api/webauthn/login/options": "ceremonia de login cu passkey — ÎNAINTE de a avea sesiune",
    "/api/webauthn/login/verify": "idem; verifică asserţiunea şi ABIA apoi deschide sesiunea",
}


# TOATE routerele montate în `main.py`, nu doar `api`. Prima versiune a testului enumera
# doar `api.router` şi rata complet `webauthn_api.router` — adică exact suprafaţa care
# manevrează passkey-urile şi step-up-ul 2FA, unde costul unei omisiuni e cel mai mare.
# Un test care acoperă jumătate din suprafaţă e mai rău decât niciunul: dă senzaţia de plasă.
ROUTERS = {"api": api.router, "webauthn_api": webauthn_api.router}


def main():
    routes = [r for rt in ROUTERS.values() for r in rt.routes if getattr(r, "path", None)]
    check("routerul chiar are rute (testul nu e gol)", len(routes) > 50, str(len(routes)))

    # Garda de completitudine: dacă cineva montează un router nou în main.py şi uită să-l
    # adauge aici, testul trebuie să CADĂ — altfel se repetă exact omisiunea de mai sus.
    main_src = pathlib.Path(__file__).resolve().parent.parent / "gateway" / "app" / "main.py"
    mounted = set(re.findall(r"app\.include_router\((\w+)\.router\)", main_src.read_text()))
    check("fiecare router montat în main.py e acoperit de test",
          mounted == set(ROUTERS), f"montate: {sorted(mounted)} | acoperite: {sorted(ROUTERS)}")

    unguarded = []
    for r in routes:
        ep = getattr(r, "endpoint", None)
        if ep is None:
            continue
        # Două forme, amândouă corecte în FastAPI:
        #   def f(user=Depends(security.require_user))        — în semnătură
        #   @router.get(..., dependencies=[Depends(...)])     — pe rută
        # Testul se uita doar la prima, deci respingea forma idiomatică de decorator. Un
        # contribuitor care scrie corect primea eroare, iar „reparaţia" la îndemână era să-şi
        # adauge ruta în PUBLIC — adică s-o declare publică pe una păzită. Un fals-pozitiv
        # care împinge spre defectul real e mai rău decât o omisiune.
        guarded = "require_user" in str(inspect.signature(ep)) or \
                  "require_scope" in str(inspect.signature(ep))
        for dep in getattr(r, "dependencies", []) or []:
            call = getattr(dep, "dependency", None)
            if call is not None and getattr(call, "__name__", "") in (
                    "require_user", "require_scope", "require_user_ws"):
                guarded = True
            # `require_scope("read")` întoarce o closure — îi verificăm originea
            if call is not None and getattr(call, "__qualname__", "").startswith("require_scope"):
                guarded = True
        if guarded:
            continue
        if r.path in PUBLIC:
            continue
        methods = ",".join(sorted(getattr(r, "methods", []) or [])) or "WS"
        unguarded.append(f"{methods} {r.path}")

    check("nicio rută nepăzită și nedeclarată", not unguarded,
          "adaugă Depends(require_user/require_scope) sau o intrare în PUBLIC cu motiv: "
          + ", ".join(sorted(unguarded)))

    # Invers: o intrare în PUBLIC care nu mai corespunde niciunei rute e o listă albă care
    # se lărgește tăcut — exact clasa pe care `check_exists` din run-tests.sh o păzește.
    paths = {r.path for r in routes}
    stale = sorted(p for p in PUBLIC if p not in paths)
    check("nicio intrare PUBLIC orfană", not stale, str(stale))

    # Rutele publice care SCRIU (nu doar citesc) sunt cele mai periculoase: fiecare trebuie
    # să fie ori poarta de autentificare însăși, ori să aibă credențialul în URL.
    # Verificăm METODELE, nu numele căii.
    # Ceremonia WebAuthn de LOGIN e POST prin natura ei (trimite provocarea şi asserţiunea),
    # şi trebuie să fie publică — se petrece înainte de a exista o sesiune. E poarta însăşi,
    # ca `/api/login`.
    WRITE_OK = {"/api/setup", "/api/login", "/api/logout", "/install/{enroll_token}",
                "/api/webauthn/login/options", "/api/webauthn/login/verify"}
    writers = set()
    for r in routes:
        if r.path not in PUBLIC:
            continue
        if {"POST", "PUT", "PATCH", "DELETE"} & set(getattr(r, "methods", []) or []):
            writers.add(r.path)
    check("orice rută publică ce scrie e declarată ca atare", not (writers - WRITE_OK),
          "publice + scriu, nedeclarate: " + str(sorted(writers - WRITE_OK)))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
