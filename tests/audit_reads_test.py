"""Orice rută care citeşte CONŢINUT lasă urmă în jurnalul de audit.

Jurnalul înregistra doar mutaţiile. S-a reparat adăugând „citirile care scot date" — dar
reparaţia s-a făcut printr-un tipar pe FORMA căii (`/api/sessions/` + `/transcript`), nu pe
ce face ruta. Aşa a scăpat `/api/search`, care citeşte conţinutul transcripturilor a până la
500 de sesiuni deodată şi întoarce fragmente din jurul potrivirilor: cea mai puternică citire
din API şi singura fără nicio urmă. Endpoint-ul îşi recunoştea singur clasa în comentariu.

Un audit extern a găsit-o pentru că a citit codul; o listă albă întreţinută manual va rata
următoarea la fel. Testul de aici nu verifică o listă — enumerează rutele GET care CHEAMĂ
funcţiile ce citesc conţinut şi cere ca fiecare să treacă prin `audit.audited_read`. Ruta nouă
care va citi transcripturi cade aici, nu într-un audit de peste un an.

Partea a doua e dovada prin execuţie: o căutare reală trebuie să apară în `/api/audit`,
cu interogarea în ea — „a rulat o căutare" nu răspunde la „ce a scos".
"""
import ast
import asyncio
import os
import pathlib
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, audit, config, db, security  # noqa: E402
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"

# Funcţiile din `core` care scot CONŢINUT (nu metadate). O rută care le cheamă exfiltrează,
# oricum ar arăta calea ei.
CONTENT_READERS = {"transcript_text", "search_transcripts", "read_file", "preview_file"}


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def _concrete(path: str) -> str:
    """`/api/sessions/{sid}/transcript` → o cale reală, cum o vede middleware-ul."""
    out, depth = [], 0
    for ch in path:
        if ch == "{":
            depth += 1
            continue
        if ch == "}":
            depth -= 1
            out.append("1")
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def static_gate():
    src = pathlib.Path(__file__).resolve().parent.parent / "gateway" / "app" / "api.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    readers = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        paths = []
        for dec in node.decorator_list:
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "get" and dec.args
                    and isinstance(dec.args[0], ast.Constant)):
                paths.append(dec.args[0].value)
        if not paths:
            continue
        # Atribute, nu apeluri: cititoarele de conţinut sunt blocante, deci ajung în cod ca
        # ARGUMENT (`asyncio.to_thread(core.transcript_text, …)`,
        # `run_in_executor(None, core.search_transcripts, …)`), nu ca `core.x(...)`.
        # Prima versiune căuta doar `Call.func` şi găsea zero rute — garda „testul nu e gol"
        # a prins-o. Un test care caută tiparul greşit e o poartă care raportează verde.
        refs = {a.attr for a in ast.walk(node) if isinstance(a, ast.Attribute)}
        if refs & CONTENT_READERS:
            readers.extend(paths)

    check("testul chiar găseşte rute care citesc conţinut (nu e gol)",
          len(readers) >= 2, str(readers))
    missed = [p for p in readers if not audit.audited_read(_concrete(p))]
    check("fiecare GET care citeşte conţinut e auditat", not missed,
          "neauditate: " + str(missed) + " — adaugă-le în audit._AUDITED_PATHS")

    # Invers: o intrare în `_AUDITED_PATHS` care nu mai corespunde niciunei rute e o listă
    # care se lărgeşte tăcut, exact ca `PUBLIC` din route_auth_test.
    all_paths = {r.path for r in api.router.routes if getattr(r, "path", None)}
    stale = [p for p in audit._AUDITED_PATHS if p not in all_paths]
    check("nicio cale auditată orfană", not stale, str(stale))


async def live_proof():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
        needle = "AKIA_FAKE_EXFIL_9911"
        r = await c.get("/api/search", params={"q": needle})
        check("căutarea răspunde", r.status_code == 200, str(r.status_code))

        entries = (await c.get("/api/audit?limit=50")).json()["entries"]
        paths = [e.get("path", "") for e in entries]
        check("căutarea lasă urmă în jurnalul de audit",
              any(p == "/api/search" for p in paths), str(paths[:6]))
        row = next((e for e in entries if e.get("path") == "/api/search"), {})
        check("jurnalul reţine CE s-a căutat, nu doar că s-a căutat",
              needle in (row.get("detail") or ""), str(row.get("detail")))

        # o enumerare simplă NU trebuie să facă zgomot la fiecare refresh
        before = len((await c.get("/api/audit?limit=100")).json()["entries"])
        await c.get("/api/hosts")
        after = len((await c.get("/api/audit?limit=100")).json()["entries"])
        check("listarea hosturilor rămâne neauditată (altfel jurnalul devine zgomot)",
              after == before, f"{before} → {after}")
    await db.close()


def main():
    static_gate()
    asyncio.run(live_proof())
    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
