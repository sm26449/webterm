"""Verificarea „există versiune nouă?" — pregătită pentru repo PUBLIC.

Invariantul principal: pe repo public trebuie să meargă FĂRĂ niciun secret. Tokenul rămâne
opțional (doar cât repo-ul e privat) tocmai ca aplicaţia să nu ajungă să ţină credenţiale
GitHub — cine ajunge la gateway ar ajunge şi la ele.

Al doilea invariant, mai puţin evident: neautentificat, GitHub dă 60 de cereri/oră pe IP, iar
panoul de Status face poll des. Deci şi EŞECURILE trebuie cache-uite — altfel o singură eroare
se transformă în rate-limit şi verificarea rămâne moartă.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, security, updatecheck  # noqa: E402
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"
# valoarea LIVRATĂ, prinsă înainte ca vreun test s-o modifice
DEFAULT_UPDATE_COMMAND = config.UPDATE_COMMAND


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeResp:
    """Răspuns minimal de urlopen (context manager cu .read())."""
    def __init__(self, payload):
        self._p = payload.encode()

    def read(self):
        return self._p

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    cur = config.GATEWAY_VERSION
    maj, minor, patch = (int(x) for x in cur.split("."))
    newer = f"v{maj}.{minor}.{patch + 1}"
    older = f"v{maj}.{minor}.{max(patch - 1, 0)}"

    real_fetch = updatecheck._fetch_latest_tag

    # ── 1. compararea versiunilor ──────────────────────────────────────────
    calls = []

    def fake_fetch(tag):
        def _f():
            calls.append(tag)
            return tag
        return _f

    updatecheck.reset_cache()
    updatecheck._fetch_latest_tag = fake_fetch(newer)
    r = await updatecheck.check()
    check("fără token, verificarea E activă (repo public)", r["enabled"] is True, str(r))
    check("tag mai nou → update disponibil", r.get("update_available") is True, str(r))
    check("versiunea propusă e raportată", r.get("latest") == newer, str(r))

    updatecheck.reset_cache()
    updatecheck._fetch_latest_tag = fake_fetch(older)
    r = await updatecheck.check()
    check("tag mai vechi → fără update", r.get("update_available") is False, str(r))

    updatecheck.reset_cache()
    updatecheck._fetch_latest_tag = fake_fetch("v" + cur)
    r = await updatecheck.check()
    check("acelaşi tag → fără update", r.get("update_available") is False, str(r))

    # ── 2. ce e un tag valid ───────────────────────────────────────────────
    check("semver parsat", updatecheck._parse("v1.2.3") == (1, 2, 3))
    check("fără prefixul v merge la fel", updatecheck._parse("1.2.3") == (1, 2, 3))
    check("tag incomplet ignorat", updatecheck._parse("v1.2") is None)
    check("tag străin ignorat (agent-v3)", updatecheck._parse("agent-v3") is None)
    check("pre-release NU e propus ca update", updatecheck._parse("v1.2.3-rc1") is None)
    check("gunoi ignorat", updatecheck._parse("") is None and updatecheck._parse("latest") is None)

    # ── 3. selecţia din lista GitHub: cea mai mare, nu prima ───────────────
    orig_urlopen = updatecheck.urllib.request.urlopen
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["headers"] = dict(req.headers)
        seen["url"] = req.full_url
        return FakeResp('[{"name": "v1.0.9"}, {"name": "v1.0.30"}, {"name": "nu-e-tag"},'
                        ' {"name": "v1.0.10"}]')

    updatecheck.urllib.request.urlopen = fake_urlopen
    updatecheck._fetch_latest_tag = real_fetch      # secţiunea asta testează codul REAL
    try:
        check("alege cel mai mare tag, nu ordinea din API",
              updatecheck._fetch_latest_tag() == "v1.0.30")
        # numele header-elor sunt normalizate de urllib („Authorization" → „Authorization")
        hdrs = {k.lower() for k in seen["headers"]}
        check("FĂRĂ token, cererea nu trimite Authorization (repo public)",
              "authorization" not in hdrs, str(hdrs))
        config.UPDATE_CHECK_TOKEN = "ghp_test"
        updatecheck._fetch_latest_tag()
        hdrs = {k.lower() for k in seen["headers"]}
        check("CU token, cererea îl trimite (repo privat)", "authorization" in hdrs, str(hdrs))
        config.UPDATE_CHECK_TOKEN = ""
        check("întreabă repo-ul configurat", config.UPDATE_REPO in seen["url"], seen["url"])
    finally:
        updatecheck.urllib.request.urlopen = orig_urlopen

    # ── 4. cache: succes ŞI eşec ───────────────────────────────────────────
    updatecheck.reset_cache()
    calls.clear()
    updatecheck._fetch_latest_tag = fake_fetch(newer)
    await updatecheck.check()
    await updatecheck.check()
    check("succesul e cache-uit (o singură cerere la GitHub)", len(calls) == 1, str(calls))
    check("cadenţa e zilnică, nu orară", updatecheck._TTL_OK >= 86400, str(updatecheck._TTL_OK))
    await updatecheck.check(force=True)
    check("force ocoleşte cache-ul", len(calls) == 2, str(calls))

    def boom():
        calls.append("boom")
        raise OSError("GitHub inaccesibil")

    updatecheck.reset_cache()
    calls.clear()
    updatecheck._fetch_latest_tag = boom
    r1 = await updatecheck.check()
    r2 = await updatecheck.check()
    check("eroarea nu sparge răspunsul (are versiunea curentă)", r1["current"] == cur)
    check("eroarea e raportată, nu ascunsă ca „la zi”",
          "error" in r1 and "update_available" not in r1, str(r1))
    check("EŞECUL e cache-uit — altfel poll-ul consumă rate-limitul GitHub",
          len(calls) == 1 and r2 == r1, str(calls))
    check("TTL-ul pe eşec e mai scurt decât pe succes",
          updatecheck._TTL_ERR < updatecheck._TTL_OK)

    # ── 5. oprirea: nici măcar nu atinge reţeaua ───────────────────────────
    updatecheck.reset_cache()
    calls.clear()
    updatecheck._fetch_latest_tag = fake_fetch(newer)
    r = await updatecheck.check(enabled=False)
    check("oprită din Setări → nicio conexiune", calls == [] and r["enabled"] is False, str(r))
    config.UPDATE_CHECK = False
    updatecheck.reset_cache()
    r = await updatecheck.check(enabled=True)
    check("WEBTERM_UPDATE_CHECK=0 bate setarea din UI", calls == [] and r["enabled"] is False, str(r))
    config.UPDATE_CHECK = True

    # ── 6. API ─────────────────────────────────────────────────────────────
    updatecheck.reset_cache()
    updatecheck._fetch_latest_tag = fake_fetch(newer)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as anon:
        check("/api/version cere autentificare", (await anon.get("/api/version")).status_code == 401)

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
        r = (await c.get("/api/version")).json()
        check("implicit pornită", r["enabled"] is True and r["update_available"] is True, str(r))

        r = (await c.post("/api/version/check", json={"enabled": False})).json()
        check("comutatorul opreşte imediat (nu peste o oră)", r["enabled"] is False, str(r))
        r = (await c.get("/api/version")).json()
        check("starea oprită persistă în DB",
              r["enabled"] is False and "update_available" not in r, str(r))
        check("oprită, nu propunem nicio comandă", "update_command" not in r, str(r))
        check("versiunea curentă rămâne vizibilă şi oprită", r["current"] == cur, str(r))

        r = (await c.post("/api/version/check", json={"enabled": True})).json()
        check("repornirea răspunde pe loc cu rezultatul",
              r["enabled"] is True and r["update_available"] is True, str(r))

        # comanda de update: o AFIŞĂM, n-o executăm niciodată din aplicaţie
        r = (await c.get("/api/version")).json()
        check("comanda de update e dată gata de rulat",
              r.get("update_command", "").endswith(newer), str(r.get("update_command")))
        check("comanda nu e un endpoint care execută ceva",
              not any(p.startswith("/api/version/run") for p in
                      [route.path for route in app.routes if hasattr(route, "path")]))
        config.UPDATE_COMMAND = "make update TAG={version}"
        r = (await c.post("/api/version/refresh")).json()
        check("comanda e configurabilă (instalări în alt director)",
              r.get("update_command") == f"make update TAG={newer}", str(r.get("update_command")))
        # restaurăm valoarea REALĂ, capturată la import. Aici era rescrisă cu o copie
        # scrisă de mână a default-ului: din clipa în care default-ul s-a schimbat, testul
        # a continuat să repună vechea valoare — deci verificările de mai jos ar fi măsurat
        # ce scrie testul, nu ce livrează produsul.
        config.UPDATE_COMMAND = DEFAULT_UPDATE_COMMAND

        # „verifică acum": ocoleşte fereastra zilnică — altfel n-ai ce face când chiar aştepţi
        calls.clear()
        r = await c.post("/api/version/refresh")
        check("„verifică acum” chiar întreabă GitHub, nu dă cache-ul",
              r.status_code == 200 and len(calls) == 1, f"{r.status_code} {calls}")
        await c.post("/api/version/check", json={"enabled": False})
        r = await c.post("/api/version/refresh")
        check("„verifică acum” refuzat cât verificarea e oprită", r.status_code == 400, str(r.status_code))
        await c.post("/api/version/check", json={"enabled": True})

    updatecheck.urllib.request.urlopen = orig_urlopen

    # ── comanda pe care o SUGEREAZĂ notificarea ────────────────────────────
    # Sugera `deploy.sh`, care schimbă doar imaginea. Dar jumătate din sistem rulează pe
    # HOST — `backup.sh`, `restore.sh`, `rollback.sh`, compose-ul, `upgrade.sh` însuşi — iar
    # `/opt/webterm` nu e un checkout git, deci ele rămân la ce a pus instalatorul. README-ul
    # avertizează despre exact asta şi recomandă `upgrade.sh`; notificarea trimitea pe drumul
    # opus, şi fără backupul pe care `upgrade.sh` îl face înainte. Aici păzim acordul dintre
    # ce spune produsul şi ce spune documentaţia — singurul loc unde omul citeşte instrucţiunea.
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    check("comanda de update sugerată foloseşte upgrade.sh, nu deploy.sh",
          "upgrade.sh" in DEFAULT_UPDATE_COMMAND and "deploy.sh" not in DEFAULT_UPDATE_COMMAND,
          DEFAULT_UPDATE_COMMAND)
    check("comanda sugerată ţinteşte o versiune anume (nu un tag mişcător)",
          "{version}" in DEFAULT_UPDATE_COMMAND, DEFAULT_UPDATE_COMMAND)
    readme = (root / "README.md").read_text(encoding="utf-8")
    suggested = DEFAULT_UPDATE_COMMAND.replace(" {version}", "")
    check("README-ul recomandă exact comanda pe care o afişează UI-ul",
          suggested in readme, suggested)

    # Poarta verifica DOAR config.py şi README, deci reparaţia a rămas incompletă exact pe
    # suprafeţele instalării: ultima linie tipărită de `install.sh` şi exemplul din
    # `.env.prod.example` recomandau în continuare `deploy.sh` — upgrade fără backup şi fără
    # sincronizarea scripturilor de pe host. Semnalat de un audit extern.
    for rel in ("install.sh", ".env.prod.example"):
        txt = (root / rel).read_text(encoding="utf-8")
        bad = [ln.strip() for ln in txt.splitlines()
               if "deploy.sh" in ln and ("to upgrade" in ln.lower()
                                         or "UPDATE_COMMAND" in ln)]
        check("%s nu mai recomandă deploy.sh pentru upgrade" % rel, not bad, str(bad[:2]))

    print(f"\n{ok}/{total} passed")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        # fără asta, o excepţie lasă firul non-daemon al aiosqlite viu şi procesul
        # atârnă la shutdown în loc să pice cu traceback (l-am păţit scriind testul)
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
