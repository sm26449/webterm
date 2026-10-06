"""Ţintele snippet-urilor (3.5.4): comenzile salvate din consola de flotă devin snippet-uri.

Înainte, „saved commands" de flotă trăiau doar în localStorage (`wt-fleet-saved`): pe alt
dispozitiv nu existau. Acum un saved command de flotă ESTE un snippet, cu etichete de host
opţionale (`targets: {"tags": [...]}`) care preselectează hosturile la alegere.

Ce fixează testul:
  1. create / update / list cu ţinte; etichetele normalizate EXACT ca la hosturi;
  2. plafonul de 20 de etichete → 400 cu cod (nu tăiere tăcută);
  3. forme greşite → 400 `snippet.badTargets` (nu 422 Pydantic fără cod);
  4. compatibilitate: rândurile vechi (coloana NULL) → `targets: null`; un PATCH fără
     `targets` (clienţii vechi) NU şterge ţintele; `targets: null` explicit le şterge;
  5. auth neschimbat: rutele de snippets rămân DOAR pe cookie (un token de automatizare nu
     le atinge).
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
from app import api, config, db, security  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def _err_keys():
    """Cheile `err.*` din catalogul englez — fiecare cod nou trebuie să aibă traducere."""
    path = os.path.join(os.path.dirname(__file__), "..", "frontend", "src", "lang", "en.ts")
    with open(path, encoding="utf-8") as f:
        return f.read()


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    en = _err_keys()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30, headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})

        async def get(sid):
            return next(s for s in (await c.get("/api/snippets")).json() if s["id"] == sid)

        # ── 1. rând vechi (inserat direct, fără coloana nouă) → targets null ──
        old_id = await db.execute("INSERT INTO snippets(title, body, created) VALUES(?,?,?)",
                                  "vechi", "uptime", 1.0)
        s = await get(old_id)
        check("rând vechi → targets null", "targets" in s and s["targets"] is None, repr(s))

        # ── 2. create fără targets (client vechi) ──
        r = await c.post("/api/snippets", json={"title": "df", "body": "df -h"})
        check("POST fără targets → 200", r.status_code == 200, r.text)
        plain = r.json()["id"]
        check("snippet fără ţinte → targets null", (await get(plain))["targets"] is None)

        # ── 3. create cu targets: normalizare ca la hosturi ──
        r = await c.post("/api/snippets", json={
            "title": "restart web", "body": "sudo systemctl restart {{svc}}",
            "targets": {"tags": ["Prod", " web ", "PROD", "a,b", "x" * 40]}})
        check("POST cu targets → 200", r.status_code == 200, r.text)
        sid = r.json()["id"]
        s = await get(sid)
        check("tag-uri normalizate (lowercase, dedup, virgulă separă, max 32 car.)",
              s["targets"] == {"tags": ["prod", "web", "a", "b", "x" * 32]}, repr(s["targets"]))
        check("aceeaşi normalizare ca la host (_norm_tags)",
              ",".join(s["targets"]["tags"]) == api._norm_tags("Prod web PROD a,b " + "x" * 40))

        # ── 4. targets {"tags": []} → stocat ca null ──
        r = await c.post("/api/snippets", json={"title": "gol", "body": "true", "targets": {"tags": []}})
        check("tags gol → targets null", (await get(r.json()["id"]))["targets"] is None)

        # ── 5. update: PATCH fără targets păstrează; cu targets înlocuieşte; null şterge ──
        r = await c.patch(f"/api/snippets/{sid}", json={"title": "restart web2", "body": "sudo systemctl restart nginx"})
        check("PATCH fără targets (client vechi) → 200", r.status_code == 200, r.text)
        s = await get(sid)
        check("PATCH fără targets NU şterge ţintele", s["targets"] == {"tags": ["prod", "web", "a", "b", "x" * 32]},
              repr(s["targets"]))
        check("PATCH a schimbat titlul + corpul", s["title"] == "restart web2" and s["body"].endswith("nginx"), repr(s))
        r = await c.patch(f"/api/snippets/{sid}", json={"title": "restart web2", "body": "x", "targets": {"tags": ["DB"]}})
        check("PATCH cu targets → înlocuieşte", r.status_code == 200 and (await get(sid))["targets"] == {"tags": ["db"]})
        r = await c.patch(f"/api/snippets/{sid}", json={"title": "restart web2", "body": "x", "targets": None})
        check("PATCH cu targets null → şterse", r.status_code == 200 and (await get(sid))["targets"] is None)

        # ── 6. plafonul de 20 ──
        twenty = ["t%d" % i for i in range(20)]
        r = await c.post("/api/snippets", json={"title": "20", "body": "echo", "targets": {"tags": twenty}})
        check("exact 20 de etichete → acceptat", r.status_code == 200, r.text)
        check("cele 20 stocate integral", len((await get(r.json()["id"]))["targets"]["tags"]) == 20)
        r = await c.post("/api/snippets", json={"title": "21", "body": "echo", "targets": {"tags": twenty + ["t20"]}})
        check("21 de etichete → 400", r.status_code == 400, r.text)
        check("cod snippet.tooManyTags", r.headers.get("x-webterm-error") == "snippet.tooManyTags",
              repr(r.headers.get("x-webterm-error")))
        # duplicatele nu se numără: 25 de intrări, 20 distincte după normalizare
        r = await c.post("/api/snippets", json={"title": "dup", "body": "echo",
                                                "targets": {"tags": twenty + ["T0", "t1", "T2 ", "t3", "t4"]}})
        check("duplicatele (după normalizare) nu intră în plafon", r.status_code == 200, r.text)
        r = await c.patch(f"/api/snippets/{plain}", json={"title": "df", "body": "df -h",
                                                          "targets": {"tags": twenty + ["extra"]}})
        check("PATCH cu 21 → 400 snippet.tooManyTags",
              r.status_code == 400 and r.headers.get("x-webterm-error") == "snippet.tooManyTags", r.text)
        check("PATCH refuzat nu a scris nimic", (await get(plain))["targets"] is None)

        # ── 7. forme invalide → 400 snippet.badTargets ──
        for bad in ("prod", ["prod"], {"tags": "prod"}, {"tags": [1, 2]}, {"hosts": [1]},
                    {"tags": ["a"], "extra": 1}, 5):
            r = await c.post("/api/snippets", json={"title": "bad", "body": "echo", "targets": bad})
            check("targets=%r → 400 snippet.badTargets" % (bad,),
                  r.status_code == 400 and r.headers.get("x-webterm-error") == "snippet.badTargets",
                  "%s %s" % (r.status_code, r.text))
        for code in ("snippet.badTargets", "snippet.tooManyTags", "snippet.required"):
            check("cheia err.%s există în en.ts" % code, ("'err.%s'" % code) in en)

        # ── 8. POST duplicat (titlu+corp) cu ţinte le adoptă, fără rând nou ──
        n_before = len((await c.get("/api/snippets")).json())
        r = await c.post("/api/snippets", json={"title": "df", "body": "df -h", "targets": {"tags": ["web"]}})
        check("POST duplicat → acelaşi id", r.status_code == 200 and r.json()["id"] == plain, r.text)
        check("duplicatul nu creează rând nou", len((await c.get("/api/snippets")).json()) == n_before)
        check("duplicatul cu ţinte le adoptă", (await get(plain))["targets"] == {"tags": ["web"]})
        r = await c.post("/api/snippets", json={"title": "df", "body": "df -h"})
        check("POST duplicat fără ţinte NU le şterge", (await get(plain))["targets"] == {"tags": ["web"]})

        # ── 9. JSON corupt în DB nu rupe lista ──
        await db.execute("UPDATE snippets SET targets=? WHERE id=?", "{nu-e-json", old_id)
        r = await c.get("/api/snippets")
        check("JSON corupt → lista tot 200", r.status_code == 200, r.text)
        check("JSON corupt → targets null", next(x for x in r.json() if x["id"] == old_id)["targets"] is None)

        # ── 10. PATCH cu titlu gol → 400 snippet.required ──
        r = await c.patch(f"/api/snippets/{plain}", json={"title": "  ", "body": "x"})
        check("PATCH titlu gol → 400 snippet.required",
              r.status_code == 400 and r.headers.get("x-webterm-error") == "snippet.required", r.text)

        r = await c.post("/api/tokens", json={"name": "auto", "scopes": ["read", "run"],
                                              "days": 30, "current_password": PW})
        tok = r.json().get("token", "")
        check("token de automatizare creat (read+run)", tok.startswith(security.TOKEN_PREFIX), r.text)

    # ── 11. auth neschimbat: snippets rămân DOAR pe cookie — nici anonim, nici cu un token
    #        de automatizare (chiar cu toate scope-urile) ──
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30, headers=_ORIGIN) as anon:
        r = await anon.get("/api/snippets")
        check("GET /api/snippets fără cookie → 401", r.status_code == 401, r.status_code)
    H = {**_ORIGIN, "authorization": "Bearer " + tok}
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30, headers=H) as t:
        for method, path, body in (("GET", "/api/snippets", None),
                                   ("POST", "/api/snippets", {"title": "x", "body": "y"}),
                                   ("PATCH", "/api/snippets/%d" % plain, {"title": "x", "body": "y"}),
                                   ("DELETE", "/api/snippets/%d" % plain, None)):
            r = await t.request(method, path, json=body)
            check("token: %s %s → 401" % (method, path), r.status_code == 401, r.status_code)

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
