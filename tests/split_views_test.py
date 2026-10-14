"""Split-views — layout-uri denumite de 2-4 sesiuni, per user, sincronizate server-side.

Un split-view NU ţine niciun secret: e metadată de layout care referă sesiuni gated
independent la attach. Deci CRUD = doar require_user, fără step-up. Ce verificăm aici:
  * 2-4 sesiuni DISTINCTE, existente (badCount / dupPane / badPane / noName);
  * izolare per user (nu vezi layout-urile altui cont);
  * reconciliere: GET NU mai scrie (3.6.12) — o sesiune ştearsă e scoasă din panouri de
    core.prune_split_views (reaper + ştergerea sesiunii/hostului); sub 2 → layout-ul dispare;
  * ratio clamp; PATCH parţial (rename / ratio / broadcast fără să retrimiţi panourile);
  * 3.6.12: forma (`layout`) + dimensiunile (`sizes`): enum, potrivire cu numărul de panouri,
    număr de fracţii, clamp, sumă ≈ 1, compat `ratio`;
  * 3.6.12: un panou se pune doar cu `session.watch`/`session.open` (nu `recording.view` singur);
    un panou pe care contul nu-l mai poate vedea (rol / 2FA fără step-up) e ASCUNS, nu şters, iar
    forma nu se poate rescrie cât e ascuns (409 splitview.hiddenPanes);
  * plafon per cont (splitview.tooMany) + clamp pe `position`;
  * review 3.6.12: plafonul ţine sub POST-uri concurente (INSERT…SELECT…WHERE COUNT<50) şi
    prune-ul nu pierde un PATCH concurent (compare-and-swap pe `panes`, şi la UPDATE şi la DELETE).
"""
import asyncio
import json
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, authz, config, core, db, security  # noqa: E402

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


async def _mksession(sid, host_id):
    await db.execute("INSERT INTO sessions(id, host_id, state, created) VALUES(?,?,?,?)",
                     sid, host_id, "live", time.time())


def _client(**kw):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", timeout=30,
                             headers=_ORIGIN, **kw)


async def _user_client(email, bindings):
    uid = await db.execute("INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
                           email, security.hash_password(PW), time.time())
    for rid, kind, value in bindings:
        await db.execute(
            "INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source, created)"
            " VALUES(?,?,?,?,'manual',?)", uid, rid, kind, str(value), time.time())
    authz.bump_epoch()
    tok = await security.create_web_session(uid, "split-test", False)
    return uid, _client(cookies={security.COOKIE_NAME: tok})


def _near(a, b, eps=1e-3):
    return len(a) == len(b) and all(abs(x - y) < eps for x, y in zip(a, b))


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    async with _client() as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
        me = await db.fetchone("SELECT id FROM users WHERE email=?", "a@b.co")
        uid = me["id"]
        hid = (await c.post("/api/hosts", json={"name": "srv"})).json()["id"]
        for s in ("s1", "s2", "s3", "s4"):
            await _mksession(s, hid)

        def hdr(r):
            return r.headers.get("X-WebTerm-Error")

        # ── validare la creare ────────────────────────────────────────────────
        r = await c.post("/api/split-views", json={"name": "", "panes": ["s1", "s2"]})
        check("nume gol → 400 splitview.noName", r.status_code == 400 and hdr(r) == "splitview.noName", r.text)
        r = await c.post("/api/split-views", json={"name": "x", "panes": ["s1"]})
        check("1 sesiune → 400 splitview.badCount", r.status_code == 400 and hdr(r) == "splitview.badCount", r.text)
        r = await c.post("/api/split-views", json={"name": "x", "panes": ["s1", "s2", "s3", "s1", "s2"]})
        check("5 sesiuni → 400 splitview.badCount", r.status_code == 400 and hdr(r) == "splitview.badCount", r.text)
        r = await c.post("/api/split-views", json={"name": "x", "panes": ["s1", "s1"]})
        check("aceeaşi sesiune de două ori → 400 splitview.dupPane",
              r.status_code == 400 and hdr(r) == "splitview.dupPane", r.text)
        r = await c.post("/api/split-views", json={"name": "x", "panes": ["s1", "nope"]})
        check("sesiune inexistentă → 400 splitview.badPane",
              r.status_code == 400 and hdr(r) == "splitview.badPane", r.text)

        # ── creare validă ─────────────────────────────────────────────────────
        r = await c.post("/api/split-views",
                         json={"name": "prod-debug", "panes": ["s1", "s2"], "ratio": 0.6, "broadcast": True})
        check("creare validă → 200", r.status_code == 200, r.text)
        sv = r.json()
        check("întoarce id/name/panes/ratio/broadcast",
              sv["name"] == "prod-debug" and sv["panes"] == ["s1", "s2"]
              and abs(sv["ratio"] - 0.6) < 1e-9 and sv["broadcast"] is True, str(sv))
        check("2 panouri → layout cols2, sizes din ratio [0.6, 0.4], hidden 0",
              sv["layout"] == "cols2" and _near(sv["sizes"], [0.6, 0.4]) and sv["hidden"] == 0, str(sv))
        sv_id = sv["id"]

        r = await c.post("/api/split-views", json={"name": "y", "panes": ["s1", "s2"], "ratio": 9.9})
        check("ratio în afara limitelor → clamp la 0.85", abs(r.json()["ratio"] - 0.85) < 1e-9, r.text)
        sv2_id = r.json()["id"]

        # ── listare ───────────────────────────────────────────────────────────
        lst = (await c.get("/api/split-views")).json()["split_views"]
        check("GET listează ambele", {x["id"] for x in lst} == {sv_id, sv2_id}, str(lst))

        # ── PATCH parţial ─────────────────────────────────────────────────────
        r = await c.patch(f"/api/split-views/{sv_id}", json={"name": "renamed"})
        check("PATCH doar name → schimbă doar numele",
              r.json()["name"] == "renamed" and r.json()["panes"] == ["s1", "s2"], r.text)
        r = await c.patch(f"/api/split-views/{sv_id}", json={"ratio": 0.3, "broadcast": False})
        check("PATCH ratio+broadcast",
              abs(r.json()["ratio"] - 0.3) < 1e-9 and r.json()["broadcast"] is False, r.text)
        check("PATCH ratio (client vechi) → sizes [0.3, 0.7]", _near(r.json()["sizes"], [0.3, 0.7]), r.text)
        r = await c.patch(f"/api/split-views/{sv_id}", json={"panes": ["s2", "s3"]})
        check("PATCH panes → validat + salvat", r.json()["panes"] == ["s2", "s3"], r.text)
        r = await c.patch(f"/api/split-views/{sv_id}", json={"panes": ["s2", "s2"]})
        check("PATCH panes duplicat → 400 dupPane", r.status_code == 400 and hdr(r) == "splitview.dupPane", r.text)
        r = await c.patch("/api/split-views/999999", json={"name": "z"})
        check("PATCH pe id inexistent → 404", r.status_code == 404, str(r.status_code))

        # ── 3.6.12: forma + dimensiunile ──────────────────────────────────────
        r = await c.post("/api/split-views", json={"name": "three", "panes": ["s1", "s2", "s3"]})
        three = r.json()
        check("3 panouri fără layout → main-left, dimensiuni egale pe grupuri",
              r.status_code == 200 and three["layout"] == "main-left"
              and _near(three["sizes"], [0.5, 0.5, 0.5, 0.5]), r.text)
        t_id = three["id"]
        r = await c.post("/api/split-views", json={"name": "g", "panes": ["s1", "s2", "s3"], "layout": "grid"})
        check("layout grid cu 3 panouri → 400 splitview.badLayout",
              r.status_code == 400 and hdr(r) == "splitview.badLayout", r.text)
        r = await c.post("/api/split-views", json={"name": "g", "panes": ["s1", "s2"], "layout": "bogus"})
        check("layout necunoscut → 400 splitview.badLayout",
              r.status_code == 400 and hdr(r) == "splitview.badLayout", r.text)
        r = await c.patch(f"/api/split-views/{t_id}", json={"layout": "cols3"})
        check("PATCH layout cols3 → dimensiuni egale [⅓ ×3]",
              r.status_code == 200 and r.json()["layout"] == "cols3"
              and _near(r.json()["sizes"], [1 / 3] * 3), r.text)
        r = await c.patch(f"/api/split-views/{t_id}", json={"sizes": [0.5, 0.5]})
        check("sizes cu număr greşit → 400 splitview.badSizes",
              r.status_code == 400 and hdr(r) == "splitview.badSizes", r.text)
        r = await c.patch(f"/api/split-views/{t_id}", json={"sizes": [0.5, 0.5, 0.3]})
        check("sizes cu suma 1.3 → 400 splitview.badSizes",
              r.status_code == 400 and hdr(r) == "splitview.badSizes", r.text)
        r = await c.patch(f"/api/split-views/{t_id}", json={"sizes": [0, 0.5, 0.5]})
        check("sizes cu 0 → 400 splitview.badSizes",
              r.status_code == 400 and hdr(r) == "splitview.badSizes", r.text)
        r = await c.patch(f"/api/split-views/{t_id}", content='{"sizes": [NaN, 0.5, 0.5]}',
                          headers={"content-type": "application/json"})
        check("sizes NaN → refuzat (400/422), nu salvat", r.status_code in (400, 422), r.text)
        r = await c.patch(f"/api/split-views/{t_id}", json={"sizes": [0.05, 0.05, 0.9]})
        sz = r.json().get("sizes", [])
        check("sizes sub minim → clamp ≥ 0.1 fiecare, suma 1",
              r.status_code == 200 and all(x >= 0.0999 for x in sz) and abs(sum(sz) - 1) < 1e-3, r.text)
        r = await c.patch(f"/api/split-views/{t_id}", json={"layout": "main-top", "sizes": [0.7, 0.3, 0.4, 0.6]})
        check("PATCH layout main-top + sizes pe 2 grupuri",
              r.json().get("layout") == "main-top" and _near(r.json()["sizes"], [0.7, 0.3, 0.4, 0.6]), r.text)
        r = await c.patch(f"/api/split-views/{t_id}", json={"layout": "main-top", "sizes": [0.7, 0.3, 0.9, 0.6]})
        check("al doilea grup cu suma 1.5 → 400 badSizes",
              r.status_code == 400 and hdr(r) == "splitview.badSizes", r.text)
        r = await c.patch(f"/api/split-views/{t_id}", json={"panes": ["s1", "s2", "s3", "s4"]})
        check("PATCH 4 panouri → layout grid implicit",
              r.json().get("layout") == "grid" and len(r.json()["sizes"]) == 4, r.text)
        r = await c.patch(f"/api/split-views/{t_id}", json={"panes": ["s4", "s1"]})
        check("PATCH înapoi la 2 panouri → cols2", r.json().get("layout") == "cols2", r.text)
        # rând dinainte de 3.6.12: fără layout/sizes, doar ratio
        await db.execute(
            "INSERT INTO split_views(user_id, name, panes, ratio, broadcast, position, created, updated)"
            " VALUES(?,?,?,?,?,?,?,?)", uid, "legacy", '["s1","s2"]', 0.3, 0, 0, time.time(), time.time())
        lst = (await c.get("/api/split-views")).json()["split_views"]
        leg = next((x for x in lst if x["name"] == "legacy"), None)
        check("rând vechi (doar ratio) → layout cols2, sizes [0.3, 0.7]",
              leg is not None and leg["layout"] == "cols2" and _near(leg["sizes"], [0.3, 0.7]), str(leg))

        # ── position: clamp ───────────────────────────────────────────────────
        r = await c.patch(f"/api/split-views/{sv2_id}", json={"position": 99999999})
        check("position uriaş → clamp la 1000", r.json().get("position") == 1000, r.text)
        r = await c.patch(f"/api/split-views/{sv2_id}", json={"position": -5})
        check("position negativ → 0", r.json().get("position") == 0, r.text)

        # ── izolare per user ──────────────────────────────────────────────────
        await db.execute(
            "INSERT INTO split_views(user_id, name, panes, ratio, broadcast, position, created, updated)"
            " VALUES(?,?,?,?,?,?,?,?)",
            uid + 777, "al-altcuiva", '["s1","s2"]', 0.5, 0, 0, time.time(), time.time())
        lst = (await c.get("/api/split-views")).json()["split_views"]
        check("nu văd layout-ul altui user", all(x["name"] != "al-altcuiva" for x in lst), str(lst))

        # ── reconciliere: GET nu scrie; prune în reaper / la ştergerea sesiunii ─
        # sv_id are acum panes [s2, s3]; s3 dispare → rămâne [s2] (<2)
        await db.execute("DELETE FROM sessions WHERE id=?", "s3")
        lst = (await c.get("/api/split-views")).json()["split_views"]
        check("layout cu <2 panouri vii → nelistat la GET", all(x["id"] != sv_id for x in lst), str(lst))
        check("… dar GET NU l-a şters (fără scrieri în GET)",
              await db.fetchone("SELECT 1 FROM split_views WHERE id=?", sv_id) is not None)
        await core.prune_split_views()
        check("prune (reaper) şterge layout-ul cu <2 panouri vii",
              await db.fetchone("SELECT 1 FROM split_views WHERE id=?", sv_id) is None)
        check("layout cu panouri intacte rămâne",
              await db.fetchone("SELECT 1 FROM split_views WHERE id=?", sv2_id) is not None)
        # 3 panouri, unul dispare → rămân 2, forma revine la implicit
        hx = "ab" * 16                    # DELETE /api/sessions cere un sid real (32 hex)
        await _mksession(hx, hid)
        r = await c.post("/api/split-views", json={"name": "trio", "panes": ["s1", "s2", hx], "layout": "cols3"})
        trio = r.json()["id"]
        await _mksession("s5", hid)
        await db.execute("UPDATE sessions SET state='closed' WHERE id=?", hx)
        r = await c.request("DELETE", f"/api/sessions/{hx}")
        check("DELETE /api/sessions/{sid} → 200", r.status_code == 200, r.text)
        row = await db.fetchone("SELECT panes, layout FROM split_views WHERE id=?", trio)
        check("ştergerea sesiunii curăţă imediat panoul (+ forma revine la implicit)",
              row is not None and json.loads(row["panes"]) == ["s1", "s2"] and (row["layout"] or "") == "",
              str(dict(row) if row else None))

        # ── plafon per cont ───────────────────────────────────────────────────
        have = (await db.fetchone("SELECT COUNT(*) AS n FROM split_views WHERE user_id=?", uid))["n"]
        for i in range(api.SPLIT_MAX_PER_USER - have):
            await db.execute(
                "INSERT INTO split_views(user_id, name, panes, ratio, broadcast, position, created, updated)"
                " VALUES(?,?,?,?,?,?,?,?)", uid, f"bulk{i}", '["s1","s2"]', 0.5, 0, 0, time.time(), time.time())
        r = await c.post("/api/split-views", json={"name": "one-too-many", "panes": ["s1", "s2"]})
        check("peste plafon (50) → 400 splitview.tooMany",
              r.status_code == 400 and hdr(r) == "splitview.tooMany", r.text)
        await db.execute("DELETE FROM split_views WHERE user_id=? AND name LIKE 'bulk%'", uid)
        # review 3.6.12 (L1): COUNT-ul şi INSERT-ul erau separate de await-uri (validarea panourilor)
        # → POST-uri concurente treceau toate de plafon. Acum plafonul e în INSERT (atomic).
        have = (await db.fetchone("SELECT COUNT(*) AS n FROM split_views WHERE user_id=?", uid))["n"]
        for i in range(api.SPLIT_MAX_PER_USER - have - 2):
            await db.execute(
                "INSERT INTO split_views(user_id, name, panes, ratio, broadcast, position, created, updated)"
                " VALUES(?,?,?,?,?,?,?,?)", uid, f"bulk{i}", '["s1","s2"]', 0.5, 0, 0, time.time(), time.time())
        rs = await asyncio.gather(*[c.post("/api/split-views", json={"name": f"race{i}", "panes": ["s1", "s2"]})
                                    for i in range(12)])
        n_after = (await db.fetchone("SELECT COUNT(*) AS n FROM split_views WHERE user_id=?", uid))["n"]
        check("12 POST-uri concurente cu 2 locuri libere → exact 2 create, plafonul (50) ţine",
              sum(r.status_code == 200 for r in rs) == 2 and n_after == api.SPLIT_MAX_PER_USER,
              f"created={sum(r.status_code == 200 for r in rs)} rows={n_after}")
        check("… restul → 400 splitview.tooMany",
              all(hdr(r) == "splitview.tooMany" for r in rs if r.status_code != 200),
              str([r.status_code for r in rs]))
        await db.execute("DELETE FROM split_views WHERE user_id=? AND (name LIKE 'bulk%' OR name LIKE 'race%')", uid)

        # review 3.6.12 (L2): prune citea panourile, apoi scria lista filtrată — un PATCH venit între
        # citire şi scriere era suprascris (lost update). Acum scrierea e compare-and-swap pe `panes`.
        r = await c.post("/api/split-views", json={"name": "cas", "panes": ["s1", "s2"]})
        cas = r.json()["id"]
        await db.execute("UPDATE split_views SET panes=? WHERE id=?", '["s1","s2","gone-sid"]', cas)
        orig_fetchall = db.fetchall

        slowed = []

        async def slow_fetchall(q, *a):
            res = await orig_fetchall(q, *a)
            if "FROM sessions WHERE id IN" in q and not slowed:   # doar citirea prune-ului
                slowed.append(1)
                await asyncio.sleep(0.2)          # fereastra dintre citire şi scriere, lărgită
            return res

        async def patch_meanwhile():
            await asyncio.sleep(0.05)
            return await c.patch(f"/api/split-views/{cas}", json={"panes": ["s5", "s1"], "sizes": [0.3, 0.7]})

        db.fetchall = slow_fetchall
        try:
            _, pr = await asyncio.gather(core.prune_split_views(), patch_meanwhile())
        finally:
            db.fetchall = orig_fetchall
        row = await db.fetchone("SELECT panes, sizes FROM split_views WHERE id=?", cas)
        check("prune concurent cu PATCH: PATCH-ul nu e pierdut (CAS pe panes)",
              pr.status_code == 200 and row is not None and json.loads(row["panes"]) == ["s5", "s1"]
              and _near(json.loads(row["sizes"] or "[]"), [0.3, 0.7]), f"{pr.status_code} {dict(row) if row else None}")
        await db.execute("UPDATE split_views SET panes=? WHERE id=?", '["s1","gone-sid"]', cas)

        async def patch_meanwhile2():
            await asyncio.sleep(0.05)
            return await c.patch(f"/api/split-views/{cas}", json={"panes": ["s5", "s2"]})

        slowed.clear()
        db.fetchall = slow_fetchall
        try:
            await asyncio.gather(core.prune_split_views(), patch_meanwhile2())
        finally:
            db.fetchall = orig_fetchall
        row = await db.fetchone("SELECT panes FROM split_views WHERE id=?", cas)
        check("prune concurent cu PATCH: layout-ul reparat de PATCH NU e şters (CAS şi pe DELETE)",
              row is not None and json.loads(row["panes"]) == ["s5", "s2"], str(dict(row) if row else None))
        await c.request("DELETE", f"/api/split-views/{cas}")

        # ── delete ────────────────────────────────────────────────────────────
        r = await c.request("DELETE", f"/api/split-views/{sv2_id}")
        check("DELETE → 200", r.status_code == 200, r.text)
        lst = (await c.get("/api/split-views")).json()["split_views"]
        check("după delete nu mai e listat", all(x["id"] != sv2_id for x in lst), str(lst))

        # ── 3.6.12: drepturi — session.watch/open, nu recording.view singur ──────
        hid2 = (await c.post("/api/hosts", json={"name": "other"})).json()["id"]
        await _mksession("o1", hid2)
        await _mksession("o2", hid2)
        rec_role = await db.execute(
            "INSERT INTO roles(key, name, description, perms, builtin, created, updated)"
            " VALUES(NULL,'ReplayOnly','',?,0,?,?)",
            json.dumps(["host.view", "recording.view"]), time.time(), time.time())
        viewer = await authz.role_id("viewer")
        _, rec = await _user_client("rec@x.co", [(rec_role, "all", "")])
        r = await rec.post("/api/split-views", json={"name": "r", "panes": ["s1", "s2"]})
        check("doar recording.view → 400 splitview.badPane (un panou e un terminal viu)",
              r.status_code == 400 and hdr(r) == "splitview.badPane", r.text)
        bid, bob = await _user_client("bob@x.co", [(viewer, "all", "")])
        r = await bob.post("/api/split-views", json={"name": "bob", "panes": ["s1", "o1", "o2"]})
        check("viewer (session.watch) → poate crea", r.status_code == 200, r.text)
        bob_sv = r.json()["id"]
        # dreptul pe `other` dispare: panourile de acolo devin ASCUNSE, nu şterse
        await db.execute("DELETE FROM role_bindings WHERE user_id=?", bid)
        await db.execute(
            "INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source, created)"
            " VALUES(?,?,'host',?,'manual',?)", bid, viewer, str(hid), time.time())
        authz.bump_epoch()
        lst = (await bob.get("/api/split-views")).json()["split_views"]
        mine = next((x for x in lst if x["id"] == bob_sv), None)
        check("pierderea dreptului → panourile ascunse (hidden=2), doar s1 vizibil",
              mine is not None and mine["panes"] == ["s1"] and mine["hidden"] == 2, str(lst))
        check("ID-urile panourilor ascunse NU apar în răspuns", "o1" not in json.dumps(lst), str(lst))
        row = await db.fetchone("SELECT panes FROM split_views WHERE id=?", bob_sv)
        check("… şi NU sunt şterse din DB", json.loads(row["panes"]) == ["s1", "o1", "o2"], row["panes"])
        r = await bob.patch(f"/api/split-views/{bob_sv}", json={"panes": ["s1", "s2"]})
        check("PATCH panes cu panouri ascunse → 409 splitview.hiddenPanes",
              r.status_code == 409 and hdr(r) == "splitview.hiddenPanes", r.text)
        r = await bob.patch(f"/api/split-views/{bob_sv}", json={"sizes": [0.5, 0.5, 0.5, 0.5]})
        check("PATCH sizes cu panouri ascunse → 409", r.status_code == 409, r.text)
        r = await bob.patch(f"/api/split-views/{bob_sv}", json={"name": "bob2"})
        check("PATCH name merge şi cu panouri ascunse", r.status_code == 200 and r.json()["name"] == "bob2", r.text)
        await core.prune_split_views()
        check("prune NU atinge panourile ascunse (sesiunile există)",
              json.loads((await db.fetchone("SELECT panes FROM split_views WHERE id=?", bob_sv))["panes"])
              == ["s1", "o1", "o2"])
        await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source, created)"
                         " VALUES(?,?,'host',?,'manual',?)", bid, viewer, str(hid2), time.time())
        authz.bump_epoch()
        lst = (await bob.get("/api/split-views")).json()["split_views"]
        mine = next((x for x in lst if x["id"] == bob_sv), None)
        check("dreptul revine → layout-ul revine întreg",
              mine is not None and mine["panes"] == ["s1", "o1", "o2"] and mine["hidden"] == 0, str(mine))
        r = await bob.patch(f"/api/split-views/{bob_sv}", json={"panes": ["o1", "s5"]})
        check("PATCH de alt user pe sesiuni pe care le vede → ok", r.status_code == 200, r.text)
        r = await c.patch(f"/api/split-views/{bob_sv}", json={"name": "hijack"})
        check("alt cont (chiar Owner) nu poate modifica layout-ul lui bob → 404", r.status_code == 404, r.text)

        # ── 3.6.12: host 2FA — fără fereastră de step-up panoul e ascuns ───────
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", hid2)
        await _mksession("o3", hid2)
        r = await c.post("/api/split-views", json={"name": "2fa", "panes": ["s1", "o3"]})
        check("sesiune pe host 2FA fără step-up → 400 badPane (ca /api/sessions)",
              r.status_code == 400 and hdr(r) == "splitview.badPane", r.text)
        security._stepup_windows[(uid, hid2)] = (time.time(), time.time() + 300)
        r = await c.post("/api/split-views", json={"name": "2fa", "panes": ["s1", "o3", "s2"]})
        check("cu fereastra de step-up deschisă → creat", r.status_code == 200 and r.json()["hidden"] == 0, r.text)
        tfa = r.json()["id"]
        security._stepup_windows.pop((uid, hid2), None)
        lst = (await c.get("/api/split-views")).json()["split_views"]
        mine = next((x for x in lst if x["id"] == tfa), None)
        check("fereastra închisă → panoul 2FA ascuns (hidden=1), restul vizibil",
              mine is not None and mine["panes"] == ["s1", "s2"] and mine["hidden"] == 1, str(mine))
        check("forma rămâne cea pentru 3 panouri (main-left), nu se rescrie",
              mine is not None and mine["layout"] == "main-left", str(mine))
        check("GET nu a deschis/glisat fereastra de step-up", (uid, hid2) not in security._stepup_windows)
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", hid2)

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
