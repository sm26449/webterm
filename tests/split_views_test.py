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
    prune-ul nu pierde un PATCH concurent (compare-and-swap pe `panes`, şi la UPDATE şi la DELETE);
  * 3.6.13: parserul OSC 133 al hub-ului (marcaje rupte între chunk-uri, C1, abandon, buffer
    mărginit) şi starea trimisă browserului (`init.osc133`, mesajul `osc133` după replay / resync,
    `synced` doar când replay-ul ajunge exact în punctul live şi conţine ultimul marcaj).
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

    osc133_parser_tests()
    await osc133_hub_tests()

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


# ---------------------------------------------------------------------------
# 3.6.13: starea OSC 133 a hub-ului (rezidualele guardrail-ului broadcast din 3.6.12)
# ---------------------------------------------------------------------------

class _FakeWs:
    def __init__(self):
        self.sent = []

    async def send_text(self, s):
        self.sent.append(json.loads(s))

    async def send_bytes(self, b):
        self.sent.append(bytes(b))

    async def close(self, code=1000):
        pass


def _scan(data, chunks=None):
    from app import osc133
    sc = osc133.Osc133Scanner()
    if chunks is None:
        sc.feed(data, 0)
    else:
        pos = 0
        for n in chunks:
            sc.feed(data[pos:pos + n], pos)
            pos += n
        if pos < len(data):
            sc.feed(data[pos:], pos)
    return sc


def osc133_parser_tests():
    import random
    from app import osc133
    print("-- 3.6.13: parserul OSC 133 al hub-ului")
    B = b"\x1b]133;A\x07$ \x1b]133;B\x07"           # un prompt complet
    s = B + b"rm -rf /srv"
    sc = _scan(s)
    check("A apoi B (BEL) → integrat, ultimul B, offsetul introducerii lui B",
          sc.integrated and sc.last == "B" and sc.last_start == s.index(b"\x1b]133;B"),
          (sc.integrated, sc.last, sc.last_start))
    sc = _scan(B + b"ls\x1b]133;E;ls\x07\x1b]133;C\x1b\\out")
    check("B → E;cmd → C (terminat cu ST) → C", sc.last == "C")
    sc = _scan(B + b"ls\x1b]133;C\x07")
    check("B → C → C", sc.last == "C")
    sc = _scan(B + "\u009d133;D;0\u009c".encode())
    check("C1 OSC / ST codate UTF-8 (\\xc2\\x9d … \\xc2\\x9c) → D", sc.last == "D", sc.last)
    sc = _scan(b"\x1b]133;B\x1bX")
    check("ESC termină OSC-ul (ca xterm) → B", sc.last == "B")
    # L1 (review 3.6.13): xterm porneşte o comandă doar dintr-un C care urmează unui prompt
    for stream, why in ((b"\x1b]133;C\x07", "fără niciun B"),
                        (B + b"\x1b]133;C\x07\x1b]133;D;0\x07\x1b]133;C\x07", "după D, fără B nou"),
                        (B + b"\x1b]133;E;\x07\x1b]133;C\x07", "după un E gol"),
                        (B + b"\x1b]133;A\x07\x1b]133;C\x07", "după A"),
                        (B + b"\x1b]133;C\x07", "imediat după B, fără nimic tastat"),
                        (b"\x1b]133;B\x1b\\\x1b]133;C\x1b\\", "imediat după B (ST), fără nimic tastat")):
        sc = _scan(stream)
        check("C %s (job în fundal care tipăreşte ESC]133;C) → necunoscut" % why, sc.last is None, sc.last)
    # rupt între chunk-uri, octet cu octet şi la întâmplare: aceeaşi stare, aceleaşi offseturi
    s = (b"\x1b[31mred\x1b[0m\r\n\x1b]133;D;0\x07\x1b]133;A\x07\xc2\xa0~$ \x1b]133;B\x07ls -la"
         + "\u009d133;C\u009c".encode() + b"total 0\r\n\x1b[?2004h" + b"\x1b]133;D;0\x1b\\\x1b]133;A\x07$ \x1b]133;B\x07")
    whole = _scan(s)
    ok_split = True
    for seed in range(200):
        rnd = random.Random(seed)
        cuts = []
        left = len(s)
        while left > 0:
            n = rnd.randint(1, 7)
            cuts.append(min(n, left))
            left -= n
        sc = _scan(s, cuts)
        if (sc.last, sc.last_start, sc.integrated, sc.alt) != (whole.last, whole.last_start, whole.integrated, whole.alt):
            ok_split = False
            break
    bytewise = _scan(s, [1] * len(s))
    check("marcaje rupte între chunk-uri (octet cu octet + 200 tăieturi aleatoare) → aceeaşi stare",
          ok_split and (bytewise.last, bytewise.last_start) == (whole.last, whole.last_start)
          and whole.last == "B" and whole.last_start == s.rindex(b"\x1b]133;B"),
          (whole.last, whole.last_start, bytewise.last, bytewise.last_start))
    sc = _scan(B + b"\x1b]0;titlu \xc2\xb0C\x07\x1b]7;file://h/tmp\x07\x1b]1330;C\x07\x1b]13a3;C\x07")
    check("titlu (cu °) / cwd / alt id / id ne-numeric ASCII NU sunt 133 → rămâne B", sc.last == "B", sc.last)
    sc = _scan(B + b"x\x1b]0133;C\x07")
    check("zerourile din faţa id-ului contează ca la xterm (0133 = 133)", sc.last == "C")
    sc = _scan(B + b"x\x1b]13\x003;\x01C\x07")
    check("C0-urile din payload sunt ignorate, ca la xterm (13\\x003;\\x01C = 133;C)", sc.last == "C", sc.last)
    sc = _scan(B + b"x\x1b\x00\x7f]133;C\x07")
    check("C0 / DEL între ESC şi ] nu întrerup secvenţa (xterm: rămâne în ESCAPE)", sc.last == "C")
    sc = _scan(b"\x1b ]133;B\x07")
    check("ESC <intermediar> ] nu e OSC", sc.last is None and not sc.integrated)
    sc = _scan(B + b"\x1b]133;C\xc2\x9d133;D;1\x07")
    check("U+009D în OSC porneşte unul nou → D", sc.last == "D")
    sc = _scan(B + b"x\x1b]133;C;x\xc2\xa0y\x07")
    check("un caracter U+00A0 în payload nu termină OSC-ul", sc.last == "C")
    # fail-closed: un 133 abandonat / nelămurit face ultimul marcaj necunoscut
    for tail, why in ((b"\x1b]133;C\x18", "abandonat cu CAN"),
                      (b"\x1b]133;C\xc2\x85", "abandonat cu un alt C1 (NEL)"),
                      (b"\x1b]133;E;rm -rf /\x07", "E"), (b"\x1b]133;Bx\x07", "fel necunoscut"),
                      (b"\x1b]133\x07", "fără ;"), (b"\x1b]133;\x07", "fel gol")):
        sc = _scan(B + tail)
        check("după B, un 133 %s → ultimul marcaj necunoscut, integrat rămâne" % why,
              sc.last is None and sc.integrated, (tail, sc.last))
    # L2 (review 3.6.13): decodorul UTF-8 al lui xterm ARUNCĂ octeţii invalizi, deci `ESC \x80 ]133;B`
    # E un marcaj pentru xterm. Nu ghicim: ultimul marcaj devine necunoscut.
    probes = (b"\x1b\x80]133;B\x07", b"\x1b\xe2]133;B\x07", b"\x1b]1\x803;B\x07",
              b"\x1b]1\xef\xbb\xbf33;B\x07", b"\x1b]" + b"0" * 61 + b"133;B\x07",
              b"\x1b]" + b"0" * 70 + b"133;B\x07", b"\x1b]133;" + b"B" * 70 + b"\x07")
    for p in probes:
        sc = _scan(B + b"\x1b]133;C\x07" + b"\x1b]133;D;0\x07" + p)
        check("probă %r → ultimul marcaj necunoscut (nu D-ul vechi)" % p[:24], sc.last is None, sc.last)
    sc = _scan(B + b"\x1b\x80]0;titlu\x07")
    check("OSC ne-133 cu ESC „murdar” → nu ştim dacă e 133 → necunoscut", sc.last is None)
    # bufferul e mărginit: un OSC uriaş nu umflă memoria; peste PAYLOAD_LIMIT → necunoscut
    sc = osc133.Osc133Scanner()
    sc.feed(B + b"\x1b]133;D;", 0)
    big = b"x" * (1 << 20)
    off = len(B) + 9
    for _ in range(11):
        sc.feed(big, off)
        off += len(big)
    bounded = len(sc._head) <= osc133.HEAD_MAX
    sc.feed(b"\x07", off)
    check("OSC uriaş: buffer ≤ HEAD_MAX; peste PAYLOAD_LIMIT → necunoscut", bounded and sc.last is None)
    sc = _scan(B + b"\x1b" + b"\x00" * 5000 + b"]133;C\x07", [len(B) + 100, 2000, 2000, 2000])
    check("ESC urmat de o rafală de C0 peste plafonul de carry → necunoscut", sc.last is None, sc.last)
    sc = _scan(B)
    sc.gap()
    check("gol în flux → ultimul marcaj necunoscut, integrarea rămâne", sc.last is None and sc.integrated)
    sc = _scan(B)
    sc.rebase()
    check("transcript rescris → felul rămâne, poziţia nu", sc.last == "B" and sc.last_start is None)
    # L3 (review 3.6.13): ecranul alternativ şi secvenţele scoase din replay
    sc = _scan(b"\x1b[?1049h" + B)
    check("B pe ecranul alternativ → last_alt", sc.last == "B" and sc.last_alt and sc.alt)
    sc = _scan(b"\x1b[?1049h\x1b[?1049l" + B)
    check("înapoi pe ecranul principal → last_alt fals", sc.last == "B" and not sc.last_alt)
    sc = _scan(b"\x1b[?47h\x1bc" + B)
    check("RIS închide ecranul alternativ", not sc.last_alt and not sc.alt)
    sc = _scan(b"\x1b[?1;1049h" + B)
    check("DECSET cu mai mulţi parametri (?1;1049h) → alternativ", sc.last_alt)
    sc = _scan(B + b"ls\x1b[H\x1b[2J$ ls")
    check("ESC[2J după ultimul B (Ctrl+L, repaint) → strip_end după marcaj",
          sc.strip_end is not None and sc.strip_end > sc.last_start)
    sc = _scan(b"\x1b[2J" + B)
    check("ESC[2J înaintea lui B → nu contează", sc.strip_end < sc.last_start)
    # calea fierbinte (review 3.6.13, M3): fără pas Python per octet
    loads = {
        "plain": b"hello world\n" * 1_000_000,
        "sgr-dense": b"\x1b[0m" * 2_500_000,
        "c2-dense": "°".encode() * 5_000_000,
        "osc-title-with-deg": b"\x1b]0;" + "°".encode() * 5_000_000 + b"\x07",
        "ls-color": b"\x1b[01;34mdir\x1b[0m  \x1b[01;32mexe\x1b[0m\n" * 300_000,
    }
    for name, load in loads.items():
        sc = osc133.Osc133Scanner()
        t0 = time.perf_counter()
        for i in range(0, len(load), 16384):
            sc.feed(load[i:i + 16384], i)
        rate = len(load) / 1e6 / (time.perf_counter() - t0)
        # prag generos (CI partajat); local: 100–350 MB/s
        check("scanare %s: %.0f MB/s (≥ 20)" % (name, rate), rate >= 20, rate)


async def osc133_hub_tests():
    print("-- 3.6.13: starea OSC 133 în hub, init, attach, resync")
    sid = "0133" * 8
    row = {"id": sid, "host_id": 1, "rows": 24, "cols": 80,
           "agent_epoch": None, "agent_offset": 0, "created": time.time()}
    hub = core.SessionHub(row)
    try:
        await hub._process_output(b"hello\r\n\x1b]133;A\x07$ \x1b]133;")
        st = hub.osc133_state(None)
        check("B neterminat la capătul chunk-ului: încă A, neintegrat", st["last"] == "A" and not st["integrated"], st)
        await hub._process_output(b"B\x07rm -rf /srv")
        st = hub.osc133_state(None)
        check("hub: B terminat în chunk-ul următor → integrat, ultimul B, nesincronizat fără replay",
              st == {"integrated": True, "last": "B", "synced": False}, st)
        check("out_pos = out_f.tell()", hub.out_pos == hub.out_f.tell(), (hub.out_pos, hub.out_f.tell()))
        hub._flush()
        end = hub.out_f.tell()
        span = {"end": end, "limit": 4096, "gen": hub.out_gen}
        check("replay complet până în punctul live, cu B în fereastră → synced",
              hub.osc133_state(span)["synced"] is True)
        check("B în afara ferestrei replay-ului → nesincronizat",
              hub.osc133_state({"end": end, "limit": 10, "gen": hub.out_gen})["synced"] is False)
        check("replay care se opreşte înaintea punctului live (gaura de checkpoint) → nesincronizat",
              hub.osc133_state({"end": end - 1, "limit": 4096, "gen": hub.out_gen})["synced"] is False)
        check("altă generaţie de transcript → nesincronizat",
              hub.osc133_state({"end": end, "limit": 4096, "gen": hub.out_gen + 1})["synced"] is False)
        check("span gol / invalid → nesincronizat",
              hub.osc133_state({})["synced"] is False
              and hub.osc133_state({"end": str(end), "limit": 4096, "gen": hub.out_gen})["synced"] is False)

        # attach: span completat doar când citirea e sigură
        span = {}
        await core.attach_replay(sid, hub, 0, 0, span=span)
        check("attach_replay pe un transcript flush-uit: span = [end-limit, end) din disc",
              span.get("end") == end and span.get("gen") == hub.out_gen and span.get("limit") > 0, span)
        check("… şi starea e sincronizată", hub.osc133_state(span)["synced"] is True)
        await hub._process_output(b"x")             # neflush-uit: gaura de checkpoint
        span = {}
        await core.attach_replay(sid, hub, 0, 0, span=span)
        check("octeţi ne-scrişi încă pe disc → replay-ul nu ajunge în punctul live → nesincronizat",
              hub.osc133_state(span or None)["synced"] is False, (span, hub.out_pos))

        # api._send_osc133: fără replay trimis nu pleacă nimic; cu span gol → nesincronizat
        class _C:
            def __init__(self):
                self.sent = []

            async def send_text(self, s):
                self.sent.append(json.loads(s))
        c = _C()
        await api._send_osc133(c, hub, None)
        check("fără replay trimis (sesiune blocată) nu se trimite starea", c.sent == [])
        await api._send_osc133(c, hub, {})
        check("replay trimis, fereastră nesigură → osc133 cu synced=false",
              c.sent == [{"type": "osc133", "integrated": True, "last": "B", "synced": False}], c.sent)

        # resync FULL (resume / unlock): tail exact până la cutoff → synced, trimis DUPĂ tail
        ws = _FakeWs()
        client = core.BrowserClient(ws, hub)
        hub.clients.add(client)
        await client._resync(full=True)
        kinds = [x.get("type") if isinstance(x, dict) else "bytes" for x in ws.sent]
        osc = [x for x in ws.sent if isinstance(x, dict) and x.get("type") == "osc133"]
        check("resync full: resync → tail → osc133 (înaintea oricărui octet live)",
              kinds[-3:] == ["resync", "bytes", "osc133"], kinds)
        check("resync full: B în tail, fără gaură → synced", osc and osc[-1]["synced"] is True
              and osc[-1]["last"] == "B", osc)
        ws.sent.clear()
        await client._resync(full=False)
        osc = [x for x in ws.sent if isinstance(x, dict) and x.get("type") == "osc133"]
        check("resync lossy (fără cutoff): nesincronizat, dar felul ultimului marcaj live rămâne",
              osc and osc[-1] == {"type": "osc133", "integrated": True, "last": "B", "synced": False}, osc)

        # ssh / sudo -i: ultimul marcaj live e C → îl trimitem (browserul ştie că rulează ceva)
        await hub._process_output(b"\r\n\x1b]133;C\x07Last login: ...\r\nroot@db:~# ")
        check("C live → last=C", hub.osc133_state(None)["last"] == "C")
        # gol în flux (agent repornit): ultimul marcaj nu mai e de încredere
        hub._write_gap_marker()
        st = hub.osc133_state(None)
        check("gap marker → last=None, integrated rămâne", st["last"] is None and st["integrated"], st)
        check("out_pos urmează şi marcajul de gol", hub.out_pos == hub.out_f.tell())

        # L3 (review 3.6.13): ecranul alternativ şi secvenţele scoase din replay
        await hub._process_output(b"\x1b[?1049h\x1b]133;A\x07$ \x1b]133;B\x07")
        check("B pe ecranul alternativ, flux fără tmux → last=None",
              hub.osc133_state(None)["last"] is None and hub.osc.last == "B")
        real_source = hub._source
        hub._source = lambda: type("S", (), {"backend": "tmux"})()
        check("… pe un flux tmux comutarea e a clientului tmux → B",
              hub.osc133_state(None)["last"] == "B")
        hub._source = lambda: type("S", (), {"backend": "pty"})()
        check("… backend pty → tot None", hub.osc133_state(None)["last"] is None)
        hub._source = real_source
        await hub._process_output(b"\x1b[?1049l\x1b]133;A\x07$ \x1b]133;B\x07ls")
        hub._flush()
        end = hub.out_f.tell()
        span = {"end": end, "limit": 1 << 20, "gen": hub.out_gen}
        check("înapoi pe ecranul principal → B, sincronizat", hub.osc133_state(span) ==
              {"integrated": True, "last": "B", "synced": True}, hub.osc133_state(span))
        await hub._process_output(b"\x1b[H\x1b[2J$ ls")     # Ctrl+L la prompt: fără B nou
        hub._flush()
        end = hub.out_f.tell()
        st = hub.osc133_state({"end": end, "limit": 1 << 20, "gen": hub.out_gen})
        check("ESC[2J după ultimul B (read_tail îl scoate din replay) → nesincronizat",
              st["last"] == "B" and st["synced"] is False, st)
        # L1: un C care nu urmează unui prompt (job în fundal) → None, nu „rulează"
        await hub._process_output(b"\x1b]133;D;0\x07\x1b]133;C\x07")
        check("C fără B înainte → last=None", hub.osc133_state(None)["last"] is None)
        hub.clients.discard(client)
    finally:
        hub.teardown()


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
