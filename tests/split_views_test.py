"""Split-views — layout-uri denumite de 2-4 sesiuni, per user, sincronizate server-side.

Un split-view NU ţine niciun secret: e metadată de layout care referă sesiuni gated
independent la attach. Deci CRUD = doar require_user, fără step-up. Ce verificăm aici:
  * 2-4 sesiuni DISTINCTE, existente (badCount / dupPane / badPane / noName);
  * izolare per user (nu vezi layout-urile altui cont);
  * reconciliere: o sesiune închisă e curăţată din panouri; sub 2 → layout-ul dispare;
  * ratio clamp; PATCH parţial (rename / ratio / broadcast fără să retrimiţi panourile).
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


async def _mksession(sid, host_id):
    import time
    await db.execute("INSERT INTO sessions(id, host_id, state, created) VALUES(?,?,?,?)",
                     sid, host_id, "live", time.time())


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
        me = await db.fetchone("SELECT id FROM users WHERE email=?", "a@b.co")
        uid = me["id"]
        hid = (await c.post("/api/hosts", json={"name": "srv"})).json()["id"]
        for s in ("s1", "s2", "s3"):
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
        r = await c.patch(f"/api/split-views/{sv_id}", json={"panes": ["s2", "s3"]})
        check("PATCH panes → validat + salvat", r.json()["panes"] == ["s2", "s3"], r.text)
        r = await c.patch(f"/api/split-views/{sv_id}", json={"panes": ["s2", "s2"]})
        check("PATCH panes duplicat → 400 dupPane", r.status_code == 400 and hdr(r) == "splitview.dupPane", r.text)
        r = await c.patch("/api/split-views/999999", json={"name": "z"})
        check("PATCH pe id inexistent → 404", r.status_code == 404, str(r.status_code))

        # ── izolare per user ──────────────────────────────────────────────────
        import time
        await db.execute(
            "INSERT INTO split_views(user_id, name, panes, ratio, broadcast, position, created, updated)"
            " VALUES(?,?,?,?,?,?,?,?)",
            uid + 777, "al-altcuiva", '["s1","s2"]', 0.5, 0, 0, time.time(), time.time())
        lst = (await c.get("/api/split-views")).json()["split_views"]
        check("nu văd layout-ul altui user", all(x["name"] != "al-altcuiva" for x in lst), str(lst))

        # ── reconciliere: sesiune închisă → panou curăţat; sub 2 → layout şters ─
        await db.execute("DELETE FROM sessions WHERE id=?", "s3")
        # sv_id are acum panes [s2, s3]; s3 dispărut → rămâne [s2] (<2) → se şterge
        lst = (await c.get("/api/split-views")).json()["split_views"]
        check("layout cu <2 panouri vii → pruned la GET", all(x["id"] != sv_id for x in lst), str(lst))
        # sv2_id are [s1, s2] — intacte
        check("layout cu panouri intacte rămâne", any(x["id"] == sv2_id for x in lst), str(lst))

        # ── delete ────────────────────────────────────────────────────────────
        r = await c.request("DELETE", f"/api/split-views/{sv2_id}")
        check("DELETE → 200", r.status_code == 200, r.text)
        lst = (await c.get("/api/split-views")).json()["split_views"]
        check("după delete nu mai e listat", all(x["id"] != sv2_id for x in lst), str(lst))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
