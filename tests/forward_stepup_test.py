"""Forward-urile pe host cu 2FA cer step-up — la configurare ŞI la acces.

Un port forward e o gaură făcută la comandă în reţeaua host-ului: ţinta implicită e
`127.0.0.1`, deci `127.0.0.1:2375` (API-ul Docker, fără autentificare) devine accesibil din
afară. Pe un host marcat „cere 2FA la conectare" asta trebuie să coste un factor.

Nu costa. Comentariul din cod justifica scutirea cu „accesul la forward-urile de agent rămâne
pe cookie, aceeaşi categorie ca citirea istoricului" — dar citirea istoricului a fost închisă cu
step-up pe 2026-08-06, deci premisa căzuse şi forward-urile rămăseseră SINGURA acţiune de host
care se putea face cu un cookie furat. Hosturile SSH cu 2FA erau deja blocate accidental
(`_ensure_forward_source` refuză să ridice o conexiune), dar cele cu agent — majoritatea — nu.

Două planuri, ambele necesare:
  * configurarea (create/patch/delete): fără ea, oricine cu cookie îşi făcea tunel nou;
  * accesul (`forward_auth`): fără el, gardul de mai sus ar opri doar tunelurile NOI, iar unul
    deja existent ar rămâne deschis pe cookie.
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
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 follow_redirects=False) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
        me = await db.fetchone("SELECT id FROM users WHERE email=?", "a@b.co")
        uid = me["id"]

        plain = (await c.post("/api/hosts", json={"name": "fara-2fa"})).json()["id"]
        gated = (await c.post("/api/hosts", json={"name": "cu-2fa"})).json()["id"]
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", gated)

        FWD = {"label": "docker", "target_host": "127.0.0.1", "target_port": 2375,
               "scheme": "http", "enabled": True}

        # ── 1. configurare: crearea unui tunel ────────────────────────────────
        security._stepup_windows.clear()
        r = await c.post(f"/api/hosts/{plain}/forwards", json=FWD)
        check("host fără 2FA: crearea merge ca înainte", r.status_code == 200, r.text)
        ok_fid = r.json()["id"]

        r = await c.post(f"/api/hosts/{gated}/forwards", json=FWD)
        check("host cu 2FA, fără step-up: creare REFUZATĂ", r.status_code == 403, str(r.status_code))
        cnt = await db.fetchone("SELECT count(*) n FROM port_forwards WHERE host_id=?", gated)
        check("refuzul nu lasă rândul în urmă", cnt["n"] == 0, str(cnt["n"]))

        # cu fereastră deschisă (ca după ceremonia passkey) trece
        security.open_stepup_window(uid, gated)
        r = await c.post(f"/api/hosts/{gated}/forwards", json=FWD)
        check("host cu 2FA, în fereastră de step-up: creare permisă", r.status_code == 200, r.text)
        gated_fid = r.json()["id"]
        gated_slug = r.json()["slug"]

        # ── 2. re-ţintirea unui forward existent e la fel de puternică ────────
        security._stepup_windows.clear()
        r = await c.patch(f"/api/forwards/{gated_fid}", json={"target_port": 22})
        check("host cu 2FA, fără step-up: re-ţintire REFUZATĂ", r.status_code == 403, str(r.status_code))
        row = await db.fetchone("SELECT target_port FROM port_forwards WHERE id=?", gated_fid)
        check("ţinta a rămas neschimbată", row["target_port"] == 2375, str(row["target_port"]))
        r = await c.request("DELETE", f"/api/forwards/{gated_fid}")
        check("host cu 2FA, fără step-up: ştergere REFUZATĂ", r.status_code == 403, str(r.status_code))
        r = await c.request("DELETE", f"/api/forwards/{ok_fid}")
        check("host fără 2FA: ştergerea merge ca înainte", r.status_code == 200, r.text)

        # ── 3. ACCESUL: un tunel deja creat nu se deschide pe cookie ──────────
        # Aici e miezul: fără gardul ăsta, pasul 1 ar opri doar tunelurile NOI.
        security._stepup_windows.clear()
        r = await c.get(f"/__wtfwd/auth?slug={gated_slug}")
        check("host cu 2FA, fără step-up: accesul NU emite token",
              r.status_code == 302 and "__wtfwd/set" not in r.headers.get("location", ""),
              f"{r.status_code} {r.headers.get('location')}")
        loc = r.headers.get("location", "")
        check("omul e trimis unde poate debloca (nu un 403 sec)",
              "stepup=forward" in loc and f"#/h/{gated}" in loc, loc)
        check("întoarcerea păstrează pagina cerută", "next=" in loc, loc)
        # ruta SPA e ancorată (`^#/h/(\d+)$`): parametrii TREBUIE să stea în query, nu după hash,
        # altfel omul aterizează pe dashboard şi nu înţelege de ce
        check("parametrii stau înainte de hash (ruta SPA e ancorată)",
              loc.index("stepup=forward") < loc.index("#/h/"), loc)

        security.open_stepup_window(uid, gated)
        r = await c.get(f"/__wtfwd/auth?slug={gated_slug}")
        check("în fereastră de step-up: accesul emite tokenul",
              r.status_code == 302 and "__wtfwd/set?t=" in r.headers.get("location", ""),
              r.headers.get("location", ""))

        # ── 4. hosturile fără 2FA nu au căpătat un pas în plus ────────────────
        r = await c.post(f"/api/hosts/{plain}/forwards", json=dict(FWD, label="al2"))
        plain_slug = r.json()["slug"]
        security._stepup_windows.clear()
        r = await c.get(f"/__wtfwd/auth?slug={plain_slug}")
        check("host fără 2FA: accesul rămâne neschimbat",
              r.status_code == 302 and "__wtfwd/set?t=" in r.headers.get("location", ""),
              r.headers.get("location", ""))

        # ── 5. forward oprit/inexistent: 404 înainte de orice ─────────────────
        r = await c.get("/__wtfwd/auth?slug=nu-exista")
        check("slug inexistent → 404", r.status_code == 404, str(r.status_code))
        # ...şi nescurs: un slug oprit nu trebuie să spună „există, dar cere step-up"
        await db.execute("UPDATE port_forwards SET enabled=0 WHERE id=?", gated_fid)
        security._stepup_windows.clear()
        r = await c.get(f"/__wtfwd/auth?slug={gated_slug}")
        check("forward oprit → 404, nu redirect de step-up (fără oracol)",
              r.status_code == 404, str(r.status_code))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
