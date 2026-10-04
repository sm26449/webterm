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

# Middleware-ul `csrf_guard` cere `Origin` pe metodele care schimbă ceva şi refuză
# lipsa lui (ca `_origin_ok` pentru WebSocket). Testele imită un BROWSER, deci trimit
# antetul; fără el ar testa o cale pe care niciun browser n-o produce.
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


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 follow_redirects=False, headers=_ORIGIN) as c:
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

        # ── `_forward_stepup_ok`: pe baza REALĂ, cu schema reală ─────────────
        # Funcţia asta e chemată pentru FIECARE cerere prin tunel. Prima versiune interoga
        # `forwards` în loc de `port_forwards`, deci arunca de fiecare dată: opt teste de
        # forward au picat în CI, jumătate cu 500. Verificarea de aici e ieftină şi hermetică
        # — nu are nevoie de container, agent sau tunel — şi ar fi prins-o imediat.
        #
        # CONTRACTUL REAL (audit 2026-10-04): cererea soseşte pe `slug.<domeniu>` purtând DOAR
        # biletul de forward (`__Host-wt_fwd`). Cookie-ul de sesiune e `__Host-`, host-only pe
        # domeniul principal, şi NU ajunge niciodată pe subdomeniu. Versiunea veche a testului
        # simula un `_Req` cu cookie-ul de sesiune — adică un cookie pe care niciun browser nu-l
        # trimite — şi masca o buclă infinită de redirect pe orice forward de pe host 2FA.
        await db.execute("UPDATE port_forwards SET enabled=1 WHERE id=?", gated_fid)
        security._stepup_windows.clear()

        class _Req:
            def __init__(self, ticket=None):
                self.cookies = {api.FWD_COOKIE: ticket} if ticket else {}

        ticket = security.make_forward_token(gated_slug, uid, security.STEPUP_WINDOW_MAX)
        allowed = await api._forward_stepup_ok(plain_slug, _Req())
        check("host FĂRĂ 2FA: tunelul nu cere fereastră de step-up", allowed is True)

        allowed = await api._forward_stepup_ok(gated_slug, _Req())
        check("host CU 2FA, fără bilet: tunelul e refuzat", allowed is False)

        security.open_stepup_window(uid, gated)
        allowed = await api._forward_stepup_ok(gated_slug, _Req(ticket))
        check("host CU 2FA, bilet + fereastră deschisă, FĂRĂ cookie de sesiune: trece",
              allowed is True, allowed)

        # uid-ul din bilet e crezut doar după semnătură: un uid rescris nu împrumută fereastra
        exp_s, _uid_s, sig = ticket.split(".")
        forged = "%s.%d.%s" % (exp_s, uid + 7, sig)
        security.open_stepup_window(uid + 7, gated)
        allowed = await api._forward_stepup_ok(gated_slug, _Req(forged))
        check("bilet cu uid rescris (semnătură ruptă): refuzat chiar cu fereastra acelui uid deschisă",
              allowed is False)
        security._stepup_windows.pop((uid + 7, gated), None)

        security._stepup_windows.clear()
        allowed = await api._forward_stepup_ok(gated_slug, _Req(ticket))
        check("host CU 2FA, fereastră închisă: tunelul se închide şi el", allowed is False)

        allowed = await api._forward_stepup_ok("slug-inexistent", _Req())
        check("slug necunoscut: nu aruncă, doar lasă calea normală să dea 404",
              allowed is True)

        # ── cap-coadă pe SUBDOMENIU: client fără jar de cookie-uri (= browserul pe slug.<dom>) ──
        fwd_host = f"{gated_slug}.{api.forward_domain()}"
        async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                     follow_redirects=False) as sub:
            H = {"host": fwd_host, "cookie": f"{api.FWD_COOKIE}={ticket}"}
            security.open_stepup_window(uid, gated)
            r = await sub.get("/grafana?x=1", headers=H)
            # hostul e un agent offline → proxy-ul dă 409; esenţialul e că NU e redirect
            check("subdomeniu, bilet + fereastră deschisă: intră în proxy (nu redirect, nu 500)",
                  r.status_code not in (302, 500), f"{r.status_code} {r.headers.get('location')}")

            security._stepup_windows.clear()
            r = await sub.get("/grafana?x=1", headers=H)
            loc = r.headers.get("location", "")
            check("subdomeniu, fereastră închisă: 302", r.status_code == 302, str(r.status_code))
            check("redirect ABSOLUT către domeniul principal (altfel buclă pe subdomeniu)",
                  loc.startswith(config.PUBLIC_URL + "/__wtfwd/auth?slug=" + gated_slug), loc)
            check("`next` păstrează calea + query", "next=%2Fgrafana%3Fx%3D1" in loc, loc)

            r = await sub.get("/grafana", headers={"host": fwd_host})
            loc = r.headers.get("location", "")
            check("subdomeniu fără bilet: acelaşi redirect absolut",
                  r.status_code == 302 and loc.startswith(config.PUBLIC_URL + "/__wtfwd/auth?"), loc)

            # anti open-redirect: `next` schema-relativ (`//evil`) e aruncat, nu transmis mai departe
            r = await sub.get("http://t//evil.example/x", headers=H)
            loc = r.headers.get("location", "")
            check("`next=//evil` pe subdomeniu → aruncat (next=%2F)",
                  r.status_code == 302 and "next=%2F&" in loc + "&" and "evil" not in loc, loc)
            # ...şi la /__wtfwd/set (ultimul hop, cel care chiar redirecţionează pe `next`)
            r = await sub.get(f"/__wtfwd/set?t={ticket}&next=//evil.example/x", headers={"host": fwd_host})
            loc = r.headers.get("location", "")
            check("/__wtfwd/set cu next=//evil → rădăcina subdomeniului",
                  r.status_code == 302 and loc == f"http://{fwd_host}/", loc)

        # pe domeniul principal: `next` absolut e aruncat şi când fereastra e deschisă (biletul se
        # emite cu next=/), şi când e închisă (ocolul prin SPA nu cară URL-ul străin)
        security.open_stepup_window(uid, gated)
        r = await c.get(f"/__wtfwd/auth?slug={gated_slug}&next=https://evil.example/")
        loc = r.headers.get("location", "")
        check("forward_auth: next absolut → next=%2F la emitere",
              "__wtfwd/set?t=" in loc and loc.endswith("&next=%2F"), loc)
        security._stepup_windows.clear()
        r = await c.get(f"/__wtfwd/auth?slug={gated_slug}&next=//evil.example/")
        loc = r.headers.get("location", "")
        check("forward_auth: next=//evil → aruncat şi pe ocolul de step-up",
              "stepup=forward" in loc and "next=%2F#" in loc and "evil" not in loc, loc)

        # ── WebSocket: aceeaşi poartă, ÎNAINTE de accept ─────────────────────────
        # Un WS deschis pe host 2FA nu consulta fereastra deloc (doar biletul, valabil 1 h):
        # exact canalul interactiv (consolă web, noVNC) supravieţuia politicii.
        async def _ws(ticket_val):
            sent = []
            scope = {"type": "websocket", "path": "/ws", "query_string": b"",
                     "headers": [(b"host", fwd_host.encode()),
                                 (b"origin", f"http://{fwd_host}".encode()),
                                 (b"cookie", f"{api.FWD_COOKIE}={ticket_val}".encode())]}

            async def receive():
                return {"type": "websocket.connect"}

            async def send(m):
                sent.append(m)
            await api.handle_forward_ws(scope, receive, send)
            return sent

        security._stepup_windows.clear()
        sent = await _ws(ticket)
        check("WS pe host 2FA, fereastră închisă: refuzat cu 1008 înainte de accept",
              sent and sent[0].get("type") == "websocket.close" and sent[0].get("code") == 1008
              and not any(m.get("type") == "websocket.accept" for m in sent), str(sent))
        security.open_stepup_window(uid, gated)
        sent = await _ws(ticket)
        # trece de poartă; agentul e offline → 1011 (nu 1008): dovada că refuzul de mai sus era fereastra
        check("WS pe host 2FA, fereastră deschisă: trece de poartă (1011 = host offline, nu 1008)",
              sent and sent[0].get("code") == 1011, str(sent))

        # ── apps: un forward promovat la „bookmark" (app_type) apare în /api/apps ─────────
        security._stepup_windows.clear()
        r = await c.post(f"/api/hosts/{plain}/forwards",
                         json={"label": "Proxmox — srv", "target_host": "127.0.0.1",
                               "target_port": 8006, "scheme": "https", "enabled": True,
                               "app_type": "proxmox"})
        check("creare forward-app (app_type) → 200", r.status_code == 200, r.text)
        app_fid = r.json()["id"]
        check("forward-ul întoarce app_type", r.json().get("app_type") == "proxmox", r.text)
        apps = (await c.get("/api/apps")).json()
        check("/api/apps listează app-ul", any(a["id"] == app_fid for a in apps), str(apps))
        one = [a for a in apps if a["id"] == app_fid][0]
        check("/api/apps dă url+host, NU target:port", "url" in one and "host_name" in one
              and "target_port" not in one and "target_host" not in one, str(one))
        # audit 2026-09: coerţia tăcută ("Portainer " → '' dar 200) ascundea greşeala —
        # clientul afla abia căutând tile-ul pe dashboard. Acum invalid = 400 explicit.
        r = await c.post(f"/api/hosts/{plain}/forwards",
                         json={"label": "x", "target_port": 80, "app_type": "evil"})
        check("app_type necunoscut → 400 forward.badAppType (nu coerţie tăcută)",
              r.status_code == 400 and r.headers.get("X-WebTerm-Error") == "forward.badAppType", r.text)
        # promote/demote un forward simplu
        r = await c.post(f"/api/hosts/{plain}/forwards",
                         json={"label": "simplu", "target_port": 3000, "scheme": "http", "enabled": True})
        simple_fid = r.json()["id"]
        check("forward simplu NU e în /api/apps",
              not any(a["id"] == simple_fid for a in (await c.get("/api/apps")).json()))
        await c.patch(f"/api/forwards/{simple_fid}", json={"app_type": "custom"})
        check("după promote apare în /api/apps",
              any(a["id"] == simple_fid for a in (await c.get("/api/apps")).json()))
        await c.patch(f"/api/forwards/{simple_fid}", json={"app_type": ""})
        check("după demote dispare din /api/apps",
              not any(a["id"] == simple_fid for a in (await c.get("/api/apps")).json()))

        # ── 6. conexiunile DB (Toolbox): acelaşi gard ca forward-urile ───────────
        # O conexiune `stored` ţine o parolă DB criptată. Un cookie furat care re-ţinteşte
        # target_host către serverul atacatorului ar exfiltra parola în clar la lansare (agentul
        # o tastează în promptul „Password:" al clientului) → CRUD-ul trebuie să coste un factor
        # pe host 2FA, exact ca /forwards. audit v53.
        CONN = {"label": "pg-prod", "engine": "postgres", "target_host": "10.0.0.5",
                "target_port": 5432, "username": "app", "dbname": "shop", "cred_policy": "stored",
                "credential": "s3cret"}
        security._stepup_windows.clear()
        r = await c.post(f"/api/hosts/{plain}/connections", json=CONN)
        check("conexiune pe host fără 2FA: creare permisă", r.status_code == 200, r.text)
        plain_cid = r.json()["id"]
        # secretul NU se expune înapoi în JSON
        check("_connection_json nu întoarce credential_encrypted",
              "credential_encrypted" not in r.json() and "credential" not in r.json(), r.text)

        r = await c.post(f"/api/hosts/{gated}/connections", json=CONN)
        check("conexiune pe host 2FA, fără step-up: creare REFUZATĂ", r.status_code == 403, str(r.status_code))
        cnt = await db.fetchone("SELECT count(*) n FROM connections WHERE host_id=?", gated)
        check("refuzul nu lasă credenţialul în urmă", cnt["n"] == 0, str(cnt["n"]))

        security.open_stepup_window(uid, gated)
        r = await c.post(f"/api/hosts/{gated}/connections", json=CONN)
        check("conexiune pe host 2FA, în fereastră: creare permisă", r.status_code == 200, r.text)
        gated_cid = r.json()["id"]

        # re-ţintirea (vectorul de exfiltrare) e la fel de puternic gardată
        security._stepup_windows.clear()
        r = await c.patch(f"/api/hosts/{gated}/connections/{gated_cid}",
                          json=dict(CONN, target_host="evil.attacker.example", credential=""))
        check("re-ţintire fără step-up: REFUZATĂ", r.status_code == 403, str(r.status_code))
        row = await db.fetchone("SELECT target_host FROM connections WHERE id=?", gated_cid)
        check("ţinta a rămas neschimbată", row["target_host"] == "10.0.0.5", str(row["target_host"]))
        r = await c.request("DELETE", f"/api/hosts/{gated}/connections/{gated_cid}")
        check("ştergere fără step-up: REFUZATĂ", r.status_code == 403, str(r.status_code))
        r = await c.request("DELETE", f"/api/hosts/{plain}/connections/{plain_cid}")
        check("conexiune pe host fără 2FA: ştergerea merge ca înainte", r.status_code == 200, r.text)

        # ── 7. ştergerea hostului duce şi conexiunile (fără orfani cu secrete) ────
        # PRAGMA foreign_keys nu e setat → CASCADE inactiv; ştergem explicit. Cu id-urile
        # reutilizate, altfel un host nou ar moşteni parola stocată a celui vechi. audit v53.
        security.open_stepup_window(uid, gated)
        await c.post(f"/api/hosts/{gated}/connections", json=CONN)
        n = (await db.fetchone("SELECT count(*) n FROM connections WHERE host_id=?", gated))["n"]
        check("host 2FA are conexiuni stocate", n >= 1, str(n))
        security.open_stepup_window(uid, gated)
        r = await c.request("DELETE", f"/api/hosts/{gated}")
        check("ştergerea hostului → 200", r.status_code == 200, r.text)
        n = (await db.fetchone("SELECT count(*) n FROM connections WHERE host_id=?", gated))["n"]
        check("conexiunile hostului şterse (fără orfani)", n == 0, str(n))

        # ── funcţii pure: comanda per-politică şi validarea ──────────────────────
        stored_cmd = api._connection_command({"engine": "postgres", "target_host": "h", "target_port": 5432,
                                              "username": "u", "dbname": "d", "cred_policy": "stored"})
        check("`stored`: fără fallback la shell (client lipsă → sesiunea se încheie)",
              "${SHELL" not in stored_cmd and "exit 0" in stored_cmd, stored_cmd)
        ask_cmd = api._connection_command({"engine": "postgres", "target_host": "h", "target_port": 5432,
                                          "username": "u", "dbname": "d", "cred_policy": "ask"})
        check("`ask`: păstrează shell-ul (util ca să instalezi clientul)", "${SHELL" in ask_cmd, ask_cmd)

        def _bad(policy, **kw):
            body = api.ConnectionIn(label="x", engine=kw.get("engine", "postgres"),
                                    target_host=kw.get("target_host", "h"),
                                    target_port=kw.get("target_port", 5432),
                                    username=kw.get("username", ""),
                                    cred_policy=policy)
            try:
                api._validate_connection(body); return None
            except api.ApiError as e:
                return e.code
        check("redis + stored respins (fără prompt de parolă)",
              _bad("stored", engine="redis") == "connection.noStoredRedis")
        check("influxdb 1.x + stored FĂRĂ user respins (parola s-ar arma degeaba)",
              _bad("stored", engine="influxdb") == "connection.influxNeedsUser")
        check("influxdb 1.x + stored CU user acceptat (are prompt „password:”)",
              _bad("stored", engine="influxdb", username="admin") is None)
        check("influxdb 2.x + stored acceptat (wrapper-ul emite prompt propriu)",
              _bad("stored", engine="influxdb2") is None)
        ix = api._connection_command({"engine": "influxdb", "target_host": "h", "target_port": 8086,
                                      "username": "u", "dbname": "d", "cred_policy": "stored"})
        check("influx 1.x: `-password ''` explicit (prompt, nu parolă în argv)",
              "-password ''" in ix and "-username u" in ix and "-database d" in ix, ix)
        ix2 = api._connection_command({"engine": "influxdb2", "target_host": "h", "target_port": 8086,
                                       "username": "myorg", "dbname": "", "cred_policy": "stored"})
        # promptul wrapper-ului trebuie să conţină EXACT substringul „password:" (tiparul injecţiei
        # din agent), token-ul se citeşte cu echo OFF şi ajunge la influx DOAR prin env — niciodată
        # în argv; gol → env nesetat → fallback pe `influx config`-ul hostului
        check("influx 2.x: prompt injectabil + token doar prin env, cu org",
              "password: " in ix2 and "stty -echo" in ix2 and "INFLUX_TOKEN" in ix2
              and "v1 shell" in ix2 and "--org myorg" in ix2 and "--token" not in ix2, ix2)
        ix2n = api._connection_command({"engine": "influxdb2", "target_host": "h", "target_port": 8086,
                                        "username": "", "dbname": "", "cred_policy": "ask"})
        check("influx 2.x fără org: flagul --org lipseşte", "--org" not in ix2n, ix2n)
        check("engine necunoscut respins", _bad("ask", engine="nu-exista") == "connection.badEngine")
        check("host cu metacaractere respins", _bad("ask", target_host="h;rm -rf") == "connection.badField")
        check("port invalid respins", _bad("ask", target_port=99999) == "connection.badPort")
        check("politică necunoscută respinsă", _bad("nope") == "connection.badPolicy")

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
