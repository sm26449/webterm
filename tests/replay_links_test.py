"""Link-uri de replay pentru înregistrările sesiunilor închise (3.5.12).

Ce verificăm:
  * mascarea (pură): secrete tăiate între evenimente (2 şi 3 bucăţi), secvenţe ESC în interiorul
    unei porţiuni mascate (şi tăiate între evenimente), lungimi/timpi/număr de evenimente
    neschimbate, caractere late, `password=` urmat de culoare, prompt `Password:` + rând nou;
  * API-ul proprietarului: doar cookie (401 fără, 401 cu token Bearer), doar sesiuni ÎNCHISE,
    expirare din listă fixă (implicit 24 h, max 7 zile), eticheta curăţată, step-up pe host 2FA
    (la creare, la revocare; rândul ascuns din listă fără fereastră), izolare între conturi
    (lista, revocarea unui link străin = 404, „revocă tot" atinge doar contul propriu);
  * endpoint-urile publice: tokenul în antet, 404 IDENTIC (status + corp + antete) pentru
    lipsă / greşit / expirat / revocat / sesiune ştearsă, `no-store` + `noindex`, mascat vs brut,
    vizualizarea text mascată;
  * deschiderile: contor + ultima deschidere în listă, rând în audit_log fără token, alertă în
    aplicaţie DOAR la proprietar şi cel mult una per link la 10 minute; alertă la creare;
  * limita de rată: după prea multe tokenuri greşite, şi un token VALID primeşte 429;
  * revocare: la schimbarea parolei, la ştergerea contului, la ştergerea sesiunii.
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
from app import api, config, core, db, email_alerts, replay, security  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0
PW1, PW2 = "parolabuna1", "parolabuna2"
GHP = "ghp_" + "Q" * 36
AKIA = "AKIAIOSFODNN7EXAMPLE"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


async def _settle():
    for _ in range(20):
        await asyncio.sleep(0.01)


# ── 1. mascarea, pură ─────────────────────────────────────────────────────────────────────
def unit_redaction():
    ev = [[0.10, "o", "$ export GITHUB_TOKEN=gh"], [0.20, "o", "p_" + "Q" * 20],
          [0.30, "o", "Q" * 16 + "\r\n$ echo ok\r\n"],
          [0.40, "o", "aws "], [0.41, "o", AKIA[:7]], [0.42, "o", AKIA[7:] + " done\r\n"],
          [0.50, "r", "100x30"]]
    out = replay.redact_events(ev)
    joined_in = "".join(e[2] for e in ev if e[1] == "o")
    joined_out = "".join(e[2] for e in out if e[1] == "o")
    check("mascare: tokenul GitHub tăiat în 3 evenimente nu mai apare (nici bucăţi din el)",
          GHP not in joined_out and "Q" * 8 not in joined_out, joined_out)
    check("mascare: cheia AWS tăiată în 3 evenimente e ascunsă", AKIA not in joined_out
          and "IOSF" not in joined_out, joined_out)
    check("mascare: acelaşi număr de evenimente, aceiaşi timpi, aceleaşi tipuri",
          [(e[0], e[1]) for e in out] == [(e[0], e[1]) for e in ev])
    check("mascare: fiecare eveniment îşi păstrează lungimea",
          all(len(a[2]) == len(b[2]) for a, b in zip(ev, out)),
          [(len(a[2]), len(b[2])) for a, b in zip(ev, out)])
    check("mascare: textul din jur rămâne (`$ echo ok`, `done`)",
          "$ echo ok" in joined_out and " done" in joined_out and "GITHUB_TOKEN=" in joined_out)
    check("mascare: evenimentele non-`o` (resize) trec neatinse", out[-1] == ev[-1])
    check("mascare: fără secrete → aceeaşi listă", replay.redact_events([[0, "o", "ls -la\r\n"]])
          == [[0, "o", "ls -la\r\n"]])
    check("mascare: concatenarea are aceeaşi lungime", len(joined_in) == len(joined_out))

    # o cheie privată cu o secvenţă de culoare TĂIATĂ între evenimente: ESC-ul rămâne întreg
    pk = [[1.0, "o", "-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXk\x1b["],
          [1.1, "o", "1mAAAAABG5vbmU\x1b[0m\r\n-----END OPENSSH PRIVATE KEY-----\r\n"]]
    po = replay.redact_events(pk)
    check("cheie privată: corpul mascat, BEGIN/END rămân",
          "b3BlbnNzaC1rZXk" not in po[0][2] and "AAAAABG5vbmU" not in po[1][2]
          and "BEGIN OPENSSH PRIVATE KEY" in po[0][2] and "END OPENSSH" in po[1][2], po)
    check("cheie privată: secvenţa ESC tăiată între evenimente rămâne intactă (`\\x1b[` + `1m`)",
          po[0][2].endswith("\x1b[") and po[1][2].startswith("1m") and "\x1b[0m" in po[1][2], po)
    check("cheie privată: CR/LF păstrate (poziţionarea nu se strică)",
          po[0][2].count("\r\n") == pk[0][2].count("\r\n"))

    s = "ls -la password=\x1b[31mhunter2\x1b[0m"
    m = replay.mask_secrets(s)
    check("`password=` urmat de culoare: valoarea ascunsă, culorile intacte",
          "hunter2" not in m and m.count("\x1b[31m") == 1 and m.count("\x1b[0m") == 1
          and len(m) == len(s), repr(m))
    p = "[sudo] Password:\r\nls -la\r\n"
    check("prompt `Password:` urmat de rând nou: rândul următor NU e mascat",
          replay.mask_secrets(p) == p, repr(replay.mask_secrets(p)))
    w = replay.mask_secrets("token=密码ab")
    check("caracter lat → `**` (lăţimea pe ecran se păstrează)", w == "token=******", repr(w))
    for sample, secret in (("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
                           ("git clone https://bob:hunter22@git.example/x", "hunter22"),
                           ("export ANTHROPIC_API_KEY=sk-ant-api03-" + "x" * 30, "api03"),
                           ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG", "wJalrXUt"),
                           ("github_pat_" + "A1" * 20, "A1A1A1"),
                           ("curl -H 'X: wt_ABCDEFGHIJKLMN'", "ABCDEFGHIJKLMN"),
                           ("jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "SflKxwRJ")):
        check(f"tipar: {sample[:28]}…", secret not in replay.mask_secrets(sample),
              replay.mask_secrets(sample))

    raw = (json.dumps({"version": 2, "width": 80, "height": 24}) + "\n"
           + json.dumps([0.1, "o", "token=abc"]) + "\n" + "garbage line\n"
           + json.dumps([0.2, "o", "def\r\n"]) + "\n").encode()
    red = replay.redact_cast(raw).decode()
    lines = red.strip().split("\n")
    check("redact_cast: antetul trece neschimbat, linia coruptă se sare",
          json.loads(lines[0])["width"] == 80 and len(lines) == 3, red)
    check("redact_cast: valoarea tăiată între evenimente e ascunsă",
          "abc" not in red and "def" not in red.split("\n", 1)[1], red)


async def _mk_session(sid, host_id, state, events):
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,closed_at,rows,cols)"
        " VALUES(?,?,?,?,?,?,?,?)", sid, host_id, "deploy " + sid[:4], state,
        time.time() - 600, time.time() - 60 if state == "closed" else None, 24, 80)
    out_path, cast_path = core.transcript_paths(sid)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes("".join(e[2] for e in events).encode())
    cast_path.write_text(json.dumps({"version": 2, "width": 80, "height": 24}) + "\n"
                         + "".join(json.dumps(e) + "\n" for e in events))


def _pub(token):
    return {"x-replay-token": token} if token is not None else {}


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    email_alerts._send_blocking = lambda cfg, subject, body: None

    unit_redaction()

    EVENTS = [[0.5, "o", "$ export TOKEN=s3cr"], [0.7, "o", "etvalue1\r\n$ echo " + GHP[:10]],
              [0.9, "o", GHP[10:] + "\r\n"], [1.5, "o", "$ exit\r\n"]]
    S_OK, S_LIVE, S_2FA, S_DEL = "a" * 32, "b" * 32, "c" * 32, "d" * 32

    transport = httpx.ASGITransport(app=app, client=("203.0.113.7", 5555))
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as a, \
            httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as b, \
            httpx.AsyncClient(transport=transport, base_url="http://t") as anon:
        await a.post("/api/setup", json={"email": "unu@x.co", "password": PW1, "setup_token": "test-setup"})
        r = await a.post("/api/users", json={"email": "doi@x.co", "password": PW2, "current_password": PW1})
        check("al doilea cont creat", r.status_code == 200, r.text[:120])
        await b.post("/api/login", json={"email": "doi@x.co", "password": PW2})
        u1 = (await db.fetchone("SELECT id FROM users WHERE email='unu@x.co'"))["id"]
        u2 = (await db.fetchone("SELECT id FROM users WHERE email='doi@x.co'"))["id"]
        hid = (await a.post("/api/hosts", json={"name": "srv"})).json()["id"]
        hid2 = (await a.post("/api/hosts", json={"name": "critic", "require_2fa": True})).json()["id"]
        for sid, h, st in ((S_OK, hid, "closed"), (S_LIVE, hid, "live"), (S_2FA, hid2, "closed"),
                           (S_DEL, hid, "closed")):
            await _mk_session(sid, h, st, EVENTS)
        await _settle()

        # ── auth pe API-ul proprietarului ──────────────────────────────────────────────────
        r = await anon.post(f"/api/sessions/{S_OK}/replay-links", json={})
        check("creare fără cookie → 401", r.status_code == 401, r.status_code)
        r = await a.post("/api/tokens", json={"name": "ci", "scopes": ["read", "run"],
                                              "days": 5, "current_password": PW1})
        tok = r.json().get("token", "")
        r = await anon.post(f"/api/sessions/{S_OK}/replay-links", json={},
                            headers={"authorization": "Bearer " + tok})
        check("creare cu token de automatizare → 401 (doar browser)", r.status_code == 401, r.status_code)
        r = await anon.get("/api/replay-links", headers={"authorization": "Bearer " + tok})
        check("listare cu token de automatizare → 401", r.status_code == 401, r.status_code)

        # ── validări ───────────────────────────────────────────────────────────────────────
        r = await a.post(f"/api/sessions/{S_LIVE}/replay-links", json={})
        check("sesiune VIE → 409 replay.notClosed",
              r.status_code == 409 and r.json().get("code") == "replay.notClosed", r.text[:120])
        r = await a.post(f"/api/sessions/{S_OK}/replay-links", json={"expires_hours": 48})
        check("expirare din afara listei → 400", r.status_code == 400
              and r.json().get("code") == "replay.badExpiry", r.text[:120])
        r = await a.post(f"/api/sessions/{S_OK}/replay-links", json={"expires_hours": 24 * 30})
        check("peste 7 zile → 400", r.status_code == 400)
        r = await a.post("/api/sessions/" + "z" * 32 + "/replay-links", json={})
        check("sid invalid → 404", r.status_code == 404)

        t0 = time.time()
        r = await a.post(f"/api/sessions/{S_OK}/replay-links",
                         json={"label": "  pentru\x1b[31m echipa‮  " + "x" * 200})
        j = r.json()
        check("creare (implicit) → 200, URL cu fragment #/replay/", r.status_code == 200
              and "/#/replay/" in j.get("url", ""), r.text[:200])
        tok_masked = j["url"].rsplit("/", 1)[1]
        check("implicit: 24 h şi mascare PORNITĂ",
              abs(j["expires"] - (t0 + 86400)) < 5 and j["redact"] is True, j)
        check("eticheta: fără caractere de control/bidi, plafonată la 80",
              "\x1b" not in j["label"] and "‮" not in j["label"] and len(j["label"]) <= 80
              and j["label"].startswith("pentru"), repr(j["label"]))
        row = await db.fetchone("SELECT token_hash FROM replay_links WHERE id=?", j["id"])
        check("în DB stă doar hash-ul tokenului", row["token_hash"] == security.sha256_hex(tok_masked)
              and tok_masked not in row["token_hash"])
        r = await a.post(f"/api/sessions/{S_OK}/replay-links",
                         json={"expires_hours": 168, "redact": False, "label": "brut"})
        j_raw = r.json()
        tok_raw = j_raw["url"].rsplit("/", 1)[1]
        check("7 zile + fără mascare → acceptat", r.status_code == 200
              and abs(j_raw["expires"] - (time.time() + 7 * 86400)) < 5 and j_raw["redact"] is False)
        r = await a.post(f"/api/sessions/{S_OK}/replay-links", json={"expires_hours": 1})
        j_1h = r.json()
        tok_1h = j_1h["url"].rsplit("/", 1)[1]
        check("1 oră → acceptat", r.status_code == 200 and abs(j_1h["expires"] - (time.time() + 3600)) < 5)
        audit_rows = await db.fetchall("SELECT path, detail FROM audit_log WHERE method='POST'"
                                       " AND path LIKE '%/replay-links'")
        check("crearea e auditată (cu mascarea în detaliu), fără token",
              any("UNMASKED" in r_["detail"] for r_ in audit_rows)
              and not any(tok_raw in (r_["path"] + r_["detail"]) for r_ in audit_rows),
              [dict(x) for x in audit_rows])
        await _settle()
        al = await db.fetchall("SELECT * FROM alerts WHERE kind='replay_link'")
        check("alertă la creare → doar la contul care l-a creat",
              len(al) == 3 and all(x["user_id"] == u1 for x in al), [dict(x) for x in al])

        # ── 2FA ────────────────────────────────────────────────────────────────────────────
        security.clear_stepup_for(u1)
        r = await a.post(f"/api/sessions/{S_2FA}/replay-links", json={})
        check("host 2FA fără step-up → 403 stepup.*", r.status_code == 403
              and r.json().get("code", "").startswith("stepup."), r.text[:160])
        r = await a.post(f"/api/sessions/{S_2FA}/replay-links", json={"stepup_password": PW1})
        # 3.5.13: parola singură nu mai e step-up (contul n-are passkey/TOTP)
        check("host 2FA cu parola SINGURĂ → 403 stepup.needsFactor",
              r.status_code == 403 and r.json().get("code") == "stepup.needsFactor", r.text[:160])
        security.open_stepup_window(u1, hid2)          # = un factor real prezentat prin /stepup
        r = await a.post(f"/api/sessions/{S_2FA}/replay-links", json={})
        j_2fa = r.json()
        check("host 2FA cu fereastra de step-up deschisă → creat", r.status_code == 200, r.text[:160])
        security.clear_stepup_for(u1)
        r = await a.get("/api/replay-links")
        lst = r.json()
        check("listă fără fereastră 2FA: rândul 2FA ascuns, dar numărat",
              lst["hidden"] == 1 and len(lst["links"]) == 3
              and all(x["sid"] != S_2FA for x in lst["links"]), lst)
        check("lista NU conţine token sau URL",
              not any(k in json.dumps(lst) for k in (tok_masked, tok_raw, "/#/replay/")))
        r = await a.delete(f"/api/replay-links/{j_2fa['id']}")
        check("revocare pe host 2FA fără step-up → 403", r.status_code == 403, r.status_code)
        security.open_stepup_window(u1, hid2)
        r = await a.get("/api/replay-links")
        check("cu fereastra deschisă, rândul 2FA apare", r.json()["hidden"] == 0
              and len(r.json()["links"]) == 4)
        r = await a.get("/api/replay-links", params={"sid": S_OK})
        check("filtrul ?sid= întoarce doar link-urile acelei înregistrări",
              len(r.json()["links"]) == 3 and all(x["sid"] == S_OK for x in r.json()["links"]))

        # ── izolare între conturi ─────────────────────────────────────────────────────────
        r = await b.get("/api/replay-links")
        check("contul 2 nu vede link-urile contului 1", r.status_code == 200
              and r.json() == {"links": [], "hidden": 0}, r.text[:200])
        r = await b.delete(f"/api/replay-links/{j['id']}")
        check("contul 2 nu poate revoca link-ul contului 1 (404, nu 403)", r.status_code == 404)
        r = await b.post(f"/api/sessions/{S_DEL}/replay-links", json={"label": "al doilea"})
        tok_b = r.json()["url"].rsplit("/", 1)[1]
        r = await b.post("/api/replay-links/revoke-all")
        check("„revocă tot” al contului 2 îi atinge doar link-urile lui",
              r.json().get("revoked") == 1
              and (await db.fetchone("SELECT COUNT(*) AS c FROM replay_links WHERE user_id=?", u1))["c"] == 4)

        # ── public: 404 identic ──────────────────────────────────────────────────────────
        replay.reset_limits()
        r = await anon.get("/api/replay/meta", headers=_pub(tok_masked))
        m = r.json()
        check("meta public → 200 cu titlu + etichetă, fără host/cont",
              r.status_code == 200 and m["title"].startswith("deploy") and m["label"].startswith("pentru")
              and "host" not in json.dumps(m).lower() and "unu@x.co" not in json.dumps(m), m)
        check("meta: Cache-Control no-store + X-Robots-Tag noindex + Referrer-Policy no-referrer",
              r.headers.get("cache-control") == "no-store" and "noindex" in r.headers.get("x-robots-tag", "")
              and r.headers.get("referrer-policy") == "no-referrer", dict(r.headers))
        # expirat / revocat / sesiune ştearsă — pregătim câte un token pentru fiecare
        r = await a.post(f"/api/sessions/{S_OK}/replay-links", json={})
        tok_exp, id_exp = r.json()["url"].rsplit("/", 1)[1], r.json()["id"]
        await db.execute("UPDATE replay_links SET expires=? WHERE id=?", time.time() - 1, id_exp)
        r = await a.post(f"/api/sessions/{S_OK}/replay-links", json={})
        tok_rev, id_rev = r.json()["url"].rsplit("/", 1)[1], r.json()["id"]
        r = await a.delete(f"/api/replay-links/{id_rev}")
        check("revocarea unui link → 200", r.status_code == 200)
        r = await a.post(f"/api/sessions/{S_DEL}/replay-links", json={})
        tok_del = r.json()["url"].rsplit("/", 1)[1]
        r = await a.delete(f"/api/sessions/{S_DEL}")
        check("ştergerea sesiunii → 200", r.status_code == 200, r.text[:100])
        check("…şi link-urile ei au plecat din DB",
              (await db.fetchone("SELECT COUNT(*) AS c FROM replay_links WHERE sid=?", S_DEL))["c"] == 0)

        def shape(resp):
            hd = {k: v for k, v in resp.headers.items() if k.lower() not in ("date", "content-length")}
            return (resp.status_code, resp.text, tuple(sorted(hd.items())))

        variants = {"fără token": None, "token greşit": security.new_token(), "token scurt": "abc",
                    "expirat": tok_exp, "revocat": tok_rev, "sesiune ştearsă": tok_del,
                    "contul 2 l-a revocat": tok_b}
        for path in ("/api/replay/meta", "/api/replay/cast", "/api/replay/text"):
            replay.reset_limits()
            shapes = {}
            for name, t in variants.items():
                shapes[name] = shape(await anon.get(path, headers=_pub(t)))
            first = next(iter(shapes.values()))
            check(f"{path}: 404 IDENTIC (status, corp, antete) pentru {len(variants)} cazuri",
                  first[0] == 404 and all(v == first for v in shapes.values()),
                  {k: v[:2] for k, v in shapes.items()})
            check(f"{path}: şi 404-ul e no-store", ("cache-control", "no-store") in first[2])
        r = await anon.get(f"/api/replay/{tok_masked}")
        check("tokenul în CALE nu deschide nimic (doar antetul)", r.status_code != 200, r.status_code)

        # ── conţinut: mascat vs brut ─────────────────────────────────────────────────────
        replay.reset_limits()
        email_alerts._last_sent.clear()
        orig = core.transcript_paths(S_OK)[1].read_bytes()
        r = await anon.get("/api/replay/cast", headers=_pub(tok_raw))
        check("link FĂRĂ mascare → exact fişierul .cast", r.status_code == 200 and r.content == orig)
        r = await anon.get("/api/replay/cast", headers=_pub(tok_masked),
                           follow_redirects=False)
        body = r.text
        evs = [json.loads(x) for x in body.strip().split("\n")[1:]]
        check("link mascat → secretele tăiate între evenimente nu mai apar",
              r.status_code == 200 and "s3cretvalue1" not in body and "etvalue1" not in body
              and GHP not in body and GHP[10:] not in body, body)
        check("link mascat → aceiaşi timpi şi aceleaşi lungimi per eveniment",
              [(e[0], len(e[2])) for e in evs] == [(e[0], len(e[2])) for e in EVENTS], evs)
        check("cast: no-store", r.headers.get("cache-control") == "no-store")
        r = await anon.get("/api/replay/text", headers=_pub(tok_masked, ))
        check("vizualizarea text: mascată, restul lizibil",
              r.status_code == 200 and "s3cretvalue1" not in r.text and "$ exit" in r.text, r.text)
        for _ in range(2):
            await anon.get("/api/replay/cast", headers={**_pub(tok_masked), "user-agent": "Mozilla/5.0 " + "X" * 400})
        await _settle()

        # ── deschideri: contor, audit, alertă ─────────────────────────────────────────────
        r = await a.get("/api/replay-links", params={"sid": S_OK})
        mine = {x["id"]: x for x in r.json()["links"]}
        check("lista: 4 deschideri pe link-ul mascat (3 cast + 1 text), cu ultima deschidere + IP",
              mine[j["id"]]["opens"] == 4 and mine[j["id"]]["last_opened"]
              and mine[j["id"]]["last_ip"] == "203.0.113.7", mine.get(j["id"]))
        check("meta NU se numără ca deschidere (link-ul de 1 h: 0)", mine[j_1h["id"]]["opens"] == 0)
        aud = await db.fetchall("SELECT * FROM audit_log WHERE path LIKE '/api/replay/%'")
        check("fiecare deschidere → rând în audit_log, actor = link-ul, IP = client_ip",
              len(aud) == 5 and all(x["actor"].startswith("replay-link #") and x["ip"] == "203.0.113.7"
                                    for x in aud), [dict(x) for x in aud])
        check("audit: user-agent trunchiat, tokenul nicăieri",
              all(len(x["detail"]) <= 500 and "X" * 200 not in x["detail"] for x in aud)
              and not any(t in (x["path"] + x["detail"]) for x in aud for t in (tok_masked, tok_raw)))
        opens = await db.fetchall("SELECT * FROM replay_opens WHERE link_id=?", j["id"])
        check("jurnalul per link are deschiderile (IP + UA trunchiat)",
              len(opens) == 4 and all(len(o["user_agent"]) <= 160 for o in opens))
        ao1 = await db.fetchall("SELECT * FROM alerts WHERE kind='replay_opened' AND user_id=?", u1)
        ao2 = await db.fetchall("SELECT * FROM alerts WHERE kind='replay_opened' AND user_id=?", u2)
        check("alertă „deschis” → doar proprietarul, o dată per link în 10 min (2 link-uri deschise → 2)",
              len(ao1) == 2 and len(ao2) == 0, [dict(x) for x in ao1])
        check("alerta are IP-ul", all("203.0.113.7" in x["details"] for x in ao1))

        # ── limita de rată ───────────────────────────────────────────────────────────────
        replay.reset_limits()
        for _ in range(replay.MISS_MAX):
            await anon.get("/api/replay/meta", headers=_pub(security.new_token()))
        r = await anon.get("/api/replay/meta", headers=_pub(tok_masked))
        check("după prea multe tokenuri greşite, şi tokenul VALID primeşte 429 (fără oracol)",
              r.status_code == 429 and r.headers.get("retry-after") and
              r.headers.get("cache-control") == "no-store", r.status_code)
        replay.reset_limits()
        codes = [(await anon.get("/api/replay/meta", headers=_pub(tok_masked))).status_code
                 for _ in range(replay.RATE_MAX + 1)]
        check("plafonul total per IP: după RATE_MAX cereri → 429", codes[:-1] == [200] * replay.RATE_MAX
              and codes[-1] == 429, codes[-3:])
        replay.reset_limits()

        # ── revocare la schimbarea parolei ────────────────────────────────────────────────
        r = await a.post("/api/account", json={"current_password": PW1, "new_password": PW1 + "x"})
        check("parola schimbată", r.status_code == 200, r.text[:160])
        left = (await db.fetchone("SELECT COUNT(*) AS c FROM replay_links"))["c"]
        r = await anon.get("/api/replay/meta", headers=_pub(tok_masked))
        check("schimbarea parolei revocă link-urile de replay (global, ca share-urile)",
              left == 0 and r.status_code == 404, (left, r.status_code))
        check("…şi jurnalul lor de deschideri",
              (await db.fetchone("SELECT COUNT(*) AS c FROM replay_opens"))["c"] == 0)

        # ── revocare la ştergerea contului ────────────────────────────────────────────────
        r = await b.post(f"/api/sessions/{S_OK}/replay-links", json={})
        r = await a.post(f"/api/sessions/{S_OK}/replay-links", json={})
        r = await a.post(f"/api/users/{u2}/delete", json={"current_password": PW1 + "x"})
        check("contul 2 şters", r.status_code == 200, r.text[:160])
        check("ştergerea contului îi revocă link-urile, nu şi pe ale altora",
              (await db.fetchone("SELECT COUNT(*) AS c FROM replay_links WHERE user_id=?", u2))["c"] == 0
              and (await db.fetchone("SELECT COUNT(*) AS c FROM replay_links WHERE user_id=?", u1))["c"] == 1)

        # ── „Revocă tot" (panică, global) din inventarul de share-uri ────────────────────
        r = await a.post("/api/shares/revoke-all", json={"current_password": PW1 + "x"})
        check("panica globală acoperă şi link-urile de replay",
              r.status_code == 200 and r.json().get("revoked") == 1
              and (await db.fetchone("SELECT COUNT(*) AS c FROM replay_links"))["c"] == 0, r.text[:120])

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
