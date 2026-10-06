"""Export / import CSV al hosturilor (3.5.4) — hermetic.

Ce fixează testul:
  · exportul: antetul şi ordinea coloanelor, BOM-ul UTF-8, ghilimelele RFC 4180, neutralizarea
    CSV injection (= + - @), numele de fişier, `via_host` = NUMELE agentului, ţintele efemere
    lăsate afară, hosturile 2FA incluse fără step-up;
  · NICIUN secret în octeţii CSV-ului: parolă/cheie/passphrase stocate, tokenul de enroll,
    tokenul agentului (clar + hash), instance id, pinul known_hosts, tokenul de share;
  · importul: fiecare cod de eroare pe rândul lui, duplicatele sărite (serverul re-verifică),
    via_host rezolvat după nume — inclusiv un agent din ACELAŞI fişier, aflat DUPĂ ţinta jump;
    plafonul de 500, opţiunile (folder, etichete, politica), auditul;
  · un token de automatizare e refuzat pe ambele rute;
  · drumul complet: export din instanţa A → import într-o instanţă NOUĂ (DB gol) → aceleaşi
    hosturi (nume, tip, adresă, port, user, folder, etichete, notă, 2FA, relaţia via).
"""
import asyncio
import csv
import io
import os
import re
import sys
import tempfile
import time

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
HEADER = ["name", "connection_type", "hostname", "port", "username", "via_host", "folder", "tags",
          "note", "require_2fa", "credential_policy", "auth_method", "agent_note"]


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


_TRIGGER = re.compile(r"^'+[=+\-@\t\r]")


def unneutralize(cell: str) -> str:
    """Oglinda lui `stripFormulaPrefix` din frontend/src/lib/hostscsv.ts: scoate EXACT un `'`."""
    return cell[1:] if _TRIGGER.match(cell) else cell


def parse_csv(raw: bytes) -> list:
    text = raw.decode("utf-8")
    if text.startswith("﻿"):
        text = text[1:]
    rows = list(csv.reader(io.StringIO(text, newline="")))
    head, body = rows[0], rows[1:]
    return [{k: unneutralize(v) for k, v in zip(head, r)} for r in body]


SECRET_PW = "Parola-Super-Secreta-42"
# Cheie FALSĂ, compusă din bucăţi: un antet `BEGIN … PRIVATE KEY` literal declanşează scanerul de
# secrete din CI (gitleaks) chiar şi pe un fixture — iar testul are nevoie doar de un şir unic.
_PK = "PRIVATE " + "KEY"
SECRET_KEY = ("-----BEGIN OPENSSH " + _PK + "-----\nb3BlbnNzaC1rZXktdjEAAAAAPRIVATEKEYMATERIAL"
              "\n-----END OPENSSH " + _PK + "-----\n")
SECRET_PASSPHRASE = "pass-phrase-de-nespus"
PIN = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPINNEDHOSTKEYVALUEXYZ"
INSTANCE = "instance-id-0123456789abcdef"
SHARE = "SHARETOKEN" + "s" * 30


async def setup_account(c) -> None:
    r = await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
    assert r.status_code == 200, r.text


async def seed(c) -> dict:
    ids = {}

    async def mk(key, **body):
        r = await c.post("/api/hosts", json=body)
        assert r.status_code == 200, (key, r.text)
        ids[key] = r.json()["id"]

    await mk("gw", name="gw-bucureşti", folder="Producţie", tags="prod, ro", note="poarta, \"principală\"")
    await mk("web", name="web01", connection_type="ssh", hostname="10.0.0.5", ssh_port=2222,
             ssh_username="deploy", auth_method="password", credential=SECRET_PW,
             credential_policy="stored", folder="Producţie", tags="prod web",
             note="linia 1\nlinia 2")
    await mk("db", name="db-intern", connection_type="ssh-jump", hostname="192.168.1.10",
             ssh_username="root", auth_method="key", credential=SECRET_KEY,
             passphrase=SECRET_PASSPHRASE, credential_policy="stored", via_host_id=ids["gw"],
             require_2fa=True, note="=HYPERLINK(\"http://evil\")")
    await mk("sw", name="switch-core", connection_type="telnet", hostname="10.0.0.1",
             ssh_port=23, credential_policy="ask", note="@cmd|' /C calc'!A0")
    await mk("tj", name="+router", connection_type="telnet-jump", hostname="172.16.0.1",
             via_host_id=ids["gw"], credential_policy="ask", note="-dash, 'quoted'")
    await mk("eph", name="o-singura-data", connection_type="ssh-jump", hostname="10.9.9.9",
             ssh_username="x", via_host_id=ids["gw"], credential_policy="ask", ephemeral=True)
    await db.execute("UPDATE hosts SET known_hosts=?, instance_id=? WHERE id=?", PIN, INSTANCE, ids["web"])
    await db.execute("UPDATE hosts SET instance_id=? WHERE id=?", INSTANCE, ids["gw"])
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,rows,cols,share_token,share_expires)"
        " VALUES(?,?,?,?,?,?,?,?,?)", "f" * 32, ids["web"], "t", "live", time.time(), 24, 80,
        SHARE, time.time() + 3600)
    return ids


def norm_host(h: dict, names: dict) -> tuple:
    return (h["name"], h["connection_type"], h["hostname"] or "",
            h["ssh_port"] if h["connection_type"] != "agent" else None,
            h["ssh_username"] or "", names.get(h["via_host_id"], ""), h["folder"],
            tuple(sorted(h["tags"])), h["note"], h["require_2fa"])


async def snapshot(c) -> list:
    hs = [h for h in (await c.get("/api/hosts")).json() if not h["ephemeral"]]
    names = {h["id"]: h["name"] for h in hs}
    return sorted(norm_host(h, names) for h in hs)


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        await setup_account(c)
        ids = await seed(c)
        all_ids = ",".join(str(i) for i in ids.values())

        # ── export: forma ────────────────────────────────────────────────────
        r = await c.get("/api/hosts/export.csv?ids=" + all_ids)
        check("export → 200", r.status_code == 200, r.text[:200])
        raw = r.content
        check("export: text/csv; charset=utf-8",
              r.headers.get("content-type") == "text/csv; charset=utf-8", r.headers.get("content-type"))
        cd = r.headers.get("content-disposition", "")
        check("export: attachment webterm-hosts-YYYYMMDD.csv",
              re.fullmatch(r'attachment; filename="webterm-hosts-\d{8}\.csv"', cd) is not None, cd)
        check("export: începe cu BOM UTF-8", raw.startswith(b"\xef\xbb\xbf"), raw[:8])
        text = raw.decode("utf-8")[1:]
        check("export: antetul exact, în ordine",
              text.split("\r\n", 1)[0] == ",".join(HEADER), text.split("\r\n", 1)[0])
        check("export: rânduri terminate CRLF (RFC 4180)", text.endswith("\r\n") and "\r\n" in text)
        rows = parse_csv(raw)
        by = {x["name"]: x for x in rows}
        check("export: ţinta efemeră („conectează o dată”) NU intră",
              "o-singura-data" not in by and len(rows) == 5, sorted(by))
        check("export: hostul 2FA intră fără step-up (doar metadate), require_2fa=1",
              by.get("db-intern", {}).get("require_2fa") == "1"
              and by["web01"]["require_2fa"] == "0", str(by.get("db-intern")))
        check("export: via_host = NUMELE agentului, nu id-ul",
              by["db-intern"]["via_host"] == "gw-bucureşti"
              and by["+router"]["via_host"] == "gw-bucureşti" and by["web01"]["via_host"] == "", str(by["db-intern"]))
        check("export: agent_note doar la agenţi",
              by["gw-bucureşti"]["agent_note"] == "reinstall the agent on the new gateway"
              and by["web01"]["agent_note"] == "", str(by["gw-bucureşti"]))
        check("export: agentul n-are port/user/politică/metodă",
              [by["gw-bucureşti"][k] for k in ("port", "username", "credential_policy", "auth_method")]
              == ["", "", "", ""], str(by["gw-bucureşti"]))
        w = by["web01"]
        check("export: câmpurile SSH",
              (w["connection_type"], w["hostname"], w["port"], w["username"], w["folder"],
               w["credential_policy"], w["auth_method"])
              == ("ssh", "10.0.0.5", "2222", "deploy", "Producţie", "stored", "password"), str(w))
        check("export: etichetele separate prin spaţiu", w["tags"] == "prod web", w["tags"])
        check("export: diacriticele întregi (UTF-8)", "gw-bucureşti" in text and "Producţie" in text)
        check("export: virgulă + ghilimele în celulă → citat RFC 4180 (\"\" pentru ghilimele)",
              '"poarta, ""principală"""' in text, text[:400])
        check("export: newline în celulă → citat, păstrat", w["note"] == "linia 1\nlinia 2", repr(w["note"]))
        # CSV injection: celulele brute (înainte de strip) încep cu `'`
        rawcells = {r_[0]: r_ for r_ in csv.reader(io.StringIO(text, newline=""))}
        check("injecţie: = neutralizat cu '", rawcells["db-intern"][8].startswith("'=HYPERLINK"),
              rawcells["db-intern"][8])
        check("injecţie: @ neutralizat", rawcells["switch-core"][8].startswith("'@cmd"))
        check("injecţie: - neutralizat", rawcells["'+router"][8].startswith("'-dash"))
        check("injecţie: + neutralizat (şi în coloana name)", "'+router" in rawcells)
        check("injecţie: strip-ul la import redă valoarea exactă",
              by["db-intern"]["note"] == '=HYPERLINK("http://evil")' and by["+router"]["note"] == "-dash, 'quoted'")
        check("injecţie: celula „'=x” se dublează ('' ) ca round-trip-ul să fie fără pierderi",
              api._csv_cell("'=x") == "''=x" and unneutralize(api._csv_cell("'=x")) == "'=x"
              and api._csv_cell("'normal") == "'normal")

        # ── niciun secret în octeţi ──────────────────────────────────────────
        hrows = {x["id"]: x for x in await db.fetchall("SELECT * FROM hosts")}
        secrets = {"parola stocată": SECRET_PW, "cheia privată": "PRIVATEKEYMATERIAL",
                   "passphrase": SECRET_PASSPHRASE, "pin known_hosts": "PINNEDHOSTKEYVALUE",
                   "instance id": INSTANCE, "token de share": SHARE}
        for hid, hr in hrows.items():
            for col in ("enroll_token", "token_hash", "token_encrypted", "credential_encrypted",
                        "enroll_pass_hash"):
                if hr[col]:
                    secrets[f"{col} #{hid}"] = hr[col]
            if hr["token_encrypted"]:
                secrets[f"token agent clar #{hid}"] = security.decrypt_secret(hr["token_encrypted"])
        check("seed-ul chiar are tokenuri de enroll + credenţiale (testul nu e gol)",
              any(k.startswith("enroll_token") for k in secrets)
              and any(k.startswith("credential_encrypted") for k in secrets), str(list(secrets)[:6]))
        leaked = [k for k, v in secrets.items() if v and v.encode() in raw]
        check("export: NICIUN secret în octeţii CSV", not leaked, str(leaked))
        check("export: nicio coloană cu nume de secret",
              not any(s in h for h in HEADER for s in ("token", "credential_enc", "key", "pass", "known", "instance")),
              str(HEADER))

        r = await c.get("/api/hosts/export.csv")
        check("export fără ids → 400 hostcsv.noIds", r.status_code == 400 and r.json().get("code") == "hostcsv.noIds", r.text)
        r = await c.get("/api/hosts/export.csv?ids=1,abc")
        check("export cu ids invalide → 400 hostcsv.badIds", r.status_code == 400 and r.json().get("code") == "hostcsv.badIds", r.text)
        r = await c.get("/api/hosts/export.csv?ids=%d" % ids["eph"])
        check("export doar al hostului efemer → antet gol", r.status_code == 200 and len(parse_csv(r.content)) == 0)

        await asyncio.sleep(0.05)
        a = await db.fetchone("SELECT status, detail, actor FROM audit_log WHERE path=?"
                              " AND detail LIKE 'exported%' ORDER BY id ASC LIMIT 1",
                              "/api/hosts/export.csv")
        check("export: urmă în audit cu numărul", a is not None and a["detail"] == "exported 5 hosts as CSV"
              and a["actor"] == "a@b.co", str(dict(a) if a else None))

        # ── import: un cod de eroare pe fiecare rând ─────────────────────────
        def row(**kw):
            base = {"name": "", "connection_type": "ssh", "hostname": "", "port": "", "username": "",
                    "via_host": ""}
            base.update(kw)
            return base

        cases = [
            (row(name="", hostname="1.1.1.1", username="u"), "host.nameRequired"),
            (row(name="n-type", connection_type=""), "hostcsv.typeRequired"),
            (row(name="n-bad", connection_type="rdp", hostname="h"), "host.badType"),
            (row(name="n-host", hostname="", username="u"), "host.hostnameRequired"),
            (row(name="n-user", hostname="h1"), "ssh.userRequired"),
            (row(name="n-port", hostname="h2", username="u", port="99999"), "host.badPort"),
            (row(name="n-port2", hostname="h2", username="u", port="22a"), "host.badPort"),
            (row(name="n-auth", hostname="h3", username="u", auth_method="parola"), "host.badAuthMethod"),
            (row(name="n-pol", hostname="h4", username="u", credential_policy="never"), "host.badCredentialPolicy"),
            (row(name="n-via0", connection_type="ssh-jump", hostname="h5", username="u"), "hostcsv.viaRequired"),
            (row(name="n-via1", connection_type="ssh-jump", hostname="h5", username="u",
                 via_host="nu-exista"), "hostcsv.viaMissing"),
            (row(name="n-via2", connection_type="telnet-jump", hostname="h6", via_host="web01"),
             "sshjump.needsAgent"),
            (row(name="WEB01", hostname="9.9.9.9", username="x"), "hostcsv.duplicate"),
            (row(name="alt-nume", hostname="10.0.0.5", port="2222", username="DEPLOY"), "hostcsv.duplicate"),
            ("nu-e-obiect", "hostcsv.badRow"),
        ]
        r = await c.post("/api/hosts/import", json={"rows": [x for x, _ in cases]})
        check("import cu erori → 200 (rezultat per rând)", r.status_code == 200, r.text[:200])
        res = r.json()
        got = [x.get("code") for x in res["results"]]
        want = [code for _, code in cases]
        for (x, code), g in zip(cases, got):
            nm = x["name"] if isinstance(x, dict) else x
            check(f"import: rândul „{nm}” → {code}", g == code, str(g))
        check("import: niciun host creat din rândurile greşite", res["created"] == 0
              and res["skipped"] == len(cases), str(res)[:200])
        check("import: index-urile acoperă toate rândurile, în ordine",
              [x["index"] for x in res["results"]] == list(range(len(cases))))
        check("import: duplicatele marcate skipped, erorile nu",
              res["results"][12]["skipped"] is True and res["results"][0]["skipped"] is False)
        check("import: vars la via lipsă (numele)", res["results"][10].get("vars") == {"name": "nu-exista"},
              str(res["results"][10]))
        n_before = (await db.fetchone("SELECT COUNT(*) c FROM hosts"))["c"]
        await db.execute(
            "INSERT INTO hosts(name, token_hash, token_encrypted, created, connection_type)"
            " VALUES(?,?,?,?,?)", "GW-Bucureşti", "dup-hash", "x", time.time(), "agent")
        r = await c.post("/api/hosts/import", json={"rows": [
            row(name="ambiguu", connection_type="ssh-jump", hostname="h7", username="u",
                via_host="gw-bucureşti")]})
        check("import: doi agenţi cu acelaşi nume → hostcsv.viaAmbiguous",
              r.json()["results"][0].get("code") == "hostcsv.viaAmbiguous", r.text[:200])
        await db.execute("DELETE FROM hosts WHERE token_hash='dup-hash'")
        check("refuzurile n-au scris nimic", (await db.fetchone("SELECT COUNT(*) c FROM hosts"))["c"]
              == n_before, str(n_before))

        # ── import: via după nume, cu agentul DUPĂ ţinta în acelaşi fişier ───
        mixed = [
            row(name="tinta-prin-nou", connection_type="ssh-jump", hostname="10.1.1.1",
                username="ops", via_host="agent-nou", tags="a", note="prin agentul din fişier"),
            row(name="agent-nou", connection_type="agent", hostname="masina-noua", folder="Lab",
                port="1234", username="ignorat"),
            row(name="direct-1", hostname="10.2.2.2", username="u", port="", require_2fa="1",
                credential_policy="stored", auth_method="key"),
            row(name="direct-1", hostname="10.2.2.3", username="u"),          # duplicat în fişier
            row(name="tel-1", connection_type="telnet", hostname="10.3.3.3", port=""),
        ]
        r = await c.post("/api/hosts/import", json={"rows": mixed, "options": {
            "folder": "Importate", "tags": "csv, Nou", "credential_policy": "ask"}})
        res = r.json()
        check("import mixt → 200, 4 create, 1 sărit", r.status_code == 200 and res["created"] == 4
              and res["skipped"] == 1, str(res)[:300])
        rs = res["results"]
        check("import: ţinta jump (rândul 0) găseşte agentul de pe rândul 1 (agenţii intră primii)",
              rs[0]["ok"] and rs[1]["ok"], str(rs[:2]))
        check("import: al doilea „direct-1” e duplicat (serverul vede rândul creat înainte)",
              rs[3].get("code") == "hostcsv.duplicate" and rs[3]["skipped"], str(rs[3]))
        check("import: agentul primeşte comanda lui de instalare (fără link de grup)",
              "install_command" in rs[1] and "/install/" in rs[1]["install_command"]
              and "/install/group/" not in rs[1]["install_command"]
              and "install_command" not in rs[0], str(rs[1])[:200])
        ag = await db.fetchone("SELECT * FROM hosts WHERE id=?", rs[1]["id"])
        check("import: agentul e în aşteptare (enroll_token, TTL ~24h, fără versiune)",
              ag["enroll_token"] and ag["agent_version"] is None
              and 86000 < ag["enroll_expires"] - time.time() <= 86400
              and ag["enroll_token"] in rs[1]["install_command"], str(dict(ag))[:200])
        check("import: agentul n-are port/user din CSV (le raportează agentul)",
              ag["ssh_username"] is None and ag["hostname"] == "masina-noua", str(dict(ag))[:200])
        jt = await db.fetchone("SELECT * FROM hosts WHERE id=?", rs[0]["id"])
        check("import: ţinta jump legată de noul agent", jt["via_host_id"] == rs[1]["id"], str(jt["via_host_id"]))
        check("import: opţiunea folder bate folderul din fişier",
              jt["folder"] == "Importate" and ag["folder"] == "Importate")
        check("import: etichetele extra se adaugă (normalizate)", jt["tags"] == "a,csv,nou", jt["tags"])
        d1 = await db.fetchone("SELECT * FROM hosts WHERE id=?", rs[2]["id"])
        check("import: politica din opţiuni (ask) bate coloana; fără credenţial stocat",
              d1["credential_policy"] == "ask" and d1["credential_encrypted"] is None
              and d1["auth_method"] == "key" and d1["require_2fa"] == 1 and d1["ssh_port"] == 22,
              str(dict(d1))[:300])
        t1 = await db.fetchone("SELECT * FROM hosts WHERE id=?", rs[4]["id"])
        check("import: telnet fără port → 23", t1["ssh_port"] == 23, str(t1["ssh_port"]))
        check("import: agentul are politica implicită (stored), nu opţiunea",
              ag["credential_policy"] == "stored")
        await asyncio.sleep(0.05)
        a = await db.fetchone("SELECT detail FROM audit_log WHERE path=? ORDER BY id DESC LIMIT 1",
                              "/api/hosts/import")
        check("import: audit „imported N hosts (M skipped)”",
              a is not None and a["detail"] == "imported 4 hosts (1 skipped)", str(dict(a) if a else None))

        # opţiune de politică invalidă → refuz întreg, cu codul comun
        r = await c.post("/api/hosts/import", json={"rows": [], "options": {"credential_policy": "x"}})
        check("import: politică invalidă în opţiuni → 400 host.badCredentialPolicy",
              r.status_code == 400 and r.json().get("code") == "host.badCredentialPolicy", r.text)

        # ── plafonul ─────────────────────────────────────────────────────────
        many = [row(name=f"h{i}", hostname=f"10.8.{i // 250}.{i % 250}", username="u") for i in range(501)]
        n0 = (await db.fetchone("SELECT COUNT(*) c FROM hosts"))["c"]
        r = await c.post("/api/hosts/import", json={"rows": many})
        check("import: 501 rânduri → 400 hostcsv.tooMany {max: 500}",
              r.status_code == 400 and r.json().get("code") == "hostcsv.tooMany"
              and r.json().get("vars") == {"max": 500}, r.text[:200])
        check("import: peste plafon nu scrie nimic", (await db.fetchone("SELECT COUNT(*) c FROM hosts"))["c"] == n0)
        r = await c.post("/api/hosts/import", json={"rows": many[:500]})
        check("import: exact 500 rânduri → acceptat", r.status_code == 200 and r.json()["created"] == 500,
              r.text[:200])
        await db.execute("DELETE FROM hosts WHERE name GLOB 'h[0-9]*'")

        # ── validarea comună: POST /api/hosts are aceleaşi coduri noi ────────
        for body, code in (({"name": "  "}, "host.nameRequired"),
                           ({"name": "p", "connection_type": "ssh", "hostname": "h", "ssh_username": "u",
                             "ssh_port": 0}, "host.badPort"),
                           ({"name": "p", "connection_type": "ssh", "hostname": "h", "ssh_username": "u",
                             "auth_method": "x"}, "host.badAuthMethod")):
            r = await c.post("/api/hosts", json=body)
            check(f"POST /api/hosts → {code} (aceeaşi validare ca importul)",
                  r.status_code == 400 and r.json().get("code") == code, r.text[:160])

        # ── token de automatizare: refuzat ───────────────────────────────────
        tok = security.TOKEN_PREFIX + security.new_token()
        await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by, expires)"
                         " VALUES(?,?,?,?,?,?)", "ci", security.sha256_hex(tok), "read,run",
                         time.time(), "a@b.co", time.time() + 3600)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers={**_ORIGIN, "Authorization": "Bearer " + tok}) as bot:
        check("controlul: tokenul e valid pe o rută `read`", (await bot.get("/api/hosts")).status_code == 200)
        r = await bot.get("/api/hosts/export.csv?ids=" + all_ids)
        check("token pe export → 401/403", r.status_code in (401, 403), f"{r.status_code} {r.text[:80]}")
        r = await bot.post("/api/hosts/import", json={"rows": [row(name="bot", hostname="1.2.3.4", username="u")]})
        check("token pe import → 401/403", r.status_code in (401, 403), f"{r.status_code} {r.text[:80]}")
        check("tokenul nu a creat nimic", not await db.fetchone("SELECT 1 FROM hosts WHERE name='bot'"))
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as anon:
        check("anonim pe export → 401", (await anon.get("/api/hosts/export.csv?ids=1")).status_code == 401)

    # ── drumul complet: instanţa A → instanţa B (DB nou, gol) ────────────────
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        r = await c.post("/api/login", json={"email": "a@b.co", "password": PW})
        assert r.status_code == 200, r.text
        # doar hosturile seed-ului original (agentul + jump-urile lui + directele)
        src_ids = [ids[k] for k in ("gw", "web", "db", "sw", "tj")]
        exported = (await c.get("/api/hosts/export.csv?ids=" + ",".join(map(str, src_ids)))).content
        hs = [h for h in (await c.get("/api/hosts")).json() if h["id"] in src_ids]
        names = {h["id"]: h["name"] for h in (await c.get("/api/hosts")).json()}
        before = sorted(norm_host(h, names) for h in hs)

    await db.close()
    config.DB_PATH = config.DATA_DIR / "instanta-b.db"
    await db.connect()
    await api.init_setup_token()
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        await setup_account(c)
        check("instanţa B e goală", (await c.get("/api/hosts")).json() == [])
        rows_b = parse_csv(exported)
        # jump-urile ÎNAINTEA agentului în fişier: ordinea nu trebuie să conteze
        rows_b.sort(key=lambda x: x["connection_type"] == "agent")
        r = await c.post("/api/hosts/import", json={"rows": rows_b})
        check("round-trip: toate rândurile create", r.status_code == 200 and r.json()["created"] == 5,
              r.text[:300])
        after = await snapshot(c)
        check("round-trip: aceleaşi hosturi (nume, tip, adresă, port, user, via, folder, etichete, notă, 2FA)",
              after == before, f"\nA={before}\nB={after}")
        r = await c.post("/api/hosts/import", json={"rows": rows_b})
        check("round-trip: re-importul aceluiaşi fişier sare tot (5 duplicate)",
              r.json()["created"] == 0 and all(x.get("code") == "hostcsv.duplicate" for x in r.json()["results"]),
              r.text[:300])

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
