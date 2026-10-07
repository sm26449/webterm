"""Rezumatul de securitate (`GET /api/security/summary`) + inventarul share-urilor (3.5.4).

Ce fixează testul:
  · logica de status a fiecărei verificări, pe stare de DB construită de mână (nu pe ce se
    întâmplă să existe într-o instalare de test);
  · `GET /api/shares` NU conţine niciodată tokenul sau URL-ul — nici ca valoare, nici ca cheie;
  · `POST /api/shares/revoke-all` cere parola contului (401 fără), întoarce numărul, goleşte
    `share_token` pe TOATE rândurile, deconectează invitaţii live şi lasă urmă în audit;
  · un token de automatizare e refuzat pe toate trei: inventarul de acces e doar pentru oameni.
"""
import asyncio
import os
import sys
import tempfile
import time
import types

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, email_alerts, security, signing  # noqa: E402

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


# alertele pleacă în fundal pe SMTP/webhook — în test doar le numărăm
FIRED = []
email_alerts._fire = lambda subject, body, **k: FIRED.append(subject)


class FakeClient:
    def __init__(self, is_owner):
        self.is_owner = is_owner


class FakeHub:
    """Hub minimal: un owner + N invitaţi; `revoke_shares` îi scoate pe invitaţi, ca cel real."""
    def __init__(self, guests):
        self.clients = {FakeClient(True)} | {FakeClient(False) for _ in range(guests)}
        self.revoked = 0

    async def revoke_shares(self):
        self.revoked += 1
        self.clients = {c for c in self.clients if c.is_owner}


async def summary(c) -> dict:
    r = await c.get("/api/security/summary")
    assert r.status_code == 200, r.text
    return {x["id"]: x for x in r.json()["checks"]}


async def add_share(sid, host_id, token, writable=False, expires_in=3600, by="a@b.co"):
    await db.execute(
        "INSERT INTO sessions(id,host_id,title,state,created,rows,cols,share_token,share_expires,"
        " share_writable,share_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        sid, host_id, "titlu-" + sid[:4], "live", time.time(), 24, 80,
        security.sha256_hex(token), time.time() + expires_in, 1 if writable else 0, by)


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200, r.text[:120])
        uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]

        # ── forma răspunsului: fără proză, doar id/status/value ───────────────
        r = await c.get("/api/security/summary")
        body = r.json()
        ids = [x["id"] for x in body["checks"]]
        check("summary: verificările documentate, în ordine",
              ids == ["account2fa", "shares", "guardrail", "signingKey", "hosts2fa", "backup",
                      "alerts", "agents"], str(ids))
        check("summary: fiecare verificare are exact {id, status, value}",
              all(set(x) == {"id", "status", "value"} and isinstance(x["value"], dict)
                  and x["status"] in ("ok", "warn", "bad", "info") for x in body["checks"]))
        check("summary: TLS lipseşte (nu e cunoscut din aplicaţie — nu-l inventăm)",
              "tls" not in ids)

        # ── account2fa ────────────────────────────────────────────────────────
        s = await summary(c)
        check("account2fa: fără passkey şi fără TOTP → bad",
              s["account2fa"]["status"] == "bad", str(s["account2fa"]))
        await db.execute("INSERT INTO webauthn_credentials(user_id,credential_id,public_key,created)"
                         " VALUES(?,?,?,?)", uid, b"c1", b"k1", time.time())
        s = await summary(c)
        check("account2fa: 1 passkey, fără hosturi 2FA → ok",
              s["account2fa"]["status"] == "ok" and s["account2fa"]["value"]["passkeys"] == 1,
              str(s["account2fa"]))
        h2fa = (await c.post("/api/hosts", json={"name": "critic", "require_2fa": True})).json()["id"]
        hplain = (await c.post("/api/hosts", json={"name": "simplu"})).json()["id"]
        s = await summary(c)
        check("account2fa: 1 passkey, fără TOTP, cu hosturi 2FA → warn (o cheie pierdută = uşă închisă)",
              s["account2fa"]["status"] == "warn", str(s["account2fa"]))
        await db.execute("UPDATE users SET totp_enabled=1 WHERE id=?", uid)
        s = await summary(c)
        check("account2fa: + TOTP → ok", s["account2fa"]["status"] == "ok", str(s["account2fa"]))
        await db.execute("UPDATE users SET totp_enabled=0 WHERE id=?", uid)
        await db.execute("INSERT INTO webauthn_credentials(user_id,credential_id,public_key,created)"
                         " VALUES(?,?,?,?)", uid, b"c2", b"k2", time.time())
        s = await summary(c)
        check("account2fa: 2 passkey-uri → ok", s["account2fa"]["status"] == "ok", str(s["account2fa"]))

        # ── hosts2fa ──────────────────────────────────────────────────────────
        check("hosts2fa: info, 1 din 2",
              s["hosts2fa"]["status"] == "info" and s["hosts2fa"]["value"] == {"on": 1, "total": 2},
              str(s["hosts2fa"]))

        # ── guardrail ─────────────────────────────────────────────────────────
        check("guardrail: implicit (activ, cu reguli) → ok",
              s["guardrail"]["status"] == "ok" and s["guardrail"]["value"]["rules"] > 0,
              str(s["guardrail"]))
        await api._set_setting("command_guard", '{"enabled": false, "rules": [{"pattern": "x"}]}')
        s = await summary(c)
        check("guardrail: dezactivat → warn", s["guardrail"]["status"] == "warn", str(s["guardrail"]))
        await api._set_setting("command_guard", '{"enabled": true, "rules": []}')
        s = await summary(c)
        check("guardrail: activ dar 0 reguli → warn",
              s["guardrail"]["status"] == "warn" and s["guardrail"]["value"] == {"enabled": True, "rules": 0},
              str(s["guardrail"]))

        # ── signingKey ────────────────────────────────────────────────────────
        check("signingKey: lipsă → warn",
              s["signingKey"]["status"] == "warn" and s["signingKey"]["value"]["state"] == "missing",
              str(s["signingKey"]))
        signing.generate("cheie-cu-parola-1")
        signing.lock()
        s = await summary(c)
        check("signingKey: criptată şi blocată → bad",
              s["signingKey"]["status"] == "bad" and s["signingKey"]["value"]["state"] == "locked",
              str(s["signingKey"]))
        signing.load("cheie-cu-parola-1")
        s = await summary(c)
        check("signingKey: deblocată → ok", s["signingKey"]["status"] == "ok", str(s["signingKey"]))

        # ── backup ────────────────────────────────────────────────────────────
        check("backup: niciodată → bad",
              s["backup"]["status"] == "bad" and s["backup"]["value"]["last_ok"] is None,
              str(s["backup"]))
        await api._set_setting("backup_last", str(time.time() - 3600))
        s = await summary(c)
        check("backup: reuşit acum o oră → ok", s["backup"]["status"] == "ok", str(s["backup"]))
        check("backup: fără off-site → nu se pretinde criptat",
              s["backup"]["value"]["offsite"] is False and s["backup"]["value"]["encrypted"] is False,
              str(s["backup"]["value"]))
        await api._set_setting("backup_last", str(time.time() - 3 * 86400))
        s = await summary(c)
        check("backup: ultimul reuşit acum 3 zile (fără programare) → warn",
              s["backup"]["status"] == "warn", str(s["backup"]))
        await api._set_setting("backup_schedule", "weekly")
        s = await summary(c)
        check("backup: 3 zile pe o programare SĂPTĂMÂNALĂ → ok (nu zgomot)",
              s["backup"]["status"] == "ok", str(s["backup"]))
        await api._set_setting("backup_last_error",
                               '{"ts": %f, "error": "disk full", "stage": "snapshot"}' % time.time())
        s = await summary(c)
        check("backup: ultima încercare a eşuat → bad, cu etapa (fără textul erorii)",
              s["backup"]["status"] == "bad" and s["backup"]["value"]["failed_stage"] == "snapshot"
              and "disk full" not in str(s["backup"]), str(s["backup"]))
        await api._set_setting("backup_last_error", "")

        # ── alerts ────────────────────────────────────────────────────────────
        check("alerts: nici SMTP, nici webhook → warn",
              s["alerts"]["status"] == "warn" and s["alerts"]["value"] == {"smtp": False, "webhook": False},
              str(s["alerts"]))
        hook = "https://hooks.example.com/services/SECRET-PATH-123"
        await api._set_setting("alert_webhook", hook)
        await api._set_setting("smtp_password_enc", security.encrypt_secret("smtp-parola-secreta"))
        r = await c.get("/api/security/summary")
        s = {x["id"]: x for x in r.json()["checks"]}
        check("alerts: webhook configurat → ok", s["alerts"]["status"] == "ok", str(s["alerts"]))
        check("alerts: răspunsul nu scurge URL-ul webhook-ului sau parola SMTP",
              "SECRET-PATH" not in r.text and "smtp-parola" not in r.text)

        # ── agents ────────────────────────────────────────────────────────────
        expected = core.agent_expected()["version"]
        check("agents: versiunea livrată e citită", isinstance(expected, int), str(expected))
        check("agents: niciun agent online → ok, offline numărat separat",
              s["agents"]["status"] == "ok" and s["agents"]["value"]["offline"] == 2
              and s["agents"]["value"]["online"] == 0, str(s["agents"]))
        core.sources[hplain] = types.SimpleNamespace(agent_version=expected)
        s = await summary(c)
        check("agents: online pe versiunea curentă → ok",
              s["agents"]["status"] == "ok" and s["agents"]["value"]["online"] == 1, str(s["agents"]))
        core.sources[hplain] = types.SimpleNamespace(agent_version=expected - 1)
        s = await summary(c)
        check("agents: un agent online mai vechi → warn",
              s["agents"]["status"] == "warn" and s["agents"]["value"]["outdated"] == 1
              and s["agents"]["value"]["offline"] == 1, str(s["agents"]))
        core.sources.pop(hplain, None)

        # ── shares: status + inventar ─────────────────────────────────────────
        check("shares: niciun link → ok", s["shares"]["status"] == "ok", str(s["shares"]))
        r = await c.get("/api/shares")
        check("/api/shares gol → listă goală + 0 ascunse",
              r.status_code == 200 and r.json() == {"shares": [], "hidden": 0}, r.text[:120])

        tok_ro, tok_rw, tok_2fa, tok_old = ("TOKRO" + "x" * 20, "TOKRW" + "y" * 20,
                                            "TOK2FA" + "z" * 20, "TOKOLD" + "w" * 20)
        sid_ro, sid_rw, sid_2fa, sid_old = "a" * 32, "b" * 32, "c" * 32, "d" * 32
        await add_share(sid_ro, hplain, tok_ro)
        s = await summary(c)
        check("shares: un link read-only → warn",
              s["shares"]["status"] == "warn" and s["shares"]["value"] == {"active": 1, "writable": 0},
              str(s["shares"]))
        await add_share(sid_rw, hplain, tok_rw, writable=True, by="coleg@b.co")
        await add_share(sid_2fa, h2fa, tok_2fa)
        await add_share(sid_old, hplain, tok_old, expires_in=-60)        # expirat: nu contează
        s = await summary(c)
        check("shares: oricare writable → bad; expiratul nu se numără; cel 2FA da",
              s["shares"]["status"] == "bad" and s["shares"]["value"] == {"active": 3, "writable": 1},
              str(s["shares"]))

        core.hubs[sid_rw] = FakeHub(guests=2)
        hub_ro = core.hubs[sid_ro] = FakeHub(guests=1)
        security.clear_stepup_for(uid)
        r = await c.get("/api/shares")
        data = r.json()
        rows = {x["sid"]: x for x in data["shares"]}
        check("/api/shares: cele 2 vizibile, cel de pe hostul 2FA ascuns (fără fereastră)",
              set(rows) == {sid_ro, sid_rw} and data["hidden"] == 1, str(data)[:300])
        rw = rows.get(sid_rw, {})
        check("/api/shares: câmpurile rândului",
              rw.get("title") == "titlu-bbbb" and rw.get("host_name") == "simplu"
              and rw.get("by") == "coleg@b.co" and rw.get("writable") is True
              and rw.get("expires", 0) > time.time() and rw.get("host_id") == hplain, str(rw))
        check("/api/shares: invitaţii conectaţi (owner-ul nu se numără)",
              rw.get("viewers") == 2 and rows.get(sid_ro, {}).get("viewers") == 1, str(rows))

        def leaks(text, payload):
            keys = set()

            def walk(o):
                if isinstance(o, dict):
                    for k, v in o.items():
                        keys.add(k.lower())
                        walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)
            walk(payload)
            bad_keys = {k for k in keys if "token" in k or "url" in k or "hash" in k}
            secrets = [tok_ro, tok_rw, tok_2fa, tok_old]
            bad_vals = [t for t in secrets if t in text or security.sha256_hex(t) in text]
            return bad_keys, bad_vals or ("/#/shared/" in text and ["url"])

        bk, bv = leaks(r.text, data)
        check("/api/shares: nicio cheie token/url/hash", not bk, str(bk))
        check("/api/shares: nici tokenul, nici hash-ul lui, nici un URL de share", not bv, str(bv))

        security.open_stepup_window(uid, h2fa)
        r = await c.get("/api/shares")
        data = r.json()
        check("/api/shares: cu fereastră de step-up pe hostul 2FA → apare şi el",
              {x["sid"] for x in data["shares"]} == {sid_ro, sid_rw, sid_2fa} and data["hidden"] == 0,
              str(data)[:300])
        bk, bv = leaks(r.text, data)
        check("/api/shares (cu 2FA deschis): tot fără token/url", not bk and not bv, f"{bk} {bv}")
        security.clear_stepup_for(uid)

        # ── revoke-all ────────────────────────────────────────────────────────
        r = await c.post("/api/shares/revoke-all", json={})
        check("revoke-all FĂRĂ parola contului → 401", r.status_code == 401, r.text[:120])
        r = await c.post("/api/shares/revoke-all", json={"current_password": "gresita99"})
        check("revoke-all cu parolă greşită → 401", r.status_code == 401, r.text[:120])
        left = await db.fetchone("SELECT COUNT(*) c FROM sessions WHERE share_token IS NOT NULL")
        check("refuzul nu a atins nimic", left["c"] == 4, str(left["c"]))

        FIRED.clear()
        r = await c.post("/api/shares/revoke-all", json={"current_password": PW})
        check("revoke-all cu parola → 200", r.status_code == 200, r.text[:160])
        check("revoke-all: întoarce numărul de link-uri ACTIVE revocate (inclusiv cel 2FA ascuns)",
              r.json().get("revoked") == 3, r.text[:160])
        left = await db.fetchone("SELECT COUNT(*) c FROM sessions WHERE share_token IS NOT NULL"
                                 " OR share_expires IS NOT NULL OR share_writable=1")
        check("revoke-all: share_token NULL pe toate rândurile (şi expirat)", left["c"] == 0, str(left["c"]))
        check("revoke-all: invitaţii live sunt deconectaţi (hub.revoke_shares)",
              core.hubs[sid_rw].revoked == 1 and hub_ro.revoked == 1
              and api._share_guests(sid_rw) == 0, f"{core.hubs[sid_rw].revoked} {hub_ro.revoked}")
        check("revoke-all: alertă de securitate trimisă",
              any("share links were revoked" in x for x in FIRED), str(FIRED))
        await asyncio.sleep(0.05)
        a = await db.fetchone("SELECT status, detail, actor FROM audit_log WHERE path=?"
                              " ORDER BY id DESC LIMIT 1", "/api/shares/revoke-all")
        check("revoke-all: scris în audit (actor + detaliu)",
              a is not None and a["status"] == 200 and "revoked all share links (3 active)" in a["detail"]
              and a["actor"] == "a@b.co", str(dict(a) if a else None))
        s = await summary(c)
        check("după revoke-all: shares → ok", s["shares"]["status"] == "ok", str(s["shares"]))
        r = await c.post("/api/shares/revoke-all", json={"current_password": PW})
        check("revoke-all pe nimic → 200, 0", r.status_code == 200 and r.json()["revoked"] == 0, r.text)
        core.hubs.pop(sid_rw, None)
        core.hubs.pop(sid_ro, None)

        # ── cont SSO: parola locală nu există → re-auth-ul lui real (fereastra account-scope) ──
        prev_oidc = config.OIDC_ENABLED
        config.OIDC_ENABLED = True
        await db.execute("UPDATE users SET sso_subject='sub-1' WHERE id=?", uid)
        r = await c.post("/api/shares/revoke-all", json={"current_password": PW})
        check("SSO fără re-auth proaspăt → 403 shares.ssoReauth (parola locală nu contează)",
              r.status_code == 403 and r.json().get("code") == "shares.ssoReauth", r.text[:160])
        security.open_stepup_window(uid, 0)
        r = await c.post("/api/shares/revoke-all", json={})
        check("SSO cu fereastra account-scope deschisă → 200", r.status_code == 200, r.text[:160])
        security.clear_stepup_for(uid)
        await db.execute("UPDATE users SET sso_subject=NULL WHERE id=?", uid)
        config.OIDC_ENABLED = prev_oidc

        # ── token de automatizare: refuzat pe toate trei ─────────────────────
        raw = security.TOKEN_PREFIX + security.new_token()
        await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by, expires)"
                         " VALUES(?,?,?,?,?,?)", "ci", security.sha256_hex(raw), "read,run",
                         time.time(), "a@b.co", time.time() + 3600)
        await add_share("e" * 32, hplain, "TOKNEW" + "q" * 20)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers={**_ORIGIN, "Authorization": "Bearer " + raw}) as bot:
        check("controlul: tokenul chiar e valid pe o rută `read`",
              (await bot.get("/api/sessions")).status_code == 200)
        for method, path, js in (("GET", "/api/security/summary", None), ("GET", "/api/shares", None),
                                 ("POST", "/api/shares/revoke-all", {"current_password": PW})):
            r = await bot.request(method, path, json=js)
            check(f"token de automatizare pe {method} {path} → 401/403",
                  r.status_code in (401, 403), f"{r.status_code} {r.text[:100]}")
        left = await db.fetchone("SELECT COUNT(*) c FROM sessions WHERE share_token IS NOT NULL")
        check("tokenul nu a revocat nimic", left["c"] == 1, str(left["c"]))
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as anon:
        for path in ("/api/security/summary", "/api/shares"):
            check(f"anonim pe {path} → 401", (await anon.get(path)).status_code == 401)

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
