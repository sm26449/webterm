"""SCIM 2.0 (3.6.11): ce înseamnă „dezactivat" — şi că ţine.

Instanţă hermetică; IdP-ul e simulat cu cereri SCIM în forma Authentik. Ce se verifică:
  * `active:false` (PATCH) dezactivează: sesiunile web dispar şi cookie-ul vechi dă 401, un
    terminal DESCHIS se închide pe loc (epoch bump, fără tick de 60 s), biletele de forward mor,
    tokenurile de automatizare sunt revocate (şterse, nu doar golite), share-urile live şi link-urile
    de replay sunt revocate, drepturile sunt GOALE (legăturile rămân, pentru o reactivare); audit +
    alertă în istoricul celor cu security.view;
  * un cont dezactivat nu intră: parola corectă → 403 `auth.accountDisabled` (cea greşită → 401,
    fără oracol), passkey → 403, SSO → redirect `sso_error=disabled`, fără sesiune nouă;
    `create_web_session` refuză şi el (plasă);
  * DELETE = dezactivare + dezlegare (contul şi istoricul rămân; GET pe resursă → 404); o re-creare
    a aceleiaşi persoane îl readoptă şi îl reactivează;
  * ultimul Owner PERMANENT nu poate fi dezactivat nici şters prin SCIM (403, audit, alertă
    critică); cu un al doilea Owner permanent, da — iar un Owner dezactivat nu mai numără ca Owner;
  * reactivarea: SCIM `active:true` (doar conturi SCIM), Owner din UI (parolă; un Admin → 403;
    un cont activ → 409), `python3 -m app.admin enable` de pe server; toate auditate;
  * lista de conturi arată `disabled`, `disabled_by`, `scim`.
"""
import argparse
import asyncio
import base64
import json
import os
import time

os.environ["WEBTERM_OIDC_ISSUER"] = "http://127.0.0.1:9"
os.environ["WEBTERM_OIDC_CLIENT_ID"] = "wt-client"
os.environ["WEBTERM_OIDC_CLIENT_SECRET"] = "wt-secret"
os.environ.pop("WEBTERM_OIDC_ALLOWED_GROUPS", None)
os.environ.pop("WEBTERM_OIDC_ROLE_MAP", None)
os.environ.pop("WEBTERM_OIDC_SSO_ONLY", None)

import rbac_util as U  # noqa: E402
from app import accounts, admin, api, authz, core, db, oidc, oidc_api, scim, security, webauthn_api  # noqa: E402
from app.errors import ApiError  # noqa: E402

check = U.Checker()
PW = U.OWNER_PW
SCIM_CT = "application/scim+json"


def sc(token):
    return U.client(headers={"authorization": "Bearer " + token, "content-type": SCIM_CT})


def ak_user(username, email, ext=None, active=True):
    body = {"schemas": [scim.S_USER], "userName": username, "displayName": username,
            "active": active, "emails": [{"value": email, "type": "other", "primary": True}]}
    if ext:
        body["externalId"] = ext
    return body


def deactivate(active=False):
    return {"schemas": [scim.S_PATCH], "Operations": [{"op": "replace", "path": "active",
                                                       "value": active}]}


class FakeWS:
    def __init__(self, cookie):
        self.headers = {"origin": U.ORIGIN["origin"], "user-agent": "scim-test"}
        self.cookies = {security.COOKIE_NAME: cookie}
        self.client = type("C", (), {"host": "127.0.0.1"})()
        self.query_params = {}
        self.sent_text, self.sent_bytes = [], []
        self.closed = None
        self.accepted = False
        self.q = asyncio.Queue()

    async def accept(self):
        self.accepted = True

    async def send_text(self, t):
        self.sent_text.append(t)

    async def send_bytes(self, b):
        self.sent_bytes.append(b)

    async def receive(self):
        return await self.q.get()

    async def close(self, code=None):
        if self.closed is None:
            self.closed = code
        await self.q.put({"type": "websocket.disconnect"})

    def init(self):
        for t in self.sent_text:
            j = json.loads(t)
            if j.get("type") == "init":
                return j
        return {}


class FakeSource:
    epoch = None

    async def send_data(self, sid, data):
        pass

    async def resize(self, sid, rows, cols):
        pass


class _Verified:
    new_sign_count = 9


def idp(sub, email, groups=None):
    def complete(state, code):
        return {"sub": sub, "email": email, "email_verified": True, "groups": groups or [],
                "groups_present": True, "groups_readable": True, "intent": "login",
                "host_id": None}
    oidc.complete = complete


async def sso_login(sub, email):
    idp(sub, email)
    c = U.client()
    r = await c.get("/api/oidc/callback", params={"code": "c", "state": "s"},
                    cookies={oidc_api.STATE_COOKIE: "s"}, follow_redirects=False)
    await c.aclose()
    return r


async def passkey_login(cred_id: bytes):
    raw = base64.urlsafe_b64encode(cred_id).rstrip(b"=").decode()
    c = U.client()
    r = await c.post("/api/webauthn/login/verify", json={"credential": {"rawId": raw, "id": raw}})
    await c.aclose()
    return r


async def uid_of(email):
    r = await db.fetchone("SELECT id FROM users WHERE email=?", email)
    return r["id"] if r else None


async def n_sessions(uid):
    return (await db.fetchone("SELECT COUNT(*) AS c FROM web_sessions WHERE user_id=?", uid))["c"]


async def make_token(owner):
    r = await owner.post("/api/settings/scim/token", json={"current_password": PW})
    assert r.status_code == 200, r.text
    return r.json()["token"]


async def test_disable(owner, c, host):
    print("── active:false: tot accesul viu se închide ACUM, contul rămâne")
    r = await c.post("/scim/v2/Users", json=ak_user("op", "op@x.co", ext="sub-op"))
    sid_op = r.json()["id"]
    op = await uid_of("op@x.co")
    await U.bind(op, "operator", "folder", "prod")
    # SSO o dată: contul se leagă (sso_subject) — ca în viaţa reală
    r = await sso_login("sub-op", "op@x.co")
    check("op intră prin SSO (cont SCIM legat prin externalId = sub)",
          "sso_error" not in r.headers.get("location", ""), r.headers.get("location"))
    cop = await U.login("op@x.co")
    check("înainte: cookie-ul lui op merge", (await cop.get("/api/me/permissions")).status_code == 200)
    # token de automatizare, share live, link de replay, terminal deschis, bilet de forward
    raw_api = "wt_" + security.new_token()
    await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by,"
                     " created_by_id, expires) VALUES(?,?,?,?,?,?,?)", "op-auto",
                     security.sha256_hex(raw_api), "read", time.time(), "op@x.co", op,
                     time.time() + 3600)
    tc = U.client(headers={"authorization": "Bearer " + raw_api})
    check("înainte: tokenul lui op merge", (await tc.get("/api/hosts")).status_code == 200)
    live = await U.add_session(host, state="live", created_by=op)
    await db.execute("UPDATE sessions SET share_token=?, share_expires=?, share_by_id=?, share_by=?"
                     " WHERE id=?", security.sha256_hex("shr"), time.time() + 3600, op, "op@x.co", live)
    closed = await U.add_session(host, state="closed", created_by=op)
    await db.execute("INSERT INTO replay_links(token_hash, sid, user_id, created, expires)"
                     " VALUES(?,?,?,?,?)", security.sha256_hex("rpl"), closed, op, time.time(),
                     time.time() + 3600)
    row = await db.fetchone("SELECT * FROM sessions WHERE id=?", live)
    hub = core.get_or_create_hub(row)
    hub.attached = True
    hub._source = lambda: FakeSource()
    api.WS_REVALIDATE_SECS = 30           # închiderea trebuie să vină din epoch bump, nu din tick
    ws = FakeWS(cop.cookies.get(security.COOKIE_NAME))
    task = asyncio.create_task(api.browser_ws(ws, live))
    for _ in range(50):
        await asyncio.sleep(0.02)
        if ws.closed is not None or ws.init():
            break
    check("înainte: terminalul lui op e deschis, rw", ws.accepted and ws.init().get("readonly") is False,
          str(ws.sent_text[:2]))
    await U.add_forward(host, "svc")
    ticket = security.make_forward_token("svc", op)
    check("înainte: biletul de forward e valid", await api._forward_authz_ok("svc", ticket))

    r = await c.patch("/scim/v2/Users/" + sid_op, json=deactivate())
    check("PATCH active:false → 200, active=false", r.status_code == 200 and r.json()["active"] is False,
          r.text[:200])
    for _ in range(50):
        if ws.closed is not None:
            break
        await asyncio.sleep(0.02)
    check("terminalul DESCHIS se închide pe loc (4401/4403)", ws.closed in (4401, 4403), str(ws.closed))
    await ws.q.put({"type": "websocket.disconnect"})
    try:
        await asyncio.wait_for(task, 5)
    except Exception:                                  # noqa: BLE001
        pass
    check("sesiunile web şterse", await n_sessions(op) == 0)
    check("cookie-ul vechi → 401", (await cop.get("/api/me/permissions")).status_code == 401)
    check("tokenul de automatizare → 401 şi şters din DB", (await tc.get("/api/hosts")).status_code == 401
          and not await db.fetchone("SELECT 1 FROM api_tokens WHERE created_by_id=?", op))
    s = await db.fetchone("SELECT share_token FROM sessions WHERE id=?", live)
    check("share-ul live revocat", s["share_token"] is None)
    check("link-ul de replay revocat", not await db.fetchone("SELECT 1 FROM replay_links WHERE user_id=?", op))
    check("biletul de forward nu mai trece", not await api._forward_authz_ok("svc", ticket))
    g = await authz.grants_for_user(op)
    check("drepturile sunt GOALE", not g.global_perms and not g.all_host_perms
          and not await authz.perms_on(g, host))
    check("…dar legătura de rol rămâne (pentru reactivare)",
          bool(await db.fetchone("SELECT 1 FROM role_bindings WHERE user_id=?", op)))
    a = await db.fetchone("SELECT detail FROM audit_log WHERE detail LIKE 'account op@x.co disabled%'")
    check("auditat, cu ce s-a revocat", a is not None and "1 automation token" in a["detail"], str(a and a["detail"]))
    oid = await uid_of(U.OWNER_EMAIL)
    al = await db.fetchone("SELECT 1 FROM alerts WHERE user_id=? AND msg_params LIKE '%scim_account_disabled%'", oid)
    check("alertă în istoricul Owner-ului (security.view)", al is not None)
    lst = (await owner.get("/api/users")).json()
    me = next(u for u in lst if u["email"] == "op@x.co")
    check("lista de conturi: disabled + disabled_by=scim + scim", me["disabled"] and me["disabled_by"] == "scim"
          and me["scim"] and me["scim_linked"], str(me))
    await cop.aclose()
    await tc.aclose()
    return op, sid_op


async def test_no_sign_in(op):
    print("── un cont dezactivat nu intră: parolă, passkey, SSO, plasa din create_web_session")
    lid = await U.add_user("local@x.co", pw="parolabuna1")
    await db.execute("UPDATE users SET disabled=1, disabled_by='scim' WHERE id=?", lid)
    c = U.client()
    r = await c.post("/api/login", json={"email": "local@x.co", "password": "parolabuna1"})
    check("parola CORECTĂ → 403 auth.accountDisabled", r.status_code == 403
          and U.code(r) == "auth.accountDisabled", "%s %s" % (r.status_code, r.text[:120]))
    r = await c.post("/api/login", json={"email": "local@x.co", "password": "gresita123"})
    check("parola greşită → 401 obişnuit (fără oracol)", r.status_code == 401 and U.code(r) == "auth.badCredentials")
    await c.aclose()
    check("…nicio sesiune creată", await n_sessions(lid) == 0)
    orig_v, orig_c = webauthn_api.verify_authentication_response, webauthn_api._consume
    webauthn_api.verify_authentication_response = lambda **kw: _Verified()
    webauthn_api._consume = lambda cred: b"challenge"
    try:
        await db.execute("INSERT INTO webauthn_credentials(user_id, credential_id, public_key,"
                         " sign_count, name, created) VALUES(?,?,?,0,'k',?)", lid, b"cred-dis", b"pk",
                         time.time())
        r = await passkey_login(b"cred-dis")
        check("passkey → 403 auth.accountDisabled, fără cookie", r.status_code == 403
              and U.code(r) == "auth.accountDisabled"
              and security.COOKIE_NAME not in r.headers.get("set-cookie", ""), "%s %s" % (r.status_code, r.text[:120]))
    finally:
        webauthn_api.verify_authentication_response, webauthn_api._consume = orig_v, orig_c
    r = await sso_login("sub-op", "op@x.co")
    check("SSO → redirect sso_error=disabled, fără cookie",
          r.headers.get("location", "").endswith("sso_error=disabled")
          and security.COOKIE_NAME not in r.headers.get("set-cookie", ""), r.headers.get("location"))
    check("…nicio sesiune pentru op", await n_sessions(op) == 0)
    try:
        await security.create_web_session(op, "x", False)
        refused = False
    except ApiError as e:
        refused = e.code == "auth.accountDisabled"
    check("create_web_session refuză un cont dezactivat (plasa)", refused)
    tok = security.new_token()
    await db.execute("INSERT INTO web_sessions(token_hash, user_id, created, expires, last_seen)"
                     " VALUES(?,?,?,?,?)", security.sha256_hex(tok), op, time.time(), time.time() + 99, time.time())
    check("o sesiune rămasă (scrisă direct) nu mai deschide nimic",
          await security.user_for_token(tok) is None and not await security.session_valid(tok))


async def test_reenable(owner, c, op, sid_op, host):
    print("── reactivarea: SCIM active:true, Owner din UI, CLI")
    r = await c.patch("/scim/v2/Users/" + sid_op, json=deactivate(True))
    check("SCIM active:true → reactivat", r.status_code == 200 and r.json()["active"] is True)
    check("…drepturile revin (legăturile păstrate)",
          "session.open" in await authz.perms_on(await authz.grants_for_user(op), host))
    r = await sso_login("sub-op", "op@x.co")
    check("…şi intră din nou prin SSO", "sso_error" not in r.headers.get("location", ""))
    await c.patch("/scim/v2/Users/" + sid_op, json=deactivate(False))
    await U.add_user("adm@x.co", bindings=[("admin", "all", "")])
    adm = await U.login("adm@x.co")
    r = await adm.post("/api/users/%d/enable" % op, json={"current_password": "parolabuna1"})
    check("un Admin NU reactivează (doar Owner) → 403", r.status_code == 403 and U.code(r) == "authz.ownerOnly")
    r = await owner.post("/api/users/%d/enable" % op, json={})
    check("Owner fără parolă → 401", r.status_code == 401)
    r = await owner.post("/api/users/%d/enable" % op, json={"current_password": PW})
    me = next((u for u in r.json() if u["email"] == "op@x.co"), {}) if r.status_code == 200 else {}
    check("Owner cu parolă → reactivat", r.status_code == 200 and me.get("disabled") is False, r.text[:200])
    a = await db.fetchone("SELECT detail FROM audit_log WHERE path=? AND status=200",
                          "/api/users/%d/enable" % op)
    check("…auditat", a is not None and "re-enabled" in a["detail"])
    r = await owner.post("/api/users/%d/enable" % op, json={"current_password": PW})
    check("reactivarea unui cont activ → 409 account.notDisabled", r.status_code == 409
          and U.code(r) == "account.notDisabled")
    await c.patch("/scim/v2/Users/" + sid_op, json=deactivate(False))
    await admin.cmd_enable(argparse.Namespace(email="op@x.co"))
    row = await db.fetchone("SELECT disabled FROM users WHERE id=?", op)
    cli = await db.fetchone("SELECT 1 FROM audit_log WHERE path='/admin/enable'")
    check("`app.admin enable` de pe server reactivează + auditează", row["disabled"] == 0 and cli is not None)
    await adm.aclose()


async def test_delete(owner, c, op, sid_op):
    print("── DELETE = dezactivare + dezlegare; re-crearea readoptă")
    r = await c.delete("/scim/v2/Users/" + sid_op)
    check("DELETE → 204", r.status_code == 204)
    row = await db.fetchone("SELECT * FROM users WHERE id=?", op)
    check("contul RĂMÂNE (istoric), dezactivat, scim_id gol", row is not None and row["disabled"] == 1
          and row["disabled_by"] == "scim-delete" and row["scim_id"] is None and row["scim_managed"] == 1)
    check("GET pe resursa ştearsă → 404", (await c.get("/scim/v2/Users/" + sid_op)).status_code == 404)
    check("DELETE din nou → 404", (await c.delete("/scim/v2/Users/" + sid_op)).status_code == 404)
    r = await c.post("/scim/v2/Users", json=ak_user("op", "op@x.co", ext="sub-op"))
    check("re-crearea aceleiaşi persoane → acelaşi cont, reactivat", r.status_code == 201
          and await uid_of("op@x.co") == op and r.json()["active"] is True, r.text[:200])
    return r.json()["id"]


async def test_last_owner(owner, c):
    print("── ultimul Owner permanent nu se dezactivează / şterge prin SCIM")
    r = await sso_login("sub-boss", "boss@x.co")
    boss = await uid_of("boss@x.co")
    r = await c.post("/scim/v2/Users", json=ak_user("boss", "boss@x.co", ext="sub-boss"))
    sid_boss = r.json()["id"]
    check("contul SSO-only boss e adoptat de SCIM", r.status_code == 201 and await uid_of("boss@x.co") == boss)
    # Owner dat de un GRUP SSO (source=sso): un Owner dat DE MÂNĂ nu e niciodată atins de SCIM
    # (revizuirea independentă 3.6.11 — vezi test_review_owner_level)
    await U.bind(boss, "owner", "all", "")
    await db.execute("UPDATE role_bindings SET source='sso' WHERE user_id=?", boss)
    oid = await uid_of(U.OWNER_EMAIL)
    # boss devine SINGURUL Owner permanent: Owner-ul local e retrogradat la unul temporar
    await db.execute("UPDATE role_bindings SET expires=? WHERE user_id=?", time.time() + 7200, oid)
    authz.bump_epoch()
    check("pregătire: boss e singurul Owner permanent", await authz.owner_count() == 1)
    r = await c.patch("/scim/v2/Users/" + sid_boss, json={"Operations": [
        {"op": "replace", "path": "displayName", "value": "Renamed Boss"},
        {"op": "replace", "path": "active", "value": False}]})
    row = await db.fetchone("SELECT scim_display_name FROM users WHERE id=?", boss)
    check("refuzul e ATOMIC: nicio altă schimbare din aceeaşi cerere nu e scrisă", r.status_code == 403
          and row["scim_display_name"] != "Renamed Boss", str(row["scim_display_name"]))
    r = await c.patch("/scim/v2/Users/" + sid_boss, json=deactivate())
    j = r.json()
    check("active:false pe ultimul Owner permanent → 403 SCIM", r.status_code == 403
          and j.get("schemas") == [scim.S_ERROR] and "last permanent Owner" in j.get("detail", ""), r.text[:200])
    row = await db.fetchone("SELECT disabled FROM users WHERE id=?", boss)
    check("…contul NU e dezactivat", row["disabled"] == 0)
    r = await c.delete("/scim/v2/Users/" + sid_boss)
    check("DELETE pe ultimul Owner permanent → 403, contul rămâne legat", r.status_code == 403
          and (await db.fetchone("SELECT scim_id FROM users WHERE id=?", boss))["scim_id"] == sid_boss)
    al = await db.fetchone("SELECT severity FROM alerts WHERE user_id=? AND msg_params LIKE '%scim_last_owner_refused%'", oid)
    check("…alertă CRITICĂ", al is not None and al["severity"] == "critical")
    au = await db.fetchone("SELECT 1 FROM audit_log WHERE status=403 AND detail LIKE '%last permanent Owner%'")
    check("…auditat", au is not None)
    await db.execute("UPDATE role_bindings SET expires=NULL WHERE user_id=?", oid)
    authz.bump_epoch()
    r = await c.patch("/scim/v2/Users/" + sid_boss, json=deactivate())
    check("cu un al doilea Owner permanent: boss se poate dezactiva", r.status_code == 200
          and r.json()["active"] is False)
    check("…iar un Owner dezactivat nu mai numără ca Owner", await authz.owner_count() == 1)
    r = await owner.post("/api/users/%d/bindings/%d/delete" % (oid, (await db.fetchone(
        "SELECT b.id FROM role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=? AND r.key='owner'",
        oid))["id"]), json={"current_password": PW})
    check("…deci Owner-ul local rămas nu-şi poate scoate rolul (ultimul Owner ACTIV)", r.status_code in (400, 403),
          "%s %s" % (r.status_code, r.text[:120]))


async def alert_of(key, severity="critical"):
    for _ in range(50):                   # alertele se scriu dintr-un task
        row = await db.fetchone("SELECT severity FROM alerts WHERE msg_params LIKE ? AND severity=?",
                                "%%%s%%" % key, severity)
        if row is not None:
            return row
        await asyncio.sleep(0.02)
    return None


async def test_review_owner_level(owner, c):
    """Revizuirea independentă a SCIM (3.6.11): tokenul SCIM nu poate prelua / scoate un Owner."""
    print("── revizuirea 3.6.11: adopţia, Owner-ii daţi în WebTerm, reactivarea, Admin vs Owner dezactivat")
    # M1: un Owner SSO-only, dat DE MÂNĂ, nu se adoptă — nici prin externalId = sub cu alt email
    await sso_login("sub-o2", "o2@x.co")
    o2 = await uid_of("o2@x.co")
    await U.bind(o2, "owner", "all", "")
    before = dict(await db.fetchone("SELECT * FROM users WHERE id=?", o2))
    r = await c.post("/scim/v2/Users", json=ak_user("x", "attacker@evil.co", ext="sub-o2"))
    after = dict(await db.fetchone("SELECT * FROM users WHERE id=?", o2))
    # a doua re-revizuire 3.6.11: verificarea Owner-ului rulează ÎNAINTEA celei de email; refuzurile
    # permanente sunt 400/403, niciodată 409 (Authentik ar abandona restul paginii de sincronizare)
    check("adopţie prin externalId = sub dar ALT email (Owner dat în WebTerm) → 403, contul neatins",
          r.status_code == 403 and "Owner-level" in r.json().get("detail", "") and before == after,
          r.text[:200])
    r = await c.post("/scim/v2/Users", json=ak_user("o2", "o2@x.co", ext="sub-o2"))
    after = dict(await db.fetchone("SELECT * FROM users WHERE id=?", o2))
    check("adopţia unui cont cu Owner dat în WebTerm → 403 (chiar cu emailul lui), neatins",
          r.status_code == 403 and "Owner-level" in r.json().get("detail", "") and before == after,
          r.text[:200])
    check("…alertă CRITICĂ (scim_owner_refused)", await alert_of("scim_owner_refused") is not None)
    # un rol custom cu o permisiune doar-de-Owner = Owner sub alt nume
    await sso_login("sub-o3", "o3@x.co")
    o3 = await uid_of("o3@x.co")
    perms = sorted(authz.BUILTIN_ROLES["owner"]["perms"] - authz.BUILTIN_ROLES["admin"]["perms"])[:1]
    rid = await db.execute("INSERT INTO roles(key, name, description, perms, builtin, created, updated)"
                           " VALUES(NULL, 'Shadow', '', ?, 0, ?, ?)", json.dumps(perms), time.time(),
                           time.time())
    await db.execute("INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
                     " created) VALUES(?,?,'all','','manual',?)", o3, rid, time.time())
    authz.bump_epoch()
    r = await c.post("/scim/v2/Users", json=ak_user("o3", "o3@x.co", ext="sub-o3"))
    check("…la fel pentru un rol custom cu o permisiune doar-de-Owner (%s)" % perms, r.status_code == 403,
          r.text[:160])
    # adopţia unui cont SSO-only obişnuit: merge, dar e alertată CRITIC şi emailul nu se mai schimbă
    await sso_login("sub-pia", "pia@x.co")
    pia = await uid_of("pia@x.co")
    r = await c.post("/scim/v2/Users", json=ak_user("pia", "pia@x.co", ext="sub-pia"))
    sid_pia = r.json().get("id")
    check("adopţia unui cont SSO-only fără rol de Owner → 201, acelaşi cont", r.status_code == 201
          and await uid_of("pia@x.co") == pia, r.text[:160])
    check("…alertă CRITICĂ (scim_account_adopted)", await alert_of("scim_account_adopted") is not None)
    r = await c.patch("/scim/v2/Users/" + sid_pia, json={"Operations": [
        {"op": "replace", "path": "emails", "value": [{"value": "pia2@x.co", "primary": True}]}]})
    check("…SCIM nu schimbă emailul unui cont pe care nu l-a creat (400 mutability)",
          r.status_code == 400 and r.json().get("scimType") == "mutability"
          and await uid_of("pia@x.co") == pia, r.text[:160])
    # Owner dat de mână unui cont CREAT de SCIM: SCIM nu-l mai dezactivează / şterge / re-emailează
    r = await c.post("/scim/v2/Users", json=ak_user("mo", "mo@x.co", ext="sub-mo"))
    sid_mo, mo = r.json()["id"], await uid_of("mo@x.co")
    await U.bind(mo, "owner", "all", "")
    r = await c.patch("/scim/v2/Users/" + sid_mo, json=deactivate())
    row = await db.fetchone("SELECT disabled FROM users WHERE id=?", mo)
    check("active:false pe un cont cu Owner dat în WebTerm → 403, nedezactivat", r.status_code == 403
          and row["disabled"] == 0, r.text[:200])
    r = await c.delete("/scim/v2/Users/" + sid_mo)
    row = await db.fetchone("SELECT disabled, scim_id FROM users WHERE id=?", mo)
    check("DELETE pe el → 403, rămâne activ şi legat", r.status_code == 403 and row["disabled"] == 0
          and row["scim_id"] == sid_mo, r.text[:200])
    r = await c.patch("/scim/v2/Users/" + sid_mo, json={"Operations": [
        {"op": "replace", "path": "emails", "value": [{"value": "mo2@x.co", "primary": True}]}]})
    check("…nici emailul nu i-l schimbă (403)", r.status_code == 403 and await uid_of("mo@x.co") == mo)
    # L1: reactivarea prin SCIM nu redă un Owner dat de mână; nici un cont dezactivat de WebTerm
    r = await c.post("/scim/v2/Users", json=ak_user("re", "re@x.co", ext="sub-re"))
    sid_re, re_ = r.json()["id"], await uid_of("re@x.co")
    r = await c.patch("/scim/v2/Users/" + sid_re, json=deactivate())
    check("pregătire: re dezactivat de SCIM", r.status_code == 200 and r.json()["active"] is False)
    await U.bind(re_, "owner", "all", "")          # dat de un Owner cât e dezactivat
    r = await c.patch("/scim/v2/Users/" + sid_re, json=deactivate(True))
    row = await db.fetchone("SELECT disabled FROM users WHERE id=?", re_)
    check("SCIM active:true pe un cont cu Owner dat în WebTerm → 403, rămâne dezactivat",
          r.status_code == 403 and row["disabled"] == 1, r.text[:200])
    r = await c.post("/scim/v2/Users", json=ak_user("cli", "cli@x.co", ext="sub-cli"))
    sid_cli, cli = r.json()["id"], await uid_of("cli@x.co")
    await db.execute("UPDATE users SET disabled=1, disabled_at=?, disabled_by='owner' WHERE id=?",
                     time.time(), cli)
    r = await c.patch("/scim/v2/Users/" + sid_cli, json=deactivate(True))
    row = await db.fetchone("SELECT disabled FROM users WHERE id=?", cli)
    check("SCIM active:true pe un cont dezactivat de altcineva decât SCIM → 403", r.status_code == 403
          and row["disabled"] == 1, r.text[:200])
    # L2: un Admin nu atinge un Owner DEZACTIVAT (re: Owner, dezactivat)
    adm = await U.login("adm@x.co")
    check("is_owner_user vede Owner-ul dezactivat; owner_count nu-l numără",
          await authz.is_owner_user(re_) and not (await authz.grants_for_user(re_)).is_owner())
    r = await adm.post("/api/users/%d/bindings" % re_, json={"role": "viewer", "scope_kind": "all",
                                                           "current_password": "parolabuna1"})
    check("Admin adaugă un rol unui Owner DEZACTIVAT → 403 authz.ownerOnly", r.status_code == 403
          and U.code(r) == "authz.ownerOnly", "%s %s" % (r.status_code, r.text[:120]))
    r = await adm.post("/api/users/%d/delete" % re_, json={"current_password": "parolabuna1"})
    check("Admin şterge un Owner DEZACTIVAT → 403", r.status_code == 403
          and await uid_of("re@x.co") == re_, r.text[:120])
    r = await owner.post("/api/users/%d/delete" % re_, json={"current_password": PW})
    check("…un Owner îl poate şterge (un Owner dezactivat nu e „ultimul Owner”)",
          r.status_code == 200 and await uid_of("re@x.co") is None, r.text[:160])
    await adm.aclose()


async def test_review_tokens(owner, c):
    print("── revizuirea 3.6.11: tokenurile de grup ale unui cont scos; tokenuri fără creator")
    r = await c.post("/scim/v2/Users", json=ak_user("eg", "eg@x.co", ext="sub-eg"))
    sid_eg, eg = r.json()["id"], await uid_of("eg@x.co")
    for name, by_id in (("eg-new", eg), ("eg-legacy", None)):
        await db.execute("INSERT INTO enroll_groups(name, token_hash, created, created_by, created_by_id,"
                         " expires) VALUES(?,?,?,?,?,?)", name, security.sha256_hex(name), time.time(),
                         "eg@x.co", by_id, time.time() + 3600)
    await c.patch("/scim/v2/Users/" + sid_eg, json=deactivate())
    rows = {x["name"]: x["revoked"] for x in await db.fetchall(
        "SELECT name, revoked FROM enroll_groups WHERE name LIKE 'eg-%'")}
    check("dezactivarea revocă tokenurile de grup ale contului (după id)", rows.get("eg-new") == 1,
          str(rows))
    # re-review 3.6.11 (LOW-2): fără id, emailul NU mai e creator (backfill-ul o dată, la pornire)
    check("…NU şi pe unul fără creator cu acelaşi email (doar după id, niciodată după email)",
          rows.get("eg-legacy") == 0, str(rows))
    lu = await U.add_user("lu@x.co")
    await db.execute("INSERT INTO enroll_groups(name, token_hash, created, created_by, created_by_id,"
                     " expires) VALUES('lu-grp',?,?,?,?,?)", security.sha256_hex("lu-grp"), time.time(),
                     "lu@x.co", lu, time.time() + 3600)
    r = await owner.post("/api/users/%d/delete" % lu, json={"current_password": PW})
    row = await db.fetchone("SELECT revoked FROM enroll_groups WHERE name='lu-grp'")
    check("ştergerea contului revocă tokenurile lui de grup", r.status_code == 200 and row["revoked"] == 1,
          r.text[:120])
    raw = "wt_" + security.new_token()
    await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by, expires)"
                     " VALUES('orphan', ?, 'read', ?, 'ghost@x.co', ?)", security.sha256_hex(raw),
                     time.time(), time.time() + 3600)
    await U.add_user("ghost@x.co", bindings=[("admin", "all", "")])
    tc = U.client(headers={"authorization": "Bearer " + raw})
    r = await tc.get("/api/hosts")
    g = await authz.grants_for_token(dict(await db.fetchone("SELECT * FROM api_tokens WHERE name='orphan'")))
    check("un token fără creator (id) NU e moştenit de contul care ia acum acel email (nu vede nimic)",
          r.status_code in (200, 401) and (r.status_code == 401 or r.json() == []) and g.user_id is None
          and not g.global_perms, "%s %s" % (r.status_code, r.text[:80]))
    await tc.aclose()


async def n_alerts(key, account):
    await asyncio.sleep(0.3)              # alertele se scriu dintr-un task
    row = await db.fetchone("SELECT COUNT(DISTINCT ts) AS c FROM alerts WHERE msg_params LIKE ?"
                            " AND msg_params LIKE ?", "%%%s%%" % key, "%%%s%%" % account)
    return row["c"]


async def test_rereview(owner, c):
    """Re-review-ul fixurilor SCIM (3.6.11)."""
    print("── re-review 3.6.11: active:false nu e blocat de identitate; alerte rărite; disabled_by")
    # MEDIUM-1: cont ADOPTAT, emailul redenumit în IdP + active:false (Authentik trimite tot) →
    # se dezactivează, emailul NU se schimbă
    await sso_login("sub-ren", "ren@x.co")
    ren = await uid_of("ren@x.co")
    await U.bind(ren, "operator", "all")
    r = await c.post("/scim/v2/Users", json=ak_user("ren", "ren@x.co", ext="sub-ren"))
    sid_ren = r.json()["id"]
    r = await c.put("/scim/v2/Users/" + sid_ren, json=ak_user("ren", "ren.new@x.co", ext="sub-ren"))
    check("PUT cu email redenumit, fără active:false → tot refuzat, 400 (nimic nu se schimbă)",
          r.status_code == 400 and await uid_of("ren@x.co") == ren, r.text[:160])
    r = await c.put("/scim/v2/Users/" + sid_ren,
                    json=ak_user("ren", "ren.new@x.co", ext="sub-ren", active=False))
    row = await db.fetchone("SELECT email, disabled, disabled_by FROM users WHERE id=?", ren)
    check("PUT {email redenumit, active:false} pe un cont adoptat → 200, DEZACTIVAT, email neschimbat",
          r.status_code == 200 and r.json().get("active") is False and row["disabled"] == 1
          and row["email"] == "ren@x.co" and row["disabled_by"] == "scim", "%s %s %s" % (
              r.status_code, r.text[:160], dict(row)))
    au = await db.fetchone("SELECT detail FROM audit_log WHERE detail LIKE ? ORDER BY id DESC",
                           "%ren@x.co: ignored the identity change%")
    check("…schimbarea de identitate ignorată e auditată", au is not None)
    check("…şi alertată (avertisment, scim_identity_ignored)",
          await alert_of("scim_identity_ignored", "warning") is not None)
    r = await c.put("/scim/v2/Users/" + sid_ren,
                    json=ak_user("ren", "ren.new@x.co", ext="sub-ren", active=False))
    check("…sincronizarea următoare: 200 din nou, fără a doua alertă în aceeaşi oră",
          r.status_code == 200 and await n_alerts("scim_identity_ignored", "ren@x.co") == 1,
          r.text[:160])
    # PATCH cu ambele operaţii
    await sso_login("sub-rex", "rex@x.co")
    rex = await uid_of("rex@x.co")
    r = await c.post("/scim/v2/Users", json=ak_user("rex", "rex@x.co", ext="sub-rex"))
    sid_rex = r.json()["id"]
    r = await c.patch("/scim/v2/Users/" + sid_rex, json={"schemas": [scim.S_PATCH], "Operations": [
        {"op": "replace", "path": 'emails[type eq "work"].value', "value": "rex.new@x.co"},
        {"op": "replace", "path": "active", "value": False}]})
    row = await db.fetchone("SELECT email, disabled FROM users WHERE id=?", rex)
    check("PATCH {email redenumit + active:false} → 200, dezactivat, email neschimbat",
          r.status_code == 200 and row["disabled"] == 1 and row["email"] == "rex@x.co",
          "%s %s" % (r.status_code, r.text[:160]))
    # cont creat de SCIM, încă nelegat de SSO, cu un rol dat de mână (a doua gardă)
    r = await c.post("/scim/v2/Users", json=ak_user("una", "una@x.co", ext="sub-una"))
    sid_una, una = r.json()["id"], await uid_of("una@x.co")
    await U.bind(una, "viewer", "all")
    r = await c.patch("/scim/v2/Users/" + sid_una, json={"Operations": [
        {"op": "replace", "value": {"emails": [{"value": "una.new@x.co", "primary": True}],
                                    "active": False}}]})
    row = await db.fetchone("SELECT email, disabled FROM users WHERE id=?", una)
    check("…la fel pe un cont nelegat cu roluri date de mână (PATCH fără path)",
          r.status_code == 200 and row["disabled"] == 1 and row["email"] == "una@x.co",
          "%s %s" % (r.status_code, r.text[:160]))
    # POST (re-provizionare după DELETE) cu email redenumit + active:false: readoptat sub
    # emailul lui, dezactivat — nu 409
    r = await c.post("/scim/v2/Users", json=ak_user("uma", "uma@x.co", ext="sub-uma"))
    sid_uma, uma = r.json()["id"], await uid_of("uma@x.co")
    await U.bind(uma, "viewer", "all")
    await c.delete("/scim/v2/Users/" + sid_uma)
    r = await c.post("/scim/v2/Users", json=ak_user("uma", "uma.new@x.co", ext="sub-uma",
                                                     active=False))
    row = await db.fetchone("SELECT email, disabled, scim_id FROM users WHERE id=?", uma)
    check("POST {email redenumit, active:false} pe un cont scos → 201, rămâne dezactivat, email neschimbat",
          r.status_code == 201 and row["disabled"] == 1 and row["email"] == "uma@x.co"
          and row["scim_id"] == r.json().get("id"), "%s %s %s" % (r.status_code, r.text[:160],
                                                                   dict(row)))
    # LOW-1: refuzul unui Owner dat în WebTerm: o alertă critică pe oră, nu una pe sincronizare
    for _ in range(4):
        r = await c.post("/scim/v2/Users", json=ak_user("o2", "o2@x.co", ext="sub-o2"))
    check("refuzuri repetate pe acelaşi Owner → tot 403, dar O SINGURĂ alertă critică pe oră",
          r.status_code == 403 and await n_alerts("scim_owner_refused", "o2@x.co") == 1,
          str(await n_alerts("scim_owner_refused", "o2@x.co")))
    # LOW-3: un cont dezactivat ÎN WebTerm rămâne „al WebTerm”, orice ar face SCIM
    r = await c.post("/scim/v2/Users", json=ak_user("wd", "wd@x.co", ext="sub-wd"))
    sid_wd, wd = r.json()["id"], await uid_of("wd@x.co")
    await db.execute("UPDATE users SET disabled=1, disabled_at=?, disabled_by='owner' WHERE id=?",
                     time.time(), wd)
    await c.patch("/scim/v2/Users/" + sid_wd, json=deactivate())
    r = await c.delete("/scim/v2/Users/" + sid_wd)
    row = await db.fetchone("SELECT disabled, disabled_by FROM users WHERE id=?", wd)
    check("SCIM active:false + DELETE pe un cont dezactivat în WebTerm: disabled_by rămâne 'owner'",
          r.status_code == 204 and row["disabled"] == 1 and row["disabled_by"] == "owner",
          "%s %s" % (r.status_code, dict(row)))
    r = await c.post("/scim/v2/Users", json=ak_user("wd", "wd@x.co", ext="sub-wd"))
    row = await db.fetchone("SELECT disabled FROM users WHERE id=?", wd)
    check("…iar re-provizionarea lui NU-l reactivează (403, rămâne dezactivat)",
          r.status_code == 403 and row["disabled"] == 1, "%s %s" % (r.status_code, r.text[:160]))
    # NOTE L3: un utilizator INACTIV în IdP, fără cont în WebTerm → nimic creat, 400, fără alertă
    for _ in range(3):
        r = await c.post("/scim/v2/Users", json=ak_user("ina", "ina@x.co", ext="sub-ina",
                                                         active=False))
    au = await db.fetchone("SELECT COUNT(*) AS n FROM audit_log WHERE detail LIKE ?",
                           "%inactive in the identity provider%ina@x.co%")
    check("POST active:false pentru o identitate nouă → 400 invalidValue, NICIUN cont creat",
          r.status_code == 400 and r.json().get("scimType") == "invalidValue"
          and await uid_of("ina@x.co") is None, "%s %s" % (r.status_code, r.text[:160]))
    check("…fără alertă de cont nou; auditat o dată pe oră (nu la fiecare sincronizare)",
          await n_alerts("scim_account_created", "ina@x.co") == 0 and au["n"] == 1, str(au["n"]))
    r = await c.post("/scim/v2/Users", json=ak_user("ina", "ina@x.co", ext="sub-ina"))
    check("…activat în IdP → creat (201)", r.status_code == 201 and await uid_of("ina@x.co"),
          r.text[:160])


async def audit_n(like):
    return (await db.fetchone("SELECT COUNT(*) AS n FROM audit_log WHERE detail LIKE ?", like))["n"]


async def test_rereview2(owner, c):
    """A doua re-revizuire a SCIM (3.6.11)."""
    print("── a doua re-revizuire 3.6.11: refuzuri ne-409, adopţie+dezactivare, tokenuri după id, orfani")
    from app import syshealth
    # LOW: cont SSO (sub-g) niciodată legat de SCIM; IdP-ul i-a redenumit emailul ŞI îl dezactivează
    # → adoptat sub emailul LUI, dezactivat, avertizat (înainte: 409, contul rămânea ACTIV)
    await sso_login("sub-g", "g@x.co")
    g = await uid_of("g@x.co")
    await U.bind(g, "operator", "all")
    r = await c.post("/scim/v2/Users", json=ak_user("g", "g.new@x.co", ext="sub-g"))
    row = dict(await db.fetchone("SELECT email, disabled, scim_id FROM users WHERE id=?", g))
    check("POST ext=sub, alt email, ACTIV → 400 invalidValue (nu 409), contul neatins",
          r.status_code == 400 and r.json().get("scimType") == "invalidValue"
          and row == {"email": "g@x.co", "disabled": 0, "scim_id": None}, "%s %s" % (r.status_code, r.text[:160]))
    # re-revizuirea finală 3.6.11 (MEDIUM 2): cine are tokenul SCIM şi ştie DOAR `sub`-ul nu
    # adoptă contul cu active:false (răspunsul i-ar da emailul, iar un PUT cu el + active:true l-ar
    # reactiva sub SCIM) — contul e dezactivat PE LOC, nelegat, 'scim-identity', 400 fără resursă
    n_au = await audit_n("%matched g@x.co by externalId only%")
    for _ in range(3):
        r = await c.post("/scim/v2/Users", json=ak_user("g", "g.new@x.co", ext="sub-g", active=False))
    row = dict(await db.fetchone("SELECT email, disabled, disabled_by, scim_id, scim_managed,"
                                 " scim_external_id FROM users WHERE id=?", g))
    check("POST ext=sub, alt email, active:false → 400 invalidValue FĂRĂ resursă şi fără email; "
          "contul dezactivat pe loc ('scim-identity'), NELEGAT de SCIM",
          r.status_code == 400 and r.json().get("scimType") == "invalidValue"
          and "g@x.co" not in r.text and "emails" not in r.json() and "id" not in r.json()
          and row == {"email": "g@x.co", "disabled": 1, "disabled_by": "scim-identity",
                      "scim_id": None, "scim_managed": 0, "scim_external_id": None},
          "%s %s %s" % (r.status_code, r.text[:200], row))
    check("…auditat şi avertizat O DATĂ pe oră (scim_disabled_unlinked), nu la fiecare sincronizare",
          n_au == 0 and await audit_n("%matched g@x.co by externalId only%") == 1
          and await n_alerts("scim_disabled_unlinked", "g@x.co") == 1
          and await alert_of("scim_disabled_unlinked", "critical") is not None)
    leak = [await c.get("/scim/v2/Users", params={"filter": q}) for q in
            ('externalId eq "sub-g"', 'emails eq "g@x.co"', 'userName eq "g"')]
    st = (await owner.get("/api/settings/scim")).json()
    check("…nici filtrele GET, nici ultima eroare nu dau emailul contului ne-SCIM",
          all(x.status_code == 200 and x.json()["totalResults"] == 0 for x in leak)
          and "g@x.co" not in json.dumps(st.get("last_error")), str(st.get("last_error")))
    r = await c.post("/scim/v2/Users", json=ak_user("g", "g@x.co", ext="sub-g", active=True))
    row = dict(await db.fetchone("SELECT disabled, disabled_by, scim_id FROM users WHERE id=?", g))
    check("…apoi POST cu emailul LUI şi active:true → 403, rămâne dezactivat, neadoptat",
          r.status_code == 403 and row == {"disabled": 1, "disabled_by": "scim-identity",
                                           "scim_id": None}, "%s %s %s" % (r.status_code, r.text[:160], row))
    r = await c.post("/scim/v2/Users", json=ak_user("g", "g@x.co", ext="sub-g", active=False))
    sid_g = r.json().get("id")
    r2 = await c.put("/scim/v2/Users/%s" % sid_g, json=ak_user("g", "g@x.co", ext="sub-g"))
    r3 = await c.delete("/scim/v2/Users/%s" % sid_g)
    row = dict(await db.fetchone("SELECT disabled, disabled_by FROM users WHERE id=?", g))
    check("…adoptat mai târziu cu emailul lui (active:false): SCIM tot nu-l reactivează, iar "
          "active:false / DELETE nu mută 'scim-identity' înapoi în 'scim*'",
          r.status_code == 201 and r2.status_code == 403 and r3.status_code == 204
          and row == {"disabled": 1, "disabled_by": "scim-identity"},
          "%s %s %s %s" % (r.status_code, r2.status_code, r3.status_code, row))
    lst = {x["email"]: x for x in (await owner.get("/api/users")).json()}
    r = await owner.post("/api/users/%d/enable" % g, json={"current_password": PW})
    row = dict(await db.fetchone("SELECT disabled, disabled_by FROM users WHERE id=?", g))
    check("…lista conturilor arată 'scim-identity'; un Owner îl reactivează din Setări",
          lst["g@x.co"]["disabled_by"] == "scim-identity" and r.status_code == 200
          and row == {"disabled": 0, "disabled_by": None}, "%s %s" % (r.status_code, row))
    # Owner dat în WebTerm: verificarea Owner rulează ÎNAINTE, chiar cu active:false
    await sso_login("sub-og", "og@x.co")
    og = await uid_of("og@x.co")
    await U.bind(og, "owner", "all", "")
    r = await c.post("/scim/v2/Users", json=ak_user("og", "og.new@x.co", ext="sub-og", active=False))
    row = await db.fetchone("SELECT disabled, scim_id FROM users WHERE id=?", og)
    check("…dar un Owner dat în WebTerm (alt email, active:false) → 403, NU adoptat, NU dezactivat",
          r.status_code == 403 and row["disabled"] == 0 and row["scim_id"] is None, r.text[:160])
    # externalId abandonat la dezactivare → reactivarea cu noul externalId e refuzată (fail closed),
    # dar explicat; 400, nu 409
    r = await c.post("/scim/v2/Users", json=ak_user("h", "h@x.co", ext="ext-h1"))
    await c.delete("/scim/v2/Users/" + r.json()["id"])
    r = await c.post("/scim/v2/Users", json=ak_user("h", "h@x.co", ext="ext-h2", active=True))
    check("re-provizionare cu ALT externalId, activ → 400 mutability", r.status_code == 400
          and r.json().get("scimType") == "mutability", r.text[:160])
    r = await c.post("/scim/v2/Users", json=ak_user("h", "h@x.co", ext="ext-h2", active=False))
    sid_h = r.json().get("id")
    r = await c.put("/scim/v2/Users/" + sid_h, json=ak_user("h", "h@x.co", ext="ext-h2"))
    row = await db.fetchone("SELECT disabled FROM users WHERE email='h@x.co'")
    check("…apoi PUT active:true cu noul externalId → 400 explicat (reactivarea inclusă), rămâne dezactivat",
          r.status_code == 400 and "re-activation" in r.json().get("detail", "")
          and row["disabled"] == 1, r.text[:240])
    # auditul unei schimbări de identitate ignorate: o dată pe oră pe cont (Authentik re-trimite la
    # FIECARE sincronizare completă)
    like = "%ren@x.co: ignored the identity change%"
    n0 = await audit_n(like)
    sid_ren = (await db.fetchone("SELECT scim_id FROM users WHERE email='ren@x.co'"))["scim_id"]
    for _ in range(3):
        r = await c.put("/scim/v2/Users/" + sid_ren, json=ak_user("ren", "ren.new@x.co", ext="sub-ren",
                                                                   active=False))
    check("PUT-uri repetate cu identitatea refuzată → 200, auditul NU creşte la fiecare sincronizare",
          r.status_code == 200 and n0 == 1 and await audit_n(like) == 1, "%s %s" % (n0, await audit_n(like)))
    # HARDENING: tokenurile de automatizare revocate DOAR după id-ul creatorului
    a = await U.add_user("ta@x.co")
    b = await U.add_user("tb@x.co")
    for name, by_id in (("ta-own", a), ("tb-stale-email", b)):
        await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by,"
                         " created_by_id, expires) VALUES(?,?,'read',?,'ta@x.co',?,?)", name,
                         security.sha256_hex(name), time.time(), by_id, time.time() + 3600)
    r = await owner.post("/api/users/%d/delete" % a, json={"current_password": PW})
    names = {x["name"] for x in await db.fetchall("SELECT name FROM api_tokens WHERE name LIKE 't%-%'")}
    check("ştergerea contului revocă tokenul LUI, nu pe al altuia cu acelaşi email în created_by",
          r.status_code == 200 and "ta-own" not in names and "tb-stale-email" in names, str(names))
    r = await c.post("/scim/v2/Users", json=ak_user("tc", "tc@x.co"))
    sid_tc, tcid = r.json()["id"], await uid_of("tc@x.co")
    for name, by_id in (("tc-own", tcid), ("tb-stale2", b)):
        await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by,"
                         " created_by_id, expires) VALUES(?,?,'read',?,'tc@x.co',?,?)", name,
                         security.sha256_hex(name), time.time(), by_id, time.time() + 3600)
    await c.patch("/scim/v2/Users/" + sid_tc, json=deactivate())
    names = {x["name"] for x in await db.fetchall("SELECT name FROM api_tokens WHERE name LIKE 't%-%'")}
    check("…la fel la dezactivarea prin SCIM", "tc-own" not in names and "tb-stale2" in names, str(names))
    # starea de dinainte de backfill: tokenul fără id primeşte id-ul la pornire, apoi e revocat normal
    pb = await U.add_user("pb@x.co")
    await db.execute("INSERT INTO api_tokens(name, token_hash, scopes, created, created_by, expires)"
                     " VALUES('pb-legacy', ?, 'read', ?, 'pb@x.co', ?)", security.sha256_hex("pb-legacy"),
                     time.time(), time.time() + 3600)
    await db.execute("DELETE FROM app_settings WHERE key='tokens_creator_backfilled'")
    await db.close()
    await db.connect()                     # o pornire nouă: authz.seed face backfill-ul
    row = await db.fetchone("SELECT created_by_id FROM api_tokens WHERE name='pb-legacy'")
    check("pre-backfill: la pornire tokenul primeşte id-ul creatorului", row["created_by_id"] == pb,
          str(dict(row)))
    r = await owner.post("/api/users/%d/delete" % pb, json={"current_password": PW})
    row = await db.fetchone("SELECT 1 FROM api_tokens WHERE name='pb-legacy'")
    check("…şi ştergerea contului îl revocă (după id)", r.status_code == 200 and row is None, r.text[:120])
    # tokenuri de înrolare orfane: insignă „creator gone" + avertisment în System health, NU revocate
    await db.execute("INSERT INTO enroll_groups(name, token_hash, created, created_by, created_by_id,"
                     " expires) VALUES('orph-gone',?,?,'nobody@x.co',987654,?)",
                     security.sha256_hex("orph-gone"), time.time(), time.time() + 3600)
    lst = {x["name"]: x for x in (await owner.get("/api/enroll-groups")).json()}
    check("lista tokenurilor de grup marchează creatorul dispărut (id NULL sau cont şters)",
          lst["orph-gone"]["creator_gone"] is True and lst["eg-legacy"]["creator_gone"] is True
          and lst["eg-new"]["creator_gone"] is False, str({k: v.get("creator_gone") for k, v in lst.items()}))
    res = await syshealth.c_enroll_orphans()
    check("System health: AVERTISMENT doar cu numărul (fără nume de tokenuri), recomandare, salt în Setări",
          res is not None and res.severity == "warning" and res.key == "enroll_orphans"
          and res.params["count"] == 2 and "names" not in res.params
          and res.action == "settings:enroll" and res.rec == "revoke_orphan_enroll", str(res))
    row = await db.fetchone("SELECT revoked FROM enroll_groups WHERE name='orph-gone'")
    check("…fără revocare automată", row["revoked"] == 0)
    for n in ("orph-gone", "eg-legacy"):
        await owner.post("/api/enroll-groups/%d/revoke" % lst[n]["id"])
    res = await syshealth.c_enroll_orphans()
    check("…revocate de Owner → check-ul revine la ok (sau n/a)", res is None or res.severity == "ok", str(res))


async def test_audit_sc01(owner, c):
    """Audit 2026-10-17, SC-01: o coliziune de UNICITATE (email / externalId deja al altui cont)
    bloca dezactivarea — `_email_free` / `_ext_free` rulau în afara umbrelei
    `_guard_identity_or_drop`, deci `{email luat, active:false}` dădea 400 şi persoana rămânea
    ACTIVĂ (reprodus în docs/audit-2026-10-17/tools/scim_repro.py, 3 variante)."""
    print("── audit 2026-10-17 SC-01: o coliziune de email/externalId nu blochează dezactivarea")
    like_ign = "%%%s: ignored the identity change%%"
    # 1. PUT {email deja al altui cont (local), active:false} pe un cont creat de SCIM
    r = await c.post("/scim/v2/Users", json=ak_user("ana", "ana@x.co", ext="sub-ana"))
    sid_ana, ana = r.json()["id"], await uid_of("ana@x.co")
    bob = await U.add_user("bob@x.co")
    r = await c.put("/scim/v2/Users/" + sid_ana, json=ak_user("ana", "bob@x.co", ext="sub-ana"))
    row = await db.fetchone("SELECT email, COALESCE(disabled,0) AS d FROM users WHERE id=?", ana)
    check("PUT {email luat} FĂRĂ active:false → tot 400 invalidValue, nimic schimbat",
          r.status_code == 400 and r.json().get("scimType") == "invalidValue"
          and row["email"] == "ana@x.co" and row["d"] == 0, "%s %s" % (r.status_code, r.text[:160]))
    r = await c.put("/scim/v2/Users/" + sid_ana,
                    json=ak_user("ana", "bob@x.co", ext="sub-ana", active=False))
    row = await db.fetchone("SELECT email, COALESCE(disabled,0) AS d, disabled_by FROM users"
                            " WHERE id=?", ana)
    check("PUT {email luat de alt cont, active:false} → 200, DEZACTIVAT (scim), email neschimbat",
          r.status_code == 200 and r.json().get("active") is False and row["d"] == 1
          and row["disabled_by"] == "scim" and row["email"] == "ana@x.co",
          "%s %s %s" % (r.status_code, r.text[:160], dict(row)))
    check("…identitatea ignorată e auditată (o dată pe oră)", await audit_n(like_ign % "ana@x.co") == 1,
          str(await audit_n(like_ign % "ana@x.co")))
    check("…şi alertată (scim_identity_ignored, avertisment)",
          await n_alerts("scim_identity_ignored", "ana@x.co") == 1)
    b = await db.fetchone("SELECT email, COALESCE(disabled,0) AS d FROM users WHERE id=?", bob)
    check("…contul care deţine emailul e neatins", b["email"] == "bob@x.co" and b["d"] == 0)
    # 2. PATCH {emails[…].value = luat, active:false}
    r = await c.post("/scim/v2/Users", json=ak_user("anb", "anb@x.co", ext="sub-anb"))
    sid_anb, anb = r.json()["id"], await uid_of("anb@x.co")
    r = await c.patch("/scim/v2/Users/" + sid_anb, json={"schemas": [scim.S_PATCH], "Operations": [
        {"op": "replace", "path": 'emails[type eq "other"].value', "value": "bob@x.co"},
        {"op": "replace", "path": "active", "value": False}]})
    row = await db.fetchone("SELECT email, COALESCE(disabled,0) AS d FROM users WHERE id=?", anb)
    check("PATCH {email luat + active:false} → 200, dezactivat, email neschimbat",
          r.status_code == 200 and row["d"] == 1 and row["email"] == "anb@x.co",
          "%s %s %s" % (r.status_code, r.text[:160], dict(row)))
    check("…auditat", await audit_n(like_ign % "anb@x.co") == 1)
    # 3. PUT {externalId deja al altui cont, active:false} pe un cont adoptat fără externalId
    r = await c.post("/scim/v2/Users", json=ak_user("cat", "cat@x.co", ext="sub-cat"))
    check("cont cat (sub-cat) → 201", r.status_code == 201)
    dan = await db.execute("INSERT INTO users(email, password_hash, created, local_password)"
                           " VALUES(?,?,?,0)", "dan@x.co", security.hash_password("x"), time.time())
    r = await c.post("/scim/v2/Users", json=ak_user("dan", "dan@x.co"))
    check("dan (SSO-only, fără externalId) adoptat → 201", r.status_code == 201, r.text[:160])
    sid_dan = r.json()["id"]
    r = await c.put("/scim/v2/Users/" + sid_dan, json=ak_user("dan", "dan@x.co", ext="sub-cat"))
    check("PUT {externalId al lui cat} fără active:false → 400", r.status_code == 400, r.text[:160])
    r = await c.put("/scim/v2/Users/" + sid_dan,
                    json=ak_user("dan", "dan@x.co", ext="sub-cat", active=False))
    row = await db.fetchone("SELECT scim_external_id, COALESCE(disabled,0) AS d FROM users"
                            " WHERE id=?", dan)
    check("PUT {externalId al altui cont, active:false} → 200, dezactivat, externalId rămâne NULL",
          r.status_code == 200 and row["d"] == 1 and row["scim_external_id"] is None,
          "%s %s %s" % (r.status_code, r.text[:160], dict(row)))
    check("…auditat", await audit_n(like_ign % "dan@x.co") == 1)
    cat = await db.fetchone("SELECT scim_external_id, COALESCE(disabled,0) AS d FROM users"
                            " WHERE email='cat@x.co'")
    check("…cat îşi păstrează externalId-ul şi rămâne activ",
          cat["scim_external_id"] == "sub-cat" and cat["d"] == 0)
    # 4. ramura de adopţie din create_user: re-provizionare (după DELETE + Re-enable de Owner) cu
    #    {externalId al contului, email al ALTUI cont, active:false} — înainte: 400 „belong to
    #    different WebTerm accounts”, contul rămânea activ
    r = await c.post("/scim/v2/Users", json=ak_user("eli", "eli@x.co", ext="sub-eli"))
    sid_eli, eli = r.json()["id"], await uid_of("eli@x.co")
    await c.delete("/scim/v2/Users/" + sid_eli)
    r = await owner.post("/api/users/%d/enable" % eli, json={"current_password": PW})
    row = await db.fetchone("SELECT COALESCE(disabled,0) AS d, scim_id FROM users WHERE id=?", eli)
    check("eli: DELETE apoi Re-enable de Owner → activ, nelegat de SCIM",
          r.status_code == 200 and row["d"] == 0 and row["scim_id"] is None, "%s %s" % (r.status_code, dict(row)))
    r = await c.post("/scim/v2/Users", json=ak_user("eli", "bob@x.co", ext="sub-eli"))
    row = await db.fetchone("SELECT COALESCE(disabled,0) AS d, scim_id FROM users WHERE id=?", eli)
    check("POST {externalId al lui eli, email al lui bob} FĂRĂ active:false → 400, nimic schimbat",
          r.status_code == 400 and "different WebTerm accounts" in r.text and row["d"] == 0
          and row["scim_id"] is None, "%s %s" % (r.status_code, r.text[:160]))
    r = await c.post("/scim/v2/Users", json=ak_user("eli", "bob@x.co", ext="sub-eli", active=False))
    row = await db.fetchone("SELECT email, COALESCE(disabled,0) AS d, disabled_by, scim_id,"
                            " scim_external_id FROM users WHERE id=?", eli)
    check("POST {externalId al lui eli, email al lui bob, active:false} → 201, eli DEZACTIVAT sub "
          "emailul LUI, relegat", r.status_code == 201 and r.json().get("emails", [{}])[0].get("value")
          == "eli@x.co" and row["d"] == 1 and row["disabled_by"] == "scim" and row["email"] == "eli@x.co"
          and row["scim_id"] == r.json().get("id") and row["scim_external_id"] == "sub-eli",
          "%s %s %s" % (r.status_code, r.text[:200], dict(row)))
    check("…auditat ca identitate ignorată", await audit_n(like_ign % "eli@x.co") == 1)
    b = await db.fetchone("SELECT email, COALESCE(disabled,0) AS d, scim_managed FROM users WHERE id=?", bob)
    check("…bob (deţinătorul emailului) neatins: activ, nu e al SCIM",
          b["email"] == "bob@x.co" and b["d"] == 0 and not b["scim_managed"])
    # acelaşi POST pentru un cont care se potriveşte DOAR după `sub` (nu creat de SCIM): tot
    # dezactivare în loc, fără resursă (400) — ramura `_disable_unlinked` nu s-a schimbat
    await sso_login("sub-fay", "fay@x.co")
    fay = await uid_of("fay@x.co")
    r = await c.post("/scim/v2/Users", json=ak_user("fay", "bob@x.co", ext="sub-fay", active=False))
    row = await db.fetchone("SELECT COALESCE(disabled,0) AS d, disabled_by, scim_managed FROM users"
                            " WHERE id=?", fay)
    check("POST {sub al lui fay, email al lui bob, active:false} → 400 fără email, fay dezactivat "
          "în loc (scim-identity), nelegat", r.status_code == 400 and "fay@x.co" not in r.text
          and row["d"] == 1 and row["disabled_by"] == "scim-identity" and not row["scim_managed"],
          "%s %s %s" % (r.status_code, r.text[:160], dict(row)))
    # 5. corecţie (rest SC-01): contul e ÎNCĂ provizionat (scim_id), dar IdP-ul şi-a pierdut
    #    legătura şi re-POST-ează {externalId al lui, email al lui bob, active:false} — înainte:
    #    400 „already provisioned” şi persoana rămânea activă
    r = await c.post("/scim/v2/Users", json=ak_user("gus", "gus@x.co", ext="sub-gus"))
    sid_gus, gus = r.json()["id"], await uid_of("gus@x.co")
    r = await c.post("/scim/v2/Users", json=ak_user("gus", "bob@x.co", ext="sub-gus"))
    row = await db.fetchone("SELECT email, COALESCE(disabled,0) AS d FROM users WHERE id=?", gus)
    check("re-POST {externalId al lui gus (provizionat), email al lui bob} FĂRĂ active:false → 400 "
          "(different WebTerm accounts), nimic schimbat", r.status_code == 400
          and "different WebTerm accounts" in r.text
          and row["d"] == 0 and row["email"] == "gus@x.co", "%s %s %s" % (r.status_code, r.text[:160], dict(row)))
    r = await c.post("/scim/v2/Users", json=ak_user("gus", "gus@x.co", ext="sub-gus"))
    check("re-POST cu emailul LUI, fără active:false → 400 already provisioned (se releagă prin discovery)",
          r.status_code == 400 and "already provisioned" in r.text and "deactivated" not in r.text, r.text[:160])
    r = await c.post("/scim/v2/Users", json=ak_user("gus", "bob@x.co", ext="sub-gus", active=False))
    row = await db.fetchone("SELECT email, COALESCE(disabled,0) AS d, disabled_by, scim_id FROM users"
                            " WHERE id=?", gus)
    check("re-POST {…, active:false} → tot 400 already provisioned (IdP-ul se releagă), dar gus "
          "DEZACTIVAT (scim), email neschimbat, scim_id păstrat",
          r.status_code == 400 and "already provisioned" in r.text and "deactivated as requested" in r.text
          and row["d"] == 1 and row["disabled_by"] == "scim" and row["email"] == "gus@x.co"
          and row["scim_id"] == sid_gus, "%s %s %s" % (r.status_code, r.text[:200], dict(row)))
    check("…identitatea ignorată e auditată", await audit_n(like_ign % "gus@x.co") == 1)
    b = await db.fetchone("SELECT email, COALESCE(disabled,0) AS d FROM users WHERE id=?", bob)
    check("…bob neatins", b["email"] == "bob@x.co" and b["d"] == 0)
    r = await c.get("/scim/v2/Users/" + sid_gus)
    check("…GET pe resursa lui gus: active=false", r.status_code == 200 and r.json().get("active") is False,
          "%s %s" % (r.status_code, r.text[:120]))


async def map_group(owner, group, role, kind="all", value=""):
    r = await owner.post("/api/settings/oidc-roles", json={
        "group": group, "role": role, "scope_kind": kind, "scope_value": value, "current_password": PW})
    assert r.status_code == 200, r.text


async def binding_tuples(uid):
    return sorted((r["key"], r["scope_kind"], r["scope_value"], r["source"], r["expires"]) for r in await db.fetchall(
        "SELECT r.key, b.scope_kind, b.scope_value, b.source, b.expires FROM role_bindings b"
        " JOIN roles r ON r.id=b.role_id WHERE b.user_id=?", uid))


async def offboard_state(uid):
    """What SC-02 compares between `active:false` and DELETE: disabled, bindings, group memberships."""
    row = await db.fetchone("SELECT COALESCE(disabled, 0) AS d FROM users WHERE id=?", uid)
    groups = sorted(r["group_id"] for r in await db.fetchall(
        "SELECT group_id FROM scim_group_members WHERE user_id=?", uid))
    return row["d"], await binding_tuples(uid), groups


async def test_sc02_delete_keeps_bindings(owner, c):
    """SC-02 (audit 2026-10-17, decizia owner-ului): DELETE lasă contul EXACT ca active:false —
    dezactivat, cu legăturile de rol ŞI apartenenţele la grupurile SCIM păstrate — ca Re-enable să
    aducă înapoi fiecare rol, cum promit docs/UI. Înainte: DELETE scotea userul din grupuri şi
    re-rula maparea → legăturile SSO dispăreau, persoana primea email „your access changed", iar
    Owner-ul care dădea Re-enable primea un cont fără roluri."""
    print("── SC-02: DELETE păstrează legăturile (ca active:false); Re-enable aduce rolurile înapoi")
    await map_group(owner, "wt-db", "operator", "tag", "db")
    dbhost = await U.add_host(owner, "dbbox", tags="db")
    sids, uids = {}, {}
    for n in ("eva", "evb"):
        r = await c.post("/scim/v2/Users", json=ak_user(n, "%s@x.co" % n, ext="sub-" + n))
        sids[n], uids[n] = r.json()["id"], await uid_of("%s@x.co" % n)
        await U.bind(uids[n], "viewer", "all")              # o legătură dată de mână, pe lângă grup
    r = await c.post("/scim/v2/Groups", json={"schemas": [scim.S_GROUP], "displayName": "wt-db",
                                              "members": [{"value": sids["eva"]}, {"value": sids["evb"]}]})
    check("pregătire: grupul wt-db cu eva şi evb → 201", r.status_code == 201, r.text[:160])
    for n in ("eva", "evb"):
        check("pregătire: %s are operator @ tag:db din grup + viewer manual" % n,
              ("operator", "tag", "db", "sso", None) in await binding_tuples(uids[n])
              and ("viewer", "all", "", "manual", None) in await binding_tuples(uids[n]),
              str(await binding_tuples(uids[n])))
    before = await binding_tuples(uids["eva"])
    n_sync = await audit_n("%SSO roles synced%eva@x.co%")
    n_al = await n_alerts("sso_access_changed", "eva@x.co")
    r = await c.delete("/scim/v2/Users/" + sids["eva"])
    check("DELETE eva → 204", r.status_code == 204, r.text[:120])
    row = await db.fetchone("SELECT disabled, disabled_by, scim_id, scim_managed FROM users WHERE id=?", uids["eva"])
    check("…dezactivat (scim-delete), dezlegat (scim_id NULL), încă scim_managed",
          row["disabled"] == 1 and row["disabled_by"] == "scim-delete" and row["scim_id"] is None
          and row["scim_managed"] == 1, str(dict(row)))
    check("…legăturile de rol sunt NESCHIMBATE (before == after), inclusiv cea din grupul SCIM",
          await binding_tuples(uids["eva"]) == before, "%s → %s" % (before, await binding_tuples(uids["eva"])))
    check("…apartenenţa la grupul SCIM rămâne",
          await db.fetchone("SELECT 1 FROM scim_group_members WHERE user_id=?", uids["eva"]) is not None)
    check("…nicio re-sincronizare: fără rând „SSO roles synced … removed” pentru eva",
          await audit_n("%SSO roles synced%eva@x.co%") == n_sync,
          str(await db.fetchall("SELECT detail FROM audit_log WHERE detail LIKE '%SSO roles synced%eva@x.co%'")))
    check("…şi fără emailul „your access changed” către un cont dezactivat",
          await n_alerts("sso_access_changed", "eva@x.co") == n_al)
    check("…drepturile sunt GOALE cât e dezactivat (legăturile nu se citesc)",
          "session.open" not in await authz.perms_on(await authz.grants_for_user(uids["eva"]), dbhost))
    # active:false pe evb lasă ACEEAŞI stare (în afară de scim_id, pe care doar DELETE îl goleşte)
    r = await c.patch("/scim/v2/Users/" + sids["evb"], json=deactivate())
    check("active:false pe evb → 200", r.status_code == 200 and r.json()["active"] is False, r.text[:120])
    sa, sb = await offboard_state(uids["eva"]), await offboard_state(uids["evb"])
    check("DELETE şi active:false lasă aceeaşi stare: dezactivat, aceleaşi legături, aceleaşi grupuri",
          sa[0] == sb[0] == 1 and sa[1] == sb[1] and sa[2] == sb[2], "%s vs %s" % (sa, sb))
    # Re-enable de Owner: rolurile sunt din nou EFECTIVE
    r = await owner.post("/api/users/%d/enable" % uids["eva"], json={"current_password": PW})
    check("Re-enable (Owner, Settings) → 200", r.status_code == 200, r.text[:160])
    g = await authz.grants_for_user(uids["eva"])
    check("…operator @ tag:db din grup e din nou efectiv pe hostul db",
          "session.open" in await authz.perms_on(g, dbhost), str(await authz.perms_on(g, dbhost)))
    check("…şi viewer manual @ all", "session.watch" in g.all_host_perms, str(g.all_host_perms))
    # re-provizionarea de către IdP readoptă acelaşi cont, cu legăturile lui
    r = await c.post("/scim/v2/Users", json=ak_user("eva", "eva@x.co", ext="sub-eva"))
    check("re-crearea lui eva → acelaşi cont, aceleaşi legături", r.status_code == 201
          and await uid_of("eva@x.co") == uids["eva"] and await binding_tuples(uids["eva"]) == before, r.text[:160])
    # igienă: evb înapoi activ
    await c.patch("/scim/v2/Users/" + sids["evb"], json=deactivate(True))


async def test_rb06_scim_break_glass(owner, c):
    """RB-06 (audit 2026-10-17): IdP-ul nu poate dezactiva ultimul Owner permanent CU PAROLĂ
    LOCALĂ (contul break-glass) — nici prin active:false, nici prin DELETE. În practică SCIM nu
    vede un cont cu parolă locală (`_user`, adopţia re-verificată în UPDATE); verificăm plasa
    (accounts.disable / _active_precheck) direct şi că HTTP-ul nu ajunge la el (404)."""
    print("── RB-06: SCIM nu poate dezactiva contul break-glass (plasă fail-closed, auditată, alertată)")
    # stare reală: parolă locală pusă pe un Owner venit din SSO care era ultimul Owner — /api/account
    # new_password PĂSTREAZĂ legătura Owner (source=sso), deci OwnerLevel nu se aplică
    bg = await U.add_user("bg-scim@x.co", bindings=[("owner", "all", "")])
    await db.execute("UPDATE role_bindings SET source='sso' WHERE user_id=?", bg)
    others = [r["id"] for r in await db.fetchall(
        "SELECT DISTINCT u.id FROM users u JOIN role_bindings b ON b.user_id=u.id JOIN roles r ON r.id=b.role_id"
        " WHERE r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL AND COALESCE(u.local_password, 1)=1"
        " AND COALESCE(u.disabled, 0)=0 AND u.id<>?", bg)]
    saved = {o: (await db.fetchone("SELECT local_password FROM users WHERE id=?", o))["local_password"] for o in others}
    for o in others:
        await db.execute("UPDATE users SET local_password=0 WHERE id=?", o)
    authz.bump_epoch()
    check("pregătire: bg-scim e singurul break-glass, dar nu singurul Owner permanent",
          await authz.owner_count(with_local_password=True) == 1 and await authz.owner_count() >= 2)
    n_au = await audit_n("%refused to disable bg-scim@x.co: the last permanent Owner with a local password%")
    try:
        try:
            await accounts.disable(bg, by="scim", actor=scim.ACTOR, ip="203.0.113.7", reason="SCIM active=false")
            got = None
        except accounts.LastBreakGlass as e:
            got = e
        check("accounts.disable(by='scim') pe contul break-glass → LastBreakGlass", got is not None, repr(got))
        check("…contul rămâne activ", (await db.fetchone("SELECT COALESCE(disabled,0) AS d FROM users WHERE id=?", bg))["d"] == 0)
        check("…auditat (rând 400, via scim)", await audit_n("%refused to disable bg-scim@x.co: the last permanent Owner with a local password%") == n_au + 1
              and await db.fetchone("SELECT 1 FROM audit_log WHERE status=400 AND via='scim' AND detail LIKE '%bg-scim@x.co%break-glass%'") is not None)
        check("…alertă CRITICĂ scim_last_break_glass_refused", await alert_of("scim_last_break_glass_refused", "critical") is not None)
        try:
            await scim._active_precheck(bg, False, "203.0.113.7")
            pe = None
        except scim.ScimError as e:
            pe = e
        check("_active_precheck(active=false) → 400 SCIM, scimType mutability (nu 409: rulează şi în POST /Users)",
              pe is not None and pe.status_code == 400 and pe.scim_type == "mutability"
              and "break-glass" in pe.detail, repr(pe and (pe.status_code, pe.scim_type, pe.detail[:80])))
        try:
            await accounts.disable(bg, by="scim-delete", actor=scim.ACTOR, ip="203.0.113.7", reason="SCIM delete")
            got = None
        except accounts.LastBreakGlass as e:
            got = e
        check("…la fel pe calea DELETE (by='scim-delete')", got is not None)
        # P1 review: fiecare refuz e auditat, dar alerta CRITICĂ pleacă o dată pe oră per cont —
        # Authentik reia toată pagina de sincronizare periodic; un IdP configurat greşit nu
        # trebuie să pagineze flota la fiecare interval pentru acelaşi refuz
        check("…trei refuzuri = trei rânduri de audit, dar O singură alertă (throttle 1 h per cont)",
              await audit_n("%refused to disable bg-scim@x.co: the last permanent Owner with a local password%") == n_au + 3
              and await n_alerts("scim_last_break_glass_refused", "bg-scim@x.co") == 1,
              "audit=%d alerts=%d" % (await audit_n("%refused to disable bg-scim@x.co%"),
                                      await n_alerts("scim_last_break_glass_refused", "bg-scim@x.co")))
        # HTTP: chiar legat forţat de SCIM (doar prin DB), un cont cu parolă locală e invizibil
        await db.execute("UPDATE users SET scim_managed=1, scim_id='forced-bg' WHERE id=?", bg)
        r = await c.patch("/scim/v2/Users/forced-bg", json=deactivate())
        r2 = await c.delete("/scim/v2/Users/forced-bg")
        check("PATCH active:false / DELETE pe el prin HTTP → 404 (SCIM nu vede conturile cu parolă), rămâne activ",
              r.status_code == 404 and r2.status_code == 404
              and (await db.fetchone("SELECT COALESCE(disabled,0) AS d FROM users WHERE id=?", bg))["d"] == 0,
              "%s %s" % (r.status_code, r2.status_code))
        await db.execute("UPDATE users SET scim_managed=0, scim_id=NULL WHERE id=?", bg)
        # cu un al doilea Owner PERMANENT cu parolă locală: dezactivarea trece
        oid = await uid_of(U.OWNER_EMAIL)
        await db.execute("UPDATE users SET local_password=1 WHERE id=?", oid)
        authz.bump_epoch()
        res = await accounts.disable(bg, by="scim", actor=scim.ACTOR, ip="203.0.113.7", reason="SCIM active=false")
        check("cu alt Owner permanent cu parolă: accounts.disable trece", res is not None
              and (await db.fetchone("SELECT COALESCE(disabled,0) AS d FROM users WHERE id=?", bg))["d"] == 1, str(res))
    finally:
        for o, lp in saved.items():
            await db.execute("UPDATE users SET local_password=? WHERE id=?", lp, o)
        await db.execute("UPDATE users SET disabled=0, disabled_at=NULL, disabled_by=NULL WHERE id=?", bg)
        await U.unbind_all(bg)


async def test_flt03_passwd_detaches(owner, c):
    """FL-T03 (2): `python3 -m app.admin passwd` pe un cont SCIM îl desprinde (CHANGELOG 3.6.11):
    scim_id NULL, scim_managed 0, local_password 1, scos din grupurile SCIM, audit /admin/passwd."""
    print("── FL-T03: admin passwd pe un cont SCIM → desprins, cu parolă locală, auditat")
    r = await c.post("/scim/v2/Users", json=ak_user("pw", "pw@x.co", ext="sub-pw"))
    sid, uid = r.json()["id"], await uid_of("pw@x.co")
    r = await c.post("/scim/v2/Groups", json={"schemas": [scim.S_GROUP], "displayName": "wt-pw",
                                              "members": [{"value": sid}]})
    check("pregătire: cont SCIM, membru într-un grup SCIM", r.status_code == 201
          and await db.fetchone("SELECT 1 FROM scim_group_members WHERE user_id=?", uid) is not None)
    old_hash = (await db.fetchone("SELECT password_hash FROM users WHERE id=?", uid))["password_hash"]
    real = admin._read_new_password
    admin._read_new_password = lambda: "Parola-noua-123"
    try:
        await admin.cmd_passwd(argparse.Namespace(email="pw@x.co"))
    finally:
        admin._read_new_password = real
    row = await db.fetchone("SELECT scim_id, scim_managed, local_password, password_hash FROM users WHERE id=?", uid)
    check("scim_id IS NULL, scim_managed=0, local_password=1, hash schimbat",
          row["scim_id"] is None and row["scim_managed"] == 0 and row["local_password"] == 1
          and row["password_hash"] != old_hash, str(dict(row)))
    check("…parola nouă chiar merge", security.verify_password("Parola-noua-123", row["password_hash"]))
    check("…scos din grupurile SCIM", await db.fetchone("SELECT 1 FROM scim_group_members WHERE user_id=?", uid) is None)
    au = await db.fetchone("SELECT actor, via, detail FROM audit_log WHERE path='/admin/passwd' AND actor_id=?", uid)
    check("…rând de audit /admin/passwd „detached from SCIM”", au is not None and "detached from SCIM" in au["detail"]
          and au["via"] == "cli", str(au and dict(au)))
    check("…SCIM nu-l mai vede (GET → 404) şi nu-l mai poate dezactiva",
          (await c.get("/scim/v2/Users/" + sid)).status_code == 404
          and (await c.patch("/scim/v2/Users/" + sid, json=deactivate())).status_code == 404)
    # RB-06 (rbac-sso.md, revizuirea P1): `admin passwd` pe un cont a cărui singură legătură Owner
    # vine din SSO şi care e ULTIMUL Owner permanent nu lasă instanţa fără Owner — legătura
    # Owner @ all rămâne (aceeaşi regulă ca în /api/account new_password); celelalte sso pleacă
    pw2 = await U.add_user("pw2@x.co", bindings=[("owner", "all", ""), ("viewer", "all", "")])
    await db.execute("UPDATE role_bindings SET source='sso' WHERE user_id=?", pw2)
    await db.execute("UPDATE users SET local_password=0, sso_subject='sub-pw2' WHERE id=?", pw2)
    parked = [r["id"] for r in await db.fetchall(
        "SELECT b.id FROM role_bindings b JOIN roles r ON r.id=b.role_id WHERE r.key='owner'"
        " AND b.scope_kind='all' AND b.expires IS NULL AND b.user_id<>?", pw2)]
    for bid in parked:                     # every other permanent Owner becomes time-bound (restored below)
        await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() + 3600, bid)
    authz.bump_epoch()
    try:
        check("pregătire: pw2 e singurul Owner permanent, cu legătura Owner din SSO",
              await authz.owner_count(exclude_user=pw2) == 0 and await authz.owner_count() == 1)
        admin._read_new_password = lambda: "Parola-noua-123"
        try:
            await admin.cmd_passwd(argparse.Namespace(email="pw2@x.co"))
        finally:
            admin._read_new_password = real
        t = await binding_tuples(pw2)
        check("admin passwd pe ULTIMUL Owner: legătura Owner @ all (sso) RĂMÂNE, viewer (sso) pleacă",
              t == [("owner", "all", "", "sso", None)], str(t))
        check("…acum e cont break-glass (Owner permanent cu parolă locală)",
              await authz.owner_count(with_local_password=True) == 1 and await authz.last_break_glass(pw2))
    finally:
        for bid in parked:
            await db.execute("UPDATE role_bindings SET expires=NULL WHERE id=?", bid)
        authz.bump_epoch()
    # RB-06 (revizuirea P1): şi ultimul Owner permanent CU PAROLĂ LOCALĂ îşi păstrează legătura
    # Owner (sso) la `admin passwd` când ceilalţi Owneri permanenţi sunt SSO-only — altfel
    # instanţa rămâne doar cu Owneri pe care o pană a IdP-ului îi lasă afară
    pw4 = await U.add_user("pw4@x.co", bindings=[("owner", "all", ""), ("viewer", "all", "")])
    await db.execute("UPDATE role_bindings SET source='sso' WHERE user_id=?", pw4)
    await db.execute("UPDATE users SET local_password=0, sso_subject='sub-pw4' WHERE id=?", pw4)
    bg_others = [r["id"] for r in await db.fetchall(
        "SELECT DISTINCT u.id FROM users u JOIN role_bindings b ON b.user_id=u.id JOIN roles r ON r.id=b.role_id"
        " WHERE r.key='owner' AND b.scope_kind='all' AND b.expires IS NULL AND COALESCE(u.local_password, 1)=1"
        " AND u.id<>?", pw4)]
    saved_lp = {o: (await db.fetchone("SELECT local_password FROM users WHERE id=?", o))["local_password"]
                for o in bg_others}
    try:
        for o in bg_others:                # ceilalţi Owneri permanenţi devin SSO-only (restauraţi mai jos)
            await db.execute("UPDATE users SET local_password=0 WHERE id=?", o)
        authz.bump_epoch()
        check("pregătire: alţi Owneri permanenţi există, dar toţi SSO-only",
              await authz.owner_count(exclude_user=pw4) >= 1 and await authz.owner_count(with_local_password=True) == 0,
              "%d %d" % (await authz.owner_count(exclude_user=pw4), await authz.owner_count(with_local_password=True)))
        admin._read_new_password = lambda: "Parola-noua-123"
        try:
            await admin.cmd_passwd(argparse.Namespace(email="pw4@x.co"))
        finally:
            admin._read_new_password = real
        t = await binding_tuples(pw4)
        check("admin passwd pe ultimul Owner permanent CU PAROLĂ (ceilalţi SSO-only): legătura Owner (sso) RĂMÂNE, viewer pleacă",
              t == [("owner", "all", "", "sso", None)], str(t))
        check("…pw4 e acum contul break-glass", await authz.last_break_glass(pw4))
    finally:
        for o, lp in saved_lp.items():
            await db.execute("UPDATE users SET local_password=? WHERE id=?", lp, o)
        authz.bump_epoch()
    await U.unbind_all(pw4)
    # cu alt Owner permanent CU PAROLĂ prezent, legătura Owner din SSO pleacă ca oricare alta
    pw3 = await U.add_user("pw3@x.co", bindings=[("owner", "all", "")])
    await db.execute("UPDATE role_bindings SET source='sso' WHERE user_id=?", pw3)
    await db.execute("UPDATE users SET local_password=0, sso_subject='sub-pw3' WHERE id=?", pw3)
    authz.bump_epoch()
    admin._read_new_password = lambda: "Parola-noua-123"
    try:
        await admin.cmd_passwd(argparse.Namespace(email="pw3@x.co"))
    finally:
        admin._read_new_password = real
    check("…dar cu alt Owner permanent: legătura Owner (sso) e scoasă", await binding_tuples(pw3) == [],
          str(await binding_tuples(pw3)))
    await U.unbind_all(pw2)


async def test_flt03_recreated_in_idp(owner, c):
    """FL-T03 (3), CHANGELOG 3.6.11: „A person re-created in the IdP (new externalId) stays
    disabled in WebTerm until an Owner deletes the old account — on purpose (fail closed); the
    error now says so." Şi: emailul unui cont ADOPTAT nu se schimbă prin SCIM (text explicit)."""
    print("── FL-T03: re-creat în IdP (externalId nou) → rămâne dezactivat până un Owner şterge contul vechi")
    await sso_login("sub-old", "old@x.co")
    old = await uid_of("old@x.co")
    await U.bind(old, "viewer", "all")
    r = await c.post("/scim/v2/Users", json=ak_user("old", "old@x.co", ext="sub-old"))
    sid = r.json()["id"]
    check("pregătire: contul SSO old e adoptat", r.status_code == 201 and await uid_of("old@x.co") == old)
    r = await c.put("/scim/v2/Users/" + sid, json=ak_user("old", "old.renamed@x.co", ext="sub-old"))
    check("PUT cu email nou pe cont ADOPTAT → 400 mutability, textul spune că se schimbă doar în WebTerm",
          r.status_code == 400 and r.json().get("scimType") == "mutability"
          and "existed before SCIM took it over" in r.json().get("detail", "")
          and "only be changed in WebTerm" in r.json().get("detail", ""), r.text[:200])
    check("…emailul vechi rămâne", await uid_of("old@x.co") == old and await uid_of("old.renamed@x.co") is None)
    r = await c.put("/scim/v2/Users/" + sid, json=ak_user("old", "old@x.co", ext="sub-old-v2"))
    check("PUT cu externalId NOU pe cont activ → 400 mutability", r.status_code == 400
          and r.json().get("scimType") == "mutability", r.text[:160])
    r = await c.delete("/scim/v2/Users/" + sid)
    check("IdP-ul şterge persoana → 204, dezactivat", r.status_code == 204
          and (await db.fetchone("SELECT disabled FROM users WHERE id=?", old))["disabled"] == 1)
    n_users = (await db.fetchone("SELECT COUNT(*) AS c FROM users"))["c"]
    r = await c.post("/scim/v2/Users", json=ak_user("old", "old@x.co", ext="sub-old-v2"))
    d = r.json().get("detail", "")
    check("re-creat în IdP cu externalId nou → 400 mutability", r.status_code == 400
          and r.json().get("scimType") == "mutability", r.text[:160])
    check("…eroarea spune ce e de făcut: „delete the old WebTerm account (Settings → Users & roles)”",
          "delete the old WebTerm account" in d and "Settings" in d and "re-activation included" in d, d[:240])
    row = await db.fetchone("SELECT disabled, scim_id, scim_external_id FROM users WHERE id=?", old)
    check("…contul vechi rămâne dezactivat, nelegat, cu externalId-ul vechi; niciun cont nou (fail closed)",
          row["disabled"] == 1 and row["scim_id"] is None and row["scim_external_id"] == "sub-old"
          and (await db.fetchone("SELECT COUNT(*) AS c FROM users"))["c"] == n_users, str(dict(row)))
    check("…şi persoana NU poate intra prin SSO cu identitatea veche",
          "sso_error=disabled" in (await sso_login("sub-old", "old@x.co")).headers.get("location", ""))
    r = await owner.post("/api/users/%d/delete" % old, json={"current_password": PW})
    check("un Owner şterge contul vechi → 200", r.status_code == 200, r.text[:160])
    r = await c.post("/scim/v2/Users", json=ak_user("old", "old@x.co", ext="sub-old-v2"))
    new = await uid_of("old@x.co")
    check("…acum re-provizionarea reuşeşte: 201, cont NOU (alt id), activ, fără rolurile celui vechi",
          r.status_code == 201 and new is not None and new != old and r.json()["active"] is True
          and await binding_tuples(new) == [], "%s %s" % (r.status_code, r.text[:160]))


async def main():
    await U.boot()
    owner = await U.owner_client()
    host = await U.add_host(owner, "alpha", folder="prod")
    tok = await make_token(owner)
    c = sc(tok)
    op, sid_op = await test_disable(owner, c, host)
    await test_no_sign_in(op)
    await test_reenable(owner, c, op, sid_op, host)
    sid_op = await test_delete(owner, c, op, sid_op)
    await test_last_owner(owner, c)
    await test_review_owner_level(owner, c)
    await test_review_tokens(owner, c)
    await test_rereview(owner, c)
    await test_rereview2(owner, c)
    await test_audit_sc01(owner, c)
    await test_sc02_delete_keeps_bindings(owner, c)
    await test_rb06_scim_break_glass(owner, c)
    await test_flt03_passwd_detaches(owner, c)
    await test_flt03_recreated_in_idp(owner, c)
    await c.aclose()
    await owner.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
