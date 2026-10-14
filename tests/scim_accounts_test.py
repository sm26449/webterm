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
from app import admin, api, authz, core, db, oidc, oidc_api, scim, security, webauthn_api  # noqa: E402
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
    check("adopţie prin externalId = sub dar ALT email → 409, contul neatins", r.status_code == 409
          and r.json().get("scimType") == "uniqueness" and before == after, r.text[:200])
    r = await c.post("/scim/v2/Users", json=ak_user("o2", "o2@x.co", ext="sub-o2"))
    after = dict(await db.fetchone("SELECT * FROM users WHERE id=?", o2))
    check("adopţia unui cont cu Owner dat în WebTerm → 409 (chiar cu emailul lui), neatins",
          r.status_code == 409 and "Owner-level" in r.json().get("detail", "") and before == after,
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
    check("…la fel pentru un rol custom cu o permisiune doar-de-Owner (%s)" % perms, r.status_code == 409,
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
    check("…SCIM nu schimbă emailul unui cont pe care nu l-a creat (409 mutability)",
          r.status_code == 409 and r.json().get("scimType") == "mutability"
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
    check("…nici emailul nu i-l schimbă (409)", r.status_code == 409 and await uid_of("mo@x.co") == mo)
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
    rows = await db.fetchall("SELECT revoked FROM enroll_groups WHERE name LIKE 'eg-%'")
    check("dezactivarea revocă tokenurile de grup ale contului (după id şi, vechi, după email)",
          len(rows) == 2 and all(x["revoked"] == 1 for x in rows), str([dict(x) for x in rows]))
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
    await c.aclose()
    await owner.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
