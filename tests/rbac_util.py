"""Fixture comune pentru suitele de roluri (rbac_*_test.py) — NU e un test în sine.

O instanţă hermetică (DB temporar, fără agent): un Owner creat prin `/api/setup`, două hosturi
în foldere diferite (`prod` / `lab`), conturi suplimentare inserate direct cu legăturile cerute,
fiecare cu propriul client HTTP (cookie) — exact cum le-ar vedea un browser.
"""
import os
import sys
import tempfile
import time

# Mediul TREBUIE pus înainte de primul `import app` (config citeşte env la import).
os.environ.setdefault("WEBTERM_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("WEBTERM_SETUP_TOKEN", "test-setup")
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://localhost:8000")
os.environ.setdefault("WEBTERM_UPDATE_CHECK", "0")          # fără reţea din teste
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gateway"))

import httpx  # noqa: E402
from app import api, authz, config, db, security  # noqa: E402
from app.main import app  # noqa: E402

ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
OWNER_EMAIL, OWNER_PW = "owner@x.co", "parolaowner1"


class Checker:
    def __init__(self):
        self.ok = 0
        self.total = 0

    def __call__(self, name, cond, detail=""):
        self.total += 1
        self.ok += 1 if cond else 0
        print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))

    def summary(self) -> bool:
        print(f"\n{self.ok}/{self.total} teste trecute")
        return self.ok == self.total


def client(**kw) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t",
                             timeout=30, headers=dict(ORIGIN, **kw.pop("headers", {})), **kw)


async def boot():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()


async def owner_client():
    c = client()
    r = await c.post("/api/setup", json={"email": OWNER_EMAIL, "password": OWNER_PW,
                                         "setup_token": "test-setup"})
    assert r.status_code == 200, r.text
    return c


async def add_host(owner, name, folder="", tags="", **extra) -> int:
    r = await owner.post("/api/hosts", json=dict({"name": name, "folder": folder, "tags": tags},
                                                 **extra))
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def add_user(email, pw="parolabuna1", bindings=()) -> int:
    uid = await db.execute("INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
                           email, security.hash_password(pw), time.time())
    for role, kind, value in bindings:
        await bind(uid, role, kind, value)
    return uid


async def bind(uid, role, kind="all", value="") -> int:
    rid = await authz.role_id(role)
    bid = await db.execute(
        "INSERT INTO role_bindings(user_id, role_id, scope_kind, scope_value, source, created)"
        " VALUES(?,?,?,?,'manual',?)", uid, rid, kind, str(value), time.time())
    authz.bump_epoch()
    return bid


async def unbind_all(uid):
    await db.execute("DELETE FROM role_bindings WHERE user_id=?", uid)
    authz.bump_epoch()


async def login(email, pw="parolabuna1") -> httpx.AsyncClient:
    """Un cookie de sesiune web pentru cont, fără cererea de login (care ar număra IP-uri noi şi
    ar porni alerte) — exact ce face `/api/login` după verificarea parolei."""
    row = await db.fetchone("SELECT id FROM users WHERE email=?", email)
    tok = await security.create_web_session(row["id"], "rbac-test", False)
    c = client(cookies={security.COOKIE_NAME: tok})
    return c


async def add_session(host_id, sid=None, state="live", created_by=None) -> str:
    import secrets
    sid = sid or secrets.token_hex(16)
    await db.execute(
        "INSERT INTO sessions(id, host_id, title, state, created, created_by_id)"
        " VALUES(?,?,?,?,?,?)", sid, host_id, "t-" + sid[:6], state, time.time(), created_by)
    return sid


async def add_forward(host_id, slug, enabled=1, app_type="") -> int:
    return await db.execute(
        "INSERT INTO port_forwards(host_id, label, slug, target_host, target_port, scheme,"
        " enabled, created, app_type) VALUES(?,?,?,?,?,?,?,?,?)",
        host_id, slug, slug, "127.0.0.1", 8080, "http", enabled, time.time(), app_type)


def code(r) -> str:
    return r.headers.get("x-webterm-error", "")
