"""Backup off-host în cloud (Google Drive / Dropbox): fluxul OAuth, invariantul „doar
arhive criptate", stocarea secretelor și retenția la distanță. Hermetic — providerii sunt
înlocuiți cu un fals în-memorie, nu se atinge rețeaua."""
import asyncio
import json
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "https://wt.example.com"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, backup, cloudbackup, config, db, security  # noqa: E402

# Middleware-ul `csrf_guard` cere `Origin` pe metodele care schimbă ceva şi refuză
# lipsa lui (ca `_origin_ok` pentru WebSocket). Testele imită un BROWSER, deci trimit
# antetul; fără el ar testa o cale pe care niciun browser n-o produce.
_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0


def check(name, cond):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


# ── provider fals: reține ce s-a urcat, ca să putem verifica CONȚINUTUL ──
class FakeCloud:
    def __init__(self):
        self.files = []          # [{id, name, ts, data}]
        self.deleted = []
        self.refreshed = 0

    def install(self):
        cloudbackup.PROVIDERS["fake"] = self
        return self

    # interfața Provider
    id = "fake"
    label = "Fake"
    console_url = ""
    app_type = ""

    def authorize_url(self, cid, redirect, state):
        return f"https://fake/auth?client_id={cid}&redirect_uri={redirect}&state={state}"

    def exchange(self, cid, secret, code, redirect):
        return {"refresh": "refresh-" + code, "access": "access-1"}

    def refresh(self, cid, secret, refresh_token):
        self.refreshed += 1
        return "access-token"

    def account(self, token):
        return "eu@example.com"

    def ensure_folder(self, token, current):
        return current or "folder-1"

    def upload(self, token, folder, name, data):
        self.files.insert(0, {"id": "f%d" % len(self.files), "name": name,
                              "ts": "%d" % (10_000 - len(self.files)), "data": data})

    def list_files(self, token, folder):
        return [{"id": f["id"], "name": f["name"], "ts": f["ts"]} for f in self.files]

    def delete(self, token, file_id):
        self.deleted.append(file_id)
        self.files = [f for f in self.files if f["id"] != file_id]


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    fake = FakeCloud().install()

    PASSWORD = "parolabuna1"
    BK_PASS = "parola-de-backup"

    # ── URL-urile reale de autorizare: fără offline, programarea moare tăcut ──
    g = cloudbackup.PROVIDERS["gdrive"].authorize_url("cid", "https://wt/x", "st")
    check("Drive cere offline + consent (altfel nu vine refresh token)",
          "access_type=offline" in g and "prompt=consent" in g)
    check("Drive cere doar scope-ul drive.file (nu tot Drive-ul)",
          "drive.file" in g and "auth%2Fdrive&" not in g)
    d = cloudbackup.PROVIDERS["dropbox"].authorize_url("cid", "https://wt/x", "st")
    check("Dropbox cere token_access_type=offline", "token_access_type=offline" in d)
    check("redirect_uri se construiește din PUBLIC_URL",
          cloudbackup.redirect_uri() == "https://wt.example.com/api/backup/cloud/callback")

    # ── configurare: validări + secretele nu stau în clar ──
    try:
        await cloudbackup.save_config("fake", "cid", "csecret", "scurta", 5, False)
        check("parolă scurtă respinsă", False)
    except cloudbackup.CloudError:
        check("parolă scurtă respinsă", True)
    try:
        await cloudbackup.save_config("altceva", "cid", "csecret", BK_PASS, 5, False)
        check("provider necunoscut respins", False)
    except cloudbackup.CloudError:
        check("provider necunoscut respins", True)

    await cloudbackup.save_config("fake", "cid", "csecret", BK_PASS, 3, False)
    raw = await db.fetchall("SELECT key, value FROM app_settings WHERE key LIKE 'cloud_%'")
    blob = " ".join(str(r["value"]) for r in raw)
    check("client secret nu e în clar în DB", "csecret" not in blob)
    check("parola de backup nu e în clar în DB", BK_PASS not in blob)
    st = await cloudbackup.status()
    check("status NU întoarce secrete",
          "csecret" not in json.dumps(st) and BK_PASS not in json.dumps(st))
    check("status arată că e configurat, dar neconectat",
          st["configured"] and not st["connected"] and st["has_passphrase"])

    # ── state-ul OAuth e legat de utilizatorul care a pornit fluxul ──
    url = await cloudbackup.authorize_url(1)
    state = url.split("state=")[1]
    try:
        await cloudbackup.finish_authorization(2, "code-x", state)
        check("state legat de user (alt user respins)", False)
    except cloudbackup.CloudError:
        check("state legat de user (alt user respins)", True)
    url = await cloudbackup.authorize_url(1)
    state = url.split("state=")[1]
    cloudbackup._states[state] = (1, time.time() - 1)          # expirat
    try:
        await cloudbackup.finish_authorization(1, "code-x", state)
        check("state expirat respins", False)
    except cloudbackup.CloudError:
        check("state expirat respins", True)

    url = await cloudbackup.authorize_url(1)
    state = url.split("state=")[1]
    await cloudbackup.finish_authorization(1, "code-x", state)
    st = await cloudbackup.status()
    check("după autorizare: conectat + cont afișat",
          st["connected"] and st["account"] == "eu@example.com")
    check("refresh token stocat criptat",
          "refresh-code-x" not in " ".join(
              str(r["value"]) for r in
              await db.fetchall("SELECT value FROM app_settings WHERE key LIKE 'cloud_%'")))

    # ── invariantul: NU urcăm arhive necriptate ──
    await cloudbackup._set(cloudbackup.K_PASSPHRASE, "")
    try:
        await cloudbackup.upload_backup()
        check("fără parolă → refuză uploadul", False)
    except cloudbackup.CloudError:
        check("fără parolă → refuză uploadul", True)
    await cloudbackup._set(cloudbackup.K_PASSPHRASE, security.encrypt_secret(BK_PASS))

    name = await cloudbackup.upload_backup()
    up = fake.files[0]
    check("arhiva a ajuns la provider", up["name"] == name and len(up["data"]) > 0)
    check("ce s-a urcat e CRIPTAT (nu se vede cheia seifului)",
          b"webterm.db" not in up["data"] and b"secret" not in up["data"][:200])
    restored = backup.decrypt(up["data"], BK_PASS)
    check("arhiva urcată se decriptează cu parola configurată", restored.startswith(b"\x1f\x8b"))
    try:
        backup.decrypt(up["data"], "alta-parola")
        check("altă parolă nu deschide arhiva", False)
    except Exception:                       # noqa: BLE001
        check("altă parolă nu deschide arhiva", True)

    # ── retenție la distanță: păstrează `keep`, atinge doar fișierele noastre ──
    fake.files.append({"id": "strain", "name": "poze-vacanta.zip", "ts": "1", "data": b""})
    for _ in range(4):
        await cloudbackup.upload_backup()
    ours = [f for f in fake.files if f["name"].startswith("webterm-")]
    check("retenția păstrează exact `keep` arhive", len(ours) == 3)
    check("fișierele străine din dosar rămân neatinse",
          any(f["name"] == "poze-vacanta.zip" for f in fake.files))

    # ── schimbarea providerului invalidează autorizarea (token pentru alt cont) ──
    await cloudbackup.save_config("fake", "alt-client", "", BK_PASS, 3, False)
    st = await cloudbackup.status()
    check("schimbarea clientului deconectează", not st["connected"])

    # ── API: auth + re-auth cu parola contului ──
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://t", headers=_ORIGIN) as anon:
        for path in ("/api/backup/cloud", "/api/backup/cloud/authorize"):
            r = await anon.get(path)
            check(f"GET {path} fără sesiune → 401", r.status_code == 401)
        r = await anon.post("/api/backup/cloud/config", json={"provider": "fake", "client_id": "x"})
        check("POST config fără sesiune → 401", r.status_code == 401)

    async with httpx.AsyncClient(transport=transport, base_url="https://t", headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": PASSWORD,
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200)
        r = await c.post("/api/backup/cloud/config", json={
            "provider": "fake", "client_id": "cid2", "client_secret": "s2",
            "passphrase": BK_PASS, "keep": 5, "current_password": "gresita"})
        check("config fără parola contului → 401", r.status_code == 401)
        r = await c.post("/api/backup/cloud/config", json={
            "provider": "fake", "client_id": "cid2", "client_secret": "s2",
            "passphrase": BK_PASS, "keep": 5, "current_password": PASSWORD})
        check("config cu re-auth corect → 200", r.status_code == 200)
        check("răspunsul de config nu conține secrete", "s2" not in r.text and BK_PASS not in r.text)
        r = await c.get("/api/backup/cloud")
        check("statusul listează providerii pentru UI",
              any(p["id"] == "gdrive" for p in r.json()["providers"]))
        r = await c.post("/api/backup/cloud/disconnect")
        check("disconnect păstrează configurarea, taie tokenul",
              r.json()["configured"] and not r.json()["connected"])
        r = await c.post("/api/backup/cloud/upload")
        check("upload fără conexiune → 400 explicit", r.status_code == 400)

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
