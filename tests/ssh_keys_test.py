"""Chei de deploy host→host (Toolbox → SSH keys) — auditul v54 (H-1..H-4).

Modelul: privata se naşte pe hostul SURSĂ şi nu-l părăseşte; gateway-ul ţine doar publica +
graful de deploy. FakeAgent-ul de aici EXECUTĂ rețetele shell pe bune (sh -c, HOME=tempdir),
deci idempotenţa, permisiunile şi revoke-ul pe blob se verifică pe un filesystem real, nu pe
mock-uri. Ce verificăm:
  * H-1: o „publică" cu linii multiple / non-ed25519 e refuzată la citire (sshkey.badPublic);
  * H-3: deploy-ul cere un factor PROASPĂT şi pe hosturi FĂRĂ require_2fa (403 stepup.password),
    iar parola greşită nu trece; un Bearer de automatizare nu se autentifică deloc (401);
  * rețete: append idempotent (şi peste schimbarea opţiunilor from= — o singură linie per blob),
    perms 700/600, revoke scoate DOAR blob-ul nostru (linia străină rămâne) inclusiv când linia
    a fost editată manual pe ţintă; grep exit 1 pe fişier golit nu e eroare;
  * verify: deployed / edited / missing; delete refuzat cât există deploy-uri active;
  * garda anti-pivot: generate pe o ţintă activă → 409 sshkey.pivot, trece cu confirmed;
  * selfDeploy şi notAgent (ţinte doar hosturi de agent).
"""
import asyncio
import base64
import os
import shutil
import subprocess
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"

# o cheie ed25519 validă, fixă (doar material PUBLIC) — pt. hosturile unde „adoptăm" fişiere
# pre-existente fără să depindem de ssh-keygen pe maşina de test
FIXED_PUB = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPZm4qhqNbyCLZbB9jTZ8oS7Ku+m+9lSpM9C7EOMi3O"
             " webterm-deploy")
OTHER_LINE = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7yFEwUsWjKmO4XByC2C6nsz9bosZya1cSHSMedTiTM"
              " somebody-else")


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeAgent(core.AgentConnection):
    """Execută op-urile `run` şi `fs_read` REAL, cu HOME-ul redirectat într-un tempdir —
    exact ce face agentul (shell + fs), minus WS-ul."""

    def __init__(self, host_id, home):
        self.host_id = host_id
        self.home = home

    async def request(self, op, timeout=20.0, **kw):
        if op == "run":
            p = subprocess.run(["/bin/sh", "-c", kw["cmd"]],
                               env={**os.environ, "HOME": self.home},
                               capture_output=True, timeout=30)
            return {"ok": True, "exit_code": p.returncode,
                    "stdout": p.stdout.decode(), "stderr": p.stderr.decode()}
        if op == "fs_read":
            path = kw["path"]
            if path.startswith("~"):
                path = self.home + path[1:]
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError as e:
                return {"ok": False, "msg": str(e)}
            return {"ok": True, "data_b64": base64.b64encode(data).decode(), "eof": True}
        return {"ok": False, "msg": "unsupported op " + op}

    async def disconnect(self):
        pass


def seed_key(home, pub):
    os.makedirs(os.path.join(home, ".ssh"), mode=0o700, exist_ok=True)
    with open(os.path.join(home, ".ssh", "webterm_ed25519"), "w") as f:
        f.write("FAKE PRIVATE KEY MATERIAL\n")
    with open(os.path.join(home, ".ssh", "webterm_ed25519.pub"), "w") as f:
        f.write(pub + "\n")


def ak_path(home):
    return os.path.join(home, ".ssh", "authorized_keys")


def ak_lines(home):
    try:
        with open(ak_path(home)) as f:
            return [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return []


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    homes = {n: tempfile.mkdtemp(prefix="wtssh-" + n) for n in ("src", "tgt", "evil", "third")}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30,
                                 headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
        uid = (await db.fetchone("SELECT id FROM users WHERE email=?", "a@b.co"))["id"]
        ids = {}
        for n in ("src", "tgt", "evil", "third"):
            ids[n] = (await c.post("/api/hosts", json={"name": n})).json()["id"]
            core.sources[ids[n]] = FakeAgent(ids[n], homes[n])
        rd = await c.post("/api/hosts", json={"name": "direct", "connection_type": "ssh",
                                              "hostname": "1.2.3.4", "ssh_username": "u",
                                              "auth_method": "password", "credential": "x"})
        direct_id = rd.json()["id"]

        def hdr(r):
            return r.headers.get("X-WebTerm-Error")

        # ── generate ─────────────────────────────────────────────────────────
        r = await c.get(f"/api/hosts/{ids['src']}/deploy-key")
        check("GET fără cheie → key null", r.status_code == 200 and r.json()["key"] is None, r.text)
        r = await c.post(f"/api/hosts/{direct_id}/deploy-key/generate", json={})
        check("generate pe host SSH-direct → 400 sshkey.notAgent",
              r.status_code == 400 and hdr(r) == "sshkey.notAgent", r.text)

        if shutil.which("ssh-keygen"):
            r = await c.post(f"/api/hosts/{ids['src']}/deploy-key/generate", json={})
            check("generate (ssh-keygen real) → 200 + fingerprint SHA256",
                  r.status_code == 200 and r.json()["fingerprint"].startswith("SHA256:"), r.text)
            check("privata există pe host, 600",
                  (os.stat(os.path.join(homes["src"], ".ssh", "webterm_ed25519")).st_mode & 0o777)
                  == 0o600)
        else:
            seed_key(homes["src"], FIXED_PUB)
            r = await c.post(f"/api/hosts/{ids['src']}/deploy-key/generate", json={})
            check("generate (adoptă fişier existent) → 200",
                  r.status_code == 200 and r.json()["fingerprint"].startswith("SHA256:"), r.text)
        src_pub = r.json()["public_key"]
        r = await c.post(f"/api/hosts/{ids['src']}/deploy-key/generate", json={})
        check("generate din nou → 409 sshkey.exists",
              r.status_code == 409 and hdr(r) == "sshkey.exists", r.text)

        # H-1: „publica" vine de pe un host potenţial compromis — o a doua linie strecurată
        # (cheia atacatorului) trebuie refuzată la citire, nu propagată pe ţinte
        seed_key(homes["evil"], FIXED_PUB + "\n" + OTHER_LINE)
        r = await c.post(f"/api/hosts/{ids['evil']}/deploy-key/generate", json={})
        check("H-1: pub cu linii multiple → 400 sshkey.badPublic",
              r.status_code == 400 and hdr(r) == "sshkey.badPublic", r.text)
        seed_key(homes["third"], OTHER_LINE.replace("ssh-ed25519", "ssh-rsa"))
        r = await c.post(f"/api/hosts/{ids['third']}/deploy-key/generate", json={})
        check("H-1: alt tip de cheie → 400 sshkey.badPublic",
              r.status_code == 400 and hdr(r) == "sshkey.badPublic", r.text)

        # ── H-3: deploy = acordare de acces → factor PROASPĂT şi pe hosturi non-2FA ──
        dep = {"key_host_id": ids["src"]}
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/deploy", json=dep)
        check("H-3: deploy fără factor → 403 stepup.password",
              r.status_code == 403 and hdr(r) == "stepup.password", r.text)
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/deploy",
                         json=dep | {"stepup_password": "gresita"})
        check("H-3: parolă greşită → 403", r.status_code == 403, r.text)
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/deploy",
                         json=dep | {"stepup_password": PW})
        check("deploy cu parola contului → 200", r.status_code == 200, r.text)
        lines = ak_lines(homes["tgt"])
        check("authorized_keys are exact linia publică", lines == [src_pub], str(lines))
        check("perms ~/.ssh=700, authorized_keys=600",
              (os.stat(os.path.join(homes["tgt"], ".ssh")).st_mode & 0o777) == 0o700
              and (os.stat(ak_path(homes["tgt"])).st_mode & 0o777) == 0o600)
        r = await c.post("/api/hosts", json={"name": "x"},
                         headers={"Authorization": "Bearer wt_fake", **_ORIGIN})
        check("Bearer de automatizare pe rutele cookie-only → nu se autentifică",
              r.status_code in (200, 401))   # require_user ignoră Bearer; tokenul fals nu-l ajută
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/deploy", json=dep)
        check("re-deploy idempotent (fereastră proaspătă) → 200 şi tot o linie",
              r.status_code == 200 and ak_lines(homes["tgt"]) == [src_pub], r.text)

        # opţiuni: re-deploy cu from= ÎNLOCUIEŞTE linia (un blob = o linie), nu acumulează
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/deploy",
                         json=dep | {"from_ip": "10.0.0.5"})
        lines = ak_lines(homes["tgt"])
        check("re-deploy cu from= → o singură linie, cu opţiune",
              r.status_code == 200 and lines == ['from="10.0.0.5" ' + src_pub], str(lines))
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/deploy",
                         json=dep | {"from_ip": 'x";evil'})
        check("from= cu caractere interzise → 400 sshkey.badFrom",
              r.status_code == 400 and hdr(r) == "sshkey.badFrom", r.text)
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/deploy", json=dep)
        check("înapoi fără opţiuni → tot o linie curată",
              r.status_code == 200 and ak_lines(homes["tgt"]) == [src_pub], r.text)
        r = await c.post(f"/api/hosts/{ids['src']}/deploy-key/deploy", json=dep)
        check("selfDeploy → 400", r.status_code == 400 and hdr(r) == "sshkey.selfDeploy", r.text)

        # ── verify: deployed / edited / missing ──────────────────────────────
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/verify", json=dep)
        check("verify → deployed", r.json().get("status") == "deployed", r.text)
        with open(ak_path(homes["tgt"]), "w") as f:
            f.write("no-pty " + src_pub + "\n")
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/verify", json=dep)
        check("linia editată manual → edited", r.json().get("status") == "edited", r.text)
        os.unlink(ak_path(homes["tgt"]))
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/verify", json=dep)
        check("fişier lipsă → missing", r.json().get("status") == "missing", r.text)

        # ── revoke: scoate DOAR blob-ul nostru, chiar de pe o linie editată ──
        with open(ak_path(homes["tgt"]), "w") as f:
            f.write(OTHER_LINE + "\n" + 'from="1.1.1.1" ' + src_pub + "\n")
        os.chmod(ak_path(homes["tgt"]), 0o600)
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/revoke", json=dep)
        lines = ak_lines(homes["tgt"])
        check("revoke pe blob → linia noastră (editată) dispare, cea străină rămâne",
              r.status_code == 200 and r.json()["removed"] and lines == [OTHER_LINE], str(lines))
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/revoke", json=dep)
        check("revoke idempotent → 200, removed=false",
              r.status_code == 200 and r.json()["removed"] is False, r.text)
        r = await c.get(f"/api/hosts/{ids['src']}/deploy-key")
        deps_list = r.json()["deployments"]
        check("deployment marcat revoked în evidenţă",
              len(deps_list) == 1 and deps_list[0]["status"] == "revoked", r.text)

        # ── delete: refuzat cât există deploy-uri active ─────────────────────
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/deploy", json=dep)
        check("re-deploy după revoke → 200", r.status_code == 200, r.text)
        r = await c.delete(f"/api/hosts/{ids['src']}/deploy-key")
        check("delete cu deploy activ → 409 sshkey.hasDeployments",
              r.status_code == 409 and hdr(r) == "sshkey.hasDeployments", r.text)

        # ── garda anti-pivot: tgt e ŢINTĂ activă → o cheie pe el creează lanţ ──
        seed_key(homes["tgt"], OTHER_LINE)
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/generate", json={})
        check("generate pe o ţintă activă → 409 sshkey.pivot",
              r.status_code == 409 and hdr(r) == "sshkey.pivot", r.text)
        r = await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/generate", json={"confirmed": True})
        check("cu confirmed=true → 200", r.status_code == 200, r.text)
        r = await c.get(f"/api/hosts/{ids['tgt']}/deploy-key")
        inb = r.json()["inbound"]
        check("inbound pe ţintă arată cheia sursei",
              len(inb) == 1 and inb[0]["source_host_id"] == ids["src"], r.text)

        # ── ţintă cu require_2fa: AMBELE gărzi (step-up H1 + factor proaspăt H-3) pe o parolă ──
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", ids["third"])
        os.makedirs(os.path.join(homes["third"], ".ssh"), mode=0o700, exist_ok=True)
        for f in ("webterm_ed25519", "webterm_ed25519.pub"):
            p3 = os.path.join(homes["third"], ".ssh", f)
            if os.path.exists(p3):
                os.unlink(p3)
        r = await c.post(f"/api/hosts/{ids['third']}/deploy-key/deploy", json=dep)
        check("ţintă 2FA fără factor → 403 (step-up)", r.status_code == 403, r.text)
        r = await c.post(f"/api/hosts/{ids['third']}/deploy-key/deploy",
                         json=dep | {"stepup_password": PW})
        check("ţintă 2FA cu parolă → 200 (trece şi H1 şi H-3)",
              r.status_code == 200 and src_pub in ak_lines(homes["third"]), r.text)
        await c.post(f"/api/hosts/{ids['third']}/deploy-key/revoke", json=dep)
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", ids["third"])

        # GET pe host 2FA cere step-up (topologia SSH e sensibilă — audit v54 #6)
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", ids["third"])
        security.clear_stepup_for(uid)
        r = await c.get(f"/api/hosts/{ids['third']}/deploy-key")
        check("GET deploy-key pe host 2FA fără step-up → 403", r.status_code == 403, r.text)

        # DEADLOCK regression (audit v54 #1): fereastră VECHE dar validă pe host 2FA. Un factor
        # proaspăt prin /stepup trebuie să reîmprospăteze opened_at, altfel _require_fresh_factor
        # rămâne pe veci nesatisfăcut şi deploy-ul intră în buclă de 403.
        import time as _t
        security._stepup_windows[(uid, ids["third"])] = (_t.time() - 400, _t.time() + 300)
        check("fereastra veche NU e „proaspătă” (>120s)",
              not security.stepup_window_fresh(uid, ids["third"]))
        r = await c.post(f"/api/hosts/{ids['third']}/stepup", json={"stepup_password": PW})
        check("/stepup cu parolă pe fereastră veche → 200 (reînnoieşte opened_at)",
              r.status_code == 200, r.text)
        check("după /stepup fereastra E proaspătă",
              security.stepup_window_fresh(uid, ids["third"]))
        r = await c.post(f"/api/hosts/{ids['third']}/deploy-key/deploy", json=dep)
        check("deploy fără creds în corp, pe fereastra proaspătă → 200 (fără deadlock)",
              r.status_code == 200, r.text)
        await c.post(f"/api/hosts/{ids['third']}/deploy-key/revoke",
                     json=dep | {"stepup_password": PW})
        # /stepup cu parolă GREŞITĂ pe host non-2FA → 401, nu 200 tăcut (audit v54 #2)
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", ids["third"])
        r = await c.post(f"/api/hosts/{ids['third']}/stepup", json={"stepup_password": "gresita"})
        check("/stepup parolă greşită pe host non-2FA → 401 (nu 200 tăcut)",
              r.status_code == 401, r.text)

        # ── agent offline: deploy → 409, nimic scris, nimic în evidenţă ──────
        saved = core.sources.pop(ids["third"])
        r = await c.post(f"/api/hosts/{ids['third']}/deploy-key/deploy",
                         json=dep | {"stepup_password": PW})
        check("agent offline la deploy → 409", r.status_code == 409, r.text)
        core.sources[ids["third"]] = saved

        # curăţenie: revoke + delete pe src → fişierele dispar de pe host
        await c.post(f"/api/hosts/{ids['tgt']}/deploy-key/revoke", json=dep)
        r = await c.delete(f"/api/hosts/{ids['src']}/deploy-key")
        check("delete după revoke → 200 şi fişierele şterse de pe sursă",
              r.status_code == 200
              and not os.path.exists(os.path.join(homes["src"], ".ssh", "webterm_ed25519")),
              r.text)
        r = await c.get(f"/api/hosts/{ids['src']}/deploy-key")
        check("după delete → key null", r.json()["key"] is None, r.text)

        # ── ţintă ŞTEARSĂ din flotă: evidenţa NU dispare (cheia e încă pe maşină), dar nici
        #    nu blochează pentru totdeauna ştergerea cheii de pe sursă ─────────
        seed_key(homes["src"], FIXED_PUB)
        r = await c.post(f"/api/hosts/{ids['src']}/deploy-key/generate", json={})
        check("re-generate pe src (adopţie) → 200", r.status_code == 200, r.text)
        r = await c.post(f"/api/hosts/{ids['evil']}/deploy-key/deploy",
                         json=dep | {"stepup_password": PW})
        check("deploy pe ţinta ce va fi ştearsă → 200", r.status_code == 200, r.text)
        await c.delete(f"/api/hosts/{ids['evil']}")
        r = await c.get(f"/api/hosts/{ids['src']}/deploy-key")
        dl = r.json()["deployments"]
        check("ţintă ştearsă → rândul rămâne vizibil, fără nume (orfan marcat)",
              len(dl) == 1 and dl[0]["target_name"] in ("", None), r.text)
        r = await c.delete(f"/api/hosts/{ids['src']}/deploy-key")
        check("orfanul nu blochează ştergerea cheii de pe sursă",
              r.status_code == 200, r.text)

    await db.close()
    for h in homes.values():
        shutil.rmtree(h, ignore_errors=True)
    print(f"\n{ok}/{total} checks passed")
    if ok != total:
        raise SystemExit(1)


asyncio.run(main())
