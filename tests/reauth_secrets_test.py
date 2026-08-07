"""Re-autentificare pe operaţiile cu secrete + rezolvarea IP-ului real (fail-closed).

Invariantul, într-o frază: **un cookie furat nu trebuie să fie de ajuns.**

De ce a existat gaura: descărcarea backup-ului cerea o parolă… dar aia e parola de CRIPTARE
a arhivei, aleasă de cel care descarcă. Nu dovedeşte nimic. Restul API-ului cerea deja parola
CONTULUI pentru lucruri mai mici (creare de cont, token de automatizare), deci incoerenţa era
exact pe operaţiile grele. Semnalat de un audit extern pe 2026-08-06.

Ce e în arhivă: `data/secret` (cheia care decriptează toate credenţialele SSH şi tokenurile de
agent) plus cheia de semnare a flotei. Iar `restore` merge în sens invers: cine încarcă o arhivă
a lui înlocuieşte baza de date — adică şi conturile — şi preia instanţa.
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
WRONG = "parolagresita9"


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
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})

        # ── 1. descărcarea backup-ului ────────────────────────────────────────
        body = {"passphrase": "criptareaMea1", "include_transcripts": False}
        r = await c.post("/api/backup/download", json=body)
        check("backup download FĂRĂ parola contului → 401", r.status_code == 401, str(r.status_code))
        r = await c.post("/api/backup/download", json={**body, "current_password": WRONG})
        check("backup download cu parolă greşită → 401", r.status_code == 401, str(r.status_code))
        r = await c.post("/api/backup/download", json={**body, "current_password": PW})
        check("backup download cu parola contului → merge", r.status_code == 200, str(r.status_code))
        check("arhiva chiar vine (nu un răspuns gol)", len(r.content) > 100, str(len(r.content)))
        check("parola de criptare nu e confundată cu cea a contului",
              (await c.post("/api/backup/download",
                            json={"passphrase": PW, "current_password": "criptareaMea1"})).status_code == 401)

        # ── 2. restore: preluarea instanţei, în sens invers ───────────────────
        blob = r.content
        r = await c.post("/api/backup/restore", content=blob, headers={
            "Content-Type": "application/octet-stream",
            "X-Restore-Pass": "criptareaMea1"})
        check("restore FĂRĂ parola contului → 401", r.status_code == 401, str(r.status_code))
        r = await c.post("/api/backup/restore", content=blob, headers={
            "Content-Type": "application/octet-stream",
            "X-Restore-Pass": "criptareaMea1", "X-Reauth-Pass": WRONG})
        check("restore cu parolă greşită → 401", r.status_code == 401, str(r.status_code))

        # ── 3. cheia de semnare a flotei ─────────────────────────────────────
        r = await c.post("/api/signing/generate", json={"passphrase": ""})
        check("generarea cheii FĂRĂ parola contului → 401", r.status_code == 401, str(r.status_code))
        r = await c.post("/api/signing/generate", json={"passphrase": "", "current_password": PW})
        check("generarea cheii cu parola contului → merge", r.status_code == 200, str(r.status_code))

        r = await c.post("/api/signing/backup", json={"passphrase": "exportulMeu1"})
        check("exportul cheii FĂRĂ parola contului → 401", r.status_code == 401, str(r.status_code))
        r = await c.post("/api/signing/backup", json={"passphrase": "exportulMeu1",
                                                      "current_password": PW})
        check("exportul cheii cu parola contului → merge", r.status_code == 200, str(r.status_code))

        r = await c.post("/api/signing/import", json={"pem": "x", "current_password": WRONG})
        check("importul cheii cu parolă greşită → 401", r.status_code == 401, str(r.status_code))

        # ── 4. mesajul spune CE se cere, ca omul să nu creadă că e parola arhivei ──
        r = await c.post("/api/backup/download", json=body)
        check("mesajul de refuz explică ce parolă se cere",
              "account password" in r.text and "backup" in r.text, r.text[:120])

        # ── 5. ce NU s-a stricat: operaţiile obişnuite nu cer re-auth ─────────
        check("listarea backup-urilor rămâne fără re-auth",
              (await c.get("/api/backup/status")).status_code == 200)
        check("starea cheii de semnare rămâne fără re-auth",
              (await c.get("/api/signing/status")).status_code == 200)

    # ── 6. fără sesiune, totul e 401 (nu 400/500 care ar scurge existenţa) ──
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as anon:
        for path in ("/api/backup/download", "/api/signing/backup", "/api/signing/generate"):
            r = await anon.post(path, json={"passphrase": "x", "current_password": PW})
            check(f"anonim pe {path} → 401", r.status_code == 401, str(r.status_code))

    # ── 7. IP-ul real: antet cu mai puţine intrări decât hop-uri = NU-l credem ──
    # Contează fiindcă pe IP se ţine lockout-ul şi rate-limitul: cine îşi alege „IP-ul real"
    # scapă de propriul lockout sau îl provoacă pe al altcuiva.
    class FakeReq:
        def __init__(self, xff, peer="10.0.0.9"):
            self.headers = {"x-forwarded-for": xff} if xff else {}
            self.client = type("C", (), {"host": peer})()

    saved = config.TRUSTED_PROXY_HOPS
    try:
        config.TRUSTED_PROXY_HOPS = 1
        check("1 hop, un singur XFF → clientul văzut de proxy",
              security.client_ip(FakeReq("1.2.3.4")) == "1.2.3.4")
        check("1 hop, XFF forjat în stânga → luăm ultimul, nu primul",
              security.client_ip(FakeReq("9.9.9.9, 1.2.3.4")) == "1.2.3.4")
        config.TRUSTED_PROXY_HOPS = 2
        check("2 hop-uri, 2 intrări → prima e clientul",
              security.client_ip(FakeReq("1.2.3.4, 172.16.0.1")) == "1.2.3.4")
        check("2 hop-uri, O SINGURĂ intrare → NU credem antetul, luăm peer-ul (fail-closed)",
              security.client_ip(FakeReq("9.9.9.9")) == "10.0.0.9",
              security.client_ip(FakeReq("9.9.9.9")))
        check("fără XFF → peer-ul socketului", security.client_ip(FakeReq("")) == "10.0.0.9")
        check("XFF gol/virgule → peer-ul socketului",
              security.client_ip(FakeReq(" , ,")) == "10.0.0.9")
        # peer PUBLIC = cererea a venit direct la aplicaţie, nu prin proxy-ul nostru →
        # antetul e scris de client şi nu spune nimic despre el
        config.TRUSTED_PROXY_HOPS = 1
        check("peer public → XFF ignorat complet (nu e proxy-ul nostru)",
              security.client_ip(FakeReq("1.2.3.4", peer="8.8.8.8")) == "8.8.8.8",
              security.client_ip(FakeReq("1.2.3.4", peer="8.8.8.8")))
        check("peer privat → XFF crezut (proxy pe reţeaua docker)",
              security.client_ip(FakeReq("1.2.3.4", peer="172.18.0.5")) == "1.2.3.4")
        check("peer loopback → XFF crezut (proxy pe aceeaşi maşină)",
              security.client_ip(FakeReq("1.2.3.4", peer="127.0.0.1")) == "1.2.3.4")
        # listă explicită de CIDR-uri: doar proxy-ul declarat, nu orice reţea privată
        config.TRUSTED_PROXY_CIDRS = ["172.18.0.0/16"]
        check("CIDR explicit: peer din proxy → XFF crezut",
              security.client_ip(FakeReq("1.2.3.4", peer="172.18.0.5")) == "1.2.3.4")
        check("CIDR explicit: alt peer privat → XFF IGNORAT",
              security.client_ip(FakeReq("1.2.3.4", peer="10.9.9.9")) == "10.9.9.9",
              security.client_ip(FakeReq("1.2.3.4", peer="10.9.9.9")))
        config.TRUSTED_PROXY_CIDRS = ["ceva-invalid"]
        check("CIDR invalid nu deschide poarta (fail-closed)",
              security.client_ip(FakeReq("1.2.3.4", peer="172.18.0.5")) == "172.18.0.5")
        config.TRUSTED_PROXY_CIDRS = []
    finally:
        config.TRUSTED_PROXY_HOPS = saved
        config.TRUSTED_PROXY_CIDRS = []

    print(f"\n{ok}/{total} passed")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
