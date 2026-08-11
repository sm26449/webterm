"""Comanda de instalare a agentului — inclusiv varianta cu user dedicat.

Textul ăsta ajunge lipit într-un shell, adesea ca root, pe o maşină de producţie. Deci nu e
„doar UI": forma lui e o suprafaţă. Testele de aici fixează ce trebuie să conţină (linger,
token-ul corect, -k doar în insecure) şi, mai important, ce NU trebuie — să nu se strecoare
vreodată un `rm`, un `chmod 777` sau un pipe către root.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
# http, nu https: cu PUBLIC_URL https cookie-ul de sesiune e Secure şi httpx nu-l
# trimite pe http://t → tot API-ul răspunde 401 şi testul pare că e despre altceva
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

    plain = api._install_command("TOK123")
    ded = api._install_command_dedicated("TOK123")

    check("varianta simplă e un one-liner care se termină în | sh", plain.endswith("| sh"))
    # comanda trebuie să meargă şi pe imagini minimale fără curl: scriptul adus are deja
    # fallback curl→wget, dar comanda care îl aduce nu avea şi murea cu „curl: not found"
    check("are fallback pe wget (imagini fără curl)",
          "command -v curl" in plain and "wget " in plain, plain)
    check("conţine tokenul de enroll", "/install/TOK123.sh" in plain and "/install/TOK123.sh" in ded)
    check("foloseşte URL-ul public configurat", config.PUBLIC_URL in plain)
    check("fără -k pe gateway cu CA publică", " -fsS " in plain and "-fsSk" not in plain)

    # ── varianta cu user dedicat ──
    check("creează userul dedicat", f"useradd -m -s /bin/bash {api.AGENT_USER}" in ded)
    check("useradd tolerează userul existent (comanda se poate relua)", "|| true" in ded)
    check("activează linger — altfel serviciul moare la logout",
          f"loginctl enable-linger {api.AGENT_USER}" in ded)
    check("rulează instalarea CA userul dedicat", f"sudo -iu {api.AGENT_USER}" in ded)
    check("linger vine ÎNAINTE de instalare",
          ded.index("enable-linger") < ded.index("sudo -iu"), ded)
    check("instalarea propriu-zisă e aceeaşi comandă", plain in ded)
    check("nu rulează instalarea ca root", "sudo sh -c 'curl" not in ded and "| sudo sh" not in ded)

    # ── ce nu are voie să apară niciodată în text care se lipeşte într-un shell ──
    for bad in ("rm -rf", "chmod 777", "curl | sudo", "&&rm", "> /etc/", "dd if="):
        check(f"nu conţine „{bad}”", bad not in ded and bad not in plain)
    # „curl" apare de două ori: o dată în `command -v curl`, o dată ca descărcare.
    # Ce contează e să existe UN SINGUR fetch pe fiecare ramură.
    check("o singură descărcare efectivă pe fiecare ramură",
          ded.count("curl -fsS") == 1 and ded.count("wget ") == 1, ded)
    check("aceeaşi adresă în ambele ramuri", ded.count("/install/TOK123.sh") == 2, ded)
    check("fără newline (rămâne un one-liner de copiat)", "\n" not in ded and "\n" not in plain)

    # ── insecure: -k şi în varianta dedicată ──
    config.AGENT_INSECURE = True
    try:
        check("insecure → -k în ambele variante",
              "-fsSk" in api._install_command("T") and "-fsSk" in api._install_command_dedicated("T"))
    finally:
        config.AGENT_INSECURE = False

    # ── API: ambele variante ajung la UI, pe crearea de host şi pe re-enroll ──
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
        h = (await c.post("/api/hosts", json={"name": "nou"})).json()
        check("crearea hostului întoarce ambele variante",
              "/install/" in h.get("install_command", "")
              and h.get("install_command", "").endswith("| sh")
              and h.get("install_command_dedicated", "").startswith("sudo useradd"),
              str(h.get("install_command_dedicated"))[:60])
        r = (await c.post(f"/api/hosts/{h['id']}/enroll")).json()
        check("re-enroll (reinstalare) le întoarce pe amândouă",
              "install_command" in r and "install_command_dedicated" in r, str(r.keys()))
        check("re-enroll schimbă tokenul în AMBELE variante",
              r["install_command"] != h["install_command"]
              and r["install_command_dedicated"] != h["install_command_dedicated"])

    print(f"\n{ok}/{total} passed")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        # o excepţie fără db.close() lasă firul non-daemon al aiosqlite viu şi procesul
        # atârnă la shutdown în loc să pice cu traceback
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
