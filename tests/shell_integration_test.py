"""Integrarea de shell (OSC 133): scriptul servit, digest-ul care îl leagă, instalarea
automată la înrolarea unui host şi opţiunea de refuz. Hermetic (in-process ASGI).

Miza de securitate: scriptul se sursează în FIECARE shell interactiv de pe host. Dacă
cineva îl poate substitui între gateway şi host, rulează cod la fiecare prompt. De-aia
octeţii descărcaţi se verifică faţă de un sha256 transportat prin canalul de încredere.
"""
import asyncio
import hashlib
import os
import re
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "https://wt.example.com"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, security  # noqa: E402
from app.main import app  # noqa: E402

ok = 0
total = 0


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

    script = (config.AGENT_FILE.parent / "shell-integration.sh").read_bytes()
    digest = hashlib.sha256(script).hexdigest()

    # ── scriptul în sine: garduri care trebuie să rămână ──
    text = script.decode()
    check("nu face nimic în shell neinteractiv (scripturile n-au prompt)",
          "case \"$-\" in" in text and "*i*" in text)
    check("tmux: passthrough pe PANE, nu global (altfel orice sesiune poate injecta)",
          "set -p allow-passthrough" in text)
    check("emite toate cele patru marcaje OSC 133",
          all(m in text for m in ('133;$1', '"A"', '"C"', '"D;$e"')))
    # fişierul ajunge în rc-uri; dacă cineva îl sursează dintr-un shell POSIX (/bin/sh =
    # dash), trebuie să iasă curat prin garda de interactivitate, NU să dea „Syntax error"
    # la parsare. Sintaxa bash (array-uri, +=) se ascunde în `eval`. Regresie reală: a fost
    # spartă când am adăugat suport pentru PROMPT_COMMAND ca array.
    import subprocess
    src = str(config.AGENT_FILE.parent / "shell-integration.sh")
    check("scriptul rămâne parsabil de /bin/sh (dash)",
          subprocess.run(["sh", "-n", src], capture_output=True).returncode == 0)
    check("sursat din /bin/sh iese curat (rc=0)",
          subprocess.run(["sh", "-c", ". %s" % src], capture_output=True).returncode == 0)

    # ── comportamentul REAL în bash: marcajele trebuie să supravieţuiască felului în care
    # oamenii îşi construiesc promptul. Rulăm bash interactiv pe un pty (fără `script`,
    # care lipseşte din imaginile slim) şi numărăm marcajele emise.
    def run_bash(rc_body: str, cmds=("echo a", "echo b", "echo c")) -> bytes:
        import pty
        import subprocess
        rc = os.path.join(tempfile.mkdtemp(), "rc")
        with open(rc, "w") as f:
            f.write(rc_body)
        m, s = pty.openpty()
        p = subprocess.Popen(["bash", "--rcfile", rc, "-i"], stdin=s, stdout=s, stderr=s,
                             close_fds=True, env=dict(os.environ, TERM="dumb", PS1="$ "))
        os.close(s)
        os.write(m, ("\n".join(cmds) + "\nexit\n").encode())
        out = b""
        try:
            while True:
                chunk = os.read(m, 65536)
                if not chunk:
                    break
                out += chunk
        except OSError:
            pass
        p.wait(timeout=10)
        os.close(m)
        return out

    def markers(rc_body: str, cmds=("echo a", "echo b", "echo c")) -> dict:
        found = re.findall(rb"\]133;([ABCD])", run_bash(rc_body, cmds))
        return {k: found.count(k.encode()) for k in "ABCD"}

    src_path = str(config.AGENT_FILE.parent / "shell-integration.sh")
    base = "PS1='t$ '\n. %s\n" % src_path
    n = markers(base)
    check("bash normal: toate cele 4 marcaje", min(n.values()) >= 3, str(n))
    # regresia găsită în producţie (host-ul Learning): rc-ul reasigna PS1 DUPĂ linia noastră
    # → B dispărea, iar istoricul înghiţea promptul („root@learning:~# frs" ca text de comandă)
    n = markers(base + "PS1='REASIGNAT$ '\n")
    check("PS1 reasignat după sursare: B supravieţuieşte", n["B"] >= 3, str(n))
    # prompt dinamic (starship/powerline): reconstruieşte PS1 la fiecare prompt, după noi
    n = markers(base + "_dyn() { PS1=\"din-$RANDOM\\$ \"; }\n"
                       "PROMPT_COMMAND=\"${PROMPT_COMMAND:+$PROMPT_COMMAND; }_dyn\"\n",
                cmds=tuple("echo %d" % i for i in range(6)))
    check("prompt dinamic: hook-ul se re-aşază la final şi B revine", n["B"] >= 3, str(n))
    check("prompt dinamic: A/C/D nu se pierd (PROMPT_COMMAND rămâne valid)",
          n["A"] >= 5 and n["D"] >= 5, str(n))
    n = markers(base + ". %s\n" % src_path)
    check("re-sursare: fără marcaje duble", n["B"] <= n["A"], str(n))
    # regresie proprie (v1.0.126→130): ca să ne re-aşezăm la finalul lui PROMPT_COMMAND
    # tăiam şirul pe „;" şi-l reasamblam — dar „;" apare des ÎNTRE GHILIMELE (titlul de
    # terminal). Codul utilizatorului ajungea rescris: `]0;%s` devenea `]0; %s`.
    titled = (base
              + 'PROMPT_COMMAND=\'printf "\\033]0;%s\\007" "$PWD"\''
                '"${PROMPT_COMMAND:+; $PROMPT_COMMAND}"\n'
              + '_dyn() { PS1="d-$RANDOM\\$ "; }\n'
                'PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND; }_dyn"\n')
    out = run_bash(titled, cmds=("echo 1", "echo 2", "echo 3", 'echo "PC=[$PROMPT_COMMAND]"'))
    pc = out.split(b"PC=[")[-1].split(b"]\r")[0] if b"PC=[" in out else b""
    check("PROMPT_COMMAND-ul utilizatorului rămâne NEATINS (';' între ghilimele)",
          b"]0;%s" in pc and b"]0; %s" not in pc, repr(pc[:80]))
    check("hook-ul nostru ajunge ultimul în PROMPT_COMMAND",
          pc.rstrip().endswith(b"_wt_ps1_b"), repr(pc[-40:]))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://t") as anon:
        r = await anon.get("/agent/shell-integration.sh")
        check("scriptul e public (host-ul îl ia fără cookie de browser)", r.status_code == 200)
        check("scriptul servit e IDENTIC cu cel de pe disc",
              hashlib.sha256(r.content).hexdigest() == digest)
        r = await anon.get("/api/shell-integration/command")
        check("comanda de activare cere autentificare", r.status_code == 401)

    async with httpx.AsyncClient(transport=transport, base_url="https://t") as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": "parolabuna1",
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200)
        cmd = (await c.get("/api/shell-integration/command")).json()["command"]
        check("comanda din UI conţine digest-ul curent", digest in cmd)
        check("comanda scrie fişierul cu 0600 (se sursează în fiecare shell)", "0o600" in cmd)
        check("comanda e idempotentă (nu dublează linia din rc)",
              "grep -q 'webterm/shell-integration'" in cmd)

        # ── instalarea automată la înrolarea unui host nou ──
        r = await c.post("/api/hosts", json={"name": "nou"})
        hid = r.json()["id"]
        cmdline = (await c.post(f"/api/hosts/{hid}/enroll")).json()["install_command"]
        path = re.search(r"/install/([A-Za-z0-9_-]+\.sh)", cmdline).group(0)

    async with httpx.AsyncClient(transport=transport, base_url="https://t") as anon:
        r = await anon.get(path)
        check("installer-ul se serveşte cu tokenul din one-liner", r.status_code == 200)
        inst = r.text
    check("installer-ul include integrarea de shell", "shell-integration.sh" in inst)
    check("installer-ul foloseşte ACELAŞI digest (fără drift)", digest in inst)
    check("installer-ul se poate refuza explicit",
          "WEBTERM_NO_SHELL_INTEGRATION" in inst)
    check("installer-ul spune ce a modificat în rc",
          "Shell integration enabled in" in inst)
    check("eşecul integrării nu opreşte instalarea agentului (doar avertizează)",
          "shell integration was not installed" in inst and "set -eu" in inst.splitlines()[2])
    # `.format()` pe un şablon shell: o acoladă neescapată ar fi umplut scriptul cu gunoi
    check("nu au rămas câmpuri de format needucate în script",
          not re.search(r"\{[a-z_]+\}", inst), "câmp rămas")

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
