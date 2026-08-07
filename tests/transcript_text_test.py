"""Vizualizarea TEXT a transcripturilor: curăţarea secvenţelor de control, semantica CR /
backspace, coada pentru UI şi autentificarea. Hermetic (in-process ASGI, fişiere scrise de mână).

Contextul: redarea brută a unei sesiuni închise nu arată nimic util când înăuntru a rulat o
aplicaţie pe tot ecranul — aceea repictează acelaşi ecran, deci sute de KB de redesenări se
prăbuşesc într-un singur ecran. Textul e singurul mod în care „istoricul" devine căutabil.
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
from app import api, config, core, db, security  # noqa: E402
from app.main import app  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


SID = "b" * 32


def write_out(payload: bytes):
    out_path, _ = core.transcript_paths(SID)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(payload)


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    # un transcript ca în realitate: culori, titlu OSC, alt-screen, o bară de progres
    # rescrisă cu CR, o greşeală corectată cu backspace şi redesenări de TUI
    write_out(
        b"\x1b[?1049h\x1b]0;titlu\x07"
        b"\x1b[32mroot@box\x1b[0m:~# ls -la\n"
        b"total 4\n"
        b"descarc: 10%\rdescarc: 50%\rdescarc: 100%\n"
        b"root@box:~# eco\x08\x08\x08echo salut\n"
        b"salut\n"
        b"\x1b[H\x1b[2J\x1b[1;1Hchenar redesenat\n"
        b"\n\n\n\n"
        b"root@box:~# exit\n"
        b"\x1b[?1049l"
    )
    text = core.transcript_text(SID)
    check("nicio secvenţă ESC rămasă în text", "\x1b" not in text)
    check("comenzile se văd", "ls -la" in text and "echo salut" in text)
    check("CR: rămâne doar starea finală a liniei",
          "descarc: 100%" in text and "descarc: 10%" not in text)
    check("backspace aplicat (nu apare textul şters)", "eco" not in text)
    check("titlul OSC nu ajunge în text", "titlu" not in text)
    check("rafalele de linii goale sunt comprimate", "\n\n\n" not in text)
    check("liniile sunt în ordine", text.index("ls -la") < text.index("exit"))

    # regresii găsite pe transcripturi REALE (sesiuni cu Claude Code / TUI):
    write_out(
        b"\x1b(Bre-semneaza\x1b(B ceva\n"                    # desemnare de charset (tmux o emite des)
        b"\x1bOAsageata\n"                                    # SS3
        b"col1\x1b[6Ccol2\n"                                  # aliniere prin salt de cursor
        b"\x1b[1;1Hsus\x1b[5;1Hjos\n"                         # poziţionare absolută (TUI)
    )
    t2 = core.transcript_text(SID)
    check("ESC ( B nu lasă litera în text (bugul cu B lipit de cuvinte)",
          "re-semneaza ceva" in t2 and "BRe" not in t2 and "Bceva" not in t2)
    check("SS3 (ESC O A) consumat complet", "sageata" in t2 and "Asageata" not in t2)
    check("saltul de cursor pe orizontală devine spaţii (cuvintele nu se lipesc)",
          "col1      col2" in t2)
    check("poziţionarea verticală devine linie nouă (nu lipeşte ecranele)",
          "sus" in t2 and "jos" in t2 and "susjos" not in t2)

    # coada: pentru UI citim doar ultimii octeţi, nu tot fişierul
    write_out(b"inceput vechi\n" + b"x" * (3 * 1024 * 1024) + b"\nsfarsit recent\n")
    tail = core.transcript_text(SID, tail_bytes=64 * 1024)
    check("coada conţine sfârşitul", "sfarsit recent" in tail)
    check("coada NU citeşte tot fişierul", "inceput vechi" not in tail)
    check("coada e mărginită", len(tail) <= 64 * 1024 + 16)

    # transcript inexistent → text gol, fără excepţie
    check("sid fără transcript → text gol", core.transcript_text("c" * 32) == "")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as anon:
        r = await anon.get(f"/api/sessions/{SID}/transcript?format=txt")
        check("fără sesiune → 401", r.status_code == 401)

    write_out(b"\x1b[32msalut\x1b[0m din transcript\n")
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": "parolabuna1",
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200)
        r = await c.get(f"/api/sessions/{SID}/transcript?format=txt")
        check("format=txt întoarce text curat",
              r.status_code == 200 and r.text.strip() == "salut din transcript")
        check("txt e servit ca text, nu ca octeţi",
              r.headers["content-type"].startswith("text/plain"))
        check("descărcarea are nume de fişier .txt",
              "attachment" in r.headers.get("content-disposition", ""))
        r = await c.get(f"/api/sessions/{SID}/transcript?format=txt&tail=true")
        check("tail=true e pentru vizualizare (fără attachment)",
              r.status_code == 200 and "attachment" not in r.headers.get("content-disposition", ""))
        r = await c.get(f"/api/sessions/{SID}/transcript?format=out")
        check("formatele vechi merg mai departe (out)",
              r.status_code == 200 and b"\x1b[32m" in r.content)
        r = await c.get("/api/sessions/nu-e-sid-valid/transcript?format=txt")
        check("sid invalid → 404", r.status_code == 404)

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
