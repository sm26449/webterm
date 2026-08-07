"""Coada de transcript trimisă browserului la ataşare nu trebuie să-l lase blocat în
ecranul alternativ.

Bug real (host de producţie): fereastra de 256 KB începea cu `ESC[?1049h` — ieşirea
rămăsese înaintea ei. Browserul intra în alt-screen şi nu mai ieşea; cum tracker-ul de
comenzi ignoră DELIBERAT marcajele din alt-screen (rândurile de acolo dispar la ieşire),
toate marcajele OSC 133 erau aruncate: panoul ⌘ rămânea pe „activează integrarea", iar
istoricul global gol — deşi shell-ul emitea corect (verificat în transcript).
"""
import os
import re
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, core  # noqa: E402

ok = 0
total = 0
ALT = re.compile(rb"\x1b\[\?(?:1049|1047|47)([hl])")


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def write(sid, payload):
    config.ensure_dirs()
    out, _ = core.transcript_paths(sid)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(payload)


def ends_in_alt(data):
    m = ALT.findall(data)
    return bool(m) and m[-1] == b"h"


def main():
    # 1. coadă TĂIATĂ care începe în mijlocul unui alt-screen (cazul din producţie)
    sid = "a" * 32
    write(sid, b"\x1b[?1049h" + b"TUI care repicteaza\n" * 20000 + b"prompt$ ")
    tail = core.read_tail(sid, limit=4096)
    check("coada tăiată nu lasă browserul în ecran alternativ", not ends_in_alt(tail))
    check("conţinutul rămâne (scoatem doar comutările)", b"prompt$" in tail)

    # 2. coadă ÎNTREAGĂ (sesiune proaspătă): fluxul tmux ÎNCEPE cu intrarea în alt-screen,
    #    iar ieşirea vine abia la detach — deci fără strip, orice sesiune nouă e blocată.
    #    Ăsta era cazul din producţie; cel tăiat mergea din întâmplare.
    sid = "b" * 32
    write(sid, b"\x1b[?1049h" + b"prompt$ ls\nfisiere\n")
    tail = core.read_tail(sid, limit=1024 * 1024)
    check("coadă NEtăiată: intrarea tmux în alt-screen nu ajunge la browser",
          not ALT.search(tail), repr(tail[:40]))
    check("conţinutul sesiunii proaspete rămâne", b"prompt$ ls" in tail)

    # 3. sesiune ÎNCHISĂ: la fel, plus clear-screen-ul de la clientul tmux mort
    sid = "c" * 32
    write(sid, b"\x1b[?1049hceva\x1b[2J\x1b[?1049l")
    tail = core.read_tail(sid, limit=1024 * 1024)
    check("replay-ul unei sesiuni închise n-are comutări/clear",
          not ALT.search(tail) and b"\x1b[2J" not in tail)

    # 4. o coadă tăiată care e „curată" nu trebuie să-şi piardă conţinutul
    sid = "d" * 32
    write(sid, b"x" * 20000 + b"\nultima linie\n")
    tail = core.read_tail(sid, limit=4096)
    check("coada tăiată fără alt-screen păstrează sfârşitul", tail.endswith(b"ultima linie\n"))

    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
