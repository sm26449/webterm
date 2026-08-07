"""Validarea țintei de forward (`_validate_forward`) — allowlist strict pe target_host.

Motivul securitate: blocklist-ul vechi lăsa să treacă ESC (0x1b) și restul C0, iar un
target_host cu secvențe ANSI ajungea în terminal/transcript prin marcajul de reconectare
telnet, ocolind filtrul OSC. Allowlist-ul (`[A-Za-z0-9._:-]`) elimină clasa. Acceptă
hostname / IPv4 / IPv6; respinge orice caracter de control sau metacaracter."""
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app.api import _validate_forward  # noqa: E402
from fastapi import HTTPException  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def rejected(host, port=23, scheme="telnet"):
    try:
        _validate_forward(host, port, scheme)
        return False
    except HTTPException:
        return True


# --- ținte legitime: acceptate ---
for h in ["1.2.3.4", "192.168.88.1", "switch1.lan.local", "fe80::1", "::1", "host_name", "a-b.c"]:
    check(f"acceptă {h!r}", not rejected(h), "respins greșit")

# --- injecție de secvențe în terminal (motivul fix-ului): respinse ---
for h, why in [
    ("1.2.3.4\x1b[2J", "ESC (clear screen)"),
    ("1.2.3.4\x1b]0;pwn\x07", "ESC OSC set-title"),
    ("a\x07b", "BEL"),
    ("a\x00b", "NUL"),
    ("a\x7fb", "DEL"),
    ("a\x9bb", "CSI 8-bit"),
]:
    check(f"respinge control char: {why}", rejected(h), h.encode().hex())

# --- metacaractere clasice (CRLF/slash/@/spațiu): respinse ---
for h in ["a\r\nb", "a b", "a/b", "a\\b", "a@b", "a\tb"]:
    check(f"respinge metacaracter {h!r}", rejected(h))

# --- degenerate ---
check("respinge gol", rejected(""))
check("respinge >255", rejected("x" * 256))

# --- scheme & port (regresie pe restul validării) ---
check("scheme necunoscut respins", rejected("1.2.3.4", scheme="gopher"))
check("scheme telnet acceptat", not rejected("1.2.3.4", scheme="telnet"))
check("scheme http acceptat", not rejected("1.2.3.4", scheme="http"))
check("port 0 respins", rejected("1.2.3.4", port=0))
check("port 70000 respins", rejected("1.2.3.4", port=70000))

print(f"\n{ok}/{total} PASS")
sys.exit(0 if ok == total else 1)
