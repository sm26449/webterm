"""Teste pentru shim-ul telnet IAC (gateway/app/telnet.py) — modul pur, fără I/O.

Device-ul telnet din capăt e NE-DE-ÎNCREDERE, deci parserul trebuie să: (1) negocieze
corect opțiunile esențiale fără bucle, (2) scoată IAC din fluxul spre terminal, (3)
reziste la orice input ostil (IAC tăiat între citiri, subnegociere uriașă, IAC IAC).
Unit + fuzz. Niciun proces gateway/agent necesar."""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
from app import telnet as T  # noqa: E402
from app.telnet import (IAC, DO, DONT, WILL, WONT, SB, SE, NOP,  # noqa: E402
                        OPT_ECHO, OPT_SGA, OPT_TTYPE, OPT_NAWS)

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def sh(rows=24, cols=80):
    return T.TelnetShim(rows=rows, cols=cols)


# 1. passthrough curat, fără protocol
s = sh()
check("passthrough", s.receive(b"hello world") == b"hello world" and s.drain() == b"")

# 2. IAC IAC = 0xFF literal în date
s = sh()
check("IAC IAC -> 0xFF literal", s.receive(b"a\xff\xffb") == b"a\xffb")

# 3. device DO TTYPE -> noi WILL TTYPE, nimic în terminal
s = sh()
clean = s.receive(bytes((IAC, DO, OPT_TTYPE)))
check("DO TTYPE stripped din output", clean == b"")
check("DO TTYPE -> WILL TTYPE", s.drain() == bytes((IAC, WILL, OPT_TTYPE)))

# 4. device DO NAWS -> WILL NAWS + subnegociere cu dimensiunea
s = sh(rows=24, cols=80)
s.receive(bytes((IAC, DO, OPT_NAWS)))
out = s.drain()
expect = bytes((IAC, WILL, OPT_NAWS, IAC, SB, OPT_NAWS, 0, 80, 0, 24, IAC, SE))
check("DO NAWS -> WILL NAWS + size(80x24)", out == expect, out.hex())

# 5. device WILL ECHO -> noi DO ECHO; them_will_echo True
s = sh()
s.receive(bytes((IAC, WILL, OPT_ECHO)))
check("WILL ECHO -> DO ECHO", s.drain() == bytes((IAC, DO, OPT_ECHO)))
check("them_will_echo True", s.them_will_echo is True)

# 6. device WILL <opțiune necunoscută> -> DONT
s = sh()
s.receive(bytes((IAC, WILL, 99)))
check("WILL necunoscut -> DONT", s.drain() == bytes((IAC, DONT, 99)))

# 7. device DO <opțiune necunoscută> -> WONT
s = sh()
s.receive(bytes((IAC, DO, 99)))
check("DO necunoscut -> WONT", s.drain() == bytes((IAC, WONT, 99)))

# 8. subnegociere TTYPE SEND -> IS xterm-256color
s = sh()
s.receive(bytes((IAC, SB, OPT_TTYPE, 1, IAC, SE)))   # 1 = SEND
resp = s.drain()
expect = bytes((IAC, SB, OPT_TTYPE, 0)) + b"xterm-256color" + bytes((IAC, SE))
check("TTYPE SEND -> IS xterm-256color", resp == expect, resp)

# 9. IAC tăiat între feed-uri (3 bucăți) -> același rezultat
s = sh()
s.receive(bytes((IAC,)))
s.receive(bytes((DO,)))
c = s.receive(bytes((OPT_TTYPE,)))
check("IAC split pe 3 feed-uri", c == b"" and s.drain() == bytes((IAC, WILL, OPT_TTYPE)))

# 10. date + IAC NOP întrețesute -> NOP dispare, datele rămân
s = sh()
check("IAC NOP înghițit", s.receive(b"he" + bytes((IAC, NOP)) + b"llo") == b"hello")

# 11. subnegociere uriașă fără SE -> mărginită, fără crash/OOM
s = sh()
s.receive(bytes((IAC, SB, OPT_TTYPE)) + b"\x00" * 100000)
check("SB uriașă mărginită la _MAX_SB", len(s._sbbuf) <= T._MAX_SB, str(len(s._sbbuf)))
# după închiderea SB, revine la normal și livrează date
s.receive(bytes((IAC, SE)))
check("recuperare după SB uriașă", s.receive(b"xyz") == b"xyz")

# 12. anti-buclă: DO SGA de două ori -> un singur WILL
s = sh()
s.receive(bytes((IAC, DO, OPT_SGA)))
first = s.drain()
s.receive(bytes((IAC, DO, OPT_SGA)))
second = s.drain()
check("anti-buclă DO SGA", first == bytes((IAC, WILL, OPT_SGA)) and second == b"", second.hex())

# 13. resize -> NAWS doar după ce a fost negociat
s = sh(rows=24, cols=80)
check("resize fără NAWS negociat = gol", s.resize(30, 100) == b"")
s2 = sh(rows=24, cols=80)
s2.receive(bytes((IAC, DO, OPT_NAWS)))
s2.drain()
naws = s2.resize(30, 100)
check("resize după NAWS -> subnegociere nouă",
      naws == bytes((IAC, SB, OPT_NAWS, 0, 100, 0, 30, IAC, SE)), naws.hex())
check("resize idempotent (aceeași dimensiune = gol)", s2.resize(30, 100) == b"")

# 14. send() escapează IAC din input-ul userului
s = sh()
check("send escapează 0xFF", s.send(b"a\xffb") == b"a\xff\xffb")
check("send fără 0xFF = neschimbat", s.send(b"ls -la\r") == b"ls -la\r")

# 15. NAWS cu dimensiune care conține 255 -> octetul se dublează (escaping în SB)
s = sh(rows=255, cols=80)
s.receive(bytes((IAC, DO, OPT_NAWS)))
out = s.drain()
# height=255 -> 0x00 0xff, iar 0xff se dublează în subnegociere
check("NAWS escapează 255 în payload", bytes((0, 80, 0, 255, 255)) in out, out.hex())

# ---- FUZZ: parserul nu trebuie să crape NICIODATĂ pe input ostil ----
rng = random.Random(1234)
fuzz_ok = True
bound_ok = True
for _ in range(20000):
    n = rng.randint(0, 40)
    data = bytes(rng.randint(0, 255) for _ in range(n))
    try:
        s.receive(data)
        s.drain()
    except Exception as e:            # noqa: BLE001
        fuzz_ok = False
        print("    fuzz crash:", e, data.hex())
        break
    if len(s._sbbuf) > T._MAX_SB:      # bufferul de subnegociere rămâne mărginit
        bound_ok = False
        break
check("fuzz: fără crash pe 20000 input-uri aleatorii", fuzz_ok)
check("fuzz: buffer subnegociere mărginit sub orice input", bound_ok)

# ---- proprietate: byte-cu-byte == tot-odată (mașina de stări e consistentă) ----
prop_ok = True
for _ in range(2000):
    n = rng.randint(0, 60)
    data = bytes(rng.randint(0, 255) for _ in range(n))
    a = sh(); b = sh()
    clean_a = a.receive(data); drain_a = a.drain()
    clean_b = bytearray();
    for byte in data:
        clean_b += b.receive(bytes((byte,)))
    drain_b = b.drain()
    if bytes(clean_a) != bytes(clean_b) or drain_a != drain_b:
        prop_ok = False
        print("    mismatch pe:", data.hex())
        break
check("byte-cu-byte identic cu tot-odată", prop_ok)

# ---- clean output nu conține IAC brut necerut (doar prin IAC IAC) ----
s = sh()
clean = s.receive(bytes((IAC, DO, OPT_SGA)) + b"data" + bytes((IAC, WILL, OPT_ECHO)))
check("IAC scos complet din output", clean == b"data")


# ========================================================================
# F5 — OscFilter: elimină OSC 133/52 din output de device ne-de-încredere
# ========================================================================
def osc():
    return T.OscFilter()

# text simplu neatins
check("OSC: passthrough text", osc().filter(b"hello world") == b"hello world")

# OSC 133 (BEL-terminat) eliminat complet
f = osc()
check("OSC 133 (BEL) eliminat",
      f.filter(b"a\x1b]133;A\x07b") == b"ab")

# OSC 133 (ST-terminat: ESC \) eliminat
f = osc()
check("OSC 133 (ST) eliminat",
      f.filter(b"x\x1b]133;D;0\x1b\\y") == b"xy")

# NORMALIZARE numerică: identificator ne-canonic (0133/052) — xterm îl parsează ca 133/52,
# deci trebuie filtrat la fel (altfel un device ostil ocolește filtrul cu ESC ]0133;)
f = osc()
check("OSC 0133 (zero în față) eliminat", f.filter(b"a\x1b]0133;A\x07b") == b"ab")
f = osc()
check("OSC 052 (zero în față) eliminat", f.filter(b"a\x1b]052;c;QQ==\x07b") == b"ab")
f = osc()
check("OSC 0 (titlu) rămâne — nu confundat cu 052", f.filter(b"\x1b]0;t\x07x") == b"\x1b]0;t\x07x")

# OSC 52 (clipboard) eliminat
f = osc()
check("OSC 52 clipboard eliminat",
      f.filter(b"\x1b]52;c;aGVsbG8=\x07done") == b"done")

# OSC ne-țintă (titlu = OSC 0) trece NEATINS
f = osc()
title = b"\x1b]0;my title\x07"
check("OSC 0 (titlu) pass-through", f.filter(b"pre" + title + b"post") == b"pre" + title + b"post")

# OSC 2 (titlu) pass-through cu ST
f = osc()
t2 = b"\x1b]2;win\x1b\\"
check("OSC 2 (titlu, ST) pass-through", f.filter(t2) == t2)

# CSI/SGR (culori) neatins
f = osc()
sgr = b"\x1b[31mRED\x1b[0m"
check("CSI/SGR neatins", f.filter(sgr) == sgr)

# --- evaziune: OSC 52 fragmentat byte-cu-byte NU trebuie să scape ---
f = osc()
payload = b"pre\x1b]52;c;ZXZpbA==\x07post"
acc = bytearray()
for byte in payload:
    acc += f.filter(bytes((byte,)))
check("OSC 52 fragmentat byte-cu-byte tot eliminat", bytes(acc) == b"prepost", bytes(acc))

# --- fragmentare exact pe ESC ] (split între recv-uri) ---
f = osc()
out = f.filter(b"a\x1b") + f.filter(b"]133;B\x07b")
check("OSC 133 tăiat pe ESC] tot eliminat", out == b"ab", out)

# --- id tăiat („13" apoi „3;...") ---
f = osc()
out = f.filter(b"\x1b]13") + f.filter(b"3;C\x07z")
check("OSC 133 cu id tăiat tot eliminat", out == b"z", out)

# --- OSC uriașă fără terminator: bufferul rămâne mărginit (fără OOM) ---
# La depășirea plafonului filtrul abandonează OSC-ul și revine la NORMAL (prefixul e deja
# consumat → niciun 133/52 nu scapă); octeții rămași ies ca text inofensiv.
f = osc()
f.filter(b"\x1b]0;")                    # deschide un OSC ne-țintă, fără terminator
maxlen = 0
data = b"A" * (T._OSC_MAX + 5000)
for i in range(0, len(data), 100):
    f.filter(data[i:i + 100])
    maxlen = max(maxlen, len(f._buf))
check("OSC uriașă fără terminator: buffer mărginit", maxlen <= T._OSC_MAX + 4, maxlen)

# --- ESC ESC (nu e OSC) trece ---
f = osc()
check("ESC ESC pass-through", f.filter(b"\x1b\x1b[0m") == b"\x1b\x1b[0m")

# --- byte-cu-byte identic cu tot-odată (mașina OSC e consistentă) ---
prop_ok = True
corpus = [b"\x1b]133;A\x07", b"\x1b]52;c;QQ==\x1b\\", b"\x1b]0;t\x07",
          b"plain", b"\x1b[1mX\x1b[0m", b"\xff\x1b]133;\x07mix"]
for _ in range(3000):
    data = b"".join(rng.choice(corpus) for _ in range(rng.randint(0, 6)))
    a = osc(); b = osc()
    whole = a.filter(data)
    piece = bytearray()
    for byte in data:
        piece += b.filter(bytes((byte,)))
    if whole != bytes(piece):
        prop_ok = False
        print("    OSC mismatch pe:", data.hex())
        break
check("OSC: byte-cu-byte identic cu tot-odată", prop_ok)

# --- OSC 133/52 injectate în zgomot aleator NU supraviețuiesc (nici fragmentate) ---
strip_ok = True
targets = [b"\x1b]133;A\x07", b"\x1b]133;D;0\x1b\\", b"\x1b]52;c;ZXZpbA==\x07",
           b"\x1b]52;c;\x1b\\"]
for _ in range(5000):
    # zgomot fără ESC (ca să nu introducem accidental alte secvențe), cu ținte injectate
    noise = bytes(rng.randint(0, 254) if rng.random() > 0.02 else 0x20 for _ in range(rng.randint(0, 30)))
    noise = noise.replace(b"\x1b", b" ")
    data = noise + rng.choice(targets) + noise
    f = osc()
    # livrare fragmentată aleator, ca un device ostil care taie secvența
    out = bytearray()
    i = 0
    while i < len(data):
        step = rng.randint(1, 4)
        out += f.filter(data[i:i + step])
        i += step
    if b"\x1b]133" in out or b"\x1b]52;" in out:
        strip_ok = False
        print("    OSC scurs:", data.hex())
        break
check("fuzz: OSC 133/52 injectat+fragmentat nu supraviețuiește", strip_ok)

failed = [n for n, c in results if not c]
print(f"\n{len(results) - len(failed)}/{len(results)} PASS")
sys.exit(1 if failed else 0)
