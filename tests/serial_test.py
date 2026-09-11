"""Hermetic: consola serială din agent (agent/ptyd.py) contra unui PTY — un device caracter real,
controlabil, care se comportă ca `/dev/tty*`. Închide golul semnalat de audit: `_configure_serial`
(termios: baud/biţi/paritate/stop/raw), enumerarea porturilor şi bridge-ul brut de octeţi n-aveau
NICIUN test. Restul căii (gateway ↔ agent ↔ device fizic) cere un agent real + hardware, deci stă
pe treapta `local`/`stack`; aici testăm exact bucata de protocol-pe-octeţi care ascunde bug-uri."""
import os
import sys
import termios

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import ptyd  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


def _captured_cflags(fd, baud, bits, parity, stop, flow):
    """Rulează `_configure_serial` capturând array-ul termios pe care îl trimite la `tcsetattr`.
    Testăm LOGICA funcţiei (ce cflag calculează), nu ce reflectă înapoi un PTY: PTY-urile Linux
    nu onorează CSIZE/PARENB/CSTOPB (n-au UART real), deci un readback ar rata bucata de config
    seriala care contează. Capturarea la `tcsetattr` e sursa adevărului pentru codul sub test."""
    seen = {}
    orig = termios.tcsetattr

    def spy(f, when, attrs):
        seen["a"] = list(attrs)
        return orig(f, when, attrs)
    termios.tcsetattr = spy
    try:
        ptyd._configure_serial(fd, baud, bits, parity, stop, flow)
    finally:
        termios.tcsetattr = orig
    return seen["a"]


def main():
    # un PTY = pereche master/slave; slave-ul e un tty real (baud + bridge de octeţi funcţionează)
    master, slave = os.openpty()
    try:
        # 1. baud nesuportat ⇒ ValueError (nu configurează orbeşte)
        raised = False
        try:
            ptyd._configure_serial(slave, 9601, 8, "none", 1, "none")
        except ValueError:
            raised = True
        check("baud nesuportat ⇒ ValueError", raised)

        # 2. 9600 8N1 raw — verificăm array-ul termios pe care îl calculează funcţia
        a = _captured_cflags(slave, 9600, 8, "none", 1, "none")
        check("baud 9600 setat (ispeed+ospeed)", a[4] == termios.B9600 and a[5] == termios.B9600)
        check("8 biţi de date (CS8)", (a[2] & termios.CSIZE) == termios.CS8)
        check("fără paritate (PARENB stins)", not (a[2] & termios.PARENB))
        check("1 stop bit (CSTOPB stins)", not (a[2] & termios.CSTOPB))
        check("raw: fără ECHO şi fără ICANON", not (a[3] & termios.ECHO) and not (a[3] & termios.ICANON))
        check("raw: fără OPOST (ieşirea nu se procesează)", not (a[1] & termios.OPOST))

        # 3. 7E2: 7 biţi, paritate pară, 2 stop biţi
        a = _captured_cflags(slave, 19200, 7, "even", 2, "none")
        check("7 biţi de date (CS7)", (a[2] & termios.CSIZE) == termios.CS7)
        check("paritate pară (PARENB, fără PARODD)", (a[2] & termios.PARENB) and not (a[2] & termios.PARODD))
        check("2 stop biţi (CSTOPB)", bool(a[2] & termios.CSTOPB))
        check("baud 19200 setat", a[4] == termios.B19200)

        # 4. paritate impară ⇒ PARENB + PARODD
        a = _captured_cflags(slave, 115200, 8, "odd", 1, "none")
        check("paritate impară (PARENB + PARODD)", (a[2] & termios.PARENB) and (a[2] & termios.PARODD))

        # 5. control flux hardware ⇒ CRTSCTS
        a = _captured_cflags(slave, 9600, 8, "none", 1, "rtscts")
        check("flow rtscts ⇒ CRTSCTS", bool(a[2] & termios.CRTSCTS))

        # 6. bridge de octeţi BRUT în ambele sensuri (premisa consolei seriale): după raw+8N1,
        #    ce scriu pe master ajunge neatins pe slave şi invers (asta un PTY chiar onorează)
        ptyd._configure_serial(slave, 9600, 8, "none", 1, "none")
        os.write(master, b"AT\r\n")
        got = os.read(slave, 64)
        check("octeţii curg master→slave neatinşi", got == b"AT\r\n", repr(got))
        os.write(slave, b"OK\r\n")
        back = os.read(master, 64)
        check("octeţii curg slave→master neatinşi", back == b"OK\r\n", repr(back))
    finally:
        os.close(master)
        os.close(slave)

    # 7. enumerarea porturilor nu crapă şi întoarce o listă cu forma aşteptată (în CI de obicei
    #    goală — porturile ttyS fantomă sunt filtrate — dar discovery-ul trebuie să fie robust)
    try:
        ports = ptyd.serial_ports()
        shape_ok = isinstance(ports, list) and all(
            isinstance(p, dict) and "device" in p and "desc" in p for p in ports)
        check("serial_ports() întoarce o listă cu forma corectă", shape_ok, repr(ports)[:120])
    except Exception as e:                      # noqa: BLE001
        check("serial_ports() nu crapă", False, repr(e))

    # 8. clasa Serial ţine starea stream-ului aşa cum se aşteaptă op-urile
    s = ptyd.Serial("stream-1", 7)
    check("Serial reţine stream_id + fd", s.stream_id == "stream-1" and s.fd == 7 and s.wbuf == b"")

    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
