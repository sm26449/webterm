"""Shim telnet minimal — mașină de stări IAC pură, fără I/O.

Sesiunile telnet-via-agent (bastion spre echipamente din LAN) folosesc tunelul TCP
brut al agentului (`ForwardStream`). Spre deosebire de `TelnetSource` (care lasă
`telnetlib3` să dețină socketul și să negocieze), aici avem doar octeți bruți, deci
vorbim noi protocolul telnet: negociem opțiunile esențiale, răspundem la TTYPE/NAWS,
și — critic — **scoatem secvențele IAC din fluxul dat lui xterm** (altfel apar ca
gunoi pe ecran).

Modulul e PUR (fără socket, fără asyncio): `receive()` primește octeți de la device
și întoarce octeții „curați" pentru terminal, acumulând răspunsurile de protocol
într-un buffer intern (`drain()`). Asta îl face ușor de testat unitar și de fuzzat —
device-ul din capăt e ne-de-încredere, deci parserul TREBUIE să reziste la orice input
(IAC tăiat între citiri, subnegociere uriașă, IAC IAC, opțiuni necunoscute).

Suntem CLIENTUL; device-ul e serverul telnet. Referințe: RFC 854 (telnet), 855 (opțiuni),
857 (ECHO), 858 (SGA), 1073 (NAWS), 1091 (TTYPE).
"""

# --- comenzi (octetul de după IAC) ---
IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250          # început subnegociere
GA = 249
SE = 240          # sfârșit subnegociere
NOP = 241

# --- opțiuni ---
OPT_BINARY = 0
OPT_ECHO = 1
OPT_SGA = 3       # suppress-go-ahead (mod caracter)
OPT_TTYPE = 24    # terminal-type
OPT_NAWS = 31     # negotiate-about-window-size

# Opțiuni pe care le activăm pe partea NOASTRĂ când device-ul cere (DO x) → WILL x.
_WE_WILL = frozenset({OPT_NAWS, OPT_TTYPE, OPT_SGA, OPT_BINARY})
# Opțiuni pe care le acceptăm ca device-ul să le activeze (WILL x → DO x).
_THEY_MAY = frozenset({OPT_ECHO, OPT_SGA, OPT_BINARY})

# Subnegocierea TTYPE: sub-comenzi
_TTYPE_IS = 0
_TTYPE_SEND = 1

# Plafon dur pe bufferul de subnegociere: un device malițios poate trimite
# `IAC SB <opt> <mult>… ` fără `IAC SE` → OOM. Peste atât, abandonăm subnegocierea.
_MAX_SB = 512

# stări parser
_NORMAL = 0
_IAC = 1          # am văzut IAC, aștept comanda
_CMD = 2          # am văzut DO/DONT/WILL/WONT, aștept opțiunea
_SB = 3           # în subnegociere, colectez în _sbbuf
_SB_IAC = 4       # în subnegociere, am văzut IAC (aștept SE sau IAC literal)


class TelnetShim:
    def __init__(self, rows: int = 24, cols: int = 80, term: str = "xterm-256color"):
        self.rows = rows
        self.cols = cols
        self.term = term.encode("ascii", "ignore") or b"xterm-256color"
        self._state = _NORMAL
        self._cmd = 0                 # comanda DO/DONT/WILL/WONT în așteptarea opțiunii
        self._sbbuf = bytearray()     # corpul subnegocierii curente
        self._out = bytearray()       # răspunsuri de protocol către device (drain())
        # starea negociată, ca să NU reintrăm în bucle de răspuns (RFC 854: nu
        # confirma o opțiune deja în starea dorită)
        self._us = {}                 # opt -> bool (noi am trimis WILL)
        self._them = {}               # opt -> bool (device-ul a trimis WILL)

    # ------------------------------------------------------------------ output
    def drain(self) -> bytes:
        """Octeții de protocol de trimis către device de la ultimul drain."""
        if not self._out:
            return b""
        data = bytes(self._out)
        self._out.clear()
        return data

    def _send(self, *parts: bytes) -> None:
        for p in parts:
            self._out += p

    def _reply_cmd(self, cmd: int, opt: int) -> None:
        self._out += bytes((IAC, cmd, opt))

    # --------------------------------------------------------------- them WILL
    @property
    def them_will_echo(self) -> bool:
        """Device-ul s-a angajat că face echo (ECHO). Semnal secundar pentru
        detecția ferestrei de parolă (vezi redactarea de transcript)."""
        return bool(self._them.get(OPT_ECHO))

    # ------------------------------------------------------------------- feed
    def receive(self, data: bytes) -> bytes:
        """Procesează octeți de la device; întoarce octeții curați pentru terminal.
        Răspunsurile de protocol se acumulează intern (ia-le cu `drain()`)."""
        out = bytearray()
        for b in data:
            st = self._state
            if st == _NORMAL:
                if b == IAC:
                    self._state = _IAC
                else:
                    out.append(b)
            elif st == _IAC:
                if b == IAC:                 # IAC IAC = 0xFF literal în date
                    out.append(IAC)
                    self._state = _NORMAL
                elif b in (DO, DONT, WILL, WONT):
                    self._cmd = b
                    self._state = _CMD
                elif b == SB:
                    self._sbbuf.clear()
                    self._state = _SB
                else:                        # GA/NOP/SE-rătăcit/alte comenzi 2-octeți
                    self._state = _NORMAL
            elif st == _CMD:
                self._negotiate(self._cmd, b)
                self._state = _NORMAL
            elif st == _SB:
                if b == IAC:
                    self._state = _SB_IAC
                else:
                    if len(self._sbbuf) < _MAX_SB:
                        self._sbbuf.append(b)
                    # peste plafon: continuăm să consumăm până la IAC SE, dar nu mai
                    # bufferăm (evităm OOM la un device care nu trimite niciodată SE)
            elif st == _SB_IAC:
                if b == IAC:                 # IAC IAC în subnegociere = 0xFF literal
                    if len(self._sbbuf) < _MAX_SB:
                        self._sbbuf.append(IAC)
                    self._state = _SB
                elif b == SE:                # sfârșit subnegociere
                    self._handle_sb(bytes(self._sbbuf))
                    self._sbbuf.clear()
                    self._state = _NORMAL
                else:                        # IAC <altceva> în SB: comandă întreruptă
                    self._sbbuf.clear()
                    self._state = _NORMAL
        return bytes(out)

    # ----------------------------------------------------------- negociere
    def _negotiate(self, cmd: int, opt: int) -> None:
        if cmd == WILL:
            # device-ul vrea să activeze opt pe partea LUI
            if opt in _THEY_MAY:
                if not self._them.get(opt):
                    self._them[opt] = True
                    self._reply_cmd(DO, opt)
                # deja DO → tăcere (anti-buclă)
            else:
                if self._them.get(opt) is not False:
                    self._them[opt] = False
                    self._reply_cmd(DONT, opt)
        elif cmd == WONT:
            if self._them.get(opt) is not False:
                self._them[opt] = False
                self._reply_cmd(DONT, opt)
            # deja DONT → tăcere
        elif cmd == DO:
            # device-ul ne cere să activăm opt pe partea NOASTRĂ
            if opt in _WE_WILL:
                first = not self._us.get(opt)
                if first:
                    self._us[opt] = True
                    self._reply_cmd(WILL, opt)
                # NAWS: trimite dimensiunea imediat ce am acceptat (și la re-cerere)
                if opt == OPT_NAWS:
                    self._out += self._naws_bytes()
            else:
                if self._us.get(opt) is not False:
                    self._us[opt] = False
                    self._reply_cmd(WONT, opt)
        elif cmd == DONT:
            if self._us.get(opt) is not False:
                self._us[opt] = False
                self._reply_cmd(WONT, opt)

    def _handle_sb(self, body: bytes) -> None:
        if not body:
            return
        if body[0] == OPT_TTYPE and len(body) >= 2 and body[1] == _TTYPE_SEND:
            # IAC SB TTYPE IS <term> IAC SE
            self._out += bytes((IAC, SB, OPT_TTYPE, _TTYPE_IS))
            self._out += _escape_iac(self.term)
            self._out += bytes((IAC, SE))
        # alte subnegocieri (ex. NAWS de la server — nu se întâmplă) → ignorate

    # ---------------------------------------------------------------- NAWS
    def _naws_bytes(self) -> bytes:
        return bytes((IAC, SB, OPT_NAWS)) + _naws_payload(self.cols, self.rows) + bytes((IAC, SE))

    def resize(self, rows: int, cols: int) -> bytes:
        """Actualizează dimensiunea; întoarce subnegocierea NAWS de trimis (goală
        dacă NAWS nu a fost negociat sau dimensiunea nu s-a schimbat)."""
        rows = max(1, min(9999, int(rows)))
        cols = max(1, min(9999, int(cols)))
        if (rows, cols) == (self.rows, self.cols):
            return b""
        self.rows, self.cols = rows, cols
        if self._us.get(OPT_NAWS):
            return self._naws_bytes()
        return b""

    # -------------------------------------------------------------- input
    def send(self, data: bytes) -> bytes:
        """Octeți de la utilizator → către device: escapează IAC (0xFF → 0xFF 0xFF)
        ca un 0xFF din input să nu fie confundat cu o comandă."""
        return _escape_iac(data)


def _escape_iac(data: bytes) -> bytes:
    if IAC not in data:
        return data
    return data.replace(b"\xff", b"\xff\xff")


def _naws_payload(cols: int, rows: int) -> bytes:
    # width (16-bit) apoi height (16-bit), network order; octeții == 255 se dublează
    # (escaping IAC în interiorul subnegocierii)
    raw = bytes(((cols >> 8) & 0xff, cols & 0xff, (rows >> 8) & 0xff, rows & 0xff))
    return _escape_iac(raw)


# ---------------------------------------------------------------------------
# Filtru OSC pentru output de device (F5)
# ---------------------------------------------------------------------------
# Device-ul din capăt e NE-de-încredere, iar xterm interpretează secvențele OSC din
# output-ul lui. Două sunt periculoase venind de la un device:
#   * OSC 133 — marcaje de prompt „semantic". Produsul le folosește pentru tracking-ul
#     de comenzi (vezi memory „security-model-osc133-shell"); un device poate FALSIFICA
#     blocuri de comenzi → poluează tracking / transcript / a11y.
#   * OSC 52 — scriere/citire clipboard → un device poate otrăvi clipboardul sau exfiltra.
# Le eliminăm din fluxul telnet ÎNAINTE de transcript și browser (un singur chokepoint,
# la gateway, care protejează și `.cast`). Restul OSC (titlu etc.) urmează politica xterm
# existentă, moștenită de la sesiunile PTY/SSH.
#
# Parserul e stateful — secvența OSC poate fi tăiată între recv-uri, iar un device ostil
# o poate fragmenta INTENȚIONAT ca să evadeze un filtru per-chunk — și mărginit: un OSC
# uriaș fără terminator e abandonat (nu creștem memoria la infinit).
# OSC 7 = raportarea directorului curent (cwd). Un device ne-de-încredere l-ar putea
# FALSIFICA ca să păcălească panourile Fișiere/Git („urmărește cwd") să lucreze pe o cale
# aleasă de atacator pe hostul-agent → îl filtrăm și pe el, ca 133/52.
_OSC_STRIP_IDS = frozenset((b"133", b"52", b"7"))
_OSC_MAX = 4096          # plafon pe corpul unei OSC ne-terminate → drop peste atât

_ESC = 0x1b
_BEL = 0x07
_RBRACKET = 0x5d         # ']'
_BACKSLASH = 0x5c        # '\' (a doua jumătate a ST: ESC '\')
_SEMI = 0x3b             # ';'

_F_NORMAL = 0
_F_ESC = 1               # am văzut ESC, aștept ']' (OSC) sau alt escape
_F_OSC = 2               # în corpul OSC (buffer în _buf), aștept terminator BEL / ST
_F_OSC_ESC = 3           # în OSC, am văzut ESC (posibil ST = ESC '\')


class OscFilter:
    """Elimină OSC 133 și OSC 52 dintr-un flux de octeți ne-de-încredere (output de
    device telnet). Stateful între apeluri (secvențe tăiate / fragmentate) și mărginit.
    Nu atinge alte OSC și nici CSI/SGR (culori, cursor) — doar cele două periculoase."""

    def __init__(self):
        self._st = _F_NORMAL
        self._buf = bytearray()      # secvența OSC în curs, incl. prefixul ESC ']'

    def filter(self, data: bytes) -> bytes:
        out = bytearray()
        for b in data:
            st = self._st
            if st == _F_NORMAL:
                if b == _ESC:
                    self._st = _F_ESC
                else:
                    out.append(b)
            elif st == _F_ESC:
                if b == _RBRACKET:               # ESC ] → început OSC
                    self._buf = bytearray((_ESC, _RBRACKET))
                    self._st = _F_OSC
                elif b == _ESC:                  # ESC ESC → rămânem în ESC
                    out.append(_ESC)
                else:                            # alt escape (CSI etc.) — pass-through
                    out.append(_ESC)
                    out.append(b)
                    self._st = _F_NORMAL
            elif st == _F_OSC:
                if b == _BEL:                    # BEL = terminator OSC
                    self._emit_osc(out, b"\x07")
                    self._st = _F_NORMAL
                elif b == _ESC:                  # posibil ST (ESC '\')
                    self._st = _F_OSC_ESC
                else:
                    self._buf.append(b)
                    if len(self._buf) > _OSC_MAX:  # OSC abuziv fără terminator → drop
                        self._buf = bytearray()
                        self._st = _F_NORMAL
            elif st == _F_OSC_ESC:
                if b == _BACKSLASH:              # ESC '\' = ST, terminator
                    self._emit_osc(out, b"\x1b\\")
                    self._st = _F_NORMAL
                else:                            # ESC <altceva>: tratăm OSC ca terminat aici
                    self._emit_osc(out, b"")
                    self._st = _F_NORMAL
                    if b == _ESC:
                        self._st = _F_ESC
                    else:
                        out.append(b)
        return bytes(out)

    def _emit_osc(self, out: bytearray, terminator: bytes) -> None:
        """Decide dacă OSC-ul acumulat în _buf (prefix ESC ']') e țintă (133/52 → drop)
        sau nu (→ îl reemite integral, cu terminatorul lui)."""
        body = self._buf[2:]
        semi = body.find(_SEMI)
        ident = bytes(body[:semi] if semi >= 0 else body)
        # NORMALIZARE numerică: xterm parsează identificatorul OSC ca NUMĂR (acumulator de
        # cifre), deci `0133`→133 și `052`→52. Comparația brută pe octeți era ocolibilă de
        # un device ostil cu `ESC ]0133;…`. Comparăm numeric.
        if ident.isdigit():
            ident = str(int(ident)).encode()
        if ident not in _OSC_STRIP_IDS:
            out += self._buf
            out += terminator
        # altfel: OSC 133/52 → eliminat complet (prefix + corp + terminator)
        self._buf = bytearray()
