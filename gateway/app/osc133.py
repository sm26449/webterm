"""Starea shell integration (OSC 133) a unei sesiuni, văzută de HUB în fluxul LIVE (3.6.13).

De ce în gateway: după o ataşare / reconectare, browserul vede doar coada rejucată din transcript,
care (1) poate să nu conţină niciun marcaj (un output lung le-a împins afară din fereastră) şi
(2) poate să-i lipsească ultima bucată ne-scrisă pe disc (~2,5 s) — deci ultimul marcaj rejucat nu
dovedeşte nimic (vezi docs/design/SPLIT-VIEWS.md, „residuals"). Hub-ul vede ÎNTREG fluxul de la
crearea lui, în ordine, chunk cu chunk — el ştie dacă shell-ul a emis vreodată un B şi care a fost
ultimul marcaj LIVE.

Parserul imită ce face xterm.js 5.5 (EscapeSequenceParser + OscParser) cu octeţii, fiindcă tracker-ul
din browser vede marcajele prin parserul lui xterm:
  · introducere: ESC `]` (C0-urile „executabile" dintre ESC şi `]` nu întrerup starea ESCAPE) sau
    C1 OSC = U+009D, adică UTF-8 `\\xc2\\x9d`;
  · terminare cu succes: BEL, ESC (ST = ESC `\\`), U+009C; abandon: CAN / SUB, orice alt C1;
    U+009D reporneşte un OSC nou;
  · C0-urile din payload sunt IGNORATE (nu ajung în date), DEL intră în date;
  · identificatorul = cifre până la `;` (zerourile din faţă contează ca la xterm: `0133` = 133);
    un ne-cifră înainte de `;` = abandon; fără `;` = payload gol;
  · payload peste 10 000 000 = abandon (PAYLOAD_LIMIT din xterm; aici în octeţi, nu în unităţi
    UTF-16 — diferenţa contează doar pentru un flux construit anume, vezi mai jos).
Bufferul e MĂRGINIT: păstrăm doar primii HEAD_MAX octeţi utili ai unui OSC (identificatorul +
felul marcajului); restul doar se numără. Marcajele rupte între chunk-uri se refac (starea
parserului trece de la un chunk la altul). Calea fierbinte sare prin `re.search` peste textul
fără ESC / `\\xc2`, deci costul pe octet rămâne în C.

ÎNCREDERE: fluxul e output-ul sesiunii — orice program rulat acolo poate tipări marcaje false.
Exact la fel ca marcajele pe care tracker-ul din browser le vede LIVE azi; starea de aici nu
trebuie să fie MAI uşor de păcălit decât calea live, şi nu e: ea doar rezumă acelaşi flux. Nimic
de aici nu vine de la browser."""
import re
from typing import Optional

HEAD_MAX = 64                 # octeţi utili păstraţi dintr-un OSC (id + felul marcajului)
PAYLOAD_LIMIT = 10_000_000    # ca xterm.js (Constants.PAYLOAD_LIMIT)
KINDS = ("A", "B", "C", "D")

_GROUND, _ESC, _C2, _OSC, _OSC_C2 = range(5)
# în GROUND ne interesează doar ESC şi primul octet al unui C1 codat UTF-8
_GROUND_RE = re.compile(rb"[\x1b\xc2]")
# în OSC: terminatori (BEL, ESC, CAN, SUB) şi `\xc2` (posibil C1: ST / OSC / alt C1)
_OSC_STOP_RE = re.compile(rb"[\x07\x18\x1a\x1b\xc2]")
# octeţi care NU scot parserul din ESCAPE (xterm: C0 „executabile" = EXECUTE, DEL = IGNORE, ambele
# rămân în ESCAPE): 0x00-0x17, 0x19, 0x1c-0x1f, 0x7f. CAN (0x18) / SUB (0x1a) = înapoi în GROUND.
_ESC_KEEP = frozenset(list(range(0x00, 0x18)) + [0x19] + list(range(0x1c, 0x20)) + [0x7f])
# C0-uri ignorate în payload-ul unui OSC (nu ajung în date)
_OSC_IGNORED = bytes(b for b in range(0x20) if b not in (0x07, 0x18, 0x1a, 0x1b))


class Osc133Scanner:
    """Urmăreşte, într-un flux de octeţi dat bucată cu bucată, marcajele OSC 133.

    `integrated` = s-a văzut cel puţin un B (sfârşit de prompt) — ca `CommandTracker.integrated`
    din browser: o integrare care emite doar A/C/D nu arată niciodată linia tastată.
    `last` = felul ultimului marcaj 133 ('A'|'B'|'C'|'D'); None = necunoscut (niciun marcaj de la
    creare / de la ultimul gol în flux, sau ultimul marcaj a fost altceva: E, P, gol, trunchiat).
    `last_start` = offsetul absolut (în transcript) al introducerii ultimului marcaj, sau None
    dacă nu se ştie (ex. după o rescriere a transcriptului)."""

    __slots__ = ("integrated", "last", "last_start", "_state", "_start", "_head", "_size", "_c2_at")

    def __init__(self) -> None:
        self.integrated = False
        self.last: Optional[str] = None
        self.last_start: Optional[int] = None
        self._state = _GROUND
        self._start: Optional[int] = None      # offsetul introducerii OSC-ului / ESC-ului în curs
        self._head = bytearray()
        self._size = 0
        self._c2_at: Optional[int] = None      # offsetul unui `\xc2` rămas la capătul chunk-ului

    # -- evenimente din afara fluxului ------------------------------------------------------

    def gap(self) -> None:
        """Lipsesc octeţi din flux (agent repornit, inel depăşit): ultimul marcaj nu mai e de
        încredere. `integrated` rămâne — shell-ul nu-şi pierde integrarea la un gol."""
        self.last = None
        self.last_start = None
        self._state = _GROUND
        self._start = None
        self._head.clear()
        self._size = 0

    def rebase(self) -> None:
        """Transcriptul a fost rescris (plafon): offseturile vechi nu mai înseamnă nimic. Felul
        ultimului marcaj rămâne valabil (fluxul e continuu), poziţia lui nu."""
        self.last_start = None
        self._start = None
        self._c2_at = None

    def snapshot(self) -> dict:
        return {"integrated": self.integrated, "last": self.last}

    # -- parser -----------------------------------------------------------------------------

    def _osc_begin(self, start: Optional[int]) -> None:
        self._state = _OSC
        self._start = start
        self._head.clear()
        self._size = 0

    def _put(self, chunk: bytes) -> None:
        self._size += len(chunk)
        room = HEAD_MAX - len(self._head)
        if room > 0:
            # C0-urile ignorate nu intră în date (xterm le sare); restul — da, inclusiv DEL
            useful = chunk.translate(None, _OSC_IGNORED)
            self._head += useful[:room]

    def _dispatch(self) -> None:
        """OSC terminat cu succes: dacă e 133, actualizează starea."""
        start, head, size = self._start, bytes(self._head), self._size
        self._state = _GROUND
        self._start = None
        self._head.clear()
        self._size = 0
        if size > PAYLOAD_LIMIT:
            return                                   # xterm abandonează (hitLimit)
        sep = head.find(b";")
        ident = head if sep < 0 else head[:sep]
        if sep < 0 and len(head) >= HEAD_MAX:
            return                                   # id neterminat în fereastră: nu-l ghicim
        if not ident or not ident.isdigit():
            return                                   # xterm: ne-cifră înainte de `;` = abandon
        if int(ident) != 133:
            return
        if sep < 0:
            kind = b""
        else:
            payload = head[sep + 1:]
            end = payload.find(b";")
            if end < 0 and len(head) >= HEAD_MAX:
                kind = b"?"                          # felul poate continua dincolo de fereastră
            else:
                kind = payload if end < 0 else payload[:end]
        k = kind.decode("latin-1")
        if k == "B":
            self.integrated = True
        self.last = k if k in KINDS else None        # E / P / gol / necunoscut → nu ştim
        self.last_start = start

    def feed(self, data: bytes, pos: int) -> None:
        """`data` = octeţii unui chunk, `pos` = offsetul absolut al primului octet."""
        i = 0
        n = len(data)
        while i < n:
            st = self._state
            if st == _GROUND:
                m = _GROUND_RE.search(data, i)
                if m is None:
                    return
                j = m.start()
                self._start = pos + j
                self._state = _ESC if data[j] == 0x1B else _C2
                i = j + 1
            elif st == _ESC:
                b = data[i]
                if b == 0x5D:                                  # `]`
                    self._osc_begin(self._start)
                elif b == 0x1B:
                    self._start = pos + i
                elif b == 0xC2:
                    self._start = pos + i
                    self._state = _C2
                elif b not in _ESC_KEEP:
                    self._state = _GROUND
                    self._start = None
                i += 1
            elif st == _C2:                                    # văzut `\xc2` în GROUND / ESC
                b = data[i]
                if b == 0x9D:                                  # U+009D = OSC
                    self._osc_begin(self._start)
                    i += 1
                elif b == 0x1B:
                    self._start = pos + i
                    self._state = _ESC
                    i += 1
                elif b == 0xC2:
                    self._start = pos + i
                    i += 1
                else:
                    self._state = _GROUND
                    self._start = None
                    i += 1
            elif st == _OSC:
                m = _OSC_STOP_RE.search(data, i)
                j = n if m is None else m.start()
                if j > i:
                    self._put(data[i:j])
                if m is None:
                    return
                b = data[j]
                if b == 0x07:                                  # BEL
                    self._dispatch()
                elif b == 0x1B:                                # ESC: xterm termină OSC-ul (succes)
                    self._dispatch()
                    self._state = _ESC
                    self._start = pos + j
                elif b in (0x18, 0x1A):                        # CAN / SUB: abandon
                    self._state = _GROUND
                    self._start = None
                    self._head.clear()
                    self._size = 0
                else:                                          # `\xc2`: poate fi un C1
                    self._state = _OSC_C2
                    self._c2_at = pos + j
                i = j + 1
            else:                                              # _OSC_C2
                b = data[i]
                if b == 0x9C:                                  # ST
                    self._dispatch()
                    i += 1
                elif b == 0x9D:                                # OSC nou: cel vechi se aruncă
                    self._osc_begin(self._c2_at)
                    i += 1
                elif 0x80 <= b <= 0x9F:                        # alt C1: OSC abandonat
                    self._state = _GROUND
                    self._start = None
                    self._head.clear()
                    self._size = 0
                    i += 1
                else:
                    # `\xc2` era începutul unui caracter obişnuit (U+00A0–U+00BF) sau UTF-8 invalid:
                    # date de payload; octetul curent se reprocesează în OSC
                    self._state = _OSC
                    self._put(b"\xc2")
