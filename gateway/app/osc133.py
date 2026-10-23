"""Starea shell integration (OSC 133) a unei sesiuni, văzută de HUB în fluxul LIVE (3.6.13).

De ce în gateway: după o ataşare / reconectare, browserul vede doar coada rejucată din transcript,
care (1) poate să nu conţină niciun marcaj (un output lung le-a împins afară din fereastră) şi
(2) poate să-i lipsească ultima bucată ne-scrisă pe disc (~2,5 s) — deci ultimul marcaj rejucat nu
dovedeşte nimic (vezi docs/design/SPLIT-VIEWS.md). Hub-ul vede ÎNTREG fluxul de la crearea lui, în
ordine, chunk cu chunk — el ştie dacă shell-ul a emis vreodată un B şi care a fost ultimul marcaj LIVE.

Parserul urmează xterm.js 5.5 (EscapeSequenceParser + OscParser), fiindcă tracker-ul din browser vede
marcajele prin parserul lui xterm:
  · introducere: ESC `]` — C0 / DEL între ESC şi `]` nu întrerup starea ESCAPE — sau C1 OSC = U+009D
    (UTF-8 `\\xc2\\x9d`), oriunde în flux;
  · terminare cu succes: BEL, ESC (ST = ESC `\\`), U+009C; abandon: CAN / SUB / orice alt C1;
    U+009D reporneşte un OSC nou; C0 din payload e ignorat;
  · identificatorul = cifre până la `;` (`0133` = 133), un ne-cifră = abandon, fără `;` = payload gol.
Unde xterm şi un parser pe octeţi pot vedea lucruri diferite — decodorul UTF-8 al lui xterm ARUNCĂ
octeţii invalizi (continuări singure, lead-uri greşite, BOM), plafonul de payload e în unităţi UTF-16,
iar noi păstrăm doar primii HEAD_MAX octeţi — parserul NU ghiceşte: orice OSC care POATE fi 133 şi pe
care nu-l putem citi sigur (octet non-ASCII între ESC şi `]` sau în identificator, identificator
trunchiat, felul trunchiat, payload peste plafon) face ultimul marcaj NECUNOSCUT (None). Fail-closed:
None = browserul tratează linia drept necunoscută.

Performanţă (review 3.6.13, M3): calea fierbinte e o singură căutare regex (în C) care sare direct la
introduceri OSC / secvenţe de ecran alternativ / un prefix rupt la capătul chunk-ului; în OSC, direct
la terminatori. Niciun pas Python per octet, nici pe text plin de SGR sau de `\\xc2` (°, ă…).

Ecranul alternativ (review 3.6.13, L3): marcajele emise pe ecranul alternativ (DECSET 47/1047/1049,
RIS îl închide) sunt reţinute cu `last_alt`; hub-ul le raportează ca None pe un flux fără tmux (pe un
flux tmux, ecranul alternativ al clientului tmux e un artefact — vezi SessionHub.osc133_state).
Secvenţele pe care `read_tail` le SCOATE din replay (1049/1047/1048/47 h/l, ESC[2J, ESC[3J, RIS) sunt
urmărite (`strip_end`): una după ultimul marcaj înseamnă că ecranul rejucat nu e cel live (Ctrl+L la
prompt, repaint) sau că scoaterea ei a putut lipi un marcaj fals → nesincronizat.

C (review 3.6.13, L1): xterm creează o „comandă în curs" doar dintr-un C care urmează unui prompt (B,
eventual B → E). Un C singur (job în fundal care tipăreşte `ESC]133;C`) e raportat ca None.

ÎNCREDERE: fluxul e output-ul sesiunii — orice program rulat acolo poate tipări marcaje false, exact
ca pe calea live din browser. Starea de aici doar rezumă acelaşi flux; nimic nu vine de la browser."""
import re
from typing import Optional

HEAD_MAX = 64                 # octeţi utili păstraţi dintr-un OSC (id + felul marcajului)
PAYLOAD_LIMIT = 10_000_000    # ca xterm.js (Constants.PAYLOAD_LIMIT; acolo în unităţi UTF-16)
CARRY_MAX = 4096              # prefix de secvenţă reţinut între chunk-uri
# buget de evenimente (paşi Python) per chunk: max(32, 1 la 512 octeţi). Peste el → _flood
EVENT_BUDGET_MIN = 32
EVENT_BUDGET_BYTES = 512
TAIL_MAX = 4096               # cât reluăm după o inundaţie
KINDS = ("A", "B", "C", "D")

# C0 care NU scot xterm din ESCAPE (EXECUTE / IGNORE), plus octeţi ≥0x80 (decodorul UTF-8 al lui xterm
# poate să-i arunce: „tainted", vezi mai sus)
_CLS = rb"[\x00-\x17\x19\x1c-\x1f\x7f\x80-\xff]"
# căutări cu prefix LITERAL (sre le face cu un skip rapid, fără încercări per octet): introducerea
# OSC obişnuită, C1 OSC, DECSET/DECRST privat, ştergerile de ecran, RIS — şi forma „ciudată"
# ESC <C0/DEL/≥0x80> … `]` (doar ESC urmat DIRECT de un astfel de octet e candidat)
# DECSET/DECRST doar cu un mod de ecran alternativ (47/1047/1048/1049) — restul (?25h, ?2004h…) nu
# ne priveşte, deci nici nu costă un pas Python
_ALT_MODE_RE = re.compile(rb"\x1b\[\?((?:[0-9]*;)*(?:47|1047|1048|1049)(?:;[0-9]*)*)([hl])")
# `ESC ]` — DAR nu un OSC cu id curat ne-133 (titlu, cwd, hyperlink…): pe acela nu-l parcurgem deloc.
# Payload-ul lui nu poate conţine ESC (l-ar termina), iar un U+009D / U+009C din el înseamnă acelaşi
# lucru şi în GROUND (OSC nou / nimic), deci a-l sări e echivalent cu a-l parsa. Căutarea rămâne în C.
_OSC_INTRO_RE = re.compile(rb"\x1b\](?!(?!0*133[;\x07\x1b])[0-9]{1,16}[;\x07\x1b])")
_NEEDLES = (_OSC_INTRO_RE, b"\xc2\x9d", _ALT_MODE_RE, b"\x1b[2J", b"\x1b[3J", b"\x1bc")
# calea rapidă după `ESC ]`: un id curat, terminat de `;` / BEL / ESC — ne-133 = de ignorat (vezi feed)
_FAST_ID_RE = re.compile(rb"([0-9]{1,16})[;\x07\x1b]")
# un 133 complet şi curat (ASCII tipăribil, fără C0 / octeţi înalţi), în acelaşi chunk
_FAST_133_RE = re.compile(rb"\x1b\]133(?:;([\x20-\x3a\x3c-\x7e]*)(;[\x20-\x7e]*)?)?(\x07|\x1b\\)")
_WEIRD_RE = re.compile(rb"\x1b" + _CLS)
_WEIRD_OSC_RE = re.compile(rb"\x1b(" + _CLS + rb"*)(?:\]|\xc2\x9d)")
# prefix de secvenţă rămas la capătul chunk-ului (de la ULTIMUL ESC)
_PART_RE = re.compile(rb"\x1b(?:" + _CLS + rb"*|\[\?[0-9;]*|\[[23]?)\Z")
# în OSC: terminatori (BEL, ESC, CAN, SUB) şi C1 (ST / OSC / alt C1)
_OSC_END_RE = re.compile(rb"[\x07\x18\x1a\x1b]")
_OSC_C1_RE = re.compile(rb"\xc2[\x80-\x9f]")
_C1_LOW_RE = re.compile(rb"[\x80-\x9f]")


def _c1_search(data: bytes, i: int, end: int):
    """Primul C1 codat UTF-8 (`\xc2` + 0x80–0x9F) din data[i:end]. Întâi căutăm al DOILEA octet (rar
    într-un payload cu `°`/`©`, unde `\xc2` e la fiecare caracter); la prima potrivire care nu e
    precedată de `\xc2` (text chirilic etc.) trecem pe căutarea după `\xc2`, rară acolo."""
    m = _C1_LOW_RE.search(data, i + 1 if i + 1 <= end else end, end)
    if m is None:
        return None
    j = m.start()
    if data[j - 1] == 0xC2 and j - 1 >= i:
        return _OSC_C1_RE.search(data, j - 1, end)
    return _OSC_C1_RE.search(data, i, end)
# C0-uri ignorate în payload-ul unui OSC (nu ajung în date)
_OSC_IGNORED = bytes(b for b in range(0x20) if b not in (0x07, 0x18, 0x1a, 0x1b))
_ALT_MODES = (b"47", b"1047", b"1049")
_STRIPPED_MODES = (b"47", b"1047", b"1048", b"1049")     # exact ce scoate read_tail (ALT_SCREEN_RE)
_HIGH = re.compile(rb"[\x80-\xff]")


def _exit_from(tail: bytes) -> Optional[int]:
    """Numărul din payload-ul de după felul marcajului („0" din „D;0"); None dacă nu sunt cifre.
    ADITIV (Faza 2): nu influenţează deloc decizia guardrail-ului, care priveşte doar felul."""
    if not tail:
        return None
    end = tail.find(b";")
    num = tail if end < 0 else tail[:end]
    try:
        return int(num) if num.isdigit() else None
    except ValueError:        # număr absurd de lung
        return None


class Osc133Scanner:
    """`integrated` = s-a văzut un B (sfârşit de prompt), ca `CommandTracker.integrated`.
    `last` = felul ultimului marcaj 133 ('A'|'B'|'C'|'D') sau None (necunoscut: niciun marcaj de la
    creare / de la un gol, sau un marcaj de nefolosit). `last_start` = offsetul absolut al introducerii
    lui (None = nu se ştie). `last_alt` = emis pe ecranul alternativ. `strip_end` = capătul ultimei
    secvenţe pe care read_tail o scoate din replay."""

    __slots__ = ("integrated", "last", "last_exit", "last_start", "last_alt", "strip_end", "alt",
                 "_phase", "alt_unknown", "_in_osc", "_start", "_head", "_size", "_taint", "_carry", "_carry_pos")

    def __init__(self) -> None:
        self.integrated = False
        self.last: Optional[str] = None
        # exit code-ul ultimului marcaj „D" (int) sau None. ADITIV pentru notificările de task
        # (Faza 2): guardrail-ul nu-l citeşte — foloseşte doar `last`/`integrated`. „Doar adaug
        # citiri, nu scurtez" (regula din 3.6.13).
        self.last_exit: Optional[int] = None
        self.last_start: Optional[int] = None
        self.last_alt = False
        self.strip_end: Optional[int] = None
        self.alt = False
        self._phase: Optional[str] = None     # 'B' / 'BE' = un C acum ar porni o comandă
        self.alt_unknown = False              # după o inundaţie: nu ştim pe ce ecran suntem
        self._in_osc = False
        self._start: Optional[int] = None
        self._head = bytearray()
        self._size = 0
        self._taint = False
        self._carry = b""
        self._carry_pos = 0

    # -- evenimente din afara fluxului ------------------------------------------------------

    def _unknown(self) -> None:
        self.last = None
        self.last_exit = None
        self.last_start = None
        self.last_alt = False
        self._phase = None

    def gap(self) -> None:
        """Lipsesc octeţi din flux (agent repornit, inel depăşit): ultimul marcaj nu mai e de
        încredere. `integrated` rămâne — shell-ul nu-şi pierde integrarea la un gol."""
        self._unknown()
        self._in_osc = False
        self._start = None
        self._head.clear()
        self._size = 0
        self._taint = False
        self._carry = b""

    def rebase(self) -> None:
        """Transcriptul a fost rescris (plafon): offseturile vechi nu mai înseamnă nimic. Felul
        ultimului marcaj rămâne valabil (fluxul e continuu), poziţia lui nu."""
        self.last_start = None
        self.strip_end = None
        self._phase = None                     # `_b_end` era din generaţia veche
        if self._carry or self._in_osc:
            # o secvenţă începută înainte de rescriere ar primi un offset din generaţia veche: o
            # aruncăm şi nu mai ştim ultimul marcaj (fail-closed; rescrierea e rară — 64 MiB)
            self.gap()

    def snapshot(self) -> dict:
        return {"integrated": self.integrated, "last": self.last}

    # -- parser -----------------------------------------------------------------------------

    def _osc_begin(self, start: Optional[int], taint: bool) -> None:
        self._in_osc = True
        self._start = start
        self._head.clear()
        self._size = 0
        self._taint = taint

    def _osc_abort(self) -> None:
        """CAN / SUB / alt C1: xterm nu livrează OSC-ul. Dacă putea fi 133, nu ştim ce a fost."""
        if self._maybe133():
            self._unknown()
        self._in_osc = False
        self._start = None
        self._head.clear()

    def _maybe133(self) -> bool:
        head = bytes(self._head)
        sep = head.find(b";")
        ident = head if sep < 0 else head[:sep]
        if ident.isdigit() and sep >= 0 and int(ident) != 133 and not self._taint:
            return False
        if ident and not ident.isdigit() and not _HIGH.search(ident) and not self._taint:
            return False                       # xterm abandonează oricum un id ne-numeric
        return True

    def _put(self, data: bytes, i: int, j: int) -> None:
        """Payload-ul data[i:j]: se numără; doar începutul (capul) se copiază."""
        self._size += j - i
        room = HEAD_MAX - len(self._head)
        if room > 0:
            end = min(j, i + room + 4096)
            useful = data[i:end].translate(None, _OSC_IGNORED)
            if len(useful) < room and j > end:
                self._taint = True             # prea mult C0 ignorat: capul nu e complet
            self._head += useful[:room]

    def _dispatch(self, osc_end: int = 0) -> None:
        """`osc_end` = offsetul de după OSC (pentru un B: de aici începe linia tastată)."""
        start, head, size, taint = self._start, bytes(self._head), self._size, self._taint
        self._in_osc = False
        self._start = None
        self._head.clear()
        sep = head.find(b";")
        ident = head if sep < 0 else head[:sep]
        clean_ident = bool(ident) and ident.isdigit()
        if clean_ident and int(ident) != 133 and (sep >= 0 or len(head) < HEAD_MAX) and not taint:
            return                             # alt OSC (titlu, cwd…), citit sigur
        if not taint and ident and not ident.isdigit() and not _HIGH.search(ident):
            return                             # xterm: ne-cifră ASCII înainte de `;` = abandon
        if not ident and sep >= 0 and not taint:
            return                             # `ESC];…`: id gol, xterm nu-l livrează unui handler
        if not ident and sep < 0 and not taint:
            return                             # OSC gol
        # de aici: e 133 sau nu ştim sigur
        if taint or not clean_ident or size > PAYLOAD_LIMIT or (sep < 0 and len(head) >= HEAD_MAX):
            self._unknown()
            return
        exit_code = None
        if sep < 0:
            kind = b""
        else:
            payload = head[sep + 1:]
            end = payload.find(b";")
            if end < 0 and len(head) >= HEAD_MAX:
                self._unknown()                # felul poate continua dincolo de fereastră
                return
            kind = payload if end < 0 else payload[:end]
            if kind == b"D" and end >= 0:
                exit_code = _exit_from(payload[end + 1:])
        self._mark(kind.decode("latin-1"), sep >= 0 and len(head[sep + 1:]) > 2, start, osc_end, exit_code)

    def _mark(self, k: str, has_text: bool, start: Optional[int], osc_end: int,
              exit_code: Optional[int] = None) -> None:
        """Un marcaj 133 citit sigur: `k` = felul, `has_text` = payload „X;<ceva>" (pentru E),
        `exit_code` = numărul din „D;<cod>" (doar pentru D; ADITIV, pentru notificările de task)."""
        if k == "B":
            self.integrated = True
        if k == "C":
            # xterm porneşte o comandă doar dintr-un C după prompt, cu text tastat. Hub-ul nu citeşte
            # ecranul, deci cere dovada explicită: B → E;<cmd> → C (integrarea noastră trimite E pentru
            # orice comandă nevidă). Octeţii dintre B şi C nu dovedesc nimic (review 3.6.13, LOW-1a:
            # `\e[0m\e]133;C` la un prompt gol). O integrare fără E = None (necunoscut), ca în 3.6.12.
            ok = self._phase == "BE"
            self._phase = None
            if not ok:
                self._unknown()                # C fără prompt înainte: xterm nu porneşte o comandă
                return
        elif k == "B":
            self._phase = "B"
        elif k == "E":
            self._phase = "BE" if self._phase == "B" and has_text else None
            self.last = None                   # E nu e o stare în sine; C-ul care urmează decide
            self.last_exit = None
            self.last_start = None
            self.last_alt = False
            return
        else:
            self._phase = None
        if k not in KINDS:
            self._unknown()
            return
        self.last = k
        self.last_exit = exit_code if k == "D" else None
        self.last_start = start
        self.last_alt = self.alt or self.alt_unknown

    def _mode(self, params: bytes, set_: bool) -> None:
        ps = params.split(b";")
        if any(p in _ALT_MODES for p in ps):
            self.alt = set_
            self.alt_unknown = False

    def feed(self, data: bytes, pos: int) -> None:
        """`data` = octeţii unui chunk, `pos` = offsetul absolut al primului octet."""
        if self._carry:
            data = self._carry + data
            pos = self._carry_pos
            self._carry = b""
        n = len(data)
        i = 0
        nxt = [-2] * (len(_NEEDLES) + 1)       # -2 = de calculat, -1 = nu mai apare în chunk
        budget = max(EVENT_BUDGET_MIN, n // EVENT_BUDGET_BYTES)
        while i < n:
            budget -= 1
            if budget < 0:
                self._flood(data, pos)
                return
            if self._in_osc:
                i = self._osc_step(data, i, pos)
                if i < 0:
                    return
                continue                               # poziţiile din cache < i se recalculează
            best = -1
            which = -1
            for k in range(len(nxt)):
                v = nxt[k]
                if v == -2 or (v >= 0 and v < i):
                    if k < len(_NEEDLES):
                        nd = _NEEDLES[k]
                        if isinstance(nd, bytes):
                            v = data.find(nd, i)
                        else:
                            m = nd.search(data, i)
                            v = m.start() if m else -1
                    else:
                        m = _WEIRD_RE.search(data, i)
                        v = m.start() if m else -1
                    nxt[k] = v
                if v >= 0 and (best < 0 or v < best):
                    best, which = v, k
            if best < 0:
                break
            j = best
            if which == 0:                                   # ESC ]
                m = _FAST_ID_RE.match(data, j + 2)            # aici: id 0*133 sau necurat
                if m is not None:
                    f = _FAST_133_RE.match(data, j)
                    if f is not None:
                        kind = f.group(1) or b""
                        rest = f.group(2)
                        exit_code = _exit_from(rest[1:]) if (kind == b"D" and rest) else None
                        self._mark(kind.decode("ascii"), rest is not None and len(rest) > 1,
                                   pos + j, pos + f.end(), exit_code)
                        i = f.end()
                        continue
                self._osc_begin(pos + j, False)
                i = j + 2
            elif which == 1:                                 # U+009D
                self._osc_begin(pos + j, False)
                i = j + 2
            elif which == 2:                                 # ESC [ ? … 47/1047/1048/1049 … h/l
                m = _ALT_MODE_RE.match(data, j)
                params = m.group(1)
                self._mode(params, m.group(2) == b"h")
                if params in _STRIPPED_MODES:
                    self.strip_end = pos + m.end()
                i = m.end()
            elif which in (3, 4):                            # ESC[2J / ESC[3J (scoase din replay)
                self.strip_end = pos + j + 4
                i = j + 4
            elif which == 5:                                 # RIS: ecranul principal
                self.alt = False
                self.alt_unknown = False
                self.strip_end = pos + j + 2
                i = j + 2
            else:                                            # ESC <C0/DEL/≥0x80> …
                m = _WEIRD_OSC_RE.match(data, j)
                if m is None:
                    if _PART_RE.fullmatch(data, j):
                        break
                    i = j + 1
                    continue
                self._osc_begin(pos + j, bool(_HIGH.search(m.group(1))))
                i = m.end()
        if self._in_osc or i >= n:
            return
        # prefix de secvenţă la capăt → îl păstrăm pentru chunk-ul următor
        e = data.rfind(b"\x1b", i)
        start = -1
        if e >= 0 and _PART_RE.fullmatch(data, e):
            start = e
        elif data.endswith(b"\xc2") and n - 1 >= i:
            start = n - 1
        if start >= 0:
            if n - start > CARRY_MAX:                        # ESC urmat de o rafală nesfârşită
                self._unknown()
                return
            self._carry, self._carry_pos = data[start:], pos + start

    def _flood(self, data: bytes, pos: int) -> None:
        """Prea multe secvenţe de interes într-un chunk (review 3.6.13, MEDIUM-1: un flux construit —
        `ESC ] x BEL`, `ESC [?1049h`, `ESC ]133;A BEL` repetate — ar ţine loop-ul gateway-ului partajat câte
        milisecunde pe chunk). Nu-l mai parcurgem: starea devine NECUNOSCUTĂ (fail-closed), iar parserul
        se reaşază ieftin. ESC şi orice C1 duc xterm într-o stare cunoscută din ORICE stare, deci
        reluăm parsarea doar de la ultimul ESC / C1 din ultimii TAIL_MAX octeţi (după el nu mai e
        niciunul — cost mărginit); fără niciunul acolo, GROUND (până la următorul ESC / C1, care
        resincronizează ambele parsere la fel)."""
        n = len(data)
        self._unknown()
        self.strip_end = pos + n                   # nimic de dinainte nu mai poate fi „sincronizat"
        self.alt_unknown = True                    # nu ştim ce comutări de ecran au trecut
        if data.find(b"133;B") >= 0:
            self.integrated = True                 # doar adaugă rezultate „necunoscut"
        self._carry = b""
        self._in_osc = False
        self._start = None
        self._head.clear()
        self._taint = False
        lo = max(0, n - TAIL_MAX)
        start = data.rfind(b"\x1b", lo)
        k = n
        while True:                                # ultimul C1 (`\xc2` + 0x80–0x9F) din fereastră
            k = data.rfind(b"\xc2", lo, k)
            if k < 0 or k <= start:
                break
            if k + 1 < n and 0x80 <= data[k + 1] <= 0x9F:
                start = k
                break
        if start >= 0:
            self.feed(data[start:], pos + start)   # un singur ESC / C1: câteva evenimente, nu o inundaţie

    def _osc_step(self, data: bytes, i: int, pos: int) -> int:
        """Un pas în OSC: până la terminator. Întoarce indexul de continuare, sau -1 = chunk consumat."""
        n = len(data)
        m1 = _OSC_END_RE.search(data, i)
        m2 = _c1_search(data, i, m1.start() if m1 else n)
        tail_c2 = data.endswith(b"\xc2") and (m1 is None) and (m2 is None) and n - 1 >= i
        if m2 is not None:
            j = m2.start()
        elif m1 is not None:
            j = m1.start()
        elif tail_c2:
            j = n - 1
        else:
            j = n
        if j > i:
            self._put(data, i, j)
        if j >= n:
            return -1
        if tail_c2 and m1 is None and m2 is None:            # `\xc2` la capăt: aşteptăm continuarea
            self._carry, self._carry_pos = data[j:], pos + j
            return -1
        b = data[j]
        if b == 0x07:                                        # BEL
            self._dispatch(pos + j + 1)
            return j + 1
        if b == 0x1B:                                        # ESC: termină OSC-ul, ESC-ul se reprocesează
            self._dispatch(pos + j + 2)                      # + ST (`ESC \\`) — dacă nu urmează `\\`, fail-closed
            return j
        if b in (0x18, 0x1A):                                # CAN / SUB: abandon
            self._osc_abort()
            return j + 1
        c = data[j + 1]                                      # C1 codat UTF-8
        if c == 0x9C:                                        # ST
            self._dispatch(pos + j + 2)
        elif c == 0x9D:                                      # OSC nou: cel vechi se aruncă
            self._osc_abort()
            self._osc_begin(pos + j, False)
        else:                                                # alt C1: abandon
            self._osc_abort()
        return j + 2
