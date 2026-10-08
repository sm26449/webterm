"""Link-uri de replay (3.5.12): partajarea PUBLICĂ, doar-citire, a înregistrării unei sesiuni
ÎNCHISE — fără cont, fără restul aplicaţiei.

Ce e aici (logica pură, testabilă fără HTTP); rutele stau în api.py:
  * mascarea secretelor probabile din înregistrare (`redact_cast`, `mask_secrets`), pe aceleaşi
    tipare ca istoricul de alerte (`alert_history.SECRET_PATTERNS`);
  * limitarea ratei pe endpoint-urile publice (`gate`, `record_miss`).

Mascarea — de ce aşa:
  * înregistrarea e asciicast v2: un antet JSON, apoi câte un eveniment `[t, "o", text]` per
    bucată de output. O bucată e ce a venit pe fir, nu o unitate logică — un token poate fi
    tăiat oricum între două evenimente (`tok` | `en=abc` | `123`). De aceea tiparele rulează pe
    CONCATENAREA tuturor evenimentelor de output, iar porţiunile găsite se redistribuie înapoi pe
    evenimente. Nu e o fereastră glisantă cu o limită de lungime: orice tăietură e acoperită;
  * înlocuirea păstrează LUNGIMEA (un `*` per caracter, două pentru un caracter lat), iar
    secvenţele de control din interiorul unei porţiuni rămân neatinse — deci poziţionarea
    cursorului, culorile şi timpii fiecărui eveniment rămân exact cum erau;
  * e BEST-EFFORT, şi UI-ul o spune: un secret fără formă recunoscută (o parolă afişată fără
    `password=` în faţă), unul desenat caracter cu caracter de o aplicaţie pe tot ecranul (cu
    mutări de cursor între litere) sau unul colorat la mijloc nu se recunoaşte. Tastarea nu e
    înregistrată deloc (core: doar output-ul ajunge în .cast).
"""

import json
import time
import unicodedata

from . import alert_history

# expirarea: alegeri fixe (1 h / 24 h / 7 zile), nimic peste 7 zile
EXPIRY_HOURS = (1, 24, 168)
DEFAULT_EXPIRY_HOURS = 24
LABEL_MAX = 80
MAX_ACTIVE_PER_USER = 200          # plafon de link-uri active per cont (anti-abuz)
MAX_ACTIVE_PER_SESSION = 20        # … şi per înregistrare
OPENS_KEPT = 50                    # rânduri din jurnalul de deschideri păstrate per link
ALERT_EVERY = 600                  # alerta „link deschis": cel mult una per link la 10 minute
SPAN_CAP = 16384                   # o porţiune mascată nu trece de atât (cheie privată fără END)


# ── mascare ──────────────────────────────────────────────────────────────────────────────
def _is_ctrl(c: str) -> bool:
    o = ord(c)
    return o < 0x20 or o == 0x7f or 0x80 <= o < 0xa0


def _mask_chars(seg: str) -> list:
    """Câte un înlocuitor per caracter din `seg`: `*` (sau `**` pentru un caracter lat),
    caracterele de control şi SECVENŢELE ESC (CSI/OSC/ESC x) rămân neschimbate."""
    out = []
    i, n = 0, len(seg)
    while i < n:
        c = seg[i]
        if c == "\x1b":
            j = i + 1
            if j < n and seg[j] == "[":                       # CSI: parametri + octet final
                j += 1
                while j < n and not ("@" <= seg[j] <= "~"):
                    j += 1
                j += 1
            elif j < n and seg[j] == "]":                     # OSC: până la BEL sau ST
                j += 1
                while j < n and seg[j] not in "\x07\x1b":
                    j += 1
                j += 2 if (j < n and seg[j] == "\x1b") else 1
            else:
                j += 1
            j = min(j, n)
            out.extend(seg[i:j])
            i = j
            continue
        if _is_ctrl(c):
            out.append(c)
        elif unicodedata.east_asian_width(c) in ("W", "F"):
            out.append("**")
        else:
            out.append("*")
        i += 1
    return out


def _spans(s: str) -> list:
    return [(a, min(b, a + SPAN_CAP)) for a, b in alert_history.secret_spans(s)]


def mask_secrets(s: str) -> str:
    """Varianta pe un singur şir (vizualizarea text): aceleaşi porţiuni, aceeaşi mascare."""
    parts, pos = [], 0
    for a, b in _spans(s):
        parts.append(s[pos:a])
        parts.append("".join(_mask_chars(s[a:b])))
        pos = b
    parts.append(s[pos:])
    return "".join(parts)


def redact_events(events: list) -> list:
    """`events` = [[t, kind, text], …] → aceeaşi listă, cu secretele din evenimentele `o`
    mascate PESTE graniţele dintre evenimente. Timpii, tipurile şi numărul de evenimente rămân."""
    outs = [i for i, e in enumerate(events) if e[1] == "o"]
    texts = [events[i][2] for i in outs]
    joined = "".join(texts)
    spans = _spans(joined)
    if not spans:
        return events
    # înlocuitorii per caracter, calculaţi pe TOATĂ porţiunea (o secvenţă ESC tăiată între două
    # evenimente e recunoscută ca întreg), apoi împărţiţi pe evenimente
    reps = [(a, b, _mask_chars(joined[a:b])) for a, b in spans]
    result = [list(e) for e in events]
    si, off = 0, 0
    for idx, text in zip(outs, texts):
        end = off + len(text)
        while si < len(reps) and reps[si][1] <= off:
            si += 1
        if si < len(reps) and reps[si][0] < end:
            pieces, pos, k = [], off, si
            while k < len(reps) and reps[k][0] < end:
                a, b, rep = reps[k]
                lo, hi = max(a, off), min(b, end)
                pieces.append(joined[pos:lo])
                pieces.append("".join(rep[lo - a:hi - a]))
                pos = hi
                if b > end:
                    break
                k += 1
            pieces.append(joined[pos:end])
            result[idx][2] = "".join(pieces)
        off = end
    return result


def redact_cast(raw: bytes) -> bytes:
    """Un fişier .cast (asciicast v2) → acelaşi fişier, mascat. Antetul trece neschimbat;
    liniile corupte se sar (player-ul le sare oricum)."""
    lines = raw.decode("utf-8", "replace").split("\n")
    header, events = [], []
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("{"):
            if not events and not header:
                header.append(line)
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, list) and len(e) >= 3 and isinstance(e[0], (int, float)) \
                and isinstance(e[2], str):
            events.append(e[:3])
    out = header + [json.dumps(e) for e in redact_events(events)]
    return ("\n".join(out) + "\n").encode("utf-8")


_cache: dict = {"key": None, "data": b""}


def redacted_cast_file(path) -> bytes:
    """`redact_cast` pe un fişier, cu un cache de o intrare: o sesiune ÎNCHISĂ nu se mai
    schimbă, deci aceeaşi înregistrare deschisă de mai mulţi invitaţi se maschează o dată."""
    st = path.stat()
    key = (str(path), st.st_mtime_ns, st.st_size)
    if _cache["key"] == key:
        return _cache["data"]
    data = redact_cast(path.read_bytes())
    _cache.update(key=key, data=data)
    return data


# ── limitarea ratei pe endpoint-urile publice ─────────────────────────────────────────────
# Tokenul are 256 de biţi, deci ghicirea nu e o ameninţare reală — limita există ca un client
# să nu poată folosi endpoint-urile publice ca amplificator (mascarea unei înregistrări de zeci
# de MB costă CPU) şi ca un scanner să fie oprit devreme. Două plafoane, per IP:
#   * total: RATE_MAX cereri / RATE_WINDOW (un invitat legitim face 2-3);
#   * eşecuri: MISS_MAX tokenuri necunoscute / MISS_WINDOW → blocat MISS_LOCK secunde, pentru
#     ORICE token (şi unul valid) — altfel blocajul ar fi el însuşi un oracol.
RATE_MAX, RATE_WINDOW = 60, 60.0
MISS_MAX, MISS_WINDOW, MISS_LOCK = 20, 600.0, 600.0
_req: dict = {}
_miss: dict = {}
_locked: dict = {}


def _prune(now: float) -> None:
    if len(_req) + len(_miss) + len(_locked) < 2048:
        return
    for d, w in ((_req, RATE_WINDOW), (_miss, MISS_WINDOW)):
        for k in [k for k, ts in d.items() if not ts or now - ts[-1] > w]:
            d.pop(k, None)
    for k in [k for k, t in _locked.items() if t <= now]:
        _locked.pop(k, None)


def gate(ip: str) -> int:
    """0 = cererea trece; altfel câte secunde să aştepte clientul (429 + Retry-After)."""
    now = time.time()
    _prune(now)
    until = _locked.get(ip, 0)
    if until > now:
        return int(until - now) + 1
    ts = [t for t in _req.get(ip, []) if now - t < RATE_WINDOW]
    if len(ts) >= RATE_MAX:
        _req[ip] = ts
        return int(RATE_WINDOW - (now - ts[0])) + 1
    ts.append(now)
    _req[ip] = ts
    return 0


def record_miss(ip: str) -> None:
    now = time.time()
    ts = [t for t in _miss.get(ip, []) if now - t < MISS_WINDOW]
    ts.append(now)
    if len(ts) >= MISS_MAX:
        _locked[ip] = now + MISS_LOCK
        ts = []
    _miss[ip] = ts


def reset_limits() -> None:
    """Pentru teste."""
    _req.clear()
    _miss.clear()
    _locked.clear()
