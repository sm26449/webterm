"""Poarta handshake-ului de agent (`/agent/ws`), în memorie (3.6.38).

Cerinţa (Stefan, 2026-11-19): un robot care trimite zeci de cereri pe secundă fără token, sau cu
unul greşit, nu trebuie să ne facă să citim şi să scriem în SQLite la fiecare cerere. Un token bun
trece; lipsă sau greşit → blocare.

  * Tokenurile BUNE se ţin în memorie: amprentele (`token_hash`) tuturor hosturilor, încărcate din
    DB la pornire şi reîmprospătate la `REFRESH` secunde (un singur SELECT, oricât trafic ar fi).
    Un agent cu token cunoscut trece MEREU, chiar de pe o adresă blocată: un NAT împărţit cu un
    atacator nu scoate agenţii legitimi din flotă.
  * Token LIPSĂ: refuz pe loc, fără nicio citire. Token NECUNOSCUT: o citire în DB (acoperă un host
    creat de mai puţin de `REFRESH` secunde), dar numai cât adresa nu e blocată.
  * Fiecare refuz e un „strike" pe adresă (IPv6: pe /64, altfel un atacator îşi schimbă adresa în
    propriul /64 la fiecare cerere). `STRIKES` strike-uri în `WINDOW` secunde → blocare `BLOCK_BASE`,
    dublată la fiecare recidivă, până la `BLOCK_MAX`. O adresă blocată cu un token necunoscut e
    refuzată fără DB, fără log, fără eveniment.
  * Memorie plafonată: cel mult `MAX_KEYS` adrese urmărite; peste plafon se aruncă întâi cele
    neblocate şi expirate, apoi cele mai vechi.

Totul e în procesul gateway-ului (un singur worker, vezi Dockerfile): o repornire şterge blocările,
ceea ce e acceptabil — limitele lui Traefik rămân primul strat, iar un bot revine repede în blocare.
Sursa adresei: `security.client_ip_ws` (lanţul de proxy-uri de încredere); când nu poate fi stabilită,
toate cererile fără sursă împart aceeaşi cheie, deci un antet trimis de client nu deschide buget nou."""
import ipaddress
import logging
import time
from typing import Optional

from . import db

log = logging.getLogger("webterm.agentgate")

STRIKES = 5
WINDOW = 600.0
BLOCK_BASE = 600.0
BLOCK_MAX = 86400.0
MAX_KEYS = 50000
REFRESH = 60.0

_known: set = set()
_known_at = 0.0
# cheie → [strike-uri în fereastră, începutul ferestrei, blocat până la, nivel de recidivă, ultima atingere]
_state: dict = {}
stats = {"blocked_refusals": 0, "blocks": 0}


def ip_key(ip: str) -> str:
    """Adresa ca cheie: IPv4 întreagă, IPv6 pe /64; orice altceva (\"?\", gol) = o singură cheie comună."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return "unknown"
    if a.version == 6:
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network("%s/64" % a, strict=False))
    return str(a)


async def refresh_known(now: Optional[float] = None, force: bool = False) -> None:
    """Un singur SELECT pe REFRESH secunde, oricâte handshake-uri sosesc deodată: momentul se
    marchează ÎNAINTE de await (review 3.6.38: altfel 200 de cereri simultane = 200 de SELECT-uri)."""
    global _known, _known_at
    now = now or time.time()
    if not force and now - _known_at < REFRESH:
        return
    prev_at = _known_at
    _known_at = now
    try:
        rows = await db.fetchall("SELECT token_hash FROM hosts WHERE token_hash IS NOT NULL AND token_hash != ''")
    except Exception:                       # noqa: BLE001 — încercăm din nou la următorul handshake
        _known_at = prev_at
        raise
    _known = {r["token_hash"] for r in rows}


def is_known(token_hash: str) -> bool:
    return bool(token_hash) and token_hash in _known


def remember(token_hash: str) -> None:
    if token_hash:
        _known.add(token_hash)


def forget(token_hash: str) -> None:
    _known.discard(token_hash)


def blocked(ip: str, now: Optional[float] = None) -> bool:
    st = _state.get(ip_key(ip))
    return bool(st and st[2] > (now or time.time()))


def blocked_count(now: Optional[float] = None) -> int:
    now = now or time.time()
    return sum(1 for st in _state.values() if st[2] > now)


def _prune(now: float) -> None:
    """Peste plafon aruncăm cheia atinsă cel mai demult. `_state` e ordonat după ultima atingere
    (strike() mută cheia la coadă), deci primul element e cel mai vechi: O(1), nu o sortare a
    50 000 de intrări la fiecare adresă nouă (review 3.6.38: ~12 ms pe event loop)."""
    while len(_state) >= MAX_KEYS:
        del _state[next(iter(_state))]


def strike(ip: str, now: Optional[float] = None) -> bool:
    """Un handshake refuzat de pe `ip`. Întoarce True dacă abia acum a fost blocat."""
    now = now or time.time()
    key = ip_key(ip)
    st = _state.pop(key, None)                    # pop + reinserare = mutat la coada ordinii
    if st is None:
        _prune(now)
        st = [0, now, 0.0, 0, now]
    _state[key] = st
    st[4] = now
    # #8: recidiva se uită după o zi fără blocare (un agent vechi uitat într-un NAT nu urcă la nesfârşit)
    if st[3] and st[2] <= now and now - max(st[2], st[1]) > BLOCK_MAX:
        st[3] = 0
    if now - st[1] > WINDOW:                      # fereastră nouă (nivelul de recidivă rămâne)
        st[0], st[1] = 0, now
    st[0] += 1
    if st[0] >= STRIKES and st[2] <= now:
        st[2] = now + min(BLOCK_BASE * (2 ** st[3]), BLOCK_MAX)
        st[3] += 1
        st[0], st[1] = 0, now
        stats["blocks"] += 1
        return True
    return False


def forgive(ip: str, triggered: bool) -> None:
    """Anulează un strike dat PROVIZORIU înaintea citirii din DB, când tokenul s-a dovedit valid.
    Strike-ul se dă înainte de citire ca să nu existe niciun `await` între „e blocat?" şi numărare:
    altfel 40 de cereri simultane trec toate de verificare (măsurat în staging: 15 citiri pe IP în
    loc de 5). Dacă tocmai strike-ul ăsta a declanşat blocarea, o desfacem."""
    st = _state.get(ip_key(ip))
    if not st:
        return
    if triggered:
        # strike-ul ăsta a fost al STRIKES-lea: desfacem blocarea, dar păstrăm celelalte STRIKES-1
        # (review 3.6.38: aducerea la 0 îi dădea unui atacator din acelaşi NAT încă 5 citiri)
        st[2] = 0.0
        st[3] = max(0, st[3] - 1)
        st[0] = STRIKES - 1
        stats["blocks"] = max(0, stats["blocks"] - 1)
    elif st[0] > 0:
        st[0] -= 1


def note_blocked_refusal() -> None:
    stats["blocked_refusals"] += 1


def reset_for_tests() -> None:
    global _known, _known_at
    _known, _known_at = set(), 0.0
    _state.clear()
    stats.update(blocked_refusals=0, blocks=0)
