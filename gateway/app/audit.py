"""Jurnal de audit: cine, ce, când, de la ce IP — pentru fiecare cerere care SCHIMBĂ ceva.

De ce există: transcripturile spun ce s-a tastat într-un terminal, `agent_events` spune cum
au venit și plecat agenții, dar până acum nimic nu răspundea la „ce s-a făcut prin UI/API".
Într-un model single-admin valoarea nu e atribuirea (contul e unul singur), ci reconstituirea
DUPĂ un incident: dacă îți fură cineva cookie-ul, vrei să vezi ce share-uri a creat, ce
fișiere a scos, ce a rulat pe flotă și de pe ce IP.

Colectare AUTOMATĂ, prin middleware (vezi main.py): orice POST/PATCH/PUT/DELETE pe /api/*
ajunge aici, cu status-ul răspunsului. Alegerea e deliberată — o listă de apeluri manuale
rămâne mereu în urma endpoint-urilor noi, exact genul de gaură care se observă abia la audit.
Endpoint-urile care au context util (ce comandă, ce fișier, ce host) îl atașează cu
`detail()`; restul sunt oricum identificabile din metodă + cale.

NU se înregistrează corpurile cererilor: acolo trec parole, token-uri de step-up, conținut de
fișier. Jurnalul e o listă de acțiuni, nu o copie a traficului.
"""

import logging
import time

from . import config, db

log = logging.getLogger("webterm")

# plafon dur de rânduri, peste retenţia temporală (vezi prune)
MAX_ROWS = 200_000

# calea completă e „ținta" (are id-urile în ea); nu logăm query string-ul — poate conține
# token de share/enroll, iar valoarea lui de audit e zero față de riscul de a-l persista
_SKIP = ("/api/history",)      # zgomot pur: istoricul de comenzi are deja tabelul lui

# Citiri care SCOT DATE din sistem. Middleware-ul înregistra doar metodele care schimbă ceva,
# ceea ce lăsa exfiltrarea complet nevăzută: descărcarea unui fişier, transcriptul unei sesiuni,
# jurnalul agentului. Chiar scenariul pentru care există modulul ăsta — „mi-a fost furat
# cookie-ul, ce a scos?" — nu avea răspuns. Enumerările simple (lista de hosturi/sesiuni) rămân
# în afara listei: fac zgomot la fiecare refresh şi nu scot conţinut.
_AUDITED_READS = (
    "/api/sessions/", "/api/hosts/", "/api/backup/",
)
_READ_MARKERS = (
    "/transcript", "/preview", "/fs/download", "/agent-log", "/export", "/download",
)


def audited_read(path: str) -> bool:
    """GET care scoate CONŢINUT din sistem (nu doar listează)."""
    return (any(path.startswith(p) for p in _AUDITED_READS)
            and any(m in path for m in _READ_MARKERS))


def _skip(method: str, path: str) -> bool:
    """Zgomotul se taie, distrugerea nu.

    `_SKIP` compara doar prefixul căii, indiferent de metodă — deci `DELETE /api/history`,
    adică ştergerea întregului istoric căutabil de comenzi, nu lăsa NICIO urmă. Dar `POST` pe
    aceeaşi cale chiar e zgomot: se scrie o dată la fiecare comandă rulată. Deci pe căile din
    `_SKIP` auditam totul MAI PUŢIN ştergerea."""
    if not any(path.startswith(p) for p in _SKIP):
        return False
    return method != "DELETE"


def detail(request, text: str) -> None:
    """Atașează context semantic cererii curente (ce comandă, ce fișier, ce host).
    Middleware-ul îl preia la final. Apelabil de oriunde are `request`."""
    try:
        request.state.audit_detail = text[:500]
    except Exception:                       # noqa: BLE001 — auditul nu rupe calea principală
        pass


def actor(request, email: str) -> None:
    """Marchează actorul când cererea NU are încă sesiune (login, setup, passkey login)."""
    try:
        request.state.audit_actor = (email or "")[:200]
    except Exception:                       # noqa: BLE001
        pass


async def record(ts: float, actor_email: str, ip: str, method: str, path: str,
                 status: int, det: str = "") -> None:
    if _skip(method, path):
        return
    # Un client ANONIM nu trebuie să poată umfla jurnalul: orice 401/404 pe /api/* scria un rând,
    # iar retenţia e doar temporală. Cererile respinse fără actor sunt zgomot de scanare; cele
    # cu actor (cookie furat care loveşte un 403) rămân, fiindcă alea chiar spun ceva.
    if not actor_email and status in (401, 403, 404, 405):
        return
    try:
        await db.execute(
            "INSERT INTO audit_log(ts, actor, ip, method, path, status, detail)"
            " VALUES(?,?,?,?,?,?,?)",
            ts, actor_email[:200], ip[:64], method, path[:400], int(status), det[:500])
    except Exception:                       # noqa: BLE001 — auditul nu rupe cererea…
        # …dar nici nu dispare în tăcere. Se înghiţea complet, deci pista de audit se stingea
        # exact când contează: DB blocat, disc plin, migrare în curs — adică în timpul unui
        # incident. Cererea reuşeşte în continuare (jurnalul nu e o barieră), dar rămâne o urmă
        # în logul serverului că nu s-a putut scrie.
        log.exception("audit: could not write the entry for %s %s", method, path)


async def prune() -> None:
    """Retenție (implicit cât arhiva de transcripturi): un jurnal care crește la infinit
    e o problemă de disc și de confidențialitate, nu o virtute."""
    try:
        await db.execute("DELETE FROM audit_log WHERE ts < ?",
                         time.time() - config.AUDIT_RETENTION_DAYS * 86400)
        # Plafon şi pe NUMĂR de rânduri: retenţia temporală singură nu opreşte o inundare
        # rapidă (un client care bate API-ul umple discul mult înainte de expirare).
        await db.execute(
            "DELETE FROM audit_log WHERE id NOT IN"
            " (SELECT id FROM audit_log ORDER BY ts DESC LIMIT ?)", MAX_ROWS)
    except Exception:                       # noqa: BLE001
        pass


async def recent(limit: int = 200, before: float = 0.0, q: str = "",
                 failed_only: bool = False) -> list:
    """Ultimele intrări, cele mai noi întâi. `q` filtrează pe cale/detaliu/IP (LIKE),
    `before` paginează în trecut."""
    sql = ["SELECT ts, actor, ip, method, path, status, detail FROM audit_log WHERE 1=1"]
    args: list = []
    if before:
        sql.append("AND ts < ?")
        args.append(before)
    if q:
        sql.append("AND (path LIKE ? OR detail LIKE ? OR ip LIKE ?)")
        args += ["%" + q + "%"] * 3
    if failed_only:
        sql.append("AND status >= 400")
    sql.append("ORDER BY ts DESC LIMIT ?")
    args.append(max(1, min(1000, limit)))
    rows = await db.fetchall(" ".join(sql), *args)
    return [dict(r) for r in rows]
