"""Tipurile de conexiune ale unui host — SINGURUL loc care le enumeră şi le grupează.

    agent        agentul WebTerm rulează pe host (PTY local, fişiere, docker…)
    ssh          gateway-ul deschide SSH direct către host
    ssh-jump     SSH către host, cu TCP-ul deschis DIN agentul altui host (`via_host_id`)
    telnet       telnet direct
    telnet-jump  telnet prin agentul altui host

Până la 3.6.35 tuplurile de mai jos erau scrise de mână de ~70 de ori în api.py/core.py, iar
regula „NULL = agent" (hosturile create înainte de tipurile de conexiune) era repetată ca
`row["connection_type"] or "agent"`. Bypass-urile găsite la review în lotul SSH din 3.6.34 (un
host `agent` mutat pe `ssh` cu parola veche) stăteau exact în matricea asta. Un tip nou se
adaugă AICI şi în `frontend/src/lib/conntypes.ts`; `tests/conntypes_test.py` verifică că nu
reapar tupluri literale în altă parte şi că cele două liste sunt identice.
"""
from __future__ import annotations

# INV-02 (docs/design/INVARIANTS.md): singurul loc care enumeră tipurile; fără tip = agent.
AGENT = "agent"
SSH = "ssh"
SSH_JUMP = "ssh-jump"
TELNET = "telnet"
TELNET_JUMP = "telnet-jump"

ALL = (AGENT, SSH, SSH_JUMP, TELNET, TELNET_JUMP)
SSH_FAMILY = (SSH, SSH_JUMP)            # autentificare SSH: utilizator, parolă/cheie, cheie de host
TELNET_FAMILY = (TELNET, TELNET_JUMP)
JUMP = (SSH_JUMP, TELNET_JUMP)          # TCP-ul pleacă din agentul hostului `via_host_id`
NETWORK = SSH_FAMILY + TELNET_FAMILY    # gateway-ul se conectează la un hostname (nu e agent)


# Aceeaşi regulă („NULL = agent") în SQL. Constantă din cod, sigură de interpolat într-o
# interogare. Coloana are DEFAULT 'agent', deci NULL apare doar pe date scrise de mână — dar
# regula trebuie să fie aceeaşi în Python şi în SQL, nu „aproape aceeaşi".
SQL_IS_AGENT = "coalesce(connection_type,'agent')='agent'"
SQL_NETWORK = "connection_type IN (%s)" % ",".join("'%s'" % t for t in NETWORK)


def of(x) -> str:
    """Tipul stocat al unui host: rând sqlite / dict / model cu `connection_type`, sau direct
    valoarea. NULL sau gol = `agent` (hosturile de dinaintea tipurilor de conexiune). NU
    normalizează majusculele: valorile sunt validate la scriere (`host.badType`)."""
    if x is None or isinstance(x, str):
        return x or AGENT
    # Strict: un rând FĂRĂ coloana `connection_type` (SELECT incomplet) ridică KeyError, nu e
    # ghicit ca agent — altfel o verificare „doar pentru agent" ar trece pe un host direct.
    if hasattr(x, "keys"):
        return x["connection_type"] or AGENT
    return x.connection_type or AGENT


def is_agent(x) -> bool:
    return of(x) == AGENT


def default_port(ctype: str) -> int:
    return 23 if ctype in TELNET_FAMILY else 22


def target_proto(ctype: str) -> str:
    """Protocolul cu care gateway-ul ar vorbi cu ţinta. Un host `agent` e tratat ca SSH: la o
    mutare agent → ssh/telnet, adresa veche se compară ca ţintă SSH (vezi api._conn_target)."""
    return TELNET if ctype in TELNET_FAMILY else SSH
