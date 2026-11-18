"""Revocarea accesului DERIVAT: share-uri live și link-uri de replay.

Folosit de rutele din api.py (logout, schimbare de parolă, ștergere de cont) și share_api.py („Revocă tot"),
de accounts.py (ștergere / dezactivare de cont) și de ssomap.py (rol pierdut din SSO). Stă în
modul propriu ca acestea să nu importe api.py (vezi tests/import_layers_test.py).
"""
from __future__ import annotations

import time

from . import authz, core, db

# INV-05 (docs/design/INVARIANTS.md): accesul derivat moare odată cu cel care l-a dat (logout, parolă, rol pierdut).
async def revoke_all_shares(owner_email: str | None = None,
                             owner_id: int | None = None) -> int:
    """Share-urile (PTY live, opţional writable) sunt acces DERIVAT — mor la logout /
    schimbare de parolă, ca token-urile de forward (M3). Altfel un share creat cu un
    cookie furat supravieţuieşte deconectării owner-ului până la expirare (max 24h).

    `owner_email` limitează revocarea la share-urile create de ACEL cont. Înainte era
    global, iar de la conturile multiple (1.0.137) asta însemna: logout-ul lui A omoară
    link-urile lui B, într-un mod imposibil de diagnosticat („de ce a murit share-ul de
    incident?"). Semnalat de un audit extern. Fără argument (sau pe share-uri vechi, fără
    `share_by`) rămâne global — la schimbarea parolei după compromitere vrei exact asta.

    Întoarce câte link-uri ÎNCĂ ACTIVE (neexpirate) au fost revocate — „Revocă tot" din
    inventarul de share-uri (3.5.4) îl arată omului. Rândurile expirate se curăţă şi ele, dar
    nu se numără: n-ar mai fi deschis nimic."""
    now = time.time()
    if owner_email or owner_id is not None:
        # id-ul e cheia; emailul rămâne rezervă pentru share-urile create înainte de migrare.
        # Cheiat DOAR pe email, o schimbare de email scotea share-urile de sub orice revocare.
        where = " WHERE share_token IS NOT NULL AND (share_by_id=? OR share_by=?)"
        args = (owner_id, owner_email)
    else:
        where = " WHERE share_token IS NOT NULL"
        args = ()
    rows = await db.fetchall("SELECT id, share_expires FROM sessions" + where, *args)
    await db.execute("UPDATE sessions SET share_token=NULL, share_expires=NULL,"
                     " share_writable=0" + where, *args)
    sids = {r["id"] for r in rows}
    for sid, hub in list(core.hubs.items()):
        if sid in sids:
            await hub.revoke_shares()      # închide invitaţii deja conectaţi (stop broadcast)
    return sum(1 for r in rows if (r["share_expires"] or 0) > now)


async def delete_replay_links(where: str, *args) -> int:
    """Şterge link-urile de replay care se potrivesc (+ jurnalul lor de deschideri) şi întoarce
    câte erau ÎNCĂ ACTIVE. Ştergere, nu marcaj: un link revocat nu mai are ce arăta, iar urma
    durabilă a deschiderilor stă oricum în audit_log."""
    rows = await db.fetchall("SELECT id, expires FROM replay_links" + where, *args)
    if not rows:
        return 0
    ids = [r["id"] for r in rows]
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        marks = ",".join("?" * len(chunk))
        await db.execute("DELETE FROM replay_opens WHERE link_id IN (%s)" % marks, *chunk)
        await db.execute("DELETE FROM replay_links WHERE id IN (%s)" % marks, *chunk)
    now = time.time()
    return sum(1 for r in rows if r["expires"] > now)


async def revoke_replay_links(owner_id: int | None = None) -> int:
    """Revocarea link-urilor de replay pe căile pe care mor şi share-urile live: schimbarea
    parolei (global — după un compromis vrei TOT acest acces derivat tăiat), ştergerea contului
    (doar ale lui), „Revocă tot" din inventar (global). NU şi la logout: un link de replay nu e
    o vedere a unui terminal viu, ci o înregistrare încheiată, cu expirare de maxim 7 zile — iar
    omul care partajează o înregistrare şi apoi se deconectează nu se aşteaptă s-o fi retras."""
    if owner_id is None:
        return await delete_replay_links("")
    return await delete_replay_links(" WHERE user_id=?", owner_id)


async def revoke_unauthorized_derived(uid: int) -> None:
    g = await authz.grants_for_user(uid)
    rows = await db.fetchall(
        "SELECT id, host_id, share_writable FROM sessions WHERE share_token IS NOT NULL"
        " AND share_by_id=?", uid)
    for r in rows:
        have = await authz.perms_on(g, r["host_id"])
        if "share.live" not in have or (r["share_writable"] and "share.live_write" not in have):
            await db.execute("UPDATE sessions SET share_token=NULL, share_expires=NULL,"
                             " share_writable=0 WHERE id=?", r["id"])
            hub = core.hubs.get(r["id"])
            if hub:
                await hub.revoke_shares()
    links = await db.fetchall(
        "SELECT l.id, s.host_id FROM replay_links l LEFT JOIN sessions s ON s.id=l.sid"
        " WHERE l.user_id=?", uid)
    for ln in links:
        if ln["host_id"] is None or "share.replay" not in await authz.perms_on(g, ln["host_id"]):
            await delete_replay_links(" WHERE id=?", ln["id"])
