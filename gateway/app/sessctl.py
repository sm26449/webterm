"""Who may control a session. `require_session_control` (your own session, or `session.manage` on
the host) is called by the session routes (api.py `[sessions]`) and the share / replay routes
(`share_api.py`). The private root terminals on the gateway host (`ROOT_TERMINAL_ORIGINS`, read
with `session_origin`: certificate renewal, System health fixes), which nobody else types into and
nobody shares, are checked by the browser websocket (api.py `_ws_access`) and by live sharing;
`[certs]` opens them with `CERT_RENEW_ORIGIN`. Moved out of api.py.
"""
from .errors import ApiError
from . import authz, db


async def require_session_control(request, sid: str, user) -> None:
    """Mutaţiile pe o sesiune (titlu, kill, ştergere, reconectare): `session.open` (verificat de
    rută) + sesiunea e a ta — sau ai `session.manage` pe host (Q5: Operatorii urmăresc sesiunile
    altora, dar nu le controlează)."""
    row = await db.fetchone("SELECT host_id, created_by_id FROM sessions WHERE id=?", sid)
    if not row:
        return                                    # handlerul răspunde cu 404-ul lui
    if row["created_by_id"] is None or row["created_by_id"] == user["id"]:
        return
    have = await authz.require_on(request, row["host_id"], "session.open", "sid")
    if "session.manage" not in have:
        raise ApiError(403, "authz.denied", "your role does not allow this here (session.manage)",
                       vars={"perm": "session.manage"})


CERT_RENEW_ORIGIN = "cert-renew"


# 3.6.8: every session that types a ROOT command on the gateway host (cert renewal, System health
# fixes) is private: only its Owner types, others may watch, nobody can share it.
ROOT_TERMINAL_ORIGINS = frozenset({CERT_RENEW_ORIGIN, "health-fix"})


def session_origin(row) -> str:
    return (row["origin"] if "origin" in row.keys() else "") or ""
