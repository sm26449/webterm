"""Igiena sesiunilor inactive (3.7.1): notificare după N zile nefolosite, închidere automată opţională.

Decizia proprietarului (2026-11-21):
  * „inactivă" = fără input, fără output ŞI fără niciun client ataşat pe toată perioada. Un `tail -f`
    sau un build care scrie nu e niciodată inactiv; o comandă tăcută zile întregi pare inactivă —
    pentru ea există notificarea şi „Păstrează deschisă";
  * implicit: notificarea PORNITĂ (7 zile), închiderea automată OPRITĂ până o porneşte un Owner/Admin
    pentru instanţă; închiderea vine la `grace_days` (2) după notificare;
  * notificarea merge proprietarului sesiunii (`created_by_id`); sesiunile fără proprietar → cei cu
    `session.manage` pe host. Terminalele root de pe gateway (ROOT_TERMINAL_ORIGINS): doar proprietarul;
  * închiderea foloseşte calea EXISTENTĂ (`core.kill_session`, ca butonul Stop): tmux omorât pe host,
    transcript păstrat, hub curăţat de `on_exit`, plus un rând de audit „system:idle-sessions".

Fail-closed (ce NU închide niciodată): orice eroare, o sesiune al cărei flux nu-l vedem (fără hub,
hub neataşat la sursă, host offline), un client ataşat, „Păstrează deschisă", o sesiune fără
destinatar pentru notificare (nimeni n-a fost avertizat), o notificare trimisă cât închiderea
automată era oprită (n-a promis nicio închidere), activitate după notificare.
"""
import json
import logging
import time
from typing import Optional

from . import audit, authz, core, db, email_alerts, sessctl

log = logging.getLogger("webterm")

SETTING_KEY = "idle_sessions"
DAY = 86400.0
DEFAULTS = {"notify": True, "notify_days": 7, "autoclose": False, "grace_days": 2}
NOTIFY_DAYS = (1, 90)
GRACE_DAYS = (1, 30)
SWEEP_INTERVAL = 600.0           # şi cadenţa cu care se persistă `last_active` (~10 min)
SWEEP_STARTUP_GRACE = 600.0      # după pornire: reconcilierea agenţilor re-ataşează hub-urile întâi
MAX_ROWS = 2000                  # sesiuni vii citite pe sweep (plafon de lucru)
MAX_ACTIONS = 20                 # notificări + închideri pe sweep (restul la următorul)
MAX_RECIPIENT_SCAN = 500         # conturi verificate pentru `session.manage` (sesiune fără proprietar)
_CACHE_TTL = 30.0

_cache: dict = {"at": 0.0, "policy": dict(DEFAULTS)}


def _clamp(v, lo, hi, default) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def sanitize(raw) -> dict:
    """Politica stocată → valori sigure. Orice lucru necitibil cade pe implicit (închidere OPRITĂ)."""
    d = raw if isinstance(raw, dict) else {}
    return {
        # notificarea e inofensivă: doar un `false` explicit o opreşte
        "notify": d.get("notify") is not False,
        "notify_days": _clamp(d.get("notify_days"), *NOTIFY_DAYS, DEFAULTS["notify_days"]),
        # doar un `true` explicit porneşte închiderea — nimic „truthy" (fail-closed)
        "autoclose": d.get("autoclose") is True,
        "grace_days": _clamp(d.get("grace_days"), *GRACE_DAYS, DEFAULTS["grace_days"]),
    }


async def load_policy(fresh: bool = False) -> dict:
    now = time.time()
    if not fresh and now - _cache["at"] < _CACHE_TTL:
        return dict(_cache["policy"])
    try:
        raw = json.loads(await db.get_setting(SETTING_KEY, "") or "{}")
    except ValueError:
        raw = {}
    pol = sanitize(raw)
    _cache["at"], _cache["policy"] = now, pol
    return dict(pol)


async def save_policy(pol: dict) -> dict:
    pol = sanitize(pol)
    prev = await load_policy(fresh=True)
    await db.set_setting(SETTING_KEY, json.dumps(pol))
    if pol["autoclose"] and not prev["autoclose"]:
        # Review 3.7.1: oprit apoi repornit, un termen vechi (deja trecut) închidea sesiunea în 10 minute,
        # deşi omul văzuse ultima dată „nimic programat". Ştergem termenele: sweep-ul trimite o notificare
        # nouă, cu termenul de acum, înainte de orice închidere.
        await db.execute("UPDATE sessions SET idle_close_after=NULL WHERE idle_close_after IS NOT NULL")
    _cache["at"], _cache["policy"] = time.time(), pol
    return dict(pol)


def notice_json(row, pol: dict) -> Optional[dict]:
    """Ce vede UI-ul despre notificarea unei sesiuni (lista de sesiuni): None = nicio notificare."""
    at = row["idle_notified_at"] if "idle_notified_at" in row.keys() else None
    if not at or row["state"] != "live":
        return None
    close_at = close_deadline(row, pol)
    return {"at": at, "days": pol["notify_days"], "close_at": close_at}


def close_deadline(row, pol: dict) -> Optional[float]:
    """Momentul închiderii automate, sau None dacă nu e programată: închiderea trebuie să fie pornită
    ACUM şi să fi fost pornită la notificare (`idle_close_after` fixat atunci). O grație mărită între
    timp amână termenul; una micşorată nu-l aduce mai aproape de ce i s-a spus omului."""
    if not pol["autoclose"] or not pol["notify"]:
        return None                           # funcţia oprită = nimic programat
    at = row["idle_notified_at"]
    after = row["idle_close_after"]
    if not at or not after:
        return None
    return max(float(after), float(at) + pol["grace_days"] * DAY)


async def set_keep_open(sid: str, keep: bool) -> None:
    """„Păstrează deschisă": anulează şi o notificare/închidere în curs."""
    await db.execute("UPDATE sessions SET keep_open=?, idle_notified_at=NULL, idle_close_after=NULL"
                     " WHERE id=?", 1 if keep else 0, sid)
    hub = core.hubs.get(sid)
    if hub is not None:
        hub.idle_pending = False


def _transcript_mtime(sid: str) -> Optional[float]:
    try:
        return core.transcript_paths(sid)[0].stat().st_mtime
    except (OSError, ValueError):
        return None


def last_activity(row, hub) -> Optional[float]:
    """Ultima folosire cunoscută a sesiunii, sau None = nu ştim (→ nu facem nimic). Sursele: hub-ul
    (output/input/prezenţă în memorie), `last_active` persistat (supravieţuieşte restartului),
    mtime-ul transcriptului (orice output scris vreodată), crearea."""
    if hub is None:
        return None
    if hub.clients:
        return time.time()
    mt = _transcript_mtime(row["id"])
    if mt is None:
        return None                           # transcript ilizibil: nu putem dovedi inactivitatea
    vals = [hub.activity_at(), mt, row["created"] or 0.0, row["last_active"] or 0.0]
    return max(vals)


async def recipients(row) -> list:
    """Cine primeşte notificarea. Proprietarul, dacă e activ şi încă vede sesiunile hostului; altfel
    (sesiune fără proprietar / proprietar dezactivat sau fără acces) cei cu `session.manage` pe host.
    Terminalele root de pe gateway: DOAR proprietarul — nimeni altcineva nu le controlează."""
    hid = row["host_id"]
    owner = row["created_by_id"]
    if owner is not None:
        u = await db.fetchone("SELECT id, disabled FROM users WHERE id=?", owner)
        if u is not None and not u["disabled"]:
            have = await authz.perms_on(await authz.grants_for_user(owner), hid)
            if "session.watch" in have or "session.open" in have:
                return [owner]
    if sessctl.session_origin(row) in sessctl.ROOT_TERMINAL_ORIGINS:
        return []
    out = []
    for u in await db.fetchall("SELECT id FROM users WHERE COALESCE(disabled, 0)=0 ORDER BY id LIMIT ?",
                               MAX_RECIPIENT_SCAN):
        if "session.manage" in await authz.perms_on(await authz.grants_for_user(u["id"]), hid):
            out.append(u["id"])
    return out


async def _host_name(hid) -> str:
    r = await db.fetchone("SELECT name FROM hosts WHERE id=?", hid)
    return (r["name"] if r else "") or "host"


async def _notify(row, hub, pol: dict, uids: list, now: float) -> bool:
    close_after = now + pol["grace_days"] * DAY if pol["autoclose"] else None
    # condiţionat: o sesiune marcată Keep / închisă / deja notificată între citire şi acum nu se atinge
    won = await db.execute_returning(
        "UPDATE sessions SET idle_notified_at=?, idle_close_after=? WHERE id=? AND state='live'"
        " AND COALESCE(keep_open, 0)=0 AND (idle_notified_at IS NULL OR idle_close_after IS NULL)"
        " RETURNING id", now, close_after, row["id"])
    if won is None:
        return False
    hub.idle_pending = True
    host = await _host_name(row["host_id"])
    # toţi destinatarii într-o singură alertă (review 3.7.1: câte un email identic per cont)
    email_alerts.notify_session_idle(list(uids), row["title"] or "", host, row["host_id"], row["id"],
                                     pol["notify_days"], pol["grace_days"] if close_after else 0)
    return True


# INV-13 (docs/design/INVARIANTS.md): închiderea automată nu atinge o sesiune folosită, păstrată sau neanunţată.
async def _close(row, hub, pol: dict, uids: list, now: float) -> bool:
    sid = row["id"]
    fresh = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    if fresh is None or fresh["state"] != "live" or fresh["keep_open"]:
        return False
    deadline = close_deadline(fresh, pol)
    if deadline is None or now < deadline or fresh["idle_notified_at"] != row["idle_notified_at"]:
        return False
    # ultima verificare, SINCRON cu trimiterea (fără await între ea şi kill): un client ataşat sau
    # orice activitate după notificare → nu închidem
    if hub.closed or not hub.attached or hub.clients or not hub.idle_pending:
        return False
    if hub.activity_at() > float(fresh["idle_notified_at"]):
        return False
    # Sursa se ia SINCRON şi verificările se refac chiar înainte de kill, fără niciun await între ele
    # (review 3.7.1: `core.kill_session` citea întâi rândul din DB, iar un browser care se ataşa în
    # acel await îşi vedea sesiunea închisă imediat după ataşare — exact ce INV-13 interzice).
    source = core.session_sources.get(sid) or core.source_for(row["host_id"])
    if source is None:
        return False                          # host offline: altă dată
    if hub.closed or not hub.attached or hub.clients or not hub.idle_pending:
        return False
    if hub.activity_at() > float(fresh["idle_notified_at"]):
        return False
    hub.exit_reason = "idle"
    try:
        await source.kill(sid)
    except Exception as e:                    # noqa: BLE001 — host plecat, timeout: altă dată
        hub.exit_reason = "exited"
        log.info("idle session %s not closed: %s", sid, e)
        # rezultatul e necunoscut (agentul poate să fi închis-o totuşi): urmă în audit, ca o închidere
        # survenită după timeout să nu rămână fără explicaţie
        await audit.record(now, "system:idle-sessions", "-", "IDLE", "/api/sessions/%s/kill" % sid, 504,
                           ("idle close of \"%s\" not confirmed (%s); the session may still be open"
                            % (row["title"] or "", type(e).__name__))[:480], host_id=row["host_id"])
        return False
    idle_days = int((now - float(fresh["idle_notified_at"])) / DAY) + pol["notify_days"]
    host = await _host_name(row["host_id"])
    await audit.record(now, "system:idle-sessions", "-", "IDLE", "/api/sessions/%s/kill" % sid, 200,
                       ("closed idle session \"%s\" (unused for about %d days, notice sent %d day(s) "
                        "earlier)" % (row["title"] or "", idle_days, pol["grace_days"]))[:480],
                       host_id=row["host_id"])
    email_alerts.notify_session_idle_closed(list(uids), row["title"] or "", host, row["host_id"], sid, idle_days)
    return True


async def sweep(now: Optional[float] = None) -> dict:
    """Un ciclu: persistă activitatea hub-urilor, notifică sesiunile inactive, închide (dacă e pornit)
    pe cele notificate, nefolosite de atunci, după grație. Întoarce contoarele (pentru teste/jurnal)."""
    pol = await load_policy(fresh=True)
    now = time.time() if now is None else now
    stats = {"notified": 0, "closed": 0, "cleared": 0}
    actions = 0
    rows = await db.fetchall("SELECT * FROM sessions WHERE state='live' ORDER BY created LIMIT ?", MAX_ROWS)
    for row in rows:
        sid = row["id"]
        hub = core.hubs.get(sid)
        try:
            if hub is not None and not hub.closed:
                await hub.persist_activity()
            if row["keep_open"]:
                continue
            # fluxul trebuie să curgă prin hub (altfel n-am vedea output-ul) şi hostul să fie online
            if hub is None or hub.closed or not hub.attached or core.source_for(row["host_id"]) is None:
                continue
            last = last_activity(row, hub)
            if last is None:
                continue
            notified = row["idle_notified_at"]
            if notified and (hub.clients or last > float(notified)):
                # folosită după notificare: anulăm (dacă hub-ul n-a făcut-o deja)
                await db.execute("UPDATE sessions SET idle_notified_at=NULL, idle_close_after=NULL"
                                 " WHERE id=? AND idle_notified_at=?", sid, notified)
                hub.idle_pending = False
                stats["cleared"] += 1
                continue
            if hub.clients or not pol["notify"] or actions >= MAX_ACTIONS:
                continue
            idle_for = now - last
            if idle_for < pol["notify_days"] * DAY:
                continue
            # notificare: prima, sau a doua („se va închide…") când închiderea a fost pornită după prima
            if not notified or (pol["autoclose"] and not row["idle_close_after"]):
                actions += 1                  # căutarea destinatarilor costă şi ea (review 3.7.1): în buget
                uids = await recipients(row)
                if not uids:
                    continue                  # nimeni avertizat → nimic programat, nimic închis
                if await _notify(row, hub, pol, uids, now):
                    stats["notified"] += 1
                continue
            deadline = close_deadline(row, pol)
            if deadline is None or now < deadline:
                continue
            if idle_for < pol["notify_days"] * DAY + (deadline - float(notified)):
                continue                      # perioada întreagă (prag + grație) fără nicio folosire
            if actions >= MAX_ACTIONS:
                continue
            actions += 1
            uids = await recipients(row)
            if not uids:
                continue                      # nu mai ştim cui să-i spunem: nu închidem
            if await _close(row, hub, pol, uids, now):
                stats["closed"] += 1
        except Exception:                     # noqa: BLE001 — o sesiune ciudată nu opreşte sweep-ul
            log.exception("idle-session sweep: session %s skipped", sid)
    return stats
