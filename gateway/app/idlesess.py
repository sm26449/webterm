"""Igiena sesiunilor inactive (3.7.1): NOTIFICARE după N zile nefolosite. Nimic nu se închide automat.

Decizia proprietarului (2026-11-22): 3.7.1 livrează doar notificarea. Închiderea automată cere o garanţie
pe partea agentului (închidere condiţionată, atomică, în tmux) care nu e gata; designul şi codul sunt
păstrate pe ramura `feat/agent62-autoclose`, pentru 3.8. Până atunci:
  * `AUTOCLOSE_AVAILABLE = False`: politica nu poate porni închiderea (`sanitize` o forţează oprită,
    inclusiv un `autoclose: true` rămas în DB de la un rc), ruta refuză cu 400, sweep-ul nu trimite
    niciodată un kill, iar notificările nu poartă nicio dată de închidere;
  * „inactivă" = fără input, fără output ŞI fără niciun client ataşat pe toată perioada. Un `tail -f`
    sau un build care scrie nu e niciodată inactiv;
  * notificarea merge proprietarului sesiunii (`created_by_id`); sesiunile fără proprietar → cei cu
    `session.manage` pe host. Terminalele root de pe gateway (ROOT_TERMINAL_ORIGINS): doar proprietarul;
  * o notificare pe perioadă de inactivitate: prima folosire o anulează (hub-ul, imediat), iar o nouă
    perioadă de N zile aduce o notificare nouă. „Păstrează deschisă" opreşte notificările.

Fail-closed: orice lucru necunoscut (fără hub, hub neataşat, host offline, transcript ilizibil, nimeni
de anunţat, o eroare) = nicio notificare. Notificarea se scrie AŞTEPTAT în aplicaţie: dacă scrierea
eşuează, rândul sesiunii nu rămâne marcat „notificat" şi se reîncearcă după un backoff.
"""
import asyncio
import json
import logging
import time
from typing import Optional

from . import authz, core, db, email_alerts, sessctl

log = logging.getLogger("webterm")

# INV-13 (docs/design/INVARIANTS.md): în 3.7.1 nicio sesiune nu se închide automat — doar notificare.
AUTOCLOSE_AVAILABLE = False

SETTING_KEY = "idle_sessions"
DAY = 86400.0
DEFAULTS = {"notify": True, "notify_days": 7, "autoclose": False}
NOTIFY_DAYS = (1, 90)
SWEEP_INTERVAL = 600.0           # şi cadenţa cu care se persistă `last_active` (~10 min)
SWEEP_STARTUP_GRACE = 600.0      # după pornire: reconcilierea agenţilor re-ataşează hub-urile întâi
SWEEP_BUDGET = 120.0             # secunde de lucru pe ciclu (restul la următorul, de unde a rămas)
MAX_ROWS = 2000                  # sesiuni vii citite pe sweep (plafon de lucru; cursorul se roteşte)
MAX_ACTIONS = 20                 # notificări pe sweep (restul la următorul)
MAX_RECIPIENT_SCAN = 500         # conturi verificate pentru `session.manage` (sesiune fără proprietar)
BACKOFF_FAILED = 3600.0          # după o notificare care nu s-a putut scrie
BACKOFF_NO_RECIPIENT = 6 * 3600.0
_CACHE_TTL = 30.0

# `ver` creşte la fiecare salvare: o citire din DB pornită ÎNAINTE de o salvare nu suprascrie memoria
_state: dict = {"policy": dict(DEFAULTS), "at": 0.0, "loaded": False, "ver": 0}
_save_lock = asyncio.Lock()
_cursor: dict = {"start": ""}    # primul sid de la care citeşte următorul sweep (rotaţie)
_backoff: dict = {}              # sid → time.monotonic() până la care nu mai încercăm o notificare


def _clamp(v, lo, hi, default) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def sanitize(raw) -> dict:
    """Politica stocată → valori sigure. Orice lucru necitibil cade pe implicit."""
    d = raw if isinstance(raw, dict) else {}
    return {
        # notificarea e inofensivă: doar un `false` explicit o opreşte
        "notify": d.get("notify") is not False,
        "notify_days": _clamp(d.get("notify_days"), *NOTIFY_DAYS, DEFAULTS["notify_days"]),
        # INV-13 (docs/design/INVARIANTS.md): închiderea nu e disponibilă în 3.7.1 — un `true` stocat
        # (DB de la un rc 3.7.1) se citeşte OPRIT; doar un `true` explicit ar conta când va exista
        "autoclose": AUTOCLOSE_AVAILABLE and d.get("autoclose") is True,
    }


def current_policy() -> dict:
    """Politica din memorie, SINCRON."""
    return dict(_state["policy"])


async def load_policy(fresh: bool = False) -> dict:
    now = time.time()
    if not fresh and _state["loaded"] and now - _state["at"] < _CACHE_TTL:
        return current_policy()
    ver = _state["ver"]
    try:
        raw = json.loads(await db.get_setting(SETTING_KEY, "") or "{}")
    except ValueError:
        raw = {}
    pol = sanitize(raw)
    if _state["ver"] == ver:
        # nicio salvare cât citeam; altfel memoria (scrisă de `save_policy`) câştigă
        _state.update(policy=pol, at=now, loaded=True)
    return current_policy()


def _publish(pol: dict) -> None:
    _state["ver"] += 1
    _state.update(policy=dict(pol), at=time.time(), loaded=True)


async def save_policy(pol: dict) -> dict:
    """Salvează politica (după `sanitize`: închiderea rămâne oprită). O oprire a notificărilor are
    efect imediat în memorie, chiar dacă scrierea în DB eşuează; o pornire, doar după scriere."""
    async with _save_lock:
        prev = await load_policy(fresh=True)
        new = sanitize(pol)
        _publish(dict(new, notify=new["notify"] and prev["notify"]))
        await db.set_setting(SETTING_KEY, json.dumps(new))
        _publish(new)
        return dict(new)


def _row_get(row, key):
    return row[key] if key in row.keys() else None


def notice_json(row, pol: dict) -> Optional[dict]:
    """Ce vede UI-ul despre notificarea unei sesiuni (lista de sesiuni): None = nicio notificare.
    Nicio dată de închidere: în 3.7.1 nimic nu se închide automat."""
    at = _row_get(row, "idle_notified_at")
    if not at or row["state"] != "live":
        return None
    return {"at": at, "days": pol["notify_days"]}


async def set_keep_open(sid: str, keep: bool) -> None:
    """„Păstrează deschisă": fără notificări de inactivitate; anulează şi o notificare în curs."""
    hub = core.hubs.get(sid)
    if hub is not None and keep:
        hub.idle_pending = False
        hub.keep_open = True
    await db.execute("UPDATE sessions SET keep_open=?, idle_notified_at=NULL WHERE id=?", 1 if keep else 0, sid)
    if hub is not None:
        hub.idle_pending = False
        hub.keep_open = bool(keep)


def _transcript_mtime(sid: str) -> Optional[float]:
    try:
        return core.transcript_paths(sid)[0].stat().st_mtime
    except (OSError, ValueError):
        return None


async def last_activity(row, hub) -> Optional[float]:
    """Ultima folosire cunoscută a sesiunii, sau None = nu ştim (→ nu facem nimic). Sursele: hub-ul
    (output/input/prezenţă în memorie), `last_active` persistat (supravieţuieşte restartului),
    mtime-ul transcriptului (orice output scris vreodată; citit pe un thread, nu în loop), crearea."""
    if hub is None:
        return None
    if hub.clients:
        return time.time()
    mt = await asyncio.to_thread(_transcript_mtime, row["id"])
    if mt is None:
        return None                           # transcript ilizibil: nu putem dovedi inactivitatea
    if hub.clients:                           # s-a ataşat cineva cât citeam
        return time.time()
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


def _backoff_set(sid: str, secs: float) -> None:
    _backoff[sid] = time.monotonic() + secs


def _backed_off(sid: str) -> bool:
    until = _backoff.get(sid)
    if until is None:
        return False
    if time.monotonic() >= until:
        _backoff.pop(sid, None)
        return False
    return True


async def _notify(row, hub, pol: dict, uids: list, now: float) -> bool:
    sid = row["id"]
    # 1) revendicăm notificarea, condiţionat: o sesiune marcată Keep / închisă / deja notificată între
    #    citire şi acum nu se atinge
    won = await db.execute_returning(
        "UPDATE sessions SET idle_notified_at=? WHERE id=? AND state='live' AND COALESCE(keep_open, 0)=0"
        " AND idle_notified_at IS NULL RETURNING id", now, sid)
    if won is None:
        return False
    hub.idle_pending = True                   # prima activitate de acum încolo anulează notificarea
    # 2) notificarea în aplicaţie, AŞTEPTATĂ: o scriere eşuată nu lasă sesiunea marcată „notificată"
    #    (altfel nu s-ar mai reîncerca niciodată în perioada asta)
    try:
        host = await _host_name(row["host_id"])
        # toţi destinatarii într-o singură alertă (un singur email/webhook pentru toţi)
        await email_alerts.notify_session_idle(
            list(uids), row["title"] or "", host, row["host_id"], sid, pol["notify_days"], ts=now)
    except Exception as e:                    # noqa: BLE001 — notificarea nu s-a scris: reîncercăm mai târziu
        log.warning("idle notice for session %s not recorded: %s", sid, e)
        hub.idle_pending = False
        await db.execute("UPDATE sessions SET idle_notified_at=NULL WHERE id=? AND idle_notified_at=?", sid, now)
        _backoff_set(sid, BACKOFF_FAILED)
        return False
    return True


async def _rows() -> list:
    """Fereastra de lucru: până la MAX_ROWS sesiuni vii, începând de la cursor şi continuând de la
    început (rotaţie) — peste plafon, fiecare sesiune ajunge la rând."""
    start = _cursor["start"]
    rows = list(await db.fetchall("SELECT * FROM sessions WHERE state='live' AND id >= ? ORDER BY id LIMIT ?",
                                  start, MAX_ROWS))
    if start and len(rows) < MAX_ROWS:
        rows += list(await db.fetchall("SELECT * FROM sessions WHERE state='live' AND id < ? ORDER BY id"
                                       " LIMIT ?", start, MAX_ROWS - len(rows)))
    return rows


# INV-13 (docs/design/INVARIANTS.md): sweep-ul doar notifică; nu trimite niciodată un kill.
async def sweep(now: Optional[float] = None) -> dict:
    """Un ciclu: persistă activitatea hub-urilor, anulează notificările sesiunilor folosite între timp şi
    notifică sesiunile nefolosite de `notify_days` zile. Întoarce contoarele (pentru teste/jurnal)."""
    pol = await load_policy(fresh=True)
    now = time.time() if now is None else now
    t_end = time.monotonic() + SWEEP_BUDGET
    stats = {"notified": 0, "cleared": 0}
    actions = 0
    rows = await _rows()
    resume = None                             # primul sid care a rămas fără buget → următorul sweep
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
            last = await last_activity(row, hub)
            if last is None:
                continue
            notified = row["idle_notified_at"]
            if notified and (hub.clients or last > float(notified)):
                # folosită după notificare: anulăm (dacă hub-ul n-a făcut-o deja)
                await db.execute("UPDATE sessions SET idle_notified_at=NULL WHERE id=? AND idle_notified_at=?",
                                 sid, notified)
                hub.idle_pending = False
                stats["cleared"] += 1
                continue
            if notified or hub.clients or not pol["notify"]:
                continue                      # o singură notificare pe perioadă de inactivitate
            if now - last < pol["notify_days"] * DAY:
                continue
            if _backed_off(sid):
                continue
            if actions >= MAX_ACTIONS or time.monotonic() >= t_end:
                if resume is None:
                    resume = sid
                if time.monotonic() >= t_end:
                    break
                continue
            actions += 1                      # căutarea destinatarilor costă şi ea: în buget
            uids = await recipients(row)
            if not uids:
                _backoff_set(sid, BACKOFF_NO_RECIPIENT)
                continue                      # nimeni de avertizat → nimic
            if await _notify(row, hub, pol, uids, now):
                stats["notified"] += 1
        except Exception:                     # noqa: BLE001 — o sesiune ciudată nu opreşte sweep-ul
            log.exception("idle-session sweep: session %s skipped", sid)
            _backoff_set(sid, BACKOFF_FAILED)
    if resume is not None:
        _cursor["start"] = resume
    elif len(rows) >= MAX_ROWS:
        _cursor["start"] = rows[-1]["id"]     # fereastra plină: următorul sweep continuă de aici
    if len(_backoff) > 4 * MAX_ROWS:          # sesiuni închise de mult: curăţăm intrările expirate
        for k in [k for k, v in _backoff.items() if v <= time.monotonic()]:
            _backoff.pop(k, None)
    return stats
