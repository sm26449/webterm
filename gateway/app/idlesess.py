"""Igiena sesiunilor inactive (3.7.1): notificare după N zile nefolosite, închidere automată opţională.

Decizia proprietarului (2026-11-21):
  * „inactivă" = fără input, fără output ŞI fără niciun client ataşat pe toată perioada. Un `tail -f`
    sau un build care scrie nu e niciodată inactiv; o comandă tăcută zile întregi pare inactivă —
    pentru ea există notificarea şi „Păstrează deschisă";
  * implicit: notificarea PORNITĂ (7 zile), închiderea automată OPRITĂ până o porneşte un Owner/Admin
    pentru instanţă; închiderea vine la `grace_days` (2) după notificare;
  * notificarea merge proprietarului sesiunii (`created_by_id`); sesiunile fără proprietar → cei cu
    `session.manage` pe host. Terminalele root de pe gateway (ROOT_TERMINAL_ORIGINS): doar proprietarul;
  * închiderea foloseşte calea sursei (ca butonul Stop): tmux omorât pe host, transcript păstrat, hub
    curăţat de `on_exit`, plus un rând de audit „system:idle-sessions".

Fail-closed (ce NU închide niciodată): orice eroare, o sesiune al cărei flux nu-l vedem (fără hub,
hub neataşat la sursă, replay neterminat, ataşat de prea puţin timp, host offline), un client ataşat,
„Păstrează deschisă", o sesiune fără destinatar, o notificare care nu s-a putut ÎNREGISTRA (nimeni n-a
fost avertizat dovedit), o notificare trimisă cât închiderea era oprită sau sub o generaţie mai veche a
politicii, activitate după notificare, o grație care n-a trecut şi pe ceasul monoton al procesului.

Auditul Codex 3.7.1 (constatările 1–3, 5, 6, 8):
  * notificarea se scrie în aplicaţie AŞTEPTAT, înainte de termen; termenul se fixează doar după o
    scriere reuşită, iar la închidere se caută rândul acela (dovada) pentru un destinatar curent;
  * politica are o generaţie, actualizată în memorie ÎNAINTE de scrierea în DB; termenul o poartă, iar
    ultima verificare (sincronă, fără await până la trimiterea kill-ului) citeşte politica din memorie;
  * `hub.idle_closing` se pune sincron înainte de kill; ataşările îl văd şi refuză;
  * răspunsul agentului se verifică, iar succesul (audit 200, alerta „închisă") vine doar după `on_exit`;
  * cursor rotativ, backoff per sesiune, buget de timp pe ciclu, `stat()` pe thread.

Reziduul #3 (agentul 62): între ultima verificare şi momentul în care agentul execută kill-ul pot apărea
output, input sau un om ataşat direct la tmux pe host — gateway-ul nu le vede. De aceea închiderea
merge prin op-ul CONDIŢIONAT `kill_if_quiet`: gateway-ul spune cât timp n-a văzut nimic, iar agentul
refuză (`active`) dacă el are dovezi de activitate în fereastra aceea. Doar sesiunile unui agent ≥ 62 pot
fi închise automat; agenţii mai vechi, SSH, telnet şi serial primesc doar notificarea (fără termen).
"""
import asyncio
import json
import logging
import time
from typing import Optional

from . import audit, authz, bgtasks, core, db, email_alerts, sessctl

log = logging.getLogger("webterm")

SETTING_KEY = "idle_sessions"
DAY = 86400.0
DEFAULTS = {"notify": True, "notify_days": 7, "autoclose": False, "grace_days": 2, "gen": 0}
NOTIFY_DAYS = (1, 90)
GRACE_DAYS = (1, 30)
SWEEP_INTERVAL = 600.0           # şi cadenţa cu care se persistă `last_active` (~10 min)
SWEEP_STARTUP_GRACE = 600.0      # după pornire: reconcilierea agenţilor re-ataşează hub-urile întâi
SWEEP_BUDGET = 120.0             # secunde de lucru pe ciclu (restul la următorul, de unde a rămas)
MAX_ROWS = 2000                  # sesiuni vii citite pe sweep (plafon de lucru; cursorul se roteşte)
MAX_ACTIONS = 20                 # notificări + închideri pe sweep (restul la următorul)
MAX_RECIPIENT_SCAN = 500         # conturi verificate pentru `session.manage` (sesiune fără proprietar)
MIN_ATTACHED = 600.0             # hub ataşat la sursa curentă de ≥10 min: output-ul din întrerupere a sosit
CLOSE_CONFIRM = 30.0             # cât aşteptăm `on_exit` după kill (pe un task, nu în sweep)
BACKOFF_FAILED = 3600.0          # după un kill eşuat / neconfirmat / o notificare neînregistrată
BACKOFF_NO_RECIPIENT = 6 * 3600.0
_CACHE_TTL = 30.0

# `ver` creşte la fiecare salvare: o citire din DB pornită ÎNAINTE de o salvare nu suprascrie memoria
_state: dict = {"policy": dict(DEFAULTS), "at": 0.0, "loaded": False, "ver": 0}
_save_lock = asyncio.Lock()
_cursor: dict = {"start": ""}    # primul sid de la care citeşte următorul sweep (rotaţie)
_backoff: dict = {}              # sid → time.monotonic() până la care nu mai încercăm o acţiune


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
        "gen": _clamp(d.get("gen"), 0, 2 ** 53, 0),
    }


def current_policy() -> dict:
    """Politica din memorie, SINCRON (ultima verificare dinaintea kill-ului nu are voie la await)."""
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
    # o oprire salvată în memorie dar nescrisă în DB (scrierea a eşuat) rămâne în vigoare până la o
    # salvare reuşită (re-review 3.7.1: altfel sweep-ul următor reînvia termenele vechi)
    ov = _state.get("strict")
    if ov:
        pol = dict(pol, autoclose=pol["autoclose"] and ov["autoclose"], notify=pol["notify"] and ov["notify"],
                   gen=max(pol["gen"], ov["gen"]))
    if _state["ver"] == ver:
        # nicio salvare cât citeam; altfel memoria (scrisă de `save_policy` înaintea DB-ului) câştigă
        _state.update(policy=pol, at=now, loaded=True)
    return current_policy()


def _publish(pol: dict) -> None:
    _state["ver"] += 1
    _state.update(policy=dict(pol), at=time.time(), loaded=True)


async def save_policy(pol: dict, reauth=None) -> dict:
    """Salvează politica. Ordinea contează (auditul Codex 3.7.1, constatarea 2): MEMORIA întâi, în
    varianta strictă — o oprire (închidere sau notificare) are efect imediat, inclusiv pe un sweep în
    zbor; o pornire devine efectivă abia după ce s-a scris în DB. Orice comutare a închiderii sau a
    notificării măreşte generaţia: termenele fixate sub generaţia veche nu mai închid nimic."""
    async with _save_lock:
        prev = await load_policy(fresh=True)
        new = sanitize(pol)
        switched = new["autoclose"] != prev["autoclose"] or new["notify"] != prev["notify"]
        new["gen"] = prev["gen"] + 1 if switched else prev["gen"]
        if new["autoclose"] and not prev["autoclose"]:
            # re-review 3.7.1: decizia „cere re-autentificare" se ia AICI, sub lacăt, faţă de starea
            # reală (o cerere care citise „pornit" înaintea unei opriri concurente nu mai sare peste ea)
            if reauth is None:
                raise PermissionError("enabling automatic closing needs a fresh re-authentication")
            await reauth()
        strict = dict(new, autoclose=new["autoclose"] and prev["autoclose"], notify=new["notify"] and prev["notify"])
        _state["strict"] = strict
        _publish(strict)
        if new["autoclose"] and not prev["autoclose"]:
            # Review 3.7.1: oprit apoi repornit, un termen vechi (deja trecut) închidea sesiunea în 10
            # minute, deşi omul văzuse ultima dată „nimic programat". Generaţia o împiedică deja;
            # ştergem şi termenele, ca lista de sesiuni să nu mai arate nimic programat.
            await db.execute("UPDATE sessions SET idle_close_after=NULL, idle_close_gen=NULL"
                             " WHERE idle_close_after IS NOT NULL")
        await db.set_setting(SETTING_KEY, json.dumps(new))
        _state["strict"] = None
        _publish(new)
        return dict(new)


def _row_get(row, key):
    return row[key] if key in row.keys() else None


def notice_json(row, pol: dict) -> Optional[dict]:
    """Ce vede UI-ul despre notificarea unei sesiuni (lista de sesiuni): None = nicio notificare."""
    at = _row_get(row, "idle_notified_at")
    if not at or row["state"] != "live":
        return None
    close_at = close_deadline(row, pol)
    return {"at": at, "days": pol["notify_days"], "close_at": close_at}


def close_deadline(row, pol: dict) -> Optional[float]:
    """Momentul închiderii automate, sau None dacă nu e programată: închiderea trebuie să fie pornită
    ACUM, să fi fost pornită la notificare (`idle_close_after` fixat atunci) ŞI sub aceeaşi generaţie a
    politicii. O grație mărită între timp amână termenul; una micşorată nu-l aduce mai aproape."""
    if not pol["autoclose"] or not pol["notify"]:
        return None                           # funcţia oprită = nimic programat
    at = _row_get(row, "idle_notified_at")
    after = _row_get(row, "idle_close_after")
    gen = _row_get(row, "idle_close_gen")
    if not at or not after or gen is None or int(gen) != pol["gen"]:
        return None
    return max(float(after), float(at) + pol["grace_days"] * DAY)


async def set_keep_open(sid: str, keep: bool) -> None:
    """„Păstrează deschisă": anulează şi o notificare/închidere în curs. Memoria ÎNTÂI, sincron (re-review
    3.7.1): o închidere aflată între citirea rândului şi ultima verificare trebuie să vadă Keep, altfel
    utilizatorul primea „păstrată" iar sesiunea se închidea oricum."""
    hub = core.hubs.get(sid)
    if hub is not None and keep:
        hub.idle_pending = False
        hub.idle_notice_seen = None
        hub.keep_open = True
    await db.execute("UPDATE sessions SET keep_open=?, idle_notified_at=NULL, idle_close_after=NULL,"
                     " idle_close_gen=NULL WHERE id=?", 1 if keep else 0, sid)
    if hub is not None:
        hub.idle_pending = False
        hub.idle_notice_seen = None
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


def _observe_notice(hub, notified: float, mono: float) -> None:
    """Momentul (monoton) în care ACEST proces a văzut notificarea. După un restart / un hub nou /
    un restore, grația reîncepe de la prima observare — omul a fost anunţat, doar închiderea e mai
    târziu. Un salt înainte al ceasului de perete nu scurtează nimic."""
    seen = getattr(hub, "idle_notice_seen", None)
    if seen is None or seen[0] != notified:
        hub.idle_notice_seen = (notified, mono)


def _mono_grace_ok(hub, notified: float, deadline: float, mono: float) -> bool:
    seen = getattr(hub, "idle_notice_seen", None)
    return seen is not None and seen[0] == notified and mono - seen[1] >= deadline - notified


def closing_source(row):
    """Sursa prin care sesiunea poate fi închisă CONDIŢIONAT (AgentConnection, agent ≥ 62), sau None.
    SINCRON (folosită şi în ultima verificare dinaintea kill-ului). Orice altă sursă — agent mai vechi,
    SSH, telnet, serial, host offline — nu poate dovedi că sesiunea e încă liniştită: doar notificare."""
    source = core.session_sources.get(row["id"]) or core.source_for(row["host_id"])
    if isinstance(source, core.AgentConnection) and source.can_kill_if_quiet():
        return source
    return None


def _source_settled(hub, mono: float) -> bool:
    """Fluxul sesiunii e la zi: replay-ul ataşării curente s-a terminat şi hub-ul e ataşat la sursa
    curentă de cel puţin MIN_ATTACHED (output-ul produs cât agentul era deconectat a sosit)."""
    at = getattr(hub, "attached_mono", None)
    return hub.replay_settled() and at is not None and mono - at >= MIN_ATTACHED


async def _notify(row, hub, pol: dict, uids: list, now: float, mono: float) -> bool:
    sid = row["id"]
    # notificarea promite o închidere doar dacă sursa o poate face condiţionat (agent ≥ 62)
    closing = pol["autoclose"] and closing_source(row) is not None
    # 1) revendicăm notificarea, FĂRĂ termen (nimic programat încă). Condiţionat: o sesiune marcată
    #    Keep / închisă / deja notificată valid între citire şi acum nu se atinge.
    won = await db.execute_returning(
        "UPDATE sessions SET idle_notified_at=?, idle_close_after=NULL, idle_close_gen=NULL"
        " WHERE id=? AND state='live' AND COALESCE(keep_open, 0)=0"
        " AND (idle_notified_at IS NULL OR idle_close_after IS NULL OR COALESCE(idle_close_gen, -1)<>?)"
        " RETURNING id", now, sid, pol["gen"])
    if won is None:
        return False
    hub.idle_pending = True                   # prima activitate de acum încolo anulează notificarea
    # 2) notificarea în aplicaţie, AŞTEPTATĂ (auditul Codex 3.7.1, constatarea 1): fără un rând scris
    #    pentru un destinatar eligibil nu există notificare şi deci nici termen
    try:
        host = await _host_name(row["host_id"])
        # toţi destinatarii într-o singură alertă (review 3.7.1: câte un email identic per cont)
        recorded = await email_alerts.notify_session_idle(
            list(uids), row["title"] or "", host, row["host_id"], sid, pol["notify_days"],
            pol["grace_days"] if closing else 0, ts=now)
    except Exception as e:                    # noqa: BLE001 — fără dovadă: nimic programat
        log.warning("idle notice for session %s not recorded: %s", sid, e)
        recorded = []
    if not recorded:
        hub.idle_pending = False
        await db.execute("UPDATE sessions SET idle_notified_at=NULL WHERE id=? AND idle_notified_at=?"
                         " AND idle_close_after IS NULL", sid, now)
        _backoff_set(sid, BACKOFF_FAILED)
        return False
    _observe_notice(hub, now, mono)
    if closing:
        # 3) termenul, sub generaţia cu care a plecat notificarea — doar dacă politica n-a fost
        #    schimbată între timp (altfel notificarea rămâne una fără închidere)
        cur = current_policy()
        if cur["autoclose"] and cur["notify"] and cur["gen"] == pol["gen"]:
            await db.execute(
                "UPDATE sessions SET idle_close_after=?, idle_close_gen=? WHERE id=? AND idle_notified_at=?"
                " AND state='live' AND COALESCE(keep_open, 0)=0",
                now + pol["grace_days"] * DAY, pol["gen"], sid, now)
    return True


async def _notice_recorded(sid: str, notified: float, uids: list) -> bool:
    """Există, pentru un destinatar CURENT, rândul de alertă care a anunţat închiderea?"""
    if not uids:
        return False
    r = await db.fetchone(
        "SELECT 1 FROM alerts WHERE kind='session_idle' AND msg_key='session_idle_close' AND ts=?"
        " AND msg_params LIKE ? AND user_id IN (%s) LIMIT 1" % ",".join("?" * len(uids)),
        float(notified), '%%"sid":"%s"%%' % sid, *[int(u) for u in uids])
    return r is not None


def _closable_now(fresh, hub, pol: dict, now: float, mono: float) -> bool:
    """Ultima verificare, SINCRONĂ (fără await între ea, `idle_closing` şi trimiterea kill-ului)."""
    deadline = close_deadline(fresh, pol)
    notified = fresh["idle_notified_at"]
    if deadline is None or not notified or now < deadline:
        return False
    if hub.closed or not hub.attached or hub.clients or not hub.idle_pending or hub.idle_closing:
        return False
    if getattr(hub, "keep_open", False) or _row_get(fresh, "keep_open"):
        return False
    if hub.activity_at() > float(notified):
        return False
    return _source_settled(hub, mono) and _mono_grace_ok(hub, float(notified), deadline, mono)


# INV-13 (docs/design/INVARIANTS.md): închiderea automată nu atinge o sesiune folosită, păstrată sau neanunţată.
async def _close(row, hub, uids: list, now: float, mono: float) -> str:
    """'closed' (confirmat de `on_exit`), 'pending' (trimis, confirmarea pe un task), 'active' (agentul a
    văzut activitate: notificarea anulată), 'failed', 'skip'."""
    sid = row["id"]
    fresh = await db.fetchone("SELECT * FROM sessions WHERE id=?", sid)
    if fresh is None or fresh["state"] != "live" or fresh["keep_open"]:
        return "skip"
    notified = fresh["idle_notified_at"]
    if not notified or notified != row["idle_notified_at"]:
        return "skip"
    if not await _notice_recorded(sid, float(notified), uids):
        # niciun destinatar curent n-a fost anunţat dovedit: nimic închis; următorul sweep trimite o
        # notificare nouă, cu grație nouă
        log.info("idle session %s: no recorded notice for a current recipient; not closing", sid)
        await db.execute("UPDATE sessions SET idle_close_after=NULL, idle_close_gen=NULL"
                         " WHERE id=? AND idle_notified_at=?", sid, notified)
        return "skip"
    # Sursa se ia SINCRON şi verificările se refac chiar înainte de kill, fără niciun await între ele
    # (review 3.7.1: un browser care se ataşa într-un await îşi vedea sesiunea închisă imediat după).
    if core.session_sources.get(sid) is None and core.source_for(row["host_id"]) is None:
        return "skip"                         # host offline: altă dată
    source = closing_source(row)
    if source is None:
        # agentul a fost înlocuit cu unul care nu ştie `kill_if_quiet` (sau sesiunea nu e pe agent):
        # termenul dispare, UI-ul nu mai promite închiderea; notificarea rămâne
        await db.execute("UPDATE sessions SET idle_close_after=NULL, idle_close_gen=NULL"
                         " WHERE id=? AND idle_notified_at=?", sid, notified)
        return "skip"
    if not _closable_now(fresh, hub, current_policy(), now, mono):
        return "skip"
    # cât n-a văzut ACEST gateway nimic: ceasul de perete (ultima activitate) şi, ca plasă la un salt
    # înapoi al ceasului, timpul monoton de când procesul a văzut notificarea (orice folosire de atunci
    # ar fi anulat-o). Maximul e cererea MAI strictă către agent (fereastra lui de verificare e mai lungă).
    seen = getattr(hub, "idle_notice_seen", None)
    quiet = max(now - hub.activity_at(), (mono - seen[1]) if seen else 0.0, 0.0)
    hub.idle_closing = True                   # din acest moment ataşările sunt refuzate (api [ws])
    hub.exit_reason = "idle"
    why = ""
    resp: dict = {}
    try:
        resp = await source.kill_if_quiet(sid, quiet)
        if not resp.get("ok"):
            why = str(resp.get("code") or resp.get("msg") or "refused")[:60]
    except Exception as e:                    # noqa: BLE001 — host plecat, timeout: rezultat necunoscut
        why = type(e).__name__
    if why == "active":
        await _host_active(row, hub, now, notified, str(resp.get("msg") or "")[:60])
        return "active"
    if why:
        await _unconfirmed(row, hub, now, why)
        return "failed"
    if hub.closed and await _closed_as_idle(sid):
        await _confirmed(row, fresh, uids, now)
        return "closed"
    bgtasks.spawn(_await_exit(row, fresh, hub, uids, now), "confirm idle close")
    return "pending"


async def _host_active(row, hub, now: float, notified, detail: str) -> None:
    """Agentul a refuzat: a văzut activitate pe care gateway-ul n-a văzut-o. E folosire: notificarea se
    anulează, o perioadă nouă de inactivitate începe ACUM (fără alertă — nu s-a închis nimic)."""
    sid = row["id"]
    hub.idle_closing = False
    hub.exit_reason = "exited"
    hub.idle_pending = False
    hub.idle_notice_seen = None
    hub.last_host_activity_at = time.time()
    await db.execute("UPDATE sessions SET idle_notified_at=NULL, idle_close_after=NULL, idle_close_gen=NULL,"
                     " last_active=MAX(COALESCE(last_active, 0), ?) WHERE id=? AND idle_notified_at=?",
                     hub.last_host_activity_at, sid, notified)
    log.info("idle session %s not closed: activity on the host (%s)", sid, detail or "active")
    await audit.record(now, "system:idle-sessions", "-", "IDLE", "/api/sessions/%s/kill" % sid, 409,
                       ("idle close of \"%s\" skipped: activity on the host%s"
                        % (row["title"] or "", " (%s)" % detail if detail else ""))[:480],
                       host_id=row["host_id"])


async def _await_exit(row, fresh, hub, uids: list, now: float) -> None:
    """Confirmarea: `on_exit` (hub închis) în cel mult CLOSE_CONFIRM secunde; altfel „neconfirmat"."""
    t_end = time.monotonic() + CLOSE_CONFIRM
    while not hub.closed and time.monotonic() < t_end:
        await asyncio.sleep(0.5)
    if hub.closed and await _closed_as_idle(row["id"]):
        await _confirmed(row, fresh, uids, now)
    else:
        await _unconfirmed(row, hub, now, "no exit within %ds" % int(CLOSE_CONFIRM) if not hub.closed
                           else "the session ended for another reason")


async def _closed_as_idle(sid: str) -> bool:
    """Re-review 3.7.1: orice `hub.closed` (pierdută, host şters, ieşire naturală în fereastră) nu e o
    închidere de inactivitate; doar rândul închis cu motivul `idle` o confirmă."""
    r = await db.fetchone("SELECT state, close_reason FROM sessions WHERE id=?", sid)
    return bool(r) and r["state"] == "closed" and (r["close_reason"] or "") == "idle"


async def _unconfirmed(row, hub, now: float, why: str) -> None:
    sid = row["id"]
    if not hub.closed:
        hub.exit_reason = "exited"
    hub.idle_closing = False
    # fără reîncercare până când reconcilierea arată starea reală (heartbeat-ul agentului o face la
    # zeci de secunde; backoff-ul e mult mai lung)
    _backoff_set(sid, BACKOFF_FAILED)
    log.info("idle session %s not closed: %s", sid, why)
    # rezultatul e necunoscut (agentul poate să fi închis-o totuşi): urmă în audit, ca o închidere
    # survenită după timeout să nu rămână fără explicaţie
    await audit.record(now, "system:idle-sessions", "-", "IDLE", "/api/sessions/%s/kill" % sid, 504,
                       ("idle close of \"%s\" not confirmed (%s); the session may still be open"
                        % (row["title"] or "", why))[:480], host_id=row["host_id"])


async def _confirmed(row, fresh, uids: list, now: float) -> None:
    sid = row["id"]
    _backoff.pop(sid, None)
    pol = current_policy()
    idle_days = int((now - float(fresh["idle_notified_at"])) / DAY) + pol["notify_days"]
    grace = int(round((now - float(fresh["idle_notified_at"])) / DAY))
    host = await _host_name(row["host_id"])
    await audit.record(now, "system:idle-sessions", "-", "IDLE", "/api/sessions/%s/kill" % sid, 200,
                       ("closed idle session \"%s\" (unused for about %d days, notice sent %d day(s) "
                        "earlier)" % (row["title"] or "", idle_days, grace))[:480],
                       host_id=row["host_id"])
    email_alerts.notify_session_idle_closed(list(uids), row["title"] or "", host, row["host_id"], sid, idle_days)


async def _rows() -> list:
    """Fereastra de lucru: până la MAX_ROWS sesiuni vii, începând de la cursor şi continuând de la
    început (rotaţie) — peste plafon, fiecare sesiune ajunge la rând (auditul Codex 3.7.1, constatarea 8)."""
    start = _cursor["start"]
    rows = list(await db.fetchall("SELECT * FROM sessions WHERE state='live' AND id >= ? ORDER BY id LIMIT ?",
                                  start, MAX_ROWS))
    if start and len(rows) < MAX_ROWS:
        rows += list(await db.fetchall("SELECT * FROM sessions WHERE state='live' AND id < ? ORDER BY id"
                                       " LIMIT ?", start, MAX_ROWS - len(rows)))
    return rows


async def sweep(now: Optional[float] = None, mono: Optional[float] = None) -> dict:
    """Un ciclu: persistă activitatea hub-urilor, notifică sesiunile inactive, închide (dacă e pornit)
    pe cele notificate, nefolosite de atunci, după grație. Întoarce contoarele (pentru teste/jurnal).
    `now` = ceasul de perete (termenele din DB), `mono` = ceasul monoton al procesului (grația văzută)."""
    pol = await load_policy(fresh=True)
    now = time.time() if now is None else now
    mono = time.monotonic() if mono is None else mono
    t_end = time.monotonic() + SWEEP_BUDGET
    stats = {"notified": 0, "closed": 0, "cleared": 0, "pending": 0}
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
            if getattr(hub, "idle_closing", False):
                continue                      # un kill în zbor: confirmarea vine pe taskul ei
            last = await last_activity(row, hub)
            if last is None:
                continue
            notified = row["idle_notified_at"]
            if notified and (hub.clients or last > float(notified)):
                # folosită după notificare: anulăm (dacă hub-ul n-a făcut-o deja)
                await db.execute("UPDATE sessions SET idle_notified_at=NULL, idle_close_after=NULL,"
                                 " idle_close_gen=NULL WHERE id=? AND idle_notified_at=?", sid, notified)
                hub.idle_pending = False
                hub.idle_notice_seen = None
                stats["cleared"] += 1
                continue
            if notified:
                _observe_notice(hub, float(notified), mono)
            if hub.clients or not pol["notify"]:
                continue
            idle_for = now - last
            if idle_for < pol["notify_days"] * DAY:
                continue
            deadline = close_deadline(row, pol)
            # notificare: prima, sau una nouă („se va închide…") când închiderea e pornită şi termenul
            # lipseşte / e dintr-o generaţie mai veche a politicii
            # (o sesiune care nu poate fi închisă condiţionat — agent < 62, SSH, telnet, serial — rămâne cu
            # notificarea simplă; altfel ar primi una nouă la fiecare sweep)
            wants_notice = not notified or (pol["autoclose"] and deadline is None
                                            and closing_source(row) is not None)
            if not wants_notice:
                if deadline is None or now < deadline:
                    continue
                if idle_for < pol["notify_days"] * DAY + (deadline - float(notified)):
                    continue                  # perioada întreagă (prag + grație) fără nicio folosire
                if not _mono_grace_ok(hub, float(notified), deadline, mono) or not _source_settled(hub, mono):
                    continue                  # grația n-a trecut şi pe ceasul procesului / flux nesigur
            if _backed_off(sid):
                continue
            if actions >= MAX_ACTIONS or time.monotonic() >= t_end:
                if resume is None:
                    resume = sid
                if time.monotonic() >= t_end:
                    break
                continue
            actions += 1                      # căutarea destinatarilor costă şi ea (review 3.7.1): în buget
            uids = await recipients(row)
            if not uids:
                _backoff_set(sid, BACKOFF_NO_RECIPIENT)
                continue                      # nimeni de avertizat → nimic programat, nimic închis
            if wants_notice:
                if await _notify(row, hub, pol, uids, now, mono):
                    stats["notified"] += 1
                continue
            r = await _close(row, hub, uids, now, mono)
            if r == "closed":
                stats["closed"] += 1
            elif r == "pending":
                stats["pending"] += 1
            elif r == "active":
                stats["cleared"] += 1
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
