"""Host routes: list / create / update (PATCH) / delete / uninstall a host, its flags (2FA,
crown jewel, autostart, forget credentials, provision), the SSH host-key alarm and accept, and
the Add-host connection test with its pending generated key. Moved out of api.py;
shared host helpers live in `hostmodel.py`. Mounted in main.py next to `api.router`.
"""
import asyncio
import json
import logging
import time

import asyncssh

from fastapi import (APIRouter, Depends, Request)
from pydantic import BaseModel
from typing import Optional


from .errors import ApiError
from . import (audit, authz, certmon, core,
               db, email_alerts, security, conntypes, ssomap, stepup)
from . import hostmodel

log = logging.getLogger("webterm")
# Aceeaşi gardă ca api.router (fail-closed): o rută fără permisiune declarată → 500 authz.undeclared.
router = APIRouter(dependencies=[Depends(authz.declared)])


# ── [hosts] Host JSON: what the host list returns ─────────────────────────────────────────────────


def _host_supervision(row) -> dict | None:
    """Pornirea la boot a agentului (agent v57+): {mode, linger, boot[, scope, watchdog]} din
    coloana `supervision_summary` (scrisă la primirea diagnosticului / după comutarea din UI).
    None = necunoscut (agent mai vechi, coloană goală sau JSON stricat) — UI-ul arată „necunoscut",
    nu „nu"."""
    raw = row["supervision_summary"] if "supervision_summary" in row.keys() else None
    if not raw:
        return None
    try:
        s = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return core.supervision_summary({"supervision": s})


def _sees_crown(request) -> bool:
    """3.6.10 (review): the crown-jewel flag says "this host runs WebTerm / holds its backups" —
    a map for an attacker. Only an Owner or a holder of users.manage (who decides who gets a shell
    where) sees it; never an automation token, never a plain host viewer."""
    p = getattr(request.state, "principal", None)
    if p is None or p.kind != "user":
        return False
    g = authz.grants_of(request)
    return g.is_owner() or g.has_global("users.manage")


def _host_json(row, crown: bool = False) -> dict:
    conn = core.sources.get(row["id"])
    ctype = conntypes.of(row)
    is_agent = ctype == "agent"
    expected = core.agent_expected()["version"]
    out = {
        "id": row["id"], "name": row["name"], "note": row["note"],
        "alerts_muted": bool(row["alerts_muted"]) if "alerts_muted" in row.keys() else False,
        "online": hostmodel.host_online(row), "hostname": row["hostname"],
        "agent_user": row["agent_user"], "agent_version": row["agent_version"],
        "backend": row["backend"], "last_heartbeat": row["last_heartbeat"],
        "folder": (row["folder"] or "") if "folder" in row.keys() else "",
        "tags": [t for t in ((row["tags"] or "").split(",")
                             if "tags" in row.keys() and row["tags"] else [])],
        "updates": hostmodel.host_updates(row),
        # 3.7.0 — mTLS: required = clichetul (doar certificat); last = ultima conexiune mTLS; expiră = certificatul
        "mtls": ({"required": bool(row["mtls_required"]), "last": row["mtls_last"],
                  "not_after": row["mtls_not_after"], "issued": bool(row["mtls_serial"])}
                 if is_agent and "mtls_required" in row.keys() else None),
        "supervision": _host_supervision(row) if is_agent else None,
        # 3.6.9: the agent's Python is (likely / confirmed) older than its 3.6 minimum — file
        # operations fail there. None = no sign of it (the agent does not report its version).
        "agent_python_old": (core.agent_python_old.get(row["id"])
                             if is_agent and core.agent_python_old.get(row["id"]) in ("likely", "confirmed")
                             else None),
        "conflict": core.host_conflict(row["id"]),
        # Agentul a fost scos de pe host. Hostul rămâne până când cineva confirmă în UI —
        # poate nu vrei să-l ştergi, ci doar să-l reinstalezi, caz în care marcajul dispare
        # singur la reconectare. Expus DOAR când e credibil (heartbeat-urile s-au oprit
        # imediat după marcaj): un marcaj plantat de cineva cu shell pe host nu ajunge
        # badge în UI, deci nu poate invita operatorul să şteargă un host viu.
        "uninstalled_at": (row["uninstalled_at"]
                           if "uninstalled_at" in row.keys()
                           and core.uninstall_marker_credible(row["uninstalled_at"],
                                                              row["last_heartbeat"])
                           else None),
        "metrics": conn.metrics if conn else None,
        "agent_latest": expected,
        # Link de instalare încă VALABIL şi NEFOLOSIT (agentul nu s-a conectat niciodată): un
        # semnal ca să observi un link uitat/scurs. Se stinge singur la prima conectare a
        # agentului (enroll_token → NULL la revendicare) sau la expirare.
        "enroll_pending": is_agent and row["agent_version"] is None
            and ("enroll_token" in row.keys() and bool(row["enroll_token"]))
            and (row["enroll_expires"] or 0) > time.time(),
        "enroll_protected": is_agent and "enroll_pass_hash" in row.keys()
            and bool(row["enroll_pass_hash"]),
        # de ce NU se poate actualiza (dacă e cazul) — altfel UI-ul arată „update disponibil"
        # la infinit, fără motiv şi fără remediu
        "update_blocked": (row["update_blocked"] if "update_blocked" in row.keys() else None),
        "update_pending": is_agent and (bool(core.pending_updates.get(row["id"]))
            or (conn is not None and expected is not None
                and (conn.agent_version or 0) < expected)),
        # conectare directă (niciun secret nu iese de aici)
        "connection_type": ctype,
        "via_host_id": row["via_host_id"] if "via_host_id" in row.keys() else None,
        "ephemeral": bool(row["ephemeral"]) if "ephemeral" in row.keys() else False,
        "ssh_username": row["ssh_username"],
        "ssh_port": row["ssh_port"],
        "auth_method": row["auth_method"],
        "require_2fa": bool(row["require_2fa"]),
        "credential_policy": row["credential_policy"],
        "has_credentials": bool(row["credential_encrypted"]),
        # alarmă de host-key schimbat (SSH direct/jump), persistentă până la accept/re-pin;
        # cât e setată, conectarea e refuzată (ssh.hostKeyChanged) fără dial
        "hostkey_alarm": hostmodel.hostkey_alarm(row),
    }
    if crown:
        # 3.6.10: runs the gateway / holds its backups — a shell there equals Owner (badge in the
        # UI). Only for an Owner or users.manage (`_sees_crown`); absent for everyone else.
        out["crown_jewel"] = bool(row["crown_jewel"]) if "crown_jewel" in row.keys() else False
    return out


# ── [hosts] List / create hosts ───────────────────────────────────────────────────────────────────


@router.get("/api/hosts")
async def list_hosts(request: Request,
                     user=Depends(authz.perm('host.view', list=True, tokens='read'))):
    vis = await authz.visible_hosts(authz.grants_of(request), "host.view")
    rows = await db.fetchall("SELECT * FROM hosts ORDER BY name")
    gw_host = (await certmon.cert_renew_host_id()) if authz.grants_of(request).is_owner() else None
    crown = _sees_crown(request)
    out = []
    for r in rows:
        if not authz.in_visible(vis, r["id"]):
            continue
        j = _host_json(r, crown)
        # o ţintă jump vizibilă al cărei agent `via` NU e vizibil: nu-i dăm id-ul agentului
        # (oracol de existenţă); UI-ul o afişează atunci la nivelul de sus, nu sub părinte
        if j.get("via_host_id") and not authz.in_visible(vis, j["via_host_id"]):
            j["via_host_id"] = None
        # 3.6.10: a hint for the Owner, never for others (it says which host runs the gateway):
        # the host picked as the gateway host for certificate renewals is a crown jewel
        if gw_host and r["id"] == gw_host and not j.get("crown_jewel"):
            j["crown_hint"] = "gateway"
        out.append(j)
    return out


@router.post("/api/hosts")
async def create_host(host: hostmodel.HostIn, request: Request, user=Depends(authz.perm('hosts.create'))):
    v = await hostmodel.validate_host(host, user, authz.grants_of(request))
    row, enroll, pw = await hostmodel.insert_host(host, user, v)
    return dict(_host_json(row, _sees_crown(request)), install_command=hostmodel.install_command(enroll, pw),
                install_command_dedicated=hostmodel.install_command_dedicated(enroll, pw),
                enroll_expires=row["enroll_expires"])


# ── [ssh] Host key alarm: read / accept (fingerprint-bound) ───────────────────────────────────────


class HostKeyAcceptIn(BaseModel):
    # amprenta pe care omul a VĂZUT-o în dialog: accept-ul pinează doar dacă e chiar cea a alarmei
    # de acum (un dialog vechi nu pinează o cheie pe care nimeni n-a văzut-o — review lot 2, M5)
    fingerprint: str = ""
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


@router.get("/api/hosts/{host_id}/hostkey")
async def host_hostkey(host_id: int, user=Depends(authz.perm('host.diagnostics', host='host_id'))):
    """Starea pinului de host-key al unui host SSH (direct/jump): amprenta curentă (cea pinată,
    sau cea OFERITĂ dacă e o alarmă activă), cea anterioară şi momentul schimbării — ca omul să
    poată compara cu `ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub` pe server, out-of-band."""
    row = await db.fetchone("SELECT id, known_hosts, hostkey_alarm FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    alarm = hostmodel.hostkey_alarm(row)
    pinned_fp = core.hostkey_fingerprint(row["known_hosts"] or "")
    if alarm:
        return {"fingerprint": alarm["new_fp"], "previous": alarm["old_fp"] or pinned_fp,
                "changed_at": alarm["changed_at"], "pinned": bool(row["known_hosts"]), "alarm": True,
                "first": alarm["first"]}
    return {"fingerprint": pinned_fp, "previous": None, "changed_at": None,
            "pinned": bool(row["known_hosts"]), "alarm": False}


# INV-03 (docs/design/INVARIANTS.md): acceptul e legat de amprenta văzută; altă cheie între timp = ssh.hostKeyStale.
@router.post("/api/hosts/{host_id}/hostkey/accept")
async def host_hostkey_accept(host_id: int, body: HostKeyAcceptIn, request: Request,
                              user=Depends(authz.perm('host.edit', host='host_id'))):
    """Re-pinează cheia NOUĂ după verificare out-of-band şi stinge alarma. Singura cale de
    re-pin din UI — înainte trucul era „schimb portul şi-l pun la loc" (audit UX §6.e2).
    Pe hosturile 2FA cere step-up (e echivalentul lui „ştergi known_hosts"); e auditat şi
    alertat ca schimbare de securitate, fiindcă un accept greşit legitimează un MITM."""
    row = await db.fetchone("SELECT id, name, known_hosts, hostkey_alarm FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    try:
        alarm = json.loads(row["hostkey_alarm"] or "null")
    except ValueError:
        alarm = None
    if not alarm:
        raise ApiError(409, "ssh.noHostKeyAlarm", "no host-key change is pending for this host")
    if (body.fingerprint or "").strip() != (alarm.get("new_fp") or ""):
        raise ApiError(409, "ssh.hostKeyStale",
                       "the host key changed since you looked at it — review the new fingerprint")
    if alarm.get("first") and row["known_hosts"]:
        # între timp hostul a primit un pin (test verificat): alarma de prim contact nu-l înlocuieşte
        await db.execute("UPDATE hosts SET hostkey_alarm=NULL WHERE id=?", host_id)
        raise ApiError(409, "ssh.noHostKeyAlarm", "this host already has a pinned key")
    new_key = alarm.get("new_key") or ""
    old_fp, new_fp = alarm.get("old_fp") or "?", alarm.get("new_fp") or "?"
    # Condiţionat de alarma CITITĂ: între citire şi aici e step-up-ul (await-uri), iar un PATCH
    # concurent (pin verificat de test, mutare) nu trebuie suprascris cu cheia unei alarme vechi
    # (review 2). Fără cheie capturată (asyncssh vechi?) → pinul se resetează: confirmare la dial.
    await db.execute("UPDATE hosts SET known_hosts=?, hostkey_alarm=NULL WHERE id=? AND hostkey_alarm=?",
                     new_key or None, host_id, row["hostkey_alarm"])
    after = await db.fetchone("SELECT known_hosts, hostkey_alarm FROM hosts WHERE id=?", host_id)
    if not after or after["hostkey_alarm"] is not None or (after["known_hosts"] or None) != (new_key or None):
        raise ApiError(409, "ssh.hostKeyStale", "the host changed while you were confirming — review it again")
    if alarm.get("first") and new_key:
        # primul contact confirmat: pin iniţial, nu o re-pinare — auditat, fără alertă de flotă
        audit.detail(request, "host-key first contact confirmed: %s" % new_fp)
        await core.record_agent_event(host_id, "hostkey_accepted", reason="hostkey_first_confirmed",
                                      detail="%s by %s" % (new_fp, user["email"]))
        return {"ok": True, "fingerprint": new_fp, "pinned": True}
    audit.detail(request, "host-key accepted: %s → %s" % (old_fp, new_fp))
    await core.record_agent_event(host_id, "hostkey_accepted", reason="hostkey_accepted",
                                  detail="%s → %s by %s" % (old_fp, new_fp, user["email"]))
    email_alerts.notify_security_change(
        "SSH host key re-pinned for host '%s' (%s → %s)" % (row["name"], old_fp, new_fp),
        security.client_ip(request), user["email"], fleet=True, host_id=host_id,
        what_key="host_key_repinned", what_params={"host": row["name"], "old_fp": old_fp, "new_fp": new_fp})
    return {"ok": True, "fingerprint": new_fp if new_key else None, "pinned": bool(new_key)}


# ── [hosts] Update host (PATCH): retarget binding, credentials, TOFU reset ────────────────────────


class HostPatch(BaseModel):
    """Editare PARȚIALĂ: doar câmpurile trimise se aplică.

    Vechiul PATCH lua un `hostmodel.HostIn` întreg și scria doar name/note/folder. Două consecințe:
    câmpurile de conexiune (hostname, user, port, credențiale) erau acceptate și IGNORATE
    tăcut — clientul primea `ok: true` fără să se fi schimbat nimic — iar un PATCH parțial
    ȘTERGEA nota și folderul, fiindcă lipsa lor din corp înseamnă `""` în `hostmodel.HostIn`.
    Cu `None` ca „netrimis", ambele dispar."""
    name: Optional[str] = None
    note: Optional[str] = None
    folder: Optional[str] = None
    connection_type: Optional[str] = None
    hostname: Optional[str] = None
    ssh_username: Optional[str] = None
    ssh_port: Optional[int] = None
    auth_method: Optional[str] = None
    credential: Optional[str] = None      # write-only; netrimis = păstrează ce e stocat
    passphrase: Optional[str] = None
    credential_policy: Optional[str] = None
    via_host_id: Optional[int] = None     # ssh-jump: hostul-agent prin care tunelăm
    tags: Optional[str] = None
    alerts_muted: Optional[bool] = None   # opreşte alertele de host-offline pentru acest host
    pin_hostkey: Optional[str] = None     # vezi hostmodel.HostIn: doar cheia văzută de testul de conexiune
    pending_key_id: Optional[str] = None  # vezi hostmodel.HostIn: cheia generată în formular devine credenţialul
    # 3.6.10: mutarea unui host crown-jewel într-un folder/tag cu legături ⚑ cere confirmare
    confirm_crown_jewel: bool = False
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


# câmpurile care schimbă UNDE și CU CE ne conectăm — aceeași clasă cu provisioning-ul
_CONN_FIELDS = ("connection_type", "hostname", "ssh_username", "ssh_port",
                "auth_method", "credential", "credential_policy", "via_host_id")


# INV-01 (docs/design/INVARIANTS.md): un secret salvat aparține ȚINTEI (protocol, gazdă, port, via), nu rândului; o mutare cere parola din nou.
def _conn_target(ctype: str, hostname, port, via) -> tuple:
    """Ţinta la care pleacă un credenţial: (protocol, gazdă, port, rută jump). `via` contează doar
    pe tipurile jump (un ssh direct pleacă din reţeaua gateway-ului, oricare ar fi `via` rămas)."""
    proto = conntypes.target_proto(ctype)
    jump = ctype in conntypes.JUMP
    return (proto, (hostname or "").strip().lower(), int(port or conntypes.default_port(proto)),
            int(via or 0) if jump else 0)


def _has_stored_password(row) -> bool:
    """Rândul ţine o PAROLĂ în seif (ssh sau telnet), oricare ar fi tipul/politica/metoda de acum.
    Blob ilizibil → True (fail-closed: nu ştim ce e, tratăm ca secret)."""
    if not row["credential_encrypted"]:
        return False
    try:
        cred = hostmodel.decode_credential(row["credential_encrypted"])
    except Exception:                       # noqa: BLE001
        return True
    return isinstance(cred, dict) and bool(cred.get("password"))


def _retargets(row, new_type: str, hostname, port, via) -> bool:
    """Ţinta s-ar muta faţă de cea pentru care a fost salvat credenţialul. Parola unui host
    `agent` vine din provisioning-ul prin SSH, deci ţinta ei e SSH pe adresa lui — NU protocolul
    cerut acum (altfel ssh → agent+adresă nouă → ssh/telnet o muta fără întrebare; review 2, H)."""
    old_type = conntypes.of(row)
    if old_type == conntypes.AGENT:
        old_type = conntypes.SSH
    return (_conn_target(old_type, row["hostname"], row["ssh_port"], row["via_host_id"])
            != _conn_target(new_type, hostname, port, via))


@router.patch("/api/hosts/{host_id}")
async def update_host(host_id: int, host: HostPatch, request: Request,
                      user=Depends(authz.perm('host.edit', host='host_id'))):
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    given = host.model_dump(exclude_unset=True)
    # 3.6 (§A.11.1): folderul şi etichetele DECID cine vede hostul — mutarea lui în `lab` dă
    # shell fiecărui Operator din lab. Deci `host.edit` singur nu ajunge: cere `hosts.create` @ all.
    grants = authz.grants_of(request)
    scope_moved = (("folder" in given and (given["folder"] or "").strip() != (row["folder"] or ""))
                   or ("tags" in given and hostmodel.norm_tags(given["tags"] or "") != (row["tags"] or "")))
    if scope_moved:
        authz.require_global(grants, "hosts.create")
    crown_moved = []
    if scope_moved and (row["crown_jewel"] or 0) and not (row["ephemeral"] or 0):
        # 3.6.10 (§A.11.2): mutat într-un folder/tag peste care cineva (ne-Owner) are un rol ⚑,
        # hostul crown-jewel îi dă acelui cont un shell pe instanţă. Aceeaşi confirmare ca la o
        # legătură nouă; doar legăturile/mapările care NU-l acopereau deja contează.
        old_ref = authz.HostRef(host_id, row["folder"] or "", authz.tag_set(row["tags"]))
        new_ref = authz.HostRef(
            host_id,
            (given["folder"] or "").strip() if "folder" in given else (row["folder"] or ""),
            authz.tag_set(hostmodel.norm_tags(given["tags"] or "")) if "tags" in given else old_ref.tags)
        crown_moved = await authz.crown_exposure(new_ref, before=old_ref)
        if crown_moved and not _sees_crown(request):
            # who cannot see the crown flag must not learn it from this answer either
            raise ApiError(403, "host.moveNeedsOwner",
                           "this folder/tag change needs an Owner or an account manager")
        if crown_moved and not host.confirm_crown_jewel:
            raise ApiError(409, "authz.crownJewelMove",
                           "moving this crown-jewel host gives a shell on it to %d more role "
                           "binding(s) or SSO mapping(s); confirm to move it anyway"
                           % len(crown_moved), vars={"host": row["name"] or "", "n": len(crown_moved)})
    # …iar o ţintă jump deschide TCP DIN hostul `via` (§A.11.4): orice atingere a ţintei (adresă,
    # port, tip, via — schimbată SAU doar retrimisă) cere `forward.manage` pe via-ul EFECTIV, ca la
    # creare şi la /api/hosts/test. Altfel `host.edit` pe jump ar re-ţinti pivotul oriunde.
    eff_type = given.get("connection_type") or conntypes.of(row)
    if eff_type in conntypes.JUMP and any(
            f in given for f in ("hostname", "ssh_port", "connection_type", "via_host_id")):
        eff_via = given["via_host_id"] if "via_host_id" in given else row["via_host_id"]
        if eff_via:                 # fără via → refuzat mai jos (400 sshjump.needsAgent)
            await authz.require_on(grants, eff_via, "forward.manage")
    # `touches_conn` = un câmp de conexiune se SCHIMBĂ efectiv, nu doar e prezent în payload.
    # UI-ul (AddHostModal) trimite MEREU `connection_type`, chiar şi la o redenumire pură, deci
    # „prezent" însemna că ORICE editare pica pe calea de re-provisioning: agentul deconectat
    # degeaba (host offline câteva secunde), step-up cerut inutil pe hosturi 2FA, iar terminalul
    # deschis rămânea fără input. Comparăm cu valoarea curentă; `credential` e write-only, deci
    # o valoare prezentă = schimbare. (Bug raportat: redenumire → nu mai poţi scrie.)
    def _conn_changed(f):
        if f not in given:
            return False
        if f == "credential":
            return bool(given[f])
        return given[f] != row[f]
    touches_conn = any(_conn_changed(f) for f in _CONN_FIELDS)
    # cheia generată în formular = credenţial nou; un pin de host-key diferit de cel stocat =
    # schimbă CE maşină acceptăm. Ambele sunt din clasa provisioning-ului (step-up pe 2FA).
    pin_given = (given.get("pin_hostkey") or "").strip()
    pend_given = (given.get("pending_key_id") or "").strip()
    if pend_given or (pin_given and not hostmodel.same_hostkey(pin_given, row["known_hosts"] or "")):
        touches_conn = True
    if touches_conn:
        # Repointarea unui host către altă mașină (sau altă credențială) e echivalentă cu
        # provisioning-ul: cine are doar cookie-ul nu trebuie să poată face asta pe un host 2FA.
        await stepup.require_host_stepup(host_id, user, host.stepup_grant, host.stepup_password, host.stepup_totp)
    elif given.get("alerts_muted") and row["require_2fa"]:
        # A REDUCE monitorizarea unui host 2FA cere step-up: sweep-ul refuză explicit ca marcajul
        # neautentificat de uninstall să cumpere tăcere (core.py, audit 2026-08) — un cookie furat
        # n-are voie s-o cumpere nici pe calea asta. RE-activarea alertelor rămâne liberă (întăreşte
        # monitorizarea), simetric cu politica din `set_require_2fa`.
        await stepup.require_host_stepup(host_id, user, host.stepup_grant, host.stepup_password, host.stepup_totp)

    old_type = conntypes.of(row)
    new_type = given.get("connection_type", old_type)
    if new_type not in conntypes.ALL:
        raise ApiError(400, "host.badType", "unknown connection type")
    eff = lambda f, col=None: (given[f] if f in given else row[col or f])   # noqa: E731
    hostname = (eff("hostname") or "").strip()
    ssh_username = (eff("ssh_username") or "").strip()
    policy = eff("credential_policy") or "stored"
    hostmodel.check_cred_policy(policy)
    auth_method = eff("auth_method") or "password"

    if new_type in conntypes.NETWORK and not hostname:
        raise ApiError(400, "host.hostnameRequired", "hostname required for a direct connection")
    if new_type in conntypes.SSH_FAMILY and not ssh_username:
        raise ApiError(400, "ssh.userRequired", "an SSH username is required")
    # la editarea unui jump, agentul `via` trebuie să rămână un host de tip agent (ca la creare)
    if new_type in conntypes.JUMP:
        via_id = eff("via_host_id")
        # Self-via: un host AGENT retipizat la jump cu `via_host_id=<propriul id>` trecea regula
        # „via e agent" (rândul lui încă zice agent), apoi `touches_conn` îi scotea propria sursă
        # → „agent offline" la orice conectare, fără remediu în UI. La fel un ciclu A→B→A, posibil
        # doar pe DB-uri în care `via_host_id` a rămas agăţat pe un rând retipizat la agent
        # (defectul de mai jos) — urcăm lanţul cu o buclă mărginită, nu avem încredere în date.
        if via_id == host_id:
            raise ApiError(400, "sshjump.viaLoop", "a jump host cannot route through itself")
        via = (await db.fetchone("SELECT connection_type, via_host_id FROM hosts WHERE id=?", via_id)
               if via_id else None)
        if not via or not conntypes.is_agent(via):
            raise ApiError(400, "sshjump.needsAgent", "pick an agent host to reach the target through")
        cur, hops = via["via_host_id"], 0
        while cur and hops < 16:
            if cur == host_id:
                raise ApiError(400, "sshjump.viaLoop", "the jump chain would loop back to this host")
            nxt = await db.fetchone("SELECT via_host_id FROM hosts WHERE id=?", cur)
            cur, hops = (nxt["via_host_id"] if nxt else None), hops + 1
    # Un agent prin care trec ţinte jump SALVATE nu-şi poate schimba tipul: copiii ar rămâne cu
    # `via` spre un non-agent (conectare imposibilă) şi ar dispărea din sidebar, care îi randează
    # doar sub părinte. Acelaşi refuz ca la ştergere — operatorul re-leagă sau şterge copiii întâi.
    if old_type == "agent" and new_type != "agent":
        await _refuse_if_jump_children(host_id)
    # Întoarcerea la SSH după ce agentul a preluat: detaliile de conexiune supraviețuiesc
    # provisioning-ului, dar credențialul e ȘTERS dacă politica era `ephemeral`. Fără el nu
    # ne putem conecta, deci cerem unul acum, în loc să eșuăm abia la prima conectare.
    if pend_given and new_type not in conntypes.SSH_FAMILY:
        raise ApiError(400, "sshkey.notSsh", "SSH key generation is only for SSH hosts")
    # Parola STOCATĂ e a destinaţiei de acum. Mutarea hostului pe altă adresă / port / rută jump
    # o păstra, iar prima conectare (TOFU, pinul resetat) o trimitea noii ţinte — inclusiv unui
    # server SSH al celui care a făcut mutarea (raport de securitate 2026-11, lot 2). Acum ţinta
    # nouă cere parola din nou. Doar parola: o cheie privată nu pleacă niciodată la server
    # (semnătura e legată de sesiune), deci schimbarea IP-ului unui host cu cheie rămâne liberă.
    # Regula se ia din parola STOCATĂ, nu din câmpurile cererii: tipul, politica („ask") sau metoda
    # („key") schimbate odată cu adresa, apoi readuse într-un al doilea PATCH, ocoleau o verificare
    # legată de ele — iar telnet o trimitea chiar în clar (review lot 2, C1). Agent = nu o foloseşte.
    pw_moves = (not given.get("credential") and not pend_given and _has_stored_password(row)
                and _retargets(row, new_type, hostname, eff("ssh_port"), eff("via_host_id")))
    # Pe `agent` parola nu se foloseşte: o ţintă mutată nu cere parola, dar o ŞTERGE din seif — ca
    # să nu reînvie la întoarcerea pe ssh/telnet spre noua adresă (review 2, H)
    drop_secret = pw_moves and new_type == "agent"
    if pw_moves and new_type != "agent":
        raise ApiError(400, "host.retargetNeedsPassword",
                       "the host now points somewhere else — enter the password again; the stored "
                       "one is only sent to the address it was saved for")
    if (new_type == "ssh" and policy == "stored" and not pend_given
            and not given.get("credential") and not row["credential_encrypted"]):
        raise ApiError(400, "host.noStoredCredentials",
                       "the host no longer has stored SSH credentials "
                       "(removed when the agent was installed) — enter the password or key")

    # Pinul de host-key aparține MAȘINII vechi: dacă am mutat hostul în altă parte, pinul
    # respinge noua mașină la fiecare încercare, iar mesajul arată ca un MITM. Îl resetăm
    # explicit (TOFU repinează la prima conectare) și O SPUNEM în răspuns.
    # Ţinta = protocol + gazdă (fără diferenţe de majuscule) + port + rută jump: şi un ssh-jump
    # devenit ssh direct (alt drum, altă reţea) e altă ţintă (review lot 2, H2)
    repinned = _retargets(row, new_type, hostname, eff("ssh_port"), eff("via_host_id"))
    new_pin = None
    if pin_given:
        if new_type not in conntypes.SSH_FAMILY:
            raise ApiError(400, "hosttest.pinMismatch", "only SSH hosts have a host key to pin")
        eff_port = (given["ssh_port"] if "ssh_port" in given else row["ssh_port"]) or 22
        new_pin = hostmodel.verified_pin(user["id"], new_type, hostname, eff_port, eff("via_host_id") or 0, pin_given)
        # Pe ACEEAŞI ţintă, un pin existent se schimbă doar prin fluxul de alarmă („accept",
        # cu amprentele la vedere, auditat şi alertat) — nu printr-un test făcut fără host_id
        # (care n-a comparat cu pinul) urmat de un PATCH. Altfel testul ar ocoli alarma de MITM.
        if not repinned and row["known_hosts"] and not hostmodel.same_hostkey(new_pin, row["known_hosts"]):
            raise ApiError(409, "hosttest.pinConflict",
                           "this host already has a different pinned host key — review it with the "
                           "host-key alarm instead")
    if pend_given:
        given["auth_method"], given["credential_policy"] = "key", "stored"
        given.pop("credential", None)

    sets, vals = [], []
    for col, key in (("name", "name"), ("note", "note"), ("folder", "folder"),
                     ("hostname", "hostname"), ("ssh_username", "ssh_username"),
                     ("auth_method", "auth_method"), ("credential_policy", "credential_policy")):
        if key in given:
            v = given[key]
            sets.append(f"{col}=?")
            vals.append(v.strip() if isinstance(v, str) else v)
    # `via_host_id` are sens DOAR în familia jump. Când hostul iese din ea (ssh-jump → ssh/agent)
    # îl golim explicit: altfel clientul îl considera în continuare cuibărit (`isNested`), iar un
    # fost jump devenit agent, cu `via` agăţat, era singura cale spre un ciclu de via-uri.
    if new_type in conntypes.JUMP:
        if "via_host_id" in given:
            sets.append("via_host_id=?"); vals.append(given["via_host_id"])
    elif row["via_host_id"] is not None or "via_host_id" in given:
        sets.append("via_host_id=NULL")
    if "ssh_port" in given:
        sets.append("ssh_port=?"); vals.append(given["ssh_port"])
    if "tags" in given:
        sets.append("tags=?"); vals.append(hostmodel.norm_tags(given["tags"]))
    if "alerts_muted" in given:
        # la re-activarea alertelor curăţăm şi dedup-ul (DB + backstop-ul RAM): un host încă
        # offline va re-declanşa o alertă la următorul sweep (vrei să ştii că e tot jos),
        # nu să rămână tăcut din inerţie.
        sets.append("alerts_muted=?"); vals.append(1 if given["alerts_muted"] else 0)
        if not given["alerts_muted"]:
            sets.append("offline_notified=?"); vals.append(0)
            core.rearm_offline_alert(host_id)
    if "connection_type" in given:
        sets.append("connection_type=?"); vals.append(new_type)
    if given.get("credential"):
        blob = hostmodel.credential_blob(hostmodel.HostIn(
            name=row["name"], connection_type=new_type, auth_method=auth_method,
            credential=given["credential"], passphrase=given.get("passphrase") or "",
            credential_policy=policy))
        sets.append("credential_encrypted=?"); vals.append(blob)
    elif drop_secret or (policy == "ask" and row["credential_encrypted"] and not pend_given):
        # „cere de fiecare dată" = nimic stocat. Lăsat în seif, secretul revenea la viaţă la
        # întoarcerea pe „stored" — pe o ţintă mutată între timp (review lot 2, C1)
        sets.append("credential_encrypted=NULL")
    # Cheie → PAROLĂ pe aceeaşi ţintă: pinul a fost pus tăcut (TOFU e păstrat doar pentru chei), deci
    # nimeni nu l-a confirmat. Îl ştergem: prima conectare cu parola cere confirmarea amprentei,
    # dacă formularul nu aduce chiar acum un pin verificat de test (review 2, pin moştenit).
    if (not repinned and not new_pin and new_type in conntypes.SSH_FAMILY and row["known_hosts"]
            and (row["auth_method"] or "password") == "key" and auth_method == "password"):
        sets.append("known_hosts=NULL"); sets.append("hostkey_alarm=NULL")
    if repinned:
        # ţintă nouă: pinul vechi pleacă; dacă testul a văzut-o, pinăm direct cheia ei
        sets.append("known_hosts=?"); vals.append(new_pin)
        sets.append("hostkey_alarm=NULL")      # pin nou = alarma veche nu mai are obiect
    elif new_pin and not row["known_hosts"]:
        sets.append("known_hosts=?"); vals.append(new_pin)
        # pinul verificat de test înlocuieşte o alarmă de prim contact rămasă (posibil cu cheia
        # unui MITM văzută la un dial anterior) — altfel „Trust" ar fi suprascris pinul bun (M4)
        sets.append("hostkey_alarm=NULL")
    if not sets and not pend_given:
        return {"ok": True, "changed": False}
    async with authz.bindings_lock:
        if scope_moved:
            # revizuirea 3.6.10: între verificarea de sus şi scriere au trecut step-up-ul şi alte
            # aşteptări — cineva a putut marca hostul crown-jewel, mutat folderul/etichetele sau
            # acorda o legătură ⚑ între timp. Expunerea se recalculează pe starea de ACUM, sub
            # lock-ul legăturilor (acordările îl ţin şi ele), imediat înainte de UPDATE.
            cur = await db.fetchone("SELECT name, folder, tags, COALESCE(crown_jewel, 0) AS cj,"
                                    " COALESCE(ephemeral, 0) AS eph FROM hosts WHERE id=?", host_id)
            if not cur:
                raise ApiError(404, "host.missing", "no such host")
            crown_moved = []
            if cur["cj"] and not cur["eph"]:
                old_ref = authz.HostRef(host_id, cur["folder"] or "", authz.tag_set(cur["tags"]))
                new_ref = authz.HostRef(
                    host_id,
                    (given["folder"] or "").strip() if "folder" in given else (cur["folder"] or ""),
                    authz.tag_set(hostmodel.norm_tags(given["tags"] or "")) if "tags" in given else old_ref.tags)
                crown_moved = await authz.crown_exposure(new_ref, before=old_ref)
                if crown_moved and not _sees_crown(request):
                    raise ApiError(403, "host.moveNeedsOwner",
                                   "this folder/tag change needs an Owner or an account manager")
                if crown_moved and not host.confirm_crown_jewel:
                    raise ApiError(409, "authz.crownJewelMove",
                                   "moving this crown-jewel host gives a shell on it to %d more role "
                                   "binding(s) or SSO mapping(s); confirm to move it anyway"
                                   % len(crown_moved),
                                   vars={"host": cur["name"] or "", "n": len(crown_moved)})
        if pend_given:
            # ultima, după toate validările: revendicarea şterge rândul în aşteptare
            sets.append("credential_encrypted=?")
            vals.append(await hostmodel.claim_pending_key(user["id"], pend_given))
        vals.append(host_id)
        await db.execute("UPDATE hosts SET %s WHERE id=?" % ", ".join(sets), *vals)
    if "name" in given and isinstance(given["name"], str) \
            and given["name"].strip() != (row["name"] or ""):
        # 3.6.5: WEBTERM_OIDC_ROLE_MAP numeşte hostul după NUME, rezolvat doar la pornire
        await ssomap.note_config_host_change(host_id, "renamed from '%s' to '%s'" % (
            (row["name"] or "")[:80], given["name"].strip()[:80]))
    if scope_moved or "via_host_id" in given or "connection_type" in given:
        authz.bump_epoch()          # cine vede hostul s-a putut schimba: socket-urile re-verifică
    if crown_moved:
        what = "crown-jewel host %s moved (folder/tags) — CONFIRMED: now also reachable with a " \
               "shell through %s" % (row["name"], "; ".join(
                   "%s %s (%s @ %s)" % (e["kind"], e["who"], e["role"],
                                        authz.scope_label(e["scope_kind"], e["scope_value"]))
                   for e in crown_moved[:authz.CROWN_LIST_MAX]))
        audit.detail(request, what)
        log.warning("%s (by %s)", what, user["email"])

    # O conexiune vie ține parametrii VECHI: fără demontare, editarea pare fără efect până
    # la următoarea deconectare accidentală.
    dropped = False
    if touches_conn:
        conn = core.sources.pop(host_id, None)
        if conn:
            dropped = True
            try:
                await conn.disconnect()
            except Exception:
                pass
        # Detaşăm EXPLICIT hub-urile hostului. `sources.pop` de mai sus face ca `was_current`
        # din `_shutdown` să fie False (sursa nu mai e în dicţionar când agentul cade), deci
        # `on_detached` NU rulează şi hub-urile rămân `attached=True`. La reconectarea agentului
        # `ensure_attached` iese imediat (no-op), aşa că noua conexiune nu re-primeşte niciodată
        # `attach` pentru sesiunile vii → terminalul deschis nu mai poate scrie deşi hostul e
        # online şi sesiunea „live". (Bug raportat: editarea unui host agent → nu mai poţi tasta.)
        core.detach_host_hubs(host_id)
    return {"ok": True, "changed": True, "connection_type": new_type,
            "host_key_reset": repinned, "disconnected": dropped}


class Toggle2fa(BaseModel):
    enabled: bool
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


# ── [hosts] Per-host flags: require 2FA, crown jewel, provision, forget credentials ───────────────


@router.post("/api/hosts/{host_id}/require-2fa")
async def set_require_2fa(host_id: int, body: Toggle2fa, user=Depends(authz.perm('host.admin', host='host_id'))):
    """Activează/dezactivează cererea de 2FA la conectarea pe acest host.
    GAP-fix: DEZACTIVAREA cere step-up — altfel un cookie furat stingea 2FA pe host și tot
    gard-ul H1 devenea no-op. `stepup.require_host_stepup` citește valoarea CURENTĂ (încă 1 la
    dezactivare → cere step-up; 0 la activare → no-op, întărirea securității nu cere factor)."""
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    await db.execute("UPDATE hosts SET require_2fa=? WHERE id=?", int(body.enabled), host_id)
    if body.enabled:
        # Biletul de forward e valabil 12h şi nu ştie de host. Cine marchează un host „cere 2FA"
        # tocmai fiindcă e îngrijorat rămânea cu tunelurile deschise până la expirare: handshake-ul
        # NOU cerea step-up, cel vechi mergea în continuare. `logout` bumpează deja epoch-ul.
        security.bump_forward_epoch()
        # 3.5.13: parola singură nu mai deschide un host 2FA. Nu blocăm activarea (întărirea
        # securităţii nu cere nimic), dar spunem ACUM că, fără passkey/TOTP/SSO, contul nu va
        # putea deschide hostul până nu înrolează un factor — nu la primul click pe Conectare.
        if not await stepup.user_has_factor(user):
            return {"ok": True, "warning": "stepup.needsFactor"}
    return {"ok": True}


class CrownJewelIn(BaseModel):
    enabled: bool
    current_password: str = ""     # doar la SCOATEREA marcajului (reduce o protecţie)
    totp_code: str = ""
    email_code: str = ""
    stepup_grant: str = ""


@router.post("/api/hosts/{host_id}/crown-jewel")
async def set_crown_jewel(host_id: int, body: CrownJewelIn, request: Request,
                          user=Depends(authz.perm('host.admin', host='host_id'))):
    """3.6.10 (§A.11.2): mark a host as a crown jewel — it runs the gateway or holds its backups,
    so a shell there IS Owner. Owner-only both ways (the route's `host.admin` + Owner @ all in the
    handler). Marking tightens (no re-auth); clearing loosens, so it takes the password (or SSO /
    passkey re-auth) and the second factor, like any access change. Audited and alerted. The
    answer lists the non-Owner role bindings and SSO mappings that already give a shell there —
    the flag guards FUTURE grants; existing ones are for the Owner to review."""
    grants = authz.grants_of(request)
    if not grants.is_owner():
        raise ApiError(403, "authz.ownerOnly", "only an Owner can mark or unmark a crown-jewel host")
    row = await db.fetchone("SELECT id, name, COALESCE(crown_jewel, 0) AS cj,"
                            " COALESCE(ephemeral, 0) AS eph FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    if row["eph"]:
        raise ApiError(400, "host.crownEphemeral", "a connect-once target cannot be a crown jewel")
    want = bool(body.enabled)
    if bool(row["cj"]) == want:
        return {"ok": True, "crown_jewel": want, "changed": False,
                "exposure": await authz.crown_exposure(await authz.host_ref(host_id)) if want else []}
    if not want:
        await stepup.reauth_for_access_change(user, request, body, "remove the crown-jewel mark")
    async with authz.bindings_lock:
        authz.forget_cached(user["id"])  # re-auth was a suspension point: re-check NOW
        if not (await authz.grants_for_user(user["id"])).is_owner():
            raise ApiError(403, "authz.ownerOnly", "only an Owner can mark or unmark a crown-jewel host")
        await db.execute("UPDATE hosts SET crown_jewel=? WHERE id=?", 1 if want else 0, host_id)
    exposure = await authz.crown_exposure(await authz.host_ref(host_id)) if want else []
    what = "host %s %s a crown jewel" % (row["name"], "marked as" if want else "is no longer")
    audit.detail(request, what + (" (%d non-Owner shell grant(s) already cover it)" % len(exposure)
                                  if exposure else ""))
    log.warning("%s (by %s)", what, user["email"])
    email_alerts.notify_security_change(what, security.client_ip(request), user["email"],
                                        fleet=True, what_key="crown_jewel_changed",
                                        what_params={"host": row["name"] or "",
                                                     "state": "on" if want else "off"})
    return {"ok": True, "crown_jewel": want, "changed": True, "exposure": exposure}


@router.post("/api/hosts/{host_id}/provision")
async def provision_agent(host_id: int, request: Request, user=Depends(authz.perm('host.admin', host='host_id'))):
    """Instalează agentul pe un host SSH: se conectează prin SSH, rulează
    installer-ul, AȘTEAPTĂ ca agentul să se conecteze (test), apoi trece host-ul
    în mod agent și șterge credențialele dacă politica e `ephemeral`."""
    await stepup.require_host_stepup(host_id, user)   # H1
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    if conntypes.of(row) != conntypes.SSH:
        raise ApiError(400, "provision.sshOnly", "provisioning is only available for SSH hosts")
    # 1) conexiune SSH (creds stocate; rate-limited; pin host-key)
    await hostmodel.connect_direct(row, request)
    src = core.sources.get(host_id)
    if not isinstance(src, core.SshSource):
        raise ApiError(502, "provision.noSsh", "the SSH connection is not available")
    # 2) enroll token proaspăt + rulează installer-ul prin canalul SSH
    enroll = security.new_token()[:32]
    # re-enrolare: pin-ul de instanţă se şterge aici; starea mTLS (INV-12) abia când installer-ul
    # revendică linkul (api.install_script)
    await db.execute("UPDATE hosts SET enroll_token=?, enroll_expires=?, instance_id=NULL WHERE id=?",
                     enroll, time.time() + 3600, host_id)
    try:
        result = await asyncio.wait_for(src._conn.run(hostmodel.install_command(enroll), check=False), 150)
    except Exception as e:
        log.warning("install over SSH failed on host %s: %s: %s", host_id, type(e).__name__, e)
        raise ApiError(502, "provision.installFailed", f"install over SSH failed: {e}")
    out = ((result.stdout or "") + (result.stderr or ""))[-1200:]
    # 3) TEST: așteaptă agentul să sune acasă (dovada că merge)
    connected = False
    for _ in range(40):
        await asyncio.sleep(1)
        if isinstance(core.sources.get(host_id), core.AgentConnection):
            connected = True
            break
    if not connected:
        raise ApiError(504, "provision.agentNotConnected",
                       "the installed agent did not connect in time.\n\n" + out)
    # 4) succes: mod agent + ștergere credențiale după politică
    delete_creds = row["credential_policy"] == "ephemeral"
    await db.execute("UPDATE hosts SET connection_type=? WHERE id=?", conntypes.AGENT, host_id)
    if delete_creds:
        await db.execute(
            "UPDATE hosts SET credential_encrypted=NULL, credential_policy='stored' WHERE id=?",
            host_id)
        await _drop_ssh_credential_in_memory(host_id)   # vezi helperul: DB-ul singur nu ajunge
    return {"ok": True, "credentials_deleted": delete_creds}


async def _drop_ssh_credential_in_memory(host_id: int) -> bool:
    """Închide conexiunea SSH vie a hostului, dacă există. Întoarce True dacă a fost una.

    Ştergerea rândului din DB nu e suficientă ca „uită credenţialele" să fie adevărat:
    `asyncssh` păstrează `password` şi `client_keys` ÎN CLAR în opţiunile conexiunii
    (`SSHClientConnectionOptions`), iar `SSHClientConnection` le ţine cât trăieşte ea. Deci
    parola rămânea în memoria gateway-ului până când conexiunea pica singură — uneori ore.

    Nu e o escaladare (ca s-o citeşti îţi trebuie execuţie de cod în proces, iar atunci ai
    şi cheia seifului), dar butonul promite ceva şi oamenii îl apasă tocmai ca acel ceva să
    nu mai existe. O promisiune pe jumătate adevărată e mai rea decât una absentă.

    Costul asumat: sesiunile SSH vii de pe hostul ăla se termină. E consecinţa corectă —
    „uită credenţialele" se apasă când calea SSH nu mai e necesară (agentul a preluat), iar
    o conexiune care supravieţuieşte ştergerii credenţialei e exact ce voiai să eviţi.
    Semnalat ca zonă neexaminată de un audit extern; verificat şi confirmat în asyncssh."""
    src = core.sources.get(host_id)
    if not isinstance(src, core.SshSource):
        return False
    core.sources.pop(host_id, None)
    try:
        await src.disconnect()
    except Exception:                       # noqa: BLE001 — închiderea e best-effort
        log.warning("closing the ssh connection for host=%s failed", host_id, exc_info=True)
    return True


class ForgetCredsIn(BaseModel):
    current_password: str = ""


@router.post("/api/hosts/{host_id}/forget-credentials")
async def forget_credentials(host_id: int, body: ForgetCredsIn,
                             user=Depends(authz.perm('host.admin', host='host_id'))):
    """Delete the stored SSH credentials (once the agent has taken over, or at any time).

    F-05: ştergerea e IREVERSIBILĂ — dacă hostul nu mai are agent, credenţiala aia era
    singurul mod de a ajunge la el din WebTerm. Cerea doar un cookie valid, deci era şi
    ţinta ideală a unui CSRF (endpoint fără body, deci cerere „simplă"). Acum are body,
    step-up pe hosturile cu 2FA, şi re-autentificare cu parola."""
    await stepup.require_host_stepup(host_id, user)
    if not await stepup.verify_reauth_password(user, body.current_password):
        raise ApiError(401, "auth.wrongCurrentPassword",
                       "re-enter your account password to forget the stored credentials")
    await db.execute("UPDATE hosts SET credential_encrypted=NULL WHERE id=?", host_id)
    dropped = await _drop_ssh_credential_in_memory(host_id)
    return {"ok": True, "connection_closed": dropped}


# ── [hosts] Delete / uninstall host, autostart ────────────────────────────────────────────────────


async def _refuse_if_jump_children(host_id: int) -> None:
    """409 dacă sub host stau ţinte jump PERSISTENTE (`via_host_id`). Verificat ÎNAINTE de orice
    efect ireversibil (deconectarea sursei, `uninstall` cerut agentului) — `core.purge_host` ar
    refuza şi el, dar prea târziu. Copiii efemeri nu blochează: pleacă odată cu părintele."""
    kids = await db.fetchall(
        "SELECT id, name FROM hosts WHERE via_host_id=? AND id!=? AND ephemeral=0 ORDER BY name",
        host_id, host_id)
    if kids:
        raise ApiError(409, "host.hasJumpChildren",
                       "saved jump targets are routed through this host (%s); re-route or delete "
                       "them first" % ", ".join(k["name"] for k in kids[:5]))


@router.delete("/api/hosts/{host_id}")
async def delete_host(host_id: int, user=Depends(authz.perm("host.admin", host="host_id"))):
    await stepup.require_host_stepup(host_id, user)   # F-05: ştergerea unui host cu 2FA e o acţiune de host
    live = await db.fetchone(
        "SELECT id FROM sessions WHERE host_id=? AND state IN ('creating','live')",
        host_id)
    if live:
        raise ApiError(409, "host.hasLiveSessions", "the host has live sessions; close them first")
    await _refuse_if_jump_children(host_id)
    conn = core.sources.pop(host_id, None)
    if conn:
        try:
            # prin interfața SessionSource, NU `conn.ws` — doar AgentConnection are `.ws`;
            # pt. un host SSH (SshSource) `conn.ws` dădea AttributeError înghițit → conexiunea
            # SSH nu se închidea niciodată (leak). `disconnect()` e definit pt. toate sursele.
            await conn.disconnect()
        except Exception:
            pass
    # Nimic nu cade automat: PRAGMA foreign_keys nu e setat, deci FOREIGN KEY ... ON DELETE CASCADE
    # e inactiv, iar id-urile de host se reutilizează (INTEGER PRIMARY KEY fără AUTOINCREMENT).
    # Aici se ştergeau doar `connections` (audit v53) — hostul următor cu acelaşi id moştenea
    # forward-urile, sesiunile, cheia de deploy şi evenimentele celui vechi (G-12). `purge_host`
    # curăţă TOT ce referenţiază hostul (transcripturile se arhivează, nu rămân orfane); cu
    # curăţarea completă, reutilizarea id-ului e inofensivă — nu rescriem tabelul la AUTOINCREMENT.
    await _purge_host_rows(host_id)
    return {"ok": True}


async def _purge_host_rows(host_id: int) -> None:
    """`core.purge_host` tradus în răspuns HTTP: copiii jump persistenţi → 409 cu cod stabil."""
    try:
        await core.purge_host(host_id)
    except core.HostHasDependents as e:
        raise ApiError(409, "host.hasJumpChildren",
                       "saved jump targets are routed through this host (ids %s); re-route or "
                       "delete them first" % ", ".join(str(c) for c in e.children[:5]))


@router.post("/api/hosts/{host_id}/uninstall")
async def uninstall_host(host_id: int, force: bool = False,
                         user=Depends(authz.perm("host.admin", host="host_id"))):
    """Dezinstalează COMPLET agentul de pe server: îi cere să-și scoată supravegherea
    (systemd/cron) + serverul tmux + fișierele din ~/.webterm/ și să iasă, apoi îl scoate din
    WebTerm. Hosturile directe SSH/telnet n-au nimic instalat → doar scoatere din WebTerm.
    `force=1`: scoate doar din WebTerm chiar dacă agentul e offline (fișierele rămân pe host)."""
    await stepup.require_host_stepup(host_id, user)   # H1
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    live = await db.fetchone(
        "SELECT id FROM sessions WHERE host_id=? AND state IN ('creating','live')", host_id)
    if live:
        raise ApiError(409, "host.hasLiveSessions", "the host has live sessions; close them first")
    await _refuse_if_jump_children(host_id)     # înainte să-i cerem agentului să se dezinstaleze

    ctype = conntypes.of(row)
    uninstalled = False
    warnings = []
    if ctype == "agent":
        conn = core.sources.get(host_id)
        if isinstance(conn, core.AgentConnection):
            try:
                resp = await conn.request("uninstall", timeout=20)
                uninstalled = bool(resp.get("ok"))
                warnings = resp.get("warnings", []) or []
            except (core.AgentGone, asyncio.TimeoutError):
                if not force:
                    raise ApiError(409, "host.uninstallNoAnswer",
                                   "the agent did not answer; retry while it is online, "
                                   "or pass force=1 to drop it from WebTerm only "
                                   "(the files stay on the server, to be cleaned up by hand)")
        elif not force:
            raise ApiError(409, "host.uninstallOffline",
                           "the agent is offline; it cannot be uninstalled remotely "
                           "right now. Bring it online and retry, or pass force=1 to "
                           "drop it from WebTerm only.")

    c = core.sources.pop(host_id, None)
    if c and not uninstalled:
        try:
            await c.disconnect()
        except Exception:
            pass
    await _purge_host_rows(host_id)     # curăţare completă, vezi delete_host (G-12)
    return {"ok": True, "uninstalled": uninstalled, "warnings": warnings}


class AutostartIn(BaseModel):
    enable: bool
    stepup_grant: str = ""       # 2FA: grant/parolă pt. host-uri cu require_2fa (H1)
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


AUTOSTART_MIN_AGENT = 57         # op-ul `autostart` există din agentul v57


@router.post("/api/hosts/{host_id}/autostart")
async def host_autostart(host_id: int, body: AutostartIn, request: Request,
                         user=Depends(authz.perm('host.admin', host='host_id'))):
    """Porneşte / opreşte pornirea agentului la boot (systemd --user, altfel cron — ca
    instalatorul). Agentul care rulează ACUM nu e atins: efectul e la următorul reboot.
    Răspunsul poartă starea NOUĂ citită înapoi de agent, stocată imediat (badge-ul din sidebar
    nu aşteaptă diagnosticul orar). Fără root, `linger` rămâne de obicei oprit → `hint`."""
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)   # H1
    audit.detail(request, "autostart %s" % ("enable" if body.enable else "disable"))
    row = await db.fetchone("SELECT id, connection_type FROM hosts WHERE id=?", host_id)
    if not row:
        raise ApiError(404, "host.missing", "no such host")
    if not conntypes.is_agent(row):
        raise ApiError(400, "host.autostartNotAgent",
                       "only hosts with an agent have something to start at boot")
    conn = core.sources.get(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise ApiError(409, "host.offline", "the host is offline; its agent is not connected")
    if (conn.agent_version or 0) < AUTOSTART_MIN_AGENT:
        raise ApiError(409, "host.autostartAgentOld",
                       "the agent on this host is too old to change autostart (needs v%d, has v%s); "
                       "update it first" % (AUTOSTART_MIN_AGENT, conn.agent_version),
                       vars={"need": AUTOSTART_MIN_AGENT, "have": conn.agent_version or 0})
    try:
        resp = await conn.request("autostart", enable=body.enable, timeout=30)
    except (core.AgentGone, asyncio.TimeoutError):
        raise ApiError(504, "host.noAnswer", "the host did not answer in time")
    sup = core.supervision_summary({"supervision": resp.get("supervision")})
    if sup:
        await db.execute("UPDATE hosts SET supervision_summary=? WHERE id=?",
                         json.dumps(sup), host_id)
    if not resp.get("ok"):
        raise ApiError(400, "host.autostartFailed",
                       "could not change autostart: %s" % core.clip(resp.get("msg") or
                                                                    resp.get("code") or "?", 300),
                       vars={"reason": core.clip(resp.get("msg") or "", 200) or ""})
    return {"ok": True, "supervision": sup, "hint": core.clip(resp.get("hint") or "", 500) or ""}


# ── [hosts-test] Testul de conexiune din Add host + cheia generată la creare (3.5.4) ──────
# `POST /api/hosts/test` rulează dial-ul real (core.probe_ssh / probe_telnet) cu câmpurile din
# formular, fără să salveze nimic. Poate sonda ORICE gazdă:port, adică e un scaner de porturi
# din interiorul reţelei gazdei — de-aia: doar cookie (nu token de automatizare), plafon per
# user, metadatele cloud blocate (după rezolvare, nu doar pe text), portul validat, audit fără
# credenţial. Credenţialul din cerere trăieşte doar în memorie, pe durata testului.


# Aceeaşi listă ca la webhook / SMTP: reţelele private rămân permise (un server SSH în LAN e
# exact ţinta unui produs self-hosted), doar serviciul de metadate al cloudului e refuzat.
_METADATA_HOSTS = ("169.254.169.254", "metadata.google.internal", "fd00:ec2::254")


def _is_metadata_target(host: str) -> bool:
    """Numele sau adresa (inclusiv forma IPv4-mapată `::ffff:169.254.169.254`) e cea de metadate."""
    import ipaddress
    h = (host or "").strip().strip("[]").lower().rstrip(".")
    if h in _METADATA_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(h.split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip) in _METADATA_HOSTS


HOSTTEST_RATE = 10              # teste per user …


HOSTTEST_WINDOW = 60.0          # … pe fereastra asta (secunde)


_hosttest_hits: dict = {}       # user_id -> [monotonic, …]


def _hosttest_rate(user_id) -> None:
    now = time.monotonic()
    hits = [t for t in _hosttest_hits.get(user_id, []) if now - t < HOSTTEST_WINDOW]
    if len(hits) >= HOSTTEST_RATE:
        retry = int(HOSTTEST_WINDOW - (now - hits[0])) + 1
        _hosttest_hits[user_id] = hits
        raise ApiError(429, "hosttest.rateLimited",
                       "too many connection tests; retry in %ds" % retry,
                       headers={"Retry-After": str(retry)}, vars={"retry": retry})
    hits.append(now)
    _hosttest_hits[user_id] = hits


def _remember_tested_hostkey(target: tuple, keyline: str, fp: str) -> None:
    now = time.monotonic()
    for k in [k for k, v in hostmodel.tested_hostkeys.items() if now - v[2] > hostmodel.HOSTKEY_TEST_TTL]:
        hostmodel.tested_hostkeys.pop(k, None)
    if len(hostmodel.tested_hostkeys) > 2000:            # plafon dur: cel mai vechi pleacă
        hostmodel.tested_hostkeys.pop(min(hostmodel.tested_hostkeys, key=lambda k: hostmodel.tested_hostkeys[k][2]), None)
    hostmodel.tested_hostkeys[target] = (keyline, fp, now)


async def _pending_key(user_id, pending_id: str):
    """Rândul cheii în aşteptare — al ACESTUI user şi neexpirat — sau 400."""
    row = None
    if pending_id:
        row = await db.fetchone(
            "SELECT * FROM pending_ssh_keys WHERE id=? AND user_id=? AND created>=?",
            pending_id, user_id, time.time() - core.PENDING_KEY_TTL)
    if not row:
        raise ApiError(400, "sshkey.pendingMissing",
                       "the generated key expired or does not exist — generate a new one")
    return row


@router.post("/api/hosts/ssh-key/pending")
async def pending_ssh_key(request: Request, user=Depends(authz.perm("hosts.create"))):
    """Generează o pereche Ed25519 ÎNAINTE ca hostul să existe (formularul Add host): privata
    stă criptată în seif, legată de user, ~1h; întoarce publica + `pending_key_id`. Create /
    update cu `pending_key_id` o leagă de host ca credenţial stocat. Doar Ed25519."""
    await core.purge_pending_ssh_keys()
    # plafon per user: cele mai vechi pleacă (un dublu-click nu blochează pe nimeni o oră)
    old = await db.fetchall("SELECT id FROM pending_ssh_keys WHERE user_id=? ORDER BY created DESC",
                            user["id"])
    for r in old[core.PENDING_KEYS_PER_USER - 1:]:
        await db.execute("DELETE FROM pending_ssh_keys WHERE id=?", r["id"])
    k = asyncssh.generate_private_key("ssh-ed25519", comment="webterm")
    pub = k.export_public_key().decode().strip()
    fp = k.get_fingerprint()
    pid = security.new_token()[:32]
    now = time.time()
    await db.execute(
        "INSERT INTO pending_ssh_keys(id, user_id, credential_encrypted, public_key, fingerprint, created)"
        " VALUES(?,?,?,?,?,?)", pid, user["id"],
        security.encrypt_secret(json.dumps({"key": k.export_private_key().decode()})), pub, fp, now)
    audit.detail(request, "generated a pending SSH key %s" % fp)
    return {"pending_key_id": pid, "public_key": pub, "fingerprint": fp,
            "expires": now + core.PENDING_KEY_TTL}


class HostTestIn(BaseModel):
    connection_type: str = "ssh"         # ssh | ssh-jump | telnet | telnet-jump
    hostname: str = ""
    ssh_port: Optional[int] = None       # None = portul implicit al protocolului
    ssh_username: str = ""
    auth_method: str = "password"        # password | key
    credential: str = ""                 # write-only, doar în memorie pe durata testului
    passphrase: str = ""
    via_host_id: int = 0                 # familia jump: agentul prin care tunelăm
    host_id: int = 0                     # editare: hostul existent (credenţialul stocat + pinul lui)
    pending_key_id: str = ""             # cheia generată în formular, încă nelegată
    # lot 2: cheia publică pe care omul a văzut-o (amprenta) şi o acceptă — abia atunci testul
    # trimite PAROLA; fără ea, la primul contact testul se opreşte la host key
    trust_hostkey: str = ""
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey)


# Etapa picată → cod i18n, când clasa e a testului (TCP, banner, pin…). Cauzele care au deja un
# cod la conectarea reală (auth respinsă, agent care nu ajunge la ţintă, eroare SSH) trec prin
# `hostmodel.ssh_dial_error`, ca formularul să arate EXACT mesajul pe care l-ar vedea omul la conectare.
_HOSTTEST_CODES = (
    ("tcp:dns", "hosttest.dns"),
    ("tcp:refused", "hosttest.refused"),
    ("tcp:unreachable", "hosttest.unreachable"),
    ("tcp:timeout", "hosttest.tcpTimeout"),
    ("banner:not_ssh", "hosttest.notSsh"),
    ("banner:closed", "hosttest.closed"),
    ("banner:silent", "hosttest.telnetSilent"),
    ("hostkey:mismatch", "hosttest.hostKeyMismatch"),
    ("hostkey:timeout", "hosttest.timeout"),
    ("auth:timeout", "hosttest.timeout"),
    ("auth:skipped", "hosttest.authSkipped"),
)


def _hosttest_stage(st: dict, row: dict, ssh: bool, expected_fp: str = "", offered_fp: str = "") -> dict:
    """Etapa din core → forma publică {id, ok, ms?, code?, vars?, detail?, warn?, skipped?}.
    Excepţia (cu textul ei englezesc) NU iese din server — doar codul."""
    out = {"id": st["id"], "ok": bool(st["ok"])}
    for f in ("ms", "detail", "warn", "skipped"):
        if st.get(f) is not None:
            out[f] = st[f]
    if st["ok"]:
        return out
    kind, exc = st.get("kind") or "", st.get("exc")
    code = dict(_HOSTTEST_CODES).get("%s:%s" % (st["id"], kind)) if kind else None
    if st["id"] == "banner" and kind == "timeout":
        code = "ssh.noBanner" if ssh else "hosttest.closed"
    if code is None:
        if exc is not None:
            err = hostmodel.ssh_dial_error(exc, row)
            code = err.code
            if err.vars:
                out["vars"] = err.vars
        else:
            code = "hosttest.failed"
    if code == "hosttest.hostKeyMismatch":
        out["vars"] = {"old_fp": expected_fp, "new_fp": offered_fp}
    out["code"] = code
    return out


# INV-01 (docs/design/INVARIANTS.md): parola stocată se folosește doar pe ACEEAȘI țintă.
@router.post("/api/hosts/test")
async def test_host_connection(body: HostTestIn, request: Request, user=Depends(authz.perm('hosts.create'))):
    """„Test connection" din Add host / Edit host: tcp → banner → host key → auth, cu dial-ul real,
    fără să salveze nimic. Întoarce {ok, stages, hostkey?}; textul îl pune UI-ul din coduri."""
    ctype = body.connection_type or ""
    if ctype not in conntypes.NETWORK:
        raise ApiError(400, "hosttest.badType", "connection tests are for ssh, ssh-jump, telnet and telnet-jump")
    ssh = ctype in conntypes.SSH_FAMILY
    hostname = body.hostname.strip()
    # urma în jurnal ÎNAINTE de orice refuz: o sondă blocată (metadate, plafon) contează la audit
    audit.detail(request, "connection test (%s) to %s:%s" % (ctype, hostname[:200], body.ssh_port or ""))
    if not hostname:
        raise ApiError(400, "host.hostnameRequired", "hostname required for a direct connection")
    port = body.ssh_port if body.ssh_port is not None else (22 if ssh else 23)
    if not 1 <= int(port) <= 65535:
        raise ApiError(400, "hosttest.badPort", "the port must be between 1 and 65535")
    if ssh and not body.ssh_username.strip():
        raise ApiError(400, "ssh.userRequired", "an SSH username is required")
    if len(hostname) > 253 or any(c.isspace() or ord(c) < 32 for c in hostname):
        raise ApiError(400, "hosttest.badHost", "not a valid host name or address")
    row = None
    # 3.6: testul foloseşte credenţialul STOCAT al hostului editat → `host.edit` pe el; o ţintă
    # jump deschide TCP din agentul `via` → `forward.manage` acolo (§A.11.4). Ambele înainte de
    # existenţă/step-up: un host invizibil dă 404 ca unul inexistent.
    if body.host_id:
        await authz.require_on(request, body.host_id, "host.edit")
    if ctype in conntypes.JUMP and body.via_host_id:
        await authz.require_on(request, body.via_host_id, "forward.manage")
    if body.host_id:
        row = await db.fetchone("SELECT * FROM hosts WHERE id=?", body.host_id)
        if not row:
            raise ApiError(404, "host.missing", "no such host")
        # testul cu credenţialul STOCAT al unui host = conectare la el: aceleaşi cerinţe de step-up
        await stepup.require_host_stepup(body.host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    _hosttest_rate(user["id"])
    if _is_metadata_target(hostname):
        raise ApiError(400, "hosttest.blocked", "that address is the cloud metadata service")
    via = body.via_host_id if ctype in conntypes.JUMP else 0
    if via:
        vrow = await db.fetchone("SELECT connection_type FROM hosts WHERE id=?", via)
        if not vrow or not conntypes.is_agent(vrow):
            raise ApiError(400, "sshjump.needsAgent", "pick an agent host to reach the target through")
        if not isinstance(core.sources.get(via), core.AgentConnection):
            raise ApiError(409, "hosttest.viaOffline", "the jump host's agent is offline — the test needs it online")
    elif ctype in conntypes.JUMP:
        raise ApiError(400, "sshjump.needsAgent", "pick an agent host to reach the target through")

    # credenţialul: cheia generată > ce s-a tastat > cel stocat al hostului editat (doar dacă
    # metoda e aceeaşi — altfel parola stocată ar fi încercată drept cheie). Nimic → auth sărit.
    auth = "key" if body.auth_method == "key" else "password"
    cred = None
    if ssh:
        if body.pending_key_id:
            pk = await _pending_key(user["id"], body.pending_key_id)
            cred, auth = hostmodel.decode_credential(pk["credential_encrypted"]), "key"
        elif body.credential:
            cred = ({"key": body.credential, "passphrase": body.passphrase or None} if auth == "key"
                    else {"password": body.credential})
        elif (row is not None and row["credential_encrypted"] and row["credential_policy"] != "ask"
              and (row["auth_method"] or "password") == auth
              and (auth == "key" or not _retargets(row, ctype, hostname, port, via))):
            # parola stocată doar spre ţinta pentru care a fost salvată (lot 2): pe o adresă nouă
            # testul sare peste auth, ca la politica „ask" — nu trimite parola unui server nou
            cred = hostmodel.decode_credential(row["credential_encrypted"])
        if cred is not None and auth == "key":
            try:
                asyncssh.import_private_key(cred.get("key") or "", cred.get("passphrase") or None)
            except Exception:                           # noqa: BLE001 — cheie greşită / passphrase greşit
                raise ApiError(400, "hosttest.badKey",
                               "the private key could not be read — wrong passphrase, or not a private key")
    target = {"id": body.host_id or 0, "name": row["name"] if row else hostname,
              "connection_type": ctype, "hostname": hostname, "ssh_port": int(port),
              "ssh_username": body.ssh_username.strip(), "auth_method": auth,
              "via_host_id": via or None, "known_hosts": None}
    # hostul editat, pe ACEEAŞI ţintă, are deja un pin: testul îl verifică (şi refuză înainte
    # de auth dacă diferă) — exact ce ar face conectarea reală.
    expected = ""
    if (ssh and row is not None and row["known_hosts"]
            and (row["hostname"] or "").lower() == hostname.lower()
            and int(row["ssh_port"] or 22) == int(port)
            and (row["via_host_id"] or 0) == (via or 0)):
        expected = row["known_hosts"]
    # Primul contact cu PAROLĂ (fără pin): parola pleacă abia după ce omul a văzut amprenta şi a
    # acceptat-o (`trust_hostkey`), ca la OpenSSH. Probe-ul refuză ÎNAINTE de auth o cheie oferită
    # diferită de cea acceptată. Fără acceptare: doar până la host key (raport 2026-11, lot 2).
    needs_trust = False
    if ssh and not expected and cred is not None and auth == "password":
        trusted = (body.trust_hostkey or "").strip()
        if trusted:
            try:
                asyncssh.import_public_key(trusted)
            except Exception:                           # noqa: BLE001
                raise ApiError(400, "hosttest.badTrustKey", "that is not an SSH public key")
            expected = trusted
        else:
            cred, needs_trust = None, True

    # rezolvare + poartă de metadate pe ADRESELE rezultate (un nume care rezolvă la 169.254.169.254
    # nu trece). Jump: rezolvă agentul, în reţeaua lui — verificăm best-effort şi local.
    addrs, pre = None, None
    try:
        resolved = await core.resolve_target(hostname, int(port))
    except core.ProbeFailed as pf:
        resolved = []
        if not via:
            pre = pf
    if any(_is_metadata_target(sa[0]) for _f, sa in resolved):
        raise ApiError(400, "hosttest.blocked", "that address is the cloud metadata service")
    if not via:
        addrs = resolved

    if pre is not None:
        res = {"stages": [{"id": "tcp", "ok": False, "ms": 0, "kind": pre.kind, "exc": pre.exc}],
               "hostkey": None}
    else:
        probe = (core.probe_ssh(target, cred, addrs, expected) if ssh
                 else core.probe_telnet(target, addrs))
        try:
            # plasa de siguranţă: probe-ul îşi respectă singur bugetul de PROBE_TIMEOUT
            res = await asyncio.wait_for(probe, core.PROBE_TIMEOUT + 3)
        except asyncio.TimeoutError:
            res = {"stages": [{"id": "tcp", "ok": False, "kind": "timeout"}], "hostkey": None}

    expected_fp = core.hostkey_fingerprint(expected) if expected else ""
    hk = res.get("hostkey")
    stages = [_hosttest_stage(st, target, ssh, expected_fp, hk["fingerprint_sha256"] if hk else "")
              for st in res["stages"]]
    ok = bool(stages) and all(s["ok"] or s.get("warn") or s.get("skipped") for s in stages)
    hostkey_ok = any(s["id"] == "hostkey" and s["ok"] for s in stages)
    if needs_trust and hostkey_ok:
        # nu „reuşit": sign-in-ul aşteaptă confirmarea amprentei (UI: „Trust and test sign-in")
        for st in stages:
            if st["id"] == "auth":
                st.update(ok=False, skipped=True, code="hosttest.confirmHostkey")
        ok = False
    out = {"ok": ok, "stages": stages}
    if needs_trust and hostkey_ok:
        out["needs_trust"] = True
    if hk:
        out["hostkey"] = {"type": hk["type"], "fingerprint_sha256": hk["fingerprint_sha256"]}
        if hostkey_ok:
            # cheia pe care create/update o vor accepta ca `pin_hostkey` (şi doar pe ea)
            out["hostkey"]["key"] = hk["key"]
            _remember_tested_hostkey(hostmodel.test_target(user["id"], ctype, hostname, port, via),
                                     hk["key"], hk["fingerprint_sha256"])
    failed = next((s for s in stages if not s["ok"] and not s.get("warn") and not s.get("skipped")), None)
    audit.detail(request, "connection test (%s) to %s:%s%s → %s" % (
        ctype, hostname, port, " via host #%d" % via if via else "",
        "ok" if not failed else "failed at %s (%s)" % (failed["id"], failed.get("code", ""))))
    return out
