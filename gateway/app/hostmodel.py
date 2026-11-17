"""Hosts: the model and the helpers shared by the host routes (`hosts_api.py`) and the rest of the
API (`api.py`): the HostIn body, tags, stored credentials (encrypt / decode / resolve, INV-01),
the credential policy, direct SSH / telnet dialling, online / updates summaries, the install
one-liners, validate + insert of a new host, and the host-key pins verified by the Add-host test
(INV-02) that a later create picks up. No routes here, and nothing here imports api.py.
"""
import asyncio
import json
import logging
import re
import time

import asyncssh

from pydantic import BaseModel
from typing import Optional


from .errors import ApiError, rate_limited
from . import (authz, config, core,
               db, security, conntypes)

log = logging.getLogger("webterm")


def hostkey_alarm(row):
    """Alarma de host-key schimbat de pe rândul hostului → dict pentru UI (fără cheia brută),
    sau None. `hostkey_alarm` vine dintr-o migraţie, deci verificăm prezenţa coloanei."""
    raw = row["hostkey_alarm"] if "hostkey_alarm" in row.keys() else None
    if not raw:
        return None
    try:
        a = json.loads(raw)
    except ValueError:
        return None
    return {"old_fp": a.get("old_fp") or "", "new_fp": a.get("new_fp") or "",
            "changed_at": a.get("changed_at"),
            # primul contact (lot 2): nu e o schimbare, e o amprentă de confirmat înainte de parolă
            "first": bool(a.get("first"))}


# Parola de instalare ajunge INTERPOLATĂ în one-liner-ul copiat de admin (curl -H 'X-Enroll-Pass: …',
# iar la userul dedicat şi într-un `sh -c '…'`): un apostrof sau `$(…)` ar rupe/altera exact comanda
# pe care o lipeşti pe host. Alfabet strict + plafon de lungime (argon2 pe input nelimitat = CPU
# gratuit pentru oricine loveşte endpointul). Face adevărat comentariul „generată/validată" de la
# emitere, care până acum promitea o validare inexistentă (audit 2026-09).
_ENROLL_PASS_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


def clean_enroll_pass(raw: str) -> str:
    p = (raw or "").strip()
    if p and not _ENROLL_PASS_RE.fullmatch(p):
        raise ApiError(400, "enroll.badPassChars",
                       "install password: letters, digits, . _ - only, max 64 characters")
    return p


class HostIn(BaseModel):
    name: str
    note: str = ""
    folder: str = ""
    # conectare directă (agent = comportamentul clasic, fără câmpurile de mai jos)
    connection_type: str = "agent"       # agent | ssh | ssh-jump | telnet
    hostname: str = ""
    ssh_username: str = ""
    # None = „portul implicit al protocolului" (22 ssh, 23 telnet), hotărât server-side în
    # create_host. Era `int = 22` necondiţionat, iar `host_row["ssh_port"] or 23` din core nu se
    # declanşa niciodată → telnet/telnet-jump create prin API sunau la 22. UI-ul trimite mereu
    # portul explicit (AddHostModal pune 23 la telnet), deci contractul lui nu se schimbă.
    ssh_port: Optional[int] = None
    via_host_id: int = 0                 # ssh-jump: hostul-agent prin al cărui tunel ajungem
    auth_method: str = "password"        # password | key
    credential: str = ""                 # write-only: parola sau cheia privată
    passphrase: str = ""                 # write-only: passphrase-ul cheii
    require_2fa: bool = False
    credential_policy: str = "stored"    # stored | ask | ephemeral
    tags: str = ""                       # etichete libere, virgulă/spaţiu separat (normalizate)
    # „Conectează o dată" (fără salvare): creează o ţintă ssh-jump/telnet-jump EFEMERĂ, doar
    # ca să deschizi o sesiune acum. Ascunsă din sidebar; reaper-ul o şterge când moare sesiunea.
    ephemeral: bool = False
    # Înrolare (doar agent): cât e valid link-ul + o parolă temporară OPŢIONALĂ cerută la instalare
    enroll_ttl: int = 3600               # secunde; implicit 1h (plafonat 5min..30 zile)
    enroll_password: str = ""            # write-only; gol = fără parolă
    # Testul de conexiune (POST /api/hosts/test): cheia de host văzută de test. Serverul o
    # acceptă DOAR dacă e exact cea din cache-ul testului (user + ţintă, ~10 min) — altfel un
    # client ar putea pina o cheie arbitrară. Gol = TOFU la prima conectare, ca până acum.
    pin_hostkey: str = ""
    # Cheia generată în formular (POST /api/hosts/ssh-key/pending): privata, deja în seif, devine
    # credenţialul stocat al hostului (auth key, politica `stored`); rândul în aşteptare se şterge.
    pending_key_id: str = ""


MAX_TAGS = 20


def tag_list(s: str, limit: Optional[int] = MAX_TAGS) -> list:
    """Lista de etichete normalizate: lowercase, fără spaţii/duplicate, max 32 de caractere
    fiecare. `limit=None` NU taie — ţintele de snippet vor să ştie câte au venit, ca să refuze
    peste plafon în loc să piardă în tăcere etichetele de la coadă."""
    seen, out = set(), []
    for tag in authz.tag_tokens(s):    # acelaşi tokenizer ca potrivirea scope-urilor (authz)
        if tag not in seen:
            seen.add(tag)
            out.append(tag)
        if limit is not None and len(out) >= limit:
            break
    return out


def norm_tags(s: str) -> str:
    """Normalizează etichetele: lowercase, fără spaţii/duplicate, plafon de număr şi lungime
    (un host compromis... nu, hosturile nu-şi setează tag-urile — dar UI-ul poate trimite orice)."""
    return ",".join(tag_list(s))


# Politicile de credenţiale cunoscute. Serverul accepta ORICE text: un `credential_policy` scris
# greşit printr-un client API (`"Ask"`, `"never"`) era tratat ca `stored` în unele locuri şi ca
# altceva în altele (3.5.2). Refuzăm la intrare, cu cod.
_CRED_POLICIES = ("stored", "ask", "ephemeral")


def check_cred_policy(policy: str) -> None:
    if policy not in _CRED_POLICIES:
        raise ApiError(400, "host.badCredentialPolicy",
                       "credential_policy must be one of: %s" % ", ".join(_CRED_POLICIES),
                       vars={"allowed": ", ".join(_CRED_POLICIES)})


def credential_blob(h: "HostIn"):
    """Fernet blob holding the credentials, or None (agent host / `ask` policy / empty)."""
    if h.connection_type == "agent" or h.credential_policy == "ask" or not h.credential:
        return None
    if h.auth_method == "key":
        payload = {"key": h.credential}
        if h.passphrase:
            payload["passphrase"] = h.passphrase
    else:
        payload = {"password": h.credential}
    return security.encrypt_secret(json.dumps(payload))


def decode_credential(blob: str) -> dict:
    """Blobul de credenţiale din seif → {password} / {key, passphrase?}.
    Formatul e JSON (vezi `credential_blob`). EXCEPŢIE moştenită: `/ssh-key/generate` scria până
    în 3.5.4 PEM-ul GOL, nu JSON — iar conectarea cu un astfel de host crăpa cu JSONDecodeError
    (500) la `json.loads`. Rândurile vechi rămân citibile: un PEM gol devine {key}."""
    raw = security.decrypt_secret(blob)
    try:
        cred = json.loads(raw)
    except ValueError:
        cred = None
    if isinstance(cred, dict):
        return cred
    if raw.lstrip().startswith("-----BEGIN"):
        return {"key": raw}
    raise ApiError(400, "sshkey.badKey", "the stored credential is unreadable")


def _resolve_credential(row, body_credential="", body_passphrase=""):
    """Credențialele de folosit la conectare: din request (politică `ask`) sau
    decriptate din seif. Returnează dict {password} sau {key, passphrase?}."""
    if row["credential_policy"] == "ask":
        if not body_credential:
            raise ApiError(400, "host.credentialsRequired", "credentials required (policy: ask every time)")
        if row["auth_method"] == "key":
            return {"key": body_credential, "passphrase": body_passphrase or None}
        return {"password": body_credential}
    if not row["credential_encrypted"]:
        raise ApiError(400, "host.noStoredCredentials", "no stored credentials for this host")
    return decode_credential(row["credential_encrypted"])


async def connect_direct(row, request, body_credential="", body_passphrase=""):
    """Ensure a connected SSH source for the host (dial + pin the host key). Rate-limited.
    `ssh-jump` dials over the agent tunnel (dial_ssh_jump); plain `ssh` dials a direct socket."""
    if isinstance(core.sources.get(row["id"]), core.SshSource):
        return
    ip = security.client_ip(request)
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        raise rate_limited(retry)
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    # Alarmă de host-key NEREZOLVATĂ → refuz FĂRĂ dial. Fail-closed era deja (dial-ul pica la
    # fiecare încercare), dar redialul (a) retrimitea cererea spre o ţintă suspectă la fiecare
    # click şi (b) făcea starea invizibilă între două toast-uri. Acum hostul stă blocat, cu
    # amprentele la vedere, până când omul le verifică out-of-band şi apasă „accept" (sau
    # resetează pinul mutând hostul). (audit UX §6.e1/§6.e2)
    alarm = hostkey_alarm(row)
    if alarm and alarm["first"]:
        raise ApiError(409, "ssh.hostKeyUnverified",
                       "first connection: confirm the host key fingerprint %s before signing in"
                       % (alarm["new_fp"] or "?"), vars={"new_fp": alarm["new_fp"]})
    if alarm:
        raise ApiError(409, "ssh.hostKeyChanged",
                       "the host key fingerprint changed (%s → %s) — possible MITM; connection "
                       "refused until the new key is reviewed" % (alarm["old_fp"] or "?", alarm["new_fp"] or "?"),
                       vars={"old_fp": alarm["old_fp"], "new_fp": alarm["new_fp"]})
    cred = _resolve_credential(row, body_credential, body_passphrase)
    jump = (row["connection_type"] or "") == "ssh-jump"
    try:
        if jump:
            await core.dial_ssh_jump(row, cred)
        else:
            await core.dial_ssh(row, cred)
    except (core.ForwardError, core.HostKeyMismatch, asyncssh.Error, OSError,
            asyncio.TimeoutError) as e:
        if isinstance(e, asyncssh.PermissionDenied):
            security.record_login_failure(ip)
        raise ssh_dial_error(e, row)
    security.record_login_success(ip)


def ssh_dial_error(e: BaseException, row) -> ApiError:
    """Clasificatorul COMUN al eşecurilor de dial SSH (direct / jump): conectarea reală
    (`connect_direct`) şi testul de conexiune (`POST /api/hosts/test`) dau ACELAŞI cod pentru
    aceeaşi cauză, deci omul vede acelaşi mesaj în formular şi la prima conectare."""
    if isinstance(e, core.ForwardError):
        # agentul nu poate deschide TCP spre ţintă (refuzat / fără rută / gazdă greşită)
        return ApiError(502, "sshjump.unreachable",
                        "the agent could not reach %s:%s — %s"
                        % (row["hostname"], row["ssh_port"] or 22, e))
    if isinstance(e, core.HostKeyUnverified) and not e.new_fp:
        # serverul n-a prezentat o cheie pe care s-o putem arăta: nimic de confirmat, nimic trimis
        return ApiError(502, "ssh.hostKeyUnreadable",
                        "the server did not present a host key WebTerm can show — nothing was sent")
    if isinstance(e, core.HostKeyUnverified):
        return ApiError(409, "ssh.hostKeyUnverified",
                        "first connection: confirm the host key fingerprint %s before signing in"
                        % (e.new_fp or "?"), vars={"new_fp": e.new_fp})
    if isinstance(e, core.HostKeyMismatch):
        return ApiError(409, "ssh.hostKeyChanged",
                        "the host key fingerprint changed (%s → %s) — possible MITM; connection refused"
                        % (e.old_fp or "?", e.new_fp or "?"),
                        vars={"old_fp": e.old_fp, "new_fp": e.new_fp})
    if isinstance(e, asyncssh.PermissionDenied):
        # ţinta a răspuns, dar a RESPINS credenţialele (user/parolă greşite ori metodă nepotrivită)
        return ApiError(401, "ssh.authFailed",
                        "%s@%s rejected the credentials — wrong password, or the server wants a key"
                        % (row["ssh_username"] or "", row["hostname"]))
    if isinstance(e, asyncio.TimeoutError):
        # TCP s-a conectat, dar NICIUN banner SSH în SSH_CONNECT_TIMEOUT: aproape sigur
        # portul e greşit / nu e un server SSH acolo / e filtrat. `str(TimeoutError)` e gol,
        # deci construim noi un mesaj cu sens (altfel UI-ul arăta „cannot connect: ").
        return ApiError(504, "ssh.noBanner",
                        "no SSH greeting from %s:%s within %ds — wrong port, not an SSH server, "
                        "or filtered" % (row["hostname"], row["ssh_port"] or 22, core.SSH_CONNECT_TIMEOUT))
    return ApiError(502, "ssh.connectFailed", f"cannot connect over SSH: {e or type(e).__name__}")


async def connect_telnet(row, request, body_credential=""):
    """Asigură o sursă Telnet conectată (dial + auto-login best-effort). Rate-limited."""
    if isinstance(core.sources.get(row["id"]), core.TelnetSource):
        return
    ip = security.client_ip(request)
    allowed, retry = security.login_allowed(ip)
    if not allowed:
        raise rate_limited(retry)
    await security.apply_global_tarpit(retry)   # F-02: frână, nu poartă
    password = ""
    if row["credential_policy"] == "ask":
        password = body_credential or ""
    elif row["credential_encrypted"]:
        password = decode_credential(row["credential_encrypted"]).get("password", "")
    creds = {"username": row["ssh_username"] or "", "password": password}
    try:
        await core.dial_telnet(row, creds)
    except (OSError, asyncio.TimeoutError, ConnectionRefusedError) as e:
        raise ApiError(502, "telnet.connectFailed", f"cannot connect over Telnet: {e or type(e).__name__}")
    security.record_login_success(ip)


def host_updates(row) -> dict | None:
    """Rezumatul update-urilor OS (agent v51+): {count, security, manager}, pentru badge-ul din
    sidebar — număr, fără lista pachetelor (aia se cere la deschiderea panoului).
    Citit din coloana `updates_summary`, scrisă la primirea diagnosticului (core.updates_summary):
    listarea hosturilor e poll la 5 s per client şi parsa tot blobul de diagnostic pentru FIECARE
    host — un agent compromis cu un snapshot mare scumpea fiecare poll (audit 2026-10-04, S-03).
    None dacă agentul nu raportează încă (v50) sau verificarea e dezactivată pe host.
    Fallback: rând de dinaintea coloanei (NULL) → parsăm blobul vechi, dar DOAR sub plafon."""
    keys = row.keys()
    if "updates_summary" in keys and row["updates_summary"] is not None:
        if not row["updates_summary"]:
            return None
        try:
            u = json.loads(row["updates_summary"])
        except (TypeError, ValueError):
            return None
        return u if isinstance(u, dict) and isinstance(u.get("count"), int) else None
    if "diagnostics" not in keys or not row["diagnostics"]:
        return None
    if len(row["diagnostics"]) > core.DIAG_MAX_BYTES:
        return None        # blob moştenit peste plafon: nu-l re-parsăm la fiecare poll
    try:
        d = json.loads(row["diagnostics"])
    except (TypeError, ValueError):
        return None
    # un agent compromis/buggy poate fi stocat un JSON top-level NON-obiect (`[1,2]`, `42`):
    # core.updates_summary verifică tipul înainte de .get — altfel un singur host otrăvit dădea
    # 500 pe toată lista.
    return core.updates_summary(d)


def host_online(row) -> bool:
    """Hostul e „online" = i se poate deschide o sesiune ACUM. Pentru agent/ssh/telnet direct
    înseamnă o sursă proprie în `core.sources`. Pentru familia jump (ssh-jump, telnet-jump)
    sesiunile se deschid prin tunelul AGENTULUI `via_host_id` (core.create_telnet_jump_session /
    dial_ssh_jump), iar telnet-jump nu înregistrează NIMIC sub propriul id (sursa e per-sesiune,
    în `session_sources`) → `online` era permanent False, deci `isSessionLive` din client
    ascundea/înnegrea sesiunile lui LIVE în toată aplicaţia (Sessions, tab-uri, Dashboard).
    Regula corectă: jump = agentul părinte conectat (sau sursa proprie, pentru ssh-jump activ).
    Primeşte orice rând cu `id`, `connection_type`, `via_host_id` (nu doar `SELECT *`)."""
    if row["id"] in core.sources:
        return True
    ctype = conntypes.of(row["connection_type"] if "connection_type" in row.keys() else None)
    via = row["via_host_id"] if "via_host_id" in row.keys() else None
    if ctype in conntypes.JUMP and via:
        return isinstance(core.sources.get(via), core.AgentConnection)
    return False


AGENT_USER = "webterm"          # userul dedicat propus în varianta cu privilegii minime


def install_command(enroll_token: str, password: str = "", group: bool = False) -> str:
    """The install one-liner for one host (`/install/<token>.sh`) or, with `group=True`, for a
    group enrolment token (`/install/group/<token>.sh`: run it on N machines, the gateway
    creates one host per run). One builder for both, so a fix (the wget fallback below was
    one) cannot land in only one of them."""
    # self-signed gateway: the one-liner itself must skip cert verification
    flags = "-fsSk" if config.AGENT_INSECURE else "-fsS"
    wflags = "--no-check-certificate " if config.AGENT_INSECURE else ""
    url = "%s/install/%s%s.sh" % (config.PUBLIC_URL, "group/" if group else "", enroll_token)
    # Parola temporară călătoreşte ca HEADER, nu în URL: un proxy/access-log înregistrează
    # metoda+URL-ul, nu anteturile, deci un URL scurs acolo NU conţine parola. Ambele mijloace
    # de aducere (curl/wget) o trimit. Parola conţine doar caractere din alfabetul nostru
    # (generată/validată), fără ghilimele — dar o punem între ghilimele oricum.
    ch = ' -H "X-Enroll-Pass: %s"' % password if password else ""
    wh = ' --header="X-Enroll-Pass: %s"' % password if password else ""
    # Fallback pe wget: scriptul PE CARE îl aducem are deja fallback curl→wget, dar comanda
    # care îl aduce nu avea, deci pe o imagine minimală fără curl (debian-slim, alpine)
    # înrolarea murea cu `sh: 1: curl: not found` înainte să apuce să ruleze ceva. Ironia e
    # că exact acel caz e explicat într-un comentariu din scriptul nelivrat.
    return ("(command -v curl >/dev/null && curl %s%s %s || wget %s%s-qO- %s) | sh"
            % (flags, ch, url, wflags, wh, url))


def install_command_dedicated(enroll_token: str, password: str = "") -> str:
    """Aceeaşi instalare, dar sub un user dedicat, fără drepturi.

    Rulat ca root, agentul înseamnă root shell pe host: cine compromite gateway-ul sau contul
    tău are hostul. Sub `webterm`, are doar ce are `webterm`.

    `loginctl enable-linger` NU e opţional aici: fără el, `systemd --user` opreşte serviciul
    când userul n-are sesiune de login şi nu-l porneşte la boot — agentul ar părea că moare
    singur. `useradd` e tolerat dacă userul există deja (|| true), ca să poţi relua comanda."""
    inner = install_command(enroll_token, password)
    return ("sudo useradd -m -s /bin/bash %s 2>/dev/null || true; "
            "sudo loginctl enable-linger %s; "
            "sudo -iu %s sh -c '%s'" % (AGENT_USER, AGENT_USER, AGENT_USER, inner))


async def validate_host(host: HostIn, user, grants=None) -> dict:
    """SINGURA cale de validare pentru un host nou — `POST /api/hosts` şi importul CSV trec
    amândouă pe aici, ca un rând de CSV să nu poată crea ceva ce formularul ar refuza (sau
    invers). Întoarce valorile normalizate pe care le scrie `insert_host`."""
    ctype = conntypes.of(host.connection_type)
    # Un tip necunoscut („SSH", typo de script) era coerce TĂCUT la agent: 200 cu un host agent
    # şi credenţialul aruncat de credential_blob. PATCH-ul dădea deja 400 — acum şi POST-ul.
    if ctype not in conntypes.ALL:
        raise ApiError(400, "host.badType", "unknown connection type")
    # Numele gol trecea: UI-ul are `required`, dar API-ul (şi acum CSV-ul) nu — un host fără
    # nume e un rând pe care nu-l mai găseşti în sidebar.
    if not host.name.strip():
        raise ApiError(400, "host.nameRequired", "a host name is required")
    check_cred_policy(host.credential_policy)
    if ctype in conntypes.NETWORK and not host.hostname.strip():
        raise ApiError(400, "host.hostnameRequired", "hostname required for a direct connection")
    if ctype in conntypes.SSH_FAMILY and not host.ssh_username.strip():
        raise ApiError(400, "ssh.userRequired", "an SSH username is required")
    # metoda de autentificare era scrisă orbeşte; un „pasword" dintr-un CSV ar fi dat un host
    # care nu se mai conectează niciodată, fără nicio explicaţie
    if ctype in conntypes.SSH_FAMILY and host.auth_method not in ("password", "key"):
        raise ApiError(400, "host.badAuthMethod", "auth_method must be password or key")
    if host.ssh_port is not None and not 1 <= host.ssh_port <= 65535:
        raise ApiError(400, "host.badPort", "the port must be between 1 and 65535")
    if ctype in conntypes.JUMP:
        # 3.6 (§A.11.4): o ţintă jump deschide TCP DIN hostul `via` — un pivot de reţea, deci
        # cere `forward.manage` acolo. Verificat înaintea existenţei: un `via` invizibil dă
        # acelaşi 404 ca unul inexistent. `grants=None` doar din apelanţi interni fără cerere.
        if grants is None:
            raise authz.not_found("host_id")
        await authz.require_on(grants, host.via_host_id, "forward.manage")
        via = await db.fetchone("SELECT connection_type FROM hosts WHERE id=?", host.via_host_id)
        if not via or not conntypes.is_agent(via):
            raise ApiError(400, "sshjump.needsAgent", "pick an agent host to reach the target through")
    port = host.ssh_port or conntypes.default_port(ctype)
    # pin din testul de conexiune: doar cheia pe care TESTUL a văzut-o pe aceeaşi ţintă
    known = None
    if host.pin_hostkey:
        if ctype not in conntypes.SSH_FAMILY:
            raise ApiError(400, "hosttest.pinMismatch", "only SSH hosts have a host key to pin")
        known = verified_pin(user["id"], ctype, host.hostname, port, host.via_host_id, host.pin_hostkey)
    if host.pending_key_id and ctype not in conntypes.SSH_FAMILY:
        raise ApiError(400, "sshkey.notSsh", "SSH key generation is only for SSH hosts")
    return {"ctype": ctype, "port": port, "known": known}


async def insert_host(host: HostIn, user, v: dict):
    """Scrie hostul validat de `validate_host`. Întoarce (rândul, tokenul de enroll, parola)."""
    ctype, port, known = v["ctype"], v["port"], v["known"]
    cred_blob, auth_method, policy = credential_blob(host), host.auth_method, host.credential_policy
    if host.pending_key_id:
        # revendicare ATOMICĂ (DELETE … RETURNING): cheia se leagă o singură dată, doar de userul ei
        cred_blob = await claim_pending_key(user["id"], host.pending_key_id)
        auth_method, policy = "key", "stored"
    token = security.new_token()
    enroll = security.new_token()[:32]
    ttl = max(300, min(30 * 86400, int(host.enroll_ttl or 3600)))   # 5 min .. 30 zile, implicit 1h
    pw = clean_enroll_pass(host.enroll_password)
    pass_hash = await security.hash_password_async(pw) if pw else None
    host_id = await db.execute(
        # `folder` lipsea din INSERT deşi `HostIn` îl acceptă: hostul creat direct într-un grup
        # ieşea mereu în afara lui, fără nicio eroare. Aceeaşi clasă cu PATCH-ul care accepta
        # câmpuri de conexiune şi le ignora.
        "INSERT INTO hosts(name, note, folder, token_hash, token_encrypted, enroll_token,"
        " enroll_expires, enroll_pass_hash, created, connection_type, hostname, ssh_username,"
        " ssh_port, auth_method, credential_encrypted, require_2fa, credential_policy, tags,"
        " via_host_id, ephemeral, known_hosts)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        host.name.strip(), host.note, host.folder.strip(), security.sha256_hex(token),
        security.encrypt_secret(token), enroll,
        time.time() + ttl, pass_hash, time.time(),
        ctype, host.hostname.strip() or None, host.ssh_username.strip() or None,
        port, auth_method, cred_blob,
        int(host.require_2fa), policy, norm_tags(host.tags),
        host.via_host_id if ctype in conntypes.JUMP else None,
        1 if (host.ephemeral and ctype in conntypes.JUMP) else 0, known)
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    return row, enroll, pw


# Cheia de host văzută de ultimul test, per (user, ţintă). Create/update acceptă `pin_hostkey`
# DOAR dacă e exact cheia de aici: clientul nu poate „inventa" un pin, poate doar confirma ce a
# văzut serverul. RAM, ~10 min — un restart îl goleşte (salvarea cade atunci pe TOFU).
HOSTKEY_TEST_TTL = 600.0


tested_hostkeys: dict = {}     # (user_id, via, host, port) -> (keyline, fingerprint, monotonic)


def test_target(user_id, ctype: str, hostname: str, port, via) -> tuple:
    jump = ctype in conntypes.JUMP
    return (user_id, int(via or 0) if jump else 0, (hostname or "").strip().lower(), int(port or 0))


def same_hostkey(a: str, b: str) -> bool:
    """Două linii de cheie publică OpenSSH sunt aceeaşi cheie (tip + blob; comentariul nu contează)."""
    pa, pb = (a or "").split(), (b or "").split()
    return len(pa) >= 2 and len(pb) >= 2 and pa[:2] == pb[:2]


def verified_pin(user_id, ctype: str, hostname: str, port, via, pin: str) -> str:
    """Linia de cheie de pinat (cea văzută de server, NU textul clientului) — sau 400. `pin` poate
    fi linia publică întoarsă de test sau amprenta ei SHA256."""
    ent = tested_hostkeys.get(test_target(user_id, ctype, hostname, port, via))
    pin = (pin or "").strip()
    if (ent and time.monotonic() - ent[2] <= HOSTKEY_TEST_TTL
            and (pin == ent[1] or same_hostkey(pin, ent[0]))):
        return ent[0]
    raise ApiError(400, "hosttest.pinMismatch",
                   "pin_hostkey does not match the host key seen by a recent connection test "
                   "of this target — run the test again")


async def claim_pending_key(user_id, pending_id: str) -> str:
    """Revendicare ATOMICĂ (DELETE … RETURNING): blobul criptat al privatei, o singură dată."""
    row = await db.execute_returning(
        "DELETE FROM pending_ssh_keys WHERE id=? AND user_id=? AND created>=? "
        "RETURNING credential_encrypted",
        pending_id, user_id, time.time() - core.PENDING_KEY_TTL)
    if not row:
        raise ApiError(400, "sshkey.pendingMissing",
                       "the generated key expired or does not exist — generate a new one")
    return row["credential_encrypted"]
