"""Alerte de securitate pe email (SMTP), opționale și best-effort.

Config SMTP din baza de date (editabilă din UI) peste variabilele de mediu.
Fără config, totul e no-op. Deliberat NU trimitem un email per încercare eșuată
(ar fi un vector de mail-bombing) — doar semnale rare și utile: un IP tocmai
blocat, sau un login reușit de pe un IP nevăzut până acum.
"""

import asyncio
import logging
import smtplib
import ssl
import time
from email.message import EmailMessage

from . import alert_history, config, db

log = logging.getLogger("webterm")

# throttling in-memory: cheie -> ultimul epoch trimis
_last_sent: dict = {}

# cheile din tabela app_settings
_KEYS = ("smtp_host", "smtp_port", "smtp_user", "smtp_password_enc",
         "smtp_from", "smtp_to", "smtp_starttls", "alert_webhook")

# Starea ultimei livrări, PERSISTATĂ (app_settings) ca UI-ul să poată răspunde la „au plecat
# alertele?". Până acum un SMTP care picase de luni de zile era invizibil: `_fire` înghiţea
# eroarea în log şi atât (audit UX §7). JSON: {ts, subject[, error]}.
K_EMAIL_LAST_SENT = "alert_email_last_sent"
K_EMAIL_LAST_FAILED = "alert_email_last_failed"
K_WEBHOOK_LAST_SENT = "alert_webhook_last_sent"
K_WEBHOOK_LAST_FAILED = "alert_webhook_last_failed"
_STATUS_KEYS = (K_EMAIL_LAST_SENT, K_EMAIL_LAST_FAILED, K_WEBHOOK_LAST_SENT, K_WEBHOOK_LAST_FAILED)


async def _record(key: str, subject: str, error: str = "") -> None:
    """Scrie starea livrării; best-effort (fără DB la startup/shutdown → nimic)."""
    import json as _json
    if not db.connected():
        return
    payload = {"ts": time.time(), "subject": subject[:120]}
    if error:
        payload["error"] = error[:300]
    try:
        await db.execute("INSERT INTO app_settings(key, value) VALUES(?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         key, _json.dumps(payload))
    except Exception as e:                  # noqa: BLE001 — statusul nu rupe alerta
        log.debug("alert status not recorded (%s): %s", key, e)


async def alert_status() -> dict:
    """Ultimul email / webhook trimis şi ultimul eşuat, pentru tab-ul Notificări."""
    import json as _json
    out = {k: None for k in _STATUS_KEYS}
    if not db.connected():
        return out
    rows = await db.fetchall("SELECT key, value FROM app_settings WHERE key IN (%s)"
                             % ",".join("?" * len(_STATUS_KEYS)), *_STATUS_KEYS)
    for r in rows:
        try:
            out[r["key"]] = _json.loads(r["value"]) if r["value"] else None
        except ValueError:
            out[r["key"]] = None
    return out


def _post_webhook(url: str, subject: str, body: str) -> None:
    """Aceleaşi alerte, pe un webhook (Slack / Discord / Teams / orice endpoint).
    Emailul e potrivit pentru arhivă, dar prost pentru reacţie: la un lockout sau la o
    flotă care cade vrei un ping în chat. Payload compatibil cu Slack/Discord (`text` +
    `content`), plus câmpuri proprii pentru cine parsează JSON."""
    import json as _json
    import urllib.request
    payload = _json.dumps({
        "text": "[WebTerm] %s\n%s" % (subject, body),      # Slack / Mattermost
        "content": "**[WebTerm] %s**\n%s" % (subject, body),  # Discord
        "subject": subject, "body": body,                    # consumatori proprii
    }).encode()
    # doar http(s): fără asta, un webhook configurat greşit cu `file://`/`gopher://` ar lăsa
    # urllib să citească fişiere locale / să vorbească alte protocoale (clasa SSRF din audit).
    if not url.lower().startswith(("https://", "http://")):
        raise ValueError("webhook URL must be http(s)")
    req = urllib.request.Request(url, data=payload, method="POST", headers={  # noqa: S310 — schemă validată mai sus
        "Content-Type": "application/json", "User-Agent": "WebTerm"})
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
        r.read(2048)


async def load_config() -> dict:
    """Config SMTP efectiv: valorile din DB au prioritate peste env. Parola din
    DB e criptată (Fernet); env-ul rămâne fallback. Întoarce un dict cu chei
    normalizate și `parola` în clar (doar în memorie, pentru trimitere)."""
    from . import security  # lazy: security importă email_alerts (evită ciclul)
    # calea de alertă e best-effort şi rulează în task de fundal → dacă DB-ul nu e conectat
    # (startup/shutdown), folosim doar config-ul din env, fără să aruncăm NoneType.execute.
    d = {}
    if db.connected():
        rows = await db.fetchall(
            "SELECT key, value FROM app_settings WHERE key IN (%s)"
            % ",".join("?" * len(_KEYS)), *_KEYS)
        d = {r["key"]: r["value"] for r in rows}
    password = ""
    if d.get("smtp_password_enc"):
        try:
            password = security.decrypt_secret(d["smtp_password_enc"])
        except Exception:
            password = ""
    cfg = {
        "host": d.get("smtp_host") or config.SMTP_HOST,
        "port": int(d.get("smtp_port") or config.SMTP_PORT or 587),
        "user": d.get("smtp_user") if d.get("smtp_user") is not None else config.SMTP_USER,
        "password": password or config.SMTP_PASSWORD,
        "starttls": (d["smtp_starttls"] == "1") if d.get("smtp_starttls") is not None
                    else config.SMTP_STARTTLS,
        "from": d.get("smtp_from") or config.ALERT_FROM,
        "to": d.get("smtp_to") or config.ALERT_TO,
        "webhook": d.get("alert_webhook") or config.ALERT_WEBHOOK,
    }
    return cfg


def _configured(cfg: dict) -> bool:
    return bool(cfg["host"] and cfg["to"] and cfg["from"])


def _send_blocking(cfg: dict, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[WebTerm] {subject}"
    msg["From"] = cfg["from"]
    msg["To"] = cfg["to"]
    msg.set_content(body)
    # Portul 465 = TLS IMPLICIT (SMTPS): conexiunea e TLS de la primul octet, iar `smtplib.SMTP`
    # aştepta acolo un banner în clar şi expira tăcut. Îl tratăm separat, cu acelaşi context care
    # verifică certificatul; pe orice alt port rămâne SMTP + STARTTLS opţional (3.5.2).
    if int(cfg["port"]) == 465:
        with smtplib.SMTP_SSL(cfg["host"], 465, timeout=15,
                              context=ssl.create_default_context()) as s:
            if cfg["user"]:
                s.login(cfg["user"], cfg["password"])
            s.send_message(msg)
        return
    with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
        if cfg["starttls"]:
            # M2: context care VERIFICĂ certificatul serverului (hostname + CA). Fără el,
            # starttls() nu autentifică peer-ul → un MITM pe rețea putea intercepta
            # credențialele SMTP printr-un STARTTLS-stripping / cert fals.
            s.starttls(context=ssl.create_default_context())
        if cfg["user"]:
            s.login(cfg["user"], cfg["password"])
        s.send_message(msg)


async def smtp_ready() -> bool:
    """Avem un canal de email funcţional configurat? Poarta de confirmare pe email se aplică
    doar dacă răspunsul e da — altfel o instalare fără SMTP n-ar mai putea schimba niciodată
    parola, ceea ce e o blocare permanentă, nu o măsură de securitate."""
    try:
        return _configured(await load_config())
    except Exception:                       # noqa: BLE001 — DB indisponibil ⇒ poarta nu se aplică
        return False


async def send_account_code(to_email: str, code: str, what: str) -> None:
    """Trimite un cod de confirmare la adresa CONTULUI, sincron, şi ARUNCĂ dacă nu pleacă.

    Deliberat nu trece prin `_fire`: acela e best-effort (înghite erorile — aici ai rămâne să
    aştepţi la nesfârşit un cod care n-a plecat) şi difuzează şi pe webhook — un cod de
    confirmare postat într-un canal de chat nu mai confirmă nimic. Şi destinatarul e adresa
    contului, nu `cfg["to"]`: aceea e cutia de alerte a instanţei, nu a omului care schimbă
    parola."""
    cfg = dict(await load_config())
    if not _configured(cfg):
        raise RuntimeError("SMTP is not configured")
    cfg["to"] = to_email
    await asyncio.to_thread(
        _send_blocking, cfg, "Confirmation code: %s" % what,
        "Your confirmation code is:\n\n    %s\n\n"
        "It is valid for 10 minutes and can be used once.\n\n"
        "It was requested to %s from a device that has never been seen on a successful login "
        "to this account. If that was not you, do NOT enter this code — someone knows your "
        "password. Change it from a device you normally use." % (code, what))


def _fire(subject: str, body: str, kind: str = "system", severity: str = "info",
          host_id=None, user_id=None, user_email=None) -> None:
    """Send without blocking the handler; swallow any error (best-effort).

    3.5.11: înainte de canalul extern, evenimentul se înregistrează în istoricul din aplicaţie
    (`alert_history.record`) pentru conturile cărora le priveşte, iar preferinţele lor decid dacă
    mai pleacă pe email/webhook. O eroare la înregistrare NU opreşte emailul (best-effort)."""
    async def _run():
        cfg = None
        try:
            if not await alert_history.record(kind, severity, subject, body, host_id=host_id,
                                              user_id=user_id, user_email=user_email):
                return                      # toate conturile vizate au oprit emailul pentru tipul ăsta
        except Exception as e:              # noqa: BLE001 — istoricul nu rupe alerta
            log.warning("in-app alert not recorded (%s): %s", kind, e)
        try:
            cfg = await load_config()
            if _configured(cfg):
                await asyncio.to_thread(_send_blocking, cfg, subject, body)
                await _record(K_EMAIL_LAST_SENT, subject)
        except Exception as e:
            log.warning("email alert failed (%s): %s", subject, e)
            await _record(K_EMAIL_LAST_FAILED, subject, str(e))
        # webhook-ul e independent de SMTP: cine are doar chat nu trebuie să ţină un SMTP
        try:
            url = (cfg or {}).get("webhook") or ""
            if url:
                await asyncio.to_thread(_post_webhook, url, subject, body)
                await _record(K_WEBHOOK_LAST_SENT, subject)
        except Exception as e:
            log.warning("webhook alert failed (%s): %s", subject, e)
            await _record(K_WEBHOOK_LAST_FAILED, subject, str(e))

    try:
        asyncio.get_running_loop().create_task(_run())
    except RuntimeError:
        pass  # fără event loop (ex. în teste sincrone) — ignoră


async def send_test() -> None:
    """Send a test email SYNCHRONOUSLY and raise on failure (for the "test" button
    in the UI, so the result is visible)."""
    cfg = await load_config()
    if not _configured(cfg):
        raise RuntimeError("SMTP is not configured (missing host or destination address)")
    subject = "Test de configurare"
    try:
        await asyncio.to_thread(
            _send_blocking, cfg, subject,
            "This is a test email from WebTerm. If it arrives, security alerts "
            "are working.")
    except Exception as e:
        await _record(K_EMAIL_LAST_FAILED, subject, str(e))
        raise
    await _record(K_EMAIL_LAST_SENT, subject)


async def send_webhook_test() -> None:
    """POST de test pe webhook, SINCRON, şi aruncă la eşec (butonul „Test webhook" din UI)."""
    cfg = await load_config()
    url = cfg.get("webhook") or ""
    if not url:
        raise RuntimeError("no webhook URL is configured")
    subject = "Test de configurare"
    try:
        await asyncio.to_thread(_post_webhook, url, subject,
                                "This is a test alert from WebTerm. If it arrives, alerts reach this channel.")
    except Exception as e:
        await _record(K_WEBHOOK_LAST_FAILED, subject, str(e))
        raise
    await _record(K_WEBHOOK_LAST_SENT, subject)


_EVICT_AFTER = 3600.0        # > orice min_interval folosit; peste atât intrarea nu mai throttle-uiește

def _throttled(key: str, min_interval: float) -> bool:
    now = time.time()
    # evacuare oportunistă: sub credential-stuffing distribuit (multe IP-uri), _last_sent ar
    # crește nemărginit pe viața procesului. Peste un prag, curățăm intrările învechite.
    if len(_last_sent) > 256:
        for k in [k for k, t in _last_sent.items() if now - t > _EVICT_AFTER]:
            _last_sent.pop(k, None)
    if now - _last_sent.get(key, 0) < min_interval:
        return False
    _last_sent[key] = now
    return True


def notify_lockout(ip: str, fails: int) -> None:
    """An IP was just blocked. At most one alert per IP every 15 min."""
    if not _throttled(f"lock:{ip}", 900):
        return
    _fire("IP blocked after failed login attempts",
          f"IP {ip} was temporarily blocked after {fails} failed authentication "
          f"attempts.\n\nIf this was not you, someone is trying to guess your "
          f"password — but access is blocked.", kind="lockout", severity="warning")


def notify_agent_relocation(host_name: str, instance_short: str, host_id=None) -> None:
    """Un agent a încercat să se conecteze de pe o ALTĂ maşină pe tokenul unui host deja fixat
    (clonă de VM / token furat şi mutat) — conexiunea a fost REFUZATĂ. Semnal de compromis puternic.
    Cel mult o alertă / 15 min per host (un atacator care reîncearcă nu ne inundă)."""
    if not _throttled(f"reloc:{host_name}", 900):
        return
    _fire("Agent rejected: relocation/cloning attempt",
          f"Host '{host_name}' is pinned to one machine, but its token was used from a "
          f"DIFFERENT machine (instance {instance_short}…) — the connection was REFUSED.\n\n"
          f"If you are NOT reinstalling the host: someone has the agent's token and is trying "
          f"to use it elsewhere. Check the host; revoke or reinstall the agent if needed.",
          kind="agent_relocation", severity="critical", host_id=host_id)


def notify_agent_ip_change(host_name: str, old_ip: str, new_ip: str, host_id=None) -> None:
    """Agentul unui host s-a reconectat de la un IP nou. Informativ (IP-urile se schimbă legitim:
    DHCP / reboot / NAT), dar util ca semnal. Cel mult o alertă / oră per host."""
    if not _throttled(f"agentip:{host_name}", 3600):
        return
    _fire("Agent reconnected from a new IP",
          f"The agent on host '{host_name}' connected from a new IP.\n\n"
          f"New: {new_ip}\nPrevious: {old_ip}\n\n"
          f"Normal after a reboot or a network change. If the host has a fixed IP you did not touch, "
          f"it is worth a look.", kind="agent_ip_change", severity="info", host_id=host_id)


def notify_new_login(ip: str, user_agent: str, email: str, user_id=None) -> None:
    """A successful login from an IP never seen before. The most valuable signal."""
    _fire("New login on your account",
          f"Successful authentication for {email} from a new IP.\n\n"
          f"IP: {ip}\nBrowser: {user_agent or '?'}\n\n"
          f"If this was not you, change the password immediately and review the active "
          f"sessions in settings.", kind="new_login", severity="warning",
          user_id=user_id, user_email=email)


def notify_session_attach(title: str, ip: str, user_agent: str, email: str, user_id=None) -> None:
    """Cineva s-a ataşat la o sesiune VIE de pe un IP nemaivăzut la un login al contului.
    Throttled per IP: dacă deschizi cinci taburi de pe acelaşi loc nou, primeşti un mesaj, nu
    cinci. Ataşările de pe locuri cunoscute nu trimit nimic — altfel alerta devine zgomot şi
    nimeni n-o mai citeşte, iar atunci n-o mai citeşte nici pe cea care conta."""
    if not _throttled("attach:" + ip, 900):
        return
    _fire("A new device attached to a live session",
          f"Account: {email}\nSession: {title or '(untitled)'}\n\n"
          f"IP: {ip}\nBrowser: {user_agent or '?'}\n\n"
          f"This IP has not been seen on a successful login for this account. If it was not "
          f"you, open the session and remove that client from the viewer list, then change "
          f"the password — the browser session behind it stays valid until you do.",
          kind="session_attach", severity="warning", user_id=user_id, user_email=email)


def notify_security_change(what: str, ip: str, email: str, fleet: bool = False,
                           severity: str = "warning", user_id=None, host_id=None) -> None:
    """A sensitive account change (password, 2FA, new passkey, new account, new API token).

    `fleet=True`: schimbarea priveşte TOATĂ instanţa (cont nou, token de automatizare, token de
    grup, host key re-pinat, share-uri revocate) → istoricul o arată fiecărui cont (`admin_change`);
    altfel e a contului care a făcut-o (`account_change`)."""
    _fire(f"Security change: {what}",
          f"On account {email}: {what}.\nIP: {ip}\n\n"
          f"If this was not you, the account is probably compromised.",
          kind="admin_change" if fleet else "account_change", severity=severity,
          host_id=host_id, user_id=None if fleet else user_id, user_email=None if fleet else email)


def notify_host_key_changed(host_name: str, detail: str, host_id=None) -> None:
    """Host-key-ul unei ţinte SSH (direct sau jump) NU se potriveşte cu cel pinat — ori s-a
    re-provizionat legitim, ori e un MITM activ. Conexiunea a fost REFUZATĂ. Semnal puternic,
    throttle per host (15 min) ca un atacator care reîncearcă să nu inunde."""
    if not _throttled("hostkey:" + host_name, 900):
        return
    _fire("SSH host key changed — connection refused",
          f"The pinned SSH host key for '{host_name}' did not match on connect — the connection "
          f"was REFUSED.\n{detail}\n\nIf you did not re-provision this host, this is a possible "
          f"man-in-the-middle. Verify out-of-band before clearing the pinned key.",
          kind="host_key_changed", severity="critical", host_id=host_id)


def notify_ssh_key_action(action: str, source: str, target: str, fingerprint: str,
                          ip: str, email: str, host_id=None) -> None:
    """O cheie de deploy a fost pusă/scoasă din authorized_keys pe o ţintă — adică s-a acordat
    sau retras acces SSH DURABIL, care supravieţuieşte revocării cookie-urilor şi chiar opririi
    WebTerm. Fiecare muchie nouă trebuie să fie un eveniment văzut, nu o descoperire la audit.
    Fără throttle: deploy-urile sunt rare şi deliberate; fiecare merită propria urmă."""
    _fire(f"SSH deploy key {action}: {source} → {target}",
          f"On account {email}: the deploy key of host '{source}' ({fingerprint}) was "
          f"{action} on host '{target}'.\nIP: {ip}\n\n"
          f"If this was not you, revoke the key from Toolbox → SSH keys on '{source}' "
          f"and check ~/.ssh/authorized_keys on '{target}'.",
          kind="ssh_key", severity="warning", host_id=host_id)


def notify_host_enrolled(group_name: str, ip: str, host_id=None) -> None:
    """Un host nou s-a auto-înmatriculat în flotă printr-un token de grup. Înrolarea era un act
    deliberat, per-host, dintr-un browser autentificat; un token de grup o face din afară, deci
    fiecare maşină nouă merită o urmă vizibilă. Throttle per grup (10 min): un rollout de zeci de
    maşini trimite un semnal, nu zeci — dar un enroll IZOLAT, neaşteptat, tot ajunge la tine."""
    if not _throttled("enroll:" + group_name, 600):
        return
    _fire("A host auto-enrolled into the fleet",
          f"A new host registered itself using the group enrollment token '{group_name}'.\n"
          f"IP: {ip}\n\n"
          f"If you are rolling out machines, this is expected (one alert per group per 10 min). "
          f"If not, revoke the token in Settings → the host got its own agent credential and can "
          f"reach the gateway until you remove it.", kind="host_enrolled", severity="warning",
          host_id=host_id)


def notify_host_unlocked(host_name: str, ip: str, email: str, host_id=None, user_id=None) -> None:
    """A host marked `require_2fa` was just unlocked (step-up passed) — i.e. a PROTECTED host
    is now being accessed. These are the hosts explicitly flagged as sensitive, so an unlock is
    exactly the event worth surfacing. Throttled per host+IP (15 min): the step-up window is
    minutes long, so a legitimate session re-unlocking now and then must not become noise."""
    if not _throttled("unlock:%s:%s" % (host_name, ip), 900):
        return
    _fire("A 2FA-protected host was unlocked",
          f"Account: {email}\nHost: {host_name}\nIP: {ip}\n\n"
          f"Step-up (passkey or account password) passed, so this host — which you marked as "
          f"requiring 2FA — is now accessible for a short window. If this was not you, change "
          f"your password and review the active sessions in settings.",
          kind="host_unlocked", severity="info", host_id=host_id, user_id=user_id, user_email=email)


def notify_replay_created(title: str, label: str, hours: int, redact: bool, ip: str,
                          email: str, user_id=None) -> None:
    """S-a creat un link PUBLIC de replay către înregistrarea unei sesiuni. E o cale de acces
    fără cont, deci contul trebuie s-o vadă — mai ales dacă n-a creat-o el (cookie furat).
    Fără throttle: crearea e rară şi deliberată."""
    span = "1 hour" if hours == 1 else ("7 days" if hours == 168 else "%d hours" % hours)
    _fire("Public replay link created",
          f"Account: {email}\nSession: {title or '(untitled)'}\n"
          + (f"Label: {label}\n" if label else "")
          + f"Valid for: {span}\nSecret masking: {'on' if redact else 'OFF'}\nIP: {ip}\n\n"
          f"Anyone with the link can watch this recording until it expires. If this was not "
          f"you, revoke it from the dashboard (Share links) and change your password.",
          kind="replay_link", severity="warning", user_id=user_id, user_email=email)


def notify_replay_opened(link_id: int, title: str, label: str, ip: str, user_agent: str,
                         email: str, user_id=None) -> None:
    """Cineva a deschis un link de replay. Doar contului care l-a creat; cel mult o alertă per
    link la 10 minute (un invitat care derulează şi reîncarcă nu inundă istoricul)."""
    if not _throttled("replay:%d" % link_id, 600):
        return
    _fire("Your replay link was opened",
          f"Session: {title or '(untitled)'}\n"
          + (f"Link: {label}\n" if label else f"Link: #{link_id}\n")
          + f"IP: {ip}\nBrowser: {user_agent or '?'}\n\n"
          f"Further opens in the next 10 minutes are counted in the link list, not alerted.",
          kind="replay_opened", severity="info", user_id=user_id, user_email=email)


# ---------------------------------------------------------------------------
# Alerte pe praguri de resurse (CPU / RAM / disc)
# ---------------------------------------------------------------------------
# Ce vrea un operator de flotă: să afle de discul plin ÎNAINTE să pice hostul.
# Reguli ca alertele să rămână utile (o alertă ignorată e mai rea decât niciuna):
#  - histerezis: alertăm la depășirea pragului, dar „armăm" din nou abia sub
#    prag − MARJA — altfel o valoare care oscilează în jurul pragului spamează;
#  - persistență: CPU-ul trebuie să stea peste prag mai multe cicluri la rând
#    (un vârf de 5 secunde la un `build` nu e un incident);
#  - throttling: cel mult o alertă per (host, metrică) la 30 min;
#  - notificăm și revenirea la normal (închiderea buclei — știi că s-a rezolvat).

DEFAULT_THRESHOLDS = {"cpu": 90, "mem": 90, "disk": 90}
HYSTERESIS = 10           # puncte procentuale sub prag pentru re-armare
CPU_SUSTAINED = 3         # cicluri de heartbeat consecutive peste prag
ALERT_MIN_INTERVAL = 1800  # secunde între două alerte pentru aceeași metrică

_LABELS = {"cpu": "CPU", "mem": "memory", "disk": "disk"}

# stare in-memory per (host_id, metrică): dacă suntem „în alertă" și de câte
# cicluri consecutive e depășit pragul
_breach: dict = {}
_firing: dict = {}


# cache cu TTL: check_metrics rulează la FIECARE heartbeat de la agent, iar
# pragurile se schimbă rar. Fără cache, un agent compromis care inundă cu
# heartbeat-uri forța 3 query-uri DB per heartbeat pe conexiunea aiosqlite
# unică (serializată) → contenție. Invalidat la salvarea pragurilor (api.py).
_thr_cache: dict = {"value": None, "at": 0.0}
_THR_TTL = 30.0


def invalidate_thresholds() -> None:
    _thr_cache["value"] = None


async def load_thresholds() -> dict:
    """Praguri din DB (editabile din UI). 0 sau lipsă = metrica e dezactivată.
    Cache-uit `_THR_TTL` secunde ca heartbeat-urile să nu lovească DB de fiecare dată."""
    now = time.time()
    if _thr_cache["value"] is not None and now - _thr_cache["at"] < _THR_TTL:
        return dict(_thr_cache["value"])
    out = dict(DEFAULT_THRESHOLDS)
    for k in DEFAULT_THRESHOLDS:
        row = await db.fetchone("SELECT value FROM app_settings WHERE key=?",
                                f"alert_{k}")
        if row and row["value"] not in (None, ""):
            try:
                out[k] = int(row["value"])
            except (TypeError, ValueError):
                pass
    _thr_cache["value"] = dict(out)
    _thr_cache["at"] = now
    return out


def _pct(used, total):
    try:
        if used is None or not total:
            return None
        return 100.0 * float(used) / float(total)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def check_metrics(host_id: int, host_name: str, metrics: dict, thresholds: dict) -> None:
    """Evaluează metricele unui heartbeat. Apelat din core.reconcile — sincron
    și ieftin (fără I/O); trimiterea efectivă se face pe un thread, ca restul."""
    if not metrics:
        return
    values = {
        "cpu": metrics.get("cpu_pct"),
        "mem": _pct(metrics.get("mem_used"), metrics.get("mem_total")),
        "disk": _pct(metrics.get("disk_used"), metrics.get("disk_total")),
    }
    for key, value in values.items():
        limit = thresholds.get(key) or 0
        if not limit or value is None:
            continue
        state_key = (host_id, key)
        over = value >= limit
        # CPU e volatil: cerem persistență. RAM/discul se mișcă lent → imediat.
        need = CPU_SUSTAINED if key == "cpu" else 1
        streak = _breach.get(state_key, 0) + 1 if over else 0
        _breach[state_key] = streak

        if over and streak >= need and not _firing.get(state_key):
            if not _throttled(f"res:{host_id}:{key}", ALERT_MIN_INTERVAL):
                continue
            _firing[state_key] = True
            _fire(
                f"[{host_name}] {_LABELS[key]} at {value:.0f}% (threshold {limit}%)",
                f"Host {host_name} crossed the alert threshold.\n\n"
                f"Metric: {_LABELS[key]}\nValue: {value:.1f}%\nThreshold: {limit}%\n\n"
                f"You get a single alert while it stays above the threshold; "
                f"you will hear again when it drops below {max(0, limit - HYSTERESIS)}%.",
                kind="resource", severity="warning", host_id=host_id)
        elif _firing.get(state_key) and value <= limit - HYSTERESIS:
            # revenire la normal: re-armăm și confirmăm rezolvarea
            _firing[state_key] = False
            _fire(
                f"[{host_name}] {_LABELS[key]} back to {value:.0f}%",
                f"Host {host_name}: {_LABELS[key]} dropped to {value:.1f}% "
                f"(below the {limit}% threshold minus the {HYSTERESIS}-point margin).",
                kind="resource", severity="ok", host_id=host_id)


# ── hostul a tăcut / a revenit ────────────────────────────────────────────────
# Aveam alerte pentru lockout, relocare de agent, IP schimbat, login nou şi praguri de
# resurse — dar NU pentru „agentul nu mai raportează", adică exact evenimentul pe care
# îl vrei primul într-o flotă. Semnalat de auditul extern, 2026-08-06.
def notify_host_offline(host_id: int, host_name: str, silent_for: float,
                        uninstall_reported: bool = False) -> None:
    """Trimite alerta „un host care raporta a încetat". Dedup-ul (o singură alertă per cădere)
    şi respectarea toggle-ului per-host `alerts_muted` se fac în `core.sweep_hosts_offline`, pe
    starea PERSISTATĂ `hosts.offline_notified` — înainte trăia doar în RAM, deci o repornire de
    gateway re-trimitea pentru fiecare host încă tăcut. Aici doar compunem şi trimitem emailul.

    `uninstall_reported`: agentul a POSTat /agent/uninstalled înainte să tacă. NU suprimăm
    alerta pe baza asta — raportul vine autentificat DOAR cu tokenul hostului, deci oricine
    are shell pe maşină îl poate trimite şi apoi omorî agentul, cumpărându-şi tăcerea exact
    când face teardown pe un host compromis (audit de securitate 2026-08). În schimb adaptăm
    TEXTUL: la un uninstall real diagnosticele obişnuite (tmux ls, ptyd.log) sunt inutile —
    fişierele sunt şterse — iar acţiunea corectă e alta. Aşa un uninstall legitim nu mai
    produce un incident cu paşi imposibili, dar căderea nu e NICIODATĂ complet tăcută."""
    if uninstall_reported:
        _fire(f"[{host_name}] host offline after an uninstall report",
              f"The agent on '{host_name}' reported that it was uninstalled, then stopped "
              f"reporting ({int(silent_for)}s ago).\n\n"
              f"If you ran `ptyd.py uninstall` here, this is expected: remove the host in "
              f"WebTerm, or reinstall the agent and this clears itself.\n"
              f"If you did NOT: the agent was stopped by someone with shell access on the "
              f"host — the uninstall report is only authenticated by the host token. "
              f"Investigate the machine; do not assume the removal was intentional.",
              kind="host_offline", severity="warning", host_id=host_id)
        return
    _fire(f"[{host_name}] host offline",
          f"The agent on '{host_name}' has not reported for {int(silent_for)}s.\n\n"
          f"The tmux sessions on the host keep running — what broke is the link to the "
          f"gateway: the agent stopped, network/DNS, or the machine went down.\n"
          f"Check: `tmux -L webterm ls` on the host, then `~/.webterm/ptyd.log`.",
          kind="host_offline", severity="warning", host_id=host_id)


def notify_host_online(host_id: int, host_name: str) -> None:
    """Perechea celei de sus: fără ea, o alertă de cădere rămâne deschisă la nesfârşit. Chemată
    de sweep DOAR când chiar trimisesem o alertă de offline (hosts.offline_notified=1)."""
    _fire(f"[{host_name}] host back online",
          f"The agent on '{host_name}' is reporting again.",
          kind="host_offline", severity="ok", host_id=host_id)


def notify_disk_low(free: int, total: int, pct: float) -> None:
    """Discul gateway-ului se umple. Alerta asta lipsea, şi era singura care conta.

    Existau praguri de CPU/RAM/disc pentru hosturile ADMINISTRATE, alimentate din metricele
    agentului — dar nu şi pentru maşina gateway-ului, singura a cărei umplere opreşte tot
    produsul. Efectul măsurat al lipsei: container `healthy`, `/api/status` verde, iar
    login-ul răspunde 500 cu „database or disk is full". Nimeni n-avea unde să se uite.
    O dată la 6h, ca să nu devină zgomot cât timp cineva face loc."""
    if not _throttled("disk_low", 6 * 3600):
        return
    gb = lambda n: "%.1f GB" % (n / 1024 ** 3)          # noqa: E731
    _fire("Gateway disk is filling up (%.0f%% free)" % pct,
          f"The WebTerm gateway has {gb(free)} free of {gb(total)} ({pct:.1f}%).\n\n"
          f"When it runs out, the database and the transcripts stop being writable: logins "
          f"start failing with 500 while the container still reports healthy.\n\n"
          f"Transcripts are the usual cause. Lower WEBTERM_ARCHIVE_DAYS, or "
          f"WEBTERM_TRANSCRIPT_MAX_BYTES, or make room on the volume.",
          kind="gateway_disk", severity="critical")


def notify_signing_locked(behind: int) -> None:
    """The signing key is locked and the agents have fallen behind.

    The red dot in the UI helps someone who is looking at the UI. But upgrades are run from cron
    or remotely, and then the person walks away. Without an alert the fleet sits on an old version
    — with bugs fixed in the meantime — and nobody finds out. Once every 12h, so it stays signal
    rather than noise."""
    if not _throttled("signing_locked", 12 * 3600):
        return
    _fire("The signing key is locked — agents are NOT updating",
          f"The gateway has an ENCRYPTED signing key, and it is locked since the last restart.\n"
          f"{behind} agent(s) are on an older version and cannot be updated.\n\n"
          f"Unlock it: Settings → Infrastructure & tokens → Agent signing key.\n"
          f"Agent updates are signed, and without the key the gateway refuses (correctly) to "
          f"push unsigned code to the hosts.", kind="signing_locked", severity="warning")


def notify_update_refused(host_id: int, code: str, hint: str) -> None:
    """An agent refused a signed update. At most one alert per host every 6h."""
    if not _throttled(f"update_refused:{host_id}", 6 * 3600):
        return
    _fire("Agent: update REFUSED (%s)" % code,
          f"Host #{host_id} refused the agent update.\n\nReason: {code}\n{hint}\n\n"
          f"Until this is fixed the host stays on the old agent version — including without the "
          f"security fixes shipped since.", kind="update_refused", severity="warning",
          host_id=host_id)


def notify_backup_failed(provider: str, fails: int, last_ok_ts: float, error: str) -> None:
    """The SCHEDULED off-host backup upload keeps failing.

    A backup that only lives on the machine you are backing up doesn't survive losing that
    machine. The scheduled off-host copy was the safety net — and its failure was COMPLETELY
    silent (only a field for the UI nobody watches): an expired OAuth refresh or a wrong
    passphrase means the operator believes they have off-host copies they don't. Once every 12h,
    so a persistent failure stays signal rather than nightly noise."""
    if not _throttled("backup_failed", 12 * 3600):
        return
    if last_ok_ts:
        age_days = (time.time() - last_ok_ts) / 86400
        age = "The last SUCCESSFUL off-host backup was %.1f days ago." % age_days
    else:
        age = "There has NEVER been a successful off-host backup on this destination."
    _fire("Off-host backup is FAILING (%s)" % provider,
          f"The scheduled backup upload to '{provider}' has failed {fails} time(s) in a row.\n\n"
          f"{age}\n\nLast error: {error}\n\n"
          f"Common causes: expired OAuth authorisation (reconnect in Settings → Backup), a wrong "
          f"encryption passphrase, or the SFTP/FTPS server being unreachable or its host key "
          f"having changed. Until fixed, you have no fresh off-host copy of the vault.",
          kind="backup_failed", severity="critical")


def notify_local_backup_failed(error: str, last_ok_ts: float) -> None:
    """Backup-ul programat LOCAL (snapshot-ul de pe server) a eşuat.

    Perechea lui `notify_backup_failed` (copia off-host): acela pleca doar dacă snapshot-ul
    local reuşea şi uploadul pica. Dacă pica chiar snapshot-ul (disc plin, DB blocat) nu pleca
    NIMIC — nici upload, nici alertă — iar lista de backup-uri se golea tăcut prin retenţie
    (audit G-13/G-15 + UX §7.f1). O dată la 12h, ca o cauză persistentă să rămână semnal."""
    if not _throttled("backup_local_failed", 12 * 3600):
        return
    if last_ok_ts:
        age = "The last SUCCESSFUL scheduled backup was %.1f days ago." % ((time.time() - last_ok_ts) / 86400)
    else:
        age = "There has NEVER been a successful scheduled backup on this gateway."
    _fire("Scheduled backup is FAILING",
          f"The scheduled backup on the WebTerm gateway failed.\n\n{age}\n\nLast error: {error}\n\n"
          f"Common causes: the gateway disk is full, the database is locked by another process, or "
          f"the data volume is read-only. Until fixed, the local snapshots age out under retention "
          f"and there is no fresh copy of the vault — download a backup manually from Settings → "
          f"Backup if you cannot fix it right away.", kind="backup_failed", severity="critical")
