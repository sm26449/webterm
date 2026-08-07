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

from . import config, db

log = logging.getLogger("webterm")

# throttling in-memory: cheie -> ultimul epoch trimis
_last_sent: dict = {}

# cheile din tabela app_settings
_KEYS = ("smtp_host", "smtp_port", "smtp_user", "smtp_password_enc",
         "smtp_from", "smtp_to", "smtp_starttls", "alert_webhook")


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
    req = urllib.request.Request(url, data=payload, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "WebTerm"})
    with urllib.request.urlopen(req, timeout=10) as r:
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
    with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
        if cfg["starttls"]:
            # M2: context care VERIFICĂ certificatul serverului (hostname + CA). Fără el,
            # starttls() nu autentifică peer-ul → un MITM pe rețea putea intercepta
            # credențialele SMTP printr-un STARTTLS-stripping / cert fals.
            s.starttls(context=ssl.create_default_context())
        if cfg["user"]:
            s.login(cfg["user"], cfg["password"])
        s.send_message(msg)


def _fire(subject: str, body: str) -> None:
    """Send without blocking the handler; swallow any error (best-effort)."""
    async def _run():
        cfg = None
        try:
            cfg = await load_config()
            if _configured(cfg):
                await asyncio.to_thread(_send_blocking, cfg, subject, body)
        except Exception as e:
            log.warning("email alert failed (%s): %s", subject, e)
        # webhook-ul e independent de SMTP: cine are doar chat nu trebuie să ţină un SMTP
        try:
            url = (cfg or {}).get("webhook") or ""
            if url:
                await asyncio.to_thread(_post_webhook, url, subject, body)
        except Exception as e:
            log.warning("webhook alert failed (%s): %s", subject, e)

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
    await asyncio.to_thread(
        _send_blocking, cfg, "Test de configurare",
        "This is a test email from WebTerm. If it arrives, security alerts "
        "are working.")


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
          f"password — but access is blocked.")


def notify_agent_relocation(host_name: str, instance_short: str) -> None:
    """Un agent a încercat să se conecteze de pe o ALTĂ maşină pe tokenul unui host deja fixat
    (clonă de VM / token furat şi mutat) — conexiunea a fost REFUZATĂ. Semnal de compromis puternic.
    Cel mult o alertă / 15 min per host (un atacator care reîncearcă nu ne inundă)."""
    if not _throttled(f"reloc:{host_name}", 900):
        return
    _fire("Agent rejected: relocation/cloning attempt",
          f"Host '{host_name}' is pinned to one machine, but its token was used from a "
          f"DIFFERENT machine (instance {instance_short}…) — the connection was REFUSED.\n\n"
          f"If you are NOT reinstalling the host: someone has the agent's token and is trying "
          f"to use it elsewhere. Check the host; revoke or reinstall the agent if needed.")


def notify_agent_ip_change(host_name: str, old_ip: str, new_ip: str) -> None:
    """Agentul unui host s-a reconectat de la un IP nou. Informativ (IP-urile se schimbă legitim:
    DHCP / reboot / NAT), dar util ca semnal. Cel mult o alertă / oră per host."""
    if not _throttled(f"agentip:{host_name}", 3600):
        return
    _fire("Agent reconnected from a new IP",
          f"The agent on host '{host_name}' connected from a new IP.\n\n"
          f"New: {new_ip}\nPrevious: {old_ip}\n\n"
          f"Normal after a reboot or a network change. If the host has a fixed IP you did not touch, "
          f"it is worth a look.")


def notify_new_login(ip: str, user_agent: str, email: str) -> None:
    """A successful login from an IP never seen before. The most valuable signal."""
    _fire("New login on your account",
          f"Successful authentication for {email} from a new IP.\n\n"
          f"IP: {ip}\nBrowser: {user_agent or '?'}\n\n"
          f"If this was not you, change the password immediately and review the active "
          f"sessions in settings.")


def notify_security_change(what: str, ip: str, email: str) -> None:
    """A sensitive account change (password, 2FA, new passkey)."""
    _fire(f"Security change: {what}",
          f"On account {email}: {what}.\nIP: {ip}\n\n"
          f"If this was not you, the account is probably compromised.")


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
                f"you will hear again when it drops below {max(0, limit - HYSTERESIS)}%.")
        elif _firing.get(state_key) and value <= limit - HYSTERESIS:
            # revenire la normal: re-armăm și confirmăm rezolvarea
            _firing[state_key] = False
            _fire(
                f"[{host_name}] {_LABELS[key]} back to {value:.0f}%",
                f"Host {host_name}: {_LABELS[key]} dropped to {value:.1f}% "
                f"(below the {limit}% threshold minus the {HYSTERESIS}-point margin).")


# ── hostul a tăcut / a revenit ────────────────────────────────────────────────
# Aveam alerte pentru lockout, relocare de agent, IP schimbat, login nou şi praguri de
# resurse — dar NU pentru „agentul nu mai raportează", adică exact evenimentul pe care
# îl vrei primul într-o flotă. Semnalat de auditul extern, 2026-08-06.
_offline_since: dict = {}      # host_id -> epoch al alertei (prezent = l-am anunţat deja)


def notify_host_offline(host_id: int, host_name: str, silent_for: float) -> None:
    """Un host care raporta a încetat. O singură alertă per cădere (nu la fiecare tură a
    reaper-ului); revenirea se anunţă separat, ca să poţi închide incidentul."""
    if host_id in _offline_since:
        return
    _offline_since[host_id] = time.time()
    _fire(f"[{host_name}] host offline",
          f"The agent on '{host_name}' has not reported for {int(silent_for)}s.\n\n"
          f"The tmux sessions on the host keep running — what broke is the link to the "
          f"gateway: the agent stopped, network/DNS, or the machine went down.\n"
          f"Check: `tmux -L webterm ls` on the host, then `~/.webterm/ptyd.log`.")


def notify_host_online(host_id: int, host_name: str) -> None:
    """The counterpart of the one above: without it, a down alert stays open forever."""
    if _offline_since.pop(host_id, None) is None:
        return                                  # n-a fost anunţat ca offline → nimic de închis
    _fire(f"[{host_name}] host back online",
          f"The agent on '{host_name}' is reporting again.")


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
          f"WEBTERM_TRANSCRIPT_MAX_BYTES, or make room on the volume.")


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
          f"Unlock it: Settings → Security → unlock the fleet signing key.\n"
          f"Agent updates are signed, and without the key the gateway refuses (correctly) to "
          f"push unsigned code to the hosts.")


def notify_update_refused(host_id: int, code: str, hint: str) -> None:
    """An agent refused a signed update. At most one alert per host every 6h."""
    if not _throttled(f"update_refused:{host_id}", 6 * 3600):
        return
    _fire("Agent: update REFUSED (%s)" % code,
          f"Host #{host_id} refused the agent update.\n\nReason: {code}\n{hint}\n\n"
          f"Until this is fixed the host stays on the old agent version — including without the "
          f"security fixes shipped since.")
