"""Gateway configuration from environment variables."""

import logging
import os
import secrets
from pathlib import Path

log = logging.getLogger("webterm")


def _str(name, default):
    """Şir din mediu, tolerant la valoarea GOALĂ — perechea lui `_num`.

    Aceeaşi capcană, partea de şiruri: compose pasează `${VAR:-}`, deci variabila ajunge
    PREZENTĂ şi goală, iar `os.environ.get(name, default)` întoarce default DOAR când lipseşte.
    Numericele au fost reparate după ce un `int("")` a doborât gateway-ul la pornire; şirurile
    au rămas, şi eşuează mai urât fiindcă nu crapă — se comportă greşit în tăcere:
    `WEBTERM_UPDATE_REPO` gol → verificarea de versiuni interoghează un repo inexistent, deci
    nimeni nu mai află de un release de securitate; `WEBTERM_DATA_DIR` gol → `Path("")` se
    rezolvă la directorul CURENT, nu la `data/`; `WEBTERM_SMTP_STARTTLS` gol → criptarea la
    trimiterea mailului se stinge singură."""
    return (os.environ.get(name) or "").strip() or default


GATEWAY_VERSION = "2.0.5"

# Referința imaginii care rulează (setată la deploy prin compose), afișată în UI
# ca să știi mereu ce versiune e live. Gol în dev (rulare din surse).
IMAGE_REF = os.environ.get("WEBTERM_IMAGE_REF", "")

# Verificare „există versiune nouă?" — singura conexiune pe care gateway-ul o
# inițiază singur spre exterior. Pe repo public merge fără niciun secret; pe repo
# privat cere un token read-only (opțional, scope minim: metadata read).
# WEBTERM_UPDATE_CHECK=0 o oprește complet (există și comutator în Setări).
UPDATE_CHECK = _str("WEBTERM_UPDATE_CHECK", "1") != "0"
UPDATE_CHECK_TOKEN = os.environ.get("WEBTERM_UPDATE_CHECK_TOKEN", "")
UPDATE_REPO = _str("WEBTERM_UPDATE_REPO", "sm26449/webterm")
# Ce trebuie rulat ca să iei versiunea nouă. UI-ul o AFIȘEAZĂ, nu o execută: un buton
# care repornește aplicația din interiorul ei ar cere gateway-ului drept de creare de
# containere, adică root pe host. Update-ul rămâne o decizie dată de la tastatură.
# `{version}` se înlocuiește cu tag-ul găsit.
# `or` nu `get(default)`: compose trimite variabila GOALĂ când nu e setată în .env,
# iar `get` ar întoarce "" și am rămâne fără comandă de afișat.
#
# `upgrade.sh`, nu `deploy.sh`. Sugera `deploy.sh`, care schimbă DOAR imaginea — iar
# jumătate din sistem rulează pe HOST, nu în container: `backup.sh`, `restore.sh`,
# `rollback.sh`, compose-ul şi `upgrade.sh` însuşi. `/opt/webterm` nu e un checkout git,
# deci ele rămân îngheţate la ce a pus instalatorul. README-ul spune exact asta şi
# recomandă `upgrade.sh`; notificarea din UI recomanda contrariul, adică fix drumul
# despre care documentaţia avertizează. În plus `upgrade.sh` face backup ÎNAINTE de
# upgrade — omul care urmează sugestia aplicaţiei merita şi plasa aia.
UPDATE_COMMAND = (os.environ.get("WEBTERM_UPDATE_COMMAND", "").strip()
                  or "cd /opt/webterm && sudo ./upgrade.sh {version}")

DATA_DIR = Path(_str("WEBTERM_DATA_DIR", "data")).resolve()
TRANSCRIPT_DIR = DATA_DIR / "transcripts"
# transcripturile sesiunilor șterse se mută aici, se păstrează o vreme, apoi se curăță
ARCHIVE_DIR = TRANSCRIPT_DIR / "arhiva"
DB_PATH = DATA_DIR / "webterm.db"


def _num(name, default, cast=int):
    """Numeric din mediu, tolerant la valoarea GOALĂ.

    `os.environ.get(name, default)` întoarce default DOAR când variabila lipseşte. Compose o
    pasează cu `${VAR:-}`, adică PREZENTĂ şi goală când n-o pui în `.env` — iar `int("")` ridică
    ValueError la import, deci gateway-ul nici nu porneşte. S-a întâmplat exact aşa la deploy-ul
    1.0.153: passthrough-urile adăugate în compose au scos la iveală citirile astea şi containerul
    a intrat în buclă de restart (failsafe-ul a făcut rollback, dar producţia a fost jos).
    O valoare invalidă (nu doar goală) cade tot pe default, cu avertisment: un typo în `.env` nu
    trebuie să doboare serviciul."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return cast(raw)
    except ValueError:
        log.warning("%s=%r is not a valid number — using %s", name, raw, default)
        return default


# câte zile păstrăm transcripturile arhivate înainte de ștergerea definitivă
ARCHIVE_RETENTION_DAYS = _num("WEBTERM_ARCHIVE_DAYS", 120)
# După câte zile o sesiune ÎNCHISĂ îşi mută transcriptul în arhivă (de unde îl şterge
# retenţia de mai sus). Arhivarea se făcea DOAR la ştergerea manuală a sesiunii, deci o
# sesiune pur şi simplu închisă îşi păstra cele două fişiere la nesfârşit — până la 64 MiB
# fiecare. Singura creştere nemărginită din produs, găsită de un audit extern: 120 de
# sesiuni închise = 240 de fişiere pe care nimeni nu le mai atingea. 0 dezactivează.
CLOSED_ARCHIVE_DAYS = _num("WEBTERM_CLOSED_ARCHIVE_DAYS", 30)
# jurnalul de audit (cine/ce/când/de la ce IP pe fiecare cerere care schimbă ceva).
# Aceeași fereastră ca arhiva: destul cât să reconstitui un incident, nu la infinit.
AUDIT_RETENTION_DAYS = _num("WEBTERM_AUDIT_DAYS", 120)

# Public URL the browser and the agents use to reach the gateway.
PUBLIC_URL = _str("WEBTERM_PUBLIC_URL", "http://localhost:8000").rstrip("/")

# Bake "insecure": true into agent configs (self-signed TLS on the gateway).
AGENT_INSECURE = os.environ.get("WEBTERM_AGENT_INSECURE", "") == "1"

# Optional fixed setup token; if unset, one is generated on first boot and
# printed to the logs. Required to create the first account (anti-hijack).
SETUP_TOKEN = os.environ.get("WEBTERM_SETUP_TOKEN") or None

AGENT_FILE = Path(os.environ.get(
    "WEBTERM_AGENT_FILE",
    Path(__file__).resolve().parent.parent.parent / "agent" / "ptyd.py"))

HEARTBEAT_STALE = 90.0          # seconds without heartbeat -> host offline
# Sesiunea de browser: TTL absolut + expirare pe inactivitate. Uşa din faţă e un root shell pe
# toată flota, deci cine vrea o fereastră mai strânsă (device furat, laptop împrumutat) trebuie
# s-o poată strânge fără rebuild. Default-urile rămân cele istorice: 30 zile / 12 ore.
WEB_SESSION_TTL = int(_num("WEBTERM_SESSION_TTL_DAYS", 30, float) * 24 * 3600)
WEB_SESSION_IDLE = int(_num("WEBTERM_SESSION_IDLE_HOURS", 12, float) * 3600)
# idle-lock de securitate: pe host-urile cu require_2fa, blochează terminalul (output
# suprimat + input refuzat) după atâtea secunde fără input de operator; reluarea cere
# un step-up passkey. 0 = dezactivat. Apără de sesiuni autentificate nesupravegheate.
IDLE_LOCK_SECS = _num("WEBTERM_IDLE_LOCK_SECS", 300)
BROWSER_TAIL_BYTES = 256 * 1024  # transcript tail replayed to a connecting browser
# per-session transcript cap: when .out passes MAX, keep only the last KEEP bytes
# (head-truncated, gap-marked) so a runaway `cat`/`yes` can't fill the disk.
TRANSCRIPT_MAX_BYTES = _num("WEBTERM_TRANSCRIPT_MAX_BYTES", 64 * 1024 * 1024)
TRANSCRIPT_KEEP_BYTES = _num("WEBTERM_TRANSCRIPT_KEEP_BYTES", 16 * 1024 * 1024)
# reverse-proxy topology for real-client-IP (rate-limit/lockout correctness).
# X-Forwarded-For is spoofable on the left; only the proxies you actually run
# are authoritative. Number of trusted hops in front of the gateway: Caddy=1,
# Cloudflare→Traefik=2. Cloudflare users can instead trust CF-Connecting-IP.
TRUSTED_PROXY_HOPS = max(1, _num("WEBTERM_TRUSTED_PROXY_HOPS", 1))
TRUST_CF_CONNECTING_IP = os.environ.get("WEBTERM_TRUST_CF_IP", "").lower() in ("1", "true", "yes")
# Cine are voie să scrie X-Forwarded-For. Implicit: orice peer din reţea privată/loopback —
# într-un deployment normal proxy-ul e pe reţeaua docker. Dacă aplicaţia devine accesibilă din
# altă parte a reţelei interne (alt container, alt host din LAN), „privat" nu mai e suficient:
# atunci restrânge la CIDR-ul proxy-ului, ex. `172.18.0.0/16` sau `10.1.2.3/32`.
# Semnalat de auditul de ciclu de viaţă, 2026-08-06.
TRUSTED_PROXY_CIDRS = [c.strip() for c in
                       os.environ.get("WEBTERM_TRUSTED_PROXY_CIDRS", "").split(",") if c.strip()]
CLIENT_BUFFER_LIMIT = _num("WEBTERM_CLIENT_BUFFER", 1024 * 1024)  # per-browser-ws backlog before forced resync

# Brute-force: câte eșecuri per IP în fereastră înainte de lockout. Implicit 5
# (era 8); pe un tool cu un singur admin, prea jos (2-3) te blochează pe typo.
IP_MAX_FAILS = max(1, _num("WEBTERM_IP_MAX_FAILS", 5))

# ── Alerte pe email (opțional). Fără SMTP host → totul e no-op. ───────────────
# Trimite: lockout de IP (throttled) și login reușit de pe un IP nou.
SMTP_HOST = os.environ.get("WEBTERM_SMTP_HOST", "")
SMTP_PORT = _num("WEBTERM_SMTP_PORT", 587)
SMTP_USER = os.environ.get("WEBTERM_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("WEBTERM_SMTP_PASSWORD", "")
SMTP_STARTTLS = _str("WEBTERM_SMTP_STARTTLS", "1").lower() in ("1", "true", "yes")
# expeditor și destinatar (adresa de admin care primește alertele)
# `_str`, nu `get`: compose pasează `${WEBTERM_ALERT_FROM:-}`, deci variabila ajunge
# PREZENTĂ şi GOALĂ, iar `get(name, default)` cade pe default doar când LIPSEŞTE. Aici
# default-ul e altă valoare de config (`SMTP_USER`), deci rezultatul era "" — şi
# `email_alerts_enabled()` devenea False. Operatorul care punea SMTP în `.env` fără
# `WEBTERM_ALERT_FROM` nu mai primea alertele de lockout şi de login de pe IP nou,
# fără nicio eroare. Exact capcana pentru care există `_str`.
ALERT_FROM = _str("WEBTERM_ALERT_FROM", SMTP_USER)
ALERT_TO = os.environ.get("WEBTERM_ALERT_TO", "")
# Alerte şi pe webhook (Slack/Discord/Teams/orice endpoint JSON). Independent de SMTP:
# emailul e bun de arhivă, dar prost pentru reacţie — la un lockout sau la o flotă care
# cade vrei un ping în chat, nu un mail citit peste trei ore.
ALERT_WEBHOOK = os.environ.get("WEBTERM_ALERT_WEBHOOK", "")


def email_alerts_enabled() -> bool:
    return bool(SMTP_HOST and ALERT_TO and ALERT_FROM)


def ws_public_url() -> str:
    if PUBLIC_URL.startswith("https://"):
        return "wss://" + PUBLIC_URL[len("https://"):]
    return "ws://" + PUBLIC_URL[len("http://"):]


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)


# Set when load_secret() had to mint a brand-new key (i.e. the file was absent).
# Startup uses this to refuse booting against an existing encrypted vault with a
# fresh key, which would silently make every stored secret undecryptable.
secret_was_generated = False


def load_secret() -> bytes:
    """Cookie-signing / crypto secret, generated once and kept in data/."""
    global secret_was_generated
    ensure_dirs()
    path = DATA_DIR / "secret"
    if path.exists():
        return path.read_bytes()
    secret = secrets.token_bytes(32)
    path.write_bytes(secret)
    path.chmod(0o600)
    secret_was_generated = True
    return secret
