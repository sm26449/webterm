"""SQLite access layer (aiosqlite, no ORM)."""

import logging
import time

import aiosqlite

from . import config

log = logging.getLogger("webterm")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    user_agent TEXT DEFAULT '',
    last_seen REAL
);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    credential_id BLOB NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT DEFAULT '',
    name TEXT DEFAULT '',
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    note TEXT DEFAULT '',
    token_hash TEXT UNIQUE NOT NULL,
    token_encrypted TEXT NOT NULL,
    enroll_token TEXT,
    enroll_expires REAL,
    instance_id TEXT,                        -- id de mașină pinat (anti-clonă: refuză al 2-lea host pe același token)
    agent_version INTEGER,
    backend TEXT,
    hostname TEXT,
    agent_user TEXT,
    last_heartbeat REAL,
    connection_type TEXT DEFAULT 'agent',   -- agent | ssh | telnet
    ssh_username TEXT,
    ssh_port INTEGER DEFAULT 22,
    auth_method TEXT,                        -- password | key
    credential_encrypted TEXT,               -- Fernet(JSON): {password} sau {key,passphrase}
    known_hosts TEXT,                        -- amprenta host key-ului pinată (TOFU)
    require_2fa INTEGER DEFAULT 0,
    credential_policy TEXT DEFAULT 'stored', -- stored | ask | ephemeral
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    host_id INTEGER NOT NULL,
    title TEXT DEFAULT '',
    note TEXT DEFAULT '',
    state TEXT NOT NULL,              -- creating | live | closed | lost
    created REAL NOT NULL,
    closed_at REAL,
    exit_status INTEGER,
    close_reason TEXT,
    rows INTEGER DEFAULT 24,
    cols INTEGER DEFAULT 80,
    agent_epoch TEXT,
    agent_offset INTEGER DEFAULT 0,
    kind TEXT DEFAULT 'shell',        -- shell | telnet (bastion telnet-via-agent)
    -- ținta telnet-bastion, păstrată ca reconectarea (după căderea agentului) să
    -- redeschidă un telnet nou spre același device fără a depinde de forward-ul-sursă
    target_host TEXT,
    target_port INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_host ON sessions(host_id, created);
CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state, created);
CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created);
CREATE TABLE IF NOT EXISTS snippets (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,          -- sha256 al codului; single-use
    used REAL,                        -- epoch când a fost folosit, altfel NULL
    created REAL NOT NULL
);
-- IP-urile de pe care s-a autentificat cu succes (hash), pt. alerta „login nou"
CREATE TABLE IF NOT EXISTS seen_logins (
    user_id INTEGER NOT NULL,
    ip_hash TEXT NOT NULL,
    created REAL NOT NULL,
    PRIMARY KEY (user_id, ip_hash)
);
-- setări editabile din UI (ex. SMTP); valorile sensibile se stochează criptate
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
-- port forwards: proxy HTTP(S) prin agent către un serviciu de pe host. `slug`
-- e eticheta de subdomeniu (unic). Ținta e declarată de admin (anti-SSRF: nu vine
-- niciodată din URL). enabled=0 implicit → ruta nu proxyează până nu o pornești.
CREATE TABLE IF NOT EXISTS port_forwards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    label TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    target_host TEXT NOT NULL DEFAULT '127.0.0.1',
    target_port INTEGER NOT NULL,
    scheme TEXT NOT NULL DEFAULT 'http',
    description TEXT DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0,
    created REAL NOT NULL
);

-- istoric global de comenzi (căutabil, audit-lite): comenzi finalizate raportate
-- de client din marcajele OSC 133 + comenzi rulate pe flotă. source: 'session'|'fleet'.
CREATE TABLE IF NOT EXISTS command_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    host_name TEXT DEFAULT '',
    command TEXT NOT NULL,
    exit_code INTEGER,
    cwd TEXT DEFAULT '',
    source TEXT NOT NULL DEFAULT 'session',
    created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cmdhist_created ON command_history(created);

-- Jurnal de evenimente de conexiune ale agentului (observabilitate/debug): connect,
-- disconnect (cu motiv), update pushed/deferred/applied, conflict. Retenţie 7 zile.
CREATE TABLE IF NOT EXISTS agent_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    event TEXT NOT NULL,          -- connect / disconnect / update_pushed / update_deferred / update_applied / conflict
    reason TEXT DEFAULT '',       -- heartbeat_stale / superseded / ws_error / closed / instance_refused / ...
    detail TEXT DEFAULT ''        -- ex. versiune agent, instanţă scurtă
);
CREATE INDEX IF NOT EXISTS idx_agent_events_host ON agent_events(host_id, ts);

-- jurnal de audit: o linie per cerere care schimbă ceva (POST/PATCH/PUT/DELETE pe /api).
-- Umplut automat din middleware (vezi audit.py) — nu din apeluri manuale, ca să nu rămână
-- în urma endpoint-urilor noi. NU conține corpuri de cerere (parole, conținut de fișier).
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT DEFAULT '',        -- emailul contului (gol = cerere neautentificată, ex. login eșuat)
    ip TEXT DEFAULT '',           -- IP-ul clientului, așa cum îl vede gateway-ul (vezi TRUSTED_PROXY_HOPS)
    method TEXT NOT NULL,
    path TEXT NOT NULL,           -- calea, fără query string (poate conține token de share/enroll)
    status INTEGER NOT NULL,      -- codul HTTP: >=400 = acțiune respinsă
    detail TEXT DEFAULT ''        -- contextul atașat de endpoint (comandă, fișier, host)
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

-- token-uri de automatizare (cron, CI, monitorizare). NU sunt „conturi fără parolă": merg
-- DOAR pe o listă albă mică de endpoint-uri, cu scope explicit, expirare obligatorie şi fără
-- acces la hosturile cu 2FA (step-up-ul cere passkey, un token nu-l poate satisface).
-- Stocăm doar hash-ul; valoarea în clar se arată o singură dată, la creare.
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    scopes TEXT NOT NULL DEFAULT 'read',   -- listă separată prin virgulă: read | run
    created REAL NOT NULL,
    created_by TEXT DEFAULT '',            -- emailul contului care l-a emis
    expires REAL NOT NULL,                 -- expirarea e OBLIGATORIE
    last_used REAL
);
"""

# additive migrations for DBs created by an older version
MIGRATIONS = [
    "ALTER TABLE hosts ADD COLUMN folder TEXT DEFAULT ''",
    # Revocarea era cheiată pe EMAIL, care e mutabil: schimbi emailul, iar ştergerea contului
    # nu mai prinde nici tokenurile lui, nici share-urile — tokenul trăia până la 365 de zile.
    # Emailul rămâne, pentru afişare şi pentru rândurile vechi; decizia se ia pe id.
    "ALTER TABLE api_tokens ADD COLUMN created_by_id INTEGER",
    "ALTER TABLE sessions ADD COLUMN share_by_id INTEGER",
    "ALTER TABLE sessions ADD COLUMN share_token TEXT",
    "ALTER TABLE sessions ADD COLUMN share_expires REAL",
    "ALTER TABLE sessions ADD COLUMN share_writable INTEGER DEFAULT 0",
    "ALTER TABLE sessions ADD COLUMN serial_config TEXT",   # JSON: device/baud/biți/paritate/stop/flow
    "ALTER TABLE sessions ADD COLUMN kind TEXT DEFAULT 'shell'",
    # conectare directă SSH/Telnet
    "ALTER TABLE hosts ADD COLUMN connection_type TEXT DEFAULT 'agent'",
    "ALTER TABLE hosts ADD COLUMN ssh_username TEXT",
    "ALTER TABLE hosts ADD COLUMN ssh_port INTEGER DEFAULT 22",
    "ALTER TABLE hosts ADD COLUMN auth_method TEXT",
    "ALTER TABLE hosts ADD COLUMN credential_encrypted TEXT",
    "ALTER TABLE hosts ADD COLUMN known_hosts TEXT",
    "ALTER TABLE hosts ADD COLUMN agent_ip TEXT",   # ultimul IP sursă văzut al agentului (observabilitate)
    "ALTER TABLE hosts ADD COLUMN require_2fa INTEGER DEFAULT 0",
    "ALTER TABLE hosts ADD COLUMN credential_policy TEXT DEFAULT 'stored'",
    "ALTER TABLE hosts ADD COLUMN instance_id TEXT",
    # 2FA prin TOTP (opțional, activat de user)
    # cu mai multe conturi, watermark-ul ${email} de pe un share trebuie să arate cine l-a
    # creat, nu „primul cont din tabelă"
    "ALTER TABLE sessions ADD COLUMN share_by TEXT",
    # de ce agentul nu se poate actualiza (cod de refuz). În RAM nu ajungea: nici UI-ul după
    # un restart, nici `upgrade.sh`, care întreabă DB-ul dintr-un proces separat. Un audit de
    # ciclu de viaţă a arătat că starea era vizibilă doar în log — invizibilă din cron.
    "ALTER TABLE hosts ADD COLUMN update_blocked TEXT",
    "ALTER TABLE users ADD COLUMN totp_secret_encrypted TEXT",
    "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0",
    # anti-replay TOTP: ultimul pas de timp (counter) consumat cu succes
    "ALTER TABLE users ADD COLUMN totp_last_counter INTEGER DEFAULT 0",
    # ținta telnet-bastion, pt. reconectarea sesiunii după căderea agentului
    "ALTER TABLE sessions ADD COLUMN target_host TEXT",
    "ALTER TABLE sessions ADD COLUMN target_port INTEGER",
    "ALTER TABLE web_sessions ADD COLUMN last_seen REAL",   # L2: idle-expiry pe sesiunile web
]

# tabele adăugate ulterior (executeScript de mai sus le creează pe DB-uri noi;
# pentru DB-uri vechi, CREATE TABLE IF NOT EXISTS e idempotent la fiecare boot)

_conn: aiosqlite.Connection = None


def connected() -> bool:
    """True dacă DB-ul e conectat. Căile best-effort care rulează în task-uri de fundal
    (ex. alertele email la lockout) o folosesc ca să nu arunce NoneType.execute dacă
    nimeresc un moment de startup/shutdown când `_conn` e încă/deja None."""
    return _conn is not None


async def connect() -> None:
    global _conn
    config.ensure_dirs()
    _conn = await aiosqlite.connect(config.DB_PATH)
    _conn.row_factory = aiosqlite.Row
    await _conn.executescript(SCHEMA)
    for stmt in MIGRATIONS:
        try:
            await _conn.execute(stmt)
        except Exception as e:
            # migrațiile aditive re-rulate lovesc „duplicate column" — normal, îl ignorăm.
            # ORICE altă eroare (schema drift real, DB corupt) NU trebuie înghițită tăcut.
            if "duplicate column" not in str(e).lower():
                log.warning("migration failed (%s): %s", stmt.split("ADD COLUMN")[-1].strip()[:40], e)
    # index pt. lookup-ul pe share_token (endpoint PUBLIC /ws/shared/{token} + shared_meta):
    # coloana vine dintr-o migrație, deci indexul se creează DUPĂ. Fără el, fiecare cerere
    # (inclusiv cu token invalid) scanează toată tabela sessions (~120z istoric) — amplificare
    # ieftină pt. un atacator care lovește tokenuri aleatoare. Parțial → mic (doar sesiuni share-uite).
    await _conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sessions_share ON sessions(share_token) "
        "WHERE share_token IS NOT NULL")
    await _conn.execute("PRAGMA journal_mode=WAL")
    # synchronous=NORMAL: sub WAL, durabil la crash de proces (doar un crash de OS/kernel
    # în fereastra dintre commit și checkpoint poate pierde ultima tranzacție — acceptabil
    # pt. state-ul ăsta). Elimină un fsync per commit pe calea caldă (heartbeat, checkpoint,
    # istoric) → câștig mare de I/O pe HDD/SD. busy_timeout: nu eșua instant pe lock.
    await _conn.execute("PRAGMA synchronous=NORMAL")
    await _conn.execute("PRAGMA busy_timeout=5000")
    # curăță sesiunile web expirate (altfel tabelul crește la nesfârșit)
    await _conn.execute("DELETE FROM web_sessions WHERE expires < ?", (now(),))
    await _conn.commit()


async def close() -> None:
    global _conn
    if _conn:
        await _conn.close()
        _conn = None


async def fetchone(sql: str, *args):
    async with _conn.execute(sql, args) as cur:
        return await cur.fetchone()


async def fetchall(sql: str, *args):
    async with _conn.execute(sql, args) as cur:
        return await cur.fetchall()


async def execute(sql: str, *args) -> int:
    cur = await _conn.execute(sql, args)
    await _conn.commit()
    return cur.lastrowid


async def execute_returning(sql: str, *args):
    """Run a write with a RETURNING clause and return the row (or None). The
    UPDATE + read is a single serialized statement, so concurrent callers can't
    both claim the same row (used for single-use enroll tokens)."""
    async with _conn.execute(sql, args) as cur:
        row = await cur.fetchone()
    await _conn.commit()
    return row


def now() -> float:
    return time.time()
