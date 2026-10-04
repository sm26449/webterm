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
-- Cod de confirmare trimis pe email, pentru schimbări de credenţiale iniţiate de pe un
-- dispozitiv necunoscut. Un singur challenge viu per (cont, scop): un al doilea „trimite-mi
-- codul" îl înlocuieşte pe primul, ca să nu se acumuleze coduri valide în inbox.
CREATE TABLE IF NOT EXISTS email_challenges (
    user_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, purpose)
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
-- Token de înrolare DE GRUP: onboarding la scară de flotă. Un singur one-liner rulat pe N
-- maşini; la fiecare `/install/group/<token>` gateway-ul AUTO-CREEAZĂ un host nou cu PROPRIUL
-- token permanent (deci fiecare maşină e revocabilă individual — modelul per-host nu se erodează).
-- Tokenul de grup doar AUTORIZEAZĂ crearea: opt-in, expiră OBLIGATORIU, revocabil, plafon de
-- utilizări, iar fiecare auto-enroll e auditat + alertat.
CREATE TABLE IF NOT EXISTS enroll_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,       -- sha256 al tokenului (valoarea se arată o singură dată)
    created REAL NOT NULL,
    created_by TEXT DEFAULT '',
    expires REAL NOT NULL,                 -- expirarea e OBLIGATORIE (ca la api_tokens)
    max_uses INTEGER NOT NULL DEFAULT 0,   -- 0 = nelimitat (dar tot expiră)
    uses INTEGER NOT NULL DEFAULT 0,
    folder TEXT DEFAULT '',                -- hosturile noi aterizează aici
    require_2fa INTEGER NOT NULL DEFAULT 0,-- hosturile noi moştenesc asta
    revoked INTEGER NOT NULL DEFAULT 0
);

-- Lansatoare de conexiuni DB: o conexiune salvată → o sesiune care rulează CLI-ul potrivit
-- (psql/mysql/mongosh/clickhouse-client/redis-cli) pe HOSTUL agentului, cu ţinta pre-completată.
-- Lansator, nu client. `cred_policy`='ask' (implicit, clientul cere parola — zero secrete stocate)
-- | 'stored' (parolă în vault criptat, injectată prin env la copil — slice 2) | 'ephemeral'.
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,               -- hostul de agent care rulează clientul
    label TEXT NOT NULL,
    engine TEXT NOT NULL,                    -- postgres|mysql|mongodb|clickhouse|redis
    target_host TEXT DEFAULT '',             -- gol => localhost pe hostul agentului
    target_port INTEGER,
    username TEXT DEFAULT '',
    dbname TEXT DEFAULT '',
    extra_args TEXT DEFAULT '',              -- flaguri opţionale (validate server-side)
    cred_policy TEXT DEFAULT 'ask',          -- ask | stored | ephemeral
    credential_encrypted TEXT,               -- doar pentru 'stored' (vault, slice 2)
    created REAL NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS split_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,                -- proprietarul layout-ului (izolare multi-account)
    name TEXT NOT NULL,
    panes TEXT NOT NULL DEFAULT '[]',        -- JSON: 2-4 sid-uri DISTINCTE (sessions.id e TEXT)
    ratio REAL DEFAULT 0.5,                  -- divider pt. 2 panouri (0.15..0.85)
    broadcast INTEGER DEFAULT 0,             -- tastare difuzată în toate panourile
    position INTEGER DEFAULT 0,              -- ordinea în bara de taburi
    created REAL NOT NULL,
    updated REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_split_views_user ON split_views(user_id, position);

-- Chei de deploy host→host (Toolbox → SSH keys): PRIVATA se naşte şi RĂMÂNE pe hostul
-- sursă (~/.ssh/webterm_ed25519, generată de agent prin op-ul `run`); aici ţinem DOAR
-- materialul public + graful de unde-e-deployată, ca accesul să fie inventariat şi
-- revocabil per-muchie. O cheie per host sursă (UNIQUE) — fără fişiere derivate din label.
CREATE TABLE IF NOT EXISTS ssh_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL UNIQUE,        -- hostul SURSĂ (unde stă privata)
    public_key TEXT NOT NULL,               -- linia publică validată strict (o singură linie)
    fingerprint TEXT NOT NULL,              -- SHA256:… calculat în gateway din blob
    comment TEXT DEFAULT '',
    created REAL NOT NULL,
    created_by TEXT DEFAULT ''
);

-- O muchie sursă→ţintă: linia EXACT aşa cum a fost scrisă în authorized_keys (cu opţiunile
-- ei), ca UI-ul să poată arăta diff-ul; revocarea potriveşte pe BLOB (câmpul 2), nu pe linie,
-- ca o editare manuală a opţiunilor pe ţintă să nu lase cheia validă dar „revocată".
CREATE TABLE IF NOT EXISTS ssh_key_deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER NOT NULL,
    target_host_id INTEGER NOT NULL,
    options TEXT DEFAULT '',                -- '' | 'from="…"' (validat strict server-side)
    line TEXT NOT NULL,                     -- linia scrisă (options + public_key)
    status TEXT DEFAULT 'deployed',         -- deployed | edited | missing | revoked
    deployed_at REAL NOT NULL,
    deployed_by TEXT DEFAULT '',
    revoked_at REAL,
    UNIQUE(key_id, target_host_id)
);
CREATE INDEX IF NOT EXISTS idx_sshdep_target ON ssh_key_deployments(target_host_id);
"""

# additive migrations for DBs created by an older version
MIGRATIONS = [
    "ALTER TABLE hosts ADD COLUMN folder TEXT DEFAULT ''",
    # „Sesiunea asta s-a deschis de pe un loc nemaivăzut." Se ştampilează O DATĂ, la login,
    # şi NU se recalculează după: login-ul reuşit înregistrează IP-ul în `seen_logins`, deci
    # o verificare făcută mai târziu ar găsi mereu adresa „cunoscută" — verdictul trebuie
    # îngheţat exact în momentul în care era încă adevărat.
    "ALTER TABLE web_sessions ADD COLUMN device_new INTEGER DEFAULT 0",
    # Agentul a fost scos de pe host cu `ptyd.py uninstall`. NU ştergem hostul aici:
    # asta ar duce decizia distructivă la cine are shell pe maşină, iar hostul ar putea
    # dispărea din tabloul operatorului fără ca el să afle. Marcăm, şi UI-ul întreabă.
    "ALTER TABLE hosts ADD COLUMN uninstalled_at REAL",
    # De câte ori s-a logat contul de la adresa asta. „Văzută o dată" nu e un loc
    # obişnuit — un atacator care ştie parola şi se loghează de două ori de la el
    # de-acasă şi-ar declara singur adresa drept cunoscută. DEFAULT 3, ca instalările
    # existente să nu-şi piardă dintr-odată toate locurile familiare: rândurile care
    # există deja chiar reprezintă login-uri reale, doar că nu le numărasem.
    "ALTER TABLE seen_logins ADD COLUMN logins INTEGER NOT NULL DEFAULT 3",
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
    # SSO/OIDC: `sub`-ul stabil al userului la IdP (ex. Authentik). NULL = cont local
    # (break-glass). Potrivim după `sub` (imutabil), emailul rămâne pentru afişare/audit.
    "ALTER TABLE users ADD COLUMN sso_subject TEXT",
    # O identitate IdP (`sub`) = cel mult un cont. Index unic parţial (NULL-urile nu se ciocnesc)
    # — gard la nivel de DB peste check-then-act din provizionarea SSO, ca două callback-uri
    # concurente pentru acelaşi `sub` să nu poată dubla contul.
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso_subject ON users(sso_subject) "
    "WHERE sso_subject IS NOT NULL",
    # Host auto-înrolat printr-un token de grup: numele e un placeholder până când agentul
    # raportează hostname-ul la prima conectare, moment în care îl adoptăm ŞI stingem flagul
    # (deci o redenumire ulterioară din UI rămâne). Vezi `/install/group` + reconcile.
    "ALTER TABLE hosts ADD COLUMN name_auto INTEGER NOT NULL DEFAULT 0",
    # Etichete libere pe host (listă separată prin virgulă, normalizată lowercase): filtrare la
    # scară de flotă („all prod", „all debian") mai flexibilă decât folderul (o singură ierarhie).
    "ALTER TABLE hosts ADD COLUMN tags TEXT DEFAULT ''",
    # Ultimul snapshot de diagnostic (JSON: sistem/cpu/mem/storage/reţea+rute), pushat de agent la
    # conectare + orar, plus on-demand. Persistat ca să rămână VIZIBIL când hostul e down (vezi ce
    # IP-uri/rute avea), cu `diagnostics_at` = momentul colectării pentru eticheta „acum X".
    "ALTER TABLE hosts ADD COLUMN diagnostics TEXT",
    "ALTER TABLE hosts ADD COLUMN diagnostics_at REAL",
    # Parolă temporară OPŢIONALĂ pe link-ul de înrolare: hash-ul (argon2) al unei parole cerute la
    # instalare, pe lângă token-ul din URL. Livrată pe alt canal → un URL scurs singur nu ajunge.
    # NULL = fără parolă (comportamentul clasic). Se stinge odată cu token-ul, la revendicare.
    "ALTER TABLE hosts ADD COLUMN enroll_pass_hash TEXT",
    # Aceeaşi parolă opţională, dar pe token-ul de GRUP (reutilizabil): cerută la fiecare instalare.
    "ALTER TABLE enroll_groups ADD COLUMN pass_hash TEXT",
    # Un forward promovat la „app" (bookmark): tip aplicaţie (proxmox/portainer/custom) pentru icon
    # + agregare pe dashboard. Gol = forward obişnuit. Un bookmark E un forward + puţină metadată.
    "ALTER TABLE port_forwards ADD COLUMN app_type TEXT DEFAULT ''",
    # Alerte de host offline: `alerts_muted` le opreşte per-host (ex. o maşină oprită
    # intenţionat); `offline_notified` persistă dedup-ul „am trimis deja alerta de cădere"
    # (înainte trăia doar în RAM → o repornire de gateway re-trimitea pentru fiecare host tăcut).
    "ALTER TABLE hosts ADD COLUMN alerts_muted INTEGER DEFAULT 0",
    "ALTER TABLE hosts ADD COLUMN offline_notified INTEGER DEFAULT 0",
    # SSH-jump (bastion de prim rang): un host de tip `ssh-jump` e un host SSH-direct al cărui
    # TCP trece prin tunelul agentului `via_host_id` (open_forward), nu printr-un socket direct.
    # Gateway-ul rulează clientul asyncssh peste tunel → DEŢINE pinning-ul de host-key (anti-MITM).
    "ALTER TABLE hosts ADD COLUMN via_host_id INTEGER",
    # Host EFEMER (conectare „o singură dată", fără salvare): o ţintă ssh-jump/telnet-jump
    # creată doar ca să deschizi o sesiune acum. Ascuns din sidebar; un reaper îl şterge
    # când nu mai are sesiuni vii (vezi core.sweep_ephemeral_hosts).
    "ALTER TABLE hosts ADD COLUMN ephemeral INTEGER DEFAULT 0",
    # Rezumatul {count, security, manager} al update-urilor OS, extras din diagnostic LA PRIMIRE
    # (core.updates_summary): listarea hosturilor îl citeşte direct, în loc să parseze tot blobul
    # de diagnostic per host la fiecare poll (audit 2026-10-04, S-03). '' = snapshot fără
    # update-uri raportate; NULL = rând de dinaintea coloanei (fallback pe blob, mărginit).
    "ALTER TABLE hosts ADD COLUMN updates_summary TEXT",
    # alarma de host-key schimbat (SSH direct / jump): JSON {old_fp, new_fp, new_key, changed_at}.
    # Persistă până la „accept" (re-pin după verificare out-of-band) sau până la resetarea
    # pinului (PATCH cu hostname/port nou). Cât e setată, conectarea e REFUZATĂ fără dial.
    "ALTER TABLE hosts ADD COLUMN hostkey_alarm TEXT",
]

# tabele adăugate ulterior (executeScript de mai sus le creează pe DB-uri noi;
# pentru DB-uri vechi, CREATE TABLE IF NOT EXISTS e idempotent la fiecare boot)

_conn: aiosqlite.Connection = None


class MigrationError(RuntimeError):
    """O migrație a eșuat cu altceva decât „duplicate column" — boot-ul se refuză (G-16)."""


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
    # busy_timeout ÎNAINTE de migrații: `python3 -m app.admin` (care face și el db.connect())
    # sau un backup în curs țin un lock scurt; fără timeout, un ALTER TABLE pica instant cu
    # „database is locked" — iar cu fail-fast-ul de mai jos asta ar fi oprit boot-ul degeaba.
    await _conn.execute("PRAGMA busy_timeout=5000")
    await _conn.executescript(SCHEMA)
    for stmt in MIGRATIONS:
        try:
            await _conn.execute(stmt)
        except Exception as e:
            # migrațiile aditive re-rulate lovesc „duplicate column" — normal, îl ignorăm.
            # ORICE altă eroare (FS read-only, DB corupt, schema drift real) OPREȘTE boot-ul:
            # înainte era doar un WARNING și gateway-ul pornea cu o coloană lipsă → fiecare
            # cerere care o atingea dădea 500 „la întâmplare", fără niciun semnal clar la
            # pornire (audit gateway-logic G-16). Siguranța datelor bate disponibilitatea:
            # un boot refuzat cu mesaj explicit se repară în minute; o schemă parțială în
            # producție se descoperă din loguri de 500 după ore.
            if "duplicate column" in str(e).lower():
                continue
            log.error("MIGRATION FAILED — refusing to start with a partial schema.\n"
                      "  statement: %s\n  error: %s: %s\n"
                      "  Fix the cause (disk full / read-only data dir / corrupt DB → restore a "
                      "backup) and restart.", stmt, type(e).__name__, e)
            await _conn.close()
            _conn = None
            raise MigrationError("%s: %s (statement: %s)" % (type(e).__name__, e, stmt)) from e
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
    # istoric) → câștig mare de I/O pe HDD/SD. (busy_timeout e setat mai sus, înainte de migrații.)
    await _conn.execute("PRAGMA synchronous=NORMAL")
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
