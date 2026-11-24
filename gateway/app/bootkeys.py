"""Encryption at rest, wired into the real boot (3.8 PR4; docs/design/ENCRYPTION-AT-REST.md §12.9
"Wiring checklist", §12.10).

`prepare()` is the first thing `main.lifespan` does, before `config.ensure_dirs()`, the transcript
clean-up, the staged-restore apply, the vault and `db.connect()`:

    DATA_DIR itself (only it) is created → keys.boot(): process lock, inventory, key source,
    key check → [legacy + key: 3.7 staged restore applied, FK_legacy proven on the database,
    migration] → staged restore applied under the lock (legacy: the 3.7 code; protected: the
    WTS1 journal with the open keyring, then keys.wtk re-opened) → vault keys loaded.

Decision table (§12.9): a 3.7 volume with no key source boots exactly as before (legacy state,
nothing written but `.lock`); a configured source on a 3.7 volume migrates it; a protected volume
needs exactly its key; a new empty volume needs an external key or WEBTERM_KEY_IN_VOLUME=1.

The process lock (and the DATA_DIR fd) is kept in `_boot` for the life of the process, also when a
later boot step fails: only process exit releases it. `release()` exists for tests.

INV-14 (docs/design/INVARIANTS.md): a missing, wrong or divergent key refuses the boot before any
clean-up, restore or schema step; the state System health shows comes from here.
"""
import base64
import json
import logging
import os
import pathlib
import re
import sqlite3
import stat
import urllib.parse

from cryptography.fernet import Fernet, InvalidToken

from . import backup, config, keys, security

log = logging.getLogger("webterm")

DB_NAME = "webterm.db"
# Un token Fernet: versiunea 0x80 → base64 url-safe începe cu „gA”; minim ~100 de caractere.
_FERNET_RE = re.compile(r"^gA[A-Za-z0-9_-]{60,}={0,2}$")
_MAX_CANDIDATES = 256         # valori încercate cel mult (Fernet e ieftin; plafonul ține boot-ul scurt)
_PER_COLUMN = 32
_MAX_SETTINGS_ROWS = 5000

_boot = None                  # keys.BootResult: lock + fd DATA_DIR, ținute până la ieșirea procesului
_host_keys = None             # backup.HostKeys al procesului (keyring deschis + MK)

# Ce arată System health. `mode`: legacy | protected | reduced; `source`: file | env | volume |
# default-file | None.
STATE = {"mode": "", "source": None, "key_location": None, "warnings": (), "migrated": False,
         "restore_applied": False, "legacy_proof": ""}


# ── item 3: FK_legacy proven on the database ────────────────────────────────


def _db_uri(dir_fd) -> str:
    # prin fd-ul fixat al DATA_DIR (nu printr-o nouă rezolvare a căii): același director pe care
    # l-a inventariat lock-ul. immutable=1: SQLite nu creează -wal/-shm și nu ia lock-uri, deci
    # proba nu scrie nimic în volum (garanția „refuz = nimic schimbat”).
    base = "/proc/self/fd/%d" % dir_fd
    path = os.path.join(base if os.path.isdir(base) else str(config.DATA_DIR), DB_NAME)
    return "file:%s?mode=ro&immutable=1" % urllib.parse.quote(path, safe="/")


def _strings_in(value: str):
    """Valorile candidate dintr-un rând app_settings: tokenul însuși sau, pentru un JSON (CA-ul
    agenților: {"cert", "key"}), șirurile lui de pe primul nivel."""
    if not isinstance(value, str):
        return
    v = value.strip()
    if v.startswith("{") and len(v) < 65536:
        try:
            doc = json.loads(v)
        except ValueError:
            return
        if isinstance(doc, dict):
            for x in doc.values():
                if isinstance(x, str):
                    yield x
        return
    yield v


def _looks_encrypted(v: str) -> bool:
    # doar ce ARATĂ a valoare de seif (token Fernet, eventual cu prefixul unei chei 3.8): un
    # placeholder sau un șir gol nu poate nici dovedi, nici infirma cheia
    for p in (security.FK_PREFIX, security.FK_LEGACY_PREFIX):
        if v.startswith(p):
            return p == security.FK_PREFIX or bool(_FERNET_RE.match(v[len(p):]))
    return bool(_FERNET_RE.match(v))


def legacy_candidates(con) -> list:
    """Every encrypted value the 3.7 schema can hold, without knowing the schema version: each
    `*_encrypted` column of each table, plus the app_settings values that are a Fernet token or a
    JSON object holding one (SMTP password, cloud credentials, the agents' CA key)."""
    out = []
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for t in tables:
        qt = '"%s"' % t.replace('"', '""')
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % qt)]
        for c in cols:
            if not str(c).endswith("_encrypted"):
                continue
            qc = '"%s"' % str(c).replace('"', '""')
            for (v,) in con.execute("SELECT %s FROM %s WHERE %s IS NOT NULL AND %s != '' LIMIT %d"
                                    % (qc, qt, qc, qc, _PER_COLUMN)):
                if isinstance(v, str) and _looks_encrypted(v):
                    out.append(v)
    if "app_settings" in tables:
        for (v,) in con.execute("SELECT value FROM app_settings LIMIT %d" % _MAX_SETTINGS_ROWS):
            for x in _strings_in(v):
                if _looks_encrypted(x):
                    out.append(x)
    return out[:_MAX_CANDIDATES]


def prove_legacy_key(dir_fd, secret: bytes, kind: str = keys.KIND_INVALID_KEY) -> str:
    """§12.9 checklist item 3 + 9. Before `secret` becomes FK_legacy:
      - the database holds encrypted values → at least one must decrypt with `secret`
        ("proven"); none → refuse (`legacy-key-unproven`): a foreign 32-byte file never becomes
        FK_legacy;
      - a value that already carries the 3.8 FK prefix → refuse (a protected database next to
        a 3.7 key is a mixed set, never migrated);
      - no encrypted value at all (a fresh 3.7 install, or one that never stored a credential)
        → eligible ("no-ciphertext"): nothing exists that a wrong key could make unreadable;
      - but a non-empty `webterm.db-wal` while the checkpointed file shows nothing → refuse
        (`legacy-db-wal-pending`): the probe reads the file only (immutable, writes nothing), so
        values still in the WAL are not seen. Start once without the key (a clean stop
        checkpoints the WAL), then with it.
    Returns "proven" or "no-ciphertext"; refuses with BootRefused(kind)."""
    try:
        st = os.stat(DB_NAME, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return "no-ciphertext"
    except OSError as e:
        raise keys.BootRefused("legacy-db-unreadable", "%s: %s" % (DB_NAME, e.strerror), kind) from None
    if not stat.S_ISREG(st.st_mode):
        raise keys.BootRefused("legacy-db-not-regular", DB_NAME, kind)
    try:
        wal = os.stat(DB_NAME + "-wal", dir_fd=dir_fd, follow_symlinks=False).st_size > 0
    except FileNotFoundError:
        wal = False
    except OSError:
        wal = True                      # nu știm → tratat ca WAL nescris în fișier (mai strict)
    try:
        con = sqlite3.connect(_db_uri(dir_fd), uri=True, timeout=2)
        try:
            found = legacy_candidates(con)
        finally:
            con.close()
    except sqlite3.Error:
        raise keys.BootRefused("legacy-db-unreadable", DB_NAME, kind) from None
    if any(v.startswith(security.FK_PREFIX) for v in found):
        raise keys.BootRefused("legacy-db-has-protected-values", DB_NAME, kind)
    if not found:
        if wal:
            raise keys.BootRefused("legacy-db-wal-pending", DB_NAME + "-wal", kind)
        return "no-ciphertext"
    f = Fernet(base64.urlsafe_b64encode(secret))
    for v in found:
        if v.startswith(security.FK_LEGACY_PREFIX):
            v = v[len(security.FK_LEGACY_PREFIX):]
        try:
            f.decrypt(v.encode())
            return "proven"
        except (InvalidToken, ValueError, TypeError):
            continue
    raise keys.BootRefused("legacy-key-unproven", "%s does not decrypt the database's %d encrypted "
                           "value(s)" % (keys.LEGACY_SECRET, len(found)), kind)


# ── boot ────────────────────────────────────────────────────────────────────


def _host_keys_provider():
    return _host_keys


def prepare(env=None, data_dir=None):
    """The §12.9 boot order end to end (module docstring). Raises BootRefused (or the restore's
    own error) to stop the boot; nothing after it may run. Returns the keys.BootResult."""
    global _boot, _host_keys
    env = os.environ if env is None else env
    data_dir = pathlib.Path(data_dir if data_dir is not None else config.DATA_DIR)
    # item 1: înainte de lock se poate crea DOAR DATA_DIR însuși (nu părinții, nu transcripts/,
    # backups/…); tot restul vine după ce inventarul a decis ce fel de volum e.
    try:
        data_dir.mkdir(mode=0o755, exist_ok=True)
    except OSError as e:
        raise keys.BootRefused("data-dir-unavailable", e.strerror or "", keys.KIND_PREFLIGHT_IO) from None
    applied = {"restore": False, "proof": ""}

    def before_migrate(lock, inv):
        # item 2: un restore 3.7 pus în staging pe un volum 3.7 se aplică ÎNTÂI, cu cheia 3.7
        # (codul 3.7, acum sub lock-ul procesului), apoi se migrează în același boot: FK_legacy
        # e dovedit pe DB-ul restaurat, deci starea migrată nu se publică înaintea restore-ului.
        if inv.staged_restore:
            if inv.migrating:
                raise keys.BootRefused("staged-restore-during-migration", ".restore-flag")
            if backup.apply_pending_restore():
                applied["restore"] = True
                log.warning("restore applied at boot (3.7 backup) before the migration to a master key")
        kind = keys.KIND_INCOMPLETE if applied["restore"] else keys.KIND_INVALID_KEY
        applied["proof"] = prove_legacy_key(lock.dir_fd, keys.read_legacy_secret(lock), kind)

    res = keys.boot(str(data_dir), env, before_migrate=before_migrate)
    # de aici lock-ul rămâne al procesului, și la eroare (doar ieșirea îl eliberează)
    _boot = res
    if res.state.mode == "legacy":
        # exact 3.7: restore-ul din staging (dacă e) apoi cheia din data/secret
        if backup.apply_pending_restore():
            applied["restore"] = True
            log.warning("restore applied at boot from the uploaded backup")
            secret = keys.read_legacy_secret(res.lock)
        else:
            secret = res.legacy_key
        security.init_crypto(secret)
    else:
        # item 6: furnizorul de chei + starea protejată din inventarul luat SUB lock, înainte de
        # orice rută de backup; un keys.wtk dispărut nu mai poate fi citit drept „legacy”.
        _host_keys = backup.HostKeys(res.keyring, res.master_key)
        backup.set_boot_protected(True)
        backup.set_host_keys_provider(_host_keys_provider)
        if backup.apply_pending_restore(keys=_host_keys):
            applied["restore"] = True
            # epoch / installation id se pot schimba: keys.wtk se redeschide cu MK-ul procesului
            # înainte de seif și de db.connect
            inv = keys.classify(res.lock)
            ring, state = keys.open_protected(inv=inv, lock=res.lock, resolved=res.resolved)
            res.keyring = ring
            res.state = state
            _host_keys = backup.HostKeys(ring, res.master_key)
            log.warning("restore applied at boot from an encrypted backup; keys.wtk re-opened "
                        "(epoch %d)", ring.epoch)
        security.init_crypto_keyring(res.keyring.fk_legacy, res.keyring.fk)
    STATE.update(mode=res.state.mode, source=res.state.source, key_location=res.state.key_location,
                 warnings=tuple(res.state.warnings), migrated=bool(res.state.migrated),
                 restore_applied=applied["restore"], legacy_proof=applied["proof"])
    if res.state.mode == "legacy":
        log.info("encryption at rest: legacy (no master key configured; the vault key is data/secret)")
    else:
        log.warning("encryption at rest: %s (key source %s)%s", res.state.mode, res.state.source,
                    " — migrated from 3.7 on this boot" if res.state.migrated else "")
    return res


def describe_refusal(e: BaseException) -> str:
    """One log line for a refused boot: reason code, subject (a name, never a value), kind, and
    what to do. Never key material (BootRefused carries none)."""
    if isinstance(e, keys.BootRefused):
        hint = {
            "no-source": "new installations need a master key: mount a key file and set "
                         "WEBTERM_MASTER_KEY_FILE, or set WEBTERM_KEY_IN_VOLUME=1 (reduced protection)",
            "locked": "another WebTerm process (or an admin command) holds the data directory",
            "wrong-key": "the configured master key is not the one this data was protected with",
            "legacy-key-unproven": "data/secret does not decrypt this database: restore the right "
                                   "data/secret, or start without a master key",
            "legacy-db-wal-pending": "start once WITHOUT the master key and stop it cleanly, then "
                                     "start with the key",
        }.get(e.reason, "see docs/INSTALL.md → Encryption at rest")
        return "boot refused: %s (%s) [kind=%s] — %s" % (e.reason, e.subject or "-", e.kind, hint)
    return "boot refused: %s: %s" % (type(e).__name__, str(e)[:300])


def release() -> None:
    """Tests only: drop the lock and every registration, as if the process had exited."""
    global _boot, _host_keys
    if _boot is not None:
        _boot.lock.release()
    _boot = None
    _host_keys = None
    backup.set_host_keys_provider(None)
    backup.set_boot_protected(False)
    STATE.update(mode="", source=None, key_location=None, warnings=(), migrated=False,
                 restore_applied=False, legacy_proof="")
