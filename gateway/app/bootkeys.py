"""Encryption at rest, wired into the real boot (3.8 PR4; docs/design/ENCRYPTION-AT-REST.md §12.9
"Wiring checklist", §12.10).

`prepare()` is the first thing `main.lifespan` does, before `config.ensure_dirs()`, the transcript
clean-up, the staged-restore apply, the vault and `db.connect()`:

    DATA_DIR itself (only it) is created → keys.boot(): process lock, inventory, key source,
    key check → [legacy + key: 3.7 staged restore applied, FK_legacy proven on the database,
    migration] → staged restore applied under the lock (legacy: the 3.7 code; protected: the
    WTS1 journal with the open keyring, then keys.wtk re-opened) → vault keys loaded.

Decision table (§12.9): a 3.7 volume with no key source boots exactly as before (legacy state;
the preflight writes nothing but `.lock` and `.maint.lock`, the rest of the boot is 3.7's own
writes); a configured source on a 3.7 volume migrates it; a protected volume needs exactly its
key; a new empty volume needs an external key or WEBTERM_KEY_IN_VOLUME=1.

M2: once the boot began to change the volume (a 3.7 restore applied by the hook, a publication),
the lock is never released on an error path: keys.boot keeps it for the life of the process.
M3: `.maint.lock` is held exclusively across the preflight, the restore and the migration (and,
from main.lifespan, the schema step); admin DB-only commands take it shared.

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
STAGED_DIR = "restore-pending"
STAGED_FLAG = ".restore-flag"
# Un token Fernet: versiunea 0x80 → base64 url-safe începe cu „gA”; minim ~100 de caractere.
_FERNET_RE = re.compile(r"^gA[A-Za-z0-9_-]{60,}={0,2}$")
# H4: INVENTARUL e complet (fiecare rând al fiecărei coloane `*_encrypted` şi al app_settings,
# citit în flux, fără LIMIT înaintea clasificării); doar DECRIPTAREA are buget. Plafonul
# inventarului e un refuz explicit, niciodată „no-ciphertext”.
_DECRYPT_BUDGET = 256         # valori încercate cel mult (regula „măcar una se decriptează”)
_FIRST_PER_SOURCE = 4         # primele valori ale fiecărei surse intră în buget înaintea restului
_MAX_VAULT_VALUES = 500_000   # valori de seif clasificate; peste → refuz legacy-db-inventory-too-large
_JSON_DEPTH = 16
# Timpul cât boot-ul aşteaptă o comandă admin doar-DB (lacăt partajat) înainte de refuz (M3).
MAINT_WAIT = 30.0

_boot = None                  # keys.BootResult: lock + fd DATA_DIR, ţinute până la ieşirea procesului
_host_keys = None             # backup.HostKeys al procesului (keyring deschis + MK)

# Ce arată System health. `mode`: legacy | protected | reduced; `source`: file | env | volume |
# default-file | None.
STATE = {"mode": "", "source": None, "key_location": None, "warnings": (), "migrated": False,
         "restore_applied": False, "legacy_proof": ""}


# ── item 3: FK_legacy proven on the database ────────────────────────────────


def _db_uri(dir_fd, base_path=None) -> str:
    # prin fd-ul fixat al directorului (nu printr-o nouă rezolvare a căii): acelaşi director pe
    # care l-a inventariat lock-ul. immutable=1: SQLite nu creează -wal/-shm şi nu ia lock-uri,
    # deci proba nu scrie nimic în volum (garanţia „refuz = nimic schimbat”). Fiindcă immutable
    # ignoră WAL-ul, un WAL nevid e refuzat ÎNAINTE de citire (H4).
    base = "/proc/self/fd/%d" % dir_fd
    path = os.path.join(base if os.path.isdir(base) else str(base_path or config.DATA_DIR), DB_NAME)
    return "file:%s?mode=ro&immutable=1" % urllib.parse.quote(path, safe="/")


class _Unclassifiable(Exception):
    def __init__(self, reason, where):
        super().__init__(where)
        self.reason = reason
        self.where = where


class VaultInventory:
    """H4: what the 3.7 schema can hold encrypted, classified exhaustively. `count` = every
    vault-shaped value seen; `candidates` = the decryption budget (first values of each source
    first, then the rest in order). A `FK:` value anywhere, an unclassifiable value or an
    inventory over the cap raise _Unclassifiable while scanning."""

    def __init__(self):
        self.count = 0
        self.candidates = []
        self._rest = []
        self._per_source = {}

    def add(self, v, where):
        self.count += 1
        if self.count > _MAX_VAULT_VALUES:
            raise _Unclassifiable("legacy-db-inventory-too-large", "more than %d encrypted values"
                                  % _MAX_VAULT_VALUES)
        n = self._per_source.get(where, 0)
        self._per_source[where] = n + 1
        if n < _FIRST_PER_SOURCE:
            if len(self.candidates) < _DECRYPT_BUDGET:
                self.candidates.append(v)
        elif len(self.candidates) + len(self._rest) < _DECRYPT_BUDGET:
            self._rest.append(v)

    def budget(self):
        return (self.candidates + self._rest)[:_DECRYPT_BUDGET]


def _vault_value(v: str):
    """Classify one string: "fk" (3.8 FK: prefix), "candidate" (a Fernet token, optionally with
    the FKL: prefix), "bad" (vault-shaped but not a token: a broken FKL: value or a damaged
    token), or None (not a vault value: a placeholder, plain text)."""
    if v.startswith(security.FK_PREFIX):
        return "fk"
    if v.startswith(security.FK_LEGACY_PREFIX):
        return "candidate" if _FERNET_RE.match(v[len(security.FK_LEGACY_PREFIX):]) else "bad"
    if _FERNET_RE.match(v):
        return "candidate"
    return None


def _classify_column(inv, v, where):
    if v is None or v == "":
        return
    if not isinstance(v, str):
        # 3.7 scrie doar text în coloanele *_encrypted: un BLOB/număr nu se poate clasifica
        raise _Unclassifiable("legacy-db-unclassifiable", where)
    kind = _vault_value(v)
    if kind == "fk":
        raise _Unclassifiable("legacy-db-has-protected-values", where)
    if kind == "candidate":
        inv.add(v, where)
    elif kind == "bad" or v.startswith("gA"):
        # „arată” a token (prefixul versiunii Fernet) dar nu e unul întreg: nu ştim ce e → refuz
        raise _Unclassifiable("legacy-db-unclassifiable", where)
    # altfel: placeholder / text fără formă de seif — nu dovedeşte şi nu infirmă cheia


def _walk_json(inv, doc, where, depth=0):
    if depth > _JSON_DEPTH:
        raise _Unclassifiable("legacy-db-unclassifiable", where)
    if isinstance(doc, dict):
        items = doc.values()
    elif isinstance(doc, list):
        items = doc
    else:
        items = (doc,)
    for x in items:
        if isinstance(x, (dict, list)):
            _walk_json(inv, x, where, depth + 1)
        elif isinstance(x, str):
            _classify_setting_str(inv, x, where)


def _classify_setting_str(inv, v, where):
    kind = _vault_value(v.strip())
    if kind == "fk":
        raise _Unclassifiable("legacy-db-has-protected-values", where)
    if kind == "bad":
        raise _Unclassifiable("legacy-db-unclassifiable", where)
    if kind == "candidate":
        inv.add(v.strip(), where)


def _classify_setting(inv, key, value):
    where = "app_settings[%s]" % str(key)[:64]
    if value is None or value == "":
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        if b"gA" in b or security.FK_PREFIX.encode() in b:
            raise _Unclassifiable("legacy-db-unclassifiable", where)
        return
    if not isinstance(value, str):
        return                                  # număr: nu e valoare de seif
    v = value.strip()
    if v[:1] in ("{", "["):
        try:
            doc = json.loads(v)
        except ValueError:
            doc = None
        if doc is None and v not in ("null",):
            # nu se parsează, dar poate ascunde un token / un FK: → nu-l putem clasifica
            if "gA" in v or security.FK_PREFIX in v:
                raise _Unclassifiable("legacy-db-unclassifiable", where)
            return
        _walk_json(inv, doc, where)
        return
    _classify_setting_str(inv, v, where)


def legacy_inventory(con) -> VaultInventory:
    """H4: every encrypted value the 3.7 schema can hold, without knowing the schema version:
    each `*_encrypted` column of each table (every non-empty row, streamed) and every
    app_settings value that is, or holds as JSON at any depth, a Fernet token (SMTP password,
    cloud credentials, the agents' CA key). Raises _Unclassifiable (see VaultInventory)."""
    inv = VaultInventory()
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for t in tables:
        qt = '"%s"' % t.replace('"', '""')
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % qt)]
        for c in cols:
            if not str(c).endswith("_encrypted"):
                continue
            qc = '"%s"' % str(c).replace('"', '""')
            where = "%s.%s" % (t, c)
            # fără LIMIT: cursorul curge rând cu rând, clasificarea vede tot
            for (v,) in con.execute("SELECT %s FROM %s WHERE %s IS NOT NULL" % (qc, qt, qc)):
                _classify_column(inv, v, where)
    if "app_settings" in tables:
        for k, v in con.execute("SELECT key, value FROM app_settings"):
            _classify_setting(inv, k, v)
    return inv


def legacy_candidates(con) -> list:
    """The decryption budget of legacy_inventory (kept for callers and tests)."""
    return legacy_inventory(con).budget()


def _side_file_pending(dir_fd, name) -> bool:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_size > 0
    except FileNotFoundError:
        return False
    except OSError:
        return True                     # nu ştim → tratat ca nescris în fişier (mai strict)


def prove_legacy_key(dir_fd, secret: bytes, kind: str = keys.KIND_INVALID_KEY, base_path=None) -> str:
    """§12.9 checklist item 3 + 9, H4. Before `secret` becomes FK_legacy:
      - a non-empty `webterm.db-wal` (or a hot `-journal`) → refuse (`legacy-db-wal-pending`)
        BEFORE any read: the probe reads the file only (immutable, writes nothing), so values
        still in the WAL would be invisible. Stop the 3.7 gateway cleanly first (a clean stop
        checkpoints the WAL), or start once without the key and stop it;
      - the complete inventory (legacy_inventory): a value with the 3.8 FK prefix → refuse
        (`legacy-db-has-protected-values`, a mixed set is never migrated); an unclassifiable
        value → `legacy-db-unclassifiable`; over the cap → `legacy-db-inventory-too-large`;
      - encrypted values present → at least one of the decryption budget must decrypt with
        `secret` ("proven"); none → refuse (`legacy-key-unproven`): a foreign 32-byte file
        never becomes FK_legacy;
      - no encrypted value at all → eligible ("no-ciphertext").
    Returns "proven" or "no-ciphertext"; refuses with BootRefused(kind)."""
    try:
        st = os.stat(DB_NAME, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        if _side_file_pending(dir_fd, DB_NAME + "-wal"):
            raise keys.BootRefused("legacy-db-wal-pending", DB_NAME + "-wal", kind) from None
        return "no-ciphertext"
    except OSError as e:
        raise keys.BootRefused("legacy-db-unreadable", "%s: %s" % (DB_NAME, e.strerror), kind) from None
    if not stat.S_ISREG(st.st_mode):
        raise keys.BootRefused("legacy-db-not-regular", DB_NAME, kind)
    for side in ("-wal", "-journal"):
        if _side_file_pending(dir_fd, DB_NAME + side):
            raise keys.BootRefused("legacy-db-wal-pending", DB_NAME + side, kind)
    try:
        con = sqlite3.connect(_db_uri(dir_fd, base_path), uri=True, timeout=2)
        try:
            inv = legacy_inventory(con)
        finally:
            con.close()
    except _Unclassifiable as e:
        raise keys.BootRefused(e.reason, e.where, kind) from None
    except sqlite3.Error:
        raise keys.BootRefused("legacy-db-unreadable", DB_NAME, kind) from None
    if not inv.count:
        return "no-ciphertext"
    f = Fernet(base64.urlsafe_b64encode(secret))
    tried = inv.budget()
    for v in tried:
        if v.startswith(security.FK_LEGACY_PREFIX):
            v = v[len(security.FK_LEGACY_PREFIX):]
        try:
            f.decrypt(v.encode())
            return "proven"
        except (InvalidToken, ValueError, TypeError):
            continue
    raise keys.BootRefused("legacy-key-unproven", "%s does not decrypt any of %d (of %d) encrypted "
                           "value(s)" % (keys.LEGACY_SECRET, len(tried), inv.count), kind)


# ── M2: a 3.7 staged restore before a migration ─────────────────────────────


def check_legacy_staging(lock) -> None:
    """M2: before a migration applies a 3.7 staged restore, the staged set must be complete
    (`.restore-flag` + `restore-pending/` with `webterm.db` and a 32-byte `secret`, all plain)
    and self-consistent: the staged secret proves the staged DB (prove_legacy_key on the staged
    directory). Refuses BEFORE any live mutation (kind invalid-key): 3.7 would silently skip an
    incomplete staging and boot the old data, but a migration must not publish keys for a set
    it has not checked."""
    dfd = lock.dir_fd
    try:
        fst = os.stat(STAGED_FLAG, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(fst.st_mode):
            raise keys.BootRefused("staged-restore-incomplete", STAGED_FLAG)
    except FileNotFoundError:
        raise keys.BootRefused("staged-restore-incomplete", STAGED_FLAG) from None
    try:
        sfd = os.open(STAGED_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    except OSError:
        raise keys.BootRefused("staged-restore-incomplete", STAGED_DIR) from None
    try:
        try:
            dst = os.stat(DB_NAME, dir_fd=sfd, follow_symlinks=False)
        except FileNotFoundError:
            raise keys.BootRefused("staged-restore-incomplete", STAGED_DIR + "/" + DB_NAME) from None
        if not stat.S_ISREG(dst.st_mode):
            raise keys.BootRefused("staged-restore-incomplete", STAGED_DIR + "/" + DB_NAME)
        try:
            staged_secret = keys._read_small(keys.LEGACY_SECRET, sfd, 32, STAGED_DIR + "/secret",
                                             keys.BootRefused, False)
        except keys.BootRefused:
            raise keys.BootRefused("staged-restore-incomplete", STAGED_DIR + "/secret") from None
        if len(staged_secret) != 32:
            raise keys.BootRefused("staged-restore-incomplete", STAGED_DIR + "/secret")
        try:
            prove_legacy_key(sfd, staged_secret, keys.KIND_INVALID_KEY,
                             base_path=pathlib.Path(lock.path) / STAGED_DIR)
        except keys.BootRefused as e:
            raise keys.BootRefused("staged-restore-invalid", "%s: %s/%s" % (e.reason, STAGED_DIR, DB_NAME)) from None
    finally:
        os.close(sfd)


# ── boot ────────────────────────────────────────────────────────────────────


def _host_keys_provider():
    return _host_keys


def prepare(env=None, data_dir=None, hold_maintenance=False):
    """The §12.9 boot order end to end (module docstring). Raises BootRefused (or the restore's
    own error) to stop the boot; nothing after it may run. Returns the keys.BootResult.

    M3: the exclusive DATA_DIR/.maint.lock is held from right after `.lock` to the end of the
    restore apply, so an admin DB-only command (shared lock) never runs during them. With
    `hold_maintenance` the caller keeps it (main.lifespan: until db.connect() has finished the
    schema) and drops it with end_maintenance(); otherwise it is dropped on return."""
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
            # M2: setul din staging e complet şi coerent (secretul lui dovedeşte DB-ul lui)
            # ÎNAINTE de orice mutaţie; altfel refuz, nimic schimbat
            check_legacy_staging(lock)
            # de aici volumul se schimbă: keys.boot ţine lock-ul la orice eroare (M2)
            lock.mutated = True
            if not backup.apply_pending_restore():
                raise keys.BootRefused("staged-restore-not-applied", STAGED_FLAG, keys.KIND_INCOMPLETE)
            applied["restore"] = True
            log.warning("restore applied at boot (3.7 backup) before the migration to a master key")
        # H4: proba pe DB-ul live (şi după un restore: cel restaurat); refuzul fără restore nu a
        # scris nimic (invalid-key), după restore e operation-incomplete
        kind = keys.KIND_INCOMPLETE if applied["restore"] else keys.KIND_INVALID_KEY
        applied["proof"] = prove_legacy_key(lock.dir_fd, keys.read_legacy_secret(lock), kind)

    res = keys.boot(str(data_dir), env, before_migrate=before_migrate, maint_wait=MAINT_WAIT)
    # de aici lock-ul rămâne al procesului, și la eroare (doar ieșirea îl eliberează); la fel
    # .maint.lock până la sfârşitul fazelor care schimbă volumul
    _boot = res
    for w in res.state.warnings:
        if w == "transcripts-symlink":
            log.warning("legacy volume: transcripts/ is a symlink to another directory (supported "
                        "3.7 layout); it was checked through the link. Migrating to a master key "
                        "needs transcripts/ as a plain directory first")
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
    if not hold_maintenance:
        res.lock.end_maintenance()
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
            "legacy-db-wal-pending": "stop the 3.7 gateway cleanly first (a clean stop checkpoints "
                                     "the WAL), or start once WITHOUT the master key and stop it "
                                     "cleanly, then start with the key",
            "legacy-db-has-protected-values": "the database already holds values of a protected "
                                              "installation next to a 3.7 data/secret (a mixed set): "
                                              "restore a consistent backup",
            "legacy-db-unclassifiable": "a value in the named column looks encrypted but is not a "
                                        "valid token: inspect it before migrating",
            "legacy-db-inventory-too-large": "too many encrypted values to check at boot: start "
                                             "without a master key and contact support",
            "transcripts-symlink": "transcripts/ is a symlink (supported 3.7 layout): it boots "
                                   "without a master key; to migrate, make it a plain directory",
            "staged-restore-incomplete": "a 3.7 restore is staged but incomplete: remove "
                                         ".restore-flag and restore-pending/ or stage it again",
            "staged-restore-invalid": "the staged 3.7 backup's data/secret does not open its own "
                                      "database: stage a complete backup",
            "maintenance-busy": "an admin command holds the database: let it finish, then start",
        }.get(e.reason, "see docs/INSTALL.md → Encryption at rest")
        return "boot refused: %s (%s) [kind=%s] — %s" % (e.reason, e.subject or "-", e.kind, hint)
    return "boot refused: %s: %s" % (type(e).__name__, str(e)[:300])


def end_maintenance() -> None:
    """main.lifespan, after db.connect(): the boot's mutating phases (keys, restore, schema) are
    over; admin DB-only commands may run again. `.lock` stays with the process."""
    if _boot is not None:
        _boot.lock.end_maintenance()


def release() -> None:
    """Tests only: drop the lock and every registration, as if the process had exited."""
    global _boot, _host_keys
    keys.release_retained()
    if _boot is not None:
        _boot.lock.release()
    _boot = None
    _host_keys = None
    backup.set_host_keys_provider(None)
    backup.set_boot_protected(False)
    STATE.update(mode="", source=None, key_location=None, warnings=(), migrated=False,
                 restore_applied=False, legacy_proof="")
