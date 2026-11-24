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
import logging
import os
import pathlib
import stat

from . import backup, config, keys, security
# R-H2: inventarul seifului 3.7 şi proba FK_legacy stau în legacyvault (le folosesc şi restore-urile)
from .legacyvault import (DB_NAME, VaultInventory, legacy_candidates, legacy_inventory,  # noqa: F401
                          prove_legacy_key)

log = logging.getLogger("webterm")

STAGED_DIR = "restore-pending"
STAGED_FLAG = ".restore-flag"
# Timpul cât boot-ul aşteaptă o comandă admin doar-DB (lacăt partajat) înainte de refuz (M3).
MAINT_WAIT = 30.0

_boot = None                  # keys.BootResult: lock + fd DATA_DIR, ţinute până la ieşirea procesului
_host_keys = None             # backup.HostKeys al procesului (keyring deschis + MK)

# Ce arată System health. `mode`: legacy | protected | reduced; `source`: file | env | volume |
# default-file | None.
STATE = {"mode": "", "source": None, "key_location": None, "warnings": (), "migrated": False,
         "restore_applied": False, "legacy_proof": ""}


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
