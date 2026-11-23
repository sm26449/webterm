"""Key sources, boot contract, process lock and atomic key-manifest publication (3.8,
docs/design/ENCRYPTION-AT-REST.md §12.9, normative).

Not wired into the real boot yet: `config.load_secret`, `security.init_crypto` and
`main.lifespan` do not call this module in PR2 (see the wiring checklist in §12.9). Only
os / fcntl / stat / hashlib and `keyring.py`; no config, no DB, no logging of anything secret.

Entry points (all of them under a `ProcessLock`, whose directory fd is the only way they reach
`DATA_DIR`):

    acquire_lock(data_dir)                          → ProcessLock (flock on DATA_DIR/.lock)
    classify(lock)                                  → Inventory (empty / legacy / protected / ambiguous)
    resolve_master_key(env, lock, inv)              → ResolvedKey | None
    bootstrap(lock, resolved)                       → (Keyring, ProtectionState)        class empty
    migrate_legacy(lock, resolved)                  → (Keyring, ProtectionState)        class legacy
    open_protected(lock, inv, resolved)             → (Keyring, ProtectionState)        class protected
    rotate_master_key(lock, old_mk, new_mk)         → Keyring (external key only)
    publish_manifest(lock, blob, mk, previous_mk=)  → Keyring (atomic, verified read-back)
    boot(data_dir, env)                             → BootResult (the §12.9 order, end to end)
    expected_mk_id(data_dir), key_file_mk_id(path)  → hex MK ids for the operator (no key needed)

Every refusal is a `BootRefused` with a short `reason` code, a `subject` (a file or variable
NAME, never a value) and a `kind`:

    "invalid-key"           preflight refusal: nothing in DATA_DIR was written (only `.lock`)
    "operation-incomplete"  a publication started and failed before keys.wtk's rename; a tmp may
                            remain, the next boot (right key) recovers
    "commit-unknown"        keys.wtk's rename happened (this boot or an earlier one) and a later
                            step failed (dir fsync, read-back, legacy-secret removal); nothing is
                            undone, the next boot re-verifies

Crash injection: the `_crash_at` hook is called with a step name at each publication point;
tests raise from it to stop the sequence there. Steps:

    "<f>:before-tmp" "<f>:partial-tmp" "<f>:tmp-written" "<f>:renamed" "<f>:published"
        (f = "master.key", "migrating.wtm" or "keys.wtk")
    "migrate:verified" "secret:barrier" "secret:unlinked" "secret:removed"
    "marker:barrier" "marker:unlinked" "marker:removed"
"""
import base64
import binascii
import errno
import fcntl
import hashlib
import hmac
import os
import re
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field

from . import keyring as kr

DEFAULT_KEY_FILE = "/run/secrets/webterm_master_key"
ENV_KEY_FILE = "WEBTERM_MASTER_KEY_FILE"
ENV_KEY_VALUE = "WEBTERM_MASTER_KEY"
ENV_IN_VOLUME = "WEBTERM_KEY_IN_VOLUME"

LOCK_NAME = ".lock"
MANIFEST = "keys.wtk"
MANIFEST_TMP = "keys.wtk.tmp"
LEGACY_SECRET = "secret"
VOLUME_KEY = "master.key"
VOLUME_KEY_TMP = "master.key.tmp"
MIGRATION_MARKER = "migrating.wtm"
MIGRATION_MARKER_TMP = "migrating.wtm.tmp"
KEY_ARTEFACTS = (LEGACY_SECRET, MANIFEST, MANIFEST_TMP, VOLUME_KEY, VOLUME_KEY_TMP,
                 MIGRATION_MARKER, MIGRATION_MARKER_TMP)
STAGING = ("restore-pending", ".restore-flag", ".restore")
NEW_MARKERS = ("erasures.wtj", ".restore")
# Familia `.wt*` (numele noului format: keys.wtk, erasures.wtj, migrating.wtm, segmente …) e
# rezervată: un astfel de nume la rădăcina DATA_DIR fără keys.wtk interzice ramura legacy.
_WT_FAMILY = re.compile(r"\.wt[a-z0-9]*$")
# nume rezervate pentru segmentele de înregistrare (WTX1, descriptori, index) sub transcripts/
TRANSCRIPT_MARKER_EXT = (".wtx", ".wtd", ".idx")
# ce lasă în urmă un bootstrap întrerupt: nu schimbă clasa „empty”
BOOTSTRAP_LEFTOVERS = (MANIFEST_TMP, VOLUME_KEY_TMP, VOLUME_KEY)

KEY_FILE_MAX = 256
KEY_B64_LEN = 44

MARKER_MAGIC = b"WTM1"
MARKER_LEN = 4 + kr.ID_LEN + kr.ID_LEN + 32 + 32
_SECRET_DIGEST_LABEL = b"wt/v1/migrate-secret\x00"

KIND_INVALID_KEY = "invalid-key"
KIND_INCOMPLETE = "operation-incomplete"
KIND_COMMIT_UNKNOWN = "commit-unknown"

LOCATION_EXTERNAL = "external (not verified off-host)"

_RD = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class BootRefused(Exception):
    """The data directory cannot be opened. `reason` is a stable code, `subject` a name, `kind`
    one of the three KIND_* outcomes (module docstring)."""

    def __init__(self, reason, subject="", kind=KIND_INVALID_KEY):
        super().__init__(f"{reason} ({subject})" if subject else reason)
        self.reason = reason
        self.subject = subject
        self.kind = kind


class LockError(BootRefused):
    pass


class KeySourceError(BootRefused):
    pass


class WrongKey(BootRefused):
    pass


def _noop(_step):
    return None


@contextmanager
def _phase(kind, subject):
    """Tot ce eșuează aici primește `kind`: un OSError brut devine BootRefused("io-error"), un
    refuz „preflight” e reclasificat. Un kind deja mai precis (commit-unknown din interior) rămâne."""
    try:
        yield
    except BootRefused as e:
        if e.kind == KIND_INVALID_KEY:
            e.kind = kind
        raise
    except OSError as e:
        code = errno.errorcode.get(e.errno, "EIO") if e.errno else "EIO"
        raise BootRefused("io-error", f"{subject}: {code}", kind) from e


# ── lock ─────────────────────────────────────────────────────────────────────


class ProcessLock:
    """Holds DATA_DIR's fd and the flocked `.lock` fd. Released only by `release()` or by the
    process exiting; the gateway keeps it for its whole life."""

    def __init__(self, path, dir_fd, lock_fd):
        self.path = path
        self.dir_fd = dir_fd
        self.lock_fd = lock_fd

    def __repr__(self):
        return f"ProcessLock({self.path!r})"

    def release(self):
        for fd in (self.lock_fd, self.dir_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.lock_fd = self.dir_fd = None


def _trusted_owner_mode(st, what, subject):
    """DATA_DIR și .lock sunt domeniul de încredere: owner = noi sau root, fără scriere pentru
    grup/alții (altfel un al treilea poate înlocui numele .lock și flock nu mai exclude nimic)."""
    if st.st_uid not in (os.geteuid(), 0):
        raise LockError(f"{what}-bad-owner", subject)
    if st.st_mode & 0o022:
        raise LockError(f"{what}-bad-mode", subject)


def acquire_lock(data_dir):
    """Exclusive, non-blocking flock on DATA_DIR/.lock (created 0600 if absent, never written,
    never removed). DATA_DIR and .lock must be owned by us or root and not group/world-writable."""
    try:
        dfd = os.open(data_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as e:
        raise LockError("data-dir-unavailable", e.strerror or "") from None
    lfd = None
    try:
        _trusted_owner_mode(os.fstat(dfd), "data-dir", "DATA_DIR")
        try:
            lfd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                          0o600, dir_fd=dfd)
        except OSError as e:
            # ELOOP = .lock e un symlink; EISDIR = director. Nu „reparăm” nimic: refuzăm.
            raise LockError("lock-not-regular" if e.errno in (errno.ELOOP, errno.EISDIR) else
                            "lock-unavailable", LOCK_NAME) from None
        lst = os.fstat(lfd)
        if not stat.S_ISREG(lst.st_mode):
            raise LockError("lock-not-regular", LOCK_NAME)
        _trusted_owner_mode(lst, "lock", LOCK_NAME)
        try:
            fcntl.flock(lfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LockError("locked", "another process holds the data directory") from None
        return ProcessLock(os.fspath(data_dir), dfd, lfd)
    except BaseException:
        if lfd is not None:
            os.close(lfd)
        os.close(dfd)
        raise


# ── reading small files ──────────────────────────────────────────────────────


def _read_small(name, dir_fd, max_len, subject, err, private):
    """Open O_NOFOLLOW|O_NONBLOCK, fstat on the SAME fd, read at most max_len + 1 bytes."""
    try:
        fd = os.open(name, _RD, dir_fd=dir_fd)
    except FileNotFoundError:
        raise err("missing", subject) from None
    except OSError as e:
        raise err("symlink" if e.errno == errno.ELOOP else "unreadable", subject) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise err("not-regular", subject)
        if private:
            if st.st_uid not in (os.geteuid(), 0):
                raise err("bad-owner", subject)
            if st.st_mode & 0o077:
                raise err("bad-mode", subject)
        if st.st_size > max_len:
            raise err("too-large", subject)
        buf = bytearray()
        while len(buf) <= max_len:
            try:
                chunk = os.read(fd, max_len + 1 - len(buf))
            except OSError:
                raise err("unreadable", subject) from None
            if not chunk:
                break
            buf += chunk
        if len(buf) > max_len:
            raise err("too-large", subject)
        return bytes(buf)
    finally:
        os.close(fd)


def _read_manifest(lock):
    return _read_small(MANIFEST, lock.dir_fd, kr.MAN_MAX_LEN, MANIFEST, BootRefused, False)


def _read_secret(lock):
    data = _read_small(LEGACY_SECRET, lock.dir_fd, kr.KEY_LEN, LEGACY_SECRET, BootRefused, False)
    if len(data) != kr.KEY_LEN:
        raise BootRefused("bad-legacy-secret", LEGACY_SECRET)
    return data


# ── migration marker ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MigrationMarker:
    """`migrating.wtm`: the durable intent of a 3.7 → 3.8 migration. Digests only, no key."""
    installation_id: bytes
    mk_id: bytes
    secret_digest: bytes
    manifest_digest: bytes


def _secret_digest(secret):
    return hashlib.sha256(_SECRET_DIGEST_LABEL + bytes(secret)).digest()


def _marker_bytes(installation_id, mk_id, secret, blob):
    return (MARKER_MAGIC + installation_id + mk_id + _secret_digest(secret)
            + hashlib.sha256(bytes(blob)).digest())


def _read_marker(lock):
    data = _read_small(MIGRATION_MARKER, lock.dir_fd, MARKER_LEN, MIGRATION_MARKER, BootRefused, False)
    if len(data) != MARKER_LEN or data[:4] != MARKER_MAGIC:
        raise BootRefused("marker-invalid", MIGRATION_MARKER)
    p = 4
    inst = data[p:p + kr.ID_LEN]
    p += kr.ID_LEN
    mk_id = data[p:p + kr.ID_LEN]
    p += kr.ID_LEN
    return MigrationMarker(inst, mk_id, data[p:p + 32], data[p + 32:p + 64])


def _precommit_evidence(lock):
    """secret + migrating.wtm fără keys.wtk: reluabil DOAR dacă keys.wtk.tmp e exact manifestul
    anunțat de marker (rename-ul nu s-a făcut sau nu a devenit durabil). Altfel manifestul a fost
    publicat și s-a pierdut → ambiguous."""
    try:
        marker = _read_marker(lock)
        tmp = _read_small(MANIFEST_TMP, lock.dir_fd, kr.MAN_MAX_LEN, MANIFEST_TMP, BootRefused, False)
        secret = _read_secret(lock)
    except BootRefused:
        return False
    return (hmac.compare_digest(hashlib.sha256(tmp).digest(), marker.manifest_digest)
            and hmac.compare_digest(_secret_digest(secret), marker.secret_digest))


# ── inventory ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Inventory:
    kind: str                      # "empty" | "legacy" | "protected" | "ambiguous"
    in_volume: bool = False        # master.key present
    secret_leftover: bool = False  # protected + data/secret (last step of the 3.7 migration)
    staged_restore: bool = False
    leftovers: tuple = ()          # keys.wtk.tmp / master.key.tmp / migrating.wtm.tmp present
    reason: str = ""               # for ambiguous: the first offending entry
    migrating: bool = False        # migrating.wtm present (protected: resume; legacy: pre-commit)


def _lstat(lock, name):
    try:
        return os.stat(name, dir_fd=lock.dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _exists(lock, name):
    return _lstat(lock, name) is not None


def _open_subdir(name, dir_fd):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)


def _transcripts_untouched(lock):
    """`transcripts/` gol sau doar cu `arhiva/` goală: ce creează config.ensure_dirs înainte de
    boot. Orice altceva (sau o eroare la listare) e dată."""
    try:
        fd = _open_subdir("transcripts", lock.dir_fd)
    except OSError:
        return False
    try:
        names = os.listdir(fd)
        if not names:
            return True
        if names != ["arhiva"]:
            return False
        try:
            afd = _open_subdir("arhiva", fd)
        except OSError:
            return False
        try:
            return not os.listdir(afd)
        finally:
            os.close(afd)
    except OSError:
        return False
    finally:
        os.close(fd)


def _reserved_name(n):
    return n.endswith(TRANSCRIPT_MARKER_EXT) or bool(_WT_FAMILY.search(n))


def _transcripts_marker(lock):
    """Primul nume rezervat noului format sub transcripts/ (rădăcina + un nivel de subdirectoare,
    ca `arhiva/`), sau None. O listare eșuată nu dovedește absența → tratată ca marker."""
    try:
        fd = _open_subdir("transcripts", lock.dir_fd)
    except FileNotFoundError:
        return None
    except OSError:
        return "transcripts (unreadable)"
    try:
        for n in sorted(os.listdir(fd)):
            if _reserved_name(n):
                return f"transcripts/{n}"
            st = os.stat(n, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                sfd = _open_subdir(n, fd)
                try:
                    hit = next((m for m in sorted(os.listdir(sfd)) if _reserved_name(m)), None)
                finally:
                    os.close(sfd)
                if hit:
                    return f"transcripts/{n}/{hit}"
        return None
    except OSError:
        return "transcripts (unreadable)"
    finally:
        os.close(fd)


def _top_marker(names):
    for n in names:
        if n in NEW_MARKERS or (n not in KEY_ARTEFACTS and _WT_FAMILY.search(n)):
            return n
    return None


def classify(lock):
    """§12.9 Inventory: top level of DATA_DIR (+ reserved names under transcripts/), symlinks
    never followed. Read-only."""
    names = sorted(os.listdir(lock.dir_fd))
    st = {n: os.stat(n, dir_fd=lock.dir_fd, follow_symlinks=False) for n in names}

    for n in KEY_ARTEFACTS:
        if n in st and not stat.S_ISREG(st[n].st_mode):
            return Inventory("ambiguous", reason=f"{n} is not a regular file")
    if LEGACY_SECRET in st and st[LEGACY_SECRET].st_size != kr.KEY_LEN:
        return Inventory("ambiguous", reason=f"{LEGACY_SECRET} is not {kr.KEY_LEN} bytes")

    staged = any(n in st for n in STAGING)
    leftovers = tuple(n for n in (MANIFEST_TMP, VOLUME_KEY_TMP, MIGRATION_MARKER_TMP) if n in st)
    in_volume = VOLUME_KEY in st
    has_secret = LEGACY_SECRET in st
    has_marker = MIGRATION_MARKER in st

    if MANIFEST in st:
        if has_secret and not has_marker:
            # protocolul scrie migrating.wtm ÎNAINTEA manifestului și îl șterge DUPĂ secret:
            # secret + keys.wtk fără marker nu e o stare a migrării noastre.
            return Inventory("ambiguous", staged_restore=staged,
                             reason=f"{LEGACY_SECRET} next to {MANIFEST} without {MIGRATION_MARKER}")
        return Inventory("protected", in_volume=in_volume, secret_leftover=has_secret,
                         staged_restore=staged, leftovers=leftovers, migrating=has_marker)
    if has_marker:
        if has_secret and MANIFEST_TMP in st and _precommit_evidence(lock):
            return Inventory("legacy", in_volume=in_volume, staged_restore=staged, leftovers=leftovers,
                             migrating=True)
        return Inventory("ambiguous", staged_restore=staged,
                         reason=f"{MIGRATION_MARKER} without {MANIFEST}: migration published but {MANIFEST} missing")
    marker = _top_marker(names)
    if marker:
        return Inventory("ambiguous", staged_restore=staged, reason=f"{marker} without {MANIFEST}")
    if has_secret:
        tmarker = _transcripts_marker(lock)
        if tmarker:
            return Inventory("ambiguous", staged_restore=staged, reason=f"{tmarker} without {MANIFEST}")
        return Inventory("legacy", in_volume=in_volume, staged_restore=staged, leftovers=leftovers)

    def tolerated(n):
        mode = st[n].st_mode
        if n == LOCK_NAME:
            return stat.S_ISREG(mode)
        if n == "lost+found":
            return stat.S_ISDIR(mode)
        if n == "transcripts":
            return stat.S_ISDIR(mode) and _transcripts_untouched(lock)
        return n in BOOTSTRAP_LEFTOVERS

    other = [n for n in names if not tolerated(n)]
    if not other:
        return Inventory("empty", in_volume=in_volume, leftovers=leftovers)
    return Inventory("ambiguous", staged_restore=staged, reason=f"{other[0]} without a key")


# ── key encodings ────────────────────────────────────────────────────────────


def decode_key_text(raw, subject):
    """Canonical standard base64 of exactly 32 bytes; one trailing "\\n" tolerated."""
    if isinstance(raw, str):
        try:
            raw = raw.encode("ascii")
        except UnicodeEncodeError:
            raise KeySourceError("bad-encoding", subject) from None
    if not isinstance(raw, (bytes, bytearray)):
        raise KeySourceError("bad-encoding", subject)
    raw = bytes(raw)
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if len(raw) != KEY_B64_LEN:
        raise KeySourceError("bad-encoding", subject)
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise KeySourceError("bad-encoding", subject) from None
    # re-codificarea egală = canonic: fără biţi nefolosiţi în ultimul caracter, fără alt padding
    if len(key) != kr.KEY_LEN or base64.b64encode(key) != raw:
        raise KeySourceError("bad-encoding", subject)
    return key


def encode_key_text(key):
    """The canonical key-file content for a 32-byte MK (with the tolerated trailing newline)."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != kr.KEY_LEN:
        raise KeySourceError("bad-encoding", "key")
    return base64.b64encode(bytes(key)) + b"\n"


def read_key_file(path, dir_fd=None, subject=None):
    subject = subject or os.fspath(path)
    return decode_key_text(_read_small(path, dir_fd, KEY_FILE_MAX, subject, KeySourceError, True), subject)


# ── key sources ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ResolvedKey:
    source: str                              # "file" | "env" | "default-file" | "volume"
    mk: bytes = field(default=None, repr=False)  # None only for "volume" before bootstrap/migration
    path: str = ""


def _env_set(env, name):
    """strip() decide DOAR dacă variabila e setată; valoarea întoarsă e cea originală, validată
    apoi cu aceleași reguli stricte ca fișierul (un singur \\n final, nimic altceva)."""
    v = env.get(name)
    return v if isinstance(v, str) and v.strip() else ""


def _under(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def check_outside_data_dir(lock, path, subject):
    """A key FILE must not live in the data tree: by path (as given and resolved) and by
    (st_dev, st_ino) of every ancestor of the resolved path against DATA_DIR's own fd (catches a
    bind mount of DATA_DIR elsewhere). Hardlinks and copies cannot be seen from here: the real
    separation is the operator's mount configuration (§12.9 Key sources)."""
    msg = f"{subject} is inside the data directory; use {ENV_IN_VOLUME}=1 explicitly"
    try:
        dst = os.fstat(lock.dir_fd)
        root_abs = os.path.abspath(lock.path)
        root_real = os.path.realpath(lock.path)
        p_abs = os.path.abspath(path)
        p_real = os.path.realpath(path)
    except OSError:
        raise KeySourceError("unreadable", subject) from None
    if any(_under(p, r) for p in (p_abs, p_real) for r in (root_abs, root_real)):
        raise KeySourceError("key-in-data-dir", msg)
    cur = os.path.dirname(p_real)
    while True:
        try:
            st = os.stat(cur)
        except OSError:
            raise KeySourceError("unreadable", subject) from None
        if (st.st_dev, st.st_ino) == (dst.st_dev, dst.st_ino):
            raise KeySourceError("key-in-data-dir", msg)
        parent = os.path.dirname(cur)
        if parent == cur:
            return
        cur = parent


def _read_external_file(lock, path, subject):
    mk = read_key_file(path, subject=subject)
    check_outside_data_dir(lock, path, subject)
    return mk


def resolve_master_key(env, lock, inv, default_key_file=DEFAULT_KEY_FILE):
    """§12.9 Key sources. Returns None when no source is configured (allowed only for an empty
    or legacy volume; the caller decides). Never generates a key."""
    kfile = _env_set(env, ENV_KEY_FILE)
    kval = _env_set(env, ENV_KEY_VALUE)
    iv = env.get(ENV_IN_VOLUME)
    iv = iv.strip() if isinstance(iv, str) else ""
    if iv not in ("", "0", "1"):
        raise KeySourceError("bad-value", ENV_IN_VOLUME)
    in_vol = iv == "1"
    configured = [n for n, on in ((ENV_KEY_FILE, kfile), (ENV_KEY_VALUE, kval), (ENV_IN_VOLUME, in_vol)) if on]
    if len(configured) > 1:
        # Două surse = eroare de operare; a ghici care câştigă e exact cum se înlocuieşte o cheie pe tăcute.
        raise KeySourceError("conflict", " + ".join(configured))
    if inv.in_volume and not in_vol:
        raise KeySourceError("conflict", f"{VOLUME_KEY} present but {ENV_IN_VOLUME} is not 1")
    if kfile:
        return ResolvedKey("file", _read_external_file(lock, kfile, ENV_KEY_FILE), kfile)
    if kval:
        return ResolvedKey("env", decode_key_text(kval, ENV_KEY_VALUE))
    if in_vol:
        if inv.in_volume:
            return ResolvedKey("volume", read_key_file(VOLUME_KEY, lock.dir_fd, VOLUME_KEY), VOLUME_KEY)
        if inv.kind == "protected":
            # keys.wtk există: o cheie nouă nu se generează niciodată peste el.
            raise KeySourceError("missing", VOLUME_KEY)
        return ResolvedKey("volume", None, VOLUME_KEY)
    # Calea implicită e consultată numai când nicio sursă explicită nu e setată (fallback).
    if inv.kind == "protected":
        return ResolvedKey("default-file", _read_external_file(lock, default_key_file, default_key_file),
                           default_key_file)
    try:
        mk = _read_external_file(lock, default_key_file, default_key_file)
    except KeySourceError as e:
        if e.reason == "missing":  # doar ENOENT înseamnă „neconfigurat”
            return None
        raise
    return ResolvedKey("default-file", mk, default_key_file)


# ── state ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ProtectionState:
    mode: str                 # "legacy" | "protected" | "reduced"
    source: str = None        # ResolvedKey.source, or None in legacy
    staged_restore: bool = False
    migrated: bool = False    # this boot finished the 3.7 → 3.8 migration
    warnings: tuple = ()      # "key-in-environment", "key-in-volume", "legacy-key-in-volume"
    key_location: str = None  # LOCATION_EXTERNAL | "environment" | "in-volume" | None (legacy)


def _state(resolved, inv, migrated=False):
    if resolved.source == "volume":
        return ProtectionState("reduced", "volume", inv.staged_restore, migrated, ("key-in-volume",), "in-volume")
    if resolved.source == "env":
        return ProtectionState("protected", "env", inv.staged_restore, migrated, ("key-in-environment",),
                               "environment")
    return ProtectionState("protected", resolved.source, inv.staged_restore, migrated, (), LOCATION_EXTERNAL)


# ── atomic publication ───────────────────────────────────────────────────────


def _unlink_leftover(lock, name):
    try:
        os.unlink(name, dir_fd=lock.dir_fd)
    except FileNotFoundError:
        pass


def _write_all(fd, data, subject):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if not n:  # o scriere de zero octeţi nu e progres: abandonăm, tmp-ul rămâne de aruncat
            raise BootRefused("write-failed", subject)
        view = view[n:]


def _atomic_publish(lock, name, tmp, data, crash, commit_kind, before_rename=None):
    """§12.9 steps 2–5: drop a leftover tmp, O_EXCL|O_NOFOLLOW 0600, write, fsync, close,
    (before_rename), rename, fsync dir. Failures up to the rename → operation-incomplete; the dir
    fsync after it → `commit_kind` (commit-unknown for keys.wtk; never undone)."""
    dfd = lock.dir_fd
    with _phase(KIND_INCOMPLETE, tmp):
        _unlink_leftover(lock, tmp)
        crash(f"{name}:before-tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            os.fchmod(fd, 0o600)
            half = len(data) // 2
            _write_all(fd, data[:half], tmp)
            if half:
                crash(f"{name}:partial-tmp")
            _write_all(fd, data[half:], tmp)
            os.fsync(fd)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.close(fd)  # o eroare la close (EIO pe NFS…) contează: tmp-ul nu e sigur scris
        crash(f"{name}:tmp-written")
        if before_rename is not None:
            before_rename()
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    crash(f"{name}:renamed")
    with _phase(commit_kind, name):
        os.fsync(dfd)
    crash(f"{name}:published")


def _open_blob(blob, mk, profile):
    try:
        return kr.open_keyring_bytes(blob, mk, profile)
    except kr.WrongKeyError:
        raise WrongKey("wrong-key", MANIFEST) from None
    except kr.KeyringError as e:
        raise BootRefused("manifest-invalid", f"{MANIFEST}: {e.reason}") from None


def _open_ring(lock, mk, profile):
    return _open_blob(_read_manifest(lock), mk, profile)


def publish_manifest(lock, blob, mk, previous_mk=None, profile=kr.PROFILE_V1, _crash_at=None,
                     _before_rename=None):
    """Publish `blob` as keys.wtk atomically and return the keyring re-opened from disk.
    Without `previous_mk`, keys.wtk must not exist; with it, the current file must open with
    `previous_mk` and the new one must keep its installation id and raise its epoch."""
    crash = _crash_at or _noop
    try:
        new = kr.open_keyring_bytes(blob, mk, profile)  # nu publicăm niciodată ce nu se deschide
    except kr.KeyringError as e:
        raise BootRefused("manifest-invalid", f"new: {e.reason}") from None
    if previous_mk is None:
        if _exists(lock, MANIFEST):
            raise BootRefused("manifest-exists", MANIFEST)
    else:
        if not _exists(lock, MANIFEST):
            raise BootRefused("manifest-missing", MANIFEST)
        cur = _open_ring(lock, previous_mk, profile)
        if not hmac.compare_digest(cur.installation_id, new.installation_id):
            raise BootRefused("installation-mismatch", MANIFEST)
        if new.epoch <= cur.epoch:
            raise BootRefused("epoch-not-increasing", MANIFEST)
    _atomic_publish(lock, MANIFEST, MANIFEST_TMP, bytes(blob), crash, KIND_COMMIT_UNKNOWN, _before_rename)
    # după rename: nimic nu se anulează orbește; boot-ul următor re-verifică
    with _phase(KIND_COMMIT_UNKNOWN, MANIFEST):
        if not hmac.compare_digest(_read_manifest(lock), bytes(blob)):
            raise BootRefused("readback-mismatch", MANIFEST)
        return _open_ring(lock, mk, profile)


def _ensure_volume_key(lock, crash):
    """MK în volum (opt-out): refolosim un master.key rămas valid, altfel generăm şi publicăm
    atomic ÎNAINTEA manifestului (altfel un crash ar lăsa un keys.wtk fără cheia lui)."""
    if _exists(lock, VOLUME_KEY):
        return read_key_file(VOLUME_KEY, lock.dir_fd, VOLUME_KEY)
    mk = secrets.token_bytes(kr.KEY_LEN)
    # master.key e un sub-pas: manifestul nu e publicat încă → operation-incomplete
    _atomic_publish(lock, VOLUME_KEY, VOLUME_KEY_TMP, encode_key_text(mk), crash, KIND_INCOMPLETE)
    with _phase(KIND_INCOMPLETE, VOLUME_KEY):
        if not hmac.compare_digest(read_key_file(VOLUME_KEY, lock.dir_fd, VOLUME_KEY), mk):
            raise BootRefused("readback-mismatch", VOLUME_KEY)
    return mk


def _mk_for(lock, resolved, crash):
    if resolved is None:
        raise KeySourceError("no-source", "new installations need an external key or "
                             f"{ENV_IN_VOLUME}=1")
    if resolved.mk is not None:
        return resolved.mk
    if resolved.source != "volume":
        raise KeySourceError("missing", resolved.source)
    return _ensure_volume_key(lock, crash)


def _envelopes(mk, kwk, snk=None, fk_legacy=None, fk=None, dbk=None):
    envs = [kr.wrap_under_mk(mk, kr.KT_KWK, kwk)]
    if snk is not None:
        envs.append(kr.wrap_under_mk(mk, kr.KT_SNK, snk))
    for t, k in ((kr.KT_FK_LEGACY, fk_legacy), (kr.KT_FK, fk), (kr.KT_DBK, dbk)):
        if k is not None:
            envs.append(kr.wrap_under_kwk(kwk, t, k))
    return tuple(envs)


def _resolved_with(resolved, mk):
    return ResolvedKey(resolved.source, mk, resolved.path)


def bootstrap(lock, resolved, profile=kr.PROFILE_V1, _crash_at=None):
    """Class `empty`: new installation id, KWK, SNK, FK; keys.wtk epoch 1."""
    crash = _crash_at or _noop
    inv = classify(lock)
    if inv.kind != "empty":
        raise BootRefused("not-empty", inv.kind)
    mk = _mk_for(lock, resolved, crash)
    with _phase(KIND_INCOMPLETE, MANIFEST):
        rnd = secrets.token_bytes
        envs = _envelopes(mk, rnd(32), snk=rnd(32), fk=rnd(32))
        blob = kr.encode_manifest(kr.KeyManifest(rnd(kr.ID_LEN), 1, kr.key_id(mk), (), envs), mk, profile)
        ring = publish_manifest(lock, blob, mk, profile=profile, _crash_at=crash)
    return ring, _state(_resolved_with(resolved, mk), inv)


def _remove_marker(lock, crash):
    """Markerul dispare numai după ce absența lui `secret` e durabilă (fsync înainte de unlink)."""
    with _phase(KIND_COMMIT_UNKNOWN, MIGRATION_MARKER):
        os.fsync(lock.dir_fd)
        crash("marker:barrier")
        os.unlink(MIGRATION_MARKER, dir_fd=lock.dir_fd)
        crash("marker:unlinked")
        os.fsync(lock.dir_fd)
        crash("marker:removed")


def _remove_legacy_secret(lock, ring, marker, crash):
    """Ultimul pas al migrării: data/secret dispare DOAR dacă e exact FK_legacy din keys.wtk
    re-deschis de pe disc și cel anunțat de marker. Două chei legacy diferite = cineva a scris
    una dintre ele → refuz. H1: fsync pe director ÎNAINTE de unlink (manifestul văzut poate fi
    doar în cache după un crash între rename și fsync); la eșec `secret` rămâne."""
    secret = _read_secret(lock)
    if ring.fk_legacy is None or not hmac.compare_digest(ring.fk_legacy, secret):
        raise BootRefused("legacy-secret-mismatch", LEGACY_SECRET)
    if not hmac.compare_digest(_secret_digest(secret), marker.secret_digest):
        raise BootRefused("legacy-secret-mismatch", MIGRATION_MARKER)
    with _phase(KIND_COMMIT_UNKNOWN, LEGACY_SECRET):
        os.fsync(lock.dir_fd)
        crash("secret:barrier")
        os.unlink(LEGACY_SECRET, dir_fd=lock.dir_fd)
        crash("secret:unlinked")
        os.fsync(lock.dir_fd)
        crash("secret:removed")


def _check_marker(marker, ring, blob):
    if not (hmac.compare_digest(marker.installation_id, ring.installation_id)
            and hmac.compare_digest(marker.mk_id, ring.mk_id)
            and hmac.compare_digest(marker.manifest_digest, hashlib.sha256(blob).digest())):
        raise BootRefused("migration-marker-mismatch", MIGRATION_MARKER)


def migrate_legacy(lock, resolved, profile=kr.PROFILE_V1, _crash_at=None):
    """Class `legacy` + a source: data/secret becomes FK_legacy. Order: keys.wtk.tmp written →
    migrating.wtm published (intent) → keys.wtk renamed + fsync → read back and re-opened →
    secret removed (dir fsync before and after) → marker removed."""
    crash = _crash_at or _noop
    inv = classify(lock)
    if inv.kind != "legacy":
        raise BootRefused("not-legacy", inv.kind)
    if resolved is None:
        raise KeySourceError("no-source", "migration needs a master key")
    secret = _read_secret(lock)
    if inv.migrating:
        # pre-commit dovedit de classify: manifestul n-a devenit niciodată autoritate, deci
        # nimic nu a fost scris sub cheile lui. Cerem totuși aceeași MK ca la prima încercare.
        old = _read_marker(lock)
        if resolved.mk is None:
            # master.key a dispărut după marker: nu generăm o cheie nouă peste o migrare începută
            raise KeySourceError("missing", VOLUME_KEY)
        if not hmac.compare_digest(old.mk_id, kr.key_id(resolved.mk)):
            raise WrongKey("wrong-key", MIGRATION_MARKER)
    mk = _mk_for(lock, resolved, crash)
    with _phase(KIND_INCOMPLETE, MANIFEST):
        if inv.migrating:
            # markerul vechi pleacă ÎNAINTEA tmp-ului: altfel un crash ar lăsa marker fără dovadă
            _unlink_leftover(lock, MIGRATION_MARKER)
            os.fsync(lock.dir_fd)
        rnd = secrets.token_bytes
        inst = rnd(kr.ID_LEN)
        envs = _envelopes(mk, rnd(32), snk=rnd(32), fk_legacy=secret, fk=rnd(32))
        blob = kr.encode_manifest(kr.KeyManifest(inst, 1, kr.key_id(mk), (), envs), mk, profile)
        mbytes = _marker_bytes(inst, kr.key_id(mk), secret, blob)

        def intent():
            # fsync-ul de director al markerului face durabilă și intrarea keys.wtk.tmp
            _atomic_publish(lock, MIGRATION_MARKER, MIGRATION_MARKER_TMP, mbytes, crash, KIND_INCOMPLETE)

        ring = publish_manifest(lock, blob, mk, profile=profile, _crash_at=crash, _before_rename=intent)
        with _phase(KIND_COMMIT_UNKNOWN, MANIFEST):
            if ring.fk_legacy is None or not hmac.compare_digest(ring.fk_legacy, secret):
                raise BootRefused("legacy-secret-mismatch", MANIFEST)
            crash("migrate:verified")
            marker = _read_marker(lock)
            _check_marker(marker, ring, blob)
            _remove_legacy_secret(lock, ring, marker, crash)
            _remove_marker(lock, crash)
    return ring, _state(_resolved_with(resolved, mk), inv, migrated=True)


def open_protected(lock, inv, resolved, profile=kr.PROFILE_V1, _crash_at=None):
    """Class `protected`: exactly the current MK opens keys.wtk; never a fallback. With
    migrating.wtm, finishes the migration (secret, then marker), each removal behind a dir fsync."""
    crash = _crash_at or _noop
    if inv.kind != "protected":
        raise BootRefused("not-protected", inv.kind)
    if resolved is None or resolved.mk is None:
        raise KeySourceError("no-source", MANIFEST)
    blob = _read_manifest(lock)
    ring = _open_blob(blob, resolved.mk, profile)
    migrated = False
    if inv.migrating:
        marker = _read_marker(lock)
        _check_marker(marker, ring, blob)
        if inv.secret_leftover:
            _remove_legacy_secret(lock, ring, marker, crash)
        _remove_marker(lock, crash)
        migrated = True
    return ring, _state(resolved, inv, migrated)


def rotate_master_key(lock, old_mk, new_mk, profile=kr.PROFILE_V1, new_key_file=None, _crash_at=None):
    """One new keys.wtk (epoch + 1) with the stable keys re-wrapped under `new_mk`; the old MK
    id joins the retired list. External key only (in-volume would need two files to switch).
    With `new_key_file`, that file must already hold `new_mk` (read back with `read_key_file`,
    outside DATA_DIR) before anything is published (§12.9 MK rotation)."""
    inv = classify(lock)
    if inv.kind != "protected":
        raise BootRefused("not-protected", inv.kind)
    if inv.in_volume:
        raise BootRefused("unsupported", "rotation with the key in the volume")
    if inv.secret_leftover or inv.migrating:
        raise BootRefused("migration-unfinished", MIGRATION_MARKER if inv.migrating else LEGACY_SECRET)
    old_mk = _key32(old_mk, "old_mk")
    new_mk = _key32(new_mk, "new_mk")
    if hmac.compare_digest(old_mk, new_mk):
        raise BootRefused("same-key", "new_mk")
    if new_key_file is not None:
        persisted = _read_external_file(lock, new_key_file, "new_key_file")
        if not hmac.compare_digest(persisted, new_mk):
            raise BootRefused("new-key-not-persisted", "new_key_file")
    ring = _open_ring(lock, old_mk, profile)
    new_id = kr.key_id(new_mk)
    retired = sorted((set(ring.retired_mk_ids) | {ring.mk_id}) - {new_id})
    if len(retired) > kr.MAN_MAX_RETIRED:
        raise BootRefused("too-many-retired", MANIFEST)
    # KWP e determinist: plicurile de sub KWK ies identice octet cu octet; doar KWK/SNK se re-ambalează.
    envs = _envelopes(new_mk, ring.kwk, snk=ring.snk, fk_legacy=ring.fk_legacy, fk=ring.fk, dbk=ring.dbk)
    try:
        blob = kr.encode_manifest(kr.KeyManifest(ring.installation_id, ring.epoch + 1, new_id,
                                                 tuple(retired), envs), new_mk, profile)
    except kr.KeyringError as e:
        raise BootRefused("manifest-invalid", e.reason) from None
    return publish_manifest(lock, blob, new_mk, previous_mk=old_mk, profile=profile, _crash_at=_crash_at)


def _key32(k, name):
    if not isinstance(k, (bytes, bytearray)) or len(k) != kr.KEY_LEN:
        raise BootRefused("bad-key", name)
    return bytes(k)


# ── operator helpers ─────────────────────────────────────────────────────────


def expected_mk_id(data_dir):
    """The MK id (hex) keys.wtk was published for, read WITHOUT the key and without the process
    lock (the gateway may be running). Unauthenticated: it only tells the operator which key a
    volume asks for; the boot still authenticates the manifest with the key itself."""
    dfd = os.open(data_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        blob = _read_small(MANIFEST, dfd, kr.MAN_MAX_LEN, MANIFEST, BootRefused, False)
    finally:
        os.close(dfd)
    try:
        # parse structural, neautentificat: informativ, nu decide nimic
        return kr._parse_manifest_unauthenticated(blob).mk_id.hex()
    except kr.KeyringError as e:
        raise BootRefused("manifest-invalid", f"{MANIFEST}: {e.reason}") from None


def key_file_mk_id(path):
    """The MK id (hex) of a key file, for comparison with `expected_mk_id`; the key never leaves."""
    return kr.key_id(read_key_file(path)).hex()


# ── boot ─────────────────────────────────────────────────────────────────────


@dataclass
class BootResult:
    lock: ProcessLock
    state: ProtectionState
    keyring: kr.Keyring = field(default=None, repr=False)
    legacy_key: bytes = field(default=None, repr=False)  # only in the legacy state


def boot(data_dir, env, default_key_file=DEFAULT_KEY_FILE, profile=kr.PROFILE_V1, migrate=True,
         _crash_at=None):
    """§12.9 order: lock → inventory → key source → open / bootstrap / migrate. On a preflight
    refusal (kind invalid-key) nothing but `.lock` may have been created; the lock is released on
    every refusal."""
    lock = acquire_lock(data_dir)
    try:
        inv = classify(lock)
        if inv.kind == "ambiguous":
            raise BootRefused("ambiguous", inv.reason)
        resolved = resolve_master_key(env, lock, inv, default_key_file)
        if inv.kind == "empty":
            ring, state = bootstrap(lock, resolved, profile, _crash_at)
            return BootResult(lock, state, ring)
        if inv.kind == "legacy":
            if resolved is None or not migrate:
                if inv.migrating:
                    # o migrare a început: niciodată înapoi în legacy fără operator
                    raise BootRefused("migration-unfinished", MIGRATION_MARKER)
                return BootResult(lock, ProtectionState("legacy", None, inv.staged_restore, False,
                                                        ("legacy-key-in-volume",)),
                                  legacy_key=_read_secret(lock))
            ring, state = migrate_legacy(lock, resolved, profile, _crash_at)
            return BootResult(lock, state, ring)
        ring, state = open_protected(lock, inv, resolved, profile, _crash_at)
        return BootResult(lock, state, ring)
    except BaseException:
        lock.release()
        raise
