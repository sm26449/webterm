"""Backup / restore din aplicație (Settings).

Un backup = snapshot CRASH-CONSISTENT al DB-ului (VACUUM INTO, nu copie de fișier viu) +
cheia seifului (`data/secret`, care decriptează TOATE credențialele SSH) + cheia de semnare
a flotei (`data/agent-signing.key/.pub`, ca agenții să rămână actualizabili după restore) +
opțional transcripturile, împachetat tar.gz.

Securitate: fiindcă backup-ul conține cheia seifului, orice DESCĂRCARE e criptată cu o
PAROLĂ dată de utilizator (scrypt → AES-GCM). Un fișier scurs fără parolă e inutil.
Backup-urile PROGRAMATE stau pe server necriptate — serverul are oricum cheia în clar la
`data/secret`, deci nu adaugă expunere; la descărcare se criptează cu parola userului.

Restore: nu se poate rescrie un DB deschis pe loc → punem fișierele într-o zonă de staging
+ un marker, apoi procesul iese, iar containerul (restart: unless-stopped) repornește;
la boot, `apply_pending_restore()` face swap-ul ÎNAINTE de `db.connect()`.

3.8 (docs/design/ENCRYPTION-AT-REST.md §12.10): pe un volum PROTEJAT (`keys.wtk` există) totul de
mai sus e înlocuit de containerul WTS1 (`snapshot.py`): snapshoturi locale `.wts` sub SNK,
descărcări/upload-uri WTBK1(WTS1 portabil), niciodată `secret` sau MK; restore verificat complet
înainte de staging. Volumele legacy rămân EXACT pe codul 3.7 (atenţie: `.wtsnap` / `.keep`
conţin cheia seifului în clar — articol de retenţie din wiring checklist).
Recenzia PR3: rutarea nu deduce „legacy” din lipsa keys.wtk când există urme ale formatului nou
(volume_kind, H2); setul de restore e publicat durabil, cu manifest şi flag-jurnal (H1);
inventarul transcripturilor e o listă de permisiuni parcursă prin fd-uri (H3); un singur
extractor tar strict pentru WTS1 şi importul 3.7 (M1/M3); writer-ul aplică bugetele cititorului
şi îşi verifică produsul (M2); un container cere un singur MK, cel din header (M4).
"""
import contextlib
import contextvars
import errno
import fcntl
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import config
from . import erasure
from . import keyring as kr
from . import keys as keystore
from . import legacyvault
from . import snapshot as wts
from . import txstore
from . import wtbk

log = logging.getLogger("webterm")

_MAGIC = b"WTBK1"
_SALT = 16
_NONCE = 12
_SCRYPT_N = 2 ** 15         # ~30ms derivare; anti brute-force pe fișierul descărcat
RETENTION_DAYS = 7
# Sufixul fişierului temporar al unui snapshot în curs de scriere. Stă în ACELAŞI director ca
# ţinta (os.replace e atomic doar pe acelaşi filesystem) şi nu se potriveşte cu `*.wtsnap`, deci
# list_backups / encrypt_stored / prune nu-l văd niciodată ca arhivă validă (audit G-15).
TMP_SUFFIX = ".tmp"
STALE_TMP_SECS = 3600          # un .tmp mai vechi de atât e rest de la un crash → îl curăţăm

# Perioadele programării (secunde). „Scadent" se calculează faţă de ultimul backup REUŞIT,
# nu faţă de boot — altfel un gateway care reporneşte mai des decât tick-ul nu face niciodată
# backup (audit G-13).
SCHEDULE_PERIODS = {"daily": 86400, "weekly": 7 * 86400}
CLOCK_SKEW_SECS = 60           # last > now + atât = ceasul a sărit înapoi → tratăm ca scadent


def next_due(schedule: str, last_ok: float, now: float | None = None):
    """Momentul următorului backup programat, sau None dacă programarea e oprită.
    `last_ok` = ts-ul ultimului backup REUŞIT (0 = niciodată → scadent acum)."""
    period = SCHEDULE_PERIODS.get(schedule)
    if not period:
        return None
    now = time.time() if now is None else now
    if last_ok <= 0 or last_ok > now + CLOCK_SKEW_SECS:
        return now
    return last_ok + period


def is_due(schedule: str, last_ok: float, now: float | None = None) -> bool:
    """Catch-up: dacă ultimul backup reuşit e mai vechi decât perioada (sau n-a existat), e
    scadent ACUM — indiferent de câte reporniri au fost între timp."""
    nd = next_due(schedule, last_ok, now)
    if nd is None:
        return False
    now = time.time() if now is None else now
    return nd <= now


def _secret_path():
    return config.DATA_DIR / "secret"


def _backup_dir():
    d = config.DATA_DIR / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _restore_dir():
    return config.DATA_DIR / "restore-pending"


def _restore_flag():
    return config.DATA_DIR / ".restore-flag"


# ---------------------------------------------------------------- work dir (scratch on the volume)
# Toate temporarele unui backup / restore (copia VACUUM INTO, spool-urile de transcript, WTS-ul
# primit prin socket, DB-ul extras la verificare) stau AICI, pe volumul de date, niciodată în
# directorul temporar al sistemului: în producţie containerul e read_only cu /tmp tmpfs de 64 MiB,
# iar un backup cu transcripturi murea cu ENOSPC (3.8 rc3). Un director privat per operaţie,
# ţinut sub flock cât trăieşte; ce rămâne de la un crash (lock liber) se şterge la boot şi înaintea
# fiecărei operaţii. Sub backups/, deci fără nume rezervate în rădăcina volumului (keys.find_reserved,
# txstore.inventory) şi fără să se potrivească cu `_NEW_BACKUP` (inventarul legacy vs 3.8).
WORK_DIR = ".work"
WORK_GRACE_SECS = 60           # fereastra mkdir → flock a creatorului; mai tânăr de atât nu se atinge
_WORK_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _check_private_dir(fd, what: str) -> None:
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        raise ValueError("%s is not a directory of this service — refused" % what)
    if st.st_mode & 0o077:
        os.fchmod(fd, 0o700)


def _open_work_root(create: bool):
    """fd of backups/.work (0700, ours, never a symlink), or None when absent and not `create`."""
    if create:
        bdir = _backup_dir()
    else:
        bdir = config.DATA_DIR / "backups"
    try:
        bfd = os.open(str(bdir), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        if create:
            raise
        return None
    try:
        if create:
            try:
                os.mkdir(WORK_DIR, 0o700, dir_fd=bfd)
            except FileExistsError:
                pass
        try:
            wfd = os.open(WORK_DIR, _WORK_DIR_FLAGS, dir_fd=bfd)
        except FileNotFoundError:
            if create:
                raise
            return None
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENOTDIR):
                raise ValueError("backups/%s is not a plain directory (symlink?) — refused" % WORK_DIR) from None
            raise
    finally:
        os.close(bfd)
    try:
        _check_private_dir(wfd, "backups/" + WORK_DIR)
    except BaseException:
        os.close(wfd)
        raise
    return wfd


def _sweep_work_fd(wfd, wpath: str, grace: float) -> int:
    """Removes what a dead operation left (an entry whose flock we can take, older than `grace`);
    an entry in use (flock held by a live operation, in this or another process) is skipped."""
    n = 0
    now = time.time()
    for name in os.listdir(wfd):
        try:
            st = os.stat(name, dir_fd=wfd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if now - st.st_mtime < grace:
            continue
        if not stat.S_ISDIR(st.st_mode):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(name, dir_fd=wfd)
            n += 1
            continue
        try:
            dfd = os.open(name, _WORK_DIR_FLAGS, dir_fd=wfd)
        except OSError:
            continue
        try:
            try:
                fcntl.flock(dfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue                      # o operaţie vie îl ţine
            # rmtree pe Linux merge prin fd-uri şi nu urmează symlink-uri dinăuntru
            shutil.rmtree(os.path.join(wpath, name), ignore_errors=True)
            n += 1
        finally:
            os.close(dfd)
    return n


def sweep_work(grace: float = WORK_GRACE_SECS) -> int:
    """Boot / before each operation: stale entries of backups/.work removed. → how many."""
    wfd = _open_work_root(create=False)
    if wfd is None:
        return 0
    try:
        return _sweep_work_fd(wfd, str(config.DATA_DIR / "backups" / WORK_DIR), grace)
    finally:
        os.close(wfd)


@contextmanager
def work_dir(prefix: str = "op-"):
    """A private (0700, ours, flock-held) scratch directory for one backup / restore operation,
    under DATA_DIR/backups/.work; removed on exit, success or failure. Never the system temp dir."""
    wfd = _open_work_root(create=True)
    wpath = str(config.DATA_DIR / "backups" / WORK_DIR)
    dfd = None
    try:
        _sweep_work_fd(wfd, wpath, WORK_GRACE_SECS)
        name = prefix + secrets.token_hex(12)
        os.mkdir(name, 0o700, dir_fd=wfd)
        dfd = os.open(name, _WORK_DIR_FLAGS, dir_fd=wfd)
        fcntl.flock(dfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _check_private_dir(dfd, "the backup work directory")
    except BaseException:
        if dfd is not None:
            os.close(dfd)
        os.close(wfd)
        raise
    os.close(wfd)
    path = os.path.join(wpath, name)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
        os.close(dfd)


# ------------------------------------------------------------------ criptare
def _derive(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=8, p=1).derive(passphrase.encode("utf-8"))


def encrypt(data: bytes, passphrase: str) -> bytes:
    import secrets as _s
    salt, nonce = _s.token_bytes(_SALT), _s.token_bytes(_NONCE)
    ct = AESGCM(_derive(passphrase, salt)).encrypt(nonce, data, _MAGIC)
    return _MAGIC + salt + nonce + ct


def decrypt(blob: bytes, passphrase: str) -> bytes:
    if blob[:len(wtbk.MAGIC)] == wtbk.MAGIC:
        # o arhivă host (backup.sh, WTBK2) încărcată prin UI: aceeaşi uşă, în memorie (blob-ul e deja
        # mărginit de UPLOAD_MAX); mărimile declarate în antet sunt verificate de cititorul WTS1
        r = wtbk.Reader(io.BytesIO(blob), passphrase, max_plain=len(blob))
        out = bytearray()
        while True:
            b = r.read(wtbk.CHUNK)
            if not b:
                return bytes(out)
            out += b
    if blob[:len(_MAGIC)] != _MAGIC:
        raise ValueError("nu pare un backup WebTerm")
    off = len(_MAGIC)
    salt = blob[off:off + _SALT]
    nonce = blob[off + _SALT:off + _SALT + _NONCE]
    ct = blob[off + _SALT + _NONCE:]
    try:
        return AESGCM(_derive(passphrase, salt)).decrypt(nonce, ct, _MAGIC)
    except Exception:
        raise ValueError("wrong passphrase, or the file is corrupt")


# ------------------------------------------------------------------ snapshot
def make_snapshot(include_transcripts: bool = False) -> bytes:
    """tar.gz {webterm.db (VACUUM INTO), secret, [transcripts]}. SINCRON — apelează
    prin asyncio.to_thread din endpoint-uri (VACUUM + gzip pot dura).
    Doar volume clasificate EXPLICIT legacy (volume_kind, H2): pe un volum protejat sau cu urme
    ale formatului nou (keys.wtk lipsă dar migrating.wtm / .wts / furnizor de chei) arhiva în
    clar, cu `secret`, e refuzată (§12.10)."""
    if volume_kind() != "legacy":
        raise ValueError("this installation is protected: plaintext snapshots are refused")
    buf = io.BytesIO()
    with work_dir() as td:
        dbcopy = os.path.join(td, "webterm.db")
        reserve_space(td, db_size(), "the database copy of the backup")
        con = sqlite3.connect(str(config.DB_PATH))
        try:
            con.execute("VACUUM INTO ?", (dbcopy,))   # copie curată, crash-consistent
        finally:
            con.close()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(dbcopy, arcname="webterm.db")
            sp = _secret_path()
            if sp.exists():
                tar.add(str(sp), arcname="secret")
            # L4: cheia de semnare a flotei. Fără ea, un restore lăsa agenții imposibil de actualizat
            # (o cheie nouă generată n-ar fi de încredere → re-enroll manual pe fiecare host). Cheia
            # privată e ≤ sensibilă ca `secret` (deja în backup) și poate fi criptată cu parolă la repaus.
            for name in ("agent-signing.key", "agent-signing.pub"):
                p = config.DATA_DIR / name
                if p.exists():
                    tar.add(str(p), arcname=name)
            if include_transcripts and config.TRANSCRIPT_DIR.exists():
                # Fişier cu fişier, tolerant la eşec. `tar.add` pe TOT directorul aruncă
                # `OSError: unexpected end of data` dacă un transcript se micşorează în timp
                # ce e citit — iar asta se întâmpla exact când trebuie: `_maybe_cap` trunchia
                # in-place fişierele care trec de plafon, adică fix în sesiunile cu output
                # masiv. Rezultatul era pierderea ÎNTREGII arhive, nu a unui fişier. Prins prin
                # reproducere de auditul intern (2026-08-06).
                base = config.TRANSCRIPT_DIR
                tar.add(str(base), arcname="transcripts", recursive=False)
                for f in sorted(base.rglob("*")):
                    # temporarele plafonului de transcript (core.CAP_TMP_SUFFIX) sunt o copiere în
                    # curs, nu date: originalul e încă la locul lui şi intră în arhivă
                    if f.name.endswith(".cap-tmp"):
                        continue
                    try:
                        tar.add(str(f), arcname="transcripts/" + str(f.relative_to(base)),
                                recursive=False)
                    except OSError as e:
                        log.warning("transcript skipped from the backup (%s): %s", f.name, e)
    return buf.getvalue()


def make_encrypted(passphrase: str, include_transcripts: bool = False, keys=None) -> bytes:
    """Download / remote upload. Legacy: WTBK1(tar.gz). Protected: WTBK1(portable WTS1) —
    the passphrase is mandatory on both (§12.10: two secrets for an archive that leaves)."""
    if is_protected():
        return encrypt(make_portable_bytes(include_transcripts, keys), passphrase)
    return encrypt(make_snapshot(include_transcripts), passphrase)


# ------------------------------------------------------- backup-uri programate
_fsync = os.fsync            # alias ca testele să poată injecta un eşec la mijlocul scrierii


def _atomic_write(path, data: bytes, mode: int = 0o600) -> None:
    """Scrie `data` în `path` TOT-SAU-NIMIC: temp în acelaşi director → fsync → os.replace.
    `path.write_bytes` lăsa, la disc plin / crash la mijloc, un `.wtsnap` trunchiat pe care
    list_backups îl arăta şi encrypt_stored îl livra userului ca backup valid (audit G-15).
    Temp-ul nu se potriveşte cu `*.wtsnap`, deci nu e vizibil nicăieri până la replace."""
    path = str(path)
    tmp = path + TMP_SUFFIX
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.write(fd, data)
            _fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def run_scheduled_backup(include_transcripts: bool = False, keys=None) -> str:
    """Creează un snapshot NECRIPTAT în data/backups/ (serverul are oricum cheia) +
    aplică retenția. Întoarce numele fișierului. SINCRON (to_thread).
    Volum protejat: un WTS1 local (`.wts`, plic SNK), scris în flux, fără `secret` sau MK."""
    if is_protected():
        hk, blob = _host(keys)
        name = "webterm-%s%s" % (time.strftime("%Y%m%d-%H%M%S", time.gmtime()), WTS_EXT)
        _wts_to_file(_backup_dir() / name, hk, blob, include_transcripts)
        prune_backups()
        log.info("scheduled backup created: %s", name)
        return name
    snap = make_snapshot(include_transcripts)
    name = "webterm-%s.wtsnap" % time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    _atomic_write(_backup_dir() / name, snap)
    prune_backups()
    log.info("scheduled backup created: %s (%d KB)", name, len(snap) // 1024)
    return name


def prune_backups(days: int = RETENTION_DAYS) -> int:
    now = time.time()
    cutoff = now - days * 86400
    n = 0
    for f in _backup_dir().glob("*.wtsnap"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                n += 1
        except OSError:
            pass
    for f in _backup_dir().glob("*" + WTS_EXT):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                n += 1
        except OSError:
            pass
    # resturi `.tmp` de la un crash în timpul scrierii: nu sunt arhive, doar ocupă disc
    for f in [*_backup_dir().glob("*.wtsnap" + TMP_SUFFIX), *_backup_dir().glob("*" + WTS_EXT + TMP_SUFFIX)]:
        try:
            if f.stat().st_mtime < now - STALE_TMP_SECS:
                f.unlink()
        except OSError:
            pass
    return n


def list_backups() -> list:
    out = []
    for f in sorted([*_backup_dir().glob("*.wtsnap"), *_backup_dir().glob("*" + WTS_EXT)], reverse=True):
        try:
            st = f.stat()
            out.append({"name": f.name, "size": st.st_size, "created": int(st.st_mtime)})
        except OSError:
            pass
    return out


def remote_name(local_name: str) -> str:
    """Name of the off-host copy of a stored snapshot (both are WTBK1 files once uploaded)."""
    for ext in (".wtsnap", WTS_EXT):
        if local_name.endswith(ext):
            return local_name[:-len(ext)] + ".wtbk"
    return local_name


def encrypt_stored(name: str, passphrase: str, keys=None, mk=None) -> bytes:
    """Citește un backup programat stocat și-l criptează cu parola userului (pt. download).
    Un `.wts` local se deschide cu SNK şi se re-criptează în flux ca WTS1 portabil cu o cheie de
    conţinut NOUĂ (niciodată aceeaşi cheie cu alt AAD), cu keys.wtk-ul interior re-ambalat sub
    MK-ul curent (M4: un singur MK deschide rezultatul; un snapshot de dinaintea unei rotaţii
    cere MK-ul vechi în `mk`), verificat pe ruta portabilă, apoi stratul cu parolă."""
    if isinstance(name, str) and name.endswith(WTS_EXT) and "/" not in name and "\\" not in name:
        if not is_protected():
            raise ValueError(_WTS_ON_LEGACY)
        hk, _ = _host(keys)
        path = _open_stored_wts(name)
        buf = _ExportBuf()
        with open(os.open(str(path), _FILE_RO), "rb") as f:
            _transcode(f, hk, buf, mk)
        _verify_wts(io.BytesIO(buf.getvalue()), hk, None, prefer="portable")
        return encrypt(buf.getvalue(), passphrase)
    if "/" in name or "\\" in name or not name.endswith(".wtsnap"):
        raise ValueError("invalid name")
    volume_kind()                                  # H2: un volum ambiguu nu livrează nimic
    path = _backup_dir() / name
    if not path.exists():
        raise FileNotFoundError(name)
    return encrypt(path.read_bytes(), passphrase)


# --------------------------------------------------------------- verify/restore
# Plafon dur pe conţinutul DECOMPRIMAT al unui backup (un snapshot real e mic — DB + cheie).
# Anti bombă de compresie: un tar.gz mic poate declara/expanda la zeci de GB şi umple discul
# gateway-ului la extragere; BoundedGunzip (snapshot.py) se opreşte la plafon, deci nu
# materializează niciodată bomba.
RESTORE_MAX_UNCOMPRESSED = 2 * 1024 * 1024 * 1024      # 2 GB
# Calea host-ului (backup.sh / restore.sh, snapshot-urile stocate, copia de siguranţă, socket-ul de
# control): fără plafon fix. Scrierea e mărginită de inventar şi de discul liber al destinaţiei;
# citirea de mărimile EXACTE declarate în antetul autentificat (WTBK2) sau de fişierul însuşi,
# plus discul liber al staging-ului; plafonul de raport al BoundedGunzip rămâne (bombă de compresie).
HOST_MAX = 1 << 62
DISK_RESERVE = 64 << 20        # ce lăsăm liber pe volum peste estimare (DB-ul viu, jurnalele)


def _inspect(raw: bytes) -> dict:
    """Validează un snapshot 3.7 decriptat (tar.gz); întoarce meta. RC-M1: prin ACEEAŞI conductă ca
    staging-ul (_extract_legacy_strict: extractorul strict, fără duplicate / aliasuri / nume
    necanonice, DB-ul EverShell, perechea de semnare, cheia dovedită pe DB-ul arhivei), doar că pe
    disc ajunge numai webterm.db (într-un director privat, şters după). Lipsa cheii nu e refuz aici
    (`has_secret` False; verify_restorable / staging-ul refuză). Orice arhivă invalidă → ValueError."""
    with work_dir("inspect-") as td:
        try:
            arc, secret, users_since = _extract_legacy_strict(raw, td, keep_files=False, require_secret=False)
            has_secret = secret is not None
            del secret
            arc.mem.clear()
        except (OSError, EOFError) as e:
            raise ValueError("corrupt file, or not a WebTerm backup") from e
    return {"has_secret": has_secret,
            "has_transcripts": bool(arc.dirs) or any(n.startswith("transcripts/") for n in arc.seen),
            "users_since": users_since}


def prove_legacy_secret(db_dir: str, secret: bytes) -> str:
    """R-H2: the 32-byte vault key of a pre-3.8 archive must decrypt at least one encrypted value
    of THAT archive's database (`db_dir/webterm.db`), with the boot's own inventory and budget
    (legacyvault.prove_legacy_key); a database without encrypted values is eligible. Refusal →
    ValueError naming the reason (never the key). → "proven" | "no-ciphertext"."""
    dfd = os.open(db_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return legacyvault.prove_legacy_key(dfd, secret, base_path=db_dir)
    except keystore.BootRefused as e:
        raise ValueError("the vault key in the backup does not open its own database (%s) — refused"
                         % e.reason) from None
    finally:
        os.close(dfd)


class StageProgress:
    """R-M1: how far a staging run got. `mutated`: the data directory was changed (the first
    rename into it); `committed`: the new flag is published AND its directory fsynced. The host
    script maps them to exit codes (refused before any change / committed / uncertain)."""

    def __init__(self):
        self.mutated = False
        self.committed = False


def verify(blob: bytes, passphrase: str, keys=None, mk=None, prefer: str = "local") -> dict:
    raw = decrypt(blob, passphrase)
    # RC-M1: aceeaşi rută ca stage_restore din ruta API (care nu oferă importul legacy): un 3.7 pe
    # un volum protejat e refuzat aici la fel ca la restore. H2: un volum ambiguu nu verifică nimic.
    if restore_route(raw, is_protected(), False) == "wts":
        return _verify_wts_bytes(raw, keys, mk, prefer)
    return _inspect(raw)


_WTS_ON_LEGACY = ("this backup comes from an installation with encryption at rest; it can only be "
                  "restored on an installation whose key manifest (keys.wtk) is set up")
_NEEDS_LEGACY_IMPORT = ("a pre-3.8 backup holds the raw vault key; on this installation it needs the "
                        "explicit legacy import — refused")
_IMPORT_ON_LEGACY = "the legacy import is for protected installations; this one is pre-3.8 — refused"
_IMPORT_OF_WTS = "the legacy import is only for a pre-3.8 backup; this one is a 3.8 backup — refused"


def restore_route(raw: bytes, protected: bool, legacy_import: bool) -> str:
    """RC-M1: the ONE dispatch of a decrypted archive, by its INNER format and the target's policy
    (never by the outer wrapper: a WTBK1 holding a 3.7 tar is a 3.7 archive). `hostops verify`,
    `hostops stage-restore` and stage_restore call it, so verify and stage reach the same verdict,
    before anything is stopped. → "wts" | "legacy-import" | "legacy-volume"; refusal → ValueError."""
    if raw[:4] == wts.MAGIC:
        if not protected:
            raise ValueError(_WTS_ON_LEGACY)
        if legacy_import:
            raise ValueError(_IMPORT_OF_WTS)
        return "wts"
    if raw[:2] != b"\x1f\x8b":
        raise ValueError("corrupt file, or not a WebTerm backup")
    if protected:
        if not legacy_import:
            raise ValueError(_NEEDS_LEGACY_IMPORT)
        return "legacy-import"
    if legacy_import:
        raise ValueError(_IMPORT_ON_LEGACY)
    return "legacy-volume"


def verify_restorable(blob: bytes, passphrase: str, keys=None, mk=None, prefer: str = "local") -> dict:
    """3.6.8: a real restore test without restoring — decrypt, unpack (bounded), integrity-check
    the database, and require the vault key (a backup without it restores nothing usable)."""
    info = verify(blob, passphrase, keys, mk, prefer)
    if info.get("format") != "WTS1" and not info["has_secret"]:
        raise ValueError("backup without the vault key — a restore would leave the credentials "
                         "undecryptable")
    return info


def verify_stored(name: str, keys=None) -> dict:
    """The same check on a stored scheduled snapshot (`data/backups/*.wtsnap`, unencrypted;
    `*.wts`, a local WTS1 checked end to end with the host's SNK)."""
    if isinstance(name, str) and name.endswith(WTS_EXT) and "/" not in name and "\\" not in name:
        if not is_protected():
            raise ValueError(_WTS_ON_LEGACY)
        hk, _ = _host(keys)
        path = _open_stored_wts(name)
        with _restore_lock():
            td = _private_tmpdir()
            try:
                with open(os.open(str(path), _FILE_RO), "rb") as f:
                    # un .wts stocat (programat, copie de siguranţă) nu mai are plafonul fix de 2 GiB:
                    # bugetul e mărimea lui şi discul liber pe care se extrage
                    info, _inner = _verify_wts(f, hk, td, max_plaintext=os.fstat(f.fileno()).st_size,
                                               max_unpacked=max(0, free_bytes(td) - DISK_RESERVE))
            finally:
                shutil.rmtree(td, ignore_errors=True)
        info.pop("_content", None)
        return info
    # un `.wtsnap` 3.7 rămas pe un volum protejat rămâne verificabil (§12.10); un volum ambiguu nu (H2)
    volume_kind()
    if "/" in name or "\\" in name or not name.endswith(".wtsnap"):
        raise ValueError("invalid name")
    path = _backup_dir() / name
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(name)
    if path.stat().st_size > RESTORE_MAX_UNCOMPRESSED:
        raise ValueError("backup too large")
    info = _inspect(path.read_bytes())
    if not info["has_secret"]:
        raise ValueError("backup without the vault key — a restore would leave the credentials "
                         "undecryptable")
    return info


def stage_restore(blob: bytes, passphrase: str, keys=None, mk=None, legacy_import: bool = False,
                  prefer: str = "local", progress=None, erasure_fetch=None) -> dict:
    """Decriptează + validează + extrage în restore-pending/ + scrie markerul. Aplicarea
    reală se face la următorul boot (apply_pending_restore), după un restart.
    Volum protejat: un WTS1 (verificat complet înainte de staging; `mk` = MK-ul operatorului
    pentru un backup portabil al altei instalări sau făcut sub un MK retras; `prefer="portable"`
    alege plicul portabil înaintea celui local) sau, cu `legacy_import=True`, un backup
    pre-3.8 importat explicit (cheia lui dovedită pe DB-ul lui, R-H2). Volum legacy: un WTS1 e
    refuzat; un backup 3.7 e verificat ca în 3.7 plus proba cheii pe DB-ul lui, apoi publicat
    durabil (set complet, flag atomic, R-M1). `progress` (StageProgress): cât s-a ajuns.
    `erasure_fetch(k_erase, inst)` (3.8 PR6a, doar cu înregistrările criptate active): jurnalele de
    ştergeri ale destinaţiilor off-host, pentru dovada continuităţii (§12.11.4)."""
    progress = progress if progress is not None else StageProgress()
    raw = decrypt(blob, passphrase)
    _invalidate_kind()
    route = restore_route(raw, is_protected(), legacy_import)     # RC-M1: aceeaşi rută ca verify
    if route == "wts":
        return _stage_wts(io.BytesIO(raw), keys, mk, prefer, progress, erasure_fetch)
    if route == "legacy-import":
        return _stage_legacy_import(raw, keys, progress)
    return _stage_legacy_volume(raw, progress)


def verify_legacy_volume(raw: bytes) -> dict:
    """RC-M1: a 3.7 archive for a legacy volume, checked exactly as _stage_legacy_volume checks it
    (the strict extractor, the vault key required and proven on the archive's own database),
    without staging anything."""
    if volume_kind() != "legacy":
        raise ValueError(_NEEDS_LEGACY_IMPORT)
    info = _inspect(raw)
    if not info["has_secret"]:
        raise ValueError("backup without the vault key — a restore would leave the credentials "
                         "undecryptable; use a complete WebTerm backup")
    return info


def _stage_legacy_volume(raw: bytes, progress) -> dict:
    """A 3.7 backup onto a legacy volume. RC-M1: the same strict extractor and proofs as verify
    (_extract_legacy_strict) into a private directory; the vault key (memory only until here) is
    written into the set, and the EXACT pair that is published (the set's webterm.db and the
    `secret` read back from the set) is proven again right before publishing. Then the durable
    publication: the old flag removed durably first (a crash never leaves a flag over a
    half-swapped set), the old set moved aside, the new one renamed into place, the flag written
    atomically (tmp, fsync, rename, directory fsync) — the commit point."""
    rd, flag = _restore_dir(), _restore_flag()
    with _restore_lock():
        td = _private_tmpdir()
        trash = None
        try:
            arc, secret, users_since = _extract_legacy_strict(raw, td)
            _write_new(os.path.join(td, "secret"), secret)
            del secret
            arc.mem.clear()
            info = {"has_secret": True, "users_since": users_since,
                    "has_transcripts": bool(arc.dirs) or any(n.startswith("transcripts/") for n in arc.seen)}
            files, dirs = _tree(td)
            for rel in files:
                if not _allowed(rel, False, "legacy"):
                    raise ValueError("unexpected file in the restore staging — refused: %s" % rel[:80])
            for rel in dirs:
                if rel not in _TX_DIRS:
                    raise ValueError("unexpected directory in the restore staging — refused")
            # RC-M1: perechea publicată, exact cum stă în set (nu cum era în memorie)
            pub = _read_small(os.path.join(td, "secret"), kr.KEY_LEN + 1)
            if len(pub) != kr.KEY_LEN:
                raise ValueError("the vault key in the restore staging is malformed — refused")
            _check_db(os.path.join(td, "webterm.db"))
            prove_legacy_secret(td, pub)
            del pub
            for rel in files:
                _fsync_path(files[rel])
            for rel in sorted(dirs, key=lambda r: -r.count("/")):
                _fsync_dir(os.path.join(td, rel))
            _fsync_dir(td)
            _step("legacy:extracted")
            # R-M1: de aici volumul se schimbă
            progress.mutated = True
            if os.path.lexists(str(flag)):
                os.unlink(str(flag))
                _fsync_dir(config.DATA_DIR)
            if os.path.lexists(str(rd)):
                trash = tempfile.mkdtemp(prefix=VERIFY_PREFIX + "old-", dir=str(_backup_dir()))
                os.rename(str(rd), os.path.join(trash, "set"))
            os.rename(td, str(rd))
            td = None
            _fsync_dir(_backup_dir())
            _fsync_dir(config.DATA_DIR)
            _step("legacy:renamed")
            _write_flag_bytes(str(int(time.time())).encode())
            progress.committed = True
            _invalidate_kind()
        finally:
            if td is not None:
                shutil.rmtree(td, ignore_errors=True)
            if trash is not None and progress.committed:
                shutil.rmtree(trash, ignore_errors=True)
    log.warning("RESTORE staged — it is applied on the next restart")
    return info


def _atomic_copy(src: str, dst) -> None:
    """Copie atomică pe același filesystem: scrie într-un temp lângă țintă + os.replace.
    Astfel o țintă (DB / cheie) nu rămâne niciodată trunchiată la un crash în timpul copierii."""
    tmp = str(dst) + ".restoring"
    shutil.copy2(src, tmp)
    os.replace(tmp, str(dst))       # rename atomic → înlocuire tot-sau-nimic


def apply_pending_restore(keys=None, force_without_safety_copy: bool = False) -> bool:
    """La boot, ÎNAINTE de db.connect(): dacă există un restore în staging, îl aplică
    (swap DB + secret + transcripturi). Întoarce True dacă a aplicat ceva.

    IDEMPOTENT + REÎNCERCABIL: DB-ul și cheia seifului trebuie să swap-eze ÎMPREUNĂ — un
    swap ne-atomic lăsa DB nou + cheie veche = seif nedecriptabil silențios. Copiem din
    staging (NU mutăm), deci originalele rămân intacte până la commit-ul complet; ștergem
    staging + flag DOAR după ce totul e la loc. Un crash/excepție la mijloc lasă staging-ul
    + flagul → următorul boot reia de la zero și converge. Ridicăm la eșec (main.py refuză
    să pornească cu stare parțială, în loc să servească un seif rupt). Fiecare fișier critic
    e înlocuit atomic (temp + os.replace).

    3.8 (H1/H2): fără flag şi fără staging nu e nimic de făcut (ca în 3.7). Altfel întâi
    clasificarea volumului: protejat → jurnalul protejat (`_apply_protected`, unde orice marcaj
    incomplet e refuz); ambiguu (keys.wtk lipsă cu urme ale formatului nou, staging 3.8 pe un
    volum fără keys.wtk) → refuz; legacy → codul 3.7 de mai jos, neschimbat."""
    flag, rd = _restore_flag(), _restore_dir()
    if not os.path.lexists(flag) and not os.path.lexists(rd):
        return False
    _invalidate_kind()
    if volume_kind() == "protected":
        return _apply_protected(keys, force_without_safety_copy)
    if not flag.exists() or not (rd / "webterm.db").exists():
        return False
    # Plasă de siguranță: snapshot al stării CURENTE înainte de a o suprascrie. Sufix
    # `.keep` → retenția NU-l șterge (e singura recuperare dacă restore-ul e greșit).
    try:
        if config.DB_PATH.exists():
            cur = make_snapshot(include_transcripts=False)
            keep = _backup_dir() / ("pre-restore-%d.wtsnap.keep" % int(time.time()))
            # conţine `data/secret` NECRIPTAT — sub umask 022 ieşea 0644, adică lizibil de
            # orice user de pe maşină; _atomic_write deschide cu 0600 şi scrie tot-sau-nimic.
            _atomic_write(keep, cur)
    except Exception as e:                        # noqa: BLE001
        log.warning("the pre-restore snapshot failed (continuing): %s", e)

    # cheia seifului întâi (trebuie să existe pentru DB-ul restaurat), apoi transcripturi
    if (rd / "secret").exists():
        _atomic_copy(str(rd / "secret"), _secret_path())
        _secret_path().chmod(0o600)
    # L4: cheia de semnare a flotei (dacă backup-ul o conține) — ca agenții să rămână actualizabili
    for name in ("agent-signing.key", "agent-signing.pub"):
        if (rd / name).exists():
            _atomic_copy(str(rd / name), config.DATA_DIR / name)
            (config.DATA_DIR / name).chmod(0o600)
    if (rd / "transcripts").is_dir():
        if config.TRANSCRIPT_DIR.exists():
            shutil.rmtree(config.TRANSCRIPT_DIR)
        shutil.copytree(str(rd / "transcripts"), str(config.TRANSCRIPT_DIR))
    # DB ultimul = punctul de commit al datelor; apoi curăță WAL/SHM vechi ca să nu
    # contrazică noul DB
    _atomic_copy(str(rd / "webterm.db"), config.DB_PATH)
    for ext in ("-wal", "-shm"):
        p = config.DATA_DIR / ("webterm.db" + ext)
        if p.exists():
            p.unlink()
    log.warning("RESTORE applied from a backup (DB + key%s)",
                " + transcripturi" if (rd / "transcripts").is_dir() else "")
    # commit: abia acum, cu totul la loc, eliminăm staging-ul + flagul
    shutil.rmtree(rd, ignore_errors=True)
    try:
        flag.unlink()
    except OSError:
        pass
    return True


# ═══════════════════════════════════════════════════════════════ protected (3.8, WTS1)
# docs/design/ENCRYPTION-AT-REST.md §12.10. Volumul e „protejat” când `keys.wtk` există; atunci
# niciun backup nu conţine `secret` sau MK, ci doar keys.wtk (inutil fără MK) într-un container
# WTS1. Volumele legacy (fără keys.wtk) merg EXACT pe codul de mai sus, neschimbat.
KEYS_NAME = "keys.wtk"
WTS_EXT = ".wts"
CONTENT_MANIFEST = "wts-manifest.json"
CONTENT_MANIFEST_MAX = 4 * 1024 * 1024
RESTORE_MANIFEST = "restore.json"
RESTORE_MANIFEST_MAX = CONTENT_MANIFEST_MAX + 64 * 1024
FLAG_MAX = 64 * 1024
MAX_MEMBERS = 200_000
SIGNING_MAX = 64 * 1024
STAGE_LOCK = ".restore.lock"
VERIFY_PREFIX = ".restore-verify-"
_SIGNING = ("agent-signing.key", "agent-signing.pub")
# 3.8 PR6a: jurnalul de ştergeri (WTJ1) e membru doar al unui manifest `wts-content-2` (§12.11.3)
JOURNAL_MEMBER = erasure.JOURNAL_NAME
_TOP_FILES = frozenset({"webterm.db", KEYS_NAME, *_SIGNING, JOURNAL_MEMBER})
_REC_STATES = frozenset({"included", "legacy", "excluded", "not-requested", "one-kind"})
_SID_HEX = re.compile(r"^[0-9a-f]{32}$")
_NAME_PART = re.compile(r"^[A-Za-z0-9_@+=-][A-Za-z0-9._@+=-]{0,254}$")
_TX_DEPTH = 4
# H3: inventarul transcripturilor e o listă de PERMISIUNI, nu de excluderi: doar înregistrările
# pe care le scrie core.py (`<sid>.out`, `<sid>.cast`), la rădăcină şi în `arhiva/`.
_TX_FILE = re.compile(r"^[A-Za-z0-9_-]{1,128}\.(out|cast)$")
_TX_GEN = re.compile(r"^([0-9a-f]{32})\.(out|cast)\.([0-9a-f]{32})\.wtx$")
_TX_ARCHIVE = "arhiva"
_TX_DIRS = frozenset({"transcripts", "transcripts/" + _TX_ARCHIVE})
_LEGACY_IMPORT_FILES = frozenset({"webterm.db", *_SIGNING})
# M1: profilul tar. Writer-ul nostru scrie USTAR pur (fără extensii); arhivele 3.7 (tarfile PAX
# implicit) au antete PAX mici pentru mtime fracţionar. Doar acelea, mărginite, şi doar la import.
_PAX_MAX = 8 * 1024
_PAX_KEYS_LEGACY = frozenset({"path", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname"})
_MEM_CAP = {CONTENT_MANIFEST: CONTENT_MANIFEST_MAX, KEYS_NAME: kr.MAN_MAX_LEN, "secret": kr.KEY_LEN,
            "agent-signing.key": SIGNING_MAX, "agent-signing.pub": SIGNING_MAX}
_SHA_HEX = re.compile(r"^[0-9a-f]{64}$")
_BUSY = "another backup verification or restore is in progress — try again in a moment"
# R-H1: un jurnal de apply neterminat (flag `applying`/`committed`) se reia, nu se înlocuieşte
_IN_PROGRESS = ("a restore is being applied and its journal is not finished — restart the gateway "
                "so it completes before another restore is staged")
# R-H1: fiecare set staged are directorul lui (`restore-pending.<generaţie>`); flagul îl numeşte
SET_PREFIX = "restore-pending."
_GEN_HEX = re.compile(r"^[0-9a-f]{32}$")
# R-M2: un export oferit pentru descărcare / upload trebuie să încapă în ruta de restore
UPLOAD_MAX = 512 * 1024 * 1024
_WTBK_OVERHEAD = len(_MAGIC) + _SALT + _NONCE + 16
# R-M2: verificarea „restaurabilă” cere schema minimă a gateway-ului, nu doar un SQLite integru
_REQUIRED_TABLES = ("users", "hosts", "sessions", "app_settings")
_PUB_HEX = re.compile(rb"^[0-9a-f]{64}\n?$")
_KEYS_MISSING = ("this installation is protected but keys.wtk is missing — every backup and restore "
                 "is refused until the key manifest is back")


@dataclass(frozen=True)
class HostKeys:
    """The running process's opened keyring and the MK it was opened with (the MK only derives
    the portable envelope's KEK; it is never written anywhere)."""
    ring: kr.Keyring
    mk: bytes = field(repr=False)


# Boot-ul (încă necablat, §12.9 Wiring checklist) înregistrează aici furnizorul; până atunci un
# volum protejat fără `keys=` explicit e refuzat (fail closed), nu tratat ca legacy.
_host_keys_provider = None
_boot_protected = False
# Injecţie de defecte pentru teste (H1): chemat cu numele fiecărui pas durabil al staging/apply.
_fault = None


def _step(name: str) -> None:
    if _fault is not None:
        _fault(name)


def set_host_keys_provider(fn) -> None:
    """Registered by the boot once the keyring is open. While one is registered the process
    KNOWS it is protected: a missing keys.wtk is then a refusal, never the legacy path (H2)."""
    global _host_keys_provider
    _host_keys_provider = fn


def set_boot_protected(flag: bool) -> None:
    """The wiring PR sets this from the boot state (keys.classify under the process lock) before
    any backup route runs; with it set, ENOENT on keys.wtk is never read as "legacy"."""
    global _boot_protected
    _boot_protected = bool(flag)


def _protected_expected() -> bool:
    return _boot_protected or _host_keys_provider is not None


class _DirView:
    """keys.classify / find_reserved read DATA_DIR only through `dir_fd`; this gives them one
    without the process lock (read-only; the wiring PR routes through the boot state instead)."""

    def __init__(self, dir_fd):
        self.dir_fd = dir_fd


_NEW_BACKUP = re.compile(r"\.wts(\.keep|\.tmp)?$")


def _is_link(dfd, name: str) -> bool:
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=dfd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def _followed_backups(dfd) -> str:
    """R-M3: 3.7 suporta `backups/` ca symlink către alt disc. Fără keys.wtk îl listăm urmând
    legătura (doar citire, doar numele de la primul nivel); o ţintă care nu se poate lista nu
    dovedeşte absenţa unui WTS1 → rămâne urmă (refuz)."""
    try:
        bfd = os.open("backups", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=dfd)
    except OSError:
        return "backups (symlink, unreadable)"
    try:
        for n in os.listdir(bfd):
            if _NEW_BACKUP.search(n):
                return "backups/" + n
    except OSError:
        return "backups (symlink, unreadable)"
    finally:
        os.close(bfd)
    log.warning("legacy volume: backups/ is a symlink to another directory (supported 3.7 layout); "
                "it was checked through the link and holds no 3.8 snapshot")
    return ""


def _followed_transcripts(dfd) -> str:
    """R-M3: `transcripts/` symlink (layout 3.7 suportat) pe un volum fără keys.wtk: acelaşi
    inventar ca keys.classify (o singură definiţie, keys.find_reserved_through_link), prin
    legătura rădăcinii; sub ea niciun alt symlink nu e urmat. Orice eroare → urmă (refuz)."""
    hit = keystore.find_reserved_through_link(dfd)
    if not hit:
        log.warning("legacy volume: transcripts/ is a symlink to another directory (supported 3.7 "
                    "layout); it was checked through the link and holds no 3.8 recording")
    return hit


def _new_format_traces(dfd) -> str:
    """A trace that this volume has been protected, looked for when keys.wtk is absent (H2).
    R-M3: the supported 3.7 layouts (`backups/` or `transcripts/` as a symlink to another disk)
    are checked through the link and stay legacy, with a warning."""
    for n in keystore.KEY_ARTEFACTS:
        if n in (keystore.LEGACY_SECRET, keystore.MANIFEST):
            continue
        try:
            os.stat(n, dir_fd=dfd, follow_symlinks=False)
            return n
        except FileNotFoundError:
            pass
    hit = keystore.find_reserved(dfd)
    if hit == keystore.RESERVED_DIR + " (unreadable)" and _is_link(dfd, keystore.RESERVED_DIR):
        hit = _followed_transcripts(dfd)
    if hit:
        return hit
    # R-H1: generaţiile de staging 3.8 (restore-pending.<gen>) există doar pe un volum protejat
    for n in os.listdir(dfd):
        if n.startswith(SET_PREFIX):
            return n
    try:
        sfd = os.open("restore-pending", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=dfd)
    except FileNotFoundError:
        sfd = None
    except OSError:
        return "restore-pending (not a plain directory)"
    if sfd is not None:
        try:
            for n in (KEYS_NAME, RESTORE_MANIFEST):
                try:
                    os.stat(n, dir_fd=sfd, follow_symlinks=False)
                    return "restore-pending/" + n
                except FileNotFoundError:
                    pass
        finally:
            os.close(sfd)
    try:
        flag = _read_small(config.DATA_DIR / ".restore-flag", FLAG_MAX)
        if flag[:1] == b"{":
            return ".restore-flag (3.8 format)"
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        return ".restore-flag (unreadable)"
    try:
        bfd = os.open("backups", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        return ""
    except OSError:
        if _is_link(dfd, "backups"):
            return _followed_backups(dfd)
        return "backups (not a plain directory)"
    try:
        for n in os.listdir(bfd):
            if _NEW_BACKUP.search(n):
                return "backups/" + n
    finally:
        os.close(bfd)
    return ""


# R-M3: clasificarea se refoloseşte cât timp nimic din ce citeşte nu s-a schimbat (cheia = stat-urile
# intrărilor inventariate + starea de boot); stage/apply o invalidează explicit. Doar rezultatele
# curate („legacy”/„protected”) se păstrează: un refuz se recalculează mereu.
_kind_cache = None
_KIND_STAT = (KEYS_NAME, *keystore.KEY_ARTEFACTS, ".restore-flag", "restore-pending", "backups",
              keystore.RESERVED_DIR, keystore.RESERVED_DIR + "/" + _TX_ARCHIVE)


def _invalidate_kind() -> None:
    global _kind_cache
    _kind_cache = None


def _kind_key(dfd):
    def sig(st):
        return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    out = [str(config.DATA_DIR), _protected_expected(), sig(os.fstat(dfd))]
    for n in _KIND_STAT:
        for follow in (False, True):
            try:
                out.append(sig(os.stat(n, dir_fd=dfd, follow_symlinks=follow)))
            except OSError as e:
                out.append(e.errno)
    return tuple(out)


def volume_kind() -> str:
    """"protected" (keys.wtk, and keys.classify agrees) or "legacy"; anything else → ValueError.

    H2: ENOENT on keys.wtk is "legacy" ONLY when nothing says otherwise — no host-keys provider
    or boot flag, no key artefact of the new format (migrating.wtm, keys.wtk.tmp, master.key…),
    no reserved name (keys.find_reserved), no 3.8 staging and no WTS1 snapshot in backups/.
    Lock-free read; the wiring PR must route through the boot state taken under the lock.
    R-M3: a clean result is cached per process while the inventoried entries are unchanged."""
    global _kind_cache
    try:
        dfd = os.open(str(config.DATA_DIR), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        if _protected_expected():
            raise ValueError(_KEYS_MISSING) from None
        return "legacy"
    try:
        key = _kind_key(dfd)
        if _kind_cache is not None and _kind_cache[0] == key:
            return _kind_cache[1]
        kind = _classify(dfd)
        _kind_cache = (key, kind)
        return kind
    finally:
        os.close(dfd)


def _classify(dfd) -> str:
    try:
        st = os.stat(KEYS_NAME, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("keys.wtk is not a regular file — refused")
        try:
            inv = keystore.classify(_DirView(dfd))
        except OSError:
            raise ValueError("the data directory cannot be read — refused") from None
        if inv.kind != "protected":
            raise ValueError("the data directory is in an inconsistent state (%s) — refused" % inv.reason)
        return "protected"
    if _protected_expected():
        raise ValueError(_KEYS_MISSING)
    try:
        trace = _new_format_traces(dfd)
    except OSError:
        trace = "DATA_DIR (unreadable)"
    if trace:
        raise ValueError("keys.wtk is missing but %s shows this installation was protected — "
                         "refused" % trace)
    return "legacy"


def is_protected() -> bool:
    """keys.wtk present (regular, consistent volume) → True; a volume that is neither cleanly
    legacy nor cleanly protected → ValueError (see volume_kind)."""
    return volume_kind() == "protected"


def _read_small(path, max_len: int) -> bytes:
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_len:
            raise ValueError("%s is not a small regular file — refused" % os.path.basename(str(path)))
        out = b""
        while len(out) <= max_len:
            b = os.read(fd, max_len + 1 - len(out))
            if not b:
                break
            out += b
    finally:
        os.close(fd)
    if len(out) > max_len:
        raise ValueError("%s too large — refused" % os.path.basename(str(path)))
    return out


def _open_ring(blob: bytes, mk: bytes, what: str) -> kr.Keyring:
    try:
        return kr.open_keyring_bytes(blob, mk, kr.PROFILE_V1)
    except kr.WrongKeyError:
        raise wts.SnapshotWrongKey("wrong-mk", what) from None
    except kr.KeyringError as e:
        raise wts.SnapshotError("keyring-invalid", "%s: %s" % (what, e.reason)) from None


def _host(keys=None):
    """(HostKeys, keys.wtk bytes) for a protected volume. The keys come from the caller or the
    registered provider; keys.wtk is re-read and must open with that MK and name the same
    installation and epoch as the keyring the process holds (a manifest changed under a running
    gateway is refused, not followed)."""
    if keys is None and _host_keys_provider is not None:
        keys = _host_keys_provider()
    if keys is None:
        raise ValueError("this installation is protected (keys.wtk) but its keyring is not open — refused")
    blob = _read_small(config.DATA_DIR / KEYS_NAME, kr.MAN_MAX_LEN)
    ring = _open_ring(blob, keys.mk, KEYS_NAME)
    if ring.installation_id != keys.ring.installation_id or ring.epoch != keys.ring.epoch:
        raise ValueError("keys.wtk changed since the keyring was opened — refused")
    if ring.snk is None:
        raise ValueError("keys.wtk has no snapshot key — refused")
    return HostKeys(ring, keys.mk), blob


def _safe_name(name: str) -> str:
    """Canonical archive name (no '.', '..', empty parts, absolute paths or backslashes)."""
    if not isinstance(name, str) or not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise wts.SnapshotError("bad-member-name", repr(name)[:80])
    parts = name.split("/")
    if not all(_NAME_PART.match(p) for p in parts) or len(parts) > _TX_DEPTH + 1:
        raise wts.SnapshotError("bad-member-name", repr(name)[:80])
    return name


def _is_tx_file(name: str) -> bool:
    parts = name.split("/")
    if parts[0] != "transcripts":
        return False
    if len(parts) == 2 and _TX_GEN.match(parts[1]):
        return True                              # PR6c: o generaţie WTX1 (doar direct sub transcripts/)
    if len(parts) == 2:
        base = parts[1]
    elif len(parts) == 3 and parts[1] == _TX_ARCHIVE:
        base = parts[2]
    else:
        return False
    return bool(_TX_FILE.match(base)) and not keystore.is_reserved_name(base, "transcripts")


def _allowed(name: str, is_dir: bool, profile: str = "wts1") -> bool:
    if is_dir:
        return name in _TX_DIRS
    if "/" not in name:
        if profile == "wts1":
            return name in _TOP_FILES or name == CONTENT_MANIFEST
        return name in _LEGACY_IMPORT_FILES or name == "secret"
    return _is_tx_file(name)


# ---------------------------------------------------------------- strict tar (M1)
def _cstr(field_: bytes, what: str) -> str:
    head, _sep, tail = field_.partition(b"\0")
    if tail.strip(b"\0"):
        raise wts.SnapshotError("bad-tar-header", what)
    try:
        return head.decode("utf-8")
    except UnicodeDecodeError:
        raise wts.SnapshotError("bad-tar-header", what) from None


def _octal(field_: bytes, what: str) -> int:
    if field_[:1] and field_[0] & 0x80:
        raise wts.SnapshotError("bad-tar-header", what + " (base-256)")
    s = field_.strip(b" \0")
    if not re.fullmatch(rb"[0-7]{1,12}", s):
        raise wts.SnapshotError("bad-tar-header", what)
    return int(s, 8)


@dataclass
class _Entry:
    name: str
    is_dir: bool
    size: int


class _StrictTar:
    """Bounded tar reader (M1): POSIX USTAR headers only (checksum, magic, version, no links, no
    device/sparse/GNU types), regular files and directories, zero padding after every member,
    both end blocks zero and only zeros up to the end of the decompressed stream (read to EOF by
    `src.drain_zeros`, so nothing hides in a read-ahead buffer). PAX headers: refused for WTS1
    (our writer never emits them); for a 3.7 import only small ones with harmless keys."""

    def __init__(self, src, profile: str):
        self._src = src
        self._profile = profile
        self._left = 0
        self._pad = 0
        self._count = 0
        self._ended = False

    def _exact(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            b = self._src.read(n - len(out))
            if not b:
                raise wts.SnapshotError("truncated-archive")
            out += b
        return bytes(out)

    def read(self, n: int) -> bytes:
        n = min(n, self._left)
        if n <= 0:
            return b""
        b = self._exact(n)
        self._left -= n
        return b

    def _skip_rest(self) -> None:
        while self._left:
            self.read(1 << 20)
        if self._pad:
            if self._exact(self._pad).strip(b"\0"):
                raise wts.SnapshotError("bad-tar-padding")
            self._pad = 0

    def _header(self, blk: bytes):
        if blk[257:265] != b"ustar\x0000":
            raise wts.SnapshotError("unsupported-tar-format")
        want = _octal(blk[148:156], "checksum")
        if want != sum(blk[:148]) + 8 * 32 + sum(blk[156:]):
            raise wts.SnapshotError("bad-tar-checksum")
        typ = blk[156:157]
        if typ not in (b"0", b"\0", b"5", b"x"):
            raise wts.SnapshotError("unexpected-member-type")
        if blk[157:257].strip(b"\0") or blk[500:512].strip(b"\0"):
            raise wts.SnapshotError("bad-tar-header", "link/padding")
        name = _cstr(blk[0:100], "name")
        prefix = _cstr(blk[345:500], "prefix")
        return typ, (prefix + "/" + name if prefix else name), _octal(blk[124:136], "size")

    def _pax(self, data: bytes) -> dict:
        out, pos = {}, 0
        while pos < len(data):
            sp = data.find(b" ", pos, pos + 12)
            ln = data[pos:sp] if sp > pos else b""
            if not ln.isdigit() or ln.startswith(b"0"):
                raise wts.SnapshotError("bad-tar-extension")
            rec = data[pos:pos + int(ln)]
            if len(rec) != int(ln) or not rec.endswith(b"\n"):
                raise wts.SnapshotError("bad-tar-extension")
            k, eq, v = rec[sp - pos + 1:-1].partition(b"=")
            try:
                key, val = k.decode("ascii"), v.decode("utf-8")
            except UnicodeDecodeError:
                raise wts.SnapshotError("bad-tar-extension") from None
            if not eq or key not in _PAX_KEYS_LEGACY or key in out:
                raise wts.SnapshotError("unsupported-tar-extension", key[:20])
            out[key] = val
            pos += len(rec)
        return out

    def __iter__(self):
        return self

    def __next__(self) -> _Entry:
        if self._ended:
            raise StopIteration
        self._skip_rest()
        pax = None
        while True:
            blk = self._exact(512)
            if blk == bytes(512):
                if pax is not None:
                    raise wts.SnapshotError("bad-tar-extension", "no member after it")
                if self._exact(512) != bytes(512):
                    raise wts.SnapshotError("bad-tar-end")
                self._src.drain_zeros()
                self._ended = True
                raise StopIteration
            self._count += 1
            if self._count > MAX_MEMBERS:
                raise wts.SnapshotTooLarge("too-many-members")
            typ, name, size = self._header(blk)
            if typ == b"x":
                if self._profile != "legacy" or pax is not None:
                    raise wts.SnapshotError("unsupported-tar-extension")
                if size > _PAX_MAX:
                    raise wts.SnapshotTooLarge("tar-extension")
                data = self._exact(size)
                pad = (-size) % 512
                if pad and self._exact(pad).strip(b"\0"):
                    raise wts.SnapshotError("bad-tar-padding")
                pax = self._pax(data)
                continue
            if pax and "path" in pax:
                name = pax["path"]
            is_dir = typ == b"5"
            if is_dir:
                if size:
                    raise wts.SnapshotError("bad-tar-header", "directory with data")
                name = name[:-1] if name.endswith("/") else name
            elif name.endswith("/"):
                raise wts.SnapshotError("bad-member-name", repr(name)[:80])
            self._left, self._pad = size, (-size) % 512
            return _Entry(name, is_dir, size)


class _Archive:
    """The one strict extractor (WTS1 restore, verify, transcoding and the 3.7 import): every
    name canonical and allowed by the profile, no duplicates, the content manifest last, every
    byte hashed. Small members in `mem_only` / `mem_also` are kept in memory (capped before
    they are read); `mem_only` ones never reach a file."""

    def __init__(self, src, profile: str, mem_only=(), mem_also=()):
        self._tar = _StrictTar(src, profile)
        self._profile = profile
        self._mem_only = frozenset(mem_only)
        self._mem_also = frozenset(mem_also)
        self.seen: dict = {}
        self.dirs: set = set()
        self.mem: dict = {}
        self._cur = None
        self._folded: set = set()

    def entries(self):
        for e in self._tar:
            if self._cur is not None:
                raise wts.SnapshotError("member-not-consumed", self._cur)
            if self._profile == "wts1" and CONTENT_MANIFEST in self.mem:
                raise wts.SnapshotError("member-after-manifest")
            name = _safe_name(e.name)
            if name in self.seen or name in self.dirs or name in self.mem:
                raise wts.SnapshotError("duplicate-member", name)
            # RC-M1: _safe_name refuză deja orice nume necanonic (`./`, `//`, `..`, `/` în faţă), deci
            # două nume diferite nu pot ajunge la aceeaşi cale; rămâne aliasul doar de majuscule (pe un
            # filesystem insensibil la majuscule ar fi acelaşi fişier). Numele legitime nu se ciocnesc
            # (sid-uri hex mici, nume fixe), deci refuzul nu atinge arhivele reale.
            folded = name.casefold()
            if folded in self._folded:
                raise wts.SnapshotError("duplicate-member", "case alias: %s" % name[:80])
            self._folded.add(folded)
            if not _allowed(name, e.is_dir, self._profile):
                raise wts.SnapshotError("unexpected-member", name)
            if e.is_dir:
                self.dirs.add(name)
                yield name, True, 0
                continue
            if name in self._mem_only or name in self._mem_also:
                if name == "secret" and e.size != kr.KEY_LEN:
                    raise ValueError("the vault key in the backup is malformed — refused")
                if e.size > _MEM_CAP[name]:
                    raise wts.SnapshotTooLarge("member", name)
                data = self._tar.read(e.size)
                if len(data) != e.size:
                    raise wts.SnapshotError("short-member", name)
                self.mem[name] = data
                if name in self._mem_only:
                    continue
            self._cur = name
            yield name, False, e.size
            if self._cur is not None:
                raise wts.SnapshotError("member-not-consumed", name)

    def data(self):
        """Chunks of the current file member; recorded as (size, sha256) once fully read."""
        name = self._cur
        if name is None:
            raise wts.SnapshotError("no-current-member")
        h, n = hashlib.sha256(), 0
        if name in self.mem:
            b = self.mem[name]
            h.update(b)
            n = len(b)
            yield b
        else:
            while True:
                b = self._tar.read(1 << 20)
                if not b:
                    break
                h.update(b)
                n += len(b)
                yield b
        self.seen[name] = (n, h.hexdigest())
        self._cur = None


def _canon(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def _strict_json(raw: bytes, err):
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError("duplicate key")
            d[k] = v
        return d

    def no_const(_c):
        raise ValueError("constant")

    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=no_const,
                         parse_float=no_const)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise err() from None
    if _canon(doc) != raw:
        raise err()
    return doc


def _file_list(files, err) -> dict:
    if type(files) is not list:
        raise err()
    out = {}
    for e in files:
        if type(e) is not dict or set(e) != {"name", "size", "sha256"}:
            raise err()
        name, size, sha = e["name"], e["size"], e["sha256"]
        if type(name) is not str or type(size) is not int or size < 0 or type(sha) is not str \
                or not _SHA_HEX.match(sha) or name in out:
            raise err()
        out[name] = (size, sha)
    return out


def _parse_content_manifest(raw: bytes) -> dict:
    return _parse_content_doc(raw)[0]


def _parse_content_doc(raw: bytes) -> tuple:
    """(files, v2 extras | None). v1 = {format, files}; v2 (§12.11.3) adds `created`, `erasure`
    ("tracked"), `erasure_journal` (the WTJ1 member, its length, SHA-256, head, attested heads) and
    `recordings` (one entry per descriptor of the DB copy)."""
    def err():
        return wts.SnapshotError("bad-content-manifest")
    doc = _strict_json(raw, err)
    if type(doc) is not dict:
        raise err()
    if doc.get("format") == "wts-content-1" and set(doc) == {"format", "files"}:
        files = _file_list(doc["files"], err)
        if JOURNAL_MEMBER in files:
            raise err()                          # un jurnal e membru doar al unui manifest v2
        return files, None
    if doc.get("format") != "wts-content-2" or set(doc) != {"format", "files", "created", "erasure",
                                                            "erasure_journal", "recordings"}:
        raise err()
    files = _file_list(doc["files"], err)
    ej, recs = doc["erasure_journal"], doc["recordings"]
    if doc["erasure"] != "tracked" or type(doc["created"]) is not int or type(ej) is not dict \
            or set(ej) != {"member", "length", "sha256", "head", "attested"} or ej["member"] != JOURNAL_MEMBER \
            or type(ej["length"]) is not int or ej["length"] < erasure.HDR_LEN \
            or type(ej["sha256"]) is not str or not _SHA_HEX.match(ej["sha256"]) \
            or type(ej["head"]) is not dict or set(ej["head"]) != {"n", "mac"} \
            or type(ej["head"]["n"]) is not int or ej["head"]["n"] < 0 \
            or ej["length"] != erasure.prefix_len(ej["head"]["n"]) \
            or type(ej["head"]["mac"]) is not str or not _SHA_HEX.match(ej["head"]["mac"]) \
            or type(ej["attested"]) is not list or type(recs) is not list or len(recs) > MAX_MEMBERS:
        raise err()
    for a in ej["attested"]:
        if type(a) is not dict or set(a) != {"destination", "n", "time"} or type(a["destination"]) is not str \
                or not 0 < len(a["destination"]) <= 512 or type(a["n"]) is not int or a["n"] < 0 \
                or type(a["time"]) is not int:
            raise err()
    seen = set()
    for r in recs:
        if type(r) is not dict or not {"sid", "kind", "state"} <= set(r) <= {"sid", "kind", "state", "reason"} \
                or type(r["sid"]) is not str or not _SID_HEX.match(r["sid"]) or r["kind"] not in ("out", "cast") \
                or r["state"] not in _REC_STATES or (r["sid"], r["kind"]) in seen \
                or ("reason" in r and (type(r["reason"]) is not str or len(r["reason"]) > 64)):
            raise err()
        seen.add((r["sid"], r["kind"]))
    if files.get(JOURNAL_MEMBER) != (ej["length"], ej["sha256"]):
        raise err()
    return files, {k: doc[k] for k in ("created", "erasure", "erasure_journal", "recordings")}


# ---------------------------------------------------------------- writing WTS1
class _IterReader:
    """File-like over an iterator of byte chunks (tarfile.addfile reads exactly ti.size)."""

    def __init__(self, it):
        self._it = iter(it)
        self._buf = b""

    def read(self, n=-1):
        while len(self._buf) < n:
            b = next(self._it, b"")
            if not b:
                break
            self._buf += b
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


class _TarOut:
    """USTAR → gzip → WTS1 Writer with the reader's budgets enforced while writing (M2): member
    count, unpacked size, content-manifest size. Every file is hashed on exactly the bytes
    written; the manifest goes last."""

    def __init__(self, w, max_unpacked=RESTORE_MAX_UNCOMPRESSED):
        self._tar = tarfile.open(fileobj=w, mode="w|gz", format=tarfile.USTAR_FORMAT)
        self.entries: list = []
        self._count = 0
        self._size = 0
        self._max = max_unpacked

    def _info(self, name, size, is_dir=False):
        if size > USTAR_MEMBER_MAX:
            # L1: un membru USTAR are < 8 GiB (member_preflight o spune înainte, cu numele fişierului)
            raise wts.SnapshotTooLarge("member-too-large", name[:80])
        ti = tarfile.TarInfo(name)
        ti.size, ti.mtime = size, int(time.time())
        ti.mode = 0o700 if is_dir else 0o600
        if is_dir:
            ti.type = tarfile.DIRTYPE
        ti.tobuf(tarfile.USTAR_FORMAT, "utf-8", "strict")   # nume nereprezentabil → ValueError, nimic scris
        return ti

    def _budget(self, size):
        self._count += 1
        self._size += 512 + size + (-size) % 512
        if self._count > MAX_MEMBERS:
            raise wts.SnapshotTooLarge("too-many-members")
        if self._size + 1024 + tarfile.RECORDSIZE > self._max:
            raise wts.SnapshotTooLarge("unpacked-budget")

    def add_dir(self, name):
        ti = self._info(name, 0, True)
        self._budget(0)
        self._tar.addfile(ti)

    def add_stream(self, name, size, chunks):
        ti = self._info(name, size)
        self._budget(size)
        h = hashlib.sha256()

        def hashed():
            for b in chunks:
                h.update(b)
                yield b
        gen = hashed()
        self._tar.addfile(ti, _IterReader(gen))
        # sursa trebuie să se termine exact la `size` (şi generatorul să ajungă la capăt: acolo
        # îşi înregistrează extractorul strict hashul membrului)
        if any(gen):
            raise OSError("more data than declared for %s" % name[:80])
        self.entries.append({"name": name, "size": size, "sha256": h.hexdigest()})

    def add_bytes(self, name, data):
        self.add_stream(name, len(data), [data])

    def finish(self, extra=None):
        doc = {"format": "wts-content-1", "files": self.entries}
        if extra is not None:
            doc = dict(extra, format="wts-content-2", files=self.entries)
        man = _canon(doc)
        if len(man) > CONTENT_MANIFEST_MAX:
            raise wts.SnapshotTooLarge("manifest")
        ti = self._info(CONTENT_MANIFEST, len(man))
        self._budget(len(man))
        self._tar.addfile(ti, io.BytesIO(man))
        self._tar.close()


def _file_chunks(f, size):
    left = size
    while left > 0:
        b = f.read(min(left, 1 << 20))
        if not b:
            raise OSError("file shrank while archived")
        left -= len(b)
        yield b


def _forbidden_inodes(signing: bool = True):
    """(dev, ino) of every key file and of DATA_DIR itself: never archived under another name
    (H3: a hardlink, a symlinked root, a bind mount of the key into transcripts/). `signing=False`
    leaves out the signing key files themselves (R-H2: the set their own reads are checked against)."""
    out = set()
    names = (keystore.LEGACY_SECRET, keystore.VOLUME_KEY, keystore.VOLUME_KEY_TMP, KEYS_NAME,
             keystore.MANIFEST_TMP, keystore.MIGRATION_MARKER, "webterm.db", keystore.LOCK_NAME,
             keystore.MAINT_LOCK_NAME,
             "webterm.db-wal", "webterm.db-shm") + (_SIGNING if signing else ())
    paths = [config.DATA_DIR / n for n in names] + [config.DATA_DIR]
    for p in (os.environ.get(keystore.ENV_KEY_FILE), keystore.DEFAULT_KEY_FILE):
        if p:
            paths.append(p)
    for p in paths:
        for follow in (False, True):
            try:
                st = os.stat(str(p), follow_symlinks=follow)
                out.add((st.st_dev, st.st_ino))
            except OSError:
                pass
    return out


_DIR_RO = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_RO = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _add_transcripts(t: _TarOut, td: str) -> None:
    """H3: `transcripts/` opened without following a symlink and walked through directory fds;
    only regular, single-link files with a recording name, never a key file's inode."""
    forbidden = _forbidden_inodes()
    try:
        root = os.open(str(config.TRANSCRIPT_DIR), _DIR_RO)
    except FileNotFoundError:
        return
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError("the transcripts directory is not a plain directory (symlink?) — refused") from None
        raise
    try:
        st = os.fstat(root)
        if (st.st_dev, st.st_ino) in forbidden:
            raise ValueError("the transcripts directory is the data directory — refused")
        t.add_dir("transcripts")
        _walk_transcripts(t, root, "transcripts", 0, forbidden, td)
    finally:
        os.close(root)


def _walk_transcripts(t, dfd, rel, depth, forbidden, td):
    for n in sorted(os.listdir(dfd)):
        try:
            st = os.stat(n, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(st.st_mode):
            if depth == 0 and n == _TX_ARCHIVE and (st.st_dev, st.st_ino) not in forbidden:
                cfd = os.open(n, _DIR_RO, dir_fd=dfd)
                try:
                    cst = os.fstat(cfd)
                    if (cst.st_dev, cst.st_ino) == (st.st_dev, st.st_ino):
                        t.add_dir(rel + "/" + n)
                        _walk_transcripts(t, cfd, rel + "/" + n, 1, forbidden, td)
                finally:
                    os.close(cfd)
            else:
                log.warning("directory skipped from the backup: %s/%s", rel, n[:80])
            continue
        if not _TX_FILE.match(n) or keystore.is_reserved_name(n, "transcripts"):
            if not n.endswith(".cap-tmp"):
                log.warning("file skipped from the backup (not a recording): %s/%s", rel, n[:80])
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (st.st_dev, st.st_ino) in forbidden:
            log.warning("transcript skipped from the backup (link or key alias): %s/%s", rel, n[:80])
            continue
        try:
            fd = os.open(n, _FILE_RO, dir_fd=dfd)
        except OSError as e:
            log.warning("transcript skipped from the backup (%s): %s", n[:80], e)
            continue
        with os.fdopen(fd, "rb") as f:
            fst = os.fstat(f.fileno())
            if ((fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(fst.st_mode)
                    or fst.st_nlink != 1):
                log.warning("transcript skipped from the backup (changed while read): %s", n[:80])
                continue
            # copie (cel mult mărimea de la stat) într-un temp privat: antetul tar şi hashul
            # descriu exact aceiaşi octeţi chiar dacă transcriptul se schimbă între timp
            with tempfile.TemporaryFile(dir=td) as spool:
                left, size = fst.st_size, 0
                while left > 0:
                    b = f.read(min(left, 1 << 20))
                    if not b:
                        break
                    spool.write(b)
                    size += len(b)
                    left -= len(b)
                spool.seek(0)
                t.add_stream(rel + "/" + n, size, _file_chunks(spool, size))


def _read_signing(name: str, forbidden):
    """R-H2: the fleet signing key file read through ONE O_NOFOLLOW fd, checked on that fd:
    regular, single link, small, and not the inode of a key file, the DB, `.lock` or the external
    MK file. None when absent. A hardlink or alias is refused (the backup fails), never archived."""
    try:
        fd = os.open(str(config.DATA_DIR / name), _FILE_RO)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ValueError("%s is a symlink — refused" % name) from None
        raise
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > SIGNING_MAX:
            raise ValueError("%s is not a small regular file — refused" % name)
        if st.st_nlink != 1 or (st.st_dev, st.st_ino) in forbidden:
            raise ValueError("%s is a hard link or an alias of another file (key material?) — refused" % name)
        b = f.read(SIGNING_MAX + 1)
    if len(b) > SIGNING_MAX:
        raise ValueError("%s too large — refused" % name)
    return b


def _check_signing_pair(key, pub) -> None:
    """R-H2/R-M1: the fleet signing key is a PAIR — both files or neither. The private key is a
    PKCS8 PEM (signing.py); unencrypted it must be Ed25519 and its public key must be `pub`
    (64 lowercase hex). An encrypted PEM can only be checked for form (no passphrase here)."""
    if key is None and pub is None:
        return
    if key is None or pub is None:
        raise ValueError("the fleet signing key is incomplete (agent-signing.key and agent-signing.pub "
                         "go together) — refused")
    if not _PUB_HEX.match(pub):
        raise ValueError("agent-signing.pub is not an Ed25519 public key — refused")
    try:
        priv = serialization.load_pem_private_key(key, password=None)
    except TypeError:
        if not key.lstrip().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
            raise ValueError("agent-signing.key is not a PKCS8 PEM key — refused") from None
        return                                   # criptată la repaus: doar forma, perechea nu
    except Exception:                            # noqa: BLE001
        raise ValueError("agent-signing.key is not a PKCS8 PEM key — refused") from None
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("agent-signing.key is not an Ed25519 key — refused")
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not hmac.compare_digest(raw.hex().encode(), pub.strip()):
        raise ValueError("agent-signing.key and agent-signing.pub are not a pair — refused")


def _signing_pair_live():
    """The live pair, read and checked (export side)."""
    forbidden = _forbidden_inodes(signing=False)
    key = _read_signing(_SIGNING[0], forbidden)
    pub = _read_signing(_SIGNING[1], forbidden)
    _check_signing_pair(key, pub)
    return {n: b for n, b in zip(_SIGNING, (key, pub)) if b is not None}


def _check_staged_signing(td: str) -> None:
    """Import side: the extracted (fresh, private) signing files must form a valid pair."""
    got = []
    for n in _SIGNING:
        try:
            got.append(_read_small(os.path.join(td, n), SIGNING_MAX))
        except FileNotFoundError:
            got.append(None)
    _check_signing_pair(*got)


def _limits(host: bool) -> tuple:
    """(max WTS1 plaintext, max unpacked tar) of a writer: the restore route's budgets for what
    goes through memory (download / upload), none on the host path (streamed to a file)."""
    return (HOST_MAX, HOST_MAX) if host else (wts.MAX_PLAINTEXT, RESTORE_MAX_UNCOMPRESSED)


def _write_wts(out, hk: HostKeys, keys_blob: bytes, include_transcripts: bool, local: bool,
               portable: bool, safety: bool = False, cancel=None, host: bool = False) -> None:
    """Streams a WTS1 container to `out`: tar.gz {webterm.db (VACUUM INTO), keys.wtk, fleet
    signing key, [transcripts], wts-manifest.json (last)}. Never `secret`, never the MK.
    `host`: no fixed size budget (a file on disk, read back with its own size as the budget)."""
    ring = hk.ring
    max_pt, max_un = _limits(host)
    signing = _signing_pair_live()              # R-H2: înainte de writer — un refuz nu lasă nimic
    if txstore.enabled():
        # PR6c (§12.11.3): copia DB-ului, înregistrările WTX1 şi textul clar al migrării printr-un
        # SINGUR snapshot (bariera Store-ului viu, sau lacătul de boot fără el)
        _write_wts_tx(out, hk, keys_blob, include_transcripts, local, portable, safety, signing, cancel, host)
        return
    # flag oprit: exact calea PR5 (boot-ul a refuzat deja un volum cu artefacte criptate)
    w = wts.Writer(out, installation_id=ring.installation_id, epoch=ring.epoch, mk_id=ring.mk_id,
                   snk=ring.snk if local else None, mk=hk.mk if portable else None, max_plaintext=max_pt)
    with work_dir() as td:
        dbcopy = os.path.join(td, "webterm.db")
        reserve_space(td, db_size(), "the database copy of the backup")
        con = sqlite3.connect(str(config.DB_PATH))
        try:
            con.execute("VACUUM INTO ?", (dbcopy,))
        finally:
            con.close()
        # PR6c/M4: un volum cu înregistrări criptate (sau jurnalul lor) nu se arhivează pe calea 3.7 —
        # ar pierde generaţiile şi jurnalul în tăcere (ex. un container `hostops` fără flag). Aceeaşi
        # decizie ca boot-ul flag-off (txhub.boot): ORICE intrare a inventarului comun, inclusiv
        # fişiere WTX fără rânduri în registru (orfane), raportate separat.
        found = txstore.inventory(config.DATA_DIR, dbcopy)
        if found:
            files = [f for f in found if f.startswith("transcripts:")]
            if files and len(files) == len(found):
                raise ValueError("this volume holds encrypted-recording files without ledger rows (orphans: %s); "
                                 "the gateway refuses to boot on it too — back it up with %s=1 — refused"
                                 % (files[0][:80], txstore.ENV_FLAG))
            raise ValueError("this volume holds encrypted recordings (%s); back it up with %s=1 — refused"
                             % (found[0][:80], txstore.ENV_FLAG))
        t = _TarOut(w, max_un)
        size = os.path.getsize(dbcopy)
        with open(dbcopy, "rb") as f:
            t.add_stream("webterm.db", size, _file_chunks(f, size))
        t.add_bytes(KEYS_NAME, keys_blob)
        for name, b in signing.items():
            t.add_bytes(name, b)
        if include_transcripts:
            _add_transcripts(t, td)
        t.finish()
    w.close()


class SnapshotBusy(ValueError):
    """The recording snapshot could not be taken now (another backup in flight, the barrier or a
    budget ran out, cancelled): nothing was written (`backup.busy`)."""


def _write_wts_tx(out, hk: HostKeys, keys_blob: bytes, include_transcripts: bool, local: bool,
                  portable: bool, safety: bool, signing: dict, cancel=None, host: bool = False) -> None:
    """§12.11.3 with encrypted recordings on: `txstore.backup_snapshot()` (VACUUM INTO + pins
    under the barrier), then per recording pair a verify pass and an emit pass. A pair that fails
    authentication is excluded as a unit (listed with its reason, alarm, the backup goes on); a
    pair whose bytes change between the passes abandons the container, which is rebuilt ONCE
    (new Writer = new content key) without it; a second change fails the backup. `out` must be
    seekable (a temp file or the export buffer)."""
    ring = hk.ring
    max_pt, max_un = _limits(host)
    dropped = {}
    for attempt in (0, 1):
        with work_dir() as td:
            dbcopy = os.path.join(td, "webterm.db")
            reserve_space(td, db_size(), "the database copy of the backup")
            try:
                snap = txstore.backup_snapshot(dbcopy, kwk=ring.kwk, inst=ring.installation_id,
                                               recordings=include_transcripts, cancel=cancel)
            except txstore.BackupBusy as e:
                raise SnapshotBusy("the backup could not take its snapshot now (%s) — try again in a "
                                   "moment" % e.detail) from None
            try:
                w = wts.Writer(out, installation_id=ring.installation_id, epoch=ring.epoch, mk_id=ring.mk_id,
                               snk=ring.snk if local else None, mk=hk.mk if portable else None,
                               max_plaintext=max_pt)
                t = _TarOut(w, max_un)
                size = os.path.getsize(dbcopy)
                with open(dbcopy, "rb") as f:
                    t.add_stream("webterm.db", size, _file_chunks(f, size))
                t.add_bytes(KEYS_NAME, keys_blob)
                for name, b in signing.items():
                    t.add_bytes(name, b)
                extra = _erasure_member(t, dbcopy, ring, include_transcripts, safety, snap=snap,
                                        dropped=dropped)
                if extra is None:
                    if include_transcripts:
                        # fără jurnal (copie de siguranţă de diagnostic, set de date neurmărit): v1,
                        # doar textul clar 3.7 — o generaţie WTX1 nu are voie într-un manifest v1
                        _add_transcripts(t, td)
                    t.finish()
                else:
                    t.finish(extra)
                w.close()
                return
            except txstore.BackupChanged as e:
                snap.alarm("transcript.backupExcluded", "%s: changed while it was copied" % e.sid)
                if attempt:
                    raise ValueError("a recording changed while it was copied, twice — backup refused") from None
                log.warning("backup: recording %s changed while copied; rebuilding the archive without it",
                            e.sid[:8])
                dropped[e.sid] = "changed-while-copied"
                out.seek(0)
                out.truncate()
            except txstore.BackupBusy as e:
                raise SnapshotBusy("the backup snapshot was stopped (%s) — nothing was written" % e.detail) from None
            finally:
                snap.release()


def _erasure_member(t, dbcopy: str, ring, include_transcripts: bool, safety: bool = False, snap=None,
                    dropped=None):
    """§12.11.3: the erasure journal cut at the DB copy's committed head, the recordings of the
    snapshot (verified, emitted or excluded) and the v2 manifest fields. None = this dataset never
    had a journal (the manifest stays v1). A journal that does not match the DB fails the whole
    backup (journal error ≠ corruption, step 4)."""
    try:
        m = erasure.backup_member(dbcopy, config.DATA_DIR, ring.kwk, ring.installation_id)
    except erasure.JournalError as e:
        if safety:
            # copia de siguranţă dinaintea unui restore: volumul înlocuit are jurnalul pierdut /
            # stricat (exact cazul pe care restore-ul îl repară). Copia rămâne, fără jurnal (v1);
            # restaurată, staging-ul ei o refuză (DB cu ştergeri, fără jurnal) — e o copie de diagnostic
            log.warning("pre-restore safety copy WITHOUT the erasure journal (%s)", e.reason)
            return None
        raise ValueError("the erasure journal cannot be backed up (%s) — backup refused" % e.reason) from None
    if m is None and not safety:
        # fără jurnal şi fără cap: un set de date care n-a avut niciodată ştergeri urmărite. Dacă
        # inventarul comun găseşte totuşi înregistrări criptate, jurnalul s-a pierdut → refuz
        found = txstore.inventory(config.DATA_DIR, dbcopy)
        if found:
            raise ValueError("encrypted recordings without their erasure journal (%s) — backup refused"
                             % found[0][:80])
        return None
    if m is None:
        return None
    t.add_bytes(JOURNAL_MEMBER, m["bytes"])
    recs = _emit_recordings(t, snap, dropped or {}) if snap is not None else []
    head = m["head"]
    return {"created": int(time.time()), "erasure": "tracked", "recordings": recs,
            "erasure_journal": {"member": JOURNAL_MEMBER, "length": len(m["bytes"]),
                                "sha256": hashlib.sha256(m["bytes"]).hexdigest(),
                                "head": {"n": head.n, "mac": head.mac.hex()},
                                "attested": m["attested"]}}


def _emit_recordings(t, snap, dropped: dict) -> list:
    """The manifest's `recordings` (§12.11.3): every descriptor of the copy (+ `one-kind` for the
    kind a sid never had), and, with recordings requested, each pair verified then emitted as
    `transcripts/<sid>.<k>.<gen>.wtx` (exactly phys_len bytes), or excluded as a unit with its
    reason and an alarm (owner Q3); the migration's plaintext copied from the file whose identity
    the copied row names (`legacy`), or excluded when it changed. `.idx` is never archived."""
    recs = [{"sid": sid, "kind": kind, "state": state, **({"reason": why} if why else {})}
            for sid, kind, state, why in snap.listing]
    if snap.pairs or snap.legacy:
        t.add_dir("transcripts")
    for p in snap.pairs:
        why = dropped.get(p.sid) or snap.verify_pair(p)
        if why:
            if why != "absent":
                # `absent` = restaurat fără generaţii (deja „nu e în acest backup"): nu e o alarmă nouă
                snap.alarm("transcript.backupExcluded", "%s: %s" % (p.sid, why))
            log.warning("backup: recording %s excluded (%s)", p.sid[:8], why)
            recs.extend({"sid": p.sid, "kind": k, "state": "excluded", "reason": why[:64]} for k in p.kinds)
            continue
        for bg in p.gens:
            t.add_stream("transcripts/" + txstore.gen_name(p.sid, bg.kind, bg.g.gen_id.hex()),
                         bg.g.phys_len, snap.gen_chunks(p, bg))
        recs.extend({"sid": p.sid, "kind": k, "state": "included"} for k in p.kinds)
    if any(lg.dirn == "arhiva" for lg in snap.legacy):
        t.add_dir("transcripts/" + _TX_ARCHIVE)
    for lg in snap.legacy:
        fd = snap.legacy_open(lg)
        if fd is None:
            snap.alarm("transcript.backupExcluded", "%s.%s: plaintext changed since its inventory" % (lg.sid, lg.kind))
            recs.append({"sid": lg.sid, "kind": lg.kind, "state": "excluded", "reason": "legacy-changed"})
            continue
        try:
            rel = "transcripts/" + (_TX_ARCHIVE + "/" if lg.dirn == "arhiva" else "") + lg.name
            t.add_stream(rel, lg.ident[2], snap.legacy_chunks(fd, lg.ident[2]))
        finally:
            os.close(fd)
        recs.append({"sid": lg.sid, "kind": lg.kind, "state": "legacy"})
    return recs


def _wts_to_file(path, hk, keys_blob, include_transcripts, local=True, portable=False,
                 exclusive: bool = False, safety: bool = False) -> None:
    """Writes a WTS1 file all-or-nothing (tmp in the same dir, fsync, read back and verified as
    restorable, replace, dir fsync). A failed attempt leaves no file; a retry is a new Writer
    (new CK). `exclusive` (R-L1): published with link(2), which never replaces an existing file."""
    path = str(path)
    tmp = path + TMP_SUFFIX
    try:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as f:
            _write_wts(f, hk, keys_blob, include_transcripts, local, portable, safety, host=True)
            f.flush()
            _fsync(f.fileno())
        # M2: succes doar pentru o arhivă pe care restore-ul o acceptă (bugete, manifest, keyring);
        # bugetul citirii = mărimea fişierului scris (fără plafonul fix de 2 GiB al încărcărilor)
        with open(os.open(tmp, _FILE_RO), "rb") as f:
            _verify_wts(f, hk, None, prefer="local" if local else "portable", **_file_budget(f))
        if exclusive:
            os.link(tmp, path)
            os.unlink(tmp)
        else:
            os.replace(tmp, path)
        _fsync_dir(os.path.dirname(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _fsync_dir(d) -> None:
    fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _fsync(fd)
    finally:
        os.close(fd)


class _ExportBuf(io.BytesIO):
    """R-M2: the in-memory WTS1 of a download / remote upload, capped so that its WTBK1 fits the
    restore route's upload limit (UPLOAD_MAX): a bigger export is refused while it is produced
    (`backup.limitExceeded`), never handed out as a file no route can restore."""

    def write(self, b):
        if self.tell() + len(b) + _WTBK_OVERHEAD > UPLOAD_MAX:
            raise wts.SnapshotTooLarge("export", "larger than the %d MiB restore upload limit; keep it as a "
                                       "stored snapshot or leave transcripts out" % (UPLOAD_MAX >> 20))
        return super().write(b)


def spool_live_snapshot(f, include_transcripts: bool, cancel=None, keys=None) -> None:
    """Control socket (§12.11.3, `hostops backup --live`): the WTS1 of the in-app download (local +
    portable envelopes) written into the gateway's private spool `f`, through the same snapshot
    (barrier, pins, verify and emit passes), then fsynced. No fixed size cap: hostops wraps it in
    the streamed WTBK2 layer, which restore.sh reads in bounded memory (the socket checked the
    spool's free space before it started)."""
    if not is_protected():
        raise ValueError("the live backup socket serves protected volumes only")
    hk, blob = _host(keys)
    member_preflight(include_transcripts)
    _write_wts(metered(f, "the backup spool"), hk, blob, include_transcripts, local=True, portable=True,
               cancel=cancel, host=True)
    f.flush()
    _fsync(f.fileno())


def _file_budget(f) -> dict:
    """Reader budgets of a WTS1 file we wrote ourselves and only hash (nothing extracted but the
    database): its plaintext is at most its size; the unpacked size has no fixed cap (the
    gunzip's ratio cap still stops a bomb)."""
    return {"max_plaintext": os.fstat(f.fileno()).st_size, "max_unpacked": HOST_MAX}


def verify_spool(f, keys=None) -> tuple:
    """The full archive check of a spooled WTS1 (portable route, database included) BEFORE anything
    of it is offered; → (size, SHA-256 hex) of exactly the verified bytes, and the exact unpacked
    size of its tar stream (the WTBK2 header declares it)."""
    hk, _ = _host(keys)
    f.seek(0)
    info, _inner = _verify_wts(f, hk, None, prefer="portable", **_file_budget(f))
    f.seek(0)
    h = hashlib.sha256()
    size = 0
    for b in iter(lambda: f.read(1 << 20), b""):
        h.update(b)
        size += len(b)
    return size, h.hexdigest(), info["unpacked_len"]


def free_bytes(path) -> int:
    """Bytes an unprivileged writer may still use on the filesystem holding `path`."""
    st = os.statvfs(str(path))
    return st.f_bavail * st.f_frsize


# ── bugetul de disc al operaţiilor host (Codex M2, §12.10.1 "Size budget") ──────────────────────
# Volumul de date e acelaşi sistem de fişiere pe care rulează gateway-ul (şi, în producţie, restul
# maşinii): o copie de lucru care îl umple până la ultimul octet lasă gateway-ul fără loc pentru
# DB-ul viu şi jurnale. Operaţiile host (backup, spool-ul socket-ului, verify, stage) lasă deci
# liber cel puţin max(1 GiB, 5 % din sistemul de fişiere) şi se opresc — curăţând după ele — când
# ar trece pragul, nu doar la verificarea de dinainte (o estimare poate greşi, un alt proces scrie).
HEADROOM_MIN = 1 << 30
HEADROOM_DIV = 20                  # 5 %
BUDGET_STEP = 8 << 20              # cât scriem între două citiri ale spaţiului liber
_BUDGET = contextvars.ContextVar("wt_host_write_budget", default=None)


class NoSpace(OSError):
    """A host operation would leave less than its reserve free (ENOSPC before the disk is full)."""

    def __init__(self, free: int, need: int, what: str):
        self.free, self.need, self.what = free, need, what
        super().__init__(errno.ENOSPC, "%s needs %d MiB more than the %d MiB free while keeping the "
                         "reserve for the gateway — stopped and cleaned up" % (what, max(0, need - free) >> 20, free >> 20))

    def __str__(self):
        return self.strerror


def headroom(path) -> int:
    """The free space a host operation leaves on the filesystem holding `path`:
    max(HEADROOM_MIN, 1/HEADROOM_DIV of its size)."""
    st = os.statvfs(str(path))
    return max(HEADROOM_MIN, st.f_blocks * st.f_frsize // HEADROOM_DIV)


@contextmanager
def write_budget(reserve: int):
    """Every file the backup code writes in this context (the work copy, the spool, the files a
    verification or a staging extracts, the reservation before a VACUUM INTO) is metered: it
    stops with NoSpace once fewer than `reserve` bytes would stay free on its filesystem.
    Per thread / task (a ContextVar): a gateway backup on another thread is not affected."""
    tok = _BUDGET.set(int(reserve))
    try:
        yield
    finally:
        _BUDGET.reset(tok)


def reserve_space(path, n: int, what: str) -> None:
    """Before a write we cannot meter (sqlite's VACUUM INTO): `n` bytes must fit above the reserve."""
    keep = _BUDGET.get()
    if keep is None:
        return
    free = free_bytes(path)
    if free - n < keep:
        raise NoSpace(free, n + keep, what)


class _Budgeted:
    """A file proxy for write_budget: statvfs every BUDGET_STEP bytes, before writing past it."""

    def __init__(self, f, keep: int, what: str):
        self._f, self._keep, self._what = f, keep, what
        self._since = None

    def write(self, b):
        n = len(b)
        if self._since is None or self._since + n > BUDGET_STEP:
            st = os.fstatvfs(self._f.fileno())
            free = st.f_bavail * st.f_frsize
            # până la următoarea citire se pot scrie încă BUDGET_STEP octeţi: îi socotim de acum
            if free - n - BUDGET_STEP < self._keep:
                raise NoSpace(free, n + BUDGET_STEP + self._keep, self._what)
            self._since = 0
        self._since += n
        return self._f.write(b)

    def __getattr__(self, name):
        return getattr(self._f, name)


def metered(f, what: str):
    """`f` under the active write_budget (unchanged when there is none)."""
    keep = _BUDGET.get()
    return f if keep is None else _Budgeted(f, keep, what)


def db_size() -> int:
    """The live database and its WAL: the size of a VACUUM INTO copy, or of the database a
    verification extracts, is at most this."""
    n = 0
    for p in (config.DB_PATH, config.DATA_DIR / "webterm.db-wal"):
        with contextlib.suppress(OSError):
            n += os.lstat(str(p)).st_size
    return n


def host_work_need() -> int:
    """Bytes `hostops backup` (or the socket's spool) writes on the data volume besides its
    reserve: the work copy (host_estimate) plus the DB copy taken for the snapshot / extracted to
    verify it (one at a time, each ≤ db_size)."""
    return host_estimate() + db_size()


def restore_space_need(unpacked_len: int) -> int:
    """Bytes a protected restore of an archive whose tar stream is `unpacked_len` needs on the
    data volume, by phase, for its peak: the staged set (≤ unpacked_len), then at the next boot
    the copy the apply makes of it (≤ unpacked_len) while the staged set, the live data AND the
    pre-restore safety copy of the live data (≤ host_estimate) exist, the safety copy's
    verification scratch (≤ db_size) included. The caller adds the reserve."""
    return 2 * unpacked_len + host_estimate() + db_size()


# Limita USTAR a unui membru: câmpul de mărime are 11 cifre octale (< 8 GiB); tarfile refuză abia
# la antetul membrului, după gigaocteţi scrişi — o verificăm înainte de a scrie ceva (Codex L1)
USTAR_MEMBER_MAX = 8 ** 11 - 1


def member_preflight(include_transcripts: bool = True) -> None:
    """Refuses early, with the file named, a volume one of whose backup members would not fit a
    USTAR header (≥ 8 GiB): the database (+ WAL, an upper bound of its VACUUM copy) and, with
    transcripts, every regular file under transcripts/."""
    if db_size() > USTAR_MEMBER_MAX:
        raise ValueError("the database is %d MiB; a single file of a backup is limited to 8 GiB (USTAR) "
                         "— refused before anything was written. VACUUM the database or prune old data"
                         % (db_size() >> 20))
    if not include_transcripts:
        return
    for dp, _dn, fn in os.walk(str(config.TRANSCRIPT_DIR)):
        for name in fn:
            with contextlib.suppress(OSError):
                st = os.lstat(os.path.join(dp, name))
                if stat.S_ISREG(st.st_mode) and st.st_size > USTAR_MEMBER_MAX:
                    raise ValueError("the recording %s is %d MiB; a single file of a backup is limited to 8 GiB "
                                     "(USTAR) — refused before anything was written"
                                     % (name[:80], st.st_size >> 20))


def host_estimate() -> int:
    """Upper bound of a host backup (uncompressed): the database (+ its WAL) and every regular file
    under transcripts/ (symlinks not followed), plus the tar overhead and a margin. backup.sh
    compares it with the free space of the backup directory, hostops with the volume's."""
    n = 0
    for p in (config.DB_PATH, config.DATA_DIR / "webterm.db-wal"):
        with contextlib.suppress(OSError):
            n += os.lstat(str(p)).st_size
    files = 0
    for dp, _dn, fn in os.walk(str(config.TRANSCRIPT_DIR)):
        for name in fn:
            with contextlib.suppress(OSError):
                st = os.lstat(os.path.join(dp, name))
                if stat.S_ISREG(st.st_mode):
                    n += st.st_size
                    files += 1
    return n + 1024 * (files + 8) + n // 100 + (16 << 20)


def write_host_snapshot(f, include_transcripts: bool, keys=None) -> None:
    """`hostops backup` without the control socket: the portable WTS1 (local + portable
    envelopes, like a download) streamed into `f`, a private file in a work dir on the data
    volume, then fsynced. No fixed size cap (the host path, §12.10.1)."""
    if not is_protected():
        raise ValueError("this installation is not protected: the host archive is the 3.7 one")
    hk, blob = _host(keys)
    member_preflight(include_transcripts)
    _write_wts(metered(f, "the backup's work copy"), hk, blob, include_transcripts, local=True,
               portable=True, host=True)
    f.flush()
    _fsync(f.fileno())


def verify_host_snapshot(f, keys=None) -> tuple:
    """The restorable check of a host WTS1 file through the portable route (the one restore.sh
    uses on another installation), before hostops wraps it: → (size, exact unpacked size), the
    two lengths the WTBK2 header declares."""
    hk, _ = _host(keys)
    f.seek(0)
    info, _inner = _verify_wts(f, hk, None, prefer="portable", **_file_budget(f))
    return os.fstat(f.fileno()).st_size, info["unpacked_len"]


def verify_host_stream(src, keys=None, *, max_plaintext: int, unpacked_len: int) -> dict:
    """`hostops verify` of a WTBK2: the WTS1 read from `src` (the authenticated WTBK2 plaintext)
    through the restorable check — every byte authenticated and hashed, the strict tar and the
    content manifest, the inner keys.wtk, the database extracted alone into a work dir and
    checked — in bounded memory; the unpacked size must be exactly the declared one."""
    hk, _ = _host(keys)
    info, _inner = _verify_wts(src, hk, None, max_plaintext=max_plaintext, max_unpacked=unpacked_len,
                               expect_unpacked=unpacked_len)
    info.pop("_content", None)
    return info


def stage_host_stream(src, keys=None, *, max_plaintext: int, unpacked_len: int, progress=None) -> dict:
    """`hostops stage-restore` of a WTBK2: stage_restore's protected route over a stream. The WTS1
    is extracted into the private `.restore-verify-*` directory on the volume as it is read;
    nothing is published before the last byte (WTS1 final frame, WTBK2 last chunk, end of input
    and whatever the source checks there) is proven and the unpacked size equals the declared."""
    progress = progress if progress is not None else StageProgress()
    _invalidate_kind()
    restore_route(wts.MAGIC, is_protected(), False)          # RC-M1: un WTS1 doar pe un volum protejat
    return _stage_wts(src, keys, None, "local", progress, None,
                      budget={"max_plaintext": max_plaintext, "max_unpacked": unpacked_len,
                              "expect_unpacked": unpacked_len})


def make_portable_bytes(include_transcripts: bool = False, keys=None) -> bytes:
    """A portable WTS1 (local + portable envelopes) in memory — the input of the WTBK1
    passphrase layer for downloads and remote uploads (that layer is single-shot AES-GCM, a
    known full-buffer path, §12.10). Verified through the portable route before it is returned."""
    hk, blob = _host(keys)
    buf = _ExportBuf()
    _write_wts(buf, hk, blob, include_transcripts, local=True, portable=True)
    _verify_wts(io.BytesIO(buf.getvalue()), hk, None, prefer="portable")
    return buf.getvalue()


# ---------------------------------------------------------------- reading WTS1
def _unlock(reader, hk: HostKeys, mk=None, prefer: str = "local") -> None:
    """M4: the local envelope with this host's SNK (same installation), or the portable one with
    the operator's `mk` or the host MK when the header names it. `prefer="portable"` tries the
    portable envelope first; a local envelope under another SNK (a recovered installation)
    falls through to the portable one instead of failing."""
    if prefer not in ("local", "portable"):
        raise ValueError("invalid envelope preference")

    def local():
        if reader.local and reader.installation_id == hk.ring.installation_id:
            reader.unlock(snk=hk.ring.snk, installation_id=hk.ring.installation_id)
            return True
        return False

    def portable():
        for cand in (mk, hk.mk):
            if cand is not None and reader.portable and kr.key_id(cand) == reader.mk_id:
                reader.unlock(mk=cand)
                return True
        return False

    for route in ((local, portable) if prefer == "local" else (portable, local)):
        try:
            if route():
                return
        except wts.SnapshotWrongKey:
            continue
    raise wts.SnapshotWrongKey("needs-mk", "the backup needs master key " + reader.mk_id.hex(),
                               mk_id=reader.mk_id)


def _unpack_verified(reader, dest, db_dest=None, max_unpacked=RESTORE_MAX_UNCOMPRESSED,
                     placeholder=None) -> tuple:
    """Streams the authenticated tar.gz through the strict extractor into `dest` (a fresh
    private dir; None = hash only, except `webterm.db` into `db_dest` when given — R-M2's
    restorable check of a produced container), then the gzip and WTS1 streams to their
    authenticated end; the extracted set must equal the content manifest and the signing files
    must be a valid pair (R-H2). Returns (info, inner keys.wtk bytes); info["unpacked_len"] is the
    exact size of the decompressed tar stream. `placeholder(name)` True: that file member is
    hashed and checked like every other but written EMPTY (the preflight of `hostops verify`,
    whose checks read only its name — never a staged set that is published)."""
    gz = wts.BoundedGunzip(reader, max_unpacked)
    arc = _Archive(gz, "wts1", mem_only=(CONTENT_MANIFEST,), mem_also=(KEYS_NAME, *_SIGNING))
    try:
        for name, is_dir, _size in arc.entries():
            target = dest if dest is not None else (db_dest if name == "webterm.db" else None)
            if target is None:
                if not is_dir:
                    for _b in arc.data():
                        pass
                continue
            path = os.path.join(target, name)
            if is_dir:
                os.makedirs(path, mode=0o700, exist_ok=True)
                continue
            parent = os.path.dirname(name)
            if parent:
                os.makedirs(os.path.join(target, parent), mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as out:
                if placeholder is not None and placeholder(name):
                    for _b in arc.data():
                        pass
                    continue
                mo = metered(out, "extracting the archive")
                for b in arc.data():
                    mo.write(b)
        reader.finish()
    except (FileExistsError, NotADirectoryError, IsADirectoryError):
        raise wts.SnapshotError("conflicting-members") from None
    if CONTENT_MANIFEST not in arc.mem:
        raise wts.SnapshotError("no-content-manifest")
    files, extras = _parse_content_doc(arc.mem[CONTENT_MANIFEST])
    if files != arc.seen:
        raise wts.SnapshotError("content-manifest-mismatch")
    if "webterm.db" not in arc.seen or KEYS_NAME not in arc.seen:
        raise wts.SnapshotError("incomplete", "webterm.db and keys.wtk are required")
    _check_signing_pair(arc.mem.get(_SIGNING[0]), arc.mem.get(_SIGNING[1]))
    info = {"has_transcripts": bool(arc.dirs) or any(n.startswith("transcripts/") for n in arc.seen),
            "has_signing_key": "agent-signing.key" in arc.seen,
            "erasure": "tracked" if extras is not None else "not-tracked", "_content": extras,
            "unpacked_len": gz.out_len}
    return info, arc.mem[KEYS_NAME]


def _check_db(path: str):
    """R-M2 restorable check: SQLite integrity AND the gateway's minimal schema (the tables every
    EverShell database has), opened read-only. → MIN(users.created).
    RC4 (e2e): immutable=1, ca la proba legacyvault — o copie 3.7 făcută cu API-ul de backup SQLite
    (scripts/backup.sh) are antetul în modul WAL, iar o deschidere `mode=ro` obişnuită crea
    webterm.db-wal/-shm în setul din staging, pe care verificarea arborelui îl refuza apoi („unexpected
    file”): restaurarea copiei de dinainte de migrare era imposibilă. Setul e privat (nimeni nu scrie
    în el) şi un -wal venit din arhivă e refuzat de verificarea arborelui, deci immutable nu ascunde nimic."""
    con = sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(path, safe="/"), uri=True)
    try:
        try:
            r = con.execute("PRAGMA integrity_check").fetchone()[0]
        except sqlite3.Error:
            r = None
        if r != "ok":
            raise ValueError("the database in the backup is corrupt")
        try:
            tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.Error:
            tables = set()
        missing = [t for t in _REQUIRED_TABLES if t not in tables]
        if missing:
            raise ValueError("the database in the backup is not an EverShell database (missing tables: %s) "
                             "— refused" % ", ".join(missing))
        try:
            return con.execute("SELECT MIN(created) FROM users").fetchone()[0]
        except sqlite3.Error:
            return None
    finally:
        con.close()


def _envelopes_for(mk: bytes, r: kr.Keyring) -> tuple:
    envs = [kr.wrap_under_mk(mk, kr.KT_KWK, r.kwk)]
    if r.snk is not None:
        envs.append(kr.wrap_under_mk(mk, kr.KT_SNK, r.snk))
    for t, k in ((kr.KT_FK_LEGACY, r.fk_legacy), (kr.KT_FK, r.fk), (kr.KT_DBK, r.dbk)):
        if k is not None:
            envs.append(kr.wrap_under_kwk(r.kwk, t, k))
    return tuple(envs)


def _rewrap(src: kr.Keyring, mk: bytes, epoch: int, extra_retired=()) -> bytes:
    """`src`'s keys under `mk` (installation id of `src`); retired ids = src's ∪ its MK id ∪
    `extra_retired`, minus the new MK id."""
    new_id = kr.key_id(mk)
    retired = set(src.retired_mk_ids) | {src.mk_id} | set(extra_retired)
    retired.discard(new_id)
    if len(retired) > kr.MAN_MAX_RETIRED:
        raise ValueError("too many retired master keys — refused")
    m = kr.KeyManifest(src.installation_id, epoch, new_id, tuple(sorted(retired)), _envelopes_for(mk, src))
    return kr.encode_manifest(m, mk, kr.PROFILE_V1)


def _manifest_for_host(src: kr.Keyring, hk: HostKeys) -> bytes:
    """The keyring of a restored snapshot, re-wrapped under the host MK (the one the next boot
    will use), epoch above both the snapshot's and the host's; the snapshot's MK id (and, same
    installation, the host's old ids) stay listed as retired: backups made under them exist."""
    extra = ()
    if src.installation_id == hk.ring.installation_id:
        extra = tuple(hk.ring.retired_mk_ids) + (hk.ring.mk_id,)
    return _rewrap(src, hk.mk, max(src.epoch, hk.ring.epoch) + 1, extra)


def _open_inner(blob: bytes, reader, hk: HostKeys, mk=None) -> kr.Keyring:
    """M4: the inner keys.wtk is under the MK the header names (writers keep them equal), and
    carries the header's installation id and epoch and an SNK."""
    cand = next((c for c in (hk.mk, mk) if c is not None and kr.key_id(c) == reader.mk_id), None)
    if cand is None:
        raise wts.SnapshotWrongKey("needs-mk", "its keys.wtk needs master key " + reader.mk_id.hex(),
                                   mk_id=reader.mk_id)
    try:
        inner = kr.open_keyring_bytes(blob, cand, kr.PROFILE_V1)
    except kr.WrongKeyError:
        raise wts.SnapshotError("keyring-mismatch", "keys.wtk is not under the header's master key") from None
    except kr.KeyringError as e:
        raise wts.SnapshotError("keyring-invalid", e.reason) from None
    if (inner.installation_id != reader.installation_id or inner.epoch != reader.epoch
            or inner.mk_id != reader.mk_id or inner.snk is None):
        raise wts.SnapshotError("keyring-mismatch")
    return inner


def _verify_wts(fileobj, hk: HostKeys, dest, mk=None, prefer="local", max_plaintext=wts.MAX_PLAINTEXT,
                restorable: bool = True, max_unpacked=RESTORE_MAX_UNCOMPRESSED, expect_unpacked=None,
                placeholder=None) -> tuple:
    """Full check of a WTS1. R-M2: `restorable` (default) = structural (header MAC, envelope,
    every chunk, final frame, EOF, strict tar, content manifest, signing pair, inner keys.wtk
    bound to the header) + the database (integrity + minimal schema): extracted into `dest`, or,
    with `dest=None`, only `webterm.db` into a private temp dir. `restorable=False` with
    `dest=None` = structural only (hash, nothing written). `expect_unpacked`: the exact unpacked
    size an authenticated outer header declared (WTBK2); any other size is refused before the
    caller publishes anything. Returns (info, inner keyring)."""
    reader = wts.Reader(fileobj, max_plaintext)
    _unlock(reader, hk, mk, prefer)
    with contextlib.ExitStack() as stack:
        # DB-ul extras pentru verificare: în directorul de lucru de pe volum, nu în /tmp (tmpfs mic)
        tmp = stack.enter_context(work_dir("verify-")) if dest is None and restorable else None
        info, inner_blob = _unpack_verified(reader, dest, db_dest=tmp, max_unpacked=max_unpacked,
                                            placeholder=placeholder)
        if expect_unpacked is not None and info["unpacked_len"] != expect_unpacked:
            raise wts.SnapshotError("declared-size-mismatch", "%d unpacked, %d declared"
                                    % (info["unpacked_len"], expect_unpacked))
        inner = _open_inner(inner_blob, reader, hk, mk)
        where = dest if dest is not None else tmp
        users_since = _check_db(os.path.join(where, "webterm.db")) if where is not None else None
    info.update({"has_secret": False, "has_keyring": True, "users_since": users_since,
                 "format": "WTS1", "portable": reader.portable, "restorable": where is not None,
                 "same_installation": inner.installation_id == hk.ring.installation_id})
    return info, inner


def _transcode(src, hk: HostKeys, out, mk=None) -> None:
    """A stored local snapshot → WTS1 local + portable with a NEW content key, streamed (no
    plaintext on disk). M4: the inner keys.wtk is authenticated with the MK its header names
    (the host's, or the operator's `mk` for a snapshot made before a rotation) and re-wrapped
    under the current host MK, so the result opens with ONE MK. The source manifest must match
    before the output is closed (a bad source leaves an unclosed, discarded output)."""
    reader = wts.Reader(src)
    _unlock(reader, hk, mk)
    host_id = kr.key_id(hk.mk)
    if reader.mk_id != host_id and (mk is None or kr.key_id(mk) != reader.mk_id):
        raise wts.SnapshotWrongKey("needs-mk", "this snapshot was made under master key %s"
                                   % reader.mk_id.hex(), mk_id=reader.mk_id)
    w = wts.Writer(out, installation_id=reader.installation_id, epoch=reader.epoch, mk_id=host_id,
                   snk=hk.ring.snk, mk=hk.mk)
    t = _TarOut(w)
    gz = wts.BoundedGunzip(reader, RESTORE_MAX_UNCOMPRESSED)
    arc = _Archive(gz, "wts1", mem_only=(CONTENT_MANIFEST,), mem_also=(KEYS_NAME, *_SIGNING))
    for name, is_dir, size in arc.entries():
        if is_dir:
            t.add_dir(name)
        elif name == KEYS_NAME:
            blob = b"".join(arc.data())
            inner = _open_inner(blob, reader, hk, mk)
            t.add_bytes(KEYS_NAME, blob if inner.mk_id == host_id else _rewrap(inner, hk.mk, inner.epoch))
        else:
            t.add_stream(name, size, arc.data())
    reader.finish()
    if CONTENT_MANIFEST not in arc.mem or _parse_content_manifest(arc.mem[CONTENT_MANIFEST]) != arc.seen:
        raise wts.SnapshotError("content-manifest-mismatch")
    if KEYS_NAME not in arc.seen or "webterm.db" not in arc.seen:
        raise wts.SnapshotError("incomplete", "webterm.db and keys.wtk are required")
    _check_signing_pair(arc.mem.get(_SIGNING[0]), arc.mem.get(_SIGNING[1]))
    t.finish()
    w.close()


# ---------------------------------------------------------------- operations lock (H1, M3)
def _private_tmpdir() -> str:
    # sub backups/ (acelaşi filesystem ca restore-pending/ → rename atomic), 0700
    return tempfile.mkdtemp(prefix=VERIFY_PREFIX, dir=str(_backup_dir()))


@contextmanager
def _restore_lock():
    """One verify / stage / apply at a time (flock on backups/.restore.lock, non-blocking: a
    second attempt is refused, never queued). Under it, `.restore-verify-*` left by a crash are
    removed: every creator of such a directory holds this lock. The wiring PR may replace it
    with the boot's process lock."""
    d = _backup_dir()
    fd = os.open(str(d / STAGE_LOCK), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError(_BUSY) from None
        for p in d.glob(VERIFY_PREFIX + "*"):
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p, ignore_errors=True)
        yield
    finally:
        os.close(fd)


def _verify_wts_bytes(raw: bytes, keys=None, mk=None, prefer="local") -> dict:
    hk, _ = _host(keys)
    with _restore_lock():
        td = _private_tmpdir()
        try:
            info, _inner = _verify_wts(io.BytesIO(raw), hk, td, mk, prefer)
        finally:
            shutil.rmtree(td, ignore_errors=True)
    info.pop("_content", None)
    return info


# ---------------------------------------------------------------- staging (H1)
def _write_new(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if not n:
                raise OSError("short write")
            view = view[n:]
        _fsync(fd)
    finally:
        os.close(fd)


def _tree(root: str):
    """(files {rel: abs}, dirs {rel}) of a staging tree; anything but regular files and
    directories (a symlink, a fifo…) → refuse."""
    files, dirs = {}, set()
    for dp, dn, fn in os.walk(root):
        rel_dp = os.path.relpath(dp, root)
        for n in dn + fn:
            p = os.path.join(dp, n)
            rel = n if rel_dp == "." else rel_dp.replace(os.sep, "/") + "/" + n
            st = os.lstat(p)
            if stat.S_ISDIR(st.st_mode):
                dirs.add(rel)
            elif stat.S_ISREG(st.st_mode):
                files[rel] = p
            else:
                raise ValueError("the restore staging holds a non-regular entry — refused")
    return files, dirs


def _hash_file(p: str):
    h, n = hashlib.sha256(), 0
    with open(os.open(p, _FILE_RO), "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError("the restore staging holds a non-regular entry — refused")
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
            n += len(b)
    return n, h.hexdigest()


def _fsync_path(p: str) -> None:
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _fsync(fd)
    finally:
        os.close(fd)


def _write_flag(doc: dict) -> None:
    """The flag, atomically and durably (tmp, fsync, rename, directory fsync)."""
    _write_flag_bytes(_canon(doc))


def _write_flag_bytes(raw: bytes) -> None:
    d = config.DATA_DIR
    tmp = str(d / ".restore-flag.tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    _write_new(tmp, raw)
    _step("flag:tmp")
    os.replace(tmp, str(_restore_flag()))
    _step("flag:renamed")
    _fsync_dir(d)


_FLAG_FORMAT = "wt-restore-flag-1"
_FLAG_STATES = ("staged", "applying", "committed")


def _read_flag():
    """None (no flag), "legacy" (a 3.7 flag: a timestamp), or the 3.8 flag document."""
    try:
        raw = _read_small(_restore_flag(), FLAG_MAX)
    except FileNotFoundError:
        return None
    if raw[:1] != b"{":
        return "legacy"

    def err():
        return ValueError("the restore flag is malformed — refused")
    doc = _strict_json(raw, err)
    if (type(doc) is not dict or not {"format", "manifest", "state", "set"} <= set(doc)
            or not set(doc) <= {"format", "manifest", "state", "set", "safety", "quarantine", "erasure_proven",
                                "erasure_threshold", "erasure_known", "erasure_required", "erasure_overflow",
                                "erasure_intents", "erasure_unverified", "erasure_conflict"}
            or doc["format"] != _FLAG_FORMAT or doc["state"] not in _FLAG_STATES
            or type(doc["manifest"]) is not str or not _SHA_HEX.match(doc["manifest"])
            or type(doc["set"]) is not str or not _GEN_HEX.match(doc["set"])
            or type(doc.get("safety", "")) is not str
            or type(doc.get("erasure_proven", False)) is not bool
            or type(doc.get("erasure_overflow", False)) is not bool):
        raise err()
    # R-M1: decizia de carantină se ia o dată (la `applying`) şi se reia din flag, nu se recalculează
    if doc["state"] != "staged" and type(doc.get("quarantine")) is not bool:
        raise err()
    try:
        if "erasure_threshold" in doc:
            erasure.Head.from_json(doc["erasure_threshold"])
        if "erasure_known" in doc:
            erasure.known_from_json(doc["erasure_known"])
        if "erasure_required" in doc:
            erasure.required_from_json(doc["erasure_required"])
        if "erasure_unverified" in doc:
            erasure.known_from_json(doc["erasure_unverified"])
        if "erasure_conflict" in doc:
            erasure.conflict_from_json(doc["erasure_conflict"])
        if "erasure_intents" in doc:
            _intents_of_flag(doc["erasure_intents"])
    except (erasure.JournalError, erasure.ErasureConflict):
        raise err() from None
    return doc


def _set_dir(gen: str):
    return config.DATA_DIR / (SET_PREFIX + gen)


def _refuse_active_journal() -> None:
    """R-H1: under the operations lock, before a new set may replace the current one: a flag in
    `applying` or `committed` is a journal that only apply may finish (refused, `backup.restoreInProgress`);
    a malformed flag is refused too (never silently dropped)."""
    flag = _read_flag()
    if isinstance(flag, dict) and flag["state"] != "staged":
        raise ValueError(_IN_PROGRESS)


def _drop_unflagged_sets(keep) -> None:
    """Staging sets the flag does not name (an older generation, an interrupted stage, a 3.7-named
    `restore-pending/`): moved aside under backups/ in one rename each, then deleted. Called under
    the lock, only once the flag naming `keep` is durable (or with no 3.8 flag at all)."""
    names = [n for n in os.listdir(str(config.DATA_DIR))
             if n == "restore-pending" or (n.startswith(SET_PREFIX) and n != SET_PREFIX + (keep or ""))]
    if not names:
        return
    trash = tempfile.mkdtemp(prefix=VERIFY_PREFIX + "old-", dir=str(_backup_dir()))
    for i, n in enumerate(names):
        os.rename(str(config.DATA_DIR / n), os.path.join(trash, "set%d" % i))
    _fsync_dir(config.DATA_DIR)
    shutil.rmtree(trash, ignore_errors=True)


def _stage_publish(td: str, staged_blob: bytes, mk: bytes, progress=None, erasure_summary=None) -> None:
    """H1/R-H1: publishes a fully verified tree as ONE durable staged set. Every file and
    directory fsynced, then `restore.json` (generation, files with sizes + SHA-256, keyring
    identity), one rename to `restore-pending.<generation>`, and the flag LAST, atomically,
    naming that generation and the manifest's digest; only then the previous generation is
    removed. A crash anywhere leaves the old flag with its complete set, or the new flag with
    its complete set (never a flag without its set). An `applying`/`committed` flag is refused."""
    ring = _open_ring(staged_blob, mk, "staged keys.wtk")
    files, dirs = _tree(td)
    entries = []
    for rel in sorted(files):
        if not _allowed(rel, False) or rel == CONTENT_MANIFEST:
            raise ValueError("unexpected file in the restore staging — refused: %s" % rel[:80])
        size, sha = _hash_file(files[rel])
        entries.append({"name": rel, "size": size, "sha256": sha})
        _fsync_path(files[rel])
    for rel in sorted(dirs, key=lambda r: -r.count("/")):
        if rel not in _TX_DIRS:
            raise ValueError("unexpected directory in the restore staging — refused")
        _fsync_dir(os.path.join(td, rel))
    doc = {"format": "wt-restore-1", "generation": secrets.token_hex(16), "created": int(time.time()),
           "installation_id": ring.installation_id.hex(), "epoch": ring.epoch, "mk_id": ring.mk_id.hex(),
           "files": entries, "dirs": sorted(dirs)}
    if erasure_summary is not None:
        doc["erasure"] = erasure_summary
    raw = _canon(doc)
    if len(raw) > RESTORE_MANIFEST_MAX:
        raise wts.SnapshotTooLarge("restore-manifest")
    _write_new(os.path.join(td, RESTORE_MANIFEST), raw)
    _fsync_dir(td)
    _step("stage:manifest")
    # R-H1: setul curent rămâne flag-uit şi intact până când flagul noului set e durabil; un jurnal
    # de apply neterminat nu se înlocuieşte deloc
    _refuse_active_journal()
    gen = doc["generation"]
    progress = progress if progress is not None else StageProgress()
    progress.mutated = True                     # R-M1: prima schimbare a directorului de date
    os.rename(td, str(_set_dir(gen)))
    _fsync_dir(_backup_dir())
    _fsync_dir(config.DATA_DIR)
    _step("stage:renamed")
    _write_flag({"format": _FLAG_FORMAT, "manifest": hashlib.sha256(raw).hexdigest(), "state": "staged",
                 "set": gen})
    progress.committed = True                   # flag publicat + director fsync-uit
    _invalidate_kind()
    _step("stage:flag")
    _drop_unflagged_sets(gen)
    _step("stage:old-removed")
    log.warning("RESTORE staged — it is applied on the next restart")


def _stage_wts(fileobj, keys=None, mk=None, prefer="local", progress=None, erasure_fetch=None,
               budget=None) -> dict:
    """Protected restore of a WTS1: everything verified in a private dir BEFORE restore-pending/
    is touched; the staged keys.wtk is the snapshot's keyring re-wrapped under the host MK; the
    verified files are exactly the ones published (no second extraction)."""
    hk, _ = _host(keys)
    with _restore_lock():
        _refuse_active_journal()
        td = _private_tmpdir()
        try:
            info, inner, summary = _preflight_wts(fileobj, hk, td, mk, prefer, budget, erasure_fetch)
            staged = _manifest_for_host(inner, hk)
            kp = os.path.join(td, KEYS_NAME)
            os.unlink(kp)
            _write_new(kp, staged)
            _stage_publish(td, staged, hk.mk, progress, summary)
        except BaseException:
            shutil.rmtree(td, ignore_errors=True)
            raise
    return _missing_data_note(info)


def _preflight_wts(fileobj, hk: HostKeys, td: str, mk=None, prefer="local", budget=None, erasure_fetch=None,
                   live_root=None, placeholder=None) -> tuple:
    """Codex M1: the ONE acceptance of a WTS1 for this volume, shared by the staging and by
    `hostops verify` (preflight_wts): the full check of the container extracted into `td` (strict
    tar, content manifest, signing pair, inner keys.wtk, database), then the erasure / recording
    rules of the TARGET (§12.11.4 at stage: the flag policy, recording membership and every WTX
    generation, the journal against the manifest and the DB, the live head). `live_root`: the
    target's data dir (default config.DATA_DIR). → (info, inner keyring, erasure summary | None)."""
    info, inner = _verify_wts(fileobj, hk, td, mk, prefer, placeholder=placeholder, **(budget or {}))
    content = info.pop("_content", None)
    summary = _erasure_stage(td, content, inner, erasure_fetch, live_inst=hk.ring.installation_id,
                             live_root=live_root)
    if summary is not None:
        info["erasure"] = summary["state"]
        info["erasure_proof"] = summary["proof"]
    return info, inner, summary


def _preflight_placeholder(name: str) -> bool:
    """What the preflight does not need on disk: every file member except the database, the keys,
    the signing pair, the erasure journal and the WTX generations directly under transcripts/
    (verified in full). The 3.7 plaintext recordings are checked by name only (membership), so
    their bytes are hashed against the manifest and not written."""
    if name in _TOP_FILES:
        return False
    head, _sep, base = name.rpartition("/")
    return not (head == "transcripts" and _TX_GEN.match(base))


def preflight_wts(fileobj, keys=None, *, live_root, budget=None) -> dict:
    """`hostops verify` of a WTS1 (a WTBK2 stream, or a WTBK1's inner bytes): exactly the
    staging's acceptance (_preflight_wts) in a private scratch dir of the CURRENT data dir (the
    verify's own scratch: the target volume is only read), without staging anything. Only the
    members the checks read are written (bounded by the declared unpacked size and the active
    write budget); the scratch is removed before returning. An archive staging would refuse is
    refused here, before restore.sh stops the app."""
    hk, _ = _host(keys)
    with work_dir("preflight-") as td:
        info, _inner, _summary = _preflight_wts(fileobj, hk, td, budget=budget, live_root=live_root,
                                                placeholder=_preflight_placeholder)
    return info


def _live_journal(root=None):
    try:
        return erasure.Journal(config.DATA_DIR if root is None else root, b"", b"\0" * 16).read_bytes()
    except (erasure.JournalError, OSError):
        return None                              # necitibil = nu e J_v (deci nici dovadă)


def _erasure_stage(td: str, content, inner: kr.Keyring, fetch, live_inst=None, live_root=None):
    """§12.11.4 "Continuity at restore", at stage. Flag off: an archive with erasure state is
    refused (this build cannot honour it), anything else is the PR5 / 3.7 path (None). Flag on:
    the backup's journal checked against its manifest and its DB, every staged descriptor listed
    (absent when the backup did not carry it), the sources reconciled (divergence refused); J*
    is written into the staging. Returns the summary kept in restore.json."""
    dbp = os.path.join(td, "webterm.db")
    if not txstore.enabled():
        if content is not None or txstore.inventory(td, dbp):
            raise erasure.ErasureUnsupported("this backup holds encrypted recordings or an erasure journal; "
                                             "this build restores it only with encrypted recordings on — refused")
        return None
    k = erasure.k_erase_of(inner.kwk)
    inst = inner.installation_id
    try:
        head_db, att_b, cfg_ids = erasure.staged_state(dbp)
        # R-H1: un dataset salvat cât era în carantină îşi poartă pragul (markerul de continuitate
        # din DB-ul lui): reimportul nu-l coboară niciodată
        staged_terms = erasure.marker_terms_in(dbp)
    except erasure.JournalError:
        raise erasure.ErasureConflict("the backup's erasure state is unreadable — refused") from None
    jp = os.path.join(td, JOURNAL_MEMBER)
    jb = None
    known = {d: int(v.get("n", 0)) for d, v in att_b.items() if isinstance(v, dict)}
    if content is not None:
        jb = _read_small(jp, erasure.MAX_FILE)
        erasure.check_member(jb, content["erasure_journal"], k, inst, head_db)
        for a in content["erasure_journal"]["attested"]:
            known[a["destination"]] = max(known.get(a["destination"], 0), a["n"])
        _stage_recordings(td, dbp, content["recordings"], inner)
    elif _staged_generations(td):
        raise erasure.ErasureConflict("recording generations in an archive without a v2 manifest — refused")
    elif head_db is not None and head_db.n > 0:
        raise erasure.ErasureConflict("the backup's database records erasures but the archive has no "
                                      "erasure journal — refused")
    results, ids = fetch(k, inst) if fetch is not None else ([], [])
    # H1/M1: capul comis al DB-ului VIU (număr + MAC) şi capetele lui atestate, citite ÎNAINTE de
    # jurnalul viu (o ştergere scrie jurnalul înainte de capul din DB: jurnalul citit după nu poate
    # rămâne în urmă), sub lacătul de restore; pragul intră în rezumat şi apoi în flag
    live_db = config.DB_PATH if live_root is None else os.path.join(str(live_root), "webterm.db")
    live = erasure.live_state(live_db, live_inst, inst)
    dec = erasure.decide_restore(k_erase=k, inst=inst, j_b=jb, tracked=content is not None,
                                 j_v=_live_journal(live_root), dest_results=results,
                                 required_dests=set(cfg_ids) | set(ids), known_attested=known, live=live,
                                 staged=staged_terms)
    if dec.short:
        log.warning("restore: no source reaches the live erasure head n=%d — the restored recordings "
                    "will be quarantined", dec.threshold.n)
    if dec.journal is not None and dec.journal != jb:
        if os.path.lexists(jp):
            os.unlink(jp)
        _write_new(jp, dec.journal)
    for r in dec.rolled_back:
        log.warning("restore: erasure attestations on %s are older than recorded (rolled back)", r[:120])
    for r in results:
        if r.error in erasure.GAP_ERRORS:
            # R5-H1 / R6-H1: golul (obiect neverificabil sau fork) intră în rezumat → flag → marker
            log.warning("restore: the erasure journal at %s is %s (n=%d) — no proof, kept as a gap",
                        r.id[:120], "a fork" if r.error == "conflict" else "unverifiable", r.unverified)
    return dec.summary(content["created"] if content is not None else 0)


def _staged_generations(td: str) -> list:
    d = os.path.join(td, "transcripts")
    return sorted(n for n in os.listdir(d) if _TX_GEN.match(n)) if os.path.isdir(d) else []


def _staged_plaintext(td: str) -> dict:
    """{(sid, kind): "transcripts" | "arhiva"} of the staged 3.7-named plaintext files."""
    out = {}
    for sub, dirn in (("transcripts", "transcripts"), ("transcripts/" + _TX_ARCHIVE, "arhiva")):
        d = os.path.join(td, sub)
        if not os.path.isdir(d):
            continue
        for n in os.listdir(d):
            full = os.path.join(d, n)
            if os.path.isdir(full) or (dirn == "transcripts" and _TX_GEN.match(n)):
                continue
            m = re.match(r"^([0-9a-f]{32})\.(out|cast)$", n)
            if not m:
                # un manifest v2 numeşte fiecare text clar printr-o intrare `legacy` (sid.kind)
                raise erasure.ErasureConflict("a plaintext member outside the manifest's recordings — refused")
            if os.path.isfile(full):
                if (m.group(1), m.group(2)) in out:
                    raise erasure.ErasureConflict("the same recording twice in the archive (transcripts/ and "
                                                  "arhiva/) — refused")
                out[(m.group(1), m.group(2))] = dirn
    return out


def _stage_recordings(td: str, dbp: str, recs, inner: kr.Keyring) -> None:
    """§12.11.3 "Restore of recordings", at stage. Every staged descriptor is named by the
    manifest; an `included` one is decoded with the STAGED keyring and RK envelope and every one
    of its generations is a member of exactly `phys_len` bytes that passes the full check; one the
    backup did not carry (`excluded` / `not-requested` / `one-kind`) → `absent`. Every `.wtx`
    member is named by an included descriptor, every `legacy` entry by exactly one plaintext
    member and no other plaintext member exists. Anything else → refused."""
    listed = {(r["sid"], r["kind"]): r["state"] for r in recs}
    try:
        pairs = txstore.staged_pairs(dbp, inner.kwk, inner.installation_id,
                                     decode=lambda sid, kind: listed.get((sid, kind)) == "included")
    except txstore.GenCorrupt as e:
        raise erasure.ErasureConflict("a recording descriptor of the backup does not authenticate (%s) — "
                                      "refused" % e.detail[:80]) from None
    expected = set()
    absent = []
    tdir = os.path.join(td, "transcripts")
    for sid, (rk, gens, statuses) in pairs.items():
        for kind in statuses:
            state = listed.get((sid, kind))
            if state is None:
                raise erasure.ErasureConflict("a recording of the backup's database is not in its manifest — refused")
            if state in ("excluded", "not-requested", "one-kind"):
                absent.append((sid, kind))
            elif state != "included":
                raise erasure.ErasureConflict("a recording with a descriptor is listed as %s — refused" % state)
        for kind, g in gens:
            if listed.get((sid, kind)) != "included":
                continue
            name = txstore.gen_name(sid, kind, g.gen_id.hex())
            expected.add(name)
            try:
                fd = os.open(os.path.join(tdir, name), _FILE_RO)
            except FileNotFoundError:
                raise erasure.ErasureConflict("an included recording generation is missing from the archive — "
                                              "refused") from None
            try:
                txstore.verify_generation_fd(fd, sid, kind, g, rk, exact_size=True)
            except txstore.GenCorrupt as e:
                raise erasure.ErasureConflict("a recording generation of the backup fails its check (%s.%s: %s) "
                                              "— refused" % (sid[:8], kind, e.detail[:40])) from None
            finally:
                os.close(fd)
    for (sid, kind), state in listed.items():
        if state == "included" and kind not in (pairs.get(sid, (None, None, {}))[2]):
            raise erasure.ErasureConflict("the manifest includes a recording the backup's database does not "
                                          "describe — refused")
    if set(_staged_generations(td)) != expected:
        raise erasure.ErasureConflict("the archive holds recording generations no included descriptor names — "
                                      "refused")
    plain = _staged_plaintext(td)
    legacy = {k for k, v in listed.items() if v == "legacy"}
    if set(plain) != legacy:
        raise erasure.ErasureConflict("the archive's plaintext recordings do not match its manifest — refused")
    con = sqlite3.connect(dbp, isolation_level=None)
    try:
        for sid, kind in absent:
            con.execute("UPDATE tx_descriptors SET status='absent' WHERE sid=? AND kind=?", (sid, kind))
    finally:
        con.close()


def _missing_data_note(info: dict) -> dict:
    # M3: ce NU vine din backup rămâne cel de pe volum — spus explicit, nu descoperit după restore
    # R-M1: alt set de date (alt installation id) fără transcripturi → cele live merg în carantină
    info = dict(info)
    other = info.get("same_installation") is False
    info["live_transcripts_kept"] = not info.get("has_transcripts") and not other
    info["live_transcripts_quarantined"] = not info.get("has_transcripts") and other
    info["live_signing_key_kept"] = not info.get("has_signing_key")
    return info


def _extract_legacy_strict(raw: bytes, td: str, keep_files: bool = True, require_secret: bool = True) -> tuple:
    """R-H2: a pre-3.8 archive through the gateway's strict extractor (M3) into `td`, then every
    check a legacy import makes: webterm.db present and an EverShell database, the signing pair
    whole, a 32-byte `secret` (memory only, never written) that decrypts at least one encrypted
    value of exactly this database (prove_legacy_secret). The same function for `hostops verify`
    and for the staging, so what was verified is what is staged. → (archive, secret, users_since).
    RC-M1: also `_inspect` (every 3.7 verify, legacy volume included): `keep_files=False` reads and
    hashes every member exactly the same way but writes only webterm.db (the proofs need it);
    `require_secret=False` reports a missing key as `secret is None` instead of refusing."""
    gz = wts.BoundedGunzip(io.BytesIO(raw), RESTORE_MAX_UNCOMPRESSED)
    arc = _Archive(gz, "legacy", mem_only=("secret",), mem_also=_SIGNING)
    try:
        for name, is_dir, _size in arc.entries():
            path = os.path.join(td, name)
            if not keep_files and name != "webterm.db":
                if not is_dir:
                    for _b in arc.data():
                        pass
                continue
            if is_dir:
                os.makedirs(path, mode=0o700, exist_ok=True)
                continue
            parent = os.path.dirname(name)
            if parent:
                os.makedirs(os.path.join(td, parent), mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as out:
                for b in arc.data():
                    out.write(b)
    except (FileExistsError, NotADirectoryError, IsADirectoryError):
        raise wts.SnapshotError("conflicting-members") from None
    if "webterm.db" not in arc.seen:
        raise ValueError("backup without webterm.db")
    _check_signing_pair(arc.mem.get(_SIGNING[0]), arc.mem.get(_SIGNING[1]))
    secret = arc.mem.get("secret")
    if secret is None and not require_secret:
        return arc, None, _check_db(os.path.join(td, "webterm.db"))
    if secret is None or len(secret) != kr.KEY_LEN:
        raise ValueError("backup without the vault key — a restore would leave the credentials "
                         "undecryptable; use a complete WebTerm backup")
    users_since = _check_db(os.path.join(td, "webterm.db"))
    prove_legacy_secret(td, secret)
    return arc, secret, users_since


def _legacy_import_info(arc, users_since) -> dict:
    info = {"has_secret": False, "has_keyring": True, "format": "legacy-import", "users_since": users_since,
            "same_installation": True,
            "has_transcripts": bool(arc.dirs) or any(n.startswith("transcripts/") for n in arc.seen),
            "has_signing_key": "agent-signing.key" in arc.seen}
    return _missing_data_note(info)


def verify_legacy_import(raw: bytes, keys=None) -> dict:
    """R-H2: the legacy import's complete check without staging anything (a private directory,
    removed afterwards): exactly the extraction and proofs _stage_legacy_import makes."""
    _host(keys)                                  # un volum protejat, cu cheile lui deschise
    with _restore_lock():
        td = _private_tmpdir()
        try:
            arc, secret, users_since = _extract_legacy_strict(raw, td)
            del secret
            arc.mem.clear()
        finally:
            shutil.rmtree(td, ignore_errors=True)
    return _legacy_import_info(arc, users_since)


def _stage_legacy_import(raw: bytes, keys=None, progress=None) -> dict:
    """Explicit import of a pre-3.8 backup on a protected volume, through the same strict
    extractor as WTS1 (M3): its raw `secret` (kept in memory only) becomes the FK_legacy of a new
    keys.wtk (this installation, host MK, other keys unchanged) only once it is proven on the
    archive's own database (R-H2); the DB is checked on exactly the files that are then
    published; the raw key is never written to staging."""
    hk, _ = _host(keys)
    with _restore_lock():
        _refuse_active_journal()
        td = _private_tmpdir()
        try:
            arc, secret, users_since = _extract_legacy_strict(raw, td)
            r = hk.ring
            new = kr.Keyring(r.installation_id, r.epoch, r.mk_id, r.retired_mk_ids, kwk=r.kwk,
                             snk=r.snk, fk_legacy=secret, fk=r.fk, dbk=r.dbk)
            staged = _manifest_for_host(new, hk)
            del secret, new
            arc.mem.clear()
            # RC-M1: perechea EXACTĂ care se publică: FK_legacy citit din keys.wtk-ul staged (redeschis
            # cu MK-ul gazdei) trebuie să deschidă webterm.db-ul din set, chiar înainte de publicare
            fk = _open_ring(staged, hk.mk, "staged keys.wtk").fk_legacy
            if fk is None:
                raise ValueError("the staged keys.wtk lost the imported vault key — refused")
            _check_db(os.path.join(td, "webterm.db"))
            prove_legacy_secret(td, fk)
            del fk
            _write_new(os.path.join(td, KEYS_NAME), staged)
            _stage_publish(td, staged, hk.mk, progress)
        except BaseException:
            shutil.rmtree(td, ignore_errors=True)
            raise
    return _legacy_import_info(arc, users_since)


# ---------------------------------------------------------------- apply (H1)
def _validate_staging(rd, digest: str, mk: bytes, gen=None):
    """The staged set must be exactly its manifest: the manifest's digest is the flag's, every
    listed file present with its size and SHA-256, nothing else, the staged keys.wtk opens with
    the host MK and carries the manifest's identity. → (manifest doc, staged keys.wtk bytes)."""
    if not os.path.isdir(rd) or os.path.islink(rd):
        raise ValueError("a restore is flagged but its staging is missing — refused")
    try:
        raw = _read_small(os.path.join(rd, RESTORE_MANIFEST), RESTORE_MANIFEST_MAX)
    except FileNotFoundError:
        raise ValueError("a restore is flagged but its staging has no manifest — refused") from None
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest):
        raise ValueError("the restore staging does not match its flag — refused")

    def err():
        return ValueError("the restore manifest is malformed — refused")
    doc = _strict_json(raw, err)
    want = {"format", "generation", "created", "installation_id", "epoch", "mk_id", "files", "dirs"}
    if type(doc) is not dict or not want <= set(doc) <= want | {"erasure"} or doc["format"] != "wt-restore-1":
        raise err()
    er = doc.get("erasure")
    base = {"state", "proof", "since", "n"}
    if "erasure" in doc and (type(er) is not dict
                             or set(er) not in (base, base | {"threshold", "known"},
                                                base | {"threshold", "known", "required", "overflow"},
                                                base | {"threshold", "known", "required", "overflow",
                                                        "unverified"},
                                                base | {"threshold", "known", "required", "overflow",
                                                        "unverified", "conflict"})
                             or er["state"] not in ("not-tracked", "proven", "unproven")
                             or er["proof"] not in ("volume", "destinations", "none")
                             or type(er["since"]) is not int or type(er["n"]) is not int):
        raise err()
    if "erasure" in doc and "threshold" in er:
        try:
            erasure.Head.from_json(er["threshold"])
            erasure.known_from_json(er["known"])
            if "required" in er:
                erasure.required_from_json(er["required"])
                if type(er["overflow"]) is not bool:
                    raise err()
            if "unverified" in er:
                erasure.known_from_json(er["unverified"])
            if "conflict" in er:
                erasure.conflict_from_json(er["conflict"])
        except erasure.JournalError:
            raise err() from None
    if gen is not None and doc["generation"] != gen:
        raise ValueError("the restore staging is not the generation its flag names — refused")
    listed = _file_list(doc["files"], err)
    if type(doc["dirs"]) is not list or not all(type(x) is str and x in _TX_DIRS for x in doc["dirs"]):
        raise err()
    files, dirs = _tree(str(rd))
    files.pop(RESTORE_MANIFEST, None)
    if set(files) != set(listed) or dirs != set(doc["dirs"]):
        raise ValueError("the restore staging is incomplete or has extra entries — refused")
    for rel, p in files.items():
        if not _allowed(rel, False) or rel == CONTENT_MANIFEST:
            raise ValueError("unexpected file in the restore staging — refused")
        if _hash_file(p) != listed[rel]:
            raise ValueError("a staged file changed since it was verified — refused: %s" % rel[:80])
    if "webterm.db" not in listed or KEYS_NAME not in listed:
        raise ValueError("the restore staging has no database or keys.wtk — refused")
    if (_SIGNING[0] in listed) != (_SIGNING[1] in listed):
        raise ValueError("the restore staging holds half of the signing key pair — refused")
    staged = _read_small(os.path.join(rd, KEYS_NAME), kr.MAN_MAX_LEN)
    ring = _open_ring(staged, mk, "staged keys.wtk")
    if (ring.installation_id.hex(), ring.epoch, ring.mk_id.hex()) != (doc["installation_id"], doc["epoch"], doc["mk_id"]):
        raise ValueError("the staged keys.wtk does not match the restore manifest — refused")
    return doc, staged


def _copy_durable(src: str, dst) -> None:
    """dst replaced atomically and durably: tmp (O_NOFOLLOW, 0600), fsync, rename, dir fsync."""
    dst = str(dst)
    tmp = dst + ".restoring"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    with open(os.open(src, _FILE_RO), "rb") as f:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as out:
            for b in iter(lambda: f.read(1 << 20), b""):
                out.write(b)
            out.flush()
            _fsync(out.fileno())
    os.replace(tmp, dst)
    _fsync_dir(os.path.dirname(dst))


def _copy_tree_durable(src: str, dst: str) -> None:
    os.mkdir(dst, 0o700)
    for n in sorted(os.listdir(src)):
        s, d = os.path.join(src, n), os.path.join(dst, n)
        st = os.lstat(s)
        if stat.S_ISDIR(st.st_mode):
            _copy_tree_durable(s, d)
        elif stat.S_ISREG(st.st_mode):
            with open(os.open(s, _FILE_RO), "rb") as f:
                fd = os.open(d, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                with os.fdopen(fd, "wb") as out:
                    for b in iter(lambda: f.read(1 << 20), b""):
                        out.write(b)
                    out.flush()
                    _fsync(out.fileno())
        else:
            raise ValueError("the restore staging holds a non-regular entry — refused")
    _fsync_dir(dst)


def _swap_transcripts(src: str) -> None:
    """Live transcripts replaced by the staged ones: a full durable copy next to them, then two
    renames. Idempotent: a re-run after a crash rebuilds the copy and finishes the swap."""
    live = str(config.TRANSCRIPT_DIR)
    parent = os.path.dirname(live)
    new, old = live + ".restoring", live + ".pre-restore"
    if os.path.lexists(new):
        shutil.rmtree(new)
    _copy_tree_durable(src, new)
    _step("apply:transcripts-copied")
    if os.path.lexists(old):
        shutil.rmtree(old)
    if os.path.lexists(live):
        os.rename(live, old)
    os.rename(new, live)
    _fsync_dir(parent)
    _step("apply:transcripts-swapped")
    shutil.rmtree(old, ignore_errors=True)


def _finish_restore(rd) -> None:
    """After the durable commit only: the staging, then the flag."""
    if os.path.lexists(rd):
        old = tempfile.mkdtemp(prefix=VERIFY_PREFIX + "done-", dir=str(_backup_dir()))
        os.rename(str(rd), os.path.join(old, "set"))
        _fsync_dir(config.DATA_DIR)
        shutil.rmtree(old, ignore_errors=True)
    _step("apply:staging-removed")
    try:
        os.unlink(_restore_flag())
    except FileNotFoundError:
        pass
    _fsync_dir(config.DATA_DIR)


def _publish_keys(blob: bytes) -> None:
    """keys.wtk replaced atomically: tmp O_EXCL|O_NOFOLLOW 0600, fsync, rename, dir fsync,
    read back."""
    d = config.DATA_DIR
    tmp = d / (KEYS_NAME + TMP_SUFFIX)
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    _write_new(str(tmp), blob)
    os.replace(str(tmp), str(d / KEYS_NAME))
    _fsync_dir(d)
    if _read_small(d / KEYS_NAME, kr.MAN_MAX_LEN) != blob:
        raise OSError("keys.wtk read-back mismatch")


def _safety_copy(hk: HostKeys, current: bytes, gen: str, include_transcripts: bool) -> str:
    """R-L1: `pre-restore-<ts>-<restore id>-<random>.wts.keep`, published without ever replacing
    an existing copy. R-M1: with the live transcripts when the apply will replace them."""
    keep = _backup_dir() / ("pre-restore-%d-%s-%s%s.keep" % (int(time.time()), gen[:12],
                                                             secrets.token_hex(4), WTS_EXT))
    _wts_to_file(keep, hk, current, include_transcripts, local=True, portable=True, exclusive=True,
                 safety=True)
    return keep.name


def _quarantine_transcripts(gen: str) -> None:
    """R-M1: the restored dataset is another installation's and brings no transcripts: the live
    ones belong to the replaced dataset (same session ids may exist in the new DB), so they are
    moved, whole, to `backups/quarantine-<restore id>/` instead of being kept next to it.
    Idempotent: nothing to move once the live directory is gone."""
    live = str(config.TRANSCRIPT_DIR)
    if not os.path.lexists(live):
        return
    q = os.path.join(str(_backup_dir()), "quarantine-" + gen)
    try:
        os.mkdir(q, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(q)
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError("the transcript quarantine is not a plain directory — refused")
    dst = os.path.join(q, "transcripts")
    if os.path.lexists(dst):
        dst = os.path.join(q, "transcripts-" + secrets.token_hex(4))
    os.rename(live, dst)
    _fsync_dir(q)
    _fsync_dir(os.path.dirname(live))
    _step("apply:transcripts-quarantined")
    log.warning("the restored backup is another installation's and has no transcripts: the live "
                "transcripts were moved to %s", os.path.relpath(dst, str(config.DATA_DIR)))


def _apply_space(need: int, what: str) -> None:
    """Boot (state `staged`, nothing changed yet): `need` + DISK_RESERVE free on the data volume,
    else a clean refusal (ValueError: the boot stops, the old data and the staged set stay)."""
    try:
        free = free_bytes(config.DATA_DIR)
    except OSError as e:
        raise ValueError("the free space of the data volume cannot be read (%s) — the restore is refused, "
                         "nothing was changed" % e.strerror) from None
    if free < need + DISK_RESERVE:
        raise ValueError("the data volume has %d MiB free; %s needs %d MiB — the restore is refused and "
                         "nothing was changed (the current data stays). Free some space, then restart"
                         % (free >> 20, what, (need + DISK_RESERVE) >> 20))


def _apply_protected(keys=None, force_without_safety_copy: bool = False) -> bool:
    """Protected apply as a resumable journal kept in the flag (H1): `staged` → mandatory safety
    copy → `applying` → keys.wtk, signing key, transcripts, DB (each step idempotent and
    durable) → `committed` → staging removed → flag removed. Any incomplete marker is a refusal,
    never "nothing to do". The caller re-opens keys.wtk afterwards.
    R-M1: the dataset rule — another installation id without transcripts → the live transcripts
    are quarantined (decided once, kept in the flag); the signing key is a pair; the safety copy
    holds the live transcripts whenever the apply replaces them."""
    with _restore_lock():
        _invalidate_kind()
        flag = _read_flag()
        if flag is None:
            if os.path.lexists(_restore_dir()) or any(n.startswith(SET_PREFIX) for n in os.listdir(str(config.DATA_DIR))):
                log.warning("an unfinished restore staging without its flag is ignored; the next "
                            "restore replaces it")
            return False
        if flag == "legacy":
            raise ValueError("a pre-3.8 restore staging (raw vault key) on a protected volume — refused")
        if keys is None and _host_keys_provider is not None:
            keys = _host_keys_provider()
        if keys is None:
            raise ValueError("a protected restore needs the open keyring — refused")
        current = _read_small(config.DATA_DIR / KEYS_NAME, kr.MAN_MAX_LEN)
        # keys.wtk curent trebuie să se deschidă cu MK-ul dat: altfel cheile primite nu sunt ale
        # acestui volum şi nu înlocuim nimic
        hk = HostKeys(_open_ring(current, keys.mk, KEYS_NAME), keys.mk)
        gen = flag["set"]
        rd = _set_dir(gen)
        _drop_unflagged_sets(gen)
        if flag["state"] == "committed":
            _finish_restore(rd)
            log.warning("RESTORE finished (committed before the last restart)")
            return True
        doc, staged = _validate_staging(rd, flag["manifest"], keys.mk, gen)
        listed = {e["name"] for e in doc["files"]}
        has_tx = "transcripts" in doc["dirs"] or any(n.startswith("transcripts/") for n in listed)
        # 3.8 PR6a (§12.11.4): sursele de ştergeri reconciliate DIN NOU, sub lacăt, înainte de orice
        # mutaţie a apply-ului; un conflict lasă volumul neatins
        er_plan = _erasure_apply_plan(rd, doc, staged, keys.mk, listed, flag, hk)
        if flag["state"] == "staged":
            other = doc["installation_id"] != hk.ring.installation_id.hex()
            # Codex M2: spaţiul se verifică din nou ACUM, înainte de `applying` (staging-ul l-a
            # socotit, dar între timp volumul s-a putut umple): copia setului (DB + transcripturi) şi
            # copia de siguranţă a datelor curente (+ copia DB-ului ei); lipsă → refuz curat, nimic
            # schimbat, datele vechi rămân (boot-ul refuză până se eliberează spaţiu)
            copy_need = sum(int(e["size"]) for e in doc["files"])
            safety_need = 0
            if config.DB_PATH.exists() and not force_without_safety_copy:
                safety_need = (host_estimate() if has_tx else db_size() + (16 << 20)) + db_size()
            _apply_space(copy_need + safety_need, "applying this restore (the copy of the staged set and the "
                         "pre-restore safety copy of the current data)")
            name = ""
            try:
                if config.DB_PATH.exists():
                    name = _safety_copy(hk, current, gen, include_transcripts=has_tx)
            except Exception as e:                    # noqa: BLE001
                if not force_without_safety_copy:
                    raise ValueError("the pre-restore safety copy could not be made (%s) — the restore "
                                     "is refused; free space and restart, or apply it with "
                                     "force_without_safety_copy" % str(e)[:120]) from None
                log.warning("the pre-restore safety copy failed, applying WITHOUT it (forced): %s", e)
            try:
                _apply_space(copy_need, "applying this restore (the copy of the staged set)")
            except ValueError:
                # copia de siguranţă abia făcută nu rămâne: altfel fiecare boot refuzat ar mai adăuga una
                if name:
                    with contextlib.suppress(OSError):
                        os.unlink(str(_backup_dir() / name))
                raise
            _step("apply:safety")
            flag = dict(flag, state="applying", safety=name, quarantine=bool(other and not has_tx))
            if er_plan is not None:
                # PR6a: dovada se decide O DATĂ (ca şi carantina R-M1); la reluare jurnalul publicat
                # de noi nu mai e „J_v" şi n-are voie să devină dovadă. H1: pragul (capul comis al
                # DB-ului viu ÎNAINTE de a-l înlocui) şi capetele cunoscute rămân în flag: la reluare
                # DB-ul viu poate fi deja cel restaurat
                flag["erasure_proven"] = bool(er_plan["proven"])
                flag["erasure_threshold"] = er_plan["threshold"].to_json()
                flag["erasure_known"] = er_plan["known"]
                flag["erasure_required"] = er_plan["required"]
                flag["erasure_overflow"] = er_plan["overflow"]
                flag["erasure_intents"] = er_plan["intents"]
                # R5-H1: golul (destinaţie → n neverificabil) văzut la stage sau în markerul viu
                flag["erasure_unverified"] = er_plan["unverified"]
                if er_plan["conflict"] is not None:
                    # R7-H1: conflictul autentificat (capete + tombstone-uri) trece prin flag în marker
                    flag["erasure_conflict"] = er_plan["conflict"]
            _write_flag(flag)
            _step("apply:applying")
        if current != staged:
            _publish_keys(staged)
        _step("apply:keys")
        if _SIGNING[0] in listed and _SIGNING[1] in listed:
            for name in _SIGNING:
                _copy_durable(os.path.join(rd, name), config.DATA_DIR / name)
        _step("apply:signing")
        if has_tx:
            _swap_transcripts(os.path.join(rd, "transcripts"))
        elif flag["quarantine"]:
            _quarantine_transcripts(gen)
        else:
            log.warning("the backup has no transcripts: the live transcripts are kept")
        if er_plan is not None:
            _erasure_publish(er_plan, gen)
        _step("apply:erasure-journal")
        _copy_durable(os.path.join(rd, "webterm.db"), config.DB_PATH)
        for ext in ("-wal", "-shm"):
            p = config.DATA_DIR / ("webterm.db" + ext)
            if os.path.lexists(p):
                os.unlink(p)
        _fsync_dir(config.DATA_DIR)
        if er_plan is not None and er_plan["intents"]:
            # R2-H1: intenţiile de ştergere ale DB-ului viu (din flag) trec în DB-ul restaurat; boot-ul
            # care urmează le duce la capăt (un restore nu ascunde o ştergere cerută)
            erasure.carry_intents_sync(config.DB_PATH, er_plan["intents"])
        _step("apply:db")
        if has_tx and txstore.enabled():
            # PR6c (§12.11.3 Apply): registrul şi rândurile migrării restaurate numesc inode-urile
            # volumului înlocuit; le legăm de fişierele tocmai copiate (verificate la stage)
            txstore.rebind_restored_sync(config.DB_PATH, config.TRANSCRIPT_DIR)
        _step("apply:rebind")
        if er_plan is not None:
            # H1: la reluare pragul se re-verifică pe jurnalul care rămâne pe volum; o dovadă din
            # flag care nu-l mai atinge nu ridică nimic (fail closed)
            if (flag.get("erasure_proven", False) and er_plan["reach"] and not er_plan["unverified"]
                    and er_plan["conflict"] is None):
                erasure.clear_unproven_sync(config.DB_PATH)
            else:
                erasure.mark_unproven_sync(config.DB_PATH, er_plan["since"], er_plan["n"],
                                           threshold=er_plan["threshold"], known=er_plan["known"],
                                           transcripts_dir=config.TRANSCRIPT_DIR,
                                           required=er_plan["required"], overflow=er_plan["overflow"],
                                           unverified=er_plan["unverified"], conflict=er_plan["conflict"])
                log.warning("RESTORE without proof of erasure continuity: every restored recording "
                            "is quarantined until the erasures after the backup can be proven")
        _step("apply:erasure-quarantine")
        _write_flag(dict(flag, state="committed"))
        _step("apply:committed")
        _finish_restore(rd)
        _invalidate_kind()
        log.warning("RESTORE applied from an encrypted backup (DB + keys.wtk%s)",
                    " + transcripts" if has_tx else "")
        return True


def _erasure_apply_plan(rd, doc: dict, staged: bytes, mk: bytes, listed: set, flag=None, hk=None):
    """None = nothing of the erasure contract here (PR5 / 3.7 path). Otherwise the journal to
    publish and whether the continuity is proven, decided again now (stage → apply window).

    H1: on a first apply (`staged`) the threshold is the highest of the stage's and the LIVE
    database's committed head now (same installation; read before the live journal), the known
    heads are merged; on a resumed apply both come from the flag (the live DB may already be the
    restored one). `reach` = the journal left on the volume holds the threshold.
    R5-H1: `unverified` (a destination's newer object the stage could not authenticate, or one the
    live marker keeps) travels the same way (stage summary → flag → marker, folded into `known`
    and `required`); while it is not empty the apply proves nothing, first apply or resumed."""
    er = doc.get("erasure")
    if er is None and JOURNAL_MEMBER not in listed:
        return None
    if not txstore.enabled():
        raise erasure.ErasureUnsupported("a restore staging with an erasure journal needs encrypted "
                                         "recordings on — refused")
    ring = _open_ring(staged, mk, "staged keys.wtk")
    k = erasure.k_erase_of(ring.kwk)
    inst = ring.installation_id
    er = er or {}
    try:
        t = erasure.Head.from_json(er["threshold"]) if "threshold" in er else erasure.EMPTY_HEAD
        known = erasure.known_from_json(er.get("known", {}))
        required = erasure.required_from_json(er.get("required", []))
        unverified = erasure.known_from_json(er.get("unverified", {}))
        # R7-H1: conflictul autentificat văzut la stage (ramuri + tombstone-uri), păstrat întreg
        conflict = erasure.conflict_from_json(er["conflict"]) if er.get("conflict") is not None else None
    except erasure.JournalError:
        raise erasure.ErasureConflict("the restore staging's erasure threshold is malformed — refused") from None
    overflow = er.get("overflow", False) is True
    live_ok = False
    intents = {}
    if flag is None or flag.get("state") == "staged":
        live = erasure.live_state(config.DB_PATH, hk.ring.installation_id if hk is not None else None, inst)
        if live.state == "same":
            # R-H1: pragul = max(al stage-ului, capul comis viu, markerul viu al unui restore
            # anterior); acelaşi n cu alt MAC = conflict (ErasureConflict, volumul neatins)
            t = erasure.merge_threshold(t, live.head)
            overflow = overflow or live.overflow or erasure.known_overflow(known, live.attested)
            known = erasure.merge_known(known, live.attested)
            required = sorted(set(required) | set(live.required))
            unverified = erasure.merge_known(unverified, live.unverified)
            conflict = erasure.conflict_union(conflict, live.conflict)
            try:
                intents = erasure.intents_in(config.DB_PATH)
            except sqlite3.Error:
                raise erasure.ErasureConflict("the live erase intents cannot be read — refused") from None
            if len(intents) > _INTENTS_MAX:
                raise erasure.ErasureConflict("too many unfinished erasures on the live volume — refused")
        elif live.state == "bad":
            # Recheck 6678938: aceeaşi instalare, starea de ştergere ilizibilă (carantină, fără
            # dovadă). Intenţiile ei se transferă totuşi; dacă nici ele nu se pot inventaria, un
            # restore ar putea readuce RK-ul unei ştergeri cerute → refuz (fail closed)
            try:
                intents = erasure.intents_in(config.DB_PATH)
            except sqlite3.Error:
                raise erasure.ErasureConflict("the live database's erase intents cannot be read — "
                                              "refused") from None
            if len(intents) > _INTENTS_MAX:
                raise erasure.ErasureConflict("too many unfinished erasures on the live volume — refused")
        live_ok = live.state == "same"
    else:
        intents = _intents_of_flag(flag.get("erasure_intents", {}))
        if "erasure_threshold" in flag:
            t = erasure.Head.from_json(flag["erasure_threshold"])
        if "erasure_known" in flag:
            known = erasure.known_from_json(flag["erasure_known"])
        if "erasure_required" in flag:
            required = erasure.required_from_json(flag["erasure_required"])
        # R5-H1: la reluare golul vine din flag ŞI din stage (niciodată mai puţin decât s-a văzut)
        unverified = erasure.merge_known(unverified, erasure.known_from_json(flag.get("erasure_unverified", {})))
        if flag.get("erasure_conflict") is not None:
            conflict = erasure.conflict_union(conflict, erasure.conflict_from_json(flag["erasure_conflict"]))
        overflow = overflow or flag.get("erasure_overflow", False) is True
    # R5-H1: golul e o obligaţie ca un cap cunoscut, iar destinaţia lui devine obligatorie
    overflow = overflow or erasure.known_overflow(known, unverified)
    known = erasure.merge_known(known, unverified)
    required = sorted(set(required) | set(unverified))
    sj = _read_small(os.path.join(str(rd), JOURNAL_MEMBER), erasure.MAX_FILE) if JOURNAL_MEMBER in listed else None
    live_j = _live_journal()
    foreign = False
    if live_j is not None:
        try:
            erasure.parse(live_j, k, inst)
        except erasure.JournalError as e:
            foreign = e.reason == "foreign"
    publish, proven, head = erasure.reconcile_apply(k_erase=k, inst=inst, staged_journal=sj,
                                                    live_journal=None if foreign else live_j,
                                                    stage_summary=er, threshold=t, live_ok=live_ok,
                                                    known=known, unverified=unverified, conflict=conflict)
    final = publish if publish is not None else (None if foreign else live_j)
    # R2-M2: şi la reluare, jurnalul rămas trebuie să atingă şi capetele off-host păstrate
    top = max([t.n] + list(known.values()))
    reach = erasure.journal_reaches(final, k, inst, t) and _journal_n(final, k, inst) >= top
    return {"publish": publish, "proven": proven and not overflow and not unverified and conflict is None,
            "n": head.n, "conflict": conflict,
            "foreign": foreign, "since": int(er.get("since", 0)), "threshold": t, "known": known,
            "required": list(required), "overflow": bool(overflow), "reach": reach,
            "intents": intents, "unverified": unverified}


_INTENTS_MAX = 256                      # ştergeri în zbor; peste = refuz (flag-ul are o limită de mărime)


def _intents_of_flag(doc) -> dict:
    """The erase intents kept in the restore flag; malformed → refused (never silently dropped)."""
    if type(doc) is not dict or len(doc) > _INTENTS_MAX:
        raise erasure.ErasureConflict("the restore flag's erase intents are malformed — refused")
    for sid, kinds in doc.items():
        if (type(sid) is not str or len(sid) != 32 or type(kinds) is not list
                or any(k not in ("out", "cast") for k in kinds)):
            raise erasure.ErasureConflict("the restore flag's erase intents are malformed — refused")
    return dict(doc)


def _journal_n(raw, k, inst) -> int:
    if raw is None:
        return 0
    try:
        return erasure.parse(raw, k, inst).n
    except erasure.JournalError:
        return 0


def _erasure_publish(plan: dict, gen: str) -> None:
    """J* becomes the volume journal (never a shorter one: reconcile_apply chose the longest); the
    journal of ANOTHER installation is moved aside with the quarantined transcripts."""
    if plan["foreign"]:
        q = _backup_dir() / ("quarantine-%s-erasures.wtj" % gen)
        if not os.path.lexists(q):
            os.rename(str(config.DATA_DIR / JOURNAL_MEMBER), str(q))
            _fsync_dir(config.DATA_DIR)
    if plan["publish"] is not None:
        erasure.Journal(config.DATA_DIR, b"", b"\0" * 16).replace(plan["publish"])


def _open_stored_wts(name: str):
    path = _backup_dir() / name
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(name)
    return path


def raw_key_copies() -> int:
    """3.8 wiring item 5: how many stored files hold the raw 3.7 vault key (`*.wtsnap`, the 3.7
    scheduled snapshots, and `*.wtsnap.keep`, the 3.7 pre-restore copies). Regular files only,
    counted by name, never opened. System health shows the count on a protected volume."""
    n = 0
    d = config.DATA_DIR / "backups"
    if not d.is_dir():
        return 0
    for pat in ("*.wtsnap", "*.wtsnap.keep"):
        for f in d.glob(pat):
            try:
                if stat.S_ISREG(f.lstat().st_mode):
                    n += 1
            except OSError:
                pass
    return n


def list_keep_copies() -> list:
    """L1: the pre-restore safety copies (`*.keep`, never pruned). Read-only inventory, so they
    stay visible for retention; a `.wtsnap.keep` holds the 3.7 raw vault key."""
    out = []
    for f in sorted(_backup_dir().glob("*.keep"), reverse=True):
        try:
            st = f.lstat()
            if stat.S_ISREG(st.st_mode):
                out.append({"name": f.name, "size": st.st_size, "created": int(st.st_mtime),
                            "raw_vault_key": f.name.endswith(".wtsnap.keep")})
        except OSError:
            pass
    return out
