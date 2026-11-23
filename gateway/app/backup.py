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
"""
import gzip
import hashlib
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import config
from . import keyring as kr
from . import snapshot as wts

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


# ------------------------------------------------------------------ criptare
def _derive(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=8, p=1).derive(passphrase.encode("utf-8"))


def encrypt(data: bytes, passphrase: str) -> bytes:
    import secrets as _s
    salt, nonce = _s.token_bytes(_SALT), _s.token_bytes(_NONCE)
    ct = AESGCM(_derive(passphrase, salt)).encrypt(nonce, data, _MAGIC)
    return _MAGIC + salt + nonce + ct


def decrypt(blob: bytes, passphrase: str) -> bytes:
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
    Doar volume legacy: pe un volum protejat (keys.wtk) arhiva în clar e refuzată (§12.10)."""
    if is_protected():
        raise ValueError("this installation is protected: plaintext snapshots are refused")
    buf = io.BytesIO()
    with tempfile.TemporaryDirectory() as td:
        dbcopy = os.path.join(td, "webterm.db")
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


def encrypt_stored(name: str, passphrase: str, keys=None) -> bytes:
    """Citește un backup programat stocat și-l criptează cu parola userului (pt. download).
    Un `.wts` local se deschide cu SNK şi se re-criptează în flux ca WTS1 portabil cu o cheie de
    conţinut NOUĂ (niciodată aceeaşi cheie cu alt AAD), apoi stratul cu parolă."""
    if isinstance(name, str) and name.endswith(WTS_EXT) and "/" not in name and "\\" not in name:
        hk, _ = _host(keys)
        path = _open_stored_wts(name)
        buf = io.BytesIO()
        with open(path, "rb") as f:
            rd = wts.Reader(f)
            _unlock(rd, hk)
            w = wts.Writer(buf, installation_id=rd.installation_id, epoch=rd.epoch, mk_id=hk.ring.mk_id,
                           snk=hk.ring.snk, mk=hk.mk)
            for chunk in rd.chunks():
                w.write(chunk)
            w.close()
        return encrypt(buf.getvalue(), passphrase)
    if "/" in name or "\\" in name or not name.endswith(".wtsnap"):
        raise ValueError("invalid name")
    path = _backup_dir() / name
    if not path.exists():
        raise FileNotFoundError(name)
    return encrypt(path.read_bytes(), passphrase)


# --------------------------------------------------------------- verify/restore
# Plafon dur pe conţinutul DECOMPRIMAT al unui backup (un snapshot real e mic — DB + cheie).
# Anti bombă de compresie: un tar.gz mic poate declara/expanda la zeci de GB şi umple discul
# gateway-ului la _inspect (getnames walk) sau la extractall. GzipFile.read(n) decomprimă cel
# mult n octeţi, deci nu materializează niciodată bomba.
RESTORE_MAX_UNCOMPRESSED = 2 * 1024 * 1024 * 1024      # 2 GB


def _gunzip_bounded(raw: bytes) -> bytes:
    """Decomprimă gzip cu plafon dur pe ieşire; peste RESTORE_MAX_UNCOMPRESSED → ValueError."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as g:
            out = g.read(RESTORE_MAX_UNCOMPRESSED + 1)
    except (OSError, EOFError) as e:
        raise ValueError("corrupt file, or not a WebTerm backup") from e
    if len(out) > RESTORE_MAX_UNCOMPRESSED:
        raise ValueError("backup too large when unpacked (possible compression bomb) — refused")
    return out


def _inspect(raw: bytes) -> dict:
    """Validează un snapshot decriptat (tar.gz cu un DB integru); întoarce meta.
    Orice conținut care nu e un tar.gz valid → ValueError (nu excepție de tarfile),
    ca endpointul să-l mapeze curat pe 400 în loc de 500."""
    with tempfile.TemporaryDirectory() as td:
        try:
            flat = _gunzip_bounded(raw)               # plafon anti bombă de compresie
            with tarfile.open(fileobj=io.BytesIO(flat), mode="r:") as tar:
                names = tar.getnames()
                if "webterm.db" not in names:
                    raise ValueError("backup without webterm.db")
                m = tar.getmember("webterm.db")
                tar.extract(m, td, filter="data")     # nume fix, filtru anti-traversal
        except (tarfile.TarError, OSError, EOFError) as e:
            raise ValueError("corrupt file, or not a WebTerm backup") from e
        dbp = os.path.join(td, "webterm.db")
        r = sqlite3.connect(dbp).execute("PRAGMA integrity_check").fetchone()[0]
        if r != "ok":
            raise ValueError("the database in the backup is corrupt")
        try:
            created = sqlite3.connect(dbp).execute(
                "SELECT MIN(created) FROM users").fetchone()[0]
        except Exception:
            created = None
    return {"has_secret": "secret" in names,
            "has_transcripts": any(n.startswith("transcripts") for n in names),
            "users_since": created}


def verify(blob: bytes, passphrase: str, keys=None, mk=None) -> dict:
    raw = decrypt(blob, passphrase)
    if raw[:4] == wts.MAGIC:
        if not is_protected():
            raise ValueError(_WTS_ON_LEGACY)
        return _verify_wts_bytes(raw, keys, mk)
    return _inspect(raw)


_WTS_ON_LEGACY = ("this backup comes from an installation with encryption at rest; it can only be "
                  "restored on an installation whose key manifest (keys.wtk) is set up")


def verify_restorable(blob: bytes, passphrase: str, keys=None, mk=None) -> dict:
    """3.6.8: a real restore test without restoring — decrypt, unpack (bounded), integrity-check
    the database, and require the vault key (a backup without it restores nothing usable)."""
    info = verify(blob, passphrase, keys, mk)
    if info.get("format") != "WTS1" and not info["has_secret"]:
        raise ValueError("backup without the vault key — a restore would leave the credentials "
                         "undecryptable")
    return info


def verify_stored(name: str, keys=None) -> dict:
    """The same check on a stored scheduled snapshot (`data/backups/*.wtsnap`, unencrypted;
    `*.wts`, a local WTS1 checked end to end with the host's SNK)."""
    if isinstance(name, str) and name.endswith(WTS_EXT) and "/" not in name and "\\" not in name:
        hk, _ = _host(keys)
        path = _open_stored_wts(name)
        td = _private_tmpdir()
        try:
            with open(path, "rb") as f:
                info, _inner = _verify_wts(f, hk, td)
        finally:
            shutil.rmtree(td, ignore_errors=True)
        return info
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


def stage_restore(blob: bytes, passphrase: str, keys=None, mk=None, legacy_import: bool = False) -> dict:
    """Decriptează + validează + extrage în restore-pending/ + scrie markerul. Aplicarea
    reală se face la următorul boot (apply_pending_restore), după un restart.
    Volum protejat: un WTS1 (verificat complet înainte de staging; `mk` = MK-ul operatorului
    pentru un backup portabil al altei instalări) sau, cu `legacy_import=True`, un backup
    pre-3.8 importat explicit. Volum legacy: un WTS1 e refuzat, restul e codul de dinainte."""
    raw = decrypt(blob, passphrase)
    if raw[:4] == wts.MAGIC:
        if not is_protected():
            raise ValueError(_WTS_ON_LEGACY)
        return _stage_wts(io.BytesIO(raw), keys, mk)
    if is_protected():
        if not legacy_import:
            raise ValueError("a pre-3.8 backup holds the raw vault key; on this installation it "
                             "needs the explicit legacy import — refused")
        return _stage_legacy_import(raw, keys)
    info = _inspect(raw)                          # abortează dacă e corupt/greșit
    # un backup WebTerm include MEREU cheia seifului (make_snapshot); lipsa ei = backup
    # incomplet / de la alt instrument → restaurarea ar pune un DB nou peste cheia veche,
    # lăsând toate credențialele SSH + tokenurile de agent nedecriptabile. Refuză din start.
    if not info["has_secret"]:
        raise ValueError("backup without the vault key — a restore would leave the credentials "
                         "undecryptable; use a complete WebTerm backup")
    rd = _restore_dir()
    if rd.exists():
        shutil.rmtree(rd)
    rd.mkdir(parents=True)
    flat = _gunzip_bounded(raw)                   # plafon anti bombă de compresie (vezi _gunzip_bounded)
    with tarfile.open(fileobj=io.BytesIO(flat), mode="r:") as tar:
        tar.extractall(rd, filter="data")         # filtru data = anti path-traversal/symlink
    _restore_flag().write_text(str(int(time.time())))
    log.warning("RESTORE staged — it is applied on the next restart")
    return info


def _atomic_copy(src: str, dst) -> None:
    """Copie atomică pe același filesystem: scrie într-un temp lângă țintă + os.replace.
    Astfel o țintă (DB / cheie) nu rămâne niciodată trunchiată la un crash în timpul copierii."""
    tmp = str(dst) + ".restoring"
    shutil.copy2(src, tmp)
    os.replace(tmp, str(dst))       # rename atomic → înlocuire tot-sau-nimic


def apply_pending_restore(keys=None) -> bool:
    """La boot, ÎNAINTE de db.connect(): dacă există un restore în staging, îl aplică
    (swap DB + secret + transcripturi). Întoarce True dacă a aplicat ceva.

    IDEMPOTENT + REÎNCERCABIL: DB-ul și cheia seifului trebuie să swap-eze ÎMPREUNĂ — un
    swap ne-atomic lăsa DB nou + cheie veche = seif nedecriptabil silențios. Copiem din
    staging (NU mutăm), deci originalele rămân intacte până la commit-ul complet; ștergem
    staging + flag DOAR după ce totul e la loc. Un crash/excepție la mijloc lasă staging-ul
    + flagul → următorul boot reia de la zero și converge. Ridicăm la eșec (main.py refuză
    să pornească cu stare parțială, în loc să servească un seif rupt). Fiecare fișier critic
    e înlocuit atomic (temp + os.replace)."""
    flag, rd = _restore_flag(), _restore_dir()
    if not flag.exists() or not (rd / "webterm.db").exists():
        return False
    # 3.8: un volum protejat (sau un staging cu keys.wtk) nu primeşte niciodată `secret` în clar
    if is_protected() or os.path.lexists(rd / KEYS_NAME):
        return _apply_protected(rd, flag, keys)
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
MAX_MEMBERS = 200_000
_TOP_FILES = frozenset({"webterm.db", KEYS_NAME, "agent-signing.key", "agent-signing.pub"})
_NAME_PART = re.compile(r"^[A-Za-z0-9_@+=-][A-Za-z0-9._@+=-]{0,254}$")
_TX_DEPTH = 4


@dataclass(frozen=True)
class HostKeys:
    """The running process's opened keyring and the MK it was opened with (the MK only derives
    the portable envelope's KEK; it is never written anywhere)."""
    ring: kr.Keyring
    mk: bytes = field(repr=False)


# Boot-ul (încă necablat, §12.9 Wiring checklist) înregistrează aici furnizorul; până atunci un
# volum protejat fără `keys=` explicit e refuzat (fail closed), nu tratat ca legacy.
_host_keys_provider = None


def set_host_keys_provider(fn) -> None:
    global _host_keys_provider
    _host_keys_provider = fn


def is_protected() -> bool:
    """keys.wtk present (regular file) → protected. Anything else at that name → refuse."""
    try:
        st = os.lstat(config.DATA_DIR / KEYS_NAME)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("keys.wtk is not a regular file — refused")
    return True


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


def _allowed(name: str, is_dir: bool) -> bool:
    parts = name.split("/")
    if parts[0] == "transcripts":
        return True
    return not is_dir and len(parts) == 1 and (name in _TOP_FILES or name == CONTENT_MANIFEST)


def _add_member(tar, arcname: str, src, size: int, entries: list, td: str, stable: bool) -> None:
    """Adds one regular file, hashing exactly the bytes archived. A file that may change while
    read (transcripts) is first copied (at most its stat size) into a private temp file, so the
    tar header's size and the manifest's hash always describe the same bytes."""
    h = hashlib.sha256()
    if stable:
        with open(src, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        n = os.path.getsize(src)
        ti = tarfile.TarInfo(arcname)
        ti.size, ti.mode, ti.mtime = n, 0o600, int(time.time())
        with open(src, "rb") as f:
            tar.addfile(ti, f)
    else:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as f, tempfile.TemporaryFile(dir=td) as spool:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return
            left, n = size, 0
            while left > 0:
                b = f.read(min(left, 1 << 20))
                if not b:
                    break                      # micşorat între timp: arhivăm ce am citit
                spool.write(b)
                h.update(b)
                n += len(b)
                left -= len(b)
            spool.seek(0)
            ti = tarfile.TarInfo(arcname)
            ti.size, ti.mode, ti.mtime = n, 0o600, int(time.time())
            tar.addfile(ti, spool)
    entries.append({"name": arcname, "size": ti.size, "sha256": h.hexdigest()})


def _add_bytes(tar, arcname: str, data: bytes, entries) -> None:
    ti = tarfile.TarInfo(arcname)
    ti.size, ti.mode, ti.mtime = len(data), 0o600, int(time.time())
    tar.addfile(ti, io.BytesIO(data))
    if entries is not None:
        entries.append({"name": arcname, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})


def _add_dir(tar, arcname: str) -> None:
    ti = tarfile.TarInfo(arcname)
    ti.type, ti.mode, ti.mtime = tarfile.DIRTYPE, 0o700, int(time.time())
    tar.addfile(ti)


def _write_wts(out, hk: HostKeys, keys_blob: bytes, include_transcripts: bool, local: bool,
               portable: bool) -> None:
    """Streams a WTS1 container to `out`: tar.gz {webterm.db (VACUUM INTO), keys.wtk, fleet
    signing key, [transcripts], wts-manifest.json (last)}. Never `secret`, never the MK."""
    ring = hk.ring
    w = wts.Writer(out, installation_id=ring.installation_id, epoch=ring.epoch, mk_id=ring.mk_id,
                   snk=ring.snk if local else None, mk=hk.mk if portable else None)
    entries: list = []
    with tempfile.TemporaryDirectory() as td:
        dbcopy = os.path.join(td, "webterm.db")
        con = sqlite3.connect(str(config.DB_PATH))
        try:
            con.execute("VACUUM INTO ?", (dbcopy,))
        finally:
            con.close()
        with tarfile.open(fileobj=w, mode="w|gz") as tar:
            _add_member(tar, "webterm.db", dbcopy, 0, entries, td, stable=True)
            _add_bytes(tar, KEYS_NAME, keys_blob, entries)
            for name in ("agent-signing.key", "agent-signing.pub"):
                p = config.DATA_DIR / name
                if p.is_file() and not p.is_symlink():
                    _add_member(tar, name, str(p), p.stat().st_size, entries, td, stable=False)
            if include_transcripts and config.TRANSCRIPT_DIR.is_dir():
                base = config.TRANSCRIPT_DIR
                _add_dir(tar, "transcripts")
                for f in sorted(base.rglob("*")):
                    rel = "transcripts/" + str(f.relative_to(base))
                    if f.name.endswith(".cap-tmp"):
                        continue
                    try:
                        _safe_name(rel)
                    except ValueError:
                        log.warning("transcript skipped from the backup (unsupported name): %s", f.name)
                        continue
                    try:
                        st = os.lstat(f)
                        if stat.S_ISDIR(st.st_mode):
                            _add_dir(tar, rel)
                        elif stat.S_ISREG(st.st_mode):
                            _add_member(tar, rel, str(f), st.st_size, entries, td, stable=False)
                    except OSError as e:
                        log.warning("transcript skipped from the backup (%s): %s", f.name, e)
            man = json.dumps({"format": "wts-content-1", "files": entries},
                             sort_keys=True, separators=(",", ":")).encode()
            _add_bytes(tar, CONTENT_MANIFEST, man, None)
    w.close()


def _wts_to_file(path, hk, keys_blob, include_transcripts, local=True, portable=False) -> None:
    """Writes a WTS1 file all-or-nothing (tmp in the same dir, fsync, replace, dir fsync).
    A failed attempt leaves no file; a retry is a new Writer, so a new content key."""
    path = str(path)
    tmp = path + TMP_SUFFIX
    try:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as f:
            _write_wts(f, hk, keys_blob, include_transcripts, local, portable)
            f.flush()
            _fsync(f.fileno())
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


def make_portable_bytes(include_transcripts: bool = False, keys=None) -> bytes:
    """A portable WTS1 (local + portable envelopes) in memory — the input of the WTBK1
    passphrase layer for downloads and remote uploads (that layer is single-shot AES-GCM)."""
    hk, blob = _host(keys)
    buf = io.BytesIO()
    _write_wts(buf, hk, blob, include_transcripts, local=True, portable=True)
    return buf.getvalue()


def _unlock(reader, hk: HostKeys, mk=None) -> None:
    """Local envelope with this host's SNK (same installation), else the portable one with the
    operator's `mk` or, failing that, the host MK when the header names it."""
    if reader.local and reader.installation_id == hk.ring.installation_id:
        reader.unlock(snk=hk.ring.snk, installation_id=hk.ring.installation_id)
        return
    for cand in (mk, hk.mk):
        if cand is not None and reader.portable and kr.key_id(cand) == reader.mk_id:
            reader.unlock(mk=cand)
            return
    raise wts.SnapshotWrongKey("no-usable-envelope", "the backup needs master key " + reader.mk_id.hex())


def _unpack_verified(reader, dest: str) -> dict:
    """Streams the authenticated tar.gz into `dest` (a fresh private dir): names, types and
    sizes checked per member, every byte hashed, the content manifest last and equal to what
    was extracted, the gzip and WTS1 streams consumed to their authenticated end."""
    gz = wts.BoundedGunzip(reader, RESTORE_MAX_UNCOMPRESSED)
    seen: dict = {}
    dirs = set()
    manifest = None
    count = 0
    try:
        with tarfile.open(fileobj=gz, mode="r|") as tar:
            for m in tar:
                count += 1
                if count > MAX_MEMBERS:
                    raise wts.SnapshotTooLarge("too-many-members")
                if manifest is not None:
                    raise wts.SnapshotError("member-after-manifest")
                name = _safe_name(m.name)
                if name in seen or name in dirs:
                    raise wts.SnapshotError("duplicate-member", name)
                if m.isdir():
                    if not _allowed(name, True):
                        raise wts.SnapshotError("unexpected-member", name)
                    os.makedirs(os.path.join(dest, name), mode=0o700, exist_ok=True)
                    dirs.add(name)
                    continue
                if not m.isreg():
                    raise wts.SnapshotError("unexpected-member-type", name)
                if name == CONTENT_MANIFEST:
                    if m.size > CONTENT_MANIFEST_MAX:
                        raise wts.SnapshotTooLarge("manifest")
                    manifest = tar.extractfile(m).read(CONTENT_MANIFEST_MAX + 1)
                    continue
                if not _allowed(name, False):
                    raise wts.SnapshotError("unexpected-member", name)
                parent = os.path.dirname(name)
                if parent:
                    os.makedirs(os.path.join(dest, parent), mode=0o700, exist_ok=True)
                h = hashlib.sha256()
                n = 0
                src = tar.extractfile(m)
                fd = os.open(os.path.join(dest, name),
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                with os.fdopen(fd, "wb") as out:
                    for b in iter(lambda: src.read(1 << 20), b""):
                        h.update(b)
                        n += len(b)
                        out.write(b)
                if n != m.size:
                    raise wts.SnapshotError("short-member", name)
                seen[name] = (n, h.hexdigest())
        gz.drain_zeros()
        reader.finish()
    except tarfile.TarError as e:
        raise wts.SnapshotError("bad-archive", str(e)[:80]) from None
    except (FileExistsError, NotADirectoryError, IsADirectoryError):
        # un fişier şi un director cu acelaşi nume (ex. „transcripts/a” apoi „transcripts/a/b”)
        raise wts.SnapshotError("conflicting-members") from None
    if manifest is None:
        raise wts.SnapshotError("no-content-manifest")
    try:
        doc = json.loads(manifest)
        listed = {e["name"]: (int(e["size"]), str(e["sha256"])) for e in doc["files"]}
        if doc.get("format") != "wts-content-1" or len(listed) != len(doc["files"]):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise wts.SnapshotError("bad-content-manifest") from None
    if listed != seen:
        raise wts.SnapshotError("content-manifest-mismatch")
    if "webterm.db" not in seen or KEYS_NAME not in seen:
        raise wts.SnapshotError("incomplete", "webterm.db and keys.wtk are required")
    return {"has_transcripts": "transcripts" in dirs or any(n.startswith("transcripts/") for n in seen)}


def _check_db(path: str):
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        try:
            r = con.execute("PRAGMA integrity_check").fetchone()[0]
        except sqlite3.Error:
            r = None
        if r != "ok":
            raise ValueError("the database in the backup is corrupt")
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


def _manifest_for_host(src: kr.Keyring, hk: HostKeys) -> bytes:
    """The keyring of a restored snapshot, re-wrapped under the host MK (the one the next boot
    will use), epoch above both the snapshot's and the host's; the snapshot's MK id (and, same
    installation, the host's old ids) stay listed as retired: backups made under them exist."""
    host_id = kr.key_id(hk.mk)
    retired = set(src.retired_mk_ids) | {src.mk_id}
    if src.installation_id == hk.ring.installation_id:
        retired |= set(hk.ring.retired_mk_ids) | {hk.ring.mk_id}
    retired.discard(host_id)
    if len(retired) > kr.MAN_MAX_RETIRED:
        raise ValueError("too many retired master keys — refused")
    m = kr.KeyManifest(src.installation_id, max(src.epoch, hk.ring.epoch) + 1, host_id,
                       tuple(sorted(retired)), _envelopes_for(hk.mk, src))
    return kr.encode_manifest(m, hk.mk, kr.PROFILE_V1)


def _verify_wts(fileobj, hk: HostKeys, dest: str, mk=None, max_plaintext=wts.MAX_PLAINTEXT) -> tuple:
    """Full check of a WTS1 into `dest`: header MAC, envelope, every chunk, final frame, EOF,
    content manifest, DB integrity, and the inner keys.wtk opened with the MK it names (the
    host's or the operator's `mk`). Returns (info, inner keyring)."""
    reader = wts.Reader(fileobj, max_plaintext)
    _unlock(reader, hk, mk)
    info = _unpack_verified(reader, dest)
    inner_blob = _read_small(os.path.join(dest, KEYS_NAME), kr.MAN_MAX_LEN)
    inner = None
    for cand in (hk.mk, mk):
        if cand is None:
            continue
        try:
            inner = kr.open_keyring_bytes(inner_blob, cand, kr.PROFILE_V1)
            break
        except kr.WrongKeyError:
            continue
        except kr.KeyringError as e:
            raise wts.SnapshotError("keyring-invalid", e.reason) from None
    if inner is None:
        raise wts.SnapshotWrongKey("inner-keyring", "its keys.wtk needs the master key it was made under")
    if inner.installation_id != reader.installation_id or inner.snk is None:
        raise wts.SnapshotError("keyring-mismatch")
    users_since = _check_db(os.path.join(dest, "webterm.db"))
    info.update({"has_secret": False, "has_keyring": True, "users_since": users_since,
                 "format": "WTS1", "portable": reader.portable,
                 "same_installation": inner.installation_id == hk.ring.installation_id})
    return info, inner


def _private_tmpdir() -> str:
    # sub backups/ (acelaşi filesystem ca restore-pending/ → rename atomic), 0700
    return tempfile.mkdtemp(prefix=".restore-verify-", dir=str(_backup_dir()))


def _verify_wts_bytes(raw: bytes, keys=None, mk=None) -> dict:
    hk, _ = _host(keys)
    td = _private_tmpdir()
    try:
        info, _inner = _verify_wts(io.BytesIO(raw), hk, td, mk)
    finally:
        shutil.rmtree(td, ignore_errors=True)
    return info


def _stage_dir(td: str) -> None:
    """Moves a fully verified tree into restore-pending/ (one rename) and writes the flag."""
    rd = _restore_dir()
    if rd.exists():
        shutil.rmtree(rd)
    os.rename(td, str(rd))
    _restore_flag().write_text(str(int(time.time())))
    log.warning("RESTORE staged — it is applied on the next restart")


def _stage_wts(fileobj, keys=None, mk=None) -> dict:
    """Protected restore of a WTS1: everything verified in a private dir BEFORE restore-pending/
    is touched; the staged keys.wtk is the snapshot's keyring re-wrapped under the host MK."""
    hk, _ = _host(keys)
    td = _private_tmpdir()
    try:
        info, inner = _verify_wts(fileobj, hk, td, mk)
        staged = _manifest_for_host(inner, hk)
        kp = os.path.join(td, KEYS_NAME)
        os.unlink(kp)
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(staged)
        _stage_dir(td)
    except BaseException:
        shutil.rmtree(td, ignore_errors=True)
        raise
    return info


_LEGACY_IMPORT_FILES = frozenset({"webterm.db", "agent-signing.key", "agent-signing.pub"})


def _stage_legacy_import(raw: bytes, keys=None) -> dict:
    """Explicit import of a pre-3.8 backup on a protected volume: its raw `secret` becomes the
    FK_legacy of a new keys.wtk (this installation, host MK, other keys unchanged); the raw key
    is never written to staging."""
    hk, _ = _host(keys)
    info = _inspect(raw)
    if not info["has_secret"]:
        raise ValueError("backup without the vault key — a restore would leave the credentials "
                         "undecryptable; use a complete WebTerm backup")
    td = _private_tmpdir()
    try:
        secret = None
        flat = _gunzip_bounded(raw)
        with tarfile.open(fileobj=io.BytesIO(flat), mode="r:") as tar:
            for m in tar.getmembers():
                name = m.name
                if name == "secret":
                    if not m.isreg() or m.size != 32 or secret is not None:
                        raise ValueError("the vault key in the backup is malformed — refused")
                    secret = tar.extractfile(m).read(33)
                    continue
                if name in _LEGACY_IMPORT_FILES or name == "transcripts" or name.startswith("transcripts/"):
                    tar.extract(m, td, filter="data")
                    continue
                raise ValueError("unexpected entry in a pre-3.8 backup — refused: %s" % name[:80])
        if secret is None or len(secret) != 32:
            raise ValueError("backup without the vault key — refused")
        r = hk.ring
        new = kr.Keyring(r.installation_id, r.epoch, r.mk_id, r.retired_mk_ids, kwk=r.kwk,
                         snk=r.snk, fk_legacy=secret, fk=r.fk, dbk=r.dbk)
        staged = _manifest_for_host(new, hk)
        del secret, new
        fd = os.open(os.path.join(td, KEYS_NAME),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(staged)
        _stage_dir(td)
    except tarfile.TarError as e:
        shutil.rmtree(td, ignore_errors=True)
        raise ValueError("corrupt file, or not a WebTerm backup") from e
    except BaseException:
        shutil.rmtree(td, ignore_errors=True)
        raise
    info = dict(info, has_secret=False, has_keyring=True, format="legacy-import")
    return info


def _publish_keys(blob: bytes) -> None:
    """keys.wtk replaced atomically: tmp O_EXCL|O_NOFOLLOW 0600, fsync, rename, dir fsync,
    read back."""
    d = config.DATA_DIR
    tmp = d / (KEYS_NAME + TMP_SUFFIX)
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(blob)
        while view:
            n = os.write(fd, view)
            if not n:
                raise OSError("short write on keys.wtk")
            view = view[n:]
        _fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(d / KEYS_NAME))
    _fsync_dir(d)
    if _read_small(d / KEYS_NAME, kr.MAN_MAX_LEN) != blob:
        raise OSError("keys.wtk read-back mismatch")


def _apply_protected(rd, flag, keys=None) -> bool:
    """Protected apply (idempotent, resumable like the legacy one): the staged keys.wtk must open
    with the host MK; safety copy as a WTS1; keys.wtk first, the DB last (commit point). The
    caller re-opens keys.wtk afterwards (a foreign restore changes the installation id)."""
    if not is_protected():
        raise ValueError("a protected restore is staged but this volume has no keys.wtk — refused")
    if os.path.lexists(rd / "secret") or os.path.lexists(rd / "master.key"):
        raise ValueError("the staged restore contains a raw key — refused on a protected volume")
    if not os.path.lexists(rd / KEYS_NAME):
        raise ValueError("the staged restore has no keys.wtk — refused on a protected volume")
    if keys is None and _host_keys_provider is not None:
        keys = _host_keys_provider()
    if keys is None:
        raise ValueError("a protected restore needs the open keyring — refused")
    staged = _read_small(rd / KEYS_NAME, kr.MAN_MAX_LEN)
    _open_ring(staged, keys.mk, "staged keys.wtk")      # trebuie să se deschidă cu MK-ul gazdei
    current = _read_small(config.DATA_DIR / KEYS_NAME, kr.MAN_MAX_LEN)
    # keys.wtk curent trebuie şi el să se deschidă cu MK-ul dat: altfel cheile primite nu sunt
    # ale acestui volum şi nu înlocuim nimic (fail closed, nu doar „copia de siguranţă a eşuat”)
    hk = HostKeys(_open_ring(current, keys.mk, KEYS_NAME), keys.mk)
    if current != staged:
        # plasa de siguranţă: starea curentă ca WTS1 local + portabil (se deschide cu MK-ul
        # gazdei şi după ce keys.wtk se schimbă). Un al doilea apel (reluare) găseşte deja
        # keys.wtk nou şi nu mai face copia: starea curentă e atunci pe jumătate restaurată.
        try:
            if config.DB_PATH.exists():
                keep = _backup_dir() / ("pre-restore-%d%s.keep" % (int(time.time()), WTS_EXT))
                _wts_to_file(keep, hk, current, False, local=True, portable=True)
        except Exception as e:                        # noqa: BLE001
            log.warning("the pre-restore snapshot failed (continuing): %s", e)
        _publish_keys(staged)
    for name in ("agent-signing.key", "agent-signing.pub"):
        if (rd / name).exists():
            _atomic_copy(str(rd / name), config.DATA_DIR / name)
            (config.DATA_DIR / name).chmod(0o600)
    if (rd / "transcripts").is_dir():
        if config.TRANSCRIPT_DIR.exists():
            shutil.rmtree(config.TRANSCRIPT_DIR)
        shutil.copytree(str(rd / "transcripts"), str(config.TRANSCRIPT_DIR))
    _atomic_copy(str(rd / "webterm.db"), config.DB_PATH)
    for ext in ("-wal", "-shm"):
        p = config.DATA_DIR / ("webterm.db" + ext)
        if p.exists():
            p.unlink()
    log.warning("RESTORE applied from an encrypted backup (DB + keys.wtk%s)",
                " + transcripts" if (rd / "transcripts").is_dir() else "")
    shutil.rmtree(rd, ignore_errors=True)
    try:
        flag.unlink()
    except OSError:
        pass
    return True


def _open_stored_wts(name: str):
    path = _backup_dir() / name
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(name)
    return path
