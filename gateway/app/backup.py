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
"""
import gzip
import io
import logging
import os
import shutil
import sqlite3
import tarfile
import tempfile
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import config

log = logging.getLogger("webterm")

_MAGIC = b"WTBK1"
_SALT = 16
_NONCE = 12
_SCRYPT_N = 2 ** 15         # ~30ms derivare; anti brute-force pe fișierul descărcat
RETENTION_DAYS = 7


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
    prin asyncio.to_thread din endpoint-uri (VACUUM + gzip pot dura)."""
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
                # ce e citit — iar asta se întâmplă exact când trebuie: `_maybe_cap` trunchiază
                # in-place fişierele care trec de plafon, adică fix în sesiunile cu output
                # masiv. Rezultatul era pierderea ÎNTREGII arhive, nu a unui fişier. Prins prin
                # reproducere de auditul intern (2026-08-06).
                base = config.TRANSCRIPT_DIR
                tar.add(str(base), arcname="transcripts", recursive=False)
                for f in sorted(base.rglob("*")):
                    try:
                        tar.add(str(f), arcname="transcripts/" + str(f.relative_to(base)),
                                recursive=False)
                    except OSError as e:
                        log.warning("transcript skipped from the backup (%s): %s", f.name, e)
    return buf.getvalue()


def make_encrypted(passphrase: str, include_transcripts: bool = False) -> bytes:
    return encrypt(make_snapshot(include_transcripts), passphrase)


# ------------------------------------------------------- backup-uri programate
def run_scheduled_backup(include_transcripts: bool = False) -> str:
    """Creează un snapshot NECRIPTAT în data/backups/ (serverul are oricum cheia) +
    aplică retenția. Întoarce numele fișierului. SINCRON (to_thread)."""
    snap = make_snapshot(include_transcripts)
    name = "webterm-%s.wtsnap" % time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    path = _backup_dir() / name
    path.write_bytes(snap)
    path.chmod(0o600)
    prune_backups()
    log.info("scheduled backup created: %s (%d KB)", name, len(snap) // 1024)
    return name


def prune_backups(days: int = RETENTION_DAYS) -> int:
    cutoff = time.time() - days * 86400
    n = 0
    for f in _backup_dir().glob("*.wtsnap"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                n += 1
        except OSError:
            pass
    return n


def list_backups() -> list:
    out = []
    for f in sorted(_backup_dir().glob("*.wtsnap"), reverse=True):
        try:
            st = f.stat()
            out.append({"name": f.name, "size": st.st_size, "created": int(st.st_mtime)})
        except OSError:
            pass
    return out


def encrypt_stored(name: str, passphrase: str) -> bytes:
    """Citește un backup programat stocat și-l criptează cu parola userului (pt. download)."""
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


def verify(blob: bytes, passphrase: str) -> dict:
    return _inspect(decrypt(blob, passphrase))


def stage_restore(blob: bytes, passphrase: str) -> dict:
    """Decriptează + validează + extrage în restore-pending/ + scrie markerul. Aplicarea
    reală se face la următorul boot (apply_pending_restore), după un restart."""
    raw = decrypt(blob, passphrase)
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


def apply_pending_restore() -> bool:
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
    # Plasă de siguranță: snapshot al stării CURENTE înainte de a o suprascrie. Sufix
    # `.keep` → retenția NU-l șterge (e singura recuperare dacă restore-ul e greșit).
    try:
        if config.DB_PATH.exists():
            cur = make_snapshot(include_transcripts=False)
            keep = _backup_dir() / ("pre-restore-%d.wtsnap.keep" % int(time.time()))
            keep.write_bytes(cur)
            # conţine `data/secret` NECRIPTAT — sub umask 022 ieşea 0644, adică lizibil de
            # orice user de pe maşină. `run_scheduled_backup` face chmod 600; aici lipsea.
            keep.chmod(0o600)
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
