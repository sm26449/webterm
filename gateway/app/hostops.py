"""Host-side backup / restore through the gateway's own code (3.8, encryption at rest).

`scripts/backup.sh` and `scripts/restore.sh` run these in the APP image (the same code as the
gateway), never with a shell `tar` or a hand-written swap (PR4 review, H2/H3/M5):

    python3 -m app.hostops backup [--live] [--no-transcripts]
        → a protected volume's archive on stdout: WTBK1(portable WTS1), the passphrase from
          WEBTERM_BACKUP_PASSPHRASE. Written by backup.py's protected writer (inventory through
          fds, inode/nlink filters, signing-pair checks, self-verification). `--live`: run inside
          the running app (`docker exec`); the gateway holds `.lock`, so the capture takes the
          shared `.maint.lock` instead (never during a boot's restore / migration phase).
          With encrypted recordings (the flag, the socket or any of their artefacts), `--live`
          never reads the volume: the gateway takes the snapshot through its local control socket
          `DATA_DIR/.ctl/backup.sock` (ctlsock.py, §12.11.3) and streams the verified WTS1 back;
          no answer → refused (exit 3).
          Without `--live` the data directory's `.lock` must be free (the app is stopped).
    python3 -m app.hostops verify --sha256 HEX [--legacy-import]          (archive on stdin)
        → the gateway's full restore check (strict extractor, keyring, database) in a private
          scratch directory; the data volume is only read (no lock: the app may run).
    python3 -m app.hostops stage-restore --sha256 HEX [--legacy-import]   (archive on stdin)
        → backup.stage_restore under the data directory's `.lock` + exclusive `.maint.lock`
          (the durable, two-generation staged set of PR3); the app applies it at its next boot,
          under its own lock, with the resumable journal. Never moves `.lock` or `master.key`.

The archive on stdin must hash to `--sha256` (the digest the script took of its private, pinned
copy): what was checked is what is staged. Legacy archives (a 3.7 tar.gz, already decrypted by
the script) go through the same public `backup` entry points.

Exit codes (R-M1, stage-restore): 0 committed — the new flag is published and its directory
fsynced; 3 refused before any change — the data volume is exactly as it was (the caller may
restart the app); 4 outcome uncertain — something failed after the volume began to change (a
failed fsync after a rename, an unexpected I/O error): the caller must NOT restart the app on its
own; 1 anything else (treated like 4 by restore.sh). For verify / backup: 0 done, 3 refused.
A legacy (pre-3.8) archive is checked by the same code that stages it (RC-M1): one route decided
by the INNER format (a WTBK1 holding a 3.7 tar is a 3.7 archive) and the target's policy
(backup.restore_route), then the same strict extractor (no duplicate, non-canonical or case-alias
names) and the key proof on the archive's own database for both a legacy import (R-H2) and a
legacy volume; the staging proves the exact published pair again. Messages never carry key material.
INV-14 (docs/design/INVARIANTS.md): the key decides before anything is written.
"""
import argparse
import contextlib
import hashlib
import os
import secrets
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from . import backup, config, ctlsock, txstore
from . import keyring as kr
from . import keys

EXIT_OK, EXIT_ERR, EXIT_REFUSED, EXIT_UNCERTAIN = 0, 1, 3, 4
# antetul stratului cu parolă (backup.encrypt); un tar.gz începe cu magicul gzip
WTBK_MAGIC = b"WTBK1"
GZIP_MAGIC = b"\x1f\x8b"
ENV_PASSPHRASE = "WEBTERM_BACKUP_PASSPHRASE"
# aceeaşi limită ca plafonul de decomprimare al restore-ului: arhiva stă în memorie o dată
STDIN_MAX = backup.RESTORE_MAX_UNCOMPRESSED
MAINT_WAIT = 15.0


class Refused(Exception):
    """Nothing in the data volume was changed (exit 3)."""


class Uncertain(Exception):
    """The volume began to change and the staging did not reach its commit (exit 4)."""


class _DirView:
    """Fd-ul directorului de date, fără `.lock`: clasificarea şi rezolvarea cheii (read-only) cât
    timp app-ul rulează. Aceeaşi formă ca ProcessLock pentru funcţiile din keys."""

    def __init__(self, path):
        self.path = path
        self.dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.lock_fd = None
        self.maint_fd = None
        self.mutated = False

    def release(self):
        if self.dir_fd is not None:
            os.close(self.dir_fd)
            self.dir_fd = None


def _say(msg):
    print(msg, file=sys.stderr, flush=True)


def _refusal(e):
    # BootRefused poartă un cod şi un NUME, niciodată o valoare
    if isinstance(e, keys.BootRefused):
        return "%s (%s)" % (e.reason, e.subject or "-")
    return str(e)[:300] or type(e).__name__


def _point_at(data_dir):
    """Backup.py citeşte căile din config la fiecare apel: le îndreptăm spre `data_dir`."""
    p = Path(data_dir)
    config.DATA_DIR = p
    config.TRANSCRIPT_DIR = p / "transcripts"
    config.ARCHIVE_DIR = config.TRANSCRIPT_DIR / "arhiva"
    config.DB_PATH = p / "webterm.db"


def _read_stdin(expect):
    buf = bytearray()
    src = sys.stdin.buffer
    while True:
        chunk = src.read(1 << 20)
        if not chunk:
            break
        buf += chunk
        if len(buf) > STDIN_MAX:
            raise Refused("the archive is larger than %d bytes — refused" % STDIN_MAX)
    raw = bytes(buf)
    digest = hashlib.sha256(raw).hexdigest()
    if expect is not None and digest != expect:
        # M5: arhiva verificată şi cea aplicată sunt aceeaşi copie fixată, octet cu octet
        raise Refused("the archive is not the one that was checked (sha256 %s, expected %s) — "
                      "refused" % (digest, expect))
    return raw, digest


def _passphrase():
    p = os.environ.get(ENV_PASSPHRASE, "")
    if not p:
        raise Refused("an encrypted archive (.wtbk) needs %s" % ENV_PASSPHRASE)
    return p


def _wrap_legacy(raw):
    """Un tar.gz 3.7 (deja decriptat de script) intră pe aceleaşi uşi publice ca o descărcare:
    WTBK1 cu o parolă efemeră, doar în memoria acestui proces."""
    eph = secrets.token_urlsafe(24)
    return backup.encrypt(raw, eph), eph


def _archive_kind(raw):
    if raw[:len(WTBK_MAGIC)] == WTBK_MAGIC:
        return "wtbk"
    if raw[:2] == GZIP_MAGIC:
        return "legacy"
    raise Refused("not a WebTerm backup (neither a .wtbk nor a 3.7 tar.gz) — refused")


def _inventory(view):
    try:
        inv = keys.classify(view)
    except OSError as e:
        raise Refused("the data volume cannot be read (%s) — refused" % e.strerror) from None
    if inv.kind == "ambiguous":
        raise Refused("the data volume is inconsistent (%s): start the app once and read its log" % inv.reason)
    if inv.kind == "empty":
        raise Refused("the data volume is empty: start the app once (it sets up the key), then restore")
    if inv.migrating or inv.secret_leftover or inv.leftovers:
        raise Refused("a key operation is unfinished (%s): start the app once (it completes it), then "
                      "run this again" % ", ".join(inv.leftovers or (keys.MIGRATION_MARKER,)))
    return inv


def _open_keys(view, inv):
    """The configured master key, resolved exactly like the boot (pinned file, never inside the
    volume unless WEBTERM_KEY_IN_VOLUME=1, mode 0400), and keys.wtk opened with it (authenticated).
    `open_protected` writes nothing here: a migration marker was refused by `_inventory`."""
    try:
        resolved = keys.resolve_master_key(os.environ, view, inv)
        if resolved is None or resolved.mk is None:
            raise Refused("no master key is configured for this installation (WEBTERM_MASTER_KEY_FILE)")
        ring, _state = keys.open_protected(view, inv, resolved)
    except keys.BootRefused as e:
        raise Refused("the configured master key does not open this volume's keys.wtk: %s" % _refusal(e)) from None
    hk = backup.HostKeys(ring, resolved.mk)
    backup.set_boot_protected(True)
    backup.set_host_keys_provider(lambda: hk)
    return hk, resolved


def _manifest_bytes(dir_fd):
    fd = os.open(keys.MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > kr.MAN_MAX_LEN:
            raise Refused("keys.wtk is not a plain file — refused")
        with os.fdopen(os.dup(fd), "rb") as f:
            return f.read(kr.MAN_MAX_LEN + 1)
    finally:
        os.close(fd)


# ── backup ───────────────────────────────────────────────────────────────────


def cmd_backup(args):
    passphrase = _passphrase()
    data = str(config.DATA_DIR)
    lock = maint = None
    try:
        lock = keys.acquire_lock(data)
    except keys.LockError as e:
        if e.reason != "locked" or not args.live:
            raise Refused("the data directory is in use (%s): with the app running, back up through it "
                          "(backup.sh does)" % _refusal(e)) from None
    view = lock if lock is not None else _DirView(data)
    try:
        try:
            # partajat: exclude doar fazele de boot care schimbă volumul (restore, migrare, schema)
            maint = keys.acquire_maint_lock(view.dir_fd, exclusive=False, wait=MAINT_WAIT)
        except keys.BootRefused as e:
            raise Refused("the app is changing the data volume right now (%s): try again in a minute"
                          % _refusal(e)) from None
        inv = _inventory(view)
        if inv.kind != "protected":
            raise Refused("this volume is not protected (no keys.wtk): backup.sh archives it the 3.7 way")
        if inv.staged_restore:
            # un restore pus în staging se aplică la boot: o captură acum ar salva starea de dinainte
            _say("note: a restore is staged on this volume and is applied at the next start of the app")
        hk, resolved = _open_keys(view, inv)
        if lock is None and _needs_socket():
            # PR6c (§12.11.3): gateway-ul rulează şi ţine înregistrări criptate → snapshot-ul îl ia
            # EL (barieră, pin-uri), prin socket-ul local; fără răspuns → refuz, niciodată o citire
            # directă a volumului viu
            blob = _live_via_socket(hk, passphrase, not args.no_transcripts)
        else:
            blob = backup.make_encrypted(passphrase, include_transcripts=not args.no_transcripts, keys=hk)
    except (ValueError, OSError) as e:
        raise Refused("the backup was not written: %s" % _refusal(e)) from None
    finally:
        if maint is not None:
            os.close(maint)
        view.release()
    out = sys.stdout.buffer
    out.write(blob)
    out.flush()
    _say("kind: %s" % ("reduced" if resolved.source == "volume" else "protected"))
    _say("sha256: %s" % hashlib.sha256(blob).hexdigest())
    return EXIT_OK


def _needs_socket():
    """The live volume may hold encrypted recordings (flag on, the socket exists, or any artefact
    of the inventory): then only the running gateway may snapshot it."""
    if txstore.enabled() or os.path.lexists(ctlsock.socket_path()):
        return True
    try:
        return bool(txstore.inventory(config.DATA_DIR, config.DB_PATH))
    except Exception:                       # noqa: BLE001 — necitibil = nu dovedeşte absenţa
        return True


def _live_via_socket(hk, passphrase, include):
    """`hostops backup --live` through the gateway's control socket: the WTS1 lands in a private
    temp file, its length and SHA-256 must be the gateway's answer and its structure must pass the
    restore check before the passphrase layer is added; a partial file is deleted, never reused."""
    try:
        client = ctlsock.Client(ctlsock.socket_path())
    except (ctlsock.ClientError, OSError) as e:
        raise Refused("the running gateway did not answer on its backup control socket (%s): a live "
                      "volume with encrypted recordings is never read directly — refused. System health "
                      "shows why the socket is missing; or stop the app and back up again" % e) from None
    fd, tmp = tempfile.mkstemp(prefix="wt-live-", suffix=".wts")
    try:
        with os.fdopen(fd, "w+b") as f:
            try:
                size, _sha = client.snapshot(f, recordings=include)
            except (ctlsock.ClientError, OSError) as e:
                raise Refused("the live backup through the gateway failed: %s — refused" % e) from None
            f.flush()
            if f.tell() != size:
                raise Refused("the live backup is not the size the gateway announced — refused")
            f.seek(0)
            backup._verify_wts(f, hk, None, prefer="portable")
            f.seek(0)
            data = f.read()
    finally:
        client.close()
        with contextlib.suppress(OSError):
            os.unlink(tmp)
    return backup.encrypt(data, passphrase)


# ── verify ───────────────────────────────────────────────────────────────────


def _route(raw, kind, inv, legacy_import):
    """RC-M1: the archive's route, by its INNER format (a WTBK1 is decrypted first: one holding a
    3.7 tar is a 3.7 archive) and the target volume's policy, through backup.restore_route — the
    one decision stage_restore also makes, so verify (before the app is stopped) and stage reach
    the same verdict. → (route, inner bytes, blob, passphrase); blob/passphrase are None for a
    plain 3.7 tar.gz (stage-restore wraps it)."""
    if kind == "wtbk":
        blob, pw = raw, _passphrase()
        try:
            inner = backup.decrypt(raw, pw)
        except ValueError as e:
            raise Refused("the archive cannot be opened: %s" % _refusal(e)) from None
    else:
        inner, blob, pw = raw, None, None
    protected = inv.kind == "protected"
    try:
        route = backup.restore_route(inner, protected, legacy_import)
    except ValueError as e:
        legacy_inner = inner[:2] == GZIP_MAGIC
        if legacy_inner and protected and not legacy_import:
            raise Refused("a pre-3.8 archive holds the raw vault key; on a protected volume it needs "
                          "the explicit legacy import (--legacy-import) — refused") from None
        if legacy_inner and not protected and legacy_import:
            raise Refused("--legacy-import is for protected volumes; this one is pre-3.8 — refused") from None
        raise Refused("the archive is refused: %s" % _refusal(e)) from None
    return route, inner, blob, pw


def _check(raw, kind, inv, hk, legacy_import):
    """The gateway's restore check against a private scratch data directory that mirrors the
    target volume's kind (its keys.wtk, nothing else): per route, exactly the extraction and
    proofs the staging makes (RC-M1)."""
    route, inner, blob, pw = _route(raw, kind, inv, legacy_import)
    try:
        if route == "legacy-import":
            return route, backup.verify_legacy_import(inner, keys=hk)
        if route == "legacy-volume":
            return route, backup.verify_legacy_volume(inner)
        return route, backup.verify_restorable(blob, pw, keys=hk)
    except Exception as e:                      # noqa: BLE001 — orice eroare a cititorului = refuz
        raise Refused("the archive is refused: %s" % _refusal(e)) from None


def cmd_verify(args):
    raw, digest = _read_stdin(args.sha256)
    kind = _archive_kind(raw)
    view = _DirView(str(config.DATA_DIR))
    scratch = tempfile.mkdtemp(prefix="wt-hostops-")
    try:
        inv = _inventory(view)
        hk = None
        if inv.kind == "protected":
            hk, resolved = _open_keys(view, inv)
            blob = _manifest_bytes(view.dir_fd)
        view.release()
        # nimic din volum nu se scrie: lock-ul operaţiilor şi temporarele stau în scratch
        _point_at(scratch)
        if hk is not None:
            fd = os.open(os.path.join(scratch, keys.MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
        route, info = _check(raw, kind, inv, hk, args.legacy_import)
    finally:
        view.release()
        shutil.rmtree(scratch, ignore_errors=True)
    print("sha256: %s" % digest)
    print("volume: %s" % inv.kind)
    print("archive: %s" % ("legacy-import" if route == "legacy-import" else info.get("format") or "legacy"))
    if hk is not None:
        print("master-key: %s (%s) opens this volume's keys.wtk" % (kr.key_id(hk.mk).hex(), resolved.source))
        print("volume-key: %d" % (resolved.source == "volume"))
    if info.get("same_installation") is False:
        print("note: the archive comes from another installation (its transcripts replace the live ones, "
              "or the live ones are quarantined)")
    return EXIT_OK


# ── stage-restore ────────────────────────────────────────────────────────────


def cmd_stage(args):
    raw, digest = _read_stdin(args.sha256)
    kind = _archive_kind(raw)
    data = str(config.DATA_DIR)
    _point_at(data)
    try:
        lock = keys.acquire_lock(data)
    except keys.BootRefused as e:
        # H2: un conflict (app pornit, vacuum, alt restore) se refuză înaintea oricărei mutaţii
        raise Refused("the data directory is in use (%s): stop the app (and any admin command) first"
                      % _refusal(e)) from None
    maint = None
    try:
        try:
            maint = keys.acquire_maint_lock(lock.dir_fd, exclusive=True, wait=0.0)
        except keys.BootRefused as e:
            raise Refused("an admin command is using the data directory (%s) — refused" % _refusal(e)) from None
        inv = _inventory(lock)
        hk = None
        if inv.kind == "protected":
            hk, _resolved = _open_keys(lock, inv)
        elif inv.staged_restore:
            # 3.7: un singur set fără jurnal; nu-l înlocuim pe jumătate peste unul deja flag-uit
            raise Refused("a restore is already staged on this volume: start the app once (it applies "
                          "it), then run this again")
        # RC-M1: aceeaşi rută ca verify (format interior + politica ţintei), decisă înainte de orice
        route, _inner, blob, pw = _route(raw, kind, inv, args.legacy_import)
        del _inner
        if blob is None:
            blob, pw = _wrap_legacy(raw)
        progress = backup.StageProgress()
        try:
            info = backup.stage_restore(blob, pw, keys=hk, legacy_import=route == "legacy-import",
                                        progress=progress)
        except Exception as e:                  # noqa: BLE001
            # R-M1: rezultatul vine din ce a raportat staging-ul, nu dintr-o comparaţie de octeţi
            # a flagului: înainte de prima schimbare → refuz curat; după commit (flag publicat ŞI
            # director fsync-uit) → doar curăţenia a eşuat; între ele → incert, fără restart
            if not progress.mutated:
                raise Refused("nothing was staged: %s" % _refusal(e)) from None
            if not progress.committed:
                raise Uncertain("the staging failed after the data volume began to change: %s"
                                % _refusal(e)) from None
            _say("warning: the restore was staged (committed), then a clean-up step failed: %s" % _refusal(e))
            info = {}
        if not progress.committed:
            raise Uncertain("the staging returned without a committed flag")
    finally:
        if maint is not None:
            os.close(maint)
        lock.release()
    print("sha256: %s" % digest)
    print("staged: %s" % ("legacy-import" if route == "legacy-import" else
                          "protected" if route == "wts" else "legacy"))
    if info.get("live_transcripts_quarantined"):
        print("note: the archive comes from another installation; the live transcripts are quarantined")
    if info.get("live_signing_key_kept"):
        print("note: the archive has no fleet signing key; the current one is kept")
    return EXIT_OK


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m app.hostops")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--live", action="store_true")
    b.add_argument("--no-transcripts", action="store_true")
    for name in ("verify", "stage-restore"):
        s = sub.add_parser(name)
        s.add_argument("--sha256", required=True)
        s.add_argument("--legacy-import", action="store_true")
    args = p.parse_args(argv)
    fn = {"backup": cmd_backup, "verify": cmd_verify, "stage-restore": cmd_stage}[args.cmd]
    try:
        return fn(args)
    except Refused as e:
        _say("REFUSING: %s" % e)
        return EXIT_REFUSED
    except Uncertain as e:
        _say("UNCERTAIN: %s" % e)
        return EXIT_UNCERTAIN
    except keys.BootRefused as e:
        _say("REFUSING: %s" % _refusal(e))
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
