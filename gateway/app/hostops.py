"""Host-side backup / restore through the gateway's own code (3.8, encryption at rest).

`scripts/backup.sh` and `scripts/restore.sh` run these in the APP image (the same code as the
gateway), never with a shell `tar` or a hand-written swap (PR4 review, H2/H3/M5):

    python3 -m app.hostops backup [--live] [--no-transcripts]
        → a protected volume's archive on stdout: WTBK2(portable WTS1) — the streamed passphrase
          layer (wtbk.py, §12.10.1), the passphrase from WEBTERM_BACKUP_PASSPHRASE — in bounded
          memory whatever the volume's size. Written by backup.py's protected writer (inventory
          through fds, inode/nlink filters, signing-pair checks) into a private work file on the
          volume, checked restorable, then wrapped. `--live`: run inside
          the running app (`docker exec`); the gateway holds `.lock`, so the capture takes the
          shared `.maint.lock` instead (never during a boot's restore / migration phase).
          With encrypted recordings (the flag, the socket or any of their artefacts), `--live`
          never reads the volume: the gateway takes the snapshot through its local control socket
          `DATA_DIR/.ctl/backup.sock` (ctlsock.py, §12.11.3) and streams the verified WTS1 back,
          wrapped on the fly (its exact sizes come with the answer); no answer → refused (exit 3).
          Without `--live` the data directory's `.lock` must be free (the app is stopped).
    python3 -m app.hostops estimate
        → `estimate: N`, an upper bound (bytes, uncompressed) of the backup; backup.sh refuses
          early when its destination has less free space.
    python3 -m app.hostops verify --sha256 HEX [--legacy-import] [--for-restore]   (archive on stdin)
        → the staging's own acceptance (backup.preflight_wts: strict extractor, keyring,
          database, and the target's recording / erasure rules — flag policy, recording
          membership, WTX generations, journal) in a private scratch directory; the data volume
          is only read (no lock: the app may run). `--for-restore` (restore.sh, before it stops
          the app): too little free space on the volume for the restore is a refusal, not a note.
    python3 -m app.hostops stage-restore --sha256 HEX [--legacy-import]   (archive on stdin)
        → backup.stage_restore under the data directory's `.lock` + exclusive `.maint.lock`
          (the durable, two-generation staged set of PR3); the app applies it at its next boot,
          under its own lock, with the resumable journal. Never moves `.lock` or `master.key`.

The archive on stdin must hash to `--sha256` (the digest the script took of its private, pinned
copy): what was checked is what is staged. A WTBK2 is read as a stream (bounded memory): the
digest is checked when the input ends, which is before the end of the archive is accepted, so
before anything is published; WTBK1 and 3.7 archives are read whole (≤ 2 GiB, as before). Legacy archives (a 3.7 tar.gz, already decrypted by
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
import errno
import hashlib
import io
import os
import secrets
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from . import backup, config, ctlsock, txstore, wtbk
from . import keyring as kr
from . import keys
from . import snapshot as wts

EXIT_OK, EXIT_ERR, EXIT_REFUSED, EXIT_UNCERTAIN = 0, 1, 3, 4
# antetul stratului cu parolă (backup.encrypt); un tar.gz începe cu magicul gzip
WTBK_MAGIC = b"WTBK1"
WTBK2_MAGIC = wtbk.MAGIC
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


class PinMismatch(ValueError):
    """The input is not the archive the script pinned (M5)."""


class _Pinned:
    """stdin, hashed as it is read. When it ends, its SHA-256 must be `expect` (M5: what was
    checked is what is staged): a WTBK2 reader reaches that end before it accepts the archive's
    last chunk, so a different file is refused before anything is published. `peek` keeps the
    first bytes for the format check (they are hashed once, when read)."""

    def __init__(self, src, expect):
        self._src = src
        self._expect = expect
        self._h = hashlib.sha256()
        self._head = b""
        self._eof = False
        self.size = 0

    def _pull(self, n):
        b = self._src.read(n)
        if b:
            self._h.update(b)
            self.size += len(b)
        elif not self._eof:
            self._eof = True
            if self._expect is not None and self.digest != self._expect:
                raise PinMismatch("the archive is not the one that was checked (sha256 %s, expected %s) — "
                                  "refused" % (self.digest, self._expect))
        return b

    def peek(self, n):
        while len(self._head) < n:
            b = self._pull(n - len(self._head))
            if not b:
                break
            self._head += b
        return self._head[:n]

    def read(self, n=-1):
        if n is None or n < 0:
            raise ValueError("unbounded read")
        if self._head:
            out, self._head = self._head[:n], self._head[n:]
            return out
        return self._pull(n)

    def read_all(self, cap):
        buf = bytearray()
        while True:
            b = self.read(1 << 20)
            if not b:
                return bytes(buf)
            buf += b
            if len(buf) > cap:
                raise Refused("the archive is larger than %d bytes — refused (only a WTBK2 archive, "
                              "written by this version's backup.sh, is read as a stream)" % cap)

    @property
    def digest(self):
        return self._h.hexdigest()


def _open_wtbk2(src):
    """The WTBK2 layer over `src`: header and passphrase checked before any body byte is read."""
    try:
        return wtbk.Reader(src, _passphrase())
    except (wtbk.WtbkError, PinMismatch) as e:
        raise Refused("the archive cannot be opened: %s" % _refusal(e)) from None


def _stream_route(inv, legacy_import):
    """RC-M1 for a WTBK2: it carries a 3.8 snapshot only (content type WTS1 in its authenticated
    header; the WTS1 reader checks the magic again), so the same policy as `_route` gives `wts`."""
    try:
        return backup.restore_route(wts.MAGIC, inv.kind == "protected", legacy_import)
    except ValueError as e:
        raise Refused("the archive is refused: %s" % _refusal(e)) from None


def _need_space(path, need, what):
    """`need` bytes for `what` plus the reserve kept free for the gateway (backup.headroom) must be
    free on the filesystem of `path`; → the reserve (the caller meters its writes with it)."""
    try:
        free = backup.free_bytes(path)
        keep = backup.headroom(path)
    except OSError as e:
        raise Refused("the free space of the data volume cannot be read (%s) — refused" % e.strerror) from None
    if free < need + keep:
        raise Refused("the data volume has %s free; %s needs %s, plus %s kept free for the gateway — "
                      "refused. Free some space, then run this again" % (_mib(free), what, _mib(need), _mib(keep)))
    return keep


def _mib(n):
    return "%d MiB" % (n >> 20)


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
    if raw[:len(WTBK2_MAGIC)] == WTBK2_MAGIC:
        return "wtbk2"
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
        out = _HashedOut(sys.stdout.buffer)
        if lock is None and _needs_socket():
            # PR6c (§12.11.3): gateway-ul rulează şi ţine înregistrări criptate → snapshot-ul îl ia
            # EL (barieră, pin-uri), prin socket-ul local; fără răspuns → refuz, niciodată o citire
            # directă a volumului viu
            _live_via_socket(hk, passphrase, not args.no_transcripts, out)
        else:
            _local_snapshot(hk, passphrase, not args.no_transcripts, out)
        out.flush()
    except (ValueError, OSError) as e:
        raise Refused("the backup was not written: %s" % _refusal(e)) from None
    finally:
        if maint is not None:
            os.close(maint)
        view.release()
    _say("kind: %s" % ("reduced" if resolved.source == "volume" else "protected"))
    _say("sha256: %s" % out.digest)
    return EXIT_OK


class _HashedOut:
    """stdout, hashed as written; every write must be taken whole (the WTBK2 writer checks it)."""

    def __init__(self, dst):
        self._dst = dst
        self._h = hashlib.sha256()

    def write(self, b):
        n = self._dst.write(b)
        if n == len(b):
            self._h.update(b)
        return n

    def flush(self):
        self._dst.flush()

    @property
    def digest(self):
        return self._h.hexdigest()


def _copy_into(src, w):
    for b in iter(lambda: src.read(1 << 20), b""):
        w.write(b)


def _local_snapshot(hk, passphrase, include, out):
    """The WTS1 written by the gateway's code into a private file of a work dir on the data volume
    (never /tmp: a 64 MiB tmpfs in production; never memory: the volume may be larger than RAM),
    checked restorable through the portable route, then wrapped in WTBK2 with its exact sizes."""
    backup.member_preflight(include)
    # M2: copia de lucru ŞI copia DB-ului (cea a snapshot-ului, apoi cea extrasă la verificare) stau
    # pe acelaşi volum, peste rezerva gateway-ului; scrierea e contorizată (refuz + curăţenie)
    keep = _need_space(config.DATA_DIR, backup.host_work_need(),
                       "the backup's work copy and its database copy")
    with backup.write_budget(keep), backup.work_dir("hostbk-") as wd:
        fd = os.open(os.path.join(wd, "host.wts"), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w+b") as f:
            backup.write_host_snapshot(f, include, keys=hk)
            size, unpacked = backup.verify_host_snapshot(f, keys=hk)
            f.seek(0)
            w = wtbk.Writer(out, passphrase, plain_len=size, unpacked_len=unpacked)
            _copy_into(f, w)
            # mai puţini octeţi decât fişierul verificat → close refuză (niciun ultim chunk scris)
            w.close()


def _needs_socket():
    """The live volume may hold encrypted recordings (flag on, the socket exists, or any artefact
    of the inventory): then only the running gateway may snapshot it."""
    if txstore.enabled() or os.path.lexists(ctlsock.socket_path()):
        return True
    try:
        return bool(txstore.inventory(config.DATA_DIR, config.DB_PATH))
    except Exception:                       # noqa: BLE001 — necitibil = nu dovedeşte absenţa
        return True


def _live_via_socket(hk, passphrase, include, out):
    """`hostops backup --live` through the gateway's control socket. The gateway verified its
    spool in full (restorable, portable route) before answering with its size, SHA-256 and unpacked
    size; the bytes are wrapped in WTBK2 as they arrive (no second copy on the volume, nothing in
    memory). The last WTBK2 chunk is written only after the SHA-256 of everything read matched the
    answer: a short, changed or failed transfer leaves an archive without its end, which every
    reader refuses, and exit 3 (backup.sh then publishes nothing; it also runs the full restore
    check on the result before publishing)."""
    try:
        client = ctlsock.Client(ctlsock.socket_path())
    except (ctlsock.ClientError, OSError) as e:
        raise Refused("the running gateway did not answer on its backup control socket (%s): a live "
                      "volume with encrypted recordings is never read directly — refused. System health "
                      "shows why the socket is missing; or stop the app and back up again" % e) from None
    try:
        try:
            snap, size, sha, unpacked = client.start(recordings=include)
            w = wtbk.Writer(out, passphrase, plain_len=size, unpacked_len=unpacked)
            client.read_into(w, snap, size, sha)
        except (ctlsock.ClientError, OSError) as e:
            raise Refused("the live backup through the gateway failed: %s — refused" % e) from None
        w.close()
    finally:
        client.close()


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


def _check(raw, kind, inv, hk, legacy_import, live_root):
    """The gateway's restore check against a private scratch data directory that mirrors the
    target volume's kind (its keys.wtk, nothing else): per route, exactly the extraction and
    proofs the staging makes (RC-M1); a WTS1 through the staging's own acceptance, the target's
    recording and erasure rules included (Codex M1: backup.preflight_wts)."""
    route, inner, _blob, _pw = _route(raw, kind, inv, legacy_import)
    try:
        if route == "legacy-import":
            return route, backup.verify_legacy_import(inner, keys=hk)
        if route == "legacy-volume":
            return route, backup.verify_legacy_volume(inner)
        return route, backup.preflight_wts(io.BytesIO(inner), keys=hk, live_root=live_root)
    except Exception as e:                      # noqa: BLE001 — orice eroare a cititorului = refuz
        raise Refused("the archive is refused: %s" % _refusal(e)) from None


def _verify_scratch(stack):
    """The verify's private scratch data dir. On a writable volume (app running: `docker exec`,
    where /tmp is a 64 MiB tmpfs) it is a work dir on the volume, like every backup temporary
    (backup.work_dir). Only a volume mounted read-only (backup.sh's `ro` container, app stopped,
    whose /tmp is the container's disk layer) falls back to the system temp dir."""
    try:
        return stack.enter_context(backup.work_dir("hostops-"))
    except OSError as e:
        if e.errno != errno.EROFS:
            raise
    scratch = tempfile.mkdtemp(prefix="wt-hostops-")
    stack.callback(shutil.rmtree, scratch, True)
    return scratch


def cmd_verify(args):
    src = _Pinned(sys.stdin.buffer, args.sha256)
    kind = _archive_kind(src.peek(len(WTBK2_MAGIC)))
    raw = None
    if kind != "wtbk2":
        raw, digest = _read_stdin_from(src)
    live_root = str(config.DATA_DIR)
    view = _DirView(live_root)
    stack = contextlib.ExitStack()
    try:
        scratch = _verify_scratch(stack)
        inv = _inventory(view)
        hk = None
        space = None
        if inv.kind == "protected":
            hk, resolved = _open_keys(view, inv)
            # R-M3: un apply neterminat pe ţintă (flag `applying` / `committed`, sau ilizibil) face
            # staging-ul imposibil: refuzat ACUM, înainte ca restore.sh să oprească app-ul
            # (un test de restore doar notează: arhiva în sine e bună, ca la lipsa spaţiului)
            try:
                backup.refuse_active_journal(live_root)
            except ValueError as e:
                if args.for_restore:
                    raise Refused("%s — refused" % e) from None
                _say("note: %s: a restore would be refused until then" % e)
            blob = _manifest_bytes(view.dir_fd)
            # M2: ce cere restore-ul pe volumul ŢINTĂ (măsurat înainte de _point_at, care mută căile)
            try:
                space = (backup.free_bytes(live_root), backup.restore_space_need(0), backup.headroom(live_root))
            except OSError as e:
                raise Refused("the free space of the data volume cannot be read (%s) — refused" % e.strerror) from None
        view.release()
        # volumul nu se schimbă: lock-ul operaţiilor şi temporarele stau în scratch (privat, şters la
        # final); scratch-ul păstrează rezerva sistemului lui de fişiere (pe volum: cea a gateway-ului)
        stack.enter_context(backup.write_budget(backup.headroom(scratch)))
        _point_at(scratch)
        if hk is not None:
            fd = os.open(os.path.join(scratch, keys.MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
        if kind == "wtbk2":
            route = _stream_route(inv, args.legacy_import)
            r = _open_wtbk2(src)
            try:
                # M1: aceeaşi acceptare ca staging-ul (politica ţintei, înregistrări, jurnal), nu doar structura
                info = backup.preflight_wts(r, keys=hk, live_root=live_root,
                                            budget={"max_plaintext": r.plain_len, "max_unpacked": r.unpacked_len,
                                                    "expect_unpacked": r.unpacked_len})
                r.finish()
            except Exception as e:              # noqa: BLE001 — orice eroare a cititorului = refuz
                raise Refused("the archive is refused: %s" % _refusal(e)) from None
            digest = src.digest
        else:
            route, info = _check(raw, kind, inv, hk, args.legacy_import, live_root)
        if space is not None and info.get("unpacked_len") is not None:
            free, base, keep = space
            need = base + 2 * info["unpacked_len"]
            if free < need + keep:
                msg = ("the data volume has %s free; restoring this archive needs %s (the staged copy, the "
                       "copy the next start makes, the safety copy of the current data) plus %s kept free "
                       "for the gateway" % (_mib(free), _mib(need), _mib(keep)))
                if args.for_restore:
                    # M2: refuzat ÎNAINTE ca restore.sh să oprească app-ul
                    raise Refused(msg + " — refused. Free some space, then run this again")
                _say("note: " + msg + ": a restore would be refused until space is freed")
    finally:
        view.release()
        stack.close()
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


def _read_stdin_from(src):
    try:
        raw = src.read_all(STDIN_MAX)
    except PinMismatch as e:
        raise Refused(str(e)) from None
    return raw, src.digest


def _stage_stream(src, inv, hk, legacy_import, progress):
    """A WTBK2 staged as a stream. Free space first: the staged copy and the copy the apply makes
    at the next boot both hold the declared unpacked size (refused before anything is written)."""
    route = _stream_route(inv, legacy_import)
    r = _open_wtbk2(src)
    # M2: vârful restore-ului pe volum, pe faze (backup.restore_space_need) + rezerva gateway-ului
    keep = _need_space(config.DATA_DIR, backup.restore_space_need(r.unpacked_len),
                       "this restore (the staged copy, the copy the next start makes and the safety copy "
                       "of the current data)")
    with backup.write_budget(keep):
        info = backup.stage_host_stream(r, keys=hk, max_plaintext=r.plain_len, unpacked_len=r.unpacked_len,
                                        progress=progress)
    r.finish()
    return route, info


def cmd_stage(args):
    src = _Pinned(sys.stdin.buffer, args.sha256)
    kind = _archive_kind(src.peek(len(WTBK2_MAGIC)))
    raw = digest = None
    if kind != "wtbk2":
        raw, digest = _read_stdin_from(src)
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
        progress = backup.StageProgress()
        if kind != "wtbk2":
            # RC-M1: aceeaşi rută ca verify (format interior + politica ţintei), decisă înainte de orice
            route, _inner, blob, pw = _route(raw, kind, inv, args.legacy_import)
            del _inner
            if blob is None:
                blob, pw = _wrap_legacy(raw)
        try:
            if kind == "wtbk2":
                route, info = _stage_stream(src, inv, hk, args.legacy_import, progress)
                digest = src.digest
            else:
                with backup.write_budget(backup.headroom(data)):
                    info = backup.stage_restore(blob, pw, keys=hk, legacy_import=route == "legacy-import",
                                                progress=progress)
        except Refused:
            if progress.mutated:
                raise Uncertain("the staging failed after the data volume began to change") from None
            raise
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


def cmd_estimate(args):
    """An upper bound of the backup's size (backup.sh: refuse early when the destination is too
    small). Reads sizes only (lstat), no lock: the app may run."""
    print("estimate: %d" % backup.host_estimate())
    # M2: ce scrie backup-ul pe volum pe lângă arhivă (copia de lucru / spool-ul + copia DB-ului), rezerva
    # gateway-ului şi dispozitivul volumului: backup.sh le adună la nevoia destinaţiei când e ACELAŞI
    # sistem de fişiere (arhiva creşte cât copia de lucru încă există)
    print("work: %d" % backup.host_work_need())
    print("headroom: %d" % backup.headroom(config.DATA_DIR))
    print("device: %d" % os.stat(str(config.DATA_DIR)).st_dev)
    return EXIT_OK


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m app.hostops")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("estimate")
    b = sub.add_parser("backup")
    b.add_argument("--live", action="store_true")
    b.add_argument("--no-transcripts", action="store_true")
    for name in ("verify", "stage-restore"):
        s = sub.add_parser(name)
        s.add_argument("--sha256", required=True)
        s.add_argument("--legacy-import", action="store_true")
        if name == "verify":
            # restore.sh înainte de oprire: lipsa spaţiului pentru restore = refuz, nu o notă
            s.add_argument("--for-restore", action="store_true")
    args = p.parse_args(argv)
    fn = {"backup": cmd_backup, "verify": cmd_verify, "stage-restore": cmd_stage,
          "estimate": cmd_estimate}[args.cmd]
    try:
        return fn(args)
    except (Refused, PinMismatch) as e:
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
