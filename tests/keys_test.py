"""Key sources, boot contract, process lock and atomic keys.wtk publication
(gateway/app/keys.py, ENCRYPTION-AT-REST.md §12.9): inventory classes, the lock (same process and
a child process), key-file checks on the same fd, source precedence and conflicts, bootstrap,
3.7 migration and MK rotation with a crash at every publication step, and the guarantee that a
refused boot (wrong / missing key, also with a staged restore) leaves the data directory
byte-identical. Temp directories only; never /run/secrets, never a real data/secret.

Hook-ul _crash_at ridică Crash la pasul ales: starea de pe disc e exact cea de după acel pas."""
import base64
import errno
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile

GW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gateway")
sys.path.insert(0, GW)
from app import keyring as kr  # noqa: E402
from app import keys as K  # noqa: E402

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


def raises(fn, exc, reason=None):
    try:
        fn()
    except exc as e:
        if reason is None or getattr(e, "reason", None) == reason:
            return True
        print(f"      (reason {getattr(e, 'reason', None)!r}, expected {reason!r})")
        return False
    except Exception as e:  # noqa: BLE001
        print(f"      (unexpected {type(e).__name__}: {e})")
        return False
    print("      (no exception)")
    return False


class Crash(Exception):
    pass


def crash_at(step):
    def hook(x):
        if x == step:
            raise Crash(step)
    return hook


ROOT = tempfile.mkdtemp(prefix="wt-keys-test-")
_n = [0]
MK1, MK2, MK3 = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))
SECRET = hashlib.sha256(b"legacy").digest()
NODEF = os.path.join(ROOT, "no-default-key")  # calea implicită a testelor: nu există


def fresh(name="d"):
    _n[0] += 1
    d = os.path.join(ROOT, f"{name}{_n[0]}")
    os.mkdir(d)
    os.chmod(d, 0o700)  # independent de umask: DATA_DIR scriibil de grup e refuzat (M3)
    return d


def put(path, data, mode=0o600):
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)
    return path


def keyfile(key, mode=0o600, content=None):
    p = os.path.join(fresh("k"), "mk")
    return put(p, base64.b64encode(key) + b"\n" if content is None else content, mode)


def legacy_dir():
    d = fresh("legacy")
    put(os.path.join(d, "secret"), SECRET)
    put(os.path.join(d, "webterm.db"), b"SQLite format 3\x00" + b"x" * 100)
    os.makedirs(os.path.join(d, "transcripts", "arhiva"))
    put(os.path.join(d, "transcripts", "s1.out"), b"hello")
    return d


def snapshot(d, skip_lock=False):
    out = {}
    for base, dirs, files in os.walk(d, followlinks=False):
        for n in dirs + files:
            p = os.path.join(base, n)
            rel = os.path.relpath(p, d)
            if skip_lock and rel == ".lock":
                continue
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                body = os.readlink(p)
            elif stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    body = hashlib.sha256(f.read()).hexdigest()
            else:
                body = None
            out[rel] = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, body)
    return out


def boot(d, env=None, **kw):
    kw.setdefault("default_key_file", NODEF)
    return K.boot(d, env or {}, **kw)


def boot_ok(d, env=None, **kw):
    r = boot(d, env, **kw)
    r.lock.release()
    return r


def env_file(key):
    return {K.ENV_KEY_FILE: keyfile(key)}


def rot(lock, old, new, **kw):
    """Rotație cu noul fișier-cheie persistat (M4: parametrul e obligatoriu)."""
    return K.rotate_master_key(lock, old, new, keyfile(new if len(new) == 32 else MK3), **kw)


def with_lock(d, fn):
    lock = K.acquire_lock(d)
    try:
        return fn(lock)
    finally:
        lock.release()


def kind(d):
    return with_lock(d, K.classify).kind


def refused_twice_identical(d, env, reason=None, exc=K.BootRefused, **kw):
    """Două boot-uri refuzate: conţinut+nume+moduri identice (fără .lock faţă de „înainte”,
    cu .lock între primul şi al doilea)."""
    before = snapshot(d, skip_lock=True)
    ok1 = raises(lambda: boot(d, env, **kw), exc, reason)
    after1 = snapshot(d)
    ok2 = raises(lambda: boot(d, env, **kw), exc, reason)
    after2 = snapshot(d)
    return ok1 and ok2 and before == snapshot(d, skip_lock=True) and after1 == after2


# ── inventory ────────────────────────────────────────────────────────────────
print("inventory")
d = fresh()
check("empty directory → empty", kind(d) == "empty")
check(".lock is created 0600 and empty", stat.S_IMODE(os.lstat(os.path.join(d, ".lock")).st_mode) == 0o600
      and os.path.getsize(os.path.join(d, ".lock")) == 0)
check("classification with .lock already present is still empty", kind(d) == "empty")
os.makedirs(os.path.join(d, "transcripts", "arhiva"))
os.mkdir(os.path.join(d, "lost+found"))
put(os.path.join(d, "lost+found", "#123"), b"x")
check("lost+found (any content) + transcripts/arhiva (empty) → empty", kind(d) == "empty")
put(os.path.join(d, "keys.wtk.tmp"), b"junk")
put(os.path.join(d, "master.key.tmp"), b"junk")
inv = with_lock(d, K.classify)
check("bootstrap leftovers keep empty", inv.kind == "empty" and set(inv.leftovers) == {"keys.wtk.tmp", "master.key.tmp"})
put(os.path.join(d, "master.key"), b"x")
check("leftover master.key keeps empty (in_volume flagged)", with_lock(d, K.classify).in_volume)
d = fresh()
os.makedirs(os.path.join(d, "transcripts", "arhiva"))
put(os.path.join(d, "transcripts", "arhiva", "old.out"), b"x")
check("transcripts/arhiva with a file → ambiguous", kind(d) == "ambiguous")
d = fresh()
os.makedirs(os.path.join(d, "transcripts", "other"))
check("transcripts with another subdir → ambiguous", kind(d) == "ambiguous")
d = fresh()
put(os.path.join(d, "webterm.db"), b"x")
inv = with_lock(d, K.classify)
check("data without secret → ambiguous, names the entry", inv.kind == "ambiguous" and "webterm.db" in inv.reason)
d = legacy_dir()
check("secret (32 B) + data → legacy", kind(d) == "legacy")
os.mkdir(os.path.join(d, "restore-pending"))
put(os.path.join(d, ".restore-flag"), b"")
inv = with_lock(d, K.classify)
check("legacy + 3.7 staging → legacy, staged_restore", inv.kind == "legacy" and inv.staged_restore)
d = fresh()
put(os.path.join(d, "secret"), SECRET[:31])
check("secret of 31 bytes → ambiguous", kind(d) == "ambiguous")
d = fresh()
os.symlink(put(os.path.join(fresh("t"), "s"), SECRET), os.path.join(d, "secret"))
check("secret as a symlink → ambiguous", kind(d) == "ambiguous")
d = fresh()
os.mkdir(os.path.join(d, "secret"))
check("secret as a directory → ambiguous", kind(d) == "ambiguous")
d = fresh()
put(os.path.join(d, "keys.wtk"), b"anything")
check("keys.wtk present → protected (content not judged by classify)", kind(d) == "protected")
put(os.path.join(d, "master.key"), b"x")
put(os.path.join(d, "secret"), SECRET)
inv = with_lock(d, K.classify)
check("protected + secret WITHOUT migrating.wtm → ambiguous (not a state of our migration)",
      inv.kind == "ambiguous" and "migrating.wtm" in inv.reason)
put(os.path.join(d, "migrating.wtm"), b"x")
inv = with_lock(d, K.classify)
check("protected + master.key + secret + marker → in_volume + secret_leftover + migrating",
      inv.kind == "protected" and inv.in_volume and inv.secret_leftover and inv.migrating)
d = fresh()
os.symlink("/etc/hostname", os.path.join(d, "keys.wtk"))
check("keys.wtk as a symlink → ambiguous", kind(d) == "ambiguous")
d = fresh()
os.mkdir(os.path.join(d, "keys.wtk"))
check("keys.wtk as a directory → ambiguous", kind(d) == "ambiguous")
d = fresh()
os.mkfifo(os.path.join(d, "master.key"))
check("master.key as a FIFO → ambiguous", kind(d) == "ambiguous")
d = fresh()
put(os.path.join(d, "erasures.wtj"), b"x")
check("erasures.wtj without keys.wtk → ambiguous", kind(d) == "ambiguous")
d = legacy_dir()
put(os.path.join(d, "erasures.wtj"), b"x")
check("legacy + a new-format marker → ambiguous", kind(d) == "ambiguous")
d = fresh()
os.mkdir(os.path.join(d, ".restore"))
check(".restore/ without keys.wtk → ambiguous", kind(d) == "ambiguous")
d = fresh()
os.mkdir(os.path.join(d, "restore-pending"))
check("staged restore in an otherwise empty dir → ambiguous", kind(d) == "ambiguous")
for label, rel in (("top-level .wtd segment", "seg.wtd"), ("top-level .wt* family name", "x.wtq"),
                   ("transcripts/*.wtx", "transcripts/s1.wtx"), ("transcripts/arhiva/*.idx", "transcripts/arhiva/s0.idx"),
                   ("transcripts/*.wtd", "transcripts/s1.wtd"), ("migrating.wtm alone", "migrating.wtm")):
    d = legacy_dir()
    put(os.path.join(d, rel), b"x")
    inv = with_lock(d, K.classify)
    check(f"legacy + reserved new-format name ({label}) → ambiguous, never legacy",
          inv.kind == "ambiguous" and os.path.basename(rel) in inv.reason)
d = legacy_dir()
os.makedirs(os.path.join(d, "backups"))
put(os.path.join(d, "backups", "webterm-1.wtsnap"), b"x")
put(os.path.join(d, "transcripts", "arhiva", "old.cast"), b"x")
check("legacy + 3.7 backups/*.wtsnap and archived .cast → still legacy", kind(d) == "legacy")
d = legacy_dir()
before = snapshot(d, skip_lock=True)
for _ in range(2):
    with_lock(d, K.classify)
check("classify is read-only", snapshot(d, skip_lock=True) == before)

# ── lock ─────────────────────────────────────────────────────────────────────
print("lock")
d = fresh()
lock = K.acquire_lock(d)
check("second acquire in the same process → locked", raises(lambda: K.acquire_lock(d), K.LockError, "locked"))
code = ("import sys; sys.path.insert(0, %r)\nfrom app import keys\n"
        "try:\n    keys.acquire_lock(%r)\nexcept keys.LockError as e:\n    print(e.reason); sys.exit(3)\n"
        "sys.exit(0)") % (GW, d)
cp = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
check("a second process is refused (locked)", cp.returncode == 3 and cp.stdout.strip() == "locked")
check("a refused boot of a second process changes nothing", raises(lambda: boot(d, env_file(MK1)), K.LockError, "locked")
      and not os.path.exists(os.path.join(d, "keys.wtk")))
lock.release()
cp = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
check("after release a second process gets the lock", cp.returncode == 0)
d = fresh()
target = os.path.join(fresh("t"), "victim")
os.symlink(target, os.path.join(d, ".lock"))
check(".lock as a symlink → refused, target not created",
      raises(lambda: K.acquire_lock(d), K.LockError, "lock-not-regular") and not os.path.exists(target))
d = fresh()
os.mkdir(os.path.join(d, ".lock"))
check(".lock as a directory → refused", raises(lambda: K.acquire_lock(d), K.LockError, "lock-not-regular"))
check("missing data directory → refused", raises(lambda: K.acquire_lock(os.path.join(ROOT, "nope")),
                                                 K.LockError, "data-dir-unavailable"))
for mode in (0o777, 0o775, 0o757):
    d = fresh()
    os.chmod(d, mode)
    check(f"DATA_DIR mode {oct(mode)} (group/world-writable) → refused, nothing created",
          raises(lambda: K.acquire_lock(d), K.LockError, "data-dir-bad-mode") and os.listdir(d) == [])
d = fresh()
put(os.path.join(d, ".lock"), b"", 0o666)
check(".lock group/world-writable → refused, not removed",
      raises(lambda: K.acquire_lock(d), K.LockError, "lock-bad-mode") and os.path.exists(os.path.join(d, ".lock")))
d = fresh()
put(os.path.join(d, ".lock"), b"", 0o644)
check(".lock 0644 is accepted (not writable by others)", with_lock(d, K.classify).kind == "empty")
if os.geteuid() == 0:
    d = fresh()
    os.chown(d, 54321, 54321)
    check("DATA_DIR owned by another user → refused", raises(lambda: K.acquire_lock(d), K.LockError, "data-dir-bad-owner"))
    d = fresh()
    put(os.path.join(d, ".lock"), b"")
    os.chown(os.path.join(d, ".lock"), 54321, 54321)
    check(".lock owned by another user → refused", raises(lambda: K.acquire_lock(d), K.LockError, "lock-bad-owner"))
else:
    print("  (skip owner tests: not root)")

# ── key files and encodings ──────────────────────────────────────────────────
print("key sources")
good = base64.b64encode(MK1)
check("valid key file", K.read_key_file(keyfile(MK1)) == MK1)
check("no trailing newline is fine", K.read_key_file(keyfile(MK1, content=good)) == MK1)
for label, content in (("two newlines", good + b"\n\n"), ("CRLF", good + b"\r\n"), ("leading space", b" " + good),
                       ("trailing space", good + b" "), ("31 bytes", base64.b64encode(MK1[:31])),
                       ("33 bytes", base64.b64encode(MK1 + b"x")), ("no padding", good.rstrip(b"=")),
                       ("url-safe alphabet", base64.urlsafe_b64encode(b"\xfb" * 32)),
                       ("non-canonical unused bits", good[:42] + bytes([good[42] + 1]) + b"="),
                       ("raw 32 bytes", MK1), ("trailing garbage", good + b"\nX"), ("empty", b"")):
    check(f"key file refused: {label}", raises(lambda c=content: K.read_key_file(keyfile(MK1, content=c)),
                                               K.KeySourceError, "bad-encoding"))
check("key file oversized → too-large", raises(lambda: K.read_key_file(keyfile(MK1, content=good + b"\n" * 300)),
                                              K.KeySourceError, "too-large"))
p = keyfile(MK1)
ln = p + ".lnk"
os.symlink(p, ln)
check("key file symlink → symlink", raises(lambda: K.read_key_file(ln), K.KeySourceError, "symlink"))
check("key file is a directory → not-regular", raises(lambda: K.read_key_file(fresh("kd")), K.KeySourceError, "not-regular"))
fifo = os.path.join(fresh("kf"), "fifo")
os.mkfifo(fifo, 0o600)
check("key file is a FIFO → not-regular (does not block)", raises(lambda: K.read_key_file(fifo), K.KeySourceError, "not-regular"))
check("mode 0640 → bad-mode", raises(lambda: K.read_key_file(keyfile(MK1, 0o640)), K.KeySourceError, "bad-mode"))
check("mode 0604 → bad-mode", raises(lambda: K.read_key_file(keyfile(MK1, 0o604)), K.KeySourceError, "bad-mode"))
check("mode 0620 (group-writable) → bad-mode", raises(lambda: K.read_key_file(keyfile(MK1, 0o620)), K.KeySourceError, "bad-mode"))
check("mode 0400 is fine", K.read_key_file(keyfile(MK1, 0o400)) == MK1)
if os.geteuid() == 0:
    p = keyfile(MK1)
    os.chown(p, 54321, 54321)
    check("owner neither us nor root → bad-owner", raises(lambda: K.read_key_file(p), K.KeySourceError, "bad-owner"))
else:
    print("  (skip owner test: not root)")
check("missing key file → missing", raises(lambda: K.read_key_file(os.path.join(ROOT, "none")), K.KeySourceError, "missing"))
check("env value decoded", K.decode_key_text(good.decode(), "env") == MK1)
check("env value non-ASCII refused", raises(lambda: K.decode_key_text("ă" * 44, "env"), K.KeySourceError, "bad-encoding"))
try:
    K.read_key_file(keyfile(MK1, 0o644))
    msg = ""
except K.KeySourceError as e:
    msg = str(e)
check("errors never carry the key text", msg and good.decode() not in msg and good.decode()[:20] not in msg)
r = K.ResolvedKey("env", MK1)
check("ResolvedKey repr hides the key", MK1.hex() not in repr(r) and repr(MK1) not in repr(r))


def resolve(d, env, default=NODEF):
    return with_lock(d, lambda lk: K.resolve_master_key(env, lk, K.classify(lk), default))


d = fresh()
check("file + env → conflict", raises(lambda: resolve(d, {K.ENV_KEY_FILE: keyfile(MK1), K.ENV_KEY_VALUE: good.decode()}),
                                      K.KeySourceError, "conflict"))
check("in-volume + file → conflict", raises(lambda: resolve(d, {K.ENV_KEY_FILE: keyfile(MK1), K.ENV_IN_VOLUME: "1"}),
                                            K.KeySourceError, "conflict"))
check("WEBTERM_KEY_IN_VOLUME=yes → bad-value", raises(lambda: resolve(d, {K.ENV_IN_VOLUME: "yes"}), K.KeySourceError, "bad-value"))
check("empty / whitespace variables count as unset", resolve(d, {K.ENV_KEY_FILE: "", K.ENV_KEY_VALUE: "  ", K.ENV_IN_VOLUME: "0"}) is None)
check("empty volume, no source, default absent → None", resolve(d, {}) is None)
rk = resolve(d, {}, keyfile(MK1))
check("default file present → default-file", rk.source == "default-file" and rk.mk == MK1)
check("default file present but invalid → refused", raises(lambda: resolve(d, {}, keyfile(MK1, 0o644)), K.KeySourceError, "bad-mode"))
check("configured file missing → refused", raises(lambda: resolve(d, {K.ENV_KEY_FILE: os.path.join(ROOT, "x")}),
                                                  K.KeySourceError, "missing"))
check("configured env invalid → refused", raises(lambda: resolve(d, {K.ENV_KEY_VALUE: "abc"}), K.KeySourceError, "bad-encoding"))
check("explicit file wins over the default path", resolve(d, env_file(MK2), keyfile(MK1)).mk == MK2)
rk = resolve(d, {K.ENV_IN_VOLUME: "1"})
check("in-volume on an empty dir → volume, to be generated", rk.source == "volume" and rk.mk is None)
# L1: strip() decide doar „setat”; valoarea originală trece prin aceleaşi reguli ca fişierul
for label, v in (("leading space", " " + good.decode()), ("trailing space", good.decode() + " "),
                 ("CRLF", good.decode() + "\r\n"), ("two newlines", good.decode() + "\n\n"), ("tab", good.decode() + "\t")):
    check(f"env value refused: {label}", raises(lambda v=v: resolve(d, {K.ENV_KEY_VALUE: v}), K.KeySourceError, "bad-encoding"))
check("env value with one trailing \\n is fine", resolve(d, {K.ENV_KEY_VALUE: good.decode() + "\n"}).mk == MK1)
rk = resolve(d, {K.ENV_KEY_VALUE: base64.b64encode(MK2).decode()}, keyfile(MK1))
check("default path present + explicit env → env wins, no conflict (default is only a fallback)",
      rk.source == "env" and rk.mk == MK2)
check("key file path with a trailing space is not trimmed → missing",
      raises(lambda: resolve(d, {K.ENV_KEY_FILE: keyfile(MK1) + " "}), K.KeySourceError, "missing"))

# ── bootstrap ────────────────────────────────────────────────────────────────
print("bootstrap")
d = fresh()
check("empty + no source → refused, nothing but .lock",
      refused_twice_identical(d, {}, "no-source") and sorted(os.listdir(d)) == [".lock"])
d = fresh()
put(os.path.join(d, "keys.wtk.tmp"), b"junk from a crash")
env1 = env_file(MK1)
r = boot_ok(d, env1)
mpath = os.path.join(d, "keys.wtk")
check("bootstrap with an external key → protected / file", r.state.mode == "protected" and r.state.source == "file")
check("bootstrap: keys.wtk 0600, leftover tmp gone", stat.S_IMODE(os.lstat(mpath).st_mode) == 0o600
      and not os.path.exists(mpath + ".tmp"))
check("bootstrap keyring: epoch 1, KWK+SNK+FK, no legacy, no DBK",
      r.keyring.epoch == 1 and r.keyring.snk and r.keyring.fk and r.keyring.fk_legacy is None and r.keyring.dbk is None)
check("BootResult repr hides keys", r.keyring.kwk.hex() not in repr(r) and MK1.hex() not in repr(r))
r2 = boot_ok(d, env1)
check("second boot opens the same keyring", r2.keyring.installation_id == r.keyring.installation_id
      and r2.keyring.kwk == r.keyring.kwk)
check("protected + wrong key twice → refused, byte-identical", refused_twice_identical(d, env_file(MK2), "wrong-key", K.WrongKey))
check("protected + no source (default absent) → refused, byte-identical", refused_twice_identical(d, {}, "missing"))
check("protected + configured file missing → refused", refused_twice_identical(d, {K.ENV_KEY_FILE: os.path.join(ROOT, "gone")}, "missing"))
check("protected + key via the default path", boot_ok(d, {}, default_key_file=keyfile(MK1)).state.source == "default-file")
check("external file → key_location says not verified off-host",
      boot_ok(d, env1).state.key_location == "external (not verified off-host)")
# H3: un fişier-cheie în arborele de date nu e „protected”
inside = put(os.path.join(d, "not-a-key-name"), base64.b64encode(MK1) + b"\n")
check("key file at an arbitrary name inside DATA_DIR → refused, byte-identical",
      refused_twice_identical(d, {K.ENV_KEY_FILE: inside}, "key-in-data-dir"))
os.makedirs(os.path.join(d, "transcripts", "arhiva"), exist_ok=True)
deep = put(os.path.join(d, "transcripts", "arhiva", "k"), base64.b64encode(MK1) + b"\n")
check("key file in a subdirectory of DATA_DIR → refused", refused_twice_identical(d, {K.ENV_KEY_FILE: deep}, "key-in-data-dir"))
via = os.path.join(fresh("t"), "ln")
os.symlink(d, via)
check("key file reached through a symlinked directory → refused (no symlink anywhere in the key path)",
      refused_twice_identical(d, {K.ENV_KEY_FILE: os.path.join(via, "not-a-key-name")}, "symlink"))
check("default path inside DATA_DIR → refused", refused_twice_identical(d, {}, "key-in-data-dir", default_key_file=inside))
try:
    boot(d, {K.ENV_KEY_FILE: inside})
    msg = ""
except K.KeySourceError as e:
    msg = str(e)
check("the refusal names the explicit opt-out", "WEBTERM_KEY_IN_VOLUME=1" in msg)
os.unlink(inside)
os.unlink(deep)
dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
other_view = K.ProcessLock(os.path.join(ROOT, "elsewhere-view"), dfd, None)  # ca un bind mount: altă cale, acelaşi inode
os.makedirs(os.path.join(d, "sub"))
kp = put(os.path.join(d, "sub", "mk"), base64.b64encode(MK1) + b"\n")
check("inode ancestry catches DATA_DIR seen under another path (bind-mount view)",
      raises(lambda: K.check_outside_data_dir(other_view, kp, "x"), K.KeySourceError, "key-in-data-dir"))
check("a key file outside the data tree passes the ancestry check", K.check_outside_data_dir(other_view, keyfile(MK1), "x") is None)
os.close(dfd)
shutil.rmtree(os.path.join(d, "sub"))
# M3 (recheck): lanț de fd-uri fixate; niciun symlink nicăieri în calea cheii
real = fresh("kp")
put(os.path.join(real, "mk"), base64.b64encode(MK1) + b"\n")
lnk = os.path.join(fresh("t"), "lnk")
os.symlink(real, lnk)
check("key file outside DATA_DIR but behind a symlinked parent → refused (symlink)",
      raises(lambda: K.read_key_file(os.path.join(lnk, "mk")), K.KeySourceError, "symlink")
      and refused_twice_identical(d, {K.ENV_KEY_FILE: os.path.join(lnk, "mk")}, "symlink"))
check("'..' in a key path → refused", raises(lambda: K.read_key_file(real + "/../" + os.path.basename(real) + "/mk"),
                                            K.KeySourceError, "unreadable"))
check("missing intermediate directory → missing", raises(lambda: K.read_key_file(os.path.join(real, "no", "mk")),
                                                         K.KeySourceError, "missing"))
check("intermediate component that is a file → not-regular",
      raises(lambda: K.read_key_file(os.path.join(real, "mk", "x")), K.KeySourceError, "not-regular"))


class SwapOS:
    """Rulează `fn` imediat după ce fișierul-cheie „mk” a fost deschis (relativ la un dir fd):
    exact intervalul în care vechiul cod re-rezolva calea pentru verificarea locației."""

    def __init__(self, fn):
        self.fn, self.done = fn, False

    def __getattr__(self, n):
        real = getattr(os, n)
        if n != "open":
            return real

        def w(*a, **kw):
            fd = real(*a, **kw)
            if not self.done and a[0] == "mk" and kw.get("dir_fd") is not None:
                self.done = True
                self.fn()
            return fd
        return w


dv = fresh()
os.makedirs(os.path.join(dv, "sub"))
put(os.path.join(dv, "sub", "mk"), base64.b64encode(MK1) + b"\n")


def swap_out():
    # DATA_DIR se mută; la vechea cale apare un fișier-cheie „din afară”
    os.rename(dv, dv + "-moved")
    os.makedirs(os.path.join(dv, "sub"))
    put(os.path.join(dv, "sub", "mk"), base64.b64encode(MK2) + b"\n")


lock = K.acquire_lock(dv)
sw = SwapOS(swap_out)
K.os = sw
try:
    ok = raises(lambda: K.read_key_file(os.path.join(dv, "sub", "mk"), subject="x", lock=lock), K.KeySourceError, "key-in-data-dir")
finally:
    K.os = os
    lock.release()
check("path swapped between opening the key and the location check → verdict on the opened file: refused",
      ok and sw.done)
r = boot_ok(d, {K.ENV_KEY_VALUE: good.decode()})
check("key in the environment → warned", "key-in-environment" in r.state.warnings)
check("protected + WEBTERM_KEY_IN_VOLUME=1 without master.key → refused",
      refused_twice_identical(d, {K.ENV_IN_VOLUME: "1"}, "missing"))
blob = open(mpath, "rb").read()
put(mpath, blob[:-1] + bytes([blob[-1] ^ 1]))
check("tampered keys.wtk → manifest-invalid, byte-identical", refused_twice_identical(d, env1, "manifest-invalid"))
put(mpath, b"\x00" * (kr.MAN_MAX_LEN + 1))
check("oversized keys.wtk → too-large", refused_twice_identical(d, env1, "too-large"))

d = fresh()
r = boot_ok(d, {K.ENV_IN_VOLUME: "1"})
vk = os.path.join(d, "master.key")
check("in-volume bootstrap → reduced, master.key 0600", r.state.mode == "reduced" and "key-in-volume" in r.state.warnings
      and stat.S_IMODE(os.lstat(vk).st_mode) == 0o600)
check("in-volume: next boot opens", boot_ok(d, {K.ENV_IN_VOLUME: "1"}).keyring.kwk == r.keyring.kwk)
check("master.key present without the opt-in → refused, byte-identical", refused_twice_identical(d, env1, "conflict")
      and refused_twice_identical(d, {}, "conflict"))
os.chmod(vk, 0o644)
check("master.key group/world readable → refused", refused_twice_identical(d, {K.ENV_IN_VOLUME: "1"}, "bad-mode"))

# crash at every bootstrap step, external and in-volume
for label, env in (("external", env1), ("in-volume", {K.ENV_IN_VOLUME: "1"})):
    steps = []
    boot_ok(fresh(), env, _crash_at=steps.append)
    ok = bool(steps)
    for s in steps:
        d = fresh()

        hook = crash_at(s)
        ok &= raises(lambda: boot(d, env, _crash_at=hook), Crash)
        k = kind(d)
        ok &= k in ("empty", "protected")
        if s == "keys.wtk:renamed":
            # rename nedurabil (fără fsync pe director): fişierul poate reveni la .tmp
            os.rename(os.path.join(d, "keys.wtk"), os.path.join(d, "keys.wtk.tmp"))
            ok &= kind(d) == "empty"
        r = boot_ok(d, env)
        ok &= r.keyring is not None and not os.path.exists(os.path.join(d, "keys.wtk.tmp"))
        ok &= boot_ok(d, env).keyring.installation_id == r.keyring.installation_id
    check(f"bootstrap ({label}): crash at each of {len(steps)} steps → next boot completes", ok)

# ── legacy migration ─────────────────────────────────────────────────────────
print("legacy migration")
d = legacy_dir()
before = snapshot(d, skip_lock=True)
r = boot_ok(d, {})
check("legacy + no source → legacy state, 3.7 key, nothing written",
      r.state.mode == "legacy" and r.legacy_key == SECRET and r.keyring is None and snapshot(d, skip_lock=True) == before)
check("legacy + migrate=False with a key → legacy, nothing written",
      boot_ok(d, env1, migrate=False).state.mode == "legacy" and snapshot(d, skip_lock=True) == before)
check("legacy + invalid configured key twice → refused, byte-identical",
      refused_twice_identical(d, {K.ENV_KEY_FILE: keyfile(MK1, 0o644)}, "bad-mode"))
check("legacy + default path present but invalid → refused", refused_twice_identical(d, {}, "bad-encoding",
                                                                                     default_key_file=keyfile(MK1, content=b"x")))
r = boot_ok(d, env1)
check("migration → protected, migrated, FK_legacy = old secret, secret removed",
      r.state.mode == "protected" and r.state.migrated and r.keyring.fk_legacy == SECRET
      and not os.path.exists(os.path.join(d, "secret")) and r.keyring.fk and r.keyring.snk)
check("migrated: data untouched", os.path.exists(os.path.join(d, "webterm.db")) and os.path.exists(os.path.join(d, "transcripts", "s1.out")))
check("migrated volume without a key never falls back → refused", refused_twice_identical(d, {}, "missing"))
check("migrated volume with the key opens", boot_ok(d, env1).keyring.fk_legacy == SECRET)
d = legacy_dir()
r = boot_ok(d, {K.ENV_IN_VOLUME: "1"})
check("legacy + in-volume opt-out → reduced, master.key written, secret removed",
      r.state.mode == "reduced" and os.path.exists(os.path.join(d, "master.key")) and not os.path.exists(os.path.join(d, "secret")))

MARK = "migrating.wtm"


def gone(d, *names):
    return not any(os.path.lexists(os.path.join(d, n)) for n in names)


for label, env in (("external", env1), ("in-volume", {K.ENV_IN_VOLUME: "1"})):
    steps = []
    boot_ok(legacy_dir(), env, _crash_at=steps.append)
    ok = all(x in steps for x in ("migrating.wtm:published", "migrate:verified", "secret:barrier", "secret:removed",
                                   "marker:removed"))
    ok &= steps.index("migrating.wtm:published") < steps.index("keys.wtk:renamed")
    for s in steps:
        d = legacy_dir()

        hook = crash_at(s)
        ok &= raises(lambda: boot(d, env, _crash_at=hook), Crash)
        sp = os.path.join(d, "secret")
        secret_ok = os.path.exists(sp) and open(sp, "rb").read() == SECRET
        inv = with_lock(d, K.classify)
        k = inv.kind
        man_ok = False
        if k == "protected":
            mk = MK1 if label == "external" else K.read_key_file(os.path.join(d, "master.key"))
            man_ok = kr.open_keyring_bytes(open(os.path.join(d, "keys.wtk"), "rb").read(), mk, kr.PROFILE_V1).fk_legacy == SECRET
        # niciodată „niciuna”: ori secret intact (legacy), ori manifest verificat cu FK_legacy = secret
        step_ok = (k == "legacy" and secret_ok) or (k == "protected" and man_ok)
        # markerul există de la publicarea lui până la ultimul pas; fără el nu există keys.wtk
        step_ok &= inv.migrating == os.path.exists(os.path.join(d, MARK))
        if k == "protected" and os.path.exists(sp):
            step_ok &= secret_ok and inv.migrating  # secretul nu dispare înainte de verificare
        if label == "external":
            if k == "protected":
                step_ok &= refused_twice_identical(d, env_file(MK2), "wrong-key", K.WrongKey)
                step_ok &= refused_twice_identical(d, {}, "missing")
            elif inv.migrating:
                # pre-commit: fără sursă NU se întoarce în legacy
                step_ok &= refused_twice_identical(d, {}, "migration-unfinished")
                step_ok &= refused_twice_identical(d, env_file(MK2), "wrong-key", K.WrongKey)
            else:
                step_ok &= boot_ok(d, {}).state.mode == "legacy"
        if s == "keys.wtk:renamed":
            # rename nedurabil: keys.wtk poate reveni la .tmp → pre-commit dovedit, reluabil
            os.rename(os.path.join(d, "keys.wtk"), os.path.join(d, "keys.wtk.tmp"))
            inv2 = with_lock(d, K.classify)
            step_ok &= inv2.kind == "legacy" and inv2.migrating
        if s == "migrating.wtm:renamed":
            os.rename(os.path.join(d, MARK), os.path.join(d, MARK + ".tmp"))
            inv2 = with_lock(d, K.classify)
            step_ok &= inv2.kind == "legacy" and not inv2.migrating
        pending = os.path.exists(os.path.join(d, MARK)) or os.path.exists(sp)
        r = boot_ok(d, env)
        step_ok &= r.keyring.fk_legacy == SECRET and gone(d, "secret", MARK) and kind(d) == "protected"
        step_ok &= r.state.migrated == pending  # „migrated” = acest boot a terminat migrarea
        if not step_ok:
            print(f"      (step {s} failed)")
        ok &= step_ok
    check(f"migration ({label}): crash at each of {len(steps)} steps → legacy, pre-commit or verified-protected, then completes", ok)

# H2: manifest pierdut DUPĂ publicare → niciodată legacy
for s in ("migrate:verified", "secret:barrier", "secret:unlinked", "marker:barrier"):
    d = legacy_dir()
    raises(lambda: boot(d, env1, _crash_at=crash_at(s)), Crash)
    os.unlink(os.path.join(d, "keys.wtk"))
    inv = with_lock(d, K.classify)
    check(f"crash at {s} + keys.wtk lost → ambiguous 'published but keys.wtk missing', refused with or without key",
          inv.kind == "ambiguous" and "keys.wtk missing" in inv.reason
          and refused_twice_identical(d, {}, "ambiguous") and refused_twice_identical(d, env1, "ambiguous"))
d = legacy_dir()
raises(lambda: boot(d, {K.ENV_IN_VOLUME: "1"}, _crash_at=crash_at("migrating.wtm:published")), Crash)
os.unlink(os.path.join(d, "master.key"))
check("pre-commit in-volume migration whose master.key vanished → refused, no new key generated",
      refused_twice_identical(d, {K.ENV_IN_VOLUME: "1"}, "missing") and gone(d, "master.key"))
d = legacy_dir()
raises(lambda: boot(d, env1, _crash_at=crash_at("migrating.wtm:published")), Crash)
put(os.path.join(d, "keys.wtk.tmp"), b"a different manifest")
check("pre-commit marker whose keys.wtk.tmp does not match → ambiguous", kind(d) == "ambiguous")
d = legacy_dir()
raises(lambda: boot(d, env1, _crash_at=crash_at("migrating.wtm:published")), Crash)
put(os.path.join(d, "secret"), hashlib.sha256(b"other").digest())
check("pre-commit marker with a different secret → ambiguous", kind(d) == "ambiguous")
d = legacy_dir()
raises(lambda: boot(d, env1, _crash_at=crash_at("migrate:verified")), Crash)
mp = os.path.join(d, MARK)
mb = open(mp, "rb").read()
put(mp, mb[:4] + b"\x00" * 16 + mb[20:])
check("protected + marker naming another installation → refused, byte-identical",
      refused_twice_identical(d, env1, "migration-marker-mismatch"))
put(mp, b"garbage")
check("protected + unparseable marker → refused", refused_twice_identical(d, env1, "marker-invalid"))
put(mp, mb)
lock = K.acquire_lock(d)
check("rotation refused while a migration is unfinished",
      raises(lambda: rot(lock, MK1, MK2), K.BootRefused, "migration-unfinished"))
lock.release()
check("restored marker → the migration finishes", boot_ok(d, env1).state.migrated and gone(d, "secret", MARK))

d = legacy_dir()


def stop_after_publish(x):
    if x == "migrate:verified":
        raise Crash(x)


raises(lambda: boot(d, env1, _crash_at=stop_after_publish), Crash)
put(os.path.join(d, "secret"), hashlib.sha256(b"other").digest())
check("protected + a DIFFERENT leftover secret → refused, byte-identical",
      refused_twice_identical(d, env1, "legacy-secret-mismatch"))

# ── fault injection (H1, M1) ─────────────────────────────────────────────────
print("I/O faults")


class FaultOS:
    """Înlocuieşte `os` în keys.py: delegă tot, jurnalizează open/write/close/fsync/rename/unlink/read
    (cu numele fişierului din spatele fd-ului) şi ridică OSError la regula armată."""
    WATCH = ("open", "write", "close", "fsync", "rename", "unlink", "read")

    def __init__(self, rules=()):
        self.rules = list(rules)
        self.fdname = {}
        self.log = []

    def __getattr__(self, n):
        real = getattr(os, n)
        if n not in self.WATCH:
            return real

        def wrapped(*a, **kw):
            target = self.fdname.get(a[0], "?") if n in ("write", "close", "fsync", "read") else a[0]
            self.log.append((n, target))
            for r in self.rules:
                if r["armed"] and r["fn"] == n and r["target"] == target:
                    r["armed"], r["hit"] = False, True
                    if n == "close":
                        os.close(a[0])
                        self.fdname.pop(a[0], None)
                    raise OSError(r["err"], os.strerror(r["err"]))
            res = real(*a, **kw)
            if n == "open":
                self.fdname[res] = a[0]
            elif n == "close":
                self.fdname.pop(a[0], None)
            return res
        return wrapped


def with_faults(d, env, rules, arm_at=None, crash=None):
    """Boot sub FaultOS; regula cu arm_at se armează când hook-ul vede pasul. → (kind | "ok", proxy)."""
    for r in rules:
        r.setdefault("err", errno.ENOSPC)
        r.setdefault("hit", False)
        r["armed"] = arm_at is None

    def hook(x):
        if x == arm_at:
            for r in rules:
                r["armed"] = True
        if crash and x == crash:
            raise Crash(x)
    proxy = FaultOS(rules)
    K.os = proxy
    try:
        try:
            boot(d, env, _crash_at=hook).lock.release()
            out = "ok"
        except K.BootRefused as e:
            out = e.kind
    finally:
        K.os = os
    return out, proxy


INC, CU = "operation-incomplete", "commit-unknown"
cases_boot = (("open keys.wtk.tmp", "open", "keys.wtk.tmp", None, INC), ("write keys.wtk.tmp", "write", "keys.wtk.tmp", None, INC),
              ("close keys.wtk.tmp", "close", "keys.wtk.tmp", None, INC), ("fsync keys.wtk.tmp", "fsync", "keys.wtk.tmp", None, INC),
              ("rename keys.wtk.tmp", "rename", "keys.wtk.tmp", None, INC),
              ("dir fsync after rename", "fsync", "DIR", "keys.wtk:renamed", CU),
              ("read-back of keys.wtk", "read", "keys.wtk", "keys.wtk:published", CU))
for label, fn, target, arm, want in cases_boot:
    d = fresh()
    rule = {"fn": fn, "target": d if target == "DIR" else target, "err": errno.EIO if fn != "write" else errno.ENOSPC}
    got, _ = with_faults(d, env1, [rule], arm)
    r = boot_ok(d, env1)
    check(f"bootstrap, {label} fails → {want}; next boot recovers",
          rule["hit"] and got == want and r.keyring is not None and boot_ok(d, env1).keyring.kwk == r.keyring.kwk
          and gone(d, "keys.wtk.tmp"))
d = fresh()
rule = {"fn": "write", "target": "master.key.tmp"}
got, _ = with_faults(d, {K.ENV_IN_VOLUME: "1"}, [rule])
check("bootstrap in-volume, write master.key.tmp ENOSPC → operation-incomplete; next boot recovers",
      rule["hit"] and got == INC and boot_ok(d, {K.ENV_IN_VOLUME: "1"}).state.mode == "reduced")

cases_mig = (("open keys.wtk.tmp", "open", "keys.wtk.tmp", None, INC, True),
             ("write migrating.wtm.tmp", "write", "migrating.wtm.tmp", None, INC, True),
             ("rename keys.wtk.tmp", "rename", "keys.wtk.tmp", None, INC, True),
             ("dir fsync after the marker", "fsync", "DIR", "migrating.wtm:renamed", INC, True),
             ("dir fsync after keys.wtk rename", "fsync", "DIR", "keys.wtk:renamed", CU, True),
             ("read-back of keys.wtk", "read", "keys.wtk", "keys.wtk:published", CU, True),
             ("dir fsync barrier before unlinking secret", "fsync", "DIR", "migrate:verified", CU, True),
             ("unlink secret", "unlink", "secret", None, CU, True),
             ("dir fsync after unlinking secret", "fsync", "DIR", "secret:unlinked", CU, False),
             ("unlink migrating.wtm", "unlink", "migrating.wtm", None, CU, False))
for label, fn, target, arm, want, secret_kept in cases_mig:
    d = legacy_dir()
    rule = {"fn": fn, "target": d if target == "DIR" else target, "err": errno.EIO}
    got, _ = with_faults(d, env1, [rule], arm)
    sp = os.path.join(d, "secret")
    kept = os.path.exists(sp) and open(sp, "rb").read() == SECRET
    r = boot_ok(d, env1)
    check(f"migration, {label} fails → {want}{', secret kept' if secret_kept else ''}; next boot finishes",
          rule["hit"] and got == want and (kept or not secret_kept) and r.keyring.fk_legacy == SECRET
          and gone(d, "secret", MARK) and kind(d) == "protected")

# H1: reluarea (protected + secret + marker) face fsync pe director ÎNAINTE de unlink şi după
for s in ("keys.wtk:renamed", "migrate:verified", "secret:barrier"):
    d = legacy_dir()
    raises(lambda: boot(d, env1, _crash_at=crash_at(s)), Crash)
    got, proxy = with_faults(d, env1, [])
    log = proxy.log
    iu = log.index(("unlink", "secret"))
    check(f"resume after a crash at {s}: dir fsync before unlinking secret and after it",
          got == "ok" and ("fsync", d) in log[:iu] and ("fsync", d) in log[iu:]
          and log.index(("unlink", MARK)) > iu and gone(d, "secret", MARK))
d = legacy_dir()
raises(lambda: boot(d, env1, _crash_at=crash_at("keys.wtk:renamed")), Crash)
before = snapshot(d, skip_lock=True)
rule = {"fn": "fsync", "target": d, "err": errno.EIO}
got, _ = with_faults(d, env1, [rule])
check("resume with an injected dir-fsync error → commit-unknown, secret kept, nothing changed",
      rule["hit"] and got == CU and snapshot(d, skip_lock=True) == before)
check("… and the next boot finishes the migration", boot_ok(d, env1).state.migrated and gone(d, "secret", MARK))
d = legacy_dir()
raises(lambda: boot(d, env1, _crash_at=crash_at("secret:unlinked")), Crash)
check("crash after unlinking secret (before its fsync) → protected + marker, next boot removes the marker",
      with_lock(d, K.classify).migrating and boot_ok(d, env1).state.migrated and gone(d, "secret", MARK))
try:
    boot(fresh(), {})
    kd = None
except K.BootRefused as e:
    kd = e.kind
check("a preflight refusal has kind invalid-key", kd == "invalid-key")


class ListdirFails:
    def __getattr__(self, n):
        if n == "listdir":
            def fail(*a, **kw):
                raise OSError(errno.EIO, "injected")
            return fail
        return getattr(os, n)


d = legacy_dir()
before = snapshot(d, skip_lock=True)
K.os = ListdirFails()
try:
    boot(d, env1)
    kd = None
except K.BootRefused as e:
    kd = (e.kind, e.reason, e.subject)
finally:
    K.os = os
check("Low 5: an OSError while listing DATA_DIR → kind preflight-io, nothing written, lock released",
      kd == ("preflight-io", "io-error", "EIO") and snapshot(d, skip_lock=True) == before and kind(d) == "legacy")

# ── High 1 (recheck): reluarea pre-commit e autentificată cu MK ──
print("pre-commit resume")


def precommit_dir():
    d = legacy_dir()
    raises(lambda: boot(d, env1, _crash_at=crash_at("migrating.wtm:published")), Crash)
    return d


def rd(d, n):
    with open(os.path.join(d, n), "rb") as f:
        return f.read()


d = precommit_dir()
inv = with_lock(d, K.classify)
tmpb, mb = rd(d, "keys.wtk.tmp"), rd(d, MARK)
r = boot_ok(d, env1)
check("pre-commit fixture is legacy + migrating; resume publishes EXACTLY the authenticated tmp (no new keyring)",
      inv.kind == "legacy" and inv.migrating and rd(d, "keys.wtk") == tmpb and r.keyring.installation_id == mb[4:20]
      and r.state.migrated and r.keyring.fk_legacy == SECRET and gone(d, "secret", MARK, "keys.wtk.tmp"))
# reproducerea recenzentului: doar MK id-ul din marker schimbat, tmp și hashuri intacte, altă MK
d = precommit_dir()
mb2 = rd(d, MARK)
put(os.path.join(d, MARK), mb2[:20] + kr.key_id(MK2) + mb2[36:])
check("marker MK id edited + another MK → migration-proof-invalid, byte-identical, no keys.wtk",
      with_lock(d, K.classify).migrating
      and refused_twice_identical(d, env_file(MK2), "migration-proof-invalid") and gone(d, "keys.wtk"))
check("… and with the original MK → refused as well (the marker no longer names it)",
      refused_twice_identical(d, env1, "migration-proof-invalid") and gone(d, "keys.wtk"))
# tmp consistent cu markerul (hashuri corecte) dar FK_legacy ≠ secret
d = precommit_dir()
inst = os.urandom(16)
envs = K._envelopes(MK1, os.urandom(32), snk=os.urandom(32), fk_legacy=hashlib.sha256(b"other").digest(), fk=os.urandom(32))
blob = kr.encode_manifest(kr.KeyManifest(inst, 1, kr.key_id(MK1), (), envs), MK1)
put(os.path.join(d, "keys.wtk.tmp"), blob)
put(os.path.join(d, MARK), K._marker_bytes(inst, kr.key_id(MK1), SECRET, blob))
check("tmp + marker consistent but FK_legacy ≠ secret → migration-proof-invalid, byte-identical",
      with_lock(d, K.classify).migrating and refused_twice_identical(d, env1, "migration-proof-invalid"))
# tmp care NU se deschide cu MK (alt MAC), marker care numește MK și hashul lui
d = precommit_dir()
bad = bytearray(rd(d, "keys.wtk.tmp"))
bad[-1] ^= 1
put(os.path.join(d, "keys.wtk.tmp"), bytes(bad))
put(os.path.join(d, MARK), rd(d, MARK)[:68] + hashlib.sha256(bytes(bad)).digest())
check("tmp with a broken MAC (marker re-hashed to match) → migration-proof-invalid, byte-identical",
      with_lock(d, K.classify).migrating and refused_twice_identical(d, env1, "migration-proof-invalid"))
# nicio dovadă ștearsă înainte de commit
d = precommit_dir()
got, proxy = with_faults(d, env1, [])
log = proxy.log
ir = log.index(("rename", "keys.wtk.tmp"))
check("resume: keys.wtk.tmp fsynced and renamed before any unlink of the proof (marker / tmp / secret)",
      got == "ok" and ("fsync", "keys.wtk.tmp") in log[:ir]
      and not any(e in log[:ir] for e in (("unlink", MARK), ("unlink", "keys.wtk.tmp"), ("unlink", "secret"))))
d = precommit_dir()
before = snapshot(d, skip_lock=True)
rule = {"fn": "fsync", "target": "keys.wtk.tmp", "err": errno.EIO}
got, _ = with_faults(d, env1, [rule])
check("resume, fsync of the proven tmp fails → operation-incomplete, nothing changed, next boot finishes",
      rule["hit"] and got == INC and snapshot(d, skip_lock=True) == before
      and boot_ok(d, env1).keyring.installation_id == rd(d, "keys.wtk")[8:24] and gone(d, "secret", MARK))
steps = []
boot_ok(precommit_dir(), env1, _crash_at=steps.append)
ok = "resume:proven" in steps and steps.index("resume:proven") < steps.index("keys.wtk:renamed")
for s in steps:
    d = precommit_dir()
    inst = rd(d, MARK)[4:20]
    hook = crash_at(s)
    ok &= raises(lambda: boot(d, env1, _crash_at=hook), Crash)
    ik = kind(d)
    ok &= ik in ("legacy", "protected") and (ik == "protected") == (s not in ("resume:proven",))
    r = boot_ok(d, env1)
    ok &= r.keyring.installation_id == inst and gone(d, "secret", MARK, "keys.wtk.tmp") and kind(d) == "protected"
check(f"resume: crash at each of {len(steps)} steps → pre-commit or protected, then completes with the SAME installation", ok)

# ── High 2 (recheck): artefacte amestecate ──
print("mixed artefacts")
for label, rel in (("transcripts/record.wtx", "transcripts/record.wtx"), ("top-level erasures.wtj", "erasures.wtj"),
                   ("transcripts/arhiva/s.wtd", "transcripts/arhiva/s.wtd"), ("top-level x.wtq", "x.wtq")):
    d = precommit_dir()
    put(os.path.join(d, rel), b"x")
    inv = with_lock(d, K.classify)
    check(f"pre-commit fixture + {label} → ambiguous, refused byte-identical with the right key",
          inv.kind == "ambiguous" and os.path.basename(rel) in inv.reason
          and refused_twice_identical(d, env1, "ambiguous") and gone(d, "keys.wtk"))
check("reserved namespace: one definition",
      K.is_reserved_name("keys.wtk") and K.is_reserved_name("migrating.wtm") and K.is_reserved_name(".restore")
      and K.is_reserved_name("erasures.wtj") and not K.is_reserved_name("keys.wtk.tmp") and not K.is_reserved_name("secret")
      and K.is_reserved_name("s.idx", "transcripts") and not K.is_reserved_name("s.idx")
      and not K.is_reserved_name("s1.out", "transcripts") and K.RESERVED_SCAN_DEPTH == 1)
d = legacy_dir()
os.makedirs(os.path.join(d, "transcripts", "a", "b"))
put(os.path.join(d, "transcripts", "a", "b", "x.wtx"), b"x")
check("documented depth: a reserved name deeper than RESERVED_SCAN_DEPTH is not inspected",
      with_lock(d, lambda lk: K.find_reserved(lk.dir_fd)) is None)
if os.geteuid() != 0:
    d = precommit_dir()
    ap = os.path.join(d, "transcripts", "arhiva")
    os.chmod(ap, 0)
    try:
        inv = with_lock(d, K.classify)
    finally:
        os.chmod(ap, 0o755)
    check("pre-commit + an unreadable transcripts subdirectory → ambiguous", inv.kind == "ambiguous" and "unreadable" in inv.reason)
else:
    print("  (skip unreadable-directory test: root reads everything)")

# ── staged restore ───────────────────────────────────────────────────────────
print("staged restore")
d = fresh()
boot_ok(d, env1)
os.makedirs(os.path.join(d, "restore-pending"))
put(os.path.join(d, "restore-pending", "webterm.db"), b"staged db")
put(os.path.join(d, ".restore-flag"), b"1")
os.makedirs(os.path.join(d, ".restore", "7"))
put(os.path.join(d, ".restore", "7", "keys.wtk"), b"staged manifest")
check("staged restore + wrong key → refused, staging byte-identical",
      refused_twice_identical(d, env_file(MK2), "wrong-key", K.WrongKey))
check("staged restore + missing key → refused, byte-identical", refused_twice_identical(d, {}, "missing"))
before = snapshot(d, skip_lock=True)
r = boot_ok(d, env1)
check("staged restore + right key → opens, flagged, staging untouched",
      r.state.staged_restore and snapshot(d, skip_lock=True) == before)
d = legacy_dir()
os.makedirs(os.path.join(d, "restore-pending"))
put(os.path.join(d, ".restore-flag"), b"1")
check("legacy + staging + invalid key → refused, byte-identical",
      refused_twice_identical(d, {K.ENV_KEY_VALUE: "nope"}, "bad-encoding"))

# ── leftover tmp ─────────────────────────────────────────────────────────────
print("leftover keys.wtk.tmp")
d = fresh()
boot_ok(d, env1)
put(os.path.join(d, "keys.wtk.tmp"), b"half a manifest")
before = snapshot(d, skip_lock=True)
r = boot_ok(d, env1)
check("protected + leftover tmp: boot opens and does not touch it", r.keyring and snapshot(d, skip_lock=True) == before)
check("protected + leftover tmp + wrong key → refused, byte-identical",
      refused_twice_identical(d, env_file(MK2), "wrong-key", K.WrongKey))
lock = K.acquire_lock(d)
ring2 = rot(lock, MK1, MK2)
lock.release()
check("the next publication removes the leftover tmp", ring2.epoch == 2 and not os.path.exists(os.path.join(d, "keys.wtk.tmp")))

# ── publication rules ────────────────────────────────────────────────────────
print("publication")
d = fresh()
r = boot_ok(d, env1)
cur = open(os.path.join(d, "keys.wtk"), "rb").read()
m = kr._parse_manifest_unauthenticated(cur)


def remanifest(epoch=None, inst=None, mk=MK1):
    return kr.encode_manifest(kr.KeyManifest(inst or m.installation_id, epoch or m.epoch, kr.key_id(mk), (),
                                             m.envelopes), mk)


def publish(blob, mk=MK1, prev=MK1):
    return with_lock(d, lambda lk: K.publish_manifest(lk, blob, mk, previous_mk=prev))


before = snapshot(d, skip_lock=True)
check("same epoch → refused", raises(lambda: publish(remanifest(1)), K.BootRefused, "epoch-not-increasing"))
check("other installation id → refused", raises(lambda: publish(remanifest(2, b"\x01" * 16)), K.BootRefused, "installation-mismatch"))
check("no predecessor given but keys.wtk exists → refused", raises(lambda: publish(remanifest(2), prev=None), K.BootRefused, "manifest-exists"))
check("predecessor opened with the wrong MK → refused", raises(lambda: publish(remanifest(2), prev=MK2), K.WrongKey, "wrong-key"))
check("blob that does not open with its MK → refused", raises(lambda: publish(remanifest(2), mk=MK2), K.BootRefused, "manifest-invalid"))
check("refused publications change nothing", snapshot(d, skip_lock=True) == before)
ring = publish(remanifest(5))
check("higher epoch publishes and reads back", ring.epoch == 5 and open(os.path.join(d, "keys.wtk"), "rb").read() == remanifest(5))
d2 = fresh()
put(os.path.join(d2, "keys.wtk.tmp"), b"x")
os.chmod(os.path.join(d2, "keys.wtk.tmp"), 0o644)
lk = K.acquire_lock(d2)
check("publish with no predecessor on an empty dir → 0600, tmp replaced",
      K.publish_manifest(lk, remanifest(1), MK1).epoch == 1 and stat.S_IMODE(os.lstat(os.path.join(d2, "keys.wtk")).st_mode) == 0o600)
lk.release()
d2 = fresh()
victim = os.path.join(fresh("t"), "victim")
os.symlink(victim, os.path.join(d2, "keys.wtk.tmp"))
lk = K.acquire_lock(d2)
K.publish_manifest(lk, remanifest(1), MK1)
lk.release()
check("a leftover tmp symlink is removed, never followed", os.path.isfile(os.path.join(d2, "keys.wtk"))
      and not os.path.islink(os.path.join(d2, "keys.wtk")) and not os.path.lexists(os.path.join(d2, "keys.wtk.tmp"))
      and not os.path.exists(victim))

# ── rotation ─────────────────────────────────────────────────────────────────
print("rotation")
d = legacy_dir()
r1 = boot_ok(d, env1).keyring
old_blob = open(os.path.join(d, "keys.wtk"), "rb").read()
lock = K.acquire_lock(d)
r2 = rot(lock, MK1, MK2)
lock.release()
new_blob = open(os.path.join(d, "keys.wtk"), "rb").read()
mo, mn = kr._parse_manifest_unauthenticated(old_blob), kr._parse_manifest_unauthenticated(new_blob)
check("rotation: same installation, epoch + 1, new MK id, old id retired",
      r2.installation_id == r1.installation_id and r2.epoch == r1.epoch + 1 and r2.mk_id == kr.key_id(MK2)
      and r2.retired_mk_ids == (kr.key_id(MK1),))
check("rotation: stable keys unchanged", (r2.kwk, r2.snk, r2.fk, r2.fk_legacy) == (r1.kwk, r1.snk, r1.fk, r1.fk_legacy))
check("rotation: KWK-wrapped envelopes byte-identical, MK-wrapped re-wrapped",
      all(mo.envelope(t) == mn.envelope(t) for t in (kr.KT_FK_LEGACY, kr.KT_FK))
      and all(mo.envelope(t) != mn.envelope(t) for t in (kr.KT_KWK, kr.KT_SNK)))
check("after rotation the old MK is refused", refused_twice_identical(d, env1, "wrong-key", K.WrongKey))
check("after rotation the new MK opens", boot_ok(d, env_file(MK2)).keyring.epoch == 2)
lock = K.acquire_lock(d)
r3 = rot(lock, MK2, MK3)
check("second rotation: both old ids retired, sorted", r3.retired_mk_ids == tuple(sorted((kr.key_id(MK1), kr.key_id(MK2)))))
check("rotation back to a retired MK drops it from the retired list",
      rot(lock, MK3, MK1).retired_mk_ids == tuple(sorted((kr.key_id(MK2), kr.key_id(MK3)))))
check("rotation with the same key → refused", raises(lambda: rot(lock, MK1, MK1), K.BootRefused, "same-key"))
check("rotation with a wrong old MK → refused", raises(lambda: rot(lock, MK2, MK3), K.WrongKey, "wrong-key"))
check("rotation with a short key → refused", raises(lambda: rot(lock, MK1, MK2[:31]), K.BootRefused, "bad-key"))
lock.release()
d = fresh()
boot_ok(d, {K.ENV_IN_VOLUME: "1"})
lock = K.acquire_lock(d)
check("rotation with the key in the volume → unsupported",
      raises(lambda: rot(lock, K.read_key_file(os.path.join(d, "master.key")), MK2), K.BootRefused, "unsupported"))
lock.release()

# M2: MK-ul aşteptat se citeşte fără cheie; noua cheie e persistată şi verificată înainte de commit
d = fresh()
boot_ok(d, env1)
lock = K.acquire_lock(d)
check("expected_mk_id reads keys.wtk without the key (and while the lock is held)",
      K.expected_mk_id(d) == kr.key_id(MK1).hex() == K.key_file_mk_id(keyfile(MK1)))
before = snapshot(d, skip_lock=True)
check("rotation with a new key file holding another key → refused, nothing published",
      raises(lambda: K.rotate_master_key(lock, MK1, MK2, new_key_file=keyfile(MK3)), K.BootRefused, "new-key-not-persisted")
      and snapshot(d, skip_lock=True) == before)
check("rotation with a missing new key file → refused",
      raises(lambda: K.rotate_master_key(lock, MK1, MK2, new_key_file=os.path.join(ROOT, "nope")), K.KeySourceError, "missing"))
inside = put(os.path.join(d, "newkey"), base64.b64encode(MK2) + b"\n")
check("rotation with the new key file inside DATA_DIR → refused",
      raises(lambda: K.rotate_master_key(lock, MK1, MK2, new_key_file=inside), K.KeySourceError, "key-in-data-dir"))
os.unlink(inside)
K.rotate_master_key(lock, MK1, MK2, new_key_file=keyfile(MK2))
lock.release()
check("rotation with the persisted new key → expected_mk_id is the new id", K.expected_mk_id(d) == kr.key_id(MK2).hex())
check("expected_mk_id on a volume without keys.wtk → refused", raises(lambda: K.expected_mk_id(fresh()), K.BootRefused, "missing"))

# M4 (recheck): new_key_file obligatoriu, fsync pe fișier și pe directorul lui înainte de publicare
d = fresh()
boot_ok(d, env1)
before = snapshot(d, skip_lock=True)
lock = K.acquire_lock(d)
check("rotation without new_key_file → TypeError (required parameter)", raises(lambda: K.rotate_master_key(lock, MK1, MK2), TypeError))
check("rotation with new_key_file=None → refused (no-source)",
      raises(lambda: K.rotate_master_key(lock, MK1, MK2, None), K.KeySourceError, "no-source"))
nkr = fresh("nk")
put(os.path.join(nkr, "mk"), base64.b64encode(MK2) + b"\n")
nkl = os.path.join(fresh("t"), "lnk")
os.symlink(nkr, nkl)
check("rotation with a new key file behind a symlinked parent → refused (symlink)",
      raises(lambda: K.rotate_master_key(lock, MK1, MK2, os.path.join(nkl, "mk")), K.KeySourceError, "symlink"))
lock.release()
check("refused rotations change nothing", snapshot(d, skip_lock=True) == before)
nk = keyfile(MK2)
proxy = FaultOS()
K.os = proxy
try:
    with_lock(d, lambda lk: K.rotate_master_key(lk, MK1, MK2, nk))
finally:
    K.os = os
log = proxy.log
ir = log.index(("rename", "keys.wtk.tmp"))
check("rotation fsyncs the new key file and its directory before publishing",
      ("fsync", "mk") in log[:ir] and ("fsync", os.path.basename(os.path.dirname(nk))) in log[:ir]
      and boot_ok(d, {K.ENV_KEY_FILE: nk}).keyring.mk_id == kr.key_id(MK2))
d = fresh()
boot_ok(d, env1)
before = snapshot(d, skip_lock=True)
proxy = FaultOS([{"fn": "fsync", "target": "mk", "err": errno.EIO, "armed": True, "hit": False}])
K.os = proxy
try:
    ok = raises(lambda: with_lock(d, lambda lk: K.rotate_master_key(lk, MK1, MK2, keyfile(MK2))), K.BootRefused,
                "new-key-not-durable")
finally:
    K.os = os
check("fsync of the new key file fails → new-key-not-durable, nothing published, old MK opens",
      ok and snapshot(d, skip_lock=True) == before and boot_ok(d, env1).keyring.epoch == 1)

steps = []
d = fresh()
boot_ok(d, env1)
with_lock(d, lambda lk: rot(lk, MK1, MK2, _crash_at=steps.append))
ok = bool(steps)
for s in steps:
    d = fresh()
    r0 = boot_ok(d, env1).keyring

    hook = crash_at(s)
    ok &= raises(lambda: with_lock(d, lambda lk: rot(lk, MK1, MK2, _crash_at=hook)), Crash)
    opens = []
    for mk in (MK1, MK2):
        try:
            opens.append((mk, boot_ok(d, env_file(mk)).keyring))
        except K.WrongKey:
            pass
    ok &= len(opens) == 1 and opens[0][1].kwk == r0.kwk and opens[0][1].fk == r0.fk
    ok &= (opens[0][0] == MK2) == (s in ("keys.wtk:renamed", "keys.wtk:published"))
check(f"rotation: crash at each of {len(steps)} steps → exactly one of old/new opens, same stable keys", ok)

shutil.rmtree(ROOT, ignore_errors=True)
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
