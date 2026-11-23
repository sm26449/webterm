"""Key sources, boot contract, process lock and atomic keys.wtk publication
(gateway/app/keys.py, ENCRYPTION-AT-REST.md §12.9): inventory classes, the lock (same process and
a child process), key-file checks on the same fd, source precedence and conflicts, bootstrap,
3.7 migration and MK rotation with a crash at every publication step, and the guarantee that a
refused boot (wrong / missing key, also with a staged restore) leaves the data directory
byte-identical. Temp directories only; never /run/secrets, never a real data/secret.

Hook-ul _crash_at ridică Crash la pasul ales: starea de pe disc e exact cea de după acel pas."""
import base64
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
check("protected + master.key + secret → in_volume + secret_leftover", inv.in_volume and inv.secret_leftover)
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

for label, env in (("external", env1), ("in-volume", {K.ENV_IN_VOLUME: "1"})):
    steps = []
    boot_ok(legacy_dir(), env, _crash_at=steps.append)
    ok = "migrate:verified" in steps and "secret:removed" in steps
    for s in steps:
        d = legacy_dir()

        hook = crash_at(s)
        ok &= raises(lambda: boot(d, env, _crash_at=hook), Crash)
        sp = os.path.join(d, "secret")
        secret_ok = os.path.exists(sp) and open(sp, "rb").read() == SECRET
        k = kind(d)
        man_ok = False
        if k == "protected":
            mk = MK1 if label == "external" else K.read_key_file(os.path.join(d, "master.key"))
            man_ok = kr.open_keyring_bytes(open(os.path.join(d, "keys.wtk"), "rb").read(), mk, kr.PROFILE_V1).fk_legacy == SECRET
        # niciodată „niciuna”: ori secret intact (legacy), ori manifest verificat cu FK_legacy = secret
        ok &= (k == "legacy" and secret_ok) or (k == "protected" and man_ok)
        if k == "protected" and os.path.exists(sp):
            ok &= secret_ok  # secretul nu dispare înainte de verificare
            if label == "external":
                ok &= refused_twice_identical(d, env_file(MK2), "wrong-key", K.WrongKey)
        if s == "keys.wtk:renamed":
            os.rename(os.path.join(d, "keys.wtk"), os.path.join(d, "keys.wtk.tmp"))
            ok &= kind(d) == "legacy"
        r = boot_ok(d, env)
        ok &= r.keyring.fk_legacy == SECRET and not os.path.exists(sp) and kind(d) == "protected"
    check(f"migration ({label}): crash at each of {len(steps)} steps → legacy or verified-protected, then completes", ok)

d = legacy_dir()


def stop_after_publish(x):
    if x == "migrate:verified":
        raise Crash(x)


raises(lambda: boot(d, env1, _crash_at=stop_after_publish), Crash)
put(os.path.join(d, "secret"), hashlib.sha256(b"other").digest())
check("protected + a DIFFERENT leftover secret → refused, byte-identical",
      refused_twice_identical(d, env1, "legacy-secret-mismatch"))

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
ring2 = K.rotate_master_key(lock, MK1, MK2)
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
r2 = K.rotate_master_key(lock, MK1, MK2)
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
r3 = K.rotate_master_key(lock, MK2, MK3)
check("second rotation: both old ids retired, sorted", r3.retired_mk_ids == tuple(sorted((kr.key_id(MK1), kr.key_id(MK2)))))
check("rotation back to a retired MK drops it from the retired list",
      K.rotate_master_key(lock, MK3, MK1).retired_mk_ids == tuple(sorted((kr.key_id(MK2), kr.key_id(MK3)))))
check("rotation with the same key → refused", raises(lambda: K.rotate_master_key(lock, MK1, MK1), K.BootRefused, "same-key"))
check("rotation with a wrong old MK → refused", raises(lambda: K.rotate_master_key(lock, MK2, MK3), K.WrongKey, "wrong-key"))
check("rotation with a short key → refused", raises(lambda: K.rotate_master_key(lock, MK1, MK2[:31]), K.BootRefused, "bad-key"))
lock.release()
d = fresh()
boot_ok(d, {K.ENV_IN_VOLUME: "1"})
lock = K.acquire_lock(d)
check("rotation with the key in the volume → unsupported",
      raises(lambda: K.rotate_master_key(lock, K.read_key_file(os.path.join(d, "master.key")), MK2), K.BootRefused, "unsupported"))
lock.release()

steps = []
d = fresh()
boot_ok(d, env1)
with_lock(d, lambda lk: K.rotate_master_key(lk, MK1, MK2, _crash_at=steps.append))
ok = bool(steps)
for s in steps:
    d = fresh()
    r0 = boot_ok(d, env1).keyring

    hook = crash_at(s)
    ok &= raises(lambda: with_lock(d, lambda lk: K.rotate_master_key(lk, MK1, MK2, _crash_at=hook)), Crash)
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
