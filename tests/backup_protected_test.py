"""Backup / restore pe un volum PROTEJAT (keys.wtk, 3.8; gateway/app/backup.py, §12.10).

Snapshotul nu conţine `secret` sau MK (căutăm cheile brute în container, în tar-ul decriptat,
în staging şi în copia de siguranţă), conţine keys.wtk; restore round-trip pe un volum temporar,
restore din altă instalare cu MK-ul operatorului, import explicit al unui backup pre-3.8 fără ca
cheia brută să ajungă în staging, şi refuz ÎNAINTE de staging la cheie greşită / conţinut
modificat / bombă / prea multe intrări. Partea legacy rămâne în backup_test.py, neschimbată."""
import base64
import io
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import time
import zlib
from pathlib import Path

from cryptography.fernet import Fernet

ROOT = tempfile.mkdtemp(prefix="wt-bkp-")
os.environ["WEBTERM_DATA_DIR"] = os.path.join(ROOT, "boot")
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import backup, config  # noqa: E402
from app import keyring as kr  # noqa: E402
from app import snapshot as wts  # noqa: E402

ok = 0
total = 0
PASS = "parola-de-test-lunga"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def refused(fn, exc=ValueError):
    try:
        fn()
        return False
    except exc:
        return True


def use(d):
    config.DATA_DIR = Path(d)
    config.DB_PATH = config.DATA_DIR / "webterm.db"
    config.TRANSCRIPT_DIR = config.DATA_DIR / "transcripts"


def volume(name, protected=True, email="a@b.c", secret_leftover=False):
    d = os.path.join(ROOT, name)
    os.makedirs(os.path.join(d, "transcripts", "arhiva"))
    use(d)
    con = sqlite3.connect(str(config.DB_PATH))
    con.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, created REAL)")
    for t in ("hosts", "sessions"):                        # R-M2: schema minimă a gateway-ului
        con.execute("CREATE TABLE %s(id INTEGER PRIMARY KEY, cred_encrypted TEXT)" % t)
    con.execute("CREATE TABLE app_settings(key TEXT PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO users(email, created) VALUES(?, 1000)", (email,))
    con.commit()
    con.close()
    key, pub = signing_pair()
    (config.DATA_DIR / "agent-signing.key").write_bytes(key)
    (config.DATA_DIR / "agent-signing.pub").write_bytes(pub)
    (config.TRANSCRIPT_DIR / "s1.out").write_bytes(b"hello transcript " * 100)
    (config.TRANSCRIPT_DIR / "s1.cast").write_bytes(b'{"v":2}\n')
    (config.TRANSCRIPT_DIR / "arhiva" / "s0.out").write_bytes(b"old")
    keys = {"secret": os.urandom(32)}
    if not protected:
        (config.DATA_DIR / "secret").write_bytes(keys["secret"])
        # R-H2: o valoare de seif reală, ca proba FK_legacy să aibă ce dovedi
        tok = Fernet(base64.urlsafe_b64encode(keys["secret"])).encrypt(b"pw").decode()
        con = sqlite3.connect(str(config.DB_PATH))
        con.execute("INSERT INTO hosts(cred_encrypted) VALUES(?)", (tok,))
        con.commit()
        con.close()
        return None, keys
    if secret_leftover:
        # sub-starea secret_leftover a migrării: keys.wtk + secret + migrating.wtm (keys.classify)
        (config.DATA_DIR / "secret").write_bytes(keys["secret"])
        (config.DATA_DIR / "migrating.wtm").write_bytes(b"WTM1" + b"\0" * 96)
    keys.update(mk=os.urandom(32), kwk=os.urandom(32), snk=os.urandom(32), fk=os.urandom(32),
                fk_legacy=os.urandom(32))
    mk = keys["mk"]
    envs = (kr.wrap_under_mk(mk, kr.KT_KWK, keys["kwk"]), kr.wrap_under_mk(mk, kr.KT_SNK, keys["snk"]),
            kr.wrap_under_kwk(keys["kwk"], kr.KT_FK_LEGACY, keys["fk_legacy"]),
            kr.wrap_under_kwk(keys["kwk"], kr.KT_FK, keys["fk"]))
    blob = kr.encode_manifest(kr.KeyManifest(os.urandom(16), 1, kr.key_id(mk), (), envs), mk)
    (config.DATA_DIR / "keys.wtk").write_bytes(blob)
    return host_keys(mk), keys


def signing_pair(encrypted=False):
    """O pereche de semnare reală (PEM PKCS8 + hex public), ca în signing.py."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    enc = ser.BestAvailableEncryption(b"pw-semnare") if encrypted else ser.NoEncryption()
    pem = priv.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, enc)
    pub = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex() + "\n"
    return pem, pub.encode()


def pending():
    """Setul staged numit de flag (R-H1: restore-pending.<generaţie>)."""
    return config.DATA_DIR / (backup.SET_PREFIX + flag_doc()["set"])


def staged_sets():
    return sorted(n for n in os.listdir(config.DATA_DIR) if n.startswith(backup.SET_PREFIX) or n == "restore-pending")


def host_keys(mk):
    ring = kr.open_keyring_bytes((config.DATA_DIR / "keys.wtk").read_bytes(), mk, kr.PROFILE_V1)
    return backup.HostKeys(ring, mk)


def raw_keys_in(paths_or_bytes, keys):
    """Cheile brute (şi forma hex) căutate în octeţi sau recursiv în fişierele unui director."""
    needles = [k for n, k in keys.items() if n in ("mk", "kwk", "snk", "fk", "fk_legacy", "secret")]
    needles += [k.hex().encode() for k in list(needles)]
    blobs = []
    for x in paths_or_bytes:
        if isinstance(x, (bytes, bytearray)):
            blobs.append(bytes(x))
        elif os.path.isdir(x):
            for dp, _dn, fn in os.walk(x):
                blobs += [Path(dp, f).read_bytes() for f in fn]
        elif os.path.exists(x):
            blobs.append(Path(x).read_bytes())
    return [n for n in needles if any(n in b for b in blobs)]


def tar_plain(wts_bytes, snk=None, inst=None, mk=None):
    r = wts.Reader(io.BytesIO(wts_bytes))
    r.unlock(snk=snk, installation_id=inst, mk=mk)
    gz = b"".join(r.chunks())
    return zlib.decompress(gz, 31)


def tar_names(plain):
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as t:
        return t.getnames()


def custom_wts(hk, members, manifest=True, bad_hash=False):
    """Un WTS1 autentic (cheile gazdei) cu un tar ales de test — conţinut ostil, dar semnat."""
    raw = io.BytesIO()
    entries = []
    with tarfile.open(fileobj=raw, mode="w:gz") as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
            import hashlib
            entries.append({"name": name, "size": len(data),
                            "sha256": ("0" * 64) if bad_hash else hashlib.sha256(data).hexdigest()})
        if manifest:
            m = json.dumps({"format": "wts-content-1", "files": entries}, sort_keys=True,
                           separators=(",", ":")).encode()
            ti = tarfile.TarInfo(backup.CONTENT_MANIFEST)
            ti.size = len(m)
            t.addfile(ti, io.BytesIO(m))
    out = io.BytesIO()
    w = wts.Writer(out, installation_id=hk.ring.installation_id, epoch=hk.ring.epoch,
                   mk_id=hk.ring.mk_id, snk=hk.ring.snk, mk=hk.mk)
    w.write(raw.getvalue())
    w.close()
    return backup.encrypt(out.getvalue(), PASS)


def nothing_staged():
    leftovers = list((config.DATA_DIR / "backups").glob(".restore-verify-*"))
    return (not staged_sets() and not (config.DATA_DIR / ".restore-flag").exists()
            and not leftovers)


def db_email():
    con = sqlite3.connect(str(config.DB_PATH))
    try:
        return con.execute("SELECT email FROM users").fetchone()[0]
    finally:
        con.close()


def set_email(e):
    con = sqlite3.connect(str(config.DB_PATH))
    con.execute("UPDATE users SET email=?", (e,))
    con.commit()
    con.close()


# ══════════════════════════════════════════════ review PR3 (H1–H4, M1–M4, L1)
class Crash(Exception):
    pass


def tar_bytes(members, fmt=tarfile.USTAR_FORMAT, manifest=True, manifest_raw=None, pax=None):
    """tar NECOMPRIMAT (ca testul să-i poată modifica octeţii), cu manifestul canonic la final."""
    import hashlib
    raw = io.BytesIO()
    entries = []
    with tarfile.open(fileobj=raw, mode="w", format=fmt) as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            if pax and name in pax:
                ti.pax_headers = pax[name]
            t.addfile(ti, io.BytesIO(data))
            entries.append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        if manifest:
            m = manifest_raw if manifest_raw is not None else json.dumps(
                {"format": "wts-content-1", "files": entries}, sort_keys=True, separators=(",", ":")).encode()
            ti = tarfile.TarInfo(backup.CONTENT_MANIFEST)
            ti.size = len(m)
            t.addfile(ti, io.BytesIO(m))
    return raw.getvalue(), entries


def wrap_tar(hk, plain):
    out = io.BytesIO()
    w = wts.Writer(out, installation_id=hk.ring.installation_id, epoch=hk.ring.epoch,
                   mk_id=hk.ring.mk_id, snk=hk.ring.snk, mk=hk.mk)
    w.write(_gz(plain))
    w.close()
    return backup.encrypt(out.getvalue(), PASS)


def _gz(b):
    c = zlib.compressobj(6, zlib.DEFLATED, 31)
    return c.compress(b) + c.flush()


def flag_doc():
    return json.loads((config.DATA_DIR / ".restore-flag").read_text())


def keyring_epoch(mk):
    return kr.open_keyring_bytes((config.DATA_DIR / "keys.wtk").read_bytes(), mk, kr.PROFILE_V1).epoch


def rotate(mk_old, mk_new):
    """Rotaţie simulată: keys.wtk re-ambalat sub MK nou, epoch + 1, MK vechi retras."""
    ring = kr.open_keyring_bytes((config.DATA_DIR / "keys.wtk").read_bytes(), mk_old, kr.PROFILE_V1)
    (config.DATA_DIR / "keys.wtk").write_bytes(backup._rewrap(ring, mk_new, ring.epoch + 1))
    return host_keys(mk_new)


def plain_of(blob_wtbk, mk):
    return tar_plain(backup.decrypt(blob_wtbk, PASS), mk=mk)


def faults(step_name=None, nth=None):
    """Cârlig de defect: Crash la pasul numit, sau la al n-lea pas (orice nume)."""
    seen = []

    def f(name):
        seen.append(name)
        if (step_name is not None and name == step_name) or (nth is not None and len(seen) == nth):
            raise Crash(name)
    return f, seen


def fsync_fail_at(n):
    calls = [0]
    orig = backup._fsync

    def f(fd):
        calls[0] += 1
        if calls[0] == n:
            raise OSError("injected fsync failure")
        return orig(fd)
    return f, calls


def staged_ok():
    """Invariantul H1 după un crash la staging: fie niciun flag, fie un flag al unui set complet."""
    flag = config.DATA_DIR / ".restore-flag"
    if not flag.exists():
        return True
    try:
        backup._validate_staging(pending(), flag_doc()["manifest"], KEYS_MK[0], flag_doc()["set"])
        return True
    except Exception:
        return False


KEYS_MK = [None]


def h1_tests():
    hk, K = volume("H1")
    KEYS_MK[0] = K["mk"]
    blob = backup.make_encrypted(PASS, include_transcripts=True, keys=hk)
    set_email("live@x")
    (config.TRANSCRIPT_DIR / "live.out").write_bytes(b"live")

    # 1) setul durabil: manifest de restore + flag care îl numeşte
    backup.stage_restore(blob, PASS, keys=hk)
    rd = pending()
    man = json.loads((pending() / "restore.json").read_bytes())
    fd = flag_doc()
    import hashlib
    check("H1: restore.json cu generaţie, fişiere (mărime + sha256), identitatea keyring-ului",
          man["format"] == "wt-restore-1" and len(man["generation"]) == 32
          and {"webterm.db", "keys.wtk"} <= {e["name"] for e in man["files"]}
          and man["installation_id"] == hk.ring.installation_id.hex() and man["epoch"] == hk.ring.epoch + 1
          and man["mk_id"] == kr.key_id(K["mk"]).hex(), man.get("format"))
    check("H1: flagul e scris ultimul şi numeşte digestul manifestului",
          fd["state"] == "staged" and fd["manifest"] == hashlib.sha256((rd / "restore.json").read_bytes()).hexdigest())

    # 2) orice marcaj incomplet = refuz (nu „nimic de făcut”), DB neatinsă
    def hostile(mutate, label):
        backup.stage_restore(blob, PASS, keys=hk)
        mutate()
        r = refused(lambda: backup.apply_pending_restore(keys=hk))
        check(f"H1 apply refuzat: {label}", r and db_email() == "live@x")
    hostile(lambda: (pending() / "webterm.db").unlink(), "flag fără DB (reproducerea recenziei)")
    hostile(lambda: (pending() / "agent-signing.key").unlink(), "membru lipsă")
    hostile(lambda: (pending() / "transcripts" / "s1.out").write_bytes(b"altceva"), "fişier modificat după verificare")
    hostile(lambda: (pending() / "extra.out").write_bytes(b"x"), "fişier în plus")
    hostile(lambda: shutil.rmtree(pending()), "flag fără staging")
    hostile(lambda: (config.DATA_DIR / ".restore-flag").write_text(
        json.dumps(dict(flag_doc(), manifest="0" * 64), sort_keys=True, separators=(",", ":"))),
        "flag care nu corespunde manifestului")
    hostile(lambda: (config.DATA_DIR / ".restore-flag").write_text("1"), "flag 3.7 pe volum protejat")
    hostile(lambda: (pending() / "restore.json").write_bytes(b"{}"), "manifest de restore înlocuit")
    os.unlink(config.DATA_DIR / ".restore-flag")
    check("H1: staging fără flag (stage întrerupt) ignorat, DB neatinsă",
          backup.apply_pending_restore(keys=hk) is False and db_email() == "live@x")

    # 3) două stage-uri concurente: al doilea e refuzat (lock în backups/)
    import fcntl
    lfd = os.open(str(config.DATA_DIR / "backups" / backup.STAGE_LOCK), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(lfd, fcntl.LOCK_EX)
    try:
        check("H1: stage cu lock-ul ţinut de altă operaţie refuzat",
              refused(lambda: backup.stage_restore(blob, PASS, keys=hk)))
    finally:
        os.close(lfd)
    inner = {}

    def nested(name):
        if name == "stage:manifest" and "r" not in inner:
            inner["r"] = refused(lambda: backup.stage_restore(blob, PASS, keys=hk))
    backup._fault = nested
    try:
        backup.stage_restore(blob, PASS, keys=hk)
    finally:
        backup._fault = None
    check("H1: un al doilea stage în timpul primului refuzat", inner.get("r") is True)
    check("H1: primul stage complet", staged_ok() and flag_doc()["state"] == "staged")

    # 4) .restore-verify-* rămase de la un crash: curăţate la următoarea operaţie, sub lock
    stale = config.DATA_DIR / "backups" / ".restore-verify-stale"
    stale.mkdir()
    (stale / "webterm.db").write_bytes(b"plaintext")
    backup.verify(blob, PASS, keys=hk)
    check("M3: .restore-verify-* rămas curăţat la următoarea operaţie", not stale.exists())

    # 5) fault injection la staging: fiecare pas durabil şi fiecare fsync
    probe, steps = faults()
    backup._fault = probe
    try:
        backup.stage_restore(blob, PASS, keys=hk)
    finally:
        backup._fault = None
    stage_steps = list(steps)
    ok_all = True
    for i in range(1, len(stage_steps) + 1):
        f, _s = faults(nth=i)
        backup._fault = f
        try:
            backup.stage_restore(blob, PASS, keys=hk)
            ok_all = False
        except Crash:
            pass
        finally:
            backup._fault = None
        if not staged_ok():
            ok_all = False
    check("H1: crash la fiecare pas al staging-ului (%d) → flag absent sau set complet" % len(stage_steps), ok_all,
          stage_steps)
    f, calls = fsync_fail_at(10 ** 9)
    backup._fsync = f
    backup.stage_restore(blob, PASS, keys=hk)
    n_fsync = calls[0]
    backup._fsync = os.fsync
    ok_all = True
    for i in range(1, n_fsync + 1):
        f, _c = fsync_fail_at(i)
        backup._fsync = f
        try:
            backup.stage_restore(blob, PASS, keys=hk)
        except OSError:
            pass
        finally:
            backup._fsync = os.fsync
        if not staged_ok():
            ok_all = False
    check("H1: eşec la fiecare fsync al staging-ului (%d) → flag absent sau set complet" % n_fsync, ok_all)

    # 6) fault injection la apply: crash la fiecare pas, apoi reluarea converge
    def fresh_stage():
        global_hk = host_keys(K["mk"])
        set_email("live@x")
        backup.stage_restore(blob, PASS, keys=global_hk)
        return global_hk

    cur = fresh_stage()
    probe, steps = faults()
    backup._fault = probe
    try:
        backup.apply_pending_restore(keys=cur)
    finally:
        backup._fault = None
    apply_steps = list(steps)
    ok_all, bad = True, []
    for i in range(1, len(apply_steps) + 1):
        cur = fresh_stage()
        want_epoch = json.loads((pending() / "restore.json").read_bytes())["epoch"]
        f, _s = faults(nth=i)
        backup._fault = f
        try:
            backup.apply_pending_restore(keys=cur)
            ok_all = False
        except Crash:
            pass
        finally:
            backup._fault = None
        try:
            again = backup.apply_pending_restore(keys=cur)
        except Exception as e:
            again = repr(e)
        good = (again is True and db_email() == "a@b.c" and keyring_epoch(K["mk"]) == want_epoch
                and nothing_staged() and (config.TRANSCRIPT_DIR / "s1.out").exists()
                and not (config.TRANSCRIPT_DIR / "live.out").exists()
                and not os.path.lexists(str(config.TRANSCRIPT_DIR) + ".restoring")
                and not os.path.lexists(str(config.TRANSCRIPT_DIR) + ".pre-restore"))
        if not good:
            ok_all = False
            bad.append((apply_steps[i - 1], again))
        (config.TRANSCRIPT_DIR / "live.out").write_bytes(b"live")
    check("H1: crash la fiecare pas al apply-ului (%d), apoi reluare → converge" % len(apply_steps), ok_all, bad)
    cur = fresh_stage()
    f, calls = fsync_fail_at(10 ** 9)
    backup._fsync = f
    backup.apply_pending_restore(keys=cur)
    backup._fsync = os.fsync
    n_fsync = calls[0]
    ok_all, bad = True, []
    for i in range(1, n_fsync + 1, 3):
        cur = fresh_stage()
        f, _c = fsync_fail_at(i)
        backup._fsync = f
        try:
            backup.apply_pending_restore(keys=cur)
        except (OSError, ValueError):
            pass
        finally:
            backup._fsync = os.fsync
        try:
            again = backup.apply_pending_restore(keys=cur)
        except Exception as e:
            again = repr(e)
        if not (again in (True, False) and db_email() == "a@b.c" and nothing_staged()):
            ok_all = False
            bad.append((i, again))
    check("H1: eşec de fsync la apply (%d puncte), apoi reluare → converge" % len(range(1, n_fsync + 1, 3)),
          ok_all, bad)

    # 7) copia de siguranţă e obligatorie (override explicit testat)
    cur = fresh_stage()
    orig = backup._wts_to_file
    backup._wts_to_file = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
    try:
        r = refused(lambda: backup.apply_pending_restore(keys=cur))
        check("M3: apply refuzat când copia de siguranţă nu se poate face",
              r and db_email() == "live@x" and flag_doc()["state"] == "staged")
        check("M3: force_without_safety_copy=True aplică",
              backup.apply_pending_restore(keys=cur, force_without_safety_copy=True) is True and db_email() == "a@b.c")
    finally:
        backup._wts_to_file = orig

    # 8) date absente din backup: transcripturile live rămân, şi e spus explicit
    cur = host_keys(K["mk"])
    b2 = backup.make_encrypted(PASS, include_transcripts=False, keys=cur)
    (config.TRANSCRIPT_DIR / "live.out").write_bytes(b"live")
    info = backup.stage_restore(b2, PASS, keys=cur)
    check("M3: info spune că transcripturile live rămân", info["live_transcripts_kept"] is True
          and info["live_signing_key_kept"] is False)
    backup.apply_pending_restore(keys=cur)
    check("M3: transcripturile live păstrate", (config.TRANSCRIPT_DIR / "live.out").exists())


def h2_tests():
    # volum protejat care îşi pierde keys.wtk: NICIO operaţie nu cade pe traseul legacy
    hk, K = volume("H2", secret_leftover=True)
    backup.run_scheduled_backup(keys=hk)
    legacy_blob = None
    _n, KL = volume("H2L", protected=False, email="leg@x")
    legacy_blob = backup.make_encrypted(PASS)
    use(os.path.join(ROOT, "H2"))
    os.unlink(config.DATA_DIR / "keys.wtk")
    os.unlink(config.DATA_DIR / "migrating.wtm")
    ops = {
        "is_protected": lambda: backup.is_protected(),
        "make_snapshot": lambda: backup.make_snapshot(),
        "make_encrypted": lambda: backup.make_encrypted(PASS),
        "run_scheduled_backup": lambda: backup.run_scheduled_backup(),
        "verify (3.7)": lambda: backup.verify(legacy_blob, PASS),
        "stage_restore (3.7)": lambda: backup.stage_restore(legacy_blob, PASS),
    }
    for label, fn in ops.items():
        check(f"H2: keys.wtk pierdut + .wts în backups/ → {label} refuzat", refused(fn))
    check("H2: niciun .wtsnap cu secret produs", not list((config.DATA_DIR / "backups").glob("*.wtsnap"))
          and nothing_staged())
    for p in (config.DATA_DIR / "backups").glob("*.wts"):
        p.unlink()
    (config.DATA_DIR / "migrating.wtm").write_bytes(b"x")
    check("H2: keys.wtk lipsă + migrating.wtm → refuz", refused(lambda: backup.make_encrypted(PASS)))
    os.unlink(config.DATA_DIR / "migrating.wtm")
    backup.set_host_keys_provider(lambda: hk)
    try:
        check("H2: furnizor de chei înregistrat + keys.wtk lipsă → refuz",
              refused(lambda: backup.make_encrypted(PASS)) and refused(lambda: backup.make_snapshot()))
    finally:
        backup.set_host_keys_provider(None)
    backup.set_boot_protected(True)
    try:
        check("H2: boot protejat + keys.wtk lipsă → refuz", refused(lambda: backup.make_snapshot()))
    finally:
        backup.set_boot_protected(False)
    (config.TRANSCRIPT_DIR / "s9.wtx").write_bytes(b"x")
    check("H2: segment rezervat sub transcripts/ fără keys.wtk → refuz", refused(lambda: backup.make_snapshot()))
    os.unlink(config.TRANSCRIPT_DIR / "s9.wtx")
    rd = config.DATA_DIR / "restore-pending"
    rd.mkdir()
    (rd / "webterm.db").write_bytes(config.DB_PATH.read_bytes())
    (rd / "secret").write_bytes(b"S" * 32)
    (rd / "restore.json").write_bytes(b"{}")
    (config.DATA_DIR / ".restore-flag").write_text("1")
    secret_before = (config.DATA_DIR / "secret").read_bytes()
    check("H2: staging 3.8 pe volum fără keys.wtk → apply refuzat, secret neatins",
          refused(lambda: backup.apply_pending_restore()) and (config.DATA_DIR / "secret").read_bytes() == secret_before)
    os.unlink(rd / "restore.json")
    check("H2: după curăţare volumul e legacy curat (snapshot 3.7 permis)", backup.make_snapshot()[:2] == b"\x1f\x8b")
    shutil.rmtree(rd)
    os.unlink(config.DATA_DIR / ".restore-flag")
    use(os.path.join(ROOT, "H2L"))
    check("H2: volumul legacy obişnuit nu e afectat", backup.volume_kind() == "legacy"
          and backup.apply_pending_restore() is False)


def h3_tests():
    hk, K = volume("H3", secret_leftover=True)
    T = config.TRANSCRIPT_DIR
    os.link(config.DATA_DIR / "secret", T / "leak.out")
    os.symlink(config.DATA_DIR / "secret", T / "ln.out")
    (T / "secret").write_bytes(K["secret"])
    os.symlink(config.DATA_DIR, T / "arhiva" / "sub")
    os.symlink(config.DATA_DIR, T / "data")
    name = backup.run_scheduled_backup(include_transcripts=True, keys=hk)
    plain = tar_plain((config.DATA_DIR / "backups" / name).read_bytes(), snk=K["snk"], inst=hk.ring.installation_id)
    names = tar_names(plain)
    check("H3: hardlink, symlink, nume nepermis, director-alias excluse",
          not ({"transcripts/leak.out", "transcripts/ln.out", "transcripts/secret"} & set(names))
          and not any("sub" in n or "data" in n.split("/")[1:2] for n in names if n.startswith("transcripts/")), names)
    check("H3: înregistrările legitime incluse", "transcripts/s1.out" in names and "transcripts/arhiva/s0.out" in names)
    check("H3: cheia brută absentă din tar-ul decriptat", K["secret"] not in plain and not raw_keys_in([plain], K))
    # rădăcina transcripts/ ca symlink spre DATA_DIR (cu `secret` rămas): refuz
    os.rename(T, str(T) + ".real")
    os.symlink(config.DATA_DIR, T)
    before = set(os.listdir(config.DATA_DIR / "backups"))
    check("H3: rădăcina transcripts/ symlink → backup cu transcripturi refuzat",
          refused(lambda: backup.run_scheduled_backup(include_transcripts=True, keys=hk))
          and refused(lambda: backup.make_encrypted(PASS, include_transcripts=True, keys=hk))
          and set(os.listdir(config.DATA_DIR / "backups")) == before)
    out = backup.make_encrypted(PASS, include_transcripts=False, keys=hk)
    check("H3: fără transcripturi backup-ul merge şi nu conţine cheia",
          K["secret"] not in plain_of(out, K["mk"]) and not any(n.startswith("transcripts") for n in tar_names(plain_of(out, K["mk"]))))


def m1_tests():
    hk, K = volume("M1")
    db_bytes = config.DB_PATH.read_bytes()
    kw = (config.DATA_DIR / "keys.wtk").read_bytes()
    base = [("webterm.db", db_bytes), ("keys.wtk", kw)]
    good, _e = tar_bytes(base)
    check("M1: arhiva USTAR canonică acceptată", backup.verify(wrap_tar(hk, good), PASS, keys=hk)["format"] == "WTS1")
    # ultimul membru se termină la len - 1024 - padding; primul bloc final începe acolo
    end = len(good)
    while good[end - 512:end] == bytes(512):
        end -= 512
    t = bytearray(good)
    t[end + 512 + 7] = 1
    check("M1: octet nenul în AL DOILEA bloc final refuzat",
          refused(lambda: backup.stage_restore(wrap_tar(hk, bytes(t)), PASS, keys=hk)) and nothing_staged())
    t = bytearray(good)
    t[-1] = 1
    check("M1: octet nenul în padding-ul de după final refuzat",
          refused(lambda: backup.stage_restore(wrap_tar(hk, bytes(t)), PASS, keys=hk)) and nothing_staged())
    check("M1: octeţi după arhivă refuzaţi",
          refused(lambda: backup.verify(wrap_tar(hk, good + b"\x01" + bytes(511)), PASS, keys=hk)))
    huge, _e = tar_bytes(base, fmt=tarfile.PAX_FORMAT, pax={"webterm.db": {"comment": "x" * (1 << 20)}})
    check("M1: antet PAX uriaş refuzat (WTS1 nu acceptă extensii)",
          refused(lambda: backup.stage_restore(wrap_tar(hk, huge), PASS, keys=hk)) and nothing_staged())
    gnu, _e = tar_bytes(base + [("transcripts/" + "a" * 120 + ".out", b"x")], fmt=tarfile.GNU_FORMAT)
    check("M1: GNU longname refuzat", refused(lambda: backup.verify(wrap_tar(hk, gnu), PASS, keys=hk)))
    _p, entries = tar_bytes(base, manifest=False)
    files = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    dup = ('{"files":%s,"files":%s,"format":"wts-content-1"}' % (files, files)).encode()
    t, _e = tar_bytes(base, manifest_raw=dup)
    check("M1: manifest JSON cu chei duplicate refuzat", refused(lambda: backup.verify(wrap_tar(hk, t), PASS, keys=hk)))
    loose = json.dumps({"format": "wts-content-1", "files": entries}).encode()
    t, _e = tar_bytes(base, manifest_raw=loose)
    check("M1: manifest JSON necanonic refuzat", refused(lambda: backup.verify(wrap_tar(hk, t), PASS, keys=hk)))
    strsize = json.dumps({"format": "wts-content-1", "files": [dict(e, size=str(e["size"])) for e in entries]},
                         sort_keys=True, separators=(",", ":")).encode()
    t, _e = tar_bytes(base, manifest_raw=strsize)
    check("M1: tip greşit în manifest (size ca şir) refuzat", refused(lambda: backup.verify(wrap_tar(hk, t), PASS, keys=hk)))
    t, _e = tar_bytes(base, manifest_raw=b"\xff\xfe")
    check("M1: manifest ne-UTF-8 → eroarea modulului (ValueError), nu 500",
          refused(lambda: backup.verify(wrap_tar(hk, t), PASS, keys=hk), wts.SnapshotError))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tt:
        ti = tarfile.TarInfo("transcripts/x.out")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "../secret"
        tt.addfile(ti)
    check("M1: symlink în arhivă refuzat", refused(lambda: backup.verify(wrap_tar(hk, raw.getvalue()), PASS, keys=hk)))
    # importul 3.7 trece prin acelaşi extractor strict
    use(os.path.join(ROOT, "M1"))
    sec = os.urandom(32)
    leg = io.BytesIO()
    with tarfile.open(fileobj=leg, mode="w:gz", format=tarfile.PAX_FORMAT) as tt:
        for n, d, ph in (("webterm.db", db_bytes, {"comment": "y" * 20000}), ("secret", sec, None)):
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            if ph:
                ti.pax_headers = ph
            tt.addfile(ti, io.BytesIO(d))
    check("M1: import 3.7 cu antet PAX mare refuzat",
          refused(lambda: backup.stage_restore(backup.encrypt(leg.getvalue(), PASS), PASS, keys=hk, legacy_import=True))
          and nothing_staged())
    leg = io.BytesIO()
    with tarfile.open(fileobj=leg, mode="w:gz") as tt:
        for n, d in (("webterm.db", db_bytes), ("secret", sec)):
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            tt.addfile(ti, io.BytesIO(d))
        ti = tarfile.TarInfo("transcripts/x.out")
        ti.type = tarfile.LNKTYPE
        ti.linkname = "secret"
        tt.addfile(ti)
    check("M1/M3: import 3.7 cu hardlink intern refuzat (fără tar.extract)",
          refused(lambda: backup.stage_restore(backup.encrypt(leg.getvalue(), PASS), PASS, keys=hk, legacy_import=True))
          and nothing_staged())


def m2_tests():
    hk, K = volume("M2")
    backup._backup_dir()
    for i in range(4):
        (config.TRANSCRIPT_DIR / ("t%d.out" % i)).write_bytes(b"x")
    old = backup.MAX_MEMBERS
    backup.MAX_MEMBERS = 5
    try:
        before = set(os.listdir(config.DATA_DIR / "backups"))
        check("M2: writer-ul aplică plafonul de membri al cititorului",
              refused(lambda: backup.run_scheduled_backup(include_transcripts=True, keys=hk), wts.SnapshotTooLarge)
              and set(os.listdir(config.DATA_DIR / "backups")) == before)
    finally:
        backup.MAX_MEMBERS = old
    orig = backup._TarOut.finish

    def lying(self):
        self.entries.append({"name": "transcripts/ghost.out", "size": 1, "sha256": "0" * 64})
        return orig(self)
    backup._TarOut.finish = lying
    try:
        before = set(os.listdir(config.DATA_DIR / "backups"))
        check("M2: o arhivă produsă pe care restore-ul n-ar accepta-o nu e raportată ca succes",
              refused(lambda: backup.run_scheduled_backup(keys=hk)) and refused(lambda: backup.make_encrypted(PASS, keys=hk))
              and set(os.listdir(config.DATA_DIR / "backups")) == before)
    finally:
        backup._TarOut.finish = orig
    keep = config.DATA_DIR / "backups" / "pre-restore-1.wts.keep"
    keep.write_bytes(b"x")
    check("L1: copiile .keep apar în inventar (doar citire)",
          [k["name"] for k in backup.list_keep_copies()] == ["pre-restore-1.wts.keep"]
          and "pre-restore-1.wts.keep" not in {b["name"] for b in backup.list_backups()})


def m4_tests():
    hk1, K = volume("M4")
    mk1 = K["mk"]
    s1 = backup.run_scheduled_backup(keys=hk1)
    d1 = backup.make_encrypted(PASS, keys=hk1)
    mk2, mk3 = os.urandom(32), os.urandom(32)
    hk2 = rotate(mk1, mk2)
    try:
        backup.encrypt_stored(s1, PASS, keys=hk2)
        check("M4: snapshot local vechi după rotaţie fără MK-ul vechi → „trebuie MK <id>”", False)
    except wts.SnapshotWrongKey as e:
        check("M4: snapshot local vechi după rotaţie fără MK-ul vechi → „trebuie MK <id>”",
              e.mk_id == kr.key_id(mk1))
    x2 = backup.encrypt_stored(s1, PASS, keys=hk2, mk=mk1)
    inner = backup.decrypt(x2, PASS)
    plain = tar_plain(inner, mk=mk2)
    ring_in = kr.open_keyring_bytes(tarfile.open(fileobj=io.BytesIO(plain)).extractfile("keys.wtk").read(),
                                    mk2, kr.PROFILE_V1)
    check("M4: re-export: MK exterior = MK interior = MK curent, epoch-ul header-ului = al keyring-ului",
          inner[40:56] == kr.key_id(mk2) and ring_in.mk_id == kr.key_id(mk2)
          and ring_in.epoch == int.from_bytes(inner[32:40], "little") and kr.key_id(mk1) in ring_in.retired_mk_ids)
    check("M4: re-exportul nu se deschide cu MK-ul vechi", refused(lambda: tar_plain(inner, mk=mk1), wts.SnapshotWrongKey))
    hk3 = rotate(mk2, mk3)
    check("M4: a doua rotaţie: re-export tot cu MK-ul snapshotului",
          backup.decrypt(backup.encrypt_stored(s1, PASS, keys=hk3, mk=mk1), PASS)[40:56] == kr.key_id(mk3))
    check("M4: exportul de sub MK2 pe gazda MK3 cere MK2",
          refused(lambda: backup.stage_restore(x2, PASS, keys=hk3), wts.SnapshotWrongKey) and nothing_staged())
    try:
        backup.stage_restore(d1, PASS, keys=hk3)
        check("M4: download local vechi (MK1) după două rotaţii: cere MK1 (id în eroare)", False)
    except wts.SnapshotWrongKey as e:
        check("M4: download local vechi (MK1) după două rotaţii: cere MK1 (id în eroare)",
              e.mk_id == kr.key_id(mk1) and nothing_staged())
    info = backup.stage_restore(d1, PASS, keys=hk3, mk=mk1)
    check("M4: cu MK1 se restaurează pe gazda MK3", info["same_installation"] is True)
    backup.apply_pending_restore(keys=hk3)
    hk3 = host_keys(mk3)
    check("M4: după restore keys.wtk e sub MK3", hk3.ring.mk_id == kr.key_id(mk3))
    # SNK divergent pe aceeaşi instalare (recuperare): plicul local nu se potriveşte → ruta portabilă
    d3 = backup.make_encrypted(PASS, keys=hk3)
    r = hk3.ring
    other = kr.Keyring(r.installation_id, r.epoch, r.mk_id, r.retired_mk_ids, kwk=r.kwk, snk=os.urandom(32),
                       fk_legacy=r.fk_legacy, fk=r.fk, dbk=r.dbk)
    (config.DATA_DIR / "keys.wtk").write_bytes(backup._rewrap(other, mk3, r.epoch + 1))
    hk3b = host_keys(mk3)
    check("M4: SNK divergent → ruta portabilă cu MK-ul gazdei", backup.verify(d3, PASS, keys=hk3b)["format"] == "WTS1")
    check("M4: prefer=\"portable\" explicit", backup.verify(d3, PASS, keys=hk3b, prefer="portable")["portable"] is True)
    check("M4: prefer invalid refuzat", refused(lambda: backup.verify(d3, PASS, keys=hk3b, prefer="x")))
    # header şi keyring interior legate (epoch / instalare)
    db_bytes = config.DB_PATH.read_bytes()
    kw = (config.DATA_DIR / "keys.wtk").read_bytes()
    t, _e = tar_bytes([("webterm.db", db_bytes), ("keys.wtk", kw)])
    out = io.BytesIO()
    w = wts.Writer(out, installation_id=hk3b.ring.installation_id, epoch=hk3b.ring.epoch + 5,
                   mk_id=hk3b.ring.mk_id, snk=hk3b.ring.snk, mk=hk3b.mk)
    w.write(_gz(t))
    w.close()
    check("M4: epoch din header ≠ epoch-ul keyring-ului interior → refuz",
          refused(lambda: backup.verify(backup.encrypt(out.getvalue(), PASS), PASS, keys=hk3b)))


def l1_tests():
    from app import backup_api
    e = backup_api._backup_value_error(wts.SnapshotWrongKey("needs-mk", "x", mk_id=b"\x01" * 16))
    check("L1: „trebuie MK <id>” are cod propriu cu id-ul", e.code == "backup.needsMasterKey")
    check("L1: limită depăşită are cod propriu", backup_api._backup_value_error(
        wts.SnapshotTooLarge("too-many-members")).code == "backup.limitExceeded")
    check("L1: operaţie concurentă → backup.busy (409)",
          backup_api._backup_value_error(ValueError(backup._BUSY)).status_code == 409)
    check("L1: bomba 3.7 rămâne backup.tooLarge", backup_api._backup_value_error(
        ValueError("backup too large when unpacked (possible compression bomb) — refused")).code == "backup.tooLarge")
    import asyncio

    class Req:
        def __init__(self, headers, chunks):
            self.headers, self._chunks, self.read = headers, chunks, 0

        async def stream(self):
            for c in self._chunks:
                self.read += len(c)
                yield c
    big = Req({"content-length": str(backup_api.UPLOAD_MAX + 1)}, [b"x"])
    try:
        asyncio.run(backup_api._read_upload(big))
        check("M2: Content-Length peste limită refuzat înainte de citirea corpului", False)
    except Exception as ex:
        check("M2: Content-Length peste limită refuzat înainte de citirea corpului",
              getattr(ex, "status_code", 0) == 413 and big.read == 0)
    old = backup_api.UPLOAD_MAX
    backup_api.UPLOAD_MAX = 10
    try:
        lying = Req({}, [b"x" * 6, b"y" * 6, b"z" * 6])
        try:
            asyncio.run(backup_api._read_upload(lying))
            check("M2: fără Content-Length, corpul e tăiat la limită", False)
        except Exception as ex:
            check("M2: fără Content-Length, corpul e tăiat la limită",
                  getattr(ex, "status_code", 0) == 413 and lying.read == 12)
        check("M2: corp sub limită citit întreg", asyncio.run(backup_api._read_upload(Req({}, [b"ab", b"c"]))) == b"abc")
    finally:
        backup_api.UPLOAD_MAX = old


# ══════════════════════════════════════════════ recheck PR3 (fdbfda2): R-H1, R-H2, R-M1–M3, R-L1
def rh1_tests():
    from app import backup_api
    hk, K = volume("RH1")
    KEYS_MK[0] = K["mk"]
    blob_a = backup.make_encrypted(PASS, include_transcripts=True, keys=hk)
    set_email("b@x")
    blob_b = backup.make_encrypted(PASS, include_transcripts=True, keys=hk)
    set_email("live@x")

    # 1) crash imediat după publicarea keyring-ului: flag `applying`, DB veche → stage refuzat
    backup.stage_restore(blob_a, PASS, keys=hk)
    gen_a = flag_doc()["set"]
    f, _s = faults("apply:keys")
    backup._fault = f
    try:
        backup.apply_pending_restore(keys=hk)
    except Crash:
        pass
    finally:
        backup._fault = None
    check("R-H1: crash după keys.wtk → flag `applying`, DB încă veche",
          flag_doc()["state"] == "applying" and db_email() == "live@x")
    hk2 = host_keys(K["mk"])                       # keys.wtk a fost deja înlocuit (epoch + 1)
    try:
        backup.stage_restore(blob_b, PASS, keys=hk2)
        msg = None
    except ValueError as e:
        msg = str(e)
    check("R-H1: stage peste un jurnal `applying` refuzat (restoreInProgress)", msg == backup._IN_PROGRESS, msg)
    check("R-H1: jurnalul rămâne intact (acelaşi set, aceeaşi stare)",
          flag_doc()["state"] == "applying" and flag_doc()["set"] == gen_a and staged_ok() and staged_sets() == [backup.SET_PREFIX + gen_a])
    e = backup_api._backup_value_error(ValueError(backup._IN_PROGRESS))
    check("R-H1: API → 409 backup.restoreInProgress", e.code == "backup.restoreInProgress" and e.status_code == 409,
          (e.code, getattr(e, "status_code", None)))
    try:
        backup._stage_legacy_import(b"", keys=hk2)
        msg = None
    except ValueError as e:
        msg = str(e)
    check("R-H1: legacy import peste jurnal activ refuzat la fel",
          msg == backup._IN_PROGRESS and flag_doc()["state"] == "applying", msg)
    check("R-H1: apply reia jurnalul şi converge", backup.apply_pending_restore(keys=hk2) is True
          and db_email() == "a@b.c" and nothing_staged())

    # 2) `committed` nefinalizat: tot refuz, apoi apply termină
    hk = host_keys(K["mk"])
    set_email("live@x")
    backup.stage_restore(blob_a, PASS, keys=hk)
    f, _s = faults("apply:committed")
    backup._fault = f
    try:
        backup.apply_pending_restore(keys=hk)
    except Crash:
        pass
    finally:
        backup._fault = None
    hk = host_keys(K["mk"])
    check("R-H1: stage peste `committed` refuzat", refused(lambda: backup.stage_restore(blob_b, PASS, keys=hk))
          and flag_doc()["state"] == "committed")
    check("R-H1: apply finalizează `committed`", backup.apply_pending_restore(keys=hk) is True and nothing_staged())

    # 3) înlocuirea unui set staged cu crash la fiecare pas: vechiul SAU noul set, niciodată niciunul
    def email_of_set():
        con = sqlite3.connect(str(pending() / "webterm.db"))
        try:
            return con.execute("SELECT email FROM users").fetchone()[0]
        finally:
            con.close()
    hk = host_keys(K["mk"])
    backup.stage_restore(blob_a, PASS, keys=hk)
    probe, steps = faults()
    backup._fault = probe
    try:
        backup.stage_restore(blob_b, PASS, keys=hk)
    finally:
        backup._fault = None
    repl_steps = list(steps)
    ok_all, bad = True, []
    for i in range(1, len(repl_steps) + 1):
        backup.stage_restore(blob_a, PASS, keys=hk)
        f, _s = faults(nth=i)
        backup._fault = f
        try:
            backup.stage_restore(blob_b, PASS, keys=hk)
        except Crash:
            pass
        finally:
            backup._fault = None
        good = (config.DATA_DIR / ".restore-flag").exists() and staged_ok() and email_of_set() in ("a@b.c", "b@x")
        if not good:
            ok_all = False
            bad.append(repl_steps[i - 1])
    check("R-H1: înlocuire cu crash la fiecare pas (%d) → setul vechi sau cel nou, flag valid" % len(repl_steps),
          ok_all, bad)
    backup.stage_restore(blob_b, PASS, keys=hk)
    check("R-H1: după o înlocuire reuşită rămâne o singură generaţie (cea numită de flag)",
          staged_sets() == [backup.SET_PREFIX + flag_doc()["set"]] and email_of_set() == "b@x", staged_sets())
    f, _s = faults("stage:flag")
    backup._fault = f
    try:
        backup.stage_restore(blob_a, PASS, keys=hk)
    except Crash:
        pass
    finally:
        backup._fault = None
    check("R-H1: crash după flagul nou → generaţia veche e orfană, curăţată de apply",
          len(staged_sets()) == 2 and backup.apply_pending_restore(keys=hk) is True
          and db_email() == "a@b.c" and nothing_staged(), staged_sets())
    hk = host_keys(K["mk"])
    raw_flag = json.dumps({"format": "wt-restore-flag-1", "manifest": "0" * 64, "state": "staged"},
                          sort_keys=True, separators=(",", ":"))
    (config.DATA_DIR / ".restore-flag").write_text(raw_flag)
    check("R-H1: un flag fără generaţie e refuzat (stage şi apply)",
          refused(lambda: backup.stage_restore(blob_a, PASS, keys=hk))
          and refused(lambda: backup.apply_pending_restore(keys=hk)))
    os.unlink(config.DATA_DIR / ".restore-flag")


def rh2_tests():
    hk, K = volume("RH2")
    pub = config.DATA_DIR / "agent-signing.pub"
    key = config.DATA_DIR / "agent-signing.key"
    good_pub, good_key = pub.read_bytes(), key.read_bytes()
    mkfile = os.path.join(ROOT, "RH2-mk")
    Path(mkfile).write_bytes(K["mk"])
    os.environ[backup.keystore.ENV_KEY_FILE] = mkfile
    try:
        pub.unlink()
        os.link(mkfile, pub)
        out = []

        def attempt():
            out.append(backup.make_encrypted(PASS, keys=hk))
        r = refused(attempt)
        r2 = refused(lambda: backup.run_scheduled_backup(keys=hk))
        check("R-H2: agent-signing.pub = hardlink la fişierul MK → backup refuzat", r and r2 and not out)
        check("R-H2: niciun .wts rămas după refuz",
              not [n for n in os.listdir(config.DATA_DIR / "backups") if n.endswith((".wts", ".tmp"))])
        pub.unlink()
        os.link(config.DATA_DIR / "keys.wtk", pub)
        check("R-H2: hardlink la keys.wtk → refuzat", refused(lambda: backup.make_encrypted(PASS, keys=hk)))
        pub.unlink()
        # inode interzis pe fd-ul citit (fără nlink > 1): verificat direct cu setul de inode-uri
        pub.write_bytes(good_pub)
        st = os.stat(pub)
        check("R-H2: inode-ul unei chei (set interzis) refuzat chiar cu un singur link",
              refused(lambda: backup._read_signing("agent-signing.pub", {(st.st_dev, st.st_ino)})))
        check("R-H2: setul interzis conţine fişierul MK extern, DB-ul şi .lock",
              (os.stat(mkfile).st_dev, os.stat(mkfile).st_ino) in backup._forbidden_inodes(signing=False)
              and (os.stat(config.DB_PATH).st_ino) in {i for _d, i in backup._forbidden_inodes(signing=False)})
    finally:
        os.environ.pop(backup.keystore.ENV_KEY_FILE, None)
    # perechea: jumătate, nepotrivită, format greşit
    pub.unlink()
    check("R-H2: doar agent-signing.key (fără .pub) → export refuzat", refused(lambda: backup.make_encrypted(PASS, keys=hk)))
    other_key, other_pub = signing_pair()
    pub.write_bytes(other_pub)
    check("R-H2: pereche nepotrivită → export refuzat", refused(lambda: backup.make_encrypted(PASS, keys=hk)))
    key.write_bytes(b"not a pem")
    check("R-H2: cheie privată care nu e PEM → export refuzat", refused(lambda: backup.make_encrypted(PASS, keys=hk)))
    enc_key, enc_pub = signing_pair(encrypted=True)
    key.write_bytes(enc_key)
    pub.write_bytes(enc_pub)
    check("R-H2: PEM criptat la repaus (doar forma) acceptat", backup.make_encrypted(PASS, keys=hk)[:5] == b"WTBK1")
    key.write_bytes(good_key)
    pub.write_bytes(good_pub)
    # la import: perechea nepotrivită / jumătate refuzată ÎNAINTE de staging
    db_bytes = config.DB_PATH.read_bytes()
    kw = (config.DATA_DIR / "keys.wtk").read_bytes()
    t, _e = tar_bytes([("webterm.db", db_bytes), ("keys.wtk", kw), ("agent-signing.key", good_key),
                       ("agent-signing.pub", other_pub)])
    check("R-H2: pereche nepotrivită în backup → import refuzat, nimic staged",
          refused(lambda: backup.stage_restore(wrap_tar(hk, t), PASS, keys=hk)) and nothing_staged())
    t, _e = tar_bytes([("webterm.db", db_bytes), ("keys.wtk", kw), ("agent-signing.key", good_key)])
    check("R-H2: jumătate de pereche în backup → import refuzat",
          refused(lambda: backup.stage_restore(wrap_tar(hk, t), PASS, keys=hk)) and nothing_staged())
    t, _e = tar_bytes([("webterm.db", db_bytes), ("keys.wtk", kw), ("agent-signing.key", good_key),
                       ("agent-signing.pub", good_pub)])
    check("R-H2: perechea bună în backup → acceptată", backup.verify(wrap_tar(hk, t), PASS, keys=hk)["format"] == "WTS1")
    leg = io.BytesIO()
    with tarfile.open(fileobj=leg, mode="w:gz", format=tarfile.USTAR_FORMAT) as tt:
        for n, b in (("webterm.db", db_bytes), ("secret", os.urandom(32)), ("agent-signing.key", good_key),
                     ("agent-signing.pub", other_pub)):
            ti = tarfile.TarInfo(n)
            ti.size = len(b)
            tt.addfile(ti, io.BytesIO(b))
    check("R-H2: import 3.7 cu pereche nepotrivită refuzat",
          refused(lambda: backup.stage_restore(backup.encrypt(leg.getvalue(), PASS), PASS, keys=hk, legacy_import=True))
          and nothing_staged())


def rm1_tests():
    hkB, KB = volume("RM1B")
    b_pub = (config.DATA_DIR / "agent-signing.pub").read_bytes()
    blob_b = backup.make_encrypted(PASS, include_transcripts=False, keys=hkB)
    hk, K = volume("RM1A")
    (config.TRANSCRIPT_DIR / "live.out").write_bytes(b"live")
    info = backup.stage_restore(blob_b, PASS, keys=hk, mk=KB["mk"])
    gen = flag_doc()["set"]
    check("R-M1: alt set de date fără transcripturi → info anunţă carantina",
          info["live_transcripts_quarantined"] is True and info["live_transcripts_kept"] is False, info)
    f, _s = faults("apply:transcripts-quarantined")
    backup._fault = f
    try:
        backup.apply_pending_restore(keys=hk)
    except Crash:
        pass
    finally:
        backup._fault = None
    check("R-M1: decizia de carantină e în flag (`applying`)", flag_doc().get("quarantine") is True)
    hk = HostKeysFor(K["mk"])
    check("R-M1: reluarea după carantină converge", backup.apply_pending_restore(keys=hk) is True and nothing_staged())
    q = config.DATA_DIR / "backups" / ("quarantine-" + gen)
    check("R-M1: transcripturile live mutate în backups/quarantine-<restore id>/",
          (q / "transcripts" / "live.out").read_bytes() == b"live" and (q / "transcripts" / "s1.out").exists()
          and not (config.TRANSCRIPT_DIR / "live.out").exists() and len(os.listdir(q)) == 1)
    check("R-M1: perechea de semnare a backup-ului aplicată întreagă",
          (config.DATA_DIR / "agent-signing.pub").read_bytes() == b_pub)
    # acelaşi set de date fără transcripturi: cele live rămân (regula veche, spusă explicit)
    hk = HostKeysFor(K["mk"])
    blob_same = backup.make_encrypted(PASS, include_transcripts=False, keys=hk)
    config.TRANSCRIPT_DIR.mkdir(exist_ok=True)
    (config.TRANSCRIPT_DIR / "live2.out").write_bytes(b"live2")
    info = backup.stage_restore(blob_same, PASS, keys=hk)
    backup.apply_pending_restore(keys=hk)
    check("R-M1: aceeaşi instalare fără transcripturi → păstrate",
          info["live_transcripts_kept"] is True and (config.TRANSCRIPT_DIR / "live2.out").exists())
    # copia de siguranţă conţine transcripturile când apply-ul le înlocuieşte
    hk = HostKeysFor(K["mk"])
    blob_tx = backup.make_encrypted(PASS, include_transcripts=True, keys=hk)
    (config.TRANSCRIPT_DIR / "only-live.out").write_bytes(b"only live")
    backup.stage_restore(blob_tx, PASS, keys=hk)
    gen = flag_doc()["set"]
    backup.apply_pending_restore(keys=hk)
    keeps = [n for n in os.listdir(config.DATA_DIR / "backups") if gen[:12] in n and n.endswith(".keep")]
    names = tar_names(tar_plain((config.DATA_DIR / "backups" / keeps[0]).read_bytes(), mk=K["mk"])) if keeps else []
    check("R-M1: copia de siguranţă include transcripturile înlocuite",
          "transcripts/only-live.out" in names and not (config.TRANSCRIPT_DIR / "only-live.out").exists(), names)


def HostKeysFor(mk):
    return host_keys(mk)


def rm2_tests():
    from app import backup_api
    hk, K = volume("RM2")
    info = backup.verify(backup.make_encrypted(PASS, keys=hk), PASS, keys=hk)
    check("R-M2: verify = restaurabilă (DB + schemă)", info.get("restorable") is True)
    calls = []
    orig = backup._check_db
    backup._check_db = lambda p: (calls.append(p), orig(p))[1]
    try:
        backup.make_encrypted(PASS, keys=hk)
        n_dl = len(calls)
        backup.run_scheduled_backup(keys=hk)
    finally:
        backup._check_db = orig
    check("R-M2: exportul şi snapshotul programat verificate ca restaurabile (DB deschis)",
          n_dl >= 1 and len(calls) >= 2, len(calls))
    # DB fără schema gateway-ului: produsul e refuzat, iar la import la fel
    con = sqlite3.connect(str(config.DB_PATH))
    con.execute("DROP TABLE hosts")
    con.commit()
    con.close()
    before = sorted(os.listdir(config.DATA_DIR / "backups"))
    check("R-M2: DB fără tabelele gateway-ului → export refuzat",
          refused(lambda: backup.make_encrypted(PASS, keys=hk)) and refused(lambda: backup.run_scheduled_backup(keys=hk))
          and sorted(os.listdir(config.DATA_DIR / "backups")) == before)
    kw = (config.DATA_DIR / "keys.wtk").read_bytes()
    t, _e = tar_bytes([("webterm.db", config.DB_PATH.read_bytes()), ("keys.wtk", kw)])
    try:
        backup.stage_restore(wrap_tar(hk, t), PASS, keys=hk)
        msg = ""
    except ValueError as e:
        msg = str(e)
    check("R-M2: import al unui DB fără schemă refuzat înainte de staging",
          "missing tables: hosts" in msg and nothing_staged()
          and backup_api._backup_value_error(ValueError(msg)).code == "backup.badFile", msg)
    con = sqlite3.connect(str(config.DB_PATH))
    con.execute("CREATE TABLE hosts(id INTEGER PRIMARY KEY)")
    con.commit()
    con.close()
    # export peste limita de upload a restore-ului → refuzat la producere
    old = backup.UPLOAD_MAX
    backup.UPLOAD_MAX = 512
    try:
        try:
            backup.make_encrypted(PASS, include_transcripts=True, keys=hk)
            err = None
        except wts.SnapshotTooLarge as e:
            err = e
        check("R-M2: export > limita de upload → SnapshotTooLarge (backup.limitExceeded)",
              err is not None and backup_api._backup_value_error(err).code == "backup.limitExceeded")
        name = backup.run_scheduled_backup(keys=hk)
        check("R-M2: limita nu atinge snapshotul local programat", name.endswith(backup.WTS_EXT))
        check("R-M2: nici descărcarea unui snapshot stocat peste limită",
              refused(lambda: backup.encrypt_stored(name, PASS, keys=hk), wts.SnapshotTooLarge))
    finally:
        backup.UPLOAD_MAX = old
    check("R-M2: ruta de upload foloseşte aceeaşi limită", backup_api.UPLOAD_MAX == backup.UPLOAD_MAX)


def rm3_tests():
    # volum legacy cu backups/ symlink către alt disc
    volume("RM3", protected=False)
    other = os.path.join(ROOT, "RM3-otherdisk")
    os.makedirs(other)
    Path(other, "webterm-20260101-000000.wtsnap").write_bytes(b"x")
    os.symlink(other, config.DATA_DIR / "backups")
    check("R-M3: backups/ symlink pe volum legacy → legacy (nu ambiguu)", backup.volume_kind() == "legacy")
    check("R-M3: snapshotul 3.7 merge prin legătură", backup.make_snapshot()[:2] == b"\x1f\x8b")
    Path(other, "webterm-x.wts").write_bytes(b"x")
    check("R-M3: un .wts în ţinta legăturii → refuz (urmă 3.8)", refused(backup.volume_kind))
    os.unlink(os.path.join(other, "webterm-x.wts"))
    os.unlink(config.DATA_DIR / "backups")
    os.symlink(os.path.join(ROOT, "RM3-missing"), config.DATA_DIR / "backups")
    check("R-M3: legătură backups/ care nu se poate lista → refuz", refused(backup.volume_kind))
    os.unlink(config.DATA_DIR / "backups")
    # transcripts/ symlink (layout 3.7)
    tx_other = os.path.join(ROOT, "RM3-tx")
    shutil.move(str(config.TRANSCRIPT_DIR), tx_other)
    os.symlink(tx_other, config.TRANSCRIPT_DIR)
    check("R-M3: transcripts/ symlink pe volum legacy → legacy", backup.volume_kind() == "legacy")
    check("R-M3: snapshotul 3.7 cu transcripturi prin legătură",
          "transcripts/s1.out" in tarfile.open(fileobj=io.BytesIO(backup.make_snapshot(True))).getnames())
    Path(tx_other, "arhiva", "s7.wtx").write_bytes(b"x")
    check("R-M3: segment rezervat în ţinta legăturii → refuz", refused(backup.volume_kind))
    os.unlink(os.path.join(tx_other, "arhiva", "s7.wtx"))
    # cache: o a doua clasificare nu rescanează; o schimbare o invalidează
    calls = []
    orig = backup._classify
    backup._classify = lambda dfd: (calls.append(1), orig(dfd))[1]
    try:
        backup._invalidate_kind()
        backup.volume_kind()
        backup.volume_kind()
        backup.is_protected()
        n1 = len(calls)
        (config.DATA_DIR / "backups").mkdir(exist_ok=True)
        Path(config.DATA_DIR, "backups", "webterm-y.wts").write_bytes(b"x")
        r = refused(backup.volume_kind)
        n2 = len(calls)
        os.unlink(config.DATA_DIR / "backups" / "webterm-y.wts")
        backup.volume_kind()
        backup._invalidate_kind()
        backup.volume_kind()
    finally:
        backup._classify = orig
    check("R-M3: clasificarea e refolosită (un singur inventar pentru 3 apeluri)", n1 == 1, n1)
    check("R-M3: o schimbare în backups/ invalidează cache-ul (refuz văzut)", r and n2 == 2, n2)
    check("R-M3: invalidarea explicită rescanează", len(calls) == 4, len(calls))
    # volum protejat: refuzul conservator rămâne (transcripts/ symlink nu intră în backup)
    hk, K = volume("RM3P")
    tx2 = os.path.join(ROOT, "RM3P-tx")
    shutil.move(str(config.TRANSCRIPT_DIR), tx2)
    os.symlink(tx2, config.TRANSCRIPT_DIR)
    check("R-M3: volum protejat cu transcripts/ symlink → backup cu transcripturi refuzat",
          refused(lambda: backup.make_encrypted(PASS, include_transcripts=True, keys=hk)))


def rl1_tests():
    hk, K = volume("RL1")
    blob = backup.make_encrypted(PASS, keys=hk)
    orig = time.time
    time.time = lambda: 1700000000.0
    try:
        for _ in range(2):
            hk = host_keys(K["mk"])
            backup.stage_restore(blob, PASS, keys=hk)
            backup.apply_pending_restore(keys=hk)
    finally:
        time.time = orig
    keeps = [n for n in os.listdir(config.DATA_DIR / "backups") if n.startswith("pre-restore-1700000000-")]
    check("R-L1: două apply-uri în aceeaşi secundă → două copii distincte", len(keeps) == 2, keeps)
    target = config.DATA_DIR / "backups" / keeps[0]
    before = target.read_bytes()
    hk = host_keys(K["mk"])
    _h, blob_k = backup._host(hk)
    check("R-L1: publicarea exclusivă nu suprascrie o copie existentă",
          refused(lambda: backup._wts_to_file(target, _h, blob_k, False, portable=True, exclusive=True), FileExistsError)
          and target.read_bytes() == before and not os.path.exists(str(target) + backup.TMP_SUFFIX))


def _retar_secret(raw, secret):
    """Acelaşi tar.gz 3.7, cu `secret` înlocuit (o cheie de 32 de octeţi din altă copie)."""
    src = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as dst:
        for m in src.getmembers():
            if m.name == "secret":
                m.size = len(secret)
                dst.addfile(m, io.BytesIO(secret))
            else:
                dst.addfile(m, src.extractfile(m) if m.isfile() else None)
    return out.getvalue()


def pr4_recheck_tests():
    """Recheck PR4 (b3be939): R-H2 — FK_legacy dovedit pe DB-ul EXACT al arhivei înainte de orice
    publicare (import pe volum protejat, verify, restore 3.7 pe volum legacy); R-M1 — staging-ul
    spune explicit cât a ajuns (nimic schimbat / commit durabil / incert)."""
    _n, _KL = volume("RCL", protected=False, email="legacy@rc")
    good = backup.make_encrypted(PASS)
    raw = backup.decrypt(good, PASS)
    foreign = _retar_secret(raw, os.urandom(32))
    blob_f = backup.encrypt(foreign, PASS)
    hk, _K = volume("RCP")
    check("R-H2: verify_legacy_import refuză un secret de 32 de octeţi străin DB-ului",
          refused(lambda: backup.verify_legacy_import(foreign, keys=hk)) and nothing_staged())
    pr = backup.StageProgress()
    check("R-H2: importul legacy cu secret străin e refuzat înainte de staging (nimic schimbat)",
          refused(lambda: backup.stage_restore(blob_f, PASS, keys=hk, legacy_import=True, progress=pr))
          and nothing_staged() and not pr.mutated and not pr.committed)
    info = backup.verify_legacy_import(raw, keys=hk)
    check("R-H2: verify_legacy_import acceptă arhiva cu cheia ei", info.get("format") == "legacy-import"
          and nothing_staged(), info)
    pr = backup.StageProgress()
    backup.stage_restore(good, PASS, keys=hk, legacy_import=True, progress=pr)
    check("R-M1: import reuşit → mutated + committed", pr.mutated and pr.committed and flag_doc()["state"] == "staged")

    use(os.path.join(ROOT, "RCL"))
    check("R-H2: restore 3.7 pe volum legacy cu secret străin refuzat (verify + stage), nimic schimbat",
          refused(lambda: backup.verify_restorable(blob_f, PASS))
          and refused(lambda: backup.stage_restore(blob_f, PASS)) and nothing_staged())
    # R-M1: fsync-ul directorului eşuează DUPĂ rename-ul flagului → incert, nu „commit”
    orig, state = backup._fsync, {"armed": False}

    def fsync(fd):
        if state["armed"]:
            raise OSError(5, "injected EIO")
        return orig(fd)

    def fault(name):
        if name == "flag:renamed":
            state["armed"] = True
    backup._fsync, backup._fault = fsync, fault
    pr = backup.StageProgress()
    try:
        r = refused(lambda: backup.stage_restore(good, PASS, progress=pr), OSError)
    finally:
        backup._fsync, backup._fault = orig, None
    check("R-M1: fsync eşuat după rename-ul flagului (legacy) → eroare, mutated fără committed",
          r and pr.mutated and not pr.committed)
    pr = backup.StageProgress()
    backup.stage_restore(good, PASS, progress=pr)
    rd = config.DATA_DIR / "restore-pending"
    check("R-M1: staging legacy durabil: set complet, flag 3.7, committed",
          pr.committed and (rd / "webterm.db").is_file() and (rd / "secret").read_bytes() == _KL["secret"]
          and (config.DATA_DIR / ".restore-flag").read_bytes()[:1] != b"{"
          and not (config.DATA_DIR / ".restore-flag.tmp").exists()
          and not list((config.DATA_DIR / "backups").glob(".restore-verify-*")))
    check("R-M1: apply 3.7 al setului publicat", backup.apply_pending_restore() and db_email() == "legacy@rc")


def pr4_second_recheck_tests():
    """Al doilea recheck PR4 (e1dea74), RC-M1: o singură rută (formatul interior + politica ţintei)
    pentru verify şi stage; perechea EXACTĂ publicată (DB-ul din set + cheia din set) re-dovedită
    chiar înainte de publicare, pe volum legacy şi la importul legacy."""
    import dataclasses
    _n, _KL = volume("RC2L", protected=False, email="legacy@rc2")
    good = backup.make_encrypted(PASS)
    raw = backup.decrypt(good, PASS)
    R = backup.restore_route
    check("RC-M1: restore_route — tabelul complet (format interior × ţintă × opţiune)",
          R(raw, False, False) == "legacy-volume" and R(raw, True, True) == "legacy-import"
          and refused(lambda: R(raw, True, False)) and refused(lambda: R(raw, False, True))
          and R(b"WTS1" + b"x" * 60, True, False) == "wts" and refused(lambda: R(b"WTS1" + b"x" * 60, False, False))
          and refused(lambda: R(b"WTS1" + b"x" * 60, True, True)) and refused(lambda: R(b"nimic", False, False)))
    # volum legacy: cheia scrisă în set diferă de cea verificată → re-proba perechii publicate refuză
    orig_w = backup._write_new

    def bad_write(path, data):
        if os.path.basename(path) == "secret":
            data = os.urandom(len(data))
        return orig_w(path, data)
    backup._write_new = bad_write
    pr = backup.StageProgress()
    try:
        r = refused(lambda: backup.stage_restore(good, PASS, progress=pr))
    finally:
        backup._write_new = orig_w
    check("RC-M1: legacy → volum legacy: cheia din SET nu deschide DB-ul din set → refuz înainte de publicare",
          r and not pr.mutated and nothing_staged())
    check("RC-M1: verify_legacy_volume = acelaşi verdict ca staging-ul (arhiva bună trece)",
          backup.verify_legacy_volume(raw)["has_secret"] is True and nothing_staged())
    pr = backup.StageProgress()
    backup.stage_restore(good, PASS, progress=pr)
    rd = config.DATA_DIR / "restore-pending"
    check("RC-M1: staging legacy prin extractorul strict: setul are exact DB + cheie + perechea de semnare",
          pr.committed and (rd / "secret").read_bytes() == _KL["secret"]
          and {p.name for p in rd.iterdir()} <= {"webterm.db", "secret", "agent-signing.key", "agent-signing.pub", "transcripts"},
          sorted(p.name for p in rd.iterdir()))
    check("RC-M1: …şi boot-ul 3.7 îl aplică", backup.apply_pending_restore() and db_email() == "legacy@rc2")

    # import legacy pe volum protejat: FK_legacy din keys.wtk-ul staged ≠ cheia dovedită → refuz
    hk, _K = volume("RC2P")
    orig_m = backup._manifest_for_host
    backup._manifest_for_host = lambda src, h: orig_m(dataclasses.replace(src, fk_legacy=os.urandom(32)), h)
    pr = backup.StageProgress()
    try:
        r = refused(lambda: backup.stage_restore(good, PASS, keys=hk, legacy_import=True, progress=pr))
    finally:
        backup._manifest_for_host = orig_m
    check("RC-M1: import legacy: FK_legacy din keys.wtk-ul STAGED nu deschide DB-ul din set → refuz, nimic schimbat",
          r and not pr.mutated and nothing_staged())
    check("RC-M1: verify() pe volum protejat al unui WTBK1 cu tar 3.7 nu trece prin calea legacy-volume",
          refused(lambda: backup.verify_legacy_volume(raw)))
    pr = backup.StageProgress()
    check("RC-M1: stage_restore WTBK1(3.7) pe volum protejat fără import explicit → refuz, nimic schimbat",
          refused(lambda: backup.stage_restore(good, PASS, keys=hk, progress=pr)) and not pr.mutated and nothing_staged())


def recheck_tests():
    rh1_tests()
    rh2_tests()
    rm1_tests()
    rm2_tests()
    rm3_tests()
    rl1_tests()


def review_tests():
    h1_tests()
    h2_tests()
    h3_tests()
    m1_tests()
    m2_tests()
    m4_tests()
    l1_tests()


def main():
    # ── A: volum protejat, cu un `secret` rămas (sub-starea secret_leftover a migrării)
    hk, K = volume("A", secret_leftover=True)
    check("is_protected", backup.is_protected())
    check("make_snapshot în clar refuzat pe volum protejat", refused(lambda: backup.make_snapshot()))
    check("fără keyring (niciun furnizor) → refuz, nu legacy",
          refused(lambda: backup.run_scheduled_backup()) and refused(lambda: backup.make_encrypted(PASS)))
    other_hk, _ = volume("tmpX")
    use(os.path.join(ROOT, "A"))
    check("keyring străin (alt MK) refuzat", refused(lambda: backup.run_scheduled_backup(keys=other_hk)))

    # 1) snapshot local programat (.wts)
    name = backup.run_scheduled_backup(include_transcripts=True, keys=hk)
    p = config.DATA_DIR / "backups" / name
    data = p.read_bytes()
    check("programat: extensia .wts", name.endswith(backup.WTS_EXT), name)
    check("programat: 0600", (p.stat().st_mode & 0o777) == 0o600)
    check("programat: header WTS1, doar plic local", data[:4] == b"WTS1" and data[5] == wts.FLAG_LOCAL)
    check("programat: listat", name in {b["name"] for b in backup.list_backups()})
    check("programat: nicio cheie brută în container", not raw_keys_in([data], K))
    plain = tar_plain(data, snk=K["snk"], inst=hk.ring.installation_id)
    names = tar_names(plain)
    check("conţinut: fără secret / master.key", "secret" not in names and "master.key" not in names, names)
    check("conţinut: keys.wtk + webterm.db + manifest (ultimul)",
          {"keys.wtk", "webterm.db"} <= set(names) and names[-1] == backup.CONTENT_MANIFEST, names)
    check("conţinut: transcripturi incluse", "transcripts/s1.out" in names and "transcripts/arhiva/s0.out" in names)
    check("conţinut: nicio cheie brută în tar-ul decriptat", not raw_keys_in([plain], K))
    check("conţinut: keys.wtk = cel de pe volum",
          tarfile.open(fileobj=io.BytesIO(plain)).extractfile("keys.wtk").read()
          == (config.DATA_DIR / "keys.wtk").read_bytes())
    check("MK-ul nu deschide un snapshot local (doar SNK)",
          refused(lambda: tar_plain(data, mk=K["mk"]), wts.SnapshotWrongKey))
    info = backup.verify_stored(name, keys=hk)
    check("verify_stored .wts", info["format"] == "WTS1" and info["users_since"] == 1000 and info["has_transcripts"])
    check("verify_stored nu lasă directoare temporare", nothing_staged())

    # furnizorul înregistrat de boot înlocuieşte parametrul
    backup.set_host_keys_provider(lambda: hk)
    try:
        n2 = backup.run_scheduled_backup()
        check("furnizor de keyring: backup fără parametru", n2.endswith(".wts"))
    finally:
        backup.set_host_keys_provider(None)

    # 2) scriere ambiguă: eşec la fsync → nimic vizibil; reîncercarea = CK nou
    before = {b["name"] for b in backup.list_backups()}
    orig = backup._fsync
    backup._fsync = lambda fd: (_ for _ in ()).throw(OSError("disk full"))
    try:
        backup.run_scheduled_backup(keys=hk)
        check("eşec la scriere propagat", False)
    except OSError:
        check("eşec la scriere propagat", True)
    finally:
        backup._fsync = orig
    check("după eşec: niciun .wts nou, niciun .tmp",
          {b["name"] for b in backup.list_backups()} == before
          and not list((config.DATA_DIR / "backups").glob("*.tmp")))
    time.sleep(1.1)
    n3 = backup.run_scheduled_backup(keys=hk)
    d3 = (config.DATA_DIR / "backups" / n3).read_bytes()
    check("reîncercare: alt CK (plic diferit)", d3[60:143] != data[60:143])

    # 3) descărcare: WTBK1(WTS1 portabil), deschis cu parola + MK
    blob = backup.make_encrypted(PASS, include_transcripts=False, keys=hk)
    inner = backup.decrypt(blob, PASS)
    check("download: WTBK1 peste WTS1 local+portabil", blob[:5] == b"WTBK1" and inner[:4] == b"WTS1"
          and inner[5] == wts.FLAG_LOCAL | wts.FLAG_PORTABLE)
    check("download: nicio cheie brută", not raw_keys_in([blob, inner], K))
    check("download: MK-ul îl deschide (kitul de recuperare)",
          "keys.wtk" in tar_names(tar_plain(inner, mk=K["mk"])))
    check("download: parolă greşită refuzată", refused(lambda: backup.verify(blob, "gresita-rau-x", keys=hk)))
    check("verify_restorable pe WTS1", backup.verify_restorable(blob, PASS, keys=hk)["format"] == "WTS1")
    sdl = backup.encrypt_stored(name, PASS, keys=hk)
    sin = backup.decrypt(sdl, PASS)
    check("stocat → download portabil, CK nou",
          sin[5] == 3 and sin[60:143] != data[60:143] and "webterm.db" in tar_names(tar_plain(sin, mk=K["mk"])))
    check("remote_name", backup.remote_name("webterm-1.wts") == "webterm-1.wtbk"
          and backup.remote_name("webterm-1.wtsnap") == "webterm-1.wtbk")

    # 4) restore round-trip pe acelaşi volum
    set_email("schimbat@x")
    check("restore: fără keyring refuzat, nimic în staging",
          refused(lambda: backup.stage_restore(blob, PASS)) and nothing_staged())
    info = backup.stage_restore(blob, PASS, keys=hk)
    rd = pending()
    check("staging: webterm.db + keys.wtk, fără secret",
          (rd / "webterm.db").exists() and (rd / "keys.wtk").exists() and not (rd / "secret").exists())
    check("staging: nicio cheie brută", not raw_keys_in([str(rd)], K))
    st = kr.open_keyring_bytes((rd / "keys.wtk").read_bytes(), K["mk"], kr.PROFILE_V1)
    check("staging: keys.wtk se deschide cu MK-ul gazdei, epoch +1, aceeaşi instalare",
          st.epoch == 2 and st.installation_id == hk.ring.installation_id and st.snk == K["snk"])
    check("staging: fără directoare temporare", not list((config.DATA_DIR / "backups").glob(".restore-verify-*")))
    check("apply fără keyring refuzat", refused(lambda: backup.apply_pending_restore()))
    check("apply: DB încă nemodificată după refuz", db_email() == "schimbat@x")
    applied = backup.apply_pending_restore(keys=hk)
    check("apply: DB restaurat", applied and db_email() == "a@b.c")
    check("apply: keys.wtk = cel din staging (epoch 2)",
          kr.open_keyring_bytes((config.DATA_DIR / "keys.wtk").read_bytes(), K["mk"], kr.PROFILE_V1).epoch == 2)
    check("apply: staging + flag curăţate", nothing_staged())
    keeps = list((config.DATA_DIR / "backups").glob("pre-restore-*.wts.keep"))
    check("apply: copie de siguranţă WTS1 (local+portabil), fără chei brute",
          len(keeps) == 1 and keeps[0].read_bytes()[5] == 3 and not raw_keys_in([str(keeps[0])], K))
    check("copia de siguranţă se deschide cu MK-ul după schimbarea keys.wtk",
          "webterm.db" in tar_names(tar_plain(keeps[0].read_bytes(), mk=K["mk"])))
    check("keyring vechi (epoch 1) refuzat după restore", refused(lambda: backup.run_scheduled_backup(keys=hk)))
    hk = host_keys(K["mk"])
    check("`secret` rămas pe volum nu intră în backup",
          "secret" not in tar_names(tar_plain(backup.decrypt(backup.make_encrypted(PASS, keys=hk), PASS),
                                              mk=K["mk"])))

    # 5) refuzuri ÎNAINTE de staging (conţinut autentic dar ostil)
    db_bytes = config.DB_PATH.read_bytes()
    kw = (config.DATA_DIR / "keys.wtk").read_bytes()
    cases = {
        "secret în arhivă": [("webterm.db", db_bytes), ("keys.wtk", kw), ("secret", K["secret"])],
        "nume cu ..": [("webterm.db", db_bytes), ("keys.wtk", kw), ("transcripts/../x", b"1")],
        "fără keys.wtk": [("webterm.db", db_bytes)],
        "fişier apoi director cu acelaşi nume": [("webterm.db", db_bytes), ("keys.wtk", kw),
                                                 ("transcripts/a", b"1"), ("transcripts/a/b", b"2")],
        "intrare dublată": [("webterm.db", db_bytes), ("keys.wtk", kw), ("keys.wtk", kw)],
        "fişier necunoscut la rădăcină": [("webterm.db", db_bytes), ("keys.wtk", kw), ("master.key", b"k")],
        "DB corupt": [("webterm.db", b"SQLite format 3\x00" + b"\xff" * 4000), ("keys.wtk", kw)],
        "keys.wtk de la altă instalare": [("webterm.db", db_bytes),
                                          ("keys.wtk", (Path(ROOT) / "tmpX" / "keys.wtk").read_bytes())],
    }
    for label, members in cases.items():
        b = custom_wts(hk, members)
        check(f"refuzat înainte de staging: {label}",
              refused(lambda: backup.stage_restore(b, PASS, keys=hk)) and nothing_staged())
    b = custom_wts(hk, [("webterm.db", db_bytes), ("keys.wtk", kw)], bad_hash=True)
    check("refuzat: manifest de conţinut care nu corespunde",
          refused(lambda: backup.stage_restore(b, PASS, keys=hk)) and nothing_staged())
    b = custom_wts(hk, [("webterm.db", db_bytes), ("keys.wtk", kw)], manifest=False)
    check("refuzat: fără manifest de conţinut", refused(lambda: backup.stage_restore(b, PASS, keys=hk))
          and nothing_staged())
    bomb = custom_wts(hk, [("webterm.db", b"\0" * (100 << 20)), ("keys.wtk", kw)])
    check("bombă de compresie refuzată înainte de staging",
          refused(lambda: backup.stage_restore(bomb, PASS, keys=hk), wts.SnapshotTooLarge) and nothing_staged())
    old_max = backup.MAX_MEMBERS
    backup.MAX_MEMBERS = 3
    try:
        b = custom_wts(hk, [("webterm.db", db_bytes), ("keys.wtk", kw)] + [(f"transcripts/t{i}.out", b"x") for i in range(5)])
        check("prea multe intrări refuzate", refused(lambda: backup.stage_restore(b, PASS, keys=hk),
                                                     wts.SnapshotTooLarge) and nothing_staged())
    finally:
        backup.MAX_MEMBERS = old_max
    tampered = bytearray(backup.decrypt(blob, PASS))
    tampered[-40] ^= 1
    check("WTS1 modificat (sub parolă) refuzat",
          refused(lambda: backup.stage_restore(backup.encrypt(bytes(tampered), PASS), PASS, keys=hk))
          and nothing_staged())

    # 6) backup portabil al ALTEI instalări (B): cere MK-ul operatorului
    hkB, KB = volume("B", email="b@b.b")
    blobB = backup.make_encrypted(PASS, keys=hkB)
    use(os.path.join(ROOT, "A"))
    check("B pe A fără MK: refuzat, nimic în staging",
          refused(lambda: backup.stage_restore(blobB, PASS, keys=hk), wts.SnapshotWrongKey) and nothing_staged())
    check("B pe A cu MK greşit: refuzat",
          refused(lambda: backup.stage_restore(blobB, PASS, keys=hk, mk=os.urandom(32)), wts.SnapshotWrongKey)
          and nothing_staged())
    check("verify B cu MK-ul operatorului", backup.verify(blobB, PASS, keys=hk, mk=KB["mk"])["same_installation"] is False)
    backup.stage_restore(blobB, PASS, keys=hk, mk=KB["mk"])
    rd = pending()
    stB = kr.open_keyring_bytes((rd / "keys.wtk").read_bytes(), K["mk"], kr.PROFILE_V1)
    check("B: keys.wtk re-ambalat sub MK-ul gazdei, instalarea lui B, MK-ul B retras",
          stB.installation_id == hkB.ring.installation_id and stB.snk == KB["snk"]
          and kr.key_id(KB["mk"]) in stB.retired_mk_ids)
    check("B: nici MK-ul lui B, nici cheile brute în staging",
          not raw_keys_in([str(rd)], KB) and not raw_keys_in([str(rd)], K))
    backup.apply_pending_restore(keys=hk)
    check("B aplicat: DB-ul lui B", db_email() == "b@b.b")
    hk = host_keys(K["mk"])
    check("B aplicat: instalarea lui B, deschisă cu MK-ul gazdei",
          hk.ring.installation_id == hkB.ring.installation_id)

    # 7) backup pre-3.8 pe volum protejat: doar import explicit; cheia brută nu ajunge în staging
    _none, KC = volume("C", protected=False, email="legacy@c")
    blobC = backup.make_encrypted(PASS)
    check("volum legacy: backup-ul e tar.gz cu secret (cod neschimbat)",
          "secret" in tarfile.open(fileobj=io.BytesIO(backup.decrypt(blobC, PASS))).getnames())
    check("WTS1 pe volum legacy refuzat (verify + restore)",
          refused(lambda: backup.verify(blob, PASS)) and refused(lambda: backup.stage_restore(blob, PASS))
          and nothing_staged())
    use(os.path.join(ROOT, "A"))
    check("pre-3.8 pe protejat fără import explicit refuzat",
          refused(lambda: backup.stage_restore(blobC, PASS, keys=hk)) and nothing_staged())
    backup.stage_restore(blobC, PASS, keys=hk, legacy_import=True)
    rd = pending()
    check("import: fără secret în staging", not (rd / "secret").exists())
    check("import: cheia brută nicăieri în staging", not raw_keys_in([str(rd)], {"secret": KC["secret"]}))
    stC = kr.open_keyring_bytes((rd / "keys.wtk").read_bytes(), K["mk"], kr.PROFILE_V1)
    check("import: FK_legacy = cheia backup-ului, restul cheilor gazdei",
          stC.fk_legacy == KC["secret"] and stC.kwk == hk.ring.kwk and stC.epoch == hk.ring.epoch + 1)
    backup.apply_pending_restore(keys=hk)
    check("import aplicat: DB-ul legacy", db_email() == "legacy@c" and not (config.DATA_DIR / "secret.restoring").exists())
    hk = host_keys(K["mk"])

    # 8) staging ostil la apply
    def stage_manual(files):
        rd = config.DATA_DIR / "restore-pending"
        rd.mkdir()
        for n, b in files.items():
            (rd / n).write_bytes(b)
        (config.DATA_DIR / ".restore-flag").write_text("1")
        return rd
    import shutil
    rd = stage_manual({"webterm.db": config.DB_PATH.read_bytes(), "keys.wtk": (config.DATA_DIR / "keys.wtk").read_bytes(),
                       "secret": b"S" * 32})
    check("apply protejat refuză un staging cu `secret`", refused(lambda: backup.apply_pending_restore(keys=hk)))
    shutil.rmtree(rd)
    rd = stage_manual({"webterm.db": b"x", "keys.wtk": (Path(ROOT) / "tmpX" / "keys.wtk").read_bytes()})
    before_db = config.DB_PATH.read_bytes()
    check("apply refuză un keys.wtk care nu se deschide cu MK-ul gazdei",
          refused(lambda: backup.apply_pending_restore(keys=hk)) and config.DB_PATH.read_bytes() == before_db)
    shutil.rmtree(rd)
    (config.DATA_DIR / ".restore-flag").unlink()
    use(os.path.join(ROOT, "C"))
    rd = stage_manual({"webterm.db": b"x", "keys.wtk": b"k"})
    check("volum legacy refuză un staging cu keys.wtk", refused(lambda: backup.apply_pending_restore()))
    check("volum legacy: secret neatins", (config.DATA_DIR / "secret").read_bytes() == KC["secret"])
    use(os.path.join(ROOT, "A"))

    # 9) retenţie + nume
    old = config.DATA_DIR / "backups" / "webterm-old.wts"
    old.write_bytes(b"x")
    os.utime(old, (time.time() - 30 * 86400,) * 2)
    tmp = config.DATA_DIR / "backups" / ("webterm-crash.wts" + backup.TMP_SUFFIX)
    tmp.write_bytes(b"x")
    os.utime(tmp, (time.time() - 7200,) * 2)
    backup.prune_backups()
    check("prune: .wts vechi + .wts.tmp rămas şterse", not old.exists() and not tmp.exists())
    check("nume ostil refuzat la verify", refused(lambda: backup.verify_stored("../x.wts", keys=hk), (ValueError, FileNotFoundError)))
    check("keys.wtk ca symlink → refuz", (lambda: (os.replace(config.DATA_DIR / "keys.wtk", config.DATA_DIR / "k2"),
                                                    os.symlink(config.DATA_DIR / "k2", config.DATA_DIR / "keys.wtk"),
                                                    refused(backup.is_protected))[-1])())

    review_tests()
    recheck_tests()
    pr4_recheck_tests()
    pr4_second_recheck_tests()

    print(f"\n{ok}/{total} passed")
    shutil.rmtree(ROOT, ignore_errors=True)
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
