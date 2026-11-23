"""Backup / restore pe un volum PROTEJAT (keys.wtk, 3.8; gateway/app/backup.py, §12.10).

Snapshotul nu conţine `secret` sau MK (căutăm cheile brute în container, în tar-ul decriptat,
în staging şi în copia de siguranţă), conţine keys.wtk; restore round-trip pe un volum temporar,
restore din altă instalare cu MK-ul operatorului, import explicit al unui backup pre-3.8 fără ca
cheia brută să ajungă în staging, şi refuz ÎNAINTE de staging la cheie greşită / conţinut
modificat / bombă / prea multe intrări. Partea legacy rămâne în backup_test.py, neschimbată."""
import io
import json
import os
import sqlite3
import sys
import tarfile
import tempfile
import time
import zlib
from pathlib import Path

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
    con.execute("INSERT INTO users(email, created) VALUES(?, 1000)", (email,))
    con.commit()
    con.close()
    (config.DATA_DIR / "agent-signing.key").write_bytes(b"SIGNING-PRIVATE-" + name.encode())
    (config.TRANSCRIPT_DIR / "s1.out").write_bytes(b"hello transcript " * 100)
    (config.TRANSCRIPT_DIR / "s1.cast").write_bytes(b'{"v":2}\n')
    (config.TRANSCRIPT_DIR / "arhiva" / "s0.out").write_bytes(b"old")
    keys = {"secret": os.urandom(32)}
    if not protected:
        (config.DATA_DIR / "secret").write_bytes(keys["secret"])
        return None, keys
    if secret_leftover:
        (config.DATA_DIR / "secret").write_bytes(keys["secret"])
    keys.update(mk=os.urandom(32), kwk=os.urandom(32), snk=os.urandom(32), fk=os.urandom(32),
                fk_legacy=os.urandom(32))
    mk = keys["mk"]
    envs = (kr.wrap_under_mk(mk, kr.KT_KWK, keys["kwk"]), kr.wrap_under_mk(mk, kr.KT_SNK, keys["snk"]),
            kr.wrap_under_kwk(keys["kwk"], kr.KT_FK_LEGACY, keys["fk_legacy"]),
            kr.wrap_under_kwk(keys["kwk"], kr.KT_FK, keys["fk"]))
    blob = kr.encode_manifest(kr.KeyManifest(os.urandom(16), 1, kr.key_id(mk), (), envs), mk)
    (config.DATA_DIR / "keys.wtk").write_bytes(blob)
    return host_keys(mk), keys


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
            m = json.dumps({"format": "wts-content-1", "files": entries}).encode()
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
    return (not (config.DATA_DIR / "restore-pending").exists() and not (config.DATA_DIR / ".restore-flag").exists()
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
    rd = config.DATA_DIR / "restore-pending"
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
        b = custom_wts(hk, [("webterm.db", db_bytes), ("keys.wtk", kw)] + [(f"transcripts/t{i}", b"x") for i in range(5)])
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
    rd = config.DATA_DIR / "restore-pending"
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
    rd = config.DATA_DIR / "restore-pending"
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

    print(f"\n{ok}/{total} passed")
    shutil.rmtree(ROOT, ignore_errors=True)
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
