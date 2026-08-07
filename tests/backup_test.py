"""Backup / restore din Settings (gateway/app/backup.py).

Verifică: roundtrip criptare (scrypt→AES-GCM), respingerea parolei greșite / fișierului
străin, snapshot crash-consistent (VACUUM INTO) cu cheia seifului, backup-uri programate +
retenție, și fluxul stage→apply al restore-ului (swap DB + cheie la boot). Fără WS/HTTP."""
import os
import sqlite3
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import backup, config  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def _seed_db(email="a@b.c"):
    config.ensure_dirs()
    con = sqlite3.connect(str(config.DB_PATH))
    con.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT, created REAL)")
    con.execute("DELETE FROM users")
    con.execute("INSERT INTO users(email, created) VALUES(?, 1000)", (email,))
    con.commit()
    con.close()
    (config.DATA_DIR / "secret").write_bytes(b"S" * 32)


def main():
    _seed_db()

    # 1) criptare roundtrip + meta corectă
    blob = backup.make_encrypted("parola-tare", include_transcripts=False)
    check("magic WTBK1", blob[:5] == b"WTBK1")
    info = backup.verify(blob, "parola-tare")
    check("verify: are secret", info["has_secret"] is True)
    check("verify: users_since păstrat", info["users_since"] == 1000)

    # 2) parolă greșită → ValueError, nu date
    try:
        backup.verify(blob, "gresita-rau")
        check("parolă greșită respinsă", False, "a acceptat parola greșită")
    except ValueError:
        check("parolă greșită respinsă", True)

    # 3) fișier străin → ValueError (fără magic)
    try:
        backup.decrypt(b"nu-e-un-backup-webterm-deloc", "parola-tare")
        check("fișier străin respins", False)
    except ValueError:
        check("fișier străin respins", True)

    # 4) parola prea scurtă e treaba endpointului; aici doar că derivarea diferă pe salt
    b2 = backup.encrypt(b"x", "p")
    b3 = backup.encrypt(b"x", "p")
    check("nonce/salt aleator (blob-uri diferite)", b2 != b3)

    # 5) backup programat necriptat + list + retenție
    name = backup.run_scheduled_backup()
    check("scheduled backup .wtsnap", name.endswith(".wtsnap"))
    check("apare în list_backups", any(b["name"] == name for b in backup.list_backups()))
    # retenția: un fișier vechi de 8 zile dispare
    old = config.DATA_DIR / "backups" / "webterm-old.wtsnap"
    old.write_bytes(b"x")
    os.utime(old, (time.time() - 8 * 86400, time.time() - 8 * 86400))
    backup.prune_backups()
    check("retenție: >7 zile șters", not old.exists())
    check("retenție: recent păstrat", (config.DATA_DIR / "backups" / name).exists())

    # 6) encrypt_stored → download criptat cu parola userului
    enc = backup.encrypt_stored(name, "alta-parola")
    check("encrypt_stored verificabil", backup.verify(enc, "alta-parola")["has_secret"])

    # 7) encrypt_stored: nume cu traversare respins
    try:
        backup.encrypt_stored("../../etc/passwd", "x" * 8)
        check("encrypt_stored anti-traversal", False)
    except ValueError:
        check("encrypt_stored anti-traversal", True)

    # 8) stage + apply restore readuce starea veche
    con = sqlite3.connect(str(config.DB_PATH))
    con.execute("UPDATE users SET email='SCHIMBAT@x.y'")
    con.commit()
    con.close()
    backup.stage_restore(blob, "parola-tare")
    check("flag de restore scris", backup._restore_flag().exists())
    # reîncercabil: staging păstrează sursele (copy, nu move) până la commit
    check("staging are DB + secret înainte de apply",
          (backup._restore_dir() / "webterm.db").exists() and (backup._restore_dir() / "secret").exists())
    applied = backup.apply_pending_restore()
    check("apply_pending_restore = True", applied is True)
    check("staging șters DUPĂ apply (commit)", not backup._restore_dir().exists())
    check("fără temp .restoring rezidual",
          not list(config.DATA_DIR.glob("*.restoring")))
    con = sqlite3.connect(str(config.DB_PATH))
    email = con.execute("SELECT email FROM users").fetchone()[0]
    con.close()
    check("DB readus la starea din backup", email == "a@b.c", "email=%r" % email)
    check("flag curățat după apply", not backup._restore_flag().exists())
    # pre-restore are sufix .keep → NU apare în list_backups (glob *.wtsnap) și scapă de
    # retenție; îl căutăm direct în dir-ul de backups
    pre = list((config.DATA_DIR / "backups").glob("pre-restore-*.wtsnap.keep"))
    check("plasă de siguranță pre-restore creată (exemptă de retenție)", len(pre) >= 1,
          "găsite=%d" % len(pre))

    # 9) boot fără flag → no-op
    check("apply fără flag = no-op", backup.apply_pending_restore() is False)

    # 10) DB corupt în backup → refuzat la stage (integrity_check)
    bad = backup.encrypt(b"nu e un tar gzip valid", "p" * 8)
    try:
        backup.stage_restore(bad, "p" * 8)
        check("restore refuză conținut invalid", False)
    except ValueError:
        check("restore refuză conținut invalid", True)

    # 11) backup FĂRĂ cheia seifului (incomplet / de la alt instrument) → refuzat la stage
    import io as _io, tarfile as _tf
    buf = _io.BytesIO()
    with _tf.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(str(config.DB_PATH), arcname="webterm.db")   # doar DB, fără 'secret'
    nosecret = backup.encrypt(buf.getvalue(), "p" * 8)
    check("_inspect vede lipsa cheii", backup.verify(nosecret, "p" * 8)["has_secret"] is False)
    try:
        backup.stage_restore(nosecret, "p" * 8)
        check("restore refuză backup fără cheia seifului", False)
    except ValueError:
        check("restore refuză backup fără cheia seifului", True)

    # #5 (audit): bombă de compresie — plafon pe conţinutul DECOMPRIMAT (un tar.gz mic care
    # expandează la zeci de GB umple discul la _inspect/extractall). Coborâm plafonul sub
    # dimensiunea DB-ului real ca să declanşăm refuzul fără a genera GB.
    _orig_cap = backup.RESTORE_MAX_UNCOMPRESSED
    backup.RESTORE_MAX_UNCOMPRESSED = 100
    try:
        buf2 = _io.BytesIO()
        with _tf.open(fileobj=buf2, mode="w:gz") as tar:
            tar.add(str(config.DB_PATH), arcname="webterm.db")
        bomb = backup.encrypt(buf2.getvalue(), "p" * 8)
        try:
            backup.verify(bomb, "p" * 8)
            check("restore refuză o bombă de compresie (peste plafon decomprimat)", False)
        except ValueError as e:
            check("restore refuză o bombă de compresie (peste plafon decomprimat)",
                  ("bomb" in str(e).lower()) or ("prea mare" in str(e).lower()))
    finally:
        backup.RESTORE_MAX_UNCOMPRESSED = _orig_cap

    print(f"\n{ok}/{total} teste trecute")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
