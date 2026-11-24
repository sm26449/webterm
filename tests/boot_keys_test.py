"""Boot-ul real cu criptarea la repaus (3.8 PR4, docs/design/ENCRYPTION-AT-REST.md §12.9 Wiring
checklist; gateway/app/bootkeys.py + main.lifespan).

Scenarii end-to-end pe volume temporare:
  * volum 3.7 fără cheie → legacy, arborele identic octet cu octet în afară de `.lock`;
  * volum 3.7 + cheie → migrat; FK_legacy dovedit pe DB; valorile vechi se decriptează, cele noi
    poartă prefixul FK; tokenurile de forward emise înainte rămân valide;
  * `secret` străin (nu decriptează nimic din DB) → refuz, nimic schimbat; DB fără ciphertext →
    eligibil; WAL nescris + fără ciphertext → refuz; o valoare FK: lângă un secret 3.7 → refuz;
  * volum protejat + cheie greşită / lipsă → refuz, identic la două porniri;
  * restore 3.8 în staging + cheie greşită → refuz înainte de orice swap; cu cheia bună → aplicat,
    keys.wtk redeschis; restore 3.7 în staging + cheie → întâi restore, apoi migrare;
  * al doilea proces → refuz (`locked`); comenzile admin care scriu refuză cât ţine gateway-ul lock-ul;
  * volum gol fără cheie → refuz; cu WEBTERM_KEY_IN_VOLUME=1 → „reduced”;
  * ordinea reală din main.lifespan: cheie greşită + staging + temporare de plafon → refuz ÎNAINTE de
    clean-up (temporarele şi staging-ul rămân)."""
import asyncio
import base64
import hashlib
import os
import sqlite3
import stat
import sys
import tempfile
from pathlib import Path

ROOT = tempfile.mkdtemp(prefix="wt-bootkeys-")
os.environ["WEBTERM_DATA_DIR"] = os.path.join(ROOT, "default")
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
for _v in ("WEBTERM_MASTER_KEY_FILE", "WEBTERM_MASTER_KEY", "WEBTERM_KEY_IN_VOLUME"):
    os.environ.pop(_v, None)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402

from app import admin, backup, bootkeys, config, core, keys, security, syshealth  # noqa: E402

ok = 0
total = 0
PASS = "parola-de-test-lunga"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def use(d):
    config.DATA_DIR = Path(d)
    config.DB_PATH = config.DATA_DIR / "webterm.db"
    config.TRANSCRIPT_DIR = config.DATA_DIR / "transcripts"
    config.ARCHIVE_DIR = config.TRANSCRIPT_DIR / "arhiva"


def fernet(k):
    return Fernet(base64.urlsafe_b64encode(k))


def make_db(path, values=(), settings=()):
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, created REAL, totp_secret_encrypted TEXT)")
    con.execute("CREATE TABLE hosts(id INTEGER PRIMARY KEY, token_encrypted TEXT, credential_encrypted TEXT)")
    con.execute("CREATE TABLE sessions(id INTEGER PRIMARY KEY)")
    con.execute("CREATE TABLE app_settings(key TEXT PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO users(email, created) VALUES('a@b.c', 1000)")
    for v in values:
        con.execute("INSERT INTO hosts(token_encrypted) VALUES(?)", (v,))
    for k, v in settings:
        con.execute("INSERT INTO app_settings(key, value) VALUES(?, ?)", (k, v))
    con.commit()
    con.close()


def legacy_volume(name, encrypted=True, secret=None, settings=()):
    d = Path(ROOT) / name
    (d / "transcripts" / "arhiva").mkdir(parents=True)
    (d / "backups").mkdir()
    secret = secret or os.urandom(32)
    (d / "secret").write_bytes(secret)
    os.chmod(d / "secret", 0o600)
    make_db(d / "webterm.db", [fernet(secret).encrypt(b"agent-token").decode()] if encrypted else (),
            settings)
    (d / "transcripts" / "s1.out").write_bytes(b"hello " * 50)
    (d / "backups" / "webterm-1.wtsnap").write_bytes(b"3.7 snapshot with the raw key")
    use(d)
    return d, secret


def key_file(name, k=None):
    k = k or os.urandom(32)
    p = Path(ROOT) / "keys" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(base64.b64encode(k) + b"\n")
    os.chmod(p, 0o600)
    return str(p), k


def tree(d):
    """Arborele (recursiv, fără a urma symlinkuri): nume, tip, mod, mărime, conţinut, ţintă."""
    out = {}
    for base, dirs, files in os.walk(d):
        for n in dirs + files:
            p = os.path.join(base, n)
            st = os.lstat(p)
            rel = os.path.relpath(p, d)
            if stat.S_ISREG(st.st_mode):
                h = hashlib.sha256(Path(p).read_bytes()).hexdigest()
            elif stat.S_ISLNK(st.st_mode):
                h = os.readlink(p)
            else:
                h = ""
            out[rel] = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode),
                        st.st_size if not stat.S_ISDIR(st.st_mode) else 0, h)
    return out


def without_lock(t):
    return {k: v for k, v in t.items() if k != ".lock"}


def prepare(env):
    bootkeys.release()
    return bootkeys.prepare(env=env)


def refusal(env):
    bootkeys.release()
    try:
        bootkeys.prepare(env=env)
        return None
    except keys.BootRefused as e:
        return e
    finally:
        bootkeys.release()


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── 1. compatibilitate: volum 3.7, nicio cheie ─────────────────────────────────
def test_legacy_no_key():
    print("── volum 3.7 fără nicio sursă de cheie → exact ca înainte")
    d, secret = legacy_volume("legacy-nokey")
    before = tree(d)
    res = prepare({})
    config.ensure_dirs()
    core.cleanup_cap_temps()
    after = tree(d)
    check("starea e legacy", res.state.mode == "legacy" and bootkeys.STATE["mode"] == "legacy", res.state)
    check("arborele e identic octet cu octet în afară de .lock", without_lock(after) == before,
          set(after.items()) ^ set(before.items()))
    check(".lock creat 0600, gol", ".lock" in after and after[".lock"][1] == 0o600 and after[".lock"][2] == 0)
    v = fernet(secret).encrypt(b"x").decode()
    check("seiful = data/secret (o valoare 3.7 se decriptează)", security.decrypt_secret(v) == "x")
    new = security.encrypt_secret("nou")
    check("o scriere nouă în legacy rămâne FĂRĂ prefix (lizibilă şi de 3.7)",
          not new.startswith(security.FK_PREFIX) and fernet(secret).decrypt(new.encode()) == b"nou")
    check("o valoare FK: în legacy → InvalidToken (niciun fallback)",
          _raises(lambda: security.decrypt_secret(security.FK_PREFIX + v), InvalidToken))
    check("niciun furnizor de chei de backup înregistrat", backup._host_keys_provider is None
          and not backup._boot_protected)
    check("System health: info „criptarea e oprită”",
          run(syshealth.c_crypto_protection()).key == "crypto_legacy")
    check("…copiile cu cheia brută nu se raportează pe legacy", run(syshealth.c_crypto_legacy_copies()) is None)
    # a doua pornire: tot identic (inclusiv .lock)
    t1 = tree(d)
    prepare({})
    check("a doua pornire legacy: identic, .lock inclus", tree(d) == t1)
    bootkeys.release()


def _raises(fn, exc):
    try:
        fn()
        return False
    except exc:
        return True


# ── 2. volum 3.7 + cheie → migrare ─────────────────────────────────────────────
def test_legacy_migrates():
    print("── volum 3.7 + WEBTERM_MASTER_KEY_FILE → migrare, FK_legacy dovedit")
    d, secret = legacy_volume("legacy-key", settings=(("smtp_password_enc", None),))
    security.init_crypto(secret)
    old_value = security.encrypt_secret("parola-smtp")
    fwd = security.make_forward_token("grafana", 1)
    kf, mk = key_file("mig")
    res = prepare({"WEBTERM_MASTER_KEY_FILE": kf})
    check("starea e protected, migrated", res.state.mode == "protected" and res.state.migrated, res.state)
    check("dovada FK_legacy: decriptat din DB", bootkeys.STATE["legacy_proof"] == "proven", bootkeys.STATE)
    check("secret şi migrating.wtm au dispărut, keys.wtk există",
          not (d / "secret").exists() and not (d / "migrating.wtm").exists() and (d / "keys.wtk").exists())
    check("FK_legacy == vechiul secret", res.keyring.fk_legacy == secret)
    check("MK-ul ţinut = cel din fişier", res.master_key == mk)
    check("o valoare scrisă de 3.7 se decriptează după migrare", security.decrypt_secret(old_value) == "parola-smtp")
    new = security.encrypt_secret("nou")
    check("o scriere nouă poartă prefixul FK şi NU se deschide cu FK_legacy",
          new.startswith(security.FK_PREFIX)
          and _raises(lambda: fernet(secret).decrypt(new[len(security.FK_PREFIX):].encode()), InvalidToken))
    check("…şi se deschide cu FK", security.decrypt_secret(new) == "nou"
          and fernet(res.keyring.fk).decrypt(new[len(security.FK_PREFIX):].encode()) == b"nou")
    check("tokenurile de forward emise înainte rămân valide (HMAC din FK_legacy)",
          security.verify_forward_token(fwd, "grafana"))
    check("backup: furnizorul de chei înregistrat + starea protejată", backup._host_keys_provider is not None
          and backup._boot_protected and backup.volume_kind() == "protected")
    r = run(syshealth.c_crypto_protection())
    check("System health: ok, sursa file", r.key == "crypto_protected" and r.params == {"source": "file"}, r)
    r = run(syshealth.c_crypto_legacy_copies())
    check("System health: 1 backup cu cheia brută (warning)", r.severity == "warning"
          and r.params == {"count": 1}, r)
    bootkeys.release()
    # repornire: deschide keys.wtk, nimic nou
    t = tree(d)
    res2 = prepare({"WEBTERM_MASTER_KEY_FILE": kf})
    check("repornirea deschide acelaşi keyring", res2.state.mode == "protected" and not res2.state.migrated
          and res2.keyring.installation_id == res.keyring.installation_id)
    check("…fără să scrie nimic", tree(d) == t)
    bootkeys.release()
    e = refusal({})
    check("după migrare, fără cheie → refuz (niciodată înapoi în legacy)", e is not None and e.reason in ("no-source", "missing"), e)


def test_legacy_proof_refusals():
    print("── dovada FK_legacy: secret străin / fără ciphertext / WAL / FK: amestecat")
    d, _ = legacy_volume("foreign")
    (d / "secret").write_bytes(os.urandom(32))          # un fişier de 32 B care NU e cheia DB-ului
    kf, _ = key_file("foreign")
    before = tree(d)
    e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("secret străin → refuz legacy-key-unproven, kind invalid-key",
          e is not None and e.reason == "legacy-key-unproven" and e.kind == keys.KIND_INVALID_KEY, e)
    check("…nimic scris în afară de .lock", without_lock(tree(d)) == before)
    check("…mesajul nu conţine material de cheie", (d / "secret").read_bytes().hex() not in str(e))
    e2 = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("…a doua încercare: acelaşi refuz, acelaşi arbore", e2 is not None and e2.reason == e.reason
          and without_lock(tree(d)) == before)

    d, _ = legacy_volume("no-cipher", encrypted=False)
    kf, _ = key_file("no-cipher")
    res = prepare({"WEBTERM_MASTER_KEY_FILE": kf})
    check("DB fără nicio valoare criptată → eligibil (no-ciphertext), migrat",
          res.state.migrated and bootkeys.STATE["legacy_proof"] == "no-ciphertext", bootkeys.STATE)
    bootkeys.release()

    d, _ = legacy_volume("wal", encrypted=False)
    (d / "webterm.db-wal").write_bytes(b"\0" * 64)
    kf, _ = key_file("wal")
    before = tree(d)
    e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("WAL nescris + fără ciphertext în fişier → refuz legacy-db-wal-pending",
          e is not None and e.reason == "legacy-db-wal-pending", e)
    check("…proba nu scrie nimic (nici -shm)", without_lock(tree(d)) == before, set(tree(d)) - set(before))

    d, secret = legacy_volume("mixed", settings=(("x", security.FK_PREFIX + "gA" + "A" * 80),))
    kf, _ = key_file("mixed")
    e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("o valoare FK: într-un DB legacy → refuz (set amestecat)",
          e is not None and e.reason == "legacy-db-has-protected-values", e)

    d, secret = legacy_volume("settings-only", encrypted=False, secret=os.urandom(32))
    con = sqlite3.connect(str(d / "webterm.db"))
    con.execute("INSERT INTO app_settings(key, value) VALUES('agent_ca', ?)",
                ('{"cert": "x", "key": "%s"}' % fernet((d / "secret").read_bytes()).encrypt(b"pem").decode(),))
    con.commit()
    con.close()
    kf, _ = key_file("settings-only")
    res = prepare({"WEBTERM_MASTER_KEY_FILE": kf})
    check("cheia CA-ului din app_settings (JSON) dovedeşte FK_legacy",
          res.state.migrated and bootkeys.STATE["legacy_proof"] == "proven", bootkeys.STATE)
    bootkeys.release()


# ── 3. volum protejat: cheie greşită / lipsă ───────────────────────────────────
def protected_volume(name):
    d = Path(ROOT) / name
    d.mkdir()
    use(d)
    kf, mk = key_file(name)
    res = prepare({"WEBTERM_MASTER_KEY_FILE": kf})
    make_db(config.DB_PATH, [security.encrypt_secret("t")])
    (d / "transcripts").mkdir(exist_ok=True)
    (d / "transcripts" / "s1.out").write_bytes(b"x" * 100)
    return d, kf, mk, res


def test_protected_wrong_key():
    print("── volum protejat + cheie greşită / lipsă → refuz, nimic schimbat")
    d, kf, mk, res = protected_volume("prot")
    check("bootstrap cu fişier extern → protected", res.state.mode == "protected" and res.state.source == "file")
    bootkeys.release()
    bad, _ = key_file("prot-bad")
    before = tree(d)
    e = refusal({"WEBTERM_MASTER_KEY_FILE": bad})
    check("cheie greşită → wrong-key (invalid-key)", e is not None and e.reason == "wrong-key"
          and e.kind == keys.KIND_INVALID_KEY, e)
    t1 = tree(d)
    e = refusal({"WEBTERM_MASTER_KEY_FILE": bad})
    check("…două refuzuri: identic (cu .lock), şi faţă de înainte (fără .lock)",
          tree(d) == t1 and without_lock(t1) == without_lock(before))
    e = refusal({})
    check("fără cheie → refuz", e is not None and e.reason in ("no-source", "missing"), e)
    e = refusal({"WEBTERM_MASTER_KEY_FILE": os.path.join(ROOT, "keys", "lipseste")})
    check("fişier de cheie configurat dar lipsă → refuz missing", e is not None and e.reason == "missing", e)
    check("…tot nimic schimbat", without_lock(tree(d)) == without_lock(before))


def test_protected_staged_restore():
    print("── restore 3.8 în staging: cheie greşită → refuz înainte de swap; cheia bună → aplicat")
    d, kf, mk, res = protected_volume("prot-restore")
    blob = backup.make_encrypted(PASS, include_transcripts=True)
    # starea live se schimbă după backup: restore-ul trebuie s-o readucă
    con = sqlite3.connect(str(config.DB_PATH))
    con.execute("INSERT INTO users(email, created) VALUES('dupa@backup', 2000)")
    con.commit()
    con.close()
    backup.stage_restore(blob, PASS)
    check("staging 3.8 prezent", (d / ".restore-flag").exists())
    bootkeys.release()
    bad, _ = key_file("prot-restore-bad")
    before = tree(d)
    e = refusal({"WEBTERM_MASTER_KEY_FILE": bad})
    check("cheie greşită → refuz wrong-key", e is not None and e.reason == "wrong-key", e)
    check("…înainte de orice swap: arborele (staging inclus) neschimbat", without_lock(tree(d)) == without_lock(before))
    res2 = prepare({"WEBTERM_MASTER_KEY_FILE": kf})
    check("cheia bună → restore aplicat la boot", bootkeys.STATE["restore_applied"], bootkeys.STATE)
    check("…staging-ul a dispărut", not (d / ".restore-flag").exists())
    con = sqlite3.connect(str(config.DB_PATH))
    n = con.execute("SELECT count(*) FROM users WHERE email='dupa@backup'").fetchone()[0]
    con.close()
    check("…DB-ul e cel din backup", n == 0)
    check("…keys.wtk redeschis, furnizorul ţine keyring-ul curent",
          backup._host_keys_provider().ring.epoch == res2.keyring.epoch and backup._host()[0].ring.installation_id
          == res2.keyring.installation_id)
    bootkeys.release()


def test_legacy_staged_restore_then_migrate():
    print("── restore 3.7 în staging pe volum 3.7 + cheie → întâi restore (cheia 3.7), apoi migrare")
    d, secret_a = legacy_volume("legacy-restore")
    secret_b = os.urandom(32)
    rp = d / "restore-pending"
    rp.mkdir()
    (rp / "secret").write_bytes(secret_b)
    make_db(rp / "webterm.db", [fernet(secret_b).encrypt(b"restored-token").decode()])
    (d / ".restore-flag").write_text("1700000000")
    kf, _ = key_file("legacy-restore")
    res = prepare({"WEBTERM_MASTER_KEY_FILE": kf})
    check("restore aplicat ÎNAINTEA migrării, migrarea a rulat", bootkeys.STATE["restore_applied"]
          and res.state.migrated, bootkeys.STATE)
    check("FK_legacy = cheia DIN backup (dovedită pe DB-ul restaurat)", res.keyring.fk_legacy == secret_b)
    con = sqlite3.connect(str(config.DB_PATH))
    v = con.execute("SELECT token_encrypted FROM hosts").fetchone()[0]
    con.close()
    check("valoarea restaurată se decriptează după migrare", security.decrypt_secret(v) == "restored-token")
    check("staging-ul 3.7 consumat", not rp.exists() and not (d / ".restore-flag").exists())
    bootkeys.release()

    # restore 3.7 cu un DB pe care cheia lui NU îl deschide → refuz după restore (operation-incomplete)
    d, _ = legacy_volume("legacy-restore-bad")
    rp = d / "restore-pending"
    rp.mkdir()
    (rp / "secret").write_bytes(os.urandom(32))
    make_db(rp / "webterm.db", [fernet(os.urandom(32)).encrypt(b"x").decode()])
    (d / ".restore-flag").write_text("1700000000")
    kf, _ = key_file("legacy-restore-bad")
    e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("restore 3.7 nedovedibil → refuz, kind operation-incomplete (restore-ul s-a aplicat)",
          e is not None and e.reason == "legacy-key-unproven" and e.kind == keys.KIND_INCOMPLETE, e)
    check("…volumul rămâne legacy (nicio cheie publicată)", (d / "secret").exists() and not (d / "keys.wtk").exists())


def test_exclusion():
    print("── un singur proces: al doilea boot şi comenzile admin care scriu sunt refuzate")
    d, _ = legacy_volume("excl")
    prepare({})
    # al doilea „proces”: alt fd pe acelaşi .lock (flock e per descriere de fişier deschis)
    try:
        keys.boot(str(d), {})
        second = None
    except keys.BootRefused as x:
        second = x
    check("al doilea boot pe acelaşi volum → locked", second is not None and second.reason == "locked", second)
    try:
        admin._writer_lock("passwd")
        refused_admin = False
    except SystemExit as x:
        refused_admin = x.code == 3
    check("admin passwd cu gateway-ul pornit → refuz (exit 3)", refused_admin)
    check("admin list/roles nu iau lock-ul", admin._writer_lock("list") is None and admin._writer_lock("roles") is None)
    check("toate comenzile care scriu sunt în WRITERS", {"passwd", "disable-2fa", "logout-all", "promote",
                                                         "sso-only", "enable", "vacuum"} == set(admin.WRITERS))
    bootkeys.release()
    lk = admin._writer_lock("promote")
    check("cu gateway-ul oprit, admin ia lock-ul", lk is not None)
    try:
        keys.boot(str(d), {})
        blocked = False
    except keys.BootRefused as x:
        blocked = x.reason == "locked"
    check("…iar gateway-ul nu porneşte cât rulează comanda", blocked)
    lk.release()


def test_empty_volume():
    print("── instalare nouă: fără cheie → refuz; WEBTERM_KEY_IN_VOLUME=1 → reduced")
    d = Path(ROOT) / "empty"
    use(d)
    e = refusal({})
    check("volum gol fără cheie → no-source", e is not None and e.reason == "no-source", e)
    check("…a creat DOAR DATA_DIR şi .lock", sorted(os.listdir(d)) == [".lock"], os.listdir(d))
    check("…mesajul spune ce e de făcut", "WEBTERM_KEY_IN_VOLUME=1" in bootkeys.describe_refusal(e))
    res = prepare({"WEBTERM_KEY_IN_VOLUME": "1"})
    check("WEBTERM_KEY_IN_VOLUME=1 → reduced, master.key în volum", res.state.mode == "reduced"
          and (d / "master.key").exists() and res.master_key is not None)
    check("System health: warning „protecţie redusă”", run(syshealth.c_crypto_protection()).key == "crypto_reduced")
    check("fără FK_legacy: o valoare nefixată → InvalidToken", _raises(
        lambda: security.decrypt_secret(fernet(os.urandom(32)).encrypt(b"x").decode()), InvalidToken))
    bootkeys.release()
    res = prepare({"WEBTERM_KEY_IN_VOLUME": "1"})
    check("repornire reduced: acelaşi keyring", res.state.mode == "reduced")
    bootkeys.release()


def test_lifespan_order():
    print("── main.lifespan: cheie greşită + staging + temporare → refuz ÎNAINTE de clean-up")
    from app import main
    d, kf, mk, res = protected_volume("lifespan")
    blob = backup.make_encrypted(PASS)
    backup.stage_restore(blob, PASS)
    bootkeys.release()
    tmp = d / "transcripts" / (".s1.out" + core.CAP_TMP_SUFFIX)
    tmp.write_bytes(b"temp de plafon")
    bad, _ = key_file("lifespan-bad")
    before = tree(d)
    os.environ["WEBTERM_MASTER_KEY_FILE"] = bad
    try:
        async def go():
            async with main.lifespan(main.app):
                pass
        try:
            run(go())
            refused_boot = False
        except RuntimeError:
            refused_boot = True
    finally:
        os.environ.pop("WEBTERM_MASTER_KEY_FILE", None)
        bootkeys.release()
    check("lifespan refuză cu cheia greşită", refused_boot)
    check("…temporarul de plafon NU a fost şters (clean-up-ul vine după chei)", tmp.exists())
    check("…staging-ul neatins, arborele identic (fără .lock)", without_lock(tree(d)) == without_lock(before))


def main_():
    test_legacy_no_key()
    test_legacy_migrates()
    test_legacy_proof_refusals()
    test_protected_wrong_key()
    test_protected_staged_restore()
    test_legacy_staged_restore_then_migrate()
    test_exclusion()
    test_empty_volume()
    test_lifespan_order()
    print(f"\n{ok}/{total} passed")
    raise SystemExit(0 if ok == total else 1)


if __name__ == "__main__":
    main_()
