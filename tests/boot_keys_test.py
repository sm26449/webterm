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
  * al doilea proces → refuz (`locked`); `admin vacuum` refuză cât ţine gateway-ul lock-ul, iar
    comenzile break-glass doar-DB (passwd, disable-2fa, promote, enable, logout-all) rulează, fără
    să atingă cheile;
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


LOCKS = (".lock", ".maint.lock")


def without_lock(t):
    # preflight-ul scrie doar cele două fişiere de lacăt (goale, niciodată scrise)
    return {k: v for k, v in t.items() if k not in LOCKS}


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
    check("arborele e identic octet cu octet în afară de .lock/.maint.lock", without_lock(after) == before,
          set(after.items()) ^ set(before.items()))
    check(".lock creat 0600, gol", ".lock" in after and after[".lock"][1] == 0o600 and after[".lock"][2] == 0)
    check(".maint.lock creat 0644, gol (deschis read-only şi de root, M3)", ".maint.lock" in after
          and after[".maint.lock"][1] == 0o644 and after[".maint.lock"][2] == 0, after.get(".maint.lock"))
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
    check("M2: restore 3.7 al cărui secret nu-i deschide DB-ul → refuz ÎNAINTE de restore (invalid-key)",
          e is not None and e.reason == "staged-restore-invalid" and e.kind == keys.KIND_INVALID_KEY, e)
    check("…volumul rămâne legacy (nicio cheie publicată), staging-ul neaplicat",
          (d / "secret").exists() and not (d / "keys.wtk").exists() and (d / ".restore-flag").exists())


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
        admin._writer_lock("vacuum")
        refused_admin = False
    except SystemExit as x:
        refused_admin = x.code == 3
    check("admin vacuum cu gateway-ul pornit → refuz (exit 3)", refused_admin)
    check("admin list/roles şi comenzile doar-DB nu iau lock-ul",
          all(admin._writer_lock(c) is None for c in ("list", "roles", *admin.DB_ONLY)))
    check("doar vacuum cere lock-ul; break-glass-ul doar-DB e complet",
          set(admin.NEEDS_LOCK) == {"vacuum"}
          and set(admin.DB_ONLY) == {"passwd", "disable-2fa", "logout-all", "promote", "sso-only", "enable"})
    bootkeys.release()
    lk = admin._writer_lock("vacuum")
    check("cu gateway-ul oprit, vacuum ia lock-ul", lk is not None)
    try:
        keys.boot(str(d), {})
        blocked = False
    except keys.BootRefused as x:
        blocked = x.reason == "locked"
    check("…iar gateway-ul nu porneşte cât rulează vacuum", blocked)
    lk.release()


def test_admin_db_only_while_running():
    """Decizia lui Stefan (2026-11-24): comenzile break-glass doar-DB rulează ca în 3.7, cu
    gateway-ul pornit (alt proces ţine lock-ul), pe un volum PROTEJAT, fără să atingă cheile."""
    print("── admin passwd/disable-2fa/promote/enable/logout-all/sso-only cu gateway-ul pornit, volum protejat")
    from app import db
    d = Path(ROOT) / "admin-live"
    d.mkdir()
    use(d)
    kf, _mk = key_file("admin-live")
    prepare({"WEBTERM_MASTER_KEY_FILE": kf})          # „gateway-ul”: ţine lock-ul pe tot testul

    async def seed():
        await db.connect()
        await db.execute("INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
                         "ana@x.co", security.hash_password("vechea-parola-lunga"), 1000.0)
        await db.execute("INSERT INTO users(email, password_hash, created, sso_subject) VALUES(?,?,?,?)",
                         "bob@x.co", security.hash_password("alta-parola-lunga"), 1001.0, "sub-bob")
        await db.close()
    run(seed())
    keys_before = (d / "keys.wtk").read_bytes()
    # nicio comandă doar-DB nu are voie să atingă seiful: dacă ar cripta/decripta ceva, ar avea
    # nevoie de keyring — testul ar prinde-o aici
    saved = security.encrypt_secret, security.decrypt_secret

    def boom(*_a, **_k):
        raise AssertionError("an admin DB-only command touched the vault")
    security.encrypt_secret = security.decrypt_secret = boom
    orig_pw, orig_argv = admin._read_new_password, sys.argv
    admin._read_new_password = lambda: "parola-noua-lunga-1"
    results = {}
    try:
        for cmd, *rest in (("passwd", "ana@x.co"), ("disable-2fa", "ana@x.co"), ("promote", "ana@x.co"),
                           ("enable", "ana@x.co"), ("logout-all", "ana@x.co"),
                           ("sso-only", "bob@x.co", "--force")):
            sys.argv = ["app.admin", cmd, *rest]
            try:
                run(admin.main())
                results[cmd] = 0
            except SystemExit as x:
                results[cmd] = x.code
            except AssertionError as x:
                results[cmd] = str(x)
    finally:
        security.encrypt_secret, security.decrypt_secret = saved
        admin._read_new_password, sys.argv = orig_pw, orig_argv
    check("toate rulează cât gateway-ul ţine lock-ul, fără să atingă seiful",
          all(v == 0 for v in results.values()), results)

    async def row():
        await db.connect()
        try:
            u = await db.fetchone("SELECT password_hash FROM users WHERE email='ana@x.co'")
            own = await db.fetchone("SELECT COUNT(*) FROM role_bindings b JOIN roles r ON r.id=b.role_id"
                                    " WHERE r.key='owner' AND b.scope_kind='all'")
            return u["password_hash"], own[0]
        finally:
            await db.close()
    h, owners_n = run(row())
    check("…parola schimbată şi contul e Owner", security.verify_password("parola-noua-lunga-1", h)
          and owners_n >= 1, owners_n)
    check("…keys.wtk neatins, nimic publicat", (d / "keys.wtk").read_bytes() == keys_before
          and not (d / "keys.wtk.tmp").exists())
    sys.argv = ["app.admin", "vacuum"]
    try:
        run(admin.main())
        vac = None
    except SystemExit as x:
        vac = x.code
    finally:
        sys.argv = orig_argv
    check("…vacuum, în schimb, refuză (exit 3)", vac == 3, vac)
    bootkeys.release()


def test_empty_volume():
    print("── instalare nouă: fără cheie → refuz; WEBTERM_KEY_IN_VOLUME=1 → reduced")
    d = Path(ROOT) / "empty"
    use(d)
    e = refusal({})
    check("volum gol fără cheie → no-source", e is not None and e.reason == "no-source", e)
    check("…a creat DOAR DATA_DIR, .lock şi .maint.lock", sorted(os.listdir(d)) == [".lock", ".maint.lock"],
          os.listdir(d))
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


# ── H4: inventar complet, separat de bugetul de decriptare ─────────────────────
def _fill(d, rows=(), settings=()):
    con = sqlite3.connect(str(d / "webterm.db"))
    for v in rows:
        con.execute("INSERT INTO hosts(token_encrypted) VALUES(?)", (v,))
    for k, v in settings:
        con.execute("INSERT INTO app_settings(key, value) VALUES(?, ?)", (k, v))
    con.commit()
    con.close()


def test_h4_inventory():
    print("── H4: placeholdere înaintea ciphertext-ului, FK: după plafon, WAL amestecat, neclasificabil")
    # 40 de placeholdere (peste vechiul plafon de 32/coloană), apoi un token al ALTEI chei
    d, _ = legacy_volume("h4-placeholders", encrypted=False)
    _fill(d, ["pending-%d" % i for i in range(40)] + [fernet(os.urandom(32)).encrypt(b"x").decode()])
    kf, _ = key_file("h4-placeholders")
    before = tree(d)
    e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("placeholdere apoi ciphertext străin după vechiul plafon/coloană → legacy-key-unproven "
          "(nu „no-ciphertext”)", e is not None and e.reason == "legacy-key-unproven", e)
    check("…nimic scris", without_lock(tree(d)) == before)

    d, secret = legacy_volume("h4-placeholders-ok", encrypted=False)
    _fill(d, ["pending-%d" % i for i in range(40)] + [fernet(secret).encrypt(b"x").decode()])
    kf, _ = key_file("h4-placeholders-ok")
    res = prepare({"WEBTERM_MASTER_KEY_FILE": kf})
    check("…acelaşi lucru cu tokenul cheii bune → proven", res.state.migrated
          and bootkeys.STATE["legacy_proof"] == "proven", bootkeys.STATE)
    bootkeys.release()

    # 300 de tokenuri valide (peste vechiul plafon global de 256), apoi un FK:
    d, secret = legacy_volume("h4-fk-late")
    f = fernet(secret)
    _fill(d, [f.encrypt(b"t%d" % i).decode() for i in range(300)] + [security.FK_PREFIX + f.encrypt(b"z").decode()])
    kf, _ = key_file("h4-fk-late")
    e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("FK: după 300 de valori (peste vechiul plafon 256) → legacy-db-has-protected-values",
          e is not None and e.reason == "legacy-db-has-protected-values" and e.subject == "hosts.token_encrypted", e)

    # FK: într-un JSON imbricat din app_settings, după 5000 de rânduri de setări
    d, secret = legacy_volume("h4-fk-json")
    _fill(d, settings=[("k%05d" % i, "v") for i in range(5001)]
          + [("zz_cloud", '{"a": {"b": ["%s"]}}' % (security.FK_PREFIX + fernet(secret).encrypt(b"c").decode()))])
    kf, _ = key_file("h4-fk-json")
    e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("FK: într-un JSON imbricat, după 5000 de setări → refuz", e is not None
          and e.reason == "legacy-db-has-protected-values", e)

    # WAL amestecat: fişierul checkpointat are un token valid, WAL-ul o valoare FK:
    d, secret = legacy_volume("h4-wal", encrypted=False)
    src = Path(ROOT) / "h4-wal-src"
    src.mkdir()
    con = sqlite3.connect(str(src / "webterm.db"))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE hosts(id INTEGER PRIMARY KEY, token_encrypted TEXT)")
    con.execute("INSERT INTO hosts(token_encrypted) VALUES(?)", (fernet(secret).encrypt(b"old").decode(),))
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("INSERT INTO hosts(token_encrypted) VALUES(?)",
                (security.FK_PREFIX + fernet(os.urandom(32)).encrypt(b"new").decode(),))
    con.commit()
    for n in ("webterm.db", "webterm.db-wal"):
        (d / n).write_bytes((src / n).read_bytes())
    con.close()
    check("(fixture: WAL nevid, token valid în fişier)", (d / "webterm.db-wal").stat().st_size > 0)
    kf, _ = key_file("h4-wal")
    before = tree(d)
    e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("WAL nevid, chiar cu un token valid în fişier → legacy-db-wal-pending (nu „proven”)",
          e is not None and e.reason == "legacy-db-wal-pending", e)
    check("…nimic scris (nici -shm)", without_lock(tree(d)) == before)
    check("…mesajul spune să opreşti curat gateway-ul 3.7", "stop the 3.7 gateway cleanly" in
          bootkeys.describe_refusal(e))

    # valoare neclasificabilă: un BLOB într-o coloană *_encrypted / un FKL: fără token
    for name, v in (("h4-blob", b"\x80binary"), ("h4-fkl", security.FK_LEGACY_PREFIX + "nu-e-token"),
                    ("h4-trunc", "gAAAAAB-trunchiat")):
        d, _ = legacy_volume(name)
        _fill(d, [v])
        kf, _ = key_file(name)
        e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
        check("%s → legacy-db-unclassifiable (refuz explicit)" % name, e is not None
              and e.reason == "legacy-db-unclassifiable" and e.subject == "hosts.token_encrypted", e)

    # inventar peste plafon → refuz explicit, nu „no-ciphertext”
    d, secret = legacy_volume("h4-cap")
    _fill(d, [fernet(secret).encrypt(b"t").decode() for _ in range(6)])
    kf, _ = key_file("h4-cap")
    saved = bootkeys._MAX_VAULT_VALUES
    bootkeys._MAX_VAULT_VALUES = 5
    try:
        e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    finally:
        bootkeys._MAX_VAULT_VALUES = saved
    check("inventar peste plafon → legacy-db-inventory-too-large", e is not None
          and e.reason == "legacy-db-inventory-too-large", e)

    # bugetul de decriptare ia întâi primele valori ale FIECĂREI surse
    d, secret = legacy_volume("h4-budget", encrypted=False)
    other = fernet(os.urandom(32))
    _fill(d, [other.encrypt(b"x").decode() for _ in range(300)],
          settings=[("smtp", fernet(secret).encrypt(b"p").decode())])
    kf, _ = key_file("h4-budget")
    res = prepare({"WEBTERM_MASTER_KEY_FILE": kf})
    check("300 de valori ale altei chei + una bună în app_settings → proven (bugetul atinge fiecare sursă)",
          res.state.migrated and bootkeys.STATE["legacy_proof"] == "proven", bootkeys.STATE)
    bootkeys.release()


# ── M1: layout-uri 3.7 suportate ───────────────────────────────────────────────
def test_m1_layouts():
    print("── M1: transcripts/ symlink (3.7) → legacy cu avertisment; migrarea şi seturile amestecate refuzate")
    d, _ = legacy_volume("m1-link")
    ext = Path(ROOT) / "m1-link-ext"
    (d / "transcripts").rename(ext)
    (d / "transcripts").symlink_to(ext)
    before = tree(d)
    res = prepare({})
    check("transcripts/ symlink, fără cheie → legacy", res.state.mode == "legacy", res.state)
    check("…cu avertismentul transcripts-symlink", "transcripts-symlink" in bootkeys.STATE["warnings"],
          bootkeys.STATE)
    check("…nimic schimbat în afară de lacăte", without_lock(tree(d)) == before)
    bootkeys.release()
    kf, _ = key_file("m1-link")
    e = refusal({"WEBTERM_MASTER_KEY_FILE": kf})
    check("…cu cheie → refuz transcripts-symlink (o migrare ar lăsa un volum fără backup)",
          e is not None and e.reason == "transcripts-symlink" and e.kind == keys.KIND_INVALID_KEY, e)
    check("…nimic schimbat", without_lock(tree(d)) == before)

    (ext / "seg.wtx").write_bytes(b"x")
    e = refusal({})
    check("ţinta symlink-ului cu o înregistrare 3.8 → ambiguous (set amestecat)",
          e is not None and e.reason == "ambiguous" and "seg.wtx" in e.subject, e)
    (ext / "seg.wtx").unlink()
    (ext / "arhiva" / "old.wtd").write_bytes(b"x")
    e = refusal({})
    check("…şi un nivel mai jos (arhiva/) → ambiguous", e is not None and e.reason == "ambiguous", e)
    (ext / "arhiva" / "old.wtd").unlink()
    (d / "master.key").write_bytes(b"x" * 45)
    e = refusal({})
    check("symlink + master.key (urmă a formatului nou) → refuz", e is not None and e.reason == "ambiguous", e)
    (d / "master.key").unlink()

    d, _ = legacy_volume("m1-nosecret")
    (d / "secret").unlink()
    e = refusal({})
    check("DB fără secret → refuz (ambiguous)", e is not None and e.reason == "ambiguous", e)
    d, _ = legacy_volume("m1-marker")
    (d / "erasures.wtj").write_bytes(b"x")
    e = refusal({})
    check("marker rezervat la rădăcină → refuz", e is not None and e.reason == "ambiguous"
          and "erasures.wtj" in e.subject, e)


# ── M2: lock-ul după o mutaţie; staging incomplet ──────────────────────────────
def _lock_free(d):
    try:
        keys.acquire_lock(str(d)).release()
        return True
    except keys.BootRefused as x:
        return x.reason != "locked"


def test_m2_lock_after_mutation():
    print("── M2: după o mutaţie lock-ul rămâne al procesului; staging 3.7 incomplet refuzat înainte")
    d, secret = legacy_volume("m2-incomplete")
    (d / ".restore-flag").write_text("1700000000")
    (d / "restore-pending").mkdir()
    make_db(d / "restore-pending" / "webterm.db", [fernet(secret).encrypt(b"x").decode()])
    kf, _ = key_file("m2-incomplete")
    before = tree(d)
    bootkeys.release()
    try:
        bootkeys.prepare(env={"WEBTERM_MASTER_KEY_FILE": kf})
        e = None
    except keys.BootRefused as x:
        e = x
    check("staging 3.7 fără secret + cheie → refuz staged-restore-incomplete, invalid-key",
          e is not None and e.reason == "staged-restore-incomplete" and e.kind == keys.KIND_INVALID_KEY, e)
    check("…nimic schimbat, lock eliberat (nicio mutaţie)", without_lock(tree(d)) == before and _lock_free(d))
    bootkeys.release()

    # un restore 3.7 care începe să scrie şi cade cu OSError brut
    d, secret = legacy_volume("m2-oserror")
    (d / ".restore-flag").write_text("1700000000")
    (d / "restore-pending").mkdir()
    (d / "restore-pending" / "secret").write_bytes(secret)
    make_db(d / "restore-pending" / "webterm.db", [fernet(secret).encrypt(b"x").decode()])
    kf, _ = key_file("m2-oserror")
    orig = backup.apply_pending_restore

    def half_apply(*_a, **_k):
        (d / "webterm.db").write_bytes(b"jumatate")
        raise OSError(5, "disk error")
    backup.apply_pending_restore = half_apply
    try:
        try:
            bootkeys.prepare(env={"WEBTERM_MASTER_KEY_FILE": kf})
            e = None
        except keys.BootRefused as x:
            e = x
    finally:
        backup.apply_pending_restore = orig
    check("OSError brut după ce restore-ul a început → io-error, kind operation-incomplete (nu preflight-io)",
          e is not None and e.reason == "io-error" and e.kind == keys.KIND_INCOMPLETE, e)
    check("…lock-ul rămâne al procesului (alt boot → locked)", not _lock_free(d))
    check("…şi .maint.lock (admin doar-DB refuză)", _maint_busy(d))
    bootkeys.release()
    check("…eliberat doar la „ieşirea procesului”", _lock_free(d))

    # o publicare a migrării care cade cu o excepţie oarecare → lock reţinut
    d, _ = legacy_volume("m2-publish")
    kf, _ = key_file("m2-publish")

    def boom(step):
        if step == "keys.wtk:tmp-written":
            raise RuntimeError("crash simulat")
    try:
        keys.boot(str(d), {"WEBTERM_MASTER_KEY_FILE": kf}, _crash_at=boom)
        e = None
    except RuntimeError as x:
        e = x
    check("migrare întreruptă după prima scriere → lock reţinut", e is not None and not _lock_free(d), e)
    keys.release_retained()
    check("…release_retained (teste) îl eliberează", _lock_free(d))
    # un refuz preflight (cheie lipsă) eliberează în continuare lock-ul
    e = refusal({"WEBTERM_MASTER_KEY_FILE": os.path.join(ROOT, "keys", "lipseste-m2")})
    check("refuz preflight → lock eliberat", e is not None and _lock_free(d), e)


# ── M3: admin doar-DB: conexiune de mentenanţă + .maint.lock ───────────────────
def _maint_busy(d):
    dfd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.close(keys.acquire_maint_lock(dfd, False, 0))
        return False
    except keys.BootRefused as x:
        return x.reason == "maintenance-busy"
    finally:
        os.close(dfd)


def _admin(*argv):
    orig = sys.argv
    sys.argv = ["app.admin", *argv]
    try:
        run(admin.main())
        return 0
    except SystemExit as x:
        return x.code
    finally:
        sys.argv = orig


def _schema(path):
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        return (con.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name").fetchall(),
                con.execute("PRAGMA journal_mode").fetchone()[0])
    finally:
        con.close()


def test_m3_admin_maintenance():
    print("── M3: admin doar-DB: fără schemă/migrări, refuz în fazele exclusive ale boot-ului")
    from app import db
    d = Path(ROOT) / "m3"
    d.mkdir()
    use(d)
    kf, _ = key_file("m3")
    e_missing = _admin("enable", "nimeni@x.co")
    check("DB lipsă → refuz (exit 3), DB-ul NU se creează", e_missing == 3 and not (d / "webterm.db").exists(),
          e_missing)
    bootkeys.release()
    bootkeys.prepare(env={"WEBTERM_MASTER_KEY_FILE": kf}, hold_maintenance=True)
    check("boot în faza exclusivă: .maint.lock ţinut", _maint_busy(d))

    async def seed():
        await db.connect()
        await db.execute("INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
                         "ana@x.co", security.hash_password("vechea-parola-lunga"), 1000.0)
        await db.close()
    run(seed())
    check("admin enable în timpul fazei exclusive → refuz neblocant (exit 3)", _admin("enable", "ana@x.co") == 3)
    bootkeys.end_maintenance()
    before = _schema(d / "webterm.db")
    check("după faza exclusivă (gateway pornit normal) → rulează", _admin("enable", "ana@x.co") == 0)
    check("…list rulează şi ea", _admin("list") == 0)
    check("…nicio schimbare de schemă sau de journal_mode", _schema(d / "webterm.db") == before)
    con = sqlite3.connect(str(d / "webterm.db"))
    con.execute("ALTER TABLE users ADD COLUMN viitor TEXT")
    con.commit()
    con.close()
    check("schemă diferită de a codului → refuz (exit 3)", _admin("enable", "ana@x.co") == 3)
    check("…boot-ul aşteaptă / refuză cât ţine o comandă admin lacătul partajat", _boot_waits(d, kf))
    bootkeys.release()


def _boot_waits(d, kf):
    dfd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY)
    held = keys.acquire_maint_lock(dfd, False, 0)
    os.close(dfd)
    bootkeys.release()
    try:
        keys.boot(str(d), {"WEBTERM_MASTER_KEY_FILE": kf}, maint_wait=0.2)
        return False
    except keys.BootRefused as x:
        return x.reason == "maintenance-busy" and _lock_free(d)
    finally:
        os.close(held)


def main_():
    test_legacy_no_key()
    test_legacy_migrates()
    test_legacy_proof_refusals()
    test_protected_wrong_key()
    test_protected_staged_restore()
    test_legacy_staged_restore_then_migrate()
    test_exclusion()
    test_admin_db_only_while_running()
    test_empty_volume()
    test_lifespan_order()
    test_h4_inventory()
    test_m1_layouts()
    test_m2_lock_after_mutation()
    test_m3_admin_maintenance()
    print(f"\n{ok}/{total} passed")
    raise SystemExit(0 if ok == total else 1)


if __name__ == "__main__":
    main_()
