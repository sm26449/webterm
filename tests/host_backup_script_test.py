"""scripts/backup.sh + scripts/restore.sh pe volume 3.7 şi 3.8 (criptare la repaus, INV-14).

Hermetic: un `docker` FALS pe PATH rulează codul Python al scripturilor cu python-ul local, cu
căile containerului (/data, /out, /in, /kout, /kin) mapate pe directoare temporare prin WT_*;
„imaginea app-ului" (verificarea cheii master) rulează cu gateway/ pe PYTHONPATH, deci cu
exact codul de chei din repo. Nu atinge niciun volum, container sau Docker real.

Scenarii:
  * backup legacy: arhiva are `secret`, nu `.lock`;
  * backup protejat: keys.wtk, fără `secret`, fără cheia master, fără `.lock`; mesajul spune că
    cheia master NU e în arhivă; refuz cu migrating.wtm / secret lângă keys.wtk / temporare;
    volum „reduced": master.key nu intră în arhivă;
  * backup legacy cu urme ale formatului nou (master.key fără keys.wtk) → refuz;
  * restore protejat cu cheia bună → aplicat, `.lock` neatins, starea veche în .restore-prev;
  * restore protejat cu cheie greşită / fără cheie → refuz ÎNAINTE de oprirea app-ului, volum identic;
  * arhivă cu secret + keys.wtk (fără marker) sau cu master.key → refuz înainte de oprire;
  * restore legacy (3.7) → ca înainte, `.lock` neatins;
  * restore „reduced" pe acelaşi volum → master.key rămâne;
  * --verify: cheia bună → OK; greşită → FAILED; fără container app → OK, „NOT checked";
  * arhivă criptată (.enc) round-trip, dacă openssl există."""
import base64
import hashlib
import io
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
GATEWAY = os.path.join(REPO, "gateway")
sys.path.insert(0, GATEWAY)
for _v in ("WEBTERM_MASTER_KEY_FILE", "WEBTERM_MASTER_KEY", "WEBTERM_KEY_IN_VOLUME"):
    os.environ.pop(_v, None)

from app import keys  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {str(detail)[-700:]}"))


FAKE_DOCKER = r'''#!%(py)s
import os, sys
F = os.environ["FAKE_DIR"]
a = sys.argv[1:]
with open(os.path.join(F, "calls"), "a") as f:
    f.write(" ".join(a) + "\n")


def rd(n, default=""):
    p = os.path.join(F, n)
    return open(p).read() if os.path.exists(p) else default


if a[:1] == ["compose"]:
    if "ps" in a:
        sys.stdout.write(rd("app_cid"))
    sys.exit(0)
if a[:1] in (["image"], ["pull"]):
    sys.exit(0)
if a[:2] == ["volume", "inspect"]:
    sys.exit(0 if os.path.isdir(os.path.join(F, "vol", a[2])) else 1)
if a[:1] == ["ps"]:
    sys.exit(0)
if a[:1] == ["inspect"]:
    fmt = a[a.index("--format") + 1]
    if "Config.Image" in fmt:
        print("fake-app-image")
    elif "Config.Env" in fmt:
        sys.stdout.write(rd("app_env"))
    sys.exit(0)
if a[:1] != ["run"]:
    print("fake docker: unexpected %%s" %% a, file=sys.stderr)
    sys.exit(9)
VAL = {"-v", "-e", "--entrypoint", "--env-file", "--volumes-from", "--user", "-u", "--network", "-w"}
env = {k: v for k, v in os.environ.items() if not k.startswith("WT_")}
MAP = {"/data": "WT_DATA", "/out": "WT_OUT", "/in": "WT_IN", "/kout": "WT_KOUT", "/kin": "WT_KIN"}
entry, i = None, 1
while i < len(a):
    o = a[i]
    if o in VAL:
        v = a[i + 1]
        i += 2
        if o == "-v":
            src, dst = v.split(":")[:2]
            if not src.startswith("/"):
                src = os.path.join(F, "vol", src)
            if dst in MAP:
                env[MAP[dst]] = src
        elif o == "-e":
            k, _, val = v.partition("=")
            env[k] = val if "=" in v else os.environ.get(k, "")
        elif o == "--env-file":
            for line in open(v).read().splitlines():
                if "=" in line:
                    k, _, val = line.partition("=")
                    env[k] = val
        elif o == "--volumes-from":
            env["WT_DATA"] = os.path.join(F, "vol", rd("app_vol").strip())
        elif o == "--entrypoint":
            entry = v
        continue
    if o.startswith("-"):
        i += 1
        continue
    break
image, rest = a[i], a[i + 1:]
if entry != "python3":
    sys.exit(0)                      # `sh -c du …` din restore.sh
if image == "fake-app-image":
    env["PYTHONPATH"] = os.environ["FAKE_GATEWAY"]
os.execve(sys.executable, [sys.executable] + rest, env)
'''


class Env:
    def __init__(self):
        self.base = tempfile.mkdtemp(prefix="wt-hostbk-")
        self.fake = os.path.join(self.base, "fake")
        os.makedirs(os.path.join(self.fake, "bin"))
        os.makedirs(os.path.join(self.fake, "vol"))
        d = os.path.join(self.fake, "bin", "docker")
        with open(d, "w") as f:
            f.write(FAKE_DOCKER % {"py": sys.executable})
        os.chmod(d, 0o755)
        # copii ale scripturilor, FĂRĂ host-health.sh lângă ele (nu scriem statusuri nicăieri)
        self.scripts = os.path.join(self.base, "scripts")
        os.makedirs(self.scripts)
        for s in ("backup.sh", "restore.sh"):
            shutil.copy(os.path.join(REPO, "scripts", s), self.scripts)
        self.out = os.path.join(self.base, "out")
        self.inst = os.path.join(self.base, "inst")
        os.makedirs(self.inst)
        open(os.path.join(self.inst, "docker-compose.prod.yml"), "w").write("services: {}\n")
        self.keys = os.path.join(self.base, "keys")
        os.makedirs(self.keys)

    def vol(self, name):
        return os.path.join(self.fake, "vol", name)

    def key_file(self, name):
        p = os.path.join(self.keys, name)
        with open(p, "wb") as f:
            f.write(base64.b64encode(os.urandom(32)) + b"\n")
        os.chmod(p, 0o400)
        return p

    def app(self, vol, env_lines=(), cid="cid-app"):
        for n, v in (("app_vol", vol), ("app_env", "".join(x + "\n" for x in env_lines)), ("app_cid", cid)):
            p = os.path.join(self.fake, n)
            if v is None:
                if os.path.exists(p):
                    os.unlink(p)
            else:
                open(p, "w").write(v)

    def calls(self):
        p = os.path.join(self.fake, "calls")
        return open(p).read() if os.path.exists(p) else ""

    def reset_calls(self):
        p = os.path.join(self.fake, "calls")
        if os.path.exists(p):
            os.unlink(p)

    def run(self, script, *args, extra=None, stdin=""):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("WEBTERM_", "WT_"))}
        env.update({"PATH": os.path.join(self.fake, "bin") + ":" + os.environ["PATH"],
                    "FAKE_DIR": self.fake, "FAKE_GATEWAY": GATEWAY,
                    "WEBTERM_BACKUP_DIR": self.out, "WEBTERM_UID": "%d:%d" % (os.getuid(), os.getgid())})
        env.update(extra or {})
        p = subprocess.run(["bash", os.path.join(self.scripts, script), *args], cwd=self.inst, env=env,
                           input=stdin, capture_output=True, text=True, timeout=120)
        return p.returncode, p.stdout + p.stderr


def make_db(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT)")
    con.execute("INSERT INTO users(email) VALUES('a@b.c')")
    con.commit()
    con.close()


def common_files(d):
    make_db(os.path.join(d, "webterm.db"))
    open(os.path.join(d, "agent-signing.key"), "w").write("signing")
    open(os.path.join(d, "agent-signing.pub"), "w").write("pub")
    os.makedirs(os.path.join(d, "transcripts"), exist_ok=True)
    open(os.path.join(d, "transcripts", "s1.out"), "w").write("x" * 10)


def legacy_volume(e, name):
    d = e.vol(name)
    os.makedirs(d)
    common_files(d)
    with open(os.path.join(d, "secret"), "wb") as f:
        f.write(os.urandom(32))
    open(os.path.join(d, ".lock"), "w").write("")
    return d


def protected_volume(e, name, key=None, in_volume=False):
    d = e.vol(name)
    os.makedirs(d)
    env = {"WEBTERM_KEY_IN_VOLUME": "1"} if in_volume else {"WEBTERM_MASTER_KEY_FILE": key}
    res = keys.boot(d, env)
    res.lock.release()
    common_files(d)
    return d


def tree(d):
    out = {}
    for base, dirs, files in os.walk(d):
        for n in dirs + files:
            p = os.path.join(base, n)
            st = os.lstat(p)
            h = hashlib.sha256(open(p, "rb").read()).hexdigest() if stat.S_ISREG(st.st_mode) else ""
            out[os.path.relpath(p, d)] = (stat.S_IFMT(st.st_mode), h, st.st_ino)
    return out


def names(archive):
    with tarfile.open(archive) as t:
        return {m.name.split("/", 1)[0] for m in t.getmembers()}


def newest(e):
    arcs = sorted((os.path.join(e.out, n) for n in os.listdir(e.out)), key=os.path.getmtime)
    return arcs[-1]


def backup(e, vol, extra=None):
    if os.path.isdir(e.out):
        shutil.rmtree(e.out)
    x = {"WEBTERM_VOLUME": vol, "WEBTERM_BACKUP_ALLOW_PLAINTEXT": "1"}
    x.update(extra or {})
    return e.run("backup.sh", extra=x)


def craft(path, members):
    """O arhivă tar.gz făcută de mână: {nume: octeţi}."""
    with tarfile.open(path, "w:gz") as t:
        for n, data in members.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return path


def test_backup(e):
    print("── backup.sh: volum legacy, protejat, reduced, inconsistent")
    legacy_volume(e, "leg")
    rc, out = backup(e, "leg")
    arc = newest(e) if rc == 0 else ""
    check("legacy: arhiva are secret + DB + cheia de semnare, nu .lock",
          rc == 0 and {"webterm.db", "secret", "agent-signing.key", "transcripts"} <= names(arc)
          and ".lock" not in names(arc), out)
    check("…avertismentul spune că arhiva ţine cheia seifului", "vault key (data/secret)" in out, out)

    kf = e.key_file("prot.key")
    d = protected_volume(e, "prot", kf)
    rc, out = backup(e, "prot")
    arc = newest(e) if rc == 0 else ""
    n = names(arc) if arc else set()
    check("protejat: arhiva are keys.wtk + DB + cheia de semnare, fără secret / cheie master / .lock",
          rc == 0 and {"webterm.db", "keys.wtk", "agent-signing.key", "transcripts"} <= n
          and not n & {"secret", "master.key", ".lock"}, (out, n))
    check("…spune că cheia master NU e în arhivă şi unde stă", "master key is NOT in this archive" in out
          and "secrets/master-key/master.key" in out, out)
    check("…şi nu pretinde că arhiva ţine cheia seifului", "vault key" not in out, out)

    for extra_name, why in (("migrating.wtm", "migrare neterminată"), ("secret", "secret lângă keys.wtk"),
                            ("keys.wtk.tmp", "temporar de publicare")):
        p = os.path.join(d, extra_name)
        open(p, "wb").write(b"x" * 32)
        rc, out = backup(e, "prot")
        check("protejat + %s (%s) → refuz, nicio arhivă" % (extra_name, why),
              rc != 0 and "REFUSING" in out and not os.listdir(e.out), out)
        os.unlink(p)

    d = protected_volume(e, "red", in_volume=True)
    rc, out = backup(e, "red")
    arc = newest(e) if rc == 0 else ""
    check("reduced: master.key NU intră în arhivă, mesajul o spune",
          rc == 0 and "keys.wtk" in names(arc) and "master.key" not in names(arc)
          and "WEBTERM_KEY_IN_VOLUME=1" in out, out)

    d = legacy_volume(e, "legstray")
    open(os.path.join(d, "master.key"), "w").write("k")
    rc, out = backup(e, "legstray")
    check("legacy cu master.key fără keys.wtk → refuz (volum inconsistent)",
          rc != 0 and "without keys.wtk" in out and not os.listdir(e.out), out)
    shutil.rmtree(e.out)


def restore(e, archive, vol, extra=None, yes=True):
    x = {"WEBTERM_VOLUME": vol}
    x.update(extra or {})
    e.reset_calls()
    return e.run("restore.sh", archive, extra=x, stdin="y\n" if yes else "n\n")


def test_restore(e):
    print("── restore.sh: arhive protejate şi legacy")
    kf = e.key_file("src.key")
    protected_volume(e, "rsrc", kf)
    rc, out = backup(e, "rsrc")
    arc = os.path.join(e.base, "prot.tar.gz")
    shutil.copy(newest(e), arc)
    src_keys = open(os.path.join(e.vol("rsrc"), "keys.wtk"), "rb").read()

    tgt = legacy_volume(e, "rtgt")
    lock_ino = os.lstat(os.path.join(tgt, ".lock")).st_ino
    before = tree(tgt)

    # cheie greşită: refuz înainte de oprire
    wrong = e.key_file("wrong.key")
    e.app("rtgt", ["WEBTERM_MASTER_KEY_FILE=" + wrong])
    rc, out = restore(e, arc, "rtgt")
    check("protejat + cheie greşită → refuz, cu id-urile cheilor", rc != 0 and "does not open" in out
          and "needs the key with id" in out, out)
    check("…app-ul NU a fost oprit, volumul identic", "stop app" not in e.calls() and tree(tgt) == before,
          e.calls())

    e.app("rtgt", [])
    rc, out = restore(e, arc, "rtgt")
    check("protejat + nicio cheie configurată → refuz, nimic oprit",
          rc != 0 and "REFUSING" in out and "stop app" not in e.calls() and tree(tgt) == before, out)

    e.app("rtgt", ["WEBTERM_MASTER_KEY_FILE=" + kf])
    rc, out = restore(e, arc, "rtgt", yes=False)
    check("cheia bună dar „n” la confirmare → abandon, nimic oprit",
          rc != 0 and "aborted" in out and "stop app" not in e.calls() and tree(tgt) == before, out)

    rc, out = restore(e, arc, "rtgt")
    after = set(os.listdir(tgt))
    check("protejat + cheia bună → restaurat", rc == 0 and "opens the archive's keys.wtk" in out
          and open(os.path.join(tgt, "keys.wtk"), "rb").read() == src_keys, out)
    check("…fără secret în volum, starea veche (cu secret) în .restore-prev",
          "secret" not in after and os.path.exists(os.path.join(tgt, ".restore-prev", "secret")), after)
    check("….lock rămâne pe loc (acelaşi inode), nu e mutat în .restore-prev",
          os.lstat(os.path.join(tgt, ".lock")).st_ino == lock_ino
          and not os.path.exists(os.path.join(tgt, ".restore-prev", ".lock")), after)
    calls = e.calls()
    check("…app oprit, apoi pornit", "stop app" in calls and "up -d app" in calls
          and calls.index("stop app") < calls.index("up -d app"), calls)
    res = keys.boot(tgt, {"WEBTERM_MASTER_KEY_FILE": kf})
    check("…gateway-ul porneşte pe volumul restaurat cu cheia lui", res.state.mode == "protected", res.state)
    res.lock.release()

    # arhive făcute de mână: refuzate la citire, înainte de oprire
    db = open(os.path.join(e.vol("rsrc"), "webterm.db"), "rb").read()
    before = tree(tgt)
    for label, members, needle in (
            ("secret + keys.wtk fără migrating.wtm", {"webterm.db": db, "keys.wtk": src_keys, "secret": b"s" * 32},
             "both secret and keys.wtk"),
            ("cu master.key", {"webterm.db": db, "keys.wtk": src_keys, "master.key": b"k"}, "master.key"),
            ("legacy fără secret", {"webterm.db": db}, "without the vault key"),
            ("migrating.wtm fără keys.wtk", {"webterm.db": db, "secret": b"s" * 32, "migrating.wtm": b"m"},
             "without keys.wtk")):
        p = craft(os.path.join(e.base, "craft.tar.gz"), members)
        rc, out = restore(e, p, "rtgt")
        check("arhivă %s → refuz, nimic oprit, volum identic" % label,
              rc != 0 and needle in out and "stop app" not in e.calls() and tree(tgt) == before, out)

    # legacy, ca în 3.7
    legacy_volume(e, "lsrc")
    rc, out = backup(e, "lsrc")
    larc = os.path.join(e.base, "leg.tar.gz")
    shutil.copy(newest(e), larc)
    ltgt = legacy_volume(e, "ltgt")
    lino = os.lstat(os.path.join(ltgt, ".lock")).st_ino
    e.app("ltgt", [])
    rc, out = restore(e, larc, "ltgt")
    check("legacy → restaurat ca în 3.7, .lock neatins",
          rc == 0 and open(os.path.join(ltgt, "secret"), "rb").read()
          == open(os.path.join(e.vol("lsrc"), "secret"), "rb").read()
          and os.lstat(os.path.join(ltgt, ".lock")).st_ino == lino, out)

    # reduced: cheia din volum rămâne cu datele restaurate
    red = protected_volume(e, "rred", in_volume=True)
    vkey = open(os.path.join(red, "master.key"), "rb").read()
    rc, out = backup(e, "rred")
    rarc = os.path.join(e.base, "red.tar.gz")
    shutil.copy(newest(e), rarc)
    e.app("rred", ["WEBTERM_KEY_IN_VOLUME=1"])
    rc, out = restore(e, rarc, "rred")
    check("reduced pe acelaşi volum → master.key păstrat", rc == 0
          and open(os.path.join(red, "master.key"), "rb").read() == vkey, out)
    res = keys.boot(red, {"WEBTERM_KEY_IN_VOLUME": "1"})
    check("…şi volumul porneşte („reduced”)", res.state.mode == "reduced", res.state)
    res.lock.release()

    # --verify
    e.app("rtgt", ["WEBTERM_MASTER_KEY_FILE=" + kf])
    rc, out = e.run("restore.sh", "--verify", arc)
    check("--verify protejat, cheia bună → OK, cheia confirmată", rc == 0 and "opens the archive's keys.wtk" in out, out)
    e.app("rtgt", ["WEBTERM_MASTER_KEY_FILE=" + wrong])
    rc, out = e.run("restore.sh", "--verify", arc)
    check("--verify protejat, cheie greşită → FAILED", rc != 0 and "FAILED" in out, out)
    e.app("rtgt", [], cid=None)
    rc, out = e.run("restore.sh", "--verify", arc)
    check("--verify fără container app → OK, dar „master key was NOT checked”",
          rc == 0 and "NOT checked" in out, out)
    rc, out = e.run("restore.sh", "--verify", larc)
    check("--verify legacy → OK ca înainte", rc == 0 and "has the vault key" in out, out)
    p = craft(os.path.join(e.base, "craft.tar.gz"), {"webterm.db": db, "keys.wtk": src_keys, "secret": b"s" * 32})
    rc, out = e.run("restore.sh", "--verify", p)
    check("--verify arhivă amestecată → FAILED", rc != 0 and "both secret and keys.wtk" in out, out)

    if shutil.which("openssl"):
        e.app("rtgt", ["WEBTERM_MASTER_KEY_FILE=" + kf])
        rc, out = backup(e, "rsrc", {"WEBTERM_BACKUP_PASSPHRASE": "parola-arhivei"})
        enc = newest(e)
        rc2, out2 = restore(e, enc, "rtgt", {"WEBTERM_BACKUP_PASSPHRASE": "parola-arhivei"})
        check("arhivă protejată criptată (.enc) → round-trip", rc == 0 and enc.endswith(".enc") and rc2 == 0,
              out + out2)
    else:
        print("  SKIP: openssl not installed")


def main():
    e = Env()
    try:
        test_backup(e)
        test_restore(e)
    finally:
        shutil.rmtree(e.base, ignore_errors=True)
    print(f"\n{ok}/{total} passed")
    raise SystemExit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
