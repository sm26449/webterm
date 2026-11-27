"""scripts/backup.sh + scripts/restore.sh pe volume 3.7 şi 3.8 (criptare la repaus, INV-14).

Recenzia PR4 (H2/H3/M5): pe un volum protejat arhiva o scrie gateway-ul (`python3 -m app.hostops
backup`, în imaginea app-ului), iar restore-ul o verifică şi o pune în staging tot cu codul
gateway-ului, sub lock-ul volumului; boot-ul o aplică. Aici rulăm scripturile cu un `docker` FALS pe
PATH: „imaginea app-ului" e python-ul local cu gateway/ pe PYTHONPATH (exact codul din repo), iar
/data e un director temporar (WEBTERM_DATA_DIR). Nu atinge niciun volum, container sau Docker real.

Scenarii:
  * backup legacy (3.7): tar.gz cu `secret`, fără `.lock`;
  * backup protejat: .wtbk (WTBK2 → WTS1) scris de gateway, cu app-ul pornit (`docker exec`, lock-ul
    ţinut de „gateway") şi oprit (container nou fără reţea, cheia montată read-only, nicio
    `--env-file`); verificat înainte de publicare; fără parolă / app nesănătos / cheie dată ca
    valoare cu app-ul oprit / lock ocupat → refuz, nicio arhivă;
  * hardlink spre master.key în transcripts/ (volum „reduced") → conţinutul cheii nu intră;
  * restore protejat cu cheia bună → staging + boot „protected" cu datele sursei; `.lock` neatins;
  * cheie greşită / „n" / lock ocupat / `docker ps` eşuat / alt container pe volum → refuz, volum
    neschimbat, app-ul repornit doar când îl opriserăm;
  * staging terminat necunoscut → app-ul NU e repornit;
  * arhivă 3.7 pe volum legacy (ca înainte) şi pe volum protejat (doar cu --legacy-import);
  * reduced pe acelaşi volum → master.key rămâne (acelaşi inode);
  * tar.gz făcute de mână (secret + keys.wtk, master.key, nume dublat) → refuz;
  * --verify; hostops direct: digest greşit → refuz; verify nu scrie nimic în volum."""
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
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
GATEWAY = os.path.join(REPO, "gateway")
sys.path.insert(0, GATEWAY)
for _v in ("WEBTERM_MASTER_KEY_FILE", "WEBTERM_MASTER_KEY", "WEBTERM_KEY_IN_VOLUME"):
    os.environ.pop(_v, None)
_BOOT_DIR = tempfile.mkdtemp(prefix="wt-hostbk-boot-")
os.environ["WEBTERM_DATA_DIR"] = _BOOT_DIR
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")

from app import backup, bootkeys, config, hostops, keys  # noqa: E402

ok = 0
total = 0
PASS = "parola-arhivei-host"
FOREIGN_DB = b""


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {str(detail)[-900:]}"))


FAKE_DOCKER = r'''#!%(py)s
import os, sys
F = os.environ["FAKE_DIR"]
a = sys.argv[1:]
with open(os.path.join(F, "calls"), "a") as f:
    f.write(" ".join(a) + "\n")


def rd(n, default=""):
    p = os.path.join(F, n)
    return open(p).read() if os.path.exists(p) else default


def wr(n, v):
    open(os.path.join(F, n), "w").write(v)


def vol(name):
    return os.path.join(F, "vol", name)


CID = rd("app_cid").strip()
AVOL = rd("app_vol").strip()
RUNNING = rd("app_running", "true").strip()
GW = os.environ["FAKE_GATEWAY"]


def base_env():
    return {k: v for k, v in os.environ.items() if not k.startswith(("WT_", "WEBTERM_"))}


HOSTOPS_MAIN = "\nimport sys\nfrom app import hostops\nsys.exit(hostops.main(sys.argv[1:]))\n"
if a[:1] == ["compose"]:
    sys.exit(0)
if a[:1] in (["image"], ["pull"], ["logs"]):
    sys.exit(0)
if a[:2] == ["volume", "inspect"]:
    sys.exit(0 if os.path.isdir(vol(a[2])) else 1)
if a[:2] == ["volume", "ls"]:
    print("\n".join(sorted(os.listdir(os.path.join(F, "vol")))))
    sys.exit(0)
if a[:1] == ["ps"]:
    if rd("ps_fail"):
        sys.exit(1)
    flt = [x.split("=", 1)[1] for x in a if x.startswith("volume=")]
    want = flt[0] if flt else None
    out = []
    if CID and (want is None or want == AVOL) and ("-a" in a or RUNNING == "true"):
        out.append(CID)
    if want == AVOL:
        out += [x for x in rd("others").split() if x]
    print("\n".join(out))
    sys.exit(0)
if a[:1] in (["stop"], ["start"]):
    wr("app_running", "true" if a[0] == "start" else "false")
    sys.exit(0)
if a[:1] == ["inspect"]:
    fmt = a[a.index("--format") + 1] if "--format" in a else a[a.index("-f") + 1]
    if a[-1] != CID:
        sys.exit(1)
    if '"/data"' in fmt:
        print(AVOL)
    elif "com.docker.compose.service" in fmt:
        print("app")
    elif fmt == "{{.Image}}":
        print("sha256:fakeapp")
    elif "Config.Env" in fmt:
        sys.stdout.write(rd("app_env"))
    elif "{{.Type}}" in fmt:
        sys.stdout.write(rd("app_mounts"))
    elif "State.Running}}|" in fmt:
        print("%%s|%%s" %% (RUNNING, rd("app_health", "healthy").strip() if RUNNING == "true" else ""))
    elif "State.Running" in fmt:
        print(RUNNING)
    elif "Health.Status" in fmt:
        print(rd("app_health", "healthy").strip() if RUNNING == "true" else "exited")
    sys.exit(0)
if a[:1] == ["exec"]:
    env = base_env()
    i = 1
    while a[i].startswith("-"):
        if a[i] == "-e":
            k = a[i + 1]
            if k in os.environ:
                env[k] = os.environ[k]
            i += 2
        elif a[i] == "-u":
            i += 2
        else:
            i += 1
    if a[i] != CID or RUNNING != "true":
        sys.exit(1)
    for line in rd("app_env").splitlines():
        k, _, v = line.partition("=")
        env[k] = v
    env.update(PYTHONPATH=GW, WEBTERM_DATA_DIR=vol(AVOL))
    rest = a[i + 1:]
    if rd("hostops_pre") and rest[1:3] == ["-m", "app.hostops"]:
        rest = rest[:1] + ["-c", rd("hostops_pre") + HOSTOPS_MAIN] + rest[3:]
    os.execve(sys.executable, [sys.executable] + rest[1:], env)
if a[:1] != ["run"]:
    print("fake docker: unexpected %%s" %% a, file=sys.stderr)
    sys.exit(9)
VAL = {"-v", "-e", "--entrypoint", "--env-file", "--volumes-from", "--user", "-u", "--network", "-w"}
env = base_env()
MAP = {"/data": "WT_DATA", "/out": "WT_OUT", "/in": "WT_IN"}
entry, i = None, 1
while i < len(a):
    o = a[i]
    if o in VAL:
        v = a[i + 1]
        i += 2
        if o == "-v":
            src, dst = v.split(":")[:2]
            if not src.startswith("/"):
                src = vol(src)
            if dst in MAP:
                env[MAP[dst]] = src
            if dst == "/data":
                env["WEBTERM_DATA_DIR"] = src
        elif o == "-e":
            k, _, val = v.partition("=")
            if "=" in v:
                env[k] = val
            elif k in os.environ:
                env[k] = os.environ[k]
        elif o == "--env-file":
            sys.exit("fake docker: --env-file is not allowed (M5)")
        elif o == "--entrypoint":
            entry = v
        continue
    if o.startswith("-"):
        i += 1
        continue
    break
image, rest = a[i], a[i + 1:]
if entry != "python3":
    sys.exit(0)
if image == "sha256:fakeapp":
    env["PYTHONPATH"] = GW
    if rest[:2] == ["-m", "app.hostops"] and rest[2:3] == ["stage-restore"] and rd("stage_crash"):
        sys.exit(137)
    if rest[:2] == ["-m", "app.hostops"] and rest[2:3] == ["stage-restore"] and rd("stage_fsync_fail"):
        # R-M1: fsync-ul directorului eşuează DUPĂ rename-ul flagului (EIO injectat în codul real)
        rest = ["-c", "import sys\nfrom app import backup, hostops\nst = {'on': False}\no = backup._fsync\n"
                "def fs(fd):\n    if st['on']:\n        raise OSError(5, 'injected EIO')\n    return o(fd)\n"
                "def fault(n):\n    if n == 'flag:renamed':\n        st['on'] = True\n"
                "backup._fsync = fs\nbackup._fault = fault\nsys.exit(hostops.main())"] + rest[2:]
    elif rd("hostops_pre") and rest[:2] == ["-m", "app.hostops"]:
        rest = ["-c", rd("hostops_pre") + HOSTOPS_MAIN] + rest[2:]
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
        df = os.path.join(self.fake, "bin", "df")
        with open(df, "w") as f:
            # df fals doar când testul îl cere (df_avail); altfel cel real
            f.write('#!/bin/sh\nif [ -f "$FAKE_DIR/df_avail" ]; then echo Avail; cat "$FAKE_DIR/df_avail"; exit 0; fi\n'
                    'PATH=/usr/bin:/bin exec df "$@"\n')
        os.chmod(df, 0o755)
        s = os.path.join(self.fake, "bin", "sleep")
        with open(s, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(s, 0o755)
        # copii ale scripturilor, FĂRĂ host-health.sh lângă ele (nu scriem statusuri nicăieri)
        self.scripts = os.path.join(self.base, "scripts")
        os.makedirs(self.scripts)
        for sc in ("backup.sh", "restore.sh"):
            shutil.copy(os.path.join(REPO, "scripts", sc), self.scripts)
        self.out = os.path.join(self.base, "out")
        self.inst = os.path.join(self.base, "inst")
        os.makedirs(self.inst)
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

    def put(self, name, value):
        p = os.path.join(self.fake, name)
        if value is None:
            if os.path.exists(p):
                os.unlink(p)
        else:
            open(p, "w").write(value)

    def app(self, vol, env_lines=(), cid="cid-app", running=True, health="healthy", mounts=None):
        self.put("app_vol", vol)
        self.put("app_env", "".join(x + "\n" for x in env_lines))
        self.put("app_cid", cid)
        self.put("app_running", "true" if running else "false")
        self.put("app_health", health)
        if mounts is None:
            mounts = "bind||%s|%s\n" % (self.keys, self.keys)   # cheia: aceeaşi cale „în container"
        self.put("app_mounts", mounts)
        for n in ("others", "ps_fail", "stage_crash", "stage_fsync_fail", "hostops_pre", "df_avail"):
            self.put(n, None)

    def state(self, name):
        p = os.path.join(self.fake, name)
        return open(p).read().strip() if os.path.exists(p) else ""

    def calls(self):
        p = os.path.join(self.fake, "calls")
        return open(p).read() if os.path.exists(p) else ""

    def reset_calls(self):
        p = os.path.join(self.fake, "calls")
        if os.path.exists(p):
            os.unlink(p)

    def env(self, extra=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("WEBTERM_", "WT_"))}
        env.update({"PATH": os.path.join(self.fake, "bin") + ":" + os.environ["PATH"],
                    "FAKE_DIR": self.fake, "FAKE_GATEWAY": GATEWAY,
                    "WEBTERM_BACKUP_DIR": self.out, "WEBTERM_UID": "%d:%d" % (os.getuid(), os.getgid())})
        env.update(extra or {})
        return env

    def run(self, script, *args, extra=None, stdin=""):
        self.reset_calls()
        p = subprocess.run(["bash", os.path.join(self.scripts, script), *args], cwd=self.inst,
                           env=self.env(extra), input=stdin, capture_output=True, text=True, timeout=180)
        return p.returncode, p.stdout + p.stderr


def make_db(path, email="a@b.c"):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, created REAL)")
    for t in ("hosts", "sessions"):
        con.execute("CREATE TABLE %s(id INTEGER PRIMARY KEY, cred_encrypted TEXT)" % t)
    con.execute("CREATE TABLE app_settings(key TEXT PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO users(email, created) VALUES(?, 1000)", (email,))
    con.commit()
    con.close()


def _foreign_db():
    """Un DB valid cu o valoare de seif criptată sub o cheie pe care arhiva NU o poartă (R-H2)."""
    from cryptography.fernet import Fernet
    d = tempfile.mkdtemp(prefix="wt-hostbk-fdb-")
    p = os.path.join(d, "webterm.db")
    make_db(p, email="strain@x")
    con = sqlite3.connect(p)
    tok = Fernet(base64.urlsafe_b64encode(os.urandom(32))).encrypt(b"pw").decode()
    con.execute("INSERT INTO hosts(cred_encrypted) VALUES(?)", (tok,))
    con.commit()
    con.close()
    raw = open(p, "rb").read()
    shutil.rmtree(d, ignore_errors=True)
    return raw


def signing_pair():
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    return pem, (priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex() + "\n").encode()


def common_files(d, email):
    make_db(os.path.join(d, "webterm.db"), email)
    k, p = signing_pair()
    open(os.path.join(d, "agent-signing.key"), "wb").write(k)
    open(os.path.join(d, "agent-signing.pub"), "wb").write(p)
    os.makedirs(os.path.join(d, "transcripts"), exist_ok=True)
    open(os.path.join(d, "transcripts", "s1.out"), "w").write("x" * 10)


def legacy_volume(e, name, email="legacy@x"):
    d = e.vol(name)
    os.makedirs(d)
    common_files(d, email)
    with open(os.path.join(d, "secret"), "wb") as f:
        f.write(os.urandom(32))
    open(os.path.join(d, ".lock"), "w").write("")
    return d


def protected_volume(e, name, key=None, in_volume=False, email="prot@x"):
    d = e.vol(name)
    os.makedirs(d)
    env = {"WEBTERM_KEY_IN_VOLUME": "1"} if in_volume else {"WEBTERM_MASTER_KEY_FILE": key}
    res = keys.boot(d, env)
    res.lock.release()
    common_files(d, email)
    return d


def tree(d):
    out = {}
    for base, dirs, files in os.walk(d):
        for n in dirs + files:
            p = os.path.join(base, n)
            st = os.lstat(p)
            h = hashlib.sha256(open(p, "rb").read()).hexdigest() if stat.S_ISREG(st.st_mode) else ""
            out[os.path.relpath(p, d)] = (stat.S_IFMT(st.st_mode), h, st.st_ino)
    # directorul de lucru al backup-ului (backups/.work, temporarele de pe volum) nu e dată: rămâne
    # GOL după orice operaţie — orice fişier lăsat în el apare mai departe ca diferenţă
    if "backups/.work" in out and not any(k.startswith("backups/.work/") for k in out):
        del out["backups/.work"]
    if "backups" in out and not any(k.startswith("backups/") for k in out):
        del out["backups"]
    return out


def data_tree(d):
    # ce contează pentru date: fără lacăte (create la prima utilizare, niciodată scrise); lacătul
    # operaţiilor de restore (backups/.restore.lock) îl ia şi un staging în flux refuzat la capăt
    out = {k: v for k, v in tree(d).items() if k not in (".lock", ".maint.lock", "backups/.restore.lock")}
    if "backups" in out and not any(k.startswith("backups/") for k in out):
        del out["backups"]
    return out


def names(archive):
    with tarfile.open(archive) as t:
        return {m.name.split("/", 1)[0] for m in t.getmembers()}


def newest(e):
    arcs = sorted((os.path.join(e.out, n) for n in os.listdir(e.out)), key=os.path.getmtime)
    return arcs[-1]


def backup_run(e, vol, extra=None, plaintext_ok=True):
    if os.path.isdir(e.out):
        shutil.rmtree(e.out)
    x = {"WEBTERM_VOLUME": vol}
    if plaintext_ok:
        x["WEBTERM_BACKUP_ALLOW_PLAINTEXT"] = "1"
    x.update(extra or {})
    return e.run("backup.sh", extra=x)


def craft(path, members):
    """O arhivă tar.gz făcută de mână: [(nume, octeţi)] (un nume poate apărea de două ori)."""
    with tarfile.open(path, "w:gz") as t:
        for n, data in members:
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return path


def boot_check(d, env):
    """Boot-ul real al gateway-ului pe volumul restaurat (aplică setul din staging) → (mode, email)."""
    config.DATA_DIR = Path(d)
    config.DB_PATH = config.DATA_DIR / "webterm.db"
    config.TRANSCRIPT_DIR = config.DATA_DIR / "transcripts"
    config.ARCHIVE_DIR = config.TRANSCRIPT_DIR / "arhiva"
    try:
        res = bootkeys.prepare(env, data_dir=d)
        mode = res.state.mode
        applied = bootkeys.STATE.get("restore_applied")
    except Exception as ex:                       # noqa: BLE001
        return "refused: %s" % ex, None, None
    finally:
        bootkeys.release()
    email = sqlite3.connect(os.path.join(d, "webterm.db")).execute("SELECT email FROM users").fetchone()[0]
    return mode, email, applied


def hold_lock(d):
    return keys.acquire_lock(d)


PE = {"WEBTERM_BACKUP_PASSPHRASE": PASS}


def test_backup(e):
    print("── backup.sh: legacy, protejat (live / oprit), refuzuri")
    legacy_volume(e, "leg")
    rc, out = backup_run(e, "leg")
    arc = newest(e) if rc == 0 else ""
    check("legacy: arhiva are secret + DB + cheia de semnare, nu .lock",
          rc == 0 and {"webterm.db", "secret", "agent-signing.key", "transcripts"} <= names(arc)
          and ".lock" not in names(arc), out)
    check("…avertismentul spune că arhiva ţine cheia seifului", "vault key (data/secret)" in out, out)

    kf = e.key_file("prot.key")
    d = protected_volume(e, "prot", kf)
    e.app("prot", ["WEBTERM_MASTER_KEY_FILE=" + kf])
    gw = hold_lock(d)                               # „gateway-ul" ţine .lock
    try:
        rc, out = backup_run(e, "prot", PE)
    finally:
        gw.release()
    arc = newest(e) if rc == 0 else ""
    raw = open(arc, "rb").read() if arc else b""
    check("protejat, app pornit: .wtbk scris de gateway (docker exec), criptat WTBK2 (în flux)",
          rc == 0 and arc.endswith(".wtbk") and raw[:5] == b"WTBK2" and "exec -i" in e.calls(), out + e.calls())
    check("…verificat înainte de publicare, fără temporar rămas, mod 0600",
          "(verified)" in out and os.listdir(e.out) == [os.path.basename(arc)]
          and stat.S_IMODE(os.stat(arc).st_mode) == 0o600, (out, os.listdir(e.out) if os.path.isdir(e.out) else None))
    check("…spune că cheia master NU e în arhivă şi unde stă", "master key is NOT in this archive" in out
          and "secrets/master-key/master.key" in out, out)
    inner = backup.decrypt(raw, PASS) if raw else b""
    check("…în interior un WTS1 (nu un tar cu shell-ul)", inner[:4] == b"WTS1", inner[:8])

    e.app("prot", ["WEBTERM_MASTER_KEY_FILE=" + kf], running=False)
    rc, out = backup_run(e, "prot", PE)
    calls = e.calls()
    arc = newest(e) if rc == 0 else ""
    check("protejat, app oprit: container nou, fără reţea, cheia montată read-only, fără --env-file",
          rc == 0 and arc.endswith(".wtbk") and "run --rm -i --network none" in calls
          and ("%s:%s:ro" % (e.keys, e.keys)) in calls and "--env-file" not in calls
          and "exec " not in calls, out + calls)
    # R-L1: acelaşi nume (aceeaşi secundă) → a doua rulare refuză, prima arhivă rămâne neatinsă
    ds = os.path.join(e.fake, "bin", "date")
    with open(ds, "w") as f:
        f.write('#!/bin/sh\n[ -n "$FAKE_STAMP" ] && [ "$1" = "+%Y%m%d-%H%M%S" ] && { echo "$FAKE_STAMP"; exit 0; }\n'
                'exec /usr/bin/date "$@"\n')
    os.chmod(ds, 0o755)
    shutil.rmtree(e.out, ignore_errors=True)
    x = dict(PE, WEBTERM_VOLUME="prot", FAKE_STAMP="20260101-000000")
    rc1, out1 = e.run("backup.sh", extra=x)
    first = newest(e) if rc1 == 0 else ""
    b1 = open(first, "rb").read() if first else b""
    rc2, out2 = e.run("backup.sh", extra=x)
    os.unlink(ds)
    check("R-L1: două backup-uri cu acelaşi nume → al doilea refuză, primul neatins, niciun temporar",
          rc1 == 0 and rc2 != 0 and "already exists" in out2 and open(first, "rb").read() == b1
          and os.listdir(e.out) == [os.path.basename(first)], (out1[-300:], out2[-300:], os.listdir(e.out)))
    # RC-L1: un director apare la numele final DUPĂ verificarea „există deja” (simulat la primul
    # `sync` al temporarului) → `ln -T` refuză; nimic nu e publicat înăuntrul lui
    ss = os.path.join(e.fake, "bin", "sync")
    with open(ss, "w") as f:
        f.write('#!/bin/sh\nfor a in "$@"; do case "$a" in *.wtbk.tmp)\n'
                '  b=$(basename "$a"); s=${b#.webterm-}; s=${s%.*.wtbk.tmp}\n'
                '  mkdir -p "$(dirname "$a")/webterm-$s.wtbk" ;; esac; done\nexec /usr/bin/sync "$@"\n')
    os.chmod(ss, 0o755)
    shutil.rmtree(e.out, ignore_errors=True)
    rc, out = e.run("backup.sh", extra=dict(PE, WEBTERM_VOLUME="prot"))
    os.unlink(ss)
    inside = [n for n in os.listdir(e.out) if os.path.isdir(os.path.join(e.out, n))]
    check("RC-L1: un director apărut la numele final → refuz, nimic publicat în el, niciun temporar",
          rc != 0 and "could not publish" in out and len(inside) == 1 and inside[0].endswith(".wtbk")
          and os.listdir(os.path.join(e.out, inside[0])) == [] and len(os.listdir(e.out)) == 1,
          (out[-300:], os.listdir(e.out)))
    shutil.rmtree(e.out, ignore_errors=True)
    os.makedirs(e.out)
    gw = hold_lock(d)
    try:
        rc, out = backup_run(e, "prot", PE)
    finally:
        gw.release()
    check("…app oprit dar .lock ţinut de altcineva → refuz, nicio arhivă",
          rc != 0 and "REFUSING" in out and not os.listdir(e.out), out)

    rc, out = backup_run(e, "prot")
    check("protejat fără parolă → refuz (o arhivă protejată e mereu criptată)",
          rc != 0 and "WEBTERM_BACKUP_PASSPHRASE" in out and not os.listdir(e.out), out)
    e.app("prot", ["WEBTERM_MASTER_KEY_FILE=" + kf], health="starting")
    rc, out = backup_run(e, "prot", PE)
    check("app pornit dar nesănătos → refuz", rc != 0 and "not healthy" in out and not os.listdir(e.out), out)
    e.app("prot", ["WEBTERM_MASTER_KEY=" + base64.b64encode(os.urandom(32)).decode()], running=False)
    rc, out = backup_run(e, "prot", PE)
    check("cheie dată ca valoare (WEBTERM_MASTER_KEY) cu app-ul oprit → refuz, nu se copiază",
          rc != 0 and "WEBTERM_MASTER_KEY" in out and "--network none" not in e.calls() and not os.listdir(e.out), out)
    e.app("altvol", ["WEBTERM_MASTER_KEY_FILE=" + kf])
    rc, out = backup_run(e, "prot", PE)
    check("niciun container app pe volum → refuz", rc != 0 and "no app container" in out, out)

    for extra_name, why in (("migrating.wtm", "migrare neterminată"), ("secret", "secret lângă keys.wtk"),
                            ("keys.wtk.tmp", "temporar de publicare")):
        e.app("prot", ["WEBTERM_MASTER_KEY_FILE=" + kf])
        p = os.path.join(d, extra_name)
        open(p, "wb").write(b"x" * 32)
        rc, out = backup_run(e, "prot", PE)
        check("protejat + %s (%s) → refuz, nicio arhivă" % (extra_name, why),
              rc != 0 and "REFUSING" in out and not os.listdir(e.out), out)
        os.unlink(p)

    # H3: un hardlink spre cheia din volum, sub alt nume, nu-i aduce conţinutul în arhivă
    red = protected_volume(e, "red", in_volume=True)
    mkey = open(os.path.join(red, "master.key"), "rb").read()
    os.link(os.path.join(red, "master.key"), os.path.join(red, "transcripts", "leak.out"))
    e.app("red", ["WEBTERM_KEY_IN_VOLUME=1"])
    rc, out = backup_run(e, "red", PE)
    leaked = None
    if rc == 0:
        res = keys.boot(red, {"WEBTERM_KEY_IN_VOLUME": "1"})
        res.lock.release()
        td = tempfile.mkdtemp(dir=e.base)
        config.DATA_DIR = Path(red)
        hk = backup.HostKeys(res.keyring, res.master_key)
        inner = backup.decrypt(open(newest(e), "rb").read(), PASS)
        backup._verify_wts(io.BytesIO(inner), hk, td, prefer="portable")
        leaked = any(mkey.strip() in open(os.path.join(b, n), "rb").read()
                     for b, _ds, fs in os.walk(td) for n in fs)
    check("reduced + hardlink transcripts/leak.out → master.key: arhiva nu conţine cheia "
          "(sau backup-ul refuză)", (rc == 0 and leaked is False) or (rc != 0 and "REFUSING" in out),
          (rc, leaked, out))
    os.unlink(os.path.join(red, "transcripts", "leak.out"))
    rc, out = backup_run(e, "red", PE)
    check("reduced: .wtbk, mesajul spune WEBTERM_KEY_IN_VOLUME=1",
          rc == 0 and newest(e).endswith(".wtbk") and "WEBTERM_KEY_IN_VOLUME=1" in out, out)

    d = legacy_volume(e, "legstray")
    open(os.path.join(d, "master.key"), "w").write("k")
    rc, out = backup_run(e, "legstray")
    check("legacy cu master.key fără keys.wtk → refuz (volum inconsistent)",
          rc != 0 and "without keys.wtk" in out and not os.listdir(e.out), out)
    shutil.rmtree(e.out)


def restore(e, archive, vol, extra=None, yes=True, args=()):
    x = {"WEBTERM_VOLUME": vol}
    x.update(extra or {})
    return e.run("restore.sh", *args, archive, extra=x, stdin="y\n" if yes else "n\n")


def make_archive(e, vol, key_env, dest, extra=None):
    e.app(vol, key_env)
    rc, out = backup_run(e, vol, dict(PE, **(extra or {})))
    assert rc == 0, out
    shutil.copy(newest(e), dest)
    return dest


def test_restore(e):
    print("── restore.sh: arhive protejate şi legacy, prin codul gateway-ului")
    kf = e.key_file("src.key")
    protected_volume(e, "rsrc", kf, email="sursa@x")
    arc = make_archive(e, "rsrc", ["WEBTERM_MASTER_KEY_FILE=" + kf], os.path.join(e.base, "prot.wtbk"))

    # ţinta: protejată cu ALTĂ cheie → refuz înainte de oprire
    wrong = e.key_file("wrong.key")
    t2 = protected_volume(e, "rwrong", wrong, email="tinta@x")
    e.app("rwrong", ["WEBTERM_MASTER_KEY_FILE=" + wrong])
    before = tree(t2)
    rc, out = restore(e, arc, "rwrong", PE)
    check("protejat + cheie greşită → refuz, cu id-ul cheii cerute", rc != 0 and "needs master key" in out, out)
    check("…app-ul NU a fost oprit, volumul identic", "stop " not in e.calls() and tree(t2) == before, e.calls())

    # ţinta: aceeaşi cheie, altă instalare
    tgt = protected_volume(e, "rtgt", kf, email="tinta@x")
    e.app("rtgt", ["WEBTERM_MASTER_KEY_FILE=" + kf])
    lock_ino = os.lstat(os.path.join(tgt, ".lock")).st_ino
    before = data_tree(tgt)
    rc, out = restore(e, arc, "rtgt", PE, yes=False)
    check("„n” la confirmare → abandon, nimic oprit, volum identic",
          rc != 0 and "aborted" in out and "stop " not in e.calls() and data_tree(tgt) == before, out)

    e.put("others", "cid-other")
    rc, out = restore(e, arc, "rtgt", PE)
    check("alt container pe volum după oprire → refuz, app repornit, volum identic",
          rc != 0 and "still using volume" in out and "start cid-app" in e.calls()
          and data_tree(tgt) == before, out + e.calls())
    e.put("others", None)
    e.put("ps_fail", "1")
    rc, out = restore(e, arc, "rtgt", PE)
    check("`docker ps` eşuat → refuz (nu „niciun container”), volum identic",
          rc != 0 and "REFUSING" in out and data_tree(tgt) == before, out)
    e.put("ps_fail", None)

    gw = hold_lock(tgt)                             # un vacuum / alt proces ţine .lock
    try:
        rc, out = restore(e, arc, "rtgt", PE)
    finally:
        gw.release()
    calls = e.calls()
    check("lock ţinut de altcineva → staging refuzat înaintea oricărei mutaţii, app repornit",
          rc != 0 and "locked" in out and "nothing was staged" in out and "start cid-app" in calls
          and data_tree(tgt) == before, out + calls)
    maint = keys.acquire_maint_lock(os.open(tgt, os.O_RDONLY | os.O_DIRECTORY), exclusive=False)
    try:
        rc, out = restore(e, arc, "rtgt", PE)
    finally:
        os.close(maint)
    check("o comandă admin (.maint.lock) în curs → refuz, volum identic",
          rc != 0 and "admin command" in out and data_tree(tgt) == before, out)

    e.put("stage_crash", "1")
    rc, out = restore(e, arc, "rtgt", PE)
    check("staging terminat necunoscut (exit 137) → app-ul NU e repornit, spune de ce",
          rc != 0 and "start cid-app" not in e.calls() and "NOT restarted" in out, out + e.calls())
    e.put("stage_crash", None)
    e.put("app_running", "true")

    # R-M1: fsync-ul directorului eşuează după publicarea flagului → exit 4, app-ul rămâne oprit
    e.put("stage_fsync_fail", "1")
    rc, out = restore(e, arc, "rtgt", PE)
    calls = e.calls()
    check("R-M1: fsync eşuat după rename-ul flagului → exit 4 (incert), app-ul NU e repornit, paşi de recuperare",
          rc != 0 and "exit 4" in out and "UNCERTAIN" in out and "stop cid-app" in calls
          and "start cid-app" not in calls and "left STOPPED" in out, out[-600:] + calls)
    e.put("stage_fsync_fail", None)
    mode, email, applied = boot_check(tgt, {"WEBTERM_MASTER_KEY_FILE": kf})
    check("R-M1: …următorul boot recuperează: aplică setul publicat (protected, datele sursei)",
          mode == "protected" and email == "sursa@x" and applied, (mode, email, applied))
    e.put("app_running", "true")

    rc, out = restore(e, arc, "rtgt", PE)
    calls = e.calls()
    check("protejat + cheia bună → verificat, oprit, pus în staging, pornit",
          rc == 0 and "staged: protected" in out and "restored from" in out
          and calls.index("stop cid-app") < calls.index("stage-restore") < calls.index("start cid-app"),
          out + calls)
    check("…staging-ul a rulat fără reţea, cu volumul rw şi cheia read-only, fără --env-file",
          "run --rm -i --network none" in calls and "--env-file" not in calls, calls)
    check("….lock rămâne pe loc (acelaşi inode)", os.lstat(os.path.join(tgt, ".lock")).st_ino == lock_ino)
    check("…un set durabil în staging (flag + restore-pending.<gen>)",
          os.path.exists(os.path.join(tgt, ".restore-flag"))
          and any(n.startswith("restore-pending.") for n in os.listdir(tgt)), os.listdir(tgt))
    mode, email, applied = boot_check(tgt, {"WEBTERM_MASTER_KEY_FILE": kf})
    check("…boot-ul gateway-ului aplică setul: protected, datele sursei",
          mode == "protected" and email == "sursa@x" and applied, (mode, email, applied))

    # arhive făcute de mână: refuzate la citire de extractorul STRICT al gateway-ului (R-H2: niciun
    # alt parser), înainte de oprire — şi fără --legacy-import, şi cu el
    db = open(os.path.join(e.vol("rsrc"), "webterm.db"), "rb").read()
    before = data_tree(tgt)
    for label, members in (
            ("secret + keys.wtk", [("webterm.db", db), ("keys.wtk", b"k"), ("secret", b"s" * 32)]),
            ("cu master.key", [("webterm.db", db), ("secret", b"s" * 32), ("master.key", b"k")]),
            ("legacy fără secret", [("webterm.db", db)]),
            ("nume dublat", [("webterm.db", db), ("secret", b"s" * 32), ("webterm.db", b"x")]),
            ("secret străin DB-ului (32 de octeţi)", [("webterm.db", FOREIGN_DB), ("secret", os.urandom(32))])):
        p = craft(os.path.join(e.base, "craft.tar.gz"), members)
        for args in ((), ("--legacy-import",)):
            rc, out = restore(e, p, "rtgt", PE, args=args)
            check("arhivă %s%s → refuz, nimic oprit, volum identic" % (label, " (--legacy-import)" if args else ""),
                  rc != 0 and "REFUSING" in out and "stop " not in e.calls() and data_tree(tgt) == before, out[-400:])

    # legacy, ca în 3.7
    legacy_volume(e, "lsrc", email="vechi@x")
    e.app("lsrc", [])
    rc, out = backup_run(e, "lsrc")
    larc = os.path.join(e.base, "leg.tar.gz")
    shutil.copy(newest(e), larc)
    ltgt = legacy_volume(e, "ltgt", email="altul@x")
    lino = os.lstat(os.path.join(ltgt, ".lock")).st_ino
    e.app("ltgt", [])
    rc, out = restore(e, larc, "ltgt", args=("--legacy-import",))
    check("legacy pe volum legacy cu --legacy-import → refuz (opţiunea e pentru volume protejate)",
          rc != 0 and "--legacy-import is for protected volumes" in out, out)
    rc, out = restore(e, larc, "ltgt")
    check("legacy pe volum legacy → pus în staging, .lock neatins",
          rc == 0 and os.lstat(os.path.join(ltgt, ".lock")).st_ino == lino, out)
    mode, email, applied = boot_check(ltgt, {})
    check("…boot-ul 3.7 îl aplică: secretul sursei, datele sursei",
          mode == "legacy" and email == "vechi@x" and open(os.path.join(ltgt, "secret"), "rb").read()
          == open(os.path.join(e.vol("lsrc"), "secret"), "rb").read(), (mode, email))

    # legacy pe volum protejat: doar cu importul explicit
    pk = e.key_file("p.key")
    ptgt = protected_volume(e, "ptgt", pk, email="protejat@x")
    e.app("ptgt", ["WEBTERM_MASTER_KEY_FILE=" + pk])
    before = data_tree(ptgt)
    rc, out = restore(e, larc, "ptgt")
    check("arhivă 3.7 pe volum protejat fără --legacy-import → refuz, volum identic",
          rc != 0 and "--legacy-import" in out and data_tree(ptgt) == before, out)
    rc, out = restore(e, larc, "ptgt", args=("--legacy-import",))
    check("…cu --legacy-import → pus în staging, fără `secret` brut în volum",
          rc == 0 and not os.path.exists(os.path.join(ptgt, "secret"))
          and not any(open(os.path.join(b, n), "rb").read() == open(os.path.join(e.vol("lsrc"), "secret"), "rb").read()
                      for b, _ds, fs in os.walk(ptgt) for n in fs), out)
    mode, email, applied = boot_check(ptgt, {"WEBTERM_MASTER_KEY_FILE": pk})
    check("…boot-ul: protected, datele arhivei 3.7", mode == "protected" and email == "vechi@x", (mode, email))

    # reduced: cheia din volum rămâne pe loc
    red = protected_volume(e, "rred", in_volume=True, email="redus@x")
    rarc = make_archive(e, "rred", ["WEBTERM_KEY_IN_VOLUME=1"], os.path.join(e.base, "red.wtbk"))
    con = sqlite3.connect(os.path.join(red, "webterm.db"))
    con.execute("UPDATE users SET email='schimbat@x'")
    con.commit()
    con.close()
    vkey = open(os.path.join(red, "master.key"), "rb").read()
    vino = os.lstat(os.path.join(red, "master.key")).st_ino
    e.app("rred", ["WEBTERM_KEY_IN_VOLUME=1"], mounts="")
    rc, out = restore(e, rarc, "rred", PE)
    check("reduced pe acelaşi volum → master.key neatins (acelaşi inode, acelaşi conţinut)", rc == 0
          and open(os.path.join(red, "master.key"), "rb").read() == vkey
          and os.lstat(os.path.join(red, "master.key")).st_ino == vino, out)
    mode, email, applied = boot_check(red, {"WEBTERM_KEY_IN_VOLUME": "1"})
    check("…şi volumul porneşte „reduced”, cu datele arhivei", mode == "reduced" and email == "redus@x",
          (mode, email))

    # --verify
    e.app("rtgt", ["WEBTERM_MASTER_KEY_FILE=" + kf])
    before = data_tree(tgt)
    rc, out = e.run("restore.sh", "--verify", arc, extra=dict(PE, WEBTERM_VOLUME="rtgt"))
    check("--verify protejat, cheia bună → OK", rc == 0 and "restore test OK" in out, out)
    e.app("rtgt", ["WEBTERM_MASTER_KEY_FILE=" + kf], running=False)
    rc, out = e.run("restore.sh", "--verify", arc, extra=dict(PE, WEBTERM_VOLUME="rtgt"))
    check("--verify cu app-ul oprit (container nou, volum read-only) → OK, volumul neschimbat",
          rc == 0 and ":/data:ro" in e.calls() and data_tree(tgt) == before, out + e.calls())
    e.app("rwrong", ["WEBTERM_MASTER_KEY_FILE=" + wrong])
    rc, out = e.run("restore.sh", "--verify", arc, extra=dict(PE, WEBTERM_VOLUME="rwrong"))
    check("--verify protejat, cheie greşită → FAILED", rc != 0 and "needs master key" in out, out)
    e.put("app_cid", "")
    rc, out = e.run("restore.sh", "--verify", arc, extra=dict(PE, WEBTERM_VOLUME="rwrong"))
    check("--verify fără container app → refuz (nimic nu poate verifica arhiva)",
          rc != 0 and "no app container" in out, out)
    e.app("ltgt", [])
    rc, out = e.run("restore.sh", "--verify", larc, extra={"WEBTERM_VOLUME": "ltgt"})
    check("--verify legacy → OK", rc == 0 and "restore test OK" in out, out)
    rc, out = e.run("restore.sh", "--verify", arc, extra={"WEBTERM_VOLUME": "rtgt"})
    check(".wtbk fără parolă → refuz", rc != 0 and "WEBTERM_BACKUP_PASSPHRASE" in out, out)

    if shutil.which("openssl"):
        rc, out = backup_run(e, "lsrc", PE)
        enc = newest(e)
        ltgt2 = legacy_volume(e, "ltgt2")
        e.app("ltgt2", [])
        rc2, out2 = restore(e, enc, "ltgt2", PE)
        check("arhivă 3.7 criptată (.enc) → round-trip", rc == 0 and enc.endswith(".enc") and rc2 == 0
              and boot_check(ltgt2, {})[1] == "vechi@x", out + out2)
    else:
        print("  SKIP: openssl not installed")


def hostops_run(e, vol, args, stdin, env_extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("WEBTERM_", "WT_"))}
    env.update(PYTHONPATH=GATEWAY, WEBTERM_DATA_DIR=e.vol(vol), **(env_extra or {}))
    p = subprocess.run([sys.executable, "-m", "app.hostops", *args], input=stdin, env=env,
                       capture_output=True, timeout=120)
    return p.returncode, p.stdout.decode(errors="replace") + p.stderr.decode(errors="replace")


def test_hostops(e):
    print("── app.hostops direct: digest fixat, verify fără scrieri, coduri de ieşire")
    kf = e.key_file("h.key")
    d = protected_volume(e, "hsrc", kf, email="h@x")
    kenv = {"WEBTERM_MASTER_KEY_FILE": kf, "WEBTERM_BACKUP_PASSPHRASE": PASS}
    rc, out = hostops_run(e, "hsrc", ["backup"], b"", kenv)
    check("backup fără --live, .lock liber → exit 0", rc == 0, out[-400:])
    env = {k: v for k, v in os.environ.items() if not k.startswith(("WEBTERM_", "WT_"))}
    env.update(PYTHONPATH=GATEWAY, WEBTERM_DATA_DIR=d, **kenv)
    blob = subprocess.run([sys.executable, "-m", "app.hostops", "backup"], env=env, capture_output=True).stdout
    sha = hashlib.sha256(blob).hexdigest()
    before = tree(d)
    rc, out = hostops_run(e, "hsrc", ["verify", "--sha256", sha], blob, kenv)
    check("verify → exit 0 şi NIMIC scris în volum (nici lacăte, nici temporare)",
          rc == 0 and "volume: protected" in out and tree(d) == before, (out, set(tree(d)) ^ set(before)))
    rc, out = hostops_run(e, "hsrc", ["verify", "--sha256", "0" * 64], blob, kenv)
    check("verify cu alt digest → exit 3", rc == hostops.EXIT_REFUSED and "not the one that was checked" in out, out)
    rc, out = hostops_run(e, "hsrc", ["stage-restore", "--sha256", "0" * 64], blob, kenv)
    check("stage-restore cu alt digest → exit 3, volum neschimbat",
          rc == hostops.EXIT_REFUSED and data_tree(d) == {k: v for k, v in before.items()
                                                          if k not in (".lock", ".maint.lock")}, out)
    rc, out = hostops_run(e, "hsrc", ["stage-restore", "--sha256", sha], blob,
                          {"WEBTERM_MASTER_KEY_FILE": kf})
    check("stage-restore fără parolă → exit 3", rc == hostops.EXIT_REFUSED and "PASSPHRASE" in out, out)
    rc, out = hostops_run(e, "hsrc", ["stage-restore", "--sha256", sha], blob, kenv)
    check("stage-restore → exit 0, set în staging", rc == 0 and "staged: protected" in out, out)
    # §12.10.1: arhiva host e WTBK2 (în flux); WTBK1(WTS1) al rc-urilor anterioare rămâne restaurabil
    check("hostops backup scrie WTBK2", blob[:5] == hostops.WTBK2_MAGIC == b"WTBK2", blob[:8])
    rc, out = hostops_run(e, "hsrc", ["estimate"], b"", kenv)
    est = int(out.split("estimate: ")[1].split()[0]) if "estimate: " in out else -1
    check("hostops estimate → o margine superioară (≥ DB-ul volumului)",
          rc == 0 and est >= os.path.getsize(os.path.join(d, "webterm.db")), out)
    w1 = backup.encrypt(backup.decrypt(blob, PASS), PASS)
    s1 = hashlib.sha256(w1).hexdigest()
    rc1, out1 = hostops_run(e, "hsrc", ["verify", "--sha256", s1], w1, kenv)
    rc2, out2 = hostops_run(e, "hsrc", ["stage-restore", "--sha256", s1], w1, kenv)
    check("WTBK1(WTS1) (arhivă host 3.8-rc) → verify şi stage-restore tot exit 0",
          rc1 == 0 and rc2 == 0 and "staged: protected" in out2, (out1, out2))
    mid = len(blob) // 2
    bad = {"trunchiată (ultimul octet)": blob[:-1], "un octet inversat la mijloc": blob[:mid] + bytes([blob[mid] ^ 1]) + blob[mid + 1:],
           "antet alterat (unpacked_len)": blob[:44] + bytes([blob[44] ^ 1]) + blob[45:],
           "un chunk în plus": blob + blob[-100:], "doar o parte din antet": blob[:60]}
    res = {}
    for name, b_ in bad.items():
        sb = hashlib.sha256(b_).hexdigest()
        before = data_tree(d)
        rv, ov = hostops_run(e, "hsrc", ["verify", "--sha256", sb], b_, kenv)
        rs, os_ = hostops_run(e, "hsrc", ["stage-restore", "--sha256", sb], b_, kenv)
        res[name] = (rv, rs, data_tree(d) == before)
    check("WTBK2 alterat → verify şi stage-restore exit 3, volumul identic",
          all(v == (hostops.EXIT_REFUSED, hostops.EXIT_REFUSED, True) for v in res.values()), res)
    before = data_tree(d)
    rs, os_ = hostops_run(e, "hsrc", ["stage-restore", "--sha256", sha], blob,
                          {"WEBTERM_MASTER_KEY_FILE": kf, "WEBTERM_BACKUP_PASSPHRASE": "alta-parola"})
    check("WTBK2 cu parola greşită → exit 3 înaintea oricărei scrieri", rs == hostops.EXIT_REFUSED
          and "wrong passphrase" in os_ and data_tree(d) == before, os_)
    check("hostops.WTBK_MAGIC e antetul real al backup.encrypt", backup.encrypt(b"x", "p")[:5] == hostops.WTBK_MAGIC)
    check("R-M1: codurile de ieşire sunt distincte (0 commit, 3 refuz, 4 incert)",
          (hostops.EXIT_OK, hostops.EXIT_REFUSED, hostops.EXIT_UNCERTAIN) == (0, 3, 4))
    # R-H1: backup.sh şi restore.sh iau lacătul de lifecycle al instalării (cel al deploy.sh)
    import fcntl
    fd = os.open(os.path.join(e.base, ".deploy.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        e.app("hsrc", ["WEBTERM_MASTER_KEY_FILE=" + kf])
        rc1, out1 = backup_run(e, "hsrc")
        rc2, out2 = restore(e, os.path.join(e.base, "nu-exista.wtbk"), "hsrc", PE)
    finally:
        os.close(fd)
    check("R-H1: backup.sh / restore.sh cât un deploy ţine .deploy.lock → refuz, niciun docker",
          rc1 != 0 and "another deploy" in out1 and rc2 != 0 and "another deploy" in out2
          and "docker" not in e.calls(), (out1[-300:], out2[-300:]))


def test_rcm1(e):
    """RC-M1: o singură conductă legacy — ruta după formatul INTERIOR şi politica ţintei, acelaşi
    verdict la verify şi la stage (deci înainte de orice oprire), acelaşi extractor strict pe
    ambele ţinte, aliasurile de nume refuzate."""
    print("── RC-M1: WTBK1 with a 3.7 payload, one legacy pipeline, name aliases")
    kf = e.key_file("m1.key")
    src = legacy_volume(e, "m1src", email="m1@x")
    rdf = lambda n: open(os.path.join(src, n), "rb").read()  # noqa: E731
    base = [("webterm.db", rdf("webterm.db")), ("secret", rdf("secret")),
            ("agent-signing.key", rdf("agent-signing.key")), ("agent-signing.pub", rdf("agent-signing.pub")),
            ("transcripts/s1.out", b"x" * 10)]
    tgz = open(craft(os.path.join(e.base, "m1.tar.gz"), base), "rb").read()
    wtbk = backup.encrypt(tgz, PASS)
    kenv = {"WEBTERM_MASTER_KEY_FILE": kf, "WEBTERM_BACKUP_PASSPHRASE": PASS}
    lenv = {"WEBTERM_BACKUP_PASSPHRASE": PASS}
    n = [0]

    def fresh(kind):
        n[0] += 1
        name = "m1%s%d" % (kind, n[0])
        if kind == "p":
            return name, protected_volume(e, name, kf, email="tinta@x"), kenv
        return name, legacy_volume(e, name, email="tinta@x"), lenv

    def both(kind, blob, args):
        """verify şi stage pe volume proaspete identice; → [(rc, out, volum neschimbat)] pentru fiecare."""
        sha = hashlib.sha256(blob).hexdigest()
        res = []
        for cmd in ("verify", "stage-restore"):
            name, d, env = fresh(kind)
            before = data_tree(d)
            rc, out = hostops_run(e, name, [cmd, "--sha256", sha, *args], blob, env)
            # stage-ul ia întâi lacătul restore-ului (backups/.restore.lock, gol, ca .lock): nu e dată
            after = {k: v for k, v in data_tree(d).items() if k not in ("backups", "backups/.restore.lock")}
            res.append((rc, out, after == {k: v for k, v in before.items() if k not in ("backups", "backups/.restore.lock")}))
        return res

    for label, kind, blob, args, want in (
            ("WTBK1(3.7) → protejat, fără --legacy-import", "p", wtbk, (), 3),
            ("WTBK1(3.7) → protejat, cu --legacy-import", "p", wtbk, ("--legacy-import",), 0),
            ("WTBK1(3.7) → legacy, fără opţiune", "l", wtbk, (), 0),
            ("WTBK1(3.7) → legacy, cu --legacy-import", "l", wtbk, ("--legacy-import",), 3),
            ("tar.gz 3.7 → protejat, fără --legacy-import", "p", tgz, (), 3),
            ("tar.gz 3.7 → legacy, cu --legacy-import", "l", tgz, ("--legacy-import",), 3)):
        (vrc, vout, vsame), (src_, sout, ssame) = both(kind, blob, args)
        check(f"RC-M1: {label}: verify şi stage dau acelaşi verdict ({want})",
              vrc == want and src_ == want and vsame and (ssame if want else True), (vrc, vout[-300:], src_, sout[-300:]))
        if want == 3:
            check(f"RC-M1: {label}: refuzul stage-ului lasă volumul identic", ssame, sout[-300:])
        if want == 0 and kind == "p":
            check(f"RC-M1: {label}: ruta e importul legacy la ambele",
                  "archive: legacy-import" in vout and "staged: legacy-import" in sout, (vout, sout))
        if want == 0 and kind == "l":
            check(f"RC-M1: {label}: ruta e restore-ul legacy la ambele", "staged: legacy" in sout, sout)
    # prin restore.sh: refuzul vine de la verify, deci înainte de oprirea app-ului
    name, d, _env = fresh("p")
    path = os.path.join(e.base, "m1.wtbk")
    open(path, "wb").write(wtbk)
    e.app(name, ["WEBTERM_MASTER_KEY_FILE=" + kf])
    before = data_tree(d)
    rc, out = restore(e, path, name, PE)
    check("RC-M1: restore.sh WTBK1(3.7) pe volum protejat fără --legacy-import → refuz ÎNAINTE de oprire",
          rc != 0 and "--legacy-import" in out and "stop " not in e.calls() and data_tree(d) == before, out[-400:])
    rc, out = restore(e, path, name, PE, args=("--legacy-import",))
    check("RC-M1: …cu --legacy-import → pus în staging (import legacy)", rc == 0 and "legacy-import" in out, out[-400:])
    mode, email, _applied = boot_check(d, {"WEBTERM_MASTER_KEY_FILE": kf})
    check("RC-M1: …boot-ul: protected, datele arhivei 3.7", mode == "protected" and email == "m1@x", (mode, email))

    # aliasuri de nume: refuzate de extractorul strict la verify ŞI la stage, pe ambele ţinte
    db = rdf("webterm.db")
    for label, members in (
            ("./webterm.db + webterm.db", [("./webterm.db", b"x" * 64)] + base),
            ("./webterm.db singur", [("./webterm.db", db)] + base[1:]),
            ("transcripts//s1.out", base[:4] + [("transcripts//s1.out", b"y")]),
            ("transcripts/./s1.out", base[:4] + [("transcripts/./s1.out", b"y")]),
            ("transcripts/../webterm.db", base + [("transcripts/../webterm.db", b"z")]),
            ("/webterm.db absolut", base + [("/webterm.db", b"z")]),
            ("coliziune de majuscule", base + [("transcripts/S1.out", b"y")]),
            ("webterm.db dublat", base + [("webterm.db", b"z")])):
        raw = open(craft(os.path.join(e.base, "alias.tar.gz"), members), "rb").read()
        for kind, args in (("l", ()), ("p", ("--legacy-import",))):
            for blob, wrap in ((raw, "tar.gz"), (backup.encrypt(raw, PASS), "WTBK1")):
                (vrc, vout, vsame), (src_, sout, ssame) = both(kind, blob, args)
                check(f"RC-M1: alias {label} ({wrap} → {'protejat' if kind == 'p' else 'legacy'}) → refuz la verify şi stage, volum identic",
                      vrc == 3 and src_ == 3 and vsame and ssame, (vout[-200:], sout[-200:]))
    # extractorul strict direct: aliasul de majuscule şi duplicatul
    for label, members in (("majuscule", base + [("transcripts/S1.out", b"y")]),
                           ("./ + simplu", [("./webterm.db", db)] + base)):
        raw = open(craft(os.path.join(e.base, "alias2.tar.gz"), members), "rb").read()
        td = tempfile.mkdtemp(prefix="wt-rcm1-")
        try:
            backup._extract_legacy_strict(raw, td)
            check(f"RC-M1: _extract_legacy_strict refuză {label}", False, "acceptat")
        except ValueError as ex:
            check(f"RC-M1: _extract_legacy_strict refuză {label}", True, str(ex))
        finally:
            shutil.rmtree(td, ignore_errors=True)


# Un volum protejat cu înregistrări criptate (WTX1) şi jurnal de ştergeri, făcut cu Store-ul real (ca
# txbackup_test), apoi arhiva lui WTBK2 scrisă de hostops._local_snapshot. `bad`: manifestul arhivei
# (autentic, semnat de writer) numeşte o înregistrare inclusă drept `legacy` — metadate nepotrivite cu DB-ul.
TRACKED_FIXTURE = r'''
import asyncio, json, os, sqlite3, sys, time
from pathlib import Path
d, kf, out_good, out_bad, pw = sys.argv[1:6]
from app import backup, config, db, hostops, keys
from app import erasure as er
from app import txstore as ts
res = keys.boot(d, {"WEBTERM_MASTER_KEY_FILE": kf})
ring, mk = res.keyring, res.master_key
res.lock.release()
hostops._point_at(d)
os.makedirs(config.ARCHIVE_DIR, exist_ok=True)
con = sqlite3.connect(str(config.DB_PATH))
con.executescript(db.SCHEMA)
for m in db.MIGRATIONS:
    try:
        con.execute(m)
    except sqlite3.OperationalError:
        pass
con.commit()
con.close()
ts.create_test_volume(config.DB_PATH)
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
priv = Ed25519PrivateKey.generate()
open(os.path.join(d, "agent-signing.key"), "wb").write(
    priv.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
open(os.path.join(d, "agent-signing.pub"), "wb").write(
    (priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex() + "\n").encode())


async def rec():
    st = ts.Store(transcripts_dir=config.TRANSCRIPT_DIR, kwk=ring.kwk, installation_id=ring.installation_id,
                  gen_limits=(2, 1 << 20))
    await er.boot(st)
    await st.recover()
    sid = os.urandom(16).hex()
    c = sqlite3.connect(str(config.DB_PATH), isolation_level=None)
    c.execute("INSERT INTO sessions(id, host_id, title, state, created, rows, cols) VALUES(?,?,?,?,?,?,?)",
              (sid, 1, "t", "live", time.time(), 24, 80))
    r = await st.start_recorder(sid, track_agent=False)
    r.feed_cast_only(b'{"version": 2, "width": 80, "height": 24}\n', at=r.received)
    for i in range(3):
        o = os.urandom(200)
        r.feed(o, json.dumps([0.1 * i, "o", o.hex()[:20]]).encode() + b"\n", at=r.received)
        await r.checkpoint()
    await r.close()
    c.execute("UPDATE sessions SET state='closed', closed_at=? WHERE id=?", (time.time(), sid))
    c.close()
    await st.shutdown()
    st.close()
    er.reset()

asyncio.run(rec())
hk = backup.HostKeys(ring, mk)
backup.set_boot_protected(True)
backup.set_host_keys_provider(lambda: hk)
with open(out_good, "wb") as f:
    hostops._local_snapshot(hk, pw, True, f)
orig = backup._emit_recordings


def lying(t, snap, dropped):
    recs = orig(t, snap, dropped)
    for r in recs:
        if r["state"] == "included":
            r["state"] = "legacy"
            break
    return recs

backup._emit_recordings = lying
with open(out_bad, "wb") as f:
    hostops._local_snapshot(hk, pw, True, f)
print("tracked-fixture-ok")
'''


def tracked_archives(e, kf):
    """(good.wtbk, bad.wtbk) of a tracked protected volume made under key `kf`."""
    d = e.vol("trksrc")
    os.makedirs(d)
    os.chmod(d, 0o700)                          # volumul de test al Store-ului: un director privat
    good, bad = os.path.join(e.base, "tracked.wtbk"), os.path.join(e.base, "tracked-bad.wtbk")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("WEBTERM_", "WT_"))}
    env.update(PYTHONPATH=GATEWAY, WEBTERM_DATA_DIR=d, WEBTERM_TX_RECORDINGS="1", WEBTERM_TEST_GATE="1",
               WEBTERM_PUBLIC_URL="http://127.0.0.1:8000")
    p = subprocess.run([sys.executable, "-c", TRACKED_FIXTURE, d, kf, good, bad, PASS], env=env,
                       capture_output=True, text=True, timeout=180)
    assert "tracked-fixture-ok" in p.stdout, p.stdout[-1500:] + p.stderr[-3000:]
    return good, bad


def test_m1(e):
    """Codex M1: verify = the staging's acceptance (target policy, recording membership, journal),
    so restore.sh refuses BEFORE it stops the app what the staging would refuse."""
    print("── Codex M1: verify runs the staging's recording / erasure acceptance")
    kf = e.key_file("m1trk.key")
    good, bad = tracked_archives(e, kf)
    tx_on = ["WEBTERM_MASTER_KEY_FILE=" + kf, "WEBTERM_TX_RECORDINGS=1"]
    # controlul pozitiv: o ţintă cu înregistrările criptate active acceptă arhiva bună
    protected_volume(e, "m1on", kf, email="tinta@x")
    e.app("m1on", tx_on)
    rc, out = restore(e, good, "m1on", PE, args=("--verify",))
    check("M1: tracked WTBK2 → flag-on target: verify passes (control)", rc == 0 and "restore test OK" in out,
          out[-600:])
    # ţinta fără flag: staging-ul ar refuza (_erasure_stage) → verify refuză, app-ul nu e oprit
    t_off = protected_volume(e, "m1off", kf, email="tinta@x")
    e.app("m1off", ["WEBTERM_MASTER_KEY_FILE=" + kf])
    before = data_tree(t_off)
    rc, out = restore(e, good, "m1off", PE)
    calls = e.calls()
    check("M1: valid tracked WTBK2 → flag-off target: refused at verify, the app never stopped",
          rc != 0 and "encrypted recordings" in out and "not confirmed restorable" in out
          and "stop " not in calls and data_tree(t_off) == before, out[-600:] + calls)
    rc, out = restore(e, good, "m1off", PE, args=("--verify",))
    check("M1: …and the restore test (--verify) fails too", rc != 0 and "restore test OK" not in out, out[-400:])
    # metadate nepotrivite (manifest autentic, dar o înregistrare cu descriptor listată `legacy`)
    t_bad = protected_volume(e, "m1bad", kf, email="tinta@x")
    e.app("m1bad", tx_on)
    before = data_tree(t_bad)
    rc, out = restore(e, bad, "m1bad", PE)
    check("M1: mismatched recording metadata → refused at verify, the app never stopped",
          rc != 0 and "listed as legacy" in out and "stop " not in e.calls() and data_tree(t_bad) == before,
          out[-600:] + e.calls())
    # aceeaşi arhivă direct la stage: acelaşi verdict (refuz) — verify şi stage nu se mai despart
    sha = hashlib.sha256(open(bad, "rb").read()).hexdigest()
    rc, out = hostops_run(e, "m1bad", ["stage-restore", "--sha256", sha], open(bad, "rb").read(),
                          {"WEBTERM_MASTER_KEY_FILE": kf, "WEBTERM_TX_RECORDINGS": "1",
                           "WEBTERM_BACKUP_PASSPHRASE": PASS})
    check("M1: …stage-restore refuses it the same way (exit 3, nothing staged)",
          rc == hostops.EXIT_REFUSED and "listed as legacy" in out and data_tree(t_bad) == before, out[-400:])


GIB = 1 << 30


def work_empty(d):
    wd = os.path.join(d, "backups", ".work")
    return not os.path.isdir(wd) or os.listdir(wd) == []


def fake_space(total, free, fd_free=None, keep_drop=None):
    """statvfs / fstatvfs replaced (in this process): a filesystem of `total` bytes with `free`
    available; `fd_free` = what fstatvfs (the metered writers) sees; `keep_drop` = (dir, bytes):
    once a pre-restore safety copy exists in `dir`, `free` drops by `bytes`."""
    real_s, real_f = os.statvfs, os.fstatvfs

    def mk(avail):
        avail = max(0, avail)
        return os.statvfs_result((4096, 4096, total // 4096, avail // 4096, avail // 4096, 1 << 20,
                                  1 << 20, 1 << 20, 0, 255))

    def cur():
        if keep_drop and any(n.startswith("pre-restore-") for n in os.listdir(keep_drop[0])):
            return free - keep_drop[1]
        return free

    def st(p):
        return mk(cur())

    def fst(fd):
        return mk(cur() if fd_free is None else fd_free)

    os.statvfs, os.fstatvfs = st, fst
    return lambda: (setattr(os, "statvfs", real_s), setattr(os, "fstatvfs", real_f))


def hostops_pre(e, vol, args, stdin, env_extra, pre):
    """hostops in a subprocess with `pre` (Python source) run first — the statvfs fakes."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("WEBTERM_", "WT_"))}
    env.update(PYTHONPATH=GATEWAY, WEBTERM_DATA_DIR=e.vol(vol), **(env_extra or {}))
    code = pre + "\nimport sys\nfrom app import hostops\nsys.exit(hostops.main(sys.argv[1:]))\n"
    p = subprocess.run([sys.executable, "-c", code, *args], input=stdin, env=env, capture_output=True, timeout=120)
    return p.returncode, p.stdout.decode(errors="replace") + p.stderr.decode(errors="replace")


FAKE_PRE = r'''
import os
_T, _F, _FD = %d, %d, %r
def _mk(a):
    a = max(0, a)
    return os.statvfs_result((4096, 4096, _T // 4096, a // 4096, a // 4096, 1 << 20, 1 << 20, 1 << 20, 0, 255))
os.statvfs = lambda p: _mk(_F)
os.fstatvfs = lambda fd: _mk(_F if _FD is None else _FD)
'''


def _with_env(env):
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)

    def undo():
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return undo


def _open_volume(d, kf):
    """In-process: config at `d`, its keys opened like hostops (→ hk, undo)."""
    undo = _with_env({"WEBTERM_MASTER_KEY_FILE": kf})
    hostops._point_at(d)
    view = hostops._DirView(d)
    try:
        inv = hostops._inventory(view)
        hk, _r = hostops._open_keys(view, inv)
    finally:
        view.release()
    return hk, undo


def test_m2(e):
    """Codex M2: space accounted per filesystem and phase, a hard write budget with a reserve for
    the gateway, a recheck at boot before `applying` (statvfs faked)."""
    print("── Codex M2: disk budget of host backup / restore")
    kf = e.key_file("m2.key")
    d = protected_volume(e, "m2src", kf, email="m2@x")
    hk, undo_env = _open_volume(d, kf)
    try:
        dbn, est = backup.db_size(), backup.host_estimate()
        keep = 5 * GIB                                  # 5 % din 100 GiB
        # DB mare: copia de lucru încape, copia DB-ului (snapshot / verificare) care coexistă cu ea nu
        restore_fs = fake_space(100 * GIB, est + keep + dbn // 2)
        try:
            out = io.BytesIO()
            try:
                hostops._local_snapshot(hk, PASS, True, out)
                r = "written"
            except hostops.Refused as ex:
                r = str(ex)
        finally:
            restore_fs()
        check("M2: large DB — work copy + DB copy + reserve counted: refused before writing",
              "database copy" in r and "kept free for the gateway" in r and out.getvalue() == b""
              and work_empty(d), r)
        # bugetul dur: estimarea trece, dar scrierea ar coborî sub rezervă → oprit, directorul de lucru gol
        restore_fs = fake_space(100 * GIB, 50 * GIB, fd_free=keep + (1 << 20))
        try:
            out = io.BytesIO()
            try:
                hostops._local_snapshot(hk, PASS, True, out)
                r = "written"
            except (OSError, ValueError) as ex:
                r = "%s: %s" % (type(ex).__name__, ex)
        finally:
            restore_fs()
        check("M2: hard budget — the writer stops at the reserve (NoSpace) and cleans its work dir",
              r.startswith("NoSpace") and "reserve for the gateway" in r and out.getvalue() == b""
              and work_empty(d), r)
        # fără fake: backup-ul trece (controlul)
        out = io.BytesIO()
        hostops._local_snapshot(hk, PASS, True, out)
        blob = out.getvalue()
        check("M2: …and with room the same backup is written", blob[:5] == b"WTBK2")
    finally:
        undo_env()
    sha = hashlib.sha256(blob).hexdigest()
    kenv = {"WEBTERM_MASTER_KEY_FILE": kf, "WEBTERM_BACKUP_PASSPHRASE": PASS}
    # verify: scratch-ul (DB-ul extras) e contorizat la fel
    rc, out = hostops_pre(e, "m2src", ["verify", "--sha256", sha], blob, kenv,
                          FAKE_PRE % (100 * GIB, 50 * GIB, keep + (1 << 20)))
    check("M2: verify's scratch is metered too → refused at the reserve, nothing left",
          rc == hostops.EXIT_REFUSED and "reserve for the gateway" in out and work_empty(d), out[-400:])

    # restore mic peste un set de date mare: copia de siguranţă a datelor curente intră în socoteală
    tgt = protected_volume(e, "m2big", kf, email="mare@x")
    big = os.path.join(tgt, "transcripts", "big.out")
    with open(big, "wb") as f:
        f.truncate(3 * GIB)                             # rar (sparse): 3 GiB pentru lstat, ~0 pe disc
    e.app("m2big", ["WEBTERM_MASTER_KEY_FILE=" + kf])
    path = os.path.join(e.base, "m2.wtbk")
    open(path, "wb").write(blob)
    before = data_tree(tgt)
    # 2 GiB peste rezervă: regula veche (2 × unpacked + 64 MiB) trecea; copia de siguranţă (3 GiB) nu încape
    e.put("hostops_pre", FAKE_PRE % (100 * GIB, keep + 2 * GIB, None))
    try:
        rc, out = restore(e, path, "m2big", PE)
        calls = e.calls()
        rc_v, out_v = restore(e, path, "m2big", PE, args=("--verify",))
    finally:
        e.put("hostops_pre", None)
    check("M2: small restore replacing a large dataset → refused at verify, the app never stopped",
          rc != 0 and "safety copy of the current data" in out and "stop " not in calls
          and data_tree(tgt) == before, out[-600:] + calls)
    check("M2: …the restore TEST only notes it (the archive itself is fine)",
          rc_v == 0 and "a restore would be refused until space is freed" in out_v, out_v[-500:])
    rc, out = hostops_pre(e, "m2big", ["stage-restore", "--sha256", sha], blob, kenv,
                          FAKE_PRE % (100 * GIB, keep + 2 * GIB, None))
    check("M2: …stage-restore applies the same rule (exit 3, nothing staged)",
          rc == hostops.EXIT_REFUSED and "safety copy" in out and data_tree(tgt) == before, out[-400:])
    os.unlink(big)

    # boot: recheck înainte de `applying` — un set în staging, apoi discul s-a umplut
    rc, out = hostops_run(e, "m2big", ["stage-restore", "--sha256", sha], blob, kenv)
    check("M2: staged with room", rc == 0, out[-300:])
    kdir = os.path.join(tgt, "backups")
    email0 = sqlite3.connect(os.path.join(tgt, "webterm.db")).execute("SELECT email FROM users").fetchone()[0]
    restore_fs = fake_space(100 * GIB, 1 << 20)
    try:
        mode, _email, _a = boot_check(tgt, {"WEBTERM_MASTER_KEY_FILE": kf})
    finally:
        restore_fs()
    email1 = sqlite3.connect(os.path.join(tgt, "webterm.db")).execute("SELECT email FROM users").fetchone()[0]
    flag = open(os.path.join(tgt, ".restore-flag"), "rb").read() if os.path.exists(os.path.join(tgt, ".restore-flag")) else b""
    check("M2: boot with too little space → refused before `applying`, old data kept, nothing copied",
          str(mode).startswith("refused") and "nothing was changed" in str(mode) and email1 == email0
          and b'"staged"' in flag and not any(n.startswith("pre-restore-") for n in os.listdir(kdir)),
          (mode, email1, flag[:200]))
    # copia de siguranţă încape, dar după ea nu mai e loc pentru copia setului → copia ştearsă, refuz
    restore_fs = fake_space(100 * GIB, 40 * GIB, keep_drop=(kdir, 40 * GIB - (1 << 20)))
    try:
        mode, _email, _a = boot_check(tgt, {"WEBTERM_MASTER_KEY_FILE": kf})
    finally:
        restore_fs()
    flag = open(os.path.join(tgt, ".restore-flag"), "rb").read() if os.path.exists(os.path.join(tgt, ".restore-flag")) else b""
    check("M2: no room left after the safety copy → refused, the safety copy removed, still `staged`",
          str(mode).startswith("refused") and b'"staged"' in flag
          and not any(n.startswith("pre-restore-") for n in os.listdir(kdir)), (mode, os.listdir(kdir)))
    mode, email, _a = boot_check(tgt, {"WEBTERM_MASTER_KEY_FILE": kf})
    check("M2: …with room the boot applies it", mode == "protected" and email == "m2@x", (mode, email))

    # backup.sh: destinaţia pe ACELAŞI sistem de fişiere cu volumul → arhiva + copia de lucru + rezerva
    e.app("m2src", ["WEBTERM_MASTER_KEY_FILE=" + kf], running=False)
    e.put("df_avail", str(backup.host_estimate() + (64 << 20)))
    try:
        rc, out = backup_run(e, "m2src", PE)
    finally:
        e.put("df_avail", None)
    check("M2: backup.sh — destination shares the volume's filesystem → its work copy and reserve "
          "are counted, refused before writing", rc != 0 and "same filesystem" in out
          and not (os.path.isdir(e.out) and os.listdir(e.out)), out[-500:])


def main():
    global FOREIGN_DB
    FOREIGN_DB = _foreign_db()
    # 3.8 (repetiţia e2e a activării): containerul nou în care rulează codul gateway-ului (backup
    # offline, staging-ul restore-ului) primeşte ACELAŞI flag de înregistrări criptate ca app-ul;
    # fără el, restore.sh refuza orice arhivă cu înregistrări WTX1 / jurnal de ştergeri
    for sc in ("backup.sh", "restore.sh"):
        src = open(os.path.join(REPO, "scripts", sc)).read()
        check("%s: the tool container gets the app's WEBTERM_TX_RECORDINGS" % sc,
              "sed -n 's/^WEBTERM_TX_RECORDINGS=//p'" in src
              and 'KEY_ARGS+=(-e "WEBTERM_TX_RECORDINGS=$tx")' in src)
    e = Env()
    try:
        test_backup(e)
        test_restore(e)
        test_hostops(e)
        test_rcm1(e)
        test_m1(e)
        test_m2(e)
    finally:
        shutil.rmtree(e.base, ignore_errors=True)
        shutil.rmtree(_BOOT_DIR, ignore_errors=True)
    print(f"\n{ok}/{total} passed")
    raise SystemExit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
