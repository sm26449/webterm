"""3.6.9 — the portable Python for agent hosts with a missing or < 3.6 python3.

Two layers, both must refuse a wrong file:
  * gateway (pyruntime.py + GET /agent/python/{target}): pinned manifest only, SHA-256 verified
    BEFORE caching (a mismatch is never cached, never served), size cap, https + allow-listed
    redirects, a free-space check, a cached file re-hashed before first serve, the HOST's agent
    token required;
  * host (the install script): the expected SHA-256 embedded from the same manifest, the archive
    listed before extraction (absolute paths, `..`, links escaping python/, odd entry types refused),
    an unknown architecture or too-old glibc refused, the agent token never on a command line.
Hermetic: fake openers instead of the network, the install script run by /bin/sh with fake
`curl`/`uname`/`getconf` and tiny hand-made tarballs (no 30 MB download).
"""
import asyncio
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rbac_util as U  # noqa: E402
from app import api, db, pyruntime, security  # noqa: E402
import importlib  # noqa: E402
gw_main = importlib.import_module("app.main")  # the module (app.main is shadowed by a function)

check = U.Checker()
SP = Path(tempfile.mkdtemp(prefix="pyrt-test-"))


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOpener:
    def __init__(self, data: bytes):
        self.data = data
        self.urls = []

    def open(self, req, timeout=None):
        self.urls.append(req.full_url)
        return FakeResp(self.data)


def manifest_checks():
    print("── the pinned manifest")
    m = pyruntime.MANIFEST
    want = {"x86_64-gnu", "aarch64-gnu", "armv7-gnueabihf", "x86_64-musl", "aarch64-musl"}
    check("five pinned targets", set(m["targets"]) == want, sorted(m["targets"]))
    check("every target has a 64-hex SHA-256 and a size",
          all(len(t["sha256"]) == 64 and t["size"] > 1_000_000 for t in m["targets"].values()))
    check("base URL is the pinned release on github.com",
          m["base_url"].startswith("https://github.com/astral-sh/python-build-standalone/releases/download/"))
    bad = SP / "bad.json"
    bad.write_text(json.dumps({"base_url": "http://evil/", "targets": {"x": {}}}))
    check("a manifest with a non-https/non-github base is ignored (no targets)",
          pyruntime.load_manifest(bad)["targets"] == {})
    bad.write_text(json.dumps({"base_url": "https://github.com/x/", "targets": {
        "x86_64-gnu": {"file": "../../etc/passwd", "sha256": "0" * 64, "size": 5},
        "aarch64-gnu": {"file": pyruntime.MANIFEST["targets"]["aarch64-gnu"]["file"], "sha256": "nothex", "size": 5}}}))
    check("malformed entries (path in file, bad hash) are dropped", pyruntime.load_manifest(bad)["targets"] == {})
    check("unknown target → None", pyruntime.target("mips-gnu") is None and pyruntime.target("../x") is None)


def download_checks():
    print("── gateway download: verify before caching")
    data = b"pretend tarball " * 1000
    sha = hashlib.sha256(data).hexdigest()
    dest = SP / "cache" / "f.tar.gz"
    pyruntime.download_verified("https://github.com/x/f", dest, sha, len(data), opener=FakeOpener(data))
    check("good bytes → cached", dest.exists() and dest.read_bytes() == data)
    dest.unlink()
    for got, why in ((data[:-1] + b"X", "wrong hash"), (data + b"more", "larger than pinned"),
                     (data[:-10], "shorter than pinned")):
        try:
            pyruntime.download_verified("https://github.com/x/f", dest, sha, len(data), opener=FakeOpener(got))
            ok = False
        except pyruntime.RuntimeUnavailable:
            ok = True
        leftovers = list((SP / "cache").iterdir())
        check("refused + nothing cached: " + why, ok and not dest.exists() and not leftovers, leftovers)
    try:
        pyruntime.download_verified("http://github.com/x/f", dest, sha, len(data), opener=FakeOpener(data))
        check("plain http refused", False)
    except pyruntime.RuntimeUnavailable:
        check("plain http refused", True)
    # review L3: bounded inside the worker thread, temp from mkstemp, timeouts are 503 codes
    seen = []

    class Drip:
        """A server that sends one byte per read, forever (each recv well under READ_TIMEOUT)."""
        def __init__(self, stop_after=None, ev=None):
            self.n, self.stop_after, self.ev = 0, stop_after, ev

        def open(self, req, timeout=None):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def read1(self, n):
            seen.extend((p.name, p.stat().st_mode & 0o777) for p in (SP / "cache").iterdir()
                        if p.name.startswith(".f.tar.gz.part."))
            self.n += 1
            if self.stop_after and self.n == self.stop_after:
                self.ev.set()
            time.sleep(0.01)
            return b"x"

    t0 = time.monotonic()
    try:
        pyruntime.download_verified("https://github.com/x/f", dest, sha, len(data), opener=Drip(), deadline=0.3)
        code = None
    except pyruntime.RuntimeUnavailable as e:
        code = e.code
    check("slow drip (1 byte per read): the total deadline holds inside the thread → pyruntime.timeout",
          code == "pyruntime.timeout" and time.monotonic() - t0 < 5 and not list((SP / "cache").iterdir()),
          (code, time.monotonic() - t0))
    check("the temp file comes from mkstemp (random name, mode 0600), next to the cache file",
          bool(seen) and all(n != ".f.tar.gz.part.%d" % os.getpid() and m == 0o600 for n, m in seen), seen[:1])
    ev = threading.Event()
    try:
        pyruntime.download_verified("https://github.com/x/f", dest, sha, len(data), opener=Drip(5, ev),
                                    deadline=60, stop=ev)
        code = None
    except pyruntime.RuntimeUnavailable as e:
        code = e.code
    check("stop event set by the caller → the worker ends at its next read, nothing left",
          code == "pyruntime.timeout" and not list((SP / "cache").iterdir()), code)

    class SockTimeout(FakeOpener):
        def open(self, req, timeout=None):
            raise socket.timeout("timed out")
    try:
        pyruntime.download_verified("https://github.com/x/f", dest, sha, len(data), opener=SockTimeout(b""))
        code = None
    except pyruntime.RuntimeUnavailable as e:
        code = e.code
    check("a socket timeout → pyruntime.timeout (a 503 code, not a 500)", code == "pyruntime.timeout", code)

    h = pyruntime._PinnedRedirects()
    try:
        h.redirect_request(None, None, 302, "", {}, "https://evil.example/x")
        check("redirect to a non-GitHub host refused", False)
    except pyruntime.RuntimeUnavailable:
        check("redirect to a non-GitHub host refused", True)
    try:
        h.redirect_request(None, None, 302, "", {}, "http://objects.githubusercontent.com/x")
        check("redirect to http (not https) refused", False)
    except pyruntime.RuntimeUnavailable:
        check("redirect to http (not https) refused", True)


async def route_checks():
    print("── GET /agent/python/{target}")
    await U.boot()
    owner = await U.owner_client()
    hid = await U.add_host(owner, "mailer")
    token = "agent-token-for-test"
    await db.execute("UPDATE hosts SET token_hash=? WHERE id=?", security.sha256_hex(token), hid)
    c = U.client()
    key = "x86_64-gnu"
    t = pyruntime.MANIFEST["targets"][key]
    r = await c.get("/agent/python/%s.tar.gz" % key)
    check("no token → 401", r.status_code == 401, r.status_code)
    r = await c.get("/agent/python/%s.tar.gz" % key, headers={"Authorization": "Bearer wrong"})
    check("wrong token → 401", r.status_code == 401, r.status_code)
    auth = {"Authorization": "Bearer " + token}
    r = await c.get("/agent/python/mips-gnu.tar.gz", headers=auth)
    check("unknown target → 404 pyruntime.unknownTarget",
          r.status_code == 404 and r.headers.get("x-webterm-error") == "pyruntime.unknownTarget", r.status_code)
    r = await c.get("/agent/python/..%2F..%2Fetc%2Fpasswd", headers=auth)
    check("a path as target → 404", r.status_code == 404, r.status_code)
    r = await c.get("/agent/nope", headers=auth)
    check("an unknown /agent/* path → 404", r.status_code == 404, r.status_code)
    # the SPA catch-all exists only when the UI is built; its rule is checked directly (review L5)
    check("SPA catch-all: /api/* and /agent/* are reserved (404), the UI's own paths are not",
          all(gw_main.spa_reserved(p) for p in ("api", "api/x", "agent", "agent/python/../../etc/passwd", "/agent/x"))
          and not any(gw_main.spa_reserved(p) for p in ("", "agents", "apix", "settings/agent", "hosts/1")))

    # small pinned entry for the test (the real ones are 30 MB): swap the manifest in place
    data = b"\x1f\x8b fake runtime " * 4000
    saved = dict(pyruntime.MANIFEST["targets"])
    pyruntime.MANIFEST["targets"][key] = {"file": t["file"], "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    real_get = pyruntime.get
    real_free = pyruntime._free_bytes
    cache = pyruntime.cache_dir()
    try:
        # disk bound
        pyruntime._free_bytes = lambda p: len(data) + pyruntime.FREE_MARGIN - 1
        r = await c.get("/agent/python/%s.tar.gz" % key, headers=auth)
        check("not enough free space → 503 pyruntime.noSpace, nothing downloaded",
              r.status_code == 503 and r.headers.get("x-webterm-error") == "pyruntime.noSpace"
              and not (cache / t["file"]).exists(), (r.status_code, r.headers.get("x-webterm-error")))
        pyruntime._free_bytes = real_free
        # mismatching upstream → 503, never cached
        bad = FakeOpener(data[:-1] + b"!")
        pyruntime.get = lambda k, opener=None: real_get(k, opener=bad)
        r = await c.get("/agent/python/%s.tar.gz" % key, headers=auth)
        check("upstream bytes with the wrong hash → 503 pyruntime.badHash, not cached",
              r.status_code == 503 and r.headers.get("x-webterm-error") == "pyruntime.badHash"
              and not (cache / t["file"]).exists(), (r.status_code, r.headers.get("x-webterm-error")))
        # good upstream → served, cached, header carries the hash
        good = FakeOpener(data)
        pyruntime.get = lambda k, opener=None: real_get(k, opener=good)
        r = await c.get("/agent/python/%s.tar.gz" % key, headers=auth)
        check("good upstream → 200, the exact bytes, X-Checksum-Sha256",
              r.status_code == 200 and r.content == data
              and r.headers.get("x-checksum-sha256") == hashlib.sha256(data).hexdigest(), r.status_code)
        check("…fetched from the pinned URL (+ encoded)",
              good.urls == [pyruntime.MANIFEST["base_url"] + t["file"].replace("+", "%2B")], good.urls)
        r = await c.get("/agent/python/%s.tar.gz" % key, headers=auth)
        check("second request served from the cache (no new download)", r.status_code == 200 and len(good.urls) == 1)
        # a cached file changed on disk → deleted, re-fetched (here: upstream now bad → 503, not served)
        (cache / t["file"]).write_bytes(b"tampered")
        pyruntime._verified.clear()
        pyruntime.get = lambda k, opener=None: real_get(k, opener=bad)
        r = await c.get("/agent/python/%s.tar.gz" % key, headers=auth)
        check("tampered cache → never served (re-hash on first serve)",
              r.status_code == 503 and not (cache / t["file"]).exists(), r.status_code)
        # verified in this process, then replaced by same-size bytes: identity changed → re-hashed
        pyruntime.get = lambda k, opener=None: real_get(k, opener=good)
        r = await c.get("/agent/python/%s.tar.gz" % key, headers=auth)
        swapped = cache / (".swap")
        swapped.write_bytes(data[:-1] + b"!")
        os.replace(swapped, cache / t["file"])
        pyruntime.get = lambda k, opener=None: real_get(k, opener=bad)
        r = await c.get("/agent/python/%s.tar.gz" % key, headers=auth)
        check("verified file swapped for same-size bytes (new inode/mtime) → re-hashed, not served",
              r.status_code == 503 and not (cache / t["file"]).exists(), r.status_code)
        # the outer wait gives up (a worker stuck in one read): 503 pyruntime.timeout, not a 500;
        # the stop event ends the worker and its temp file goes away
        class Stuck(FakeOpener):
            def open(self, req, timeout=None):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def read1(self, n):
                time.sleep(0.5)
                return b"x"
        saved_t = (pyruntime.DOWNLOAD_DEADLINE, pyruntime.READ_TIMEOUT, pyruntime.OUTER_SLACK)
        pyruntime.DOWNLOAD_DEADLINE, pyruntime.READ_TIMEOUT, pyruntime.OUTER_SLACK = 60.0, 0.1, 0.0
        stuck = Stuck(b"")
        pyruntime.get = lambda k, opener=None: real_get(k, opener=stuck)
        try:
            pyruntime.DOWNLOAD_DEADLINE = 0.05     # outer wait = 0.05 + 0.1 + 0 s; inner deadline too
            r = await c.get("/agent/python/%s.tar.gz" % key, headers=auth)
        finally:
            pyruntime.DOWNLOAD_DEADLINE, pyruntime.READ_TIMEOUT, pyruntime.OUTER_SLACK = saved_t
        await asyncio.sleep(1.2)
        check("download timeout → 503 pyruntime.timeout (not 500); the worker stopped, no temp left",
              r.status_code == 503 and r.headers.get("x-webterm-error") == "pyruntime.timeout"
              and not [p for p in cache.iterdir() if p.name.startswith(".")],
              (r.status_code, r.headers.get("x-webterm-error"), list(cache.iterdir())))
        # concurrency bound
        check("bounded: at most 2 parallel downloads, one lock per target",
              pyruntime.MAX_PARALLEL == 2 and isinstance(pyruntime._locks.get(key), asyncio.Lock))
    finally:
        pyruntime.get = real_get
        pyruntime._free_bytes = real_free
        pyruntime.MANIFEST["targets"].clear()
        pyruntime.MANIFEST["targets"].update(saved)
        shutil.rmtree(cache, ignore_errors=True)
    return token


# ── the install script, host side ────────────────────────────────────────────────────────────
def make_tar(path: Path, members):
    """members: list of (name, kind, payload) with kind in file|dir|symlink|hardlink."""
    with tarfile.open(path, "w:gz") as tf:
        for m in members:
            name, kind, payload = m[:3]
            extra = m[3] if len(m) > 3 else {}
            ti = tarfile.TarInfo(name)
            ti.uid, ti.gid = extra.get("uid", 0), extra.get("uid", 0)
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = extra.get("mode", 0o755)
                tf.addfile(ti)
            elif kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tf.addfile(ti)
            elif kind == "hardlink":
                ti.type = tarfile.LNKTYPE
                ti.linkname = payload
                tf.addfile(ti)
            else:
                b = payload.encode()
                ti.size = len(b)
                ti.mode = extra.get("mode", 0o755)
                tf.addfile(ti, io.BytesIO(b))


GOOD_PY = "#!/bin/sh\ncase \"$*\" in *version_info*) exit 0 ;; *sys.version*) echo 3.12.15 ;; esac\nexit 0\n"
GOOD = [("python", "dir", ""), ("python/bin", "dir", ""), ("python/bin/python3.12", "file", GOOD_PY),
        ("python/bin/python3", "symlink", "python3.12"), ("python/share/t/a", "dir", ""),
        ("python/share/t/1", "symlink", "../t/a")]


def _shadow_path(work: Path) -> str:
    """A PATH with every tool of /usr/bin and /bin EXCEPT curl and wget (symlinks), so the script
    sees only the fake fetcher we put first."""
    sh = work / "shadow"
    sh.mkdir()
    for d in ("/usr/bin", "/bin"):
        for n in os.listdir(d):
            if n in ("curl", "wget") or (sh / n).exists():
                continue
            try:
                os.symlink(os.path.join(d, n), sh / n)
            except OSError:
                pass
    return str(sh)


FAKE_WGET = (
    "#!/bin/sh\n"
    "if [ \"$1\" = --version ]; then [ \"$WGET_KIND\" = gnu ] && echo 'GNU Wget 1.21.4 built on linux-gnu.' && exit 0;"
    " echo 'wget: unrecognized option: version' >&2; exit 1; fi\n"
    "echo \"ARGS: $*\" >> \"$LOG\"\n"
    "[ -n \"${WGETRC:-}\" ] && grep -q 'Bearer TOKEN-SECRET-123' \"$WGETRC\" && echo CFG_OK >> \"$LOG\"\n"
    "out=''; url=''\n"
    "while [ $# -gt 0 ]; do case \"$1\" in -O) out=\"$2\"; shift ;; http*) url=\"$1\" ;; esac; shift; done\n"
    "case \"$url\" in */agent/python/*) cp \"$TGZ\" \"$out\" ;; *) exit 8 ;; esac\n")


def run_installer(tgz: Path, arch="x86_64", glibc="glibc 2.23", sha=None, fetcher="curl", env_extra=None,
                  portable=True, home_mode=None):
    """Render the install script with a test manifest entry pinned to `tgz` (or `sha`), run it
    with fake curl (or GNU/BusyBox wget)/uname/getconf; return (rc, output, home, fetch log)."""
    key = "x86_64-gnu"
    data = tgz.read_bytes()
    saved = dict(pyruntime.MANIFEST["targets"])
    pyruntime.MANIFEST["targets"][key] = dict(saved[key], sha256=sha or hashlib.sha256(data).hexdigest())
    try:
        script = api._install_script_for("TOKEN-SECRET-123")
    finally:
        pyruntime.MANIFEST["targets"].clear()
        pyruntime.MANIFEST["targets"].update(saved)
    work = Path(tempfile.mkdtemp(dir=SP))
    home = work / "home"
    home.mkdir()
    bindir = work / "bin"
    bindir.mkdir()
    (work / "install.sh").write_text(script)
    if fetcher == "curl":
        (bindir / "curl").write_text(
            "#!/bin/sh\nout=''; url=''\n"
            "echo \"ARGS: $*\" >> \"$LOG\"\n"
            "while [ $# -gt 0 ]; do case \"$1\" in -o) out=\"$2\"; shift ;; -K) grep -q 'Bearer TOKEN-SECRET-123' \"$2\" && echo CFG_OK >> \"$LOG\" ;; http*) url=\"$1\" ;; esac; shift; done\n"
            "case \"$url\" in */agent/python/*) cp \"$TGZ\" \"$out\" ;; *) exit 22 ;; esac\n")
        rest = "/usr/bin:/bin"
    else:
        (bindir / "wget").write_text(FAKE_WGET)
        rest = _shadow_path(work)
    (bindir / "uname").write_text("#!/bin/sh\necho \"$FAKE_ARCH\"\n")
    (bindir / "getconf").write_text("#!/bin/sh\necho \"$FAKE_GLIBC\"\n")
    for f in bindir.iterdir():
        f.chmod(0o755)
    if home_mode is not None:
        home.chmod(home_mode)
    env = {"PATH": "%s:%s" % (bindir, rest), "HOME": str(home), "LOG": str(work / "curl.log"),
           "TGZ": str(tgz), "FAKE_ARCH": arch, "FAKE_GLIBC": glibc,
           "WGET_KIND": "gnu" if fetcher == "gnu-wget" else "busybox",
           "WEBTERM_NO_SHELL_INTEGRATION": "1"}
    if portable:
        env["WEBTERM_PORTABLE_PYTHON"] = "1"
    env.update(env_extra or {})
    r = subprocess.run(["/bin/sh", str(work / "install.sh")], env=env, capture_output=True, text=True, timeout=120)
    log = (work / "curl.log").read_text() if (work / "curl.log").exists() else ""
    return r.returncode, r.stdout + r.stderr, home, log


def installer_checks():
    print("── install script: the host side")
    good = SP / "good.tgz"
    make_tar(good, GOOD)
    rc, out, home, log = run_installer(good)
    py = home / ".webterm" / "python" / "bin" / "python3"
    check("good archive → installed in ~/.webterm/python and announced",
          py.exists() and "Python: installed 3.12.15" in out and "sha256 verified" in out, out[-600:])
    check("…then it went on to fetch the agent (stopped there by the fake)", "agent/ptyd.py" in log)
    check("the agent token is never on a command line (curl -K config file)",
          "CFG_OK" in log and "TOKEN-SECRET-123" not in log, log)
    check("no temp directory left behind", not [p for p in (home / ".webterm").iterdir() if p.name.startswith(".pyrt")])

    rc, out, home, _ = run_installer(good, sha="0" * 64)
    check("hash mismatch → refused, nothing installed",
          rc != 0 and "does not match its pinned SHA-256" in out and not (home / ".webterm" / "python").exists(), out[-300:])

    for members, why in ((GOOD + [("python/../../evil", "file", "x")], "`..` entry"),
                         (GOOD + [("/tmp/evil", "file", "x")], "absolute entry"),
                         (GOOD + [("other/x", "file", "x")], "entry outside python/"),
                         (GOOD + [("python/bin/esc", "symlink", "../../../etc/passwd")], "symlink escaping"),
                         (GOOD + [("python/bin/abs", "symlink", "/etc/passwd")], "absolute symlink"),
                         (GOOD + [("python/x", "symlink", "..")], "symlink to the parent of python/"),
                         (GOOD + [("python/bin/hl", "hardlink", "python/bin/python3.12")], "hardlink entry")):
        bad = SP / "bad.tgz"
        make_tar(bad, members)
        rc, out, home, _ = run_installer(bad)
        check("unsafe archive refused (%s), nothing installed" % why,
              rc != 0 and "refused" in out and not (home / ".webterm" / "python").exists(), out[-300:])

    rc, out, home, _ = run_installer(good, arch="mips")
    check("unknown architecture → refused with a clear message",
          rc != 0 and "no portable Python for this machine (mips" in out and not (home / ".webterm" / "python").exists(),
          out[-300:])
    rc, out, home, _ = run_installer(good, glibc="glibc 2.12")
    check("glibc older than 2.17 → refused", rc != 0 and "glibc 2.12 is older than 2.17" in out, out[-300:])
    rc, out, home, _ = run_installer(good, arch="aarch64", glibc="glibc 2.31")
    check("aarch64 picks the aarch64-gnu build", "aarch64-gnu" in out, out[-300:])

    print("── install script: owners and modes, fetchers, interpreter paths (review L1, L4, L6)")
    as_root = os.geteuid() == 0
    script = api._install_script_for("TOKEN-SECRET-123")
    check("rendered: tar xzof (archive owners dropped), chmod -R go-w, chown -hR 0:0 when root",
          "tar xzof ../py.tgz" in script and 'chmod -R go-w "$T/x/python"' in script
          and 'chown -hR 0:0 "$T/x/python"' in script)
    check("rendered: interpreter and agent paths quoted in the systemd unit and the crontab",
          'ExecStart="$PY" "$AGENT" run' in script and "@reboot '$PY' '$AGENT' start # webterm" in script
          and "* * * * * '$PY' '$AGENT' start # webterm-watchdog" in script)

    loose = SP / "loose.tgz"
    make_tar(loose, [("python", "dir", "", {"mode": 0o777, "uid": 4242}),
                     ("python/bin", "dir", "", {"mode": 0o775, "uid": 4242}),
                     ("python/bin/python3.12", "file", GOOD_PY, {"mode": 0o777, "uid": 4242}),
                     ("python/bin/python3", "symlink", "python3.12"),
                     ("python/lib", "dir", "", {"mode": 0o777, "uid": 4242}),
                     ("python/lib/x.py", "file", "x = 1\n", {"mode": 0o666, "uid": 4242})])
    rc, out, home, _ = run_installer(loose)
    tree = home / ".webterm" / "python"
    entries = [tree] + list(tree.rglob("*")) if tree.exists() else []
    writable = [str(p) for p in entries if not p.is_symlink() and p.stat().st_mode & 0o022]
    check("archive with 0777/0666 modes and uid 4242 → installed, nothing group/world-writable",
          bool(entries) and not writable, (writable, out[-300:]))
    if as_root:
        foreign = [str(p) for p in entries if p.lstat().st_uid != 0 or p.lstat().st_gid != 0]
        check("as root: every file of the portable Python belongs to root:root (uid 4242 not kept)",
              not foreign, foreign[:3])

    rc, out, home, log = run_installer(good, fetcher="gnu-wget")
    check("no curl, GNU wget → the token comes from WGETRC (a 0600 file), never on the command line",
          (home / ".webterm" / "python" / "bin" / "python3").exists() and "CFG_OK" in log
          and "TOKEN-SECRET-123" not in log, (out[-300:], log))
    rc, out, home, log = run_installer(good, fetcher="busybox-wget")
    check("no curl, BusyBox wget → refused with 'install curl', nothing fetched, nothing installed",
          rc != 0 and "needs curl" in out and "apk add curl" in out and "/agent/python/" not in log
          and not (home / ".webterm" / "python").exists(), (out[-300:], log))

    weird = SP / "py%dir"
    weird.mkdir()
    (weird / "python3").write_text(GOOD_PY)
    (weird / "python3").chmod(0o755)
    rc, out, home, _ = run_installer(good, portable=False, env_extra={"WEBTERM_PYTHON": str(weird / "python3")})
    check("WEBTERM_PYTHON with a % (cron) → refused before anything is written",
          rc != 0 and "plain characters" in out and not (home / ".webterm").exists(), out[-300:])
    if as_root:
        def py_in(name, dmode=0o755, owner=None):
            d = SP / name
            d.mkdir()
            d.chmod(dmode)
            (d / "python3").write_text(GOOD_PY)
            (d / "python3").chmod(0o755)
            if owner is not None:
                os.chown(d / "python3", owner, owner)
            return str(d / "python3")
        rc, out, home, _ = run_installer(good, portable=False, env_extra={"WEBTERM_PYTHON": py_in("ww", 0o777)})
        check("as root: an interpreter in a world-writable folder → refused, nothing installed",
              rc != 0 and "not safe to run as root" in out and "world-writable" in out
              and not (home / ".webterm").exists(), out[-300:])
        rc, out, home, _ = run_installer(good, portable=False, env_extra={"WEBTERM_PYTHON": py_in("nb", owner=65534)})
        check("as root: an interpreter owned by another user → refused",
              rc != 0 and "owned by uid 65534" in out, out[-300:])
        rc, out, home, log = run_installer(good, portable=False, env_extra={"WEBTERM_PYTHON": py_in("ok")})
        check("as root: a root-owned interpreter in root-owned folders (a sticky /tmp above is fine) → accepted",
              "not safe" not in out and "agent/ptyd.py" in log, out[-300:])
    else:
        check("root-only interpreter checks skipped (not root)", True)


async def main():
    try:
        manifest_checks()
        download_checks()
        await route_checks()
        installer_checks()
    finally:
        shutil.rmtree(SP, ignore_errors=True)
        await db.close()
    return check.summary()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
