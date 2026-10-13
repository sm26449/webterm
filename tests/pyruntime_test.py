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
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rbac_util as U  # noqa: E402
from app import api, db, pyruntime, security  # noqa: E402

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
        for name, kind, payload in members:
            ti = tarfile.TarInfo(name)
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
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
                ti.mode = 0o755
                tf.addfile(ti, io.BytesIO(b))


GOOD_PY = "#!/bin/sh\ncase \"$*\" in *version_info*) exit 0 ;; *sys.version*) echo 3.12.15 ;; esac\nexit 0\n"
GOOD = [("python", "dir", ""), ("python/bin", "dir", ""), ("python/bin/python3.12", "file", GOOD_PY),
        ("python/bin/python3", "symlink", "python3.12"), ("python/share/t/a", "dir", ""),
        ("python/share/t/1", "symlink", "../t/a")]


def run_installer(tgz: Path, arch="x86_64", glibc="glibc 2.23", sha=None):
    """Render the install script with a test manifest entry pinned to `tgz` (or `sha`), run it
    with fake curl/uname/getconf; return (rc, output, home)."""
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
    (bindir / "curl").write_text(
        "#!/bin/sh\nout=''; url=''\n"
        "echo \"ARGS: $*\" >> \"$LOG\"\n"
        "while [ $# -gt 0 ]; do case \"$1\" in -o) out=\"$2\"; shift ;; -K) grep -q 'Bearer TOKEN-SECRET-123' \"$2\" && echo CFG_OK >> \"$LOG\" ;; http*) url=\"$1\" ;; esac; shift; done\n"
        "case \"$url\" in */agent/python/*) cp \"$TGZ\" \"$out\" ;; *) exit 22 ;; esac\n")
    (bindir / "uname").write_text("#!/bin/sh\necho \"$FAKE_ARCH\"\n")
    (bindir / "getconf").write_text("#!/bin/sh\necho \"$FAKE_GLIBC\"\n")
    for f in bindir.iterdir():
        f.chmod(0o755)
    env = {"PATH": "%s:/usr/bin:/bin" % bindir, "HOME": str(home), "LOG": str(work / "curl.log"),
           "TGZ": str(tgz), "FAKE_ARCH": arch, "FAKE_GLIBC": glibc, "WEBTERM_PORTABLE_PYTHON": "1",
           "WEBTERM_NO_SHELL_INTEGRATION": "1"}
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
