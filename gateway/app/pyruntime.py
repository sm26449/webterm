"""Portable Python runtime for agent hosts (3.6.9).

Hosts whose python3 is missing or older than 3.6 (Ubuntu 16.04 and Debian 9 ship 3.5) cannot run
the agent's file operations. Instead of a separate 3.5-compatible agent, the install script gives
such a host a self-contained CPython (python-build-standalone, `install_only_stripped`) under
`~/.webterm/python/`, owned by the agent's user, and starts the agent with it.

The gateway serves the tarball, so hosts without internet access work:
  * ONLY the pinned files of `pyruntime.json` (release tag, name, size, SHA-256) exist; the target
    is a key of that manifest, never a file name or URL from the request;
  * first request: the gateway downloads the pinned URL over HTTPS (redirects only to GitHub's own
    download hosts), streams it to a temp file under the data volume while hashing it, refuses
    anything larger than the pinned size, and moves it into the cache ONLY if the SHA-256 matches.
    A mismatch is never cached and never served;
  * bounded: one download per target at a time, at most MAX_PARALLEL overall, a total deadline,
    and a free-space check (pinned size + FREE_MARGIN) before downloading;
  * a cached file is re-hashed once per gateway process before it is first served (a file changed
    on disk is deleted and fetched again), then streamed;
  * the route needs the HOST's agent token (`Authorization: Bearer`) — the credential the install
    script already carries — so the gateway is not an anonymous download proxy.
The host verifies the same SHA-256 again (embedded in the install script), so a wrong file is
refused at both ends.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import ssl
import time
import urllib.request
from pathlib import Path
from typing import Optional

from . import config

log = logging.getLogger("webterm")

MANIFEST_PATH = Path(__file__).with_name("pyruntime.json")
ALLOWED_HOSTS = ("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")
MAX_PARALLEL = 2
DOWNLOAD_DEADLINE = 600.0          # seconds, whole download
READ_TIMEOUT = 30.0                # per socket operation
FREE_MARGIN = 512 * 1024 * 1024    # keep this much free on the data volume after the download
CHUNK = 1024 * 1024
_TARGET_RE = re.compile(r"^[a-z0-9_]+-[a-z0-9]+$")
_FILE_RE = re.compile(r"^cpython-[0-9.]+\+[0-9]{8}-[a-z0-9_]+-unknown-linux-[a-z0-9]+-install_only_stripped\.tar\.gz$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class RuntimeUnavailable(Exception):
    """→ the route answers 503 with a stable code; `code` says why."""

    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    """The pinned manifest, validated strictly — a malformed entry is dropped, never guessed."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"targets": {}}
    base = raw.get("base_url", "")
    if not (isinstance(base, str) and base.startswith("https://github.com/") and base.endswith("/")):
        return {"targets": {}}
    out = {k: raw.get(k) for k in ("release", "python", "min_glibc", "base_url")}
    out["targets"] = {}
    for key, t in (raw.get("targets") or {}).items():
        if not (isinstance(t, dict) and isinstance(key, str) and _TARGET_RE.match(key)):
            continue
        f, sha, size = t.get("file"), t.get("sha256"), t.get("size")
        if (isinstance(f, str) and _FILE_RE.match(f) and isinstance(sha, str) and _SHA_RE.match(sha)
                and isinstance(size, int) and not isinstance(size, bool) and 0 < size < 200 * 1024 * 1024):
            out["targets"][key] = {"file": f, "sha256": sha, "size": size}
    return out


MANIFEST = load_manifest()


def target(key) -> Optional[dict]:
    return MANIFEST["targets"].get(key) if isinstance(key, str) else None


def cache_dir() -> Path:
    return Path(config.DATA_DIR) / "pyruntime"


_locks: dict = {}
_sem: Optional[asyncio.Semaphore] = None
_verified: set = set()             # cached files hashed OK by this process


def _sem_get() -> asyncio.Semaphore:
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(MAX_PARALLEL)
    return _sem


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(CHUNK), b""):
            h.update(b)
    return h.hexdigest()


class _PinnedRedirects(urllib.request.HTTPRedirectHandler):
    """Follow GitHub's redirect to its download CDN — and nothing else (https, allow-listed host)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlparse
        u = urlparse(newurl)
        if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
            raise RuntimeUnavailable("pyruntime.badRedirect", "refused redirect to %s" % u.hostname)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener():
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _PinnedRedirects())


def download_verified(url: str, dest: Path, sha256: str, size: int, opener=None,
                      deadline: float = DOWNLOAD_DEADLINE) -> None:
    """Blocking (runs in a thread). Streams `url` into a temp file next to `dest`, hashing as it
    goes; more bytes than `size`, a wrong total or a wrong hash → the temp file is deleted and
    RuntimeUnavailable is raised. Only a verified file is renamed into place."""
    if not url.startswith("https://"):
        raise RuntimeUnavailable("pyruntime.badUrl", "only https downloads")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(".%s.part.%d" % (dest.name, os.getpid()))
    h = hashlib.sha256()
    n = 0
    end = time.monotonic() + deadline
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "webterm-gateway"})
        with (opener or _opener()).open(req, timeout=READ_TIMEOUT) as r, open(tmp, "wb") as out:
            while True:
                if time.monotonic() > end:
                    raise RuntimeUnavailable("pyruntime.timeout", "download took too long")
                b = r.read(CHUNK)
                if not b:
                    break
                n += len(b)
                if n > size:
                    raise RuntimeUnavailable("pyruntime.badSize", "larger than the pinned size")
                h.update(b)
                out.write(b)
        if n != size:
            raise RuntimeUnavailable("pyruntime.badSize", "got %d bytes, pinned %d" % (n, size))
        if h.hexdigest() != sha256:
            raise RuntimeUnavailable("pyruntime.badHash", "SHA-256 mismatch — not cached, not served")
        os.chmod(tmp, 0o644)
        os.replace(tmp, dest)
    except RuntimeUnavailable:
        raise
    except Exception as e:             # noqa: BLE001 — network/disk: a stable code, no partial file
        raise RuntimeUnavailable("pyruntime.downloadFailed", "%s" % (e.__class__.__name__,))
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _free_bytes(p: Path) -> int:
    p.mkdir(parents=True, exist_ok=True)
    return shutil.disk_usage(p).free


async def get(key: str, *, opener=None) -> tuple:
    """→ (path, entry) of the verified cached tarball for `key`, fetching it if needed."""
    t = target(key)
    if not t:
        raise RuntimeUnavailable("pyruntime.unknownTarget", "no portable Python for that target")
    d = cache_dir()
    dest = d / t["file"]
    lock = _locks.setdefault(key, asyncio.Lock())
    async with lock:
        if dest.exists():
            if str(dest) in _verified:
                return dest, t
            got = await asyncio.to_thread(sha256_file, dest)
            if got == t["sha256"]:
                _verified.add(str(dest))
                return dest, t
            log.warning("portable python: cached %s does not match its pinned hash — deleted", dest.name)
            dest.unlink(missing_ok=True)
        free = await asyncio.to_thread(_free_bytes, d)
        if free < t["size"] + FREE_MARGIN:
            raise RuntimeUnavailable("pyruntime.noSpace", "not enough free space on the data volume")
        async with _sem_get():
            log.info("portable python: downloading %s (%d bytes)", t["file"], t["size"])
            url = MANIFEST["base_url"] + t["file"].replace("+", "%2B")
            await asyncio.wait_for(
                asyncio.to_thread(download_verified, url, dest, t["sha256"], t["size"], opener),
                timeout=DOWNLOAD_DEADLINE + 60)
        _verified.add(str(dest))
        _prune(d)
        return dest, t


def _prune(d: Path) -> None:
    """Old pinned releases left in the cache (after a manifest bump) are deleted."""
    keep = {t["file"] for t in MANIFEST["targets"].values()}
    try:
        for p in d.iterdir():
            if p.is_file() and p.name not in keep and not p.name.startswith("."):
                p.unlink(missing_ok=True)
    except OSError:
        pass
