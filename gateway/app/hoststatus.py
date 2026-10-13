"""Status files written by the HOST helpers (3.6.8) — read here as UNTRUSTED input.

Why: the host timers (scripts/backup.sh, cert-check.sh, host-health.sh, docker-cleanup.sh) used to
report only to journald. A nightly backup that failed for weeks was visible to whoever ran
`systemctl --failed`, i.e. nobody. Now each of them leaves a small JSON in the data volume
(`<data>/host-status/<id>.json`, written by `scripts/host-health.sh --record` as root) and the
gateway turns it into a System health check.

The gateway gets NO new privilege for this: it only READS files in its own data volume. And the
files are treated as hostile, because anything that can write into the volume (a compromised
gateway process itself, a restored backup, a careless admin) can put anything there:
  * only a FIXED set of names is ever opened (`IDS`) — nothing is enumerated or globbed;
  * the directory and the file are opened with O_NOFOLLOW (a symlink is refused, not followed),
    the file must be a regular file of at most MAX_BYTES, read with a hard cap;
  * the JSON must match the schema exactly: unknown keys are dropped, every value is type-checked
    and bounded, strings lose control characters and are cut; `ts` must be a sane finite number;
  * nothing from a file is ever executed, used to build a command, or rendered as HTML: the
    message travels as plain text (React escapes it) and through `alert_history.scrub` before it
    reaches an alert. Commands come only from the server-side allow-list (healthcmd.py).
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
import time
from typing import Optional

from . import config

DIRNAME = "host-status"
MAX_BYTES = 4096
MSG_MAX = 200
STR_MAX = 128

# id → how often the host helper is expected to write it (seconds). The gateway decides staleness
# from THIS table, never from the file: a file cannot declare itself fresh for a year.
IDS = {
    "backup": 86400,            # scripts/backup.sh (webterm-backup.timer, daily 03:30)
    "cert-check": 86400,        # scripts/cert-check.sh (webterm-cert-check.timer, daily 07:15)
    "host-health": 3600,        # scripts/host-health.sh (webterm-host-health.timer, hourly)
    "cloudflare-token": 3600,   # written by host-health.sh
    "authentik-image": 3600,    # written by host-health.sh
    "docker-cleanup": 86400,    # scripts/docker-cleanup.sh (webterm-docker-cleanup.timer, 04:17)
    "restore-verify": 0,        # scripts/restore.sh --verify (on demand: never stale)
}
STATUSES = ("ok", "warn", "error", "skipped")
TIMER_STATES = ("enabled", "disabled", "missing")
KIT_KEYS = ("backup", "cert_check", "cleanup")          # host-health.sh's kit report (3.6.9)
TIMERS = ("webterm-backup.timer", "webterm-cert-check.timer", "webterm-host-health.timer",
          "webterm-docker-cleanup.timer")
_VERSION_RE = re.compile(r"^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,3}$")
_PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_BASENAME_RE =re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ISO_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9:.]{2,15}(?:Z|[+-][0-9:]{2,5})?)?$")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")
_EARLIEST = 1577836800          # 2020-01-01: older than this is not a real status
_FUTURE_SLACK = 300             # a host clock a little ahead is tolerated, a year ahead is not


def clean_text(v, limit: int = STR_MAX) -> str:
    """Plain, single-line, bounded text: control and bidi-override characters become spaces."""
    if not isinstance(v, str):
        return ""
    return " ".join(_CTRL.sub(" ", v).split())[:limit]


def _int(v, lo: int, hi: int) -> Optional[int]:
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    return v if lo <= v <= hi else None


def _num(v, lo: float, hi: float) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    f = float(v)
    if not math.isfinite(f) or not lo <= f <= hi:
        return None
    return round(f, 2)


def _enum(v, allowed) -> Optional[str]:
    return v if isinstance(v, str) and v in allowed else None


def _match(v, rx) -> Optional[str]:
    return v if isinstance(v, str) and len(v) <= STR_MAX and rx.match(v) else None


def _data(sid: str, raw) -> dict:
    """The per-id `data` block: an allow-list of keys, each type-checked. Everything else is
    dropped silently (a newer host script may add fields; an older gateway ignores them)."""
    if not isinstance(raw, dict):
        return {}
    out: dict = {}

    def put(key, val):
        if val is not None:
            out[key] = val

    if sid == "backup":
        put("archive", _match(raw.get("archive"), _BASENAME_RE))
        if isinstance(raw.get("encrypted"), bool):
            out["encrypted"] = raw["encrypted"]
        put("offhost", _enum(raw.get("offhost"), ("none", "ok", "failed")))
    elif sid == "cert-check":
        put("days_left", _int(raw.get("days_left"), -100000, 100000))
    elif sid == "host-health":
        timers = raw.get("timers")
        if isinstance(timers, dict):
            t = {k: timers[k] for k in TIMERS if _enum(timers.get(k), TIMER_STATES)}
            if t:
                out["timers"] = t
        if isinstance(raw.get("legacy_cron"), bool):
            out["legacy_cron"] = raw["legacy_cron"]
        put("script_version", _int(raw.get("script_version"), 0, 10000))
        # 3.6.9 kit report: does each timer's script support reporting, since when is it
        # installed, when does the timer fire next (epoch seconds; 0 = unknown)
        for k in KIT_KEYS:
            if isinstance(raw.get("kit_" + k), bool):
                out["kit_" + k] = raw["kit_" + k]
            put("since_" + k, _int(raw.get("since_" + k), 0, 2 ** 40))
            put("next_" + k, _int(raw.get("next_" + k), 0, 2 ** 40))
    elif sid == "cloudflare-token":
        put("token_status", _enum(raw.get("token_status"),
                                  ("active", "expired", "disabled", "invalid", "unknown")))
        exp = raw.get("expires_on")
        if exp == "":
            out["expires_on"] = ""
        else:
            put("expires_on", _match(exp, _ISO_RE))
    elif sid == "authentik-image":
        put("running", _match(raw.get("running"), _VERSION_RE))
        put("pinned", _match(raw.get("pinned"), _VERSION_RE))
        # profile = this install's compose profile; kit = deploy/authentik; separate = another
        # compose project (e.g. /opt/authentik). Detected by the compose project label.
        put("layout", _enum(raw.get("layout"), ("profile", "kit", "separate")))
        put("project", _match(raw.get("project"), _PROJECT_RE))
    elif sid == "docker-cleanup":
        put("disk_free_pct", _num(raw.get("disk_free_pct"), 0, 100))
        put("images_removed", _int(raw.get("images_removed"), 0, 100000))
    elif sid == "restore-verify":
        put("archive", _match(raw.get("archive"), _BASENAME_RE))
    return out


def validate(sid: str, doc, now: Optional[float] = None) -> Optional[dict]:
    """Schema check of one parsed document → a clean dict, or None (refused)."""
    now = time.time() if now is None else now
    if sid not in IDS or not isinstance(doc, dict):
        return None
    if doc.get("v") != 1 or doc.get("id") != sid:
        return None
    status = _enum(doc.get("status"), STATUSES)
    ts = doc.get("ts")
    if status is None or isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return None
    ts = float(ts)
    if not math.isfinite(ts) or ts < _EARLIEST or ts > now + _FUTURE_SLACK:
        return None
    return {"id": sid, "status": status, "ts": ts,
            "message": clean_text(doc.get("message"), MSG_MAX),
            "data": _data(sid, doc.get("data"))}


def _read_bounded(sid: str, base: Optional[str] = None) -> tuple:
    """(bytes | None, error | None). O_NOFOLLOW on the directory AND on the file, regular file
    only, size checked on the open descriptor (no TOCTOU between stat and read)."""
    d = base if base is not None else str(config.DATA_DIR / DIRNAME)
    flags_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dfd = os.open(d, flags_dir)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return None, "directory unreadable (%s)" % (e.strerror or e.__class__.__name__)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(sid + ".json", flags, dir_fd=dfd)
        except FileNotFoundError:
            return None, None
        except OSError as e:
            return None, "unreadable (%s)" % (e.strerror or e.__class__.__name__)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None, "not a regular file"
            if st.st_size > MAX_BYTES:
                return None, "too large"
            buf = os.read(fd, MAX_BYTES + 1)
            if len(buf) > MAX_BYTES:
                return None, "too large"
            return buf, None
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def read(sid: str, now: Optional[float] = None, base: Optional[str] = None) -> dict:
    """One status → {"state": "missing" | "invalid" | "ok", ...}.
       missing — no file (the helper never ran / is not installed);
       invalid — present but refused (symlink, too big, bad JSON, bad schema): `error` says why;
       ok      — `status`, `ts`, `message`, `data`, `age`, `stale` (older than 2× the interval)."""
    if sid not in IDS:
        return {"state": "invalid", "error": "unknown id"}
    now = time.time() if now is None else now
    raw, err = _read_bounded(sid, base)
    if err:
        return {"state": "invalid", "error": err}
    if raw is None:
        return {"state": "missing"}
    try:
        doc = json.loads(raw.decode("utf-8"), parse_constant=lambda _c: None)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return {"state": "invalid", "error": "not valid JSON"}
    clean = validate(sid, doc, now)
    if clean is None:
        return {"state": "invalid", "error": "does not match the status schema"}
    age = max(0.0, now - clean["ts"])
    interval = IDS[sid]
    clean.update(state="ok", age=age, stale=bool(interval) and age > 2 * interval)
    return clean


def read_all(now: Optional[float] = None, base: Optional[str] = None) -> dict:
    return {sid: read(sid, now, base) for sid in IDS}
