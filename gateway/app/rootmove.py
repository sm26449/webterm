"""Uploads into folders the agent's user cannot write (3.6.9) — the pure, testable half.

Why this exists: the file APIs act as the AGENT's user (often an unprivileged `webterm`), not as
whoever the terminal has become with sudo. An Owner in a root shell in `/srv/bin/lists`
(`drwxr-xr-x root root`) who uploaded there through Files got only "The file operation failed on
the host" — true, by design, and useless. Two things live here, both without an agent change:

  * `reason()` — the agent's strerror, sanitised, for errors we have no specific text for;
  * "Upload and move as root": the file goes to the agent's inbox (`~/.webterm/inbox`, written as
    the agent's user, like paste-to-inbox), then WebTerm TYPES — never runs — a command into the
    person's own terminal that installs it into the target folder with sudo:

        sudo install -m 0644 -- '<inbox file>' '<dir>/<name>' && rm -f -- '<inbox file>'

    The command text is security critical (it lands in what is often a root shell), so it is built
    here and nowhere else, the way healthcmd.py builds the System health commands:
      - every value is validated: the folder is an absolute, normalised path, the names are plain
        file names, and none of them may contain control, format (bidi) or line-separator
        characters — rejected, not stripped: a name that needs stripping is not the name the
        person meant;
      - the inbox file name is GENERATED here (timestamp + random), never taken from the client;
      - every token goes through `shlex.quote`, and the text must round-trip through `shlex.split`
        to exactly the argv we meant, or there is no command at all (`MoveError`, fail closed).

    Reading the inbox file as root (sudo install) is not a new privilege for the agent's user:
    that user owns the inbox, but it also owns the tmux server the root shell runs in, so it can
    already type into that shell. sudo on the host stays the real gate, and the person presses
    Enter after reading the command.
"""

from __future__ import annotations

import posixpath
import re
import secrets
import shlex
import time
import unicodedata

INBOX_REL = "~/.webterm/inbox"       # the same inbox as paste-to-inbox (frontend lib/transfers.ts)
MAX_FILES = 20
MAX_PATH = 4096
MAX_NAME_BYTES = 255
MAX_COMMAND = 32768
REASON_MAX = 120

# Cc (C0/C1 controls, DEL), Cf (format: bidi overrides, zero-width), Zl/Zp (line/paragraph
# separators), Cs/Co (surrogates, private use). Any of these in a path that is TYPED into a
# terminal is either an attack (a `\r` sends the line, ESC starts a sequence, U+202E reorders what
# the person reads) or garbage — refused.
_BAD_CATEGORIES = {"Cc", "Cf", "Zl", "Zp", "Cs", "Co"}
_INBOX_NAME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}_root-move_[0-9a-f]{8}$")


class MoveError(ValueError):
    pass


def has_bad_chars(s: str) -> bool:
    return any(unicodedata.category(ch) in _BAD_CATEGORIES for ch in s)


def reason(msg: str) -> str:
    """The strerror part of an agent fs error ("<path>: <strerror>"), safe to show: control and
    format characters removed, whitespace collapsed, at most REASON_MAX characters. The path is
    dropped (the UI already says which file); "" when nothing usable is left."""
    if not isinstance(msg, str):
        return ""
    return clean_text(msg.rsplit(": ", 1)[-1])


def clean_text(text: str) -> str:
    """Any agent-supplied text made safe to show: control/format characters become spaces,
    whitespace collapses, at most REASON_MAX characters."""
    if not isinstance(text, str):
        return ""
    out = "".join(" " if unicodedata.category(ch) in _BAD_CATEGORIES else ch for ch in text)
    out = " ".join(out.split())
    if len(out) > REASON_MAX:
        out = out[:REASON_MAX - 1].rstrip() + "…"
    return out


def check_dir(d) -> str:
    """An absolute, normalised directory path (what Files shows in its path bar)."""
    if not isinstance(d, str) or not d:
        raise MoveError("the folder must be a non-empty string")
    if len(d) > MAX_PATH:
        raise MoveError("the folder path is too long")
    if has_bad_chars(d):
        raise MoveError("the folder path contains control characters")
    if not d.startswith("/") or d.startswith("//"):
        raise MoveError("the folder must be an absolute path")
    if posixpath.normpath(d) != d:
        raise MoveError("the folder path must be normalised (no ., .. or trailing /)")
    return d


def check_name(n) -> str:
    """A plain file name: no `/`, not `.`/`..`, at most 255 bytes, no control characters."""
    if not isinstance(n, str) or not n:
        raise MoveError("the file name must be a non-empty string")
    if "/" in n or n in (".", ".."):
        raise MoveError("the file name must not be a path")
    if len(n.encode("utf-8", "surrogatepass")) > MAX_NAME_BYTES:
        raise MoveError("the file name is too long")
    if has_bad_chars(n):
        raise MoveError("the file name contains control characters")
    return n


def inbox_name(now: float | None = None) -> str:
    """WebTerm's own name for the staged file — never derived from what the client sent."""
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.gmtime(now if now is not None else time.time()))
    return "%s_root-move_%s" % (stamp, secrets.token_hex(4))


def check_inbox(inbox: str) -> str:
    """The inbox path the AGENT resolved (fs_mkdir's reply). Same rules as a target folder, and
    it must end in the inbox we asked for — anything else and we do not build a command."""
    try:
        check_dir(inbox)
    except MoveError:
        raise MoveError("the agent returned an unusable inbox path")
    if not inbox.endswith("/.webterm/inbox"):
        raise MoveError("the agent returned an unexpected inbox path")
    return inbox


def build(inbox: str, target_dir: str, names: list, now: float | None = None) -> dict:
    """→ {"uploads": [{"name", "upload_path"}], "command": str}. Raises MoveError."""
    inbox = check_inbox(inbox)
    target_dir = check_dir(target_dir)
    if not isinstance(names, list) or not 1 <= len(names) <= MAX_FILES:
        raise MoveError("between 1 and %d files" % MAX_FILES)
    names = [check_name(n) for n in names]
    if len(set(names)) != len(names):
        raise MoveError("duplicate file names")
    uploads, segments, srcs = [], [], []
    for n in names:
        staged = inbox_name(now)
        while any(u["upload_path"].endswith("/" + staged) for u in uploads):
            staged = inbox_name(now)                      # same second, same 32 random bits: retry
        if not _INBOX_NAME_RE.match(staged):
            raise MoveError("internal: bad inbox name")
        src = inbox + "/" + staged
        dst = (target_dir.rstrip("/") or "") + "/" + n
        uploads.append({"name": n, "upload_path": src})
        srcs.append(src)
        segments.append(["sudo", "install", "-m", "0644", "--", src, dst])
    segments.append(["rm", "-f", "--"] + srcs)
    text = " && ".join(" ".join(shlex.quote(t) for t in seg) for seg in segments)
    want: list = []
    for i, seg in enumerate(segments):
        if i:
            want.append("&&")
        want.extend(seg)
    if (shlex.split(text) != want or has_bad_chars(text) or "\n" in text
            or len(text) > MAX_COMMAND):
        raise MoveError("the command did not round-trip")
    return {"uploads": uploads, "command": text}
