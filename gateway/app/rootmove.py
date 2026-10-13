"""Uploads into folders the agent's user cannot write (3.6.9) — the pure, testable half.

Why this exists: the file APIs act as the AGENT's user (often an unprivileged `webterm`), not as
whoever the terminal has become with sudo. An Owner in a root shell in `/srv/bin/lists`
(`drwxr-xr-x root root`) who uploaded there through Files got only "The file operation failed on
the host" — true, by design, and useless. Two things live here, both without an agent change:

  * `reason()` — the agent's strerror, sanitised, for errors we have no specific text for;
  * "Upload and move as root", in two steps:
      1. `new_plan()` — WebTerm names the staging files in the agent's inbox (`~/.webterm/inbox`,
         written as the agent's user U, like paste-to-inbox). While the bytes stream through the
         gateway into each staged file, the gateway hashes them (SHA-256, core.stage_*);
      2. after the uploads, `command()` builds the command that WebTerm TYPES — never runs — into
         the person's own terminal, or offers to copy:

        sudo sh -c '<MOVE_SCRIPT>' webterm-move <U> <dir> [<staged> <size> <sha256> <dir>/<name>]...

    The inbox belongs to U. Between the upload and the person pressing Enter, U can swap a staged
    file for a symlink or hardlink to e.g. /etc/shadow, for a FIFO or /dev/zero, and anyone with
    `files.write` on the host can upload over it. Typed into U's own tmux that would add nothing
    (U can already type there), but the Copy fallback is pasted into SSH/console root shells too.
    So the command never trusts the inbox:
      - it reads each staged file AS U (`sudo -u U -- head -c <size>`): a link to a file U cannot
        read fails, and at most <size> bytes are read (no /dev/zero disk fill);
      - it writes them into a fixed name inside a root-only `mktemp -d` folder IN the target
        folder (checked after entering it: see MOVE_SCRIPT), checks the SHA-256
        the gateway recorded while the bytes passed through it, and only then does `chmod 0644`
        and `mv -T` into place (same file system → atomic; never into a directory). A mismatch
        or any error: the temp file is removed, nothing lands, the command stops;
      - the staged file is removed as U, never as root;
      - the target folder is entered once with `cd -P` and must physically be the folder named (no
        symlink in its path); everything after that is relative to it.
    The script is a constant (nothing is interpolated into it); every value is a positional
    argument.

    The command text is security critical (it lands in what is often a root shell), so it is built
    here and nowhere else, the way healthcmd.py builds the System health commands:
      - every value is validated: the folder is an absolute, normalised path, the names are plain
        file names, U is a plain POSIX user name, and none of them may contain control, format
        (bidi) or line-separator characters — rejected, not stripped: a name that needs stripping
        is not the name the person meant — nor a backslash: in fish a backslash inside '…' still
        escapes the quote, so shlex.quote's output is only inert there without one (the command
        text, script included, has no backslash at all);
      - the inbox file name is GENERATED here (timestamp + random), never taken from the client;
      - every token goes through `shlex.quote`, and the text must round-trip through `shlex.split`
        to exactly the argv we meant, or there is no command at all (`MoveError`, fail closed).
    sudo on the host stays the real gate, and the person presses Enter after reading the command.
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
# A plain POSIX user name, as `useradd` accepts it by default: no leading `-` (an option), no
# `#uid` (sudo syntax), no `$`, nothing a shell would treat specially.
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SIZE = 1 << 50


class MoveError(ValueError):
    pass


class MoveBackslash(MoveError):
    """A backslash in the folder or a name (re-review M2): refused, see `check_dir`."""
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
    if "\\" in d:
        # fish: inside '…' a backslash still escapes a quote (and itself), so shlex.quote's output
        # is not inert there — a name `a<backslash>` then `x;id;#` would leave the quotes and run.
        # The command is typed into whatever shell the person uses (fish included): refused, not
        # escaped (re-review M2).
        raise MoveBackslash("the folder path contains a backslash")
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
    if "\\" in n:
        raise MoveBackslash("the file name contains a backslash")     # fish, see check_dir
    return n


def check_user(u) -> str:
    """The agent's user (reported by the agent, stored in hosts.agent_user). Unknown or odd → no
    command at all: we would not know as whom to read the staged files."""
    if not isinstance(u, str) or not _USER_RE.match(u) or shlex.split(shlex.quote(u)) != [u]:
        raise MoveError("the agent's user is unknown or not a plain user name")
    return u


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


def check_staged(inbox: str, path) -> str:
    """A staged path WebTerm generated — <inbox>/<inbox_name()> — and nothing else."""
    inbox = check_inbox(inbox)
    if (not isinstance(path, str) or not path.startswith(inbox + "/")
            or not _INBOX_NAME_RE.match(path[len(inbox) + 1:])):
        raise MoveError("internal: not a staged path")
    return path


def staged_paths(inbox: str, names: list, now: float | None = None) -> list:
    """→ [{"name", "upload_path"}]: one generated staging file per validated name."""
    inbox = check_inbox(inbox)
    if not isinstance(names, list) or not 1 <= len(names) <= MAX_FILES:
        raise MoveError("between 1 and %d files" % MAX_FILES)
    names = [check_name(n) for n in names]
    if len(set(names)) != len(names):
        raise MoveError("duplicate file names")
    uploads: list = []
    for n in names:
        staged = inbox_name(now)
        while any(u["upload_path"].endswith("/" + staged) for u in uploads):
            staged = inbox_name(now)                      # same second, same 32 random bits: retry
        uploads.append({"name": n, "upload_path": check_staged(inbox, inbox + "/" + staged)})
    return uploads


# Run by `sudo sh -c` with positional args: $1 = the agent's user, $2 = the target folder, then
# per file: staged path, size, SHA-256, destination. A CONSTANT: nothing is ever interpolated into
# it. No single quote (it is single-quoted on the command line) and no newline (it is typed).
# The bytes go into a fixed name `f` inside a root-owned 0700 `mktemp -d` folder, never into a
# file whose path is re-resolved (re-review L1: with a temp FILE, whoever can write the target
# folder could swap it for a symlink between `>`, `sha256sum` and `chmod` — root would truncate or
# chmod any file). A subshell enters the temp folder with `cd -P` and checks it is ours: at
# exactly the path mktemp made, owned by root with mode 0700 (`find . -prune -user -perm`: POSIX,
# unlike `test -O`) — a folder swapped in while it was still empty fails one of them. From then
# on `f` and `../<name>` are relative to that inode, which no one else can write, rename or
# remove. The subshell's EXIT trap removes `f`; the main shell's `c` only `rmdir`s the (then
# empty) temp folder: no `rm -rf` as root. INT/HUP/TERM go through `exit`, so the EXIT traps run
# (Ctrl-C on a FIFO someone left in the inbox leaves nothing behind). Messages go through `m`
# (printf "%s"), never `echo`: dash's echo interprets backslash escapes in its arguments, so a
# value in an echo could emit terminal escapes (re-review L2).
# The target folder is resolved ONCE: `cd -P` into it, and its physical path must be exactly the
# folder named (re-review L4) — a symlink anywhere in it, now or swapped in after staging, is
# refused. From there on every path in the folder is relative to that working directory (the
# inode we checked), so swapping a folder above it during the loop changes nothing.
MOVE_SCRIPT = (
    'u=$1 d=$2; shift 2; t=; '
    'm() { printf "webterm: %s" "$1"; echo; }; '
    'c() { [ -z "$t" ] || rmdir -- "$t" 2>/dev/null; t=; }; '
    'trap c EXIT; trap "exit 130" HUP INT TERM; '
    'cd -P -- "$d" && [ "$(pwd -P)" = "$d" ] || { m "NOT installed: $d is not that folder any more '
    '(a symlink in its path, or it is gone); nothing was moved" >&2; exit 1; }; '
    'while [ $# -ge 4 ]; do '
    's=$1 z=$2 h=$3 f=$4; shift 4; n=${f##*/}; '
    't=$(mktemp -d -- ./.webterm-move.XXXXXX) || exit 1; '
    'if ( cd -P -- "$t" && [ "$(pwd -P)" = "${d%/}/${t#./}" ] '
    '&& [ "$(find . -prune -user "$(id -u)" -perm 700)" = . ] || exit 1; '
    'trap "rm -f f" EXIT; trap "exit 130" HUP INT TERM; '
    '{ sudo -u "$u" -- head -c "$z" -- "$s"; } >f && x=$(sha256sum <f) && [ "${x%% *}" = "$h" ] '
    '&& chmod 0644 f && mv -f -T -- f "../$n" ); '
    'then c; m "installed $f"; sudo -u "$u" -- rm -f -- "$s" || :; '
    'else m "NOT installed: $f - the uploaded file was changed or replaced, '
    'or $u could not read it (SHA-256 check); nothing was moved" >&2; exit 1; fi; '
    'done'
)
SCRIPT_NAME = "webterm-move"


def command(agent_user: str, inbox: str, target_dir: str, items: list) -> str:
    """The command to type or copy. `items`: [{"name", "upload_path", "size", "sha256"}], size and
    hash being what the GATEWAY streamed into the staged file (core.stage_result). Raises
    MoveError — then there is no command."""
    u = check_user(agent_user)
    target_dir = check_dir(target_dir)
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_FILES:
        raise MoveError("between 1 and %d files" % MAX_FILES)
    argv = ["sudo", "sh", "-c", MOVE_SCRIPT, SCRIPT_NAME, u, target_dir]
    seen: set = set()
    for it in items:
        name = check_name(it.get("name"))
        if name in seen:
            raise MoveError("duplicate file names")
        seen.add(name)
        src = check_staged(inbox, it.get("upload_path"))
        size, sha = it.get("size"), it.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size < MAX_SIZE:
            raise MoveError("internal: bad size")
        if not isinstance(sha, str) or not _SHA_RE.match(sha):
            raise MoveError("internal: bad hash")
        argv += [src, str(size), sha, target_dir.rstrip("/") + "/" + name]
    quoted = [shlex.quote(t) for t in argv]
    text = " ".join(quoted)
    # fish: no backslash anywhere (see check_dir), and no bare token starting with `%` (fish
    # expands `%self`) or `~` — every value token starts with `/`, a digit or a hex digit anyway
    if (shlex.split(text) != argv or has_bad_chars(text) or "\n" in text or "\\" in text
            or any(q[:1] in ("%", "~") for q in quoted) or len(text) > MAX_COMMAND):
        raise MoveError("the command did not round-trip")
    return text


# ── plans: the staged paths handed out, until their command is built ─────────────────────────
# In memory: a gateway restart forgets them, and the person uploads again (fail closed — the
# hashes were in memory too). The index (host, staged path) → plan lets the upload routes refuse
# anyone else writing into a staged file while its plan is live; the hash check would refuse the
# result anyway, this keeps the error early and clear.
PLAN_TTL = 24 * 3600
MAX_PLANS = 512
_plans: dict = {}          # plan_id -> {"plan_id","host_id","user_id","dir","inbox","uploads","at"}
_staged: dict = {}         # (host_id, upload_path) -> plan_id


def _expire(now: float) -> list:
    """Drop plans older than PLAN_TTL, then the oldest beyond MAX_PLANS - 1. → the dropped plans."""
    gone = [pid for pid, p in _plans.items() if now - p["at"] > PLAN_TTL]
    over = len(_plans) - len(gone) - MAX_PLANS + 1
    if over > 0:
        gone += [pid for pid in _plans if pid not in gone][:over]
    return [p for p in (drop_plan(pid) for pid in gone) if p]


def new_plan(host_id: int, user_id: int, inbox: str, target_dir: str, names: list,
             now: float | None = None) -> tuple:
    """→ (plan, dropped): the new plan (`plan_id`, `uploads`, …) and the older plans it evicted
    (the caller forgets their stage hashes)."""
    now = time.time() if now is None else now
    target_dir = check_dir(target_dir)
    uploads = staged_paths(inbox, names, now)
    dropped = _expire(now)
    pid = secrets.token_hex(16)
    plan = {"plan_id": pid, "host_id": host_id, "user_id": user_id, "dir": target_dir,
            "inbox": inbox, "uploads": uploads, "at": now}
    _plans[pid] = plan
    for u in uploads:
        _staged[(host_id, u["upload_path"])] = pid
    return plan, dropped


def get_plan(plan_id, now: float | None = None):
    if not isinstance(plan_id, str):
        return None
    now = time.time() if now is None else now
    p = _plans.get(plan_id)
    if p is None or now - p["at"] > PLAN_TTL:
        return None
    return p


def drop_plan(plan_id: str):
    p = _plans.pop(plan_id, None)
    if p:
        for u in p["uploads"]:
            if _staged.get((p["host_id"], u["upload_path"])) == plan_id:
                del _staged[(p["host_id"], u["upload_path"])]
    return p


def staged_owner(host_id: int, path) -> int | None:
    """The user whose live plan staged `path` on this host, or None."""
    pid = _staged.get((host_id, path)) if isinstance(path, str) else None
    p = _plans.get(pid) if pid else None
    return p["user_id"] if p else None
