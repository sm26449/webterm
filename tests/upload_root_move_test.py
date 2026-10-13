"""3.6.9 — uploads into folders the agent's user cannot write, and agents on a too-old Python.

Hermetic (temp DB, fake agent, no network). Covers:
  * rootmove: strerror sanitising, folder/name validation, the generated inbox names, the
    `sudo install` command and its shlex round-trip — including injection attempts (quotes, $(),
    backticks, newlines, ESC, bidi overrides, NUL) — and the command EXECUTED by a real shell with a
    fake `sudo`, to prove the names land literally and nothing in them runs;
  * error mapping: files.failedReason / files.agentInternal, and the write-error enrichment
    ({user, dir[, mode]}) with a fake agent;
  * the route POST /api/hosts/{id}/fs/root-move: authentication, authorization (Viewer refused,
    Operator/Owner allowed, an Operator scoped to another host refused), validation, the agent's
    inbox path checked, the audit entry;
  * the upload route returning the enriched code end to end;
  * core.agent_python_old: the os.scandir fingerprint, the OS hint, the fs_list probe settling it,
    and the System health check.
"""
import asyncio
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
         "x;touch PWNED3", "\\", "*", "~root", "!!", "a\"b"]


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

    n1 = rootmove.inbox_name(0)
    check("inbox_name: generated (stamp + random), safe charset",
          rootmove._INBOX_NAME_RE.match(n1) is not None and n1.startswith("1970-01-01_00-00-00_root-move_"), n1)
    check("inbox_name: random part differs", rootmove.inbox_name(0) != rootmove.inbox_name(0))

    plan = rootmove.build(INBOX, "/srv/it's $(x)", NASTY)
    srcs = [u["upload_path"] for u in plan["uploads"]]
    check("build: one staged file per name, all under the inbox, names never in the staged path",
          len(srcs) == len(NASTY) and all(s.startswith(INBOX + "/") for s in srcs)
          and not any(n in s.rsplit("/", 1)[1] for n, s in zip(NASTY, srcs) if len(n) > 2))
    argv = shlex.split(plan["command"])
    want = []
    for i, (n, s) in enumerate(zip(NASTY, srcs)):
        if i:
            want.append("&&")
        want += ["sudo", "install", "-m", "0644", "--", s, "/srv/it's $(x)/" + n]
    want += ["&&", "rm", "-f", "--"] + srcs
    check("build: the command parses to EXACTLY the intended argv", argv == want)
    check("build: no newline / control characters in the command",
          "\n" not in plan["command"] and not rootmove.has_bad_chars(plan["command"]))
    check("build: root folder → /<name>", shlex.split(rootmove.build(INBOX, "/", ["a"])["command"])[6] == "/a")
    for bad, what in ((["a", "a"], "duplicates"), ([], "no files"), (["x"] * 21, "too many")):
        try:
            rootmove.build(INBOX, "/srv", bad)
            check("build: refuses " + what, False)
        except rootmove.MoveError:
            check("build: refuses " + what, True)
    for inbox in ("relative/.webterm/inbox", "/home/x/other", "/home/x/.webterm/inbox/", "/a\n/.webterm/inbox", ""):
        try:
            rootmove.build(inbox, "/srv", ["a"])
            check("build: refuses agent inbox %r" % inbox, False)
        except rootmove.MoveError:
            check("build: refuses agent inbox %r" % inbox, True)


def shell_checks():
    """The command, run by a real /bin/sh with a fake `sudo` (exec "$@"): every nasty name lands
    literally, nothing in a name or the folder executes, staged files are removed."""
    print("── rootmove: the command executed by a real shell")
    base = tempfile.mkdtemp()
    try:
        inbox = os.path.join(base, "home", ".webterm", "inbox")
        target = os.path.join(base, "srv", "it's $(touch PWNED0) `touch PWNED00`")
        os.makedirs(inbox)
        os.makedirs(target)
        bindir = os.path.join(base, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "sudo"), "w") as f:
            f.write('#!/bin/sh\nexec "$@"\n')
        os.chmod(os.path.join(bindir, "sudo"), 0o755)
        plan = rootmove.build(inbox, target, NASTY)
        for i, u in enumerate(plan["uploads"]):
            with open(u["upload_path"], "w") as f:
                f.write("content-%d" % i)
        env = dict(os.environ, PATH=bindir + ":" + os.environ.get("PATH", "/usr/bin:/bin"))
        r = subprocess.run(["/bin/sh", "-c", plan["command"]], cwd=base, env=env,
                           capture_output=True, text=True, timeout=30)
        check("shell: the command succeeds", r.returncode == 0, r.stderr[-300:])
        landed = sorted(os.listdir(target))
        check("shell: every name landed literally in the target folder", landed == sorted(NASTY), landed)
        ok_content = all(open(os.path.join(target, n)).read() == "content-%d" % i for i, n in enumerate(NASTY))
        check("shell: each file has its own content", ok_content)
        check("shell: installed with mode 0644",
              all(oct(os.stat(os.path.join(target, n)).st_mode & 0o777) == "0o644" for n in NASTY))
        check("shell: the staged inbox files were removed", os.listdir(inbox) == [])
        pwned = []
        for root, _dirs, files in os.walk(base):
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

    async def fs_write_bin(self, path, offset, block, timeout=60.0):
        d = os.path.dirname(path)
        if d in self.deny:
            return {"ok": False, "id": 1, "code": "fs_error", "msg": "%s: Permission denied" % path}
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
            if kw["path"] in self.deny:
                return {"ok": True, "exists": True, "size": 4096, "dir": True, "mode": 0o755}
            return {"ok": True, "exists": False, "size": 0}
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


async def route_checks(owner, hid):
    print("── POST /fs/root-move")
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
        check("Operator with files.write → 200 + plan", r.status_code == 200 and j.get("command"), r.text[:200])
        r = await owner.post(url, json={"dir": "/srv/bin/lists", "names": ["it's", "$(id)"]})
        j = r.json()
        check("Owner → 200; command round-trips to the intended argv",
              r.status_code == 200 and shlex.split(j["command"])[:7]
              == ["sudo", "install", "-m", "0644", "--", j["uploads"][0]["upload_path"], "/srv/bin/lists/it's"],
              j)
        check("staged files are in the agent's inbox, named by WebTerm",
              all(u["upload_path"].startswith(INBOX + "/") and "root-move_" in u["upload_path"] for u in j["uploads"]))
        check("the agent was asked to create its inbox", ("fs_mkdir", {"path": rootmove.INBOX_REL, "parents": True}) in fake.calls)
        row = await db.fetchone("SELECT detail FROM audit_log WHERE path=? ORDER BY id DESC LIMIT 1", url)
        check("audited: 'upload and move as root … (command typed, not run)'",
              row and "move as root" in row["detail"] and "not run" in row["detail"], row and row["detail"])
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
        r = await owner.post(url, json={"dir": "/srv/x", "names": ["f%d" % i for i in range(21)]})
        check("more than 20 names → 422", r.status_code == 422, r.status_code)
        fake.inbox = "/tmp/evil"
        r = await owner.post(url, json={"dir": "/srv/x", "names": ["a"]})
        check("an unexpected inbox path from the agent → refused (no command)",
              r.status_code == 400 and "command" not in r.json(), r.text[:120])
    finally:
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
    await python_checks(owner)
    await db.close()
    return check.summary()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
