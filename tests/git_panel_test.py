"""Git panel: real Git in temporary repositories behind the authenticated API."""
import asyncio
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time

import rbac_util as U
from app import authz, core, db, gitpanel

check = U.Checker()


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True).stdout


class LocalAgent(core.AgentConnection):
    async def run_command(self, cmd, timeout):
        p = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=timeout)
        return {"ok": True, "exit_code": p.returncode, "stdout": p.stdout, "stderr": p.stderr}

    async def request(self, op, **kwargs):
        assert op == "session_cwd"
        return {"ok": True, "cwd": self.cwd}


async def content_filter_tests(base, agent):
    """The exact production command must not run clean/smudge/process, even cross-owner."""
    repo = base / "filtered-repo"
    repo.mkdir()
    git(repo, "init"); git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    f = repo / "evil.txt"; f.write_text("aaaa\n")
    (repo / ".gitattributes").write_text("*.txt filter=pwn\n")
    git(repo, "add", "."); git(repo, "commit", "-m", "unfiltered baseline")
    f.write_text("bbbb\n")
    stamp = f.stat().st_mtime + 2
    os.utime(f, (stamp, stamp))             # same size: force actual content comparison
    marker = base / "content-filter-ran"
    driver = base / "content-filter.sh"
    driver.write_text("#!/bin/sh\nid -u > " + shlex.quote(str(marker)) + "\ncat\n")
    driver.chmod(0o755)
    git(repo, "config", "filter.pwn.clean", str(driver))
    git(repo, "config", "filter.pwn.smudge", str(driver))
    # Positive control: without the panel's isolation this really does execute code.
    git(repo, "-c", "core.fsmonitor=false", "diff", "--no-ext-diff", "--no-textconv", "--", "evil.txt")
    check("clean-filter positive control executes the fixture", marker.exists())
    marker.unlink()
    async def inspect(label):
        for op, params in [("status", {}), ("diff", {"path": "evil.txt"}),
                           ("staged_diff", {"path": "evil.txt"}),
                           ("untracked_diff", {"path": "evil.txt"})]:
            cmd, _ = gitpanel.command(str(repo), op, **params)
            r = await agent.run_command(cmd, 30)
            check(label + " " + op + " blocks content filters",
                  r["exit_code"] in (0, 1) and not marker.exists(), str(r)[:200])
            if marker.exists():
                marker.unlink()
    await inspect("same-owner clean/smudge")
    git(repo, "config", "filter.pwn.process", str(driver))
    await inspect("process filter")
    git(repo, "config", "--unset", "filter.pwn.process")
    if os.geteuid() == 0:
        os.chown(repo, 65534, 65534)
        await inspect("cross-owner clean/smudge")
        os.chown(repo, os.geteuid(), os.getegid())
    if os.geteuid() == 0:
        # $GIT_DIR/info/attributes is a layer --attr-source cannot suppress. A filter assigned there
        # must still never run as a more-privileged user than the repo's git-dir owner: a root read
        # of a repo owned by another user is re-executed as that owner.
        ia = base / "info-attr-repo"; ia.mkdir()
        git(ia, "init"); git(ia, "config", "user.name", "x"); git(ia, "config", "user.email", "x@y.z")
        (ia / "g.txt").write_text("aaaa\n"); git(ia, "add", "."); git(ia, "commit", "-m", "base")
        (ia / "g.txt").write_text("bbbb\n")
        rootmark = base / "info-attr-ran-as-root"
        asroot = base / "asroot.sh"
        asroot.write_text('#!/bin/sh\n[ "$(id -u)" = 0 ] && : > ' + shlex.quote(str(rootmark)) + '\ncat\n')
        asroot.chmod(0o755)
        git(ia, "config", "filter.pwn.clean", str(asroot))
        (ia / ".git" / "info" / "attributes").write_text("g.txt filter=pwn\n")
        base.chmod(0o755)
        subprocess.run(["chown", "-R", "65534:65534", str(ia)], check=True)
        try:
            for op, params in [("status", {}), ("diff", {"path": "g.txt"})]:
                cmd, _ = gitpanel.command(str(ia), op, **params)
                r = await agent.run_command(cmd, 30)
                check("info/attributes filter is confined to the owner, never root (" + op + ")",
                      not rootmark.exists() and r["exit_code"] in (0, 1), str(r)[:200])
                if rootmark.exists():
                    rootmark.unlink()
        finally:
            subprocess.run(["chown", "-R", "%d:%d" % (os.geteuid(), os.getegid()), str(ia)], check=True)
    # Configured includes must not restore an executable driver in the read view.
    include = base / "included-filter.config"
    include.write_text('[filter "pwn"]\nclean = ' + str(driver) + '\nsmudge = ' + str(driver) + '\n')
    git(repo, "config", "--unset", "filter.pwn.clean")
    git(repo, "config", "--unset", "filter.pwn.smudge")
    git(repo, "config", "include.path", str(include))
    await inspect("included filter")
    git(repo, "config", "--unset", "include.path")
    previous = {k: os.environ.get(k) for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM")}
    try:
        os.environ["GIT_CONFIG_GLOBAL"] = str(include)
        os.environ["GIT_CONFIG_SYSTEM"] = str(include)
        os.environ.pop("GIT_CONFIG_NOSYSTEM", None)
        await inspect("global/system filter")
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    # A .git FILE pointing to another location's metadata must not run the pointed-to config's
    # filter (isolation borrows objects/refs/index as data, never the pointed-to config).
    gm = base / "gitfile-meta"; gm.mkdir()
    git(gm, "init"); git(gm, "config", "user.name", "x"); git(gm, "config", "user.email", "x@y.z")
    (gm / "p.txt").write_text("one\n"); git(gm, "add", "."); git(gm, "commit", "-m", "b")
    gm_marker = base / "gitfile-ran"
    gm_drv = base / "gitfile-drv.sh"
    gm_drv.write_text("#!/bin/sh\nid -u > " + shlex.quote(str(gm_marker)) + "\ncat\n"); gm_drv.chmod(0o755)
    git(gm, "config", "filter.pwn.clean", str(gm_drv))
    (gm / ".git" / "info" / "attributes").write_text("p.txt filter=pwn\n")
    view = base / "gitfile-view"; view.mkdir()
    (view / "p.txt").write_text("two\n")
    (view / ".git").write_text("gitdir: " + str(gm / ".git") + "\n")
    cmd, _ = gitpanel.command(str(view), "diff", path="p.txt")
    r = await agent.run_command(cmd, 30)
    check("a .git-file pointer never runs the pointed-to config's filter",
          not gm_marker.exists() and r["exit_code"] in (0, 1), str(r)[:200])

    git(repo, "update-index", "--split-index")
    cmd, _ = gitpanel.command(str(repo), "diff", path="evil.txt")
    r = await agent.run_command(cmd, 30)
    check("split-index diff is preserved", r["exit_code"] == 0 and "+bbbb" in r["stdout"], str(r)[:200])


async def main():
    await U.boot()
    original = core.source_for
    agent = LocalAgent.__new__(LocalAgent)
    try:
        with tempfile.TemporaryDirectory(prefix="wt-git-test-") as tmp:
            base = Path(tmp)
            # Ignore the operator machine's global trust/config and sudo identity in fixtures.
            os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
            os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
            os.environ.pop("SUDO_UID", None)
            repo = base / "repo with 'quotes'"
            repo.mkdir()
            git(repo, "init"); git(repo, "config", "user.name", "Fixture")
            git(repo, "config", "user.email", "fixture@example.invalid")
            sub = repo / "sub"; sub.mkdir()
            file = sub / "a.txt"; file.write_text("before\n")
            git(repo, "add", "."); git(repo, "commit", "-m", "fixture")
            file.write_text("after\n")
            owner = await U.owner_client()
            hid = await U.add_host(owner, "git-fixture")
            other = await U.add_host(owner, "other-fixture")
            sid = await U.add_session(hid)
            agent.cwd = str(sub)
            core.source_for = lambda host_id: agent
            core.sources[hid] = agent

            async def call(operation=None, cwd=sub, client=owner, **body):
                if operation is not None:
                    body["operation"] = operation
                return await client.post(f"/api/hosts/{hid}/git", json={"cwd": str(cwd), **body})

            async def good(operation, **params):
                r = await call(operation, **params)
                check(operation + " accepted", r.status_code == 200, r.text[:150])
                return r.json()

            r = await good("root")
            check("subfolder discovers actual root", r["stdout"].rstrip("\n") == str(repo))
            r = await good("status")
            check("status contains literal root-relative path", " M sub/a.txt\0" in r["stdout"])
            r = await good("diff", path="sub/a.txt")
            check("diff from subfolder shows actual changes", "+after" in r["stdout"] and r["exit_code"] == 0)
            weird = 'space -> ă\n"quote".txt'
            (repo / weird).write_text("new file\n")
            r = await good("status")
            check("status preserves unicode, newline, quotes and arrow", "?? " + weird + "\0" in r["stdout"])
            r = await good("untracked_diff", path=weird)
            check("untracked diff preserves literal filename", r["exit_code"] == 1 and "+new file" in r["stdout"])
            marker = base / "driver-ran"
            driver = base / "driver.sh"
            driver.write_text("#!/bin/sh\nprintf executed > " + shlex.quote(str(marker)) + "\nprintf converted\\n\n")
            driver.chmod(0o755)
            (repo / ".gitattributes").write_text("*.txt diff=fixture\n")
            git(repo, "config", "diff.fixture.textconv", str(driver))
            git(repo, "config", "diff.fixture.command", str(driver))
            git(repo, "config", "core.fsmonitor", str(driver))
            r = await good("diff", path="sub/a.txt")
            check("diff does not invoke textconv/external driver", not marker.exists() and "+after" in r["stdout"])
            await good("status")
            check("status does not invoke fsmonitor", not marker.exists())
            head = git(repo, "rev-parse", "HEAD").strip()
            for op, fields in [("commits", {}), ("branches", {}), ("activity", {}), ("show", {"revision": head})]:
                r = await good(op, **fields)
                check(op + " exits successfully", r["exit_code"] == 0)
            check("history never invokes drivers", not marker.exists())

            outside = base / "outside.txt"; outside.write_text("keep\n")
            before = git(repo, "reflog")
            hostile = [["diff", "--output=" + str(outside)], ["reflog", "expire", "--expire=all", "--all"],
                       ["reflog", "delete", "HEAD@{0}"], ["log", "--output=" + str(outside)],
                       ["diff", "--ext-diff", "--", "sub/a.txt"], ["show", "--textconv", "HEAD"],
                       ["commit", "--no-verify", "-m", "bad"], ["status", "--porcelain", "--branch", "--short"]]
            for args in hostile:
                r = await call(args=args)
                check("reject unsafe legacy arguments " + args[0], r.status_code == 400, r.text[:100])
            check("outside file not overwritten", outside.read_text() == "keep\n")
            check("reflog not pruned", git(repo, "reflog") == before)
            for fields in [{"path": "../outside.txt"}, {"path": str(outside)}, {"path": "bad\0file"}]:
                r = await call("diff", **fields)
                check("reject path traversal/absolute/NUL", r.status_code == 400)
            r = await call("show", revision="HEAD --output=bad")
            check("reject revision/options injection", r.status_code == 400)
            r = await call("status", args=["status"])
            check("reject contradictory request formats", r.status_code == 400)
            # A shell-looking filename remains data, including command substitutions.
            injection = "$(touch marker); file.txt"; (repo / injection).write_text("literal\n")
            r = await good("untracked_diff", path=injection)
            check("shell metacharacters remain literal", "+literal" in r["stdout"] and not (repo / "marker").exists())

            await db.execute("INSERT INTO app_settings(key,value) VALUES('command_guard',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                             json.dumps({"enabled": True, "rules": [{"pattern": "git.*add", "action": "block"},
                                                                      {"pattern": "git.*reset", "action": "confirm"}]}))
            r = await call("stage", path="sub/a.txt")
            check("structured stage obeys guardrail", r.status_code == 403 and "guardrail" in r.text)
            r = await call(args=["add", "--", "sub/a.txt"])
            check("legacy stage obeys same guardrail", r.status_code == 403)
            r = await call("unstage", path="sub/a.txt")
            check("unstage requires configured confirmation", r.status_code == 409 and "guardrail" in r.text)
            r = await call("unstage", path="sub/a.txt", confirmed=True)
            check("confirmed unstage succeeds", r.status_code == 200 and r.json()["exit_code"] == 0)
            await db.execute("UPDATE app_settings SET value=? WHERE key='command_guard'", json.dumps({"enabled": False, "rules": []}))
            r = await good("stage", path="sub/a.txt")
            check("stage from subfolder succeeds", r["exit_code"] == 0)
            r = await good("staged_diff", path="sub/a.txt")
            check("staged diff shows changes", "+after" in r["stdout"])
            # Drop the clean filter settings before testing a normal trusted write.
            r = await good("commit", message="panel fixture commit")
            check("trusted commit succeeds", r["exit_code"] == 0)

            # A staged rename must unstage BOTH sides, or the delete of the original stays staged.
            rn = base / "rename-repo"; rn.mkdir()
            git(rn, "init"); git(rn, "config", "user.name", "x"); git(rn, "config", "user.email", "x@y.z")
            (rn / "old.txt").write_text("hi\n"); git(rn, "add", "."); git(rn, "commit", "-m", "base")
            git(rn, "mv", "old.txt", "new.txt")
            r = (await call("status", cwd=rn)).json()
            check("staged rename shows R with both paths", "R  new.txt\0old.txt\0" in r["stdout"], str(r)[:150])
            r = await call("unstage", cwd=rn, path="new.txt", orig="old.txt")
            check("rename unstage accepted", r.status_code == 200 and r.json()["exit_code"] == 0, r.text[:150])
            r = (await call("status", cwd=rn)).json()
            check("rename unstage resets BOTH sides (no staged delete left)",
                  " D old.txt\0" in r["stdout"] and "?? new.txt\0" in r["stdout"] and "R  " not in r["stdout"], str(r)[:150])
            r = await call("unstage", cwd=rn, path="new.txt", orig="../escape")
            check("unstage rejects a traversal in orig", r.status_code == 400)

            # Config isolation must keep non-executable fidelity: upstream/ahead-behind, the local
            # ignore + filemode toggles, and shallow-clone history (all regressed in the first pass).
            bare = base / "upstream.git"; subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
            up = base / "up"; up.mkdir()
            git(up, "init"); git(up, "config", "user.name", "x"); git(up, "config", "user.email", "x@y.z")
            (up / "f.txt").write_text("one\n"); git(up, "add", "."); git(up, "commit", "-m", "c1")
            git(up, "remote", "add", "origin", str(bare)); git(up, "push", "-q", "origin", "master")
            git(up, "branch", "--set-upstream-to=origin/master", "master")
            (up / "f.txt").write_text("one\ntwo\n"); git(up, "add", "."); git(up, "commit", "-m", "c2")
            r = (await call("status", cwd=up)).json()
            check("isolation keeps upstream + ahead/behind", "## master...origin/master [ahead 1]\0" in r["stdout"], str(r)[:150])
            git(up, "config", "core.filemode", "false")
            (up / ".git" / "info" / "exclude").write_text("ignored.log\n")
            (up / "ignored.log").write_text("x\n"); os.chmod(up / "f.txt", 0o755)
            r = (await call("status", cwd=up)).json()
            check("isolation honors core.filemode=false and info/exclude",
                  "f.txt" not in r["stdout"] and "ignored.log" not in r["stdout"], str(r)[:150])
            deep = base / "deep"; deep.mkdir()
            git(deep, "init"); git(deep, "config", "user.name", "x"); git(deep, "config", "user.email", "x@y.z")
            for i in range(4):
                (deep / "f.txt").write_text("l%d\n" % i); git(deep, "add", "."); git(deep, "commit", "-m", "c%d" % i)
            shal = base / "shal"
            subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + str(deep), str(shal)], check=True)
            r = (await call("commits", cwd=shal)).json()
            check("isolation loads shallow-clone history (no parent-traversal crash)", r["exit_code"] == 0, str(r)[:150])

            # Ownership checks must remain on writes even though safe reads work cross-user.
            if os.geteuid() == 0:
                os.chown(repo, 65534, 65534)
                r = await good("status")
                check("cross-owner read works from subfolder", r["exit_code"] == 0)
                await good("diff", path="sub/a.txt")
                check("cross-owner read cannot execute repository config", not marker.exists())
                r = await good("stage", path="sub/a.txt")
                check("cross-owner write keeps Git ownership protection", r["exit_code"] != 0 and "dubious ownership" in r["stderr"])
                os.chown(repo, os.geteuid(), os.getegid())
                base.chmod(0o755)
                repo.chmod(0o755)
                def unprivileged():
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)
                cmd, _ = gitpanel.command(str(sub), "status")
                r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True,
                                   preexec_fn=unprivileged, timeout=30)
                check("unprivileged agent can inspect a readable cross-owner repo", r.returncode == 0, r.stderr)
                repo.chmod(0o700)
                r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True,
                                   preexec_fn=unprivileged, timeout=30)
                # The read fails and leaks no repo data: git never runs, and stdout carries ONLY our
                # own access diagnosis (directory metadata anyone could already `stat`), not status.
                _, d = gitpanel.parse_diag(r.stdout)
                check("safe reads never bypass private directory permissions",
                      r.returncode != 0 and bool(d) and d["code"] == "EACCES" and d["comp"] == str(repo),
                      r.stdout[:120] or r.stderr)
                repo.chmod(0o755)

            # A role with run but without files.read can still discover its terminal directory.
            uid = await U.add_user("run-only@example.invalid")
            rid = await db.execute("INSERT INTO roles(name,perms,builtin,created,updated) VALUES(?,?,0,?,?)", "Run only", '["run"]', time.time(), time.time())
            await db.execute("INSERT INTO role_bindings(user_id,role_id,scope_kind,scope_value,source,created) VALUES(?,?,'host',?,'manual',?)", uid, rid, str(hid), time.time())
            authz.bump_epoch()
            run_only = await U.login("run-only@example.invalid")
            r = await call("cwd", client=run_only, sid=sid)
            check("run-only role can discover cwd", r.status_code == 200 and r.json().get("cwd") == str(sub), r.text[:100])
            r = await run_only.get(f"/api/hosts/{hid}/fs/cwd?sid={sid}")
            check("files.read remains required on file API", r.status_code == 403)
            other_sid = await U.add_session(other)
            r = await call("cwd", client=run_only, sid=other_sid)
            check("cwd rejects another host's session", r.status_code == 404)
            viewer = await U.add_user("viewer@example.invalid", bindings=[("viewer", "all", "")])
            assert viewer
            view_client = await U.login("viewer@example.invalid")
            r = await call("status", client=view_client)
            check("viewer without run cannot use Git", r.status_code == 403)
            # A missing directory is diagnosed as "missing" through the API (even root gets ENOENT,
            # not EACCES, here) and never carries a fix command.
            r = await good("root", cwd=base / ("nope-" + os.urandom(3).hex()))
            acc = r.get("access") or {}
            check("missing directory → access.reason 'missing', no command",
                  acc.get("reason") == "missing" and acc.get("offer") is False and not acc.get("command"), str(acc))
            await run_only.aclose(); await view_client.aclose(); await owner.aclose()
            # Normal worktrees (.git file) retain root-relative paths too.
            wt = base / "worktree"
            git(repo, "worktree", "add", "-b", "fixture-wt", str(wt))
            (wt / "sub" / "a.txt").write_text("worktree change\n")
            cmd, _ = gitpanel.command(str(wt / "sub"), "diff", path="sub/a.txt")
            r = await agent.run_command(cmd, 30)
            check("linked worktree/subfolder diff works", r["exit_code"] == 0 and "+worktree change" in r["stdout"])
            if os.geteuid() == 0:
                os.chown(wt, 65534, 65534)
                r = await agent.run_command(cmd, 30)
                check("cross-owner linked worktree diff works", r["exit_code"] == 0 and "+worktree change" in r["stdout"], str(r)[:200])
                os.chown(wt, os.geteuid(), os.getegid())
            # ── Access diagnosis: why a directory can't be opened, and the one safe fix we offer ──
            # Policy gate (deterministic): we offer ONLY `usermod` into a real user's own NAMED group,
            # for a path under a home — never for system paths, a root agent, privileged or numeric
            # groups, low ids, or non-POSIX names (so the command can never become dangerous).
            def diagf(**kw):
                d = dict(code="EACCES", comp="/home/alice", ouid="1000", ouser="alice",
                         ggid="1000", ggroup="alice", auid="1000", auser="webterm")
                d.update(kw); return d
            off = gitpanel.access_fix(diagf())
            check("home + user-private group → offers scoped usermod",
                  off["offer"] and off["command"] == "sudo usermod -aG alice webterm && sudo systemctl restart webterm-agent", str(off))
            check("agent running as root → never offers a grant", not gitpanel.access_fix(diagf(auid="0"))["offer"])
            check("path outside /home → never offers a grant", not gitpanel.access_fix(diagf(comp="/usr/sbin"))["offer"])
            check("root-owned directory → never offers a grant", not gitpanel.access_fix(diagf(ouid="0", ggid="0", ggroup="root"))["offer"])
            check("privileged group → never offers a grant", not gitpanel.access_fix(diagf(ggroup="docker"))["offer"])
            check("system gid → never offers a grant", not gitpanel.access_fix(diagf(ggid="27", ggroup="sudo"))["offer"])
            check("numeric (unnamed) group → never offers a grant", not gitpanel.access_fix(diagf(ggroup="1000"))["offer"])
            check("agent name must be POSIX → no command injection", not gitpanel.access_fix(diagf(auser="x;reboot"))["offer"])

            if os.geteuid() == 0:
                def nobody():
                    os.setgroups([]); os.setgid(65534); os.setuid(65534)
                base.chmod(0o755)
                # Real EACCES from a dropped-privilege agent, blocked by a non-home directory → facts,
                # then policy says "system" (no command).
                sysp = base / "sysblk"; (sysp / "repo").mkdir(parents=True)
                os.chown(sysp, 4242, 4242); sysp.chmod(0o750)
                cmd, _ = gitpanel.command(str(sysp / "repo"), "root")
                p = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, preexec_fn=nobody, timeout=30)
                _, d = gitpanel.parse_diag(p.stdout)
                check("dropped agent on unreadable dir → EACCES fact names the blocking component",
                      bool(d) and d["code"] == "EACCES" and d["comp"] == str(sysp) and d["auid"] == "65534", str(d))
                check("EACCES outside /home → policy 'system', no command",
                      gitpanel.access_fix(d)["reason"] == "system" and not gitpanel.access_fix(d)["offer"])
                # Blocked by a real user home → EACCES fact carries the owner and a /home path.
                hp = Path("/home") / ("wt-git-acl-" + os.urandom(4).hex())
                (hp / "repo").mkdir(parents=True)
                os.chown(hp, 4242, 4242); hp.chmod(0o750)
                try:
                    cmd, _ = gitpanel.command(str(hp / "repo"), "root")
                    p = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, preexec_fn=nobody, timeout=30)
                    _, d = gitpanel.parse_diag(p.stdout)
                    check("dropped agent blocked by a /home dir → EACCES fact under /home with owner",
                          bool(d) and d["code"] == "EACCES" and d["comp"] == str(hp) and d["comp"].startswith("/home/") and d["ouid"] == "4242", str(d))
                finally:
                    subprocess.run(["rm", "-rf", str(hp)])

            await content_filter_tests(base, agent)
    finally:
        core.source_for = original
        core.sources.clear()
        await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
