"""Fixed Git panel operations. No client-controlled Git options or config execution on reads."""
import re
import shlex

from .errors import ApiError

US = "\x1f"
WRITE_OPS = frozenset({"stage", "unstage", "commit"})


def _bad():
    raise ApiError(400, "git.badSubcommand", "unsupported git operation or arguments")


def legacy_operation(args):
    """Accept only the former panel's exact shapes for tabs cached across an upgrade."""
    fixed = {
        ("rev-parse", "--show-toplevel"): "root",
        ("status",): "legacy_status",
        ("status", "--porcelain", "--branch"): "legacy_status",
        ("log", "--max-count=50", "--format=%H" + US + "%h" + US + "%an" + US + "%ar" + US + "%s"): "commits",
        ("for-each-ref", "--sort=-committerdate", "--count=200",
         "--format=%(HEAD)" + US + "%(refname:short)" + US + "%(upstream:short)" + US
         + "%(upstream:track)" + US + "%(committerdate:relative)", "refs/heads"): "branches",
        ("reflog", "--max-count=50", "--format=%h" + US + "%gd" + US + "%gs"): "activity",
    }
    if tuple(args) in fixed:
        return fixed[tuple(args)], {}
    for prefix, op in [(["diff", "--"], "diff"), (["diff", "--staged", "--"], "staged_diff"),
                       (["diff", "--no-index", "--", "/dev/null"], "untracked_diff"),
                       (["add", "--"], "stage"), (["reset", "--"], "unstage"),
                       (["reset", "-q", "HEAD", "--"], "unstage")]:
        if len(args) == len(prefix) + 1 and args[:-1] == prefix:
            return op, {"path": args[-1]}
    if len(args) == 3 and args[:2] == ["commit", "-m"]:
        return "commit", {"message": args[2]}
    if len(args) == 5 and args[:4] == ["show", "--no-color", "--stat", "-p"]:
        return "show", {"revision": args[4]}
    _bad()


def operation_args(operation, *, path="", revision="", message=""):
    if operation in {"diff", "staged_diff", "untracked_diff", "stage", "unstage"}:
        # Literal root-relative file paths, never options or pathspec expressions.
        if (not path or len(path) > 4096 or "\0" in path or path.startswith("/")
                or ".." in path.split("/")):
            _bad()
    diff = ["--no-ext-diff", "--no-textconv", "--no-color", "--ignore-submodules=all"]
    if operation == "root":
        return ["rev-parse", "--show-toplevel"]
    if operation in {"status", "legacy_status"}:
        return ["status", "--porcelain", *(["-z"] if operation == "status" else []),
                "--branch", "--untracked-files=all", "--ignore-submodules=all"]
    if operation == "diff":
        return ["diff", *diff, "--", path]
    if operation == "staged_diff":
        return ["diff", *diff, "--staged", "--", path]
    if operation == "untracked_diff":
        return ["diff", *diff, "--no-index", "--", "/dev/null", path]
    if operation == "commits":
        return ["log", "--no-show-signature", "--max-count=50", "--format=%H" + US + "%h" + US + "%an" + US + "%ar" + US + "%s"]
    if operation == "branches":
        return ["for-each-ref", "--sort=-committerdate", "--count=200",
                "--format=%(HEAD)" + US + "%(refname:short)" + US + "%(upstream:short)" + US
                + "%(upstream:track)" + US + "%(committerdate:relative)", "refs/heads"]
    if operation == "activity":
        return ["reflog", "show", "--no-show-signature", "--max-count=50", "--format=%h" + US + "%gd" + US + "%gs"]
    if operation == "show":
        if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", revision):
            _bad()
        return ["show", *diff, "--no-show-signature", "--stat", "-p", revision, "--"]
    if operation == "stage":
        return ["add", "--", path]
    if operation == "unstage":
        return ["reset", "-q", "HEAD", "--", path]
    if operation == "commit":
        if not message.strip() or len(message) > 4096 or "\0" in message:
            _bad()
        return ["commit", "-m", message]
    _bad()


def command(cwd, operation, **params):
    """Discover the physical worktree root without parsing untrusted Git configuration.

    Worktree .git files are handled by Git itself. We never add trust for writes: hooks,
    clean filters and signing are executable configuration and require Git's normal trust.
    The readonly exception is per invocation, scoped to the discovered worktree root.
    """
    if not cwd.startswith("/") or "\0" in cwd:
        raise ApiError(400, "git.cwdAbsolute", "cwd must be an absolute path")
    args = operation_args(operation, **params)
    readonly = operation not in WRITE_OPS
    base = ["git", "--no-pager", "--literal-pathspecs", "-c", "core.fsmonitor=false"]
    if readonly:
        # Reads enable safe.directory to view a repo owned by another user, which also makes Git
        # trust that repo's config — where a clean/smudge/process filter, a textconv or an external
        # diff driver could run as the (possibly more-privileged) agent. A filter only fires if some
        # .gitattributes assigns it, so we read attributes from the EMPTY TREE instead of the
        # worktree/index/HEAD (see --attr-source below): no path is assigned any driver, whatever the
        # config defines or where it comes from. core.attributesFile and GIT_ATTR_NOSYSTEM close the
        # per-user and system attribute files too. Writes deliberately keep Git's normal trust and
        # abort cross-owner, so they are left untouched.
        #
        # --attr-source cannot suppress $GIT_DIR/info/attributes (a separate, highest-precedence
        # layer with no override flag). So, as a second line, a read running as root against a repo
        # whose .git is owned by another user is re-executed AS that owner (see setpriv below): any
        # filter that still fires, via info/attributes or otherwise, runs with no more privilege than
        # whoever controls the repo's git dir — never as root. A root-owned .git means only root could
        # have planted a filter, so no drop is needed there.
        base += ["-c", "core.hooksPath=/dev/null", "-c", "log.showSignature=false",
                 "-c", "submodule.recurse=false", "-c", "status.submoduleSummary=false",
                 "-c", "core.attributesFile=/dev/null", "-c", "safe.directory="]
    script = 'cd -P -- ' + shlex.quote(cwd) + ' || exit\n'
    script += '''wt_git_cwd=$PWD
wt_git_root=$PWD
while [ ! -e "$wt_git_root/.git" ]; do
    [ "$wt_git_root" != / ] || break
    wt_git_root=${wt_git_root%/*}
    [ -n "$wt_git_root" ] || wt_git_root=/
done
[ -e "$wt_git_root/.git" ] || wt_git_root=$wt_git_cwd
'''
    if readonly:
        # Empty-tree id for THIS repo's object format (sha1/sha256); falls back to the sha1 value.
        # It never writes and runs no filter. An old Git without --attr-source errors out below
        # rather than silently running filters (fail closed).
        script += ('wt_git_empty=$(env GIT_OPTIONAL_LOCKS=0 git -c "safe.directory=$wt_git_root"'
                   ' -C "$wt_git_root" hash-object -t tree /dev/null 2>/dev/null)\n'
                   'case "$wt_git_empty" in *[!0-9a-fA-F]*|"")'
                   ' wt_git_empty=4b825dc642cb6eb9a060e54bf8d69288fbee4904 ;; esac\n')
        # Confine any filter that info/attributes could still assign: if root and the repo's .git is
        # owned by another user, drop to that user (and its primary group, no supplementary groups).
        # setpriv is part of util-linux; if it is missing we refuse rather than read as root.
        script += ('wt_git_drop=\n'
                   'if [ "$(id -u)" = 0 ]; then\n'
                   '    wt_git_uid=$(stat -c %u "$wt_git_root/.git" 2>/dev/null || echo 0)\n'
                   '    wt_git_gid=$(stat -c %g "$wt_git_root/.git" 2>/dev/null || echo 0)\n'
                   '    case "$wt_git_uid" in ""|*[!0-9]*) wt_git_uid=0 ;; esac\n'
                   '    case "$wt_git_gid" in ""|*[!0-9]*) wt_git_gid=0 ;; esac\n'
                   '    if [ "$wt_git_uid" != 0 ]; then\n'
                   '        command -v setpriv >/dev/null 2>&1 || { echo "git panel: setpriv unavailable;'
                   ' refusing to read a repo owned by uid $wt_git_uid as root" >&2; exit 126; }\n'
                   '        wt_git_drop="setpriv --reuid=$wt_git_uid --regid=$wt_git_gid --clear-groups --"\n'
                   '    fi\n'
                   'fi\n')
    script += 'exec env GIT_OPTIONAL_LOCKS=0 '
    if readonly:
        script += 'GIT_ATTR_NOSYSTEM=1 $wt_git_drop '
    script += " ".join(shlex.quote(a) for a in base)
    if readonly:
        script += ' --attr-source="$wt_git_empty" -c "safe.directory=$wt_git_root"'
    script += ' -C "$wt_git_root" ' + " ".join(shlex.quote(a) for a in args)
    cmd = "/bin/sh -c " + shlex.quote(script)
    if len(cmd) > 16000:
        raise ApiError(400, "run.tooLong", "command too long")
    # Match guardrails against the equivalent visible Git action, not the shell wrapper.
    guard = " ".join(shlex.quote(a) for a in ["git", "-C", cwd, *args])
    return cmd, guard
