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


def _bad_path(p):
    return not p or len(p) > 4096 or "\0" in p or p.startswith("/") or ".." in p.split("/")


def operation_args(operation, *, path="", revision="", message="", orig=""):
    if operation in {"diff", "staged_diff", "untracked_diff", "stage", "unstage"}:
        # Literal root-relative file paths, never options or pathspec expressions.
        if _bad_path(path):
            _bad()
    # A staged rename needs BOTH sides reset, or the delete of the original stays staged.
    if operation == "unstage" and orig and _bad_path(orig):
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
        return ["reset", "-q", "HEAD", "--", path] + ([orig] if orig else [])
    if operation == "commit":
        if not message.strip() or len(message) > 4096 or "\0" in message:
            _bad()
        return ["commit", "-m", message]
    _bad()


# Root discovery (physical worktree top) shared by reads and writes.
_DISCOVER_ROOT = '''wt_git_cwd=$PWD
wt_git_root=$PWD
while [ ! -e "$wt_git_root/.git" ]; do
    [ "$wt_git_root" != / ] || break
    wt_git_root=${wt_git_root%/*}
    [ -n "$wt_git_root" ] || wt_git_root=/
done
[ -e "$wt_git_root/.git" ] || wt_git_root=$wt_git_cwd
'''

# Reads run against a throwaway git dir WE control, that borrows the repo's objects, refs, HEAD,
# index and logs as DATA (never its config). The repo's own config/config.worktree/commondir — the
# only place a clean/smudge/process filter, textconv or external diff driver is DEFINED — is never
# loaded, so no such program can run on a read, whatever a .gitattributes (in-tree OR info/attributes)
# assigns, and regardless of whether the agent is root or unprivileged. Global/system config and
# attribute files are excluded too. This needs no safe.directory and no --attr-source, so it works on
# old Git. Trade-off: diff/status compare raw content without custom filters (e.g. Git-LFS smudging).
# Writes are NOT isolated: stage/commit keep Git's normal ownership trust and the guardrail, and abort
# on a cross-owner repo, so a filter there runs only for a repo the writer already owns.
_ISOLATE_READS = r'''wt_gf="$wt_git_root/.git"
if [ -d "$wt_gf" ]; then wt_gd=$wt_gf; wt_common=$wt_gf
elif [ -f "$wt_gf" ]; then
    wt_gd=$(sed -n 's/^gitdir: *//p' "$wt_gf" 2>/dev/null | head -n1)
    [ -n "$wt_gd" ] || { echo "not a git repository (bad gitdir link)" >&2; exit 128; }
    case "$wt_gd" in /*) ;; *) wt_gd="$wt_git_root/$wt_gd" ;; esac
    if [ -f "$wt_gd/commondir" ]; then
        wt_c=$(head -n1 "$wt_gd/commondir" 2>/dev/null)
        case "$wt_c" in /*) wt_common=$wt_c ;; *) wt_common="$wt_gd/$wt_c" ;; esac
    else wt_common=$wt_gd; fi
else echo "not a git repository" >&2; exit 128; fi
wt_tmp=$(mktemp -d "${TMPDIR:-/tmp}/wt-git-ro.XXXXXX") || exit 1
trap 'rm -rf "$wt_tmp"' EXIT INT TERM
mkdir -p "$wt_tmp/objects/info" "$wt_tmp/info"
if grep -q 'objectformat *= *sha256' "$wt_common/config" 2>/dev/null; then
    printf '[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n' > "$wt_tmp/config"
else printf '[core]\n\trepositoryformatversion = 0\n' > "$wt_tmp/config"; fi
# Carry back ONLY non-executable settings a faithful read needs: branch tracking (upstream +
# ahead/behind) and the status-correctness toggles. Strict allowlist, never filter/diff/textconv/
# hooks/pager/include/url/credential/alias/... — that would defeat the isolation. --no-includes so
# an attacker's include chain is not traversed; each value is set with `git config`, never executed.
for wt_cf in "$wt_common/config" "$wt_gd/config.worktree"; do
    [ -f "$wt_cf" ] || continue
    for wt_k in $(git config -f "$wt_cf" --no-includes --name-only --list 2>/dev/null); do
        case "$wt_k" in
          branch.*.remote|branch.*.merge|branch.*.rebase|remote.*.fetch|\
          core.filemode|core.ignorecase|core.symlinks|core.bare|core.logallrefupdates|\
          core.precomposeunicode|core.protecthfs|core.protectntfs)
            wt_v=$(git config -f "$wt_cf" --no-includes --get "$wt_k" 2>/dev/null) \
              && git config -f "$wt_tmp/config" "$wt_k" "$wt_v" 2>/dev/null ;;
        esac
    done
done
printf '%s\n' "$wt_common/objects" > "$wt_tmp/objects/info/alternates"
[ -f "$wt_common/objects/info/alternates" ] && cat "$wt_common/objects/info/alternates" >> "$wt_tmp/objects/info/alternates"
cp "$wt_gd/HEAD" "$wt_tmp/HEAD" 2>/dev/null || printf 'ref: refs/heads/master\n' > "$wt_tmp/HEAD"
ln -s "$wt_common/refs" "$wt_tmp/refs" 2>/dev/null
[ -e "$wt_common/packed-refs" ] && ln -s "$wt_common/packed-refs" "$wt_tmp/packed-refs"
[ -e "$wt_gd/logs" ] && ln -s "$wt_gd/logs" "$wt_tmp/logs"
[ -d "$wt_gd/worktrees" ] && ln -s "$wt_gd/worktrees" "$wt_tmp/worktrees"
# Shallow graft and the local exclude file are data, not executable config: a shallow clone's
# history traversal fails without "shallow", and status is noisy without info/exclude. We take
# exclude by itself (never info/attributes, which is the filter-assignment vector).
[ -e "$wt_common/shallow" ] && cp "$wt_common/shallow" "$wt_tmp/shallow"
[ -e "$wt_common/info/exclude" ] && ln -s "$wt_common/info/exclude" "$wt_tmp/info/exclude"
'''


def command(cwd, operation, **params):
    """Build the shell command for one fixed Git panel operation.

    Reads are config-isolated (see _ISOLATE_READS); writes run against the real repo with Git's
    normal ownership trust and the guardrail. The physical worktree root is discovered without
    parsing untrusted config.
    """
    if not cwd.startswith("/") or "\0" in cwd:
        raise ApiError(400, "git.cwdAbsolute", "cwd must be an absolute path")
    args = operation_args(operation, **params)
    readonly = operation not in WRITE_OPS
    script = 'cd -P -- ' + shlex.quote(cwd) + ' || exit\n' + _DISCOVER_ROOT
    quoted = " ".join(shlex.quote(a) for a in args)
    if readonly:
        script += _ISOLATE_READS
        script += ('GIT_OPTIONAL_LOCKS=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null'
                   ' GIT_ATTR_NOSYSTEM=1 GIT_INDEX_FILE="$wt_gd/index"'
                   ' git -C "$wt_git_root" --git-dir="$wt_tmp" --work-tree="$wt_git_root"'
                   ' --no-pager --literal-pathspecs'
                   ' -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null '
                   + quoted + '\n')
        script += 'wt_rc=$?\nrm -rf "$wt_tmp"\ntrap - EXIT\nexit $wt_rc\n'
    else:
        script += ('exec env GIT_OPTIONAL_LOCKS=0 git --no-pager --literal-pathspecs'
                   ' -c core.fsmonitor=false -C "$wt_git_root" ' + quoted)
    cmd = "/bin/sh -c " + shlex.quote(script)
    if len(cmd) > 16000:
        raise ApiError(400, "run.tooLong", "command too long")
    # Match guardrails against the equivalent visible Git action, not the shell wrapper.
    guard = " ".join(shlex.quote(a) for a in ["git", "-C", cwd, *args])
    return cmd, guard
