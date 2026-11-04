"""Fixed Git panel operations. No client-controlled Git options or config execution on reads."""
import re
import shlex

from .errors import ApiError

US = "\x1f"
WRITE_OPS = frozenset({"stage", "unstage", "commit"})

# ── Access diagnosis ─────────────────────────────────────────────────────────
# When the panel cannot open a directory, we don't just say "can't cd": the agent diagnoses WHY —
# as its OWN identity — and reports facts; the gateway (access_fix) decides what, if anything, to
# propose. A grant command is offered ONLY for a real user's home directory and ONLY as
# `usermod -aG <that user's own group> <agent>`. Everything else (missing path, system/root-owned,
# privileged group, or an agent already running as root) gets no command at all. The person always
# reviews and runs it themselves.
_DIAG_MARK = "\x1e"                 # RS: starts the one diagnosis line; US separates its fields
# Groups we never add the agent to (membership here is a privilege grant, not a read-access grant).
_PRIVILEGED_GROUPS = frozenset({
    "root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "libvirt", "kvm", "qemu",
    "shadow", "disk", "staff", "sys", "daemon", "bin", "systemd-journal", "systemd-network",
    "users", "tty", "dialout", "video", "audio", "cdrom", "plugdev", "netdev", "input",
})
_POSIX_NAME = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\$?$")
_SUPERVISABLE = ("/home/",)         # only ever propose a grant for a path inside a user home


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


def _cd_or_diag(cwd):
    """cd into the panel directory; on failure, emit a structured diagnosis and stop.

    The agent walks the path top-down, finds the first component that is missing (ENOENT) or that
    it cannot enter (EACCES), stats it, and prints ONE line (RS-marked, US-separated so a path with
    spaces survives) with: code, blocking component, its owner uid/name and group gid/name, and the
    agent's own uid/name. No policy here — just facts for gitpanel.access_fix."""
    q = shlex.quote(cwd)
    return (
        'wt_target=' + q + '\n'
        'if cd -P -- "$wt_target" 2>/dev/null; then :\n'
        'else\n'
        '  wt_auid=$(id -u 2>/dev/null); wt_auser=$(id -un 2>/dev/null)\n'
        '  wt_code=EACCES; wt_blk=$wt_target; wt_acc=""; wt_oifs=$IFS; IFS=/; set -f\n'
        '  for wt_seg in $wt_target; do\n'
        '    [ -n "$wt_seg" ] || continue\n'
        '    wt_acc="$wt_acc/$wt_seg"\n'
        '    if [ ! -e "$wt_acc" ]; then wt_code=ENOENT; wt_blk=$wt_acc; break; fi\n'
        '    if ! (cd -P -- "$wt_acc" 2>/dev/null); then wt_code=EACCES; wt_blk=$wt_acc; break; fi\n'
        '  done\n'
        '  IFS=$wt_oifs; set +f\n'
        '  wt_si=$(stat -c "%u %U %g %G" "$wt_blk" 2>/dev/null || echo "- - - -"); set -- $wt_si\n'
        '  printf \'\\036code=%s\\037comp=%s\\037ouid=%s\\037ouser=%s\\037ggid=%s\\037ggroup=%s\\037auid=%s\\037auser=%s\\n\''
        ' "$wt_code" "$wt_blk" "$1" "$2" "$3" "$4" "${wt_auid:--}" "${wt_auser:--}"\n'
        '  exit 128\n'
        'fi\n'
    )


def parse_diag(stdout):
    """Split the diagnosis line (if any) out of a read's stdout. Returns (clean_stdout, fields|None)."""
    if _DIAG_MARK not in stdout:
        return stdout, None
    lines = stdout.split("\n")
    for i, line in enumerate(lines):
        if line.startswith(_DIAG_MARK):
            fields = {}
            for tok in line[len(_DIAG_MARK):].split(US):
                k, _, v = tok.partition("=")
                if k:
                    fields[k] = v
            return "\n".join(lines[:i] + lines[i + 1:]), fields
    return stdout, None


def access_fix(diag):
    """Policy over the agent's facts. We ONLY ever propose `usermod -aG <user's own group> <agent>`
    for a real user's home directory; otherwise no command. Built from validated POSIX names only,
    so it can never become `usermod -aG root …` or touch a system path."""
    comp = diag.get("comp", "")
    if diag.get("code") == "ENOENT":
        return {"reason": "missing", "path": comp, "offer": False, "command": ""}
    deny = {"reason": "system", "path": comp, "offer": False, "command": ""}
    try:
        auid = int(diag.get("auid", "x"))
        ouid = int(diag.get("ouid", "x"))
        ggid = int(diag.get("ggid", "x"))
    except ValueError:
        return deny
    agent = diag.get("auser", "")
    group = diag.get("ggroup", "")
    if auid == 0:                                   # root never gets EACCES; nothing to grant
        return deny
    if not comp.startswith(_SUPERVISABLE):          # outside user homes → never propose
        return deny
    if ouid < 1000 or ggid < 1000:                  # system-owned directory or group → never propose
        return deny
    if group in _PRIVILEGED_GROUPS or not _POSIX_NAME.match(group):
        return deny
    if not _POSIX_NAME.match(agent):
        return deny
    cmd = "sudo usermod -aG %s %s && sudo systemctl restart webterm-agent" % (group, agent)
    return {"reason": "denied", "path": comp, "offer": True, "command": cmd,
            "group": group, "agent": agent}


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
    script = _cd_or_diag(cwd) + _DISCOVER_ROOT
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
