# Git panel: supervision lens, read isolation, access diagnosis

The Git toolbox began as a status list for the terminal's own repository. It is now a
**supervision lens**: you point it at any absolute path — typically a folder an AI agent is
working in — and watch what happens there (Changes, Commits, Branches, and the reflog as an
Activity feed, with history rewrites tinted). Because it reads repositories that the person
operating the browser does not own, and repositories that another, less-trusted user may control,
the interesting parts of its design are all about *whose identity a read runs as* and *what a
repository is allowed to make a read do*.

This note records three decisions, in the order they were forced, and why each is the way it is.

## The identity invariant

A Git read does **not** run as whoever you have become in the terminal with `su`/`sudo su`. It
runs as the **agent's own OS account** — `ptyd.py`'s process identity on that host, which is
often an unprivileged `webterm`, and sometimes `root`. The terminal and the panel are separate
channels: changing user in the shell changes your *shell*, not the agent process that the panel
talks to.

This is not a limitation to be worked around; it is the boundary that makes supervision safe (the
panel cannot be steered into reading something by what you type in the shell). But it has a direct
consequence: **to read a folder, either the files are readable by the agent account, or the agent
runs as `root`** (which has implicit access to everything). There is no third option, and in
particular no amount of `su` in the terminal creates one.

Everything below follows from taking that invariant seriously.

## Reads run in configuration isolation (3.6.27)

A repository is attacker-controlled data when you are supervising someone else's work. Git, by
design, lets a repository's own configuration run programs during ordinary read operations —
`filter.*.clean`/`.smudge`/`.process`, `diff.*.textconv`, external diff drivers, hooks, the pager,
signature verification, fsmonitor. A `git status` or `git diff` on a hostile repo could therefore
execute code **as the agent account** — which, when the agent is root, is RCE as root from merely
*viewing* a folder.

The earlier attempts to contain this (3.6.26) tried to trust the repo just enough to read it while
disabling each known program hook, and — for `.git/info/attributes`, the one attribute layer with
no suppression flag — dropping to the git-dir owner for the read. Two gaps remained and were both
reproduced: the owner-drop keyed off the owner of the `.git` *entry*, so a root-owned `.git` file
pointing at another user's metadata skipped the drop and a filter ran as root; and an unprivileged
agent reading another account's repo ran that repo's filter as the agent.

**Decision: don't trust the repo's configuration at all for reads.** A read is executed against a
throwaway, application-controlled `GIT_DIR` that borrows the real repository's **objects, refs,
HEAD, index and logs as data** (alternates for objects; symlinks/`GIT_INDEX_FILE` for the rest)
and never loads the repository's `config`, `config.worktree`, an `include`, the commondir, or
global/system config. A clean/smudge filter, textconv or external diff driver is therefore never
*defined* while a read runs, so none can run — whatever `.gitattributes` (in-tree or
`info/attributes`) assigns, and whether the agent is root or unprivileged. This also removed the
dependency on `--attr-source`, so reads work on older Git.

The honest trade-off: diff and status compare **raw** object content, without the repository's
custom filters, so output can differ for repositories that depend on them (Git-LFS is the obvious
case). We accept that for reads — correctness of a supervision view is worth less than the
guarantee that viewing cannot execute code. **Writes are unchanged**: staging and committing keep
Git's normal ownership trust, abort on a cross-owner repository, and go through the command
guardrail — so a filter on a write only ever runs for a repo the writer already owns.

Lesson worth keeping: the fix is to **isolate the configuration**, not to chase the owner, the
attribute source, or the privilege level. Every version of "trust it a little, then disable the
dangerous bits" left a bit undisabled.

## Diagnosing why a folder won't open — and offering one safe fix (3.6.28)

Given the identity invariant, the common failure is mundane: the agent is `webterm`, the repo
lives at `/home/alice/project`, and `/home/alice` is `0750`. The repo itself may be
world-readable, but the agent cannot *traverse* the home to reach it. The panel used to show one
generic "permission" message for this — and the identical message for a simple typo in the path.

The feature splits that into facts, and then applies policy on top of the facts:

- **The agent reports facts.** On a `cd` failure the agent walks the path top-down, finds the
  first component that is missing (`ENOENT`) or un-enterable (`EACCES`), `stat`s it, and prints a
  single control-character-delimited line of facts to stdout: the error code, the blocking
  component, its owner (uid + name), its group (gid + name), and the agent's own identity
  (uid + name). The `cd`'s own stderr is suppressed so it cannot leak a path or be mistaken for
  output.
- **Python applies policy.** `parse_diag()` lifts that line out of the output; `access_fix()`
  decides what, if anything, to offer. A **missing** directory is reported as missing, with no
  fix (it is almost always a typo). A directory the agent genuinely cannot traverse is reported
  with the account that blocks it.

### Decision: what fix we are willing to propose, and what we never propose

This is the part worth reading carefully, because the user set the boundary explicitly:
*"if the user wants something else, they'll do it themselves directly — we don't propose it."*

We offer a **single** command, and only in one shape:

```
sudo usermod -aG <the blocking directory's own group> <agent account>
sudo systemctl restart webterm-agent
```

— pre-filled with the real names, **typed into the terminal for the person to review and run**
(bracketed paste at a prompt, never executed for them; a Copy button otherwise, reusing the same
`rootmove.ts` path as every other "type this for me" affordance). It is offered **only** when all
of these hold:

- the agent is **not** already root (if it were, the read would have succeeded — this flow never
  fires for a root agent);
- the blocking component is under `/home/`;
- the owner uid **and** group gid are both ≥ 1000 (a real human account, not a system one);
- the group name is a valid POSIX name and is **not** in a denylist of privileged/shared groups
  (`root`, `sudo`, `wheel`, `docker`, `adm`, `users`, …);
- both the group and agent names match a strict POSIX pattern.

The command is assembled **server-side from those validated names only**, so it can never become
`usermod -aG root …`, `usermod -aG docker …`, or a `chmod` on a system path. Anything outside the
one safe case — a system path, a root-owned directory, a privileged group, a numeric or non-POSIX
name — produces a plain explanation and **no command at all**.

Two things we deliberately did **not** do:

- **No `chmod`.** Loosening the mode on someone's home (or anywhere) is a bigger, vaguer change
  than adding the agent to the directory's existing group, and far easier to get dangerously
  wrong. Group membership is the smallest grant that fixes the stated problem.
- **No "fix whatever is blocking you" generality.** A naive version of this feature would read the
  blocking component and propose opening *it* — which, pointed at `/usr/sbin` or a privileged
  group, would be a one-click privilege escalation suggested *by WebTerm*. The gate exists so the
  tool's own suggestion can never be the dangerous thing. The person remains free to do anything
  else themselves; we simply refuse to be the one proposing it.

## Where the code lives

- `gateway/app/gitpanel.py` — `_ISOLATE_READS` (the throwaway-GIT_DIR read model), `_cd_or_diag()`
  (the fact-gathering probe), `parse_diag()`, `access_fix()` (the policy gate above), and the
  denylists/patterns it uses.
- `gateway/app/api.py` — the `host_git` endpoint parses the diagnosis and attaches an `access`
  object to the response (for reads and writes; normally `null`).
- `frontend/src/components/GitPanel.tsx` — the supervision UI, and the "can't open" block that
  renders the four states (missing / blocked-with-offer / blocked-no-offer / legacy).
- `frontend/src/lib/rootmove.ts` — the shared "type this command at a prompt for review" helper.
- `tests/git_panel_test.py` — the read-isolation regression tests (cross-owner, unprivileged
  agent, `.git`-file pointer, `info/attributes`) and the full policy-gate matrix plus real
  dropped-privilege `EACCES`/`ENOENT` diagnoses.

See the [CHANGELOG](../../CHANGELOG.md) entries for 3.6.27 (read isolation) and 3.6.28 (access
diagnosis) for the user-facing summaries.
