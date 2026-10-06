# Command guardrail (Settings → Security)

A list of regular expressions that catch commands you almost never mean to run —
`rm -rf /`, `mkfs`, `dd of=/dev/…`, `DROP TABLE` — and either ask **"are you sure?"** or
refuse them outright. It is there for the tired-operator moment: the wrong tab, the wrong
host, a pasted line that was meant for a scratch VM. Use it to protect against your own
typos, and against scripts and automation tokens that call the fleet `run` endpoint.

It is **a safety net, not a barrier**. Anyone who is past login can turn it off, and a
terminal session can always run a command the guardrail would have stopped (see
[Where it applies](#where-it-applies)). Do not treat it as an access-control layer.

## What it is for

- **Catching mistakes before they execute.** A matching command is either held for a
  confirmation dialog (`confirm`) or refused (`block`).
- **Making fleet-wide commands deliberate.** In **Run on fleet**, a matching command asks
  once — *"This command matches a guardrail rule (/…/) and will run on ALL selected hosts.
  Continue?"* — before anything is dispatched.
- **Holding automation to the same rules.** Automation tokens with the `run` scope go
  through the same server-side check as the fleet console; see
  [AUTOMATION-TOKENS.md](AUTOMATION-TOKENS.md).

It is on by default and ships with six `confirm` rules:

| Pattern | Catches |
|---|---|
| `\brm\s+(-[a-z]*r[a-z]*f\|-[a-z]*f[a-z]*r\|-r\s+-f\|-f\s+-r)\s+/` | `rm -rf /…`, `rm -fr /…`, `rm -r -f /…` on an absolute path |
| `\bmkfs\b` | creating a filesystem |
| `\bdd\b.*\bof=/dev/` | `dd` writing to a device |
| `:\s*\(\s*\)\s*\{.*:\s*\|\s*:` | the classic bash fork bomb |
| `\bDROP\s+(DATABASE\|TABLE)\b` | dropping a database or table |
| `>\s*/dev/sd` | redirecting output onto a raw disk |

(`\|` in the table is just Markdown escaping; the stored pattern has a plain `|`.)

## Rules: confirm vs block

Each rule is a pattern plus an action. The editor is in **Settings → Security → Command
guardrail**: the **Check dangerous commands on Enter** switch, one row per rule (pattern,
`confirm`/`block`, ✕ to delete), **+ add rule**, and **Save guardrail**. Nothing applies
until you press Save; the server then validates every pattern, and the open terminals in
this browser pick up the new rules straight away.

| Action | In a terminal | In Run on fleet | Via `POST /api/hosts/{id}/run` |
|---|---|---|---|
| `confirm` | Enter is held; a *Potentially dangerous command* dialog shows the line, with **Cancel (clear)** (focused by default) and **Run**. Escape = cancel. | One dialog for the whole run, **Run on all** to continue | `409 run.guardConfirm` unless the request carries `"confirmed": true` |
| `block` | Enter is swallowed, Ctrl+U is sent to clear the line, and *Blocked by guardrail: …* shows for 4 s | Refused before dispatch: *Blocked by the guardrail* | `403 run.guardBlocked`, always — no flag overrides it |

**`block` rules win.** Every `block` rule is checked before any `confirm` rule, on the
client and on the server alike, so the order of the list doesn't matter: a command that
matches both is blocked. (Before 3.5.1 the first match in list order won, which let a broad
`confirm` rule above a `block` rule turn the block into a mere confirmation.)

Cancelling a confirmation in the terminal also clears the line (Ctrl+U), so a stray second
Enter does not run it.

## Where it applies

| Path | Checked by | Enforced? |
|---|---|---|
| **Run on fleet** (Fleet console) | the browser before dispatch, **and** the server on each host's `/run` | yes, server-side |
| **Automation tokens** (`run` scope → `POST /api/hosts/{id}/run`) | the server | yes, server-side |
| **Panel actions** (since 3.5.2): Services start/stop/restart, Docker start/stop/restart, Git add/reset/restore/commit | the server, on the equivalent shell command (`systemctl stop nginx.service`, `docker restart web1`, `git -C /repo reset -- a.txt`) | yes, server-side; the panel asks you on a `confirm` rule |
| **Commands typed in a terminal** | the browser, at Enter | only with shell integration, and only in the browser |

**Server-side, on `/run`.** `POST /api/hosts/{id}/run` is a clean choke point, so the
gateway re-checks every command there regardless of the client: `block` → 403,
`confirm` → 409 unless `confirmed` is true. The server cannot open a dialog, so
`confirmed: true` means "a human (or a script that knows what it is doing) already said
yes". The fleet console sends it after asking you; a token caller sets it itself.

**In a terminal, only with shell integration.** The gateway does not inspect the keystroke
stream of a PTY. The check runs in the browser, when a key submits the line — **Enter**
(also with Shift or Ctrl) or **Ctrl+J**: it reads the line you typed from the screen, from the end of the
prompt (the OSC 133 `B` marker) to the cursor. Without
[shell integration](SHELL-INTEGRATION.md) there is no prompt marker, so there is nothing to
check and Enter passes straight through. Inside a full-screen program (vim, htop, less —
the alternate screen) the check is skipped too.

**Why it's a safety net, not a barrier.** In the terminal the check is client-side and
heuristic, so it is easy to step around, deliberately or not:

- multi-line pasted text is checked line by line: if any line matches a rule, the paste is
  held back (paste the lines one at a time, so Enter checks each); "paste and run" from the
  clipboard history pastes without the Enter in that case. Single-line pastes are checked
  when you press Enter, like typing;
- the line is read from the screen up to the cursor, so text to the right of the cursor,
  aliases, variables and scripts are invisible to it (`rm -rf "$DIR"` with `DIR=/` is not
  `rm -rf /`);
- a host without shell integration is not covered at all;
- anyone signed in can switch the guardrail off in Settings.

Read-only panel calls (git status/diff, Docker lists and logs, the services list) are not
checked: they change nothing, and they run on every refresh.

## Writing patterns

- **Search, not full match.** A rule fires if the pattern matches **anywhere** in the
  command. Anchor with `^` / `$` when you mean the whole line.
- **Always case-insensitive.** The server uses Python `re.search` with `re.IGNORECASE`;
  the browser uses JavaScript `new RegExp(pattern, 'i')`. `drop table` matches
  `DROP\s+TABLE`.
- **No multiline flag.** `^` is the start of the whole command (leading and trailing
  whitespace are trimmed first), not the start of each line.
- **Stay in the common subset of Python and JavaScript regex.** The server validates with
  Python's `re.compile`; the terminal and fleet checks run the same pattern as a JavaScript
  `RegExp`. A pattern that is valid only in Python (e.g. a named group written `(?P<name>…)`)
  saves fine and works on `/run`, but the browser silently skips it — so it would not
  protect the terminal. Stick to `\b`, `\s`, `\d`, character classes, groups, alternation
  and simple quantifiers.

Examples:

| Pattern | Action | Effect |
|---|---|---|
| `rm\s+-rf\s+/` | `block` | `rm -rf /`, `rm -rf /var/lib/…` (but not `rm -fr /` — the built-in rule covers both orders) |
| `^reboot` | `confirm` | `reboot`, `reboot now` — **not** `sudo reboot` (use `\breboot\b` for that) |
| `^(sudo\s+)?(reboot\|poweroff\|shutdown)\b` | `confirm` | the same, with or without `sudo` |
| `DROP\s+TABLE` | `confirm` | `drop table users;` in a `psql -c` or `mysql -e` line |
| `\bterraform\s+destroy\b` | `block` | refuses `terraform destroy` everywhere |
| `\bkubectl\b.*\bdelete\s+(ns\|namespace)\b` | `confirm` | deleting a Kubernetes namespace |

**What the server refuses at save** (`400`, nothing is stored):

- an invalid regex — *"That guardrail pattern is not a valid regular expression."*
  (`guard.badRegex`);
- a pattern that is too slow — *"… too slow to evaluate (catastrophic backtracking) —
  simplify it."* (`guard.regexTooSlow`). Each new pattern is run against a small corpus of
  long, uniform strings (runs of letters, digits, spaces, `/`, `.`, `_`, `\`, `:` ending in a
  character that breaks the match — the shape that makes `(a+)+$` blow up), with the same
  **0.25 s** budget used at run time. Nested quantifiers such as `(a+)+`, `(\w+\s?)+$` fail
  this; `.*` chains such as `.*.*=` pass.

Empty patterns are dropped silently. Patterns are trimmed and cut to 300 characters.

## Limits

- **100 rules**, **300 characters** per pattern (extra rules and characters are dropped
  when the setting is saved or loaded).
- **0.25 s per rule per command on `/run`.** Matching runs in a separate, minimal Python
  process that is killed when a rule exceeds the budget, so a pathological pattern cannot
  hang the request or burn the gateway's CPU. A rule that times out is **skipped** for
  that command (it does not block or confirm it), and the skip is written to the audit log
  as principal `system:guardrail`, status `408`, with the rule's pattern. If you see those
  entries, simplify the rule.
- **Patterns must be valid in both Python and JavaScript.** The server matches with Python
  `re`, the terminal with the browser's `RegExp`. Settings refuses a pattern the browser
  can't compile (e.g. `(?P<name>…)`), so a rule can't silently stop working in the terminal.
  Prefer syntax common to both; `\A`/`\Z` compile in JS but mean something else there.
- **A rule whose regex fails to compile on the server** (only possible if the stored
  setting was edited outside the UI) is ignored on `/run`, not treated as a match.
- **`/run` commands are limited to 8000 characters**; longer commands are refused before
  the guardrail runs (`400 run.tooLong`).
- **One global rule set.** There are no per-host or per-user rules; the rules apply to every
  host.
- **Browsers pick up changes from the app state.** The browser where you press Save
  refreshes immediately; another browser or device that already has WebTerm open keeps the
  rules it loaded until it reloads the app state. The fleet console always fetches the
  current rules before a run, and the server always uses the saved ones.
- **Block rules win.** When a `block` and a `confirm` rule both match, the command is blocked,
  whatever their order in the list (since 3.5.1).
- **Turning it off** (`Check dangerous commands on Enter` unchecked, then Save) disables
  every check: terminal, fleet console, panel actions and the server-side `/run` check.

## Maintenance notes

- Backend: `gateway/app/api.py` — `COMMAND_GUARD_DEFAULT`, `_load_command_guard`,
  `_match_guard_rule`, `_enforce_guard` (used by `host_run`, `host_git` writes, `docker_action`,
  `service_action`), `GET`/`POST /api/settings/command-guard`;
  the time-budgeted matcher is `security.regex_search_budget` (`REGEX_BUDGET = 0.25`) in
  `gateway/app/security.py`. Stored in the `command_guard` setting as JSON.
- Frontend: `matchCommandRule` and `pendingCommand` in `frontend/src/lib/commands.ts`; the
  Enter handler and the confirm dialog in `components/SessionView.tsx`; the fleet check in
  `components/FleetRunModal.tsx`; the editor in `components/settings/SecurityTab.tsx`.
