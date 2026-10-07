# Run on hosts

Three things that capitalize on what makes WebTerm unique — it knows the whole
fleet and treats commands as objects (OSC 133): per-command actions, **Run on hosts**
(the same command on several hosts at once), and a searchable global history.

## Command-block actions

With [shell integration](SHELL-INTEGRATION.md) active, every command in the
**Commands** panel gets quick actions on hover:

- **Run again** — puts the command at the prompt, but **does not press Enter**: you
  see it and run it yourself. Deliberate — an old command re-executed blindly (an
  `rm`, a deploy) is exactly the accident to avoid.
- **copy command** — the command line itself.
- **copy output** — just the output bytes (no prompt, no command line).
- **copy as markdown** — command + output + exit code + duration in a ` ```console `
  block, ready to paste into a ticket or chat.

## Running a command on several hosts

One command → N hosts → a grid of results. The **"Run on hosts"** button
in the sidebar opens a three-step flow:

1. **Pick** the hosts (tick them / "all online"). Works on hosts with an **agent**.
2. Type the command.
3. **Confirm** — a deliberate step: "⚠ You're running on N hosts", the command plus
   the list, and the host count repeated on the button (`Run on 5 hosts`), so a
   broadcast to production can't happen by accident.

Then the **grid** fills in live as each host responds: per host — a status dot, exit
code, one line of output; click a row → full output. "Copy report" gives the whole
table as markdown.

**How it runs:** one request per host, in parallel (no "job" state on the server).
The agent runs the command in your login shell (`bash -lc`), captures
stdout/stderr plus the exit code, with a timeout (max 300s) and an output cap
(256 KB). No new privileges — the agent already runs commands as you in the PTY.

<a id="saved-fleet-commands"></a>

## Saved commands

A command saved in Run on hosts **is a snippet**: the same server-side store you reach from the
terminal (`Alt+S`, the command palette, Toolbox → Library). Save a command once and it is
there on every device, in Run on hosts and in the terminal.

- **Save.** Type a command, name it and press **Save command**. Saving a name that
  already exists with a different command asks before replacing it.
- **Targets by tag (optional).** Tick **Remember target tags: prod, web** before saving and
  the snippet keeps the tags of the hosts you selected. Picking that command later selects
  the **online** agent hosts that carry **any** of those tags, and a line says how many it
  matched ("matches 3 online hosts"). You can still change the selection before running.
  Only a snippet's explicit tags select hosts: a command without targets leaves your
  selection alone, and nothing is selected when Run on hosts opens.
- **Parameters.** `{{param}}` placeholders work as in the terminal: picking such a command
  shows a field per parameter and the final command; **Continue** stays disabled until
  every parameter is filled.
- **Rename (✎) and delete (×)** change the snippet itself, so the terminal sees the change
  too. Commands with targets are listed first and show their tags as `#tag` chips.
- Target tags can also be edited wherever snippets are edited (Alt+S → Manage, Toolbox →
  Library). They are normalised like host tags (lowercase, no duplicates, 32 characters);
  more than 20 distinct tags is refused.

**Migration from older versions.** Up to 3.5.3 saved commands lived only in the
browser (localStorage key `wt-fleet-saved`). The first time you open Run on hosts
after upgrading, each of them is uploaded as a snippet (the saved name becomes the title;
a command whose body already exists as a snippet is skipped). The local key is removed only
after every upload succeeded; if one fails, the key stays and the next opening retries,
skipping what already made it. Two tabs opening at once are serialised by a short-lived
lock in localStorage, so nothing is uploaded twice. Commands saved in another browser
migrate when Run on hosts is opened there.

There is deliberately no in-gateway scheduler (that would break the "single replica, no
always-on background state" design; use the host's own cron or an automation token for
scheduled runs). The snippet API (`/api/snippets`) is browser-session only: automation
tokens get 401.

<a id="fleet-scale-onboarding"></a>

## Bulk enrollment

Adding hosts one at a time is fine for a handful; for a real fleet, use a **group
enrollment token**.

1. **+ host → "Many machines".** Group-token creation lives in the Add-host flow, behind
   the **"One host / Many machines"** switch — where you'd look to add hosts, not three
   levels deep in settings. Give the token a name, an expiry, an optional **max-uses** cap
   (0 = unlimited), an optional **folder** the new hosts land in, and whether new hosts
   should **require 2FA**. Creating it re-authenticates and asks for your second factor — a
   reusable token that can register hosts is a provisioning-class credential. (The tokens
   you've created are **listed and revoked** under **Settings → Security**, which is the
   credential-management surface — not where you create them.)
2. You get **one install one-liner**, shown once. Run it on every machine (config
   management, a `for` loop over SSH, a golden image's first-boot script, …).
3. Each run **auto-creates a new host** with its **own** agent token and dials back in.
   The host appears with a placeholder name that is replaced by the machine's hostname
   on first connect.

**Why this is safe.** The group token only *authorizes creation* — it never becomes the
credential a machine keeps. Every machine ends up with its own per-host token, so you can
revoke one machine without touching the others (exactly like a hand-added host). The group
token itself is **revocable** (Settings → Security; already-enrolled machines keep
working, no new machine can enroll), **expires**, and is **use-capped** (enforced
atomically, so concurrent installs can't overshoot the cap). Every auto-enrollment is
written to the **audit log** (actor `group:<name>`) and raises a **security alert**
(email + webhook), so an unexpected enrollment is visible immediately.

## Global command history

Search **all** the commands you've run — across every host and session, in one
place. It's also a **lightweight audit log** ("what did I run, where, when").

Open it from the **command palette** (⌘/Ctrl+Shift+K → "Command history"): live
search, filter by host, per-command status + exit code + cwd + relative time, copy,
"clear history".

**Source:** interactive commands are reported by the client from the OSC 133
markers (no agent change); commands sent with Run on hosts are written automatically (labelled *Run on hosts*). Persisted in
`command_history` (the last ~10,000). A single account → the history is like
`~/.bash_history`, only searchable everywhere.

## Security

The [single-account invariant](../README.md#security) applies: anyone who gets
past login administers all hosts. Commands and history run at the same access level
as the interactive shell — no new privileges. Run on hosts requires either an
authenticated browser session or an automation token with the `run` scope (the global
history is browser-session only); hosts marked
"require 2FA" refuse automation tokens outright.
