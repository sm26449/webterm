# Fleet console

Three things that capitalize on what makes WebTerm unique — it knows the whole
fleet and treats commands as objects (OSC 133): per-command actions, running the
same command across multiple hosts, and a searchable global history.

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

## Running across multiple hosts

One command → N hosts → a grid of results. The **"Run on multiple hosts"** button
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

## Saved fleet commands

In the fleet console, press **Save command** to name the command you just typed; it
appears as a chip you can click to reload it, or remove with ×. Saved commands live in
your **browser** (localStorage), not on the gateway — they are a personal convenience,
not shared state, and there is deliberately no in-gateway scheduler (that would break
the "single replica, no always-on background state" design; use the host's own cron or
an automation token for scheduled runs).

## Fleet-scale onboarding

Adding hosts one at a time is fine for a handful; for a real fleet, use a **group
enrollment token**.

1. **Settings → Security → Fleet enrollment.** Give the token a name, an expiry, an
   optional **max-uses** cap (0 = unlimited), an optional **folder** the new hosts land
   in, and whether new hosts should **require 2FA**. Creating it re-authenticates and
   asks for your second factor — a reusable token that can register hosts is a
   provisioning-class credential.
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
markers (no agent change); fleet runs are written automatically. Persisted in
`command_history` (the last ~10,000). A single account → the history is like
`~/.bash_history`, only searchable everywhere.

## Security

The [single-account invariant](../README.md#security) applies: anyone who gets
past login administers all hosts. Commands and history run at the same access level
as the interactive shell — no new privileges. Fleet runs and history require either an
authenticated browser session or an automation token with the `run` scope; hosts marked
"require 2FA" refuse automation tokens outright.
