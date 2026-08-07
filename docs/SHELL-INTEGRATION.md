# Shell integration (OSC 133) — commands as objects

With integration enabled, terminal output is no longer an amorphous stream: every
command has an identity — **exit code, duration, its own output**. It is the same idea
as the "blocks" other modern terminals offer, with one deliberate constraint: **we
re-render nothing**, we only annotate the stream, so vim, htop, `less` and Claude Code
work exactly as before.

## What you gain

| Situation | Without integration | With integration |
|---|---|---|
| A command that fails silently (`systemctl reload`, `docker compose up -d`) | you only find out if you type `echo $?` | red dot + exit code, immediately |
| You want a command's output (for a ticket, a chat) | you select through the scrollback with the mouse | "copy the output" → exactly its bytes, no prompt |
| You ran an `apt upgrade` with 400 lines | you scroll | `Alt+↑` jumps straight to the previous command |
| "Why did the deploy take so long?" | you don't know | the duration of each command, in the panel |
| An hour-long debugging session | scrollback | the panel = a map of what you did, what worked, what didn't |

## How to enable it

In the host's session, press the **`⌘`** button in the toolbar → **"Enable shell
integration"**. The application **types the command into the terminal** (you see it,
so you know exactly what runs on your server). The command:

1. downloads `~/.webterm/shell-integration.sh` (~7 KB) using `python3` (the only
   dependency the agent requires anyway);
2. appends to `~/.bashrc` / `~/.zshrc` (idempotent — running it repeatedly doesn't
   duplicate):
   ```sh
   # WebTerm shell integration (OSC 133)
   [ -f ~/.webterm/shell-integration.sh ] && . ~/.webterm/shell-integration.sh
   ```
3. activates it immediately in the current session.

**On new hosts it is installed with the agent** (since v1.0.125): the enrollment
installer fetches the script, verifies its **sha256** (computed by the gateway when it
generated that installer, so the two can't drift), writes it `0600` and appends the same
rc line — then prints which file it touched. Skip it with
`WEBTERM_NO_SHELL_INTEGRATION=1` before the install command; if the download or hash
check fails, the agent still installs and the UI activation stays available.

**Disabling**: delete the two lines from the rc file (or `rm
~/.webterm/shell-integration.sh` — the line becomes a no-op). Nothing else is left
behind.

## How it works

The script emits OSC 133 markers at each prompt:

| Marker | When | What it means |
|---|---|---|
| `A` | before the prompt | the prompt begins |
| `B` | end of the prompt (bash) / `precmd`, i.e. before it (zsh) | the typed command starts here |
| `C` | after Enter (PS0) | execution begins → output starts here |
| `D;<cod>` | before the next prompt | the command finished, with its exit code |

The frontend (`lib/commands.ts`) turns them into objects, tied to the buffer via
xterm markers (they survive scrollback).

### tmux

Sequences emitted from a pane **don't** reach the outer terminal unless they're
wrapped in DCS passthrough, and the tmux server must accept passthrough. The script
does both by itself:

```sh
tmux set -g allow-passthrough on      # once, at source time
printf '\033Ptmux;\033\033]133;%s\007\033\\' "$1"   # wrap for tmux
```

Verified on tmux 3.4 with a real pty: the markers (including the exit codes) reach
the browser intact.

### Why the screen is not a source of truth under tmux

Passthrough delivers the markers **out of band**: tmux forwards them to the client
immediately, while the pane's content is repainted separately, with absolute cursor
moves. **The order is not preserved.** Captured bytes from a real session:

```
ESC[11;1H            cursor to the start of the line
ESC]133;B            ← the marker arrives HERE, cursor still at column 1
ESC[11;1Hroot@host:~#   ← only now is the prompt painted
echo hello
ESC]133;C
```

Anything derived from *where the cursor is* when a marker arrives is therefore wrong
under tmux. That produced three symptoms that looked unrelated (all fixed in
v1.0.128–134):

- the command text read from the buffer became `root@host:~# ls` instead of `ls`,
  polluting the ⌘ panel, the global history and "copy command";
- "copy output" delivered other people's prompts and commands — or nothing at all,
  depending on timing;
- the browser stayed stuck in tmux's alternate screen (tmux enters it when a client
  attaches and leaves at detach), which killed scrollback *and* silently dropped every
  marker, because the tracker deliberately ignores markers in the alternate screen.

**Invariants that keep this fixed — don't "simplify" them back:**

1. **The command text comes from the shell, not the screen** — marker `E;<command>`
   (bash: `history 1` inside PS0; zsh: `$1` in `preexec`), stripped of ESC/BEL/newline.
   Screen reading survives only as a fallback for hosts still on an older script.
2. **The output is captured from the stream** between `C` and `D`
   (`CommandTracker.feed`), not read from rows; control sequences are stripped at copy
   time, `\r` reduced to the line's final state. Cap: 256 KB per command.
3. **The replayed tail never counts as live activity** — OSC 133 markers are ignored
   while history is being written, and the tracker is reset first. Otherwise every
   reconnect re-reports "commands" built from replayed rows.
4. **Alternate-screen switches are stripped from the replay** (`core.read_tail`), always.
   Fresh sessions carry tmux's unmatched `ESC[?1049h`; long-lived ones "worked" only
   because it had scrolled out of the 256 KB window.

The E2E suite (`scripts/e2e-session.mjs`) covers all of this **with tmux installed** in
the smoke container. Running it on the `pty` fallback tests a different backend than
production — that gap is exactly why these bugs lived so long.

## Security

- **Install-time integrity**: the activation command arrives over the authenticated
  channel (browser ↔ gateway, TLS) and includes the script's **sha256**; the
  download verifies it before writing and sourcing it. A MITM on the fetch can't
  substitute the script, not even on deployments with `WEBTERM_AGENT_INSECURE=1`
  (unverified TLS).
- **`WEBTERM_AGENT_INSECURE=1` is strictly for dev / IP access with a self-signed
  certificate. Don't set it in production** — it disables TLS verification on
  fetches. A normal deployment (domain + Let's Encrypt) doesn't use it.
- **tmux passthrough on the pane, not global**: the script asks for
  `allow-passthrough` on the session's pane (`set -p`), not on the whole tmux server,
  so a hostile process in another session cannot inject uncensored DCS sequences.
  On tmux older than 3.3 `set -p` is not accepted for this option and the script
  **falls back to `set -g`**, which turns passthrough on server-wide. That fallback
  exists so shell integration works at all on older tmux; if the pane-scoped
  guarantee matters to you, run tmux ≥ 3.3.
- The file is written with `600` permissions (directory `700`) regardless of umask
  — it's sourced in every shell, so it must not be writable by other users.

## OSC 7 — the current directory (cwd)

Besides the OSC 133 markers, the integration also emits **OSC 7**
(`file://host/path`) at each prompt, reporting the current directory. With it, the
**file panel follows the `cd` from the terminal** — it moves through the UI along
with you. Like OSC 133, it's wrapped in tmux passthrough, so it works in tmux
sessions too. The host part of the URL is cosmetic (the UI uses only the path).
Without integration active, the panel stays on manual navigation — clean
degradation.

## Known limitations

- **Alternate screen** (vim, htop, `less`): the markers are ignored while it's
  active — those rows disappear on exit, so markers wouldn't make sense. The command
  that started the TUI closes normally on exit.
- **"Copy the output" refuses** if it can't extract the output with certainty (the
  command is still running, the rows have scrolled out of the scrollback).
  Deliberate: the text lands in the clipboard and, pasted into a shell, would
  **execute** — better a message than the wrong slice. (A real regression, v1.0.20 →
  fixed in v1.0.21.)
- Without integration active, **nothing changes** — clean degradation.

## Testing

`scripts/e2e-session.mjs` (run in CI, against a real agent) covers: activation, the
commands appearing, capturing the exit code, **the exact clipboard contents**
("contains the output", "does NOT contain the prompt"), and continued recording
after noisy output.
