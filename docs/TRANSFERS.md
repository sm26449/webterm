# Transfers

How files move between your browser and a host, and — the part that matters for AI CLIs —
how a screenshot in your clipboard becomes a **path** a tool on the host can open.

Everything here uses the agent's existing file API (`fs` list / mkdir / upload / delete). No
gateway or agent change was needed; a host that already runs the agent has all of it.

## Where transfers show up

- **Transfers chip** in the tab strip (right end, next to the split-view chips; shown only while
  jobs exist — on every page: sessions, host pages and the Dashboard, so a running upload is never
  out of sight when you switch context):
  `↑ file 63% · 24 MB/s · 9m` for one upload, `↑ N transfers · 63%` for several. Click (or
  Enter) opens a **popover** with the full list and the actions: Retry, Cancel, Dismiss,
  Discard, Open folder, and for finished uploads **Copy path** / **Insert path** (insert types
  the path into the current session when it is on the same host). The chip pulses only while
  something is **stalled** or **retrying** (respects `prefers-reduced-motion`).
- **Transfers strip** (under the top chrome, on every screen): appears **only when a job needs
  a decision** — stalled, failed, or incomplete after a reload — and disappears when resolved.
  A healthy upload never claims that space. State changes are still announced once through a
  polite live region; with the tab in the background, *done* and *failed* also raise a browser
  notification.
- **Files panel**: the per-host rows it always had.

## Resume semantics (unchanged)

Uploads go in 8 MiB chunks with an explicit offset; the host appends to `<dest>.wtpart.<id>` and
the commit renames atomically (with a CRC-32 check when the whole file went through one
session). A byte-level watchdog marks a chunk **Stalled** after 20 s without progress and
aborts + resends after 60 s; each chunk gets up to 8 attempts with capped backoff; the job
resumes by itself on `online` / tab visible. After a page reload, unfinished uploads are listed
as **Incomplete** — drop the same file into the same folder to continue from the confirmed
offset; **Discard** deletes the partial on the host.

## Drop on the terminal → upload to the session directory

Drag files from your desktop onto a terminal. The overlay says where they will land before
you release:

- **the session's current directory** when the shell reports it (OSC 7, i.e. shell integration
  is active — see [SHELL-INTEGRATION](SHELL-INTEGRATION.md));
- otherwise the agent user's **home directory**, and the overlay says so.

Each file becomes its own job (`<dir>/<name>`, existing files are overwritten), and when it
finishes its path is **typed at the prompt** followed by a space — no Enter. Drop (or click) on
**Choose another folder…** to open the Files panel instead and pick the directory there.
Dropping files on a **folder row** in the Files panel uploads into that folder; dropping
anywhere else in the panel keeps the current-directory behaviour.

## Paste an image or file → inbox + path

Paste (Ctrl/Cmd+V) with an **image or file** in the clipboard while the terminal is focused.
Text pastes are untouched — they still go through xterm's bracketed paste exactly as before.

The file is uploaded to the host's **inbox** and its path is typed at the prompt:

```
~/.webterm/inbox/<YYYY-MM-DD_HH-mm-ss>[-n].<ext>       # unnamed (a pasted screenshot)
~/.webterm/inbox/<YYYY-MM-DD_HH-mm-ss>[-n]_<name>      # a pasted file that had a name
```

- The timestamp is the browser's local time; `-n` (2, 3, …) separates several unnamed items
  pasted in the same second. "Unnamed" means the browser's generic name (`image.png`,
  `Pasted Graphic`) or none at all.
- The extension comes from the MIME type (`png`, `jpg`, `gif`, `webp`, `pdf`, `txt`, …;
  unknown types get `bin`).
- The inbox directory is created with `mkdir -p` before the first upload (once per host per
  page load).
- The inserted path is **shell-quoted only when needed** (spaces or special characters →
  single quotes, `'` inside becomes `'\''`), so a plain path stays plain.
- If the tab that received the paste is closed by the time the upload finishes, nothing is
  typed anywhere (it could be a different host's shell); the row stays in the popover with
  **Copy path** until you dismiss it.

**Settings → Preferences → Transfers** lets you send pasted files to the **session directory**
instead of the inbox (same naming), and sets the **inbox retention** (default **7 days**,
`0` = keep forever). Retention is applied opportunistically and client-side: after each
successful inbox upload, the inbox is listed and files older than N days are deleted — at
most 50 per run, best effort, never the file just uploaded. There is no cron on the host; if you
stop pasting, nothing is cleaned.

## Why: CLI tools that take file paths

Claude Code, aider, and friends run **on the host**, inside the terminal. They cannot read your
browser's clipboard — a screenshot you copied on your laptop simply does not exist on that
machine. WebTerm materialises it there and gives the tool the only thing it understands: a path.

```
$ claude
> Look at this error: ~/.webterm/inbox/2026-10-04_14-03-22.png      ← Ctrl+V did this
```

The same works for `aider --read <path>`, `cat`, `python -c 'open(...)'`, or any command that
takes a filename — paste first, then finish the line.

## Keys and storage

| Where | Key | Meaning |
|---|---|---|
| localStorage | `wt_paste_dest` | `inbox` (default) or `cwd` |
| localStorage | `wt_inbox_days` | retention in days, `0` = keep |
| localStorage | `wt_up_<host>_<dest>_<size>_<mtime>` | resumable-upload metadata (see above) |
| host | `~/.webterm/inbox/` | pasted files |
