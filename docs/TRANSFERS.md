# Transfers

How files move between your browser and a host, and — the part that matters for AI CLIs —
how a screenshot in your clipboard becomes a **path** a tool on the host can open.

Paste and drop (phase 1) use the agent's existing file API (`fs` list / mkdir / upload /
delete) — no gateway or agent change was needed for them, so a host that already runs the agent
has them. The performance work (phase 2, below) did add to both: the binary `FRAME_FSWRITE`
upload frame in agent v55 and the gateway's reorder window (`_UploadWindow`).

## Where transfers show up

Since 3.3.0 all progress lives in **one floating Transfers widget** in the **bottom-right
corner** — on every page (sessions, host pages, the Dashboard), shown only while jobs exist, so a
running transfer is never out of sight when you switch context. (It replaced the earlier tab-strip
chip, its popover and the attention strip under the top chrome.) On a phone it spans the width
between the gutters and sits above the key bar, so it never covers the terminal input.

- **Collapsed** (the default, and remembered): a compact pill — `file 63%` for one job,
  `N transfers · 63%` for several. It pulses only while something is **stalled**, **retrying** or
  **failed** (respects `prefers-reduced-motion`). Click (or Enter) to expand.
- **Expanded**: a card with every job — name, size, progress, speed, ETA — and its actions:
  Retry, Pause / Resume, Cancel, Dismiss, Discard, Open folder, and for finished uploads
  **Copy path** / **Insert path** (insert types the path into the current session when it is on
  the same host). **Clear finished** appears once everything has stopped; **–** collapses it back
  to the pill.
- When a job newly **needs a decision** — stalled, failed, or incomplete after a reload — the
  widget expands by itself, once (it does not fight you if you collapse it again). State changes
  are announced once through a polite live region; with the tab in the background, *done* and
  *failed* also raise a browser notification.
- **Files panel**: the per-host rows it always had.

## Pipelining, adaptive chunks, pause/resume (phase 2)

**Pipelined upload.** The browser sends up to **3 chunks concurrently** (`UP_WINDOW`) over HTTP, so
the bodies travel up the browser→gateway link in parallel and hide its round-trip time on
high-latency connections — the win grows with latency (roughly one stall per 3 chunks instead of one
per chunk). The catch: the agent's `fs_write` is a **strict append at the current size** (any other
offset is rejected `offset_conflict`), so the gateway may not write chunks out of order. It keeps a
small **reorder window** per upload (`gateway/app/core._UploadWindow`): a chunk that arrives ahead of
its turn has its bytes held in a **bounded buffer** and the request waits; the chunk that fills the
gap writes everything contiguously, in order, and wakes the waiters. Because the agent still sees a
pure append-only sequence, its incremental CRC-32 stays correct. The buffer is capped at
`UPLOAD_WINDOW_MAX` (= `WINDOW_K` × the client's max chunk = **48 MiB per upload**); only *out-of-order*
chunks occupy it (an in-order one is written immediately), so a sequential upload never touches it.
Past the cap the gateway answers **429** and the client eases off and retries that chunk — backpressure,
not an error. A duplicate of an already-landed chunk (a lost ack) is idempotent (returns the current
offset, nothing re-written).

**Adaptive chunk size.** The client starts at **8 MiB** and adjusts each chunk between **2 and 16 MiB**
(`nextChunkSize`): bigger when a chunk finished quickly on a fast, stable link (fewer round-trips),
smaller when it ran long or hit a stall/retry (cheaper retries). The gateway re-splits every chunk
into 1 MiB blocks toward the agent, so the HTTP chunk size is **not** bounded by the 16 MiB agent
frame — only by the reorder-window memory above.

**Pause / Resume.** Each running transfer has a **Pause** button (in the Transfers widget);
pausing stops sending, aborts the in-flight chunks, and keeps the `File` + offset in memory and the
`.wtpart` temp on the host. **Resume** re-enters from the real offset via `fs_upload/status`. A reload
while paused loses the `File` (as always) — the row comes back **Incomplete**; re-drop the same file
to continue.

## Resume semantics

Uploads go in adaptive 2–16 MiB chunks (8 MiB to start) with an explicit offset; the host appends to
`<dest>.wtpart.<id>` and the commit renames atomically with a CRC-32 integrity check. On the gateway→agent hop a block
travels as a raw binary frame (`FRAME_FSWRITE`), not base64 inside JSON — base64 cost +33% bytes
and encode/decode CPU on both ends. The host (agent v55+) accumulates the CRC-32 as it appends
each block, so the commit verifies integrity without re-reading the whole file (a multi-GB re-read
used to stall the host for minutes), and a **resumed** upload gets the CRC of the bytes already on
disk from `fs_upload/status` and keeps verifying from the real offset (older agents fall back to
checking only when the whole file went through one session, and to the base64 op + full-file
re-read at commit — the gateway speaks both protocols during a fleet rollout).
A byte-level watchdog marks a chunk **Stalled** after 20 s without progress and
aborts + resends after 60 s; each chunk gets up to 8 attempts with capped backoff; the job
resumes by itself on `online` / tab visible. After a page reload, unfinished uploads are listed
as **Incomplete** — drop the same file into the same folder to continue from the confirmed
offset; **Discard** deletes the partial on the host.

## Downloads (host → browser)

The **Download** button on a file row now goes through the **same engine** as uploads, so a download
is a job too: it shows a `↓` row in the Transfers widget with progress, speed and ETA, and can be retried
or paused. The gateway serves `GET /fs/download` with **HTTP Range** support (206) over the existing
`fs_read` (which already reads from any offset) — **no agent change**. The browser fetches from the
current offset, with the same byte-level watchdog (Stalled → abort → retry with backoff); on a blip it
resumes from the bytes already written **within the session**.

Where the file lands:

- with the **File System Access API** (Chrome/Edge): you pick the destination once and the bytes
  **stream to disk** — fine for multi-GB files, and in-session resume continues the open stream;
- otherwise the bytes are collected into a **Blob** and saved at the end. That holds the whole file in
  memory, so a file larger than **1 GiB** needs a browser with the File System Access API — otherwise
  the download is refused with a clear message.

**Not yet:** resume **across a page reload** (we don't persist the file handle) and resumable
**directory** archives (`.tgz` is still a plain streamed link). Downloads rely on TLS for integrity;
there is no end-to-end CRC check like uploads have.

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
  typed anywhere (it could be a different host's shell); the row stays in the Transfers widget with
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
