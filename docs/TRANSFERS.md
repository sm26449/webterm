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

Downloads rely on TLS for integrity; there is no end-to-end CRC check like uploads have.

### Resume after a page reload (3.5.13)

Only on the **File System Access** path (Chrome/Edge — a single large file with the save picker, or
a multi-select download into a folder you picked). There the browser gives us a
`FileSystemFileHandle`, which can be stored in **IndexedDB** (database `webterm-transfers`) together
with the host, the remote path, the total size, the server's **validator** and a **checkpoint** —
the number of bytes known to be on disk. After a reload (or a crash, or a closed laptop) the job
comes back in the Transfers widget as **Interrupted — Resume / Discard**:

- **Resume** asks for permission to write the file again (the browser requires a click for that),
  checks the file on disk and continues from `min(checkpoint, size on disk)` with a `Range` request.
  A 2FA host asks for the step-up first, like any file action.
- If the file **changed on the host** since the download started, the bytes are not glued together:
  the row explains it and offers **Start over** — from zero, into the same file, truncated first.
  The validator is a weak `ETag: W/"<size>-<mtime>"` (plus `Last-Modified`) that `GET /fs/download`
  now sends, built from the `fs_stat` it already does — **no agent change**. It catches a changed
  size or modification time; a rewrite with the same size inside the same second would pass.
- Permission refused → the row says so and Resume asks again. The partial file moved or deleted →
  the row says so; Discard and download again. Host offline, session expired → the usual errors and
  Retry.
- **Discard** forgets the job. The partial file normally stays where you saved it (deleting it
  would need its handle and a permission prompt just for that); it is removed only when the handle
  is already loaded and the browser already allows writing it. **Cancel** on a running download
  deletes the partial file once it holds our bytes (before the first checkpoint the chosen file is
  untouched).

**Why checkpoints, and what they cost.** Chromium writes a `FileSystemWritableFileStream` into a
swap file (`<name>.crswap`) and moves it over the real file only on `close()`. Bytes written but not
closed are **lost** on reload. So the engine periodically closes the stream (the bytes become the
file's), stores the offset, and reopens it with `createWritable({ keepExistingData: true })` +
`truncate` + `seek`. The stored resume point is that committed offset, never the in-flight count.
Reopening copies the existing file into a new swap file (a cheap clone on APFS/btrfs, a real copy on
ext4/NTFS), and `close()` reads the file once for Chromium's safe-browsing check — so every checkpoint
costs I/O proportional to what is already downloaded. A fixed step (every 256 MiB) would be
quadratic: ~160 full copies for a 40 GB file. The step is therefore **geometric**: the next
checkpoint comes after another `max(256 MiB, 50 % of what is committed)` (or after 30 s once at least
64 MiB are pending, for slow links) — about 12 checkpoints for 40 GB, local I/O overhead bounded by
roughly 3× the file size, and a reload loses at most about a third of the progress (the last
≤256 MiB early on). **Pause** and a final error also checkpoint, so a paused download loses nothing
on reload. These costs are estimates from Chromium's implementation; they have not been measured on
every platform.

Checked in a real Chromium (153, headless, with origin-private-file-system handles standing in for
picker handles — the picker itself cannot be driven headless): bytes written without `close()` are
gone after a reload; the handle survives IndexedDB across documents; `keepExistingData` + `truncate`
+ `seek` continues exactly at the checkpoint; `truncate` does not move the write cursor (hence the
`seek`). One caveat found there: in an **off-the-record** profile (Playwright's default context, the
equivalent of an Incognito window) reading a file handle back from IndexedDB **crashed the whole
browser**. So the list shown at start-up never touches the handles — they live in a separate object
store and are read only when you click **Resume** / **Start over**. Whether a real Incognito window
with a picker handle behaves the same has not been verified.

What is stored and when it goes away: host id, path, name, size, ETag, mtime, checkpoint, created /
updated time and, in a separate store, the file handle — no cookies or tokens. Records are keyed by **user id** (another
account in the same browser does not see them), removed on completion, Cancel, Dismiss and Discard,
expire after **7 days** without activity, and are cleared on **sign-out**. A session that merely
expires hides the rows; they come back when the same account signs in again.

**Not resumable after a reload:** Blob downloads (Firefox, Safari, and small files in any browser —
there is no file handle, the bytes live in the tab's memory; they still resume **within** the
session), folder `.tgz` archives (generated on the fly, no stable validator), files reached through
a **symbolic link** (the agent's `fs_stat` is an `lstat`, so the gateway has no size for the target —
the link streams without `Range` and without a validator; before 3.5.13 the link's own
length was sent as `Content-Length`, which broke the download), and hosts with an agent older than v50.

## Folder downloads (`.tgz`)

The download button on a **folder** row packs the folder into a `.tgz` **on the host** (`tar` through
the agent's existing `run` op, next to the folder) and streams it through `GET /fs/archive`. Since
3.5.5 that stream is a Transfers job like any download, not a bare link:

- the row first says **preparing the archive on the host…** while `tar` runs (up to the agent's
  5-minute cap — the byte watchdog only starts once the response begins);
- then it shows the **bytes received** and the speed. The archive is built on the fly, so its size
  is **not known in advance** — there is no percentage, the bar is indeterminate;
- **Cancel** closes the connection; the gateway then deletes the temporary `.wtarch.<id>.tgz` on
  the host;
- on failure the row shows the **server's message** (translated where we have a code: *the folder
  could not be archived*, *permission denied*, *archiving the file-system root is refused* …);
- it is **not resumable** — the row says so. Every request produces a new archive, so there is no
  stable offset to continue from. **Retry** starts it again from zero (the destination is truncated).

Saving follows the file downloads: with the File System Access API you pick the destination and the
archive streams to disk; otherwise it is collected in a Blob, and an archive that grows past
**1 GiB** fails with the *too large for this browser* message.

## Multi-select in the Files panel

Every row has a checkbox. On a desktop:

- **click** a checkbox, or **Ctrl/Cmd+click** a row, toggles it; **Shift+click** selects the range
  from the last row you touched (the *anchor*) to this one; **Ctrl+Shift+click** adds the range to
  the selection;
- **Space** toggles the focused row, **Shift+↑/↓** extends the selection from the anchor,
  **Ctrl/Cmd+A** selects everything visible, **Escape** clears the selection (a second Escape closes
  the panel), **Delete** with a selection asks to delete the selection;
- the checkbox in the sort bar is **Select all**: it selects what you **see** — the filter and the
  hidden-files toggle are respected — and clears those rows on a second press.

On a phone or tablet, **long-press** a row (half a second, without moving) to start selecting; while
something is selected, a tap on a row toggles it instead of opening it. The checkboxes are 24 px
(36 px rows) on touch screens.

The single-row gestures are unchanged: double-click a file name copies the name, triple-click copies
the full path, and dropping files on a folder row uploads into that folder. Clicks on a checkbox
never trigger them. Navigating to another folder clears the selection; reloading the same folder
keeps what still exists.

A **selection bar** appears at the bottom: **N selected · Download · Delete · Copy to host… · Clear**.

- **Download** starts **one Transfers job per item**: files through the download engine (Range,
  pause, retry), folders as `.tgz` archives (above). With the File System Access API you choose a
  **folder once** and every file streams into it (a name that already exists there gets ` (1)`, it is
  never overwritten silently); without it each item is saved as a Blob, and a file over 1 GiB is
  reported instead of started. At most 3 run at a time.
- **Delete** asks **once**, listing the count and the first five names; if folders are included it
  says so — they are deleted **recursively**, the same rule as deleting one folder. Items are deleted
  one by one; failures are **reported per item** (*2 of 7 could not be deleted: …*) and stay
  selected.

## Copy to another host

**Copy to host…** in the selection bar copies the selected **files** to another host **through the
gateway**: agent A → gateway → agent B. The data never passes through your browser (useful from a
phone, or over a slow link), and nothing has to be installed between the two hosts.

The dialog asks for:

- the **destination host** — only hosts with an **online agent**; the source host is listed last as
  *(same host)*: copying within one host (another folder, or a duplicate next to the original) is
  allowed;
- the **destination folder** — a path field plus a small folder browser (it lists the destination
  through the same API as the Files panel, so a 2FA host asks for its step-up there);
- **if a file already exists**: **Skip**, **Overwrite** (atomic replace; the existing file keeps its
  permissions), or **Keep both** — the copy is named `name (1).ext`, `name (2).ext` … (`a.tar.gz`
  becomes `a (1).tar.gz`, `.bashrc` becomes `.bashrc (1)`). Copying a file onto itself with
  *Overwrite* is skipped.

The job appears in the **Transfers widget** as a **copy A → B** row: percentage over the total
size, speed, *files 3/5 · skipped: 1 · failed: 1*, **Cancel**, and on failure the first error with
**Retry**, which starts a new job with only the files that failed. Closing the tab does not stop the
copy — it runs on the server — but a reload loses the row.

**How it works.** `POST /api/fs/copy` `{src_host, paths[], dst_host, dst_dir, on_conflict}` returns
a `job_id`; `GET /api/fs/copy/{job_id}` reports per-file and total bytes, state and errors (`?files=1`
for every file row); `DELETE /api/fs/copy/{job_id}` cancels. The gateway reads each file with the
agent's `fs_read` (as a download does) and writes it with the **upload machinery**: the destination
gets the same `.wtpart.<id>` temporary file, the bytes are applied strictly in order (binary frames
on agent ≥ 55), and the commit checks the **CRC-32** of what was read on the source against the CRC
the destination agent computed on disk **before** the atomic rename — a corrupted copy never appears
under its final name. A file that changes on the source during the copy (size or mtime) fails
instead of landing half old, half new.

**Backpressure and memory.** Each file has one reader and one writer joined by a small bounded
queue: the reader stops when 4 source chunks (256 KiB each) are waiting, and the writer waits for
the destination agent's acknowledgement of every 1 MiB block. The gateway therefore holds a few
megabytes per file in flight, never the file. A job copies **2 files at a time**; at most 4 jobs per
user (16 on the gateway) run at once.

**Cancel** stops the file in flight and **deletes its temporary file on the destination**; files
already copied **stay**. A source read error, a refused file or a CRC mismatch fails **that file**
only; the job continues and ends as *failed* with the per-file errors.

**Limits**

- at most **1000 files** per copy; the total size is unlimited (and shown);
- **folders are not copied** — the button is disabled for a selection of folders only, and folders in
  a mixed selection are left out with a note. Walking a tree with the current agent operations would
  lose the executable bits (the agent has no `chmod` operation) and silently follow symlinks; copying
  folders between hosts comes with the **next agent update**;
- **special files** (devices, FIFOs, sockets — e.g. `/dev/zero`) are refused, the same guard as
  downloads; **symbolic links** to files are followed and copied as the file they point to;
- **permissions and ownership are not copied**: a new file gets the destination agent's default
  mode (umask, usually `0644`) and is owned by the destination agent's user. The dialog warns when
  a selected file is private on the source (e.g. `0600`, an SSH key);
- paths must be absolute or `~/…`, without `..` segments or control characters; two sources with
  the same file name in one job are refused.

**Security.** Session cookie only — an automation token gets `401`. Both ends need what reading and
writing files need on their own: the **step-up** of a 2FA host is required on the **source and on
the destination**. Each job is visible and cancellable only by the account that started it. The
audit log records `copy N files A:/path → B:/dir` (and the cancel).

**Jobs live in the gateway's memory.** A finished job stays queryable for **one hour**. A **gateway
restart loses running jobs**: files already committed stay; the temporary file of the one in
flight is removed by the upload garbage collector after 24 hours (or on the next upload into that
folder). Start the copy again with **Skip** to finish the rest.

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
| IndexedDB | `webterm-transfers` / `downloads` + `handles`, key `<user>:<host>:<path>` | interrupted File System Access downloads: metadata, and the file handle read only on Resume (see *Resume after a page reload*) |
| host | `~/.webterm/inbox/` | pasted files |
