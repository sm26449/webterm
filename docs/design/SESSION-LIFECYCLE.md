# Session lifecycle

A session is a tmux session on a host. The gateway keeps a row describing it and a `SessionHub` in
memory that pipes bytes between the agent and any attached browsers. Everything below follows from
those two facts being able to disagree.

## States

| State | Meaning |
|---|---|
| `creating` | requested, the agent has not confirmed yet |
| `live` | the agent reports it as alive |
| `lost` | the gateway lost track of it, but tmux may well still be running on the host |
| `closed` | it exited; the transcript is final |

`lost` is the interesting one. It is not "gone" — it is "we disagree with the host". A session
becomes `lost` when the agent stops reporting it (agent restarted, host offline, network gone).
The tmux session usually survives all of those, which is the whole point of using tmux.

That has a consequence worth spelling out: **operations on a `lost` session must still reach the
host.** Killing one has to send the kill, not return success because the row looks inactive. The
alternative is a user who believes they closed a root shell and did not.

## Reconciliation

On every heartbeat the agent reports which sessions it has. `reconcile()` compares that against
the database and moves rows between states. Three rules earn their keep:

- **Only shell sessions.** Telnet-bastion and serial sessions do not live in the agent's tmux, so
  a reconciliation that forgets to filter by `kind` will "clean up" live sessions the agent has no
  reason to report. Filter once, in one place — this has broken more than once by being reinvented.
- **The report is untrusted input.** A malformed entry must skip that entry, not abort the whole
  pass. Update pushes happen at the end of reconciliation; if a malformed report can abort it, a
  host can veto its own updates while looking healthy.
- **Adoption re-attaches, it does not recreate.** A session the gateway has forgotten but the agent
  still has is adopted under its original id, with a marker written into the transcript to show
  where the gap is.

## Transcripts

Every session writes two files: a raw byte stream (`.out`) and an asciicast recording (`.cast`)
for playback. Both are append-only while the session lives.

**Input is never recorded.** What you type does not enter the transcript — only what the host
sends back. Passwords typed at a prompt with echo disabled therefore do not end up in the
recording, or in a backup of it.

Writes are buffered and checkpointed, which creates a trap: a session that goes quiet has no next
write to flush the last one. Reloading the page would show an empty terminal and the transcript
would be missing the last command. A delayed flush closes that — the rule is that persistence must
not depend on more output arriving, because for an idle terminal it never does.

## Replay on attach

A browser that attaches gets one binary frame before the live stream: the **transcript tail** —
the last 256 KiB of the flushed `.out`, with alt-screen switches, full clears and resets stripped
(`read_tail`). The unflushed checkpoint window is deliberately left out: replaying it into a
terminal of a different size collides with the tmux resize redraw.

Under tmux that tail is a poor scrollback. tmux scrolls with a scroll region and `CSI n S`, and
xterm.js only moves lines into scrollback on a line feed at the bottom of the region — so 256 KiB
of tmux traffic often leaves tens of lines, or none. Since agent 57, a **fresh attach to a live
tmux session** puts the pane's real history above the tail:

- The browser sends `?sb=<its scrollback>&rows=<its rows>` on the session (and share) websocket;
  the gateway clamps both. With no `sb` (an old frontend, a test client) the replay is exactly the
  old one.
- The gateway asks the agent for `history {sid, lines: sb}`. The agent runs
  `tmux capture-pane -p -e -J -S -N -E -1` on `wt-<sid>:` on a worker thread: colours kept,
  wrapped lines joined, and the visible screen left out (the redraw that follows the attach paints
  it). With no history it skips the capture, and with several panes it declines. The reply is
  zlib + base64 and capped at 1 MiB, far below the agent's 4 MiB outbox limit, which would drop
  the whole agent connection. The most recent lines are kept when it has to truncate.
- The gateway keeps only text and SGR from the capture: no cursor movement, no clears, no
  alt-screen, no OSC, no C0/C1 controls. It joins the lines with CRLF and adds a dim seam line.
  Then it pushes the screen into scrollback with `rows - 1` line feeds and homes the cursor, so
  that the tail, which often starts with absolute cursor positioning, cannot overwrite the last
  screen of history. The **unchanged** tail follows in the same frame.
- **The commands panel still works** because the tail is unchanged: OSC 133 markers come from the
  tail, exactly as before. `capture-pane` drops OSC sequences, so the history above has none.
- **The seam is not deduplicated, on purpose.** Lines the tail scrolls into xterm's scrollback can
  appear twice, just below the seam. That is at most the scrollback a tmux session showed before
  this change. Trimming the history by text-matching it against the tail would lose lines: we
  cannot tell which tail lines reach scrollback, because the ones tmux scrolled with `CSI S`
  never do.
- Any failure falls back silently to the old replay: agent below 57, the pty backend, several
  panes, a 3 s timeout, or an oversized or corrupt reply. The history request is made before the
  tail is read, and the client joins the hub only after the frame is sent, so the live queue
  cannot interleave with it or duplicate it. If the hub locks while the gateway waits for the agent,
  nothing is sent.
- Shares follow the owner's policy: they get the history whenever they would get the tail, and get
  nothing on a 2FA host with no owner present.

Streams that are not tmux traffic, such as the pty backend, telnet, serial and closed sessions,
get a 2 MiB tail instead of 256 KiB when the browser's scrollback is large (desktop). Mobile keeps
256 KiB. Resume and unlock resyncs do **not** fetch tmux history; they replay the tail, at the
attach-time window for a full resync and at 256 KiB for a lossy one.

## The screen is not the source of truth

Under tmux, structured data (OSC 133 shell markers, OSC 52 clipboard) arrives through DCS
passthrough — out of band, not as text on the screen. Anything that parses shell state must read
the byte stream.

Code that reads the rendered screen instead works perfectly in a plain PTY and fails under tmux.
Since tmux is how sessions survive, that combination is the production one; a test that runs
without tmux is testing a different program.

## Idle lock

On a host marked "require 2FA", a session that has been idle beyond a threshold starts **locked**:
scrollback is not replayed, output is suppressed, and input is refused until the user re-verifies.
The lock state lives on the hub.

Because hubs are in memory, a gateway restart creates a fresh one — so idle time accumulated while
disconnected cannot be recovered from it. Attaching therefore requires an open step-up window
rather than an inference from idle time. Anything that gates access on in-memory state must ask
what that state looks like one second after a restart.
