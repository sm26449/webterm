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
