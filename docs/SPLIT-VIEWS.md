# Split views

A split view shows **two or more sessions side by side in one tab**, so you can watch a log in one
pane while you work in another, or run the same command on two hosts at once. It was added in
3.6.12 and refined in 3.6.13 (the broadcast guardrail). Terminals in a split are the same live
sessions as in their own tabs — nothing is duplicated, and moving a session in or out never
reconnects it.

## Opening and closing

- **`Alt+D`** on a session opens it side by side with the current one (reusing an existing split
  that already holds the same two sessions instead of making a second).
- **Drag** a tab onto another session's pane, or use the split controls in the tab bar.
- A split view gets its own **chip in the tab bar**, so you can always get back to it. Closing the
  chip breaks the sessions back out into ordinary tabs; the sessions keep running.

Tab-level navigation leaves the split view (clicking a tab, `Alt+1…9`, `Alt+0`, picking a session
in the sidebar or palette); **pane-level** navigation stays inside it (`Alt+←/→` between panes,
`Alt+M`, `Alt+X`, clicking or tabbing into a pane). See [SHORTCUTS.md](SHORTCUTS.md).

## Layouts

WebTerm picks a sensible layout for the number of panes and lets you change it from the tab bar:

| Layout | Shape |
|---|---|
| `cols2` / `cols3` | two or three equal columns |
| `main-left` | one large pane on the left, the rest stacked on the right |
| `main-top` | one large pane on top, the rest in a row beneath |
| `grid` | an even grid (4 panes = 2×2) |

Drag a divider to resize; the sizes are remembered per split.

## Moving, swapping and maximizing

- **`Alt+←` / `Alt+→`** — move focus to the previous / next pane.
- **`Alt+M`** — swap the focused pane with the next one.
- **`Alt+X`** — maximize the focused pane to fill the view, or restore it (double-clicking the
  pane title does the same). The other sessions keep running in the background; maximize does not
  pause them on desktop.

`Alt+M` and `Alt+X` act only inside a split view; elsewhere they fall through to the OS. On macOS
`Option+M`/`Option+X` may be dead keys — see the note in [SHORTCUTS.md](SHORTCUTS.md).

## Broadcast — typing into every pane at once

Turn on **broadcast** to send your keystrokes to every pane in the split at the same time (the
same command on several hosts). It is off by default and clearly marked while on.

Broadcast changes what the [command guardrail](GUARDRAIL.md) can promise. The guardrail reads the
line from **one** pane's prompt; it cannot see every pane's prompt at once, so with broadcast on it
says **"Can't check every pane"** and asks before sending to all of them, rather than pretending it
vetted each line. A dangerous-command rule is still your safety net on the pane you are reading —
it just can't vouch for the others. Broadcast is a convenience, not an access boundary.

## On a phone or a narrow pane

On a phone the split shows one pane at a time with a switcher; a pane that is **not on screen is
paused** to save battery and data. When you switch back to it, WebTerm **resyncs** the terminal
from the host, so a paused pane catches up rather than showing stale output. On desktop every pane
streams continuously (a maximized pane does not pause the others).

## See also

- [SHORTCUTS.md](SHORTCUTS.md) — every split-view key.
- [GUARDRAIL.md](GUARDRAIL.md) — the broadcast "can't check every pane" rule and the echo wait.
- [FEATURES.md](FEATURES.md) — the rest of the terminal features.
