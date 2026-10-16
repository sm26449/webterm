# Split-views — named, persistent multi-pane layouts

Written for someone about to build or change the feature.

## The problem

WebTerm had three overlapping ways to show more than one terminal at once:

- **Alt+D split** — a global `secondSid` shown beside the primary tab, with its own
  ratio (`splitRatio`), persisted as a single `wt_layout` in localStorage.
- **Grid / broadcast** — `gridSids` (2–4), rendered as a split (2, with `splitPct`)
  or a 2×2 grid (3–4), with type-to-all broadcast. Not persisted.
- (and plain tabs, one session each.)

Two 2-pane systems with *two different* ratio values, one global split that
"followed" you when you switched tabs (the source of the "which pane does this tab
land in?" ambiguity), and nothing you could name, keep, or have more than one of.

## The model

A **split-view** is a named, saved layout of 2–4 **distinct** sessions:

```
{ id, name, panes: string[]  (2–4 distinct session ids), layout, sizes, ratio, broadcast, position, hidden }
```

Split-views live in the tab bar **alongside** the physical session tabs (which are
unchanged — still one session each). You can have several, each named. The three
old mechanisms collapse into this one: creating a split-view replaces "open grid"
and "Alt+D"; the two ratio values become the per-view `sizes`.

### Layouts and sizes (3.6.12)

| `layout` | panes | `sizes` (groups, each sums to 1) |
|---|---|---|
| `cols2` | 2 | `[col0, col1]` |
| `cols3` | 3 | `[col0, col1, col2]` — three equal columns by default |
| `main-left` | 3 | `[col0, col1, row0, row1]` — one big pane left, two stacked right (rows of the stack) |
| `main-top` | 3 | `[row0, row1, col0, col1]` — one big pane on top, two below (columns of the bottom row) |
| `grid` | 4 | `[col0, col1, row0, row1]` — 2 × 2 |

The defaults are `cols2` / `main-left` / `grid` for 2 / 3 / 4 panes; there is no 3-in-a-2×2 grid
any more (it left an unlabeled empty cell). The table lives in two places on purpose —
`gateway/app/api.py` (`SPLIT_LAYOUTS`, validation) and `frontend/src/lib/splitLayout.ts`
(geometry) — change both together. `ratio` stays for old clients: on `cols2` it is `sizes[0]`, and
a `ratio` PATCH from an old bundle becomes `sizes = [r, 1-r]`.

The server validates: `layout` is in the enum and fits the pane count (`splitview.badLayout`);
`sizes` has exactly the number of entries the layout needs, every entry is a finite fraction in
(0, 1), and each group sums to 1 ± 0.02 (`splitview.badSizes`); then each entry is clamped to
0.1–0.9 and the group renormalized. A pane-count change resets the layout and sizes to the default.

## The one invariant that makes it safe

**One session = one terminal in the document.** The same `session.id` mounted twice in one
document is the thing that is *not* safe: `window.__wtTerms`, the broadcast handle map and React
keys are all keyed by session id and would collide, and two WebSockets on one PTY start a tmux
detach war. Within a split-view the panes are **distinct** sessions (enforced by the server and,
before every optimistic update, by `isDistinct` / `applyPaneMove` in `lib/splitLayout.ts`).

Since 3.6.12 the guarantee comes from **one keyed list** instead of "only the active view is
mounted": `mountedSids` in `App.tsx` = the keep-alive stack ∪ the active split's panes,
deduplicated, each rendered as `<div key={sid}>`. Without a split the stack is the familiar overlay
(only the selected tab visible). With a split the same container becomes a CSS grid: the panes get
a `grid-area`, the rest of the stack stays mounted but hidden. Consequences:

- entering or leaving a split, changing its layout, swapping or maximizing panes **never remounts
  or reconnects** a terminal (the e2e checks the `__wtTerms` instances and counts session
  WebSockets across a swap and an exit/re-entry);
- the panes of the active split count as "recently used", so after you leave the split they stay
  in the keep-alive stack;
- every pane wrapper keeps the same tree shape in both modes (bar slot · content · drop overlay),
  because React reconciles by position — an extra node would remount the terminal.

The gateway already fans one session out to N clients and the agent keeps one tmux client per
session, so resize is reconciled at the gateway (one shared size, last-writer-wins with an
idle/active gate) — never in tmux.

## Selection and focus

The route (`#/s/<sid>`) is the **selected pane**, inside a split too, so the TabBar highlight, the
keyboard focus and the action target (search, font, snippets) always agree:

- **Entering** a split (chip, Alt+D, wizard, reload with `wt_active_split`) selects the pane that
  was last focused in that split (`wt_split_focus`, per browser), else the first, and focuses its
  terminal. Clicking the chip of the split you are already in re-focuses the selected pane.
- **Inside** a split, a click or a focus (Tab) in a pane selects it, via `history.replaceState`
  (pane clicks do not fill the Back history). A pane that only *receives* focus from a button in its
  own bar does not get the focus pulled back into the terminal.
- **Rule for navigation** (also in docs/SHORTCUTS.md): tab-level navigation (a tab click, Alt+1…9,
  Alt+0 / Home, a session from the sidebar or palette, a host page) leaves the split; pane-level
  navigation stays — inside a split `Alt+←/→` go to the previous / next pane, `Alt+M` swaps the
  focused pane with the next one and `Alt+X` maximizes / restores it (on macOS only when the key
  gives the plain letter — `Option+M`/`Option+X` that type `µ`/`≈` go to the shell; use the pane
  bar buttons there, see `altLetter` in lib/shortcuts.ts). `Alt+W` does nothing inside
  a split (the pane's tab would come straight back). A navigation to a session outside the split
  (Back, a link) leaves it.
- Only the selected pane takes the focus when it mounts; the others mount without stealing it.

## Resizing

Dividers sit in the 6 px grid gap. While you drag, only CSS variables on the grid change (in
`requestAnimationFrame`, with pointer capture and `touch-action: none`), so React does not re-render
and xterm does not refit on every frame; the panes' `ResizeObserver` is debounced (~100 ms). On
release the sizes are committed and PATCHed once. From the keyboard a divider is a WAI-ARIA window
splitter: arrows move it 2 %, `Home` / `End` go to the edge, `aria-valuetext` says both sides
("40% / 60%"); the PATCH is debounced. Double-click evens the panes out.

When a split mounts, its layout changes or a divider is released, **every visible pane** sends its
size as the active device (`active: true`). Before, only the focused pane did, and the gateway could
drop the passive resize of the others, leaving them clipped at another client's size. "Visible" and
"focused" are separate props (`paneVisible`, `paneActive`): a visible but unfocused pane still
rebuilds its WebGL renderer when the browser tab comes back.

## Moving panes

- drag a pane's **title bar** onto another pane → the two swap;
- drag a **tab** from the tab bar onto a pane → that session takes the pane; if it is already
  another pane of the split, the two swap (never the same session twice);
- each pane bar has a **Move to…** menu (swap with a named position) and `Alt+M`;
- **maximize** a pane temporarily with a double-click on its title, its maximize button or `Alt+X`
  (not persisted; the other panes keep streaming so restoring is instant).

The drags use private MIME types (`application/x-wt-pane`, `application/x-wt-session`) — never
`text/plain`, which xterm's textarea would type into the shell — and are caught in the capture
phase on the pane wrapper, so a *file* dragged onto a terminal still goes to the upload path.
Any page (or another WebTerm tab) can put the same types on a drag, with a session id of its
choosing, so a drop is accepted only when the drag **started in this page**: the pane bar and the
tab record what they drag (`lib/dragState.ts`) and the drop must carry exactly that id.

## Phones (< 768 px)

One pane at a time, with a pane switcher above it; the hidden panes stay mounted and pause their
stream — except while **broadcast** is on: then every pane keeps streaming, because a hidden pane
still receives your keys and the guardrail needs its current line (see Broadcast). Dividers and drag-to-swap are off; Move to… is off too (the switcher is the way to change
panes), maximize stays.

## Persistence — definitions server-side, selection per-device

- **Definitions** (`split_views` table, per user) are **server-side**, so a layout you build on the
  desktop is there on the phone. They reference session ids, which are themselves server-side and
  shared across devices.
- **The active selection** (which view is open) and the last focused pane of each view stay
  **per-browser** in localStorage — device A can be on a split-view while device B is on a tab.

A split-view holds **no secret** — it is layout metadata that references sessions which are
independently gated at attach time. So its CRUD needs only `require_user`; it does **not** cost a
step-up factor.

## Reconciliation, visibility & limits

- **GET never writes** (3.6.12). It queries only the sessions the user's layouts reference, and
  returns only the panes the caller can see **now**: the role gives `session.watch` or
  `session.open` on the host, and on a `require_2fa` host the step-up window is open — the same rule
  as `/api/sessions` (read passively: GET does not slide the window). The other live panes are
  **hidden, not deleted** (`hidden: n`, ids not returned), so the layout comes back whole after the
  unlock or the role change.
- While a pane is hidden the **shape** (panes, layout, sizes, ratio) cannot be changed — the server
  answers `409 splitview.hiddenPanes`, because a client that only sees part of a layout would
  otherwise rewrite it without the hidden panes. Rename, broadcast and position still work. The UI
  shows the visible panes in a default layout (not persisted) with a notice, and turns off
  rearranging.
- What the `hidden` count and the `409 splitview.hiddenPanes` reveal: only that a session **you
  yourself put** into this layout still exists (it was not deleted; dead panes are pruned). Never
  its id, host, title or state, and nothing about sessions you never referenced — the layout is
  yours, so this is at most "the thing I added earlier is still there".
- Panes whose session no longer exists are pruned by `core.prune_split_views`: in the session
  reaper (every minute) and right after a session or host delete; a layout that drops below 2 live
  panes is deleted. GET just leaves those out in the meantime.
- If the active split has fewer than 2 panes you can see, the UI leaves it with a toast instead of
  showing an empty main area. A failed GET keeps the previous state (it used to close the split).
- A pane needs `session.watch` or `session.open`; `recording.view` alone (replays of closed
  sessions) is not enough for a live pane.
- At most **50** split-views per account (`400 splitview.tooMany`), enforced inside the INSERT
  (`INSERT … SELECT … WHERE COUNT(*) < 50`), so concurrent POSTs cannot overshoot it. The prune
  writes compare-and-swap on the `panes` it read (`UPDATE/DELETE … WHERE id=? AND panes IS ?`): a
  PATCH that lands between its read and its write is not overwritten — the reaper retries next
  cycle. A PATCH racing a delete answers 404, not 500. `position` is clamped to
  0–1000; chips can be reordered by drag or `Alt+Shift+←/→`, and only the moved positions are
  PATCHed. Alt+D reuses an existing split with the same two sessions, and new splits get the first
  unused "Split N" name.

## Broadcast

Broadcast is a per-split-view property (persisted), with the amber band in every pane; the focused
pane keeps a thicker ring so you still see where search / font / Ctrl+W go. The command guardrail
checks **every target pane**: on Enter it looks at the typed command (OSC 133) of the origin and of
each other pane, and the outcome — block (clear the line), cancel (clear) or confirmed run — is
sent to all of them, not only to the pane you typed in.

The typed command of a pane is read from what its shell has **echoed**, so it can be stale. Fail
closed (review of 3.6.12, `lib/broadcastGuard.ts`), when guardrail rules are active:

- the **origin pane is a target too**: its line is re-read after the echo wait like the others,
  not only at the keydown;
- a target pane that is **not receiving output** (paused stream, history replay in progress) forces
  a "Can't check every pane" confirmation — its line is unknown. While broadcast is on, phones keep
  every pane streaming, so a paused pane is the exception, not the rule;
- after **any history replay** (attach, reconnect, a phone pane resumed when broadcast turns on) the
  OSC 133 tracker starts over and the replayed marks are ignored, so a pane's typed line is unknown
  until its shell prints the next **live** prompt — a command recalled with `↑` before the
  reconnect is on that line, unseen. A pane whose shell has integration (a `B` prompt-end mark
  seen, live or replayed — the flag survives the reset; an integration that only emits `A`/`C`/`D`
  never shows the typed line and is treated as none, so it can't cause a permanent dialog), runs no
  command and is on the main screen, but is stale or not at a prompt, counts as **unknown**: Enter waits up to 150 ms, then asks for the same
  confirmation. The first confirmed Enter makes the shell print a live prompt and the pane is
  checked normally again. A pane that never showed a `B` mark (no shell integration) is passed as
  before — nothing can be read there, exactly like the origin pane without integration. The
  **last replayed mark proves nothing** (verification of 3.6.12): the attach / reconnect tail
  (`read_tail`) leaves out the bytes not yet flushed to the transcript (up to ~2.5 s), so a replay
  that ends in `C` may simply be missing the `D`/`A`/`B` of a command that just finished — the pane
  is really at a prompt with an unseen line. The browser can't tell a gap-free resync
  (resume/unlock, flushed up to a cutoff) from one with a gap (attach, slow client): the `resync`
  message doesn't say. So the replay on its own never makes a line known — only the **hub state**
  can (3.6.13, see "OSC 133 state from the gateway hub" below): a live `C` (a program is running)
  or a live `B` inside a replay that provably reaches the live point; everything else stays unknown
  until a live `B` — fail closed;
- a target pane at a shell prompt whose last keys have **not echoed back yet** (latency: `↑` may
  have recalled a command nobody has seen) makes Enter wait up to **150 ms** for the echo, then
  decide; still no echo → the same confirmation. Keys typed during the wait are queued and sent
  after the Enter, in order (a queued Enter is checked again). When the wait ends in a dialog or a
  block, the queued keys are dropped **with a notice** ("N keys typed while the panes were being
  checked were not sent"), never silently;
- the echo test (tightened in 3.6.13, `lib/echo.ts`): **each send is confirmed separately**. The
  reference for the earliest un-echoed send is the line state (screen, absolute cursor row/column,
  OSC 133 line) right after the previous echo — or, when nothing was pending, a snapshot taken once
  xterm had parsed everything that arrived before the key. Output counts as an echo only if it
  **changed** that state. A run of plain-text sends is confirmed when the line now shows exactly
  their text appended (fast typing echoed in one chunk). A key that is **not** plain text (`↑`,
  `Ctrl+P`, `Tab`, editing keys) is confirmed **at most one per burst of output**, and only once the
  stream has been quiet for RTT/2 (20–50 ms; 30 ms without a measured RTT) — with no output still
  waiting to be parsed (writes in flight are counted; a large write is parsed in slices) — and the
  line unchanged since its last change. Plain text typed right after such a key (`↑` then ` -v`) is
  confirmed together with it only when the line now is **exactly** a line seen during that burst
  (up to 16 kept) plus the typed text — not "ends with": `↑` recalling `…/tmp/x` followed by a typed
  `x` would otherwise confirm the `x` before its own echo. Otherwise the text stays pending (the time
  net; in a single pane the check also judges the line with the text appended, with and without
  overlap). Residual: a redisplay split exactly before characters identical to the ones typed next
  can still match — so `↑↑⏎` typed faster than the round trip can't pass on the first `↑`'s
  echo, not even when that `↑`'s redisplay arrives split across two chunks (third review of 3.6.13;
  before it, each half confirmed one key). Two non-text echoes in one burst leave the second
  un-echoed — fail closed (the wait, then "Can't check", or the time net). Residual: a key whose
  echo arrives in bursts more than the quiet window apart (a heavily loaded host) can be confirmed
  by the first burst; the line judged is then the one on the screen. A clock in the prompt or a tmux status
  repaint (cursor goes away and comes back) doesn't count. Keys with no visible effect (`Tab` with
  no completion only rings the bell, `Home` at column 0 prints nothing) would never "echo", so they
  **settle** after max(1 s, 4 × measured RTT), capped at 5 s — but for a broadcast target only if
  *some* output arrived after them (the 3.6.12 coarse rule): a stalled host that sends nothing never
  counts as echoed. Every state the new test calls echoed was also echoed under the 3.6.12 rule, so
  it is never looser. More than 64 un-echoed sends collapse into one entry; it is released once the
  host has demonstrably caught up — output arrived after its last key, the line changed since it
  formed, and the time net has passed since its last key — or by a replay (before 3.6.13's second
  review it stayed until a reconnect, so a few seconds of lag made every later Enter ask). Keys sent
  while **no line was readable** (typeahead during a running command) are "blind": the line going
  away doesn't confirm them, and when the next prompt appears they are confirmed only if the line
  actually shows them — until then the single-pane check appends them to the line and judges that
  (`rm -rf /srv` typed during a build is caught even if Enter comes before readline redraws it).
  Blind keys older than the time net were consumed by the program (vim, a REPL) and are dropped.
  When the line disappears (Enter → the command runs), the keys sent while it was readable are
  confirmed — the 3.6.12 coarse rule. **Terminal-generated reports** (mouse — SGR, urxvt, X10 via
  `onBinary` — focus `CSI I`/`CSI O`, CPR, DA1/2/3, DSR, DECRPM, window-op replies, colour replies
  `OSC 4/1x;rgb:…`, DECRQSS) are not tracked as keys and don't wait in a check's queue. Only the
  exact reply shapes count, with **no C0 — and so no CR/LF — in any body**; a chunk that contains a
  line break is never a report and always goes through the guardrail, and data from a paste is
  never a report (a capture-phase paste listener marks it). Before the second review a pasted
  `ESC]0;x⏎rm -rf /srv⏎BEL` (shell without bracketed paste) was classified as a report and sent
  unchecked to every pane. Every `term.paste()` (Ctrl+V, the paste button and the mobile keybar's,
  the paste history) goes through one helper that sets the same flag. `CSI 1;<n> R` stays a key: it
  is also F3 with modifiers (2–8, and 9–16 with Meta/Super) — unless the output has asked for the
  cursor position (`CSI 6 n` / `CSI ? 6 n`, counted per pane and consumed by each reply; a request
  split across chunks is missed → key, fail closed): then a row-1 reply (nushell, some zsh themes
  after `clear`) is a report. Other rows are always reports. Replies tmux asks the outer terminal
  for at `refresh-client` (XTVERSION, XTGETTCAP, colour-scheme and kitty-keyboard reports) are
  reports too. Only input from the terminal itself (`onData` / `onBinary`) or broadcast from
  another pane is classified by shape; text the app inserts (snippets, palette, "Run again") is
  always a key, and a broadcast carries the origin's classification to the other panes (a pane
  never re-classifies broadcast data by shape). Diagnostics (the console line logged with the "Can't check this line yet" dialog)
  show non-text keys only by shape — printable characters are masked.
  Found by the e2e gate on the merged branch (ordinary typing must never ask): **Enter** is
  confirmed by the first line change in output that arrived after it, and everything queued before
  it leaves the queue with it (that line was already submitted). Keys typed while an Enter is still
  un-echoed are **blind** (typeahead for the next line: the next prompt can appear before readline
  redraws them), so the command starting doesn't confirm them; they are confirmed only when a
  readable line shows them, and until then the single-pane check appends them to the line. A blind
  Enter (sent with no readable line — a command running, or right after a reload until the first
  live prompt) and everything before it leave the queue when a readable line appears. The
  quiet-window candidate is also checked at each output, not only at the next Enter. Matching is
  **exact** — the line read from the prompt must equal the reference plus the typed text; a
  soft-wrapped row (or a row whose last cell is filled — measured in cells, so wide characters
  count) is joined without a space, so a long line still matches. A full row followed by a row not
  marked as wrapped is ambiguous (tmux repaints continuation rows without the wrap flag, but it can
  also be a real line break: `Ctrl+V Ctrl+J`, zsh multi-line): the guardrail checks the rules
  against both joins and the stricter verdict wins; anything that doesn't match stays un-echoed (fail closed). Past 64
  un-echoed sends, only runs of plain text are merged (a merged run is confirmed only whole and
  keeps its text, so the single-pane check appends it instead of asking); Enter, non-text and blind
  keys stay separate, and only past 64 of those does everything collapse into one text-less entry.
  When the guard holds Enter, the `keypress` xterm would still turn into a second `\r` is swallowed
  (before, that duplicate was queued and sent after the held Enter).
  **The prompt position is an xterm marker** (third review of 3.6.13, H1): it used to be an absolute
  row, and once the scrollback is full every scroll trims the top row and shifts every absolute row
  by one (xterm no longer moves `ybase`) — a long session at the bottom of the screen read the line
  from the wrong row, and the guard saw only a fragment. The marker follows the trimming; if the
  prompt row leaves the buffer entirely the line is **lost**: unknown for broadcast, and "Can't check
  this line yet" in a single pane. The marker follows trims, inserts and deletes, but not rows that
  move without them — zsh's `Ctrl+L` (ED2 in place, prompt redrawn at the top, no new `B`), a scroll
  region whose top isn't row 1 (tmux status line at the top, the lower pane of a tmux split), a tmux
  repaint after a resize. So the line is also **lost** when the marker's row is below the cursor,
  when a row between it and the cursor doesn't continue the line (neither wrapped nor filled to its
  last cell — measured in cells, so trailing spaces and wide characters don't matter), when the row
  no longer holds, exactly, the prompt prefix it held at the first key sent after `B` (up to `B`'s
  column; under tmux `B` can land at column 0, then up to the cursor, cut after the last prompt
  terminator `$ # % > ❯` + space — never a right prompt or typeahead), and when an ED2 / ED3 / RIS /
  scroll region with top > 1 went through the output after `B` with nothing to verify yet (a
  sequence split across output chunks is caught too).
  **Principle (verification of dcbf298): no heuristic ever removes text from what the guard judges —
  heuristics may only add readings.** The guard always judges the **conservative reading**: from the
  original `B` position to the end of the logical line, uncut; every other reading is an extra
  variant and the strictest verdict wins. Prompt text in the conservative reading can only add
  confirmations (the built-in rules don't match prompt text — `user@host:~$`, paths, clocks, git
  branches).
  - **Re-anchoring** (the reading start moves to the cursor): at most once per `B`, at the first key
    after it with nothing pending, and only when `B`'s position is demonstrably stale — on another
    row, separated from the current line by a row that doesn't continue it (under tmux `B` arrives
    before the painted text, on the previous command's row), with no prompt terminator followed by
    more text between it and the cursor, `B`'s own row included (zsh push-line / `print -z` / fzf
    widgets and redrawn typeahead restore text after the prompt — that is not skipped; zsh emits `B`
    at column 0 of the prompt row, which then holds the prompt and the restored buffer's first row).
    The rows above the cursor's block are left out of that test only when `B` is at column 0 and the
    cursor's block holds nothing but a prompt (it ends in a terminator + blanks): a two-line prompt
    whose first line holds `%` / `>` followed by text is not restored text. Or on the same row with
    the cursor left of `B` (moving the start left only adds text). **The conservative reading never
    moves** (verification of 512c42f): it always starts at the original `B` (row and column), uncut,
    through every row down to the end of the cursor's logical line — re-anchoring only adds a
    reading. A stale `B` sitting on a row with old text (output of the previous command after it)
    can therefore add a confirmation (fail closed); a fresh `B` on the correct row reads only the new
    prompt. If the conservative reading's mark disappears (scrollback trimmed) while the reading
    position is still alive, the line is lost (fail closed). Otherwise a non-contiguous line stays
    lost (fail closed).
  - **Continuation lines (PS2)** emit no OSC 133: after `for i in 1 2; do` ⏎ (or a heredoc, a
    trailing `\`, an open quote) the next rows are not contiguous with `B`'s row. Once a line
    terminator was sent after `B` and no `C` arrived, the contiguity check is skipped (the other
    checks stay) and the conservative reading from `B` to the end — PS2 prompts included, they only
    add text — is judged: a harmless loop runs without a dialog, `rm -rf /srv` on a continuation row
    hits the rule.
  - **Text after the cursor runs as well**: `↑` recalls `rm -rf /srv/data`, then `Home` or `←` and
    `sudo ` — read only up to the cursor the guard saw `sudo `. The readings judged: up to the cursor,
    to the **end of the logical line** (the cursor row and the rows that continue it) from the reading
    start, and the ambiguous joins. The conservative reading goes further: from `B` down to the
    **last non-blank row of the buffer** — a multi-line buffer has rows after a literal newline that
    run too (zsh `↑` recalls `cd /srv` + newline + `rm -rf /srv/data`, `↑` again moves the cursor
    into the buffer's first row; Ctrl+V Ctrl+J; push-line). Blank rows don't stop it (a buffer can
    hold blank lines). Rows that are definitely not the buffer are left out: a tmux pane border (a
    row of box-drawing characters only, from column 0 across the full pane width, with a horizontal
    run — the reading stops there, below is another pane; a shorter `────` typed into a heredoc does
    not stop it) and, in a tmux-backed session, the last screen row when every cell has the same
    non-default background (a tmux status bar; WebTerm's own tmux runs with the status bar off).
    Text below the line may still be something else — a zsh completion list, text left by
    `tput cup` / a progress tool — so **a match found only in that below-the-cursor reading never
    blocks and never clears the line**: it becomes a confirm dialog that says the match is in text
    below the cursor and shows the rows it read; Cancel keeps the line. A match also present in a
    normal reading keeps its normal verdict. Known (confirm only, never a block): a tmux status bar
    with the default background, or a `pane-border-status` line with text in the border, is read
    as text below the cursor and can add a confirm. A logical line that continues for more than 50 rows
    after the cursor row is not truncated: it is unknown ("Can't check").
  - **Right prompt**: text right of the cursor at the first key, separated from it by blanks, is
    recorded with its row and column; a reading without it is only an extra variant, built only while
    that exact text still sits at that position and no typed text reaches it (`RPROMPT='%~'` showing
    `/srv/data`, then `sudo rm -rf /srv/data` typed: the uncut reading still catches it). Ghost text
    (zsh autosuggestions) can only add confirmations, never "Can't check".
  Residual: a background job that prints while the keys are in flight still moves the
  cursor and counts as the earliest key's echo;
- **a single pane (no broadcast) waits for the echo too** (3.6.13): with rules active, Enter /
  `Ctrl+J` and a chunk ending in a line break wait up to 150 ms; then, if keys are still un-echoed
  and they were all plain text (a slow link while typing), the line on the screen **and** the line
  plus that text (merged with any part already echoed) are checked; if any un-echoed key was an
  editing / control key (`↑`, `Ctrl+P`, `Tab`, `Backspace`…) it asks **"Can't check this line
  yet"** (a known block still wins). Its **Run** judges the line again at click time: by then the
  echo has usually arrived, and a rule matching the now-visible line escalates (block → blocked,
  confirm → the rule dialog) instead of running. The held Enter is sent to this pane only. Without
  broadcast the "unknown after replay" rule still does not apply (unchanged from 3.6.12);
- **every target is judged before anything is decided** (final review of 3.6.12): while
  broadcasting, only a **block** rule on the origin's own line short-circuits; a confirm rule there
  goes through the same judgement as the other panes. Then: a **block** in any pane wins (the line
  is cleared everywhere); otherwise any paused / unknown / un-echoed pane → wait, then "Can't check
  every pane", **carrying the confirm hits** so the dialog shows them too; only when every pane is
  readable does a confirm hit give the rule dialog. Before this, a confirm on the origin's line
  (`sudo reboot`) was answered on its own and "Run" sent Enter to a pane whose line was `rm -rf …`
  (block) or unseen. The rule dialog lists **every distinct line** that matches a rule, with the
  panes it would run in (the following lines of a multi-line paste / snippet are judged in every
  pane too);
- **"Run" on any broadcast dialog** (rule or "Can't check") judges every pane again at click time
  and sends only if the result is ok or exactly the confirm set the user saw (for "Can't check",
  also an unknown with that same set — the user accepted the unreadable panes). Anything else
  escalates: a block → the block notice, a different confirm set (a pane's line changed) → a new
  dialog, a pane that became unreadable → "Can't check every pane". The "Can't check" verdict
  carries the **ids of the unreadable panes**; "Run" sends only if no pane outside that accepted
  set became unreadable. Panes are keyed by their **session id**, not their label (two untitled
  panes on the same host share a label; colliding labels get a short id suffix in the dialog).
  A dialog opened **without** broadcast stays local: its "Run" (or "Cancel & clear") reaches only
  its own pane even if broadcast was turned on while it was open — its line was never judged in the
  other panes;
- panes whose keys don't reach the host at all (watch-only, ended, socket closed) are not targets.

Every path that can submit a line goes through the same check: the keyboard Enter / `Ctrl+J`, a
bare Enter that arrives without a keydown (mobile IME, keybar), any other input chunk that contains
a line break (an IME commit such as `ls⏎`, `Alt+Enter`, a pasted text — each line checked, the
first one appended to what is already typed in each pane; control characters and ESC sequences are
stripped from the checked lines, so `Alt+Enter` (`\x1b\r`) is Enter on the typed line, not
"line + ESC"; TAB / VT / FF become a space, so `rm\t-rf` still matches `rm\s+-rf`. A chunk that
also carries **readline editing keys** — any C0 / DEL / C1 character or ESC other than CR/LF,
the bracketed-paste markers and the lone ESC of `Alt+Enter` (e.g. `Ctrl+U`, Backspace, `Ctrl+Y`,
`Ctrl+V`, `ESC .`) — runs a line that differs from the text we could check, so it asks "Can't
check this input" (with and without broadcast; a known block still wins). Since 3.6.13 that
includes **`Tab` outside a bracketed paste**: it is readline completion (`rm -rf /tm⇥⏎` runs
`rm -rf /tmp/`). Between `ESC[200~` and the next `ESC[201~` (or the end of the chunk) a `Tab` is
literal — but only when the shell of the origin **and of every target pane** has bracketed paste
mode on (xterm's `bracketedPasteMode`); otherwise the markers could come from the pasted text
itself and the shell would not honour them. That mode is **not trusted** in a pane whose stream
goes through a tmux client (agent with the tmux backend, and SSH sessions, which start
`tmux new -A` when the remote has it): tmux sends `ESC[?2004h` to its client once, at attach, and
never forwards the pane's own toggles (verified on tmux 3.4) — so xterm says "on" while bash ≤ 5.0,
busybox sh or a zsh without `zle_bracketed_paste` in the pane would still complete the `Tab`. There
a `Tab` inside a paste is "Can't check this input" — fail closed, hotfix after 3.6.13. The mode is
trusted only on an allowlist, like the gateway's plain-stream check: an agent with the `pty` backend
and telnet; any other or unknown backend counts as tmux. Known limit: a tmux started by hand inside
a `pty` or telnet session makes the mode just as sticky, and the browser cannot detect it), "Paste & run" from the paste history
(its Enter takes the same queued path as a typed Enter, so it never starts a second wait), and snippets / palette inserts (typed into every
pane when broadcasting; one containing a line break is checked line by line — the first line
appended to what is already typed — and not typed at all if a line matches; since 3.6.13 they also
get the editing-key check — their text is sent as is, without bracketed paste, so a `Tab` in a
snippet that ends in Enter is completion → "Can't check this input" — and the echo wait, in a single
pane as when broadcasting). "Run again" types the
command into every pane without Enter. A pasted text whose line ends with a bare CR (`cmd\r`) hits
the multi-line paste guard like LF. A watch-only pane broadcasts nothing (its keys go nowhere).

### OSC 133 state from the gateway hub (3.6.13)

Closes the two 3.6.12 residuals: (1) a replay tail with **no OSC 133 mark at all** made an
integrated pane look like one without integration, so its line was passed unchecked until the next
live prompt; (2) after every reattach, panes inside ssh / `sudo -i` / a REPL started before the
replay asked "Can't check every pane" on every broadcast Enter.

**Gateway (`gateway/app/osc133.py`, `SessionHub`).** The hub sees the whole output stream of a live
session, in order, chunk by chunk, from the moment it was created. `Osc133Scanner` follows xterm.js
5.5: `ESC ]` (C0 / DEL between them keep the ESC state) or C1 `U+009D`; ends on BEL, ESC (ST) or
`U+009C`; CAN / SUB / any other C1 abort; `U+009D` restarts; C0 inside the payload is ignored; the
identifier is digits up to `;` (`0133` is 133, an ASCII non-digit aborts). Marks split across
chunks are reassembled (a partial sequence at the end of a chunk is carried, at most 4 KiB). It
keeps `integrated` (a `B` was seen — monotonic, survives gaps), `last` (`A`/`B`/`C`/`D` or `None`),
the transcript offset where that mark starts, whether it was emitted on the **alternate screen**,
and where the last sequence that `read_tail` strips from replays ended. Nothing comes from the
browser: input never reaches the scanner. The state lives only in memory — after a gateway restart
it starts empty until the shell's next mark. Fail closed everywhere the parser can't be sure
(review of 3.6.13, L2): xterm's UTF-8 decoder **drops** invalid bytes (lone continuation bytes, bad
lead bytes, BOM), its payload limit counts UTF-16 units, and the hub keeps only the first 64 bytes
of an OSC — so any OSC that *might* be 133 but can't be read for certain (a byte ≥ 0x80 between ESC
and `]` or in the identifier, an identifier or kind cut by the 64-byte window, a payload over
10 000 000 bytes, a 133 aborted by CAN / SUB / C1, an `E`, an empty or unknown kind, a partial
sequence over the carry cap) makes `last` **`None`** instead of leaving an older mark in place.
- **`C` (L1):** xterm's tracker only starts a "running command" from a `C` that follows a prompt
  with something typed. The hub doesn't read the screen, so it needs explicit proof: it reports
  `C` only after `B` → `E;<cmd>` (non-empty) → `C` — our integration sends `E` for every non-empty
  command. Anything else is `None`: no `B` since the last `C`/`D`, after `A`, after an empty `E`,
  and `B` → bytes → `C` without `E` (bytes prove nothing: `\e[0m\e]133;C` at an empty prompt is a
  background job, not a command). An integration that never sends `E` gets no `C` seed — its panes
  stay unknown after a reattach, as in 3.6.12.
- **Alternate screen (L3):** DECSET / DECRST 47 / 1047 / 1049 (also inside a multi-parameter
  `CSI ? 1;1049 h`) and RIS are tracked; a mark emitted on the alternate screen is reported as
  `None` on a non-tmux stream (pty / telnet / serial — e.g. tmux or screen run inside a plain pty,
  whose inner shell's marks reach us while the outer screen is alternate; `read_tail` strips the
  switch, so the replay would show that `B` on the main screen). On the agent's tmux backend the
  outer tmux client sits on the alternate screen for as long as it is attached, so the switch is an
  artefact there and is ignored. **SSH counts as non-tmux** (fail closed): its session command is
  `tmux new -A … || exec $SHELL -l`, so a remote without tmux gives a plain shell, and finding out
  would need a second exec on the remote — which regresses hosts with `ForceCommand` / `command=`
  menus, appliance CLIs, a `read` in `.bashrc`, `MaxSessions` limits or bastions that audit every
  exec (a probe tried during this review was dropped for that reason). On an SSH host with tmux the
  marks therefore come from the alternate screen and stay unknown after a reattach, as in 3.6.12.
  Any other or unknown source counts as non-tmux too.
- **Stripped sequences (L3):** `read_tail` removes 47/1047/1048/1049 h/l, `ESC[2J`, `ESC[3J` and
  RIS from every replay. If one of them lies after the last mark, `synced` is false: the replayed
  screen isn't the live one (`Ctrl+L` at the prompt, a repaint), and removing it could splice a mark
  together in the replay that the hub never saw. Residual: under tmux, a full repaint (every
  attach asks for one) can clear the screen, so after another client attached a `B` may only be
  seeded again from the next live prompt.
- **Performance (M3):** the hot path never steps through bytes in Python. Literal-prefix searches
  (run by `re` in C) jump straight to `ESC ]` — skipping, inside the regex, any OSC with a clean
  non-133 identifier (titles, cwd, hyperlinks), which xterm handles identically — `U+009D`, an
  alternate-screen DECSET, `ESC[2J`/`ESC[3J`, RIS and `ESC` + C0/high byte; inside an OSC, straight
  to its terminator; a complete clean `ESC]133;…` is read with one regex. Every remaining Python
  step is an **event**, and a chunk gets a budget of max(32, 1 per 512 bytes) events. A chunk that
  exceeds it (crafted floods: `\e]x\a`, `\e]\a`, `\e]0133;A\a`, `\e]133;A\a`, `\e[?1049h`,
  `\e[2J`, `\ec`, `\e\x01`, `\e\x80`, `\u009d\a`… repeated) is not parsed any further: `last` becomes
  `None`, `strip_end` moves to the end of the chunk (nothing before it can be synced), the screen
  becomes "unknown" (later marks count as alternate-screen until an explicit 47/1047/1049 switch or
  RIS), `integrated` is set if `133;B` appears in it (only adds unknowns), and the parser restarts
  from the last `ESC` / C1 in the chunk's final 4 KiB — `ESC` and C1 put xterm into a known state
  from any state, and nothing after that point can trigger another event, so the restart is
  bounded. Measured on this host, 16 KiB chunks: plain ~280 MB/s, SGR-dense ~120, `°`-dense
  ~290, OSC title full of `°` ~220, `ls --color` ~175, Cyrillic ~265; floods: `\e]x\a` 88,
  `\e]\a` 85, `\u009d\a` 179, `\e\x01` 109, `\e\x80` 110, `\e]0133;A\a` 105, `\ec` 74,
  `\e[?1049h` 101, `\e]133;A\a` 107, `\e[2J` 98, C1 inside a 133 payload 111 (all ≤ 0.22 ms per
  16 KiB); `ESC` repeated ~45. For comparison, writing the chunk to the `.cast` file
  (`json.dumps`) runs at ~260 MB/s. The budget is per chunk; a stream of tiny chunks pays the
  hub's per-chunk costs (file writes, `.cast` JSON) long before the scanner matters.

**Protocol.** The hub takes a snapshot **synchronously** with the moment live output starts flowing
to that client — `hub.clients.add(client)` on attach, the queue drain in `BrowserClient._resync`
(and again at the second drain of a lossy resync, whose dropped bytes move the live point) — and
sends `{"type": "osc133", integrated, last, synced}` right after the replay bytes and before any
live byte (the sender task starts only afterwards; in `_resync` the sender is the caller). Nothing
goes in `init`: it is sent before the step-up / lock decision (review of 3.6.13, L7), and output
processed between `init` and the replay would make it stale anyway. A locked attach (and a share
guest without the owner present on a 2FA host) gets no replay and no `osc133`; the unlock resync
sends its own. `synced` is true only when the replay this client got ends **exactly** at that live
point, contains the last mark whole and has no stripped sequence after it: for a full resync, the
flush-bounded cutoff with an unchanged transcript generation; for an attach, the replay read the
flushed file and nothing was flushed or rewritten during the read (size + generation checked
before and after) **and** nothing unflushed is left (`end == out_f.tell()`), i.e. the session was
idle for the 2.5 s checkpoint — the usual state of a pane parked at a prompt.

**Browser (`CommandTracker.applyHubState`).** Applied after xterm has parsed the replay (an empty
`term.write` queued behind it), only if the tracker is still stale from that replay (no live mark
since). Narrow, fail closed:
- `integrated: true` → integrated (a `false` never clears what the browser saw itself);
- `last: 'C'` → a program started from a prompt before the replay is running: Enter goes to it,
  as when that `C` is seen live (`lineKnown()` true, `atPrompt()` false) until a live `D`. It
  doesn't depend on the replay;
- `last: 'B'` + `synced` + the tracker's own **last replayed mark is also `B`** (its position kept
  with an xterm marker) → the line is read from that `B` to the cursor, as for a live prompt. The
  double check means the gateway parser and xterm must agree; any disagreement stays unknown;
- anything else (`A`, `D`, `null`, not synced, a different last replayed mark) → unknown until the
  next live `B`, as in 3.6.12.

**What is still spoofable, and why it is not worse.** The marks are bytes in the session's output:
any program running in the pane can print a fake `B` or `C`. That was already true of the live path
— the browser's tracker trusts live marks the same way — and the guardrail is a safety net against
mistakes, not a boundary against a hostile program on the host (which could simply run the command
itself). The hub only reports what the live tracker would also have believed: a `C` counts only
after `B` → `E;<cmd>`, where xterm's tracker would start a command too (a program that prints `B`,
`E;x` and `C` fakes it live just the same), a `B` only places the line start, read
from the browser's own replayed screen exactly as a live fake `B` would, and only when the replay
provably equals the live screen (no stripped sequence after it). Where the hub's byte parser and
xterm's decoder could disagree, the hub reports `None`. Browser input never feeds the scanner, and
`integrated` can only add unknowns. After a gateway restart the hub knows nothing until the next
mark, so the browser falls back to the 3.6.12 behaviour (unknown, or "no integration" if the tail
holds no `B`) — residual: a session whose marks are all outside the tail, after a gateway restart
and before the shell's next prompt, still looks unintegrated.

## Data model (DB)

`split_views`: `id`, `user_id`, `name`, `panes` (JSON array of session ids), `ratio` (float,
compat), `layout` (text, `''` = default for the pane count), `sizes` (JSON fractions, `''` =
default), `broadcast` (int), `position` (order in the tab bar), `created`, `updated`. `layout` and
`sizes` came in 3.6.12 through the additive ALTER list.

## API

All `Depends(security.require_user)`, no step-up:

- `GET    /api/split-views` — the user's split-views (visible panes only, `hidden` count, no writes).
- `POST   /api/split-views` — create (2–4 distinct sessions the caller can see; optional
  `layout`, `sizes`, `position`; cap 50).
- `PATCH  /api/split-views/{id}` — rename / re-pane / layout / sizes / ratio / broadcast / position
  (shape changes refused while a pane is hidden).
- `DELETE /api/split-views/{id}`.

## Entry points & visuals

Three ways to create one: the **"+ Split view"** button in the tab bar (accent-coloured, labelled on
first use), **right-click a terminal → Add to split view**, and **Alt+D** (quick 2-pane). The wizard
lists the existing panes first (even without a tab) and the order you tick them is the order of the
panes. Every pane has a slim title bar (number, title · host, Move to…, maximize) and a border; the
focused pane gets an **accent** bar and ring (amber when broadcast is on). The active split's chip
row also has a **layout picker** when the pane count allows more than one layout (3 panes). Each
pane is a `role="group"` labelled "Pane i of n: title", and moving between panes is announced
("Pane 2 of 3 — htop on db-01").

One xterm 5.x caveat lives in `main.tsx`: disposing a terminal during a transition can let a
deferred `Viewport.syncScrollArea` fire on the torn-down terminal (`reading 'dimensions'`). A
`safeFit()` guard, disposing the renderer before `term.dispose()`, and a tightly-scoped `error`
handler that swallows only that exact benign error keep it from surfacing. `__wtTerms` entries are
removed only by the terminal instance that owns them.
