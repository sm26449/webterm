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

- a target pane that is **not receiving output** (paused stream, history replay in progress) forces
  a "Can't check every pane" confirmation — its line is unknown. While broadcast is on, phones keep
  every pane streaming so this is the exception (reconnects), not the rule;
- a target pane at a shell prompt whose last keys have **not echoed back yet** (latency: `↑` may
  have recalled a command nobody has seen) makes Enter wait up to **150 ms** for the echo, then
  decide; still no echo → the same confirmation. Keys typed during the wait are queued and sent
  after the Enter, in order;
- a rule that matches any pane's line still wins (block / confirm, as before);
- panes whose keys don't reach the host at all (watch-only, ended, socket closed) are not targets.

Every path that can submit a line goes through the same check: the keyboard Enter / `Ctrl+J`, a
bare Enter that arrives without a keydown (mobile IME, keybar), "Paste & run" from the paste history
(its Enter goes to every pane, after the check), and snippets / palette inserts (typed into every
pane when broadcasting; one containing a line break is checked line by line — the first line
appended to what is already typed — and not typed at all if a line matches). "Run again" types the
command into every pane without Enter. A pasted text whose line ends with a bare CR (`cmd\r`) hits
the multi-line paste guard like LF. A watch-only pane broadcasts nothing (its keys go nowhere).

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
