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
{ id, name, panes: string[]  (2–4 distinct session ids), ratio, broadcast }
```

Split-views live in the tab bar **alongside** the physical session tabs (which are
unchanged — still one session each). You can have several, each named. The three
old mechanisms collapse into this one: creating a split-view replaces "open grid"
and "Alt+D"; the two ratio values become one `ratio` per split-view.

## The one invariant that makes it safe

**Only the active view is mounted** — a physical tab *or* one split-view, never
both, exactly like tabs today. That single rule dissolves every hazard:

- The gateway already fans one session out to N clients (multi-device), and the
  agent keeps exactly one tmux client per session (`tmux … -D`), so resize is
  reconciled at the gateway (one shared size, last-writer-wins with an idle/active
  gate) — never in tmux.
- The frontier that is *not* safe is the same `session.id` mounted **twice in one
  document**: `window.__wtTerms`, the broadcast `sendMap`, and React `key={s.id}`
  are all keyed by session id and would collide. The "only the active view is
  mounted" rule means this never happens — and within a split-view the panes are
  **distinct** sessions, so no collision there either.
- When you switch between a physical tab and a split-view that share a session, the
  session simply re-attaches at the new pane's size — the exact path grid↔tab
  already uses.

So the active view's sessions are **excluded from the keep-alive stack** (the same
trick the old `secondSid` used at `App.tsx:600`), and a split-view **takes over**
the main area like the grid does today.

## Persistence — definitions server-side, selection per-device

- **Definitions** (`split_views` table, per user) are **server-side**, so a layout
  you build on the desktop is there on the phone. They reference session ids, which
  are themselves server-side and shared across devices.
- **The active selection** (which view is open) stays **per-browser** in
  localStorage — device A can be on a split-view while device B is on a tab.

A split-view holds **no secret** — it is layout metadata that references sessions
which are independently gated at attach time. So its CRUD needs only
`require_user`; unlike stored DB connections, it does **not** cost a step-up factor.

## Reconciliation & edge cases

- On read, panes are filtered to sessions that still exist; a split-view that drops
  below 2 live panes is pruned.
- A session may appear in a physical tab **and** in one or more split-views at once
  — never mounted simultaneously, only when its view is active.
- Same session twice inside one split-view is rejected (it would be two tmux clients
  at two sizes — a resize war), mirroring the old `primary ≠ second` guard.
- Broadcast is a per-split-view property (persisted), with the existing amber-band
  warning and guard.

## Data model (DB)

`split_views`: `id`, `user_id`, `name`, `panes` (JSON array of session ids),
`ratio` (float), `broadcast` (int), `position` (order in the tab bar), `created`,
`updated`. Added idempotently, like `connections`.

## API

All `Depends(security.require_user)`, no step-up:

- `GET    /api/split-views` — the user's split-views (dead panes filtered).
- `POST   /api/split-views` — create (2–4 distinct, existing sessions).
- `PATCH  /api/split-views/{id}` — rename / re-pane / ratio / broadcast / position.
- `DELETE /api/split-views/{id}`.

## Frontend state

`splitViews[]` (from the API) + `activeSplitId` (local) replace `gridSids`,
`secondSid`, `splitPct`, `splitRatio`. `activeSplitId != null` is the old
`gridActive`. Rendering reuses the existing 2-pane (draggable divider) and 3–4-pane
(2×2) renderers, with `ratio`/`broadcast` read from the active split-view.
