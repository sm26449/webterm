# Design system

WebTerm's UI grew screen by screen. By 3.5.6 it had 12 hand-picked text sizes (49 uses below
11px), 9 border-radius variants for the same kinds of elements, about 170 emoji and Unicode
glyphs used as icons next to an SVG icon set, two different colour sets for the same CPU
thresholds, and no shared button. 3.5.7 puts a small system under all of it. This page is the
reference: what exists, when to use which piece, and the rules a check enforces for you.

Everything here is presentation. None of it changes what a button does.

## Tokens

### Type scale

Defined in `frontend/tailwind.config.js` (`theme.fontSize`). The scale **replaces** Tailwind's,
so these are the only `text-<size>` classes that generate CSS.

| Class | Size / line height | Use for |
|---|---|---|
| `text-2xs` | 11 / 16px | the smallest text allowed, for secondary detail only: meta lines, badges, captions, dense table cells |
| `text-xs` | 12 / 16px | secondary text, small buttons, toolbars |
| `text-compact` | 13 / 20px | dense lists, modal prose, monospace command lines, settings section titles |
| `text-sm` | 14 / 20px | body text, buttons; inputs from `sm` up |
| `text-base` | 16 / 24px | prominent body (login); **every text input below `sm`** (`text-base sm:text-sm`) so iOS does not zoom on focus |
| `text-lg` | 18 / 28px | page and dialog titles (`h1` on the host page, empty states) |
| `text-xl` | 20 / 28px | Dashboard title, the host status line |
| `text-display` | 22 / 28px | the login wordmark |
| `text-2xl`, `text-3xl` | 24, 30px | big numbers (status tiles, load) |
| `text-hero` | 60px | the "403" on a revoked share page |

**11px is the floor, not a default.** Below 11px CSS, labels are unreadable on 1× screens, and the
guard rejects anything smaller. The floor is a technical limit; it is not the size for text people
act on. Status, errors, the result of an operation, the name of what a button will affect and
anything read under pressure use `text-xs` or larger; `text-2xs` is for detail that repeats or
qualifies something already said (timestamps, counts, captions, badges).

An earlier version of this page justified the floor with "Apple's HIG puts the minimum at 11pt".
That argument was wrong and is withdrawn. 11pt is not 11px CSS: in CSS a point is 1.333px, so
11pt is about 14.7px, and Apple's points line up with CSS pixels only on Apple screens at default
zoom. More importantly, the HIG figure is the smallest caption in a native type ramp whose body
text is 17pt (iOS) or 13pt (macOS) — it says how small a caption may get, not that operational
information may sit at that size. The 11px floor stands on the legibility reason alone.

The one exception is the session thumbnail on the host page: it is an `aria-hidden` picture of a
terminal screen inside a button that has its own name, not text to read.

Section titles ("eyebrows") have one treatment: `eyebrow` from `components/ui`
(`text-xs font-semibold uppercase tracking-wide text-slate-500`).

### Radius scale

Three steps, plus `full` for shapes that are round by nature (dots, pills, avatars) and `none`.

| Class | Value | Use for |
|---|---|---|
| `rounded-md` | 6px | controls: buttons, inputs, chips, badges, menu items |
| `rounded-xl` | 12px | cards, popovers, menus, panels |
| `rounded-2xl` | 16px | dialogs, sheets, the login card |

The scale replaces Tailwind's: `rounded`, `rounded-sm`, `rounded-lg` and `rounded-3xl` produce no
CSS at all, which is why the guard below fails on them instead of letting them silently vanish.

### Colour

Surfaces and text keep the existing theme variables (`--ink-*`, `--tx-*`, exposed as
`bg-ink-*` / `text-slate-*`). 3.5.7 adds semantic names on top:

| Token | Tailwind | Same as | Meaning |
|---|---|---|---|
| `--ok` | `text-ok`, `bg-ok/10` | `.wt-good` | online, success, attached |
| `--warn` | `text-warn` | `.wt-warn` | needs attention, reconnecting, pending update |
| `--danger` | `text-danger` | `.wt-danger` | offline/lost, failure, destructive |
| `--info` | `text-info` | `.wt-info` | neutral-but-highlighted state ("on demand") |
| `--accent` | `text-accent` | `.wt-accent` | selected / current |
| `--link` | `text-link` | `.wt-link` | links, link-coloured hovers |
| `--viz-ok/warn/danger` | `stroke`/`fill` via `lib/thresholds` | — | chart strokes (gauges, sparklines, load ring) |
| — | `bg-surface`, `bg-surface-raised`, `bg-surface-sunken`, `border-surface-line` | `ink-900/800/950/700` | surfaces by role |

Every status token has a value for **both** themes and is re-declared in the zones that carry
their own palette (`.wt-workspace`, `.wt-command`, `.wt-transfers-widget`, `.wt-canvas`), so
`text-ok` is always the AA-passing green for the surface it sits on. Text tokens pass 4.5:1 on
the weakest surface of their theme; the `--viz-*` chart colours target the 3:1 that WCAG 1.4.11
asks of graphics. On the dark theme the two sets are the same colours.

Do not write `text-emerald-400`, `text-sky-300` and friends for meaning. They were picked for a
dark background and fall to 1.5–2.9:1 on Aurora; this is exactly the class of bug the audits kept
finding one screen at a time.

### Thresholds

`lib/thresholds.ts` is the only place that knows CPU/memory/disk pressure: green below 70%,
amber from 70%, red from 90%. `pressureColor(pct)` returns the chart colour, `pressureTextColor`
the AA text colour. Sparkline, HostLoadRing and the host page gauges all use it — before 3.5.7
they had two different hex sets for the same signal.

## Components (`frontend/src/components/ui/`)

Import from `./ui` (or `../ui` from `settings/`).

| Component | Use when | Notes |
|---|---|---|
| `Button` | any text button | `variant`: `primary` (the one main action), `secondary`, `danger` (destructive, confirmed), `ghost` (cancel, low emphasis); `size`: `sm`, `md`, `lg` (empty-state and dialog CTAs); `loading` shows a spinner, disables, sets `aria-busy` |
| `IconButton` | a button with only an icon | `label` is **required** and becomes `aria-label` and `title`; `size` `sm` (24px) / `md` (32px); `.wt-touch` by default (44px under `pointer: coarse`); `variant` `ghost`, `ghostRaised` (ghost on an already raised `ink-800` surface), `subtle`, `danger` (neutral at rest, red on hover), `link` (the main action of an icon toolbar); `active` = the selected/on state (accent on a raised background) — visual only, the caller adds `aria-pressed` (toggle) or `aria-expanded` (disclosure) |
| `Badge` | counts, short states, tags | `tone`: `neutral`, `ok`, `warn`, `danger`, `info`, `accent`; `size` `sm` (inline count/tag) / `md` (a stand-alone pill: a role, "read-only"); `caps` for short type labels ("SSH"); the text says the state, the colour only repeats it |
| `EmptyState` | "nothing here yet" | icon + title + body + optional action; `size="page"` for full screens, `framed` for a dashed placeholder inside a page |
| `ErrorState` | "could not load" | never show an empty state for a failed fetch — it lies. `LoadFailed` is `ErrorState` with the standard title and Retry |
| `Card` | a bordered surface grouping related content | `padding` `md`/`sm`/`none`, `as` keeps the right element |

Class helpers for the cases where you need a string: `buttonClass(variant, size)`,
`iconButtonClass(...)`, `btn.primary` & co. (kept for `settings/`), `compactAction` (the 24px
text actions in transfer rows), `eyebrow`, `cardClass`.

Two rules that keep the components honest:

- **`className` is for layout only** (margins, width, flex, gap, visibility). Tailwind does not
  resolve conflicts by attribute order, so `className="px-4"` on a `Button` that already has `px-3`
  is a coin toss. Need a different size? Use `size`. A different colour or a selected state? It is
  a variant (`IconButton active`, `Badge size`/`caps`). Since 3.6.3 the guard enforces this (rule 4
  below).
- **`Button` and `IconButton` do not default `type`.** A `<button>` inside a `<form>` is a submit
  button, and migrating existing buttons must not change what Enter does in a form. In new code,
  write `type="button"` or `type="submit"`.

  *Decision note (3.6.3).* The external UI audit questioned this default. We keep it, and so does
  the audit's own recommendation: switching the components to `type="button"` would silently turn
  every migrated submit button into a no-op on Enter. The real risk the audit points at is new code
  that forgets the attribute; the rule is "write it at the call site", reviewed like any other
  prop. A product-wide change of the default is not planned.

### Disclosures, menus and touch sheets (3.6.3)

- A button that shows a panel of plain actions is a **disclosure**: the trigger has
  `aria-expanded` + `aria-controls`, the items are ordinary buttons (never `role="menuitem"`),
  Tab moves through them, Escape closes and returns focus to the trigger. Use the ARIA menu
  pattern (`role="menu"`, roving focus, arrow keys) only when all of it is implemented — the
  terminal context menu and the host "⋯" menu are menus; the session "More" panel is a disclosure.
- On a phone the same panel is a **bottom sheet** with labelled 44px actions (`.wt-sheet-bottom`
  keeps the last one above the home indicator).
- Actions with operational effect (start/stop/restart a service) do not sit as adjacent 24px
  icons on touch: under `pointer: coarse` they collapse to one labelled 44px "Actions" button that
  opens a sheet; confirmation semantics do not change. Desktop keeps the compact icons.

### Loading and errors: error ≠ empty (3.6.1)

A failed fetch tells you nothing about the server, so the UI must not say anything about it
either. "No passkeys", "no sessions", "no results" and a form showing defaults are all claims
about server state; after a failed request they are lies, and the external UI audit found them in
a dozen places (some of them on security settings). The contract:

- **Every load has three states:** loading, loaded, failed. `lib/loadable.ts` holds them
  (`Load<T>` for lists bound to a key, `LoadState` for forms). Never `.catch(() => {})` on a load
  and never turn a failure into `[]` — `src/uiaudit.guard.test.ts` fails the build if the files it
  lists do.
- **Failed first load → `ErrorState` with Retry**, never the empty state. A failed *refresh* may
  keep the last good data for the **same** key (host, query, filter), labelled as stale ("Couldn't
  refresh — showing the last loaded list."). Data of another key is never shown, not even stale:
  bind loaded data to the identity it was fetched for and ignore late responses for an old key
  (`settleLoad`, `loadFor`).
- **Forms save only over loaded values.** While a Settings section is loading or failed, its form
  is not shown (`settings/NotLoaded.tsx`) and its save path refuses (`canSave`). Defaults such as
  90/90/90 thresholds, an empty SMTP host or "no guardrail rules" would otherwise overwrite the
  real configuration.
- **Action errors go to a persistent `role="alert"` region** next to the control, mounted all the
  time (`className={err ? '…' : 'sr-only'}`) so the change is announced; the success text appears
  only after a successful response, in a `role="status"` region. Toasts disappear before they are
  read and are not a substitute.
- **Actions with side effects are re-entrancy safe:** a ref set synchronously on the first
  activation (`exclusive()` in `lib/guard.ts`) plus `Button loading` for the visual state. A React
  state flag alone lets two activations in the same tick through.

## Icons

All icons are inline SVG in `components/Icons.tsx`: 24×24 viewBox, `stroke="currentColor"`,
stroke width 2, round caps and joins, `aria-hidden`. Each takes `size` (16 by default; 12–14
inside text).

**Do**
- Use an icon from `Icons.tsx`; add one there (same style) if it is missing.
- Give every icon-only control a name: `IconButton label=…`, or `aria-label` on a native button.
- Let the icon inherit colour (`currentColor`) from a semantic class (`wt-good`, `text-danger`).
- Pair status icons with text or a screen-reader label. Colour and shape are never the only signal.

**Don't**
- Use emoji or Unicode symbols as icons (`✕ ✓ ⚠ ☰ ⛶ ⌨ 🔌 🩺 👁 🔔 ▶ ▸ …`). They render
  differently on every OS, are missing on some Android builds and in headless Chromium, and sit
  badly next to line icons.
- Select an element in a test by its glyph. Select by `aria-label`, `title`, role or test id.

**Content is not an icon.** These stay as text on purpose: the © in copyright lines; arrows that
are notation inside a sentence ("`*.example.com → 203.0.113.7`", "`→ host:port`"); key names in
keyboard legends (`↑ ↓ ↵`, `Alt+Shift+←/→`) and on the mobile keybar keys; the password
placeholder `•••••••`; and every string in `lang/*.ts`, which are translated texts and outside
this rule.

## Themes

**Midnight** (dark) and **Aurora** (light) are token overrides on `:root[data-theme]`; there are no
`dark:` classes. In Aurora, the sidebar, the Dashboard, the host page (including its embedded
Files/Forwards/Services/Docker/Databases/AI panels), dialogs and Settings follow the light theme.

The **terminal area stays dark in both themes, deliberately**: the tab strip, the session header
and toolbar, the terminal, the status bar, the session drawers, the transcript player, the file
editor surface, the command palette and the floating Transfers widget. A terminal is a dark
surface (its colour scheme is the user's terminal theme, not the app's), and the chrome around it
matches it, the way Terminal.app looks in a light macOS window. The palette stays dark because
the hosts' identity colours are calibrated for a dark background. These zones re-declare the dark
token set (`.wt-workspace`, `.wt-command`, `.wt-editor`, `.wt-transfers-widget`), so components
inside them need nothing special. A themed page that lives inside the workspace opts back out with
`.wt-canvas` (Dashboard, host page); a terminal preview on a themed page opts back in with
`.wt-workspace`.

## Guardrails

`frontend/src/design.guard.test.ts` runs with the frontend unit tests (`npx vitest run`, part of CI
and of `npm run lint`). It scans string literals, template strings and JSX text — not comments —
and fails on:

1. any arbitrary text size `text-[Npx]` (use the scale; below 11px is never allowed);
2. any radius outside `rounded-md` / `rounded-xl` / `rounded-2xl` / `rounded-full` / `rounded-none`;
3. emoji (`\p{Extended_Pictographic}`) and the icon-like symbols (`✕ ✓ ✗ ✎ ☰ ⌘ ⌨ ⏻ ⛶ ▶ ■ ● ▸ ▾ …`)
   in `.tsx` files; lone arrows and dashes count when they are the whole text of a node;
4. presentational classes in `className` on `Button`, `IconButton` and `Badge` (3.6.3): text
   colour or size, `bg-*`, `font-*`, `uppercase`/`tracking-*`/`leading-*`, padding, `ring`/`border`,
   `rounded`, `shadow` and the semantic colour classes (`wt-accent`, `wt-danger`, …), with or
   without a variant prefix (`hover:`, `sm:`). Layout (margins, width, flex, gap, `hidden`,
   opacity for reveal-on-hover, `wt-touch`) stays allowed.

Intentional exceptions live in the `ALLOW` table at the top of the file, each with its reason.
To list everything the guard sees (for an audit):
`VITE_DESIGN_REPORT=1 npx vitest run src/design.guard.test.ts`.
