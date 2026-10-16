# Keyboard shortcuts

Press **`?`** in the app for the live cheatsheet — it is generated from the single
registry (`frontend/src/lib/shortcuts.ts`), so anything registered there appears
automatically. A few shortcuts are handled directly in components rather than through the
registry (`Alt+1…9`, `Alt+↑/↓`, `Ctrl+M`, `Mod+Shift+K`); those are listed in the cheatsheet
through an explicit `EXTRA` block in `KeyboardHelp.tsx`, which is the part that can fall behind.
Panel-local keys and mouse/touch gestures (below) are listed there too, since 3.5.1.

`Mod` = **⌘** on macOS, **Ctrl** everywhere else.

**Split views — the rule:** tab-level navigation (clicking a tab, `Alt+1…9`, `Alt+0`, picking a
session in the sidebar or palette) leaves the split view; pane-level navigation stays in it
(`Alt+←/→` between panes, `Alt+M`, `Alt+X`, clicking or tabbing into a pane). Its chip stays in the
tab bar, so you can always return. `Alt+M` and `Alt+X` only act inside a split view; elsewhere the
key goes to the shell untouched. On **macOS**, `Option+M` / `Option+X` normally type `µ` / `≈`: there
the shortcut fires only when the key produces the plain letter (e.g. Option set to act as Meta in a
custom layout) — otherwise the character goes to the terminal and you use the pane bar's **Move to…**
and maximize buttons (or double-click the pane title).

## Navigation

| Shortcut | Action |
|---|---|
| `Mod+K` | Command palette (sessions, hosts, actions, snippets) |
| `Mod+Shift+K` | Palette — universal escape hatch, works from the terminal too |
| `Alt+1..9` | Jump to tab N |
| `Alt+←` / `Alt+→` | Previous / next tab — inside a split view: previous / next **pane** |
| `Alt+W` | Close the tab (the session stays active); does nothing inside a split view |
| `Alt+T` | Reopen the last closed tab |
| `Alt+Shift+←` / `Alt+Shift+→` | Move the focused tab left / right (keyboard alternative to drag; `←`/`→`/`Home`/`End` move focus between tabs first) |
| `Alt+0` | Home (dashboard) — leaves a split view |
| `/` | Search host / session / history (sidebar) |
| `?` | This cheatsheet (outside the terminal and text fields) |

## Session

| Shortcut | Action |
|---|---|
| `Mod+Shift+F` | Search the session history (scrollback) |
| `Alt+↑` / `Alt+↓` | Jump to the previous / next command (requires [shell integration](SHELL-INTEGRATION.md)) |
| `Alt+D` | Split: open the session side by side (reuses a split view with the same two sessions) |
| `Alt+M` | Split view: swap the focused pane with the next one (macOS: see the note above) |
| `Alt+X` | Split view: maximize / restore the focused pane (macOS: see the note above) |
| `Alt+P` | Detach the session into a window |
| `Alt+S` | Saved commands (snippets) |
| `Alt+E` | Open / close the session's **Files** panel (inside a split view: the focused pane's). Not bound in bash/zsh readline; in fish it replaces "edit the line in `$EDITOR`" — the same trade-off as `Alt+S`/`Alt+P`. macOS: see the note above (`Option+E` is the accent dead key) |
| `Alt++` / `Alt+−` | Larger / smaller font |
| `Mod+Shift+V` | Paste picker — clipboard history shared by all terminals (`Shift+Enter` in the picker = paste and run) |

The paste picker lists what you copied in **any** terminal of this window: the last 10 copies,
newest first, each with its source session and age ("emaildb · 4 min ago"). An entry expires
1 hour after it was last copied; copying the same text again moves it back to the top. `✕`
removes one entry and **Clear history** removes all of them. The history lives in memory only
(never in browser storage, since it often holds passwords and tokens): a reload loses it, and
it is cleared on idle-lock and on logout. A popped-out session window has its own history.

## Panels (only while the panel has focus)

| Shortcut | Action |
|---|---|
| `Mod+S` | File editor: save |
| `Mod+F` / `Mod+H` | File editor: find / replace |
| `Mod+G` | File editor: go to line |
| `Mod+/` | File editor: toggle line comment (in the file's language) |
| `Alt+Z` | File editor: toggle word wrap |
| `F1` | File editor: command palette (every editor command, with its shortcut) |
| `Mod+Enter` | Git panel: commit (from the message field) |
| `Shift+Enter` | Scrollback search: previous match (`Enter` = next) |
| `←` / `→` (`↑` / `↓` on a horizontal one), `Home` / `End` on a split divider | Resize the panes; Home / End go to the edge; double-click the divider evens the panes out |

## Files list

Active **only while the Files list has focus** — never in the terminal, never in a text field
(the path, the filter, an inline rename). The list keeps the focus (roving focus): it gets it when
the panel opens and back after navigating, renaming, creating, deleting, closing the editor, a
dialog or the row menu; clicking a row puts it there too. Nothing here uses `Alt+←/→` — those stay
the tab / pane keys. `Mod+U`, `Mod+R` / `F5` and `Mod+L` are taken from the browser **only** while
the list has focus.

| Shortcut | Action |
|---|---|
| `Enter` / double-click / double-tap | Open: enter the folder, or edit the file (a single click on a folder name enters it too) |
| `↑` / `↓`, `Home` / `End` / `PgUp` / `PgDn` | Move the current row |
| letters | Type a name to jump to it (prefix, ~1 s buffer; repeating one letter cycles through the names that start with it) |
| `Backspace` / `Alt+↑` (macOS `⌘↑`) | Up one level (the folder you came from stays selected) |
| `Mod+[` / `Mod+]`, mouse buttons 4 / 5 | Back / forward through the folders visited in this panel |
| `Mod+L` | Edit the path (also: click the last breadcrumb, or the pencil); `Tab` completes a folder name, `Esc` cancels |
| `/` | Filter (the filter is cleared when you change folder) |
| `F2` | Rename (the name without its extension is pre-selected) |
| `F7` | New folder |
| `Alt+N` | New file (macOS: only when Option doesn't type a character) |
| `Mod+U` | Upload files here |
| `F5` / `Mod+R` | Reload the listing (not the page) |
| `Mod+C` | Copy the name (with a multi-selection: the selected names, one per line); a text selection is copied normally |
| `Mod+Shift+C` | Copy the full path |
| `Shift+F10` / Menu key / right-click | Row actions menu: open / edit, download (`.tgz` for folders), rename, duplicate, copy name, copy path, copy to host…, **cd here in the terminal**, delete. `↑`/`↓`/`Home`/`End` move, `Esc` closes and returns to the row. Right-click on the empty part of the list: new file / folder, upload, reload, copy path, cd here |
| `Space`, `Shift+↑`/`↓`, `Mod+A` | Select a row, extend the selection, select all visible |
| `Delete` | Delete (the selection, or the current row). The confirmation has the focus: `Enter` deletes, `Esc` cancels |
| `Esc` | Clear the selection; a second `Esc` closes the panel |

**cd here in the terminal** (session panel only) types `cd -- '<path>'` at the prompt and does
**not** press Enter — like *Insert path*: you see the command and run it yourself. It is refused
with a message when WebTerm cannot see a shell prompt (a program such as `mc`, `vim` or `less`
is in front) and for paths with control, invisible or bidirectional characters.

## Mouse and touch

| Gesture | Action |
|---|---|
| Right-click / long-press in a terminal | Terminal menu: open the selected path in Files (when the selection looks like a path), upload into the session's folder, new file/folder here, clear the terminal |
| Double-click a session in Host overview | Open it |
| Drag a split pane's title bar onto another pane | Swap the two panes (or use the pane's **Move to…** menu) |
| Drag a tab onto a split pane | Show that session in the pane (if it is already another pane, the two swap) |
| Double-click a split pane's title bar | Maximize the pane; again to restore |
| Tap the tab-count button at the end of the tab bar (phones, or whenever tabs don't fit) | List of **all** open tabs: host, live / closed / lost, new-output dot; tap to switch, ✕ closes the tab (the session keeps running). `↑`/`↓`/`Home`/`End` move, `Esc` closes |
| Back button / swipe-back while a panel is open on a phone | Closes the panel (Files, Git, Forwards, Docker, Services, Toolbox, AI tools, Commands) and returns to the terminal, instead of leaving the app. In **Files** it first goes back through the folders you visited; it closes the panel only at the first one |
| Tap `⋯` on a file row (touch) | The row's actions as a bottom sheet (44 px targets); the floating `+` holds new file / new folder / upload. Long-press still starts a multi-selection; the selection bar sits at the bottom |

## Touch key bar (phones and tablets)

Shown under the terminal on any touch-first device (coarse pointer), at any width; hidden with a
mouse. Since 3.5.5 it has **two rows**, so no key hides off-screen:

| Row | Keys |
|---|---|
| 1 — always needed | `Ctrl` and `Alt` (latched: tap, then the next key gets the modifier; lit while armed), `Esc`, `Tab`, `↑` `↓` `←` `→` |
| 2 — the rest | Paste `⎘`, `^C` `^D`, `⇞` `⇟` (tmux scrollback, tmux hosts only), `\|` `/` `-` `~`, `Home` `End` `PgUp` `PgDn`, `^Z` `^R` |

Row 2 scrolls sideways on narrow phones; a fade on its right edge shows there is more.
On a **short screen** (under ~420 px tall, e.g. a phone in landscape) the bar collapses to row 1
plus a `⌃` toggle that brings row 2 back; the choice is remembered on that device only. `Ctrl`/`Alt`
combine with any key the way xterm sends them (`Alt+↑` = `ESC [1;3A`, `Ctrl+PgUp` = `ESC [5;5~`).

On phones, session panels open as a **full-screen sheet** with a `← Terminal` button at the top
(`Esc` also closes them); on tablets and desktops they stay side panels.

## Terminal (owned by the shell)

| Shortcut | Action |
|---|---|
| `Ctrl+C` | Copies **if you have a selection**, otherwise interrupts the process (as in VS Code) |
| `Ctrl+Shift+C` | Always copies |
| `Ctrl+V` / `Mod+V` | Paste (via bracketed paste — multi-line is safe) |
| `Ctrl+M` | "Tab focus mode": Tab leaves the terminal for the rest of the app |
| `Ctrl+R`, `Ctrl+D`, `Ctrl+L`… | **Untouched** — they belong to the shell |

## Design principles

- **The terminal comes first**: no app shortcut steals a combination the shell
  uses. That's why actions live on `Mod+Shift+*` or `Alt+*`.
- **Nothing the browser reserves**: `Ctrl+Shift+W` / `Ctrl+Shift+T` close the browser window /
  reopen a browser tab on Chromium and cannot be intercepted, so tab close/reopen live on
  `Alt+W` / `Alt+T`. (On Firefox for Windows/Linux, `Alt+letter` may also open a menu-bar entry.)
- **Identify by `e.code`, not by character**: on macOS, `Alt+letter` produces
  alternate characters ("¡", "∑"), so `e.key` would never match. The exceptions are the
  few combinations where the character *is* the identity (digits, arrows).
- **A single registry**: the handler, cheatsheet, and tooltips all read from the
  same place. A new shortcut is added in `lib/shortcuts.ts` — and appears everywhere automatically.
