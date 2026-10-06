# Keyboard shortcuts

Press **`?`** in the app for the live cheatsheet — it is generated from the single
registry (`frontend/src/lib/shortcuts.ts`), so anything registered there appears
automatically. A few shortcuts are handled directly in components rather than through the
registry (`Alt+1…9`, `Alt+↑/↓`, `Ctrl+M`, `Mod+Shift+K`); those are listed in the cheatsheet
through an explicit `EXTRA` block in `KeyboardHelp.tsx`, which is the part that can fall behind.
Panel-local keys and mouse/touch gestures (below) are listed there too, since 3.5.1.

`Mod` = **⌘** on macOS, **Ctrl** everywhere else.

## Navigation

| Shortcut | Action |
|---|---|
| `Mod+K` | Command palette (sessions, hosts, actions, snippets) |
| `Mod+Shift+K` | Palette — universal escape hatch, works from the terminal too |
| `Alt+1..9` | Jump to tab N |
| `Alt+←` / `Alt+→` | Previous / next tab |
| `Alt+W` | Close the tab (the session stays active) |
| `Alt+T` | Reopen the last closed tab |
| `Alt+Shift+←` / `Alt+Shift+→` | Move the focused tab left / right (keyboard alternative to drag; `←`/`→`/`Home`/`End` move focus between tabs first) |
| `Alt+0` | Home (dashboard) |
| `/` | Search host / session / history (sidebar) |
| `?` | This cheatsheet (outside the terminal and text fields) |

## Session

| Shortcut | Action |
|---|---|
| `Mod+Shift+F` | Search the session history (scrollback) |
| `Alt+↑` / `Alt+↓` | Jump to the previous / next command (requires [shell integration](SHELL-INTEGRATION.md)) |
| `Alt+D` | Split: open the session side by side |
| `Alt+P` | Detach the session into a window |
| `Alt+S` | Saved commands (snippets) |
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
| `Mod+Enter` | Git panel: commit (from the message field) |
| `Shift+Enter` | Scrollback search: previous match (`Enter` = next) |
| `←` / `→` on the split divider | Resize the split; double-click the divider resets it to 50/50 |

## Mouse and touch

| Gesture | Action |
|---|---|
| Right-click / long-press in a terminal | Terminal menu: open the selected path in Files (when the selection looks like a path), upload into the session's folder, new file/folder here, clear the terminal |
| Double-click a session in Host overview | Open it |

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
