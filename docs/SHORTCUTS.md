# Keyboard shortcuts

Press **`?`** in the app for the live cheatsheet — it is generated from the single
registry (`frontend/src/lib/shortcuts.ts`), so anything registered there appears
automatically. A few shortcuts are handled directly in components rather than through the
registry (`Alt+1…9`, `Alt+↑/↓`, `Ctrl+M`, `Mod+Shift+K`); those are listed in the cheatsheet
through an explicit `EXTRA` block in `KeyboardHelp.tsx`, which is the part that can fall behind.
Panel-local keys (`Mod+S`, `Mod+Enter`) are not in the cheatsheet.

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
| `Mod+Shift+V` | Paste picker — clipboard history of this terminal (`Shift+Enter` in the picker = paste and run) |

## Panels (only while the panel has focus)

| Shortcut | Action |
|---|---|
| `Mod+S` | File editor: save |
| `Mod+Enter` | Git panel: commit (from the message field) |

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
