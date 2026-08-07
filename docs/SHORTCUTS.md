# Keyboard shortcuts

Press **`?`** in the app for the live cheatsheet — it is generated from the single
registry (`frontend/src/lib/shortcuts.ts`), so anything registered there appears
automatically. A few shortcuts are handled directly in components rather than through the
registry (`Alt+1…9`, `Alt+↑/↓`, `Ctrl+M`); those are listed in the cheatsheet through an
explicit `EXTRA` block in `KeyboardHelp.tsx`, which is the part that can fall behind.

`Mod` = **⌘** on macOS, **Ctrl** everywhere else.

## Navigation

| Shortcut | Action |
|---|---|
| `Mod+K` | Command palette (sessions, hosts, actions, snippets) |
| `Mod+Shift+K` | Palette — universal escape hatch, works from the terminal too |
| `Alt+1..9` | Jump to tab N |
| `Alt+←` / `Alt+→` | Previous / next tab |
| `Mod+Shift+W` | Close the tab (the session stays active) |
| `Mod+Shift+T` | Reopen the last closed tab |
| `Alt+0` | Home (dashboard) |
| `/` | Search host / session / history (sidebar) |

## Session

| Shortcut | Action |
|---|---|
| `Mod+Shift+F` | Search the session history (scrollback) |
| `Alt+↑` / `Alt+↓` | Jump to the previous / next command (requires [shell integration](SHELL-INTEGRATION.md)) |
| `Alt+D` | Split: open the session side by side |
| `Alt+P` | Detach the session into a window |
| `Alt+S` | Saved commands (snippets) |
| `Alt++` / `Alt+−` | Larger / smaller font |

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
- **Identify by `e.code`, not by character**: on macOS, `Alt+letter` produces
  alternate characters ("¡", "∑"), so `e.key` would never match. The exceptions are the
  few combinations where the character *is* the identity (digits, arrows).
- **A single registry**: the handler, cheatsheet, and tooltips all read from the
  same place. A new shortcut is added in `lib/shortcuts.ts` — and appears everywhere automatically.
