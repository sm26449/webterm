# AI tools — Claude Code subagents, skills and CLAUDE.md on a host

A small graphical manager for the files that CLI coding harnesses read from disk: Claude Code's
**subagents**, **skills** and **`CLAUDE.md`** memory, plus a generic **`AGENTS.md`**. Use it when
you run Claude Code (or another agent CLI) *on* a fleet host and want to see, create or edit its
configuration without remembering the paths, typing YAML frontmatter from scratch, or opening
an editor in the terminal. It works from a phone too.

WebTerm never runs anything from these files. It only lists, creates from templates, edits and
deletes them, at their real locations on the host. Everything goes through the existing file API
(`/api/hosts/{id}/fs` list / preview / upload / mkdir / delete), so the agent gained no new op.

## What it is for

The files are the ones Claude Code documents:

| What | Global scope (`~`) | Project scope |
|---|---|---|
| Memory | `~/.claude/CLAUDE.md` | `<project>/CLAUDE.md` |
| `AGENTS.md` | — (no standard global variant) | `<project>/AGENTS.md` |
| Subagents | `~/.claude/agents/<name>.md` | `<project>/.claude/agents/<name>.md` |
| Skills | `~/.claude/skills/<name>/SKILL.md` | `<project>/.claude/skills/<name>/SKILL.md` |

Where to open it:

- **Host page → AI tools** tab (the ✦ tab), shown only for an agent host whose agent is online.
- **In a terminal**, right-click → **AI tools (Claude Code)…** (agent hosts only). Opened this way,
  the panel starts on the **Project** scope with the terminal's current directory (from the
  shell's OSC 7 reports) as the project folder.

The panel shows `CLAUDE.md` / `AGENTS.md` with **Edit** (present) or **Create** (missing), then the
**Subagents** and **Skills** lists, each item with its `description:` from the frontmatter (read
for the first 40 items; a file that cannot be read just shows no description). **Edit** opens the
same editor as the Files panel. The ↻ button reloads.

## Requirements

- **An agent host.** On SSH, telnet or jump hosts the panel only shows the "works only through the
  WebTerm agent" message; the host-page tab is hidden until the agent is online.
- **The same OS user as the harness.** The agent runs terminal sessions and file operations as the
  one OS user it runs as, so a file created here lands in that user's `~` and is owned by them —
  exactly where a `claude` started from a WebTerm terminal on that host looks. There is no runtime
  check comparing users: if you run Claude Code as a *different* user on that host (e.g. via
  `sudo -u`), the global scope here is not its `~/.claude`; use the Project scope on a folder
  that user reads, or manage it from that user's own agent.
- **Claude Code does not need to be installed.** Nothing checks for it; the panel only manages
  files. Missing directories (`~/.claude/agents` before your first agent) are normal and are
  created on the first **Create**.
- On a host with **Require 2FA**, the file calls need the host step-up like the Files panel.
  The file routes take a browser session only, so automation tokens cannot use them.

## Scopes: user and project

The tab strip switches between **Global (~)** and **Project**:

- **Global (~)** — *"Applies to every project for this user on this host (~/.claude)."* The home
  directory is resolved by asking the agent for `~`, so paths are shown with `~` but written as
  absolute paths.
- **Project** — *"Lives in the project folder, so you can commit it with the code."* Type the
  folder and press **Open**. It must be absolute or start with `~` (a relative path is refused
  with *"Use an absolute path (or one starting with ~)."*); a trailing `/` is dropped. The last
  folder you opened is remembered per host in the browser's local storage. Opening the panel from
  a terminal's right-click menu pre-fills the terminal's current folder instead.

`AGENTS.md` appears only in the Project scope.

## Templates

**New agent** / **New skill** opens an inline form: a **Name** and a **Template**.

- **Name**: lowercase letters, digits and single hyphens, at most 64 characters (`code-reviewer`).
  An invalid name is **not** silently corrected; the form shows the rule and a suggestion
  (*"Try: code-reviewer"*). The rule is also a path barrier: no `/`, `..` or spaces, so a name
  cannot escape the directory.
- **Templates** (the content is English on purpose: the model reads it, not the UI):

| Kind | Template | What you get |
|---|---|---|
| Subagent | **Blank agent** | frontmatter `name` + `description`, a placeholder system prompt |
| Subagent | **Code reviewer** | `tools: Read, Grep, Glob, Bash`; reviews `git diff`, reports by severity with file:line and a fix |
| Skill | **Blank skill** | frontmatter `name` + `description`, `## Instructions` and `## Examples` sections |
| `CLAUDE.md` | (single) | Overview / Commands / Conventions skeleton |
| `AGENTS.md` | (single) | Setup / Testing / Conventions skeleton |

After **Create** the parent directories are made (`mkdir -p`), the file is written and opened in
the editor straight away.

Example: Project scope on `~/src/shop`, **New agent** → name `code-reviewer`, template *Code
reviewer* → `~/src/shop/.claude/agents/code-reviewer.md`. **New skill** → `release-notes` →
`~/src/shop/.claude/skills/release-notes/SKILL.md`.

## Safety

- **Never overwrites.** Right before writing, the panel re-lists the target directory; if the
  file already exists it stops with *"… already exists — open it from the list instead."* Saves
  from the editor carry the file's mtime, so a concurrent change on the host is reported as a
  conflict instead of being overwritten (unless you choose to overwrite). Uploads are written to a
  temp file and renamed into place.
- **Delete asks first.** A subagent deletes its one `.md` file; a skill deletes **its whole
  folder** recursively (*"SKILL.md and any files next to it"*). There is no undo.
- **Audit.** Creating/saving (upload), mkdir and delete are logged like any other change; the
  description previews are logged as content reads (`/preview`).
- **These files steer an AI that can act on the host.** A subagent's `tools:` line and a skill's
  instructions decide what Claude Code will do there, as the agent user. Treat editing them like
  editing a script that user runs. Anyone past WebTerm login can edit them (the single-account
  model of the [threat model](THREAT-MODEL.md)).
- The description in the list is read with a simple line match on `description:` in the
  frontmatter, not a YAML parser; an unusual frontmatter only loses its description in the list,
  Claude Code itself is unaffected.

## Maintenance notes

- UI: `frontend/src/components/AiToolsPanel.tsx`; paths, name rule and templates (pure, testable):
  `frontend/src/lib/aitools.ts`.
- Backend: the generic file routes in `gateway/app/api.py` (`/api/hosts/{id}/fs*`), agent ops
  `fs_list`, `fs_read`, `fs_write`, `fs_mkdir`, `fs_rename`, `fs_delete` in `agent/ptyd.py`.
