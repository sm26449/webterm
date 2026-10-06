/* AI tools: WebTerm ca MANAGER grafic al fişierelor de configurare pe care le citesc harness-urile
   CLI (Claude Code, AGENTS.md) — la locaţiile lor reale, pe host, ca acelaşi user de OS care
   rulează harness-ul (agentul face sesiunile ŞI fs-ul ca acelaşi user; pe SSH = userul ssh).
   WebTerm nu rulează nimic din ele; doar le listează, creează din şabloane, editează şi şterge.

   Aici stă partea „pură" (testabilă fără DOM): catalogul de tipuri, căile pe scope (global =
   home, proiect = un director), validarea numelor şi şabloanele. Panoul doar o foloseşte.
   Schema e cea documentată de Claude Code: sub-agenţi = `.claude/agents/<nume>.md` cu
   frontmatter `name`/`description` (+ opţional `tools`, `model`); skill-uri =
   `.claude/skills/<nume>/SKILL.md` cu `name`/`description`; memoria = `CLAUDE.md`
   (global `~/.claude/CLAUDE.md`, proiect `./CLAUDE.md`); `AGENTS.md` generic = doar proiect. */

export type AiScope = 'global' | 'project'
export type AiKind = 'claude-md' | 'agents-md' | 'agent' | 'skill'

/** Unirea de căi POSIX fără dubluri de `/` (baza poate fi `~` sau absolută). */
export function joinPath(...parts: string[]): string {
  const out = parts.filter((p) => p !== '').join('/').replace(/\/{2,}/g, '/')
  return out.length > 1 ? out.replace(/\/$/, '') : out
}

/** Baza unui scope: `home` pentru global, directorul proiectului altfel. */
export interface AiBases { home: string; project: string | null }

/** Fişierele „singulare" (un fişier fix pe scope). `null` = nu există în scope-ul acela. */
export function singlePath(kind: 'claude-md' | 'agents-md', scope: AiScope, b: AiBases): string | null {
  const base = scope === 'global' ? b.home : b.project
  if (!base) return null
  if (kind === 'claude-md') return scope === 'global' ? joinPath(base, '.claude', 'CLAUDE.md') : joinPath(base, 'CLAUDE.md')
  return scope === 'project' ? joinPath(base, 'AGENTS.md') : null   // AGENTS.md n-are variantă globală standard
}

/** Directorul unei colecţii (sub-agenţi / skill-uri) pe scope. */
export function collectionDir(kind: 'agent' | 'skill', scope: AiScope, b: AiBases): string | null {
  const base = scope === 'global' ? b.home : b.project
  if (!base) return null
  return joinPath(base, '.claude', kind === 'agent' ? 'agents' : 'skills')
}

/** Calea fişierului unui element dintr-o colecţie. */
export function itemPath(kind: 'agent' | 'skill', dir: string, name: string): string {
  return kind === 'agent' ? joinPath(dir, `${name}.md`) : joinPath(dir, name, 'SKILL.md')
}

/** Numele unui element dintr-o intrare de director: `x.md` → `x` la agenţi; directorul la skill-uri. */
export function itemName(kind: 'agent' | 'skill', entry: { name: string; dir?: boolean }): string | null {
  if (kind === 'agent') return !entry.dir && /\.md$/i.test(entry.name) ? entry.name.replace(/\.md$/i, '') : null
  return entry.dir && !entry.name.startsWith('.') ? entry.name : null
}

/** Numele acceptat de Claude Code pentru agenţi/skill-uri: litere mici, cifre, cratimă; max 64.
    Validarea e şi o barieră de cale: fără `/`, `..` sau spaţii nu poţi ieşi din director. */
export function validName(name: string): boolean {
  return /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name) && name.length <= 64
}

/** Normalizarea unui nume tastat liber spre forma validă (sugestie, nu impunere). */
export function slugify(s: string): string {
  return s.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64).replace(/-+$/, '')
}

/** Descrierea dintr-un frontmatter YAML simplu (`description: …` pe o linie). Pentru listă —
    nu e un parser YAML; un frontmatter exotic doar nu-şi arată descrierea. */
export function frontmatterDescription(text: string): string | null {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text)
  if (!m) return null
  const line = /^description:\s*(.+)$/m.exec(m[1])
  if (!line) return null
  return line[1].trim().replace(/^(['"])(.*)\1$/, '$2') || null
}

export interface AiTemplate { id: string; kind: AiKind; body: (name: string) => string }

/** Şabloanele de pornire. Conţinutul e în engleză intenţionat: e citit de model, nu de UI. */
export const TEMPLATES: AiTemplate[] = [
  {
    id: 'agent-blank', kind: 'agent',
    body: (n) => `---
name: ${n}
description: Describe when Claude should delegate to this agent (one or two sentences).
---

You are a specialised assistant. Explain the role, the steps to follow and what to return.
`,
  },
  {
    id: 'agent-reviewer', kind: 'agent',
    body: (n) => `---
name: ${n}
description: Reviews recent code changes for bugs, security issues and readability. Use after writing or modifying code.
tools: Read, Grep, Glob, Bash
---

You are a senior code reviewer.

1. Run \`git diff\` to see the recent changes and focus on the modified files.
2. Look for correctness bugs, unhandled errors, security problems (secrets, injection,
   unsafe input) and confusing code.
3. Report findings ordered by severity, each with file:line, the problem and a concrete fix.
   Say clearly when you find nothing worth changing.
`,
  },
  {
    id: 'skill-blank', kind: 'skill',
    body: (n) => `---
name: ${n}
description: What this skill does and when Claude should use it.
---

# ${n}

## Instructions
Step-by-step guidance for Claude.

## Examples
- An example request and the expected result.
`,
  },
  {
    id: 'claude-md', kind: 'claude-md',
    body: () => `# Project notes for Claude

## Overview
What this project is and how it is organised.

## Commands
- Build: \`…\`
- Test: \`…\`

## Conventions
- Code style, naming and anything Claude should always (or never) do here.
`,
  },
  {
    id: 'agents-md', kind: 'agents-md',
    body: () => `# AGENTS.md

Instructions for coding agents working in this repository.

## Setup
- How to install dependencies and run the project.

## Testing
- How to run the tests; what must pass before a change is done.

## Conventions
- Style, structure and rules to follow.
`,
  },
]

export function templatesFor(kind: AiKind): AiTemplate[] {
  return TEMPLATES.filter((t) => t.kind === kind)
}
