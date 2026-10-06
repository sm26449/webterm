import { describe, expect, it } from 'vitest'
import {
  TEMPLATES, collectionDir, frontmatterDescription, itemName, itemPath, joinPath,
  singlePath, slugify, templatesFor, validName,
} from './aitools'

const b = { home: '/home/ana', project: '/srv/app' }

describe('joinPath', () => {
  it('fără dubluri de / şi fără / final', () => {
    expect(joinPath('/home/ana/', '.claude', 'agents')).toBe('/home/ana/.claude/agents')
    expect(joinPath('/', 'CLAUDE.md')).toBe('/CLAUDE.md')
    expect(joinPath('/')).toBe('/')
  })
})

describe('căi pe scope', () => {
  it('CLAUDE.md global sub ~/.claude, de proiect în rădăcina proiectului', () => {
    expect(singlePath('claude-md', 'global', b)).toBe('/home/ana/.claude/CLAUDE.md')
    expect(singlePath('claude-md', 'project', b)).toBe('/srv/app/CLAUDE.md')
  })
  it('AGENTS.md doar pe proiect', () => {
    expect(singlePath('agents-md', 'global', b)).toBeNull()
    expect(singlePath('agents-md', 'project', b)).toBe('/srv/app/AGENTS.md')
  })
  it('fără proiect ales, scope-ul de proiect nu are căi', () => {
    const nb = { home: '/home/ana', project: null }
    expect(singlePath('claude-md', 'project', nb)).toBeNull()
    expect(collectionDir('agent', 'project', nb)).toBeNull()
  })
  it('colecţii şi elemente', () => {
    expect(collectionDir('agent', 'global', b)).toBe('/home/ana/.claude/agents')
    expect(collectionDir('skill', 'project', b)).toBe('/srv/app/.claude/skills')
    expect(itemPath('agent', '/srv/app/.claude/agents', 'rev')).toBe('/srv/app/.claude/agents/rev.md')
    expect(itemPath('skill', '/srv/app/.claude/skills', 'pdf')).toBe('/srv/app/.claude/skills/pdf/SKILL.md')
  })
})

describe('itemName', () => {
  it('agenţi = fişiere .md; skill-uri = directoare neascunse', () => {
    expect(itemName('agent', { name: 'rev.md' })).toBe('rev')
    expect(itemName('agent', { name: 'notes.txt' })).toBeNull()
    expect(itemName('agent', { name: 'x.md', dir: true })).toBeNull()
    expect(itemName('skill', { name: 'pdf', dir: true })).toBe('pdf')
    expect(itemName('skill', { name: '.cache', dir: true })).toBeNull()
    expect(itemName('skill', { name: 'README.md' })).toBeNull()
  })
})

describe('validName / slugify', () => {
  it('acceptă doar litere mici, cifre, cratime', () => {
    expect(validName('code-reviewer')).toBe(true)
    expect(validName('a1')).toBe(true)
    for (const bad of ['', 'Code', 'a b', '../x', 'a/b', '-a', 'a-', 'a--b', 'x'.repeat(65)])
      expect(validName(bad)).toBe(false)
  })
  it('slugify produce un nume valid', () => {
    expect(slugify('  Code Reviewer!! ')).toBe('code-reviewer')
    expect(slugify('Ştiinţă și artă')).toBe('stiinta-si-arta')
    expect(validName(slugify('../../etc/passwd'))).toBe(true)
  })
})

describe('frontmatterDescription', () => {
  it('citeşte description, cu sau fără ghilimele', () => {
    expect(frontmatterDescription('---\nname: a\ndescription: Does X\n---\nbody')).toBe('Does X')
    expect(frontmatterDescription('---\ndescription: "Quoted"\n---\n')).toBe('Quoted')
  })
  it('fără frontmatter = null', () => {
    expect(frontmatterDescription('# title\ndescription: no')).toBeNull()
  })
})

describe('şabloane', () => {
  it('fiecare tip are cel puţin un şablon', () => {
    for (const k of ['claude-md', 'agents-md', 'agent', 'skill'] as const)
      expect(templatesFor(k).length).toBeGreaterThan(0)
  })
  it('agenţii şi skill-urile au frontmatter cu numele dat şi o descriere', () => {
    for (const t of TEMPLATES.filter((t) => t.kind === 'agent' || t.kind === 'skill')) {
      const txt = t.body('my-thing')
      expect(txt.startsWith('---\nname: my-thing\n')).toBe(true)
      expect(frontmatterDescription(txt)).toBeTruthy()
    }
  })
})
