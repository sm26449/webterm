import { describe, expect, it } from 'vitest'
import type { Terminal } from '@xterm/xterm'
import { CommandTracker } from './commands'
import { insertPathConfirmed, insertPathOutcome, registerInsertTarget, typeIntoConfirmed, typeIntoOutcome } from './transfers'

// Hotfix 3.6.13: după o reataşare sub tmux, cu un CLI (Claude Code) în prim-plan, calea lipită nu se
// mai tasta ('notPrompt'). Rândul din Transferuri oferă acum „Type into terminal": un click explicit,
// aceleaşi porţi, mereu ca bracketed paste, fără Enter — şi NICIODATĂ automat.
const target = (typed: string[], opts: { bracketed?: boolean; prompt?: boolean; ok?: boolean } = {}) => ({
  send: (t: string) => { typed.push(t); return opts.ok ?? true },
  bracketedPaste: () => opts.bracketed ?? false,
  atPrompt: () => opts.prompt ?? false,
})
const PATH = '/home/webterm/.webterm/inbox/20261016-101500.png'

describe('Type into terminal after notPrompt (hotfix 3.6.13)', () => {
  it('reattach under tmux with a program running: the automatic insert stays refused (guardrail unchanged)', () => {
    // tracker după replay + starea hub-ului „ultimul marcaj LIVE = C" (un program rulează)
    const buf = { type: 'normal', baseY: 0, cursorY: 0, cursorX: 2, getLine: () => ({ length: 80, translateToString: () => '' }) }
    const fake = { buffer: { active: buf }, registerMarker: () => ({ line: 0, isDisposed: false, dispose() {} }) }
    const tr = new CommandTracker(fake as unknown as Terminal)
    tr.reset()
    expect(tr.applyHubState({ integrated: true, last: 'C', synced: false })).toBe(true)
    expect(tr.atPrompt()).toBe(false)
    const typed: string[] = []
    // DECSET 2004 nu se vede după reataşare (tmux îl trimite clientului doar la attach)
    registerInsertTarget('cli', { ...target(typed), atPrompt: () => tr.atPrompt() })
    expect(insertPathOutcome('cli', PATH)).toBe('notPrompt')
    expect(typed).toEqual([])
    // click-ul explicit: tastat, împachetat, cu spaţiu, fără Enter
    expect(insertPathConfirmed('cli', PATH)).toBe('typed')
    expect(typed).toEqual(['\x1b[200~' + PATH + ' \x1b[201~'])
    expect(typed[0]).not.toMatch(/[\r\n]/)
    registerInsertTarget('cli', null)
  })

  it('always wraps in bracketed-paste markers, quoting the path like the automatic insert', () => {
    const typed: string[] = []
    registerInsertTarget('q', target(typed))
    expect(insertPathConfirmed('q', "/tmp/it's here.png")).toBe('typed')
    expect(typed).toEqual(["\x1b[200~'/tmp/it'\\''s here.png' \x1b[201~"])
    registerInsertTarget('q', null)
  })

  it('wraps even at a prompt (no plain-typed variant): a readline/CLI that asked for it gets a paste', () => {
    const typed: string[] = []
    registerInsertTarget('pr', target(typed, { prompt: true }))
    expect(typeIntoConfirmed('pr', 'abc')).toBe('typed')
    expect(typed).toEqual(['\x1b[200~abc\x1b[201~'])
    registerInsertTarget('pr', null)
  })

  it('refuses unsafe text: control characters, ESC (bracket breakout), newline, bidi, empty', () => {
    const typed: string[] = []
    registerInsertTarget('u', target(typed))
    for (const bad of ['a\r', 'a\nid', 'x\x1b[201~; id', 'a‮b', 'a b', 'a\x00b', 'a\x9bb', '', 'a'.repeat(32769)])
      expect(typeIntoConfirmed('u', bad)).toBe('unsafe')
    expect(typed).toEqual([])
    // a path: shellQuote strips control bytes first, so the only ESCs typed are the brackets
    expect(insertPathConfirmed('u', '/tmp/a\x1b[201~b\n')).toBe('typed')
    expect(typed).toEqual(["\x1b[200~'/tmp/a[201~b' \x1b[201~"])
    registerInsertTarget('u', null)
  })

  it('read-only / muted / closed socket (the target says no) → refused; a closed tab → noTarget', () => {
    registerInsertTarget('ro', target([], { ok: false }))
    expect(insertPathConfirmed('ro', PATH)).toBe('refused')
    registerInsertTarget('ro', null)
    expect(insertPathConfirmed('ro', PATH)).toBe('noTarget')
    expect(insertPathConfirmed(undefined, PATH)).toBe('noTarget')
  })

  it('never returns notPrompt, and the guarded variant is unchanged for raw-mode programs', () => {
    const typed: string[] = []
    registerInsertTarget('mc', target(typed))
    expect(typeIntoOutcome('mc', 'abc')).toBe('notPrompt')
    expect(typed).toEqual([])
    expect(typeIntoConfirmed('mc', 'abc')).not.toBe('notPrompt')
    registerInsertTarget('mc', null)
  })
})
