import { describe, expect, it } from 'vitest'
import type { Terminal } from '@xterm/xterm'
import { CommandTracker } from './commands'
import { opaqueInput } from './broadcastGuard'
import { pasteModeUntrusted, trustedBracketed } from './termmodes'
import { typeCommandOutcome } from './rootmove'
import { canTypeInto, insertPathConfirmed, insertPathOutcome, notTypedReasonKey, registerInsertTarget, typeIntoConfirmed, typeIntoOutcome } from './transfers'

// Hotfix 3.6.13: după o reataşare sub tmux, cu un CLI (Claude Code) în prim-plan, calea lipită nu se
// mai tasta ('notPrompt'). Rândul din Transferuri oferă acum „Type into terminal": un click explicit,
// aceleaşi porţi, fără Enter — şi NICIODATĂ automat. Plus review-ul independent (M1, M2, L1–L4):
// sub tmux `bracketedPasteMode` e lipicios (tmux trimite ?2004h o dată, la attach) → nu-l credem.
type Opts = { bracketed?: boolean; prompt?: boolean; ok?: boolean; tmux?: boolean; canType?: boolean }
const target = (typed: string[], opts: Opts = {}) => ({
  send: (t: string) => { typed.push(t); return opts.ok ?? true },
  bracketedPaste: () => opts.bracketed ?? false,
  atPrompt: () => opts.prompt ?? false,
  viaTmux: () => opts.tmux ?? false,
  canType: () => opts.canType ?? true,
})
const PATH = '/home/webterm/.webterm/inbox/20261016-101500.png'
const W = (s: string) => '\x1b[200~' + s + '\x1b[201~'

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
    registerInsertTarget('cli', { ...target(typed, { tmux: true }), atPrompt: () => tr.atPrompt() })
    expect(insertPathOutcome('cli', PATH)).toBe('notPrompt')
    expect(typed).toEqual([])
    // click-ul explicit: tastat, împachetat (tmux), cu spaţiu, fără Enter
    expect(insertPathConfirmed('cli', PATH)).toBe('typed')
    expect(typed).toEqual([W(PATH + ' ')])
    expect(typed[0]).not.toMatch(/[\r\n]/)
    registerInsertTarget('cli', null)
  })

  it('M2: under tmux the sticky bracketed mode no longer authorises auto-typing (mc/vim/less, sudo text)', () => {
    const typed: string[] = []
    // pagină care a văzut attach-ul tmux: modul e „on", dar în panou rulează mc (fără prompt)
    registerInsertTarget('mc', target(typed, { tmux: true, bracketed: true }))
    expect(insertPathOutcome('mc', PATH)).toBe('notPrompt')
    expect(typeCommandOutcome('mc', 'sudo true')).toBe('notPrompt')
    expect(typed).toEqual([])
    // doar OSC 133 autorizează sub tmux — şi atunci mereu împachetat (tmux scoate marcajele la nevoie)
    registerInsertTarget('mc', target(typed, { tmux: true, prompt: true }))
    expect(typeIntoOutcome('mc', 'abc')).toBe('typed')
    expect(typed).toEqual([W('abc')])
    registerInsertTarget('mc', null)
  })

  it('M2: viaTmux that throws counts as tmux (fail closed)', () => {
    const typed: string[] = []
    registerInsertTarget('x', { ...target(typed, { bracketed: true }), viaTmux: () => { throw new Error('gone') } })
    expect(typeIntoOutcome('x', 'abc')).toBe('notPrompt')
    registerInsertTarget('x', null)
  })

  it('without tmux the mode is exact: bracketed → wrapped auto-insert; prompt only → plain', () => {
    const typed: string[] = []
    registerInsertTarget('pty', target(typed, { bracketed: true }))
    expect(typeIntoOutcome('pty', 'abc')).toBe('typed')
    registerInsertTarget('pty', target(typed, { prompt: true }))
    expect(typeIntoOutcome('pty', 'def')).toBe('typed')
    expect(typed).toEqual([W('abc'), 'def'])
    registerInsertTarget('pty', null)
  })

  it('L1: the confirmed click on a non-tmux backend (mode off) sends plain text — no ^[[200~ junk', () => {
    const typed: string[] = []
    registerInsertTarget('cat', target(typed))
    expect(insertPathOutcome('cat', PATH)).toBe('notPrompt')
    expect(insertPathConfirmed('cat', "/tmp/it's here.png")).toBe('typed')
    expect(typed).toEqual(["'/tmp/it'\\''s here.png' "])
    registerInsertTarget('cat', target(typed, { tmux: true }))
    expect(typeIntoConfirmed('cat', 'abc')).toBe('typed')
    expect(typed[1]).toBe(W('abc'))
    registerInsertTarget('cat', null)
  })

  it('refuses unsafe text: control characters, ESC (bracket breakout), newline, bidi, empty, oversize', () => {
    const typed: string[] = []
    registerInsertTarget('u', target(typed, { tmux: true }))
    for (const bad of ['a\r', 'a\nid', 'x\x1b[201~; id', 'a‮b', 'a b', 'a\x00b', 'a\x9bb', '', 'a'.repeat(32769)])
      expect(typeIntoConfirmed('u', bad)).toBe('unsafe')
    expect(typed).toEqual([])
    // a path: shellQuote strips control bytes first, so the only ESCs typed are the brackets
    expect(insertPathConfirmed('u', '/tmp/a\x1b[201~b\n')).toBe('typed')
    expect(typed).toEqual([W("'/tmp/a[201~b' ")])
    registerInsertTarget('u', null)
  })

  it('read-only / muted / closed / guardrail waiting (the target says no) → refused; a closed tab → noTarget', () => {
    registerInsertTarget('ro', target([], { ok: false }))
    expect(insertPathConfirmed('ro', PATH)).toBe('refused')
    registerInsertTarget('ro', null)
    expect(insertPathConfirmed('ro', PATH)).toBe('noTarget')
    expect(insertPathConfirmed(undefined, PATH)).toBe('noTarget')
  })

  it('L4: the offer is hidden in a view-only / muted session', () => {
    registerInsertTarget('v', target([], { canType: false }))
    expect(canTypeInto('v')).toBe(false)
    registerInsertTarget('v', target([]))
    expect(canTypeInto('v')).toBe(true)
    registerInsertTarget('v', null)
    expect(canTypeInto('v')).toBe(false)
  })

  it('L3: every outcome has its own message', () => {
    expect(notTypedReasonKey('unsafe')).toBe('transfers.whyUnsafe')
    expect(notTypedReasonKey('noTarget')).toBe('transfers.whyNoTarget')
    expect(notTypedReasonKey('refused')).toBe('transfers.whyRefused')
    expect(notTypedReasonKey('notPrompt')).toBe('transfers.whyNotPrompt')
  })

  it('never returns notPrompt from the confirmed path; the guarded one is unchanged for raw-mode programs', () => {
    const typed: string[] = []
    registerInsertTarget('mc2', target(typed))
    expect(typeIntoOutcome('mc2', 'abc')).toBe('notPrompt')
    expect(typed).toEqual([])
    expect(typeIntoConfirmed('mc2', 'abc')).not.toBe('notPrompt')
    registerInsertTarget('mc2', null)
  })
})

describe('M1: TAB inside a paste under tmux is not trusted as literal (guardrail fails closed)', () => {
  it('tmux-backed agent, SSH (tmux new -A) and an unknown host are untrusted; agent pty / telnet are not', () => {
    expect(pasteModeUntrusted({ backend: 'tmux', connection_type: 'agent' })).toBe(true)
    expect(pasteModeUntrusted({ backend: null, connection_type: 'ssh' })).toBe(true)
    expect(pasteModeUntrusted({ backend: null, connection_type: 'ssh-jump' })).toBe(true)
    expect(pasteModeUntrusted(null)).toBe(true)
    expect(pasteModeUntrusted({ backend: 'pty', connection_type: 'agent' })).toBe(false)
    expect(pasteModeUntrusted({ backend: null, connection_type: 'telnet' })).toBe(false)
  })
  it('`rm -rf /tm<TAB>…` pasted: literal only with a trusted mode', () => {
    const d = '\x1b[200~rm -rf /tm\tp/x\x1b[201~\r'
    expect(opaqueInput(d, trustedBracketed(false, true))).toBe(false)   // pty, shell asked: TAB is text
    expect(opaqueInput(d, trustedBracketed(true, true))).toBe(true)     // tmux: xterm says on, pane may not → can't check
    expect(opaqueInput(d, trustedBracketed(false, false))).toBe(true)
  })
})
