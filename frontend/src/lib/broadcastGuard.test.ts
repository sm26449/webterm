import { describe, expect, it } from 'vitest'
import type { CommandGuard } from './api'
import type { Terminal } from '@xterm/xterm'
import { CommandTracker } from './commands'
import { isBareEnter, judgePeers, PeerState, splitLines, submitsLine, unbracket } from './broadcastGuard'

// review independent 3.6.12 (M1): un Enter difuzat verifică linia din FIECARE panou-ţintă, iar un
// panou a cărui linie nu poate fi crezută (pauză / fără ecou încă) cere confirmare — fail-closed.
const guard: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'confirm' }] }
const peer = (o: Partial<PeerState> = {}): PeerState =>
  ({ inert: false, live: true, atPrompt: true, echoed: true, pending: null, known: true, ...o })

describe('judgePeers', () => {
  it('fără guardrail activ: nimic de verificat', () => {
    expect(judgePeers([peer({ live: false })], null, false).kind).toBe('ok')
    expect(judgePeers([peer({ live: false })], { enabled: false, rules: guard.rules }, false).kind).toBe('ok')
    expect(judgePeers([peer({ live: false })], { enabled: true, rules: [] }, false).kind).toBe('ok')
  })

  it('panouri vii, cu ecou, linii inofensive → ok', () => {
    expect(judgePeers([peer({ pending: 'ls -la' }), peer()], guard, false).kind).toBe('ok')
  })

  it('linia unui panou atinge regula → rule (cu comanda acelui panou)', () => {
    const v = judgePeers([peer({ pending: 'ls' }), peer({ pending: 'rm -rf /srv' })], guard, false)
    expect(v).toMatchObject({ kind: 'rule', cmd: 'rm -rf /srv' })
  })

  it('panou pe pauză (telefon, panou ascuns) → unknown, chiar dacă linia veche pare inofensivă', () => {
    expect(judgePeers([peer(), peer({ live: false, pending: null })], guard, false).kind).toBe('unknown')
  })

  it('tastele n-au ecou încă → wait; după răgaz → unknown', () => {
    const ps = [peer({ echoed: false, pending: 'ls' })]
    expect(judgePeers(ps, guard, false).kind).toBe('wait')
    expect(judgePeers(ps, guard, true).kind).toBe('unknown')
  })

  it('ecoul a sosit şi arată comanda rechemată (↑) → rule', () => {
    expect(judgePeers([peer({ echoed: true, pending: 'rm -rf ~' })], guard, false).kind).toBe('rule')
  })

  it('regula câştigă peste unknown (ştim sigur că e periculos)', () => {
    const v = judgePeers([peer({ live: false }), peer({ pending: 'rm -rf x' })], guard, false)
    expect(v.kind).toBe('rule')
  })

  it('panou inert (doar-vizualizare / socket închis) nu poate rula nimic → ignorat', () => {
    expect(judgePeers([peer({ inert: true, live: false, echoed: false })], guard, true).kind).toBe('ok')
  })

  it('fără shell integration (nu e „la prompt") nu se aşteaptă ecou — ca în panoul de origine', () => {
    expect(judgePeers([peer({ atPrompt: false, echoed: false })], guard, true).kind).toBe('ok')
  })

  it('lineOf: un snippet inserat se verifică lipit de linia existentă a fiecărui panou', () => {
    const v = judgePeers([peer({ pending: 'sudo rm' })], guard, false, (p) => (p ?? '') + ' -rf /')
    expect(v).toMatchObject({ kind: 'rule', cmd: 'sudo rm -rf /' })
  })
})

describe('linii / Enter', () => {
  it('CR singur e un terminator de linie, ca LF şi CRLF (paste „cmd\\r")', () => {
    expect(submitsLine('rm -rf /\r')).toBe(true)
    expect(submitsLine('a\nb')).toBe(true)
    expect(submitsLine('ls -la')).toBe(false)
    expect(splitLines('a\rb\r\nc\nd')).toEqual(['a', 'b', 'c', 'd'])
  })

  it('Enter „gol" din onData (IME mobil / keybar)', () => {
    expect(isBareEnter('\r')).toBe(true)
    expect(isBareEnter('\n')).toBe(true)
    expect(isBareEnter('\x1b\r')).toBe(false)
    expect(isBareEnter('ls\r')).toBe(false)
  })
})

// Terminal minimal pentru CommandTracker: un singur rând „$ " + ce s-a tastat, cursorul la final.
function fakeTerm(): { term: Terminal; type: (s: string) => void; alt: (on: boolean) => void } {
  let line = '$ '
  let bufType = 'normal'
  const buffer = {
    get type() { return bufType },
    baseY: 0, cursorY: 0,
    get cursorX() { return line.length },
    getLine: (row: number) => (row === 0
      ? { length: line.length, translateToString: (_t: boolean, from = 0, to = line.length) => line.slice(from, to) }
      : undefined),
  }
  const term = { buffer: { active: buffer }, registerMarker: () => ({ line: 0, dispose() {} }) } as unknown as Terminal
  return { term, type: (s) => { line += s }, alt: (on) => { bufType = on ? 'alternate' : 'normal' } }
}

// starea unui panou, construită EXACT ca în SessionView.paneState
const stateOf = (tr: CommandTracker, o: Partial<PeerState> = {}): PeerState => ({
  inert: false, live: true, echoed: true,
  atPrompt: tr.atPrompt(), pending: tr.pendingCommand(), known: tr.lineKnown(), ...o,
})

// re-review 3.6.12 (M1 rezidual): după un replay (ataşare / reconectare / reluarea unui panou de
// telefon) trackerul e resetat şi marcajele rejucate ignorate → atPrompt=false până la următorul
// prompt LIVE. Logica veche trata asta ca „fără shell integration" → ok, deci o comandă rechemată
// (↑) înainte de reconectare rula neverificată în panoul ascuns.
describe('linie necunoscută după replay (CommandTracker.lineKnown)', () => {
  it('integrat, apoi reset (replay), fără prompt live încă → wait, apoi unknown', () => {
    const { term, type } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.handle('A'); tr.handle('B')
    expect(tr.atPrompt()).toBe(true)
    tr.reset()                       // replay de istoric
    type('rm -rf /srv')              // linia rejucată (rechemată înainte de reconectare)
    expect(tr.atPrompt()).toBe(false)
    expect(tr.lineKnown()).toBe(false)
    const ps = [stateOf(tr)]
    // logica veche (fără `known`) zicea ok: atPrompt=false = „fără shell integration"
    expect(judgePeers([{ ...ps[0], known: true }], guard, true).kind).toBe('ok')
    expect(judgePeers(ps, guard, false).kind).toBe('wait')
    expect(judgePeers(ps, guard, true).kind).toBe('unknown')
  })

  it('montare nouă: doar marcaje REJUCATE (ignorate) → tot integrat, linia necunoscută', () => {
    const { term } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.reset()
    tr.noteReplayedMark()
    expect(tr.integrated).toBe(true)
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('unknown')
  })

  it('primul prompt LIVE după replay → linia se vede din nou (regula prinde)', () => {
    const { term, type } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.noteReplayedMark(); tr.reset()
    tr.handle('A'); tr.handle('B')
    expect(tr.stale).toBe(false)
    type('rm -rf /srv')
    expect(judgePeers([stateOf(tr)], guard, true)).toMatchObject({ kind: 'rule', cmd: 'rm -rf /srv' })
    expect(judgePeers([stateOf(tr)], { enabled: true, rules: [{ pattern: 'shutdown', action: 'block' }] }, true).kind).toBe('ok')
  })

  it('fără shell integration (niciun marcaj, nici rejucat) → ok, ca înainte', () => {
    const { term } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.reset()
    expect(tr.integrated).toBe(false)
    expect(tr.lineKnown()).toBe(true)
    expect(judgePeers([stateOf(tr, { echoed: false })], guard, true).kind).toBe('ok')
  })

  it('comandă în curs sau TUI (ecran alternativ) → Enter-ul merge la program: ok', () => {
    const { term, type, alt } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.handle('B'); type('sleep 100'); tr.handle('C')
    expect(tr.running).toBe(true)
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('ok')
    tr.handle('D;0')
    alt(true)
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('ok')
  })

  it('integrat, între Enter (C gol) şi următorul prompt → wait (nu ok)', () => {
    const { term } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.handle('A'); tr.handle('B'); tr.handle('C')   // Enter pe linie goală: fără comandă
    expect(tr.running).toBe(false)
    expect(judgePeers([stateOf(tr)], guard, false).kind).toBe('wait')
  })
})

describe('unbracket', () => {
  it('scoate marcajele bracketed paste doar pentru verificare', () => {
    expect(unbracket('\x1b[200~rm -rf /\r\x1b[201~')).toBe('rm -rf /\r')
    // un payload care îşi închide singur paste-ul: liniile de după se văd la verificare
    expect(splitLines(unbracket('\x1b[200~ls\x1b[201~\rrm -rf ~\r'))).toContain('rm -rf ~')
  })
})
