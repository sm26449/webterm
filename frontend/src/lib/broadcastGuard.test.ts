import { describe, expect, it } from 'vitest'
import type { CommandGuard } from './api'
import { isBareEnter, judgePeers, PeerState, splitLines, submitsLine } from './broadcastGuard'

// review independent 3.6.12 (M1): un Enter difuzat verifică linia din FIECARE panou-ţintă, iar un
// panou a cărui linie nu poate fi crezută (pauză / fără ecou încă) cere confirmare — fail-closed.
const guard: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'confirm' }] }
const peer = (o: Partial<PeerState> = {}): PeerState =>
  ({ inert: false, live: true, atPrompt: true, echoed: true, pending: null, ...o })

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
