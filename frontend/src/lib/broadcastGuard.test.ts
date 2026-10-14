import { describe, expect, it } from 'vitest'
import type { CommandGuard } from './api'
import type { Terminal } from '@xterm/xterm'
import { CommandTracker } from './commands'
import { isBareEnter, judgePeers, PeerState, runDecision, splitLines, stripControls, submitsLine, unbracket } from './broadcastGuard'

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

  // review final 3.6.12 (M): un confirm NU mai câştigă peste unknown — „Rulează" ar fi trimis Enter
  // şi în panoul pe care nu-l vedem; confirmarea vine ataşată dialogului „nu pot verifica"
  it('confirm + panou pe pauză → unknown, cu regula arătată', () => {
    const v = judgePeers([peer({ live: false }), peer({ pending: 'rm -rf x' })], guard, false)
    expect(v).toMatchObject({ kind: 'unknown', hits: [{ cmd: 'rm -rf x' }] })
  })

  it('un block câştigă peste unknown (ştim sigur că e interzis)', () => {
    const g: CommandGuard = { enabled: true, rules: [{ pattern: 'mkfs', action: 'block' }] }
    expect(judgePeers([peer({ live: false }), peer({ pending: 'mkfs /dev/sda' })], g, false))
      .toMatchObject({ kind: 'rule', rule: { action: 'block' } })
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

// review final 3.6.12 (M): confirm în origine + altceva în alt panou. Logica veche: checkSubmit
// scurtcircuita pe confirm-ul local (dialog), iar „Rulează" trimitea Enter tuturor, fără re-verificare.
describe('broadcast: confirm în origine nu ascunde celelalte panouri', () => {
  const g: CommandGuard = { enabled: true, rules: [
    { pattern: 'reboot', action: 'confirm' }, { pattern: 'rm\\s+-rf', action: 'block' }, { pattern: 'shutdown', action: 'confirm' },
  ] }
  const origin = (o: Partial<PeerState> = {}) => peer({ label: 'web1', pending: 'sudo reboot', ...o })

  it('origine confirm + panou cu block → block (nu dialogul de confirmare)', () => {
    // judgePeers vechi întorcea PRIMA regulă (confirm-ul originii) → block-ul era ascuns
    const v = judgePeers([origin(), peer({ label: 'db1', pending: 'rm -rf /var/lib' })], g, true)
    expect(v).toMatchObject({ kind: 'rule', rule: { action: 'block' }, cmd: 'rm -rf /var/lib', hits: [{ panes: ['db1'] }] })
  })

  it('origine confirm + panou neactualizat (stale / fără ecou) → wait, apoi unknown cu regula arătată', () => {
    const ps = [origin(), peer({ label: 'db1', known: false })]
    expect(judgePeers(ps, g, false)).toMatchObject({ kind: 'wait' })
    const v = judgePeers(ps, g, true)
    expect(v).toMatchObject({ kind: 'unknown', hits: [{ cmd: 'sudo reboot', panes: ['web1'] }] })
    expect(judgePeers([origin(), peer({ label: 'db1', echoed: false })], g, true).kind).toBe('unknown')
  })

  it('două confirmări diferite → ambele listate; aceeaşi linie în 2 panouri → o intrare, 2 panouri', () => {
    const v = judgePeers([origin(), peer({ label: 'db1', pending: 'shutdown -h now' }), peer({ label: 'db2', pending: 'sudo reboot' })], g, true)
    expect(v.kind).toBe('rule')
    if (v.kind !== 'rule') return
    expect(v.hits.map((h) => [h.cmd, h.panes])).toEqual([['sudo reboot', ['web1', 'db2']], ['shutdown -h now', ['db1']]])
  })

  it('liniile următoare ale unui paste (extra) se verifică în fiecare panou', () => {
    const v = judgePeers([origin({ pending: null }), peer({ label: 'db1' })], g, true, (p) => p, ['rm -rf /'])
    expect(v).toMatchObject({ kind: 'rule', rule: { action: 'block' }, hits: [{ panes: ['web1', 'db1'] }] })
  })

  it('„Rulează" după ce linia unui panou s-a schimbat → dialog nou (escaladare), nu trimite', () => {
    const seen = judgePeers([origin(), peer({ label: 'db1', pending: 'ls' })], g, true)
    expect(seen.kind).toBe('rule')
    if (seen.kind !== 'rule') return
    // acelaşi set → trimite
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', pending: 'ls' })], g, true), seen.hits, false)).toBe('send')
    // db1 a rechemat între timp `shutdown` → alt set de confirmări → escaladare
    const now = judgePeers([origin(), peer({ label: 'db1', pending: 'shutdown' })], g, true)
    expect(runDecision(now, seen.hits, false)).toBe('escalate')
    // db1 a rechemat `rm -rf` → block → escaladare
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', pending: 'rm -rf ~' })], g, true), seen.hits, false)).toBe('escalate')
    // db1 a intrat pe pauză → unknown → escaladare (dialogul de regulă nu acceptă panouri neverificabile)
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', live: false })], g, true), seen.hits, false)).toBe('escalate')
    // linia originii a fost ştearsă → ok → trimite
    expect(runDecision(judgePeers([origin({ pending: null }), peer({ label: 'db1' })], g, true), seen.hits, false)).toBe('send')
  })

  it('„Rulează" pe dialogul „nu pot verifica": acelaşi unknown → trimite; o regulă apărută → escaladare', () => {
    const seen = judgePeers([origin(), peer({ label: 'db1', live: false })], g, true)
    expect(seen.kind).toBe('unknown')
    if (seen.kind !== 'unknown') return
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', live: false })], g, true), seen.hits, true)).toBe('send')
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', live: false, pending: 'shutdown' })], g, true), seen.hits, true)).toBe('escalate')
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', pending: 'rm -rf /' })], g, true), seen.hits, true)).toBe('escalate')
    // panoul a revenit, linie inofensivă: acelaşi set de confirmări (al originii) → trimite
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', pending: 'ls' })], g, true), seen.hits, true)).toBe('send')
  })

  it('fără broadcast (un singur panou, viu): confirm → dialogul regulii, ca înainte', () => {
    expect(judgePeers([origin()], g, true)).toMatchObject({ kind: 'rule', cmd: 'sudo reboot', rule: { action: 'confirm' } })
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

  // review final 3.6.12 (L): Alt+Enter se verifica drept „linie + ESC" — `rm -rf /\x1b` nu mai era
  // linia tastată (o regulă ancorată cu $ rata); acum ESC / C0 dispar din linia verificată
  it('Alt+Enter (\\x1b\\r) = Enter pe linia curentă: ESC / C0 scoase la verificare', () => {
    const lines = splitLines(unbracket('\x1b\r')).map(stripControls)
    expect(lines).toEqual(['', ''])
    expect('rm -rf /' + lines[0]).toBe('rm -rf /')
    expect(stripControls('ls\x1b[A\x1bb\x7f\x07')).toBe('ls')
    const anchored: CommandGuard = { enabled: true, rules: [{ pattern: '^reboot$', action: 'block' }] }
    expect(judgePeers([peer({ pending: 'reboot\x1b' })], anchored, true).kind).toBe('rule')
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
    tr.noteReplayedMark('A'); tr.noteReplayedMark('B')
    expect(tr.integrated).toBe(true)
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('unknown')
  })

  it('primul prompt LIVE după replay → linia se vede din nou (regula prinde)', () => {
    const { term, type } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.noteReplayedMark('B'); tr.reset()
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

// review final 3.6.12 (UX): guardrail-ul nu trebuie să ceară confirmare la nesfârşit
describe('CommandTracker: integrare doar cu B; replay oprit într-o comandă', () => {
  it('integrare doar cu A/C/D (fără B) → neintegrat: fără dialog permanent', () => {
    const { term } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.handle('A'); tr.handle('C'); tr.handle('D;0')
    tr.reset(); tr.noteReplayedMark('A'); tr.noteReplayedMark('D;0')
    // logica veche: orice marcaj = integrat → lineKnown false pentru totdeauna (fără B nu se reface)
    expect(tr.integrated).toBe(false)
    expect(tr.lineKnown()).toBe(true)
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('ok')
  })

  it('ultimul marcaj rejucat e C fără D (ssh / sudo -i / REPL) → comandă în curs, linia cunoscută', () => {
    const { term } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.reset()
    tr.noteReplayedMark('A'); tr.noteReplayedMark('B'); tr.noteReplayedMark('E;ssh db1'); tr.noteReplayedMark('C')
    // logica veche: stale → unknown la fiecare Enter difuzat, cât timp ţine sesiunea ssh
    expect(tr.lineKnown()).toBe(true)
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('ok')
    // comanda se termină LIVE: până la următorul B linia e din nou necunoscută (fail-closed)
    tr.handle('D;0')
    expect(tr.lineKnown()).toBe(false)
    tr.handle('A'); tr.handle('B')
    expect(tr.lineKnown()).toBe(true)
  })

  it('prompt inactiv după replay (ultimul marcaj B sau D) → tot necunoscut (fail-closed)', () => {
    for (const tail of [['B'], ['B', 'C', 'D;0'], ['B', 'C', 'D;0', 'A']]) {
      const { term } = fakeTerm()
      const tr = new CommandTracker(term)
      tr.reset()
      for (const m of tail) tr.noteReplayedMark(m)
      expect(tr.lineKnown()).toBe(false)
      expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('unknown')
    }
  })
})

describe('unbracket', () => {
  it('scoate marcajele bracketed paste doar pentru verificare', () => {
    expect(unbracket('\x1b[200~rm -rf /\r\x1b[201~')).toBe('rm -rf /\r')
    // un payload care îşi închide singur paste-ul: liniile de după se văd la verificare
    expect(splitLines(unbracket('\x1b[200~ls\x1b[201~\rrm -rf ~\r'))).toContain('rm -rf ~')
  })
})
