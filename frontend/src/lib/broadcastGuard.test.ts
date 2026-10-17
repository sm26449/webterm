import { describe, expect, it } from 'vitest'
import type { CommandGuard } from './api'
import type { Terminal } from '@xterm/xterm'
import { CommandTracker } from './commands'
import { ACCEPT_AND_HOLD, CTRL_O, SUBMIT_RE, acceptsLine, echoSettled, echoSettleMs, hitsKey, isBareEnter, isSubmitKey, judgeLocal, judgePeers, LocalState, mergeTyped, metaAccept, opaqueInput, PeerState, plainText, runDecision, splitLines, stripControls, submitsLine, unbracket } from './broadcastGuard'

// review independent 3.6.12 (M1): un Enter difuzat verifică linia din FIECARE panou-ţintă, iar un
// panou a cărui linie nu poate fi crezută (pauză / fără ecou încă) cere confirmare — fail-closed.
const guard: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'confirm' }] }
let nextId = 0
const peer = (o: Partial<PeerState> = {}): PeerState =>
  ({ inert: false, live: true, atPrompt: true, echoed: true, pending: null, known: true, id: o.label ?? `p${++nextId}`, ...o })

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
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', pending: 'ls' })], g, true), seen.hits, null)).toBe('send')
    // db1 a rechemat între timp `shutdown` → alt set de confirmări → escaladare
    const now = judgePeers([origin(), peer({ label: 'db1', pending: 'shutdown' })], g, true)
    expect(runDecision(now, seen.hits, null)).toBe('escalate')
    // db1 a rechemat `rm -rf` → block → escaladare
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', pending: 'rm -rf ~' })], g, true), seen.hits, null)).toBe('escalate')
    // db1 a intrat pe pauză → unknown → escaladare (dialogul de regulă nu acceptă panouri neverificabile)
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', live: false })], g, true), seen.hits, null)).toBe('escalate')
    // linia originii a fost ştearsă → ok → trimite
    expect(runDecision(judgePeers([origin({ pending: null }), peer({ label: 'db1' })], g, true), seen.hits, null)).toBe('send')
  })

  it('„Rulează" pe dialogul „nu pot verifica": acelaşi unknown → trimite; o regulă apărută → escaladare', () => {
    const seen = judgePeers([origin(), peer({ label: 'db1', live: false })], g, true)
    expect(seen.kind).toBe('unknown')
    if (seen.kind !== 'unknown') return
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', live: false })], g, true), seen.hits, seen.unreadable)).toBe('send')
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', live: false, pending: 'shutdown' })], g, true), seen.hits, seen.unreadable)).toBe('escalate')
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', pending: 'rm -rf /' })], g, true), seen.hits, seen.unreadable)).toBe('escalate')
    // panoul a revenit, linie inofensivă: acelaşi set de confirmări (al originii) → trimite
    expect(runDecision(judgePeers([origin(), peer({ label: 'db1', pending: 'ls' })], g, true), seen.hits, seen.unreadable)).toBe('send')
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
  inert: false, live: true, echoed: true, id: 'tr',
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

  // verificare 3.6.12 (F1): tail-ul rejucat omite octeţii ne-scrişi încă pe disc (~2,5 s), deci D/A/B-ul
  // unei comenzi tocmai terminate pot lipsi — „C la final" NU dovedeşte că rulează ceva. Logica din
  // e2de5c4 zicea „rulează" (ok) → o comandă rechemată la promptul real pleca neverificată.
  it('ultimul marcaj rejucat e C fără D → tot necunoscut (D/A/B pot lipsi din tail)', () => {
    const { term, type } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.reset()
    tr.noteReplayedMark('A'); tr.noteReplayedMark('B'); tr.noteReplayedMark('E;make'); tr.noteReplayedMark('C')
    type('rm -rf /srv')              // de fapt: promptul real, cu o comandă rechemată (D/A/B nerejucate)
    expect(tr.lineKnown()).toBe(false)
    expect(judgePeers([stateOf(tr)], guard, false).kind).toBe('wait')
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('unknown')
    // primul prompt LIVE: linia se vede din nou
    tr.handle('D;0'); tr.handle('A'); tr.handle('B')
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

// verificare 3.6.12 (F2, F3, F4, F5)
describe('verificare 3.6.12: dialog fără broadcast, id-uri, taste de editare, panouri neverificabile noi', () => {
  const g: CommandGuard = { enabled: true, rules: [{ pattern: 'reboot', action: 'confirm' }, { pattern: 'rm\\s+-rf', action: 'confirm' }] }

  it('F2: dialog deschis fără broadcast (fără re-verificare) → „Rulează" trimite doar local', () => {
    // logica veche: `!v` → sendAll, deci un broadcast pornit între timp trimitea Enter neverificat
    expect(runDecision(null, [], null)).toBe('local')
    expect(runDecision(null, [], [])).toBe('local')
  })

  it('F3: două panouri fără titlu pe acelaşi host → chei distincte (id), etichete dezambiguizate', () => {
    const a = peer({ id: 'aaaaaaaa-1111', label: 'web1', pending: 'sudo reboot' })
    const b = peer({ id: 'bbbbbbbb-2222', label: 'web1', pending: 'sudo reboot' })
    const c = peer({ id: 'cccccccc-3333', label: 'web1', pending: 'ls' })
    const both = judgePeers([a, b], g, true)
    expect(both.kind).toBe('rule')
    if (both.kind !== 'rule') return
    // logica veche deduplica după etichetă: un singur „web1"
    expect(both.hits[0].panes).toEqual(['aaaaaaaa-1111', 'bbbbbbbb-2222'])
    expect(both.hits[0].labels).toEqual(['web1 · aaaaaa', 'web1 · bbbbbb'])
    // dialogul a arătat linia în panoul a; acum e în panoul b (aceeaşi etichetă) → escaladare
    const seen = judgePeers([a, c], g, true)
    const now = judgePeers([{ ...a, pending: 'ls' }, { ...c, pending: 'sudo reboot' }], g, true)
    if (seen.kind !== 'rule' || now.kind !== 'rule') throw new Error('rule expected')
    expect(hitsKey(now.hits)).not.toBe(hitsKey(seen.hits))
    expect(runDecision(now, seen.hits, null)).toBe('escalate')
    // etichete unice rămân neschimbate
    expect(judgePeers([peer({ id: 'x', label: 'db1', pending: 'reboot' })], g, true)).toMatchObject({ hits: [{ labels: ['db1'] }] })
  })

  it('F4: TAB / VT / FF devin spaţiu în linia verificată (rm\\t-rf atinge rm\\s+-rf)', () => {
    // logica veche ştergea TAB-ul: `rm-rf` nu se potrivea
    expect(stripControls('rm\t-rf /')).toBe('rm -rf /')
    expect(judgePeers([peer({ pending: 'rm\t-rf /' })], g, true).kind).toBe('rule')
  })

  it('F4: un chunk cu taste de editare readline e opac; CR/LF, bracketed paste, Alt+Enter nu', () => {
    for (const d of ['\x15rm -rf /\r', 'ls\x7f\r', '\x10\r', '\x19\r', '\x16\x0d\r', '\x1b.\r', 'ls\x1b[D\r', '\x0crm\r', 'a\x9bb\r', '\x1b\x1b\r']) {
      expect(opaqueInput(d), JSON.stringify(d)).toBe(true)
    }
    for (const d of ['ls\r', '\x1b\r', 'ls\x1b\r', '\x1b[200~ls\r\x1b[201~', 'a\r\nb\n', 'café\r']) {
      expect(opaqueInput(d), JSON.stringify(d)).toBe(false)
    }
    // logica veche verifica `rm -rf /` scos din `\x15…` / linia fără DEL — alt text decât cel rulat
    const v = judgePeers([peer({ id: 'o', pending: 'ls' }), peer({ id: 'p' })], g, true, (p) => p, [], true)
    expect(v).toMatchObject({ kind: 'unknown', unreadable: ['o', 'p'] })
    // un block cunoscut câştigă totuşi
    const blk: CommandGuard = { enabled: true, rules: [{ pattern: 'mkfs', action: 'block' }] }
    expect(judgePeers([peer({ pending: 'mkfs /dev/sda' })], blk, true, (p) => p, [], true).kind).toBe('rule')
    // fără guardrail activ: nimic de verificat
    expect(judgePeers([peer()], null, true, (p) => p, [], true).kind).toBe('ok')
  })

  it('F5: „Rulează" pe „nu pot verifica" escaladează dacă a devenit neverificabil un panou NOU', () => {
    const seen = judgePeers([peer({ id: 'o' }), peer({ id: 'db1', live: false }), peer({ id: 'db2' })], g, true)
    expect(seen).toMatchObject({ kind: 'unknown', hits: [], unreadable: ['db1'] })
    if (seen.kind !== 'unknown') return
    // acelaşi panou neverificabil → trimite
    expect(runDecision(judgePeers([peer({ id: 'o' }), peer({ id: 'db1', live: false }), peer({ id: 'db2' })], g, true), seen.hits, seen.unreadable)).toBe('send')
    // db2 a intrat pe pauză (sau linia lui a devenit necunoscută) → escaladare; logica veche: send
    const now = judgePeers([peer({ id: 'o' }), peer({ id: 'db1', live: false }), peer({ id: 'db2', live: false })], g, true)
    expect(runDecision(now, seen.hits, seen.unreadable)).toBe('escalate')
    const now2 = judgePeers([peer({ id: 'o' }), peer({ id: 'db1', live: false }), peer({ id: 'db2', known: false })], g, true)
    expect(runDecision(now2, seen.hits, seen.unreadable)).toBe('escalate')
    // db1 a revenit (mai puţine panouri neverificabile) → ok
    expect(runDecision(judgePeers([peer({ id: 'o' }), peer({ id: 'db1' }), peer({ id: 'db2' })], g, true), seen.hits, seen.unreadable)).toBe('send')
  })
})

describe('unbracket', () => {
  it('scoate marcajele bracketed paste doar pentru verificare', () => {
    expect(unbracket('\x1b[200~rm -rf /\r\x1b[201~')).toBe('rm -rf /\r')
    // un payload care îşi închide singur paste-ul: liniile de după se văd la verificare
    expect(splitLines(unbracket('\x1b[200~ls\x1b[201~\rrm -rf ~\r'))).toContain('rm -rf ~')
  })
})

// 3.6.13 (rezidual 3.6.12): TAB într-un chunk care trimite o linie = completare readline → opac;
// literal doar într-un bracketed paste, şi doar dacă shell-ul a cerut bracketed paste
describe('3.6.13: TAB în chunk-uri care trimit o linie', () => {
  it('TAB în afara unui bracketed paste → opac (completarea schimbă linia)', () => {
    // logica veche: TAB permis → `rm -rf /tm⇥⏎` se verifica drept `rm -rf /tm `, rula `rm -rf /tmp/`
    for (const d of ['a\tb\r', 'rm -rf /tm\t\r', '\t\r']) {
      expect(opaqueInput(d), JSON.stringify(d)).toBe(true)
      expect(opaqueInput(d, true), JSON.stringify(d)).toBe(true)
    }
  })
  it('TAB într-un bracketed paste: literal doar cu bracketed paste cerut de shell', () => {
    const paste = '\x1b[200~printf "a\tb"\r\x1b[201~'
    expect(opaqueInput(paste, true)).toBe(false)
    expect(opaqueInput(paste, false)).toBe(true)          // fără DECSET 2004: marcajele pot fi chiar din text
    expect(opaqueInput('\x1b[200~a\tb\r', true)).toBe(false)   // paste neînchis în chunk: până la capăt
  })
  it('un payload care îşi închide singur paste-ul: TAB-ul de după e iar completare', () => {
    expect(opaqueInput('\x1b[200~ls\x1b[201~rm -rf /tm\t\r', true)).toBe(true)
    expect(opaqueInput('\x1b[200~a\tb\x1b[201~\x1b[200~c\td\r\x1b[201~', true)).toBe(false)
    // alte taste de editare rămân opace şi într-un paste (ca în 3.6.12)
    expect(opaqueInput('\x1b[200~ls\x7f\r\x1b[201~', true)).toBe(true)
  })
})

// 3.6.13 (rezidual 3.6.12): Enter într-un singur panou aştepta 0 ms — Ctrl+P + Enter rapid trimitea o
// linie pe care trackerul n-o văzuse (ecoul lui Ctrl+P încă pe drum)
describe('3.6.13: Enter fără broadcast aşteaptă ecoul (judgeLocal)', () => {
  const g: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'confirm' }, { pattern: '^reboot$', action: 'block' }] }
  const st = (o: Partial<LocalState> = {}): LocalState => ({ atPrompt: true, echoed: true, pending: null, unechoed: [], ...o })

  it('fără guardrail activ / cu ecou: ca înainte', () => {
    expect(judgeLocal(st({ echoed: false, unechoed: [null] }), null, true).kind).toBe('ok')
    expect(judgeLocal(st({ pending: 'ls' }), g, false).kind).toBe('ok')
    expect(judgeLocal(st({ pending: 'rm -rf /srv' }), g, false)).toMatchObject({ kind: 'rule', cmd: 'rm -rf /srv' })
  })
  it('Ctrl+P fără ecou → wait, apoi „nu pot verifica" (logica veche: ok pe linia veche)', () => {
    const s = st({ pending: 'ls', echoed: false, unechoed: [null] })
    expect(judgeLocal(s, g, false).kind).toBe('wait')
    expect(judgeLocal(s, g, true).kind).toBe('unknown')
  })
  it('doar text simplu fără ecou (legătură lentă) → linia + textul, fără dialog dacă e inofensivă', () => {
    expect(judgeLocal(st({ pending: 'l', echoed: false, unechoed: ['s'] }), g, true).kind).toBe('ok')
    expect(judgeLocal(st({ pending: 'rm -r', echoed: false, unechoed: ['f /srv'] }), g, true))
      .toMatchObject({ kind: 'rule', cmd: 'rm -rf /srv' })
    // ecou parţial: „rebo" pe ecran, „oot" trimis → reboot (block, ancorat)
    expect(judgeLocal(st({ pending: 'rebo', echoed: false, unechoed: ['oot'] }), g, true))
      .toMatchObject({ kind: 'rule', cmd: 'reboot', rule: { action: 'block' } })
  })
  it('un block cunoscut câştigă şi peste „nu pot verifica"', () => {
    expect(judgeLocal(st({ pending: 'reboot', echoed: false, unechoed: [null] }), g, true).kind).toBe('rule')
  })
  it('nu la prompt (comandă în curs / fără integrare) → nu aşteaptă', () => {
    expect(judgeLocal(st({ atPrompt: false, echoed: false, unechoed: [null] }), g, false).kind).toBe('ok')
  })
  it('fără nicio trimitere urmărită dar fără ecou → fail-closed', () => {
    expect(judgeLocal(st({ pending: 'ls', echoed: false, unechoed: [] }), g, true).kind).toBe('unknown')
  })
  it('chunk (lineOf / extra) cu ecou lipsă: prima linie lipită de linia de după ecou', () => {
    const v = judgeLocal(st({ pending: 'rm', echoed: false, unechoed: [' -'] }), g, true, (p) => (p ?? '') + 'rf /x', ['ls'])
    expect(v).toMatchObject({ kind: 'rule', cmd: 'rm -rf /x' })
  })
  it('mergeTyped / plainText', () => {
    expect(mergeTyped('rebo', 'oot')).toBe('reboot')
    expect(mergeTyped('ls', ' -la')).toBe('ls -la')
    expect(mergeTyped('', 'x')).toBe('x')
    expect(plainText('ls -la')).toBe(true)
    expect(plainText('\x10')).toBe(false)
    expect(plainText('\t')).toBe(false)
    expect(plainText('\x1b[A')).toBe(false)
  })
})

// 3.6.13 (rezidual 3.6.12): ecoul strâns + plasa de timp
describe('3.6.13: ecou strâns (echoSettled)', () => {
  it('ecou strâns = gata; altfel plasa de timp (≥ 1 s, ≥ 4 × RTT)', () => {
    expect(echoSettleMs(null)).toBe(1000)
    expect(echoSettleMs(600)).toBe(2400)
    expect(echoSettleMs(Number.NaN)).toBe(1000)
    const base = { strict: false, coarse: true, rtt: 50, requireOutput: true }
    expect(echoSettled({ ...base, strict: true, sinceSend: 0 })).toBe(true)
    expect(echoSettled({ ...base, sinceSend: 100 })).toBe(false)   // un ceas / repaint n-a schimbat linia
    expect(echoSettled({ ...base, sinceSend: 1500 })).toBe(true)   // TAB fără completare (doar BEL)
  })
  it('broadcast: host fără NICIUN output rămâne fără ecou (ca regula grosieră din 3.6.12)', () => {
    expect(echoSettled({ strict: false, coarse: false, rtt: null, requireOutput: true, sinceSend: 60_000 })).toBe(false)
    // un singur panou: 3.6.12 nu aştepta deloc; o tastă fără output nu cere dialog la nesfârşit
    expect(echoSettled({ strict: false, coarse: false, rtt: null, requireOutput: false, sinceSend: 1500 })).toBe(true)
    expect(echoSettled({ strict: false, coarse: false, rtt: null, requireOutput: false, sinceSend: 100 })).toBe(false)
  })
})

// 3.6.13 (rezidual 3.6.12): starea OSC 133 a hub-ului după replay (mesajul `osc133`)
describe('3.6.13: CommandTracker.applyHubState', () => {
  it('ultimul marcaj LIVE = C (ssh / sudo -i / REPL pornit înainte de replay) → rulează: Enter-ul merge la program', () => {
    const { term, type } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.reset()
    tr.noteReplayedMark('A'); tr.noteReplayedMark('B'); tr.noteReplayedMark('C')
    type('root@db:~# ')
    // 3.6.12: necunoscut → dialog la fiecare Enter difuzat
    expect(tr.lineKnown()).toBe(false)
    expect(tr.applyHubState({ integrated: true, last: 'C', synced: false })).toBe(true)
    expect(tr.lineKnown()).toBe(true)
    expect(tr.atPrompt()).toBe(false)
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('ok')
    // D live: comanda pornită înainte de replay s-a terminat → din nou neştiut până la B
    tr.handle('D;0')
    expect(tr.lineKnown()).toBe(false)
    tr.handle('A'); tr.handle('B')
    expect(tr.lineKnown()).toBe(true)
  })

  it('B + synced + ultimul marcaj rejucat B → linia de pe ecran e cunoscută (regula prinde)', () => {
    const { term, type } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.reset()
    tr.noteReplayedMark('A'); tr.noteReplayedMark('B')
    type('rm -rf /srv')              // comandă rechemată înainte de reconectare, în replay
    expect(tr.applyHubState({ integrated: true, last: 'B', synced: true })).toBe(true)
    expect(tr.stale).toBe(false)
    expect(judgePeers([stateOf(tr)], guard, true)).toMatchObject({ kind: 'rule', cmd: 'rm -rf /srv' })
  })

  it('orice nepotrivire → rămâne necunoscută (fail-closed)', () => {
    const cases: [string[], unknown][] = [
      [['A', 'B'], { integrated: true, last: 'B', synced: false }],      // gaura de checkpoint
      [['A', 'B', 'C'], { integrated: true, last: 'B', synced: true }],  // replay-ul a văzut alt ultim marcaj
      [['A'], { integrated: true, last: 'B', synced: true }],            // B-ul nu e în replay
      [['A', 'B'], { integrated: true, last: 'A', synced: true }],
      [['A', 'B'], { integrated: true, last: 'D', synced: true }],
      [['A', 'B'], { integrated: true, last: null, synced: true }],
      [['A', 'B'], { integrated: true, last: 'B', synced: 'yes' }],       // tipuri stricte
      [['A', 'B'], null],
      [['A', 'B'], 'B'],
    ]
    for (const [marks, st] of cases) {
      const { term, type } = fakeTerm()
      const tr = new CommandTracker(term)
      tr.reset()
      for (const m of marks) tr.noteReplayedMark(m)
      type('rm -rf /srv')
      tr.applyHubState(st)
      expect(tr.lineKnown(), JSON.stringify([marks, st])).toBe(false)
      expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('unknown')
    }
  })

  // review 3.6.13 (L3): read_tail scoate comutările de ecran din replay, deci în browser un B rejucat
  // apare mereu pe ecranul principal — hub-ul e cel care urmăreşte ecranul alternativ şi trimite
  // last=null pentru un marcaj de acolo (tests/split_views_test.py). Aici: last=null → necunoscut.
  it('B de pe ecranul alternativ (hub: last=null) → necunoscut, deşi replay-ul arată un B', () => {
    const { term, type } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.reset()
    tr.noteReplayedMark('A'); tr.noteReplayedMark('B')
    type('rm -rf /srv')
    expect(tr.applyHubState({ integrated: true, last: null, synced: true })).toBe(false)
    expect(tr.lineKnown()).toBe(false)
  })

  it('nu suprascrie o stare LIVE: aplicată doar imediat după replay', () => {
    const { term } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.reset()
    tr.handle('A'); tr.handle('B')   // un prompt live a venit deja
    expect(tr.applyHubState({ integrated: true, last: 'C', synced: false })).toBe(false)
    expect(tr.atPrompt()).toBe(true)
  })

  it('integrated de la hub (mesajul osc133) fără niciun marcaj în replay → linia necunoscută, nu „fără integrare"', () => {
    const { term, type } = fakeTerm()
    const tr = new CommandTracker(term)
    tr.reset()
    type('rm -rf /srv')
    // 3.6.12: fără marcaj în fereastra replay-ului = „fără shell integration" → ok, neverificat
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('ok')
    tr.applyHubState({ integrated: true, last: null, synced: false })   // mesajul `osc133`, după replay
    expect(judgePeers([stateOf(tr)], guard, true).kind).toBe('unknown')
    // `integrated: false` de la hub nu şterge ce am văzut noi
    tr.applyHubState({ integrated: false, last: null, synced: false })
    expect(tr.integrated).toBe(true)
  })
})

// e2e 3.6.13: o linie tastată care trece pe rândul următor (wrap) se citea cu un spaţiu în plus
describe('CommandTracker: linie înfăşurată pe mai multe rânduri', () => {
  function wrapTerm(rows: { text: string; wrapped: boolean }[]): Terminal {
    const last = rows.length - 1
    const buffer = {
      type: 'normal', baseY: 0, cursorY: last,
      get cursorX() { return rows[last].text.length },
      getLine: (r: number) => (rows[r]
        ? { length: rows[r].text.length, isWrapped: rows[r].wrapped,
            translateToString: (_t: boolean, from = 0, to = rows[r].text.length) => rows[r].text.slice(from, to) }
        : undefined),
    }
    return { buffer: { active: buffer }, registerMarker: () => ({ line: 0, dispose() {} }) } as unknown as Terminal
  }
  it('rând continuat prin wrap → fără spaţiu la graniţă (regula vede „rm -rf /tmp")', () => {
    const rows = [{ text: '', wrapped: false }, { text: '', wrapped: true }]
    const term = wrapTerm(rows)
    const tr = new CommandTracker(term)
    // B la începutul rândului 0 (cursorul acolo), apoi textul curge pe două rânduri
    ;(term.buffer.active as unknown as { cursorY: number }).cursorY = 0
    tr.handle('B')
    ;(term.buffer.active as unknown as { cursorY: number }).cursorY = 1
    rows[0].text = 'echo x; rm -rf /tm'
    rows[1].text = 'p'
    expect(tr.pendingCommand()).toBe('echo x; rm -rf /tmp')
    const g: CommandGuard = { enabled: true, rules: [{ pattern: 'rm -rf /tmp$', action: 'block' }] }
    expect(judgePeers([stateOf(tr)], g, true).kind).toBe('rule')
  })
  it('rând nou adevărat (fără wrap) → tot despărţit printr-un spaţiu, ca înainte', () => {
    const rows = [{ text: '', wrapped: false }, { text: '', wrapped: false }]
    const term = wrapTerm(rows)
    const tr = new CommandTracker(term)
    ;(term.buffer.active as unknown as { cursorY: number }).cursorY = 0
    tr.handle('B')
    ;(term.buffer.active as unknown as { cursorY: number }).cursorY = 1
    rows[0].text = 'echo a'
    rows[1].text = 'b'
    expect(tr.pendingCommand()).toBe('echo a b')
  })
})

// verificarea lui c9321d9: textul de SUB linia cursorului (pendingBelow) doar confirmă, niciodată block
describe('judgePeers / judgeLocal: potrivire doar sub cursor → confirmare `below`', () => {
  const blk: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf\\s+/srv', action: 'block' }] }
  it('broadcast: block doar în textul de dedesubt → rule confirm, hit marcat below', () => {
    const v = judgePeers([peer({ pending: 'ls', pendingBelow: ['ls DROP rm -rf /srv/data'] }), peer({ pending: 'ls' })], blk, true)
    expect(v.kind).toBe('rule')
    if (v.kind !== 'rule') return
    expect(v.rule.action).toBe('confirm')
    expect(v.hits).toHaveLength(1)
    expect(v.hits[0].below).toBe(true)
  })
  it('broadcast: block într-o citire normală a altui panou câştigă (block)', () => {
    const v = judgePeers([peer({ pending: 'ls', pendingBelow: ['ls rm -rf /srv/x'] }), peer({ pending: 'rm -rf /srv/y' })], blk, true)
    expect(v.kind === 'rule' && v.rule.action).toBe('block')
  })
  it('broadcast: aceeaşi regulă atinsă şi în citirea normală a panoului → fără hit below în plus', () => {
    const v = judgePeers([peer({ id: 'a', pending: 'ls', pendingAlts: ['ls rm -rf /srv/x'], pendingBelow: ['ls rm -rf /srv/x y'] })], blk, true)
    expect(v.kind === 'rule' && v.rule.action).toBe('block')
    expect(v.kind === 'rule' && v.hits.every((h) => !h.below)).toBe(true)
  })
  it('un singur panou: block doar dedesubt → confirmare below; block în linie → block', () => {
    const base: LocalState = { atPrompt: true, echoed: true, pending: 'ls', unechoed: [] }
    const v = judgeLocal({ ...base, pendingBelow: ['ls rm -rf /srv/data'] }, blk, true)
    expect(v).toMatchObject({ kind: 'rule', below: true, rule: { action: 'confirm' } })
    const v2 = judgeLocal({ ...base, pending: 'rm -rf /srv/a', pendingBelow: ['rm -rf /srv/a b'] }, blk, true)
    expect(v2).toMatchObject({ kind: 'rule', rule: { action: 'block' } })
    expect(v2.kind === 'rule' && v2.below).toBeFalsy()
  })
})

// audit 2026-10-17 (SV-01): Ctrl+O (`\x0f`) EXECUTĂ linia în bash (operate-and-get-next) şi zsh
// (accept-line-and-down-history), dar userInput verifica doar CR/LF — pleca direct, local şi în
// broadcast („↑ + comandă nevăzută", scenariul închis pentru Enter în 3.6.13, rămânea deschis).
describe('SV-01: Ctrl+O (\\x0f) e un Enter cu altă haină', () => {
  it('tasta singură e o tastă de trimitere (onData / keybar / coada de taste reţinute), ca un Enter gol', () => {
    expect(CTRL_O).toBe('\x0f')
    expect(isSubmitKey('\x0f')).toBe(true)
    expect(isSubmitKey('\r')).toBe(true)
    expect(isSubmitKey('\n')).toBe(true)
    expect(isSubmitKey('\r\n')).toBe(true)
    // nu „gol": un chunk cu text / ESC înainte trece prin submitChunk (fiecare linie verificată)
    expect(isSubmitKey('ls\x0f')).toBe(false)
    expect(isSubmitKey('\x1b\x0f')).toBe(false)
    expect(isSubmitKey('\x0f\x0f')).toBe(false)
    // isBareEnter rămâne strict Enter (căile care îl mai folosesc nu se lărgesc pe tăcute)
    expect(isBareEnter('\x0f')).toBe(false)
  })

  it('un chunk de paste care conţine \\x0f TRIMITE o linie: se judecă pe linii, ca la CR/LF', () => {
    expect(submitsLine('rm -rf /\x0f')).toBe(true)
    expect(submitsLine('\x0f')).toBe(true)
    expect(submitsLine('ls -la')).toBe(false)
    expect(splitLines('a\x0fb\rc\nd')).toEqual(['a', 'b', 'c', 'd'])
    // linia verificată e cea pe care o execută shell-ul: textul de dinaintea lui \x0f, fără C0
    const lines = splitLines(unbracket('rm -rf /\x0f')).map(stripControls)
    expect(lines).toEqual(['rm -rf /', ''])
    expect(stripControls('rm\x0f')).toBe('rm')
    // fail-closed („only add readings"): un \x0f în mijlocul unui chunk rămâne tastă de editare
    // (shell-ul aduce şi următoarea linie din istoric) → „nu pot verifica", nu trecere liberă
    expect(opaqueInput('ls\x0f')).toBe(true)
    expect(opaqueInput('ls\x0f', true)).toBe(true)
  })

  // re-review SV-01: zsh (keymap emacs) leagă `ESC a` / `ESC A` (Alt+A / Alt+Shift+A în xterm) la
  // `accept-and-hold` — EXECUTĂ linia (şi o păstrează în buffer). Chunk-ul nu era nici plainText,
  // nici tastă de trimitere, nici submitsLine → pleca direct, local şi în broadcast.
  it('Alt+A (`ESC a` / `ESC A`, zsh accept-and-hold) e aceeaşi tastă de trimitere, pe toate căile', () => {
    expect(ACCEPT_AND_HOLD).toEqual(['\x1ba', '\x1bA'])
    expect(isSubmitKey('\x1ba')).toBe(true)
    expect(isSubmitKey('\x1bA')).toBe(true)
    expect(isBareEnter('\x1ba')).toBe(false)
    // săgeţile (CSI / SS3), Alt+altă literă, ESC singur, litera singură NU trimit linia
    for (const k of ['\x1b[A', '\x1bOA', '\x1b[a', '\x1bb', '\x1b', 'a', 'A', 'ls\x1ba', '\x1ba\x1ba']) {
      expect(isSubmitKey(k), JSON.stringify(k)).toBe(false)
    }
    // chunk (paste / IME / inserare): judecat pe linii, ca la CR/LF/\x0f
    expect(submitsLine('rm -rf /\x1ba')).toBe(true)
    expect(submitsLine('rm -rf /\x1bA')).toBe(true)
    expect(SUBMIT_RE.test('\x1bA')).toBe(true)
    for (const k of ['\x1b[A', '\x1bOA', '\x1b[200~ls -la\x1b[201~', '\x1b[1;5A', 'ls -la']) {
      expect(submitsLine(k), JSON.stringify(k)).toBe(false)
    }
    expect(splitLines('a\x1bAb\x1bac\x0fd\re')).toEqual(['a', 'b', 'c', 'd', 'e'])
    expect(splitLines(unbracket('rm -rf /\x1ba')).map(stripControls)).toEqual(['rm -rf /', ''])
    // fail-closed: un ESC a în mijlocul unui chunk rămâne „nu pot verifica", nu trecere liberă
    expect(opaqueInput('ls\x1ba')).toBe(true)
    expect(opaqueInput('ls\x1ba', true)).toBe(true)
  })

  // re-review SV-01 (MED): zsh asamblează `ESC a` tastă cu tastă — Escape (chunk `\x1b`, trimis ca
  // atare) şi apoi `a` (chunk de text, trimis ca atare) e aceeaşi legătură, fără timeout. Şi de pe
  // keybar-ul mobil (are Esc). userInput nu ţinea minte chunk-ul anterior → nicio verificare.
  it('Escape apoi `a` / `A` (două chunk-uri) e tot accept-and-hold: tastă de trimitere DOAR după un ESC singur', () => {
    expect(metaAccept('\x1b', 'a')).toBe(true)
    expect(metaAccept('\x1b', 'A')).toBe(true)
    expect(isSubmitKey('a', '\x1b')).toBe(true)
    expect(isSubmitKey('A', '\x1b')).toBe(true)
    // fără ESC înainte (altă tastă, nimic, un raport = null) litera e doar text
    expect(isSubmitKey('a')).toBe(false)
    expect(isSubmitKey('a', null)).toBe(false)
    expect(isSubmitKey('a', 'x')).toBe(false)
    expect(isSubmitKey('a', '\r')).toBe(false)
    // prefixul e un chunk care se TERMINĂ cu Escape singur (`ls⎋` lipit lasă acelaşi prefix; `ESC ESC` primeşte
    // o citire în plus — doar adaugă citiri); după o săgeată sau `Alt+Enter` shell-ul nu mai e în prefix meta
    for (const prev of ['ls\x1b', '\x1b\x1b', 'rm -rf /\x1b']) expect(isSubmitKey('a', prev), JSON.stringify(prev)).toBe(true)
    for (const prev of ['\x1b[A', '\x1bOA', '\x1b\r', '\x1b[200~', '\x1bx', '']) {
      expect(isSubmitKey('a', prev), JSON.stringify(prev)).toBe(false)
    }
    // după ESC, doar `a` / `A` trimit linia: `b` (backward-word), `ab`, un Enter cu ESC e deja isBareEnter
    for (const d of ['b', 'ab', 'aa', '', ' ', '\x1ba']) expect(metaAccept('\x1b', d), JSON.stringify(d)).toBe(false)
    // Enter / Ctrl+O / ESC a singure rămân taste de trimitere indiferent de ce a fost înainte
    for (const prev of [null, '\x1b', 'x']) {
      for (const d of ['\r', '\n', '\r\n', CTRL_O, ...ACCEPT_AND_HOLD]) expect(isSubmitKey(d, prev)).toBe(true)
    }
  })

  // re-review SV-01 (LOW): noteSubmitSent (sare contiguitatea rândurilor până la promptul următor, PS2)
  // DOAR pentru accept-line-ul adevărat al shell-ului — nu pentru `ESC a` (în bash nu face nimic şi ar
  // absorbi rânduri străine în linia judecată)
  it('acceptsLine: CR / LF / Ctrl+O da, `ESC a` şi `a` nu', () => {
    for (const d of ['\r', '\n', '\r\n', '\x0f', 'ls\n', 'rm -rf /\x0f']) expect(acceptsLine(d), JSON.stringify(d)).toBe(true)
    for (const d of ['\x1ba', '\x1bA', 'a', '\x1b', 'ls -la', 'rm -rf /\x1ba']) expect(acceptsLine(d), JSON.stringify(d)).toBe(false)
    // submitsLine rămâne mai larg: un chunk cu ESC a se judecă pe linii
    expect(submitsLine('rm -rf /\x1ba')).toBe(true)
  })
})
