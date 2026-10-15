import { describe, expect, it } from 'vitest'
import type { CommandGuard } from './api'
import { EchoTracker, isTerminalReport, LineKey, ECHO_PENDING_MAX } from './echo'
import { echoSettleMs, judgeLocal, localRunDecision, plainText } from './broadcastGuard'

// Un „shell" minimal: linia tastată + cursorul la capăt, cu istoric pentru ↑.
function shell(history: string[]) {
  let line = ''
  let hist = history.length
  const key = (): LineKey => ({ k: `normal\u00000\u0000${2 + line.length}\u0000${line}`, line })
  // ce ar face readline cu o tastă, când îi ajunge ecoul
  const apply = (d: string) => {
    if (d === '\x1b[A') { hist = Math.max(0, hist - 1); line = history[hist] ?? line }
    else line += d
  }
  return { key, apply, get line() { return line } }
}

// un panou: trimite (EchoTracker.sent + instantaneul de referinţă), iar ecoul fiecărei taste ajunge
// mai târziu, în chunk-uri alese de test
function pane(history: string[] = []) {
  const sh = shell(history)
  const echo = new EchoTracker()
  const inFlight: string[] = []
  let t = 0
  const send = (d: string) => {
    const { seq, needBase } = echo.sent(plainText(d) ? d : null, t)
    if (needBase) echo.setBase(seq, sh.key())   // write('') gol: nimic nu sosise încă
    inFlight.push(d)
  }
  /** sosesc ecourile primelor `n` taste din zbor, într-un singur chunk de output */
  const arrive = (n: number) => {
    const tag = echo.inputSeq
    for (const d of inFlight.splice(0, n)) sh.apply(d)
    echo.output(tag, sh.key)
  }
  const local = () => ({ atPrompt: true, echoed: echo.echoed(false, t, null), pending: sh.line || null, unechoed: echo.unechoed() })
  return { sh, echo, send, arrive, local, tick: (ms: number) => { t += ms } }
}

const g: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'block' }] }

describe('3.6.13 (review M1): ecoul unei taste vechi nu confirmă tasta nouă', () => {
  it('↑↑⏎ rapid: ecoul primului ↑ NU confirmă al doilea; linia rulată nu e cea citită', () => {
    const p = pane(['rm -rf /srv', 'ls'])
    p.send('\x1b[A'); p.send('\x1b[A')
    p.arrive(1)                      // primul ↑ → „ls" pe ecran
    expect(p.sh.line).toBe('ls')
    // logica veche: instantaneu doar pentru ultima trimitere → „ls" ≠ linia goală → echoed, ok pe „ls"
    expect(p.echo.echoedSeq).toBe(1)
    expect(p.echo.echoed(false, 0, null)).toBe(false)
    expect(judgeLocal(p.local(), g, false).kind).toBe('wait')
    expect(judgeLocal(p.local(), g, true).kind).toBe('unknown')
    p.arrive(1)                      // al doilea ↑ → rm -rf /srv
    expect(p.echo.echoed(false, 0, null)).toBe(true)
    expect(judgeLocal(p.local(), g, true)).toMatchObject({ kind: 'rule', cmd: 'rm -rf /srv' })
  })

  it('două ecouri non-text în acelaşi chunk: al doilea rămâne fără ecou (fail-closed), nu invers', () => {
    const p = pane(['rm -rf /srv', 'ls'])
    p.send('\x1b[A'); p.send('\x1b[A')
    p.arrive(2)
    expect(p.echo.echoedSeq).toBe(1)
    expect(p.echo.echoed(false, 0, null)).toBe(false)
  })

  it('tastare rapidă de text simplu: un chunk cu mai multe ecouri le confirmă pe toate', () => {
    const p = pane()
    for (const c of 'ls -la') p.send(c)
    p.arrive(6)
    expect(p.echo.echoed(true, 0, null)).toBe(true)
    expect(p.echo.unechoed()).toEqual([])
  })

  it('text simplu sosit parţial: doar cât arată linia; restul rămâne, ca text', () => {
    const p = pane()
    for (const c of 'reboot') p.send(c)
    p.arrive(4)
    expect(p.sh.line).toBe('rebo')
    expect(p.echo.unechoed()).toEqual(['o', 't'])
  })

  it('output care nu schimbă linia (ceas, repaint) nu e ecou; strict doar după schimbare', () => {
    const p = pane()
    p.send('x')
    p.echo.output(p.echo.inputSeq, p.sh.key)     // un repaint: linia identică
    expect(p.echo.echoedSeq).toBe(0)
    expect(p.echo.coarseSeq).toBe(1)
    p.arrive(1)
    expect(p.echo.echoedSeq).toBe(1)
  })

  it('fără linie citibilă (fără shell integration): regula grosieră din 3.6.12', () => {
    const echo = new EchoTracker()
    const { seq } = echo.sent(null, 0)
    echo.setBase(seq, null)
    echo.output(seq, () => null)
    expect(echo.echoed(true, 0, null)).toBe(true)
  })

  it('replay complet → totul confirmat; rafală fără ecou peste plafon → niciodată „confirmată" de o schimbare', () => {
    const p = pane()
    for (let i = 0; i < ECHO_PENDING_MAX + 1; i++) p.send('\x10')
    expect(p.echo.unechoed()).toEqual([null])
    p.sh.apply('x'); p.echo.output(p.echo.inputSeq, p.sh.key)
    expect(p.echo.echoed(true, 0, null)).toBe(false)
    p.echo.replayed()
    expect(p.echo.echoed(true, 0, null)).toBe(true)
  })
})

describe('3.6.13 (review M2): rapoartele terminalului nu sunt taste', () => {
  it('focus, mouse, CPR, DA, DSR, OSC de culoare → raport', () => {
    for (const d of ['\x1b[I', '\x1b[O', '\x1b[<0;12;5M', '\x1b[<0;12;5m\x1b[<0;12;5M', '\x1b[32;10;5M',
      '\x1b[M !!', '\x1b[24;80R', '\x1b[?1;2c', '\x1b[>0;276;0c', '\x1b[0n', '\x1b[?2004;1$y',
      '\x1b]11;rgb:0000/0000/0000\x07', '\x1b]10;rgb:ffff/ffff/ffff\x1b\\', '\x1b[8;24;80t', '\x1bP!|00000000\x1b\\']) {
      expect(isTerminalReport(d), JSON.stringify(d)).toBe(true)
    }
  })
  it('tastele rămân taste (fail-closed): ↑, Ctrl+P, TAB, Shift/Ctrl+F3 (= CSI 1;2..8 R), text', () => {
    for (const d of ['\x1b[A', '\x10', '\t', '\x1b[1;5R', '\x1b[1;2R', 'ls', '\x1b[I ls', '', '\x1b[200~x\x1b[201~']) {
      expect(isTerminalReport(d), JSON.stringify(d)).toBe(false)
    }
  })
})

describe('3.6.13 (review L4, L6)', () => {
  it('„Rulează" din dialogul de ecou: o regulă pe linia devenită vizibilă escaladează', () => {
    expect(localRunDecision({ kind: 'ok' })).toBe('send')
    expect(localRunDecision({ kind: 'unknown' })).toBe('send')   // acceptat explicit în dialog
    expect(localRunDecision({ kind: 'rule', rule: g.rules[0], cmd: 'rm -rf /srv' })).toBe('escalate')
  })
  it('plasa de timp a ecoului e plafonată (vârf de RTT)', () => {
    expect(echoSettleMs(30_000)).toBe(5000)
    expect(echoSettleMs(1000)).toBe(4000)
  })
})
