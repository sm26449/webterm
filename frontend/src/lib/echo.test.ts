import { describe, expect, it } from 'vitest'
import type { CommandGuard } from './api'
import { countCprReplies, countCprRequests, echoes, EchoTracker, isTerminalReport, keyShape, LineKey, ECHO_PENDING_MAX, reportOnly, sendIsReport, sentArgs } from './echo'
import { echoSettleMs, judgeLocal, judgePeers, localRunDecision, plainText } from './broadcastGuard'

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
  return { key, apply, set: (l: string) => { line = l }, get line() { return line } }
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
    echo.output(tag, sh.key, t, null)
  }
  /** un chunk care pune linia pe `l` (o redesenare parţială) */
  const chunk = (l: string) => { sh.set(l); echo.output(echo.inputSeq, sh.key, t, null) }
  // ca în SessionView: echoed (cu starea liniei) ÎNAINTEA lui unechoed
  const local = () => {
    const echoed = echo.echoed(false, t, null, sh.key())
    return { atPrompt: true, echoed, pending: sh.line || null, unechoed: echo.unechoed() }
  }
  return { sh, echo, send, arrive, chunk, local, tick: (ms: number) => { t += ms } }
}

const g: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'block' }] }

describe('3.6.13 (review M1): ecoul unei taste vechi nu confirmă tasta nouă', () => {
  it('↑↑⏎ rapid: ecoul primului ↑ NU confirmă al doilea; linia rulată nu e cea citită', () => {
    const p = pane(['rm -rf /srv', 'ls'])
    p.send('\x1b[A'); p.send('\x1b[A')
    p.arrive(1)                      // primul ↑ → „ls" pe ecran
    expect(p.sh.line).toBe('ls')
    expect(p.echo.unechoed()).toEqual([null, null])   // schimbarea unei taste ne-text: aşteaptă liniştea
    p.tick(100)
    // logica veche: instantaneu doar pentru ultima trimitere → „ls" ≠ linia goală → echoed, ok pe „ls"
    expect(judgeLocal(p.local(), g, false).kind).toBe('wait')
    expect(p.echo.unechoed()).toEqual([null])
    expect(judgeLocal(p.local(), g, true).kind).toBe('unknown')
    p.arrive(1)                      // al doilea ↑ → rm -rf /srv
    p.tick(100)
    expect(judgeLocal(p.local(), g, true)).toMatchObject({ kind: 'rule', cmd: 'rm -rf /srv' })
  })

  it('două ecouri non-text în acelaşi chunk: al doilea rămâne fără ecou (fail-closed), nu invers', () => {
    const p = pane(['rm -rf /srv', 'ls'])
    p.send('\x1b[A'); p.send('\x1b[A')
    p.arrive(2)
    p.tick(100)
    expect(p.local().echoed).toBe(false)
    expect(p.echo.unechoed()).toEqual([null])
  })

  // a treia trecere de review (MEDIUM-2): redesenarea UNEI taste ruptă în două chunk-uri
  it('ecoul unui ↑ rupt în două chunk-uri NU confirmă două taste', () => {
    const p = pane(['rm -rf /srv', 'ls -la /tmp'])
    p.send('\x1b[A'); p.send('\x1b[A')
    p.chunk('ls -l')                 // prima jumătate a redesenării lui ↑1
    p.tick(5)
    p.chunk('ls -la /tmp')           // restul ei; ↑2 n-a sosit încă
    p.tick(100)
    const st = p.local()
    // logica din fd208c4: chunk 1 confirma ↑1, chunk 2 confirma ↑2 → „ls -la /tmp" citit, rm -rf rulat
    expect(st.echoed).toBe(false)
    expect(st.unechoed).toEqual([null])
    expect(judgeLocal(st, g, true).kind).toBe('unknown')
  })

  it('o tastă ne-text: confirmată abia după ce fluxul tace, cu linia stabilă', () => {
    const p = pane(['ls'])
    p.send('\x1b[A')
    p.arrive(1)
    p.tick(10)
    expect(p.local().echoed).toBe(false)        // prea devreme
    p.tick(40)
    expect(p.local().echoed).toBe(true)
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
    expect(p.echo.unechoed()).toEqual(['x'])
    expect(p.echo.coarseSeq).toBe(1)
    p.arrive(1)
    expect(p.echo.unechoed()).toEqual([])
  })

  it('linia dispare (Enter → comanda rulează): tastele de dinainte au primit ecou (regula grosieră)', () => {
    const p = pane()
    p.send('l'); p.send('\x1b[D')
    p.echo.output(p.echo.inputSeq, () => null)
    expect(p.echo.echoed(true, 0, null)).toBe(true)
  })

  it('replay complet → totul confirmat', () => {
    const p = pane()
    for (let i = 0; i < 5; i++) p.send('\x10')
    p.echo.replayed()
    expect(p.echo.echoed(true, 0, null)).toBe(true)
  })

  // review 3.6.13 (MEDIUM-2): rafala comprimată nu mai blochează până la reconectare
  it('rafală peste plafon: eliberată când hostul a ajuns din urmă (output, linie schimbată, plasa de timp)', () => {
    const p = pane()
    for (let i = 0; i < ECHO_PENDING_MAX + 1; i++) p.send('\x10')
    expect(p.echo.unechoed()).toEqual([null])
    const tag = p.echo.inputSeq
    p.echo.output(tag, p.sh.key, 0, null)                      // referinţa rafalei
    p.sh.apply('x'); p.echo.output(tag, p.sh.key, 500, null)   // linia s-a schimbat, dar prea devreme
    expect(p.echo.echoed(true, 500, null)).toBe(false)
    p.sh.apply('y'); p.echo.output(tag, p.sh.key, 1500, null)  // după plasa de timp
    expect(p.echo.unechoed()).toEqual([])
    // tastele de după sunt urmărite normal
    p.send('z'); p.sh.apply('z'); p.echo.output(p.echo.inputSeq, p.sh.key, 1500, null)
    expect(p.echo.unechoed()).toEqual([])
  })
})

// review 3.6.13 (LOW-1b): typeahead tastat cât rula o comandă
describe('3.6.13: typeahead „orb"', () => {
  function busyPane() {
    let line: string | null = null                 // null = nicio linie citibilă (comandă în curs)
    const echo = new EchoTracker()
    const key = (): LineKey | null => (line === null ? null : { k: `n\u00000\u0000${line.length}\u0000${line}`, line })
    const send = (d: string, t = 0) => {
      const { seq, needBase } = echo.sent(plainText(d) ? d : null, t)
      if (needBase) echo.setBase(seq, key())
    }
    return { echo, key, send, set: (l: string | null) => { line = l } }
  }
  it('promptul apare fără typeahead pe ecran → NU e ecou; verificarea lipeşte textul (regula prinde)', () => {
    const b = busyPane()
    for (const c of 'rm -rf /srv') b.send(c)
    b.set('')                                     // promptul nou, linie goală (typeahead încă neafişat)
    b.echo.output(b.echo.inputSeq, b.key, 10, null)
    expect(b.echo.echoed(false, 10, null)).toBe(false)
    // logica de dinainte: credit strict la prima linie citibilă → Enter citea linia goală, shell-ul rula typeahead-ul
    expect(judgeLocal({ atPrompt: true, echoed: false, pending: null, unechoed: b.echo.unechoed() }, g, true))
      .toMatchObject({ kind: 'rule', cmd: 'rm -rf /srv' })
    b.set('rm -rf /srv')                          // readline afişează typeahead-ul
    b.echo.output(b.echo.inputSeq, b.key, 20, null)
    expect(b.echo.echoed(false, 20, null)).toBe(true)
  })
  it('promptul apare cu typeahead-ul deja afişat → confirmat', () => {
    const b = busyPane()
    for (const c of 'ls') b.send(c)
    b.set('ls')
    b.echo.output(b.echo.inputSeq, b.key, 10, null)
    expect(b.echo.unechoed()).toEqual([])
  })
  it('taste consumate de un program (vim) mai vechi decât plasa de timp → nu blochează promptul de după', () => {
    const b = busyPane()
    for (const c of ':wq') b.send(c, 0)
    b.set('')
    b.echo.output(b.echo.inputSeq, b.key, 3000, null)
    expect(b.echo.unechoed()).toEqual([])
  })
})

describe('3.6.13 (review HIGH-1): un text lipit în forma unui raport NU ocoleşte guardrail-ul', () => {
  it('chunk cu CR/LF → niciodată raport, trece prin guardrail', () => {
    for (const d of ['\x1b]0;x\rrm -rf /srv\r\x07', '\x1b]11;rgb:0/0/0\x07\r', '\x1b[I\r', '\x1bP1$rx\rrm -rf /\r\x1b\\']) {
      expect(isTerminalReport(d), JSON.stringify(d)).toBe(false)
      expect(reportOnly(d, false, false), JSON.stringify(d)).toBe(false)
      expect(reportOnly(d, true, false), JSON.stringify(d)).toBe(false)   // nici marcat explicit
    }
    expect(reportOnly(new Uint8Array([0x1b, 0x5b, 0x4d, 0x20, 0x0d, 0x21]), true, false)).toBe(false)
  })
  it('datele unui paste nu sunt niciodată rapoarte', () => {
    expect(reportOnly('\x1b[I', false, true)).toBe(false)
    expect(reportOnly('\x1b[I', false, false)).toBe(true)
  })
  it('OSC: doar răspunsurile de culoare; un titlu sau alt OSC nu e raport', () => {
    expect(isTerminalReport('\x1b]0;x\x07')).toBe(false)
    expect(isTerminalReport('\x1b]52;c;cm0gLXJmIC8=\x07')).toBe(false)
    expect(isTerminalReport('\x1b]4;1;rgb:cd/00/00\x1b\\')).toBe(true)
    expect(isTerminalReport('\x1b]11;rgb:0000/0000/0000\x07')).toBe(true)
  })
})

describe('3.6.13 (review M2): rapoartele terminalului nu sunt taste', () => {
  it('focus, mouse, CPR, DA, DSR, OSC de culoare → raport', () => {
    for (const d of ['\x1b[I', '\x1b[O', '\x1b[<0;12;5M', '\x1b[<0;12;5m\x1b[<0;12;5M', '\x1b[32;10;5M',
      '\x1b[M !!', '\x1b[24;80R', '\x1b[?1;2c', '\x1b[>0;276;0c', '\x1b[0n', '\x1b[?2004;1$y',
      '\x1b]11;rgb:0000/0000/0000\x07', '\x1b]10;rgb:ffff/ffff/ffff\x1b\\', '\x1b[8;24;80t', '\x1bP!|00000000\x1b\\',
      '\x1bP>|xterm.js(5.5.0)\x1b\\', '\x1bP1+r544e=787465726d\x1b\\', '\x1b[?997;1n', '\x1b[?0u']) {
      expect(isTerminalReport(d), JSON.stringify(d)).toBe(true)
    }
  })
  it('tastele rămân taste (fail-closed): ↑, Ctrl+P, TAB, F3 cu modificatori şi Meta (= CSI 1;n R), text', () => {
    for (const d of ['\x1b[A', '\x10', '\t', '\x1b[1;5R', '\x1b[1;2R', '\x1b[1;9R', '\x1b[1;16R', '\x1b[1;40R', 'ls', '\x1b[I ls', '', '\x1b[200~x\x1b[201~']) {
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

describe('3.6.13, verificarea finală', () => {
  // LOW-C: output primit dar încă neparsat → nu e „linişte"
  it('o scriere încă neparsată amână confirmarea tastei ne-text', () => {
    const p = pane(['ls'])
    p.send('\x1b[A')
    p.arrive(1)
    p.echo.writeStart()              // o scriere mare, parsată în felii — callback-ul n-a venit încă
    p.tick(200)
    expect(p.local().echoed).toBe(false)
    p.echo.writeEnd()
    p.tick(100)
    expect(p.local().echoed).toBe(true)
  })

  // LOW-A: ↑ apoi „ -v" tastat imediat
  it('text simplu tastat imediat după o tastă ne-text e confirmat odată cu ea (fără plasa de 1 s)', () => {
    const p = pane(['ls'])
    p.send('\x1b[A')
    p.arrive(1)                      // „ls"
    for (const c of ' -v') p.send(c)
    p.arrive(3)                      // „ls -v": încă în aceeaşi rafală
    p.tick(100)
    const st = p.local()
    expect(st.echoed).toBe(true)
    expect(st.unechoed).toEqual([])
    expect(st.pending).toBe('ls -v')
  })
  it('… dar nu dacă linia de la prima schimbare îl conţinea deja (nu e ecoul lui)', () => {
    const p = pane([])
    p.send('\x1b[A')
    p.chunk('x -v')                  // linia avea deja „ -v" la prima schimbare
    p.send(' '); p.send('-'); p.send('v')
    p.tick(100)
    expect(p.local().unechoed).toEqual([' ', '-', 'v'])
  })

  // LOW-B: CPR pe rândul 1 doar după o cerere din output
  it('ESC[1;nR: raport doar după o cerere de poziţie (ESC[6n / ESC[?6n) din output', () => {
    expect(isTerminalReport('\x1b[1;5R')).toBe(false)
    expect(isTerminalReport('\x1b[1;5R', true)).toBe(true)
    expect(isTerminalReport('\x1b[12;5R')).toBe(true)
    expect(reportOnly('\x1b[1;40R', false, false, true)).toBe(true)
    expect(reportOnly('\x1b[1;40R', false, false, false)).toBe(false)
    // nici o cerere nu face raport un chunk cu linie sau un paste
    expect(reportOnly('\x1b[1;40R\r', false, false, true)).toBe(false)
    expect(reportOnly('\x1b[1;40R', false, true, true)).toBe(false)
    const enc = new TextEncoder()
    expect(countCprRequests(enc.encode('a\x1b[6nb\x1b[?6n\x1b[0m\x1b[6'))).toBe(2)
    expect(countCprRequests(enc.encode('\x1b[5n\x1b[16n'))).toBe(0)
    expect(countCprReplies('\x1b[1;5R\x1b[?3;1R')).toBe(2)
  })
})

describe('3.6.13, verificarea lui f34e5ec: text după o tastă ne-text — potrivire EXACTĂ', () => {
  it('↑ recheamă „…/tmp/x" (redesenare ruptă), apoi „x" tastat fără ecou → x NU e confirmat', () => {
    const p = pane([])
    p.send('\x1b[A')
    p.chunk('')                      // prima jumătate: linia ştearsă
    p.tick(5)
    p.chunk('rm -rf /tmp/x')         // restul redesenării
    p.send('x')                      // ecoul lui x n-a sosit
    p.tick(100)
    const st = p.local()
    // logica din f34e5ec („se termină cu" + prima linie „"): x confirmat → verificat „…/tmp/x", rula „…/tmp/xx"
    expect(st.unechoed).toEqual(['x'])
    expect(st.echoed).toBe(false)
    const g2: CommandGuard = { enabled: true, rules: [{ pattern: 'rm -rf /tmp/xx$', action: 'block' }] }
    expect(judgeLocal(st, g2, true).kind).toBe('rule')   // verificarea locală vede şi linia + „x"
  })
  it('↑ apoi „ -v" cu ecoul sosit → confirmat (linia = linia rechemată + text, exact)', () => {
    const p = pane(['ls'])
    p.send('\x1b[A')
    p.arrive(1)
    for (const c of ' -v') p.send(c)
    p.arrive(3)
    p.tick(100)
    expect(p.local().unechoed).toEqual([])
  })
})

// e2e 3.6.13: o linie lungă tastată rapid (Playwright keyboard.type, un onData per caracter) ajungea
// la „Încă nu pot verifica linia" — fără nicio tastă ne-text
describe('3.6.13 e2e: linie lungă tastată rapid', () => {
  const cmd = "seq -f 'WT_HIST_%g' 1 3000; yes " + 'F'.repeat(96) + ' | head -n 3500; echo WT_HIST_$((7*6))'
  const g3: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'block' }] }

  it('ecoul unei linii lungi (citită fără spaţiu la wrap — vezi readCommand) e recunoscut exact', () => {
    const echo = new EchoTracker()
    let shown = ''
    const key = (): LineKey => ({ k: `n\u00000\u0000${shown.length}\u0000${shown}`, line: shown })
    let sentIdx = 0
    for (const c of cmd) {
      const { seq, needBase } = echo.sent(c, 0)
      if (needBase) echo.setBase(seq, key())
      sentIdx++
      if (sentIdx % 7 === 0) {          // ecouri sosite în rafale
        shown = cmd.slice(0, sentIdx)
        echo.output(echo.inputSeq, key, 0, null)
      }
    }
    shown = cmd
    echo.output(echo.inputSeq, key, 0, null)
    expect(echo.unechoed()).toEqual([])
  })

  it('o linie citită cu un spaţiu în plus NU confirmă tastele (comparaţie exactă — review L3)', () => {
    const echo = new EchoTracker()
    let line = ''
    const key = (): LineKey => ({ k: `n\u00000\u0000${line.length}\u0000${line}`, line })
    for (const c of 'ab') { const r = echo.sent(c, 0); if (r.needBase) echo.setBase(r.seq, key()) }
    line = 'a b'
    echo.output(echo.inputSeq, key, 0, null)
    expect(echo.unechoed().join('')).toBe('ab')
  })

  it('peste plafonul de 64 fără ecou, dar doar text: verificarea lipeşte textul, nu cere dialog', () => {
    const echo = new EchoTracker()
    for (const c of cmd) {
      const { seq, needBase } = echo.sent(c, 0)
      if (needBase) echo.setBase(seq, { k: 'n\u00000\u00000\u0000', line: '' })
    }
    const un = echo.unechoed()
    expect(un.every((t) => t !== null)).toBe(true)
    const v = judgeLocal({ atPrompt: true, echoed: false, pending: null, unechoed: un }, g3, true)
    // logica din fd208c4..77a945a: intrarea comprimată era null → „Încă nu pot verifica linia"
    expect(v.kind).toBe('ok')
    // o regulă tot prinde linia lipită
    const v2 = judgeLocal({ atPrompt: true, echoed: false, pending: null, unechoed: ['rm -rf /', ...un] }, g3, true)
    expect(v2.kind).toBe('rule')
  })
})

// e2e 3.6.13 (cauza reală a dialogului la o comandă tastată normal): Enter-ul comenzii ANTERIOARE
// rămânea în aşteptare (C, D şi promptul nou într-un singur chunk), iar textul tastat după el se
// strângea până la plafon → intrare comprimată fără text → „Încă nu pot verifica linia"
describe('3.6.13 e2e: Enter anterior + linie lungă', () => {
  const g4: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'block' }] }
  const long = "seq -f 'WT_HIST_%g' 1 3000; yes " + 'F'.repeat(96) + ' | head -n 3500; echo WT_HIST_$((7*6))'

  it('Enter-ul de dinainte se confirmă la prima schimbare; textul de după se potriveşte normal', () => {
    const echo = new EchoTracker()
    let line = 'echo DUPA_RELOAD'
    let row = 0
    const key = (): LineKey => ({ k: `n\u0000${row}\u0000${line.length}\u0000${line}`, line })
    const send = (text: string | null, t: number, submit = false) => {
      const { seq, needBase } = echo.sent(text, t, submit)
      if (needBase) echo.setBase(seq, key())                 // ca SessionView (write gol)
    }
    send(null, 0, true)                                      // Enter
    // un singur chunk: rând nou, output, D, prompt nou (linia niciodată „necitibilă")
    row = 2; line = ''
    echo.output(echo.inputSeq, key, 5, null)
    // logica din 77a945a: Enter-ul rămânea candidat până la următorul Enter
    expect(echo.unechoed()).toEqual([])
    let t = 10
    for (let i = 0; i < long.length; i++) {
      send(long[i], t)
      if (i % 5 === 4 || i === long.length - 1) { line = long.slice(0, i + 1); echo.output(echo.inputSeq, key, t, null) }
      t += 1
    }
    expect(echo.unechoed()).toEqual([])
    expect(judgeLocal({ atPrompt: true, echoed: echo.echoed(false, t, null, key()), pending: line, unechoed: echo.unechoed() }, g4, true).kind).toBe('ok')
  })

  it('↑ apoi tastare lungă cu pauze: ↑ se confirmă la output (nu abia la Enter), fără intrare comprimată', () => {
    const echo = new EchoTracker()
    let line = ''
    const key = (): LineKey => ({ k: `n\u00000\u0000${line.length}\u0000${line}`, line })
    const { seq } = echo.sent(null, 0)                         // ↑
    echo.setBase(seq, key())
    line = 'ls'
    echo.output(echo.inputSeq, key, 1, null)
    let t = 100                                                // pauză > fereastra de linişte
    const typed = ' ' + 'x'.repeat(90)
    for (let i = 0; i < typed.length; i++) {
      const r = echo.sent(typed[i], t)
      if (r.needBase) echo.setBase(r.seq, key())
      line = 'ls' + typed.slice(0, i + 1)
      echo.output(echo.inputSeq, key, t + 5, null)
      t += 100
    }
    expect(echo.unechoed()).toEqual([])
  })
})

// e2e 3.6.13 (diagnoza [wt-echo]): după un reload linia e necunoscută până la primul prompt live,
// deci comanda tastată atunci + Enter-ul ei sunt „oarbe"; rămâneau în aşteptare şi blocau comanda
// următoare („Încă nu pot verifica linia")
describe('3.6.13 e2e: Enter „orb" consumat', () => {
  it('comanda oarbă + Enter-ul ei ies din aşteptare la prima linie citibilă; textul de după se potriveşte', () => {
    const echo = new EchoTracker()
    let line: string | null = null                 // după reload: nicio linie citibilă
    const key = (): LineKey | null => (line === null ? null : { k: `n\u00000\u0000${line.length}\u0000${line}`, line })
    const send = (d: string, t: number) => {
      const r = echo.sent(plainText(d) ? d : null, t, d === '\r')
      if (r.needBase) echo.setBase(r.seq, key())
    }
    let t = 0
    for (const c of 'echo DUPA_ISTORIC_42') send(c, t++)
    send('\r', t++)
    // prompt live nou, linia goală; utilizatorul tastează comanda următoare
    line = ''
    echo.output(echo.inputSeq, key, t, null)
    expect(echo.unechoed()).toEqual([])
    const next = 'sleep 2; echo WT_BG_42'
    for (let i = 0; i < next.length; i++) {
      send(next[i], t++)
      line = next.slice(0, i + 1)
      echo.output(echo.inputSeq, key, t, null)
    }
    expect(echo.unechoed()).toEqual([])
    expect(echo.echoed(false, t, null, key())).toBe(true)
  })
  it('typeahead tastat DUPĂ Enter-ul orb rămâne (verificarea locală îl lipeşte)', () => {
    const echo = new EchoTracker()
    let line: string | null = null
    const key = (): LineKey | null => (line === null ? null : { k: `n\u00000\u0000${line.length}\u0000${line}`, line })
    const send = (d: string, t: number) => {
      const r = echo.sent(plainText(d) ? d : null, t, d === '\r')
      if (r.needBase) echo.setBase(r.seq, key())
    }
    for (const c of 'make') send(c, 0)
    send('\r', 0)
    for (const c of 'rm -rf /srv') send(c, 0)       // tastat cât rula make
    line = ''                                          // promptul nou, typeahead-ul neafişat încă
    echo.output(echo.inputSeq, key, 5, null)
    expect(echo.unechoed().join('')).toBe('rm -rf /srv')
  })
})

describe('3.6.13 e2e: textul unei linii deja trimise nu blochează coada', () => {
  it('text nepotrivit (linie citită greşit sub tmux) + Enter → la prima schimbare de după Enter iese tot', () => {
    const echo = new EchoTracker()
    let line = 'garbage'
    const key = (): LineKey => ({ k: `n\u00000\u0000${line.length}\u0000${line}`, line })
    const send = (d: string, t: number, submit = false) => {
      const r = echo.sent(plainText(d) ? d : null, t, submit)
      if (r.needBase) echo.setBase(r.seq, key())
    }
    for (const c of 'for i in 1 2; do echo $i; done') send(c, 0)
    line = 'something else'                      // ecoul nu se potriveşte (rândul promptului greşit)
    echo.output(echo.inputSeq, key, 1, null)
    send('\r', 2, true)
    line = ''                                    // prompt nou
    echo.output(echo.inputSeq, key, 3, null)
    // logica din 40d5d80: textul nepotrivit + Enter-ul din spatele lui rămâneau → dialog la comanda următoare
    expect(echo.unechoed()).toEqual([])
  })
})

describe('review 3.6.13 H1: un rând de prompt citit greşit nu se confirmă niciodată', () => {
  it('linia citită de la prompt nu arată textul tastat → rămâne fără ecou; broadcast: unknown', () => {
    const base: LineKey = { k: 'a', line: 'rm -rf /srv/da' }
    expect(echoes(base, { k: 'b', line: 'ta/old' }, 'ta/old')).toBe(false)     // fragment de pe alt rând
    expect(echoes(base, { k: 'b', line: 'rm -rf /srv/data/old' }, 'ta/old')).toBe(true)
    const g5: CommandGuard = { enabled: true, rules: [{ pattern: '^rm\\s+-rf', action: 'block' }] }
    // panou-ţintă la broadcast cu tastele fără ecou → wait, apoi unknown (nu „ok" pe fragment)
    expect(judgePeers([{ inert: false, live: true, atPrompt: true, echoed: false, pending: 'ta/old', known: true, id: 'p' }], g5, true).kind).toBe('unknown')
  })
})

describe('review 3.6.13 H1: prompt pierdut → „nu pot verifica" şi într-un singur panou', () => {
  it('judgeLocal cu lineLost → unknown (un block cunoscut câştigă)', () => {
    const g6: CommandGuard = { enabled: true, rules: [{ pattern: 'mkfs', action: 'block' }] }
    expect(judgeLocal({ atPrompt: false, echoed: true, pending: null, unechoed: [], lineLost: true }, g6, true).kind).toBe('unknown')
    expect(judgeLocal({ atPrompt: true, echoed: true, pending: 'mkfs /dev/x', unechoed: [], lineLost: true }, g6, true).kind).toBe('rule')
  })
})

// review 3.6.13 M1: typeahead după un Enter încă fără ecou
describe('review 3.6.13 M1: tastele de după un Enter fără ecou sunt „oarbe"', () => {
  it('make⏎rm -rf /tmp/b — linia a doua NU se confirmă la pornirea comenzii; verificarea o lipeşte', () => {
    const echo = new EchoTracker()
    let line: string | null = ''
    const key = (): LineKey | null => (line === null ? null : { k: `n\u00000\u0000${line.length}\u0000${line}`, line })
    const send = (d: string, t: number) => {
      const r = echo.sent(plainText(d) ? d : null, t, d === '\r')
      if (r.needBase) echo.setBase(r.seq, key())
    }
    for (const c of 'make') send(c, 0)
    line = 'make'; echo.output(echo.inputSeq, key, 1, null)
    send('\r', 2)
    for (const c of 'rm -rf /tmp/b') send(c, 3)
    line = null; echo.output(echo.inputSeq, key, 4, null)     // C: make rulează
    line = ''; echo.output(echo.inputSeq, key, 5, null)       // D/A/B: prompt nou, typeahead încă neafişat
    expect(echo.unechoed().join('')).toBe('rm -rf /tmp/b')
    const g7: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'block' }] }
    expect(judgeLocal({ atPrompt: true, echoed: echo.echoed(false, 6, null, key()), pending: null, unechoed: echo.unechoed() }, g7, true).kind).toBe('rule')
  })
})

describe('review 3.6.13 L2: diagnoza nu conţine text tastat', () => {
  it('keyShape păstrează doar caracterele de control', () => {
    expect(keyShape('\x1b[200~secret-token\r')).toBe(JSON.stringify('\x1b' + '·'.repeat(15)))
    expect(keyShape('\x10')).toBe(JSON.stringify('\x10'))
  })
})

describe('review 3.6.13 L1: textul inserat nu e niciodată raport', () => {
  it('un snippet în forma unui răspuns DCS (readline: ESC P = M-p) rămâne tastă', () => {
    const dcs = '\x1bP>|xterm.js(5.5.0)\x1b\\'
    expect(sendIsReport('key', dcs, false, false)).toBe(false)     // typeText / inserări
    expect(sendIsReport('auto', dcs, false, false)).toBe(true)     // date difuzate: după formă
    expect(sendIsReport('auto', dcs, true, false)).toBe(false)     // dintr-un paste: niciodată
    expect(sendIsReport('report', '\x1b[I', false, false)).toBe(true)
  })
})

// audit 2026-10-17 (SV-01): SessionView.send marchează Ctrl+O (`\x0f`) ca trimitere a liniei
// (sentArgs → isSubmitKey) — ecoul lui e orice schimbare a liniei şi închide tot ce era înaintea lui,
// ca Enter. Până atunci pleca cu submit=false: textul dinaintea lui rămânea în aşteptare şi bloca
// verificarea comenzii următoare („Încă nu pot verifica linia").
describe('SV-01: Ctrl+O închide tot ce era înaintea lui, ca Enter', () => {
  // `submit` = false simulează cablajul VECHI (submit mereu false pentru o tastă care nu e Enter);
  // altfel argumentele lui sent() sunt EXACT cele ale lui SessionView.send (sentArgs, cu chunk-ul anterior)
  const run = (submit: boolean, ...keys: string[]) => {
    const echo = new EchoTracker()
    let line = ''
    let row = 0
    let prev: string | null = null
    const key = (): LineKey => ({ k: `n\u0000${row}\u0000${line.length}\u0000${line}`, line })
    const send = (d: string, t: number) => {
      const a = sentArgs(d, prev)
      prev = d
      const { seq, needBase } = echo.sent(a.text, t, a.submit && submit, a.raw)
      if (needBase) echo.setBase(seq, key())
    }
    for (const c of 'rm -rf /tmp/x') send(c, 1)
    for (const k of keys.length ? keys : ['\x0f']) send(k, 2)   // Ctrl+O = operate-and-get-next
    // un singur chunk: rând nou, comanda rulează, prompt nou cu următoarea linie din istoric
    row = 2; line = 'echo next'
    echo.output(echo.inputSeq, key, 5, null)
    return echo
  }
  it('sentArgs (cablajul lui SessionView.send): tasta de trimitere pleacă fără text, cu submit', () => {
    expect(sentArgs('\x0f', null)).toEqual({ text: null, submit: true, raw: '\x0f' })
    expect(sentArgs('\r', 'x')).toEqual({ text: null, submit: true, raw: '\r' })
    expect(sentArgs('\x1ba', null)).toEqual({ text: null, submit: true, raw: '\x1ba' })
    // text simplu: textul lui, nu trimitere; ESC singur: fără text, nu trimitere
    expect(sentArgs('x', null)).toEqual({ text: 'x', submit: false, raw: 'x' })
    expect(sentArgs('\x1b', 'x')).toEqual({ text: null, submit: false, raw: '\x1b' })
    expect(sentArgs(new Uint8Array(3), '\x1b')).toEqual({ text: null, submit: false, raw: '<3 bytes>' })
    // re-review SV-01 (MED): `a` după un Escape trimis singur e a doua tastă a lui `ESC a` — trimitere,
    // nu text (ecoul lui nu e un „a" pe linie); după orice alt chunk e text
    expect(sentArgs('a', '\x1b')).toEqual({ text: null, submit: true, raw: 'a' })
    expect(sentArgs('A', '\x1b')).toEqual({ text: null, submit: true, raw: 'A' })
    expect(sentArgs('a', 'x')).toEqual({ text: 'a', submit: false, raw: 'a' })
    expect(sentArgs('a', null)).toEqual({ text: 'a', submit: false, raw: 'a' })
    expect(sentArgs('b', '\x1b')).toEqual({ text: 'b', submit: false, raw: 'b' })
  })
  it('cu submit (fix): nimic în aşteptare după ecoul lui', () => {
    expect(run(true).unechoed()).toEqual([])
  })
  it('fără submit (comportamentul vechi): textul tastat rămâne în aşteptare → ar bloca linia următoare', () => {
    expect(run(false).unechoed().length).toBeGreaterThan(0)
  })
  it('Escape apoi `a` (două chunk-uri, zsh accept-and-hold) închide tot ce era înaintea lor, ca Enter', () => {
    expect(run(true, '\x1b', 'a').unechoed()).toEqual([])
    expect(run(true, '\x1b', 'A').unechoed()).toEqual([])
    expect(run(false, '\x1b', 'a').unechoed().length).toBeGreaterThan(0)
    // `x` apoi `a`: nicio trimitere — textul rămâne în aşteptare (linia nu l-a arătat)
    expect(run(true, 'x', 'a').unechoed().length).toBeGreaterThan(0)
  })
  it('\\x0f nu e niciodată raport de terminal (onData, onBinary): trece prin guardrail', () => {
    expect(isTerminalReport('\x0f')).toBe(false)
    expect(reportOnly('\x0f', false, false)).toBe(false)
    expect(reportOnly('rm -rf /\x0f', false, false)).toBe(false)
    expect(reportOnly(new Uint8Array([0x0f]), true, false)).toBe(false)
    expect(sendIsReport('auto', 'rm -rf /\x0f', false, false)).toBe(false)
  })
  // re-review SV-01: `ESC a` / `ESC A` (zsh accept-and-hold) — aceeaşi tratare ca Ctrl+O
  it('ESC a (zsh accept-and-hold) închide tot ce era înaintea lui, ca Enter, şi nu e niciodată raport', () => {
    expect(run(true, '\x1ba').unechoed()).toEqual([])
    expect(run(true, '\x1bA').unechoed()).toEqual([])
    expect(run(false, '\x1ba').unechoed().length).toBeGreaterThan(0)
    expect(isTerminalReport('\x1ba')).toBe(false)
    expect(reportOnly('\x1ba', false, false)).toBe(false)
    expect(reportOnly('\x1bA', true, false)).toBe(false)        // nici pe o cale „doar rapoarte"
    expect(reportOnly('rm -rf /\x1ba', false, false)).toBe(false)
    expect(reportOnly(new Uint8Array([0x1b, 0x61]), true, false)).toBe(false)
    expect(reportOnly(new Uint8Array([0x1b, 0x41]), true, false)).toBe(false)
    expect(sendIsReport('auto', 'rm -rf /\x1ba', false, false)).toBe(false)
    // rapoartele reale rămân rapoarte (focus in, mouse X10 pe onBinary)
    expect(reportOnly('\x1b[I', false, false)).toBe(true)
    expect(reportOnly(new Uint8Array([0x1b, 0x5b, 0x4d, 0x20, 0x21, 0x21]), true, false)).toBe(true)
  })
})

// hotfix 3.6.17 (CI roşu pe SV-01): o rafală de output care se termină exact după un spaţiu tastat
// („rm -rf ␣"), apoi linişte, apoi restul liniei. Cu cheia de ecou citită EXACT (typedLine) spaţiul
// schimbă linia şi tot ce urmează se confirmă; cu linia citită cu trim (pendingCommand) spaţiul nu
// schimba nimic, devenea tastă-candidat confirmată la linişte cu referinţa trunchiată, iar de la „/"
// niciun text nu se mai potrivea — zeci de taste rămâneau „fără ecou" (dialog „Încă nu pot verifica").
describe('hotfix 3.6.17: spaţiu la capăt de rafală, apoi linişte, apoi text', () => {
  function paneWithKey(trimKey: boolean) {
    let line = ''
    const shown = () => (trimKey ? line.trim() : line)
    const key = (): LineKey => ({ k: `n\u00000\u0000${line.length}\u0000${shown()}`, line: shown() })
    const echo = new EchoTracker()
    const inFlight: string[] = []
    let t = 0
    const send = (d: string) => {
      const { seq, needBase } = echo.sent(d, t)
      if (needBase) echo.setBase(seq, key())
      inFlight.push(d)
    }
    const arrive = (n: number) => {
      const tag = echo.inputSeq
      for (const d of inFlight.splice(0, n)) line += d
      echo.output(tag, key, t, null)
    }
    const type = (s: string) => { for (const c of s) send(c) }
    return { echo, send, arrive, type, key: () => key(), tick: (ms: number) => { t += ms }, now: () => t }
  }
  const scenario = (p: ReturnType<typeof paneWithKey>) => {
    p.type('rm -rf'); p.arrive(6); p.tick(5)
    p.type(' '); p.arrive(1)              // rafala se termină exact după spaţiu
    p.tick(100)                           // linişte (> echoQuietMs): tasta-candidat s-ar confirma acum
    p.type('/tmp/x'); p.arrive(6); p.tick(100)
    p.echo.echoed(false, p.now(), null, p.key())   // ca SessionView.echoedNow: încearcă quiet()
    return p.echo.unechoed()
  }
  it('cheia EXACTĂ (typedLine): spaţiul schimbă linia, tot textul se confirmă', () => {
    expect(scenario(paneWithKey(false))).toEqual([])
  })
  it('cheia cu trim (bug-ul): după spaţiu nimic nu se mai potriveşte — de asta cheia nu mai e pendingCommand', () => {
    const left = scenario(paneWithKey(true))
    expect(left.length).toBeGreaterThan(0)   // (aproape) tot „/tmp/x" rămâne fără ecou, deşi e pe ecran
  })
})
