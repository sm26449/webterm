import { describe, expect, it } from 'vitest'
import type { Terminal } from '@xterm/xterm'
import { CommandTracker, isPaneBorder, screenResetIn, screenResetScan, splitAfterMarks } from './commands'
import type { CommandGuard } from './api'
import { judgeLocal } from './broadcastGuard'

const enc = new TextEncoder()
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

function fakeTerm(): Terminal {
  const buffer = {
    type: 'normal', baseY: 0, cursorY: 0, cursorX: 2,
    getLine: (r: number) => (r === 0 ? { length: 2, isWrapped: false, translateToString: () => '$ ' } : undefined),
  }
  let n = 0
  return { buffer: { active: buffer }, registerMarker: () => ({ line: n++, dispose() {} }) } as unknown as Terminal
}

// SessionView, în mic: fiecare bucată se dă tracker-ului ÎNAINTE de a fi „parsată", cu starea de atunci;
// marcajul de la capătul ei se aplică după
function play(tr: CommandTracker, chunk: string) {
  for (const part of splitAfterMarks(enc.encode(chunk))) {
    const text = dec(part)
    if (tr.capturing) tr.feed(text)
    const m = /\x1b\]133;([^\x07\x1b]*)(?:\x07|\x1b\\)$/.exec(text)
    if (m) tr.handle(m[1])
  }
  tr.endChunk()
}

describe('captura output-ului în ordinea parsării (e2e 3.6.13: „copiază output-ul")', () => {
  it('splitAfterMarks: tăiat DUPĂ fiecare marcaj OSC 133 (BEL sau ST); restul rămâne', () => {
    const parts = splitAfterMarks(enc.encode('a\x1b]133;C\x07out\r\n\x1b]133;D;0\x1b\\$ x')).map(dec)
    expect(parts).toEqual(['a\x1b]133;C\x07', 'out\r\n\x1b]133;D;0\x1b\\', '$ x'])
    expect(splitAfterMarks(enc.encode('plain text')).map(dec)).toEqual(['plain text'])
    expect(splitAfterMarks(enc.encode('x\x1b]133;D')).map(dec)).toEqual(['x\x1b]133;D'])   // rupt la capăt
    expect(splitAfterMarks(enc.encode('\x1b]0;title\x07x')).map(dec)).toEqual(['\x1b]0;title\x07x'])
  })

  it('C şi output-ul lui în acelaşi chunk (sosite înaintea parsării lui C) → în captură', () => {
    const tr = new CommandTracker(fakeTerm())
    tr.handle('B')
    // logica veche: la SOSIRE nu rula nimic → nimic capturat → extragere de pe ecran, până la cursor
    play(tr, '\x1b]133;E;echo OSC_OK\x07\x1b]133;C\x07OSC_OK\r\n')
    play(tr, '\x1b]133;D;0\x07\x1b]133;A\x07root@h:~# \x1b]133;B\x07')
    const cmd = tr.commands[0]
    expect(cmd.captured).toContain('OSC_OK')
    expect(tr.outputOf(cmd)).toBe('OSC_OK')
    // comenzile de după NU mai intră în captura ei
    play(tr, '(exit 3)\r\n\x1b]133;E;(exit 3)\x07\x1b]133;C\x07\x1b]133;D;3\x07root@h:~# ')
    play(tr, 'cd /tmp\r\n')
    expect(tr.outputOf(cmd)).toBe('OSC_OK')
  })

  it('sub tmux D poate sosi înaintea ultimelor rânduri pictate: restul chunk-ului lui D intră în captură', () => {
    const tr = new CommandTracker(fakeTerm())
    tr.handle('B')
    play(tr, '\x1b]133;E;echo OSC_OK\x07\x1b]133;C\x07')
    play(tr, '\x1b]133;D;0\x07OSC_OK\r\nroot@h:~# ')
    expect(tr.outputOf(tr.commands[0])).toBe('OSC_OK')
    play(tr, 'next chunk\r\n')
    expect(tr.commands[0].captured).not.toContain('next chunk')
  })
})

// review 3.6.13 H1: poziţia promptului e un marker xterm, nu un rând absolut
describe('CommandTracker: rândul promptului urmează tăierea scrollback-ului', () => {
  function trimTerm() {
    const rows = [{ t: '$ ls', w: false }, { t: 'out', w: false }, { t: '$ rm -rf /srv/da', w: false }, { t: 'ta/old', w: true }]
    const markers: { line: number; isDisposed: boolean; dispose(): void }[] = []
    const buffer = {
      type: 'normal', baseY: 0,
      cursorY: 2, cursorX: 2,
      getLine: (r: number) => (rows[r] !== undefined
        ? { length: 80, isWrapped: rows[r].w, translateToString: (_t: boolean, from = 0, to?: number) => rows[r].t.slice(from, to) }
        : undefined),
    }
    const term = {
      cols: 80, buffer: { active: buffer },
      registerMarker: () => {
        const m = { line: buffer.baseY + buffer.cursorY, isDisposed: false, dispose() { m.isDisposed = true } }
        markers.push(m)
        return m
      },
    } as unknown as Terminal
    /** scrollback plin: rândul de sus e tăiat, totul urcă un rând (xterm: onTrim mută markerele) */
    const trim = () => {
      rows.shift()
      for (const m of markers) { m.line -= 1; if (m.line < 0) m.isDisposed = true }
      buffer.cursorY -= 1
    }
    return { term, buffer, trim }
  }
  it('după tăiere, linia se citeşte tot de la B (nu un fragment de pe alt rând)', () => {
    const { term, buffer, trim } = trimTerm()
    const tr = new CommandTracker(term)
    tr.handle('B')                                   // B la rândul 2, coloana 2
    buffer.cursorY = 3; buffer.cursorX = 6           // textul a trecut pe rândul următor (wrap)
    expect(tr.pendingCommand()).toBe('rm -rf /srv/data/old')
    trim(); trim()
    // logica veche (rând absolut 2): rândul 2 e acum „ta/old" → fragment, regula ^rm rata
    expect(tr.pendingCommand()).toBe('rm -rf /srv/data/old')
  })
  it('rândul promptului ieşit din buffer → promptLost, linia necunoscută', () => {
    const { term, buffer, trim } = trimTerm()
    const tr = new CommandTracker(term)
    tr.handle('B')
    buffer.cursorY = 3; buffer.cursorX = 6
    trim(); trim(); trim()
    expect(tr.promptLost).toBe(true)
    expect(tr.pendingCommand()).toBeNull()
    expect(tr.lineKnown()).toBe(false)
  })
})

// verificarea lui 222eae0 (H1 rezidual): rândul promptului mutat FĂRĂ evenimente de marker
describe('CommandTracker.promptLost: rânduri mutate fără evenimente de marker', () => {
  function screen(rowsInit: string[], cursor: { row: number; col: number }) {
    const rows = rowsInit.map((t) => ({ t, w: false }))
    const buffer = {
      type: 'normal', baseY: 0,
      get cursorY() { return cursor.row }, get cursorX() { return cursor.col },
      getLine: (r: number) => (rows[r] !== undefined
        ? { length: 80, isWrapped: rows[r].w, translateToString: (trim: boolean, from = 0, to?: number) => {
            const s = rows[r].t.slice(from, to)
            return trim ? s.replace(/\s+$/, '') : s
          } }
        : undefined),
    }
    const term = {
      cols: 80, buffer: { active: buffer },
      registerMarker: () => ({ line: cursor.row, isDisposed: false, dispose() {} }),
    } as unknown as Terminal
    return { term, rows, cursor }
  }
  const block: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'block' }] }

  it('prompt normal: tastare pe acelaşi rând → nu e pierdut, regula prinde', () => {
    const { term, rows, cursor } = screen(['out', 'out', '% '], { row: 2, col: 2 })
    const tr = new CommandTracker(term)
    tr.handle('B')
    tr.notePromptPainted()
    rows[2].t = '% rm -rf /'; cursor.col = 10
    expect(tr.promptLost).toBe(false)
    expect(tr.lineKnown()).toBe(true)
    expect(tr.pendingCommand()).toBe('rm -rf /')
    expect(judgeLocal({ atPrompt: true, echoed: true, pending: tr.pendingCommand(), unechoed: [], lineLost: tr.promptLost }, block, true).kind).toBe('rule')
  })

  it('zsh Ctrl+L: ecranul şters pe loc, promptul redesenat SUS fără B nou → pierdut, „nu pot verifica"', () => {
    const { term, rows, cursor } = screen(['a', 'b', 'c', 'd', 'e', '% '], { row: 5, col: 2 })
    const tr = new CommandTracker(term)
    tr.handle('B')
    tr.notePromptPainted()
    // ED2 + redesenare: rândurile rescrise pe loc (markerul rămâne pe rândul 5), cursorul sus
    for (const r of rows) r.t = ''
    rows[0].t = '% rm -rf /'; cursor.row = 0; cursor.col = 10
    // logica din 222eae0: promptRow (5) > cursor (0) → linie goală → Enter neverificat
    expect(tr.promptLost).toBe(true)
    expect(tr.lineKnown()).toBe(false)
    expect(judgeLocal({ atPrompt: true, echoed: true, pending: tr.pendingCommand(), unechoed: [], lineLost: tr.promptLost }, block, true).kind).toBe('unknown')
  })

  it('regiune de scroll cu marginea de sus ≠ 1: conţinutul urcă, markerul nu → textul rândului s-a schimbat → pierdut', () => {
    const { term, rows, cursor } = screen(['status', 'x', '$ ', ''], { row: 2, col: 2 })
    const tr = new CommandTracker(term)
    tr.handle('B')
    tr.notePromptPainted()                          // „$ " reţinut
    rows[2].t = '$ rm -rf /srv/da'; rows[3] = { t: 'ta/old', w: true }; cursor.row = 3; cursor.col = 6
    expect(tr.promptLost).toBe(false)
    // derulare în regiune: rândul 2 primeşte continuarea, promptul urcă pe rândul 1 (fără evenimente)
    rows[1] = { t: '$ rm -rf /srv/da', w: false }; rows[2] = { t: 'ta/old', w: true }; rows[3] = { t: '', w: false }
    cursor.row = 2
    expect(tr.promptLost).toBe(true)
    expect(tr.lineKnown()).toBe(false)
  })

  it('ştergere de ecran / RIS în output după B, fără nicio tastă de verificat → pierdut; după B nou → bine', () => {
    const { term, cursor } = screen(['$ '], { row: 0, col: 2 })
    const tr = new CommandTracker(term)
    tr.handle('B')
    tr.noteScreenReset()
    expect(tr.promptLost).toBe(true)
    tr.handle('A'); cursor.col = 2; tr.handle('B')
    expect(tr.promptLost).toBe(false)
  })

  it('screenResetIn: ED2, ED3, RIS, DECSTBM cu marginea de sus > 1; nu SGR / DECSTBM 1;n', () => {
    const e = (s: string) => new TextEncoder().encode(s)
    for (const s of ['\x1b[2J', 'x\x1b[3J', '\x1bc', '\x1b[3;24r']) expect(screenResetIn(e(s)), JSON.stringify(s)).toBe(true)
    for (const s of ['\x1b[0m', '\x1b[1;23r', '\x1b[J', '\x1b[1J', 'plain', '\x1b[r']) expect(screenResetIn(e(s)), JSON.stringify(s)).toBe(false)
  })
})

// verificare 222eae0, L-b: rând plin urmat de un rând fără wrap — ambiguu, ambele variante verificate
describe('CommandTracker.pendingAlt: lipirea rândurilor', () => {
  function cellTerm(rowTexts: string[], wrapped: boolean[], cols: number, wide = false) {
    const buffer = {
      type: 'normal', baseY: 0, cursorY: rowTexts.length - 1,
      // la B (rândul 0) cursorul e la coloana 0; după, la capătul ultimului rând
      get cursorX() { return this.cursorY === 0 ? 0 : rowTexts[rowTexts.length - 1].length },
      getLine: (r: number) => (rowTexts[r] === undefined ? undefined : {
        length: cols, isWrapped: wrapped[r],
        translateToString: (_t: boolean, from = 0, to?: number) => rowTexts[r].slice(from, to),
        getCell: (x: number) => {
          if (wide && r === 0 && x >= cols - 2) return { getChars: () => (x === cols - 2 ? '字' : ''), getWidth: () => (x === cols - 2 ? 2 : 0) }
          return { getChars: () => rowTexts[r][x] ?? '', getWidth: () => 1 }
        },
      }),
    }
    let marker = 0
    return { buffer: { active: buffer }, cols, registerMarker: () => ({ line: marker++ === 0 ? 0 : 0, isDisposed: false, dispose() {} }) } as unknown as Terminal
  }
  it('rând plin (ultima celulă ocupată) + rând fără wrap → linia fără spaţiu ŞI varianta cu spaţiu', () => {
    const term = cellTerm(['aaaaaaaaaa', 'rm -rf /'], [false, false], 10)
    ;(term.buffer.active as unknown as { cursorY: number }).cursorY = 0
    const tr = new CommandTracker(term)
    tr.handle('B')
    ;(term.buffer.active as unknown as { cursorY: number }).cursorY = 1
    expect(tr.pendingCommand()).toBe('aaaaaaaaaarm -rf /')
    expect(tr.pendingAlt()).toBe('aaaaaaaaaa rm -rf /')
    const g: CommandGuard = { enabled: true, rules: [{ pattern: '\\brm\\s+-rf', action: 'block' }] }
    // doar varianta lipită ar rata `\brm`; verificarea ia verdictul mai strict
    expect(judgeLocal({ atPrompt: true, echoed: true, pending: tr.pendingCommand(), pendingAlt: tr.pendingAlt(), unechoed: [] }, g, true).kind).toBe('rule')
  })
  it('rând marcat isWrapped → fără ambiguitate; caracter lat pe ultimele celule = rând plin', () => {
    const t1 = cellTerm(['aaaaaaaaaa', 'bb'], [false, true], 10)
    ;(t1.buffer.active as unknown as { cursorY: number }).cursorY = 0
    const tr1 = new CommandTracker(t1)
    tr1.handle('B')
    ;(t1.buffer.active as unknown as { cursorY: number }).cursorY = 1
    expect(tr1.pendingAlt()).toBeNull()
    expect(tr1.pendingCommand()).toBe('aaaaaaaaaabb')
    const t2 = cellTerm(['aaaa字', 'x'], [false, false], 6, true)
    ;(t2.buffer.active as unknown as { cursorY: number }).cursorY = 0
    const tr2 = new CommandTracker(t2)
    tr2.handle('B')
    ;(t2.buffer.active as unknown as { cursorY: number }).cursorY = 1
    expect(tr2.pendingAlt()).toBe('aaaa字 x')
  })
})

// verificarea lui 2872ae6: textul de DUPĂ cursor, prompturi din dreapta, prefixul exact
describe('CommandTracker: linia până la capăt, RPROMPT, prefixul promptului', () => {
  function oneRow(initial: string, cursorCol: number, cols = 80) {
    const st = { t: initial, col: cursorCol }
    const buffer = {
      type: 'normal', baseY: 0, cursorY: 0,
      get cursorX() { return st.col },
      getLine: (r: number) => (r === 0 ? {
        length: cols, isWrapped: false,
        translateToString: (trim: boolean, from = 0, to?: number) => {
          const s = st.t.padEnd(cols).slice(from, to)
          return trim ? s.replace(/\s+$/, '') : s
        },
        getCell: (x: number) => ({ getChars: () => (st.t[x] ?? '').trim(), getWidth: () => 1 }),
      } : undefined),
    }
    const term = { cols, buffer: { active: buffer }, registerMarker: () => ({ line: 0, isDisposed: false, dispose() {} }) } as unknown as Terminal
    return { term, st }
  }
  const g: CommandGuard = { enabled: true, rules: [{ pattern: '^(sudo )?rm\\s+-rf', action: 'block' }] }
  const judge = (tr: CommandTracker) => judgeLocal({ atPrompt: true, echoed: true, pending: tr.pendingCommand(),
    pendingAlts: tr.pendingVariants(), unechoed: [], lineLost: tr.promptLost }, g, true).kind

  it('cursorul dus la coloana lui B (Home) după `rm -rf /x` → regula prinde (linia până la capăt)', () => {
    const { term, st } = oneRow('$ ', 2)
    const tr = new CommandTracker(term)
    tr.handle('B')
    tr.notePromptPainted()
    st.t = '$ rm -rf /x'; st.col = 2                  // Home: cursorul înapoi la începutul liniei
    // logica din 2872ae6: citit doar până la cursor → linie goală → Enter neverificat
    expect(tr.pendingCommand()).toBeNull()
    expect(tr.pendingVariants()).toContain('rm -rf /x')
    expect(judge(tr)).toBe('rule')
    st.t = '$ sudo rm -rf /x'; st.col = 7             // `sudo ` adăugat în faţă, cursorul la mijloc
    expect(tr.pendingCommand()).toBe('sudo')
    expect(judge(tr)).toBe('rule')
  })

  it('RPROMPT (zsh, ceas în dreapta): fără dialog fals, linia judecată fără el', () => {
    const { term, st } = oneRow('$ ' + ' '.repeat(60) + '10:42', 2)
    const tr = new CommandTracker(term)
    tr.handle('B')
    tr.notePromptPainted()
    st.t = '$ ls -la' + ' '.repeat(54) + '10:42'; st.col = 8
    expect(tr.promptLost).toBe(false)
    // citirea conservatoare (netăiată) e judecată mereu; RPROMPT-ul nu atinge regula → fără dialog
    expect(tr.pendingVariants().some((v) => v.startsWith('ls -la') && v.endsWith('10:42'))).toBe(true)
    expect(judge(tr)).toBe('ok')
  })

  it('sub tmux (B la coloana 0) cu RPROMPT: prefixul e doar promptul — tastarea nu-l „pierde"', () => {
    const { term, st } = oneRow('', 0)
    const tr = new CommandTracker(term)
    tr.handle('B')                                     // marcajul a sosit înaintea promptului pictat
    st.t = 'user@h:~$ ' + ' '.repeat(50) + '10:42'; st.col = 10
    tr.notePromptPainted()
    st.t = 'user@h:~$ make test' + ' '.repeat(41) + '10:42'; st.col = 19
    // logica din 2872ae6: tot rândul (cu „10:42") reţinut → după tastare nu mai „începe cu" → mereu pierdut
    expect(tr.promptLost).toBe(false)
    expect(judge(tr)).toBe('ok')
  })

  it('sub tmux, typeahead redesenat la prima tastă apoi şters → nu e pierdut', () => {
    const { term, st } = oneRow('', 0)
    const tr = new CommandTracker(term)
    tr.handle('B')
    st.t = 'root@h:/tmp# ls'; st.col = 15               // typeahead „ls" deja pe ecran la prima tastă
    tr.notePromptPainted()
    st.t = 'root@h:/tmp# '; st.col = 13                 // Ctrl+U
    expect(tr.promptLost).toBe(false)
  })

  it('prefix exact până la coloana lui B: alt prompt cu acelaşi „$" → pierdut', () => {
    const { term, st } = oneRow('a@h:~$ ', 7)
    const tr = new CommandTracker(term)
    tr.handle('B')
    tr.notePromptPainted()
    st.t = 'b@x:/$ ls'; st.col = 9
    expect(tr.promptLost).toBe(true)
  })

  it('spaţii finale multe pe rândul promptului nu fac linia „pierdută" (contiguitate în celule)', () => {
    const { term, st } = oneRow('$ ', 2)
    const tr = new CommandTracker(term)
    tr.handle('B')
    tr.notePromptPainted()
    st.t = '$ echo "a          "'; st.col = 21
    expect(tr.promptLost).toBe(false)
  })

  it('screenResetScan: o secvenţă ruptă între două bucăţi e găsită; una completă nu se numără de două ori', () => {
    const e = (s: string) => new TextEncoder().encode(s)
    let r = screenResetScan(new Uint8Array(0), e('out\x1b['))
    expect(r.hit).toBe(false)
    r = screenResetScan(r.carry, e('2Jmore'))
    expect(r.hit).toBe(true)
    r = screenResetScan(new Uint8Array(0), e('\x1b[2J\x1b]133;B\x07'))
    expect(r.hit).toBe(true)
    expect(r.carry.length).toBe(0)
    r = screenResetScan(r.carry, e('$ '))
    expect(r.hit).toBe(false)
    r = screenResetScan(new Uint8Array(0), e('x\x1b'))
    r = screenResetScan(r.carry, e('c'))
    expect(r.hit).toBe(true)
  })
})

// e2e 3.6.13 (după 2872ae6): sub tmux B soseşte înaintea textului pictat — poziţia lui poate fi pe
// rândul comenzii anterioare; prima tastă re-ancorează începutul liniei la cursor
describe('CommandTracker.notePromptPainted(reanchor)', () => {
  function rowsTerm(rows: string[], cursor: { row: number; col: number }) {
    const buffer = {
      type: 'normal', baseY: 0,
      get cursorY() { return cursor.row }, get cursorX() { return cursor.col },
      getLine: (r: number) => (rows[r] === undefined ? undefined : {
        length: 80, isWrapped: false,
        translateToString: (trim: boolean, from = 0, to?: number) => {
          const s = rows[r].padEnd(80).slice(from, to)
          return trim ? s.replace(/\s+$/, '') : s
        },
        getCell: (x: number) => ({ getChars: () => (rows[r][x] ?? '').trim(), getWidth: () => 1 }),
      }),
    }
    return { cols: 80, buffer: { active: buffer }, registerMarker: () => ({ line: cursor.row, isDisposed: false, dispose() {} }) } as unknown as Terminal
  }
  it('B pe rândul comenzii anterioare, promptul pictat două rânduri mai jos → re-ancorat, linia citită corect', () => {
    const rows = ['root@h:~# echo X', '', '']
    const cursor = { row: 0, col: 16 }
    const term = rowsTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')                                   // marcajul a sosit înaintea output-ului pictat
    rows[1] = 'X'; rows[2] = 'root@h:~# '; cursor.row = 2; cursor.col = 10
    expect(tr.promptLost).toBe(true)                 // fără re-ancorare: rândurile 0..2 nu sunt contigue
    tr.notePromptPainted(true)                       // prima tastă, nimic în aşteptare
    rows[2] = 'root@h:~# rm -rf /'; cursor.col = 18
    expect(tr.promptLost).toBe(false)
    expect(tr.pendingCommand()).toBe('rm -rf /')
  })
  it('typeahead în aşteptare → fără re-ancorare (rămâne „pierdut" → „nu pot verifica", fail-closed)', () => {
    const rows = ['root@h:~# make', 'ok', 'root@h:~# rm -rf']
    const cursor = { row: 0, col: 14 }
    const term = rowsTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')
    cursor.row = 2; cursor.col = 16
    tr.notePromptPainted(false)
    expect(tr.promptLost).toBe(true)
  })
})

// verificarea lui dcbf298: nicio euristică nu scoate text din ce se judecă — doar adaugă variante
describe('CommandTracker: citirea conservatoare (de la B-ul original, netăiată) e judecată mereu', () => {
  function rowsTerm(rows: string[], cursor: { row: number; col: number }) {
    const buffer = {
      type: 'normal', baseY: 0,
      get cursorY() { return cursor.row }, get cursorX() { return cursor.col },
      getLine: (r: number) => (rows[r] === undefined ? undefined : {
        length: 80, isWrapped: false,
        translateToString: (trim: boolean, from = 0, to?: number) => {
          const s = rows[r].padEnd(80).slice(from, to)
          return trim ? s.replace(/\s+$/, '') : s
        },
        getCell: (x: number) => ({ getChars: () => (rows[r][x] ?? '').trim(), getWidth: () => 1 }),
      }),
    }
    const markers: { line: number }[] = []
    return {
      cols: 80, buffer: { active: buffer },
      registerMarker: () => { const m = { line: cursor.row, isDisposed: false, dispose() {} }; markers.push(m); return m },
    } as unknown as Terminal
  }
  const g: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf\\s+/srv', action: 'block' }] }
  const judge = (tr: CommandTracker) => judgeLocal({ atPrompt: true, echoed: true, pending: tr.pendingCommand(),
    pendingAlts: tr.pendingVariants(), unechoed: [], lineLost: tr.promptLost }, g, true).kind

  it('zsh push-line / print -z: linia restaurată după prompt, cursorul la capăt → fără re-ancorare, regula prinde', () => {
    const rows = ['% rm -rf /srv']
    const cursor = { row: 0, col: 2 }
    const term = rowsTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')                                   // B după „% "
    cursor.col = 13                                  // linia restaurată, cursorul la capăt
    tr.notePromptPainted(true)                       // prima tastă, nimic în aşteptare
    // logica din be5f68b: re-ancorat după „/srv" → linie goală → Enter neverificat
    expect(tr.pendingCommand()).toBe('rm -rf /srv')
    expect(judge(tr)).toBe('rule')
  })

  it('sub tmux: linie restaurată după un B vechi (terminator + text) → fără re-ancorare (pierdut → „nu pot verifica")', () => {
    const rows = ['root@h:~# ls', 'a b', 'root@h:~# rm -rf /srv']
    const cursor = { row: 0, col: 12 }
    const term = rowsTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')                                   // B vechi, pe rândul comenzii anterioare
    cursor.row = 2; cursor.col = 21
    tr.notePromptPainted(true)
    expect(tr.promptLost).toBe(true)
    expect(judge(tr)).not.toBe('ok')
  })

  it('re-ancorarea legitimă (tmux, B vechi, prompt gol) păstrează citirea de la B-ul original printre variante', () => {
    const rows = ['root@h:~# echo X', 'X', 'root@h:~# ']
    const cursor = { row: 0, col: 16 }
    const term = rowsTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')
    cursor.row = 2; cursor.col = 10
    tr.notePromptPainted(true)
    rows[2] = 'root@h:~# rm -rf /srv'; cursor.col = 21
    expect(tr.promptLost).toBe(false)
    expect(tr.pendingCommand()).toBe('rm -rf /srv')
    expect(judge(tr)).toBe('rule')
  })

  it('cel mult o re-ancorare per B: snapshot gol la prima tastă, a doua tastă nu mai re-ancorează după „r"', () => {
    const rows = ['', '', '']
    const cursor = { row: 0, col: 0 }
    const term = rowsTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')
    cursor.row = 2; cursor.col = 0                   // PS1 terminat cu \n: rânduri goale, nimic de reţinut
    tr.notePromptPainted(true)
    rows[2] = 'r'; cursor.col = 1
    tr.notePromptPainted(true)                       // a doua tastă
    rows[2] = 'rm -rf /srv'; cursor.col = 11
    // logica din be5f68b: re-ancorat după „r" → „m -rf /srv"
    expect(tr.pendingCommand()).toBe('rm -rf /srv')
    expect(judge(tr)).toBe('rule')
  })

  it('RPROMPT=%~ (/srv/data), ↑ `rm -rf /srv/data`, Home, `sudo ` → citirea netăiată prinde regula', () => {
    const rows = ['% ' + ' '.repeat(60) + '/srv/data']
    const cursor = { row: 0, col: 2 }
    const term = rowsTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')
    tr.notePromptPainted(true)                        // RPROMPT „/srv/data" reţinut la coloana 62
    // zsh ascunde RPROMPT-ul cât linia e lungă; ↑ + Home + „sudo "
    rows[0] = '% sudo rm -rf /srv/data'; cursor.col = 7
    const v = tr.pendingVariants()
    // logica din dcbf298: capătul „/srv/data" era tăiat ca RPROMPT → „sudo rm -rf" → regula rata
    expect(v).toContain('sudo rm -rf /srv/data')
    expect(judge(tr)).toBe('rule')
  })

  it('text tastat lipit de cursor la prima tastă nu e luat drept RPROMPT', () => {
    const rows = ['$ ls -la']
    const cursor = { row: 0, col: 2 }
    const term = rowsTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')
    cursor.col = 4                                    // cursorul la mijlocul unui text existent
    tr.notePromptPainted(true)
    rows[0] = '$ ls -la /srv'; cursor.col = 13
    expect(tr.pendingVariants().concat(tr.pendingCommand() ?? '')).toContain('ls -la /srv')
  })
})

describe('CommandTracker: B vechi pe rândul comenzii anterioare (tmux)', () => {
  it('comanda anterioară `rm -rf /srv/old` NU intră în citirea conservatoare a comenzii următoare', () => {
    const rows = ['root@h:~# rm -rf /srv/old', '', 'root@h:~# ']
    const cursor = { row: 0, col: 25 }
    const buffer = {
      type: 'normal', baseY: 0,
      get cursorY() { return cursor.row }, get cursorX() { return cursor.col },
      getLine: (r: number) => (rows[r] === undefined ? undefined : {
        length: 80, isWrapped: false,
        translateToString: (trim: boolean, from = 0, to?: number) => {
          const s = rows[r].padEnd(80).slice(from, to)
          return trim ? s.replace(/\s+$/, '') : s
        },
        getCell: (x: number) => ({ getChars: () => (rows[r][x] ?? '').trim(), getWidth: () => 1 }),
      }),
    }
    const term = { cols: 80, buffer: { active: buffer },
      registerMarker: (off = 0) => ({ line: cursor.row + off, isDisposed: false, dispose() {} }) } as unknown as Terminal
    const tr = new CommandTracker(term)
    tr.handle('B')                                   // B vechi: pe rândul comenzii deja rulate
    cursor.row = 2; cursor.col = 10
    tr.notePromptPainted(true)
    rows[2] = 'root@h:~# ls'; cursor.col = 12
    const g: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf\\s+/', action: 'confirm' }] }
    const v = judgeLocal({ atPrompt: true, echoed: true, pending: tr.pendingCommand(), pendingAlts: tr.pendingVariants(), unechoed: [], lineLost: tr.promptLost }, g, true)
    expect(v.kind).toBe('ok')
    // citirea conservatoare a liniei curente: tot rândul ei, cu promptul, netăiat
    expect(tr.pendingVariants()).toContain('root@h:~# ls')
  })
})

// verificarea lui 1a3d058: citirea conservatoare după re-ancorarea pe gol, prompturi pe două rânduri,
// marcajul original dispărut
describe('CommandTracker: re-ancorarea pe gol (verificarea lui 1a3d058)', () => {
  function offTerm(rows: string[], cursor: { row: number; col: number }) {
    const buffer = {
      type: 'normal', baseY: 0,
      get cursorY() { return cursor.row }, get cursorX() { return cursor.col },
      getLine: (r: number) => (rows[r] === undefined ? undefined : {
        length: 80, isWrapped: false,
        translateToString: (trim: boolean, from = 0, to?: number) => {
          const s = rows[r].padEnd(80).slice(from, to)
          return trim ? s.replace(/\s+$/, '') : s
        },
        getCell: (x: number) => ({ getChars: () => (rows[r][x] ?? '').trim(), getWidth: () => 1 }),
      }),
    }
    const markers: { line: number; isDisposed: boolean; dispose(): void }[] = []
    const term = { cols: 80, buffer: { active: buffer },
      registerMarker: (off = 0) => {
        const m = { line: cursor.row + off, isDisposed: false, dispose() { m.isDisposed = true; m.line = -1 } }
        markers.push(m)
        return m
      } } as unknown as Terminal
    return { term, markers }
  }
  const g: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf\\s+/srv', action: 'block' }] }
  const judge = (tr: CommandTracker) => judgeLocal({ atPrompt: true, echoed: true, pending: tr.pendingCommand(),
    pendingAlts: tr.pendingVariants(), unechoed: [], lineLost: tr.promptLost }, g, true).kind

  it('M1: buffer restaurat pe două rânduri, prompt fără terminator → regula prinde comanda de pe primul rând', () => {
    const rows = ['root@h:~# echo X', '', '']
    const cursor = { row: 0, col: 16 }
    const { term } = offTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')                                   // B vechi, pe rândul comenzii anterioare
    rows[1] = '➜  ~ rm -rf /srv'                // prompt fără terminator ($ # % > ❯) + rândul 1
    rows[2] = 'echo done'; cursor.row = 2; cursor.col = 9
    tr.notePromptPainted(true)                       // re-ancorat la cursor (gol, fără text restaurat)
    // logica din 1a3d058: citirea conservatoare pornea de la blocul cursorului → doar „echo done"
    expect(tr.pendingVariants().some((v) => v.includes('rm -rf /srv'))).toBe(true)
    expect(judge(tr)).toBe('rule')
  })

  it('LOW-1: prompt pe două rânduri cu `%` şi `>` urmate de text pe primul rând → re-ancorat, nu „nu pot verifica"', () => {
    const rows = ['', '']
    const cursor = { row: 0, col: 0 }
    const { term } = offTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')                                   // sub tmux: B la coloana 0, înaintea textului pictat
    rows[0] = 'stefan@h % ~/src > main'
    rows[1] = '❯ '; cursor.row = 1; cursor.col = 2
    tr.notePromptPainted(true)
    expect(tr.promptLost).toBe(false)
    rows[1] = '❯ rm -rf /srv'; cursor.col = 13
    expect(tr.promptLost).toBe(false)
    expect(tr.pendingCommand()).toBe('rm -rf /srv')
    expect(judge(tr)).toBe('rule')
    // citirea conservatoare (de la B-ul original, rândul lui inclus, netăiată) rămâne printre variante
    expect([tr.pendingCommand(), ...tr.pendingVariants()].map((v) => (v ?? '').replace(/\s+/g, ' '))).toContain('stefan@h % ~/src > main ❯ rm -rf /srv')
  })

  it('LOW-1: cu B la coloana 0, textul restaurat în blocul cursorului tot opreşte re-ancorarea (fail-closed)', () => {
    const rows = ['', '']
    const cursor = { row: 0, col: 0 }
    const { term } = offTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')
    rows[0] = 'stefan@h ~/src'
    rows[1] = '% rm -rf /srv'; cursor.row = 1; cursor.col = 13
    tr.notePromptPainted(true)
    expect(tr.promptLost).toBe(true)
    expect(judge(tr)).not.toBe('ok')
  })

  it('LOW-2: marcajul citirii conservatoare dispărut, poziţia de citire vie → pierdut („nu pot verifica")', () => {
    const rows = ['root@h:~# echo X', 'X', 'root@h:~# ']
    const cursor = { row: 0, col: 16 }
    const { term, markers } = offTerm(rows, cursor)
    const tr = new CommandTracker(term)
    tr.handle('B')
    cursor.row = 2; cursor.col = 10
    tr.notePromptPainted(true)
    rows[2] = 'root@h:~# ls'; cursor.col = 12
    expect(tr.promptLost).toBe(false)
    const orig = markers[0]                          // marcajul lui B (citirea conservatoare)
    expect(orig.line).toBe(0)
    orig.isDisposed = true                           // scrollback tăiat sub rândul conservator
    expect(tr.promptLostReason()).toBe('orig-gone')
    expect(judge(tr)).not.toBe('ok')
  })
})

// verificarea lui 512c42f: citirea conservatoare porneşte MEREU de la B-ul original; continuări PS2
describe('CommandTracker: citirea conservatoare de la B, continuări PS2 (verificarea lui 512c42f)', () => {
  function offTerm(rows: string[], cursor: { row: number; col: number }) {
    const buffer = {
      type: 'normal', baseY: 0,
      get cursorY() { return cursor.row }, get cursorX() { return cursor.col },
      getLine: (r: number) => (rows[r] === undefined ? undefined : {
        length: 80, isWrapped: false,
        translateToString: (trim: boolean, from = 0, to?: number) => {
          const s = rows[r].padEnd(80).slice(from, to)
          return trim ? s.replace(/\s+$/, '') : s
        },
        getCell: (x: number) => ({ getChars: () => (rows[r][x] ?? '').trim(), getWidth: () => 1 }),
      }),
    }
    return { cols: 80, buffer: { active: buffer },
      registerMarker: (off = 0) => {
        const m = { line: cursor.row + off, isDisposed: false, dispose() { m.isDisposed = true; m.line = -1 } }
        return m
      } } as unknown as Terminal
  }
  const block: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf\\s+/srv', action: 'block' }] }
  const confirm: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf\\s+/', action: 'confirm' }] }
  const judge = (tr: CommandTracker, g: CommandGuard = block) => judgeLocal({ atPrompt: true, echoed: true,
    pending: tr.pendingCommand(), pendingAlts: tr.pendingVariants(), unechoed: [], lineLost: tr.promptLost }, g, true).kind

  it('M1: zsh — B la coloana 0 a rândului promptului, buffer restaurat pe două rânduri → regula prinde', () => {
    const rows = ['', '']
    const cursor = { row: 0, col: 0 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')                                   // precmd: B la coloana 0, înaintea promptului
    rows[0] = 'host% rm -rf /srv'                    // push-line / print -z $'rm -rf /srv\nls'
    rows[1] = 'ls'; cursor.row = 1; cursor.col = 2   // End
    tr.notePromptPainted(true)
    // logica din 512c42f: re-ancorat, citirea conservatoare de la rândul 1 → „ls" / '' → Enter fără dialog
    expect([tr.pendingCommand() ?? '', ...tr.pendingVariants()].some((v) => v.includes('rm -rf /srv'))).toBe(true)
    expect(judge(tr)).toBe('rule')
    expect(judge(tr, confirm)).not.toBe('ok')
  })

  it('M1: print -z — B după `host% `, buffer restaurat pe două rânduri → re-ancorat, regula prinde tot', () => {
    const rows = ['host% ', '']
    const cursor = { row: 0, col: 6 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')
    rows[0] = 'host% rm -rf /srv'
    rows[1] = 'ls'; cursor.row = 1; cursor.col = 2
    tr.notePromptPainted(true)
    expect([tr.pendingCommand(), ...tr.pendingVariants()].map((v) => (v ?? '').replace(/\s+/g, ' '))).toContain('rm -rf /srv ls')
    expect(judge(tr)).toBe('rule')
    expect(judge(tr, confirm)).toBe('rule')
  })

  it('cazul normal: B proaspăt, corect plasat după comanda anterioară `rm -rf /srv/old` → `ls` fără dialog', () => {
    const rows = ['root@h:~# rm -rf /srv/old', 'root@h:~# ']
    const cursor = { row: 1, col: 10 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')
    tr.notePromptPainted(true)
    rows[1] = 'root@h:~# ls'; cursor.col = 12
    expect(tr.promptLost).toBe(false)
    expect(judge(tr, confirm)).toBe('ok')
  })

  function ps2(lines: string[], g: CommandGuard = block) {
    const rows = ['$ ']
    const cursor = { row: 0, col: 2 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')
    tr.notePromptPainted(true)
    rows[0] = '$ ' + lines[0]; cursor.col = rows[0].length
    const verdicts: string[] = []
    for (let i = 1; i < lines.length; i++) {
      verdicts.push(judge(tr, g))                    // Enter pe rândul curent: verdictul de dinainte
      tr.noteSubmitSent()                            // Enter-ul a plecat; shell-ul afişează PS2
      rows[i] = '> ' + lines[i]; cursor.row = i; cursor.col = rows[i].length
    }
    verdicts.push(judge(tr, g))
    return { tr, verdicts }
  }

  it('M2: buclă `for` pe 3 rânduri → nici „nu pot verifica", nici dialog', () => {
    const { tr, verdicts } = ps2(['for i in 1 2; do', 'echo $i', 'done'], confirm)
    expect(tr.promptLost).toBe(false)
    expect(verdicts).toEqual(['ok', 'ok', 'ok'])
  })

  it('M2: heredoc şi continuare cu `\\` → fără dialog', () => {
    expect(ps2(['cat <<EOF', 'hello', 'EOF'], confirm).verdicts).toEqual(['ok', 'ok', 'ok'])
    expect(ps2(['echo a \\', 'b'], confirm).verdicts).toEqual(['ok', 'ok'])
  })

  it('M2: `rm -rf /srv` pe un rând de continuare → regula prinde (buclă, heredoc, `\\`)', () => {
    expect(ps2(['for i in 1 2; do', 'rm -rf /srv', 'done']).verdicts.slice(1)).toEqual(['rule', 'rule'])
    expect(ps2(['sh <<EOF', 'rm -rf /srv', 'EOF']).verdicts.slice(1)).toEqual(['rule', 'rule'])
    expect(ps2(['echo a \\', 'rm -rf /srv']).verdicts).toEqual(['ok', 'rule'])
  })

  it('M2: fără Enter trimis, golul rămâne „pierdut"; un C + B nou şterge starea de continuare', () => {
    const rows = ['$ ']
    const cursor = { row: 0, col: 2 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')
    tr.notePromptPainted(true)
    rows[0] = '$ for i in 1 2; do'; cursor.col = 18
    rows[1] = '> echo $i'; cursor.row = 1; cursor.col = 9
    expect(tr.promptLost).toBe(true)                 // nimic trimis: rândurile nu sunt ale liniei
    tr.noteSubmitSent()
    expect(tr.promptLost).toBe(false)
    tr.handle('C'); tr.handle('D;0')
    rows[2] = '1'; rows[3] = '$ '; cursor.row = 3; cursor.col = 2
    tr.handle('B')
    rows[4] = 'x'; cursor.row = 4; cursor.col = 1   // B nou, apoi un rând care nu continuă linia
    expect(tr.promptLost).toBe(true)
  })
})

// verificarea lui 2806021: rândurile de SUB linia cursorului (buffer pe mai multe rânduri) şi plafonul
describe('CommandTracker: rândurile de sub cursor, plafonul liniei (verificarea lui 2806021)', () => {
  function offTerm(rows: string[], cursor: { row: number; col: number }) {
    const buffer = {
      type: 'normal', baseY: 0,
      get cursorY() { return cursor.row }, get cursorX() { return cursor.col },
      getLine: (r: number) => (rows[r] === undefined ? undefined : {
        length: 80, isWrapped: false,
        translateToString: (trim: boolean, from = 0, to?: number) => {
          const s = rows[r].padEnd(80).slice(from, to)
          return trim ? s.replace(/\s+$/, '') : s
        },
        getCell: (x: number) => ({ getChars: () => (rows[r][x] ?? '').trim(), getWidth: () => 1 }),
      }),
    }
    return { cols: 80, rows: 24, buffer: { active: buffer },
      registerMarker: (off = 0) => {
        const m = { line: cursor.row + off, isDisposed: false, dispose() { m.isDisposed = true; m.line = -1 } }
        return m
      } } as unknown as Terminal
  }
  const block: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf\\s+/srv', action: 'block' }] }
  const confirm: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf\\s+/', action: 'confirm' }] }
  const judge = (tr: CommandTracker, g: CommandGuard) => judgeLocal({ atPrompt: true, echoed: true,
    pending: tr.pendingCommand(), pendingAlts: tr.pendingVariants(), pendingBelow: tr.pendingBelow(), unechoed: [], lineLost: tr.promptLost }, g, true).kind

  it('zsh ↑ recheamă `cd /srv` + newline + `rm -rf /srv/data`, ↑ din nou (cursorul pe rândul 1) → regula prinde', () => {
    const rows = ['% ', '', '', '']
    const cursor = { row: 0, col: 2 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')
    tr.notePromptPainted(true)                       // ↑
    rows[0] = '% cd /srv'; rows[1] = 'rm -rf /srv/data'; cursor.row = 1; cursor.col = 16
    cursor.row = 0; cursor.col = 9                   // ↑ din nou: up-line-or-history urcă în buffer
    // logica din 2806021: toate citirile se opreau la capătul rândului cursorului → „cd /srv" → ok
    expect(tr.promptLost).toBe(false)
    expect(judge(tr, block)).toBe('rule')
    expect(judge(tr, confirm)).toBe('rule')
  })

  it('buffer Ctrl+V Ctrl+J (newline literal), cursorul pe primul rând → regula prinde rândul de dedesubt', () => {
    const rows = ['% ', '', '']
    const cursor = { row: 0, col: 2 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')
    tr.notePromptPainted(true)
    rows[0] = '% ls'; rows[1] = 'rm -rf /srv/data'; cursor.row = 0; cursor.col = 4
    expect(judge(tr, confirm)).toBe('rule')
  })

  it('prompt normal pe un rând, rânduri goale dedesubt → fără dialog', () => {
    const rows = ['root@h:~# rm -rf /srv/old', 'root@h:~# ', '', '', '']
    const cursor = { row: 1, col: 10 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')
    tr.notePromptPainted(true)
    rows[1] = 'root@h:~# ls -la'; cursor.col = 16
    expect(tr.promptLost).toBe(false)
    expect(judge(tr, confirm)).toBe('ok')
  })

  it('LOW: linia continuă peste plafonul de 50 de rânduri după cursor → necunoscut, nu tăiat', () => {
    const full = 'a'.repeat(80)
    const rows = ['$ ' + 'a'.repeat(78), ...Array.from({ length: 51 }, () => full), 'rm -rf /srv']
    const cursor = { row: 0, col: 2 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')
    tr.notePromptPainted(true)
    expect(tr.promptLostReason()).toMatch(/^too-long/)
    expect(judge(tr, confirm)).not.toBe('ok')
  })

  it('LOW: sub plafon (49 de rânduri de continuare) → linia se citeşte întreagă', () => {
    const full = 'a'.repeat(80)
    const rows = ['$ ' + 'a'.repeat(78), ...Array.from({ length: 48 }, () => full), 'a rm -rf /srv']
    const cursor = { row: 0, col: 2 }
    const tr = new CommandTracker(offTerm(rows, cursor))
    tr.handle('B')
    tr.notePromptPainted(true)
    expect(tr.promptLost).toBe(false)
    expect(judge(tr, block)).toBe('rule')
  })
})

// verificarea lui c9321d9: textul de SUB cursor doar confirmă (niciodată block / Ctrl+U); margini şi bara tmux
describe('CommandTracker.pendingBelow: textul de sub linia cursorului (verificarea lui c9321d9)', () => {
  function bgTerm(rows: string[], cursor: { row: number; col: number }, statusRows: number[]) {
    const buffer = {
      type: 'normal', baseY: 0,
      get cursorY() { return cursor.row }, get cursorX() { return cursor.col },
      getLine: (r: number) => (rows[r] === undefined ? undefined : {
        length: 80, isWrapped: false,
        translateToString: (trim: boolean, from = 0, to?: number) => {
          const s = rows[r].padEnd(80).slice(from, to)
          return trim ? s.replace(/\s+$/, '') : s
        },
        getCell: (x: number) => ({
          getChars: () => (rows[r][x] ?? '').trim(), getWidth: () => 1,
          isBgDefault: () => !statusRows.includes(r), getBgColor: () => (statusRows.includes(r) ? 2 : 0), getBgColorMode: () => 1,
        }),
      }),
    }
    return { cols: 80, rows: rows.length, buffer: { active: buffer },
      registerMarker: (off = 0) => {
        const m = { line: cursor.row + off, isDisposed: false, dispose() { m.isDisposed = true; m.line = -1 } }
        return m
      } } as unknown as Terminal
  }
  const verdict = (tr: CommandTracker, g: CommandGuard) => judgeLocal({ atPrompt: true, echoed: true,
    pending: tr.pendingCommand(), pendingAlts: tr.pendingVariants(), pendingBelow: tr.pendingBelow(), unechoed: [],
    lineLost: tr.promptLost }, g, true)
  const block = (pattern: string): CommandGuard => ({ enabled: true, rules: [{ pattern, action: 'block' }] })
  /** B după „% " pe rândul 0, prima tastă, apoi ecranul `rows` cu cursorul la capătul rândului 0 */
  function at(rows: string[], statusRows: number[] = [], tmux = false) {
    const cursor = { row: 0, col: 2 }
    const shown = rows.slice()
    rows.fill('')
    rows[0] = '% '
    const tr = new CommandTracker(bgTerm(rows, cursor, statusRows))
    tr.tmuxBacked = tmux
    tr.handle('B')
    tr.notePromptPainted(true)
    shown.forEach((t, i) => { rows[i] = t })
    cursor.col = shown[0].length
    return tr
  }

  it('lista de completare zsh sub o comandă inofensivă: o regulă BLOCK devine doar confirmare (below), fără block', () => {
    const tr = at(['% mkdir x', 'mkfs       mkfs.ext4  mkdir      mkfifo', ''])
    const v = verdict(tr, block('\\bmkfs\\b'))
    expect(v.kind).toBe('rule')
    if (v.kind !== 'rule') return
    expect(v.rule.action).toBe('confirm')
    expect(v.below).toBe(true)
    expect(v.cmd).toContain('mkfs')
  })

  it('o potrivire şi în citirea normală îşi păstrează verdictul (block rămâne block)', () => {
    const tr = at(['% mkfs /dev/sdb', 'mkfs       mkfs.ext4', ''])
    const v = verdict(tr, block('\\bmkfs\\b'))
    expect(v.kind === 'rule' && v.rule.action).toBe('block')
    expect(v.kind === 'rule' && v.below).toBeFalsy()
  })

  it('buffer pe mai multe rânduri cu un rând GOL între `cd /srv` şi `rm -rf /srv/data`, cursorul pe rândul 1 → prins (confirmare)', () => {
    const tr = at(['% cd /srv', '', 'rm -rf /srv/data', ''])
    const v = verdict(tr, block('rm\\s+-rf\\s+/srv'))
    expect(v.kind).toBe('rule')
    expect(v.kind === 'rule' && v.below).toBe(true)
  })

  it('split tmux orizontal: rândurile de sub marginea panoului nu intră', () => {
    const tr = at(['% ls', '', '─'.repeat(80), 'DROP TABLE users; rm -rf /srv/data', ''])
    expect(tr.pendingBelow()).toEqual([])
    expect(verdict(tr, block('rm\\s+-rf\\s+/srv')).kind).toBe('ok')
    // margine cu joncţiune (┼) — tot margine
    const tr2 = at(['% ls', '─'.repeat(30) + '┼' + '─'.repeat(49), 'rm -rf /srv/data'])
    expect(verdict(tr2, block('rm\\s+-rf\\s+/srv')).kind).toBe('ok')
  })

  it('bara de stare tmux (ultimul rând, fundal uniform nedefault) nu intră — doar într-o sesiune tmux', () => {
    const screen = ['% ls', '', '', '[0] 0:rm -rf /srv/data*                     "host" 12:00']
    expect(verdict(at(screen.slice(), [3], true), block('rm\\s+-rf\\s+/srv')).kind).toBe('ok')
    // fără tmux sau fără stilul barei rândul rămâne: doar o confirmare în plus
    const v = verdict(at(screen.slice(), [3], false), block('rm\\s+-rf\\s+/srv'))
    expect(v.kind === 'rule' && v.rule.action).toBe('confirm')
    const v2 = verdict(at(screen.slice(), [], true), block('rm\\s+-rf\\s+/srv'))
    expect(v2.kind === 'rule' && v2.rule.action).toBe('confirm')
  })

  it('L1 (5336911): `────` tastat într-un heredoc (mai scurt decât panoul) NU opreşte citirea — rândul rm e prins', () => {
    const tr = at(['% cat <<EOF', '─'.repeat(20), 'EOF', 'rm -rf /srv/data', ''])
    const v = verdict(tr, block('rm\\s+-rf\\s+/srv'))
    expect(v.kind).toBe('rule')
    expect(v.kind === 'rule' && v.rule.action).toBe('confirm')
    expect(v.kind === 'rule' && v.below).toBe(true)
    // şi un rând de chenar care nu începe la coloana 0 (indentat) nu e margine de panou
    const tr2 = at(['% cat <<EOF', '  ' + '─'.repeat(78), 'EOF', 'rm -rf /srv/data'])
    expect(verdict(tr2, block('rm\\s+-rf\\s+/srv')).kind).toBe('rule')
  })

  it('isPaneBorder: doar pe toată lăţimea panoului, de la coloana 0, fără spaţii', () => {
    expect(isPaneBorder('─'.repeat(80), 80)).toBe(true)
    expect(isPaneBorder('─'.repeat(40) + '┬' + '─'.repeat(39), 80)).toBe(true)
    expect(isPaneBorder('─'.repeat(79), 80)).toBe(false)
    expect(isPaneBorder(' ' + '─'.repeat(79), 80)).toBe(false)
    expect(isPaneBorder('─'.repeat(39) + ' ' + '─'.repeat(40), 80)).toBe(false)
  })

  it('prompt pe un rând, nimic dedesubt → fără citire de dedesubt', () => {
    expect(at(['% ls', '', '', '']).pendingBelow()).toEqual([])
  })
})

// hotfix 3.6.17: cheia de ecou citeşte linia EXACT (cu spaţiul de la capăt); comanda judecată rămâne cu trim
describe('CommandTracker.typedLine: linia exactă, cu spaţiul de la capăt', () => {
  function termWith(text: string) {
    const buffer = {
      type: 'normal', baseY: 0, cursorY: 0, cursorX: text.length,
      getLine: (r: number) => (r === 0
        ? { length: 80, isWrapped: false, translateToString: (_t: boolean, from = 0, to?: number) => text.slice(from, to) }
        : undefined),
    }
    return { term: { cols: 80, buffer: { active: buffer }, registerMarker: () => ({ line: 0, isDisposed: false, dispose() {} }) } as unknown as Terminal, buffer }
  }
  it('„rm -rf ␣": typedLine păstrează spaţiul, pendingCommand nu', () => {
    const { term, buffer } = termWith('$ ')
    const tr = new CommandTracker(term)
    tr.handle('B')                                           // B la coloana 2
    const t2 = termWith('$ rm -rf ')
    ;(term as unknown as { buffer: { active: unknown } }).buffer.active = t2.buffer
    expect(tr.typedLine()).toBe('rm -rf ')
    expect(tr.pendingCommand()).toBe('rm -rf')
    void buffer
  })
  it('fără prompt / pe ecranul alternativ: null, ca pendingCommand', () => {
    const { term } = termWith('$ ')
    const tr = new CommandTracker(term)
    expect(tr.typedLine()).toBeNull()
    tr.handle('B')
    ;(term.buffer.active as unknown as { type: string }).type = 'alternate'
    expect(tr.typedLine()).toBeNull()
    expect(tr.pendingCommand()).toBeNull()
  })
})
