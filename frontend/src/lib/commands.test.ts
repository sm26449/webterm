import { describe, expect, it } from 'vitest'
import type { Terminal } from '@xterm/xterm'
import { CommandTracker, splitAfterMarks } from './commands'

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
