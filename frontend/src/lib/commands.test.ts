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
