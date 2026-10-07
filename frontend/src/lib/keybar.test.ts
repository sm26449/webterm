import { afterEach, describe, expect, it } from 'vitest'
import {
  KEYBAR_EXPANDED_KEY, ROW1, ROW2, SHORT_VIEWPORT_PX, SHORT_VIEWPORT_QUERY,
  keybarLayout, keybarRows, readKeybarExpanded, writeKeybarExpanded,
} from './keybar'

const labels = (ks: { label: string }[]) => ks.map((k) => k.label)
const g = globalThis as unknown as { window?: unknown }
afterEach(() => { delete g.window })

describe('keybarRows (ce tastă pe ce rând)', () => {
  it('rândul 1 = esenţialele: Esc, Tab, săgeţi (Ctrl/Alt sunt modificatorii, randaţi separat)', () => {
    expect(labels(ROW1)).toEqual(['Esc', 'Tab', '↑', '↓', '←', '→'])
  })

  it('rândul 2 = restul setului existent, fără nicio tastă pierdută sau dublată', () => {
    const all = [...labels(ROW1), ...labels(ROW2)]
    expect(new Set(all).size).toBe(all.length)
    for (const k of ['^C', '^D', '^Z', '^R', '|', '/', '-', '~', 'Home', 'End', 'PgUp', 'PgDn', '⇞', '⇟']) {
      expect(labels(ROW2)).toContain(k)
    }
    expect(all).toHaveLength(20)
  })

  it('secvenţele rămân cele de xterm (nu s-a schimbat decât aşezarea)', () => {
    const seq = Object.fromEntries([...ROW1, ...ROW2].map((k) => [k.label, k.seq]))
    expect(seq.Esc).toBe('\x1b')
    expect(seq.Tab).toBe('\t')
    expect(seq['↑']).toBe('\x1b[A')
    expect(seq['→']).toBe('\x1b[C')
    expect(seq.Home).toBe('\x1b[H')
    expect(seq.End).toBe('\x1b[F')
    expect(seq.PgUp).toBe('\x1b[5~')
    expect(seq.PgDn).toBe('\x1b[6~')
    expect(seq['^C']).toBe('\x03')
    expect(seq['^R']).toBe('\x12')
  })

  it('⇞/⇟ (rotiţă tmux) doar pe backend tmux — pe pty ar ajunge gunoi în shell', () => {
    expect(labels(keybarRows('tmux').row2)).toContain('⇞')
    expect(labels(keybarRows('pty').row2)).not.toContain('⇞')
    expect(labels(keybarRows(null).row2)).not.toContain('⇟')
    expect(keybarRows('pty').row1).toHaveLength(6)
  })
})

describe('keybarLayout (câte rânduri)', () => {
  it('viewport înalt: mereu 2 rânduri, fără comutator (preferinţa nu contează)', () => {
    expect(keybarLayout(false, false)).toEqual({ rows: 2, toggle: false })
    expect(keybarLayout(false, true)).toEqual({ rows: 2, toggle: false })
  })

  it('viewport scund (peisaj): 1 rând implicit + comutator; extins = 2', () => {
    expect(keybarLayout(true, false)).toEqual({ rows: 1, toggle: true })
    expect(keybarLayout(true, true)).toEqual({ rows: 2, toggle: true })
  })

  it('pragul de „scund" e ~420px, sub peisajul unui telefon şi peste orice portret', () => {
    expect(SHORT_VIEWPORT_PX).toBe(420)
    expect(SHORT_VIEWPORT_QUERY).toBe('(max-height: 419.98px)')
  })
})

describe('preferinţa extins/strâns (per dispozitiv)', () => {
  it('se citeşte/scrie în localStorage; lipsă = strâns', () => {
    const store: Record<string, string> = {}
    g.window = { localStorage: {
      getItem: (k: string) => store[k] ?? null,
      setItem: (k: string, v: string) => { store[k] = v },
    } }
    expect(readKeybarExpanded()).toBe(false)
    writeKeybarExpanded(true)
    expect(store[KEYBAR_EXPANDED_KEY]).toBe('1')
    expect(readKeybarExpanded()).toBe(true)
    writeKeybarExpanded(false)
    expect(readKeybarExpanded()).toBe(false)
  })

  it('storage blocat (Safari privat): nu aruncă, cade pe strâns', () => {
    g.window = { get localStorage(): Storage { throw new Error('SecurityError') } }
    expect(readKeybarExpanded()).toBe(false)
    expect(() => writeKeybarExpanded(true)).not.toThrow()
  })
})
