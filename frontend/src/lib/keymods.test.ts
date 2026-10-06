import { describe, expect, it } from 'vitest'
import { applyMods } from './keymods'

describe('applyMods (keybar tactil)', () => {
  it('fără modificatori: secvenţa neschimbată', () => {
    expect(applyMods('\x1b[A', false, false)).toBe('\x1b[A')
    expect(applyMods('|', false, false)).toBe('|')
  })

  it('Ctrl maschează un caracter mascabil', () => {
    expect(applyMods('c', true, false)).toBe('\x03')
    expect(applyMods('/', true, false)).toBe('/')          // sub '@' → nemascabil
  })

  it('Alt prefixează cu ESC; Ctrl+Alt = ESC + caracter de control', () => {
    expect(applyMods('-', false, true)).toBe('\x1b-')
    expect(applyMods('r', true, true)).toBe('\x1b\x12')
    expect(applyMods('\x1b', false, true)).toBe('\x1b\x1b')
  })

  it('săgeţi/Home/End primesc parametrul xterm de modificator', () => {
    expect(applyMods('\x1b[A', false, true)).toBe('\x1b[1;3A')   // Alt+↑
    expect(applyMods('\x1b[D', true, false)).toBe('\x1b[1;5D')   // Ctrl+←
    expect(applyMods('\x1b[H', true, true)).toBe('\x1b[1;7H')    // Ctrl+Alt+Home
  })

  it('PgUp/PgDn: forma cu tildă', () => {
    expect(applyMods('\x1b[5~', true, false)).toBe('\x1b[5;5~')
    expect(applyMods('\x1b[6~', false, true)).toBe('\x1b[6;3~')
  })
})
