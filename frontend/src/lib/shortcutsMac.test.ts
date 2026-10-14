import { describe, expect, it } from 'vitest'
import { altLetter } from './shortcuts'

// review independent 3.6.12 (L8): pe macOS Option+M / Option+X TASTEAZĂ „µ" / „≈" — scurtătura de
// split nu are voie să le fure din shell.
const ev = (code: string, key: string, o: Partial<KeyboardEvent> = {}) =>
  ({ code, key, altKey: true, metaKey: false, ctrlKey: false, shiftKey: false, ...o }) as KeyboardEvent

describe('altLetter (Alt+M / Alt+X în split)', () => {
  it('Linux/Windows: pe code (merge şi pe layout-uri non-latine)', () => {
    expect(altLetter(ev('KeyM', 'm'), 'm', false)).toBe(true)
    expect(altLetter(ev('KeyM', 'ь'), 'm', false)).toBe(true)
    expect(altLetter(ev('KeyX', 'x'), 'x', false)).toBe(true)
  })

  it('macOS: Option care tastează un caracter („µ", „≈") NU e scurtătură', () => {
    expect(altLetter(ev('KeyM', 'µ'), 'm', true)).toBe(false)
    expect(altLetter(ev('KeyX', '≈'), 'x', true)).toBe(false)
  })

  it('macOS: Option ca Meta (tasta produce litera simplă) → scurtătură', () => {
    expect(altLetter(ev('KeyM', 'm'), 'm', true)).toBe(true)
    expect(altLetter(ev('KeyX', 'x'), 'x', true)).toBe(true)
  })

  it('cu Shift / Ctrl / Meta sau fără Alt → nu', () => {
    expect(altLetter(ev('KeyM', 'M', { shiftKey: true }), 'm', false)).toBe(false)
    expect(altLetter(ev('KeyM', 'm', { ctrlKey: true }), 'm', false)).toBe(false)
    expect(altLetter(ev('KeyM', 'm', { metaKey: true }), 'm', false)).toBe(false)
    expect(altLetter(ev('KeyM', 'm', { altKey: false }), 'm', false)).toBe(false)
  })
})
