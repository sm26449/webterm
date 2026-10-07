import { describe, expect, it } from 'vitest'
import { isOverflowing, menuNav, showAllTabsButton, tabState } from './tablist'

describe('isOverflowing', () => {
  it('conţinut mai lat decât zona = overflow; rotunjirea sub-pixel nu contează', () => {
    expect(isOverflowing(800, 390)).toBe(true)
    expect(isOverflowing(390, 390)).toBe(false)
    expect(isOverflowing(391, 390)).toBe(false)
    expect(isOverflowing(392, 390)).toBe(true)
  })
})

describe('showAllTabsButton', () => {
  it('pe telefon mereu (când există taburi), altfel doar la overflow', () => {
    expect(showAllTabsButton(1, true, false)).toBe(true)
    expect(showAllTabsButton(3, false, false)).toBe(false)
    expect(showAllTabsButton(12, false, true)).toBe(true)
    expect(showAllTabsButton(0, true, true)).toBe(false)
  })
})

describe('tabState', () => {
  it('vie / pierdută / închisă cu eroare / închisă normal', () => {
    expect(tabState({ state: 'active' }, true)).toBe('live')
    expect(tabState({ state: 'lost' }, false)).toBe('lost')
    expect(tabState({ state: 'closed', exit_status: 2 }, false)).toBe('failed')
    expect(tabState({ state: 'closed', exit_status: 0 }, false)).toBe('closed')
    expect(tabState({ state: 'closed', exit_status: null }, false)).toBe('closed')
  })
})

describe('menuNav (WAI-ARIA menu)', () => {
  it('↓/↑ cu wrap, Home/End la capete, restul tastelor nu mută focusul', () => {
    expect(menuNav('ArrowDown', 0, 4)).toBe(1)
    expect(menuNav('ArrowDown', 3, 4)).toBe(0)
    expect(menuNav('ArrowUp', 0, 4)).toBe(3)
    expect(menuNav('Home', 2, 4)).toBe(0)
    expect(menuNav('End', 0, 4)).toBe(3)
    expect(menuNav('a', 1, 4)).toBeNull()
  })

  it('fără item focalizat: ↓ = primul, ↑ = ultimul; meniu gol = nimic', () => {
    expect(menuNav('ArrowDown', -1, 4)).toBe(0)
    expect(menuNav('ArrowUp', -1, 4)).toBe(3)
    expect(menuNav('ArrowDown', 0, 0)).toBeNull()
  })
})
