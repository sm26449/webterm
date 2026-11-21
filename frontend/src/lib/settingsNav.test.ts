import { describe, expect, it } from 'vitest'
import { escapeAction, initialPhoneScreen, railKeyTarget, railTabStop, settingsLayout } from './settingsNav'

describe('initialPhoneScreen', () => {
  it('o ţintă explicită aterizează în categorie, rotiţa simplă pe listă', () => {
    expect(initialPhoneScreen(true)).toBe('cat')
    expect(initialPhoneScreen(false)).toBe('list')
  })
})

describe('settingsLayout', () => {
  it('desktop: totul vizibil, fără Back, indiferent de ecran sau căutare', () => {
    for (const screen of ['list', 'cat'] as const) {
      for (const searching of [false, true]) {
        expect(settingsLayout(false, screen, searching)).toEqual({ showNav: true, showContent: true, showBack: false, showSearch: true })
      }
    }
  })
  it('telefon, lista: căutarea + lista; în timpul căutării rezultatele iau locul listei', () => {
    expect(settingsLayout(true, 'list', false)).toEqual({ showNav: true, showContent: false, showBack: false, showSearch: true })
    expect(settingsLayout(true, 'list', true)).toEqual({ showNav: false, showContent: true, showBack: false, showSearch: true })
  })
  it('telefon, categoria: Back + conţinut, fără listă şi fără căutare', () => {
    expect(settingsLayout(true, 'cat', false)).toEqual({ showNav: false, showContent: true, showBack: true, showSearch: false })
  })
})

describe('escapeAction', () => {
  it('goleşte întâi căutarea', () => {
    expect(escapeAction(true, 'cat', true)).toBe('clear')
    expect(escapeAction(false, 'list', true)).toBe('clear')
  })
  it('pe telefon, din categorie, înapoi la listă', () => {
    expect(escapeAction(true, 'cat', false)).toBe('back')
  })
  it('altfel închide (desktop mereu; telefon de pe listă)', () => {
    expect(escapeAction(true, 'list', false)).toBe('close')
    expect(escapeAction(false, 'cat', false)).toBe('close')
  })
})

describe('railKeyTarget', () => {
  it('săgeţile se mută şi se rotesc la capete', () => {
    expect(railKeyTarget('ArrowDown', 0, 4)).toBe(1)
    expect(railKeyTarget('ArrowRight', 3, 4)).toBe(0)
    expect(railKeyTarget('ArrowUp', 0, 4)).toBe(3)
    expect(railKeyTarget('ArrowLeft', 2, 4)).toBe(1)
  })
  it('Home / End', () => {
    expect(railKeyTarget('Home', 2, 4)).toBe(0)
    expect(railKeyTarget('End', 0, 4)).toBe(3)
  })
  it('alte taste nu sunt ale rail-ului', () => {
    for (const k of ['Tab', 'Enter', ' ', 'a', 'Escape']) expect(railKeyTarget(k, 1, 4)).toBeNull()
  })
  it('index necunoscut porneşte de la primul; listă goală = nimic', () => {
    expect(railKeyTarget('ArrowDown', -1, 3)).toBe(1)
    expect(railKeyTarget('ArrowDown', 0, 0)).toBeNull()
  })
})

describe('railTabStop', () => {
  it('categoria activă dacă e vizibilă, altfel prima', () => {
    expect(railTabStop(['a', 'b', 'c'], 'b')).toBe('b')
    expect(railTabStop(['a', 'b'], 'z')).toBe('a')
    expect(railTabStop([], 'z')).toBeUndefined()
  })
})
