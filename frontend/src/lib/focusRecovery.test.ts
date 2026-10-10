import { describe, expect, it } from 'vitest'
import { ALLOWED_OUTSIDE, focusPlace } from './focusRecovery'

// DOM minim, fără jsdom: un nod ştie în ce container e şi ce selectori „îl conţin" (closest).
const body = { tag: 'body' }
const node = (inTrap: boolean, ancestors: string[] = []) => ({
  inTrap,
  closest: (sel: string) => (sel.split(',').some((s) => ancestors.includes(s)) ? {} : null),
})
const trap = { contains: (n: unknown) => !!(n as { inTrap?: boolean })?.inTrap }

describe('focusPlace (U13: focusul care a ieşit din modalul din vârf)', () => {
  it('focus pe <body> sau nicăieri = pierdut (butonul focalizat a dispărut la schimbarea fazei)', () => {
    expect(focusPlace(body as never, trap, body)).toBe('lost')
    expect(focusPlace(null, trap, body)).toBe('lost')
    expect(focusPlace(undefined, trap, body)).toBe('lost')
  })

  it('în dialog = în regulă', () => {
    expect(focusPlace(node(true), trap, body)).toBe('inside')
  })

  it('pe un element din pagina din spate = evadat (se recuperează)', () => {
    expect(focusPlace(node(false), trap, body)).toBe('escaped')
    expect(focusPlace(node(false, ['#root', 'aside']), trap, body)).toBe('escaped')
  })

  it('popup-urile portalate legitim NU sunt deturnate: Monaco, HelpTip, ConfirmModal, meniuri', () => {
    for (const sel of ['.monaco-editor', '.context-view', '[role="dialog"]', '[role="alertdialog"]',
      '[role="tooltip"]', '[role="menu"]', '[role="listbox"]', '[data-focus-trap-allow]']) {
      expect(ALLOWED_OUTSIDE.split(',')).toContain(sel)
      expect(focusPlace(node(false, [sel]), trap, body)).toBe('allowed')
    }
  })
})
