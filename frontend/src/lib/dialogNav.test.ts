import { describe, expect, it } from 'vitest'
import { dialogNavKey, dialogNavTarget, Nav } from './dialogNav'

const TAB: Nav = { dir: 'next', wrap: true }
const SHIFT_TAB: Nav = { dir: 'prev', wrap: true }
const RIGHT: Nav = { dir: 'next', wrap: false }
const LEFT: Nav = { dir: 'prev', wrap: false }

describe('dialogNavKey (taste care mută focusul între butoanele unui dialog)', () => {
  it('Tab / Shift+Tab: circular', () => {
    expect(dialogNavKey({ key: 'Tab' })).toEqual(TAB)
    expect(dialogNavKey({ key: 'Tab', shiftKey: true })).toEqual(SHIFT_TAB)
  })

  it('→ / ←: fără trecere de capăt', () => {
    expect(dialogNavKey({ key: 'ArrowRight' })).toEqual(RIGHT)
    expect(dialogNavKey({ key: 'ArrowLeft' })).toEqual(LEFT)
  })

  it('↑ / ↓ NU navighează: „↑ apoi Enter" (reflex de shell) nu are voie să ajungă pe Rulează', () => {
    expect(dialogNavKey({ key: 'ArrowUp' })).toBeNull()
    expect(dialogNavKey({ key: 'ArrowDown' })).toBeNull()
  })

  it('cu Ctrl / Alt / Meta nu e a dialogului (Alt+← = înapoi, Ctrl+Tab = alt tab)', () => {
    for (const mod of ['altKey', 'ctrlKey', 'metaKey'] as const) {
      expect(dialogNavKey({ key: 'Tab', [mod]: true })).toBeNull()
      expect(dialogNavKey({ key: 'ArrowLeft', [mod]: true })).toBeNull()
    }
    expect(dialogNavKey({ key: 'ArrowRight', shiftKey: true })).toBeNull()   // selecţie de text
  })

  it('Enter, Escape, litere: nu sunt navigare', () => {
    for (const key of ['Enter', 'Escape', ' ', 'a', 'Home', 'PageDown']) expect(dialogNavKey({ key })).toBeNull()
  })
})

describe('dialogNavTarget (ce buton primeşte focusul; 0 = Anulează, 1 = Rulează)', () => {
  it('Tab pe două butoane: mereu celălalt (circular)', () => {
    expect(dialogNavTarget(2, 0, TAB)).toBe(1)
    expect(dialogNavTarget(2, 1, TAB)).toBe(0)
    expect(dialogNavTarget(2, 0, SHIFT_TAB)).toBe(1)
    expect(dialogNavTarget(2, 1, SHIFT_TAB)).toBe(0)
  })

  it('săgeţile: → duce pe Rulează, ← înapoi pe Anulează', () => {
    expect(dialogNavTarget(2, 0, RIGHT)).toBe(1)
    expect(dialogNavTarget(2, 1, LEFT)).toBe(0)
  })

  it('săgeţile se opresc la capăt: ← de pe Anulează NU sare pe Rulează', () => {
    expect(dialogNavTarget(2, 0, LEFT)).toBe(0)
    expect(dialogNavTarget(2, 1, RIGHT)).toBe(1)
    expect(dialogNavTarget(3, 2, RIGHT)).toBe(2)
    expect(dialogNavTarget(3, 0, LEFT)).toBe(0)
  })

  it('circular pe trei butoane doar cu Tab', () => {
    expect(dialogNavTarget(3, 2, TAB)).toBe(0)
    expect(dialogNavTarget(3, 0, SHIFT_TAB)).toBe(2)
    expect(dialogNavTarget(3, 1, RIGHT)).toBe(2)
  })

  it('focus în dialog dar pe niciun buton: o săgeată merge pe PRIMUL (cel sigur), oricare ar fi', () => {
    expect(dialogNavTarget(2, -1, RIGHT)).toBe(0)
    expect(dialogNavTarget(2, -1, LEFT)).toBe(0)
    expect(dialogNavTarget(2, 9, LEFT)).toBe(0)
  })

  it('…iar Tab se poartă ca nativ: Tab pe primul, Shift+Tab pe ultimul', () => {
    expect(dialogNavTarget(2, -1, TAB)).toBe(0)
    expect(dialogNavTarget(2, -1, SHIFT_TAB)).toBe(1)
  })

  it('un singur buton rămâne pe el; fără butoane = -1', () => {
    expect(dialogNavTarget(1, 0, TAB)).toBe(0)
    expect(dialogNavTarget(1, 0, LEFT)).toBe(0)
    expect(dialogNavTarget(0, -1, TAB)).toBe(-1)
  })
})
