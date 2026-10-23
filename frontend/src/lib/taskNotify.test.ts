import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  DEFAULT_SEC, parseOscNotify, sanitizeOscText, setTaskNotifyEnabled, setTaskNotifySeconds,
  shouldNotifyCommand, taskNotifyEnabled, taskNotifySeconds,
} from './taskNotify'

// Mediul de test e `node` (fără jsdom): lib/storage.ts atinge `window.localStorage`, deci îl stubuim.
class FakeStorage {
  private m = new Map<string, string>()
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null }
  setItem(k: string, v: string) { this.m.set(k, v) }
  removeItem(k: string) { this.m.delete(k) }
}
beforeEach(() => { vi.stubGlobal('window', { localStorage: new FakeStorage() }) })
afterEach(() => vi.unstubAllGlobals())

describe('preferința (per-browser)', () => {
  it('implicit oprit, prag implicit', () => {
    expect(taskNotifyEnabled()).toBe(false)
    expect(taskNotifySeconds()).toBe(DEFAULT_SEC)
  })
  it('round-trip enable + prag mărginit', () => {
    setTaskNotifyEnabled(true)
    expect(taskNotifyEnabled()).toBe(true)
    setTaskNotifySeconds(10); expect(taskNotifySeconds()).toBe(10)
    setTaskNotifySeconds(0); expect(taskNotifySeconds()).toBe(1)        // sub minim → mărginit
    setTaskNotifySeconds(99999); expect(taskNotifySeconds()).toBe(3600) // peste maxim → mărginit
    setTaskNotifySeconds(NaN); expect(taskNotifySeconds()).toBe(DEFAULT_SEC)
  })
  it('gunoi în storage → implicit, nu aruncă', () => {
    window.localStorage.setItem('wt_tasknotify_sec', 'abc')
    expect(taskNotifySeconds()).toBe(DEFAULT_SEC)
  })
})

describe('shouldNotifyCommand', () => {
  const on = { enabled: true, minSeconds: 30, inactive: true }
  it('sună la eșec peste prag, cât ești plecat', () => {
    expect(shouldNotifyCommand(1, 60_000, on)).toBe(true)
    expect(shouldNotifyCommand(127, 30_000, on)).toBe(true)   // fix pe prag
  })
  it('NU sună la succes', () => {
    expect(shouldNotifyCommand(0, 600_000, on)).toBe(false)
  })
  it('NU sună sub prag', () => {
    expect(shouldNotifyCommand(1, 29_999, on)).toBe(false)
  })
  it('NU sună fără exit code (comandă încă în curs / necunoscut)', () => {
    expect(shouldNotifyCommand(undefined, 999_999, on)).toBe(false)
  })
  it('NU sună dacă e oprit sau dacă te uiți la panou', () => {
    expect(shouldNotifyCommand(1, 60_000, { ...on, enabled: false })).toBe(false)
    expect(shouldNotifyCommand(1, 60_000, { ...on, inactive: false })).toBe(false)
  })
})

describe('sanitizeOscText (input neîncredere)', () => {
  it('taie control chars, ESC, BEL, newline și plafonează', () => {
    expect(sanitizeOscText('ok\u001b]0;evil\u0007\nline')).toBe('ok ]0;evil line')
    expect(sanitizeOscText('a'.repeat(500)).length).toBe(120)
    expect(sanitizeOscText('   ')).toBe('')
  })
})

describe('parseOscNotify', () => {
  it('OSC 777 „notify;titlu;corp"', () => {
    expect(parseOscNotify(777, 'notify;Build;gata')).toEqual({ title: 'Build', body: 'gata' })
  })
  it('OSC 777 corp cu „;" se păstrează', () => {
    expect(parseOscNotify(777, 'notify;t;a;b')).toEqual({ title: 't', body: 'a;b' })
  })
  it('OSC 777 fără prefixul „notify" → null (nu e notificare)', () => {
    expect(parseOscNotify(777, 'altceva;x')).toBeNull()
  })
  it('OSC 9 = tot payload-ul e corpul', () => {
    expect(parseOscNotify(9, 'task gata')).toEqual({ title: '', body: 'task gata' })
  })
  it('OSC 99 = corpul după ultimul „;"', () => {
    expect(parseOscNotify(99, 'd=1;i=2;gata')).toEqual({ title: '', body: 'gata' })
  })
  it('gol → null', () => {
    expect(parseOscNotify(9, '   ')).toBeNull()
    expect(parseOscNotify(777, 'notify;;')).toBeNull()
  })
})
