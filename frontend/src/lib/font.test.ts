import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// font.ts atinge window + localStorage doar la APEL, deci le stubuim ca globale de
// test — fără jsdom. Bug-uri reparate în 2.0.6–2.0.9 pe care testele le țintuiesc:
// default-ul de lățime înghețat la prima vizită, A± no-op când setItem aruncă
// (Safari privat), migrarea veche care putea crăpa view-ul la randare.
import { FONT_STORAGE_KEY, deviceClass, preferredFont, setPreferredFont } from './font'

class FakeStorage {
  private m = new Map<string, string>()
  throwOnWrite = false
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null }
  setItem(k: string, v: string) {
    if (this.throwOnWrite) throw new DOMException('QuotaExceededError')
    this.m.set(k, v)
  }
  removeItem(k: string) { this.m.delete(k) }
}

let storage: FakeStorage
let dispatched: Event[]

beforeEach(() => {
  storage = new FakeStorage()
  dispatched = []
  vi.stubGlobal('localStorage', storage)
  vi.stubGlobal('window', {
    innerWidth: 1200,
    dispatchEvent: (e: Event) => { dispatched.push(e); return true },
  })
})
afterEach(() => vi.unstubAllGlobals())

const setWidth = (w: number) =>
  ((globalThis as unknown as { window: { innerWidth: number } }).window.innerWidth = w)

describe('deviceClass + default-uri', () => {
  it('pragurile 640/768 împart telefon/tabletă/desktop', () => {
    setWidth(500); expect(deviceClass()).toBe('phone')
    setWidth(700); expect(deviceClass()).toBe('tablet')
    setWidth(1400); expect(deviceClass()).toBe('desktop')
  })

  it('default-urile pe clase: 9/12/14 — și NU se persistă (bug-ul înghețării)', () => {
    setWidth(500); expect(preferredFont()).toBe(9)
    setWidth(700); expect(preferredFont()).toBe(12)
    setWidth(1400); expect(preferredFont()).toBe(14)
    expect(storage.getItem(FONT_STORAGE_KEY)).toBeNull()   // doar A± persistă
  })
})

describe('setPreferredFont', () => {
  it('suprascrie DOAR clasa curentă și anunță panourile', () => {
    setWidth(1400)
    expect(setPreferredFont(16)).toBe(16)
    expect(preferredFont()).toBe(16)
    setWidth(500)
    expect(preferredFont()).toBe(9)                        // telefonul rămâne pe default
    expect(dispatched.some((e) => e.type === 'wt-font')).toBe(true)
  })

  it('clamp la 8..24', () => {
    expect(setPreferredFont(3)).toBe(8)
    expect(setPreferredFont(99)).toBe(24)
  })

  it('storage blocat (Safari privat): fontul tot se schimbă, evenimentul tot pleacă', () => {
    storage.throwOnWrite = true
    expect(setPreferredFont(17)).toBe(17)                  // nu aruncă
    expect(dispatched.some((e) => e.type === 'wt-font')).toBe(true)
  })
})

describe('migrarea vechii chei wt_font', () => {
  it('valoarea veche devine override al clasei curente, cheia dispare', () => {
    setWidth(1400)
    storage.setItem('wt_font', '18')
    expect(preferredFont()).toBe(18)
    expect(storage.getItem('wt_font')).toBeNull()
    expect(storage.getItem(FONT_STORAGE_KEY)).toContain('desktop')
  })

  it('valoare coruptă → default, fără excepții (rula în useState initializer)', () => {
    setWidth(1400)
    storage.setItem('wt_font', 'NaN-garbage')
    expect(preferredFont()).toBe(14)
  })
})
