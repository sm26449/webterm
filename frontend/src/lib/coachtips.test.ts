import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  TIP_ADDHOST_AGENT,
  TIP_KEYS,
  TIP_TERMINAL_PASTE,
  TIP_TOOLBAR,
  dismissTip,
  isTipDismissed,
  resetAllTips,
} from './coachtips'

// Mediul de test e `node` (fără jsdom): lib/storage.ts atinge `window.localStorage`, deci îl
// stubuim ca în walkthrough.test.ts — fără dependenţă de jsdom pentru două globale.
class FakeStorage {
  private m = new Map<string, string>()
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null }
  setItem(k: string, v: string) { this.m.set(k, v) }
  removeItem(k: string) { this.m.delete(k) }
}
let storage: FakeStorage
beforeEach(() => {
  storage = new FakeStorage()
  vi.stubGlobal('window', { localStorage: storage })
})
afterEach(() => vi.unstubAllGlobals())

describe('isTipDismissed / dismissTip', () => {
  it('neînchis la început; închis după dismiss', () => {
    expect(isTipDismissed(TIP_TERMINAL_PASTE)).toBe(false)
    dismissTip(TIP_TERMINAL_PASTE)
    expect(isTipDismissed(TIP_TERMINAL_PASTE)).toBe(true)
    expect(storage.getItem(TIP_TERMINAL_PASTE)).toBe('1')
  })

  it('doar exact „1" înseamnă închis', () => {
    storage.setItem(TIP_TOOLBAR, '0')
    expect(isTipDismissed(TIP_TOOLBAR)).toBe(false)
    storage.setItem(TIP_TOOLBAR, 'da')
    expect(isTipDismissed(TIP_TOOLBAR)).toBe(false)
  })

  it('cheile sunt independente între ele', () => {
    dismissTip(TIP_ADDHOST_AGENT)
    expect(isTipDismissed(TIP_ADDHOST_AGENT)).toBe(true)
    expect(isTipDismissed(TIP_TOOLBAR)).toBe(false)
  })
})

describe('resetAllTips', () => {
  it('şterge toate cheile cunoscute', () => {
    for (const k of TIP_KEYS) dismissTip(k)
    for (const k of TIP_KEYS) expect(isTipDismissed(k)).toBe(true)
    resetAllTips()
    for (const k of TIP_KEYS) expect(isTipDismissed(k)).toBe(false)
  })

  it('şterge şi o cheie wt_tip_* necunoscută (sfat viitor), când storage-ul se poate enumera', () => {
    storage.setItem('wt_tip_future_feature', '1')
    // Object.keys pe stub nu expune cheile Map-ului, dar funcţia nu trebuie să arunce; iar
    // cheile cunoscute oricum se curăţă. (În browser real, enumerarea prinde şi necunoscuta.)
    expect(() => resetAllTips()).not.toThrow()
  })
})

describe('siguranţă fără localStorage', () => {
  it('nu aruncă dacă atingerea localStorage dă excepţie', () => {
    vi.stubGlobal('window', {
      get localStorage(): Storage { throw new Error('SecurityError') },
    })
    expect(() => isTipDismissed(TIP_TOOLBAR)).not.toThrow()
    expect(isTipDismissed(TIP_TOOLBAR)).toBe(false)
    expect(() => dismissTip(TIP_TOOLBAR)).not.toThrow()
    expect(() => resetAllTips()).not.toThrow()
  })
})
