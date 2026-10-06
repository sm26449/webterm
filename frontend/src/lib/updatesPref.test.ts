import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  UPD_MODE_KEY,
  UPD_MUTE_KEY,
  isHostMuted,
  mutedHosts,
  setHostMuted,
  setUpdatesMode,
  updatesMode,
  updatesSignal,
} from './updatesPref'

// Mediul de test e `node`: stub de localStorage ca în coachtips.test.ts. Stub-ul de window n-are
// dispatchEvent — notify() trebuie să tolereze asta (acelaşi caz ca un mediu fără window).
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

describe('updatesMode', () => {
  it('implicit „all"; gunoiul cade tot pe „all"', () => {
    expect(updatesMode()).toBe('all')
    storage.setItem(UPD_MODE_KEY, 'loud')
    expect(updatesMode()).toBe('all')
  })
  it('persistă modul ales', () => {
    setUpdatesMode('security')
    expect(updatesMode()).toBe('security')
    setUpdatesMode('off')
    expect(storage.getItem(UPD_MODE_KEY)).toBe('off')
  })
})

describe('mascare per host', () => {
  it('mute / unmute', () => {
    expect(isHostMuted(3)).toBe(false)
    setHostMuted(3, true)
    setHostMuted(1, true)
    expect(isHostMuted(3)).toBe(true)
    expect(storage.getItem(UPD_MUTE_KEY)).toBe('[1,3]')
    setHostMuted(3, false)
    expect(isHostMuted(3)).toBe(false)
    expect(isHostMuted(1)).toBe(true)
  })
  it('JSON stricat sau valori non-întregi = listă goală / filtrate', () => {
    storage.setItem(UPD_MUTE_KEY, '{nope')
    expect(mutedHosts().size).toBe(0)
    storage.setItem(UPD_MUTE_KEY, '[2,"x",2.5,null,7]')
    expect([...mutedHosts()]).toEqual([2, 7])
  })
})

describe('updatesSignal', () => {
  const none = new Set<number>()
  const plain = { count: 4, security: 0 }
  const sec = { count: 4, security: 2 }
  it('fără update-uri = nimic', () => {
    expect(updatesSignal(1, null, 'all', none)).toBe('none')
    expect(updatesSignal(1, { count: 0, security: null }, 'all', none)).toBe('none')
  })
  it('„all": discret pentru obişnuite, accent pentru securitate', () => {
    expect(updatesSignal(1, plain, 'all', none)).toBe('quiet')
    expect(updatesSignal(1, sec, 'all', none)).toBe('security')
  })
  it('„security": doar cele de securitate', () => {
    expect(updatesSignal(1, plain, 'security', none)).toBe('none')
    expect(updatesSignal(1, sec, 'security', none)).toBe('security')
  })
  it('„off" şi hostul mascat ascund tot, inclusiv securitatea', () => {
    expect(updatesSignal(1, sec, 'off', none)).toBe('none')
    expect(updatesSignal(1, sec, 'all', new Set([1]))).toBe('none')
    expect(updatesSignal(2, sec, 'all', new Set([1]))).toBe('security')
  })
})
