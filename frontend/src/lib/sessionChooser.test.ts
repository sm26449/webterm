import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from './api'
import {
  askGlobalEnabled, askHostEnabled, chooserNavTarget, hostOptOutKeys, lastActivity, otherClients,
  resetHostOptOuts, reusableSessions, setAskGlobal, setAskHost, shouldAskBeforeNew,
} from './sessionChooser'

// mediul de test e `node`: stub minim de localStorage (ca în coachtips.test.ts), cu key()/length
class FakeStorage {
  private m = new Map<string, string>()
  get length() { return this.m.size }
  key(i: number) { return [...this.m.keys()][i] ?? null }
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null }
  setItem(k: string, v: string) { this.m.set(k, v) }
  removeItem(k: string) { this.m.delete(k) }
}
beforeEach(() => { vi.stubGlobal('window', { localStorage: new FakeStorage() }) })
afterEach(() => vi.unstubAllGlobals())

const ses = (o: Partial<Session>): Session => ({
  id: 'x', host_id: 1, title: '', note: '', state: 'live', created: 100, closed_at: null, exit_status: null,
  close_reason: null, rows: 24, cols: 80, connected_clients: 0, out_offset: 0, created_by_id: 7, ...o,
})

describe('reusableSessions', () => {
  const list = [
    ses({ id: 'old', created: 100, last_output: 900 }),
    ses({ id: 'new', created: 500, last_output: null }),
    ses({ id: 'busy', created: 200, last_output: 1000 }),
    ses({ id: 'closed', state: 'closed', last_output: 2000 }),
    ses({ id: 'lost', state: 'lost' }),
    ses({ id: 'other-host', host_id: 2 }),
    ses({ id: 'someone-else', created_by_id: 8, last_output: 5000 }),
    ses({ id: 'pre-roles', created_by_id: null, created: 50 }),
    ses({ id: 'starting', state: 'creating', created: 60 }),
  ]
  it('doar sesiunile vii, de pe host, ale mele; activitatea cea mai recentă întâi', () => {
    expect(reusableSessions(1, list, 7).map((s) => s.id)).toEqual(['busy', 'old', 'new', 'starting', 'pre-roles'])
  })
  it('fără cont cunoscut nu propune nimic (fluxul de azi)', () => {
    expect(reusableSessions(1, list, null)).toEqual([])
    expect(reusableSessions(1, list, undefined)).toEqual([])
  })
  it('lastActivity cade pe `created` când lipseşte output-ul', () => {
    expect(lastActivity(ses({ created: 42 }))).toBe(42)
    expect(lastActivity(ses({ created: 42, last_output: 99 }))).toBe(99)
  })
})

describe('shouldAskBeforeNew', () => {
  const one = [ses({})]
  it('întreabă doar cu ceva de reluat şi drept de deschidere', () => {
    expect(shouldAskBeforeNew({ hostId: 1, reusable: one, canOpen: true })).toBe(true)
    expect(shouldAskBeforeNew({ hostId: 1, reusable: [], canOpen: true })).toBe(false)
    expect(shouldAskBeforeNew({ hostId: 1, reusable: one, canOpen: false })).toBe(false)
  })
  it('comutatorul global şi „nu mă mai întreba" pe host', () => {
    setAskHost(1, false)
    expect(askHostEnabled(1)).toBe(false)
    expect(askHostEnabled(2)).toBe(true)
    expect(shouldAskBeforeNew({ hostId: 1, reusable: one, canOpen: true })).toBe(false)
    expect(shouldAskBeforeNew({ hostId: 2, reusable: one, canOpen: true })).toBe(true)
    setAskGlobal(false)
    expect(askGlobalEnabled()).toBe(false)
    expect(shouldAskBeforeNew({ hostId: 2, reusable: one, canOpen: true })).toBe(false)
    setAskGlobal(true)
    expect(askGlobalEnabled()).toBe(true)
  })
  it('„întreabă din nou pe toate hosturile" şterge doar cheile per host', () => {
    setAskHost(1, false)
    setAskHost(22, false)
    setAskGlobal(false)
    expect(hostOptOutKeys().sort()).toEqual(['wt_ask_new_session_h1', 'wt_ask_new_session_h22'])
    resetHostOptOuts()
    expect(hostOptOutKeys()).toEqual([])
    expect(askHostEnabled(22)).toBe(true)
    expect(askGlobalEnabled()).toBe(false)
  })
  it('storage blocat: implicit întreabă, fără excepţii', () => {
    vi.stubGlobal('window', { get localStorage(): Storage { throw new Error('SecurityError') } })
    expect(askGlobalEnabled()).toBe(true)
    expect(askHostEnabled(1)).toBe(true)
    expect(hostOptOutKeys()).toEqual([])
  })
})

describe('otherClients / chooserNavTarget', () => {
  it('tab-ul curent nu se numără', () => {
    expect(otherClients(ses({ connected_clients: 3 }), true)).toBe(2)
    expect(otherClients(ses({ connected_clients: 3 }), false)).toBe(3)
    expect(otherClients(ses({ connected_clients: 0 }), true)).toBe(0)
  })
  it('↑/↓ cu trecere la capăt, Home/End, restul nu e al listei', () => {
    expect(chooserNavTarget(3, 0, 'ArrowDown')).toBe(1)
    expect(chooserNavTarget(3, 2, 'ArrowDown')).toBe(0)
    expect(chooserNavTarget(3, 0, 'ArrowUp')).toBe(2)
    expect(chooserNavTarget(3, -1, 'ArrowDown')).toBe(0)
    expect(chooserNavTarget(3, 1, 'Home')).toBe(0)
    expect(chooserNavTarget(3, 1, 'End')).toBe(2)
    expect(chooserNavTarget(3, 1, 'Enter')).toBeNull()
    expect(chooserNavTarget(0, 0, 'ArrowDown')).toBeNull()
  })
})
