import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MAX_ENTRIES, TTL_MS, clearAll, history, record, remove, setLabel } from './cliphistory'

// history-ul e global la nivel de modul: îl golim între teste
beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-10-07T10:00:00Z'))
  clearAll()
})
afterEach(() => { vi.useRealTimers() })

const texts = () => history().map((e) => e.text)

describe('cliphistory (global, în memorie)', () => {
  it('e comun tuturor sesiunilor, newest-first', () => {
    record('A', 'din-a')
    record('B', 'din-b')
    expect(texts()).toEqual(['din-b', 'din-a'])
    expect(history().map((e) => e.sid)).toEqual(['B', 'A'])
  })

  it('plafonează la 10 intrări', () => {
    expect(MAX_ENTRIES).toBe(10)
    for (let i = 0; i < 15; i++) record(i % 2 ? 'A' : 'B', `t${i}`)
    expect(texts()).toHaveLength(10)
    expect(texts()[0]).toBe('t14')
    expect(texts()[9]).toBe('t5')
  })

  it('dedup: o re-copiere mută intrarea sus şi îi reîmprospătează ora (şi sursa)', () => {
    record('A', 'x')
    vi.advanceTimersByTime(10 * 60_000)
    record('A', 'y')
    vi.advanceTimersByTime(10 * 60_000)
    record('B', 'x')
    const h = history()
    expect(h.map((e) => e.text)).toEqual(['x', 'y'])
    expect(h[0].at).toBe(Date.now())
    expect(h[0].sid).toBe('B')
  })

  it('expiră la 1 h de la ultima copiere', () => {
    expect(TTL_MS).toBe(3_600_000)
    record('A', 'vechi')
    vi.advanceTimersByTime(30 * 60_000)
    record('A', 'nou')
    vi.advanceTimersByTime(30 * 60_000 - 1)
    expect(texts()).toEqual(['nou', 'vechi'])
    vi.advanceTimersByTime(1)                    // „vechi" are fix 1 h
    expect(texts()).toEqual(['nou'])
    vi.advanceTimersByTime(30 * 60_000)
    expect(texts()).toEqual([])
  })

  it('o re-copiere înainte de expirare reporneşte ceasul', () => {
    record('A', 'x')
    vi.advanceTimersByTime(50 * 60_000)
    record('A', 'x')
    vi.advanceTimersByTime(50 * 60_000)
    expect(texts()).toEqual(['x'])
  })

  it('remove scoate o singură intrare; clearAll le scoate pe toate', () => {
    record('A', 'a'); record('A', 'b'); record('B', 'c')
    remove('b')
    expect(texts()).toEqual(['c', 'a'])
    clearAll()
    expect(texts()).toEqual([])
  })

  it('respinge textele peste MAX_LEN şi ignoră golul / sid-ul gol', () => {
    record('A', 'x'.repeat(100_001))
    record('A', '')
    record('', 'fără sursă')
    expect(texts()).toEqual([])
    record('A', 'y'.repeat(100_000))
    expect(texts()).toHaveLength(1)
  })

  it('păstrează eticheta sursei; cea curentă (setLabel) are prioritate la citire', () => {
    record('A', 'cu-label', 'emaildb')
    expect(history()[0].label).toBe('emaildb')
    setLabel('B', 'web-01')
    record('B', 'din-b')
    expect(history()[0].label).toBe('web-01')
    setLabel('B', 'web-01 (prod)')               // tab redenumit după copiere
    expect(history()[0].label).toBe('web-01 (prod)')
    expect(history()[1].label).toBe('emaildb')
  })

  it('history() întoarce copii: mutarea rezultatului nu atinge store-ul', () => {
    record('A', 'x')
    const h = history()
    h[0].text = 'altceva'
    h.pop()
    expect(texts()).toEqual(['x'])
  })
})
