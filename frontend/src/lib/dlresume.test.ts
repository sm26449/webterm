import { describe, expect, it } from 'vitest'
import {
  CK_BYTES, CK_INTERVAL_MS, CK_MIN_BYTES, DL_REC_TTL_MS, DlRecStore, DlRecord, asRecord, contentRangeTotal,
  dlRecKey, forgetUser, isExpired, lastModifiedSec, loadForUser, resumeOffset, shouldCheckpoint, validatorMatches,
} from './dlresume'

const MiB = 1024 * 1024

describe('shouldCheckpoint: cadenţa geometrică', () => {
  it('nimic de comis → nu', () => {
    expect(shouldCheckpoint(0, 0, 999_999)).toBe(false)
    expect(shouldCheckpoint(100, 100, 999_999)).toBe(false)
  })
  it('sub pasul minim: nici după mult timp', () => {
    expect(shouldCheckpoint(0, CK_MIN_BYTES - 1, CK_INTERVAL_MS * 10)).toBe(false)
  })
  it('între pasul minim şi CK_BYTES: doar după CK_INTERVAL_MS (legături lente)', () => {
    expect(shouldCheckpoint(0, CK_MIN_BYTES, CK_INTERVAL_MS - 1)).toBe(false)
    expect(shouldCheckpoint(0, CK_MIN_BYTES, CK_INTERVAL_MS)).toBe(true)
  })
  it('la CK_BYTES: imediat', () => {
    expect(shouldCheckpoint(0, CK_BYTES, 0)).toBe(true)
  })
  it('pasul creşte cu 50% din ce e deja comis (cost liniar, nu pătratic)', () => {
    const c = 10 * 1024 * MiB
    expect(shouldCheckpoint(c, c + CK_BYTES, 0)).toBe(false)           // 256 MiB nu mai ajung
    expect(shouldCheckpoint(c, c + c / 2 - 1, CK_INTERVAL_MS * 10)).toBe(false)
    expect(shouldCheckpoint(c, c + c / 2, 0)).toBe(true)
  })
  it('un fişier de 40 GB pe o legătură rapidă: ~12 checkpoint-uri, suma comisă < 3× fişierul', () => {
    const N = 40 * 1024 * MiB
    let committed = 0, n = 0, sum = 0
    for (let w = 0; w < N; w += 16 * MiB) {
      if (shouldCheckpoint(committed, w, 0)) { committed = w; n++; sum += w }
    }
    expect(n).toBeGreaterThanOrEqual(10)
    expect(n).toBeLessThanOrEqual(14)
    expect(sum).toBeLessThan(3 * N)
  })
})

describe('resumeOffset', () => {
  it('min(checkpoint, mărimea reală de pe disc)', () => {
    expect(resumeOffset(1000, 5000)).toBe(1000)
    expect(resumeOffset(1000, 400)).toBe(400)            // fişierul a fost trunchiat între timp
    expect(resumeOffset(1000, 1000)).toBe(1000)
  })
  it('valori invalide → 0 (start over sigur)', () => {
    expect(resumeOffset(NaN, 10)).toBe(0)
    expect(resumeOffset(-5, 10)).toBe(0)
    expect(resumeOffset(10, NaN)).toBe(0)
    expect(resumeOffset(10.7, 100)).toBe(10)
  })
})

describe('validatorul (ETag + total)', () => {
  const saved = { etag: 'W/"100-5"', size: 100 }
  it('acelaşi ETag + acelaşi total → da', () => {
    expect(validatorMatches(saved, { etag: 'W/"100-5"', total: 100 })).toBe(true)
    expect(validatorMatches(saved, { etag: 'W/"100-5"', total: null })).toBe(true)
  })
  it('ETag diferit / lipsă → nu', () => {
    expect(validatorMatches(saved, { etag: 'W/"100-6"', total: 100 })).toBe(false)
    expect(validatorMatches(saved, { etag: null, total: 100 })).toBe(false)
    expect(validatorMatches({ etag: null, size: 100 }, { etag: null, total: 100 })).toBe(false)
  })
  it('total diferit de mărimea salvată → nu', () => {
    expect(validatorMatches(saved, { etag: 'W/"100-5"', total: 101 })).toBe(false)
  })
  it('Content-Range şi Last-Modified', () => {
    expect(contentRangeTotal('bytes 10-99/100')).toBe(100)
    expect(contentRangeTotal('bytes */100')).toBe(100)
    expect(contentRangeTotal('bytes 0-1/*')).toBeNull()
    expect(contentRangeTotal(null)).toBeNull()
    expect(lastModifiedSec('Tue, 14 Nov 2023 22:13:20 GMT')).toBe(1700000000)
    expect(lastModifiedSec('nonsense')).toBeNull()
  })
})

// ── stoc în memorie (în locul IndexedDB) ──
function memStore(): DlRecStore & { map: Map<string, unknown>; handles: Map<string, unknown>; handleReads: number } {
  const map = new Map<string, unknown>()
  const handles = new Map<string, unknown>()
  const s = {
    map, handles, handleReads: 0,
    all: async () => [...map.values()],
    put: async (r: DlRecord, h?: unknown) => { map.set(r.key, r); if (h) handles.set(r.key, h) },
    del: async (k: string) => { map.delete(k); handles.delete(k) },
    handle: async (k: string) => { s.handleReads++; return (handles.get(k) ?? null) as never },
    handleKeys: async () => [...handles.keys()],
  }
  return s
}

const rec = (o: Partial<DlRecord> = {}): DlRecord => ({
  key: dlRecKey(7, 1, '/x'), v: 1, userId: 7, hostId: 1, hostName: 'h', path: '/x', name: 'x', size: 10,
  etag: 'W/"10-1"', mtime: 1, checkpoint: 4, created: 1000, updated: 1000, ...o,
})

describe('înregistrările: per cont, expirare, logout', () => {
  it('loadForUser: doar ale contului curent; expiratele şi cele stricate se şterg', async () => {
    const s = memStore()
    const now = 10 * DL_REC_TTL_MS
    await s.put(rec({ key: 'a', userId: 7, updated: now - 1000 }))
    await s.put(rec({ key: 'b', userId: 8, updated: now - 1000 }))             // alt cont: neatins
    await s.put(rec({ key: 'c', userId: 7, updated: now - DL_REC_TTL_MS - 1 })) // expirat
    s.map.set('d', { key: 'd', v: 1, userId: 7 })                               // stricat (fără câmpuri)
    s.handles.set('a', {}); s.handles.set('c', {}); s.handles.set('zombie', {})   // handle fără metadate
    const mine = await loadForUser(s, 7, now)
    expect(mine.map((r) => r.key)).toEqual(['a'])
    expect([...s.map.keys()].sort()).toEqual(['a', 'b'])
    expect([...s.handles.keys()]).toEqual(['a'])                               // expirat + orfan: şterse
    expect(s.handleReads).toBe(0)                                               // niciun handle deserializat
    expect((await loadForUser(s, 8, now)).map((r) => r.key)).toEqual(['b'])
  })
  it('isExpired: după 7 zile fără activitate', () => {
    expect(isExpired({ created: 0, updated: 1000 }, 1000 + DL_REC_TTL_MS)).toBe(false)
    expect(isExpired({ created: 0, updated: 1000 }, 1001 + DL_REC_TTL_MS)).toBe(true)
  })
  it('asRecord respinge forme greşite', () => {
    expect(asRecord(null)).toBeNull()
    expect(asRecord({ ...rec(), v: 2 })).toBeNull()
    expect(asRecord({ ...rec(), etag: '' })).toBeNull()
    expect(asRecord(rec())).not.toBeNull()
  })
  it('forgetUser: doar înregistrările contului', async () => {
    const s = memStore()
    await s.put(rec({ key: 'a', userId: 7 }))
    await s.put(rec({ key: 'b', userId: 8 }))
    await forgetUser(s, 7)
    expect([...s.map.keys()]).toEqual(['b'])
  })
  it('un stoc care aruncă nu strică pornirea', async () => {
    const bad: DlRecStore = { all: async () => { throw new Error('idb') }, put: async () => {}, del: async () => {},
      handle: async () => null, handleKeys: async () => [] }
    expect(await loadForUser(bad, 7, 0)).toEqual([])
    await expect(forgetUser(bad, 7)).resolves.toBeUndefined()
  })
})

