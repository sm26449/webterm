import { describe, expect, it } from 'vitest'
import {
  BACKOFF_CAP_MS, backoffMs, crc32, dirName, etaSec, fmtBytes, fmtEta, nextChunkSize, parseUpLsKey,
  parseUploadMeta, resolveResync, speedTracker, UP_CHUNK, UP_CHUNK_MAX, UP_CHUNK_MIN, upLsKey,
} from './uploads'

const UID = 'a'.repeat(32)

describe('metadate persistate (wt_up_*)', () => {
  it('cheia se construieşte şi se parsează înapoi, chiar cu `_` în cale', () => {
    const k = upLsKey(7, '/srv/my_dir/big_file.iso', 17_000_000_000, 1700000000000)
    expect(parseUpLsKey(k)).toEqual({ hostId: 7, dest: '/srv/my_dir/big_file.iso', size: 17_000_000_000, lastModified: 1700000000000 })
    expect(parseUpLsKey('wt_lang')).toBeNull()
  })

  it('format VECHI (doar uid): metadatele se reconstruiesc din cheie, pos necunoscut = 0', () => {
    const k = upLsKey(3, '/tmp/a_b.bin', 10, 20)
    const m = parseUploadMeta(UID, k)
    expect(m).toMatchObject({ uid: UID, hostId: 3, dest: '/tmp/a_b.bin', name: 'a_b.bin', size: 10, lastModified: 20, pos: 0, hostName: '' })
  })

  it('format NOU (JSON): se citeşte întreg', () => {
    const raw = JSON.stringify({ uid: UID, hostId: 2, hostName: 'nas', dest: '/x/y.iso', name: 'y.iso', size: 5, lastModified: 9, pos: 3, updated: 1 })
    expect(parseUploadMeta(raw, 'wt_up_2_/x/y.iso_5_9')).toEqual({ uid: UID, hostId: 2, hostName: 'nas', dest: '/x/y.iso', name: 'y.iso', size: 5, lastModified: 9, pos: 3, updated: 1 })
  })

  it('valori corupte → null (cheia e ştearsă de restoreOrphans)', () => {
    expect(parseUploadMeta('not json, not hex', 'wt_up_1_/a_1_1')).toBeNull()
    expect(parseUploadMeta(JSON.stringify({ uid: 'zz' }), 'wt_up_1_/a_1_1')).toBeNull()
    expect(parseUploadMeta(null, 'wt_up_1_/a_1_1')).toBeNull()
    expect(parseUploadMeta(UID, 'wt_up_broken')).toBeNull()   // uid vechi, dar cheia nu se poate parsa
  })
})

describe('resincronizare după 409/403', () => {
  const pos = 16, end = 24
  it('serverul are deja felia → landed (doar răspunsul s-a pierdut)', () => {
    expect(resolveResync(pos, end, 24)).toEqual({ action: 'landed', pos: 24 })
  })
  it('serverul n-are nimic nou → retry pe aceeaşi felie (CRC rămâne valid)', () => {
    expect(resolveResync(pos, end, 16)).toEqual({ action: 'retry', pos: 16 })
  })
  it('aterizare parţială / alt scriitor → jump la offset-ul real', () => {
    expect(resolveResync(pos, end, 20)).toEqual({ action: 'jump', pos: 20 })
    expect(resolveResync(pos, end, 40)).toEqual({ action: 'jump', pos: 40 })
  })
})

describe('backoff', () => {
  it('1,2,4,8 s apoi plafon de 15 s', () => {
    expect([1, 2, 3, 4, 5, 6, 8].map(backoffMs)).toEqual([1000, 2000, 4000, 8000, 15000, 15000, 15000])
    expect(backoffMs(0)).toBe(1000)
    expect(BACKOFF_CAP_MS).toBe(15000)
  })
})

describe('viteză netezită + ETA', () => {
  it('ignoră eşantioanele sub 1 s şi netezeşte exponenţial', () => {
    const s = speedTracker(0.5)
    expect(s.sample(0, 0)).toBe(0)
    expect(s.sample(500, 500)).toBe(0)                 // prea devreme: nu schimbă nimic
    expect(s.sample(1000, 1000)).toBe(1000)            // prima rată = instantanee (1000 B/s)
    expect(s.sample(4000, 2000)).toBe(2000)            // inst 3000, EWMA 0.5 → 2000
  })
  it('un salt înapoi (felie reluată) reporneşte curat, fără viteză negativă', () => {
    const s = speedTracker()
    s.sample(0, 0); s.sample(8000, 1000)
    expect(s.sample(2000, 2000)).toBe(8000)            // păstrează rata veche, re-ancorează
    s.reset()
    expect(s.rate).toBe(0)
  })
  it('ETA doar când există viteză', () => {
    expect(etaSec(100, 50, 0)).toBeNull()
    expect(etaSec(100, 50, 10)).toBe(5)
    expect(etaSec(100, 100, 10)).toBe(0)
  })
})

describe('formatare', () => {
  const t = (k: string) => ({ 'time.s': 's', 'time.m': 'm', 'time.h': 'h' }[k] ?? k)
  it('octeţi', () => {
    expect(fmtBytes(512)).toBe('512 B')
    expect(fmtBytes(24 * 1024 * 1024)).toBe('24.0 MB')
    expect(fmtBytes(17 * 1024 ** 3)).toBe('17.00 GB')
  })
  it('ETA', () => {
    expect(fmtEta(null, t)).toBe('—')
    expect(fmtEta(45, t)).toBe('45s')
    expect(fmtEta(12 * 60, t)).toBe('12m')
    expect(fmtEta(3600 + 5 * 60, t)).toBe('1h 5m')
  })
  it('directorul ţintei pentru „deschide directorul"', () => {
    expect(dirName('/srv/x/y.iso')).toBe('/srv/x')
    expect(dirName('/y.iso')).toBe('/')
    expect(dirName('y.iso')).toBe('.')
  })
})

describe('felie adaptivă (nextChunkSize)', () => {
  const MB = 1024 * 1024
  it('legătură rapidă (felie sub ţinta joasă) → creşte, plafonat la MAX', () => {
    expect(nextChunkSize(UP_CHUNK, 1000, false)).toBe(UP_CHUNK * 2)      // 8→16 MiB
    expect(nextChunkSize(UP_CHUNK_MAX, 1000, false)).toBe(UP_CHUNK_MAX)  // deja la plafon
  })
  it('legătură lentă (felie peste ţinta înaltă) → scade, podea la MIN', () => {
    expect(nextChunkSize(16 * MB, 20000, false)).toBe(8 * MB)
    expect(nextChunkSize(UP_CHUNK_MIN, 20000, false)).toBe(UP_CHUNK_MIN) // deja la podea
  })
  it('instabil (stall/retry) → scade indiferent de durată', () => {
    expect(nextChunkSize(16 * MB, 500, true)).toBe(8 * MB)
  })
  it('în fereastra ţintă → neschimbat', () => {
    expect(nextChunkSize(UP_CHUNK, 5000, false)).toBe(UP_CHUNK)
  })
  it('rămâne mereu între MIN şi MAX', () => {
    for (const ms of [0, 100, 5000, 99999]) {
      for (const u of [false, true]) {
        const n = nextChunkSize(UP_CHUNK, ms, u)
        expect(n).toBeGreaterThanOrEqual(UP_CHUNK_MIN)
        expect(n).toBeLessThanOrEqual(UP_CHUNK_MAX)
      }
    }
  })
})

describe('crc32 (IEEE, identic cu zlib.crc32 din agent)', () => {
  it('vectorul standard „123456789" = 0xCBF43926, incremental pe două felii', () => {
    const bytes = new TextEncoder().encode('123456789')
    expect(crc32(0, bytes)).toBe(0xCBF43926)
    expect(crc32(crc32(0, bytes.slice(0, 4)), bytes.slice(4))).toBe(0xCBF43926)
  })
})
