import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { DlRecStore, DlRecord } from './dlresume'

/* Motorul REAL de download (downloads.ts) cu fetch fals, un handle fals cu semantica Chromium
   (swap + close) şi un „reload" = module noi (vi.resetModules) peste aceeaşi „IndexedDB". Separat de
   dlresume.test.ts pentru că aici `shouldCheckpoint` e înlocuit cu un prag la scara testului. */

// ── stoc în memorie (în locul IndexedDB) + handle fals cu semantica Chromium (swap + close) ──
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

/** FileSystemFileHandle fals: scrierile merg într-un SWAP; doar close() le mută pe „disc". Exact
    proprietatea pentru care există checkpoint-urile. */
class FakeHandle {
  disk = new Uint8Array(0)
  perm: PermissionState = 'granted'
  gone = false
  closes = 0
  keepCopies = 0
  name = 'big.bin'
  async createWritable(o?: { keepExistingData?: boolean }) {
    if (this.perm !== 'granted') throw new DOMException('no', 'NotAllowedError')
    if (this.gone) throw new DOMException('gone', 'NotFoundError')
    if (o?.keepExistingData) this.keepCopies++
    let swap = o?.keepExistingData ? this.disk.slice() : new Uint8Array(0)
    let cur = 0
    const grow = (n: number) => { if (swap.length < n) { const b = new Uint8Array(n); b.set(swap); swap = b } }
    return {
      write: async (d: BufferSource) => {
        const b = d instanceof Uint8Array ? d : new Uint8Array(d as ArrayBuffer)
        grow(cur + b.length); swap.set(b, cur); cur += b.length
      },
      seek: async (n: number) => { cur = n },
      truncate: async (n: number) => { const b = new Uint8Array(n); b.set(swap.subarray(0, n)); swap = b; if (cur > n) cur = n },
      close: async () => { this.disk = swap; this.closes++ },
      abort: async () => { /* swap aruncat */ },
    }
  }
  async getFile() { if (this.gone) throw new DOMException('gone', 'NotFoundError'); return { size: this.disk.length } }
  async queryPermission() { return this.perm }
  async requestPermission() { return this.perm }
}

// ── motorul real (downloads.ts) cu fetch fals, handle fals şi un „reload" = module noi ──────

interface Srv { data: Uint8Array; etag: string; hangAt: number | null; requests: string[]; served: number }
function serve(srv: Srv) {
  return vi.fn(async (_url: string, init?: RequestInit) => {
    const range = String((init?.headers as Record<string, string>)?.Range ?? '')
    srv.requests.push(range)
    const start = Number(range.match(/bytes=(\d+)-/)?.[1] ?? 0)
    if (start >= srv.data.length) return new Response(null, { status: 416 })
    const signal = init?.signal
    let off = start
    const body = new ReadableStream<Uint8Array>({
      pull(ctl) {
        if (srv.hangAt != null && off >= srv.hangAt) {
          // conexiunea „atârnă" (tab-ul va fi reîncărcat): nu mai vine nimic, niciodată
          return new Promise<void>((resolve) => signal?.addEventListener('abort', () => { ctl.error(new DOMException('a', 'AbortError')); resolve() }))
        }
        if (off >= srv.data.length) { ctl.close(); return }
        const end = Math.min(srv.data.length, off + 1024, srv.hangAt ?? Infinity)
        ctl.enqueue(srv.data.slice(off, end))
        off = end
        srv.served = Math.max(srv.served, off)
      },
    })
    return new Response(body, { status: 206, headers: {
      'Content-Range': `bytes ${start}-${srv.data.length - 1}/${srv.data.length}`,
      ETag: srv.etag, 'Last-Modified': 'Tue, 14 Nov 2023 22:13:20 GMT',
    } })
  })
}

const blob = (n: number, seed = 1) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) % 251)
const until = async (f: () => boolean, ms = 3000) => {
  const t0 = Date.now()
  while (!f()) {
    if (Date.now() - t0 > ms) throw new Error('timeout')
    await new Promise((r) => setTimeout(r, 2))
  }
}

describe('motorul: checkpoint, reload, reluare', () => {
  let store: ReturnType<typeof memStore>
  let handle: FakeHandle
  let srv: Srv
  const ID = 'dl_1_/home/u/big.bin'

  async function freshModules() {
    vi.resetModules()
    const dl = await import('./downloads')
    const us = await import('./uploadStore')
    dl._setDownloadStore(store)
    // checkpoint la fiecare ≥10 000 octeţi: aceeaşi mecanică, la scara unui test
    dl._setCheckpointPolicy((c, w) => w - c >= 10_000)
    return { dl, store: us.uploadStore }
  }

  beforeEach(() => {
    vi.stubGlobal('window', { setTimeout, clearTimeout, setInterval: () => 0, clearInterval: () => {},
      dispatchEvent: () => true, showSaveFilePicker: async () => handle, addEventListener: () => {} })
    vi.stubGlobal('navigator', { languages: ['en'], language: 'en' })
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => {} })
    vi.stubGlobal('document', { createElement: () => ({ click: () => {} }), addEventListener: () => {} })
    store = memStore()
    handle = new FakeHandle()
    srv = { data: blob(50_000), etag: 'W/"50000-1700000000"', hangAt: 35_000, requests: [], served: 0 }
    vi.stubGlobal('fetch', serve(srv))
  })
  afterEach(() => { vi.unstubAllGlobals() })

  /** prima „viaţă" a tab-ului: porneşte descărcarea, care atârnă la 35 000 de octeţi */
  async function firstLife() {
    const a = await freshModules()
    a.dl.setDownloadUser(7)
    // size 0 = „necunoscută" → calea File System Access (sub DL_FSA_PREFER ar fi Blob); mărimea vine
    // din Content-Range
    void a.dl.startDownload({ hostId: 1, hostName: 'nas', path: '/home/u/big.bin', name: 'big.bin', size: 0 })
    // progresul publicat e rărit (≤10/s); ce contează e că serverul a ajuns la punctul de „atârnare"
    await until(() => srv.served >= 35_000)
    await until(() => [...store.map.values()].some((r) => (r as DlRecord).checkpoint >= 30_000))
    return a
  }

  it('checkpoint-urile comit pe disc; ce nu s-a comis se pierde la reload; Resume continuă corect', async () => {
    await firstLife()
    const r = [...store.map.values()][0] as DlRecord
    expect(r.userId).toBe(7)
    expect(r.etag).toBe(srv.etag)
    expect(r.size).toBe(50_000)
    expect(r.mtime).toBe(1700000000)
    expect(r.checkpoint).toBe(handle.disk.length)        // persistat = EXACT ce e comis pe disc
    expect(handle.disk.length).toBeLessThan(35_000)       // octeţii din swap nu sunt pe disc
    expect(handle.closes).toBeGreaterThanOrEqual(3)        // checkpoint-uri = close()…
    expect(handle.keepCopies).toBe(handle.closes)          // …+ redeschidere cu keepExistingData
    expect(JSON.stringify(Object.keys(r))).not.toMatch(/token|cookie|handle/i)
    expect(store.handles.get(r.key)).toBe(handle)            // handle-ul: separat, scris o dată

    // ── reload: module noi, aceeaşi „IndexedDB", acelaşi handle ──
    srv.hangAt = null
    const b = await freshModules()
    b.dl.setDownloadUser(7)
    await b.dl.restoreInterruptedDownloads()
    const row = b.store.get(ID)!
    expect(row.state).toBe('orphan')
    expect(store.handleReads).toBe(0)                         // lista de la pornire nu atinge handle-ul
    expect(row.dir).toBe('down')
    expect(row.pos).toBe(r.checkpoint)
    srv.requests.length = 0
    b.dl.resumeInterrupted(ID)
    await until(() => b.store.get(ID)?.state === 'done')
    expect(srv.requests[0]).toBe(`bytes=${r.checkpoint}-`)   // reluat de la checkpoint, nu de la 0
    expect(store.handleReads).toBe(1)                         // handle-ul citit o dată, la Resume
    expect(handle.disk).toEqual(srv.data)                     // octet cu octet
    expect(store.map.size).toBe(0)                            // terminat → înregistrarea pleacă
  })

  it('alt cont în acelaşi browser nu vede descărcarea întreruptă', async () => {
    await firstLife()
    const b = await freshModules()
    b.dl.setDownloadUser(8)
    await b.dl.restoreInterruptedDownloads()
    expect(b.store.get(ID)).toBeUndefined()
    expect(store.map.size).toBe(1)                            // a contului 7 rămâne
  })

  it('fişierul s-a schimbat pe host → eroare + Start over (de la zero, în acelaşi fişier)', async () => {
    await firstLife()
    srv.hangAt = null
    srv.data = blob(42_000, 9)
    srv.etag = 'W/"42000-1700000099"'
    const b = await freshModules()
    b.dl.setDownloadUser(7)
    await b.dl.restoreInterruptedDownloads()
    b.dl.resumeInterrupted(ID)
    await until(() => b.store.get(ID)?.state === 'err')
    expect(b.store.get(ID)!.restartable).toBe(true)
    expect(b.store.get(ID)!.error).toMatch(/changed on the host/)
    b.dl.restartDownload(ID)
    await until(() => b.store.get(ID)?.state === 'done')
    expect(handle.disk).toEqual(srv.data)                     // nimic din fişierul vechi
  })

  it('permisiune refuzată → rămâne „Întrerupt" cu explicaţia; fişier dispărut → explicaţia', async () => {
    await firstLife()
    const b = await freshModules()
    b.dl.setDownloadUser(7)
    await b.dl.restoreInterruptedDownloads()
    handle.perm = 'denied'
    b.dl.resumeInterrupted(ID)
    await until(() => !!b.store.get(ID)?.detail)
    expect(b.store.get(ID)!.state).toBe('orphan')
    expect(b.store.get(ID)!.detail).toMatch(/Permission/)
    handle.perm = 'granted'
    handle.gone = true
    b.dl.resumeInterrupted(ID)
    await until(() => /moved or deleted/.test(b.store.get(ID)?.detail ?? ''))
    expect(store.map.size).toBe(1)                            // Discard decide omul
    b.dl.discardDownload(ID)
    await until(() => store.map.size === 0)
    expect(b.store.get(ID)).toBeUndefined()
  })

  it('fişierul de pe disc e mai scurt decât checkpoint-ul → reia de la mărimea reală', async () => {
    await firstLife()
    srv.hangAt = null
    handle.disk = handle.disk.slice(0, 5000)                  // trunchiat între timp
    const b = await freshModules()
    b.dl.setDownloadUser(7)
    await b.dl.restoreInterruptedDownloads()
    srv.requests.length = 0
    b.dl.resumeInterrupted(ID)
    await until(() => b.store.get(ID)?.state === 'done')
    expect(srv.requests[0]).toBe('bytes=5000-')
    expect(handle.disk).toEqual(srv.data)
  })

  it('pauza comite pe disc tot ce s-a scris (un reload după pauză nu pierde nimic)', async () => {
    const a = await firstLife()
    await new Promise((r) => setTimeout(r, 50))              // tot ce a trimis serverul e scris (în swap)
    a.dl.pauseDownload(ID)
    await until(() => a.store.get(ID)?.state === 'paused')
    const r = [...store.map.values()][0] as DlRecord
    expect(handle.disk.length).toBe(35_000)
    expect(r.checkpoint).toBe(35_000)
    // reluare în sesiune: redeschide la checkpoint şi termină
    srv.hangAt = null
    a.dl.resumeDownload(ID)
    await until(() => a.store.get(ID)?.state === 'done')
    expect(handle.disk).toEqual(srv.data)
  })

  it('logout explicit: înregistrările contului se şterg, rândurile întrerupte dispar', async () => {
    await firstLife()
    const b = await freshModules()
    b.dl.setDownloadUser(7)
    await b.dl.restoreInterruptedDownloads()
    expect(b.store.get(ID)?.state).toBe('orphan')
    await b.dl.forgetDownloads()
    expect(store.map.size).toBe(0)
    expect(b.store.get(ID)).toBeUndefined()
  })

  it('Blob (fără File System Access): nimic persistat', async () => {
    const a = await freshModules()
    vi.stubGlobal('window', { setTimeout, clearTimeout, setInterval: () => 0, clearInterval: () => {}, dispatchEvent: () => true })
    vi.stubGlobal('URL', { createObjectURL: () => 'blob:x', revokeObjectURL: () => {} })
    srv.hangAt = null
    a.dl.setDownloadUser(7)
    await a.dl.startDownload({ hostId: 1, hostName: 'nas', path: '/home/u/big.bin', name: 'big.bin', size: 50_000 })
    expect(a.store.get(ID)?.state).toBe('done')
    expect(store.map.size).toBe(0)
  })
})
