import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { _resetSheetState, claimSheetHistory, lockBodyScroll, PHONE_QUERY, SHEET_QUERY } from './sheet'

/* Istoric de browser minimal: stivă de intrări + `popstate` ASINCRON la back(), ca în browser
   (exact asincronia care face comutarea Files → Git delicată). */
class FakeHistory {
  entries: { state: unknown; url: string }[] = [{ state: null, url: '#/s/abc' }]
  idx = 0
  backCalls = 0
  constructor(private fire: () => void) {}
  get state() { return this.entries[this.idx].state }
  get url() { return this.entries[this.idx].url }
  pushState(state: unknown, _t: string, url?: string) {
    this.entries = this.entries.slice(0, this.idx + 1)
    this.entries.push({ state, url: url ?? this.url })
    this.idx++
  }
  back() {
    this.backCalls++
    setTimeout(() => { if (this.idx > 0) { this.idx--; this.fire() } }, 0)
  }
  /** navigare pe hash (location.hash = …): intrare nouă, fără state */
  navigate(url: string) { this.pushState(null, '', url) }
}

let hist: FakeHistory
let listeners: Array<() => void>
const g = globalThis as unknown as { window?: unknown; document?: unknown }

beforeEach(() => {
  vi.useFakeTimers()
  listeners = []
  hist = new FakeHistory(() => listeners.forEach((l) => l()))
  g.window = {
    history: hist,
    addEventListener: (type: string, fn: () => void) => { if (type === 'popstate') listeners.push(fn) },
    removeEventListener: (_type: string, fn: () => void) => { listeners = listeners.filter((l) => l !== fn) },
  }
  g.document = { body: { style: { overflow: '' } } }
})
afterEach(() => {
  _resetSheetState()
  vi.useRealTimers()
  delete g.window
  delete g.document
})

describe('media queries', () => {
  it('foaia: sub sm SAU telefon în peisaj (pointer grosier + înălţime mică)', () => {
    expect(SHEET_QUERY).toContain('max-width: 639.98px')
    expect(SHEET_QUERY).toContain('(pointer: coarse) and (max-height: 480px)')
    expect(PHONE_QUERY).toBe('(max-width: 639.98px)')
  })
})

describe('claimSheetHistory (butonul Back de Android)', () => {
  it('deschiderea împinge o intrare marcată CU ACELAŞI URL (rutele pe hash rămân neatinse)', () => {
    claimSheetHistory(() => {})
    expect(hist.entries).toHaveLength(2)
    expect(hist.url).toBe('#/s/abc')
    expect(hist.state).toMatchObject({ __wtSheet: true })
  })

  it('Back închide foaia, iar cleanup-ul de după nu mai consumă încă o intrare', () => {
    const close = vi.fn()
    const release = claimSheetHistory(close)
    hist.back()                       // userul apasă Back
    vi.runAllTimers()
    expect(close).toHaveBeenCalledTimes(1)
    expect(hist.idx).toBe(0)
    release()                         // panoul se demontează după onClose
    vi.runAllTimers()
    expect(hist.backCalls).toBe(1)    // doar Back-ul userului
    expect(hist.idx).toBe(0)
  })

  it('închiderea din UI (← Terminal / Escape) consumă intrarea, fără să cheme close a doua oară', () => {
    const close = vi.fn()
    const release = claimSheetHistory(close)
    release()
    vi.runAllTimers()
    expect(hist.backCalls).toBe(1)
    expect(hist.idx).toBe(0)
    expect(close).not.toHaveBeenCalled()
  })

  it('comutarea directă Files → Git în acelaşi commit refoloseşte intrarea (nu închide noul panou)', () => {
    const closeA = vi.fn()
    const closeB = vi.fn()
    const releaseA = claimSheetHistory(closeA)
    releaseA()                        // cleanup Files…
    claimSheetHistory(closeB)         // …şi mount Git, în acelaşi commit
    vi.runAllTimers()
    expect(hist.backCalls).toBe(0)
    expect(hist.entries).toHaveLength(2)
    expect(hist.state).toMatchObject({ __wtSheet: true })
    hist.back()
    vi.runAllTimers()
    expect(closeB).toHaveBeenCalledTimes(1)
    expect(closeA).not.toHaveBeenCalled()
  })

  it('după o navigare pe hash, cleanup-ul nu mai dă back (ar anula navigarea)', () => {
    const release = claimSheetHistory(() => {})
    hist.navigate('#/s/other')
    release()
    vi.runAllTimers()
    expect(hist.backCalls).toBe(0)
    expect(hist.url).toBe('#/s/other')
  })

  it('o intrare deja marcată nu se dublează la re-claim (StrictMode: mount/cleanup/mount)', () => {
    const close = vi.fn()
    const r1 = claimSheetHistory(close)
    r1()
    claimSheetHistory(close)
    vi.runAllTimers()
    expect(hist.entries).toHaveLength(2)
    expect(hist.backCalls).toBe(0)
  })
})

describe('lockBodyScroll', () => {
  it('numărat: două foi suprapuse nu se deblochează reciproc', () => {
    const body = (g.document as { body: { style: { overflow: string } } }).body
    body.style.overflow = 'auto'
    const u1 = lockBodyScroll()
    const u2 = lockBodyScroll()
    expect(body.style.overflow).toBe('hidden')
    u1()
    u1()                              // idempotent
    expect(body.style.overflow).toBe('hidden')
    u2()
    expect(body.style.overflow).toBe('auto')
  })
})
