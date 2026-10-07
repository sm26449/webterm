import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CopyStatus, cancelCopy, copyLabel, copyPatch, copyRowId, dismissCopy, fileErrText, startCopy } from './copyjobs'
import { numberedName } from './downloads'
import { canPause, isCopy, sizeKnown, uploadStore } from './uploadStore'

// `t` de test: întoarce cheia + variabilele, ca aserţiunile să vadă CE s-a ales, nu traducerea
const t = (k: string, v?: Record<string, string | number>) =>
  (k === 'err.files.notRegular' ? 'not a regular file (tr)' : k.startsWith('err.') ? k : k + (v ? JSON.stringify(v) : ''))

const st = (o: Partial<CopyStatus> = {}): CopyStatus => ({
  job_id: 'j1', state: 'running', src_host: 1, src_host_name: 'a', dst_host: 2, dst_host_name: 'b', dst_dir: '/in',
  on_conflict: 'skip', total_bytes: 1000, done_bytes: 250, files_total: 4, files_done: 1, files_skipped: 0,
  files_failed: 0, errors: [], ...o,
})

describe('copyPatch: starea serverului → rândul din Transferuri', () => {
  it('running: % pe octeţi + rezumatul fişierelor', () => {
    const p = copyPatch(st(), t)
    expect(p.state).toBe('running')
    expect(p.pct).toBe(25)
    expect(p.pos).toBe(250)
    expect(p.size).toBe(1000)
    expect(p.detail).toContain('transfers.copyFiles')
  })
  it('total încă necunoscut (faza de stat) → 0%, nu NaN', () => {
    expect(copyPatch(st({ total_bytes: 0, done_bytes: 0 }), t).pct).toBe(0)
  })
  it('done → 100%, cu sărite în detaliu', () => {
    const p = copyPatch(st({ state: 'done', done_bytes: 1000, files_done: 3, files_skipped: 1 }), t)
    expect(p.state).toBe('done')
    expect(p.pct).toBe(100)
    expect(p.detail).toContain('transfers.copySkipped')
  })
  it('done cu toate fişierele sărite (total 0) → tot 100%', () => {
    expect(copyPatch(st({ state: 'done', total_bytes: 0, done_bytes: 0 }), t).pct).toBe(100)
  })
  it('failed → err cu PRIMA eroare: numele fişierului + codul tradus', () => {
    const p = copyPatch(st({
      state: 'failed', files_failed: 2,
      errors: [{ src: '/dev/zero', name: 'zero', dst: '', size: 0, done: 0, state: 'err', error: 'raw', code: 'files.notRegular' }],
    }), t)
    expect(p.state).toBe('err')
    expect(p.error).toBe('zero: not a regular file (tr)')
    expect(p.detail).toContain('transfers.copyFailed')
  })
  it('cod necunoscut în catalog → mesajul brut al serverului', () => {
    expect(fileErrText({ src: '', name: 'x', dst: '', size: 0, done: 0, state: 'err', error: 'boom', code: 'nope.nope' }, t)).toBe('boom')
  })
  it('cancelled → cancelled, fără viteză', () => {
    const p = copyPatch(st({ state: 'cancelled' }), t)
    expect(p.state).toBe('cancelled')
    expect(p.bytesPerSec).toBe(0)
  })
  it('eticheta: un fişier = numele lui; mai multe = „N fişiere"', () => {
    expect(copyLabel(['/a/b/raport.pdf'], t)).toBe('raport.pdf')
    expect(copyLabel(['/a/x', '/a/y'], t)).toBe('transfers.copyNFiles{"n":2}')
  })
})

describe('tipul de job în store', () => {
  it('copy: fără pauză; arhivă: fără pauză şi fără mărime cunoscută', () => {
    const base = { id: 'x', hostId: 1, hostName: 'h', dest: '/', name: 'n', size: 0, pos: 0, pct: 0, bytesPerSec: 0, etaSec: null, state: 'running' as const, attempts: 1 }
    expect(isCopy({ ...base, dir: 'copy' })).toBe(true)
    expect(canPause({ ...base, dir: 'copy' })).toBe(false)
    expect(canPause({ ...base, dir: 'down', kind: 'archive' })).toBe(false)
    expect(canPause({ ...base, dir: 'down', size: 10 })).toBe(true)
    expect(canPause(base)).toBe(true)
    expect(sizeKnown({ ...base, dir: 'down', kind: 'archive' })).toBe(false)
    expect(sizeKnown({ ...base, size: 5 })).toBe(true)
  })
  it('numberedName: aceeaşi regulă ca rename-ul de pe gateway', () => {
    expect(numberedName('raport.pdf', 1)).toBe('raport (1).pdf')
    expect(numberedName('a.tar.gz', 2)).toBe('a (2).tar.gz')
    expect(numberedName('.bashrc', 1)).toBe('.bashrc (1)')
    expect(numberedName('Makefile', 3)).toBe('Makefile (3)')
  })
})

describe('motorul de copiere: POST → rând în store → polling → done / cancel', () => {
  const calls: { url: string; method: string; body?: string }[] = []
  let status: CopyStatus
  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('window', { setTimeout, clearTimeout, dispatchEvent: () => true })
    vi.stubGlobal('navigator', { languages: ['en'], language: 'en' })
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => {} })
    calls.length = 0
    status = st({ job_id: 'abc' })
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      calls.push({ url, method, body: init?.body as string | undefined })
      const json = url === '/api/fs/copy' && method === 'POST' ? { job_id: 'abc', dst_dir: '/home/u/in' }
        : method === 'DELETE' ? { ...status, state: 'cancelled' } : status
      return new Response(JSON.stringify(json), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }))
  })
  afterEach(() => {
    dismissCopy(copyRowId('abc'))
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('porneşte: corpul POST corect + rând `copy` cu „A → B"', async () => {
    const id = await startCopy({ srcHost: 1, srcName: 'alpha', dstHost: 2, dstName: 'beta',
      paths: ['/s/a', '/s/b'], dstDir: '~/in', onConflict: 'rename' })
    expect(JSON.parse(calls[0].body!)).toEqual({ src_host: 1, paths: ['/s/a', '/s/b'], dst_host: 2, dst_dir: '~/in', on_conflict: 'rename' })
    const row = uploadStore.get(id)!
    expect(row.dir).toBe('copy')
    expect(row.hostName).toBe('alpha → beta')
    expect(row.dest).toBe('/home/u/in')              // dst_dir canonic de la server
    expect(row.state).toBe('running')
  })
  it('polling-ul aduce progresul, apoi starea finală', async () => {
    const id = await startCopy({ srcHost: 1, srcName: 'a', dstHost: 2, dstName: 'b', paths: ['/s/a'], dstDir: '/in', onConflict: 'skip' })
    await vi.advanceTimersByTimeAsync(1100)
    expect(uploadStore.get(id)!.pct).toBe(25)
    status = st({ job_id: 'abc', state: 'done', done_bytes: 1000, files_done: 4 })
    await vi.advanceTimersByTimeAsync(1100)
    expect(uploadStore.get(id)!.state).toBe('done')
    const polls = calls.filter((c) => c.url.startsWith('/api/fs/copy/abc')).length
    await vi.advanceTimersByTimeAsync(5000)
    expect(calls.filter((c) => c.url.startsWith('/api/fs/copy/abc')).length).toBe(polls)   // nu mai pollează
  })
  it('cancel: DELETE pe job + rândul trece în cancelled', async () => {
    const id = await startCopy({ srcHost: 1, srcName: 'a', dstHost: 2, dstName: 'b', paths: ['/s/a'], dstDir: '/in', onConflict: 'skip' })
    await cancelCopy(id)
    expect(calls.some((c) => c.method === 'DELETE' && c.url === '/api/fs/copy/abc')).toBe(true)
    expect(uploadStore.get(id)!.state).toBe('cancelled')
  })
})
