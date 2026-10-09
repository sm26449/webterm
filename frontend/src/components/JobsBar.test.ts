import { describe, expect, it } from 'vitest'
import { jobStatusParts, jobStatusText } from './JobsBar'
import type { UploadJob } from '../lib/uploadStore'

const t = (k: string, v?: Record<string, string | number>) => (v ? `${k}(${Object.values(v).join(',')})` : k)
const job = (p: Partial<UploadJob>): UploadJob => ({
  id: 'x', hostId: 1, hostName: 'a', dest: '/d', name: 'n', size: 100, pos: 40, pct: 40, bytesPerSec: 0,
  etaSec: null, state: 'running', attempts: 1, ...p,
})

// Rândul din Transferuri: textul lung (fişierul în lucru, rezumatul, eroarea) pe linia a doua,
// ca să nu strivească numele (capturile 3.5.17 ale copierii de foldere).
describe('jobStatusParts', () => {
  it('copiere în curs: % + viteză pe linia numelui, fişierul + numărătorile dedesubt', () => {
    const p = jobStatusParts(job({ dir: 'copy', detail: '→ logs/a.log · files 6/14 · folders 2/3' }), t)
    expect(p.head).toBe('40% · 0 B/s')
    expect(p.extra).toBe('→ logs/a.log · files 6/14 · folders 2/3')
  })
  it('copiere gata: „100% · Done" + rezumatul', () => {
    const p = jobStatusParts(job({ dir: 'copy', state: 'done', pct: 100, detail: 'files 8/8 · not copied: 1' }), t)
    expect(p).toEqual({ head: '100% · jobs.stateDone', extra: 'files 8/8 · not copied: 1' })
  })
  it('eroare: „Failed" scurt + motivul (şi, la copiere, numărătorile)', () => {
    expect(jobStatusParts(job({ state: 'err', error: 'disk full' }), t)).toEqual({ head: 'jobs.stateFailed', extra: 'disk full' })
    expect(jobStatusParts(job({ dir: 'copy', state: 'err', error: 'a: denied', detail: 'failed: 1' }), t).extra)
      .toBe('a: denied · failed: 1')
  })
  it('upload neterminat: % sus, explicaţia jos', () => {
    expect(jobStatusParts(job({ state: 'orphan' }), t)).toEqual({ head: '40%', extra: 'jobs.stateOrphan' })
  })
  it('upload simplu: totul pe o linie, fără a doua', () => {
    const p = jobStatusParts(job({ state: 'done', pct: 100 }), t)
    expect(p).toEqual({ head: '100% · jobs.stateDone', extra: '' })
    expect(jobStatusText(job({ state: 'orphan' }), t)).toBe('40% · jobs.stateOrphan')
  })
})
