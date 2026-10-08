import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DockerStat, cpuShare, fmtMem, fmtPct, matchStats, nextStatsDelay, startPolling, STATS_INTERVAL, STATS_SLOW_INTERVAL, VisibilitySource } from './dockerStats'
import en from '../lang/en'
import ro from '../lang/ro'

const stat = (o: Partial<DockerStat>): DockerStat => ({
  id: '', name: '', cpu_pct: null, mem_used: null, mem_limit: null, mem_pct: null,
  net_rx: null, net_tx: null, block_read: null, block_write: null, pids: null, ...o,
})

describe('potrivirea statisticilor cu rândurile din docker ps', () => {
  const rows = [stat({ id: '3f2a1b4c5d6e', name: 'web' }), stat({ id: 'bbbbbbbbbbbb', name: 'db' })]
  it('id-ul lung din ps începe cu id-ul scurt din stats', () => {
    expect(matchStats(rows, '3f2a1b4c5d6e' + 'f'.repeat(52), 'web')?.name).toBe('web')
  })
  it('rezervă pe nume (şi pe o listă de nume separată prin virgulă)', () => {
    expect(matchStats(rows, 'cccccccccccc', 'db')?.id).toBe('bbbbbbbbbbbb')
    expect(matchStats(rows, '', 'x, db')?.id).toBe('bbbbbbbbbbbb')
  })
  it('nimic pentru un container fără statistici (oprit) sau fără date', () => {
    expect(matchStats(rows, 'dddddddddddd', 'old')).toBeUndefined()
    expect(matchStats(null, 'x', 'y')).toBeUndefined()
    expect(matchStats([stat({ id: '', name: '' })], '', '')).toBeUndefined()
  })
})

describe('formatare', () => {
  it('procente compacte; null pentru lipsă', () => {
    expect(fmtPct(0.42)).toBe('0.4%')
    expect(fmtPct(12.34)).toBe('12%')
    expect(fmtPct(250.5)).toBe('251%')
    expect(fmtPct(null)).toBeNull()
    expect(fmtPct(NaN)).toBeNull()
  })
  it('memorie folosită / limită; fără limită doar folosită; null pentru lipsă', () => {
    expect(fmtMem(12 * 1024 ** 2, 2 * 1024 ** 3)).toBe('12.0 MB / 2.00 GB')
    expect(fmtMem(512, null)).toBe('512 B')
    expect(fmtMem(512, 0)).toBe('512 B')
    expect(fmtMem(null, 100)).toBeNull()
  })
  it('întârzierea: ok → 5 s, indisponibil → 30 s, eroare → stop', () => {
    expect(nextStatsDelay('ok')).toBe(STATS_INTERVAL)
    expect(nextStatsDelay('unavailable')).toBe(STATS_SLOW_INTERVAL)
    expect(nextStatsDelay('error')).toBeNull()
  })
})

class FakeDoc implements VisibilitySource {
  hidden = false
  fns = new Set<() => void>()
  addEventListener(_t: 'visibilitychange', fn: () => void) { this.fns.add(fn) }
  removeEventListener(_t: 'visibilitychange', fn: () => void) { this.fns.delete(fn) }
  set(hidden: boolean) { this.hidden = hidden; this.fns.forEach((f) => f()) }
}

describe('bucla de sondare', () => {
  beforeEach(() => { vi.useFakeTimers() })
  afterEach(() => { vi.useRealTimers() })

  it('rulează imediat, apoi la intervalul întors de tick', async () => {
    const doc = new FakeDoc()
    const tick = vi.fn(async () => 5000)
    const stop = startPolling(tick, doc)
    await vi.advanceTimersByTimeAsync(0)
    expect(tick).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(4999)
    expect(tick).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(tick).toHaveBeenCalledTimes(2)
    stop()
  })

  it('se opreşte cât tabul e ascuns şi reia IMEDIAT la revenire', async () => {
    const doc = new FakeDoc()
    const tick = vi.fn(async () => 5000)
    const stop = startPolling(tick, doc)
    await vi.advanceTimersByTimeAsync(0)
    doc.set(true)
    await vi.advanceTimersByTimeAsync(60000)
    expect(tick).toHaveBeenCalledTimes(1)
    doc.set(false)
    await vi.advanceTimersByTimeAsync(0)
    expect(tick).toHaveBeenCalledTimes(2)
    stop()
  })

  it('nu porneşte deloc dacă tabul e deja ascuns', async () => {
    const doc = new FakeDoc()
    doc.hidden = true
    const tick = vi.fn(async () => 5000)
    const stop = startPolling(tick, doc)
    await vi.advanceTimersByTimeAsync(20000)
    expect(tick).not.toHaveBeenCalled()
    stop()
  })

  it('oprirea (panou închis) anulează timerul şi ascultătorul', async () => {
    const doc = new FakeDoc()
    const tick = vi.fn(async () => 5000)
    const stop = startPolling(tick, doc)
    await vi.advanceTimersByTimeAsync(0)
    stop()
    expect(doc.fns.size).toBe(0)
    await vi.advanceTimersByTimeAsync(60000)
    expect(tick).toHaveBeenCalledTimes(1)
  })

  it('null (eroare) opreşte bucla — fără furtună de cereri, nici la revenirea vizibilităţii', async () => {
    const doc = new FakeDoc()
    const tick = vi.fn(async () => null)
    const stop = startPolling(tick, doc)
    await vi.advanceTimersByTimeAsync(60000)
    doc.set(true); doc.set(false)
    await vi.advanceTimersByTimeAsync(60000)
    expect(tick).toHaveBeenCalledTimes(1)
    stop()
  })

  it('o excepţie în tick e tratată ca eroare (stop), nu ca promisiune respinsă necapturată', async () => {
    const doc = new FakeDoc()
    const tick = vi.fn(async () => { throw new Error('x') })
    const stop = startPolling(tick, doc)
    await vi.advanceTimersByTimeAsync(20000)
    expect(tick).toHaveBeenCalledTimes(1)
    stop()
  })

  it('tick-urile nu se suprapun (un tick lent + revenire la vizibil)', async () => {
    const doc = new FakeDoc()
    let live = 0
    let maxLive = 0
    const tick = vi.fn(async () => {
      live++; maxLive = Math.max(maxLive, live)
      await new Promise((r) => setTimeout(r, 8000))
      live--
      return 5000
    })
    const stop = startPolling(tick, doc)
    await vi.advanceTimersByTimeAsync(1000)
    doc.set(true); doc.set(false)
    await vi.advanceTimersByTimeAsync(30000)
    expect(maxLive).toBe(1)
    stop()
  })
})

describe('CPU relativ la host (3.5.15)', () => {
  it('împarte la nucleele hostului: 96% dintr-un nucleu pe 8 nuclee = 12% din host', () => {
    const s = cpuShare(96, 8)
    expect(s.hostPct).toBe(12)
    expect(s.corePct).toBe(96)
    expect(s.pressure).toBe(12)          // culoarea de prag urmează valoarea normalizată
    expect(fmtPct(s.hostPct)).toBe('12%')
  })
  it('400% pe 4 nuclee = 100% din host; o depăşire de eşantionare nu trece de 100%', () => {
    expect(cpuShare(400, 4).hostPct).toBe(100)
    expect(cpuShare(430, 4).hostPct).toBe(100)
    expect(cpuShare(430, 4).corePct).toBe(430)
  })
  it('nuclee necunoscute / invalide → valoarea brută, pragul pe ea', () => {
    for (const n of [null, undefined, 0, -1, 2.5, NaN]) {
      const s = cpuShare(150, n as number | null | undefined)
      expect(s.hostPct).toBeNull()
      expect(s.corePct).toBe(150)
      expect(s.pressure).toBe(150)
    }
  })
  it('fără valoare CPU → nimic de afişat', () => {
    expect(cpuShare(null, 8)).toEqual({ hostPct: null, corePct: null, pressure: 0 })
    expect(cpuShare(NaN, 8).corePct).toBeNull()
    expect(cpuShare(-3, 8).corePct).toBeNull()
  })
  it('textele „din host · dintr-un nucleu" există în EN şi RO, cu ambele valori', () => {
    for (const lang of [en.strings, ro.strings]) {
      expect(lang['docker.stats.cpuBoth']).toContain('{host}')
      expect(lang['docker.stats.cpuBoth']).toContain('{core}')
      expect(lang['docker.stats.cpuPerCore']).toContain('{core}')
      expect(lang['docker.stats.perCoreShort']).toBeTruthy()
    }
  })
})
