/* Regresii din auditul funcţional al 3.6.3 (rezolvate în 3.6.4). */
import { describe, expect, it } from 'vitest'
import { ApiError, errText } from './api'
import { initialFleet, settleFleet } from './fleetLoad'
import en from '../lang/en'
import ro from '../lang/ro'

const cat = (c: unknown) => ((c as { strings?: Record<string, string> }).strings ?? c) as Record<string, string>
const mkT = (dict: Record<string, string>) => (k: string, v?: Record<string, string | number>) => {
  let s = dict[k] ?? k
  for (const [a, b] of Object.entries(v ?? {})) s = s.split('{' + a + '}').join(String(b))
  return s
}

describe('#1 flota: eroare ≠ gol', () => {
  const ok = <T,>(value: T) => ({ status: 'fulfilled', value }) as const
  const bad = (reason: unknown) => ({ status: 'rejected', reason }) as const
  const err = (e: unknown) => String((e as Error).message)

  it('sesiuni picate: hosturile se folosesc, sesiunile rămân cele vechi, eroarea e raportată', () => {
    const f1 = settleFleet(initialFleet<string, string>(), ok(['h1', 'h2']), ok(['s1']), err)
    const f2 = settleFleet(f1, ok(['h1', 'h2', 'h3']), bad(new Error('500')), err)
    expect(f2.hosts).toEqual(['h1', 'h2', 'h3'])
    expect(f2.sessions).toEqual(['s1'])
    expect(f2.sessionsErr).toBe('500')
    expect(f2.hostsLoaded).toBe(true)
  })
  it('prima încărcare picată: NU e „încărcat" (deci nu „nu ai niciun host")', () => {
    const f = settleFleet(initialFleet<string, string>(), bad(new Error('down')), bad(new Error('down')), err)
    expect(f.hostsLoaded).toBe(false)
    expect(f.hosts).toEqual([])
    expect(f.hostsErr).toBe('down')
  })
  it('hosturi picate după o încărcare reuşită: lista veche rămâne, încă „încărcat"', () => {
    const f1 = settleFleet(initialFleet<string, string>(), ok(['h1']), ok([]), err)
    const f2 = settleFleet(f1, bad(new Error('x')), ok(['s']), err)
    expect(f2.hosts).toEqual(['h1'])
    expect(f2.hostsLoaded).toBe(true)
    expect(f2.hostsErr).toBe('x')
    expect(f2.sessionsErr).toBeNull()
  })
})

describe('#4 errText arată detaliul serverului', () => {
  for (const [name, dict] of [['en', cat(en)], ['ro', cat(ro)]] as const) {
    it(`${name}: services.failed / docker.failed includ mesajul`, () => {
      const t = mkT(dict)
      const e = new ApiError(400, 'Failed to stop cron.service: Access denied', 'services.failed')
      expect(errText(e, t)).toContain('Failed to stop cron.service: Access denied')
      const d = new ApiError(400, 'Error response from daemon: No such container', 'docker.failed')
      expect(errText(d, t)).toContain('No such container')
      expect(errText(d, t)).not.toContain('{detail}')
    })
  }
})
