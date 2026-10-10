import { describe, expect, it } from 'vitest'
import { exclusive, type Flag } from './guard'

// Modelul lui „Rulează" din FleetRunModal (U02): verificările async (guardrail, step-up) urmate
// de trimitere. Două activări în acelaşi tick NU au voie să trimită de două ori.
function fleetRun() {
  const flag: Flag = { current: false }
  const busy: boolean[] = []
  let dispatched = 0
  let release!: () => void
  const checks = () => new Promise<void>((r) => { release = r })   // guardrail + step-up în curs
  const run = (opts: { cancel?: boolean; fail?: boolean } = {}) => exclusive(flag, async () => {
    await checks()
    if (opts.fail) throw new Error('step-up failed')
    if (opts.cancel) return            // guardrail refuzat de om: nimic nu pleacă
    dispatched++
  }, (b) => busy.push(b))
  return { flag, busy, run, dispatched: () => dispatched, release: () => release() }
}

describe('exclusive (gardă de re-intrare, U02)', () => {
  it('două activări rapide → o singură trimitere', async () => {
    const f = fleetRun()
    const a = f.run()
    const b = f.run()                  // dublu-clic / Enter + clic în acelaşi tick
    expect(await b).toBe(false)        // a doua e ignorată imediat
    f.release()
    expect(await a).toBe(true)
    expect(f.dispatched()).toBe(1)
    expect(f.busy).toEqual([true, false])
  })

  it('steagul e setat SINCRON la prima activare (înainte de orice await)', () => {
    const f = fleetRun()
    void f.run()
    expect(f.flag.current).toBe(true)
  })

  it('anularea (guardrail refuzat) eliberează garda: o rulare nouă e posibilă', async () => {
    const f = fleetRun()
    const a = f.run({ cancel: true }); f.release(); await a
    expect(f.flag.current).toBe(false)
    const b = f.run(); f.release(); await b
    expect(f.dispatched()).toBe(1)
  })

  it('o eroare eliberează garda şi se propagă (nu rămâne blocat „ocupat")', async () => {
    const f = fleetRun()
    const a = f.run({ fail: true }); f.release()
    await expect(a).rejects.toThrow('step-up failed')
    expect(f.flag.current).toBe(false)
    expect(f.busy).toEqual([true, false])
  })
})
