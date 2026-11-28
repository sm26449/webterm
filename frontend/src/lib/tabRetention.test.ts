import { describe, expect, it } from 'vitest'
import type { Session } from './api'
import { markAlive, markDetached, markGone, newTabRetention, RETAIN_MAX_MS, retainOpenTabs } from './tabRetention'

const GATED = 1
const PLAIN = 2
const mk = (id: string, state: Session['state'] = 'live', host_id = GATED): Session =>
  ({ id, host_id, title: id, note: '', state, created: 0, closed_at: null, exit_status: null } as Session)

const T0 = 1_000_000
// opţiunile unui poll pornit la `at` (implicit: acum, după orice `gone` dat înainte)
const o = (at = T0, gated: number[] = [GATED]) => ({ gatedHosts: new Set(gated), pollStart: at, now: at })

describe('retainOpenTabs', () => {
  it('sesiunea prezentă: tabul rămâne, lista neschimbată', () => {
    const st = newTabRetention()
    const list = [mk('a'), mk('b')]
    const r = retainOpenTabs(list, ['a'], st, true, o())
    expect(r.tabs).toEqual(['a'])
    expect(r.sessions).toBe(list)
  })

  it('sesiune vie de pe un host 2FA care dispare din listă: tabul rămâne, randat din cache', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a'), mk('b')], ['a', 'b'], st, true, o())
    const r = retainOpenTabs([mk('b')], ['a', 'b'], st, true, o(T0 + 5000))
    expect(r.tabs).toEqual(['a', 'b'])
    expect(r.sessions.map((s) => s.id)).toEqual(['b', 'a'])
  })

  it('M2: host FĂRĂ require_2fa → lipsa din listă închide tabul (ştearsă / revocată)', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a', 'live', PLAIN)], ['a'], st, true, o())
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 5000)).tabs).toEqual([])
  })

  it('M2: hostul nu mai e 2FA (sau nu mai e în lista de hosturi) → nu se mai reţine', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 5000, [])).tabs).toEqual([])
  })

  it('M2: reţinerea expiră după plafonul de step-up + marjă de la ultima apariţie', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + RETAIN_MAX_MS)).tabs).toEqual(['a'])
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + RETAIN_MAX_MS + 1)).tabs).toEqual([])
  })

  it('M2: o reapariţie în listă reporneşte ceasul reţinerii', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    retainOpenTabs([mk('a')], ['a'], st, true, o(T0 + 3_000_000))
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + RETAIN_MAX_MS + 1)).tabs).toEqual(['a'])
  })

  it('lipsă + raportată încheiată de SessionView → tabul se închide', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    markGone(st, 'a', T0 + 1)
    const r = retainOpenTabs([], ['a'], st, true, o(T0 + 2))
    expect(r.tabs).toEqual([])
    expect(r.sessions).toEqual([])
  })

  it('handshake refuzat apoi socket deschis (onAlive) → semnalul se anulează, tabul rămâne', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    markGone(st, 'a', T0 + 1)
    markAlive(st, 'a')
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 2)).tabs).toEqual(['a'])
  })

  it('lipsă + ultima stare văzută închisă → tabul se închide', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a', 'closed')], ['a'], st, true, o())
    expect(retainOpenTabs([], ['a'], st, true, o()).tabs).toEqual([])
  })

  it('lipsă fără nimic în cache (ex. după reload) → se închide ca înainte', () => {
    const st = newTabRetention()
    expect(retainOpenTabs([], ['a'], st, true, o()).tabs).toEqual([])
  })

  it('raportată încheiată dar încă în listă (sesiune închisă) → tabul rămâne', () => {
    const st = newTabRetention()
    markGone(st, 'a', T0 - 1)
    expect(retainOpenTabs([mk('a', 'closed')], ['a'], st, true, o()).tabs).toEqual(['a'])
  })

  it('revine vie în listă (reconectare telnet) → semnalul vechi de „încheiată" se şterge', () => {
    const st = newTabRetention()
    markGone(st, 'a', T0 - 1)
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    expect(st.gone.has('a')).toBe(false)
    expect(retainOpenTabs([], ['a'], st, true, o()).tabs).toEqual(['a'])
  })

  it('L1: un poll pornit ÎNAINTE de raport nu şterge `gone` cu citirea lui „vie"', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    const pollStart = T0 + 10
    markGone(st, 'a', T0 + 20)                  // 4404 cât poll-ul era în zbor
    retainOpenTabs([mk('a')], ['a'], st, true, { gatedHosts: new Set([GATED]), pollStart, now: T0 + 30 })
    expect(st.gone.has('a')).toBe(true)
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 40)).tabs).toEqual([])
  })

  it('listă veche (poll picat): nu tăiem taburi şi nu actualizăm cache-ul', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    const r = retainOpenTabs([mk('a', 'closed')], ['a', 'x'], st, false, o())
    expect(r.tabs).toEqual(['a', 'x'])
    expect(st.cache.get('a')?.s.state).toBe('live')
  })

  // 3.8.2 (raport Stefan, prod 2026-11-27): terminal 2FA lăsat în fundal → idle-lock după 5 min →
  // hub-ul blocat iese din listă şi nu mai revine până la deblocare. Plafonul curgea de la ultima
  // apariţie în listă, deci tabul (ataşat, blocat, sesiune vie) dispărea la ~65 min după blocare.
  it('3.8.2: socket deschis (blocat în fundal) → tabul rămâne oricât lipseşte din listă', () => {
    const st = newTabRetention()
    markAlive(st, 'a')
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    for (let t = T0 + 5000; t <= T0 + 3 * RETAIN_MAX_MS; t += 600_000) {
      expect(retainOpenTabs([], ['a'], st, true, o(t)).tabs).toEqual(['a'])
    }
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 3 * RETAIN_MAX_MS + 1)).tabs).toEqual(['a'])
  })

  it('3.8.2: după închiderea socketului plafonul curge de la ultima dovadă (socketul), nu de la listă', () => {
    const st = newTabRetention()
    markAlive(st, 'a')
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    const t1 = T0 + 2 * RETAIN_MAX_MS
    retainOpenTabs([], ['a'], st, true, o(t1))          // încă ataşat: dovadă la t1
    markDetached(st, 'a')                                // demontat / reconectare picată
    expect(retainOpenTabs([], ['a'], st, true, o(t1 + RETAIN_MAX_MS)).tabs).toEqual(['a'])
    expect(retainOpenTabs([], ['a'], st, true, o(t1 + RETAIN_MAX_MS + 1)).tabs).toEqual([])
  })

  it('3.8.2: sesiune încheiată (onGone) cu socketul de istoric deschis → nu e dovadă de viaţă', () => {
    const st = newTabRetention()
    markAlive(st, 'a')
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    markGone(st, 'a', T0 + 1)
    expect(st.attached.has('a')).toBe(false)
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 2)).tabs).toEqual([])
  })

  it('3.8.2: socket deschis nu inventează un tab fără cache (ex. după reload) şi nu ocoleşte hostul ne-2FA', () => {
    const st = newTabRetention()
    markAlive(st, 'a')
    expect(retainOpenTabs([], ['a'], st, true, o()).tabs).toEqual([])
    markAlive(st, 'b')
    retainOpenTabs([mk('b', 'live', PLAIN)], ['b'], st, true, o())
    expect(retainOpenTabs([], ['b'], st, true, o(T0 + 5000)).tabs).toEqual([])
  })

  it('tab închis: cache-ul şi semnalul lui se curăţă', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    markGone(st, 'a', T0)
    retainOpenTabs([], [], st, true, o())
    expect(st.cache.size).toBe(0)
    expect(st.gone.size).toBe(0)
  })
})
