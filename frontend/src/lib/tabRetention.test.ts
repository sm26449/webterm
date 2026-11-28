import { describe, expect, it } from 'vitest'
import type { Session } from './api'
import {
  authResetNeeded, CONNECT_FAILS_GONE, initMeansGone, markAlive, markConnectFailed, markGone, newTabRetention,
  reportsAliveOnOpen, retainOpenTabs,
} from './tabRetention'

const GATED = 1
const PLAIN = 2
const mk = (id: string, state: Session['state'] = 'live', host_id = GATED): Session =>
  ({ id, host_id, title: id, note: '', state, created: 0, closed_at: null, exit_status: null } as Session)

const T0 = 1_000_000
// opţiunile unui poll pornit la `at` (implicit: acum, după orice `gone` dat înainte)
const o = (at = T0, gated: number[] = [GATED]) => ({ gatedHosts: new Set(gated), pollStart: at })

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
    retainOpenTabs([mk('a')], ['a'], st, true, { gatedHosts: new Set([GATED]), pollStart })
    expect(st.gone.has('a')).toBe(true)
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 40)).tabs).toEqual([])
  })

  it('listă veche (poll picat): nu tăiem taburi şi nu actualizăm cache-ul', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    const r = retainOpenTabs([mk('a', 'closed')], ['a', 'x'], st, false, o())
    expect(r.tabs).toEqual(['a', 'x'])
    expect(st.cache.get('a')?.state).toBe('live')
  })

  // 3.8.2 (decizia lui Stefan): pe un host 2FA tabul nu expiră cu timpul. Prod 2026-11-27: terminal
  // lăsat în fundal → idle-lock după 5 min → hub-ul blocat lipseşte din listă până la deblocare →
  // tabul (sesiune vie, ataşată, blocată) dispărea la plafonul de 65 min de 3.8.1.
  it('3.8.2: sesiune 2FA lipsă din listă oricât de mult (zile) → tabul rămâne', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a'), mk('b', 'live', PLAIN)], ['a', 'b'], st, true, o())
    for (const t of [T0 + 3_900_001, T0 + 86_400_000, T0 + 7 * 86_400_000]) {
      expect(retainOpenTabs([mk('b', 'live', PLAIN)], ['a', 'b'], st, true, o(t)).tabs).toEqual(['a', 'b'])
    }
  })

  it('3.8.2: 9 taburi, cel 2FA nemontat (fără socket, fără niciun semnal) → rămâne', () => {
    const st = newTabRetention()
    const plain = Array.from({ length: 8 }, (_, i) => mk('p' + i, 'live', PLAIN))
    const open = ['a', ...plain.map((x) => x.id)]
    retainOpenTabs([mk('a'), ...plain], open, st, true, o())
    const r = retainOpenTabs(plain, open, st, true, o(T0 + 10 * 3_600_000))
    expect(r.tabs).toEqual(open)
    expect(r.sessions.map((x) => x.id)).toEqual([...plain.map((x) => x.id), 'a'])
  })

  it('3.8.2: clic pe tabul reţinut → sesiunea încheiată la ataşare (onGone) → se închide, oricât de târziu', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    const late = T0 + 5 * 3_600_000
    expect(retainOpenTabs([], ['a'], st, true, o(late)).tabs).toEqual(['a'])
    markAlive(st, 'a')               // socketul s-a deschis…
    markGone(st, 'a', late + 1)      // …şi `init` a spus că sesiunea e încheiată
    expect(retainOpenTabs([], ['a'], st, true, o(late + 2)).tabs).toEqual([])
  })

  it('3.8.2: lista proaspătă o arată încheiată, apoi lipseşte → se închide', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    expect(retainOpenTabs([mk('a', 'closed')], ['a'], st, true, o(T0 + 5000)).tabs).toEqual(['a'])
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 10_000)).tabs).toEqual([])
  })

  it('tab închis: cache-ul şi semnalul lui se curăţă', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    markGone(st, 'a', T0)
    retainOpenTabs([], [], st, true, o())
    expect(st.cache.size).toBe(0)
    expect(st.gone.size).toBe(0)
  })

  // review L1: tab reţinut montat, reconectările refuzate înainte de accept (1006, după prima deschidere)
  it('L1: refuzuri consecutive de conectare, listă proaspătă fără sesiune → se închide după prag', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    for (let i = 1; i < CONNECT_FAILS_GONE; i++) markConnectFailed(st, 'a')
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 5000)).tabs).toEqual(['a'])
    markConnectFailed(st, 'a')
    // poll picat (gateway jos): nu tăiem, oricâte refuzuri
    expect(retainOpenTabs([], ['a'], st, false, o(T0 + 6000)).tabs).toEqual(['a'])
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 10_000)).tabs).toEqual([])
  })

  it('L1: o deschidere reuşită (onAlive) resetează numărătoarea; sesiunea încă în listă nu e tăiată', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    for (let i = 0; i < CONNECT_FAILS_GONE; i++) markConnectFailed(st, 'a')
    expect(retainOpenTabs([mk('a')], ['a'], st, true, o(T0 + 1000)).tabs).toEqual(['a'])
    markAlive(st, 'a')
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 5000)).tabs).toEqual(['a'])
  })
})

describe('SessionView: semnalele pentru reţinere', () => {
  it('socketul one-shot de istoric al unei sesiuni încheiate nu raportează onAlive', () => {
    expect(reportsAliveOnOpen(false)).toBe(true)
    expect(reportsAliveOnOpen(true)).toBe(false)
  })
  it('init cu o stare ne-vie = sesiune încheiată (onGone)', () => {
    expect(initMeansGone('live')).toBe(false)
    expect(initMeansGone('creating')).toBe(false)
    for (const st of ['closed', 'lost', undefined, null, '']) expect(initMeansGone(st)).toBe(true)
  })
  it('flux complet: tab reţinut nemontat, click → init closed → se închide (exit nu mai e „anulat" de onAlive)', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    if (reportsAliveOnOpen(false)) markAlive(st, 'a')
    if (initMeansGone('closed')) markGone(st, 'a', T0 + 1)
    if (reportsAliveOnOpen(true)) markAlive(st, 'a')      // socketul de istoric de după exit
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 2)).tabs).toEqual([])
  })
})

// review M1: taburile 2FA reţinute nu expiră → nu trec de la un cont la altul în acelaşi browser
describe('authResetNeeded', () => {
  const A = { authenticated: true, user_id: 1 }
  it('prima stare a paginii (reload cu sesiune validă): nimic de golit', () => {
    expect(authResetNeeded(null, A)).toBe(false)
  })
  it('acelaşi cont, aceeaşi stare (poll-ul de 5 min): nu goleşte', () => {
    expect(authResetNeeded(A, { ...A })).toBe(false)
  })
  it('ieşire / expirare (wt-unauth) → goleşte', () => {
    expect(authResetNeeded(A, { authenticated: false, user_id: null })).toBe(true)
  })
  it('alt cont (fără 401 între ele) → goleşte', () => {
    expect(authResetNeeded(A, { authenticated: true, user_id: 2 })).toBe(true)
  })
  it('intrare (inclusiv re-intrarea aceluiaşi cont) → goleşte', () => {
    expect(authResetNeeded({ authenticated: false, user_id: null }, A)).toBe(true)
  })
  it('flux: A reţine un tab 2FA, iese, intră B → reţinerea nouă nu mai are tabul', () => {
    let st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true, o())
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 5000)).tabs).toEqual(['a'])
    if (authResetNeeded(A, { authenticated: false, user_id: null })) st = newTabRetention()
    expect(retainOpenTabs([], ['a'], st, true, o(T0 + 10_000)).tabs).toEqual([])
  })
})
