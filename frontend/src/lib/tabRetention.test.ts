import { describe, expect, it } from 'vitest'
import type { Session } from './api'
import { newTabRetention, retainOpenTabs } from './tabRetention'

const mk = (id: string, state: Session['state'] = 'live'): Session =>
  ({ id, host_id: 1, title: id, note: '', state, created: 0, closed_at: null, exit_status: null } as Session)

describe('retainOpenTabs', () => {
  it('sesiunea prezentă: tabul rămâne, lista neschimbată', () => {
    const st = newTabRetention()
    const list = [mk('a'), mk('b')]
    const r = retainOpenTabs(list, ['a'], st, true)
    expect(r.tabs).toEqual(['a'])
    expect(r.sessions).toBe(list)
  })

  it('sesiune vie care dispare din listă (fereastra 2FA închisă): tabul rămâne, randat din cache', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a'), mk('b')], ['a', 'b'], st, true)
    const r = retainOpenTabs([mk('b')], ['a', 'b'], st, true)
    expect(r.tabs).toEqual(['a', 'b'])
    expect(r.sessions.map((s) => s.id)).toEqual(['b', 'a'])
  })

  it('lipsă + raportată încheiată de SessionView → tabul se închide', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true)
    st.gone.add('a')
    const r = retainOpenTabs([], ['a'], st, true)
    expect(r.tabs).toEqual([])
    expect(r.sessions).toEqual([])
  })

  it('lipsă + ultima stare văzută închisă → tabul se închide', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a', 'closed')], ['a'], st, true)
    expect(retainOpenTabs([], ['a'], st, true).tabs).toEqual([])
  })

  it('lipsă fără nimic în cache (ex. după reload) → se închide ca înainte', () => {
    const st = newTabRetention()
    expect(retainOpenTabs([], ['a'], st, true).tabs).toEqual([])
  })

  it('raportată încheiată dar încă în listă (host fără 2FA, sesiune închisă) → tabul rămâne', () => {
    const st = newTabRetention()
    st.gone.add('a')
    expect(retainOpenTabs([mk('a', 'closed')], ['a'], st, true).tabs).toEqual(['a'])
  })

  it('revine vie în listă (reconectare telnet) → semnalul vechi de „încheiată" se şterge', () => {
    const st = newTabRetention()
    st.gone.add('a')
    retainOpenTabs([mk('a')], ['a'], st, true)
    expect(st.gone.has('a')).toBe(false)
    expect(retainOpenTabs([], ['a'], st, true).tabs).toEqual(['a'])
  })

  it('listă veche (poll picat): nu tăiem taburi şi nu actualizăm cache-ul', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true)
    const r = retainOpenTabs([mk('a', 'closed')], ['a', 'x'], st, false)
    expect(r.tabs).toEqual(['a', 'x'])
    expect(st.cache.get('a')?.state).toBe('live')
  })

  it('tab închis: cache-ul şi semnalul lui se curăţă', () => {
    const st = newTabRetention()
    retainOpenTabs([mk('a')], ['a'], st, true)
    st.gone.add('a')
    retainOpenTabs([], [], st, true)
    expect(st.cache.size).toBe(0)
    expect(st.gone.size).toBe(0)
  })
})
