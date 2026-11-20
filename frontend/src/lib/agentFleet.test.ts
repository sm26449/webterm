import { describe, expect, it } from 'vitest'
import {
  eventMatches, filterFleet, fleetDuration, fleetMtls, fleetVersions, routeKey, sortFleet, type FleetAgent,
} from './agentFleet'
import { mtlsState } from './mtls'

const base: FleetAgent = {
  id: 1, name: 'alpha', folder: 'prod', online: true, route: 'mtls', mtls_required: true, mtls_issued: true,
  mtls_not_after: 2e9, agent_version: 60, agent_ip: '198.51.100.7', connected_since: 1, last_heartbeat: 2,
  reconnects_24h: 0,
}
const a = (o: Partial<FleetAgent>): FleetAgent => ({ ...base, ...o })

const list = [
  a({ id: 1, name: 'zeta', route: 'token', mtls_required: false, agent_version: 59 }),
  a({ id: 2, name: 'Alpha' }),
  a({ id: 3, name: 'beta', online: false, route: null, folder: 'lab', agent_ip: '10.0.0.4' }),
  a({ id: 4, name: 'gamma', route: 'mtls', mtls_required: false }),
]
const all = { q: '', route: 'all' as const, version: '' }

describe('agentFleet', () => {
  it('sorts online first, offline last, then by name (case-insensitive)', () => {
    expect(sortFleet(list).map((x) => x.name)).toEqual(['Alpha', 'gamma', 'zeta', 'beta'])
  })
  it('filters by route, offline and version', () => {
    expect(filterFleet(list, { ...all, route: 'mtls' }).map((x) => x.id)).toEqual([2, 4])
    expect(filterFleet(list, { ...all, route: 'token' }).map((x) => x.id)).toEqual([1])
    expect(filterFleet(list, { ...all, route: 'offline' }).map((x) => x.id)).toEqual([3])
    expect(filterFleet(list, { ...all, version: '59' }).map((x) => x.id)).toEqual([1])
  })
  it('searches name, IP and folder', () => {
    expect(filterFleet(list, { ...all, q: 'ALP' }).map((x) => x.id)).toEqual([2])
    expect(filterFleet(list, { ...all, q: '10.0.0' }).map((x) => x.id)).toEqual([3])
    expect(filterFleet(list, { ...all, q: ' lab ' }).map((x) => x.id)).toEqual([3])
    expect(filterFleet(list, { ...all, q: 'nothing' })).toEqual([])
  })
  it('route words: required beats plain mTLS; offline has none', () => {
    expect(routeKey(list[1])).toBe('health.agents.route.mtlsRequired')
    expect(routeKey(list[3])).toBe('health.agents.route.mtls')
    expect(routeKey(list[0])).toBe('health.agents.route.token')
    expect(routeKey(list[2])).toBe('health.agents.route.none')
  })
  it('versions newest first; certificate via lib/mtls', () => {
    expect(fleetVersions({ online: 0, offline: 0, mtls: 0, token: 0, versions: { 59: 1, 60: 3 } }))
      .toEqual([['60', 3], ['59', 1]])
    expect(mtlsState(fleetMtls(list[1]))).toBe('required')
    expect(mtlsState(fleetMtls(a({ mtls_required: false, mtls_issued: false })))).toBe('none')
  })
  it('durations', () => {
    const t = (k: string, v?: Record<string, string | number>) => k + JSON.stringify(v)
    expect(fleetDuration(30, t)).toBe('health.agents.dur.s{"n":30}')
    expect(fleetDuration(600, t)).toBe('health.agents.dur.m{"n":10}')
    expect(fleetDuration(3 * 3600 + 600, t)).toBe('health.agents.dur.hm{"h":3,"m":10}')
    expect(fleetDuration(2 * 86400 + 3600, t)).toBe('health.agents.dur.dh{"d":2,"h":1}')
  })
  it('event filter', () => {
    const evs = [
      { event: 'connect', detail: 'v60 · mTLS' }, { event: 'connect', detail: 'v60 · token' },
      { event: 'disconnect', reason: 'closed' }, { event: 'update_pushed' }, { event: 'update_refused' },
      { event: 'handshake_refused', reason: 'handshake_mtls_missing' },
      { event: 'handshake_refused', reason: 'handshake_bad_token' }, { event: 'mtls_provisioned' },
    ]
    const pick = (f: Parameters<typeof eventMatches>[1]) => evs.map((e, i) => (eventMatches(e, f) ? i : -1)).filter((i) => i >= 0)
    expect(pick('all')).toHaveLength(evs.length)
    expect(pick('connections')).toEqual([0, 1, 2])
    expect(pick('refusals')).toEqual([4, 5, 6])
    expect(pick('updates')).toEqual([3, 4])
    expect(pick('mtls')).toEqual([0, 5, 7])
  })
})
