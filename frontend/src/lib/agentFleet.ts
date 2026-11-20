// 3.7.0: System health → Connected agents (GET /api/health/agents). The server decides who is listed
// (only hosts with host.view) and what each route is; this file only filters, sorts and picks words.
import type { HostMtls } from './mtls'

export type FleetRoute = 'mtls' | 'token'

export interface FleetAgent {
  id: number
  name: string
  folder: string
  online: boolean
  route: FleetRoute | null
  mtls_required: boolean
  mtls_issued: boolean
  mtls_not_after: number | null
  agent_version: number | null
  agent_ip: string | null
  connected_since: number | null
  last_heartbeat: number | null
  reconnects_24h: number
}

export interface FleetSummary {
  online: number
  offline: number
  mtls: number
  token: number
  versions: Record<string, number>
}

export interface FleetPayload {
  agents: FleetAgent[]
  summary: FleetSummary
  expected_version: number | null
  now: number
}

export type RouteFilter = 'all' | 'mtls' | 'token' | 'offline'

export interface FleetFilter {
  q: string
  route: RouteFilter
  version: string            // '' = every version
}

/** The same shape the host page uses, so the certificate column reuses lib/mtls. */
export function fleetMtls(a: FleetAgent): HostMtls {
  return { required: a.mtls_required, issued: a.mtls_issued, not_after: a.mtls_not_after, last: null }
}

export function matchesFleet(a: FleetAgent, f: FleetFilter): boolean {
  if (f.route === 'offline' && a.online) return false
  if ((f.route === 'mtls' || f.route === 'token') && a.route !== f.route) return false
  if (f.version && String(a.agent_version ?? '') !== f.version) return false
  const q = f.q.trim().toLowerCase()
  if (!q) return true
  return [a.name, a.agent_ip ?? '', a.folder].some((s) => s.toLowerCase().includes(q))
}

/** Online first (they are what you look for), offline last; then by name. */
export function sortFleet(list: FleetAgent[]): FleetAgent[] {
  return [...list].sort((x, y) => (Number(y.online) - Number(x.online))
    || x.name.localeCompare(y.name, undefined, { sensitivity: 'base' }))
}

export function filterFleet(list: FleetAgent[], f: FleetFilter): FleetAgent[] {
  return sortFleet(list.filter((a) => matchesFleet(a, f)))
}

/** Versions for the filter / chips, newest first: [["60", 12], ["59", 3]]. */
export function fleetVersions(s: FleetSummary): [string, number][] {
  return Object.entries(s.versions).sort((a, b) => Number(b[0]) - Number(a[0]) || a[0].localeCompare(b[0]))
}

/** i18n key for the route cell: "mTLS required" says more than "mTLS" (token alone is refused). */
export function routeKey(a: FleetAgent): string {
  if (!a.online || !a.route) return 'health.agents.route.none'
  if (a.route === 'mtls') return a.mtls_required ? 'health.agents.route.mtlsRequired' : 'health.agents.route.mtls'
  return 'health.agents.route.token'
}

type T = (k: string, v?: Record<string, string | number>) => string

/** "for how long": seconds → "5 min", "3 h 10 min", "4 d 2 h". */
export function fleetDuration(seconds: number, t: T): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return t('health.agents.dur.s', { n: s })
  const m = Math.floor(s / 60)
  if (m < 60) return t('health.agents.dur.m', { n: m })
  const h = Math.floor(m / 60)
  if (h < 24) return t('health.agents.dur.hm', { h, m: m % 60 })
  return t('health.agents.dur.dh', { d: Math.floor(h / 24), h: h % 24 })
}

// ── Diagnostic → Logs: the connection-log filter ─────────────────────────────────────────────
export type EventFilter = 'all' | 'connections' | 'refusals' | 'updates' | 'mtls'
export const EVENT_FILTERS: EventFilter[] = ['all', 'connections', 'refusals', 'updates', 'mtls']

export interface AgentEvent { event: string; reason?: string; detail?: string }

// Un eveniment poate aparţine mai multor categorii (un refuz mTLS e şi refuz, şi mTLS);
// filtrul doar ascunde rânduri, deci o categorie în plus nu ascunde nimic din ce trebuie văzut.
export function eventMatches(e: AgentEvent, f: EventFilter): boolean {
  const ev = e.event || ''
  const reason = e.reason || ''
  switch (f) {
    case 'all': return true
    case 'connections': return ev === 'connect' || ev === 'disconnect' || ev === 'ip_change' || ev === 'conflict'
    case 'refusals': return ev.endsWith('_refused') || ev === 'conflict' || ev.startsWith('handshake_')
    case 'updates': return ev.startsWith('update_')
    case 'mtls': return ev.startsWith('mtls_') || reason.includes('mtls')
      || (ev === 'connect' && /\bmTLS\b/.test(e.detail || ''))
  }
}
