import { describe, expect, it } from 'vitest'
import type { Host } from './api'
import {
  AgentEvent, canWake, fmtOfflineDuration, offlineActions, offlineMode, offlineReason,
  offlineSince, offlineTarget, outageDisconnect, sinceNeedsDate,
} from './hostOffline'

// host minimal: doar câmpurile pe care le citeşte logica overlay-ului
const mk = (o: Partial<Host> = {}): Host => ({
  id: 1, name: 'srv', note: '', online: false, hostname: 'srv.lan', agent_user: 'root',
  agent_version: 57, agent_latest: 57, update_pending: false, metrics: null, backend: 'tmux',
  last_heartbeat: 1000, connection_type: 'agent', ...o,
} as Host)
const live = { state: 'live' as const, kind: 'shell' as const, closed_at: null }
const t = (k: string) => ({ 'time.s': 's', 'time.m': 'm', 'time.h': 'h', 'time.d': 'd' } as Record<string, string>)[k] ?? k
const ev = (ts: number, event: string, reason = ''): AgentEvent => ({ ts, event, reason, detail: '' })

describe('offlineMode', () => {
  it('host de agent căzut cu sesiune vie → agent', () => {
    expect(offlineMode({ session: live, host: mk() })).toBe('agent')
  })
  it('host de agent online → nimic', () => {
    expect(offlineMode({ session: live, host: mk({ online: true }) })).toBeNull()
  })
  it('sesiune închisă normal → nimic, chiar dacă hostul e jos', () => {
    expect(offlineMode({ session: { ...live, state: 'closed' }, host: mk() })).toBeNull()
  })
  it('sesiune `lost` pe host de agent jos → tot agent (tmux-ul e re-adoptat la revenire)', () => {
    expect(offlineMode({ session: { ...live, state: 'lost' }, host: mk() })).toBe('agent')
  })
  it('SSH direct offline cu sesiunea vie = „la cerere", nu o cădere', () => {
    expect(offlineMode({ session: live, host: mk({ connection_type: 'ssh' }) })).toBeNull()
  })
  it('SSH/telnet direct cu sesiunea pierdută → connLost', () => {
    expect(offlineMode({ session: { ...live, state: 'lost' }, host: mk({ connection_type: 'ssh' }) })).toBe('connLost')
    expect(offlineMode({ session: live, host: mk({ connection_type: 'telnet' }), lostReason: 'agent-gone' })).toBe('connLost')
  })
  it('telnet-bastion pe agent viu, legătura spre device căzută → connLost', () => {
    expect(offlineMode({ session: { ...live, kind: 'telnet' }, host: mk({ online: true }), lostReason: 'agent-gone' })).toBe('connLost')
  })
  it('ţintă jump cu agentul-părinte căzut → via', () => {
    const parent = mk({ id: 9, name: 'bastion' })
    expect(offlineMode({ session: live, host: mk({ connection_type: 'ssh-jump', via_host_id: 9 }), viaHost: parent })).toBe('via')
    expect(offlineMode({ session: live, host: mk({ connection_type: 'ssh-jump', via_host_id: 9 }), viaHost: { ...parent, online: true } })).toBeNull()
  })
  it('fără host → nimic', () => {
    expect(offlineMode({ session: live, host: undefined })).toBeNull()
  })
})

describe('offlineTarget', () => {
  it('via → părintele; altfel hostul sesiunii', () => {
    const h = mk({ id: 2, connection_type: 'ssh-jump' }), p = mk({ id: 9 })
    expect(offlineTarget('via', h, p).id).toBe(9)
    expect(offlineTarget('agent', h, p).id).toBe(2)
  })
})

describe('offlineSince / outageDisconnect', () => {
  it('preferă momentul deconectării din jurnal', () => {
    const evs = [ev(1030, 'disconnect', 'closed'), ev(500, 'connect')]
    expect(offlineSince('agent', mk(), evs, live, 5000)).toBe(1030)
  })
  it('o deconectare MAI VECHE decât ultimul heartbeat e altă cădere → heartbeat-ul', () => {
    const evs = [ev(400, 'disconnect', 'closed')]
    expect(outageDisconnect(mk(), evs)).toBeNull()
    expect(offlineSince('agent', mk(), evs, live, 5000)).toBe(1000)
  })
  it('fără jurnal şi fără heartbeat → momentul observat de pagină', () => {
    expect(offlineSince('agent', mk({ last_heartbeat: null }), null, live, 4242)).toBe(4242)
  })
  it('connLost → closed_at al sesiunii, altfel momentul observat', () => {
    expect(offlineSince('connLost', mk(), null, { closed_at: 777 }, 9)).toBe(777)
    expect(offlineSince('connLost', mk(), null, { closed_at: null }, 9)).toBe(9)
  })
})

describe('fmtOfflineDuration', () => {
  it('secunde, minute, ore+minute, zile+ore', () => {
    expect(fmtOfflineDuration(42, t)).toBe('42s')
    expect(fmtOfflineDuration(5 * 60 + 9, t)).toBe('5m')
    expect(fmtOfflineDuration(3600, t)).toBe('1h')
    expect(fmtOfflineDuration(3600 + 4 * 60, t)).toBe('1h 4m')
    expect(fmtOfflineDuration(2 * 86400 + 5 * 3600, t)).toBe('2d 5h')
    expect(fmtOfflineDuration(86400, t)).toBe('1d')
  })
  it('negativ (ceasuri decalate) → 0s, nu „-3s"', () => {
    expect(fmtOfflineDuration(-3, t)).toBe('0s')
  })
  it('data apare doar când ora singură e ambiguă (≥20h)', () => {
    expect(sinceNeedsDate(0, 3600)).toBe(false)
    expect(sinceNeedsDate(0, 21 * 3600)).toBe(true)
  })
})

describe('offlineReason', () => {
  it('dezinstalat are prioritate', () => {
    expect(offlineReason(mk({ uninstalled_at: 999 }), [ev(1030, 'disconnect', 'closed')])).toBe('hostOffline.reasonUninstalled')
  })
  it('instance_refused (la deconectare sau la reîncercări) → relocat', () => {
    expect(offlineReason(mk(), [ev(1030, 'disconnect', 'instance_refused')])).toBe('hostOffline.reasonRelocated')
    expect(offlineReason(mk(), [ev(1100, 'handshake_refused', 'handshake_instance_conflict'), ev(1030, 'disconnect', 'closed')]))
      .toBe('hostOffline.reasonRelocated')
  })
  it('update împins chiar înainte → restart pentru update; amânat → nu', () => {
    expect(offlineReason(mk(), [ev(1030, 'disconnect', 'closed'), ev(1000, 'update_pushed')])).toBe('hostOffline.reasonUpdate')
    expect(offlineReason(mk(), [ev(1030, 'disconnect', 'closed'), ev(1001, 'update_deferred'), ev(1000, 'update_pushed')]))
      .toBe('diag.reasonClosed')
    // update vechi (>120s) nu explică această cădere
    expect(offlineReason(mk({ last_heartbeat: 1000 }), [ev(1030, 'disconnect', 'closed'), ev(800, 'update_pushed')])).toBe('diag.reasonClosed')
  })
  it('motivele cunoscute de deconectare → textele din panoul de diagnostic', () => {
    expect(offlineReason(mk(), [ev(1090, 'disconnect', 'heartbeat_stale')])).toBe('diag.reasonHeartbeatStale')
  })
  it('necunoscut sau fără jurnal → null (nu inventăm)', () => {
    expect(offlineReason(mk(), [ev(1030, 'disconnect', 'cosmic_rays')])).toBeNull()
    expect(offlineReason(mk(), null)).toBeNull()
  })
})

describe('offlineActions / canWake', () => {
  it('agent jos: Diagnostic + Wake + pagina hostului, fără Reconnect', () => {
    expect(offlineActions('agent', mk(), live)).toEqual({ diagnostics: true, wake: true, hostPage: true, reconnect: false })
  })
  it('via: Wake după regula părintelui (agent offline)', () => {
    expect(offlineActions('via', mk({ id: 9 }), live).wake).toBe(true)
  })
  it('connLost: fără Diagnostic/Wake; Reconnect doar pe telnet', () => {
    const ssh = mk({ connection_type: 'ssh' })
    expect(offlineActions('connLost', ssh, live)).toEqual({ diagnostics: false, wake: false, hostPage: true, reconnect: false })
    expect(offlineActions('connLost', ssh, { kind: 'telnet' }).reconnect).toBe(true)
  })
  it('canWake = regula sidebarului: doar agent, doar offline', () => {
    expect(canWake(mk())).toBe(true)
    expect(canWake(mk({ online: true }))).toBe(false)
    expect(canWake(mk({ connection_type: 'ssh' }))).toBe(false)
    expect(canWake(mk({ connection_type: 'telnet' }))).toBe(false)
    expect(canWake(mk({ connection_type: undefined }))).toBe(true)
    expect(canWake(null)).toBe(false)
  })
})
