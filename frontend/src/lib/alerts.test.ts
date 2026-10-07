import { describe, expect, it } from 'vitest'
import { AlertItem, AlertPref, applyPref, badgeText, groupPrefs, mergePage, normSeverity, severityTone } from './alerts'
import en from '../lang/en'
import ro from '../lang/ro'

const pref = (kind: string, group: AlertPref['group'], security = false): AlertPref =>
  ({ kind, group, scope: 'fleet', security, email: true, inapp: true })

const item = (id: number): AlertItem =>
  ({ id, ts: id, kind: 'resource', severity: 'info', title: `a${id}`, details: '', host_id: null, read: false })

describe('severity', () => {
  it('maps to a badge tone, unknown → info', () => {
    expect(severityTone('critical')).toBe('danger')
    expect(severityTone('warning')).toBe('warn')
    expect(severityTone('ok')).toBe('ok')
    expect(severityTone('info')).toBe('info')
    expect(severityTone('whatever')).toBe('info')
    expect(normSeverity('whatever')).toBe('info')
    expect(normSeverity('critical')).toBe('critical')
  })
  it('every severity has a label in en and ro', () => {
    for (const s of ['critical', 'warning', 'info', 'ok']) {
      expect(en.strings[`alerts.sev.${s}`]).toBeTruthy()
      expect(ro.strings[`alerts.sev.${s}`]).toBeTruthy()
    }
  })
})

describe('badgeText', () => {
  it('hides zero, caps at 99+', () => {
    expect(badgeText(0)).toBe('')
    expect(badgeText(-3)).toBe('')
    expect(badgeText(7)).toBe('7')
    expect(badgeText(99)).toBe('99')
    expect(badgeText(100)).toBe('99+')
  })
})

describe('prefs', () => {
  const prefs = [pref('host_offline', 'hosts'), pref('new_login', 'account', true), pref('backup_failed', 'gateway')]
  it('groups in UI order and drops empty groups', () => {
    expect(groupPrefs(prefs).map((g) => g.group)).toEqual(['account', 'hosts', 'gateway'])
  })
  it('security kinds cannot leave the in-app history', () => {
    const next = applyPref(prefs, 'new_login', 'inapp', false)
    expect(next.find((p) => p.kind === 'new_login')!.inapp).toBe(true)
    const next2 = applyPref(prefs, 'new_login', 'email', false)
    expect(next2.find((p) => p.kind === 'new_login')!.email).toBe(false)
    const next3 = applyPref(prefs, 'host_offline', 'inapp', false)
    expect(next3.find((p) => p.kind === 'host_offline')!.inapp).toBe(false)
  })
  it('every kind and group the gateway knows has a label in en and ro', () => {
    const kinds = ['new_login', 'session_attach', 'account_change', 'host_unlocked', 'admin_change', 'ssh_key',
      'host_key_changed', 'agent_relocation', 'host_enrolled', 'lockout', 'host_offline', 'resource',
      'agent_ip_change', 'update_refused', 'gateway_disk', 'signing_locked', 'backup_failed']
    for (const lang of [en.strings, ro.strings]) {
      for (const k of kinds) expect(lang[`alerts.kind.${k}`], k).toBeTruthy()
      for (const g of ['account', 'security', 'hosts', 'gateway']) expect(lang[`alerts.group.${g}`], g).toBeTruthy()
    }
  })
})

describe('mergePage', () => {
  it('appends without duplicates, newest first', () => {
    expect(mergePage([item(9), item(8)], [item(8), item(7)]).map((a) => a.id)).toEqual([9, 8, 7])
  })
})
