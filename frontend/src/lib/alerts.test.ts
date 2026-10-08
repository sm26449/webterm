import { describe, expect, it } from 'vitest'
import { AlertItem, AlertPref, applyPref, badgeText, groupPrefs, localizeAlert, mergePage, normSeverity, severityTone } from './alerts'
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

describe('localizeAlert (3.5.15)', () => {
  // un `t` minimal, cu aceleaşi reguli ca I18nProvider: plural prin Intl, fallback pe cheie
  const mkT = (strings: Record<string, string>, lang: string) =>
    (key: string, vars?: Record<string, string | number>) => {
      let s: string | undefined
      if (vars && typeof vars.count === 'number') {
        s = strings[key + '.' + new Intl.PluralRules(lang).select(vars.count)] ?? strings[key + '.other']
      }
      s = s ?? strings[key] ?? key
      for (const [k, v] of Object.entries(vars || {})) s = s.split('{' + k + '}').join(String(v))
      return s
    }
  const tEn = mkT(en.strings, 'en')
  const tRo = mkT(ro.strings, 'ro')
  const base = { ...item(1), title: 'stored title', details: 'stored details' }

  it('old rows (no key) keep the stored English text', () => {
    expect(localizeAlert(base, tRo)).toEqual({ title: 'stored title', details: 'stored details' })
  })
  it('unknown keys (newer server) fall back to the stored text', () => {
    expect(localizeAlert({ ...base, msg_key: 'from_the_future', msg_params: {} }, tRo).title).toBe('stored title')
  })
  it('translates title and details with params', () => {
    const a = { ...base, msg_key: 'lockout', msg_params: { ip: '1.2.3.4', fails: 5 } }
    const r = localizeAlert(a, tRo)
    expect(r.title).toBe(ro.strings['alertmsg.lockout.title'])
    expect(r.details).toContain('1.2.3.4')
    expect(r.details).toContain('5 încercări')
    expect(localizeAlert(a, tEn).details).toContain('after 5 failed')
  })
  it('translates nested codes: metric, security-change description, span, masking, age', () => {
    const res = localizeAlert({ ...base, msg_key: 'resource_high',
      msg_params: { host: 'srv', metric: 'mem', value: '93', value1: '93.2', threshold: 90, rearm: 80 } }, tRo)
    expect(res.title).toBe('[srv] memorie la 93% (prag 90%)')
    const sec = localizeAlert({ ...base, msg_key: 'security_change',
      msg_params: { what_key: 'totp_disabled', what: '2FA (TOTP) disabled', email: 'a@x', ip: '1.1.1.1' } }, tRo)
    expect(sec.title).toBe('Schimbare de securitate: 2FA (TOTP) dezactivat')
    // o descriere fără cheie cunoscută → textul englezesc trimis de server, în fraza tradusă
    const sec2 = localizeAlert({ ...base, msg_key: 'security_change',
      msg_params: { what_key: 'nope', what: 'something new', email: 'a@x', ip: '1.1.1.1' } }, tRo)
    expect(sec2.title).toBe('Schimbare de securitate: something new')
    const rep = localizeAlert({ ...base, msg_key: 'replay_created',
      msg_params: { email: 'a@x', session: '', hours: 24, masking: false, ip: '1.1.1.1' } }, tRo)
    expect(rep.details).toContain('24 de ore')
    expect(rep.details).toContain('OPRITĂ')
    expect(rep.details).toContain('(fără titlu)')
    expect(localizeAlert({ ...base, msg_key: 'replay_created',
      msg_params: { email: 'a@x', session: 's', hours: 1, masking: true, ip: '1' } }, tEn).details).toContain('Valid for: 1 hour')
    const bk = localizeAlert({ ...base, msg_key: 'backup_local_failed',
      msg_params: { error: 'disk full', age_key: 'local_never', days: '' } }, tEn)
    expect(bk.details).toContain('NEVER been a successful scheduled backup')
    expect(bk.details).not.toContain('{')
  })
  it('every message key the server sends has a title + details in both catalogs', () => {
    const keys = ['lockout', 'agent_relocation', 'agent_ip_change', 'new_login', 'session_attach', 'security_change',
      'host_key_changed', 'ssh_key_deployed', 'ssh_key_revoked', 'host_enrolled', 'host_unlocked', 'replay_created',
      'replay_created_label', 'replay_opened', 'resource_high', 'resource_ok', 'host_offline', 'host_offline_uninstall',
      'host_online', 'gateway_disk', 'signing_locked', 'update_refused', 'backup_failed', 'backup_local_failed']
    for (const lang of [en.strings, ro.strings]) {
      for (const k of keys) {
        expect(lang[`alertmsg.${k}.title`], k).toBeTruthy()
        expect(lang[`alertmsg.${k}.details`], k).toBeTruthy()
      }
    }
  })
})
