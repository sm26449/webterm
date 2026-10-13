import { describe, expect, it } from 'vitest'
import {
  actionTarget, checkText, docUrl, fixMode, needsAttention, optText, severityTone, sortChecks, splitChecks,
  type HealthCheck,
} from './health'
import en from '../lang/en'
import ro from '../lang/ro'
import { SETTINGS_CATS } from './settingsIndex'

const base: HealthCheck = {
  id: 'x', severity: 'ok', message_key: 'disk_ok', params: { pct: '42' }, why_key: 'gateway.disk',
  recommendation_key: '', commands: [], command_where: '', requires_root: false, action: '', source: 'gateway',
  doc: '', hosts: [], hosts_hidden: 0, checked_at: 1, first_failed_at: null, changed_at: 1, muted: false,
  muted_until: 0, message: 'Gateway disk: 42% free',
}
const mk = (o: Partial<HealthCheck>): HealthCheck => ({ ...base, ...o })

// a t() over a catalog, with the same plural + fallback rules as lib/i18n
function tFor(strings: Record<string, string>, lang: string) {
  return (key: string, vars?: Record<string, string | number>) => {
    let s: string | undefined
    if (vars && typeof vars.count === 'number') {
      s = strings[key + '.' + new Intl.PluralRules(lang).select(vars.count)] ?? strings[key + '.other']
    }
    s = s ?? strings[key] ?? key
    for (const [k, v] of Object.entries(vars ?? {})) s = s.split('{' + k + '}').join(String(v))
    return s
  }
}
const tEn = tFor(en.strings, 'en')
const tRo = tFor(ro.strings, 'ro')

describe('health: ordering and attention', () => {
  it('critical before warning before info; muted after open problems; passing last', () => {
    const list = [
      mk({ id: 'a', severity: 'ok' }), mk({ id: 'b', severity: 'info' }), mk({ id: 'c', severity: 'critical', muted: true }),
      mk({ id: 'd', severity: 'warning' }), mk({ id: 'e', severity: 'critical' }),
    ]
    expect(sortChecks(list).map((c) => c.id)).toEqual(['e', 'd', 'b', 'c', 'a'])
    const { open, passing } = splitChecks(list)
    expect(open.map((c) => c.id)).toEqual(['e', 'd', 'b', 'c'])
    expect(passing.map((c) => c.id)).toEqual(['a'])
  })
  it('only unmuted warning/critical need attention (the badge)', () => {
    expect(needsAttention(mk({ severity: 'critical' }))).toBe(true)
    expect(needsAttention(mk({ severity: 'warning' }))).toBe(true)
    expect(needsAttention(mk({ severity: 'warning', muted: true }))).toBe(false)
    expect(needsAttention(mk({ severity: 'info' }))).toBe(false)
  })
  it('tones: muted is neutral whatever the severity', () => {
    expect(severityTone('critical')).toBe('danger')
    expect(severityTone('warning')).toBe('warn')
    expect(severityTone('critical', true)).toBe('neutral')
  })
})

describe('health: text', () => {
  it('translates the message key with params, plural-aware in both languages', () => {
    const c = mk({ severity: 'warning', message_key: 'agents_outdated', params: { count: 3, version: 58, days: 7 } })
    expect(checkText(c, tEn)).toBe('3 agents have been behind v58 for more than 7 days')
    expect(checkText({ ...c, params: { count: 1, version: 58, days: 7 } }, tEn)).toBe('1 agent has been behind v58 for more than 7 days')
    expect(checkText({ ...c, params: { count: 21, version: 58, days: 7 } }, tRo)).toContain('21 de agenți')
  })
  it('an unknown key (newer server) falls back to the server text, as plain text', () => {
    const c = mk({ message_key: 'something_new', message: '<img src=x onerror=alert(1)>' })
    expect(checkText(c, tEn)).toBe('<img src=x onerror=alert(1)>')   // React renders it as text
  })
  it('optional catalog text is empty when the key is unknown', () => {
    expect(optText('health.why.', 'gateway.disk', tEn)).toMatch(/logins fail/)
    expect(optText('health.why.', 'nope', tEn)).toBe('')
    expect(optText('health.rec.', '', tEn)).toBe('')
  })
  it('Romanian strings use comma-below ș/ț, never the cedilla forms', () => {
    const bad = Object.entries(ro.strings).filter(([k, v]) => k.startsWith('health.') && /[şţŞŢ]/.test(v))
    expect(bad).toEqual([])
  })
})

describe('health: actions', () => {
  it('terminal only for an Owner with a gateway host picked', () => {
    expect(fixMode({ can_terminal: true, terminal_host: { id: 1, name: 'gw' } })).toBe('terminal')
    expect(fixMode({ can_terminal: true, terminal_host: null })).toBe('pick')
    expect(fixMode({ can_terminal: false, terminal_host: { id: 1, name: 'gw' } })).toBe('copy')
  })
  it('every Settings jump lands on a real tab', () => {
    const cats = new Set(SETTINGS_CATS.map((c) => c.id as string))
    for (const a of ['settings:notifications', 'settings:backup', 'settings:signing', 'settings:certificates',
      'settings:forward', 'about:update']) {
      const tgt = actionTarget(a)
      expect(tgt, a).not.toBeNull()
      expect(cats.has(tgt!.cat), a).toBe(true)
    }
    expect(actionTarget('agent_update')).toBeNull()
    expect(actionTarget('javascript:alert(1)')).toBeNull()
  })
  it('doc links: only docs/ paths, into the repository', () => {
    expect(docUrl('docs/AUTHENTIK-UPGRADE.md')).toBe('https://github.com/sm26449/webterm/blob/main/docs/AUTHENTIK-UPGRADE.md')
    expect(docUrl('docs/INSTALL.md#dead-man-switch')).toContain('#dead-man-switch')
    expect(docUrl('javascript:alert(1)')).toBeNull()
    expect(docUrl('https://evil.example/docs/x.md')).toBeNull()
    expect(docUrl('docs/../../etc/passwd')).toBeNull()
    expect(docUrl('')).toBeNull()
  })
})
