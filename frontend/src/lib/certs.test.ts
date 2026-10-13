import { describe, expect, it } from 'vitest'
import { certStateText, certTone, needsRenew, renewMode, sortCerts, type CertItem } from './certs'
import { SETTINGS_INDEX, sectionVisible } from './settingsIndex'
import en from '../lang/en'
import ro from '../lang/ro'

const item = (over: Partial<CertItem> = {}): CertItem => ({
  name: 'wt.example.com', role: 'main', state: 'ok', level: 0, days_left: 62.4,
  renew_domain: 'wt.example.com', renew_command: 'sudo /opt/webterm/scripts/cert-renew.sh --domain wt.example.com',
  ...over,
})
const owner = { can_renew: true, renew_host: { id: 3, name: 'gw' } }

// the same plural rules as I18nProvider: Intl.PluralRules + fallback on the key
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

describe('certificate status (3.6.7)', () => {
  it('tones: expiring is a warning, expired / default / mismatch are danger, a failed check is muted', () => {
    expect(certTone('ok')).toBe('good')
    expect(certTone('expiring')).toBe('warn')
    expect(certTone('expiring_soon')).toBe('warn')
    for (const s of ['expired', 'default', 'mismatch'] as const) expect(certTone(s)).toBe('danger')
    expect(certTone('error')).toBe('muted')
  })
  it('state text in both languages, with plurals', () => {
    expect(certStateText(item(), tEn)).toBe('Valid, 62 days left')
    expect(certStateText(item({ state: 'expiring', level: 1, days_left: 1.2 }), tEn)).toBe('Expires in 1 day')
    expect(certStateText(item({ state: 'expired', level: 3, days_left: -12.5 }), tEn)).toBe('Expired 13 days ago')
    expect(certStateText(item({ state: 'expiring_soon', level: 2, days_left: 2.9 }), tRo)).toBe('Expiră în 2 zile')
    expect(certStateText(item({ state: 'expired', level: 3, days_left: -25 }), tRo)).toBe('A expirat acum 25 de zile')
    expect(certStateText(item({ state: 'default', level: 3 }), tEn)).toBe('Traefik default certificate')
    for (const s of ['default', 'mismatch', 'error'] as const) {
      expect(certStateText(item({ state: s }), tRo)).not.toContain('settings.certs')
    }
  })
  it('only a certificate that needs a human gets a Renew action', () => {
    expect(needsRenew(item())).toBe(false)
    expect(renewMode(owner, item())).toBe('none')
    expect(needsRenew(item({ state: 'expiring', level: 1 }))).toBe(true)
  })
  it('Renew: terminal with a picked host, copy without one, nothing for a non-Owner', () => {
    const bad = item({ state: 'expired', level: 3 })
    expect(renewMode(owner, bad)).toBe('terminal')
    expect(renewMode({ can_renew: true, renew_host: null }, bad)).toBe('copy')
    expect(renewMode({ can_renew: false, renew_host: { id: 3, name: 'gw' } }, bad)).toBe('none')
  })
  it('fails closed when the server gave no command (it refused to build one)', () => {
    expect(renewMode(owner, item({ state: 'expired', level: 3, renew_command: '' }))).toBe('none')
    expect(renewMode(owner, item({ state: 'expired', level: 3, renew_domain: undefined }))).toBe('none')
  })
  it('sorts main → forward → authentik', () => {
    const out = sortCerts([item({ name: 'auth.x.com', role: 'authentik' }), item({ name: 'cert-check.x.com', role: 'forward' }),
      item({ name: 'x.com', role: 'main' })])
    expect(out.map((i) => i.role)).toEqual(['main', 'forward', 'authentik'])
  })
  it('every role / via / state label exists in en and ro', () => {
    for (const lang of [en.strings, ro.strings]) {
      for (const k of ['role.main', 'role.forward', 'role.authentik', 'via.traefik', 'via.public',
        'state.default', 'state.mismatch', 'state.error']) expect(lang['settings.certs.' + k], k).toBeTruthy()
    }
  })
  it('Romanian strings use comma-below ș/ț, never the cedilla forms', () => {
    for (const [k, v] of Object.entries(ro.strings)) {
      if (k.startsWith('settings.certs.') || k.startsWith('alertmsg.cert_') || k.startsWith('err.certs.')
        || k === 'alerts.kind.tls_cert' || k === 'roles.perm.certs.renew') {
        expect(/[şţŞŢ]/.test(v), k).toBe(false)
      }
    }
  })
  it('the section is in the settings search, on the Infrastructure tab, behind settings.manage', () => {
    const s = SETTINGS_INDEX.find((x) => x.id === 'certificates')
    expect(s?.cat).toBe('infrastructura')
    expect(s?.perm).toBe('settings.manage')
    expect(sectionVisible('certificates', (p) => p === 'settings.manage')).toBe(true)
    expect(sectionVisible('certificates', () => false)).toBe(false)
  })
})
