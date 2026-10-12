import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, describe, expect, it, vi } from 'vitest'
import en from '../lang/en'
import ro from '../lang/ro'
import { searchSettings, SETTINGS_INDEX } from './settingsIndex'
import { tabListNav } from './tablist'
import {
  DEFAULT_SSO_GROUPS, effectiveSubTab, EMPTY_FILTER, filterAccounts, filterActive, groupMappings, hasNoRole,
  loadSubTab, roleUsage, saveSubTab, signInOf, subTabOfSection, visibleSubTabs, type SsoMapping, type UserRow,
} from './usersAdmin'
import SubTabs from '../components/settings/users/SubTabs'

/* Settings → Users & roles, 3.6.6: sub-tab-urile, căutarea/filtrele conturilor, mapările SSO
   grupate şi contractul cu căutarea din Setări (rezultatul aterizează pe sub-tab-ul potrivit). */

const b = (id: number, role: string, extra: Partial<{ role_id: number; role_name: string }> = {}) => ({
  id, role, role_id: extra.role_id ?? 0, role_name: extra.role_name ?? role, scope_kind: 'all' as const,
  scope_value: '', source: 'manual', expires: null,
})
const u = (id: number, email: string, p: Partial<UserRow> = {}): UserRow => ({
  id, email, created: 1_700_000_000 + id, totp: false, passkeys: 0, is_self: false, bindings: [], ...p,
})
const USERS: UserRow[] = [
  u(1, 'owner@example.com', { is_self: true, bindings: [b(1, 'owner')] }),
  u(2, 'zoe.admin@example.com', { bindings: [b(2, 'admin')] }),
  u(3, 'alice@corp.ro', { sso: true, local_password: false, bindings: [b(3, 'viewer'), b(4, '', { role_id: 9, role_name: 'Auditor' })] }),
  u(4, 'bob@corp.ro', { sso: true, local_password: true }),
  u(5, 'șerban@corp.ro', { bindings: [b(5, 'operator')] }),
  u(6, 'nobody@example.com'),
]
const emails = (list: UserRow[]) => list.map((x) => x.email)

describe('signInOf', () => {
  it('parolă locală / doar SSO / SSO cu parolă locală', () => {
    expect(signInOf({ sso: false })).toBe('local')
    expect(signInOf({})).toBe('local')
    expect(signInOf({ sso: true, local_password: false })).toBe('sso')
    expect(signInOf({ sso: true, local_password: true })).toBe('both')
  })
})

describe('filterAccounts', () => {
  it('fără filtre: toate, contul tău primul, apoi alfabetic', () => {
    expect(emails(filterAccounts(USERS, EMPTY_FILTER))).toEqual([
      'owner@example.com', 'alice@corp.ro', 'bob@corp.ro', 'nobody@example.com', 'șerban@corp.ro', 'zoe.admin@example.com',
    ])
    expect(filterActive(EMPTY_FILTER)).toBe(false)
  })

  it('căutarea: fără diacritice, fără majuscule, fiecare cuvânt trebuie să apară', () => {
    expect(emails(filterAccounts(USERS, { ...EMPTY_FILTER, query: 'SERBAN' }))).toEqual(['șerban@corp.ro'])
    expect(emails(filterAccounts(USERS, { ...EMPTY_FILTER, query: 'corp alice' }))).toEqual(['alice@corp.ro'])
    expect(filterAccounts(USERS, { ...EMPTY_FILTER, query: 'zzz' })).toEqual([])
    expect(filterActive({ ...EMPTY_FILTER, query: '  ' })).toBe(false)
    expect(filterActive({ ...EMPTY_FILTER, query: 'a' })).toBe(true)
  })

  it('rol predefinit după cheie, rol custom după id', () => {
    expect(emails(filterAccounts(USERS, { ...EMPTY_FILTER, role: 'admin' }))).toEqual(['zoe.admin@example.com'])
    expect(emails(filterAccounts(USERS, { ...EMPTY_FILTER, role: 'id:9' }))).toEqual(['alice@corp.ro'])
    expect(filterAccounts(USERS, { ...EMPTY_FILTER, role: 'id:10' })).toEqual([])
  })

  it('autentificare: „parolă locală" include SSO + parolă; „doar SSO" nu', () => {
    expect(emails(filterAccounts(USERS, { ...EMPTY_FILTER, signIn: 'sso' }))).toEqual(['alice@corp.ro'])
    expect(emails(filterAccounts(USERS, { ...EMPTY_FILTER, signIn: 'local' }))).not.toContain('alice@corp.ro')
    expect(emails(filterAccounts(USERS, { ...EMPTY_FILTER, signIn: 'local' }))).toContain('bob@corp.ro')
  })

  it('fără rol', () => {
    expect(emails(filterAccounts(USERS, { ...EMPTY_FILTER, noRole: true }))).toEqual(['bob@corp.ro', 'nobody@example.com'])
    expect(hasNoRole({})).toBe(true)
    expect(hasNoRole({ bindings: [] })).toBe(true)
  })

  it('filtrele se combină (ŞI)', () => {
    expect(emails(filterAccounts(USERS, { ...EMPTY_FILTER, noRole: true, signIn: 'local', query: 'nobody' }))).toEqual(['nobody@example.com'])
    expect(filterAccounts(USERS, { ...EMPTY_FILTER, noRole: true, role: 'admin' })).toEqual([])
  })

  it('nu modifică lista primită', () => {
    const copy = USERS.map((x) => x.email)
    filterAccounts(USERS, EMPTY_FILTER)
    expect(USERS.map((x) => x.email)).toEqual(copy)
  })

  it('rămâne rapid la 2000 de conturi', () => {
    const many = Array.from({ length: 2000 }, (_, i) => u(100 + i, `user${i}@example.com`, { bindings: i % 3 ? [b(i, 'viewer')] : [] }))
    const t0 = performance.now()
    const out = filterAccounts(many, { ...EMPTY_FILTER, query: 'user1', noRole: true })
    expect(performance.now() - t0).toBeLessThan(200)
    expect(out.every((x) => x.email.includes('user1') && hasNoRole(x))).toBe(true)
  })
})

describe('sub-tab-uri: vizibilitate (aceleaşi condiţii ca secţiunile de dinainte)', () => {
  const v = (manage: boolean, rolesManage: boolean, ssoEnabled = false, ssoFailed = false) =>
    visibleSubTabs({ manage, rolesManage, ssoEnabled, ssoFailed })
  it('fără drepturi de administrare: niciun sub-tab (doar „Your access")', () => {
    expect(v(false, false)).toEqual([])
    expect(v(false, false, true, true)).toEqual([])
  })
  it('users.manage: Accounts + Roles; SSO doar cu SSO activ sau eroare de încărcare', () => {
    expect(v(true, false)).toEqual(['accounts', 'roles'])
    expect(v(true, false, true)).toEqual(['accounts', 'roles', 'sso'])
    expect(v(true, false, false, true)).toEqual(['accounts', 'roles', 'sso'])
  })
  it('doar roles.manage: doar Roles (SSO cere users.manage)', () => {
    expect(v(false, true, true)).toEqual(['roles'])
  })
  it('sub-tab-ul efectiv: cel cerut dacă e vizibil, altfel primul', () => {
    expect(effectiveSubTab('sso', ['accounts', 'roles', 'sso'])).toBe('sso')
    expect(effectiveSubTab('sso', ['accounts', 'roles'])).toBe('accounts')
    expect(effectiveSubTab(null, ['roles'])).toBe('roles')
    expect(effectiveSubTab('accounts', [])).toBeNull()
  })
})

describe('sub-tab-uri: ultimul ales, per browser', () => {
  afterEach(() => { vi.unstubAllGlobals() })
  it('se păstrează şi se citeşte înapoi; o valoare necunoscută e ignorată', () => {
    const store = new Map<string, string>()
    vi.stubGlobal('window', { localStorage: {
      getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, x: string) => { store.set(k, x) },
    } })
    expect(loadSubTab()).toBeNull()
    saveSubTab('roles')
    expect(loadSubTab()).toBe('roles')
    store.set('wt_users_subtab', 'evil')
    expect(loadSubTab()).toBeNull()
  })
  it('localStorage care aruncă (Safari blocat, iframe sandbox) nu strică nimic', () => {
    vi.stubGlobal('window', { get localStorage(): Storage { throw new Error('SecurityError') } })
    expect(loadSubTab()).toBeNull()
    expect(() => saveSubTab('sso')).not.toThrow()
  })
})

describe('căutarea din Setări aterizează pe sub-tab-ul potrivit', () => {
  const tEn = (k: string) => en.strings[k] ?? k
  const tRo = (k: string) => ro.strings[k] ?? en.strings[k] ?? k
  const land = (q: string, t = tEn) => {
    const hit = searchSettings(q, t)[0]
    return hit && { section: hit.section.id, tab: subTabOfSection(hit.section.id) }
  }
  it('fiecare secţiune din Users & roles are sub-tab, în afară de „Your access" (deasupra lor)', () => {
    for (const s of SETTINGS_INDEX.filter((x) => x.cat === 'utilizatori')) {
      if (s.id === 'myAccess') expect(subTabOfSection(s.id)).toBeUndefined()
      else expect(subTabOfSection(s.id), s.id).toBeDefined()
    }
  })
  it('„custom roles" → Roles, „sso groups" → SSO groups, „accounts" → Accounts (en şi ro)', () => {
    expect(land('custom roles')).toEqual({ section: 'roles', tab: 'roles' })
    expect(land('authentik groups')).toEqual({ section: 'ssoMapping', tab: 'sso' })
    expect(land('accounts')).toEqual({ section: 'users', tab: 'accounts' })
    expect(land('grupuri sso', tRo)).toEqual({ section: 'ssoMapping', tab: 'sso' })
    expect(land('conturi', tRo)).toEqual({ section: 'users', tab: 'accounts' })
  })
  it('UsersTab pune data-setting-id-ul fiecărei secţiuni pe panoul sub-tab-ului ei', () => {
    const src = (import.meta.glob('../components/settings/UsersTab.tsx', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)['../components/settings/UsersTab.tsx']
    for (const [section, tab] of [['users', 'accounts'], ['roles', 'roles'], ['ssoMapping', 'sso']] as const) {
      expect(subTabOfSection(section)).toBe(tab)
      expect(src).toContain(`{...panel('${tab}')} data-setting-id="${section}"`)
    }
    // şi SettingsModal îi dă saltul, ca sub-tab-ul să se deschidă înainte de derulare
    const modal = (import.meta.glob('../components/SettingsModal.tsx', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)['../components/SettingsModal.tsx']
    expect(modal).toContain('<UsersTab jump={jump} />')
  })
})

describe('tablist: tastatura (WAI-ARIA tabs)', () => {
  it('→/← cu wrap, Home/End la capete, restul tastelor nu fac nimic', () => {
    expect(tabListNav('ArrowRight', 0, 3)).toBe(1)
    expect(tabListNav('ArrowRight', 2, 3)).toBe(0)
    expect(tabListNav('ArrowLeft', 0, 3)).toBe(2)
    expect(tabListNav('ArrowLeft', 2, 3)).toBe(1)
    expect(tabListNav('Home', 2, 3)).toBe(0)
    expect(tabListNav('End', 0, 3)).toBe(2)
    expect(tabListNav('ArrowDown', 0, 3)).toBeNull()
    expect(tabListNav('Enter', 0, 3)).toBeNull()
    expect(tabListNav('ArrowRight', 0, 0)).toBeNull()
  })

  it('SubTabs: role=tab, aria-selected, aria-controls, roving tabindex, contorul în nume', () => {
    const html = renderToStaticMarkup(createElement(SubTabs<'accounts' | 'roles' | 'sso'>, {
      idPrefix: 'x', label: 'Sections', active: 'roles', onChange: () => {},
      tabs: [{ id: 'accounts', label: 'Accounts', count: 12, warn: 2, warnLabel: '2 without a role' },
        { id: 'roles', label: 'Roles', count: 5 }, { id: 'sso', label: 'SSO groups', count: 0 }],
    }))
    expect(html).toContain('role="tablist"')
    expect(html).toContain('aria-label="Sections"')
    expect(html.match(/role="tab"/g)).toHaveLength(3)
    const tab = (id: string) => html.match(new RegExp(`<button[^>]*data-subtab="${id}"[^>]*>`))?.[0] ?? ''
    expect(tab('roles')).toContain('aria-selected="true"')
    expect(tab('roles')).toContain('tabindex="0"')
    expect(tab('accounts')).toContain('aria-selected="false"')
    expect(tab('accounts')).toContain('tabindex="-1"')
    expect(tab('sso')).toContain('tabindex="-1"')
    expect(tab('accounts')).toContain('aria-controls="x-panel-accounts"')
    expect(tab('accounts')).toContain('id="x-tab-accounts"')
    expect(html).toContain('2 without a role')   // avertismentul are text, nu doar culoare
  })
})

describe('roleUsage şi groupMappings', () => {
  const m = (id: number, group: string, role: string, role_id = 0, source: 'ui' | 'config' = 'ui'): SsoMapping => ({
    id, group, role, role_id, role_name: role, scope_kind: 'all', scope_value: '', sso_bindings: 0, source,
  })
  const MAPS = [m(1, 'wt-ops', 'operator'), m(2, 'wt-admins', 'admin', 0, 'config'), m(3, '*', 'viewer'),
    m(4, 'wt-ops', '', 9), m(5, 'Auditors', '', 9)]
  it('număr de legături (din conturi) şi de mapări, predefinit şi custom', () => {
    expect(roleUsage('admin', USERS, MAPS)).toEqual({ bindings: 1, mappings: 1 })
    expect(roleUsage('id:9', USERS, MAPS)).toEqual({ bindings: 1, mappings: 2 })
    expect(roleUsage('owner', USERS, MAPS)).toEqual({ bindings: 1, mappings: 0 })
    expect(roleUsage('viewer', [], [])).toEqual({ bindings: 0, mappings: 0 })
  })
  it('grupate pe grup, alfabetic, „*" la urmă; ordinea serverului în grup', () => {
    const g = groupMappings(MAPS)
    expect(g.map((x) => x.group)).toEqual(['Auditors', 'wt-admins', 'wt-ops', '*'])
    expect(g.find((x) => x.group === 'wt-ops')?.mappings.map((x) => x.id)).toEqual([1, 4])
    expect(groupMappings([])).toEqual([])
  })
  it('grupurile implicite din provision.py au text în en şi ro', () => {
    expect(DEFAULT_SSO_GROUPS.map((x) => x.group)).toEqual(['wt-access', 'wt-admins', 'wt-readonly', 'wt-db', 'wt-network'])
    for (const g of DEFAULT_SSO_GROUPS) {
      expect(en.strings['roles.sso.default.' + g.key]).toBeTruthy()
      expect(ro.strings['roles.sso.default.' + g.key]).toBeTruthy()
    }
  })
  it('cheile construite dinamic (tipul de autentificare) există în en şi ro', () => {
    for (const k of ['local', 'sso', 'both']) {
      for (const pre of ['settings.users.signIn.', 'settings.users.signInLong.']) {
        expect(en.strings[pre + k], pre + k).toBeTruthy()
        expect(ro.strings[pre + k], pre + k).toBeTruthy()
      }
    }
  })
})
