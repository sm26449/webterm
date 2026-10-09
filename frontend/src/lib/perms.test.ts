import { afterEach, describe, expect, it, vi } from 'vitest'
import en from '../lang/en'
import ro from '../lang/ro'
import { anyHost, can, canOn, getPerms, hasNoAccess, loadPerms, MyPerms, permsOn, roleLabel, ROLE_KEYS,
  scopeLabel, setPerms } from './perms'

const base: MyPerms = { global: [], all_hosts: [], hosts: {}, bindings: [], owner: false, epoch: 1, has_admins: true }
const t = (k: string, v?: Record<string, string | number>) => {
  let s = en.strings[k] ?? k
  for (const [n, x] of Object.entries(v ?? {})) s = s.split('{' + n + '}').join(String(x))
  return s
}

describe('perms: necunoscut = permis (Owner-ul nu vede nimic clipind la pornire)', () => {
  it('null → totul permis', () => {
    expect(can(null, 'backups.manage')).toBe(true)
    expect(canOn(null, 3, 'files.write')).toBe(true)
    expect(anyHost(null, 'run')).toBe(true)
    expect(permsOn(null, 3)).toBeNull()
    expect(hasNoAccess(null)).toBe(false)
  })
})

describe('perms: global vs pe host', () => {
  const op: MyPerms = { ...base, hosts: { '7': ['host.view', 'session.open', 'files.read'] },
    bindings: [{ id: 1, role: 'operator', role_name: 'Operator', scope_kind: 'folder', scope_value: 'prod',
      source: 'manual', expires: null }] }
  it('globalele vin doar din `global`', () => {
    expect(can(op, 'tokens.create')).toBe(false)
    expect(can({ ...base, global: ['tokens.create'] }, 'tokens.create')).toBe(true)
  })
  it('pe host: all_hosts ∪ hosts[id]', () => {
    expect(canOn(op, 7, 'session.open')).toBe(true)
    expect(canOn(op, 8, 'session.open')).toBe(false)
    expect(canOn({ ...op, all_hosts: ['host.view'] }, 8, 'host.view')).toBe(true)
    expect([...(permsOn(op, 7) ?? [])].sort()).toEqual(['files.read', 'host.view', 'session.open'])
  })
  it('anyHost decide „ascunde" vs „dezactivează"', () => {
    expect(anyHost(op, 'files.read')).toBe(true)
    expect(anyHost(op, 'run')).toBe(false)
    expect(anyHost({ ...base, all_hosts: ['run'] }, 'run')).toBe(true)
  })
  it('fără legături = fără acces', () => {
    expect(hasNoAccess(base)).toBe(true)
    expect(hasNoAccess(op)).toBe(false)
  })
})

describe('perms: etichete', () => {
  const host = (id: number) => (id === 3 ? 'web01' : undefined)
  it('scope', () => {
    expect(scopeLabel({ scope_kind: 'all', scope_value: '' }, host, t)).toBe(en.strings['roles.scope.allLabel'])
    expect(scopeLabel({ scope_kind: 'folder', scope_value: 'prod' }, host, t)).toContain('prod')
    expect(scopeLabel({ scope_kind: 'tag', scope_value: 'web' }, host, t)).toContain('web')
    expect(scopeLabel({ scope_kind: 'host', scope_value: '3' }, host, t)).toContain('web01')
    expect(scopeLabel({ scope_kind: 'host', scope_value: '9' }, host, t)).toContain('#9')
  })
  it('rolurile predefinite au nume în en şi ro', () => {
    for (const k of ROLE_KEYS) {
      expect(en.strings['roles.role.' + k], k).toBeTruthy()
      expect(ro.strings['roles.role.' + k], k).toBeTruthy()
      expect(roleLabel({ role: k, role_name: 'x' }, t)).toBe(en.strings['roles.role.' + k])
    }
    expect(roleLabel({ role: 'custom', role_name: 'Auditor' }, t)).toBe('Auditor')
  })
})

describe('perms: store', () => {
  afterEach(() => setPerms(null))
  it('setPerms nu notifică pentru aceleaşi date', () => {
    setPerms(base)
    expect(getPerms()).toEqual(base)
    const same = { ...base }
    setPerms(same)
    expect(getPerms()).not.toBe(same)   // păstrează obiectul vechi (fără re-render)
  })
  it('loadPerms: o eroare lasă starea neschimbată', async () => {
    setPerms(base)
    const f = vi.fn().mockRejectedValue(new Error('down'))
    vi.stubGlobal('fetch', f)
    expect(await loadPerms()).toEqual(base)
    vi.unstubAllGlobals()
  })
})
