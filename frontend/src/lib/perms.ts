import { useSyncExternalStore } from 'react'
import { api } from './api'
import { sectionVisible } from './settingsIndex'

/* Permisiunile contului curent (3.6, roluri) — pentru gating-ul COSMETIC din UI. Serverul decide
   oricum (authz.perm pe fiecare rută); aici doar ascundem ce nu poţi folosi nicăieri şi
   dezactivăm, cu motivul în tooltip, ce nu poţi folosi pe hostul ăsta (docs/design/ROLES-AND-SSH.md
   §A.9 „hide vs disable").

   Până la primul răspuns (`null`) totul e permis: un Owner nu trebuie să vadă butoane clipind la
   pornire, iar pentru un cont restrâns o fracţiune de secundă cu un buton în plus nu deschide
   nimic — serverul refuză. */

export type RoleKey = 'owner' | 'admin' | 'operator' | 'viewer'
export type ScopeKind = 'all' | 'folder' | 'tag' | 'host'

export interface Binding {
  id: number
  role: RoleKey | string
  role_id?: number
  role_name: string
  scope_kind: ScopeKind
  scope_value: string
  source: string
  expires: number | null
}

export interface MyPerms {
  global: string[]
  all_hosts: string[]
  hosts: Record<string, string[]>
  bindings: Binding[]
  owner: boolean
  epoch: number
  has_admins: boolean
}

export const ROLE_KEYS: readonly RoleKey[] = ['owner', 'admin', 'operator', 'viewer']
/** rolurile predefinite care dau un shell undeva (⚑): toate în afară de Viewer */
export const SHELL_ROLES: readonly string[] = ['owner', 'admin', 'operator']
export const SCOPE_KINDS: readonly ScopeKind[] = ['all', 'folder', 'tag', 'host']

// ── Roluri custom (3.6.2) ─────────────────────────────────────────────────────────────────
export interface PermSpec { id: string; kind: 'host' | 'global'; shell: boolean }
export interface RoleRow {
  id: number
  key?: string
  name: string
  description?: string
  perms: string[]
  shell: boolean
  bindings?: number
  sso_bindings?: number
  mappings?: number
  editable?: boolean
}
export interface RolesCatalogue {
  perms: PermSpec[]
  roles: (RoleRow & { key: RoleKey })[]
  custom: RoleRow[]
  scopes: string[]
}

/** Grupele din editorul de roluri — aceeaşi împărţire ca în docs/ROLES.md („Permission
    reference"). O permisiune din catalog care lipseşte de aici cade în ultimul grup potrivit
    tipului ei (vezi `groupPerms`), deci o permisiune nouă nu dispare tăcut din editor. */
export const PERM_GROUPS: readonly { id: string; perms: readonly string[] }[] = [
  { id: 'hosts', perms: ['host.view', 'host.diagnostics', 'host.wake', 'host.edit', 'host.admin'] },
  { id: 'sessions', perms: ['session.watch', 'recording.view', 'session.open', 'session.manage',
    'share.live', 'share.live_write', 'share.replay'] },
  { id: 'files', perms: ['files.read', 'files.write', 'files.delete'] },
  { id: 'ops', perms: ['run', 'docker.view', 'docker.act', 'services.view', 'services.act', 'serial.use'] },
  { id: 'network', perms: ['forward.use', 'forward.manage', 'toolbox.use', 'toolbox.manage', 'deploykey.manage'] },
  { id: 'instance', perms: [] },
]

export function groupPerms(catalogue: PermSpec[]): { id: string; perms: PermSpec[] }[] {
  const byId = new Map(catalogue.map((p) => [p.id, p]))
  const placed = new Set<string>()
  const out = PERM_GROUPS.map((g) => {
    const perms = g.perms.map((id) => byId.get(id)).filter((p): p is PermSpec => !!p)
    perms.forEach((p) => placed.add(p.id))
    return { id: g.id, perms }
  })
  for (const p of catalogue) {
    if (placed.has(p.id)) continue
    const g = p.kind === 'global' ? out[out.length - 1] : out[0]
    g.perms.push(p)
  }
  return out.filter((g) => g.perms.length > 0)
}

/** Modele de pornire din design (§A.5): nu sunt roluri predefinite, doar o bifare rapidă. */
export const ROLE_PRESETS: readonly { id: string; labelKey: string; perms: readonly string[] }[] = [
  { id: 'auditor', labelKey: 'roles.custom.presetAuditor', perms: ['host.view', 'recording.view', 'audit.view'] },
  { id: 'filesOnly', labelKey: 'roles.custom.presetFilesOnly', perms: ['files.read', 'files.write'] },
]

/** Ce are contul peste TOATĂ instanţa: globalele + permisiunile de host de la o legătură `all`.
    Plafonul (cosmetic) al editorului de roluri — serverul aplică exact aceeaşi regulă. */
export function heldEverywhere(p: MyPerms | null): Set<string> | null {
  if (!p) return null
  return new Set([...p.global, ...p.all_hosts])
}

/** Valoarea din <select> pentru un rol: cheia celor predefinite, `id:N` pentru cele custom. */
export const roleValue = (r: { key?: string; id: number }) => (r.key ? r.key : 'id:' + r.id)
export function roleBody(v: string): { role?: string; role_id?: number } {
  return v.startsWith('id:') ? { role_id: Number(v.slice(3)) } : { role: v }
}

/** permisiune globală (instanţă). `null` = încă necunoscut → permis. */
export function can(p: MyPerms | null, perm: string): boolean {
  return !p || p.global.includes(perm)
}

/** permisiunile pe un host: cele valabile pe toate hosturile ∪ cele din legăturile cu scope */
export function permsOn(p: MyPerms | null, hostId: number | null | undefined): Set<string> | null {
  if (!p) return null
  const out = new Set(p.all_hosts)
  if (hostId != null) for (const x of p.hosts[String(hostId)] ?? []) out.add(x)
  return out
}

export function canOn(p: MyPerms | null, hostId: number | null | undefined, perm: string): boolean {
  const s = permsOn(p, hostId)
  return !s || s.has(perm)
}

/** permisiunea există pe MĂCAR un host (decide „ascunde" vs „dezactivează") */
export function anyHost(p: MyPerms | null, perm: string): boolean {
  if (!p) return true
  if (p.all_hosts.includes(perm)) return true
  return Object.values(p.hosts).some((list) => list.includes(perm))
}

/** contul nu are nicio legătură → „fără acces încă" */
export function hasNoAccess(p: MyPerms | null): boolean {
  return !!p && p.bindings.length === 0
}

/** Eticheta scope-ului unei legături: „toate hosturile", „folder prod", „tag web", numele hostului. */
export function scopeLabel(b: Pick<Binding, 'scope_kind' | 'scope_value'>,
                           hostName: (id: number) => string | undefined,
                           t: (k: string, v?: Record<string, string | number>) => string): string {
  switch (b.scope_kind) {
    case 'all': return t('roles.scope.allLabel')
    case 'folder': return t('roles.scope.folderLabel', { name: b.scope_value })
    case 'tag': return t('roles.scope.tagLabel', { name: b.scope_value })
    case 'host': {
      const n = hostName(Number(b.scope_value))
      return t('roles.scope.hostLabel', { name: n ?? '#' + b.scope_value })
    }
    default: return b.scope_value
  }
}

/** numele rolului, tradus (rolurile custom din 3.6.1 cad pe numele lor) */
export function roleLabel(b: Pick<Binding, 'role' | 'role_name'>, t: (k: string) => string): string {
  return (ROLE_KEYS as readonly string[]).includes(b.role) ? t('roles.role.' + b.role) : (b.role_name || b.role)
}

// ── store ─────────────────────────────────────────────────────────────────────────────────
let current: MyPerms | null = null
let lastJson = ''
const listeners = new Set<() => void>()

export function setPerms(p: MyPerms | null): void {
  const j = JSON.stringify(p)
  if (j === lastJson) return          // poll-ul de 5 s nu re-randează nimic dacă nu s-a schimbat
  lastJson = j
  current = p
  listeners.forEach((l) => l())
}

export function getPerms(): MyPerms | null {
  return current
}

/** Re-citeşte permisiunile; o eroare (sesiune expirată, gateway jos) lasă starea neschimbată. */
export async function loadPerms(): Promise<MyPerms | null> {
  try {
    const p = await api<MyPerms>('/api/me/permissions')
    setPerms(p)
    return p
  } catch {
    return current
  }
}

function subscribe(l: () => void): () => void {
  listeners.add(l)
  return () => { listeners.delete(l) }
}

export function usePerms(): MyPerms | null {
  return useSyncExternalStore(subscribe, getPerms, getPerms)
}

/** Pentru tab-urile din Setări: `vis('smtp')` — secţiunea e vizibilă contului curent? */
export function useSectionVisible(): (id: string) => boolean {
  const p = usePerms()
  return (id: string) => sectionVisible(id, (perm) => can(p, perm))
}
