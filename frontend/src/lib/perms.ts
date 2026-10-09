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
