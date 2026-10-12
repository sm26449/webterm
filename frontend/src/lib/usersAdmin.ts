import type { Binding, ScopeKind } from './perms'
import { fold } from './settingsIndex'
import { lsGet, lsSet } from './storage'

/* Settings → Users & roles (3.6.6): logica PURĂ a sub-tab-urilor (Accounts | Roles | SSO groups),
   a căutării/filtrării conturilor şi a mapărilor SSO grupate. Fără React, deci testabilă în vitest
   (usersAdmin.test.ts). Totul aici e de PREZENTARE: ce vede omul, în ce ordine. Nicio decizie de
   autorizare — serverul o ia pe fiecare rută, iar vizibilitatea sub-tab-urilor repetă exact
   condiţiile pe care UsersTab le aplica secţiunilor înainte de 3.6.6. */

export type UserRow = {
  id: number; email: string; created: number; totp: boolean; passkeys: number; sso?: boolean
  is_self: boolean; bindings?: Binding[]; local_password?: boolean
}

export type SsoMapping = {
  id: number; group: string; role: string; role_id: number; role_name: string
  scope_kind: ScopeKind; scope_value: string; sso_bindings: number
  /** 3.6.5: 'config' = din WEBTERM_OIDC_ROLE_MAP (.env) — doar citire în UI */
  source?: 'ui' | 'config'
}

// ── sub-tab-uri ──────────────────────────────────────────────────────────────────────────────
export type UsersSubTab = 'accounts' | 'roles' | 'sso'
export const USERS_SUBTABS: readonly UsersSubTab[] = ['accounts', 'roles', 'sso']

/** secţiunea din indexul căutării (data-setting-id) → sub-tab-ul pe care stă.
    `myAccess` stă deasupra sub-tab-urilor (vizibil oricui), deci nu are sub-tab. */
const SECTION_TAB: Record<string, UsersSubTab> = { users: 'accounts', roles: 'roles', ssoMapping: 'sso' }
export const subTabOfSection = (section: string | undefined): UsersSubTab | undefined =>
  (section ? SECTION_TAB[section] : undefined)

/** Ce sub-tab-uri vede contul. Aceleaşi condiţii ca secţiunile de dinainte (cosmetic — serverul
    refuză oricum): conturile cu `users.manage`; rolurile cu `roles.manage` SAU `users.manage`
    (catalogul se încarcă pentru amândouă — cine acordă roluri trebuie să ştie ce înseamnă ele;
    editarea rămâne doar cu `roles.manage`); grupurile SSO cu `users.manage`, doar când SSO e activ
    sau încărcarea a picat (eroarea se arată, nu se ascunde). */
export function visibleSubTabs(p: { manage: boolean; rolesManage: boolean; ssoEnabled: boolean; ssoFailed: boolean }): UsersSubTab[] {
  const out: UsersSubTab[] = []
  if (p.manage) out.push('accounts')
  if (p.manage || p.rolesManage) out.push('roles')
  if (p.manage && (p.ssoEnabled || p.ssoFailed)) out.push('sso')
  return out
}

/** Sub-tab-ul efectiv: cel cerut dacă e vizibil, altfel primul vizibil (sau null fără niciunul). */
export function effectiveSubTab(wanted: UsersSubTab | null, visible: readonly UsersSubTab[]): UsersSubTab | null {
  if (wanted && visible.includes(wanted)) return wanted
  return visible[0] ?? null
}

const TAB_KEY = 'wt_users_subtab'
/** ultimul sub-tab ales, per browser (lib/storage: localStorage cu try/catch) */
export function loadSubTab(): UsersSubTab | null {
  const v = lsGet(TAB_KEY)
  return (USERS_SUBTABS as readonly string[]).includes(v ?? '') ? (v as UsersSubTab) : null
}
export const saveSubTab = (tab: UsersSubTab): void => lsSet(TAB_KEY, tab)

// ── conturi: tipul de autentificare, căutare, filtre ─────────────────────────────────────────
/** `local` = doar parolă locală; `sso` = doar SSO; `both` = SSO cu parolă locală (grupurile nu-i
    dau roluri până nu-şi scoate parola — 3.6.2). */
export type SignIn = 'local' | 'sso' | 'both'
export function signInOf(u: Pick<UserRow, 'sso' | 'local_password'>): SignIn {
  if (!u.sso) return 'local'
  return u.local_password ? 'both' : 'sso'
}

export type AccountFilter = {
  query: string
  /** '' = orice rol; o cheie predefinită (`admin`) sau `id:N` pentru un rol custom */
  role: string
  /** '' = oricare; `local` = are parolă locală (inclusiv SSO + parolă); `sso` = doar SSO */
  signIn: '' | 'local' | 'sso'
  noRole: boolean
}
export const EMPTY_FILTER: AccountFilter = { query: '', role: '', signIn: '', noRole: false }

export const hasNoRole = (u: Pick<UserRow, 'bindings'>): boolean => (u.bindings ?? []).length === 0

/** legătura e rolul ales în filtru? (predefinit după cheie, custom după id) */
export function bindingIsRole(b: Pick<Binding, 'role' | 'role_id'>, role: string): boolean {
  if (role.startsWith('id:')) return b.role_id === Number(role.slice(3))
  return b.role === role
}

/** Căutare (email, fără diacritice, fiecare cuvânt trebuie să apară) + filtre. Ordinea: contul
    tău primul, apoi alfabetic după email — la 100+ conturi ordinea creării nu ajută pe nimeni. */
export function filterAccounts(users: readonly UserRow[], f: AccountFilter): UserRow[] {
  const words = fold(f.query).split(/\s+/).filter(Boolean)
  return users
    .filter((u) => {
      const email = fold(u.email)
      if (!words.every((w) => email.includes(w))) return false
      if (f.signIn === 'sso' && signInOf(u) !== 'sso') return false
      if (f.signIn === 'local' && signInOf(u) === 'sso') return false
      if (f.noRole && !hasNoRole(u)) return false
      if (f.role && !(u.bindings ?? []).some((b) => bindingIsRole(b, f.role))) return false
      return true
    })
    .sort((a, b) => (a.is_self === b.is_self ? a.email.localeCompare(b.email) : a.is_self ? -1 : 1))
}

export const filterActive = (f: AccountFilter): boolean => !!(f.query.trim() || f.role || f.signIn || f.noRole)

// ── roluri: unde e folosit fiecare (din datele deja încărcate) ──────────────────────────────
/** Câte legături (din lista de conturi) şi câte mapări SSO folosesc rolul. Pentru rolurile
    predefinite serverul nu trimite contoarele, dar le avem din listele deja încărcate. */
export function roleUsage(role: string, users: readonly UserRow[], mappings: readonly SsoMapping[]): { bindings: number; mappings: number } {
  let bindings = 0
  for (const u of users) for (const b of u.bindings ?? []) if (bindingIsRole(b, role)) bindings++
  const nm = mappings.filter((m) => (role.startsWith('id:') ? m.role_id === Number(role.slice(3)) : m.role === role)).length
  return { bindings, mappings: nm }
}

// ── SSO: mapările grupate pe numele grupului ────────────────────────────────────────────────
/** grupuri în ordine alfabetică (`*` = toţi utilizatorii SSO, ultimul); în grup, ordinea serverului */
export function groupMappings(mappings: readonly SsoMapping[]): { group: string; mappings: SsoMapping[] }[] {
  const by = new Map<string, SsoMapping[]>()
  for (const m of mappings) {
    const list = by.get(m.group)
    if (list) list.push(m)
    else by.set(m.group, [m])
  }
  return [...by.entries()]
    .sort(([a], [b]) => (a === '*' ? 1 : b === '*' ? -1 : a.localeCompare(b)))
    .map(([group, list]) => ({ group, mappings: list }))
}

/** grupurile create de `deploy/authentik/provision.py` (docs/SSO.md, „Groups out of the box") */
export const DEFAULT_SSO_GROUPS: readonly { group: string; key: string }[] = [
  { group: 'wt-access', key: 'access' },
  { group: 'wt-admins', key: 'admins' },
  { group: 'wt-readonly', key: 'readonly' },
  { group: 'wt-db', key: 'db' },
  { group: 'wt-network', key: 'network' },
]
