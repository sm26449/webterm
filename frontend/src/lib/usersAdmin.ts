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
  /** 3.6.10 — doar cu users.manage: ultima autentificare reuşită şi cum */
  last_login?: number | null
  last_login_method?: LoginMethod | null
  /** de când înregistrează serverul (un cont mai vechi fără ştampilă = „neînregistrat") */
  last_login_tracked_since?: number | null
  /** 3.6.11 — dezactivat de IdP prin SCIM (`active:false` = 'scim', DELETE = 'scim-delete') */
  disabled?: boolean
  disabled_at?: number | null
  disabled_by?: 'scim' | 'scim-delete' | null
  /** 3.6.11 — administrat de IdP prin SCIM; `scim_linked` = încă o resursă SCIM (nu ştearsă) */
  scim?: boolean
  scim_linked?: boolean
  display_name?: string | null
}

/** 3.6.11: starea SCIM din Settings → Users & roles → SSO groups (GET /api/settings/scim) */
export type ScimStatus = {
  configured: boolean; enabled: boolean; oidc_enabled: boolean; url: string
  token_created: number | null; token_created_by: string | null
  last_request: number | null
  last_error: { ts: number; status: number; detail: string } | null
  managed_accounts: number; disabled_accounts: number; groups: number
  /** doar în răspunsul la creare / rotire — arătat O SINGURĂ DATĂ */
  token?: string
}

/** ce arată panoul SCIM: neconfigurat / oprit / pornit dar fără SSO / pornit */
export type ScimState = 'off' | 'paused' | 'noSso' | 'on'
export function scimState(s: Pick<ScimStatus, 'configured' | 'enabled' | 'oidc_enabled'>): ScimState {
  if (!s.configured) return 'off'
  if (!s.enabled) return 'paused'
  return s.oidc_enabled ? 'on' : 'noSso'
}

export type LoginMethod = 'password' | 'password_2fa' | 'passkey' | 'sso'

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
  // 3.6.11: un cont creat de SCIM, încă nelegat (n-a intrat încă prin SSO), n-are parolă locală:
  // e tot „doar SSO". Fără câmp (rânduri vechi) = parolă locală, ca înainte.
  if (!u.sso) return u.local_password === false ? 'sso' : 'local'
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

// ── 3.6.10: ultima autentificare ─────────────────────────────────────────────────────────────
export type LastSignIn =
  | { state: 'at'; at: number; method: LoginMethod | null }
  | { state: 'never' }
  | { state: 'untracked'; since: number }
  | { state: 'hidden' }

/** Ce spunem despre ultima autentificare. `hidden` = serverul nu a trimis câmpul (fără
    users.manage); `untracked` = cont mai vechi decât înregistrarea, fără ştampilă — NU „niciodată". */
export function lastSignIn(u: Pick<UserRow, 'created' | 'last_login' | 'last_login_method' | 'last_login_tracked_since'>): LastSignIn {
  if (u.last_login === undefined) return { state: 'hidden' }
  if (u.last_login) return { state: 'at', at: u.last_login, method: u.last_login_method ?? null }
  const since = u.last_login_tracked_since
  if (since && u.created < since) return { state: 'untracked', since }
  return { state: 'never' }
}

// ── 3.6.10: legături temporare ───────────────────────────────────────────────────────────────
export type ExpiryChoice = 'permanent' | '4h' | '1d' | '7d' | 'custom'
export const EXPIRY_CHOICES: readonly ExpiryChoice[] = ['permanent', '4h', '1d', '7d', 'custom']
const PRESET_SECONDS: Record<string, number> = { '4h': 4 * 3600, '1d': 86400, '7d': 7 * 86400 }
/** aceeaşi limită ca serverul (authz.BINDING_MAX_DAYS) — o verificare de comoditate */
export const EXPIRY_MAX_DAYS = 366

/** → secunde epoch (sfârşitul), `null` = permanentă, `'invalid'` = data custom lipsă / în trecut /
    prea departe. `custom` = valoarea unui <input type="datetime-local"> (ora locală). */
export function expiryFrom(choice: ExpiryChoice, custom: string, nowMs: number): number | null | 'invalid' {
  if (choice === 'permanent') return null
  const now = nowMs / 1000
  if (choice !== 'custom') return Math.round(now + PRESET_SECONDS[choice])
  if (!custom) return 'invalid'
  const ms = new Date(custom).getTime()
  if (!Number.isFinite(ms)) return 'invalid'
  const ts = Math.round(ms / 1000)
  if (ts < now + 120 || ts > now + EXPIRY_MAX_DAYS * 86400) return 'invalid'
  return ts
}

/** cât mai e până la sfârşit, compact: {n, unit} cu unit m | h | d (rotunjit în sus la minute,
    în jos la ore/zile — „expiră în 3 h" nu trebuie să mintă în sus). `null` = a expirat. */
export function expiresIn(expires: number, nowMs: number): { n: number; unit: 'm' | 'h' | 'd' } | null {
  const left = expires - nowMs / 1000
  if (left <= 0) return null
  if (left < 3600) return { n: Math.max(1, Math.ceil(left / 60)), unit: 'm' }
  if (left < 2 * 86400) return { n: Math.floor(left / 3600), unit: 'h' }
  return { n: Math.floor(left / 86400), unit: 'd' }
}

// ── 3.6.10: explain access ───────────────────────────────────────────────────────────────────
export type ExplainBinding = Binding & {
  perms: string[]; expired: boolean; shell: boolean; ignored_global: string[]; sso_groups?: string[]
}
export type ExplainNote = { code: string; binding?: number; n?: number }
export type Explain = {
  user: { id: number; email: string; self: boolean }
  /** `crown_jewel`: only for an Owner or users.manage (3.6.10 review) */
  host: { id: number; name: string; folder: string; tags: string[]; crown_jewel?: boolean; require_2fa: boolean }
  bindings: ExplainBinding[]
  effective: string[]
  shell: boolean
  notes: ExplainNote[]
}

/** Ce poate face, în cuvinte (cheile `explain.can.*`), în ordinea în care întreabă omul:
    terminal, fişiere, comenzi, apoi restul. Doar din setul EFECTIV trimis de server. */
const CAPABILITIES: readonly [string, string][] = [
  ['session.open', 'terminal'], ['files.write', 'filesWrite'], ['files.read', 'filesRead'],
  ['run', 'run'], ['docker.act', 'docker'], ['session.watch', 'watch'],
  ['recording.view', 'recordings'], ['host.admin', 'admin'],
]
export function capabilities(effective: readonly string[]): string[] {
  const has = new Set(effective)
  const out = CAPABILITIES.filter(([p]) => has.has(p)).map(([, k]) => k)
  // „modifică fişiere" include „deschide": nu le spunem pe amândouă
  if (out.includes('filesWrite')) return out.filter((k) => k !== 'filesRead')
  if (!out.length && has.has('host.view')) return ['view']
  return out
}

// ── 3.6.10: tokenuri cu rol + scope ──────────────────────────────────────────────────────────
export type TokenRow = {
  id: number; name: string; scopes: string; created: number; created_by: string; expires: number
  last_used: number | null; expired: boolean
  role?: string; role_id?: number | null; role_name?: string
  scope_kind?: ScopeKind; scope_value?: string
}

/** null = token vechi (fără plafon de rol: doar scope-urile read/run ∩ creatorul) */
export function tokenCap(tk: Pick<TokenRow, 'role' | 'role_id' | 'role_name' | 'scope_kind' | 'scope_value'>):
  { role: string; role_name: string; scope_kind: ScopeKind; scope_value: string } | null {
  if (!tk.role_id) return null
  return { role: tk.role || '', role_name: tk.role_name || tk.role || '?',
    scope_kind: tk.scope_kind ?? 'all', scope_value: tk.scope_value ?? '' }
}
