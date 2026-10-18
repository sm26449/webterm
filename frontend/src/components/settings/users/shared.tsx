import { useEffect, useMemo, useState } from 'react'
import { accessReauthPlan, api, withAccessReauth, type Host, type ReauthMe, type ReauthPlan, type SettingsReturn } from '../../../lib/api'
import { useConfirm } from '../../../lib/confirm'
import { useI18n } from '../../../lib/i18n'
import { ROLE_KEYS, RolesCatalogue, roleValue, ScopeKind, SCOPE_KINDS, SHELL_ROLES } from '../../../lib/perms'
import { EXPIRY_CHOICES, expiresIn, expiryFrom, type ExpiryChoice, type UserRow } from '../../../lib/usersAdmin'
import { field } from '../ui'

/* Piese comune sub-tab-urilor din Users & roles (3.6.6; mutate din UsersTab.tsx fără schimbări de
   comportament): alegerea scope-ului, opţiunile de rol şi regula „⚑ shell". */

/** scope-ul implicit al unui rol: Operator/Viewer (şi rolurile custom) au sens DOAR restrânse (§A.5) */
export const defaultScope = (role: string): ScopeKind => (role === 'owner' || role === 'admin' ? 'all' : 'folder')

export const scopeOk = (kind: ScopeKind, value: string) => kind === 'all' || value.trim() !== ''

export function ScopePicker(props: {
  kind: ScopeKind; value: string; hosts: Host[]
  onChange: (kind: ScopeKind, value: string) => void
  idPrefix: string
}) {
  const { t } = useI18n()
  const folders = useMemo(() => [...new Set(props.hosts.map((h) => h.folder || '').filter(Boolean))].sort(), [props.hosts])
  const tags = useMemo(() => [...new Set(props.hosts.flatMap((h) => h.tags || []))].sort(), [props.hosts])
  const listId = `${props.idPrefix}-scope-list`
  return (
    <div className="flex flex-col gap-2 sm:flex-row">
      <select value={props.kind} aria-label={t('roles.scope.label')} className={field + ' sm:w-40'}
        onChange={(e) => props.onChange(e.target.value as ScopeKind, '')}>
        {SCOPE_KINDS.map((k) => <option key={k} value={k}>{t('roles.scope.' + k)}</option>)}
      </select>
      {props.kind === 'host' && (
        <select value={props.value} aria-label={t('roles.scope.host')} className={field}
          onChange={(e) => props.onChange('host', e.target.value)}>
          <option value="">{t('roles.scope.hostPlaceholder')}</option>
          {props.hosts.filter((h) => !h.ephemeral).map((h) => <option key={h.id} value={String(h.id)}>{h.name}</option>)}
        </select>
      )}
      {(props.kind === 'folder' || props.kind === 'tag') && (
        <>
          <input type="text" list={listId} value={props.value} autoComplete="off"
            onChange={(e) => props.onChange(props.kind, e.target.value)}
            placeholder={t(props.kind === 'folder' ? 'roles.scope.folderPlaceholder' : 'roles.scope.tagPlaceholder')}
            aria-label={t('roles.scope.' + props.kind)} className={field} />
          <datalist id={listId}>
            {(props.kind === 'folder' ? folders : tags).map((v) => <option key={v} value={v} />)}
          </datalist>
        </>
      )}
    </div>
  )
}

/** 3.6.10: durata unei legături noi — permanentă / 4 h / 1 zi / 7 zile / până la o dată. Valoarea
    finală (secunde epoch | null | 'invalid') o calculează `expiryFrom`, la trimitere. */
export function ExpiryPicker(props: {
  choice: ExpiryChoice; custom: string; idPrefix: string
  onChange: (choice: ExpiryChoice, custom: string) => void
}) {
  const { t } = useI18n()
  const invalid = props.choice === 'custom' && expiryFrom('custom', props.custom, Date.now()) === 'invalid'
  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
      <select value={props.choice} aria-label={t('roles.expiry.label')} className={field + ' sm:w-48'}
        data-expiry-choice onChange={(e) => props.onChange(e.target.value as ExpiryChoice, props.custom)}>
        {EXPIRY_CHOICES.map((c) => <option key={c} value={c}>{t('roles.expiry.' + c)}</option>)}
      </select>
      {props.choice === 'custom' && (
        <input type="datetime-local" value={props.custom} aria-label={t('roles.expiry.customLabel')}
          aria-invalid={invalid || undefined} aria-describedby={invalid ? `${props.idPrefix}-exp-err` : undefined}
          onChange={(e) => props.onChange('custom', e.target.value)} className={field + ' sm:w-56'} />
      )}
      {invalid && props.custom && (
        <span id={`${props.idPrefix}-exp-err`} className="text-xs text-warn">{t('roles.expiry.invalid')}</span>
      )}
    </div>
  )
}

/** „expiră în 3h" pentru o legătură temporară (nimic pentru una permanentă) */
export function useExpiryText() {
  const { t } = useI18n()
  return (expires: number | null | undefined): string => {
    if (!expires) return ''
    const left = expiresIn(expires, Date.now())
    return left ? t('roles.expiry.in', { time: `${left.n}${t('time.' + left.unit)}` }) : t('explain.expired')
  }
}

/** <option>-urile de rol: predefinitele (fără Owner pentru un ne-Owner), apoi cele custom. */
export function RoleOptions(props: { catalogue: RolesCatalogue | null; isOwner: boolean }) {
  const { t } = useI18n()
  const builtins = ROLE_KEYS.filter((k) => props.isOwner || k !== 'owner')   // doar un Owner acordă Owner
  return (
    <>
      {builtins.map((k) => <option key={k} value={k}>{t('roles.role.' + k)}</option>)}
      {(props.catalogue?.custom ?? []).map((r) => <option key={r.id} value={roleValue(r)}>{r.name}</option>)}
    </>
  )
}

export const shellOf = (catalogue: RolesCatalogue | null, v: string): boolean => {
  if (!v) return false
  if (!v.startsWith('id:')) return SHELL_ROLES.includes(v)
  return !!catalogue?.custom.find((r) => roleValue(r) === v)?.shell
}

/** numele afişat al unei valori de rol (`admin` → „Admin", `id:7` → numele rolului custom) */
export function useRoleName(catalogue: RolesCatalogue | null) {
  const { t } = useI18n()
  return (v: string) => (v.startsWith('id:')
    ? catalogue?.custom.find((r) => roleValue(r) === v)?.name ?? v
    : t('roles.role.' + v))
}

/** RB-03 (audit 2026-10-17): re-autentificarea la o schimbare de acces, pentru TOATE acţiunile din
    Accounts / Roles / SSO groups / tokenuri / parola locală (lib/api.ts `withAccessReauth`). `me` =
    rândul propriu de la /api/users (`selfOf` / `useSelfRow`): un cont SSO nu mai primeşte un prompt de
    parolă pe care n-o are — confirmă (dialogul obişnuit) şi face passkey account-scope sau step-up SSO.
    `plan` lasă formularele cu parolă inline (Add account, token) să ascundă câmpul când nu e de folos.
    `passwordGate` = o rută care verifică doar parola (niciuna azi, 3.6.18): planul e 'password' pentru oricine
    (altfel am promite „fără parolă" şi serverul ar răspunde 401). `returnTo` = panoul Settings de
    redeschis după un redirect la IdP (salvat în sessionStorage înainte de plecare). */
export const RETURN_USERS: SettingsReturn = { cat: 'utilizatori' }
export const RETURN_INFRA: SettingsReturn = { cat: 'infrastructura' }
export function useAccessReauth(me: ReauthMe, opts: { passwordGate?: boolean; returnTo?: SettingsReturn } = {}) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const passwordGate = !!opts.passwordGate
  const returnTo = opts.returnTo
  const plan: ReauthPlan = accessReauthPlan(me, typeof window !== 'undefined' && !!window.PublicKeyCredential, passwordGate)
  const reauth = <T,>(prompt: string, send: (cred: object) => Promise<T>, password?: string) =>
    withAccessReauth(t, prompt, send, {
      me, password, passwordGate, returnTo,
      confirm: (q) => confirm({ title: t('access.reauth.title'), message: q, confirmLabel: t('common.confirm') }),
    })
  return { plan, reauth }
}

/** rândul propriu dintr-o listă deja încărcată (`undefined` = încă nu ştim) */
export const selfOf = (users: UserRow[] | null | undefined): ReauthMe =>
  users ? users.find((u) => u.is_self) ?? null : undefined

/** rândul propriu de la /api/users, pentru panourile care nu au lista (orice cont îl primeşte, §A.6.3);
    un fetch picat lasă `null` → planul cu parolă, iar 403-ul serverului rămâne plasa de siguranţă.
    Lista e scumpă pentru users.manage (legăturile fiecărui cont, RB-07) şi tab-ul se remontează la
    fiecare schimbare de sub-tab: răspunsul e ţinut un minut la nivel de modul. Un rând vechi nu
    slăbeşte nimic — planul greşit sfârşeşte în 403 → step-up SSO, iar un fetch picat nu e reţinut.
    Cache-ul e uitat la `wt-unauth` (sesiune expirată / ieşire): pagina de login vine fără reload,
    deci alt cont intrat în acelaşi minut nu trebuie să moştenească rândul precedentului. */
const SELF_ROW_TTL = 60_000
let selfRowCache: { at: number; p: Promise<ReauthMe> } | null = null
export function forgetSelfRow(): void { selfRowCache = null }
if (typeof window !== 'undefined') window.addEventListener('wt-unauth', forgetSelfRow)
export function fetchSelfRow(now = Date.now()): Promise<ReauthMe> {
  if (!selfRowCache || now - selfRowCache.at > SELF_ROW_TTL) {
    const p = api<UserRow[]>('/api/users').then((rows) => selfOf(rows))
    p.catch(() => { if (selfRowCache?.p === p) selfRowCache = null })
    selfRowCache = { at: now, p }
  }
  return selfRowCache.p
}
export function useSelfRow(): ReauthMe {
  const [me, setMe] = useState<ReauthMe>(undefined)
  useEffect(() => {
    let live = true
    fetchSelfRow().then((row) => { if (live) setMe(row) }).catch(() => { if (live) setMe(null) })
    return () => { live = false }
  }, [])
  return me
}

/** Mesajul unei acţiuni, lângă panoul care l-a produs. Regiunile stau montate mereu (design
    system, „error ≠ empty"): o schimbare e anunţată, iar eroarea e `alert`, succesul `status`. */
export function ActionStatus(props: { msg: string; err: string }) {
  return (
    <>
      <p role="alert" className={props.err ? 'mt-2 text-sm wt-danger' : 'sr-only'}>{props.err}</p>
      <p role="status" className={props.msg && !props.err ? 'mt-2 text-sm wt-good' : 'sr-only'}>{props.err ? '' : props.msg}</p>
    </>
  )
}
