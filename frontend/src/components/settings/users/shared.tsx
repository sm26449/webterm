import { useMemo } from 'react'
import type { Host } from '../../../lib/api'
import { useI18n } from '../../../lib/i18n'
import { ROLE_KEYS, RolesCatalogue, roleValue, ScopeKind, SCOPE_KINDS, SHELL_ROLES } from '../../../lib/perms'
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
