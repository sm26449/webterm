import { FormEvent, useId, useMemo, useRef, useState } from 'react'
import { api, Host, withSecondFactor as withSecondFactorT } from '../../../lib/api'
import { askSecret } from '../../../lib/secretPrompt'
import { useI18n } from '../../../lib/i18n'
import { docsUrl } from '../../../lib/help'
import { roleBody, roleLabel, RolesCatalogue, ScopeKind, scopeLabel } from '../../../lib/perms'
import { fold } from '../../../lib/settingsIndex'
import { DEFAULT_SSO_GROUPS, groupMappings, type SsoMapping } from '../../../lib/usersAdmin'
import { field, heading } from '../ui'
import { Badge, Button, IconButton } from '../../ui'
import { CloseIcon, SearchIcon } from '../../Icons'
import HelpTip from '../../HelpTip'
import { defaultScope, RoleOptions, ScopePicker, shellOf, useRoleName } from './shared'

/* Sub-tab-ul „SSO groups" (3.6.2 „Maparea grupurilor SSO"; reorganizat în 3.6.6). Mapările sunt
   grupate pe numele grupului; cele din WEBTERM_OIDC_ROLE_MAP (.env) poartă „from configuration" şi
   n-au buton de ştergere (serverul le refuză oricum: 409 ssoMap.fromConfig). Adăugarea/ştergerea:
   aceleaşi rute, aceeaşi parolă (askSecret) + al doilea factor, aceeaşi regulă „doar un Owner
   atinge o mapare la Owner" (afişată; serverul o aplică). */

const SSO_DOC = 'docs/SSO.md#groups-out-of-the-box-365'
/** peste atâtea grupuri apare câmpul de filtrare */
const FILTER_FROM = 6

export default function SsoPanel(props: {
  catalogue: RolesCatalogue | null; hosts: Host[]; isOwner: boolean
  mappings: SsoMapping[]; localPwAccounts: number; reload: () => Promise<void>
  done: (text: string) => void; fail: (e: unknown) => void
}) {
  const { t } = useI18n()
  const [form, setForm] = useState({ group: '', role: 'viewer', scope_kind: 'folder' as ScopeKind, scope_value: '' })
  const [adding, setAdding] = useState(false)
  const [busy, setBusy] = useState(false)
  const [query, setQuery] = useState('')
  const addBtnRef = useRef<HTMLButtonElement>(null)
  const formId = useId()
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const hostName = (id: number) => props.hosts.find((h) => h.id === id)?.name
  const roleName = useRoleName(props.catalogue)
  const label = (m: SsoMapping) => t('roles.chip', {
    role: roleLabel({ role: m.role, role_name: m.role_name }, t), scope: scopeLabel(m, hostName, t) })
  const scopeOk = form.scope_kind === 'all' || form.scope_value.trim() !== ''

  const groups = useMemo(() => groupMappings(props.mappings), [props.mappings])
  const shown = useMemo(() => {
    const q = fold(query.trim())
    return q ? groups.filter((g) => fold(g.group).includes(q)) : groups
  }, [groups, query])

  const closeForm = () => {
    setAdding(false)
    requestAnimationFrame(() => addBtnRef.current?.focus())
  }

  async function add(e: FormEvent) {
    e.preventDefault()
    const group = form.group.trim()
    const binding = t('roles.chip', { role: roleName(form.role),
      scope: scopeLabel({ scope_kind: form.scope_kind, scope_value: form.scope_value.trim() }, hostName, t) })
    const pw = await askSecret(t('roles.sso.addConfirm', { group, binding }))
    if (!pw) return
    setBusy(true)
    try {
      await withSecondFactor((extra) => api('/api/settings/oidc-roles', {
        method: 'POST',
        body: JSON.stringify({ group, ...roleBody(form.role), scope_kind: form.scope_kind,
          scope_value: form.scope_kind === 'all' ? '' : form.scope_value.trim(), current_password: pw, ...extra }),
      }))
      await props.reload()
      setForm({ ...form, group: '' })
      props.done(t('roles.sso.added'))
      closeForm()
    } catch (x) { props.fail(x) }
    setBusy(false)
  }

  async function remove(m: SsoMapping) {
    const pw = await askSecret(t('roles.sso.removeConfirm', { group: m.group, binding: label(m) }))
    if (!pw) return
    try {
      await withSecondFactor((extra) => api(`/api/settings/oidc-roles/${m.id}/delete`,
        { method: 'POST', body: JSON.stringify({ current_password: pw, ...extra }) }))
      await props.reload()
      props.done(t('roles.sso.removed'))
    } catch (x) { props.fail(x) }
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className={heading + ' !mt-0 flex flex-1 items-center gap-2'}>{t('roles.sso.title')}<HelpTip id="ssoMapping" /></h3>
        <Button ref={addBtnRef} type="button" size="sm" variant={adding ? 'secondary' : 'primary'}
          aria-expanded={adding} aria-controls={adding ? formId : undefined}
          onClick={() => (adding ? closeForm() : setAdding(true))} data-sso-add>
          {t('roles.sso.add')}
        </Button>
      </div>
      <p className="mt-1 text-xs text-slate-500">{t('roles.sso.hint')}</p>
      {props.localPwAccounts > 0 && (
        <p className="mt-1 text-xs text-slate-400" data-sso-localpw-note>
          {t('roles.sso.localPwNote', { n: props.localPwAccounts })}
        </p>
      )}

      {adding && (
        // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape în formular îl închide (şi nu închide tot modalul)
        <form id={formId} onSubmit={add} className="mt-3 flex flex-col gap-2 rounded-xl bg-ink-800/60 p-3 ring-1 ring-ink-700" data-sso-form
          aria-label={t('roles.sso.add')}
          onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); closeForm() } }}>
          <div className="text-sm font-semibold text-slate-200">{t('roles.sso.add')}</div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input type="text" value={form.group} maxLength={256} autoComplete="off" spellCheck={false} autoFocus
              aria-label={t('roles.sso.group')} placeholder={t('roles.sso.groupPlaceholder')} className={field}
              onChange={(e) => setForm({ ...form, group: e.target.value })} />
            <select value={form.role} aria-label={t('roles.role.label')} className={field + ' sm:w-48'}
              onChange={(e) => setForm({ ...form, role: e.target.value, scope_kind: defaultScope(e.target.value), scope_value: '' })}>
              <RoleOptions catalogue={props.catalogue} isOwner={props.isOwner} />
            </select>
          </div>
          <ScopePicker idPrefix="sso" kind={form.scope_kind} value={form.scope_value} hosts={props.hosts}
            onChange={(k, v) => setForm({ ...form, scope_kind: k, scope_value: v })} />
          <p className="text-xs text-slate-400">{t('roles.sso.caseNote')}</p>
          {shellOf(props.catalogue, form.role) && <p className="text-xs text-slate-400">{t('roles.shellHint')}</p>}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" variant="primary" disabled={busy || !form.group.trim() || !scopeOk}>{t('roles.sso.add')}</Button>
            <Button type="button" onClick={closeForm}>{t('roles.custom.cancel')}</Button>
          </div>
        </form>
      )}

      {props.mappings.some((m) => m.source === 'config') && (
        <p className="mt-3 text-xs text-slate-400" data-sso-config-note>{t('roles.sso.configNote')}</p>
      )}

      {groups.length > FILTER_FROM && (
        <div className="relative mt-3 sm:max-w-xs">
          <span aria-hidden="true" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500">
            <SearchIcon size={14} />
          </span>
          <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" spellCheck={false}
            aria-label={t('roles.sso.filter')} placeholder={t('roles.sso.filter')} className={field + ' pl-8'} />
        </div>
      )}

      <div className="mt-3" data-sso-mappings>
        {props.mappings.length === 0 ? (
          <div className="rounded-xl px-4 py-4 text-sm border border-dashed border-ink-700" data-sso-empty>
            <p className="font-semibold text-slate-200">{t('roles.sso.none')}</p>
            <p className="mt-2 text-xs text-slate-400">{t('roles.sso.emptyDefaults')}</p>
            <ul className="mt-2 flex flex-col gap-1 text-xs text-slate-400">
              {DEFAULT_SSO_GROUPS.map((g) => (
                <li key={g.group} className="flex flex-wrap gap-x-2">
                  <code className="font-mono text-slate-300">{g.group}</code>
                  <span>{t('roles.sso.default.' + g.key)}</span>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-slate-400">{t('roles.sso.emptyRoleMap')}</p>
            <a href={docsUrl(SSO_DOC)} target="_blank" rel="noopener noreferrer"
              className="wt-link mt-2 inline-block text-xs underline">{t('roles.sso.emptyDocs')}</a>
          </div>
        ) : shown.length === 0 ? (
          <p className="text-sm text-slate-400">{t('roles.sso.noMatch', { query: query.trim() })}</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {shown.map((g) => (
              <li key={g.group} className="rounded-xl bg-ink-800/60 ring-1 ring-ink-700" data-sso-group={g.group}>
                <div className="flex items-center gap-2 border-b border-ink-700 px-3 py-1.5">
                  <span className="min-w-0 flex-1 break-all font-mono text-sm font-semibold text-slate-200">
                    {g.group === '*' ? <>* <span className="font-sans text-xs font-normal text-slate-400">{t('roles.sso.everyone')}</span></> : g.group}
                  </span>
                  <Badge>{t('roles.sso.groupCount', { count: g.mappings.length })}</Badge>
                </div>
                <ul className="flex flex-col">
                  {g.mappings.map((m) => (
                    <li key={m.id} className="flex flex-wrap items-center gap-2 px-3 py-1.5 text-sm">
                      {/* vizual grupul e în antet; cititorul de ecran aude mereu „grup → rol · scope" */}
                      <span className="sr-only">{t('roles.sso.mapping', { group: m.group, binding: label(m) })}</span>
                      <span aria-hidden="true" className="min-w-0 flex-1 break-words text-slate-200">{label(m)}</span>
                      {m.source === 'config' && (
                        <Badge title={t('roles.sso.fromConfigTitle')} tone="info">
                          <span data-sso-from-config>{t('roles.sso.fromConfig')}</span>
                        </Badge>
                      )}
                      {m.sso_bindings > 0 && <Badge>{t('roles.sso.active', { n: m.sso_bindings })}</Badge>}
                      {m.source !== 'config' && (props.isOwner || m.role !== 'owner') && (
                        <IconButton label={t('roles.sso.remove', { group: m.group, binding: label(m) })} variant="danger"
                          onClick={() => remove(m)}>
                          <CloseIcon size={12} />
                        </IconButton>
                      )}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  )
}
