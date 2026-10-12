import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import { api, withSecondFactor as withSecondFactorT } from '../../../lib/api'
import { askSecret } from '../../../lib/secretPrompt'
import { useI18n } from '../../../lib/i18n'
import { groupPerms, heldEverywhere, ROLE_PRESETS, RoleRow, RolesCatalogue, roleValue, usePerms } from '../../../lib/perms'
import { roleUsage, type SsoMapping, type UserRow } from '../../../lib/usersAdmin'
import { field, heading } from '../ui'
import { Badge, Button } from '../../ui'
import HelpTip from '../../HelpTip'

/* Sub-tab-ul „Roles" (3.6.6). Rolurile predefinite (doar citire: ce înseamnă, câte permisiuni, unde
   sunt folosite) şi rolurile custom (3.6.2) cu editorul lor. Editarea cere `roles.manage`, ca
   înainte; cine are doar `users.manage` vede lista (o foloseşte oricum când acordă roluri), fără
   butoane. Fiecare salvare/ştergere: aceeaşi parolă (askSecret) + al doilea factor, aceleaşi rute. */

type Draft = { id: number | null; name: string; description: string; perms: Set<string> }

function RoleEditor(props: {
  catalogue: RolesCatalogue; draft: Draft; held: Set<string> | null; busy: boolean
  onChange: (d: Draft) => void; onSubmit: (e: FormEvent) => void; onCancel: () => void
}) {
  const { t } = useI18n()
  const { draft, held } = props
  // „New role" / „Edit" nu mai e sub cursor când se deschide editorul → focusul pe primul câmp,
  // nu pe <body> (audit 3.6.3)
  const nameRef = useRef<HTMLInputElement>(null)
  useEffect(() => { nameRef.current?.focus() }, [])
  const groups = useMemo(() => groupPerms(props.catalogue.perms), [props.catalogue.perms])
  const shellIds = useMemo(() => new Set(props.catalogue.perms.filter((p) => p.shell).map((p) => p.id)), [props.catalogue.perms])
  const anyShell = [...draft.perms].some((p) => shellIds.has(p))
  const toggle = (id: string, on: boolean) => {
    const perms = new Set(draft.perms)
    if (on) perms.add(id)
    else perms.delete(id)
    props.onChange({ ...draft, perms })
  }
  const formId = draft.id == null ? 'role-new' : `role-${draft.id}`
  return (
    // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape în formular îl închide (şi nu închide tot modalul)
    <form onSubmit={props.onSubmit} className="mt-3 flex flex-col gap-3 rounded-xl bg-ink-800/60 p-3 ring-1 ring-ink-700"
      aria-labelledby={`${formId}-title`} data-role-editor
      onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); props.onCancel() } }}>
      <div id={`${formId}-title`} className="text-sm font-semibold text-slate-200">
        {draft.id == null ? t('roles.custom.formTitleNew') : t('roles.custom.formTitleEdit', { name: draft.name })}
      </div>
      <div className="flex flex-col gap-2 sm:flex-row">
        <input ref={nameRef} type="text" value={draft.name} maxLength={60} autoComplete="off" aria-label={t('roles.custom.name')}
          placeholder={t('roles.custom.name')} className={field + ' sm:w-56'}
          onChange={(e) => props.onChange({ ...draft, name: e.target.value })} />
        <input type="text" value={draft.description} maxLength={300} autoComplete="off"
          aria-label={t('roles.custom.description')} placeholder={t('roles.custom.description')} className={field}
          onChange={(e) => props.onChange({ ...draft, description: e.target.value })} />
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
        <span>{t('roles.custom.preset')}</span>
        {ROLE_PRESETS.map((p) => (
          <Button key={p.id} type="button" size="sm"
            disabled={!!held && p.perms.some((x) => !held.has(x))}
            onClick={() => props.onChange({ ...draft, name: draft.name || t(p.labelKey), perms: new Set(p.perms) })}>
            {t(p.labelKey)}
          </Button>
        ))}
      </div>
      {groups.map((g) => (
        <fieldset key={g.id} className="flex flex-col gap-0.5">
          <legend className="mb-1 text-xs font-semibold text-slate-400">{t('roles.group.' + g.id)}</legend>
          <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-2">
            {g.perms.map((p) => {
              const notHeld = !!held && !held.has(p.id)
              const inputId = `${formId}-perm-${p.id.replace(/\./g, '-')}`
              return (
                <label key={p.id} htmlFor={inputId} title={notHeld ? t('roles.custom.notHeld') : undefined}
                  className={`flex min-h-7 items-center gap-2 text-sm ${notHeld ? 'text-slate-500' : 'text-slate-200'}`}>
                  <input id={inputId} type="checkbox" checked={draft.perms.has(p.id)}
                    disabled={notHeld && !draft.perms.has(p.id)}
                    onChange={(e) => toggle(p.id, e.target.checked)}
                    className="h-4 w-4 shrink-0 rounded-md accent-sky-600 [@media(pointer:coarse)]:h-6 [@media(pointer:coarse)]:w-6" />
                  <span className="min-w-0 flex-1">
                    {t('roles.perm.' + p.id)} <code className="text-2xs text-slate-400">{p.id}</code>
                  </span>
                  {p.shell && (
                    <Badge tone="warn" title={t('roles.shellHint')}>
                      <span aria-hidden="true">{t('roles.shellFlag')}</span>
                      <span className="sr-only">{t('roles.shellFlagLabel')}</span>
                    </Badge>
                  )}
                </label>
              )
            })}
          </div>
        </fieldset>
      ))}
      <p className="text-xs text-slate-400">{t('roles.custom.scopeNote')}</p>
      {anyShell && (
        <p role="note" className="rounded-md bg-warn/10 px-2 py-1.5 text-xs text-warn">
          <span aria-hidden="true">{t('roles.shellFlag')} </span>{t('roles.custom.shellBanner')}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="primary" disabled={props.busy || !draft.name.trim() || draft.perms.size === 0}>
          {draft.id == null ? t('roles.custom.create') : t('roles.custom.save')}
        </Button>
        <Button type="button" onClick={props.onCancel}>{t('roles.custom.cancel')}</Button>
      </div>
    </form>
  )
}

/** „Folosit de 3 legături şi 1 mapare SSO" / „Nefolosit încă" */
function usageText(t: (k: string, v?: Record<string, string | number>) => string, bindings: number, mappings: number) {
  return (bindings || mappings)
    ? t('roles.custom.used', { bindings: t('roles.custom.usedBindings', { count: bindings }), mappings: t('roles.custom.usedMappings', { count: mappings }) })
    : t('roles.custom.unused')
}

export default function RolesPanel(props: {
  catalogue: RolesCatalogue | null
  /** `roles.manage`: fără el lista e doar de citit */
  canEdit: boolean
  /** conturile şi mapările deja încărcate (pentru „unde e folosit" la rolurile predefinite);
      `null` = nu le avem (fără `users.manage`) — atunci nu afirmăm nimic despre folosire */
  users: UserRow[] | null
  mappings: SsoMapping[] | null
  reload: () => Promise<void>
  done: (text: string) => void; fail: (e: unknown) => void
}) {
  const { t } = useI18n()
  const perms = usePerms()
  const held = heldEverywhere(perms)
  const [draft, setDraft] = useState<Draft | null>(null)
  const [busy, setBusy] = useState(false)
  const newBtnRef = useRef<HTMLButtonElement>(null)
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const cat = props.catalogue

  const close = () => {
    setDraft(null)
    requestAnimationFrame(() => newBtnRef.current?.focus())   // focusul revine pe declanşator
  }

  async function save(e: FormEvent) {
    e.preventDefault()
    if (!draft) return
    const name = draft.name.trim()
    const pw = await askSecret(t(draft.id == null ? 'roles.custom.createConfirm' : 'roles.custom.saveConfirm', { name }))
    if (!pw) return
    setBusy(true)
    try {
      const body = { name, description: draft.description.trim(), perms: [...draft.perms].sort(), current_password: pw }
      await withSecondFactor((extra) => api(draft.id == null ? '/api/roles' : `/api/roles/${draft.id}`, {
        method: draft.id == null ? 'POST' : 'PATCH', body: JSON.stringify({ ...body, ...extra }),
      }))
      await props.reload()
      props.done(t(draft.id == null ? 'roles.custom.created' : 'roles.custom.saved'))
      close()
    } catch (x) { props.fail(x) }
    setBusy(false)
  }

  async function remove(r: RoleRow) {
    const pw = await askSecret(t('roles.custom.deleteConfirm', { name: r.name }))
    if (!pw) return
    try {
      await withSecondFactor((extra) => api(`/api/roles/${r.id}/delete`,
        { method: 'POST', body: JSON.stringify({ current_password: pw, ...extra }) }))
      await props.reload()
      props.done(t('roles.custom.deleted'))
    } catch (x) { props.fail(x) }
  }

  const usageKnown = props.users !== null
  return (
    <>
      <h3 className={heading + ' !mt-0 flex items-center gap-2'}>{t('roles.builtin.title')}<HelpTip id="roles" /></h3>
      <p className="mt-1 text-xs text-slate-500">{t('roles.builtin.hint')}</p>
      <ul className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2" data-builtin-roles>
        {(cat?.roles ?? []).map((r) => {
          const u = usageKnown ? roleUsage(r.key, props.users ?? [], props.mappings ?? []) : null
          return (
            <li key={r.key} className="flex flex-col gap-1 rounded-xl bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-slate-200">{t('roles.role.' + r.key)}</span>
                <Badge>{t('roles.custom.builtin')}</Badge>
                {r.shell && <Badge tone="warn" title={t('roles.shellHint')}>{t('roles.shell')}</Badge>}
              </div>
              <p className="text-xs text-slate-400">{t('roles.roleDesc.' + r.key)}</p>
              <p className="text-2xs text-slate-400">
                {t('roles.custom.permCount', { count: r.perms.length })}
                {u && <> · {usageText(t, u.bindings, u.mappings)}</>}
              </p>
            </li>
          )
        })}
      </ul>

      <div className="mt-6 flex flex-wrap items-center gap-2">
        <h3 className={heading + ' !mt-0 flex flex-1 items-center gap-2'}>{t('roles.custom.listTitle')}<HelpTip id="customRoles" /></h3>
        {cat && props.canEdit && !draft && (
          <Button ref={newBtnRef} type="button" size="sm" variant="primary" data-new-role
            onClick={() => setDraft({ id: null, name: '', description: '', perms: new Set(['host.view']) })}>
            {t('roles.custom.new')}
          </Button>
        )}
      </div>
      <p className="mt-1 text-xs text-slate-500">{t('roles.custom.hint')}</p>
      {!props.canEdit && <p className="mt-1 text-xs text-slate-400">{t('roles.custom.readOnly')}</p>}
      {cat && draft && (
        <RoleEditor catalogue={cat} draft={draft} held={held} busy={busy} onChange={setDraft}
          onSubmit={save} onCancel={close} />
      )}
      <ul className="mt-2 flex flex-col gap-1" data-roles-list>
        {cat && cat.custom.length === 0 && (
          <li className="px-3 py-1.5 text-sm text-slate-400">{t('roles.custom.none')}</li>
        )}
        {(cat?.custom ?? []).map((r) => {
          // contoarele vin de la server pentru rolurile custom; mapările le putem număra şi noi
          const nm = r.mappings ?? (props.mappings ?? []).filter((m) => m.role_id === r.id).length
          return (
            <li key={r.id} className="flex flex-col gap-1 rounded-md bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700"
              data-role-value={roleValue(r)}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="min-w-0 flex-1 truncate font-semibold text-slate-200">{r.name}</span>
                {r.shell && (
                  <Badge tone="warn" title={t('roles.shellHint')}>{t('roles.shell')}</Badge>
                )}
                {props.canEdit && (
                  <>
                    <Button type="button" size="sm" disabled={!r.editable || !!draft} aria-label={t('roles.custom.editAria', { name: r.name })}
                      title={r.editable ? undefined : t('roles.custom.cannotEdit')}
                      onClick={() => setDraft({ id: r.id, name: r.name, description: r.description ?? '', perms: new Set(r.perms) })}>
                      {t('roles.custom.edit')}
                    </Button>
                    <Button type="button" size="sm" variant="danger" disabled={!r.editable || !!(r.bindings || r.mappings)}
                      aria-label={t('roles.custom.deleteAria', { name: r.name })}
                      title={!r.editable ? t('roles.custom.cannotEdit') : (r.bindings || r.mappings) ? t('roles.custom.inUseHint') : undefined}
                      onClick={() => remove(r)}>
                      {t('settings.delete')}
                    </Button>
                  </>
                )}
              </div>
              {r.description && <p className="text-xs text-slate-400">{r.description}</p>}
              <p className="text-xs text-slate-400">
                {t('roles.custom.permCount', { count: r.perms.length })} · {usageText(t, r.bindings ?? 0, nm)}
              </p>
            </li>
          )
        })}
      </ul>
    </>
  )
}
