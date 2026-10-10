import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api, ApiError, errText, Host, withSecondFactor as withSecondFactorT } from '../../lib/api'
import { useConfirm } from '../../lib/confirm'
import { ssoStepupRedirect } from '../../lib/stepup'
import { askSecret } from '../../lib/secretPrompt'
import { useI18n } from '../../lib/i18n'
import { Binding, groupPerms, heldEverywhere, loadPerms, ROLE_KEYS, ROLE_PRESETS, roleBody, roleLabel, RoleRow,
  RolesCatalogue, roleValue, ScopeKind, SCOPE_KINDS, scopeLabel, SHELL_ROLES, usePerms, can } from '../../lib/perms'
import { field, heading } from './ui'
import { Badge, Button, IconButton } from '../ui'
import { CloseIcon } from '../Icons'
import HelpTip from '../HelpTip'
import { canSave, type LoadState } from '../../lib/loadable'
import NotLoaded from './NotLoaded'

/* Settings → Users & roles (3.6). Extras din AccountTab: conturile şi, acum, LEGĂTURILE lor de
   rol (rol @ scope — docs/ROLES.md). Fără `users.manage` vezi doar propriul acces, read-only;
   serverul aplică oricum regulile (anti-escaladare, doar Owner atinge Owner-ii, ultimul Owner,
   nu-ţi schimbi singur accesul) — UI-ul doar le face vizibile.

   3.6.2: secţiunea „Roluri" (roluri custom, cu `roles.manage`) şi „Maparea grupurilor SSO"
   (cu `users.manage`, doar când SSO e activ). Aceleaşi reguli: tot ce bifezi aici e verificat
   din nou pe server, sub lock, pe drepturile de ACUM. */

type UserRow = {
  id: number; email: string; created: number; totp: boolean; passkeys: number; sso?: boolean
  is_self: boolean; bindings?: Binding[]; local_password?: boolean
}

type SsoMapping = {
  id: number; group: string; role: string; role_id: number; role_name: string
  scope_kind: ScopeKind; scope_value: string; sso_bindings: number
}

/** scope-ul implicit al unui rol: Operator/Viewer (şi rolurile custom) au sens DOAR restrânse (§A.5) */
const defaultScope = (role: string): ScopeKind => (role === 'owner' || role === 'admin' ? 'all' : 'folder')

function ScopePicker(props: {
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
function RoleOptions(props: { catalogue: RolesCatalogue | null; isOwner: boolean }) {
  const { t } = useI18n()
  const builtins = ROLE_KEYS.filter((k) => props.isOwner || k !== 'owner')   // doar un Owner acordă Owner
  return (
    <>
      {builtins.map((k) => <option key={k} value={k}>{t('roles.role.' + k)}</option>)}
      {(props.catalogue?.custom ?? []).map((r) => <option key={r.id} value={roleValue(r)}>{r.name}</option>)}
    </>
  )
}

const shellOf = (catalogue: RolesCatalogue | null, v: string): boolean => {
  if (!v) return false
  if (!v.startsWith('id:')) return SHELL_ROLES.includes(v)
  return !!catalogue?.custom.find((r) => roleValue(r) === v)?.shell
}

/* ── Roluri custom ──────────────────────────────────────────────────────────────────────── */
type Draft = { id: number | null; name: string; description: string; perms: Set<string> }

function RoleEditor(props: {
  catalogue: RolesCatalogue; draft: Draft; held: Set<string> | null; busy: boolean
  onChange: (d: Draft) => void; onSubmit: (e: FormEvent) => void; onCancel: () => void
}) {
  const { t } = useI18n()
  const { draft, held } = props
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
    <form onSubmit={props.onSubmit} className="mt-3 flex flex-col gap-3 rounded-xl bg-ink-800/60 p-3 ring-1 ring-ink-700"
      aria-labelledby={`${formId}-title`} data-role-editor>
      <div id={`${formId}-title`} className="text-sm font-semibold text-slate-200">
        {draft.id == null ? t('roles.custom.formTitleNew') : t('roles.custom.formTitleEdit', { name: draft.name })}
      </div>
      <div className="flex flex-col gap-2 sm:flex-row">
        <input type="text" value={draft.name} maxLength={60} autoComplete="off" aria-label={t('roles.custom.name')}
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

function RolesSection(props: {
  catalogue: RolesCatalogue | null; reload: () => Promise<void>
  done: (text: string) => void; fail: (e: unknown) => void
}) {
  const { t } = useI18n()
  const perms = usePerms()
  const held = heldEverywhere(perms)
  const [draft, setDraft] = useState<Draft | null>(null)
  const [busy, setBusy] = useState(false)
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const cat = props.catalogue

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
      setDraft(null)
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

  return (
    <>
      <h3 className={heading + ' flex items-center gap-2'}>{t('roles.custom.title')}<HelpTip id="customRoles" /></h3>
      <p className="mt-1 text-xs text-slate-500">{t('roles.custom.hint')}</p>
      <ul className="mt-2 flex flex-col gap-1" data-roles-list>
        {(cat?.roles ?? []).map((r) => (
          <li key={r.key} className="flex flex-wrap items-center gap-2 rounded-md px-3 py-1.5 text-sm ring-1 ring-ink-700">
            <span className="font-semibold text-slate-200">{t('roles.role.' + r.key)}</span>
            <Badge>{t('roles.custom.builtin')}</Badge>
            <span className="text-xs text-slate-400">{t('roles.custom.permCount', { n: r.perms.length })}</span>
          </li>
        ))}
        {cat && cat.custom.length === 0 && (
          <li className="px-3 py-1.5 text-sm text-slate-400">{t('roles.custom.none')}</li>
        )}
        {(cat?.custom ?? []).map((r) => (
          <li key={r.id} className="flex flex-col gap-1 rounded-md bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
            <div className="flex flex-wrap items-center gap-2">
              <span className="min-w-0 flex-1 truncate font-semibold text-slate-200">{r.name}</span>
              {r.shell && (
                <Badge tone="warn" title={t('roles.shellHint')}>{t('roles.shell')}</Badge>
              )}
              <Button size="sm" disabled={!r.editable} aria-label={t('roles.custom.editAria', { name: r.name })}
                title={r.editable ? undefined : t('roles.custom.cannotEdit')}
                onClick={() => setDraft({ id: r.id, name: r.name, description: r.description ?? '', perms: new Set(r.perms) })}>
                {t('roles.custom.edit')}
              </Button>
              <Button size="sm" variant="danger" disabled={!r.editable || !!(r.bindings || r.mappings)}
                aria-label={t('roles.custom.deleteAria', { name: r.name })}
                title={!r.editable ? t('roles.custom.cannotEdit') : (r.bindings || r.mappings) ? t('roles.custom.inUseHint') : undefined}
                onClick={() => remove(r)}>
                {t('settings.delete')}
              </Button>
            </div>
            {r.description && <p className="text-xs text-slate-400">{r.description}</p>}
            <p className="text-xs text-slate-400">
              {t('roles.custom.permCount', { n: r.perms.length })} · {(r.bindings || r.mappings)
                ? t('roles.custom.used', { bindings: r.bindings ?? 0, mappings: r.mappings ?? 0 })
                : t('roles.custom.unused')}
            </p>
          </li>
        ))}
      </ul>
      {cat && !draft && (
        <div className="mt-2">
          <Button onClick={() => setDraft({ id: null, name: '', description: '', perms: new Set(['host.view']) })} data-new-role>
            {t('roles.custom.new')}
          </Button>
        </div>
      )}
      {cat && draft && (
        <RoleEditor catalogue={cat} draft={draft} held={held} busy={busy} onChange={setDraft}
          onSubmit={save} onCancel={() => setDraft(null)} />
      )}
    </>
  )
}

/* ── Maparea grupurilor SSO ─────────────────────────────────────────────────────────────── */
function SsoSection(props: {
  catalogue: RolesCatalogue | null; hosts: Host[]; isOwner: boolean
  mappings: SsoMapping[]; localPwAccounts: number; reload: () => Promise<void>
  done: (text: string) => void; fail: (e: unknown) => void
}) {
  const { t } = useI18n()
  const [form, setForm] = useState({ group: '', role: 'viewer', scope_kind: 'folder' as ScopeKind, scope_value: '' })
  const [busy, setBusy] = useState(false)
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const hostName = (id: number) => props.hosts.find((h) => h.id === id)?.name
  const roleName = (v: string) => (v.startsWith('id:')
    ? props.catalogue?.custom.find((r) => roleValue(r) === v)?.name ?? v
    : t('roles.role.' + v))
  const label = (m: SsoMapping) => t('roles.chip', {
    role: roleLabel({ role: m.role, role_name: m.role_name }, t), scope: scopeLabel(m, hostName, t) })
  const scopeOk = form.scope_kind === 'all' || form.scope_value.trim() !== ''

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
      <h3 className={heading + ' flex items-center gap-2'}>{t('roles.sso.title')}<HelpTip id="ssoMapping" /></h3>
      <p className="mt-1 text-xs text-slate-500">{t('roles.sso.hint')}</p>
      <p className="mt-1 text-xs text-slate-400" data-sso-localpw-note>
        {t('roles.sso.localPwNote', { n: props.localPwAccounts })}
      </p>
      <ul className="mt-2 flex flex-col gap-1" data-sso-mappings>
        {props.mappings.length === 0 && <li className="text-sm text-slate-400">{t('roles.sso.none')}</li>}
        {props.mappings.map((m) => (
          <li key={m.id} className="flex flex-wrap items-center gap-2 rounded-md bg-ink-800/60 px-3 py-1.5 text-sm ring-1 ring-ink-700">
            <span className="min-w-0 flex-1 break-all text-slate-200">
              {t('roles.sso.mapping', { group: m.group, binding: label(m) })}
            </span>
            {m.sso_bindings > 0 && <Badge>{t('roles.sso.active', { n: m.sso_bindings })}</Badge>}
            {(props.isOwner || m.role !== 'owner') && (
              <IconButton label={t('roles.sso.remove', { group: m.group, binding: label(m) })} onClick={() => remove(m)}>
                <CloseIcon size={12} />
              </IconButton>
            )}
          </li>
        ))}
      </ul>
      <form onSubmit={add} className="mt-3 flex flex-col gap-2" data-sso-form>
        <div className="text-xs font-semibold text-slate-400">{t('roles.sso.add')}</div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <input type="text" value={form.group} maxLength={256} autoComplete="off" spellCheck={false}
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
        <div>
          <Button type="submit" variant="primary" disabled={busy || !form.group.trim() || !scopeOk}>{t('roles.sso.add')}</Button>
        </div>
      </form>
    </>
  )
}

export default function UsersTab() {
  const { t } = useI18n()
  const perms = usePerms()
  const manage = can(perms, 'users.manage')
  const rolesManage = can(perms, 'roles.manage')
  const isOwner = perms ? perms.owner : true
  const [busy, setBusy] = useState(false)
  const [users, setUsers] = useState<UserRow[]>([])
  const [hosts, setHosts] = useState<Host[]>([])
  const [catalogue, setCatalogue] = useState<RolesCatalogue | null>(null)
  const [sso, setSso] = useState<{ enabled: boolean; mappings: SsoMapping[]; local_password_accounts?: number } | null>(null)
  const { confirm } = useConfirm()
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  // unde apare mesajul: lângă secţiunea care l-a produs (altfel un „Rol salvat" ar apărea sus,
  // sub formularul de conturi, în afara ecranului)
  const [msgAt, setMsgAt] = useState<'users' | 'roles' | 'sso'>('users')
  const [newUser, setNewUser] = useState({ email: '', password: '', current_password: '',
    role: '', scope_kind: 'folder' as ScopeKind, scope_value: '' })
  const [grant, setGrant] = useState({ uid: '', role: 'viewer', scope_kind: 'folder' as ScopeKind, scope_value: '' })

  // U04: o listă de utilizatori goală pe un fetch picat ascundea conturile (şi rolurile) existente
  const [usersState, setUsersState] = useState<LoadState>({ status: 'loading' })
  const loadUsers = () => api<UserRow[]>('/api/users')
    .then((r) => { setUsers(r); setUsersState({ status: 'ok' }) })
    .catch((e) => setUsersState({ status: 'error', error: errText(e, t) }))
  const loadCatalogue = () => api<RolesCatalogue>('/api/roles').then(setCatalogue)
    .catch((e) => setErr(t('common.loadFailed') + ' ' + errText(e, t)))
  const loadSso = () => api<{ enabled: boolean; mappings: SsoMapping[]; local_password_accounts?: number }>(
    '/api/settings/oidc-roles').then(setSso)
    .catch(() => setSso(null))
  useEffect(() => {
    loadUsers()
    api<Host[]>('/api/hosts').then(setHosts).catch((e) => setErr(t('common.loadFailed') + ' ' + errText(e, t)))
  }, [])
  useEffect(() => { if (manage || rolesManage) void loadCatalogue() }, [manage, rolesManage])   // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (manage) void loadSso() }, [manage])   // eslint-disable-line react-hooks/exhaustive-deps

  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const hostName = (id: number) => hosts.find((h) => h.id === id)?.name
  const chip = (b: Binding) => t('roles.chip', { role: roleLabel(b, t), scope: scopeLabel(b, hostName, t) })
  const roleName = (v: string) => (v.startsWith('id:')
    ? catalogue?.custom.find((r) => roleValue(r) === v)?.name ?? v
    : t('roles.role.' + v))
  const scopeOk = (kind: ScopeKind, value: string) => kind === 'all' || value.trim() !== ''
  const done = (text: string, at: 'users' | 'roles' | 'sso' = 'users') => {
    setMsg(text); setErr(''); setMsgAt(at); loadPerms()
  }
  const fail = (e: unknown, at: 'users' | 'roles' | 'sso' = 'users') => {
    setErr(errText(e, t) || String(e)); setMsg(''); setMsgAt(at)
  }
  const reloadRoles = async () => { await Promise.all([loadCatalogue(), manage ? loadUsers() : Promise.resolve()]) }
  const reloadSso = async () => { await Promise.all([loadSso(), loadCatalogue(), loadUsers()]) }

  async function addUser(e: FormEvent) {
    e.preventDefault()
    setErr(''); setMsg(''); setBusy(true)
    try {
      const { role, ...rest } = newUser
      const body = { ...rest, ...(role ? roleBody(role) : {}), scope_value: role ? newUser.scope_value.trim() : '' }
      setUsers(await withSecondFactor((extra) => api<UserRow[]>('/api/users',
        { method: 'POST', body: JSON.stringify({ ...body, ...extra }) })))
      setNewUser({ email: '', password: '', current_password: '', role: '', scope_kind: 'folder', scope_value: '' })
      done(t('settings.users.added'))
    } catch (x) { fail(x) }
    setBusy(false)
  }

  async function removeUser(u: UserRow) {
    // askSecret, nu window.prompt: aici se tastează parola TA — mascată, ca peste tot
    const pw = await askSecret(t('settings.users.deleteConfirm', { email: u.email }))
    if (!pw) return
    setErr(''); setMsg('')
    try {
      setUsers(await withSecondFactor((extra) => api<UserRow[]>(`/api/users/${u.id}/delete`,
        { method: 'POST', body: JSON.stringify({ current_password: pw, ...extra }) })))
      done(t('settings.users.deleted'))
    } catch (x) { fail(x) }
  }

  async function addBinding(e: FormEvent) {
    e.preventDefault()
    const u = users.find((x) => String(x.id) === grant.uid)
    if (!u) return
    const label = t('roles.chip', { role: roleName(grant.role),
      scope: scopeLabel({ scope_kind: grant.scope_kind, scope_value: grant.scope_value.trim() }, hostName, t) })
    const pw = await askSecret(t('roles.bindings.addConfirm', { email: u.email, binding: label }))
    if (!pw) return
    setErr(''); setMsg(''); setBusy(true)
    try {
      await withSecondFactor((extra) => api(`/api/users/${u.id}/bindings`, {
        method: 'POST',
        body: JSON.stringify({ ...roleBody(grant.role), scope_kind: grant.scope_kind,
          scope_value: grant.scope_kind === 'all' ? '' : grant.scope_value.trim(), current_password: pw, ...extra }),
      }))
      await loadUsers()
      if (catalogue) void loadCatalogue()
      done(t('roles.bindings.added'))
    } catch (x) { fail(x) }
    setBusy(false)
  }

  async function removeBinding(u: UserRow, b: Binding) {
    const pw = await askSecret(t('roles.bindings.removeConfirm', { email: u.email, binding: chip(b) }))
    if (!pw) return
    setErr(''); setMsg('')
    try {
      await withSecondFactor((extra) => api(`/api/users/${u.id}/bindings/${b.id}/delete`,
        { method: 'POST', body: JSON.stringify({ current_password: pw, ...extra }) }))
      await loadUsers()
      if (catalogue) void loadCatalogue()
      done(t('roles.bindings.removed'))
    } catch (x) { fail(x) }
  }

  // 3.6.2 (revizuirea de securitate): un cont SSO cu parolă locală nu primeşte roluri din
  // grupuri. Omul îşi scoate singur parola (cu re-auth SSO); scoaterea revocă şi passkey-urile.
  async function removeLocalPassword() {
    if (!(await confirm({ title: t('roles.localPw.confirmTitle'), message: t('roles.localPw.confirmBody'),
      confirmLabel: t('roles.localPw.remove'), danger: true }))) return
    try {
      await withSecondFactor((extra) => api('/api/account',
        { method: 'POST', body: JSON.stringify({ remove_password: true, ...extra }) }))
      await loadUsers()
      done(t('roles.localPw.removed'))
    } catch (x) {
      if (x instanceof ApiError && x.code === 'account.ssoReauth') { ssoStepupRedirect(0); return }
      fail(x)
    }
  }

  const self = users.find((u) => u.is_self)
  const mine = perms?.bindings ?? self?.bindings ?? []
  const others = users.filter((u) => !u.is_self)
  const sourceTitle = (b: Binding) => (b.source === 'migration' ? t('roles.sourceMigration')
    : b.source === 'sso' ? t('roles.sourceSso') : undefined)
  const status = (at: 'users' | 'roles' | 'sso') => (msg || err) && msgAt === at && (
    <p role="status" className={`mt-2 text-sm ${err ? 'wt-danger' : 'wt-good'}`}>{err || msg}</p>
  )

  return (
    <div>
      <section data-setting-id="myAccess">
        <h3 className={heading + ' !mt-0 flex items-center gap-2'}>{t('roles.myAccess')}<HelpTip id="roles" /></h3>
        <p className="mt-1 text-xs text-slate-500">{t('roles.myAccessHint')}</p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {mine.length === 0
            ? <span className="text-sm text-slate-400">{t('roles.myNone')}</span>
            : mine.map((b) => (
              <Badge key={b.id} tone={b.role === 'owner' ? 'accent' : 'neutral'} className="px-2 py-0.5"
                title={sourceTitle(b)}>{chip(b)}</Badge>
            ))}
        </div>
        {self?.sso && self.local_password && (
          <div className="mt-3 flex flex-col items-start gap-2 rounded-md bg-warn/10 px-3 py-2" data-localpw-self>
            <p className="text-xs text-warn">{t('roles.localPw.mine')}</p>
            <Button size="sm" variant="danger" onClick={removeLocalPassword}>{t('roles.localPw.remove')}</Button>
          </div>
        )}
        {!manage && status('users')}
        <ul className="mt-3 flex flex-col gap-1 text-xs text-slate-400">
          {ROLE_KEYS.map((k) => (
            <li key={k} className="flex items-start gap-2">
              <span className="w-20 shrink-0 font-semibold text-slate-300">{t('roles.role.' + k)}</span>
              <span className="min-w-0 flex-1">{t('roles.roleDesc.' + k)}</span>
              {SHELL_ROLES.includes(k) && (
                <Badge tone="warn" title={t('roles.shellHint')}>{t('roles.shell')}</Badge>
              )}
            </li>
          ))}
        </ul>
      </section>

      <section data-setting-id="users" hidden={!manage}>
        <h3 className={heading}>{t('settings.users.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.users.hint')}</p>
        <NotLoaded state={usersState} onRetry={() => { setUsersState({ status: 'loading' }); void loadUsers() }} />
        <ul className="mt-2 flex flex-col gap-1" data-users-list>
          {canSave(usersState) && users.map((u) => (
            <li key={u.id} className="flex flex-col gap-1.5 rounded-md bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <div className="flex items-center gap-2">
                <span className="min-w-0 flex-1 truncate text-slate-200">{u.email}</span>
                {u.is_self && <span className="wt-chip-accent shrink-0 rounded-md px-1.5 py-0.5 text-2xs">{t('settings.users.you')}</span>}
                {u.sso && <span className="shrink-0 text-2xs text-slate-500">SSO</span>}
                {u.sso && u.local_password && (
                  <Badge tone="warn" title={t('roles.localPw.badgeHint')}>{t('roles.localPw.badge')}</Badge>
                )}
                {u.totp && <span className="shrink-0 text-2xs text-slate-500">2FA</span>}
                {u.passkeys > 0 && <span className="shrink-0 text-2xs text-slate-500">{t('settings.users.passkeys', { n: u.passkeys })}</span>}
                {!u.is_self && users.length > 1 && (
                  <button type="button" onClick={() => removeUser(u)} className="shrink-0 text-xs wt-danger hover:underline">
                    {t('settings.delete')}
                  </button>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                {(u.bindings ?? []).length === 0 && (
                  <Badge tone="warn">{t('roles.noRole')}</Badge>
                )}
                {(u.bindings ?? []).map((b) => (
                  <Badge key={b.id} tone={b.role === 'owner' ? 'accent' : 'neutral'} className="py-0.5 pl-2"
                    title={sourceTitle(b)}>
                    {chip(b)}
                    {!u.is_self && (isOwner || b.role !== 'owner') && (
                      <IconButton label={t('roles.bindings.remove', { binding: chip(b) })} touch={false}
                        onClick={() => removeBinding(u, b)}>
                        <CloseIcon size={10} />
                      </IconButton>
                    )}
                  </Badge>
                ))}
              </div>
            </li>
          ))}
        </ul>

        {others.length > 0 && (
          <form onSubmit={addBinding} className="mt-3 flex flex-col gap-2" data-grant-form>
            <div className="text-xs font-semibold text-slate-400">{t('roles.bindings.add')}</div>
            <div className="flex flex-col gap-2 sm:flex-row">
              <select value={grant.uid} aria-label={t('roles.bindings.account')} className={field}
                onChange={(e) => setGrant({ ...grant, uid: e.target.value })}>
                <option value="">{t('roles.bindings.accountPlaceholder')}</option>
                {others.map((u) => <option key={u.id} value={String(u.id)}>{u.email}</option>)}
              </select>
              <select value={grant.role} aria-label={t('roles.role.label')} className={field + ' sm:w-40'}
                onChange={(e) => setGrant({ ...grant, role: e.target.value, scope_kind: defaultScope(e.target.value), scope_value: '' })}>
                <RoleOptions catalogue={catalogue} isOwner={isOwner} />
              </select>
            </div>
            <ScopePicker idPrefix="grant" kind={grant.scope_kind} value={grant.scope_value} hosts={hosts}
              onChange={(k, v) => setGrant({ ...grant, scope_kind: k, scope_value: v })} />
            {shellOf(catalogue, grant.role) && <p className="text-xs text-slate-500">{t('roles.shellHint')}</p>}
            <div>
              <Button type="submit" variant="primary" disabled={busy || !grant.uid || !scopeOk(grant.scope_kind, grant.scope_value)}>
                {t('roles.bindings.addButton')}
              </Button>
            </div>
          </form>
        )}

        <form onSubmit={addUser} className="mt-5 flex flex-col gap-2" data-add-user-form>
          <div className="text-xs font-semibold text-slate-400">{t('settings.users.add')}</div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input type="email" value={newUser.email} autoComplete="off"
              onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
              placeholder={t('settings.users.emailPlaceholder')} aria-label={t('settings.email')} className={field} />
            <input type="password" value={newUser.password} autoComplete="new-password"
              onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              placeholder={t('settings.users.passwordPlaceholder')} aria-label={t('settings.newPassword')} className={field} />
          </div>
          <select value={newUser.role} aria-label={t('roles.role.label')} className={field}
            onChange={(e) => setNewUser({ ...newUser, role: e.target.value,
              scope_kind: defaultScope(e.target.value), scope_value: '' })}>
            <option value="">{t('roles.noRole')}</option>
            <RoleOptions catalogue={catalogue} isOwner={isOwner} />
          </select>
          {newUser.role && (
            <ScopePicker idPrefix="newuser" kind={newUser.scope_kind} value={newUser.scope_value} hosts={hosts}
              onChange={(k, v) => setNewUser({ ...newUser, scope_kind: k, scope_value: v })} />
          )}
          <input type="password" value={newUser.current_password} autoComplete="current-password"
            onChange={(e) => setNewUser({ ...newUser, current_password: e.target.value })}
            placeholder={t('settings.currentPasswordConfirm')} aria-label={t('settings.currentPassword')} className={field} />
          <div className="flex items-center gap-3">
            <Button variant="primary" type="submit"
              disabled={busy || !newUser.current_password || (!!newUser.role && !scopeOk(newUser.scope_kind, newUser.scope_value))}>
              {t('settings.users.add')}
            </Button>
          </div>
        </form>
        {status('users')}
      </section>

      <section data-setting-id="roles" hidden={!rolesManage}>
        <RolesSection catalogue={catalogue} reload={reloadRoles}
          done={(x) => done(x, 'roles')} fail={(e) => fail(e, 'roles')} />
        {status('roles')}
      </section>

      <section data-setting-id="ssoMapping" hidden={!manage || !sso?.enabled}>
        {manage && sso?.enabled && (
          <SsoSection catalogue={catalogue} hosts={hosts} isOwner={isOwner} mappings={sso.mappings}
            localPwAccounts={sso.local_password_accounts ?? 0}
            reload={reloadSso} done={(x) => done(x, 'sso')} fail={(e) => fail(e, 'sso')} />
        )}
        {status('sso')}
      </section>
    </div>
  )
}
