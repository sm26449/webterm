import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api, errText, Host, withSecondFactor as withSecondFactorT } from '../../lib/api'
import { askSecret } from '../../lib/secretPrompt'
import { useI18n } from '../../lib/i18n'
import { Binding, loadPerms, ROLE_KEYS, roleLabel, ScopeKind, SCOPE_KINDS, scopeLabel, SHELL_ROLES,
  usePerms, can } from '../../lib/perms'
import { field, heading } from './ui'
import { Badge, Button, IconButton } from '../ui'
import { CloseIcon } from '../Icons'
import HelpTip from '../HelpTip'

/* Settings → Users & roles (3.6). Extras din AccountTab: conturile şi, acum, LEGĂTURILE lor de
   rol (rol @ scope — docs/ROLES.md). Fără `users.manage` vezi doar propriul acces, read-only;
   serverul aplică oricum regulile (anti-escaladare, doar Owner atinge Owner-ii, ultimul Owner,
   nu-ţi schimbi singur accesul) — UI-ul doar le face vizibile. */

type UserRow = {
  id: number; email: string; created: number; totp: boolean; passkeys: number; sso?: boolean
  is_self: boolean; bindings?: Binding[]
}

/** scope-ul implicit al unui rol: Operator/Viewer au sens DOAR restrânse (§A.5) */
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

export default function UsersTab() {
  const { t } = useI18n()
  const perms = usePerms()
  const manage = can(perms, 'users.manage')
  const isOwner = perms ? perms.owner : true
  const [busy, setBusy] = useState(false)
  const [users, setUsers] = useState<UserRow[]>([])
  const [hosts, setHosts] = useState<Host[]>([])
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [newUser, setNewUser] = useState({ email: '', password: '', current_password: '',
    role: '', scope_kind: 'folder' as ScopeKind, scope_value: '' })
  const [grant, setGrant] = useState({ uid: '', role: 'viewer', scope_kind: 'folder' as ScopeKind, scope_value: '' })

  const loadUsers = () => api<UserRow[]>('/api/users').then(setUsers).catch(() => {})
  useEffect(() => {
    loadUsers()
    api<Host[]>('/api/hosts').then(setHosts).catch(() => {})
  }, [])

  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const hostName = (id: number) => hosts.find((h) => h.id === id)?.name
  const chip = (b: Binding) => t('roles.chip', { role: roleLabel(b, t), scope: scopeLabel(b, hostName, t) })
  const roleOptions = ROLE_KEYS.filter((k) => isOwner || k !== 'owner')   // doar un Owner acordă Owner
  const scopeOk = (kind: ScopeKind, value: string) => kind === 'all' || value.trim() !== ''
  const done = (text: string) => { setMsg(text); setErr(''); loadPerms() }
  const fail = (e: unknown) => { setErr(errText(e, t) || String(e)); setMsg('') }

  async function addUser(e: FormEvent) {
    e.preventDefault()
    setErr(''); setMsg(''); setBusy(true)
    try {
      const body = { ...newUser, scope_value: newUser.role ? newUser.scope_value.trim() : '' }
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
    const label = t('roles.chip', { role: t('roles.role.' + grant.role),
      scope: scopeLabel({ scope_kind: grant.scope_kind, scope_value: grant.scope_value.trim() }, hostName, t) })
    const pw = await askSecret(t('roles.bindings.addConfirm', { email: u.email, binding: label }))
    if (!pw) return
    setErr(''); setMsg(''); setBusy(true)
    try {
      await withSecondFactor((extra) => api(`/api/users/${u.id}/bindings`, {
        method: 'POST',
        body: JSON.stringify({ role: grant.role, scope_kind: grant.scope_kind,
          scope_value: grant.scope_kind === 'all' ? '' : grant.scope_value.trim(), current_password: pw, ...extra }),
      }))
      await loadUsers()
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
      done(t('roles.bindings.removed'))
    } catch (x) { fail(x) }
  }

  const mine = perms?.bindings ?? users.find((u) => u.is_self)?.bindings ?? []
  const others = users.filter((u) => !u.is_self)

  return (
    <div>
      <section data-setting-id="myAccess">
        <h3 className={heading + ' !mt-0 flex items-center gap-2'}>{t('roles.myAccess')}<HelpTip id="roles" /></h3>
        <p className="mt-1 text-xs text-slate-500">{t('roles.myAccessHint')}</p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {mine.length === 0
            ? <span className="text-sm text-slate-400">{t('roles.myNone')}</span>
            : mine.map((b) => (
              <Badge key={b.id} tone={b.role === 'owner' ? 'accent' : 'neutral'} className="px-2 py-0.5">{chip(b)}</Badge>
            ))}
        </div>
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
        <ul className="mt-2 flex flex-col gap-1" data-users-list>
          {users.map((u) => (
            <li key={u.id} className="flex flex-col gap-1.5 rounded-md bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <div className="flex items-center gap-2">
                <span className="min-w-0 flex-1 truncate text-slate-200">{u.email}</span>
                {u.is_self && <span className="wt-chip-accent shrink-0 rounded-md px-1.5 py-0.5 text-2xs">{t('settings.users.you')}</span>}
                {u.sso && <span className="shrink-0 text-2xs text-slate-500">SSO</span>}
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
                    title={b.source === 'migration' ? t('roles.sourceMigration') : undefined}>
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
                {roleOptions.map((k) => <option key={k} value={k}>{t('roles.role.' + k)}</option>)}
              </select>
            </div>
            <ScopePicker idPrefix="grant" kind={grant.scope_kind} value={grant.scope_value} hosts={hosts}
              onChange={(k, v) => setGrant({ ...grant, scope_kind: k, scope_value: v })} />
            {SHELL_ROLES.includes(grant.role) && <p className="text-xs text-slate-500">{t('roles.shellHint')}</p>}
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
            {roleOptions.map((k) => <option key={k} value={k}>{t('roles.role.' + k)}</option>)}
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
        {(msg || err) && (
          <p role="status" className={`mt-2 text-sm ${err ? 'wt-danger' : 'wt-good'}`}>{err || msg}</p>
        )}
      </section>
    </div>
  )
}
