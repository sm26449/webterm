import { FormEvent, useEffect, useId, useMemo, useRef, useState } from 'react'
import { api, Host, withSecondFactor as withSecondFactorT } from '../../../lib/api'
import { askSecret } from '../../../lib/secretPrompt'
import { useI18n } from '../../../lib/i18n'
import { Binding, roleBody, roleLabel, RolesCatalogue, roleValue, ROLE_KEYS, ScopeKind, scopeLabel } from '../../../lib/perms'
import { fmtTs } from '../../../lib/tz'
import { EMPTY_FILTER, expiryFrom, filterAccounts, filterActive, hasNoRole, lastSignIn, signInOf,
  type AccountFilter, type ExpiryChoice, type UserRow } from '../../../lib/usersAdmin'
import { crownDialog, withCrownConfirm } from '../../../lib/crown'
import { useConfirm } from '../../../lib/confirm'
import { field } from '../ui'
import { Badge, Button, IconButton } from '../../ui'
import { ChevronIcon, CloseIcon, SearchIcon, WarningIcon } from '../../Icons'
import { defaultScope, ExpiryPicker, RoleOptions, ScopePicker, scopeOk, shellOf, useExpiryText, useRoleName } from './shared'
import ExplainAccess from './ExplainAccess'

/** 3.6.10: textul ultimei autentificări (lung în detalii, scurt în rând); '' = nu e de arătat */
function useLastSignIn() {
  const { t } = useI18n()
  const method = (m: string | null) => t('settings.users.loginMethod.' + (m || 'unknown'))
  return (u: UserRow, short = false): string => {
    const s = lastSignIn(u)
    if (s.state === 'hidden') return ''
    if (s.state === 'at') {
      return short ? t('settings.users.lastSignIn.short', { date: fmtTs(s.at, 'date') })
        : t('settings.users.lastSignIn.at', { date: fmtTs(s.at, 'datetime'), method: method(s.method) })
    }
    if (s.state === 'untracked') return short ? '' : t('settings.users.lastSignIn.untracked', { date: fmtTs(s.since, 'date') })
    return short ? t('settings.users.lastSignIn.shortNever') : t('settings.users.lastSignIn.never')
  }
}

/** 3.6.10: confirmarea blocantă „shell pe un host crown-jewel" (serverul o cere cu 409) */
function useCrownAsk() {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  return (e: Parameters<typeof crownDialog>[0]) => confirm(crownDialog(e, t))
}

/* Sub-tab-ul „Accounts" (3.6.6). Înainte: o listă cu TOATE conturile, fiecare cu toate legăturile şi
   butoanele inline, plus două formulare mereu deschise dedesubt — la 100+ conturi, o pagină fără
   capăt. Acum: căutare + filtre (logica pură în lib/usersAdmin.ts), rânduri compacte care se
   desfac (acolo stau legăturile şi acţiunile), „Add account" deschide formularul la cerere.

   Acţiunile sunt EXACT cele de dinainte: aceleaşi rute, aceeaşi parolă (askSecret, mascată) + al
   doilea factor (withSecondFactor), aceleaşi condiţii de afişare (nu-ţi atingi singur accesul, doar
   un Owner atinge legăturile Owner, ultimul cont nu se şterge). Serverul le re-verifică pe toate. */

const PAGE = 50

/** eticheta unei legături, ca peste tot: „Operator · folder prod" */
function useChip(hosts: Host[]) {
  const { t } = useI18n()
  const hostName = (id: number) => hosts.find((h) => h.id === id)?.name
  return { hostName, chip: (b: Binding) => t('roles.chip', { role: roleLabel(b, t), scope: scopeLabel(b, hostName, t) }) }
}

function SignInBadge(props: { u: UserRow }) {
  const { t } = useI18n()
  const s = signInOf(props.u)
  if (s === 'both') return <Badge tone="warn" title={t('roles.localPw.badgeHint')}>{t('settings.users.signIn.both')}</Badge>
  return <Badge>{t('settings.users.signIn.' + s)}</Badge>
}

function AddAccountForm(props: {
  id: string; catalogue: RolesCatalogue | null; hosts: Host[]; isOwner: boolean
  onDone: (users: UserRow[]) => void; onCancel: () => void; fail: (e: unknown) => void
}) {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)
  const [newUser, setNewUser] = useState({ email: '', password: '', current_password: '',
    role: '', scope_kind: 'folder' as ScopeKind, scope_value: '' })
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const crownAsk = useCrownAsk()

  async function addUser(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    try {
      const { role, ...rest } = newUser
      const body = { ...rest, ...(role ? roleBody(role) : {}), scope_value: role ? newUser.scope_value.trim() : '' }
      const users = await withCrownConfirm((crown) => withSecondFactor((extra) => api<UserRow[]>('/api/users',
        { method: 'POST', body: JSON.stringify({ ...body, ...crown, ...extra }) })), crownAsk)
      if (!users) { setBusy(false); return }
      setNewUser({ email: '', password: '', current_password: '', role: '', scope_kind: 'folder', scope_value: '' })
      props.onDone(users)
    } catch (x) { props.fail(x) }
    setBusy(false)
  }

  return (
    // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape în formular îl închide (şi nu închide tot modalul)
    <form id={props.id} onSubmit={addUser} data-add-user-form aria-label={t('settings.users.add')}
      onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); props.onCancel() } }}
      className="mt-3 flex flex-col gap-2 rounded-xl bg-ink-800/60 p-3 ring-1 ring-ink-700">
      <div className="text-sm font-semibold text-slate-200">{t('settings.users.add')}</div>
      <p className="text-xs text-slate-400">{t('settings.users.addHint')}</p>
      <div className="flex flex-col gap-2 sm:flex-row">
        <input type="email" value={newUser.email} autoComplete="off" autoFocus
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
        <RoleOptions catalogue={props.catalogue} isOwner={props.isOwner} />
      </select>
      {newUser.role && (
        <ScopePicker idPrefix="newuser" kind={newUser.scope_kind} value={newUser.scope_value} hosts={props.hosts}
          onChange={(k, v) => setNewUser({ ...newUser, scope_kind: k, scope_value: v })} />
      )}
      <input type="password" value={newUser.current_password} autoComplete="current-password"
        onChange={(e) => setNewUser({ ...newUser, current_password: e.target.value })}
        placeholder={t('settings.currentPasswordConfirm')} aria-label={t('settings.currentPassword')} className={field} />
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" type="submit" loading={busy}
          disabled={!newUser.current_password || (!!newUser.role && !scopeOk(newUser.scope_kind, newUser.scope_value))}>
          {t('settings.users.add')}
        </Button>
        <Button type="button" onClick={props.onCancel}>{t('roles.custom.cancel')}</Button>
      </div>
    </form>
  )
}

/** Partea desfăcută a unui rând: detalii, legăturile (cu ×), „dă un rol", ştergerea contului. */
function AccountDetails(props: {
  u: UserRow; id: string; labelledBy: string; canDelete: boolean
  catalogue: RolesCatalogue | null; hosts: Host[]; isOwner: boolean
  reload: () => Promise<void>; setUsers: (u: UserRow[]) => void
  done: (text: string) => void; fail: (e: unknown) => void
}) {
  const { t } = useI18n()
  const { u } = props
  const { hostName, chip } = useChip(props.hosts)
  const roleName = useRoleName(props.catalogue)
  const [busy, setBusy] = useState(false)
  const [grant, setGrant] = useState({ role: 'viewer', scope_kind: 'folder' as ScopeKind, scope_value: '',
    expiry: 'permanent' as ExpiryChoice, custom: '' })
  const [explain, setExplain] = useState(false)
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const crownAsk = useCrownAsk()
  const expiryText = useExpiryText()
  const signIn = useLastSignIn()
  const sourceTitle = (b: Binding) => (b.source === 'migration' ? t('roles.sourceMigration')
    : b.source === 'sso' ? t('roles.sourceSso') : undefined)
  const expires = expiryFrom(grant.expiry, grant.custom, Date.now())

  async function addBinding(e: FormEvent) {
    e.preventDefault()
    const until = expiryFrom(grant.expiry, grant.custom, Date.now())
    if (until === 'invalid') { props.fail(new Error(t('roles.expiry.invalid'))); return }
    const label = t('roles.chip', { role: roleName(grant.role),
      scope: scopeLabel({ scope_kind: grant.scope_kind, scope_value: grant.scope_value.trim() }, hostName, t) })
    const pw = await askSecret(until
      ? t('roles.bindings.addConfirmUntil', { email: u.email, binding: label, date: fmtTs(until, 'datetime') })
      : t('roles.bindings.addConfirm', { email: u.email, binding: label }))
    if (!pw) return
    setBusy(true)
    try {
      const r = await withCrownConfirm((crown) => withSecondFactor((extra) => api(`/api/users/${u.id}/bindings`, {
        method: 'POST',
        body: JSON.stringify({ ...roleBody(grant.role), scope_kind: grant.scope_kind,
          scope_value: grant.scope_kind === 'all' ? '' : grant.scope_value.trim(), expires: until,
          current_password: pw, ...crown, ...extra }),
      })), crownAsk)
      if (r !== null) {
        await props.reload()
        props.done(t('roles.bindings.added'))
      }
    } catch (x) { props.fail(x) }
    setBusy(false)
  }

  // 3.6.10: o legătură temporară devine permanentă (serverul aplică regulile de acordare)
  async function makePermanent(b: Binding) {
    const pw = await askSecret(t('roles.expiry.permanentConfirm', { email: u.email, binding: chip(b) }))
    if (!pw) return
    try {
      await withSecondFactor((extra) => api(`/api/users/${u.id}/bindings/${b.id}/expiry`,
        { method: 'POST', body: JSON.stringify({ expires: null, current_password: pw, ...extra }) }))
      await props.reload()
      props.done(t('roles.expiry.madePermanent'))
    } catch (x) { props.fail(x) }
  }

  async function removeBinding(b: Binding) {
    const pw = await askSecret(t('roles.bindings.removeConfirm', { email: u.email, binding: chip(b) }))
    if (!pw) return
    try {
      await withSecondFactor((extra) => api(`/api/users/${u.id}/bindings/${b.id}/delete`,
        { method: 'POST', body: JSON.stringify({ current_password: pw, ...extra }) }))
      await props.reload()
      props.done(t('roles.bindings.removed'))
    } catch (x) { props.fail(x) }
  }

  async function removeUser() {
    // askSecret, nu window.prompt: aici se tastează parola TA — mascată, ca peste tot
    const pw = await askSecret(t('settings.users.deleteConfirm', { email: u.email }))
    if (!pw) return
    try {
      props.setUsers(await withSecondFactor((extra) => api<UserRow[]>(`/api/users/${u.id}/delete`,
        { method: 'POST', body: JSON.stringify({ current_password: pw, ...extra }) })))
      props.done(t('settings.users.deleted'))
    } catch (x) { props.fail(x) }
  }

  const bindings = u.bindings ?? []
  return (
    <div id={props.id} role="region" aria-labelledby={props.labelledBy}
      className="flex flex-col gap-3 border-t border-ink-700 px-3 py-3" data-account-details>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
        <dt className="text-slate-500">{t('settings.users.col.signIn')}</dt>
        <dd className="text-slate-300">{t('settings.users.signInLong.' + signInOf(u))}</dd>
        <dt className="text-slate-500">{t('settings.users.col.created')}</dt>
        <dd className="text-slate-300">{fmtTs(u.created, 'date')}</dd>
        {signIn(u) && (
          <>
            <dt className="text-slate-500">{t('settings.users.col.lastSignIn')}</dt>
            <dd className="text-slate-300" data-last-signin>{signIn(u)}</dd>
          </>
        )}
        <dt className="text-slate-500">{t('settings.users.col.security')}</dt>
        <dd className="text-slate-300">
          {u.totp ? t('settings.users.totpOn') : t('settings.users.totpOff')}
          {' · '}{t('settings.users.passkeys', { n: u.passkeys })}
        </dd>
      </dl>
      {u.sso && u.local_password && (
        <p className="rounded-md bg-warn/10 px-2 py-1.5 text-xs text-warn">{t('roles.localPw.badgeHint')}</p>
      )}

      <div>
        <div className="text-xs font-semibold text-slate-400">{t('settings.users.rolesHeading')}</div>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5" data-account-bindings>
          {bindings.length === 0 && <Badge tone="warn" size="md">{t('roles.noRole')}</Badge>}
          {bindings.map((b) => (
            <span key={b.id} className="inline-flex items-center gap-1">
              <Badge tone={b.role === 'owner' ? 'accent' : 'neutral'} size="md" title={sourceTitle(b)}>
                {chip(b)}
                {b.expires ? <span className="text-warn" data-binding-expiry>{' · ' + expiryText(b.expires)}</span> : null}
                {!u.is_self && (props.isOwner || b.role !== 'owner') && (
                  <IconButton label={t('roles.bindings.remove', { binding: chip(b) })} touch={false}
                    onClick={() => removeBinding(b)}>
                    <CloseIcon size={10} />
                  </IconButton>
                )}
              </Badge>
              {b.expires && b.source !== 'sso' && !u.is_self && (props.isOwner || b.role !== 'owner') && (
                <Button type="button" size="sm" variant="ghost" onClick={() => makePermanent(b)}
                  aria-label={t('roles.expiry.makePermanentAria', { binding: chip(b) })}>
                  {t('roles.expiry.makePermanent')}
                </Button>
              )}
            </span>
          ))}
        </div>
      </div>

      <div>
        <Button type="button" size="sm" variant="secondary" aria-expanded={explain} data-explain-open
          onClick={() => setExplain((v) => !v)}>
          {t('explain.button')}
        </Button>
        {explain && (
          <div className="mt-2">
            <ExplainAccess userId={u.id} email={u.email} self={u.is_self} hosts={props.hosts} />
          </div>
        )}
      </div>

      {u.is_self ? (
        <p className="text-xs text-slate-400">{t('settings.users.selfNote')}</p>
      ) : (
        <form onSubmit={addBinding} className="flex flex-col gap-2" data-grant-form aria-label={t('roles.bindings.addFor', { email: u.email })}>
          <div className="text-xs font-semibold text-slate-400">{t('roles.bindings.addFor', { email: u.email })}</div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <select value={grant.role} aria-label={t('roles.role.label')} className={field + ' sm:w-48'}
              onChange={(e) => setGrant({ ...grant, role: e.target.value, scope_kind: defaultScope(e.target.value), scope_value: '' })}>
              <RoleOptions catalogue={props.catalogue} isOwner={props.isOwner} />
            </select>
            <div className="min-w-0 flex-1">
              <ScopePicker idPrefix={`grant-${u.id}`} kind={grant.scope_kind} value={grant.scope_value} hosts={props.hosts}
                onChange={(k, v) => setGrant({ ...grant, scope_kind: k, scope_value: v })} />
            </div>
          </div>
          <ExpiryPicker idPrefix={`grant-${u.id}`} choice={grant.expiry} custom={grant.custom}
            onChange={(expiry, custom) => setGrant({ ...grant, expiry, custom })} />
          {grant.expiry !== 'permanent' && <p className="text-xs text-slate-500">{t('roles.expiry.hint')}</p>}
          {shellOf(props.catalogue, grant.role) && <p className="text-xs text-slate-500">{t('roles.shellHint')}</p>}
          <div>
            <Button type="submit" variant="primary" size="sm" loading={busy}
              disabled={!scopeOk(grant.scope_kind, grant.scope_value) || expires === 'invalid'}>
              {t('roles.bindings.addButton')}
            </Button>
          </div>
        </form>
      )}

      {props.canDelete && (
        <div className="flex justify-end border-t border-ink-700 pt-3">
          <Button type="button" size="sm" variant="danger" onClick={removeUser}
            aria-label={t('settings.users.deleteAria', { email: u.email })}>
            {t('settings.users.delete')}
          </Button>
        </div>
      )}
    </div>
  )
}

export default function AccountsPanel(props: {
  users: UserRow[]; catalogue: RolesCatalogue | null; hosts: Host[]; isOwner: boolean
  reload: () => Promise<void>; setUsers: (u: UserRow[]) => void
  done: (text: string) => void; fail: (e: unknown) => void
}) {
  const { t } = useI18n()
  const { chip } = useChip(props.hosts)
  const signIn = useLastSignIn()
  const [filter, setFilter] = useState<AccountFilter>(EMPTY_FILTER)
  const [limit, setLimit] = useState(PAGE)
  const [openId, setOpenId] = useState<number | null>(null)
  const [adding, setAdding] = useState(false)
  const addBtnRef = useRef<HTMLButtonElement>(null)
  const uid = useId()
  const formId = `${uid}-add`

  const shown = useMemo(() => filterAccounts(props.users, filter), [props.users, filter])
  const noRoleCount = useMemo(() => props.users.filter(hasNoRole).length, [props.users])
  const active = filterActive(filter)
  // un filtru nou porneşte de la prima pagină
  useEffect(() => { setLimit(PAGE) }, [filter])
  const set = (patch: Partial<AccountFilter>) => setFilter((f) => ({ ...f, ...patch }))

  const closeAdd = () => {
    setAdding(false)
    requestAnimationFrame(() => addBtnRef.current?.focus())
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <p className="min-w-0 flex-1 text-xs text-slate-500">{t('settings.users.hint')}</p>
        <Button ref={addBtnRef} type="button" size="sm" variant={adding ? 'secondary' : 'primary'}
          aria-expanded={adding} aria-controls={adding ? formId : undefined} data-add-user
          onClick={() => (adding ? closeAdd() : setAdding(true))}>
          {t('settings.users.add')}
        </Button>
      </div>

      {adding && (
        <AddAccountForm id={formId} catalogue={props.catalogue} hosts={props.hosts} isOwner={props.isOwner}
          fail={props.fail} onCancel={closeAdd}
          onDone={(users) => { props.setUsers(users); props.done(t('settings.users.added')); closeAdd() }} />
      )}

      {noRoleCount > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md bg-warn/10 px-3 py-2 text-xs text-warn" data-no-role-banner>
          <WarningIcon size={14} />
          <span className="min-w-0 flex-1">{t('settings.users.noRoleBanner', { count: noRoleCount })}</span>
          {!filter.noRole && (
            <Button type="button" size="sm" onClick={() => set({ noRole: true, role: '' })}>
              {t('settings.users.noRoleShow')}
            </Button>
          )}
        </div>
      )}

      {/* căutare + filtre: pe telefon câmpul pe un rând, filtrele două câte două dedesubt */}
      <div role="group" aria-label={t('settings.users.searchLabel')} className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-[minmax(0,1fr)_auto_auto]">
        <div className="relative col-span-2 sm:col-span-1">
          <span aria-hidden="true" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500">
            <SearchIcon size={14} />
          </span>
          <input type="search" value={filter.query} onChange={(e) => set({ query: e.target.value })}
            autoComplete="off" spellCheck={false} data-account-search
            aria-label={t('settings.users.search')} placeholder={t('settings.users.search')} className={field + ' pl-8'} />
        </div>
        <select value={filter.role} onChange={(e) => set({ role: e.target.value, noRole: false })}
          aria-label={t('settings.users.filterRole')} className={field + ' sm:w-40'}>
          <option value="">{t('settings.users.anyRole')}</option>
          {ROLE_KEYS.map((k) => <option key={k} value={k}>{t('roles.role.' + k)}</option>)}
          {(props.catalogue?.custom ?? []).map((r) => <option key={r.id} value={roleValue(r)}>{r.name}</option>)}
        </select>
        <select value={filter.signIn} onChange={(e) => set({ signIn: e.target.value as AccountFilter['signIn'] })}
          aria-label={t('settings.users.filterSignIn')} className={field + ' sm:w-44'}>
          <option value="">{t('settings.users.anySignIn')}</option>
          <option value="local">{t('settings.users.filterLocal')}</option>
          <option value="sso">{t('settings.users.filterSso')}</option>
        </select>
        <div className="col-span-2 flex flex-wrap items-center gap-2 sm:col-span-3">
          <label className="flex min-h-7 items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={filter.noRole} data-filter-norole
              onChange={(e) => set({ noRole: e.target.checked, role: e.target.checked ? '' : filter.role })}
              className="h-4 w-4 shrink-0 rounded-md accent-sky-600 [@media(pointer:coarse)]:h-6 [@media(pointer:coarse)]:w-6" />
            {t('settings.users.filterNoRole')}
          </label>
          {active && (
            <Button type="button" size="sm" variant="ghost" className="ml-auto" onClick={() => setFilter(EMPTY_FILTER)}>
              {t('settings.users.clearFilters')}
            </Button>
          )}
        </div>
      </div>

      <p role="status" className="mt-2 text-xs text-slate-500" data-accounts-count>
        {active
          ? t('settings.users.showing', { shown: shown.length, total: props.users.length })
          : t('settings.users.total', { count: props.users.length })}
      </p>

      {shown.length === 0 ? (
        <p className="mt-2 rounded-md px-3 py-3 text-sm text-slate-400 ring-1 ring-ink-700">{t('settings.users.noMatch')}</p>
      ) : (
        <ul className="mt-2 flex flex-col gap-1" data-users-list>
          {shown.slice(0, limit).map((u) => {
            const open = openId === u.id
            const bindings = u.bindings ?? []
            const headId = `${uid}-acc-${u.id}`
            const detailsId = `${uid}-acc-${u.id}-details`
            return (
              <li key={u.id} data-account={u.email}
                className={`rounded-md bg-ink-800/60 text-sm ring-1 ${hasNoRole(u) ? 'ring-warn/40' : 'ring-ink-700'}`}>
                <button type="button" id={headId} aria-expanded={open} aria-controls={detailsId}
                  onClick={() => setOpenId(open ? null : u.id)}
                  className="wt-touch flex w-full min-w-0 items-center gap-2 rounded-md px-3 py-2 text-left hover:bg-ink-800">
                  <span className="text-slate-400"><ChevronIcon open={open} size={12} /></span>
                  <span className="flex min-w-0 flex-1 flex-col gap-1 sm:flex-row sm:items-center sm:gap-2">
                    <span className="flex min-w-0 items-center gap-2 sm:w-64 sm:shrink-0">
                      <span className="min-w-0 truncate text-slate-200">{u.email}</span>
                      {u.is_self && <Badge tone="accent">{t('settings.users.you')}</Badge>}
                    </span>
                    <span className="flex min-w-0 flex-1 flex-wrap items-center gap-1">
                      <SignInBadge u={u} />
                      {bindings.length === 0
                        ? <Badge tone="warn"><WarningIcon size={10} />{t('roles.noRole')}</Badge>
                        : bindings.slice(0, 2).map((b) => (
                          <Badge key={b.id} tone={b.role === 'owner' ? 'accent' : 'neutral'}>{chip(b)}</Badge>
                        ))}
                      {bindings.length > 2 && <Badge>{t('settings.users.moreRoles', { n: bindings.length - 2 })}</Badge>}
                    </span>
                  </span>
                  <span className="hidden shrink-0 text-2xs text-slate-500 md:inline" data-last-signin-short>
                    {signIn(u, true) || fmtTs(u.created, 'date')}
                  </span>
                </button>
                {open && (
                  <AccountDetails u={u} id={detailsId} labelledBy={headId}
                    canDelete={!u.is_self && props.users.length > 1}
                    catalogue={props.catalogue} hosts={props.hosts} isOwner={props.isOwner}
                    reload={props.reload} setUsers={props.setUsers} done={props.done} fail={props.fail} />
                )}
              </li>
            )
          })}
        </ul>
      )}
      {shown.length > limit && (
        <div className="mt-2">
          <Button type="button" size="sm" onClick={() => setLimit((n) => n + PAGE)} data-accounts-more>
            {t('settings.users.showMore', { n: Math.min(PAGE, shown.length - limit), left: shown.length - limit })}
          </Button>
        </div>
      )}
    </>
  )
}
