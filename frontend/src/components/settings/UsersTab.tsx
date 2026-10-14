import { useEffect, useId, useState } from 'react'
import { api, ApiError, errText, Host, withSecondFactor as withSecondFactorT } from '../../lib/api'
import { useConfirm } from '../../lib/confirm'
import { ssoStepupRedirect } from '../../lib/stepup'
import { useI18n } from '../../lib/i18n'
import { Binding, loadPerms, ROLE_KEYS, roleLabel, RolesCatalogue, scopeLabel, SHELL_ROLES, usePerms, can } from '../../lib/perms'
import { effectiveSubTab, hasNoRole, loadSubTab, saveSubTab, subTabOfSection, visibleSubTabs,
  type SsoMapping, type UserRow, type UsersSubTab } from '../../lib/usersAdmin'
import { heading } from './ui'
import { Badge, Button, ErrorState } from '../ui'
import HelpTip from '../HelpTip'
import { type LoadState } from '../../lib/loadable'
import NotLoaded from './NotLoaded'
import SubTabs from './users/SubTabs'
import AccountsPanel from './users/AccountsPanel'
import RolesPanel from './users/RolesPanel'
import SsoPanel from './users/SsoPanel'
import ScimPanel from './users/ScimPanel'
import { ActionStatus } from './users/shared'
import ExplainAccess from './users/ExplainAccess'

/* Settings → Users & roles (3.6). Conturile şi LEGĂTURILE lor de rol (rol @ scope — docs/ROLES.md),
   rolurile custom (3.6.2) şi maparea grupurilor SSO (3.6.2). Fără `users.manage` vezi doar propriul
   acces, read-only; serverul aplică oricum regulile (anti-escaladare, doar Owner atinge Owner-ii,
   ultimul Owner, nu-ţi schimbi singur accesul) — UI-ul doar le face vizibile.

   3.6.6: pagina nu mai e un scroll fără capăt. „Your access" rămâne un rezumat compact DEASUPRA
   sub-tab-urilor — e singura parte pe care o vede orice cont, iar un admin are nevoie de propriul
   scope tocmai când acordă altora; ca tab separat ar fi ascuns exact contextul ăsta, iar un cont
   fără drepturi de administrare ar fi văzut un tablist cu un singur tab. Dedesubt: Accounts | Roles
   | SSO groups (users/*.tsx), cu aceleaşi condiţii de vizibilitate ca secţiunile de dinainte.

   Contractul cu căutarea din Setări (lib/settingsIndex): fiecare panou poartă `data-setting-id`-ul
   secţiunii lui AICI, iar `jump` (de la SettingsModal) comută sub-tab-ul înainte ca modalul să
   caute secţiunea vizibilă. */

type SsoState = { enabled: boolean; mappings: SsoMapping[]; local_password_accounts?: number }
type Where = 'self' | UsersSubTab

export default function UsersTab(props: { jump?: { id: string; n: number } | null }) {
  const { t } = useI18n()
  const perms = usePerms()
  const manage = can(perms, 'users.manage')
  const rolesManage = can(perms, 'roles.manage')
  const isOwner = perms ? perms.owner : true
  const [users, setUsers] = useState<UserRow[]>([])
  const [hosts, setHosts] = useState<Host[]>([])
  const [catalogue, setCatalogue] = useState<RolesCatalogue | null>(null)
  const [sso, setSso] = useState<SsoState | null>(null)
  const { confirm } = useConfirm()
  // unde apare mesajul: în panoul care l-a produs (altfel un „Rol salvat" ar apărea în alt sub-tab)
  const [note, setNote] = useState<{ at: Where; msg: string; err: string }>({ at: 'self', msg: '', err: '' })
  const [loadErr, setLoadErr] = useState('')

  // U04: o listă de utilizatori goală pe un fetch picat ascundea conturile (şi rolurile) existente
  const [usersState, setUsersState] = useState<LoadState>({ status: 'loading' })
  const loadUsers = () => api<UserRow[]>('/api/users')
    .then((r) => { setUsers(r); setUsersState({ status: 'ok' }) })
    .catch((e) => setUsersState({ status: 'error', error: errText(e, t) }))
  const loadCatalogue = () => api<RolesCatalogue>('/api/roles').then(setCatalogue)
    .catch((e) => setLoadErr(t('common.loadFailed') + ' ' + errText(e, t)))
  // eroare ≠ gol (audit 3.6.3): un fetch picat ascundea toată secţiunea, ca şi cum SSO n-ar exista
  const [ssoErr, setSsoErr] = useState('')
  const loadSso = () => api<SsoState>('/api/settings/oidc-roles').then((r) => { setSso(r); setSsoErr('') })
    .catch((e) => { setSso(null); setSsoErr(errText(e, t) || t('common.loadFailed')) })
  useEffect(() => {
    loadUsers()
    api<Host[]>('/api/hosts').then(setHosts).catch((e) => setLoadErr(t('common.loadFailed') + ' ' + errText(e, t)))
  }, [])   // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (manage || rolesManage) void loadCatalogue() }, [manage, rolesManage])   // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (manage) void loadSso() }, [manage])   // eslint-disable-line react-hooks/exhaustive-deps

  // ── sub-tab-uri ──
  const tabs = visibleSubTabs({ manage, rolesManage, ssoEnabled: !!sso?.enabled, ssoFailed: !!ssoErr })
  const [wanted, setWanted] = useState<UsersSubTab | null>(() => subTabOfSection(props.jump?.id) ?? loadSubTab())
  const tab = effectiveSubTab(wanted, tabs)
  const choose = (x: UsersSubTab) => { setWanted(x); saveSubTab(x) }
  // link adânc / rezultat de căutare: comută sub-tab-ul secţiunii (SettingsModal aşteaptă apoi ca
  // ea să devină vizibilă). Nu se salvează ca preferinţă: e o vizită, nu o alegere.
  useEffect(() => {
    const x = subTabOfSection(props.jump?.id)
    if (x) setWanted(x)
  }, [props.jump])
  const idPrefix = useId()
  const withTabs = tabs.length > 1

  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const hostName = (id: number) => hosts.find((h) => h.id === id)?.name
  const chip = (b: Binding) => t('roles.chip', { role: roleLabel(b, t), scope: scopeLabel(b, hostName, t) })
  const doneAt = (at: Where) => (text: string) => { setNote({ at, msg: text, err: '' }); loadPerms() }
  const failAt = (at: Where) => (e: unknown) => { setNote({ at, msg: '', err: errText(e, t) || String(e) }) }
  const status = (at: Where) => <ActionStatus msg={note.at === at ? note.msg : ''} err={note.at === at ? note.err : ''} />
  const reloadAccounts = async () => { await Promise.all([loadUsers(), catalogue ? loadCatalogue() : Promise.resolve()]) }
  const reloadRoles = async () => { await Promise.all([loadCatalogue(), manage ? loadUsers() : Promise.resolve()]) }
  const reloadSso = async () => { await Promise.all([loadSso(), loadCatalogue(), loadUsers()]) }

  // 3.6.2 (revizuirea de securitate): un cont SSO cu parolă locală nu primeşte roluri din
  // grupuri. Omul îşi scoate singur parola (cu re-auth SSO); scoaterea revocă şi passkey-urile.
  async function removeLocalPassword() {
    if (!(await confirm({ title: t('roles.localPw.confirmTitle'), message: t('roles.localPw.confirmBody'),
      confirmLabel: t('roles.localPw.remove'), danger: true }))) return
    try {
      await withSecondFactor((extra) => api('/api/account',
        { method: 'POST', body: JSON.stringify({ remove_password: true, ...extra }) }))
      await loadUsers()
      doneAt('self')(t('roles.localPw.removed'))
    } catch (x) {
      if (x instanceof ApiError && x.code === 'account.ssoReauth') { ssoStepupRedirect(0); return }
      failAt('self')(x)
    }
  }

  const self = users.find((u) => u.is_self)
  const mine = perms?.bindings ?? self?.bindings ?? []
  const sourceTitle = (b: Binding) => (b.source === 'migration' ? t('roles.sourceMigration')
    : b.source === 'sso' ? t('roles.sourceSso') : undefined)
  const usersOk = usersState.status === 'ok'
  const noRole = usersOk ? users.filter(hasNoRole).length : 0
  const labels: Record<UsersSubTab, string> = {
    accounts: t('settings.users.tabAccounts'), roles: t('settings.users.tabRoles'), sso: t('settings.users.tabSso'),
  }
  const counts: Record<UsersSubTab, number | undefined> = {
    accounts: usersOk ? users.length : undefined,
    roles: catalogue ? catalogue.roles.length + catalogue.custom.length : undefined,
    sso: sso ? sso.mappings.length : undefined,
  }
  // atributele unui panou: tabpanel doar când există tablist (altfel aria-labelledby ar arăta în gol)
  const panel = (x: UsersSubTab) => ({
    hidden: tab !== x,
    ...(withTabs ? { role: 'tabpanel', id: `${idPrefix}-panel-${x}`, 'aria-labelledby': `${idPrefix}-tab-${x}` } : {}),
    className: withTabs ? 'pt-4' : 'pt-2',
  })

  return (
    <div>
      <section data-setting-id="myAccess" className="rounded-xl bg-ink-800/40 px-3 py-3 ring-1 ring-ink-700">
        <h3 className={heading + ' !mt-0 flex items-center gap-2'}>{t('roles.myAccess')}<HelpTip id="roles" /></h3>
        <div className="mt-2 flex flex-wrap items-center gap-1.5" data-my-access>
          {mine.length === 0
            ? <span className="text-sm text-slate-400">{t('roles.myNone')}</span>
            : mine.map((b) => (
              <Badge key={b.id} tone={b.role === 'owner' ? 'accent' : 'neutral'} size="md"
                title={sourceTitle(b)}>{chip(b)}</Badge>
            ))}
        </div>
        <p className="mt-2 text-xs text-slate-500">{t('roles.myAccessHint')}</p>
        {/* 3.6.10: „de ce pot / nu pot…" pe un host anume — aceeaşi explicaţie ca pentru un admin */}
        {self && hosts.length > 0 && (
          <details className="mt-2" data-explain-self>
            <summary className="cursor-pointer text-xs wt-link">{t('explain.titleSelf')}</summary>
            <div className="mt-2">
              <ExplainAccess userId={self.id} email={self.email} self hosts={hosts} />
            </div>
          </details>
        )}
        {self?.sso && self.local_password && (
          <div className="mt-3 flex flex-col items-start gap-2 rounded-md bg-warn/10 px-3 py-2" data-localpw-self>
            <p className="text-xs text-warn">{t('roles.localPw.mine')}</p>
            <Button type="button" size="sm" variant="danger" onClick={removeLocalPassword}>{t('roles.localPw.remove')}</Button>
          </div>
        )}
        {status('self')}
        {/* fără sub-tab-ul Roles (cont fără drepturi de administrare), ce înseamnă fiecare rol stă aici */}
        {!tabs.includes('roles') && (
          <ul className="mt-3 flex flex-col gap-1 text-xs text-slate-400" data-role-glossary>
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
        )}
      </section>

      {loadErr && <p role="alert" className="mt-3 text-sm wt-danger">{loadErr}</p>}

      {tab && (
        <div className="mt-5">
          {withTabs && (
            <SubTabs idPrefix={idPrefix} label={t('settings.users.tabsLabel')} active={tab} onChange={choose}
              tabs={tabs.map((x) => ({ id: x, label: labels[x], count: counts[x],
                ...(x === 'accounts' && noRole > 0 ? { warn: noRole, warnLabel: t('settings.users.noRoleBanner', { count: noRole }) } : {}) }))} />
          )}

          <div {...panel('accounts')} data-setting-id="users">
            {!withTabs && <h3 className={heading + ' !mt-0'}>{t('settings.users.title')}</h3>}
            {tabs.includes('accounts') && (
              <>
                <NotLoaded state={usersState} onRetry={() => { setUsersState({ status: 'loading' }); void loadUsers() }} />
                {usersOk && (
                  <AccountsPanel users={users} catalogue={catalogue} hosts={hosts} isOwner={isOwner}
                    reload={reloadAccounts} setUsers={setUsers} done={doneAt('accounts')} fail={failAt('accounts')} />
                )}
                {status('accounts')}
              </>
            )}
          </div>

          <div {...panel('roles')} data-setting-id="roles">
            {tabs.includes('roles') && (
              <>
                <RolesPanel catalogue={catalogue} canEdit={rolesManage}
                  users={manage && usersOk ? users : null} mappings={manage ? sso?.mappings ?? [] : null}
                  reload={reloadRoles} done={doneAt('roles')} fail={failAt('roles')} />
                {status('roles')}
              </>
            )}
          </div>

          <div {...panel('sso')} data-setting-id="ssoMapping">
            {tabs.includes('sso') && (
              <>
                {ssoErr && (
                  <>
                    <h3 className={heading + ' !mt-0'}>{t('roles.sso.title')}</h3>
                    <ErrorState compact title={t('roles.sso.loadFailed')} message={ssoErr} onRetry={() => { void loadSso() }} />
                  </>
                )}
                {sso?.enabled && (
                  <SsoPanel catalogue={catalogue} hosts={hosts} isOwner={isOwner} mappings={sso.mappings}
                    localPwAccounts={sso.local_password_accounts ?? 0}
                    reload={reloadSso} done={doneAt('sso')} fail={failAt('sso')} />
                )}
                {/* 3.6.11: SCIM — starea pentru users.manage, acţiunile doar pentru un Owner */}
                {sso?.enabled && <ScimPanel isOwner={isOwner} done={(x) => { doneAt('sso')(x); void loadUsers() }} fail={failAt('sso')} />}
                {status('sso')}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
