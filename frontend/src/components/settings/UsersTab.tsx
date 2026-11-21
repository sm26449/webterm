import { useEffect, useId, useState } from 'react'
import { api, errText, Host } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { loadPerms, RolesCatalogue, usePerms, can } from '../../lib/perms'
import { effectiveSubTab, hasNoRole, loadSubTab, saveSubTab, subTabOfSection, visibleSubTabs,
  type SsoMapping, type UserRow, type UsersSubTab } from '../../lib/usersAdmin'
import { ErrorState, SettingsSection } from '../ui'
import HelpTip from '../HelpTip'
import { type LoadState } from '../../lib/loadable'
import NotLoaded from './NotLoaded'
import SubTabs from './users/SubTabs'
import AccountsPanel from './users/AccountsPanel'
import RolesPanel from './users/RolesPanel'
import SsoPanel from './users/SsoPanel'
import ScimPanel from './users/ScimPanel'
import { ActionStatus, selfOf } from './users/shared'

/* Settings → People & roles (3.6; „Users & roles" până în 3.7.1). Conturile şi LEGĂTURILE lor de
   rol (rol @ scope — docs/ROLES.md), rolurile custom (3.6.2) şi maparea grupurilor SSO (3.6.2).
   Serverul aplică oricum regulile (anti-escaladare, doar Owner atinge Owner-ii, ultimul Owner, nu-ţi
   schimbi singur accesul) — UI-ul doar le face vizibile.

   3.6.6: Accounts | Roles | SSO groups (users/*.tsx) pe sub-tab-uri. 3.7.1 (auditul UX Setări M1):
   „Your access" s-a mutat în Account & security (MyAccessTab.tsx) — un cont fără drepturi de
   administrare nu mai primeşte un tab întreg pentru un singur card; tab-ul ăsta apare doar cu
   `users.manage` / `roles.manage`.

   Contractul cu căutarea din Setări (lib/settingsIndex): fiecare panou poartă `data-setting-id`-ul
   secţiunii lui AICI, iar `jump` (de la SettingsModal) comută sub-tab-ul înainte ca modalul să
   caute secţiunea vizibilă. */

type SsoState = { enabled: boolean; mappings: SsoMapping[]; local_password_accounts?: number }
type Where = UsersSubTab

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
  // unde apare mesajul: în panoul care l-a produs (altfel un „Rol salvat" ar apărea în alt sub-tab)
  const [note, setNote] = useState<{ at: Where | null; msg: string; err: string }>({ at: null, msg: '', err: '' })
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
    void loadUsers()
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

  const doneAt = (at: Where) => (text: string) => { setNote({ at, msg: text, err: '' }); void loadPerms() }
  const failAt = (at: Where) => (e: unknown) => { setNote({ at, msg: '', err: errText(e, t) || String(e) }) }
  const status = (at: Where) => <ActionStatus msg={note.at === at ? note.msg : ''} err={note.at === at ? note.err : ''} />
  const reloadAccounts = async () => { await Promise.all([loadUsers(), catalogue ? loadCatalogue() : Promise.resolve()]) }
  const reloadRoles = async () => { await Promise.all([loadCatalogue(), manage ? loadUsers() : Promise.resolve()]) }
  const reloadSso = async () => { await Promise.all([loadSso(), loadCatalogue(), loadUsers()]) }

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
      {loadErr && <p role="alert" className="mt-3 text-sm wt-danger">{loadErr}</p>}

      {tab && (
        <div>
          {withTabs && (
            <SubTabs idPrefix={idPrefix} label={t('settings.users.tabsLabel')} active={tab} onChange={choose}
              tabs={tabs.map((x) => ({ id: x, label: labels[x], count: counts[x],
                ...(x === 'accounts' && noRole > 0 ? { warn: noRole, warnLabel: t('settings.users.noRoleBanner', { count: noRole }) } : {}) }))} />
          )}

          <div {...panel('accounts')} data-setting-id="users">
            {tabs.includes('accounts') && (
              // 3.7.1: secţiune-card, ca restul Setărilor (titlul spune ce e lista, nu doar sub-tab-ul)
              <SettingsSection title={t('settings.users.title')} titleExtra={<HelpTip id="roles" />}>
                <NotLoaded state={usersState} onRetry={() => { setUsersState({ status: 'loading' }); void loadUsers() }} />
                {usersOk && (
                  <AccountsPanel users={users} catalogue={catalogue} hosts={hosts} isOwner={isOwner}
                    reload={reloadAccounts} setUsers={setUsers} done={doneAt('accounts')} fail={failAt('accounts')} />
                )}
                {status('accounts')}
              </SettingsSection>
            )}
          </div>

          <div {...panel('roles')} data-setting-id="roles">
            {tabs.includes('roles') && (
              <>
                <RolesPanel catalogue={catalogue} canEdit={rolesManage} me={usersOk ? selfOf(users) : undefined}
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
                  <SettingsSection title={t('roles.sso.title')}>
                    <ErrorState compact title={t('roles.sso.loadFailed')} message={ssoErr} onRetry={() => { void loadSso() }} />
                  </SettingsSection>
                )}
                {sso?.enabled && (
                  <SsoPanel catalogue={catalogue} hosts={hosts} isOwner={isOwner} mappings={sso.mappings}
                    localPwAccounts={sso.local_password_accounts ?? 0} me={usersOk ? selfOf(users) : undefined}
                    reload={reloadSso} done={doneAt('sso')} fail={failAt('sso')} />
                )}
                {/* 3.6.11: SCIM — starea pentru users.manage, acţiunile doar pentru un Owner */}
                {sso?.enabled && <ScimPanel isOwner={isOwner} me={usersOk ? selfOf(users) : undefined} done={(x) => { doneAt('sso')(x); void loadUsers() }} fail={failAt('sso')} />}
                {status('sso')}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
