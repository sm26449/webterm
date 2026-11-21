import { useEffect, useState } from 'react'
import { api, errText, Host, withAccessReauth, withSecondFactor as withSecondFactorT } from '../../lib/api'
import { useConfirm } from '../../lib/confirm'
import { useI18n } from '../../lib/i18n'
import { Binding, can, loadPerms, ROLE_KEYS, roleLabel, scopeLabel, SHELL_ROLES, usePerms } from '../../lib/perms'
import { type UserRow } from '../../lib/usersAdmin'
import { heading } from './ui'
import { Badge, Button } from '../ui'
import HelpTip from '../HelpTip'
import { ActionStatus, RETURN_MY_ACCESS } from './users/shared'
import ExplainAccess from './users/ExplainAccess'

/* Settings → Account & security → „Your access" (read-only). Până în 3.7.1 stătea deasupra
   sub-tab-urilor din Users & roles; auditul UX Setări (M1) a arătat că un Viewer primea un tab
   întreg „Users & roles" pentru un singur card, iar rolul tău stătea în al treilea loc faţă de parolă
   şi 2FA. Mutat aici ca atare (aceleaşi date, aceeaşi acţiune „scoate parola locală"); ce vede
   fiecare rol nu se schimbă — /api/users întoarce oricui măcar propriul rând, serverul decide. */
export default function MyAccessTab() {
  const { t } = useI18n()
  const perms = usePerms()
  const { confirm } = useConfirm()
  const [users, setUsers] = useState<UserRow[]>([])
  const [hosts, setHosts] = useState<Host[]>([])
  const [note, setNote] = useState({ msg: '', err: '' })
  // eroare ≠ gol (audit UI 3.6.1): fără rândul propriu lipsesc „de ce pot…" şi scoaterea parolei
  // locale — o spunem, nu le ascundem tăcut. Legăturile de rol vin oricum din /api/me/perms.
  const [loadErr, setLoadErr] = useState('')
  const failed = (e: unknown) => setLoadErr(t('common.loadFailed') + ' ' + errText(e, t))

  const loadUsers = () => api<UserRow[]>('/api/users').then(setUsers).catch(failed)
  useEffect(() => {
    void loadUsers()
    api<Host[]>('/api/hosts').then(setHosts).catch(failed)
  }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)
  const hostName = (id: number) => hosts.find((h) => h.id === id)?.name
  const chip = (b: Binding) => t('roles.chip', { role: roleLabel(b, t), scope: scopeLabel(b, hostName, t) })
  const self = users.find((u) => u.is_self)

  // 3.6.2 (revizuirea de securitate): un cont SSO cu parolă locală nu primeşte roluri din
  // grupuri. Omul îşi scoate singur parola; scoaterea revocă şi passkey-urile. Re-auth-ul (RB-03):
  // passkey account-scope dacă are, altfel step-up SSO (redirect; la întoarcere fereastra e deschisă)
  // — serverul ignoră parola unui cont SSO. Confirmarea e dialogul de aici, nu încă unul.
  async function removeLocalPassword() {
    if (!(await confirm({ title: t('roles.localPw.confirmTitle'), message: t('roles.localPw.confirmBody'),
      confirmLabel: t('roles.localPw.remove'), danger: true }))) return
    try {
      const r = await withAccessReauth(t, t('access.reauth.removeLocalPw'),
        (cred) => withSecondFactor((extra) => api('/api/account',
          { method: 'POST', body: JSON.stringify({ remove_password: true, ...cred, ...extra }) })),
        { me: self, returnTo: RETURN_MY_ACCESS })
      if (r === null) return
      await loadUsers()
      setNote({ msg: t('roles.localPw.removed'), err: '' })
      void loadPerms()
    } catch (x) {
      setNote({ msg: '', err: errText(x, t) || String(x) })
    }
  }
  const mine = perms?.bindings ?? self?.bindings ?? []
  const sourceTitle = (b: Binding) => (b.source === 'migration' ? t('roles.sourceMigration')
    : b.source === 'sso' ? t('roles.sourceSso') : undefined)
  // ce înseamnă fiecare rol: aici doar pentru cine NU vede sub-tab-ul Roles din „People & roles"
  // (aceeaşi condiţie ca lib/usersAdmin visibleSubTabs)
  const seesRoles = can(perms, 'users.manage') || can(perms, 'roles.manage')

  return (
    <section data-setting-id="myAccess" className="mt-6 rounded-xl bg-ink-800/40 px-3 py-3 ring-1 ring-ink-700">
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
      {loadErr && <p role="alert" className="mt-2 text-xs wt-danger">{loadErr}</p>}
      <ActionStatus msg={note.msg} err={note.err} />
      {!seesRoles && (
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
  )
}
