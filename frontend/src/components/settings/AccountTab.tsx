import { FormEvent, useEffect, useState } from 'react'
import { api, ApiError, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { field, heading } from './ui'

// Cont: schimbarea emailului/parolei (cu al doilea factor pe dispozitiv nou — email-code) şi
// conturile (toate cu drepturi depline; nu există roluri). Extras din SettingsModal.
type UserRow = { id: number; email: string; created: number; totp: boolean; passkeys: number; is_self: boolean }

export default function AccountTab(props: { email?: string | null; onAccountChanged: () => void }) {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)
  const [curPw, setCurPw] = useState('')
  const [newEmail, setNewEmail] = useState(props.email ?? '')
  const [newPw, setNewPw] = useState('')
  const [emailCode, setEmailCode] = useState('')
  const [codeAsked, setCodeAsked] = useState(false)
  const [accountMsg, setAccountMsg] = useState('')
  const [accountErr, setAccountErr] = useState('')

  const [users, setUsers] = useState<UserRow[]>([])
  const [newUser, setNewUser] = useState({ email: '', password: '', current_password: '' })
  const [usersMsg, setUsersMsg] = useState('')
  const [usersErr, setUsersErr] = useState('')
  const loadUsers = () => api<UserRow[]>('/api/users').then(setUsers).catch(() => {})

  useEffect(() => { loadUsers() }, [])   // încarcă lista la deschiderea tab-ului

  async function saveAccount(e: FormEvent) {
    e.preventDefault()
    setAccountErr(''); setAccountMsg(''); setBusy(true)
    try {
      await api('/api/account', {
        method: 'POST',
        body: JSON.stringify({
          current_password: curPw,
          email: newEmail,
          new_password: newPw || undefined,
          email_code: emailCode || undefined,
        }),
      })
      setAccountMsg(t('settings.accountUpdated'))
      setCurPw(''); setNewPw(''); setEmailCode(''); setCodeAsked(false)
      props.onAccountChanged()
    } catch (err) {
      // Serverul tocmai a trimis codul pe email — deschidem câmpul şi păstrăm ce a completat deja,
      // ca „mai introdu şi codul" să nu însemne „ia-o de la capăt".
      if (err instanceof ApiError && err.code === 'account.codeRequired') setCodeAsked(true)
      setAccountErr(errText(err, t) || t('settings.error'))
    } finally {
      setBusy(false)
    }
  }

  async function addUser(e: FormEvent) {
    e.preventDefault()
    setUsersErr(''); setUsersMsg(''); setBusy(true)
    try {
      setUsers(await api<UserRow[]>('/api/users', { method: 'POST', body: JSON.stringify(newUser) }))
      setNewUser({ email: '', password: '', current_password: '' })
      setUsersMsg(t('settings.users.added'))
    } catch (e) {
      setUsersErr(errText(e, t) || String(e))
    }
    setBusy(false)
  }

  async function removeUser(u: UserRow) {
    // ştergerea unui cont taie şi sesiunile lui: e o revocare, nu o ascundere
    const pw = window.prompt(t('settings.users.deleteConfirm', { email: u.email }))
    if (!pw) return
    setUsersErr(''); setUsersMsg('')
    try {
      setUsers(await api<UserRow[]>(`/api/users/${u.id}/delete`,
        { method: 'POST', body: JSON.stringify({ current_password: pw }) }))
      setUsersMsg(t('settings.users.deleted'))
    } catch (e) {
      setUsersErr(errText(e, t) || String(e))
    }
  }

  return (
    <div>
      {/* ── Cont ── */}
      <h3 className={heading + ' !mt-0'}>{t('settings.account')}</h3>
      <form onSubmit={saveAccount} className="mt-2 flex flex-col gap-2">
        <input type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)}
          placeholder={t('settings.email')} aria-label={t('settings.email')}
          autoComplete="username" className={field} />
        <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)}
          placeholder={t('settings.newPasswordPlaceholder')} aria-label={t('settings.newPassword')}
          autoComplete="new-password" className={field} />
        <input type="password" required value={curPw} onChange={(e) => setCurPw(e.target.value)}
          placeholder={t('settings.currentPasswordConfirm')} aria-label={t('settings.currentPassword')}
          autoComplete="current-password" className={field} />
        {codeAsked && (
          <div className="flex flex-col gap-1">
            <input type="text" inputMode="numeric" autoComplete="one-time-code"
              value={emailCode} onChange={(e) => setEmailCode(e.target.value)}
              placeholder={t('settings.emailCodePlaceholder')} aria-label={t('settings.emailCodePlaceholder')}
              className={field} />
            <p className="text-xs text-slate-400">{t('settings.emailCodeHint')}</p>
          </div>
        )}
        <div className="flex items-center gap-3">
          <button disabled={busy || !curPw}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
            {t('settings.saveAccount')}
          </button>
          {accountMsg && <span className="text-sm wt-good">{accountMsg}</span>}
          {accountErr && <span className="text-sm wt-danger">{accountErr}</span>}
        </div>
      </form>

      {/* ── Conturi (toate cu drepturi depline) ── */}
      <h3 className={heading}>{t('settings.users.title')}</h3>
      <p className="mt-1 text-xs text-slate-500">{t('settings.users.hint')}</p>
      <ul className="mt-2 flex flex-col gap-1">
        {users.map((u) => (
          <li key={u.id} className="flex items-center gap-2 rounded-lg bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
            <span className="min-w-0 flex-1 truncate text-slate-200">{u.email}</span>
            {u.is_self && <span className="shrink-0 rounded bg-sky-600/20 px-1.5 py-0.5 text-[11px] wt-accent">{t('settings.users.you')}</span>}
            {u.totp && <span className="shrink-0 text-[11px] text-slate-500">2FA</span>}
            {u.passkeys > 0 && <span className="shrink-0 text-[11px] text-slate-500">{t('settings.users.passkeys', { n: u.passkeys })}</span>}
            {!u.is_self && users.length > 1 && (
              <button onClick={() => removeUser(u)} className="shrink-0 text-xs wt-danger hover:underline">
                {t('settings.delete')}
              </button>
            )}
          </li>
        ))}
      </ul>
      <form onSubmit={addUser} className="mt-3 flex flex-col gap-2">
        <div className="flex flex-col gap-2 sm:flex-row">
          <input type="email" value={newUser.email} autoComplete="off"
            onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
            placeholder={t('settings.users.emailPlaceholder')} aria-label={t('settings.email')} className={field} />
          <input type="password" value={newUser.password} autoComplete="new-password"
            onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
            placeholder={t('settings.users.passwordPlaceholder')} aria-label={t('settings.newPassword')} className={field} />
        </div>
        <input type="password" value={newUser.current_password} autoComplete="current-password"
          onChange={(e) => setNewUser({ ...newUser, current_password: e.target.value })}
          placeholder={t('settings.currentPasswordConfirm')} aria-label={t('settings.currentPassword')} className={field} />
        <div className="flex items-center gap-3">
          <button type="submit" disabled={busy || !newUser.current_password}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
            {t('settings.users.add')}
          </button>
          {usersMsg && <span className="text-sm wt-good">{usersMsg}</span>}
          {usersErr && <span className="text-sm wt-danger">{usersErr}</span>}
        </div>
      </form>
    </div>
  )
}
