import { FormEvent, useState } from 'react'
import { api, ApiError, errText, withSecondFactor as withSecondFactorT } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { field } from './ui'
import { Button, Field, SettingsSection } from '../ui'
import HelpTip from '../HelpTip'

// 3.7.1 (audit UX Setări #6): pe ecrane tactile câmpurile contului ating 44 px (.wt-touch, index.css)
const touchField = `${field} wt-touch`

// Cont: schimbarea emailului/parolei (cu al doilea factor pe dispozitiv nou — email-code).
// Lista de conturi + rolurile lor s-au mutat în UsersTab (3.6, „Users & roles").

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

  // second_gate acoperă acum şi operaţiile de cont (audit intern 2026-09-23): cu TOTP activ,
  // serverul cere codul — withSecondFactor îl cere reactiv şi reîncearcă o dată.
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>, opts?: { totpOnly?: boolean }) =>
    withSecondFactorT(t, send, opts)

  async function saveAccount(e: FormEvent) {
    e.preventDefault()
    setAccountErr(''); setAccountMsg(''); setBusy(true)
    try {
      // totpOnly: fluxul de email-code pe dispozitiv nou are câmpul lui INLINE în formular
      // (codeAsked) — mai bun decât un prompt(); interceptăm doar TOTP-ul
      await withSecondFactor((extra) => api('/api/account', {
        method: 'POST',
        body: JSON.stringify({
          current_password: curPw,
          email: newEmail,
          new_password: newPw || undefined,
          email_code: emailCode || undefined,
          ...extra,
        }),
      }), { totpOnly: true })
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

  // 3.7.1 (audit UX Setări M8/Me1): o secţiune-card cu etichete VIZIBILE; placeholder-ul nu mai ţine
  // loc de nume — după completare, trei câmpuri de parolă arătau la fel. Un singur Save, în subsol.
  return (
    <form onSubmit={saveAccount}>
      <SettingsSection data-setting-id="account" title={t('settings.account')} titleExtra={<HelpTip id="account" />}
        description={t('settings.accountDesc')}
        footer={<>
          <Button variant="primary" type="submit" className="wt-touch" loading={busy} disabled={!curPw}
            aria-describedby={!curPw ? 'acct-save-why' : undefined}>
            {t('settings.saveAccount')}
          </Button>
          {!curPw && <span id="acct-save-why" className="text-xs text-slate-500">{t('settings.saveAccountWhy')}</span>}
          <span role="status" className={accountMsg ? 'text-sm wt-good' : 'sr-only'}>{accountMsg}</span>
          <span role="alert" className={accountErr ? 'text-sm wt-danger' : 'sr-only'}>{accountErr}</span>
        </>}>
        <div className="flex flex-col gap-3">
          <Field label={t('settings.email')}>
            <input type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)}
              autoComplete="username" className={touchField} />
          </Field>
          <Field label={t('settings.newPassword')} hint={t('settings.newPasswordHint')}>
            <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)}
              autoComplete="new-password" className={touchField} />
          </Field>
          <Field label={t('settings.currentPassword')} hint={t('settings.currentPasswordHint')}>
            <input type="password" required value={curPw} onChange={(e) => setCurPw(e.target.value)}
              autoComplete="current-password" className={touchField} />
          </Field>
          {codeAsked && (
            <Field label={t('settings.emailCodePlaceholder')} hint={t('settings.emailCodeHint')}>
              <input type="text" inputMode="numeric" autoComplete="one-time-code"
                value={emailCode} onChange={(e) => setEmailCode(e.target.value)} className={touchField} />
            </Field>
          )}
        </div>
      </SettingsSection>
    </form>
  )
}
