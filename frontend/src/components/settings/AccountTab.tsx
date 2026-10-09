import { FormEvent, useState } from 'react'
import { api, ApiError, errText, withSecondFactor as withSecondFactorT } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { field, heading } from './ui'
import { Button } from '../ui'

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

  return (
    <div>
      <section data-setting-id="account">
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
            <Button variant="primary" disabled={busy || !curPw}>
              {t('settings.saveAccount')}
            </Button>
            {accountMsg && <span className="text-sm wt-good">{accountMsg}</span>}
            {accountErr && <span className="text-sm wt-danger">{accountErr}</span>}
          </div>
        </form>
      </section>

    </div>
  )
}
