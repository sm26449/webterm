import { startAuthentication } from '@simplewebauthn/browser'
import { FormEvent, useState } from 'react'
import { errText, api, getBootVersion } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { KeyIcon } from './Icons'

export default function LoginPage(props: {
  setupRequired: boolean
  webauthnAvailable: boolean
  onLogin: () => void
}) {
  const { t } = useI18n()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [setupToken, setSetupToken] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [totpRequired, setTotpRequired] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function passkeyLogin() {
    setError('')
    setBusy(true)
    try {
      const options = await api<any>('/api/webauthn/login/options', { method: 'POST' })
      const credential = await startAuthentication({ optionsJSON: options })
      await api('/api/webauthn/login/verify', {
        method: 'POST',
        body: JSON.stringify({ credential }),
      })
      props.onLogin()
    } catch (err) {
      if (err instanceof Error && err.name === 'NotAllowedError') return
      setError(errText(err, t) || t('login.passkeyUnavailable'))
    } finally {
      setBusy(false)
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      if (props.setupRequired) {
        await api('/api/setup', {
          method: 'POST',
          body: JSON.stringify({ email, password, setup_token: setupToken }),
        })
        props.onLogin()
        return
      }
      const r = await api<{ ok?: boolean; totp_required?: boolean }>('/api/login', {
        method: 'POST',
        body: JSON.stringify({ email, password, totp_code: totpCode || undefined }),
      })
      if (r.totp_required) {
        // parola e corectă — cere al doilea factor și rămâi pe formular
        setTotpRequired(true)
        setError('')
        return
      }
      props.onLogin()
    } catch (err) {
      setError(errText(err, t) || t('login.networkError'))
    } finally {
      setBusy(false)
    }
  }

  const inputClass =
    'w-full rounded-xl bg-ink-800/70 px-4 py-3 text-base text-slate-200 placeholder-slate-500 ' +
    'ring-1 ring-ink-700 transition focus:ring-2 focus:ring-sky-500'

  const version = getBootVersion()

  return (
    <div className="flex h-full items-center justify-center p-5">
      <div className="login-card w-full max-w-[380px] rounded-3xl p-8 sm:p-9">
        <div className="flex flex-col items-center text-center">
          <div className="brand-badge flex h-14 w-14 items-center justify-center rounded-2xl">
            {/* marca „Flota": promptul se deschide spre trei noduri (hosturile) */}
            <svg width="42" height="42" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M4.5 6.4 9.4 12 4.5 17.6" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M9.4 12 14.6 7.1M9.4 12 18.4 12M9.4 12 14.6 16.9" fill="none" stroke="#fff" strokeWidth="1.35" strokeLinecap="round" opacity="0.6" />
              <circle cx="14.6" cy="7.1" r="2.1" fill="#fff" />
              <circle cx="18.4" cy="12" r="2.1" fill="#fff" />
              <circle cx="14.6" cy="16.9" r="2.1" fill="#fff" />
            </svg>
          </div>
          <h1 className="mt-4 text-[22px] font-semibold tracking-tight text-slate-200">WebTerm</h1>
          <p className="mt-1 text-[13px] leading-relaxed text-slate-500">
            {props.setupRequired ? t('login.subtitle.setup') : t('login.subtitle.login')}
          </p>
        </div>

        <form onSubmit={submit} className="mt-7 flex flex-col gap-3">
          <input
            type="email"
            required
            placeholder={t('login.email')}
            aria-label={t('login.email')}
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={inputClass}
          />
          <input
            type="password"
            required
            aria-label={t('login.password')}
            placeholder={props.setupRequired ? t('login.passwordNew') : t('login.password')}
            autoComplete={props.setupRequired ? 'new-password' : 'current-password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={inputClass}
          />
          {props.setupRequired && (
            <div>
              <input
                required
                placeholder={t('login.setupToken')}
                aria-label={t('login.setupToken')}
                value={setupToken}
                onChange={(e) => setSetupToken(e.target.value)}
                className={inputClass}
              />
              <p className="mt-1 px-1 text-[12px] leading-snug text-slate-500">
                {t('login.setupTokenHint')}{' '}
                (<code className="font-mono">docker compose logs app</code>).
              </p>
            </div>
          )}
          {totpRequired && (
            <div>
              <input
                required
                autoFocus
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder={t('login.totp')}
                aria-label={t('login.totp')}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                className={inputClass}
              />
              <p className="mt-1 px-1 text-[12px] leading-snug text-slate-500">
                {t('login.totpHint')}
              </p>
            </div>
          )}
          {error && (
            <div className="wt-danger rounded-lg bg-rose-500/10 px-3 py-2 text-[13px] ring-1 ring-rose-500/20">
              {error}
            </div>
          )}
          <button
            disabled={busy}
            className="mt-1 rounded-xl bg-sky-600 py-3 text-[15px] font-medium text-white shadow-sm transition hover:bg-sky-700 active:scale-[0.99] disabled:opacity-50"
          >
            {busy ? t('login.processing') : props.setupRequired ? t('login.createAccount') : totpRequired ? t('login.confirmCode') : t('login.enter')}
          </button>
        </form>

        {!props.setupRequired && props.webauthnAvailable && window.PublicKeyCredential && (
          <>
            <div className="my-5 flex items-center gap-3 text-[11px] uppercase tracking-widest text-slate-600">
              <span className="h-px flex-1 bg-ink-700" />
              {t('login.or')}
              <span className="h-px flex-1 bg-ink-700" />
            </div>
            <button
              type="button"
              onClick={passkeyLogin}
              disabled={busy}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-ink-800/60 py-3 text-[14px] font-medium text-slate-300 ring-1 ring-ink-700 transition hover:bg-ink-700/60 disabled:opacity-50"
            >
              <KeyIcon /> {busy ? t('login.processing') : t('login.passkey')}
            </button>
          </>
        )}

        <footer className="mt-7 border-t border-ink-800/70 pt-4 text-center text-[11px] leading-relaxed text-slate-600">
          <span className="font-medium text-slate-500">WebTerm</span>
          {version && <span className="tabular-nums"> · v{version}</span>} · {t('login.footer.tagline')}
          <br />
          <a href="https://github.com/sm26449/webterm" target="_blank" rel="noopener noreferrer" className="hover:text-slate-400 hover:underline">
            {t('login.footer.license')}
          </a>
          <span> · © 2026 Stefan Maldaianu</span>
        </footer>
      </div>
    </div>
  )
}
