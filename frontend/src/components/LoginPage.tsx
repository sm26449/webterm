import { startAuthentication } from '@simplewebauthn/browser'
import { FormEvent, useEffect, useRef, useState } from 'react'
import { errText, api, getBootVersion } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { KeyIcon, ShieldIcon } from './Icons'

/** cheia mesajului pentru `?sso_error=<reason>` (exportată pentru test) */
export function ssoErrorKey(reason: string | null): string {
  if (reason === 'disabled') return 'login.ssoDisabled'
  if (reason === 'unavailable') return 'login.ssoUnavailable'
  return 'login.ssoError'
}

export type SsoStatus = { enabled: boolean; provider_name: string; degraded?: boolean }

/** localStorage: ultima stare „SSO activ" confirmată. Un blip de reţea la /api/oidc/status nu
 *  trebuie să facă opţiunea SSO să DISPARĂ din login (3.6.20: un singur eşec al cererii ascundea
 *  complet butonul şi omul credea că SSO e stricat, deşi backendul era sănătos). */
export const SSO_KNOWN_KEY = 'wt_sso_known'

/** Decizia când TOATE încercările către /api/oidc/status eşuează. Endpoint-ul e PUBLIC şi reflectă
 *  o configuraţie STATICĂ — un eşec tranzitoriu nu e dovadă că SSO lipseşte. Dacă am văzut vreodată
 *  SSO activ (known-good), arătăm butonul în stare „inaccesibil"; altfel rămâne necunoscut (null =
 *  fără buton, dar formularul de parolă e mereu acolo ca break-glass). Pur, deci testabil. */
export function ssoFallback(cachedRaw: string | null): SsoStatus | null {
  try {
    const kg = JSON.parse(cachedRaw || 'null')
    if (kg && kg.enabled) return { enabled: true, provider_name: String(kg.provider_name || ''), degraded: true }
  } catch { /* JSON invalid / localStorage indisponibil */ }
  return null
}

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
  // FL-07: `degraded` = ultima sondă a gateway-ului (System health) n-a putut contacta IdP-ul —
  // butonul SSO spune asta ÎNAINTE de click, nu după un redirect eşuat
  const [sso, setSso] = useState<SsoStatus | null>(null)
  // La eşec, focusul merge pe PRIMUL câmp marcat invalid (WCAG 3.3.1): fără asta un utilizator
  // de cititor de ecran apasă Enter cu parola greşită şi rămâne pe buton, fără să audă nimic.
  const emailRef = useRef<HTMLInputElement>(null)
  const totpRef = useRef<HTMLInputElement>(null)
  function fail(msg: string) {
    setError(msg)
    ;(totpRequired ? totpRef : emailRef).current?.focus()
  }

  // SSO e opţional: aflăm din /api/oidc/status dacă afişăm butonul. Formularul de parolă
  // rămâne MEREU vizibil (break-glass), chiar când SSO e activ.
  useEffect(() => {
    let alive = true
    // 3.6.20: reîncercăm de câteva ori şi păstrăm un known-good. Înainte, un SINGUR eşec al cererii
    // (ex. un blip de DNS în container) făcea `setSso(null)` → butonul SSO dispărea complet până la
    // un reload reuşit. Un endpoint public, cu config statică, nu trebuie să evaporeze opţiunea SSO.
    async function loadSso() {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const s = await api<SsoStatus>('/api/oidc/status')
          if (!alive) return
          setSso(s)
          try {
            localStorage.setItem(SSO_KNOWN_KEY, JSON.stringify({ enabled: s.enabled, provider_name: s.provider_name }))
          } catch { /* localStorage indisponibil */ }
          return
        } catch {
          if (attempt < 2) await new Promise((r) => setTimeout(r, 300 * (attempt + 1)))
        }
      }
      if (!alive) return
      let cached: string | null = null
      try { cached = localStorage.getItem(SSO_KNOWN_KEY) } catch { /* localStorage indisponibil */ }
      setSso(ssoFallback(cached))
    }
    loadSso()
    // eroare venită din redirect-ul de callback (?sso_error=...): o arătăm, nu o înghiţim
    const p = new URLSearchParams(window.location.search)
    if (p.get('sso_error') || p.get('sso') === 'disabled') {
      // 3.6.11: contul e dezactivat (SCIM) — spus pe nume, altfel omul reîncearcă la nesfârşit.
      // FL-07: IdP-ul nu a putut fi contactat (discovery / token endpoint) ≠ o eroare de callback:
      // „încearcă din nou sau foloseşte parola" minţea un cont SSO-only; mesajul numeşte break-glass-ul
      setError(t(ssoErrorKey(p.get('sso_error'))))
      window.history.replaceState(null, '', window.location.pathname)
    }
    return () => { alive = false }
  }, [t])

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
      setError(errText(err, t) || t('login.passkeyUnavailable'))   // nu e un câmp invalid: fără mutare de focus
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
      fail(errText(err, t) || t('login.networkError'))
    } finally {
      setBusy(false)
    }
  }

  const inputClass =
    'w-full rounded-xl bg-ink-800/70 px-4 py-3 text-base text-slate-200 placeholder-slate-500 ' +
    'ring-1 ring-[rgb(var(--field-border))] transition focus:ring-2 focus:ring-sky-500'
  // eroarea e una singură şi generică (serverul nu spune CARE câmp e greşit — deliberat, la
  // login), deci o legăm de toate câmpurile completate: oricare ar fi focalizat, e citită
  // eticheta persistentă (U22): mică, dar nu estompată — e numele câmpului, nu un comentariu
  const labelClass = 'mb-1 block px-1 text-xs font-medium text-slate-400'
  const invalid = error ? { 'aria-invalid': true as const, 'aria-describedby': 'login-error' } : {}

  const version = getBootVersion()

  return (
    <div className="flex h-full items-center justify-center p-5">
      <div className="login-card w-full max-w-[380px] rounded-2xl p-8 sm:p-9">
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
          <h1 className="mt-4 text-display font-semibold tracking-tight text-slate-200">WebTerm</h1>
          <p className="mt-1 text-compact leading-relaxed text-slate-500">
            {props.setupRequired ? t('login.subtitle.setup') : t('login.subtitle.login')}
          </p>
        </div>

        <form onSubmit={submit} className="mt-7 flex flex-col gap-3">
          {/* U22 (3.6.3): etichete VIZIBILE şi persistente, legate de câmp (htmlFor/id). Placeholder-ul
              dispărea la prima literă — după completare nu mai ştiai ce câmp e care (WCAG 3.3.2). */}
          <div>
            <label htmlFor="login-email" className={labelClass}>{t('login.email')}</label>
            <input
              id="login-email"
              ref={emailRef}
              type="email"
              required
              autoComplete="username"
              {...invalid}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={inputClass}
            />
          </div>
          <div>
            <label htmlFor="login-password" className={labelClass}>
              {props.setupRequired ? t('login.passwordNew') : t('login.password')}
            </label>
            <input
              id="login-password"
              type="password"
              required
              autoComplete={props.setupRequired ? 'new-password' : 'current-password'}
              {...invalid}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={inputClass}
            />
          </div>
          {props.setupRequired && (
            <div>
              <label htmlFor="login-setup-token" className={labelClass}>{t('login.setupToken')}</label>
              <input
                id="login-setup-token"
                required
                {...invalid}
                value={setupToken}
                onChange={(e) => setSetupToken(e.target.value)}
                className={inputClass}
              />
              <p className="mt-1 px-1 text-xs leading-snug text-slate-500">
                {t('login.setupTokenHint')}{' '}
                (<code className="font-mono">docker compose logs app</code>).
              </p>
            </div>
          )}
          {/* anunţul pasului 2: câmpul TOTP apare şi primeşte focus, dar fără o regiune live
              cititorul de ecran nu află DE CE a sărit focusul. Montată permanent (goală). */}
          <p role="status" className="sr-only">{totpRequired ? t('login.totpStep') : ''}</p>
          {totpRequired && (
            <div>
              <label htmlFor="login-totp" className={labelClass}>{t('login.totp')}</label>
              <input
                id="login-totp"
                ref={totpRef}
                required
                autoFocus
                inputMode="numeric"
                pattern="[0-9]*"
                autoComplete="one-time-code"
                {...invalid}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                className={inputClass}
              />
              <p className="mt-1 px-1 text-xs leading-snug text-slate-500">
                {t('login.totpHint')}
              </p>
            </div>
          )}
          {/* `role="alert"` montat PERMANENT: o regiune live care apare odată cu textul nu e anunţată
              de toate cititoarele; goală nu ocupă loc (fără padding când nu e eroare) */}
          <div
            id="login-error"
            role="alert"
            className={error ? 'wt-danger rounded-md bg-rose-500/10 px-3 py-2 text-compact ring-1 ring-rose-500/20' : 'sr-only'}
          >
            {error}
          </div>
          <button
            disabled={busy}
            className="mt-1 rounded-xl bg-sky-600 py-3 text-base font-medium text-white shadow-sm transition hover:bg-sky-700 active:scale-[0.99] disabled:opacity-50"
          >
            {busy ? t('login.processing') : props.setupRequired ? t('login.createAccount') : totpRequired ? t('login.confirmCode') : t('login.enter')}
          </button>
        </form>

        {(() => {
          if (props.setupRequired) return null
          const passkeyOn = props.webauthnAvailable && !!window.PublicKeyCredential
          const ssoOn = !!sso?.enabled
          if (!passkeyOn && !ssoOn) return null
          // când ambele metode sunt prezente stau pe UN rând, cu etichete scurte; când e
          // una singură, butonul ocupă tot rândul şi primeşte eticheta completă.
          const both = passkeyOn && ssoOn
          // FL-07: nota „IdP inaccesibil" stă lângă buton cât timp sonda zice degradat — şi după un
          // click eşuat (altfel `aria-describedby` arăta spre un id inexistent); lipseşte doar când
          // alerta de eroare de deasupra spune deja exact acelaşi text (?sso_error=unavailable)
          const degradedNote = ssoOn && !!sso!.degraded && error !== t('login.ssoUnavailable')
          const btn =
            'flex flex-1 items-center justify-center gap-2 rounded-xl bg-ink-800/60 py-3 ' +
            'text-sm font-medium text-slate-300 ring-1 ring-ink-700 transition ' +
            'hover:bg-ink-700/60 disabled:opacity-50'
          return (
            <>
              <div className="my-5 flex items-center gap-3 text-2xs uppercase tracking-widest text-slate-600">
                <span className="h-px flex-1 bg-ink-700" />
                {t('login.or')}
                <span className="h-px flex-1 bg-ink-700" />
              </div>
              <div className="flex gap-2">
                {passkeyOn && (
                  <button type="button" onClick={passkeyLogin} disabled={busy} className={btn}>
                    <KeyIcon /> {busy ? t('login.processing') : both ? t('login.passkeyShort') : t('login.passkey')}
                  </button>
                )}
                {ssoOn && (
                  // FL-07: degradat = sonda n-a ajuns la IdP; rămâne apăsabil (sonda se re-rulează
                  // singură în ≤5 min după un eşec — 3.6.20 — iar un click o re-testează pe loc), dar
                  // spune starea în text — textul vizibil E numele
                  // accesibil (fără aria-label: WCAG 2.5.3 label-in-name, axe 4.14 ca în 3.6.13), iar nota
                  // completă de break-glass vine prin aria-describedby
                  <a href="/api/oidc/login" className={btn + (sso!.degraded ? ' opacity-70' : '')}
                    aria-describedby={degradedNote ? 'login-sso-degraded' : undefined} data-sso-degraded={sso!.degraded || undefined}>
                    <ShieldIcon /> {both ? sso!.provider_name : t('login.sso', { provider: sso!.provider_name })}
                    {sso!.degraded && <span className="text-xs text-warn">({t('login.ssoUnreachable')})</span>}
                  </a>
                )}
              </div>
              {degradedNote && (
                <p id="login-sso-degraded" role="status" className="mt-3 rounded-md bg-warn/10 px-3 py-2 text-xs leading-snug text-warn">
                  {t('login.ssoUnavailable')}
                </p>
              )}
            </>
          )
        })()}

        <footer className="mt-7 border-t border-ink-800/70 pt-4 text-center text-2xs leading-relaxed text-slate-600">
          <span className="font-medium text-slate-500">WebTerm</span>
          {version && <span className="tabular-nums"> · v{version}</span>} · {t('login.footer.tagline')}
          <br />
          <a href="https://github.com/sm26449/webterm" target="_blank" rel="noopener noreferrer" className="inline-block py-1.5 hover:text-slate-400 hover:underline">
            {t('login.footer.license')}
          </a>
          <span> · © {new Date().getFullYear()} WebTerm</span>
        </footer>
      </div>
    </div>
  )
}
