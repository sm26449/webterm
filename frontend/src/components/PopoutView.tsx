import { useCallback, useEffect, useState } from 'react'
import { startAuthentication } from '@simplewebauthn/browser'
import { api, AppState, CommandGuard, Host, Session, setStepupHandler } from '../lib/api'
import { hostAt } from '../lib/host'
import { useI18n } from '../lib/i18n'
import { registerToast } from '../lib/notify'
import { askSecret, registerSecretPrompt, SecretAsk } from '../lib/secretPrompt'
import SecretPromptModal from './SecretPromptModal'
import SessionView from './SessionView'
import Toasts, { ToastItem } from './Toasts'

/** Detached window: just the terminal, no sidebar. Drag it to another
    monitor. Connects to the same session (multi-device is native).

    Fereastra e un boot separat (fără MainApp), deci tot ce MainApp face pentru SessionView
    trebuie refăcut aici, la scară mică. Până în 3.5.3 lipseau guardrail-ul (`commandGuard`
    nepasat → nicio comandă nu era verificată în popout) şi step-up-ul (pe un host 2FA,
    idle-lock-ul nu se putea debloca decât cu passkey, iar kill/revocare cădeau pe 403). */
export default function PopoutView(props: { sid: string }) {
  const { t } = useI18n()
  const [session, setSession] = useState<Session | null>(null)
  const [host, setHost] = useState<Host | undefined>(undefined)
  const [gone, setGone] = useState(false)
  const [guard, setGuard] = useState<CommandGuard | null>(null)
  const [webauthn, setWebauthn] = useState(false)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const [sessions, hosts, state] = await Promise.all([
          api<Session[]>('/api/sessions'),
          api<Host[]>('/api/hosts'),
          // /api/state = aceeaşi sursă ca fereastra principală pentru guardrail + WebAuthn
          api<AppState>('/api/state').catch(() => null),
        ])
        if (!active) return
        if (state) {
          setGuard(state.command_guard ?? null)
          setWebauthn(!!state.webauthn_available)
        }
        const s = sessions.find((x) => x.id === props.sid) ?? null
        if (!s) {
          setGone(true)
          return
        }
        const h = hosts.find((x) => x.id === s.host_id)
        setSession(s)
        setHost(h)
        document.title = `${s.title || t('app.sessionFallback')}${h ? ' · ' + hostAt(h) : ''} · WebTerm`
      } catch {
        /* retry on next tick */
      }
    }
    load()
    // `t` umbrea funcţia de traducere din componentă
    const timer = setInterval(() => { if (!document.hidden) load() }, 5000)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [props.sid])

  // toast-uri: fără gazdă, erorile acţiunilor (kill, redenumire, revocare) se pierdeau în tăcere
  const [toasts, setToasts] = useState<ToastItem[]>([])
  useEffect(() => {
    registerToast((message, kind) => {
      const id = `${Date.now()}-${Math.random()}`
      setToasts((ts) => [...ts, { id, message, kind }])
      setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), kind === 'error' ? 12000 : 6000)
    })
  }, [])

  // gazda pentru askSecret() (parola contului / cod TOTP), ca în App — fără ea, askSecret cădea
  // pe window.prompt, care afişează parola în CLAR
  const [secretReq, setSecretReq] = useState<{ ask: SecretAsk; resolve: (v: string | null) => void } | null>(null)
  useEffect(() => {
    registerSecretPrompt((ask) => new Promise((resolve) => {
      setSecretReq((prev) => {
        prev?.resolve(null)
        return { ask, resolve }
      })
    }))
    return () => registerSecretPrompt(null)
  }, [])

  // Ceremonia de step-up, aceeaşi scară ca în App.stepupCredential: passkey → TOTP → parola
  // contului. SSO nu are nevoie de nimic aici: api() face singur redirectul la IdP pe 403
  // `host.needs2faSso`, iar întoarcerea restaurează hash-ul (#/popout/<sid>).
  const stepupCredential = useCallback(async (
    hostId: number, code?: string,
  ): Promise<{ stepup_grant?: string; stepup_password?: string; totp?: string } | null> => {
    if (webauthn) {
      try {
        const options = await api<Record<string, unknown>>('/api/webauthn/stepup/options', {
          method: 'POST', body: JSON.stringify({ host_id: hostId }),
        })
        const credential = await startAuthentication({ optionsJSON: options as never })
        const r = await api<{ grant: string }>('/api/webauthn/stepup/verify', {
          method: 'POST', body: JSON.stringify({ host_id: hostId, credential }),
        })
        return { stepup_grant: r.grant }
      } catch {
        return null
      }
    }
    if (code === 'stepup.totp') {
      const otp = await askSecret(t('stepup.totpTitle'), {
        masked: false, otp: true, label: t('stepup.totpLabel'), hint: t('stepup.totpHint'),
      })
      return otp === null ? null : { totp: otp.trim() }
    }
    const pw = await askSecret(t('app.reauth'), { label: t('app.accountPassword'), hint: t('app.reauthSubtitle') })
    return pw === null ? null : { stepup_password: pw }
  }, [webauthn, t])

  // handler-ul global: withStepup()/api() îl cheamă la un 403 de step-up (kill, share, fs…)
  useEffect(() => {
    setStepupHandler(async (hostId, code) => {
      const cred = await stepupCredential(hostId, code)
      if (!cred) return false
      try {
        await api(`/api/hosts/${hostId}/stepup`, { method: 'POST', body: JSON.stringify(cred) })
        return true
      } catch {
        return false
      }
    })
    return () => setStepupHandler(null)
  }, [stepupCredential])

  if (gone) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 text-slate-500">
        <div className="text-lg">{t('popout.gone')}</div>
        <button onClick={() => window.close()} className="rounded-lg bg-ink-800 px-4 py-2 text-sm text-slate-300 hover:bg-ink-700">
          {t('popout.close')}
        </button>
      </div>
    )
  }
  if (!session) {
    return <div className="flex h-full items-center justify-center text-slate-500">{t('popout.connecting')}</div>
  }

  return (
    /* wt-workspace: cromul terminalului rămâne întunecat și pe tema Aurora,
       identic cu fereastra principală (tokenii dark se aplică prin clasă) */
    <div className="wt-workspace wt-main h-full">
      <SessionView
        session={session}
        host={host}
        popout
        commandGuard={guard}
        stepupCredential={stepupCredential}
        onMenu={() => {}}
        onChanged={() => {}}
        onDeleted={() => window.close()}
      />
      {secretReq && (
        <SecretPromptModal
          ask={secretReq.ask}
          onSubmit={(v) => { secretReq.resolve(v); setSecretReq(null) }}
          onCancel={() => { secretReq.resolve(null); setSecretReq(null) }}
        />
      )}
      <Toasts items={toasts} onDismiss={(id) => setToasts((ts) => ts.filter((x) => x.id !== id))} />
    </div>
  )
}
