import { FormEvent, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { SecretAsk } from '../lib/secretPrompt'
import { Button } from './ui'

// Fratele lui ConfirmModal, dar cu un input (mascat pentru parole): înlocuieşte
// window.prompt() pe fluxurile de re-autentificare — acela arăta parola în clar.
// Escape/backdrop = anulare (întoarce null, ca prompt()); Enter trimite.
export default function SecretPromptModal(props: {
  ask: SecretAsk
  onSubmit: (value: string) => void
  onCancel: () => void
}) {
  const { t } = useI18n()
  const [value, setValue] = useState('')
  const [err, setErr] = useState('')
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onCancel)

  const otp = !!props.ask.otp

  const submit = (e: FormEvent) => {
    e.preventDefault()
    // OTP: validăm formatul (6 cifre) client-side şi anunţăm eroarea prin role="alert" — altfel
    // trimiterea unui cod evident greşit ar consuma singura reîncercare de step-up a serverului.
    if (otp) {
      const code = value.replace(/\s/g, '')
      if (!/^\d{6}$/.test(code)) { setErr(t('stepup.totpInvalid')); return }
      props.onSubmit(code)
      return
    }
    props.onSubmit(value)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={props.onCancel}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={props.ask.title}
        className="glass w-full max-w-sm rounded-2xl p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <form onSubmit={submit}>
          {otp && (
            <div className="mb-2 text-sm font-medium text-slate-100">{props.ask.title}</div>
          )}
          <label className="block text-sm leading-relaxed text-slate-200" htmlFor="wt-secret-input">
            {otp ? (props.ask.label ?? props.ask.title) : props.ask.title}
          </label>
          <input
            id="wt-secret-input"
            autoFocus
            type={props.ask.masked ? 'password' : 'text'}
            autoComplete={props.ask.masked ? 'current-password' : 'one-time-code'}
            inputMode={otp ? 'numeric' : undefined}
            pattern={otp ? '[0-9]{6}' : undefined}
            maxLength={otp ? 6 : undefined}
            aria-invalid={otp && err ? true : undefined}
            aria-describedby={otp ? 'wt-secret-hint' : undefined}
            value={value}
            onChange={(e) => { setValue(e.target.value); if (err) setErr('') }}
            className="mt-3 min-h-[36px] w-full rounded-lg border border-ink-700 bg-ink-900 px-3 py-2 text-sm outline-none focus:border-sky-600"
          />
          {otp && props.ask.hint && (
            <p id="wt-secret-hint" className="mt-2 text-xs text-slate-400">{props.ask.hint}</p>
          )}
          {otp && err && (
            <p role="alert" className="mt-2 text-xs text-rose-400">{err}</p>
          )}
          <div className="mt-5 flex justify-end gap-2">
            <button
              type="button"
              onClick={props.onCancel}
              className="rounded-lg px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800"
            >
              {t('common.cancel')}
            </button>
            <Button variant="primary"
              type="submit">
              {t('common.confirm')}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
