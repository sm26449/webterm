import { FormEvent, useRef, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { SecretAsk } from '../lib/secretPrompt'

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
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onCancel)

  const submit = (e: FormEvent) => {
    e.preventDefault()
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
          <label className="block text-sm leading-relaxed text-slate-200" htmlFor="wt-secret-input">
            {props.ask.title}
          </label>
          <input
            id="wt-secret-input"
            autoFocus
            type={props.ask.masked ? 'password' : 'text'}
            autoComplete={props.ask.masked ? 'current-password' : 'one-time-code'}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            className="mt-3 w-full rounded-lg border border-ink-700 bg-ink-900 px-3 py-2 text-sm outline-none focus:border-sky-600"
          />
          <div className="mt-5 flex justify-end gap-2">
            <button
              type="button"
              onClick={props.onCancel}
              className="rounded-lg px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800"
            >
              {t('common.cancel')}
            </button>
            <button
              type="submit"
              className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700"
            >
              {t('common.confirm')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
