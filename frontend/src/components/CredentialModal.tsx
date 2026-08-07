import { FormEvent, useRef, useState } from 'react'
import { useFocusTrap } from '../lib/useFocusTrap'
import { useI18n } from '../lib/i18n'

export type CredField = {
  key: string
  label: string
  type: 'password' | 'textarea'
  placeholder?: string
  optional?: boolean
}

/** Promise-bridged credential prompt: real inputs (textarea for SSH keys,
   masked password fields) instead of the native single-line prompt(), which
   can't take a multi-line PEM and shows the secret in clear. */
export default function CredentialModal(props: {
  title: string
  subtitle?: string
  fields: CredField[]
  submitLabel?: string
  onSubmit: (values: Record<string, string>) => void
  onCancel: () => void
}) {
  const { t } = useI18n()
  const [values, setValues] = useState<Record<string, string>>({})
  const set = (k: string, v: string) => setValues((s) => ({ ...s, [k]: v }))
  const missing = props.fields.some((f) => !f.optional && !(values[f.key] || '').trim())
  const ref = useRef<HTMLFormElement>(null)
  useFocusTrap(ref, props.onCancel)

  function submit(e: FormEvent) {
    e.preventDefault()
    if (!missing) props.onSubmit(values)
  }

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 p-4"
      onClick={props.onCancel}>
      <form ref={ref} onClick={(e) => e.stopPropagation()} onSubmit={submit}
        className="glass w-full max-w-md space-y-4 rounded-2xl p-6" role="dialog" aria-modal="true" aria-label={props.title}>
        <div>
          <h2 className="font-semibold">{props.title}</h2>
          {props.subtitle && <p className="mt-1 truncate text-sm text-slate-500">{props.subtitle}</p>}
        </div>
        {props.fields.map((f, i) => (
          <label key={f.key} className="block">
            <span className="mb-1 block text-xs font-medium text-slate-400">
              {f.label}{f.optional ? ' ' + t('cred.optional') : ''}
            </span>
            {f.type === 'textarea' ? (
              <textarea
                autoFocus={i === 0}
                value={values[f.key] || ''}
                onChange={(e) => set(f.key, e.target.value)}
                placeholder={f.placeholder}
                rows={5}
                className="w-full rounded-lg bg-ink-800 px-3 py-2 font-mono text-xs placeholder-slate-500 ring-1 ring-ink-700 focus:ring-sky-600"
              />
            ) : (
              <input
                type="password"
                autoFocus={i === 0}
                autoComplete="new-password"
                value={values[f.key] || ''}
                onChange={(e) => set(f.key, e.target.value)}
                placeholder={f.placeholder}
                className="w-full rounded-lg bg-ink-800 px-4 py-2.5 placeholder-slate-500 ring-1 ring-ink-700 focus:ring-sky-600"
              />
            )}
          </label>
        ))}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={props.onCancel}
            className="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-ink-800">{t('cred.cancel')}</button>
          <button disabled={missing}
            className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-40">
            {props.submitLabel || t('cred.continue')}
          </button>
        </div>
      </form>
    </div>
  )
}
