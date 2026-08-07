import { FormEvent, useRef, useState } from 'react'
import { Snippet } from '../lib/api'
import { useFocusTrap } from '../lib/useFocusTrap'
import { useI18n } from '../lib/i18n'

/** Parametrii unui snippet: placeholder-ele `{{nume}}` din corp devin câmpuri.
    Comanda finală e arătată integral înainte de rulare — pe un terminal de
    producție, „ce anume se va executa" nu e o întrebare retorică. */
export const snippetParams = (body: string): string[] =>
  [...new Set([...body.matchAll(/\{\{\s*([\w.-]+)\s*\}\}/g)].map((m) => m[1]))]

export const fillSnippet = (body: string, values: Record<string, string>): string =>
  body.replace(/\{\{\s*([\w.-]+)\s*\}\}/g, (_, k: string) => values[k] ?? '')

export default function SnippetParams(props: {
  snippet: Snippet
  onRun: (body: string) => void
  onCancel: () => void
}) {
  const { t } = useI18n()
  const params = snippetParams(props.snippet.body)
  const [values, setValues] = useState<Record<string, string>>({})
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onCancel)

  const preview = fillSnippet(props.snippet.body, values)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    props.onRun(preview)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('snippetparams.ariaLabel', { title: props.snippet.title })}
        className="glass w-full max-w-lg rounded-2xl p-6"
      >
        <h2 className="font-semibold">{props.snippet.title}</h2>
        <p className="mt-1 text-xs text-slate-500">
          {t('snippetparams.hint')}
        </p>

        <form onSubmit={submit} className="mt-4 space-y-3">
          {params.map((p, i) => (
            <label key={p} className="block">
              <span className="mb-1 block text-xs font-medium text-slate-400">{p}</span>
              <input
                autoFocus={i === 0}
                value={values[p] ?? ''}
                onChange={(e) => setValues({ ...values, [p]: e.target.value })}
                className="w-full rounded-lg bg-ink-800 px-3 py-2 text-sm ring-1 ring-ink-700 focus:ring-sky-600"
              />
            </label>
          ))}

          <div>
            <span className="mb-1 block text-xs font-medium text-slate-400">{t('snippetparams.finalCommand')}</span>
            <code className="block max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-[#0b0e14] p-3 font-mono text-xs text-emerald-300">
              {preview}
            </code>
          </div>

          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={props.onCancel} className="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-ink-800">
              {t('snippetparams.cancel')}
            </button>
            <button className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-700">
              {t('snippetparams.insert')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
