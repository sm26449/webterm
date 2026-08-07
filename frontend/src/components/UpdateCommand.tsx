import { useState } from 'react'
import { useI18n } from '../lib/i18n'
import { copyText } from '../lib/clipboard'

/** Comanda de update, gata de copiat. Deliberat NU există buton „actualizează acum":
    aplicaţia care se reporneşte singură e cel mai periculos buton pe care l-am putea
    adăuga (vezi post-mortemul v1.0.11), iar update-ul e o decizie conştientă, dată de
    la tastatură. Noi doar spunem că există versiune nouă şi exact ce trebuie rulat. */
export default function UpdateCommand(props: { command: string }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  return (
    <div className="mt-2 flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-950 px-2.5 py-1.5">
      {/* overflow-x pe cod: o comandă lungă derulează în cutia ei, nu lăţeşte modalul */}
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-pre font-mono text-xs text-slate-300">
        {props.command}
      </code>
      <button
        type="button"
        onClick={() => {
          copyText(props.command)
            .then((ok) => {
              if (!ok) return
              setCopied(true)
              setTimeout(() => setCopied(false), 1500)
            })
            .catch(() => {})
        }}
        className="shrink-0 rounded border border-ink-700 px-2 py-0.5 text-[11px] text-slate-400 hover:bg-ink-800"
      >
        {copied ? t('settings.update.copied') : t('settings.update.copy')}
      </button>
    </div>
  )
}
