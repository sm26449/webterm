import { useState } from 'react'
import { useI18n } from '../lib/i18n'
import { copyText } from '../lib/clipboard'
import { Button } from './ui'

/** Starea verificării de versiune, când gazda vrea să o arate lângă comandă. `error` = ultima
    verificare a EŞUAT (GitHub inaccesibil, DNS, proxy): atunci spunem „n-am putut verifica" cu
    motivul şi oferim reîncercarea — niciodată un „la zi" rămas de la verificarea precedentă,
    pentru că un „la zi" vechi e exact minciuna care te lasă pe o versiune cu CVE. */
export interface UpdateCheckStatus {
  error?: string | null
  checking?: boolean
  onRetry?: () => void
}

/** Comanda de update, gata de copiat. Deliberat NU există buton „actualizează acum":
    aplicaţia care se reporneşte singură e cel mai periculos buton pe care l-am putea
    adăuga (vezi post-mortemul v1.0.11), iar update-ul e o decizie conştientă, dată de
    la tastatură. Noi doar spunem că există versiune nouă şi exact ce trebuie rulat. */
export default function UpdateCommand(props: { command: string; status?: UpdateCheckStatus }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  const st = props.status
  return (
    <div>
      {st?.error && (
        <div role="alert" className="wt-warn mb-2 flex flex-wrap items-center gap-2 rounded-lg bg-amber-500/10 px-2.5 py-1.5 text-xs ring-1 ring-amber-500/30">
          <span className="min-w-0 flex-1 break-words">{t('settings.update.failed', { error: st.error })}</span>
          {st.onRetry && (
            <Button variant="secondary" size="sm" type="button" onClick={st.onRetry} disabled={st.checking}>
              {st.checking ? t('settings.update.checking') : t('settings.update.retry')}
            </Button>
          )}
        </div>
      )}
      <div className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-950 px-2.5 py-1.5">
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
        {/* confirmarea copierii, anunţată (textul butonului se schimbă, dar focusul e deja pe el) */}
        <span role="status" className="sr-only">{copied ? t('settings.update.copied') : ''}</span>
      </div>
    </div>
  )
}
