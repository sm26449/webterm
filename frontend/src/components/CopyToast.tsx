import { useEffect, useRef, useState } from 'react'
import { onCopyToast } from '../lib/copytoast'
import { useI18n } from '../lib/i18n'
import { CopyIcon } from './Icons'

// Feedback discret „Copiat", separat de Toasts.tsx (alerte importante, stivuite, 6s). Un
// SINGUR pill care se resetează la fiecare copiere şi se stinge singur repede — copierea e
// frecventă (mai ales selecţia din tmux), deci nu trebuie să se acumuleze şi nici să distragă.
export default function CopyToast() {
  const { t } = useI18n()
  const [state, setState] = useState<{ label: string; on: boolean }>({ label: '', on: false })
  const timer = useRef<number | undefined>(undefined)

  useEffect(() => onCopyToast((_nonce, label) => {
    setState({ label: label || t('session.copied'), on: true })
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setState((s) => ({ ...s, on: false })), 1100)
  }), [t])

  return (
    <div
      role="status"
      aria-live="polite"
      className={`pointer-events-none fixed bottom-6 left-1/2 z-[60] -translate-x-1/2 ${
        state.on ? 'wt-copytoast-on' : 'wt-copytoast-off'}`}
    >
      <span className="flex items-center gap-1.5 rounded-full border border-ink-600 bg-ink-800/95 px-3 py-1.5 text-xs font-medium text-slate-200 shadow-lg backdrop-blur">
        <CopyIcon /> {state.on ? state.label : ''}
      </span>
    </div>
  )
}
