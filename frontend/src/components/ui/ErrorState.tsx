import type { ReactNode } from 'react'
import { useI18n } from '../../lib/i18n'
import { buttonClass } from './classes'

/** Starea „ceva n-a mers" — DISTINCTĂ de starea goală (EmptyState). Spune ce s-a întâmplat
    (titlu + mesajul serverului, dacă există) şi, când se poate, oferă Reîncearcă. `role="alert"`:
    apare după o acţiune (încărcare), deci cititorul de ecran o anunţă fără să mute focusul.
    LoadFailed e acest component cu titlul „n-am putut încărca". */
export default function ErrorState(props: {
  title: ReactNode
  message?: ReactNode
  onRetry?: () => void
  /** eticheta butonului; implicit „Reîncearcă" */
  retryLabel?: string
  compact?: boolean
}) {
  const { t } = useI18n()
  return (
    <div role="alert" className={`${props.compact ? 'p-3' : 'p-6'} text-center text-xs`}>
      <p className="wt-danger font-medium">{props.title}</p>
      {props.message && <p className="mt-1 break-words text-slate-500">{props.message}</p>}
      {props.onRetry && (
        <button type="button" onClick={props.onRetry}
          className={`mt-2 ${buttonClass('secondary', 'sm')}`}>
          {props.retryLabel ?? t('common.retry')}
        </button>
      )}
    </div>
  )
}
