import { useI18n } from '../../lib/i18n'
import type { LoadState } from '../../lib/loadable'
import { ErrorState } from '../ui'

/** Locţiitorul unei secţiuni de Setări care NU s-a încărcat (3.6.1, U04). Formularul nu se arată
    deloc până nu are valorile de pe server: valorile implicite din state arătau ca nişte setări
    salvate, iar Save le scria peste configuraţia reală. „Se încarcă…" sau eroarea + Reîncearcă. */
export default function NotLoaded(props: { state: LoadState; onRetry: () => void }) {
  const { t } = useI18n()
  if (props.state.status === 'ok') return null
  if (props.state.status === 'loading') {
    return <div className="mt-2 text-xs text-slate-500">{t('settings.loading')}</div>
  }
  return (
    <div className="mt-2 rounded-md ring-1 ring-ink-700" data-testid="settings-not-loaded">
      <ErrorState compact title={t('settings.notLoaded')} message={props.state.error} onRetry={props.onRetry} />
    </div>
  )
}
