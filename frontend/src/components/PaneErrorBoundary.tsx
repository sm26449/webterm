import { Component, Fragment, ReactNode } from 'react'
import { useI18n } from '../lib/i18n'

/** Fallback-ul de eroare ca funcțional separat: clasa nu poate folosi hooks,
    dar UI-ul de failsafe are nevoie de `t()`. */
function PaneErrorFallback(props: { error: Error; onRemount: () => void }) {
  const { t } = useI18n()
  return (
    <div className="flex h-full w-full flex-col items-center justify-center gap-3 p-6 text-center">
      <div className="wt-danger text-sm font-medium">{t('paneerr.title')}</div>
      <div className="max-w-md break-all font-mono text-xs text-slate-500">{String(props.error)}</div>
      <div className="text-xs text-slate-500">
        {t('paneerr.intact')}
      </div>
      <button
        onClick={props.onRemount}
        className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-700"
      >
        {t('paneerr.remount')}
      </button>
    </div>
  )
}

/** Izolează crash-urile de render la nivel de panou: un terminal care crapă
    nu mai doboară toată aplicația în pagina de failsafe (lecția v1.0.11 —
    boundary-ul de la rădăcină prindea totul sau nimic). Remontarea schimbă
    key-ul subtree-ului: websocket-ul se redeschide, sesiunea tmux e neatinsă. */
export default class PaneErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null; epoch: number }
> {
  state = { error: null as Error | null, epoch: 0 }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <PaneErrorFallback
          error={this.state.error}
          onRemount={() => this.setState((s) => ({ error: null, epoch: s.epoch + 1 }))}
        />
      )
    }
    return <Fragment key={this.state.epoch}>{this.props.children}</Fragment>
  }
}
