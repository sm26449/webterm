import { useI18n } from '../lib/i18n'
import type { ToastKind } from '../lib/notify'

export interface ToastItem {
  id: string
  message: string
  kind: ToastKind
}

export default function Toasts(props: {
  items: ToastItem[]
  onDismiss: (id: string) => void
}) {
  const { t } = useI18n()            // înainte de orice return (rules-of-hooks)
  if (props.items.length === 0) return null
  return (
    <div
      // erorile sunt `assertive` (cititorul de ecran le anunţă imediat); info/warn `polite`
      aria-live={props.items.some((i) => i.kind === 'error') ? 'assertive' : 'polite'}
      role={props.items.some((i) => i.kind === 'error') ? 'alert' : 'status'}
      className="pointer-events-none fixed bottom-4 right-4 z-50 flex max-w-sm flex-col gap-2 pb-[env(safe-area-inset-bottom)]"
    >
      {props.items.map((item) => (
        <button
          key={item.id}
          onClick={() => props.onDismiss(item.id)}
          aria-label={t('toast.dismiss')}
          className={`pointer-events-auto flex cursor-pointer items-start gap-2 rounded-lg border px-4 py-3 text-left text-sm shadow-lg ${
            item.kind === 'error'
              ? 'border-rose-500/50 bg-ink-800 wt-danger'
              : item.kind === 'warn'
              ? 'border-amber-500/40 bg-ink-800 wt-warn'
              : 'border-ink-600 bg-ink-800 text-slate-200'
          }`}
        >
          {/* un indicator vizual pe lângă culoare — eroarea nu se bazează DOAR pe roşu (daltonism) */}
          {item.kind === 'error' && <span aria-hidden="true" className="mt-px shrink-0 font-semibold">⚠</span>}
          <span className="min-w-0">{item.message}</span>
        </button>
      ))}
    </div>
  )
}
