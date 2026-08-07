export interface ToastItem {
  id: string
  message: string
  kind: 'info' | 'warn'
}

export default function Toasts(props: {
  items: ToastItem[]
  onDismiss: (id: string) => void
}) {
  if (props.items.length === 0) return null
  return (
    <div
      role="status"
      aria-live="polite"
      className="pointer-events-none fixed bottom-4 right-4 z-50 flex max-w-sm flex-col gap-2 pb-[env(safe-area-inset-bottom)]"
    >
      {props.items.map((t) => (
        <button
          key={t.id}
          onClick={() => props.onDismiss(t.id)}
          aria-label="Dismiss notification"
          className={`pointer-events-auto cursor-pointer rounded-lg border px-4 py-3 text-left text-sm shadow-lg ${
            t.kind === 'warn'
              ? 'border-amber-500/40 bg-ink-800 wt-warn'
              : 'border-ink-600 bg-ink-800 text-slate-200'
          }`}
        >
          {t.message}
        </button>
      ))}
    </div>
  )
}
