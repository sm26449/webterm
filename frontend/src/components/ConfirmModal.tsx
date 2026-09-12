import { useRef } from 'react'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'

// Confirmare mică, reutilizabilă (stil AboutModal: glass, focus-trap, Escape/backdrop închid).
// Folosită pentru acţiuni cu cost de revenire — prima: logout-ul (pierzi sesiunea web şi re-auth).
export default function ConfirmModal(props: {
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean        // buton de confirmare roşu pentru acţiuni distructive
  onConfirm: () => void
  onCancel: () => void
}) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onCancel)
  const confirmBtn = props.danger
    ? 'bg-rose-600 hover:bg-rose-700'
    : 'bg-sky-600 hover:bg-sky-700'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={props.onCancel}>
      <div
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-label={props.title}
        className="glass w-full max-w-sm rounded-2xl p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold leading-tight">{props.title}</h2>
        <p className="mt-3 text-sm leading-relaxed text-slate-300">{props.message}</p>
        <div className="mt-6 flex justify-end gap-2">
          <button
            onClick={props.onCancel}
            className="rounded-lg px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800"
          >
            {props.cancelLabel ?? t('common.cancel')}
          </button>
          <button
            autoFocus
            onClick={props.onConfirm}
            className={`rounded-lg px-3 py-1.5 text-sm font-medium text-white ${confirmBtn}`}
          >
            {props.confirmLabel ?? t('common.confirm')}
          </button>
        </div>
      </div>
    </div>
  )
}
