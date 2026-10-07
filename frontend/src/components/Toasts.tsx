import { useEffect, useRef } from 'react'
import { useI18n } from '../lib/i18n'
import type { ToastKind } from '../lib/notify'
import { CloseIcon, WarningIcon } from './Icons'

export interface ToastItem {
  id: string
  message: string
  kind: ToastKind
}

/* Stiva de toast-uri. Trei lucruri pe care auditul de accesibilitate (2026-10, 2.1 şi 5.3) le-a
   găsit stricate în varianta veche şi care dictează forma de aici:
   1. Fiecare toast era un `<button>` cu `aria-label` de închidere cu mesajul înăuntru: `aria-label`
      ÎNLOCUIEŞTE conţinutul ca nume accesibil, deci cititorul de ecran auzea „Închide notificarea,
      buton" şi nimic altceva — eroarea nu putea fi recitită. Acum mesajul e textul unui element
      `role="alert"` (eroare) / `role="status"` (info/warn), iar butonul de închidere e un control
      separat, cu numele lui.
   2. Regiunile live sunt anunţate doar dacă EXISTAU în DOM înainte să primească conţinut. Containerul
      se monta odată cu primul toast → primul toast (de obicei chiar eroarea care contează) nu era
      anunţat. Containerele `aria-live` de aici sunt montate permanent, goale.
   3. Închiderea automată (App.tsx: 6 s info, 12 s eroare) nu putea fi oprită: cât timp mouse-ul
      sau focusul e pe stivă, cerem gazdei să nu şteargă nimic (`onHoldChange`), ca să poţi citi /
      copia mesajul în ritmul tău (WCAG 2.2.1). */
export default function Toasts(props: {
  items: ToastItem[]
  onDismiss: (id: string) => void
  /** true cât timp utilizatorul e pe stivă (hover/focus) — gazda amână închiderea automată */
  onHoldChange?: (held: boolean) => void
}) {
  const { t } = useI18n()            // înainte de orice return (rules-of-hooks)
  const held = useRef(false)
  const setHeld = (v: boolean) => {
    if (held.current === v) return
    held.current = v
    props.onHoldChange?.(v)
  }
  // dacă ultimul toast dispare cât e „ţinut", eliberăm — altfel gazda ar rămâne cu timerul în pauză
  useEffect(() => { if (props.items.length === 0) setHeld(false) }, [props.items.length]) // eslint-disable-line react-hooks/exhaustive-deps

  const errors = props.items.filter((i) => i.kind === 'error')
  const others = props.items.filter((i) => i.kind !== 'error')
  const render = (item: ToastItem) => (
    <div
      key={item.id}
      role={item.kind === 'error' ? 'alert' : 'status'}
      className={`wt-toast pointer-events-auto flex items-start gap-2 rounded-xl border px-3 py-2.5 text-left text-sm shadow-lg ${
        item.kind === 'error'
          ? 'border-rose-500/50 bg-ink-800 wt-danger'
          : item.kind === 'warn'
          ? 'border-amber-500/40 bg-ink-800 wt-warn'
          : 'border-ink-600 bg-ink-800 text-slate-200'
      }`}
    >
      {/* un indicator vizual pe lângă culoare — eroarea nu se bazează DOAR pe roşu (daltonism) */}
      {item.kind === 'error' && <span aria-hidden="true" className="mt-0.5 shrink-0"><WarningIcon /></span>}
      <span className="min-w-0 flex-1 break-words">{item.message}</span>
      <button
        type="button"
        onClick={() => props.onDismiss(item.id)}
        aria-label={t('toast.dismiss')}
        className="-mr-1 -mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-md text-slate-400 hover:bg-ink-700 hover:text-slate-100"
      >
        <CloseIcon size={14} />
      </button>
    </div>
  )

  return (
    <div
      className="pointer-events-none fixed bottom-4 right-4 z-50 flex max-w-sm flex-col gap-2 pb-[env(safe-area-inset-bottom)]"
      onMouseEnter={() => setHeld(true)}
      onMouseLeave={() => setHeld(false)}
      onFocusCapture={() => setHeld(true)}
      onBlurCapture={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setHeld(false) }}
    >
      {/* două regiuni live permanente: erorile `assertive` (întrerup), restul `polite` */}
      <div aria-live="polite" className="flex flex-col gap-2">{others.map(render)}</div>
      <div aria-live="assertive" className="flex flex-col gap-2">{errors.map(render)}</div>
    </div>
  )
}
