import { ReactNode, useEffect, useState } from 'react'
import { useI18n } from '../lib/i18n'
import { CloseIcon } from './Icons'
import { dismissTip, isTipDismissed } from '../lib/coachtips'
import { Button } from './ui'

/* Sfat contextual: un callout MIC, NON-MODAL, ancorat lângă un element relevant, arătat o
   singură dată (vezi lib/coachtips.ts). Completează walkthrough-ul de primă rulare — acela
   explică totul o dată, la început; ăsta apare la momentul potrivit, lângă UI-ul concret.

   A11Y — de ce `role="status"` şi NU `role="dialog"`:
   Sfatul e un indiciu advisor, non-blocant, care NU trebuie să fure focusul — omul e în
   terminal sau completează un formular, iar un hint nu are voie să-i întrerupă fluxul. Un
   `role="dialog"` (chiar non-modal) creează aşteptarea că focusul intră în el şi că e un
   context de focus — ceea ce ar induce în eroare cititoarele de ecran, de vreme ce noi NU
   mutăm focusul deliberat. `role="status"` (regiune live politicoasă) anunţă titlul + corpul
   la apariţie fără să fure focusul şi fără să sugereze un modal, iar butoanele dinăuntru rămân
   în ordinea normală de Tab (deci e tastabil, cerinţa). NU prinde focusul (useFocusTrap e
   intenţionat absent) — e non-blocant, spre deosebire de modalul walkthrough-ului. */
export default function CoachTip(props: {
  /** cheia de localStorage care face sfatul „o singură dată" (vezi lib/coachtips.ts) */
  tipKey: string
  /** condiţia de declanşare a părintelui (sesiune vie, formular agent deschis etc.) */
  show: boolean
  title: string
  body: string
  icon?: ReactNode
  /** clase de POZIŢIONARE aplicate wrapperului (absolute inset-…): ancorarea e treaba părintelui,
      care ştie unde e ţinta; primitivul rămâne agnostic de layout */
  className?: string
  /** notifică părintele la închidere — ex. ca să declanşeze următorul sfat SCALONAT (toolbar
      după paste), astfel încât două callout-uri să nu apară niciodată simultan */
  onDismiss?: () => void
}) {
  const { t } = useI18n()
  // starea „închis" se citeşte o dată, din localStorage: dacă a mai fost văzut, nu reapare.
  const [dismissed, setDismissed] = useState(() => isTipDismissed(props.tipKey))
  const visible = props.show && !dismissed

  const close = () => {
    dismissTip(props.tipKey)
    setDismissed(true)
    props.onDismiss?.()
  }

  // Escape închide sfatul. CAPTURE + stopPropagation: când sfatul stă peste un modal cu
  // focus-trap (AddHostModal ascultă Escape pe document, în faza de bubble), primul Escape
  // trebuie să închidă DOAR hint-ul, nu şi modalul — îl consumăm înainte să urce. Al doilea
  // Escape (hint-ul demontat → fără ascultător) ajunge la modal, ca de obicei. În afara unui
  // modal (sfaturile din sesiune), stopPropagation e inofensiv.
  useEffect(() => {
    if (!visible) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      e.stopPropagation()
      close()
    }
    document.addEventListener('keydown', onKey, true)
    return () => document.removeEventListener('keydown', onKey, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible])

  if (!visible) return null

  return (
    <div
      // `role="status"` + live politicos: apariţia se anunţă, fără să fure focusul (vezi comentariul
      // de sus). `pointer-events-auto`: părintele poate fi un strat cu pointer-events-none (terminal).
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-testid={`coachtip-${props.tipKey}`}
      className={`glass wt-step-anim pointer-events-auto z-20 w-[min(19rem,calc(100vw-2rem))] rounded-xl border-l-2 border-sky-500 p-3 shadow-xl ring-1 ring-ink-700 ${props.className ?? ''}`}
    >
      <div className="flex items-start gap-2.5">
        {props.icon && (
          <span aria-hidden="true" className="wt-info mt-0.5 shrink-0">{props.icon}</span>
        )}
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold leading-tight text-slate-100">{props.title}</p>
          <p className="mt-1 text-xs leading-relaxed text-slate-300">{props.body}</p>
          <div className="mt-2.5 flex justify-end">
            <Button variant="primary" size="sm"
              type="button"
              onClick={close} className="wt-touch">
              {t('tips.gotIt')}
            </Button>
          </div>
        </div>
        {/* ✕: a doua cale de închidere, tastabilă. aria-label prin t() (nu literal: testul i18n
            interzice aria-label/title hardcodate care ar scăpa de traducere). */}
        <button
          type="button"
          onClick={close}
          aria-label={t('tips.dismiss')}
          className="wt-touch -mr-1 -mt-1 grid shrink-0 place-items-center rounded-md p-1 text-slate-400 hover:bg-ink-800 hover:text-slate-200"
        >
          <CloseIcon />
        </button>
      </div>
    </div>
  )
}
