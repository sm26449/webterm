// Puntea spre plasa de siguranță din public/failsafe.js — script clasic, în
// afara bundle-ului, care arată o pagină statică de recuperare când aplicația
// nu pornește sau crapă fatal (vezi post-mortem v1.0.11 în CHANGELOG).
type FailsafeWindow = Window & {
  __WT_BOOTED?: boolean
  __wtFailsafe?: (msg: string) => void
}

/** Anunță watchdog-ul că UI-ul a ajuns la un ecran funcțional (login sau app). */
export function markBooted() {
  ;(window as FailsafeWindow).__WT_BOOTED = true
  // dublat ca atribut DOM pentru smoke test-ul din CI: CSP-ul (fără
  // unsafe-eval) blochează waitForFunction din Playwright, dar un selector
  // pe atribut se poate aștepta fără eval
  document.documentElement.setAttribute('data-wt-booted', '1')
}

/** Afișează pagina statică de failsafe (folosit de ErrorBoundary). */
export function showFailsafe(msg: string) {
  ;(window as FailsafeWindow).__wtFailsafe?.(msg)
}
