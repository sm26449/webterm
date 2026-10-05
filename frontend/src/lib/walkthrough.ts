import { lsGet, lsRemove, lsSet } from './storage'

/* Logica „pură" a walkthrough-ului de primă rulare, scoasă din componentă ca să fie
   TESTABILĂ fără DOM (clamp-ul de pas + regulile de persistență). Componenta rămâne
   doar prezentare; deciziile „se mai arată? / se marchează gata?" trăiesc aici. */

// O singură cheie de localStorage: setată = „nu mai deschide automat niciodată". Lipsa ei
// (sau '0') = prima rulare → se deschide o dată. Numele e parte din contractul cu testele
// e2e (ele o presetează ca walkthrough-ul să nu blocheze fluxul de login), deci nu-l schimba.
export const WALKTHROUGH_DONE_KEY = 'wt_walkthrough_done'

export const TOTAL_STEPS = 7

/** Ţine indexul de pas în interval, oricât de „sălbatică" ar fi intrarea (clic pe un dot,
    ←/→ la capete, un index salvat devenit invalid dacă scade numărul de paşi). Fără asta,
    un index negativ sau ≥N ar randa `steps[i] === undefined` şi componenta ar arunca. */
export function clampStep(i: number, total: number = TOTAL_STEPS): number {
  if (!Number.isFinite(i)) return 0
  if (total <= 0) return 0
  return Math.max(0, Math.min(Math.trunc(i), total - 1))
}

/** Marcat „gata" = citirea întoarce exact '1'. Orice altceva (null, '0', gunoi) = nu. */
export function isWalkthroughDone(): boolean {
  return lsGet(WALKTHROUGH_DONE_KEY) === '1'
}

export function markWalkthroughDone(): void {
  lsSet(WALKTHROUGH_DONE_KEY, '1')
}

/** Readuce prima-rulare (toggle-ul din Setări „arată pentru sesiuni noi"): ştergem cheia,
    deci la următoarea autentificare walkthrough-ul se redeschide automat. */
export function resetWalkthrough(): void {
  lsRemove(WALKTHROUGH_DONE_KEY)
}

/** Se deschide automat DOAR dacă eşti autentificat şi n-a fost marcat gata. Pe ecranul de
    login (authenticated=false) nu apare niciodată — altfel ar acoperi formularul. Testele
    presetează cheia, deci întoarce false la ele şi fluxul de login rămâne neatins. */
export function shouldAutoOpen(authenticated: boolean): boolean {
  return authenticated && !isWalkthroughDone()
}

/** Regula unică de persistenţă la ÎNCHIDERE, comună tuturor căilor (Gata / Skip / Escape /
    ✕ / backdrop). Întoarce dacă trebuie marcat „gata":
      - bifa „nu mai arăta" bifată  → mereu da (orice cale de închidere);
      - altfel, doar la auto-open ŞI finalizare (butonul „Gata") → tur încheiat la prima rulare.
    „Skip for now" fără bifă NU marchează → reapare la sesiunea următoare. La REDESCHIDERE
    (auto=false, din „?"/Setări) nimic nu atinge cheia dacă bifa nu e pusă — exact cerinţa
    „replay-ul nu schimbă starea decât dacă bifezi". */
export function shouldMarkDoneOnClose(
  opts: { auto: boolean; reason: 'finish' | 'skip'; dontShowAgain: boolean },
): boolean {
  if (opts.dontShowAgain) return true
  return opts.auto && opts.reason === 'finish'
}
