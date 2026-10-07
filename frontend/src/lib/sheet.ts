import { useEffect, useState } from 'react'

/* Panourile sesiunii (Files/Git/Forwards/Docker/Services/Toolbox/AI tools/Commands) ca FOAIE pe
   tot ecranul pe telefon. Pe desktop/tabletă rămân drawer/coloană, neschimbate.

   De ce aici şi nu în fiecare panou: toate trec deja prin `useDrawer`, deci decizia „foaie sau
   drawer" + istoricul (butonul Back de Android) + blocarea scroll-ului din spate se iau O DATĂ.
   Panoul primeşte doar `drawer.sheet` şi îşi alege clasa + bara cu „← Terminal" (SheetBar). */

/** Sub `sm` (640px) — sau telefon în peisaj: pointer grosier + înălţime mică (844×390 are lăţime
    de „tabletă", dar un drawer de 384px lângă un terminal de 8 rânduri e la fel de inutilizabil).
    Pragul de înălţime e acelaşi ca pentru cromul compact din index.css (480px). */
export const SHEET_QUERY = '(max-width: 639.98px), (pointer: coarse) and (max-height: 480px)'

/** Clasa unei foi: pe tot viewport-ul, opacă; inset-urile safe-area + overscroll în `.wt-sheet`. */
export const SHEET_CLS = 'wt-sheet fixed inset-0 z-40 flex w-full flex-col overflow-hidden bg-ink-900 outline-none'

/** Telefon în portret (sub `sm`) — pentru butonul „toate taburile" din TabBar. */
export const PHONE_QUERY = '(max-width: 639.98px)'

/** true cât timp `query` se potriveşte (şi `enabled`); urmăreşte rotirea/redimensionarea. */
export function useMediaQuery(query: string, enabled = true): boolean {
  const match = () => enabled && typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    && window.matchMedia(query).matches
  const [on, setOn] = useState(match)
  useEffect(() => {
    if (!enabled || typeof window.matchMedia !== 'function') { setOn(false); return }
    const mq = window.matchMedia(query)
    const upd = () => setOn(mq.matches)
    upd()
    mq.addEventListener?.('change', upd)
    return () => mq.removeEventListener?.('change', upd)
  }, [query, enabled])
  return on
}

/** true cât timp panoul trebuie randat ca foaie (şi `enabled`: un panou embed nu e niciodată foaie). */
export const useSheetMode = (enabled = true): boolean => useMediaQuery(SHEET_QUERY, enabled)

/* ── Butonul Back (Android) / swipe-back (iOS) ────────────────────────────────────────────────
   La deschiderea unei foi împingem o intrare de istoric CU ACELAŞI URL (doar `state` marcat), deci
   rutele pe hash (`#/s/<sid>`, `#/h/<id>`) nu se schimbă şi `hashchange` nu se declanşează — App
   ascultă doar `hashchange`. Back → `popstate` pe intrarea anterioară (nemarcată) → închidem foaia
   în loc să părăsim aplicaţia. Închiderea din UI (← Terminal / Escape / ✕) consumă intrarea cu
   `history.back()`, iar popstate-ul ăla îl ignorăm.

   Comutarea directă între panouri (Files → Git) face cleanup + mount în acelaşi commit React:
   `back()`-ul e AMÂNAT un tick şi anulat dacă o altă foaie revendică intrarea între timp — altfel
   back-ul asincron ar ajunge DUPĂ push-ul noului panou şi l-ar închide pe el. */
const MARK = '__wtSheet'
let owner: (() => void) | null = null
let ignorePops = 0
let pendingBack: ReturnType<typeof setTimeout> | null = null
let listening = false

const isMarked = (s: unknown): boolean =>
  !!s && typeof s === 'object' && (s as Record<string, unknown>)[MARK] === true

function onPop() {
  if (ignorePops > 0) { ignorePops--; return }
  // înapoi pe o intrare fără marcaj = userul a ieşit din foaie
  if (owner && !isMarked(window.history.state)) {
    const close = owner
    owner = null
    close()
  }
}

/** Revendică intrarea de istoric pentru foaia curentă; `close` e chemat la Back. Întoarce
    funcţia de eliberare (cleanup-ul efectului). */
export function claimSheetHistory(close: () => void): () => void {
  if (!listening) { window.addEventListener('popstate', onPop); listening = true }
  if (pendingBack) {
    // foaia anterioară tocmai s-a închis în acelaşi commit: refolosim intrarea ei
    clearTimeout(pendingBack); pendingBack = null
  } else if (!isMarked(window.history.state)) {
    const prev = window.history.state
    window.history.pushState({ ...(prev && typeof prev === 'object' ? prev : {}), [MARK]: true }, '')
  }
  owner = close
  return () => {
    if (owner !== close) return            // deja închisă prin Back, sau altă foaie a preluat-o
    owner = null
    if (!isMarked(window.history.state)) return   // s-a navigat între timp (hash nou): nimic de consumat
    pendingBack = setTimeout(() => {
      pendingBack = null
      if (owner || !isMarked(window.history.state)) return
      ignorePops++
      window.history.back()
    }, 0)
  }
}

/** Blochează scroll-ul paginii din spatele foii (numărat: două foi suprapuse nu se deblochează
    reciproc). */
let locks = 0
let prevOverflow = ''
export function lockBodyScroll(): () => void {
  if (locks++ === 0) {
    prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
  }
  let done = false
  return () => {
    if (done) return
    done = true
    if (--locks === 0) document.body.style.overflow = prevOverflow
  }
}

/** doar pentru teste: starea de modul înapoi la zero */
export function _resetSheetState() {
  if (pendingBack) clearTimeout(pendingBack)
  owner = null; ignorePops = 0; pendingBack = null; locks = 0; prevOverflow = ''
  if (listening && typeof window !== 'undefined') window.removeEventListener('popstate', onPop)
  listening = false
}
