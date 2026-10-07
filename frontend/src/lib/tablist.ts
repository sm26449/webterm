/* Lista „toate taburile" din TabBar (telefon / taburi care nu încap): logica pură, testabilă. */

/** Bara derulează pe orizontală dacă are mai mult conţinut decât lăţime (1px toleranţă pentru
    rotunjirile sub-pixel de la zoom, care altfel ar aprinde butonul pe desktop fără motiv). */
export const isOverflowing = (scrollWidth: number, clientWidth: number): boolean =>
  scrollWidth - clientWidth > 1

/** Butonul apare pe telefon (2–3 taburi vizibile, restul fără niciun indiciu) şi oriunde altundeva
    doar când taburile chiar nu încap. Fără taburi n-are ce lista. */
export const showAllTabsButton = (count: number, phone: boolean, overflowing: boolean): boolean =>
  count > 0 && (phone || overflowing)

export type TabState = 'live' | 'closed' | 'lost' | 'failed'

/** Aceeaşi clasificare ca punctul de stare de pe tab: închisă cu exit ≠ 0 = „failed" (roşu),
    nu la fel ca una terminată normal. */
export function tabState(s: { state?: string | null; exit_status?: number | null }, live: boolean): TabState {
  if (live) return 'live'
  if (s.state === 'lost') return 'lost'
  if (s.exit_status != null && s.exit_status !== 0) return 'failed'
  return 'closed'
}

/** Navigarea din tastatură într-un meniu (WAI-ARIA menu): ↓/↑ cu wrap, Home/End la capete.
    Întoarce indexul nou, sau null pentru o tastă care nu mută focusul. */
export function menuNav(key: string, i: number, n: number): number | null {
  if (n <= 0) return null
  if (key === 'ArrowDown') return i < 0 ? 0 : (i + 1) % n
  if (key === 'ArrowUp') return i < 0 ? n - 1 : (i - 1 + n) % n
  if (key === 'Home') return 0
  if (key === 'End') return n - 1
  return null
}
