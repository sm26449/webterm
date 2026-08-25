// Font-size-ul terminalului e o proprietate a DISPOZITIVULUI, nu a tabului:
// același browser vrea aceeași literă în toate sesiunile, iar un telefon vrea
// alta decât laptopul. Preferința se ține deci per clasă de lățime (telefon /
// tabletă / desktop), în localStorage-ul fiecărui browser, iar A± suprascrie
// DOAR clasa pe care ești acum — rotirea sau alt dispozitiv își păstrează
// calibrarea proprie. Vechea cheie `wt_font` (o singură valoare, scrisă și
// pentru default-ul nemodificat) îngropa euristica de lățime la prima vizită;
// e migrată o dată, ca override al clasei curente, apoi ștearsă.
export type DeviceClass = 'phone' | 'tablet' | 'desktop'

// pe telefoane (îngust) fontul mic încadrează mult mai bine coloanele
// terminalului — testat pe device real, 9 e treapta cea mai bună (min = 8).
// Tabletele (640–768) rămân la 12, desktop la 14. Se poate ajusta cu A±.
const DEFAULTS: Record<DeviceClass, number> = { phone: 9, tablet: 12, desktop: 14 }
export const FONT_MIN = 8
export const FONT_MAX = 24
const KEY = 'wt_font_device'

const clamp = (n: number) => Math.min(FONT_MAX, Math.max(FONT_MIN, Math.round(n)))

export function deviceClass(): DeviceClass {
  const w = window.innerWidth
  return w < 640 ? 'phone' : w < 768 ? 'tablet' : 'desktop'
}

function overrides(): Partial<Record<DeviceClass, number>> {
  try {
    const raw = localStorage.getItem(KEY)
    if (raw) return JSON.parse(raw) as Partial<Record<DeviceClass, number>>
  } catch { /* valoare coruptă → pornim curat */ }
  return {}
}

export function preferredFont(): number {
  const cls = deviceClass()
  const o = overrides()
  const saved = o[cls]
  if (typeof saved === 'number' && Number.isFinite(saved)) return clamp(saved)
  const legacy = localStorage.getItem('wt_font')
  if (legacy != null) {
    localStorage.removeItem('wt_font')
    const n = Number(legacy)
    if (Number.isFinite(n) && n > 0) {
      localStorage.setItem(KEY, JSON.stringify({ ...o, [cls]: clamp(n) }))
      return clamp(n)
    }
  }
  return DEFAULTS[cls]
}

// Setează preferința clasei curente și anunță toate panourile montate —
// taburile din fundal se aliniază pe loc, nu la următoarea lor montare.
export function setPreferredFont(n: number): number {
  const v = clamp(n)
  localStorage.setItem(KEY, JSON.stringify({ ...overrides(), [deviceClass()]: v }))
  window.dispatchEvent(new Event('wt-font'))
  return v
}
