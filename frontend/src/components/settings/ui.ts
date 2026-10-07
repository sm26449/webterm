import { ApiError } from '../../lib/api'

// Clase UI partajate între tab-urile din Settings (extrase din god-component-ul SettingsModal
// când a fost spart pe tab-uri). O singură sursă, ca input-urile/heading-urile să rămână identice.
export const field =
  // ring pe `--field-border` (nu ink-700): conturul câmpului trebuie să treacă 3:1 (WCAG 1.4.11);
  // ink-700 dădea 1,2–1,3:1 pe ambele teme — câmpul se distingea doar prin fundal
  'w-full rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 ring-1 ring-[rgb(var(--field-border))] focus:ring-sky-500'
export const heading = 'mt-6 text-[13px] font-semibold uppercase tracking-wide text-slate-400'

// Butoane: patru intenţii, o singură sursă — mutate în design system (components/ui/classes.ts,
// unde stă şi explicaţia culorilor). Re-exportul păstrează importurile existente.
export { btn } from '../ui/classes'

// Descărcare de blob (endpoint-urile întorc octeți, nu JSON → fetch brut). Partajat între
// BackupTab (arhivă) şi secţiunea de semnare a flotei din SettingsModal (cheia de semnare).
export async function downloadBlob(path: string, body: unknown, fallbackName: string) {
  const res = await fetch(path, {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  if (!res.ok) {
    let detail = res.statusText
    try { detail = (await res.json()).detail ?? detail } catch { /* non-JSON */ }
    throw new ApiError(res.status, detail)
  }
  const cd = res.headers.get('Content-Disposition') || ''
  const m = cd.match(/filename="([^"]+)"/)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = m?.[1] || fallbackName
  document.body.appendChild(a); a.click(); a.remove()
  URL.revokeObjectURL(url)
}
