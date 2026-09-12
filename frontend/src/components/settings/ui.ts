import { ApiError } from '../../lib/api'

// Clase UI partajate între tab-urile din Settings (extrase din god-component-ul SettingsModal
// când a fost spart pe tab-uri). O singură sursă, ca input-urile/heading-urile să rămână identice.
export const field =
  'w-full rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 ring-1 ring-ink-700 focus:ring-sky-500'
export const heading = 'mt-6 text-[13px] font-semibold uppercase tracking-wide text-slate-400'

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
