import { useEffect, useState } from 'react'
import { lsGet, lsRemove, lsSet } from './storage'

/* Cât de „gălăgioase" sunt update-urile OS în listă (badge-ul din Sidebar + chip-ul din
   HostOverview). Preferinţă per browser, ca restul (temă, fus orar, sfaturi): e despre ce vrei
   TU să vezi, nu despre host. Două niveluri:
   - global (`wt_upd_mode`): toate / doar securitate / ascunse;
   - per host (`wt_upd_mute`): lista de id-uri pentru care NU vrei semnalul („mascarea").
   Logica „pură" stă aici (testabilă fără DOM), componentele doar o citesc prin `useUpdatesPref`.
   Pe pagina hostului chip-ul apare mereu (neutru); mascarea priveşte doar lista, zgomotul pasiv. */

export type UpdatesMode = 'all' | 'security' | 'off'
export type HostUpdates = { count: number; security: number | null } | null | undefined

export const UPD_MODE_KEY = 'wt_upd_mode'
export const UPD_MUTE_KEY = 'wt_upd_mute'
const EVT = 'wt-updates-pref'

export function updatesMode(): UpdatesMode {
  const v = lsGet(UPD_MODE_KEY)
  return v === 'security' || v === 'off' ? v : 'all'
}

export function setUpdatesMode(m: UpdatesMode): void {
  lsSet(UPD_MODE_KEY, m)
  notify()
}

/** Id-urile hosturilor mascate. Gunoi în storage (JSON stricat, non-numere) = listă goală:
    o preferinţă coruptă nu trebuie să ascundă nimic şi nici să arunce. */
export function mutedHosts(): Set<number> {
  try {
    const arr: unknown = JSON.parse(lsGet(UPD_MUTE_KEY) || '[]')
    return new Set(Array.isArray(arr) ? arr.filter((x): x is number => Number.isInteger(x)) : [])
  } catch {
    return new Set()
  }
}

export function isHostMuted(id: number): boolean {
  return mutedHosts().has(id)
}

export function setHostMuted(id: number, muted: boolean): void {
  const s = mutedHosts()
  if (muted) s.add(id)
  else s.delete(id)
  lsSet(UPD_MUTE_KEY, JSON.stringify([...s].sort((a, b) => a - b)))
  notify()
}

/** „Arată din nou peste tot" din Setări: goleşte lista de mascări per host. */
export function unmuteAllHosts(): void {
  lsRemove(UPD_MUTE_KEY)
  notify()
}

/** Ce semnal arătăm pentru un host: nimic, discret (doar număr) sau securitate (accent).
    Hostul mascat nu arată nimic, indiferent de mod — exact asta cere „mascarea". */
export function updatesSignal(
  hostId: number, u: HostUpdates, mode: UpdatesMode = updatesMode(), muted: Set<number> = mutedHosts(),
): 'none' | 'quiet' | 'security' {
  if (!u || u.count <= 0 || mode === 'off' || muted.has(hostId)) return 'none'
  if (u.security) return 'security'
  return mode === 'security' ? 'none' : 'quiet'
}

function notify(): void {
  try { window.dispatchEvent(new Event(EVT)) } catch { /* fără window (teste node) */ }
}

/** Re-randare la orice schimbare de preferinţă (din Setări, din meniul hostului, alt tab). */
export function useUpdatesPref(): { mode: UpdatesMode; muted: Set<number> } {
  const [state, setState] = useState(() => ({ mode: updatesMode(), muted: mutedHosts() }))
  useEffect(() => {
    const sync = () => setState({ mode: updatesMode(), muted: mutedHosts() })
    const onStorage = (e: StorageEvent) => { if (e.key === UPD_MODE_KEY || e.key === UPD_MUTE_KEY) sync() }
    window.addEventListener(EVT, sync)
    window.addEventListener('storage', onStorage)
    return () => { window.removeEventListener(EVT, sync); window.removeEventListener('storage', onStorage) }
  }, [])
  return state
}
