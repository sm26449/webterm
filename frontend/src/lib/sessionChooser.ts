/* „New session" pe un host care are deja sesiuni deschise (3.7.1).

   De ce: fiecare clic pe „New session" deschidea încă un terminal, iar oamenii ajungeau cu 6–8
   sesiuni uitate pe acelaşi host (fiecare cu tmux-ul ei, fiecare în lista din Dashboard). Acum,
   dacă hostul are deja sesiuni VII ale TALE, un dialog mic le arată şi propune tot „sesiune nouă"
   (rândul selectat implicit — Enter face exact ce făcea clicul înainte), dar o poţi relua pe una.

   Aici e doar decizia (testabilă fără DOM): ce sesiuni apar, în ce ordine, dacă întrebăm, unde se
   ţine „nu mă mai întreba". Serverul rămâne cel care decide accesul la ataşare (`_ws_access`). */

import type { Session } from './api'
import { lsGet, lsRemove, lsSet } from './storage'

/** Comutatorul global din Setări → Terminal şi spaţiu de lucru ('0' = nu întreba; implicit pornit). */
export const ASK_GLOBAL_KEY = 'wt_ask_new_session'
/** „Nu mă mai întreba pentru hostul ăsta" — per browser, per host ('0' = nu întreba). */
export const ASK_HOST_PREFIX = 'wt_ask_new_session_h'

export const askGlobalEnabled = (): boolean => lsGet(ASK_GLOBAL_KEY) !== '0'
export function setAskGlobal(on: boolean): void {
  if (on) lsRemove(ASK_GLOBAL_KEY)
  else lsSet(ASK_GLOBAL_KEY, '0')
}
export const askHostEnabled = (hostId: number): boolean => lsGet(ASK_HOST_PREFIX + hostId) !== '0'
export function setAskHost(hostId: number, on: boolean): void {
  if (on) lsRemove(ASK_HOST_PREFIX + hostId)
  else lsSet(ASK_HOST_PREFIX + hostId, '0')
}

/** Cheile „nu mă mai întreba" puse pe hosturi (pentru „Întreabă din nou pe toate hosturile"). */
export function hostOptOutKeys(): string[] {
  try {
    const out: string[] = []
    const ls = window.localStorage
    for (let i = 0; i < ls.length; i++) {
      const k = ls.key(i)
      if (k && k.startsWith(ASK_HOST_PREFIX) && /^\d+$/.test(k.slice(ASK_HOST_PREFIX.length))) out.push(k)
    }
    return out
  } catch {
    return []    // storage blocat: nimic de resetat
  }
}
export function resetHostOptOuts(): void {
  for (const k of hostOptOutKeys()) lsRemove(k)
}

/** Momentul ultimei activităţi: ultimul output văzut de gateway, altfel deschiderea. */
export const lastActivity = (s: Session): number => s.last_output ?? s.created

/** Sesiunile pe care le propunem spre reluare: VII, pe hostul ăsta, ale TALE (sau dinainte de
    roluri, fără creator — `_ws_access` le tratează tot ca ale tale). Ale altora nu: chiar cu
    session.watch le-ai primi doar în citire, deci n-ar înlocui o sesiune nouă. Fără `userId`
    (starea contului încă necunoscută) → nimic, adică fluxul de azi. Ordinea: activitatea cea mai
    recentă întâi. */
export function reusableSessions(hostId: number, sessions: readonly Session[], userId: number | null | undefined): Session[] {
  if (userId == null) return []
  return sessions
    .filter((s) => s.host_id === hostId && (s.state === 'live' || s.state === 'creating')
      && (s.created_by_id == null || s.created_by_id === userId))
    .sort((a, b) => lastActivity(b) - lastActivity(a) || b.created - a.created)
}

/** Întrebăm doar dacă: ai voie să deschizi o sesiune aici (altfel butonul nici nu porneşte nimic),
    există ceva de reluat, şi n-ai oprit întrebarea (global sau pe host). */
export function shouldAskBeforeNew(opts: {
  hostId: number
  reusable: readonly Session[]
  canOpen: boolean
  askGlobal?: boolean
  askHost?: boolean
}): boolean {
  const g = opts.askGlobal ?? askGlobalEnabled()
  const h = opts.askHost ?? askHostEnabled(opts.hostId)
  return opts.canOpen && g && h && opts.reusable.length > 0
}

/** Câţi ALŢI clienţi sunt ataşaţi acum: tab-ul ăsta, dacă sesiunea e deja deschisă aici, nu se
    numără (altfel „deschisă pe 1 alt dispozitiv" ar fi chiar fereastra în care citeşti). */
export function otherClients(s: Session, openHere: boolean): number {
  return Math.max(0, (s.connected_clients || 0) - (openHere ? 1 : 0))
}

/** Navigarea în listă: ↑/↓ (cu trecere la capăt), Home/End. null = tasta nu e a listei. */
export function chooserNavTarget(count: number, current: number, key: string): number | null {
  if (count <= 0) return null
  switch (key) {
    case 'ArrowDown': return current < 0 ? 0 : (current + 1) % count
    case 'ArrowUp': return current < 0 ? count - 1 : (current - 1 + count) % count
    case 'Home': return 0
    case 'End': return count - 1
    default: return null
  }
}
