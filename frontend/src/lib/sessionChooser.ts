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

/* ── Tab-ul de lansare (3.7.1, decizia proprietarului) ──────────────────────────────────────────
   „New session" pe un host unde ai deja sesiuni VII ale tale, care NU sunt deja într-un tab aici,
   deschide un tab opac de alegere; shell-ul se creează abia după alegere. Dacă toate sunt deja în
   tab-uri aici, nu întrebăm (le vezi oricum). Odată deschis, lansatorul le arată pe TOATE (rc5:
   proprietarul vedea 2 carduri pe un host cu mult mai multe şi credea că lista e greşită); cele
   deschise deja aici poartă insigna „Open in a tab here" şi doar comută pe tab-ul existent. */

/** Cardurile lansatorului: TOATE refolosibilele de pe host — întâi cele care nu sunt încă într-un tab
    aici, apoi cele deschise deja aici; în fiecare grup, după activitate (ordinea din reusableSessions). */
export function launcherSessions(hostId: number, sessions: readonly Session[], userId: number | null | undefined,
                                 openTabIds: readonly string[]): Session[] {
  const open = new Set(openTabIds)
  const all = reusableSessions(hostId, sessions, userId)
  return [...all.filter((s) => !open.has(s.id)), ...all.filter((s) => open.has(s.id))]
}

/** Refolosibilele care NU sunt deja într-un tab aici — doar ele decid dacă lansatorul apare. */
export function launcherPending(hostId: number, sessions: readonly Session[], userId: number | null | undefined,
                                openTabIds: readonly string[]): Session[] {
  const open = new Set(openTabIds)
  return reusableSessions(hostId, sessions, userId).filter((s) => !open.has(s.id))
}

/** 'launcher' = arătăm tab-ul de alegere; 'direct' = sesiune nouă, exact ca înainte. `direct`
    (Shift+clic / Shift+Enter) sare peste întrebare; un host offline nu are ce alege (butonul e oricum
    inactiv, iar o încercare trebuie să dea eroarea obişnuită, nu un ecran de alegere). */
export function launcherDecision(opts: {
  hostId: number
  sessions: readonly Session[]
  userId: number | null | undefined
  openTabIds: readonly string[]
  canOpen: boolean
  online: boolean
  direct?: boolean
  askGlobal?: boolean
  askHost?: boolean
}): 'launcher' | 'direct' {
  if (opts.direct || !opts.online) return 'direct'
  const reusable = launcherPending(opts.hostId, opts.sessions, opts.userId, opts.openTabIds)
  return shouldAskBeforeNew({
    hostId: opts.hostId, reusable, canOpen: opts.canOpen, askGlobal: opts.askGlobal, askHost: opts.askHost,
  }) ? 'launcher' : 'direct'
}

/** Peste o zi fără output = „inactivă" (textul se estompează, intră la „Close idle…"). */
export const IDLE_SECS = 86400
/** Câte carduri arătăm înainte de „View all N" (telefonul are mai puţin ecran). */
export const LAUNCHER_VISIBLE = { desktop: 5, phone: 4 } as const

/** Cât timp a trecut, în unitatea pe care o afişăm (min / h / zile); 'now' sub un minut. */
export function durationParts(secs: number): { unit: 'now' | 'min' | 'h' | 'd'; n: number } {
  const s = Math.max(0, secs)
  if (s < 60) return { unit: 'now', n: 0 }
  if (s < 3600) return { unit: 'min', n: Math.floor(s / 60) }
  if (s < 86400) return { unit: 'h', n: Math.floor(s / 3600) }
  return { unit: 'd', n: Math.floor(s / 86400) }
}

/** Ce spune un card despre sesiune (fără DOM): activitatea, vechimea, insignele. `now` în secunde. */
export function cardFacts(s: Session, now: number, openHere = false): {
  idleSecs: number
  ageSecs: number
  idle: boolean
  starting: boolean
  others: number
  shared: boolean
  keepOpen: boolean
  idleNotice: boolean
} {
  const idleSecs = Math.max(0, now - lastActivity(s))
  return {
    idleSecs,
    ageSecs: Math.max(0, now - s.created),
    idle: idleSecs >= IDLE_SECS,
    starting: s.state === 'creating',
    others: otherClients(s, openHere),
    shared: !!s.shared,
    keepOpen: !!s.keep_open,
    idleNotice: !!s.idle_notice,
  }
}

/** Candidatele pentru „Close idle…": inactive de peste o zi, VII. Lăsăm deoparte (fail-safe — închiderea
    omoară shell-ul) cele marcate „Keep open", cele cu link de share activ (cineva poate urmări) şi cele
    ataşate acum în alt browser/dispozitiv (cineva le foloseşte, chiar fără output). Şi cele deschise
    într-un tab AICI (`openTabIds`): le vezi, nu le închidem pe la spate. */
export function idleCandidates(list: readonly Session[], now: number, openTabIds: readonly string[] = []): Session[] {
  const open = new Set(openTabIds)
  return list.filter((s) => s.state === 'live' && !open.has(s.id) && !s.keep_open && !s.shared
    && (s.connected_clients || 0) === 0 && now - lastActivity(s) >= IDLE_SECS)
}

/** Cum a fost cerută o sesiune nouă: `direct` = Shift ţinut (clic, Enter) → fără lansator. */
export type NewSessionOpts = { direct?: boolean }
export const newSessionOpts = (e?: { shiftKey?: boolean } | null): NewSessionOpts => ({ direct: !!e?.shiftKey })
