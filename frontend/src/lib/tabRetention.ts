// Păstrarea taburilor deschise când sesiunea lipseşte TEMPORAR din /api/sessions (3.8.1).
//
// De ce: pe un host `require_2fa`, lista de sesiuni ascunde sesiunile hostului cât fereastra de
// step-up e închisă (meta-leak, INV-04). Fereastra glisează doar pe acţiuni sensibile, nu pe tastare,
// iar serverul păstrează în listă doar sesiunile la care eşti ataşat deblocat din acest login; la
// plafonul de 60 min hub-ul se blochează şi sesiunea iese din nou din listă. Înainte, poll-ul de 5 s
// tăia orice tab absent din listă, deci terminalul pe care lucrai (sau cel blocat, care aştepta
// passkey-ul) dispărea şi trebuia redeschis din pagina hostului.
//
// Acum: ultimul obiect Session văzut pentru un tab deschis e ţinut într-un cache; cât lipseşte din
// listă, tabul e randat din cache. Reţinerea e îngustă, ca un tab mort să nu rămână:
//  · doar pentru sesiunile unui host `require_2fa` (singurul caz în care lipsa e temporară; pe un
//    host normal lipsa = ştearsă/revocată, iar un tab nemontat nu raportează niciodată `gone`);
//  · nu după ce SessionView a raportat exit / lost / 4404 / 4403 / handshake refuzat / sesiune
//    încheiată la ataşare (`gone`), sau dacă ultimul obiect văzut în listă nu mai era viu.
// Un tab fără nimic în cache (ex. după reload) se închide ca înainte: nu inventăm sesiuni.
//
// 3.8.2 (decizia lui Stefan): pe un host 2FA tabul NU expiră cu timpul. 3.8.1 îl ţinea cel mult
// 65 min de la ultima apariţie în listă, dar un terminal lăsat în fundal primeşte idle-lock după
// 5 min, iar hub-ul blocat nu mai apare în listă până la deblocare (INV-04) — deci tabul unei
// sesiuni vii, ataşate şi blocate dispărea (producţie 2026-11-27: sesiunea Orbit blocată la 21:56,
// reataşată la 22:04/22:14/22:28, dispărută ~23:01). Lipsa din listă nu spune nimic despre o sesiune
// 2FA, deci timpul nu e un semnal: tabul rămâne până îl închide omul sau până aflăm că sesiunea s-a
// încheiat. Un tab nemontat (peste stiva keep-alive) se lămureşte la click: SessionView se ataşează
// (blocat, cu deblocarea prin passkey), iar dacă sesiunea s-a încheiat / a dispărut raportează `gone`.
import type { Session } from './api'

export interface TabRetention {
  // ultimul Session văzut în listă, doar pentru sid-urile din taburile deschise
  cache: Map<string, Session>
  // sid → momentul în care SessionView a raportat sesiunea încheiată/dispărută
  gone: Map<string, number>
  // sid → reconectări CONSECUTIVE refuzate înainte de deschidere (review L1), resetat la onAlive
  fails: Map<string, number>
}

// Review L1 (3.8.2): un tab 2FA reţinut şi montat a cărui reconectare e refuzată înainte de accept
// (1006: sesiune ştearsă / acces pierdut după prima deschidere) nu raporta niciodată `gone` şi rămânea
// „reconnecting" pe veci. După atâtea refuzuri la rând, cu lista proaspătă primită (gateway-ul
// răspunde) şi sesiunea absentă din ea, îl tratăm ca dispărut. Pe un host 2FA fără fereastră serverul
// acceptă şi blochează (nu refuză), deci asta nu taie un terminal doar blocat.
export const CONNECT_FAILS_GONE = 3

export function newTabRetention(): TabRetention {
  return { cache: new Map(), gone: new Map(), fails: new Map() }
}

/** SessionView a raportat sesiunea încheiată / refuzată (vezi `onGone`). */
export function markGone(st: TabRetention, sid: string, now = Date.now()): void {
  st.gone.set(sid, now)
}

/** Socketul s-a deschis (din nou): semnalul de „încheiată" nu mai e valabil. */
export function markAlive(st: TabRetention, sid: string): void {
  st.gone.delete(sid)
  st.fails.delete(sid)
}

/** Un socket al tabului s-a închis fără să se fi deschis vreodată (refuz înainte de accept / reţea). */
export function markConnectFailed(st: TabRetention, sid: string): void {
  st.fails.set(sid, (st.fails.get(sid) ?? 0) + 1)
}

/** SessionView, `onopen`: socketul one-shot de istoric al unei sesiuni ÎNCHEIATE nu e dovadă de viaţă
 *  (altfel ar şterge `gone` raportat la exit, iar tabul unei sesiuni moarte n-ar mai expira niciodată). */
export function reportsAliveOnOpen(exited: boolean): boolean {
  return !exited
}

/** SessionView, mesajul `init`: o sesiune care nu mai e vie la (re)ataşare e încheiată → `gone`
 *  (tab reţinut, nemontat, a cărui sesiune s-a închis între timp; click → montare → init closed). */
export function initMeansGone(state: unknown): boolean {
  return state !== 'live' && state !== 'creating'
}

const alive = (s: Session) => s.state === 'live' || s.state === 'creating'

export interface RetainOpts {
  /** hosturile cu `require_2fa` (doar sesiunile lor se reţin) */
  gatedHosts: ReadonlySet<number>
  /** momentul în care a PORNIT poll-ul care a adus `list`: o citire „vie" nu şterge un `gone`
      raportat după acest moment (poll vechi ajuns după raport) */
  pollStart: number
}

/** Combină lista proaspătă cu sesiunile reţinute pentru taburile deschise.
 *  `fresh` = lista a venit acum de la server (doar atunci actualizăm cache-ul şi tăiem taburi).
 *  Întoarce lista de afişat (cea de pe server + cele reţinute, la coadă) şi taburile valide. */
export function retainOpenTabs(
  list: Session[], openTabs: string[], st: TabRetention, fresh: boolean, opts: RetainOpts,
): { sessions: Session[]; tabs: string[] } {
  const byId = new Map(list.map((s) => [s.id, s]))
  if (fresh) {
    for (const sid of openTabs) {
      const s = byId.get(sid)
      if (!s) continue
      st.cache.set(sid, s)
      // a revenit viu (ex. reconectare telnet): semnalul vechi de „încheiată" nu mai e valabil —
      // dar doar dacă a fost dat ÎNAINTE de pornirea acestui poll (altfel citirea e mai veche)
      const g = st.gone.get(sid)
      if (alive(s) && g !== undefined && g < opts.pollStart) st.gone.delete(sid)
    }
  }
  const extra: Session[] = []
  const tabs: string[] = []
  for (const sid of openTabs) {
    if (byId.has(sid)) { tabs.push(sid); continue }
    const c = st.cache.get(sid)
    if (!c || st.gone.has(sid) || !alive(c)) continue
    if (!opts.gatedHosts.has(c.host_id)) continue
    if (fresh && (st.fails.get(sid) ?? 0) >= CONNECT_FAILS_GONE) continue
    extra.push(c)
    tabs.push(sid)
  }
  // nu ţinem nimic pentru taburi închise: nici cache, nici semnal
  for (const k of [...st.cache.keys()]) if (!openTabs.includes(k)) st.cache.delete(k)
  for (const k of [...st.gone.keys()]) if (!openTabs.includes(k)) st.gone.delete(k)
  for (const k of [...st.fails.keys()]) if (!openTabs.includes(k)) st.fails.delete(k)
  return { sessions: extra.length ? [...list, ...extra] : list, tabs: fresh ? tabs : openTabs }
}

export interface AuthSnap { authenticated: boolean; user_id: number | null }

/** Review M1 (3.8.2): taburile reţinute nu expiră, deci nu au voie să treacă de la un cont la altul
 *  în acelaşi browser. ORICE schimbare de autentificare văzută de pagină (ieşire, expirare/`wt-unauth`,
 *  intrare, alt `user_id`) goleşte reţinerea şi taburile — inclusiv re-intrarea aceluiaşi cont
 *  (simplu şi sigur). `prev` null = prima stare a paginii (reload cu sesiunea validă): nimic de golit. */
export function authResetNeeded(prev: AuthSnap | null, next: AuthSnap): boolean {
  if (!prev) return false
  return prev.authenticated !== next.authenticated
    || (next.authenticated && prev.user_id !== next.user_id)
}
