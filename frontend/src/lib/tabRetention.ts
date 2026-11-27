// Păstrarea taburilor deschise când sesiunea lipseşte TEMPORAR din /api/sessions (3.8.1).
//
// De ce: pe un host `require_2fa`, lista de sesiuni ascunde sesiunile hostului cât fereastra de
// step-up e închisă (meta-leak, INV-04). Fereastra glisează doar pe acţiuni sensibile, nu pe tastare,
// iar serverul păstrează în listă doar sesiunile la care eşti ataşat deblocat; la plafonul de 60 min
// hub-ul se blochează şi sesiunea iese din nou din listă. Înainte, poll-ul de 5 s tăia orice tab
// absent din listă, deci terminalul pe care lucrai (sau cel blocat, care aştepta passkey-ul)
// dispărea şi trebuia redeschis din pagina hostului.
//
// Acum: ultimul obiect Session văzut pentru un tab deschis e ţinut într-un cache; cât lipseşte din
// listă, tabul e randat din cache. Un tab absent se închide doar dacă sesiunea e ştiută încheiată:
// SessionView a raportat exit / lost / 4404 / 4403 (`gone`), sau ultimul obiect văzut nu mai era
// viu. Un tab fără nimic în cache (ex. după reload) se închide ca înainte: nu inventăm sesiuni.
import type { Session } from './api'

export interface TabRetention {
  // ultimul Session văzut, doar pentru sid-urile din taburile deschise
  cache: Map<string, Session>
  // sid-uri raportate încheiate/dispărute de SessionView
  gone: Set<string>
}

export function newTabRetention(): TabRetention {
  return { cache: new Map(), gone: new Set() }
}

const alive = (s: Session) => s.state === 'live' || s.state === 'creating'

/** Combină lista proaspătă cu sesiunile reţinute pentru taburile deschise.
 *  `fresh` = lista a venit acum de la server (doar atunci actualizăm cache-ul şi tăiem taburi).
 *  Întoarce lista de afişat (cea de pe server + cele reţinute, la coadă) şi taburile valide. */
export function retainOpenTabs(
  list: Session[], openTabs: string[], st: TabRetention, fresh: boolean,
): { sessions: Session[]; tabs: string[] } {
  const byId = new Map(list.map((s) => [s.id, s]))
  if (fresh) {
    for (const sid of openTabs) {
      const s = byId.get(sid)
      if (!s) continue
      st.cache.set(sid, s)
      // a revenit viu (ex. reconectare telnet): semnalul vechi de „încheiată" nu mai e valabil
      if (alive(s)) st.gone.delete(sid)
    }
  }
  const extra: Session[] = []
  const tabs: string[] = []
  for (const sid of openTabs) {
    if (byId.has(sid)) { tabs.push(sid); continue }
    const c = st.cache.get(sid)
    if (!c || st.gone.has(sid) || !alive(c)) continue
    extra.push(c)
    tabs.push(sid)
  }
  // nu ţinem nimic pentru taburi închise: nici cache, nici semnal
  for (const k of [...st.cache.keys()]) if (!openTabs.includes(k)) st.cache.delete(k)
  for (const k of [...st.gone]) if (!openTabs.includes(k)) st.gone.delete(k)
  return { sessions: extra.length ? [...list, ...extra] : list, tabs: fresh ? tabs : openTabs }
}
