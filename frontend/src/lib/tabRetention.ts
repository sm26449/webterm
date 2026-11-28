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
// listă, tabul e randat din cache. Reţinerea e îngustă, ca un tab mort să nu rămână pe veci:
//  · doar pentru sesiunile unui host `require_2fa` (singurul caz în care lipsa e temporară; pe un
//    host normal lipsa = ştearsă/revocată, iar un tab nemontat nu raportează niciodată `gone`);
//  · cel mult RETAIN_MAX_MS de la ultima DOVADĂ că sesiunea trăieşte: apariţia în listă sau un
//    socket deschis al tabului (vezi `attached` mai jos);
//  · nu după ce SessionView a raportat exit / lost / 4404 / 4403 / handshake refuzat (`gone`),
//    sau dacă ultimul obiect văzut nu mai era viu.
// Un tab fără nimic în cache (ex. după reload) se închide ca înainte: nu inventăm sesiuni.
//
// 3.8.2: plafonul se măsura DOAR de la ultima apariţie în listă. Un terminal 2FA lăsat în fundal
// primeşte idle-lock după 5 min fără input; hub-ul blocat iese din listă (INV-04) şi nu mai apare
// acolo până la deblocare. Tabul era deci tăiat la 65 min după blocare, deşi socketul lui era încă
// ataşat şi sesiunea vie (overlay-ul aştepta passkey-ul) — în producţie (2026-11-27) tabul sesiunii
// Orbit s-a reconectat la 22:04, 22:14 şi 22:28 după blocarea de la 21:56 şi a dispărut ~23:01.
// Un socket deschis spre sesiune e dovadă că ea trăieşte (gateway-ul îl închide / trimite exit când
// se încheie), deci reîmprospătează ceasul; plafonul rămâne doar pentru taburile fără socket.
import type { Session } from './api'

// STEPUP_WINDOW_MAX (gateway, 3600 s) + marjă de 5 min, de la ultima dovadă că sesiunea trăieşte
export const RETAIN_MAX_MS = (3600 + 300) * 1000

interface Cached { s: Session; seen: number }

export interface TabRetention {
  // ultimul Session văzut (şi când), doar pentru sid-urile din taburile deschise
  cache: Map<string, Cached>
  // sid → momentul în care SessionView a raportat sesiunea încheiată/dispărută
  gone: Map<string, number>
  // sid-urile al căror SessionView are ACUM socketul deschis (onAlive → onDetach)
  attached: Set<string>
}

export function newTabRetention(): TabRetention {
  return { cache: new Map(), gone: new Map(), attached: new Set() }
}

/** SessionView a raportat sesiunea încheiată / refuzată (vezi `onGone`). */
export function markGone(st: TabRetention, sid: string, now = Date.now()): void {
  st.gone.set(sid, now)
  // un socket încă deschis spre o sesiune încheiată (citirea one-shot a istoricului) nu e dovadă de viaţă
  st.attached.delete(sid)
}

/** Socketul s-a deschis (din nou): semnalul de „încheiată" nu mai e valabil, iar cât rămâne
 *  deschis sesiunea e ştiută vie (reîmprospătează plafonul reţinerii). */
export function markAlive(st: TabRetention, sid: string): void {
  st.gone.delete(sid)
  st.attached.add(sid)
}

/** Socketul tabului s-a închis (reconectare, sesiune încheiată, demontare): de aici plafonul
 *  curge din nou de la ultima dovadă. */
export function markDetached(st: TabRetention, sid: string): void {
  st.attached.delete(sid)
}

const alive = (s: Session) => s.state === 'live' || s.state === 'creating'

export interface RetainOpts {
  /** hosturile cu `require_2fa` (doar sesiunile lor se reţin) */
  gatedHosts: ReadonlySet<number>
  /** momentul în care a PORNIT poll-ul care a adus `list`: o citire „vie" nu şterge un `gone`
      raportat după acest moment (poll vechi ajuns după raport) */
  pollStart: number
  now?: number
}

/** Combină lista proaspătă cu sesiunile reţinute pentru taburile deschise.
 *  `fresh` = lista a venit acum de la server (doar atunci actualizăm cache-ul şi tăiem taburi).
 *  Întoarce lista de afişat (cea de pe server + cele reţinute, la coadă) şi taburile valide. */
export function retainOpenTabs(
  list: Session[], openTabs: string[], st: TabRetention, fresh: boolean, opts: RetainOpts,
): { sessions: Session[]; tabs: string[] } {
  const now = opts.now ?? Date.now()
  const byId = new Map(list.map((s) => [s.id, s]))
  if (fresh) {
    for (const sid of openTabs) {
      const s = byId.get(sid)
      if (!s) continue
      st.cache.set(sid, { s, seen: now })
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
    if (!c || st.gone.has(sid) || !alive(c.s)) continue
    // socket deschis acum = sesiunea trăieşte acum (blocată sau nu): ceasul porneşte de aici
    if (st.attached.has(sid)) c.seen = Math.max(c.seen, now)
    if (!opts.gatedHosts.has(c.s.host_id)) continue
    if (now - c.seen > RETAIN_MAX_MS) continue
    extra.push(c.s)
    tabs.push(sid)
  }
  // nu ţinem nimic pentru taburi închise: nici cache, nici semnal
  for (const k of [...st.cache.keys()]) if (!openTabs.includes(k)) st.cache.delete(k)
  for (const k of [...st.gone.keys()]) if (!openTabs.includes(k)) st.gone.delete(k)
  return { sessions: extra.length ? [...list, ...extra] : list, tabs: fresh ? tabs : openTabs }
}
